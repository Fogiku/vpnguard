// Модули агента: у каждого свой поток, свой ритм и своя очередь команд. Долгое действие одного модуля (переподключение VPN,
// перезапуск службы, тест zapret) не задерживает остальные. Главный поток (Run) только следит: настройки, команды, обновление кода,
// зависшие модули. Новый модуль — новый файл agent\*.cs и строка в StartModules().
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;

namespace VpnGuard
{
    public static partial class Agent
    {
        class Module
        {
            public string Name, Title;
            public Func<int> IntervalMs;                 // ритм (может зависеть от настроек)
            public Action Tick;                          // одна проверка модуля
            public Action<string> OnCmd;                 // команда, адресованная модулю, — выполняется в его потоке
            public string[] Commands = new string[0], Prefixes = new string[0];      // команды целиком и по началу («install …»)
            public int WarnAfterSec = 180;               // одно действие дольше — предупреждение в журнале
            public readonly AutoResetEvent Wake = new AutoResetEvent(false);
            public readonly ConcurrentQueue<string> Cmds = new ConcurrentQueue<string>();
            public readonly ConcurrentQueue<KeyValuePair<string, Action>> Jobs = new ConcurrentQueue<KeyValuePair<string, Action>>();   // реакции на события
            public volatile bool Busy; public DateTime BusySince = DateTime.MinValue, LastEnd = DateTime.MinValue;
            public long Runs, Errors; public string LastError = "", Doing = ""; public bool Warned;
            public volatile bool TickNow = true;          // проверить при следующем пробуждении (а не только по ритму)
            public DateTime NextTick = DateTime.MinValue;
            public Func<object> State;                   // своё состояние для сводки — строится в потоке модуля
            public volatile object Published; public DateTime PublishedAt = DateTime.MinValue;
        }
        static readonly List<Module> Mods = new List<Module>();
        static volatile bool Stopping;
        static Module AddModule(string name, string title, Func<int> intervalMs, Action tick, Action<string> onCmd = null, params string[] cmds)
        {
            var m = new Module { Name = name, Title = title, IntervalMs = intervalMs, Tick = tick, OnCmd = onCmd, Commands = cmds ?? new string[0] };
            lock (Mods) Mods.Add(m);
            return m;
        }
        static Module FindModule(string name) { lock (Mods) return Mods.FirstOrDefault(m => m.Name == name); }
        static int CheckMs() { return Math.Max(10, CfgInt("checkIntervalSec", 30)) * 1000; }

        // ---------------------------------------------------------------- события: модуль сообщает, что произошло, — подписчики реагируют в своём потоке
        // tunnel.switched (откуда→куда), tunnel.reconnected (meduza|amnezia — адаптер мог смениться), mode.changed (режим),
        // wg.restarted, ics.reapply, inet.lost (причина), inet.restored (сколько не было)
        class AgentEvent { public DateTime At; public string Name, Info, From; public string[] To; }
        static readonly List<AgentEvent> EventLog = new List<AgentEvent>();
        static readonly Dictionary<string, List<KeyValuePair<Module, Action<string>>>> Subs = new Dictionary<string, List<KeyValuePair<Module, Action<string>>>>();
        static void On(string module, string evt, Action<string> handler)
        {
            var m = FindModule(module); if (m == null) return;
            lock (Subs) { List<KeyValuePair<Module, Action<string>>> l; if (!Subs.TryGetValue(evt, out l)) Subs[evt] = l = new List<KeyValuePair<Module, Action<string>>>(); l.Add(new KeyValuePair<Module, Action<string>>(m, handler)); }
        }
        static void Emit(string evt, string info = "")
        {
            List<KeyValuePair<Module, Action<string>>> l; lock (Subs) l = Subs.ContainsKey(evt) ? Subs[evt].ToList() : new List<KeyValuePair<Module, Action<string>>>();
            var e = new AgentEvent { At = DateTime.Now, Name = evt, Info = info ?? "", From = EventFrom(), To = l.Select(x => x.Key.Title).Distinct().ToArray() };
            lock (EventLog) { EventLog.Add(e); if (EventLog.Count > 100) EventLog.RemoveAt(0); }
            foreach (var s in l) { var h = s.Value; var inf = e.Info; s.Key.Jobs.Enqueue(new KeyValuePair<string, Action>(evt, () => h(inf))); s.Key.TickNow = true; s.Key.Wake.Set(); }
            Wake("status");
        }
        static string EventFrom()
        {
            var fm = CurModule != null ? FindModule(CurModule) : null; if (fm != null) return fm.Title;
            var tn = Thread.CurrentThread.Name ?? ""; return tn == "inet" ? "Проверка интернета" : tn == "" ? "главный поток" : tn;
        }
        static object[] EventsInfo()
        {
            lock (EventLog) return EventLog.AsEnumerable().Reverse().Take(30).Select(e => (object)new Dictionary<string, object> {
                { "at", e.At.ToString("HH:mm:ss") }, { "name", e.Name }, { "info", e.Info }, { "from", e.From }, { "to", string.Join(", ", e.To) } }).ToArray();
        }
        // кто на что реагирует
        static void Subscribe()
        {
            On("ics", "tunnel.switched", _ => ForceIcs = true);
            On("ics", "tunnel.reconnected", kind => { if (TunnelKind() == kind) ForceIcs = true; });   // переподключился тот, что несёт трафик
            On("ics", "mode.changed", _ => ForceIcs = true);
            On("ics", "wg.restarted", _ => ForceIcs = true);
            On("ics", "ics.reapply", _ => ForceIcs = true);
            On("failover", "tunnel.switched", _ => FoFails = 0);
            On("failover", "mode.changed", _ => FoFails = 0);
            On("tunnels", "tunnel.switched", _ => { });                                          // разбудить: сверить маршруты, восстановить упавший
            On("tunnels", "inet.restored", _ => { ProbeFailures = 0; AwgProbeFailures = 0; DualFails = 0; });
            On("zapret", "inet.restored", _ => {
                // адреса, «замолчавшие» из-за обрыва, — снова через zapret (иначе ещё 5–10 мин шли бы через VPN)
                int nb = CzBypass.Count + CzRemap.Count; CzBypass.Clear(); CzRemap.Clear(); CzGoodIp.Clear(); CzBadHost.Clear();
                if (nb > 0) Log("zapret для клиентов: после обрыва связи сброшено " + nb + " временных обходов — снова через zapret", "INFO");
            });
        }

        static void StartModules()
        {
            AddModule("tunnels", "Туннели", CheckMs, () => VpnWatch(), TunnelCmd,
                "reconnect", "reconnect-meduza", "reconnect-awg", "restart-meduza", "meduza-test", "meduza-catalog", "meduza-proto-reset", "dual-switch", "dual-compare");
            AddModule("wg", "WG-Server", () => 15000, () => { WgWatch(); WgClientsWatch(); }, c => { if (c == "restart-wg") { SvcRestart(CfgStr("wg.serviceName", "WireGuardTunnel$wg_server")); Emit("wg.restarted"); } }, "restart-wg");
            AddModule("ics", "Раздача", () => 10000, SharingWatch, c => { if (c == "reapply-ics") ForceIcs = true; }, "reapply-ics");
            AddModule("zapret", "zapret", CheckMs, () => { ZapretWatch(); ClientZapretWatch(); LanWatch(); }, c => ZCommand(c),
                "zapret-on", "zapret-off", "zapret-check", "zapret-releases", "zapret-update", "zapret-reload", "zapret-test")
                .State = () => new Dictionary<string, object> { { "zapret", ZSnapshotSafe() }, { "cz", CzSnapshot() } };
            FindModule("zapret").WarnAfterSec = 900;                                    // подбор стратегии идёт несколько минут
            AddModule("ps", "Часть PowerShell", () => 10000, PsPartWatch);
            AddModule("web", "Веб-сервер и значок", () => 30000, WebHostTick);
            var upd = AddModule("update", "Обновление VpnGuard", () => 60000, AppUpdateTick, AppUpdateCmd, "app-check", "app-update");
            upd.WarnAfterSec = 900; upd.State = () => new Dictionary<string, object> { { "app", AppSnapshot() } };
            AddModule("status", "Сводка", () => 10000, Snapshot);
            var comp = AddModule("components", "Компоненты", () => 60000, ComponentsTick, ComponentsCmd, "software-check", "install-missing", "check-update");
            comp.Prefixes = new[] { "install " }; comp.WarnAfterSec = 1200;                 // установка может идти минутами
            comp.State = () => new Dictionary<string, object> { { "software", SoftwareSnapshot() }, { "meduzaRemoteVersion", SwS("meduzaRemote") }, { "meduzaLastCheck", When(SwD("meduzaChecked")) } };
            AddModule("failover", "Быстрое переключение", () => Math.Max(2, CfgInt("vpn.fastCheckSec", 5)) * 1000, FailoverTick);
            Subscribe();
            foreach (var m in Mods.ToList()) { var mm = m; new Thread(() => ModuleLoop(mm)) { IsBackground = true, Name = "mod-" + m.Name }.Start(); }
        }
        static void ModuleLoop(Module m)
        {
            PerfThread("модуль: " + m.Title); CurModule = m.Name;
            Thread.Sleep(200);
            while (!Stopping) {
                KeyValuePair<string, Action> job;
                while (m.Jobs.TryDequeue(out job)) {
                    try { job.Value(); } catch (Exception e) { Log("Модуль «" + m.Title + "»: событие " + job.Key + ": " + e.Message, "ERROR"); }
                }
                string c;
                while (m.Cmds.TryDequeue(out c)) {
                    m.Busy = true; m.BusySince = DateTime.Now; m.Doing = "команда " + c; m.Warned = false;
                    try { PerfRun(m.Name + "/" + c, () => m.OnCmd(c)); }
                    catch (Exception e) { Log("Модуль «" + m.Title + "»: команда " + c + ": " + e.Message, "ERROR"); }
                    finally { m.Busy = false; if (ActivityBy == m.Name) Activity = ""; }
                    m.TickNow = true; Wake("status");
                }
                int iv = 10000; try { iv = Math.Max(500, m.IntervalMs()); } catch { }
                if (m.TickNow || DateTime.Now >= m.NextTick) {
                    m.TickNow = false; m.NextTick = DateTime.Now.AddMilliseconds(iv);
                    m.Busy = true; m.BusySince = DateTime.Now; m.Doing = ""; m.Warned = false;
                    try { PerfRun(m.Name, m.Tick); m.LastError = ""; }
                    catch (Exception e) { m.Errors++; m.LastError = e.Message; Log("Модуль «" + m.Title + "»: " + e.Message, "ERROR"); }
                    finally { m.Busy = false; m.LastEnd = DateTime.Now; m.Runs++; if (ActivityBy == m.Name && Activity.Length > 0) { Activity = ""; Wake("status"); } }
                    PublishState(m);
                }
                var wait = m.NextTick - DateTime.Now;
                m.Wake.WaitOne(Math.Max(100, Math.Min(iv, (int)wait.TotalMilliseconds)));
            }
        }
        // разбудить модуль (проверить сейчас, не дожидаясь своего ритма)
        static void Wake(string name) { var m = FindModule(name); if (m != null) { m.TickNow = true; m.Wake.Set(); } }
        // состояние модуля для сводки: строится в его потоке (без гонок с его же изменениями)
        static void PublishState(Module m)
        {
            if (m.State == null) return;
            try { m.Published = m.State(); m.PublishedAt = DateTime.Now; } catch (Exception e) { Log("Модуль «" + m.Title + "»: состояние: " + e.Message, "WARN"); }
        }
        // свежая копия состояния модуля: попросить модуль (он сделает это между своими действиями) и подождать до 1,5 с;
        // занят долгим действием — последняя опубликованная
        static object Published(string name)
        {
            var m = FindModule(name); if (m == null || m.State == null) return null;
            var ready = new ManualResetEvent(false);
            try {
                m.Jobs.Enqueue(new KeyValuePair<string, Action>("публикация", () => { PublishState(m); try { ready.Set(); } catch { } }));
                m.Wake.Set();
                ready.WaitOne(1500);
            } finally { ready.Close(); }
            return m.Published;
        }

        // команды из окна / веба / удалённой диагностики: каждая — своему модулю; не наши — части PowerShell
        static void DispatchCommands()
        {
            List<string> files; try { files = Directory.GetFiles(CmdDir, "*.cmd").OrderBy(f => f).ToList(); } catch { return; }
            foreach (var f in files) {
                string a = ""; try { a = File.ReadAllText(f).Trim(); } catch { }
                if (a == "check-now") {
                    try { File.Delete(f); } catch { }
                    Log("Команда из монитора: check-now", "INFO");
                    lock (Mods) foreach (var m in Mods) { m.TickNow = true; m.Wake.Set(); }
                    continue;
                }
                Module to; lock (Mods) to = Mods.FirstOrDefault(m => m.Commands.Contains(a) || m.Prefixes.Any(p => a.StartsWith(p) && Regex.IsMatch(a.Substring(p.Length), "^[a-z]{1,20}$")));
                if (to == null) {                            // остальное — PowerShell (обновления, установка компонентов …)
                    try { File.Move(f, Path.Combine(CmdPsDir, Path.GetFileName(f))); } catch { try { File.Delete(f); } catch { } }
                    PsPartAt = DateTime.MinValue; Wake("ps"); continue;
                }
                try { File.Delete(f); } catch { }
                Log("Команда из монитора: " + a + (to.Busy ? " (модуль «" + to.Title + "» сейчас занят: " + (to.Doing.Length > 0 ? to.Doing : "проверка") + " — выполню следом)" : ""), "INFO");
                to.Cmds.Enqueue(a); to.TickNow = true; to.Wake.Set();
            }
        }
        // модуль слишком долго делает одно действие — в журнал (один раз за действие); важный модуль (туннели, раздача, WG-Server)
        // занят дольше agent.stuckRestartMin (10) мин — он завис: true — перезапустить агент
        static readonly string[] Critical = { "tunnels", "ics", "wg", "failover" };
        static bool WatchModules()
        {
            int stuckMin = Math.Max(3, CfgInt("agent.stuckRestartMin", 10));
            lock (Mods) foreach (var m in Mods) {
                if (!m.Busy) continue;
                var sec = (DateTime.Now - m.BusySince).TotalSeconds;
                if (!m.Warned && sec >= m.WarnAfterSec) { m.Warned = true; Log("Модуль «" + m.Title + "» выполняет одно действие уже " + (int)sec + " с" + (m.Doing.Length > 0 ? " (" + m.Doing + ")" : "") + (Activity.Length > 0 ? " — сейчас: " + Activity : ""), "WARN"); }
                if (Critical.Contains(m.Name) && sec >= stuckMin * 60) {
                    Log("Модуль «" + m.Title + "» завис: одно действие идёт " + (int)(sec / 60) + " мин" + (m.Doing.Length > 0 ? " (" + m.Doing + ")" : "") + " — перезапускаю агент", "ERROR");
                    return true;
                }
            }
            return false;
        }
        // команды, которые понимает агент (для веб-сервера: какие команды пропускать)
        static string[] AgentCommands()
        {
            lock (Mods) return new[] { "check-now" }.Concat(Mods.SelectMany(m => m.Commands)).Distinct().ToArray();
        }
        // для окна/веба
        static object[] ModulesInfo()
        {
            lock (Mods) return Mods.Select(m => (object)new Dictionary<string, object> {
                { "name", m.Name }, { "title", m.Title }, { "busy", m.Busy }, { "busySec", m.Busy ? (long)(DateTime.Now - m.BusySince).TotalSeconds : 0 }, { "doing", m.Doing },
                { "lastAgo", m.LastEnd == DateTime.MinValue ? -1 : (long)(DateTime.Now - m.LastEnd).TotalSeconds }, { "runs", m.Runs }, { "errors", m.Errors }, { "lastError", m.LastError } }).ToArray();
        }
    }
}
