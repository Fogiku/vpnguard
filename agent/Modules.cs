// Модули агента: у каждого свой поток, свой ритм и своя очередь команд. Долгое действие одного модуля (переподключение VPN,
// перезапуск службы, тест zapret) не задерживает остальные. Главный поток (Run) только следит: настройки, команды, обновление кода,
// зависшие модули. Новый модуль — новый файл agent\*.cs и строка в StartModules().
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
            public string[] Commands = new string[0];
            public int WarnAfterSec = 180;               // одно действие дольше — предупреждение в журнале
            public readonly AutoResetEvent Wake = new AutoResetEvent(false);
            public readonly ConcurrentQueue<string> Cmds = new ConcurrentQueue<string>();
            public volatile bool Busy; public DateTime BusySince = DateTime.MinValue, LastEnd = DateTime.MinValue;
            public long Runs, Errors; public string LastError = "", Doing = ""; public bool Warned;
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

        static void StartModules()
        {
            AddModule("tunnels", "Туннели", CheckMs, () => VpnWatch(), TunnelCmd,
                "reconnect", "reconnect-meduza", "reconnect-awg", "restart-meduza", "meduza-test", "meduza-catalog", "meduza-proto-reset", "dual-switch");
            AddModule("wg", "WG-Server", () => 15000, () => { WgWatch(); WgClientsWatch(); }, c => { if (c == "restart-wg") { SvcRestart(CfgStr("ws4w.serviceName", "")); RequestIcs(); } }, "restart-wg");
            AddModule("ics", "Раздача", () => 10000, SharingWatch, c => { if (c == "reapply-ics") ForceIcs = true; }, "reapply-ics");
            AddModule("zapret", "zapret", CheckMs, () => { ZapretWatch(); ClientZapretWatch(); LanWatch(); }, c => ZCommand(c),
                "zapret-on", "zapret-off", "zapret-check", "zapret-releases", "zapret-update", "zapret-reload", "zapret-test");
            AddModule("ps", "Часть PowerShell", () => 10000, PsPartWatch);
            AddModule("status", "Сводка", () => 10000, Snapshot);
            AddModule("failover", "Быстрое переключение", () => Math.Max(2, CfgInt("vpn.fastCheckSec", 5)) * 1000, FailoverTick);
            foreach (var m in Mods.ToList()) { var mm = m; new Thread(() => ModuleLoop(mm)) { IsBackground = true, Name = "mod-" + m.Name }.Start(); }
        }
        static void ModuleLoop(Module m)
        {
            PerfThread("модуль: " + m.Title); CurModule = m.Name;
            Thread.Sleep(200);
            while (!Stopping) {
                string c;
                while (m.Cmds.TryDequeue(out c)) {
                    m.Busy = true; m.BusySince = DateTime.Now; m.Doing = "команда " + c; m.Warned = false;
                    try { PerfRun(m.Name + "/" + c, () => m.OnCmd(c)); }
                    catch (Exception e) { Log("Модуль «" + m.Title + "»: команда " + c + ": " + e.Message, "ERROR"); }
                    finally { m.Busy = false; if (ActivityBy == m.Name) Activity = ""; }
                    Wake("status");
                }
                m.Busy = true; m.BusySince = DateTime.Now; m.Doing = ""; m.Warned = false;
                try { PerfRun(m.Name, m.Tick); m.LastError = ""; }
                catch (Exception e) { m.Errors++; m.LastError = e.Message; Log("Модуль «" + m.Title + "»: " + e.Message, "ERROR"); }
                finally { m.Busy = false; m.LastEnd = DateTime.Now; m.Runs++; if (ActivityBy == m.Name && Activity.Length > 0) { Activity = ""; Wake("status"); } }
                int iv = 10000; try { iv = m.IntervalMs(); } catch { }
                m.Wake.WaitOne(Math.Max(500, iv));
            }
        }
        // разбудить модуль (проверить сейчас, не дожидаясь своего ритма)
        static void Wake(string name) { var m = FindModule(name); if (m != null) m.Wake.Set(); }
        // раздаче — перенастроиться сейчас
        static void RequestIcs() { ForceIcs = true; Wake("ics"); }

        // команды из окна / веба / удалённой диагностики: каждая — своему модулю; не наши — части PowerShell
        static void DispatchCommands()
        {
            List<string> files; try { files = Directory.GetFiles(CmdDir, "*.cmd").OrderBy(f => f).ToList(); } catch { return; }
            foreach (var f in files) {
                string a = ""; try { a = File.ReadAllText(f).Trim(); } catch { }
                if (a == "check-now") {
                    try { File.Delete(f); } catch { }
                    Log("Команда из монитора: check-now", "INFO");
                    lock (Mods) foreach (var m in Mods) m.Wake.Set();
                    continue;
                }
                Module to; lock (Mods) to = Mods.FirstOrDefault(m => m.Commands.Contains(a));
                if (to == null) {                            // остальное — PowerShell (обновления, установка компонентов …)
                    try { File.Move(f, Path.Combine(CmdPsDir, Path.GetFileName(f))); } catch { try { File.Delete(f); } catch { } }
                    PsPartAt = DateTime.MinValue; Wake("ps"); continue;
                }
                try { File.Delete(f); } catch { }
                Log("Команда из монитора: " + a + (to.Busy ? " (модуль «" + to.Title + "» сейчас занят: " + (to.Doing.Length > 0 ? to.Doing : "проверка") + " — выполню следом)" : ""), "INFO");
                to.Cmds.Enqueue(a); to.Wake.Set();
            }
        }
        // модуль слишком долго делает одно действие — в журнал (один раз за действие)
        static void WatchModules()
        {
            lock (Mods) foreach (var m in Mods) {
                if (!m.Busy || m.Warned) continue;
                var sec = (DateTime.Now - m.BusySince).TotalSeconds;
                if (sec >= m.WarnAfterSec) { m.Warned = true; Log("Модуль «" + m.Title + "» выполняет одно действие уже " + (int)sec + " с" + (m.Doing.Length > 0 ? " (" + m.Doing + ")" : "") + (Activity.Length > 0 ? " — сейчас: " + Activity : ""), "WARN"); }
            }
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
