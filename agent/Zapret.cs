// VpnGuard — агент на C#, шаг 2: zapret-discord-youtube (Flowseal).
// Установка/обновление из GitHub, winws.exe с выбранной стратегией, маршруты YouTube/Discord мимо VPN
// (диапазоны Google, видеосерверы провайдера, свои домены), проверка сайтов curl'ом напрямую, состояние для окна/веба.
// Подбор стратегии по-прежнему идёт отдельным процессом PowerShell (VpnGuard.ps1 -ZapretTest), агент забирает результат.
// Состояние — data\zapret-state.json в том же виде, что у Zapret.ps1 (можно переключаться между движками).
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace VpnGuard
{
    public static partial class Agent
    {
        const string ZRepo = "Flowseal/zapret-discord-youtube";
        static string ZStatePath { get { return Path.Combine(DataDir, "zapret-state.json"); } }
        static string ZTestPath { get { return Path.Combine(DataDir, "zapret-test.json"); } }
        static string ZGooglePath { get { return Path.Combine(DataDir, "zapret-google-ranges.json"); } }
        static Dictionary<string, object> Z;
        static string ZBadSig = "", ZVideoVia = "";
        static DateTime ZVideoMissAt = DateTime.MinValue;

        static Dictionary<string, object> ZDefaults { get { return Defaults; } }      // умолчания zapret.* — из config-schema.txt
        static readonly string[] ZDefTargets = { "https://www.youtube.com", "https://i.ytimg.com", "https://redirector.googlevideo.com", "https://discord.com", "https://gateway.discord.gg", "https://cdn.discordapp.com" };
        static readonly string[] ZDefDomains = { "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com", "gateway.discord.gg", "cdn.discordapp.com",
            "media.discordapp.net", "updates.discord.com", "dis.gd", "discord-attachments-uploads-prd.storage.googleapis.com" };

        // ---------------------------------------------------------------- настройки и состояние
        static bool ZDirect() { return Mode() == "zapret"; }
        static bool ZOn() { return ZDirect() || CfgBool("zapret.enabled", false); }   // в режиме «без VPN» zapret включён всегда
        static string ZC(string k) { object d; ZDefaults.TryGetValue("zapret." + k, out d); return CfgStr("zapret." + k, d == null ? "" : Convert.ToString(d, CultureInfo.InvariantCulture)); }
        static int ZI(string k) { object d; ZDefaults.TryGetValue("zapret." + k, out d); return CfgInt("zapret." + k, d is int ? (int)d : 0); }
        static bool ZB(string k) { object d; ZDefaults.TryGetValue("zapret." + k, out d); return CfgBool("zapret." + k, d is bool && (bool)d); }
        static string ZDir() { var d = ZC("dir"); return d.Length > 0 ? d : Path.Combine(Root, "zapret"); }
        static bool ZInstalled() { return File.Exists(Path.Combine(ZDir(), "bin", "winws.exe")); }

        static void ZLoad()
        {
            Z = new Dictionary<string, object>();
            try { var o = Json.DeserializeObject(File.ReadAllText(ZStatePath, Encoding.UTF8)) as Dictionary<string, object>; if (o != null) Z = o; } catch { }
        }
        static void ZSave()
        {
            try { var tmp = ZStatePath + ".tmp"; File.WriteAllText(tmp, Json.Serialize(Z), Bom); if (File.Exists(ZStatePath)) File.Replace(tmp, ZStatePath, null); else File.Move(tmp, ZStatePath); }
            catch (Exception e) { Log("zapret: не удалось сохранить состояние: " + e.Message, "WARN"); }
        }
        static string ZS(string k) { object v; return Z.TryGetValue(k, out v) && v != null ? Convert.ToString(v, CultureInfo.InvariantCulture) : ""; }
        static int ZN(string k) { int i; return int.TryParse(ZS(k), out i) ? i : 0; }
        static DateTime ZD(string k)
        {
            DateTime d; var s = ZS(k);
            if (s.Length == 0 || !DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out d)) return DateTime.MinValue;
            if (d.Year < 2000) return DateTime.MinValue;
            return d.Kind == DateTimeKind.Utc ? d.ToLocalTime() : d;
        }
        static void ZSetD(string k, DateTime d) { Z[k] = d == DateTime.MinValue ? DateTime.MinValue.ToString("o") : d.ToString("o"); }
        static List<object> ZArr(string k) { object v; var l = new List<object>(); if (Z.TryGetValue(k, out v) && v is IEnumerable && !(v is string)) foreach (var x in (IEnumerable)v) if (x != null) l.Add(x); return l; }
        static List<Dictionary<string, object>> ZRoutes() { return ZArr("routes").OfType<Dictionary<string, object>>().ToList(); }
        static Version Ver(string s) { var m = Regex.Match(s ?? "", @"\d+(\.\d+){1,3}"); return m.Success ? new Version(m.Value) : new Version(0, 0); }
        static string JS(object d, string k) { var x = d as Dictionary<string, object>; object v; return x != null && x.TryGetValue(k, out v) && v != null ? Convert.ToString(v, CultureInfo.InvariantCulture) : ""; }

        // ---------------------------------------------------------------- включение / выключение / наблюдение
        static void ZSetEnabled(bool on)
        {
            CfgSet("zapret.enabled", on);
            if (on) { Log("zapret: включён из окна", "INFO"); ZSetD("fallbackUntil", DateTime.MinValue); ZSave(); }
            else { Log("zapret: выключен из окна", "INFO"); ZDisableNow(); }
        }
        static void ZDisableNow()
        {
            var t = ZTestRunner();
            if (t != null) {
                int pid; int.TryParse(JS(t, "pid"), out pid);
                try { Process.GetProcessById(pid).Kill(); } catch { }
                File.WriteAllText(ZTestPath, Json.Serialize(new Dictionary<string, object> { { "running", false }, { "consumed", true }, { "error", "подбор прерван: zapret выключен" } }), Bom);
                Log("zapret: подбор стратегии прерван", "INFO");
            }
            if (ZRoutes().Count > 0) ZRemoveRoutes();
            if (ZN("winwsPid") > 0 || Process.GetProcessesByName("winws").Length > 0) { ZStopWinws(); Log("zapret: winws остановлен", "INFO"); }
            ZSave();
        }
        static void ZapretWatch()
        {
            if (Z == null) ZLoad();
            ZReceiveTest();
            try { ZReleases(false); } catch { }               // список версий для выбора — раз в 12 ч
            if (ZTestRunner() != null) return;                 // идёт подбор — winws и маршруты не трогаем
            bool on = ZOn();
            if (on || (ZB("autoUpdate") && ZInstalled())) ZUpdate(false);
            if (!on) {
                if (ZRoutes().Count > 0 || ZN("winwsPid") > 0) ZDisableNow();
                // winws, запущенный не нами (service.bat, вручную): при выключенном zapret меняет трафик YouTube/Discord и путает проверки
                var foreign = Process.GetProcessesByName("winws");
                if (foreign.Length > 0) {
                    foreach (var p in foreign) { string path = ""; try { path = p.MainModule.FileName; } catch { } Log("zapret выключен, но работает чужой winws (PID " + p.Id + ", " + path + ") — останавливаю", "WARN"); }
                    ZStopService(); ZStopWinws();
                }
                return;
            }
            if (!ZInstalled()) { Z["lastError"] = "zapret не установлен (нет доступа к GitHub?)"; return; }
            var fb = ZD("fallbackUntil");
            if (fb > DateTime.Now) { if (ZRoutes().Count > 0 || ZN("winwsPid") > 0) ZDisableNow(); return; }      // нет рабочей стратегии — ждём, трафик в VPN
            if (fb != DateTime.MinValue) { ZSetD("fallbackUntil", DateTime.MinValue); ZStartTest("повтор после неудачного подбора"); return; }

            string manual = ZC("strategy"), strategy = manual.Length > 0 ? manual : ZS("strategy");
            bool stale = (DateTime.Now - ZD("lastTest")).TotalHours >= ZI("retestHours");
            if (manual.Length == 0 && (strategy.Length == 0 || stale)) { ZStartTest(strategy.Length == 0 ? "стратегия ещё не выбрана" : "прошло больше " + ZI("retestHours") + " ч"); return; }
            if (!ZStrategies().Contains(strategy)) {
                Z["lastError"] = "стратегия '" + strategy + "' не найдена";
                if (manual.Length == 0) { Z["strategy"] = ""; ZStartTest("стратегия пропала после обновления"); }
                return;
            }
            if (ZWinws() == null || ZS("runningStrategy") != strategy) {
                ZStopService(); ZStopWinws();
                try {
                    SetActivity("запускаю zapret (" + strategy + ")");
                    ZStartWinws(strategy); Z["runningStrategy"] = strategy; Z["lastError"] = ""; ZSetD("healthAt", DateTime.MinValue);
                    Log("zapret: winws запущен со стратегией '" + strategy + "' (PID " + Z["winwsPid"] + ")", "INFO");
                } catch (Exception e) { Z["lastError"] = e.Message; Log("zapret: " + e.Message, "ERROR"); ZSave(); return; }
            }
            if (!ZDirect() && ZB("routeIspVideo")) { try { UpdateIspVideo(false); } catch (Exception e) { Log("zapret: видеосерверы провайдера: " + e.Message, "WARN"); } }
            ZSyncRoutes(false);
            if ((DateTime.Now - ZD("healthAt")).TotalMinutes >= ZI("healthCheckMin") && !InetBad()) {
                var path = ZPhys();
                if (path != null) {
                    var r = ZTest(path.Ip, ZTargets(), ZI("curlTimeoutSec"));
                    if (InetBad()) { ZSave(); return; }               // пока проверяли, связь начала пропадать — результат ничего не говорит о zapret
                    int ok = r.Count(x => x.Ok);
                    ZSetD("healthAt", DateTime.Now); Z["healthOk"] = ok; Z["healthTotal"] = r.Count; Z["healthChecks"] = ZChecks(r);
                    int minOk = Math.Max(1, Math.Min(ZN("lastScore"), r.Count) - 1);
                    var bad = r.Where(x => !x.Ok).ToList(); var sig = string.Join("|", bad.Select(x => x.Label));
                    if (bad.Count > 0 && (sig != ZBadSig || ok < minOk)) Log("zapret: не прошли проверку: " + string.Join("; ", bad.Select(x => x.Label + " — " + x.Why)), ok < minOk ? "WARN" : "INFO");
                    else if (bad.Count == 0 && ZBadSig.Length > 0) Log("zapret: все проверки снова проходят", "INFO");
                    ZBadSig = sig;
                    // видео YouTube не грузится или медленное — сайт может открываться, а смотреть нельзя: тоже повод переподобрать
                    // (не чаще раза в 6 ч — если медленно со всеми стратегиями, не прерывать YouTube постоянно)
                    bool videoBad = bad.Any(x => x.Url == "ytspeed" || x.Url == "ytvideo") && (DateTime.Now - ZD("videoRetestAt")).TotalHours >= 6;
                    if (ok < minOk || videoBad) {
                        Z["healthFails"] = ZN("healthFails") + 1;
                        Log(ok < minOk ? "zapret: открылось " + ok + "/" + r.Count + " сайтов" : "zapret: видео YouTube с этой стратегией не идёт или медленное (" + ZN("healthFails") + "/2)", "WARN");
                        if (ZN("healthFails") >= 2 && manual.Length == 0) {
                            Z["healthFails"] = 0;
                            if (ok >= minOk) ZSetD("videoRetestAt", DateTime.Now);
                            ZStartTest(ok < minOk ? "стратегия перестала работать" : "видео YouTube медленное или не грузится");
                        }
                    } else Z["healthFails"] = 0;
                }
            }
            ZSave();
        }
        static void ZReload()
        {
            if (!ZOn()) { Log("zapret: списки сохранены — применятся при включении zapret", "INFO"); return; }
            SetActivity("zapret: применяю списки");
            var name = ZS("runningStrategy");
            if (name.Length > 0) { ZStopWinws(); Thread.Sleep(500); try { ZStartWinws(name); Z["runningStrategy"] = name; } catch (Exception e) { Log("zapret: перезапуск winws: " + e.Message, "ERROR"); } }
            try { ZSyncRoutes(true); } catch (Exception e) { Log("zapret: маршруты: " + e.Message, "ERROR"); }
            ZSave(); Log("zapret: списки применены — winws перезапущен, маршруты пересчитаны", "INFO");
        }
        // команды zapret из окна/веба; false — команда не про zapret
        static bool ZCommand(string a)
        {
            if (Z == null) ZLoad();
            switch (a) {
                case "zapret-on": ZSetEnabled(true); return true;
                case "zapret-off": ZSetEnabled(false); return true;
                case "zapret-check": ZSetD("healthAt", DateTime.MinValue); return true;
                case "zapret-releases": ZReleases(true); return true;
                case "zapret-update": ZUpdate(true); return true;
                case "zapret-reload": ZReload(); return true;
                case "zapret-test": if (CfgBool("zapret.enabled", false) || ZDirect()) ZDisableNow(); ZStartTest("по команде из окна"); return true;
            }
            return false;
        }

        // ---------------------------------------------------------------- состояние
        static string ZKey = ""; static HashSet<uint> ZHosts; static List<uint[]> ZNets;
        static uint HostU(IPAddress a) { var b = a.GetAddressBytes(); return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]; }
        static int ZConnCount()
        {
            var routes = ZRoutes(); if (routes.Count == 0) return 0;
            var key = routes.Count + "|" + ZS("lastRouteRefresh");
            if (key != ZKey) {
                ZHosts = new HashSet<uint>(); ZNets = new List<uint[]>();
                foreach (var r in routes) {
                    var pp = JS(r, "p").Split('/'); IPAddress ip; int len;
                    if (pp.Length != 2 || !IPAddress.TryParse(pp[0], out ip) || !int.TryParse(pp[1], out len)) continue;
                    uint v = HostU(ip);
                    if (len >= 32) ZHosts.Add(v); else { uint m = len == 0 ? 0 : 0xFFFFFFFFu << (32 - len); ZNets.Add(new[] { v & m, m }); }
                }
                ZKey = key;
            }
            int n = 0;
            foreach (var c in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()) {
                if (c.State != TcpState.Established) continue;
                var a = c.RemoteEndPoint.Address; if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
                if (a.AddressFamily != AddressFamily.InterNetwork) continue;
                uint v = HostU(a);
                if (ZHosts.Contains(v)) { n++; continue; }
                foreach (var nt in ZNets) if ((v & nt[1]) == nt[0]) { n++; break; }
            }
            return n;
        }
        static string Dt(DateTime d) { return d == DateTime.MinValue ? "—" : d.ToString("dd.MM.yyyy HH:mm:ss"); }
        static object ZSnapshotSafe()
        {
            try { return ZSnapshot(); }
            catch (Exception e) { return new Dictionary<string, object> { { "level", 2 }, { "state", "Ошибка" }, { "details", new[] { e.Message } }, { "kv", new object[0] }, { "enabled", CfgBool("zapret.enabled", false) } }; }
        }
        static Dictionary<string, object> ZSnapshot()
        {
            if (Z == null) ZLoad();
            bool on = ZOn(); var t = ZTestRunner(); bool inst = ZInstalled();
            string manual = ZC("strategy"), strategy = manual.Length > 0 ? manual : ZS("strategy");
            bool winws = ZWinws() != null;
            var checks = ZArr("healthChecks").OfType<Dictionary<string, object>>().ToList();
            int hOk = ZN("healthOk"), hTot = ZN("healthTotal");
            int lv; string st;
            if (t != null) { lv = 1; st = "Подбор стратегии " + JS(t, "index") + "/" + JS(t, "total"); }
            else if (!on) { lv = -1; st = "Выключен"; }
            else if (!inst) { lv = 2; st = "Не установлен"; }
            else if (ZD("fallbackUntil") > DateTime.Now) { lv = 1; st = ZDirect() ? "Нет рабочей стратегии — повтор позже" : "Нет рабочей стратегии — всё через VPN"; }
            else if (ZS("lastError").Length > 0) { lv = 2; st = "Ошибка"; }
            else if (!winws) { lv = 1; st = "Запускается"; }
            else if (hTot > 0 && hOk < hTot) { lv = 1; st = "Работает частично (" + hOk + "/" + hTot + ")"; if (checks.Any(c => JS(c, "ok") != "True" && JS(c, "n").Contains("видео"))) st = "Нет видео YouTube"; }
            else { lv = 0; st = "Работает"; }
            string ver = ZS("version").Length > 0 ? ZS("version") : ZLocalVersion(), remote = ZS("remoteVersion");
            string verLine = "Версия: " + (ver.Length > 0 ? ver : "не установлен") + (remote.Length > 0 && ver.Length > 0 && Ver(remote) > Ver(ver) ? " (есть " + remote + ")" : "");
            bool vpnOn = !ZDirect();
            string vpnWarn = !on || !vpnOn ? "" : CzWanted()
                ? "Включён вместе с VPN: YouTube и Discord этого ПК и клиентов WG-Server идут мимо VPN через zapret («zapret для клиентов» на вкладке WG-Server: агент пропускает их через zapret этого ПК). Остальной трафик — через VPN."
                : "Включён вместе с VPN: YouTube и Discord этого ПК идут мимо VPN через zapret (провайдер их замедляет), а у клиентов WG-Server, пока zapret включён, они не открываются — zapret обрабатывает только трафик самого ПК. Включите «zapret для клиентов» на вкладке WG-Server — тогда и у них YouTube/Discord пойдут через zapret.";
            var bad = checks.Where(c => JS(c, "ok") != "True").ToList();
            int routesN = ZRoutes().Count; DateTime hAt = ZD("healthAt");
            var details = new List<string> { vpnWarn, verLine,
                "Стратегия: " + (strategy.Length > 0 ? strategy + (manual.Length > 0 ? " (вручную)" : ZN("lastTotal") > 0 ? " · " + ZN("lastScore") + "/" + ZN("lastTotal") + " при подборе" : "") : "—"),
                t != null ? "Сейчас проверяю: " + JS(t, "current") : hTot > 0 ? "Проверка " + When(hAt) + ": открылось " + hOk + "/" + hTot : "Проверка: ещё не было",
                t == null && bad.Count > 0 ? "Не прошли: " + string.Join("; ", bad.Select(c => JS(c, "n") + " (" + JS(c, "why") + ")")) : "",
                "Маршрутов мимо VPN: " + routesN, ZS("lastError").Length > 0 ? "Ошибка: " + ZS("lastError") : "" };
            int conns = 0; if (on) { try { conns = ZConnCount(); } catch { } }
            string ts = ""; try { ts = ZTcpTimestamps(); } catch { }
            string via = ZS("videoHostVia"); var ggc = ZArr("ggc").Select(x => Convert.ToString(x)).ToList();
            var kv = new List<object[]> {
                Kv("Включён", on ? "да" + (vpnOn ? " — вместе с VPN (см. предупреждение выше)" : " — режим «Без VPN»") : "нет"),
                Kv("Версия", ver.Length > 0 ? ver : "не установлен"), Kv("На GitHub", remote.Length > 0 ? remote : "—"),
                Kv("Выбранная версия", ZC("version").Length > 0 ? ZC("version") + " — закреплена, не обновляется" : "последняя (обновляется сама)"),
                Kv("Проверка обновлений", Dt(ZD("lastUpdateCheck"))),
                Kv("Стратегия", strategy.Length > 0 ? strategy + (manual.Length > 0 ? " (выбрана вручную)" : " (подобрана)") : "—"),
                Kv("Запущена", winws ? ZS("runningStrategy") + " · winws PID " + ZN("winwsPid") : "winws не запущен"),
                Kv("Последний подбор", Dt(ZD("lastTest"))), Kv("Проверка сайтов", hTot > 0 ? hOk + "/" + hTot + " · " + Dt(hAt) : "—"),
                Kv("Метки времени TCP", ts == "Enabled" ? "включены" : ts.Length > 0 ? ts + " — включатся при запуске zapret" : "—"),
                Kv("Видеосервер YouTube", ZS("videoHost").Length > 0 ? ZS("videoHost") + (via == "direct" ? " (провайдера, найден напрямую)" : via == "vpn" ? " (найден через VPN — не тот, что у браузера)" : "") : "—"),
                Kv("Видеосерверы провайдера мимо VPN", ggc.Count > 0 ? string.Join(", ", ggc) : "—"), Kv("Маршрутов мимо VPN", routesN),
                Kv("Соединений мимо VPN сейчас", on ? conns + " (TCP к YouTube/Discord и своим доменам)" : "—"), Kv("Папка", ZDir()) };
            var snap = Comp(lv, st, details, kv);
            snap["enabled"] = on; snap["strategies"] = ZStrategies().ToArray(); snap["testing"] = t != null; snap["results"] = ZArr("results").ToArray();
            snap["current"] = strategy; snap["manual"] = manual; snap["running"] = ZS("runningStrategy"); snap["checks"] = checks.ToArray();
            snap["checkedAt"] = hAt != DateTime.MinValue ? hAt.ToString("HH:mm") : ""; snap["videoCheck"] = ZB("videoCheck"); snap["vpnWarn"] = vpnWarn;
            snap["version"] = ver; snap["pinned"] = ZC("version"); snap["latest"] = remote;
            snap["versions"] = ZArr("releases").Select(r => (object)new Dictionary<string, object> { { "v", JS(r, "v") }, { "date", JS(r, "date") }, { "pre", JS(r, "pre") == "True" } }).ToArray();
            snap["conns"] = conns; snap["dir"] = ZDir();
            snap["progress"] = t != null ? new Dictionary<string, object> { { "index", t.ContainsKey("index") ? t["index"] : 0 }, { "total", t.ContainsKey("total") ? t["total"] : 0 }, { "current", JS(t, "current") } } : null;
            return snap;
        }
    }
}
