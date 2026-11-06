// Туннель MeduzaVPN: приложение, CLI, подключение, протоколы, перезапуски.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32;


namespace VpnGuard
{
    public static partial class Agent
    {
        // ---------------------------------------------------------------- MeduzaVPN
        static string MzExe()
        {
            var p = CfgStr("meduza.exePath", ""); if (p.Length > 0) return p;
            var loc = MzUninstall("InstallLocation"); if (!string.IsNullOrEmpty(loc)) return Path.Combine(loc, "medusa_vpn.exe");
            return @"C:\Program Files\MeduzaVPN\medusa_vpn.exe";
        }
        static string MzUninstall(string value) { return Cached("mzu:" + value, 300, () => MzUninstallReg(value)); }
        static string MzUninstallReg(string value)
        {
            foreach (var root in new[] { @"Software\Microsoft\Windows\CurrentVersion\Uninstall", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" }) {
                try {
                    using (var k = Registry.LocalMachine.OpenSubKey(root)) {
                        if (k == null) continue;
                        foreach (var sub in k.GetSubKeyNames()) using (var s = k.OpenSubKey(sub)) {
                            var dn = s == null ? null : s.GetValue("DisplayName") as string;
                            if (dn != null && dn.StartsWith("MeduzaVPN", StringComparison.OrdinalIgnoreCase)) return Convert.ToString(s.GetValue(value));
                        }
                    }
                } catch { }
            }
            return null;
        }
        static string MzVersion()
        {
            var v = MzUninstall("DisplayVersion"); if (!string.IsNullOrEmpty(v)) return v;
            try { var e = MzExe(); if (File.Exists(e)) return FileVersionInfo.GetVersionInfo(e).ProductVersion; } catch { }
            return "0.0";
        }
        static string Cli() { var p = CfgStr("meduza.cliPath", ""); return p.Length > 0 ? p : Path.Combine(BinDir, "meduzavpn.exe"); }
        static bool MzPipe()
        {
            try { var want = @"\\.\pipe\" + CfgStr("meduza.pipeName", "MeduzaVPN"); return Directory.GetFiles(@"\\.\pipe\").Any(f => string.Equals(f, want, StringComparison.OrdinalIgnoreCase)); } catch { return false; }
        }
        static ExeResult MzCli(string args, int timeout) { if (!File.Exists(Cli())) return new ExeResult { Code = -2, Err = "CLI не найден" }; return Exe(Cli(), args, timeout); }
        static Process MzProc() { try { return Process.GetProcessesByName(CfgStr("meduza.processName", "medusa_vpn")).FirstOrDefault(); } catch { return null; } }
        static string MzProtocol() { return MzOverride.Length > 0 ? MzOverride : CfgStr("meduza.protocol", "ultra"); }
        static NetworkInterface MzAltUp() { try { return NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name.StartsWith("MeduzaVPN", StringComparison.OrdinalIgnoreCase) && n.OperationalStatus == OperationalStatus.Up); } catch { return null; } }
        static void MzResolveAdapter()
        {
            string want = CfgStr("meduza.adapterName", "MeduzaVPN ULTRA");
            if (Nic(want) != null) { MzAdapter = want; return; }
            NetworkInterface alt = null;
            try { alt = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.Name.StartsWith("MeduzaVPN", StringComparison.OrdinalIgnoreCase)).OrderBy(n => n.OperationalStatus == OperationalStatus.Up ? 0 : 1).FirstOrDefault(); } catch { }
            if (alt != null && alt.Name != MzAdapter) { Log("MeduzaVPN: адаптер туннеля сейчас называется «" + alt.Name + "» (протокол " + MzProtocol() + ") — использую его", "INFO"); MzAdapter = alt.Name; }
        }
        static bool MzConnect(int timeoutSec)
        {
            if (!MzPipe()) { Log("Канал управления MeduzaVPN недоступен (включите \"Управление из командной строки\" в настройках приложения) — жду автоподключения самого приложения", "WARN"); return false; }
            string proto = MzProtocol(), sid = CfgStr("meduza.serviceId", "");
            string a = "connect" + (sid.Length > 0 ? " \"" + sid + "\"" : "") + (proto.Length > 0 ? " --protocol " + proto : "") + " --wait";
            SetActivity("подключаю MeduzaVPN (" + proto + ")"); ReconnectCount++;
            Log("MeduzaVPN: meduzavpn " + a, "INFO");
            NetChanged(); var r = MzCli(a, timeoutSec > 0 ? timeoutSec : CfgInt("meduza.connectTimeoutSec", 90) + 30); NetChanged();
            if (r.Code != 0) Log("MeduzaVPN: connect завершился с кодом " + r.Code + ": " + r.Out + " " + r.Err, "WARN");
            var dl = DateTime.Now.AddSeconds(15);
            while (DateTime.Now < dl) {
                if (Up(MzAdapterName())) { Log("MeduzaVPN: туннель подключён (" + proto + ")", "INFO"); return true; }
                var alt = MzAltUp(); if (alt != null) { MzAdapter = alt.Name; Log("MeduzaVPN: подключён, адаптер «" + alt.Name + "» (" + proto + ")", "INFO"); return true; }
                Thread.Sleep(2000);
            }
            return Up(MzAdapterName());
        }
        static void MzDisconnect() { if (MzPipe()) { NetChanged(); var r = MzCli("disconnect", 30); NetChanged(); Log("MeduzaVPN: disconnect (код " + r.Code + ")", "INFO"); } }
        static void MzStart()
        {
            string exe = MzExe();
            if (!File.Exists(exe)) { Log("MeduzaVPN не найден: " + exe, "ERROR"); return; }
            Log("MeduzaVPN: запуск " + exe, "INFO"); SetActivity("запускаю MeduzaVPN");
            try { Process.Start(new ProcessStartInfo(exe) { WorkingDirectory = Path.GetDirectoryName(exe), UseShellExecute = true }); } catch (Exception e) { Log("MeduzaVPN: " + e.Message, "ERROR"); return; }
            MeduzaStartedAt = DateTime.Now; ProbeFailures = 0; NotResponding = 0; DownTicks = 0;
            var dl = DateTime.Now.AddSeconds(40); while (DateTime.Now < dl && !MzPipe()) Thread.Sleep(2000);
            Thread.Sleep(3000);
            if (!Up(MzAdapterName()) && MzPipe()) MzConnect(0);
        }
        static void MzStop()
        {
            MzDisconnect();
            foreach (var p in Process.GetProcessesByName(CfgStr("meduza.processName", "medusa_vpn"))) { Log("MeduzaVPN: остановка процесса", "INFO"); try { p.Kill(); p.WaitForExit(15000); } catch { } }
        }
        static void MzRestart(string reason)
        {
            if (InetBad()) { Log("MeduzaVPN: перезапуск отменён — нет интернета или он нестабилен (" + (InetWhy.Length > 0 ? InetWhy : "связь нестабильна") + ")", "INFO"); return; }
            Restarts.RemoveAll(d => d < DateTime.Now.AddMinutes(-30));
            if (Restarts.Count >= CfgInt("meduza.maxRestartsPer30Min", 5)) { Log("MeduzaVPN: слишком много перезапусков за 30 мин, пауза (причина: " + reason + ")", "WARN"); return; }
            Restarts.Add(DateTime.Now); LastRestart = DateTime.Now; LastRestartReason = reason; RestartCount++;
            Log("MeduzaVPN: ПЕРЕЗАПУСК — " + reason, "WARN"); SetActivity("перезапускаю MeduzaVPN");
            MzStop(); Thread.Sleep(3000); MzStart();
        }
        static bool MzTraffic() { bool ok = ProbeVia(MzAdapterName(), 4000, null); LastTraffic = ok; LastTrafficAt = DateTime.Now; return ok; }
        static List<string> MzProtocols()
        {
            var l = new List<string>();
            if (Catalog != null && Catalog.ContainsKey("protocols")) foreach (Dictionary<string, object> p in (IEnumerable)Catalog["protocols"]) { var id = Convert.ToString(p["id"]); if (id.Length > 0) l.Add(id); }
            return l;
        }
        // список VPN и протоколов аккаунта (meduzavpn list --json), раз в час
        static void MzCatalog(bool force)
        {
            if (!force && Catalog != null && (DateTime.Now - CatalogAt).TotalMinutes < 60) return;
            if (!MzPipe() && !force) return;
            CatalogAt = DateTime.Now;
            var sv = MzCli("list --services --json", 30); var pr = MzCli("list --protocols --json", 30);
            var services = ParseList(sv.Out, "service|vpn|location|server"); var protocols = ParseList(pr.Out, "protocol");
            Catalog = new Dictionary<string, object> { { "services", services }, { "protocols", protocols }, { "at", DateTime.Now.ToString("HH:mm") },
                { "error", sv.Code != 0 ? ("list --services: код " + sv.Code + " " + sv.Err).Trim() : pr.Code != 0 ? ("list --protocols: код " + pr.Code + " " + pr.Err).Trim() : "" } };
            Log("MeduzaVPN: список VPN — " + services.Count + ", протоколов — " + protocols.Count + (Convert.ToString(Catalog["error"]).Length > 0 ? " (" + Catalog["error"] + ")" : ""), "INFO");
        }
        static List<object> ParseList(string text, string kind)
        {
            var res = new List<object>(); object o;
            try { o = Json.DeserializeObject(text); } catch { return res; }
            IEnumerable arr = null;
            if (o is object[]) arr = (object[])o;
            else if (o is Dictionary<string, object>) foreach (var kv in (Dictionary<string, object>)o) { if (kv.Value is object[] && (arr == null || Regex.IsMatch(kv.Key, kind))) { arr = (object[])kv.Value; if (Regex.IsMatch(kv.Key, kind)) break; } }
            if (arr == null) return res;
            Func<Dictionary<string, object>, string[], string> pick = (x, names) => { foreach (var n in names) { object v; if (x.TryGetValue(n, out v) && v != null && Convert.ToString(v).Length > 0) return Convert.ToString(v); } return ""; };
            foreach (var x in arr) {
                if (x == null) continue;
                var d = x as Dictionary<string, object>;
                if (d == null) { res.Add(new Dictionary<string, object> { { "id", Convert.ToString(x) }, { "name", Convert.ToString(x) }, { "info", "" } }); continue; }
                object av; if (d.TryGetValue("available", out av) && av is bool && !(bool)av) continue;      // в сборке для Windows нет движка
                string id = pick(d, new[] { "id", "service_id", "serviceId", "slug", "key", "name", "protocol" }), nm = pick(d, new[] { "title", "display_name", "displayName", "name", "location", "city", "country", "protocol", "id" });
                var info = string.Join(", ", new[] { "country", "location", "city", "region", "status", "type", "engine" }.Select(k => pick(d, new[] { k })).Where(v => v.Length > 0 && v != nm));
                res.Add(new Dictionary<string, object> { { "id", id }, { "name", nm }, { "info", info } });
            }
            return res;
        }
        // связь пропала, тот же протокол не помог — попробовать другие
        static bool MzProtoFallback(string reason)
        {
            if (!CfgBool("meduza.autoProtocol", true) || !MzPipe()) return false;
            if ((DateTime.Now - MzFallbackAt).TotalMinutes < 15) return false;
            if (InetBad()) return true;                 // интернета нет вообще — перебирать протоколы бессмысленно
            MzFallbackAt = DateTime.Now;
            string cur = MzProtocol(), chosen = CfgStr("meduza.protocol", "ultra");
            try { MzCatalog(false); } catch { }
            var tested = new List<string>();
            if (ProtoTest != null && ProtoTest.ContainsKey("results")) foreach (Dictionary<string, object> r in ((IEnumerable)ProtoTest["results"]).Cast<Dictionary<string, object>>().Where(r => r["ok"] is bool && (bool)r["ok"]).OrderBy(r => Convert.ToInt32(r["pingMs"]))) tested.Add(Convert.ToString(r["protocol"]));
            var same = new[] { cur, "meduza-" + cur, Regex.Replace(cur, "^meduza-", "") };
            // протокол wireguard у MeduzaVPN включает блокировку всего трафика мимо своего туннеля (kill switch WireGuard): на время попытки
            // пропадают резервный туннель, маршруты zapret и локальная сеть — при автоматическом переборе его не пробуем (meduza.protoFallbackSkip)
            var skip = new HashSet<string>(CfgList("meduza.protoFallbackSkip", new[] { "wireguard" }).Select(x => x.Trim().ToLowerInvariant()));
            var order = tested.Concat(MzProtocols()).Concat(new[] { chosen }).Where(p => p.Length > 0 && !same.Contains(p) && !skip.Contains(p.ToLowerInvariant()) && !skip.Contains(Regex.Replace(p.ToLowerInvariant(), "^meduza-", ""))).Distinct().ToList();
            if (order.Count == 0) { Log("MeduzaVPN: " + reason + " — других протоколов нет (список не получен), пробовать нечего", "WARN"); return false; }
            Log("MeduzaVPN: " + reason + ", протокол " + cur + " — пробую другие: " + string.Join(", ", order), "WARN");
            string prev = MzOverride; int noConn = 0, maxNoConn = Math.Max(2, CfgInt("meduza.fallbackMaxTimeouts", 3));
            foreach (var p in order) {
                if (InetBad()) { MzOverride = prev; Log("MeduzaVPN: пропал интернет — перебор протоколов прерван", "WARN"); MzDisconnect(); Thread.Sleep(1000); MzConnect(0); return true; }
                DualMidCheck();
                SetActivity("MeduzaVPN: пробую протокол " + p);
                MzDisconnect(); Thread.Sleep(2000);
                MzOverride = (p == chosen || p == "meduza-" + chosen) ? "" : p;
                bool conn = MzConnect(60);
                if (conn && MzTraffic()) {
                    MzProtoSince = DateTime.Now; MzReturnAt = DateTime.Now; ProbeFailures = 0; DownTicks = 0; IcsIfUplink("meduza");
                    Log(MzOverride.Length > 0 ? "MeduzaVPN: протокол " + cur + " не работает — переключился на " + p + " (выбран в настройках: " + chosen + "; агент будет пробовать вернуть его)" : "MeduzaVPN: снова работает выбранный протокол " + p, "WARN");
                    return true;
                }
                Log("MeduzaVPN: протокол " + p + " тоже не работает" + (conn ? "" : " (не подключился)"), "WARN");
                noConn = conn ? 0 : noConn + 1;
                if (noConn >= maxNoConn) {
                    MzOverride = prev;
                    Log("MeduzaVPN: " + noConn + " протокола подряд не подключились, а интернет есть — похоже, недоступен сам сервис MeduzaVPN, перебирать дальше бессмысленно. Перебор прерван, повторю через 15 мин", "WARN");
                    MzDisconnect(); Thread.Sleep(1000); MzConnect(0); return false;
                }
                try { WgWatch(); } catch { }                 // перебор долгий — WG-Server не должен ждать
            }
            MzOverride = prev; Log("MeduzaVPN: ни один протокол не заработал", "WARN"); return false;
        }
        static void MzProtoReturn()
        {
            int mins = CfgInt("meduza.protocolReturnMin", 60);
            if (MzOverride.Length == 0 || mins <= 0 || (DateTime.Now - MzReturnAt).TotalMinutes < mins) return;
            MzReturnAt = DateTime.Now; string alt = MzOverride, chosen = CfgStr("meduza.protocol", "ultra");
            Log("MeduzaVPN: пробую вернуть выбранный протокол " + chosen + " (сейчас работает " + alt + ")", "INFO");
            MzDisconnect(); Thread.Sleep(2000); MzOverride = "";
            if (MzConnect(60) && MzTraffic()) { Log("MeduzaVPN: выбранный протокол " + chosen + " снова работает", "INFO"); IcsIfUplink("meduza"); return; }
            Log("MeduzaVPN: " + chosen + " по-прежнему не работает — остаюсь на " + alt, "WARN");
            MzOverride = alt; MzDisconnect(); Thread.Sleep(2000); MzConnect(0); IcsIfUplink("meduza");
        }
        static void MzProtoTest()
        {
            if (!MzPipe()) { Log("MeduzaVPN: тест протоколов невозможен — канал CLI недоступен", "WARN"); return; }
            MzCatalog(true);
            var protos = MzProtocols(); if (protos.Count == 0) protos.Add(CfgStr("meduza.protocol", "ultra"));
            var res = new List<object>();
            ProtoTest = new Dictionary<string, object> { { "running", true }, { "index", 0 }, { "total", protos.Count }, { "current", "" }, { "results", res }, { "at", "" } };
            Log("MeduzaVPN: тест протоколов: " + string.Join(", ", protos) + " (клиенты wg_server на время теста могут терять интернет)", "WARN");
            string sid = CfgStr("meduza.serviceId", ""); int i = 0;
            foreach (var p in protos) {
                i++; ProtoTest["index"] = i; ProtoTest["current"] = p; SetActivity("тест протокола " + p + " (" + i + "/" + protos.Count + ")");
                MzDisconnect(); Thread.Sleep(2000);
                var sw = Stopwatch.StartNew();
                var r = MzCli("connect" + (sid.Length > 0 ? " \"" + sid + "\"" : "") + " --protocol " + p + " --wait", CfgInt("meduza.connectTimeoutSec", 90) + 30);
                string ad = null; var dl = DateTime.Now.AddSeconds(15);
                while (DateTime.Now < dl && ad == null) { var a = MzAltUp(); if (a != null) ad = a.Name; else Thread.Sleep(1000); }
                double conn = Math.Round(sw.Elapsed.TotalSeconds, 1);
                var ms = new List<long>(); if (ad != null) { Thread.Sleep(2000); ProbeVia(ad, 3000, ms); }
                string err = r.Code != 0 ? Regex.Replace(r.Err + " " + r.Out, @"\s+", " ").Trim() : ""; if (err.Length > 120) err = err.Substring(0, 120) + "…";
                if (ad == null && err.Length == 0) err = "туннель не поднялся";
                res.Add(new Dictionary<string, object> { { "protocol", p }, { "ok", ms.Count > 0 }, { "probes", ms.Count + "/" + ProbeHosts().Length }, { "connectSec", conn }, { "pingMs", ms.Count > 0 ? (int)ms.Average() : -1 }, { "adapter", ad ?? "" }, { "error", err } });
                Log("MeduzaVPN: тест " + p + ": " + (ms.Count > 0 ? "работает (" + ms.Count + "/" + ProbeHosts().Length + ")" : "НЕ работает") + ", подключение " + conn + " с, " + (ms.Count > 0 ? "отклик " + (int)ms.Average() + " мс" : err), "INFO");
                Snapshot();
            }
            ProtoTest["running"] = false; ProtoTest["current"] = ""; ProtoTest["at"] = DateTime.Now.ToString("dd.MM HH:mm");
            SetActivity("возвращаю протокол " + MzProtocol());
            MzDisconnect(); Thread.Sleep(2000); MzConnect(0); MzResolveAdapter(); IcsIfUplink("meduza");
            var ok = res.Cast<Dictionary<string, object>>().Where(x => (bool)x["ok"]).OrderBy(x => (int)x["pingMs"]).Select(x => x["protocol"] + " (" + x["pingMs"] + " мс)").ToList();
            Log("MeduzaVPN: тест протоколов завершён — работают: " + (ok.Count > 0 ? string.Join(", ", ok) : "ни один"), "INFO");
        }
        static bool MzUpdating() { return File.Exists(Path.Combine(DataDir, "meduza-updating.flag")) && (DateTime.Now - File.GetLastWriteTime(Path.Combine(DataDir, "meduza-updating.flag"))).TotalMinutes < 30; }
        static void MeduzaWatch()
        {
            if (MzUpdating()) return;                    // идёт обновление MeduzaVPN (PowerShell) — не мешать
            MzResolveAdapter();
            try { MzCatalog(false); } catch { }
            var proc = MzProc();
            if (proc == null) { Log("MeduzaVPN: процесс не запущен", "WARN"); MzStart(); return; }
            bool responding = true; try { responding = proc.Responding; } catch { }
            if (!responding) { if (++NotResponding >= 4) { MzRestart("приложение не отвечает"); return; } } else NotResponding = 0;
            if (Up(MzAdapterName())) {
                DownTicks = 0;
                if (MzTraffic()) { ProbeFailures = 0; MzProtoReturn(); return; }
                ProbeFailures++;
                Log("MeduzaVPN: нет трафика через туннель (" + ProbeFailures + "/" + CfgInt("meduza.probeFailuresBeforeReconnect", 3) + ")", "WARN");
                if (ProbeFailures >= CfgInt("meduza.probeFailuresBeforeReconnect", 3)) {
                    ProbeFailures = 0;
                    if (MzPipe()) {
                        MzDisconnect(); Thread.Sleep(3000);
                        if (MzConnect(0) && MzTraffic()) return;
                        if (MzProtoFallback("нет трафика через туннель")) return;
                    }
                    MzRestart("туннель не пропускает трафик");
                }
                return;
            }
            LastTraffic = null;
            if ((DateTime.Now - MeduzaStartedAt).TotalSeconds < CfgInt("meduza.startupGraceSec", 60)) return;
            DownTicks++;
            Log("MeduzaVPN: адаптер '" + MzAdapterName() + "' не поднят", "WARN");
            if (MzConnect(0)) { DownTicks = 0; return; }
            if (DownTicks >= 2 && MzProtoFallback("туннель не подключается")) { DownTicks = 0; return; }
            if (DownTicks >= 3) { DownTicks = 0; MzRestart("туннель не подключается"); }
        }

        // для окна и веба (сводка): часть «MeduzaVPN»
        static Dictionary<string, object> MeduzaComp(string mode, string kind, Dictionary<string, object> ps)
        {
            var proc = MzProc(); bool pipe = MzPipe(); string ver = MzVersion(); bool updating = MzUpdating();
            // MeduzaVPN
            int mL; string mS; bool responding = true; try { if (proc != null) responding = proc.Responding; } catch { }
            if (updating) { mL = 1; mS = "Обновляется"; } else if (proc == null) { mL = 2; mS = "Не запущен"; } else if (!responding) { mL = 1; mS = "Не отвечает"; } else { mL = 0; mS = "Работает"; }
            if (mode != "meduza" && mode != "dual" && !updating) { mL = -1; mS = proc != null ? "Не используется (запущен)" : "Не используется"; }
            else if (mode == "dual" && mL == 0) {
                if (!Up(MzAdapterName())) { mL = 1; mS = "Туннель не подключён"; } else if (LastTraffic == false) { mL = 1; mS = "Нет трафика"; } else mS = kind == "meduza" ? "Работает · активный" : "Работает · резерв";
            }
            string remoteVer = ps.ContainsKey("meduzaRemoteVersion") ? Convert.ToString(ps["meduzaRemoteVersion"]) : "";
            string started = ""; try { if (proc != null) started = proc.StartTime.ToString("dd.MM HH:mm"); } catch { }
            var meduza = Comp(mL, mS, new[] { "Версия " + ver + (remoteVer.Length > 0 && remoteVer != ver ? " (есть " + remoteVer + ")" : ""), proc != null ? "PID " + proc.Id + (started.Length > 0 ? ", с " + started : "") : "процесс отсутствует",
                "Канал CLI: " + (pipe ? "доступен" : "нет") + " · протокол " + MzProtocol() + (MzOverride.Length > 0 ? " (запасной вместо " + CfgStr("meduza.protocol", "ultra") + ")" : ""),
                "Перезапуски: " + Restarts.ToArray().Count(d => d > DateTime.Now.AddMinutes(-30)) + " за 30 мин, посл. " + When(LastRestart) }, new List<object[]> {
                Kv("Версия", ver), Kv("Доступная версия", remoteVer.Length > 0 ? remoteVer : "—"), Kv("Последняя проверка обновлений", ps.ContainsKey("meduzaLastCheck") ? ps["meduzaLastCheck"] : "—"),
                Kv("Процесс", proc != null ? "PID " + proc.Id + (responding ? "" : " (не отвечает)") : "не запущен"), Kv("Память", proc != null ? (proc.WorkingSet64 / 1048576) + " МБ" : "—"),
                Kv("Канал CLI", pipe ? "доступен" : "нет — включите управление из командной строки"),
                Kv("VPN (страна)", CfgStr("meduza.serviceId", "").Length > 0 ? CfgStr("meduza.serviceId", "") : "по умолчанию (единственный на аккаунте)"),
                Kv("Протокол", MzProtocol() + (MzOverride.Length > 0 ? " — запасной, выбранный " + CfgStr("meduza.protocol", "ultra") + " не работал (с " + When(MzProtoSince) + ")" : "") + " · адаптер «" + MzAdapterName() + "»"),
                Kv("Автоподбор протокола", CfgBool("meduza.autoProtocol", true) ? "включён — при потере связи пробует другие протоколы" : "выключен"),
                Kv("Перезапусков за 30 мин", Restarts.ToArray().Count(d => d > DateTime.Now.AddMinutes(-30)) + " из " + CfgInt("meduza.maxRestartsPer30Min", 5) + " допустимых"),
                Kv("Перезапусков с запуска агента", RestartCount), Kv("Последний перезапуск", When(LastRestart)), Kv("Причина", LastRestartReason.Length > 0 ? LastRestartReason : "—") });
            meduza["serviceId"] = CfgStr("meduza.serviceId", ""); meduza["protocol"] = CfgStr("meduza.protocol", "ultra"); meduza["adapter"] = MzAdapterName();
            meduza["catalog"] = Catalog; meduza["protoTest"] = ProtoTest; meduza["protocolNow"] = MzProtocol(); meduza["protocolOverride"] = MzOverride;
            return meduza;
        }
    }
}
