// Туннель AmneziaVPN: приложение, служба, адаптер, проверка трафика, перезапуски.
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
        // ---------------------------------------------------------------- AmneziaVPN (режим amnezia)
        // Приложение AmneziaVPN: сервер и протокол выбираются в нём самом, командной строки нет. Агент держит его запущенным,
        // находит адаптер туннеля (имя/описание по шаблону — зависит от протокола), проверяет трафик и при сбое перезапускает
        // приложение и его службу (туннель поднимается сам, если в AmneziaVPN включено «Автоподключение»).
        static string AvpnLastAdapter = ""; static DateTime AvpnStartedAt = DateTime.MinValue;
        static string AwgExe()
        {
            var p = CfgStr("amnezia.exe", ""); if (p.IndexOf("AmneziaVPN", StringComparison.OrdinalIgnoreCase) >= 0 && p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return p;
            var loc = AppUninstall("^AmneziaVPN", "InstallLocation");
            if (!string.IsNullOrEmpty(loc) && File.Exists(Path.Combine(loc, "AmneziaVPN.exe"))) return Path.Combine(loc, "AmneziaVPN.exe");
            return @"C:\Program Files\AmneziaVPN\AmneziaVPN.exe";
        }
        static string AppUninstall(string nameRx, string value) { return Cached("au:" + nameRx + "|" + value, 300, () => AppUninstallReg(nameRx, value)); }
        static string AppUninstallReg(string nameRx, string value)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
                foreach (var root in new[] { @"Software\Microsoft\Windows\CurrentVersion\Uninstall", @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" }) {
                    try {
                        using (var k = hive.OpenSubKey(root)) {
                            if (k == null) continue;
                            foreach (var sub in k.GetSubKeyNames()) using (var s = k.OpenSubKey(sub)) {
                                var dn = s == null ? null : s.GetValue("DisplayName") as string;
                                if (dn != null && Regex.IsMatch(dn, nameRx, RegexOptions.IgnoreCase)) return Convert.ToString(s.GetValue(value));
                            }
                        }
                    } catch { }
                }
            return null;
        }
        static string AvpnSvcName() { return CfgStr("amnezia.serviceName", "AmneziaVPN-service"); }
        static string AvpnPattern() { return CfgStr("amnezia.adapterPattern", "amnezia|tun2socks|TAP-Windows Adapter V9"); }
        static Process AvpnProc() { try { return Process.GetProcessesByName("AmneziaVPN").FirstOrDefault(); } catch { return null; } }
        // адаптер туннеля (поднятый — в первую очередь); имя запоминаем — оно нужно раздаче, пока туннель переподключается
        static NetworkInterface AvpnNic()
        {
            NetworkInterface a = null;
            try {
                var rx = new Regex(AvpnPattern(), RegexOptions.IgnoreCase);
                a = AllNics().Where(n => rx.IsMatch(n.Name) || rx.IsMatch(n.Description))
                    .OrderBy(n => n.OperationalStatus == OperationalStatus.Up ? 0 : 1).FirstOrDefault();
            } catch { }
            if (a != null) AvpnLastAdapter = a.Name;
            return a;
        }
        static string AvpnAdapter() { var a = AvpnNic(); return a != null ? a.Name : AvpnLastAdapter; }
        static bool IsAvpnAlias(string alias)
        {
            if (string.IsNullOrEmpty(alias)) return false;
            if (alias == AvpnLastAdapter) return true;
            try { return Regex.IsMatch(alias, AvpnPattern(), RegexOptions.IgnoreCase); } catch { return false; }
        }
        static void AvpnStart()
        {
            var exe = AwgExe();
            if (!File.Exists(exe)) throw new Exception("AmneziaVPN не установлен (" + exe + ") — установите его на вкладке «Компоненты»");
            try { var s = Svc(AvpnSvcName()); if (s != null && s.Status != ServiceControllerStatus.Running) s.Start(); } catch (Exception e) { Log("AmneziaVPN: служба " + AvpnSvcName() + " не запускается: " + e.Message, "WARN"); }
            Log("AmneziaVPN: запуск " + exe, "INFO");
            Process.Start(new ProcessStartInfo(exe) { WorkingDirectory = Path.GetDirectoryName(exe), UseShellExecute = true, WindowStyle = ProcessWindowStyle.Minimized });
            AvpnStartedAt = DateTime.Now;
        }
        // закрыть приложение и разорвать туннель: служба AmneziaVPN держит его и без окна — перезапускаем её
        static void AvpnStop()
        {
            foreach (var p in Process.GetProcessesByName("AmneziaVPN")) { try { p.Kill(); p.WaitForExit(10000); } catch { } }
            try { foreach (var s in ServiceController.GetServices().Where(x => x.ServiceName.StartsWith("AmneziaWGTunnel$", StringComparison.OrdinalIgnoreCase) && x.ServiceName.IndexOf("AmneziaVPN", StringComparison.OrdinalIgnoreCase) >= 0 && x.Status == ServiceControllerStatus.Running)) s.Stop(); } catch { }
            SvcHardRestart(AvpnSvcName());
        }
        static string WaitAvpnUp(int sec)
        {
            var dl = DateTime.Now.AddSeconds(sec);
            do { var a = AvpnNic(); if (a != null && a.OperationalStatus == OperationalStatus.Up) return a.Name; Thread.Sleep(2000); } while (DateTime.Now < dl);
            return null;
        }
        static TunDiagRes AwgDiag; static string AwgDiagLogged = "";
        static bool AwgTrafficOk(string name)
        {
            bool ok = false;
            {
                try {
                    var d = TunDiag(name); AwgDiag = d; ok = ok || d.Ok;
                    if (d.Short != AwgDiagLogged) { Log("AmneziaVPN: диагностика туннеля — " + d.Text, d.Ok ? "INFO" : "WARN"); AwgDiagLogged = d.Short; }
                } catch (Exception e) { Log("AmneziaVPN: диагностика: " + e.Message, "WARN"); }
            }
            AwgTraffic = ok; AwgTrafficAt = DateTime.Now; return ok;
        }
        static void AwgRestart(string reason)
        {
            if (InetBad()) { Log("AmneziaVPN: перезапуск отменён — нет интернета или он нестабилен (" + (InetWhy.Length > 0 ? InetWhy : "связь нестабильна") + ")", "INFO"); return; }
            AwgRestarts.RemoveAll(d => d < DateTime.Now.AddMinutes(-30));
            if (AwgRestarts.Count >= CfgInt("meduza.maxRestartsPer30Min", 5)) { Log("AmneziaVPN: слишком много перезапусков за 30 мин, пауза (" + reason + ")", "WARN"); return; }
            AwgRestarts.Add(DateTime.Now); AwgLastRestart = DateTime.Now; AwgLastReason = reason; RestartCount++;
            Log("AmneziaVPN: ПЕРЕЗАПУСК — " + reason, "WARN"); SetActivity("перезапускаю AmneziaVPN");
            AvpnStop(); Thread.Sleep(3000);
            try { AvpnStart(); ReconnectCount++; } catch (Exception e) { Log("AmneziaVPN: " + e.Message, "ERROR"); return; }
            var n = WaitAvpnUp(60);
            if (n != null) { Log("AmneziaVPN: туннель поднят (" + n + ")", "INFO"); IcsIfUplink("amnezia"); AwgDownTicks = 0; }
            else Log("AmneziaVPN: после перезапуска туннель не поднялся — проверьте, что в AmneziaVPN включено «Автоподключение»", "WARN");
        }
        // выбран другой режим: туннель AmneziaVPN не должен работать (closeApp — закрыть и само приложение)
        static void AvpnDisable(bool closeApp)
        {
            var a = AvpnNic(); bool up = a != null && a.OperationalStatus == OperationalStatus.Up;
            if (up || (closeApp && AvpnProc() != null)) { Log("AmneziaVPN: отключаю (выбран другой режим)", "INFO"); AvpnStop(); }
        }
        static DateTime AwgWarnAt = DateTime.MinValue, AwgSrvDownSince = DateTime.MinValue; static bool AwgSrvRestarted;
        static void AmneziaWatch()
        {
            if (AvpnBlocked()) {
                var bn = AvpnNic(); if (AvpnProc() != null || (bn != null && bn.OperationalStatus == OperationalStatus.Up)) { Log("Защита AmneziaVPN: AmneziaVPN отключён до " + AgBlockedUntil.ToString("HH:mm") + " — закрываю", "WARN"); AvpnStop(); }
                AwgTraffic = null; return;
            }
            if (!File.Exists(AwgExe())) { if ((DateTime.Now - AwgWarnAt).TotalMinutes >= 10) { Log("AmneziaVPN не установлен (" + AwgExe() + ") — установите на вкладке «Компоненты» и добавьте сервер в приложении", "ERROR"); AwgWarnAt = DateTime.Now; } return; }
            if (AvpnProc() == null) {
                Log("AmneziaVPN: приложение не запущено", "WARN"); SetActivity("запускаю AmneziaVPN");
                try { AvpnStart(); } catch (Exception e) { Log("AmneziaVPN: " + e.Message, "ERROR") ; }
                return;
            }
            var a = AvpnNic();
            if (a != null && a.OperationalStatus == OperationalStatus.Up) {
                AwgDownTicks = 0;
                bool srvDown = AwgSrvDownSince != DateTime.MinValue;
                // сервер не отвечает: перезапуск приложения его не починит — проверяем реже и без перезапусков
                if (srvDown && (DateTime.Now - AwgTrafficAt).TotalMinutes < Math.Max(1, CfgInt("amnezia.serverDownCheckMin", 5))) return;
                if (AwgTrafficOk(a.Name)) {
                    if (srvDown) Log("AmneziaVPN: сервер снова отвечает — туннель пропускает трафик (не отвечал " + Dur(DateTime.Now - AwgSrvDownSince) + ")", "WARN");
                    AwgSrvDownSince = DateTime.MinValue; AwgSrvRestarted = false; AwgProbeFailures = 0; return;
                }
                bool noServer = AwgDiag != null && !AwgDiag.Ok && AwgDiag.Short == "сервер VPN не отвечает";
                if (srvDown) { if (!noServer) { AwgSrvDownSince = DateTime.MinValue; AwgSrvRestarted = false; } return; }
                AwgProbeFailures++;
                Log("AmneziaVPN: нет трафика через туннель (" + AwgProbeFailures + "/" + CfgInt("meduza.probeFailuresBeforeReconnect", 3) + ")" + (AwgDiag != null && !AwgDiag.Ok ? " — " + AwgDiag.Short : ""), "WARN");
                if (AwgProbeFailures >= CfgInt("meduza.probeFailuresBeforeReconnect", 3)) {
                    AwgProbeFailures = 0;
                    if (noServer && AwgSrvRestarted) {
                        AwgSrvDownSince = DateTime.Now;
                        Log("AmneziaVPN: сервер VPN не отвечает и после перезапуска — дело не в приложении, перезапуски не помогут. Проверяю раз в " + Math.Max(1, CfgInt("amnezia.serverDownCheckMin", 5)) + " мин без перезапусков; смените сервер или протокол в приложении AmneziaVPN", "WARN");
                    } else { if (noServer) AwgSrvRestarted = true; AwgRestart(noServer ? "сервер VPN не отвечает — пробую один перезапуск" : "туннель не пропускает трафик"); }
                }
                return;
            }
            AwgTraffic = null;
            if ((DateTime.Now - AvpnStartedAt).TotalSeconds < CfgInt("meduza.startupGraceSec", 60)) return;    // только что запущено — даём подключиться
            AwgDownTicks++;
            Log("AmneziaVPN: туннель не подключён (" + AwgDownTicks + "/3)" + (AwgDownTicks == 1 ? " — включите в AmneziaVPN «Автоподключение», иначе после перезапуска он не подключится сам" : ""), "WARN");
            if (AwgDownTicks >= 3) { AwgDownTicks = 0; AwgRestart("туннель не подключается"); }
        }

        // для окна и веба (сводка): часть «AmneziaVPN»
        static Dictionary<string, object> AmneziaComp(string mode, string kind)
        {
            var avNic = AvpnNic();
            // AmneziaVPN
            bool used = mode == "amnezia" || mode == "dual"; string avExe = AwgExe(); bool inst = File.Exists(avExe);
            var avProc = AvpnProc(); var avSvc = Svc(AvpnSvcName()); bool aUp = avNic != null && avNic.OperationalStatus == OperationalStatus.Up;
            string aIp = aUp ? Ipv4(avNic.Name) : null;
            int aL; string aS;
            if (!used) { aL = -1; aS = aUp ? "Не используется (туннель поднят)" : avProc != null ? "Не используется (запущен)" : "Не используется"; }
            else if (!inst) { aL = 2; aS = "Не установлен"; } else if (avProc == null) { aL = 2; aS = "Не запущен"; } else if (!aUp) { aL = 1; aS = "Туннель не подключён"; }
            else if (AwgTraffic == false) { aL = 1; aS = "Нет трафика"; } else { aL = 0; aS = "Подключён"; }
            if (used && AvpnBlocked()) { aL = 2; aS = "Отключён защитой до " + AgBlockedUntil.ToString("HH:mm") + " — отрезал локальную сеть"; }
            string agTxt = !CfgBool("amnezia.lanGuard", true) ? "Защита локальной сети: выключена" : AvpnBlocked() ? "Защита: отключён до " + AgBlockedUntil.ToString("HH:mm") + " — " + AgTripWhy + ". Выключите в AmneziaVPN Kill Switch"
                : AgTrips > 0 ? "Защита: срабатывала " + When(AgTripAt) + " (" + AgTripWhy + ")" : "Защита локальной сети: включена, срабатываний не было";
            string aVer = ""; try { if (inst) aVer = Cached("fv:" + avExe, 300, () => FileVersionInfo.GetVersionInfo(avExe).ProductVersion); } catch { }
            string aTr = AwgTraffic == true ? "OK" : AwgTraffic == false ? "НЕТ" : "—";
            long avMem = 0; try { if (avProc != null) avMem = avProc.WorkingSet64 / 1048576; } catch { }
            var awg = Comp(aL, aS, new[] { inst ? "AmneziaVPN " + aVer + " · " + (avProc != null ? "PID " + avProc.Id : "не запущен") : "AmneziaVPN не установлен",
                "Туннель: " + (aUp ? avNic.Name + " · IP " + aIp : avNic != null ? avNic.Name + " — " + avNic.OperationalStatus : "не подключён"),
                "Трафик: " + aTr + ", проверка " + When(AwgTrafficAt) + (AwgDiag != null && !AwgDiag.Ok ? " — " + AwgDiag.Short : ""), "Перезапуски: " + AwgRestarts.ToArray().Count(d => d > DateTime.Now.AddMinutes(-30)) + " за 30 мин, посл. " + When(AwgLastRestart), agTxt }, new List<object[]> {
                Kv("Диагностика туннеля", AwgDiag == null ? "ещё не было" : AwgDiag.At.ToString("HH:mm:ss") + " — " + AwgDiag.Text),
                Kv("Защита локальной сети", agTxt + (AgBaseAt != DateTime.MinValue ? " · без AmneziaVPN: роутер " + (AgGwBase ? "отвечал" : "не отвечал") + ", клиентов WG на связи " + Math.Max(0, AgPeersBase) : "")),
                Kv("Приложение AmneziaVPN", inst ? "установлено · версия " + aVer : "не установлено (" + avExe + ")"),
                Kv("Процесс", avProc != null ? "PID " + avProc.Id + " · " + avMem + " МБ" : "не запущен"),
                Kv("Служба", avSvc != null ? avSvc.ServiceName + " · " + avSvc.Status + " / " + StartMode(avSvc.ServiceName) : "не найдена"),
                Kv("Используется", mode == "dual" ? (kind == "amnezia" ? "да — активный из двух туннелей" : "да — резерв из двух туннелей") : used ? "да — режим AmneziaVPN" : "нет (другой режим)"),
                Kv("Адаптер туннеля", avNic != null ? avNic.Name + " · " + avNic.Description + " · " + avNic.OperationalStatus : "не найден (туннель не подключён)"), Kv("IP", aIp ?? "—"),
                Kv("Проверка трафика", aTr + " · " + When(AwgTrafficAt)), Kv("Сбоев проверки подряд", AwgProbeFailures + " (перезапуск после " + CfgInt("meduza.probeFailuresBeforeReconnect", 3) + ")"),
                Kv("Перезапусков за 30 мин", AwgRestarts.ToArray().Count(d => d > DateTime.Now.AddMinutes(-30)) + " из " + CfgInt("meduza.maxRestartsPer30Min", 5) + " допустимых"),
                Kv("Последний перезапуск", When(AwgLastRestart)), Kv("Причина", AwgLastReason.Length > 0 ? AwgLastReason : "—"),
                Kv("Сервер и протокол", "выбираются в приложении AmneziaVPN; там же включите «Автоподключение»") });
            awg["installed"] = inst; awg["running"] = avProc != null; awg["active"] = avNic != null ? avNic.Name : ""; awg["adapter"] = avNic != null ? avNic.Name : "";
            awg["configs"] = new object[0]; awg["test"] = null;
            return awg;
        }
    }
}
