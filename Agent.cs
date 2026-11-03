// VpnGuard — агент на C# (шаг 1): основной цикл вместо PowerShell.
// Делает сам: MeduzaVPN (процесс, подключение, трафик, перезапуски, запасной протокол, тест протоколов), AmneziaWG (туннель,
// трафик, перезапуски, тест конфигов), режим «без VPN», wg_server, раздача ICS, трафик, история, состояние для окна/веб/значка.
// Поручает PowerShell (VpnGuard.ps1 -PsPart, коротко, раз в 2 мин или сразу по команде): zapret, обновления VpnGuard/MeduzaVPN/
// компонентов, веб-сервер, значок, создание сервера wg_server, остальные команды. Режим «два туннеля» — пока агент на PowerShell.
// Собирается встроенным компилятором .NET Framework (C# 5), запускается из VpnGuard.ps1, если agent.engine = 'csharp'.
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
    public static class Agent
    {
        static string Root, DataDir, LogDir, CmdDir, CmdPsDir, ConfigPath, StatusPath, PsStatusPath, BinDir, AwgDir, Version = "";
        static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 200 };
        static Dictionary<string, object> Cfg = new Dictionary<string, object>();
        static DateTime CfgStamp = DateTime.MinValue;
        static readonly UTF8Encoding Bom = new UTF8Encoding(true);
        static readonly object LogLock = new object();
        static readonly DateTime StartedAt = DateTime.Now;
        static string CodeSig = "";

        // ---------------------------------------------------------------- состояние
        static readonly List<DateTime> Restarts = new List<DateTime>(), AwgRestarts = new List<DateTime>();
        static int ProbeFailures, DownTicks, NotResponding, RestartCount, ReconnectCount, IcsFixCount, AwgProbeFailures, AwgDownTicks, WgMissingTicks;
        static bool? LastTraffic, AwgTraffic;
        static DateTime LastTrafficAt = DateTime.MinValue, AwgTrafficAt = DateTime.MinValue, MeduzaStartedAt = DateTime.MinValue, LastRestart = DateTime.MinValue, AwgLastRestart = DateTime.MinValue;
        static DateTime LastIcsApply = DateTime.MinValue, LastIpFix = DateTime.MinValue, LastIcsFix = DateTime.MinValue, UltraUpSince = DateTime.MinValue, WgUpSince = DateTime.MinValue;
        static DateTime CatalogAt = DateTime.MinValue, MzFallbackAt = DateTime.MinValue, MzReturnAt = DateTime.MinValue, MzProtoSince = DateTime.MinValue, LastSnapshot = DateTime.MinValue;
        static string LastRestartReason = "", AwgLastReason = "", MzOverride = "", MzAdapter = "", Activity = "", LastMode = null;
        static DateTime ActivitySince = DateTime.MinValue;
        static bool ForceIcs;
        static Dictionary<string, object> Catalog, ProtoTest, AwgTest;
        static readonly List<Dictionary<string, object>> History = new List<Dictionary<string, object>>();
        static Process PsPart; static DateTime PsPartAt = DateTime.MinValue;

        // ---------------------------------------------------------------- точка входа
        public static int Main(string[] argv)
        {
            bool snapOnly = argv.Contains("--snapshot");          // проверка (Test.ps1): только записать состояние и выйти, ничего не меняя
            var args = argv.Where(a => a != "--snapshot").ToArray();
            Root =args.Length > 0 ? args[0].TrimEnd('\\') : Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ".."));
            ConfigPath = args.Length > 1 ? args[1] : Path.Combine(Root, "config.json");
            DataDir = Path.Combine(Root, "data"); LogDir = Path.Combine(DataDir, "logs"); CmdDir = Path.Combine(DataDir, "cmd"); CmdPsDir = Path.Combine(DataDir, "cmd-ps");
            StatusPath = Path.Combine(DataDir, "status.json"); PsStatusPath = Path.Combine(DataDir, "status-ps.json"); BinDir = Path.Combine(Root, "bin"); AwgDir = Path.Combine(DataDir, "amnezia");
            foreach (var d in new[] { DataDir, LogDir, CmdDir, CmdPsDir }) Directory.CreateDirectory(d);
            try { var m = Regex.Match(File.ReadAllText(Path.Combine(Root, "VpnGuard.ps1")), @"\$AgentVersion\s*=\s*'([^']+)'"); if (m.Success) Version = m.Groups[1].Value; } catch { }
            CodeSig = SourceSig();
            if (snapOnly) { LoadCfg(true); LastMode = Mode(); try { SnapshotCore(); return 0; } catch (Exception e) { Console.Error.WriteLine(e); return 1; } }
            // как и VpnGuard.ps1: без прав администратора не управлять ничем и сразу выйти
            if (!new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator)) { Log("Агент C#: нужны права администратора", "ERROR"); return 1; }
            // запускать только из папки VpnGuard (рядом должен быть VpnGuard.ps1 с выбранным движком csharp)
            if (!File.Exists(Path.Combine(Root, "VpnGuard.ps1"))) return 1;
            bool own = false;
            using (var mutex = new Mutex(false, "Global\\VpnGuard")) {
                try { own = mutex.WaitOne(60000); } catch (AbandonedMutexException) { own = true; }
                if (!own) return 0;                     // работает другой агент
                try { Run(); }
                catch (Exception e) { Log("Агент C#: аварийная остановка: " + e, "ERROR"); return 1; }
                finally { try { mutex.ReleaseMutex(); } catch { } }
            }
            return 0;
        }

        static void Run()
        {
            LoadCfg(true);
            LoadTrafficDays();
            Log("VpnGuard " + Version + " запущен — агент на C# (PID " + Process.GetCurrentProcess().Id + ")", "INFO");
            MeduzaStartedAt = DateTime.Now;
            while (true) {
                var t0 = DateTime.Now;
                LoadCfg(false);
                // вернуть работу агенту на PowerShell: так выбрали в настройках или включён режим «два туннеля»
                if (CfgStr("agent.engine", "powershell") != "csharp" || Mode() == "dual") {
                    Log(Mode() == "dual" ? "Агент C#: режим «два туннеля» пока работает на агенте PowerShell — передаю работу ему" : "Агент C#: выбран агент на PowerShell — передаю работу ему", "WARN");
                    HandOver(); return;
                }
                if (SourceSig() != CodeSig) { Log("Агент C#: код обновлён — перезапуск на новой версии", "INFO"); HandOver(); return; }
                foreach (var step in new Action[] { Commands, WgWatch, VpnWatch, SharingWatch, PsPartWatch }) {
                    try { step(); } catch (Exception e) { Log("Агент C#: " + step.Method.Name + ": " + e.Message, "ERROR"); }
                    if ((DateTime.Now - LastSnapshot).TotalSeconds >= 10) Snapshot();
                }
                Activity = ""; Snapshot();
                if (DateTime.Now.Hour == 3 && DateTime.Now.Minute < 2) RemoveOldLogs();
                int iv = Math.Max(10, CfgInt("checkIntervalSec", 30)) * 1000;
                while ((DateTime.Now - t0).TotalMilliseconds < iv) {
                    Thread.Sleep(1000);
                    if (Directory.GetFiles(CmdDir, "*.cmd").Length > 0) break;
                }
            }
        }

        // передать работу: VpnGuard.ps1 через задачу планировщика (он решит, какой агент запускать)
        static void HandOver()
        {
            Snapshot();
            Run("cmd.exe", "/c ping -n 4 127.0.0.1 >nul & schtasks /run /tn \"VpnGuard\"", false);
        }
        static string SourceSig()
        {
            try { var f = Path.Combine(Root, "Agent.cs"); return File.Exists(f) ? File.GetLastWriteTimeUtc(f).Ticks.ToString() : ""; } catch { return ""; }
        }

        // ---------------------------------------------------------------- настройки (умолчания — как у агента PowerShell)
        static readonly Dictionary<string, object> Defaults = new Dictionary<string, object> {
            {"checkIntervalSec", 30}, {"logRetentionDays", 14}, {"vpn.mode", "meduza"}, {"vpn.stopInactive", true},
            {"meduza.processName", "medusa_vpn"}, {"meduza.adapterName", "MeduzaVPN ULTRA"}, {"meduza.pipeName", "MeduzaVPN"}, {"meduza.cliPath", ""}, {"meduza.exePath", ""},
            {"meduza.serviceId", ""}, {"meduza.protocol", "ultra"}, {"meduza.connectTimeoutSec", 90}, {"meduza.startupGraceSec", 60},
            {"meduza.probeFailuresBeforeReconnect", 3}, {"meduza.maxRestartsPer30Min", 5}, {"meduza.autoProtocol", true}, {"meduza.protocolReturnMin", 60},
            {"ws4w.interfaceName", "wg_server"}, {"ws4w.serviceName", "WireGuardTunnel$wg_server"}, {"ws4w.configPath", ""}, {"ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe"},
            {"ws4w.serverAddress", ""}, {"ws4w.autoCreateServer", true}, {"sharing.enabled", true},
            {"amnezia.exe", @"C:\Program Files\AmneziaWG\amneziawg.exe"}, {"amnezia.servicePrefix", "AmneziaWGTunnel$"}, {"amnezia.active", ""},
            {"zapret.enabled", false} };
        static void LoadCfg(bool force)
        {
            DateTime st = File.Exists(ConfigPath) ? File.GetLastWriteTimeUtc(ConfigPath) : DateTime.MinValue;
            if (!force && st == CfgStamp) return;
            CfgStamp = st;
            try { Cfg = st == DateTime.MinValue ? new Dictionary<string, object>() : (Json.DeserializeObject(File.ReadAllText(ConfigPath, Encoding.UTF8)) as Dictionary<string, object>) ?? new Dictionary<string, object>(); if (!force) Log("Настройки перечитаны из config.json", "INFO"); }
            catch (Exception e) { Log("config.json с ошибкой, оставляю прежние настройки: " + e.Message, "ERROR"); }
        }
        static object CfgGet(string path)
        {
            object cur = Cfg;
            foreach (var p in path.Split('.')) { var d = cur as Dictionary<string, object>; if (d == null || !d.ContainsKey(p)) { object df; return Defaults.TryGetValue(path, out df) ? df : null; } cur = d[p]; }
            if (cur == null) { object df; return Defaults.TryGetValue(path, out df) ? df : null; }
            return cur;
        }
        static string CfgStr(string p, string def) { var v = CfgGet(p); return v == null ? def : Convert.ToString(v, CultureInfo.InvariantCulture); }
        static int CfgInt(string p, int def) { int i; return int.TryParse(CfgStr(p, def.ToString()), out i) ? i : def; }
        static bool CfgBool(string p, bool def) { var v = CfgGet(p); if (v is bool) return (bool)v; bool b; return bool.TryParse(Convert.ToString(v), out b) ? b : def; }
        static string[] CfgList(string p, string[] def)
        {
            var v = CfgGet(p) as IEnumerable; if (v == null || v is string) return def;
            var l = new List<string>(); foreach (var x in v) l.Add(Convert.ToString(x)); return l.Count > 0 ? l.ToArray() : def;
        }
        static string Mode() { var m = CfgStr("vpn.mode", "meduza"); return new[] { "meduza", "amnezia", "dual", "zapret" }.Contains(m) ? m : "meduza"; }
        static string[] ProbeHosts() { return CfgList("meduza.probeHosts", new[] { "1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443" }); }
        static string MzAdapterName() { return MzAdapter.Length > 0 ? MzAdapter : CfgStr("meduza.adapterName", "MeduzaVPN ULTRA"); }
        static string WgIf() { return CfgStr("ws4w.interfaceName", "wg_server"); }

        // ---------------------------------------------------------------- журнал
        public static void Log(string msg, string level)
        {
            lock (LogLock) {
                try { File.AppendAllText(Path.Combine(LogDir, "vpnguard-" + DateTime.Now.ToString("yyyyMMdd") + ".log"), DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " [" + level + "] " + msg + "\r\n", Bom); } catch { }
            }
        }
        static void RemoveOldLogs()
        {
            int keep = CfgInt("logRetentionDays", 14);
            foreach (var f in Directory.GetFiles(LogDir, "vpnguard-*.log")) { try { if ((DateTime.Now - File.GetLastWriteTime(f)).TotalDays > keep) File.Delete(f); } catch { } }
        }
        static void SetActivity(string t) { Activity = t; ActivitySince = DateTime.Now; Snapshot(); }

        // ---------------------------------------------------------------- помощники: процессы, адаптеры, сеть
        class ExeResult { public int Code; public string Out = "", Err = ""; }
        static ExeResult Exe(string file, string args, int timeoutSec)
        {
            var r = new ExeResult();
            try {
                var psi = new ProcessStartInfo(file, args) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
                using (var p = Process.Start(psi)) {
                    var o = p.StandardOutput.ReadToEndAsync(); var e = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(timeoutSec * 1000)) { try { p.Kill(); } catch { } r.Code = -1; r.Err = "таймаут " + timeoutSec + " с"; return r; }
                    r.Code = p.ExitCode; r.Out = o.Result.Trim(); r.Err = e.Result.Trim();
                }
            } catch (Exception e) { r.Code = -2; r.Err = e.Message; }
            return r;
        }
        static void Run(string file, string args, bool wait)
        {
            try { var p = Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true }); if (wait) p.WaitForExit(60000); } catch (Exception e) { Log("Запуск " + file + ": " + e.Message, "ERROR"); }
        }
        static NetworkInterface Nic(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            try { return NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => string.Equals(n.Name, name, StringComparison.OrdinalIgnoreCase)); } catch { return null; }
        }
        static bool Up(string name) { var n = Nic(name); return n != null && n.OperationalStatus == OperationalStatus.Up; }
        static string Ipv4(string name)
        {
            var n = Nic(name); if (n == null) return null;
            try { foreach (var u in n.GetIPProperties().UnicastAddresses) if (u.Address.AddressFamily == AddressFamily.InterNetwork && !u.Address.ToString().StartsWith("169.254.")) return u.Address.ToString(); } catch { }
            return null;
        }
        static bool TcpVia(string srcIp, string hostPort, int timeoutMs)
        {
            var hp = hostPort.Split(':'); if (hp.Length != 2) return false;
            using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
                try {
                    if (!string.IsNullOrEmpty(srcIp)) s.Bind(new IPEndPoint(IPAddress.Parse(srcIp), 0));
                    var ar = s.BeginConnect(hp[0], int.Parse(hp[1]), null, null);
                    if (ar.AsyncWaitHandle.WaitOne(timeoutMs)) { s.EndConnect(ar); return true; }
                    return false;
                } catch { return false; }
            }
        }
        static bool ProbeVia(string adapter, int timeoutMs, List<long> times)
        {
            string ip = Ipv4(adapter); if (ip == null) return false; bool ok = false;
            foreach (var h in ProbeHosts()) { var sw = Stopwatch.StartNew(); if (TcpVia(ip, h, timeoutMs)) { ok = true; if (times != null) times.Add(sw.ElapsedMilliseconds); else break; } }
            return ok;
        }
        static ServiceController Svc(string name)
        {
            try { var s = ServiceController.GetServices().FirstOrDefault(x => string.Equals(x.ServiceName, name, StringComparison.OrdinalIgnoreCase)); return s; } catch { return null; }
        }
        static void SetAutoStart(string svc) { Exe("sc.exe", "config \"" + svc + "\" start= auto", 30); }
        static string StartMode(string svc) { try { using (var mo = new ManagementObject("Win32_Service.Name='" + svc.Replace("'", "\\'").Replace("\\", "\\\\") + "'")) return Convert.ToString(mo["StartMode"]); } catch { return ""; } }
        static string When(DateTime d)
        {
            if (d == DateTime.MinValue) return "не было";
            var s = (DateTime.Now - d).TotalSeconds;
            return d.ToString(d.Date == DateTime.Today ? "HH:mm:ss" : "dd.MM HH:mm") + (s < 3600 ? " (" + (int)(s / 60) + " мин назад)" : "");
        }
        static bool IsTunnel(string alias)
        {
            if (string.IsNullOrEmpty(alias)) return false;
            if (alias.StartsWith("MeduzaVPN", StringComparison.OrdinalIgnoreCase) || alias == MzAdapterName() || alias == WgIf()) return true;
            return AwgConfigs().Any(c => c.Name == alias);
        }
        // физический выход: работающий адаптер со шлюзом IPv4, не туннель
        static string PhysAlias()
        {
            try {
                foreach (var n in NetworkInterface.GetAllNetworkInterfaces().OrderBy(n => n.NetworkInterfaceType == NetworkInterfaceType.Ethernet ? 0 : 1)) {
                    if (n.OperationalStatus != OperationalStatus.Up || IsTunnel(n.Name)) continue;
                    var gw = n.GetIPProperties().GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork && g.Address.ToString() != "0.0.0.0");
                    if (gw != null) return n.Name;
                }
            } catch { }
            return "";
        }

        // ---------------------------------------------------------------- команды
        static readonly string[] OwnCmds = { "check-now", "reconnect", "reconnect-meduza", "reconnect-awg", "restart-meduza", "restart-wg", "reapply-ics", "meduza-test", "meduza-catalog", "meduza-proto-reset", "awg-test" };
        static void Commands()
        {
            var files = Directory.GetFiles(CmdDir, "*.cmd").OrderBy(f => f).ToList();
            foreach (var f in files) {
                string a = ""; try { a = File.ReadAllText(f).Trim(); } catch { }
                if (!OwnCmds.Contains(a)) {                  // остальное — PowerShell (zapret, обновления, установка компонентов …)
                    try { File.Move(f, Path.Combine(CmdPsDir, Path.GetFileName(f))); } catch { try { File.Delete(f); } catch { } }
                    PsPartAt = DateTime.MinValue; continue;
                }
                try { File.Delete(f); } catch { }
                Log("Команда из монитора: " + a, "INFO");
                switch (a) {
                    case "reconnect":
                        if (Mode() == "amnezia") { var n = AwgActive(); if (n != null) { AwgRestarts.Clear(); AwgRestart(n.Name, "по команде из окна"); } }
                        else if (Mode() == "meduza") { MzReconnectCmd(); }
                        break;
                    case "reconnect-meduza": MzReconnectCmd(); break;
                    case "reconnect-awg": { var n = AwgActive(); if (n != null) { AwgRestarts.Clear(); AwgRestart(n.Name, "по команде из окна"); } } break;
                    case "restart-meduza": Restarts.Clear(); MzRestart("по команде из монитора"); break;
                    case "restart-wg": SvcRestart(CfgStr("ws4w.serviceName", "")); ForceIcs = true; break;
                    case "reapply-ics": ForceIcs = true; break;
                    case "meduza-test": MzProtoTest(); break;
                    case "meduza-catalog": MzCatalog(true); break;
                    case "meduza-proto-reset": if (MzOverride.Length > 0) { MzReturnAt = DateTime.MinValue; MzProtoReturn(); } break;
                    case "awg-test": AwgConfigTest(); break;
                }
            }
            if (files.Count > 0) Snapshot();
        }
        static void MzReconnectCmd() { MzDisconnect(); Thread.Sleep(3000); if (!MzConnect(0)) MzRestart("переподключение из монитора не удалось"); }
        static void SvcRestart(string name)
        {
            try {
                var s = Svc(name); if (s == null) return;
                if (s.Status != ServiceControllerStatus.Stopped) { s.Stop(); s.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30)); }
                s.Start(); s.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            } catch (Exception e) { Log(name + ": " + e.Message, "ERROR"); }
        }

        // ---------------------------------------------------------------- MeduzaVPN
        static string MzExe()
        {
            var p = CfgStr("meduza.exePath", ""); if (p.Length > 0) return p;
            var loc = MzUninstall("InstallLocation"); if (!string.IsNullOrEmpty(loc)) return Path.Combine(loc, "medusa_vpn.exe");
            return @"C:\Program Files\MeduzaVPN\medusa_vpn.exe";
        }
        static string MzUninstall(string value)
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
            var r = MzCli(a, timeoutSec > 0 ? timeoutSec : CfgInt("meduza.connectTimeoutSec", 90) + 30);
            if (r.Code != 0) Log("MeduzaVPN: connect завершился с кодом " + r.Code + ": " + r.Out + " " + r.Err, "WARN");
            var dl = DateTime.Now.AddSeconds(15);
            while (DateTime.Now < dl) {
                if (Up(MzAdapterName())) { Log("MeduzaVPN: туннель подключён (" + proto + ")", "INFO"); return true; }
                var alt = MzAltUp(); if (alt != null) { MzAdapter = alt.Name; Log("MeduzaVPN: подключён, адаптер «" + alt.Name + "» (" + proto + ")", "INFO"); return true; }
                Thread.Sleep(2000);
            }
            return Up(MzAdapterName());
        }
        static void MzDisconnect() { if (MzPipe()) { var r = MzCli("disconnect", 30); Log("MeduzaVPN: disconnect (код " + r.Code + ")", "INFO"); } }
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
            MzFallbackAt = DateTime.Now;
            string cur = MzProtocol(), chosen = CfgStr("meduza.protocol", "ultra");
            try { MzCatalog(false); } catch { }
            var tested = new List<string>();
            if (ProtoTest != null && ProtoTest.ContainsKey("results")) foreach (Dictionary<string, object> r in ((IEnumerable)ProtoTest["results"]).Cast<Dictionary<string, object>>().Where(r => r["ok"] is bool && (bool)r["ok"]).OrderBy(r => Convert.ToInt32(r["pingMs"]))) tested.Add(Convert.ToString(r["protocol"]));
            var same = new[] { cur, "meduza-" + cur, Regex.Replace(cur, "^meduza-", "") };
            var order = tested.Concat(MzProtocols()).Concat(new[] { chosen }).Where(p => p.Length > 0 && !same.Contains(p)).Distinct().ToList();
            if (order.Count == 0) { Log("MeduzaVPN: " + reason + " — других протоколов нет (список не получен), пробовать нечего", "WARN"); return false; }
            Log("MeduzaVPN: " + reason + ", протокол " + cur + " — пробую другие: " + string.Join(", ", order), "WARN");
            string prev = MzOverride;
            foreach (var p in order) {
                SetActivity("MeduzaVPN: пробую протокол " + p);
                MzDisconnect(); Thread.Sleep(2000);
                MzOverride = (p == chosen || p == "meduza-" + chosen) ? "" : p;
                if (MzConnect(60) && MzTraffic()) {
                    MzProtoSince = DateTime.Now; MzReturnAt = DateTime.Now; ProbeFailures = 0; DownTicks = 0; ForceIcs = true;
                    Log(MzOverride.Length > 0 ? "MeduzaVPN: протокол " + cur + " не работает — переключился на " + p + " (выбран в настройках: " + chosen + "; агент будет пробовать вернуть его)" : "MeduzaVPN: снова работает выбранный протокол " + p, "WARN");
                    return true;
                }
                Log("MeduzaVPN: протокол " + p + " тоже не работает", "WARN");
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
            if (MzConnect(60) && MzTraffic()) { Log("MeduzaVPN: выбранный протокол " + chosen + " снова работает", "INFO"); ForceIcs = true; return; }
            Log("MeduzaVPN: " + chosen + " по-прежнему не работает — остаюсь на " + alt, "WARN");
            MzOverride = alt; MzDisconnect(); Thread.Sleep(2000); MzConnect(0); ForceIcs = true;
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
            MzDisconnect(); Thread.Sleep(2000); MzConnect(0); MzResolveAdapter(); ForceIcs = true;
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

        // ---------------------------------------------------------------- AmneziaWG
        class AwgCfg { public string Name, Title, Endpoint, Address, File; }
        static List<AwgCfg> AwgConfigs()
        {
            var l = new List<AwgCfg>(); if (!Directory.Exists(AwgDir)) return l;
            foreach (var f in Directory.GetFiles(AwgDir, "*.conf").OrderBy(x => x)) {
                string t = ""; try { t = File.ReadAllText(f); } catch { }
                var nm = Regex.Match(t, @"(?m)^#\s*Name\s*=\s*(.+?)\s*$").Groups[1].Value;
                l.Add(new AwgCfg { Name = Path.GetFileNameWithoutExtension(f), Title = nm.Length > 0 ? nm : Path.GetFileNameWithoutExtension(f), File = f,
                    Endpoint = Regex.Match(t, @"(?m)^\s*Endpoint\s*=\s*(\S+)").Groups[1].Value, Address = Regex.Match(t, @"(?m)^\s*Address\s*=\s*([^\r\n]+)").Groups[1].Value.Trim() });
            }
            return l;
        }
        static AwgCfg AwgActive() { var l = AwgConfigs(); var a = CfgStr("amnezia.active", ""); return l.FirstOrDefault(c => c.Name == a) ?? l.FirstOrDefault(); }
        static string AwgExe() { return CfgStr("amnezia.exe", @"C:\Program Files\AmneziaWG\amneziawg.exe"); }
        static string AwgSvc(string name) { return CfgStr("amnezia.servicePrefix", "AmneziaWGTunnel$") + name; }
        static void AwgStart(string name)
        {
            if (!File.Exists(AwgExe())) throw new Exception("AmneziaWG не установлен (" + AwgExe() + ") — установите его на вкладке «Компоненты»");
            var f = Path.Combine(AwgDir, name + ".conf"); if (!File.Exists(f)) throw new Exception("нет конфига " + f);
            var r = Exe(AwgExe(), "/installtunnelservice \"" + f + "\"", 60); if (r.Code != 0) throw new Exception("installtunnelservice: код " + r.Code + " " + r.Err);
            SetAutoStart(AwgSvc(name));
        }
        static void AwgStop(string name)
        {
            if (Svc(AwgSvc(name)) == null) return;
            if (File.Exists(AwgExe()) && Exe(AwgExe(), "/uninstalltunnelservice \"" + name + "\"", 60).Code == 0) return;
            try { var s = Svc(AwgSvc(name)); if (s != null) s.Stop(); } catch { }
        }
        static void AwgStopAll(string except)
        {
            foreach (var c in AwgConfigs()) { if (c.Name == except) continue; if (Svc(AwgSvc(c.Name)) != null) { Log("AmneziaWG: отключаю туннель " + c.Name, "INFO"); AwgStop(c.Name); } }
        }
        static bool WaitUp(string name, int sec) { var dl = DateTime.Now.AddSeconds(sec); do { if (Up(name)) return true; Thread.Sleep(1000); } while (DateTime.Now < dl); return false; }
        static bool AwgTrafficOk(string name) { bool ok = ProbeVia(name, 4000, null); AwgTraffic = ok; AwgTrafficAt = DateTime.Now; return ok; }
        static void AwgRestart(string name, string reason)
        {
            AwgRestarts.RemoveAll(d => d < DateTime.Now.AddMinutes(-30));
            if (AwgRestarts.Count >= CfgInt("meduza.maxRestartsPer30Min", 5)) { Log("AmneziaWG: слишком много перезапусков за 30 мин, пауза (" + reason + ")", "WARN"); return; }
            AwgRestarts.Add(DateTime.Now); AwgLastRestart = DateTime.Now; AwgLastReason = reason; RestartCount++;
            Log("AmneziaWG: ПЕРЕЗАПУСК туннеля " + name + " — " + reason, "WARN"); SetActivity("перезапускаю AmneziaWG (" + name + ")");
            AwgStop(name); Thread.Sleep(2000);
            try { AwgStart(name); ReconnectCount++; } catch (Exception e) { Log("AmneziaWG: " + e.Message, "ERROR"); return; }
            if (WaitUp(name, 20)) { Log("AmneziaWG: туннель " + name + " поднят", "INFO"); ForceIcs = true; }
        }
        static DateTime AwgWarnAt = DateTime.MinValue;
        static void AmneziaWatch()
        {
            var c = AwgActive();
            if (c == null) { if ((DateTime.Now - AwgWarnAt).TotalMinutes >= 10) { Log("AmneziaWG: нет ни одного конфига — импортируйте его (вкладка AmneziaWG)", "WARN"); AwgWarnAt = DateTime.Now; } return; }
            if (!File.Exists(AwgExe())) { if ((DateTime.Now - AwgWarnAt).TotalMinutes >= 10) { Log("AmneziaWG не установлен (" + AwgExe() + ") — установите на вкладке «Компоненты»", "ERROR"); AwgWarnAt = DateTime.Now; } return; }
            AwgStopAll(c.Name);
            var svc = Svc(AwgSvc(c.Name));
            if (svc == null) {
                Log("AmneziaWG: подключаю туннель " + c.Name, "INFO"); SetActivity("подключаю AmneziaWG (" + c.Name + ")");
                try { AwgStart(c.Name); ReconnectCount++; } catch (Exception e) { Log("AmneziaWG: " + e.Message, "ERROR"); return; }
                if (WaitUp(c.Name, 20)) { Log("AmneziaWG: туннель " + c.Name + " поднят", "INFO"); ForceIcs = true; }
                return;
            }
            if (svc.Status != ServiceControllerStatus.Running) {
                Log("AmneziaWG: служба туннеля в состоянии " + svc.Status + " — запускаю", "WARN");
                try { svc.Start(); } catch { AwgRestart(c.Name, "служба не запускается"); }
                return;
            }
            if (!Up(c.Name)) { AwgDownTicks++; AwgTraffic = null; Log("AmneziaWG: адаптер " + c.Name + " не поднят (" + AwgDownTicks + ")", "WARN"); if (AwgDownTicks >= 2) { AwgDownTicks = 0; AwgRestart(c.Name, "адаптер не поднят"); } return; }
            AwgDownTicks = 0;
            if (AwgTrafficOk(c.Name)) { AwgProbeFailures = 0; return; }
            AwgProbeFailures++;
            Log("AmneziaWG: нет трафика через туннель (" + AwgProbeFailures + "/" + CfgInt("meduza.probeFailuresBeforeReconnect", 3) + ")", "WARN");
            if (AwgProbeFailures >= CfgInt("meduza.probeFailuresBeforeReconnect", 3)) { AwgProbeFailures = 0; AwgRestart(c.Name, "туннель не пропускает трафик"); }
        }
        static void AwgConfigTest()
        {
            var list = AwgConfigs();
            if (list.Count == 0) { Log("AmneziaWG: нет конфигов для теста", "WARN"); return; }
            if (!File.Exists(AwgExe())) { Log("AmneziaWG: не установлен — тест невозможен", "WARN"); return; }
            var res = new List<object>();
            AwgTest = new Dictionary<string, object> { { "running", true }, { "index", 0 }, { "total", list.Count }, { "current", "" }, { "results", res }, { "at", "" } };
            Log("AmneziaWG: тест конфигов: " + string.Join(", ", list.Select(x => x.Name)), "WARN");
            var active = AwgActive(); AwgStopAll(""); int i = 0;
            foreach (var c in list) {
                i++; AwgTest["index"] = i; AwgTest["current"] = c.Title; SetActivity("тест AmneziaWG: " + c.Title + " (" + i + "/" + list.Count + ")");
                var sw = Stopwatch.StartNew(); string err = ""; var ms = new List<long>();
                try { AwgStart(c.Name); if (WaitUp(c.Name, 20)) { Thread.Sleep(2000); ProbeVia(c.Name, 3000, ms); } else err = "туннель не поднялся"; } catch (Exception e) { err = e.Message; }
                double conn = Math.Round(sw.Elapsed.TotalSeconds, 1);
                AwgStop(c.Name);
                res.Add(new Dictionary<string, object> { { "protocol", c.Title }, { "name", c.Name }, { "ok", ms.Count > 0 }, { "probes", ms.Count + "/" + ProbeHosts().Length }, { "connectSec", conn }, { "pingMs", ms.Count > 0 ? (int)ms.Average() : -1 }, { "adapter", c.Name }, { "error", err } });
                Log("AmneziaWG: тест " + c.Title + ": " + (ms.Count > 0 ? "работает, отклик " + (int)ms.Average() + " мс" : "НЕ работает " + err), "INFO");
                Snapshot();
            }
            AwgTest["running"] = false; AwgTest["current"] = ""; AwgTest["at"] = DateTime.Now.ToString("dd.MM HH:mm");
            if (Mode() == "amnezia" && active != null) { SetActivity("возвращаю AmneziaWG (" + active.Name + ")"); try { AwgStart(active.Name); WaitUp(active.Name, 20); } catch { } ForceIcs = true; }
        }

        // ---------------------------------------------------------------- режим работы
        static string UplinkName() { var m = Mode(); if (m == "zapret") return PhysAlias(); if (m == "amnezia") { var a = AwgActive(); return a == null ? "" : a.Name; } return MzAdapterName(); }
        static readonly Dictionary<string, string> ModeNames = new Dictionary<string, string> { { "meduza", "MeduzaVPN" }, { "amnezia", "AmneziaWG" }, { "dual", "два туннеля (MeduzaVPN + AmneziaWG)" }, { "zapret", "без VPN (только zapret)" } };
        static void VpnWatch()
        {
            string mode = Mode();
            if (mode != LastMode) {
                if (LastMode != null) Log("Режим: " + ModeNames[LastMode] + " → " + ModeNames[mode], "WARN");
                SetActivity("переключаю режим: " + ModeNames[mode]);
                if (mode != "meduza" && CfgBool("vpn.stopInactive", true) && MzProc() != null) { Log("MeduzaVPN: отключаю и закрываю (выбран другой режим)", "INFO"); MzStop(); }
                if (mode != "amnezia") AwgStopAll("");
                if (mode == "meduza") MeduzaStartedAt = DateTime.Now;
                ProbeFailures = 0; DownTicks = 0; LastTraffic = null; AwgProbeFailures = 0; AwgDownTicks = 0; AwgTraffic = null; ForceIcs = true;
                LastMode = mode;
            }
            if (mode == "meduza") MeduzaWatch();
            else if (mode == "amnezia") { if (Up(MzAdapterName())) { Log("MeduzaVPN: подключён, но выбран режим AmneziaWG — отключаю", "WARN"); MzDisconnect(); } AmneziaWatch(); }
            else if (mode == "zapret") { if (Up(MzAdapterName())) { Log("MeduzaVPN: подключён, но выбран режим без VPN — отключаю", "WARN"); MzDisconnect(); } AwgStopAll(""); LastTraffic = null; AwgTraffic = null; }
        }

        // ---------------------------------------------------------------- wg_server
        static string WgConf()
        {
            var p = CfgStr("ws4w.configPath", ""); if (p.Length > 0 && File.Exists(p)) return p;
            try {     // сервер, созданный самим VpnGuard (запомнен в state.json)
                var st = Json.DeserializeObject(File.ReadAllText(Path.Combine(DataDir, "state.json"), Encoding.UTF8)) as Dictionary<string, object>;
                object w; if (st != null && st.TryGetValue("wgConfPath", out w) && w != null && Convert.ToString(w).Length > 0 && File.Exists(Convert.ToString(w))) return Convert.ToString(w);
            } catch { }
            try {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + CfgStr("ws4w.serviceName", "WireGuardTunnel$wg_server"))) {
                    var img = k == null ? null : Convert.ToString(k.GetValue("ImagePath"));
                    var mt = Regex.Match(img ?? "", "/tunnelservice\\s+\"?([^\"]+?\\.conf(\\.dpapi)?)\"?\\s*$");
                    if (mt.Success && File.Exists(mt.Groups[1].Value)) return mt.Groups[1].Value;
                }
            } catch { }
            string n = WgIf(), pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            foreach (var c in new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WS4W", "server_wg", n + ".conf"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WS4W", n + ".conf"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WS4W", n + ".conf"),
                Path.Combine(DataDir, "wg", n + ".conf"), Path.Combine(pf, "WireGuard", "Data", "Configurations", n + ".conf.dpapi"), Path.Combine(pf, "WireGuard", "Data", "Configurations", n + ".conf") })
                if (File.Exists(c)) return c;
            return null;
        }
        static string WgServerAddress()
        {
            var a = CfgStr("ws4w.serverAddress", ""); if (a.Length > 0) return a;
            var c = WgConf();
            if (c != null && c.EndsWith(".conf")) { try { var m = Regex.Match(File.ReadAllText(c), @"(?m)^\s*Address\s*=\s*([\d\.]+)"); if (m.Success) return m.Groups[1].Value; } catch { } }
            var ip = Ipv4(WgIf()); return ip != null && !ip.StartsWith("192.168.137.") ? ip : null;
        }
        static void WgWatch()
        {
            string sn = CfgStr("ws4w.serviceName", "WireGuardTunnel$wg_server"), wgExe = CfgStr("ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe");
            var svc = Svc(sn); var conf = WgConf();
            if (svc == null) {
                if (conf != null && File.Exists(wgExe)) {
                    Log("wg_server: служба туннеля отсутствует — устанавливаю из " + conf, "WARN");
                    var r = Exe(wgExe, "/installtunnelservice \"" + conf + "\"", 60); Log("wg_server: installtunnelservice код " + r.Code + " " + r.Err, "INFO"); Thread.Sleep(5000);
                } else if (CfgBool("ws4w.autoCreateServer", true)) {
                    if (++WgMissingTicks < 3) Log("wg_server: нет ни службы, ни конфига (" + WgMissingTicks + "/3) — если так останется, создам сервер сам", "WARN");
                    else { WgMissingTicks = 0; QueuePs("wg-create"); }
                } else Log("wg_server: служба '" + sn + "' не найдена и конфиг не найден — настройте туннель в WS4W", "ERROR");
                return;
            }
            if (StartMode(sn) != "Auto") { SetAutoStart(sn); Log("wg_server: тип запуска службы -> Автоматически", "INFO"); }
            if (svc.Status != ServiceControllerStatus.Running) {
                Log("wg_server: служба в состоянии " + svc.Status + " — запускаю", "WARN");
                try { if (svc.Status != ServiceControllerStatus.Stopped) { svc.Stop(); svc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)); } svc.Start(); svc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30)); Log("wg_server: служба запущена", "INFO"); }
                catch (Exception e) { Log("wg_server: не удалось запустить: " + e.Message, "ERROR"); }
                return;
            }
            if (!Up(WgIf())) { Log("wg_server: служба работает, но адаптер не поднят — перезапуск службы", "WARN"); SvcRestart(sn); }
        }
        static Dictionary<string, string> PeerNamesByKey = new Dictionary<string, string>(), PeerNamesByIp = new Dictionary<string, string>(); static string PeerStamp = "";
        static void LoadPeerNames()
        {
            var conf = WgConf(); if (conf == null || !conf.EndsWith(".conf")) return;
            var dir = Path.GetDirectoryName(Path.GetDirectoryName(conf));
            List<string> files = new List<string>(); try { files = Directory.GetFiles(dir, "*.conf", SearchOption.AllDirectories).Where(f => f != conf).Take(200).ToList(); } catch { }
            var stamp = string.Join("|", new[] { conf }.Concat(files).Select(f => File.GetLastWriteTimeUtc(f).Ticks));
            if (stamp == PeerStamp) return;
            var byKey = new Dictionary<string, string>(); var byIp = new Dictionary<string, string>();
            bool inPeer = false; string key = null, nm = null, before = null;
            Action flush = () => { if (inPeer && key != null && nm != null) byKey[key] = nm; };
            foreach (var l in File.ReadAllLines(conf, Encoding.UTF8)) {
                if (Regex.IsMatch(l, @"^\s*\[Peer\]")) { flush(); inPeer = true; key = null; nm = before; before = null; continue; }
                if (Regex.IsMatch(l, @"^\s*\[")) { flush(); inPeer = false; before = null; continue; }
                var m = Regex.Match(l, @"^\s*[#;]\s*(?:(?:Name|Client|Имя)\s*[=:]\s*)?(.{1,60}?)\s*$");
                if (m.Success) { if (inPeer && nm == null) nm = m.Groups[1].Value; else before = m.Groups[1].Value; continue; }
                var k = Regex.Match(l, @"^\s*PublicKey\s*=\s*(\S+)"); if (inPeer && k.Success) key = k.Groups[1].Value;
            }
            flush();
            foreach (var f in files) { try { var a = Regex.Match(File.ReadAllText(f), @"(?m)^\s*Address\s*=\s*([\d\.]+)"); if (a.Success) byIp[a.Groups[1].Value] = Path.GetFileNameWithoutExtension(f); } catch { } }
            PeerNamesByKey = byKey; PeerNamesByIp = byIp; PeerStamp = stamp;
        }
        static List<object> WgPeers(out int active, out string port)
        {
            active = 0; port = ""; var list = new List<object>();
            var wg = Path.Combine(Path.GetDirectoryName(CfgStr("ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe")), "wg.exe");
            if (!File.Exists(wg)) return null;
            var r = Exe(wg, "show " + WgIf() + " dump", 5); if (r.Code != 0) return null;
            var lines = r.Out.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries); if (lines.Length == 0) return null;
            var h = lines[0].Split('\t'); if (h.Length > 2) port = h[2];
            try { LoadPeerNames(); } catch { }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            foreach (var l in lines.Skip(1)) {
                var p = l.Split('\t'); if (p.Length < 7) continue;
                string ip = Regex.Replace(p[3].Split(',')[0], @"/\d+$", ""); long hs; long.TryParse(p[4], out hs); long rx, tx; long.TryParse(p[5], out rx); long.TryParse(p[6], out tx);
                string name; if (!PeerNamesByKey.TryGetValue(p[0], out name) && !PeerNamesByIp.TryGetValue(ip, out name)) name = ip;
                bool act = hs > 0 && now - hs < 180; if (act) active++;
                list.Add(new Dictionary<string, object> { { "name", name }, { "key", p[0].Substring(0, Math.Min(8, p[0].Length)) }, { "ip", ip }, { "endpoint", p[2] == "(none)" ? "" : p[2] }, { "hsAgo", hs > 0 ? now - hs : -1 }, { "active", act }, { "rx", rx }, { "tx", tx } });
            }
            return list;
        }

        // ---------------------------------------------------------------- раздача ICS (HNetCfg через COM, записи HomeNet через WMI)
        class IcsConn { public string Name, Device, Guid; public bool Enabled; public int Type; public object Config; }
        static object Get(object o, string prop, params object[] args) { return o.GetType().InvokeMember(prop, BindingFlags.GetProperty, null, o, args); }
        static object Call(object o, string m, params object[] args) { return o.GetType().InvokeMember(m, BindingFlags.InvokeMethod, null, o, args); }
        static List<IcsConn> IcsConnections()
        {
            var res = new List<IcsConn>();
            var mgr = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.HNetShare"));
            foreach (var c in (IEnumerable)Get(mgr, "EnumEveryConnection")) {
                var props = Get(mgr, "NetConnectionProps", c); var conf = Get(mgr, "INetSharingConfigurationForINetConnection", c);
                res.Add(new IcsConn { Name = Convert.ToString(Get(props, "Name")), Device = Convert.ToString(Get(props, "DeviceName")), Guid = Convert.ToString(Get(props, "Guid")),
                    Enabled = Convert.ToBoolean(Get(conf, "SharingEnabled")), Type = Convert.ToInt32(Get(conf, "SharingConnectionType")), Config = conf });
            }
            return res;
        }
        class IcsState { public List<IcsConn> All; public IcsConn Pub, Priv; public bool Ok; }
        static IcsState IcsStatus()
        {
            string up = UplinkName(), wg = WgIf(); var all = IcsConnections();
            var st = new IcsState { All = all, Pub = all.FirstOrDefault(c => c.Name == up), Priv = all.FirstOrDefault(c => c.Name == wg) };
            var others = all.Where(c => c.Enabled && c.Name != up && c.Name != wg).ToList();
            st.Ok = st.Pub != null && st.Pub.Enabled && st.Pub.Type == 0 && st.Priv != null && st.Priv.Enabled && st.Priv.Type == 1 && others.Count == 0;
            return st;
        }
        static bool IcsScope(string addr)
        {
            if (string.IsNullOrEmpty(addr)) return false;
            using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters", true)) {
                if (k == null) return false;
                if (Convert.ToString(k.GetValue("ScopeAddress")) == addr) return false;
                k.SetValue("ScopeAddress", addr); k.SetValue("ScopeAddressBackup", addr);
            }
            Log("ICS: ScopeAddress -> " + addr, "INFO"); return true;
        }
        static bool WaitIcs(int sec)
        {
            var dl = DateTime.Now.AddSeconds(sec);
            while (DateTime.Now < dl) {
                var s = Svc("SharedAccess"); if (s == null) return false;
                if (s.Status == ServiceControllerStatus.Running) { Thread.Sleep(500); return true; }
                if (s.Status == ServiceControllerStatus.Stopped) { try { s.Start(); } catch { } }
                Thread.Sleep(1000);
            }
            var x = Svc("SharedAccess"); return x != null && x.Status == ServiceControllerStatus.Running;
        }
        static void IcsRestartService() { try { var s = Svc("SharedAccess"); if (s != null && s.Status == ServiceControllerStatus.Running) { s.Stop(); s.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)); } } catch { } WaitIcs(30); }
        // записи раздачи удалённых адаптеров (старый ULTRA) мешают включить раздачу на новом (0x80040201)
        static int ClearStaleIcs()
        {
            int n = 0;
            var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try { foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()) present.Add(ni.Id.Trim('{', '}')); } catch { }
            try { using (var ms = new ManagementObjectSearcher(@"root\StandardCimv2", "SELECT InterfaceGuid FROM MSFT_NetAdapter")) foreach (ManagementObject o in ms.Get()) present.Add(Convert.ToString(o["InterfaceGuid"]).Trim('{', '}')); } catch { }
            var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try { using (var ms = new ManagementObjectSearcher(@"root\Microsoft\HomeNet", "SELECT * FROM HNet_Connection")) foreach (ManagementObject o in ms.Get()) names[Convert.ToString(o["Guid"]).Trim('{', '}')] = Convert.ToString(o["Name"]); } catch { }
            try {
                using (var ms = new ManagementObjectSearcher(@"root\Microsoft\HomeNet", "SELECT * FROM HNet_ConnectionProperties"))
                    foreach (ManagementObject o in ms.Get()) {
                        bool pub = Convert.ToBoolean(o["IsIcsPublic"]), priv = Convert.ToBoolean(o["IsIcsPrivate"]); if (!pub && !priv) continue;
                        var g = Regex.Match(Convert.ToString(o["Connection"]), @"\{[0-9A-Fa-f\-]+\}").Value.Trim('{', '}');
                        if (g.Length == 0 || present.Contains(g)) continue;
                        string nm; names.TryGetValue(g, out nm);
                        Log("ICS: висячая запись раздачи удалённого адаптера '" + nm + "' {" + g.ToUpper() + "} (публичный=" + pub + ", частный=" + priv + ") — очищаю", "WARN");
                        try { o["IsIcsPublic"] = false; o["IsIcsPrivate"] = false; o.Put(); n++; } catch (Exception e) { Log("ICS: не удалось очистить запись " + g + ": " + e.Message, "ERROR"); }
                    }
            } catch { }
            return n;
        }
        static void ResetAllIcs()
        {
            foreach (var c in IcsConnections()) if (c.Enabled) { Log("ICS: снимаю общий доступ с '" + c.Name + "' для полной перенастройки", "INFO"); try { Call(c.Config, "DisableSharing"); } catch (Exception e) { Log("ICS: DisableSharing '" + c.Name + "': " + e.Message, "WARN"); } }
            ClearStaleIcs(); Thread.Sleep(1000); IcsRestartService();
        }
        static void EnableIcsSide(string name, int type)
        {
            Exception last = null;
            for (int t = 1; t <= 3; t++) {
                WaitIcs(30);
                var c = IcsConnections().FirstOrDefault(x => x.Name == name);
                if (c == null) throw new Exception("адаптер '" + name + "' не найден в списке подключений");
                if (c.Enabled && c.Type == type) return;
                try { if (c.Enabled) { Call(c.Config, "DisableSharing"); Thread.Sleep(1000); WaitIcs(30); } Call(c.Config, "EnableSharing", type); return; }
                catch (Exception e) {
                    last = e.InnerException ?? e; var s = Svc("SharedAccess");
                    Log("ICS: '" + name + "' попытка " + t + "/3: " + last.Message + " (служба: " + (s == null ? "?" : s.Status.ToString()) + ")", "WARN");
                    if (t == 1) ResetAllIcs(); else { Log("ICS: перезапуск службы SharedAccess", "INFO"); IcsRestartService(); }
                    Thread.Sleep(3000);
                }
            }
            throw last;
        }
        static void SharingWatch()
        {
            if (!CfgBool("sharing.enabled", true)) return;
            string up = UplinkName(), wg = WgIf();
            if (string.IsNullOrEmpty(up) || !Up(up) || !Up(wg)) return;
            string addr = WgServerAddress(); var st = IcsStatus(); string wgIp = Ipv4(wg);
            bool ipOk = addr == null || wgIp == addr || (DateTime.Now - LastIpFix).TotalMinutes < 10;
            if (st.Ok && ipOk && !ForceIcs) return;
            if (!ForceIcs && (DateTime.Now - LastIcsApply).TotalSeconds < 20) return;
            ForceIcs = false; LastIcsApply = DateTime.Now;
            Log("ICS: настраиваю общий доступ '" + up + "' -> '" + wg + "'", "INFO"); SetActivity("настраиваю раздачу");
            try {
                if (StartMode("SharedAccess") != "Auto") SetAutoStart("SharedAccess");
                bool scope = IcsScope(addr);
                if (!WaitIcs(30)) throw new Exception("служба SharedAccess не запускается");
                if (scope) { Log("ICS: перезапуск службы SharedAccess для нового адреса", "INFO"); IcsRestartService(); }
                if (ClearStaleIcs() > 0) { Log("ICS: перезапуск службы SharedAccess после очистки старых записей", "INFO"); IcsRestartService(); }
                foreach (var c in IcsConnections()) {
                    if (!c.Enabled) continue;
                    bool right = (c.Name == up && c.Type == 0) || (c.Name == wg && c.Type == 1);
                    if (!right) { Log("ICS: снимаю общий доступ с '" + c.Name + "' (тип " + c.Type + ")", "INFO"); Call(c.Config, "DisableSharing"); Thread.Sleep(1000); }
                }
                EnableIcsSide(up, 0); EnableIcsSide(wg, 1); Thread.Sleep(3000);
                wgIp = Ipv4(wg);
                if (addr != null && wgIp != addr && (DateTime.Now - LastIpFix).TotalMinutes >= 10) {
                    LastIpFix = DateTime.Now; Log("ICS: адрес wg_server стал " + wgIp + ", ожидается " + addr + " — перезапуск туннеля", "WARN");
                    SvcRestart(CfgStr("ws4w.serviceName", "WireGuardTunnel$wg_server"));
                }
                if (IcsStatus().Ok) { Log("ICS: общий доступ включён", "INFO"); LastIcsFix = DateTime.Now; IcsFixCount++; }
                else Log("ICS: после настройки состояние не подтвердилось, повторю", "WARN");
            } catch (Exception e) { Log("ICS: ошибка: " + (e.InnerException ?? e).Message, "ERROR"); }
        }

        // ---------------------------------------------------------------- PowerShell: zapret, обновления, веб-сервер, значок …
        static void QueuePs(string cmd) { try { File.WriteAllText(Path.Combine(CmdPsDir, DateTime.UtcNow.Ticks + ".cmd"), cmd, Encoding.ASCII); } catch { } PsPartAt = DateTime.MinValue; }
        static void PsPartWatch()
        {
            if (PsPart != null && !PsPart.HasExited) {
                if ((DateTime.Now - PsPartAt).TotalMinutes > 30) { Log("Агент C#: часть PowerShell работает больше 30 мин — останавливаю", "WARN"); try { PsPart.Kill(); } catch { } }
                return;
            }
            if ((DateTime.Now - PsPartAt).TotalSeconds < 120) return;
            PsPartAt = DateTime.Now;
            try {
                PsPart = Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + Path.Combine(Root, "VpnGuard.ps1") + "\" -PsPart" + (ConfigPath != Path.Combine(Root, "config.json") ? " -ConfigPath \"" + ConfigPath + "\"" : ""))
                    { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Root });
            } catch (Exception e) { Log("Агент C#: не удалось запустить часть PowerShell: " + e.Message, "ERROR"); }
        }

        // ---------------------------------------------------------------- трафик
        static readonly Dictionary<string, long[]> TrafBase = new Dictionary<string, long[]>(); static readonly Dictionary<string, string> TrafId = new Dictionary<string, string>();
        static Dictionary<string, long[]> TrafPending = NewTraf(), TrafRate = NewTraf();
        static DateTime TrafAt = DateTime.MinValue, TrafSaved = DateTime.MinValue;
        static SortedDictionary<string, Dictionary<string, long[]>> TrafDays = new SortedDictionary<string, Dictionary<string, long[]>>();
        static Dictionary<string, long[]> NewTraf() { return new Dictionary<string, long[]> { { "u", new long[2] }, { "w", new long[2] }, { "p", new long[2] } }; }
        static void LoadTrafficDays()
        {
            try {
                var j = Json.DeserializeObject(File.ReadAllText(Path.Combine(DataDir, "traffic.json"), Encoding.UTF8)) as Dictionary<string, object>;
                var days = j["days"] as Dictionary<string, object>;
                foreach (var kv in days) { var d = (Dictionary<string, object>)kv.Value; var e = NewTraf(); foreach (var k in new[] { "u", "w", "p" }) { var a = d[k] as object[]; if (a != null) e[k] = new[] { Convert.ToInt64(a[0]), Convert.ToInt64(a[1]) }; } TrafDays[kv.Key] = e; }
            } catch { }
        }
        static Dictionary<string, string> UpdateTraffic()
        {
            var names = new Dictionary<string, string> { { "u", Mode() == "zapret" ? "" : UplinkName() }, { "w", WgIf() }, { "p", PhysAlias() } };
            var now = DateTime.Now; double sec = TrafAt == DateTime.MinValue ? 0 : Math.Max(1, (now - TrafAt).TotalSeconds);
            string day = now.ToString("yyyy-MM-dd"); if (!TrafDays.ContainsKey(day)) TrafDays[day] = NewTraf(); var today = TrafDays[day];
            var nics = new List<NetworkInterface>(); try { nics = NetworkInterface.GetAllNetworkInterfaces().ToList(); } catch { }
            foreach (var k in new[] { "u", "w", "p" }) {
                var n = names[k].Length > 0 ? nics.FirstOrDefault(x => x.Name == names[k]) : null;
                long[] d = new long[2];
                if (n != null) {
                    long rx = 0, tx = 0; try { var s = n.GetIPStatistics(); rx = s.BytesReceived; tx = s.BytesSent; } catch { }
                    long[] b; string id;
                    if (TrafBase.TryGetValue(k, out b) && TrafId.TryGetValue(k, out id) && id == n.Id) d = new[] { Math.Max(0, rx - b[0]), Math.Max(0, tx - b[1]) };
                    else if (TrafBase.ContainsKey(k) && k != "p") d = new[] { rx, tx };          // адаптер пересоздан — счёт с нуля
                    TrafBase[k] = new[] { rx, tx }; TrafId[k] = n.Id;
                } else { TrafBase.Remove(k); TrafId.Remove(k); }
                TrafPending[k] = new[] { TrafPending[k][0] + d[0], TrafPending[k][1] + d[1] };
                today[k] = new[] { today[k][0] + d[0], today[k][1] + d[1] };
                TrafRate[k] = sec > 0 ? new[] { (long)(d[0] / sec), (long)(d[1] / sec) } : new long[2];
            }
            TrafAt = now;
            while (TrafDays.Count > 31) TrafDays.Remove(TrafDays.Keys.First());
            if ((now - TrafSaved).TotalSeconds >= 60) {
                try {
                    var o = new Dictionary<string, object> { { "days", TrafDays.ToDictionary(kv => kv.Key, kv => (object)kv.Value.ToDictionary(x => x.Key, x => (object)x.Value)) } };
                    var tmp = Path.Combine(DataDir, "traffic.json.tmp"); File.WriteAllText(tmp, Json.Serialize(o), Bom); File.Copy(tmp, Path.Combine(DataDir, "traffic.json"), true); File.Delete(tmp); TrafSaved = now;
                } catch { }
            }
            return names;
        }

        // ---------------------------------------------------------------- состояние для окна, веб-интерфейса и значка
        static object[] Kv(string k, object v) { return new object[] { k, v == null ? "—" : Convert.ToString(v) }; }
        static Dictionary<string, object> Comp(int level, string state, IEnumerable<string> details, List<object[]> kv)
        {
            return new Dictionary<string, object> { { "level", level }, { "state", state }, { "details", details.Where(d => !string.IsNullOrEmpty(d)).ToArray() }, { "kv", kv.ToArray() } };
        }
        static Dictionary<string, object> ReadPsStatus()
        {
            try { using (var fs = new FileStream(PsStatusPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) using (var rd = new StreamReader(fs, Encoding.UTF8)) return Json.DeserializeObject(rd.ReadToEnd()) as Dictionary<string, object>; }
            catch { return null; }
        }
        static void Snapshot()
        {
            LastSnapshot = DateTime.Now;
            try { SnapshotCore(); } catch (Exception e) { Log("Агент C#: состояние: " + e.Message, "ERROR"); }
        }
        static void SnapshotCore()
        {
            string mode = Mode(); var proc = MzProc(); bool pipe = MzPipe(); string ver = MzVersion();
            var act = AwgActive(); string tun = mode == "zapret" ? "" : mode == "amnezia" ? (act == null ? "" : act.Name) : MzAdapterName();
            var ma = Nic(tun); var wa = Nic(WgIf()); var wgSvc = Svc(CfgStr("ws4w.serviceName", "WireGuardTunnel$wg_server"));
            bool uUp = ma != null && ma.OperationalStatus == OperationalStatus.Up, wUp = wgSvc != null && wgSvc.Status == ServiceControllerStatus.Running && wa != null && wa.OperationalStatus == OperationalStatus.Up;
            if (uUp) { if (UltraUpSince == DateTime.MinValue) UltraUpSince = DateTime.Now; } else UltraUpSince = DateTime.MinValue;
            if (wUp) { if (WgUpSince == DateTime.MinValue) WgUpSince = DateTime.Now; } else WgUpSince = DateTime.MinValue;
            var adNames = UpdateTraffic();
            string uIp = ma != null ? Ipv4(tun) : null, wIp = wa != null ? Ipv4(WgIf()) : null;
            var ps = ReadPsStatus() ?? new Dictionary<string, object>();
            bool updating = MzUpdating();

            // MeduzaVPN
            int mL; string mS; bool responding = true; try { if (proc != null) responding = proc.Responding; } catch { }
            if (updating) { mL = 1; mS = "Обновляется"; } else if (proc == null) { mL = 2; mS = "Не запущен"; } else if (!responding) { mL = 1; mS = "Не отвечает"; } else { mL = 0; mS = "Работает"; }
            if (mode != "meduza" && !updating) { mL = -1; mS = proc != null ? "Не используется (запущен)" : "Не используется"; }
            string remoteVer = ps.ContainsKey("meduzaRemoteVersion") ? Convert.ToString(ps["meduzaRemoteVersion"]) : "";
            string started = ""; try { if (proc != null) started = proc.StartTime.ToString("dd.MM HH:mm"); } catch { }
            var meduza = Comp(mL, mS, new[] { "Версия " + ver + (remoteVer.Length > 0 && remoteVer != ver ? " (есть " + remoteVer + ")" : ""), proc != null ? "PID " + proc.Id + (started.Length > 0 ? ", с " + started : "") : "процесс отсутствует",
                "Канал CLI: " + (pipe ? "доступен" : "нет") + " · протокол " + MzProtocol() + (MzOverride.Length > 0 ? " (запасной вместо " + CfgStr("meduza.protocol", "ultra") + ")" : ""),
                "Перезапуски: " + Restarts.Count(d => d > DateTime.Now.AddMinutes(-30)) + " за 30 мин, посл. " + When(LastRestart) }, new List<object[]> {
                Kv("Версия", ver), Kv("Доступная версия", remoteVer.Length > 0 ? remoteVer : "—"), Kv("Последняя проверка обновлений", ps.ContainsKey("meduzaLastCheck") ? ps["meduzaLastCheck"] : "—"),
                Kv("Процесс", proc != null ? "PID " + proc.Id + (responding ? "" : " (не отвечает)") : "не запущен"), Kv("Память", proc != null ? (proc.WorkingSet64 / 1048576) + " МБ" : "—"),
                Kv("Канал CLI", pipe ? "доступен" : "нет — включите управление из командной строки"),
                Kv("VPN (страна)", CfgStr("meduza.serviceId", "").Length > 0 ? CfgStr("meduza.serviceId", "") : "по умолчанию (единственный на аккаунте)"),
                Kv("Протокол", MzProtocol() + (MzOverride.Length > 0 ? " — запасной, выбранный " + CfgStr("meduza.protocol", "ultra") + " не работал (с " + When(MzProtoSince) + ")" : "") + " · адаптер «" + MzAdapterName() + "»"),
                Kv("Автоподбор протокола", CfgBool("meduza.autoProtocol", true) ? "включён — при потере связи пробует другие протоколы" : "выключен"),
                Kv("Перезапусков за 30 мин", Restarts.Count(d => d > DateTime.Now.AddMinutes(-30)) + " из " + CfgInt("meduza.maxRestartsPer30Min", 5) + " допустимых"),
                Kv("Перезапусков с запуска агента", RestartCount), Kv("Последний перезапуск", When(LastRestart)), Kv("Причина", LastRestartReason.Length > 0 ? LastRestartReason : "—") });
            meduza["serviceId"] = CfgStr("meduza.serviceId", ""); meduza["protocol"] = CfgStr("meduza.protocol", "ultra"); meduza["adapter"] = MzAdapterName();
            meduza["catalog"] = Catalog; meduza["protoTest"] = ProtoTest; meduza["protocolNow"] = MzProtocol(); meduza["protocolOverride"] = MzOverride;

            // Туннель
            bool amz = mode == "amnezia"; bool? tTr = amz ? AwgTraffic : LastTraffic; DateTime tTrAt = amz ? AwgTrafficAt : LastTrafficAt; int tFail = amz ? AwgProbeFailures : ProbeFailures; string tWhy = amz ? AwgLastReason : LastRestartReason;
            int uL; string uS;
            if (mode == "zapret") { uL = 0; uS = "VPN выключен — напрямую"; } else if (amz && act == null) { uL = 2; uS = "Нет конфига AmneziaWG"; } else if (!uUp) { uL = 2; uS = "Отключён"; } else if (tTr == false) { uL = 1; uS = "Нет трафика"; } else { uL = 0; uS = "Подключён"; }
            string kindTitle = amz ? "AmneziaWG" + (act != null ? " — " + act.Title : "") : "MeduzaVPN · " + MzProtocol();
            string trTxt = (tTr == true ? "OK" : tTr == false ? "НЕТ" : "—");
            var ultra = Comp(uL, uS, new[] { mode == "zapret" ? "Выход: " + PhysAlias() + " · YouTube/Discord — через zapret" : amz && act != null ? "Сервер: " + act.Endpoint : "",
                "Адаптер: " + (ma != null ? tun + " · " + ma.OperationalStatus + ", IP " + uIp : mode == "zapret" ? "не нужен" : "отсутствует"),
                "Трафик: " + trTxt + ", проверка " + When(tTrAt), "Сбоев проверки подряд: " + tFail, tWhy.Length > 0 ? "Последняя причина: " + tWhy : "" }, new List<object[]> {
                Kv("Режим", ModeNames[mode]), Kv("Адаптер", ma != null ? tun + " · " + ma.OperationalStatus + " · " + ma.Description : "отсутствует"), Kv("IP", uIp ?? "—"),
                Kv("Скорость канала", ma != null ? (ma.Speed / 1000000) + " Мбит/с" : "—"), Kv("Подключён с", UltraUpSince == DateTime.MinValue ? "—" : When(UltraUpSince)),
                Kv("Протокол", mode == "meduza" ? MzProtocol() : amz ? "AmneziaWG" : "—"), Kv("Проверка трафика", trTxt + " · " + When(tTrAt)), Kv("Узлы проверки", string.Join(", ", ProbeHosts())),
                Kv("Сбоев проверки подряд", tFail + " (переподключение после " + CfgInt("meduza.probeFailuresBeforeReconnect", 3) + ")"), Kv("Переподключений с запуска агента", ReconnectCount) });
            ultra["title"] = mode == "zapret" ? "Без VPN (только zapret)" : "Туннель: " + kindTitle; ultra["kind"] = mode == "zapret" ? "" : mode; ultra["standby"] = null; ultra["switches"] = 0;

            // wg_server
            int wL; string wS; int activeN = 0; string port = "";
            if (wgSvc == null) { wL = 2; wS = "Служба не найдена"; } else if (wgSvc.Status != ServiceControllerStatus.Running) { wL = 2; wS = "Служба: " + wgSvc.Status; } else if (!wUp) { wL = 1; wS = "Адаптер не поднят"; } else { wL = 0; wS = "Работает"; }
            var peers = wUp ? WgPeers(out activeN, out port) : null; if (peers == null) { activeN = 0; port = ""; }
            string addr = WgServerAddress(); string sm = wgSvc != null ? StartMode(wgSvc.ServiceName) : "";
            var wg = Comp(wL, wS, new[] { "Служба: " + (wgSvc != null ? wgSvc.Status + " / " + sm : "нет"), "IP: " + (wIp ?? "—") + (addr != null ? " (нужен " + addr + ")" : ""), peers != null ? "Клиенты: " + activeN + " активных из " + peers.Count : "Клиенты: —" }, new List<object[]> {
                Kv("Служба", wgSvc != null ? wgSvc.ServiceName + " · " + wgSvc.Status + " / " + sm : "не найдена"), Kv("Адаптер", wa != null ? wa.OperationalStatus.ToString() : "отсутствует"),
                Kv("IP", (wIp ?? "—") + (addr != null && addr != wIp ? " (нужен " + addr + ")" : "")), Kv("Порт", port.Length > 0 ? port + " UDP" : "—"), Kv("Работает с", WgUpSince == DateTime.MinValue ? "—" : When(WgUpSince)),
                Kv("Клиенты", peers != null ? activeN + " активных из " + peers.Count : "—"), Kv("Конфиг", WgConf() ?? "—") });
            wg["peers"] = peers != null ? peers.ToArray() : new object[0];

            // ICS
            IcsState ics = null; try { ics = IcsStatus(); } catch { }
            var icsSvc = Svc("SharedAccess"); int iL; string iS;
            if (!CfgBool("sharing.enabled", true)) { iL = 1; iS = "Отключено в config"; } else if (ics == null) { iL = 1; iS = "Нет данных"; } else if (ics.Ok) { iL = 0; iS = "Включена"; } else if ((!uUp && mode != "zapret") || !wUp) { iL = 1; iS = "Ждёт адаптеры"; } else { iL = 2; iS = "Не настроена"; }
            Func<IcsConn, int, string> fi = (c, want) => c == null ? "не найдено" : !c.Enabled ? c.Name + ": общий доступ выключен" : c.Type != want ? c.Name + ": НЕВЕРНАЯ роль" : c.Name + ": OK";
            string upN = UplinkName();
            var icsOther = ics != null ? ics.All.Where(c => c.Enabled && c.Name != upN && c.Name != WgIf()).Select(c => c.Name).ToList() : new List<string>();
            var icsC = Comp(iL, iS, new[] { upN + " → " + WgIf(), "Служба ICS: " + (icsSvc != null ? icsSvc.Status.ToString() : "нет"), "Восстановлена: " + When(LastIcsFix) }, new List<object[]> {
                Kv("Схема", upN + " (публичный) → " + WgIf() + " (домашняя сеть)"), Kv("Управление раздачей", CfgBool("sharing.enabled", true) ? "включено" : "выключено в настройках"),
                Kv("Служба ICS (SharedAccess)", icsSvc != null ? icsSvc.Status + " / " + StartMode("SharedAccess") : "нет"), Kv("Публичное подключение", ics != null ? fi(ics.Pub, 0) : "—"),
                Kv("Частное подключение", ics != null ? fi(ics.Priv, 1) : "—"), Kv("Лишние подключения с ICS", icsOther.Count > 0 ? string.Join(", ", icsOther) : "нет"),
                Kv("Восстановлена", When(LastIcsFix)), Kv("Восстановлений с запуска агента", IcsFixCount) });

            // AmneziaWG
            bool used = mode == "amnezia"; bool inst = File.Exists(AwgExe());
            var aSvc = act != null ? Svc(AwgSvc(act.Name)) : null; var aNic = act != null ? Nic(act.Name) : null; bool aUp = aNic != null && aNic.OperationalStatus == OperationalStatus.Up;
            int aL; string aS;
            if (AwgTest != null && AwgTest["running"] is bool && (bool)AwgTest["running"]) { aL = 1; aS = "Тест конфигов " + AwgTest["index"] + "/" + AwgTest["total"]; }
            else if (!used) { aL = -1; aS = aSvc != null && aSvc.Status == ServiceControllerStatus.Running ? "Не используется (туннель поднят)" : "Не используется"; }
            else if (!inst) { aL = 2; aS = "Не установлен"; } else if (act == null) { aL = 2; aS = "Нет конфига"; } else if (aSvc == null) { aL = 2; aS = "Туннель не подключён"; }
            else if (aSvc.Status != ServiceControllerStatus.Running) { aL = 2; aS = "Служба: " + aSvc.Status; } else if (!aUp) { aL = 1; aS = "Адаптер не поднят"; } else if (AwgTraffic == false) { aL = 1; aS = "Нет трафика"; } else { aL = 0; aS = "Подключён"; }
            string aVer = ""; try { if (inst) aVer = FileVersionInfo.GetVersionInfo(AwgExe()).ProductVersion; } catch { }
            string aTr = AwgTraffic == true ? "OK" : AwgTraffic == false ? "НЕТ" : "—";
            var awg = Comp(aL, aS, new[] { act != null ? "Конфиг: " + act.Title + " · сервер " + act.Endpoint : "Конфиг: нет", "Туннель: " + (aUp ? "IP " + Ipv4(act.Name) : aSvc != null ? aSvc.Status.ToString() : "не подключён"),
                "Трафик: " + aTr + ", проверка " + When(AwgTrafficAt), "Перезапуски: " + AwgRestarts.Count(d => d > DateTime.Now.AddMinutes(-30)) + " за 30 мин, посл. " + When(AwgLastRestart) }, new List<object[]> {
                Kv("Клиент AmneziaWG", inst ? "установлен · версия " + aVer : "не установлен (" + AwgExe() + ")"), Kv("Используется", used ? "да — режим AmneziaWG" : "нет (другой режим)"),
                Kv("Активный конфиг", act != null ? act.Title + " (" + act.Name + ")" : "—"), Kv("Сервер", act != null ? act.Endpoint : "—"),
                Kv("Служба", aSvc != null ? aSvc.ServiceName + " · " + aSvc.Status : "не установлена"), Kv("Адаптер", aNic != null ? aNic.OperationalStatus + " · IP " + (Ipv4(act.Name) ?? "—") : "отсутствует"),
                Kv("Проверка трафика", aTr + " · " + When(AwgTrafficAt)), Kv("Сбоев проверки подряд", AwgProbeFailures), Kv("Последний перезапуск", When(AwgLastRestart)), Kv("Причина", AwgLastReason.Length > 0 ? AwgLastReason : "—"), Kv("Конфигов", AwgConfigs().Count) });
            awg["installed"] = inst; awg["active"] = act != null ? act.Name : "";
            awg["configs"] = AwgConfigs().Select(c => (object)new Dictionary<string, object> { { "name", c.Name }, { "title", c.Title }, { "endpoint", c.Endpoint }, { "address", c.Address }, { "running", Svc(AwgSvc(c.Name)) != null && Svc(AwgSvc(c.Name)).Status == ServiceControllerStatus.Running } }).ToArray();
            awg["test"] = AwgTest;

            // zapret и прочее — из части PowerShell
            object zapret = ps.ContainsKey("zapret") ? ps["zapret"] : new Dictionary<string, object> { { "level", -1 }, { "state", "Нет данных" }, { "details", new string[0] }, { "kv", new object[0] }, { "enabled", CfgBool("zapret.enabled", false) } };
            int zL = -1, zc = 0; var zd = zapret as Dictionary<string, object>; if (zd != null) { int.TryParse(Convert.ToString(zd.ContainsKey("level") ? zd["level"] : -1), out zL); if (zd.ContainsKey("conns")) int.TryParse(Convert.ToString(zd["conns"]), out zc); }

            // история (точка не чаще интервала проверки)
            long nowTs = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); long lastTs = History.Count > 0 ? Convert.ToInt64(History[History.Count - 1]["t"]) : 0;
            if (nowTs - lastTs >= Math.Max(10, CfgInt("checkIntervalSec", 30) - 2)) {
                History.Add(new Dictionary<string, object> { { "t", nowTs }, { "m", mL }, { "u", uL }, { "w", wL }, { "i", iL }, { "z", zL }, { "a", aL },
                    { "tr", new[] { TrafPending["u"][0], TrafPending["u"][1], TrafPending["w"][0], TrafPending["w"][1], TrafPending["p"][0], TrafPending["p"][1] } }, { "zc", zc } });
                TrafPending = NewTraf();
                while (History.Count > 240) History.RemoveAt(0);
            }
            string act2 = Activity;          // своё действие важнее; иначе — что делает часть PowerShell (обновление, zapret)
            if (act2.Length == 0 && ps.ContainsKey("activity") && PsPart != null && !PsPart.HasExited) act2 = Convert.ToString(ps["activity"]);
            bool busy = act2.Length > 0;
            var snap = new Dictionary<string, object> {
                { "updated", DateTime.Now.ToString("o") }, { "staleAfterSec", updating ? 1800 : busy ? 900 : CfgInt("checkIntervalSec", 30) + 120 }, { "activity", act2 },
                { "activitySince", busy ? ActivitySince.ToString("o") : "" }, { "agentStarted", StartedAt.ToString("o") }, { "agentPid", Process.GetCurrentProcess().Id },
                { "agentVersion", Version + " C#" }, { "engine", "csharp" }, { "intervalSec", CfgInt("checkIntervalSec", 30) }, { "lastUpdateCheck", ps.ContainsKey("meduzaLastCheck") ? ps["meduzaLastCheck"] : "" },
                { "meduza", meduza }, { "ultra", ultra }, { "wg", wg }, { "ics", icsC }, { "zapret", zapret },
                { "traffic", new Dictionary<string, object> { { "names", adNames }, { "rate", TrafRate }, { "days", TrafDays.Reverse().Take(14).Reverse().Select(kv => (object)new Dictionary<string, object> { { "d", kv.Key }, { "u", kv.Value["u"] }, { "w", kv.Value["w"] }, { "p", kv.Value["p"] } }).ToArray() } } },
                { "counters", new Dictionary<string, object> { { "restarts", RestartCount }, { "reconnects", ReconnectCount }, { "icsFixes", IcsFixCount } } },
                { "vpn", new Dictionary<string, object> { { "mode", mode }, { "name", ModeNames[mode] }, { "uplink", upN }, { "kind", mode == "zapret" ? "" : mode }, { "primary", CfgStr("vpn.primary", "meduza") } } },
                { "amnezia", awg }, { "software", ps.ContainsKey("software") ? ps["software"] : new object[0] }, { "remote", ps.ContainsKey("remote") ? ps["remote"] : null }, { "app", ps.ContainsKey("app") ? ps["app"] : null },
                { "history", History.ToArray() } };
            var tmp = StatusPath + ".tmp";
            File.WriteAllText(tmp, Json.Serialize(snap), Bom);
            try { if (File.Exists(StatusPath)) File.Replace(tmp, StatusPath, null); else File.Move(tmp, StatusPath); } catch { File.Copy(tmp, StatusPath, true); File.Delete(tmp); }
        }
    }
}
