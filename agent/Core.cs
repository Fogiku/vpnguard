// VpnGuard — агент на C#. Исходники агента — все файлы agent\*.cs (один partial-класс Agent, разнесённый по модулям).
// Делает сам: MeduzaVPN (процесс, подключение, трафик, перезапуски, запасной протокол, тест протоколов), AmneziaVPN (приложение,
// туннель, трафик, перезапуски), режим «без VPN», wg_server, раздача ICS, трафик, история, состояние для окна/веб/значка.
// Поручает PowerShell (VpnGuard.ps1 -PsPart, коротко, раз в 2 мин или сразу по команде): zapret, обновления VpnGuard/MeduzaVPN/
// компонентов, веб-сервер, значок, создание сервера wg_server, остальные команды. Режим «два туннеля» — пока агент на PowerShell.
// Собирается встроенным компилятором .NET Framework (C# 5), запускается из VpnGuard.ps1 (задача «VpnGuard»).
// Ядро агента: точка входа, пути, настройки, журнал, общие помощники (процессы, адаптеры, службы, кэш), самозамер.
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
        static volatile bool ForceIcs;          // только модуль «Раздача»: перенастроиться (другие модули — событиями, см. Subscribe)
        static Dictionary<string, object> Catalog, ProtoTest;
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
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
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

        // ---------------------------------------------------------------- самозамер: сколько процессора тратит каждая часть агента
        // потоки — по системному id (регистрируются при старте), шаги основного цикла — по времени процессора своего потока
        [System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
        [System.Runtime.InteropServices.DllImport("kernel32.dll")] static extern bool GetThreadTimes(IntPtr h, out long c, out long e, out long k, out long u);
        static readonly System.Collections.Concurrent.ConcurrentDictionary<int, string> PerfThreads = new System.Collections.Concurrent.ConcurrentDictionary<int, string>();
        static readonly System.Collections.Concurrent.ConcurrentDictionary<string, long[]> PerfSteps = new System.Collections.Concurrent.ConcurrentDictionary<string, long[]>();
        static void PerfThread(string name) {
#pragma warning disable 618
            PerfThreads[AppDomain.GetCurrentThreadId()] = name;
#pragma warning restore 618
        }
        static long ThreadCpu() { long c, e, k, u; return GetThreadTimes(GetCurrentThread(), out c, out e, out k, out u) ? k + u : 0; }
        static void PerfRun(string name, Action a)
        {
            long c0 = ThreadCpu(); var sw = Stopwatch.StartNew();
            try { a(); } finally { var p = PerfSteps.GetOrAdd(name, _ => new long[3]); Interlocked.Add(ref p[0], ThreadCpu() - c0); Interlocked.Add(ref p[1], sw.ElapsedMilliseconds); Interlocked.Increment(ref p[2]); }
        }
        // для окна/веба: процессорные секунды по потокам и шагам с запуска агента
        static Dictionary<string, object> PerfInfo()
        {
            var th = new Dictionary<string, double>(); double total = 0;
            try {
                var pr = Process.GetCurrentProcess(); total = pr.TotalProcessorTime.TotalSeconds;
                foreach (ProcessThread t in pr.Threads) {
                    string n; if (!PerfThreads.TryGetValue(t.Id, out n)) n = "прочие (пул задач, UDP, сборка мусора)";
                    double v = 0; try { v = t.TotalProcessorTime.TotalSeconds; } catch { }
                    double old; th.TryGetValue(n, out old); th[n] = old + v;
                }
            } catch { }
            return new Dictionary<string, object> { { "total", Math.Round(total, 1) }, { "uptime", Math.Round((DateTime.Now - Process.GetCurrentProcess().StartTime).TotalSeconds) },
                { "threads", th.ToDictionary(x => x.Key, x => (object)Math.Round(x.Value, 1)) },
                { "steps", PerfSteps.ToDictionary(x => x.Key, x => (object)new object[] { Math.Round(x.Value[0] / 1e7, 1), x.Value[1], x.Value[2] }) } };
        }

        static void Run()
        {
            PerfThread("основной цикл");
            LoadCfg(true);
            LoadTrafficDays();
            Log("VpnGuard " + Version + " запущен — агент на C# (PID " + Process.GetCurrentProcess().Id + ")", "INFO");
            MeduzaStartedAt = DateTime.Now;
            new Thread(LiveLoop) { IsBackground = true, Name = "live" }.Start();
            new Thread(InetLoop) { IsBackground = true, Name = "inet" }.Start();
            StartModules();
            // главный поток: настройки, команды по модулям, обновление кода, зависшие модули, чистка журналов
            DateTime sigAt = DateTime.Now, cleanAt = DateTime.MinValue;
            while (true) {
                Thread.Sleep(1000);
                try {
                    LoadCfg(false);
                    DispatchCommands();
                    if (WatchModules()) { Stopping = true; HandOver(); return; }
                    if ((DateTime.Now - sigAt).TotalSeconds >= 10) {
                        sigAt = DateTime.Now;
                        if (SourceSig() != CodeSig) { Log("Агент C#: код обновлён — перезапуск на новой версии", "INFO"); Stopping = true; HandOver(); return; }
                    }
                    if (DateTime.Now.Hour == 3 && DateTime.Now.Minute < 2 && (DateTime.Now - cleanAt).TotalMinutes > 10) { cleanAt = DateTime.Now; RemoveOldLogs(); }
                } catch (Exception e) { Log("Агент C#: главный поток: " + e.Message, "ERROR"); Thread.Sleep(5000); }
            }
        }

        // передать работу: VpnGuard.ps1 через задачу планировщика (он решит, какой агент запускать)
        static void HandOver()
        {
            if (Monitor.TryEnter(SnapLock, 3000)) { try { SnapshotCore(); } catch { } finally { Monitor.Exit(SnapLock); } }
            Run("cmd.exe", "/c ping -n 4 127.0.0.1 >nul & schtasks /run /tn \"VpnGuard\"", false);
        }
        static string SourceSig()
        {
            try { return string.Join("|", Directory.GetFiles(Path.Combine(Root, "agent"), "*.cs").OrderBy(f => f, StringComparer.OrdinalIgnoreCase).Select(f => Path.GetFileName(f) + ":" + File.GetLastWriteTimeUtc(f).Ticks)); } catch { return ""; }
        }

        // ---------------------------------------------------------------- настройки (умолчания — как у агента PowerShell)
        static readonly Dictionary<string, object> Defaults = new Dictionary<string, object> {
            {"checkIntervalSec", 30}, {"logRetentionDays", 14}, {"vpn.mode", "meduza"}, {"vpn.stopInactive", true},
            {"meduza.processName", "medusa_vpn"}, {"meduza.adapterName", "MeduzaVPN ULTRA"}, {"meduza.pipeName", "MeduzaVPN"}, {"meduza.cliPath", ""}, {"meduza.exePath", ""},
            {"meduza.serviceId", ""}, {"meduza.protocol", "ultra"}, {"meduza.connectTimeoutSec", 90}, {"meduza.startupGraceSec", 60},
            {"meduza.probeFailuresBeforeReconnect", 3}, {"meduza.maxRestartsPer30Min", 5}, {"meduza.autoProtocol", true}, {"meduza.protocolReturnMin", 60},
            {"ws4w.interfaceName", "wg_server"}, {"ws4w.serviceName", "WireGuardTunnel$wg_server"}, {"ws4w.configPath", ""}, {"ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe"},
            {"ws4w.serverAddress", ""}, {"ws4w.autoCreateServer", true}, {"sharing.enabled", true},
            {"amnezia.exe", ""}, {"amnezia.serviceName", "AmneziaVPN-service"}, {"amnezia.adapterPattern", "amnezia|tun2socks|TAP-Windows Adapter V9"},
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
        // что агент делает сейчас (видно в окне и вебе); модуль, начавший действие, сам сбрасывает его по окончании проверки
        [ThreadStatic] static string CurModule;
        static string ActivityBy = "";
        static void SetActivity(string t) { Activity = t; ActivitySince = DateTime.Now; ActivityBy = CurModule ?? ""; Wake("status"); }

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
        // ---------------------------------------------------------------- кэш медленных запросов Windows (адаптеры, службы, реестр, WMI)
        static readonly Dictionary<string, KeyValuePair<DateTime, object>> CacheMap = new Dictionary<string, KeyValuePair<DateTime, object>>();
        static T Cached<T>(string key, double sec, Func<T> f)
        {
            KeyValuePair<DateTime, object> e;
            lock (CacheMap) if (CacheMap.TryGetValue(key, out e) && (DateTime.UtcNow - e.Key).TotalSeconds < sec) return (T)e.Value;
            var v = f(); lock (CacheMap) CacheMap[key] = new KeyValuePair<DateTime, object>(DateTime.UtcNow, v); return v;
        }
        static void Uncache(string key) { lock (CacheMap) CacheMap.Remove(key); }
        // перечень адаптеров: полный обход Windows дорог (десятки вызовов за цикл) — не чаще раза в 2 с
        static NetworkInterface[] AllNics() { return Cached("nics", 2, () => { try { return NetworkInterface.GetAllNetworkInterfaces(); } catch { return new NetworkInterface[0]; } }); }
        static NetworkInterface Nic(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            try { return AllNics().FirstOrDefault(n => string.Equals(n.Name, name, StringComparison.OrdinalIgnoreCase)); } catch { return null; }
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
    }
}
