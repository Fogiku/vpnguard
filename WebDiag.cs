// VpnGuard — удалённая диагностика на C# (раньше — PowerShell «-WebTask net/system/check/files»: 4–45 с, из них ~3 с — запуск PowerShell
// и медленные командлеты CIM). Здесь — прямые запросы к Windows: сеть, система, живые проверки, файлы. Только чтение, ничего не меняет.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
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

namespace VpnGuard
{
    public static partial class Web
    {
        // ---------------------------------------------------------------- помощники
        static string RunOut(string exe, string args, int sec)
        {
            try {
                var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
                    StandardOutputEncoding = Encoding.GetEncoding(System.Globalization.CultureInfo.CurrentCulture.TextInfo.OEMCodePage) };
                using (var p = Process.Start(psi)) {
                    var o = p.StandardOutput.ReadToEndAsync(); var e = p.StandardError.ReadToEndAsync();
                    if (!p.WaitForExit(sec * 1000)) { try { p.Kill(); } catch { } return "(таймаут " + sec + " с)"; }
                    return (o.Result + e.Result).TrimEnd();
                }
            } catch (Exception ex) { return "ошибка: " + ex.Message; }
        }
        // таблица с выравниванием (как Format-Table)
        static string Table(string[] head, IEnumerable<string[]> rows)
        {
            var all = new List<string[]> { head }; all.AddRange(rows);
            var w = head.Select((h, i) => all.Max(r => i < r.Length ? (r[i] ?? "").Length : 0)).ToArray();
            var sb = new StringBuilder();
            foreach (var r in all) {
                sb.AppendLine(string.Join(" ", w.Select((x, i) => (i < r.Length ? r[i] ?? "" : "").PadRight(x))).TrimEnd());
                if (r == head) sb.AppendLine(string.Join(" ", w.Select(x => new string('-', x))));
            }
            return sb.ToString();
        }
        static List<ManagementBaseObject> Wmi(string scope, string q)
        {
            try { using (var s = new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery(q))) return s.Get().Cast<ManagementBaseObject>().ToList(); }
            catch { return new List<ManagementBaseObject>(); }
        }
        static string W(ManagementBaseObject o, string p) { try { var v = o[p]; return v is string[] ? string.Join(", ", (string[])v) : Convert.ToString(v); } catch { return ""; } }
        static string Short(string t, int n = 300) { t = Regex.Replace(t ?? "", @"\s+", " ").Trim(); return t.Length > n ? t.Substring(0, n) + "…" : t; }
        static Dictionary<string, object> StatusObj() { try { return Json.DeserializeObject(ReadShared(StatusPath) ?? "{}") as Dictionary<string, object> ?? new Dictionary<string, object>(); } catch { return new Dictionary<string, object>(); } }
        static object Pick(object o, params string[] path) { foreach (var k in path) { var d = o as Dictionary<string, object>; if (d == null || !d.ContainsKey(k)) return null; o = d[k]; } return o; }
        static string Ip4(NetworkInterface n) { try { var u = n.GetIPProperties().UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork); return u != null ? u.Address.ToString() : null; } catch { return null; } }
        static NetworkInterface NicByName(string name) { try { return NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => string.Equals(n.Name, name, StringComparison.OrdinalIgnoreCase)); } catch { return null; } }
        static bool TcpFrom(string src, string hostPort, int ms, out long took)
        {
            took = -1; var hp = hostPort.Split(':'); if (hp.Length != 2) return false; var sw = Stopwatch.StartNew();
            using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)) {
                try {
                    if (!string.IsNullOrEmpty(src)) s.Bind(new IPEndPoint(IPAddress.Parse(src), 0));
                    var ar = s.BeginConnect(hp[0], int.Parse(hp[1]), null, null);
                    if (ar.AsyncWaitHandle.WaitOne(ms)) { s.EndConnect(ar); took = sw.ElapsedMilliseconds; return true; }
                } catch { }
            }
            return false;
        }
        static string[] CfgListW(string key, string[] def)
        {
            var v = CfgGet(key, null) as System.Collections.IEnumerable; if (v == null || v is string) return def;
            var l = new List<string>(); foreach (var x in v) l.Add(Convert.ToString(x)); return l.Count > 0 ? l.ToArray() : def;
        }
        // параллельно: имя → результат
        static Dictionary<string, string> Parallel(IEnumerable<KeyValuePair<string, Func<string>>> jobs, int waitMs)
        {
            var res = new Dictionary<string, string>(); var ts = new List<Thread>();
            foreach (var j in jobs) { var jj = j; var t = new Thread(() => { string r; try { r = jj.Value(); } catch (Exception e) { r = "ошибка: " + e.Message; } lock (res) res[jj.Key] = r; }) { IsBackground = true }; t.Start(); ts.Add(t); }
            var dl = DateTime.Now.AddMilliseconds(waitMs); foreach (var t in ts) t.Join(Math.Max(0, (int)(dl - DateTime.Now).TotalMilliseconds));
            lock (res) return new Dictionary<string, string>(res);
        }
        static string Curl { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "curl.exe"); } }
        static string PublicIp(string src) { var r = RunOut(Curl, "-s --connect-timeout 4 -m 8 " + (src != null ? "--interface " + src + " " : "") + "https://api.ipify.org", 12); return Regex.IsMatch(r, @"^\d+\.\d+\.\d+\.\d+$") ? r : "нет ответа"; }

        // DNS-запрос «A» к конкретному серверу (UDP 53) — без PowerShell
        static string DnsA(string name, string server, out long ms)
        {
            ms = -1; var sw = Stopwatch.StartNew();
            try {
                var q = new List<byte> { 0x4b, 0x1d, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
                foreach (var part in name.Split('.')) { q.Add((byte)part.Length); q.AddRange(Encoding.ASCII.GetBytes(part)); }
                q.AddRange(new byte[] { 0, 0, 1, 0, 1 });
                using (var u = new UdpClient()) {
                    u.Client.ReceiveTimeout = 3000; u.Send(q.ToArray(), q.Count, server, 53);
                    IPEndPoint ep = null; var b = u.Receive(ref ep); ms = sw.ElapsedMilliseconds;
                    int an = (b[6] << 8) | b[7], o = q.Count, rc = b[3] & 15; var ips = new List<string>();
                    if (rc != 0) return "ошибка ответа (код " + rc + ")";
                    for (int i = 0; i < an && o + 12 <= b.Length; i++) {
                        if ((b[o] & 0xC0) == 0xC0) o += 2; else { while (o < b.Length && b[o] != 0) o += b[o] + 1; o++; }
                        int type = (b[o] << 8) | b[o + 1], len = (b[o + 8] << 8) | b[o + 9]; o += 10;
                        if (type == 1 && len == 4) ips.Add(b[o] + "." + b[o + 1] + "." + b[o + 2] + "." + b[o + 3]);
                        o += len;
                    }
                    return ips.Count > 0 ? string.Join(", ", ips) : "нет A-записей";
                }
            } catch (Exception e) { ms = sw.ElapsedMilliseconds; return "ошибка: " + Short(e.Message, 80); }
        }
        [DllImport("iphlpapi.dll")] static extern int GetBestInterface(uint dest, out uint ifIndex);
        static string RouteTo(string ip)
        {
            try {
                uint idx; if (GetBestInterface(BitConverter.ToUInt32(IPAddress.Parse(ip).GetAddressBytes(), 0), out idx) != 0) return "?";
                var n = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(x => { try { return x.GetIPProperties().GetIPv4Properties().Index == idx; } catch { return false; } });
                return n != null ? n.Name : "интерфейс " + idx;
            } catch { return "?"; }
        }

        // ---------------------------------------------------------------- /net
        static string DiagNet()
        {
            var sb = new StringBuilder();
            var jobs = Parallel(new[] {
                new KeyValuePair<string, Func<string>>("ipconfig", () => RunOut("ipconfig.exe", "/all", 20)),
                new KeyValuePair<string, Func<string>>("route", () => RunOut("route.exe", "print -4", 20)),
                new KeyValuePair<string, Func<string>>("tcp", () => RunOut("netsh.exe", "interface tcp show global", 20)),
                new KeyValuePair<string, Func<string>>("udp", () => RunOut("netstat.exe", "-ano -p UDP", 20)),
            }, 25000);
            Func<string, string> J = k => jobs.ContainsKey(k) ? jobs[k] : "(нет данных)";
            sb.AppendLine("===== ipconfig /all").AppendLine(J("ipconfig"));
            sb.AppendLine("===== route print -4").AppendLine(J("route"));
            var nics = NetworkInterface.GetAllNetworkInterfaces();
            Func<NetworkInterface, int> idxOf = n => { try { return n.GetIPProperties().GetIPv4Properties().Index; } catch { return -1; } };
            sb.AppendLine("===== адаптеры").Append(Table(new[] { "ifIndex", "Name", "InterfaceDescription", "Status", "LinkSpeed" },
                nics.Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback).OrderBy(idxOf).Select(n => new[] { idxOf(n).ToString(), n.Name, n.Description, n.OperationalStatus.ToString(), n.Speed > 0 ? (n.Speed >= 1000000000 ? n.Speed / 1000000000 + " Gbps" : n.Speed / 1000000 + " Mbps") : "0 bps" })));
            var ipif = Wmi(@"\\.\root\StandardCimv2", "SELECT InterfaceIndex, InterfaceAlias, InterfaceMetric, AutomaticMetric, ConnectionState, Forwarding, NlMtu FROM MSFT_NetIPInterface WHERE AddressFamily=2");
            Func<string, string> onOff = v => v == "1" ? "Enabled" : v == "0" ? "Disabled" : v;
            sb.AppendLine("===== IPv4-интерфейсы (метрики, пересылка)").Append(Table(new[] { "ifIndex", "InterfaceAlias", "InterfaceMetric", "AutomaticMetric", "ConnectionState", "Forwarding", "NlMtu" },
                ipif.OrderBy(o => { int m; int.TryParse(W(o, "InterfaceMetric"), out m); return m; }).Select(o => new[] { W(o, "InterfaceIndex"), W(o, "InterfaceAlias"), W(o, "InterfaceMetric"), onOff(W(o, "AutomaticMetric")),
                    W(o, "ConnectionState") == "1" ? "Connected" : "Disconnected", onOff(W(o, "Forwarding")), W(o, "NlMtu") })));
            sb.AppendLine("===== IPv4-адреса").Append(Table(new[] { "InterfaceAlias", "IPAddress", "PrefixLength" },
                nics.SelectMany(n => { try { return n.GetIPProperties().UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork).Select(a => new[] { n.Name, a.Address.ToString(), a.PrefixLength.ToString() }); } catch { return new string[0][]; } })));
            sb.AppendLine("===== TCP (метки времени нужны стратегиям zapret с fooling=ts)").AppendLine(J("tcp"));
            sb.AppendLine("===== DNS-серверы").Append(Table(new[] { "InterfaceAlias", "ServerAddresses" },
                nics.Select(n => { try { return new[] { n.Name, string.Join(", ", n.GetIPProperties().DnsAddresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString())) }; } catch { return new[] { n.Name, "" }; } }).Where(r => r[1].Length > 0)));
            var prof = Wmi(@"\\.\root\StandardCimv2", "SELECT InterfaceAlias, Name, NetworkCategory, IPv4Connectivity FROM MSFT_NetConnectionProfile");
            sb.AppendLine("===== профили сетей").Append(Table(new[] { "InterfaceAlias", "Name", "NetworkCategory", "IPv4Connectivity" },
                prof.Select(o => new[] { W(o, "InterfaceAlias"), W(o, "Name"), new[] { "Public", "Private", "DomainAuthenticated" }.ElementAtOrDefault(int.Parse("0" + W(o, "NetworkCategory"))) ?? W(o, "NetworkCategory"),
                    new[] { "Disconnected", "NoTraffic", "Subnet", "LocalNetwork", "Internet" }.ElementAtOrDefault(int.Parse("0" + W(o, "IPv4Connectivity"))) ?? W(o, "IPv4Connectivity") })));
            sb.AppendLine("===== правила брандмауэра VpnGuard / WireGuard");
            try {
                dynamic fw = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")); var rows = new List<string[]>();
                foreach (dynamic r in fw.Rules) { string n = r.Name; if (Regex.IsMatch(n ?? "", "VpnGuard|WireGuard|WS4W|wg_server")) rows.Add(new[] { n, ((bool)r.Enabled).ToString(), (int)r.Direction == 1 ? "Inbound" : "Outbound", (int)r.Action == 1 ? "Allow" : "Block" }); }
                sb.Append(Table(new[] { "DisplayName", "Enabled", "Direction", "Action" }, rows));
            } catch (Exception e) { sb.AppendLine("нет доступа: " + e.Message); }
            int newPort = CfgInt("ws4w.newServerPort", 51820);
            sb.AppendLine("===== прослушиваемые UDP-порты WireGuard");
            foreach (var l in J("udp").Split('\n').Where(l => Regex.IsMatch(l, @":(51820|51821|" + newPort + @")\s"))) sb.AppendLine(l.TrimEnd());
            return sb.ToString();
        }

        // ---------------------------------------------------------------- /system
        static string DiagSystem()
        {
            var sb = new StringBuilder();
            var os = Wmi(@"\\.\root\cimv2", "SELECT Caption, Version, BuildNumber, LastBootUpTime, FreePhysicalMemory, TotalVisibleMemorySize FROM Win32_OperatingSystem").FirstOrDefault();
            if (os != null) {
                DateTime boot = DateTime.MinValue; try { boot = ManagementDateTimeConverter.ToDateTime(W(os, "LastBootUpTime")); } catch { }
                long free = 0, total = 0; long.TryParse(W(os, "FreePhysicalMemory"), out free); long.TryParse(W(os, "TotalVisibleMemorySize"), out total);
                sb.AppendLine("Windows: " + W(os, "Caption") + " " + W(os, "Version") + " (сборка " + W(os, "BuildNumber") + ") · загрузка " + boot.ToString("dd.MM.yyyy HH:mm") + " · аптайм " + (int)(DateTime.Now - boot).TotalHours + " ч");
                sb.AppendLine(".NET: " + Environment.Version + " · память свободно " + free / 1024 + " из " + total / 1024 + " МБ");
            }
            sb.AppendLine("Агент VpnGuard: " + VersionText + " · папка " + Root);
            sb.AppendLine("===== процессы").Append(Table(new[] { "Id", "ProcessName", "CPU,с", "МБ", "StartTime", "Responding" },
                Process.GetProcesses().Where(p => Regex.IsMatch(p.ProcessName, "medusa|meduza|winws|wireguard|amnezia|awg|ws4w|WgServer|powershell|VpnGuardWeb|VpnGuardTray|VpnGuardAgent", RegexOptions.IgnoreCase))
                    .OrderBy(p => p.ProcessName).Select(p => {
                        string cpu = "", st = "", resp = ""; try { cpu = ((int)p.TotalProcessorTime.TotalSeconds).ToString(); st = p.StartTime.ToString("dd.MM.yyyy HH:mm:ss"); resp = p.Responding.ToString(); } catch { }
                        return new[] { p.Id.ToString(), p.ProcessName, cpu, (p.WorkingSet64 / 1048576).ToString(), st, resp }; })));
            sb.AppendLine("===== командные строки (powershell и VpnGuard)");
            foreach (var o in Wmi(@"\\.\root\cimv2", "SELECT ProcessId, CommandLine FROM Win32_Process WHERE Name='powershell.exe' OR Name LIKE 'VpnGuard%'")) {
                var cl = Regex.Replace(W(o, "CommandLine"), @"\s+", " "); sb.AppendLine(W(o, "ProcessId").PadLeft(6) + "  " + (cl.Length > 220 ? cl.Substring(0, 220) : cl));
            }
            sb.AppendLine("===== службы").Append(Table(new[] { "Name", "Status", "StartType", "DisplayName" },
                ServiceController.GetServices().Where(s => Regex.IsMatch(s.ServiceName, "WireGuard|Amnezia|SharedAccess|zapret|WinDivert|iphlpsvc|Dnscache|BFE|mpssvc|MeduzaVPN", RegexOptions.IgnoreCase))
                    .Select(s => { string stt = ""; try { stt = s.StartType.ToString(); } catch { } return new[] { s.ServiceName, s.Status.ToString(), stt, s.DisplayName }; })));
            sb.AppendLine("===== задачи планировщика");
            foreach (var t in new[] { "VpnGuard", "VpnGuardMonitor" }) {
                var r = RunOut("schtasks.exe", "/query /tn \"" + t + "\" /fo LIST /v", 15);
                Func<string, string> f = k => { var m = Regex.Match(r, "^" + k + @":\s*(.+)$", RegexOptions.Multiline); return m.Success ? m.Groups[1].Value.Trim() : "?"; };
                sb.AppendLine(r.Contains("ERROR") || r.Contains("ОШИБКА") ? t + ": не найдена" : t + ": " + f("(Status|Состояние)") + " · последний запуск " + f("(Last Run Time|Время прошлого запуска)") + " код " + f("(Last Result|Последний результат)"));
            }
            Action<string, string, int, int, Func<EventRecord, bool>> ev = (log, levels, hours, max, filter) => {
                try {
                    var q = new EventLogQuery(log, PathType.LogName, "*[System[(" + levels + ") and TimeCreated[timediff(@SystemTime) <= " + (long)hours * 3600000 + "]]]") { ReverseDirection = true };
                    using (var rd = new EventLogReader(q)) {
                        int n = 0; EventRecord e;
                        while (n < max && (e = rd.ReadEvent()) != null) using (e) {
                            if (!filter(e)) continue; n++;
                            string msg = ""; try { msg = e.FormatDescription(); } catch { }
                            sb.AppendLine((e.TimeCreated ?? DateTime.MinValue).ToString("dd.MM HH:mm:ss") + " [" + (e.Level == 2 ? "Error" : e.Level == 3 ? "Warning" : e.Level == 1 ? "Critical" : "" + e.Level) + "] " + e.ProviderName + ": " + Short(msg));
                        }
                        if (n == 0) sb.AppendLine("нет событий");
                    }
                } catch (Exception x) { sb.AppendLine("нет событий или нет доступа: " + x.Message); }
            };
            sb.AppendLine("===== журнал System: ошибки и предупреждения за 48 ч (до 150)");
            ev("System", "Level=1 or Level=2 or Level=3", 48, 150, e => true);
            sb.AppendLine("===== журнал Application: сбои программ за 7 дней");
            ev("Application", "Level=1 or Level=2", 168, 40, e => { try { return Regex.IsMatch(e.FormatDescription() ?? "", "medusa|meduza|winws|wireguard|amnezia|powershell", RegexOptions.IgnoreCase); } catch { return false; } });
            return sb.ToString();
        }

        // ---------------------------------------------------------------- /check (живые проверки; замер скорости — /check?speed=1)
        static string DiagCheck(bool speed)
        {
            var sb = new StringBuilder(); var st = StatusObj();
            string mode = Convert.ToString(Pick(st, "vpn", "mode")), uplink = Convert.ToString(Pick(st, "vpn", "uplink"));
            sb.AppendLine("Режим: " + mode + " · трафик через: '" + uplink + "' · выход ICS: '" + uplink + "'");
            // физический выход: адаптер со шлюзом, не туннель
            NetworkInterface phys = null; string physGw = "";
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback && !Regex.IsMatch(n.Name + n.Description, "MeduzaVPN|wg_server|WireGuard|Amnezia|tun2socks|TAP-Windows", RegexOptions.IgnoreCase))) {
                var g = n.GetIPProperties().GatewayAddresses.FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork && x.Address.ToString() != "0.0.0.0");
                if (g != null) { phys = n; physGw = g.Address.ToString(); break; }
            }
            string physIp = phys != null ? Ip4(phys) : null;
            string ma = Convert.ToString(Pick(st, "meduza", "adapter")), aa = Convert.ToString(Pick(st, "amnezia", "adapter"));
            var tunnels = new[] { new[] { "meduza", ma }, new[] { "amnezia", aa } };
            var probe = CfgListW("meduza.probeHosts", new[] { "1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443" });
            // внешние IP и туннели — параллельно
            var jobs = new List<KeyValuePair<string, Func<string>>> { new KeyValuePair<string, Func<string>>("pubDef", () => PublicIp(null)) };
            if (physIp != null) jobs.Add(new KeyValuePair<string, Func<string>>("pubPhys", () => PublicIp(physIp)));
            foreach (var t in tunnels) {
                var tt = t; var nic = string.IsNullOrEmpty(tt[1]) ? null : NicByName(tt[1]); var ip = nic != null ? Ip4(nic) : null;
                if (ip != null && nic.OperationalStatus == OperationalStatus.Up) jobs.Add(new KeyValuePair<string, Func<string>>("pub" + tt[0], () => PublicIp(ip)));
                foreach (var h in probe) { var hh = h; jobs.Add(new KeyValuePair<string, Func<string>>("pr" + tt[0] + hh, () => { long ms; return ip != null && TcpFrom(ip, hh, 3000, out ms) ? ms + " мс" : "НЕТ"; })); }
            }
            var r = Parallel(jobs, 15000);
            Func<string, string> R = k => r.ContainsKey(k) ? r[k] : "нет ответа";
            sb.AppendLine("Физический выход: " + (phys != null ? phys.Name + " IP " + physIp + " шлюз " + physGw + " · внешний IP " + R("pubPhys") : "не найден"));
            sb.AppendLine("Маршрут по умолчанию: внешний IP " + R("pubDef"));
            sb.AppendLine("===== туннели");
            var metrics = Wmi(@"\\.\root\StandardCimv2", "SELECT InterfaceAlias, InterfaceMetric FROM MSFT_NetIPInterface WHERE AddressFamily=2").ToDictionary(o => W(o, "InterfaceAlias"), o => W(o, "InterfaceMetric"));
            foreach (var t in tunnels) {
                var nic = string.IsNullOrEmpty(t[1]) ? null : NicByName(t[1]);
                if (nic == null) { sb.AppendLine(t[0] + ": адаптер '" + t[1] + "' отсутствует"); continue; }
                string met; metrics.TryGetValue(nic.Name, out met);
                sb.AppendLine(t[0] + ": '" + nic.Name + "' " + nic.OperationalStatus + " IP " + Ip4(nic) + " метрика " + met + " · " + string.Join(", ", probe.Select(h => h + "=" + R("pr" + t[0] + h)))
                    + (r.ContainsKey("pub" + t[0]) ? " · внешний IP " + R("pub" + t[0]) : ""));
            }
            sb.AppendLine("===== DNS");
            var dn = Parallel(new[] { "www.youtube.com", "redirector.googlevideo.com", "discord.com", "api.ipify.org" }.Select(d => new KeyValuePair<string, Func<string>>(d, () => {
                var sw = Stopwatch.StartNew(); try { var a = Dns.GetHostAddresses(d).Where(x => x.AddressFamily == AddressFamily.InterNetwork).Select(x => x.ToString()); return d + " → " + string.Join(", ", a) + " (" + sw.ElapsedMilliseconds + " мс)"; }
                catch (Exception e) { return d + " → ошибка: " + e.Message; } })), 10000);
            foreach (var d in dn.OrderBy(x => x.Key)) sb.AppendLine(d.Value);
            // видеосервер YouTube у провайдера: находит ли его DNS — системный, роутера, 8.8.8.8, 1.1.1.1
            string vhn = ""; try { vhn = Convert.ToString(Pick(Json.DeserializeObject(ReadShared(Path.Combine(DataDir, "zapret-state.json")) ?? "{}"), "videoHost")); } catch { }
            if (!string.IsNullOrEmpty(vhn)) {
                sb.AppendLine("===== DNS видеосервера " + vhn);
                var servers = new List<string[]> { new[] { "роутер " + physGw, physGw }, new[] { "Google 8.8.8.8", "8.8.8.8" }, new[] { "Cloudflare 1.1.1.1", "1.1.1.1" } }.Where(x => x[1].Length > 0).ToList();
                var sw0 = Stopwatch.StartNew(); string sys; try { sys = string.Join(", ", Dns.GetHostAddresses(vhn).Where(x => x.AddressFamily == AddressFamily.InterNetwork).Select(x => x.ToString())); } catch (Exception e) { sys = "ошибка: " + e.Message; }
                sb.AppendLine("  " + "системный (как у браузера)".PadRight(28) + " → " + sys + " (" + sw0.ElapsedMilliseconds + " мс)");
                string firstIp = null;
                foreach (var s in servers) { long ms; var a = DnsA(vhn, s[1], out ms); sb.AppendLine("  " + s[0].PadRight(28) + " → " + a + " (" + ms + " мс)"); if (firstIp == null && Regex.IsMatch(a, @"^\d")) firstIp = a.Split(',')[0].Trim(); }
                if (firstIp != null) {
                    sb.AppendLine("  маршрут к " + firstIp + " → " + RouteTo(firstIp));
                    long ms; sb.AppendLine("  TCP 443 к " + firstIp + " напрямую (" + (phys != null ? phys.Name : "—") + "): " + (physIp != null && TcpFrom(physIp, firstIp + ":443", 3000, out ms) ? "соединяется" : "НЕ соединяется"));
                }
            }
            // сайты напрямую (мимо VPN, как их видит zapret)
            if (physIp != null) {
                sb.AppendLine("===== сайты напрямую (мимо VPN, как их видит zapret)");
                var targets = CfgListW("zapret.testTargets", new[] { "https://www.youtube.com", "https://i.ytimg.com", "https://redirector.googlevideo.com", "https://discord.com", "https://gateway.discord.gg", "https://cdn.discordapp.com" });
                var sr = Parallel(targets.Select(u => new KeyValuePair<string, Func<string>>(u, () => {
                    var o = RunOut(Curl, "-s -o NUL --connect-timeout 4 -m 6 --interface " + physIp + " -w \"%{http_code} %{size_download} %{time_total}\" \"" + u + "\"", 10).Trim();
                    var p = o.Split(' '); double tt = 0; double.TryParse(p.Length > 2 ? p[2] : "0", System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out tt);
                    bool ok = p.Length > 2 && p[0] != "000"; long kb = 0; long.TryParse(p.Length > 1 ? p[1] : "0", out kb);
                    return (ok ? "OK  " : "НЕТ ") + ((int)(tt * 1000)).ToString().PadLeft(6) + " мс " + (kb / 1024).ToString().PadLeft(6) + " КБ  " + (ok ? "HTTP " + p[0] : "не соединяется");
                })), 15000);
                foreach (var u in targets) sb.AppendLine("  " + u.Replace("https://", "").PadRight(30) + " " + (sr.ContainsKey(u) ? sr[u] : "нет ответа"));
            }
            if (speed) {
                sb.AppendLine("===== скорость загрузки (10 МБ с speed.cloudflare.com, до 20 с)");
                var paths = new List<string[]>(); if (physIp != null) paths.Add(new[] { "напрямую (" + phys.Name + ")", physIp });
                foreach (var t in tunnels) { var nic = string.IsNullOrEmpty(t[1]) ? null : NicByName(t[1]); if (nic != null && nic.OperationalStatus == OperationalStatus.Up && Ip4(nic) != null) paths.Add(new[] { "через туннель " + nic.Name, Ip4(nic) }); }
                foreach (var p in paths) {
                    var o = RunOut(Curl, "-s -o NUL --connect-timeout 5 -m 20 --interface " + p[1] + " -w \"%{speed_download} %{size_download}\" \"https://speed.cloudflare.com/__down?bytes=10000000\"", 25).Trim().Split(' ');
                    double v = 0, sz = 0; double.TryParse(o[0], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out v); if (o.Length > 1) double.TryParse(o[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out sz);
                    sb.AppendLine("  " + p[0].PadRight(28) + " " + (v * 8 / 1e6).ToString("N1").PadLeft(8) + " Мбит/с  (" + (sz / 1048576).ToString("N1") + " МБ)");
                }
            } else sb.AppendLine("===== скорость загрузки: пропущена (до 60 с) — /check?speed=1");
            sb.AppendLine("===== клиенты wg_server");
            var peers = Pick(st, "wg", "peers") as object[];
            if (peers != null && peers.Length > 0) foreach (var p in peers.OfType<Dictionary<string, object>>())
                sb.AppendLine("  " + Convert.ToString(Pick(p, "name")).PadRight(20) + " " + Convert.ToString(Pick(p, "ip")).PadRight(16) + " активен " + Convert.ToString(Pick(p, "active")) + "  " + Convert.ToString(Pick(p, "endpoint")));
            else sb.AppendLine("нет данных (туннель не поднят или агент ещё не прислал состояние)");
            return sb.ToString();
        }

        // ---------------------------------------------------------------- /files
        static string DiagFiles()
        {
            var o = new Dictionary<string, object>();
            foreach (var n in new[] { "status.json", "state.json", "zapret-state.json", "zapret-test.json", "remote-state.json" }) {
                var p = Path.Combine(DataDir, n); if (!File.Exists(p)) continue;
                try { o[n] = Json.DeserializeObject(ReadShared(p) ?? "null"); } catch (Exception e) { o[n] = "не читается: " + e.Message; }
            }
            try { o["config.json"] = File.Exists(ConfigPath) ? Json.DeserializeObject(File.ReadAllText(ConfigPath, Encoding.UTF8)) : null; } catch (Exception e) { o["config.json"] = "не читается: " + e.Message; }
            try { var sp = Path.Combine(Root, "config-schema.txt"); o["config-schema (умолчания)"] = File.Exists(sp) ? Pick(Json.DeserializeObject(File.ReadAllText(sp, Encoding.UTF8)), "settings") : null; } catch { }
            try {
                o["data"] = Directory.GetFiles(DataDir, "*", SearchOption.AllDirectories).Where(f => !Regex.IsMatch(f, @"\\(downloads|logs)\\")).Select(f => { var fi = new FileInfo(f); return (object)(f.Substring(DataDir.Length + 1) + "  " + fi.Length.ToString("N0") + " Б  " + fi.LastWriteTime.ToString("dd.MM HH:mm")); }).ToArray();
            } catch { }
            return HideSecrets(Json.Serialize(o));
        }
        // всё сразу (без полного отчёта «Диагностика» — он по-прежнему в PowerShell: /bundle?diag=1)
        static string DiagBundle()
        {
            var sb = new StringBuilder();
            foreach (var part in new[] { new KeyValuePair<string, Func<string>>("СИСТЕМА", DiagSystem), new KeyValuePair<string, Func<string>>("ЖИВЫЕ ПРОВЕРКИ", () => DiagCheck(false)),
                new KeyValuePair<string, Func<string>>("СЕТЬ", DiagNet), new KeyValuePair<string, Func<string>>("ФАЙЛЫ И НАСТРОЙКИ", DiagFiles), new KeyValuePair<string, Func<string>>("ЖУРНАЛ (2 дня)", () => Logs(2, 0, 4000)) }) {
                sb.AppendLine().AppendLine("################ " + part.Key + " ################");
                try { sb.AppendLine(part.Value()); } catch (Exception e) { sb.AppendLine("ошибка: " + e.Message); }
            }
            return sb.ToString();
        }
    }
}
