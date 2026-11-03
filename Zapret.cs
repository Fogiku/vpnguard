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

        static readonly Dictionary<string, object> ZDefaults = new Dictionary<string, object> {
            {"zapret.dir", ""}, {"zapret.autoUpdate", true}, {"zapret.updateCheckHours", 12}, {"zapret.version", ""}, {"zapret.strategy", ""},
            {"zapret.retestHours", 24}, {"zapret.healthCheckMin", 10}, {"zapret.gameFilter", "disabled"}, {"zapret.curlTimeoutSec", 5},
            {"zapret.videoCheck", true}, {"zapret.routeGoogleRanges", true}, {"zapret.routeIspVideo", true}, {"zapret.maxRoutes", 1500} };
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

        // запись в config.json (как веб-сервер: атомарно, с отступами)
        static readonly object CfgWriteLock = new object();
        static void CfgSet(string path, object value)
        {
            lock (CfgWriteLock) {
                Dictionary<string, object> o = null;
                try { if (File.Exists(ConfigPath)) o = Json.DeserializeObject(File.ReadAllText(ConfigPath, Encoding.UTF8)) as Dictionary<string, object>; } catch { }
                if (o == null) o = new Dictionary<string, object>();
                var parts = path.Split('.'); var cur = o;
                for (int i = 0; i < parts.Length - 1; i++) {
                    object nx; if (!cur.TryGetValue(parts[i], out nx) || !(nx is Dictionary<string, object>)) { nx = new Dictionary<string, object>(); cur[parts[i]] = nx; }
                    cur = (Dictionary<string, object>)nx;
                }
                cur[parts[parts.Length - 1]] = value;
                string tmp = ConfigPath + ".tmp";
                File.WriteAllText(tmp, Pretty(Json.Serialize(o)), Bom);
                try { if (File.Exists(ConfigPath)) File.Replace(tmp, ConfigPath, null); else File.Move(tmp, ConfigPath); } catch { File.Copy(tmp, ConfigPath, true); File.Delete(tmp); }
            }
            LoadCfg(true);
        }
        static string Pretty(string j)
        {
            var sb = new StringBuilder(); int ind = 0; bool str = false;
            for (int i = 0; i < j.Length; i++) {
                char c = j[i];
                if (str) { sb.Append(c); if (c == '\\') { sb.Append(j[++i]); } else if (c == '"') str = false; continue; }
                switch (c) {
                    case '"': str = true; sb.Append(c); break;
                    case '{': case '[': if (i + 1 < j.Length && (j[i + 1] == '}' || j[i + 1] == ']')) { sb.Append(c).Append(j[++i]); break; } sb.Append(c); ind++; sb.Append("\r\n").Append(' ', ind * 4); break;
                    case '}': case ']': ind--; sb.Append("\r\n").Append(' ', ind * 4).Append(c); break;
                    case ',': sb.Append(c).Append("\r\n").Append(' ', ind * 4); break;
                    case ':': sb.Append(": "); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        // ---------------------------------------------------------------- HTTP (GitHub, gstatic)
        static string HttpGet(string url, int timeoutSec)
        {
            var rq = (HttpWebRequest)WebRequest.Create(url); rq.UserAgent = "VpnGuard"; rq.Timeout = timeoutSec * 1000; rq.ReadWriteTimeout = timeoutSec * 1000;
            rq.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            using (var rs = rq.GetResponse()) using (var rd = new StreamReader(rs.GetResponseStream(), Encoding.UTF8)) return rd.ReadToEnd();
        }
        static void HttpDownload(string url, string file, int timeoutSec)
        {
            var rq = (HttpWebRequest)WebRequest.Create(url); rq.UserAgent = "VpnGuard"; rq.Timeout = timeoutSec * 1000; rq.ReadWriteTimeout = timeoutSec * 1000;
            using (var rs = rq.GetResponse()) using (var s = rs.GetResponseStream()) using (var f = File.Create(file)) s.CopyTo(f);
        }

        // ---------------------------------------------------------------- установка / обновление
        static string ZLocalVersion()
        {
            try {
                var f = Path.Combine(ZDir(), ".service", "version.txt"); if (File.Exists(f)) return File.ReadAllLines(f).FirstOrDefault().Trim();
                var sb = Path.Combine(ZDir(), "service.bat");
                if (File.Exists(sb)) { var m = Regex.Match(File.ReadAllText(sb), @"LOCAL_VERSION=([\d\.]+)"); if (m.Success) return m.Groups[1].Value; }
            } catch { }
            return "";
        }
        class ZRelease { public string Version, Url, Name; public long Size; }
        static ZRelease ZGetRelease(string tag)
        {
            var url = tag.Length > 0 ? "https://api.github.com/repos/" + ZRepo + "/releases/tags/" + tag : "https://api.github.com/repos/" + ZRepo + "/releases/latest";
            var r = (Dictionary<string, object>)Json.DeserializeObject(HttpGet(url, 30));
            var asset = ((IEnumerable)r["assets"]).OfType<Dictionary<string, object>>().FirstOrDefault(a => JS(a, "name").EndsWith(".zip", StringComparison.OrdinalIgnoreCase));
            if (asset == null) throw new Exception("в релизе нет .zip");
            long sz; long.TryParse(JS(asset, "size"), out sz);
            return new ZRelease { Version = JS(r, "tag_name").TrimStart('v'), Url = JS(asset, "browser_download_url"), Name = JS(asset, "name"), Size = sz };
        }
        static void ZUserLists()
        {
            var l = Path.Combine(ZDir(), "lists"); if (!Directory.Exists(l)) return;
            var files = new Dictionary<string, string> { { "ipset-exclude-user.txt", "203.0.113.113/32" }, { "list-general-user.txt", "# Never leave this file empty\r\ndomain.example.abc" }, { "list-exclude-user.txt", "domain.example.abc" } };
            foreach (var kv in files) { var p = Path.Combine(l, kv.Key); if (!File.Exists(p)) File.WriteAllText(p, kv.Value + "\r\n", new UTF8Encoding(false)); }
        }
        static void CopyTree(string src, string dst, List<string> errs)
        {
            Directory.CreateDirectory(dst);
            foreach (var f in Directory.GetFiles(src)) { try { File.Copy(f, Path.Combine(dst, Path.GetFileName(f)), true); } catch (Exception e) { errs.Add(e.Message); } }
            foreach (var d in Directory.GetDirectories(src)) CopyTree(d, Path.Combine(dst, Path.GetFileName(d)), errs);
        }
        static void ZInstall(ZRelease rel)
        {
            string dir = ZDir(), dl = Path.Combine(DataDir, "downloads"); Directory.CreateDirectory(dl);
            SetActivity("скачиваю zapret " + rel.Version);
            Log("zapret: загрузка " + rel.Url, "INFO");
            var zip = Path.Combine(dl, rel.Name); HttpDownload(rel.Url, zip, 300);
            if (rel.Size > 0 && new FileInfo(zip).Length != rel.Size) throw new Exception("размер архива не совпал (" + new FileInfo(zip).Length + " вместо " + rel.Size + ")");
            var tmp = Path.Combine(dl, "zapret_x"); try { if (Directory.Exists(tmp)) Directory.Delete(tmp, true); } catch { }
            ZipFile.ExtractToDirectory(zip, tmp);
            var winws = Directory.GetFiles(tmp, "winws.exe", SearchOption.AllDirectories).FirstOrDefault();
            if (winws == null) throw new Exception("в архиве нет bin\\winws.exe");
            var srcRoot = Path.GetDirectoryName(Path.GetDirectoryName(winws));
            SetActivity("устанавливаю zapret " + rel.Version);
            ZStopWinws();
            try { var s = Svc("WinDivert"); if (s != null && s.Status != ServiceControllerStatus.Stopped) { s.Stop(); s.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15)); } } catch { }
            var keep = new Dictionary<string, byte[]>();
            var lists = Path.Combine(dir, "lists");
            if (Directory.Exists(lists)) foreach (var f in Directory.GetFiles(lists, "*-user.txt")) keep[Path.GetFileName(f)] = File.ReadAllBytes(f);
            var errs = new List<string>(); CopyTree(srcRoot, dir, errs);
            if (errs.Count > 0) Log("zapret: не все файлы заменены: " + errs[0], "WARN");
            Directory.CreateDirectory(lists); foreach (var kv in keep) File.WriteAllBytes(Path.Combine(lists, kv.Key), kv.Value);
            ZUserLists();
            try { Directory.Delete(tmp, true); File.Delete(zip); } catch { }
            var v = ZLocalVersion(); Z["version"] = v.Length > 0 ? v : rel.Version;
            ZSetD("lastTest", DateTime.MinValue);           // стратегии могли измениться — переподобрать
            ZSave();
            Log("zapret: установлена версия " + Z["version"] + " в " + dir, "INFO");
        }
        static List<object> ZReleases(bool force)
        {
            var have = ZArr("releases");
            if (!force && have.Count > 0 && (DateTime.Now - ZD("releasesAt")).TotalHours < 12) return have;
            try {
                var list = Json.DeserializeObject(HttpGet("https://api.github.com/repos/" + ZRepo + "/releases?per_page=20", 30)) as object[];
                var res = new List<object>();
                foreach (Dictionary<string, object> r in list) {
                    if (JS(r, "draft") == "True") continue;
                    if (!((IEnumerable)r["assets"]).OfType<Dictionary<string, object>>().Any(a => JS(a, "name").EndsWith(".zip", StringComparison.OrdinalIgnoreCase))) continue;
                    DateTime pd; DateTime.TryParse(JS(r, "published_at"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out pd);
                    res.Add(new Dictionary<string, object> { { "v", JS(r, "tag_name").TrimStart('v') }, { "tag", JS(r, "tag_name") }, { "date", pd.ToLocalTime().ToString("dd.MM.yyyy") }, { "pre", JS(r, "prerelease") == "True" } });
                }
                Z["releases"] = res; Z["releasesAt"] = DateTime.Now.ToString("o"); ZSave(); return res;
            } catch (Exception e) { Log("zapret: не удалось получить список версий: " + e.Message, "WARN"); }
            return have;
        }
        static void ZUpdate(bool force)
        {
            bool inst = ZInstalled(); double since = (DateTime.Now - ZD("lastUpdateCheck")).TotalMinutes;
            string pin = ZC("version").Trim();
            if (pin.Length > 0) {                          // выбрана конкретная версия — ставим её и не обновляем
                var local0 = ZLocalVersion();
                if (inst && local0.Length > 0 && local0.TrimStart('v') == pin.TrimStart('v')) { Z["version"] = local0; return; }
                if (!force && since < 10) return;
                ZSetD("lastUpdateCheck", DateTime.Now);
                var tag = ZArr("releases").Where(r => JS(r, "v") == pin.TrimStart('v')).Select(r => JS(r, "tag")).FirstOrDefault() ?? pin;
                ZRelease rel0;
                try { rel0 = ZGetRelease(tag); } catch (Exception e) { Z["lastError"] = "версия " + pin + " не найдена на GitHub: " + e.Message; Log("zapret: " + Z["lastError"], "ERROR"); ZSave(); return; }
                Log("zapret: ставлю выбранную версию " + rel0.Version + " (установлена: " + (local0.Length > 0 ? local0 : "нет") + ")", "WARN");
                try { ZInstall(rel0); Z["lastError"] = ""; } catch (Exception e) { Z["lastError"] = "установка: " + e.Message; Log("zapret: ошибка установки: " + e.Message, "ERROR"); }
                ZSave(); return;
            }
            if (!force) {
                if (inst) { if (!ZB("autoUpdate") || since < ZI("updateCheckHours") * 60.0) return; }
                else if (since < 10) return;                // не установлен: пробуем не чаще раза в 10 мин
            }
            ZSetD("lastUpdateCheck", DateTime.Now);
            ZRelease rel;
            try { rel = ZGetRelease(""); } catch (Exception e) { Log("zapret: не удалось узнать последнюю версию: " + e.Message, "WARN"); ZSave(); return; }
            Z["remoteVersion"] = rel.Version;
            var local = ZLocalVersion();
            if (inst && local.Length > 0 && Ver(rel.Version) <= Ver(local)) { Z["version"] = local; ZSave(); Log("zapret " + local + " — актуальная версия", "INFO"); return; }
            Log("zapret: доступна версия " + rel.Version + " (установлена: " + (local.Length > 0 ? local : "нет") + ")", "INFO");
            try { ZInstall(rel); } catch (Exception e) { Z["lastError"] = "установка: " + e.Message; Log("zapret: ошибка установки: " + e.Message, "ERROR"); }
            ZSave();
        }

        // ---------------------------------------------------------------- стратегии и winws
        static List<string> ZStrategies()
        {
            if (!Directory.Exists(ZDir())) return new List<string>();
            return Directory.GetFiles(ZDir(), "general*.bat").Select(f => Path.GetFileNameWithoutExtension(f))
                .OrderBy(n => Regex.Replace(n, @"\d+", m => m.Value.PadLeft(4, '0')), StringComparer.OrdinalIgnoreCase).ToList();
        }
        static string ZStrategyArgs(string name)
        {
            string dir = ZDir(), bat = Path.Combine(dir, name + ".bat"); if (!File.Exists(bat)) return null;
            var raw = Regex.Replace(File.ReadAllText(bat, Encoding.Default), @"\^\s*\r?\n", " ");
            var line = Regex.Split(raw, @"\r?\n").FirstOrDefault(l => l.Contains("winws.exe")); if (line == null) return null;
            var m = Regex.Match(line, "winws\\.exe\"?\\s+(.*)$"); if (!m.Success) return null;
            var a = m.Groups[1].Value.Trim(); var gf = ZC("gameFilter");
            string gt = gf == "all" || gf == "tcp" ? "1024-65535" : "12", gu = gf == "all" || gf == "udp" ? "1024-65535" : "12";   // 12 = игровой фильтр выключен (как в service.bat)
            a = a.Replace("%BIN%", Path.Combine(dir, "bin") + "\\").Replace("%LISTS%", Path.Combine(dir, "lists") + "\\").Replace("%GameFilterTCP%", gt).Replace("%GameFilterUDP%", gu).Replace("%~dp0", dir + "\\");
            var left = Regex.Match(a, "%[A-Za-z_]+%"); if (left.Success) Log("zapret: в стратегии '" + name + "' остались неизвестные переменные: " + left.Value, "WARN");
            return a;
        }
        // метки времени TCP (RFC 1323): без них стратегии с fooling=ts не работают (service.bat тоже их включает)
        static string ZTcpTimestamps()
        {
            var o = Exe("netsh.exe", "interface tcp show global", 15).Out;
            if (Regex.IsMatch(o, @"(?im)(Timestamps|1323)[^\n]*:\s*(enabled|включ)")) return "Enabled";
            if (Regex.IsMatch(o, @"(?im)(Timestamps|1323)[^\n]*:\s*(disabled|выключ|отключ)")) return "Disabled";
            return "";
        }
        static void ZEnableTimestamps()
        {
            if (ZTcpTimestamps() == "Enabled") return;
            Exe("netsh.exe", "interface tcp set global timestamps=enabled", 15);
            var now = ZTcpTimestamps();
            if (now == "Enabled") Log("zapret: включены метки времени TCP (RFC 1323) — без них стратегии с fooling=ts не работают (так же делает service.bat)", "WARN");
            else Log("zapret: не удалось включить метки времени TCP (сейчас: '" + now + "') — стратегии с fooling=ts могут не работать", "ERROR");
        }
        static void ZStopWinws()
        {
            foreach (var p in Process.GetProcessesByName("winws")) { try { p.Kill(); p.WaitForExit(5000); } catch { } }
            Z["winwsPid"] = 0;
        }
        static void ZStopService()
        {
            var s = Svc("zapret"); if (s == null) return;
            try {
                if (s.Status != ServiceControllerStatus.Stopped) { Log("zapret: остановлена служба «zapret» (установлена через service.bat), иначе два winws мешают друг другу", "WARN"); s.Stop(); s.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)); }
                if (StartMode("zapret") != "Disabled") Exe("sc.exe", "config zapret start= disabled", 20);
            } catch (Exception e) { Log("zapret: не удалось остановить службу zapret: " + e.Message, "WARN"); }
        }
        static void ZStartWinws(string name)
        {
            try { ZEnableTimestamps(); } catch { }
            var a = ZStrategyArgs(name); if (a == null) throw new Exception("не удалось прочитать параметры стратегии '" + name + "'");
            var bin = Path.Combine(ZDir(), "bin");
            var p = Process.Start(new ProcessStartInfo(Path.Combine(bin, "winws.exe"), a) { WorkingDirectory = bin, UseShellExecute = false, CreateNoWindow = true });
            Thread.Sleep(1500);
            if (p.HasExited) throw new Exception("winws.exe завершился сразу (код " + p.ExitCode + ") со стратегией '" + name + "'");
            Z["winwsPid"] = p.Id;
        }
        static Process ZWinws()
        {
            int pid = ZN("winwsPid"); if (pid <= 0) return null;
            try { var p = Process.GetProcessById(pid); return p.ProcessName == "winws" && !p.HasExited ? p : null; } catch { return null; }
        }

        // ---------------------------------------------------------------- таблица маршрутов (iphlpapi)
        [StructLayout(LayoutKind.Sequential)]
        struct MIB_IPFORWARDROW { public uint Dest, Mask, Policy, NextHop; public int IfIndex, Type, Proto; public uint Age, NextHopAS, Metric1, Metric2, Metric3, Metric4, Metric5; }
        [DllImport("iphlpapi.dll")] static extern int GetIpForwardTable(IntPtr table, ref int size, bool order);
        [DllImport("iphlpapi.dll")] static extern int CreateIpForwardEntry(ref MIB_IPFORWARDROW row);
        [DllImport("iphlpapi.dll")] static extern int DeleteIpForwardEntry(ref MIB_IPFORWARDROW row);
        static List<MIB_IPFORWARDROW> RouteTable()
        {
            int size = 0; GetIpForwardTable(IntPtr.Zero, ref size, false);
            var buf = Marshal.AllocHGlobal(size + 4096); var res = new List<MIB_IPFORWARDROW>();
            try {
                size += 4096;
                if (GetIpForwardTable(buf, ref size, false) != 0) return res;
                int n = Marshal.ReadInt32(buf), sz = Marshal.SizeOf(typeof(MIB_IPFORWARDROW));
                for (int i = 0; i < n; i++) res.Add((MIB_IPFORWARDROW)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + 4 + i * sz), typeof(MIB_IPFORWARDROW)));
            } finally { Marshal.FreeHGlobal(buf); }
            return res;
        }
        static uint IpU(string ip) { return BitConverter.ToUInt32(IPAddress.Parse(ip).GetAddressBytes(), 0); }
        static string UIp(uint v) { return new IPAddress(BitConverter.GetBytes(v)).ToString(); }
        static uint MaskU(int len) { uint m = len == 0 ? 0 : 0xFFFFFFFFu << (32 - len); var b = BitConverter.GetBytes(m); Array.Reverse(b); return BitConverter.ToUInt32(b, 0); }
        static int MaskLen(uint maskNet) { var b = BitConverter.GetBytes(maskNet); Array.Reverse(b); uint m = BitConverter.ToUInt32(b, 0); int n = 0; while (m != 0) { n += (int)(m & 1); m >>= 1; } return n; }
        static string Prefix(MIB_IPFORWARDROW r) { return UIp(r.Dest) + "/" + MaskLen(r.Mask); }
        static int IfMetric(int ifIndex)
        {
            try { using (var s = new ManagementObjectSearcher(@"root\StandardCimv2", "SELECT InterfaceMetric FROM MSFT_NetIPInterface WHERE InterfaceIndex=" + ifIndex + " AND AddressFamily=2")) foreach (ManagementObject o in s.Get()) return Convert.ToInt32(o["InterfaceMetric"]); } catch { }
            return -1;
        }
        // маршрут в активной таблице (не постоянный): как New-NetRoute -RouteMetric 1 -PolicyStore ActiveStore
        static bool RouteAdd(string prefix, int ifIndex, string gw, int ifMetric)
        {
            var pp = prefix.Split('/'); int len = int.Parse(pp[1]);
            var row = new MIB_IPFORWARDROW { Dest = IpU(pp[0]) & MaskU(len), Mask = MaskU(len), NextHop = IpU(gw), IfIndex = ifIndex, Type = 4, Proto = 3, Metric1 = (uint)Math.Max(1, ifMetric + 1), Metric2 = uint.MaxValue, Metric3 = uint.MaxValue, Metric4 = uint.MaxValue, Metric5 = uint.MaxValue };
            int rc = CreateIpForwardEntry(ref row);
            if (rc == 0 || rc == 5010) return true;          // 5010 — уже есть
            var r = Exe("route.exe", "ADD " + UIp(row.Dest) + " MASK " + UIp(row.Mask) + " " + gw + " METRIC 1 IF " + ifIndex, 10);
            return r.Code == 0;
        }
        static void RouteDel(string prefix, int ifIndex, string gw)
        {
            try {
                foreach (var r in RouteTable()) if (Prefix(r) == prefix && r.IfIndex == ifIndex && UIp(r.NextHop) == gw) { var x = r; DeleteIpForwardEntry(ref x); }
            } catch { }
        }
        class ZPath { public int IfIndex; public string Alias, Gateway, Ip; }
        // физический путь в интернет (не туннель и не wg_server): маршрут 0.0.0.0/0 с наименьшей метрикой
        static ZPath ZPhys()
        {
            try {
                var nics = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && !IsTunnel(n.Name)).ToList();
                var byIdx = new Dictionary<int, NetworkInterface>();
                foreach (var n in nics) { try { var p = n.GetIPProperties().GetIPv4Properties(); if (p != null) byIdx[p.Index] = n; } catch { } }
                MIB_IPFORWARDROW best = new MIB_IPFORWARDROW(); bool found = false;
                foreach (var r in RouteTable()) {
                    if (r.Dest != 0 || r.Mask != 0 || r.NextHop == 0 || !byIdx.ContainsKey(r.IfIndex)) continue;
                    if (!found || r.Metric1 < best.Metric1) { best = r; found = true; }
                }
                if (!found) return null;
                var nic = byIdx[best.IfIndex]; var ip = Ipv4(nic.Name); if (ip == null) return null;
                return new ZPath { IfIndex = best.IfIndex, Alias = nic.Name, Gateway = UIp(best.NextHop), Ip = ip };
            } catch { return null; }
        }

        // ---------------------------------------------------------------- проверка сайтов
        static List<string> ZTargets()
        {
            var t = CfgList("zapret.testTargets", ZDefTargets).Where(x => x.Length > 0).ToList();
            if (ZB("videoCheck")) { if (!t.Contains("ytspeed")) t.Add("ytspeed"); if (!t.Contains("ytvideo")) t.Add("ytvideo"); }
            return t;
        }
        static string ZLabel(string s)
        {
            if (s == "ytvideo") return "YouTube: видео (googlevideo)";
            if (s == "ytspeed") return "YouTube: скорость загрузки";
            if (Regex.IsMatch(s, @"^get\s.*youtube\.com")) return "YouTube: загрузка страницы";
            if (s.Contains("redirector.googlevideo")) return "YouTube: выбор видеосервера";
            if (s.Contains("ytimg.com")) return "YouTube: превью";
            if (Regex.IsMatch(s, @"youtube\.com|youtu\.be")) return "YouTube: сайт";
            if (s.Contains("gateway.discord")) return "Discord: чат (gateway)";
            if (Regex.IsMatch(s, @"cdn\.discordapp|discordcdn")) return "Discord: файлы (CDN)";
            if (s.Contains("discord")) return "Discord: сайт";
            return Regex.Replace(Regex.Replace(Regex.Replace(s, @"^get\s+", ""), "^https?://", ""), "/.*$", "");
        }
        static string Kb(long b) { return (b / 1024.0).ToString("N0", CultureInfo.GetCultureInfo("ru-RU")); }
        static string CurlReason(int exit, string code, long size, long min, int ms)
        {
            if (exit == 0 && min > 0 && size < min) return "получено только " + Kb(size) + " КБ — загрузка обрывается";
            if (exit == 0 && !Regex.IsMatch(code ?? "", "^[1-5]\\d\\d$")) return "нет HTTP-ответа";
            if (exit == 0) return "";
            if (exit == 28 && size > 0 && size < 40960) return "оборвалось после " + Kb(size) + " КБ — DPI режет загрузку";
            if (exit == 28 && size > 0) { double s = Math.Max(1, ms) / 1000.0; return "медленно: " + Kb(size) + " КБ за " + s.ToString("N0") + " с (≈" + (size / 1024.0 / Math.Max(1, ms / 1000.0)).ToString("N0") + " КБ/с) — похоже на замедление"; }
            switch (exit) {
                case 6: return "не найден адрес (DNS)"; case 7: return "нет соединения"; case 18: return "передача оборвалась";
                case 28: return "таймаут — похоже на блокировку"; case 35: return "сброс при TLS-рукопожатии (DPI)"; case 52: return "пустой ответ";
                case 56: return "соединение сброшено (DPI)"; case 60: return "чужой сертификат — заглушка провайдера";
                case -1: return "curl не завершился"; case -2: return "не удалось узнать адрес видеосервера";
            }
            return "ошибка curl " + exit;
        }
        static string Curl { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "curl.exe"); } }
        const string UaChrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36";
        static string FindVideoHost(string srcIp, int timeoutSec, bool physOnly)
        {
            var vias = new List<string> { srcIp }; if (!string.IsNullOrEmpty(srcIp) && !physOnly) vias.Add("");
            foreach (var via in vias) {
                string ifa = string.IsNullOrEmpty(via) ? "" : "--interface " + via + " ";
                var r = Exe(Curl, "-s --connect-timeout 4 -m " + timeoutSec + " " + ifa + "\"https://redirector.googlevideo.com/report_mapping?di=no\"", timeoutSec + 5);
                var m = Regex.Match(r.Out, @"\b(sn-[a-z0-9-]{4,})");
                if (m.Success) { ZVideoVia = string.IsNullOrEmpty(via) ? "vpn" : "direct"; return "rr1---" + m.Groups[1].Value + ".googlevideo.com"; }
                r = Exe(Curl, "-s -L --connect-timeout 4 -m " + (timeoutSec + 7) + " " + ifa + "-A \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\" \"https://www.youtube.com/watch?v=jNQXAC9IVRw\"", timeoutSec + 12);
                m = Regex.Match(r.Out, @"rr\d{1,2}---(sn-[a-z0-9-]{4,})\.googlevideo\.com");
                if (m.Success) { ZVideoVia = string.IsNullOrEmpty(via) ? "vpn" : "direct"; return "rr1---" + m.Groups[1].Value + ".googlevideo.com"; }
            }
            return "";
        }
        static string VideoHost(string srcIp, int timeoutSec)
        {
            var at = ZD("videoHostAt"); string cur = ZS("videoHost");
            bool fresh = ZS("videoHostVia") != "direct" ? (DateTime.Now - at).TotalMinutes < 30 : (DateTime.Now - at).TotalHours < 6;
            if (cur.Length > 0 && fresh) return cur;
            if ((DateTime.Now - ZVideoMissAt).TotalMinutes < 30) return cur;      // недавно не нашли — не искать при каждой проверке
            var h = FindVideoHost(srcIp, timeoutSec, false);
            if (h.Length > 0) {
                if (ZVideoVia == "vpn" && ZS("videoHostVia") == "direct" && cur.Length > 0) { ZSetD("videoHostAt", DateTime.Now); return cur; }   // прямой лучше
                if (ZVideoVia == "direct" && cur != h) ZSetD("lastRouteRefresh", DateTime.MinValue);   // новый сервер провайдера — сразу маршруты
                Z["videoHost"] = h; ZSetD("videoHostAt", DateTime.Now); Z["videoHostVia"] = ZVideoVia; ZVideoMissAt = DateTime.MinValue; return h;
            }
            ZVideoMissAt = DateTime.Now; return cur;
        }
        static string YtSpeedUrl(string srcIp)
        {
            if (ZS("ytJs").Length > 0 && (DateTime.Now - ZD("ytJsAt")).TotalHours < 6) return ZS("ytJs");
            string ifa = string.IsNullOrEmpty(srcIp) ? "" : "--interface " + srcIp + " ";
            var r = Exe(Curl, "-s -L --compressed --connect-timeout 4 -m 15 " + ifa + "-A \"" + UaChrome + "\" \"https://www.youtube.com/\"", 20);
            var m = Regex.Match(r.Out, @"/s/player/[A-Za-z0-9_\-]+/[A-Za-z0-9_\.\-]+/[A-Za-z_]+/base\.js");
            if (m.Success) { Z["ytJs"] = "https://www.youtube.com" + m.Value; Z["ytJsAt"] = DateTime.Now.ToString("o"); }
            return ZS("ytJs");
        }
        class ZCheck { public string Url, Label, Code = "", Why = "", Host = ""; public bool Ok; public int Exit, Kb, Ms; public double Mbit; }
        // параллельно проверить сайты curl'ом с адреса физического адаптера (мимо VPN)
        static List<ZCheck> ZTest(string srcIp, List<string> urls, int timeoutSec)
        {
            string vh = urls.Contains("ytvideo") ? VideoHost(srcIp, Math.Max(6, timeoutSec)) : "", ys = urls.Contains("ytspeed") ? YtSpeedUrl(srcIp) : "";
            var jobs = new List<Tuple<string, string, bool, Process, Stopwatch>>();
            foreach (var spec in urls) {
                string u = spec; bool get = false;
                if (spec == "ytvideo") { if (vh.Length == 0) { jobs.Add(Tuple.Create(spec, "", false, (Process)null, (Stopwatch)null)); continue; } u = "https://" + vh + "/generate_204"; }
                else if (spec == "ytspeed") { if (ys.Length == 0) { jobs.Add(Tuple.Create(spec, "", false, (Process)null, (Stopwatch)null)); continue; } u = ys; get = true; }
                else { var gm = Regex.Match(spec, @"^get\s+(\S+)"); if (gm.Success) { u = gm.Groups[1].Value; get = true; } }
                string mode = get ? "-L -A \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\"" : "-I";
                int tmo = get ? timeoutSec + 5 : timeoutSec;
                string args = mode + " -s -o NUL -w \"%{http_code} %{size_download} %{time_total} %{time_connect} %{time_appconnect}\" -m " + tmo + " --connect-timeout 3" + (string.IsNullOrEmpty(srcIp) ? "" : " --interface " + srcIp) + " \"" + u + "\"";
                Process p = null;
                try { p = Process.Start(new ProcessStartInfo(Curl, args) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true }); } catch { }
                jobs.Add(Tuple.Create(spec, u, get, p, Stopwatch.StartNew()));
            }
            var outs = jobs.Select(j => j.Item4 != null ? j.Item4.StandardOutput.ReadToEndAsync() : null).ToList();
            foreach (var j in jobs) {
                if (j.Item4 == null) continue;
                int lim = j.Item3 ? timeoutSec + 8 : timeoutSec + 3;
                if (!j.Item4.WaitForExit((int)Math.Max(500, lim * 1000 - j.Item5.ElapsedMilliseconds))) { try { j.Item4.Kill(); } catch { } }
            }
            var res = new List<ZCheck>(); var inv = CultureInfo.InvariantCulture;
            for (int i = 0; i < jobs.Count; i++) {
                var j = jobs[i]; var c = new ZCheck { Url = j.Item1, Label = ZLabel(j.Item1) };
                if (j.Item4 == null) { c.Exit = -2; c.Ms = -1; c.Why = j.Item1 == "ytspeed" ? "не удалось открыть www.youtube.com" : CurlReason(-2, "", 0, 0, 0); res.Add(c); continue; }
                string o = ""; try { if (outs[i].Wait(2000)) o = outs[i].Result.Trim(); } catch { }
                c.Exit = j.Item4.HasExited ? j.Item4.ExitCode : -1;
                var pp = Regex.Split(o, @"\s+"); c.Code = pp.Length > 0 ? pp[0] : ""; long size = 0; if (pp.Length > 1) long.TryParse(pp[1], out size);
                double tt = 0, tc = 0, ta = 0;
                if (pp.Length > 2) double.TryParse(pp[2], NumberStyles.Float, inv, out tt);
                if (pp.Length > 4) { double.TryParse(pp[3], NumberStyles.Float, inv, out tc); double.TryParse(pp[4], NumberStyles.Float, inv, out ta); }
                c.Ms = tt > 0 ? (int)(tt * 1000) : (int)j.Item5.ElapsedMilliseconds;
                c.Why = CurlReason(c.Exit, c.Code, size, j.Item3 ? 65536 : 0, c.Ms);
                if (j.Item1 == "ytspeed" && size > 0) {                // нужно ≥ 1,5 Мбит/с (видео 480p)
                    c.Mbit = Math.Round(size * 8 / 1e6 / Math.Max(0.2, c.Ms / 1000.0), 1);
                    if (c.Exit == 0 || c.Exit == 28) c.Why = c.Mbit >= 1.5 ? "" : "≈" + c.Mbit.ToString(CultureInfo.GetCultureInfo("ru-RU")) + " Мбит/с — мало для видео (замедление)";
                }
                if (c.Exit == 28 && size == 0 && pp.Length > 4) {
                    if (tc == 0) c.Why = "не соединяется — адрес недоступен или заблокирован";
                    else if (ta == 0 && j.Item2.StartsWith("https:")) c.Why = "зависает TLS-рукопожатие — блокировка по имени сайта (DPI)";
                    else c.Why = "сервер не ответил — таймаут после соединения";
                }
                c.Ok = c.Why.Length == 0; c.Kb = (int)(size / 1024);
                try { c.Host = new Uri(j.Item2).Host; } catch { }
                res.Add(c);
            }
            return res;
        }
        static List<object> ZChecks(List<ZCheck> r)
        {
            return r.Select(c => (object)new Dictionary<string, object> { { "n", c.Label }, { "ok", c.Ok }, { "why", c.Why }, { "ms", c.Ms }, { "h", c.Host }, { "kb", c.Kb }, { "mbit", c.Mbit } }).ToList();
        }

        // ---------------------------------------------------------------- подбор стратегии (отдельный процесс PowerShell)
        static Dictionary<string, object> ZTestRunner()
        {
            Dictionary<string, object> t;
            try { t = Json.DeserializeObject(File.ReadAllText(ZTestPath, Encoding.UTF8)) as Dictionary<string, object>; } catch { return null; }
            if (t == null || JS(t, "running") != "True") return null;
            int pid; if (!int.TryParse(JS(t, "pid"), out pid) || pid <= 0) return null;
            try { var p = Process.GetProcessById(pid); return p.HasExited ? null : t; } catch { return null; }
        }
        static void ZStartTest(string reason)
        {
            if (ZTestRunner() != null) return;
            if (!ZInstalled()) { Log("zapret: не установлен — подбирать нечего", "WARN"); return; }
            Log("zapret: запускаю подбор стратегии (" + reason + ")", "INFO");
            var a = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + Path.Combine(Root, "VpnGuard.ps1") + "\" -ZapretTest" + (ConfigPath != Path.Combine(Root, "config.json") ? " -ConfigPath \"" + ConfigPath + "\"" : "");
            var p = Process.Start(new ProcessStartInfo("powershell.exe", a) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Root });
            File.WriteAllText(ZTestPath, Json.Serialize(new Dictionary<string, object> { { "running", true }, { "pid", p.Id }, { "started", DateTime.Now.ToString("o") }, { "index", 0 }, { "total", 0 }, { "current", "" }, { "results", new object[0] } }), Bom);
            Z["winwsPid"] = 0;
        }
        static bool ZReceiveTest()
        {
            Dictionary<string, object> t;
            try { t = Json.DeserializeObject(File.ReadAllText(ZTestPath, Encoding.UTF8)) as Dictionary<string, object>; } catch { return false; }
            if (t == null) return false;
            if (JS(t, "running") == "True") {
                int pid; int.TryParse(JS(t, "pid"), out pid); bool alive = false;
                try { alive = pid > 0 && !Process.GetProcessById(pid).HasExited; } catch { }
                if (alive) return false;
                Log("zapret: процесс подбора завершился аварийно", "ERROR"); t["running"] = false; t["error"] = "процесс подбора завершился аварийно";
            }
            if (JS(t, "consumed") == "True") return false;
            t["consumed"] = true;
            try { File.WriteAllText(ZTestPath, Json.Serialize(t), Bom); } catch { }
            ZSetD("lastTest", DateTime.Now); Z["ggcAt"] = "";
            var results = (t.ContainsKey("results") && t["results"] is IEnumerable) ? ((IEnumerable)t["results"]).OfType<Dictionary<string, object>>().ToList() : new List<Dictionary<string, object>>();
            Z["results"] = results.Select(r => (object)new Dictionary<string, object> { { "name", JS(r, "name") }, { "ok", r.ContainsKey("ok") ? r["ok"] : 0 }, { "total", r.ContainsKey("total") ? r["total"] : 0 }, { "error", JS(r, "error") }, { "checks", r.ContainsKey("checks") && r["checks"] is IEnumerable ? ((IEnumerable)r["checks"]).OfType<object>().ToArray() : new object[0] } }).ToList();
            if (JS(t, "videoHost").Length > 0) { Z["videoHost"] = JS(t, "videoHost"); ZSetD("videoHostAt", DateTime.Now); Z["videoHostVia"] = JS(t, "videoHostVia"); }
            string best = JS(t, "best");
            if (JS(t, "error").Length > 0) { Z["lastError"] = "подбор: " + JS(t, "error"); Log("zapret: подбор не удался: " + JS(t, "error"), "ERROR"); }
            else if (best.Length > 0) {
                var row = results.FirstOrDefault(r => JS(r, "name") == best);
                Z["strategy"] = best; Z["lastScore"] = row != null ? JS(row, "ok") : "0"; Z["lastTotal"] = row != null ? JS(row, "total") : "0";
                ZSetD("fallbackUntil", DateTime.MinValue); Z["healthFails"] = 0; Z["lastError"] = "";
                Log("zapret: лучшая стратегия — '" + best + "' (" + Z["lastScore"] + "/" + Z["lastTotal"] + " сайтов)", "INFO");
            } else {
                Z["strategy"] = ""; Z["lastScore"] = 0; ZSetD("fallbackUntil", DateTime.Now.AddHours(2)); Z["lastError"] = "ни одна стратегия не открыла сайты";
                Log("zapret: ни одна стратегия не сработала — YouTube/Discord остаются в VPN, повторю через 2 ч", "WARN");
            }
            ZSave(); return true;
        }

        // ---------------------------------------------------------------- маршруты мимо VPN
        static List<string> GoogleRanges()
        {
            bool fresh = File.Exists(ZGooglePath) && (DateTime.Now - File.GetLastWriteTime(ZGooglePath)).TotalHours < 24;
            if (!fresh) {
                try {
                    var j = (Dictionary<string, object>)Json.DeserializeObject(HttpGet("https://www.gstatic.com/ipranges/goog.json", 20));
                    var l = ((IEnumerable)j["prefixes"]).OfType<Dictionary<string, object>>().Select(p => JS(p, "ipv4Prefix")).Where(p => p.Length > 0).ToArray();
                    File.WriteAllText(ZGooglePath, Json.Serialize(l), Bom);
                } catch (Exception e) { Log("zapret: не удалось обновить диапазоны Google: " + e.Message, "WARN"); }
            }
            try {
                var o = Json.DeserializeObject(File.ReadAllText(ZGooglePath, Encoding.UTF8));
                IEnumerable arr = o is Dictionary<string, object> && ((Dictionary<string, object>)o).ContainsKey("value") ? (IEnumerable)((Dictionary<string, object>)o)["value"] : o as IEnumerable;
                return arr.OfType<object>().Select(x => Convert.ToString(x)).Where(x => Regex.IsMatch(x, @"^\d+\.\d+\.\d+\.\d+/\d+$")).ToList();
            } catch { return new List<string>(); }
        }
        static List<string> RouteDomains()
        {
            var d = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var x in CfgList("zapret.routeDomains", ZDefDomains)) if (x.Trim().Length > 0) d.Add(x.Trim().TrimStart('^'));
            var lists = Path.Combine(ZDir(), "lists");
            foreach (var f in CfgList("zapret.routeDomainLists", new[] { "list-google.txt" }).Concat(new[] { "list-general-user.txt" }).Distinct()) {
                var p = Path.Combine(lists, f); if (!File.Exists(p)) continue;
                foreach (var raw in File.ReadAllLines(p)) { var l = raw.Trim().TrimStart('^'); if (l.Length > 0 && !l.StartsWith("#") && l != "domain.example.abc") d.Add(l); }
            }
            return d.ToList();
        }
        // разрешить много имён параллельно (системный DNS), не дольше timeoutMs в сумме
        static Dictionary<string, IPAddress[]> ResolveMany(IEnumerable<string> names, int timeoutMs)
        {
            var list = names.Distinct().ToList(); var tasks = new Dictionary<string, Task<IPAddress[]>>();
            foreach (var n in list) { try { tasks[n] = Dns.GetHostAddressesAsync(n); } catch { } }
            try { Task.WaitAll(tasks.Values.ToArray(), timeoutMs); } catch { }
            var res = new Dictionary<string, IPAddress[]>();
            foreach (var kv in tasks) if (kv.Value.Status == TaskStatus.RanToCompletion) res[kv.Key] = kv.Value.Result.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
            return res;
        }
        // кэш-серверы YouTube у провайдера: страница ролика напрямую → кластеры sn-… → адреса rr1..20 → подсети /24 мимо VPN
        static void UpdateIspVideo(bool force)
        {
            if (!force && (DateTime.Now - ZD("ggcAt")).TotalMinutes < 30) return;
            var path = ZPhys(); if (path == null) return;
            Z["ggcAt"] = DateTime.Now.ToString("o");
            var r = Exe(Curl, "-s -L --compressed --connect-timeout 4 -m 15 --interface " + path.Ip + " -A \"" + UaChrome + "\" \"https://www.youtube.com/watch?v=jNQXAC9IVRw\"", 20);
            var cls = Regex.Matches(r.Out, @"rr\d{1,2}---(sn-[a-z0-9-]{4,})\.googlevideo\.com").Cast<Match>().Select(m => m.Groups[1].Value).Distinct().ToList();
            if (cls.Count == 0) return;
            Z["videoHost"] = "rr1---" + cls[0] + ".googlevideo.com"; ZSetD("videoHostAt", DateTime.Now); Z["videoHostVia"] = "direct";
            var names = new List<string>(); foreach (var cl in cls.Take(3)) for (int n = 1; n <= 20; n++) names.Add("rr" + n + "---" + cl + ".googlevideo.com");
            var set = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var kv in ResolveMany(names, 10000)) foreach (var a in kv.Value) { var o = a.GetAddressBytes(); set.Add(o[0] + "." + o[1] + "." + o[2] + ".0/24"); }
            var list = set.ToList();
            if (list.Count > 0 && string.Join(",", list) != string.Join(",", ZArr("ggc").Select(x => Convert.ToString(x)))) {
                Log("zapret: видеосерверы YouTube у провайдера (" + string.Join(", ", cls) + "): " + string.Join(", ", list) + " — пускаю мимо VPN", "WARN");
                Z["ggc"] = list; ZSetD("lastRouteRefresh", DateTime.MinValue);
            }
        }
        static List<string> ZPrefixes()
        {
            var set = new HashSet<string>(); var order = new List<string>();
            Action<string> add = p => { if (set.Add(p)) order.Add(p); };
            if (ZB("routeGoogleRanges")) { foreach (var p in GoogleRanges()) add(p); if (ZB("routeIspVideo")) foreach (var p in ZArr("ggc")) add(Convert.ToString(p)); }
            foreach (var kv in ResolveMany(RouteDomains(), 10000)) foreach (var a in kv.Value) add(a + "/32");
            foreach (var r in ZRoutes()) { var p = JS(r, "p"); if (p.EndsWith("/32")) add(p); }   // старые /32 оставляем (IP у CDN меняются)
            var list = order.Where(p => !Regex.IsMatch(p, @"^(8\.8\.8\.|8\.8\.4\.)")).ToList();    // публичный DNS остаётся в VPN
            int max = ZI("maxRoutes"); if (max > 0 && list.Count > max) list = list.Take(max).ToList();
            return list;
        }
        static void ZRemoveRoutes()
        {
            int n = 0;
            var table = RouteTable();
            foreach (var r in ZRoutes()) {
                string p = JS(r, "p"), g = JS(r, "g"); int i; int.TryParse(JS(r, "i"), out i);
                foreach (var row in table) if (row.IfIndex == i && UIp(row.NextHop) == g && Prefix(row) == p) { var x = row; DeleteIpForwardEntry(ref x); }
                n++;
            }
            if (n > 0) Log("zapret: убрано " + n + " маршрутов — YouTube/Discord снова через VPN", "INFO");
            Z["routes"] = new object[0]; ZSave();
        }
        static void ZSyncRoutes(bool refresh)
        {
            if (ZDirect()) { if (ZRoutes().Count > 0) ZRemoveRoutes(); return; }      // без VPN всё и так напрямую
            var path = ZPhys(); if (path == null) { Log("zapret: нет физического выхода в интернет — маршруты не ставлю", "WARN"); return; }
            var routes = ZRoutes();
            if (routes.Count > 0 && routes.Any(r => JS(r, "i") != path.IfIndex.ToString() || JS(r, "g") != path.Gateway)) {
                Log("zapret: сменился выход в интернет (" + path.Alias + " через " + path.Gateway + ") — переставляю маршруты", "INFO");
                ZRemoveRoutes(); routes = new List<Dictionary<string, object>>(); refresh = true;
            }
            bool need = refresh || routes.Count == 0 || (DateTime.Now - ZD("lastRouteRefresh")).TotalMinutes >= 30;
            var want = need ? ZPrefixes() : routes.Select(r => JS(r, "p")).ToList();
            if (need) ZSetD("lastRouteRefresh", DateTime.Now);
            var table = RouteTable();
            var have = new HashSet<string>(table.Where(r => r.IfIndex == path.IfIndex).Select(Prefix));
            int added = 0, failed = 0, ifm = -1;
            foreach (var p in want) {
                if (have.Contains(p)) continue;
                if (ifm < 0) ifm = Math.Max(0, IfMetric(path.IfIndex));
                if (RouteAdd(p, path.IfIndex, path.Gateway, ifm)) added++; else failed++;
            }
            var ws = new HashSet<string>(want);
            foreach (var r in routes) { if (!ws.Contains(JS(r, "p"))) { int i; int.TryParse(JS(r, "i"), out i); RouteDel(JS(r, "p"), i, JS(r, "g")); } }
            Z["routes"] = want.Select(p => (object)new Dictionary<string, object> { { "p", p }, { "i", path.IfIndex }, { "g", path.Gateway } }).ToList();
            if (added > 0) Log("zapret: добавлено " + added + " маршрутов мимо VPN через " + path.Alias + " (всего " + want.Count + ")", "INFO");
            if (failed > 0) Log("zapret: не удалось добавить " + failed + " маршрутов", "WARN");
            ZSave();
        }

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
            if ((DateTime.Now - ZD("healthAt")).TotalMinutes >= ZI("healthCheckMin")) {
                var path = ZPhys();
                if (path != null) {
                    var r = ZTest(path.Ip, ZTargets(), ZI("curlTimeoutSec"));
                    int ok = r.Count(x => x.Ok);
                    ZSetD("healthAt", DateTime.Now); Z["healthOk"] = ok; Z["healthTotal"] = r.Count; Z["healthChecks"] = ZChecks(r);
                    int minOk = Math.Max(1, Math.Min(ZN("lastScore"), r.Count) - 1);
                    var bad = r.Where(x => !x.Ok).ToList(); var sig = string.Join("|", bad.Select(x => x.Label));
                    if (bad.Count > 0 && (sig != ZBadSig || ok < minOk)) Log("zapret: не прошли проверку: " + string.Join("; ", bad.Select(x => x.Label + " — " + x.Why)), ok < minOk ? "WARN" : "INFO");
                    else if (bad.Count == 0 && ZBadSig.Length > 0) Log("zapret: все проверки снова проходят", "INFO");
                    ZBadSig = sig;
                    if (ok < minOk) {
                        Z["healthFails"] = ZN("healthFails") + 1;
                        Log("zapret: открылось " + ok + "/" + r.Count + " сайтов", "WARN");
                        if (ZN("healthFails") >= 2 && manual.Length == 0) { Z["healthFails"] = 0; ZStartTest("стратегия перестала работать"); }
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
            string vpnWarn = on && vpnOn ? "Включён вместе с VPN: YouTube и Discord этого ПК идут мимо VPN через zapret (провайдер их замедляет), а у клиентов wg_server, пока zapret включён, они не открываются — zapret работает только для самого ПК. Через VPN YouTube обычно быстрее; если zapret нужен — режим «Без VPN»." : "";
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
