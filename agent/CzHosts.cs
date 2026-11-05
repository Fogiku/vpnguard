// Ретранслятор zapret: имя сайта (SNI, Host) и списки/профили winws — что из этого zapret обработает.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace VpnGuard
{
    public static partial class Agent
    {
        // ---------------------------------------------------------------- имя сайта и списки winws (для журнала и решений)
        // zapret отправляет мимо VPN целые диапазоны адресов (Google, Discord …), а обходит DPI только для сайтов из своих списков
        // (и адресов из ipset). Соединение к сайту вне списков пошло бы к провайдеру без обхода и, скорее всего, заглохло бы.
        // Ретранслятор читает имя сайта из первого пакета (TLS ClientHello — SNI, HTTP — Host) и проверяет его так же, как winws
        // (по профилям из командной строки winws): обработает — напрямую через zapret, нет — через VPN. Сайт не ответил за
        // wg.clientFallbackMs — один повтор через другой путь; удачный путь для имени запоминается на 30 мин.
        class CzProf { public List<int[]> Ports = new List<int[]>(); public HashSet<string> Hosts, HostEx; public CzRanges Ips, IpEx; }
        static volatile List<CzProf> CzProfs = new List<CzProf>(); static string CzProfKey = ""; static int CzWArgsPid; static string CzWArgs = "";
        static readonly Dictionary<string, KeyValuePair<DateTime, object>> CzListCache = new Dictionary<string, KeyValuePair<DateTime, object>>();

        static CzRanges CzBuildRanges(IEnumerable<string> cidrs)
        {
            var rs = new List<KeyValuePair<uint, uint>>();
            foreach (var x in cidrs) {
                var pp = x.Trim().Split('/'); IPAddress ip; int len = 32;
                if (pp[0].Length == 0 || !IPAddress.TryParse(pp[0], out ip) || ip.AddressFamily != AddressFamily.InterNetwork) continue;
                if (pp.Length > 1 && (!int.TryParse(pp[1], out len) || len < 0 || len > 32)) continue;
                uint m = len == 0 ? 0 : 0xFFFFFFFFu << (32 - len), lo = IpH(ip.GetAddressBytes(), 0) & m;
                rs.Add(new KeyValuePair<uint, uint>(lo, lo | ~m));
            }
            rs.Sort((a, b) => a.Key.CompareTo(b.Key));
            var lo2 = new List<uint>(); var hi2 = new List<uint>();
            foreach (var r in rs) {
                int k = hi2.Count - 1;
                if (k >= 0 && (hi2[k] == uint.MaxValue || r.Key <= hi2[k] + 1)) { if (r.Value > hi2[k]) hi2[k] = r.Value; }
                else { lo2.Add(r.Key); hi2.Add(r.Value); }
            }
            return new CzRanges { Lo = lo2.ToArray(), Hi = hi2.ToArray() };
        }
        static bool CzInRanges(CzRanges s, uint v)
        {
            int a = 0, b = s.Lo.Length - 1;
            while (a <= b) { int m = (a + b) >> 1; if (v < s.Lo[m]) b = m - 1; else if (v > s.Hi[m]) a = m + 1; else return true; }
            return false;
        }
        static IEnumerable<string> CzListLines(string file)
        {
            try { return File.ReadAllLines(file).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith("#")); } catch { return new string[0]; }
        }
        // список доменов / адресов из файла (с кэшем по времени изменения)
        static T CzList<T>(string file, Func<IEnumerable<string>, T> make) where T : class
        {
            DateTime mt; try { mt = File.GetLastWriteTimeUtc(file); } catch { mt = DateTime.MinValue; }
            lock (CzListCache) {
                KeyValuePair<DateTime, object> c;
                if (CzListCache.TryGetValue(file, out c) && c.Key == mt && c.Value is T) return (T)c.Value;
                var v = make(CzListLines(file)); CzListCache[file] = new KeyValuePair<DateTime, object>(mt, v); return v;
            }
        }
        static HashSet<string> CzDomains(IEnumerable<string> l) { return new HashSet<string>(l.Select(x => x.TrimStart('.', '*').TrimStart('.').ToLowerInvariant()), StringComparer.OrdinalIgnoreCase); }
        // командная строка работающего winws
        static string CzWinwsArgs()
        {
            var p = ZWinws() ?? System.Diagnostics.Process.GetProcessesByName("winws").FirstOrDefault(); if (p == null) return "";
            if (p.Id == CzWArgsPid) return CzWArgs;
            string cl = "";
            try { using (var s = new System.Management.ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId=" + p.Id)) foreach (System.Management.ManagementObject o in s.Get()) cl = Convert.ToString(o["CommandLine"]); } catch { }
            CzWArgsPid = p.Id; CzWArgs = cl ?? ""; return CzWArgs;
        }
        // профили winws: порты TCP, списки доменов и адресов (что он обработает)
        static void CzUpdateProfiles(string args)
        {
            var files = Regex.Matches(args, "--(?:hostlist|hostlist-exclude|ipset|ipset-exclude)=\"?([^\"\\s]+)\"?").Cast<Match>().Select(m => m.Groups[1].Value).Distinct().ToList();
            string key = args + "|" + string.Join("|", files.Select(f => { try { return File.GetLastWriteTimeUtc(f).Ticks.ToString(); } catch { return "-"; } }));
            if (key == CzProfKey) return;
            var res = new List<CzProf>();
            foreach (var part in Regex.Split(args, @"\s--new(?=\s|$)")) {
                var ft = Regex.Match(part, @"--filter-tcp=([\d,\-]+)"); if (!ft.Success) continue;
                var pr = new CzProf();
                foreach (var r in ft.Groups[1].Value.Split(',')) { var ab = r.Split('-'); int a, b; if (int.TryParse(ab[0], out a)) pr.Ports.Add(new[] { a, ab.Length > 1 && int.TryParse(ab[1], out b) ? b : a }); }
                foreach (Match m in Regex.Matches(part, "--(hostlist|hostlist-exclude|ipset|ipset-exclude|hostlist-domains)=\"?([^\"\\s]+)\"?")) {
                    string k = m.Groups[1].Value, v = m.Groups[2].Value;
                    if (k == "hostlist") { var h = CzList<HashSet<string>>(v, CzDomains); if (pr.Hosts == null) pr.Hosts = new HashSet<string>(h, StringComparer.OrdinalIgnoreCase); else pr.Hosts.UnionWith(h); }
                    else if (k == "hostlist-domains") { var h = CzDomains(v.Split(',')); if (pr.Hosts == null) pr.Hosts = h; else pr.Hosts.UnionWith(h); }
                    else if (k == "hostlist-exclude") { var h = CzList<HashSet<string>>(v, CzDomains); if (pr.HostEx == null) pr.HostEx = new HashSet<string>(h, StringComparer.OrdinalIgnoreCase); else pr.HostEx.UnionWith(h); }
                    else if (k == "ipset") pr.Ips = CzList<CzRanges>(v, CzBuildRanges);
                    else if (k == "ipset-exclude") pr.IpEx = CzList<CzRanges>(v, CzBuildRanges);
                }
                res.Add(pr);
            }
            CzProfs = res; CzProfKey = key;
            Log("zapret для клиентов: профилей winws для TCP — " + res.Count + ", доменов в списках — " + res.Where(p => p.Hosts != null).Sum(p => p.Hosts.Count) + ", диапазонов адресов — " + res.Where(p => p.Ips != null).Sum(p => p.Ips.Lo.Length), "INFO");
        }
        static bool CzHostIn(HashSet<string> set, string host)
        {
            if (set == null || host == null) return false;
            for (string h = host; ; ) { if (set.Contains(h)) return true; int i = h.IndexOf('.'); if (i < 0) return false; h = h.Substring(i + 1); }
        }
        // обработает ли winws соединение к этому сайту (как его профили: порт, список доменов или адресов, исключения)
        static bool CzWinwsCovers(string host, uint ip, int port)
        {
            foreach (var p in CzProfs) {
                if (!p.Ports.Any(r => port >= r[0] && port <= r[1])) continue;
                if (CzHostIn(p.HostEx, host) || (p.IpEx != null && CzInRanges(p.IpEx, ip))) continue;
                if (p.Hosts == null && p.Ips == null) return true;
                if (CzHostIn(p.Hosts, host) || (p.Ips != null && CzInRanges(p.Ips, ip))) return true;
            }
            return false;
        }
        // имя сайта: TLS ClientHello (SNI) …
        static string CzSni(byte[] b, int n)
        {
            try {
                if (n < 44 || b[0] != 0x16 || b[5] != 0x01) return null;
                int p = 43;                                            // 5 запись + 4 рукопожатие + 2 версия + 32 random
                p += 1 + b[p];                                         // session id
                p += 2 + ((b[p] << 8) | b[p + 1]);                     // шифры
                p += 1 + b[p];                                         // сжатие
                int end = Math.Min(n, p + 2 + ((b[p] << 8) | b[p + 1])); p += 2;
                while (p + 4 <= end) {
                    int t = (b[p] << 8) | b[p + 1], l = (b[p + 2] << 8) | b[p + 3]; p += 4;
                    if (t == 0 && p + 5 <= end && b[p + 2] == 0) { int nl = (b[p + 3] << 8) | b[p + 4]; if (p + 5 + nl <= end) return Encoding.ASCII.GetString(b, p + 5, nl).ToLowerInvariant().TrimEnd('.'); }
                    p += l;
                }
            } catch { }
            return null;
        }
        // … или HTTP-запрос (Host)
        static string CzHttpHost(byte[] b, int n)
        {
            if (n < 16 || b[0] < 'A' || b[0] > 'Z') return null;
            var m = Regex.Match(Encoding.ASCII.GetString(b, 0, Math.Min(n, 4096)), @"\r\nHost:\s*([^\r\n:]+)", RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value.Trim().ToLowerInvariant() : null;
        }
        // первый пакет клиента: целиком запись TLS (ClientHello бывает в 2–3 сегментах) или первый кусок HTTP
        static async Task<int> CzReadFirst(Stream s, byte[] b)
        {
            int n = 0; var dl = DateTime.UtcNow.AddSeconds(10);
            while (n < b.Length) {
                var left = dl - DateTime.UtcNow; if (left <= TimeSpan.Zero) return n > 0 ? n : -1;
                var rt = s.ReadAsync(b, n, b.Length - n);
                if (await Task.WhenAny(rt, Task.Delay(left)).ConfigureAwait(false) != rt) { CzObserve(rt); return n > 0 ? n : -1; }
                int k; try { k = rt.Result; } catch { return -1; }
                if (k <= 0) return n; n += k;
                if (b[0] != 0x16) break;
                if (n >= 5 && n >= ((b[3] << 8) | b[4]) + 5) break;
            }
            return n;
        }
        static void CzObserve(Task t) { t.ContinueWith(x => { var e = x.Exception; }, TaskContinuationOptions.OnlyOnFaulted); }
    }
}
