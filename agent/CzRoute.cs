// Ретранслятор zapret: решение «zapret или VPN» — временные обходы, подмена адресов, видео Google, реклама, кэш провайдера, разнос по адресам.
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
        static int CzFallbackMs = 3000, CzBypassMin = 5; static long CzBypassPkts, CzBypassAdded, CzNoHost; static DateTime CzStartedAt = DateTime.MinValue, CzLogResetAt = DateTime.UtcNow;
        // клиент → адрес сайта, к которому zapret не ответил: следующие соединения этой пары идут мимо ретранслятора — раздача Windows
        // отправляет их в туннель VPN, как весь остальной трафик клиента (ретранслятор сам выйти в VPN к адресу zapret не может:
        // маршрут zapret у Windows сильнее адреса и интерфейса сокета)
        static readonly ConcurrentDictionary<ulong, DateTime> CzBypass = new ConcurrentDictionary<ulong, DateTime>();
        // пакет соединения, которое уже идёт через ретранслятор (SYN — всегда новое соединение)
        static bool CzIsRelayFlow(uint client, int cport, uint site, bool syn)
        {
            if (syn) return false;
            CzTcpFlow f; lock (CzLock) return CzTcp.TryGetValue(((ulong)client << 16) | (uint)cport, out f) && f.Dst == site;
        }
        static bool CzBypassed(uint client, uint site)
        {
            DateTime until; if (CzBypass.IsEmpty || !CzBypass.TryGetValue(((ulong)client << 32) | site, out until)) return false;
            if (until > DateTime.UtcNow) return true;
            CzBypass.TryRemove(((ulong)client << 32) | site, out until); return false;
        }
        // запасные адреса для имени: удачный недавно у того же «семейства» (youtube.com, googleapis.com …) и адреса из DNS — только из маршрутов zapret
        static readonly ConcurrentDictionary<string, uint> CzGoodIp = new ConcurrentDictionary<string, uint>();
        static readonly ConcurrentDictionary<uint, KeyValuePair<uint, DateTime>> CzRemap = new ConcurrentDictionary<uint, KeyValuePair<uint, DateTime>>();
        static string CzFamily(string host)
        {
            if (Regex.IsMatch(host, @"^r\d+---sn-") || host.Contains("---sn-")) return null;   // видеосервер: нужное видео только на его адресе
            var p = host.Split('.'); if (p.Length < 2) return null;
            string f = p[p.Length - 2] + "." + p[p.Length - 1];
            return f == "googlevideo.com" || f == "ggpht.com" ? null : f;            // видеосерверы и картинки — у каждого адреса своё
        }
        // заглушка провайдера вместо сайта Google: Google с современными браузерами всегда отвечает по TLS 1.3 (сертификат зашифрован);
        // открытый сертификат (сообщение Certificate в первом ответе) — значит, отвечает не Google
        static long CzStubs;
        // видео Google через VPN (wg.clientVideoVpn): кэш провайдера (адреса не Google) остаётся через zapret
        static bool CzQuicReject = true;
        static bool CzVideoVpn = true; static int CzVideoVpnMin = 360; static long CzVideoToVpn;
        static readonly ConcurrentDictionary<uint, byte> CzVideoLogged = new ConcurrentDictionary<uint, byte>();
        static CzRanges CzGoogle = new CzRanges { Lo = new uint[0], Hi = new uint[0] }; static DateTime CzGoogleAt = DateTime.MinValue;
        // имена, которым через VPN лучше всегда (wg.clientVpnHosts), и имена, недавно не ответившие через zapret
        static readonly ConcurrentDictionary<string, DateTime> CzBadHost = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        static string[] CzVpnHosts = new string[0]; static long CzHostToVpn;
        static bool CzVpnHost(string h)
        {
            foreach (var d in CzVpnHosts) if (h.Equals(d, StringComparison.OrdinalIgnoreCase) || h.EndsWith("." + d, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
        static bool CzIsVideoHost(string h) { return h.Contains("---sn-") && (h.EndsWith(".googlevideo.com", StringComparison.OrdinalIgnoreCase) || h.EndsWith(".c.youtube.com", StringComparison.OrdinalIgnoreCase)); }
        static bool CzIsGoogle(uint v)
        {
            var s = CzGoogle; int a = 0, b = s.Lo.Length - 1;
            while (a <= b) { int m = (a + b) >> 1; if (v < s.Lo[m]) b = m - 1; else if (v > s.Hi[m]) a = m + 1; else return true; }
            return false;
        }
        // диапазоны Google (goog.json, кэш zapret) — раз в 6 ч
        static void CzLoadGoogle()
        {
            if ((DateTime.UtcNow - CzGoogleAt).TotalHours < 6 && CzGoogle.Lo.Length > 0) return;
            CzGoogleAt = DateTime.UtcNow;
            var rs = new List<KeyValuePair<uint, uint>>();
            foreach (var p in GoogleRanges()) {
                var x = p.Split('/'); IPAddress a; int bits;
                if (x.Length != 2 || !IPAddress.TryParse(x[0], out a) || !int.TryParse(x[1], out bits) || bits < 8 || bits > 32) continue;
                uint lo = IpH(a.GetAddressBytes(), 0), mask = bits == 32 ? uint.MaxValue : ~(uint.MaxValue >> bits); lo &= mask;
                rs.Add(new KeyValuePair<uint, uint>(lo, lo | ~mask));
            }
            rs.Sort((p, q) => p.Key.CompareTo(q.Key));
            var lo2 = new List<uint>(); var hi2 = new List<uint>();
            foreach (var r in rs) { int k = hi2.Count - 1; if (k >= 0 && r.Key <= hi2[k] + 1 && hi2[k] != uint.MaxValue) { if (r.Value > hi2[k]) hi2[k] = r.Value; } else { lo2.Add(r.Key); hi2.Add(r.Value); } }
            if (lo2.Count > 0) CzGoogle = new CzRanges { Lo = lo2.ToArray(), Hi = hi2.ToArray() };
        }
        static bool CzStubCert(string host, byte[] b, int n)
        {
            if (host == null || !Regex.IsMatch(host, @"(^|\.)(youtube\.com|youtu\.be|google\.com|googleapis\.com|googlevideo\.com|ytimg\.com|ggpht\.com|gstatic\.com|googleusercontent\.com)$")) return false;
            try {
                for (int o = 0; o + 5 <= n; ) {
                    int type = b[o], len = (b[o + 3] << 8) | b[o + 4];
                    if (type == 0x16) for (int p = o + 5; p + 4 <= Math.Min(n, o + 5 + len); ) {
                        int ht = b[p], hl = (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3];
                        if (ht == 11) { var txt = Encoding.ASCII.GetString(b, 0, n); return !(txt.Contains("Google Trust Services") || txt.Contains("GTS CA") || txt.Contains("GlobalSign")); }   // TLS 1.2 у настоящего Google — сертификат GTS
                        p += 4 + hl;
                    }
                    if (type < 0x14 || type > 0x17) return false;
                    o += 5 + len;
                }
            } catch { }
            return false;
        }
        static void CzRemember(string host, uint ip)
        {
            var f = CzFamily(host); if (f == null) return;
            CzGoodIp[f] = ip;
            CzGoodPool.AddOrUpdate(f, new[] { ip }, (k, old) => new[] { ip }.Concat(old.Where(v => v != ip)).Take(6).ToArray());
        }
        // удачные недавно адреса семейства (до 6) — чтобы пачку одновременных соединений разнести по разным адресам
        static readonly ConcurrentDictionary<string, uint[]> CzGoodPool = new ConcurrentDictionary<string, uint[]>();
        static readonly ConcurrentDictionary<uint, int> CzInFlight = new ConcurrentDictionary<uint, int>();
        static int CzRr;
        static uint CzSpread(string host, uint ip, uint dead)
        {
            var fam = CzFamily(host); uint[] pool; if (fam == null || !CzGoodPool.TryGetValue(fam, out pool)) return ip;
            var p = pool.Where(v => v != dead && CzInSet(v)).ToArray(); if (p.Length == 0) return ip;
            int busy; CzInFlight.TryGetValue(ip, out busy);
            if (ip != dead && busy < 2) return ip;                      // адрес свободен — как есть
            return p.OrderBy(v => { int b; CzInFlight.TryGetValue(v, out b); return b; }).ThenBy(v => (v + (uint)Interlocked.Increment(ref CzRr)) % 7).First();
        }
        static async Task<List<uint>> CzAltIps(string host, uint bad)
        {
            var res = new List<uint>(); var fam = CzFamily(host); if (fam == null) return res;
            uint g; if (CzGoodIp.TryGetValue(fam, out g) && g != bad && CzInSet(g)) res.Add(g);
            try {
                var t = Dns.GetHostAddressesAsync(host);
                if (await Task.WhenAny(t, Task.Delay(2000)).ConfigureAwait(false) == t && t.Status == TaskStatus.RanToCompletion) {
                    foreach (var a in t.Result) if (a.AddressFamily == AddressFamily.InterNetwork) { var v = IpH(a.GetAddressBytes(), 0); if (v != bad && CzInSet(v) && !res.Contains(v)) res.Add(v); }
                } else CzObserve(t);
            } catch { }
            return res.Take(2).ToList();
        }
        // соединение с сайтом от имени ПК: маршрут zapret → физический адаптер → winws
        // первый SYN иногда теряется, а Windows повторяет его только через 3 с: нет ответа за 0,5 с — параллельно второе подключение,
        // через 1,5 с — третье; берём то, что ответит первым
        static long CzConnRetryWin, CzSpreadN;
        // altT — другие адреса того же сайта: повторные подключения идут на них (провайдер иногда на несколько секунд глушит SYN к одному адресу)
        static async Task<KeyValuePair<TcpClient, uint>> CzConnect(uint dst, int port, Task<List<uint>> altT = null)
        {
            var socks = new List<TcpClient>(); var pend = new List<Task>(); var ips = new List<uint>(); var sw = System.Diagnostics.Stopwatch.StartNew(); TcpClient ok = null; uint okIp = dst;
            int[] at = { 0, 500, 1500 }; int next = 0;
            try {
                while (sw.ElapsedMilliseconds < 10000) {
                    if (next < at.Length && sw.ElapsedMilliseconds >= at[next]) {
                        uint ip = dst;
                        if (next > 0) {
                            var al = altT != null && altT.Status == TaskStatus.RanToCompletion ? altT.Result.Where(v => v != dst).ToList() : new List<uint>();
                            if (al.Count < next) { next++; continue; }
                            ip = al[next - 1];
                        }
                        var s = NoInherit(new TcpClient(AddressFamily.InterNetwork) { NoDelay = true });
                        Task t; try { t = s.ConnectAsync(IpA(ip), port); } catch (Exception e) { var tcs = new TaskCompletionSource<bool>(); tcs.SetException(e); t = tcs.Task; }
                        socks.Add(s); pend.Add(t); ips.Add(ip); next++;
                    }
                    int done = pend.FindIndex(x => x.Status == TaskStatus.RanToCompletion);
                    if (done >= 0) { ok = socks[done]; okIp = ips[done]; if (done > 0) Interlocked.Increment(ref CzConnRetryWin); break; }
                    var live = pend.Where(x => !x.IsCompleted).ToList();
                    if (live.Count == 0 && next >= at.Length) break;
                    long wait = (next < at.Length ? at[next] : 10000) - sw.ElapsedMilliseconds; if (wait < 1) wait = 1;
                    live.Add(Task.Delay((int)wait));
                    await Task.WhenAny(live).ConfigureAwait(false);
                }
            } catch { }
            for (int i = 0; i < socks.Count; i++) if (socks[i] != ok) { CzObserve(pend[i]); try { socks[i].Close(); } catch { } }
            return new KeyValuePair<TcpClient, uint>(ok, okIp);
        }
    }
}
