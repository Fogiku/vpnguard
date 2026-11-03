// VpnGuard — агент на C#: zapret для клиентов WG-Server (ws4w.clientZapret).
// winws обрабатывает только трафик самого ПК — транзитный (клиентов wg_server) он не видит. Поэтому:
//   1) свой DNS на адресе ПК в сети wg_server: имена из списков zapret (YouTube, Discord, свои) → адрес ПК, остальное —
//      пересылается обычным DNS-серверам (через VPN, как и весь прочий трафик клиентов);
//   2) прокси на том же адресе (TCP 443/80): читает имя сайта (SNI / Host), сам соединяется с сайтом и пересылает байты
//      как есть, без расшифровки. Соединение — с самого ПК, поэтому его обрабатывает winws и оно идёт мимо VPN по маршрутам zapret.
// UDP (QUIC) не проксируется: YouTube сам переходит на TCP. Голос Discord (UDP на адреса без DNS) остаётся в VPN.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace VpnGuard
{
    public static partial class Agent
    {
        static Socket CzUdp; static TcpListener CzTcpDns, CzTls, CzHttp;
        static string CzIp = "", CzError = "", CzMode = "";
        static long CzQueries, CzSpoofed, CzConns, CzBytes; static int CzActive;
        static HashSet<string> CzDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase), CzExclude = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        static string CzListSig = ""; static DateTime CzFwAt = DateTime.MinValue; static string CzFwSig = "";
        static readonly Dictionary<string, Tuple<IPAddress, DateTime>> CzResolveCache = new Dictionary<string, Tuple<IPAddress, DateTime>>(StringComparer.OrdinalIgnoreCase);
        static readonly string[] CzBuiltin = { "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com", "youtubei.googleapis.com", "yt3.ggpht.com",
            "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com", "discord.dev", "discord.new", "discord.gift", "discordstatus.com", "dis.gd" };

        static bool CzWanted() { return CfgBool("ws4w.clientZapret", false); }
        // подменять имена — только пока zapret действительно работает (иначе всё — как обычно, через VPN)
        static bool CzSpoofOn() { return ZOn() && ZWinws() != null && ZTestRunner() == null; }
        static string[] CzUpstreams() { return CfgList("ws4w.clientDnsUpstream", new[] { "8.8.8.8", "8.8.4.4" }); }

        static void ClientZapretWatch()
        {
            if (!CzWanted()) { if (CzUdp != null) { CzStop(); Log("zapret для клиентов WG-Server: выключен", "INFO"); } return; }
            string wgIp = Ipv4(WgIf());
            if (wgIp == null) { if (CzUdp != null) CzStop(); CzError = "адаптер " + WgIf() + " без адреса"; return; }
            CzLoadDomains();
            if (CzUdp == null || (CzMode == "main" && CzIp != wgIp)) {
                CzStop();
                try { CzStart(wgIp); CzError = ""; }
                catch (Exception e) { CzError = e.Message; Log("zapret для клиентов WG-Server: " + e.Message, "ERROR"); CzStop(); return; }
            }
            CzFirewall();
        }

        // адрес: основной адрес ПК в сети wg_server; если порт 53 там занят (DNS-прокси раздачи Windows) — второй адрес (.53)
        static void CzStart(string wgIp)
        {
            string ip = wgIp; string mode = "main";
            Socket udp = CzBindUdp(ip);
            if (udp == null) {
                var alt = CfgStr("ws4w.clientDnsIp", "");
                if (alt.Length == 0) alt = Regex.Replace(wgIp, @"\.\d+$", ".53");
                if (Ipv4All(WgIf()).IndexOf(alt) < 0) {
                    var r = Exe("netsh.exe", "interface ipv4 add address \"" + WgIf() + "\" " + alt + " 255.255.255.0 store=active", 20);
                    Log("zapret для клиентов WG-Server: порт 53 на " + wgIp + " занят (DNS раздачи Windows) — добавляю адрес " + alt + " на " + WgIf() + (r.Code != 0 ? " (netsh: " + (r.Out + " " + r.Err).Trim() + ")" : ""), "WARN");
                    Thread.Sleep(2500);
                }
                ip = alt; mode = "alt"; udp = CzBindUdp(ip);
                if (udp == null) throw new Exception("не удалось занять UDP 53 ни на " + wgIp + ", ни на " + alt);
            }
            var a = IPAddress.Parse(ip);
            var tdns = new TcpListener(a, 53); var tls = new TcpListener(a, 443); var http = new TcpListener(a, 80);
            foreach (var l in new[] { tdns, tls, http }) { l.ExclusiveAddressUse = true; }
            try { tls.Start(256); http.Start(64); } catch (Exception e) { try { udp.Close(); } catch { } try { tls.Stop(); } catch { } throw new Exception("порт 443/80 на " + ip + " занят: " + e.Message); }
            try { tdns.Start(32); } catch { tdns = null; }
            CzUdp = udp; CzTcpDns = tdns; CzTls = tls; CzHttp = http; CzIp = ip; CzMode = mode;
            new Thread(CzUdpLoop) { IsBackground = true, Name = "cz-dns" }.Start(udp);
            if (tdns != null) new Thread(CzAcceptLoop) { IsBackground = true, Name = "cz-dns-tcp" }.Start(Tuple.Create(tdns, "dns"));
            new Thread(CzAcceptLoop) { IsBackground = true, Name = "cz-tls" }.Start(Tuple.Create(tls, "tls"));
            new Thread(CzAcceptLoop) { IsBackground = true, Name = "cz-http" }.Start(Tuple.Create(http, "http"));
            Log("zapret для клиентов WG-Server: DNS и прокси на " + ip + " (у клиентов в конфиге должен быть DNS = " + ip + "; доменов zapret: " + CzDomains.Count + ")", "WARN");
        }
        static Socket CzBindUdp(string ip)
        {
            // сначала монопольно; не вышло (кто-то слушает 0.0.0.0:53) — обычная привязка к конкретному адресу: она главнее «всех адресов»
            foreach (bool excl in new[] { true, false }) {
                var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                try { s.ExclusiveAddressUse = excl; s.Bind(new IPEndPoint(IPAddress.Parse(ip), 53)); return s; } catch { s.Close(); }
            }
            return null;
        }
        static List<string> Ipv4All(string name)
        {
            var l = new List<string>(); var n = Nic(name); if (n == null) return l;
            try { foreach (var u in n.GetIPProperties().UnicastAddresses) if (u.Address.AddressFamily == AddressFamily.InterNetwork) l.Add(u.Address.ToString()); } catch { }
            return l;
        }
        static void CzStop()
        {
            try { if (CzUdp != null) CzUdp.Close(); } catch { }
            foreach (var l in new[] { CzTcpDns, CzTls, CzHttp }) { try { if (l != null) l.Stop(); } catch { } }
            CzUdp = null; CzTcpDns = null; CzTls = null; CzHttp = null;
            if (CzMode == "alt" && CzIp.Length > 0) Exe("netsh.exe", "interface ipv4 delete address \"" + WgIf() + "\" " + CzIp, 20);
            CzIp = ""; CzMode = "";
        }
        static void CzFirewall()
        {
            string wgIp = Ipv4(WgIf()) ?? ""; string sub = Regex.Replace(wgIp, @"\.\d+$", ".0/24");
            string sig = CzIp + "|" + sub;
            if (sig == CzFwSig && (DateTime.Now - CzFwAt).TotalMinutes < 30) return;
            CzFwAt = DateTime.Now;
            const string name = "VpnGuard WG-Server zapret";
            bool have = Exe("netsh.exe", "advfirewall firewall show rule name=\"" + name + "\"", 15).Code == 0;
            if (have && sig == CzFwSig) return;
            if (have) Exe("netsh.exe", "advfirewall firewall delete rule name=\"" + name + "\"", 15);
            Exe("netsh.exe", "advfirewall firewall add rule name=\"" + name + "\" dir=in action=allow protocol=TCP localip=" + CzIp + " localport=53,80,443 remoteip=" + sub, 15);
            Exe("netsh.exe", "advfirewall firewall add rule name=\"" + name + "\" dir=in action=allow protocol=UDP localip=" + CzIp + " localport=53 remoteip=" + sub, 15);
            CzFwSig = sig;
        }

        // домены: списки zapret (те же, по которым winws решает, что обрабатывать) + YouTube/Discord + маршрутные домены
        static void CzLoadDomains()
        {
            var lists = Path.Combine(ZDir(), "lists");
            var inc = new[] { "list-general.txt", "list-google.txt", "list-general-user.txt" }.Select(f => Path.Combine(lists, f)).ToList();
            var exc = new[] { "list-exclude.txt", "list-exclude-user.txt" }.Select(f => Path.Combine(lists, f)).ToList();
            var sig = string.Join("|", inc.Concat(exc).Select(f => File.Exists(f) ? File.GetLastWriteTimeUtc(f).Ticks.ToString() : "-")) + "|" + string.Join(",", CfgList("zapret.routeDomains", ZDefDomains));
            if (sig == CzListSig) return;
            var d = new HashSet<string>(CzBuiltin, StringComparer.OrdinalIgnoreCase); var x = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in CfgList("zapret.routeDomains", ZDefDomains)) if (r.Trim().Length > 0) d.Add(r.Trim().TrimStart('^').TrimEnd('.'));
            Action<string, HashSet<string>> read = (f, set) => {
                if (!File.Exists(f)) return;
                try { foreach (var raw in File.ReadAllLines(f)) { var l = raw.Trim().TrimStart('^').TrimEnd('.'); if (l.Length > 0 && !l.StartsWith("#") && l != "domain.example.abc" && l.IndexOf('/') < 0 && Regex.IsMatch(l, @"[a-zA-Z]")) set.Add(l); } } catch { }
            };
            foreach (var f in inc) read(f, d); foreach (var f in exc) read(f, x);
            CzDomains = d; CzExclude = x; CzListSig = sig;
        }
        static bool CzMatch(string host)
        {
            if (string.IsNullOrEmpty(host)) return false;
            host = host.TrimEnd('.');
            var doms = CzDomains; var ex = CzExclude;
            for (string h = host; h.Length > 0; ) {
                if (ex.Contains(h)) return false;
                if (doms.Contains(h)) return true;
                int i = h.IndexOf('.'); if (i < 0) break; h = h.Substring(i + 1);
            }
            return false;
        }

        // ---------------------------------------------------------------- DNS
        static void CzUdpLoop(object o)
        {
            var s = (Socket)o; var buf = new byte[4096];
            while (true) {
                EndPoint from = new IPEndPoint(IPAddress.Any, 0); int n;
                try { n = s.ReceiveFrom(buf, ref from); } catch (ObjectDisposedException) { return; } catch (SocketException e) { if (e.SocketErrorCode == SocketError.ConnectionReset) continue; if (CzUdp != s) return; continue; }
                var q = new byte[n]; Buffer.BlockCopy(buf, 0, q, 0, n); var ep = from;
                ThreadPool.QueueUserWorkItem(_ => { try { var r = CzAnswer(q); if (r != null) s.SendTo(r, ep); } catch { } });
            }
        }
        // ответ на запрос DNS: своё имя → адрес прокси (A), без IPv6 и HTTPS-записей; остальное — переслать дальше
        static byte[] CzAnswer(byte[] q)
        {
            Interlocked.Increment(ref CzQueries);
            if (q.Length < 17) return null;
            int qd = (q[4] << 8) | q[5]; if (qd != 1 || (q[2] & 0x80) != 0) return CzForward(q);
            int p = 12; var sb = new StringBuilder();
            while (p < q.Length && q[p] != 0) { int len = q[p]; if ((len & 0xC0) != 0 || p + 1 + len > q.Length) return CzForward(q); if (sb.Length > 0) sb.Append('.'); sb.Append(Encoding.ASCII.GetString(q, p + 1, len)); p += 1 + len; }
            if (p + 5 > q.Length) return CzForward(q);
            int qEnd = p + 5; int type = (q[p + 1] << 8) | q[p + 2];
            string name = sb.ToString();
            if (!CzSpoofOn() || !CzMatch(name) || CzIp.Length == 0) return CzForward(q);
            if (type != 1 && type != 28 && type != 65 && type != 64) return CzForward(q);
            Interlocked.Increment(ref CzSpoofed);
            var r = new List<byte>();
            r.Add(q[0]); r.Add(q[1]); r.Add((byte)(0x80 | (q[2] & 0x01))); r.Add(0x80);     // ответ, RD как в запросе, RA, NOERROR
            r.AddRange(new byte[] { 0, 1, 0, (byte)(type == 1 ? 1 : 0), 0, 0, 0, 0 });
            for (int i = 12; i < qEnd; i++) r.Add(q[i]);
            if (type == 1) { r.AddRange(new byte[] { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4 }); r.AddRange(IPAddress.Parse(CzIp).GetAddressBytes()); }
            return r.ToArray();
        }
        static byte[] CzForward(byte[] q)
        {
            foreach (var up in CzUpstreams()) {
                IPAddress a; if (!IPAddress.TryParse(up, out a)) continue;
                using (var c = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)) {
                    try {
                        c.ReceiveTimeout = 3000; c.Connect(new IPEndPoint(a, 53)); c.Send(q);
                        var b = new byte[4096]; int n = c.Receive(b);
                        if (n >= 12 && b[0] == q[0] && b[1] == q[1]) { var r = new byte[n]; Buffer.BlockCopy(b, 0, r, 0, n); return r; }
                    } catch { }
                }
            }
            if (q.Length < 12) return null;
            var f = (byte[])q.Clone(); f[2] = (byte)(0x80 | (q[2] & 0x01)); f[3] = 0x82; return f;       // SERVFAIL
        }

        // ---------------------------------------------------------------- прокси
        static void CzAcceptLoop(object o)
        {
            var t = (Tuple<TcpListener, string>)o;
            while (true) {
                TcpClient c;
                try { c = t.Item1.AcceptTcpClient(); } catch { return; }
                var kind = t.Item2;
                new Thread(() => { try { if (kind == "dns") CzDnsTcp(c); else CzProxy(c, kind == "tls"); } catch { } finally { try { c.Close(); } catch { } } }) { IsBackground = true }.Start();
            }
        }
        static bool ReadFull(Stream s, byte[] b, int off, int n) { while (n > 0) { int k = s.Read(b, off, n); if (k <= 0) return false; off += k; n -= k; } return true; }
        static void CzDnsTcp(TcpClient c)
        {
            c.ReceiveTimeout = 10000; var s = c.GetStream(); var h = new byte[2];
            while (ReadFull(s, h, 0, 2)) {
                int len = (h[0] << 8) | h[1]; var q = new byte[len]; if (!ReadFull(s, q, 0, len)) return;
                var r = CzAnswer(q); if (r == null) return;
                s.Write(new[] { (byte)(r.Length >> 8), (byte)r.Length }, 0, 2); s.Write(r, 0, r.Length);
            }
        }
        static void CzProxy(TcpClient c, bool tls)
        {
            c.ReceiveTimeout = 10000; c.NoDelay = true;
            var cs = c.GetStream(); var buf = new byte[17000]; int have = 0; string host = null;
            // первые байты: ClientHello (имя сайта — SNI) или заголовки HTTP (Host)
            while (have < buf.Length) {
                int k = cs.Read(buf, have, buf.Length - have); if (k <= 0) return; have += k;
                if (tls) {
                    if (have >= 5) { if (buf[0] != 0x16) return; int rl = (buf[3] << 8) | buf[4]; if (have >= 5 + rl || have >= buf.Length) { host = SniOf(buf, have); break; } }
                } else {
                    var txt = Encoding.ASCII.GetString(buf, 0, have); int e = txt.IndexOf("\r\n\r\n");
                    if (e >= 0 || have > 8192) { var m = Regex.Match(txt, @"(?im)^Host:\s*([^\s:]+)"); if (m.Success) host = m.Groups[1].Value; break; }
                }
            }
            if (host == null || !CzMatch(host)) return;                 // только домены zapret — не открытый прокси
            var ip = CzResolve(host); if (ip == null) return;
            var srv = new TcpClient(AddressFamily.InterNetwork) { NoDelay = true };
            try {
                var ar = srv.BeginConnect(ip, tls ? 443 : 80, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(10000)) return; srv.EndConnect(ar);
                var ss = srv.GetStream(); ss.Write(buf, 0, have);
                c.ReceiveTimeout = 0; Interlocked.Increment(ref CzConns); Interlocked.Increment(ref CzActive);
                var up = new Thread(() => { CzPump(cs, ss); try { srv.Client.Shutdown(SocketShutdown.Send); } catch { } }) { IsBackground = true }; up.Start();
                CzPump(ss, cs); try { c.Client.Shutdown(SocketShutdown.Send); } catch { }
                up.Join(30000);
            } catch { }
            finally { Interlocked.Decrement(ref CzActive); try { srv.Close(); } catch { } }
        }
        static void CzPump(Stream a, Stream b)
        {
            var bb = new byte[65536];
            try { int n; while ((n = a.Read(bb, 0, bb.Length)) > 0) { b.Write(bb, 0, n); Interlocked.Add(ref CzBytes, n); } } catch { }
        }
        // адрес сайта — как для самого ПК (системный DNS: видеосерверы провайдера и т. п.); не наш и не частный
        static IPAddress CzResolve(string host)
        {
            lock (CzResolveCache) { Tuple<IPAddress, DateTime> t; if (CzResolveCache.TryGetValue(host, out t) && t.Item2 > DateTime.Now) return t.Item1; }
            IPAddress ip = null;
            try { ip = Dns.GetHostAddresses(host).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !IsPrivate(a)); } catch { }
            if (ip != null) lock (CzResolveCache) { if (CzResolveCache.Count > 2000) CzResolveCache.Clear(); CzResolveCache[host] = Tuple.Create(ip, DateTime.Now.AddSeconds(60)); }
            return ip;
        }
        static bool IsPrivate(IPAddress a)
        {
            var b = a.GetAddressBytes();
            return b[0] == 10 || b[0] == 127 || b[0] == 0 || (b[0] == 172 && b[1] >= 16 && b[1] < 32) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] < 128);
        }
        // имя сайта из TLS ClientHello (расширение server_name)
        static string SniOf(byte[] b, int n)
        {
            try {
                int p = 5; if (p + 4 > n || b[p] != 1) return null; p += 4;      // заголовок рукопожатия
                p += 2 + 32; if (p >= n) return null;                             // версия, random
                p += 1 + b[p]; if (p + 2 > n) return null;                        // session id
                p += 2 + ((b[p] << 8) | b[p + 1]); if (p >= n) return null;       // шифры
                p += 1 + b[p]; if (p + 2 > n) return null;                        // сжатие
                int end = Math.Min(n, p + 2 + ((b[p] << 8) | b[p + 1])); p += 2;
                while (p + 4 <= end) {
                    int et = (b[p] << 8) | b[p + 1], el = (b[p + 2] << 8) | b[p + 3]; p += 4;
                    if (et == 0 && p + 5 <= end) { int nl = (b[p + 3] << 8) | b[p + 4]; if (b[p + 2] == 0 && p + 5 + nl <= end) return Encoding.ASCII.GetString(b, p + 5, nl); return null; }
                    p += el;
                }
            } catch { }
            return null;
        }

        // ---------------------------------------------------------------- состояние
        static Dictionary<string, object> CzSnapshot()
        {
            bool on = CzWanted();
            return new Dictionary<string, object> { { "enabled", on }, { "running", CzUdp != null }, { "spoof", on && CzSpoofOn() }, { "dns", CzIp }, { "alt", CzMode == "alt" },
                { "error", CzError }, { "queries", Interlocked.Read(ref CzQueries) }, { "spoofed", Interlocked.Read(ref CzSpoofed) }, { "conns", Interlocked.Read(ref CzConns) },
                { "active", CzActive }, { "mb", Math.Round(Interlocked.Read(ref CzBytes) / 1048576.0, 1) }, { "domains", CzDomains.Count } };
        }
        static string CzSummary()
        {
            if (!CzWanted()) return "выключен (в настройках WG-Server)";
            if (CzUdp == null) return "не работает" + (CzError.Length > 0 ? ": " + CzError : "");
            return (CzSpoofOn() ? "работает" : "ждёт zapret (пока всё через VPN)") + " · DNS для клиентов " + CzIp + " · соединений " + Interlocked.Read(ref CzConns) + " (сейчас " + CzActive + "), " +
                Math.Round(Interlocked.Read(ref CzBytes) / 1048576.0, 1) + " МБ · запросов DNS " + Interlocked.Read(ref CzQueries) + ", подменено " + Interlocked.Read(ref CzSpoofed);
        }
    }
}
