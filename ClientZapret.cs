// VpnGuard — агент на C#: zapret и для клиентов WG-Server (ws4w.clientZapret), разделение по IP, прозрачно.
// winws обрабатывает только трафик, который начинается на самом ПК. Трафик клиентов wg_server к адресам из маршрутов zapret
// (YouTube, Discord, видеосерверы провайдера, свои списки) Windows и так отправляет через физический адаптер — мимо VPN.
// Агент перехватывает эти транзитные пакеты (WinDivert, тот же драйвер, что у zapret) и делает их «своими»:
//   TCP — заворачивает на свой ретранслятор на ПК (адрес ПК в сети wg_server : 34010), тот соединяется с тем же адресом
//         и портом уже от имени ПК → это соединение обрабатывает winws; ответы клиенту уходят с исходного адреса сайта;
//   UDP (QUIC и др.) — отправляет от ПК сам и возвращает ответы клиенту пакетами с адреса сайта.
// Всё остальное у клиентов — как раньше, через VPN. Ничего настраивать на устройствах не нужно.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace VpnGuard
{
    public static partial class Agent
    {
        // ---------------------------------------------------------------- WinDivert 2.2
        [StructLayout(LayoutKind.Explicit, Size = 80)]
        struct WdAddr { [FieldOffset(0)] public long Timestamp; [FieldOffset(8)] public uint Flags; [FieldOffset(12)] public uint Reserved2; [FieldOffset(16)] public uint IfIdx; [FieldOffset(20)] public uint SubIfIdx; }
        const int WdLayerNetwork = 0, WdLayerForward = 1;
        const uint WdOutbound = 1u << 17;
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr LoadLibrary(string path);
        [DllImport("WinDivert.dll", CharSet = CharSet.Ansi, SetLastError = true)] static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);
        [DllImport("WinDivert.dll", SetLastError = true)] static extern bool WinDivertRecv(IntPtr h, byte[] pkt, uint len, out uint recvLen, ref WdAddr addr);
        [DllImport("WinDivert.dll", SetLastError = true)] static extern bool WinDivertSend(IntPtr h, byte[] pkt, uint len, out uint sendLen, ref WdAddr addr);
        [DllImport("WinDivert.dll")] static extern bool WinDivertHelperCalcChecksums(byte[] pkt, uint len, ref WdAddr addr, ulong flags);
        [DllImport("WinDivert.dll")] static extern bool WinDivertClose(IntPtr h);
        static readonly IntPtr WdInvalid = new IntPtr(-1);
        static bool WdLoaded;

        // ---------------------------------------------------------------- состояние
        class CzTcpFlow { public uint Dst; public int DPort; public DateTime Last; public int SynTtl; public uint MaxTs; public bool HasTs; }
        class CzUdpFlow { public uint Client, Dst; public int CPort, DPort; public Socket Sock; public DateTime Last; }
        static readonly object CzLock = new object();
        static readonly Dictionary<ulong, CzTcpFlow> CzTcp = new Dictionary<ulong, CzTcpFlow>();
        static readonly Dictionary<string, CzUdpFlow> CzUdp = new Dictionary<string, CzUdpFlow>();
        static IntPtr CzFwd = WdInvalid, CzNet = WdInvalid;
        static TcpListener CzRelay;
        const int CzRelayPort = 34010;
        static uint CzWgIp, CzEthIp; static int CzWgIdx, CzEthIdx; static string CzSig = "", CzError = "";
        static long CzPkts, CzPass, CzTcpConns, CzUdpPkts, CzBytes, CzErrors, CzTcpUp, CzTcpDown, CzUdpDown, CzUdpSendFail, CzQuicDrop, CzNetRw, CzNetMiss, CzNetBig, CzNetSendFail, CzRelayNoFlow, CzConnFail, CzFwdBig, CzFwdMax, CzNetMax, CzMssClamped, CzDropSum, CzDropMd5, CzDropTtl, CzDropTs, CzDropNoAck, CzSumChecked; static volatile bool CzSumOff; static readonly System.Diagnostics.Stopwatch CzSw = System.Diagnostics.Stopwatch.StartNew(); static int CzActive, CzConnLogged, CzSynLogged, CzTraceLeft = 0; static readonly HashSet<ulong> CzTraced = new HashSet<ulong>(); static DateTime CzTraceAt = DateTime.MinValue;
        static HashSet<uint> CzHosts = new HashSet<uint>(); static List<uint[]> CzNets = new List<uint[]>(); static string CzSetKey = "";
        static DateTime CzFwAt = DateTime.MinValue, CzCleanAt = DateTime.MinValue; static string CzFwSig = "";

        static bool CzWanted() { return CfgBool("ws4w.clientZapret", false); }
        static uint IpH(byte[] b, int o) { return ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3]; }
        static void PutIp(byte[] b, int o, uint v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }
        static uint IpH(string s) { var b = IPAddress.Parse(s).GetAddressBytes(); return IpH(b, 0); }
        static string IpS(uint v) { return (v >> 24) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255); }
        static int IfIndexOf(string name) { var n = Nic(name); try { return n == null ? 0 : n.GetIPProperties().GetIPv4Properties().Index; } catch { return 0; } }

        static void ClientZapretWatch()
        {
            string why = null;
            if (!CzWanted()) why = "off";
            else if (ZDirect()) why = "в режиме «без VPN» клиенты и так идут напрямую — нужен режим с VPN";
            else if (ZRoutes().Count == 0) why = "zapret не включён (нет маршрутов мимо VPN)";
            string wgIp = Ipv4(WgIf()); var phys = why == null ? ZPhys() : null;
            if (why == null && wgIp == null) why = "адаптер " + WgIf() + " без адреса";
            if (why == null && phys == null) why = "нет физического выхода в интернет";
            string dll = Path.Combine(ZDir(), "bin", "WinDivert.dll");
            if (why == null && !File.Exists(dll)) why = "нет " + dll + " (zapret не установлен?)";
            if (why != null) {
                if (CzFwd != WdInvalid) { CzStop(); Log("zapret для клиентов WG-Server: остановлен" + (why == "off" ? "" : " — " + why), "INFO"); }
                CzError = why == "off" ? "" : why; return;
            }
            CzUpdateSet();
            string sig = wgIp + "|" + IfIndexOf(WgIf()) + "|" + phys.IfIndex + "|" + phys.Ip;
            if (CzFwd == WdInvalid || sig != CzSig) {
                CzStop();
                try { CzStart(dll, wgIp, phys); CzSig = sig; CzError = ""; }
                catch (Exception e) { CzError = e.Message; Log("zapret для клиентов WG-Server: " + e.Message, "ERROR"); CzStop(); return; }
            }
            CzFirewall(wgIp);
            if ((DateTime.Now - CzCleanAt).TotalSeconds >= 30) { CzCleanAt = DateTime.Now; CzCleanup(); }
        }

        static void CzStart(string dll, string wgIp, ZPath phys)
        {
            if (!WdLoaded) { if (LoadLibrary(dll) == IntPtr.Zero) throw new Exception("не загрузился " + dll + " (код " + Marshal.GetLastWin32Error() + ")"); WdLoaded = true; }
            CzWgIp = IpH(wgIp); CzEthIp = IpH(phys.Ip); CzWgIdx = IfIndexOf(WgIf()); CzEthIdx = phys.IfIndex;
            string sub = Regex.Replace(wgIp, @"\.\d+$", "");
            // транзит от клиентов wg_server (раздача Windows шлёт его в туннель VPN); адреса zapret отбираются в коде, остальное — как было
            string ff = "ip and (tcp or udp) and ip.SrcAddr >= " + sub + ".0 and ip.SrcAddr <= " + sub + ".255 and ip.SrcAddr != " + wgIp + " and (ip.DstAddr < " + sub + ".0 or ip.DstAddr > " + sub + ".255)";
            // ответы ретранслятора клиентам: исходящие с адреса ПК в сети wg_server и порта ретранслятора
            string nf = "outbound and ip and tcp and ip.SrcAddr == " + wgIp + " and tcp.SrcPort == " + CzRelayPort;
            var relay = new TcpListener(IPAddress.Parse(wgIp), CzRelayPort) { ExclusiveAddressUse = true };
            try { relay.Start(256); } catch (Exception e) { throw new Exception("порт " + CzRelayPort + " на " + wgIp + " занят: " + e.Message); }
            var hf = WinDivertOpen(ff, WdLayerForward, 0, 0);
            if (hf == WdInvalid) { relay.Stop(); throw new Exception("WinDivert (транзит) не открылся, код " + Marshal.GetLastWin32Error()); }
            var hn = WinDivertOpen(nf, WdLayerNetwork, 0, 0);
            if (hn == WdInvalid) { WinDivertClose(hf); relay.Stop(); throw new Exception("WinDivert (ответы) не открылся, код " + Marshal.GetLastWin32Error()); }
            CzFwd = hf; CzNet = hn; CzRelay = relay;
            // NAT раздачи Windows успевает переслать копию пакетов клиента к настоящему серверу (мимо перехвата) — его ответы (SYN-ACK, RST)
            // приходят клиенту вперемешку с ответами ретранслятора и рвут соединение. Ответы адресов zapret клиенту — только через ретранслятор.
            string bf = "ip and (tcp or udp) and ip.DstAddr >= " + sub + ".0 and ip.DstAddr <= " + sub + ".255 and ip.DstAddr != " + wgIp;
            var hb = WinDivertOpen(bf, WdLayerForward, 0, 0);
            if (hb == WdInvalid) Log("zapret для клиентов: фильтр ответов не открылся, код " + Marshal.GetLastWin32Error() + " — соединения могут рваться", "ERROR");
            else { CzBlk = hb; new Thread(() => CzBlkLoop(hb)) { IsBackground = true, Name = "cz-blk" }.Start(); }
            new Thread(() => CzFwdLoop(hf)) { IsBackground = true, Name = "cz-fwd" }.Start();
            new Thread(() => CzNetLoop(hn)) { IsBackground = true, Name = "cz-net" }.Start();
            new Thread(() => CzAcceptLoop(relay)) { IsBackground = true, Name = "cz-relay" }.Start();
            Log("zapret для клиентов WG-Server: включён — трафик клиентов к адресам zapret (" + ZRoutes().Count + " маршрутов) идёт через zapret этого ПК, остальное — через VPN (" + phys.Alias + ", ретранслятор " + wgIp + ":" + CzRelayPort + ")", "WARN");
        }
        static readonly List<IntPtr> CzProbes = new List<IntPtr>();
        static readonly Dictionary<string, long> CzProbeStat = new Dictionary<string, long>();
        static IntPtr CzBlk = WdInvalid; static long CzLeakDrop;
        static void CzBlkLoop(IntPtr h)
        {
            var p = new byte[65535]; var a = new WdAddr(); uint n;
            while (true) {
                if (!WinDivertRecv(h, p, (uint)p.Length, out n, ref a)) { if (CzBlk != h) return; Thread.Sleep(5); continue; }
                bool drop = false;
                try { if (n >= 20 && (p[0] >> 4) == 4 && CzInSet(IpH(p, 12))) drop = true; } catch { }
                if (drop) { Interlocked.Increment(ref CzLeakDrop); continue; }
                uint sl; WinDivertSend(h, p, n, out sl, ref a);
            }
        }
        // все TCP к клиентам не от ретранслятора: кто шлёт клиенту RST / SYN-ACK мимо нас
        static int CzRstLogged;
        static void CzRstProbe(string filter, int layer, string name)
        {
            var h = WinDivertOpen(filter, layer, -100, 1 /* SNIFF */);
            if (h == WdInvalid) { Log("zapret для клиентов: наблюдение «" + name + "» не открылось, код " + Marshal.GetLastWin32Error(), "WARN"); return; }
            lock (CzProbes) CzProbes.Add(h);
            new Thread(() => {
                var p = new byte[65535]; var a = new WdAddr(); uint n;
                while (WinDivertRecv(h, p, (uint)p.Length, out n, ref a)) {
                    try {
                        int ihl = (p[0] & 15) * 4, f = p[ihl + 13];
                        int sport = (p[ihl] << 8) | p[ihl + 1], dport = (p[ihl + 2] << 8) | p[ihl + 3];
                        if (sport == CzRelayPort) continue;
                        uint src = IpH(p, 12); bool inSet = CzInSet(src);
                        if (!inSet) continue;                      // ответы от адресов zapret, пришедшие не через ретранслятор
                        string fl = ((f & 2) != 0 ? "S" : "") + ((f & 16) != 0 ? "A" : "") + ((f & 8) != 0 ? "P" : "") + ((f & 1) != 0 ? "F" : "") + ((f & 4) != 0 ? "R" : "");
                        if (Interlocked.Increment(ref CzRstLogged) <= 60)
                            Log("наблюдение " + (CzSw.ElapsedMilliseconds % 100000).ToString("00000") + "мс [" + name + "] " + IpS(src) + ":" + sport + " → " + IpS(IpH(p, 16)) + ":" + dport + " " + fl + " ifIdx=" + a.IfIdx + (((a.Flags >> 17) & 1) == 1 ? " исх" : " вх") + " len=" + n + " ttl=" + p[8], "INFO");
                    } catch { }
                }
            }) { IsBackground = true, Name = "cz-rst-" + name }.Start();
        }
        static void CzProbe(string filter, int layer, string name)
        {
            var h = WinDivertOpen(filter, layer, -100, 1 /* SNIFF */);
            if (h == WdInvalid) { lock (CzProbeStat) CzProbeStat[name + ".openError"] = Marshal.GetLastWin32Error(); return; }
            lock (CzProbes) CzProbes.Add(h);
            new Thread(() => {
                var p = new byte[65535]; var a = new WdAddr(); uint n;
                while (WinDivertRecv(h, p, (uint)p.Length, out n, ref a)) {
                    try {
                        uint dst = IpH(p, 16); bool inSet = CzInSet(dst);
                        string k1 = name + ".if" + a.IfIdx + (((a.Flags >> 17) & 1) == 1 ? "out" : "in"), k2 = name + (inSet ? ".zapret" : ".other");
                        lock (CzProbeStat) { long v; CzProbeStat.TryGetValue(k1, out v); CzProbeStat[k1] = v + 1; CzProbeStat.TryGetValue(k2, out v); CzProbeStat[k2] = v + 1; }
                    } catch { }
                }
            }) { IsBackground = true, Name = "cz-probe-" + name }.Start();
        }
        static void CzStop()
        {
            lock (CzProbes) { foreach (var ph in CzProbes) { try { WinDivertClose(ph); } catch { } } CzProbes.Clear(); }
            var bk = CzBlk; CzBlk = WdInvalid; try { if (bk != WdInvalid) WinDivertClose(bk); } catch { }
            var f = CzFwd; var n = CzNet; CzFwd = WdInvalid; CzNet = WdInvalid;
            try { if (f != WdInvalid) WinDivertClose(f); } catch { }
            try { if (n != WdInvalid) WinDivertClose(n); } catch { }
            try { if (CzRelay != null) CzRelay.Stop(); } catch { }
            CzRelay = null; CzSig = "";
            lock (CzLock) { foreach (var u in CzUdp.Values) { try { u.Sock.Close(); } catch { } } CzUdp.Clear(); CzTcp.Clear(); }
        }
        static void CzFirewall(string wgIp)
        {
            string sub = Regex.Replace(wgIp, @"\.\d+$", ".0/24"), sig = wgIp + "|" + sub;
            if (sig == CzFwSig && (DateTime.Now - CzFwAt).TotalMinutes < 30) return;
            CzFwAt = DateTime.Now;
            const string name = "VpnGuard WG-Server zapret";
            bool have = Exe("netsh.exe", "advfirewall firewall show rule name=\"" + name + "\"", 15).Code == 0;
            if (have && sig == CzFwSig) return;
            if (have) Exe("netsh.exe", "advfirewall firewall delete rule name=\"" + name + "\"", 15);
            Exe("netsh.exe", "advfirewall firewall add rule name=\"" + name + "\" dir=in action=allow protocol=TCP localip=" + wgIp + " localport=" + CzRelayPort + " remoteip=" + sub, 15);
            CzFwSig = sig;
        }
        // адреса zapret — те же, что в маршрутах мимо VPN
        static void CzUpdateSet()
        {
            var routes = ZRoutes(); var key = routes.Count + "|" + ZS("lastRouteRefresh");
            if (key == CzSetKey) return;
            var hosts = new HashSet<uint>(); var nets = new List<uint[]>();
            foreach (var r in routes) {
                var pp = JS(r, "p").Split('/'); IPAddress ip; int len;
                if (pp.Length != 2 || !IPAddress.TryParse(pp[0], out ip) || !int.TryParse(pp[1], out len)) continue;
                uint v = IpH(ip.GetAddressBytes(), 0);
                if (len >= 32) hosts.Add(v); else { uint m = len == 0 ? 0 : 0xFFFFFFFFu << (32 - len); nets.Add(new[] { v & m, m }); }
            }
            CzHosts = hosts; CzNets = nets; CzSetKey = key;
        }
        static bool CzInSet(uint v)
        {
            if (CzHosts.Contains(v)) return true;
            foreach (var n in CzNets) if ((v & n[1]) == n[0]) return true;
            return false;
        }
        static void CzCleanup()
        {
            var now = DateTime.Now;
            lock (CzLock) {
                foreach (var k in CzTcp.Where(x => (now - x.Value.Last).TotalMinutes > 10).Select(x => x.Key).ToList()) CzTcp.Remove(k);
                foreach (var k in CzUdp.Where(x => (now - x.Value.Last).TotalSeconds > 120).Select(x => x.Key).ToList()) { try { CzUdp[k].Sock.Close(); } catch { } CzUdp.Remove(k); }
            }
        }

        // ---------------------------------------------------------------- перехват транзита клиентов
        static void CzFwdLoop(IntPtr h)
        {
            var pkt = new byte[65535]; var addr = new WdAddr(); uint len;
            while (true) {
                if (!WinDivertRecv(h, pkt, (uint)pkt.Length, out len, ref addr)) { if (CzFwd != h) return; Interlocked.Increment(ref CzErrors); Thread.Sleep(5); continue; }
                Interlocked.Increment(ref CzPkts);
                try { if (CzHandleFwd(h, pkt, (int)len, ref addr)) continue; } catch { Interlocked.Increment(ref CzErrors); }
                uint sl; WinDivertSend(h, pkt, len, out sl, ref addr);          // не наше — пропустить как было
                Interlocked.Increment(ref CzPass);
            }
        }
        // true — пакет обработан (не пропускать дальше как есть)
        static bool CzHandleFwd(IntPtr h, byte[] p, int n, ref WdAddr addr)
        {
            if (n < 20 || (p[0] >> 4) != 4) return false;
            int ihl = (p[0] & 15) * 4, proto = p[9];
            if (n < ihl + 8) return false;
            uint src = IpH(p, 12), dst = IpH(p, 16);
            if (!CzInSet(dst)) return false;
            int sport = (p[ihl] << 8) | p[ihl + 1], dport = (p[ihl + 2] << 8) | p[ihl + 3];
            if (proto == 6) {
                if (n > 1300) Interlocked.Increment(ref CzFwdBig);
                if (n > Interlocked.Read(ref CzFwdMax)) Interlocked.Exchange(ref CzFwdMax, n);
                ulong key = ((ulong)src << 16) | (uint)sport;
                // поддельные пакеты (их шлют средства обхода DPI на стороне клиента: zapret, роутер с «байпасом») — отбросить, как это сделали бы
                // сеть или сервер; иначе ретранслятор примет подделку за данные и испортит соединение
                string fake = CzFakeReason(p, ihl, n, key, dst, dport);
                if (fake != null) { CzTrace(key, "клиент→ ОТБРОШЕН (" + fake + ")", p, ihl, n); return true; }
                // SYN: уменьшить MSS клиента — ответы ретранслятора не должны быть больше MTU туннеля клиента (часто 1280)
                if ((p[ihl + 13] & 0x02) != 0) {
                    CzClampMss(p, ihl, n, src, sport);
                    lock (CzTraced) {
                        if (CfgBool("ws4w.clientTrace", false) && (DateTime.Now - CzTraceAt).TotalSeconds >= 120) { CzTraced.Clear(); CzTraceAt = DateTime.Now; CzTraceLeft = 150; }
                        if (CzTraced.Count < 3 && dport == 443) CzTraced.Add(key);
                    }
                }
                CzTrace(key, "клиент→", p, ihl, n);
                // к ретранслятору на ПК: как будто клиент подключился к адресу ПК в сети wg_server
                PutIp(p, 16, CzWgIp); p[ihl + 2] = (byte)(CzRelayPort >> 8); p[ihl + 3] = (byte)(CzRelayPort & 0xFF);
                var a = new WdAddr { Flags = WdLayerNetwork, IfIdx = (uint)CzWgIdx, SubIfIdx = 0 };     // входящий на wg_server
                WinDivertHelperCalcChecksums(p, (uint)n, ref a, 0);
                uint sl; var nh = CzNet; if (nh != WdInvalid) WinDivertSend(nh, p, (uint)n, out sl, ref a);
                return true;
            }
            if (proto == 17) {
                int ulen = n - ihl - 8; if (ulen < 0) return true;
                // QUIC (UDP 443): по умолчанию отбрасываем — YouTube и браузеры сразу переходят на TCP, а TCP идёт через ретранслятор и winws
                if (dport == 443 && CfgStr("ws4w.clientQuic", "drop") != "relay") { Interlocked.Increment(ref CzQuicDrop); return true; }
                string key = src + ":" + sport + ">" + dst + ":" + dport; CzUdpFlow f;
                lock (CzLock) {
                    if (!CzUdp.TryGetValue(key, out f)) {
                        var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                        s.Connect(new IPEndPoint(IPAddress.Parse(IpS(dst)), dport));
                        f = new CzUdpFlow { Client = src, CPort = sport, Dst = dst, DPort = dport, Sock = s };
                        CzUdp[key] = f; var ff = f;
                        new Thread(() => CzUdpRecv(ff)) { IsBackground = true }.Start();
                    }
                    f.Last = DateTime.Now;
                }
                try { f.Sock.Send(p, ihl + 8, ulen, SocketFlags.None); Interlocked.Increment(ref CzUdpPkts); Interlocked.Add(ref CzBytes, ulen); } catch { Interlocked.Increment(ref CzErrors); }
                return true;
            }
            return false;
        }
        // подделка? неверная сумма TCP / опция MD5 / TTL ниже, чем у SYN / метка времени из прошлого / данные без ACK
        static string CzFakeReason(byte[] p, int ihl, int n, ulong key, uint dst, int dport)
        {
            int flags = p[ihl + 13], doff = (p[ihl + 12] >> 4) * 4, dlen = n - ihl - doff, ttl = p[8];
            bool syn = (flags & 0x02) != 0, ack = (flags & 0x10) != 0, rst = (flags & 0x04) != 0;
            // контрольная сумма: посчитать на копии и сравнить с той, что пришла
            var cp = new byte[n]; Buffer.BlockCopy(p, 0, cp, 0, n); var ca = new WdAddr(); WinDivertHelperCalcChecksums(cp, (uint)n, ref ca, 0);
            long chk = Interlocked.Increment(ref CzSumChecked);
            if (!CzSumOff && (cp[ihl + 16] != p[ihl + 16] || cp[ihl + 17] != p[ihl + 17])) {
                long bad = Interlocked.Increment(ref CzDropSum);
                // предохранитель: если «неверных» больше половины — суммы, видимо, досчитывает адаптер; проверку отключить
                if (chk >= 200 && bad * 2 > chk) { CzSumOff = true; Log("zapret для клиентов: проверка контрольных сумм отключена — неверных " + bad + " из " + chk + " (их, видимо, досчитывает адаптер)", "WARN"); }
                else return "неверная сумма";
            }
            bool md5 = false, hasTs = false; uint ts = 0;
            for (int o = ihl + 20, end = Math.Min(n, ihl + doff); o < end; ) {
                int kind = p[o]; if (kind == 0) break; if (kind == 1) { o++; continue; }
                if (o + 1 >= end) break; int l = p[o + 1]; if (l < 2 || o + l > end) break;
                if (kind == 19) md5 = true;
                if (kind == 8 && l == 10) { hasTs = true; ts = IpH(p, o + 2); }
                o += l;
            }
            if (md5) { Interlocked.Increment(ref CzDropMd5); return "опция MD5"; }
            CzTcpFlow f;
            lock (CzLock) {
                if (syn && !ack) { f = new CzTcpFlow { Dst = dst, DPort = dport, SynTtl = ttl }; CzTcp[key] = f; }
                else if (!CzTcp.TryGetValue(key, out f) || f.Dst != dst || f.DPort != dport) { f = new CzTcpFlow { Dst = dst, DPort = dport, SynTtl = ttl }; CzTcp[key] = f; }
                f.Last = DateTime.Now;
            }
            if (f.SynTtl > 0 && ttl + 2 < f.SynTtl) { Interlocked.Increment(ref CzDropTtl); return "TTL " + ttl + " при " + f.SynTtl + " у SYN"; }
            if (!syn && !ack && !rst && dlen > 0) { Interlocked.Increment(ref CzDropNoAck); return "данные без ACK"; }
            if (hasTs) {
                if (f.HasTs && (int)(ts - f.MaxTs) < -10000) { Interlocked.Increment(ref CzDropTs); return "метка времени из прошлого"; }
                if (!f.HasTs || (int)(ts - f.MaxTs) > 0) { f.MaxTs = ts; f.HasTs = true; }
            }
            return null;
        }
        // трассировка пакетов первых соединений (флаги, seq/ack, длина данных) — для поиска поломок
        static void CzTrace(ulong key, string dir, byte[] p, int ihl, int n)
        {
            bool on; lock (CzTraced) on = CzTraced.Contains(key) && CzTraceLeft > 0; if (!on) return;
            if (Interlocked.Decrement(ref CzTraceLeft) < 0) return;
            int f = p[ihl + 13], doff = (p[ihl + 12] >> 4) * 4, dl = n - ihl - doff;
            string fl = ((f & 2) != 0 ? "S" : "") + ((f & 16) != 0 ? "A" : "") + ((f & 8) != 0 ? "P" : "") + ((f & 1) != 0 ? "F" : "") + ((f & 4) != 0 ? "R" : "");
            uint seq = IpH(p, ihl + 4), ack = IpH(p, ihl + 8); int win = (p[ihl + 14] << 8) | p[ihl + 15];
            Log("трасса " + (CzSw.ElapsedMilliseconds % 100000).ToString("00000") + "мс " + IpS((uint)(key >> 16)) + ":" + (key & 0xFFFF) + " " + dir + " " + fl + " seq=" + seq + " ack=" + ack + " len=" + dl + " win=" + win + " ip=" + n + " id=" + ((p[4] << 8) | p[5]) + " ttl=" + p[8], "INFO");
        }
        static void CzClampMss(byte[] p, int ihl, int n, uint src, int sport)
        {
            int max = Math.Max(536, CfgInt("ws4w.clientMss", 1200));
            int doff = (p[ihl + 12] >> 4) * 4, o = ihl + 20, end = Math.Min(n, ihl + doff); int seen = -1;
            while (o < end) {
                int kind = p[o]; if (kind == 0) break; if (kind == 1) { o++; continue; }
                if (o + 1 >= end) break; int l = p[o + 1]; if (l < 2 || o + l > end) break;
                if (kind == 2 && l == 4) {
                    seen = (p[o + 2] << 8) | p[o + 3];
                    if (seen > max) { p[o + 2] = (byte)(max >> 8); p[o + 3] = (byte)(max & 0xFF); Interlocked.Increment(ref CzMssClamped); }
                }
                o += l;
            }
            if (Interlocked.Increment(ref CzSynLogged) <= 3) Log("zapret для клиентов: SYN от " + IpS(src) + ":" + sport + ", MSS клиента " + (seen < 0 ? "нет" : seen.ToString()) + (seen > max ? " → " + max : ""), "INFO");
        }
        // ответы сайта по UDP → клиенту, пакетом с адреса и порта сайта
        static void CzUdpRecv(CzUdpFlow f)
        {
            var buf = new byte[65535];
            while (true) {
                int n; try { n = f.Sock.Receive(buf); } catch (SocketException e) { if (e.SocketErrorCode == SocketError.ConnectionReset) continue; return; } catch { return; }
                f.Last = DateTime.Now;
                var p = new byte[28 + n];
                p[0] = 0x45; p[2] = (byte)(p.Length >> 8); p[3] = (byte)p.Length; p[6] = 0x40; p[8] = 64; p[9] = 17;
                PutIp(p, 12, f.Dst); PutIp(p, 16, f.Client);
                p[20] = (byte)(f.DPort >> 8); p[21] = (byte)f.DPort; p[22] = (byte)(f.CPort >> 8); p[23] = (byte)f.CPort; p[24] = (byte)((8 + n) >> 8); p[25] = (byte)(8 + n);
                Buffer.BlockCopy(buf, 0, p, 28, n);
                var a = new WdAddr { Flags = WdLayerNetwork | WdOutbound, IfIdx = (uint)CzWgIdx };
                WinDivertHelperCalcChecksums(p, (uint)p.Length, ref a, 0);
                uint sl; var nh = CzNet; if (nh == WdInvalid) return;
                if (WinDivertSend(nh, p, (uint)p.Length, out sl, ref a)) Interlocked.Add(ref CzUdpDown, n); else Interlocked.Increment(ref CzUdpSendFail);
                Interlocked.Add(ref CzBytes, n);
            }
        }
        // ответы ретранслятора клиенту: адрес и порт ПК → исходный адрес и порт сайта
        static void CzNetLoop(IntPtr h)
        {
            var pkt = new byte[65535]; var addr = new WdAddr(); uint len;
            while (true) {
                if (!WinDivertRecv(h, pkt, (uint)pkt.Length, out len, ref addr)) { if (CzNet != h) return; Thread.Sleep(5); continue; }
                try {
                    int ihl = (pkt[0] & 15) * 4; uint dst = IpH(pkt, 16); int dport = (pkt[ihl + 2] << 8) | pkt[ihl + 3];
                    CzTcpFlow f; lock (CzLock) CzTcp.TryGetValue(((ulong)dst << 16) | (uint)dport, out f);
                    if (f != null) {
                        PutIp(pkt, 12, f.Dst); pkt[ihl] = (byte)(f.DPort >> 8); pkt[ihl + 1] = (byte)f.DPort;
                        WinDivertHelperCalcChecksums(pkt, len, ref addr, 0);
                        Interlocked.Increment(ref CzNetRw); if (len > 1500) Interlocked.Increment(ref CzNetBig);
                        CzTrace(((ulong)dst << 16) | (uint)dport, "→клиенту", pkt, ihl, (int)len);
                        if (len > Interlocked.Read(ref CzNetMax)) Interlocked.Exchange(ref CzNetMax, len);
                    } else Interlocked.Increment(ref CzNetMiss);
                } catch { Interlocked.Increment(ref CzErrors); }
                uint sl; if (!WinDivertSend(h, pkt, len, out sl, ref addr)) Interlocked.Increment(ref CzNetSendFail);
            }
        }

        // ---------------------------------------------------------------- ретранслятор TCP: соединение к тому же адресу — уже от ПК (через winws)
        static void CzAcceptLoop(TcpListener l)
        {
            while (true) {
                TcpClient c; try { c = l.AcceptTcpClient(); } catch { return; }
                new Thread(() => { try { CzRelayConn(c); } catch { } finally { try { c.Close(); } catch { } } }) { IsBackground = true }.Start();
            }
        }
        static void CzRelayConn(TcpClient c)
        {
            var ep = (IPEndPoint)c.Client.RemoteEndPoint; uint cip = IpH(ep.Address.GetAddressBytes(), 0);
            CzTcpFlow f; lock (CzLock) CzTcp.TryGetValue(((ulong)cip << 16) | (uint)ep.Port, out f);
            if (f == null) { Interlocked.Increment(ref CzRelayNoFlow); return; }
            c.NoDelay = true;
            var srv = new TcpClient(AddressFamily.InterNetwork) { NoDelay = true };
            try {
                var ar = srv.BeginConnect(IPAddress.Parse(IpS(f.Dst)), f.DPort, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(15000)) { Interlocked.Increment(ref CzConnFail); return; }
                try { srv.EndConnect(ar); } catch { Interlocked.Increment(ref CzConnFail); return; }
                Interlocked.Increment(ref CzTcpConns); Interlocked.Increment(ref CzActive);
                var cs = c.GetStream(); var ss = srv.GetStream();
                long[] cnt = new long[2]; var t0 = DateTime.Now; string first = null; long connMs = CzSw.ElapsedMilliseconds;
                var up = new Thread(() => { cnt[0] = CzPump(cs, ss, f, true); lock (cnt) if (first == null) first = "клиент"; try { srv.Client.Shutdown(SocketShutdown.Send); } catch { } }) { IsBackground = true }; up.Start();
                cnt[1] = CzPump(ss, cs, f, false); lock (cnt) if (first == null) first = "сайт"; try { c.Client.Shutdown(SocketShutdown.Send); } catch { }
                up.Join(60000);
                if (Interlocked.Increment(ref CzConnLogged) <= 20)
                    Log("zapret для клиентов: " + ep.Address + ":" + ep.Port + " → " + IpS(f.Dst) + ":" + f.DPort + " · к сайту " + cnt[0] + " Б, к клиенту " + cnt[1] + " Б, " + Math.Round((DateTime.Now - t0).TotalSeconds, 1) + " с, первым закрыл " + first + ", сайт подключён в " + (connMs % 100000).ToString("00000") + "мс", "INFO");
            } catch { }
            finally { if (Interlocked.Decrement(ref CzActive) < 0) Interlocked.Exchange(ref CzActive, 0); try { srv.Close(); } catch { } }
        }
        static long CzPump(Stream a, Stream b, CzTcpFlow f, bool up)
        {
            var bb = new byte[65536]; long total = 0;
            try { int n; while ((n = a.Read(bb, 0, bb.Length)) > 0) { b.Write(bb, 0, n); total += n; Interlocked.Add(ref CzBytes, n); if (up) Interlocked.Add(ref CzTcpUp, n); else Interlocked.Add(ref CzTcpDown, n); f.Last = DateTime.Now; } } catch { }
            return total;
        }

        // ---------------------------------------------------------------- состояние
        static Dictionary<string, object> CzSnapshot()
        {
            int tcpN, udpN; lock (CzLock) { tcpN = CzTcp.Count; udpN = CzUdp.Count; }
            return new Dictionary<string, object> { { "enabled", CzWanted() }, { "running", CzFwd != WdInvalid }, { "error", CzError },
                { "packets", Interlocked.Read(ref CzPkts) }, { "passed", Interlocked.Read(ref CzPass) }, { "tcpConns", Interlocked.Read(ref CzTcpConns) }, { "active", CzActive },
                { "tcpFlows", tcpN }, { "udpFlows", udpN }, { "udpPackets", Interlocked.Read(ref CzUdpPkts) }, { "mb", Math.Round(Interlocked.Read(ref CzBytes) / 1048576.0, 1) },
                { "errors", Interlocked.Read(ref CzErrors) }, { "relay", CzFwd != WdInvalid ? IpS(CzWgIp) + ":" + CzRelayPort : "" },
                { "ifWg", CzWgIdx }, { "ifEth", CzEthIdx }, { "probe", CzProbeCopy() },
                { "tcpUpKb", Interlocked.Read(ref CzTcpUp) / 1024 }, { "tcpDownKb", Interlocked.Read(ref CzTcpDown) / 1024 }, { "udpDownKb", Interlocked.Read(ref CzUdpDown) / 1024 },
                { "udpSendFail", Interlocked.Read(ref CzUdpSendFail) }, { "quicDropped", Interlocked.Read(ref CzQuicDrop) }, { "netRewritten", Interlocked.Read(ref CzNetRw) },
                { "netNoFlow", Interlocked.Read(ref CzNetMiss) }, { "netBig", Interlocked.Read(ref CzNetBig) }, { "netSendFail", Interlocked.Read(ref CzNetSendFail) },
                { "relayNoFlow", Interlocked.Read(ref CzRelayNoFlow) }, { "connFail", Interlocked.Read(ref CzConnFail) },
                { "leakDropped", Interlocked.Read(ref CzLeakDrop) }, { "mssClamped", Interlocked.Read(ref CzMssClamped) }, { "dropBadSum", Interlocked.Read(ref CzDropSum) }, { "dropMd5", Interlocked.Read(ref CzDropMd5) },
                { "dropTtl", Interlocked.Read(ref CzDropTtl) }, { "dropTs", Interlocked.Read(ref CzDropTs) }, { "dropNoAck", Interlocked.Read(ref CzDropNoAck) }, { "fwdBig", Interlocked.Read(ref CzFwdBig) }, { "fwdMax", Interlocked.Read(ref CzFwdMax) }, { "netMax", Interlocked.Read(ref CzNetMax) } };
        }
        static Dictionary<string, object> CzProbeCopy() { lock (CzProbeStat) return CzProbeStat.ToDictionary(x => x.Key, x => (object)x.Value); }
        static string CzSummary()
        {
            if (!CzWanted()) return "выключен (вкладка WG-Server)";
            if (CzFwd == WdInvalid) return "не работает" + (CzError.Length > 0 ? ": " + CzError : "");
            int tcpN, udpN; lock (CzLock) { tcpN = CzTcp.Count; udpN = CzUdp.Count; }
            return "работает · TCP-соединений через zapret " + Interlocked.Read(ref CzTcpConns) + " (сейчас " + CzActive + "), UDP-потоков " + udpN + " · " +
                Math.Round(Interlocked.Read(ref CzBytes) / 1048576.0, 1) + " МБ · перехвачено пакетов " + Interlocked.Read(ref CzPkts) + (Interlocked.Read(ref CzErrors) > 0 ? ", ошибок " + Interlocked.Read(ref CzErrors) : "");
        }
    }
}
