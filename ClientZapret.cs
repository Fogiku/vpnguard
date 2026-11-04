// VpnGuard — агент на C#: zapret и для клиентов WG-Server (ws4w.clientZapret), разделение по IP, прозрачно.
// winws обрабатывает только трафик, который начинается на самом ПК. Трафик клиентов wg_server к адресам из маршрутов zapret
// (YouTube, Discord, видеосерверы провайдера, свои списки) агент перехватывает (WinDivert, тот же драйвер, что у zapret) и делает «своим»:
//   TCP — заворачивает на свой ретранслятор на ПК (адрес ПК в сети wg_server : 34010), тот соединяется с тем же адресом
//         и портом уже от имени ПК → это соединение обрабатывает winws; ответы клиенту уходят с исходного адреса сайта;
//   UDP — QUIC (443) отбрасывает (браузеры сразу переходят на TCP), остальное отправляет от ПК и возвращает ответы клиенту.
// Всё остальное у клиентов — как раньше, через VPN. Ничего настраивать на устройствах не нужно.
// Пакеты принимаются и отправляются пачками (до 255 за вызов): через перехват идёт весь трафик клиентов, не только zapret.
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
        // ---------------------------------------------------------------- WinDivert 2.2
        [StructLayout(LayoutKind.Explicit, Size = 80)]
        struct WdAddr { [FieldOffset(0)] public long Timestamp; [FieldOffset(8)] public uint Flags; [FieldOffset(12)] public uint Reserved2; [FieldOffset(16)] public uint IfIdx; [FieldOffset(20)] public uint SubIfIdx; }
        const int WdLayerNetwork = 0, WdLayerForward = 1;
        const uint WdOutbound = 1u << 17;
        const int WdBatch = 255, WdAddrSize = 80;
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr LoadLibrary(string path);
        [DllImport("WinDivert.dll", CharSet = CharSet.Ansi, SetLastError = true)] static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);
        [DllImport("WinDivert.dll", SetLastError = true)] static extern bool WinDivertSend(IntPtr h, byte[] pkt, uint len, out uint sendLen, ref WdAddr addr);
        [DllImport("WinDivert.dll", SetLastError = true)] static extern bool WinDivertRecvEx(IntPtr h, byte[] pkt, uint len, out uint recvLen, ulong flags, [In, Out] WdAddr[] addr, ref uint addrLen, IntPtr ov);
        [DllImport("WinDivert.dll", SetLastError = true)] static extern bool WinDivertSendEx(IntPtr h, byte[] pkt, uint len, out uint sendLen, ulong flags, [In] WdAddr[] addr, uint addrLen, IntPtr ov);
        [DllImport("WinDivert.dll")] static extern bool WinDivertClose(IntPtr h);
        static readonly IntPtr WdInvalid = new IntPtr(-1);
        // сокеты .NET Framework наследуются дочерними процессами (wg.exe, PowerShell, веб-сервер …): копия держала бы порт ретранслятора
        // и соединения открытыми после закрытия у агента — запрещаем наследование
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetHandleInformation(IntPtr h, uint mask, uint flags);
        static T NoInherit<T>(T s) where T : class { try { var so = s as Socket ?? (s is TcpClient ? ((TcpClient)(object)s).Client : s is TcpListener ? ((TcpListener)(object)s).Server : null); if (so != null) SetHandleInformation(so.Handle, 1, 0); } catch { } return s; }
        static bool WdLoaded;

        // ---------------------------------------------------------------- состояние
        class CzTcpFlow { public uint Dst; public int DPort; public DateTime Last; public int SynTtl; public uint MaxTs; public bool HasTs; }
        class CzUdpFlow { public uint Client, Dst; public int CPort, DPort; public Socket Sock; public DateTime Last; }
        struct CzUdpKey : IEquatable<CzUdpKey>
        {
            public ulong A, B;
            public bool Equals(CzUdpKey o) { return A == o.A && B == o.B; }
            public override bool Equals(object o) { return o is CzUdpKey && Equals((CzUdpKey)o); }
            public override int GetHashCode() { return (A * 31 + B).GetHashCode(); }
        }
        // адреса zapret: слитые диапазоны [Lo, Hi], по возрастанию — поиск двоичный
        class CzRanges { public uint[] Lo = new uint[0], Hi = new uint[0]; }
        static readonly object CzLock = new object();
        static readonly Dictionary<ulong, CzTcpFlow> CzTcp = new Dictionary<ulong, CzTcpFlow>();
        static readonly Dictionary<CzUdpKey, CzUdpFlow> CzUdp = new Dictionary<CzUdpKey, CzUdpFlow>();
        static IntPtr CzFwd = WdInvalid, CzNet = WdInvalid, CzBlk = WdInvalid;
        static TcpListener CzRelay;
        const int CzRelayPort = 34010;
        static uint CzWgIp; static int CzWgIdx, CzEthIdx; static string CzSig = "", CzError = "";
        static long CzPkts, CzPass, CzTcpConns, CzUdpPkts, CzBytes, CzErrors, CzTcpUp, CzTcpDown, CzUdpDown, CzUdpSendFail, CzQuicDrop, CzNetRw, CzNetMiss, CzNetSendFail,
            CzRelayNoFlow, CzConnFail, CzMssClamped, CzDropSum, CzDropMd5, CzDropTtl, CzDropTs, CzDropNoAck, CzSumChecked, CzLeakDrop;
        static volatile bool CzSumOff, CzQuicRelay; static int CzActive, CzMss = 1200;
        static volatile CzRanges CzSet = new CzRanges(); static string CzSetKey = "";
        static DateTime CzFwAt = DateTime.MinValue, CzCleanAt = DateTime.MinValue; static string CzFwSig = "";
        // по клиентам: кому zapret не нужен (ws4w.clientNoZapret — их трафик целиком через VPN, как без этой функции) и счётчики
        class CzCli { public long Pkts, ZPkts, Conns, Up, Down, Quic, Fail, Leak; public int Logged, FailLogged; public DateTime LastZ = DateTime.MinValue; }
        static readonly ConcurrentDictionary<uint, CzCli> CzClients = new ConcurrentDictionary<uint, CzCli>();
        static readonly Func<uint, CzCli> CzNewCli = k => new CzCli();
        static volatile HashSet<uint> CzNoZ = new HashSet<uint>();
        static CzCli CzC(uint ip) { return CzClients.GetOrAdd(ip, CzNewCli); }
        static void CzUpdateNoZ()
        {
            var s = new HashSet<uint>(); IPAddress a;
            foreach (var x in CfgList("ws4w.clientNoZapret", new string[0]).Concat(CfgList("ws4w.clientOff", new string[0])))
                if (IPAddress.TryParse(x.Trim(), out a) && a.AddressFamily == AddressFamily.InterNetwork) s.Add(IpH(a.GetAddressBytes(), 0));
            if (!s.SetEquals(CzNoZ)) {
                var was = CzNoZ; CzNoZ = s;
                foreach (var v in s.Except(was)) Log("zapret для клиентов: " + IpS(v) + " — без zapret, весь трафик через VPN", "INFO");
                foreach (var v in was.Except(s)) Log("zapret для клиентов: " + IpS(v) + " — снова через zapret", "INFO");
            }
        }
        static bool CzClientZapret(string ip) { return !CfgList("ws4w.clientNoZapret", new string[0]).Any(x => x.Trim() == ip); }
        static Dictionary<string, object> CzClientStat(string ip)
        {
            IPAddress a; CzCli c; if (!IPAddress.TryParse(ip, out a) || !CzClients.TryGetValue(IpH(a.GetAddressBytes(), 0), out c)) return null;
            return new Dictionary<string, object> { { "pkts", Interlocked.Read(ref c.Pkts) }, { "zPkts", Interlocked.Read(ref c.ZPkts) }, { "conns", Interlocked.Read(ref c.Conns) },
                { "upKb", Interlocked.Read(ref c.Up) / 1024 }, { "downKb", Interlocked.Read(ref c.Down) / 1024 }, { "quic", Interlocked.Read(ref c.Quic) }, { "fail", Interlocked.Read(ref c.Fail) },
                { "leak", Interlocked.Read(ref c.Leak) }, { "vpn", Interlocked.Read(ref c.Fail) }, { "rate", RateOf("cz:" + ip, Interlocked.Read(ref c.Down), Interlocked.Read(ref c.Up)) }, { "lastAgo", c.LastZ == DateTime.MinValue ? -1 : (long)(DateTime.UtcNow - c.LastZ).TotalSeconds } };
        }

        // скорость (байт/с) по приращению счётчиков между снимками состояния
        static readonly Dictionary<string, KeyValuePair<DateTime, long[]>> RatePrev = new Dictionary<string, KeyValuePair<DateTime, long[]>>();
        static long[] RateOf(string key, params long[] vals)
        {
            lock (RatePrev) {
                KeyValuePair<DateTime, long[]> p; var now = DateTime.UtcNow; var res = new long[vals.Length];
                if (RatePrev.TryGetValue(key, out p) && p.Value.Length == vals.Length) {
                    double dt = (now - p.Key).TotalSeconds;
                    if (dt < 1) return RatePrevRes.ContainsKey(key) ? RatePrevRes[key] : res;
                    for (int i = 0; i < vals.Length; i++) res[i] = vals[i] >= p.Value[i] ? (long)((vals[i] - p.Value[i]) / dt) : 0;
                }
                RatePrev[key] = new KeyValuePair<DateTime, long[]>(now, vals); RatePrevRes[key] = res;
                return res;
            }
        }
        static readonly Dictionary<string, long[]> RatePrevRes = new Dictionary<string, long[]>();
        // ретранслятор (через zapret): [↓, ↑], байт/с
        static long[] CzRates() { return RateOf("cz", Interlocked.Read(ref CzTcpDown), Interlocked.Read(ref CzTcpUp)); }
        static bool CzWanted() { return CfgBool("ws4w.clientZapret", false); }
        static uint IpH(byte[] b, int o) { return ((uint)b[o] << 24) | ((uint)b[o + 1] << 16) | ((uint)b[o + 2] << 8) | b[o + 3]; }
        static void PutIp(byte[] b, int o, uint v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }
        static uint IpH(string s) { var b = IPAddress.Parse(s).GetAddressBytes(); return IpH(b, 0); }
        static string IpS(uint v) { return (v >> 24) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255); }
        static IPAddress IpA(uint v) { return new IPAddress(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v }); }
        static int IfIndexOf(string name) { var n = Nic(name); try { return n == null ? 0 : n.GetIPProperties().GetIPv4Properties().Index; } catch { return 0; } }

        // ---------------------------------------------------------------- контрольные суммы (свои: без копий пакета и без вызовов в DLL)
        static uint CsAdd(byte[] b, int o, int len, uint sum)
        {
            int end = o + (len & ~1);
            for (; o < end; o += 2) sum += (uint)((b[o] << 8) | b[o + 1]);
            if ((len & 1) != 0) sum += (uint)(b[end] << 8);
            return sum;
        }
        static ushort CsFold(uint sum) { while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16); return (ushort)~sum; }
        // сумма TCP/UDP с псевдозаголовком; поле суммы в пакете должно быть обнулено (или включено — тогда у верной суммы результат 0)
        static ushort CsL4(byte[] b, int o, int ihl, int n)
        {
            int l4 = n - ihl; uint sum = CsAdd(b, o + 12, 8, 0) + b[o + 9] + (uint)l4;
            return CsFold(CsAdd(b, o + ihl, l4, sum));
        }
        // пересчитать суммы IPv4 и TCP/UDP пакета b[o .. o+n)
        static void CsFix(byte[] b, int o, int n)
        {
            int ihl = (b[o] & 15) * 4, proto = b[o + 9];
            b[o + 10] = 0; b[o + 11] = 0; ushort ic = CsFold(CsAdd(b, o, ihl, 0)); b[o + 10] = (byte)(ic >> 8); b[o + 11] = (byte)ic;
            int co = proto == 6 ? 16 : proto == 17 ? 6 : -1; if (co < 0 || n < ihl + co + 2) return;
            b[o + ihl + co] = 0; b[o + ihl + co + 1] = 0;
            ushort c = CsL4(b, o, ihl, n); if (proto == 17 && c == 0) c = 0xFFFF;
            b[o + ihl + co] = (byte)(c >> 8); b[o + ihl + co + 1] = (byte)c;
        }

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
            CzUpdateSet(); CzUpdateNoZ();
            CzQuicRelay = CfgStr("ws4w.clientQuic", "drop") == "relay"; CzQuicReject = CfgBool("ws4w.clientQuicReject", true); CzMss = Math.Max(536, CfgInt("ws4w.clientMss", 1200));
            CzFallbackMs = Math.Max(1500, CfgInt("ws4w.clientFallbackMs", 3000)); CzBypassMin = Math.Max(1, CfgInt("ws4w.clientBypassMin", 5));
            CzVpnHosts = CfgList("ws4w.clientVpnHosts", new[] { "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com" }).Select(x => x.Trim().TrimStart('.')).Where(x => x.Length > 0).ToArray();
            CzVideoVpn = CfgBool("ws4w.clientVideoVpn", true); CzVideoVpnMin = Math.Max(10, CfgInt("ws4w.clientVideoVpnMin", 360));
            if (CzVideoVpn) { try { CzLoadGoogle(); } catch (Exception e) { Log("zapret для клиентов: диапазоны Google: " + e.Message, "WARN"); } }
            try { CzUpdateProfiles(CzWinwsArgs()); } catch (Exception e) { Log("zapret для клиентов: профили winws: " + e.Message, "WARN"); }
            string sig = wgIp + "|" + IfIndexOf(WgIf()) + "|" + phys.IfIndex + "|" + phys.Ip;
            if (CzFwd == WdInvalid || sig != CzSig) {
                CzStop();
                try { CzStart(dll, wgIp, phys); CzSig = sig; CzError = ""; }
                catch (Exception e) { CzError = e.Message; Log("zapret для клиентов WG-Server: " + e.Message, "ERROR"); CzStop(); return; }
            }
            CzFirewall(wgIp);
            if ((DateTime.UtcNow - CzCleanAt).TotalSeconds >= 30) { CzCleanAt = DateTime.UtcNow; CzCleanup(); }
            if ((DateTime.UtcNow - CzLogResetAt).TotalMinutes >= 60) { CzLogResetAt = DateTime.UtcNow; foreach (var cc in CzClients.Values) { cc.Logged = 0; cc.FailLogged = 0; } }
        }

        static void CzStart(string dll, string wgIp, ZPath phys)
        {
            if (!WdLoaded) { if (LoadLibrary(dll) == IntPtr.Zero) throw new Exception("не загрузился " + dll + " (код " + Marshal.GetLastWin32Error() + ")"); WdLoaded = true; }
            CzWgIp = IpH(wgIp); CzWgIdx = IfIndexOf(WgIf()); CzEthIdx = phys.IfIndex;
            string sub = Regex.Replace(wgIp, @"\.\d+$", "");
            // транзит от клиентов wg_server (раздача Windows шлёт его в туннель VPN); адреса zapret отбираются в коде, остальное — как было
            string ff = "ip and (tcp or udp) and ip.SrcAddr >= " + sub + ".0 and ip.SrcAddr <= " + sub + ".255 and ip.SrcAddr != " + wgIp + " and (ip.DstAddr < " + sub + ".0 or ip.DstAddr > " + sub + ".255)";
            // ответы ретранслятора клиентам: исходящие с адреса ПК в сети wg_server и порта ретранслятора
            string nf = "outbound and ip and tcp and ip.SrcAddr == " + wgIp + " and tcp.SrcPort == " + CzRelayPort;
            // NAT раздачи Windows успевает переслать копию пакетов клиента к настоящему серверу (мимо перехвата) — его ответы (SYN-ACK, RST)
            // приходят клиенту вперемешку с ответами ретранслятора и рвут соединение. Ответы адресов zapret клиенту — только через ретранслятор.
            string bf = "ip and (tcp or udp) and ip.DstAddr >= " + sub + ".0 and ip.DstAddr <= " + sub + ".255 and ip.DstAddr != " + wgIp;
            var relay = new TcpListener(IPAddress.Parse(wgIp), CzRelayPort);          // без эксклюзивного порта: иначе после перезапуска агента порт занят, пока не истекут соединения прежнего (TIME_WAIT)
            NoInherit(relay);
            try { relay.Start(256); }
            catch (Exception e) {
                // порт держит копия сокета, унаследованная процессом от прежнего агента (до 3.14.1): winws или веб-сервер — перезапустить его
                string who = "";
                try {
                    var m = Regex.Match(Exe("netstat.exe", "-ano -p TCP", 15).Out, @"(?m)^\s*TCP\s+" + Regex.Escape(wgIp) + ":" + CzRelayPort + @"\s+\S+\s+\S+\s+(\d+)\s*$");
                    if (m.Success) {
                        var p = System.Diagnostics.Process.GetProcessById(int.Parse(m.Groups[1].Value)); who = p.ProcessName + " (PID " + p.Id + ")";
                        if (p.Id != System.Diagnostics.Process.GetCurrentProcess().Id && (p.ProcessName == "winws" || p.ProcessName == "VpnGuardWeb")) {
                            Log("zapret для клиентов: порт " + CzRelayPort + " держит " + who + " (копия сокета от прежнего агента) — перезапускаю его", "WARN");
                            p.Kill(); p.WaitForExit(5000);             // winws поднимет наблюдение за zapret, веб-сервер — часть PowerShell
                        }
                    }
                } catch { }
                throw new Exception("порт " + CzRelayPort + " на " + wgIp + " занят" + (who.Length > 0 ? " (" + who + ")" : "") + ": " + e.Message);
            }
            var hf = WinDivertOpen(ff, WdLayerForward, 0, 0);
            if (hf == WdInvalid) { relay.Stop(); throw new Exception("WinDivert (транзит) не открылся, код " + Marshal.GetLastWin32Error()); }
            var hn = WinDivertOpen(nf, WdLayerNetwork, 0, 0);
            if (hn == WdInvalid) { WinDivertClose(hf); relay.Stop(); throw new Exception("WinDivert (ответы) не открылся, код " + Marshal.GetLastWin32Error()); }
            var hb = WinDivertOpen(bf, WdLayerForward, 0, 0);
            if (hb == WdInvalid) Log("zapret для клиентов: фильтр ответов не открылся, код " + Marshal.GetLastWin32Error() + " — соединения могут рваться", "ERROR");
            CzFwd = hf; CzNet = hn; CzBlk = hb; CzRelay = relay; CzStartedAt = DateTime.UtcNow;
            foreach (var cc in CzClients.Values) { cc.Logged = 0; cc.FailLogged = 0; }
            new Thread(() => CzBatchLoop(hf, () => CzFwd, CzOnFwd)) { IsBackground = true, Name = "cz-fwd" }.Start();
            new Thread(() => CzBatchLoop(hn, () => CzNet, CzOnNet)) { IsBackground = true, Name = "cz-net" }.Start();
            if (hb != WdInvalid) new Thread(() => CzBatchLoop(hb, () => CzBlk, CzOnBlk)) { IsBackground = true, Name = "cz-blk" }.Start();
            CzAcceptLoop(relay);
            Log("zapret для клиентов WG-Server: включён — трафик клиентов к адресам zapret (" + ZRoutes().Count + " маршрутов) идёт через zapret этого ПК, остальное — через VPN (" + phys.Alias + ", ретранслятор " + wgIp + ":" + CzRelayPort + ")", "WARN");
        }
        static void CzStop()
        {
            var hs = new[] { CzBlk, CzFwd, CzNet }; CzBlk = WdInvalid; CzFwd = WdInvalid; CzNet = WdInvalid;
            foreach (var h in hs) try { if (h != WdInvalid) WinDivertClose(h); } catch { }
            try { if (CzRelay != null) CzRelay.Stop(); } catch { }
            CzRelay = null; CzSig = "";
            lock (CzLock) { foreach (var u in CzUdp.Values) { try { u.Sock.Close(); } catch { } } CzUdp.Clear(); CzTcp.Clear(); }
        }
        static void CzFirewall(string wgIp)
        {
            string sub = Regex.Replace(wgIp, @"\.\d+$", ".0/24"), sig = wgIp + "|" + sub;
            if (sig == CzFwSig && (DateTime.UtcNow - CzFwAt).TotalMinutes < 30) return;
            CzFwAt = DateTime.UtcNow;
            const string name = "VpnGuard WG-Server zapret";
            bool have = Exe("netsh.exe", "advfirewall firewall show rule name=\"" + name + "\"", 15).Code == 0;
            if (have && sig == CzFwSig) return;
            if (have) Exe("netsh.exe", "advfirewall firewall delete rule name=\"" + name + "\"", 15);
            Exe("netsh.exe", "advfirewall firewall add rule name=\"" + name + "\" dir=in action=allow protocol=TCP localip=" + wgIp + " localport=" + CzRelayPort + " remoteip=" + sub, 15);
            CzFwSig = sig;
        }
        // адреса zapret — те же, что в маршрутах мимо VPN; слить в упорядоченные диапазоны
        static void CzUpdateSet()
        {
            var routes = ZRoutes(); var key = routes.Count + "|" + ZS("lastRouteRefresh");
            if (key == CzSetKey) return;
            var rs = new List<KeyValuePair<uint, uint>>();
            foreach (var r in routes) {
                var pp = JS(r, "p").Split('/'); IPAddress ip; int len;
                if (pp.Length != 2 || !IPAddress.TryParse(pp[0], out ip) || ip.AddressFamily != AddressFamily.InterNetwork || !int.TryParse(pp[1], out len) || len < 0 || len > 32) continue;
                uint m = len == 0 ? 0 : 0xFFFFFFFFu << (32 - len), lo = IpH(ip.GetAddressBytes(), 0) & m;
                rs.Add(new KeyValuePair<uint, uint>(lo, lo | ~m));
            }
            rs.Sort((x, y) => x.Key.CompareTo(y.Key));
            var lo2 = new List<uint>(); var hi2 = new List<uint>();
            foreach (var r in rs) {
                int k = hi2.Count - 1;
                if (k >= 0 && (hi2[k] == uint.MaxValue || r.Key <= hi2[k] + 1)) { if (r.Value > hi2[k]) hi2[k] = r.Value; }
                else { lo2.Add(r.Key); hi2.Add(r.Value); }
            }
            CzSet = new CzRanges { Lo = lo2.ToArray(), Hi = hi2.ToArray() }; CzSetKey = key;
        }
        static bool CzInSet(uint v)
        {
            var s = CzSet; int a = 0, b = s.Lo.Length - 1;
            while (a <= b) { int m = (a + b) >> 1; if (v < s.Lo[m]) b = m - 1; else if (v > s.Hi[m]) a = m + 1; else return true; }
            return false;
        }
        static void CzCleanup()
        {
            var now = DateTime.UtcNow;
            lock (CzLock) {
                foreach (var k in CzTcp.Where(x => (now - x.Value.Last).TotalMinutes > 10).Select(x => x.Key).ToList()) CzTcp.Remove(k);
                foreach (var k in CzBypass.Where(x => x.Value < DateTime.UtcNow).Select(x => x.Key).ToList()) { DateTime d; CzBypass.TryRemove(k, out d); }
                foreach (var k in CzRemap.Where(x => x.Value.Value < DateTime.UtcNow).Select(x => x.Key).ToList()) { KeyValuePair<uint, DateTime> d; CzRemap.TryRemove(k, out d); }
                foreach (var k in CzBadHost.Where(x => x.Value < DateTime.UtcNow).Select(x => x.Key).ToList()) { DateTime d; CzBadHost.TryRemove(k, out d); }
                foreach (var k in CzUdp.Where(x => (now - x.Value.Last).TotalSeconds > 120).Select(x => x.Key).ToList()) { try { CzUdp[k].Sock.Close(); } catch { } CzUdp.Remove(k); }
            }
        }

        // ---------------------------------------------------------------- пакеты пачками
        // обработчик: пакет b[o .. o+n), адрес a; true — пакет забран (дальше не пропускать), false — пропустить (возможно, изменённым)
        delegate bool CzPktFn(byte[] b, int o, int n, ref WdAddr a);
        static void CzBatchLoop(IntPtr h, Func<IntPtr> current, CzPktFn fn)
        {
            var buf = new byte[WdBatch * 1600 + 65536]; var addrs = new WdAddr[WdBatch];
            var outBuf = new byte[buf.Length]; var outAddrs = new WdAddr[WdBatch];
            while (true) {
                uint got, alen = (uint)(WdBatch * WdAddrSize);
                if (!WinDivertRecvEx(h, buf, (uint)buf.Length, out got, 0, addrs, ref alen, IntPtr.Zero)) { if (current() != h) return; Interlocked.Increment(ref CzErrors); Thread.Sleep(5); continue; }
                int cnt = (int)(alen / WdAddrSize), o = 0, outLen = 0, outN = 0;
                for (int i = 0; i < cnt && o + 20 <= got; i++) {
                    int n = (buf[o] >> 4) == 4 ? (buf[o + 2] << 8) | buf[o + 3] : 0;
                    if (n < 20 || o + n > got) break;                                   // не IPv4 или обрезан — дальше не разобрать
                    bool taken = false;
                    try { taken = fn(buf, o, n, ref addrs[i]); } catch { Interlocked.Increment(ref CzErrors); }
                    if (!taken) { Buffer.BlockCopy(buf, o, outBuf, outLen, n); outLen += n; outAddrs[outN++] = addrs[i]; }
                    o += n;
                }
                if (outN > 0) { uint sl; if (!WinDivertSendEx(h, outBuf, (uint)outLen, out sl, 0, outAddrs, (uint)(outN * WdAddrSize), IntPtr.Zero)) Interlocked.Increment(ref CzNetSendFail); }
            }
        }
        // ответы адресов zapret клиенту мимо ретранслятора (утечка NAT) — отбросить
        static bool CzOnBlk(byte[] b, int o, int n, ref WdAddr a)
        {
            uint to = IpH(b, o + 16), from = IpH(b, o + 12);
            if (CzNoZ.Contains(to) || !CzInSet(from)) return false;
            if (CzBypassed(to, from) && !(b[o + 9] == 6 && CzIsRelayFlow(to, b[o + (b[o] & 15) * 4 + 2] << 8 | b[o + (b[o] & 15) * 4 + 3], from, false))) return false;
            Interlocked.Increment(ref CzLeakDrop); Interlocked.Increment(ref CzC(to).Leak); return true;
        }
        // ответы ретранслятора клиенту: адрес и порт ПК → исходный адрес и порт сайта
        static bool CzOnNet(byte[] b, int o, int n, ref WdAddr a)
        {
            int ihl = (b[o] & 15) * 4; uint dst = IpH(b, o + 16); int dport = (b[o + ihl + 2] << 8) | b[o + ihl + 3];
            CzTcpFlow f; lock (CzLock) CzTcp.TryGetValue(((ulong)dst << 16) | (uint)dport, out f);
            if (f == null) { Interlocked.Increment(ref CzNetMiss); return false; }
            PutIp(b, o + 12, f.Dst); b[o + ihl] = (byte)(f.DPort >> 8); b[o + ihl + 1] = (byte)f.DPort;
            CsFix(b, o, n); Interlocked.Increment(ref CzNetRw);
            return false;
        }
        // транзит клиента: к адресам zapret — на ретранслятор (TCP) или от имени ПК (UDP); остальное — как было
        static bool CzOnFwd(byte[] b, int o, int n, ref WdAddr addr)
        {
            Interlocked.Increment(ref CzPkts);
            int ihl = (b[o] & 15) * 4, proto = b[o + 9];
            if (n < ihl + 8) return false;
            uint src = IpH(b, o + 12), dst = IpH(b, o + 16);
            var cl = CzC(src); Interlocked.Increment(ref cl.Pkts);
            if (CzNoZ.Contains(src) || !CzInSet(dst)) { Interlocked.Increment(ref CzPass); return false; }
            // zapret к этому адресу не ответил — новые соединения клиента к нему через VPN (раздача); начатые через ретранслятор — как были
            if (CzBypassed(src, dst) && !CzIsRelayFlow(src, b[o + ihl] << 8 | b[o + ihl + 1], dst, proto == 6 && (b[o + ihl + 13] & 0x02) != 0)) { Interlocked.Increment(ref CzBypassPkts); Interlocked.Increment(ref CzPass); return false; }
            Interlocked.Increment(ref cl.ZPkts); cl.LastZ = DateTime.UtcNow;
            int sport = (b[o + ihl] << 8) | b[o + ihl + 1], dport = (b[o + ihl + 2] << 8) | b[o + ihl + 3];
            if (proto == 6) {
                if (n < ihl + 20) return true;
                ulong key = ((ulong)src << 16) | (uint)sport;
                // поддельные пакеты (их шлют средства обхода DPI на стороне клиента: zapret, роутер с «байпасом») — отбросить, как это сделали бы
                // сеть или сервер; иначе ретранслятор примет подделку за данные и испортит соединение
                if (CzFake(b, o, ihl, n, key, dst, dport)) return true;
                // SYN: уменьшить MSS клиента — ответы ретранслятора не должны быть больше MTU туннеля клиента (часто 1280)
                if ((b[o + ihl + 13] & 0x02) != 0) CzClampMss(b, o, ihl, n);
                // к ретранслятору на ПК: как будто клиент подключился к адресу ПК в сети wg_server
                var p = new byte[n]; Buffer.BlockCopy(b, o, p, 0, n);
                PutIp(p, 16, CzWgIp); p[ihl + 2] = (byte)(CzRelayPort >> 8); p[ihl + 3] = (byte)(CzRelayPort & 0xFF);
                CsFix(p, 0, n);
                var a = new WdAddr { Flags = WdLayerNetwork, IfIdx = (uint)CzWgIdx, SubIfIdx = 0 };     // входящий на wg_server
                uint sl; var nh = CzNet; if (nh != WdInvalid) WinDivertSend(nh, p, (uint)n, out sl, ref a);
                return true;
            }
            if (proto == 17) {
                int ulen = n - ihl - 8; if (ulen < 0) return true;
                // QUIC (UDP 443): по умолчанию отбрасываем — YouTube и браузеры сразу переходят на TCP, а TCP идёт через ретранслятор и winws
                // молча отброшенный QUIC приложение YouTube ждёт несколько секунд — ответить «порт недоступен», чтобы оно сразу перешло на TCP
                if (dport == 443 && !CzQuicRelay) { Interlocked.Increment(ref CzQuicDrop); Interlocked.Increment(ref cl.Quic); CzIcmpUnreach(b, o, ihl, n); return true; }
                var key = new CzUdpKey { A = ((ulong)src << 16) | (uint)sport, B = ((ulong)dst << 16) | (uint)dport }; CzUdpFlow f;
                lock (CzLock) {
                    if (!CzUdp.TryGetValue(key, out f)) {
                        var s = NoInherit(new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp));
                        s.Connect(new IPEndPoint(IpA(dst), dport));
                        f = new CzUdpFlow { Client = src, CPort = sport, Dst = dst, DPort = dport, Sock = s };
                        CzUdp[key] = f; var ff = f;
                        new Thread(() => CzUdpRecv(ff)) { IsBackground = true }.Start();
                    }
                    f.Last = DateTime.UtcNow;
                }
                try { f.Sock.Send(b, o + ihl + 8, ulen, SocketFlags.None); Interlocked.Increment(ref CzUdpPkts); Interlocked.Add(ref CzBytes, ulen); } catch { Interlocked.Increment(ref CzErrors); }
                return true;
            }
            return false;
        }
        // подделка? неверная сумма TCP / опция MD5 / TTL ниже, чем у SYN / метка времени из прошлого / данные без ACK
        static bool CzFake(byte[] b, int o, int ihl, int n, ulong key, uint dst, int dport)
        {
            int t = o + ihl, flags = b[t + 13], doff = (b[t + 12] >> 4) * 4, dlen = n - ihl - doff, ttl = b[o + 8];
            bool syn = (flags & 0x02) != 0, ack = (flags & 0x10) != 0, rst = (flags & 0x04) != 0;
            if (!CzSumOff) {
                long chk = Interlocked.Increment(ref CzSumChecked);
                if (CsL4(b, o, ihl, n) != 0) {
                    long bad = Interlocked.Increment(ref CzDropSum);
                    // предохранитель: если «неверных» больше половины — суммы, видимо, досчитывает адаптер; проверку отключить
                    if (chk >= 200 && bad * 2 > chk) { CzSumOff = true; Log("zapret для клиентов: проверка контрольных сумм отключена — неверных " + bad + " из " + chk + " (их, видимо, досчитывает адаптер)", "WARN"); }
                    else return true;
                }
            }
            bool md5 = false, hasTs = false; uint ts = 0;
            for (int p = t + 20, end = Math.Min(o + n, t + doff); p < end; ) {
                int kind = b[p]; if (kind == 0) break; if (kind == 1) { p++; continue; }
                if (p + 1 >= end) break; int l = b[p + 1]; if (l < 2 || p + l > end) break;
                if (kind == 19) md5 = true;
                if (kind == 8 && l == 10) { hasTs = true; ts = IpH(b, p + 2); }
                p += l;
            }
            if (md5) { Interlocked.Increment(ref CzDropMd5); return true; }
            CzTcpFlow f;
            lock (CzLock) {
                if ((syn && !ack) || !CzTcp.TryGetValue(key, out f) || f.Dst != dst || f.DPort != dport) { f = new CzTcpFlow { Dst = dst, DPort = dport, SynTtl = ttl }; CzTcp[key] = f; }
                f.Last = DateTime.UtcNow;
            }
            if (f.SynTtl > 0 && ttl + 2 < f.SynTtl) { Interlocked.Increment(ref CzDropTtl); return true; }
            if (!syn && !ack && !rst && dlen > 0) { Interlocked.Increment(ref CzDropNoAck); return true; }
            if (hasTs) {
                if (f.HasTs && (int)(ts - f.MaxTs) < -10000) { Interlocked.Increment(ref CzDropTs); return true; }
                if (!f.HasTs || (int)(ts - f.MaxTs) > 0) { f.MaxTs = ts; f.HasTs = true; }
            }
            return false;
        }
        static void CzClampMss(byte[] b, int o, int ihl, int n)
        {
            int t = o + ihl, doff = (b[t + 12] >> 4) * 4, p = t + 20, end = Math.Min(o + n, t + doff), max = CzMss;
            while (p < end) {
                int kind = b[p]; if (kind == 0) break; if (kind == 1) { p++; continue; }
                if (p + 1 >= end) break; int l = b[p + 1]; if (l < 2 || p + l > end) break;
                if (kind == 2 && l == 4 && ((b[p + 2] << 8) | b[p + 3]) > max) { b[p + 2] = (byte)(max >> 8); b[p + 3] = (byte)(max & 0xFF); Interlocked.Increment(ref CzMssClamped); }
                p += l;
            }
        }
        // ICMP «порт недоступен» клиенту от имени сайта (тип 3, код 3): в ответе — заголовок IP и первые 8 байт исходного пакета
        static long CzIcmpSent;
        static void CzIcmpUnreach(byte[] b, int o, int ihl, int n)
        {
            if (!CzQuicReject) return;
            int ql = ihl + Math.Min(8, n - ihl); var p = new byte[28 + ql];
            p[0] = 0x45; p[2] = (byte)(p.Length >> 8); p[3] = (byte)p.Length; p[8] = 64; p[9] = 1;
            Buffer.BlockCopy(b, o + 16, p, 12, 4); Buffer.BlockCopy(b, o + 12, p, 16, 4);       // от сайта → клиенту
            p[20] = 3; p[21] = 3; Buffer.BlockCopy(b, o, p, 28, ql);
            ushort ic = CsFold(CsAdd(p, 20, 8 + ql, 0)); p[22] = (byte)(ic >> 8); p[23] = (byte)ic;
            CsFix(p, 0, p.Length);
            var a = new WdAddr { Flags = WdLayerNetwork | WdOutbound, IfIdx = (uint)CzWgIdx };
            uint sl; var nh = CzNet; if (nh != WdInvalid && WinDivertSend(nh, p, (uint)p.Length, out sl, ref a)) Interlocked.Increment(ref CzIcmpSent);
        }
        // ответы сайта по UDP → клиенту, пакетом с адреса и порта сайта
        static void CzUdpRecv(CzUdpFlow f)
        {
            var buf = new byte[65535];
            while (true) {
                int n; try { n = f.Sock.Receive(buf); } catch (SocketException e) { if (e.SocketErrorCode == SocketError.ConnectionReset) continue; return; } catch { return; }
                f.Last = DateTime.UtcNow;
                var p = new byte[28 + n];
                p[0] = 0x45; p[2] = (byte)(p.Length >> 8); p[3] = (byte)p.Length; p[6] = 0x40; p[8] = 64; p[9] = 17;
                PutIp(p, 12, f.Dst); PutIp(p, 16, f.Client);
                p[20] = (byte)(f.DPort >> 8); p[21] = (byte)f.DPort; p[22] = (byte)(f.CPort >> 8); p[23] = (byte)f.CPort; p[24] = (byte)((8 + n) >> 8); p[25] = (byte)(8 + n);
                Buffer.BlockCopy(buf, 0, p, 28, n);
                CsFix(p, 0, p.Length);
                var a = new WdAddr { Flags = WdLayerNetwork | WdOutbound, IfIdx = (uint)CzWgIdx };
                uint sl; var nh = CzNet; if (nh == WdInvalid) return;
                if (WinDivertSend(nh, p, (uint)p.Length, out sl, ref a)) Interlocked.Add(ref CzUdpDown, n); else Interlocked.Increment(ref CzUdpSendFail);
                Interlocked.Add(ref CzBytes, n);
            }
        }


        // ---------------------------------------------------------------- имя сайта и списки winws (для журнала и решений)
        // zapret отправляет мимо VPN целые диапазоны адресов (Google, Discord …), а обходит DPI только для сайтов из своих списков
        // (и адресов из ipset). Соединение к сайту вне списков пошло бы к провайдеру без обхода и, скорее всего, заглохло бы.
        // Ретранслятор читает имя сайта из первого пакета (TLS ClientHello — SNI, HTTP — Host) и проверяет его так же, как winws
        // (по профилям из командной строки winws): обработает — напрямую через zapret, нет — через VPN. Сайт не ответил за
        // ws4w.clientFallbackMs — один повтор через другой путь; удачный путь для имени запоминается на 30 мин.
        class CzProf { public List<int[]> Ports = new List<int[]>(); public HashSet<string> Hosts, HostEx; public CzRanges Ips, IpEx; }
        static volatile List<CzProf> CzProfs = new List<CzProf>(); static string CzProfKey = ""; static int CzWArgsPid; static string CzWArgs = "";
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
        // видео Google через VPN (ws4w.clientVideoVpn): кэш провайдера (адреса не Google) остаётся через zapret
        static bool CzQuicReject = true;
        static bool CzVideoVpn = true; static int CzVideoVpnMin = 360; static long CzVideoToVpn;
        static readonly ConcurrentDictionary<uint, byte> CzVideoLogged = new ConcurrentDictionary<uint, byte>();
        static CzRanges CzGoogle = new CzRanges { Lo = new uint[0], Hi = new uint[0] }; static DateTime CzGoogleAt = DateTime.MinValue;
        // имена, которым через VPN лучше всегда (ws4w.clientVpnHosts), и имена, недавно не ответившие через zapret
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
        static void CzRemember(string host, uint ip) { var f = CzFamily(host); if (f != null) CzGoodIp[f] = ip; }
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
        static async Task<TcpClient> CzConnect(uint dst, int port)
        {
            var s = NoInherit(new TcpClient(AddressFamily.InterNetwork) { NoDelay = true });
            try {
                var t = s.ConnectAsync(IpA(dst), port);
                if (await Task.WhenAny(t, Task.Delay(10000)).ConfigureAwait(false) != t || t.IsFaulted) { CzObserve(t); s.Close(); return null; }
                return s;
            } catch { try { s.Close(); } catch { } return null; }
        }

        // ---------------------------------------------------------------- ретранслятор TCP: соединение к тому же адресу — уже от ПК (через winws или VPN)
        // асинхронно: без двух потоков на каждое соединение
        static async void CzAcceptLoop(TcpListener l)
        {
            while (true) {
                TcpClient c = null; try { c = await l.AcceptTcpClientAsync().ConfigureAwait(false); } catch { if (CzRelay != l) return; }
                if (c == null) { await Task.Delay(100).ConfigureAwait(false); continue; }
                CzRelayConn(NoInherit(c));
            }
        }
        static async void CzRelayConn(TcpClient c)
        {
            TcpClient srv = null; bool counted = false;
            try {
                var ep = (IPEndPoint)c.Client.RemoteEndPoint; uint cip = IpH(ep.Address.GetAddressBytes(), 0);
                CzTcpFlow f; lock (CzLock) CzTcp.TryGetValue(((ulong)cip << 16) | (uint)ep.Port, out f);
                if (f == null) { Interlocked.Increment(ref CzRelayNoFlow); return; }
                c.NoDelay = true; var cl = CzC(cip); var cs = c.GetStream();
                // 1. первый пакет клиента — по нему видно имя сайта
                var hello = new byte[16384]; int fn = await CzReadFirst(cs, hello).ConfigureAwait(false);
                if (fn <= 0) return;
                string host = CzSni(hello, fn) ?? CzHttpHost(hello, fn);
                if (host == null) Interlocked.Increment(ref CzNoHost);
                string lists = host == null ? "" : CzWinwsCovers(host, f.Dst, f.DPort) ? "в списках zapret" : "нет в списках zapret";
                string target = IpS(f.Dst) + ":" + f.DPort + (host != null ? " (" + host + (lists.Length > 0 ? ", " + lists : "") + ")" : "");
                // 1б. видеосервер Google (rr…---sn-….googlevideo.com на адресе Google, а не кэш провайдера) — через zapret медленно:
                // эту пару клиент → адрес надолго через VPN и сбросить соединение — клиент сразу повторит, уже через VPN
                if (host != null && CzVideoVpn && CzIsVideoHost(host) && CzIsGoogle(f.Dst)) {
                    CzBypass[((ulong)cip << 32) | f.Dst] = DateTime.UtcNow.AddMinutes(CzVideoVpnMin); Interlocked.Increment(ref CzVideoToVpn);
                    if (CzVideoLogged.TryAdd(f.Dst, 0) && CzVideoLogged.Count <= 200)
                        Log("zapret для клиентов: " + ep.Address + " → " + target + " · видеосервер Google — через VPN (через zapret медленно), " + CzVideoVpnMin / 60 + " ч", "INFO");
                    try { c.Client.LingerState = new LingerOption(true, 0); } catch { }
                    return;
                }
                // 1в. сайт, который напрямую не работает (реклама doubleclick …), или имя, которое недавно уже не ответило на другом адресе, —
                // сразу через VPN, без ожидания (у рекламы Google каждый раз новый адрес, иначе каждый запрос ждал бы ~5 с)
                DateTime bh;
                if (host != null && (CzVpnHost(host) || (CzBadHost.TryGetValue(host, out bh) && bh > DateTime.UtcNow))) {
                    CzBypass[((ulong)cip << 32) | f.Dst] = DateTime.UtcNow.AddMinutes(Math.Max(CzBypassMin, 30)); Interlocked.Increment(ref CzHostToVpn);
                    try { c.Client.LingerState = new LingerOption(true, 0); } catch { }
                    return;
                }
                // 2. соединиться от имени ПК (через winws) и отправить его; сайт молчит — эту пару клиент → адрес пустить через VPN
                // адрес молчит — тот же сайт на другом адресе того же CDN (Google, Cloudflare … отдают любой свой сайт по имени):
                // на том, где недавно получилось, или из DNS; кроме видеосерверов googlevideo — у каждого свой адрес
                // кэш-сервер видео у провайдера (rr…---sn-… не на адресах Google): работает только напрямую — в VPN не уводить, ждать дольше
                bool ispCache = host != null && CzIsVideoHost(host) && !CzIsGoogle(f.Dst) && CzGoogle.Lo.Length > 0;
                var rb = new byte[32768]; int rn = 0; string fail = null; var cands = new List<uint> { f.Dst }; uint used = f.Dst; string altNote = "";
                KeyValuePair<uint, DateTime> rm;
                if (host != null && CzFamily(host) != null && CzRemap.TryGetValue(f.Dst, out rm) && rm.Value > DateTime.UtcNow) cands.Insert(0, rm.Key);   // этот адрес недавно молчал — сразу на рабочий
                for (int ai = 0; ai < cands.Count && ai < 2; ai++) {
                    uint dip = cands[ai]; fail = null; rn = 0;
                    if (srv != null) { try { srv.Close(); } catch { } srv = null; }
                    srv = await CzConnect(dip, f.DPort).ConfigureAwait(false);
                    if (srv == null) fail = "нет соединения";
                    else {
                        var s0 = srv.GetStream();
                        try { await s0.WriteAsync(hello, 0, fn).ConfigureAwait(false); } catch { fail = "ошибка отправки"; }
                        if (fail == null && host != null) {
                            var rd = s0.ReadAsync(rb, 0, rb.Length);
                            if (await Task.WhenAny(rd, Task.Delay(ai == 0 ? (ispCache ? Math.Max(CzFallbackMs, 8000) : CzFallbackMs) : 2000)).ConfigureAwait(false) == rd) {
                                try { rn = rd.Result; } catch { rn = 0; }
                                if (rn <= 0) fail = "сайт закрыл соединение";
                                else if (CzStubCert(host, rb, rn)) { fail = "сертификат открытым текстом (TLS 1.2) — похоже на заглушку провайдера"; Interlocked.Increment(ref CzStubs); }
                            }
                            else { CzObserve(rd); fail = "сайт молчит " + (ai == 0 ? (ispCache ? Math.Max(CzFallbackMs, 8000) : CzFallbackMs) / 1000.0 : 2) + " с"; }
                        }
                    }
                    if (fail == null) {
                        used = dip;
                        if (dip != f.Dst) { altNote = " · " + IpS(f.Dst) + " молчит — через zapret на " + IpS(dip); CzRemap[f.Dst] = new KeyValuePair<uint, DateTime>(dip, DateTime.UtcNow.AddMinutes(10)); }
                        break;
                    }
                    if (dip != f.Dst) { KeyValuePair<uint, DateTime> x; CzRemap.TryRemove(f.Dst, out x); }        // запасной перестал отвечать — забыть
                    if (host != null && f.DPort == 443 && !cands.Skip(ai + 1).Any()) foreach (var v in await CzAltIps(host, f.Dst).ConfigureAwait(false)) if (!cands.Contains(v)) cands.Add(v);
                }
                if (fail == null && host != null) CzRemember(host, used);
                if (fail != null) {
                    Interlocked.Increment(ref CzConnFail); Interlocked.Increment(ref cl.Fail);
                    // сразу после (пере)запуска winws обход DPI ещё не работает — такой сбой не повод уводить адрес в VPN
                    bool fresh = (DateTime.UtcNow - ZWinwsStartedAt).TotalSeconds < 30 || (DateTime.UtcNow - CzStartedAt).TotalSeconds < 30;
                    if (!fresh && !InetDown() && !ispCache) {
                        CzBypass[((ulong)cip << 32) | f.Dst] = DateTime.UtcNow.AddMinutes(CzBypassMin); Interlocked.Increment(ref CzBypassAdded);
                        if (host != null && !CzIsVideoHost(host) && lists != "в списках zapret") CzBadHost[host] = DateTime.UtcNow.AddMinutes(30);    // не из списков zapret: то же имя на других адресах — сразу через VPN
                    }
                    if (Interlocked.Increment(ref cl.FailLogged) <= 60) Log("zapret для клиентов: " + ep.Address + ":" + ep.Port + " → " + target + " · через zapret: " + fail + (cands.Count > 1 ? " (и на запасном " + IpS(cands[1]) + ")" : "") + (ispCache ? " — кэш провайдера, через VPN он не работает: клиент повторит через zapret" : fresh ? " (zapret только что запущен — обход не включаю)" : " — следующие соединения к " + IpS(f.Dst) + " " + CzBypassMin + " мин пойдут через VPN"), "INFO");
                    try { c.Client.LingerState = new LingerOption(true, 0); } catch { }   // сброс — клиент сразу повторит, уже через VPN
                    return;
                }
                Interlocked.Increment(ref CzTcpConns); Interlocked.Increment(ref CzActive); Interlocked.Increment(ref cl.Conns); counted = true;
                Interlocked.Add(ref CzBytes, fn + rn); Interlocked.Add(ref CzTcpUp, fn); Interlocked.Add(ref cl.Up, fn); Interlocked.Add(ref CzTcpDown, rn); Interlocked.Add(ref cl.Down, rn);
                var ss = srv.GetStream();
                if (rn > 0) await cs.WriteAsync(rb, 0, rn).ConfigureAwait(false);
                f.Last = DateTime.UtcNow;
                // 3. дальше — в обе стороны
                var t0 = DateTime.UtcNow; string closed = null; var sv = srv;
                var up = CzPump(cs, ss, f, true, cl).ContinueWith(t => { if (closed == null) closed = "клиент"; try { sv.Client.Shutdown(SocketShutdown.Send); } catch { } return t.Result; });
                long down = rn + await CzPump(ss, cs, f, false, cl).ConfigureAwait(false);
                if (closed == null) closed = "сайт"; try { c.Client.Shutdown(SocketShutdown.Send); } catch { }
                await Task.WhenAny(up, Task.Delay(60000)).ConfigureAwait(false);
                if (Interlocked.Increment(ref cl.Logged) <= 8)
                    Log("zapret для клиентов: " + ep.Address + ":" + ep.Port + " → " + target + altNote + " · к сайту " + (fn + (up.IsCompleted ? up.Result : 0)) + " Б, к клиенту " + down + " Б, " +
                        Math.Round((DateTime.UtcNow - t0).TotalSeconds, 1) + " с, первым закрыл " + closed, "INFO");
            } catch { }
            finally {
                if (counted && Interlocked.Decrement(ref CzActive) < 0) Interlocked.Exchange(ref CzActive, 0);
                if (srv != null) { try { srv.Close(); } catch { } } try { c.Close(); } catch { }
            }
        }
        static async Task<long> CzPump(Stream a, Stream b, CzTcpFlow f, bool up, CzCli cl)
        {
            var bb = new byte[32768]; long total = 0;
            try {
                int n;
                while ((n = await a.ReadAsync(bb, 0, bb.Length).ConfigureAwait(false)) > 0) {
                    await b.WriteAsync(bb, 0, n).ConfigureAwait(false); total += n;
                    Interlocked.Add(ref CzBytes, n);
                    if (up) { Interlocked.Add(ref CzTcpUp, n); Interlocked.Add(ref cl.Up, n); } else { Interlocked.Add(ref CzTcpDown, n); Interlocked.Add(ref cl.Down, n); }
                    f.Last = DateTime.UtcNow;
                }
            } catch { }
            return total;
        }

        // ---------------------------------------------------------------- состояние
        static Dictionary<string, object> CzSnapshot()
        {
            int tcpN, udpN; lock (CzLock) { tcpN = CzTcp.Count; udpN = CzUdp.Count; }
            return new Dictionary<string, object> { { "enabled", CzWanted() }, { "running", CzFwd != WdInvalid }, { "error", CzError },
                { "packets", Interlocked.Read(ref CzPkts) }, { "passed", Interlocked.Read(ref CzPass) }, { "tcpConns", Interlocked.Read(ref CzTcpConns) }, { "active", CzActive },
                { "tcpFlows", tcpN }, { "udpFlows", udpN }, { "udpPackets", Interlocked.Read(ref CzUdpPkts) }, { "mb", Math.Round(Interlocked.Read(ref CzBytes) / 1048576.0, 1) },
                { "errors", Interlocked.Read(ref CzErrors) }, { "relay", CzFwd != WdInvalid ? IpS(CzWgIp) + ":" + CzRelayPort : "" }, { "ifWg", CzWgIdx }, { "ifEth", CzEthIdx },
                { "ranges", CzSet.Lo.Length }, { "bypass", CzBypass.Count }, { "remap", CzRemap.Count }, { "videoVpn", Interlocked.Read(ref CzVideoToVpn) }, { "quicRejected", Interlocked.Read(ref CzIcmpSent) }, { "hostVpn", Interlocked.Read(ref CzHostToVpn) }, { "badHosts", CzBadHost.Count }, { "stubs", Interlocked.Read(ref CzStubs) }, { "bypassAdded", Interlocked.Read(ref CzBypassAdded) }, { "bypassPkts", Interlocked.Read(ref CzBypassPkts) },
                { "noHost", Interlocked.Read(ref CzNoHost) }, { "winwsProfiles", CzProfs.Count }, { "rate", CzRates() },
                { "tcpUpKb", Interlocked.Read(ref CzTcpUp) / 1024 }, { "tcpDownKb", Interlocked.Read(ref CzTcpDown) / 1024 }, { "udpDownKb", Interlocked.Read(ref CzUdpDown) / 1024 },
                { "udpSendFail", Interlocked.Read(ref CzUdpSendFail) }, { "quicDropped", Interlocked.Read(ref CzQuicDrop) }, { "netRewritten", Interlocked.Read(ref CzNetRw) },
                { "netNoFlow", Interlocked.Read(ref CzNetMiss) }, { "sendFail", Interlocked.Read(ref CzNetSendFail) },
                { "relayNoFlow", Interlocked.Read(ref CzRelayNoFlow) }, { "connFail", Interlocked.Read(ref CzConnFail) }, { "leakDropped", Interlocked.Read(ref CzLeakDrop) },
                { "mssClamped", Interlocked.Read(ref CzMssClamped) }, { "dropBadSum", Interlocked.Read(ref CzDropSum) }, { "dropMd5", Interlocked.Read(ref CzDropMd5) },
                { "dropTtl", Interlocked.Read(ref CzDropTtl) }, { "dropTs", Interlocked.Read(ref CzDropTs) }, { "dropNoAck", Interlocked.Read(ref CzDropNoAck) } };
        }
        static string CzSummary()
        {
            if (!CzWanted()) return "выключен (вкладка WG-Server)";
            if (CzFwd == WdInvalid) return "не работает" + (CzError.Length > 0 ? ": " + CzError : "");
            int tcpN, udpN; lock (CzLock) { tcpN = CzTcp.Count; udpN = CzUdp.Count; }
            return "работает · TCP-соединений через zapret " + Interlocked.Read(ref CzTcpConns) + " (сейчас " + CzActive + "), UDP-потоков " + udpN + " · " +
                Math.Round(Interlocked.Read(ref CzBytes) / 1048576.0, 1) + " МБ · перехвачено пакетов " + Interlocked.Read(ref CzPkts) + (Interlocked.Read(ref CzErrors) > 0 ? ", ошибок " + Interlocked.Read(ref CzErrors) : "");
        }

        // ---------------------------------------------------------------- отключение клиентов WG-Server (ws4w.clientOff — список IP)
        // Конфиг сервера не меняется (его ведёт и WS4W): отключённый клиент просто убирается из работающего туннеля
        // («wg set … peer … remove») и возвращается из конфига, когда его включат. После перезапуска туннеля агент снова уберёт его.
        class WcPeer { public string Key, Ip, Psk, Allowed; public int Keepalive; }
        static DateTime WcAt = DateTime.MinValue; static string WcErr = "", WcSig = ""; static readonly Dictionary<string, int> WcTries = new Dictionary<string, int>();
        static string WgExe() { return Path.Combine(Path.GetDirectoryName(CfgStr("ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe")), "wg.exe"); }
        static HashSet<string> WcOff() { return new HashSet<string>(CfgList("ws4w.clientOff", new string[0]).Select(x => x.Trim())); }
        static List<WcPeer> WgConfPeers()
        {
            var conf = WgConf(); if (conf == null || !conf.EndsWith(".conf")) return null;
            var res = new List<WcPeer>(); WcPeer cur = null;
            foreach (var l in File.ReadAllLines(conf)) {
                var h = Regex.Match(l, @"^\s*\[(\w+)\]");
                if (h.Success) { cur = h.Groups[1].Value.Equals("Peer", StringComparison.OrdinalIgnoreCase) ? new WcPeer() : null; if (cur != null) res.Add(cur); continue; }
                var m = Regex.Match(l, @"^\s*(\w+)\s*=\s*(.*?)\s*$"); if (cur == null || !m.Success) continue;
                string k = m.Groups[1].Value.ToLowerInvariant(), v = m.Groups[2].Value;
                if (k == "publickey") cur.Key = v; else if (k == "presharedkey") cur.Psk = v;
                else if (k == "allowedips") { cur.Allowed = Regex.Replace(v, @"\s+", ""); cur.Ip = Regex.Replace(cur.Allowed.Split(',')[0], @"/\d+$", ""); }
                else if (k == "persistentkeepalive") int.TryParse(v, out cur.Keepalive);
            }
            return res.Where(p => p.Key != null && p.Ip != null).ToList();
        }
        static void WgClientsWatch()
        {
            // wg.exe — раз в минуту или сразу, когда список отключённых изменился
            var offSig = string.Join(",", WcOff().OrderBy(x => x)); if (offSig == WcSig && (DateTime.UtcNow - WcAt).TotalSeconds < 60) return; WcAt = DateTime.UtcNow; WcSig = offSig;
            var svc = Svc(CfgStr("ws4w.serviceName", "WireGuardTunnel$wg_server")); if (svc == null || svc.Status != System.ServiceProcess.ServiceControllerStatus.Running) return;
            string wg = WgExe(); if (!File.Exists(wg)) return;
            List<WcPeer> conf; try { conf = WgConfPeers(); } catch { return; } if (conf == null) return;
            var off = WcOff();
            var r = Exe(wg, "show " + WgIf() + " peers", 5); if (r.Code != 0) return;
            var live = new HashSet<string>(r.Out.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()));
            string err = "";
            foreach (var p in conf) {
                string nm; if (!PeerNamesByKey.TryGetValue(p.Key, out nm)) nm = p.Ip;
                if (off.Contains(p.Ip) && live.Contains(p.Key)) {
                    var x = Exe(wg, "set " + WgIf() + " peer " + p.Key + " remove", 10);
                    if (x.Code == 0) Log("WG-Server: клиент «" + nm + "» (" + p.Ip + ") отключён", "WARN"); else err = "не удалось отключить " + p.Ip + ": " + x.Err.Trim();
                } else if (live.Contains(p.Key)) WcTries.Remove(p.Key);
                else if (!off.Contains(p.Ip)) {
                    // включили обратно (или убрали вручную) — вернуть из конфига. Туннель может такого клиента не принимать
                    // (например, ключ совпадает с ключом сервера) — тогда после двух попыток больше не пытаться
                    int tries; WcTries.TryGetValue(p.Key, out tries);
                    if (tries >= 2) { if (tries == 2) { WcTries[p.Key] = 3; Log("WG-Server: туннель не принимает клиента «" + nm + "» (" + p.Ip + ") из конфига: после добавления он снова пропадает. Больше не пытаюсь — проверьте клиента в WS4W или пересоздайте его", "WARN"); } continue; }
                    WcTries[p.Key] = tries + 1;
                    string tmp = null;
                    try {
                        string a = "set " + WgIf() + " peer " + p.Key + " allowed-ips " + (p.Allowed ?? p.Ip + "/32");
                        if (!string.IsNullOrEmpty(p.Psk)) { tmp = Path.Combine(Path.GetTempPath(), "vg-psk-" + Guid.NewGuid().ToString("N") + ".txt"); File.WriteAllText(tmp, p.Psk); a += " preshared-key \"" + tmp + "\""; }
                        if (p.Keepalive > 0) a += " persistent-keepalive " + p.Keepalive;
                        var x = Exe(wg, a, 10);
                        if (x.Code == 0) Log("WG-Server: клиент «" + nm + "» (" + p.Ip + ") включён", "INFO"); else err = "не удалось включить " + p.Ip + ": " + x.Err.Trim();
                    } finally { if (tmp != null) try { File.Delete(tmp); } catch { } }
                }
            }
            if (err != WcErr) { if (err.Length > 0) Log("WG-Server: " + err, "ERROR"); WcErr = err; }
        }
        // отключённые клиенты (их нет в «wg show») — для списка в окне
        static IEnumerable<Dictionary<string, object>> WgOffPeers(HashSet<string> shownIps)
        {
            var off = WcOff(); if (off.Count == 0) yield break;
            List<WcPeer> conf = null; try { conf = WgConfPeers(); } catch { }
            if (conf == null) yield break;
            foreach (var p in conf) {
                if (!off.Contains(p.Ip) || shownIps.Contains(p.Ip)) continue;
                string nm; if (!PeerNamesByKey.TryGetValue(p.Key, out nm) && !PeerNamesByIp.TryGetValue(p.Ip, out nm)) nm = p.Ip;
                yield return new Dictionary<string, object> { { "name", nm }, { "key", p.Key.Substring(0, Math.Min(8, p.Key.Length)) }, { "ip", p.Ip }, { "endpoint", "" }, { "hsAgo", -1 }, { "active", false }, { "rx", 0 }, { "tx", 0 }, { "off", true }, { "zapret", CzClientZapret(p.Ip) } };
            }
        }
    }
}
