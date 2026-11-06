// VpnGuard — агент на C#: zapret и для клиентов WG-Server (wg.clientZapret), разделение по IP, прозрачно.
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

        // ---------------------------------------------------------------- состояние
        class CzTcpFlow { public uint Dst; public int DPort; public DateTime Last, Syn = DateTime.UtcNow; public int SynTtl; public uint MaxTs; public bool HasTs; }
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
        static HashSet<uint> CzRescue = new HashSet<uint>(); static string CzPhysIp;
        static uint CzWgIp; static int CzWgIdx, CzEthIdx; static string CzSig = "", CzError = "";
        static long CzPkts, CzPass, CzTcpConns, CzUdpPkts, CzBytes, CzErrors, CzTcpUp, CzTcpDown, CzUdpDown, CzUdpSendFail, CzQuicDrop, CzNetRw, CzNetMiss, CzNetSendFail,
            CzRelayNoFlow, CzConnFail, CzMssClamped, CzDropSum, CzDropMd5, CzDropTtl, CzDropTs, CzDropNoAck, CzSumChecked, CzLeakDrop;
        static volatile bool CzSumOff, CzQuicRelay; static int CzActive, CzMss = 1200;
        static volatile CzRanges CzSet = new CzRanges(); static string CzSetKey = "";
        static DateTime CzFwAt = DateTime.MinValue, CzCleanAt = DateTime.MinValue; static string CzFwSig = "";
        // по клиентам: кому zapret не нужен (wg.clientNoZapret — их трафик целиком через VPN, как без этой функции) и счётчики
        class CzCli { public long Pkts, ZPkts, Conns, Up, Down, Quic, Fail, Leak; public int Logged, FailLogged; public DateTime LastZ = DateTime.MinValue; }
        static readonly ConcurrentDictionary<uint, CzCli> CzClients = new ConcurrentDictionary<uint, CzCli>();
        static readonly Func<uint, CzCli> CzNewCli = k => new CzCli();
        static volatile HashSet<uint> CzNoZ = new HashSet<uint>();
        static CzCli CzC(uint ip) { return CzClients.GetOrAdd(ip, CzNewCli); }
        static void CzUpdateNoZ()
        {
            var s = new HashSet<uint>(); IPAddress a;
            foreach (var x in CfgList("wg.clientNoZapret", new string[0]).Concat(CfgList("wg.clientOff", new string[0])))
                if (IPAddress.TryParse(x.Trim(), out a) && a.AddressFamily == AddressFamily.InterNetwork) s.Add(IpH(a.GetAddressBytes(), 0));
            if (!s.SetEquals(CzNoZ)) {
                var was = CzNoZ; CzNoZ = s;
                foreach (var v in s.Except(was)) Log("zapret для клиентов: " + IpS(v) + " — без zapret, весь трафик через VPN", "INFO");
                foreach (var v in was.Except(s)) Log("zapret для клиентов: " + IpS(v) + " — снова через zapret", "INFO");
            }
        }
        static bool CzClientZapret(string ip) { return !CfgList("wg.clientNoZapret", new string[0]).Any(x => x.Trim() == ip); }
        static Dictionary<string, object> CzClientStat(string ip)
        {
            IPAddress a; CzCli c; if (!IPAddress.TryParse(ip, out a) || !CzClients.TryGetValue(IpH(a.GetAddressBytes(), 0), out c)) return null;
            return new Dictionary<string, object> { { "pkts", Interlocked.Read(ref c.Pkts) }, { "zPkts", Interlocked.Read(ref c.ZPkts) }, { "conns", Interlocked.Read(ref c.Conns) },
                { "upKb", Interlocked.Read(ref c.Up) / 1024 }, { "downKb", Interlocked.Read(ref c.Down) / 1024 }, { "quic", Interlocked.Read(ref c.Quic) }, { "fail", Interlocked.Read(ref c.Fail) },
                { "leak", Interlocked.Read(ref c.Leak) }, { "vpn", Interlocked.Read(ref c.Fail) }, { "rate", RateOf("cz:" + ip, Interlocked.Read(ref c.Down), Interlocked.Read(ref c.Up)) }, { "lastAgo", c.LastZ == DateTime.MinValue ? -1 : (long)(DateTime.UtcNow - c.LastZ).TotalSeconds } };
        }

        // ретранслятор (через zapret): [↓, ↑], байт/с
        static long[] CzRates() { return RateOf("cz", Interlocked.Read(ref CzTcpDown), Interlocked.Read(ref CzTcpUp)); }
        static bool CzWanted() { return CfgBool("wg.clientZapret", false); }

        // адреса zapret для ретранслятора: с VPN — маршруты мимо VPN, без VPN — тот же список без маршрутов
        static List<string> CzPrefixes() { return ZDirect() ? ZArr("relaySet").Select(x => Convert.ToString(x)).ToList() : ZRoutes().Select(r => JS(r, "p")).ToList(); }
        static void ClientZapretWatch()
        {
            string why = null;
            if (!CzWanted()) why = "off";
            else if (CzPrefixes().Count == 0) why = ZDirect() ? "список адресов zapret ещё не готов" : "zapret не включён (нет маршрутов мимо VPN)";
            string wgIp = WgIp(); var phys = why == null ? ZPhys() : null;
            if (why == null && wgIp == null) why = "адаптер " + WgIf() + " без адреса";
            if (why == null && phys == null) why = "нет физического выхода в интернет";
            string dll = Path.Combine(ZDir(), "bin", "WinDivert.dll");
            if (why == null && !File.Exists(dll)) why = "нет " + dll + " (zapret не установлен?)";
            if (why != null) {
                if (CzFwd != WdInvalid) { CzStop(); Log("zapret для клиентов WG-Server: остановлен" + (why == "off" ? "" : " — " + why), "INFO"); }
                CzError = why == "off" ? "" : why; return;
            }
            CzUpdateSet(); CzUpdateNoZ();
            CzQuicRelay = CfgStr("wg.clientQuic", "drop") == "relay"; CzQuicReject = CfgBool("wg.clientQuicReject", true); CzMss = Math.Max(536, CfgInt("wg.clientMss", 1200));
            CzFallbackMs = Math.Max(1500, CfgInt("wg.clientFallbackMs", 3000)); CzBypassMin = Math.Max(1, CfgInt("wg.clientBypassMin", 5));
            CzVpnHosts = CfgList("wg.clientVpnHosts", new[] { "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com" }).Select(x => x.Trim().TrimStart('.')).Where(x => x.Length > 0).ToArray();
            CzVideoVpn = CfgBool("wg.clientVideoVpn", true); CzVideoVpnMin = Math.Max(10, CfgInt("wg.clientVideoVpnMin", 360));
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
            Log("zapret для клиентов WG-Server: включён — трафик клиентов к адресам zapret (" + CzPrefixes().Count + (ZDirect() ? " адресов) идёт через zapret этого ПК, остальное — напрямую" : " маршрутов) идёт через zapret этого ПК, остальное — через VPN") + " (" + phys.Alias + ", ретранслятор " + wgIp + ":" + CzRelayPort + ")", "WARN");
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
            var routes = CzPrefixes().Select(p => new Dictionary<string, object> { { "p", p } }).ToList(); var resc = RescueActive;
            var key = ZDirect() + "|" + routes.Count + "|" + ZS("lastRouteRefresh") + "|" + ZS("relaySetAt") + "|" + resc.Length;
            if (key == CzSetKey) return;
            var rs = new List<KeyValuePair<uint, uint>>(); var rset = new HashSet<uint>();
            foreach (var p in resc) { try { rset.Add(IpH(p.Split('/')[0])); } catch { } }
            CzRescue = rset; try { var ph = ZPhys(); CzPhysIp = ph != null ? ph.Ip : null; } catch { }
            foreach (var p in resc) routes.Add(new Dictionary<string, object> { { "p", p } });
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
            PerfThread("ретранслятор: " + (Thread.CurrentThread.Name ?? "?"));
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
            if (CzBypassed(src, dst) && !CzIsRelayFlow(src, b[o + ihl] << 8 | b[o + ihl + 1], dst, proto == 6 && (b[o + ihl + 13] & 0x02) != 0)) { Interlocked.Increment(ref CzBypassPkts); Interlocked.Increment(ref CzPass); if (proto == 6 && (b[o + ihl + 13] & 0x02) != 0) CzDbgPkt(src, dst, (b[o + ihl + 2] << 8) | b[o + ihl + 3], "через VPN (обход)"); return false; }
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
                if (dport == 443 && !CzQuicRelay) { Interlocked.Increment(ref CzQuicDrop); Interlocked.Increment(ref cl.Quic); CzIcmpUnreach(b, o, ihl, n); CzDbgPkt(src, dst, dport, "QUIC отклонён (ICMP)"); return true; }
                var key = new CzUdpKey { A = ((ulong)src << 16) | (uint)sport, B = ((ulong)dst << 16) | (uint)dport }; CzUdpFlow f;
                lock (CzLock) {
                    if (!CzUdp.TryGetValue(key, out f)) {
                        var s = NoInherit(new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp));
                        // аварийный DNS (туннели не работают): от адреса физического адаптера — мимо VPN без системных маршрутов
                        if (CzRescue.Contains(dst) && CzPhysIp != null) { try { s.Bind(new IPEndPoint(IPAddress.Parse(CzPhysIp), 0)); } catch { } }
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
        static long CzIcmpSent, CzDbgN;
        // подробный журнал ретранслятора — первый час после запуска агента (не больше 1500 строк)
        static bool CzDbg() { return CfgBool("wg.clientDebug", true) && (DateTime.UtcNow - CzStartedAt).TotalMinutes < 60 && Interlocked.Increment(ref CzDbgN) <= 1500; }
        static readonly ConcurrentDictionary<ulong, DateTime> CzDbgSeen = new ConcurrentDictionary<ulong, DateTime>();
        // UDP/QUIC и обход через VPN не проходят через ретранслятор — записать раз в минуту на пару клиент → адрес
        static void CzDbgPkt(uint src, uint dst, int dport, string what)
        {
            if (!CfgBool("wg.clientDebug", true) || (DateTime.UtcNow - CzStartedAt).TotalMinutes >= 60) return;
            ulong k = ((ulong)src << 32) | dst; DateTime t;
            if (CzDbgSeen.TryGetValue(k, out t) && (DateTime.UtcNow - t).TotalSeconds < 60) return;
            CzDbgSeen[k] = DateTime.UtcNow;
            if (CzDbg()) ThreadPool.QueueUserWorkItem(_ => Log("zapret для клиентов [подробно]: " + IpS(src) + " → " + IpS(dst) + ":" + dport + " · " + what, "INFO"));
        }
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


        // ---------------------------------------------------------------- состояние
        static Dictionary<string, object> CzSnapshot()
        {
            int tcpN, udpN; lock (CzLock) { tcpN = CzTcp.Count; udpN = CzUdp.Count; }
            return new Dictionary<string, object> { { "enabled", CzWanted() }, { "running", CzFwd != WdInvalid }, { "error", CzError },
                { "packets", Interlocked.Read(ref CzPkts) }, { "passed", Interlocked.Read(ref CzPass) }, { "tcpConns", Interlocked.Read(ref CzTcpConns) }, { "active", CzActive },
                { "tcpFlows", tcpN }, { "udpFlows", udpN }, { "udpPackets", Interlocked.Read(ref CzUdpPkts) }, { "mb", Math.Round(Interlocked.Read(ref CzBytes) / 1048576.0, 1) },
                { "errors", Interlocked.Read(ref CzErrors) }, { "relay", CzFwd != WdInvalid ? IpS(CzWgIp) + ":" + CzRelayPort : "" }, { "ifWg", CzWgIdx }, { "ifEth", CzEthIdx },
                { "ranges", CzSet.Lo.Length }, { "bypass", CzBypass.Count }, { "remap", CzRemap.Count }, { "videoVpn", Interlocked.Read(ref CzVideoToVpn) }, { "quicRejected", Interlocked.Read(ref CzIcmpSent) }, { "connRetryWins", Interlocked.Read(ref CzConnRetryWin) }, { "spread", Interlocked.Read(ref CzSpreadN) }, { "hostVpn", Interlocked.Read(ref CzHostToVpn) }, { "badHosts", CzBadHost.Count }, { "stubs", Interlocked.Read(ref CzStubs) }, { "bypassAdded", Interlocked.Read(ref CzBypassAdded) }, { "bypassPkts", Interlocked.Read(ref CzBypassPkts) },
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
    }
}
