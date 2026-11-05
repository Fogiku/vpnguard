// Учёт локальной сети: сколько трафика ПК идёт в домашнюю сеть, а не в интернет (WinDivert только смотрит).
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
        // ---------------------------------------------------------------- локальная сеть: сколько трафика ПК идёт в домашнюю сеть, а не в интернет
        // WinDivert только смотрит (SNIFF | RECV_ONLY, трафик не задерживается): пакеты физического адаптера, у которых и отправитель,
        // и получатель — частные адреса (или групповые/широковещательные). UDP-порт wg_server не считается: это интернет клиентов WG
        // (роутер пробрасывает их с адреса 192.168.x.1). Выключается в настройках: traffic.lanMeter = false
        static IntPtr LanH = WdInvalid; static string LanSig = "", LanError = "", LanNet = ""; static long LanRx, LanTx;
        static int LanWgPort = -1; static DateTime LanWgPortAt = DateTime.MinValue;
        static void LanWatch()
        {
            string why = null, dll = Path.Combine(ZDir(), "bin", "WinDivert.dll");
            if (!CfgBool("traffic.lanMeter", true)) why = "off";
            else if (!File.Exists(dll)) why = "нет WinDivert.dll (zapret не установлен)";
            var phys = why == null ? ZPhys() : null;
            if (why == null && phys == null) why = "нет физического выхода";
            uint ip = 0, mask = 0;
            if (why == null) {
                try {
                    var ua = Nic(phys.Alias).GetIPProperties().UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork && a.Address.ToString() == phys.Ip);
                    ip = IpH(phys.Ip); mask = ua != null && ua.IPv4Mask != null ? IpH(ua.IPv4Mask.GetAddressBytes(), 0) : 0xFFFFFF00;
                } catch { why = "нет адреса у " + phys.Alias; }
            }
            if (why != null) { LanClose(); LanError = why == "off" ? "" : why; LanNet = ""; return; }
            if (mask < 0xFFFF0000) mask = 0xFFFF0000;                        // сеть шире /16 — считаем только свою /16
            uint lo = ip & mask, hi = lo | ~mask; int bits = 0; for (uint m = mask; m != 0; m <<= 1) bits++;
            int port = LanWgListenPort();
            string sig = phys.IfIndex + "|" + IpS(lo) + "|" + IpS(hi) + "|" + port;
            if (LanH != WdInvalid && sig == LanSig) return;
            LanClose();
            if (!WdLoaded) { if (LoadLibrary(dll) == IntPtr.Zero) { LanError = "не загрузился " + dll; return; } WdLoaded = true; }
            // локальные — все частные адреса (в доме бывает несколько подсетей за роутером: 192.168.1.x, 192.168.100.x …)
            Func<string, string> priv = fld => "((" + fld + " >= 10.0.0.0 and " + fld + " <= 10.255.255.255) or (" + fld + " >= 172.16.0.0 and " + fld + " <= 172.31.255.255) or (" +
                fld + " >= 192.168.0.0 and " + fld + " <= 192.168.255.255) or (" + fld + " >= 169.254.0.0 and " + fld + " <= 169.254.255.255)";
            string f = "ifIdx == " + phys.IfIndex + " and ip and " + priv("ip.SrcAddr") + ") and " + priv("ip.DstAddr") + " or ip.DstAddr >= 224.0.0.0)" +
                (port > 0 ? " and (not udp or (udp.SrcPort != " + port + " and udp.DstPort != " + port + "))" : "");
            var h = WinDivertOpen(f, WdLayerNetwork, 1000, 1 | 4);
            if (h == WdInvalid || h == IntPtr.Zero) { LanError = "WinDivert: код " + Marshal.GetLastWin32Error(); return; }
            LanH = h; LanSig = sig; LanError = ""; LanNet = IpS(lo) + "/" + bits + " и др. частные адреса";
            new Thread(() => LanLoop(h)) { IsBackground = true, Name = "lan" }.Start();
            Log("Локальная сеть: учёт трафика " + LanNet + " через " + phys.Alias + " включён (отдельно от интернета)", "INFO");
        }
        static int LanWgListenPort()
        {
            if (LanWgPort >= 0 && (DateTime.UtcNow - LanWgPortAt).TotalMinutes < 10) return LanWgPort;
            LanWgPortAt = DateTime.UtcNow; int p = 0;
            try {
                var wg = Path.Combine(Path.GetDirectoryName(CfgStr("ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe")), "wg.exe");
                var r = File.Exists(wg) ? Exe(wg, "show " + WgIf() + " listen-port", 5) : null;
                if (r != null && r.Code == 0) int.TryParse(r.Out.Trim(), out p);
            } catch { }
            if (p > 0 || LanWgPort < 0) LanWgPort = p;
            return LanWgPort;
        }
        static void LanLoop(IntPtr h)
        {
            PerfThread("учёт локальной сети");
            var buf = new byte[1 << 19]; var addrs = new WdAddr[64];
            while (LanH == h) {
                uint n, al = (uint)(addrs.Length * WdAddrSize);
                if (!WinDivertRecvEx(h, buf, (uint)buf.Length, out n, 0, addrs, ref al, IntPtr.Zero)) { if (LanH != h) break; Thread.Sleep(200); continue; }
                int cnt = (int)(al / WdAddrSize), o = 0;
                for (int i = 0; i < cnt && o + 20 <= n; i++) {
                    int len = (buf[o + 2] << 8) | buf[o + 3]; if (len < 20 || o + len > n) len = (int)n - o;
                    if ((addrs[i].Flags & WdOutbound) != 0) Interlocked.Add(ref LanTx, len); else Interlocked.Add(ref LanRx, len);
                    o += len;
                }
            }
        }
        static void LanClose()
        {
            var h = LanH; LanH = WdInvalid; LanSig = "";
            if (h != WdInvalid) { try { WinDivertClose(h); } catch { } }
        }
        static long[] LanRate(string key) { return LanH != WdInvalid ? RateOf(key, Interlocked.Read(ref LanRx), Interlocked.Read(ref LanTx)) : new long[2]; }
    }
}
