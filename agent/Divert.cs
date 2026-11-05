// WinDivert: вызовы драйвера, адреса IPv4, контрольные суммы пакетов (общее для ретранслятора и учёта локальной сети).
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
    }
}
