// Сеть: HTTP (GitHub, gstatic), таблица маршрутов Windows, физический выход в интернет.
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
                var nics = AllNics().Where(n => n.OperationalStatus == OperationalStatus.Up && !IsTunnel(n.Name)).ToList();
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
    }
}
