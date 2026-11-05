// Диагностика туннеля: может ли он пропускать трафик и где обрыв.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32;


namespace VpnGuard
{
    public static partial class Agent
    {
        // ---------------------------------------------------------------- диагностика туннеля: может ли он в принципе пропускать трафик и где обрыв
        // Шлём через адаптер туннеля (адрес источника — его) TCP к нескольким узлам и DNS-запрос и смотрим счётчики адаптера:
        //  отправлено 0      — Windows не кладёт пакеты в туннель (адаптер/маршруты/приложение);
        //  отправлено, 0 пришло — пакеты уходят, сервер VPN не отвечает (сервер лежит, его блокирует провайдер, ключ/подписка не принимаются);
        //  пришло, но сайты не открываются — сервер отвечает, но дальше в интернет не выпускает (нет выхода/DNS на сервере).
        class TunDiagRes { public bool Ok; public string Short = "", Text = ""; public long Tx, Rx; public int TcpOk, TcpAll; public bool Dns; public DateTime At = DateTime.Now; }
        static TunDiagRes TunDiag(string name)
        {
            var r = new TunDiagRes();
            var nic = Nic(name);
            if (nic == null) { r.Short = "адаптера нет"; r.Text = "адаптер туннеля не найден — туннель не подключён"; return r; }
            if (nic.OperationalStatus != OperationalStatus.Up) { r.Short = "адаптер не поднят"; r.Text = "адаптер «" + name + "» есть, но не поднят (" + nic.OperationalStatus + ") — туннель не подключён"; return r; }
            string ip = Ipv4(name);
            if (ip == null) { r.Short = "нет адреса"; r.Text = "у адаптера «" + name + "» нет IPv4-адреса — приложение не настроило туннель"; return r; }
            Func<long[]> st = () => { try { var x = Nic(name).GetIPStatistics(); return new[] { x.BytesSent, x.BytesReceived }; } catch { return new long[2]; } };
            var a = st();
            var hosts = CfgList("vpn.diagHosts", new[] { "1.1.1.1:443", "8.8.8.8:443", "77.88.8.8:443", "9.9.9.9:443" });
            r.TcpAll = hosts.Length; int ok = 0;
            var ts = hosts.Select(h => System.Threading.Tasks.Task.Run(() => { if (TcpVia(ip, h, 5000)) Interlocked.Increment(ref ok); })).ToArray();
            try {                                                         // DNS-запрос «google.com A» к 8.8.8.8 через туннель
                using (var u = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)) {
                    u.Bind(new IPEndPoint(IPAddress.Parse(ip), 0)); u.ReceiveTimeout = 4000;
                    var q = new byte[] { 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, (byte)'g', (byte)'o', (byte)'o', (byte)'g', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0, 0, 1, 0, 1 };
                    u.SendTo(q, new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53));
                    var buf = new byte[512]; EndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                    r.Dns = u.ReceiveFrom(buf, ref ep) > 12 && buf[0] == 0x12 && buf[1] == 0x34;
                }
            } catch { }
            System.Threading.Tasks.Task.WaitAll(ts, 7000);
            var b = st(); r.Tx = Math.Max(0, b[0] - a[0]); r.Rx = Math.Max(0, b[1] - a[1]); r.TcpOk = ok;
            string cnt = " (через адаптер ушло " + r.Tx + " Б, пришло " + r.Rx + " Б; сайтов открылось " + ok + "/" + r.TcpAll + ", DNS " + (r.Dns ? "работает" : "не отвечает") + ")";
            if (ok > 0) { r.Ok = true; r.Short = "трафик проходит"; r.Text = "туннель пропускает трафик" + cnt; }
            else if (r.Tx < 100) { r.Short = "пакеты не уходят в туннель"; r.Text = "Windows не отправляет пакеты в туннель — адаптер или маршруты настроены не так, либо приложение VPN не обрабатывает трафик" + cnt; }
            else if (r.Rx < 40) { r.Short = "сервер VPN не отвечает"; r.Text = "пакеты уходят в туннель, но от сервера VPN ничего не приходит — сервер недоступен, его блокирует провайдер или он не принимает подключение (ключ, подписка, протокол)" + cnt; }
            else if (r.Dns) { r.Short = "DNS есть, сайты нет"; r.Text = "сервер VPN отвечает и DNS работает, но соединения с сайтами не проходят — сервер не выпускает TCP в интернет" + cnt; }
            else { r.Short = "сервер без выхода в интернет"; r.Text = "сервер VPN отвечает, но дальше в интернет не выпускает — на сервере нет выхода или DNS" + cnt; }
            return r;
        }

        // хотя бы один узел открывается через адрес ip — все сразу, ответ по первому успеху (не дольше timeoutMs)
        static bool AnyVia(string ip, string[] hosts, int timeoutMs)
        {
            if (ip == null || hosts.Length == 0) return false;
            using (var done = new ManualResetEvent(false)) {
                int left = hosts.Length, ok = 0;
                foreach (var h in hosts) {
                    var hh = h;
                    ThreadPool.QueueUserWorkItem(_ => {
                        bool r = TcpVia(ip, hh, timeoutMs);
                        if (r) Interlocked.Exchange(ref ok, 1);
                        if (r || Interlocked.Decrement(ref left) == 0) { try { done.Set(); } catch { } }
                    });
                }
                done.WaitOne(timeoutMs + 1500);
                return ok == 1;
            }
        }
        static bool ProbeVia(string adapter, int timeoutMs, List<long> times)
        {
            string ip = Ipv4(adapter); if (ip == null) return false;
            if (times == null) return AnyVia(ip, ProbeHosts(), timeoutMs);
            bool ok = false;
            foreach (var h in ProbeHosts()) { var sw = Stopwatch.StartNew(); if (TcpVia(ip, h, timeoutMs)) { ok = true; if (times != null) times.Add(sw.ElapsedMilliseconds); else break; } }
            return ok;
        }
        static ServiceController Svc(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            try { var s = new ServiceController(name); var st = s.Status; return s; } catch { return null; }      // нет такой службы — исключение
        }
        static void SetAutoStart(string svc) { Exe("sc.exe", "config \"" + svc + "\" start= auto", 30); Uncache("sm:" + svc); }
        static string StartMode(string svc) { return Cached("sm:" + svc, 300, () => StartModeWmi(svc)); }
        static string StartModeWmi(string svc) { try { using (var mo = new ManagementObject("Win32_Service.Name='" + svc.Replace("'", "\\'").Replace("\\", "\\\\") + "'")) return Convert.ToString(mo["StartMode"]); } catch { return ""; } }
        static string When(DateTime d)
        {
            if (d == DateTime.MinValue) return "не было";
            var s = (DateTime.Now - d).TotalSeconds;
            return d.ToString(d.Date == DateTime.Today ? "HH:mm:ss" : "dd.MM HH:mm") + (s < 3600 ? " (" + (int)(s / 60) + " мин назад)" : "");
        }
        static bool IsTunnel(string alias)
        {
            if (string.IsNullOrEmpty(alias)) return false;
            if (alias.StartsWith("MeduzaVPN", StringComparison.OrdinalIgnoreCase) || alias == MzAdapterName() || alias == WgIf()) return true;
            return IsAvpnAlias(alias);
        }
        // физический выход: работающий адаптер со шлюзом IPv4, не туннель
        static string PhysAlias()
        {
            try {
                foreach (var n in AllNics().OrderBy(n => n.NetworkInterfaceType == NetworkInterfaceType.Ethernet ? 0 : 1)) {
                    if (n.OperationalStatus != OperationalStatus.Up || IsTunnel(n.Name)) continue;
                    var gw = n.GetIPProperties().GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork && g.Address.ToString() != "0.0.0.0");
                    if (gw != null) return n.Name;
                }
            } catch { }
            return "";
        }
    }
}
