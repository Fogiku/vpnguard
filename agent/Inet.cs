// Интернет у провайдера: проверка напрямую через физический адаптер (мимо VPN), раз в 5 с.
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
        // ---------------------------------------------------------------- интернет вообще: напрямую через физический адаптер (мимо VPN), раз в 5 с
        // Пропал у провайдера — туннель не трогаем: переподключения, перебор протоколов и перезапуски не помогут,
        // а после возвращения связи только задержат её на 10–15 минут. Ждём и показываем это в окне и веб-интерфейсе.
        static volatile int InetState = -1;            // -1 нет данных, 0 есть, 1 нет
        static string InetWhy = "", InetVia = "", InetGw = ""; static int InetFails, InetDowns; static long InetMs = -1;
        static DateTime InetSince = DateTime.MinValue, InetLastDown = DateTime.MinValue; static TimeSpan InetLastLen = TimeSpan.Zero;
        static bool InetDown() { return InetState == 1; }
        static string[] InetHosts() { return CfgList("net.probeHosts", new[] { "77.88.8.8:53", "8.8.8.8:53", "1.1.1.1:443", "87.250.250.242:443" }); }
        static string Dur(TimeSpan t) { return t.TotalMinutes >= 60 ? (int)t.TotalHours + " ч " + t.Minutes + " мин" : t.TotalSeconds >= 60 ? (int)t.TotalMinutes + " мин " + t.Seconds + " с" : (int)t.TotalSeconds + " с"; }
        static void InetLoop()
        {
            PerfThread("проверка интернета");
            while (true) {
                try { InetCheck(); } catch { }
                Thread.Sleep(InetState == 1 ? 3000 : 5000);
            }
        }
        // хватит ответа одного узла (все — параллельно)
        static long AnyTcp(string srcIp, string[] hosts, int timeoutMs)
        {
            var done = new ManualResetEvent(false); var sw = Stopwatch.StartNew(); long[] ms = { -1 }; int left = hosts.Length;
            foreach (var h in hosts) {
                var hh = h;
                ThreadPool.QueueUserWorkItem(_ => {
                    bool ok = TcpVia(srcIp, hh, timeoutMs);
                    if (ok && Interlocked.CompareExchange(ref ms[0], sw.ElapsedMilliseconds, -1) == -1) done.Set();
                    if (Interlocked.Decrement(ref left) == 0) done.Set();
                });
            }
            done.WaitOne(timeoutMs + 500);
            return Interlocked.Read(ref ms[0]);
        }
        static void InetCheck()
        {
            string why = null, via = PhysAlias(), gw = ""; long ms = -1;
            if (via.Length == 0) why = "нет подключения к сети (кабель, Wi-Fi или роутер)";
            else {
                try { var g = Nic(via).GetIPProperties().GatewayAddresses.FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork && x.Address.ToString() != "0.0.0.0"); if (g != null) gw = g.Address.ToString(); } catch { }
                string ip = Ipv4(via);
                ms = ip == null ? -1 : AnyTcp(ip, InetHosts(), 2500);
                if (ms < 0) {
                    // напрямую не открывается, а через туннель — да: интернет есть (провайдер режет только прямые адреса)
                    string tn = KindAdapter(TunnelKind()), tip = tn.Length > 0 && Up(tn) ? Ipv4(tn) : null;
                    if (tip != null && AnyTcp(tip, ProbeHosts(), 2500) >= 0) ms = 0;
                    else {
                        bool gwOk = false; if (gw.Length > 0) { try { using (var p = new Ping()) gwOk = p.Send(gw, 1000).Status == IPStatus.Success; } catch { } }
                        why = gw.Length == 0 ? "нет шлюза у " + via : gwOk ? "провайдер не пропускает трафик (роутер " + gw + " отвечает)" : "роутер " + gw + " не отвечает";
                    }
                }
            }
            InetVia = via; InetGw = gw;
            if (why == null) {
                InetFails = 0; InetMs = ms; InetWhy = "";
                if (InetState != 0) {
                    if (InetState == 1) {
                        InetLastLen = DateTime.Now - InetSince; Log("Интернет: снова есть (не было " + Dur(InetLastLen) + ")", "WARN");
                        Emit("inet.restored", Dur(InetLastLen));
                    }
                    InetState = 0; InetSince = DateTime.Now;
                }
            } else {
                InetWhy = why; InetMs = -1;
                if (++InetFails >= 2 && InetState != 1) {
                    InetState = 1; InetSince = DateTime.Now; InetLastDown = DateTime.Now; InetDowns++;
                    Log("Интернет: пропал — " + why + ". VPN не переподключаю, жду возвращения связи", "WARN");
                    Emit("inet.lost", why);
                }
            }
        }
    }
}
