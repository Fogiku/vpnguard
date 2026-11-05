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
        static void InetCheck()
        {
            string why = null, via = PhysAlias(), gw = ""; long ms = -1;
            if (via.Length == 0) why = "нет подключения к сети (кабель, Wi-Fi или роутер)";
            else {
                try { var g = Nic(via).GetIPProperties().GatewayAddresses.FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork && x.Address.ToString() != "0.0.0.0"); if (g != null) gw = g.Address.ToString(); } catch { }
                string ip = Ipv4(via);
                ms = ip == null ? -1 : Probe(ip, InetHosts(), 2500).FirstMs;
                if (ms < 0) {
                    // напрямую не открывается, а через туннель — да: интернет есть (провайдер режет только прямые адреса)
                    string tn = KindAdapter(TunnelKind()), tip = tn.Length > 0 && Up(tn) ? Ipv4(tn) : null;
                    if (tip != null && Probe(tip, ProbeHosts(), 2500).Ok) ms = 0;
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

        // для окна и веба (сводка): часть «Интернет»
        static Dictionary<string, object> InetComp()
        {
            // интернет вообще (InetLoop)
            int nL = InetState == 0 ? 0 : InetState == 1 ? 2 : -1;
            string nS = InetState == 0 ? "Есть" + (InetMs > 0 ? " · " + InetMs + " мс" : "") : InetState == 1 ? "Нет · " + Dur(DateTime.Now - InetSince) : InetFails > 0 ? "Проверяется" : "Нет данных";
            string lastDown = InetDowns == 0 ? "не пропадал" : When(InetLastDown) + (InetState == 1 ? " — сейчас" : " на " + Dur(InetLastLen));
            var inet = Comp(nL, nS, new[] { InetState == 1 ? InetWhy : "Напрямую через " + (InetVia.Length > 0 ? InetVia : "—") + (InetGw.Length > 0 ? " · роутер " + InetGw : ""),
                "Пропадал: " + InetDowns + " раз с запуска агента" + (InetDowns > 0 ? ", последний " + lastDown : "") }, new List<object[]> {
                Kv("Состояние", nS), Kv("Причина", InetState == 1 ? InetWhy : "—"), Kv("Физический адаптер", InetVia.Length > 0 ? InetVia : "нет"), Kv("Роутер (шлюз)", InetGw.Length > 0 ? InetGw : "—"),
                Kv("Узлы проверки", string.Join(", ", InetHosts()) + " — напрямую, мимо VPN, раз в 5 с"), Kv("Пропадал с запуска агента", InetDowns + " раз"), Kv("Последний раз", lastDown),
                Kv("Пока интернета нет", "VPN не переподключается и не перезапускается, zapret не переподбирается") });
            inet["since"] = InetSince == DateTime.MinValue ? "" : InetSince.ToString("o"); inet["downs"] = InetDowns;
            return inet;
        }
    }
}
