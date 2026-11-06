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
using System.Runtime.InteropServices;
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
        // «Нестабилен» — связь то есть, то нет (за последнюю минуту были провалы): проверки служб в это время тоже ничего не скажут — ждём.
        static volatile int InetState = -1;            // -1 нет данных, 0 есть, 1 нет
        static string InetWhy = "", InetVia = "", InetGw = "", InetHost = ""; static int InetFails, InetDowns, InetOkHosts, InetTotalHosts; static long InetMs = -1, InetGwMs = -1;
        static DateTime InetSince = DateTime.MinValue, InetLastDown = DateTime.MinValue, InetRestoredAt = DateTime.MinValue; static TimeSpan InetLastLen = TimeSpan.Zero;
        static readonly Queue<bool> InetHist = new Queue<bool>();   // последние 12 проверок (~1 мин): true — интернет был
        static bool InetDown() { return InetState == 1; }
        static int InetLosses() { lock (InetHist) return InetHist.Count(x => !x); }
        static bool InetUnstable() { return InetState == 0 && (InetLosses() >= 2 || (DateTime.Now - InetRestoredAt).TotalSeconds < 30); }
        // интернет плохой (нет, нестабилен или только что был провал): проверять VPN, zapret, перебирать протоколы и переключать туннели бессмысленно
        static bool InetBad() { return InetState == 1 || InetFails > 0 || InetUnstable(); }
        static int InetLive() { return InetState == 1 ? 1 : InetUnstable() ? 2 : InetState; }   // для схемы: 0 есть, 1 нет, 2 нестабилен
        static string[] InetHosts() { return CfgList("net.probeHosts", new[] { "77.88.8.8:53", "8.8.8.8:53", "1.1.1.1:443", "87.250.250.242:443" }); }
        static string InetHostName(string h)
        {
            var ip = h.Split(':')[0];
            switch (ip) { case "77.88.8.8": return "Яндекс DNS"; case "8.8.8.8": return "Google DNS"; case "1.1.1.1": return "Cloudflare"; case "87.250.250.242": return "ya.ru"; }
            return ip;
        }
        static string Dur(TimeSpan t) { return t.TotalMinutes >= 60 ? (int)t.TotalHours + " ч " + t.Minutes + " мин" : t.TotalSeconds >= 60 ? (int)t.TotalMinutes + " мин " + t.Seconds + " с" : (int)t.TotalSeconds + " с"; }
        static void InetLoop()
        {
            PerfThread("проверка интернета");
            while (true) {
                try { InetCheck(); } catch { }
                Thread.Sleep(InetState == 1 || InetFails > 0 ? 3000 : 5000);
            }
        }
        static long PingMs(string host, int timeoutMs)
        {
            try { using (var p = new Ping()) { var r = p.Send(host, timeoutMs); return r.Status == IPStatus.Success ? r.RoundtripTime : -1; } } catch { return -1; }
        }
        // все узлы — параллельно (хватит одного); запоминаем, какой ответил первым и сколько ответило
        static void InetCheck()
        {
            string why = null, via = PhysAlias(), gw = "", host = ""; long ms = -1; int okN = 0, total = 0;
            if (via.Length == 0) why = "нет подключения к сети (кабель, Wi-Fi или роутер)";
            else {
                try { var g = Nic(via).GetIPProperties().GatewayAddresses.FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork && x.Address.ToString() != "0.0.0.0"); if (g != null) gw = g.Address.ToString(); } catch { }
                string ip = Ipv4(via);
                var pr = ip == null ? new ProbeRes() : ProbeAll(ip, InetHosts(), 2500);
                ms = pr.FirstMs; host = pr.FirstHost ?? ""; okN = pr.OkCount; total = pr.Total;
                if (!pr.Ok) {
                    // напрямую не открывается, а через туннель — да: интернет есть (провайдер режет только прямые адреса)
                    string tn = KindAdapter(TunnelKind()), tip = tn.Length > 0 && Up(tn) ? Ipv4(tn) : null;
                    if (tip != null && Probe(tip, ProbeHosts(), 2500).Ok) { ms = 0; host = "через туннель"; }
                    else {
                        long g = gw.Length > 0 ? PingMs(gw, 1000) : -1;
                        why = gw.Length == 0 ? "нет шлюза у " + via : g >= 0 ? "провайдер не пропускает трафик (роутер " + gw + " отвечает)" : "роутер " + gw + " не отвечает";
                    }
                }
            }
            InetGwMs = gw.Length > 0 ? PingMs(gw, 800) : -1;
            InetVia = via; InetGw = gw; InetOkHosts = okN; InetTotalHosts = total;
            lock (InetHist) { InetHist.Enqueue(why == null); while (InetHist.Count > 12) InetHist.Dequeue(); }
            if (why == null) {
                InetFails = 0; InetMs = ms; InetHost = host; InetWhy = "";
                if (InetState != 0) {
                    if (InetState == 1) {
                        InetLastLen = DateTime.Now - InetSince; Log("Интернет: снова есть (не было " + Dur(InetLastLen) + ")", "WARN");
                        InetRestoredAt = DateTime.Now; Emit("inet.restored", Dur(InetLastLen));
                    }
                    InetState = 0; InetSince = DateTime.Now;
                }
            } else {
                InetWhy = why; InetMs = -1; InetHost = "";
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
            bool unst = InetUnstable(); int loss = InetLosses();
            int nL = InetState == 0 ? (unst ? 1 : 0) : InetState == 1 ? 2 : -1;
            string target = InetHost.Length > 0 ? InetHost + (InetHost != "через туннель" ? " (" + InetHostName(InetHost) + ")" : "") : "";
            string nS = InetState == 0 ? (unst ? "Нестабилен" : "Есть") + (InetMs > 0 ? " · " + InetMs + " мс" : "") : InetState == 1 ? "Нет · " + Dur(DateTime.Now - InetSince) : InetFails > 0 ? "Проверяется" : "Нет данных";
            string lastDown = InetDowns == 0 ? "не пропадал" : When(InetLastDown) + (InetState == 1 ? " — сейчас" : " на " + Dur(InetLastLen));
            var inet = Comp(nL, nS, new[] { InetState == 1 ? InetWhy : unst ? "Связь прерывается: провалов " + loss + " из 12 проверок за минуту — VPN не переключаю, жду" : "Напрямую через " + (InetVia.Length > 0 ? InetVia : "—") + (InetGw.Length > 0 ? " · роутер " + InetGw : ""),
                "Пропадал: " + InetDowns + " раз с запуска агента" + (InetDowns > 0 ? ", последний " + lastDown : "") }, new List<object[]> {
                Kv("Состояние", nS), Kv("Причина", InetState == 1 ? InetWhy : "—"),
                Kv("Отклик", InetMs > 0 ? InetMs + " мс до " + target + " (TCP, напрямую мимо VPN)" : InetMs == 0 ? "есть через туннель" : "—"),
                Kv("Ответило узлов", InetTotalHosts > 0 ? InetOkHosts + " из " + InetTotalHosts : "—"),
                Kv("Роутер", InetGw.Length > 0 ? InetGw + (InetGwMs >= 0 ? " · ping " + InetGwMs + " мс" : " · не отвечает на ping") : "—"),
                Kv("Провалов за минуту", loss + " из 12"), Kv("Физический адаптер", InetVia.Length > 0 ? InetVia : "нет"),
                Kv("Узлы проверки", string.Join(", ", InetHosts().Select(h => h + " (" + InetHostName(h) + ")")) + " — напрямую, мимо VPN, раз в 5 с"), Kv("Пропадал с запуска агента", InetDowns + " раз"), Kv("Последний раз", lastDown),
                Kv("Пока интернета нет или он нестабилен", "VPN не переподключается, не переключается и не перезапускается, zapret не проверяется и не переподбирается") });
            inet["since"] = InetSince == DateTime.MinValue ? "" : InetSince.ToString("o"); inet["downs"] = InetDowns;
            inet["unstable"] = unst; inet["loss"] = loss; inet["ms"] = InetMs; inet["host"] = InetHost; inet["hostName"] = InetHost.Length > 0 && InetHost != "через туннель" ? InetHostName(InetHost) : InetHost;
            inet["gw"] = InetGw; inet["gwMs"] = InetGwMs; inet["okHosts"] = InetOkHosts; inet["hosts"] = InetTotalHosts;
            return inet;
        }
    }
}
