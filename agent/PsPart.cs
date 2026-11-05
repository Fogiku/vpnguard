// Часть PowerShell: zapret, обновления, веб-сервер, значок — по командам и по расписанию.
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
        // ---------------------------------------------------------------- PowerShell: zapret, обновления, веб-сервер, значок …
        static void QueuePs(string cmd) { try { File.WriteAllText(Path.Combine(CmdPsDir, DateTime.UtcNow.Ticks + ".cmd"), cmd, Encoding.ASCII); } catch { } PsPartAt = DateTime.MinValue; }
        static string WebSig = null;
        static string WebSignature() { return string.Join("|", new[] { "web.enabled", "web.port", "web.requirePassword", "web.token", "remote.enabled", "remote.until", "remote.allowFrom", "remote.port" }.Select(k => CfgStr(k, ""))); }
        static string PsNeededNow()
        {
            if (Directory.GetFiles(CmdPsDir, "*.cmd").Length > 0) return "команда";
            DateTime until; bool remoteEn = CfgBool("remote.enabled", false);
            bool remoteOn = remoteEn && DateTime.TryParse(CfgStr("remote.until", ""), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out until) && until.ToLocalTime() > DateTime.Now;
            if (remoteEn && !remoteOn) return "время удалённой диагностики вышло";
            if (WebSig != null && WebSignature() != WebSig) return "изменены настройки веб-интерфейса или диагностики";
            bool webRunning = Process.GetProcessesByName("VpnGuardWeb").Length > 0;
            if ((CfgBool("web.enabled", true) || remoteOn) && !webRunning) return "веб-сервер не работает";
            return null;
        }
        static void PsPartWatch()
        {
            if (PsPart != null && !PsPart.HasExited) {
                if ((DateTime.Now - PsPartAt).TotalMinutes > 30) { Log("Агент C#: часть PowerShell работает больше 30 мин — останавливаю", "WARN"); try { PsPart.Kill(); } catch { } }
                return;
            }
            // обычно — раз в 30 мин (обновления VpnGuard/MeduzaVPN, компоненты, значок: у них свои интервалы в часах);
            // сразу — по команде, если веб-сервер должен работать, а не работает, или изменили настройки веба/диагностики
            string why = PsNeededNow();
            double every = Math.Max(5, CfgInt("agent.psPartMin", 30)) * 60.0;
            if ((DateTime.Now - PsPartAt).TotalSeconds < (why != null ? 120 : every)) return;
            if (why != null && PsPartAt != DateTime.MinValue) Log("Агент C#: запускаю часть PowerShell — " + why, "INFO");
            PsPartAt = DateTime.Now; WebSig = WebSignature();
            try {
                PsPart = Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + Path.Combine(Root, "VpnGuard.ps1") + "\" -PsPart" + (ConfigPath != Path.Combine(Root, "config.json") ? " -ConfigPath \"" + ConfigPath + "\"" : ""))
                    { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Root });
            } catch (Exception e) { Log("Агент C#: не удалось запустить часть PowerShell: " + e.Message, "ERROR"); }
        }
    }
}
