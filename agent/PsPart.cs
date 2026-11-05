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
        static string PsNeededNow() { return Directory.GetFiles(CmdPsDir, "*.cmd").Length > 0 ? "команда" : null; }
        static void PsPartWatch()
        {
            if (PsPart != null && !PsPart.HasExited) {
                if ((DateTime.Now - PsPartAt).TotalMinutes > 30) { Log("Агент C#: часть PowerShell работает больше 30 мин — останавливаю", "WARN"); try { PsPart.Kill(); } catch { } }
                return;
            }
            // раз в 30 мин (самообновление VpnGuard — у него свой интервал в часах) и сразу — по команде (app-update, app-check, wg-create).
            // Компоненты, обновление MeduzaVPN, веб-сервер и значок — модули агента (Software.cs, WebHost.cs)
            string why = PsNeededNow();
            double every = Math.Max(5, CfgInt("agent.psPartMin", 30)) * 60.0;
            if ((DateTime.Now - PsPartAt).TotalSeconds < (why != null ? 120 : every)) return;
            if (why != null && PsPartAt != DateTime.MinValue) Log("Агент C#: запускаю часть PowerShell — " + why, "INFO");
            PsPartAt = DateTime.Now;
            try {
                PsPart = Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + Path.Combine(Root, "VpnGuard.ps1") + "\" -PsPart" + (ConfigPath != Path.Combine(Root, "config.json") ? " -ConfigPath \"" + ConfigPath + "\"" : ""))
                    { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Root });
            } catch (Exception e) { Log("Агент C#: не удалось запустить часть PowerShell: " + e.Message, "ERROR"); }
        }
    }
}
