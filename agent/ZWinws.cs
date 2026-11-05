// zapret: стратегии и процесс winws, метки времени TCP.
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
        // ---------------------------------------------------------------- стратегии и winws
        static List<string> ZStrategies()
        {
            if (!Directory.Exists(ZDir())) return new List<string>();
            return Directory.GetFiles(ZDir(), "general*.bat").Select(f => Path.GetFileNameWithoutExtension(f))
                .OrderBy(n => Regex.Replace(n, @"\d+", m => m.Value.PadLeft(4, '0')), StringComparer.OrdinalIgnoreCase).ToList();
        }
        static string ZStrategyArgs(string name)
        {
            string dir = ZDir(), bat = Path.Combine(dir, name + ".bat"); if (!File.Exists(bat)) return null;
            var raw = Regex.Replace(File.ReadAllText(bat, Encoding.Default), @"\^\s*\r?\n", " ");
            var line = Regex.Split(raw, @"\r?\n").FirstOrDefault(l => l.Contains("winws.exe")); if (line == null) return null;
            var m = Regex.Match(line, "winws\\.exe\"?\\s+(.*)$"); if (!m.Success) return null;
            var a = m.Groups[1].Value.Trim(); var gf = ZC("gameFilter");
            string gt = gf == "all" || gf == "tcp" ? "1024-65535" : "12", gu = gf == "all" || gf == "udp" ? "1024-65535" : "12";   // 12 = игровой фильтр выключен (как в service.bat)
            a = a.Replace("%BIN%", Path.Combine(dir, "bin") + "\\").Replace("%LISTS%", Path.Combine(dir, "lists") + "\\").Replace("%GameFilterTCP%", gt).Replace("%GameFilterUDP%", gu).Replace("%~dp0", dir + "\\");
            var left = Regex.Match(a, "%[A-Za-z_]+%"); if (left.Success) Log("zapret: в стратегии '" + name + "' остались неизвестные переменные: " + left.Value, "WARN");
            return a;
        }
        // метки времени TCP (RFC 1323): без них стратегии с fooling=ts не работают (service.bat тоже их включает)
        static string ZTcpTimestamps()
        {
            var o = Exe("netsh.exe", "interface tcp show global", 15).Out;
            if (Regex.IsMatch(o, @"(?im)(Timestamps|1323)[^\n]*:\s*(enabled|включ)")) return "Enabled";
            if (Regex.IsMatch(o, @"(?im)(Timestamps|1323)[^\n]*:\s*(disabled|выключ|отключ)")) return "Disabled";
            return "";
        }
        static void ZEnableTimestamps()
        {
            if (ZTcpTimestamps() == "Enabled") return;
            Exe("netsh.exe", "interface tcp set global timestamps=enabled", 15);
            var now = ZTcpTimestamps();
            if (now == "Enabled") Log("zapret: включены метки времени TCP (RFC 1323) — без них стратегии с fooling=ts не работают (так же делает service.bat)", "WARN");
            else Log("zapret: не удалось включить метки времени TCP (сейчас: '" + now + "') — стратегии с fooling=ts могут не работать", "ERROR");
        }
        static void ZStopWinws()
        {
            foreach (var p in Process.GetProcessesByName("winws")) { try { p.Kill(); p.WaitForExit(5000); } catch { } }
            Z["winwsPid"] = 0;
        }
        static void ZStopService()
        {
            var s = Svc("zapret"); if (s == null) return;
            try {
                if (s.Status != ServiceControllerStatus.Stopped) { Log("zapret: остановлена служба «zapret» (установлена через service.bat), иначе два winws мешают друг другу", "WARN"); s.Stop(); s.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)); }
                if (StartMode("zapret") != "Disabled") Exe("sc.exe", "config zapret start= disabled", 20);
            } catch (Exception e) { Log("zapret: не удалось остановить службу zapret: " + e.Message, "WARN"); }
        }
        static DateTime ZWinwsStartedAt = DateTime.MinValue;     // в первые секунды после запуска winws обход DPI ещё не работает
        static void ZStartWinws(string name)
        {
            try { ZEnableTimestamps(); } catch { }
            var a = ZStrategyArgs(name); if (a == null) throw new Exception("не удалось прочитать параметры стратегии '" + name + "'");
            var bin = Path.Combine(ZDir(), "bin");
            var p = Process.Start(new ProcessStartInfo(Path.Combine(bin, "winws.exe"), a) { WorkingDirectory = bin, UseShellExecute = false, CreateNoWindow = true });
            Thread.Sleep(1500);
            if (p.HasExited) throw new Exception("winws.exe завершился сразу (код " + p.ExitCode + ") со стратегией '" + name + "'");
            Z["winwsPid"] = p.Id; ZWinwsStartedAt = DateTime.UtcNow;
        }
        static Process ZWinws()
        {
            int pid = ZN("winwsPid"); if (pid <= 0) return null;
            try { var p = Process.GetProcessById(pid); return p.ProcessName == "winws" && !p.HasExited ? p : null; } catch { return null; }
        }
    }
}
