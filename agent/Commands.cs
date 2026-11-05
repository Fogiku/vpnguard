// Команды от окна, веб-интерфейса и удалённой диагностики.
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
        // ---------------------------------------------------------------- команды
        static readonly string[] OwnCmds = { "check-now", "reconnect", "reconnect-meduza", "reconnect-awg", "restart-meduza", "restart-wg", "reapply-ics", "meduza-test", "meduza-catalog", "meduza-proto-reset", "dual-switch",
            "zapret-on", "zapret-off", "zapret-check", "zapret-releases", "zapret-update", "zapret-reload", "zapret-test" };
        static void Commands()
        {
            var files = Directory.GetFiles(CmdDir, "*.cmd").OrderBy(f => f).ToList();
            foreach (var f in files) {
                string a = ""; try { a = File.ReadAllText(f).Trim(); } catch { }
                if (!OwnCmds.Contains(a)) {                  // остальное — PowerShell (zapret, обновления, установка компонентов …)
                    try { File.Move(f, Path.Combine(CmdPsDir, Path.GetFileName(f))); } catch { try { File.Delete(f); } catch { } }
                    PsPartAt = DateTime.MinValue; continue;
                }
                try { File.Delete(f); } catch { }
                Log("Команда из монитора: " + a, "INFO");
                switch (a) {
                    case "reconnect":
                        if (TunnelKind() == "amnezia") { AwgRestarts.Clear(); AwgRestart("по команде из окна"); }
                        else if (TunnelKind() == "meduza") { MzReconnectCmd(); }
                        break;
                    case "reconnect-meduza": MzReconnectCmd(); break;
                    case "reconnect-awg": AwgRestarts.Clear(); AwgRestart("по команде из окна"); break;
                    case "restart-meduza": Restarts.Clear(); MzRestart("по команде из монитора"); break;
                    case "restart-wg": SvcRestart(CfgStr("ws4w.serviceName", "")); ForceIcs = true; break;
                    case "reapply-ics": ForceIcs = true; break;
                    case "meduza-test": MzProtoTest(); break;
                    case "meduza-catalog": MzCatalog(true); break;
                    case "meduza-proto-reset": if (MzOverride.Length > 0) { MzReturnAt = DateTime.MinValue; MzProtoReturn(); } break;
                    case "dual-switch":
                        if (Mode() == "dual") { string to = OtherKind(DualAct()); if (KindOk(to)) DualSwitch(to, "вручную из окна"); else Log("Два туннеля: " + ModeNames[to] + " сейчас не пропускает трафик — не переключаю", "WARN"); }
                        break;
                    default: try { ZCommand(a); } catch (Exception e) { Log("zapret: " + a + ": " + e.Message, "ERROR"); } break;
                }
            }
            if (files.Count > 0) Snapshot();
        }
        static void MzReconnectCmd() { MzDisconnect(); Thread.Sleep(3000); if (!MzConnect(0)) MzRestart("переподключение из монитора не удалось"); }
        // перезапуск службы, которая не принимает «стоп» (AmneziaVPN-service): штатно не вышло — завершить её процесс
        // перенастроить раздачу, только если этот туннель сейчас несёт трафик (резерв перезапустился — раздачу не трогать, клиенты не рвутся;
        // если у раздаваемого адаптера сменилось имя, SharingWatch и так это увидит)
        static void IcsIfUplink(string kind) { if (TunnelKind() == kind) ForceIcs = true; }
        static void SvcHardRestart(string name)
        {
            var s = Svc(name); if (s == null) return;
            try { if (s.Status != ServiceControllerStatus.Stopped) { s.Stop(); s.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15)); } }
            catch {
                int pid = 0;
                try { using (var mo = new ManagementObject("Win32_Service.Name='" + name.Replace("\\", "\\\\").Replace("'", "\\'") + "'")) pid = Convert.ToInt32(mo["ProcessId"]); } catch { }
                if (pid > 4) {
                    try { var p = Process.GetProcessById(pid); p.Kill(); p.WaitForExit(10000); Log(name + ": служба не останавливается штатно — завершил её процесс (PID " + pid + ")", "INFO"); }
                    catch (Exception e) { Log(name + ": не удалось завершить процесс службы (PID " + pid + "): " + e.Message, "WARN"); }
                }
            }
            try { s.Refresh(); if (s.Status != ServiceControllerStatus.Running) { if (s.Status == ServiceControllerStatus.Stopped) s.Start(); s.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30)); } }
            catch (Exception e) { Log(name + ": не запускается: " + e.Message, "WARN"); }
        }
        static void SvcRestart(string name)
        {
            try {
                var s = Svc(name); if (s == null) return;
                if (s.Status != ServiceControllerStatus.Stopped) { s.Stop(); s.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30)); }
                s.Start(); s.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
            } catch (Exception e) { Log(name + ": " + e.Message, "ERROR"); }
        }
    }
}
