// Режим работы (meduza / amnezia / dual / zapret) и выбор туннеля.
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
        // ---------------------------------------------------------------- режим работы
        static string UplinkName() { var m = Mode(); if (m == "zapret") return PhysAlias(); return KindAdapter(TunnelKind()); }
        static readonly Dictionary<string, string> ModeNames = new Dictionary<string, string> { { "meduza", "MeduzaVPN" }, { "amnezia", "AmneziaVPN" }, { "dual", "два туннеля (MeduzaVPN + AmneziaVPN)" }, { "zapret", "без VPN (только zapret)" } };
        static void VpnWatch()
        {
            string mode = Mode();
            if (mode != LastMode) {
                if (LastMode != null) Log("Режим: " + ModeNames[LastMode] + " → " + ModeNames[mode], "WARN");
                SetActivity("переключаю режим: " + ModeNames[mode]);
                if (LastMode == "dual") { try { DualResetRoutes(); } catch (Exception e) { Log("Два туннеля: маршруты: " + e.Message, "WARN"); } }
                if (mode != "meduza" && mode != "dual" && CfgBool("vpn.stopInactive", true) && MzProc() != null) { Log("MeduzaVPN: отключаю и закрываю (выбран другой режим)", "INFO"); MzStop(); }
                if (mode != "amnezia" && mode != "dual") AvpnDisable(CfgBool("vpn.stopInactive", true));
                if (mode == "meduza" || mode == "dual") MeduzaStartedAt = DateTime.Now;
                if (mode == "amnezia" || mode == "dual") { AvpnStartedAt = DateTime.Now; if (AvpnBlocked()) Log("Защита AmneziaVPN: режим выбран заново — снова пробую AmneziaVPN", "INFO"); AgBlockedUntil = DateTime.MinValue; AgFails = 0; }
                if (mode == "dual") { DualActive = DualPrimary(); DualFails = 0; DualOkSince = DateTime.MinValue; }
                ProbeFailures = 0; DownTicks = 0; LastTraffic = null; AwgProbeFailures = 0; AwgDownTicks = 0; AwgTraffic = null; if (LastMode != null) Emit("mode.changed", ModeNames[LastMode] + " → " + ModeNames[mode]);
                LastMode = mode;
            }
            if (mode == "amnezia" || mode == "dual") { try { PerfRun("VpnWatch/защита Amnezia", AvpnGuard); } catch (Exception e) { Log("Защита AmneziaVPN: " + e.Message, "WARN"); } }
            if (InetDown() && mode != "zapret") { ProbeFailures = 0; DownTicks = 0; AwgProbeFailures = 0; AwgDownTicks = 0; DualFails = 0; return; }   // нет интернета у провайдера — туннель ни при чём
            if (mode == "meduza") { MeduzaWatch(); AvpnDisable(false); }
            else if (mode == "amnezia") { if (Up(MzAdapterName())) { Log("MeduzaVPN: подключён, но выбран режим AmneziaVPN — отключаю", "WARN"); MzDisconnect(); } AmneziaWatch(); }
            else if (mode == "dual") DualWatch();
            else if (mode == "zapret") { if (Up(MzAdapterName())) { Log("MeduzaVPN: подключён, но выбран режим без VPN — отключаю", "WARN"); MzDisconnect(); } AvpnDisable(false); LastTraffic = null; AwgTraffic = null; }
        }
    }
}
