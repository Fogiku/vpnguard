// Защита: AmneziaVPN не должен отрезать локальную сеть и клиентов WG-Server.
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
        // ---------------------------------------------------------------- защита: AmneziaVPN не должен отрезать локальную сеть и клиентов WG-Server
        // Маршруты AmneziaVPN локалку не трогают (сеть роутера точнее 0.0.0.0/1), но Kill Switch приложения может запретить в брандмауэре
        // всё, кроме туннеля, — тогда пропадут роутер, клиенты WG (они приходят с адреса роутера) и удалённый доступ к ПК.
        // Пока AmneziaVPN не поднят — запоминаем, как было (роутер отвечает, сколько клиентов на связи); поднят и стало хуже 2 проверки
        // подряд — гасим AmneziaVPN и смотрим, вернулось ли. Вернулось — виноват он: отключаем на amnezia.guardBlockMin минут
        // (в режиме AmneziaVPN — переключаем на MeduzaVPN). Не вернулось — дело не в нём, запускаем обратно.
        static DateTime AgBlockedUntil = DateTime.MinValue, AgTripAt = DateTime.MinValue, AgBaseAt = DateTime.MinValue;
        static string AgTripWhy = ""; static int AgFails, AgTrips, AgPeersBase = -1; static bool AgGwBase;
        static bool AvpnBlocked() { return DateTime.Now < AgBlockedUntil; }
        static string AgGateway() { var z = ZPhys(); return z != null && !string.IsNullOrEmpty(z.Gateway) ? z.Gateway : InetGw; }
        static bool AgGwOk(string gw, int tries = 8)
        {
            if (string.IsNullOrEmpty(gw)) return true;
            for (int i = 0; i < tries; i++) {
                try { using (var p = new System.Net.NetworkInformation.Ping()) if (p.Send(gw, 1000).Status == System.Net.NetworkInformation.IPStatus.Success) return true; } catch { }
                Thread.Sleep(300);
            }
            return false;                                              // ~10 с без ответа
        }
        // клиенты WG-Server с рукопожатием за последние 3 мин (на связи)
        static int AgPeers()
        {
            try {
                var wg = Path.Combine(Path.GetDirectoryName(CfgStr("ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe")), "wg.exe");
                var r = File.Exists(wg) ? Exe(wg, "show " + WgIf() + " dump", 5) : null; if (r == null || r.Code != 0) return -1;
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); int n = 0;
                foreach (var l in r.Out.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Skip(1)) {
                    var p = l.Split('\t'); long hs; if (p.Length > 4 && long.TryParse(p[4], out hs) && hs > 0 && now - hs < 180) n++;
                }
                return n;
            } catch { return -1; }
        }
        static void AvpnGuard()
        {
            if (!CfgBool("amnezia.lanGuard", true)) { AgFails = 0; return; }
            string gw = AgGateway(); var nic = AvpnNic(); bool up = nic != null && nic.OperationalStatus == OperationalStatus.Up;
            if (!up) {                                                   // AmneziaVPN не поднят — запомнить, как должно быть
                AgFails = 0; if ((DateTime.Now - AgBaseAt).TotalSeconds < 50) return;
                AgGwBase = AgGwOk(gw, 3); AgPeersBase = AgPeers(); AgBaseAt = DateTime.Now; return;
            }
            // только что (пере)подключился или трафик переключили — маршруты и раздача перестраиваются, роутер может молчать несколько секунд
            if ((DateTime.Now - AvpnStartedAt).TotalSeconds < 60 || (DateTime.Now - DualSwitchAt).TotalSeconds < 60 || (DateTime.Now - AwgLastRestart).TotalSeconds < 60) { AgFails = 0; return; }
            bool gwOk = AgGwOk(gw); int peers = AgPeers();
            string bad = !gwOk && (AgGwBase || AgBaseAt == DateTime.MinValue) ? "роутер " + gw + " не отвечает"
                : AgPeersBase > 0 && peers == 0 ? "клиенты WG-Server пропали (было на связи " + AgPeersBase + ")" : null;
            if (bad == null) { AgFails = 0; return; }
            AgFails++;
            Log("Защита AmneziaVPN: при поднятом туннеле " + bad + " (" + AgFails + "/2)", "WARN");
            if (AgFails < 2) return;
            AgFails = 0;
            // проверка: без AmneziaVPN вернётся?
            bool byGw = bad.StartsWith("роутер");
            Log("Защита AmneziaVPN: отключаю AmneziaVPN и проверяю, вернётся ли связь", "WARN"); SetActivity("проверяю, не AmneziaVPN ли отрезал локальную сеть");
            AvpnStop();
            bool back = Wait(() => byGw ? AgGwOk(gw, 2) : AgPeers() > 0, byGw ? 15 : 60);
            if (!back) {                                                 // служба могла оставить правила брандмауэра — остановить её совсем
                try { var sv = Svc(AvpnSvcName()); if (sv != null && sv.Status == ServiceControllerStatus.Running) { sv.Stop(); sv.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)); } } catch { }
                back = Wait(() => byGw ? AgGwOk(gw, 2) : AgPeers() > 0, byGw ? 15 : 60);
            }
            if (!back) {
                Log("Защита AmneziaVPN: без AmneziaVPN связь тоже не вернулась (" + bad + ") — дело не в нём, запускаю его обратно", "WARN");
                try { var sv = Svc(AvpnSvcName()); if (sv != null && sv.Status != ServiceControllerStatus.Running) sv.Start(); } catch { }
                return;
            }
            int min = Math.Max(10, CfgInt("amnezia.guardBlockMin", 180));
            AgTrips++; AgTripAt = DateTime.Now; AgTripWhy = bad; AgBlockedUntil = DateTime.Now.AddMinutes(min);
            Log("Защита AmneziaVPN: AmneziaVPN отрезал локальную сеть (" + bad + "; без него всё вернулось). Он отключён на " + min + " мин. " +
                "В приложении AmneziaVPN выключите Kill Switch (или разрешите в нём локальную сеть), затем снова выберите режим", "ERROR");
            if (Mode() == "amnezia") { CfgSet("vpn.mode", "meduza"); Log("Защита AmneziaVPN: режим переключён на MeduzaVPN, чтобы клиенты не остались без VPN", "WARN"); }
            IcsIfUplink("amnezia");
        }
        static bool Wait(Func<bool> ok, int sec)
        {
            var dl = DateTime.Now.AddSeconds(sec);
            do { Thread.Sleep(3000); if (ok()) return true; } while (DateTime.Now < dl);
            return false;
        }
    }
}
