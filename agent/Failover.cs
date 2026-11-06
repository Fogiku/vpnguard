// Быстрое переключение (режим «два туннеля»): раз в vpn.fastCheckSec (5) с — лёгкая проверка активного туннеля (несколько узлов
// параллельно, не дольше 3 с). Не прошла vpn.fastFailChecks (2) раза подряд, а резерв пропускает трафик — трафик сразу на резерв.
// Работает в своём потоке: модуль «Туннели» может в это время долго восстанавливать упавший туннель — переключение не ждёт его.
using System;
using System.Linq;

namespace VpnGuard
{
    public static partial class Agent
    {
        static int FoFails; static string FoAct = ""; static bool FoBothDown;
        static DateTime NoTunnelSince = DateTime.MinValue; static volatile bool ZRescueWant;
        // ни один туннель не пропускает трафик, а интернет напрямую есть: DNS клиентов (8.8.8.8, 1.1.1.1 …) уходит в мёртвый туннель —
        // YouTube и Discord не открываются даже через zapret. Через 15 с — пустить DNS напрямую (маршруты мимо VPN, ретранслятор клиентов)
        static void RescueTick()
        {
            string mode = Mode(); bool down = false;
            if (mode != "zapret" && InetState == 0) {
                if (mode == "dual") down = FoBothDown;
                else { var k = TunnelKind(); down = k.Length > 0 && (!Up(KindAdapter(k)) || KindTraffic(k) == false); }
            }
            if (!down) { NoTunnelSince = DateTime.MinValue; if (ZRescueWant) { ZRescueWant = false; Wake("zapret"); } return; }
            if (NoTunnelSince == DateTime.MinValue) NoTunnelSince = DateTime.Now;
            if (!ZRescueWant && (DateTime.Now - NoTunnelSince).TotalSeconds >= 15) { ZRescueWant = true; Wake("zapret"); }
        }
        static void FailoverTick()
        {
            try { RescueTick(); } catch { }
            if (Mode() != "dual" || !CfgBool("vpn.dualHot", true) || InetBad()) { FoFails = 0; FoBothDown = false; return; }
            string act = DualAct(), oth = OtherKind(act);
            if (act != FoAct) { FoAct = act; FoFails = 0; }
            // только что переключились или основной только запускается — маршруты и раздача перестраиваются
            if ((DateTime.Now - DualSwitchAt).TotalSeconds < 20) return;
            if (act == "meduza" && (DateTime.Now - MeduzaStartedAt).TotalSeconds < CfgInt("meduza.startupGraceSec", 60)) return;
            if (KindOk(act)) { FoFails = 0; FoBothDown = false; return; }
            FoFails++;
            int need = Math.Max(1, CfgInt("vpn.fastFailChecks", 2));
            if (FoFails < need) return;
            FoBothDown = !KindOk(oth);
            if (!FoBothDown) {
                DualSwitch(oth, ModeNames[act] + " не пропускает трафик (" + FoFails + " быстрые проверки подряд) — восстанавливаю его, трафик пока через " + ModeNames[oth]);
                FoFails = 0;
            } else if (FoFails == need) Log("Быстрое переключение: " + ModeNames[act] + " не пропускает трафик, но и резерв " + ModeNames[oth] + " не готов — переключать некуда", "WARN");
        }
    }
}
