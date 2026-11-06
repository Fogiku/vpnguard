// Быстрое переключение (режим «два туннеля»): раз в vpn.fastCheckSec (5) с — лёгкая проверка активного туннеля (несколько узлов
// параллельно, не дольше 3 с). Не прошла vpn.fastFailChecks (2) раза подряд, а резерв пропускает трафик — трафик сразу на резерв.
// Работает в своём потоке: модуль «Туннели» может в это время долго восстанавливать упавший туннель — переключение не ждёт его.
using System;
using System.Linq;

namespace VpnGuard
{
    public static partial class Agent
    {
        static int FoFails; static string FoAct = "";
        static void FailoverTick()
        {
            if (Mode() != "dual" || !CfgBool("vpn.dualHot", true) || InetBad()) { FoFails = 0; return; }
            string act = DualAct(), oth = OtherKind(act);
            if (act != FoAct) { FoAct = act; FoFails = 0; }
            // только что переключились или основной только запускается — маршруты и раздача перестраиваются
            if ((DateTime.Now - DualSwitchAt).TotalSeconds < 20) return;
            if (act == "meduza" && (DateTime.Now - MeduzaStartedAt).TotalSeconds < CfgInt("meduza.startupGraceSec", 60)) return;
            if (KindOk(act)) { FoFails = 0; return; }
            FoFails++;
            int need = Math.Max(1, CfgInt("vpn.fastFailChecks", 2));
            if (FoFails < need) return;
            if (KindOk(oth)) {
                DualSwitch(oth, ModeNames[act] + " не пропускает трафик (" + FoFails + " быстрые проверки подряд) — восстанавливаю его, трафик пока через " + ModeNames[oth]);
                FoFails = 0;
            } else if (FoFails == need) Log("Быстрое переключение: " + ModeNames[act] + " не пропускает трафик, но и резерв " + ModeNames[oth] + " не готов — переключать некуда", "WARN");
        }
    }
}
