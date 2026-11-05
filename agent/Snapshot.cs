// Сводка состояния для окна, веб-интерфейса и значка (status.json).
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
        // ---------------------------------------------------------------- состояние для окна, веб-интерфейса и значка
        static object[] Kv(string k, object v) { return new object[] { k, v == null ? "—" : Convert.ToString(v) }; }
        static Dictionary<string, object> Comp(int level, string state, IEnumerable<string> details, List<object[]> kv)
        {
            return new Dictionary<string, object> { { "level", level }, { "state", state }, { "details", details.Where(d => !string.IsNullOrEmpty(d)).ToArray() }, { "kv", kv.Where(x => x != null).ToArray() } };
        }
        static Dictionary<string, object> ReadPsStatus()
        {
            try { using (var fs = new FileStream(PsStatusPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) using (var rd = new StreamReader(fs, Encoding.UTF8)) return Json.DeserializeObject(rd.ReadToEnd()) as Dictionary<string, object>; }
            catch { return null; }
        }
        static readonly object SnapLock = new object(); static string SnapErr = "";
        static void Snapshot()
        {
            lock (SnapLock) {
                LastSnapshot = DateTime.Now;
                try { SnapshotCore(); SnapErr = ""; }
                catch (Exception e) { if (e.Message != SnapErr) Log("Агент C#: состояние: " + e.Message, "ERROR"); SnapErr = e.Message; }      // одна и та же ошибка — в журнал один раз
            }
        }
        static void SnapshotCore()
        {
            string mode = Mode(), kind = TunnelKind(), upN = UplinkName(); bool updating = MzUpdating();
            var adNames = UpdateTraffic();
            var ps = ReadPsStatus() ?? new Dictionary<string, object>();
            // части от модулей; zapret и ретранслятор — копия, опубликованная модулем zapret из своего потока
            var zp = Published("zapret") as Dictionary<string, object>;
            if (zp == null && FindModule("zapret") == null) zp = new Dictionary<string, object> { { "zapret", ZSnapshotSafe() }, { "cz", CzSnapshot() } };   // без модулей (проверка --snapshot)
            object zapret = zp != null && zp.ContainsKey("zapret") ? zp["zapret"] : new Dictionary<string, object> { { "level", -1 }, { "state", "Нет данных" }, { "details", new string[0] }, { "kv", new object[0] }, { "enabled", CfgBool("zapret.enabled", false) } };
            object cz = zp != null && zp.ContainsKey("cz") ? zp["cz"] : null;
            var inet = InetComp(); var meduza = MeduzaComp(mode, kind, ps); var ultra = TunnelComp(mode, kind);
            var wg = WgComp(cz); var icsC = IcsComp(mode); var awg = AmneziaComp(mode, kind);
            Func<object, int> lv = c => { var d = c as Dictionary<string, object>; int x = -1; if (d != null && d.ContainsKey("level")) int.TryParse(Convert.ToString(d["level"]), out x); return x; };
            int nL = lv(inet), mL = lv(meduza), uL = lv(ultra), wL = lv(wg), iL = lv(icsC), aL = lv(awg), zL = lv(zapret), zc = 0;
            var zd = zapret as Dictionary<string, object>; if (zd != null && zd.ContainsKey("conns")) int.TryParse(Convert.ToString(zd["conns"]), out zc);

            // история (точка не чаще интервала проверки)
            long nowTs = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); long lastTs = History.Count > 0 ? Convert.ToInt64(History[History.Count - 1]["t"]) : 0;
            if (nowTs - lastTs >= Math.Max(10, CfgInt("checkIntervalSec", 30) - 2)) {
                History.Add(new Dictionary<string, object> { { "t", nowTs }, { "n", nL }, { "m", mL }, { "u", uL }, { "w", wL }, { "i", iL }, { "z", zL }, { "a", aL },
                    { "tr", new[] { TrafPending["u"][0], TrafPending["u"][1], TrafPending["w"][0], TrafPending["w"][1], TrafPending["p"][0], TrafPending["p"][1] } }, { "zc", zc } });
                TrafPending = NewTraf();
                while (History.Count > 240) History.RemoveAt(0);
            }
            string act2 = Activity;          // своё действие важнее; иначе — что делает часть PowerShell (обновление, zapret)
            if (act2.Length == 0 && ps.ContainsKey("activity") && PsPart != null && !PsPart.HasExited) act2 = Convert.ToString(ps["activity"]);
            bool busy = act2.Length > 0;
            var snap = new Dictionary<string, object> {
                { "updated", DateTime.Now.ToString("o") }, { "staleAfterSec", updating ? 1800 : busy ? 900 : CfgInt("checkIntervalSec", 30) + 120 }, { "activity", act2 },
                { "activitySince", busy ? ActivitySince.ToString("o") : "" }, { "agentStarted", StartedAt.ToString("o") }, { "agentPid", Process.GetCurrentProcess().Id },
                { "agentVersion", Version + " C#" }, { "engine", "csharp" }, { "intervalSec", CfgInt("checkIntervalSec", 30) }, { "lastUpdateCheck", ps.ContainsKey("meduzaLastCheck") ? ps["meduzaLastCheck"] : "" },
                { "inet", inet }, { "meduza", meduza }, { "ultra", ultra }, { "wg", wg }, { "ics", icsC }, { "zapret", zapret },
                { "perf", PerfInfo() }, { "modules", ModulesInfo() }, { "events", EventsInfo() }, { "traffic", new Dictionary<string, object> { { "names", adNames }, { "rate", TrafRate }, { "lan", new Dictionary<string, object> { { "on", LanH != WdInvalid }, { "net", LanNet }, { "error", LanError } } }, { "days", TrafDays.Reverse().Take(14).Reverse().Select(kv => (object)new Dictionary<string, object> { { "d", kv.Key }, { "u", kv.Value["u"] }, { "w", kv.Value["w"] }, { "p", kv.Value["p"] } }).ToArray() } } },
                { "counters", new Dictionary<string, object> { { "restarts", RestartCount }, { "reconnects", ReconnectCount }, { "icsFixes", IcsFixCount } } },
                { "vpn", new Dictionary<string, object> { { "mode", mode }, { "name", ModeNames[mode] }, { "uplink", upN }, { "kind", kind }, { "primary", DualPrimary() } } },
                { "amnezia", awg }, { "software", ps.ContainsKey("software") ? ps["software"] : new object[0] }, { "remote", ps.ContainsKey("remote") ? ps["remote"] : null }, { "app", ps.ContainsKey("app") ? ps["app"] : null },
                { "history", History.ToArray() } };
            var tmp = StatusPath + ".tmp";
            File.WriteAllText(tmp, Json.Serialize(snap), Bom);
            try { if (File.Exists(StatusPath)) File.Replace(tmp, StatusPath, null); else File.Move(tmp, StatusPath); } catch { File.Copy(tmp, StatusPath, true); File.Delete(tmp); }
        }
    }
}
