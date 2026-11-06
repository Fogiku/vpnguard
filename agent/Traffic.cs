// Трафик по адаптерам за сутки и «живые» скорости с историей для схемы.
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
        // ---------------------------------------------------------------- трафик
        static readonly Dictionary<string, long[]> TrafBase = new Dictionary<string, long[]>(); static readonly Dictionary<string, string> TrafId = new Dictionary<string, string>();
        static Dictionary<string, long[]> TrafPending = NewTraf(), TrafRate = NewTraf();
        static DateTime TrafAt = DateTime.MinValue, TrafSaved = DateTime.MinValue;
        static SortedDictionary<string, Dictionary<string, long[]>> TrafDays = new SortedDictionary<string, Dictionary<string, long[]>>();
        static Dictionary<string, long[]> NewTraf() { return new Dictionary<string, long[]> { { "u", new long[2] }, { "w", new long[2] }, { "p", new long[2] } }; }
        static void LoadTrafficDays()
        {
            try {
                var j = Json.DeserializeObject(File.ReadAllText(Path.Combine(DataDir, "traffic.json"), Encoding.UTF8)) as Dictionary<string, object>;
                var days = j["days"] as Dictionary<string, object>;
                foreach (var kv in days) { var d = (Dictionary<string, object>)kv.Value; var e = NewTraf(); foreach (var k in new[] { "u", "w", "p" }) { var a = d[k] as object[]; if (a != null) e[k] = new[] { Convert.ToInt64(a[0]), Convert.ToInt64(a[1]) }; } TrafDays[kv.Key] = e; }
            } catch { }
        }
        static Dictionary<string, string> UpdateTraffic()
        {
            var names = new Dictionary<string, string> { { "u", Mode() == "zapret" ? "" : UplinkName() }, { "w", WgIf() }, { "p", PhysAlias() } };
            LiveNames = names;
            var now = DateTime.Now; double sec = TrafAt == DateTime.MinValue ? 0 : Math.Max(1, (now - TrafAt).TotalSeconds);
            string day = now.ToString("yyyy-MM-dd"); if (!TrafDays.ContainsKey(day)) TrafDays[day] = NewTraf(); var today = TrafDays[day];
            var nics = new List<NetworkInterface>(); try { nics = NetworkInterface.GetAllNetworkInterfaces().ToList(); } catch { }
            foreach (var k in new[] { "u", "w", "p" }) {
                var n = names[k].Length > 0 ? nics.FirstOrDefault(x => x.Name == names[k]) : null;
                long[] d = new long[2];
                if (n != null) {
                    long rx = 0, tx = 0; try { var s = n.GetIPStatistics(); rx = s.BytesReceived; tx = s.BytesSent; } catch { }
                    long[] b; string id;
                    if (TrafBase.TryGetValue(k, out b) && TrafId.TryGetValue(k, out id) && id == n.Id) d = new[] { Math.Max(0, rx - b[0]), Math.Max(0, tx - b[1]) };
                    else if (TrafBase.ContainsKey(k) && k != "p") d = new[] { rx, tx };          // адаптер пересоздан — счёт с нуля
                    TrafBase[k] = new[] { rx, tx }; TrafId[k] = n.Id;
                } else { TrafBase.Remove(k); TrafId.Remove(k); }
                TrafPending[k] = new[] { TrafPending[k][0] + d[0], TrafPending[k][1] + d[1] };
                today[k] = new[] { today[k][0] + d[0], today[k][1] + d[1] };
                TrafRate[k] = sec > 0 ? new[] { (long)(d[0] / sec), (long)(d[1] / sec) } : new long[2];
            }
            TrafRate["l"] = LanRate("traf:l");
            TrafAt = now;
            while (TrafDays.Count > 31) TrafDays.Remove(TrafDays.Keys.First());
            if ((now - TrafSaved).TotalSeconds >= 60) {
                try {
                    var o = new Dictionary<string, object> { { "days", TrafDays.ToDictionary(kv => kv.Key, kv => (object)kv.Value.ToDictionary(x => x.Key, x => (object)x.Value)) } };
                    var tmp = Path.Combine(DataDir, "traffic.json.tmp"); File.WriteAllText(tmp, Json.Serialize(o), Bom); File.Copy(tmp, Path.Combine(DataDir, "traffic.json"), true); File.Delete(tmp); TrafSaved = now;
                } catch { }
            }
            return names;
        }

        // ---------------------------------------------------------------- «живые» скорости раз в 2 с (для схемы трафика в веб-интерфейсе): data\live.json
        // адаптеры (туннель, wg_server, физический) и ретранслятор zapret — каждые 2 с; клиенты WG-Server (wg show) — каждые 4 с
        static volatile Dictionary<string, string> LiveNames;
        // История скоростей пишется всегда (раз в секунду, последние LiveHistN секунд, в памяти) — открытая страница сразу рисует, что было.
        // Дёшево, пока никто не смотрит: адаптеры — из запомненного списка (полный перечень Windows — раз в 10 с), клиенты WG (wg.exe) —
        // раз в 10 с, файлы для браузера — раз в 30 с. Страница открыта (веб-сервер трогает data\live-wanted при /api/live) —
        // клиенты раз в 2 с, live.json каждую секунду, история — раз в 2 с.
        const int LiveHistN = 180;
        static readonly List<long> LiveT = new List<long>();
        static readonly Dictionary<string, List<long[]>> LiveH = new Dictionary<string, List<long[]>>();
        static void LivePush(string k, long[] v)
        {
            List<long[]> l; if (!LiveH.TryGetValue(k, out l)) { l = new List<long[]>(); for (int i = 0; i < LiveT.Count - 1; i++) l.Add(null); LiveH[k] = l; }
            l.Add(v);
        }
        static void LiveLoop()
        {
            PerfThread("живые скорости");
            string path = Path.Combine(DataDir, "live.json"), hpath = Path.Combine(DataDir, "live-hist.json"), want = Path.Combine(DataDir, "live-wanted");
            int tick = 0; Dictionary<string, object> peers = null; DateTime peersAt = DateTime.MinValue, nicsAt = DateTime.MinValue, histAt = DateTime.MinValue, liveAt = DateTime.MinValue;
            var nicByName = new Dictionary<string, NetworkInterface>();
            while (true) {
                try {
                    Thread.Sleep(1000); tick++;
                    var names = LiveNames; if (names == null) continue;
                    var lsw = System.Diagnostics.Stopwatch.StartNew(); long tNics = 0, tWg = 0;
                    bool watched = false; try { watched = File.Exists(want) && (DateTime.UtcNow - File.GetLastWriteTimeUtc(want)).TotalSeconds < 15; } catch { }
                    // адаптеры: перечень — раз в 10 с или когда нужного нет; счётчики берутся у запомненного объекта (это быстро)
                    if ((DateTime.UtcNow - nicsAt).TotalSeconds >= 10 || names.Values.Any(n => n.Length > 0 && !nicByName.ContainsKey(n))) {
                        nicByName.Clear(); nicsAt = DateTime.UtcNow;
                        try { foreach (var n in NetworkInterface.GetAllNetworkInterfaces()) nicByName[n.Name] = n; } catch { }
                        tNics = lsw.ElapsedMilliseconds;
                    }
                    var ad = new Dictionary<string, object>();
                    foreach (var kv in names) {
                        NetworkInterface n; if (kv.Value.Length == 0 || !nicByName.TryGetValue(kv.Value, out n)) { ad[kv.Key] = new long[2]; continue; }
                        long rx = 0, tx = 0; try { var st = n.GetIPStatistics(); rx = st.BytesReceived; tx = st.BytesSent; } catch { nicsAt = DateTime.MinValue; }
                        ad[kv.Key] = RateOf("live:" + kv.Key + ":" + n.Id, rx, tx);
                    }
                    ad["l"] = LanRate("live:l");
                    if (peers == null || (DateTime.UtcNow - peersAt).TotalSeconds >= (watched ? 2 : 10)) {
                        peersAt = DateTime.UtcNow;
                        var pr = new Dictionary<string, object>();
                        long w0 = lsw.ElapsedMilliseconds; var dump = WgDump(); tWg = lsw.ElapsedMilliseconds - w0;
                        if (dump != null) foreach (var l in dump.Skip(1)) {
                            var p = l.Split('\t'); if (p.Length < 7) continue;
                            string ip = Regex.Replace(p[3].Split(',')[0], @"/\d+$", ""); long rx, tx; long.TryParse(p[5], out rx); long.TryParse(p[6], out tx);
                            var rr = RateOf("live:wg:" + p[0], rx, tx);
                            var cs = CzClientStat(ip); long[] czr = cs != null ? (long[])cs["rate"] : new long[2];
                            pr[ip] = new Dictionary<string, object> { { "rx", rr[0] }, { "tx", rr[1] }, { "cz", czr } };
                        }
                        peers = pr;
                    }
                    var czRate = RateOf("live:cz", Interlocked.Read(ref CzTcpDown), Interlocked.Read(ref CzTcpUp));
                    if (lsw.ElapsedMilliseconds > 5000 && (DateTime.UtcNow - LiveSlowLogAt).TotalMinutes >= 10) {
                        LiveSlowLogAt = DateTime.UtcNow;
                        Log("Живые скорости: проход занял " + lsw.ElapsedMilliseconds / 1000 + " с (перечень адаптеров " + tNics + " мс, wg.exe " + tWg + " мс) — схема в это время не обновлялась", "WARN");
                    }
                    long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                    // история: точка в секунду
                    lock (LiveH) {
                        LiveT.Add(now);
                        foreach (var kv in ad) LivePush("r:" + kv.Key, (long[])kv.Value);
                        foreach (var kv in peers) { var d = (Dictionary<string, object>)kv.Value; LivePush("p:" + kv.Key, new[] { Convert.ToInt64(d["rx"]), Convert.ToInt64(d["tx"]) }); }
                        LivePush("cz", czRate);
                        foreach (var l in LiveH.Values) while (l.Count < LiveT.Count) l.Add(null);           // ряд без новой точки (клиент пропал)
                        while (LiveT.Count > LiveHistN) { LiveT.RemoveAt(0); foreach (var l in LiveH.Values) l.RemoveAt(0); }
                        foreach (var k in LiveH.Where(x => x.Value.All(v => v == null)).Select(x => x.Key).ToList()) LiveH.Remove(k);
                    }
                    if (watched || (DateTime.UtcNow - liveAt).TotalSeconds >= 30) {
                        liveAt = DateTime.UtcNow;
                        var o = new Dictionary<string, object> { { "t", now }, { "rate", ad }, { "cz", czRate }, { "peers", peers }, { "inet", InetLive() } };
                        File.WriteAllText(path + ".tmp", Json.Serialize(o), Encoding.UTF8); try { File.Copy(path + ".tmp", path, true); } catch { }
                    }
                    if ((DateTime.UtcNow - histAt).TotalSeconds >= (watched ? 2 : 30)) {
                        histAt = DateTime.UtcNow; string js;
                        lock (LiveH) js = Json.Serialize(new Dictionary<string, object> { { "t", LiveT.ToArray() }, { "s", LiveH.ToDictionary(x => x.Key, x => (object)x.Value.ToArray()) } });
                        File.WriteAllText(hpath + ".tmp", js, Encoding.UTF8); try { File.Copy(hpath + ".tmp", hpath, true); } catch { }
                    }
                } catch { Thread.Sleep(5000); }
            }
        }
        static DateTime LiveSlowLogAt = DateTime.MinValue;
        // скорость (байт/с) по приращению счётчиков между снимками состояния
        static readonly Dictionary<string, KeyValuePair<DateTime, long[]>> RatePrev = new Dictionary<string, KeyValuePair<DateTime, long[]>>();
        static long[] RateOf(string key, params long[] vals)
        {
            lock (RatePrev) {
                KeyValuePair<DateTime, long[]> p; var now = DateTime.UtcNow; var res = new long[vals.Length];
                if (RatePrev.TryGetValue(key, out p) && p.Value.Length == vals.Length) {
                    double dt = (now - p.Key).TotalSeconds;
                    if (dt < 1) return RatePrevRes.ContainsKey(key) ? RatePrevRes[key] : res;
                    for (int i = 0; i < vals.Length; i++) res[i] = vals[i] >= p.Value[i] ? (long)((vals[i] - p.Value[i]) / dt) : 0;
                }
                RatePrev[key] = new KeyValuePair<DateTime, long[]>(now, vals); RatePrevRes[key] = res;
                return res;
            }
        }
        static readonly Dictionary<string, long[]> RatePrevRes = new Dictionary<string, long[]>();
    }
}
