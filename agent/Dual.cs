// Режим «два туннеля»: активный и резерв, переключение, маршруты, сервер резерва напрямую.
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
        // ---------------------------------------------------------------- режим «два туннеля» (dual): оба подняты, трафик (и раздача) — через активный; упал — сразу на другой
        static string DualActive = "", DualReason = ""; static int DualFails, DualSwitches; static DateTime DualSwitchAt = DateTime.MinValue, DualOkSince = DateTime.MinValue;
        static readonly List<KeyValuePair<int, string>> DualRoutes = new List<KeyValuePair<int, string>>();   // маршруты, добавленные агентом: индекс адаптера, префикс
        static string DualPrimary() { return CfgStr("vpn.primary", "meduza") == "amnezia" ? "amnezia" : "meduza"; }
        static string DualAct()
        {
            if (DualActive.Length == 0 && !DualLoaded) {
                DualLoaded = true;
                try {
                    var f = Path.Combine(DataDir, "dual-active.txt");
                    if (!TestMode && File.Exists(f) && (DateTime.Now - File.GetLastWriteTime(f)).TotalHours < 12) { var k = File.ReadAllText(f).Trim(); if (k == "meduza" || k == "amnezia") DualActive = k; }
                } catch { }
            }
            return DualActive == "meduza" || DualActive == "amnezia" ? DualActive : DualPrimary();
        }
        static bool DualLoaded;
        static string OtherKind(string k) { return k == "meduza" ? "amnezia" : "meduza"; }
        // какой VPN несёт трафик сейчас: meduza | amnezia | "" (без VPN)
        static string TunnelKind() { var m = Mode(); return m == "dual" ? DualAct() : m == "zapret" ? "" : m; }
        static string KindAdapter(string k) { return k == "meduza" ? MzAdapterName() : k == "amnezia" ? AvpnAdapter() : ""; }
        static bool? KindTraffic(string k) { return k == "amnezia" ? AwgTraffic : LastTraffic; }
        // быстрая проверка туннеля: адаптер поднят и через него открываются узлы проверки
        static bool KindOk(string k)
        {
            if (KindOkHook != null) return KindOkHook(k);          // самопроверка (SelfTest.cs)
            var n = KindAdapter(k); if (string.IsNullOrEmpty(n) || !Up(n)) return false;
            string ip = Ipv4(n); if (ip == null) return false;
            return Probe(ip, ProbeHosts(), 3000).Ok;
        }
        static void KindWatch(string k) { if (k == "meduza") MeduzaWatch(); else AmneziaWatch(); }
        static void StopKind(string k)
        {
            if (k == "meduza") { if (Up(MzAdapterName())) { Log("MeduzaVPN: отключаю (резерв поднимается только при сбое)", "INFO"); MzDisconnect(); } }
            else AvpnDisable(false);
        }
        static readonly object DualLock = new object();
        static void DualSwitch(string k, string reason) { lock (DualLock) DualSwitchCore(k, reason); }
        static void DualSwitchCore(string k, string reason)
        {
            string from = DualAct(); if (from == k) return;
            DualActive = k; DualSwitchAt = DateTime.Now; DualSwitches++;
            if (!TestMode) { try { File.WriteAllText(Path.Combine(DataDir, "dual-active.txt"), k); } catch { } } DualReason = reason; DualFails = 0; DualOkSince = DateTime.MinValue;
            Log("Два туннеля: трафик переключён " + ModeNames[from] + " → " + ModeNames[k] + " — " + reason, "WARN");
            try { DualSyncRoutes(); } catch (Exception e) { Log("Два туннеля: маршруты: " + e.Message, "ERROR"); }
            Emit("tunnel.switched", ModeNames[from] + " → " + ModeNames[k]); ProbeFailures = 0;
        }

        // маршруты и метрики (root\StandardCimv2 — то же, что Get-NetRoute / Get-NetIPInterface)
        static List<ManagementBaseObject> Cim(string q)
        {
            try { using (var s = new ManagementObjectSearcher(new ManagementScope(@"\\.\root\StandardCimv2"), new ObjectQuery(q))) return s.Get().Cast<ManagementBaseObject>().ToList(); }
            catch { return new List<ManagementBaseObject>(); }
        }
        static void SetIfMetric(int idx, int metric) { if (IfMetric(idx) != metric) Exe("netsh.exe", "interface ipv4 set interface " + idx + " metric=" + metric, 15); }
        static bool HasRoute(int idx, string pfx) { return RouteTable().Any(r => r.IfIndex == idx && Prefix(r) == pfx); }
        // у активного — половинки 0.0.0.0/1 + 128.0.0.0/1 (сильнее любого 0.0.0.0/0) и метрика выше физического выхода
        // (чтобы клиенты WireGuard не уходили в него); у резервного — метрика 5000

        static string DualSyncSig = ""; static DateTime DualSyncAt = DateTime.MinValue;
        static void DualSyncRoutes() { if (TestMode) return; lock (DualLock) DualSyncRoutesCore(); }
        static void DualSyncRoutesCore()
        {
            string sig = DualAct() + "|" + string.Join("|", new[] { "meduza", "amnezia" }.Select(k => { var n = KindAdapter(k); return n + ":" + Up(n) + ":" + IfIndexOf(n); }));
            if (sig == DualSyncSig && (DateTime.Now - DualSyncAt).TotalMinutes < 2) return;
            DualSyncSig = sig; DualSyncAt = DateTime.Now;
            string act = DualAct(); int physM = 25, best = int.MaxValue;
            foreach (var r in Cim("SELECT InterfaceIndex, InterfaceAlias, RouteMetric, NextHop FROM MSFT_NetRoute WHERE DestinationPrefix='0.0.0.0/0' AND AddressFamily=2")) {
                string al = Convert.ToString(r["InterfaceAlias"]), nh = Convert.ToString(r["NextHop"]);
                if (IsTunnel(al) || nh == "0.0.0.0") continue;
                int m = Convert.ToInt32(r["RouteMetric"]) + Math.Max(0, IfMetric(Convert.ToInt32(r["InterfaceIndex"])));
                if (m < best) best = m;
            }
            if (best != int.MaxValue) physM = best;
            foreach (var k in new[] { "meduza", "amnezia" }) {
                string n = KindAdapter(k); if (string.IsNullOrEmpty(n) || !Up(n)) continue;
                int idx = IfIndexOf(n); if (idx <= 0) continue;
                if (k != act) { SetIfMetric(idx, 5000); continue; }
                var own0 = Cim("SELECT RouteMetric FROM MSFT_NetRoute WHERE DestinationPrefix='0.0.0.0/0' AND InterfaceIndex=" + idx);
                if (own0.Count > 0) SetIfMetric(idx, Math.Min(4000, Math.Max(1, physM - own0.Min(o => Convert.ToInt32(o["RouteMetric"])) + 10)));
                else if (IfMetric(idx) >= 5000) SetIfMetric(idx, 5);
                foreach (var pfx in new[] { "0.0.0.0/1", "128.0.0.0/1" }) {
                    if (HasRoute(idx, pfx)) continue;
                    var x = Exe("netsh.exe", "interface ipv4 add route " + pfx + " " + idx + " 0.0.0.0 metric=0 store=active", 15);
                    if (x.Code == 0) { lock (DualRoutes) DualRoutes.Add(new KeyValuePair<int, string>(idx, pfx)); Log("Два туннеля: добавлен маршрут " + pfx + " через " + n, "INFO"); }
                    else Log("Два туннеля: не удалось добавить маршрут " + pfx + " через " + n + ": " + (x.Out + " " + x.Err).Trim(), "WARN");
                }
            }
        }
        // выход из режима: убрать наши маршруты и вернуть автоматические метрики
        static void DualResetRoutes()
        {
            List<KeyValuePair<int, string>> rs; lock (DualRoutes) { rs = DualRoutes.ToList(); DualRoutes.Clear(); }
            foreach (var r in rs) Exe("netsh.exe", "interface ipv4 delete route " + r.Value + " " + r.Key + " 0.0.0.0 store=active", 15);
            foreach (var k in new[] { "meduza", "amnezia" }) {
                string n = KindAdapter(k); int idx = string.IsNullOrEmpty(n) ? 0 : IfIndexOf(n); if (idx <= 0) continue;
                Exe("powershell.exe", "-NoProfile -Command Set-NetIPInterface -InterfaceIndex " + idx + " -AddressFamily IPv4 -AutomaticMetric Enabled", 30);
            }
        }
        // во время восстановления одного туннеля (перебор протоколов, перезапуск) — если он не работает, а другой работает, трафик сразу на другой
        // ---- сравнение туннелей: отклик и надёжность (несколько проверок узлов) и скорость загрузки через каждый
        class TunMeas { public string Kind; public int Ok, Total; public long Ms = -1; public double Mbit = -1; }
        static bool DualNeedCmp = true; static DateTime DualBothOkSince = DateTime.MinValue; static Dictionary<string, object> DualCmp;
        static TunMeas MeasureKind(string k)
        {
            var m = new TunMeas { Kind = k }; var n = KindAdapter(k); string ip = !string.IsNullOrEmpty(n) && Up(n) ? Ipv4(n) : null; if (ip == null) return m;
            var all = new List<long>();
            for (int i = 0; i < 3; i++) { var r = ProbeAll(ip, ProbeHosts(), 3000); m.Ok += r.OkCount; m.Total += r.Total; all.AddRange(r.Ms); Thread.Sleep(300); }
            if (all.Count > 0) { all.Sort(); m.Ms = all[all.Count / 2]; }
            if (m.Ok > 0 && CfgBool("vpn.compareSpeed", true)) {
                var errs = new List<string>();
                foreach (var url in new[] { CfgStr("vpn.speedUrl", "https://speed.cloudflare.com/__down?bytes=4000000"), "http://speedtest.tele2.net/1MB.zip", "https://proof.ovh.net/files/1Mb.dat" }.Distinct()) {
                    var r = Exe(Curl, "-s -L -o NUL -A \"Mozilla/5.0\" -w \"%{speed_download} %{http_code} %{size_download}\" --interface " + ip + " --connect-timeout 5 -m 12 \"" + url + "\"", 16);
                    var p = r.Out.Trim().Trim('"').Split(' '); double bps; long size;
                    if (p.Length >= 3 && p[1] == "200" && long.TryParse(p[2], out size) && size >= 200000 &&
                        double.TryParse(p[0].Replace(',', '.'), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out bps) && bps > 0) { m.Mbit = Math.Round(bps * 8 / 1e6, 1); break; }
                    errs.Add(new Uri(url).Host + ": код curl " + r.Code + (p.Length >= 2 ? ", HTTP " + p[1] : "") + (p.Length >= 3 ? ", " + p[2] + " Б" : ""));
                }
                if (m.Mbit < 0) Log("Два туннеля: скорость через " + ModeNames[k] + " не измерилась (" + string.Join("; ", errs) + ")", "INFO");
            }
            return m;
        }
        static string MeasTxt(TunMeas m) { return ModeNames[m.Kind] + ": " + (m.Total == 0 ? "не подключён" : "ответило " + m.Ok + "/" + m.Total + (m.Ms >= 0 ? ", отклик " + m.Ms + " мс" : "") + (m.Mbit > 0 ? ", " + m.Mbit + " Мбит/с" : "")); }
        // кто лучше: заметно надёжнее → заметно быстрее → заметно меньше отклик; примерно одинаковы — остаться на текущем (переключение стоит клиентам секунд связи)
        static string DualPick(TunMeas a, TunMeas b, string cur, out string why)
        {
            double ra = a.Total > 0 ? (double)a.Ok / a.Total : 0, rb = b.Total > 0 ? (double)b.Ok / b.Total : 0;
            if (Math.Abs(ra - rb) >= 0.2) { var w = ra > rb ? a : b; why = ModeNames[w.Kind] + " надёжнее (ответило " + Math.Round(100 * Math.Max(ra, rb)) + "% проверок против " + Math.Round(100 * Math.Min(ra, rb)) + "%)"; return w.Kind; }
            if (a.Mbit > 0 && b.Mbit > 0) {
                var f = a.Mbit >= b.Mbit ? a : b; var s = f == a ? b : a;
                if (f.Mbit >= 1.5 * s.Mbit && f.Mbit - s.Mbit >= 3) { why = ModeNames[f.Kind] + " быстрее (" + f.Mbit + " против " + s.Mbit + " Мбит/с)"; return f.Kind; }
            }
            if (a.Ms > 0 && b.Ms > 0) {
                var f = a.Ms <= b.Ms ? a : b; var s = f == a ? b : a;
                if (s.Ms >= 1.5 * f.Ms && s.Ms - f.Ms >= 40) { why = ModeNames[f.Kind] + " отзывчивее (отклик " + f.Ms + " против " + s.Ms + " мс)"; return f.Kind; }
            }
            why = "туннели примерно одинаковы — остаюсь на " + ModeNames[cur]; return cur;
        }
        static void DualCompare(string reason)
        {
            if (Mode() != "dual") return;
            SetActivity("сравниваю туннели");
            var a = MeasureKind("meduza"); var b = MeasureKind("amnezia"); string cur = DualAct(), why; var win = DualPick(a, b, cur, out why);
            DualCmp = new Dictionary<string, object> { { "at", DateTime.Now.ToString("o") }, { "reason", reason }, { "winner", win }, { "why", why },
                { "results", new object[] { a, b }.Cast<TunMeas>().Select(m => (object)new Dictionary<string, object> { { "kind", m.Kind }, { "name", ModeNames[m.Kind] }, { "ok", m.Ok }, { "total", m.Total }, { "ms", m.Ms }, { "mbit", m.Mbit } }).ToArray() } };
            Log("Два туннеля: сравнение (" + reason + ") — " + MeasTxt(a) + "; " + MeasTxt(b) + " → " + why, "INFO");
            if (win != cur && KindOk(win)) DualSwitch(win, "лучше по сравнению: " + why);
        }
        // VPN-приложение при подключении «прибивает» адрес своего сервера к текущему маршруту по умолчанию. Подключился AmneziaVPN, когда
        // трафик шёл через MeduzaVPN, — его сервер оказывается внутри MeduzaVPN: упал MeduzaVPN — падают оба, и MeduzaVPN видит «другой VPN».
        // Такие адреса (/32 на адаптере туннеля, без прямого маршрута; не широковещательные и не частные) — пустить напрямую через физический адаптер
        static readonly Dictionary<string, string> EpPins = new Dictionary<string, string>();
        static void PinEndpoints()
        {
            if (TestMode) return;
            var phys = ZPhys(); if (phys == null || string.IsNullOrEmpty(phys.Gateway)) return;
            var table = RouteTable();
            var direct = new HashSet<string>(table.Where(r => r.IfIndex == phys.IfIndex).Select(Prefix));
            foreach (var k in new[] { "meduza", "amnezia" }) {
                var n = KindAdapter(k); if (string.IsNullOrEmpty(n) || !Up(n)) continue;
                int idx = IfIndexOf(n); if (idx <= 0) continue; string own = Ipv4(n);
                var rows = table.Where(r => r.IfIndex == idx).ToList();
                var bcast = new HashSet<string>();
                foreach (var r in rows) { var pp = Prefix(r).Split('/'); int len = int.Parse(pp[1]); if (len >= 32) continue; uint m = len == 0 ? 0 : 0xFFFFFFFFu << (32 - len); bcast.Add(IpS(IpH(pp[0]) | ~m) + "/32"); }
                foreach (var r in rows) {
                    var p = Prefix(r); if (!p.EndsWith("/32") || bcast.Contains(p) || direct.Contains(p)) continue;
                    var ip = p.Split('/')[0];
                    if (ip == own || System.Text.RegularExpressions.Regex.IsMatch(ip, @"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|22[4-9]\.|23\d\.|24\d\.|25[0-5]\.)")) continue;
                    if (RouteAdd(p, phys.IfIndex, phys.Gateway, Math.Max(0, IfMetric(phys.IfIndex)))) {
                        EpPins[p] = k; direct.Add(p);
                        Log("Два туннеля: адрес " + ip + " (сервер другого VPN) шёл через туннель " + ModeNames[k] + " — при его сбое падали бы оба. Пускаю этот адрес напрямую", "WARN");
                    }
                }
            }
        }
        static void DualMidCheck()
        {
            if (Mode() != "dual" || !CfgBool("vpn.dualHot", true)) return;
            string act = DualAct(), oth = OtherKind(act);
            if (!KindOk(act) && KindOk(oth)) DualSwitch(oth, ModeNames[act] + " не работает — восстанавливаю его, трафик пока через " + ModeNames[oth]);
        }
        static void DualWatch()
        {
            bool hot = CfgBool("vpn.dualHot", true);
            try { PinEndpoints(); } catch (Exception e) { Log("Два туннеля: адреса серверов VPN: " + e.Message, "WARN"); }
            string act = DualAct(), oth = OtherKind(act);
            // 1. быстрая проверка активного — до долгого восстановления, чтобы клиенты не ждали
            bool actUp = Up(KindAdapter(act)), actOk = false; PerfRun("VpnWatch/проверка активного", () => { actOk = actUp && KindOk(act); });
            bool grace = act == "meduza" && (DateTime.Now - MeduzaStartedAt).TotalSeconds < CfgInt("meduza.startupGraceSec", 60);
            if (actOk || grace) DualFails = 0; else DualFails++;
            int need = Math.Max(1, CfgInt("vpn.failoverChecks", 2));
            if (!actOk && !grace && (DualFails >= need || !actUp)) {
                if (hot) {
                    if (KindOk(oth)) DualSwitch(oth, ModeNames[act] + (actUp ? " не пропускает трафик" : " отключился"));
                    else if (DualFails == need) Log("Два туннеля: " + ModeNames[act] + " не работает, резерв " + ModeNames[oth] + " тоже — восстанавливаю", "WARN");
                } else {
                    Log("Два туннеля: " + ModeNames[act] + " не работает — поднимаю резерв " + ModeNames[oth], "WARN");
                    try { KindWatch(oth); } catch (Exception e) { Log(ModeNames[oth] + ": " + e.Message, "ERROR"); }
                    var dl = DateTime.Now.AddSeconds(30); while (DateTime.Now < dl && !KindOk(oth)) Thread.Sleep(3000);
                    if (KindOk(oth)) { DualSwitch(oth, ModeNames[act] + " не работает"); StopKind(act); }
                }
            }
            // 2. наблюдение и восстановление: оба (горячий резерв) или только активный
            act = DualAct();
            try { DualSyncRoutes(); } catch { }
            if (hot) {
                bool actBad = false; PerfRun("VpnWatch/проверка активного 2", () => { actBad = !KindOk(act); });
                foreach (var k in actBad ? new[] { OtherKind(act), act } : new[] { act, OtherKind(act) }) {
                    try { var kk = k; PerfRun("VpnWatch/" + ModeNames[k], () => KindWatch(kk)); } catch (Exception e) { Log(ModeNames[k] + ": " + e.Message, "ERROR"); }
                    if (actBad && k != act) DualMidCheck();               // резерв в порядке — трафик на него до того, как чинить основной
                }
            }
            else { KindWatch(act); StopKind(OtherKind(act)); }
            // 3. был сбой (или агент только запустился), а теперь оба туннеля работают N минут — сравнить их и пустить трафик через лучший
            int fb = CfgInt("vpn.failbackMin", 3);
            if (hot && fb > 0) {
                bool both = new[] { "meduza", "amnezia" }.All(k => KindTraffic(k) == true && Up(KindAdapter(k)));
                if (!both) { DualBothOkSince = DateTime.MinValue; DualNeedCmp = true; }
                else if (DualBothOkSince == DateTime.MinValue) DualBothOkSince = DateTime.Now;
                else if (DualNeedCmp && (DateTime.Now - DualBothOkSince).TotalMinutes >= fb && !InetBad()) { DualNeedCmp = false; DualCompare("оба туннеля работают " + fb + " мин после сбоя"); }
            }
            try { DualSyncRoutes(); } catch { }
        }

        // для окна и веба (сводка): часть «Туннель»
        static Dictionary<string, object> TunnelComp(string mode, string kind)
        {
            string tun = mode == "zapret" ? "" : KindAdapter(kind); var ma = Nic(tun);
            bool uUp = ma != null && ma.OperationalStatus == OperationalStatus.Up;
            if (uUp) { if (UltraUpSince == DateTime.MinValue) UltraUpSince = DateTime.Now; } else UltraUpSince = DateTime.MinValue;
            string uIp = ma != null ? Ipv4(tun) : null;
            // Туннель
            bool amz = kind == "amnezia"; bool? tTr = amz ? AwgTraffic : LastTraffic; DateTime tTrAt = amz ? AwgTrafficAt : LastTrafficAt; int tFail = amz ? AwgProbeFailures : ProbeFailures; string tWhy = amz ? AwgLastReason : LastRestartReason;
            int uL; string uS;
            if (mode == "zapret") { uL = 0; uS = "VPN выключен — напрямую"; } else if (amz && tun.Length == 0) { uL = 2; uS = "AmneziaVPN не подключён"; } else if (!uUp) { uL = 2; uS = "Отключён"; } else if (tTr == false) { uL = 1; uS = "Нет трафика"; } else { uL = 0; uS = "Подключён"; }
            if (InetDown() && mode != "zapret") { uL = 2; uS = "Нет интернета — жду связь"; }
            string kindTitle = amz ? "AmneziaVPN" : "MeduzaVPN · " + MzProtocol();
            string trTxt = (tTr == true ? "OK" : tTr == false ? "НЕТ" : "—");
            Dictionary<string, object> sb = null;
            if (mode == "dual") {
                string oth = OtherKind(kind); bool othUp = Up(KindAdapter(oth)); bool? othTr = KindTraffic(oth);
                sb = new Dictionary<string, object> { { "kind", oth }, { "name", ModeNames[oth] }, { "up", othUp }, { "ok", othUp && othTr == true },
                    { "state", !othUp ? "не подключён" : othTr == true ? "готов" : othTr == false ? "нет трафика" : "проверяется" },
                    { "blocked", oth == "amnezia" && AvpnBlocked() }, { "why", oth == "amnezia" && AwgDiag != null && !AwgDiag.Ok ? AwgDiag.Short : "" } };
                if (oth == "amnezia" && AvpnBlocked()) sb["state"] = "отключён защитой до " + AgBlockedUntil.ToString("HH:mm");
                if (uL == 0) uS = othUp && othTr == true ? "Подключён · резерв готов" : "Подключён · резерв не готов";
            }
            var dualKv = mode != "dual" ? new List<object[]>() : new List<object[]> {
                Kv("Трафик идёт через", ModeNames[kind] + (kind == DualPrimary() ? " (основной)" : " (резервный)")),
                Kv("Переключений", DualSwitches + (DualSwitches > 0 ? " · последнее " + When(DualSwitchAt) + ": " + DualReason : "")),
                Kv("Резерв", (CfgBool("vpn.dualHot", true) ? "горячий — оба туннеля подняты" : "холодный — поднимается при сбое") + (CfgInt("vpn.failbackMin", 3) > 0 ? ", после сбоя — сравнение через " + CfgInt("vpn.failbackMin", 3) + " мин и выбор лучшего" : "")),
                Kv("Сравнение туннелей", DualCmp == null ? "ещё не было" : When(DateTime.Parse(Convert.ToString(DualCmp["at"]))) + ": " + DualCmp["why"]) };
            var ultra = Comp(uL, uS, new[] { mode == "zapret" ? "Выход: " + PhysAlias() + " · YouTube/Discord — через zapret" : "",
                sb != null ? "Резерв: " + sb["name"] + " — " + sb["state"] + " · переключений: " + DualSwitches : "",
                "Адаптер: " + (ma != null ? tun + " · " + ma.OperationalStatus + ", IP " + uIp : mode == "zapret" ? "не нужен" : "отсутствует"),
                "Трафик: " + trTxt + ", проверка " + When(tTrAt), "Сбоев проверки подряд: " + tFail, tWhy.Length > 0 ? "Последняя причина: " + tWhy : "" }, new List<object[]> {
                Kv("Режим", ModeNames[mode]), dualKv.Count > 0 ? dualKv[0] : null, dualKv.Count > 1 ? dualKv[1] : null, dualKv.Count > 2 ? dualKv[2] : null, dualKv.Count > 3 ? dualKv[3] : null, Kv("Адаптер", ma != null ? tun + " · " + ma.OperationalStatus + " · " + ma.Description : "отсутствует"), Kv("IP", uIp ?? "—"),
                Kv("Скорость канала", ma != null ? (ma.Speed / 1000000) + " Мбит/с" : "—"), Kv("Подключён с", UltraUpSince == DateTime.MinValue ? "—" : When(UltraUpSince)),
                Kv("Протокол", kind == "meduza" ? MzProtocol() : amz ? "выбран в AmneziaVPN" : "—"), Kv("Проверка трафика", trTxt + " · " + When(tTrAt)), Kv("Узлы проверки", string.Join(", ", ProbeHosts())),
                Kv("Сбоев проверки подряд", tFail + " (переподключение после " + CfgInt("meduza.probeFailuresBeforeReconnect", 3) + ")"), Kv("Переподключений с запуска агента", ReconnectCount) });
            ultra["title"] = mode == "zapret" ? "Без VPN (только zapret)" : "Туннель: " + kindTitle; ultra["kind"] = kind; ultra["standby"] = sb; ultra["switches"] = DualSwitches; ultra["compare"] = DualCmp;
            return ultra;
        }
    }
}
