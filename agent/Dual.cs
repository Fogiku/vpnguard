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
        static string DualAct() { return DualActive == "meduza" || DualActive == "amnezia" ? DualActive : DualPrimary(); }
        static string OtherKind(string k) { return k == "meduza" ? "amnezia" : "meduza"; }
        // какой VPN несёт трафик сейчас: meduza | amnezia | "" (без VPN)
        static string TunnelKind() { var m = Mode(); return m == "dual" ? DualAct() : m == "zapret" ? "" : m; }
        static string KindAdapter(string k) { return k == "meduza" ? MzAdapterName() : k == "amnezia" ? AvpnAdapter() : ""; }
        static bool? KindTraffic(string k) { return k == "amnezia" ? AwgTraffic : LastTraffic; }
        // быстрая проверка туннеля: адаптер поднят и через него открываются узлы проверки
        static bool KindOk(string k)
        {
            var n = KindAdapter(k); if (string.IsNullOrEmpty(n) || !Up(n)) return false;
            string ip = Ipv4(n); if (ip == null) return false;
            return AnyVia(ip, ProbeHosts(), 3000);
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
            DualActive = k; DualSwitchAt = DateTime.Now; DualSwitches++; DualReason = reason; DualFails = 0; DualOkSince = DateTime.MinValue;
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
        // сервер AmneziaVPN — всегда напрямую через роутер. Иначе в режиме «два туннеля» его зашифрованный трафик идёт внутри MeduzaVPN
        // (маршруты 0.0.0.0/1 активного забирают всё), и резерв умирает вместе с основным. Адрес — из конфига туннеля (Endpoint = …)
        static string AvpnEp = "", AvpnEpConf = "", AvpnEpPinned = ""; static DateTime AvpnEpAt = DateTime.MinValue;
        static readonly List<string[]> EpRoutes = new List<string[]>();     // prefix, ifIndex, gw
        static string AvpnEndpoint()
        {
            if ((DateTime.Now - AvpnEpAt).TotalSeconds < (AvpnEp.Length > 0 ? 300 : 600)) return AvpnEp;     // не нашли — следующая попытка через 10 мин
            AvpnEpAt = DateTime.Now;
            var confs = new List<string>();
            try {
                using (var svcs = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                    foreach (var n in svcs.GetSubKeyNames().Where(x => x.IndexOf("Amnezia", StringComparison.OrdinalIgnoreCase) >= 0))
                        using (var k = svcs.OpenSubKey(n)) {
                            var ip = k == null ? null : Convert.ToString(k.GetValue("ImagePath"));
                            if (string.IsNullOrEmpty(ip)) continue;
                            foreach (Match m in Regex.Matches(ip, @"""([^""]+\.conf)""|(\S+\.conf)")) confs.Add(m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value);
                        }
            } catch { }
            foreach (var root in new[] { Path.Combine(Environment.SystemDirectory, @"config\systemprofile\AppData"), Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"C:\Program Files\AmneziaVPN" }) {
                try {
                    if (!Directory.Exists(root)) continue;
                    foreach (var d in Directory.GetDirectories(root, "*", SearchOption.TopDirectoryOnly).Concat(Directory.GetDirectories(root, "*", SearchOption.TopDirectoryOnly).SelectMany(x => { try { return Directory.GetDirectories(x); } catch { return new string[0]; } })))
                        if (d.IndexOf("amnezia", StringComparison.OrdinalIgnoreCase) >= 0)
                            try { confs.AddRange(Directory.GetFiles(d, "*.conf", SearchOption.AllDirectories)); } catch { }
                } catch { }
            }
            foreach (var f in confs.Distinct().Where(File.Exists).OrderByDescending(f => File.GetLastWriteTime(f))) {
                try {
                    var m = Regex.Match(File.ReadAllText(f), @"(?im)^\s*Endpoint\s*=\s*\[?([^\]\s:]+)\]?:(\d+)");
                    if (!m.Success) continue;
                    string host = m.Groups[1].Value; IPAddress a;
                    if (!IPAddress.TryParse(host, out a)) a = Dns.GetHostAddresses(host).FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
                    if (a == null || a.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (AvpnEp != a.ToString()) Log("AmneziaVPN: сервер туннеля " + a + (host != a.ToString() ? " (" + host + ")" : "") + " — из " + f, "INFO");
                    AvpnEp = a.ToString(); AvpnEpConf = f; return AvpnEp;
                } catch { }
            }
            return AvpnEp;
        }
        static void PinEndpoints()
        {
            if (!CfgBool("vpn.pinReserveServer", true)) { UnpinEndpoints(); return; }
            var ep = AvpnEndpoint(); var phys = ZPhys();
            if (string.IsNullOrEmpty(ep) || phys == null || string.IsNullOrEmpty(phys.Gateway)) return;
            string pfx = ep + "/32";
            bool have = RouteTable().Any(r => Prefix(r) == pfx && r.IfIndex == phys.IfIndex && UIp(r.NextHop) == phys.Gateway);
            if (have && AvpnEpPinned == pfx) return;
            if (AvpnEpPinned.Length > 0 && AvpnEpPinned != pfx) UnpinEndpoints();
            if (have || RouteAdd(pfx, phys.IfIndex, phys.Gateway, 0)) {
                lock (EpRoutes) if (!EpRoutes.Any(x => x[0] == pfx)) EpRoutes.Add(new[] { pfx, phys.IfIndex.ToString(), phys.Gateway });
                if (AvpnEpPinned != pfx) Log("Два туннеля: сервер AmneziaVPN " + ep + " — напрямую через " + phys.Alias + " (не через MeduzaVPN), чтобы резерв не падал вместе с основным", "INFO");
                AvpnEpPinned = pfx;
            } else Log("Два туннеля: не удалось направить сервер AmneziaVPN " + ep + " напрямую", "WARN");
        }
        static void UnpinEndpoints()
        {
            List<string[]> rs; lock (EpRoutes) { rs = EpRoutes.ToList(); EpRoutes.Clear(); }
            foreach (var r in rs) RouteDel(r[0], int.Parse(r[1]), r[2]);
            AvpnEpPinned = "";
        }

        static string DualSyncSig = ""; static DateTime DualSyncAt = DateTime.MinValue;
        static void DualSyncRoutes() { lock (DualLock) DualSyncRoutesCore(); }
        static void DualSyncRoutesCore()
        {
            string sig = DualAct() + "|" + string.Join("|", new[] { "meduza", "amnezia" }.Select(k => { var n = KindAdapter(k); return n + ":" + Up(n) + ":" + IfIndexOf(n); }));
            if (sig == DualSyncSig && (DateTime.Now - DualSyncAt).TotalMinutes < 2) return;
            DualSyncSig = sig; DualSyncAt = DateTime.Now;
            try { PinEndpoints(); } catch (Exception e) { Log("Два туннеля: сервер AmneziaVPN: " + e.Message, "WARN"); }
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
            try { UnpinEndpoints(); } catch { }
            List<KeyValuePair<int, string>> rs; lock (DualRoutes) { rs = DualRoutes.ToList(); DualRoutes.Clear(); }
            foreach (var r in rs) Exe("netsh.exe", "interface ipv4 delete route " + r.Value + " " + r.Key + " 0.0.0.0 store=active", 15);
            foreach (var k in new[] { "meduza", "amnezia" }) {
                string n = KindAdapter(k); int idx = string.IsNullOrEmpty(n) ? 0 : IfIndexOf(n); if (idx <= 0) continue;
                Exe("powershell.exe", "-NoProfile -Command Set-NetIPInterface -InterfaceIndex " + idx + " -AddressFamily IPv4 -AutomaticMetric Enabled", 30);
            }
        }
        // во время восстановления одного туннеля (перебор протоколов, перезапуск) — если он не работает, а другой работает, трафик сразу на другой
        static void DualMidCheck()
        {
            if (Mode() != "dual" || !CfgBool("vpn.dualHot", true)) return;
            string act = DualAct(), oth = OtherKind(act);
            if (!KindOk(act) && KindOk(oth)) DualSwitch(oth, ModeNames[act] + " не работает — восстанавливаю его, трафик пока через " + ModeNames[oth]);
        }
        static void DualWatch()
        {
            bool hot = CfgBool("vpn.dualHot", true);
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
            // 3. основной снова работает N минут — вернуть трафик на него
            string prim = DualPrimary(); int fb = CfgInt("vpn.failbackMin", 5);
            if (hot && DualAct() != prim && fb > 0) {
                bool pOk = KindTraffic(prim) == true && Up(KindAdapter(prim));
                if (!pOk) DualOkSince = DateTime.MinValue;
                else if (DualOkSince == DateTime.MinValue) DualOkSince = DateTime.Now;
                else if ((DateTime.Now - DualOkSince).TotalMinutes >= fb) DualSwitch(prim, "основной туннель работает уже " + fb + " мин");
            }
            try { DualSyncRoutes(); } catch { }
        }
    }
}
