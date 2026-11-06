// Раздача ICS: общий доступ из туннеля в wg_server (HNetCfg через COM, записи HomeNet).
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
        // ---------------------------------------------------------------- раздача ICS (HNetCfg через COM, записи HomeNet через WMI)
        class IcsConn { public string Name, Device, Guid; public bool Enabled; public int Type; public object Config; }
        static object Get(object o, string prop, params object[] args) { return o.GetType().InvokeMember(prop, BindingFlags.GetProperty, null, o, args); }
        static object Call(object o, string m, params object[] args) { return o.GetType().InvokeMember(m, BindingFlags.InvokeMethod, null, o, args); }
        static List<IcsConn> IcsConnections()
        {
            var res = new List<IcsConn>();
            var mgr = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.HNetShare"));
            foreach (var c in (IEnumerable)Get(mgr, "EnumEveryConnection")) {
                var props = Get(mgr, "NetConnectionProps", c); var conf = Get(mgr, "INetSharingConfigurationForINetConnection", c);
                res.Add(new IcsConn { Name = Convert.ToString(Get(props, "Name")), Device = Convert.ToString(Get(props, "DeviceName")), Guid = Convert.ToString(Get(props, "Guid")),
                    Enabled = Convert.ToBoolean(Get(conf, "SharingEnabled")), Type = Convert.ToInt32(Get(conf, "SharingConnectionType")), Config = conf });
            }
            return res;
        }
        class IcsState { public List<IcsConn> All; public IcsConn Pub, Priv; public bool Ok; }
        static IcsState IcsLast; static DateTime IcsLastAt = DateTime.MinValue; static string IcsLastUp = "";
        static IcsState IcsStatus()
        {
            string up = UplinkName(), wg = WgIf(); var all = IcsConnections();
            var st = new IcsState { All = all, Pub = all.FirstOrDefault(c => c.Name == up), Priv = all.FirstOrDefault(c => c.Name == wg) };
            var others = all.Where(c => c.Enabled && c.Name != up && c.Name != wg).ToList();
            st.Ok = st.Pub != null && st.Pub.Enabled && st.Pub.Type == 0 && st.Priv != null && st.Priv.Enabled && st.Priv.Type == 1 && others.Count == 0;
            return st;
        }
        static bool IcsScope(string addr)
        {
            if (string.IsNullOrEmpty(addr)) return false;
            using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters", true)) {
                if (k == null) return false;
                if (Convert.ToString(k.GetValue("ScopeAddress")) == addr) return false;
                k.SetValue("ScopeAddress", addr); k.SetValue("ScopeAddressBackup", addr);
            }
            Log("ICS: ScopeAddress -> " + addr, "INFO"); return true;
        }
        static bool WaitIcs(int sec)
        {
            var dl = DateTime.Now.AddSeconds(sec);
            while (DateTime.Now < dl) {
                var s = Svc("SharedAccess"); if (s == null) return false;
                if (s.Status == ServiceControllerStatus.Running) { Thread.Sleep(500); return true; }
                if (s.Status == ServiceControllerStatus.Stopped) { try { s.Start(); } catch { } }
                Thread.Sleep(1000);
            }
            var x = Svc("SharedAccess"); return x != null && x.Status == ServiceControllerStatus.Running;
        }
        static void IcsRestartService() { try { var s = Svc("SharedAccess"); if (s != null && s.Status == ServiceControllerStatus.Running) { s.Stop(); s.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)); } } catch { } WaitIcs(30); WaitIcsReady(15); }
        // служба уже «Running», но раздача ещё не готова принимать настройки (0x80040201) — ждать, пока перечисление подключений
        // станет стабильным (дважды подряд без ошибки и с тем же числом), плюс 2 с
        static bool WaitIcsReady(int sec)
        {
            var dl = DateTime.Now.AddSeconds(sec); int prev = -1;
            while (DateTime.Now < dl) {
                int n = -1; try { n = IcsConnections().Count; } catch { }
                if (n > 0 && n == prev) { Thread.Sleep(2000); return true; }
                prev = n; Thread.Sleep(1000);
            }
            return false;
        }
        // записи раздачи удалённых адаптеров (старый ULTRA) мешают включить раздачу на новом (0x80040201): в WMI (HNet_ConnectionProperties)
        // и в реестре (SharedAccess\Parameters: SharingPublicInterface / SharingPrivateInterface — GUID адаптеров раздачи)
        static int ClearStaleIcs(bool purge = false)
        {
            int n = 0;
            var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try { foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()) present.Add(ni.Id.Trim('{', '}')); } catch { }
            try { using (var ms = new ManagementObjectSearcher(@"root\StandardCimv2", "SELECT InterfaceGuid FROM MSFT_NetAdapter")) foreach (ManagementObject o in ms.Get()) present.Add(Convert.ToString(o["InterfaceGuid"]).Trim('{', '}')); } catch { }
            try {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters", true)) {
                    if (k != null) foreach (var v in new[] { "SharingPublicInterface", "SharingPrivateInterface" }) {
                        var g = Convert.ToString(k.GetValue(v) ?? "").Trim().Trim('{', '}');
                        if (g.Length > 0 && !present.Contains(g)) { k.DeleteValue(v, false); n++; Log("ICS: в реестре раздачи (" + v + ") остался удалённый адаптер {" + g.ToUpper() + "} — убираю", "WARN"); }
                    }
                }
            } catch (Exception e) { Log("ICS: реестр раздачи: " + e.Message, "WARN"); }
            var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try { using (var ms = new ManagementObjectSearcher(@"root\Microsoft\HomeNet", "SELECT * FROM HNet_Connection")) foreach (ManagementObject o in ms.Get()) names[Convert.ToString(o["Guid"]).Trim('{', '}')] = Convert.ToString(o["Name"]); } catch { }
            try {
                using (var ms = new ManagementObjectSearcher(@"root\Microsoft\HomeNet", "SELECT * FROM HNet_ConnectionProperties"))
                    foreach (ManagementObject o in ms.Get()) {
                        bool pub = Convert.ToBoolean(o["IsIcsPublic"]), priv = Convert.ToBoolean(o["IsIcsPrivate"]); if (!pub && !priv) continue;
                        var g = Regex.Match(Convert.ToString(o["Connection"]), @"\{[0-9A-Fa-f\-]+\}").Value.Trim('{', '}');
                        if (g.Length == 0 || present.Contains(g)) continue;
                        string nm; names.TryGetValue(g, out nm);
                        Log("ICS: висячая запись раздачи удалённого адаптера '" + nm + "' {" + g.ToUpper() + "} (публичный=" + pub + ", частный=" + priv + ") — очищаю", "WARN");
                        try { o["IsIcsPublic"] = false; o["IsIcsPrivate"] = false; o.Put(); n++; } catch (Exception e) { Log("ICS: не удалось очистить запись " + g + ": " + e.Message, "ERROR"); }
                    }
            } catch { }
            // хранилище раздачи разрастается: VPN-адаптеры (MeduzaVPN ULTRA, wintun …) при каждом переподключении создаются заново с новым GUID,
            // а Windows записи об удалённых не убирает (на целевом ПК их было 132 при 5 адаптерах). Раздача на каждое включение обходит весь
            // список — и всё чаще падает с 0x80040201. Записей удалённых адаптеров 10 и больше (или раздача не включается) — удалить их целиком
            try {
                var stale = names.Keys.Where(g => !present.Contains(g)).ToList();
                if (stale.Count >= 10 || (purge && stale.Count > 0)) {
                    var st = new HashSet<string>(stale, StringComparer.OrdinalIgnoreCase); int del = 0;
                    foreach (var cls in new[] { "HNet_ConnectionProperties", "HNet_Connection" })
                        using (var ms = new ManagementObjectSearcher(@"root\Microsoft\HomeNet", "SELECT * FROM " + cls))
                            foreach (ManagementObject o in ms.Get()) {
                                var g = cls == "HNet_Connection" ? Convert.ToString(o["Guid"]) : Regex.Match(Convert.ToString(o["Connection"]), @"\{[0-9A-Fa-f\-]+\}").Value;
                                if (st.Contains(g.Trim('{', '}'))) { try { o.Delete(); del++; } catch { } }
                            }
                    if (del > 0) { Log("ICS: из хранилища раздачи Windows убрано записей удалённых адаптеров: " + stale.Count + " (их копят VPN-адаптеры при переподключениях)", "WARN"); n++; }
                }
            } catch (Exception e) { Log("ICS: чистка хранилища раздачи: " + e.Message, "WARN"); }
            return n;
        }
        static void ResetAllIcs()
        {
            foreach (var c in IcsConnections()) if (c.Enabled) { Log("ICS: снимаю общий доступ с '" + c.Name + "' для полной перенастройки", "INFO"); try { Call(c.Config, "DisableSharing"); } catch (Exception e) { Log("ICS: DisableSharing '" + c.Name + "': " + e.Message, "WARN"); } }
            ClearStaleIcs(); Thread.Sleep(1000); IcsRestartService();
        }
        static void EnableIcsSide(string name, int type)
        {
            Exception last = null;
            for (int t = 1; t <= 3; t++) {
                WaitIcs(30);
                var c = IcsConnections().FirstOrDefault(x => x.Name == name);
                if (c == null) throw new Exception("адаптер '" + name + "' не найден в списке подключений");
                if (c.Enabled && c.Type == type) return;
                try { if (c.Enabled) { Call(c.Config, "DisableSharing"); Thread.Sleep(1000); WaitIcs(30); } Call(c.Config, "EnableSharing", type); return; }
                catch (Exception e) {
                    last = e.InnerException ?? e; var s = Svc("SharedAccess");
                    Log("ICS: '" + name + "' попытка " + t + "/3: " + last.Message + " (служба: " + (s == null ? "?" : s.Status.ToString()) + ")", "WARN");
                    if (t == 1) { WaitIcsReady(15); Thread.Sleep(5000); }                 // обычно служба просто ещё не готова
                    else if (t == 2) { ResetAllIcs(); Thread.Sleep(8000); }               // всё снять, перезапустить службу и дать ей освоиться
                    Thread.Sleep(2000);
                }
            }
            throw last;
        }
        static void SharingWatch()
        {
            if (!CfgBool("sharing.enabled", true)) return;
            string up = UplinkName(), wg = WgIf();
            if (string.IsNullOrEmpty(up) || !Up(up) || !Up(wg)) return;
            string addr = WgServerAddress(); string wgIp = Ipv4(wg);
            if (!ForceIcs && IcsLast != null && IcsLast.Ok && up == IcsLastUp && (addr == null || wgIp == addr) && (DateTime.UtcNow - IcsLastAt).TotalSeconds < 60) return;
            var st = IcsStatus(); IcsLast = st; IcsLastAt = DateTime.UtcNow; IcsLastUp = up;
            bool ipOk = addr == null || wgIp == addr || (DateTime.Now - LastIpFix).TotalMinutes < 10;
            if (st.Ok && ipOk && !ForceIcs) return;
            if (!ForceIcs && (DateTime.Now - LastIcsApply).TotalSeconds < 20) return;
            // ни один туннель не пропускает трафик — перестраивать раздачу бессмысленно (каждая перестройка снимает адрес wg_server и рвёт клиентам zapret)
            string tk = TunnelKind();
            if (tk.Length > 0 && (Mode() == "dual" ? FoBothDown : KindTraffic(tk) == false) && st.Ok == false && !ForceIcs) {
                if ((DateTime.Now - IcsWaitLogAt).TotalMinutes >= 5) { IcsWaitLogAt = DateTime.Now; Log("ICS: туннели VPN сейчас не пропускают трафик — раздачу перестрою, когда заработает хотя бы один", "INFO"); }
                return;
            }
            // прошлая настройка на этот же адаптер не удалась — пауза 30 с, 1, 2, 4 мин (не больше 5), чтобы не сбрасывать раздачу по кругу
            if (up == IcsFailUp && DateTime.Now < IcsRetryAt) return;
            ForceIcs = false; LastIcsApply = DateTime.Now; var icsT0 = DateTime.Now;
            Log("ICS: настраиваю общий доступ '" + up + "' -> '" + wg + "'", "INFO"); SetActivity("настраиваю раздачу"); NetChanged();
            try {
                if (StartMode("SharedAccess") != "Auto") SetAutoStart("SharedAccess");
                bool scope = IcsScope(addr);
                if (!WaitIcs(30)) throw new Exception("служба SharedAccess не запускается");
                if (scope) { Log("ICS: перезапуск службы SharedAccess для нового адреса", "INFO"); IcsRestartService(); NetChanged(); }
                // туннель только что поднялся: адаптера может ещё не быть в списке раздачи, или он меняет имя (wintun → AmneziaVPN) — подождать до 20 с
                var conns = IcsConnections();
                for (int w = 0; w < 20 && !conns.Any(c => c.Name == up); w++) { Thread.Sleep(1000); var nu = UplinkName(); if (!string.IsNullOrEmpty(nu)) up = nu; conns = IcsConnections(); }
                if (!conns.Any(c => c.Name == up)) { Log("ICS: адаптера '" + up + "' пока нет в списке подключений — повторю через несколько секунд", "WARN"); ForceIcs = true; LastIcsApply = DateTime.Now.AddSeconds(-15); return; }
                // публичная сторона раздачи ещё не на этом туннеле (сменился туннель или прежний адаптер удалён): включение поверх прежней
                // почти всегда падает с 0x80040201 и стоит клиентам лишних 30 с — сразу снять всё, очистить записи, перезапустить службу и включить обе стороны
                if (IcsFails > 0) IcsKick(IcsFails);
                // старые записи (удалённый адаптер) — очистить; перезапуск службы — только если они были (после него раздаче нужно время)
                if (ClearStaleIcs(IcsFails > 0) > 0) { Log("ICS: перезапуск службы SharedAccess после очистки старых записей", "INFO"); IcsRestartService(); NetChanged(); }
                foreach (var c in IcsConnections()) {
                    if (!c.Enabled) continue;
                    bool right = (c.Name == up && c.Type == 0) || (c.Name == wg && c.Type == 1);
                    if (!right) { Log("ICS: снимаю общий доступ с '" + c.Name + "' (тип " + c.Type + ")", "INFO"); Call(c.Config, "DisableSharing"); Thread.Sleep(1000); }
                }
                EnableIcsSide(up, 0); EnableIcsSide(wg, 1); Thread.Sleep(3000);
                wgIp = Ipv4(wg);
                if (addr != null && wgIp != addr && (DateTime.Now - LastIpFix).TotalMinutes >= 10) {
                    LastIpFix = DateTime.Now; Log("ICS: адрес wg_server стал " + wgIp + ", ожидается " + addr + " — перезапуск туннеля", "WARN");
                    SvcRestart(CfgStr("wg.serviceName", "WireGuardTunnel$wg_server"));
                }
                if (IcsStatus().Ok) { NetChanged(); Log("ICS: общий доступ включён (за " + (int)(DateTime.Now - icsT0).TotalSeconds + " с)", "INFO"); LastIcsFix = DateTime.Now; IcsFixCount++; }
                else Log("ICS: после настройки состояние не подтвердилось, повторю", "WARN");
                if (IcsStatus().Ok) { if (IcsFails > 0) Log("ICS: раздача восстановлена после " + IcsFails + " неудач", "INFO"); IcsFails = 0; IcsFailUp = ""; }
            } catch (Exception e) {
                IcsFails++; IcsFailUp = up; int wait = Math.Min(120, 30 * (1 << Math.Min(2, IcsFails - 1))); IcsRetryAt = DateTime.Now.AddSeconds(wait);
                Log("ICS: ошибка: " + (e.InnerException ?? e).Message + " — повторю через " + (wait >= 60 ? wait / 60 + " мин" : wait + " с"), "ERROR");
            }
        }
        // 0x80040201 «событие не смогло вызвать ни одного из абонентов»: раздача оповещает другие службы через систему событий COM+,
        // а та «залипла» (бывает после пропажи сети). Перезапуск самой SharedAccess не помогает — перезапускать тех, кого она оповещает
        static void IcsKick(int level)
        {
            string[] svcs = level <= 1 ? new[] { "Netman" } : level == 2 ? new[] { "SENS", "EventSystem" } : new[] { "RasMan", "Netman" };
            Log("ICS: раздача не включается (попытка восстановления " + level + ") — перезапускаю службы " + string.Join(", ", svcs) + " и SharedAccess", "WARN");
            SetActivity("восстанавливаю службы раздачи");
            Exe("net.exe", "stop SharedAccess /y", 60);
            foreach (var s in svcs) Exe("net.exe", "stop " + s + " /y", 60);
            foreach (var s in svcs.Reverse()) Exe("net.exe", "start " + s, 60);
            foreach (var s in new[] { "EventSystem", "SENS", "Netman", "RasMan" }) { var sv = Svc(s); if (sv != null && sv.Status == ServiceControllerStatus.Stopped && StartMode(s) != "Disabled") Exe("net.exe", "start " + s, 60); }
            WaitIcs(30); WaitIcsReady(20); Thread.Sleep(5000); NetChanged();
        }
        static int IcsFails; static string IcsFailUp = ""; static DateTime IcsRetryAt = DateTime.MinValue, IcsWaitLogAt = DateTime.MinValue;

        // для окна и веба (сводка): часть «Раздача»
        static Dictionary<string, object> IcsComp(string mode)
        {
            bool uUp = mode == "zapret" || Up(KindAdapter(TunnelKind())), wUp = Up(WgIf());
            // ICS
            IcsState ics = IcsLast != null && (DateTime.UtcNow - IcsLastAt).TotalSeconds < 45 ? IcsLast : null; if (ics == null) try { ics = IcsStatus(); } catch { }
            var icsSvc = Svc("SharedAccess"); int iL; string iS;
            if (!CfgBool("sharing.enabled", true)) { iL = 1; iS = "Отключено в config"; } else if (ics == null) { iL = 1; iS = "Нет данных"; } else if (ics.Ok) { iL = 0; iS = "Включена"; } else if ((!uUp && mode != "zapret") || !wUp) { iL = 1; iS = "Ждёт адаптеры"; } else { iL = 2; iS = "Не настроена"; }
            Func<IcsConn, int, string> fi = (c, want) => c == null ? "не найдено" : !c.Enabled ? c.Name + ": общий доступ выключен" : c.Type != want ? c.Name + ": НЕВЕРНАЯ роль" : c.Name + ": OK";
            string upN = UplinkName();
            var icsOther = ics != null ? ics.All.Where(c => c.Enabled && c.Name != upN && c.Name != WgIf()).Select(c => c.Name).ToList() : new List<string>();
            var icsC = Comp(iL, iS, new[] { upN + " → " + WgIf(), "Служба ICS: " + (icsSvc != null ? icsSvc.Status.ToString() : "нет"), "Восстановлена: " + When(LastIcsFix) }, new List<object[]> {
                Kv("Схема", upN + " (публичный) → " + WgIf() + " (домашняя сеть)"), Kv("Управление раздачей", CfgBool("sharing.enabled", true) ? "включено" : "выключено в настройках"),
                Kv("Служба ICS (SharedAccess)", icsSvc != null ? icsSvc.Status + " / " + StartMode("SharedAccess") : "нет"), Kv("Публичное подключение", ics != null ? fi(ics.Pub, 0) : "—"),
                Kv("Частное подключение", ics != null ? fi(ics.Priv, 1) : "—"), Kv("Лишние подключения с ICS", icsOther.Count > 0 ? string.Join(", ", icsOther) : "нет"),
                Kv("Восстановлена", When(LastIcsFix)), Kv("Восстановлений с запуска агента", IcsFixCount) });
            return icsC;
        }
    }
}
