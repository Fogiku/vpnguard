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
        // записи раздачи удалённых адаптеров (старый ULTRA) мешают включить раздачу на новом (0x80040201)
        static int ClearStaleIcs()
        {
            int n = 0;
            var present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try { foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()) present.Add(ni.Id.Trim('{', '}')); } catch { }
            try { using (var ms = new ManagementObjectSearcher(@"root\StandardCimv2", "SELECT InterfaceGuid FROM MSFT_NetAdapter")) foreach (ManagementObject o in ms.Get()) present.Add(Convert.ToString(o["InterfaceGuid"]).Trim('{', '}')); } catch { }
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
                    if (t == 1) { WaitIcsReady(15); Thread.Sleep(3000); }                 // обычно служба просто ещё не готова
                    else if (t == 2) ResetAllIcs();
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
                if (!conns.Any(c => c.Enabled && c.Type == 0 && c.Name == up)) { Log("ICS: раздача переходит на '" + up + "' — полный сброс и включение заново", "INFO"); ResetAllIcs(); NetChanged(); }
                else if (ClearStaleIcs() > 0) { Log("ICS: перезапуск службы SharedAccess после очистки старых записей", "INFO"); IcsRestartService(); }
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
            } catch (Exception e) { Log("ICS: ошибка: " + (e.InnerException ?? e).Message, "ERROR"); }
        }

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
