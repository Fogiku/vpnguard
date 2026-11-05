// Модуль «Веб-сервер и значок»: держит запущенным bin\VpnGuardWeb.exe, пока включён веб-интерфейс или удалённая диагностика; правило
// брандмауэра для его порта; срок удалённой диагностики; пароль веб-интерфейса; сборка веб-сервера и значка у часов из исходников (csc)
// и задача значка. Раньше — часть PowerShell (Remote.ps1), раз в 30 мин. Сборку самого агента по-прежнему делает VpnGuard.ps1.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace VpnGuard
{
    public static partial class Agent
    {
        const string RemoteRule = "VpnGuard remote diagnostics";
        static string WebExe { get { return Path.Combine(BinDir, "VpnGuardWeb.exe"); } }
        static string TrayExe { get { return Path.Combine(BinDir, "VpnGuardTray.exe"); } }
        static readonly string[] WebSources = { "Web.cs", "Qr.cs", "WebDiag.cs" }, TraySources = { "Tray.cs" };
        static readonly string[] WebRefs = { "System.Web.Extensions.dll", "System.Drawing.dll", "System.Management.dll", "System.ServiceProcess.dll", "System.Core.dll", "Microsoft.CSharp.dll" };
        static readonly string[] TrayRefs = { "System.Windows.Forms.dll", "System.Drawing.dll", "System.Web.Extensions.dll" };

        // ---------------------------------------------------------------- сборка встроенным csc (подпись = sha256 исходников, как у Build-CsExe в Remote.ps1)
        static readonly Dictionary<string, string> CsBuildFail = new Dictionary<string, string>();
        static string CscPath()
        {
            var w = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            foreach (var c in new[] { Path.Combine(w, @"Microsoft.NET\Framework64\v4.0.30319\csc.exe"), Path.Combine(w, @"Microsoft.NET\Framework\v4.0.30319\csc.exe") }) if (File.Exists(c)) return c;
            return "";
        }
        static bool BuildCs(string exe, string[] sources, string target, string[] refs)
        {
            var src = sources.Select(s => Path.Combine(Root, s)).ToArray();
            if (src.Any(s => !File.Exists(s))) return false;
            string sig = string.Join("|", src.Select(Sha256Of));
            string old = ""; try { old = File.Exists(exe + ".sig") ? File.ReadAllText(exe + ".sig").Trim() : ""; } catch { }
            if (File.Exists(exe) && old == sig) return true;
            string failed; if (CsBuildFail.TryGetValue(exe, out failed) && failed == sig) return false;
            var csc = CscPath(); string name = Path.GetFileNameWithoutExtension(exe);
            if (csc.Length == 0) { CsBuildFail[exe] = sig; Log("Сборка " + name + ": нет компилятора .NET (csc.exe)", "WARN"); return false; }
            foreach (var p in Process.GetProcessesByName(name)) { try { p.Kill(); p.WaitForExit(5000); } catch { } }
            Thread.Sleep(400);
            Directory.CreateDirectory(Path.GetDirectoryName(exe));
            var tmp = exe + ".new"; try { File.Delete(tmp); } catch { }
            var r = Exe(csc, "/nologo /target:" + target + " /optimize+ /out:\"" + tmp + "\" " + string.Join(" ", refs.Select(x => "/r:" + x)) + " " + string.Join(" ", src.Select(s => "\"" + s + "\"")), 180);
            if (r.Code != 0 || !File.Exists(tmp)) {
                CsBuildFail[exe] = sig;
                Log("Сборка " + name + " не удалась (код " + r.Code + "): " + string.Join(" | ", (r.Out + "\n" + r.Err).Split('\n').Where(l => l.Contains("error")).Take(3)), "ERROR");
                return false;
            }
            try { File.Delete(exe); } catch { }
            File.Move(tmp, exe); File.WriteAllText(exe + ".sig", sig, Encoding.ASCII);
            Log("Собрано на C#: " + name + " (" + new FileInfo(exe).Length / 1024 + " КБ)", "INFO");
            return true;
        }

        // ---------------------------------------------------------------- веб-сервер и удалённая диагностика
        static DateTime RemoteUntil() { DateTime d; return DateTime.TryParse(CfgStr("remote.until", ""), null, System.Globalization.DateTimeStyles.RoundtripKind, out d) ? d.ToLocalTime() : DateTime.MinValue; }
        static bool RemoteOn() { return CfgBool("remote.enabled", false) && CfgStr("remote.token", "").Length >= 16 && RemoteUntil() > DateTime.Now; }
        static string NewWebToken() { var b = new byte[12]; using (var g = RandomNumberGenerator.Create()) g.GetBytes(b); return string.Concat(b.Select(x => x.ToString("x2"))); }
        static string WebFwSig = ""; static DateTime WebFwAt = DateTime.MinValue;
        static string FwRuleText() { var r = Exe("netsh.exe", "advfirewall firewall show rule name=\"" + RemoteRule + "\"", 15); return r.Code == 0 ? r.Out : null; }
        static void SyncWebFirewall(int port)
        {
            string wgNet = ""; try { var a = WgServerAddress(); if (!string.IsNullOrEmpty(a)) wgNet = Regex.Replace(a, @"\.\d+(/\d+)?$", ".0/24"); } catch { }
            bool any = RemoteOn() && CfgStr("remote.allowFrom", "any") != "local";
            string from = any ? "any" : "LocalSubnet" + (wgNet.Length > 0 ? "," + wgNet : ""), sig = port + "|" + from;
            if (sig == WebFwSig && (DateTime.Now - WebFwAt).TotalMinutes < 30) return;
            WebFwAt = DateTime.Now;
            // правило уже есть? порт и «откуда угодно / только своя сеть» — через COM брандмауэра (не зависит от языка Windows, в отличие от вывода netsh)
            int n = 0; string ports = "", remote = "";
            try {
                dynamic fw = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                foreach (dynamic r in fw.Rules) { if ((string)r.Name != RemoteRule) continue; n++; ports = Convert.ToString(r.LocalPorts); remote = Convert.ToString(r.RemoteAddresses); }
            } catch { n = -1; }
            bool have = n != 0, ok = n == 1 && ports == port.ToString() && (remote == "*") == any;
            if (!ok) {
                if (have) Exe("netsh.exe", "advfirewall firewall delete rule name=\"" + RemoteRule + "\"", 15);
                var r = Exe("netsh.exe", "advfirewall firewall add rule name=\"" + RemoteRule + "\" dir=in action=allow protocol=TCP localport=" + port + " remoteip=" + from + " profile=any", 15);
                if (r.Code == 0) Log("Удалённая диагностика: правило брандмауэра — TCP " + port + ", откуда: " + from, "INFO");
                else Log("Удалённая диагностика: правило брандмауэра не создано: " + (r.Out + " " + r.Err).Trim(), "WARN");
            }
            WebFwSig = sig;
        }
        static void WebWatch()
        {
            if (CfgBool("remote.enabled", false) && RemoteUntil() <= DateTime.Now) { Log("Удалённая диагностика: время вышло — выключаю", "INFO"); CfgSet("remote.enabled", false); }
            bool webOn = CfgBool("web.enabled", true), remOn = RemoteOn();
            var running = Process.GetProcessesByName("VpnGuardWeb");
            if (!webOn && !remOn) {
                if (running.Length > 0 || FwRuleText() != null) {
                    foreach (var p in running) { try { p.Kill(); } catch { } }
                    Exe("netsh.exe", "advfirewall firewall delete rule name=\"" + RemoteRule + "\"", 15); WebFwSig = "";
                    Log("Веб-сервер VpnGuard остановлен (веб-интерфейс выключен, диагностика выключена)", "INFO");
                }
                return;
            }
            if (webOn && CfgBool("web.requirePassword", true) && CfgStr("web.token", "").Length < 6) { CfgSet("web.token", NewWebToken()); Log("Веб-интерфейс: создан пароль для входа с других устройств (в config.json, web.token)", "INFO"); }
            int port = CfgInt("web.port", 8765);
            SyncWebFirewall(port);
            if (running.Length > 0) return;
            if (!BuildCs(WebExe, WebSources, "exe", WebRefs)) {
                // новая версия не собралась — запустить прежнюю сборку: удалённый доступ к ПК важнее свежего кода
                if (!File.Exists(WebExe)) { Log("Веб-сервер VpnGuard не собрался (Web.cs), прежней сборки нет — веб-интерфейс и удалённая диагностика недоступны", "ERROR"); return; }
                Log("Веб-сервер VpnGuard: новая версия не собралась — запускаю прежнюю сборку", "ERROR");
            }
            Process.Start(new ProcessStartInfo(WebExe, "\"" + Root + "\"" + (ConfigPath != Path.Combine(Root, "config.json") ? " \"" + ConfigPath + "\"" : "")) { WorkingDirectory = Root, UseShellExecute = false, CreateNoWindow = true });
            Log("Веб-сервер VpnGuard: запускаю на порту " + port + (remOn ? " · удалённая диагностика до " + RemoteUntil().ToString("dd.MM HH:mm") : ""), "WARN");
        }
        // для окна и веба (вкладка «Компоненты»)
        static Dictionary<string, object> RemoteSnapshot()
        {
            Dictionary<string, object> s = null;
            try { var p = Path.Combine(DataDir, "remote-state.json"); if (File.Exists(p)) s = Json.DeserializeObject(File.ReadAllText(p, Encoding.UTF8)) as Dictionary<string, object>; } catch { }
            Func<string, object> g = k => s != null && s.ContainsKey(k) ? s[k] : null;
            var u = RemoteUntil();
            return new Dictionary<string, object> { { "enabled", RemoteOn() }, { "until", u > DateTime.MinValue ? u.ToString("o") : "" }, { "port", CfgInt("web.port", 8765) },
                { "allowActions", CfgBool("remote.allowActions", false) }, { "allowFrom", CfgStr("remote.allowFrom", "any") }, { "web", CfgBool("web.enabled", true) },
                { "running", Process.GetProcessesByName("VpnGuardWeb").Length > 0 }, { "error", Convert.ToString(g("error") ?? "") }, { "requests", g("requests") ?? 0 }, { "last", Convert.ToString(g("last") ?? "") } };
        }

        // ---------------------------------------------------------------- значок у часов: собрать из Tray.cs и следить, чтобы задача VpnGuardMonitor открывала его (раз в 5 мин)
        static DateTime TrayAt = DateTime.MinValue;
        static void TrayWatch()
        {
            if ((DateTime.Now - TrayAt).TotalMinutes < 5) return;
            TrayAt = DateTime.Now;
            var q = Exe("schtasks.exe", "/query /tn VpnGuardMonitor /xml", 15); if (q.Code != 0) return;          // задачи нет — значок не нужен
            var cmd = Regex.Match(q.Out, @"<Command>([^<]*)</Command>").Groups[1].Value.Trim().Trim('"');
            bool was = Process.GetProcessesByName("VpnGuardTray").Length > 0;
            if (!BuildCs(TrayExe, TraySources, "winexe", TrayRefs)) return;
            bool isTray = cmd.EndsWith("VpnGuardTray.exe", StringComparison.OrdinalIgnoreCase);
            if (was && isTray && Process.GetProcessesByName("VpnGuardTray").Length == 0) Exe("schtasks.exe", "/run /tn VpnGuardMonitor", 15);   // пересобран — запустить снова
            if (!isTray) {
                var r = Exe("schtasks.exe", "/change /tn VpnGuardMonitor /tr \"\\\"" + TrayExe + "\\\" \\\"" + Root + "\\\"\"", 15);
                Log(r.Code == 0 ? "Значок у часов: ярлык VpnGuard и вход в Windows открывают значок (веб-интерфейс по щелчку)" : "Значок у часов: задачу VpnGuardMonitor не удалось переключить: " + (r.Out + r.Err).Trim(), r.Code == 0 ? "WARN" : "ERROR");
                if (Process.GetProcessesByName("VpnGuardTray").Length == 0) Exe("schtasks.exe", "/run /tn VpnGuardMonitor", 15);
            }
        }
        static void WebHostTick() { WebWatch(); TrayWatch(); }
    }
}
