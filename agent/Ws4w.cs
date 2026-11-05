// WS4W (WireGuard Server For Windows) больше не нужен, когда сервер WG-Server под управлением VpnGuard: поиск его следов у всех пользователей
// (программа, процессы, автозапуск, задачи планировщика, ярлыки, NAT) и удаление. Данные WS4W (%AppData%\WS4W) — в резервную копию data\backup.
// Команды модуля «Компоненты»: ws4w-scan, ws4w-remove.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace VpnGuard
{
    public static partial class Agent
    {
        static readonly Regex Ws4wRx = new Regex(@"WS4W|WgServerforWindows|WireGuard ?Server ?For ?Windows", RegexOptions.IgnoreCase);
        class Ws4wItem { public string Kind, Name, Detail, Path; }
        static List<Ws4wItem> Ws4wLast;

        // профили пользователей: SID → папка профиля (только обычные учётные записи)
        static List<KeyValuePair<string, string>> UserProfiles()
        {
            var res = new List<KeyValuePair<string, string>>();
            try {
                using (var pl = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"))
                    foreach (var sid in pl.GetSubKeyNames().Where(s => s.StartsWith("S-1-5-21-")))
                        using (var k = pl.OpenSubKey(sid)) { var p = k == null ? null : Convert.ToString(k.GetValue("ProfileImagePath")); if (!string.IsNullOrEmpty(p) && Directory.Exists(p)) res.Add(new KeyValuePair<string, string>(sid, Environment.ExpandEnvironmentVariables(p))); }
            } catch { }
            return res;
        }
        static List<Ws4wItem> Ws4wScan()
        {
            var r = new List<Ws4wItem>();
            // записи «Программы и компоненты»: компьютер и каждый пользователь (HKU\SID — если его реестр загружен, т.е. пользователь вошёл)
            var roots = new List<KeyValuePair<RegistryKey, string>> {
                new KeyValuePair<RegistryKey, string>(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                new KeyValuePair<RegistryKey, string>(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall") };
            foreach (var u in UserProfiles()) roots.Add(new KeyValuePair<RegistryKey, string>(Registry.Users, u.Key + @"\Software\Microsoft\Windows\CurrentVersion\Uninstall"));
            foreach (var rt in roots) {
                try {
                    using (var k = rt.Key.OpenSubKey(rt.Value)) {
                        if (k == null) continue;
                        foreach (var sub in k.GetSubKeyNames()) using (var s = k.OpenSubKey(sub)) {
                            var dn = s == null ? null : s.GetValue("DisplayName") as string; if (dn == null || !Ws4wRx.IsMatch(dn)) continue;
                            var un = Convert.ToString(s.GetValue("QuietUninstallString") ?? s.GetValue("UninstallString") ?? "");
                            r.Add(new Ws4wItem { Kind = "program", Name = dn + " " + s.GetValue("DisplayVersion"), Detail = un, Path = (rt.Key == Registry.Users ? @"HKU\" : @"HKLM\") + rt.Value + @"\" + sub });
                        }
                    }
                } catch { }
            }
            // процессы
            foreach (var p in Process.GetProcesses()) { try { string f = ""; try { f = p.MainModule.FileName; } catch { } if (Ws4wRx.IsMatch(p.ProcessName) || Ws4wRx.IsMatch(f)) r.Add(new Ws4wItem { Kind = "process", Name = p.ProcessName + " (" + p.Id + ")", Detail = f, Path = p.Id.ToString() }); } catch { } finally { p.Dispose(); } }
            // автозапуск (Run): компьютер и пользователи
            var runs = new List<KeyValuePair<RegistryKey, string>> { new KeyValuePair<RegistryKey, string>(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"), new KeyValuePair<RegistryKey, string>(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run") };
            foreach (var u in UserProfiles()) runs.Add(new KeyValuePair<RegistryKey, string>(Registry.Users, u.Key + @"\Software\Microsoft\Windows\CurrentVersion\Run"));
            foreach (var rt in runs) {
                try { using (var k = rt.Key.OpenSubKey(rt.Value)) if (k != null) foreach (var n in k.GetValueNames()) { var v = Convert.ToString(k.GetValue(n)); if (Ws4wRx.IsMatch(n) || Ws4wRx.IsMatch(v)) r.Add(new Ws4wItem { Kind = "autorun", Name = n, Detail = v, Path = (rt.Key == Registry.Users ? @"HKU\" : @"HKLM\") + rt.Value }); } } catch { }
            }
            // задачи планировщика (имя, путь или аргументы действия)
            try {
                dynamic svc = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")); svc.Connect();
                var stack = new Stack<dynamic>(); stack.Push(svc.GetFolder("\\"));
                while (stack.Count > 0) {
                    var f = stack.Pop();
                    foreach (dynamic t in f.GetTasks(1)) {
                        string acts = ""; try { foreach (dynamic a in t.Definition.Actions) { try { acts += a.Path + " " + a.Arguments + "; "; } catch { } } } catch { }
                        if (Ws4wRx.IsMatch((string)t.Path) || Ws4wRx.IsMatch(acts)) r.Add(new Ws4wItem { Kind = "task", Name = (string)t.Path, Detail = acts.Trim(), Path = (string)t.Path });
                    }
                    foreach (dynamic sf in f.GetFolders(0)) stack.Push(sf);
                }
            } catch (Exception e) { r.Add(new Ws4wItem { Kind = "note", Name = "задачи планировщика не прочитаны", Detail = e.Message }); }
            // папки программы и данных, ярлыки
            var dirs = new List<string> { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WS4W"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "WS4W"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WS4W") };
            var lnkDirs = new List<string> { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows\Start Menu\Programs"), Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory) };
            foreach (var u in UserProfiles()) {
                foreach (var d in new[] { @"AppData\Local\WS4W", @"AppData\Local\Programs\WS4W", @"AppData\Local\WgServerforWindows", @"AppData\Roaming\WS4W" }) dirs.Add(Path.Combine(u.Value, d));
                lnkDirs.Add(Path.Combine(u.Value, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs")); lnkDirs.Add(Path.Combine(u.Value, "Desktop"));
            }
            foreach (var d in dirs.Distinct(StringComparer.OrdinalIgnoreCase)) if (Directory.Exists(d)) r.Add(new Ws4wItem { Kind = d.IndexOf(@"\Roaming\", StringComparison.OrdinalIgnoreCase) >= 0 ? "data" : "folder", Name = d, Path = d });
            foreach (var d in lnkDirs) { try { if (Directory.Exists(d)) foreach (var f in Directory.GetFiles(d, "*.lnk", SearchOption.AllDirectories).Where(x => Ws4wRx.IsMatch(Path.GetFileName(x)))) r.Add(new Ws4wItem { Kind = "shortcut", Name = f, Path = f }); } catch { } }
            // NAT Windows (New-NetNat) — WS4W умеет «NAT Routing» вместо общего доступа; с ICS VpnGuard он не нужен
            try { foreach (ManagementObject o in new ManagementObjectSearcher(@"root\StandardCimv2", "SELECT Name, InternalIPInterfaceAddressPrefix FROM MSFT_NetNat").Get()) r.Add(new Ws4wItem { Kind = "nat", Name = Convert.ToString(o["Name"]), Detail = Convert.ToString(o["InternalIPInterfaceAddressPrefix"]), Path = Convert.ToString(o["Name"]) }); } catch { }
            Ws4wLast = r; return r;
        }
        static string Ws4wDescribe(IEnumerable<Ws4wItem> items) { return string.Join("; ", items.Where(x => x.Kind != "note").Select(x => x.Kind + ": " + x.Name + (string.IsNullOrEmpty(x.Detail) ? "" : " [" + x.Detail + "]"))); }
        static string Ws4wInstalled()
        {
            var l = Ws4wLast; if (l == null) return "";
            var p = l.FirstOrDefault(x => x.Kind == "program"); if (p != null) { var v = Regex.Match(p.Name, @"\d+(\.\d+)+").Value; return v.Length > 0 ? v : "есть"; }
            return l.Any(x => x.Kind == "folder" || x.Kind == "process") ? "есть" : l.Any(x => x.Kind == "data") ? "только данные" : "";
        }

        // WS4W закрывает доступ к конфигам клиентов (только пользователю) — забрать владение администраторам, сбросить права, снять «только чтение»
        static void Ws4wUnlock(string dir)
        {
            Exe("icacls.exe", "\"" + dir + "\" /setowner *S-1-5-32-544 /T /C /Q", 120);
            Exe("icacls.exe", "\"" + dir + "\" /reset /T /C /Q", 120);
            Exe("icacls.exe", "\"" + dir + "\" /grant *S-1-5-32-544:(OI)(CI)F *S-1-5-18:(OI)(CI)F /T /C /Q", 120);
            foreach (var f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories)) { try { File.SetAttributes(f, FileAttributes.Normal); } catch { } }
        }
        static void Ws4wCmd(string c)
        {
            if (c == "ws4w-scan") {
                var l = Ws4wScan(); var traces = l.Where(x => x.Kind != "nat" && x.Kind != "note").ToList();
                Log("WS4W: " + (traces.Count == 0 ? "следов нет" : "найдено " + traces.Count + " — " + Ws4wDescribe(traces)) + (l.Any(x => x.Kind == "nat") ? " · NAT Windows: " + Ws4wDescribe(l.Where(x => x.Kind == "nat")) : "") + Ws4wDescribe(l.Where(x => x.Kind == "note")), "INFO");
                return;
            }
            if (c != "ws4w-remove") return;
            // сервер должен быть уже под VpnGuard и служба — на его конфиге, иначе удаление WS4W может оставить клиентов без сервера
            var conf = WgConf(); string sn = CfgStr("ws4w.serviceName", "WireGuardTunnel$wg_server"), gui = CfgStr("ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe");
            if (conf == null || !conf.StartsWith(Path.Combine(DataDir, "wg"), StringComparison.OrdinalIgnoreCase)) { Log("WS4W: не удаляю — сервер WG-Server ещё не перенесён под управление VpnGuard (вкладка WG-Server → «Перенести сервер»)", "ERROR"); return; }
            var sc = WgLib.ServiceConf(sn);
            if (sc == null || !string.Equals(Path.GetFullPath(sc), Path.GetFullPath(conf), StringComparison.OrdinalIgnoreCase)) { Log("WS4W: не удаляю — служба туннеля не на конфиге VpnGuard (" + (sc ?? "нет службы") + ")", "ERROR"); return; }
            var items = Ws4wScan(); int done = 0; var errs = new List<string>();
            Log("WS4W: удаляю — " + (items.Count(x => x.Kind != "nat" && x.Kind != "note") == 0 ? "следов нет" : Ws4wDescribe(items.Where(x => x.Kind != "nat"))), "WARN");
            Action<string, Action> step = (what, a) => { try { a(); done++; Log("WS4W: " + what, "INFO"); } catch (Exception e) { errs.Add(what + ": " + e.Message); } };
            // 1. процессы и автозапуск — чтобы ничего не запустилось заново и не держало файлы
            foreach (var x in items.Where(i => i.Kind == "process")) step("завершён процесс " + x.Name, () => { using (var p = Process.GetProcessById(int.Parse(x.Path))) { p.Kill(); p.WaitForExit(10000); } });
            foreach (var x in items.Where(i => i.Kind == "autorun")) step("убран автозапуск " + x.Name, () => { var hive = x.Path.StartsWith("HKU") ? Registry.Users : Registry.LocalMachine; using (var k = hive.OpenSubKey(x.Path.Substring(4), true)) if (k != null) k.DeleteValue(x.Name, false); });
            foreach (var x in items.Where(i => i.Kind == "task")) step("удалена задача планировщика " + x.Name, () => { var r = Exe("schtasks.exe", "/Delete /TN \"" + x.Path + "\" /F", 30); if (r.Code != 0) throw new Exception(r.Err.Trim() + r.Out.Trim()); });
            // 2. штатное удаление программы (без окон); если не вышло — папки удаляются ниже
            foreach (var x in items.Where(i => i.Kind == "program")) {
                var un = x.Detail ?? ""; if (un.Length == 0) continue;
                step("удалена программа " + x.Name, () => {
                    string exe, args; var m = Regex.Match(un, "^\\s*\"([^\"]+)\"\\s*(.*)$"); if (m.Success) { exe = m.Groups[1].Value; args = m.Groups[2].Value; } else { var i = un.IndexOf(".exe", StringComparison.OrdinalIgnoreCase); exe = i > 0 ? un.Substring(0, i + 4) : un; args = i > 0 ? un.Substring(i + 4) : ""; }
                    if (Regex.IsMatch(exe, @"msiexec", RegexOptions.IgnoreCase)) args = Regex.Replace(args, @"/I\b", "/X", RegexOptions.IgnoreCase) + " /qn /norestart";
                    else if (Regex.IsMatch(exe, @"\\Update\.exe$", RegexOptions.IgnoreCase)) args = "--uninstall -s";                 // Squirrel
                    else if (!Regex.IsMatch(args, @"(/S|/quiet|/silent|/verysilent|-s)\b", RegexOptions.IgnoreCase)) args += " /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /S";
                    var r = Exe(exe, args.Trim(), 180); if (r.Code != 0 && r.Code != 3010) throw new Exception("код " + r.Code + " " + r.Err.Trim());
                });
            }
            Thread.Sleep(3000);
            // 3. остатки: папки программы, ярлыки, записи «Программы и компоненты»; данные — сначала в архив
            foreach (var x in items.Where(i => i.Kind == "data" && Directory.Exists(i.Path))) step("данные WS4W сохранены в архив и удалены: " + x.Path, () => {
                var zip = Path.Combine(DataDir, "backup", "ws4w-data-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".zip"); Directory.CreateDirectory(Path.GetDirectoryName(zip));
                Ws4wUnlock(x.Path);
                foreach (var old in Directory.GetFiles(Path.GetDirectoryName(zip), "ws4w-data-*.zip")) { try { File.Delete(old); } catch { } }    // прежняя попытка могла оборваться на закрытых файлах
                ZipFile.CreateFromDirectory(x.Path, zip);
                Directory.Delete(x.Path, true);
            });
            foreach (var x in items.Where(i => i.Kind == "folder" && Directory.Exists(i.Path))) step("удалена папка " + x.Path, () => { Ws4wUnlock(x.Path); Directory.Delete(x.Path, true); });
            foreach (var x in items.Where(i => i.Kind == "shortcut" && File.Exists(i.Path))) step("удалён ярлык " + x.Path, () => File.Delete(x.Path));
            foreach (var x in items.Where(i => i.Kind == "program")) {
                var hive = x.Path.StartsWith("HKU") ? Registry.Users : Registry.LocalMachine; var sub = x.Path.Substring(4);
                try { using (var k = hive.OpenSubKey(sub)) if (k == null) continue; } catch { continue; }
                step("убрана запись «Программы и компоненты» " + x.Name, () => { var parent = sub.Substring(0, sub.LastIndexOf('\\')); using (var k = hive.OpenSubKey(parent, true)) k.DeleteSubKeyTree(sub.Substring(sub.LastIndexOf('\\') + 1), false); });
            }
            // 4. NAT Windows для подсети сервера (WS4W «NAT Routing») мешает общему доступу (ICS) — убрать только его
            var net = Regex.Replace(WgServerAddress() ?? "-", @"\.\d+$", ".");
            foreach (var x in items.Where(i => i.Kind == "nat" && (i.Detail ?? "").StartsWith(net))) step("убран NAT Windows " + x.Name + " (" + x.Detail + ")", () => { var r = Exe("powershell.exe", "-NoProfile -Command \"Remove-NetNat -Name '" + x.Name.Replace("'", "''") + "' -Confirm:$false\"", 60); if (r.Code != 0) throw new Exception(r.Err.Trim()); });
            // 5. служба туннеля: удаление WS4W могло её снять — вернуть на конфиг VpnGuard
            Thread.Sleep(2000);
            if (Svc(sn) == null || WgLib.ServiceConf(sn) == null || !string.Equals(Path.GetFullPath(WgLib.ServiceConf(sn)), Path.GetFullPath(conf), StringComparison.OrdinalIgnoreCase)) {
                string e = null; WgLib.TryLocked(60000, () => e = WgLib.InstallService(gui, sn, WgIf(), conf));
                Log("WS4W: служба туннеля восстановлена после удаления" + (e != null ? " — ошибка: " + e : ""), e != null ? "ERROR" : "WARN"); Emit("wg.restarted", "после удаления WS4W");
            }
            var left = Ws4wScan().Where(x => x.Kind != "nat" && x.Kind != "note").ToList();
            Log("WS4W: удаление завершено — шагов " + done + (errs.Count > 0 ? ", ошибок " + errs.Count + ": " + string.Join("; ", errs) : "") + (left.Count > 0 ? " · осталось: " + Ws4wDescribe(left) : " · следов не осталось"), errs.Count > 0 || left.Count > 0 ? "WARN" : "INFO");
            Uncache("au:" + SwDefs.First(d => d.Id == "ws4w").Reg + "|DisplayVersion");
        }
    }
}
