// Модуль «Компоненты»: версии и установка нужного софта (MeduzaVPN и его CLI, WireGuard, AmneziaVPN, zapret) и автообновление MeduzaVPN.
// Раньше — часть PowerShell (Software.ps1, обновление в Meduza.ps1). Источники официальные: сервер сборок MeduzaVPN, download.wireguard.com,
// релизы GitHub. Проверка: sha256 (из release.json / GitHub) и подпись Authenticode известного издателя.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace VpnGuard
{
    public static partial class Agent
    {
        // ---------------------------------------------------------------- состояние модуля (data\components.json): переживает перезапуск агента
        static Dictionary<string, object> Sw;
        static string SwPath { get { return Path.Combine(DataDir, "components.json"); } }
        static string DlDir { get { var d = Path.Combine(DataDir, "downloads"); Directory.CreateDirectory(d); return d; } }
        static Dictionary<string, object> SwState()
        {
            if (Sw != null) return Sw;
            try { Sw = File.Exists(SwPath) ? Json.DeserializeObject(File.ReadAllText(SwPath, Encoding.UTF8)) as Dictionary<string, object> : null; } catch { }
            if (Sw == null) Sw = new Dictionary<string, object>();
            return Sw;
        }
        static void SwSave() { try { lock (SwState()) File.WriteAllText(SwPath, Json.Serialize(Sw), Encoding.UTF8); } catch { } }
        static string SwS(string k) { object v; return SwState().TryGetValue(k, out v) && v != null ? Convert.ToString(v) : ""; }
        static DateTime SwD(string k) { DateTime d; return DateTime.TryParse(SwS(k), null, System.Globalization.DateTimeStyles.RoundtripKind, out d) ? d : DateTime.MinValue; }
        static Dictionary<string, object> SwItem(string id)
        {
            var st = SwState(); object o; if (!st.TryGetValue("items", out o) || !(o is Dictionary<string, object>)) st["items"] = o = new Dictionary<string, object>();
            var items = (Dictionary<string, object>)o; object it; if (!items.TryGetValue(id, out it) || !(it is Dictionary<string, object>)) items[id] = it = new Dictionary<string, object>();
            return (Dictionary<string, object>)it;
        }

        // ---------------------------------------------------------------- компоненты
        class SwDef { public string Id, Name, Purpose, Repo, Asset, Reg, Signer = ""; }
        static readonly SwDef[] SwDefs = {
            new SwDef { Id = "meduza", Name = "MeduzaVPN", Purpose = "VPN (режим MeduzaVPN)" },
            new SwDef { Id = "meduzacli", Name = "MeduzaVPN CLI", Purpose = "управление MeduzaVPN из агента" },
            new SwDef { Id = "wireguard", Name = "WireGuard", Purpose = "туннель WG-Server для клиентов" },
            new SwDef { Id = "amneziavpn", Name = "AmneziaVPN", Purpose = "VPN (режим AmneziaVPN)", Repo = "amnezia-vpn/amnezia-client", Asset = @"_windows_x64\.exe$", Reg = "^AmneziaVPN" },
            new SwDef { Id = "zapret", Name = "zapret-discord-youtube", Purpose = "YouTube и Discord мимо блокировок" },
        };
        static Version Ver2(string s) { var m = Regex.Match(s ?? "", @"\d+(\.\d+){0,3}"); System.Version v; return m.Success && System.Version.TryParse(m.Value.Contains(".") ? m.Value : m.Value + ".0", out v) ? v : new Version(0, 0); }
        static string SwInstalled(string id)
        {
            switch (id) {
                case "meduza": { var v = MzVersion(); return Ver2(v) > new Version(0, 0) ? v : ""; }
                case "meduzacli": { if (!File.Exists(Cli())) return ""; var v = FileVersionInfo.GetVersionInfo(Cli()).ProductVersion; return string.IsNullOrEmpty(v) ? "есть" : v; }
                case "wireguard": { var v = AppUninstall("^WireGuard$", "DisplayVersion"); return !string.IsNullOrEmpty(v) ? v : File.Exists(CfgStr("wg.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe")) ? "есть" : ""; }
                case "amneziavpn": { var v = AppUninstall("^AmneziaVPN", "DisplayVersion"); if (!string.IsNullOrEmpty(v)) return v; if (File.Exists(AwgExe())) { var fv = FileVersionInfo.GetVersionInfo(AwgExe()).ProductVersion; return string.IsNullOrEmpty(fv) ? "есть" : fv; } return ""; }
                case "zapret": return ZLocalVersion();
            }
            return "";
        }
        static bool SwNeeded(string id)
        {
            string mode = Mode();
            switch (id) {
                case "meduza": case "meduzacli": return mode == "meduza" || mode == "dual";
                case "wireguard": return true;
                case "amneziavpn": return mode == "amnezia" || mode == "dual";
                case "zapret": return ZOn();
            }
            return false;
        }

        // ---------------------------------------------------------------- источники версий
        static Dictionary<string, object> MzRelease()
        {
            return Json.DeserializeObject(HttpGet(CfgStr("meduza.releaseUrl", "https://meduzavpn-builds.fra1.digitaloceanspaces.com/latest/release.json") + "?t=" + DateTimeOffset.UtcNow.ToUnixTimeSeconds(), 30)) as Dictionary<string, object>;
        }
        static Dictionary<string, object> MzReleaseFile(Dictionary<string, object> rel, string key)
        {
            return ((rel != null && rel.ContainsKey("files") ? rel["files"] as object[] : null) ?? new object[0]).OfType<Dictionary<string, object>>().FirstOrDefault(f => Convert.ToString(f.ContainsKey("key") ? f["key"] : "") == key);
        }
        class SwRel { public string Version = "", Url = "", File = "", Sha256 = ""; }
        static SwRel GitHubLatest(string repo, string assetRx)
        {
            var r = Json.DeserializeObject(HttpGet("https://api.github.com/repos/" + repo + "/releases/latest", 30)) as Dictionary<string, object>;
            var assets = ((r["assets"] as object[]) ?? new object[0]).OfType<Dictionary<string, object>>().Where(a => Regex.IsMatch(Convert.ToString(a["name"]), assetRx, RegexOptions.IgnoreCase))
                .OrderBy(a => Regex.IsMatch(Convert.ToString(a["name"]), "amd64|x64|setup", RegexOptions.IgnoreCase) ? 0 : 1).ToList();
            if (assets.Count == 0) throw new Exception("в релизе " + r["tag_name"] + " нет подходящего файла");
            var a0 = assets[0]; var dg = a0.ContainsKey("digest") ? Convert.ToString(a0["digest"]) : "";
            var m = Regex.Match(dg, "^sha256:([0-9a-f]{64})$");
            return new SwRel { Version = Ver2(Convert.ToString(r["tag_name"])).ToString(), Url = Convert.ToString(a0["browser_download_url"]), File = Convert.ToString(a0["name"]), Sha256 = m.Success ? m.Groups[1].Value.ToUpperInvariant() : "" };
        }
        static SwRel WireGuardLatest()
        {
            var html = HttpGet("https://download.wireguard.com/windows-client/", 30);
            var v = Regex.Matches(html, @"wireguard-amd64-(\d+\.\d+(?:\.\d+)*)\.msi").Cast<Match>().Select(x => x.Groups[1].Value).OrderByDescending(x => Ver2(x)).FirstOrDefault();
            if (v == null) throw new Exception("не нашёл MSI на download.wireguard.com");
            return new SwRel { Version = v, Url = "https://download.wireguard.com/windows-client/wireguard-amd64-" + v + ".msi", File = "wireguard-amd64-" + v + ".msi" };
        }

        // ---------------------------------------------------------------- проверка файлов: sha256 и подпись Authenticode
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)] static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, IntPtr data);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct WtFile { public int Size; public string Path; public IntPtr H; public IntPtr Subject; }
        [StructLayout(LayoutKind.Sequential)] struct WtData { public int Size; public IntPtr Policy, Sip; public int UiChoice, Revocation, Union; public IntPtr File; public int StateAction; public IntPtr State; public IntPtr Url; public int Prov, Ui; public IntPtr Sig; }
        // «Valid» — подпись цела и сертификат доверенный; «NotSigned»; иначе — повреждена/недоверенная
        static string SignStatus(string file)
        {
            var f = new WtFile { Size = Marshal.SizeOf(typeof(WtFile)), Path = file };
            IntPtr pf = Marshal.AllocHGlobal(f.Size), pd = IntPtr.Zero;
            try {
                Marshal.StructureToPtr(f, pf, false);
                var d = new WtData { Size = Marshal.SizeOf(typeof(WtData)), UiChoice = 2, Revocation = 0, Union = 1, File = pf, StateAction = 0 };
                pd = Marshal.AllocHGlobal(d.Size); Marshal.StructureToPtr(d, pd, false);
                int r = WinVerifyTrust(new IntPtr(-1), new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"), pd);
                return r == 0 ? "Valid" : r == unchecked((int)0x800B0100) ? "NotSigned" : "0x" + r.ToString("X8");
            } finally { Marshal.FreeHGlobal(pf); if (pd != IntPtr.Zero) Marshal.FreeHGlobal(pd); }
        }
        static string SignerOf(string file) { try { return X509Certificate.CreateFromSignedFile(file).Subject; } catch { return ""; } }
        static bool SignedBy(string file, string signer) { return SignStatus(file) == "Valid" && SignerOf(file).IndexOf(signer, StringComparison.OrdinalIgnoreCase) >= 0; }
        static string Sha256Of(string file) { using (var s = File.OpenRead(file)) using (var h = SHA256.Create()) return BitConverter.ToString(h.ComputeHash(s)).Replace("-", ""); }
        // скачать и проверить: sha256 (если известен), подпись (если известен издатель; без издателя — неподписанный только с sha256)
        static string SwDownload(SwRel rel, string signer)
        {
            var dst = Path.Combine(DlDir, rel.File);
            Log("Компоненты: загрузка " + rel.Url, "INFO"); HttpDownload(rel.Url, dst, 900);
            if (rel.Sha256.Length > 0 && !string.Equals(Sha256Of(dst), rel.Sha256, StringComparison.OrdinalIgnoreCase)) { File.Delete(dst); throw new Exception("sha256 не совпал"); }
            var st = SignStatus(dst);
            if (signer.Length > 0) { if (!SignedBy(dst, signer)) { File.Delete(dst); throw new Exception("подпись не прошла проверку (ожидался «" + signer + "», статус " + st + ", подписал «" + SignerOf(dst) + "»)"); } }
            else if (st != "Valid" && st != "NotSigned") { File.Delete(dst); throw new Exception("подпись повреждена (" + st + ")"); }
            else if (st == "NotSigned" && rel.Sha256.Length == 0) { File.Delete(dst); throw new Exception("файл не подписан и GitHub не дал sha256 — установите вручную"); }
            return dst;
        }
        static void SwRun(string file, string args, int min)
        {
            var p = file.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)
                ? Process.Start(new ProcessStartInfo("msiexec.exe", "/i \"" + file + "\" /qn /norestart " + args) { UseShellExecute = false, CreateNoWindow = true })
                : Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = false });
            if (!p.WaitForExit(min * 60000)) { try { p.Kill(); } catch { } throw new Exception("установщик завис — прерван"); }
            if (p.ExitCode != 0 && p.ExitCode != 3010) throw new Exception("установщик завершился с кодом " + p.ExitCode);
        }

        // ---------------------------------------------------------------- проверка версий (раз в software.checkHours) и установка
        static void SwCheck(bool force)
        {
            if (!force && (DateTime.Now - SwD("checkedAt")).TotalHours < Math.Max(1, CfgInt("software.checkHours", 12))) return;
            SwState()["checkedAt"] = DateTime.Now.ToString("o");
            SetActivity("проверяю версии компонентов");
            Dictionary<string, object> rel = null;
            foreach (var d in SwDefs) {
                var it = SwItem(d.Id);
                try {
                    switch (d.Id) {
                        case "meduza": rel = rel ?? MzRelease(); { var f = MzReleaseFile(rel, "MeduzaVPN-Setup.exe"); var v = f != null ? Ver2(Convert.ToString(f["version"]).Split('+')[0]).ToString() : ""; it["latest"] = v; SwState()["meduzaRemote"] = v; } break;
                        case "meduzacli": rel = rel ?? MzRelease(); { var f = MzReleaseFile(rel, "meduzavpn-windows.zip"); it["latest"] = f != null ? Ver2(Convert.ToString(f["version"])).ToString() : ""; } break;
                        case "wireguard": it["latest"] = WireGuardLatest().Version; break;
                        case "zapret": { var r = ZGetRelease(""); it["latest"] = r != null ? r.Version : ""; } break;
                        default: it["latest"] = GitHubLatest(d.Repo, d.Asset).Version; break;
                    }
                    it["error"] = "";
                } catch (Exception e) { it["error"] = "проверка: " + e.Message; }
            }
            SwSave(); Log("Компоненты: версии проверены", "INFO");
        }
        static void SwInstall(string id)
        {
            var d = SwDefs.FirstOrDefault(x => x.Id == id); if (d == null) { Log("Компоненты: неизвестный компонент " + id, "WARN"); return; }
            var it = SwItem(id); it["status"] = "устанавливается"; it["error"] = ""; SetActivity("устанавливаю " + d.Name);
            try {
                switch (id) {
                    case "meduza": MzUpdate(true); break;
                    case "meduzacli": SwState()["cliSha256"] = ""; MzCliUpdate(MzRelease()); break;
                    case "zapret": { var z = FindModule("zapret"); if (z != null) { z.Cmds.Enqueue("zapret-update"); z.TickNow = true; z.Wake.Set(); } } break;   // zapret ставит свой модуль
                    case "wireguard": {
                        var rel = WireGuardLatest(); var f = SwDownload(rel, "WireGuard LLC");
                        Log("Компоненты: устанавливаю WireGuard " + rel.Version + " (туннель wg_server на несколько секунд прервётся)", "WARN");
                        SwRun(f, "DO_NOT_LAUNCH=1", 15); try { File.Delete(f); } catch { }
                        Emit("wg.restarted", "установлен WireGuard " + rel.Version);
                    } break;
                    default: {
                        var rel = GitHubLatest(d.Repo, d.Asset); var f = SwDownload(rel, d.Signer);
                        Log("Компоненты: устанавливаю " + d.Name + " " + rel.Version, "INFO");
                        SwRun(f, id == "amneziavpn" ? "install --accept-licenses --default-answer --confirm-command" : (f.EndsWith(".msi") ? "" : ""), 20);   // AmneziaVPN — Qt Installer Framework, тихо
                        try { File.Delete(f); } catch { }
                    } break;
                }
                it["status"] = ""; Uncache("au:^AmneziaVPN|DisplayVersion"); Uncache("au:^WireGuard$|DisplayVersion"); Uncache("mzu:DisplayVersion");
                Log("Компоненты: " + d.Name + " — установлена версия " + SwInstalled(id), "INFO");
            } catch (Exception e) { it["status"] = ""; it["error"] = e.Message; Log("Компоненты: " + d.Name + " — ошибка установки: " + e.Message, "ERROR"); }
            SwSave();
        }
        static void SwInstallMissing() { foreach (var d in SwDefs) if (SwNeeded(d.Id) && SwInstalled(d.Id).Length == 0) SwInstall(d.Id); }

        // ---------------------------------------------------------------- MeduzaVPN: CLI и приложение (раз в meduza.updateCheckHours, в режиме MeduzaVPN или «два туннеля»)
        static string MzSigner { get { return CfgStr("meduza.signer", "IPFB LLC"); } }
        static bool MzDownload(Dictionary<string, object> f, string target)
        {
            foreach (var u in new[] { "versioned_url", "url" }.Where(k => f.ContainsKey(k) && Convert.ToString(f[k]).Length > 0).Select(k => Convert.ToString(f[k]))) {
                try {
                    Log("Загрузка " + u, "INFO"); SetActivity("скачиваю " + Path.GetFileName(u));
                    HttpDownload(u, target, 900);
                    var want = f.ContainsKey("sha256") ? Convert.ToString(f["sha256"]) : "";
                    if (want.Length > 0 && !string.Equals(Sha256Of(target), want, StringComparison.OrdinalIgnoreCase)) throw new Exception("sha256 не совпал");
                    return true;
                } catch (Exception e) { Log("Загрузка не удалась: " + e.Message, "WARN"); try { File.Delete(target); } catch { } }
            }
            return false;
        }
        static void MzCliUpdate(Dictionary<string, object> rel)
        {
            var f = MzReleaseFile(rel, "meduzavpn-windows.zip"); if (f == null) return;
            string sha = f.ContainsKey("sha256") ? Convert.ToString(f["sha256"]) : "";
            if (File.Exists(Cli()) && SwS("cliSha256") == sha) return;
            var zip = Path.Combine(DlDir, "meduzavpn-windows.zip"); if (!MzDownload(f, zip)) return;
            var tmp = Path.Combine(DlDir, "cli_x");
            try {
                if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
                ZipFile.ExtractToDirectory(zip, tmp);
                var nw = Directory.GetFiles(tmp, "meduzavpn.exe", SearchOption.AllDirectories).FirstOrDefault();
                if (nw != null && SignedBy(nw, MzSigner)) { File.Copy(nw, Cli(), true); SwState()["cliSha256"] = sha; SwSave(); Log("CLI meduzavpn обновлён до " + f["version"], "INFO"); }
                else Log("CLI meduzavpn: подпись не прошла проверку, не устанавливаю", "ERROR");
            } finally { try { Directory.Delete(tmp, true); } catch { } try { File.Delete(zip); } catch { } }
        }
        static void MzUpdate(bool force)
        {
            if (!force) {
                string mode = Mode();
                if (!CfgBool("meduza.autoUpdate", true) || (mode != "meduza" && mode != "dual")) return;     // в других режимах — только по кнопке
                if ((DateTime.Now - SwD("meduzaChecked")).TotalHours < Math.Max(1, CfgInt("meduza.updateCheckHours", 6))) return;
            }
            SwState()["meduzaChecked"] = DateTime.Now.ToString("o"); SwSave();
            Dictionary<string, object> rel; try { rel = MzRelease(); } catch (Exception e) { Log("Не удалось получить release.json: " + e.Message, "WARN"); return; }
            try { MzCliUpdate(rel); } catch (Exception e) { Log("Обновление CLI: " + e.Message, "WARN"); }
            var f = MzReleaseFile(rel, "MeduzaVPN-Setup.exe"); if (f == null) { Log("В release.json нет MeduzaVPN-Setup.exe", "WARN"); return; }
            var remote = Ver2(Convert.ToString(f["version"]).Split('+')[0]); var local = Ver2(MzVersion());
            SwState()["meduzaRemote"] = remote.ToString(); SwSave();
            if (remote <= local) { Log("MeduzaVPN " + local + " — актуальная версия", "INFO"); return; }
            Log("MeduzaVPN: доступно обновление " + local + " -> " + remote, "INFO");
            var setup = Path.Combine(DlDir, "MeduzaVPN-Setup-" + remote + ".exe");
            if (!MzDownload(f, setup)) return;
            if (!SignedBy(setup, MzSigner)) { Log("Установщик MeduzaVPN не прошёл проверку подписи — обновление отменено", "ERROR"); try { File.Delete(setup); } catch { } return; }
            var flag = Path.Combine(DataDir, "meduza-updating.flag");
            try { File.WriteAllText(flag, DateTime.Now.ToString("o")); } catch { }               // модуль «Туннели» не трогает MeduzaVPN, пока идёт установка
            try {
                MzStop(); Log("MeduzaVPN: установка " + remote, "INFO"); SetActivity("устанавливаю MeduzaVPN " + remote);
                var p = Process.Start(new ProcessStartInfo(setup, CfgStr("meduza.installerArgs", "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS /NOCANCEL /SP-")) { UseShellExecute = false });
                if (!p.WaitForExit(15 * 60000)) { try { p.Kill(); } catch { } Log("Установщик завис — прерван", "ERROR"); } else Log("Установщик завершился с кодом " + p.ExitCode, "INFO");
                Thread.Sleep(5000); Uncache("mzu:DisplayVersion");
                Log("MeduzaVPN: теперь установлена версия " + MzVersion(), "INFO");
            } catch (Exception e) { Log("Ошибка обновления: " + e.Message, "ERROR"); }
            finally { try { File.Delete(setup); } catch { } try { File.Delete(flag); } catch { } }
            MeduzaStartedAt = DateTime.Now; Wake("tunnels");                                       // туннели сами поднимут MeduzaVPN (или закроют, если он не нужен)
        }

        // ---------------------------------------------------------------- для окна и веба
        static object[] SoftwareSnapshot()
        {
            return SwDefs.Select(d => {
                var it = SwItem(d.Id); string inst = ""; try { inst = SwInstalled(d.Id) ?? ""; } catch { }
                string latest = it.ContainsKey("latest") ? Convert.ToString(it["latest"]) : "";
                bool upd = inst.Length > 0 && latest.Length > 0 && Ver2(inst) > new Version(0, 0) && Ver2(latest) > Ver2(inst);
                return (object)new Dictionary<string, object> { { "id", d.Id }, { "name", d.Name }, { "purpose", d.Purpose }, { "installed", inst }, { "latest", latest }, { "update", upd },
                    { "needed", SwNeeded(d.Id) }, { "status", it.ContainsKey("status") ? it["status"] : "" }, { "error", it.ContainsKey("error") ? it["error"] : "" } };
            }).ToArray();
        }
        static void ComponentsTick() { SwCheck(false); MzUpdate(false); }
        static void ComponentsCmd(string c)
        {
            if (c == "software-check") SwCheck(true);
            else if (c == "install-missing") { SwInstallMissing(); SwCheck(true); }
            else if (c == "check-update") MzUpdate(true);
            else if (c.StartsWith("install ")) { SwInstall(c.Substring(8).Trim()); SwCheck(true); }
        }
    }
}
