// Модуль «Обновление VpnGuard»: автообновление самого приложения из репозитория GitHub (раньше — Update.ps1 в части PowerShell).
// Источник: https://github.com/<update.repo> (ветка update.branch), в корне — vpnguard-manifest.json { version, build, notes, files: [{ path, sha256, size }] }.
// Файлы — по SHA коммита (raw.githubusercontent.com/<repo>/<sha>/<path>): неизменяемые адреса, без кэша. Каждый сверяется с sha256 из манифеста,
// .ps1 — проверяются парсером PowerShell, новый код агента и веб-сервера сначала пробно собирается (не собрался — обновление не ставится:
// иначе на ПК остался бы агент, который уже не может обновиться сам). Старые файлы — в data\backup\app-* (5 последних).
// config.json, data\, zapret\, bin\ не трогаются никогда. Запасной путь — Update.ps1 (команда app-update-ps).
// Проверено на ПК выпуском 3.42.1: установлен этим модулем.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace VpnGuard
{
    public static partial class Agent
    {
        static string AppStatePath { get { return Path.Combine(DataDir, "app-update.json"); } }
        static Dictionary<string, object> AppSt;
        static Dictionary<string, object> AppState()
        {
            if (AppSt != null) return AppSt;
            try { AppSt = File.Exists(AppStatePath) ? Json.DeserializeObject(File.ReadAllText(AppStatePath, Encoding.UTF8)) as Dictionary<string, object> : null; } catch { }
            return AppSt ?? (AppSt = new Dictionary<string, object>());
        }
        static string AS(string k) { object v; return AppState().TryGetValue(k, out v) && v != null ? Convert.ToString(v) : ""; }
        static void AppSave() { try { File.WriteAllText(AppStatePath, Json.Serialize(AppState()), Encoding.UTF8); } catch { } }

        static string GhGet(string url, int sec)
        {
            var rq = (HttpWebRequest)WebRequest.Create(url); rq.UserAgent = "VpnGuard-updater"; rq.Timeout = sec * 1000; rq.ReadWriteTimeout = sec * 1000;
            var tok = CfgStr("update.token", ""); if (tok.Length > 0) rq.Headers["Authorization"] = "token " + tok;      // закрытый репозиторий
            rq.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            using (var rs = rq.GetResponse()) using (var rd = new StreamReader(rs.GetResponseStream(), Encoding.UTF8)) return rd.ReadToEnd();
        }
        static byte[] GhBytes(string url, int sec)
        {
            var rq = (HttpWebRequest)WebRequest.Create(url); rq.UserAgent = "VpnGuard-updater"; rq.Timeout = sec * 1000; rq.ReadWriteTimeout = sec * 1000;
            var tok = CfgStr("update.token", ""); if (tok.Length > 0) rq.Headers["Authorization"] = "token " + tok;
            using (var rs = rq.GetResponse()) using (var s = rs.GetResponseStream()) using (var ms = new MemoryStream()) { s.CopyTo(ms); return ms.ToArray(); }
        }
        // путь из манифеста: только файлы приложения в его папке
        static bool AppPathOk(string p)
        {
            if (!Regex.IsMatch(p ?? "", @"^[A-Za-z0-9_\-\.]+(/[A-Za-z0-9_\-\.]+)*$") || p.Contains("..")) return false;
            if (Regex.IsMatch(p, @"^(data|zapret|bin|\.git)(/|$)", RegexOptions.IgnoreCase) || p.Equals("config.json", StringComparison.OrdinalIgnoreCase)) return false;
            return Regex.IsMatch(p, @"\.(ps1|cmd|cs|md|txt|html|js|css)$", RegexOptions.IgnoreCase);
        }
        static string LocalSha(string path) { return File.Exists(path) ? Sha256Of(path).ToLowerInvariant() : ""; }
        class AppLatest { public string Sha, Version, Build, Notes, Repo; public List<Dictionary<string, object>> Changed; }
        static AppLatest AppGetLatest()
        {
            string repo = CfgStr("update.repo", "Fogiku/vpnguard"), branch = CfgStr("update.branch", "main");
            if (repo.Length == 0) throw new Exception("не указан репозиторий (Настройки → Обновление приложения)");
            var c = Json.DeserializeObject(GhGet("https://api.github.com/repos/" + repo + "/commits/" + branch, 30)) as Dictionary<string, object>;
            string sha = c != null && c.ContainsKey("sha") ? Convert.ToString(c["sha"]) : "";
            if (!Regex.IsMatch(sha, "^[0-9a-f]{40}$")) throw new Exception("GitHub не вернул коммит");
            var mt = Json.DeserializeObject(GhGet("https://raw.githubusercontent.com/" + repo + "/" + sha + "/vpnguard-manifest.json", 30)) as Dictionary<string, object>;
            var files = mt != null && mt.ContainsKey("files") ? (mt["files"] as object[] ?? new object[0]).OfType<Dictionary<string, object>>().ToList() : null;
            if (files == null || files.Count == 0) throw new Exception("в репозитории нет vpnguard-manifest.json или он пустой");
            files = files.Where(f => AppPathOk(Convert.ToString(f["path"])) && Regex.IsMatch(Convert.ToString(f["sha256"]), "^[0-9a-fA-F]{64}$")).ToList();
            var changed = files.Where(f => LocalSha(Path.Combine(Root, Convert.ToString(f["path"]).Replace('/', '\\'))) != Convert.ToString(f["sha256"]).ToLowerInvariant()).ToList();
            Func<string, string> m = k => mt.ContainsKey(k) ? Convert.ToString(mt[k]) : "";
            return new AppLatest { Sha = sha, Version = m("version"), Build = m("build"), Notes = m("notes"), Repo = repo, Changed = changed };
        }
        static void AppCheck(bool install)
        {
            var st = AppState(); st["checkedAt"] = DateTime.Now.ToString("o");
            if (CfgStr("update.repo", "Fogiku/vpnguard").Length == 0) { st["error"] = "не указан репозиторий"; AppSave(); return; }
            AppLatest l;
            try { l = AppGetLatest(); } catch (Exception e) { st["error"] = "проверка: " + e.Message; AppSave(); Log("Обновление VpnGuard: " + st["error"], "WARN"); return; }
            st["latestSha"] = l.Sha; st["latestVersion"] = l.Version; st["latestBuild"] = l.Build; st["notes"] = l.Notes; st["pending"] = l.Changed.Count; st["error"] = "";
            if (l.Changed.Count == 0) { if (AS("sha") != l.Sha) { st["sha"] = l.Sha; st["version"] = l.Version; st["build"] = l.Build; } AppSave(); return; }
            Log("Обновление VpnGuard: доступна версия " + l.Version + " (сборка " + l.Build + "), изменилось файлов: " + l.Changed.Count + " — " + string.Join(", ", l.Changed.Select(f => f["path"])), "INFO");
            AppSave();
            if (install) AppInstall(l);
        }
        // исходники веб-сервера в новой версии: строка WebSources = { ... } из её agent\WebHost.cs
        static string[] AppWebSources(string stage)
        {
            foreach (var f in new[] { Path.Combine(stage, "agent", "WebHost.cs"), Path.Combine(Root, "agent", "WebHost.cs") }) {
                if (!File.Exists(f)) continue;
                var m = Regex.Match(File.ReadAllText(f), @"WebSources\s*=\s*\{([^}]*)\}");
                if (!m.Success) continue;
                var list = Regex.Matches(m.Groups[1].Value, "@?\"([^\"]+)\"").Cast<Match>().Select(x => x.Groups[1].Value.Replace("\\\\", "\\")).ToArray();
                if (list.Length > 0) return list;
            }
            return WebSources;
        }
        // пробная сборка программы на C# из новых исходников (остальные — текущие): не собралась — обновление не ставить
        static string AppTryBuild(string stage, string name, IEnumerable<string> sources, string target, string[] refs)
        {
            var csc = CscPath(); if (csc.Length == 0) return null;                // нечем собрать — не мешаем обновлению (VpnGuard.ps1 оставит прежнюю сборку)
            var outExe = Path.Combine(stage, "_build_" + name + ".exe");
            var src = sources.Select(s => File.Exists(Path.Combine(stage, s)) ? Path.Combine(stage, s) : Path.Combine(Root, s)).Where(File.Exists).ToList();
            var r = Exe(csc, "/nologo /target:" + target + " /optimize+ /out:\"" + outExe + "\" " + string.Join(" ", refs.Select(x => "/r:" + x)) + " " + string.Join(" ", src.Select(s => "\"" + s + "\"")), 180);
            try { File.Delete(outExe); } catch { }
            return r.Code == 0 ? null : string.Join(" | ", (r.Out + "\n" + r.Err).Split('\n').Where(x => x.Contains("error")).Take(3));
        }
        static void AppInstall(AppLatest l)
        {
            var st = AppState();
            SetActivity("обновляю VpnGuard до " + l.Version);
            var stage = Path.Combine(DataDir, "update", l.Sha.Substring(0, 12));
            try { if (Directory.Exists(stage)) Directory.Delete(stage, true); } catch { }
            Directory.CreateDirectory(stage);
            try {
                // 1. скачать и сверить
                foreach (var f in l.Changed) {
                    string p = Convert.ToString(f["path"]), rel = p.Replace('/', '\\'), dst = Path.Combine(stage, rel);
                    Directory.CreateDirectory(Path.GetDirectoryName(dst));
                    File.WriteAllBytes(dst, GhBytes("https://raw.githubusercontent.com/" + l.Repo + "/" + l.Sha + "/" + p, 120));
                    var h = LocalSha(dst);
                    if (h != Convert.ToString(f["sha256"]).ToLowerInvariant()) throw new Exception("контрольная сумма " + p + " не совпала (скачано " + h + ")");
                }
                // 2. код без ошибок: .ps1 — парсером PowerShell (отдельный процесс, только при обновлении); агент и веб-сервер — пробной сборкой
                var ps1 = l.Changed.Select(f => Path.Combine(stage, Convert.ToString(f["path"]).Replace('/', '\\'))).Where(x => x.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)).ToList();
                if (ps1.Count > 0) {
                    var list = Path.Combine(stage, "_ps1.txt"); File.WriteAllLines(list, ps1, Encoding.UTF8);
                    var r = Exe("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -Command \"$bad = @(); foreach ($f in Get-Content -LiteralPath '" + list + "' -Encoding UTF8) { $e = $null; [void][Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$e); if ($e.Count) { $bad += ((Split-Path $f -Leaf) + ': ' + $e[0].Message + ' (строка ' + $e[0].Extent.StartLineNumber + ')') } }; if ($bad.Count) { [Console]::Out.Write($bad[0]); exit 1 }\"", 120);
                    if (r.Code != 0) throw new Exception("ошибка в коде: " + (r.Out + r.Err).Trim());
                }
                var paths = l.Changed.Select(f => Convert.ToString(f["path"])).ToList();
                if (paths.Any(p => p.StartsWith("agent/", StringComparison.OrdinalIgnoreCase) || p.Equals("VpnGuard.ps1", StringComparison.OrdinalIgnoreCase))) {
                    // исходники агента: все agent\*.cs из новой версии (новые файлы) и текущие
                    var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var d in new[] { Path.Combine(Root, "agent"), Path.Combine(stage, "agent") }) if (Directory.Exists(d)) foreach (var x in Directory.GetFiles(d, "*.cs")) names.Add("agent\\" + Path.GetFileName(x));
                    var err = AppTryBuild(stage, "agent", names, "winexe", new[] { "System.Web.Extensions.dll", "System.ServiceProcess.dll", "System.Management.dll", "System.Core.dll", "Microsoft.CSharp.dll", "System.IO.Compression.dll", "System.IO.Compression.FileSystem.dll" });
                    if (err != null) throw new Exception("новый агент не собирается: " + err);
                }
                // список исходников веб-сервера — из новой версии (в ней могли появиться новые файлы), иначе — текущий
                var webSrc = AppWebSources(stage);
                if (paths.Any(p => webSrc.Contains(p.Replace('/', '\\'), StringComparer.OrdinalIgnoreCase))) {
                    var err = AppTryBuild(stage, "web", webSrc, "exe", WebRefs);
                    if (err != null) throw new Exception("новый веб-сервер не собирается: " + err);
                }
                // 3. резервная копия заменяемых файлов (5 последних)
                var bk = Path.Combine(DataDir, "backup", "app-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + (AS("version").Length > 0 ? AS("version") : Version));
                Directory.CreateDirectory(bk);
                foreach (var p in paths) { var src = Path.Combine(Root, p.Replace('/', '\\')); if (File.Exists(src)) { var d = Path.Combine(bk, p.Replace('/', '\\')); Directory.CreateDirectory(Path.GetDirectoryName(d)); File.Copy(src, d, true); } }
                try { foreach (var d in new DirectoryInfo(Path.Combine(DataDir, "backup")).GetDirectories("app-*").OrderByDescending(x => x.Name).Skip(5)) d.Delete(true); } catch { }
                // 4. заменить: остальное — сначала, VpnGuard.ps1 — последним
                foreach (var p in paths.OrderBy(p => p.Equals("VpnGuard.ps1", StringComparison.OrdinalIgnoreCase) ? 1 : 0)) {
                    var rel = p.Replace('/', '\\'); var dst = Path.Combine(Root, rel);
                    Directory.CreateDirectory(Path.GetDirectoryName(dst));
                    File.Copy(Path.Combine(stage, rel), dst + ".new", true);
                    if (File.Exists(dst)) File.Replace(dst + ".new", dst, null); else File.Move(dst + ".new", dst);
                }
                st["sha"] = l.Sha; st["version"] = l.Version; st["build"] = l.Build; st["at"] = DateTime.Now.ToString("o"); st["pending"] = 0; st["error"] = "";
                AppSave();
                Log("Обновление VpnGuard: установлена версия " + l.Version + " (сборка " + l.Build + "), файлов: " + paths.Count + "; копия старых — " + bk + ". Агент и веб-сервер перезапустятся сами.", "WARN");
            } catch (Exception e) {
                st["error"] = "установка: " + e.Message; AppSave();
                Log("Обновление VpnGuard не установлено: " + e.Message + " — работаю на текущей версии", "ERROR");
            } finally { try { Directory.Delete(stage, true); } catch { } }
        }
        static void AppUpdateTick()
        {
            if (CfgStr("update.repo", "Fogiku/vpnguard").Length == 0 || !CfgBool("update.auto", true)) return;
            DateTime at; DateTime.TryParse(AS("checkedAt"), null, System.Globalization.DateTimeStyles.RoundtripKind, out at);
            if ((DateTime.Now - at).TotalHours < Math.Max(1, CfgInt("update.checkHours", 3))) return;
            AppCheck(true);
        }
        static void AppUpdateCmd(string c) { if (c == "app-check") AppCheck(false); else if (c == "app-update") AppCheck(true); }
        static Dictionary<string, object> AppSnapshot()
        {
            return new Dictionary<string, object> { { "repo", CfgStr("update.repo", "Fogiku/vpnguard") }, { "branch", CfgStr("update.branch", "main") }, { "auto", CfgBool("update.auto", true) },
                { "checkHours", CfgInt("update.checkHours", 3) }, { "version", Version }, { "build", AS("build") }, { "sha", AS("sha") }, { "installedAt", AS("at") },
                { "latestVersion", AS("latestVersion") }, { "latestBuild", AS("latestBuild") }, { "notes", AS("notes") }, { "pending", AS("pending").Length > 0 ? int.Parse(AS("pending")) : 0 },
                { "checkedAt", AS("checkedAt") }, { "error", AS("error") } };
        }
    }
}
