// zapret: установка и обновление (релизы GitHub, списки пользователя).
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace VpnGuard
{
    public static partial class Agent
    {
        // ---------------------------------------------------------------- установка / обновление
        static string ZLocalVersion()
        {
            try {
                var f = Path.Combine(ZDir(), ".service", "version.txt"); if (File.Exists(f)) return File.ReadAllLines(f).FirstOrDefault().Trim();
                var sb = Path.Combine(ZDir(), "service.bat");
                if (File.Exists(sb)) { var m = Regex.Match(File.ReadAllText(sb), @"LOCAL_VERSION=([\d\.]+)"); if (m.Success) return m.Groups[1].Value; }
            } catch { }
            return "";
        }
        class ZRelease { public string Version, Url, Name; public long Size; }
        static ZRelease ZGetRelease(string tag)
        {
            var url = tag.Length > 0 ? "https://api.github.com/repos/" + ZRepo + "/releases/tags/" + tag : "https://api.github.com/repos/" + ZRepo + "/releases/latest";
            var r = (Dictionary<string, object>)Json.DeserializeObject(HttpGet(url, 30));
            var asset = ((IEnumerable)r["assets"]).OfType<Dictionary<string, object>>().FirstOrDefault(a => JS(a, "name").EndsWith(".zip", StringComparison.OrdinalIgnoreCase));
            if (asset == null) throw new Exception("в релизе нет .zip");
            long sz; long.TryParse(JS(asset, "size"), out sz);
            return new ZRelease { Version = JS(r, "tag_name").TrimStart('v'), Url = JS(asset, "browser_download_url"), Name = JS(asset, "name"), Size = sz };
        }
        static void ZUserLists()
        {
            var l = Path.Combine(ZDir(), "lists"); if (!Directory.Exists(l)) return;
            var files = new Dictionary<string, string> { { "ipset-exclude-user.txt", "203.0.113.113/32" }, { "list-general-user.txt", "# Never leave this file empty\r\ndomain.example.abc" }, { "list-exclude-user.txt", "domain.example.abc" } };
            foreach (var kv in files) { var p = Path.Combine(l, kv.Key); if (!File.Exists(p)) File.WriteAllText(p, kv.Value + "\r\n", new UTF8Encoding(false)); }
        }
        static void CopyTree(string src, string dst, List<string> errs)
        {
            Directory.CreateDirectory(dst);
            foreach (var f in Directory.GetFiles(src)) { try { File.Copy(f, Path.Combine(dst, Path.GetFileName(f)), true); } catch (Exception e) { errs.Add(e.Message); } }
            foreach (var d in Directory.GetDirectories(src)) CopyTree(d, Path.Combine(dst, Path.GetFileName(d)), errs);
        }
        static void ZInstall(ZRelease rel)
        {
            string dir = ZDir(), dl = Path.Combine(DataDir, "downloads"); Directory.CreateDirectory(dl);
            SetActivity("скачиваю zapret " + rel.Version);
            Log("zapret: загрузка " + rel.Url, "INFO");
            var zip = Path.Combine(dl, rel.Name); HttpDownload(rel.Url, zip, 300);
            if (rel.Size > 0 && new FileInfo(zip).Length != rel.Size) throw new Exception("размер архива не совпал (" + new FileInfo(zip).Length + " вместо " + rel.Size + ")");
            var tmp = Path.Combine(dl, "zapret_x"); try { if (Directory.Exists(tmp)) Directory.Delete(tmp, true); } catch { }
            ZipFile.ExtractToDirectory(zip, tmp);
            var winws = Directory.GetFiles(tmp, "winws.exe", SearchOption.AllDirectories).FirstOrDefault();
            if (winws == null) throw new Exception("в архиве нет bin\\winws.exe");
            var srcRoot = Path.GetDirectoryName(Path.GetDirectoryName(winws));
            SetActivity("устанавливаю zapret " + rel.Version);
            ZStopWinws();
            try { var s = Svc("WinDivert"); if (s != null && s.Status != ServiceControllerStatus.Stopped) { s.Stop(); s.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15)); } } catch { }
            var keep = new Dictionary<string, byte[]>();
            var lists = Path.Combine(dir, "lists");
            if (Directory.Exists(lists)) foreach (var f in Directory.GetFiles(lists, "*-user.txt")) keep[Path.GetFileName(f)] = File.ReadAllBytes(f);
            var errs = new List<string>(); CopyTree(srcRoot, dir, errs);
            if (errs.Count > 0) Log("zapret: не все файлы заменены: " + errs[0], "WARN");
            Directory.CreateDirectory(lists); foreach (var kv in keep) File.WriteAllBytes(Path.Combine(lists, kv.Key), kv.Value);
            ZUserLists();
            try { Directory.Delete(tmp, true); File.Delete(zip); } catch { }
            var v = ZLocalVersion(); Z["version"] = v.Length > 0 ? v : rel.Version;
            ZSetD("lastTest", DateTime.MinValue);           // стратегии могли измениться — переподобрать
            ZSave();
            Log("zapret: установлена версия " + Z["version"] + " в " + dir, "INFO");
        }
        static List<object> ZReleases(bool force)
        {
            var have = ZArr("releases");
            if (!force && have.Count > 0 && (DateTime.Now - ZD("releasesAt")).TotalHours < 12) return have;
            try {
                var list = Json.DeserializeObject(HttpGet("https://api.github.com/repos/" + ZRepo + "/releases?per_page=20", 30)) as object[];
                var res = new List<object>();
                foreach (Dictionary<string, object> r in list) {
                    if (JS(r, "draft") == "True") continue;
                    if (!((IEnumerable)r["assets"]).OfType<Dictionary<string, object>>().Any(a => JS(a, "name").EndsWith(".zip", StringComparison.OrdinalIgnoreCase))) continue;
                    DateTime pd; DateTime.TryParse(JS(r, "published_at"), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out pd);
                    res.Add(new Dictionary<string, object> { { "v", JS(r, "tag_name").TrimStart('v') }, { "tag", JS(r, "tag_name") }, { "date", pd.ToLocalTime().ToString("dd.MM.yyyy") }, { "pre", JS(r, "prerelease") == "True" } });
                }
                Z["releases"] = res; Z["releasesAt"] = DateTime.Now.ToString("o"); ZSave(); return res;
            } catch (Exception e) { Log("zapret: не удалось получить список версий: " + e.Message, "WARN"); }
            return have;
        }
        static void ZUpdate(bool force)
        {
            bool inst = ZInstalled(); double since = (DateTime.Now - ZD("lastUpdateCheck")).TotalMinutes;
            string pin = ZC("version").Trim();
            if (pin.Length > 0) {                          // выбрана конкретная версия — ставим её и не обновляем
                var local0 = ZLocalVersion();
                if (inst && local0.Length > 0 && local0.TrimStart('v') == pin.TrimStart('v')) { Z["version"] = local0; return; }
                if (!force && since < 10) return;
                ZSetD("lastUpdateCheck", DateTime.Now);
                var tag = ZArr("releases").Where(r => JS(r, "v") == pin.TrimStart('v')).Select(r => JS(r, "tag")).FirstOrDefault() ?? pin;
                ZRelease rel0;
                try { rel0 = ZGetRelease(tag); } catch (Exception e) { Z["lastError"] = "версия " + pin + " не найдена на GitHub: " + e.Message; Log("zapret: " + Z["lastError"], "ERROR"); ZSave(); return; }
                Log("zapret: ставлю выбранную версию " + rel0.Version + " (установлена: " + (local0.Length > 0 ? local0 : "нет") + ")", "WARN");
                try { ZInstall(rel0); Z["lastError"] = ""; } catch (Exception e) { Z["lastError"] = "установка: " + e.Message; Log("zapret: ошибка установки: " + e.Message, "ERROR"); }
                ZSave(); return;
            }
            if (!force) {
                if (inst) { if (!ZB("autoUpdate") || since < ZI("updateCheckHours") * 60.0) return; }
                else if (since < 10) return;                // не установлен: пробуем не чаще раза в 10 мин
            }
            ZSetD("lastUpdateCheck", DateTime.Now);
            ZRelease rel;
            try { rel = ZGetRelease(""); } catch (Exception e) { Log("zapret: не удалось узнать последнюю версию: " + e.Message, "WARN"); ZSave(); return; }
            Z["remoteVersion"] = rel.Version;
            var local = ZLocalVersion();
            if (inst && local.Length > 0 && Ver(rel.Version) <= Ver(local)) { Z["version"] = local; ZSave(); Log("zapret " + local + " — актуальная версия", "INFO"); return; }
            Log("zapret: доступна версия " + rel.Version + " (установлена: " + (local.Length > 0 ? local : "нет") + ")", "INFO");
            try { ZInstall(rel); } catch (Exception e) { Z["lastError"] = "установка: " + e.Message; Log("zapret: ошибка установки: " + e.Message, "ERROR"); }
            ZSave();
        }
    }
}
