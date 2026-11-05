// zapret: проверка сайтов (curl) и подбор стратегии отдельным процессом.
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
        // ---------------------------------------------------------------- проверка сайтов
        static List<string> ZTargets()
        {
            var t = CfgList("zapret.testTargets", ZDefTargets).Where(x => x.Length > 0).ToList();
            if (ZB("videoCheck")) { if (!t.Contains("ytspeed")) t.Add("ytspeed"); if (!t.Contains("ytvideo")) t.Add("ytvideo"); }
            return t;
        }
        static string ZLabel(string s)
        {
            if (s == "ytvideo") return "YouTube: видео (googlevideo)";
            if (s == "ytspeed") return "YouTube: скорость загрузки";
            if (Regex.IsMatch(s, @"^get\s.*youtube\.com")) return "YouTube: загрузка страницы";
            if (s.Contains("redirector.googlevideo")) return "YouTube: выбор видеосервера";
            if (s.Contains("ytimg.com")) return "YouTube: превью";
            if (Regex.IsMatch(s, @"youtube\.com|youtu\.be")) return "YouTube: сайт";
            if (s.Contains("gateway.discord")) return "Discord: чат (gateway)";
            if (Regex.IsMatch(s, @"cdn\.discordapp|discordcdn")) return "Discord: файлы (CDN)";
            if (s.Contains("discord")) return "Discord: сайт";
            return Regex.Replace(Regex.Replace(Regex.Replace(s, @"^get\s+", ""), "^https?://", ""), "/.*$", "");
        }
        static string Kb(long b) { return (b / 1024.0).ToString("N0", CultureInfo.GetCultureInfo("ru-RU")); }
        static string CurlReason(int exit, string code, long size, long min, int ms)
        {
            if (exit == 0 && min > 0 && size < min) return "получено только " + Kb(size) + " КБ — загрузка обрывается";
            if (exit == 0 && !Regex.IsMatch(code ?? "", "^[1-5]\\d\\d$")) return "нет HTTP-ответа";
            if (exit == 0) return "";
            if (exit == 28 && size > 0 && size < 40960) return "оборвалось после " + Kb(size) + " КБ — DPI режет загрузку";
            if (exit == 28 && size > 0) { double s = Math.Max(1, ms) / 1000.0; return "медленно: " + Kb(size) + " КБ за " + s.ToString("N0") + " с (≈" + (size / 1024.0 / Math.Max(1, ms / 1000.0)).ToString("N0") + " КБ/с) — похоже на замедление"; }
            switch (exit) {
                case 6: return "не найден адрес (DNS)"; case 7: return "нет соединения"; case 18: return "передача оборвалась";
                case 28: return "таймаут — похоже на блокировку"; case 35: return "сброс при TLS-рукопожатии (DPI)"; case 52: return "пустой ответ";
                case 56: return "соединение сброшено (DPI)"; case 60: return "чужой сертификат — заглушка провайдера";
                case -1: return "curl не завершился"; case -2: return "не удалось узнать адрес видеосервера";
            }
            return "ошибка curl " + exit;
        }
        static string Curl { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "curl.exe"); } }
        const string UaChrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36";
        static string FindVideoHost(string srcIp, int timeoutSec, bool physOnly)
        {
            var vias = new List<string> { srcIp }; if (!string.IsNullOrEmpty(srcIp) && !physOnly) vias.Add("");
            foreach (var via in vias) {
                string ifa = string.IsNullOrEmpty(via) ? "" : "--interface " + via + " ";
                var r = Exe(Curl, "-s --connect-timeout 4 -m " + timeoutSec + " " + ifa + "\"https://redirector.googlevideo.com/report_mapping?di=no\"", timeoutSec + 5);
                var m = Regex.Match(r.Out, @"\b(sn-[a-z0-9-]{4,})");
                if (m.Success) { ZVideoVia = string.IsNullOrEmpty(via) ? "vpn" : "direct"; return "rr1---" + m.Groups[1].Value + ".googlevideo.com"; }
                r = Exe(Curl, "-s -L --connect-timeout 4 -m " + (timeoutSec + 7) + " " + ifa + "-A \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\" \"https://www.youtube.com/watch?v=jNQXAC9IVRw\"", timeoutSec + 12);
                m = Regex.Match(r.Out, @"rr\d{1,2}---(sn-[a-z0-9-]{4,})\.googlevideo\.com");
                if (m.Success) { ZVideoVia = string.IsNullOrEmpty(via) ? "vpn" : "direct"; return "rr1---" + m.Groups[1].Value + ".googlevideo.com"; }
            }
            return "";
        }
        static string VideoHost(string srcIp, int timeoutSec)
        {
            var at = ZD("videoHostAt"); string cur = ZS("videoHost");
            bool fresh = ZS("videoHostVia") != "direct" ? (DateTime.Now - at).TotalMinutes < 30 : (DateTime.Now - at).TotalHours < 6;
            if (cur.Length > 0 && fresh) return cur;
            if ((DateTime.Now - ZVideoMissAt).TotalMinutes < 30) return cur;      // недавно не нашли — не искать при каждой проверке
            var h = FindVideoHost(srcIp, timeoutSec, false);
            if (h.Length > 0) {
                if (ZVideoVia == "vpn" && ZS("videoHostVia") == "direct" && cur.Length > 0) { ZSetD("videoHostAt", DateTime.Now); return cur; }   // прямой лучше
                if (ZVideoVia == "direct" && cur != h) ZSetD("lastRouteRefresh", DateTime.MinValue);   // новый сервер провайдера — сразу маршруты
                Z["videoHost"] = h; ZSetD("videoHostAt", DateTime.Now); Z["videoHostVia"] = ZVideoVia; ZVideoMissAt = DateTime.MinValue; return h;
            }
            ZVideoMissAt = DateTime.Now; return cur;
        }
        static string YtSpeedUrl(string srcIp)
        {
            if (ZS("ytJs").Length > 0 && (DateTime.Now - ZD("ytJsAt")).TotalHours < 6) return ZS("ytJs");
            string ifa = string.IsNullOrEmpty(srcIp) ? "" : "--interface " + srcIp + " ";
            var r = Exe(Curl, "-s -L --compressed --connect-timeout 4 -m 15 " + ifa + "-A \"" + UaChrome + "\" \"https://www.youtube.com/\"", 20);
            var m = Regex.Match(r.Out, @"/s/player/[A-Za-z0-9_\-]+/[A-Za-z0-9_\.\-]+/[A-Za-z_]+/base\.js");
            if (m.Success) { Z["ytJs"] = "https://www.youtube.com" + m.Value; Z["ytJsAt"] = DateTime.Now.ToString("o"); }
            return ZS("ytJs");
        }
        class ZCheck { public string Url, Label, Code = "", Why = "", Host = ""; public bool Ok; public int Exit, Kb, Ms; public double Mbit; }
        // параллельно проверить сайты curl'ом с адреса физического адаптера (мимо VPN)
        static List<ZCheck> ZTest(string srcIp, List<string> urls, int timeoutSec)
        {
            string vh = urls.Contains("ytvideo") ? VideoHost(srcIp, Math.Max(6, timeoutSec)) : "", ys = urls.Contains("ytspeed") ? YtSpeedUrl(srcIp) : "";
            var jobs = new List<Tuple<string, string, bool, Process, Stopwatch>>();
            foreach (var spec in urls) {
                string u = spec; bool get = false;
                if (spec == "ytvideo") { if (vh.Length == 0) { jobs.Add(Tuple.Create(spec, "", false, (Process)null, (Stopwatch)null)); continue; } u = "https://" + vh + "/generate_204"; }
                else if (spec == "ytspeed") { if (ys.Length == 0) { jobs.Add(Tuple.Create(spec, "", false, (Process)null, (Stopwatch)null)); continue; } u = ys; get = true; }
                else { var gm = Regex.Match(spec, @"^get\s+(\S+)"); if (gm.Success) { u = gm.Groups[1].Value; get = true; } }
                string mode = get ? "-L -A \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\"" : "-I";
                int tmo = get ? timeoutSec + 5 : timeoutSec;
                string args = mode + " -s -o NUL -w \"%{http_code} %{size_download} %{time_total} %{time_connect} %{time_appconnect}\" -m " + tmo + " --connect-timeout 3" + (string.IsNullOrEmpty(srcIp) ? "" : " --interface " + srcIp) + " \"" + u + "\"";
                Process p = null;
                try { p = Process.Start(new ProcessStartInfo(Curl, args) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true }); } catch { }
                jobs.Add(Tuple.Create(spec, u, get, p, Stopwatch.StartNew()));
            }
            var outs = jobs.Select(j => j.Item4 != null ? j.Item4.StandardOutput.ReadToEndAsync() : null).ToList();
            foreach (var j in jobs) {
                if (j.Item4 == null) continue;
                int lim = j.Item3 ? timeoutSec + 8 : timeoutSec + 3;
                if (!j.Item4.WaitForExit((int)Math.Max(500, lim * 1000 - j.Item5.ElapsedMilliseconds))) { try { j.Item4.Kill(); } catch { } }
            }
            var res = new List<ZCheck>(); var inv = CultureInfo.InvariantCulture;
            for (int i = 0; i < jobs.Count; i++) {
                var j = jobs[i]; var c = new ZCheck { Url = j.Item1, Label = ZLabel(j.Item1) };
                if (j.Item4 == null) { c.Exit = -2; c.Ms = -1; c.Why = j.Item1 == "ytspeed" ? "не удалось открыть www.youtube.com" : CurlReason(-2, "", 0, 0, 0); res.Add(c); continue; }
                string o = ""; try { if (outs[i].Wait(2000)) o = outs[i].Result.Trim(); } catch { }
                c.Exit = j.Item4.HasExited ? j.Item4.ExitCode : -1;
                var pp = Regex.Split(o, @"\s+"); c.Code = pp.Length > 0 ? pp[0] : ""; long size = 0; if (pp.Length > 1) long.TryParse(pp[1], out size);
                double tt = 0, tc = 0, ta = 0;
                if (pp.Length > 2) double.TryParse(pp[2], NumberStyles.Float, inv, out tt);
                if (pp.Length > 4) { double.TryParse(pp[3], NumberStyles.Float, inv, out tc); double.TryParse(pp[4], NumberStyles.Float, inv, out ta); }
                c.Ms = tt > 0 ? (int)(tt * 1000) : (int)j.Item5.ElapsedMilliseconds;
                c.Why = CurlReason(c.Exit, c.Code, size, j.Item3 ? 65536 : 0, c.Ms);
                if (j.Item1 == "ytspeed" && size > 0) {                // нужно ≥ 1,5 Мбит/с (видео 480p)
                    c.Mbit = Math.Round(size * 8 / 1e6 / Math.Max(0.2, c.Ms / 1000.0), 1);
                    if (c.Exit == 0 || c.Exit == 28) c.Why = c.Mbit >= 1.5 ? "" : "≈" + c.Mbit.ToString(CultureInfo.GetCultureInfo("ru-RU")) + " Мбит/с — мало для видео (замедление)";
                }
                if (c.Exit == 28 && size == 0 && pp.Length > 4) {
                    if (tc == 0) c.Why = "не соединяется — адрес недоступен или заблокирован";
                    else if (ta == 0 && j.Item2.StartsWith("https:")) c.Why = "зависает TLS-рукопожатие — блокировка по имени сайта (DPI)";
                    else c.Why = "сервер не ответил — таймаут после соединения";
                }
                c.Ok = c.Why.Length == 0; c.Kb = (int)(size / 1024);
                try { c.Host = new Uri(j.Item2).Host; } catch { }
                res.Add(c);
            }
            return res;
        }
        static List<object> ZChecks(List<ZCheck> r)
        {
            return r.Select(c => (object)new Dictionary<string, object> { { "n", c.Label }, { "ok", c.Ok }, { "why", c.Why }, { "ms", c.Ms }, { "h", c.Host }, { "kb", c.Kb }, { "mbit", c.Mbit } }).ToList();
        }

        // ---------------------------------------------------------------- подбор стратегии (в потоке модуля zapret)
        static Dictionary<string, object> ZTestRunner()
        {
            Dictionary<string, object> t;
            try { t = Json.DeserializeObject(File.ReadAllText(ZTestPath, Encoding.UTF8)) as Dictionary<string, object>; } catch { return null; }
            if (t == null || JS(t, "running") != "True") return null;
            int pid; if (!int.TryParse(JS(t, "pid"), out pid) || pid <= 0) return null;
            try { var p = Process.GetProcessById(pid); return p.HasExited ? null : t; } catch { return null; }
        }
        static void ZStartTest(string reason)
        {
            if (ZTestRunner() != null) return;
            if (InetDown()) { Log("zapret: подбор стратегии отложен — нет интернета (" + reason + ")", "INFO"); return; }
            if (!ZInstalled()) { Log("zapret: не установлен — подбирать нечего", "WARN"); return; }
            Log("zapret: запускаю подбор стратегии (" + reason + ")", "INFO");
            ZRunTest();                                        // в потоке модуля zapret: winws и состояние zapret трогает только он
            ZReceiveTest();
        }
        // подбор стратегии (раньше — отдельный процесс PowerShell -ZapretTest): без zapret и с каждой стратегией проверить сайты напрямую.
        // Ход и результат — в data\zapret-test.json (его же читает окно), после каждого шага модуль публикует своё состояние
        static void ZRunTest()
        {
            var prog = new Dictionary<string, object> { { "running", true }, { "pid", Process.GetCurrentProcess().Id }, { "started", DateTime.Now.ToString("o") }, { "index", 0 }, { "total", 0 },
                { "current", "" }, { "results", new object[0] }, { "best", "" }, { "error", "" } };
            var res = new List<Dictionary<string, object>>();
            Action write = () => {
                prog["results"] = res.Cast<object>().ToArray();
                try { File.WriteAllText(ZTestPath, Json.Serialize(prog), Bom); } catch { }
                var m = FindModule("zapret"); if (m != null) PublishState(m);
            };
            int tmo = ZI("curlTimeoutSec");
            try {
                var path = ZPhys(); if (path == null) throw new Exception("не найден физический адаптер с выходом в интернет");
                var names = ZStrategies(); if (names.Count == 0) throw new Exception("нет файлов general*.bat");
                var urls = ZTargets();
                prog["total"] = names.Count + 1;
                ZStopService(); ZStopWinws();
                if (urls.Contains("ytvideo")) {                // адрес видеосервера — заново (через VPN, если напрямую закрыт)
                    Z["videoHost"] = ""; var vh = FindVideoHost(path.Ip, 8, false);
                    if (vh.Length > 0) { Z["videoHost"] = vh; ZSetD("videoHostAt", DateTime.Now); Z["videoHostVia"] = ZVideoVia; } else ZVideoMissAt = DateTime.Now;
                }
                prog["videoHost"] = ZS("videoHost"); prog["videoHostVia"] = ZS("videoHostVia");
                Func<string, List<ZCheck>, string, Dictionary<string, object>> row = (name, r, err) => new Dictionary<string, object> {
                    { "name", name }, { "ok", r.Count(c => c.Ok) }, { "total", urls.Count }, { "failed", r.Where(c => !c.Ok).Select(c => (object)c.Label).ToArray() },
                    { "error", err }, { "checks", ZChecks(r).ToArray() }, { "ms", name == "(без zapret)" ? 0 : r.Where(c => c.Ok).Sum(c => c.Ms) } };
                // без zapret: блокирует ли провайдер вообще
                prog["index"] = 1; prog["current"] = "(без zapret)"; write();
                res.Add(row("(без zapret)", ZTest(path.Ip, urls, tmo), ""));
                int i = 1;
                foreach (var n in names) {
                    i++; prog["index"] = i; prog["current"] = n; write(); SetActivity("zapret: пробую стратегию " + n + " (" + (i - 1) + " из " + names.Count + ")");
                    var r = new List<ZCheck>(); string err = "";
                    try {
                        ZStartWinws(n); Thread.Sleep(800);
                        r = ZTest(path.Ip, urls, tmo);
                        // адрес видеосервера ещё неизвестен, а YouTube с этой стратегией открылся — узнать его напрямую и проверить видео
                        if (ZS("videoHost").Length == 0 && urls.Contains("ytvideo") && r.Any(c => (c.Ok || c.Kb > 0) && c.Label.StartsWith("YouTube") && c.Url != "ytvideo" && c.Url != "ytspeed")) {
                            var vh = FindVideoHost(path.Ip, 6, true);
                            if (vh.Length > 0) {
                                Z["videoHost"] = vh; ZSetD("videoHostAt", DateTime.Now); Z["videoHostVia"] = "direct"; prog["videoHost"] = vh; prog["videoHostVia"] = "direct";
                                r = r.Where(c => c.Url != "ytvideo").Concat(ZTest(path.Ip, new List<string> { "ytvideo" }, tmo)).ToList();
                                foreach (var prev in res) foreach (var c in ((object[])prev["checks"]).OfType<Dictionary<string, object>>())
                                    if (Convert.ToString(c["n"]).Contains("видео") && !(bool)c["ok"]) c["why"] = "не проверено — адрес видеосервера узнан позже";
                            }
                        }
                    } catch (Exception e) { err = e.Message; }
                    ZStopWinws();
                    res.Add(row(n, r, err));
                }
                // лучшая: больше всего открытых сайтов; при равенстве — где работает видео, затем быстрее загрузка, затем меньше времени
                Func<Dictionary<string, object>, IEnumerable<Dictionary<string, object>>> chk = x => ((object[])x["checks"]).OfType<Dictionary<string, object>>();
                var best = res.Where(x => (string)x["name"] != "(без zapret)")
                    .OrderByDescending(x => (int)x["ok"])
                    .ThenByDescending(x => chk(x).Count(c => Convert.ToString(c["n"]).Contains("видео") && (bool)c["ok"]))
                    .ThenByDescending(x => chk(x).Where(c => Convert.ToString(c["n"]).Contains("скорость") || Convert.ToString(c["n"]).Contains("загрузка страницы")).Sum(c => Convert.ToDouble(c["mbit"]) > 0 ? Convert.ToDouble(c["mbit"]) * 1000 : Convert.ToDouble(c["kb"])))
                    .ThenBy(x => Convert.ToInt32(x["ms"])).FirstOrDefault();
                prog["best"] = best != null && (int)best["ok"] > 0 ? best["name"] : "";
            } catch (Exception e) { prog["error"] = e.Message; }
            finally {
                ZStopWinws();
                prog["running"] = false; prog["finished"] = DateTime.Now.ToString("o"); write();
            }
        }
        static bool ZReceiveTest()
        {
            Dictionary<string, object> t;
            try { t = Json.DeserializeObject(File.ReadAllText(ZTestPath, Encoding.UTF8)) as Dictionary<string, object>; } catch { return false; }
            if (t == null) return false;
            if (JS(t, "running") == "True") {
                int pid; int.TryParse(JS(t, "pid"), out pid); bool alive = false;
                try { alive = pid > 0 && !Process.GetProcessById(pid).HasExited; } catch { }
                if (alive) return false;
                Log("zapret: процесс подбора завершился аварийно", "ERROR"); t["running"] = false; t["error"] = "процесс подбора завершился аварийно";
            }
            if (JS(t, "consumed") == "True") return false;
            t["consumed"] = true;
            try { File.WriteAllText(ZTestPath, Json.Serialize(t), Bom); } catch { }
            ZSetD("lastTest", DateTime.Now); Z["ggcAt"] = "";
            var results = (t.ContainsKey("results") && t["results"] is IEnumerable) ? ((IEnumerable)t["results"]).OfType<Dictionary<string, object>>().ToList() : new List<Dictionary<string, object>>();
            Z["results"] = results.Select(r => (object)new Dictionary<string, object> { { "name", JS(r, "name") }, { "ok", r.ContainsKey("ok") ? r["ok"] : 0 }, { "total", r.ContainsKey("total") ? r["total"] : 0 }, { "error", JS(r, "error") }, { "checks", r.ContainsKey("checks") && r["checks"] is IEnumerable ? ((IEnumerable)r["checks"]).OfType<object>().ToArray() : new object[0] } }).ToList();
            if (JS(t, "videoHost").Length > 0) { Z["videoHost"] = JS(t, "videoHost"); ZSetD("videoHostAt", DateTime.Now); Z["videoHostVia"] = JS(t, "videoHostVia"); }
            string best = JS(t, "best");
            if (JS(t, "error").Length > 0) { Z["lastError"] = "подбор: " + JS(t, "error"); Log("zapret: подбор не удался: " + JS(t, "error"), "ERROR"); }
            else if (best.Length > 0) {
                var row = results.FirstOrDefault(r => JS(r, "name") == best);
                Z["strategy"] = best; Z["lastScore"] = row != null ? JS(row, "ok") : "0"; Z["lastTotal"] = row != null ? JS(row, "total") : "0";
                ZSetD("fallbackUntil", DateTime.MinValue); Z["healthFails"] = 0; Z["lastError"] = "";
                Log("zapret: лучшая стратегия — '" + best + "' (" + Z["lastScore"] + "/" + Z["lastTotal"] + " сайтов)", "INFO");
            } else {
                Z["strategy"] = ""; Z["lastScore"] = 0; ZSetD("fallbackUntil", DateTime.Now.AddHours(2)); Z["lastError"] = "ни одна стратегия не открыла сайты";
                Log("zapret: ни одна стратегия не сработала — YouTube/Discord остаются в VPN, повторю через 2 ч", "WARN");
            }
            ZSave(); return true;
        }
    }
}
