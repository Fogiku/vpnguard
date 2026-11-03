// VpnGuard — веб-сервер (веб-интерфейс + удалённая диагностика) на C#.
// Собирается агентом на месте встроенным компилятором .NET Framework (csc.exe, C# 5):
//   csc /target:exe /out:bin\VpnGuardWeb.exe /r:System.Web.Extensions.dll /r:System.Drawing.dll Web.cs Qr.cs
// Запуск: VpnGuardWeb.exe <папка VpnGuard> [config.json] [папка data]. Работает, пока включён веб-интерфейс (web.enabled) или удалённая диагностика;
// сам выходит, когда их выключили, сменили порт или обновили исходник (агент пересоберёт и запустит снова).
// Лёгкие запросы (состояние, журнал, команды агенту, настройки, вход) — здесь; тяжёлые и редкие (проверки сети, отчёт,
// клиенты WireGuard) — в PowerShell: «VpnGuard.ps1 -WebTask <имя>», только на время запроса.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace VpnGuard
{
    public static class Web
    {
        static string Root, DataDir, LogDir, CmdDir, ConfigPath, StatusPath, StatePath, VersionText = "";
        static readonly object CfgLock = new object(), StateLock = new object(), LogLock = new object();
        static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 200 };
        static Dictionary<string, object> Cfg = new Dictionary<string, object>();
        static DateTime CfgStamp = DateTime.MinValue;
        static int Requests; static string LastReq = "";
        static readonly Dictionary<string, Ban> Bans = new Dictionary<string, Ban>();
        static string PubIp = ""; static DateTime PubIpAt = DateTime.MinValue;
        static readonly UTF8Encoding Utf8 = new UTF8Encoding(false);

        class Ban { public int Count; public DateTime Until = DateTime.MinValue; }

        static readonly string[] WebCmds = { "check-now", "reconnect", "reconnect-meduza", "reconnect-awg", "restart-meduza", "restart-wg", "reapply-ics", "check-update",
            "zapret-on", "zapret-off", "zapret-test", "zapret-update", "zapret-reload", "zapret-check", "zapret-releases", "meduza-test", "meduza-catalog", "meduza-proto-reset",
            "software-check", "install-missing", "app-check", "app-update", "dual-switch" };
        // удалённая диагностика: true — прерывает интернет клиентам (нужно remote.allowActions)
        static readonly Dictionary<string, bool> RemoteCmds = new Dictionary<string, bool> {
            {"check-now",false},{"zapret-check",false},{"meduza-catalog",false},{"software-check",false},{"app-check",false},{"app-update",false},
            {"reconnect",true},{"reconnect-meduza",true},{"reconnect-awg",true},{"restart-wg",true},{"reapply-ics",true},{"zapret-test",true},{"zapret-reload",true},
            {"meduza-test",true},{"dual-switch",true},{"meduza-proto-reset",true},{"restart-meduza",true} };
        static readonly Dictionary<string, string> WebCfgKeys = new Dictionary<string, string> {
            {"vpn.mode", @"^(meduza|amnezia|dual|zapret)$"}, {"vpn.primary", @"^(meduza|amnezia)$"}, {"zapret.strategy", @"^[\w \(\)\-\.]{0,60}$"},
            {"meduza.serviceId", @"^[\w \-\.\(\)]{0,100}$"}, {"meduza.protocol", @"^[a-z0-9\-]{1,40}$"}, {"amnezia.active", @"^[a-z0-9_=+.\-]{1,32}$"},
            {"update.auto", "bool"}, {"ws4w.clientZapret", "bool"}, {"zapret.videoCheck", "bool"}, {"zapret.version", @"^[\w\.\-]{0,30}$"} };

        // все настройки для вкладки «Настройки» веб-интерфейса: ключ, раздел, название, тип, подсказка, значение по умолчанию.
        // тип: int:мин:макс | bool | enum:a|b|c | text:регулярка | hosts (хост:порт через запятую)
        static readonly string[][] Settings = {
            new[]{"checkIntervalSec","Общее","Интервал проверки, сек","int:10:600","как часто агент проверяет всё","30"},
            new[]{"logRetentionDays","Общее","Хранить журналы, дней","int:1:365","","14"},
            new[]{"agent.engine","Общее","Движок агента","enum:powershell|csharp","csharp — основной цикл на C# (быстрее, меньше памяти; zapret и обновления — по-прежнему PowerShell; «два туннеля» — только powershell). Упадёт трижды — сам вернётся на powershell","powershell"},
            new[]{"agent.psPartMin","Общее","Агент C#: обновления и компоненты, мин","int:5:240","как часто запускать часть PowerShell (по командам — сразу)","30"},
            new[]{"amnezia.adapterPattern","Режим","AmneziaVPN: адаптер туннеля (шаблон)","text:^[\\w \\-\\.\\|\\(\\)]{1,120}$","часть имени или описания адаптера; разные протоколы — разные адаптеры","amnezia|tun2socks|TAP-Windows Adapter V9"},
            new[]{"vpn.mode","Режим","Режим работы","enum:meduza|amnezia|dual|zapret","meduza · amnezia (AmneziaVPN) · dual (два туннеля) · zapret (без VPN)","meduza"},
            new[]{"vpn.primary","Режим","Два туннеля: основной","enum:meduza|amnezia","через какой идёт трафик, пока он работает","meduza"},
            new[]{"vpn.dualHot","Режим","Два туннеля: резерв всегда поднят","bool","выключено — резерв поднимается только при сбое","true"},
            new[]{"vpn.failoverChecks","Режим","Два туннеля: проверок до переключения","int:1:10","подряд без трафика (отключение — сразу)","2"},
            new[]{"vpn.failbackMin","Режим","Два туннеля: вернуться на основной через, мин","int:0:1440","0 — не возвращать","5"},
            new[]{"vpn.stopInactive","Режим","Закрывать неиспользуемый VPN","bool","чтобы не работали два туннеля сразу","true"},
            new[]{"meduza.serviceId","MeduzaVPN","VPN (id или часть имени)","text:^[\\w \\-\\.\\(\\)]{0,100}$","пусто — единственный на аккаунте",""},
            new[]{"meduza.protocol","MeduzaVPN","Протокол","text:^[a-z0-9\\-]{1,40}$","ultra","ultra"},
            new[]{"meduza.autoProtocol","MeduzaVPN","Пробовать другие протоколы","bool","если связь пропала и переподключение не помогло","true"},
            new[]{"meduza.protocolReturnMin","MeduzaVPN","Возвращать выбранный протокол, мин","int:0:1440","0 — не возвращать","60"},
            new[]{"meduza.adapterName","MeduzaVPN","Имя адаптера туннеля","text:^[\\w \\-\\.]{1,60}$","","MeduzaVPN ULTRA"},
            new[]{"meduza.autoUpdate","MeduzaVPN","Автообновление MeduzaVPN","bool","скачивание, проверка подписи, тихая установка","true"},
            new[]{"meduza.updateCheckHours","MeduzaVPN","Проверять обновления каждые, ч","int:1:168","","6"},
            new[]{"meduza.probeHosts","MeduzaVPN","Проверка трафика (хост:порт, …)","hosts","через запятую","1.1.1.1:443, 8.8.8.8:443, 9.9.9.9:443"},
            new[]{"meduza.probeFailuresBeforeReconnect","MeduzaVPN","Неудачных проверок до переподключения","int:1:50","","3"},
            new[]{"meduza.startupGraceSec","MeduzaVPN","Ждать автоподключения после старта, сек","int:0:600","","60"},
            new[]{"meduza.maxRestartsPer30Min","MeduzaVPN","Максимум перезапусков за 30 мин","int:1:100","защита от бесконечных перезапусков","5"},
            new[]{"ws4w.endpoint","WG-Server","Адрес для клиентов (IP или имя[:порт])","text:^[\\w\\.\\-:\\[\\]]{0,100}$","пусто — как у клиентов WS4W или внешний IP",""},
            new[]{"ws4w.clientDns","WG-Server","DNS для новых клиентов","text:^[\\d\\., a-fA-F:]{0,100}$","пусто — как у клиентов WS4W или адрес сервера",""},
            new[]{"ws4w.clientZapret","WG-Server","zapret и для клиентов","bool","трафик клиентов к адресам zapret (YouTube, Discord …) — через zapret этого ПК, остальное — через VPN; на устройствах ничего менять не нужно (только агент на C#)","false"},
            new[]{"ws4w.autoCreateServer","WG-Server","Создавать сервер, если настроек нет","bool","нет ни конфига, ни службы wg_server","true"},
            new[]{"sharing.enabled","Раздача","Управлять раздачей ICS","bool","туннель → WG-Server","true"},
            new[]{"zapret.autoUpdate","zapret","Автообновление zapret","bool","если версия не выбрана","true"},
            new[]{"zapret.updateCheckHours","zapret","Проверять обновления каждые, ч","int:1:168","","12"},
            new[]{"zapret.retestHours","zapret","Переподбирать стратегию каждые, ч","int:1:720","и сразу — если сайты перестали открываться","24"},
            new[]{"zapret.healthCheckMin","zapret","Проверять сайты каждые, мин","int:2:240","","10"},
            new[]{"zapret.videoCheck","zapret","Проверять видео YouTube","bool","видеосервер и скорость загрузки","true"},
            new[]{"zapret.routeIspVideo","zapret","Видеосерверы провайдера — мимо VPN","bool","иначе в режиме с VPN видео может не грузиться","true"},
            new[]{"zapret.gameFilter","zapret","Игровой фильтр","enum:disabled|all|tcp|udp","disabled — выключен (как в service.bat)","disabled"},
            new[]{"software.checkHours","Обновления","Проверять версии компонентов, ч","int:1:168","","12"},
            new[]{"update.auto","Обновления","Ставить обновления VpnGuard само","bool","проверка sha256 и кода, копия старых файлов","true"},
            new[]{"update.checkHours","Обновления","Проверять обновления VpnGuard каждые, ч","int:1:168","","3"},
        };
        static object SettingValue(string[] d)
        {
            object v = CfgGet(d[0], null);
            if (d[3] == "hosts") { var arr = v as System.Collections.ArrayList; if (arr != null) return string.Join(", ", arr.ToArray().Select(x => Convert.ToString(x))); if (v is object[]) return string.Join(", ", ((object[])v).Select(x => Convert.ToString(x))); return v == null ? d[5] : Convert.ToString(v); }
            if (d[3] == "bool") { if (v == null) return d[5] == "true"; if (v is bool) return v; bool b; return bool.TryParse(Convert.ToString(v), out b) && b; }
            if (d[3].StartsWith("int")) { int i; return int.TryParse(Convert.ToString(v ?? d[5]), out i) ? i : int.Parse(d[5]); }
            return v == null ? d[5] : Convert.ToString(v);
        }
        static string ValidateSetting(string[] d, object raw, out object val)
        {
            val = null; string t = d[3]; string sv = raw == null ? "" : Convert.ToString(raw).Trim();
            if (t == "bool") { bool b; if (raw is bool) val = raw; else if (bool.TryParse(sv, out b)) val = b; else return "нужно да/нет"; return null; }
            if (t.StartsWith("int:")) { var p = t.Split(':'); int i; if (!int.TryParse(sv, out i)) return "нужно число"; int mn = int.Parse(p[1]), mx = int.Parse(p[2]); if (i < mn || i > mx) return "от " + mn + " до " + mx; val = i; return null; }
            if (t.StartsWith("enum:")) { if (!t.Substring(5).Split('|').Contains(sv)) return "недопустимое значение"; val = sv; return null; }
            if (t.StartsWith("text:")) { if (!Regex.IsMatch(sv, t.Substring(5))) return "недопустимые символы"; val = sv; return null; }
            if (t == "hosts") {
                var list = sv.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries).ToArray();
                if (list.Length == 0) return "нужен хотя бы один хост:порт";
                foreach (var h in list) if (!Regex.IsMatch(h, @"^[\w\.\-]+:\d{1,5}$")) return "неверный формат: " + h + " (нужно хост:порт)";
                val = list; return null;
            }
            return "неизвестный тип";
        }

        // свои списки zapret: файл, тип записей, заглушка (zapret требует непустой файл)
        static readonly string[][] ZLists = {
            new[]{"list-general-user.txt","Свои домены — обрабатывать zapret и пускать мимо VPN","domain","domain.example.abc"},
            new[]{"list-exclude-user.txt","Исключения — домены, которые zapret не трогает","domain","domain.example.abc"},
            new[]{"ipset-exclude-user.txt","Исключения — IP-адреса и подсети","ip","203.0.113.113/32"} };
        static string ZListsDir() { string d = CfgStr("zapret.dir", ""); return Path.Combine(d.Length > 0 ? d : Path.Combine(Root, "zapret"), "lists"); }

        public static int Main(string[] args)
        {
            Root = args.Length > 0 ? args[0].TrimEnd('\\') : AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            if (File.Exists(Path.Combine(Root, "..", "VpnGuard.ps1")) && !File.Exists(Path.Combine(Root, "VpnGuard.ps1"))) Root = Path.GetFullPath(Path.Combine(Root, ".."));
            DataDir = args.Length > 2 ? args[2] : Path.Combine(Root, "data"); LogDir = Path.Combine(DataDir, "logs"); CmdDir = Path.Combine(DataDir, "cmd");
            ConfigPath = args.Length > 1 ? args[1] : Path.Combine(Root, "config.json");
            StatusPath = Path.Combine(DataDir, "status.json"); StatePath = Path.Combine(DataDir, "remote-state.json");
            Directory.CreateDirectory(LogDir); Directory.CreateDirectory(CmdDir);
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            try { var m = Regex.Match(File.ReadAllText(Path.Combine(Root, "VpnGuard.ps1")), @"\$AgentVersion\s*=\s*'([^']+)'"); if (m.Success) VersionText = m.Groups[1].Value; } catch { }
            LoadCfg(true);
            if (!Needed()) { SaveState(false, "веб-интерфейс и диагностика выключены"); return 0; }
            int port = WebPort();
            var l = new HttpListener();
            l.Prefixes.Add("http://+:" + port + "/");
            try { l.Start(); }
            catch (Exception e) { SaveState(false, "порт " + port + ": " + e.Message); Log("Веб-сервер VpnGuard (C#): не удалось открыть порт " + port + ": " + e.Message, "ERROR"); return 1; }
            SaveState(true, "");
            Log("Веб-сервер VpnGuard (C#): слушает TCP " + port + " (PID " + Process.GetCurrentProcess().Id + ") — http://localhost:" + port + "/", "INFO");
            string code = CodeStamp();
            l.BeginGetContext(OnContext, l);
            try {
                while (true) {
                    Thread.Sleep(2000);
                    LoadCfg(false);
                    if (!Needed() || WebPort() != port) break;
                    if (CodeStamp() != code) { Log("Веб-сервер VpnGuard (C#): код обновлён — перезапуск", "INFO"); break; }
                }
            } finally { try { l.Stop(); l.Close(); } catch { } SaveState(false, ""); }
            return 0;
        }

        static void OnContext(IAsyncResult ar)
        {
            var l = (HttpListener)ar.AsyncState;
            HttpListenerContext ctx = null;
            try { ctx = l.EndGetContext(ar); } catch { return; }
            try { l.BeginGetContext(OnContext, l); } catch { }
            try { Handle(ctx); }
            catch (Exception e) { try { Text(ctx, 500, "ошибка: " + e.Message); } catch { } }
        }

        // ---------------------------------------------------------------- настройки
        static void LoadCfg(bool force)
        {
            lock (CfgLock) {
                DateTime st = File.Exists(ConfigPath) ? File.GetLastWriteTimeUtc(ConfigPath) : DateTime.MinValue;
                if (!force && st == CfgStamp) return;
                CfgStamp = st;
                try { Cfg = st == DateTime.MinValue ? new Dictionary<string, object>() : (Json.DeserializeObject(File.ReadAllText(ConfigPath, Encoding.UTF8)) as Dictionary<string, object>) ?? new Dictionary<string, object>(); }
                catch { }
            }
        }
        static object CfgGet(string path, object def)
        {
            lock (CfgLock) {
                object cur = Cfg;
                foreach (var p in path.Split('.')) { var d = cur as Dictionary<string, object>; if (d == null || !d.ContainsKey(p)) return def; cur = d[p]; }
                return cur ?? def;
            }
        }
        static string CfgStr(string path, string def) { var v = CfgGet(path, def); return v == null ? def : Convert.ToString(v); }
        static bool CfgBool(string path, bool def) { var v = CfgGet(path, def); if (v is bool) return (bool)v; bool b; return bool.TryParse(Convert.ToString(v), out b) ? b : def; }
        static int CfgInt(string path, int def) { var v = CfgGet(path, def); int i; return int.TryParse(Convert.ToString(v), out i) ? i : def; }
        // записать значение в config.json (как Set-ConfigValue агента): атомарно, через временный файл
        static void CfgSet(string path, object value)
        {
            lock (CfgLock) {
                Dictionary<string, object> o = null;
                try { if (File.Exists(ConfigPath)) o = Json.DeserializeObject(File.ReadAllText(ConfigPath, Encoding.UTF8)) as Dictionary<string, object>; } catch { }
                if (o == null) o = new Dictionary<string, object>();
                var parts = path.Split('.'); var cur = o;
                for (int i = 0; i < parts.Length - 1; i++) {
                    object nx; if (!cur.TryGetValue(parts[i], out nx) || !(nx is Dictionary<string, object>)) { nx = new Dictionary<string, object>(); cur[parts[i]] = nx; }
                    cur = (Dictionary<string, object>)nx;
                }
                cur[parts[parts.Length - 1]] = value;
                string tmp = ConfigPath + ".tmp";
                File.WriteAllText(tmp, Pretty(Json.Serialize(o)), new UTF8Encoding(true));
                try { if (File.Exists(ConfigPath)) File.Replace(tmp, ConfigPath, null); else File.Move(tmp, ConfigPath); } catch { File.Copy(tmp, ConfigPath, true); File.Delete(tmp); }
                CfgStamp = DateTime.MinValue;
            }
            LoadCfg(true);
        }
        static bool WebOn() { return CfgBool("web.enabled", true); }
        static int WebPort() { return CfgInt("web.port", 8765); }
        static string WebPass() { return CfgStr("web.token", ""); }
        static bool RequirePass() { return CfgBool("web.requirePassword", true); }
        static DateTime RemoteUntil() { DateTime d; return DateTime.TryParse(CfgStr("remote.until", ""), null, System.Globalization.DateTimeStyles.RoundtripKind, out d) ? d.ToLocalTime() : DateTime.MinValue; }
        static bool RemoteOn() { return CfgBool("remote.enabled", false) && CfgStr("remote.token", "").Length >= 16 && RemoteUntil() > DateTime.Now; }
        static bool Needed() { return WebOn() || RemoteOn(); }
        static string CodeStamp()
        {
            var sb = new StringBuilder();
            foreach (var f in new[] { "Web.cs", "Qr.cs" }) { var p = Path.Combine(Root, f); if (File.Exists(p)) sb.Append(File.GetLastWriteTimeUtc(p).Ticks).Append('|'); }
            return sb.ToString();
        }

        // ---------------------------------------------------------------- журнал, состояние
        static void Log(string msg, string level)
        {
            lock (LogLock) {
                try { File.AppendAllText(Path.Combine(LogDir, "vpnguard-" + DateTime.Now.ToString("yyyyMMdd") + ".log"), DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " [" + level + "] " + msg + "\r\n", new UTF8Encoding(true)); } catch { }
            }
        }
        static void SaveState(bool running, string error)
        {
            lock (StateLock) {
                var o = new Dictionary<string, object> { { "pid", Process.GetCurrentProcess().Id }, { "running", running }, { "engine", "csharp" }, { "started", DateTime.Now.ToString("o") },
                    { "port", WebPort() }, { "requests", Requests }, { "last", LastReq }, { "error", error } };
                try { File.WriteAllText(StatePath, Json.Serialize(o), new UTF8Encoding(true)); } catch { }
            }
        }
        static void SendCmd(string c, string from)
        {
            File.WriteAllText(Path.Combine(CmdDir, DateTime.UtcNow.Ticks + ".cmd"), c, Encoding.ASCII);
            Log("Веб-интерфейс: команда агенту '" + c + "' (" + from + ")", "INFO");
        }

        // ---------------------------------------------------------------- безопасность
        public static string HideSecrets(string t)
        {
            if (string.IsNullOrEmpty(t)) return t;
            t = Regex.Replace(t, @"(?im)^(\s*(PrivateKey|PresharedKey)\s*=\s*)\S+", "$1***");
            t = Regex.Replace(t, @"vpn://[A-Za-z0-9_\-+/=]+", "vpn://***");
            t = Regex.Replace(t, "(\"token\"\\s*:\\s*\")[^\"]*(\")", "$1***$2");
            return t;
        }
        public static string CookieOf(string pass)
        {
            using (var sha = SHA256.Create()) return string.Concat(sha.ComputeHash(Encoding.UTF8.GetBytes("vpnguard|" + pass)).Select(b => b.ToString("x2")));
        }
        static bool PassOk(string tok)
        {
            string p = WebPass(); if (p.Length < 6 || string.IsNullOrEmpty(tok)) return false;
            return SafeEq(tok, p) || SafeEq(tok, CookieOf(p));
        }
        static bool SafeEq(string a, string b) { if (a == null || b == null || a.Length != b.Length) return false; int d = 0; for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i]; return d == 0; }
        public static bool IsPrivate(IPAddress a)
        {
            if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
            if (IPAddress.IsLoopback(a)) return true;
            if (a.AddressFamily != AddressFamily.InterNetwork) return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal;
            var b = a.GetAddressBytes();
            return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) || (b[0] == 169 && b[1] == 254);
        }
        static bool HostOk(HttpListenerRequest r)
        {
            string h = (r.Url.Host ?? "").ToLowerInvariant().Trim('[', ']');
            if (h == "localhost" || h == Environment.MachineName.ToLowerInvariant()) return true;
            IPAddress ip; return IPAddress.TryParse(h, out ip);
        }
        static bool Banned(string ip) { lock (Bans) { Ban b; return Bans.TryGetValue(ip, out b) && b.Until > DateTime.Now; } }
        static void Fail(string ip, string what)
        {
            lock (Bans) {
                Ban b; if (!Bans.TryGetValue(ip, out b) || (b.Until != DateTime.MinValue && b.Until <= DateTime.Now)) { b = new Ban(); Bans[ip] = b; }
                if (++b.Count >= 10) { b.Until = DateTime.Now.AddMinutes(15); Log(what + ": " + ip + " — 10 неверных попыток, блокирую на 15 мин", "WARN"); }
            }
        }

        // ---------------------------------------------------------------- ответы
        static void Bytes(HttpListenerContext c, int code, byte[] b, string type)
        {
            c.Response.StatusCode = code; c.Response.ContentType = type;
            c.Response.Headers["Cache-Control"] = "no-store"; c.Response.Headers["X-Content-Type-Options"] = "nosniff"; c.Response.Headers["X-Frame-Options"] = "DENY";
            try { c.Response.ContentLength64 = b.Length; c.Response.OutputStream.Write(b, 0, b.Length); } catch { }
            try { c.Response.Close(); } catch { }
        }
        static void Text(HttpListenerContext c, int code, string s) { Bytes(c, code, Utf8.GetBytes(s ?? ""), "text/plain; charset=utf-8"); }
        static void JsonOut(HttpListenerContext c, object o, int code = 200) { Bytes(c, code, Utf8.GetBytes(Json.Serialize(o)), "application/json; charset=utf-8"); }
        static void RawJson(HttpListenerContext c, string s) { Bytes(c, 200, Utf8.GetBytes(s ?? "{}"), "application/json; charset=utf-8"); }
        static Dictionary<string, object> Body(HttpListenerRequest r)
        {
            if (!r.HasEntityBody) return new Dictionary<string, object>();
            string t; using (var rd = new StreamReader(r.InputStream, Encoding.UTF8)) t = rd.ReadToEnd();
            if (t.Length > 65536) return new Dictionary<string, object>();
            try { return (Json.DeserializeObject(t) as Dictionary<string, object>) ?? new Dictionary<string, object>(); } catch { return new Dictionary<string, object>(); }
        }
        static string BStr(Dictionary<string, object> b, string k) { object v; return b.TryGetValue(k, out v) && v != null ? Convert.ToString(v) : ""; }
        static bool BBool(Dictionary<string, object> b, string k) { object v; if (!b.TryGetValue(k, out v) || v == null) return false; if (v is bool) return (bool)v; bool x; return bool.TryParse(Convert.ToString(v), out x) && x; }
        static string ReadShared(string path)
        {
            if (!File.Exists(path)) return null;
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var rd = new StreamReader(fs, Encoding.UTF8)) return rd.ReadToEnd();
        }

        // ---------------------------------------------------------------- журнал агента
        static string Logs(int days, int minutes, int maxLines)
        {
            var files = Directory.GetFiles(LogDir, "vpnguard-*.log").OrderBy(f => f).ToList();
            var lines = new List<string>();
            foreach (var f in files.Skip(Math.Max(0, files.Count - Math.Max(1, days)))) { try { lines.AddRange(ReadShared(f).Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)); } catch { } }
            if (minutes > 0) { string since = DateTime.Now.AddMinutes(-minutes).ToString("yyyy-MM-dd HH:mm:ss"); lines = lines.Where(s => s.Length >= 19 && string.CompareOrdinal(s.Substring(0, 19), since) >= 0).ToList(); }
            lines = lines.Where(s => s.Length > 0).ToList();
            if (lines.Count > maxLines) lines = lines.Skip(lines.Count - maxLines).ToList();
            return string.Join("\n", lines);
        }

        // ---------------------------------------------------------------- тяжёлые задачи — в PowerShell
        static string PsTask(string task, string arg, int timeoutSec)
        {
            var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -File \"" + Path.Combine(Root, "VpnGuard.ps1") + "\" -WebTask " + task +
                (string.IsNullOrEmpty(arg) ? "" : " -WebArg " + Convert.ToBase64String(Utf8.GetBytes(arg))) + (ConfigPath != Path.Combine(Root, "config.json") ? " -ConfigPath \"" + ConfigPath + "\"" : ""));
            psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true; psi.CreateNoWindow = true;
            psi.StandardOutputEncoding = Encoding.UTF8; psi.StandardErrorEncoding = Encoding.UTF8; psi.WorkingDirectory = Root;
            using (var p = Process.Start(psi)) {
                var o = p.StandardOutput.ReadToEndAsync(); var e = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(timeoutSec * 1000)) { try { p.Kill(); } catch { } return "таймаут " + timeoutSec + " с\n" + o.Result; }
                string s = o.Result; if (e.Result.Trim().Length > 0) s += "\n===== stderr =====\n" + e.Result;
                return s;
            }
        }
        static Dictionary<string, object> PsJson(string task, string arg)
        {
            string s = PsTask(task, arg, 120);
            int i = s.IndexOf("{\"", StringComparison.Ordinal);
            try { if (i >= 0) return (Json.DeserializeObject(s.Substring(i)) as Dictionary<string, object>) ?? Err("пустой ответ"); } catch { }
            return Err(s.Trim().Length > 0 ? s.Trim() : "нет ответа");
        }
        static Dictionary<string, object> Err(string m) { return new Dictionary<string, object> { { "ok", false }, { "error", m } }; }

        static byte[] QrPng(string text)
        {
            bool[,] m = Qr.Encode(text, 1, 0, -1);
            int n = m.GetLength(0), q = 4, px = 8;
            using (var bmp = new Bitmap((n + 2 * q) * px, (n + 2 * q) * px))
            using (var g = Graphics.FromImage(bmp)) {
                g.Clear(Color.White);
                for (int y = 0; y < n; y++) for (int x = 0; x < n; x++) if (m[y, x]) g.FillRectangle(Brushes.Black, (x + q) * px, (y + q) * px, px, px);
                using (var ms = new MemoryStream()) { bmp.Save(ms, ImageFormat.Png); return ms.ToArray(); }
            }
        }
        static string PublicIp()
        {
            if ((DateTime.Now - PubIpAt).TotalMinutes < 30) return PubIp;
            string ip = "";
            try { using (var wc = new WebClient()) ip = wc.DownloadString("https://api.ipify.org").Trim(); } catch { }
            PubIp = ip; PubIpAt = DateTime.Now; return ip;
        }
        static List<object> LocalIps()
        {
            var r = new List<object>();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()) {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.Name.StartsWith("MeduzaVPN", StringComparison.OrdinalIgnoreCase) || ni.Name.StartsWith("awg", StringComparison.OrdinalIgnoreCase)) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses) {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    string s = ua.Address.ToString(); if (s.StartsWith("127.") || s.StartsWith("169.254.")) continue;
                    r.Add(new Dictionary<string, object> { { "ip", s }, { "alias", ni.Name } });
                }
            }
            return r;
        }
        static string RemoteIndex()
        {
            var safe = RemoteCmds.Where(k => !k.Value).Select(k => k.Key); var act = RemoteCmds.Where(k => k.Value).Select(k => k.Key);
            return "VpnGuard " + VersionText + " — удалённая диагностика (включена до " + RemoteUntil().ToString("dd.MM.yyyy HH:mm") + ")\nТокен — заголовок X-Token или параметр ?t=…\n\n" +
                "GET /status              состояние агента (status.json)\nGET /check               живые проверки: туннели, внешний IP, DNS, сайты напрямую и через туннель, клиенты wg_server\n" +
                "GET /diag                полный отчёт «Диагностика» (до 3 мин)\nGET /net                 сеть: ipconfig, маршруты, метрики, DNS, брандмауэр\n" +
                "GET /system              Windows, процессы, службы, задачи, журналы событий\nGET /logs?days=2         журнал агента (можно minutes=30, lines=5000)\n" +
                "GET /files               config.json, state, zapret-state, результаты подбора, список data\nGET /bundle              всё сразу (кроме /diag; добавьте ?diag=1)\n" +
                "GET /cmd?c=…             команда агенту: " + string.Join(", ", safe) + "\n                         " +
                (CfgBool("remote.allowActions", false) ? "разрешены и прерывающие: " + string.Join(", ", act) : "прерывающие интернет (тесты протоколов/стратегий, переподключение) — выключены в окне") + "\n";
        }

        // ---------------------------------------------------------------- разбор запроса
        static void Handle(HttpListenerContext ctx)
        {
            var req = ctx.Request;
            string ip = req.RemoteEndPoint.Address.ToString();
            string path = req.Url.AbsolutePath.TrimEnd('/').ToLowerInvariant(); if (path == "") path = "/";
            var q = req.QueryString;
            LoadCfg(false);
            if (!HostOk(req)) { Text(ctx, 400, "неверный адрес"); return; }

            string tok = req.Headers["X-Token"]; if (string.IsNullOrEmpty(tok)) tok = q["t"];
            if (string.IsNullOrEmpty(tok) && req.Cookies["vg"] != null) tok = req.Cookies["vg"].Value;
            string role = "";
            bool noPass = !RequirePass() && IsPrivate(req.RemoteEndPoint.Address);
            if (WebOn() && (req.IsLocal || noPass || PassOk(tok))) role = "web";
            else if (RemoteOn() && !string.IsNullOrEmpty(tok) && SafeEq(tok, CfgStr("remote.token", ""))) role = "diag";

            if ((path == "/" || path == "/index.html") && WebOn() && !(role == "diag" && !string.IsNullOrEmpty(req.Headers["X-Token"]))) {
                string f = Path.Combine(Root, "web", "index.html");
                if (File.Exists(f)) Bytes(ctx, 200, File.ReadAllBytes(f), "text/html; charset=utf-8"); else Text(ctx, 404, "нет файла web\\index.html");
                return;
            }
            if (path == "/api/login" && req.HttpMethod == "POST") {
                if (Banned(ip)) { JsonOut(ctx, Err("слишком много попыток, подождите 15 минут"), 403); return; }
                var b = Body(req); string pw = WebPass();
                if (WebOn() && pw.Length >= 6 && SafeEq(BStr(b, "password"), pw)) {
                    lock (Bans) Bans.Remove(ip);
                    ctx.Response.Headers.Add("Set-Cookie", "vg=" + CookieOf(pw) + "; Path=/; Max-Age=2592000; HttpOnly; SameSite=Strict");
                    Log("Веб-интерфейс: вход с " + ip, "INFO");
                    JsonOut(ctx, new Dictionary<string, object> { { "ok", true } }); return;
                }
                Fail(ip, "Веб-интерфейс"); JsonOut(ctx, Err("неверный пароль"), 401); return;
            }
            if (path == "/api/whoami") { JsonOut(ctx, new Dictionary<string, object> { { "role", role }, { "local", req.IsLocal }, { "version", VersionText }, { "password", RequirePass() }, { "engine", "csharp" } }); return; }

            if (role == "") {
                if (Banned(ip)) { Text(ctx, 403, "слишком много неверных токенов, подождите 15 минут"); return; }
                if (!string.IsNullOrEmpty(tok)) Fail(ip, "Удалённый доступ");
                Text(ctx, 401, "нужен вход: пароль веб-интерфейса или токен диагностики (X-Token или ?t=)"); return;
            }
            var readOnly = new[] { "/api/status", "/api/logs", "/api/wg/clients", "/api/wg/conf", "/api/wg/qr", "/api/whoami", "/api/remote", "/api/websettings", "/api/settings", "/api/zlist" };
            bool write = path.StartsWith("/api/") && !readOnly.Contains(path);
            if (write && (req.HttpMethod != "POST" || string.IsNullOrEmpty(req.Headers["X-VG"]))) { Text(ctx, 405, "нужен POST с заголовком X-VG"); return; }
            bool post = req.HttpMethod == "POST";
            if (post && (path == "/api/remote" || path == "/api/websettings" || path == "/api/settings" || path == "/api/zlist") && string.IsNullOrEmpty(req.Headers["X-VG"])) { Text(ctx, 405, "нужен заголовок X-VG"); return; }

            Interlocked.Increment(ref Requests); LastReq = DateTime.Now.ToString("dd.MM HH:mm:ss") + " " + ip + " " + path; SaveState(true, "");
            if (role == "diag" && path != "/status") Log("Удалённая диагностика: " + ip + " запросил " + path + (q["c"] != null ? " (" + q["c"] + ")" : ""), "INFO");
            Func<string, int, int> qi = (n, d) => { int v; return int.TryParse(q[n], out v) ? v : d; };
            bool web = role == "web";

            switch (path) {
                case "/api/status": case "/status": { string s = ReadShared(StatusPath); RawJson(ctx, HideSecrets(s ?? "{}")); return; }
                case "/api/logs": Text(ctx, 200, HideSecrets(Logs(qi("days", 1), qi("minutes", 0), qi("lines", 3000)))); return;
                case "/logs": Text(ctx, 200, HideSecrets(Logs(qi("days", 2), qi("minutes", 0), qi("lines", 5000)))); return;
                case "/api/cmd": {
                    var b = Body(req); string c = BStr(b, "c");
                    if (role == "diag") {
                        if (!RemoteCmds.ContainsKey(c)) { JsonOut(ctx, Err("команда '" + c + "' недоступна"), 400); return; }
                        if (RemoteCmds[c] && !CfgBool("remote.allowActions", false)) { JsonOut(ctx, Err("прерывающие команды выключены в окне"), 403); return; }
                    } else if (!WebCmds.Contains(c) && !Regex.IsMatch(c, @"^install [a-z]+$")) { JsonOut(ctx, Err("неизвестная команда '" + c + "'"), 400); return; }
                    SendCmd(c, role + ", " + ip); JsonOut(ctx, new Dictionary<string, object> { { "ok", true } }); return;
                }
                case "/cmd": {
                    string c = q["c"] ?? "";
                    if (!RemoteCmds.ContainsKey(c)) { Text(ctx, 400, "неизвестная команда '" + c + "'. Можно: " + string.Join(", ", RemoteCmds.Keys)); return; }
                    if (RemoteCmds[c] && !CfgBool("remote.allowActions", false) && !web) { Text(ctx, 403, "команда '" + c + "' прерывает интернет клиентам — разрешите такие команды в окне (Диагностика → Удалённая диагностика)"); return; }
                    SendCmd(c, role + ", " + ip); Text(ctx, 200, "команда '" + c + "' отправлена агенту; результат — в /logs?minutes=10 и /status"); return;
                }
                case "/api/config": {
                    if (!web) { Text(ctx, 403, "только для веб-интерфейса"); return; }
                    var b = Body(req); string k = BStr(b, "key"); object v; b.TryGetValue("value", out v);
                    if (!WebCfgKeys.ContainsKey(k)) { JsonOut(ctx, Err("настройку '" + k + "' здесь менять нельзя"), 400); return; }
                    string rule = WebCfgKeys[k];
                    if (rule == "bool") v = BBool(b, "value");
                    else { string sv = v == null ? "" : Convert.ToString(v); if (!Regex.IsMatch(sv, rule)) { JsonOut(ctx, Err("недопустимое значение для " + k), 400); return; } v = sv; }
                    CfgSet(k, v); Log("Веб-интерфейс: " + k + " = '" + v + "' (" + ip + ")", "INFO"); SendCmd("check-now", "после изменения " + k);
                    JsonOut(ctx, new Dictionary<string, object> { { "ok", true } }); return;
                }
                case "/api/websettings": {
                    if (!web) { Text(ctx, 403, "только для веб-интерфейса"); return; }
                    if (post) {
                        var b = Body(req); string np = BStr(b, "password");
                        if (np.Length > 0) {
                            if (np.Length < 6 || np.Length > 64 || Regex.IsMatch(np, @"\s")) { JsonOut(ctx, Err("пароль: от 6 до 64 символов, без пробелов"), 400); return; }
                            CfgSet("web.token", np);
                            ctx.Response.Headers.Add("Set-Cookie", "vg=" + CookieOf(np) + "; Path=/; Max-Age=2592000; HttpOnly; SameSite=Strict");
                        }
                        if (b.ContainsKey("requirePassword") && b["requirePassword"] != null) {
                            bool rp = BBool(b, "requirePassword");
                            if (rp && WebPass().Length < 6) { JsonOut(ctx, Err("сначала задайте пароль"), 400); return; }
                            CfgSet("web.requirePassword", rp);
                        }
                        Log("Веб-интерфейс: изменены настройки входа (" + ip + "): пароль " + (RequirePass() ? "нужен" : "в домашней сети не нужен") + (np.Length > 0 ? ", задан новый пароль" : ""), "WARN");
                    }
                    JsonOut(ctx, new Dictionary<string, object> { { "ok", true }, { "requirePassword", RequirePass() }, { "password", req.IsLocal ? WebPass() : "" }, { "local", req.IsLocal }, { "port", WebPort() } });
                    return;
                }
                case "/api/remote": {
                    if (!web) { Text(ctx, 403, "только для веб-интерфейса"); return; }
                    if (post) {
                        var b = Body(req);
                        if (BBool(b, "enable")) {
                            int hours; int.TryParse(BStr(b, "hours"), out hours); hours = Math.Min(168, Math.Max(1, hours));
                            var tk = new byte[20]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(tk);
                            CfgSet("remote.token", string.Concat(tk.Select(x => x.ToString("x2"))));
                            CfgSet("remote.until", DateTime.Now.AddHours(hours).ToString("o"));
                            CfgSet("remote.allowFrom", BStr(b, "allowFrom") == "local" ? "local" : "any");
                            CfgSet("remote.allowActions", BBool(b, "allowActions"));
                            CfgSet("remote.enabled", true);
                            Log("Веб-интерфейс: удалённая диагностика включена на " + hours + " ч (" + ip + ")", "WARN");
                        } else { CfgSet("remote.enabled", false); Log("Веб-интерфейс: удалённая диагностика выключена (" + ip + ")", "INFO"); }
                        SendCmd("check-now", "изменение удалённой диагностики");
                    }
                    bool on = RemoteOn(); string from = CfgStr("remote.allowFrom", "any");
                    JsonOut(ctx, new Dictionary<string, object> { { "enabled", on }, { "until", on ? RemoteUntil().ToString("o") : "" }, { "token", on ? CfgStr("remote.token", "") : "" },
                        { "allowFrom", from }, { "allowActions", CfgBool("remote.allowActions", false) }, { "port", WebPort() }, { "ips", LocalIps() },
                        { "publicIp", on && from != "local" ? PublicIp() : "" }, { "requests", Requests } });
                    return;
                }
                case "/api/settings": {
                    if (!web) { Text(ctx, 403, "только для веб-интерфейса"); return; }
                    if (post) {
                        var b = Body(req); var errs = new Dictionary<string, object>(); int n = 0;
                        foreach (var d in Settings) {
                            if (!b.ContainsKey(d[0])) continue;
                            object v; string e = ValidateSetting(d, b[d[0]], out v);
                            if (e != null) { errs[d[0]] = d[2] + ": " + e; continue; }
                            if (Json.Serialize(v) == Json.Serialize(CfgGet(d[0], null))) continue;
                            CfgSet(d[0], v); n++;
                        }
                        if (errs.Count > 0) { JsonOut(ctx, new Dictionary<string, object> { { "ok", false }, { "error", string.Join("; ", errs.Values) }, { "fields", errs } }, 400); return; }
                        if (n > 0) { Log("Веб-интерфейс: изменено настроек: " + n + " (" + ip + ")", "INFO"); SendCmd("check-now", "после изменения настроек"); }
                        JsonOut(ctx, new Dictionary<string, object> { { "ok", true }, { "changed", n } }); return;
                    }
                    var list = Settings.Select(d => (object)new Dictionary<string, object> { { "key", d[0] }, { "section", d[1] }, { "label", d[2] }, { "type", d[3] }, { "hint", d[4] }, { "value", SettingValue(d) } }).ToList();
                    JsonOut(ctx, new Dictionary<string, object> { { "ok", true }, { "settings", list }, { "repo", CfgStr("update.repo", "Fogiku/vpnguard") } }); return;
                }
                case "/api/zlist": {
                    if (!web) { Text(ctx, 403, "только для веб-интерфейса"); return; }
                    string dir = ZListsDir();
                    if (post) {
                        var b = Body(req); var def = ZLists.FirstOrDefault(z => z[0] == BStr(b, "name"));
                        if (def == null) { JsonOut(ctx, Err("неизвестный список"), 400); return; }
                        if (!Directory.Exists(dir)) { JsonOut(ctx, Err("zapret ещё не установлен — включите его, он скачается, затем добавьте списки"), 400); return; }
                        var outl = new List<string>(); var bad = new List<string>();
                        foreach (var raw in BStr(b, "text").Split(new[] { "\r\n", "\n" }, StringSplitOptions.None)) {
                            string l = raw.Trim(); if (l.Length == 0) continue;
                            if (l.StartsWith("#")) { outl.Add(l); continue; }
                            if (def[2] == "domain") {
                                l = Regex.Replace(Regex.Replace(Regex.Replace(l.ToLowerInvariant(), "^[a-z]+://", ""), "[/:?#].*$", ""), @"^(\*\.|www\.)", "");
                                if (Regex.IsMatch(l, "[а-яё]")) { try { l = new System.Globalization.IdnMapping().GetAscii(l); } catch { } }
                                if (Regex.IsMatch(l, @"^([a-z0-9-]+\.)+[a-z0-9-]{2,}$")) outl.Add(l); else bad.Add(raw.Trim());
                            } else {
                                if (Regex.IsMatch(l, @"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$") || Regex.IsMatch(l, @"^[0-9a-f:]+(/\d{1,3})?$")) outl.Add(l); else bad.Add(l);
                            }
                        }
                        if (bad.Count > 0) { JsonOut(ctx, Err("не понял строки: " + string.Join(", ", bad.Take(10)) + (def[2] == "domain" ? " — нужно: домен, например rutracker.org" : " — нужно: IP или подсеть, например 1.2.3.0/24")), 400); return; }
                        var fin = outl.Distinct().ToList();
                        if (!fin.Any(x => !x.StartsWith("#"))) { fin.Insert(0, "# Never leave this file empty"); fin.Add(def[3]); }
                        File.WriteAllText(Path.Combine(dir, def[0]), string.Join("\r\n", fin) + "\r\n", new UTF8Encoding(false));
                        Log("Веб-интерфейс: сохранён список zapret " + def[0] + " (" + fin.Count(x => !x.StartsWith("#") && x != def[3]) + " записей, " + ip + ")", "INFO");
                        SendCmd("zapret-reload", "применение списка " + def[0]);
                        JsonOut(ctx, new Dictionary<string, object> { { "ok", true } }); return;
                    }
                    var lists = ZLists.Select(z => {
                        string f = Path.Combine(dir, z[0]); string txt = "";
                        if (File.Exists(f)) txt = string.Join("\n", (ReadShared(f) ?? "").Split(new[] { "\r\n", "\n" }, StringSplitOptions.None).Where(l => l.Trim() != z[3] && !Regex.IsMatch(l, @"^#\s*Never leave this file empty")).ToArray()).Trim();
                        return (object)new Dictionary<string, object> { { "name", z[0] }, { "title", z[1] }, { "kind", z[2] }, { "exists", File.Exists(f) }, { "text", txt } };
                    }).ToList();
                    JsonOut(ctx, new Dictionary<string, object> { { "ok", true }, { "dir", dir }, { "installed", Directory.Exists(dir) }, { "lists", lists } }); return;
                }
                case "/api/diag-run": if (!web) { Text(ctx, 403, "только для веб-интерфейса"); return; } Text(ctx, 200, HideSecrets(PsTask("diag", "", 240))); return;
                case "/api/wg/clients": if (!web) { Text(ctx, 403, "только для веб-интерфейса"); return; } JsonOut(ctx, PsJson("wg-clients", "")); return;
                case "/api/wg/conf": if (!web) { Text(ctx, 403, "только для веб-интерфейса"); return; } { var r = PsJson("wg-conf", q["ip"] ?? ""); JsonOut(ctx, r, r.ContainsKey("ok") && r["ok"] is bool && (bool)r["ok"] ? 200 : 404); } return;
                case "/api/wg/qr": {
                    if (!web) { Text(ctx, 403, "только для веб-интерфейса"); return; }
                    var r = PsJson("wg-conf", q["ip"] ?? "");
                    if (!(r.ContainsKey("ok") && r["ok"] is bool && (bool)r["ok"])) { Text(ctx, 404, "нет конфига"); return; }
                    Bytes(ctx, 200, QrPng(Convert.ToString(r["text"])), "image/png"); return;
                }
                case "/api/wg/add": {
                    if (!web) { Text(ctx, 403, "только для веб-интерфейса"); return; }
                    string n = BStr(Body(req), "name").Trim();
                    if (!Regex.IsMatch(n, @"^[\w\- \.а-яА-ЯёЁ]{1,40}$")) { JsonOut(ctx, Err("имя: буквы, цифры, пробел, - _ . (до 40)"), 400); return; }
                    var r = PsJson("wg-add", n); if (r.ContainsKey("ok") && r["ok"] is bool && (bool)r["ok"]) Log("Веб-интерфейс: создан клиент WireGuard «" + r["name"] + "» " + r["ip"] + " (" + ip + ")", "INFO");
                    JsonOut(ctx, r); return;
                }
                case "/api/wg/remove": {
                    if (!web) { Text(ctx, 403, "только для веб-интерфейса"); return; }
                    var r = PsJson("wg-remove", BStr(Body(req), "ip")); if (r.ContainsKey("ok") && r["ok"] is bool && (bool)r["ok"]) Log("Веб-интерфейс: удалён клиент WireGuard «" + r["name"] + "» (" + ip + ")", "INFO");
                    JsonOut(ctx, r); return;
                }
                case "/": Text(ctx, 200, RemoteIndex()); return;
                case "/check": Text(ctx, 200, HideSecrets(PsTask("check", "", 180))); return;
                case "/diag": Text(ctx, 200, HideSecrets(PsTask("diag", "", 240))); return;
                case "/net": Text(ctx, 200, HideSecrets(PsTask("net", "", 120))); return;
                case "/system": Text(ctx, 200, HideSecrets(PsTask("system", "", 120))); return;
                case "/files": RawJson(ctx, HideSecrets(PsTask("files", "", 120))); return;
                case "/bundle": Text(ctx, 200, HideSecrets(PsTask(q["diag"] == "1" ? "bundle-diag" : "bundle", "", 420))); return;
                default: Text(ctx, 404, "нет такого адреса. Список: /"); return;
            }
        }

        // JSON с отступами — чтобы config.json оставался читаемым
        static string Pretty(string j)
        {
            var sb = new StringBuilder(); int ind = 0; bool str = false;
            for (int i = 0; i < j.Length; i++) {
                char c = j[i];
                if (str) { sb.Append(c); if (c == '\\') { sb.Append(j[++i]); } else if (c == '"') str = false; continue; }
                switch (c) {
                    case '"': str = true; sb.Append(c); break;
                    case '{': case '[': if (i + 1 < j.Length && (j[i + 1] == '}' || j[i + 1] == ']')) { sb.Append(c).Append(j[++i]); break; } sb.Append(c); ind++; sb.Append("\r\n").Append(' ', ind * 4); break;
                    case '}': case ']': ind--; sb.Append("\r\n").Append(' ', ind * 4).Append(c); break;
                    case ',': sb.Append(c).Append("\r\n").Append(' ', ind * 4); break;
                    case ':': sb.Append(": "); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }
    }
}
