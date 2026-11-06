// zapret: маршруты мимо VPN (диапазоны Google, видеосерверы провайдера, домены Discord).
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
        // ---------------------------------------------------------------- маршруты мимо VPN
        static List<string> GoogleRanges()
        {
            bool fresh = File.Exists(ZGooglePath) && (DateTime.Now - File.GetLastWriteTime(ZGooglePath)).TotalHours < 24;
            if (!fresh) {
                try {
                    var j = (Dictionary<string, object>)Json.DeserializeObject(HttpGet("https://www.gstatic.com/ipranges/goog.json", 20));
                    var l = ((IEnumerable)j["prefixes"]).OfType<Dictionary<string, object>>().Select(p => JS(p, "ipv4Prefix")).Where(p => p.Length > 0).ToArray();
                    File.WriteAllText(ZGooglePath, Json.Serialize(l), Bom);
                } catch (Exception e) { Log("zapret: не удалось обновить диапазоны Google: " + e.Message, "WARN"); }
            }
            try {
                var o = Json.DeserializeObject(File.ReadAllText(ZGooglePath, Encoding.UTF8));
                IEnumerable arr = o is Dictionary<string, object> && ((Dictionary<string, object>)o).ContainsKey("value") ? (IEnumerable)((Dictionary<string, object>)o)["value"] : o as IEnumerable;
                return arr.OfType<object>().Select(x => Convert.ToString(x)).Where(x => Regex.IsMatch(x, @"^\d+\.\d+\.\d+\.\d+/\d+$")).ToList();
            } catch { return new List<string>(); }
        }
        static List<string> RouteDomains()
        {
            var d = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var x in CfgList("zapret.routeDomains", ZDefDomains)) if (x.Trim().Length > 0) d.Add(x.Trim().TrimStart('^'));
            var lists = Path.Combine(ZDir(), "lists");
            foreach (var f in CfgList("zapret.routeDomainLists", new[] { "list-google.txt" }).Concat(new[] { "list-general-user.txt" }).Distinct()) {
                var p = Path.Combine(lists, f); if (!File.Exists(p)) continue;
                foreach (var raw in File.ReadAllLines(p)) { var l = raw.Trim().TrimStart('^'); if (l.Length > 0 && !l.StartsWith("#") && l != "domain.example.abc") d.Add(l); }
            }
            return d.ToList();
        }
        // разрешить много имён параллельно (системный DNS), не дольше timeoutMs в сумме
        static Dictionary<string, IPAddress[]> ResolveMany(IEnumerable<string> names, int timeoutMs)
        {
            var list = names.Distinct().ToList(); var tasks = new Dictionary<string, Task<IPAddress[]>>();
            foreach (var n in list) { try { tasks[n] = Dns.GetHostAddressesAsync(n); } catch { } }
            try { Task.WaitAll(tasks.Values.ToArray(), timeoutMs); } catch { }
            var res = new Dictionary<string, IPAddress[]>();
            foreach (var kv in tasks) if (kv.Value.Status == TaskStatus.RanToCompletion) res[kv.Key] = kv.Value.Result.Where(a => a.AddressFamily == AddressFamily.InterNetwork).ToArray();
            return res;
        }
        // кэш-серверы YouTube у провайдера: страница ролика напрямую → кластеры sn-… → адреса rr1..20 → подсети /24 мимо VPN
        static void UpdateIspVideo(bool force)
        {
            if (!force && (DateTime.Now - ZD("ggcAt")).TotalMinutes < 30) return;
            var path = ZPhys(); if (path == null) return;
            Z["ggcAt"] = DateTime.Now.ToString("o");
            var r = Exe(Curl, "-s -L --compressed --connect-timeout 4 -m 15 --interface " + path.Ip + " -A \"" + UaChrome + "\" \"https://www.youtube.com/watch?v=jNQXAC9IVRw\"", 20);
            var cls = Regex.Matches(r.Out, @"rr\d{1,2}---(sn-[a-z0-9-]{4,})\.googlevideo\.com").Cast<Match>().Select(m => m.Groups[1].Value).Distinct().ToList();
            if (cls.Count == 0) return;
            Z["videoHost"] = "rr1---" + cls[0] + ".googlevideo.com"; ZSetD("videoHostAt", DateTime.Now); Z["videoHostVia"] = "direct";
            var names = new List<string>(); foreach (var cl in cls.Take(3)) for (int n = 1; n <= 20; n++) names.Add("rr" + n + "---" + cl + ".googlevideo.com");
            var set = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var kv in ResolveMany(names, 10000)) foreach (var a in kv.Value) { var o = a.GetAddressBytes(); set.Add(o[0] + "." + o[1] + "." + o[2] + ".0/24"); }
            var list = set.ToList();
            if (list.Count > 0 && string.Join(",", list) != string.Join(",", ZArr("ggc").Select(x => Convert.ToString(x)))) {
                Log("zapret: видеосерверы YouTube у провайдера (" + string.Join(", ", cls) + "): " + string.Join(", ", list) + " — пускаю мимо VPN", "WARN");
                Z["ggc"] = list; ZSetD("lastRouteRefresh", DateTime.MinValue);
            }
        }
        static List<string> ZPrefixes()
        {
            var set = new HashSet<string>(); var order = new List<string>();
            Action<string> add = p => { if (set.Add(p)) order.Add(p); };
            if (ZB("routeGoogleRanges")) { foreach (var p in GoogleRanges()) add(p); if (ZB("routeIspVideo")) foreach (var p in ZArr("ggc")) add(Convert.ToString(p)); }
            var seen = Z.ContainsKey("prefixSeen") ? Z["prefixSeen"] as Dictionary<string, object> : null; if (seen == null) seen = new Dictionary<string, object>();
            long nowT = DateTime.UtcNow.Ticks, keepT = TimeSpan.FromDays(7).Ticks;
            foreach (var kv in ResolveMany(RouteDomains(), 10000)) foreach (var a in kv.Value) { add(a + "/32"); seen[a + "/32"] = nowT; }
            foreach (var r in ZRoutes()) { var p = JS(r, "p"); if (p.EndsWith("/32")) add(p); }   // старые /32 оставляем (IP у CDN меняются)
            foreach (var k in seen.Keys.ToList()) { long t; if (!long.TryParse(Convert.ToString(seen[k]), out t) || nowT - t > keepT) seen.Remove(k); else add(k); }   // и найденные за неделю
            Z["prefixSeen"] = seen;
            var list = order.Where(p => !Regex.IsMatch(p, @"^(8\.8\.8\.|8\.8\.4\.)")).ToList();    // публичный DNS остаётся в VPN
            int max = ZI("maxRoutes"); if (max > 0 && list.Count > max) list = list.Take(max).ToList();
            return list;
        }
        static void ZRemoveRoutes()
        {
            int n = 0;
            var table = RouteTable();
            foreach (var r in ZRoutes()) {
                string p = JS(r, "p"), g = JS(r, "g"); int i; int.TryParse(JS(r, "i"), out i);
                foreach (var row in table) if (row.IfIndex == i && UIp(row.NextHop) == g && Prefix(row) == p) { var x = row; DeleteIpForwardEntry(ref x); }
                n++;
            }
            if (n > 0) Log("zapret: убрано " + n + " маршрутов — YouTube/Discord снова через VPN", "INFO");
            Z["routes"] = new object[0]; ZSave();
        }
        static void ZSyncRoutes(bool refresh)
        {
            if (ZDirect()) { if (ZRoutes().Count > 0) ZRemoveRoutes(); return; }      // без VPN всё и так напрямую
            var path = ZPhys(); if (path == null) { Log("zapret: нет физического выхода в интернет — маршруты не ставлю", "WARN"); return; }
            var routes = ZRoutes();
            if (routes.Count > 0 && routes.Any(r => JS(r, "i") != path.IfIndex.ToString() || JS(r, "g") != path.Gateway)) {
                Log("zapret: сменился выход в интернет (" + path.Alias + " через " + path.Gateway + ") — переставляю маршруты", "INFO");
                ZRemoveRoutes(); routes = new List<Dictionary<string, object>>(); refresh = true;
            }
            bool need = refresh || routes.Count == 0 || (DateTime.Now - ZD("lastRouteRefresh")).TotalMinutes >= 30;
            if (need && routes.Count > 0 && InetBad()) need = false;                 // связь плохая — DNS ответит не на всё; обновлю позже
            var want = need ? ZPrefixes() : routes.Select(r => JS(r, "p")).ToList();
            if (need) ZSetD("lastRouteRefresh", DateTime.Now);
            var table = RouteTable();
            var have = new HashSet<string>(table.Where(r => r.IfIndex == path.IfIndex).Select(Prefix));
            int added = 0, failed = 0, ifm = -1;
            foreach (var p in want) {
                if (have.Contains(p)) continue;
                if (ifm < 0) ifm = Math.Max(0, IfMetric(path.IfIndex));
                if (RouteAdd(p, path.IfIndex, path.Gateway, ifm)) added++; else failed++;
            }
            var ws = new HashSet<string>(want);
            foreach (var r in routes) { if (!ws.Contains(JS(r, "p"))) { int i; int.TryParse(JS(r, "i"), out i); RouteDel(JS(r, "p"), i, JS(r, "g")); } }
            Z["routes"] = want.Select(p => (object)new Dictionary<string, object> { { "p", p }, { "i", path.IfIndex }, { "g", path.Gateway } }).ToList();
            if (added > 0) Log("zapret: добавлено " + added + " маршрутов мимо VPN через " + path.Alias + " (всего " + want.Count + ")", "INFO");
            if (failed > 0) Log("zapret: не удалось добавить " + failed + " маршрутов", "WARN");
            ZSave();
        }
    }
}
