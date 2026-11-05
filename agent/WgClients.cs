// Клиенты WG-Server: отключение и включение (ws4w.clientOff), клиенты, которых туннель не принимает.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace VpnGuard
{
    public static partial class Agent
    {
        // ---------------------------------------------------------------- отключение клиентов WG-Server (ws4w.clientOff — список IP)
        // Конфиг сервера не меняется (его ведёт и WS4W): отключённый клиент просто убирается из работающего туннеля
        // («wg set … peer … remove») и возвращается из конфига, когда его включат. После перезапуска туннеля агент снова уберёт его.
        class WcPeer { public string Key, Ip, Psk, Allowed; public int Keepalive; }
        static DateTime WcAt = DateTime.MinValue; static string WcErr = "", WcSig = ""; static readonly Dictionary<string, int> WcTries = new Dictionary<string, int>();
        static string WgExe() { return Path.Combine(Path.GetDirectoryName(CfgStr("ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe")), "wg.exe"); }
        static HashSet<string> WcOff() { return new HashSet<string>(CfgList("ws4w.clientOff", new string[0]).Select(x => x.Trim())); }
        static List<WcPeer> WgConfPeers()
        {
            var conf = WgConf(); if (conf == null || !conf.EndsWith(".conf")) return null;
            var res = new List<WcPeer>(); WcPeer cur = null;
            foreach (var l in File.ReadAllLines(conf)) {
                var h = Regex.Match(l, @"^\s*\[(\w+)\]");
                if (h.Success) { cur = h.Groups[1].Value.Equals("Peer", StringComparison.OrdinalIgnoreCase) ? new WcPeer() : null; if (cur != null) res.Add(cur); continue; }
                var m = Regex.Match(l, @"^\s*(\w+)\s*=\s*(.*?)\s*$"); if (cur == null || !m.Success) continue;
                string k = m.Groups[1].Value.ToLowerInvariant(), v = m.Groups[2].Value;
                if (k == "publickey") cur.Key = v; else if (k == "presharedkey") cur.Psk = v;
                else if (k == "allowedips") { cur.Allowed = Regex.Replace(v, @"\s+", ""); cur.Ip = Regex.Replace(cur.Allowed.Split(',')[0], @"/\d+$", ""); }
                else if (k == "persistentkeepalive") int.TryParse(v, out cur.Keepalive);
            }
            return res.Where(p => p.Key != null && p.Ip != null).ToList();
        }
        // клиенты, которых туннель не принимает: «ключ|AllowedIPs» → когда последний раз напоминали (data\wg-rejected.txt)
        static Dictionary<string, DateTime> WcRej;
        static Dictionary<string, DateTime> WcRejected()
        {
            if (WcRej != null) return WcRej;
            WcRej = new Dictionary<string, DateTime>();
            try {
                var f = Path.Combine(DataDir, "wg-rejected.txt");
                if (File.Exists(f)) foreach (var l in File.ReadAllLines(f)) { var x = l.Split('\t'); long t; if (x.Length == 2 && long.TryParse(x[1], out t)) WcRej[x[0]] = new DateTime(t); }
            } catch { }
            return WcRej;
        }
        static void WcRejSave()
        {
            try { File.WriteAllLines(Path.Combine(DataDir, "wg-rejected.txt"), WcRejected().Select(kv => kv.Key + "\t" + kv.Value.Ticks)); } catch { }
        }
        static void WgClientsWatch()
        {
            // wg.exe — раз в минуту или сразу, когда список отключённых изменился
            var offSig = string.Join(",", WcOff().OrderBy(x => x)); if (offSig == WcSig && (DateTime.UtcNow - WcAt).TotalSeconds < 60) return; WcAt = DateTime.UtcNow; WcSig = offSig;
            var svc = Svc(CfgStr("ws4w.serviceName", "WireGuardTunnel$wg_server")); if (svc == null || svc.Status != System.ServiceProcess.ServiceControllerStatus.Running) return;
            string wg = WgExe(); if (!File.Exists(wg)) return;
            List<WcPeer> conf; try { conf = WgConfPeers(); } catch { return; } if (conf == null) return;
            var off = WcOff();
            WgDumpReset(); var dump = WgDump(); if (dump == null) return;                       // свежий список (только что могли менять)
            var live = new HashSet<string>(dump.Skip(1).Select(x => x.Split('\t')[0].Trim()));
            string err = "";
            foreach (var p in conf) {
                string nm; if (!PeerNamesByKey.TryGetValue(p.Key, out nm)) nm = p.Ip;
                if (off.Contains(p.Ip) && live.Contains(p.Key)) {
                    var x = Exe(wg, "set " + WgIf() + " peer " + p.Key + " remove", 10);
                    if (x.Code == 0) Log("WG-Server: клиент «" + nm + "» (" + p.Ip + ") отключён", "WARN"); else err = "не удалось отключить " + p.Ip + ": " + x.Err.Trim();
                } else if (live.Contains(p.Key)) { WcTries.Remove(p.Key); if (WcRejected().Remove(p.Key + "|" + p.Allowed)) WcRejSave(); }
                else if (!off.Contains(p.Ip)) {
                    // включили обратно (или убрали вручную) — вернуть из конфига. Туннель может такого клиента не принимать
                    // (например, ключ совпадает с ключом сервера) — тогда после двух попыток больше не пытаться
                    int tries; WcTries.TryGetValue(p.Key, out tries);
                    string rsig = p.Key + "|" + p.Allowed; DateTime rw;
                    if (WcRejected().TryGetValue(rsig, out rw)) {           // уже знаем: туннель его не принимает (запомнено на диске)
                        if ((DateTime.Now - rw).TotalHours >= 24) { WcRej[rsig] = DateTime.Now; WcRejSave(); Log("WG-Server: клиент «" + nm + "» (" + p.Ip + ") по-прежнему не принимается туннелем — пересоздайте его на вкладке WG-Server (напоминание раз в сутки)", "WARN"); }
                        continue;
                    }
                    if (tries >= 2) {
                        WcRej[rsig] = DateTime.Now; WcRejSave();
                        Log("WG-Server: туннель не принимает клиента «" + nm + "» (" + p.Ip + ") из конфига: после добавления он снова пропадает. Больше не пытаюсь (запомнено; напомню раз в сутки) — пересоздайте клиента", "WARN");
                        continue;
                    }
                    WcTries[p.Key] = tries + 1;
                    string tmp = null;
                    try {
                        string a = "set " + WgIf() + " peer " + p.Key + " allowed-ips " + (p.Allowed ?? p.Ip + "/32");
                        if (!string.IsNullOrEmpty(p.Psk)) { tmp = Path.Combine(Path.GetTempPath(), "vg-psk-" + Guid.NewGuid().ToString("N") + ".txt"); File.WriteAllText(tmp, p.Psk); a += " preshared-key \"" + tmp + "\""; }
                        if (p.Keepalive > 0) a += " persistent-keepalive " + p.Keepalive;
                        var x = Exe(wg, a, 10);
                        if (x.Code == 0) Log("WG-Server: клиент «" + nm + "» (" + p.Ip + ") включён", "INFO"); else err = "не удалось включить " + p.Ip + ": " + x.Err.Trim();
                    } finally { if (tmp != null) try { File.Delete(tmp); } catch { } }
                }
            }
            WgDumpReset();
            if (err != WcErr) { if (err.Length > 0) Log("WG-Server: " + err, "ERROR"); WcErr = err; }
        }
        // отключённые клиенты (их нет в «wg show») — для списка в окне
        static IEnumerable<Dictionary<string, object>> WgOffPeers(HashSet<string> shownIps)
        {
            var off = WcOff(); if (off.Count == 0) yield break;
            List<WcPeer> conf = null; try { conf = WgConfPeers(); } catch { }
            if (conf == null) yield break;
            foreach (var p in conf) {
                if (!off.Contains(p.Ip) || shownIps.Contains(p.Ip)) continue;
                string nm; if (!PeerNamesByKey.TryGetValue(p.Key, out nm) && !PeerNamesByIp.TryGetValue(p.Ip, out nm)) nm = p.Ip;
                yield return new Dictionary<string, object> { { "name", nm }, { "key", p.Key.Substring(0, Math.Min(8, p.Key.Length)) }, { "ip", p.Ip }, { "endpoint", "" }, { "hsAgo", -1 }, { "active", false }, { "rx", 0 }, { "tx", 0 }, { "off", true }, { "zapret", CzClientZapret(p.Ip) } };
            }
        }
    }
}
