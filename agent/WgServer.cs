// WG-Server (wg_server): служба туннеля, адрес, клиенты.
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
        // ---------------------------------------------------------------- wg_server
        static string WgConf()
        {
            var p = CfgStr("ws4w.configPath", ""); if (p.Length > 0 && File.Exists(p)) return p;
            try {     // сервер, созданный самим VpnGuard (запомнен в state.json)
                var st = Json.DeserializeObject(File.ReadAllText(Path.Combine(DataDir, "state.json"), Encoding.UTF8)) as Dictionary<string, object>;
                object w; if (st != null && st.TryGetValue("wgConfPath", out w) && w != null && Convert.ToString(w).Length > 0 && File.Exists(Convert.ToString(w))) return Convert.ToString(w);
            } catch { }
            try {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + CfgStr("ws4w.serviceName", "WireGuardTunnel$wg_server"))) {
                    var img = k == null ? null : Convert.ToString(k.GetValue("ImagePath"));
                    var mt = Regex.Match(img ?? "", "/tunnelservice\\s+\"?([^\"]+?\\.conf(\\.dpapi)?)\"?\\s*$");
                    if (mt.Success && File.Exists(mt.Groups[1].Value)) return mt.Groups[1].Value;
                }
            } catch { }
            string n = WgIf(), pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            foreach (var c in new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WS4W", "server_wg", n + ".conf"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WS4W", n + ".conf"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WS4W", n + ".conf"),
                Path.Combine(DataDir, "wg", n + ".conf"), Path.Combine(pf, "WireGuard", "Data", "Configurations", n + ".conf.dpapi"), Path.Combine(pf, "WireGuard", "Data", "Configurations", n + ".conf") })
                if (File.Exists(c)) return c;
            return null;
        }
        static string WgServerAddress()
        {
            var a = CfgStr("ws4w.serverAddress", ""); if (a.Length > 0) return a;
            var c = WgConf();
            if (c != null && c.EndsWith(".conf")) { try { var m = Regex.Match(File.ReadAllText(c), @"(?m)^\s*Address\s*=\s*([\d\.]+)"); if (m.Success) return m.Groups[1].Value; } catch { } }
            var ip = Ipv4(WgIf()); return ip != null && !ip.StartsWith("192.168.137.") ? ip : null;
        }
        static void WgWatch()
        {
            string sn = CfgStr("ws4w.serviceName", "WireGuardTunnel$wg_server"), wgExe = CfgStr("ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe");
            var svc = Svc(sn); var conf = WgConf();
            if (svc == null) {
                if (conf != null && File.Exists(wgExe)) {
                    Log("wg_server: служба туннеля отсутствует — устанавливаю из " + conf, "WARN");
                    var r = Exe(wgExe, "/installtunnelservice \"" + conf + "\"", 60); Log("wg_server: installtunnelservice код " + r.Code + " " + r.Err, "INFO"); Thread.Sleep(5000);
                } else if (CfgBool("ws4w.autoCreateServer", true)) {
                    if (++WgMissingTicks < 3) Log("wg_server: нет ни службы, ни конфига (" + WgMissingTicks + "/3) — если так останется, создам сервер сам", "WARN");
                    else { WgMissingTicks = 0; QueuePs("wg-create"); }
                } else Log("wg_server: служба '" + sn + "' не найдена и конфиг не найден — настройте туннель в WS4W", "ERROR");
                return;
            }
            if (StartMode(sn) != "Auto") { SetAutoStart(sn); Log("wg_server: тип запуска службы -> Автоматически", "INFO"); }
            if (svc.Status != ServiceControllerStatus.Running) {
                Log("wg_server: служба в состоянии " + svc.Status + " — запускаю", "WARN");
                try { if (svc.Status != ServiceControllerStatus.Stopped) { svc.Stop(); svc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)); } svc.Start(); svc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30)); Log("wg_server: служба запущена", "INFO"); }
                catch (Exception e) { Log("wg_server: не удалось запустить: " + e.Message, "ERROR"); }
                return;
            }
            if (!Up(WgIf())) { Log("wg_server: служба работает, но адаптер не поднят — перезапуск службы", "WARN"); SvcRestart(sn); }
        }
        static Dictionary<string, string> PeerNamesByKey = new Dictionary<string, string>(), PeerNamesByIp = new Dictionary<string, string>(); static string PeerStamp = "";
        static void LoadPeerNames()
        {
            var conf = WgConf(); if (conf == null || !conf.EndsWith(".conf")) return;
            var dir = Path.GetDirectoryName(Path.GetDirectoryName(conf));
            List<string> files = new List<string>(); try { files = Directory.GetFiles(dir, "*.conf", SearchOption.AllDirectories).Where(f => f != conf).Take(200).ToList(); } catch { }
            var stamp = string.Join("|", new[] { conf }.Concat(files).Select(f => File.GetLastWriteTimeUtc(f).Ticks));
            if (stamp == PeerStamp) return;
            var byKey = new Dictionary<string, string>(); var byIp = new Dictionary<string, string>();
            // имя клиента: «# Name = …» внутри блока [Peer] (так пишет VpnGuard) → комментарий над [Peer] (так пишет WS4W: «# 1», «[Peer]»)
            // → первый свой комментарий в блоке (не «VpnGuard: …») → имя файла клиента с тем же адресом (byIp).
            // Комментарии после последнего ключа блока относятся к следующему блоку.
            bool inPeer = false; string key = null, nmName = null, nmFirst = null, above = null; var pending = new List<string>();
            Func<string, string> nameOf = c => { var mm = Regex.Match(c, @"^(?:Name|Client|Имя)\s*[=:]\s*(.{1,60})$"); return mm.Success ? mm.Groups[1].Value.Trim() : null; };
            Func<string, bool> plain = c => c.Length > 0 && c.Length <= 60 && !c.StartsWith("VpnGuard", StringComparison.OrdinalIgnoreCase);
            Action absorb = () => { foreach (var c in pending) { var n = nameOf(c); if (n != null) { if (nmName == null) nmName = n; } else if (plain(c) && nmFirst == null) nmFirst = c; } pending.Clear(); };
            Action flush = () => { var n = nmName ?? above ?? nmFirst; if (inPeer && key != null && n != null) byKey[key] = n; };
            foreach (var l in File.ReadAllLines(conf, Encoding.UTF8)) {
                var h = Regex.Match(l, @"^\s*\[(\w+)\]");
                if (h.Success) {
                    string up = null; foreach (var c in pending) { var n = nameOf(c) ?? (plain(c) ? c : null); if (n != null) up = n; }
                    pending.Clear(); flush();
                    inPeer = h.Groups[1].Value.Equals("Peer", StringComparison.OrdinalIgnoreCase); key = null; nmName = null; nmFirst = null; above = inPeer ? up : null;
                    continue;
                }
                var m = Regex.Match(l, @"^\s*[#;]\s*(.*?)\s*$"); if (m.Success) { pending.Add(m.Groups[1].Value); continue; }
                if (l.Trim().Length == 0) continue;
                absorb();
                var k = Regex.Match(l, @"^\s*PublicKey\s*=\s*(\S+)"); if (inPeer && k.Success) key = k.Groups[1].Value;
            }
            absorb(); flush();
            foreach (var f in files) { try { var a = Regex.Match(File.ReadAllText(f), @"(?m)^\s*Address\s*=\s*([\d\.]+)"); if (a.Success) byIp[a.Groups[1].Value] = Path.GetFileNameWithoutExtension(f); } catch { } }
            PeerNamesByKey = byKey; PeerNamesByIp = byIp; PeerStamp = stamp;
        }
        static List<object> WgPeers(out int active, out string port)
        {
            active = 0; port = ""; var list = new List<object>();
            var wg = Path.Combine(Path.GetDirectoryName(CfgStr("ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe")), "wg.exe");
            if (!File.Exists(wg)) return null;
            var r = Exe(wg, "show " + WgIf() + " dump", 5); if (r.Code != 0) return null;
            var lines = r.Out.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries); if (lines.Length == 0) return null;
            var h = lines[0].Split('\t'); if (h.Length > 2) port = h[2];
            try { LoadPeerNames(); } catch { }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            foreach (var l in lines.Skip(1)) {
                var p = l.Split('\t'); if (p.Length < 7) continue;
                string ip = Regex.Replace(p[3].Split(',')[0], @"/\d+$", ""); long hs; long.TryParse(p[4], out hs); long rx, tx; long.TryParse(p[5], out rx); long.TryParse(p[6], out tx);
                string name; if (!PeerNamesByKey.TryGetValue(p[0], out name) && !PeerNamesByIp.TryGetValue(ip, out name)) name = ip;
                bool act = hs > 0 && now - hs < 180; if (act) active++;
                var rr = RateOf("wg:" + p[0], rx, tx);
                list.Add(new Dictionary<string, object> { { "name", name }, { "key", p[0].Substring(0, Math.Min(8, p[0].Length)) }, { "ip", ip }, { "endpoint", p[2] == "(none)" ? "" : p[2] }, { "hsAgo", hs > 0 ? now - hs : -1 }, { "active", act }, { "rx", rx }, { "tx", tx },
                    { "rxRate", rr[0] }, { "txRate", rr[1] },
                    { "off", false }, { "zapret", CzClientZapret(ip) }, { "cz", CzClientStat(ip) } });
            }
            try { list.AddRange(WgOffPeers(new HashSet<string>(list.Select(x => (string)((Dictionary<string, object>)x)["ip"])))); } catch { }
            return list;
        }
    }
}
