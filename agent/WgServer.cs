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
            var p = CfgStr("wg.configPath", ""); if (p.Length > 0 && File.Exists(p)) return p;
            try {     // сервер, созданный самим VpnGuard (запомнен в state.json)
                var st = Json.DeserializeObject(File.ReadAllText(Path.Combine(DataDir, "state.json"), Encoding.UTF8)) as Dictionary<string, object>;
                object w; if (st != null && st.TryGetValue("wgConfPath", out w) && w != null && Convert.ToString(w).Length > 0 && File.Exists(Convert.ToString(w))) return Convert.ToString(w);
            } catch { }
            try {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + CfgStr("wg.serviceName", "WireGuardTunnel$wg_server"))) {
                    var img = k == null ? null : Convert.ToString(k.GetValue("ImagePath"));
                    var mt = Regex.Match(img ?? "", "/tunnelservice\\s+\"?([^\"]+?\\.conf(\\.dpapi)?)\"?\\s*$");
                    if (mt.Success && File.Exists(mt.Groups[1].Value)) return mt.Groups[1].Value;
                }
            } catch { }
            string n = WgIf(), pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            foreach (var c in new[] { Path.Combine(DataDir, "wg", n + ".conf"), Path.Combine(pf, "WireGuard", "Data", "Configurations", n + ".conf.dpapi"), Path.Combine(pf, "WireGuard", "Data", "Configurations", n + ".conf") })
                if (File.Exists(c)) return c;
            return null;
        }
        static string WgServerAddress()
        {
            var a = CfgStr("wg.serverAddress", ""); if (a.Length > 0) return a;
            var c = WgConf();
            if (c != null && c.EndsWith(".conf")) { try { var m = Regex.Match(File.ReadAllText(c), @"(?m)^\s*Address\s*=\s*([\d\.]+)"); if (m.Success) return m.Groups[1].Value; } catch { } }
            var ip = Ipv4(WgIf()); return ip != null && !ip.StartsWith("192.168.137.") ? ip : null;
        }
        static void WgWatch()
        {
            string sn = CfgStr("wg.serviceName", "WireGuardTunnel$wg_server"), wgExe = CfgStr("wg.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe");
            var svc = Svc(sn); var conf = WgConf();
            if (svc == null) {
                if (conf != null && File.Exists(wgExe)) {
                    // под общей блокировкой: веб-интерфейс мог как раз переустанавливать службу (перенос, новый сервер) — тогда дождаться и проверить снова
                    bool done = WgLib.TryLocked(90000, () => {
                        if (Svc(sn) != null) return;
                        conf = WgConf(); if (conf == null) return;
                        Log("wg_server: служба туннеля отсутствует — устанавливаю из " + conf, "WARN");
                        var e = WgLib.InstallService(wgExe, sn, WgIf(), conf); Log("wg_server: установка службы — " + (e ?? "готово"), e == null ? "INFO" : "ERROR");
                    });
                    if (!done) Log("wg_server: службы нет, но сервер сейчас меняют из веб-интерфейса — проверю позже", "INFO");
                } else if (CfgBool("wg.autoCreateServer", true)) {
                    if (++WgMissingTicks < 3) Log("wg_server: нет ни службы, ни конфига (" + WgMissingTicks + "/3) — если так останется, создам сервер сам", "WARN");
                    else { WgMissingTicks = 0; try { WgCreateServer(); } catch (Exception e) { Log("wg_server: не удалось создать сервер: " + e.Message, "ERROR"); } }
                } else Log("wg_server: служба '" + sn + "' не найдена и конфиг не найден — создайте сервер на вкладке WG-Server", "ERROR");
                return;
            }
            if (StartMode(sn) != "Auto") { SetAutoStart(sn); Log("wg_server: тип запуска службы -> Автоматически", "INFO"); }
            if (svc.Status != ServiceControllerStatus.Running) {
                Log("wg_server: служба в состоянии " + svc.Status + " — запускаю", "WARN");
                try { if (svc.Status != ServiceControllerStatus.Stopped) { svc.Stop(); svc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)); } svc.Start(); svc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30)); Log("wg_server: служба запущена", "INFO"); }
                catch (Exception e) { Log("wg_server: не удалось запустить: " + e.Message, "ERROR"); }
                return;
            }
            if (!Up(WgIf())) { Log("wg_server: служба работает, но адаптер не поднят — перезапуск службы", "WARN"); SvcRestart(sn); return; }
            // ICS при неудачных включениях добавляет адаптеру свой адрес 192.168.137.1 — рядом с нашим он только путает (ретранслятор, клиенты)
            try {
                string want = WgServerAddress(); var n = Nic(WgIf());
                if (want != null && n != null) {
                    var ips = n.GetIPProperties().UnicastAddresses.Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork).Select(u => u.Address.ToString()).ToList();
                    if (ips.Contains(want)) foreach (var ip in ips.Where(x => x != want && x.StartsWith("192.168.137."))) {
                        Exe("netsh.exe", "interface ipv4 delete address name=\"" + WgIf() + "\" address=" + ip, 15);
                        Log("wg_server: убран лишний адрес " + ip + " (его добавила раздача Windows) — остаётся " + want, "INFO");
                    }
                }
            } catch { }
            WgServiceHeal(sn, wgExe, conf);
        }
        // служба туннеля установлена с другим файлом, чем конфиг VpnGuard (например, её успели поставить из прежнего конфига) —
        // правки сервера не применялись бы. Переустановить на свой конфиг (не чаще раза в 10 минут)
        static DateTime WgHealAt = DateTime.MinValue;
        static void WgServiceHeal(string sn, string wgExe, string conf)
        {
            if (conf == null || !conf.StartsWith(Path.Combine(DataDir, "wg"), StringComparison.OrdinalIgnoreCase) || (DateTime.Now - WgHealAt).TotalMinutes < 10) return;
            var sc = WgLib.ServiceConf(sn); if (sc == null) return;
            try { if (string.Equals(Path.GetFullPath(sc), Path.GetFullPath(conf), StringComparison.OrdinalIgnoreCase)) return; } catch { return; }
            WgHealAt = DateTime.Now;
            WgLib.TryLocked(30000, () => {
                var now = WgLib.ServiceConf(sn); if (now == null || string.Equals(Path.GetFullPath(now), Path.GetFullPath(conf), StringComparison.OrdinalIgnoreCase)) return;
                Log("wg_server: служба туннеля работает с " + now + ", а конфиг VpnGuard — " + conf + ". Переустанавливаю службу (клиенты отключатся на несколько секунд)", "WARN");
                var e = WgLib.InstallService(wgExe, sn, WgIf(), conf);
                if (e != null) { Log("wg_server: переустановка службы: " + e + " — возвращаю прежний конфиг", "ERROR"); WgLib.InstallService(wgExe, sn, WgIf(), now); }
                else { Log("wg_server: служба туннеля — на конфиге VpnGuard", "INFO"); Emit("wg.restarted", "служба переустановлена на конфиг VpnGuard"); }
            });
        }
        static Dictionary<string, string> PeerNamesByKey = new Dictionary<string, string>(), PeerNamesByIp = new Dictionary<string, string>(); static string PeerStamp = "";
        static void LoadPeerNames()
        {
            var conf = WgConf(); if (conf == null || !conf.EndsWith(".conf")) return;
            var dir = Path.GetDirectoryName(Path.GetDirectoryName(conf));
            List<string> files = new List<string>(); try { files = Directory.GetFiles(dir, "*.conf", SearchOption.AllDirectories).Where(f => f != conf && !f.StartsWith(Path.Combine(DataDir, "backup"), StringComparison.OrdinalIgnoreCase)).Take(200).ToList(); } catch { }
            var stamp = string.Join("|", new[] { conf }.Concat(files).Select(f => File.GetLastWriteTimeUtc(f).Ticks));
            if (stamp == PeerStamp) return;
            var byKey = new Dictionary<string, string>(); var byIp = new Dictionary<string, string>();
            // имя клиента: «# Name = …» внутри блока [Peer] (так пишет VpnGuard) → комментарий над [Peer] (старый формат: «# 1», «[Peer]»)
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
            var lines = WgDump(); if (lines == null || lines.Length == 0) return null;
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

        // для окна и веба (сводка): часть «WG-Server»
        static Dictionary<string, object> WgComp(object clientZapret)
        {
            var wa = Nic(WgIf()); var wgSvc = Svc(CfgStr("wg.serviceName", "WireGuardTunnel$wg_server"));
            bool wUp = wgSvc != null && wgSvc.Status == ServiceControllerStatus.Running && wa != null && wa.OperationalStatus == OperationalStatus.Up;
            if (wUp) { if (WgUpSince == DateTime.MinValue) WgUpSince = DateTime.Now; } else WgUpSince = DateTime.MinValue;
            string wIp = wa != null ? Ipv4(WgIf()) : null;
            // wg_server
            int wL; string wS; int activeN = 0; string port = "";
            if (wgSvc == null) { wL = 2; wS = "Служба не найдена"; } else if (wgSvc.Status != ServiceControllerStatus.Running) { wL = 2; wS = "Служба: " + wgSvc.Status; } else if (!wUp) { wL = 1; wS = "Адаптер не поднят"; } else { wL = 0; wS = "Работает"; }
            var peers = wUp ? WgPeers(out activeN, out port) : null; if (peers == null) { activeN = 0; port = ""; }
            string addr = WgServerAddress(); string sm = wgSvc != null ? StartMode(wgSvc.ServiceName) : "";
            var wg = Comp(wL, wS, new[] { "Служба: " + (wgSvc != null ? wgSvc.Status + " / " + sm : "нет"), "IP: " + (wIp ?? "—") + (addr != null ? " (нужен " + addr + ")" : ""), peers != null ? "Клиенты: " + activeN + " активных из " + peers.Count : "Клиенты: —" }, new List<object[]> {
                Kv("Служба", wgSvc != null ? wgSvc.ServiceName + " · " + wgSvc.Status + " / " + sm : "не найдена"), Kv("Адаптер", wa != null ? wa.OperationalStatus.ToString() : "отсутствует"),
                Kv("IP", (wIp ?? "—") + (addr != null && addr != wIp ? " (нужен " + addr + ")" : "")), Kv("Порт", port.Length > 0 ? port + " UDP" : "—"), Kv("Работает с", WgUpSince == DateTime.MinValue ? "—" : When(WgUpSince)),
                Kv("Клиенты", peers != null ? activeN + " активных из " + peers.Count : "—"), Kv("Конфиг", WgConf() ?? "—"),
                Kv("zapret для клиентов", CzSummary()) });
            wg["peers"] = peers != null ? peers.ToArray() : new object[0];
            wg["clientZapret"] = clientZapret;
            return wg;
        }

        // «wg show wg_server dump»: первая строка — сервер (ключи, порт), дальше — клиенты (ключ, psk, адрес, разрешённые, рукопожатие, принято, отправлено …).
        // Один запуск wg.exe на всех потребителей (живые скорости, сводка, защита AmneziaVPN, клиенты, учёт локальной сети) — не чаще раза в 2 с
        static string[] WgDump()
        {
            return Cached("wgdump", 2, () => {
                var wg = Path.Combine(Path.GetDirectoryName(CfgStr("wg.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe")), "wg.exe");
                if (!File.Exists(wg)) return null;
                var r = Exe(wg, "show " + WgIf() + " dump", 5);
                return r.Code == 0 ? r.Out.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries) : null;
            });
        }
        static void WgDumpReset() { Uncache("wgdump"); }

        // новый сервер: ключи, data\wg\wg_server.conf (доступ — только администраторам и SYSTEM), служба туннеля, правило брандмауэра
        static void WgCreateServer()
        {
            string gui = CfgStr("wg.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe"), cli = Path.Combine(Path.GetDirectoryName(gui), "wg.exe");
            if (!File.Exists(gui)) throw new Exception("WireGuard не установлен (" + gui + ") — установите его на вкладке «Компоненты»");
            var dir = Path.Combine(DataDir, "wg"); Directory.CreateDirectory(dir); var conf = Path.Combine(dir, WgIf() + ".conf");
            if (!File.Exists(conf)) {
                int port = CfgInt("wg.newServerPort", 51820);
                WgLib.WriteLines(conf, WgLib.NewServerConf(cli, CfgStr("wg.newServerAddress", "10.253.0.1/24"), port, 0));
                Exe("icacls.exe", "\"" + conf + "\" /inheritance:r /grant:r *S-1-5-32-544:F *S-1-5-18:F", 15);
                Exe("netsh.exe", "advfirewall firewall add rule name=\"VpnGuard wg_server\" dir=in action=allow protocol=UDP localport=" + port + " profile=any", 15);
            }
            CfgSet("wg.configPath", conf);
            string err = null; WgLib.TryLocked(60000, () => err = WgLib.InstallService(gui, CfgStr("wg.serviceName", "WireGuardTunnel$wg_server"), WgIf(), conf));
            if (err != null) throw new Exception(err);
            Log("wg_server: создан новый сервер (" + conf + ", адрес " + CfgStr("wg.newServerAddress", "10.253.0.1/24") + ", порт " + CfgInt("wg.newServerPort", 51820) + ")", "WARN");
        }
    }
}
