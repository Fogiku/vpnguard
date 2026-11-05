// VpnGuard — клиенты и сервер WG-Server в веб-интерфейсе: список, конфиг и QR, создание, удаление, переименование клиентов;
// сервер целиком: адрес и подсеть, порт, MTU, адрес/DNS/маршруты/keepalive для клиентов, ключ сервера, правка конфига, резервные копии,
// создание с нуля, перенос конфига из другого места в папку VpnGuard, починка службы туннеля.
// Разбор и правка конфигов — общая библиотека agent\WgLib.cs (её же использует агент). Все изменения — под блокировкой Global\VpnGuardWgConf.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace VpnGuard
{
    public static partial class Web
    {
        static string WgIfName { get { return CfgStr("wg.interfaceName", "wg_server"); } }
        static string WgSvcName { get { return CfgStr("wg.serviceName", "WireGuardTunnel$wg_server"); } }
        static string WgGuiExe { get { return CfgStr("wg.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe"); } }
        static string WgCli { get { return Path.Combine(Path.GetDirectoryName(WgGuiExe), "wg.exe"); } }
        static string WgClientsDir { get { return Path.Combine(DataDir, "clients"); } }
        static string WgMirrorDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "VpnGuard", "clients"); } }   // переживает переустановку
        static string WgBackupDir { get { return Path.Combine(DataDir, "backup"); } }
        static string WgOwnDir { get { return Path.Combine(DataDir, "wg"); } }
        static string WgOwnConf { get { return Path.Combine(WgOwnDir, WgIfName + ".conf"); } }
        static string WgAllowed { get { return CfgStr("wg.clientAllowedIPs", "0.0.0.0/0"); } }
        static int WgKeepalive { get { return CfgInt("wg.clientKeepalive", 25); } }
        static readonly Regex WgNameRx = new Regex(@"^[\w\- \.а-яА-ЯёЁ]{1,40}$");
        const string WgIpRx = @"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$";

        // конфиг сервера: из настроек → из службы туннеля → свой (data\wg)
        static string WgFindConf()
        {
            var p = CfgStr("wg.configPath", ""); if (p.Length > 0 && File.Exists(p)) return p;
            var sc = WgLib.ServiceConf(WgSvcName); if (sc != null && File.Exists(sc)) return sc;
            return File.Exists(WgOwnConf) ? WgOwnConf : null;
        }
        static bool WgOwned(string conf) { return conf != null && conf.StartsWith(WgOwnDir, StringComparison.OrdinalIgnoreCase); }
        static bool WgSame(string a, string b) { try { return a != null && b != null && string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase); } catch { return false; } }
        static bool WgTunnelUp() { try { using (var s = new ServiceController(WgSvcName)) return s.Status == ServiceControllerStatus.Running; } catch { return false; } }
        static List<WgLib.ClientFile> WgFiles(string conf) { return WgLib.ClientFiles(conf, WgClientsDir, WgMirrorDir, WgBackupDir); }
        static string WgIfaceKey(string conf, string key)
        {
            var i = WgLib.Read(conf).Sections.FirstOrDefault(s => s.Type.Equals("Interface", StringComparison.OrdinalIgnoreCase)); string v;
            return i != null && i.Keys.TryGetValue(key, out v) ? v : "";
        }
        static string WgPhysIp()
        {
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback && !Regex.IsMatch(n.Name + n.Description, "MeduzaVPN|wg_server|WireGuard|Amnezia|tun2socks|TAP-Windows", RegexOptions.IgnoreCase)))
                if (n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && g.Address.ToString() != "0.0.0.0")) return Ip4(n);
            return null;
        }
        // адрес, по которому клиенты подключаются: из настроек → из готовых конфигов клиентов → внешний IP провайдера (через физический адаптер, мимо VPN)
        static string WgEndpoint(WgLib.Server info, bool lookup)
        {
            var e = CfgStr("wg.endpoint", "").Trim(); if (e.Length > 0) return Regex.IsMatch(e, @":\d+$") ? e : e + ":" + info.Port;
            var f = WgFiles(info.Conf).FirstOrDefault(x => x.Endpoint.Length > 0); if (f != null) return Regex.Replace(f.Endpoint, @":\d+$", "") + ":" + info.Port;
            if (!lookup) return "";
            var ip = PublicIp(WgPhysIp()); if (Regex.IsMatch(ip, @"^\d+\.\d+\.\d+\.\d+$")) return ip + ":" + info.Port;
            throw new Exception("Не удалось узнать внешний адрес — укажите «Адрес для клиентов» в настройках сервера.");
        }
        static string WgDns(WgLib.Server info)
        {
            var d = CfgStr("wg.clientDns", "").Trim(); if (d.Length > 0) return d;
            var f = WgFiles(info.Conf).FirstOrDefault(x => x.Dns.Length > 0); return f != null ? f.Dns : info.Ip;      // DNS-прокси раздачи на адресе сервера
        }
        static Dictionary<string, object> WgErr(string m) { return new Dictionary<string, object> { { "ok", false }, { "error", m } }; }
        static Dictionary<string, object> WgOk(params object[] kv) { var d = new Dictionary<string, object> { { "ok", true } }; for (int i = 0; i + 1 < kv.Length; i += 2) d[(string)kv[i]] = kv[i + 1]; return d; }
        static string WgBStr(Dictionary<string, object> b, string k) { return b.ContainsKey(k) && b[k] != null ? Convert.ToString(b[k]).Trim() : null; }

        // ---------------------------------------------------------------- список клиентов и сведения о сервере
        static Dictionary<string, object> WgClientsJson()
        {
            try {
                var conf = WgFindConf();
                if (conf == null) {
                    var r = WgErr("Сервера WG-Server ещё нет"); r["noServer"] = true; r["installed"] = File.Exists(WgGuiExe);
                    r["defaults"] = new Dictionary<string, object> { { "address", Regex.Replace(CfgStr("wg.newServerAddress", "10.253.0.1/24"), "/.*$", "") }, { "port", CfgInt("wg.newServerPort", 51820) } };
                    return r;
                }
                var info = WgLib.Info(conf, WgCli); var files = WgFiles(conf);
                var list = info.Peers.Select(p => {
                    var f = files.Where(x => x.Ip == p.Ip).OrderBy(x => x.Ours ? 0 : 1).FirstOrDefault();
                    string src = p.Managed || (f != null && f.Ours) ? "VpnGuard" : f != null ? "внешний файл" : "только на сервере";
                    return (object)new Dictionary<string, object> { { "name", p.Name ?? (f != null ? f.Name : p.Ip) }, { "ip", p.Ip }, { "source", src }, { "hasConf", f != null } };
                }).ToArray();
                var sc = WgLib.ServiceConf(WgSvcName); int mtu; int.TryParse(WgIfaceKey(conf, "MTU"), out mtu);
                int backups = 0; try { backups = Directory.Exists(WgBackupDir) ? Directory.GetFiles(WgBackupDir, WgIfName + "-*.conf").Length : 0; } catch { }
                return WgOk("clients", list, "server", new Dictionary<string, object> {
                    { "conf", conf }, { "owned", WgOwned(conf) }, { "address", info.Ip + "/" + info.Prefix }, { "ip", info.Ip }, { "prefix", info.Prefix }, { "port", info.Port }, { "mtu", mtu },
                    { "publicKey", info.PublicKey }, { "endpoint", WgEndpoint(info, false) }, { "endpointSet", CfgStr("wg.endpoint", "") }, { "dns", WgDns(info) }, { "dnsSet", CfgStr("wg.clientDns", "") },
                    { "allowed", WgAllowed }, { "keepalive", WgKeepalive }, { "extClients", files.Count(x => !x.Ours) }, { "noFile", list.Count(x => !(bool)((Dictionary<string, object>)x)["hasConf"]) },
                    { "svcConf", sc ?? "" }, { "svcOk", sc != null && WgSame(sc, conf) }, { "running", WgTunnelUp() }, { "installed", File.Exists(WgGuiExe) }, { "backups", backups } });
            } catch (Exception e) { return WgErr(e.Message); }
        }
        static Dictionary<string, object> WgConfJson(string ip)
        {
            try {
                var conf = WgFindConf(); var info = WgLib.Info(conf, WgCli);
                var f = WgFiles(conf).Where(x => x.Ip == ip).OrderBy(x => x.Ours ? 0 : 1).FirstOrDefault();
                if (f == null) return WgErr("конфиг этого клиента на ПК не хранится — удалите и создайте заново");
                var p = info.Peers.FirstOrDefault(x => x.Ip == ip);
                return WgOk("name", p != null && p.Name != null ? p.Name : f.Name, "text", File.ReadAllText(f.File, Encoding.UTF8));
            } catch (Exception e) { return WgErr(e.Message); }
        }
        static string WgSafeFile(string name) { return Regex.Replace(name.Trim(), @"\s+", "_") + ".conf"; }
        static void WgWriteClient(string name, IEnumerable<string> lines)
        {
            Directory.CreateDirectory(WgClientsDir); WgLib.WriteLines(Path.Combine(WgClientsDir, WgSafeFile(name)), lines);
            try { Directory.CreateDirectory(WgMirrorDir); WgLib.WriteLines(Path.Combine(WgMirrorDir, WgSafeFile(name)), lines); } catch { }
        }

        // ---------------------------------------------------------------- клиенты: создать / удалить / переименовать
        static Dictionary<string, object> WgAdd(string name)
        {
            name = (name ?? "").Trim();
            if (!WgNameRx.IsMatch(name)) return WgErr("имя: буквы, цифры, пробел, - _ . (до 40)");
            try {
                return WgLib.Locked(() => {
                    var conf = WgFindConf(); var info = WgLib.Info(conf, WgCli); var files = WgFiles(conf);
                    if (info.Peers.Any(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))) return WgErr("Клиент «" + name + "» уже есть");
                    if (File.Exists(Path.Combine(WgClientsDir, WgSafeFile(name)))) return WgErr("Файл клиента «" + name + "» уже есть");
                    var ip = WgLib.FreeIp(info, files.Select(f => f.Ip));
                    var endpoint = WgEndpoint(info, true); var dns = WgDns(info);
                    var keys = WgLib.KeyPair(WgCli); var psk = WgLib.Wg(WgCli, "genpsk");
                    var text = WgLib.ClientConf(keys[0], ip, dns, info.PublicKey, psk, endpoint, WgAllowed, WgKeepalive);
                    WgLib.AppendPeer(conf, WgBackupDir, name, keys[1], psk, ip);
                    WgWriteClient(name, text);
                    if (WgTunnelUp()) {                                                    // применить сразу, без перезапуска туннеля
                        var tmp = Path.Combine(Path.GetTempPath(), "vg-psk-" + Guid.NewGuid().ToString("N") + ".txt");
                        try { File.WriteAllText(tmp, psk); WgLib.Wg(WgCli, "set " + WgIfName + " peer " + keys[1] + " preshared-key \"" + tmp + "\" allowed-ips " + ip + "/32"); } finally { try { File.Delete(tmp); } catch { } }
                    }
                    return WgOk("name", name, "ip", ip, "text", string.Join("\r\n", text), "endpoint", endpoint);
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }
        static Dictionary<string, object> WgRemove(string ip)
        {
            try {
                return WgLib.Locked(() => {
                    var conf = WgFindConf(); var info = WgLib.Info(conf, WgCli);
                    var p = info.Peers.FirstOrDefault(x => x.Ip == ip); if (p == null) return WgErr("клиент не найден");
                    WgLib.RemovePeer(conf, WgBackupDir, p.Key);
                    if (WgTunnelUp()) { try { WgLib.Wg(WgCli, "set " + WgIfName + " peer " + p.Key + " remove"); } catch { } }
                    // файл клиента: наш — удалить (и копию); внешний — убрать в резервные копии
                    foreach (var f in WgFiles(conf).Where(x => x.Ip == ip)) {
                        try {
                            if (f.Ours) File.Delete(f.File);
                            else { Directory.CreateDirectory(WgBackupDir); File.Move(f.File, Path.Combine(WgBackupDir, "client-" + f.Name + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".conf")); }
                        } catch { }
                    }
                    WgListDrop(ip);
                    return WgOk("name", p.Name ?? ip);
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }
        static Dictionary<string, object> WgRename(string ip, string name)
        {
            name = (name ?? "").Trim();
            if (!WgNameRx.IsMatch(name)) return WgErr("имя: буквы, цифры, пробел, - _ . (до 40)");
            try {
                return WgLib.Locked(() => {
                    var conf = WgFindConf(); var info = WgLib.Info(conf, WgCli);
                    var p = info.Peers.FirstOrDefault(x => x.Ip == ip); if (p == null) return WgErr("клиент не найден");
                    if (info.Peers.Any(x => x.Ip != ip && string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase))) return WgErr("Клиент «" + name + "» уже есть");
                    string old = p.Name ?? ip;
                    WgLib.RenamePeer(conf, WgBackupDir, p.Key, name);
                    // свой файл конфига — под новым именем (и копию в ProgramData)
                    foreach (var f in WgFiles(conf).Where(x => x.Ip == ip && x.Ours)) {
                        var dst = Path.Combine(Path.GetDirectoryName(f.File), WgSafeFile(name));
                        if (!string.Equals(dst, f.File, StringComparison.OrdinalIgnoreCase) && !File.Exists(dst)) { try { File.Move(f.File, dst); } catch { } }
                    }
                    return WgOk("old", old, "name", name);
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }
        // списки IP клиентов в настройках (отключённые, без zapret): убрать адрес / заменить адреса по таблице
        static void WgListDrop(string ip) { WgListMap(new Dictionary<string, string> { { ip, null } }); }
        static void WgListMap(Dictionary<string, string> map)
        {
            foreach (var key in new[] { "wg.clientOff", "wg.clientNoZapret" }) {
                var cur = (CfgGet(key, null) as System.Collections.IEnumerable ?? new object[0]).Cast<object>().Select(x => Convert.ToString(x).Trim()).Where(x => x.Length > 0).ToList();
                var nw = cur.Select(x => map.ContainsKey(x) ? map[x] : x).Where(x => x != null).Distinct().ToList();
                if (!nw.SequenceEqual(cur)) CfgSet(key, nw.ToArray());
            }
        }

        // ---------------------------------------------------------------- настройки сервера
        // Для всех: адрес/DNS/маршруты/keepalive для клиентов (свои конфиги клиентов обновляются сами).
        // Только конфиг в папке VpnGuard: адрес сервера (подсеть /24 — адреса клиентов переносятся в новую подсеть), порт, MTU — туннель перезапускается.
        static Dictionary<string, object> WgServerSet(Dictionary<string, object> b)
        {
            try {
                return WgLib.Locked(() => {
                    var conf = WgFindConf(); if (conf == null) return WgErr("сервера ещё нет");
                    var info = WgLib.Info(conf, WgCli); var done = new List<string>(); bool owned = WgOwned(conf);
                    string ep = WgBStr(b, "endpoint"), dns = WgBStr(b, "dns"), allowed = WgBStr(b, "allowed"), addr = WgBStr(b, "address");
                    int curMtu; int.TryParse(WgIfaceKey(conf, "MTU"), out curMtu);
                    int port = b.ContainsKey("port") && Convert.ToString(b["port"]).Trim().Length > 0 ? Convert.ToInt32(b["port"]) : info.Port;
                    int mtu = b.ContainsKey("mtu") ? (Convert.ToString(b["mtu"]).Trim().Length > 0 ? Convert.ToInt32(b["mtu"]) : 0) : curMtu;
                    int ka = b.ContainsKey("keepalive") && Convert.ToString(b["keepalive"]).Trim().Length > 0 ? Convert.ToInt32(b["keepalive"]) : WgKeepalive;
                    // проверка
                    if (ep != null && ep.Length > 0 && !Regex.IsMatch(ep, @"^[A-Za-z0-9\.\-]{1,100}(:\d{1,5})?$")) return WgErr("адрес для клиентов: IP или имя, можно с :портом");
                    if (dns != null && dns.Length > 0 && !Regex.IsMatch(dns, @"^\d{1,3}(\.\d{1,3}){3}(\s*,\s*\d{1,3}(\.\d{1,3}){3})*$")) return WgErr("DNS: IP-адреса через запятую");
                    if (allowed != null) { allowed = Regex.Replace(allowed, @"\s*,\s*", ", "); if (allowed.Length == 0) allowed = "0.0.0.0/0"; if (!Regex.IsMatch(allowed, @"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}(, \d{1,3}(\.\d{1,3}){3}/\d{1,2})*$")) return WgErr("маршруты клиентов: подсети через запятую, например 0.0.0.0/0 или 192.168.1.0/24, 10.0.0.0/8"); }
                    if (port < 1 || port > 65535) return WgErr("порт: 1–65535");
                    if (mtu != 0 && (mtu < 1280 || mtu > 1500)) return WgErr("MTU: 1280–1500 (пусто — автоматически)");
                    if (ka < 0 || ka > 600) return WgErr("keepalive: 0–600 с (0 — выключено)");
                    string newIp = null;
                    if (addr != null && addr.Length > 0) {
                        var m = Regex.Match(Regex.Replace(addr, "/24$", ""), WgIpRx);
                        if (!m.Success || Enumerable.Range(1, 4).Any(i => int.Parse(m.Groups[i].Value) > 255) || int.Parse(m.Groups[4].Value) < 1 || int.Parse(m.Groups[4].Value) > 254) return WgErr("адрес сервера: IP вида 10.8.0.1 (подсеть /24)");
                        var f = int.Parse(m.Groups[1].Value); var s2 = int.Parse(m.Groups[2].Value);
                        if (!(f == 10 || (f == 172 && s2 >= 16 && s2 <= 31) || (f == 192 && s2 == 168))) return WgErr("адрес сервера — из частных сетей: 10.x.x.x, 172.16–31.x.x, 192.168.x.x");
                        if (int.Parse(m.Groups[1].Value) == 192 && s2 == 168 && m.Groups[3].Value == "137") return WgErr("подсеть 192.168.137.x занята общим доступом Windows (ICS)");
                        if (Regex.Replace(m.Value, @"\.\d+$", ".") == Regex.Replace(WgPhysIp() ?? "", @"\.\d+$", ".")) return WgErr("эта подсеть совпадает с локальной сетью ПК (" + WgPhysIp() + ")");
                        if (m.Value != info.Ip) newIp = m.Value;
                    }
                    bool srvCh = port != info.Port || mtu != curMtu || newIp != null;
                    if (srvCh && !owned) return WgErr("адрес, порт и MTU меняются только у конфига в папке VpnGuard — сначала перенесите его («Перенести конфиг в VpnGuard»)");
                    if (newIp != null) {           // клиенты переезжают в новую подсеть с тем же последним числом адреса — адрес сервера не должен совпасть ни с одним
                        var busy = info.Peers.FirstOrDefault(p => p.Ip.Split('.').Last() == newIp.Split('.')[3]);
                        if (busy != null) return WgErr("адрес " + newIp + " займёт клиент «" + (busy.Name ?? busy.Ip) + "» (" + busy.Ip + ") — выберите другое последнее число");
                    }
                    // настройки для клиентов
                    bool epCh = false, dnsCh = false, alCh = false, kaCh = false;
                    if (ep != null && ep != CfgStr("wg.endpoint", "")) { CfgSet("wg.endpoint", ep); done.Add("адрес для клиентов " + (ep.Length > 0 ? ep : "— автоматически")); epCh = true; }
                    if (dns != null && dns != CfgStr("wg.clientDns", "")) { CfgSet("wg.clientDns", dns); done.Add("DNS " + (dns.Length > 0 ? dns : "— автоматически")); dnsCh = true; }
                    if (allowed != null && allowed != WgAllowed) { CfgSet("wg.clientAllowedIPs", allowed); done.Add("маршруты клиентов " + allowed); alCh = true; }
                    if (ka != WgKeepalive) { CfgSet("wg.clientKeepalive", ka); done.Add("keepalive " + (ka > 0 ? ka + " с" : "выкл")); kaCh = true; }
                    // сервер
                    var map = new Dictionary<string, string>();
                    if (srvCh) {
                        var set = new Dictionary<string, string>();
                        if (port != info.Port) { set["ListenPort"] = port.ToString(); done.Add("порт " + port); }
                        if (mtu != curMtu) { set["MTU"] = mtu > 0 ? mtu.ToString() : null; done.Add("MTU " + (mtu > 0 ? mtu.ToString() : "автоматически")); }
                        if (newIp != null) {
                            set["Address"] = newIp + "/24"; string np = Regex.Replace(newIp, @"\.\d+$", ".");
                            foreach (var p in info.Peers) { var nip = np + p.Ip.Split('.')[3]; if (nip != p.Ip) map[p.Ip] = nip; }
                            map[info.Ip] = newIp;
                            done.Add("адрес сервера " + newIp + "/24" + (map.Count > 1 ? ", адреса клиентов перенесены в " + np + "0/24" : ""));
                        }
                        WgLib.SetKeys(conf, WgBackupDir, "Interface", set);
                        if (map.Count > 0) { WgLib.RenumberPeers(conf, WgBackupDir, map); WgListMap(map); if (CfgStr("wg.serverAddress", "").Length > 0) CfgSet("wg.serverAddress", newIp); }
                    }
                    // свои конфиги клиентов
                    int patched = 0; string epSet = CfgStr("wg.endpoint", "").Trim();
                    foreach (var f in WgFiles(conf).Where(x => x.Ours)) {
                        var fi = new Dictionary<string, string>(); var fp = new Dictionary<string, string>();
                        string nip; if (map.TryGetValue(f.Ip, out nip)) fi["Address"] = nip + "/32";
                        if (dnsCh && CfgStr("wg.clientDns", "").Length > 0) fi["DNS"] = CfgStr("wg.clientDns", "");
                        else if (newIp != null && f.Dns.Contains(info.Ip)) fi["DNS"] = f.Dns.Replace(info.Ip, newIp);
                        if (epCh && epSet.Length > 0) fp["Endpoint"] = Regex.IsMatch(epSet, @":\d+$") ? epSet : epSet + ":" + port;
                        else if (port != info.Port && f.Endpoint.Length > 0) fp["Endpoint"] = Regex.Replace(f.Endpoint, @":\d+$", "") + ":" + port;
                        if (alCh) fp["AllowedIPs"] = allowed;
                        if (kaCh) fp["PersistentKeepalive"] = ka > 0 ? ka.ToString() : null;
                        if (WgLib.PatchClient(f.File, fi, fp)) patched++;
                    }
                    if (patched > 0) done.Add("обновлено конфигов клиентов: " + patched + " — на устройствах их нужно загрузить заново (QR)");
                    if (srvCh) {
                        var e = WgLib.RestartService(WgSvcName); done.Add(e == null ? "туннель перезапущен" : "туннель не перезапустился: " + e);
                        if (port != info.Port) {
                            RunOut("netsh.exe", "advfirewall firewall delete rule name=\"VpnGuard wg_server\"", 15);
                            RunOut("netsh.exe", "advfirewall firewall add rule name=\"VpnGuard wg_server\" dir=in action=allow protocol=UDP localport=" + port + " profile=any", 15);
                        }
                        SendCmd("reapply-ics", "изменены настройки сервера WG-Server");
                    }
                    return WgOk("done", done.ToArray());
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }

        // ---------------------------------------------------------------- ключ сервера: новая пара; свои конфиги клиентов получают новый открытый ключ сервера
        static Dictionary<string, object> WgRegenKey()
        {
            try {
                return WgLib.Locked(() => {
                    var conf = WgFindConf(); if (!WgOwned(conf)) return WgErr("ключ меняется только у конфига в папке VpnGuard");
                    var keys = WgLib.KeyPair(WgCli);
                    WgLib.SetKeys(conf, WgBackupDir, "Interface", new Dictionary<string, string> { { "PrivateKey", keys[0] } });
                    int patched = 0;
                    foreach (var f in WgFiles(conf).Where(x => x.Ours)) if (WgLib.PatchClient(f.File, new Dictionary<string, string>(), new Dictionary<string, string> { { "PublicKey", keys[1] } })) patched++;
                    var e = WgLib.RestartService(WgSvcName);
                    Log("Веб-интерфейс: у сервера WG-Server новый ключ; обновлено конфигов клиентов: " + patched, "WARN");
                    return WgOk("publicKey", keys[1], "patched", patched, "restart", e ?? "");
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }

        // ---------------------------------------------------------------- конфиг сервера целиком: показать (закрытый ключ скрыт) и сохранить (с проверкой)
        static Dictionary<string, object> WgServerConfText()
        {
            try { var conf = WgFindConf(); if (conf == null) return WgErr("сервера ещё нет"); return WgOk("text", WgLib.Masked(conf), "owned", WgOwned(conf), "conf", conf); }
            catch (Exception e) { return WgErr(e.Message); }
        }
        static Dictionary<string, object> WgServerConfSave(string text)
        {
            try {
                return WgLib.Locked(() => {
                    var conf = WgFindConf(); if (!WgOwned(conf)) return WgErr("конфиг правится только в папке VpnGuard");
                    var key = WgIfaceKey(conf, "PrivateKey");
                    var lines = (text ?? "").Replace("\r\n", "\n").Split('\n').Select(l => l.TrimEnd()).Select(l => l.Contains(WgLib.KeyMask) ? Regex.Replace(l, @"=.*$", "= " + key) : l).ToList();
                    while (lines.Count > 0 && lines[lines.Count - 1].Length == 0) lines.RemoveAt(lines.Count - 1);
                    var err = WgLib.Validate(lines); if (err != null) return WgErr(err);
                    WgLib.Backup(conf, WgBackupDir); WgLib.WriteLines(conf, lines);
                    var e = WgLib.RestartService(WgSvcName);
                    SendCmd("reapply-ics", "конфиг WG-Server изменён вручную");
                    return WgOk("restart", e ?? "");
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }

        // ---------------------------------------------------------------- резервные копии конфига сервера (data\backup, последние 30 изменений)
        static readonly Regex WgBackupRx = new Regex(@"^[\w\-]+-\d{8}-\d{6}-\d{3}\.conf$");
        static Dictionary<string, object> WgBackups()
        {
            try {
                var list = !Directory.Exists(WgBackupDir) ? new object[0] : new DirectoryInfo(WgBackupDir).GetFiles(WgIfName + "-*.conf").Where(f => WgBackupRx.IsMatch(f.Name)).OrderByDescending(f => f.LastWriteTime).Take(30).Select(f => {
                    int peers = 0; string addr = "", port = "";
                    try { var c = WgLib.Read(f.FullName); peers = c.Sections.Count(s => s.Type.Equals("Peer", StringComparison.OrdinalIgnoreCase)); var i = c.Sections.FirstOrDefault(s => s.Type.Equals("Interface", StringComparison.OrdinalIgnoreCase)); if (i != null) { i.Keys.TryGetValue("Address", out addr); i.Keys.TryGetValue("ListenPort", out port); } } catch { }
                    return (object)new Dictionary<string, object> { { "file", f.Name }, { "at", f.LastWriteTime.ToString("dd.MM.yyyy HH:mm:ss") }, { "peers", peers }, { "address", addr ?? "" }, { "port", port ?? "" } };
                }).ToArray();
                return WgOk("backups", list);
            } catch (Exception e) { return WgErr(e.Message); }
        }
        static Dictionary<string, object> WgRestore(string file)
        {
            if (file == null || !WgBackupRx.IsMatch(file)) return WgErr("неверное имя копии");
            try {
                return WgLib.Locked(() => {
                    var conf = WgFindConf(); if (!WgOwned(conf)) return WgErr("восстановление — только для конфига в папке VpnGuard");
                    var src = Path.Combine(WgBackupDir, file); if (!File.Exists(src)) return WgErr("копия не найдена");
                    var lines = WgLib.ReadLines(src); var err = WgLib.Validate(lines); if (err != null) return WgErr("копия повреждена: " + err);
                    WgLib.Backup(conf, WgBackupDir); WgLib.WriteLines(conf, lines);
                    var e = WgLib.RestartService(WgSvcName); SendCmd("reapply-ics", "конфиг WG-Server восстановлен из копии");
                    Log("Веб-интерфейс: конфиг сервера WG-Server восстановлен из копии " + file, "WARN");
                    return WgOk("restart", e ?? "");
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }

        // ---------------------------------------------------------------- новый сервер с нуля (или заново: прежний конфиг и клиенты — в резервную копию)
        static Dictionary<string, object> WgCreate(Dictionary<string, object> b)
        {
            try {
                if (!File.Exists(WgGuiExe)) return WgErr("WireGuard не установлен — установите его на вкладке «Компоненты»");
                string addr = WgBStr(b, "address") ?? ""; var m = Regex.Match(Regex.Replace(addr, "/24$", ""), WgIpRx);
                if (!m.Success || Enumerable.Range(1, 4).Any(i => int.Parse(m.Groups[i].Value) > 255) || int.Parse(m.Groups[4].Value) < 1 || int.Parse(m.Groups[4].Value) > 254) return WgErr("адрес сервера: IP вида 10.8.0.1 (подсеть /24)");
                int port; if (!int.TryParse(WgBStr(b, "port") ?? "", out port) || port < 1 || port > 65535) return WgErr("порт: 1–65535");
                int mtu = 0; var ms = WgBStr(b, "mtu"); if (!string.IsNullOrEmpty(ms) && (!int.TryParse(ms, out mtu) || mtu < 1280 || mtu > 1500)) return WgErr("MTU: 1280–1500 (пусто — автоматически)");
                bool recreate = b.ContainsKey("recreate") && Convert.ToBoolean(b["recreate"]);
                return WgLib.Locked(() => {
                    var old = WgFindConf();
                    if (old != null && !recreate) return WgErr("сервер уже есть: " + old);
                    var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss"); int moved = 0;
                    if (old != null) {
                        WgLib.Backup(old, WgBackupDir);
                        var keep = Path.Combine(WgBackupDir, "clients-" + stamp); Directory.CreateDirectory(keep);
                        foreach (var d in new[] { WgClientsDir, WgMirrorDir }) if (Directory.Exists(d)) foreach (var f in Directory.GetFiles(d, "*.conf")) { try { File.Copy(f, Path.Combine(keep, Path.GetFileName(f)), true); File.Delete(f); moved++; } catch { } }
                        CfgSet("wg.clientOff", new object[0]); CfgSet("wg.clientNoZapret", new object[0]);
                    }
                    Directory.CreateDirectory(WgOwnDir); if (File.Exists(WgOwnConf)) WgLib.Backup(WgOwnConf, WgBackupDir);
                    WgLib.WriteLines(WgOwnConf, WgLib.NewServerConf(WgCli, m.Value + "/24", port, mtu));
                    RunOut("icacls.exe", "\"" + WgOwnConf + "\" /inheritance:r /grant:r *S-1-5-32-544:F *S-1-5-18:F", 15);
                    RunOut("netsh.exe", "advfirewall firewall delete rule name=\"VpnGuard wg_server\"", 15);
                    RunOut("netsh.exe", "advfirewall firewall add rule name=\"VpnGuard wg_server\" dir=in action=allow protocol=UDP localport=" + port + " profile=any", 15);
                    CfgSet("wg.configPath", WgOwnConf); if (CfgStr("wg.serverAddress", "").Length > 0) CfgSet("wg.serverAddress", m.Value);
                    if (b.ContainsKey("endpoint")) CfgSet("wg.endpoint", WgBStr(b, "endpoint")); if (b.ContainsKey("dns")) CfgSet("wg.clientDns", WgBStr(b, "dns"));
                    Log("WG-Server: создаю " + (old != null ? "заново " : "") + "сервер " + m.Value + "/24, порт " + port + (old != null ? " (прежний конфиг и " + moved / 2 + " клиент(ов) — в data\\backup)" : ""), "WARN");
                    var err = WgLib.InstallService(WgGuiExe, WgSvcName, WgIfName, WgOwnConf);
                    if (err != null) { Log("WG-Server: служба туннеля нового сервера: " + err, "ERROR"); return WgErr("сервер записан, но служба туннеля: " + err); }
                    SendCmd("reapply-ics", "создан сервер WG-Server");
                    return WgOk("conf", WgOwnConf);
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }

        // ---------------------------------------------------------------- служба туннеля — на текущий конфиг (если она работает с другим файлом)
        static Dictionary<string, object> WgFixService()
        {
            try {
                return WgLib.Locked(() => {
                    var conf = WgFindConf(); if (conf == null) return WgErr("сервера ещё нет");
                    Log("WG-Server: переустанавливаю службу туннеля на " + conf + " (было: " + (WgLib.ServiceConf(WgSvcName) ?? "нет службы") + ")", "WARN");
                    var err = WgLib.InstallService(WgGuiExe, WgSvcName, WgIfName, conf); if (err != null) return WgErr(err);
                    SendCmd("reapply-ics", "служба WG-Server переустановлена"); return WgOk();
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }

        // ---------------------------------------------------------------- перенос конфига сервера из другого места в папку VpnGuard (data\wg) и его клиентов — в data\clients;
        // служба туннеля — на новый конфиг (клиенты отключатся на несколько секунд). Прежние файлы не трогаются (копия)
        static Dictionary<string, object> WgAdopt()
        {
            try {
                return WgLib.Locked(() => {
                    var conf = WgFindConf(); if (conf == null) return WgErr("конфиг сервера не найден");
                    if (WgOwned(conf)) return WgErr("конфиг уже в папке VpnGuard");
                    var info = WgLib.Info(conf, WgCli); var files = WgFiles(conf);
                    Directory.CreateDirectory(WgOwnDir); var nconf = WgOwnConf;
                    if (File.Exists(nconf)) WgLib.Backup(nconf, WgBackupDir);
                    File.Copy(conf, nconf, true);
                    // имена — в формате VpnGuard («# Name = …» внутри блока); внешние конфиги клиентов — копии в data\clients
                    int imported = 0;
                    foreach (var p in info.Peers) {
                        var f = files.Where(x => x.Ip == p.Ip).OrderBy(x => x.Ours ? 0 : 1).FirstOrDefault();
                        string nm = p.Name ?? (f != null ? f.Name : p.Ip.Replace('.', '-'));
                        WgLib.RenamePeer(nconf, WgBackupDir, p.Key, nm);
                        if (f != null && !f.Ours && !File.Exists(Path.Combine(WgClientsDir, WgSafeFile(nm)))) { WgWriteClient(nm, WgLib.ReadLines(f.File)); imported++; }
                    }
                    RunOut("icacls.exe", "\"" + nconf + "\" /inheritance:r /grant:r *S-1-5-32-544:F *S-1-5-18:F", 15);       // закрытый ключ — только администраторам и SYSTEM
                    // сначала настройка (агент, если увидит службу пропавшей, поставит её уже из нового конфига), потом служба; не поднялась — вернуть прежний
                    Log("WG-Server: переношу конфиг сервера в папку VpnGuard (" + conf + " → " + nconf + "), клиенты отключатся на несколько секунд", "WARN");
                    CfgSet("wg.configPath", nconf);
                    var err = WgLib.InstallService(WgGuiExe, WgSvcName, WgIfName, nconf);
                    if (err != null) {
                        CfgSet("wg.configPath", conf); var back = WgLib.InstallService(WgGuiExe, WgSvcName, WgIfName, conf);
                        Log("WG-Server: новый туннель не поднялся (" + err + ") — вернул прежний конфиг" + (back != null ? ", но и он: " + back : ""), "ERROR");
                        return WgErr("туннель на новом конфиге не поднялся (" + err + ") — вернул прежний");
                    }
                    SendCmd("reapply-ics", "конфиг WG-Server перенесён в папку VpnGuard");
                    Log("WG-Server: конфиг сервера — " + nconf + "; конфигов клиентов перенесено: " + imported, "WARN");
                    return WgOk("conf", nconf, "imported", imported);
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }
    }
}
