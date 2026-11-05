// VpnGuard — клиенты и сервер WG-Server в веб-интерфейсе (раньше — PowerShell Wg.ps1 через «-WebTask»): список, конфиг и QR, создание, удаление,
// переименование, настройки сервера (адрес для клиентов, DNS, порт) и перенос сервера из WS4W под управление VpnGuard.
// Разбор и правка конфигов — общая библиотека agent\WgLib.cs (её же использует агент).
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
        static string WgIfName { get { return CfgStr("ws4w.interfaceName", "wg_server"); } }
        static string WgSvcName { get { return CfgStr("ws4w.serviceName", "WireGuardTunnel$wg_server"); } }
        static string WgGuiExe { get { return CfgStr("ws4w.wireguardExe", @"C:\Program Files\WireGuard\wireguard.exe"); } }
        static string WgCli { get { return Path.Combine(Path.GetDirectoryName(WgGuiExe), "wg.exe"); } }
        static string WgClientsDir { get { return Path.Combine(DataDir, "clients"); } }
        static string WgMirrorDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "VpnGuard", "clients"); } }   // переживает переустановку
        static string WgBackupDir { get { return Path.Combine(DataDir, "backup"); } }
        static string WgOwnDir { get { return Path.Combine(DataDir, "wg"); } }
        static readonly Regex WgNameRx = new Regex(@"^[\w\- \.а-яА-ЯёЁ]{1,40}$");

        // конфиг сервера: из настроек → из службы туннеля → известные места (WS4W, свой)
        static string WgFindConf()
        {
            var p = CfgStr("ws4w.configPath", ""); if (p.Length > 0 && File.Exists(p)) return p;
            try {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + WgSvcName)) {
                    var m = Regex.Match(k == null ? "" : Convert.ToString(k.GetValue("ImagePath")), "/tunnelservice\\s+\"?([^\"]+?\\.conf(\\.dpapi)?)\"?\\s*$");
                    if (m.Success && File.Exists(m.Groups[1].Value)) return m.Groups[1].Value;
                }
            } catch { }
            foreach (var c in new[] { Path.Combine(WgOwnDir, WgIfName + ".conf"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WS4W", "server_wg", WgIfName + ".conf"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WS4W", WgIfName + ".conf") }) if (File.Exists(c)) return c;
            return null;
        }
        static bool WgOwned(string conf) { return conf != null && conf.StartsWith(WgOwnDir, StringComparison.OrdinalIgnoreCase); }
        static bool WgTunnelUp() { try { using (var s = new ServiceController(WgSvcName)) return s.Status == ServiceControllerStatus.Running; } catch { return false; } }
        static List<WgLib.ClientFile> WgFiles(string conf) { return WgLib.ClientFiles(conf, WgClientsDir, WgMirrorDir, WgBackupDir); }
        static string WgPhysIp()
        {
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback && !Regex.IsMatch(n.Name + n.Description, "MeduzaVPN|wg_server|WireGuard|Amnezia|tun2socks|TAP-Windows", RegexOptions.IgnoreCase)))
                if (n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && g.Address.ToString() != "0.0.0.0")) return Ip4(n);
            return null;
        }
        // адрес, по которому клиенты подключаются: из настроек → из готовых конфигов клиентов → внешний IP провайдера (через физический адаптер, мимо VPN)
        static string WgEndpoint(WgLib.Server info, bool lookup)
        {
            var e = CfgStr("ws4w.endpoint", "").Trim(); if (e.Length > 0) return Regex.IsMatch(e, @":\d+$") ? e : e + ":" + info.Port;
            var f = WgFiles(info.Conf).FirstOrDefault(x => x.Endpoint.Length > 0); if (f != null) return f.Endpoint;
            if (!lookup) return "";
            var ip = PublicIp(WgPhysIp()); if (Regex.IsMatch(ip, @"^\d+\.\d+\.\d+\.\d+$")) return ip + ":" + info.Port;
            throw new Exception("Не удалось узнать внешний адрес — укажите «Адрес для клиентов» в настройках сервера.");
        }
        static string WgDns(WgLib.Server info)
        {
            var d = CfgStr("ws4w.clientDns", "").Trim(); if (d.Length > 0) return d;
            var f = WgFiles(info.Conf).FirstOrDefault(x => x.Dns.Length > 0); return f != null ? f.Dns : info.Ip;      // DNS-прокси раздачи на адресе сервера
        }
        static Dictionary<string, object> WgErr(string m) { return new Dictionary<string, object> { { "ok", false }, { "error", m } }; }

        // ---------------------------------------------------------------- список
        static Dictionary<string, object> WgClientsJson()
        {
            try {
                var conf = WgFindConf(); var info = WgLib.Info(conf, WgCli); var files = WgFiles(conf);
                var list = info.Peers.Select(p => {
                    var f = files.Where(x => x.Ip == p.Ip).OrderBy(x => x.Ours ? 0 : 1).FirstOrDefault();
                    string src = p.Managed || (f != null && f.Ours) ? "VpnGuard" : f != null ? "WS4W" : "только на сервере";
                    return (object)new Dictionary<string, object> { { "name", p.Name ?? (f != null ? f.Name : p.Ip) }, { "ip", p.Ip }, { "source", src }, { "hasConf", f != null } };
                }).ToArray();
                return new Dictionary<string, object> { { "ok", true }, { "clients", list }, { "server", new Dictionary<string, object> {
                    { "conf", conf }, { "owned", WgOwned(conf) }, { "address", info.Ip + "/" + info.Prefix }, { "port", info.Port }, { "endpoint", WgEndpoint(info, false) },
                    { "endpointSet", CfgStr("ws4w.endpoint", "") }, { "dns", WgDns(info) }, { "dnsSet", CfgStr("ws4w.clientDns", "") }, { "ws4wClients", files.Count(x => !x.Ours) } } } };
            } catch (Exception e) { return WgErr(e.Message); }
        }
        static Dictionary<string, object> WgConfJson(string ip)
        {
            try {
                var conf = WgFindConf(); var info = WgLib.Info(conf, WgCli);
                var f = WgFiles(conf).Where(x => x.Ip == ip).OrderBy(x => x.Ours ? 0 : 1).FirstOrDefault();
                if (f == null) return WgErr("конфиг этого клиента на ПК не хранится — удалите и создайте заново");
                var p = info.Peers.FirstOrDefault(x => x.Ip == ip);
                return new Dictionary<string, object> { { "ok", true }, { "name", p != null && p.Name != null ? p.Name : f.Name }, { "text", File.ReadAllText(f.File, Encoding.UTF8) } };
            } catch (Exception e) { return WgErr(e.Message); }
        }
        static string WgSafeFile(string name) { return Regex.Replace(name.Trim(), @"\s+", "_") + ".conf"; }
        static void WgWriteClient(string name, IEnumerable<string> lines)
        {
            Directory.CreateDirectory(WgClientsDir); WgLib.WriteLines(Path.Combine(WgClientsDir, WgSafeFile(name)), lines);
            try { Directory.CreateDirectory(WgMirrorDir); WgLib.WriteLines(Path.Combine(WgMirrorDir, WgSafeFile(name)), lines); } catch { }
        }

        // ---------------------------------------------------------------- создать / удалить / переименовать
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
                    var text = WgLib.ClientConf(keys[0], ip, dns, info.PublicKey, psk, endpoint);
                    WgLib.AppendPeer(conf, WgBackupDir, name, keys[1], psk, ip);
                    WgWriteClient(name, text);
                    if (WgTunnelUp()) {                                                    // применить сразу, без перезапуска туннеля
                        var tmp = Path.Combine(Path.GetTempPath(), "vg-psk-" + Guid.NewGuid().ToString("N") + ".txt");
                        try { File.WriteAllText(tmp, psk); WgLib.Wg(WgCli, "set " + WgIfName + " peer " + keys[1] + " preshared-key \"" + tmp + "\" allowed-ips " + ip + "/32"); } finally { try { File.Delete(tmp); } catch { } }
                    }
                    return new Dictionary<string, object> { { "ok", true }, { "name", name }, { "ip", ip }, { "text", string.Join("\r\n", text) }, { "endpoint", endpoint } };
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
                    // файл клиента: наш — удалить (и копию); из WS4W — убрать в копии (иначе WS4W вернёт клиента)
                    foreach (var f in WgFiles(conf).Where(x => x.Ip == ip)) {
                        try {
                            if (f.Ours) File.Delete(f.File);
                            else { Directory.CreateDirectory(WgBackupDir); File.Move(f.File, Path.Combine(WgBackupDir, "client-" + f.Name + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".conf")); }
                        } catch { }
                    }
                    return new Dictionary<string, object> { { "ok", true }, { "name", p.Name ?? ip } };
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
                    return new Dictionary<string, object> { { "ok", true }, { "old", old }, { "name", name } };
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }

        // ---------------------------------------------------------------- настройки сервера: адрес для клиентов, DNS, порт. Свои конфиги клиентов обновляются сами
        static Dictionary<string, object> WgServerSet(Dictionary<string, object> b)
        {
            try {
                return WgLib.Locked(() => {
                    var conf = WgFindConf(); var info = WgLib.Info(conf, WgCli); var done = new List<string>();
                    string ep = b.ContainsKey("endpoint") ? Convert.ToString(b["endpoint"]).Trim() : null, dns = b.ContainsKey("dns") ? Convert.ToString(b["dns"]).Trim() : null;
                    int port = b.ContainsKey("port") ? Convert.ToInt32(b["port"]) : info.Port;
                    if (ep != null && ep.Length > 0 && !Regex.IsMatch(ep, @"^[A-Za-z0-9\.\-]{1,100}(:\d{1,5})?$")) return WgErr("адрес для клиентов: IP или имя, можно с :портом");
                    if (dns != null && dns.Length > 0 && !Regex.IsMatch(dns, @"^\d{1,3}(\.\d{1,3}){3}(\s*,\s*\d{1,3}(\.\d{1,3}){3})*$")) return WgErr("DNS: IP-адреса через запятую");
                    if (port < 1 || port > 65535) return WgErr("порт: 1–65535");
                    if (ep != null && ep != CfgStr("ws4w.endpoint", "")) { CfgSet("ws4w.endpoint", ep); done.Add("адрес для клиентов " + (ep.Length > 0 ? ep : "— автоматически")); }
                    if (dns != null && dns != CfgStr("ws4w.clientDns", "")) { CfgSet("ws4w.clientDns", dns); done.Add("DNS " + (dns.Length > 0 ? dns : "— автоматически")); }
                    if (port != info.Port) {
                        if (!WgOwned(conf)) return WgErr("порт сервера WS4W меняется в WS4W — или сначала перенесите сервер под управление VpnGuard");
                        WgLib.SetListenPort(conf, WgBackupDir, port); info.Port = port;
                        try { using (var s = new ServiceController(WgSvcName)) { s.Stop(); s.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)); s.Start(); s.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20)); } } catch { }
                        RunOut("netsh.exe", "advfirewall firewall delete rule name=\"VpnGuard wg_server\"", 15);
                        RunOut("netsh.exe", "advfirewall firewall add rule name=\"VpnGuard wg_server\" dir=in action=allow protocol=UDP localport=" + port + " profile=any", 15);
                        SendCmd("reapply-ics", "порт WG-Server изменён"); done.Add("порт " + port + " (туннель перезапущен)");
                    }
                    // свои конфиги клиентов — с новым адресом и DNS (клиентам WS4W — в WS4W)
                    int patched = 0; string newEp = null, newDns = null;
                    try { newEp = WgEndpoint(info, false); } catch { } newDns = WgDns(info);
                    foreach (var f in WgFiles(conf).Where(x => x.Ours)) if (WgLib.PatchClient(f.File, string.IsNullOrEmpty(newEp) ? null : newEp, newDns)) patched++;
                    if (patched > 0) done.Add("обновлено конфигов клиентов: " + patched + " — на устройствах их нужно загрузить заново (QR)");
                    return new Dictionary<string, object> { { "ok", true }, { "done", done.ToArray() } };
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }

        // ---------------------------------------------------------------- перенос сервера из WS4W под управление VpnGuard: конфиг сервера и клиентов — в data\,
        // служба туннеля — на новый конфиг (клиенты отключатся на несколько секунд). WS4W после этого не нужен; его файлы не трогаются (копия)
        static Dictionary<string, object> WgAdopt()
        {
            try {
                return WgLib.Locked(() => {
                    var conf = WgFindConf(); if (conf == null) return WgErr("конфиг сервера не найден");
                    if (WgOwned(conf)) return WgErr("сервер уже под управлением VpnGuard");
                    var info = WgLib.Info(conf, WgCli); var files = WgFiles(conf);
                    Directory.CreateDirectory(WgOwnDir); var nconf = Path.Combine(WgOwnDir, WgIfName + ".conf");
                    if (File.Exists(nconf)) WgLib.Backup(nconf, WgBackupDir);
                    File.Copy(conf, nconf, true);
                    // имена — в формате VpnGuard («# Name = …» внутри блока); клиенты WS4W — свои файлы конфигов
                    int imported = 0;
                    foreach (var p in info.Peers) {
                        var f = files.Where(x => x.Ip == p.Ip).OrderBy(x => x.Ours ? 0 : 1).FirstOrDefault();
                        string nm = p.Name ?? (f != null ? f.Name : p.Ip.Replace('.', '-'));
                        WgLib.RenamePeer(nconf, WgBackupDir, p.Key, nm);
                        if (f != null && !f.Ours && !File.Exists(Path.Combine(WgClientsDir, WgSafeFile(nm)))) { WgWriteClient(nm, WgLib.ReadLines(f.File)); imported++; }
                    }
                    RunOut("icacls.exe", "\"" + nconf + "\" /inheritance:r /grant:r *S-1-5-32-544:F *S-1-5-18:F", 15);       // закрытый ключ — только администраторам и SYSTEM
                    // служба туннеля — на новый конфиг; не поднялась — вернуть прежний
                    Log("WG-Server: переношу сервер под управление VpnGuard (" + conf + " → " + nconf + "), клиенты отключатся на несколько секунд", "WARN");
                    RunOut(WgGuiExe, "/uninstalltunnelservice " + WgIfName, 60); Thread.Sleep(3000);
                    var r = RunOut(WgGuiExe, "/installtunnelservice \"" + nconf + "\"", 60); Thread.Sleep(5000);
                    if (!WgTunnelUp()) {
                        RunOut(WgGuiExe, "/uninstalltunnelservice " + WgIfName, 60); Thread.Sleep(2000); RunOut(WgGuiExe, "/installtunnelservice \"" + conf + "\"", 60);
                        Log("WG-Server: новый туннель не поднялся (" + r + ") — вернул прежний конфиг", "ERROR");
                        return WgErr("туннель на новом конфиге не поднялся — вернул прежний (WS4W)");
                    }
                    CfgSet("ws4w.configPath", nconf);
                    SendCmd("reapply-ics", "сервер WG-Server перенесён под управление VpnGuard");
                    Log("WG-Server: сервер под управлением VpnGuard — " + nconf + "; клиентов из WS4W перенесено: " + imported + ". WS4W больше не нужен", "WARN");
                    return new Dictionary<string, object> { { "ok", true }, { "conf", nconf }, { "imported", imported } };
                });
            } catch (Exception e) { return WgErr(e.Message); }
        }
    }
}
