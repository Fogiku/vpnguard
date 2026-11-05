// Общая библиотека WireGuard (агент и веб-сервер — один код): разбор конфига сервера wg_server в старом формате («# 1» строкой над [Peer])
// и VpnGuard («# Name = …» внутри [Peer]), имена клиентов, ключи (wg.exe), добавление / удаление / переименование клиентов.
// Меняются только блоки [Peer] (и ListenPort при смене порта), остальное в конфиге не трогается. Перед каждым изменением — копия в data\backup.
// Конфиг правят два процесса (агент, веб-сервер) — под общей блокировкой Global\VpnGuardWgConf.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace VpnGuard
{
    public static class WgLib
    {
        public class Sec { public string Type; public int Start, End; public Dictionary<string, string> Keys = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); public List<string> Comments = new List<string>(), Above = new List<string>(); }
        public class Conf { public List<string> Lines; public List<Sec> Sections; }
        public class Peer { public string Key, Ip, Name, Allowed, Psk; public bool Managed; }
        public class Server { public string Conf, Ip, PublicKey; public int Prefix, Port; public List<Peer> Peers; }
        public class ClientFile { public string File, Name, Ip, Endpoint, Dns; public bool Ours; }

        // ---------------------------------------------------------------- файлы
        public static List<string> ReadLines(string path) { return File.ReadAllLines(path, Encoding.UTF8).ToList(); }      // UTF-8 с BOM и без
        public static void WriteLines(string path, IEnumerable<string> lines)                                                   // без BOM: WireGuard читает как есть
        {
            var tmp = path + ".vg-tmp"; File.WriteAllText(tmp, string.Join("\r\n", lines) + "\r\n", new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(tmp, path, null); else File.Move(tmp, path);
        }
        public static void Backup(string path, string backupDir)
        {
            Directory.CreateDirectory(backupDir);
            File.Copy(path, Path.Combine(backupDir, Path.GetFileNameWithoutExtension(path) + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss-fff") + ".conf"), true);
            foreach (var f in new DirectoryInfo(backupDir).GetFiles("*.conf").OrderByDescending(x => x.LastWriteTime).Skip(30)) { try { f.Delete(); } catch { } }
        }
        // изменить конфиг сервера под общей блокировкой (агент и веб-сервер)
        public static T Locked<T>(Func<T> f)
        {
            using (var mx = new Mutex(false, "Global\\VpnGuardWgConf")) {
                bool got = false; try { got = mx.WaitOne(15000); } catch (AbandonedMutexException) { got = true; }
                try { return f(); } finally { if (got) try { mx.ReleaseMutex(); } catch { } }
            }
        }

        // ---------------------------------------------------------------- разбор: секции с номерами строк. Комментарии после последнего ключа секции
        // относятся к следующей (Above): старый формат — имя строкой над [Peer] («# 1»); VpnGuard — внутри («# Name = …»). End — последний ключ или комментарий внутри
        public static Conf Read(string path)
        {
            var lines = ReadLines(path); var secs = new List<Sec>(); Sec cur = null; var pending = new List<KeyValuePair<int, string>>();
            for (int i = 0; i < lines.Count; i++) {
                var l = lines[i];
                var h = Regex.Match(l, @"^\s*\[(\w+)\]");
                if (h.Success) { cur = new Sec { Type = h.Groups[1].Value, Start = i, End = i, Above = pending.Select(p => p.Value).ToList() }; pending.Clear(); secs.Add(cur); continue; }
                var c = Regex.Match(l, @"^\s*[#;]\s*(.*?)\s*$"); if (c.Success) { pending.Add(new KeyValuePair<int, string>(i, c.Groups[1].Value)); continue; }
                if (cur == null || l.Trim().Length == 0) continue;
                foreach (var p in pending) cur.Comments.Add(p.Value); pending.Clear();
                cur.End = i;
                var k = Regex.Match(l, @"^\s*(\w+)\s*=\s*(.*?)\s*$"); if (k.Success) cur.Keys[k.Groups[1].Value] = k.Groups[2].Value;
            }
            if (cur != null) foreach (var p in pending) { cur.Comments.Add(p.Value); cur.End = p.Key; }
            foreach (var s in secs) while (s.End > s.Start && lines[s.End].Trim().Length == 0) s.End--;
            return new Conf { Lines = lines, Sections = secs };
        }
        static readonly Regex NameRx = new Regex(@"^(?:Name|Client|Имя)\s*[=:]\s*(.+)$", RegexOptions.IgnoreCase);
        // имя клиента: «# Name = …» внутри блока → комментарий над [Peer] (старый формат) → первый свой комментарий в блоке
        public static string PeerName(Sec s)
        {
            foreach (var c in s.Comments) { var m = NameRx.Match(c); if (m.Success) return m.Groups[1].Value.Trim(); }
            string up = null;
            foreach (var c in s.Above) { var m = NameRx.Match(c); if (m.Success) up = m.Groups[1].Value.Trim(); else if (c.Length > 0 && c.Length <= 60 && !c.StartsWith("VpnGuard", StringComparison.OrdinalIgnoreCase)) up = c; }
            if (up != null) return up;
            foreach (var c in s.Comments) if (c.Length > 0 && !c.StartsWith("VpnGuard", StringComparison.OrdinalIgnoreCase)) return c;
            return null;
        }
        static string FirstIp(string v) { return Regex.Replace(((v ?? "").Split(',')[0]).Trim(), @"/\d+$", ""); }

        // ---------------------------------------------------------------- wg.exe: ключи. Ключ — в stdin сырыми ASCII-байтами (BOM/преамбула кодировки ломает ключ)
        public static string Wg(string wgExe, string args, string stdin = null)
        {
            if (!File.Exists(wgExe)) throw new Exception("не найден " + wgExe + " — установлен ли WireGuard?");
            var psi = new ProcessStartInfo(wgExe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true };
            using (var p = Process.Start(psi)) {
                var bs = p.StandardInput.BaseStream;
                if (stdin != null) { var b = Encoding.ASCII.GetBytes(stdin); bs.Write(b, 0, b.Length); bs.Flush(); }
                bs.Close();
                var o = p.StandardOutput.ReadToEndAsync(); var e = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(10000)) { try { p.Kill(); } catch { } throw new Exception("wg.exe " + args + " — нет ответа"); }
                if (p.ExitCode != 0) throw new Exception("wg.exe " + args.Split(' ')[0] + ": " + e.Result.Trim());
                return o.Result.Trim();
            }
        }
        public static string[] KeyPair(string wgExe) { var priv = Wg(wgExe, "genkey"); return new[] { priv, Wg(wgExe, "pubkey", priv + "\n") }; }

        // ---------------------------------------------------------------- сервер и его клиенты
        public static Server Info(string conf, string wgExe)
        {
            if (conf == null) throw new Exception("Конфиг сервера wg_server не найден.");
            if (conf.EndsWith(".dpapi", StringComparison.OrdinalIgnoreCase)) throw new Exception("Конфиг сервера зашифрован WireGuard (" + conf + ") — им нельзя управлять отсюда.");
            var c = Read(conf);
            var iface = c.Sections.FirstOrDefault(s => s.Type.Equals("Interface", StringComparison.OrdinalIgnoreCase));
            string pk; if (iface == null || !iface.Keys.TryGetValue("PrivateKey", out pk)) throw new Exception("В " + conf + " нет [Interface] с PrivateKey");
            string addr; iface.Keys.TryGetValue("Address", out addr);
            var m = Regex.Match((addr ?? "").Split(',')[0].Trim(), @"^(\d+\.\d+\.\d+\.\d+)/(\d+)$"); if (!m.Success) throw new Exception("Не понял адрес сервера '" + addr + "' в " + conf);
            string lp; int port = iface.Keys.TryGetValue("ListenPort", out lp) && int.TryParse(lp, out port) ? port : 51820;
            var peers = c.Sections.Where(s => s.Type.Equals("Peer", StringComparison.OrdinalIgnoreCase)).Select(s => {
                string k, a, psk; s.Keys.TryGetValue("PublicKey", out k); s.Keys.TryGetValue("AllowedIPs", out a); s.Keys.TryGetValue("PresharedKey", out psk);
                return new Peer { Key = k ?? "", Ip = FirstIp(a), Allowed = Regex.Replace(a ?? "", @"\s+", ""), Psk = psk ?? "", Name = PeerName(s), Managed = s.Comments.Any(x => x.StartsWith("VpnGuard", StringComparison.OrdinalIgnoreCase)) };
            }).ToList();
            return new Server { Conf = conf, Ip = m.Groups[1].Value, Prefix = int.Parse(m.Groups[2].Value), Port = port, PublicKey = Wg(wgExe, "pubkey", pk + "\n"), Peers = peers };
        }
        // конфиги клиентов: наши (data\clients и копия в ProgramData) и внешние (папки рядом с конфигом сервера)
        public static List<ClientFile> ClientFiles(string serverConf, string clientsDir, string mirrorDir, string backupDir)
        {
            var dirs = new List<string> { clientsDir, mirrorDir };
            if (serverConf != null) { var d = Path.GetDirectoryName(Path.GetDirectoryName(serverConf)); if (!string.IsNullOrEmpty(d)) dirs.Add(d); }
            var res = new List<ClientFile>(); var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in dirs.Distinct(StringComparer.OrdinalIgnoreCase)) {
                if (!Directory.Exists(d)) continue;
                IEnumerable<string> files; try { files = Directory.GetFiles(d, "*.conf", SearchOption.AllDirectories).Take(300); } catch { continue; }
                foreach (var f in files) {
                    if (string.Equals(f, serverConf, StringComparison.OrdinalIgnoreCase) || f.StartsWith(backupDir, StringComparison.OrdinalIgnoreCase) || f.IndexOf(@"\wg\", StringComparison.OrdinalIgnoreCase) >= 0 && f.EndsWith("wg_server.conf", StringComparison.OrdinalIgnoreCase)) continue;
                    try {
                        var c = Read(f);
                        var iface = c.Sections.FirstOrDefault(s => s.Type.Equals("Interface", StringComparison.OrdinalIgnoreCase)); var pe = c.Sections.FirstOrDefault(s => s.Type.Equals("Peer", StringComparison.OrdinalIgnoreCase));
                        string pk, addr, ep, dns; if (iface == null || pe == null || !iface.Keys.TryGetValue("PrivateKey", out pk)) continue;
                        iface.Keys.TryGetValue("Address", out addr); pe.Keys.TryGetValue("Endpoint", out ep); iface.Keys.TryGetValue("DNS", out dns);
                        var ip = FirstIp(addr); bool ours = f.StartsWith(clientsDir, StringComparison.OrdinalIgnoreCase) || f.StartsWith(mirrorDir, StringComparison.OrdinalIgnoreCase);
                        if (ours && !seen.Add(ip + "|" + Path.GetFileName(f))) continue;      // копия в ProgramData — тот же клиент
                        res.Add(new ClientFile { File = f, Name = Path.GetFileNameWithoutExtension(f), Ip = ip, Endpoint = ep ?? "", Dns = dns ?? "", Ours = ours });
                    } catch { }
                }
            }
            return res;
        }
        static uint U(string ip) { var b = IPAddress.Parse(ip).GetAddressBytes(); return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]; }
        static string S(uint v) { return (v >> 24) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255); }
        public static string FreeIp(Server info, IEnumerable<string> used)
        {
            var u = new HashSet<string>(used) { info.Ip }; foreach (var p in info.Peers) u.Add(p.Ip);
            uint mask = info.Prefix == 0 ? 0 : uint.MaxValue << (32 - info.Prefix), net = U(info.Ip) & mask, bc = net | ~mask;
            for (uint v = net + 2; v < bc; v++) { var s = S(v); if (!u.Contains(s)) return s; }
            throw new Exception("В подсети сервера не осталось свободных адресов");
        }
        // блок клиента: вместе с комментариями вплотную над [Peer] (старый формат: «# 1») и пустой строкой перед ними
        static int[] PeerRange(Conf c, Sec s)
        {
            int start = s.Start;
            while (start > 0 && Regex.IsMatch(c.Lines[start - 1], @"^\s*[#;]")) start--;
            if (start > 0 && c.Lines[start - 1].Trim().Length == 0) start--;
            return new[] { start, s.End };
        }
        public static Sec FindPeer(Conf c, string key) { return c.Sections.FirstOrDefault(s => s.Type.Equals("Peer", StringComparison.OrdinalIgnoreCase) && s.Keys.ContainsKey("PublicKey") && s.Keys["PublicKey"] == key); }
        public static void AppendPeer(string conf, string backupDir, string name, string pub, string psk, string ip)
        {
            Backup(conf, backupDir);
            var lines = ReadLines(conf); while (lines.Count > 0 && lines[lines.Count - 1].Trim().Length == 0) lines.RemoveAt(lines.Count - 1);
            lines.AddRange(new[] { "", "[Peer]", "# Name = " + name, "# VpnGuard: created " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"), "PublicKey = " + pub, "PresharedKey = " + psk, "AllowedIPs = " + ip + "/32" });
            WriteLines(conf, lines);
        }
        public static void RemovePeer(string conf, string backupDir, string key)
        {
            var c = Read(conf); var s = FindPeer(c, key); if (s == null) throw new Exception("Клиент не найден в конфиге сервера");
            var r = PeerRange(c, s); Backup(conf, backupDir);
            WriteLines(conf, c.Lines.Where((l, i) => i < r[0] || i > r[1]));
        }
        // переименовать: имя — «# Name = …» сразу после [Peer]; прежние имена (внутри и строкой над [Peer]) убираются
        public static void RenamePeer(string conf, string backupDir, string key, string name)
        {
            var c = Read(conf); var s = FindPeer(c, key); if (s == null) throw new Exception("Клиент не найден в конфиге сервера");
            var r = PeerRange(c, s); Backup(conf, backupDir);
            var block = new List<string>();
            for (int i = r[0]; i <= r[1]; i++) {
                var l = c.Lines[i]; var cm = Regex.Match(l, @"^\s*[#;]\s*(.*?)\s*$");
                if (i < s.Start && cm.Success) {                                   // над [Peer]: имя в старом формате — убрать, прочие комментарии оставить
                    var t = cm.Groups[1].Value; if (NameRx.IsMatch(t) || (t.Length > 0 && t.Length <= 60 && !t.StartsWith("VpnGuard", StringComparison.OrdinalIgnoreCase))) continue;
                }
                if (i > s.Start && cm.Success && NameRx.IsMatch(cm.Groups[1].Value)) continue;
                block.Add(l);
                if (i == s.Start) block.Add("# Name = " + name);
            }
            var outL = c.Lines.Take(r[0]).Concat(block).Concat(c.Lines.Skip(r[1] + 1)).ToList();
            WriteLines(conf, outL);
        }
        public static void SetListenPort(string conf, string backupDir, int port) { SetKeys(conf, backupDir, "Interface", new Dictionary<string, string> { { "ListenPort", port.ToString() } }); }

        // ---------------------------------------------------------------- правка ключей в первой секции нужного типа ([Interface] сервера; [Interface]/[Peer] клиента).
        // Значение null — убрать ключ. Остальные строки (комментарии, порядок) не трогаются. Возвращает: было ли изменение
        public static bool SetKeys(string file, string backupDir, string section, Dictionary<string, string> set)
        {
            var c = Read(file); var sec = c.Sections.FirstOrDefault(s => s.Type.Equals(section, StringComparison.OrdinalIgnoreCase));
            if (sec == null) throw new Exception("В " + Path.GetFileName(file) + " нет секции [" + section + "]");
            var lines = c.Lines.ToList(); bool ch = false; int insertAt = sec.End + 1;
            foreach (var kv in set) {
                int at = -1;
                for (int i = sec.Start + 1; i < insertAt; i++) if (Regex.IsMatch(lines[i], @"^\s*" + kv.Key + @"\s*=", RegexOptions.IgnoreCase)) at = i;
                string nl = kv.Value == null ? null : kv.Key + " = " + kv.Value;
                if (at >= 0) {
                    if (nl == null) { lines.RemoveAt(at); insertAt--; ch = true; }
                    else if (lines[at].Trim() != nl) { lines[at] = nl; ch = true; }
                } else if (nl != null) { lines.Insert(insertAt, nl); insertAt++; ch = true; }
            }
            if (!ch) return false;
            if (backupDir != null) Backup(file, backupDir);
            WriteLines(file, lines); return true;
        }
        // адреса клиентов на сервере: первый адрес в AllowedIPs каждого [Peer] — по таблице «старый IP → новый»
        public static void RenumberPeers(string conf, string backupDir, Dictionary<string, string> map)
        {
            var c = Read(conf); var lines = c.Lines.ToList(); bool ch = false;
            foreach (var s in c.Sections.Where(x => x.Type.Equals("Peer", StringComparison.OrdinalIgnoreCase)))
                for (int i = s.Start + 1; i <= s.End; i++) {
                    var m = Regex.Match(lines[i], @"^\s*AllowedIPs\s*=\s*(.*?)\s*$", RegexOptions.IgnoreCase); if (!m.Success) continue;
                    var parts = m.Groups[1].Value.Split(',').Select(x => x.Trim()).ToList(); string nw;
                    if (parts.Count > 0 && map.TryGetValue(FirstIp(parts[0]), out nw)) { parts[0] = nw + "/32"; lines[i] = "AllowedIPs = " + string.Join(", ", parts); ch = true; }
                }
            if (!ch) return;
            Backup(conf, backupDir); WriteLines(conf, lines);
        }
        // новый конфиг сервера
        public static List<string> NewServerConf(string wgExe, string address, int port, int mtu)
        {
            var keys = KeyPair(wgExe);
            var l = new List<string> { "[Interface]", "# VpnGuard: server created " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"), "PrivateKey = " + keys[0], "ListenPort = " + port, "Address = " + address };
            if (mtu > 0) l.Add("MTU = " + mtu);
            return l;
        }
        // конфиг сервера для показа и правки: закрытый ключ скрыт
        public const string KeyMask = "(скрыт — не меняйте эту строку)";
        public static string Masked(string conf) { return Regex.Replace(string.Join("\r\n", ReadLines(conf)), @"(?im)^(\s*PrivateKey\s*=\s*)\S+", "$1" + KeyMask); }
        // проверка конфига сервера перед записью: одна [Interface] с ключом и адресом /24, у каждого [Peer] — свой ключ и свой адрес в подсети
        public static string Validate(IList<string> lines)
        {
            var tmp = Path.Combine(Path.GetTempPath(), "vg-wgcheck-" + Guid.NewGuid().ToString("N") + ".conf");
            try {
                File.WriteAllLines(tmp, lines, new UTF8Encoding(false)); var c = Read(tmp);
                foreach (var l in c.Lines) { var t = l.Trim(); if (t.Length > 0 && !t.StartsWith("#") && !t.StartsWith(";") && !Regex.IsMatch(t, @"^\[\w+\]$") && !Regex.IsMatch(t, @"^\w+\s*=")) return "непонятная строка: «" + t + "»"; }
                var ifs = c.Sections.Where(s => s.Type.Equals("Interface", StringComparison.OrdinalIgnoreCase)).ToList();
                if (ifs.Count != 1) return "нужна ровно одна секция [Interface]";
                foreach (var s in c.Sections) if (!s.Type.Equals("Interface", StringComparison.OrdinalIgnoreCase) && !s.Type.Equals("Peer", StringComparison.OrdinalIgnoreCase)) return "неизвестная секция [" + s.Type + "]";
                string v; var i0 = ifs[0];
                if (!i0.Keys.TryGetValue("PrivateKey", out v) || !Regex.IsMatch(v, @"^[A-Za-z0-9+/]{42,43}=$")) return "в [Interface] нет правильного PrivateKey";
                if (!i0.Keys.TryGetValue("Address", out v) || !Regex.IsMatch(v.Split(',')[0].Trim(), @"^\d{1,3}(\.\d{1,3}){3}/24$")) return "Address сервера — IP с подсетью /24 (например 192.168.15.1/24)";
                var net = Regex.Replace(v.Split(',')[0].Trim(), @"\.\d+/24$", ".");
                if (i0.Keys.TryGetValue("ListenPort", out v)) { int p; if (!int.TryParse(v, out p) || p < 1 || p > 65535) return "ListenPort: 1–65535"; }
                if (i0.Keys.TryGetValue("MTU", out v)) { int p; if (!int.TryParse(v, out p) || p < 1280 || p > 1500) return "MTU: 1280–1500"; }
                var keys = new HashSet<string>(); var ips = new HashSet<string>();
                foreach (var s in c.Sections.Where(x => x.Type.Equals("Peer", StringComparison.OrdinalIgnoreCase))) {
                    string k, a; s.Keys.TryGetValue("PublicKey", out k); s.Keys.TryGetValue("AllowedIPs", out a);
                    if (k == null || !Regex.IsMatch(k, @"^[A-Za-z0-9+/]{42,43}=$")) return "у клиента (строка " + (s.Start + 1) + ") нет правильного PublicKey";
                    if (!keys.Add(k)) return "два клиента с одним ключом " + k.Substring(0, 8) + "…";
                    var ip = FirstIp(a); if (!Regex.IsMatch(ip, @"^\d{1,3}(\.\d{1,3}){3}$")) return "у клиента (строка " + (s.Start + 1) + ") нет AllowedIPs";
                    if (!ip.StartsWith(net)) return "адрес клиента " + ip + " не в подсети сервера " + net + "0/24";
                    if (!ips.Add(ip)) return "два клиента с одним адресом " + ip;
                }
                return null;
            } finally { try { File.Delete(tmp); } catch { } }
        }

        // ---------------------------------------------------------------- служба туннеля
        // конфиг, с которым установлена служба (ImagePath: «wireguard.exe /tunnelservice "…\wg_server.conf"»)
        public static string ServiceConf(string serviceName)
        {
            try {
                using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + serviceName)) {
                    var m = Regex.Match(k == null ? "" : Convert.ToString(k.GetValue("ImagePath")), "/tunnelservice\\s+\"?([^\"]+?\\.conf(\\.dpapi)?)\"?\\s*$");
                    return m.Success ? m.Groups[1].Value : null;
                }
            } catch { return null; }
        }
        static bool SvcExists(string name) { try { using (var s = new System.ServiceProcess.ServiceController(name)) { var x = s.Status; return true; } } catch { return false; } }
        static bool SvcRunning(string name) { try { using (var s = new System.ServiceProcess.ServiceController(name)) return s.Status == System.ServiceProcess.ServiceControllerStatus.Running; } catch { return false; } }
        static string Run(string exe, string args, int sec)
        {
            var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            using (var p = Process.Start(psi)) {
                var o = p.StandardOutput.ReadToEndAsync(); var e = p.StandardError.ReadToEndAsync();
                if (!p.WaitForExit(sec * 1000)) { try { p.Kill(); } catch { } return "нет ответа за " + sec + " с"; }
                return p.ExitCode == 0 ? null : ("код " + p.ExitCode + " " + e.Result + o.Result).Trim();
            }
        }
        // (пере)установить службу туннеля на конфиг: снять прежнюю, дождаться, что её нет, поставить, дождаться запуска и проверить, что служба — на этом конфиге.
        // Вызывать под блокировкой (Locked/TryLocked) — иначе агент может поставить службу из другого конфига, пока её нет. null — получилось, иначе причина
        public static string InstallService(string guiExe, string serviceName, string ifName, string conf)
        {
            if (!File.Exists(guiExe)) return "WireGuard не установлен (" + guiExe + ")";
            if (SvcExists(serviceName)) {
                Run(guiExe, "/uninstalltunnelservice " + ifName, 60);
                for (int i = 0; i < 40 && SvcExists(serviceName); i++) Thread.Sleep(500);
                if (SvcExists(serviceName)) return "прежняя служба туннеля не удалилась";
            }
            var err = Run(guiExe, "/installtunnelservice \"" + conf + "\"", 60); if (err != null) return "installtunnelservice: " + err;
            for (int i = 0; i < 40 && !SvcRunning(serviceName); i++) Thread.Sleep(500);
            if (!SvcRunning(serviceName)) return "служба туннеля не запустилась";
            var sc = ServiceConf(serviceName);
            if (sc != null && !string.Equals(Path.GetFullPath(sc), Path.GetFullPath(conf), StringComparison.OrdinalIgnoreCase)) return "служба установилась с другим конфигом: " + sc;
            return null;
        }
        // перезапуск службы: туннель перечитывает конфиг (адрес, порт, ключ, MTU, клиенты)
        public static string RestartService(string serviceName)
        {
            try {
                using (var s = new System.ServiceProcess.ServiceController(serviceName)) {
                    if (s.Status != System.ServiceProcess.ServiceControllerStatus.Stopped) { s.Stop(); s.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30)); }
                    s.Start(); s.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
                }
                return null;
            } catch (Exception e) { return e.Message; }
        }
        // блокировка без ожидания «до упора»: не получили за ms — действие не выполняется (агент: другой процесс как раз меняет сервер)
        public static bool TryLocked(int ms, Action a)
        {
            using (var mx = new Mutex(false, "Global\\VpnGuardWgConf")) {
                bool got = false; try { got = mx.WaitOne(ms); } catch (AbandonedMutexException) { got = true; }
                if (!got) return false;
                try { a(); return true; } finally { try { mx.ReleaseMutex(); } catch { } }
            }
        }

        // текст конфига клиента
        public static string[] ClientConf(string priv, string ip, string dns, string serverPub, string psk, string endpoint, string allowed = "0.0.0.0/0", int keepalive = 25)
        {
            var l = new List<string> { "[Interface]", "PrivateKey = " + priv, "Address = " + ip + "/32", "DNS = " + dns, "", "[Peer]", "PublicKey = " + serverPub, "PresharedKey = " + psk, "AllowedIPs = " + allowed, "Endpoint = " + endpoint };
            if (keepalive > 0) l.Add("PersistentKeepalive = " + keepalive);
            return l.ToArray();
        }
        // заменить Endpoint (адрес:порт сервера) и/или DNS в готовом конфиге клиента
        public static bool PatchClient(string file, string endpoint, string dns)
        {
            var i = new Dictionary<string, string>(); var p = new Dictionary<string, string>();
            if (dns != null) i["DNS"] = dns; if (endpoint != null) p["Endpoint"] = endpoint;
            return PatchClient(file, i, p);
        }
        public static bool PatchClient(string file, Dictionary<string, string> iface, Dictionary<string, string> peer)
        {
            bool a = iface.Count > 0 && SetKeys(file, null, "Interface", iface), b = peer.Count > 0 && SetKeys(file, null, "Peer", peer);
            return a | b;
        }
    }
}
