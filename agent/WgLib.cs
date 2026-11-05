// Общая библиотека WireGuard (агент и веб-сервер — один код): разбор конфига сервера wg_server в форматах WS4W («# 1» строкой над [Peer])
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
        // относятся к следующей (Above): WS4W пишет имя строкой над [Peer] («# 1»); VpnGuard — внутри («# Name = …»). End — последний ключ или комментарий внутри
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
        // имя клиента: «# Name = …» внутри блока → комментарий над [Peer] (WS4W) → первый свой комментарий в блоке
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
        // конфиги клиентов: наши (data\clients и копия в ProgramData) и WS4W (папки рядом с конфигом сервера)
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
        // блок клиента: вместе с комментариями вплотную над [Peer] (WS4W: «# 1») и пустой строкой перед ними
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
        // переименовать: имя — «# Name = …» сразу после [Peer]; прежние имена (внутри и строкой WS4W над [Peer]) убираются
        public static void RenamePeer(string conf, string backupDir, string key, string name)
        {
            var c = Read(conf); var s = FindPeer(c, key); if (s == null) throw new Exception("Клиент не найден в конфиге сервера");
            var r = PeerRange(c, s); Backup(conf, backupDir);
            var block = new List<string>();
            for (int i = r[0]; i <= r[1]; i++) {
                var l = c.Lines[i]; var cm = Regex.Match(l, @"^\s*[#;]\s*(.*?)\s*$");
                if (i < s.Start && cm.Success) {                                   // над [Peer]: имя WS4W — убрать, прочие комментарии оставить
                    var t = cm.Groups[1].Value; if (NameRx.IsMatch(t) || (t.Length > 0 && t.Length <= 60 && !t.StartsWith("VpnGuard", StringComparison.OrdinalIgnoreCase))) continue;
                }
                if (i > s.Start && cm.Success && NameRx.IsMatch(cm.Groups[1].Value)) continue;
                block.Add(l);
                if (i == s.Start) block.Add("# Name = " + name);
            }
            var outL = c.Lines.Take(r[0]).Concat(block).Concat(c.Lines.Skip(r[1] + 1)).ToList();
            WriteLines(conf, outL);
        }
        public static void SetListenPort(string conf, string backupDir, int port)
        {
            var c = Read(conf); var iface = c.Sections.First(s => s.Type.Equals("Interface", StringComparison.OrdinalIgnoreCase)); Backup(conf, backupDir);
            var lines = c.Lines.ToList(); int at = -1;
            for (int i = iface.Start + 1; i <= iface.End; i++) if (Regex.IsMatch(lines[i], @"^\s*ListenPort\s*=", RegexOptions.IgnoreCase)) at = i;
            if (at >= 0) lines[at] = "ListenPort = " + port; else lines.Insert(iface.Start + 1, "ListenPort = " + port);
            WriteLines(conf, lines);
        }
        // текст конфига клиента
        public static string[] ClientConf(string priv, string ip, string dns, string serverPub, string psk, string endpoint)
        {
            return new[] { "[Interface]", "PrivateKey = " + priv, "Address = " + ip + "/32", "DNS = " + dns, "", "[Peer]", "PublicKey = " + serverPub, "PresharedKey = " + psk, "AllowedIPs = 0.0.0.0/0", "Endpoint = " + endpoint, "PersistentKeepalive = 25" };
        }
        // заменить Endpoint (адрес:порт сервера) и/или DNS в готовом конфиге клиента
        public static bool PatchClient(string file, string endpoint, string dns)
        {
            var lines = ReadLines(file); bool ch = false;
            for (int i = 0; i < lines.Count; i++) {
                if (endpoint != null && Regex.IsMatch(lines[i], @"^\s*Endpoint\s*=", RegexOptions.IgnoreCase) && lines[i].Trim() != "Endpoint = " + endpoint) { lines[i] = "Endpoint = " + endpoint; ch = true; }
                if (dns != null && Regex.IsMatch(lines[i], @"^\s*DNS\s*=", RegexOptions.IgnoreCase) && lines[i].Trim() != "DNS = " + dns) { lines[i] = "DNS = " + dns; ch = true; }
            }
            if (ch) WriteLines(file, lines);
            return ch;
        }
    }
}
