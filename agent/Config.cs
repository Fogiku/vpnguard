// Запись config.json (агент, веб-сервер и PowerShell — под общей блокировкой) и красивый JSON.
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
        // запись в config.json (как веб-сервер: атомарно, с отступами)
        static readonly object CfgWriteLock = new object();
        static void CfgSet(string path, object value)
        {
            lock (CfgWriteLock) {
            // config.json пишут три программы (агент, веб-сервер, PowerShell): «прочитать → изменить → записать» — под общей блокировкой
            using (var mx = new Mutex(false, "Global\\VpnGuardConfig")) {
                bool got = false;
                try { got = mx.WaitOne(10000); } catch (AbandonedMutexException) { got = true; }
                try { CfgWrite(path, value); } finally { if (got) try { mx.ReleaseMutex(); } catch { } }
            }
            }
        }
        static void CfgWrite(string path, object value)
        {
            {
                Dictionary<string, object> o = null;
                try { if (File.Exists(ConfigPath)) o = Json.DeserializeObject(File.ReadAllText(ConfigPath, Encoding.UTF8)) as Dictionary<string, object>; } catch { }
                if (o == null) o = new Dictionary<string, object>();
                var parts = path.Split('.'); var cur = o;
                for (int i = 0; i < parts.Length - 1; i++) {
                    object nx; if (!cur.TryGetValue(parts[i], out nx) || !(nx is Dictionary<string, object>)) { nx = new Dictionary<string, object>(); cur[parts[i]] = nx; }
                    cur = (Dictionary<string, object>)nx;
                }
                cur[parts[parts.Length - 1]] = value;
                string tmp = ConfigPath + "." + Process.GetCurrentProcess().Id + ".tmp";
                File.WriteAllText(tmp, Pretty(Json.Serialize(o)), Bom);
                try { if (File.Exists(ConfigPath)) File.Replace(tmp, ConfigPath, null); else File.Move(tmp, ConfigPath); } catch { File.Copy(tmp, ConfigPath, true); File.Delete(tmp); }
            }
            LoadCfg(true);
        }
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
