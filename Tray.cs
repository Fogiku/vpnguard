// VpnGuard — значок у часов (вместо окна): цвет — общее состояние, двойной щелчок — веб-интерфейс, меню — основные действия.
// Собирается агентом встроенным компилятором .NET Framework (C# 5):
//   csc /target:winexe /out:bin\VpnGuardTray.exe /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Web.Extensions.dll Tray.cs
// Запуск: VpnGuardTray.exe <папка VpnGuard>. Запускается задачей VpnGuardMonitor (ярлык VpnGuard на рабочем столе).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace VpnGuard
{
    public class Tray : ApplicationContext
    {
        [DllImport("user32.dll")] static extern bool DestroyIcon(IntPtr h);

        readonly string Root, DataDir, StatusPath, ConfigPath, CmdDir;
        readonly NotifyIcon icon = new NotifyIcon();
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
        readonly Dictionary<int, Icon> icons = new Dictionary<int, Icon>();
        ToolStripMenuItem miState, miZapret;
        int lastWorst = -2; DateTime stamp = DateTime.MinValue; bool zapretOn;
        static readonly string[][] Comps = { new[] { "ultra", "Туннель" }, new[] { "meduza", "MeduzaVPN" }, new[] { "amnezia", "AmneziaWG" }, new[] { "wg", "WireGuard" }, new[] { "ics", "Раздача" }, new[] { "zapret", "zapret" } };

        [STAThread]
        public static void Main(string[] args)
        {
            string root = args.Length > 0 ? args[0].TrimEnd('\\') : AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            if (!File.Exists(Path.Combine(root, "VpnGuard.ps1")) && File.Exists(Path.Combine(root, "..", "VpnGuard.ps1"))) root = Path.GetFullPath(Path.Combine(root, ".."));
            bool created;
            using (var m = new Mutex(true, "Local\\VpnGuardTray", out created)) {
                if (!created) { OpenWeb(root); return; }      // уже запущен — просто открыть веб-интерфейс
                Application.EnableVisualStyles();
                Application.Run(new Tray(root));
            }
        }

        Tray(string root)
        {
            Root = root; DataDir = Path.Combine(root, "data"); StatusPath = Path.Combine(DataDir, "status.json");
            ConfigPath = Path.Combine(root, "config.json"); CmdDir = Path.Combine(DataDir, "cmd");
            var menu = new ContextMenuStrip();
            miState = new ToolStripMenuItem("VpnGuard: нет данных") { Enabled = false };
            var open = new ToolStripMenuItem("Открыть VpnGuard", null, (s, e) => OpenWeb(Root)); open.Font = new Font(open.Font, FontStyle.Bold);
            miZapret = new ToolStripMenuItem("Включить zapret", null, (s, e) => Cmd(zapretOn ? "zapret-off" : "zapret-on"));
            menu.Items.AddRange(new ToolStripItem[] {
                miState, new ToolStripSeparator(), open,
                new ToolStripMenuItem("Проверить сейчас", null, (s, e) => Cmd("check-now")),
                new ToolStripMenuItem("Переподключить туннель", null, (s, e) => Cmd("reconnect")),
                new ToolStripMenuItem("Восстановить раздачу", null, (s, e) => Cmd("reapply-ics")),
                miZapret,
                new ToolStripSeparator(),
                new ToolStripMenuItem("Перезапустить агент", null, (s, e) => RestartAgent()),
                new ToolStripMenuItem("Классическое окно", null, (s, e) => Run("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + Path.Combine(Root, "VpnGuardMonitor.ps1") + "\"")),
                new ToolStripMenuItem("Папка VpnGuard", null, (s, e) => Run("explorer.exe", "\"" + Root + "\"")),
                new ToolStripSeparator(),
                new ToolStripMenuItem("Скрыть значок", null, (s, e) => { icon.Visible = false; ExitThread(); }) });
            icon.ContextMenuStrip = menu;
            icon.DoubleClick += (s, e) => OpenWeb(Root);
            icon.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) OpenWeb(Root); };
            icon.BalloonTipClicked += (s, e) => OpenWeb(Root);
            icon.Icon = MakeIcon(-1); icon.Text = "VpnGuard — нет данных"; icon.Visible = true;
            timer.Interval = 3000; timer.Tick += (s, e) => Refresh(); timer.Start();
            Refresh();
        }

        static int WebPort(string root)
        {
            try {
                var c = new JavaScriptSerializer().DeserializeObject(File.ReadAllText(Path.Combine(root, "config.json"), Encoding.UTF8)) as Dictionary<string, object>;
                object w; if (c != null && c.TryGetValue("web", out w) && w is Dictionary<string, object>) { object p; if (((Dictionary<string, object>)w).TryGetValue("port", out p)) return Convert.ToInt32(p); }
            } catch { }
            return 8765;
        }
        static void OpenWeb(string root) { try { Process.Start("http://localhost:" + WebPort(root) + "/"); } catch { } }
        static void Run(string exe, string args) { try { Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = true }); } catch (Exception e) { MessageBox.Show(e.Message, "VpnGuard"); } }
        void Cmd(string c)
        {
            try { Directory.CreateDirectory(CmdDir); File.WriteAllText(Path.Combine(CmdDir, DateTime.UtcNow.Ticks + ".cmd"), c, Encoding.ASCII); icon.ShowBalloonTip(2500, "VpnGuard", "Отправлено агенту: " + c, ToolTipIcon.None); }
            catch (Exception e) { MessageBox.Show("Не удалось отправить команду: " + e.Message, "VpnGuard"); }
        }
        void RestartAgent()
        {
            var p = Process.Start(new ProcessStartInfo("schtasks.exe", "/end /tn VpnGuard") { CreateNoWindow = true, UseShellExecute = false }); p.WaitForExit(15000);
            Thread.Sleep(1500);
            Process.Start(new ProcessStartInfo("schtasks.exe", "/run /tn VpnGuard") { CreateNoWindow = true, UseShellExecute = false });
            icon.ShowBalloonTip(2500, "VpnGuard", "Агент перезапускается", ToolTipIcon.None);
        }

        Icon MakeIcon(int level)
        {
            Icon ic; if (icons.TryGetValue(level, out ic)) return ic;
            Color c = level == 0 ? Color.FromArgb(63, 185, 80) : level == 1 ? Color.FromArgb(210, 153, 34) : level == 2 ? Color.FromArgb(248, 81, 73) : Color.FromArgb(120, 126, 136);
            using (var bmp = new Bitmap(32, 32))
            using (var g = Graphics.FromImage(bmp)) {
                g.SmoothingMode = SmoothingMode.AntiAlias; g.Clear(Color.Transparent);
                using (var shield = new GraphicsPath()) {
                    shield.AddPolygon(new[] { new PointF(16, 1), new PointF(29, 6), new PointF(28, 18), new PointF(16, 31), new PointF(4, 18), new PointF(3, 6) });
                    using (var b = new SolidBrush(c)) g.FillPath(b, shield);
                    using (var pen = new Pen(Color.FromArgb(200, 20, 22, 27), 1.5f)) g.DrawPath(pen, shield);
                }
                using (var pen = new Pen(Color.White, 3.2f) { StartCap = LineCap.Round, EndCap = LineCap.Round }) {
                    if (level == 2) { g.DrawLine(pen, 11, 11, 21, 21); g.DrawLine(pen, 21, 11, 11, 21); }
                    else if (level == 1) { g.DrawLine(pen, 16, 9, 16, 18); g.FillEllipse(Brushes.White, 14.2f, 21, 3.6f, 3.6f); }
                    else if (level == 0) { g.DrawLines(pen, new[] { new PointF(10, 16), new PointF(14.5f, 21), new PointF(22, 11) }); }
                }
                IntPtr h = bmp.GetHicon(); ic = (Icon)Icon.FromHandle(h).Clone(); DestroyIcon(h);
            }
            icons[level] = ic; return ic;
        }

        void Refresh()
        {
            Dictionary<string, object> s = null;
            try {
                if (!File.Exists(StatusPath)) { Show(-1, "нет данных от агента", new List<string>()); return; }
                var st = File.GetLastWriteTimeUtc(StatusPath);
                if (st == stamp && lastWorst != -2 && (DateTime.UtcNow - st).TotalSeconds < 200) return;
                stamp = st;
                string txt; using (var fs = new FileStream(StatusPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) using (var rd = new StreamReader(fs, Encoding.UTF8)) txt = rd.ReadToEnd();
                s = json.DeserializeObject(txt) as Dictionary<string, object>;
            } catch { return; }
            if (s == null) return;
            double age = 1e9; object up; DateTime ut;
            if (s.TryGetValue("updated", out up) && DateTime.TryParse(Convert.ToString(up), null, System.Globalization.DateTimeStyles.RoundtripKind, out ut)) age = (DateTime.Now - ut.ToLocalTime()).TotalSeconds;
            int stale = 150; object sa; if (s.TryGetValue("staleAfterSec", out sa)) int.TryParse(Convert.ToString(sa), out stale);
            if (age > stale) { Show(-1, "агент не отвечает (данные устарели)", new List<string>()); return; }
            int worst = -1; var probs = new List<string>();
            foreach (var c in Comps) {
                object o; if (!s.TryGetValue(c[0], out o)) continue; var d = o as Dictionary<string, object>; if (d == null) continue;
                int lv; object l; if (!d.TryGetValue("level", out l) || !int.TryParse(Convert.ToString(l), out lv)) continue;
                if (lv > worst) worst = lv;
                object stt; d.TryGetValue("state", out stt);
                if (lv >= 1) probs.Add(c[1] + ": " + stt);
                if (c[0] == "zapret") { object en; zapretOn = d.TryGetValue("enabled", out en) && en is bool && (bool)en; }
            }
            object vpn; string mode = ""; if (s.TryGetValue("vpn", out vpn) && vpn is Dictionary<string, object>) { object m; if (((Dictionary<string, object>)vpn).TryGetValue("mode", out m)) mode = Convert.ToString(m); }
            miZapret.Text = zapretOn ? "Выключить zapret" : "Включить zapret"; miZapret.Visible = mode != "zapret";
            Show(worst, worst == 0 ? "всё работает" : worst == 1 ? "есть предупреждения" : worst == 2 ? "есть сбои" : "нет данных", probs);
        }

        void Show(int worst, string summary, List<string> probs)
        {
            icon.Icon = MakeIcon(worst);
            string tip = "VpnGuard — " + summary + (probs.Count > 0 ? "\n" + string.Join("\n", probs) : "");
            icon.Text = tip.Length > 63 ? tip.Substring(0, 62) + "…" : tip;       // ограничение Windows — 63 символа
            miState.Text = "VpnGuard: " + summary + (probs.Count > 0 ? " — " + probs[0] : "");
            if (lastWorst >= 0 && worst == 2 && lastWorst < 2) icon.ShowBalloonTip(8000, "VpnGuard: сбой", string.Join("\n", probs.DefaultIfEmpty("есть сбои")), ToolTipIcon.Error);
            else if (lastWorst == 2 && worst == 0) icon.ShowBalloonTip(4000, "VpnGuard", "Снова всё работает", ToolTipIcon.Info);
            lastWorst = worst;
        }

        protected override void ExitThreadCore() { timer.Stop(); icon.Visible = false; icon.Dispose(); base.ExitThreadCore(); }
    }
}
