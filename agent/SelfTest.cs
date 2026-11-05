// Самопроверка логики агента (VpnGuardAgent.exe <временная папка> --selftest; запускает Test.ps1): сценарии на «поддельных» туннелях,
// без изменений в системе — ни маршрутов, ни служб, ни раздачи. Печатает «OK …» / «FAIL …», код выхода — число неудач.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace VpnGuard
{
    public static partial class Agent
    {
        static bool TestMode;                                 // самопроверка: не трогать систему
        static Func<string, bool> KindOkHook;                 // самопроверка: «проходит ли трафик» через туннель
        static int StFails;
        static void St(bool ok, string what) { Console.WriteLine((ok ? "OK   " : "FAIL ") + what); if (!ok) StFails++; }
        static void StCfg(string json) { File.WriteAllText(ConfigPath, json, Encoding.UTF8); CfgStamp = DateTime.MinValue; LoadCfg(true); }

        static int SelfTest()
        {
            TestMode = true;
            try { Console.SetOut(new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true }); } catch { }
            try {
                // ---- схема настроек: умолчания берутся из config-schema.txt
                File.WriteAllText(Path.Combine(Root, "config-schema.txt"), "{\"settings\":[{\"key\":\"vpn.fastCheckSec\",\"default\":7},{\"key\":\"zapret.maxRoutes\",\"default\":1234}]}", Encoding.UTF8);
                SchemaStamp = DateTime.MinValue; StCfg("{}");
                St(CfgInt("vpn.fastCheckSec", 5) == 7, "схема: умолчание из config-schema.txt важнее запасного значения в коде");
                St(ZI("maxRoutes") == 1234, "схема: умолчания zapret.* — из той же схемы");
                StCfg("{\"vpn\":{\"fastCheckSec\":3}}");
                St(CfgInt("vpn.fastCheckSec", 5) == 3, "схема: значение из config.json важнее умолчания");

                // ---- модули: команды — своему модулю, check-now — всем, чужие — части PowerShell
                var a = AddModule("ta", "Тест А", () => 60000, () => { }, c => { }, "test-a");
                var b = AddModule("tb", "Тест Б", () => 60000, () => { });
                a.TickNow = false; b.TickNow = false;
                File.WriteAllText(Path.Combine(CmdDir, "1.cmd"), "test-a"); File.WriteAllText(Path.Combine(CmdDir, "2.cmd"), "check-now"); File.WriteAllText(Path.Combine(CmdDir, "3.cmd"), "install foo");
                DispatchCommands();
                string c1; St(a.Cmds.TryDequeue(out c1) && c1 == "test-a", "команды: команда модуля попала в его очередь");
                St(a.TickNow && b.TickNow, "команды: «проверить сейчас» будит все модули");
                St(File.Exists(Path.Combine(CmdPsDir, "3.cmd")) && Directory.GetFiles(CmdDir, "*.cmd").Length == 0, "команды: чужая команда передана части PowerShell, очередь пуста");
                St(AgentCommands().Contains("test-a") && AgentCommands().Contains("check-now"), "команды: агент объявляет свои команды (для веб-сервера)");

                // ---- события: подписчик получает событие в своей очереди и будится
                string got = null; b.TickNow = false;
                On("tb", "test.event", x => got = x);
                Emit("test.event", "данные");
                KeyValuePair<string, Action> job; bool hasJob = b.Jobs.TryDequeue(out job); if (hasJob) job.Value();
                St(hasJob && got == "данные" && b.TickNow, "события: подписчик получил событие (в своей очереди) и проверит себя");
                lock (EventLog) St(EventLog.Any(e => e.Name == "test.event" && e.To.Contains("Тест Б")), "события: событие записано в журнал событий с получателями");

                // ---- быстрое переключение (режим «два туннеля»): основной не пропускает трафик, резерв пропускает — переключиться
                var ics = AddModule("ics", "Раздача", () => 60000, () => { }); var fo = AddModule("failover", "Быстрое переключение", () => 60000, () => { });
                Subscribe();
                StCfg("{\"vpn\":{\"mode\":\"dual\",\"primary\":\"meduza\",\"fastFailChecks\":2}}");
                DualActive = "meduza"; DualSwitchAt = DateTime.MinValue; MeduzaStartedAt = DateTime.MinValue; FoFails = 0; ForceIcs = false;
                var ok = new Dictionary<string, bool> { { "meduza", false }, { "amnezia", true } };
                KindOkHook = k => ok[k];
                FailoverTick();
                St(DualAct() == "meduza", "переключение: после одной неудачной проверки трафик ещё на основном");
                FailoverTick();
                St(DualAct() == "amnezia", "переключение: после двух неудачных проверок трафик ушёл на исправный резерв");
                while (ics.Jobs.TryDequeue(out job)) job.Value();
                St(ForceIcs, "переключение: раздача получила событие «туннель переключён» и перенастроится");
                // сразу после переключения — не дёргать обратно
                ok["amnezia"] = false; ok["meduza"] = true; FailoverTick(); FailoverTick();
                St(DualAct() == "amnezia", "переключение: первые 20 с после переключения — без новых переключений");
                // резерв тоже не работает — не переключать «в никуда»
                DualSwitchAt = DateTime.MinValue; ok["meduza"] = false; FoFails = 0;
                FailoverTick(); FailoverTick(); FailoverTick();
                St(DualAct() == "amnezia", "переключение: если и резерв не работает — трафик не перекидывается");
                // не режим «два туннеля» — быстрое переключение молчит
                StCfg("{\"vpn\":{\"mode\":\"meduza\"}}"); ok["amnezia"] = true; DualActive = "meduza"; FoFails = 0;
                FailoverTick(); FailoverTick();
                St(DualAct() == "meduza", "переключение: вне режима «два туннеля» не работает");
                KindOkHook = null;

                // ---- проверка узлов: открытый порт — есть, закрытого — нет
                var lst = new TcpListener(IPAddress.Loopback, 0); lst.Start(); int port = ((IPEndPoint)lst.LocalEndpoint).Port;
                St(Probe("127.0.0.1", new[] { "127.0.0.1:" + port }, 2000).Ok, "проверка узлов: открытый порт отвечает");
                lst.Stop();
                var pr = Probe("127.0.0.1", new[] { "127.0.0.1:" + port, "127.0.0.1:1" }, 1500, true);
                St(!pr.Ok && pr.Total == 2, "проверка узлов: закрытые порты — нет ответа, проверены все");
                St(!Probe(null, new[] { "1.1.1.1:443" }, 1000).Ok, "проверка узлов: без адреса источника — нет");

                // ---- история: сохраняется и восстанавливается (перезапуск агента её не стирает)
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                lock (History) { History.Clear(); History.Add(new Dictionary<string, object> { { "t", now - 60 }, { "u", 0 } }); History.Add(new Dictionary<string, object> { { "t", now - 3 * 3600 }, { "u", 2 } }); }
                lock (LiveH) { LiveT.Clear(); LiveH.Clear(); LiveT.Add(now * 1000); LiveH["r:p"] = new List<long[]> { new long[] { 10, 20 } }; }
                SaveHistory();
                lock (History) History.Clear(); lock (LiveH) { LiveT.Clear(); LiveH.Clear(); }
                LoadHistory();
                St(History.Count == 1, "история: восстановлена, точки старше 2 ч отброшены");
                St(LiveT.Count == 1 && LiveH.ContainsKey("r:p") && LiveH["r:p"][0][1] == 20, "история: живые скорости восстановлены");

                // ---- WireGuard: имена клиентов в форматах WS4W («# 1» над [Peer]) и VpnGuard («# Name =» внутри) — общая библиотека и агент одинаково;
                // переименование и удаление клиента
                var wsrv = Path.Combine(Root, "srv", "server_wg"); Directory.CreateDirectory(wsrv); Directory.CreateDirectory(Path.Combine(Root, "srv", "clients_wg", "c1"));
                var wconf = Path.Combine(wsrv, "wg_server.conf");
                File.WriteAllText(wconf, string.Join("\r\n", new[] { "# wg", "[Interface]", "ListenPort=51820", "Address=192.168.15.1/24", "PrivateKey=AAAA", "", "", "# 1", "[Peer]", "PublicKey=KEY1", "AllowedIPs=192.168.15.4", "", "",
                    "# 2", "[Peer]", "PublicKey=KEY2", "AllowedIPs=192.168.15.5/32", "", "[Peer]", "# Name = телефон", "# VpnGuard: created 2026-11-03 11:53", "PublicKey = KEY4", "AllowedIPs = 192.168.15.10/32", "",
                    "[Peer]", "PublicKey = KEY6", "AllowedIPs = 192.168.15.12/32" }), new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(Root, "srv", "clients_wg", "c1", "планшет.conf"), "[Interface]\r\nPrivateKey = X\r\nAddress = 192.168.15.12/32\r\n[Peer]\r\nPublicKey = Y", Encoding.UTF8);
                Func<string> libNames = () => string.Join(";", WgLib.Read(wconf).Sections.Where(x => x.Type == "Peer").Select(x => x.Keys["PublicKey"] + "=" + WgLib.PeerName(x)));
                St(libNames() == "KEY1=1;KEY2=2;KEY4=телефон;KEY6=", "WireGuard: имена из WS4W и VpnGuard читаются (библиотека)");
                StCfg("{\"ws4w\":{\"configPath\":\"" + wconf.Replace("\\", "\\\\") + "\"}}"); PeerStamp = ""; LoadPeerNames();
                string an; PeerNamesByKey.TryGetValue("KEY1", out an); string an4; PeerNamesByKey.TryGetValue("KEY4", out an4); string anIp; PeerNamesByIp.TryGetValue("192.168.15.12", out anIp);
                St(an == "1" && an4 == "телефон" && anIp == "планшет", "WireGuard: агент видит те же имена (и имя по файлу клиента)");
                WgLib.RenamePeer(wconf, Path.Combine(Root, "bk"), "KEY1", "Мама телефон"); WgLib.RenamePeer(wconf, Path.Combine(Root, "bk"), "KEY4", "ноутбук");
                St(libNames() == "KEY1=Мама телефон;KEY2=2;KEY4=ноутбук;KEY6=", "WireGuard: переименование (и из формата WS4W)");
                WgLib.RemovePeer(wconf, Path.Combine(Root, "bk"), "KEY2");
                var wl = File.ReadAllText(wconf);
                St(libNames() == "KEY1=Мама телефон;KEY4=ноутбук;KEY6=" && wl.Contains("PrivateKey=AAAA") && !wl.Contains("KEY2") && !wl.Contains("# 2"), "WireGuard: удаление клиента не задевает сервер и соседей");

                // ---- самообновление: из манифеста принимаются только файлы приложения
                St(AppPathOk("agent/Core.cs") && AppPathOk("web/index.html") && AppPathOk("VpnGuard.ps1") && AppPathOk("config-schema.txt"), "обновление: файлы приложения принимаются");
                St(!AppPathOk("../x.ps1") && !AppPathOk("config.json") && !AppPathOk("data/x.ps1") && !AppPathOk("bin/VpnGuardAgent.exe") && !AppPathOk("C:/x.ps1") && !AppPathOk("x.exe"), "обновление: опасные пути и чужие файлы отброшены");

                // ---- самообновление: пробная сборка нового кода — с ошибкой не проходит, правильный проходит
                if (CscPath().Length > 0) {
                    var stage = Path.Combine(Root, "stage"); Directory.CreateDirectory(Path.Combine(stage, "agent"));
                    File.WriteAllText(Path.Combine(stage, "agent", "Good.cs"), "static class P { static void Main() { } }");
                    St(AppTryBuild(stage, "t1", new[] { Path.Combine("agent", "Good.cs") }, "exe", new string[0]) == null, "обновление: правильный новый код собирается");
                    File.WriteAllText(Path.Combine(stage, "agent", "Bad.cs"), "static class P { static void Main() { int x = ; } }");
                    var be = AppTryBuild(stage, "t2", new[] { Path.Combine("agent", "Bad.cs") }, "exe", new string[0]);
                    St(be != null && be.Contains("error"), "обновление: новый код с ошибкой не проходит пробную сборку");
                }

                // ---- подпись установщиков (компоненты, MeduzaVPN): неподписанный файл — «не подписан»; подписанный — с верным издателем
                var unsigned = Path.Combine(Root, "unsigned.exe"); File.WriteAllBytes(unsigned, new byte[] { 0x4D, 0x5A, 0, 0 });
                St(SignStatus(unsigned) != "Valid" && !SignedBy(unsigned, "WireGuard LLC"), "подпись: неподписанный файл не проходит проверку");
                var wgx = @"C:\Program Files\WireGuard\wireguard.exe";
                if (File.Exists(wgx)) {
                    St(SignStatus(wgx) == "Valid" && SignedBy(wgx, "WireGuard LLC"), "подпись: wireguard.exe подписан «WireGuard LLC»");
                    St(!SignedBy(wgx, "IPFB LLC"), "подпись: чужой издатель не принимается");
                }
            } catch (Exception e) { St(false, "самопроверка упала: " + e); }
            Console.WriteLine(StFails == 0 ? "ВСЁ OK" : "НЕУДАЧ: " + StFails);
            return StFails;
        }
    }
}
