// Сводка состояния для окна, веб-интерфейса и значка (status.json).
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
        // ---------------------------------------------------------------- состояние для окна, веб-интерфейса и значка
        static object[] Kv(string k, object v) { return new object[] { k, v == null ? "—" : Convert.ToString(v) }; }
        static Dictionary<string, object> Comp(int level, string state, IEnumerable<string> details, List<object[]> kv)
        {
            return new Dictionary<string, object> { { "level", level }, { "state", state }, { "details", details.Where(d => !string.IsNullOrEmpty(d)).ToArray() }, { "kv", kv.Where(x => x != null).ToArray() } };
        }
        static Dictionary<string, object> ReadPsStatus()
        {
            try { using (var fs = new FileStream(PsStatusPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) using (var rd = new StreamReader(fs, Encoding.UTF8)) return Json.DeserializeObject(rd.ReadToEnd()) as Dictionary<string, object>; }
            catch { return null; }
        }
        static readonly object SnapLock = new object(); static string SnapErr = "";
        static void Snapshot()
        {
            lock (SnapLock) {
                LastSnapshot = DateTime.Now;
                try { SnapshotCore(); SnapErr = ""; }
                catch (Exception e) { if (e.Message != SnapErr) Log("Агент C#: состояние: " + e.Message, "ERROR"); SnapErr = e.Message; }      // одна и та же ошибка — в журнал один раз
            }
        }
        static void SnapshotCore()
        {
            string mode = Mode(); var proc = MzProc(); bool pipe = MzPipe(); string ver = MzVersion();
            var avNic = AvpnNic(); string kind = TunnelKind(); string tun = mode == "zapret" ? "" : KindAdapter(kind);
            var ma = Nic(tun); var wa = Nic(WgIf()); var wgSvc = Svc(CfgStr("ws4w.serviceName", "WireGuardTunnel$wg_server"));
            bool uUp = ma != null && ma.OperationalStatus == OperationalStatus.Up, wUp = wgSvc != null && wgSvc.Status == ServiceControllerStatus.Running && wa != null && wa.OperationalStatus == OperationalStatus.Up;
            if (uUp) { if (UltraUpSince == DateTime.MinValue) UltraUpSince = DateTime.Now; } else UltraUpSince = DateTime.MinValue;
            if (wUp) { if (WgUpSince == DateTime.MinValue) WgUpSince = DateTime.Now; } else WgUpSince = DateTime.MinValue;
            var adNames = UpdateTraffic();
            string uIp = ma != null ? Ipv4(tun) : null, wIp = wa != null ? Ipv4(WgIf()) : null;
            var ps = ReadPsStatus() ?? new Dictionary<string, object>();
            bool updating = MzUpdating();

            // MeduzaVPN
            int mL; string mS; bool responding = true; try { if (proc != null) responding = proc.Responding; } catch { }
            if (updating) { mL = 1; mS = "Обновляется"; } else if (proc == null) { mL = 2; mS = "Не запущен"; } else if (!responding) { mL = 1; mS = "Не отвечает"; } else { mL = 0; mS = "Работает"; }
            if (mode != "meduza" && mode != "dual" && !updating) { mL = -1; mS = proc != null ? "Не используется (запущен)" : "Не используется"; }
            else if (mode == "dual" && mL == 0) {
                if (!Up(MzAdapterName())) { mL = 1; mS = "Туннель не подключён"; } else if (LastTraffic == false) { mL = 1; mS = "Нет трафика"; } else mS = kind == "meduza" ? "Работает · активный" : "Работает · резерв";
            }
            string remoteVer = ps.ContainsKey("meduzaRemoteVersion") ? Convert.ToString(ps["meduzaRemoteVersion"]) : "";
            string started = ""; try { if (proc != null) started = proc.StartTime.ToString("dd.MM HH:mm"); } catch { }
            var meduza = Comp(mL, mS, new[] { "Версия " + ver + (remoteVer.Length > 0 && remoteVer != ver ? " (есть " + remoteVer + ")" : ""), proc != null ? "PID " + proc.Id + (started.Length > 0 ? ", с " + started : "") : "процесс отсутствует",
                "Канал CLI: " + (pipe ? "доступен" : "нет") + " · протокол " + MzProtocol() + (MzOverride.Length > 0 ? " (запасной вместо " + CfgStr("meduza.protocol", "ultra") + ")" : ""),
                "Перезапуски: " + Restarts.ToArray().Count(d => d > DateTime.Now.AddMinutes(-30)) + " за 30 мин, посл. " + When(LastRestart) }, new List<object[]> {
                Kv("Версия", ver), Kv("Доступная версия", remoteVer.Length > 0 ? remoteVer : "—"), Kv("Последняя проверка обновлений", ps.ContainsKey("meduzaLastCheck") ? ps["meduzaLastCheck"] : "—"),
                Kv("Процесс", proc != null ? "PID " + proc.Id + (responding ? "" : " (не отвечает)") : "не запущен"), Kv("Память", proc != null ? (proc.WorkingSet64 / 1048576) + " МБ" : "—"),
                Kv("Канал CLI", pipe ? "доступен" : "нет — включите управление из командной строки"),
                Kv("VPN (страна)", CfgStr("meduza.serviceId", "").Length > 0 ? CfgStr("meduza.serviceId", "") : "по умолчанию (единственный на аккаунте)"),
                Kv("Протокол", MzProtocol() + (MzOverride.Length > 0 ? " — запасной, выбранный " + CfgStr("meduza.protocol", "ultra") + " не работал (с " + When(MzProtoSince) + ")" : "") + " · адаптер «" + MzAdapterName() + "»"),
                Kv("Автоподбор протокола", CfgBool("meduza.autoProtocol", true) ? "включён — при потере связи пробует другие протоколы" : "выключен"),
                Kv("Перезапусков за 30 мин", Restarts.ToArray().Count(d => d > DateTime.Now.AddMinutes(-30)) + " из " + CfgInt("meduza.maxRestartsPer30Min", 5) + " допустимых"),
                Kv("Перезапусков с запуска агента", RestartCount), Kv("Последний перезапуск", When(LastRestart)), Kv("Причина", LastRestartReason.Length > 0 ? LastRestartReason : "—") });
            meduza["serviceId"] = CfgStr("meduza.serviceId", ""); meduza["protocol"] = CfgStr("meduza.protocol", "ultra"); meduza["adapter"] = MzAdapterName();
            meduza["catalog"] = Catalog; meduza["protoTest"] = ProtoTest; meduza["protocolNow"] = MzProtocol(); meduza["protocolOverride"] = MzOverride;

            // Туннель
            bool amz = kind == "amnezia"; bool? tTr = amz ? AwgTraffic : LastTraffic; DateTime tTrAt = amz ? AwgTrafficAt : LastTrafficAt; int tFail = amz ? AwgProbeFailures : ProbeFailures; string tWhy = amz ? AwgLastReason : LastRestartReason;
            int uL; string uS;
            if (mode == "zapret") { uL = 0; uS = "VPN выключен — напрямую"; } else if (amz && tun.Length == 0) { uL = 2; uS = "AmneziaVPN не подключён"; } else if (!uUp) { uL = 2; uS = "Отключён"; } else if (tTr == false) { uL = 1; uS = "Нет трафика"; } else { uL = 0; uS = "Подключён"; }
            if (InetDown() && mode != "zapret") { uL = 2; uS = "Нет интернета — жду связь"; }
            string kindTitle = amz ? "AmneziaVPN" : "MeduzaVPN · " + MzProtocol();
            string trTxt = (tTr == true ? "OK" : tTr == false ? "НЕТ" : "—");
            Dictionary<string, object> sb = null;
            if (mode == "dual") {
                string oth = OtherKind(kind); bool othUp = Up(KindAdapter(oth)); bool? othTr = KindTraffic(oth);
                sb = new Dictionary<string, object> { { "kind", oth }, { "name", ModeNames[oth] }, { "up", othUp }, { "ok", othUp && othTr == true },
                    { "state", !othUp ? "не подключён" : othTr == true ? "готов" : othTr == false ? "нет трафика" : "проверяется" },
                    { "blocked", oth == "amnezia" && AvpnBlocked() }, { "server", oth == "amnezia" ? AvpnEp : "" }, { "why", oth == "amnezia" && AwgDiag != null && !AwgDiag.Ok ? AwgDiag.Short : "" } };
                if (oth == "amnezia" && AvpnBlocked()) sb["state"] = "отключён защитой до " + AgBlockedUntil.ToString("HH:mm");
                if (uL == 0) uS = othUp && othTr == true ? "Подключён · резерв готов" : "Подключён · резерв не готов";
            }
            var dualKv = mode != "dual" ? new List<object[]>() : new List<object[]> {
                Kv("Трафик идёт через", ModeNames[kind] + (kind == DualPrimary() ? " (основной)" : " (резервный)")),
                Kv("Переключений", DualSwitches + (DualSwitches > 0 ? " · последнее " + When(DualSwitchAt) + ": " + DualReason : "")),
                Kv("Резерв", (CfgBool("vpn.dualHot", true) ? "горячий — оба туннеля подняты" : "холодный — поднимается при сбое") + (CfgInt("vpn.failbackMin", 5) > 0 ? ", возврат на основной через " + CfgInt("vpn.failbackMin", 5) + " мин" : "")) };
            var ultra = Comp(uL, uS, new[] { mode == "zapret" ? "Выход: " + PhysAlias() + " · YouTube/Discord — через zapret" : "",
                sb != null ? "Резерв: " + sb["name"] + " — " + sb["state"] + " · переключений: " + DualSwitches : "",
                "Адаптер: " + (ma != null ? tun + " · " + ma.OperationalStatus + ", IP " + uIp : mode == "zapret" ? "не нужен" : "отсутствует"),
                "Трафик: " + trTxt + ", проверка " + When(tTrAt), "Сбоев проверки подряд: " + tFail, tWhy.Length > 0 ? "Последняя причина: " + tWhy : "" }, new List<object[]> {
                Kv("Режим", ModeNames[mode]), dualKv.Count > 0 ? dualKv[0] : null, dualKv.Count > 1 ? dualKv[1] : null, dualKv.Count > 2 ? dualKv[2] : null, Kv("Адаптер", ma != null ? tun + " · " + ma.OperationalStatus + " · " + ma.Description : "отсутствует"), Kv("IP", uIp ?? "—"),
                Kv("Скорость канала", ma != null ? (ma.Speed / 1000000) + " Мбит/с" : "—"), Kv("Подключён с", UltraUpSince == DateTime.MinValue ? "—" : When(UltraUpSince)),
                Kv("Протокол", kind == "meduza" ? MzProtocol() : amz ? "выбран в AmneziaVPN" : "—"), Kv("Проверка трафика", trTxt + " · " + When(tTrAt)), Kv("Узлы проверки", string.Join(", ", ProbeHosts())),
                Kv("Сбоев проверки подряд", tFail + " (переподключение после " + CfgInt("meduza.probeFailuresBeforeReconnect", 3) + ")"), Kv("Переподключений с запуска агента", ReconnectCount) });
            ultra["title"] = mode == "zapret" ? "Без VPN (только zapret)" : "Туннель: " + kindTitle; ultra["kind"] = kind; ultra["standby"] = sb; ultra["switches"] = DualSwitches;

            // интернет вообще (InetLoop)
            int nL = InetState == 0 ? 0 : InetState == 1 ? 2 : -1;
            string nS = InetState == 0 ? "Есть" + (InetMs > 0 ? " · " + InetMs + " мс" : "") : InetState == 1 ? "Нет · " + Dur(DateTime.Now - InetSince) : InetFails > 0 ? "Проверяется" : "Нет данных";
            string lastDown = InetDowns == 0 ? "не пропадал" : When(InetLastDown) + (InetState == 1 ? " — сейчас" : " на " + Dur(InetLastLen));
            var inet = Comp(nL, nS, new[] { InetState == 1 ? InetWhy : "Напрямую через " + (InetVia.Length > 0 ? InetVia : "—") + (InetGw.Length > 0 ? " · роутер " + InetGw : ""),
                "Пропадал: " + InetDowns + " раз с запуска агента" + (InetDowns > 0 ? ", последний " + lastDown : "") }, new List<object[]> {
                Kv("Состояние", nS), Kv("Причина", InetState == 1 ? InetWhy : "—"), Kv("Физический адаптер", InetVia.Length > 0 ? InetVia : "нет"), Kv("Роутер (шлюз)", InetGw.Length > 0 ? InetGw : "—"),
                Kv("Узлы проверки", string.Join(", ", InetHosts()) + " — напрямую, мимо VPN, раз в 5 с"), Kv("Пропадал с запуска агента", InetDowns + " раз"), Kv("Последний раз", lastDown),
                Kv("Пока интернета нет", "VPN не переподключается и не перезапускается, zapret не переподбирается") });
            inet["since"] = InetSince == DateTime.MinValue ? "" : InetSince.ToString("o"); inet["downs"] = InetDowns;

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
            wg["clientZapret"] = CzSnapshot();

            // ICS
            IcsState ics = IcsLast != null && (DateTime.UtcNow - IcsLastAt).TotalSeconds < 45 ? IcsLast : null; if (ics == null) try { ics = IcsStatus(); } catch { }
            var icsSvc = Svc("SharedAccess"); int iL; string iS;
            if (!CfgBool("sharing.enabled", true)) { iL = 1; iS = "Отключено в config"; } else if (ics == null) { iL = 1; iS = "Нет данных"; } else if (ics.Ok) { iL = 0; iS = "Включена"; } else if ((!uUp && mode != "zapret") || !wUp) { iL = 1; iS = "Ждёт адаптеры"; } else { iL = 2; iS = "Не настроена"; }
            Func<IcsConn, int, string> fi = (c, want) => c == null ? "не найдено" : !c.Enabled ? c.Name + ": общий доступ выключен" : c.Type != want ? c.Name + ": НЕВЕРНАЯ роль" : c.Name + ": OK";
            string upN = UplinkName();
            var icsOther = ics != null ? ics.All.Where(c => c.Enabled && c.Name != upN && c.Name != WgIf()).Select(c => c.Name).ToList() : new List<string>();
            var icsC = Comp(iL, iS, new[] { upN + " → " + WgIf(), "Служба ICS: " + (icsSvc != null ? icsSvc.Status.ToString() : "нет"), "Восстановлена: " + When(LastIcsFix) }, new List<object[]> {
                Kv("Схема", upN + " (публичный) → " + WgIf() + " (домашняя сеть)"), Kv("Управление раздачей", CfgBool("sharing.enabled", true) ? "включено" : "выключено в настройках"),
                Kv("Служба ICS (SharedAccess)", icsSvc != null ? icsSvc.Status + " / " + StartMode("SharedAccess") : "нет"), Kv("Публичное подключение", ics != null ? fi(ics.Pub, 0) : "—"),
                Kv("Частное подключение", ics != null ? fi(ics.Priv, 1) : "—"), Kv("Лишние подключения с ICS", icsOther.Count > 0 ? string.Join(", ", icsOther) : "нет"),
                Kv("Восстановлена", When(LastIcsFix)), Kv("Восстановлений с запуска агента", IcsFixCount) });

            // AmneziaVPN
            bool used = mode == "amnezia" || mode == "dual"; string avExe = AwgExe(); bool inst = File.Exists(avExe);
            var avProc = AvpnProc(); var avSvc = Svc(AvpnSvcName()); bool aUp = avNic != null && avNic.OperationalStatus == OperationalStatus.Up;
            string aIp = aUp ? Ipv4(avNic.Name) : null;
            int aL; string aS;
            if (!used) { aL = -1; aS = aUp ? "Не используется (туннель поднят)" : avProc != null ? "Не используется (запущен)" : "Не используется"; }
            else if (!inst) { aL = 2; aS = "Не установлен"; } else if (avProc == null) { aL = 2; aS = "Не запущен"; } else if (!aUp) { aL = 1; aS = "Туннель не подключён"; }
            else if (AwgTraffic == false) { aL = 1; aS = "Нет трафика"; } else { aL = 0; aS = "Подключён"; }
            if (used && AvpnBlocked()) { aL = 2; aS = "Отключён защитой до " + AgBlockedUntil.ToString("HH:mm") + " — отрезал локальную сеть"; }
            string agTxt = !CfgBool("amnezia.lanGuard", true) ? "Защита локальной сети: выключена" : AvpnBlocked() ? "Защита: отключён до " + AgBlockedUntil.ToString("HH:mm") + " — " + AgTripWhy + ". Выключите в AmneziaVPN Kill Switch"
                : AgTrips > 0 ? "Защита: срабатывала " + When(AgTripAt) + " (" + AgTripWhy + ")" : "Защита локальной сети: включена, срабатываний не было";
            string aVer = ""; try { if (inst) aVer = Cached("fv:" + avExe, 300, () => FileVersionInfo.GetVersionInfo(avExe).ProductVersion); } catch { }
            string aTr = AwgTraffic == true ? "OK" : AwgTraffic == false ? "НЕТ" : "—";
            long avMem = 0; try { if (avProc != null) avMem = avProc.WorkingSet64 / 1048576; } catch { }
            var awg = Comp(aL, aS, new[] { inst ? "AmneziaVPN " + aVer + " · " + (avProc != null ? "PID " + avProc.Id : "не запущен") : "AmneziaVPN не установлен",
                "Туннель: " + (aUp ? avNic.Name + " · IP " + aIp : avNic != null ? avNic.Name + " — " + avNic.OperationalStatus : "не подключён"),
                "Трафик: " + aTr + ", проверка " + When(AwgTrafficAt) + (AwgDiag != null && !AwgDiag.Ok ? " — " + AwgDiag.Short : ""), "Перезапуски: " + AwgRestarts.ToArray().Count(d => d > DateTime.Now.AddMinutes(-30)) + " за 30 мин, посл. " + When(AwgLastRestart), agTxt }, new List<object[]> {
                Kv("Диагностика туннеля", AwgDiag == null ? "ещё не было" : AwgDiag.At.ToString("HH:mm:ss") + " — " + AwgDiag.Text),
                Kv("Защита локальной сети", agTxt + (AgBaseAt != DateTime.MinValue ? " · без AmneziaVPN: роутер " + (AgGwBase ? "отвечал" : "не отвечал") + ", клиентов WG на связи " + Math.Max(0, AgPeersBase) : "")),
                Kv("Приложение AmneziaVPN", inst ? "установлено · версия " + aVer : "не установлено (" + avExe + ")"),
                Kv("Процесс", avProc != null ? "PID " + avProc.Id + " · " + avMem + " МБ" : "не запущен"),
                Kv("Служба", avSvc != null ? avSvc.ServiceName + " · " + avSvc.Status + " / " + StartMode(avSvc.ServiceName) : "не найдена"),
                Kv("Используется", mode == "dual" ? (kind == "amnezia" ? "да — активный из двух туннелей" : "да — резерв из двух туннелей") : used ? "да — режим AmneziaVPN" : "нет (другой режим)"),
                Kv("Адаптер туннеля", avNic != null ? avNic.Name + " · " + avNic.Description + " · " + avNic.OperationalStatus : "не найден (туннель не подключён)"), Kv("IP", aIp ?? "—"),
                Kv("Проверка трафика", aTr + " · " + When(AwgTrafficAt)), Kv("Сбоев проверки подряд", AwgProbeFailures + " (перезапуск после " + CfgInt("meduza.probeFailuresBeforeReconnect", 3) + ")"),
                Kv("Перезапусков за 30 мин", AwgRestarts.ToArray().Count(d => d > DateTime.Now.AddMinutes(-30)) + " из " + CfgInt("meduza.maxRestartsPer30Min", 5) + " допустимых"),
                Kv("Последний перезапуск", When(AwgLastRestart)), Kv("Причина", AwgLastReason.Length > 0 ? AwgLastReason : "—"),
                Kv("Сервер и протокол", "выбираются в приложении AmneziaVPN; там же включите «Автоподключение»") });
            awg["installed"] = inst; awg["running"] = avProc != null; awg["active"] = avNic != null ? avNic.Name : ""; awg["adapter"] = avNic != null ? avNic.Name : "";
            awg["configs"] = new object[0]; awg["test"] = null;

            // zapret — свой (Zapret.cs); компоненты, обновления, веб — из части PowerShell
            object zapret;
            try { zapret = ZSnapshot(); } catch (Exception e) { zapret = new Dictionary<string, object> { { "level", 2 }, { "state", "Ошибка" }, { "details", new[] { e.Message } }, { "kv", new object[0] }, { "enabled", CfgBool("zapret.enabled", false) } }; }
            int zL = -1, zc = 0; var zd = zapret as Dictionary<string, object>; if (zd != null) { int.TryParse(Convert.ToString(zd.ContainsKey("level") ? zd["level"] : -1), out zL); if (zd.ContainsKey("conns")) int.TryParse(Convert.ToString(zd["conns"]), out zc); }

            // история (точка не чаще интервала проверки)
            long nowTs = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); long lastTs = History.Count > 0 ? Convert.ToInt64(History[History.Count - 1]["t"]) : 0;
            if (nowTs - lastTs >= Math.Max(10, CfgInt("checkIntervalSec", 30) - 2)) {
                History.Add(new Dictionary<string, object> { { "t", nowTs }, { "n", nL }, { "m", mL }, { "u", uL }, { "w", wL }, { "i", iL }, { "z", zL }, { "a", aL },
                    { "tr", new[] { TrafPending["u"][0], TrafPending["u"][1], TrafPending["w"][0], TrafPending["w"][1], TrafPending["p"][0], TrafPending["p"][1] } }, { "zc", zc } });
                TrafPending = NewTraf();
                while (History.Count > 240) History.RemoveAt(0);
            }
            string act2 = Activity;          // своё действие важнее; иначе — что делает часть PowerShell (обновление, zapret)
            if (act2.Length == 0 && ps.ContainsKey("activity") && PsPart != null && !PsPart.HasExited) act2 = Convert.ToString(ps["activity"]);
            bool busy = act2.Length > 0;
            var snap = new Dictionary<string, object> {
                { "updated", DateTime.Now.ToString("o") }, { "staleAfterSec", updating ? 1800 : busy ? 900 : CfgInt("checkIntervalSec", 30) + 120 }, { "activity", act2 },
                { "activitySince", busy ? ActivitySince.ToString("o") : "" }, { "agentStarted", StartedAt.ToString("o") }, { "agentPid", Process.GetCurrentProcess().Id },
                { "agentVersion", Version + " C#" }, { "engine", "csharp" }, { "intervalSec", CfgInt("checkIntervalSec", 30) }, { "lastUpdateCheck", ps.ContainsKey("meduzaLastCheck") ? ps["meduzaLastCheck"] : "" },
                { "inet", inet }, { "meduza", meduza }, { "ultra", ultra }, { "wg", wg }, { "ics", icsC }, { "zapret", zapret },
                { "perf", PerfInfo() }, { "modules", ModulesInfo() }, { "events", EventsInfo() }, { "traffic", new Dictionary<string, object> { { "names", adNames }, { "rate", TrafRate }, { "lan", new Dictionary<string, object> { { "on", LanH != WdInvalid }, { "net", LanNet }, { "error", LanError } } }, { "days", TrafDays.Reverse().Take(14).Reverse().Select(kv => (object)new Dictionary<string, object> { { "d", kv.Key }, { "u", kv.Value["u"] }, { "w", kv.Value["w"] }, { "p", kv.Value["p"] } }).ToArray() } } },
                { "counters", new Dictionary<string, object> { { "restarts", RestartCount }, { "reconnects", ReconnectCount }, { "icsFixes", IcsFixCount } } },
                { "vpn", new Dictionary<string, object> { { "mode", mode }, { "name", ModeNames[mode] }, { "uplink", upN }, { "kind", kind }, { "primary", DualPrimary() } } },
                { "amnezia", awg }, { "software", ps.ContainsKey("software") ? ps["software"] : new object[0] }, { "remote", ps.ContainsKey("remote") ? ps["remote"] : null }, { "app", ps.ContainsKey("app") ? ps["app"] : null },
                { "history", History.ToArray() } };
            var tmp = StatusPath + ".tmp";
            File.WriteAllText(tmp, Json.Serialize(snap), Bom);
            try { if (File.Exists(StatusPath)) File.Replace(tmp, StatusPath, null); else File.Move(tmp, StatusPath); } catch { File.Copy(tmp, StatusPath, true); File.Delete(tmp); }
        }
    }
}
