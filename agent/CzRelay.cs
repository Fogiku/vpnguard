// Ретранслятор zapret: TCP-соединения клиентов — приём, соединение с сайтом, перекачка.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace VpnGuard
{
    public static partial class Agent
    {
        // ---------------------------------------------------------------- ретранслятор TCP: соединение к тому же адресу — уже от ПК (через winws или VPN)
        // асинхронно: без двух потоков на каждое соединение
        static async void CzAcceptLoop(TcpListener l)
        {
            while (true) {
                TcpClient c = null; try { c = await l.AcceptTcpClientAsync().ConfigureAwait(false); } catch { if (CzRelay != l) return; }
                if (c == null) { await Task.Delay(100).ConfigureAwait(false); continue; }
                CzRelayConn(NoInherit(c));
            }
        }
        static async void CzRelayConn(TcpClient c)
        {
            TcpClient srv = null; bool counted = false;
            try {
                var ep = (IPEndPoint)c.Client.RemoteEndPoint; uint cip = IpH(ep.Address.GetAddressBytes(), 0);
                CzTcpFlow f; lock (CzLock) CzTcp.TryGetValue(((ulong)cip << 16) | (uint)ep.Port, out f);
                if (f == null) { Interlocked.Increment(ref CzRelayNoFlow); return; }
                c.NoDelay = true; var cl = CzC(cip); var cs = c.GetStream();
                // 1. первый пакет клиента — по нему видно имя сайта
                long tAcc = (long)(DateTime.UtcNow - f.Syn).TotalMilliseconds; var sw0 = System.Diagnostics.Stopwatch.StartNew(); long tHello, tConn = -1, tResp = -1;
                var hello = new byte[16384]; int fn = await CzReadFirst(cs, hello).ConfigureAwait(false);
                tHello = sw0.ElapsedMilliseconds;
                if (fn <= 0) { if (CzDbg()) Log("zapret для клиентов [подробно]: " + ep.Address + ":" + ep.Port + " → " + IpS(f.Dst) + ":" + f.DPort + " · клиент не прислал запрос за " + tHello + " мс", "INFO"); return; }
                string host = CzSni(hello, fn) ?? CzHttpHost(hello, fn);
                if (host == null) Interlocked.Increment(ref CzNoHost);
                string lists = host == null ? "" : CzWinwsCovers(host, f.Dst, f.DPort) ? "в списках zapret" : "нет в списках zapret";
                string target = IpS(f.Dst) + ":" + f.DPort + (host != null ? " (" + host + (lists.Length > 0 ? ", " + lists : "") + ")" : "");
                // 1б. видеосервер Google (rr…---sn-….googlevideo.com на адресе Google, а не кэш провайдера) — через zapret медленно:
                // эту пару клиент → адрес надолго через VPN и сбросить соединение — клиент сразу повторит, уже через VPN
                if (host != null && CzVideoVpn && CzIsVideoHost(host) && CzIsGoogle(f.Dst)) {
                    CzBypass[((ulong)cip << 32) | f.Dst] = DateTime.UtcNow.AddMinutes(CzVideoVpnMin); Interlocked.Increment(ref CzVideoToVpn);
                    if (CzVideoLogged.TryAdd(f.Dst, 0) && CzVideoLogged.Count <= 200)
                        Log("zapret для клиентов: " + ep.Address + " → " + target + " · видеосервер Google — через VPN (через zapret медленно), " + CzVideoVpnMin / 60 + " ч", "INFO");
                    try { c.Client.LingerState = new LingerOption(true, 0); } catch { }
                    return;
                }
                // 1в. сайт, который напрямую не работает (реклама doubleclick …), или имя, которое недавно уже не ответило на другом адресе, —
                // сразу через VPN, без ожидания (у рекламы Google каждый раз новый адрес, иначе каждый запрос ждал бы ~5 с)
                DateTime bh;
                if (host != null && (CzVpnHost(host) || (CzBadHost.TryGetValue(host, out bh) && bh > DateTime.UtcNow))) {
                    CzBypass[((ulong)cip << 32) | f.Dst] = DateTime.UtcNow.AddMinutes(Math.Max(CzBypassMin, 30)); Interlocked.Increment(ref CzHostToVpn);
                    try { c.Client.LingerState = new LingerOption(true, 0); } catch { }
                    return;
                }
                // 2. соединиться от имени ПК (через winws) и отправить его; сайт молчит — эту пару клиент → адрес пустить через VPN
                // адрес молчит — тот же сайт на другом адресе того же CDN (Google, Cloudflare … отдают любой свой сайт по имени):
                // на том, где недавно получилось, или из DNS; кроме видеосерверов googlevideo — у каждого свой адрес
                // кэш-сервер видео у провайдера (rr…---sn-… не на адресах Google): работает только напрямую — в VPN не уводить, ждать дольше
                bool ispCache = host != null && CzIsVideoHost(host) && !CzIsGoogle(f.Dst) && CzGoogle.Lo.Length > 0;
                var rb = new byte[32768]; int rn = 0; string fail = null; var cands = new List<uint> { f.Dst }; uint used = f.Dst; string altNote = "";
                KeyValuePair<uint, DateTime> rm;
                if (host != null && CzFamily(host) != null && CzRemap.TryGetValue(f.Dst, out rm) && rm.Value > DateTime.UtcNow) cands[0] = rm.Key;   // исходный известен как мёртвый: запасной, а при его сбое — другой из DNS   // этот адрес недавно молчал — сразу на рабочий
                for (int ai = 0; ai < cands.Count && ai < 2; ai++) {
                    uint dip = cands[ai]; fail = null; rn = 0;
                    if (host != null && f.DPort == 443) { uint sp = CzSpread(host, dip, CzRemap.ContainsKey(f.Dst) ? f.Dst : 0); if (sp != dip) { Interlocked.Increment(ref CzSpreadN); dip = sp; } }
                    if (srv != null) { try { srv.Close(); } catch { } srv = null; }
                    Task<List<uint>> altT = null;
                    if (host != null && f.DPort == 443 && CzFamily(host) != null) { uint d0 = f.Dst; uint d1 = dip; string fam = CzFamily(host); uint[] pool; var pl = CzGoodPool.TryGetValue(fam, out pool) ? pool.Where(v => v != d0 && v != d1 && CzInSet(v)).ToList() : new List<uint>();
                        altT = pl.Count >= 2 ? Task.FromResult(pl) : CzAltIps(host, dip).ContinueWith(t => pl.Concat(t.Result).Where(v => v != d0 && v != d1).Distinct().ToList()); }
                    CzInFlight.AddOrUpdate(dip, 1, (k, v) => v + 1);
                    KeyValuePair<TcpClient, uint> cr;
                    try { cr = await CzConnect(dip, f.DPort, altT).ConfigureAwait(false); } finally { CzInFlight.AddOrUpdate(dip, 0, (k, v) => Math.Max(0, v - 1)); } srv = cr.Key; if (srv != null) dip = cr.Value; tConn = sw0.ElapsedMilliseconds;
                    if (srv == null) fail = "нет соединения";
                    else {
                        var s0 = srv.GetStream();
                        try { await s0.WriteAsync(hello, 0, fn).ConfigureAwait(false); } catch { fail = "ошибка отправки"; }
                        if (fail == null && host != null) {
                            var rd = s0.ReadAsync(rb, 0, rb.Length);
                            if (await Task.WhenAny(rd, Task.Delay(ai == 0 ? (ispCache ? Math.Max(CzFallbackMs, 8000) : CzFallbackMs) : 2000)).ConfigureAwait(false) == rd) {
                                try { rn = rd.Result; } catch { rn = 0; } tResp = sw0.ElapsedMilliseconds;
                                if (rn <= 0) fail = "сайт закрыл соединение";
                                else if (CzStubCert(host, rb, rn)) { fail = "сертификат открытым текстом (TLS 1.2) — похоже на заглушку провайдера"; Interlocked.Increment(ref CzStubs); }
                            }
                            else { CzObserve(rd); fail = "сайт молчит " + (ai == 0 ? (ispCache ? Math.Max(CzFallbackMs, 8000) : CzFallbackMs) / 1000.0 : 2) + " с"; }
                        }
                    }
                    if (fail == null) {
                        used = dip;
                        if (dip != f.Dst) { altNote = " · " + IpS(f.Dst) + " молчит — через zapret на " + IpS(dip); CzRemap[f.Dst] = new KeyValuePair<uint, DateTime>(dip, DateTime.UtcNow.AddMinutes(10)); }
                        break;
                    }
                    if (dip != f.Dst) { KeyValuePair<uint, DateTime> x; CzRemap.TryRemove(f.Dst, out x); }        // запасной перестал отвечать — забыть
                    if (host != null && f.DPort == 443 && !cands.Skip(ai + 1).Any()) foreach (var v in await CzAltIps(host, f.Dst).ConfigureAwait(false)) if (!cands.Contains(v)) cands.Add(v);
                }
                if (fail == null && host != null) CzRemember(host, used);
                if (fail != null) {
                    Interlocked.Increment(ref CzConnFail); Interlocked.Increment(ref cl.Fail);
                    // сразу после (пере)запуска winws обход DPI ещё не работает — такой сбой не повод уводить адрес в VPN
                    bool fresh = (DateTime.UtcNow - ZWinwsStartedAt).TotalSeconds < 30 || (DateTime.UtcNow - CzStartedAt).TotalSeconds < 30;
                    if (!fresh && !InetDown() && !ispCache) {
                        CzBypass[((ulong)cip << 32) | f.Dst] = DateTime.UtcNow.AddMinutes(CzBypassMin); Interlocked.Increment(ref CzBypassAdded);
                        if (host != null && !CzIsVideoHost(host) && lists != "в списках zapret") CzBadHost[host] = DateTime.UtcNow.AddMinutes(30);    // не из списков zapret: то же имя на других адресах — сразу через VPN
                    }
                    if (Interlocked.Increment(ref cl.FailLogged) <= 60) Log("zapret для клиентов: " + ep.Address + ":" + ep.Port + " → " + target + " · через zapret: " + fail + (cands.Count > 1 ? " (и на запасном " + IpS(cands[1]) + ")" : "") + (ispCache ? " — кэш провайдера, через VPN он не работает: клиент повторит через zapret" : fresh ? " (zapret только что запущен — обход не включаю)" : " — следующие соединения к " + IpS(f.Dst) + " " + CzBypassMin + " мин пойдут через VPN"), "INFO");
                    try { c.Client.LingerState = new LingerOption(true, 0); } catch { }   // сброс — клиент сразу повторит, уже через VPN
                    return;
                }
                if (CzDbg()) Log("zapret для клиентов [подробно]: " + ep.Address + ":" + ep.Port + " → " + target + altNote + " · SYN→ретранслятор " + tAcc + " мс, запрос клиента " + tHello + " мс, соединение с сайтом " + tConn + " мс, первый ответ " + tResp + " мс (" + rn + " Б)", "INFO");
                Interlocked.Increment(ref CzTcpConns); Interlocked.Increment(ref CzActive); Interlocked.Increment(ref cl.Conns); counted = true;
                Interlocked.Add(ref CzBytes, fn + rn); Interlocked.Add(ref CzTcpUp, fn); Interlocked.Add(ref cl.Up, fn); Interlocked.Add(ref CzTcpDown, rn); Interlocked.Add(ref cl.Down, rn);
                var ss = srv.GetStream();
                if (rn > 0) await cs.WriteAsync(rb, 0, rn).ConfigureAwait(false);
                f.Last = DateTime.UtcNow;
                // 3. дальше — в обе стороны
                var t0 = DateTime.UtcNow; string closed = null; var sv = srv;
                var up = CzPump(cs, ss, f, true, cl).ContinueWith(t => { if (closed == null) closed = "клиент"; try { sv.Client.Shutdown(SocketShutdown.Send); } catch { } return t.Result; });
                long down = rn + await CzPump(ss, cs, f, false, cl).ConfigureAwait(false);
                if (closed == null) closed = "сайт"; try { c.Client.Shutdown(SocketShutdown.Send); } catch { }
                await Task.WhenAny(up, Task.Delay(60000)).ConfigureAwait(false);
                if (Interlocked.Increment(ref cl.Logged) <= 8)
                    Log("zapret для клиентов: " + ep.Address + ":" + ep.Port + " → " + target + altNote + " · к сайту " + (fn + (up.IsCompleted ? up.Result : 0)) + " Б, к клиенту " + down + " Б, " +
                        Math.Round((DateTime.UtcNow - t0).TotalSeconds, 1) + " с, первым закрыл " + closed, "INFO");
            } catch { }
            finally {
                if (counted && Interlocked.Decrement(ref CzActive) < 0) Interlocked.Exchange(ref CzActive, 0);
                if (srv != null) { try { srv.Close(); } catch { } } try { c.Close(); } catch { }
            }
        }
        static async Task<long> CzPump(Stream a, Stream b, CzTcpFlow f, bool up, CzCli cl)
        {
            var bb = new byte[32768]; long total = 0;
            try {
                int n;
                while ((n = await a.ReadAsync(bb, 0, bb.Length).ConfigureAwait(false)) > 0) {
                    await b.WriteAsync(bb, 0, n).ConfigureAwait(false); total += n;
                    Interlocked.Add(ref CzBytes, n);
                    if (up) { Interlocked.Add(ref CzTcpUp, n); Interlocked.Add(ref cl.Up, n); } else { Interlocked.Add(ref CzTcpDown, n); Interlocked.Add(ref cl.Down, n); }
                    f.Last = DateTime.UtcNow;
                }
            } catch { }
            return total;
        }
    }
}
