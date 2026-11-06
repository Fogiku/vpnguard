'use strict';
// VpnGuard — веб-интерфейс: сеть, вход, страницы, отрисовка. Схема трафика — flow.js, стили — style.css.
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
let S = null, page = 'home', wgList = null, logCache = '', timer = null;
const NAMES = { home: 'Главная', ultra: 'Туннель', meduza: 'MeduzaVPN', amnezia: 'AmneziaVPN', wg: 'WG-Server', ics: 'Раздача интернета (ICS)', zapret: 'zapret-discord-youtube', traffic: 'Трафик', system: 'Компоненты и обновление', logs: 'Журнал', settings: 'Настройки', diag: 'Диагностика и доступ' };
const HKEY = { meduza: 'm', ultra: 'u', wg: 'w', ics: 'i', zapret: 'z', amnezia: 'a' };
const MODES = [['meduza', 'MeduzaVPN'], ['amnezia', 'AmneziaVPN'], ['dual', 'Два туннеля (с переключением)'], ['zapret', 'Без VPN — только zapret']];
const LV = { 0: 'работает', 1: 'предупреждение', 2: 'сбой', '-1': 'нет данных / выключено' };

// ---------------------------------------------------------------- сеть
async function api(path, body) {
  const o = body === undefined ? {} : { method: 'POST', headers: { 'X-VG': '1', 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  const r = await fetch(path, o);
  if (r.status === 401) { showLogin(); throw new Error('нужен вход'); }
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.error) || data || ('HTTP ' + r.status));
  return data;
}
function toast(t, bad) { const e = $('#toast'); e.textContent = t; e.style.color = bad ? 'var(--bad)' : ''; e.style.display = 'block'; clearTimeout(e._t); e._t = setTimeout(() => e.style.display = 'none', 4500); }
async function cmd(c, label, confirmText) {
  if (confirmText && !confirm(confirmText)) return false;
  try { await api('/api/cmd', { c }); toast('Отправлено агенту: ' + (label || c)); setTimeout(load, 2500); return true; } catch (e) { toast(e.message, true); return false; }
}
async function setCfg(key, value, label) {
  try { await api('/api/config', { key, value }); toast('Сохранено: ' + (label || key) + ' — агент применит на следующей проверке'); setTimeout(load, 2500); } catch (e) { toast(e.message, true); }
}
async function load() {
  try { S = await api('/api/status'); } catch (e) { $('#agent').textContent = 'нет связи с агентом: ' + e.message; $('#adot').className = 'dot l2'; return; }
  head(); render();
  if (page === 'diag' && $('#mods')) { $('#mods').innerHTML = modsHtml(); $('#evts').innerHTML = evtsHtml(); }   // остальное на вкладке не перерисовывается
}

// ---------------------------------------------------------------- вход
function showLogin() {
  clearInterval(timer);
  document.body.innerHTML = `<div class="card login"><h1>VpnGuard</h1><p class="muted">Вход с другого устройства. Пароль — в окне VpnGuard (вкладка «Диагностика» → «Веб-интерфейс») или в веб-интерфейсе на самом ПК (вкладка «Диагностика»).</p>
  <div class="row"><input type="password" id="pw" placeholder="пароль" style="flex:1" autofocus><button class="p" id="go">Войти</button></div><p class="err" id="lerr"></p></div>`;
  const go = async () => {
    const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: $('#pw').value }) });
    if (r.ok) location.reload(); else { const j = await r.json().catch(() => ({})); $('#lerr').textContent = j.error || 'не удалось войти'; }
  };
  $('#go').onclick = go; $('#pw').onkeydown = e => { if (e.key === 'Enter') go(); };
}

// ---------------------------------------------------------------- помощники отображения
const fmtB = b => { b = +b || 0; return b >= 1e9 ? (b / 1073741824).toFixed(2) + ' ГБ' : b >= 1e6 ? (b / 1048576).toFixed(1) + ' МБ' : (b / 1024).toFixed(0) + ' КБ'; };
const fmtR = v => { v = (+v || 0) * 8; return v >= 1e6 ? (v / 1e6).toFixed(1) + ' Мбит/с' : (v / 1e3).toFixed(0) + ' Кбит/с'; };
const ago = s => s < 0 ? 'не было' : s < 120 ? s + ' с назад' : s < 7200 ? Math.round(s / 60) + ' мин назад' : Math.round(s / 3600) + ' ч назад';
const comp = k => (S && S[k]) || null;
const lvl = o => o ? +o.level : -1;
function kvTable(o) { const rows = (o && o.kv) || []; if (!rows.length) return '<p class="muted">Нет данных.</p>'; return '<table class="kv">' + rows.map(r => `<tr><td>${esc(r[0])}</td><td>${esc(r[1])}</td></tr>`).join('') + '</table>'; }
function timeline(k) {
  const h = (S && S.history) || [], key = HKEY[k], n = 240, pad = n - h.length;
  let cells = ''; for (let i = 0; i < pad; i++) cells += '<i class="l-1"></i>';
  for (const p of h) { const v = p[key]; cells += `<i class="l${v === undefined || v === null ? -1 : v}" title="${new Date(p.t * 1000).toLocaleTimeString()} — ${LV[v ?? -1]}"></i>`; }
  let ok = 0, all = 0; for (const p of h) { const v = p[key]; if (v !== undefined && v !== null && v >= 0) { all++; if (v == 0) ok++; } }
  const iv = (S && S.intervalSec) || 30;
  return `<div class="sec">Состояние за ${Math.round(n * iv / 60)} мин${all ? ` · без сбоев ${(100 * ok / all).toFixed(1)} % времени` : ''}</div><div class="tl">${cells}</div><div class="tlx"><span>−${Math.round(n * iv / 3600)} ч</span><span>сейчас</span></div>`;
}
function compHead(k, buttons) {
  const o = comp(k), l = lvl(o);
  return `<div class="card hero st${l}"><div><div class="big"><span class="dot l${l}" style="width:16px;height:16px"></span><span class="c${l}">${esc(o ? o.state : 'нет данных')}</span></div>
    <div class="muted" style="margin-top:6px">${esc(((o && o.details) || []).join('  ·  '))}</div></div><div class="row">${buttons || ''}</div></div>`;
}
const btn = (t, onclick, p) => `<button${p ? ' class="p"' : ''} onclick="${esc(onclick)}">${esc(t)}</button>`;

// график скорости по истории агента (байты за интервал → средняя скорость)
function drawChart(cv, k) {
  const h = (S && S.history) || [], ctx = cv.getContext('2d'), dpr = window.devicePixelRatio || 1;
  const W = cv.clientWidth, H = cv.clientHeight; cv.width = W * dpr; cv.height = H * dpr; ctx.scale(dpr, dpr);
  const css = getComputedStyle(document.documentElement), col = n => css.getPropertyValue(n).trim();
  const off = { u: 0, w: 2, p: 4 }[k];
  const pts = []; for (let i = 0; i < h.length; i++) { const tr = h[i].tr; const dt = i ? Math.max(1, h[i].t - h[i - 1].t) : ((S.intervalSec) || 30);
    pts.push(tr && tr.length >= 6 && dt < 600 ? (k === 'z' ? [Math.max(0, tr[4] - tr[0] - tr[2]) / dt, Math.max(0, tr[5] - tr[1] - tr[3]) / dt] : [tr[off] / dt, tr[off + 1] / dt]) : null); }
  let mx = 12500; for (const v of pts) if (v) mx = Math.max(mx, v[0], v[1]);
  const step = [1, 2, 2.5, 5, 10]; let m = Math.pow(10, Math.floor(Math.log10(mx * 8))); let top = 0; for (const s of step) { if (s * m >= mx * 8) { top = s * m / 8; break; } } if (!top) top = 10 * m / 8;
  const L = 70, R = 10, T = 10, B = 22, pw = W - L - R, ph = H - T - B;
  ctx.font = '11px Segoe UI, sans-serif'; ctx.fillStyle = col('--dim'); ctx.strokeStyle = col('--grid'); ctx.lineWidth = 1;
  for (let j = 0; j <= 2; j++) { const y = T + ph - ph * j / 2; ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(L + pw, y); ctx.stroke(); ctx.textAlign = 'right'; ctx.fillText(fmtR(top * j / 2), L - 8, y + 4); }
  ctx.textAlign = 'left'; ctx.fillText('−2 ч', L, H - 6); ctx.textAlign = 'right'; ctx.fillText('сейчас', L + pw, H - 6);
  const n = 240, sx = pw / (n - 1), o0 = n - pts.length;
  for (const [idx, c, fill] of [[0, col('--rx'), true], [1, col('--tx'), false]]) {
    ctx.strokeStyle = c; ctx.lineWidth = 2; let seg = [];
    const flush = () => { if (seg.length > 1) { ctx.beginPath(); seg.forEach((p, i) => i ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1])); ctx.stroke();
      if (fill) { ctx.lineTo(seg[seg.length - 1][0], T + ph); ctx.lineTo(seg[0][0], T + ph); ctx.closePath(); ctx.globalAlpha = .22; ctx.fillStyle = c; ctx.fill(); ctx.globalAlpha = 1; } } seg = []; };
    pts.forEach((v, i) => { if (!v) { flush(); return; } seg.push([L + (o0 + i) * sx, T + ph - ph * Math.min(1, v[idx] / top)]); }); flush();
  }
  if (!pts.some(v => v)) { ctx.fillStyle = col('--dim'); ctx.textAlign = 'center'; ctx.fillText('пока нет данных', L + pw / 2, T + ph / 2); }
}
function chartBlock(k, title) {
  const tr = S && S.traffic, rate = tr && tr.rate && tr.rate[k], nm = tr && tr.names && tr.names[k];
  return `<div class="sec">${esc(title)}</div><div class="card"><div class="row" style="justify-content:space-between"><div class="legend"><span><b style="background:var(--rx)"></b>Загрузка ↓ ${rate ? fmtR(rate[0]) : '—'}</span><span><b style="background:var(--tx)"></b>Отдача ↑ ${rate ? fmtR(rate[1]) : '—'}</span></div><span class="sub">${nm ? 'адаптер «' + esc(nm) + '»' : k === 'z' ? 'оценка: физический − туннель − wg_server' : ''}</span></div><canvas data-chart="${k}"></canvas></div>`;
}

// ---------------------------------------------------------------- шапка
function head() {
  $('#ver').textContent = S.agentVersion ? 'агент ' + S.agentVersion : '';
  const age = (Date.now() - new Date(S.updated).getTime()) / 1000, fresh = age < (S.staleAfterSec || 150);
  $('#adot').className = 'dot ' + (fresh ? (S.activity ? 'l1' : 'l0') : 'l2');
  $('#agent').textContent = fresh ? `агент ${S.agentVersion} · обновлено ${Math.round(age)} с назад` + (S.activity ? ` · сейчас: ${S.activity}` : '') : `данные устарели (${Math.round(age / 60)} мин) — агент не отвечает?`;
  for (const d of document.querySelectorAll('[data-d]')) d.className = 'dot l' + lvl(comp(d.dataset.d));
  const m = S.vpn && S.vpn.mode; const a = $('[data-p="ultra"]'); if (a) a.firstChild.textContent = m === 'zapret' ? 'Без VPN ' : 'Туннель ';
}

// ---------------------------------------------------------------- страницы
const P = {};
P.home = () => `<div id="htop">${P.home.top()}</div><div class="hsplit"><div id="htiles">${P.home.tiles()}</div>
  <div class="card hev"><div class="sec" style="margin-top:0">Последние предупреждения и ошибки</div><pre id="events" class="lgv">${P.home.evH || esc(P.home.ev || 'загрузка…')}</pre></div></div>
  <div id="hflow">${flowBlock()}</div>`;
P.home.top = () => {
  const keys = [['inet', 'Интернет'], ['ultra', 'Туннель'], ['meduza', 'MeduzaVPN'], ['amnezia', 'AmneziaVPN'], ['wg', 'WG-Server'], ['ics', 'Раздача ICS'], ['zapret', 'zapret']];
  let worst = -1; const probs = [];
  for (const [k, n] of keys) { const l = lvl(comp(k)); if (l > worst) worst = l; if (l >= 1) probs.push(n + ': ' + comp(k).state); }
  const ht = { 0: 'Всё работает', 1: 'Есть предупреждения', 2: 'Есть сбои' }[worst] || 'Нет данных';
  const mode = (S.vpn && S.vpn.mode) || 'meduza';
  const z = comp('zapret');
  const peers = (comp('wg') && comp('wg').peers) || [];
  const tr = S.traffic, today = tr && tr.days && tr.days.find(d => d.d === new Date().toISOString().slice(0, 10));
  const h = S.history || []; let ok = 0, all = 0; for (const p of h) if (p.u >= 0) { all++; if (p.u == 0) ok++; }
  return `<div class="card hero st${worst}"><div><div class="big"><span class="dot l${worst}" style="width:18px;height:18px"></span><span class="c${worst}">${ht}</span></div>
      <div class="muted" style="margin-top:6px">${esc(probs.join('  ·  ') || 'Туннель, WG-Server и раздача в порядке')}</div>
</div>
    <div><div class="sub">Режим работы</div><select onchange="setMode(this.value)">${MODES.map(([v, t]) => `<option value="${v}"${v === mode ? ' selected' : ''}>${t}</option>`).join('')}</select></div></div>`;
};
P.home.tiles = () => {
  const keys = [['inet', 'Интернет'], ['ultra', 'Туннель'], ['meduza', 'MeduzaVPN'], ['amnezia', 'AmneziaVPN'], ['wg', 'WG-Server'], ['ics', 'Раздача ICS'], ['zapret', 'zapret']];
  const peers = (comp('wg') && comp('wg').peers) || [];
  const tr = S.traffic, today = tr && tr.days && tr.days.find(d => d.d === new Date().toISOString().slice(0, 10));
  const h = S.history || []; let ok = 0, all = 0; for (const p of h) if (p.u >= 0) { all++; if (p.u == 0) ok++; }
  return `<div class="grid">${keys.map(([k, n]) => { const o = comp(k), l = lvl(o); return `<div class="tile" onclick="location.hash='${k === 'inet' ? 'home' : k}'" title="${esc(o && o.details && o.details.join(' · '))}"><div class="t"><span class="dot l${l}"></span>${n}</div><div class="s c${l}" title="${esc(o && o.state)}">${esc(o ? String(o.state).split(' · ')[0] : 'нет данных')}</div><div class="d">${esc(o && o.details && o.details[0])}</div></div>`; }).join('')}</div>
  <div class="grid">
    <div class="tile kpi"><div class="t">Доступность туннеля · 2 ч</div><div class="v ${all ? (ok / all > .99 ? 'c0' : ok / all > .9 ? 'c1' : 'c2') : ''}">${all ? (100 * ok / all).toFixed(1) + ' %' : '—'}</div></div>
    <div class="tile kpi"><div class="t">Скорость туннеля</div><div class="v">${tr && tr.rate && tr.rate.u ? '↓ ' + fmtR(tr.rate.u[0]) : '—'}</div><div class="d">${tr && tr.rate && tr.rate.u ? '↑ ' + fmtR(tr.rate.u[1]) : ''}</div></div>
    <div class="tile kpi"><div class="t">Трафик туннеля сегодня</div><div class="v">${today ? '↓ ' + fmtB(today.u[0]) : '—'}</div><div class="d">${today ? '↑ ' + fmtB(today.u[1]) : ''}</div></div>
    <div class="tile kpi" onclick="location.hash='wg'"><div class="t">Клиенты WG-Server</div><div class="v">${peers.filter(p => p.active).length} из ${peers.length}</div><div class="d">на связи за 3 мин</div></div>
  </div>
`;
};
P.home.after = async () => { flowMount(); if (!P.home.histAt || Date.now() - P.home.histAt > 600000) { P.home.histAt = Date.now(); setTimeout(sparkHist, 2500); } if (Date.now() - (P.home.evAt || 0) < 60000) return; P.home.evAt = Date.now(); try { const t = await api('/api/logs?minutes=720&lines=3000'); const l = t.split('\n').filter(s => /\[(WARN|ERROR)\]/.test(s)).slice(-15).reverse(); P.home.ev = l.join('\n') || 'за 12 часов — ничего'; P.home.evH = l.length ? logHtml(l) : esc(P.home.ev); if ($('#events')) $('#events').innerHTML = P.home.evH; } catch (e) { } };
async function setZVer() {
  const v = $('#zver').value;
  if (!confirm(v ? `Установить zapret ${v} и закрепить эту версию?` : 'Вернуться к последней версии zapret (обновляется сама)?')) return;
  try { await api('/api/config', { key: 'zapret.version', value: v }); await api('/api/cmd', { c: 'zapret-update' }); toast('Агент установит ' + (v ? 'zapret ' + v : 'последнюю версию') + ' — 10–30 секунд'); setTimeout(load, 4000); } catch (e) { toast(e.message, true); }
}
function setMode(m) {
  const msg = { meduza: 'Переключиться на MeduzaVPN?', amnezia: 'Переключиться на AmneziaVPN? MeduzaVPN будет отключён.', dual: 'Включить режим «два туннеля»? Оба VPN будут подняты, при сбое трафик переключится на второй.', zapret: 'Отключить VPN? ПК и клиенты WG-Server пойдут в интернет напрямую, YouTube/Discord — через zapret.' }[m];
  if (confirm(msg)) setCfg('vpn.mode', m, 'режим'); else render();
}
P.ultra = () => {
  const u = comp('ultra'), dual = S.vpn && S.vpn.mode === 'dual';
  return compHead('ultra', btn('Переподключить', "cmd('reconnect','переподключение туннеля')") + (dual ? btn('Переключить на другой', "cmd('dual-switch','переключение туннеля')") : '')) +
    (dual ? `<div class="card row"><span class="muted">Основной туннель:</span><select onchange="setCfg('vpn.primary',this.value,'основной туннель')">${[['meduza', 'MeduzaVPN'], ['amnezia', 'AmneziaVPN']].map(([v, t]) => `<option value="${v}"${S.vpn.primary === v ? ' selected' : ''}>${t}</option>`).join('')}</select></div>` : '') +
    timeline('ultra') + '<div class="sec">Подробности</div><div class="card">' + kvTable(u) + '</div>' + chartBlock('u', 'Скорость — последние 2 часа');
};
P.meduza = () => {
  const m = comp('meduza') || {}, cat = m.catalog, pt = m.protoTest;
  const protos = (cat && cat.protocols) || [], cur = m.protocol || 'ultra';
  const sel = protos.map(p => `<option value="${esc(p.id)}"${p.id === cur || p.id === 'meduza-' + cur ? ' selected' : ''}>${esc(p.name)}${p.info ? ' — ' + esc(p.info) : ''}</option>`).join('') || `<option>${esc(cur)}</option>`;
  const res = (pt && pt.results) || [];
  return compHead('meduza', btn('Перезапустить MeduzaVPN', "cmd('restart-meduza','перезапуск MeduzaVPN')") + btn('Тест протоколов', "cmd('meduza-test','тест протоколов','Агент по очереди подключит каждый протокол (до минуты на протокол). Клиенты wg_server на это время теряют интернет. Запустить?')") + btn('Проверить обновление', "cmd('check-update','проверка обновления')")) +
    `<div class="sec">Протокол</div><div class="card"><div class="row"><select id="proto">${sel}</select>${btn('Применить', "setCfg('meduza.protocol', $('#proto').value, 'протокол')", true)}${btn('Обновить список', "cmd('meduza-catalog','обновление списка')")}${m.protocolOverride ? btn('Вернуть выбранный', "cmd('meduza-proto-reset','возврат протокола')") : ''}</div>
      <p class="${m.protocolOverride ? 'c1' : 'muted'}">${m.protocolOverride ? `Выбранный протокол ${esc(cur)} не работал — агент временно переключился на ${esc(m.protocolOverride)}.` : cat ? `С аккаунта: протоколов ${protos.length}, VPN ${(cat.services || []).length}${cat.error ? ' · ' + esc(cat.error) : ''}` : 'Список протоколов ещё не получен.'}</p></div>
    <div class="sec">Тест протоколов</div><div class="card">${pt && pt.running ? `<p class="c1">Идёт тест: ${pt.index} из ${pt.total} · ${esc(pt.current)}</p>` : ''}${res.length ? `<table><tr><th>Протокол</th><th>Результат</th><th>Проверки</th><th class="hide-m">Подключение</th><th>Отклик</th><th class="hide-m">Ошибка</th></tr>${res.map(r => `<tr class="${r.protocol === cur || r.protocol === 'meduza-' + cur ? 'cur' : ''}"><td><span class="dot l${r.ok ? 0 : 2}"></span> ${esc(r.protocol)}</td><td class="c${r.ok ? 0 : 2}">${r.ok ? 'работает' : 'не работает'}</td><td>${esc(r.probes)}</td><td class="hide-m">${r.connectSec} с</td><td>${r.pingMs >= 0 ? r.pingMs + ' мс' : '—'}</td><td class="hide-m">${esc(r.error)}</td></tr>`).join('')}</table>${pt.at ? `<p class="sub">Последний тест: ${esc(pt.at)}</p>` : ''}` : '<p class="muted">Тест ещё не запускали.</p>'}</div>` +
    timeline('meduza') + '<div class="sec">Подробности</div><div class="card">' + kvTable(m) + '</div>';
};
P.amnezia = () => {
  const a = comp('amnezia') || {}, sw = (S.software || []).find(x => x.id === 'amneziavpn');
  return compHead('amnezia', btn('Перезапустить AmneziaVPN', "cmd('reconnect-awg','перезапуск AmneziaVPN','Закрыть и снова открыть AmneziaVPN? Туннель переподключится (нужно включённое «Автоподключение»).')") + btn('Режим AmneziaVPN', "setMode('amnezia')") +
      (a.installed ? '' : btn('Установить AmneziaVPN', "cmd('install amneziavpn','установка AmneziaVPN','Скачать AmneziaVPN с GitHub и установить?')", true))) +
    `<div class="sec">Как это работает</div><div class="card"><p>Сервер и протокол выбираются в самом приложении AmneziaVPN — добавьте сервер (ключ <code>vpn://</code> или файл) прямо в нём.</p>
      <p>VpnGuard держит AmneziaVPN запущенным, находит его туннель${a.adapter ? ` (сейчас — «${esc(a.adapter)}»)` : ''}, проверяет трафик и при сбое перезапускает приложение.</p>
      <p class="c1">Один раз включите в AmneziaVPN: «Настройки → Подключение → Автоподключение» и «Настройки → Приложение → Автозапуск» — иначе после перезапуска туннель не поднимется сам. «Kill Switch» лучше не включать: он мешает zapret и ответам клиентам WG-Server.</p>
      ${sw ? `<p class="sub">Установлено: ${esc(sw.installed || 'нет')} · последняя версия: ${esc(sw.latest || '—')}</p>` : ''}</div>` +
    timeline('amnezia') + '<div class="sec">Подробности</div><div class="card">' + kvTable(a) + '</div>';
};
P.wg = () => {
  const cz = (comp('wg') && comp('wg').clientZapret) || {}, zon = comp('zapret') && comp('zapret').enabled;
  const peers = (comp('wg') && comp('wg').peers) || [];
  const list = (wgList && wgList.clients) || peers.map(p => ({ name: p.name, ip: p.ip, source: '', hasConf: false }));
  const rows = list.map(c => {
    const p = peers.find(x => x.ip === c.ip) || {}, off = !!p.off, zap = p.zapret !== false, s = p.cz || {}, ip = esc(c.ip), nm = esc(c.name);
    const zInfo = !cz.enabled ? '' : off ? '' : !zap ? '<div class="sub">zapret выкл — всё через VPN</div>'
      : `<div class="sub">через zapret: ${s.conns || 0} соед. · ↓ ${fmtB((s.downKb || 0) * 1024)}${s.fail ? ' · не подключилось ' + s.fail : ''}${s.lastAgo >= 0 ? ' · ' + ago(s.lastAgo) : (p.active ? ' · пока не было' : '')}</div>`;
    return `<tr${off ? ' style="opacity:.6"' : ''}><td><span class="dot l${!off && p.active ? 0 : -1}"></span> ${nm}${c.source && c.source !== 'VpnGuard' ? ` <span class="sub">${esc(c.source)}</span>` : ''}${off ? ' <b>отключён</b>' : ''}${zInfo}</td><td>${ip}</td><td class="hide-m">${esc(p.endpoint || '—')}</td><td>${off ? '—' : p.hsAgo !== undefined ? ago(p.hsAgo) : '—'}</td><td class="hide-m">↓ ${fmtB(p.tx)} ↑ ${fmtB(p.rx)}</td>
    <td class="row" style="flex-wrap:nowrap">${cz.enabled && !off ? btn(zap ? 'zapret: вкл' : 'zapret: выкл', `cliSet('${ip}',{zapret:${!zap}},'${nm}')`, zap) : ''}${btn(off ? 'Включить' : 'Отключить', `cliSet('${ip}',{off:${!off}},'${nm}')`, off)}${c.hasConf ? btn('QR и настройки', `showConf('${ip}')`) : ''}${btn('Переименовать', `wgRename('${ip}','${nm}')`)}${btn('Удалить', `delClient('${ip}','${nm}')`)}</td></tr>`; }).join('');
  const czCard = `<div class="sec">zapret для клиентов</div><div class="card">${cz.enabled
      ? `<p><span class="dot l${cz.running ? 0 : 2}"></span> <b>${cz.running ? 'Работает' : 'Не работает'}</b>${cz.error ? ' · ' + esc(cz.error) : ''}</p>
         <p>Трафик клиентов к адресам zapret (YouTube, Discord, видеосерверы провайдера, свои списки) идёт через zapret этого ПК, остальное — через VPN. На устройствах ничего менять не нужно. Для отдельного клиента zapret можно выключить в таблице ниже.</p>
         <p class="sub">TCP-соединений через zapret: ${cz.tcpConns || 0} (сейчас ${cz.active || 0}), UDP-потоков ${cz.udpFlows || 0} · ${cz.mb || 0} МБ · перехвачено пакетов ${cz.packets || 0}${cz.errors ? ' · ошибок ' + cz.errors : ''}</p>
         ${btn('Выключить', "setCfg('wg.clientZapret',false,'zapret для клиентов')")}`
      : `<p class="muted">Клиентам YouTube и Discord сейчас ${zon ? 'не открываются, пока zapret включён (zapret обрабатывает только трафик самого ПК)' : 'идут через VPN'}. Можно пустить их через zapret этого ПК: трафик к адресам zapret (YouTube, Discord …) — через zapret, остальное — через VPN. На устройствах ничего менять не нужно.</p>
         ${btn('Включить', "setCfg('wg.clientZapret',true,'zapret для клиентов')", true)}`}</div>`;
  const srv = wgServerSection();
  if (wgList && wgList.noServer) return compHead('wg', '') + srv + timeline('wg');
  return compHead('wg', btn('＋ Новый клиент', 'addClient()', true) + btn('Перезапустить туннель', "cmd('restart-wg','перезапуск WG-Server')")) +
    `<div class="sec">Клиенты (зелёный — на связи за 3 минуты)</div><div class="card">${list.length ? `<table><tr><th>Клиент</th><th>IP</th><th class="hide-m">Откуда</th><th>Рукопожатие</th><th class="hide-m">Всего</th><th></th></tr>${rows}</table>` : '<p class="muted">Клиентов нет.</p>'}</div>` +
    srv + czCard +
    timeline('wg') + '<div class="sec">Подробности</div><div class="card">' + kvTable(comp('wg')) + '</div>' + chartBlock('w', 'Скорость WG-Server — последние 2 часа');
};
P.wg.after = async () => { try { const r = await api('/api/wg/clients'); if (r.ok || r.noServer) { const changed = JSON.stringify(r) !== JSON.stringify(wgList); wgList = r; if (changed && page === 'wg') render(true); } } catch (e) { } };
async function addClient() {
  const n = prompt('Имя нового клиента (например, телефон или ноутбук):'); if (!n) return;
  try { const r = await api('/api/wg/add', { name: n }); wgList = null; toast(`Клиент «${r.name}» создан: ${r.ip}`); showConfText(r.name, r.ip, r.text); P.wg.after(); } catch (e) { toast('Не удалось: ' + e.message, true); }
}
async function cliSet(ip, o, name) {
  if (o.off === true && !confirm(`Отключить клиента «${name}» (${ip})? Он перестанет подключаться, пока его не включат обратно. Настройки клиента сохранятся.`)) return false;
  try { await api('/api/wg/client-set', Object.assign({ ip }, o)); toast(`«${name}»: ` + (o.off !== undefined ? (o.off ? 'отключён' : 'включён') : (o.zapret ? 'zapret включён' : 'zapret выключен — весь трафик через VPN')) + ' — агент применит за 10–30 с'); setTimeout(load, 3000); setTimeout(load, 12000); return true; } catch (e) { toast(e.message, true); return false; }
}
async function wgRename(ip, name) {
  const n = prompt(`Новое имя клиента «${name}» (${ip}):`, name); if (!n || n === name) return;
  try { await api('/api/wg/rename', { ip, name: n }); toast(`«${name}» → «${n}»`); wgList = null; await P.wg.after(); load(); } catch (e) { toast(e.message, true); }
}
// ---- раздел «Сервер»: состояние, настройки (форма), ключ, конфиг, резервные копии, создание с нуля
const wsIn = (id, val, ph, o = {}) => `<input type="text" id="${id}" data-keep value="${esc(val ?? '')}" placeholder="${esc(ph || '')}"${o.dis ? ' disabled' : ''} style="width:100%;max-width:${o.w || 320}px">`;
const wsRow = (label, hint, field) => `<tr><td>${label}${hint ? `<div class="sub">${hint}</div>` : ''}</td><td>${field}</td></tr>`;
function wgServerSection() {
  if (wgList && wgList.noServer) {
    const d = wgList.defaults || {};
    return `<div class="sec">Сервер</div><div class="card"><p><b>Сервера WG-Server ещё нет.</b> Его можно создать здесь — VpnGuard сам сделает ключи, конфиг, службу туннеля и правило брандмауэра.</p>
      ${wgList.installed ? '' : '<p class="c2">Сначала установите WireGuard на вкладке «Компоненты».</p>'}
      <table class="kv">${wsRow('Адрес сервера', 'подсеть /24; клиенты получат адреса из неё', wsIn('ws_addr', d.address || '10.253.0.1', '10.8.0.1'))}
        ${wsRow('Порт UDP', 'его нужно пробросить на роутере на этот ПК', wsIn('ws_port', d.port || 51820, '51820', { w: 110 }))}
        ${wsRow('MTU', 'пусто — автоматически', wsIn('ws_mtu', '', 'авто', { w: 110 }))}
        ${wsRow('Адрес для клиентов', 'внешний IP или имя (DDNS); пусто — определить автоматически', wsIn('ws_ep', '', 'автоматически'))}
        ${wsRow('DNS для клиентов', 'пусто — адрес сервера', wsIn('ws_dns', '', 'автоматически'))}</table>
      <div class="row" style="margin-top:10px">${btn('Создать сервер', 'wgCreate(false)', true)}</div></div>`;
  }
  const sv = wgList && wgList.server; if (!sv) return '';
  const own = sv.owned, dis = { dis: !own };
  const svc = !sv.running ? '<b class="c2">не работает</b>' : sv.svcOk ? '<span class="c0">работает</span>' : '<b class="c1">работает, но с другим файлом конфига</b>';
  return `<div class="sec">Сервер</div><div class="card">
    <table class="kv"><tr><td>Конфиг</td><td>${own ? '<span class="c0">в папке VpnGuard</span>' : '<b class="c1">вне папки VpnGuard</b> — адрес, порт и ключ меняются после переноса'}</td></tr>
      <tr><td>Служба туннеля</td><td>${svc}${sv.svcOk ? '' : `<div class="sub">служба: ${esc(sv.svcConf || 'не установлена')}<br>нужно: ${esc(sv.conf)}</div><div style="margin-top:6px">${btn('Исправить — переустановить службу', 'wgFixService()', true)}</div>`}</td></tr>
      <tr><td>Адрес · порт</td><td>${esc(sv.address)} · UDP ${esc(sv.port)}${sv.mtu ? ' · MTU ' + sv.mtu : ''}</td></tr>
      <tr><td>Открытый ключ сервера</td><td><code style="word-break:break-all">${esc(sv.publicKey)}</code></td></tr>
      <tr><td>Конфиг</td><td class="sub">${esc(sv.conf)}</td></tr></table>
    <div class="row" style="margin-top:10px">${btn('Конфиг сервера', 'wgConfEdit()')}${btn(`Резервные копии (${sv.backups || 0})`, 'wgBackups()')}${own ? btn('Сменить ключ сервера', 'wgRegenKey()') + btn('Создать сервер заново', 'wgCreate(true)') : btn('Перенести конфиг в VpnGuard', 'wgAdopt()', true)}</div>
    ${own ? '' : `<p class="sub" style="margin-top:8px">Конфиг сервера и клиентов (${sv.extClients || 0}) копируются в папку VpnGuard, служба туннеля переустанавливается — клиенты отключатся на несколько секунд и подключатся сами. Ключи не меняются, перенастраивать устройства не нужно. Прежние файлы остаются как есть.</p>`}</div>
  <div class="sec">Настройки сервера</div><div class="card"><table class="kv">
    ${wsRow('Адрес сервера', own ? 'подсеть /24. При смене подсети клиенты переедут в новую (последнее число адреса сохранится)' : 'меняется после переноса в VpnGuard', wsIn('ws_addr', sv.ip, '', dis))}
    ${wsRow('Порт UDP', own ? 'не забудьте пробросить новый порт на роутере' : '', wsIn('ws_port', sv.port, '', Object.assign({ w: 110 }, dis)))}
    ${wsRow('MTU', 'пусто — автоматически (1420)', wsIn('ws_mtu', sv.mtu || '', 'авто', Object.assign({ w: 110 }, dis)))}
    ${wsRow('Адрес для клиентов', 'внешний IP или имя (DDNS), можно с :портом; пусто — автоматически', wsIn('ws_ep', sv.endpointSet, sv.endpoint || 'автоматически'))}
    ${wsRow('DNS для клиентов', 'IP через запятую; пусто — автоматически', wsIn('ws_dns', sv.dnsSet, sv.dns || 'автоматически'))}
    ${wsRow('Маршруты клиентов', '0.0.0.0/0 — весь трафик устройства через сервер; или только нужные подсети через запятую', wsIn('ws_allowed', sv.allowed, '0.0.0.0/0', { w: 420 }))}
    ${wsRow('Keepalive, с', 'клиент шлёт пакет раз в N секунд, чтобы связь не засыпала; 0 — выкл', wsIn('ws_ka', sv.keepalive, '25', { w: 110 }))}
  </table><div class="row" style="margin-top:10px">${btn('Сохранить', 'wgServerSave()', true)}${btn('Отменить изменения', 'wgFormReset()')}</div>
  <p class="sub" style="margin-top:8px">Адрес, порт и MTU применяются перезапуском туннеля (клиенты отключатся на несколько секунд). Адрес/DNS/маршруты/keepalive для клиентов и смена адреса или порта записываются в конфиги клиентов, которые хранит VpnGuard${sv.noFile ? ` (у ${sv.noFile} клиент(ов) конфига на ПК нет — их нужно настроить на устройстве вручную)` : ''}; на устройствах такие конфиги нужно загрузить заново (кнопка «QR и настройки»).</p></div>`;
}
const wsVal = id => { const e = $('#' + id); return e ? e.value.trim() : undefined; };
function wgFormReset() { for (const e of document.querySelectorAll('[data-keep]')) e.value = e.defaultValue; }
async function wgServerSave() {
  const sv = (wgList && wgList.server) || {};
  const b = { endpoint: wsVal('ws_ep'), dns: wsVal('ws_dns'), allowed: wsVal('ws_allowed'), keepalive: wsVal('ws_ka') };
  if (sv.owned) Object.assign(b, { address: wsVal('ws_addr'), port: wsVal('ws_port'), mtu: wsVal('ws_mtu') });
  const srvCh = sv.owned && (b.address !== sv.ip || +b.port !== sv.port || (+b.mtu || 0) !== (sv.mtu || 0));
  const cliCh = (b.endpoint !== (sv.endpointSet || '')) || (b.dns !== (sv.dnsSet || '')) || (b.allowed !== sv.allowed) || (+b.keepalive !== sv.keepalive) || (sv.owned && (b.address !== sv.ip || +b.port !== sv.port));
  if (!srvCh && !cliCh) { toast('Изменений нет'); return; }
  if (!confirm((srvCh ? 'Туннель перезапустится — клиенты отключатся на несколько секунд.\n' : '') + (cliCh ? 'Конфиги клиентов, которые хранит VpnGuard, обновятся — на устройствах их нужно будет загрузить заново (QR).\n' : '') + '\nСохранить?')) return;
  toast('Сохраняю…');
  try { const r = await api('/api/wg/server', b); wgFormReset(); toast(r.done && r.done.length ? r.done.join('; ') : 'без изменений'); wgList = null; await P.wg.after(); render(true); } catch (e) { toast(e.message, true); }
}
async function wgCreate(recreate) {
  const b = { address: wsVal('ws_addr'), port: wsVal('ws_port'), mtu: wsVal('ws_mtu'), recreate };
  if (!recreate) Object.assign(b, { endpoint: wsVal('ws_ep'), dns: wsVal('ws_dns') });
  if (recreate) {
    if (!confirm(`Создать сервер заново с адресом ${b.address}/24 и портом ${b.port}?\n\nБудут новые ключи. ВСЕ клиенты удаляются — их нужно будет создать и настроить на устройствах заново.\nПрежний конфиг и конфиги клиентов сохранятся в data\\backup.`)) return;
    if ((prompt('Для подтверждения введите слово ЗАНОВО') || '').trim().toUpperCase() !== 'ЗАНОВО') { toast('Отменено'); return; }
  }
  toast('Создаю сервер… (до минуты)');
  try { await api('/api/wg/create', b); wgFormReset(); toast('Сервер создан и запущен'); wgList = null; await P.wg.after(); render(true); load(); } catch (e) { toast('Не удалось: ' + e.message, true); }
}
async function wgFixService() {
  if (!confirm('Переустановить службу туннеля на конфиг VpnGuard? Клиенты отключатся на несколько секунд.')) return;
  toast('Переустанавливаю службу…');
  try { await api('/api/wg/fix-service', {}); toast('Служба туннеля — на нужном конфиге'); wgList = null; await P.wg.after(); render(true); } catch (e) { toast(e.message, true); }
}
async function wgRegenKey() {
  if (!confirm('Сменить ключ сервера?\n\nСтарые конфиги на ВСЕХ устройствах перестанут подключаться. Конфиги клиентов, которые хранит VpnGuard, обновятся сами — их нужно загрузить на устройства заново (QR). Туннель перезапустится.')) return;
  try { const r = await api('/api/wg/regen-key', {}); toast(`Новый ключ сервера. Обновлено конфигов клиентов: ${r.patched}${r.restart ? ' · туннель: ' + r.restart : ''}`); wgList = null; await P.wg.after(); render(true); } catch (e) { toast(e.message, true); }
}
async function wgConfEdit() {
  let r; try { r = await api('/api/wg/server-conf'); } catch (e) { toast(e.message, true); return; }
  $('#mbody').innerHTML = `<div class="row" style="justify-content:space-between"><h1>Конфиг сервера</h1>${btn('Закрыть', 'closeModal()')}</div>
    <p class="sub">${esc(r.conf)}</p><p class="muted">${r.owned ? 'Закрытый ключ скрыт — строку с ним не меняйте. Перед сохранением конфиг проверяется; прежний попадёт в резервные копии, туннель перезапустится.' : 'Конфиг вне папки VpnGuard — здесь только просмотр.'}</p>
    <textarea class="log" id="wsconf" spellcheck="false" style="height:55vh"${r.owned ? '' : ' readonly'}>${esc(r.text)}</textarea>
    ${r.owned ? `<div class="row" style="margin-top:8px">${btn('Проверить и сохранить', 'wgConfSave()', true)}</div>` : ''}`;
  $('#modal').style.display = 'flex';
}
async function wgConfSave() {
  if (!confirm('Сохранить конфиг сервера и перезапустить туннель?')) return;
  try { const r = await api('/api/wg/server-conf', { text: $('#wsconf').value }); closeModal(); toast('Конфиг сохранён' + (r.restart ? ' · туннель: ' + r.restart : ', туннель перезапущен')); wgList = null; await P.wg.after(); render(true); } catch (e) { toast(e.message, true); }
}
async function wgBackups() {
  let r; try { r = await api('/api/wg/backups'); } catch (e) { toast(e.message, true); return; }
  const own = wgList && wgList.server && wgList.server.owned;
  $('#mbody').innerHTML = `<div class="row" style="justify-content:space-between"><h1>Резервные копии конфига сервера</h1>${btn('Закрыть', 'closeModal()')}</div>
    <p class="muted">Копия делается перед каждым изменением сервера (последние 30). Восстановление перезапустит туннель; конфиги клиентов на устройствах не меняются.</p>
    ${r.backups.length ? `<table><tr><th>Когда</th><th>Адрес</th><th>Порт</th><th>Клиентов</th><th></th></tr>${r.backups.map(x => `<tr><td>${esc(x.at)}</td><td>${esc(x.address)}</td><td>${esc(x.port)}</td><td>${x.peers}</td><td>${own ? btn('Восстановить', `wgRestore('${esc(x.file)}','${esc(x.at)}')`) : ''}</td></tr>`).join('')}</table>` : '<p class="muted">Копий пока нет.</p>'}`;
  $('#modal').style.display = 'flex';
}
async function wgRestore(file, at) {
  if (!confirm(`Вернуть конфиг сервера на копию от ${at}? Текущий тоже сохранится в копиях. Туннель перезапустится.`)) return;
  try { await api('/api/wg/restore', { file }); closeModal(); toast('Конфиг восстановлен'); wgList = null; await P.wg.after(); render(true); } catch (e) { toast(e.message, true); }
}
async function wgAdopt() {
  if (!confirm('Перенести конфиг сервера WG-Server в папку VpnGuard?\n\nКонфиг сервера и клиентов скопируется в папку VpnGuard, служба туннеля переустановится — клиенты отключатся на несколько секунд и подключатся сами (ключи те же).\nЕсли новый туннель не поднимется, вернётся прежний конфиг.')) return;
  toast('Переношу сервер… (до минуты)');
  try { const r = await api('/api/wg/adopt', {}); toast(`Конфиг перенесён в VpnGuard. Конфигов клиентов перенесено: ${r.imported}`); wgList = null; P.wg.after(); load(); } catch (e) { toast('Не удалось: ' + e.message, true); }
}
async function delClient(ip, name) {
  if (!confirm(`Удалить клиента «${name}» (${ip})? Он сразу перестанет подключаться.`)) return;
  try { await api('/api/wg/remove', { ip }); toast(`Клиент «${name}» удалён`); wgList = null; P.wg.after(); } catch (e) { toast(e.message, true); }
}
async function showConf(ip) { try { const r = await api('/api/wg/conf?ip=' + encodeURIComponent(ip)); showConfText(r.name, ip, r.text); } catch (e) { toast(e.message, true); } }
function showConfText(name, ip, text) {
  $('#mbody').innerHTML = `<div class="row" style="justify-content:space-between"><h1>${esc(name)}</h1>${btn('Закрыть', 'closeModal()')}</div>
    <div class="row" style="align-items:flex-start;margin-top:10px"><img class="qr" src="/api/wg/qr?ip=${encodeURIComponent(ip)}&_=${Date.now()}" alt="QR-код"><div style="flex:1;min-width:260px"><p class="muted">Приложение WireGuard: «+» → «Сканировать QR-код». В конфиге закрытый ключ клиента — никому не пересылайте.</p>
    <pre id="conftext">${esc(text)}</pre><div class="row">${btn('Скопировать', "navigator.clipboard.writeText($('#conftext').textContent).then(()=>toast('Скопировано'))")}${btn('Скачать .conf', `dl('${esc(name)}.conf')`)}</div></div></div>`;
  $('#modal').style.display = 'flex';
}
function dl(fn) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([$('#conftext').textContent], { type: 'text/plain' })); a.download = fn; a.click(); }
function closeModal() { $('#modal').style.display = 'none'; }
P.ics = () => compHead('ics', btn('Восстановить раздачу', "cmd('reapply-ics','восстановление раздачи')")) + timeline('ics') + '<div class="sec">Подробности</div><div class="card">' + kvTable(comp('ics')) + '</div>';
P.zapret = () => {
  const z = comp('zapret') || {}, mode = S.vpn && S.vpn.mode;
  const res = z.results || [], ch = z.checks || [];
  const opts = ['<option value="">(авто) — подбирать автоматически</option>'].concat((z.strategies || []).map(n => { const r = res.find(x => x.name === n); return `<option value="${esc(n)}"${n === z.manual ? ' selected' : ''}>${esc(n)}${r ? ` · ${r.ok} из ${r.total} при подборе` : ''}</option>`; })).join('');
  const bad = c => (c || []).filter(x => !x.ok).map(x => esc(x.n) + ' — ' + esc(x.why)).join('; ');
  return compHead('zapret', (mode !== 'zapret' ? btn(z.enabled ? 'Выключить zapret' : 'Включить zapret', z.enabled ? "cmd('zapret-off','выключение zapret')" : "cmd('zapret-on','включение zapret')", !z.enabled) : '') + btn('Подобрать стратегию', "cmd('zapret-test','подбор стратегии','Подбор займёт 2–4 минуты. Запустить?')") + btn('Обновить zapret', "cmd('zapret-update','обновление zapret')")) +
    (z.vpnWarn ? `<div class="card c1">⚠ ${esc(z.vpnWarn)}<div class="row" style="margin-top:8px">${btn('Выключить zapret', "cmd('zapret-off','выключение zapret')", true)}${btn('Режим «Без VPN»', "setMode('zapret')")}</div></div>` : '') +
    (z.progress ? `<div class="card c1">Идёт подбор: стратегия ${z.progress.index} из ${z.progress.total} · ${esc(z.progress.current)}</div>` : '') +
    `<div class="sec">Версия zapret</div><div class="card"><div class="row"><select id="zver">${['<option value="">последняя — обновляется сама' + (z.latest ? ' (' + esc(z.latest) + ')' : '') + '</option>'].concat((z.versions || []).map(v => `<option value="${esc(v.v)}"${v.v === z.pinned ? ' selected' : ''}>${esc(v.v)} · ${esc(v.date)}${v.pre ? ' · предварительная' : ''}</option>`)).join('')}${z.pinned && !(z.versions || []).some(v => v.v === z.pinned) ? `<option value="${esc(z.pinned)}" selected>${esc(z.pinned)}</option>` : ''}</select>${btn('Установить', 'setZVer()', true)}${btn('Обновить список', "cmd('zapret-releases','список версий zapret')")}</div>
      <p class="muted">Установлена: ${esc(z.version || 'нет')}${z.pinned ? ' · выбранная версия закреплена и сама не обновляется' : ''}. После смены версии агент подберёт стратегию заново (если стратегия не выбрана вручную). Свои списки сохраняются.</p></div>
    <div class="sec">Стратегия</div><div class="card"><div class="row"><select id="strat" style="max-width:100%">${opts}</select>${btn('Применить', "setCfg('zapret.strategy', $('#strat').value, 'стратегия zapret')", true)}${btn('Проверить сайты сейчас', "cmd('zapret-check','проверка сайтов')")}</div>
      <p class="muted">${z.manual ? 'Выбрана вручную: ' + esc(z.manual) : z.current ? 'Подобрана автоматически: ' + esc(z.current) : 'Стратегия ещё не выбрана.'}</p></div>
    <div class="sec">Проверка сайтов сейчас${z.checkedAt ? ' · ' + esc(z.checkedAt) : ''}</div><div class="card">${ch.length ? `<table><tr><th>Что проверяется</th><th class="hide-m">Адрес</th><th>Результат</th><th>Время</th></tr>${ch.map(c => `<tr><td><span class="dot l${c.ok ? 0 : 2}"></span> ${esc(c.n)}</td><td class="hide-m muted">${esc(c.h)}</td><td class="c${c.ok ? 0 : 2}">${c.ok ? (c.mbit ? '≈' + c.mbit + ' Мбит/с' : 'открывается') : esc(c.why)}</td><td>${c.ms >= 0 ? c.ms + ' мс' : '—'}</td></tr>`).join('')}</table>` : '<p class="muted">Проверки ещё не было.</p>'}</div>
    <div class="sec">Результаты подбора</div><div class="card">${res.length ? `<table><tr><th>Стратегия</th><th>Открылось</th><th class="hide-m">Не прошли</th><th></th></tr>${res.map(r => `<tr class="${r.name === z.current ? 'cur' : ''}"><td>${esc(r.name)}</td><td><div class="row" style="flex-wrap:nowrap"><div class="bar"><i class="l${r.ok >= r.total ? 0 : r.ok ? 1 : 2}" style="width:${100 * r.ok / Math.max(1, r.total)}%"></i></div>${r.ok}/${r.total}</div></td><td class="hide-m ${r.error || bad(r.checks) ? 'c2' : 'c0'}" style="font-size:12px">${r.error ? esc(r.error) : bad(r.checks) || (r.checks && r.checks.length ? 'всё открылось' : '')}</td><td>${r.name !== '(без zapret)' && r.name !== z.manual ? btn('Выбрать', `setCfg('zapret.strategy','${esc(r.name)}','стратегия zapret')`) : ''}</td></tr>`).join('')}</table>` : '<p class="muted">Подбора ещё не было.</p>'}</div>` +
    `<div class="sec">Свои списки</div><div class="card" id="zlists"><p class="muted">загрузка…</p></div>` +
    timeline('zapret') + '<div class="sec">Подробности</div><div class="card">' + kvTable(z) + '</div>' + chartBlock('z', 'Трафик мимо VPN — последние 2 часа (оценка)');
};
let zl = null;
P.zapret.after = async () => { if ($('#zlists') && !$('#zltext')) await loadZLists(); };
async function loadZLists(sel) {
  try { zl = await api('/api/zlist'); } catch (e) { $('#zlists').innerHTML = `<p class="err">${esc(e.message)}</p>`; return; }
  const cur = sel || ($('#zlsel') && $('#zlsel').value) || zl.lists[0].name, L = zl.lists.find(x => x.name === cur) || zl.lists[0];
  $('#zlists').innerHTML = !zl.installed ? '<p class="muted">zapret ещё не установлен — включите его, он скачается, затем добавьте списки.</p>' :
    `<div class="row"><select id="zlsel" onchange="loadZLists(this.value)">${zl.lists.map(x => `<option value="${esc(x.name)}"${x.name === L.name ? ' selected' : ''}>${esc(x.title)}</option>`).join('')}</select>
     <span class="sub">${esc(L.name)} · записей: ${L.text.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).length}</span></div>
     <p class="muted">По одному на строку: ${L.kind === 'domain' ? 'youtube.com, rutracker.org … (поддомены включаются сами)' : '1.2.3.4 или 1.2.3.0/24'}. Строки с # — комментарии. После сохранения zapret перезапустится, маршруты пересчитаются.</p>
     <textarea class="log" id="zltext" style="height:200px">${esc(L.text)}</textarea><div class="row" style="margin-top:8px">${btn('Сохранить и применить', `saveZList('${esc(L.name)}')`, true)}</div>`;
}
async function loadZListsKeep(k) { await loadZLists(k.sel); if ($('#zltext')) $('#zltext').value = k.text; }
async function saveZList(name) {
  try { await api('/api/zlist', { name, text: $('#zltext').value }); toast('Список сохранён — zapret применит его'); loadZLists(name); } catch (e) { toast(e.message, true); }
}
// ---------------------------------------------------------------- настройки
let setData = null;
P.settings = () => `<div id="setbox"><p class="muted">загрузка…</p></div>`;
P.settings.after = async () => {
  try { setData = await api('/api/settings'); } catch (e) { $('#setbox').innerHTML = `<p class="err">${esc(e.message)}</p>`; return; }
  const secs = []; for (const x of setData.settings) if (!secs.includes(x.section)) secs.push(x.section);
  const field = x => {
    const id = 'set_' + x.key.replace(/\./g, '_');
    if (x.type === 'bool') return `<label class="row" style="gap:8px"><input type="checkbox" id="${id}" ${x.value ? 'checked' : ''}> включено</label>`;
    if (x.type.startsWith('enum:')) return `<select id="${id}">${x.type.slice(5).split('|').map(v => `<option${v === x.value ? ' selected' : ''}>${esc(v)}</option>`).join('')}</select>`;
    if (x.type.startsWith('int:')) { const p = x.type.split(':'); return `<input type="text" inputmode="numeric" id="${id}" value="${esc(x.value)}" style="width:110px" title="от ${p[1]} до ${p[2]}">`; }
    return `<input type="text" id="${id}" value="${esc(x.value)}" style="width:100%;max-width:420px">`;
  };
  $('#setbox').innerHTML = secs.map(sec => `<div class="sec">${esc(sec)}</div><div class="card"><table class="kv">${setData.settings.filter(x => x.section === sec).map(x => `<tr><td>${esc(x.label)}${x.hint ? `<div class="sub">${esc(x.hint)}</div>` : ''}</td><td>${field(x)}</td></tr>`).join('')}</table></div>`).join('') +
    `<div class="card row">${btn('Сохранить', 'saveSettings()', true)}${btn('Отменить изменения', "render(true)")}<span class="sub">Источник обновлений VpnGuard: github.com/${esc(setData.repo)} (меняется только в config.json). Пароль и удалённая диагностика — на вкладке «Диагностика».</span></div>`;
};
async function saveSettings() {
  const ch = {};
  for (const x of setData.settings) {
    const el = $('#set_' + x.key.replace(/\./g, '_')); if (!el) continue;
    const v = x.type === 'bool' ? el.checked : el.value.trim();
    if (String(v) !== String(x.value)) ch[x.key] = v;
  }
  if (!Object.keys(ch).length) { toast('Изменений нет'); return; }
  try { const r = await api('/api/settings', ch); toast(`Сохранено настроек: ${r.changed} — агент применит их сам`); render(true); } catch (e) { toast(e.message, true); }
}
P.traffic = () => {
  const days = ((S.traffic && S.traffic.days) || []).slice().reverse();
  return chartBlock('u', 'Туннель — последние 2 часа') + chartBlock('w', 'WG-Server (клиенты) — последние 2 часа') + chartBlock('p', 'Физический адаптер — последние 2 часа') +
    `<div class="sec">По дням</div><div class="card"><table><tr><th>День</th><th>Туннель ↓ / ↑</th><th class="hide-m">WG-Server ↓ / ↑</th><th class="hide-m">Физический ↓ / ↑</th></tr>${days.map(d => `<tr><td>${esc(d.d)}</td><td>${fmtB(d.u[0])} / ${fmtB(d.u[1])}</td><td class="hide-m">${fmtB(d.w[0])} / ${fmtB(d.w[1])}</td><td class="hide-m">${fmtB(d.p[0])} / ${fmtB(d.p[1])}</td></tr>`).join('')}</table></div>`;
};
P.system = () => {
  const sw = S.software || [], app = S.app || {}, rm = S.remote || {};
  return `<div class="sec">VpnGuard</div><div class="card"><p>Версия <b>${esc(app.version || S.agentVersion)}</b>${app.build ? ' (сборка ' + esc(app.build) + ')' : ''}${app.repo ? ' · источник github.com/' + esc(app.repo) : ' · автообновление не настроено'}
      ${app.error ? `<br><span class="c2">${esc(app.error)}</span>` : app.pending > 0 ? `<br><span class="c1">Доступна ${esc(app.latestVersion)} (${esc(app.latestBuild)}), файлов: ${app.pending}</span>` : app.checkedAt ? '<br><span class="c0">Актуальная версия</span>' : ''}</p>
      <div class="row">${btn('Обновить сейчас', "cmd('app-update','обновление VpnGuard')", true)}${btn('Проверить', "cmd('app-check','проверка обновления')")}
      <label class="row" style="gap:6px"><input type="checkbox" ${app.auto ? 'checked' : ''} onchange="setCfg('update.auto', this.checked, 'автообновление')"> ставить обновления само</label></div></div>
    <div class="sec">Компоненты</div><div class="card"><table><tr><th>Компонент</th><th>Установлено</th><th class="hide-m">Последняя</th><th>Состояние</th><th></th></tr>${sw.map(s => `<tr><td>${esc(s.name)}<div class="sub">${esc(s.purpose)}</div></td><td>${esc(s.installed || '—')}</td><td class="hide-m">${esc(s.latest || '—')}</td><td class="${s.error ? 'c2' : s.update ? 'c1' : ''}">${esc(s.error || s.status || (s.update ? 'есть обновление' : s.installed ? 'установлен' : s.needed ? 'нужен' : 'не нужен'))}</td><td>${btn(s.installed ? (s.update ? 'Обновить' : 'Переустановить') : 'Установить', `cmd('install ${esc(s.id)}','установка ${esc(s.name)}','Установить или обновить «${esc(s.name)}»?')`)}</td></tr>`).join('')}</table>
      <div class="row" style="margin-top:10px">${btn('Установить всё нужное', "cmd('install-missing','установка недостающих','Установить всё, что нужно для текущего режима?')")}${btn('Проверить версии', "cmd('software-check','проверка версий')")}</div></div>
    <div class="sec">Удалённая диагностика</div><div class="card"><p class="muted">${rm.enabled ? 'Включена до ' + new Date(rm.until).toLocaleString() + ` · запросов: ${rm.requests}` : 'Выключена. Включается в окне VpnGuard на этом ПК (вкладка «Диагностика»).'}</p></div>`;
};
let diagText = '';
// модули агента: состояние, нагрузка (по разнице двух снимков), ошибки; события между модулями
let PERF0 = null;
const MODEV = { 'tunnel.switched': 'туннель переключён', 'tunnel.reconnected': 'туннель переподключён', 'mode.changed': 'режим сменился', 'wg.restarted': 'WG-Server перезапущен',
  'ics.reapply': 'перенастроить раздачу', 'inet.lost': 'интернет пропал', 'inet.restored': 'интернет вернулся' };
function cpuNow() {
  const p = S && S.perf; if (!p) return {};
  const prev = PERF0 && PERF0.uptime < p.uptime ? PERF0 : null, out = {};
  for (const k in p.threads) out[k] = prev && prev.threads[k] !== undefined ? 100 * (p.threads[k] - prev.threads[k]) / (p.uptime - prev.uptime) : 100 * p.threads[k] / Math.max(1, p.uptime);
  out._total = prev ? 100 * (p.total - prev.total) / (p.uptime - prev.uptime) : 100 * p.total / Math.max(1, p.uptime);
  if (!PERF0 || p.uptime - PERF0.uptime >= 30 || p.uptime < PERF0.uptime) PERF0 = JSON.parse(JSON.stringify(p));   // окно ~30 с
  return out;
}
const pct = v => v === undefined || isNaN(v) ? '—' : (v < 0.05 ? '0' : v.toFixed(v < 10 ? 1 : 0)) + ' %';
const agoS = s => s < 0 ? 'ещё не было' : s < 60 ? s + ' с назад' : Math.round(s / 60) + ' мин назад';
function modsHtml() {
  const ms = (S && S.modules) || []; if (!ms.length) return '<p class="muted">Агент этой версии не сообщает о модулях.</p>';
  const cpu = cpuNow(), mod = new Set(ms.map(m => 'модуль: ' + m.title));
  const rows = ms.map(m => {
    const st = m.lastError ? `<span class="c2">ошибка</span>` : m.busy && m.busySec >= 10 ? `<span class="c1">занят ${m.busySec} с${m.doing ? ': ' + esc(m.doing) : ''}</span>` : m.busy ? `<span class="c0">проверяет</span>` : `<span class="c0">ждёт</span>`;
    return `<tr><td><b>${esc(m.title)}</b><div class="sub">${esc(m.name)}</div></td><td>${st}</td><td>${agoS(m.lastAgo)}</td><td>${m.runs}</td><td class="${m.errors ? 'c2' : ''}">${m.errors}</td><td>${pct(cpu['модуль: ' + m.title])}</td><td class="sub">${esc(m.lastError || '')}</td></tr>`;
  }).join('');
  const other = Object.keys(cpu).filter(k => k !== '_total' && !mod.has(k)).sort((a, b) => cpu[b] - cpu[a])
    .map(k => `<tr><td>${esc(k)}</td><td colspan="4" class="sub">отдельный поток</td><td>${pct(cpu[k])}</td><td></td></tr>`).join('');
  return `<table><tr><th>Модуль</th><th>Состояние</th><th>Последняя проверка</th><th>Проверок</th><th>Ошибок</th><th>Процессор</th><th class="hide-m">Последняя ошибка</th></tr>${rows}${other}
    <tr><td><b>Агент всего</b></td><td colspan="4" class="sub">работает ${Math.round(((S.perf && S.perf.uptime) || 0) / 60)} мин</td><td><b>${pct(cpu._total)}</b></td><td></td></tr></table>
    <p class="sub" style="margin-top:8px">Процессор — доля одного ядра за последние ~30 с. Каждый модуль работает в своём потоке: занятый модуль не задерживает остальные.</p>`;
}
function evtsHtml() {
  const ev = (S && S.events) || []; if (!ev.length) return '<p class="muted">Событий пока не было — модули сообщают друг другу о переключении туннеля, смене режима, пропаже и возвращении интернета.</p>';
  return `<table><tr><th>Время</th><th>Событие</th><th>Подробности</th><th>От кого</th><th>Кому</th></tr>${ev.map(e => `<tr><td>${esc(e.at)}</td><td>${esc(MODEV[e.name] || e.name)}<div class="sub">${esc(e.name)}</div></td><td>${esc(e.info)}</td><td class="sub">${esc(e.from)}</td><td class="sub">${esc(e.to || '—')}</td></tr>`).join('')}</table>`;
}
P.diag = () => `<div class="sec">Модули агента</div><div class="card" id="mods">${modsHtml()}</div>
  <div class="sec">События между модулями</div><div class="card" id="evts">${evtsHtml()}</div>
  <div class="sec">Вход в веб-интерфейс</div><div class="card" id="webset"><p class="muted">загрузка…</p></div>
  <div class="sec">Удалённая диагностика</div><div class="card" id="remote"><p class="muted">загрузка…</p></div>
  <div class="sec">Отчёт «Диагностика»</div><div class="card"><div class="row">${btn('Собрать отчёт', 'runDiag()', true)}${btn('Скопировать', "navigator.clipboard.writeText(diagText).then(()=>toast('Скопировано'))")}${btn('Скачать', "dlText('vpnguard-diag.txt', diagText)")}<span class="sub" id="dstate"></span></div><pre id="dtext" style="max-height:60vh;overflow:auto;margin-top:10px">${esc(diagText || 'Нажмите «Собрать отчёт» (до минуты). Ключей и паролей в отчёте нет.')}</pre></div>`;
P.diag.after = async () => { await loadWebSet(); await loadRemote(); };
async function loadWebSet() {
  let w; try { w = await api('/api/websettings'); } catch (e) { $('#webset').innerHTML = `<p class="err">${esc(e.message)}</p>`; return; }
  $('#webset').innerHTML = `<p>Адрес: <b>http://localhost:${w.port}/</b> на этом ПК; с других устройств — по адресу ПК в домашней сети или через WG-Server.</p>
    <label class="row" style="gap:8px"><input type="checkbox" id="reqpw" ${w.requirePassword ? 'checked' : ''} onchange="setReqPw(this.checked)"> Требовать пароль с других устройств</label>
    <p class="muted">${w.requirePassword ? 'С этого ПК пароль не нужен никогда.' : 'Пароль не нужен из домашней сети и от клиентов WG-Server. Из интернета (если открыта удалённая диагностика «откуда угодно») пароль нужен всегда.'}</p>
    ${w.local && w.password ? `<p>Текущий пароль: <code>${esc(w.password)}</code></p>` : ''}
    <div class="row"><input type="password" id="newpw" placeholder="новый пароль (6–64 символа)" autocomplete="new-password">${btn('Сохранить пароль', 'setPw()')}</div>`;
}
async function setReqPw(on) {
  if (!on && !confirm('Отключить пароль? Веб-интерфейсом смогут управлять все устройства домашней сети и клиенты WG-Server.')) { loadWebSet(); return; }
  try { await api('/api/websettings', { requirePassword: on }); toast(on ? 'Пароль снова нужен' : 'Пароль в домашней сети не нужен'); } catch (e) { toast(e.message, true); }
  loadWebSet();
}
async function setPw() {
  const v = $('#newpw').value;
  try { await api('/api/websettings', { password: v }); toast('Пароль изменён — на других устройствах нужно войти заново'); } catch (e) { toast(e.message, true); }
  loadWebSet();
}
async function loadRemote() {
  let r; try { r = await api('/api/remote'); } catch (e) { $('#remote').innerHTML = `<p class="err">${esc(e.message)}</p>`; return; }
  const addrs = [].concat(r.publicIp ? [`http://${r.publicIp}:${r.port}/  (через интернет — нужен проброс TCP ${r.port} на роутере)`] : [], (r.ips || []).map(a => `http://${a.ip}:${r.port}/  (сеть «${a.alias}»)`));
  const conn = r.enabled ? ['VpnGuard — удалённая диагностика (до ' + new Date(r.until).toLocaleString() + ')'].concat(addrs, ['Токен: ' + r.token, `Пример: curl -H "X-Token: ${r.token}" http://АДРЕС:${r.port}/bundle`]).join('\n') : '';
  $('#remote').innerHTML = r.enabled
    ? `<p><span class="dot l0"></span> <b>Включена</b> до ${esc(new Date(r.until).toLocaleString())} · ${r.allowFrom === 'local' ? 'только домашняя сеть и WG-Server' : 'откуда угодно'} · тесты и переподключения ${r.allowActions ? 'разрешены' : 'запрещены'} · запросов: ${r.requests}</p>
       <pre id="conn">${esc(conn)}</pre><div class="row">${btn('Скопировать данные для подключения', "navigator.clipboard.writeText($('#conn').textContent).then(()=>toast('Скопировано — отправьте вместе с сообщением'))", true)}${btn('Выключить', 'setRemote(false)')}</div>`
    : `<p class="muted">Выключена. По адресу ПК и токену можно будет читать состояние, журналы, сеть и запускать проверки. Ключи скрыты, выключается сама по таймеру.</p>
       <div class="row"><select id="rhours"><option value="2">на 2 ч</option><option value="8">на 8 ч</option><option value="24" selected>на 24 ч</option><option value="72">на 72 ч</option></select>
       <select id="rfrom"><option value="local">только домашняя сеть и WG-Server</option><option value="any">откуда угодно (через интернет)</option></select>
       <label class="row" style="gap:6px"><input type="checkbox" id="ract"> разрешить тесты и переподключения</label>${btn('Включить', 'setRemote(true)', true)}</div>`;
}
async function setRemote(on) {
  const b = on ? { enable: true, hours: +$('#rhours').value, allowFrom: $('#rfrom').value, allowActions: $('#ract').checked } : { enable: false };
  if (on && b.allowFrom === 'any' && !confirm('Открыть доступ из интернета? Соединение не шифруется; нужен проброс порта на роутере.')) return;
  try { await api('/api/remote', b); toast(on ? 'Удалённая диагностика включена' : 'Удалённая диагностика выключена'); } catch (e) { toast(e.message, true); }
  setTimeout(loadRemote, 1500);
}
async function runDiag() {
  $('#dstate').textContent = 'собираю… (до минуты)'; const t0 = Date.now();
  try { diagText = await api('/api/diag-run', {}); $('#dtext').textContent = diagText; $('#dstate').textContent = `готово за ${Math.round((Date.now() - t0) / 1000)} с`; } catch (e) { $('#dstate').textContent = e.message; }
}
function dlText(fn, text) { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); a.download = fn; a.click(); }
P.logs = () => `<div class="card row"><select id="lmin" onchange="loadLog()"><option value="60">за 1 час</option><option value="360">за 6 часов</option><option value="1440" selected>за сутки</option><option value="4320">за 3 дня</option></select>
  <select id="llev" onchange="showLog()"><option value="">все</option><option value="WARN|ERROR">предупреждения и ошибки</option><option value="ERROR">только ошибки</option></select>
  <input type="text" id="lq" placeholder="поиск" oninput="showLog()">${btn('Обновить', 'loadLog()')}</div><pre class="log lgv" id="log"></pre>`;
P.logs.after = () => { if (!logCache) loadLog(); else showLog(); };
async function loadLog() { const m = +($('#lmin') || { value: 1440 }).value; try { logCache = await api(`/api/logs?minutes=${m}&days=${Math.ceil(m / 1440) + 1}&lines=6000`); showLog(); } catch (e) { toast(e.message, true); } }
function showLog() { const lev = $('#llev').value, q = $('#lq').value.toLowerCase(); let l = logCache.split('\n'); if (lev) l = l.filter(s => new RegExp('\\[(' + lev + ')\\]').test(s)); if (q) l = l.filter(s => s.toLowerCase().includes(q)); $('#log').innerHTML = logHtml(l.reverse()); }
// строки журнала: [ERROR] — красным, [WARN] — жёлтым
function logHtml(lines) { return lines.map(s => { const c = /\[ERROR\]/.test(s) ? 'le' : /\[WARN\]/.test(s) ? 'lw' : 'li'; return `<span class="${c}">${esc(s)}</span>`; }).join('\n'); }

// ---------------------------------------------------------------- отрисовка
function render(force) {
  if (!S) return;
  // во время ввода (выбор в списке, поиск) не перерисовывать
  const ae = document.activeElement; if (!force && ae && ['SELECT', 'INPUT', 'TEXTAREA'].includes(ae.tagName) && page !== 'home') return;
  if ((page === 'logs' && $('#log') || page === 'diag' && $('#remote') || page === 'settings' && $('#setbox')) && !force) return;
  const keep = page === 'zapret' && $('#zltext') ? { text: $('#zltext').value, sel: $('#zlsel') && $('#zlsel').value } : null;
  const dirty = {}; for (const e of document.querySelectorAll('#page [data-keep]')) if (e.id && e.value !== e.defaultValue) dirty[e.id] = e.value;
  if (!force && page === 'home' && $('#hflow')) { $('#htop').innerHTML = P.home.top(); $('#htiles').innerHTML = P.home.tiles(); }   // схему и журнал не трогаем
  else $('#page').innerHTML = (P[page] || P.home)();
  for (const [id, v] of Object.entries(dirty)) { const e = document.getElementById(id); if (e) e.value = v; }
  for (const cv of document.querySelectorAll('canvas[data-chart]')) drawChart(cv, cv.dataset.chart);
  if (keep && keep.text !== undefined && zl) { loadZListsKeep(keep); } else if (P[page] && P[page].after) P[page].after();
}
function go() {
  page = (location.hash || '#home').slice(1); if (!P[page]) page = 'home';
  $('#title').textContent = NAMES[page];
  for (const a of document.querySelectorAll('nav a')) a.classList.toggle('sel', a.dataset.p === page);
  nav.classList.remove('open'); logCache = ''; if (page === 'home') P.home.histAt = 0; render(true);
}
const nav = $('#nav');
window.addEventListener('hashchange', go);
window.addEventListener('resize', () => { for (const cv of document.querySelectorAll('canvas[data-chart]')) drawChart(cv, cv.dataset.chart); });
(async () => {
  try { const w = await (await fetch('/api/whoami')).json(); if (!w.role) { showLogin(); return; } } catch (e) { }
  await load(); go(); timer = setInterval(load, 3000); setInterval(liveTick, 1000);
})();
