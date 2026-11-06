'use strict';
// VpnGuard — схема трафика на главной: узлы, связи, стрелки, мини-графики, кнопки узлов. Данные — из app.js (S, LIVE).
// ---------------------------------------------------------------- схема трафика: кто с кем соединён и сколько пропускает
// Узлы и подписи — из снимка агента (S), скорости — из «живого» снимка (/api/live, раз в 2 с), пока его нет — из S.
// Связь — две полосы стрелок: «>>>>» — от клиента к интернету (отдача), «<<<<» — обратно (загрузка); чем больше трафика, тем быстрее.
// «Мимо VPN» и «программы ПК» — оценка: физический − туннель − зашифрованный трафик клиентов.
let LIVE = null, FL = null;
const FLP = 11;                                  // шаг стрелок: символ 10px Consolas (0,55 em = 5,5) + разрядка 5,5
// связь с агентом: живые данные не приходят (веб-сервер не отвечает) или не обновляются (агент не работает) — схема не показывает старые скорости
let FLOW_OFF = '', LIVE_T = 0, LIVE_AT = 0, LIVE_FAILS = 0;
function flowOffline() {
  if (LIVE_FAILS >= 2) return 'нет связи с веб-интерфейсом VpnGuard';
  if (LIVE_AT && Date.now() - LIVE_AT > 12000) return 'агент не присылает данные ' + Math.round((Date.now() - LIVE_AT) / 1000) + ' с';
  return '';
}
function flowModel() {
  const tr = S.traffic || {}, nm = tr.names || {}, wgc = comp('wg') || {}, cz = wgc.clientZapret || {};
  const off = !!FLOW_OFF;
  const R = off ? {} : (LIVE && LIVE.rate) || tr.rate || {}, LP = off ? {} : (LIVE && LIVE.peers) || null;
  const mode = (S.vpn && S.vpn.mode) || 'meduza', vpnOn = mode !== 'zapret';
  const r2 = k => [+(R[k] || [])[0] || 0, +(R[k] || [])[1] || 0];
  const u = vpnOn ? r2('u') : [0, 0], w = r2('w'), pAll = r2('p');
  // локальная сеть (агент считает её отдельно): из «интернета» вычитается, у программ ПК — своя связь
  const lanI = tr.lan || {}, lanOn = !!lanI.on, l = lanOn ? r2('l') : [0, 0];
  const p = [Math.max(0, pAll[0] - l[0]), Math.max(0, pAll[1] - l[1])];
  const byp = vpnOn ? [Math.max(0, p[0] - u[0] - w[0]), Math.max(0, p[1] - u[1] - w[1])] : [Math.max(0, p[0] - w[0]), Math.max(0, p[1] - w[1])];
  const apps = [Math.max(0, u[0] + byp[0] + l[0] - w[1]), Math.max(0, u[1] + byp[1] + l[1] - w[0])];
  const czr = off ? [0, 0] : (LIVE && LIVE.cz) || cz.rate || [0, 0];
  const peers = (wgc.peers || []).slice().sort((a, b) => (b.active - a.active) || String(a.name).localeCompare(String(b.name)));
  const shown = peers.slice(0, 6), more = peers.length - shown.length;
  const pr = c => { const l = LP && LP[c.ip]; return off ? [0, 0] : l ? [+l.tx || 0, +l.rx || 0] : [+c.txRate || 0, +c.rxRate || 0]; };
  const N = [], E = [];
  shown.forEach((c, i) => {
    const on = !c.off && c.active, r = on ? pr(c) : [0, 0];
    const nm0 = String(c.name || c.ip).replace(/['"\\]/g, '');
    N.push({ id: 'c' + i, col: 0, href: '#wg', dot: on ? 0 : -1, dim: !on, t1: c.name || c.ip, r: on ? r : null,
      acts: [c.off ? { t: '⏻', tip: 'Включить клиента', fn: `cliSet('${c.ip}',{off:false},'${nm0}')` } : { t: '⏻', bad: 1, tip: 'Отключить клиента', fn: `cliSet('${c.ip}',{off:true},'${nm0}')` }],
      t3: c.off ? 'отключён' : !c.active ? 'не на связи' : c.zapret === false ? 'zapret выкл — всё через VPN' : c.cz ? `zapret: ${c.cz.conns || 0} соед.${c.cz.vpn ? ' · не ответили ' + c.cz.vpn : ''}` : c.ip });
    E.push({ a: 'c' + i, b: 'wg', r, c: 'var(--accent)', off: !on });
  });
  if (more > 0) { N.push({ id: 'cm', col: 0, href: '#wg', dot: -1, dim: true, t1: `ещё ${more}`, r: null, t3: 'на вкладке WG-Server' }); E.push({ a: 'cm', b: 'wg', r: [0, 0], c: 'var(--accent)', off: true }); }
  N.push({ id: 'apps', col: 0, dot: -1, t1: 'Программы ПК', r: apps, t3: 'оценка' });
  N.push({ id: 'wg', col: 1, href: '#wg', dot: lvl(wgc), acts: [{ t: '⟳', tip: 'Перезапустить wg_server', fn: "cmd('restart-wg','перезапуск wg_server','Перезапустить wg_server? Клиенты переподключатся.')" }], t1: 'WG-Server', r: [w[1], w[0]], t3: `на связи ${peers.filter(x => x.active).length} из ${peers.length}` });
  N.push({ id: 'pc', col: 2, href: '#ics', dot: lvl(comp('ics')), acts: [{ t: '⟳', tip: 'Восстановить раздачу (ICS)', fn: "cmd('reapply-ics','восстановление раздачи')" }], t1: 'Маршрутизация', r: null, t3: 'раздача ICS' + (cz.running ? ` · zapret ↓ ${mbs(czr[0])}` : vpnOn ? ' из туннеля' : ' напрямую'),
    t4: cz.running && cz.bypass ? `${cz.bypass} адр. временно через VPN` : '' });
  // какой туннель несёт трафик; в режиме «два туннеля» второй — отдельным узлом «Резерв»
  const KN = { meduza: 'MeduzaVPN', amnezia: 'AmneziaVPN' }, kind = (S.vpn && S.vpn.kind) || (mode === 'amnezia' ? 'amnezia' : 'meduza'), other = kind === 'meduza' ? 'amnezia' : 'meduza';
  const sb = (comp('ultra') || {}).standby || {}, rd = sb.ok === true;
  const tun = k => k === kind
    ? { col: 3, href: '#' + k, dot: lvl(comp('ultra')), acts: [{ t: '⟳', tip: 'Переподключить ' + KN[k], fn: "cmd('reconnect','переподключение туннеля')" }], c: 'var(--vpn)', t1: KN[k], r: u, t3: (mode === 'dual' ? 'активный · ' : '') + (nm.u || 'туннель') }
    : { col: 3, href: '#' + k, dot: sb.blocked ? 2 : rd ? 0 : sb.up ? 1 : 2, dim: true, c: 'var(--vpn)', t1: KN[k], r: null,
        acts: [{ t: '⇄', tip: 'Сделать активным — переключить трафик на ' + KN[k], fn: `cmd('dual-switch','переключение на ${KN[k]}','Переключить трафик на ${KN[k]}?${rd ? '' : ' Он сейчас не проходит проверку — клиенты могут остаться без интернета.'}')` }],
        t3: 'резерв: ' + (sb.nested ? sb.nested : sb.state ? (rd ? 'готов, трафик проходит' : sb.state === 'нет трафика' ? (sb.why || 'НЕ пропускает трафик') : sb.state) : 'нет данных'), tip: sb.nested ? `${KN[k]} ${sb.nested}. При сбое ${KN[kind]} упадут оба — нужен другой сервер или протокол для ${KN[k]}.` : '' };
  // место узла закреплено за туннелем: vpn — MeduzaVPN, vpn2 — AmneziaVPN (в одиночном режиме — только vpn)
  const slot1 = mode === 'dual' ? 'meduza' : kind, slot2 = 'amnezia';
  if (vpnOn) N.push(Object.assign({ id: 'vpn' }, tun(slot1)));
  if (mode === 'dual') N.push(Object.assign({ id: 'vpn2' }, tun(slot2)));
  if (lanOn) N.push({ id: 'lan', col: 3, dot: 0, c: 'var(--lan)', t1: 'Локальная сеть', r: l, t3: (lanI.net || 'домашняя сеть') + ' · не интернет' });
  const zc = comp('zapret'), zOn = !!(zc && zc.enabled);
  N.push({ id: 'zp', col: 3, href: '#zapret', dot: lvl(comp('zapret')), acts: vpnOn ? [zOn ? { t: '⏻', bad: 1, tip: 'Выключить zapret', fn: "cmd('zapret-off','выключение zapret')" } : { t: '⏻', tip: 'Включить zapret', fn: "cmd('zapret-on','включение zapret','Включить zapret? YouTube и Discord этого ПК пойдут мимо VPN.')" }] : [], c: 'var(--zp)', t1: 'zapret', r: byp, t3: vpnOn ? 'YouTube, Discord …' : '' });
  const ni = comp('inet') || {}, nOk = off ? -1 : LIVE && LIVE.inet !== undefined ? LIVE.inet : ni.directDown ? 3 : ni.level === 0 ? 0 : ni.level === 2 ? 1 : ni.unstable ? 2 : -1;
  const gwT = ni.gw ? `роутер ${ni.gw}` + (ni.gwMs >= 0 ? ` ${ni.gwMs} мс` : ' не отвечает') : '';
  const pingT = ni.ms > 0 ? `${ni.ms} мс до ${ni.hostName || ni.host}` : ni.ms === 0 ? 'есть через туннель' : '';
  N.push({ id: 'net', col: 4, dot: nOk === 0 ? 0 : nOk === 1 ? 2 : nOk === 2 || nOk === 3 ? 1 : -1, dim: nOk === 1, t1: nOk === 1 ? 'Интернет · НЕТ СВЯЗИ' : nOk === 2 ? 'Интернет · НЕСТАБИЛЕН' : nOk === 3 ? 'Интернет · ТОЛЬКО VPN' : 'Интернет', r: p,
    t3: nOk === 1 ? (ni.details && ni.details[0]) || 'провайдер не отвечает' : nOk === 3 ? 'напрямую не пропускает · zapret ждёт' : nOk === 2 ? `провалов ${ni.loss || 0} из 12 за минуту` : pingT || (nm.p || 'физический адаптер'),
    tip: `Проверка интернета: TCP-подключение напрямую через ${nm.p || 'физический адаптер'} (мимо VPN) к ${(ni.kv || []).filter(x => x[0] === 'Узлы проверки').map(x => x[1])[0] || 'публичным узлам'}.\n` +
      (pingT ? `Последний отклик: ${pingT}${ni.host && ni.host !== 'через туннель' ? ' (' + ni.host + ')' : ''}, ответило ${ni.okHosts} из ${ni.hosts}.\n` : '') + (gwT ? gwT.replace(/^р/, 'Р') + ' (ping).' : '') });
  E.push({ a: 'wg', b: 'pc', r: [w[1], w[0]], c: 'var(--accent)' });
  E.push({ a: 'apps', b: 'pc', r: apps, c: 'var(--dim)' });
  // трафик — к узлу активного туннеля; к резервному — пустые связи
  const actId = mode === 'dual' && kind === 'amnezia' ? 'vpn2' : 'vpn', idleId = actId === 'vpn' ? 'vpn2' : 'vpn';
  if (vpnOn) { E.push({ a: 'pc', b: actId, r: u, c: 'var(--vpn)' }); E.push({ a: actId, b: 'net', r: u, c: 'var(--vpn)' }); }
  if (mode === 'dual') { E.push({ a: 'pc', b: idleId, r: [0, 0], c: 'var(--vpn)', off: true }); E.push({ a: idleId, b: 'net', r: [0, 0], c: 'var(--vpn)', off: true }); }
  E.push({ a: 'pc', b: 'zp', r: byp, c: 'var(--zp)' });
  if (lanOn) E.push({ a: 'pc', b: 'lan', r: l, c: 'var(--lan)', near: true }); E.push({ a: 'zp', b: 'net', r: byp, c: 'var(--zp)' });
  return { N, E, key: N.map(n => n.id + (n.dim ? '-' : '+')).join(',') + '|' + vpnOn + '|' + kind + '|' + zOn };
}
const mbs = v => { v = (+v || 0) * 8; return v >= 1e7 ? (v / 1e6).toFixed(0) : v >= 1e5 ? (v / 1e6).toFixed(1) : v >= 1e3 ? (v / 1e6).toFixed(2) : '0'; };
// скорость стрелок, пикс/с: 0 — стоят; дальше растёт с логарифмом трафика
const laneSpeed = r => (r = +r || 0) < 400 ? 0 : 12 + 20 * Math.log10(r / 400);

// кнопки узла: справа сверху; клик не открывает вкладку узла
const FBS = 20, FBG = 5, FLB = {};
// кнопка узла нажата и команда ушла агенту — узел «в работе»: бегущая рамка и «выполняется …», пока агент занят (не дольше 45 с)
async function flowAct(id, p, what) {
  if (!(await p)) return;
  FLB[id] = { until: Date.now() + 45000, from: Date.now(), what: String(what || '').toLowerCase() };
  flowBusyPaint();
}
function flowBusyPaint() {
  if (!FL || !FL.svg) return;
  const now = Date.now();
  for (const id in FLB) {
    const b = FLB[id], g = FL.svg.querySelector(`#fln-${id}`);
    // готово: время вышло или агент уже ничем не занят (после первых 8 с)
    const done = now > b.until || (now - b.from > 8000 && S && !S.activity);
    if (g) g.classList.toggle('busy', !done);
    const t = FL.svg.querySelector(`#fl-${id}-3`);
    if (t && !done) t.textContent = '⟳ ' + clip(b.what + (S && S.activity ? ' · ' + S.activity : '') + ' …', +t.dataset.w + 20 || 200, 6.1);
    if (done) delete FLB[id];
  }
}                         // кнопка узла: квадрат 20 px, зазор 5
function flowBtns(n) {
  let out = ''; const x = n.x + n.w - FBS - 8;
  (n.acts || []).forEach((a, i) => {
    const y = n.y + 8 + i * (FBS + FBG);
    out += `<g class="fl-btn${a.bad ? ' bad' : ''}" onclick="event.preventDefault();event.stopPropagation();flowAct('${n.id}', ${esc(a.fn)}, '${esc(a.tip)}')"><title>${esc(a.tip)}</title>
      <rect x="${x}" y="${y}" width="${FBS}" height="${FBS}" rx="2"/><text x="${x + FBS / 2}" y="${y + 14}" text-anchor="middle">${esc(a.t)}</text></g>`;
  });
  return out;
}
function flowBuild(m) {
  const { N, E } = m, byId = {}; N.forEach(n => byId[n.id] = n);
  const W = 200, H = 84, G = 14, X = [0, 265, 510, 755, 1000], VW = X[4] + W, TOP = 24, APPG = 18;
  const col0 = N.filter(n => n.col === 0), cli = col0.filter(n => n.id !== 'apps');
  // столбец туннелей: над серединой — VPN (и резерв) с подписью рамки, под ней — zapret и локальная сеть
  const up3 = (byId.vpn2 ? 2 * H + 28 : byId.vpn ? H + 14 : H / 2) + (byId.vpn ? 26 : 0), dn3 = (byId.lan ? 2 * H + 28 : H + 14) + 4;
  const VH = Math.max(TOP + col0.length * (H + G) - G + APPG, 2 * Math.max(up3, dn3)) + 4, mid = VH / 2;
  col0.forEach((n, i) => Object.assign(n, { x: X[0], y: TOP + i * (H + G) + (n.id === 'apps' ? APPG : 0) }));
  for (const n of N) if (n.col > 0) Object.assign(n, { x: X[n.col], y: mid - H / 2 });
  if (cli.length && byId.wg) byId.wg.y = (cli[0].y + cli[cli.length - 1].y) / 2;
  if (byId.vpn) { byId.vpn.y = mid - H - 14; byId.zp.y = mid + 14; }
  if (byId.vpn2) byId.vpn2.y = byId.vpn.y - H - 14;
  if (byId.lan) { if (!byId.vpn) byId.zp.y = mid - H / 2; byId.lan.y = byId.zp.y + H + 14; }
  N.forEach(n => { n.w = W; n.h = H; });
  // точки подключения: связи одной стороны узла разносятся по ней (по высоте источника/приёмника — без перекрёстков)
  const sides = {};
  E.forEach((e, i) => { (sides[e.a + 'r'] = sides[e.a + 'r'] || []).push(i); (sides[e.b + 'l'] = sides[e.b + 'l'] || []).push(i); });
  for (const k in sides) sides[k].sort((i, j) => { const o = k.endsWith('r') ? 'b' : 'a'; return byId[E[i][o]].y - byId[E[j][o]].y; });
  const portY = (n, s, i) => { const l = sides[n.id + s], f = (l.indexOf(i) + 1) / (l.length + 1); return n.y + 10 + f * (n.h - 20); };
  // вертикаль связи: если в узел входит несколько — у каждой своя, ближе к узлу — те, что ближе к краю (верхние сверху, нижние снизу)
  const vx = (e, i, x1, x2, y1, y2) => {
    const l = sides[e.b + 'l']; if (l.length < 2) return (x1 + x2) / 2;
    const B = byId[e.b], c = B.y + B.h / 2, srcY = j => byId[E[j].a].y + H / 2;
    const above = l.filter(j => srcY(j) < c - 1), below = l.filter(j => srcY(j) > c + 1).reverse();
    const ra = above.indexOf(i), rb = below.indexOf(i), rank = ra >= 0 ? ra : rb >= 0 ? rb : 0;
    return x2 - 20 - rank * 18;
  };
  let defs = '', links = '';
  E.forEach((e, i) => {
    const A = byId[e.a], B = byId[e.b], x1 = A.x + W, x2 = B.x, y1 = portY(A, 'r', i), y2 = portY(B, 'l', i), mx0 = e.near ? x1 + 12 : vx(e, i, x1, x2, y1, y2);
    for (const [lane, off] of [['u', -3.5], ['d', 3.5]]) {
      // ломаная со скошенными изломами; «туда» и «обратно» идут рядом и не пересекаются
      const d = y2 - y1, mx = mx0 + (d > 0 ? -off : off), a = y1 + off, b = y2 + off, c = Math.min(8, Math.abs(d) / 2), sg = Math.sign(d);
      const pts = Math.abs(d) < 1 ? [[x1, a], [x2, b]] : [[x1, a], [mx - c, a], [mx, a + sg * c], [mx, b - sg * c], [mx + c, b], [x2, b]];
      let len = 0; for (let k = 1; k < pts.length; k++) len += Math.hypot(pts[k][0] - pts[k - 1][0], pts[k][1] - pts[k - 1][1]);
      const id = `fl${i}${lane}`, dd = 'M' + pts.map(q => q[0].toFixed(1) + ',' + q[1].toFixed(1)).join(' L');
      defs += `<path id="${id}" d="${dd}"/>`;
      const glyph = lane === 'u' ? '>' : '<', txt = glyph.repeat(Math.ceil(len / FLP) + 3);
      links += `<use href="#${id}" class="fl-base"/><text class="fl-chv ${lane === 'u' ? 'ftx' : 'frx'}" id="${id}t" opacity=".14"><textPath id="${id}p" href="#${id}" startOffset="0">${txt}</textPath></text>`;
    }
  });
  let nodes = '';
  if (byId.vpn) {                                  // туннели VPN (активный и резерв) — один модуль
    const t = (byId.vpn2 || byId.vpn).y - 20, b = byId.vpn.y + H + 6, x = byId.vpn.x - 8;
    nodes += `<rect class="fl-grp" x="${x}" y="${t}" width="${W + 16}" height="${b - t}" rx="6"/><text class="fgl" x="${x + 10}" y="${t + 13}">ТУННЕЛИ</text>`;
  }
  if (cli.length && byId.wg) {                     // WG-Server и его клиенты — один модуль
    const t = cli[0].y - 20, b = Math.max(cli[cli.length - 1].y, byId.wg.y) + H + 8, r = byId.wg.x + W + 8;
    nodes += `<rect class="fl-grp" x="-8" y="${t}" width="${r + 8}" height="${b - t}" rx="6"/><text class="fgl" x="2" y="${t + 13}">WG-SERVER · КЛИЕНТЫ</text>`;
  }
  for (const n of N) {
    const c = 10, sh = `M${n.x + c},${n.y} H${n.x + n.w} V${n.y + n.h - c} L${n.x + n.w - c},${n.y + n.h} H${n.x} V${n.y + c} Z`;
    const lc = n.dot >= 0 ? `var(--${['ok', 'warn', 'bad'][n.dot]})` : 'var(--none)';
    const ba = (n.acts || []).length ? FBS + 12 : 0, rx = n.x + n.w - 14 - ba;     // правый край текста и графика
    const g = `<g id="fln-${n.id}"${n.dim ? ' opacity=".5"' : ''}>${n.tip ? `<title>${esc(n.tip)}</title>` : ''}<path d="${sh}" class="fl-node"${n.c ? ` style="stroke:${n.c}"` : ''}/>
      <path d="M${n.x},${n.y} h13 L${n.x},${n.y + 13} Z" fill="${n.c || 'var(--accent)'}"/>
      <rect x="${ba ? n.x + n.w - FBS - 8 - 6 - 18 : rx - 18}" y="${n.y + 10}" width="18" height="3" fill="${lc}"/>
      <text x="${n.x + 14}" y="${n.y + 21}" class="f1">${esc(clip(n.t1, ba ? n.w - 46 : n.w - 30, 9.2))}</text>
      <text x="${n.x + 14}" y="${n.y + 38}" class="f2" id="fl-${n.id}-r"></text>
      ${n.r ? `<line class="fl-spb" id="fl-${n.id}-sb" x1="${n.x + 14}" x2="${rx}" y1="${n.y + 63.5}" y2="${n.y + 63.5}"/>
      <path class="fl-sp rx" id="fl-${n.id}-sr"/><path class="fl-sp tx" id="fl-${n.id}-st"/>` : ''}${flowBtns(n)}
      <text x="${n.x + 14}" y="${n.y + 77}" class="f3" id="fl-${n.id}-3" data-w="${n.w - 20 - ba}"></text></g>`;
    nodes += n.href ? `<a href="${n.href}">${g}</a>` : g;
  }
  const el = document.createElement('div');
  el.innerHTML = `<svg viewBox="-10 -2 ${VW + 12} ${VH + 4}" role="img" aria-label="Схема трафика: клиенты → WG-Server → маршрутизация → VPN или zapret → интернет"><defs>${defs}</defs>${links}${nodes}</svg>`;
  return el.firstChild;
}
// обновить цели: цифры и скорость стрелок плавно догоняют их в цикле отрисовки (flowFrame), схема не пересоздаётся
function flowUpdate(m) {
  if (!FL) return;
  const svg = FL.svg;
  FL.nodes = FL.nodes || {}; FL.lanes = FL.lanes || {};
  for (const n of m.N) {
    const st = FL.nodes[n.id] || (FL.nodes[n.id] = { el: svg.querySelector(`#fl-${n.id}-r`), v: n.r ? n.r.slice() : null, txt: '' });
    st.t = n.r ? n.r.slice() : null; if (st.t && !st.v) st.v = st.t.slice();
    const t = svg.querySelector(`#fl-${n.id}-3`); if (t && !FLB[n.id]) t.textContent = clip(n.t4 || n.t3, +t.dataset.w + 20 || 200, 6.1);
  }
  m.E.forEach((e, i) => {
    for (const [lane, v] of [['u', e.r[1]], ['d', e.r[0]]]) {
      const k = i + lane, L = FL.lanes[k] || (FL.lanes[k] = { tp: svg.querySelector(`#fl${k}p`), tx: svg.querySelector(`#fl${k}t`), sp: 0, ph: Math.random() * FLP, op: .14, up: lane === 'u' });
      L.tsp = e.off || FLOW_OFF ? 0 : laneSpeed(v); L.top = L.tsp > 0 ? (lane === 'd' ? 1 : .85) : .14;
    }
  });
  if (!FL.raf) { FL.last = performance.now(); FL.raf = requestAnimationFrame(flowFrame); }
}
// цикл отрисовки: скорость стрелок и цифры плавно (экспоненциально, ~0,6 с) подходят к новым значениям
function flowFrame(now) {
  if (!FL) return;
  const dt = Math.min(0.1, (now - FL.last) / 1000); FL.last = now;
  if (!document.hidden && FL.svg.isConnected) {
    const ks = 1 - Math.exp(-dt / 0.6), kv = 1 - Math.exp(-dt / 0.4);
    // стрелки — не чаще 20 кадров/с: каждый сдвиг заново раскладывает текст вдоль линии (на 60 к/с — полядра процессора)
    FL.atick = (FL.atick || 0) + dt; const draw = FL.atick >= 0.05; if (draw) FL.atick = 0;
    for (const k in FL.lanes) {
      const L = FL.lanes[k]; if (!L.tp) continue;
      L.sp += (L.tsp - L.sp) * ks; L.op += (L.top - L.op) * ks;
      L.ph = (L.ph + L.sp * dt) % FLP;
      if (!draw) continue;
      const so = (L.up ? L.ph - FLP : -L.ph).toFixed(1), op = L.op.toFixed(2);
      if (so !== L.so) { L.tp.setAttribute('startOffset', so); L.so = so; }       // стоящие полосы не трогать
      if (op !== L.opS) { L.tx.setAttribute('opacity', op); L.opS = op; }
    }
    FL.tick = (FL.tick || 0) + dt;
    if (FL.tick >= 0.05) {                        // цифры — 20 раз в секунду
      FL.tick = 0;
      for (const id in FL.nodes) {
        const st = FL.nodes[id]; if (!st.el) continue;
        if (!st.t) { if (st.txt) { st.el.innerHTML = ''; st.txt = ''; } continue; }
        st.v = st.v.map((x, j) => Math.abs(st.t[j] - x) < 1 ? st.t[j] : x + (st.t[j] - x) * Math.min(1, kv * 3));
        const html = `<tspan class="frx">↓ ${mbs(st.v[0])}</tspan>  <tspan class="ftx">↑ ${mbs(st.v[1])}</tspan> Мбит/с`;
        if (html !== st.txt) { st.el.innerHTML = html; st.txt = html; }
      }
    }
  }
  FL.raf = requestAnimationFrame(flowFrame);
}
function flowMount() {
  const host = $('#flowhost'); if (!host || !S) return;
  const m = flowModel();
  if (!FL || FL.key !== m.key) { if (FL && FL.raf) cancelAnimationFrame(FL.raf); FL = { key: m.key, svg: flowBuild(m) }; }
  if (FL.svg.parentNode !== host || host.childNodes.length !== 1) host.replaceChildren(FL.svg);   // только текущая схема
  flowUpdate(m);
}
function flowBlock() {
  return `<div class="sec">Схема трафика — кто с кем соединён и сколько пропускает</div><div class="card flow"><div id="flowoff" class="flowoff" style="display:none"></div><div id="flowhost"></div>
    <div class="legend" style="flex-wrap:wrap;margin-top:8px"><span><b style="background:var(--vpn)"></b>через VPN</span><span><b style="background:var(--zp)"></b>мимо VPN через zapret</span><span><b style="background:var(--accent)"></b>клиенты WG-Server</span><span><b style="background:var(--lan)"></b>локальная сеть (не интернет)</span><span><span class="ftx">&gt;&gt;&gt; ↑ отдача</span> · <span class="frx">&lt;&lt;&lt; ↓ загрузка</span> · чем быстрее стрелки, тем больше трафика · Мбит/с</span></div></div>`;
}
// живые скорости раз в секунду — только на главной и пока вкладка видна
const SPK = {}, SPN = 180;
async function liveTick() {
  if (page !== 'home' || document.hidden || !S) return;
  try { LIVE = await api('/api/live'); if (!LIVE || !LIVE.rate) LIVE = null; LIVE_FAILS = 0; } catch (e) { LIVE = null; LIVE_FAILS++; }
  if (LIVE && LIVE.t !== LIVE_T) { LIVE_T = LIVE.t; LIVE_AT = Date.now(); }
  FLOW_OFF = flowOffline(); const ob = $('#flowoff');
  if (ob) { ob.style.display = FLOW_OFF ? '' : 'none'; ob.textContent = FLOW_OFF ? '⚠ ' + FLOW_OFF + ' — скорости не показываются (данные не обновляются)' : ''; }
  if (FL && FL.svg) FL.svg.classList.toggle('off', !!FLOW_OFF);
  if (!FL) return;
  flowMount();                                     // состав узлов изменился (клиент пропал/появился) — пересобрать
  flowBusyPaint();
  if (!FLOW_OFF) for (const n of flowModel().N) { const h = SPK[n.id] || (SPK[n.id] = []); h.push(n.r ? [+n.r[0] || 0, +n.r[1] || 0] : [0, 0]); if (h.length > SPN) h.shift(); }
  flowSpark();
}
// история скоростей из агента (он пишет её всегда) — при открытии главной графики сразу показывают последние 3 мин
async function sparkHist() {
  let h; try { h = await api('/api/live-hist'); } catch (e) { return; }
  if (!h || !h.t || !h.s || !S || !FL) return;
  const keep = LIVE, s = h.s, out = {};
  try {
    for (let i = 0; i < h.t.length; i++) {
      const rate = {}, peers = {};
      for (const k in s) { const v = s[k][i]; if (!v) continue; if (k.startsWith('r:')) rate[k.slice(2)] = v; else if (k.startsWith('p:')) peers[k.slice(2)] = { rx: v[0], tx: v[1] }; }
      if (!rate.p) continue;
      LIVE = { rate, peers, cz: (s.cz && s.cz[i]) || [0, 0] };
      for (const n of flowModel().N) (out[n.id] = out[n.id] || []).push(n.r ? [+n.r[0] || 0, +n.r[1] || 0] : [0, 0]);
    }
  } finally { LIVE = keep; }
  for (const id in out) SPK[id] = out[id].slice(-SPN);
  flowSpark();
}
// мини-график под скоростью: ↓ загрузка и ↑ отдача за последние 3 мин, масштаб — по максимуму окна (не меньше 100 Кбит/с)
function flowSpark() {
  const svg = FL && FL.svg; if (!svg) return;
  for (const id in SPK) {
    const pr = svg.querySelector(`#fl-${id}-sr`), pt = svg.querySelector(`#fl-${id}-st`); if (!pr || !pt) continue;
    const bl = svg.querySelector(`#fl-${id}-sb`); if (!bl) continue;
    const h = SPK[id], x0 = +bl.getAttribute('x1'), w = +bl.getAttribute('x2') - x0, y0 = +bl.getAttribute('y1') - .5, hh = 17;
    let mx = 12500; for (const v of h) mx = Math.max(mx, v[0], v[1]);
    const d = k => h.length < 2 ? '' : 'M' + h.map((v, i) => (x0 + w - (h.length - 1 - i) * w / (SPN - 1)).toFixed(1) + ',' + (y0 - hh * v[k] / mx).toFixed(1)).join(' L');
    pr.setAttribute('d', d(0)); pt.setAttribute('d', d(1));
  }
}
// обрезать подпись под ширину (k — ширина символа)
function clip(s, w, k = 6.6) { s = String(s || ''); const n = Math.floor((w - 20) / k); return s.length > n ? s.slice(0, Math.max(1, n - 1)) + '…' : s; }
