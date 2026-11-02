/* ec-plot.js - ba hình vẽ SVG của bài đường cong elliptic, không thư viện ngoài: (1) đường cong trên số thực với dây cung / tiếp tuyến,
   (2) lưới điểm trên trường F_p nhỏ với quỹ đạo G, 2G, 3G, ..., (3) bảng từng bit của nhân vô hướng. Màu lấy từ biến CSS của trang
   (class trên phần tử SVG), chữ trong hình chỉ là ký hiệu toán (P, Q, O, số) nên trung lập ngôn ngữ.
   The three SVG figures of the elliptic-curve article; pure math helpers (realAdd, realDomain, snapReal) are exported for tests.
   Original implementation for the ChiU·SoC site. Global: ECPlot. */
(function (root) {
  'use strict';
  var NS = 'http://www.w3.org/2000/svg';
  function el(tag, attrs, parent) {
    var e = root.document.createElementNS(NS, tag), k;
    for (k in attrs) if (attrs[k] !== undefined && attrs[k] !== null) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function text(parent, x, y, s, cls, anchor) { var t = el('text', { x: x, y: y, 'class': cls || 'lbl', 'text-anchor': anchor || 'middle' }, parent); t.textContent = s; return t; }
  function clear(svg) { while (svg.firstChild) svg.removeChild(svg.firstChild); }
  function fmt(x) { return (Math.abs(x) < 1e-9 ? 0 : x).toFixed(3).replace(/\.?0+$/, ''); }

  /* ================================================================ đường cong trên số thực: y^2 = x^3 + a x + b */
  function f(a, b, x) { return x * x * x + a * x + b; }
  function singular(a, b) { return Math.abs(4 * a * a * a + 27 * b * b) < 1e-9; }
  function realRoots(a, b) {                                // nghiệm thực của x^3 + a x + b = 0 bằng quét dấu + chia đôi
    var roots = [], lo = -20, hi = 20, N = 4000, i, x0, x1, f0, f1, m, k;
    for (i = 0; i < N; i++) {
      x0 = lo + (hi - lo) * i / N; x1 = lo + (hi - lo) * (i + 1) / N; f0 = f(a, b, x0); f1 = f(a, b, x1);
      if (f0 === 0) roots.push(x0);
      else if (f0 * f1 < 0) { for (k = 0; k < 60; k++) { m = (x0 + x1) / 2; if (f(a, b, x0) * f(a, b, m) <= 0) x1 = m; else x0 = m; } roots.push((x0 + x1) / 2); }
    }
    return roots;
  }
  function realDomain(a, b) {                               // các khoảng x có x^3 + a x + b ≥ 0: [[r1, r2], [r3, ∞]] hoặc [[r, ∞]]
    var r = realRoots(a, b);
    if (r.length >= 3) return [[r[0], r[1]], [r[2], Infinity]];
    return [[r[0], Infinity]];
  }
  function realY(a, b, x) { var v = f(a, b, x); return v < 0 ? NaN : Math.sqrt(v); }
  function snapReal(a, b, x, y) {                            // điểm trên đường cong gần cú bấm nhất: giữ x nếu được, giữ dấu của y
    var dom = realDomain(a, b), best = null, d, i, cx;
    for (i = 0; i < dom.length; i++) {
      cx = Math.min(Math.max(x, dom[i][0]), dom[i][1] === Infinity ? 1e9 : dom[i][1]);
      d = Math.abs(cx - x);
      if (best === null || d < best[1]) best = [cx, d];
    }
    var yy = realY(a, b, best[0]);
    if (isNaN(yy)) yy = 0;
    return [best[0], y < 0 ? -yy : yy];
  }
  function realAdd(a, P, Q) {
    var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1], lam, kind;
    if (Math.abs(x1 - x2) < 1e-9 && Math.abs(y1 + y2) < 1e-9) return { kind: 'inf' };
    if (Math.abs(x1 - x2) < 1e-9) { lam = (3 * x1 * x1 + a) / (2 * y1); kind = 'dbl'; }
    else { lam = (y2 - y1) / (x2 - x1); kind = 'add'; }
    var x3 = lam * lam - x1 - x2, y3 = lam * (x1 - x3) - y1;
    return { kind: kind, lam: lam, x3: x3, y3: y3 };
  }
  var RW = 560, RH = 400, RX = 3.8, RY = 6.2;               // viewBox và tầm nhìn (đơn vị toán)
  function rmap() { var sx = RW / (2 * RX), sy = RH / (2 * RY); return { X: function (x) { return RW / 2 + x * sx; }, Y: function (y) { return RH / 2 - y * sy; } }; }
  function worldFromEvent(svg, clientX, clientY) {           // toạ độ toán của một cú bấm (dùng kích thước thật của SVG)
    var r = svg.getBoundingClientRect(), u = (clientX - r.left) / (r.width || RW) * RW, v = (clientY - r.top) / (r.height || RH) * RH;
    return [(u - RW / 2) * (2 * RX) / RW, (RH / 2 - v) * (2 * RY) / RH];
  }
  function clipLine(lam, x0, y0) {                           // đoạn của đường y - y0 = lam (x - x0) nằm trong khung
    var pts = [], xs = [-RX, RX], ys = [-RY, RY], i, y, x;
    for (i = 0; i < 2; i++) { y = y0 + lam * (xs[i] - x0); if (y >= -RY && y <= RY) pts.push([xs[i], y]); }
    for (i = 0; i < 2; i++) { if (Math.abs(lam) > 1e-12) { x = x0 + (ys[i] - y0) / lam; if (x >= -RX && x <= RX) pts.push([x, ys[i]]); } }
    return pts.length >= 2 ? [pts[0], pts[pts.length - 1]] : null;
  }
  /* state: {a, b, P:[x,y], Q:[x,y]}; trả về kết quả của realAdd cùng nhãn */
  function drawReal(svg, st) {
    clear(svg);
    svg.setAttribute('viewBox', '0 0 ' + RW + ' ' + RH);
    var M = rmap(), g = el('g', { 'class': 'plot-real' }, svg), i, j, x, y, dom, d, pth, s, xEnd, step;
    for (i = -3; i <= 3; i++) { el('line', { x1: M.X(i), y1: 0, x2: M.X(i), y2: RH, 'class': 'grid' }, g); text(g, M.X(i), RH - 4, String(i), 'tick'); }
    for (j = -6; j <= 6; j += 2) { el('line', { x1: 0, y1: M.Y(j), x2: RW, y2: M.Y(j), 'class': 'grid' }, g); if (j) text(g, 10, M.Y(j) + 4, String(j), 'tick', 'start'); }
    el('line', { x1: 0, y1: M.Y(0), x2: RW, y2: M.Y(0), 'class': 'axis' }, g);
    el('line', { x1: M.X(0), y1: 0, x2: M.X(0), y2: RH, 'class': 'axis' }, g);
    if (singular(st.a, st.b)) { text(g, RW / 2, RH / 2, '4a³ + 27b² = 0', 'warn'); return { kind: 'singular' }; }
    dom = realDomain(st.a, st.b);
    for (i = 0; i < dom.length; i++) {
      xEnd = dom[i][1] === Infinity ? RX + 0.5 : dom[i][1]; s = ''; step = (xEnd - dom[i][0]) / 400;
      if (step <= 0) continue;
      for (x = dom[i][0]; x <= xEnd + 1e-9; x += step) { y = realY(st.a, st.b, Math.min(x, xEnd)); if (isNaN(y)) y = 0; s += (s ? ' L' : 'M') + fmt(M.X(x)) + ' ' + fmt(M.Y(y)); }
      for (x = xEnd; x >= dom[i][0] - 1e-9; x -= step) { y = realY(st.a, st.b, Math.max(x, dom[i][0])); if (isNaN(y)) y = 0; s += ' L' + fmt(M.X(x)) + ' ' + fmt(M.Y(-y)); }
      pth = el('path', { d: s, 'class': 'curve' }, g);
    }
    var P = st.P, Q = st.Q, r = realAdd(st.a, P, Q), same = r.kind === 'dbl', seg;
    if (r.kind === 'inf') {
      el('line', { x1: M.X(P[0]), y1: 0, x2: M.X(P[0]), y2: RH, 'class': 'chord' }, g);
      text(g, M.X(P[0]) + 8, 16, 'O', 'lbl', 'start');
    } else {
      seg = clipLine(r.lam, P[0], P[1]);
      if (seg) el('line', { x1: M.X(seg[0][0]), y1: M.Y(seg[0][1]), x2: M.X(seg[1][0]), y2: M.Y(seg[1][1]), 'class': same ? 'tangent' : 'chord' }, g);
      el('line', { x1: M.X(r.x3), y1: M.Y(-r.y3), x2: M.X(r.x3), y2: M.Y(r.y3), 'class': 'reflect' }, g);
      el('circle', { cx: M.X(r.x3), cy: M.Y(-r.y3), r: 5, 'class': 'pt third' }, g);
      el('circle', { cx: M.X(r.x3), cy: M.Y(r.y3), r: 6, 'class': 'pt sum' }, g);
      text(g, M.X(r.x3) + 9, M.Y(r.y3) + 4, same ? '2P' : 'P+Q', 'lbl', 'start');
    }
    el('circle', { cx: M.X(P[0]), cy: M.Y(P[1]), r: 7, 'class': 'pt p', 'data-pt': 'P' }, g);
    text(g, M.X(P[0]) - 10, M.Y(P[1]) - 9, 'P', 'lbl');
    if (!same) { el('circle', { cx: M.X(Q[0]), cy: M.Y(Q[1]), r: 7, 'class': 'pt q', 'data-pt': 'Q' }, g); text(g, M.X(Q[0]) + 10, M.Y(Q[1]) - 9, 'Q', 'lbl'); }
    return r;
  }

  /* ================================================================ trường F_p nhỏ: lưới điểm, quỹ đạo, P + Q */
  var FW = 520;
  /* st: {p, pts:[[x,y]], orbit:[pt|null], step, G, P, Q, R, kind} (toạ độ là Number) */
  function drawField(svg, st) {
    clear(svg);
    var p = st.p, m = 34, W = FW - 2 * m, cell = W / p, g, i, k, a, b, lab;
    svg.setAttribute('viewBox', '0 0 ' + FW + ' ' + FW);
    g = el('g', { 'class': 'plot-field' }, svg);
    var X = function (x) { return m + (x + 0.5) * cell; }, Y = function (y) { return FW - m - (y + 0.5) * cell; };
    el('rect', { x: m, y: m, width: W, height: W, 'class': 'frame' }, g);
    if (p <= 31) for (i = 1; i < p; i++) { el('line', { x1: m + i * cell, y1: m, x2: m + i * cell, y2: FW - m, 'class': 'grid' }, g); el('line', { x1: m, y1: m + i * cell, x2: FW - m, y2: m + i * cell, 'class': 'grid' }, g); }
    var tick = p <= 31 ? (p <= 17 ? 1 : 2) : (p <= 60 ? 5 : 10);
    for (i = 0; i < p; i += tick) { text(g, X(i), FW - m + 16, String(i), 'tick'); text(g, m - 8, Y(i) + 4, String(i), 'tick', 'end'); }
    el('line', { x1: m, y1: Y(p / 2 - 0.5), x2: FW - m, y2: Y(p / 2 - 0.5), 'class': 'mirror' }, g);   // trục đối xứng y <-> p - y
    var rad = Math.max(2.2, Math.min(7, cell * 0.33));
    for (i = 0; i < st.pts.length; i++) el('circle', { cx: X(st.pts[i][0]), cy: Y(st.pts[i][1]), r: rad, 'class': 'pt' }, g);
    var orb = st.orbit || [], upto = Math.min(st.step || 0, orb.length), prev = null;
    for (k = 0; k < upto; k++) {
      a = orb[k];
      if (a === null) { text(g, FW / 2, m - 10, (k + 1) + 'G = O', 'lbl'); break; }
      if (prev) el('line', { x1: X(prev[0]), y1: Y(prev[1]), x2: X(a[0]), y2: Y(a[1]), 'class': 'arrow' }, g);
      prev = a;
    }
    for (k = 0; k < upto; k++) {
      a = orb[k]; if (a === null) break;
      el('circle', { cx: X(a[0]), cy: Y(a[1]), r: rad + 2.5, 'class': 'pt orbit' + (k === upto - 1 ? ' cur' : '') }, g);
      if (p <= 31 || k === 0 || k === upto - 1 || cell >= 9) text(g, X(a[0]), Y(a[1]) - rad - 4, String(k + 1), 'num');
    }
    if (st.G) { el('circle', { cx: X(st.G[0]), cy: Y(st.G[1]), r: rad + 4, 'class': 'pt gen' }, g); text(g, X(st.G[0]) + rad + 6, Y(st.G[1]) + 4, 'G', 'lbl', 'start'); }
    if (st.P && st.Q && st.kind !== 'inf' && st.kind !== 'ident') {
      if (st.R) { el('line', { x1: X(st.R[0]), y1: Y(st.R[1]), x2: X(st.R[0]), y2: Y((p - st.R[1]) % p), 'class': 'reflect' }, g); el('circle', { cx: X(st.R[0]), cy: Y((p - st.R[1]) % p), r: rad + 2, 'class': 'pt third' }, g); }
    }
    if (st.P) { el('circle', { cx: X(st.P[0]), cy: Y(st.P[1]), r: rad + 4, 'class': 'pt p' }, g); text(g, X(st.P[0]) - rad - 6, Y(st.P[1]) - rad - 4, 'P', 'lbl'); }
    if (st.Q) { el('circle', { cx: X(st.Q[0]), cy: Y(st.Q[1]), r: rad + 4, 'class': 'pt q' }, g); text(g, X(st.Q[0]) + rad + 6, Y(st.Q[1]) - rad - 4, 'Q', 'lbl'); }
    if (st.P && st.Q && st.R) { el('circle', { cx: X(st.R[0]), cy: Y(st.R[1]), r: rad + 4, 'class': 'pt sum' }, g); lab = st.kind === 'dbl' ? '2P' : 'P+Q'; text(g, X(st.R[0]) + rad + 6, Y(st.R[1]) + rad + 12, lab, 'lbl', 'start'); }
    if (st.P && st.Q && st.kind === 'inf') { el('line', { x1: X(st.P[0]), y1: m, x2: X(st.P[0]), y2: FW - m, 'class': 'chord' }, g); text(g, X(st.P[0]), m - 10, 'P + Q = O', 'lbl'); }
  }

  /* ================================================================ bảng từng bit của k·G (hai thuật toán) - chỉ các hàng, UI viết tiêu đề */
  function ptStr(P) { return P === null ? 'O' : '(' + P[0] + ', ' + P[1] + ')'; }
  function ladderRows(tr) {
    var rows = '', i, d, l;
    for (i = 0; i < tr.bits.length; i++) {
      d = tr.da[i]; l = tr.ladder[i];
      rows += '<tr' + (d.bit === '1' ? ' class="one"' : '') + '><td class="num">' + (tr.bits.length - 1 - i) + '</td><td class="num bit">' + d.bit + '</td>' +
        '<td>' + (d.op === 'DA' ? 'D + A' : 'D') + '</td><td>' + ptStr(d.R) + '</td>' +
        '<td>A + D</td><td>' + ptStr(l.R0) + '</td><td>' + ptStr(l.R1) + '</td></tr>';
    }
    return rows;
  }

  root.ECPlot = { singular: singular, realRoots: realRoots, realDomain: realDomain, realY: realY, snapReal: snapReal, realAdd: realAdd, worldFromEvent: worldFromEvent,
    drawReal: drawReal, drawField: drawField, ladderRows: ladderRows, ptStr: ptStr, RW: RW, RH: RH, RX: RX, RY: RY, FW: FW };
})(typeof window !== 'undefined' ? window : globalThis);
