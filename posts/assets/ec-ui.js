/* ec-ui.js - giao diện của bài "đường cong elliptic": ba hình tương tác (số thực, trường F_p nhỏ, nhân vô hướng từng bit) và phòng thí
   nghiệm sáu thẻ theo các phép kiểm của NIST (sinh cặp khoá, kiểm tra khoá công khai, ECC CDH, ký ECDSA, xác minh ECDSA, tấn công nonce).
   Mọi chuỗi hiển thị có hai bản qua bi(vi, en); số và hex trung lập. Original implementation for the ChiU·SoC site. Test hook: ECLab. */
(function () {
  'use strict';
  var EC = window.EC, PL = window.ECPlot, V = window.EC_VECTORS, B = BigInt;

  /* ================================================================ tiện ích */
  function $(id) { var e = document.getElementById(id); if (!e) throw new Error('missing #' + id); return e; }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function bi(vi, en) { return '<span lang="vi">' + vi + '</span><span lang="en">' + en + '</span>'; }
  function nb(s) { return '<span data-i18n="neutral">' + s + '</span>'; }
  function num(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ' '); }
  function checked(name) { var r = document.querySelector('input[name="' + name + '"]:checked'); return r ? r.value : null; }
  function radios(name) { return Array.prototype.slice.call(document.querySelectorAll('input[name="' + name + '"]')); }
  function onRadio(name, fn) { radios(name).forEach(function (r) { r.addEventListener('change', fn); }); }
  function setRadio(name, v) { radios(name).forEach(function (r) { r.checked = r.value === v; }); radios(name).some(function (r) { if (r.value === v) { r.dispatchEvent(new Event('change')); return true; } return false; }); }
  function show(el, cls, main, sub) { el.className = 'result ' + cls; el.innerHTML = main + (sub ? '<span class="sub">' + sub + '</span>' : ''); }
  function rnd(n) { var b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
  function hex(x, c) { return EC.bigToHex(x, c ? c.bytes : 0); }
  function unhexBytes(h) { h = h.replace(/[\s:]/g, '').replace(/^0x/i, ''); if (h.length % 2) h = '0' + h; if (!/^[0-9a-fA-F]*$/.test(h)) throw new Error('HEX'); var o = new Uint8Array(h.length / 2); for (var i = 0; i < o.length; i++) o[i] = parseInt(h.substr(2 * i, 2), 16); return o; }
  function hexOfBytes(b) { var s = '', i; for (i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16); return s; }
  function ms(t) { return nb(' · ' + (t < 100 ? t.toFixed(1) : t.toFixed(0)) + ' ms'); }
  function cur(name) { return EC.CURVES[checked(name)]; }
  var HLABEL = { 'SHA2-224': 'SHA-224', 'SHA2-256': 'SHA-256', 'SHA2-384': 'SHA-384', 'SHA2-512': 'SHA-512', 'SHA2-512/224': 'SHA-512/224', 'SHA2-512/256': 'SHA-512/256',
    'SHA3-224': 'SHA3-224', 'SHA3-256': 'SHA3-256', 'SHA3-384': 'SHA3-384', 'SHA3-512': 'SHA3-512' };
  function ptStr(P, c) { return P === null ? 'O' : '(' + hex(P[0], c) + ', ' + hex(P[1], c) + ')'; }
  function pn(P) { return P === null ? null : [Number(P[0]), Number(P[1])]; }

  /* ================================================================ ô hex (khoá, toạ độ, r, s, k) và ô thông điệp (Văn bản / Hex) */
  function tool(box, html, fn) { var b = document.createElement('button'); b.type = 'button'; b.innerHTML = html; b.addEventListener('click', fn); box.appendChild(b); return b; }
  function Field(id, o) {
    var f = this;
    f.id = id; f.ta = $(id); f.cnt = $(id + '-cnt'); f.tools = $(id + '-tools'); f.name = o.name; f.need = o.need || null; f.onEdit = o.onEdit || null;
    f.msg = !!o.msg; f.fmt = f.msg ? 'text' : 'hex'; f.btn = {};
    if (f.msg) {
      f.btn.text = tool(f.tools, bi('Văn bản', 'Text'), function () { f.setFmt('text'); });
      f.btn.hex = tool(f.tools, 'Hex', function () { f.setFmt('hex'); });
    }
    var g = document.createElement('span'); g.className = 'gap'; f.tools.appendChild(g);
    tool(f.tools, bi('Chép', 'Copy'), function () { f.copy(); });
    if (!f.ta.readOnly) tool(f.tools, bi('Xoá', 'Clear'), function () { f.ta.value = ''; f.count(); f.edited(); });
    f.flashEl = document.createElement('span'); f.flashEl.className = 'flash'; f.tools.appendChild(f.flashEl);
    f.ta.addEventListener('input', function () { f.count(); f.edited(); });
    f.mark(); f.count();
  }
  Field.prototype.edited = function () { if (this.onEdit) this.onEdit(this); };
  Field.prototype.empty = function () { return !this.ta.value.trim(); };
  Field.prototype.mark = function () { for (var k in this.btn) this.btn[k].setAttribute('aria-pressed', String(k === this.fmt)); };
  Field.prototype.bytes = function () { return this.fmt === 'text' ? new TextEncoder().encode(this.ta.value) : unhexBytes(this.ta.value); };
  Field.prototype.big = function () {                      // số nguyên lớn từ hex; lỗi HEX khi có ký tự lạ
    var s = this.ta.value.replace(/[\s:]/g, '').replace(/^0x/i, '');
    if (!s) throw Object.assign(new Error('EMPTY'), { code: 'EMPTY' });
    if (!/^[0-9a-fA-F]+$/.test(s)) throw Object.assign(new Error('HEX'), { code: 'HEX' });
    if (s.length > 400) throw Object.assign(new Error('LONG'), { code: 'LONG' });
    return B('0x' + s);
  };
  Field.prototype.set = function (x, c) { this.ta.value = x === null || x === undefined ? '' : (typeof x === 'bigint' ? hex(x, c) : String(x)); this.count(); };
  Field.prototype.setBytes = function (b) { this.fmt = 'hex'; this.mark(); this.ta.value = hexOfBytes(b); this.count(); };
  Field.prototype.setText = function (s) { this.fmt = 'text'; this.mark(); this.ta.value = s; this.count(); };
  Field.prototype.setFmt = function (k) {
    if (k === this.fmt) return;
    var b;
    try { b = this.bytes(); } catch (e) { return this.flash(bi('Ô đang có ký tự không phải hex.', 'The field holds non-hex characters.'), true); }
    if (k === 'text') { var t; try { t = new TextDecoder('utf-8', { fatal: true }).decode(b); } catch (e) { return this.flash(bi('Các byte này không phải UTF-8 nên không hiện được dạng văn bản.', 'These bytes are not UTF-8, so they cannot be shown as text.'), true); } this.ta.value = t; }
    else this.ta.value = hexOfBytes(b);
    this.fmt = k; this.mark(); this.count();
  };
  Field.prototype.count = function () {
    var el = this.cnt, need = this.need ? this.need() : null, n;
    if (this.empty()) { el.className = 'cnt'; el.innerHTML = need ? nb('0 / ' + need + ' B') : ''; return; }
    try { n = this.msg ? this.bytes().length : Math.ceil(this.ta.value.replace(/[\s:]/g, '').replace(/^0x/i, '').length / 2); if (!this.msg) this.big(); }
    catch (e) { el.className = 'cnt bad'; el.innerHTML = bi('không phải hex', 'not hex'); return; }
    el.className = 'cnt' + (need ? (n <= need ? ' ok' : ' warn') : '');
    el.innerHTML = nb(num(n) + (need ? ' / ' + need : '') + ' B');
  };
  Field.prototype.flash = function (html, bad) { var el = this.flashEl; el.style.color = bad ? '#9b1d28' : ''; el.innerHTML = html; clearTimeout(this.ft); this.ft = setTimeout(function () { el.innerHTML = ''; }, bad ? 5000 : 1800); };
  Field.prototype.copy = function () {
    var f = this, s = f.ta.value; if (!s) return;
    function done() { f.flash(bi('đã chép', 'copied')); }
    function fallback() { f.ta.select(); try { document.execCommand('copy'); done(); } catch (e) { /* bị chặn */ } }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(s).then(done, fallback); else fallback();
  };
  /* đọc một số từ ô, hoặc báo lỗi vào dòng kết quả; trả về null khi hỏng */
  function bigOf(f, fail) {
    try { return f.big(); }
    catch (e) {
      if (e.code === 'EMPTY') fail(bi('Ô ' + f.name[0] + ' đang trống.', 'The ' + f.name[1] + ' field is empty.'));
      else if (e.code === 'LONG') fail(bi('Ô ' + f.name[0] + ' quá dài.', 'The ' + f.name[1] + ' field is too long.'));
      else fail(bi('Ô ' + f.name[0] + ' có ký tự không phải hex.', 'The ' + f.name[1] + ' field holds non-hex characters.'));
      return null;
    }
  }
  function bytesOf(f, fail) {
    var b;
    try { b = f.bytes(); } catch (e) { fail(bi('Ô ' + f.name[0] + ' có ký tự không phải hex.', 'The ' + f.name[1] + ' field holds non-hex characters.')); return null; }
    if (b.length > (1 << 20)) { fail(bi('Thông điệp dài hơn 1 MB.', 'The message is longer than 1 MB.')); return null; }
    return b;
  }
  function randomOr(chk, f, c, fail) {                     // ô khoá riêng / k: ngẫu nhiên nếu đánh dấu, không thì đọc ô
    if ($(chk).checked) { var d = EC.keygen(c, 'A.2.1', rnd).d; f.set(d, c); return d; }
    return bigOf(f, fail);
  }

  /* ================================================================ vết từng bước */
  function Trace() { this.h = ''; }
  Trace.prototype.line = function (vi, en, val, cls) { this.h += '<div class="tl' + (cls ? ' ' + cls : '') + '"><span class="tk">' + bi(vi, en) + '</span><code class="tv">' + esc(val) + '</code></div>'; return this; };
  Trace.prototype.note = function (vi, en, cls) { this.h += '<div class="tl' + (cls ? ' ' + cls : '') + '"><span class="tn">' + bi(vi, en) + '</span></div>'; return this; };
  Trace.prototype.into = function (el) { el.innerHTML = this.h; el.hidden = !this.h; };
  function pkvTrace(t, c, v) {
    var W = { INFINITY: ['Q ≠ O (không phải điểm vô cực)', 'Q ≠ O (not the point at infinity)'], RANGE: ['0 ≤ x, y ≤ p − 1', '0 ≤ x, y ≤ p − 1'],
      NOT_ON_CURVE: ['y² ≡ x³ − 3x + b (mod p): điểm nằm trên đường cong', 'y² ≡ x³ − 3x + b (mod p): the point is on the curve'], ORDER: ['n·Q = O (bậc của Q là n)', 'n·Q = O (Q has order n)'] };
    v.steps.forEach(function (s, i) { t.line('Bước ' + (i + 1) + ': ' + W[s[0]][0], 'Step ' + (i + 1) + ': ' + W[s[0]][1], s[1] ? '✓' : '✕', s[1] ? 'ok' : 'bad'); });
  }
  var PKV_WHY = { INFINITY: ['Q là điểm vô cực O', 'Q is the point at infinity O'], RANGE: ['toạ độ ngoài [0, p − 1]', 'a coordinate is outside [0, p − 1]'],
    NOT_ON_CURVE: ['điểm không nằm trên đường cong', 'the point is not on the curve'], ORDER: ['n·Q ≠ O', 'n·Q ≠ O'] };

  /* ================================================================ nút "Nạp ví dụ NIST": so từng giá trị với đáp án */
  function cmp(list) {                                     // list: [[nhãn, có, muốn]] -> {html, ok}
    var ok = true, h = list.map(function (r) { var good = String(r[1]).toLowerCase().replace(/^0+(?=.)/, '') === String(r[2]).toLowerCase().replace(/^0+(?=.)/, ''); ok = ok && good; return '<li><b>' + (good ? '✓' : '✕') + '</b>' + nb(r[0]) + '</li>'; }).join('');
    return { ok: ok, html: '<ul class="cmp">' + h + '</ul>' };
  }
  function exName(v) {
    var s = v.src + ' · ' + v.curve + (v.hash ? ' · ' + HLABEL[v.hash] : '');
    if (v.tcId !== undefined) s += ' · tcId ' + v.tcId;
    if (v.count !== undefined) s += ' · COUNT = ' + v.count;
    return s;
  }
  function exButtons(box, list, fn) {
    list.forEach(function (v, i) { var b = document.createElement('button'); b.type = 'button'; b.className = 'ex'; b.id = box.id + '-' + i; b.setAttribute('data-i18n', 'neutral'); b.textContent = exName(v) + (v.comment ? ' · ' + v.comment : ''); b.addEventListener('click', function () { fn(v, b); }); box.appendChild(b); });
  }
  function exVerdict(X, ok, v, html, t) {
    X.show(ok ? 'ok' : 'bad', (ok ? '✓ ' : '✕ ') + (ok ? bi('Ví dụ ' + esc(exName(v)) + ' đã được điền và chạy: mọi giá trị trùng đáp án của NIST.', 'Example ' + esc(exName(v)) + ' was loaded and run: every value equals NIST\'s answer.')
      : bi('Ví dụ ' + esc(exName(v)) + ': có giá trị KHÁC đáp án của NIST.', 'Example ' + esc(exName(v)) + ': a value DIFFERS from NIST\'s answer.')) + (t !== undefined ? ms(t) : ''), html);
  }

  /* ================================================================ khung một thẻ */
  function Tab(prefix) {                                 // show / fail là closure: chúng được truyền làm callback (bigOf, randomOr)
    var X = this;
    X.p = prefix; X.res = $(prefix + '-result'); X.tr = $(prefix + '-trace');
    X.show = function (cls, main, sub) { show(X.res, cls, main, sub); };
    X.fail = function (html) { show(X.res, 'bad', '✕ ' + html); X.tr.hidden = true; X.tr.innerHTML = ''; };
  }
  function tabs() {
    var btns = Array.prototype.slice.call(document.querySelectorAll('.tabs .tab'));
    btns.forEach(function (b) {
      b.addEventListener('click', function () {
        btns.forEach(function (x) { x.setAttribute('aria-selected', String(x === b)); $(x.getAttribute('aria-controls')).hidden = x !== b; });
      });
    });
  }

  /* ================================================================ HÌNH 1: đường cong trên số thực */
  var G1 = { a: -1, b: 1, P: [0, 1], Q: [1, 1] };
  function g1Draw() {
    var a = G1.a, b = G1.b, disc = 4 * a * a * a + 27 * b * b;
    $('g1-a-val').textContent = a.toFixed(1); $('g1-b-val').textContent = b.toFixed(1);
    $('g1-eq').textContent = 'y² = x³ ' + (a < 0 ? '− ' : '+ ') + Math.abs(a).toFixed(1) + 'x ' + (b < 0 ? '− ' : '+ ') + Math.abs(b).toFixed(1);
    $('g1-disc').innerHTML = nb('4a³ + 27b² = ' + disc.toFixed(2));
    if (PL.singular(a, b)) {
      PL.drawReal($('g1-svg'), G1);
      $('g1-out').innerHTML = bi('4a³ + 27b² = 0: đường cong suy biến (có điểm nhọn hoặc tự cắt), không dùng được cho luật nhóm. Hãy đổi a hoặc b.',
        '4a³ + 27b² = 0: a singular curve (a cusp or a self-crossing); the group law does not work on it. Change a or b.');
      $('g1-out').className = 'result bad'; return;
    }
    G1.P = PL.snapReal(a, b, G1.P[0], G1.P[1]); G1.Q = PL.snapReal(a, b, G1.Q[0], G1.Q[1]);
    var r = PL.drawReal($('g1-svg'), G1), f3 = function (x) { return (Math.abs(x) < 5e-4 ? 0 : x).toFixed(3).replace(/\.?0+$/, ''); }, out = $('g1-out');
    out.className = 'result info';
    if (r.kind === 'inf') out.innerHTML = bi('Q = −P: đường thẳng qua P và Q thẳng đứng, không cắt đường cong lần thứ ba. Quy ước: P + (−P) = O, điểm vô cực - phần tử trung hoà của nhóm.',
      'Q = −P: the line through P and Q is vertical and never meets the curve a third time. By convention P + (−P) = O, the point at infinity - the group\'s identity.');
    else out.innerHTML = (r.kind === 'dbl' ? bi('P = Q: dùng tiếp tuyến tại P. ', 'P = Q: use the tangent at P. ') : bi('Dây cung qua P và Q cắt đường cong tại điểm thứ ba (vòng rỗng); lấy đối xứng qua trục hoành được P + Q. ', 'The chord through P and Q meets the curve at a third point (hollow); its mirror image across the x-axis is P + Q. ')) +
      nb('λ = ' + f3(r.lam) + ' · x₃ = λ² − x₁ − x₂ = ' + f3(r.x3) + ' · y₃ = λ(x₁ − x₃) − y₁ = ' + f3(r.y3)) +
      ' ' + bi('(λ = (y₂ − y₁)/(x₂ − x₁) cho dây cung, (3x₁² + a)/(2y₁) cho tiếp tuyến).', '(λ = (y₂ − y₁)/(x₂ − x₁) for a chord, (3x₁² + a)/(2y₁) for the tangent).');
    return r;
  }
  function g1Pick(x, y) {                                  // đặt điểm đang chọn (P hay Q) vào điểm trên đường cong gần (x, y) nhất
    if (PL.singular(G1.a, G1.b)) return;
    var s = PL.snapReal(G1.a, G1.b, Math.max(-PL.RX, Math.min(PL.RX, x)), y);
    if (checked('g1-pick') === 'Q') G1.Q = s; else G1.P = s;
    g1Draw();
  }
  function g1Init() {
    var svg = $('g1-svg'), down = false;
    $('g1-a').addEventListener('input', function () { G1.a = +this.value; g1Draw(); });
    $('g1-b').addEventListener('input', function () { G1.b = +this.value; g1Draw(); });
    $('g1-preset-add').addEventListener('click', function () { G1.a = -1; G1.b = 1; $('g1-a').value = -1; $('g1-b').value = 1; G1.P = [0, 1]; G1.Q = [1, 1]; g1Draw(); });
    $('g1-preset-dbl').addEventListener('click', function () { G1.Q = G1.P.slice(); g1Draw(); });
    $('g1-preset-inf').addEventListener('click', function () { G1.Q = [G1.P[0], -G1.P[1]]; g1Draw(); });
    function at(ev) { var w = PL.worldFromEvent(svg, ev.clientX, ev.clientY); g1Pick(w[0], w[1]); }
    svg.addEventListener('pointerdown', function (ev) { down = true; try { svg.setPointerCapture(ev.pointerId); } catch (e) { /* jsdom */ } at(ev); ev.preventDefault(); });
    svg.addEventListener('pointermove', function (ev) { if (down) at(ev); });
    svg.addEventListener('pointerup', function () { down = false; });
    svg.addEventListener('pointercancel', function () { down = false; });
    g1Draw();
  }

  /* ================================================================ HÌNH 2: trường F_p nhỏ */
  var G2 = { p: 17, a: 2, b: 2, c: null, pts: [], G: null, orbit: [], step: 1, P: null, Q: null, timer: null };
  function g2Setup() {
    var p = +checked('g2-p'), a = +$('g2-a').value, b = +$('g2-b').value, c, pts, i;
    if (!(a >= 0 && a < p && b >= 0 && b < p && a === Math.floor(a) && b === Math.floor(b))) { $('g2-count').innerHTML = bi('a và b phải là số nguyên trong [0, p − 1].', 'a and b must be integers in [0, p − 1].'); $('g2-count').className = 'result bad'; return; }
    G2.p = p; G2.a = a; G2.b = b; c = G2.c = EC.toy(p, a, b); clearInterval(G2.timer); G2.timer = null;
    $('g2-eq').textContent = 'y² ≡ x³ + ' + a + 'x + ' + b + ' (mod ' + p + ')';
    if (c.disc === 0n) {
      G2.pts = []; G2.orbit = []; G2.G = G2.P = G2.Q = null;
      PL.drawField($('g2-svg'), { p: p, pts: [], orbit: [], step: 0 });
      $('g2-count').className = 'result bad';
      $('g2-count').innerHTML = bi('4a³ + 27b² ≡ 0 (mod ' + p + '): đường cong suy biến, không có luật nhóm. Hãy đổi a hoặc b.', '4a³ + 27b² ≡ 0 (mod ' + p + '): a singular curve with no group law. Change a or b.');
      $('g2-hasse').innerHTML = ''; $('g2-order').innerHTML = ''; $('g2-add').innerHTML = ''; $('g3-table').innerHTML = ''; $('g3-ops').innerHTML = ''; $('g3-res').innerHTML = '';
      return;
    }
    pts = G2.pts = EC.enumerate(c);
    var want = (p === 17 && a === 2 && b === 2) ? [5n, 1n] : pts[0];
    G2.G = pts.some(function (q) { return q[0] === want[0] && q[1] === want[1]; }) ? want : pts[0];
    G2.P = pts[Math.min(1, pts.length - 1)]; G2.Q = pts[Math.floor(pts.length / 2)];
    G2.orbit = EC.orbit(c, G2.G); G2.step = 1;
    var nE = pts.length + 1, h = EC.hasse(c, nE);
    $('g2-count').className = 'result info';
    $('g2-count').innerHTML = bi('Số điểm #E = ' + pts.length + ' điểm affine + O = ', 'Number of points #E = ' + pts.length + ' affine points + O = ') + nb('<b>' + nE + '</b>');
    $('g2-hasse').innerHTML = bi('Định lý Hasse: |#E − (p + 1)| ≤ 2√p, tức ', 'Hasse\'s theorem: |#E − (p + 1)| ≤ 2√p, that is ') + nb(h.lo.toFixed(2) + ' ≤ #E ≤ ' + h.hi.toFixed(2)) + ' ' + (h.ok ? bi('— đúng.', '— satisfied.') : bi('— SAI (lỗi tính toán).', '— VIOLATED (a computation error).'));
    g2Draw(); g2Add(); g3Run();
  }
  function g2Draw() {
    var c = G2.c, r = (G2.P && G2.Q) ? EC.addTrace(c, G2.P, G2.Q) : null, ord = G2.orbit.length;
    PL.drawField($('g2-svg'), { p: G2.p, pts: G2.pts.map(pn), orbit: G2.orbit.map(pn), step: G2.step, G: pn(G2.G), P: pn(G2.P), Q: pn(G2.Q), R: r ? pn(r.R) : null, kind: r ? r.kind : null });
    var k = G2.step, Pk = G2.orbit[k - 1], nE = G2.pts.length + 1;
    $('g2-order').innerHTML = nb(k + 'G = ' + PL.ptStr(pn(Pk))) + ' · ' + (Pk === null
      ? bi('Quỹ đạo của G quay về O sau ' + ord + ' bước: <b>bậc của G là ' + ord + '</b>' + (ord === nE ? ' = #E, nên G sinh ra cả nhóm.' : ', một ước của #E = ' + nE + ' (G chỉ sinh ra một nhóm con có ' + ord + ' phần tử).'),
        'The orbit of G returns to O after ' + ord + ' steps: <b>G has order ' + ord + '</b>' + (ord === nE ? ' = #E, so G generates the whole group.' : ', a divisor of #E = ' + nE + ' (G generates only a subgroup of ' + ord + ' elements).'))
      : bi('bước ' + k + ' / ' + ord + ' — bấm Bước hoặc Chạy để đi tiếp tới O.', 'step ' + k + ' / ' + ord + ' — press Step or Play to continue to O.'));
    $('g2-step').disabled = G2.step >= ord; $('g2-play').disabled = G2.step >= ord;
  }
  function g2Add() {
    var c = G2.c, P = G2.P, Q = G2.Q, p = G2.p, el = $('g2-add'), r, t = new Trace();
    if (!P || !Q) { el.innerHTML = ''; return; }
    r = EC.addTrace(c, P, Q);
    t.line('P', 'P', PL.ptStr(pn(P))).line('Q', 'Q', PL.ptStr(pn(Q)));
    if (r.kind === 'inf') t.note('x₁ = x₂ và y₁ + y₂ ≡ 0: Q = −P, nên P + Q = O (điểm vô cực).', 'x₁ = x₂ and y₁ + y₂ ≡ 0: Q = −P, so P + Q = O (the point at infinity).');
    else {
      if (r.kind === 'dbl') t.line('P = Q: λ = (3x₁² + a)·(2y₁)⁻¹ mod p', 'P = Q: λ = (3x₁² + a)·(2y₁)⁻¹ mod p', '(3·' + P[0] + '² + ' + G2.a + ')·(2·' + P[1] + ')⁻¹ = ' + r.num + ' · ' + r.den + '⁻¹ (mod ' + p + ')');
      else t.line('λ = (y₂ − y₁)·(x₂ − x₁)⁻¹ mod p', 'λ = (y₂ − y₁)·(x₂ − x₁)⁻¹ mod p', '(' + Q[1] + ' − ' + P[1] + ')·(' + Q[0] + ' − ' + P[0] + ')⁻¹ = ' + r.num + ' · ' + r.den + '⁻¹ (mod ' + p + ')');
      t.line('Nghịch đảo: ' + r.den + '⁻¹ mod ' + p, 'Inverse: ' + r.den + '⁻¹ mod ' + p, r.inv + '   (' + r.den + ' · ' + r.inv + ' = ' + (Number(r.den) * Number(r.inv)) + ' ≡ 1 mod ' + p + ')');
      t.line('λ', 'λ', r.num + ' · ' + r.inv + ' mod ' + p + ' = ' + r.lam);
      t.line('x₃ = λ² − x₁ − x₂ mod p', 'x₃ = λ² − x₁ − x₂ mod p', r.lam + '² − ' + P[0] + ' − ' + Q[0] + ' ≡ ' + r.R[0]);
      t.line('y₃ = λ(x₁ − x₃) − y₁ mod p', 'y₃ = λ(x₁ − x₃) − y₁ mod p', r.lam + '·(' + P[0] + ' − ' + r.R[0] + ') − ' + P[1] + ' ≡ ' + r.R[1]);
      t.line(r.kind === 'dbl' ? '2P' : 'P + Q', r.kind === 'dbl' ? '2P' : 'P + Q', PL.ptStr(pn(r.R)), 'ok');
    }
    t.into(el);
  }
  function g2Pick(x, y) {                                  // bấm vào ô (x, y): gán G / P / Q nếu có điểm ở đó
    var q = null, i, mode = checked('g2-mode');
    for (i = 0; i < G2.pts.length; i++) if (Number(G2.pts[i][0]) === x && Number(G2.pts[i][1]) === y) q = G2.pts[i];
    if (!q) { $('g2-pickmsg').innerHTML = bi('Ô (' + x + ', ' + y + ') không phải điểm của đường cong: ' + x + '³ + ' + G2.a + '·' + x + ' + ' + G2.b + ' không phải bình phương của ' + y + ' mod ' + G2.p + '.', 'Cell (' + x + ', ' + y + ') is not a point of the curve: ' + x + '³ + ' + G2.a + '·' + x + ' + ' + G2.b + ' is not the square of ' + y + ' mod ' + G2.p + '.'); return; }
    $('g2-pickmsg').innerHTML = '';
    if (mode === 'G') { G2.G = q; G2.orbit = EC.orbit(G2.c, q); G2.step = 1; clearInterval(G2.timer); G2.timer = null; g3Run(); }
    else if (mode === 'Q') G2.Q = q; else G2.P = q;
    g2Draw(); g2Add();
  }
  function g2Init() {
    var svg = $('g2-svg');
    onRadio('g2-p', function () { var p = +checked('g2-p'), d = { 17: [2, 2], 23: [1, 1], 29: [4, 20], 97: [2, 3], 101: [3, 7] }[p]; $('g2-a').value = d[0]; $('g2-b').value = d[1]; g2Setup(); });
    $('g2-a').addEventListener('change', g2Setup); $('g2-b').addEventListener('change', g2Setup);
    $('g2-step').addEventListener('click', function () { if (G2.step < G2.orbit.length) { G2.step++; g2Draw(); } });
    $('g2-reset').addEventListener('click', function () { clearInterval(G2.timer); G2.timer = null; G2.step = 1; g2Draw(); });
    $('g2-play').addEventListener('click', function () {
      if (G2.timer) { clearInterval(G2.timer); G2.timer = null; return; }
      G2.timer = setInterval(function () { if (G2.step >= G2.orbit.length) { clearInterval(G2.timer); G2.timer = null; return; } G2.step++; g2Draw(); }, 450);
    });
    svg.addEventListener('click', function (ev) {
      var r = svg.getBoundingClientRect(), W = PL.FW, m = 34, cell = (W - 2 * m) / G2.p, u = (ev.clientX - r.left) / (r.width || W) * W, v = (ev.clientY - r.top) / (r.height || W) * W;
      var x = Math.floor((u - m) / cell), y = Math.floor((W - m - v) / cell);
      if (x >= 0 && x < G2.p && y >= 0 && y < G2.p) g2Pick(x, y);
    });
    g2Setup();
  }

  /* ================================================================ HÌNH 3: k·G từng bit */
  function g3Run() {
    var k = Math.floor(+$('g3-k').value), c = G2.c, G = G2.G, el = $('g3-table');
    if (!c || !G || c.disc === 0n) return;
    if (!(k >= 1 && k <= 999)) { $('g3-ops').innerHTML = bi('k phải từ 1 đến 999.', 'k must be between 1 and 999.'); el.innerHTML = ''; return; }
    var t = EC.mulTrace(c, B(k), G), ord = G2.orbit.length, viaOrbit = k <= ord ? G2.orbit[k - 1] : G2.orbit[((k - 1) % ord)];
    el.innerHTML = PL.ladderRows(t);
    $('g3-ops').innerHTML = bi('k = ' + k + ' = ' + t.bits + '₂ (' + t.bits.length + ' bit, ' + t.daOps.add + ' bit 1). Nhân đôi-và-cộng: ' + t.daOps.dbl + ' nhân đôi + ' + t.daOps.add + ' cộng - số phép cộng lộ số bit 1 của k. Thang Montgomery: ' + t.ladderOps.add + ' cộng + ' + t.ladderOps.dbl + ' nhân đôi, bit nào cũng như bit nào.',
      'k = ' + k + ' = ' + t.bits + '₂ (' + t.bits.length + ' bits, ' + t.daOps.add + ' ones). Double-and-add: ' + t.daOps.dbl + ' doublings + ' + t.daOps.add + ' additions - the number of additions reveals the ones of k. Montgomery ladder: ' + t.ladderOps.add + ' additions + ' + t.ladderOps.dbl + ' doublings, every bit alike.');
    var same = EC.eq(t.kP, t.ladder[t.ladder.length - 1].R0), vo = EC.eq(t.kP, viaOrbit);
    $('g3-res').className = 'result ' + (same && vo ? 'ok' : 'bad');
    $('g3-res').innerHTML = (same && vo ? '✓ ' : '✕ ') + nb(k + 'G = ' + PL.ptStr(pn(t.kP))) + ' — ' + (same ? bi('hai thuật toán cho cùng một điểm', 'both algorithms give the same point') : bi('HAI THUẬT TOÁN KHÁC NHAU', 'THE TWO ALGORITHMS DISAGREE')) +
      (k <= ord ? (vo ? bi(', trùng điểm số ' + k + ' trên quỹ đạo ở hình 2.', ', equal to point number ' + k + ' of the orbit in figure 2.') : bi(', KHÁC điểm số ' + k + ' trên quỹ đạo.', ', DIFFERENT from orbit point ' + k + '.'))
        : bi('. k vượt bậc của G nên kG = (k mod ' + ord + ')G.', '. k exceeds the order of G, so kG = (k mod ' + ord + ')G.'));
  }

  /* ================================================================ THẺ 1: sinh cặp khoá (FIPS 186-5 A.2.1 / A.2.2) */
  var KG = new Tab('kg'), F = {};
  function kgRun(exp) {
    var c = cur('kg-curve'), method = checked('kg-method'), t = new Trace(), t0 = performance.now(), d, Q, r;
    if ($('kg-d-rnd').checked) {
      r = EC.keygen(c, method, rnd); d = r.d; F.kgD.set(d, c);
      if (method === 'A.2.1') t.line('c = RBG(N + 64) (' + (c.N + 64) + ' bit ngẫu nhiên)', 'c = RBG(N + 64) (' + (c.N + 64) + ' random bits)', hex(r.c)).line('d = (c mod (n − 1)) + 1', 'd = (c mod (n − 1)) + 1', hex(d, c));
      else t.line('c = RBG(N) (' + c.N + ' bit); loại nếu c > n − 2', 'c = RBG(N) (' + c.N + ' bits); reject if c > n − 2', hex(r.c) + (r.tries > 1 ? '   (' + r.tries + ')' : '')).line('d = c + 1', 'd = c + 1', hex(d, c));
    } else {
      d = bigOf(F.kgD, KG.fail); if (d === null) return;
      if (!EC.scalarOk(c, d)) return KG.fail(bi('d phải nằm trong [1, n − 1] của ' + c.name + '.', 'd must lie in [1, n − 1] of ' + c.name + '.'));
      t.line('d (nhập tay, đã kiểm 1 ≤ d ≤ n − 1)', 'd (typed, checked 1 ≤ d ≤ n − 1)', hex(d, c));
    }
    Q = EC.publicOf(c, d);
    t.line('Q = d·G (thang Montgomery, ' + c.N + ' bước)', 'Q = d·G (Montgomery ladder, ' + c.N + ' steps)', '').line('Q.x', 'Q.x', hex(Q[0], c)).line('Q.y', 'Q.y', hex(Q[1], c));
    t.line('Kiểm lại: Q trên đường cong', 'Check: Q on the curve', EC.onCurve(c, Q) ? '✓' : '✕', 'ok');
    F.kgQx.set(Q[0], c); F.kgQy.set(Q[1], c); t.into(KG.tr);
    var dt = performance.now() - t0;
    if (exp) { var cm = cmp([['Q.x', hex(Q[0], c), exp.qx], ['Q.y', hex(Q[1], c), exp.qy]]); return exVerdict(KG, cm.ok, exp, cm.html, dt); }
    KG.show('ok', '✓ ' + bi('Đã sinh cặp khoá ' + c.name + ' theo FIPS 186-5 ' + method + '.', 'Generated a ' + c.name + ' key pair by FIPS 186-5 ' + method + '.') + ms(dt));
  }
  function kgInit() {
    F.kgD = new Field('kg-d', { name: ['khoá riêng d', 'private key d'], need: function () { return cur('kg-curve').bytes; } });
    F.kgQx = new Field('kg-qx', { name: ['Q.x', 'Q.x'] }); F.kgQy = new Field('kg-qy', { name: ['Q.y', 'Q.y'] });
    $('kg-gen').addEventListener('click', function () { kgRun(); });
    onRadio('kg-curve', function () { F.kgD.count(); F.kgQx.set(null); F.kgQy.set(null); KG.show('info', bi('Đã chọn ' + checked('kg-curve') + '.', checked('kg-curve') + ' selected.')); KG.tr.hidden = true; });
    exButtons($('kg-ex'), V.keygen, function (v) { setRadio('kg-curve', v.curve); $('kg-d-rnd').checked = false; F.kgD.set(v.d); if (v.mode) setRadio('kg-method', v.mode === 'extra bits' ? 'A.2.1' : 'A.2.2'); kgRun(v); });
    KG.show('info', bi('Chọn đường cong, để "d ngẫu nhiên" hoặc nhập d, rồi bấm Sinh cặp khoá.', 'Choose a curve, keep "random d" or type one, then press Generate.'));
  }

  /* ================================================================ THẺ 2: kiểm tra khoá công khai (SP 800-56A r3, 5.6.2.3.3) */
  var PV = new Tab('pv');
  function pvRun(exp) {
    var c = cur('pv-curve'), qx = bigOf(F.pvQx, PV.fail); if (qx === null) return;
    var qy = bigOf(F.pvQy, PV.fail); if (qy === null) return;
    var t0 = performance.now(), v = EC.validate(c, [qx, qy], false), t = new Trace(), dt = performance.now() - t0;
    t.line('p', 'p', hex(c.p, c)).line('Q.x', 'Q.x', hex(qx)).line('Q.y', 'Q.y', hex(qy));
    pkvTrace(t, c, v); t.into(PV.tr);
    var main = v.ok ? '✓ ' + bi('Khoá công khai HỢP LỆ trên ' + c.name + ' (cả bốn bước).', 'The public key is VALID on ' + c.name + ' (all four steps).')
      : '✕ ' + bi('Khoá công khai KHÔNG hợp lệ: ' + PKV_WHY[v.reason][0] + ' (bước ' + v.steps.length + ').', 'The public key is INVALID: ' + PKV_WHY[v.reason][1] + ' (step ' + v.steps.length + ').');
    if (exp) { var cm = cmp([[exp.valid ? 'P' : 'F', v.ok ? 'P' : 'F', exp.valid ? 'P' : 'F']]); return exVerdict(PV, cm.ok, exp, cm.html + '<span class="sub">' + main + '</span>', dt); }
    PV.show(v.ok ? 'ok' : 'bad', main + ms(dt));
  }
  function pvInit() {
    F.pvQx = new Field('pv-qx', { name: ['Q.x', 'Q.x'], need: function () { return cur('pv-curve').bytes; } });
    F.pvQy = new Field('pv-qy', { name: ['Q.y', 'Q.y'], need: function () { return cur('pv-curve').bytes; } });
    $('pv-check').addEventListener('click', function () { pvRun(); });
    $('pv-from-kg').addEventListener('click', function () { if (F.kgQx.empty()) return PV.fail(bi('Thẻ Sinh cặp khoá chưa có Q.', 'The key-pair tab has no Q yet.')); setRadio('pv-curve', checked('kg-curve')); F.pvQx.set(F.kgQx.ta.value); F.pvQy.set(F.kgQy.ta.value); pvRun(); });
    $('pv-break').addEventListener('click', function () { var y = bigOf(F.pvQy, PV.fail); if (y === null) return; F.pvQy.set(y + 1n); pvRun(); });
    onRadio('pv-curve', function () { F.pvQx.count(); F.pvQy.count(); });
    exButtons($('pv-ex'), V.pkv, function (v) { setRadio('pv-curve', v.curve); F.pvQx.set(v.qx); F.pvQy.set(v.qy); pvRun(v); });
    PV.show('info', bi('Dán Q.x, Q.y (hoặc lấy Q từ thẻ Sinh cặp khoá) rồi bấm Kiểm tra.', 'Paste Q.x, Q.y (or take Q from the key-pair tab), then press Validate.'));
  }

  /* ================================================================ THẺ 3: ECC CDH, hai bên (SP 800-56A r3, 5.7.1.2) */
  var DH = new Tab('dh');
  function dhGen(side) {
    var c = cur('dh-curve'), d = randomOr('dh-d' + side + '-rnd', F['dhD' + side], c, DH.fail); if (d === null) return null;
    if (!EC.scalarOk(c, d)) { DH.fail(bi('d phải nằm trong [1, n − 1].', 'd must lie in [1, n − 1].')); return null; }
    var Q = EC.publicOf(c, d); F['dhQ' + side + 'x'].set(Q[0], c); F['dhQ' + side + 'y'].set(Q[1], c);
    F.dhZa.set(null); F.dhZb.set(null); dhCards();
    DH.show('info', bi((side === 'a' ? 'Alice' : 'Bob') + ' đã có cặp khoá. ', (side === 'a' ? 'Alice' : 'Bob') + ' has a key pair. ') + (F.dhQax.empty() || F.dhQbx.empty() ? bi('Bên kia cũng cần một cặp khoá.', 'The other side needs one too.') : bi('Bấm "Trao đổi và tính Z".', 'Press "Exchange and compute Z".')));
    return d;
  }
  function dhCards() { var a = !F.dhQax.empty(), b = !F.dhQbx.empty(), z = !F.dhZa.empty(); $('dh-c1').classList.toggle('done', a); $('dh-c2').classList.toggle('done', b); $('dh-c3').classList.toggle('done', z); $('dh-arrow').classList.toggle('lit', a && b); }
  function dhSide(c, who, dF, Qx, Qy, t) {                 // một bên: kiểm tra khoá bên kia rồi Z = x(d·Q_peer)
    var d = bigOf(dF, DH.fail); if (d === null) return null;
    var qx = bigOf(Qx, DH.fail); if (qx === null) return null;
    var qy = bigOf(Qy, DH.fail); if (qy === null) return null;
    var r = EC.ecdh(c, d, [qx, qy]);
    t.note(who === 'a' ? 'Alice kiểm tra đầy đủ khoá công khai của Bob (5.6.2.3.3) rồi mới nhân:' : 'Bob kiểm tra đầy đủ khoá công khai của Alice (5.6.2.3.3) rồi mới nhân:',
      who === 'a' ? 'Alice fully validates Bob\'s public key (5.6.2.3.3) before multiplying:' : 'Bob fully validates Alice\'s public key (5.6.2.3.3) before multiplying:');
    pkvTrace(t, c, r.pkv);
    if (r.err) { t.note('Dừng: ' + (r.err === 'SCALAR' ? 'd ngoài [1, n − 1]' : r.err === 'INFINITY' ? 'd·Q = O' : 'khoá của bên kia không hợp lệ - ' + PKV_WHY[r.err.slice(4)][0]), 'Stop: ' + (r.err === 'SCALAR' ? 'd outside [1, n − 1]' : r.err === 'INFINITY' ? 'd·Q = O' : 'the peer\'s key is invalid - ' + PKV_WHY[r.err.slice(4)][1]), 'bad'); return r; }
    t.line((who === 'a' ? 'Alice' : 'Bob') + ': P = d·Q_peer', (who === 'a' ? 'Alice' : 'Bob') + ': P = d·Q_peer', ptStr(r.P, c)).line('Z = P.x (' + c.bytes + ' byte)', 'Z = P.x (' + c.bytes + ' bytes)', hex(r.Z, c), 'ok');
    return r;
  }
  function dhRun(exp) {
    var c = cur('dh-curve'), t = new Trace(), t0 = performance.now();
    var ra = dhSide(c, 'a', F.dhDa, F.dhQbx, F.dhQby, t); if (ra === null) return;
    var rb = exp && !exp.peer_d ? null : dhSide(c, 'b', F.dhDb, F.dhQax, F.dhQay, t); if (rb === null && !(exp && !exp.peer_d)) return;
    t.into(DH.tr); var dt = performance.now() - t0;
    F.dhZa.set(ra.err ? null : ra.Z, c); F.dhZb.set(rb && !rb.err ? rb.Z : null, c); dhCards();
    if (exp) {
      var rows = [['Q_IUT.x', F.dhQax.ta.value, exp.qx], ['Q_IUT.y', F.dhQay.ta.value, exp.qy], ['Z', ra.err ? 'error' : hex(ra.Z, c), exp.z]];
      if (rb) rows.push(['Z (bên kia / peer side)', rb.err ? 'error' : hex(rb.Z, c), exp.z]);
      var cm = cmp(rows); return exVerdict(DH, cm.ok, exp, cm.html, dt);
    }
    if (ra.err) return DH.show('bad', '✕ ' + bi('Alice từ chối: khoá công khai của Bob không hợp lệ (' + (ra.err.indexOf('KEY_') === 0 ? PKV_WHY[ra.err.slice(4)][0] : ra.err) + '). Không tính Z - đây chính là chỗ chặn tấn công đường cong sai.',
      'Alice refuses: Bob\'s public key is invalid (' + (ra.err.indexOf('KEY_') === 0 ? PKV_WHY[ra.err.slice(4)][1] : ra.err) + '). No Z is computed - this is exactly what stops the invalid-curve attack.'));
    if (rb.err) return DH.show('bad', '✕ ' + bi('Bob từ chối: khoá công khai của Alice không hợp lệ.', 'Bob refuses: Alice\'s public key is invalid.'));
    var same = ra.Z === rb.Z;
    DH.show(same ? 'ok' : 'bad', (same ? '✓ ' : '✕ ') + (same ? bi('Hai bên tính ra cùng một Z: d_A·(d_B·G) = d_B·(d_A·G) = d_A·d_B·G. Z chưa phải khoá: SP 800-56A đưa Z qua một hàm dẫn xuất khoá (SP 800-56C) rồi mới dùng.',
      'Both sides get the same Z: d_A·(d_B·G) = d_B·(d_A·G) = d_A·d_B·G. Z is not yet a key: SP 800-56A passes it through a key-derivation function (SP 800-56C) first.')
      : bi('Z KHÁC nhau: một khoá công khai không đi cùng khoá riêng của nó.', 'The Z values DIFFER: a public key does not belong with its private key.')) + ms(dt));
  }
  function dhInit() {
    var need = function () { return cur('dh-curve').bytes; };
    ['a', 'b'].forEach(function (s) {
      F['dhD' + s] = new Field('dh-d' + s, { name: ['d của ' + (s === 'a' ? 'Alice' : 'Bob'), (s === 'a' ? 'Alice' : 'Bob') + '\'s d'], need: need, onEdit: function () { F['dhQ' + s + 'x'].set(null); F['dhQ' + s + 'y'].set(null); F.dhZa.set(null); F.dhZb.set(null); dhCards(); } });
      F['dhQ' + s + 'x'] = new Field('dh-q' + s + 'x', { name: ['Q.x', 'Q.x'], need: need, onEdit: function () { F.dhZa.set(null); F.dhZb.set(null); dhCards(); } });
      F['dhQ' + s + 'y'] = new Field('dh-q' + s + 'y', { name: ['Q.y', 'Q.y'], need: need, onEdit: function () { F.dhZa.set(null); F.dhZb.set(null); dhCards(); } });
      $('dh-gen-' + s).addEventListener('click', function () { dhGen(s); });
    });
    F.dhZa = new Field('dh-za', { name: ['Z của Alice', 'Alice\'s Z'] }); F.dhZb = new Field('dh-zb', { name: ['Z của Bob', 'Bob\'s Z'] });
    $('dh-compute').addEventListener('click', function () { dhRun(); });
    $('dh-break').addEventListener('click', function () { var y = bigOf(F.dhQby, DH.fail); if (y === null) return; F.dhQby.set(y + 1n); F.dhZa.set(null); F.dhZb.set(null); dhCards(); DH.show('info', bi('Đã cộng 1 vào Q_B.y: điểm không còn trên đường cong. Bấm "Trao đổi và tính Z".', 'Added 1 to Q_B.y: the point is no longer on the curve. Press "Exchange and compute Z".')); });
    onRadio('dh-curve', function () { ['dhDa', 'dhDb', 'dhQax', 'dhQay', 'dhQbx', 'dhQby', 'dhZa', 'dhZb'].forEach(function (k) { F[k].set(null); }); dhCards(); DH.tr.hidden = true; DH.show('info', bi('Đã chuyển sang ' + checked('dh-curve') + '; các ô đã được xoá.', 'Switched to ' + checked('dh-curve') + '; the fields were cleared.')); });
    exButtons($('dh-ex'), V.cdh, function (v) {
      setRadio('dh-curve', v.curve); var c = EC.CURVES[v.curve]; $('dh-da-rnd').checked = false; $('dh-db-rnd').checked = false;
      F.dhDa.set(v.d); var Qa = EC.publicOf(c, B('0x' + v.d)); F.dhQax.set(Qa[0], c); F.dhQay.set(Qa[1], c);
      F.dhQbx.set(v.peer_x); F.dhQby.set(v.peer_y); F.dhDb.set(v.peer_d || null); dhCards(); dhRun(v);
    });
    dhCards(); DH.show('info', bi('Bước 1: mỗi bên sinh cặp khoá. Bước 2: trao đổi khoá công khai. Bước 3: mỗi bên tính Z = x(d·Q_peer).', 'Step 1: each side generates a key pair. Step 2: exchange public keys. Step 3: each side computes Z = x(d·Q_peer).'));
  }

  /* ================================================================ THẺ 4: ký ECDSA (FIPS 186-5, 6.4.1) */
  var SG = new Tab('sg');
  function sgRun(exp) {
    var c = cur('sg-curve'), hn = checked('sg-hash'), kmode = checked('sg-kmode'), t = new Trace(), t0 = performance.now();
    if (c.name === 'P-192') return SG.fail(bi('Không ký trên P-192: đường cong này chỉ cho khoảng 80 bit an ninh (SP 800-57), dưới mức tối thiểu 112 bit mà SP 800-131A yêu cầu khi TẠO chữ ký, nên các bộ vector ECDSA hiện hành của NIST (ACVP KeyGen / SigGen) bắt đầu từ P-224. Xác minh chữ ký P-192 cũ vẫn được phép ("legacy use") - xem thẻ Xác minh.',
      'No signing on P-192: this curve gives about 80 bits of security (SP 800-57), below the 112-bit minimum SP 800-131A requires for signature GENERATION, which is why NIST\'s current ECDSA vector sets (ACVP KeyGen / SigGen) start at P-224. Verifying old P-192 signatures is still allowed ("legacy use") - see the Verify tab.'));
    var d = randomOr('sg-d-rnd', F.sgD, c, SG.fail); if (d === null) return;
    if (!EC.scalarOk(c, d)) return SG.fail(bi('d phải nằm trong [1, n − 1].', 'd must lie in [1, n − 1].'));
    var m = bytesOf(F.sgMsg, SG.fail); if (m === null) return;
    var h = EC.hash(hn), h1 = h.fn(m), bi2 = EC.bits2int(c, h1), e = bi2.e, k, kk;
    t.line('H(M) = ' + HLABEL[hn] + '(M), ' + bi2.hbits + ' bit', 'H(M) = ' + HLABEL[hn] + '(M), ' + bi2.hbits + ' bits', hexOfBytes(h1));
    t.line(bi2.shift ? 'e = bits2int(H): ' + bi2.hbits + ' bit băm > N = ' + c.N + ' bit, giữ ' + c.N + ' bit trái, bỏ ' + bi2.shift + ' bit phải' : 'e = bits2int(H): ' + bi2.hbits + ' bit băm ≤ N = ' + c.N + ' bit, giữ nguyên',
      bi2.shift ? 'e = bits2int(H): ' + bi2.hbits + ' hash bits > N = ' + c.N + ' bits, keep the left ' + c.N + ', drop the right ' + bi2.shift : 'e = bits2int(H): ' + bi2.hbits + ' hash bits ≤ N = ' + c.N + ' bits, unchanged', hex(e));
    if (kmode === 'given') { k = bigOf(F.sgK, SG.fail); if (k === null) return; t.line('k (cho trước, như file SigGen của CAVS)', 'k (given, as in CAVS SigGen)', hex(k, c)); }
    else if (kmode === 'det') { kk = EC.rfc6979(c, d, h1, h); k = kk.k; F.sgK.set(k, c); t.line('k = HMAC_DRBG(d, H(M)) theo RFC 6979 với HMAC-' + HLABEL[hn] + (kk.rounds > 1 ? ', ' + kk.rounds + ' vòng' : ''), 'k = HMAC_DRBG(d, H(M)) per RFC 6979 with HMAC-' + HLABEL[hn] + (kk.rounds > 1 ? ', ' + kk.rounds + ' rounds' : ''), hex(k, c)); }
    else { k = EC.keygen(c, 'A.2.1', rnd).d; F.sgK.set(k, c); t.line('k ngẫu nhiên trong [1, n − 1] (RBG; phải khác nhau ở mỗi chữ ký)', 'random k in [1, n − 1] (RBG; must differ for every signature)', hex(k, c)); }
    var s = EC.sign(c, d, e, k);
    if (s.err) return SG.fail(s.err === 'K_RANGE' ? bi('k phải nằm trong [1, n − 1].', 'k must lie in [1, n − 1].') : bi('r = 0 hoặc s = 0 (xác suất ~2⁻ᴺ): FIPS 186-5 bảo chọn k khác.', 'r = 0 or s = 0 (probability ~2⁻ᴺ): FIPS 186-5 says pick another k.'));
    t.line('R = k·G', 'R = k·G', ptStr(s.R, c)).line('r = R.x mod n', 'r = R.x mod n', hex(s.r, c)).line('k⁻¹ mod n', 'k⁻¹ mod n', hex(s.kinv, c)).line('s = k⁻¹(e + d·r) mod n', 's = k⁻¹(e + d·r) mod n', hex(s.s, c), 'ok');
    t.into(SG.tr); F.sgR.set(s.r, c); F.sgS.set(s.s, c);
    var dt = performance.now() - t0;
    if (exp) { var rows = [['r', hex(s.r, c), exp.r], ['s', hex(s.s, c), exp.s]]; if (kmode === 'det') rows.unshift(['k (RFC 6979)', hex(k, c), exp.k]); var cm = cmp(rows); return exVerdict(SG, cm.ok, exp, cm.html, dt); }
    SG.show('ok', '✓ ' + bi('Đã ký với ' + c.name + ' và ' + HLABEL[hn] + ' (' + (kmode === 'det' ? 'k tất định RFC 6979' : kmode === 'given' ? 'k cho trước' : 'k ngẫu nhiên') + '). Chữ ký (r, s) dài 2 × ' + c.bytes + ' byte.',
      'Signed with ' + c.name + ' and ' + HLABEL[hn] + ' (' + (kmode === 'det' ? 'deterministic k, RFC 6979' : kmode === 'given' ? 'given k' : 'random k') + '). The signature (r, s) is 2 × ' + c.bytes + ' bytes.') + ms(dt));
  }
  function sgInit() {
    var need = function () { return cur('sg-curve').bytes; };
    F.sgD = new Field('sg-d', { name: ['khoá riêng d', 'private key d'], need: need });
    F.sgMsg = new Field('sg-msg', { name: ['thông điệp', 'message'], msg: true });
    F.sgK = new Field('sg-k', { name: ['k', 'k'], need: need });
    F.sgR = new Field('sg-r', { name: ['r', 'r'] }); F.sgS = new Field('sg-s', { name: ['s', 's'] });
    $('sg-sign').addEventListener('click', function () { sgRun(); });
    $('sg-to-verify').addEventListener('click', function () {
      if (F.sgR.empty()) return SG.fail(bi('Chưa có chữ ký.', 'No signature yet.'));
      var c = cur('sg-curve'), d; try { d = F.sgD.big(); } catch (e) { return SG.fail(bi('Ô d đang trống.', 'The d field is empty.')); }
      var Q = EC.publicOf(c, d);
      setRadio('sv-curve', c.name); setRadio('sv-hash', checked('sg-hash')); F.svQx.set(Q[0], c); F.svQy.set(Q[1], c);
      if (F.sgMsg.fmt === 'text') F.svMsg.setText(F.sgMsg.ta.value); else F.svMsg.setBytes(F.sgMsg.bytes());
      F.svR.set(F.sgR.ta.value); F.svS.set(F.sgS.ta.value); $('tab-sv').click(); svRun();
    });
    onRadio('sg-kmode', function () { var g = checked('sg-kmode') === 'given'; $('sg-k').readOnly = !g; $('sg-k-wrap').classList.toggle('given', g); });
    onRadio('sg-curve', function () { F.sgD.count(); F.sgK.count(); F.sgR.set(null); F.sgS.set(null); SG.tr.hidden = true; SG.show('info', bi('Đã chọn ' + checked('sg-curve') + '.', checked('sg-curve') + ' selected.')); });
    exButtons($('sg-ex'), V.siggen.concat(V.det), function (v) {
      setRadio('sg-curve', v.curve); setRadio('sg-hash', v.hash); $('sg-d-rnd').checked = false; F.sgD.set(v.d);
      if (v.text !== undefined) F.sgMsg.setText(v.text); else F.sgMsg.setBytes(unhexBytes(v.msg));
      if (v.src.indexOf('DetECDSA') >= 0 || v.src.indexOf('RFC 6979') >= 0) { setRadio('sg-kmode', 'det'); F.sgK.set(null); } else { setRadio('sg-kmode', 'given'); F.sgK.set(v.k); }
      sgRun(v);
    });
    $('sg-k').readOnly = true;
    SG.show('info', bi('Nhập thông điệp, chọn hàm băm và cách lấy k, rồi bấm Ký.', 'Enter a message, pick the hash and how k is chosen, then press Sign.'));
  }

  /* ================================================================ THẺ 5: xác minh ECDSA (FIPS 186-5, 6.4.2) */
  var SV = new Tab('sv');
  var SV_WHY = { R_RANGE: ['r ngoài [1, n − 1]', 'r outside [1, n − 1]'], S_RANGE: ['s ngoài [1, n − 1]', 's outside [1, n − 1]'], INFINITY: ['R′ = u₁G + u₂Q = O', 'R′ = u₁G + u₂Q = O'],
    MISMATCH: ['x(R′) mod n ≠ r', 'x(R′) mod n ≠ r'], KEY_INFINITY: ['Q là O', 'Q is O'], KEY_RANGE: ['toạ độ của Q ngoài [0, p − 1]', 'a coordinate of Q is outside [0, p − 1]'], KEY_NOT_ON_CURVE: ['Q không nằm trên đường cong', 'Q is not on the curve'] };
  function svRun(exp) {
    var c = cur('sv-curve'), hn = checked('sv-hash'), t = new Trace(), t0 = performance.now();
    var qx = bigOf(F.svQx, SV.fail); if (qx === null) return;
    var qy = bigOf(F.svQy, SV.fail); if (qy === null) return;
    var m = bytesOf(F.svMsg, SV.fail); if (m === null) return;
    var r = bigOf(F.svR, SV.fail); if (r === null) return;
    var s = bigOf(F.svS, SV.fail); if (s === null) return;
    var h = EC.hash(hn), h1 = h.fn(m), e = EC.bits2int(c, h1).e, v = EC.verify(c, [qx, qy], e, r, s);
    t.line('1 ≤ r ≤ n − 1', '1 ≤ r ≤ n − 1', v.reason === 'R_RANGE' ? '✕' : '✓', v.reason === 'R_RANGE' ? 'bad' : 'ok');
    if (v.reason !== 'R_RANGE') t.line('1 ≤ s ≤ n − 1', '1 ≤ s ≤ n − 1', v.reason === 'S_RANGE' ? '✕' : '✓', v.reason === 'S_RANGE' ? 'bad' : 'ok');
    if (v.reason !== 'R_RANGE' && v.reason !== 'S_RANGE') t.line('Q hợp lệ (≠ O, trong phạm vi, trên đường cong)', 'Q valid (≠ O, in range, on the curve)', v.reason && v.reason.indexOf('KEY_') === 0 ? '✕ ' + SV_WHY[v.reason][1] : '✓', v.reason && v.reason.indexOf('KEY_') === 0 ? 'bad' : 'ok');
    if (v.trace.w !== undefined) {
      t.line('e = bits2int(' + HLABEL[hn] + '(M))', 'e = bits2int(' + HLABEL[hn] + '(M))', hex(e)).line('w = s⁻¹ mod n', 'w = s⁻¹ mod n', hex(v.trace.w, c)).line('u₁ = e·w mod n', 'u₁ = e·w mod n', hex(v.trace.u1, c)).line('u₂ = r·w mod n', 'u₂ = r·w mod n', hex(v.trace.u2, c));
      t.line('R′ = u₁·G + u₂·Q', 'R′ = u₁·G + u₂·Q', ptStr(v.trace.R, c));
      if (v.trace.R) t.line('v = R′.x mod n', 'v = R′.x mod n', hex(v.trace.v, c)).line('v = r ?', 'v = r ?', v.ok ? '✓' : '✕', v.ok ? 'ok' : 'bad');
    }
    t.into(SV.tr); var dt = performance.now() - t0;
    var main = v.ok ? '✓ ' + bi('Chữ ký HỢP LỆ trên ' + c.name + ' với ' + HLABEL[hn] + '.', 'The signature is VALID on ' + c.name + ' with ' + HLABEL[hn] + '.')
      : '✕ ' + bi('Chữ ký KHÔNG hợp lệ: ' + SV_WHY[v.reason][0] + '.', 'The signature is INVALID: ' + SV_WHY[v.reason][1] + '.');
    if (exp) { var cm = cmp([[exp.valid ? 'P' : 'F', v.ok ? 'P' : 'F', exp.valid ? 'P' : 'F']]); return exVerdict(SV, cm.ok, exp, cm.html + '<span class="sub">' + main + (exp.comment ? ' ' + bi('Ghi chú của NIST về ca này: ', 'NIST\'s note on this case: ') + nb(esc(exp.comment)) : '') + '</span>', dt); }
    SV.show(v.ok ? 'ok' : 'bad', main + ms(dt));
  }
  function svInit() {
    var need = function () { return cur('sv-curve').bytes; };
    F.svQx = new Field('sv-qx', { name: ['Q.x', 'Q.x'], need: need }); F.svQy = new Field('sv-qy', { name: ['Q.y', 'Q.y'], need: need });
    F.svMsg = new Field('sv-msg', { name: ['thông điệp', 'message'], msg: true });
    F.svR = new Field('sv-r', { name: ['r', 'r'], need: need }); F.svS = new Field('sv-s', { name: ['s', 's'], need: need });
    $('sv-verify').addEventListener('click', function () { svRun(); });
    $('sv-flip').addEventListener('click', function () { var b; try { b = F.svMsg.bytes(); } catch (e) { return SV.fail(bi('Thông điệp không đọc được.', 'The message cannot be read.')); } if (!b.length) return SV.fail(bi('Thông điệp đang trống.', 'The message is empty.')); b = Uint8Array.from(b); b[b.length >> 1] ^= 1; F.svMsg.setBytes(b); svRun(); });
    onRadio('sv-curve', function () { ['svQx', 'svQy', 'svR', 'svS'].forEach(function (k) { F[k].count(); }); });
    exButtons($('sv-ex'), V.sigver, function (v) { setRadio('sv-curve', v.curve); setRadio('sv-hash', v.hash); F.svQx.set(v.qx); F.svQy.set(v.qy); F.svMsg.setBytes(unhexBytes(v.msg)); F.svR.set(v.r); F.svS.set(v.s); svRun(v); });
    SV.show('info', bi('Dán Q, thông điệp và (r, s) - hoặc ký ở thẻ bên cạnh rồi bấm "Đưa sang xác minh".', 'Paste Q, the message and (r, s) - or sign in the previous tab and press "Send to Verify".'));
  }

  /* ================================================================ THẺ 6: tấn công nonce */
  var AT = new Tab('at');
  function atSign() {
    var c = cur('at-curve'), t0 = performance.now(), d = randomOr('at-d-rnd', F.atD, c, AT.fail); if (d === null) return;
    var k = randomOr('at-k-rnd', F.atK, c, AT.fail); if (k === null) return;
    if (!EC.scalarOk(c, d) || !EC.scalarOk(c, k)) return AT.fail(bi('d và k phải nằm trong [1, n − 1].', 'd and k must lie in [1, n − 1].'));
    var h = EC.hash('SHA2-256'), m1 = bytesOf(F.atM1, AT.fail), m2 = bytesOf(F.atM2, AT.fail); if (m1 === null || m2 === null) return;
    var e1 = EC.bits2int(c, h.fn(m1)).e, e2 = EC.bits2int(c, h.fn(m2)).e, s1 = EC.sign(c, d, e1, k), s2 = EC.sign(c, d, e2, k), Q = EC.publicOf(c, d);
    if (s1.err || s2.err) return AT.fail(bi('r = 0 hoặc s = 0: chọn k khác.', 'r = 0 or s = 0: pick another k.'));
    F.atQx.set(Q[0], c); F.atQy.set(Q[1], c); F.atR1.set(s1.r, c); F.atS1.set(s1.s, c); F.atR2.set(s2.r, c); F.atS2.set(s2.s, c); F.atD2.set(null); F.atD3.set(null);
    AT.tr.hidden = true;
    AT.show('info', bi('Hai chữ ký với CÙNG k: r₁ = r₂ = ' + hex(s1.r, c).slice(0, 16) + '… - kẻ tấn công nhìn thấy ngay. Bấm "Khôi phục d từ hai chữ ký".', 'Two signatures with the SAME k: r₁ = r₂ = ' + hex(s1.r, c).slice(0, 16) + '… - an attacker sees this at once. Press "Recover d from the two signatures".') + ms(performance.now() - t0));
  }
  function atRecover() {
    var c = cur('at-curve'), t = new Trace(), t0 = performance.now(), h = EC.hash('SHA2-256');
    var r1 = bigOf(F.atR1, AT.fail); if (r1 === null) return;
    var s1 = bigOf(F.atS1, AT.fail), s2 = bigOf(F.atS2, AT.fail), r2 = bigOf(F.atR2, AT.fail); if (s1 === null || s2 === null || r2 === null) return;
    var qx = bigOf(F.atQx, AT.fail), qy = bigOf(F.atQy, AT.fail); if (qx === null || qy === null) return;
    var m1 = bytesOf(F.atM1, AT.fail), m2 = bytesOf(F.atM2, AT.fail); if (m1 === null || m2 === null) return;
    if (r1 !== r2) return AT.fail(bi('r₁ ≠ r₂: hai chữ ký không dùng chung k, công thức không áp dụng được.', 'r₁ ≠ r₂: the two signatures do not share k, so the formula does not apply.'));
    var e1 = EC.bits2int(c, h.fn(m1)).e, e2 = EC.bits2int(c, h.fn(m2)).e, rec = EC.nonceReuse(c, e1, s1, e2, s2, r1);
    if (rec.err) return AT.fail(bi('s₁ = s₂ (hai thông điệp giống nhau): không có phương trình thứ hai.', 's₁ = s₂ (identical messages): there is no second equation.'));
    t.line('e₁ = bits2int(SHA-256(M₁))', 'e₁ = bits2int(SHA-256(M₁))', hex(e1)).line('e₂ = bits2int(SHA-256(M₂))', 'e₂ = bits2int(SHA-256(M₂))', hex(e2));
    t.note('s₁ = k⁻¹(e₁ + d·r) và s₂ = k⁻¹(e₂ + d·r) với cùng k, r: trừ nhau được k(s₁ − s₂) = e₁ − e₂.', 's₁ = k⁻¹(e₁ + d·r) and s₂ = k⁻¹(e₂ + d·r) with the same k, r: subtracting gives k(s₁ − s₂) = e₁ − e₂.');
    t.line('k = (e₁ − e₂)·(s₁ − s₂)⁻¹ mod n', 'k = (e₁ − e₂)·(s₁ − s₂)⁻¹ mod n', hex(rec.k, c)).line('d = (s₁·k − e₁)·r⁻¹ mod n', 'd = (s₁·k − e₁)·r⁻¹ mod n', hex(rec.d, c), 'ok');
    var Q = EC.publicOf(c, rec.d), ok = Q[0] === qx && Q[1] === qy;
    t.line('Kiểm: d·G có bằng Q không?', 'Check: does d·G equal Q?', ok ? '✓ ' + ptStr(Q, c) : '✕ ' + ptStr(Q, c), ok ? 'ok' : 'bad');
    t.into(AT.tr); F.atD2.set(rec.d, c);
    AT.show(ok ? 'ok' : 'bad', (ok ? '✓ ' : '✕ ') + (ok ? bi('Khôi phục được khoá riêng d từ hai chữ ký công khai: d·G = Q. Đây là lỗi của PlayStation 3 (2010) và của nhiều ví Bitcoin trên Android (2013). Phần cứng: k phải đến từ DRBG đạt SP 800-90 hoặc RFC 6979, không bao giờ từ bộ đếm hay LFSR.',
      'The private key d was recovered from two public signatures: d·G = Q. This was the PlayStation 3 flaw (2010) and that of several Android Bitcoin wallets (2013). In hardware, k must come from an SP 800-90 DRBG or RFC 6979, never from a counter or an LFSR.')
      : bi('d khôi phục được KHÔNG khớp Q - hai chữ ký không thuộc cùng một khoá.', 'The recovered d does NOT match Q - the two signatures are not from the same key.')) + ms(performance.now() - t0));
  }
  function atLeak() {
    var c = cur('at-curve'), h = EC.hash('SHA2-256'), k = bigOf(F.atK, AT.fail); if (k === null) return;
    var r = bigOf(F.atR1, AT.fail), s = bigOf(F.atS1, AT.fail), qx = bigOf(F.atQx, AT.fail), qy = bigOf(F.atQy, AT.fail), m1 = bytesOf(F.atM1, AT.fail); if (r === null || s === null || qx === null || qy === null || m1 === null) return;
    var e = EC.bits2int(c, h.fn(m1)).e, d = EC.leakedK(c, e, r, s, k), Q = EC.publicOf(c, d), ok = Q[0] === qx && Q[1] === qy, t = new Trace();
    t.line('d = (s·k − e)·r⁻¹ mod n', 'd = (s·k − e)·r⁻¹ mod n', hex(d, c), 'ok').line('d·G = Q ?', 'd·G = Q ?', ok ? '✓' : '✕', ok ? 'ok' : 'bad'); t.into(AT.tr); F.atD3.set(d, c);
    AT.show(ok ? 'ok' : 'bad', (ok ? '✓ ' : '✕ ') + bi('Một k bị lộ (qua kênh bên, qua lỗi) cũng đủ: d theo ngay từ một chữ ký.', 'One leaked k (through a side channel, through a fault) is enough: d follows from a single signature.'));
  }
  function atInit() {
    var need = function () { return cur('at-curve').bytes; };
    F.atD = new Field('at-d', { name: ['khoá riêng d', 'private key d'], need: need }); F.atK = new Field('at-k', { name: ['k', 'k'], need: need });
    F.atM1 = new Field('at-m1', { name: ['thông điệp 1', 'message 1'], msg: true }); F.atM2 = new Field('at-m2', { name: ['thông điệp 2', 'message 2'], msg: true });
    ['atQx', 'atQy', 'atR1', 'atS1', 'atR2', 'atS2', 'atD2', 'atD3'].forEach(function (k) { F[k] = new Field('at-' + k.slice(2).toLowerCase(), { name: [k.slice(2), k.slice(2)] }); });
    $('at-sign').addEventListener('click', atSign); $('at-recover').addEventListener('click', atRecover); $('at-leak').addEventListener('click', atLeak);
    $('at-ex').addEventListener('click', function () {
      var A = V.attacks.nonce_reuse; setRadio('at-curve', A.curve); $('at-d-rnd').checked = false; $('at-k-rnd').checked = false; F.atD.set(A.d); F.atK.set(A.k); F.atM1.setBytes(unhexBytes(A.msg1)); F.atM2.setText(A.msg2_text);
      atSign(); atRecover();
      var ok = F.atD2.ta.value.replace(/^0+/, '') === A.d_recovered.replace(/^0+/, '') && F.atS1.ta.value === A.s1 && F.atS2.ta.value === A.s2;
      AT.show(ok ? 'ok' : 'bad', (ok ? '✓ ' : '✕ ') + bi('Ví dụ: d và k lấy từ CAVS SigGen.txt (P-256, SHA-256, bản ghi đầu), hai thông điệp khác nhau; d khôi phục ' + (ok ? 'trùng' : 'KHÁC') + ' giá trị tham chiếu.', 'Example: d and k from CAVS SigGen.txt (P-256, SHA-256, first record), two different messages; the recovered d ' + (ok ? 'equals' : 'DIFFERS from') + ' the reference value.'));
    });
    F.atM1.setText('chuyển 10 đồng cho A'); F.atM2.setText('chuyển 10 đồng cho B');
    AT.show('info', bi('Bấm "Ký hai thông điệp với cùng k", rồi "Khôi phục d".', 'Press "Sign two messages with the same k", then "Recover d".'));
  }

  /* ================================================================ bảng năm đường cong (tính tại chỗ) */
  function curveTable() {
    var tb = $('curve-rows'), h = '';
    EC.NAMES.forEach(function (nm) {
      var c = EC.CURVES[nm], cc = (1n << B(c.bits)) - c.p;
      h += '<tr><td>' + nm + '</td><td class="num">' + c.bits + '</td><td class="num">' + c.N + '</td><td class="num">' + Math.ceil(c.bits / 32) + '</td><td><code>2^' + c.bits + ' − ' + (EC.bitlen(cc) > 40 ? '0x' + hex(cc) : cc.toString()) + '</code></td><td class="num">' + EC.STRENGTH[nm] + '</td></tr>';
    });
    tb.innerHTML = h;
  }

  /* ================================================================ tự kiểm chứng: chạy lại mọi vector mẫu trong máy bạn */
  function tick() { return new Promise(function (r) { setTimeout(r, 0); }); }
  $('bt-selftest').addEventListener('click', async function () {
    var st = $('st-status'), det = $('st-detail'), btn = $('bt-selftest'), lines = [], pass = 0, total = 0, g = null, groups = [];
    st.className = 'pill wait'; st.innerHTML = bi('đang chạy…', 'running…'); det.hidden = false; det.textContent = ''; btn.disabled = true; await tick();
    function group(vi, en) { g = { vi: vi, en: en, pass: 0, total: 0 }; groups.push(g); }
    function chk(label, got, want) { total++; g.total++; var a = String(got).toLowerCase().replace(/^0+(?=.)/, ''), b = String(want).toLowerCase().replace(/^0+(?=.)/, ''); if (a === b) { pass++; g.pass++; } else lines.push('FAIL ' + label + '\n  got  ' + got + '\n  want ' + want); }
    function flush() { det.innerHTML = groups.map(function (x) { return bi(x.vi, x.en) + nb(': ' + x.pass + '/' + x.total); }).join('\n') + (lines.length ? '\n\n' + nb(esc(lines.join('\n'))) : ''); }
    var C = EC.CURVES, i, v, c;
    try {
      group('Hình: đường cong y² = x³ + 2x + 2 trên F₁₇ có 19 điểm, G = (5, 1) có bậc 19, 2G = (6, 3)', 'Figures: y² = x³ + 2x + 2 over F₁₇ has 19 points, G = (5, 1) has order 19, 2G = (6, 3)');
      c = EC.toy(17, 2, 2); chk('#E', EC.enumerate(c).length + 1, 19); chk('ord G', EC.orbit(c, [5n, 1n]).length, 19); chk('2G', PL.ptStr(pn(EC.dbl(c, [5n, 1n]))), '(6, 3)'); chk('13G ladder = double-and-add', PL.ptStr(pn(EC.mulLadder(c, 13n, [5n, 1n]))), PL.ptStr(pn(EC.mulDA(c, 13n, [5n, 1n]))));
      flush(); await tick();
      group('Sinh cặp khoá: CAVS KeyPair.rsp + ACVP ECDSA-KeyGen (Q = d·G)', 'Key pairs: CAVS KeyPair.rsp + ACVP ECDSA-KeyGen (Q = d·G)');
      for (i = 0; i < V.keygen.length; i++) { v = V.keygen[i]; c = C[v.curve]; var Q = EC.publicOf(c, B('0x' + v.d)); chk(v.curve + ' Q.x', hex(Q[0]), v.qx); chk(v.curve + ' Q.y', hex(Q[1]), v.qy); }
      flush(); await tick();
      group('Kiểm tra khoá công khai: CAVS PKV.rsp + ACVP ECDSA-KeyVer', 'Public-key validation: CAVS PKV.rsp + ACVP ECDSA-KeyVer');
      for (i = 0; i < V.pkv.length; i++) { v = V.pkv[i]; chk(v.curve + ' ' + v.comment, EC.validate(C[v.curve], [B('0x' + v.qx), B('0x' + v.qy)]).ok ? 'P' : 'F', v.valid ? 'P' : 'F'); }
      flush(); await tick();
      group('ECC CDH: CAVS KAS_ECC_CDH_PrimitiveTest.txt + ACVP KAS-ECC-CDH-Component', 'ECC CDH: CAVS KAS_ECC_CDH_PrimitiveTest.txt + ACVP KAS-ECC-CDH-Component');
      for (i = 0; i < V.cdh.length; i++) { v = V.cdh[i]; c = C[v.curve]; var z = EC.ecdh(c, B('0x' + v.d), [B('0x' + v.peer_x), B('0x' + v.peer_y)]); chk(v.curve + ' Z', z.err || hex(z.Z, c), v.z); }
      flush(); await tick();
      group('Ký ECDSA với k cho trước: CAVS SigGen.txt + ACVP ECDSA-SigGen', 'ECDSA signing with given k: CAVS SigGen.txt + ACVP ECDSA-SigGen');
      for (i = 0; i < V.siggen.length; i++) { v = V.siggen[i]; c = C[v.curve]; var hh = EC.hash(v.hash), sg = EC.sign(c, B('0x' + v.d), EC.bits2int(c, hh.fn(unhexBytes(v.msg))).e, B('0x' + v.k)); chk(v.curve + ' ' + v.hash + ' r', hex(sg.r, c), v.r); chk(v.curve + ' ' + v.hash + ' s', hex(sg.s, c), v.s); }
      flush(); await tick();
      group('k tất định RFC 6979: ACVP DetECDSA-SigGen + RFC 6979 A.2.5', 'Deterministic k, RFC 6979: ACVP DetECDSA-SigGen + RFC 6979 A.2.5');
      for (i = 0; i < V.det.length; i++) { v = V.det[i]; c = C[v.curve]; var hd = EC.hash(v.hash), h1 = hd.fn(unhexBytes(v.msg)), kk = EC.rfc6979(c, B('0x' + v.d), h1, hd), sd = EC.sign(c, B('0x' + v.d), EC.bits2int(c, h1).e, kk.k); chk(v.curve + ' ' + v.hash + ' k', hex(kk.k, c), v.k); chk(v.curve + ' ' + v.hash + ' s', hex(sd.s, c), v.s); }
      flush(); await tick();
      group('Xác minh ECDSA: CAVS SigVer.rsp (có ca F) + ACVP ECDSA-SigVer', 'ECDSA verification: CAVS SigVer.rsp (with F cases) + ACVP ECDSA-SigVer');
      for (i = 0; i < V.sigver.length; i++) { v = V.sigver[i]; c = C[v.curve]; var hv = EC.hash(v.hash); chk(v.curve + ' ' + v.hash + ' ' + v.comment, EC.verify(c, [B('0x' + v.qx), B('0x' + v.qy)], EC.bits2int(c, hv.fn(unhexBytes(v.msg))).e, B('0x' + v.r), B('0x' + v.s)).ok ? 'P' : 'F', v.valid ? 'P' : 'F'); }
      flush(); await tick();
      group('Vô hướng biên d = 1, d = n − 1 trên năm đường cong; lặp nonce khôi phục d', 'Edge scalars d = 1, d = n − 1 on the five curves; nonce reuse recovers d');
      for (i = 0; i < V.edges.length; i++) { v = V.edges[i]; c = C[v.curve]; var Qe = EC.mul(c, B('0x' + v.k), c.G); chk(v.curve + ' ' + v.label, hex(Qe[0], c) + hex(Qe[1], c), v.qx + v.qy); }
      var A = V.attacks.nonce_reuse; c = C[A.curve]; var ha = EC.hash(A.hash), e1 = EC.bits2int(c, ha.fn(unhexBytes(A.msg1))).e, e2 = EC.bits2int(c, ha.fn(unhexBytes(A.msg2))).e, rr = EC.nonceReuse(c, e1, B('0x' + A.s1), e2, B('0x' + A.s2), B('0x' + A.r));
      chk('nonce reuse d', hex(rr.d, c), A.d_recovered); chk('leaked k d', hex(EC.leakedK(c, e1, B('0x' + A.r), B('0x' + A.s1), B('0x' + A.k)), c), A.d);
    } catch (e) { if (g) chk('exception', String(e && e.message), 'none'); }
    flush(); btn.disabled = false;
    st.className = 'pill ' + (pass === total ? 'ok' : 'bad');
    st.innerHTML = nb(pass + '/' + total) + ' ' + (pass === total ? bi('phép kiểm khớp', 'checks match') : bi('phép kiểm — CÓ LỖI', 'checks — FAILED'));
  });

  /* ================================================================ khởi động */
  tabs(); g1Init(); g2Init(); $('g3-k').addEventListener('input', g3Run); g3Run(); kgInit(); pvInit(); dhInit(); sgInit(); svInit(); atInit(); curveTable();
  window.ECLab = { F: F, G1: G1, G2: G2, g1Pick: g1Pick, g2Pick: g2Pick, g1Draw: g1Draw, g2Setup: g2Setup, g3Run: g3Run, kgRun: kgRun, pvRun: pvRun, dhRun: dhRun, sgRun: sgRun, svRun: svRun, atSign: atSign, atRecover: atRecover };
})();
