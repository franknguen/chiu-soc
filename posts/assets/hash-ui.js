/* Giao diện phòng thí nghiệm SHA-2 / SHA-3: năm thẻ (băm & vết, NIST ShortMsg / LongMsg, Monte Carlo, SHAKE độ dài ra,
   tuyết lở & biên khối), hộp thử tấn công mở rộng độ dài, hộp sinh IV của SHA-512/t và nút tự kiểm chứng.
   Mọi digest tính bằng hash-trace.js (HashTrace) và tính lần hai bằng file dùng chung pqc-sha2.js / pqc-mlkem.js
   (SHA-1: crypto.subtle của trình duyệt). Monte Carlo chạy trong Web Worker nếu được, không thì từng checkpoint sau
   một nhịp. Mọi chuỗi hiển thị có hai bản qua bi(vi, en).
   Original implementation for the ChiU·SoC hash article. */
(function () {
  'use strict';
  var H = window.HashTrace, V = window.HASH_VECTORS, S2 = window.PQCSHA2, PH = window.PQCHash;
  var MAXMSG = 1 << 20;

  /* ================================================================ tiện ích */
  function $(id) { var e = document.getElementById(id); if (!e) throw new Error('missing #' + id); return e; }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function bi(vi, en) { return '<span lang="vi">' + vi + '</span><span lang="en">' + en + '</span>'; }
  function nb(s) { return '<span data-i18n="neutral">' + s + '</span>'; }
  function nv(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ' '); }
  function ne(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
  function checked(name) { var r = document.querySelector('input[name="' + name + '"]:checked'); return r ? r.value : null; }
  function radios(name) { return Array.prototype.slice.call(document.querySelectorAll('input[name="' + name + '"]')); }
  function onRadio(name, fn) { radios(name).forEach(function (r) { r.addEventListener('change', fn); }); }
  function setRadio(name, v) { radios(name).forEach(function (r) { r.checked = r.value === v; }); }
  var hex = H.toHex, unhex = H.fromHex;
  function enc(s) { return new TextEncoder().encode(s); }
  function utf8(b) { return new TextDecoder('utf-8', { fatal: true }).decode(b); }
  function pat(n, seed) { var o = new Uint8Array(n); for (var i = 0; i < n; i++) o[i] = (7 * i + 3 + (seed || 0)) & 255; return o; }
  function rnd(n) { var o = new Uint8Array(n), i; for (i = 0; i < n; i += 65536) crypto.getRandomValues(o.subarray(i, Math.min(n, i + 65536))); return o; }
  function cat() { var t = 0, i, o, p = 0; for (i = 0; i < arguments.length; i++) t += arguments[i].length; o = new Uint8Array(t); for (i = 0; i < arguments.length; i++) { o.set(arguments[i], p); p += arguments[i].length; } return o; }
  function show(el, cls, main, sub) { el.className = 'result ' + cls; el.innerHTML = main + (sub ? '<span class="sub">' + sub + '</span>' : ''); }
  function short(h, n) { n = n || 16; return h.length > 2 * n ? h.slice(0, n) + '…' + h.slice(-8) : h; }
  function intIn(id, lo, hi, dflt) {
    var v = parseInt($(id).value, 10);
    if (isNaN(v)) v = dflt;
    v = Math.max(lo, Math.min(hi, v));
    $(id).value = v;
    return v;
  }
  function firstDiff(a, b) { for (var i = 0; i < Math.max(a.length, b.length); i += 2) if (a.substr(i, 2) !== b.substr(i, 2)) return i / 2; return -1; }
  var pending = 0, idleWaiters = [];
  function busy() { pending++; }
  function done() { pending--; if (pending <= 0) { pending = 0; var a = idleWaiters; idleWaiters = []; a.forEach(function (f) { f(); }); } }
  function idle() { return pending ? new Promise(function (r) { idleWaiters.push(r); }) : Promise.resolve(); }

  /* ================================================================ ô dữ liệu: văn bản / hex, đếm byte, chép, xoá */
  function tool(box, html, fn) { var b = document.createElement('button'); b.type = 'button'; b.innerHTML = html; b.addEventListener('click', fn); box.appendChild(b); return b; }
  function Field(id, o) {
    var f = this;
    o = o || {};
    f.id = id; f.ta = $(id); f.cnt = $(id + '-cnt'); f.tools = $(id + '-tools'); f.fmt = o.fmt || 'hex'; f.max = o.max || null; f.btn = {};
    f.onEdit = o.onEdit || null;
    var fmts = o.fmts || ['hex'];
    if (fmts.length > 1) fmts.forEach(function (k) {
      f.btn[k] = tool(f.tools, k === 'text' ? bi('Văn bản', 'Text') : 'Hex', function () { f.setFmt(k); });
    });
    var g = document.createElement('span'); g.className = 'gap'; f.tools.appendChild(g);
    tool(f.tools, bi('Chép', 'Copy'), function () { f.copy(); });
    tool(f.tools, bi('Mở rộng', 'Expand'), function () { f.ta.parentNode.classList.toggle('big'); });
    if (!f.ta.readOnly) tool(f.tools, bi('Xoá', 'Clear'), function () { f.ta.value = ''; f.count(); if (f.onEdit) f.onEdit(); });
    f.flashEl = document.createElement('span'); f.flashEl.className = 'flash'; f.tools.appendChild(f.flashEl);
    f.ta.addEventListener('input', function () { f.count(); if (f.onEdit) f.onEdit(); });
    f.mark(); f.count();
  }
  Field.prototype.bytes = function () {
    var s = this.ta.value;
    if (this.fmt === 'text') return enc(s);
    s = s.replace(/\s+/g, '').replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]*$/.test(s)) { var e = new Error('hex'); e.code = 'HEX_CHAR'; throw e; }
    if (s.length % 2) { var e2 = new Error('hex'); e2.code = 'HEX_ODD'; throw e2; }
    return unhex(s);
  };
  Field.prototype.peek = function () { try { return this.bytes(); } catch (e) { return null; } };
  Field.prototype.set = function (b) {
    if (!b) { this.ta.value = ''; this.count(); return; }
    if (this.fmt === 'text') { try { this.ta.value = utf8(b); } catch (e) { this.fmt = 'hex'; this.mark(); this.ta.value = hex(b); } }
    else this.ta.value = hex(b);
    this.count();
  };
  Field.prototype.setHex = function (h) { this.fmt = 'hex'; this.mark(); this.ta.value = h; this.count(); };
  Field.prototype.setFmt = function (k) {
    if (k === this.fmt) return;
    var b;
    try { b = this.bytes(); } catch (e) { return this.flash(this.errText(e), true); }
    if (k === 'text') { try { this.ta.value = utf8(b); } catch (e) { return this.flash(bi('Các byte này không phải văn bản UTF-8; giữ dạng hex.', 'These bytes are not UTF-8 text; keeping hex.'), true); } }
    else this.ta.value = hex(b);
    this.fmt = k; this.mark(); this.count();
  };
  Field.prototype.mark = function () { for (var k in this.btn) this.btn[k].setAttribute('aria-pressed', String(k === this.fmt)); };
  Field.prototype.count = function () {
    var el = this.cnt, b;
    if (!this.ta.value) { el.className = 'cnt'; el.innerHTML = this.max ? nb('0 B') : ''; return; }
    try { b = this.bytes(); } catch (e) { el.className = 'cnt bad'; el.innerHTML = bi('không hợp lệ', 'invalid'); return; }
    if (this.max && b.length > this.max) { el.className = 'cnt bad'; el.innerHTML = nb(nv(b.length) + ' B') + ' ' + bi('— quá 1 MB', '— over 1 MB'); return; }
    el.className = 'cnt'; el.innerHTML = nb(nv(b.length) + ' B');
  };
  Field.prototype.errText = function (e) {
    return e && e.code === 'HEX_ODD' ? bi('Số chữ số hex lẻ.', 'Odd number of hex digits.') : bi('Có ký tự không phải hex.', 'A character that is not hex.');
  };
  Field.prototype.flash = function (html, bad) {
    var el = this.flashEl;
    el.style.color = bad ? '#9b1d28' : '';
    el.innerHTML = html; clearTimeout(this.ft);
    this.ft = setTimeout(function () { el.innerHTML = ''; }, bad ? 5000 : 1800);
  };
  Field.prototype.copy = function () {
    var f = this, s = f.ta.value;
    if (!s) return;
    function ok() { f.flash(bi('đã chép', 'copied')); }
    function fb() { f.ta.select(); try { document.execCommand('copy'); ok(); } catch (e) { /* trình duyệt chặn */ } }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(s).then(ok, fb); else fb();
  };

  /* ================================================================ phép tính thứ hai: các file dùng chung của trang */
  function sharedCshake(fn, m, L, N, S) {
    var r = fn === 'cSHAKE128' ? 168 : 136;
    if (!N.length && !S.length) return r === 168 ? PH.shake128xof(m).squeeze(L) : PH.shake256(m, L);
    /* SP 800-185 viết lại lần hai, trên hoán vị Keccak của pqc-mlkem.js: bytepad(encode_string(N) || encode_string(S), r) || X || 00 || pad10*1 */
    function le(x) { var b = []; while (x > 0) { b.unshift(x & 255); x = Math.floor(x / 256); } if (!b.length) b = [0]; return [b.length].concat(b); }
    var z = le(r).concat(le(8 * N.length), Array.prototype.slice.call(N), le(8 * S.length), Array.prototype.slice.call(S));
    while (z.length % r) z.push(0);
    var tot = z.length + m.length, padded = new Uint8Array(Math.ceil((tot + 1) / r) * r);
    padded.set(z, 0); padded.set(m, z.length);
    padded[tot] ^= 0x04; padded[padded.length - 1] ^= 0x80;
    var s = new Int32Array(50), i, j, out = new Uint8Array(L), pos = 0;
    for (i = 0; i < padded.length; i += r) {
      for (j = 0; j < r; j += 4) s[j >> 2] ^= padded[i + j] | (padded[i + j + 1] << 8) | (padded[i + j + 2] << 16) | (padded[i + j + 3] << 24);
      PH.keccakP(s);
    }
    for (;;) {
      for (j = 0; j < r && pos < L; j++) out[pos++] = (s[j >> 2] >>> (8 * (j & 3))) & 255;
      if (pos >= L) return out;
      PH.keccakP(s);
    }
  }
  var SHARED = {
    'SHA-224': function (m) { return S2.sha224(m); }, 'SHA-256': function (m) { return S2.sha256(m); },
    'SHA-384': function (m) { return S2.sha384(m); }, 'SHA-512': function (m) { return S2.sha512(m); },
    'SHA-512/224': function (m) { return S2.sha512_224(m); }, 'SHA-512/256': function (m) { return S2.sha512_256(m); },
    'SHA3-224': function (m) { return PH.sha3_224(m); }, 'SHA3-256': function (m) { return PH.sha3_256(m); },
    'SHA3-384': function (m) { return PH.sha3_384(m); }, 'SHA3-512': function (m) { return PH.sha3_512(m); },
    'SHAKE128': function (m, L) { return PH.shake128xof(m).squeeze(L); }, 'SHAKE256': function (m, L) { return PH.shake256(m, L); },
    'cSHAKE128': function (m, L, N, S) { return sharedCshake('cSHAKE128', m, L, N, S); },
    'cSHAKE256': function (m, L, N, S) { return sharedCshake('cSHAKE256', m, L, N, S); }
  };
  /* -> Promise(hex | null): null = không có phép tính thứ hai (trình duyệt thiếu crypto.subtle cho SHA-1) */
  function second(fn, m, L, N, S) {
    if (fn === 'SHA-1') {
      if (!window.crypto || !crypto.subtle) return Promise.resolve(null);
      return crypto.subtle.digest('SHA-1', m.slice().buffer).then(function (d) { return hex(new Uint8Array(d)); }, function () { return null; });
    }
    try { return Promise.resolve(hex(SHARED[fn](m, L, N || new Uint8Array(0), S || new Uint8Array(0)))); }
    catch (e) { return Promise.resolve(null); }
  }
  function whoName(fn) {
    if (fn === 'SHA-1') return ['hàm SHA-1 có sẵn của trình duyệt', "the browser's built-in SHA-1"];
    if (fn.indexOf('SHA-') === 0) return ['pqc-sha2.js của trang', "the site's pqc-sha2.js"];
    if (fn.indexOf('cSHAKE') === 0) return ['hoán vị Keccak của pqc-mlkem.js', "pqc-mlkem.js's Keccak permutation"];
    return ['pqc-mlkem.js của trang', "the site's pqc-mlkem.js"];
  }

  /* ================================================================ mô tả hàm */
  function fnLine(fn) {
    var i = H.info(fn);
    if (i.kind === 'md') return bi(fn + ': cỗ máy ' + i.w + ' bit, khối ' + i.block + ' byte, ' + i.rounds + ' bước, ô độ dài ' + i.lenBytes + ' byte, digest ' + i.out + ' byte.' + (fn === 'SHA-1' ? ' Đã bị phá va chạm — chỉ để đọc dữ liệu cũ và để so sánh.' : ''),
      fn + ': ' + i.w + '-bit engine, ' + i.block + '-byte blocks, ' + i.rounds + ' steps, ' + i.lenBytes + '-byte length field, ' + i.out + '-byte digest.' + (fn === 'SHA-1' ? ' Collision-broken — for old data and comparison only.' : ''));
    var sfx = '0x' + ('0' + i.suffix.toString(16)).slice(-2);
    return bi(fn + ': r = ' + i.rate + ' byte, c = ' + i.cap + ' bit (an ninh tối đa ' + (i.cap / 2) + ' bit), byte hậu tố ' + sfx + (i.out ? ', digest ' + i.out + ' byte.' : ', độ dài ra tuỳ chọn.'),
      fn + ': r = ' + i.rate + ' bytes, c = ' + i.cap + ' bits (at most ' + (i.cap / 2) + '-bit security), suffix byte ' + sfx + (i.out ? ', ' + i.out + '-byte digest.' : ', output length of your choice.'));
  }

  /* ================================================================ thẻ 1: băm & vết */
  var F1 = {
    msg: new Field('h1-msg', { fmt: 'text', fmts: ['text', 'hex'], max: MAXMSG }),
    n: new Field('h1-n', { fmt: 'text', fmts: ['text', 'hex'] }),
    s: new Field('h1-s', { fmt: 'text', fmts: ['text', 'hex'] }),
    out: new Field('h1-out', { fmt: 'hex' })
  };
  var T1 = { fn: null, msg: null, opt: null, res: null, block: 0, perm: 0, round: 0, token: 0 };
  function h1Fn() { return checked('h1-fn'); }
  function h1Sync() {
    var fn = h1Fn(), i = H.info(fn), xof = i.kind === 'shake' || i.kind === 'cshake';
    $('h1-name').innerHTML = fnLine(fn);
    $('h1-xo').hidden = !xof;
    $('h1-cs').hidden = i.kind !== 'cshake';
    if (xof && !$('h1-outlen').dataset.touched) $('h1-outlen').value = fn.slice(-3) === '128' ? 32 : 64;
  }
  $('h1-outlen').addEventListener('input', function () { this.dataset.touched = '1'; });
  onRadio('h1-fn', function () { h1Sync(); h1Go(); });
  var LEG = {
    md: [['m', 'thông điệp', 'message'], ['x', 'byte đánh dấu 0x80', 'marker byte 0x80'], ['mx', 'bit thông điệp + bit 1', 'message bits + the 1 bit'],
      ['z', 'byte 0', 'zero bytes'], ['l', 'độ dài (bit, big-endian)', 'length (bits, big-endian)']],
    sp: [['c', 'tiền tố cSHAKE', 'cSHAKE prefix'], ['m', 'thông điệp', 'message'], ['s', 'hậu tố + bit 1 đầu của pad10*1', 'suffix + first pad10*1 bit'],
      ['z', 'byte 0', 'zero bytes'], ['e', 'bit 1 cuối (0x80)', 'final 1 bit (0x80)'], ['se', 'cả hai trong một byte (0x86 / 0x9F / 0x84)', 'both in one byte (0x86 / 0x9F / 0x84)']]
  };
  function renderPad(res, kind) {
    var leg = LEG[kind === 'md' ? 'md' : 'sp'];
    $('h1-legend').innerHTML = leg.map(function (l) { return '<span><span class="pb pb-' + l[0] + '">··</span> ' + bi(l[1], l[2]) + '</span>'; }).join('');
    var html = '', blk = res.block, first = res.tailStart / blk;
    for (var i = 0; i < res.tail.length; i++) {
      if (i % blk === 0) {
        if (i) html += '</div>';
        var k = first + i / blk;
        html += '<div class="blk">' + (kind === 'md' ? bi('Khối ' + k, 'Block ' + k) : bi('Khối hút số ' + k, 'Absorbed block ' + k)) + '</div><div class="row">';
      } else if (i % 16 === 0) html += '</div><div class="row">';
      if (i % 16 === 0) html += '<span class="off">' + (res.tailStart + i) + '</span>';
      var b = res.tail[i];
      html += '<span class="pb pb-' + res.cls[i] + '">' + (b < 16 ? '0' : '') + b.toString(16) + '</span>';
    }
    $('h1-pad').innerHTML = html + '</div>';
  }
  function blocksLine(fn, n, res, L) {
    var i = H.info(fn);
    if (i.kind === 'md') {
      var need = n + 1 + i.lenBytes;
      return bi(nv(n) + ' byte thông điệp + 1 byte 0x80 + ' + i.lenBytes + ' byte độ dài = ít nhất ' + nv(need) + ' byte → ' + nv(res.blocks) + ' khối ' + i.block + ' byte. Bản đồ dưới đây là ' + (res.tail.length / i.block) + ' khối cuối.',
        ne(n) + ' message bytes + 1 byte 0x80 + ' + i.lenBytes + ' length bytes = at least ' + ne(need) + ' bytes → ' + ne(res.blocks) + ' blocks of ' + i.block + ' bytes. The map below shows the last ' + (res.tail.length / i.block) + '.');
    }
    var pre = res.prefixLen ? bi(' + ' + res.prefixLen + ' byte tiền tố cSHAKE', ' + ' + res.prefixLen + ' cSHAKE prefix bytes') : '';
    return bi(nv(n) + ' byte thông điệp', ne(n) + ' message bytes') + pre +
      bi(' + phần đệm (ít nhất 1 byte) → ' + res.absorbs + ' lần hút (r = ' + i.rate + ' byte); ' + nv(L) + ' byte ra → thêm ' + res.squeezes + ' hoán vị khi vắt.',
        ' + padding (at least 1 byte) → ' + res.absorbs + ' absorbing permutations (r = ' + i.rate + ' bytes); ' + ne(L) + ' output bytes → ' + res.squeezes + ' more permutations while squeezing.');
  }
  var STEPS = ['in', 'theta', 'rho', 'pi', 'chi', 'iota'];
  var STEPTXT = {
    in: ['trạng thái vào vòng', 'the state entering the round'], theta: ['θ: mỗi bit cộng chẵn lẻ của hai cột bên cạnh', 'θ: every bit gets the parity of two neighbouring columns'],
    rho: ['ρ: mỗi lane xoay một lượng cố định', 'ρ: each lane rotated by a fixed amount'], pi: ['π: các lane đổi chỗ', 'π: the lanes move'],
    chi: ['χ: bước phi tuyến, a ⊕ (¬b ∧ c) theo hàng', 'χ: the nonlinear step, a ⊕ (¬b ∧ c) along each row'], iota: ['ι: hằng số vòng vào lane (0, 0)', 'ι: the round constant into lane (0, 0)']
  };
  function renderMdTrace(fn, res) {
    var i = H.info(fn), names = fn === 'SHA-1' ? ['a', 'b', 'c', 'd', 'e'] : ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];
    var tr = res.trace, html = '<table class="trace"><thead><tr><th>t</th><th>W<sub>t</sub></th>' + names.map(function (n) { return '<th>' + n + '</th>'; }).join('') + '</tr></thead><tbody>';
    html += '<tr class="hl"><td>' + bi('vào', 'in') + '</td><td></td>' + tr.hin.map(function (h) { return '<td>' + h + '</td>'; }).join('') + '</tr>';
    tr.rows.forEach(function (r) { html += '<tr><td>' + r[0] + '</td>' + r.slice(1).map(function (h) { return '<td>' + h + '</td>'; }).join('') + '</tr>'; });
    $('h1-tbl').innerHTML = html + '</tbody></table>';
    $('h1-binfo').innerHTML = bi('Khối ' + tr.block + ' trên tổng ' + res.blocks + ' (đánh số từ 0): ' + i.rounds + ' bước. Dòng "vào" là trạng thái khi vào khối; sau bước cuối, nó được cộng vào để ra trạng thái của khối sau.',
      'Block ' + tr.block + ' of ' + res.blocks + ' (numbered from 0): ' + i.rounds + ' steps. The "in" row is the state entering the block; after the last step it is added back to give the next block\'s state.');
  }
  function renderKeccak(res) {
    var perms = res.perms, tr = res.trace;
    $('h1-perms').innerHTML = perms.map(function (p, k) {
      return '<button type="button" data-p="' + k + '" aria-pressed="' + (k === T1.perm) + '">' + (p.kind === 'absorb' ? bi('hút ' + k, 'absorb ' + k) : bi('vắt ' + k, 'squeeze ' + k)) + '</button>';
    }).join('');
    var step = checked('h1-step') || 'chi', si = STEPS.indexOf(step), cur = tr[step], prev = si > 0 ? tr[STEPS[si - 1]] : tr.in, changed = 0;
    var html = '<div class="hd"></div>';
    for (var x = 0; x < 5; x++) html += '<div class="hd">x = ' + x + '</div>';
    for (var y = 0; y < 5; y++) {
      html += '<div class="hd">y = ' + y + '</div>';
      for (x = 0; x < 5; x++) {
        var k = x + 5 * y, ch = si > 0 && cur[k] !== prev[k];
        if (ch) changed++;
        html += '<div' + (ch ? ' class="chg"' : '') + '>' + cur[k] + '</div>';
      }
    }
    $('h1-lanes').innerHTML = html;
    var p = perms[T1.perm], st = STEPTXT[step];
    $('h1-kinfo').innerHTML = bi('Hoán vị ' + T1.perm + ' (' + (p.kind === 'absorb' ? 'hút' : 'vắt') + '), vòng ' + T1.round + ' / 23, sau ' + st[0] + '. ',
      'Permutation ' + T1.perm + ' (' + (p.kind === 'absorb' ? 'absorb' : 'squeeze') + '), round ' + T1.round + ' / 23, after ' + st[1] + '. ') +
      (si > 0 ? bi(changed + ' / 25 lane đổi so với bước trước (tô màu).', changed + ' / 25 lanes changed since the previous step (shaded).') : '');
  }
  function h1Run() {                         // tính lại với vị trí vết hiện tại
    var fn = T1.fn, o = {}, k;
    for (k in T1.opt) o[k] = T1.opt[k];
    if (H.info(fn).kind === 'md') o.traceBlock = T1.block;
    else { o.tracePerm = T1.perm; o.traceRound = T1.round; o.listPerms = true; }
    T1.res = H.run(fn, T1.msg, o);
    return T1.res;
  }
  function h1Trace() {
    var fn = T1.fn, md = H.info(fn).kind === 'md';
    $('h1-tr-md').hidden = !md; $('h1-tr-kc').hidden = md;
    var res = h1Run();
    if (md) { $('h1-blk').max = res.blocks - 1; $('h1-blk').value = T1.block; renderMdTrace(fn, res); }
    else { $('h1-round').value = T1.round; renderKeccak(res); }
  }
  function h1Go() {
    var el = $('h1-result'), fn = h1Fn(), i = H.info(fn), m, o = {};
    $('h1-nres').hidden = true;
    if ($('h1-rnd').checked) { var n = intIn('h1-rlen', 0, MAXMSG, 56); F1.msg.fmt = 'hex'; F1.msg.mark(); F1.msg.set(rnd(n)); }
    try { m = F1.msg.bytes(); } catch (e) { show(el, 'bad', bi('Ô thông điệp: ', 'Message field: ') + F1.msg.errText(e)); return; }
    if (m.length > MAXMSG) { show(el, 'bad', bi('Thông điệp dài ' + nv(m.length) + ' byte, quá giới hạn 1 MB của trang.', 'The message is ' + ne(m.length) + ' bytes, over the page\'s 1 MB limit.')); return; }
    if (i.kind === 'shake' || i.kind === 'cshake') o.outLen = intIn('h1-outlen', 1, 65536, 32);
    if (i.kind === 'cshake') {
      try { o.N = F1.n.bytes(); o.S = F1.s.bytes(); } catch (e) { show(el, 'bad', bi('Ô N / S: ', 'N / S field: ') + F1.n.errText(e)); return; }
    }
    T1.fn = fn; T1.msg = m; T1.opt = o; T1.perm = 0; T1.round = 0;
    T1.block = i.kind === 'md' ? Math.ceil((m.length + 1 + i.lenBytes) / i.block) - 1 : 0;   // vết mặc định: khối cuối
    var L = o.outLen || i.out, t0 = performance.now();
    h1Trace();
    var res = T1.res, ms = performance.now() - t0, dg = hex(res.digest);
    F1.out.setHex(dg);
    renderPad(res, i.kind);
    $('h1-blocks').innerHTML = blocksLine(fn, m.length, res, L);
    var main = bi('Digest ' + fn + ' · ' + nv(L) + ' byte', fn + ' digest · ' + ne(L) + ' bytes') + nb(' · ' + ms.toFixed(1) + ' ms');
    show(el, 'info', main, bi('đang tính lần hai…', 'computing a second time…'));
    var tok = ++T1.token, who = whoName(fn);
    busy();
    second(fn, m, L, o.N, o.S).then(function (h2) {
      if (tok !== T1.token) return;
      if (h2 === null) show(el, 'info', main, bi('Trình duyệt này không cho phép tính lần hai (' + who[0] + ').', 'This browser offers no second computation (' + who[1] + ').'));
      else if (h2 === dg) show(el, 'ok', '<span class="ic">✓</span>' + main + ' · ' + bi('hai cách tính khớp', 'both computations agree'),
        bi('Mã có ghi vết của bài này và ' + who[0] + ' cho cùng digest, từng byte.', "This article's traced code and " + who[1] + ' give the same digest, byte for byte.'));
      else show(el, 'bad', '<span class="ic">✕</span>' + main + ' · ' + bi('hai cách tính KHÁC nhau', 'the two computations DIFFER'),
        bi('Lần hai (' + who[0] + '): ', 'Second (' + who[1] + '): ') + nb(esc(short(h2, 24))));
    }).then(done, done);
  }
  $('h1-go').addEventListener('click', h1Go);
  function h1Block(d) { if (!T1.res || !T1.res.trace) return; var n = T1.res.blocks; T1.block = Math.max(0, Math.min(n - 1, d)); h1Trace(); }
  $('h1-bprev').addEventListener('click', function () { h1Block(T1.block - 1); });
  $('h1-bnext').addEventListener('click', function () { h1Block(T1.block + 1); });
  $('h1-blk').addEventListener('change', function () { h1Block(parseInt(this.value, 10) || 0); });
  function h1Round(r) { if (!T1.res) return; T1.round = Math.max(0, Math.min(23, r)); h1Trace(); }
  $('h1-rprev').addEventListener('click', function () { h1Round(T1.round - 1); });
  $('h1-rnext').addEventListener('click', function () { h1Round(T1.round + 1); });
  $('h1-round').addEventListener('change', function () { h1Round(parseInt(this.value, 10) || 0); });
  onRadio('h1-step', function () { if (T1.res && T1.res.trace && !T1.res.blocks) renderKeccak(T1.res); });
  $('h1-perms').addEventListener('click', function (ev) {
    var b = ev.target.closest ? ev.target.closest('button[data-p]') : null;
    if (!b) return;
    T1.perm = parseInt(b.getAttribute('data-p'), 10); h1Trace();
  });

  /* ================================================================ thẻ 2: NIST ShortMsg / LongMsg */
  var F2 = { msg: new Field('h2-msg'), exp: new Field('h2-exp'), got: new Field('h2-got') };
  var T2 = { cur: null };
  function caseOpts(c) {
    var m = c.bits ? unhex(c.msg) : new Uint8Array(0), o = { bits: c.bits };
    if (c.conv === 'acvp') m = H.acvpToFips(m, c.bits);
    if (c.outBits) o.outBits = c.outBits;
    if (c.N !== undefined) o.N = enc(c.N);
    if (c.Shex !== undefined) o.S = unhex(c.Shex); else if (c.S !== undefined) o.S = enc(c.S);
    return { m: m, o: o };
  }
  function nistCase(c) {
    var x = caseOpts(c), d = H.digest(c.fn, x.m, x.o);
    if (c.conv === 'acvp' && c.outBits) d = H.fipsToAcvp(d, c.outBits);
    return hex(d);
  }
  function nistLabel(c) {          // tên của NIST: CAVP · file · Len / COUNT, ACVP · thuật toán · tcId
    if (c.src === 'CAVS') return 'CAVP' + (c.orient === 'bit' ? ' (bit)' : '') + ' · ' + c.file + ' · ' + (c.file.indexOf('VariableOut') >= 0 ? c.id.replace(/^\S+ /, '') : 'Len = ' + c.bits);
    return c.id;
  }
  function h2Rows() {
    var fn = checked('h2-fn'), html = '';
    V.nist.forEach(function (c, k) {
      if (c.fn !== fn) return;
      html += '<tr><td data-i18n="neutral">' + esc(nistLabel(c)) + '</td><td class="num">' + nv(c.bits) +
        (c.orient === 'bit' ? ' <span class="tag">bit</span>' : '') + '</td><td class="num">' + (c.outBits ? c.outBits : '—') + '</td>' +
        '<td><button class="btn ghost sm" type="button" data-k="' + k + '">' + bi('Kiểm', 'Check') + '</button></td><td class="v" id="h2-v-' + k + '"></td></tr>';
    });
    $('h2-rows').innerHTML = html;
  }
  function verdictCell(k, ok) { var td = document.getElementById('h2-v-' + k); if (td) { td.className = 'v ' + (ok ? 'ok' : 'bad'); td.textContent = ok ? '✓' : '✕'; } }
  function h2Check(k) {
    var c = V.nist[k], el = $('h2-result'), got;
    try { got = nistCase(c); } catch (e) { got = 'error: ' + e.message; }
    var ok = got === c.md;
    T2.cur = k;
    F2.msg.setHex(c.bits ? c.msg : ''); F2.exp.setHex(c.md); F2.got.setHex(got);
    verdictCell(k, ok);
    var conv = c.conv === 'acvp' && c.bits % 8 ? bi(' Byte lẻ cuối của ACVP căn trái được dời về bit thấp trước khi băm (FIPS 202, phụ lục B.1).', ' ACVP\'s left-aligned last byte is moved to the low bits before hashing (FIPS 202, appendix B.1).') :
      (c.conv === 'fips' && c.bits % 8 ? bi(' File CAVP của SHA-3 đã ghi bit lẻ ở bit thấp.', ' The CAVP SHA-3 file already puts the odd bits in the low bits.') :
        (c.conv === 'md' && c.bits % 8 ? bi(' SHA-1 / SHA-2 đọc bit từ bit cao.', ' SHA-1 / SHA-2 read bits from the high end.') : ''));
    var extra = (c.N !== undefined || c.S !== undefined || c.Shex !== undefined) ? nb(' · N = "' + esc(c.N || '') + '", S = ' + (c.Shex !== undefined ? '0x' + esc(short(c.Shex, 12)) : '"' + esc(short(c.S || '', 24)) + '"')) : '';
    $('h2-info').innerHTML = nb(esc(nistLabel(c))) + ' · ' + bi(c.orient === 'bit' ? 'lẻ bit' : 'theo byte', c.orient === 'bit' ? 'bit-oriented' : 'byte-oriented') +
      nb(' · Len = ' + c.bits + (c.outBits ? ', outLen = ' + c.outBits : '')) + extra + '.' + conv;
    if (ok) show(el, 'ok', '<span class="ic">✓</span>' + bi('Khớp đáp án NIST', "Matches NIST's expected value") + nb(' · ' + esc(c.id)));
    else {
      var at = firstDiff(got, c.md);
      show(el, 'bad', '<span class="ic">✕</span>' + bi('KHÁC đáp án NIST', "DIFFERS from NIST's expected value") + nb(' · ' + esc(c.id)),
        bi('Khác từ byte số ' + at + '.', 'First difference at byte ' + at + '.'));
    }
    $('h2-open').disabled = !(c.bits % 8 === 0 && c.bits / 8 <= MAXMSG);
    return ok;
  }
  $('h2-rows').addEventListener('click', function (ev) {
    var b = ev.target.closest ? ev.target.closest('button[data-k]') : null;
    if (b) h2Check(parseInt(b.getAttribute('data-k'), 10));
  });
  onRadio('h2-fn', h2Rows);
  $('h2-all').addEventListener('click', function () {
    var by = {}, bad = [], n = 0, t0 = performance.now();
    V.nist.forEach(function (c, k) {
      var got; try { got = nistCase(c); } catch (e) { got = 'error'; }
      var ok = got === c.md;
      by[c.fn] = by[c.fn] || [0, 0]; by[c.fn][1]++; if (ok) by[c.fn][0]++; else bad.push(c.id);
      verdictCell(k, ok); n++;
    });
    var html = '<div class="tbl-wrap"><table class="cases"><thead><tr><th>' + bi('Hàm', 'Function') + '</th><th>' + bi('Khớp', 'Match') + '</th><th></th></tr></thead><tbody>';
    H.ORDER.forEach(function (fn) { var x = by[fn]; if (!x) return; html += '<tr><td data-i18n="neutral">' + fn + '</td><td class="num">' + x[0] + ' / ' + x[1] + '</td><td class="v ' + (x[0] === x[1] ? 'ok">✓' : 'bad">✕') + '</td></tr>'; });
    $('h2-sum').innerHTML = html + '</tbody></table></div>';
    var el = $('h2-result'), ms = nb(' · ' + (performance.now() - t0).toFixed(0) + ' ms');
    if (!bad.length) show(el, 'ok', '<span class="ic">✓</span>' + bi('Cả ' + n + ' trường hợp đi kèm đều khớp đáp án NIST', 'All ' + n + ' shipped cases match NIST\'s expected values') + ms);
    else show(el, 'bad', '<span class="ic">✕</span>' + bi(bad.length + ' / ' + n + ' trường hợp KHÁC đáp án NIST', bad.length + ' / ' + n + ' cases DIFFER from NIST') + ms, nb(esc(bad.slice(0, 6).join(' · '))));
  });
  function loadCase(c) {                 // một trường hợp NIST theo byte vào thẻ 1
    setRadio('h1-fn', c.fn); h1Sync();
    F1.msg.setHex(c.msg);
    if (c.outBits) { $('h1-outlen').value = c.outBits / 8; $('h1-outlen').dataset.touched = '1'; }
    if (c.N !== undefined || c.S !== undefined || c.Shex !== undefined) {
      F1.n.fmt = 'text'; F1.n.mark(); F1.n.ta.value = c.N || ''; F1.n.count();
      if (c.Shex !== undefined) F1.s.setHex(c.Shex); else { F1.s.fmt = 'text'; F1.s.mark(); F1.s.ta.value = c.S || ''; F1.s.count(); }
    }
    $('h1-rnd').checked = false;
    h1Go();
  }
  $('h2-open').addEventListener('click', function () {
    var c = V.nist[T2.cur];
    if (!c || c.bits % 8) return;
    selectTab('hash'); loadCase(c);
  });
  /* thẻ 1, "Nạp ví dụ NIST": lần lượt các trường hợp theo byte mà trang mang theo cho hàm đang chọn (chọn sẵn ở biên khối) */
  var T1N = {};
  $('h1-nist').addEventListener('click', function () {
    var fn = h1Fn(), list = [], el = $('h1-nres');
    V.nist.forEach(function (c, k) { if (c.fn === fn && !(c.bits % 8) && !(c.outBits && c.outBits % 8) && c.bits / 8 <= MAXMSG) list.push(k); });
    if (!list.length) { el.hidden = false; show(el, 'info', bi('Không có ví dụ theo byte cho hàm này.', 'No byte-oriented example for this function.')); return; }
    T1N[fn] = ((T1N[fn] === undefined ? -1 : T1N[fn]) + 1) % list.length;
    var c = V.nist[list[T1N[fn]]];
    loadCase(c);
    var got = F1.out.ta.value, ok = got === c.md, nb8 = c.bits / 8, pos = bi('Ví dụ ' + (T1N[fn] + 1) + ' / ' + list.length + ' · ', 'Example ' + (T1N[fn] + 1) + ' / ' + list.length + ' · ');
    el.hidden = false;
    if (ok) show(el, 'ok', '<span class="ic">✓</span>' + pos + bi('digest khớp đáp án NIST', "the digest matches NIST's expected value") + nb(' · ' + esc(nistLabel(c))),
      bi(nv(nb8) + ' byte thông điệp — xem bản đồ đệm và vết bên dưới.', ne(nb8) + ' message bytes — see the padding map and the trace below.'));
    else show(el, 'bad', '<span class="ic">✕</span>' + pos + bi('digest KHÁC đáp án NIST', "the digest DIFFERS from NIST's expected value") + nb(' · ' + esc(nistLabel(c))),
      bi('Khác từ byte số ' + firstDiff(got, c.md) + '.', 'First difference at byte ' + firstDiff(got, c.md) + '.'));
  });

  /* ================================================================ thẻ 3: Monte Carlo */
  var F3 = { seed: new Field('h3-seed') };
  var CODE = {
    'md-standard': 'Seed = <NIST>\nfor j = 0 .. 99:\n    MD0 = MD1 = MD2 = Seed\n    for i = 3 .. 1002:\n        Mi  = MD(i-3) || MD(i-2) || MD(i-1)\n        MDi = SHA(Mi)\n    checkpoint[j] = MD1002\n    Seed = MD1002',
    'md-alternate': 'Seed = <NIST>   (L = len(Seed) = @L bits)\nfor j = 0 .. 99:\n    A = B = C = Seed\n    for i = 0 .. 999:\n        MSG = (A || B || C) cut or zero-padded to L bits\n        MD  = SHA(MSG)\n        A = B;  B = C;  C = MD\n    checkpoint[j] = MD\n    Seed = MD',
    'sha3': 'MD0 = Seed = <NIST>\nfor j = 0 .. 99:\n    for i = 1 .. 1000:\n        MDi = SHA3(MD(i-1))\n    checkpoint[j] = MD1000\n    MD0 = MD1000',
    'shake': 'min = @MIN bits, max = @MAX bits          (file header)\nOutputlen = floor(max / 8) * 8 = @OL bits\nRange = floor(max / 8) - ceil(min / 8) + 1 = @RG\nOutput0 = Msg = <NIST, 128 bits>\nfor j = 0 .. 99:\n    for i = 1 .. 1000:\n        M = leftmost 128 bits of Output(i-1), zero-padded\n        Output(i) = SHAKE(M, Outputlen)\n        R = rightmost 16 bits of Output(i), as an integer\n        Outputlen = 8 * (ceil(min / 8) + (R mod Range))\n    checkpoint[j] = Output1000   (with its own length)\n    Output0 = Output1000'
  };
  var WHY = {
    'md-standard': ['SHAVS (CAVP), "Monte Carlo": mỗi thông điệp là ba digest trước nối lại — 1 000 lần băm cho một checkpoint, 100 checkpoint, tổng cộng 100 000 lần băm nối tiếp.',
      'SHAVS (CAVP), "Monte Carlo": each message is the previous three digests concatenated — 1,000 hashes per checkpoint, 100 checkpoints, 100,000 chained hashes in all.'],
    'md-alternate': ['ACVP, biến thể "alternate": như trên nhưng thông điệp bị cắt hay đệm 0 về đúng độ dài seed — dành cho lõi không nhận được thông điệp dài gấp ba digest.',
      'ACVP, the "alternate" variant: as above but the message is cut or zero-padded to the seed length — for cores that cannot take a message three digests long.'],
    'sha3': ['SHA3VS (CAVP) và ACVP SHA3: chuỗi đơn giản hơn — mỗi digest là thông điệp của lần băm sau.',
      'SHA3VS (CAVP) and ACVP SHA3: a simpler chain — each digest is the next hash\'s message.'],
    'shake': ['SHA3VS (CAVP), SHAKE: độ dài ra của lần sau do 16 bit cuối của đầu ra lần này quyết định, trong khoảng ghi ở đầu file — nên lõi phải vắt được mọi độ dài trong khoảng đó.',
      'SHA3VS (CAVP), SHAKE: the next output length is set by the last 16 bits of this output, within the range in the file header — so the core must squeeze every length in that range.']
  };
  var T3 = { token: 0, worker: null, timer: null, running: false };
  function mctSel() { return V.mct[parseInt(checked('h3-mct'), 10)]; }
  function mctSync() {
    var m = mctSel(), code = CODE[m.variant];
    if (m.variant === 'shake') {
      var minB = Math.ceil(m.minOutBits / 8), rg = Math.floor(m.maxOutBits / 8) - minB + 1;
      code = code.replace('@MIN', m.minOutBits).replace('@MAX', m.maxOutBits).replace('@OL', Math.floor(m.maxOutBits / 8) * 8).replace('@RG', rg);
    }
    $('h3-code').textContent = code.replace('@L', m.seedBits).replace(/SHA\(/g, m.fn + '(').replace(/SHA3\(/g, m.fn + '(').replace(/SHAKE\(M/, m.fn + '(M');
    $('h3-why').innerHTML = bi(WHY[m.variant][0], WHY[m.variant][1]) + ' ' + nb(esc(m.id)) + '. ' +
      bi('Trang mang theo đủ giá trị của NIST cho checkpoint 0–9 và 99, và 8 byte đầu của các checkpoint còn lại (cho trang nhẹ); lỗi ở bất kỳ đâu cũng lan sang mọi checkpoint sau.',
        'The page carries NIST\'s full value for checkpoints 0–9 and 99, and the first 8 bytes of the others (to keep the page light); an error anywhere spreads to every later checkpoint.');
    F3.seed.setHex(m.seed);
    $('h3-tbl').innerHTML = ''; $('h3-prog').style.width = '0';
    show($('h3-result'), 'info', bi('Chọn số checkpoint rồi bấm chạy.', 'Choose the number of checkpoints, then run.'));
  }
  onRadio('h3-mct', function () { mctStop(); mctSync(); });
  function mctBusy(on) {
    T3.running = on;
    $('h3-run').disabled = on; $('h3-all').disabled = on; $('h3-stop').disabled = !on;
    radios('h3-mct').forEach(function (r) { r.disabled = on; });
  }
  function mctStop() {
    T3.token++;
    if (T3.worker) { try { T3.worker.terminate(); } catch (e) { /* đã dừng */ } T3.worker = null; }
    if (T3.timer) { clearInterval(T3.timer); T3.timer = null; }
    if (T3.running) { mctBusy(false); done(); }
  }
  function mctRun(count) {
    mctStop();
    var m = mctSel(), tok = T3.token, el = $('h3-result'), t0 = Date.now(), ok = 0, bad = null, rows = [], shake = m.variant === 'shake';
    var job = { fn: m.fn, variant: m.variant, seed: m.seed, seedBits: m.seedBits, minOutBits: m.minOutBits, maxOutBits: m.maxOutBits };
    mctBusy(true); busy();
    var head = '<table class="trace"><thead><tr><th>j</th>' + (shake ? '<th>' + bi('độ dài ra', 'out bits') + '</th>' : '') + '<th>NIST</th><th>' + bi('trang tính', 'page') + '</th><th></th></tr></thead><tbody>';
    function tick() { show(el, 'info', bi('đang chạy… ', 'running… ') + nb(rows.length + ' / ' + count + ' · ' + Math.round((Date.now() - t0) / 1000) + ' s')); }
    tick(); T3.timer = setInterval(tick, 1000);
    function onCp(i, mdHex, outBits) {
      if (tok !== T3.token) return;
      var want = m.expected[i], good = want.length === mdHex.length ? want === mdHex : mdHex.indexOf(want) === 0;
      if (shake && outBits !== m.outBits[i]) good = false;
      if (good) ok++; else if (!bad) bad = { i: i, want: want, got: mdHex, ob: outBits, wob: shake ? m.outBits[i] : null };
      rows.push('<tr' + (good ? '' : ' class="hl"') + '><td>' + i + '</td>' + (shake ? '<td>' + outBits + '</td>' : '') + '<td>' + short(want, 12) + (want.length < mdHex.length ? '…' : '') + '</td><td>' + short(mdHex, 12) + '</td><td class="v ' + (good ? 'ok">✓' : 'bad">✕') + '</td></tr>');
      $('h3-tbl').innerHTML = head + rows.join('') + '</tbody></table>';
      $('h3-prog').style.width = (100 * (i + 1) / count) + '%';
      tick();
    }
    function onDone(err) {
      if (tok !== T3.token) return;
      clearInterval(T3.timer); T3.timer = null;
      var sec = nb(' · ' + ((Date.now() - t0) / 1000).toFixed(1) + ' s');
      if (err) show(el, 'bad', '<span class="ic">✕</span>' + bi('Lỗi khi chạy: ', 'Error while running: ') + nb(esc(err)));
      else if (!bad && ok === count) show(el, 'ok', '<span class="ic">✓</span>' + bi(ok + ' / ' + count + ' checkpoint khớp đáp án NIST', ok + ' / ' + count + ' checkpoints match NIST\'s values') + sec,
        bi(nv(1000 * count) + ' lần băm nối tiếp.', ne(1000 * count) + ' chained hashes.'));
      else show(el, 'bad', '<span class="ic">✕</span>' + bi('Checkpoint ' + bad.i + ' KHÁC đáp án NIST', 'Checkpoint ' + bad.i + ' DIFFERS from NIST') + sec,
        nb(esc(short(bad.got, 16)) + ' ≠ ' + esc(short(bad.want, 16)) + (bad.wob !== null ? ' · ' + bad.ob + ' / ' + bad.wob + ' bits' : '')));
      mctBusy(false); done();
    }
    if (window.Worker && location.protocol !== 'file:') {
      try {
        var w = new Worker('assets/hash-worker.js');
        T3.worker = w;
        w.onmessage = function (e) {
          var d = e.data;
          if (d.kind === 'cp') onCp(d.i, d.md, d.outBits);
          else if (d.kind === 'done') { onDone(null); w.terminate(); if (T3.worker === w) T3.worker = null; }
          else onDone(d.err);
        };
        w.onerror = function () { T3.worker = null; fallback(); };
        w.postMessage({ id: tok, op: 'mct', job: job, count: count });
        return;
      } catch (e) { T3.worker = null; }
    }
    fallback();
    function fallback() {                    // không có Worker (file:// hay trình duyệt cũ): từng checkpoint sau một nhịp
      var st = null, i = 0, jb = { fn: job.fn, variant: job.variant, seed: unhex(job.seed), seedBits: job.seedBits, minOutBits: job.minOutBits, maxOutBits: job.maxOutBits };
      (function step() {
        setTimeout(function () {
          if (tok !== T3.token) return;
          try { var r = H.mctStep(jb, st); st = r.st; onCp(i, hex(r.md), r.outBits); } catch (e) { onDone(String(e.message || e)); return; }
          i++;
          if (i < count) step(); else onDone(null);
        }, i ? 0 : 20);
      })();
    }
  }
  $('h3-run').addEventListener('click', function () { mctRun(intIn('h3-k', 1, 100, 5)); });
  $('h3-all').addEventListener('click', function () { $('h3-k').value = 100; mctRun(100); });
  $('h3-stop').addEventListener('click', function () {
    mctStop(); show($('h3-result'), 'info', bi('Đã dừng.', 'Stopped.'));
  });

  /* ================================================================ thẻ 4: SHAKE, độ dài ra và tính chất tiền tố */
  var F4 = { msg: new Field('h4-msg', { fmt: 'text', fmts: ['text', 'hex'], max: MAXMSG }), o1: new Field('h4-o1'), o2: new Field('h4-o2') };
  function h4Go() {
    var el = $('h4-result'), fn = checked('h4-fn'), m;
    try { m = F4.msg.bytes(); } catch (e) { show(el, 'bad', bi('Ô thông điệp: ', 'Message field: ') + F4.msg.errText(e)); return null; }
    if (m.length > MAXMSG) { show(el, 'bad', bi('Thông điệp quá 1 MB.', 'The message is over 1 MB.')); return null; }
    var L1 = intIn('h4-l1', 1, 65536, 32), L2 = intIn('h4-l2', 1, 65536, 200);
    var a = H.digest(fn, m, { outLen: L1 }), b = H.digest(fn, m, { outLen: L2 }), sa = hex(SHARED[fn](m, L1)), sb = hex(SHARED[fn](m, L2));
    F4.o1.setHex(hex(a)); F4.o2.setHex(hex(b));
    var lo = Math.min(L1, L2), pre = hex(a).slice(0, 2 * lo) === hex(b).slice(0, 2 * lo), agree = sa === hex(a) && sb === hex(b);
    var s3 = hex(H.digest('SHA3-256', m)), s5 = hex(H.digest('SHA3-512', m)).slice(0, 64);
    var cs = hex(H.digest(fn === 'SHAKE128' ? 'cSHAKE128' : 'cSHAKE256', m, { outLen: lo, S: enc('x') }));
    var r = H.info(fn).rate;
    show(el, pre && agree ? 'ok' : 'bad', '<span class="ic">' + (pre && agree ? '✓' : '✕') + '</span>' +
      (pre ? bi(lo + ' byte đầu của hai đầu ra trùng nhau: đầu ra ngắn là tiền tố của đầu ra dài.', 'The first ' + lo + ' bytes of both outputs coincide: the short output is a prefix of the long one.')
        : bi('Hai đầu ra KHÔNG có chung tiền tố — sai.', 'The two outputs do NOT share a prefix — wrong.')) +
      ' ' + (agree ? bi('Hai cách tính khớp.', 'Both computations agree.') : bi('Hai cách tính KHÁC nhau.', 'The two computations DIFFER.')),
      bi('Vắt ' + Math.max(L1, L2) + ' byte với r = ' + r + ' byte cần thêm ' + Math.max(0, Math.ceil(Math.max(L1, L2) / r) - 1) + ' hoán vị. Đối chiếu: SHA3-256(M) và 32 byte đầu của SHA3-512(M) ',
        'Squeezing ' + Math.max(L1, L2) + ' bytes with r = ' + r + ' bytes needs ' + Math.max(0, Math.ceil(Math.max(L1, L2) / r) - 1) + ' more permutations. Contrast: SHA3-256(M) and the first 32 bytes of SHA3-512(M) ') +
      (s3 === s5 ? bi('trùng (sai!)', 'coincide (wrong!)') : bi('khác hẳn nhau', 'are unrelated')) +
      bi('; cSHAKE với S = "x" cũng khác SHAKE: ', '; cSHAKE with S = "x" also differs from SHAKE: ') + nb(short(cs, 8) + ' ≠ ' + short(hex(a).slice(0, 2 * lo), 8)) + '.');
    return hex(a);
  }
  $('h4-go').addEventListener('click', h4Go);
  function h4Examples() {
    var fn = checked('h4-fn'), html = '';
    V.nist.forEach(function (c, k) {
      if (c.fn === fn && c.file.indexOf('VariableOut') >= 0) html += '<button type="button" data-k="' + k + '">' + esc(c.id.replace(/^SHAKE\d+VariableOut /, '')) + nb(' · ' + c.outBits + ' bit') + '</button>';
    });
    $('h4-ex').innerHTML = html;
    $('h4-nres').className = 'result info'; $('h4-nres').innerHTML = '';
  }
  onRadio('h4-fn', h4Examples);
  $('h4-ex').addEventListener('click', function (ev) {
    var b = ev.target.closest ? ev.target.closest('button[data-k]') : null;
    if (!b) return;
    var c = V.nist[parseInt(b.getAttribute('data-k'), 10)];
    F4.msg.setHex(c.msg); $('h4-l1').value = c.outBits / 8;
    if (parseInt($('h4-l2').value, 10) < c.outBits / 8) $('h4-l2').value = c.outBits / 8 + 32;
    var got = h4Go(), el = $('h4-nres');
    if (got === c.md) show(el, 'ok', '<span class="ic">✓</span>' + bi('Khớp đáp án NIST', "Matches NIST's expected value") + nb(' · ' + esc(c.id) + ', Outputlen = ' + c.outBits));
    else show(el, 'bad', '<span class="ic">✕</span>' + bi('KHÁC đáp án NIST', "DIFFERS from NIST's expected value") + nb(' · ' + esc(c.id)), nb(esc(short(got || '', 16)) + ' ≠ ' + esc(short(c.md, 16))));
  });

  /* ================================================================ thẻ 5: tuyết lở, biên khối, ngày sinh */
  var F5 = { msg: new Field('h5-msg', { fmt: 'text', fmts: ['text', 'hex'], max: 4096 }) };
  function h5Fn() { return checked('h5-fn'); }
  function dig5(fn, m) { var i = H.info(fn); return H.digest(fn, m, { outLen: i.out || (fn === 'SHAKE128' ? 32 : 64) }); }
  function popdiff(a, b) { var n = 0; for (var i = 0; i < a.length; i++) { var x = a[i] ^ b[i]; while (x) { n += x & 1; x >>>= 1; } } return n; }
  function flipBit(m, bit) { var o = Uint8Array.from(m); o[bit >> 3] ^= 0x80 >>> (bit & 7); return o; }
  function h5Flip() {
    var el = $('h5-result'), fn = h5Fn(), m;
    try { m = F5.msg.bytes(); } catch (e) { show(el, 'bad', bi('Ô thông điệp: ', 'Message field: ') + F5.msg.errText(e)); return; }
    if (!m.length) { show(el, 'bad', bi('Cần một thông điệp ít nhất 1 byte.', 'A message of at least 1 byte is needed.')); return; }
    if (m.length > 4096) { show(el, 'bad', bi('Ô này giới hạn 4 096 byte.', 'This field is limited to 4,096 bytes.')); return; }
    var nbits = 8 * m.length, bit;
    if ($('h5-bit-rnd').checked) { bit = (crypto.getRandomValues(new Uint32Array(1))[0]) % nbits; $('h5-bit').value = bit; }
    else bit = intIn('h5-bit', 0, nbits - 1, 0);
    var d0 = dig5(fn, m), d1 = dig5(fn, flipBit(m, bit)), k = popdiff(d0, d1), n = 8 * d0.length, s = '';
    for (var i = 0; i < d0.length; i++) for (var j = 7; j >= 0; j--) s += ((d0[i] ^ d1[i]) >> j) & 1 ? '<span class="d">1</span>' : '<span class="s">·</span>';
    $('h5-bits').innerHTML = s;
    show(el, 'info', bi('Lật bit ' + bit + ' (byte ' + (bit >> 3) + '): ' + k + ' / ' + n + ' bit digest đổi — kỳ vọng khoảng ' + (n / 2) + '.',
      'Flipping bit ' + bit + ' (byte ' + (bit >> 3) + '): ' + k + ' / ' + n + ' digest bits change — about ' + (n / 2) + ' expected.'),
      nb(fn + ' · ' + short(hex(d0), 12) + ' → ' + short(hex(d1), 12)));
    return k;
  }
  $('h5-flip').addEventListener('click', h5Flip);
  $('h5-300').addEventListener('click', function () {
    var el = $('h5-result'), fn = h5Fn(), m;
    try { m = F5.msg.bytes(); } catch (e) { show(el, 'bad', F5.msg.errText(e)); return; }
    if (!m.length || m.length > 4096) { show(el, 'bad', bi('Cần 1 tới 4 096 byte.', '1 to 4,096 bytes are needed.')); return; }
    var d0 = dig5(fn, m), n = 8 * d0.length, r = crypto.getRandomValues(new Uint32Array(300)), sum = 0, lo = n, hi = 0;
    for (var i = 0; i < 300; i++) { var k = popdiff(d0, dig5(fn, flipBit(m, r[i] % (8 * m.length)))); sum += k; lo = Math.min(lo, k); hi = Math.max(hi, k); }
    var avg = sum / 300;
    show(el, 'info', bi('300 lần lật một bit ngẫu nhiên: trung bình ' + avg.toFixed(2).replace('.', ',') + ' / ' + n + ' bit đổi (thấp nhất ' + lo + ', cao nhất ' + hi + '); kỳ vọng ' + (n / 2) + '.',
      '300 random single-bit flips: on average ' + avg.toFixed(2) + ' / ' + n + ' bits change (lowest ' + lo + ', highest ' + hi + '); ' + (n / 2) + ' expected.'),
      bi('Một bài kiểm không cần đáp án mẫu — nhưng một hàm sai vẫn có thể cho con số đẹp.', 'A test that needs no reference answer — but a wrong function can still score well.'));
  });
  function lenCount(fn, n) {
    var i = H.info(fn), r = H.run(fn, pat(n), { outLen: i.out || 32 });
    return i.kind === 'md' ? r.blocks : r.absorbs;
  }
  function h5Len() {
    var fn = h5Fn(), i = H.info(fn), blk = i.block, n = intIn('h5-len', 0, 3 * blk + 1, 0), c = lenCount(fn, n), cprev = n ? lenCount(fn, n - 1) : c, tot = c * blk;
    var padB = i.kind === 'md' ? tot - n - i.lenBytes : tot - n;
    var bar = '<span class="m" style="width:' + (100 * n / tot) + '%"></span><span class="p" style="width:' + (100 / tot) + '%"></span>' +
      '<span class="z" style="width:' + (100 * Math.max(0, padB - 1) / tot) + '%"></span>' + (i.kind === 'md' ? '<span class="l" style="width:' + (100 * i.lenBytes / tot) + '%"></span>' : '');
    $('h5-bar').innerHTML = bar;
    var unit = i.kind === 'md' ? ['khối', 'blocks'] : ['lần hút', 'absorbing permutations'];
    var jump = c !== cprev ? ' <span class="jump">' + bi('← nhảy bậc ở đây', '← the count jumps here') + '</span>' : '';
    var marks = i.kind === 'md' ? [blk - i.lenBytes - 1, blk - i.lenBytes, 2 * blk - i.lenBytes - 1, 2 * blk - i.lenBytes] : [blk - 1, blk, 2 * blk, 2 * blk + 1];
    $('h5-binfo').innerHTML = bi(fn + ': ' + n + ' byte → ' + c + ' ' + unit[0] + ' (' + tot + ' byte sau đệm).', fn + ': ' + n + ' bytes → ' + c + ' ' + unit[1] + ' (' + tot + ' bytes after padding).') + jump +
      ' ' + bi('Các độ dài đáng thử: ', 'Lengths worth testing: ') + nb(marks.join(', '));
  }
  $('h5-len').addEventListener('input', h5Len);
  onRadio('h5-fn', function () { var i = H.info(h5Fn()); $('h5-len').max = 3 * i.block + 1; $('h5-len').value = i.kind === 'md' ? i.block - i.lenBytes - 1 : i.block - 1; h5Len(); });
  $('h5-bday').addEventListener('click', function () {
    var bits = parseInt(checked('h5-bd'), 10), nbyt = bits / 8, seen = {}, i = 0, el = $('h5-bres'), t0 = performance.now();
    for (;;) {
      var d = H.digest('SHA-256', enc('msg-' + i)), key = hex(d.subarray(0, nbyt));
      if (seen[key] !== undefined) break;
      seen[key] = i; i++;
      if (i > 1 << 20) { show(el, 'bad', bi('Không tìm thấy trong 2^20 thông điệp.', 'Nothing found in 2^20 messages.')); return; }
    }
    var a = seen[key], kk = Math.round(1.1774 * Math.sqrt(Math.pow(2, bits)));
    show(el, 'ok', '<span class="ic">✓</span>' + bi('Va chạm: ', 'Collision: ') + nb('msg-' + a + ' · msg-' + i) +
      bi(' cùng ' + bits + ' bit đầu (' + key + ') sau ' + nv(i + 1) + ' thông điệp; công thức 50 %: ≈ 1,1774 · √2^' + bits + ' = ' + nv(kk) + '.',
        ' share their first ' + bits + ' bits (' + key + ') after ' + ne(i + 1) + ' messages; the 50 % formula: ≈ 1.1774 · √2^' + bits + ' = ' + ne(kk) + '.'),
      nb(short(hex(H.digest('SHA-256', enc('msg-' + a))), 16) + ' · ' + short(hex(H.digest('SHA-256', enc('msg-' + i))), 16) + ' · ' + (performance.now() - t0).toFixed(0) + ' ms'));
  });

  /* ================================================================ hộp giả mạo (mục 2) và hộp sinh IV (mục 3) */
  var FX = { secret: new Field('lx-secret', { fmt: 'text', fmts: ['text', 'hex'], max: 4096 }), msg: new Field('lx-msg', { fmt: 'text', fmts: ['text', 'hex'], max: 4096 }),
    ext: new Field('lx-ext', { fmt: 'text', fmts: ['text', 'hex'], max: 4096 }) };
  $('lx-go').addEventListener('click', function () {
    var el = $('lx-result'), fn = checked('lx-fn'), sec, msg, ext;
    try { sec = FX.secret.bytes(); msg = FX.msg.bytes(); ext = FX.ext.bytes(); } catch (e) { show(el, 'bad', FX.msg.errText(e)); return; }
    if (sec.length + msg.length + ext.length > 12288) { show(el, 'bad', bi('Tổng ba ô giới hạn 12 288 byte.', 'The three fields are limited to 12,288 bytes in total.')); return; }
    var known = H.digest(fn, cat(sec, msg)), x = H.lengthExtend(fn, known, sec.length + msg.length, ext);
    var sub = nb(fn + '(secret ‖ m) = ' + short(hex(known), 16));
    if (!x.ok) {
      var why = x.hidden === null ? bi('Bọt biển: c bit dung lượng không bao giờ ra ngoài, digest không phải trạng thái — không có gì để "băm tiếp".', 'Sponge: the c capacity bits never leave, the digest is not the state — there is nothing to "keep hashing" from.')
        : bi('Digest chỉ là một phần trạng thái: thiếu ' + x.hidden + ' bit. ' + (x.hidden <= 32 ? 'Chỉ 32 bit — đoán thử 2^32 lần là đủ, nên đây là bảo vệ yếu.' : 'Đoán chúng tốn 2^' + x.hidden + ' lần: không làm được.'),
          'The digest is only part of the state: ' + x.hidden + ' bits are missing. ' + (x.hidden <= 32 ? 'Only 32 — 2^32 guesses suffice, so this is weak protection.' : 'Guessing them costs 2^' + x.hidden + ' tries: not feasible.'));
      show(el, x.hidden !== null && x.hidden <= 32 ? 'info' : 'ok', '<span class="ic">✓</span>' + bi(fn + ' chống được cách làm trực tiếp này.', fn + ' resists this direct attack.') + ' ' + why, sub);
      return;
    }
    var full = cat(sec, msg, x.glue, ext), real = hex(H.digest(fn, full)), shared = fn === 'SHA-1' ? null : hex(SHARED[fn](full));
    var ok = real === hex(x.forged) && (shared === null || shared === real);
    show(el, ok ? 'bad' : 'info', '<span class="ic">' + (ok ? '⚠' : '?') + '</span>' +
      (ok ? bi('Giả mạo thành công: không biết bí mật mà vẫn tính đúng digest của (bí mật ‖ m ‖ đệm ‖ phần thêm).', 'Forgery succeeded: without the secret, the digest of (secret ‖ m ‖ padding ‖ extra) came out right.')
        : bi('Giả mạo không khớp — lỗi trong trang.', 'The forgery does not match — a bug in the page.')),
      sub + '<br>' + bi('Phần đệm chen vào (kẻ tấn công phải gửi kèm): ', 'Glue padding (the attacker must send it along): ') + nb(esc(short(hex(x.glue), 24))) + '<br>' +
      bi('Digest giả: ', 'Forged digest: ') + nb(short(hex(x.forged), 16)) + ' · ' + bi('băm thật cả chuỗi: ', 'real hash of the whole string: ') + nb(short(real, 16)) +
      (shared !== null ? ' · ' + bi('file dùng chung: ', 'shared file: ') + nb(short(shared, 16)) : ''));
  });
  $('iv-go').addEventListener('click', function () {
    var t = parseInt(checked('iv-t'), 10), r = H.sha512tIV(t), want = t === 256 ? '22312194fc2bf72c' : '8c3d37c819544da2', ok = r.iv[0] === want;
    var o = $('iv-out');
    o.hidden = false;
    o.innerHTML = nb('H0 (SHA-512) ⊕ a5a5a5a5a5a5a5a5 =\n  ' + r.start.join('\n  ') + '\n\nSHA-512 core on "' + esc(r.text) + '" (' + r.text.length + ' bytes, one padded block)\n\nIV (SHA-512/' + t + ') =\n  ' + r.iv.join('\n  '));
    show($('iv-result'), ok ? 'ok' : 'bad', '<span class="ic">' + (ok ? '✓' : '✕') + '</span>' +
      bi('Từ đầu tiên ' + r.iv[0] + (ok ? ' trùng' : ' KHÁC') + ' giá trị in trong FIPS 180-4, mục 5.3.6.', 'The first word ' + r.iv[0] + (ok ? ' matches' : ' DIFFERS from') + ' the value printed in FIPS 180-4, section 5.3.6.'));
  });

  /* ================================================================ thẻ */
  var TABS = ['hash', 'nist', 'mct', 'xof', 'aval'];
  function selectTab(k) { TABS.forEach(function (t) { $('tab-' + t).setAttribute('aria-selected', String(t === k)); $('panel-' + t).hidden = t !== k; }); }
  TABS.forEach(function (t) { $('tab-' + t).addEventListener('click', function () { selectTab(t); }); });

  /* ================================================================ tự kiểm chứng */
  function tickP() { return new Promise(function (r) { setTimeout(r, 0); }); }
  $('bt-selftest').addEventListener('click', async function () {
    var st = $('st-status'), det = $('st-detail'), btn = $('bt-selftest'), lines = [], pass = 0, total = 0, g = null, groups = [];
    st.className = 'pill wait'; st.innerHTML = bi('đang chạy…', 'running…');
    det.hidden = false; det.textContent = ''; btn.disabled = true; busy();
    await tickP();
    function group(vi, en) { g = { vi: vi, en: en, pass: 0, total: 0 }; groups.push(g); }
    function chk(label, got, want) {
      total++; g.total++;
      if (got === want) { pass++; g.pass++; } else lines.push('FAIL ' + label + '\n  got  ' + got + '\n  want ' + want);
    }
    function flush() {
      det.innerHTML = groups.map(function (x) { return bi(x.vi, x.en) + nb(': ' + x.pass + '/' + x.total); }).join('\n') +
        (lines.length ? '\n\n' + nb(esc(lines.join('\n'))) : '');
    }
    try {
      group('Ví dụ chuẩn ("abc", chuỗi rỗng) và bốn mẫu cSHAKE của SP 800-185', 'Standard examples ("abc", the empty string) and the four SP 800-185 cSHAKE samples');
      V.kat.forEach(function (k) { chk(k.fn + '("' + k.text + '")', hex(H.digest(k.fn, enc(k.text), { outLen: k.out })), k.md); });
      V.samples.forEach(function (s) { chk(s.label, hex(H.digest(s.fn, unhex(s.msg), { outLen: s.out, N: enc(s.N), S: enc(s.S) })), s.md); });
      flush(); await tickP();
      group('Độ dài sát biên khối: mã có ghi vết = đáp án', 'Lengths next to block boundaries: traced code = expected');
      V.boundary.forEach(function (b) {
        chk(b.fn + ' len ' + b.len + (b.out ? ' out ' + b.out : '') + (b.S ? ' S "' + b.S + '"' : ''), hex(H.digest(b.fn, pat(b.len), { outLen: b.out || undefined, N: b.N ? enc(b.N) : undefined, S: b.S ? enc(b.S) : undefined })), b.md);
      });
      flush(); await tickP();
      group('Cùng các độ dài: phép tính thứ hai độc lập (file dùng chung, SHA-1 của trình duyệt)', 'Same lengths: an independent second computation (shared files, the browser\'s SHA-1)');
      for (var i = 0; i < V.boundary.length; i++) {
        var b = V.boundary[i], h2 = await second(b.fn, pat(b.len), b.out || H.info(b.fn).out, b.N ? enc(b.N) : null, b.S ? enc(b.S) : null);
        if (h2 !== null) chk('second ' + b.fn + ' len ' + b.len + (b.out ? ' out ' + b.out : ''), h2, b.md);
      }
      flush(); await tickP();
      group('Tập vector NIST đi kèm trang (CAVP + ACVP, cả lẻ bit)', 'The NIST vectors shipped with the page (CAVP + ACVP, bit-oriented too)');
      V.nist.forEach(function (c) { var got; try { got = nistCase(c); } catch (e) { got = 'error ' + e.message; } chk(c.id, got, c.md); });
      flush(); await tickP();
      group('Monte Carlo: checkpoint 0 của mỗi file (1 000 lần băm mỗi file)', 'Monte Carlo: checkpoint 0 of every file (1,000 hashes each)');
      for (i = 0; i < V.mct.length; i++) {
        var m = V.mct[i], r = H.mctStep({ fn: m.fn, variant: m.variant, seed: unhex(m.seed), seedBits: m.seedBits, minOutBits: m.minOutBits, maxOutBits: m.maxOutBits }, null);
        chk(m.id + ' checkpoint 0', hex(r.md), m.expected[0]);
        if (i % 4 === 3) { flush(); await tickP(); }
      }
      group('IV của SHA-512/t (FIPS 180-4, mục 5.3.6) và tấn công mở rộng độ dài', 'SHA-512/t IVs (FIPS 180-4, section 5.3.6) and length extension');
      chk('SHA-512/256 IV[0]', H.sha512tIV(256).iv[0], '22312194fc2bf72c');
      chk('SHA-512/224 IV[0]', H.sha512tIV(224).iv[0], '8c3d37c819544da2');
      var sec = enc('k3y'), msg = enc('amount=100'), ext = enc('&amount=1000000'), kn = H.digest('SHA-256', cat(sec, msg)), x = H.lengthExtend('SHA-256', kn, sec.length + msg.length, ext);
      chk('SHA-256 forged = shared SHA-256 of the extended string', hex(x.forged), hex(S2.sha256(cat(sec, msg, x.glue, ext))));
      chk('SHA-512/256 refuses (256 hidden bits)', String(H.lengthExtend('SHA-512/256', H.digest('SHA-512/256', msg), msg.length, ext).hidden), '256');
    } catch (e) { if (g) chk('exception', String(e && e.message), 'none'); }
    flush(); btn.disabled = false;
    st.className = 'pill ' + (pass === total ? 'ok' : 'bad');
    st.innerHTML = nb(pass + '/' + total) + ' ' + (pass === total ? bi('phép kiểm khớp', 'checks match') : bi('phép kiểm — CÓ LỖI', 'checks — FAILED'));
    done();
  });

  /* ================================================================ khởi động */
  h1Sync(); h1Go(); h2Rows(); mctSync(); h4Examples(); h5Len();
  window.HashLab = {                                    // cửa cho bộ kiểm thử tự động; trang không tự dùng
    idle: idle, worker: function () { return !!T3.worker; }, nistCase: nistCase, sharedCshake: sharedCshake,
    state: function () { return { fn: T1.fn, block: T1.block, perm: T1.perm, round: T1.round, res: T1.res }; },
    selectTab: selectTab, F1: F1, F4: F4, F5: F5
  };
})();
