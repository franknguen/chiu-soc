/* Giao diện phòng thí nghiệm RSA: một khoá dùng chung, bốn thẻ theo loại phép thử của NIST (sinh khoá, mã hoá, giải mã,
   ký / xác minh), bảng lần vết từng bước, nút ví dụ CAVP / ACVP so từng giá trị với đáp án, và nút tự kiểm chứng.
   Sinh khoá chạy trong Web Worker nếu trình duyệt cho phép (Chrome không cho trên file://), nếu không thì chạy ngay sau
   khi trang kịp vẽ dòng "đang tính". Mọi chuỗi hiển thị có hai bản qua bi(vi, en).
   Original implementation for the ChiU·SoC RSA lab. */
(function () {
  'use strict';
  var R = window.RSACore, V = window.RSA_VECTORS;

  /* ================================================================ tiện ích */
  function $(id) { var e = document.getElementById(id); if (!e) throw new Error('missing #' + id); return e; }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function bi(vi, en) { return '<span lang="vi">' + vi + '</span><span lang="en">' + en + '</span>'; }
  function nb(s) { return '<span data-i18n="neutral">' + s + '</span>'; }
  function num(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ' '); }
  function fill(s, a) { return s.replace(/\{(\w+)\}/g, function (m, k) { return a && a[k] !== undefined && a[k] !== null ? esc(a[k]) : m; }); }
  function checked(name) { var r = document.querySelector('input[name="' + name + '"]:checked'); return r ? r.value : null; }
  function radios(name) { return Array.prototype.slice.call(document.querySelectorAll('input[name="' + name + '"]')); }
  function onRadio(name, fn) { radios(name).forEach(function (r) { r.addEventListener('change', fn); }); }
  function setRadio(name, v) { radios(name).forEach(function (r) { r.checked = r.value === String(v); }); }
  function B(h) { return R.hexToBig(h); }
  function H(x) { return x.toString(16); }
  function hexOf(b) { return R.bytesToHex(b); }
  function rnd(n) { return window.PQCHash.randomBytes(n); }
  /* số lớn: số nhỏ in hệ 10, số lớn in hex rút gọn kèm số bit */
  function short(x) {
    if (typeof x !== 'bigint') x = BigInt(x);
    if (x < 0n) return '−' + short(-x);
    var b = R.bitLen(x);
    if (b <= 40) return x.toString(10);
    var h = x.toString(16);
    return '0x' + (h.length <= 40 ? h : h.slice(0, 16) + '…' + h.slice(-12)) + ' (' + b + ' bit)';
  }
  function cv(x) { return '<code>' + esc(short(x)) + '</code>'; }
  function cb(b, max) {
    var h = hexOf(b);
    max = max || 48;
    return '<code>' + (h.length <= max ? h : h.slice(0, max - 16) + '…' + h.slice(-12)) + ' (' + b.length + ' B)</code>';
  }
  function show(el, cls, main, sub) { el.className = 'result ' + cls; el.innerHTML = main + (sub ? '<span class="sub">' + sub + '</span>' : ''); }
  function enc8(s) { return new TextEncoder().encode(s); }
  function Err(code, info) { var e = new Error(code); e.code = code; if (info) e.info = info; return e; }
  /* vài giá trị trong tệp CAVS có số chữ số hex lẻ (thông điệp / chữ ký bị cắt ở các ca F): đọc với một số 0 đứng trước */
  function evenHex(h) { return h.length % 2 ? '0' + h : h; }

  /* ================================================================ phép tính dài: Web Worker hoặc chạy sau một nhịp */
  var worker = null, wid = 0, waits = {}, pending = 0, idleWaiters = [];
  try {
    if (window.Worker && location.protocol !== 'file:') {
      worker = new Worker('assets/rsa-worker.js');
      worker.onmessage = function (e) {
        var w = waits[e.data.id]; delete waits[e.data.id];
        if (!w) return;
        if (e.data.ok) w[0]({ v: e.data.v, t: e.data.ms });
        else { var x = new Error(e.data.err); x.code = e.data.code; x.info = e.data.info; w[1](x); }
      };
      worker.onerror = function () { worker = null; for (var k in waits) { waits[k][1](new Error('worker')); delete waits[k]; } };
    }
  } catch (e) { worker = null; }
  function settle() { pending--; if (!pending) { var a = idleWaiters; idleWaiters = []; a.forEach(function (f) { f(); }); } }
  function call(op, args) {
    pending++;
    var p = worker ? new Promise(function (res, rej) { var id = ++wid; waits[id] = [res, rej]; worker.postMessage({ id: id, op: op, args: args }); })
      : new Promise(function (res, rej) {
        setTimeout(function () {
          var t0 = Date.now();
          try { var v = R.jobs[op].apply(null, args); res({ v: v, t: Date.now() - t0 }); } catch (e) { rej(e); }
        }, 20);
      });
    p.then(settle, settle);
    return p;
  }
  function idle() { return pending ? new Promise(function (r) { idleWaiters.push(r); }) : Promise.resolve(); }

  /* ================================================================ thông báo theo mã */
  var MSG = {
    HEX: ['có ký tự không phải hex', 'contains a character that is not hex'],
    HEX_ODD: ['có số chữ số hex lẻ', 'has an odd number of hex digits'],
    DEC: ['có ký tự không phải chữ số thập phân', 'contains a character that is not a decimal digit'],
    NOT_UTF8: ['chứa byte không phải văn bản UTF-8, hãy xem ở dạng hex', 'holds bytes that are not UTF-8 text; view them as hex'],
    TOO_LONG: ['quá dài cho trang này', 'is too long for this page'],
    NEED: ['đang trống', 'is empty']
  };
  function fieldErr(f, e) {
    var m = MSG[e && e.code] || ['lỗi: ' + esc(e && e.message), 'error: ' + esc(e && e.message)];
    return bi('Ô ' + f.name[0] + ' ' + m[0] + '.', 'The ' + f.name[1] + ' field ' + m[1] + '.');
  }
  var REASON = {
    OK: ['hợp lệ', 'valid'],
    SIG_LEN: ['độ dài chữ ký khác k byte', 'the signature is not k bytes long'],
    SIG_RANGE: ['số đại diện chữ ký s ≥ n — RSAVP1 báo "ngoài khoảng"', 'the signature representative s ≥ n — RSAVP1 reports "out of range"'],
    EM_TOO_SHORT: ['khoá quá ngắn cho hàm băm này: EM không đủ chỗ cho DigestInfo và phần đệm', 'the key is too short for this hash: EM has no room for DigestInfo and padding'],
    ENCODING: ['s<sup>e</sup> mod n không phải một khối PKCS#1 v1.5 (00 01 FF…FF 00 DigestInfo): sai khoá hoặc chữ ký bị sửa',
      's<sup>e</sup> mod n is not a PKCS#1 v1.5 block (00 01 FF…FF 00 DigestInfo): wrong key or modified signature'],
    HASH_ALG: ['chữ ký mang DigestInfo của {alg}, không phải hàm băm đã chọn', 'the signature carries a {alg} DigestInfo, not the chosen hash'],
    DIGEST: ['cấu trúc đúng nhưng giá trị băm khác: thông điệp (hoặc khoá) không phải cái đã được ký', 'the structure is right but the hash value differs: the message (or key) is not the one that was signed'],
    SLEN: ['sLen &gt; hLen — FIPS 186-5, mục 5.4(g) đòi 0 ≤ sLen ≤ hLen', 'sLen &gt; hLen — FIPS 186-5, section 5.4(g) requires 0 ≤ sLen ≤ hLen'],
    EM_LARGE: ['s<sup>e</sup> mod n không vừa emLen byte', 's<sup>e</sup> mod n does not fit in emLen bytes'],
    INCONSISTENT: ['emLen &lt; hLen + sLen + 2', 'emLen &lt; hLen + sLen + 2'],
    TRAILER: ['byte cuối của EM không phải 0xbc', 'the last byte of EM is not 0xbc'],
    TOP_BITS: ['các bit đầu của maskedDB không bằng 0', 'the top bits of maskedDB are not zero'],
    PADDING: ['DB không có dạng 00…00 01 ‖ salt với sLen đã cho: sai sLen, sai hàm băm, sai khoá hoặc chữ ký bị sửa',
      'DB is not 00…00 01 ‖ salt for the given sLen: wrong sLen, wrong hash, wrong key or modified signature'],
    HASH: ['H ≠ H′: thông điệp, salt hoặc hàm băm khác lúc ký', 'H ≠ H′: the message, salt or hash differs from signing time'],
    K_SMALL: ['k &lt; 2·hLen + 2: khoá quá ngắn cho OAEP với SHA-256', 'k &lt; 2·hLen + 2: the key is too short for OAEP with SHA-256'],
    RANGE: ['c nằm ngoài 0 ≤ c &lt; n', 'c is outside 0 ≤ c &lt; n'],
    Y_NONZERO: ['byte đầu Y của EM khác 0', 'the first byte Y of EM is not 0'],
    LHASH: ['lHash′ trong DB khác SHA-256(L): sai nhãn, sai khoá hoặc bản mã bị sửa', 'lHash′ in DB differs from SHA-256(L): wrong label, wrong key or modified ciphertext'],
    SEPARATOR: ['không có byte 0x01 ngăn PS với M', 'no 0x01 byte separates PS from M']
  };
  function hlabel(id) { return id === 'SHA-1' ? 'SHA-1' : R.hinfo(id).label; }
  function reasonHtml(v) {
    var m = REASON[v.reason] || [esc(v.reason), esc(v.reason)];
    var a = { alg: v.alg ? hlabel(v.alg) : '' };
    return bi(fill(m[0], a), fill(m[1], a));
  }

  /* ================================================================ ô số nguyên và ô chuỗi byte */
  function tool(box, html, fn) { var b = document.createElement('button'); b.type = 'button'; b.innerHTML = html; b.addEventListener('click', fn); box.appendChild(b); return b; }
  function addCommon(f) {
    var g = document.createElement('span'); g.className = 'gap'; f.tools.appendChild(g);
    tool(f.tools, bi('Chép', 'Copy'), function () { f.copy(); });
    tool(f.tools, bi('Mở rộng', 'Expand'), function () { f.ta.parentNode.classList.toggle('big'); });
    if (!f.ta.readOnly) tool(f.tools, bi('Xoá', 'Clear'), function () { f.ta.value = ''; f.count(); f.edited(); });
    f.flashEl = document.createElement('span'); f.flashEl.className = 'flash'; f.tools.appendChild(f.flashEl);
    f.ta.addEventListener('input', function () { f.count(); f.edited(); });
  }
  var Base = {
    edited: function () { if (this.onEdit) this.onEdit(this); },
    empty: function () { return !this.ta.value.trim(); },
    peek: function () { try { return this.empty() ? null : this.value(); } catch (e) { return null; } },
    mark: function () { for (var k in this.btn) this.btn[k].setAttribute('aria-pressed', String(k === this.fmt)); },
    flash: function (html, bad) {
      var el = this.flashEl; el.style.color = bad ? '#9b1d28' : ''; el.innerHTML = html; clearTimeout(this.ft);
      this.ft = setTimeout(function () { el.innerHTML = ''; }, bad ? 5000 : 1800);
    },
    copy: function () {
      var f = this, s = f.ta.value;
      if (!s) return;
      function done() { f.flash(bi('đã chép', 'copied')); }
      function fallback() { f.ta.select(); try { document.execCommand('copy'); done(); } catch (e) { /* trình duyệt chặn */ } }
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(s).then(done, fallback); else fallback();
    },
    setFmt: function (k) {
      if (k === this.fmt) return;
      var v;
      if (!this.empty()) { try { v = this.value(); } catch (e) { return this.flash(fieldErr(this, e), true); } }
      var old = this.fmt; this.fmt = k;
      if (v !== undefined) { try { this.set(v); } catch (e) { this.fmt = old; this.mark(); return this.flash(fieldErr(this, e), true); } }
      this.mark(); this.count();
    }
  };
  function IntField(id, o) {
    var f = this;
    f.id = id; f.ta = $(id); f.cnt = $(id + '-cnt'); f.tools = $(id + '-tools'); f.name = o.name; f.fmt = o.fmt || 'hex'; f.onEdit = o.onEdit || null; f.btn = {};
    f.btn.hex = tool(f.tools, 'Hex', function () { f.setFmt('hex'); });
    f.btn.dec = tool(f.tools, 'Dec', function () { f.setFmt('dec'); });
    addCommon(f); f.mark(); f.count();
  }
  IntField.prototype = Object.create(Base);
  IntField.prototype.value = function () {
    var s = this.ta.value.replace(/[\s_]+/g, '');
    if (!s) throw Err('NEED');
    if (s.length > 5000) throw Err('TOO_LONG');
    if (/^0x/i.test(s)) s = s.slice(2); else if (this.fmt === 'dec') { if (!/^[0-9]+$/.test(s)) throw Err('DEC'); return BigInt(s); }
    if (!/^[0-9a-fA-F]+$/.test(s)) throw Err('HEX');
    return BigInt('0x' + s);
  };
  IntField.prototype.set = function (x) {
    if (x === null || x === undefined) { this.ta.value = ''; this.count(); return; }
    if (typeof x === 'string') x = B(x);
    this.ta.value = this.fmt === 'dec' ? x.toString(10) : R.bigToHex(x);
    this.count();
  };
  IntField.prototype.count = function () {
    var el = this.cnt, x;
    if (this.empty()) { el.className = 'cnt'; el.innerHTML = ''; return; }
    try { x = this.value(); } catch (e) { el.className = 'cnt bad'; el.innerHTML = bi('không hợp lệ', 'invalid'); return; }
    el.className = 'cnt'; el.innerHTML = nb(num(R.bitLen(x)) + ' bit · ' + num(R.byteLen(x)) + ' B');
  };
  function BytesField(id, o) {
    var f = this;
    f.id = id; f.ta = $(id); f.cnt = $(id + '-cnt'); f.tools = $(id + '-tools'); f.name = o.name; f.fmt = o.fmt || 'hex'; f.onEdit = o.onEdit || null;
    f.need = o.need || null; f.btn = {};
    if (o.text !== false) {
      f.btn.hex = tool(f.tools, 'Hex', function () { f.setFmt('hex'); });
      f.btn.text = tool(f.tools, bi('Văn bản', 'Text'), function () { f.setFmt('text'); });
    }
    addCommon(f); f.mark(); f.count();
  }
  BytesField.prototype = Object.create(Base);
  BytesField.prototype.value = function () {
    var s = this.ta.value;
    if (s.length > 1 << 20) throw Err('TOO_LONG');
    if (this.fmt === 'text') return enc8(s);
    return R.hexToBytes(s);
  };
  BytesField.prototype.empty = function () { return this.fmt === 'text' ? this.ta.value === '' : !this.ta.value.trim(); };
  BytesField.prototype.set = function (b) {
    if (!b) { this.ta.value = ''; this.count(); return; }
    if (this.fmt === 'text') {
      try { this.ta.value = new TextDecoder('utf-8', { fatal: true }).decode(b); }
      catch (e) { this.fmt = 'hex'; this.mark(); this.ta.value = hexOf(b); }
    } else this.ta.value = hexOf(b);
    this.count();
  };
  BytesField.prototype.count = function () {
    var el = this.cnt, b, need = this.need ? this.need() : null;
    if (this.empty()) { el.className = 'cnt'; el.innerHTML = need ? nb('0 / ' + need + ' B') : ''; return; }
    try { b = this.value(); } catch (e) { el.className = 'cnt bad'; el.innerHTML = bi('không hợp lệ', 'invalid'); return; }
    var ok = need === null || b.length === need;
    el.className = 'cnt' + (need !== null ? (ok ? ' ok' : ' warn') : '');
    el.innerHTML = nb(num(b.length) + (need !== null ? ' / ' + need : '') + ' B' + (need !== null && ok ? ' ✓' : ''));
  };

  /* ================================================================ lần vết */
  function Trace(el) { this.el = el; this.out = []; }
  Trace.prototype.h = function (vi, en) { this.out.push('<h5>' + bi(vi, en) + '</h5>'); return this; };
  Trace.prototype.line = function (st, vi, en, val, id) {
    var ic = st === 'ok' ? '✓' : (st === 'bad' ? '✕' : '·');
    this.out.push('<div class="tl ' + st + '"' + (id ? ' data-ck="' + id + '"' : '') + '><span class="ic">' + ic + '</span><span class="tx">' + bi(vi, en) + (val ? ' ' + val : '') + '</span></div>');
    return this;
  };
  Trace.prototype.raw = function (html) { this.out.push(html); return this; };
  Trace.prototype.done = function () { this.el.innerHTML = this.out.join(''); };
  /* so một giá trị với đáp án của tệp; trả về true / false */
  function cmp(T, vi, en, got, want, src) {
    var ok = got === want;
    T.line(ok ? 'ok' : 'bad', vi + (ok ? ' = đáp án ' : ' KHÁC đáp án ') + src, en + (ok ? ' = the ' : ' DIFFERS from the ') + src + ' answer',
      '<code>' + esc(got === null || got === undefined ? '—' : String(got).length > 60 ? String(got).slice(0, 40) + '…' + String(got).slice(-12) : got) + '</code>');
    return ok;
  }
  function strip0(h) { h = String(h).toLowerCase().replace(/^0+/, ''); return h || '0'; }

  /* ================================================================ khung một thẻ */
  function Tab(res, trace, panel) { this.res = $(res); this.tr = $(trace); this.panel = $(panel); this.busyT = null; this.tok = 0; }
  Tab.prototype.busy = function (vi, en) {
    var X = this, t0 = Date.now();
    Array.prototype.forEach.call(X.panel.querySelectorAll('button'), function (b) { b.disabled = true; });
    function tick() { show(X.res, 'info', '⏳ ' + bi(vi, en), nb(((Date.now() - t0) / 1000).toFixed(1) + ' s')); }
    tick(); X.busyT = setInterval(tick, 250);
    return ++X.tok;
  };
  Tab.prototype.done = function () {
    clearInterval(this.busyT); this.busyT = null;
    Array.prototype.forEach.call(this.panel.querySelectorAll('button'), function (b) { b.disabled = false; });
  };
  Tab.prototype.ok = function (html, sub) { show(this.res, 'ok', '✓ ' + html, sub); };
  Tab.prototype.bad = function (html, sub) { show(this.res, 'bad', '✕ ' + html, sub); };
  Tab.prototype.info = function (html, sub) { show(this.res, 'info', html, sub); };
  Tab.prototype.clear = function () { this.res.className = 'result'; this.res.innerHTML = ''; this.tr.innerHTML = ''; };

  /* ================================================================ khoá dùng chung */
  var KN = { n: ['n', 'n'], e: ['e', 'e'], d: ['d', 'd'], p: ['p', 'p'], q: ['q', 'q'], dP: ['dP', 'dP'], dQ: ['dQ', 'dQ'], qInv: ['qInv', 'qInv'] };
  var KF = {}, keyTimer = null;
  Object.keys(KN).forEach(function (k) { KF[k] = new IntField('k-' + k, { name: KN[k], fmt: k === 'e' ? 'dec' : 'hex', onEdit: keyEdited }); });
  function nlen() { return +checked('rsa-size'); }
  function keyEdited() { clearTimeout(keyTimer); keyTimer = setTimeout(keyStatus, 150); }
  /* lấy các phần khoá cần; thiếu / sai thì ném lỗi có thông báo hai ngôn ngữ */
  function keyGet(need) {
    var k = {};
    Object.keys(KF).forEach(function (f) {
      var F = KF[f];
      if (F.empty()) { if (need.indexOf(f) >= 0) throw Err('UI', { html: bi('Khoá chưa có ' + f + '.', 'The key has no ' + f + ' yet.') }); return; }
      try { k[f] = F.value(); } catch (e) { throw Err('UI', { html: fieldErr(F, e) }); }
    });
    if (k.n !== undefined && k.n < 3n) throw Err('UI', { html: bi('n quá nhỏ.', 'n is too small.') });
    if (k.p && k.q && k.d !== undefined && (k.dP === undefined || k.dQ === undefined || k.qInv === undefined)) {
      try { k.dP = k.d % (k.p - 1n); k.dQ = k.d % (k.q - 1n); k.qInv = R.modInv(k.q, k.p); k.derived = true; } catch (e) { /* p, q hỏng: chỉ dùng d */ }
    }
    return k;
  }
  function keyHex(k) { var o = {}; ['n', 'e', 'd', 'p', 'q', 'dP', 'dQ', 'qInv'].forEach(function (f) { if (k[f] !== undefined) o[f] = H(k[f]); }); return o; }
  function keySet(o, dec) {
    ['n', 'e', 'd', 'p', 'q', 'dP', 'dQ', 'qInv'].forEach(function (f) { KF[f].fmt = dec || f === 'e' ? 'dec' : 'hex'; KF[f].mark(); });
    ['n', 'e', 'd', 'p', 'q', 'dP', 'dQ', 'qInv'].forEach(function (f) { KF[f].set(o[f] === undefined || o[f] === '' ? null : (typeof o[f] === 'string' ? B(o[f]) : o[f])); });
    keyStatus();
  }
  function keyStatus() {
    clearTimeout(keyTimer); keyTimer = null;
    var el = $('key-status'), k;
    try { k = keyGet([]); } catch (e) { el.className = 'keyline bad'; el.innerHTML = e.info.html; return; }
    if (k.n === undefined) { el.className = 'keyline'; el.innerHTML = bi('Chưa có khoá: sinh một khoá ở thẻ 1 hoặc bấm một nút ví dụ.', 'No key yet: generate one in tab 1 or press an example button.'); return; }
    var parts = [], bad = [];
    parts.push(nb('n: ' + R.bitLen(k.n) + ' bit'));
    if (k.p && k.q) (k.p * k.q === k.n ? parts : bad).push('p·q = n');
    if (k.d !== undefined && k.p && k.q && k.e) {
      var lam = R.lcm(k.p - 1n, k.q - 1n);
      (k.e * k.d % lam === 1n ? parts : bad).push('e·d ≡ 1 (mod λ)');
    }
    if (k.dP !== undefined && k.p && k.d !== undefined && !k.derived) (k.dP === k.d % (k.p - 1n) ? parts : bad).push('dP');
    if (k.dQ !== undefined && k.q && k.d !== undefined && !k.derived) (k.dQ === k.d % (k.q - 1n) ? parts : bad).push('dQ');
    if (k.qInv !== undefined && k.p && k.q && !k.derived) (k.q * k.qInv % k.p === 1n ? parts : bad).push('qInv');
    var priv = k.d !== undefined ? (R.hasCrt(k) ? bi('khoá riêng: d và dạng CRT', 'private key: d and CRT form') : bi('khoá riêng: d', 'private key: d')) : bi('chỉ có khoá công khai', 'public key only');
    el.className = 'keyline ' + (bad.length ? 'bad' : 'ok');
    el.innerHTML = (bad.length ? '✕ ' : '✓ ') + nb(parts.map(function (s) { return s === parts[0] ? s : s + ' ✓'; }).join(' · ')) + ' · ' + priv +
      (bad.length ? ' · ' + bi('SAI: ', 'WRONG: ') + nb(bad.join(', ')) : '');
  }
  function sizeNote() {
    var nl = nlen(), s = R.strength(nl), mr = R.mrRounds(nl), el = $('size-note');
    var base = nb('RSA-' + nl + ': E = ' + s.E.toFixed(2) + ', ES = ' + s.ES + ' bit · M-R t = ' + mr.t + ' (' + mr.src + ', 2^' + mr.perr + ')');
    if (nl < 2048) {
      el.className = 'hint warn';
      el.innerHTML = base + ' · ' + bi('Chỉ để thử, không được phép: FIPS 186-5 A.1.3 bước 1 trả FAILURE khi nlen &lt; 2048, và SP 800-131A cấm tạo chữ ký với độ mạnh dưới 112 bit.',
        'Test only, not allowed: FIPS 186-5 A.1.3 step 1 returns FAILURE for nlen &lt; 2048, and SP 800-131A disallows signature generation below 112 bits of strength.');
    } else {
      el.className = 'hint';
      el.innerHTML = base + ' · ' + bi('Cỡ được FIPS 186-5 chấp nhận.', 'A size FIPS 186-5 accepts.');
    }
  }
  onRadio('rsa-size', function () {                                  // người dùng đổi cỡ: khoá cũ không còn hợp, xoá (giữ e)
    ['n', 'd', 'p', 'q', 'dP', 'dQ', 'qInv'].forEach(function (f) { KF[f].set(null); });
    sizeNote(); keyStatus();
  });
  $('key-clear').addEventListener('click', function () { ['n', 'd', 'p', 'q', 'dP', 'dQ', 'qInv'].forEach(function (f) { KF[f].set(null); }); keyStatus(); });

  /* ================================================================ thẻ */
  var TABS = ['kg', 'enc', 'dec', 'sig'];
  function openTab(t) {
    TABS.forEach(function (x) { $('tab-' + x).setAttribute('aria-selected', String(x === t)); $('panel-' + x).hidden = x !== t; });
  }
  TABS.forEach(function (t) { $('tab-' + t).addEventListener('click', function () { openTab(t); }); });

  /* ================================================================ 1. sinh khoá */
  var KG = new Tab('kg-result', 'kg-trace', 'panel-kg');
  var seedF = new BytesField('kg-seed', { name: ['seed', 'seed'], onEdit: function () { $('kg-seed-rnd').checked = false; } });
  var CHECKS = [
    ['e_odd', 'e lẻ', 'e is odd'],
    ['e_range', '2<sup>16</sup> &lt; e &lt; 2<sup>256</sup> (A.1.1, 1(b))', '2<sup>16</sup> &lt; e &lt; 2<sup>256</sup> (A.1.1, 1(b))'],
    ['nlen_ok', 'nlen ≥ 2048 (A.1.3, bước 1)', 'nlen ≥ 2048 (A.1.3, step 1)'],
    ['p_low', 'p ≥ √2·2<sup>nlen/2 − 1</sup> (A.1.1, 2(b))', 'p ≥ √2·2<sup>nlen/2 − 1</sup> (A.1.1, 2(b))'],
    ['p_high', 'p &lt; 2<sup>nlen/2</sup>: dài đúng nlen/2 bit', 'p &lt; 2<sup>nlen/2</sup>: exactly nlen/2 bits'],
    ['q_low', 'q ≥ √2·2<sup>nlen/2 − 1</sup> (A.1.1, 2(c))', 'q ≥ √2·2<sup>nlen/2 − 1</sup> (A.1.1, 2(c))'],
    ['q_high', 'q &lt; 2<sup>nlen/2</sup>', 'q &lt; 2<sup>nlen/2</sup>'],
    ['p_gcd', 'gcd(p − 1, e) = 1 (A.1.1, 2(a))', 'gcd(p − 1, e) = 1 (A.1.1, 2(a))'],
    ['q_gcd', 'gcd(q − 1, e) = 1 (A.1.1, 2(a))', 'gcd(q − 1, e) = 1 (A.1.1, 2(a))'],
    ['p_prime', 'p là số nguyên tố xác suất: chia thử tới 10 000, rồi Miller–Rabin (B.3, B.3.1)', 'p is a probable prime: trial division up to 10 000, then Miller–Rabin (B.3, B.3.1)'],
    ['q_prime', 'q là số nguyên tố xác suất', 'q is a probable prime'],
    ['pq_dist', '|p − q| &gt; 2<sup>nlen/2 − 100</sup> (A.1.1, 2(d))', '|p − q| &gt; 2<sup>nlen/2 − 100</sup> (A.1.1, 2(d))'],
    ['d_inv', 'd = e<sup>−1</sup> mod λ(n): e·d ≡ 1 (A.1.1, 3(b))', 'd = e<sup>−1</sup> mod λ(n): e·d ≡ 1 (A.1.1, 3(b))'],
    ['d_size', '2<sup>nlen/2</sup> &lt; d &lt; λ(n) (A.1.1, 3(a))', '2<sup>nlen/2</sup> &lt; d &lt; λ(n) (A.1.1, 3(a))'],
    ['n_len', 'n dài đúng nlen bit', 'n is exactly nlen bits long']
  ];
  function mrNote(r) {
    if (!r) return '';
    if (r.small) return nb('(≤ 10 000)');
    if (r.td) return bi('chia hết cho ' + r.td, 'divisible by ' + r.td);
    return nb(r.rounds + ' M-R');
  }
  function renderChecks(T, c, nl) {
    T.h('Các điều kiện của FIPS 186-5, Phụ lục A.1.1 / A.1.3', 'FIPS 186-5 conditions, Appendix A.1.1 / A.1.3');
    var bad = 0;
    CHECKS.forEach(function (ck) {
      var ok = c.rows[ck[0]], extra = ck[0] === 'p_prime' ? mrNote(c.p_mr) : (ck[0] === 'q_prime' ? mrNote(c.q_mr) : '');
      if (!ok && !(ck[0] === 'nlen_ok')) bad++;
      if (!ok && ck[0] === 'nlen_ok') T.line('bad', ck[1] + ' — RSA-' + nl + ' chỉ để thử', ck[2] + ' — RSA-' + nl + ' is test only', '', ck[0]);
      else T.line(ok ? 'ok' : 'bad', ck[1], ck[2], extra, ck[0]);
    });
    return bad;
  }
  function renderSearch(T, r) {
    var rows = [
      ['draws', 'ứng viên đã rút (4.2 / 5.2)', 'candidates drawn (4.2 / 5.2)'],
      ['lb', 'loại: dưới √2·2<sup>nlen/2 − 1</sup> (4.4 / 5.4)', 'rejected: below √2·2<sup>nlen/2 − 1</sup> (4.4 / 5.4)'],
      ['close', 'loại: |p − q| quá nhỏ (5.5)', 'rejected: |p − q| too small (5.5)'],
      ['gcd', 'loại: gcd(x − 1, e) ≠ 1 (4.5 / 5.6)', 'rejected: gcd(x − 1, e) ≠ 1 (4.5 / 5.6)'],
      ['td', 'loại: chia thử, số nguyên tố ≤ 10 000 (B.3)', 'rejected: trial division, primes ≤ 10 000 (B.3)'],
      ['mr', 'loại: Miller–Rabin báo hợp số (B.3.1)', 'rejected: Miller–Rabin says composite (B.3.1)'],
      ['mrRounds', 'số vòng Miller–Rabin đã chạy', 'Miller–Rabin rounds run'],
      ['i', 'bộ đếm i của FIPS (giới hạn 5·nlen / 10·nlen)', 'FIPS counter i (limit 5·nlen / 10·nlen)']
    ];
    var h = '<div class="tbl-wrap"><table><thead><tr><th>' + bi('Bước', 'Step') + '</th><th>p</th><th>q</th></tr></thead><tbody>';
    rows.forEach(function (x) {
      h += '<tr><td>' + bi(x[1], x[2]) + '</td><td class="num">' + (x[0] === 'close' ? '—' : num(r.statsP[x[0]])) + '</td><td class="num">' + num(r.statsQ[x[0]]) + '</td></tr>';
    });
    T.raw(h + '</tbody></table></div>');
  }
  function renderKeyResult(T, k, dPhi) {
    T.h('Khoá', 'The key');
    var n = B(k.n), lam = B(k.lam), d = B(k.d);
    T.line('info', 'n = p·q', 'n = p·q', cv(n));
    T.line('info', 'λ(n) = lcm(p − 1, q − 1)', 'λ(n) = lcm(p − 1, q − 1)', cv(lam));
    T.line('info', 'd theo λ (FIPS 186-5)', 'd from λ (FIPS 186-5)', cv(d));
    if (dPhi) {
      var dp = B(dPhi);
      T.line(dp % lam === d ? 'ok' : 'bad', 'd theo φ, kiểu sách giáo khoa — khác d nhưng d<sub>φ</sub> ≡ d (mod λ)', 'd from φ, textbook style — different, but d<sub>φ</sub> ≡ d (mod λ)', cv(dp));
    }
    T.line('info', 'dP, dQ, qInv cho CRT', 'dP, dQ, qInv for CRT', cv(B(k.dP)) + ' ' + cv(B(k.dQ)) + ' ' + cv(B(k.qInv)));
  }
  function eGet() {
    if (KF.e.empty()) KF.e.set(65537n);
    try { return KF.e.value(); } catch (e) { throw Err('UI', { html: fieldErr(KF.e, e) }); }
  }
  function uiFail(X, e) {
    if (e && e.code === 'UI') return X.bad(e.info.html);
    var m = {
      E_EVEN: bi('e phải lẻ (FIPS 186-5, A.1.1, 1(b)).', 'e must be odd (FIPS 186-5, A.1.1, 1(b)).'),
      E_RANGE: bi('e phải thoả 2<sup>16</sup> &lt; e &lt; 2<sup>256</sup> (FIPS 186-5, A.1.1, 1(b)).', 'e must satisfy 2<sup>16</sup> &lt; e &lt; 2<sup>256</sup> (FIPS 186-5, A.1.1, 1(b)).'),
      NOT_INVERTIBLE: bi('Không có nghịch đảo: gcd(e, λ(n)) ≠ 1, hoặc p = q.', 'No inverse exists: gcd(e, λ(n)) ≠ 1, or p = q.'),
      FAILURE: bi('FIPS 186-5 A.1.3 trả FAILURE: quá nhiều ứng viên hỏng.', 'FIPS 186-5 A.1.3 returned FAILURE: too many failed candidates.')
    }[e && e.code];
    X.bad(m || bi('Lỗi không mong đợi: ', 'Unexpected error: ') + esc(e && e.message));
  }
  var ownCompare = null;                                               // đặt bởi nút "khoá mẫu riêng" để so sau khi sinh xong
  function kgGenerate() {
    var X = KG, nl = nlen(), e, seed;
    try {
      e = eGet(); R.checkE(e);
      if ($('kg-seed-rnd').checked) { seedF.fmt = 'hex'; seedF.mark(); seedF.set(rnd(32)); }
      if (seedF.empty()) throw Err('UI', { html: bi('Ô seed đang trống: nhập seed hoặc đánh dấu "seed ngẫu nhiên".', 'The seed field is empty: type a seed or tick "random seed".') });
      try { seed = seedF.value(); } catch (x) { throw Err('UI', { html: fieldErr(seedF, x) }); }
    } catch (x) { ownCompare = null; X.tr.innerHTML = ''; return uiFail(X, x); }
    var cmpTo = ownCompare; ownCompare = null;
    var tok = X.busy('Đang sinh khoá RSA-' + nl + '…', 'Generating an RSA-' + nl + ' key…');
    return call('keygen', [nl, H(e), hexOf(seed)]).then(function (res) {
      if (tok !== X.tok) return;
      X.done();
      var r = res.v, T = new Trace(X.tr);
      keySet({ n: r.n, e: r.e, d: r.d, p: r.p, q: r.q, dP: r.dP, dQ: r.dQ, qInv: r.qInv });
      T.h('Đầu vào', 'Inputs');
      T.line('info', 'nlen, e, seed', 'nlen, e, seed', '<code>' + nl + '</code> ' + cv(e) + ' ' + cb(seed));
      var mr = R.mrRounds(nl);
      T.line('info', 'số vòng Miller–Rabin cho mỗi số: t = ' + mr.t + (mr.src === 'B.1' ? ' (Bảng B.1' : ' (Phụ lục C.1') + ', xác suất lỗi 2<sup>' + mr.perr + '</sup>)',
        'Miller–Rabin rounds per prime: t = ' + mr.t + (mr.src === 'B.1' ? ' (Table B.1' : ' (Appendix C.1') + ', error probability 2<sup>' + mr.perr + '</sup>)', '');
      T.line('info', 'bộ sinh đã rút ' + num(r.ctr) + ' khối SHAKE256(seed ‖ j)', 'the generator drew ' + num(r.ctr) + ' blocks SHAKE256(seed ‖ j)', '');
      T.h('Tìm p rồi q (A.1.3, bước 4 và 5)', 'Searching for p, then q (A.1.3, steps 4 and 5)');
      renderSearch(T, r);
      if (r.restarts) T.line('info', 'd ≤ 2<sup>nlen/2</sup> nên sinh lại ' + r.restarts + ' lần', 'd ≤ 2<sup>nlen/2</sup>, so regenerated ' + r.restarts + ' times', '');
      var bad = renderChecks(T, r.check, nl);
      renderKeyResult(T, r, r.dPhi);
      var cmpBad = 0;
      if (cmpTo) {
        T.h('So với khoá mẫu riêng (mô hình Python độc lập)', 'Compared with the own example key (independent Python model)');
        ['p', 'q', 'n', 'd', 'dP', 'dQ', 'qInv'].forEach(function (f) { if (!cmp(T, f, f, strip0(r[f]), strip0(cmpTo[f]), cmpTo.src)) cmpBad++; });
        T.line(r.ctr === cmpTo.ctr ? 'ok' : 'bad', 'số khối đã rút', 'blocks drawn', nb(r.ctr + ' / ' + cmpTo.ctr));
        if (r.ctr !== cmpTo.ctr) cmpBad++;
      }
      T.done();
      var t = nb((res.t / 1000).toFixed(2) + ' s');
      if (cmpBad) X.bad(bi('Khoá KHÁC đáp án của mô hình ở ' + cmpBad + ' giá trị.', 'The key DIFFERS from the model at ' + cmpBad + ' values.'), t);
      else if (bad) X.bad(bi('Khoá sinh xong nhưng ' + bad + ' điều kiện không đạt.', 'Key generated, but ' + bad + ' conditions fail.'), t);
      else X.ok(bi('Khoá RSA-' + nl + ' sinh xong; mọi điều kiện của FIPS 186-5 đều đạt' + (nl < 2048 ? ', trừ nlen ≥ 2048: khoá chỉ để thử.' : '.') + (cmpTo ? ' Khớp khoá mẫu ✓' : ''),
        'RSA-' + nl + ' key generated; every FIPS 186-5 condition holds' + (nl < 2048 ? ', except nlen ≥ 2048: a test-only key.' : '.') + (cmpTo ? ' Matches the example key ✓' : '')), t);
    }, function (x) { if (tok !== X.tok) return; X.done(); uiFail(X, x); });
  }
  $('kg-gen').addEventListener('click', function () { ownCompare = null; kgGenerate(); });
  /* tính khoá từ p, q, e (kiểu ACVP) hoặc kiểm một khoá đầy đủ */
  function kgCheck(mode, fileCmp) {
    var X = KG, nl = nlen(), k;
    try { if (KF.e.empty()) KF.e.set(65537n); k = keyGet(mode === 'pair' ? ['n', 'e', 'd', 'p', 'q', 'dP', 'dQ', 'qInv'] : ['p', 'q', 'e']); }
    catch (x) { X.tr.innerHTML = ''; return Promise.resolve(uiFail(X, x)); }
    if (k.derived) { delete k.dP; delete k.dQ; delete k.qInv; }
    var tok = X.busy('Đang kiểm tra…', 'Checking…'), arg = mode === 'pair' ? keyHex(k) : { p: H(k.p), q: H(k.q), e: H(k.e) };
    return call('check', [nl, arg]).then(function (res) {
      if (tok !== X.tok) return;
      X.done();
      var r = res.v, T = new Trace(X.tr), bad = 0, fb = 0;
      if (mode === 'pq' && r.key) keySet({ n: r.key.n, e: H(k.e), d: r.key.d, p: H(k.p), q: H(k.q), dP: r.key.dP, dQ: r.key.dQ, qInv: r.key.qInv }, KF.p.fmt === 'dec');
      T.h('Đầu vào', 'Inputs');
      T.line('info', 'p, q, e', 'p, q, e', cv(k.p) + ' ' + cv(k.q) + ' ' + cv(k.e));
      if (r.error) T.line('bad', 'không tính được d', 'd cannot be computed', '<code>' + esc(r.error) + '</code>');
      bad = renderChecks(T, r.check, nl);
      if (r.key) renderKeyResult(T, r.key, r.dPhi);
      if (r.pair) {
        T.h('Quan hệ giữa các phần của khoá', 'Relations between the key parts');
        [['pq_n', 'p·q = n'], ['ed', 'e·d ≡ 1 (mod λ(n))'], ['dP', 'dP = d mod (p − 1)'], ['dQ', 'dQ = d mod (q − 1)'], ['qInv', 'q·qInv ≡ 1 (mod p)'],
          ['roundtrip', '(2<sup>e</sup>)<sup>d</sup> mod n = 2']].forEach(function (x) {
          if (!r.pair[x[0]]) bad++;
          T.line(r.pair[x[0]] ? 'ok' : 'bad', x[1], x[1], '', 'pair_' + x[0]);
        });
      }
      if (fileCmp) {
        T.h('So với tệp của NIST', "Compared with NIST's file");
        [['n', 'n'], ['dP', 'dmp1'], ['dQ', 'dmq1'], ['qInv', 'iqmp']].forEach(function (x) {
          if (!cmp(T, x[0], x[0], r.key ? strip0(r.key[x[0]]) : null, strip0(fileCmp.file[x[1]]), fileCmp.src)) fb++;
        });
      }
      T.done();
      if (fileCmp) {
        if (fb) X.bad(bi('KHÁC đáp án ' + esc(fileCmp.src) + ' ở ' + fb + ' giá trị.', 'DIFFERS from the ' + esc(fileCmp.src) + ' answer at ' + fb + ' values.'));
        else X.ok(bi('Khớp đáp án ' + esc(fileCmp.src) + ': n, dmp1, dmq1, iqmp (4/4).', 'Matches the ' + esc(fileCmp.src) + ' answer: n, dmp1, dmq1, iqmp (4/4).'),
          bad ? bi(bad + ' điều kiện của FIPS 186-5 không đạt.', bad + ' FIPS 186-5 conditions fail.') : bi('Mọi điều kiện của FIPS 186-5 đều đạt.', 'Every FIPS 186-5 condition holds.'));
      } else if (r.error) X.bad(bi('Không tính được khoá: gcd(e, λ(n)) ≠ 1 hoặc p = q.', 'The key cannot be computed: gcd(e, λ(n)) ≠ 1 or p = q.'));
      else if (bad) X.bad(bi(bad + ' điều kiện không đạt — xem bảng lần vết.', bad + ' conditions fail — see the trace.'));
      else X.ok(mode === 'pair' ? bi('Cặp khoá đúng và đạt mọi điều kiện của FIPS 186-5' + (nl < 2048 ? ' (trừ nlen ≥ 2048: chỉ để thử).' : '.'), 'The key pair is consistent and meets every FIPS 186-5 condition' + (nl < 2048 ? ' (except nlen ≥ 2048: test only).' : '.'))
        : bi('Đã tính n, d, dP, dQ, qInv; mọi điều kiện đạt' + (nl < 2048 ? ' (trừ nlen ≥ 2048: chỉ để thử).' : '.'), 'Computed n, d, dP, dQ, qInv; every condition holds' + (nl < 2048 ? ' (except nlen ≥ 2048: test only).' : '.')));
    }, function (x) { if (tok !== X.tok) return; X.done(); uiFail(X, x); });
  }
  $('kg-frompq').addEventListener('click', function () { kgCheck('pq'); });
  $('kg-check').addEventListener('click', function () { kgCheck('pair'); });
  $('kg-own').addEventListener('click', function () {
    var nl = nlen(), o = V.own[String(nl)];
    openTab('kg');
    $('kg-seed-rnd').checked = false; seedF.fmt = 'text'; seedF.mark(); seedF.set(enc8('chiusoc-rsa-' + nl));
    KF.e.set(B(o.e));
    ownCompare = { p: o.p, q: o.q, n: o.n, d: o.d, dP: o.dP, dQ: o.dQ, qInv: o.qInv, ctr: o.ctr, src: 'chiusoc-rsa-' + nl };
    return kgGenerate();
  });
  $('kg-acvp').addEventListener('click', function () {
    var nl = nlen(), c = V.keygen_acvp.filter(function (x) { return x.nlen === nl; })[0];
    openTab('kg');
    if (!c) { KG.tr.innerHTML = ''; return KG.info(bi('Tệp ACVP RSA-KeyGen-FIPS186-5 không có ca nào cho nlen = ' + nl + '. Hãy chọn 2048, 3072 hoặc 4096, hoặc dùng khoá mẫu riêng.',
      "NIST's ACVP RSA-KeyGen-FIPS186-5 file has no case for nlen = " + nl + '. Pick 2048, 3072 or 4096, or use the own example key.')); }
    keySet({ e: c.e, p: c.p, q: c.q });
    return kgCheck('pq', { file: c.file, src: 'ACVP RSA-KeyGen-FIPS186-5 tcId ' + c.tcId });
  });
  $('tb-load').addEventListener('click', function () {
    var T0 = V.textbook;
    keySet({ e: BigInt(T0.e), p: BigInt(T0.p), q: BigInt(T0.q) }, true);
    encM.fmt = 'dec'; encM.mark(); encM.set(BigInt(T0.m)); setRadio('enc-rule', 'rfc'); setRadio('enc-mode', 'raw'); encMode();
    openTab('kg');
    try { var lab = document.getElementById('lab'); if (lab && lab.scrollIntoView) lab.scrollIntoView(); } catch (e) { /* jsdom */ }
    return kgCheck('pq');
  });

  /* ================================================================ 2. mã hoá */
  var EN = new Tab('enc-result', 'enc-trace', 'panel-enc');
  var encM = new IntField('enc-m', { name: ['m', 'm'] });
  var encC = new IntField('enc-c', { name: ['c', 'c'] });
  var encMsg = new BytesField('enc-msg', { name: ['M', 'M'], fmt: 'text' });
  var encL = new BytesField('enc-label', { name: ['L', 'L'], fmt: 'text' });
  var encSeed = new BytesField('enc-seed', { name: ['seed', 'seed'], text: false, need: function () { return 32; }, onEdit: function () { $('enc-seed-rnd').checked = false; } });
  function encMode() { var o = checked('enc-mode') === 'oaep'; $('enc-raw').hidden = o; $('enc-oaep').hidden = !o; }
  onRadio('enc-mode', function () { encMode(); EN.clear(); });
  function rangeLines(T, x, n, rule, name) {
    var rfc = R.inRange(x, n, 'rfc'), sp = R.inRange(x, n, 'sp56b');
    T.line(rfc ? 'ok' : (rule === 'rfc' ? 'bad' : 'info'), 'RFC 8017: 0 ≤ ' + name + ' &lt; n' + (rule === 'rfc' ? ' — quy tắc đang chọn' : ''), 'RFC 8017: 0 ≤ ' + name + ' &lt; n' + (rule === 'rfc' ? ' — the selected rule' : ''), '');
    T.line(sp ? 'ok' : (rule === 'sp56b' ? 'bad' : 'info'), 'SP 800-56B r2, mục 7.1: 1 &lt; ' + name + ' &lt; n − 1' + (rule === 'sp56b' ? ' — quy tắc đang chọn' : ''),
      'SP 800-56B r2, section 7.1: 1 &lt; ' + name + ' &lt; n − 1' + (rule === 'sp56b' ? ' — the selected rule' : ''), '');
    return rule === 'rfc' ? rfc : sp;
  }
  function encRaw(exp) {
    var X = EN, k, m, rule = checked('enc-rule'), T = new Trace(X.tr);
    try { k = keyGet(['n', 'e']); if (encM.empty()) throw Err('UI', { html: bi('Ô m đang trống.', 'The m field is empty.') }); m = encM.value(); }
    catch (x) { X.tr.innerHTML = ''; encC.set(null); return x.code === 'UI' ? X.bad(x.info.html) : X.bad(fieldErr(encM, x)); }
    T.h('Kiểm khoảng (RSAEP, bước 1)', 'Range check (RSAEP, step 1)');
    var inr = rangeLines(T, m, k.n, rule, 'm');
    if (!inr) {
      encC.set(null); T.done();
      var res = exp ? cmpRefusal(T, exp) : null;
      if (exp) { T.done(); return res ? X.ok(bi('Bị từ chối, đúng như ' + exp.src + ' đòi.', 'Refused, as ' + exp.src + ' requires.')) : X.bad(bi('Bị từ chối nhưng tệp có đáp án.', 'Refused, but the file has an answer.')); }
      return X.bad(bi('m nằm ngoài khoảng của quy tắc đang chọn: RSAEP báo <code>message representative out of range</code> và dừng.', 'm is outside the selected rule\'s range: RSAEP reports <code>message representative out of range</code> and stops.'));
    }
    var tr = R.modPowTrace(m, k.e, k.n);
    T.h('c = m<sup>e</sup> mod n bằng bình phương-và-nhân', 'c = m<sup>e</sup> mod n by square-and-multiply');
    T.line('info', 'e có ' + tr.bits + ' bit: ' + tr.S + ' lần bình phương và ' + tr.M + ' lần nhân', 'e has ' + tr.bits + ' bits: ' + tr.S + ' squarings and ' + tr.M + ' multiplications', '');
    var h = '<div class="tbl-wrap"><table><thead><tr><th>#</th><th>' + bi('bit', 'bit') + '</th><th>' + bi('sau bình phương', 'after squaring') + '</th><th>' + bi('sau phép nhân', 'after multiplying') + '</th></tr></thead><tbody>';
    var last = 0;
    tr.steps.forEach(function (s) {
      if (s.i > last + 1) h += '<tr><td colspan="4">…</td></tr>';
      h += '<tr><td class="num">' + s.i + '</td><td>' + s.bit + '</td><td>' + cv(s.sq) + '</td><td>' + (s.bit === '1' ? cv(s.x) : '—') + '</td></tr>';
      last = s.i;
    });
    T.raw(h + '</tbody></table></div>');
    var c = tr.r;
    if (m === 0n || m === 1n || m === k.n - 1n) T.line('bad', 'điểm bất động: c = m — vì sao SP 800-56B loại giá trị này', 'fixed point: c = m — why SP 800-56B excludes this value', cv(c));
    if (k.n % 2n === 1n) {
      var mc = R.montConst(k.n), mp = R.montPow(m, k.e, k.n);
      T.h('Cái một mạch Montgomery cần cho n này', 'What a Montgomery circuit needs for this n');
      T.line('info', 's = ' + mc.k + ' từ 32 bit, R = 2<sup>' + mc.kbits + '</sup>', 's = ' + mc.k + ' words of 32 bits, R = 2<sup>' + mc.kbits + '</sup>', '');
      T.line('info', 'n0′ = −n<sup>−1</sup> mod 2<sup>32</sup>', 'n0′ = −n<sup>−1</sup> mod 2<sup>32</sup>', '<code>0x' + R.bigToHex(mc.n0p, 4) + '</code>');
      T.line('info', 'R<sup>2</sup> mod n', 'R<sup>2</sup> mod n', cv(mc.R2));
      T.line(mp === c ? 'ok' : 'bad', 'tính lại c bằng chuỗi REDC trong miền Montgomery: cùng kết quả', 'c recomputed by a REDC chain in the Montgomery domain: same result', '');
    }
    encC.set(c);
    var fb = 0;
    if (exp) { T.h('So với tệp của NIST', "Compared with NIST's file"); if (!cmp(T, 'c', 'c', strip0(H(c)), strip0(exp.c), exp.src)) fb++; }
    T.done();
    if (exp) return fb ? X.bad(bi('c KHÁC đáp án ' + esc(exp.src) + '.', 'c DIFFERS from the ' + esc(exp.src) + ' answer.')) : X.ok(bi('c khớp đáp án ' + esc(exp.src) + ' (1/1).', 'c matches the ' + esc(exp.src) + ' answer (1/1).'));
    X.ok(bi('c = m<sup>e</sup> mod n: ' + tr.S + ' bình phương, ' + tr.M + ' phép nhân.', 'c = m<sup>e</sup> mod n: ' + tr.S + ' squarings, ' + tr.M + ' multiplications.'), nb(esc(short(c))));
  }
  function cmpRefusal(T, exp) {
    var ok = exp.c === undefined || exp.c === null;
    T.line(ok ? 'ok' : 'bad', 'tệp ' + exp.src + ' cũng đòi từ chối', 'the ' + exp.src + ' file also requires a refusal', '');
    return ok;
  }
  function encOaep(exp) {
    var X = EN, k, M, L, seed, T = new Trace(X.tr);
    try {
      k = keyGet(['n', 'e']);
      try { M = encMsg.value(); } catch (x) { throw Err('UI', { html: fieldErr(encMsg, x) }); }
      try { L = encL.value(); } catch (x) { throw Err('UI', { html: fieldErr(encL, x) }); }
      if ($('enc-seed-rnd').checked) encSeed.set(rnd(32));
      try { seed = encSeed.value(); } catch (x) { throw Err('UI', { html: fieldErr(encSeed, x) }); }
      if (seed.length !== 32) throw Err('UI', { html: bi('seed của OAEP phải dài đúng hLen = 32 byte.', 'The OAEP seed must be exactly hLen = 32 bytes.') });
    } catch (x) { X.tr.innerHTML = ''; encC.set(null); return X.bad(x.info ? x.info.html : esc(x.message)); }
    var kk = R.byteLen(k.n), o;
    T.h('RSAES-OAEP-ENCRYPT (RFC 8017, mục 7.1.1), Hash = MGF = SHA-256', 'RSAES-OAEP-ENCRYPT (RFC 8017, section 7.1.1), Hash = MGF = SHA-256');
    T.line(M.length <= kk - 66 ? 'ok' : 'bad', 'độ dài: mLen ≤ k − 2·hLen − 2', 'length: mLen ≤ k − 2·hLen − 2', nb(M.length + ' ≤ ' + kk + ' − 66 = ' + (kk - 66)));
    try { o = R.oaepEncrypt(k.n, k.e, M, L, seed); }
    catch (x) {
      encC.set(null);
      var refusedOk = exp && !exp.c;
      if (exp) cmpRefusal(T, exp);
      T.done();
      if (refusedOk) return X.ok(bi('Bị từ chối, đúng như mong đợi: ', 'Refused, as expected: ') + bi('khoá ' + kk + ' byte quá ngắn cho OAEP-SHA-256 (cần k ≥ 66).', 'a ' + kk + '-byte key is too short for OAEP-SHA-256 (k ≥ 66 needed).'));
      return X.bad(x.code === 'MSG_TOO_LONG' ? (kk < 66 ? bi('Khoá ' + kk + ' byte quá ngắn cho OAEP-SHA-256: cần k ≥ 2·32 + 2 = 66 byte.', 'A ' + kk + '-byte key is too short for OAEP-SHA-256: k ≥ 2·32 + 2 = 66 bytes is needed.')
        : bi('Thông điệp quá dài: tối đa ' + (kk - 66) + ' byte với khoá này.', 'Message too long: at most ' + (kk - 66) + ' bytes with this key.')) : esc(x.message));
    }
    T.line('info', 'lHash = SHA-256(L)', 'lHash = SHA-256(L)', cb(o.lHash, 70));
    T.line('info', 'DB = lHash ‖ PS (' + o.psLen + ' byte 0) ‖ 01 ‖ M', 'DB = lHash ‖ PS (' + o.psLen + ' zero bytes) ‖ 01 ‖ M', cb(o.DB));
    T.line('info', 'seed (hLen byte)', 'seed (hLen bytes)', cb(seed, 70));
    T.line('info', 'dbMask = MGF1(seed, k − hLen − 1)', 'dbMask = MGF1(seed, k − hLen − 1)', cb(o.dbMask));
    T.line('info', 'maskedDB = DB ⊕ dbMask', 'maskedDB = DB ⊕ dbMask', cb(o.maskedDB));
    T.line('info', 'seedMask = MGF1(maskedDB, hLen)', 'seedMask = MGF1(maskedDB, hLen)', cb(o.seedMask, 70));
    T.line('info', 'maskedSeed = seed ⊕ seedMask', 'maskedSeed = seed ⊕ seedMask', cb(o.maskedSeed, 70));
    T.line('info', 'EM = 00 ‖ maskedSeed ‖ maskedDB', 'EM = 00 ‖ maskedSeed ‖ maskedDB', cb(o.EM));
    T.line('info', 'c = RSAEP(OS2IP(EM))', 'c = RSAEP(OS2IP(EM))', cv(o.c));
    encC.set(o.c);
    var fb = 0;
    if (exp) { T.h('So với đáp án', 'Compared with the expected value'); if (!cmp(T, 'c', 'c', strip0(H(o.c)), strip0(exp.c || '—'), exp.src)) fb++; }
    T.done();
    if (exp) return fb ? X.bad(bi('c KHÁC đáp án ' + exp.src + '.', 'c DIFFERS from the ' + exp.src + ' answer.')) : X.ok(bi('c khớp đáp án ' + exp.src + ' (1/1).', 'c matches the ' + exp.src + ' answer (1/1).'));
    X.ok(bi('Đã mã hoá ' + M.length + ' byte bằng OAEP. Mã hoá lại với seed khác sẽ ra bản mã khác.', 'Encrypted ' + M.length + ' bytes with OAEP. Encrypting again with another seed gives another ciphertext.'));
  }
  function encGo(exp) { return checked('enc-mode') === 'oaep' ? encOaep(exp) : encRaw(exp); }
  $('enc-go').addEventListener('click', function () { encGo(); });
  function encEdge(f) {
    return function () {
      var k; try { k = keyGet(['n']); } catch (x) { return EN.bad(x.info.html); }
      setRadio('enc-mode', 'raw'); encMode(); encM.set(f(k.n)); encGo();
    };
  }
  $('enc-m0').addEventListener('click', encEdge(function () { return 0n; }));
  $('enc-m1').addEventListener('click', encEdge(function () { return 1n; }));
  $('enc-mn1').addEventListener('click', encEdge(function (n) { return n - 1n; }));
  $('enc-mn').addEventListener('click', encEdge(function (n) { return n; }));
  $('enc-mrnd').addEventListener('click', encEdge(function (n) { return R.os2ip(rnd(R.byteLen(n) + 8)) % (n - 3n) + 2n; }));
  $('enc-to-dec').addEventListener('click', function () {
    if (encC.empty()) return EN.bad(bi('Chưa có bản mã: bấm Mã hoá trước.', 'No ciphertext yet: press Encrypt first.'));
    decC.set(encC.value()); setRadio('dec-mode', checked('enc-mode')); decMode();
    if (checked('enc-mode') === 'oaep') { decL.fmt = encL.fmt; decL.mark(); decL.ta.value = encL.ta.value; decL.count(); }
    setRadio('dec-rule', checked('enc-rule') || 'sp56b');
    openTab('dec'); DE.clear();
  });
  function sizeFor(nl) { setRadio('rsa-size', nl); sizeNote(); }
  function decKey(r) {
    var o = { n: r.n, e: r.e, d: r.d, p: r.p, q: r.q };
    if (r.dmp1) { o.dP = r.dmp1; o.dQ = r.dmq1; o.qInv = r.iqmp; }
    return o;
  }
  Array.prototype.forEach.call(document.querySelectorAll('#panel-enc [data-ex]'), function (b) {
    b.addEventListener('click', function () {
      var ex = b.getAttribute('data-ex'), nl = nlen(), r;
      EN.clear();
      if (ex === 'cavs') {
        r = V.rsadp_cavs.filter(function (x) { return x.result === 'P' && x.mod === (nl === 2048 ? 2048 : 1024); })[0];
        sizeFor(r.mod); keySet({ n: r.n, e: r.e }); setRadio('enc-mode', 'raw'); encMode(); setRadio('enc-rule', 'sp56b');
        encM.fmt = 'hex'; encM.mark(); encM.set(B(r.k));
        return encRaw({ c: r.c, src: 'CAVS RSADPComponent800_56B mod = ' + r.mod + ' COUNT = ' + r.count });
      }
      if (ex === 'acvp') {
        r = V.decprim.filter(function (x) { return x.passed && x.mod === nl; })[0] || V.decprim[0];
        sizeFor(r.mod); keySet(decKey(r)); setRadio('enc-mode', 'raw'); encMode(); setRadio('enc-rule', 'sp56b');
        encM.fmt = 'hex'; encM.mark(); encM.set(B(r.pt));
        return encRaw({ c: r.ct, src: 'ACVP RSA-DecryptionPrimitive tcId ' + r.tcId });
      }
      r = V.oaep.filter(function (x) { return x.nlen === nl && x.case === 'hello'; })[0];
      var o = V.own[String(nl)];
      keySet({ n: o.n, e: o.e, d: o.d, p: o.p, q: o.q, dP: o.dP, dQ: o.dQ, qInv: o.qInv });
      setRadio('enc-mode', 'oaep'); encMode();
      encMsg.fmt = 'hex'; encMsg.mark(); encMsg.set(R.hexToBytes(r.M)); encL.fmt = 'hex'; encL.mark(); encL.set(R.hexToBytes(r.L));
      $('enc-seed-rnd').checked = false; encSeed.set(R.hexToBytes(r.seed));
      return encOaep({ c: r.c, src: 'OAEP chiusoc-rsa-' + nl });
    });
  });

  /* ================================================================ 3. giải mã */
  var DE = new Tab('dec-result', 'dec-trace', 'panel-dec');
  var decC = new IntField('dec-c', { name: ['c', 'c'] });
  var decR = new IntField('dec-r', { name: ['r', 'r'], onEdit: function () { $('dec-r-rnd').checked = false; } });
  var decM = new IntField('dec-m', { name: ['m', 'm'] });
  var decMM = new BytesField('dec-M', { name: ['M', 'M'], fmt: 'text' });
  var decL = new BytesField('dec-label', { name: ['L', 'L'], fmt: 'text' });
  function decMode() { var o = checked('dec-mode') === 'oaep'; $('dec-oaep').hidden = !o; $('dec-oaep-out').hidden = !o; }
  onRadio('dec-mode', function () { decMode(); DE.clear(); });
  function decRun(opts, exp) {
    var X = DE, k, c, rule = checked('dec-rule'), T = new Trace(X.tr), oaep = checked('dec-mode') === 'oaep', r = null, L = null;
    decM.set(null); decMM.set(null);
    try {
      k = keyGet(['n', 'e']);
      if (decC.empty()) throw Err('UI', { html: bi('Ô c đang trống.', 'The c field is empty.') });
      try { c = decC.value(); } catch (x) { throw Err('UI', { html: fieldErr(decC, x) }); }
      if (oaep) { try { L = decL.value(); } catch (x) { throw Err('UI', { html: fieldErr(decL, x) }); } }
    } catch (x) { X.tr.innerHTML = ''; return Promise.resolve(X.bad(x.info.html)); }
    T.h('Kiểm khoảng (RSADP, bước 1)', 'Range check (RSADP, step 1)');
    var inr = rangeLines(T, c, k.n, rule, 'c');
    if (!inr) {
      var why = bi('c nằm ngoài khoảng của quy tắc đang chọn: RSADP báo <code>ciphertext representative out of range</code> và dừng.', 'c is outside the selected rule\'s range: RSADP reports <code>ciphertext representative out of range</code> and stops.');
      if (exp) {
        var ok = exp.refuse;
        T.line(ok ? 'ok' : 'bad', ok ? 'tệp ' + exp.src + ' cũng đòi từ chối' : 'tệp ' + exp.src + ' lại có đáp án', ok ? 'the ' + exp.src + ' file also requires a refusal' : 'the ' + exp.src + ' file has an answer', '');
        T.done();
        return Promise.resolve(ok ? X.ok(bi('Bị từ chối, đúng như ' + exp.src + ' đòi.', 'Refused, as ' + exp.src + ' requires.'), why) : X.bad(bi('Bị từ chối nhưng ' + exp.src + ' có đáp án.', 'Refused, but ' + exp.src + ' has an answer.')));
      }
      T.done();
      return Promise.resolve(X.bad(why));
    }
    if (exp && exp.noKey) {                                          // CAVS RSADPComponent: tệp không có khoá riêng
      T.h('Tệp này không có khoá riêng', 'This file has no private key');
      var ke = R.modPow(B(exp.k), k.e, k.n), ok2 = ke === c;
      T.line('info', 'đáp án k của tệp', "the file's answer k", cv(B(exp.k)));
      T.line(ok2 ? 'ok' : 'bad', 'kiểm chiều ngược: k<sup>e</sup> mod n = c', 'check the other way: k<sup>e</sup> mod n = c', '');
      decM.set(B(exp.k)); T.done();
      return Promise.resolve(ok2 ? X.ok(bi('c nằm trong khoảng (<code>Result = Pass</code>) và k<sup>e</sup> mod n = c: khớp ' + exp.src + '.', 'c is in range (<code>Result = Pass</code>) and k<sup>e</sup> mod n = c: matches ' + exp.src + '.'))
        : X.bad(bi('k<sup>e</sup> mod n KHÁC c.', 'k<sup>e</sup> mod n DIFFERS from c.')));
    }
    if (k.d === undefined) { T.done(); return Promise.resolve(X.bad(bi('Khoá chưa có d: không giải mã được.', 'The key has no d: cannot decrypt.'))); }
    if (opts.fault !== undefined && !R.hasCrt(k)) { T.done(); return Promise.resolve(X.bad(bi('Tấn công Bellcore cần khoá dạng CRT (p, q, dP, dQ, qInv).', 'The Bellcore attack needs the CRT key (p, q, dP, dQ, qInv).'))); }
    if ($('dec-blind').checked && opts.fault === undefined) {
      if ($('dec-r-rnd').checked || decR.empty()) decR.set(R.os2ip(rnd(R.byteLen(k.n) + 8)) % (k.n - 3n) + 2n);
      try { r = decR.value(); } catch (x) { T.done(); return Promise.resolve(X.bad(fieldErr(decR, x))); }
      if (R.gcd(r, k.n) !== 1n) { T.done(); return Promise.resolve(X.bad(bi('r phải nguyên tố cùng nhau với n.', 'r must be coprime to n.'))); }
    }
    var tok = X.busy('Đang giải mã…', 'Decrypting…');
    return call('decrypt', [keyHex(k), H(c), { ladder: true, fault: opts.fault, r: r === null ? null : H(r) }]).then(function (res) {
      if (tok !== X.tok) return;
      X.done();
      var v = res.v, m = B(v.plain), crtOk = true, fb = 0;
      T.h('m = c<sup>d</sup> mod n (khoá dạng (n, d))', 'm = c<sup>d</sup> mod n (key as (n, d))');
      T.line('info', 'kết quả', 'result', cv(m));
      T.line('info', 'bình phương-và-nhân trên d: ' + v.dS + ' bình phương + ' + v.dM + ' phép nhân (số phép nhân lộ số bit 1 của d)', 'square-and-multiply on d: ' + v.dS + ' squarings + ' + v.dM + ' multiplications (the multiplications reveal how many 1 bits d has)', '');
      T.line(B(v.ladder) === m ? 'ok' : 'bad', 'thang Montgomery: luôn ' + v.ladderOps + ' phép (2 mỗi bit), cùng kết quả', 'Montgomery ladder: always ' + v.ladderOps + ' operations (2 per bit), same result', '');
      if (v.crt) {
        T.h('CRT theo Garner (RFC 8017, 5.1.2, bước 2.b)', 'CRT with Garner (RFC 8017, 5.1.2, step 2.b)');
        if (k.derived) T.line('info', 'dP, dQ, qInv được tính từ p, q, d (tệp không cho)', 'dP, dQ, qInv computed from p, q, d (not given by the file)', '');
        T.line('info', 'm1 = (c mod p)<sup>dP</sup> mod p', 'm1 = (c mod p)<sup>dP</sup> mod p', cv(B(v.crt.m1)));
        T.line('info', 'm2 = (c mod q)<sup>dQ</sup> mod q', 'm2 = (c mod q)<sup>dQ</sup> mod q', cv(B(v.crt.m2)));
        T.line('info', 'h = qInv·(m1 − m2) mod p', 'h = qInv·(m1 − m2) mod p', cv(B(v.crt.h)));
        crtOk = B(v.crt.m) === m;
        T.line(crtOk ? 'ok' : 'bad', 'm = m2 + q·h — trùng với cách (n, d)', 'm = m2 + q·h — equal to the (n, d) result', cv(B(v.crt.m)));
      }
      if (v.blind) {
        T.h('Làm mù thông điệp', 'Message blinding');
        T.line('info', 'r', 'r', cv(B(v.blind.r)));
        T.line('info', 'c′ = r<sup>e</sup>·c mod n — thứ mà phần cứng thật sự lũy thừa', 'c′ = r<sup>e</sup>·c mod n — what the hardware actually exponentiates', cv(B(v.blind.cb)));
        T.line('info', 'm′ = c′<sup>d</sup> mod n = m·r mod n', 'm′ = c′<sup>d</sup> mod n = m·r mod n', cv(B(v.blind.mb)));
        T.line(B(v.blind.m) === m ? 'ok' : 'bad', 'm = m′·r<sup>−1</sup> mod n — cùng kết quả', 'm = m′·r<sup>−1</sup> mod n — same result', cv(B(v.blind.m)));
      }
      var faultHtml = null, faultOk = true;
      if (v.fault) {
        T.h('Tiêm lỗi vào nửa mod p của CRT (Bellcore)', 'Fault injected into the mod-p half of CRT (Bellcore)');
        T.line('info', 'm1′ = m1 ⊕ 2<sup>' + opts.fault + '</sup>', 'm1′ = m1 ⊕ 2<sup>' + opts.fault + '</sup>', cv(B(v.fault.m1f)));
        T.line('info', 'h′ = qInv·(m1′ − m2) mod p', 'h′ = qInv·(m1′ − m2) mod p', cv(B(v.fault.h)));
        T.line('bad', 'm′ = m2 + q·h′ — sai', 'm′ = m2 + q·h′ — wrong', cv(B(v.fault.m)));
        var g = B(v.fault.gcd), isQ = g === k.q;
        if ($('dec-verify').checked) {
          T.line(v.fault.detected ? 'ok' : 'bad', 'kiểm trước khi trả: m′<sup>e</sup> mod n ≠ c → không xuất kết quả', 'verify before release: m′<sup>e</sup> mod n ≠ c → no output', '');
          faultOk = v.fault.detected;
          faultHtml = faultOk ? ['ok', bi('Lỗi bị phát hiện, kết quả sai không ra khỏi bộ máy: kẻ tấn công không có gì để tính gcd.', 'The fault was detected and the wrong result never left the engine: the attacker has nothing to take a gcd of.')]
            : ['bad', bi('Biện pháp chống không phát hiện được lỗi.', 'The countermeasure missed the fault.')];
        } else {
          T.line(isQ ? 'bad' : 'info', 'kẻ tấn công tính gcd(m′<sup>e</sup> − c, n)' + (isQ ? ' = q: khoá bị lộ' : ''), 'the attacker computes gcd(m′<sup>e</sup> − c, n)' + (isQ ? ' = q: the key is exposed' : ''), cv(g));
          if (isQ) T.line('bad', 'và p = n / q', 'and p = n / q', cv(k.n / g));
          decM.set(B(v.fault.m));
          faultHtml = isQ ? ['bad', bi('Một lần chạy hỏng đã làm lộ khoá: gcd(m′<sup>e</sup> − c, n) = q. Bật "kiểm trước khi trả kết quả" rồi thử lại.', 'One faulty run exposed the key: gcd(m′<sup>e</sup> − c, n) = q. Tick "verify before release" and try again.')]
            : ['bad', bi('gcd không ra q — lỗi này không làm lộ khoá.', 'The gcd is not q — this fault did not expose the key.')];
        }
      }
      var oaepRes = null;
      if (oaep && !v.fault) {
        var od = R.oaepDecrypt(k, c, L);
        T.h('RSAES-OAEP-DECRYPT (RFC 8017, mục 7.1.2)', 'RSAES-OAEP-DECRYPT (RFC 8017, section 7.1.2)');
        if (od.reason === 'K_SMALL') T.line('bad', 'k &lt; 2·hLen + 2', 'k &lt; 2·hLen + 2', nb(od.k + ' &lt; 66'));
        else {
          T.line(od.Y === 0 ? 'ok' : 'bad', 'EM = Y ‖ maskedSeed ‖ maskedDB, Y = 0', 'EM = Y ‖ maskedSeed ‖ maskedDB, Y = 0', cb(od.EM));
          T.line('info', 'seed = maskedSeed ⊕ MGF1(maskedDB, hLen)', 'seed = maskedSeed ⊕ MGF1(maskedDB, hLen)', cb(od.seed, 70));
          T.line('info', 'DB = maskedDB ⊕ MGF1(seed, k − hLen − 1)', 'DB = maskedDB ⊕ MGF1(seed, k − hLen − 1)', cb(od.DB));
          if (od.Y === 0) T.line(od.reason !== 'LHASH' ? 'ok' : 'bad', 'lHash′ (đầu DB) = SHA-256(L)', "lHash′ (start of DB) = SHA-256(L)", cb(od.lHash2, 70));
          if (od.ok) T.line('ok', 'PS gồm ' + od.psLen + ' byte 0, rồi byte 01, rồi M', 'PS is ' + od.psLen + ' zero bytes, then 01, then M', cb(od.M));
          else if (od.reason === 'SEPARATOR') T.line('bad', 'không có byte 01 sau PS', 'no 01 byte after PS', '');
        }
        if (od.ok) decMM.set(od.M);
        oaepRes = od;
        if (!od.ok) T.line('info', 'Một bộ giải mã thật phải trả cùng một lỗi <code>decryption error</code> cho cả ba trường hợp và trong cùng thời gian: nếu phân biệt được (như ở đây), tấn công của Manger (2001) lấy lại bản rõ.',
          'A real decryptor must return the same <code>decryption error</code> for all three cases, in the same time: if they can be told apart (as here), Manger\'s attack (2001) recovers the plaintext.', '');
      }
      if (!v.fault) decM.set(m);
      if (exp) {
        T.h('So với tệp của NIST', "Compared with NIST's file");
        if (exp.refuse) { T.line('bad', 'tệp đòi từ chối nhưng phép giải mã đã chạy', 'the file requires a refusal but the decryption ran', ''); fb++; }
        else if (!cmp(T, 'pt', 'pt', strip0(H(m)), strip0(exp.pt), exp.src)) fb++;
        if (v.crt && exp.m1 && !cmp(T, 'm1', 'm1', strip0(v.crt.m1), strip0(exp.m1), exp.src)) fb++;
      }
      T.done();
      var t = nb((res.t / 1000).toFixed(2) + ' s');
      if (faultHtml) return faultHtml[0] === 'ok' ? X.ok(faultHtml[1], t) : X.bad(faultHtml[1], t);
      if (exp) return fb ? X.bad(bi('KHÁC đáp án ' + exp.src + ' ở ' + fb + ' giá trị.', 'DIFFERS from the ' + exp.src + ' answer at ' + fb + ' values.'), t)
        : X.ok(bi('Khớp đáp án ' + exp.src + '.', 'Matches the ' + exp.src + ' answer.'), t);
      if (oaepRes && !oaepRes.ok) return X.bad(bi('Giải mã OAEP thất bại: ', 'OAEP decryption failed: ') + reasonHtml(oaepRes), t);
      if (!crtOk) return X.bad(bi('CRT và (n, d) cho hai kết quả khác nhau: khoá không nhất quán.', 'CRT and (n, d) disagree: the key is inconsistent.'), t);
      X.ok(oaepRes ? bi('Đã giải mã OAEP: ' + oaepRes.M.length + ' byte.', 'OAEP decrypted: ' + oaepRes.M.length + ' bytes.') : bi('m = c<sup>d</sup> mod n; mọi cách tính cho cùng kết quả.', 'm = c<sup>d</sup> mod n; every method gives the same result.'), t);
    }, function (x) { if (tok !== X.tok) return; X.done(); uiFail(X, x); });
  }
  $('dec-go').addEventListener('click', function () { decRun({}); });
  $('dec-fault').addEventListener('click', function () {
    var b = Math.max(0, Math.min(8191, parseInt($('dec-bit').value, 10) || 0));
    $('dec-bit').value = String(b);
    setRadio('dec-mode', 'raw'); decMode();
    decRun({ fault: b });
  });
  Array.prototype.forEach.call(document.querySelectorAll('#panel-dec [data-ex]'), function (b) {
    b.addEventListener('click', function () {
      var ex = b.getAttribute('data-ex'), r;
      DE.clear(); setRadio('dec-mode', 'raw'); decMode(); setRadio('dec-rule', 'sp56b'); $('dec-blind').checked = false;
      if (ex.indexOf('cavs') === 0) {
        var cnt = +ex.slice(4);
        r = V.rsadp_cavs.filter(function (x) { return x.mod === 1024 && x.count === cnt; })[0];
        sizeFor(r.mod); keySet({ n: r.n, e: r.e }); decC.fmt = 'hex'; decC.mark(); decC.set(B(r.c));
        return decRun({}, r.result === 'P' ? { noKey: true, k: r.k, src: 'CAVS RSADPComponent800_56B COUNT = ' + r.count }
          : { refuse: true, src: 'CAVS RSADPComponent800_56B COUNT = ' + r.count });
      }
      var id = +ex.slice(4);
      r = V.decprim.filter(function (x) { return x.tcId === id; })[0];
      sizeFor(r.mod); keySet(decKey(r)); decC.fmt = 'hex'; decC.mark(); decC.set(B(r.ct));
      return decRun({}, { refuse: !r.passed, pt: r.pt, m1: r.m1, src: 'ACVP RSA-DecryptionPrimitive tcId ' + r.tcId });
    });
  });

  /* ================================================================ 4. ký / xác minh */
  var SG = new Tab('sig-result', 'sig-trace', 'panel-sig');
  var sigMsg = new BytesField('sig-msg', { name: ['M', 'M'], fmt: 'text' });
  var sigEm = new IntField('sig-em', { name: ['m', 'm'] });
  var sigSalt = new BytesField('sig-salt', { name: ['salt', 'salt'], text: false, need: function () { return sLen(); }, onEdit: function () { $('sig-salt-rnd').checked = false; } });
  var sigS = new BytesField('sig-S', { name: ['S', 'S'], text: false, need: function () { var n = KF.n.peek(); return n ? R.byteLen(n) : null; } });
  function sLen() { var v = parseInt($('sig-slen').value, 10); return isNaN(v) || v < 0 ? 0 : Math.min(v, 1024); }
  function sigMode() {
    var s = checked('sig-scheme');
    $('sig-msgwrap').hidden = s === 'prim'; $('sig-primwrap').hidden = s !== 'prim'; $('sig-pss').hidden = s !== 'pss';
    radios('sig-hash').forEach(function (r) { r.disabled = s === 'prim'; });
  }
  onRadio('sig-scheme', function () { sigMode(); SG.clear(); });
  onRadio('sig-hash', function () { SG.clear(); });
  $('sig-slen').addEventListener('input', function () { sigSalt.count(); });
  function sigSign(exp) {
    var X = SG, k, s = checked('sig-scheme'), hid = checked('sig-hash'), T = new Trace(X.tr), o, M;
    try {
      k = keyGet(['n', 'e', 'd']);
      if (s !== 'prim') { try { M = sigMsg.value(); } catch (x) { throw Err('UI', { html: fieldErr(sigMsg, x) }); } }
    } catch (x) { X.tr.innerHTML = ''; return X.bad(x.info.html); }
    var kk = R.byteLen(k.n), crt = R.hasCrt(k);
    try {
      if (s === 'prim') {
        var m;
        try { m = sigEm.value(); } catch (x) { throw Err('UI', { html: fieldErr(sigEm, x) }); }
        T.h('RSASP1 (RFC 8017, mục 5.2.1)', 'RSASP1 (RFC 8017, section 5.2.1)');
        T.line(m < k.n ? 'ok' : 'bad', '0 ≤ m &lt; n', '0 ≤ m &lt; n', cv(m));
        var sv = R.rsasp1(k, m);
        T.line('info', 's = m<sup>d</sup> mod n' + (crt ? ' (theo CRT)' : ''), 's = m<sup>d</sup> mod n' + (crt ? ' (by CRT)' : ''), cv(sv));
        o = { S: R.i2osp(sv, kk), s: sv };
      } else if (s === 'v15') {
        T.h('RSASSA-PKCS1-v1_5-SIGN (RFC 8017, mục 8.2.1; EMSA-PKCS1-v1_5, mục 9.2)', 'RSASSA-PKCS1-v1_5-SIGN (RFC 8017, section 8.2.1; EMSA-PKCS1-v1_5, section 9.2)');
        o = R.signPkcs1(k, hid, M);
        T.line('info', 'H = ' + hlabel(hid) + '(M)', 'H = ' + hlabel(hid) + '(M)', cb(R.hash(hid, M), 140));
        T.line('info', 'T = DigestInfo = tiền tố DER (tính từ OID) ‖ H', 'T = DigestInfo = DER prefix (computed from the OID) ‖ H', cb(o.T, 140));
        T.line('info', 'EM = 00 01 ‖ PS (' + (o.EM.length - o.T.length - 3) + ' byte FF) ‖ 00 ‖ T', 'EM = 00 01 ‖ PS (' + (o.EM.length - o.T.length - 3) + ' FF bytes) ‖ 00 ‖ T', cb(o.EM));
        T.line('info', 's = OS2IP(EM)<sup>d</sup> mod n' + (crt ? ' (theo CRT)' : ''), 's = OS2IP(EM)<sup>d</sup> mod n' + (crt ? ' (by CRT)' : ''), cv(o.s));
      } else {
        var sl = sLen(), salt;
        if ($('sig-salt-rnd').checked) sigSalt.set(rnd(sl));
        try { salt = sigSalt.empty() ? new Uint8Array(0) : sigSalt.value(); } catch (x) { throw Err('UI', { html: fieldErr(sigSalt, x) }); }
        if (salt.length !== sl) throw Err('UI', { html: bi('salt dài ' + salt.length + ' byte nhưng sLen = ' + sl + '.', 'The salt is ' + salt.length + ' bytes but sLen = ' + sl + '.') });
        T.h('RSASSA-PSS-SIGN (RFC 8017, mục 8.1.1; EMSA-PSS, mục 9.1.1), MGF1 với ' + hlabel(hid), 'RSASSA-PSS-SIGN (RFC 8017, section 8.1.1; EMSA-PSS, section 9.1.1), MGF1 with ' + hlabel(hid));
        T.line(sl <= R.hinfo(hid).len ? 'ok' : 'bad', '0 ≤ sLen ≤ hLen (FIPS 186-5, 5.4(g))', '0 ≤ sLen ≤ hLen (FIPS 186-5, 5.4(g))', nb(sl + ' ≤ ' + R.hinfo(hid).len));
        o = R.signPss(k, hid, M, salt);
        T.line('info', 'mHash = ' + hlabel(hid) + '(M)', 'mHash = ' + hlabel(hid) + '(M)', cb(o.mHash, 140));
        T.line('info', 'M′ = 00×8 ‖ mHash ‖ salt', 'M′ = 00×8 ‖ mHash ‖ salt', cb(o.Mp, 80));
        T.line('info', 'H = ' + hlabel(hid) + '(M′)', 'H = ' + hlabel(hid) + '(M′)', cb(o.H, 140));
        T.line('info', 'DB = PS (byte 0) ‖ 01 ‖ salt', 'DB = PS (zero bytes) ‖ 01 ‖ salt', cb(o.DB));
        T.line('info', 'maskedDB = DB ⊕ MGF1(H), xoá các bit đầu', 'maskedDB = DB ⊕ MGF1(H), top bits cleared', cb(o.maskedDB));
        T.line('info', 'EM = maskedDB ‖ H ‖ bc', 'EM = maskedDB ‖ H ‖ bc', cb(o.EM));
        T.line('info', 's = OS2IP(EM)<sup>d</sup> mod n' + (crt ? ' (theo CRT)' : ''), 's = OS2IP(EM)<sup>d</sup> mod n' + (crt ? ' (by CRT)' : ''), cv(o.s));
      }
    } catch (x) {
      sigS.set(null);
      var refused = exp && exp.refuse;
      if (exp) T.line(refused ? 'ok' : 'bad', refused ? 'tệp ' + exp.src + ' cũng đòi từ chối' : 'tệp ' + exp.src + ' lại có đáp án', refused ? 'the ' + exp.src + ' file also requires a refusal' : 'the ' + exp.src + ' file has an answer', '');
      T.done();
      if (x.code === 'UI') return X.bad(x.info.html);
      var why = x.code === 'RANGE' ? bi('m ≥ n: RSASP1 báo <code>message representative out of range</code>.', 'm ≥ n: RSASP1 reports <code>message representative out of range</code>.')
        : (x.code === 'EM_TOO_SHORT' ? bi('Khoá ' + kk + ' byte quá ngắn cho ' + hlabel(hid) + ' với cách đệm này.', 'A ' + kk + '-byte key is too short for ' + hlabel(hid) + ' with this encoding.')
          : (x.code === 'SLEN' ? reasonHtml({ reason: 'SLEN' }) : esc(x.message)));
      return refused ? X.ok(bi('Bị từ chối, đúng như ' + exp.src + ' đòi.', 'Refused, as ' + exp.src + ' requires.'), why) : X.bad(why);
    }
    sigS.set(o.S);
    T.line('info', 'S = I2OSP(s, k)', 'S = I2OSP(s, k)', cb(o.S));
    var fb = 0;
    if (exp) { T.h('So với tệp của NIST', "Compared with NIST's file"); if (!cmp(T, 'S', 'S', strip0(hexOf(o.S)), strip0(exp.S || '—'), exp.src)) fb++; }
    T.done();
    if (exp) return fb ? X.bad(bi('S KHÁC đáp án ' + exp.src + '.', 'S DIFFERS from the ' + exp.src + ' answer.')) : X.ok(bi('S khớp đáp án ' + exp.src + ' (1/1).', 'S matches the ' + exp.src + ' answer (1/1).'));
    X.ok(bi('Đã ký: ' + kk + ' byte.', 'Signed: ' + kk + ' bytes.'), s === 'pss' ? bi('Ký lại với salt khác sẽ ra chữ ký khác; PKCS#1 v1.5 thì luôn ra cùng một chữ ký.', 'Signing again with another salt gives another signature; PKCS#1 v1.5 always gives the same one.') : '');
  }
  function verifyOne(k, s, hid, M, S, sl, emInt) {
    if (s === 'prim') {
      var sv = R.os2ip(S);
      if (sv >= k.n) return { ok: false, reason: 'SIG_RANGE' };
      var m = R.modPow(sv, k.e, k.n);
      return { ok: emInt === undefined || emInt === null ? true : m === emInt, reason: emInt === undefined || emInt === null || m === emInt ? 'OK' : 'DIGEST', m: m };
    }
    return s === 'pss' ? R.verifyPss(k.n, k.e, hid, M, S, sl) : R.verifyPkcs1(k.n, k.e, hid, M, S);
  }
  function sigVerify(exp) {
    var X = SG, k, s = checked('sig-scheme'), hid = checked('sig-hash'), T = new Trace(X.tr), M = null, S, emInt = null;
    try {
      k = keyGet(['n', 'e']);
      if (s !== 'prim') { try { M = sigMsg.value(); } catch (x) { throw Err('UI', { html: fieldErr(sigMsg, x) }); } }
      else if (!sigEm.empty()) { try { emInt = sigEm.value(); } catch (x) { throw Err('UI', { html: fieldErr(sigEm, x) }); } }
      if (sigS.empty()) throw Err('UI', { html: bi('Ô chữ ký đang trống.', 'The signature field is empty.') });
      try { S = sigS.value(); } catch (x) { throw Err('UI', { html: fieldErr(sigS, x) }); }
    } catch (x) { X.tr.innerHTML = ''; return X.bad(x.info.html); }
    var kk = R.byteLen(k.n), v = verifyOne(k, s, hid, M, S, sLen(), emInt);
    T.h(s === 'pss' ? 'RSASSA-PSS-VERIFY (RFC 8017, mục 8.1.2)' : (s === 'v15' ? 'RSASSA-PKCS1-v1_5-VERIFY (RFC 8017, mục 8.2.2)' : 'RSAVP1 (RFC 8017, mục 5.2.2)'),
      s === 'pss' ? 'RSASSA-PSS-VERIFY (RFC 8017, section 8.1.2)' : (s === 'v15' ? 'RSASSA-PKCS1-v1_5-VERIFY (RFC 8017, section 8.2.2)' : 'RSAVP1 (RFC 8017, section 5.2.2)'));
    T.line(S.length === kk ? 'ok' : 'bad', 'độ dài S = k', 'length of S = k', nb(S.length + ' / ' + kk + ' B'));
    if (v.reason !== 'SIG_LEN') T.line(v.reason !== 'SIG_RANGE' ? 'ok' : 'bad', 's = OS2IP(S) &lt; n', 's = OS2IP(S) &lt; n', '');
    if (v.EM) T.line('info', 'EM = I2OSP(s<sup>e</sup> mod n)', 'EM = I2OSP(s<sup>e</sup> mod n)', cb(v.EM));
    if (v.EMp) T.line(v.ok ? 'ok' : 'bad', "EM′ dựng lại từ M bằng " + hlabel(hid) + (v.ok ? ' — trùng EM' : ' — khác EM'), 'EM′ rebuilt from M with ' + hlabel(hid) + (v.ok ? ' — equals EM' : ' — differs from EM'), cb(v.EMp));
    if (v.salt) T.line('info', 'salt lấy lại từ DB', 'salt recovered from DB', cb(v.salt, 140));
    if (v.H2) T.line(v.ok ? 'ok' : 'bad', "H′ = Hash(00×8 ‖ mHash ‖ salt) so với H", "H′ = Hash(00×8 ‖ mHash ‖ salt) against H", cb(v.H2, 140));
    if (v.m !== undefined) T.line(v.ok ? 'ok' : 'bad', 'm = s<sup>e</sup> mod n' + (emInt !== null ? (v.ok ? ' = m của ô' : ' ≠ m của ô') : ''), 'm = s<sup>e</sup> mod n' + (emInt !== null ? (v.ok ? ' = the m field' : ' ≠ the m field') : ''), cv(v.m));
    T.line(v.ok ? 'ok' : 'bad', 'kết luận', 'verdict', reasonHtml(v.reason === 'HASH_ALG' ? v : { reason: v.reason }));
    var fb = 0;
    if (exp) {
      T.h('So với tệp của NIST', "Compared with NIST's file");
      var want = exp.passed ? 'OK' : 'F';
      var got = v.ok ? 'OK' : 'F';
      if (!cmp(T, 'kết luận', 'verdict', got === 'OK' ? 'P' : 'F', want === 'OK' ? 'P' : 'F', exp.src)) fb++;
      if (exp.salt !== undefined && !cmp(T, 'salt', 'salt', v.salt ? hexOf(v.salt) : '', exp.salt, exp.src)) fb++;
    }
    T.done();
    if (exp) return fb ? X.bad(bi('KHÁC đáp án ' + exp.src + '.', 'DIFFERS from the ' + exp.src + ' answer.')) : X.ok(bi('Khớp đáp án ' + exp.src + ': ', 'Matches the ' + exp.src + ' answer: ') + reasonHtml(v));
    return v.ok ? X.ok(bi('Chữ ký hợp lệ.', 'The signature is valid.')) : X.bad(bi('Chữ ký KHÔNG hợp lệ: ', 'The signature is NOT valid: ') + reasonHtml(v));
  }
  $('sig-sign').addEventListener('click', function () { sigSign(); });
  $('sig-verify').addEventListener('click', function () { sigVerify(); });
  $('sig-flip').addEventListener('click', function () {
    var S = sigS.peek();
    if (!S || !S.length) return SG.bad(bi('Chưa có chữ ký để lật bit.', 'There is no signature to flip a bit of.'));
    S = S.slice(); S[S.length - 1] ^= 1; sigS.set(S);
    sigVerify();
  });
  /* chạy nhiều ca của một tệp và lập bảng: phán quyết của phòng thí nghiệm + lý do, so với P / F của NIST */
  function sigBatch(rows, src, kind) {
    var X = SG, T = new Trace(X.tr), good = 0;
    var h = '<div class="tbl-wrap"><table><thead><tr><th>#</th><th>NIST</th><th>' + bi('lý do của NIST', "NIST's reason") + '</th><th>' + bi('phòng thí nghiệm', 'the lab') + '</th><th></th></tr></thead><tbody>';
    rows.forEach(function (r, i) {
      var k = { n: B(r.n), e: B(r.e) }, v = verifyOne(k, r.sigType === 'pss' ? 'pss' : 'v15', r.hash, R.hexToBytes(evenHex(r.message || r.msg)), R.hexToBytes(evenHex(r.signature || r.S)), r.saltLen || 0);
      var want = r.passed !== undefined ? r.passed : r.result === 'P', ok = v.ok === want;
      if (ok) good++;
      h += '<tr><td class="num">' + (r.tcId || i) + '</td><td>' + (want ? 'P' : 'F') + '</td><td>' + (r.nist_reason ? '<code>' + esc(r.nist_reason) + '</code>' : '—') + '</td><td>' +
        (v.ok ? '✓ ' : '✕ ') + reasonHtml(v) + '</td><td>' + (ok ? '✓' : '✕') + '</td></tr>';
    });
    T.h(src + ': ' + rows.length + ' ca', src + ': ' + rows.length + ' cases');
    T.raw(h + '</tbody></table></div>');
    T.done();
    var last = rows[rows.length - 1];
    keySet({ n: last.n, e: last.e }); setRadio('sig-scheme', kind); sigMode(); setRadio('sig-hash', last.hash);
    sigMsg.fmt = 'hex'; sigMsg.mark(); sigMsg.set(R.hexToBytes(evenHex(last.message || last.msg))); sigS.set(R.hexToBytes(evenHex(last.signature || last.S)));
    if (kind === 'pss') $('sig-slen').value = String(last.saltLen);
    return good === rows.length ? X.ok(bi(good + '/' + rows.length + ' phán quyết khớp ' + src + '.', good + '/' + rows.length + ' verdicts match ' + src + '.'), bi('Ca cuối được nạp vào các ô để bạn thử tiếp.', 'The last case is loaded into the fields so you can keep trying.'))
      : X.bad(bi('Chỉ ' + good + '/' + rows.length + ' phán quyết khớp ' + src + '.', 'Only ' + good + '/' + rows.length + ' verdicts match ' + src + '.'));
  }
  Array.prototype.forEach.call(document.querySelectorAll('#panel-sig [data-ex]'), function (b) {
    b.addEventListener('click', function () {
      var ex = b.getAttribute('data-ex'), r;
      SG.clear();
      if (ex === 'siggen15' || ex === 'siggen15b') {
        r = V.siggen15[ex === 'siggen15' ? 0 : 1];
        sizeFor(r.mod); keySet({ n: r.n, e: r.e }); setRadio('sig-scheme', 'v15'); sigMode(); setRadio('sig-hash', r.hash);
        sigMsg.fmt = 'hex'; sigMsg.mark(); sigMsg.set(R.hexToBytes(r.msg)); sigS.set(R.hexToBytes(r.S));
        return sigVerify({ passed: true, src: 'CAVS SigGen15_186-3 mod = ' + r.mod + ' ' + hlabel(r.hash) });
      }
      if (ex === 'sigver15') { sizeFor(1024); return sigBatch(V.sigver15, 'CAVS SigVer15_186-3 mod = 1024 SHA-256', 'v15'); }
      if (ex === 'sigver-v15' || ex === 'sigver-pss') {
        var tg = ex === 'sigver-v15' ? 1 : 25, rows = V.sigver.filter(function (x) { return x.tgId === tg; });
        sizeFor(rows[0].mod);
        return sigBatch(rows, 'ACVP RSA-SigVer-FIPS186-5 tgId ' + tg, ex === 'sigver-v15' ? 'v15' : 'pss');
      }
      if (ex.indexOf('rsasp1') === 0) {
        r = V.rsasp1.filter(function (x) { return x.count === +ex.slice(7); })[0];
        sizeFor(2048); keySet({ n: r.n, e: r.e, d: r.d, p: r.p, q: r.q }); setRadio('sig-scheme', 'prim'); sigMode();
        sigEm.fmt = 'hex'; sigEm.mark(); sigEm.set(B(r.EM));
        return sigSign(r.fail ? { refuse: true, src: 'CAVS RSASP1.fax COUNT = ' + r.count } : { S: R.bigToHex(B(r.S), 256), src: 'CAVS RSASP1.fax COUNT = ' + r.count });
      }
      if (ex === 'sigprim7') {
        r = V.sigprim.filter(function (x) { return x.tcId === 7; })[0];
        sizeFor(r.mod); keySet(decKey(r)); setRadio('sig-scheme', 'prim'); sigMode();
        sigEm.fmt = 'hex'; sigEm.mark(); sigEm.set(B(r.message));
        return sigSign({ refuse: !r.passed, S: r.signature, src: 'ACVP RSA-SignaturePrimitive tcId 7' });
      }
      r = V.siggen[{ 'siggen-v15': 0, 'siggen-sha3': 1, 'siggen-pss': 2 }[ex]];
      sizeFor(r.mod); keySet({ n: r.n, e: r.e }); setRadio('sig-scheme', r.sigType === 'pss' ? 'pss' : 'v15'); sigMode(); setRadio('sig-hash', r.hash);
      if (r.sigType === 'pss') $('sig-slen').value = String(r.saltLen);
      sigMsg.fmt = 'hex'; sigMsg.mark(); sigMsg.set(R.hexToBytes(r.message)); sigS.set(R.hexToBytes(r.signature));
      return sigVerify({ passed: true, salt: r.sigType === 'pss' ? r.salt : undefined, src: 'ACVP RSA-SigGen-FIPS186-5 tgId ' + r.tgId + ' tcId ' + r.tcId });
    });
  });

  /* ================================================================ tự kiểm chứng */
  function tick() { return new Promise(function (r) { setTimeout(r, 0); }); }
  $('bt-selftest').addEventListener('click', async function () {
    var st = $('st-status'), det = $('st-detail'), btn = $('bt-selftest'), lines = [], pass = 0, total = 0, g = null, groups = [];
    pending++;                                                        // idle() waits for the self-test too
    st.className = 'pill wait'; st.innerHTML = bi('đang chạy…', 'running…');
    det.hidden = false; det.textContent = ''; btn.disabled = true;
    await tick();
    function group(vi, en) { g = { vi: vi, en: en, pass: 0, total: 0 }; groups.push(g); }
    function chk(label, got, want) {
      total++; g.total++;
      if (got === want) { pass++; g.pass++; } else lines.push('FAIL ' + label + '\n  got  ' + got + '\n  want ' + want);
    }
    function flush() {
      det.innerHTML = groups.map(function (x) { return bi(x.vi, x.en) + nb(': ' + x.pass + '/' + x.total); }).join('\n') +
        (lines.length ? '\n\n' + nb(esc(lines.join('\n'))) : '');
    }
    var v, i, k;
    try {
      group('Bảng B.1 tính lại từ công thức của Phụ lục C.1', 'Table B.1 recomputed from the Appendix C.1 formula');
      Object.keys(V.tables.b1).forEach(function (key) { var a = key.split('/'); chk('C.1 ' + key, R.c1Rounds(+a[0], -a[1]), V.tables.b1[key][1]); });
      [512, 1024, 2048, 3072, 4096].forEach(function (nl) { chk('rounds ' + nl, R.mrRounds(nl).t, V.tables.rounds[String(nl)]); chk('ES ' + nl, R.strength(nl).ES, V.tables.strength[String(nl)][1]); });
      flush(); await tick();
      group('Ví dụ p = 61, q = 53, e = 17', 'Example p = 61, q = 53, e = 17');
      var tb = V.textbook, tk = R.fromPQ(61n, 53n, 17n);
      chk('textbook n', Number(tk.n), tb.n); chk('textbook d', Number(tk.d), tb.d); chk('textbook c', Number(R.modPow(65n, 17n, tk.n)), tb.c);
      chk('textbook CRT m', Number(R.crt(tk, BigInt(tb.c)).m), tb.crt_m); chk('textbook fault gcd', Number(R.bellcore(tk.n, 17n, BigInt(tb.c), R.crt(tk, BigInt(tb.c), 0).m)), tb.fault_gcd);
      flush(); await tick();
      group('Khoá mẫu 512 và 1024 bit sinh lại từ seed', 'Example keys of 512 and 1024 bits regenerated from their seeds');
      for (i = 0; i < 2; i++) {
        var nl = [512, 1024][i], o = V.own[String(nl)];
        k = R.keygen(nl, B(o.e), R.hexToBytes(o.seed));
        ['p', 'q', 'n', 'd'].forEach(function (f) { chk('own ' + nl + ' ' + f, H(k[f]), strip0(o[f])); });
        flush(); await tick();
      }
      group('Khoá mẫu 2048 / 3072 / 4096 bit: n, d, dP, dQ, qInv từ p, q, e', 'Example keys of 2048 / 3072 / 4096 bits: n, d, dP, dQ, qInv from p, q, e');
      [2048, 3072, 4096].forEach(function (nl) {
        var o = V.own[String(nl)], f = R.fromPQ(B(o.p), B(o.q), B(o.e));
        ['n', 'd', 'dP', 'dQ', 'qInv'].forEach(function (x) { chk('own ' + nl + ' ' + x, H(f[x]), strip0(o[x])); });
      });
      flush(); await tick();
      group('ACVP RSA-KeyGen-FIPS186-5', 'ACVP RSA-KeyGen-FIPS186-5');
      V.keygen_acvp.forEach(function (c) {
        var f = R.fromPQ(B(c.p), B(c.q), B(c.e));
        [['n', 'n'], ['dP', 'dmp1'], ['dQ', 'dmq1'], ['qInv', 'iqmp']].forEach(function (x) { chk('KeyGen tcId ' + c.tcId + ' ' + x[1], H(f[x[0]]), strip0(c.file[x[1]])); });
      });
      flush(); await tick();
      group('CAVS RSADPComponent800_56B và ACVP RSA-DecryptionPrimitive', 'CAVS RSADPComponent800_56B and ACVP RSA-DecryptionPrimitive');
      V.rsadp_cavs.forEach(function (r) {
        chk('CAVS RSADP COUNT ' + r.count + ' verdict', R.inRange(B(r.c), B(r.n), 'sp56b') ? 'P' : 'F', r.result);
        if (r.k) chk('CAVS RSADP COUNT ' + r.count + ' k^e', H(R.modPow(B(r.k), B(r.e), B(r.n))), strip0(r.c));
      });
      for (i = 0; i < V.decprim.length; i++) {
        var r = V.decprim[i], kk = { n: B(r.n), e: B(r.e), d: B(r.d), p: B(r.p), q: B(r.q) }, got;
        if (r.dmp1) { kk.dP = B(r.dmp1); kk.dQ = B(r.dmq1); kk.qInv = B(r.iqmp); }
        try { got = H(R.rsadp(kk, B(r.ct), 'sp56b')); } catch (x) { got = 'refused'; }
        chk('ACVP DecryptionPrimitive tcId ' + r.tcId + ' pt', got, r.passed ? strip0(r.pt) : 'refused');
        flush(); await tick();
      }
      group('OAEP với seed cố định (mô hình độc lập)', 'OAEP with a fixed seed (independent model)');
      V.oaep.forEach(function (r) {
        var o = V.own[String(r.nlen)], kk = { n: B(o.n), e: B(o.e), d: B(o.d), p: B(o.p), q: B(o.q), dP: B(o.dP), dQ: B(o.dQ), qInv: B(o.qInv) }, got;
        try { got = H(R.oaepEncrypt(kk.n, kk.e, R.hexToBytes(r.M), R.hexToBytes(r.L), R.hexToBytes(r.seed)).c); } catch (x) { got = 'refused'; }
        chk('OAEP ' + r.nlen + ' ' + r.case + ' c', got, r.c ? strip0(r.c) : 'refused');
        if (r.c) { var d = R.oaepDecrypt(kk, B(r.c), R.hexToBytes(r.L)); chk('OAEP ' + r.nlen + ' ' + r.case + ' decrypt', d.ok ? hexOf(d.M) : d.reason, r.M); }
      });
      flush(); await tick();
      group('Chữ ký PKCS#1 v1.5 và PSS, khoá mẫu 1024 bit', 'PKCS#1 v1.5 and PSS signatures, 1024-bit example key');
      var o1 = V.own['1024'], k1 = { n: B(o1.n), e: B(o1.e), d: B(o1.d), p: B(o1.p), q: B(o1.q), dP: B(o1.dP), dQ: B(o1.dQ), qInv: B(o1.qInv) };
      V.sign.forEach(function (r) { chk('v1.5 ' + r.hash, hexOf(R.signPkcs1(k1, r.hash, R.hexToBytes(r.msg)).S), r.v15); });
      V.pss.forEach(function (r) { chk('PSS ' + r.hash + ' salt 20', hexOf(R.signPss(k1, r.hash, enc8('Hello RSA signatures'), R.hexToBytes(r.salt)).S), r.S); });
      flush(); await tick();
      group('CAVS SigGen15, SigVer15, RSASP1', 'CAVS SigGen15, SigVer15, RSASP1');
      V.siggen15.forEach(function (r) { chk('SigGen15 ' + r.mod + ' ' + r.hash, R.verifyPkcs1(B(r.n), B(r.e), r.hash, R.hexToBytes(r.msg), R.hexToBytes(r.S)).reason, 'OK'); });
      V.sigver15.forEach(function (r, j) { chk('SigVer15 #' + j + ' ' + r.result, R.verifyPkcs1(B(r.n), B(r.e), r.hash, R.hexToBytes(evenHex(r.msg)), R.hexToBytes(evenHex(r.S))).ok ? 'P' : 'F', r.result); });
      V.rsasp1.forEach(function (r) {
        var kk = R.fromPQ(B(r.p), B(r.q), B(r.e)), got;
        try { got = H(R.rsasp1(kk, B(r.EM))); } catch (x) { got = 'refused'; }
        chk('RSASP1 COUNT ' + r.count, got, r.fail ? 'refused' : strip0(r.S));
      });
      flush(); await tick();
      group('ACVP RSA-SigGen / SigVer / SignaturePrimitive', 'ACVP RSA-SigGen / SigVer / SignaturePrimitive');
      V.siggen.forEach(function (r) {
        var vv = verifyOne({ n: B(r.n), e: B(r.e) }, r.sigType === 'pss' ? 'pss' : 'v15', r.hash, R.hexToBytes(r.message), R.hexToBytes(r.signature), r.saltLen);
        chk('SigGen tgId ' + r.tgId + ' tcId ' + r.tcId, vv.reason, 'OK');
        if (r.sigType === 'pss') chk('SigGen tgId ' + r.tgId + ' salt', hexOf(vv.salt), r.salt);
      });
      V.sigver.forEach(function (r) {
        var vv = verifyOne({ n: B(r.n), e: B(r.e) }, r.sigType === 'pss' ? 'pss' : 'v15', r.hash, R.hexToBytes(r.message), R.hexToBytes(r.signature), r.saltLen);
        chk('SigVer tgId ' + r.tgId + ' tcId ' + r.tcId, vv.reason === 'HASH_ALG' ? 'HASH_ALG:' + vv.alg : vv.reason, r.reason);
      });
      V.sigprim.forEach(function (r) {
        var kk = decKeyBig(r), got;
        try { got = H(R.rsasp1(kk, B(r.message))); } catch (x) { got = 'refused'; }
        chk('SignaturePrimitive tcId ' + r.tcId, got, r.passed ? strip0(r.signature) : 'refused');
      });
    } catch (e) { if (g) chk('exception', String(e && e.message), 'none'); }
    flush(); btn.disabled = false;
    st.className = 'pill ' + (pass === total ? 'ok' : 'bad');
    st.innerHTML = nb(pass + '/' + total) + ' ' + (pass === total ? bi('phép kiểm khớp', 'checks match') : bi('phép kiểm — CÓ LỖI', 'checks — FAILED'));
    settle();
  });
  function decKeyBig(r) {
    var k = { n: B(r.n), e: B(r.e), d: B(r.d), p: B(r.p), q: B(r.q) };
    if (r.dmp1) { k.dP = B(r.dmp1); k.dQ = B(r.dmq1); k.qInv = B(r.iqmp); }
    return k;
  }

  /* ================================================================ khởi động */
  encMode(); decMode(); sigMode(); sizeNote(); keyStatus();
  window.RSALab = {                                                   // cửa cho bộ kiểm thử tự động; trang không tự dùng
    K: KF, seed: seedF, encM: encM, encC: encC, encMsg: encMsg, encL: encL, encSeed: encSeed,
    decC: decC, decR: decR, decM: decM, decMM: decMM, decL: decL, sigMsg: sigMsg, sigEm: sigEm, sigSalt: sigSalt, sigS: sigS,
    keyStatus: keyStatus, openTab: openTab,
    flush: function () { keyStatus(); return idle(); },
    idle: idle, worker: function () { return !!worker; }
  };
})();
