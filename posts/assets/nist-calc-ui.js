/* Giao diện máy tính SLH-DSA / FN-DSA / HQC-KEM: bốn thẻ, cùng cách tương tác với hai máy tính anh em. Phép tính dài
   (SLH-DSA, sinh khoá Falcon, kiểm tra cặp khoá của hai thuật toán chữ ký) chạy trong Web Worker nếu trình duyệt cho
   phép, nếu không thì chạy ngay sau khi trang kịp vẽ dòng "đang tính". Mọi chuỗi hiển thị có hai bản qua bi(vi, en).
   Original implementation for the ChiU·SoC PQC demo page. */
(function () {
  'use strict';
  var T = window.PQCTools, NT = window.NIST3Tools, V = window.NIST3_VECTORS, PH = window.PQCHash, MLDSA = window.MLDSA;

  /* ================================================================ tiện ích */
  function $(id) { var e = document.getElementById(id); if (!e) throw new Error('missing #' + id); return e; }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function bi(vi, en) { return '<span lang="vi">' + vi + '</span><span lang="en">' + en + '</span>'; }
  function nb(s) { return '<span data-i18n="neutral">' + s + '</span>'; }
  function num(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ' '); }
  function fill(s, a) { return s.replace(/\{(\w+)\}/g, function (m, k) { return a && a[k] !== undefined && a[k] !== null ? esc(a[k]) : m; }); }
  function ms(t) { return nb(' · ' + (t >= 10000 ? (t / 1000).toFixed(1) + ' s' : t.toFixed(t < 100 ? 1 : 0) + ' ms')); }
  function checked(name) { var r = document.querySelector('input[name="' + name + '"]:checked'); return r ? r.value : null; }
  function radios(name) { return Array.prototype.slice.call(document.querySelectorAll('input[name="' + name + '"]')); }
  function onRadio(name, fn) { radios(name).forEach(function (r) { r.addEventListener('change', fn); }); }
  function setRadio(name, v) { radios(name).forEach(function (r) { r.checked = r.value === v; }); }
  function unhex(s) { return T.parseHex(s); }
  function sha(b) { return T.toHex(window.PQCSHA2.sha256(b)); }
  function phLabel(id) { for (var i = 0; i < MLDSA.PH_LIST.length; i++) if (MLDSA.PH_LIST[i].id === id) return MLDSA.PH_LIST[i].label; return id; }
  function show(el, cls, main, sub) {
    el.className = 'result ' + cls;
    el.innerHTML = main + (sub ? '<span class="sub">' + sub + '</span>' : '');
  }

  /* ================================================================ phép tính dài: Web Worker hoặc chạy sau một nhịp */
  var worker = null, wid = 0, waits = {}, pending = 0, idleWaiters = [];
  try {
    if (window.Worker && location.protocol !== 'file:') {
      worker = new Worker('assets/nist-worker.js');
      worker.onmessage = function (e) {
        var w = waits[e.data.id]; delete waits[e.data.id];
        if (!w) return;
        if (e.data.ok) w[0]({ v: e.data.v, t: e.data.ms });
        else { var x = new Error(e.data.err); x.code = e.data.code; w[1](x); }
      };
      worker.onerror = function () { worker = null; for (var k in waits) { waits[k][1](new Error('worker')); delete waits[k]; } };
    }
  } catch (e) { worker = null; }
  function settle() { pending--; if (!pending) { var a = idleWaiters; idleWaiters = []; a.forEach(function (f) { f(); }); } }
  /* gọi window[lib][op](args) -> Promise({v, t}); trên trang thật luôn bất đồng bộ */
  function call(lib, op, args) {
    pending++;
    var p = worker ? new Promise(function (res, rej) { var id = ++wid; waits[id] = [res, rej]; worker.postMessage({ id: id, lib: lib, op: op, args: args }); })
      : new Promise(function (res, rej) {
        setTimeout(function () {
          var t0 = performance.now();
          try { var v = window[lib][op].apply(null, args); res({ v: v, t: performance.now() - t0 }); } catch (e) { rej(e); }
        }, 20);
      });
    p.then(settle, settle);
    return p;
  }

  /* thông báo lỗi theo mã (PQCTools / NIST3Tools ném Error có .code) */
  var TABNAME = { slh: ['Ký · SLH-DSA', 'Sign · SLH-DSA'], fn: ['Ký · FN-DSA', 'Sign · FN-DSA'], hqc: ['Trao đổi khoá · HQC-KEM', 'Key exchange · HQC-KEM'] };
  var MSG = {
    HEX_CHAR: ['có ký tự không phải hex', 'contains a character that is not hex'],
    HEX_ODD: ['có số chữ số hex lẻ', 'has an odd number of hex digits'],
    B64: ['không phải Base64 hợp lệ', 'is not valid Base64'],
    ARRAY_ITEM: ['có phần tử mảng "{item}" không phải là số', 'has an array item "{item}" that is not a number'],
    ARRAY_RANGE: ['có phần tử {item} nằm ngoài khoảng byte -128 … 255', 'has an item {item} outside the byte range -128 … 255'],
    ARRAY_CLOSE: ['thiếu dấu "{close}" ở cuối mảng', 'is missing the closing "{close}" of the array'],
    AUTO: ['không phải hex hay mảng; với dữ liệu khác hãy chọn Base64 hoặc Văn bản', 'is neither hex nor an array; pick Base64 or Text for other data'],
    NOT_UTF8: ['chứa các byte không phải văn bản UTF-8, hãy xem ở dạng hex', 'holds bytes that are not UTF-8 text; view them as hex'],
    OTHER_TAB: ['{len} byte khớp kích thước khoá {alg}. Hãy nạp ở thẻ "{tabvi}".', '{len} bytes matches the size of a {alg} key. Load it in the "{taben}" tab.'],
    OTHER_PAGE: ['File này chứa khoá {alg}. Hãy dùng máy tính ML-KEM / ML-DSA.', 'This file holds an {alg} key. Use the ML-KEM / ML-DSA calculator.'],
    UNSUPPORTED_ALG: ['File này chứa khoá có mã định danh (OID {alg}); trang này chỉ đọc khoá thô.', 'This file holds a key with an identifier (OID {alg}); this page reads raw keys only.'],
    ENCRYPTED: ['Khoá này được mã hoá bằng mật khẩu, trang chưa đọc được.', 'This key is password-encrypted, which the page cannot read.'],
    PKCS12: ['File PKCS#12 (.pfx / .p12) chưa được hỗ trợ.', 'PKCS#12 files (.pfx / .p12) are not supported.'],
    NO_SIZE_MATCH: ['{len} byte không khớp kích thước khoá nào của SLH-DSA, FN-DSA hay HQC-KEM.', '{len} bytes matches no SLH-DSA, FN-DSA or HQC-KEM key size.'],
    MIXED: ['File trộn khoá của nhiều bộ tham số khác nhau.', 'The file mixes keys of different parameter sets.'],
    BAD_PEM_BLOCK: ['Khối PEM "{label}" không chứa khoá đọc được.', 'The PEM block "{label}" holds no readable key.'],
    BAD_PEM: ['File PEM dị dạng: không có khối BEGIN / END hoàn chỉnh.', 'Malformed PEM file: no complete BEGIN / END block.'],
    TOO_BIG: ['File quá lớn (hơn 1 MB).', 'The file is too large (over 1 MB).'],
    UNRECOGNIZED: ['Không nhận ra file. Cần khoá thô dạng nhị phân, hex hay Base64.', 'File not recognised. A raw key in binary, hex or Base64 is needed.'],
    DER: ['Cấu trúc DER bị hỏng.', 'The DER structure is broken.']
  };
  function parts(e) {
    var m = MSG[e && e.code] || ['lỗi không mong đợi: ' + esc(e && e.message), 'unexpected error: ' + esc(e && e.message)];
    var a = (e && e.info) || {};
    if (e && e.code === 'OTHER_TAB') { a.tabvi = TABNAME[a.tab][0]; a.taben = TABNAME[a.tab][1]; }
    var p = [fill(m[0], a), fill(m[1], a)];
    if (e && e.code === 'NO_SIZE_MATCH' && a.ml) {
      p[0] += ' ' + fill('Độ dài này khớp khoá {ml}: hãy dùng máy tính ML-KEM / ML-DSA.', a);
      p[1] += ' ' + fill('That length matches an {ml} key: use the ML-KEM / ML-DSA calculator.', a);
    }
    return p;
  }
  function msg(e) { var p = parts(e); return bi(p[0], p[1]); }

  /* ================================================================ chọn file */
  var fileIn = $('file-in'), fileCb = null;
  fileIn.addEventListener('change', function () {
    var file = fileIn.files && fileIn.files[0], cb = fileCb;
    fileIn.value = '';
    if (!file || !cb) return;
    if (file.size > (1 << 20)) { cb(null, file.name, { code: 'TOO_BIG' }); return; }
    var rd = new FileReader();
    rd.onload = function () { cb(new Uint8Array(rd.result), file.name); };
    rd.readAsArrayBuffer(file);
  });
  function pickFile(cb) { fileCb = cb; fileIn.click(); }

  /* ================================================================ ô dữ liệu (giống hai máy tính anh em) */
  var FMT = { hex: ['Hex', 'Hex'], base64: ['Base64', 'Base64'], c: ['C', 'C'], java: ['Java', 'Java'], text: ['Văn bản', 'Text'] };
  function tool(box, html, fn) {
    var b = document.createElement('button');
    b.type = 'button'; b.innerHTML = html; b.addEventListener('click', fn); box.appendChild(b);
    return b;
  }
  function Field(id, o) {
    var f = this;
    f.id = id; f.ta = $(id); f.cnt = $(id + '-cnt'); f.tools = $(id + '-tools');
    f.name = o.name; f.fmt = o.fmt || 'hex'; f.need = o.need || null; f.max = o.max || null; f.optional = !!o.optional;
    f.parse = o.parse || null; f.onEdit = o.onEdit || null; f.btn = {};
    var fmts = o.fmts === undefined ? ['hex', 'base64', 'c', 'java'] : o.fmts;
    if (fmts.length > 1) fmts.forEach(function (k) { f.btn[k] = tool(f.tools, bi(FMT[k][0], FMT[k][1]), function () { f.setFmt(k); }); });
    var g = document.createElement('span'); g.className = 'gap'; f.tools.appendChild(g);
    if (o.load) tool(f.tools, bi('Nạp file', 'Load file'), function () {
      pickFile(function (bytes, name, err) { o.load(f, bytes, name, err); });
    });
    tool(f.tools, bi('Chép', 'Copy'), function () { f.copy(); });
    tool(f.tools, bi('Mở rộng', 'Expand'), function () { f.ta.parentNode.classList.toggle('big'); });
    if (!f.ta.readOnly) tool(f.tools, bi('Xoá', 'Clear'), function () { f.set(null); f.edited(); });
    f.flashEl = document.createElement('span'); f.flashEl.className = 'flash'; f.tools.appendChild(f.flashEl);
    f.ta.addEventListener('input', function () { f.count(); f.edited(); });
    f.mark(); f.count();
  }
  Field.prototype.edited = function () { if (this.onEdit) this.onEdit(this); };
  Field.prototype.empty = function () { return !this.ta.value.trim(); };
  Field.prototype.bytes = function () {
    var s = this.ta.value;
    if (this.parse) return this.parse(s);
    if (this.fmt === 'text') return new TextEncoder().encode(s);
    if (this.fmt === 'base64') return T.parseInput(s, 'base64');
    return T.parseAuto(s).bytes;
  };
  Field.prototype.peek = function () { try { return this.bytes(); } catch (e) { return null; } };
  Field.prototype.full = function () {
    var b = this.peek(), n = this.need ? this.need() : null;
    return b && b.length && (n === null || b.length === n) ? b : null;
  };
  Field.prototype.set = function (b) {
    if (!b) { this.ta.value = ''; this.count(); return; }
    try { this.ta.value = T.format(b, this.fmt); }
    catch (e) { this.fmt = 'hex'; this.mark(); this.ta.value = T.format(b, 'hex'); }
    this.count();
  };
  Field.prototype.setFmt = function (k) {
    if (k === this.fmt) return;
    var b, s;
    try { b = this.bytes(); } catch (e) { return this.flash(this.err(e), true); }
    try { s = T.format(b, k); } catch (e) { return this.flash(this.err(e), true); }
    this.fmt = k; this.ta.value = s; this.mark(); this.count();
  };
  Field.prototype.mark = function () { for (var k in this.btn) this.btn[k].setAttribute('aria-pressed', String(k === this.fmt)); };
  Field.prototype.count = function () {
    var need = this.need ? this.need() : null, el = this.cnt, b;
    if (this.empty()) { el.className = 'cnt'; el.innerHTML = need ? nb('0 / ' + num(need) + ' B') : ''; return; }
    try { b = this.bytes(); } catch (e) { el.className = 'cnt bad'; el.innerHTML = bi('không hợp lệ', 'invalid'); return; }
    var n = b.length, ok = need ? n === need : (this.max ? n <= this.max : true);
    el.className = 'cnt' + (need && ok ? ' ok' : (ok ? '' : ' warn'));
    el.innerHTML = nb(num(n) + (need ? ' / ' + num(need) : '') + (this.max ? ' / ≤ ' + this.max : '') + ' B' + (need && ok ? ' ✓' : ''));
  };
  Field.prototype.err = function (e) {
    var p = parts(e);
    return bi('Ô ' + this.name[0] + ' ' + p[0] + '.', 'The ' + this.name[1] + ' field ' + p[1] + '.');
  };
  Field.prototype.lenErr = function (b, need) {
    return bi('Ô ' + this.name[0] + ' cần ' + num(need) + ' byte, đang có ' + num(b.length) + ' byte.',
      'The ' + this.name[1] + ' field needs ' + num(need) + ' bytes and holds ' + num(b.length) + '.');
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
    function done() { f.flash(bi('đã chép', 'copied')); }
    function fallback() { f.ta.select(); try { document.execCommand('copy'); done(); } catch (e) { /* trình duyệt chặn */ } }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(s).then(done, fallback);
    else fallback();
  };
  function clear() { for (var i = 0; i < arguments.length; i++) arguments[i].set(null); }
  function need(f, fail, emptyMsg, len) {
    if (f.empty()) { fail(emptyMsg); return null; }
    var b;
    try { b = f.bytes(); } catch (e) { fail(f.err(e)); return null; }
    if (len !== undefined && len !== null && b.length !== len) { fail(f.lenErr(b, len)); return null; }
    return b;
  }
  /* giá trị ngẫu nhiên của một ô: đánh dấu "ngẫu nhiên" thì sinh mới và điền vào ô, không thì đọc ô (đúng độ dài) */
  function randomOrField(chk, f, len, fail, emptyMsg) {
    if ($(chk).checked) { var r = PH.randomBytes(len); f.set(r); return r; }
    return need(f, fail, emptyMsg, len);
  }
  function looksText(b) { for (var i = 0; i < b.length; i++) { var x = b[i]; if (!(x === 9 || x === 10 || x === 13 || (x >= 32 && x < 127))) return false; } return true; }
  function bytesLoader(X) {
    return function (f, bytes, name, err) {
      if (err) return X.fail(msg(err));
      var b = bytes;
      if (looksText(bytes)) {
        var s = String.fromCharCode.apply(null, Array.prototype.slice.call(bytes, 0));
        try { b = T.parseAuto(s).bytes; } catch (e) { try { b = T.parseB64(s); } catch (e2) { b = bytes; } }
      }
      f.set(b); f.edited();
      X.note(bi('Đã nạp ' + num(b.length) + ' byte từ ' + esc(name) + ' vào ô ' + f.name[0] + '.',
        'Loaded ' + num(b.length) + ' bytes from ' + esc(name) + ' into the ' + f.name[1] + ' field.'));
    };
  }
  function msgLoader(X) {
    return function (f, bytes, name, err) {
      if (err) return X.fail(msg(err));
      var text = null;
      try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (e) { text = null; }
      if (text !== null && /[\u0000-\u0008\u000e-\u001f]/.test(text)) text = null;
      if (text !== null) { f.fmt = 'text'; f.mark(); f.ta.value = text; f.count(); }
      else { f.fmt = 'hex'; f.mark(); f.set(bytes); }
      f.edited();
      X.note(bi('Đã nạp ' + num(bytes.length) + ' byte từ ' + esc(name) + ' làm thông điệp.', 'Loaded ' + num(bytes.length) + ' bytes from ' + esc(name) + ' as the message.'));
    };
  }

  /* ================================================================ dòng kiểm tra cặp khoá */
  var ROW = {
    len: ['Độ dài hai khoá đúng với bộ tham số', 'Both keys have the right length for the parameter set'],
    derived_pk_slh: ['Khoá công khai lưu trong khoá bí mật trùng ô khoá công khai', 'The public key stored inside the private key equals the Public key field'],
    root: ['Gốc cây trên cùng tính lại từ SK.seed và PK.seed trùng PK.root', 'The top tree root recomputed from SK.seed and PK.seed equals PK.root'],
    sk_decode: ['Khoá bí mật giải mã được (đúng đầu khoá, hệ số trong khoảng cho phép)', 'The private key decodes (right header, coefficients in range)'],
    derived_pk_fn: ['h = g / f mod q tính từ khoá bí mật trùng ô khoá công khai', 'h = g / f mod q computed from the private key equals the Public key field'],
    ntru: ['Phương trình NTRU fG − gF = q giải được cho G', 'The NTRU equation fG − gF = q can be completed with G'],
    derived_pk_hqc: ['Sinh khoá lại từ dk cho đúng ô khoá đóng gói ek', 'Regenerating from dk gives exactly the encapsulation key ek'],
    roundtrip_sig: ['Khứ hồi: ký bằng khoá bí mật, xác minh bằng khoá công khai', 'Round trip: sign with the private key, verify with the public key'],
    roundtrip_kem: ['Khứ hồi: đóng gói tới ek, giải bằng dk, hai khoá chung trùng nhau', 'Round trip: encapsulate to ek, decapsulate with dk, the secrets match'],
    seed: ['Seed trong ô Seed sinh ra đúng cặp khoá này (chỉ để thông tin)', 'The seed in the Seed field generates exactly this key pair (for information)'],
    seed_null: ['Ô Seed chưa đủ độ dài nên bỏ qua', 'The Seed field is not full length, so it was skipped']
  };
  var STATE = {
    match: ['ok', '✓', 'Khoá khớp: khoá bí mật thuộc về khoá công khai này.', 'Keys match: the private key belongs to this public key.'],
    other: ['bad', '✕', 'Khoá không khớp: khoá bí mật thuộc về một cặp khoá khác.', 'Keys do not match: the private key belongs to a different key pair.'],
    corrupt: ['bad', '✕', 'Khoá bí mật bị hỏng: nó không qua một phép kiểm nhất quán.', 'The private key is corrupted: it fails a consistency check.'],
    missing: ['', 'i', 'Cần cả hai khoá, đủ độ dài, để kiểm tra cặp.', 'Both keys, at full length, are needed to check the pair.']
  };
  function renderPair(el, alg, res) {
    var st = STATE[res.state], seedRow = null, li = res.rows.map(function (r) {
      var key = r[0];
      if (key === 'roundtrip') key = alg === 'hqc' ? 'roundtrip_kem' : 'roundtrip_sig';
      else if (key === 'derived_pk') key = 'derived_pk_' + alg;
      else if (key === 'seed' && r[1] === null) key = 'seed_null';
      if (r[0] === 'seed') seedRow = r[1];
      return '<li><b>' + (r[1] === null ? '—' : (r[1] ? '✓' : '✕')) + '</b>' + bi(ROW[key][0], ROW[key][1]) + '</li>';
    });
    var extra = res.state === 'match' && seedRow === false ?
      ' ' + bi('Riêng seed trong ô Seed sinh ra một cặp khoá khác.', 'The seed in the Seed field, though, generates a different key pair.') : '';
    el.className = 'pairline ' + st[0];
    el.innerHTML = '<span class="st">' + st[1] + ' ' + bi(st[2], st[3]) + '</span>' + extra +
      '<details><summary>' + bi('chi tiết', 'details') + '</summary><ul>' + li.join('') + '</ul></details>';
  }
  var pairTimer = {}, pairToken = {};
  /* kiểm tra cặp, có hẹn giờ; với SLH-DSA và FN-DSA thì qua call() vì có thể mất vài giây */
  function pairNow(X) {
    var el = $(X.tab + '-pair');
    if (X.pk.empty() && X.sk.empty()) { el.className = 'pairline'; el.innerHTML = ''; return Promise.resolve(); }
    var seedF = X.seedField(), seed = !seedF || seedF.empty() ? null : seedF.peek();
    var args = [X.tab, X.set(), X.pk.peek(), X.sk.peek(), seed], tok = pairToken[X.tab] = (pairToken[X.tab] || 0) + 1;
    if (X.tab === 'hqc') { renderPair(el, 'hqc', NT.pairCheck.apply(null, args)); return Promise.resolve(); }
    el.className = 'pairline'; el.innerHTML = bi('đang kiểm tra cặp khoá…', 'checking the key pair…');
    return call('NIST3Tools', 'pairCheck', args).then(function (r) { if (pairToken[X.tab] === tok) renderPair(el, X.tab, r.v); },
      function () { if (pairToken[X.tab] === tok) { el.className = 'pairline bad'; el.innerHTML = bi('Không kiểm tra được cặp khoá này.', 'This key pair could not be checked.'); } });
  }
  function pairLater(X) { clearTimeout(pairTimer[X.tab]); pairTimer[X.tab] = setTimeout(function () { delete pairTimer[X.tab]; pairNow(X); }, 150); }

  /* ================================================================ nạp file khoá thô */
  var ENC = { DER: ['nhị phân', 'binary'], hex: ['hex', 'hex'], base64: ['Base64', 'Base64'] };
  function keyLoader(X, prefer) {
    return function (f, bytes, name, err) {
      if (err) return X.fail(msg(err));
      var items, alg;
      try { items = T.readKeyFile(bytes, name); alg = NT.identify(items, X.tab, X.set(), prefer); }
      catch (e) { return X.fail(msg(e)); }
      var multi = items.some(function (it) { return it.notes.indexOf('MULTI_MATCH') >= 0; });
      if (alg !== X.set()) X.setLevel(alg, true);
      var got = [], pub = null, priv = null;
      items.forEach(function (it) {
        var e = ENC[it.enc] || ENC.DER;
        if (it.kind === 'public') { X.pk.set(it.data); pub = it; got.push(['khoá công khai (khoá thô, ' + e[0] + ')', 'public key (raw, ' + e[1] + ')']); }
        else { X.sk.set(it.data); priv = it; got.push(['khoá bí mật (khoá thô, ' + e[0] + ')', 'private key (raw, ' + e[1] + ')']); }
      });
      if (priv && X.seedField() && X.seedField() !== X.sk) X.seedField().set(null);
      X.keysLoaded(priv && !pub);
      var vi = got.map(function (g) { return g[0]; }).join(' và '), en = got.map(function (g) { return g[1]; }).join(' and ');
      X.note(bi('Đã nạp ' + vi + ' của ' + alg + ' từ ' + esc(name) + '.', 'Loaded the ' + alg + ' ' + en + ' from ' + esc(name) + '.'),
        multi ? bi('Độ dài này khớp nhiều bộ tham số; đã chọn ' + alg + '. Nếu sai, hãy chọn bộ đúng rồi nạp lại.',
          'This length matches several parameter sets; ' + alg + ' was chosen. If that is wrong, select the right set and load again.') : '');
    };
  }

  /* ================================================================ khung chung của một thẻ */
  function Tab(tab, res, panel) {
    var X = this;
    X.tab = tab; X.res = $(res); X.panel = $(panel); X.msg = null; X.busyT = null;
    X.fail = function (html) { X.msg = { cls: 'bad', html: '✕ ' + html }; X.update(); };
    X.note = function (html, sub, cls) { X.msg = { cls: cls || 'note', html: html, sub: sub }; X.update(); };
  }
  /* trong lúc tính: khoá các nút của thẻ, đếm giây trên dòng kết quả */
  Tab.prototype.busy = function (vi, en) {
    var X = this, t0 = Date.now();
    Array.prototype.forEach.call(X.panel.querySelectorAll('button'), function (b) { b.disabled = true; });
    function tick() { show(X.res, 'info', '⏳ ' + bi(vi, en), nb(((Date.now() - t0) / 1000).toFixed(1) + ' s')); }
    tick(); X.busyT = setInterval(tick, 250);
  };
  Tab.prototype.done = function () {
    clearInterval(this.busyT); this.busyT = null;
    Array.prototype.forEach.call(this.panel.querySelectorAll('button'), function (b) { b.disabled = false; });
  };
  function ladder(X, steps, next, note) {
    var x = X.msg;
    if (x && (x.cls === 'bad' || x.cls === 'ok')) return show(X.res, x.cls, x.html, x.sub);
    show(X.res, 'info', '→ ' + steps[next], note !== undefined ? note : (x ? x.html + (x.sub ? ' ' + x.sub : '') : ''));
  }
  function cards(prefix, list, next) {
    list.forEach(function (c) { var card = $(prefix + '-c' + c[0]); card.classList.toggle('done', c[1]); card.classList.toggle('next', next === c[0]); });
  }
  var SIGSTEPS = {
    1: bi('Bắt đầu với bước 1: sinh (hoặc nạp) một cặp khoá.', 'Start with step 1: generate (or load) a key pair.'),
    2: bi('Tiếp theo: bước 2 — nhập thông điệp cần ký.', 'Next: step 2 — enter the message to sign.'),
    3: bi('Tiếp theo: bước 3 — bấm Ký.', 'Next: step 3 — press Sign.'),
    0: bi('Đã có chữ ký: bấm Xác minh.', 'There is a signature: press Verify.')
  };

  /* ================================================================ thẻ SLH-DSA */
  var SX = new Tab('slh', 'slh-result', 'panel-slh');
  function slhSet() { return 'SLH-DSA-' + checked('slh-hash') + '-' + checked('slh-lvl') + checked('slh-var'); }
  function slhSz() { return NT.info('slh', slhSet()); }
  SX.set = slhSet;
  SX.setLevel = function (name, quiet) {
    var m = /^SLH-DSA-(SHA2|SHAKE)-(\d+)([sf])$/.exec(name);
    setRadio('slh-hash', m[1]); setRadio('slh-lvl', m[2]); setRadio('slh-var', m[3]); slhLevel(quiet);
  };
  SX.seedField = function () { return S.seed; };
  SX.keysLoaded = function () { pairLater(SX); slhStale(); };
  var S = {};
  function slhStale() { SX.msg = null; SX.update(); }
  S.seed = new Field('slh-seed', { name: ['Seed', 'Seed'], need: function () { return slhSz().seed; }, load: bytesLoader(SX),
    onEdit: function () { $('slh-seed-rnd').checked = false; pairLater(SX); } });
  S.pk = new Field('slh-pk', { name: ['khoá công khai', 'Public key'], need: function () { return slhSz().pk; }, load: keyLoader(SX, 'public'),
    onEdit: function () { pairLater(SX); slhStale(); } });
  S.sk = new Field('slh-sk', { name: ['khoá bí mật', 'Private key'], need: function () { return slhSz().sk; }, load: keyLoader(SX, 'private'),
    onEdit: function () { pairLater(SX); slhStale(); } });
  S.msg = new Field('slh-msg', { name: ['thông điệp', 'Message'], fmt: 'text', fmts: ['text', 'hex', 'base64', 'c', 'java'],
    load: msgLoader(SX), onEdit: function () { slhMp(); slhStale(); } });
  S.ctx = new Field('slh-ctx', { name: ['ngữ cảnh', 'Context'], fmt: 'text', fmts: ['text', 'hex'], max: 255,
    onEdit: function () { slhMp(); slhStale(); } });
  S.mp = new Field('slh-mp', { name: ['M′', 'M′'] });
  S.rnd = new Field('slh-rnd', { name: ['addrnd', 'addrnd'], need: function () { return slhSz().n; }, load: bytesLoader(SX),
    onEdit: function () { $('slh-rnd-rnd').checked = false; } });
  S.sig = new Field('slh-sig', { name: ['chữ ký', 'Signature'], need: function () { return slhSz().sig; }, load: bytesLoader(SX),
    onEdit: function () { slhStale(); } });
  SX.pk = S.pk; SX.sk = S.sk;
  function slhPh() { var v = checked('slh-ph'); return v === 'none' ? null : v; }
  function slhMp() {
    var m = S.msg.peek(), c = S.ctx.peek();
    S.mp.set(m && c && c.length <= 255 ? MLDSA.prepare(m, c, slhPh()) : null);
  }
  function slhMode() {
    var ph = slhPh(), c = S.ctx.peek() || new Uint8Array(0);
    var a = ph ? ['HashSLH-DSA với ' + phLabel(ph), 'HashSLH-DSA with ' + phLabel(ph)] : ['SLH-DSA thuần', 'pure SLH-DSA'];
    var b = c.length ? ['ngữ cảnh ' + num(c.length) + ' byte', num(c.length) + '-byte context'] : ['ngữ cảnh rỗng', 'empty context'];
    return [a[0] + ' · ' + b[0], a[1] + ' · ' + b[1]];
  }
  function slhPhSync(levelChanged) {
    var set = slhSet(), n = slhSz().n, reset = null, note = $('slh-ph-note');
    radios('slh-ph').forEach(function (r) {
      if (r.value === 'none') return;
      var ok = NT.prehashAllowed(set, r.value);
      r.disabled = !ok;
      if (!ok && r.checked) reset = r.value;
    });
    if (reset) {
      setRadio('slh-ph', 'none');
      note.innerHTML = bi(phLabel(reset) + ' quá yếu cho ' + set + ' nên đã được đặt lại về "Không".', phLabel(reset) + ' is too weak for ' + set + ', so it was reset to None.');
    } else if (levelChanged) note.innerHTML = '';
    $('slh-ph-why').innerHTML = bi('Ở ' + set + ' (n = ' + n + ' byte), giá trị băm phải dài ít nhất 2n = ' + 2 * n + ' byte (FIPS 205, mục 10.2.2); các hàm bị gạch là quá ngắn.',
      'At ' + set + ' (n = ' + n + ' bytes) the digest must be at least 2n = ' + 2 * n + ' bytes long (FIPS 205, section 10.2.2); the struck-out functions are too short.');
    return reset;
  }
  function slhName() {
    var z = slhSz();
    $('slh-name').innerHTML = nb(slhSet()) + ' · ' + bi('n = ' + z.n + ' byte · chữ ký ' + num(z.sig) + ' byte', 'n = ' + z.n + ' bytes · ' + num(z.sig) + '-byte signature') +
      (z.fast ? '' : ' · ' + bi('biến thể "s": chữ ký nhỏ nhưng ký mất từ khoảng một tới hơn mười giây.', '"s" variant: a small signature, but signing takes from about one to over ten seconds.'));
  }
  SX.update = function () {
    var pk = !!S.pk.full(), sk = !!S.sk.full(), m = !S.msg.empty() && !!S.msg.peek(), sig = !!S.sig.full();
    var next = !(pk || sk) ? 1 : (!m ? 2 : (!sig ? 3 : 0));
    cards('slh', [[1, pk && sk], [2, m], [3, sig]], next);
    ladder(SX, SIGSTEPS, next);
  };
  function slhLevel(quiet) {
    var z = slhSz();
    clear(S.pk, S.sk, S.sig);
    [S.seed, S.rnd].forEach(function (f) { var b = f.peek(); if (b && b.length && b.length !== (f === S.seed ? z.seed : z.n)) clear(f); });
    var reset = slhPhSync(true);
    [S.seed, S.pk, S.sk, S.rnd, S.sig].forEach(function (f) { f.count(); });
    slhName(); slhMp(); SX.kat = null;
    SX.msg = quiet ? null : { cls: 'note', html: bi('Đã chuyển sang ' + slhSet() + ': khoá và chữ ký cũ đã được xoá.', 'Switched to ' + slhSet() + ': the old keys and signature were cleared.') + (reset ? ' ' + $('slh-ph-note').innerHTML : '') };
    pairLater(SX); SX.update();
  }
  ['slh-hash', 'slh-lvl', 'slh-var'].forEach(function (g) { onRadio(g, function () { slhLevel(false); }); });
  onRadio('slh-ph', function () { $('slh-ph-note').innerHTML = ''; slhMp(); slhStale(); });
  $('slh-clear').addEventListener('click', function () { clear(S.seed, S.pk, S.sk, S.rnd, S.sig); SX.msg = null; SX.kat = null; pairLater(SX); SX.update(); });
  function slhKeygen(after) {
    var z = slhSz(), seed = randomOrField('slh-seed-rnd', S.seed, z.seed, SX.fail, bi('Ô Seed đang trống: đánh dấu "seed ngẫu nhiên" hoặc nhập ' + z.seed + ' byte.', 'The Seed field is empty: tick "random seed" or enter ' + z.seed + ' bytes.'));
    if (!seed) return;
    var set = slhSet(), n = z.n;
    SX.busy('Đang sinh cặp khoá ' + set + '…', 'Generating a ' + set + ' key pair…');
    call('SLHDSA', 'keygenInternal', [set, seed.subarray(0, n), seed.subarray(n, 2 * n), seed.subarray(2 * n)]).then(function (r) {
      SX.done(); S.pk.set(r.v.pk); S.sk.set(r.v.sk); clear(S.sig); pairLater(SX);
      if (after) after(r); else SX.note(bi('Đã sinh cặp khoá ' + set + '.', 'Generated a ' + set + ' key pair.') + ms(r.t));
    }, function (e) { SX.done(); SX.fail(bi('Không sinh được khoá: ', 'Key generation failed: ') + esc(e.message)); });
  }
  $('slh-keygen').addEventListener('click', function () { SX.kat = null; slhKeygen(); });
  $('slh-acvp').addEventListener('click', function () {
    var set = slhSet(), v = V.slh.keygen.filter(function (x) { return x.set === set; })[0];
    $('slh-seed-rnd').checked = false; S.seed.set(unhex(v.seed));
    slhKeygen(function (r) {
      var ok = sha(S.pk.full()) === v.pk_sha256 && sha(S.sk.full()) === v.sk_sha256;
      SX.note((ok ? '✓ ' : '✕ ') + (ok ? bi('Seed của vector ACVP keyGen số ' + v.tcId + ' của NIST đã được điền. Khoá sinh ra trùng từng byte với đáp án của NIST.',
        'The seed of NIST\'s ACVP keyGen vector ' + v.tcId + ' is filled in. The keys generated equal NIST\'s answer byte for byte.')
        : bi('Khoá sinh ra KHÁC đáp án ACVP của NIST.', 'The keys generated DIFFER from NIST\'s ACVP answer.')), ms(r.t), ok ? 'ok' : 'bad');
    });
  });
  function msgCtx(X, Fm, Fc) {
    var m, c;
    try { m = Fm.bytes(); } catch (e) { X.fail(Fm.err(e)); return null; }
    if (!m.length) { X.fail(bi('Thông điệp đang trống. Hãy nhập nội dung cần ký.', 'The message is empty. Enter what you want to sign.')); return null; }
    if (!Fc) return [m, null];
    try { c = Fc.bytes(); } catch (e) { X.fail(Fc.err(e)); return null; }
    if (c.length > 255) { X.fail(bi('Ngữ cảnh dài ' + num(c.length) + ' byte; tối đa là 255 byte.', 'The context is ' + num(c.length) + ' bytes; the maximum is 255.')); return null; }
    return [m, c];
  }
  $('slh-sign').addEventListener('click', function () {
    var z = slhSz(), set = slhSet(), sk = need(S.sk, SX.fail, bi('Chưa có khoá bí mật: làm bước 1, hoặc dán / nạp một khoá.', 'No private key yet: do step 1, or paste / load a key.'), z.sk);
    if (!sk) return;
    var mc = msgCtx(SX, S.msg, S.ctx);
    if (!mc) return;
    var rnd = null;
    if ($('slh-rnd-rnd').checked) { rnd = PH.randomBytes(z.n); S.rnd.set(rnd); }
    else if (!S.rnd.empty() && !(rnd = need(S.rnd, SX.fail, '', z.n))) return;
    var ph = slhPh(), md = slhMode();
    SX.busy('Đang ký bằng ' + set + '…', 'Signing with ' + set + '…');
    call('SLHDSA', 'sign', [set, mc[0], mc[1], sk, rnd, ph]).then(function (r) {
      SX.done(); S.sig.set(r.v);
      var how = rnd ? ['có addrnd ngẫu nhiên', 'with random addrnd'] : ['tất định', 'deterministic'];
      SX.note('✓ ' + bi('Đã ký · chữ ký ' + set + ' dài ' + num(r.v.length) + ' byte.', 'Signed · ' + num(r.v.length) + '-byte ' + set + ' signature.'),
        bi(md[0] + ' · ' + how[0], md[1] + ' · ' + how[1]) + ms(r.t), 'ok');
    }, function (e) { SX.done(); SX.fail(bi('Không ký được: ', 'Signing failed: ') + esc(e.message)); });
  });
  $('slh-verify').addEventListener('click', function () {
    var z = slhSz(), set = slhSet(), pk = need(S.pk, SX.fail, bi('Chưa có khoá công khai.', 'No public key yet.'), z.pk);
    if (!pk) return;
    var sig = need(S.sig, SX.fail, bi('Chưa có chữ ký: bấm Ký, hoặc dán / nạp một chữ ký.', 'No signature yet: press Sign, or paste / load one.'));
    if (!sig) return;
    var mc = msgCtx(SX, S.msg, S.ctx);
    if (!mc) return;
    var md = slhMode();
    if (sig.length !== z.sig) return SX.note('✕ ' + bi('Chữ ký KHÔNG hợp lệ.', 'The signature is NOT valid.'),
      bi('Chữ ký ' + set + ' phải dài ' + num(z.sig) + ' byte, ô đang có ' + num(sig.length) + ' byte.', 'A ' + set + ' signature is ' + num(z.sig) + ' bytes; the field holds ' + num(sig.length) + '.'), 'bad');
    SX.busy('Đang xác minh…', 'Verifying…');
    call('SLHDSA', 'verify', [set, mc[0], sig, mc[1], pk, slhPh()]).then(function (r) {
      SX.done();
      if (r.v) SX.note('✓ ' + bi('Chữ ký hợp lệ.', 'The signature is valid.'), bi(md[0], md[1]) + ms(r.t), 'ok');
      else SX.note('✕ ' + bi('Chữ ký KHÔNG hợp lệ.', 'The signature is NOT valid.'),
        bi('Khoá, thông điệp, ngữ cảnh hoặc pre-hash khác với lúc ký — hoặc chữ ký đã bị sửa. Đang kiểm theo: ' + md[0] + '.',
          'The key, message, context or pre-hash differs from signing time — or the signature was altered. Checked as: ' + md[1] + '.') + ms(r.t), 'bad');
    }, function (e) { SX.done(); SX.fail(esc(e.message)); });
  });
  $('slh-det').addEventListener('click', function () {
    $('slh-rnd-rnd').checked = false; clear(S.rnd);
    SX.note(bi('addrnd để trống: ký tất định, FIPS 205 dùng PK.seed thay chỗ của nó. Cùng khoá, cùng thông điệp thì luôn ra cùng chữ ký.',
      'addrnd left empty: deterministic signing, FIPS 205 uses PK.seed in its place. The same key and message always give the same signature.'));
  });
  $('slh-flip').addEventListener('click', function () {
    var s = S.sig.peek();
    if (!s || !s.length) return SX.fail(bi('Chưa có chữ ký để lật bit.', 'There is no signature to flip a bit in.'));
    s[s.length >> 1] ^= 1; S.sig.set(s);
    SX.note(bi('Đã lật một bit ở giữa chữ ký. Bấm Xác minh.', 'A bit in the middle of the signature was flipped. Press Verify.'));
  });

  /* ================================================================ thẻ FN-DSA */
  var FX = new Tab('fn', 'fn-result', 'panel-fn');
  function fnSet() { return checked('fn-set'); }
  function fnSz() { return NT.info('fn', fnSet()); }
  FX.set = fnSet;
  FX.setLevel = function (name, quiet) { setRadio('fn-set', name); fnLevel(quiet); };
  FX.seedField = function () { return Fd.seed; };
  FX.keysLoaded = function () { pairLater(FX); fnStale(); };
  var Fd = {};
  function fnStale() { FX.msg = null; FX.update(); }
  Fd.seed = new Field('fn-seed', { name: ['Seed', 'Seed'], need: function () { return 48; }, load: bytesLoader(FX),
    onEdit: function () { $('fn-seed-rnd').checked = false; pairLater(FX); } });
  Fd.pk = new Field('fn-pk', { name: ['khoá công khai', 'Public key'], need: function () { return fnSz().pk; }, load: keyLoader(FX, 'public'),
    onEdit: function () { pairLater(FX); fnStale(); } });
  Fd.sk = new Field('fn-sk', { name: ['khoá bí mật', 'Private key'], need: function () { return fnSz().sk; }, load: keyLoader(FX, 'private'),
    onEdit: function () { pairLater(FX); fnStale(); } });
  Fd.msg = new Field('fn-msg', { name: ['thông điệp', 'Message'], fmt: 'text', fmts: ['text', 'hex', 'base64', 'c', 'java'],
    load: msgLoader(FX), onEdit: function () { fnMp(); fnStale(); } });
  Fd.mp = new Field('fn-mp', { name: ['r ‖ M', 'r ‖ M'] });
  Fd.salt = new Field('fn-salt', { name: ['muối r', 'Salt r'], need: function () { return 40; }, load: bytesLoader(FX),
    onEdit: function () { $('fn-salt-rnd').checked = false; fnMp(); } });
  Fd.sseed = new Field('fn-sseed', { name: ['seed lấy mẫu', 'Sampler seed'], need: function () { return 48; }, load: bytesLoader(FX),
    onEdit: function () { $('fn-sseed-rnd').checked = false; } });
  Fd.sig = new Field('fn-sig', { name: ['chữ ký', 'Signature'], need: function () { return fnSz().sig; }, load: bytesLoader(FX),
    onEdit: function () { fnStale(); } });
  FX.pk = Fd.pk; FX.sk = Fd.sk;
  function fnMp() {
    var m = Fd.msg.peek(), r = Fd.salt.full();
    if (!m || !r) return Fd.mp.set(null);
    var out = new Uint8Array(r.length + m.length); out.set(r); out.set(m, r.length); Fd.mp.set(out);
  }
  FX.update = function () {
    var pk = !!Fd.pk.full(), sk = !!Fd.sk.full(), m = !Fd.msg.empty() && !!Fd.msg.peek(), sig = !!Fd.sig.full();
    var next = !(pk || sk) ? 1 : (!m ? 2 : (!sig ? 3 : 0));
    cards('fn', [[1, pk && sk], [2, m], [3, sig]], next);
    ladder(FX, SIGSTEPS, next);
  };
  function fnLevel(quiet) {
    clear(Fd.pk, Fd.sk, Fd.sig);
    [Fd.seed, Fd.pk, Fd.sk, Fd.sig].forEach(function (f) { f.count(); });
    FX.kat = null;
    FX.msg = quiet ? null : { cls: 'note', html: bi('Đã chuyển sang ' + fnSet() + ': khoá và chữ ký cũ đã được xoá vì độ dài khác.', 'Switched to ' + fnSet() + ': the old keys and signature were cleared because the sizes differ.') };
    pairLater(FX); FX.update();
  }
  onRadio('fn-set', function () { fnLevel(false); });
  $('fn-clear').addEventListener('click', function () { clear(Fd.seed, Fd.pk, Fd.sk, Fd.salt, Fd.sseed, Fd.sig); fnMp(); FX.msg = null; FX.kat = null; pairLater(FX); FX.update(); });
  function fnKeygen(after) {
    var seed = randomOrField('fn-seed-rnd', Fd.seed, 48, FX.fail, bi('Ô Seed đang trống: đánh dấu "seed ngẫu nhiên" hoặc nhập 48 byte.', 'The Seed field is empty: tick "random seed" or enter 48 bytes.'));
    if (!seed) return;
    var set = fnSet();
    FX.busy('Đang sinh cặp khoá ' + set + ' (giải phương trình NTRU)…', 'Generating a ' + set + ' key pair (solving the NTRU equation)…');
    call('FNDSA', 'keygen', [set, seed]).then(function (r) {
      FX.done(); Fd.pk.set(r.v.pk); Fd.sk.set(r.v.sk); clear(Fd.sig); pairLater(FX);
      if (after) after(r); else FX.note(bi('Đã sinh cặp khoá ' + set + '.', 'Generated a ' + set + ' key pair.') + ms(r.t));
    }, function (e) { FX.done(); FX.fail(bi('Không sinh được khoá: ', 'Key generation failed: ') + esc(e.message)); });
  }
  $('fn-keygen').addEventListener('click', function () { FX.kat = null; fnKeygen(); });
  $('fn-kat').addEventListener('click', function () {
    var v = V.fn.kat[fnSet()];
    $('fn-seed-rnd').checked = false; Fd.seed.set(unhex(v.kseed));
    $('fn-salt-rnd').checked = false; Fd.salt.set(unhex(v.salt));
    $('fn-sseed-rnd').checked = false; Fd.sseed.set(unhex(v.sseed));
    Fd.msg.fmt = 'hex'; Fd.msg.mark(); Fd.msg.set(unhex(v.msg)); fnMp();
    fnKeygen(function (r) {
      var ok = sha(Fd.pk.full()) === v.pk_sha256 && sha(Fd.sk.full()) === v.sk_sha256;
      FX.kat = v;
      FX.note((ok ? '✓ ' : '✕ ') + (ok ? bi('Seed, muối, seed lấy mẫu và thông điệp của mục KAT chính thức count = 0 đã được điền. Khoá sinh ra trùng từng byte với file KAT vòng 3 của Falcon.',
        'The seed, salt, sampler seed and message of the official KAT entry count = 0 are filled in. The keys generated equal Falcon\'s round-3 KAT file byte for byte.')
        : bi('Khoá sinh ra KHÁC file KAT chính thức.', 'The keys generated DIFFER from the official KAT file.')),
        (ok ? bi('Bấm Ký để thấy chữ ký cũng trùng.', 'Press Sign to see the signature match too.') : '') + ms(r.t), ok ? 'ok' : 'bad');
    });
  });
  var FNWHY = {
    pk: ['khoá công khai sai dạng (đầu khoá hoặc hệ số ngoài khoảng)', 'the public key is malformed (header or a coefficient out of range)'],
    format: ['chữ ký sai định dạng (độ dài hoặc byte đầu)', 'the signature is malformed (length or first byte)'],
    decompress: ['phần nén của s2 không giải được, hoặc phần đệm cuối khác 0', 'the compressed s2 does not decode, or the trailing padding is not zero'],
    norm: ['vector (s1, s2) quá dài: khoá, thông điệp hay muối khác lúc ký, hoặc chữ ký đã bị sửa', 'the vector (s1, s2) is too long: the key, message or salt differs from signing time, or the signature was altered']
  };
  $('fn-sign').addEventListener('click', function () {
    var z = fnSz(), set = fnSet(), sk = need(Fd.sk, FX.fail, bi('Chưa có khoá bí mật: làm bước 1, hoặc dán / nạp một khoá.', 'No private key yet: do step 1, or paste / load a key.'), z.sk);
    if (!sk) return;
    var mc = msgCtx(FX, Fd.msg, null);
    if (!mc) return;
    var salt = randomOrField('fn-salt-rnd', Fd.salt, 40, FX.fail, bi('Ô muối đang trống: đánh dấu "muối r ngẫu nhiên" hoặc nhập 40 byte.', 'The salt field is empty: tick "random salt r" or enter 40 bytes.'));
    if (!salt) return;
    var sseed = randomOrField('fn-sseed-rnd', Fd.sseed, 48, FX.fail, bi('Ô seed lấy mẫu đang trống: đánh dấu ô ngẫu nhiên hoặc nhập 48 byte.', 'The sampler seed field is empty: tick its random box or enter 48 bytes.'));
    if (!sseed) return;
    fnMp();
    var v = FX.kat;
    FX.busy('Đang ký bằng ' + set + '…', 'Signing with ' + set + '…');
    call('FNDSA', 'sign', [set, sk, mc[0], salt, sseed]).then(function (r) {
      FX.done(); Fd.sig.set(r.v.sig);
      var a = r.v.attempts, sub = bi(a + ' lần thử', a + (a === 1 ? ' attempt' : ' attempts')) + ms(r.t);
      if (v && sha(sk) === v.sk_sha256 && T.toHex(mc[0]) === v.msg && T.toHex(salt) === v.salt && T.toHex(sseed) === v.sseed) {
        var ok = sha(r.v.sig) === v.sig_sha256;
        return FX.note((ok ? '✓ ' : '✕ ') + (ok ? bi('Đã ký. Chữ ký trùng từng byte với chữ ký trong file KAT chính thức (viết ở dạng có đệm của đặc tả).', 'Signed. The signature equals, byte for byte, the one in the official KAT file (written in the specification\'s padded form).')
          : bi('Chữ ký KHÁC mục KAT chính thức.', 'The signature DIFFERS from the official KAT entry.')), sub, ok ? 'ok' : 'bad');
      }
      FX.note('✓ ' + bi('Đã ký · chữ ký ' + set + ' dài ' + num(r.v.sig.length) + ' byte.', 'Signed · ' + num(r.v.sig.length) + '-byte ' + set + ' signature.'), sub, 'ok');
    }, function (e) { FX.done(); FX.fail(bi('Không ký được: khoá bí mật này không dùng được (', 'Could not sign: this private key cannot be used (') + esc(e.message) + ').'); });
  });
  $('fn-verify').addEventListener('click', function () {
    var z = fnSz(), set = fnSet(), pk = need(Fd.pk, FX.fail, bi('Chưa có khoá công khai.', 'No public key yet.'), z.pk);
    if (!pk) return;
    var sig = need(Fd.sig, FX.fail, bi('Chưa có chữ ký: bấm Ký, hoặc dán / nạp một chữ ký.', 'No signature yet: press Sign, or paste / load one.'));
    if (!sig) return;
    var mc = msgCtx(FX, Fd.msg, null);
    if (!mc) return;
    FX.busy('Đang xác minh…', 'Verifying…');
    call('FNDSA', 'verify', [set, pk, mc[0], sig]).then(function (r) {
      FX.done();
      if (r.v.ok) return FX.note('✓ ' + bi('Chữ ký hợp lệ.', 'The signature is valid.'), ms(r.t), 'ok');
      var w = FNWHY[r.v.why] || [esc(r.v.why), esc(r.v.why)];
      FX.note('✕ ' + bi('Chữ ký KHÔNG hợp lệ: ' + w[0] + '.', 'The signature is NOT valid: ' + w[1] + '.'), bi('Lý do theo bộ xác minh: ', 'The verifier\'s reason: ') + nb(esc(r.v.why)) + ms(r.t), 'bad');
    }, function (e) { FX.done(); FX.fail(esc(e.message)); });
  });
  $('fn-flip').addEventListener('click', function () {
    var s = Fd.sig.peek();
    if (!s || !s.length) return FX.fail(bi('Chưa có chữ ký để lật bit.', 'There is no signature to flip a bit in.'));
    s[60] ^= 1; Fd.sig.set(s);
    FX.note(bi('Đã lật một bit trong phần nén của chữ ký. Bấm Xác minh.', 'A bit in the compressed part of the signature was flipped. Press Verify.'));
  });

  /* ================================================================ thẻ HQC-KEM */
  var HX = new Tab('hqc', 'hqc-result', 'panel-hqc');
  function hqcSet() { return checked('hqc-set'); }
  function hqcSz() { return NT.info('hqc', hqcSet()); }
  HX.set = hqcSet;
  HX.setLevel = function (name, quiet) { setRadio('hqc-set', name); hqcLevel(quiet); };
  HX.seedField = function () { return null; };
  HX.keysLoaded = function (privOnly) {
    clear(Q.ct, Q.ss, Q.ss2);
    if (privOnly && Q.sk.full()) Q.pk.set(window.HQC.keygenInternal(hqcSet(), Q.sk.full()).ek);
    pairLater(HX);
  };
  var Q = {};
  Q.sk = new Field('hqc-sk', { name: ['khoá giải đóng gói', 'Decapsulation key'], need: function () { return 32; }, load: keyLoader(HX, 'private'),
    onEdit: function () { $('hqc-seed-rnd').checked = false; clear(Q.ss2); HX.msg = null; pairLater(HX); HX.update(); } });
  Q.pk = new Field('hqc-pk', { name: ['khoá đóng gói', 'Encapsulation key'], need: function () { return hqcSz().pk; }, load: keyLoader(HX, 'public'),
    onEdit: function () { clear(Q.ct, Q.ss, Q.ss2); HX.msg = null; pairLater(HX); HX.update(); } });
  Q.m = new Field('hqc-m', { name: ['m', 'm'], need: function () { return hqcSz().m; }, load: bytesLoader(HX),
    onEdit: function () { $('hqc-m-rnd').checked = false; } });
  Q.salt = new Field('hqc-salt', { name: ['muối', 'Salt'], need: function () { return 16; }, load: bytesLoader(HX),
    onEdit: function () { $('hqc-m-rnd').checked = false; } });
  Q.ct = new Field('hqc-ct', { name: ['bản mã', 'Ciphertext'], need: function () { return hqcSz().ct; }, load: bytesLoader(HX),
    onEdit: function () { clear(Q.ss2); HX.msg = null; HX.update(); } });
  Q.ss = new Field('hqc-ss', { name: ['khoá chung K', 'Shared secret K'], need: function () { return 32; },
    onEdit: function () { HX.msg = null; HX.update(); } });
  Q.ss2 = new Field('hqc-ss2', { name: ['khoá chung K′', 'Shared secret K′'], need: function () { return 32; },
    onEdit: function () { HX.msg = null; HX.update(); } });
  HX.pk = Q.pk; HX.sk = Q.sk;
  HX.update = function () {
    var z = hqcSz(), pk = !!Q.pk.full(), sk = !!Q.sk.full(), ct = !!Q.ct.full(), ss = !!Q.ss.full(), ss2 = !!Q.ss2.full();
    var next = !pk ? 1 : (!ct ? 3 : (!ss2 ? 5 : 0));
    cards('hqc', [[1, pk && sk], [3, ct && ss], [5, ss2]], next);
    $('hqc-a2').classList.toggle('lit', pk); $('hqc-a4').classList.toggle('lit', ct);
    $('hqc-a2-txt').innerHTML = bi('khoá đóng gói ek, ' + num(z.pk) + ' byte, gửi cho bên gửi', 'encapsulation key ek, ' + num(z.pk) + ' bytes, to the sender');
    $('hqc-a4-txt').innerHTML = bi('bản mã c, ' + num(z.ct) + ' byte, gửi lại bên nhận', 'ciphertext c, ' + num(z.ct) + ' bytes, back to the receiver');
    var x = HX.msg, note = x && x.cls !== 'bad' && x.cls !== 'ok' ? x.html + (x.sub ? ' ' + x.sub : '') : '';
    if (x && (x.cls === 'bad' || x.cls === 'ok')) return show(HX.res, x.cls, x.html, x.sub);
    if (ss2) {
      if (!ss) return show(HX.res, 'info', 'i ' + bi('Đã tính K′. Ô K của bên gửi đang trống nên chưa có gì để so.', 'K′ computed. The sender\'s K field is empty, so there is nothing to compare with yet.'), note);
      if (T.eq(Q.ss.full(), Q.ss2.full()))
        return show(HX.res, 'ok', '✓ ' + bi('Hai khoá chung trùng nhau: bộ giải mã sửa lỗi bên nhận đã khôi phục đúng thông điệp m.', 'The shared secrets match: the receiver\'s error-correcting decoder recovered m correctly.'), note);
      return show(HX.res, 'bad', '✕ ' + bi('Hai khoá chung KHÁC nhau. Bản mã hoặc khoá đã bị đổi. HQC không báo lỗi mà trả về một khoá không liên quan — <em>từ chối ngầm</em>.',
        'The shared secrets do NOT match. The ciphertext or a key was changed. HQC raises no error and returns an unrelated key instead — <em>implicit rejection</em>.'), note);
    }
    var L = {
      1: bi('Bắt đầu với bước 1: bên nhận sinh (hoặc nạp) một cặp khoá.', 'Start with step 1: the receiver generates (or loads) a key pair.'),
      3: bi('Tiếp theo: bước 3 — bên gửi đóng gói tới khoá công khai.', 'Next: step 3 — the sender encapsulates to the public key.'),
      5: bi('Tiếp theo: bước 5 — bên nhận giải đóng gói bản mã.', 'Next: step 5 — the receiver decapsulates the ciphertext.')
    };
    show(HX.res, 'info', '→ ' + L[next], note);
  };
  function hqcLevel(quiet) {
    clear(Q.pk, Q.ct, Q.ss, Q.ss2);
    var b = Q.m.peek(); if (b && b.length && b.length !== hqcSz().m) clear(Q.m);
    [Q.sk, Q.pk, Q.m, Q.salt, Q.ct, Q.ss, Q.ss2].forEach(function (f) { f.count(); });
    HX.kat = null;
    HX.msg = quiet ? null : { cls: 'note', html: bi('Đã chuyển sang ' + hqcSet() + ': khoá đóng gói và bản mã cũ đã được xoá vì độ dài khác.', 'Switched to ' + hqcSet() + ': the old encapsulation key and ciphertext were cleared because the sizes differ.') };
    pairLater(HX); HX.update();
  }
  onRadio('hqc-set', function () { hqcLevel(false); });
  $('hqc-clear').addEventListener('click', function () { clear(Q.sk, Q.pk, Q.m, Q.salt, Q.ct, Q.ss, Q.ss2); HX.msg = null; HX.kat = null; pairLater(HX); HX.update(); });
  function hqcKeygen() {
    var dk = randomOrField('hqc-seed-rnd', Q.sk, 32, HX.fail, bi('Ô dk đang trống: đánh dấu "seed ngẫu nhiên" hoặc nhập 32 byte.', 'The dk field is empty: tick "random seed" or enter 32 bytes.'));
    if (!dk) return null;
    var t0 = performance.now(), kp = window.HQC.keygenInternal(hqcSet(), dk), t = performance.now() - t0;
    Q.pk.set(kp.ek); clear(Q.ct, Q.ss, Q.ss2); pairLater(HX);
    return t;
  }
  $('hqc-keygen').addEventListener('click', function () {
    HX.kat = null;
    var t = hqcKeygen();
    if (t !== null) HX.note(bi('Đã sinh cặp khoá ' + hqcSet() + '. Khoá giải đóng gói chính là 32 byte seed.', 'Generated an ' + hqcSet() + ' key pair. The decapsulation key is the 32-byte seed itself.') + ms(t));
  });
  $('hqc-kat').addEventListener('click', function () {
    var v = V.hqc.kat[hqcSet()];
    $('hqc-seed-rnd').checked = false; Q.sk.set(unhex(v.seed_kem));
    $('hqc-m-rnd').checked = false; Q.m.set(unhex(v.m)); Q.salt.set(unhex(v.salt));
    var t = hqcKeygen(), ok = sha(Q.pk.full()) === v.ek_sha256 && T.toHex(Q.sk.full()) === v.dk;
    HX.kat = v;
    HX.note((ok ? '✓ ' : '✕ ') + (ok ? bi('dk, m và muối của mục KAT chính thức count = 0 đã được điền. Khoá đóng gói sinh ra trùng file KAT của HQC 5.1.0.',
      'The dk, m and salt of the official KAT entry count = 0 are filled in. The encapsulation key generated matches the HQC 5.1.0 KAT file.')
      : bi('Khoá sinh ra KHÁC file KAT chính thức.', 'The key generated DIFFERS from the official KAT file.')),
      (ok ? bi('Bấm Đóng gói để thấy bản mã và khoá chung cũng trùng.', 'Press Encapsulate to see the ciphertext and shared secret match too.') : '') + ms(t), ok ? 'ok' : 'bad');
  });
  $('hqc-encaps').addEventListener('click', function () {
    var z = hqcSz(), ek = need(Q.pk, HX.fail, bi('Chưa có khoá đóng gói: làm bước 1, hoặc dán / nạp một khoá.', 'No encapsulation key yet: do step 1, or paste / load a key.'), z.pk);
    if (!ek) return;
    var m, salt;
    if ($('hqc-m-rnd').checked) { m = PH.randomBytes(z.m); salt = PH.randomBytes(16); Q.m.set(m); Q.salt.set(salt); }
    else {
      if (!(m = need(Q.m, HX.fail, bi('Ô m đang trống: đánh dấu "m và muối ngẫu nhiên" hoặc nhập ' + z.m + ' byte.', 'The m field is empty: tick "random m and salt" or enter ' + z.m + ' bytes.'), z.m))) return;
      if (!(salt = need(Q.salt, HX.fail, bi('Ô muối đang trống: nhập 16 byte.', 'The salt field is empty: enter 16 bytes.'), 16))) return;
    }
    var t0 = performance.now(), en = window.HQC.encapsInternal(hqcSet(), ek, m, salt), t = performance.now() - t0;
    Q.ct.set(en.ct); Q.ss.set(en.K); clear(Q.ss2);
    var v = HX.kat;
    if (v && sha(ek) === v.ek_sha256 && T.toHex(m) === v.m && T.toHex(salt) === v.salt) {
      var ok = sha(en.ct) === v.ct_sha256 && T.toHex(en.K) === v.ss;
      return HX.note((ok ? '✓ ' : '✕ ') + (ok ? bi('Đã đóng gói. Bản mã và khoá chung trùng từng byte với mục KAT chính thức count = 0.', 'Encapsulated. The ciphertext and shared secret equal, byte for byte, the official KAT entry count = 0.')
        : bi('Bản mã hoặc khoá chung KHÁC mục KAT chính thức.', 'The ciphertext or shared secret DIFFERS from the official KAT entry.')), ms(t), ok ? 'ok' : 'bad');
    }
    HX.note(bi('Đã đóng gói.', 'Encapsulated.') + ms(t));
  });
  $('hqc-decaps').addEventListener('click', function () {
    var z = hqcSz(), dk = need(Q.sk, HX.fail, bi('Chưa có khoá giải đóng gói: làm bước 1, hoặc dán / nạp một khoá.', 'No decapsulation key yet: do step 1, or paste / load a key.'), 32);
    if (!dk) return;
    var ct = need(Q.ct, HX.fail, bi('Chưa có bản mã: làm bước 3 trước.', 'No ciphertext yet: do step 3 first.'));
    if (!ct) return;
    if (ct.length !== z.ct) return HX.fail(bi('Bản mã dài ' + num(ct.length) + ' byte, ' + hqcSet() + ' cần ' + num(z.ct) + ' byte.', 'The ciphertext is ' + num(ct.length) + ' bytes; ' + hqcSet() + ' needs ' + num(z.ct) + '.'));
    var t0 = performance.now(), de = window.HQC.decaps(hqcSet(), dk, ct), t = performance.now() - t0;
    Q.ss2.set(de.K);
    HX.note(bi('Đã giải đóng gói.', 'Decapsulated.') + ms(t));
  });
  $('hqc-flip').addEventListener('click', function () {
    var ct = Q.ct.peek();
    if (!ct || !ct.length) return HX.fail(bi('Chưa có bản mã để lật bit.', 'There is no ciphertext to flip a bit in.'));
    ct[0] ^= 1; Q.ct.set(ct); clear(Q.ss2);
    HX.note(bi('Đã lật bit đầu tiên của bản mã. Bấm Giải đóng gói để xem chuyện gì xảy ra.', 'The first bit of the ciphertext was flipped. Press Decapsulate to see what happens.'));
  });

  /* ================================================================ bộ chuyển đổi */
  var cvt = { kind: '' };
  var KIND = { hex: ['hex', 'hex'], c: ['mảng C', 'C array'], java: ['mảng Java', 'Java array'], dec: ['mảng thập phân', 'decimal array'] };
  var C = {};
  C.inp = new Field('cvt-in', { name: ['dữ liệu vào', 'Input'], fmts: [],
    parse: function (s) {
      var m = checked('cvt-in');
      if (m === 'auto') { var r = T.parseAuto(s); cvt.kind = r.kind; return r.bytes; }
      cvt.kind = ''; return T.parseInput(s, m);
    },
    load: function (f, bytes, name, err) {
      if (err) return show($('cvt-result'), 'bad', '✕ ' + msg(err));
      setRadio('cvt-in', 'auto'); f.ta.value = T.format(bytes, 'hex'); cvtUpdate();
    },
    onEdit: function () { cvtUpdate(); } });
  C.out = new Field('cvt-out', { name: ['kết quả', 'Result'], fmts: [], parse: function () { return cvt.last || new Uint8Array(0); } });
  function cvtUpdate() {
    var el = $('cvt-result'), b, s, out = checked('cvt-out');
    C.inp.count();
    try { b = C.inp.bytes(); } catch (e) { cvt.last = null; C.out.ta.value = ''; C.out.count(); return show(el, 'bad', '✕ ' + C.inp.err(e)); }
    try { s = T.format(b, out); } catch (e) { cvt.last = null; C.out.ta.value = ''; C.out.count(); return show(el, 'bad', '✕ ' + bi('Kết quả ', 'The result ') + msg(e)); }
    cvt.last = b; C.out.ta.value = s; C.out.count();
    var k = KIND[cvt.kind];
    show(el, 'info', k ? bi('Nhận ra: ' + k[0] + ' · ' + num(b.length) + ' byte.', 'Detected: ' + k[1] + ' · ' + num(b.length) + ' bytes.')
      : bi(num(b.length) + ' byte.', num(b.length) + ' bytes.'));
  }
  onRadio('cvt-in', cvtUpdate); onRadio('cvt-out', cvtUpdate);
  $('cvt-use').addEventListener('click', function () {
    var out = checked('cvt-out');
    if (!cvt.last) return;
    C.inp.ta.value = C.out.ta.value;
    setRadio('cvt-in', out === 'base64' ? 'base64' : (out === 'text' ? 'text' : 'auto'));
    cvtUpdate();
  });

  /* ================================================================ thẻ */
  var TABS = ['slh', 'fn', 'hqc', 'cvt'];
  function selectTab(k) {
    TABS.forEach(function (t) { $('tab-' + t).setAttribute('aria-selected', String(t === k)); $('panel-' + t).hidden = t !== k; });
  }
  TABS.forEach(function (t) { $('tab-' + t).addEventListener('click', function () { selectTab(t); }); });

  /* ================================================================ tự kiểm chứng (SHA-256 của trình duyệt, không phải của trang) */
  async function sha256hex(b) { return T.toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', b.slice().buffer))); }
  function tick() { return new Promise(function (r) { setTimeout(r, 0); }); }
  $('bt-selftest').addEventListener('click', async function () {
    var st = $('st-status'), det = $('st-detail'), btn = $('bt-selftest'), lines = [], pass = 0, total = 0, g = null, groups = [];
    st.className = 'pill wait'; st.innerHTML = bi('đang chạy…', 'running…');
    det.hidden = false; det.textContent = ''; btn.disabled = true;
    await tick();
    if (!window.crypto || !crypto.subtle) {
      btn.disabled = false; st.className = 'pill bad'; st.innerHTML = bi('trình duyệt không có crypto.subtle', 'this browser has no crypto.subtle'); return;
    }
    function group(vi, en) { g = { vi: vi, en: en, pass: 0, total: 0 }; groups.push(g); }
    function chk(label, got, want) {
      total++; g.total++;
      if (got === want) { pass++; g.pass++; } else lines.push('FAIL ' + label + '\n  got  ' + got + '\n  want ' + want);
    }
    function flush() {
      det.innerHTML = groups.map(function (x) { return bi(x.vi, x.en) + nb(': ' + x.pass + '/' + x.total); }).join('\n') +
        (lines.length ? '\n\n' + nb(esc(lines.join('\n'))) : '');
    }
    var SL = window.SLHDSA, FN = window.FNDSA, HQ = window.HQC, name, v, i;
    try {
      group('SLH-DSA: vector ACVP keyGen của NIST (sáu bộ "f")', 'SLH-DSA: NIST ACVP keyGen vectors (the six "f" sets)');
      for (i = 0; i < V.slh.keygen.length; i++) {
        v = V.slh.keygen[i];
        if (v.slow) continue;
        var n = NT.info('slh', v.set).n, sd = unhex(v.seed), kp = SL.keygenInternal(v.set, sd.subarray(0, n), sd.subarray(n, 2 * n), sd.subarray(2 * n));
        chk(v.set + ' pk', await sha256hex(kp.pk), v.pk_sha256);
        chk(v.set + ' sk', await sha256hex(kp.sk), v.sk_sha256);
        flush(); await tick();
      }
      group('SLH-DSA: vector ACVP sigGen của NIST', 'SLH-DSA: NIST ACVP sigGen vectors');
      for (i = 0; i < V.slh.sign.length; i++) {
        v = V.slh.sign[i];
        var sig = SL.sign(v.set, unhex(v.message), unhex(v.context), unhex(v.sk), v.deterministic ? null : unhex(v.addrnd), v.preHash === 'preHash' ? v.hashAlg : null);
        chk(v.set + ' ' + v.preHash + ' sig', await sha256hex(sig), v.sig_sha256);
        flush(); await tick();
      }
      group('FN-DSA: mục KAT chính thức count = 0 (Falcon vòng 3)', 'FN-DSA: official KAT entry count = 0 (Falcon round 3)');
      for (name in V.fn.kat) {
        v = V.fn.kat[name];
        var fk = FN.keygen(name, unhex(v.kseed)), fs = FN.sign(name, fk.sk, unhex(v.msg), unhex(v.salt), unhex(v.sseed)).sig;
        chk(name + ' pk', await sha256hex(fk.pk), v.pk_sha256);
        chk(name + ' sk', await sha256hex(fk.sk), v.sk_sha256);
        chk(name + ' sig', await sha256hex(fs), v.sig_sha256);
        chk(name + ' verify', FN.verify(name, fk.pk, unhex(v.msg), fs).ok, true);
        flush(); await tick();
      }
      group('FN-DSA: seed cố định, chữ ký sai', 'FN-DSA: fixed seed, wrong signatures');
      for (name in V.fn.det) {
        v = V.fn.det[name];
        var dk2 = FN.keygen(name, unhex(v.kseed)), ds = FN.sign(name, dk2.sk, unhex(v.msg), unhex(v.salt), unhex(v.sseed)).sig;
        chk(name + ' pk', await sha256hex(dk2.pk), v.pk_sha256);
        chk(name + ' sk', await sha256hex(dk2.sk), v.sk_sha256);
        chk(name + ' sig', await sha256hex(ds), v.sig_sha256);
        var bad = Uint8Array.from(ds); bad[60] ^= 1;
        chk(name + ' flipped signature', FN.verify(name, dk2.pk, unhex(v.msg), bad).ok, false);
        flush(); await tick();
      }
      group('HQC-KEM: mục KAT chính thức count = 0 (HQC 5.1.0)', 'HQC-KEM: official KAT entry count = 0 (HQC 5.1.0)');
      for (name in V.hqc.kat) {
        v = V.hqc.kat[name];
        var hk = HQ.keygenInternal(name, unhex(v.seed_kem)), he = HQ.encapsInternal(name, hk.ek, unhex(v.m), unhex(v.salt));
        chk(name + ' ek', await sha256hex(hk.ek), v.ek_sha256);
        chk(name + ' dk', T.toHex(hk.dk), v.dk);
        chk(name + ' ct', await sha256hex(he.ct), v.ct_sha256);
        chk(name + ' K', T.toHex(he.K), v.ss);
        chk(name + ' decaps', T.toHex(HQ.decaps(name, hk.dk, he.ct).K), v.ss);
        flush(); await tick();
      }
      group('HQC-KEM: seed cố định, từ chối ngầm', 'HQC-KEM: fixed seed, implicit rejection');
      for (name in V.hqc.det) {
        v = V.hqc.det[name];
        var qk = HQ.keygenInternal(name, unhex(v.seed_kem)), qe = HQ.encapsInternal(name, qk.ek, unhex(v.m), unhex(v.salt));
        chk(name + ' ek', await sha256hex(qk.ek), v.ek_sha256);
        chk(name + ' ct', await sha256hex(qe.ct), v.ct_sha256);
        chk(name + ' K', T.toHex(qe.K), v.K);
        var qb = Uint8Array.from(qe.ct); qb[v.ct_flip_byte] ^= 1;
        chk(name + ' implicit rejection', T.toHex(HQ.decaps(name, qk.dk, qb).K), v.K_reject);
        flush(); await tick();
      }
      group('Bộ chuyển đổi dữ liệu', 'Data converter');
      V.codec.forEach(function (c) {
        var got; try { got = T.toHex(T.parseInput(c.in, c.fmt)); } catch (e) { got = 'error ' + e.code; }
        chk(c.fmt + ' ' + c.in, got, c.out);
      });
    } catch (e) { if (g) chk('exception', String(e && e.message), 'none'); }
    flush(); btn.disabled = false;
    st.className = 'pill ' + (pass === total ? 'ok' : 'bad');
    st.innerHTML = nb(pass + '/' + total) + ' ' + (pass === total ? bi('phép kiểm khớp', 'checks match') : bi('phép kiểm — CÓ LỖI', 'checks — FAILED'));
  });

  /* ================================================================ khởi động */
  slhPhSync(true); slhName(); slhMp(); fnMp(); SX.update(); FX.update(); HX.update(); cvtUpdate();
  window.NIST3Calc = {                                  // cửa cho bộ kiểm thử tự động; trang không tự dùng
    S: S, F: Fd, Q: Q, C: C,
    loadKey: function (tab, bytes, name, prefer) { keyLoader({ slh: SX, fn: FX, hqc: HX }[tab], prefer)(null, bytes, name); },
    loadBytes: function (field, bytes, name) { bytesLoader(field.id.indexOf('slh') === 0 ? SX : (field.id.indexOf('fn') === 0 ? FX : HX))(field, bytes, name); },
    loadMsg: function (tab, bytes, name) { msgLoader(tab === 'slh' ? SX : FX)(tab === 'slh' ? S.msg : Fd.msg, bytes, name); },
    flush: function () {
      ['slh', 'fn', 'hqc'].forEach(function (k) { clearTimeout(pairTimer[k]); delete pairTimer[k]; });
      return Promise.all([pairNow(SX), pairNow(FX), pairNow(HX)]).then(function () { return idle(); });
    },
    idle: idle, worker: function () { return !!worker; }
  };
  function idle() { return pending ? new Promise(function (r) { idleWaiters.push(r); }) : Promise.resolve(); }
})();
