/* Giao diện máy tính KpqC: ba thẻ (trao đổi khoá SMAUG-T, ký / xác minh HAETAE, chuyển đổi dữ liệu), cùng cách
   tương tác với máy tính ML-KEM / ML-DSA: ô dữ liệu có bộ đếm byte và nút định dạng, nạp file khoá thô, dòng kiểm
   tra cặp khoá, ví dụ KAT chính thức, nút tự kiểm chứng. Mọi chuỗi hiển thị có hai bản qua bi(vi, en).
   Original implementation for the ChiU·SoC PQC demo page. */
(function () {
  'use strict';
  var T = window.PQCTools, KT = window.KPQCTools, V = window.KPQC_VECTORS, SM = window.SMAUGT, HA = window.HAETAE, PH = window.PQCHash;

  /* ================================================================ tiện ích */
  function $(id) { var e = document.getElementById(id); if (!e) throw new Error('missing #' + id); return e; }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function bi(vi, en) { return '<span lang="vi">' + vi + '</span><span lang="en">' + en + '</span>'; }
  function nb(s) { return '<span data-i18n="neutral">' + s + '</span>'; }
  function num(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ' '); }
  function fill(s, a) { return s.replace(/\{(\w+)\}/g, function (m, k) { return a && a[k] !== undefined && a[k] !== null ? esc(a[k]) : m; }); }
  function timed(fn) { var t0 = performance.now(); var r = fn(); return { r: r, t: performance.now() - t0 }; }
  function ms(t) { return nb(' · ' + t.toFixed(1) + ' ms'); }
  function checked(name) { var r = document.querySelector('input[name="' + name + '"]:checked'); return r ? r.value : null; }
  function radios(name) { return Array.prototype.slice.call(document.querySelectorAll('input[name="' + name + '"]')); }
  function onRadio(name, fn) { radios(name).forEach(function (r) { r.addEventListener('change', fn); }); }
  function setRadio(name, v) { radios(name).forEach(function (r) { r.checked = r.value === v; }); }
  function unhex(s) { return T.parseHex(s); }
  function sha(b) { return T.toHex(window.PQCSHA2.sha256(b)); }
  function show(el, cls, main, sub) {
    el.className = 'result ' + cls;
    el.innerHTML = main + (sub ? '<span class="sub">' + sub + '</span>' : '');
  }

  /* thông báo lỗi theo mã (PQCTools / KPQCTools ném Error có .code) */
  var MSG = {
    HEX_CHAR: ['có ký tự không phải hex', 'contains a character that is not hex'],
    HEX_ODD: ['có số chữ số hex lẻ', 'has an odd number of hex digits'],
    B64: ['không phải Base64 hợp lệ', 'is not valid Base64'],
    ARRAY_ITEM: ['có phần tử mảng "{item}" không phải là số', 'has an array item "{item}" that is not a number'],
    ARRAY_RANGE: ['có phần tử {item} nằm ngoài khoảng byte -128 … 255', 'has an item {item} outside the byte range -128 … 255'],
    ARRAY_CLOSE: ['thiếu dấu "{close}" ở cuối mảng', 'is missing the closing "{close}" of the array'],
    AUTO: ['không phải hex hay mảng; với dữ liệu khác hãy chọn Base64 hoặc Văn bản', 'is neither hex nor an array; pick Base64 or Text for other data'],
    NOT_UTF8: ['chứa các byte không phải văn bản UTF-8, hãy xem ở dạng hex', 'holds bytes that are not UTF-8 text; view them as hex'],
    OTHER_TAB: ['{len} byte khớp kích thước khoá {alg}. Hãy nạp ở thẻ "{tabvi}".', '{len} bytes matches the size of an {alg} key. Load it in the "{taben}" tab.'],
    OTHER_PAGE: ['File này chứa khoá {alg}. Hãy dùng máy tính ML-KEM / ML-DSA.', 'This file holds an {alg} key. Use the ML-KEM / ML-DSA calculator.'],
    UNSUPPORTED_ALG: ['File này chứa khoá của một thuật toán khác (OID {alg}), không phải SMAUG-T hay HAETAE.', 'This file holds a key of another algorithm (OID {alg}), not SMAUG-T or HAETAE.'],
    ENCRYPTED: ['Khoá này được mã hoá bằng mật khẩu, trang chưa đọc được.', 'This key is password-encrypted, which the page cannot read.'],
    PKCS12: ['File PKCS#12 (.pfx / .p12) chưa được hỗ trợ.', 'PKCS#12 files (.pfx / .p12) are not supported.'],
    NO_SIZE_MATCH: ['{len} byte không khớp kích thước khoá nào của SMAUG-T hay HAETAE.', '{len} bytes matches no SMAUG-T or HAETAE key size.'],
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
    if (e && e.code === 'OTHER_TAB') { a.tabvi = a.tab === 'kem' ? 'Trao đổi khoá' : 'Ký & xác minh'; a.taben = a.tab === 'kem' ? 'Key exchange' : 'Sign & verify'; }
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

  /* ================================================================ ô dữ liệu (giống máy tính ML-KEM / ML-DSA) */
  var FMT = { hex: ['Hex', 'Hex'], base64: ['Base64', 'Base64'], c: ['C', 'C'], java: ['Java', 'Java'], text: ['Văn bản', 'Text'] };
  function tool(box, html, fn) {
    var b = document.createElement('button');
    b.type = 'button'; b.innerHTML = html; b.addEventListener('click', fn); box.appendChild(b);
    return b;
  }
  function Field(id, o) {
    var f = this;
    f.id = id; f.ta = $(id); f.cnt = $(id + '-cnt'); f.tools = $(id + '-tools');
    f.name = o.name; f.fmt = o.fmt || 'hex'; f.need = o.need || null; f.max = o.max || null;
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
  function looksText(b) { for (var i = 0; i < b.length; i++) { var x = b[i]; if (!(x === 9 || x === 10 || x === 13 || (x >= 32 && x < 127))) return false; } return true; }
  function bytesLoader(report) {
    return function (f, bytes, name, err) {
      if (err) return report.fail(msg(err));
      var b = bytes;
      if (looksText(bytes)) {
        var s = String.fromCharCode.apply(null, Array.prototype.slice.call(bytes, 0));
        try { b = T.parseAuto(s).bytes; } catch (e) { try { b = T.parseB64(s); } catch (e2) { b = bytes; } }
      }
      f.set(b); f.edited();
      report.note(bi('Đã nạp ' + num(b.length) + ' byte từ ' + esc(name) + ' vào ô ' + f.name[0] + '.',
        'Loaded ' + num(b.length) + ' bytes from ' + esc(name) + ' into the ' + f.name[1] + ' field.'));
    };
  }

  /* ================================================================ kiểm tra cặp khoá */
  var ROW = {
    len: ['Độ dài hai khoá đúng với bộ tham số', 'Both keys have the right length for the parameter set'],
    pk_check: ['Khoá công khai đúng độ dài (SMAUG-T không có kiểm tra nào khác: mọi chuỗi bit đều là một khoá hợp lệ)', 'The public key has the right length (SMAUG-T has no other check: every bit string is a valid key)'],
    sk_check: ['Khoá bí mật: mã 2 bit hợp lệ và mỗi đa thức có đúng h_s hệ số khác 0', 'The private key: valid 2-bit codes and exactly h_s non-zero coefficients per polynomial'],
    derived_pk: ['Khoá công khai lưu trong khoá bí mật trùng ô khoá công khai', 'The public key stored inside the private key equals the Public key field'],
    roundtrip_kem: ['Khứ hồi: đóng gói tới khoá công khai, giải bằng khoá bí mật, hai khoá chung trùng nhau', 'Round trip: encapsulate to the public key, decapsulate with the private key, the secrets match'],
    roundtrip_sig: ['Khứ hồi: ký bằng khoá bí mật, xác minh bằng khoá kiểm tra', 'Round trip: sign with the private key, verify with the verification key'],
    seed: ['Seed trong ô Seed sinh ra đúng cặp khoá này (chỉ để thông tin)', 'The seed in the Seed field generates exactly this key pair (for information)'],
    seed_null: ['Ô Seed chưa đủ độ dài nên bỏ qua', 'The Seed field is not full length, so it was skipped']
  };
  var STATE = {
    match: ['ok', '✓', 'Khoá khớp: khoá bí mật thuộc về khoá công khai này.', 'Keys match: the private key belongs to this public key.'],
    other: ['bad', '✕', 'Khoá không khớp: khoá bí mật thuộc về một cặp khoá khác.', 'Keys do not match: the private key belongs to a different key pair.'],
    corrupt: ['bad', '✕', 'Khoá bí mật bị hỏng: nó không qua một phép kiểm nhất quán.', 'The private key is corrupted: it fails a consistency check.'],
    missing: ['', 'i', 'Cần cả hai khoá, đủ độ dài, để kiểm tra cặp.', 'Both keys, at full length, are needed to check the pair.']
  };
  var pending = {};
  function pairLater(tab, fn) { clearTimeout(pending[tab]); pending[tab] = setTimeout(function () { delete pending[tab]; fn(); }, 120); }
  function renderPair(el, kem, res) {
    var st = STATE[res.state], seedRow = null, li = res.rows.map(function (r) {
      var key = r[0] === 'roundtrip' ? (kem ? 'roundtrip_kem' : 'roundtrip_sig') : (r[0] === 'seed' && r[1] === null ? 'seed_null' : r[0]);
      if (r[0] === 'seed') seedRow = r[1];
      return '<li><b>' + (r[1] === null ? '—' : (r[1] ? '✓' : '✕')) + '</b>' + bi(ROW[key][0], ROW[key][1]) + '</li>';
    });
    var extra = res.state === 'match' && seedRow === false ?
      ' ' + bi('Riêng seed trong ô Seed sinh ra một cặp khoá khác.', 'The seed in the Seed field, though, generates a different key pair.') : '';
    el.className = 'pairline ' + st[0];
    el.innerHTML = '<span class="st">' + st[1] + ' ' + bi(st[2], st[3]) + '</span>' + extra +
      '<details><summary>' + bi('chi tiết', 'details') + '</summary><ul>' + li.join('') + '</ul></details>';
  }

  /* ================================================================ nạp file khoá (khoá thô) */
  var ENC = { DER: ['nhị phân', 'binary'], hex: ['hex', 'hex'], base64: ['Base64', 'Base64'] };
  function keyLoader(X) {
    return function (f, bytes, name, err) {
      if (err) return X.fail(msg(err));
      var items, alg;
      try { items = T.readKeyFile(bytes, name); alg = KT.identify(items, X.family, X.set()); }
      catch (e) { return X.fail(msg(e)); }
      var multi = items.some(function (it) { return it.notes.indexOf('MULTI_MATCH') >= 0; });
      if (alg !== X.set()) X.setLevel(alg, true);
      var got = [], pub = null, priv = null;
      items.forEach(function (it) {
        var e = ENC[it.enc] || ENC.DER;
        if (it.kind === 'public') { X.pk.set(it.data); pub = it; got.push(['khoá công khai (khoá thô, ' + e[0] + ')', 'public key (raw, ' + e[1] + ')']); }
        else { X.sk.set(it.data); priv = it; got.push(['khoá bí mật (khoá thô, ' + e[0] + ')', 'private key (raw, ' + e[1] + ')']); }
      });
      var derived = false;
      if (priv) {
        X.seed.set(null);
        if (!pub) { X.pk.set(X.family === 'kem' ? SM.pkFromSk(alg, priv.data) : HA.pkFromSk(alg, priv.data)); derived = true; }
      }
      X.keysLoaded();
      var vi = got.map(function (g) { return g[0]; }).join(' và '), en = got.map(function (g) { return g[1]; }).join(' and ');
      var sub = (derived ? bi('Khoá công khai được lấy từ bản lưu bên trong khoá bí mật. ', 'The public key was taken from the copy stored inside the private key. ') : '') +
        (multi ? bi('Độ dài này khớp nhiều bộ tham số (TiMER và SMAUG-T128 có khoá cùng kích thước); đã chọn ' + alg + '. Nếu sai, hãy chọn mức đúng rồi nạp lại.',
          'This length matches several parameter sets (TiMER and SMAUG-T128 keys have the same sizes); ' + alg + ' was chosen. If that is wrong, select the right level and load again.') : '');
      X.note(bi('Đã nạp ' + vi + ' của ' + alg + ' từ ' + esc(name) + '.', 'Loaded the ' + alg + ' ' + en + ' from ' + esc(name) + '.'), sub);
    };
  }

  /* ================================================================ thẻ SMAUG-T */
  var kem = { msg: null, res: $('kem-result'), kat: null };
  function kemSet() { return checked('kem-set'); }
  function kemSz() { return KT.info(kemSet()); }
  var KX = {
    tab: 'kem', family: 'kem', set: kemSet, seedRnd: 'kem-seed-rnd',
    fail: function (html) { kem.msg = { cls: 'bad', html: '✕ ' + html }; kemUpdate(); },
    note: function (html, sub, cls) { kem.msg = { cls: cls || 'note', html: html, sub: sub }; kemUpdate(); },
    setLevel: function (name, quiet) { setRadio('kem-set', name); kemLevel(quiet); },
    keysLoaded: function () { clear(K.ct, K.ss, K.ss2); kemPair(); }
  };
  var K = {};
  K.seed = new Field('kem-seed', { name: ['Seed', 'Seed'], need: function () { return 64; }, load: bytesLoader(KX),
    onEdit: function () { $('kem-seed-rnd').checked = false; kemPair(); } });
  K.pk = new Field('kem-pk', { name: ['khoá công khai', 'Public key'], need: function () { return kemSz().pk; }, load: keyLoader(KX),
    onEdit: function () { clear(K.ct, K.ss, K.ss2); kem.msg = null; kemPair(); kemUpdate(); } });
  K.sk = new Field('kem-sk', { name: ['khoá bí mật', 'Private key'], need: function () { return kemSz().sk; }, load: keyLoader(KX),
    onEdit: function () { clear(K.ss2); kem.msg = null; kemPair(); kemUpdate(); } });
  K.m = new Field('kem-m', { name: ['μ', 'μ'], need: function () { return kemSz().msg; }, load: bytesLoader(KX),
    onEdit: function () { $('kem-m-rnd').checked = false; } });
  K.ct = new Field('kem-ct', { name: ['bản mã', 'Ciphertext'], need: function () { return kemSz().ct; }, load: bytesLoader(KX),
    onEdit: function () { clear(K.ss2); kem.msg = null; kemUpdate(); } });
  K.ss = new Field('kem-ss', { name: ['khoá chung K', 'Shared secret K'], need: function () { return 32; },
    onEdit: function () { kem.msg = null; kemUpdate(); } });
  K.ss2 = new Field('kem-ss2', { name: ['khoá chung K′', 'Shared secret K′'], need: function () { return 32; },
    onEdit: function () { kem.msg = null; kemUpdate(); } });
  KX.pk = K.pk; KX.sk = K.sk; KX.seed = K.seed;

  function kemPairNow() {
    var el = $('kem-pair');
    if (K.pk.empty() && K.sk.empty()) { el.className = 'pairline'; el.innerHTML = ''; return; }
    var seed = K.seed.empty() ? null : K.seed.peek();
    renderPair(el, true, KT.pairCheck(kemSet(), K.pk.peek(), K.sk.peek(), seed));
  }
  function kemPair() { pairLater('kem', kemPairNow); }
  function kemUpdate() {
    var z = kemSz(), pk = !!K.pk.full(), sk = !!K.sk.full(), ct = !!K.ct.full(), ss = !!K.ss.full(), ss2 = !!K.ss2.full();
    var next = !pk ? 1 : (!ct ? 3 : (!ss2 ? 5 : 0));
    [[1, pk && sk], [3, ct && ss], [5, ss2]].forEach(function (c) {
      var card = $('kem-c' + c[0]);
      card.classList.toggle('done', c[1]); card.classList.toggle('next', next === c[0]);
    });
    $('kem-a2').classList.toggle('lit', pk); $('kem-a4').classList.toggle('lit', ct);
    $('kem-a2-txt').innerHTML = bi('khoá công khai pk, ' + num(z.pk) + ' byte, gửi cho bên gửi', 'public key pk, ' + num(z.pk) + ' bytes, to the sender');
    $('kem-a4-txt').innerHTML = bi('bản mã ct, ' + num(z.ct) + ' byte, gửi lại bên nhận', 'ciphertext ct, ' + num(z.ct) + ' bytes, back to the receiver');
    var m = kem.msg, el = kem.res;
    if (m && (m.cls === 'bad' || m.cls === 'ok')) return show(el, m.cls, m.html, m.sub);
    var note = m ? m.html + (m.sub ? ' ' + m.sub : '') : '';
    if (ss2) {
      if (!ss) return show(el, 'info', 'i ' + bi('Đã tính K′. Ô K của bên gửi đang trống nên chưa có gì để so.', 'K′ computed. The sender\'s K field is empty, so there is nothing to compare with yet.'), note);
      if (T.eq(K.ss.full(), K.ss2.full()))
        return show(el, 'ok', '✓ ' + bi('Hai khoá chung trùng nhau: hai bên đã có cùng một bí mật 32 byte, và nó chưa từng đi trên đường truyền.',
          'The shared secrets match: both sides now hold the same 32-byte secret, and it never travelled.'), note);
      return show(el, 'bad', '✕ ' + bi('Hai khoá chung KHÁC nhau. Bản mã hoặc khoá đã bị đổi trên đường đi. SMAUG-T không báo lỗi mà trả về khoá G(d ‖ H(ct)) không liên quan — đó là <em>từ chối ngầm</em>.',
        'The shared secrets do NOT match. The ciphertext or a key was changed on the way. SMAUG-T raises no error and returns the unrelated key G(d ‖ H(ct)) instead — <em>implicit rejection</em>.'), note);
    }
    var L = {
      1: bi('Bắt đầu với bước 1: bên nhận sinh (hoặc nạp) một cặp khoá.', 'Start with step 1: the receiver generates (or loads) a key pair.'),
      3: bi('Tiếp theo: bước 3 — bên gửi đóng gói tới khoá công khai.', 'Next: step 3 — the sender encapsulates to the public key.'),
      5: bi('Tiếp theo: bước 5 — bên nhận giải đóng gói bản mã.', 'Next: step 5 — the receiver decapsulates the ciphertext.')
    };
    show(el, 'info', '→ ' + L[next], note);
  }
  function kemLevel(quiet) {
    clear(K.pk, K.sk, K.ct, K.ss, K.ss2);
    [K.seed, K.pk, K.sk, K.m, K.ct, K.ss, K.ss2].forEach(function (f) { f.count(); });
    if (!K.m.empty() && K.m.peek() && K.m.peek().length !== kemSz().msg) clear(K.m);
    kem.kat = null;
    kem.msg = quiet ? null : { cls: 'note', html: bi('Đã chuyển sang ' + kemSet() + ': khoá và bản mã cũ đã được xoá vì độ dài khác.', 'Switched to ' + kemSet() + ': the old keys and ciphertext were cleared because the sizes differ.') };
    kemPair(); kemUpdate();
  }
  onRadio('kem-set', function () { kemLevel(false); });
  $('kem-clear').addEventListener('click', function () {
    clear(K.seed, K.pk, K.sk, K.m, K.ct, K.ss, K.ss2); kem.msg = null; kem.kat = null; kemPair(); kemUpdate();
  });
  function kemKeygen() {
    var seed;
    if ($('kem-seed-rnd').checked) { seed = PH.randomBytes(64); K.seed.set(seed); }
    else if (!(seed = need(K.seed, KX.fail, bi('Ô Seed đang trống: đánh dấu "seed ngẫu nhiên" hoặc nhập 64 byte.', 'The Seed field is empty: tick "random seed" or enter 64 bytes.'), 64))) return null;
    var o = timed(function () { return SM.keygenInternal(kemSet(), seed.subarray(0, 32), seed.subarray(32, 64)); });
    K.pk.set(o.r.pk); K.sk.set(o.r.sk); clear(K.ct, K.ss, K.ss2);
    kemPair();
    return o;
  }
  $('kem-keygen').addEventListener('click', function () {
    kem.kat = null;
    var o = kemKeygen();
    if (o) KX.note(bi('Đã sinh cặp khoá ' + kemSet() + '.', 'Generated a ' + kemSet() + ' key pair.') + ms(o.t));
  });
  $('kem-kat').addEventListener('click', function () {
    var v = V.smaugt[kemSet()].kat;
    $('kem-seed-rnd').checked = false; K.seed.set(unhex(v.d + v.seed));
    $('kem-m-rnd').checked = false; K.m.set(unhex(v.mu));
    var o = kemKeygen(), ok = sha(K.pk.full()) === v.pk_sha256 && sha(K.sk.full()) === v.sk_sha256;
    kem.kat = v;
    KX.note((ok ? '✓ ' : '✕ ') + (ok ?
      bi('Seed và μ của mục KAT chính thức count = 0 đã được điền. Khoá công khai và khoá bí mật sinh ra trùng từng byte với file KAT của nhóm tác giả.',
        'The seed and μ of the official KAT entry count = 0 are filled in. The public and private keys generated equal, byte for byte, the authors\' KAT file.')
      : bi('Khoá sinh ra KHÁC file KAT chính thức.', 'The keys generated DIFFER from the official KAT file.')),
      (ok ? bi('Bấm Đóng gói để thấy bản mã và khoá chung cũng trùng.', 'Press Encapsulate to see the ciphertext and shared secret match too.') : '') + ms(o.t), ok ? 'ok' : 'bad');
  });
  $('kem-encaps').addEventListener('click', function () {
    var z = kemSz(), pk = need(K.pk, KX.fail, bi('Chưa có khoá công khai: làm bước 1, hoặc dán / nạp một khoá.', 'No public key yet: do step 1, or paste / load a key.'));
    if (!pk) return;
    if (pk.length !== z.pk) return KX.fail(bi('Khoá công khai dài ' + num(pk.length) + ' byte, ' + kemSet() + ' cần ' + num(z.pk) + ' byte.',
      'The public key is ' + num(pk.length) + ' bytes; ' + kemSet() + ' needs ' + num(z.pk) + '.'));
    var m;
    if ($('kem-m-rnd').checked) { m = PH.randomBytes(z.msg); K.m.set(m); }
    else if (!(m = need(K.m, KX.fail, bi('Ô μ đang trống: đánh dấu "μ ngẫu nhiên" hoặc nhập ' + z.msg + ' byte.', 'The μ field is empty: tick "random μ" or enter ' + z.msg + ' bytes.'), z.msg))) return;
    var o = timed(function () { return SM.encapsInternal(kemSet(), pk, m); });
    K.ct.set(o.r.ct); K.ss.set(o.r.K); clear(K.ss2);
    var v = kem.kat;
    if (v && sha(pk) === v.pk_sha256 && T.toHex(m) === v.mu) {
      var ok = sha(o.r.ct) === v.ct_sha256 && T.toHex(o.r.K) === v.ss;
      return KX.note((ok ? '✓ ' : '✕ ') + (ok ? bi('Đã đóng gói. Bản mã và khoá chung trùng từng byte với mục KAT chính thức count = 0.', 'Encapsulated. The ciphertext and shared secret equal, byte for byte, the official KAT entry count = 0.')
        : bi('Bản mã hoặc khoá chung KHÁC mục KAT chính thức.', 'The ciphertext or shared secret DIFFERS from the official KAT entry.')), ms(o.t), ok ? 'ok' : 'bad');
    }
    KX.note(bi('Đã đóng gói.', 'Encapsulated.') + ms(o.t));
  });
  $('kem-decaps').addEventListener('click', function () {
    var z = kemSz(), sk = need(K.sk, KX.fail, bi('Chưa có khoá bí mật: làm bước 1, hoặc dán / nạp một khoá.', 'No private key yet: do step 1, or paste / load a key.'), z.sk);
    if (!sk) return;
    var c = SM.skCheck(kemSet(), sk);
    if (c === 'CODE3') return KX.fail(bi('Khoá bí mật có mã 2 bit bằng 3, không ứng với hệ số −1, 0 hay +1 nào. Mã tham chiếu C không kiểm điều này; trang này từ chối.',
      'The private key contains a 2-bit code of 3, which stands for none of −1, 0, +1. The reference C code does not check this; this page refuses.'));
    if (c === 'WEIGHT') return KX.fail(bi('Một đa thức của khoá bí mật không có đúng h_s hệ số khác 0. Mã tham chiếu C không kiểm điều này; trang này từ chối.',
      'A polynomial of the private key does not have exactly h_s non-zero coefficients. The reference C code does not check this; this page refuses.'));
    var ct = need(K.ct, KX.fail, bi('Chưa có bản mã: làm bước 3 trước.', 'No ciphertext yet: do step 3 first.'));
    if (!ct) return;
    if (ct.length !== z.ct) return KX.fail(bi('Bản mã dài ' + num(ct.length) + ' byte, ' + kemSet() + ' cần ' + num(z.ct) + ' byte.',
      'The ciphertext is ' + num(ct.length) + ' bytes; ' + kemSet() + ' needs ' + num(z.ct) + '.'));
    var o = timed(function () { return SM.decapsInternal(kemSet(), sk, ct); });
    K.ss2.set(o.r.K);
    KX.note(bi('Đã giải đóng gói.', 'Decapsulated.') + ms(o.t));
  });
  $('kem-flip').addEventListener('click', function () {
    var ct = K.ct.peek();
    if (!ct || !ct.length) return KX.fail(bi('Chưa có bản mã để lật bit.', 'There is no ciphertext to flip a bit in.'));
    ct[0] ^= 1; K.ct.set(ct); clear(K.ss2);
    KX.note(bi('Đã lật bit đầu tiên của bản mã. Bấm Giải đóng gói để xem chuyện gì xảy ra.', 'The first bit of the ciphertext was flipped. Press Decapsulate to see what happens.'));
  });

  /* ================================================================ thẻ HAETAE */
  var dsa = { msg: null, res: $('dsa-result'), kat: null };
  function dsaSet() { return checked('dsa-set'); }
  function dsaSz() { return KT.info(dsaSet()); }
  var DX = {
    tab: 'dsa', family: 'sig', set: dsaSet, seedRnd: 'dsa-seed-rnd',
    fail: function (html) { dsa.msg = { cls: 'bad', html: '✕ ' + html }; dsaUpdate(); },
    note: function (html, sub, cls) { dsa.msg = { cls: cls || 'note', html: html, sub: sub }; dsaUpdate(); },
    setLevel: function (name, quiet) { setRadio('dsa-set', name); dsaLevel(quiet); },
    keysLoaded: function () { dsaPair(); }
  };
  function stale() { dsa.msg = null; dsaUpdate(); }
  function msgLoader(f, bytes, name, err) {
    if (err) return DX.fail(msg(err));
    var text = null;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (e) { text = null; }
    if (text !== null && /[\u0000-\u0008\u000e-\u001f]/.test(text)) text = null;
    if (text !== null) { f.fmt = 'text'; f.mark(); f.ta.value = text; f.count(); }
    else { f.fmt = 'hex'; f.mark(); f.set(bytes); }
    f.edited();
    DX.note(bi('Đã nạp ' + num(bytes.length) + ' byte từ ' + esc(name) + ' làm thông điệp.', 'Loaded ' + num(bytes.length) + ' bytes from ' + esc(name) + ' as the message.'));
  }
  var D = {};
  D.seed = new Field('dsa-seed', { name: ['Seed', 'Seed'], need: function () { return 32; }, load: bytesLoader(DX),
    onEdit: function () { $('dsa-seed-rnd').checked = false; dsaPair(); } });
  D.pk = new Field('dsa-pk', { name: ['khoá kiểm tra', 'Verification key'], need: function () { return dsaSz().pk; }, load: keyLoader(DX),
    onEdit: function () { dsaPair(); stale(); } });
  D.sk = new Field('dsa-sk', { name: ['khoá bí mật', 'Private key'], need: function () { return dsaSz().sk; }, load: keyLoader(DX),
    onEdit: function () { dsaPair(); stale(); } });
  D.msg = new Field('dsa-msg', { name: ['thông điệp', 'Message'], fmt: 'text', fmts: ['text', 'hex', 'base64', 'c', 'java'],
    load: msgLoader, onEdit: function () { mpUpdate(); stale(); } });
  D.ctx = new Field('dsa-ctx', { name: ['ngữ cảnh', 'Context'], fmt: 'text', fmts: ['text', 'hex'], max: 255,
    onEdit: function () { mpUpdate(); stale(); } });
  D.mp = new Field('dsa-mp', { name: ['M′', 'M′'] });
  D.rnd = new Field('dsa-rnd', { name: ['rnd', 'rnd'], need: function () { return 32; }, load: bytesLoader(DX),
    onEdit: function () { $('dsa-rnd-rnd').checked = false; } });
  D.sig = new Field('dsa-sig', { name: ['chữ ký', 'Signature'], need: function () { return dsaSz().sig; }, load: bytesLoader(DX),
    onEdit: function () { stale(); } });
  DX.pk = D.pk; DX.sk = D.sk; DX.seed = D.seed;

  function dsaPairNow() {
    var el = $('dsa-pair');
    if (D.pk.empty() && D.sk.empty()) { el.className = 'pairline'; el.innerHTML = ''; return; }
    var seed = D.seed.empty() ? null : D.seed.peek();
    renderPair(el, false, KT.pairCheck(dsaSet(), D.pk.peek(), D.sk.peek(), seed));
  }
  function dsaPair() { pairLater('dsa', dsaPairNow); }
  function preOf(c) { var p = new Uint8Array(c.length + 1); p[0] = c.length; p.set(c, 1); return p; }
  function mpUpdate() {
    var m = D.msg.peek(), c = D.ctx.peek();
    if (!m || !c || c.length > 255) return D.mp.set(null);
    var pre = preOf(c), out = new Uint8Array(pre.length + m.length);
    out.set(pre); out.set(m, pre.length);
    D.mp.set(out);
  }
  function ctxDesc() {
    var c = D.ctx.peek() || new Uint8Array(0);
    return c.length ? ['ngữ cảnh ' + num(c.length) + ' byte', num(c.length) + '-byte context'] : ['ngữ cảnh rỗng', 'empty context'];
  }
  var WHY = {
    siglen: ['chữ ký sai độ dài', 'the signature has the wrong length'],
    sizes: ['các phần nén bằng rANS khai báo kích thước không hợp lệ', 'the rANS-coded parts declare invalid sizes'],
    padding: ['phần đệm ở cuối chữ ký khác 0', 'the padding at the end of the signature is not zero'],
    norm: ['chuẩn của (z1, z2) vượt ngưỡng B″', 'the norm of (z1, z2) is over the bound B″'],
    challenge: ['thử thách c tính lại không trùng c trong chữ ký (khoá, thông điệp, ngữ cảnh khác lúc ký, hoặc chữ ký bị sửa)', 'the recomputed challenge c differs from the one in the signature (the key, message or context differs from signing time, or the signature was altered)'],
    rans: ['giải mã rANS thất bại', 'rANS decoding failed']
  };
  function dsaUpdate() {
    var pk = !!D.pk.full(), sk = !!D.sk.full(), m = !D.msg.empty() && !!D.msg.peek(), sig = !!D.sig.full();
    var next = !(pk || sk) ? 1 : (!m ? 2 : (!sig ? 3 : 0));
    [[1, pk && sk], [2, m], [3, sig]].forEach(function (c) {
      var card = $('dsa-c' + c[0]);
      card.classList.toggle('done', c[1]); card.classList.toggle('next', next === c[0]);
    });
    var x = dsa.msg, el = dsa.res;
    if (x && (x.cls === 'bad' || x.cls === 'ok')) return show(el, x.cls, x.html, x.sub);
    var note = x ? x.html + (x.sub ? ' ' + x.sub : '') : '';
    var L = {
      1: bi('Bắt đầu với bước 1: sinh (hoặc nạp) một cặp khoá.', 'Start with step 1: generate (or load) a key pair.'),
      2: bi('Tiếp theo: bước 2 — nhập thông điệp cần ký.', 'Next: step 2 — enter the message to sign.'),
      3: bi('Tiếp theo: bước 3 — bấm Ký.', 'Next: step 3 — press Sign.'),
      0: bi('Đã có chữ ký: bấm Xác minh.', 'There is a signature: press Verify.')
    };
    show(el, 'info', '→ ' + L[next], note);
  }
  function dsaLevel(quiet) {
    clear(D.pk, D.sk, D.sig);
    [D.seed, D.pk, D.sk, D.rnd, D.sig].forEach(function (f) { f.count(); });
    dsa.kat = null;
    dsa.msg = quiet ? null : { cls: 'note', html: bi('Đã chuyển sang ' + dsaSet() + ': khoá và chữ ký cũ đã được xoá vì độ dài khác.', 'Switched to ' + dsaSet() + ': the old keys and signature were cleared because the sizes differ.') };
    dsaPair(); dsaUpdate();
  }
  onRadio('dsa-set', function () { dsaLevel(false); });
  $('dsa-clear').addEventListener('click', function () {
    clear(D.seed, D.pk, D.sk, D.rnd, D.sig); dsa.msg = null; dsa.kat = null; dsaPair(); dsaUpdate();
  });
  function dsaKeygen() {
    var seed;
    if ($('dsa-seed-rnd').checked) { seed = PH.randomBytes(32); D.seed.set(seed); }
    else if (!(seed = need(D.seed, DX.fail, bi('Ô Seed đang trống: đánh dấu "seed ngẫu nhiên" hoặc nhập 32 byte.', 'The Seed field is empty: tick "random seed" or enter 32 bytes.'), 32))) return null;
    var o = timed(function () { return HA.keygenInternal(dsaSet(), seed); });
    D.pk.set(o.r.pk); D.sk.set(o.r.sk); clear(D.sig);
    dsaPair();
    return o;
  }
  $('dsa-keygen').addEventListener('click', function () {
    dsa.kat = null;
    var o = dsaKeygen();
    if (o) DX.note(bi('Đã sinh cặp khoá ' + dsaSet() + '.', 'Generated a ' + dsaSet() + ' key pair.') + ms(o.t));
  });
  $('dsa-kat').addEventListener('click', function () {
    var v = V.haetae[dsaSet()].kat, pre = unhex(v.pre);
    $('dsa-seed-rnd').checked = false; D.seed.set(unhex(v.seed));
    $('dsa-rnd-rnd').checked = false; D.rnd.set(unhex(v.rnd));
    D.ctx.fmt = 'hex'; D.ctx.mark(); D.ctx.set(pre.subarray(1));
    D.msg.fmt = 'hex'; D.msg.mark(); D.msg.set(unhex(v.msg));
    mpUpdate();
    var o = dsaKeygen(), ok = sha(D.pk.full()) === v.pk_sha256 && sha(D.sk.full()) === v.sk_sha256;
    dsa.kat = v;
    DX.note((ok ? '✓ ' : '✕ ') + (ok ?
      bi('Seed, rnd, ngữ cảnh (' + num(pre.length - 1) + ' byte ngẫu nhiên) và thông điệp của mục KAT chính thức count = 0 đã được điền. Khoá kiểm tra và khoá bí mật trùng từng byte với file KAT của nhóm tác giả.',
        'The seed, rnd, context (' + num(pre.length - 1) + ' random bytes) and message of the official KAT entry count = 0 are filled in. The verification and private keys equal, byte for byte, the authors\' KAT file.')
      : bi('Khoá sinh ra KHÁC file KAT chính thức.', 'The keys generated DIFFER from the official KAT file.')),
      (ok ? bi('Bấm Ký để thấy chữ ký cũng trùng.', 'Press Sign to see the signature match too.') : '') + ms(o.t), ok ? 'ok' : 'bad');
  });
  function msgCtx() {
    var m, c;
    try { m = D.msg.bytes(); } catch (e) { DX.fail(D.msg.err(e)); return null; }
    try { c = D.ctx.bytes(); } catch (e) { DX.fail(D.ctx.err(e)); return null; }
    if (c.length > 255) { DX.fail(bi('Ngữ cảnh dài ' + num(c.length) + ' byte; tối đa là 255 byte.', 'The context is ' + num(c.length) + ' bytes; the maximum is 255.')); return null; }
    return [m, c];
  }
  $('dsa-sign').addEventListener('click', function () {
    var z = dsaSz(), sk = need(D.sk, DX.fail, bi('Chưa có khoá bí mật: làm bước 1, hoặc dán / nạp một khoá.', 'No private key yet: do step 1, or paste / load a key.'), z.sk);
    if (!sk) return;
    var mc = msgCtx();
    if (!mc) return;
    if (!mc[0].length) return DX.fail(bi('Thông điệp đang trống. Hãy nhập nội dung cần ký.', 'The message is empty. Enter what you want to sign.'));
    var rnd;
    if ($('dsa-rnd-rnd').checked) { rnd = PH.randomBytes(32); D.rnd.set(rnd); }
    else if (!(rnd = need(D.rnd, DX.fail, bi('Ô rnd đang trống: đánh dấu "rnd ngẫu nhiên" hoặc nhập 32 byte.', 'The rnd field is empty: tick "random rnd" or enter 32 bytes.'), 32))) return;
    var pre = preOf(mc[1]), o;
    try { o = timed(function () { return HA.signInternal(dsaSet(), sk, mc[0], pre, rnd); }); }
    catch (e) { return DX.fail(bi('Không ký được: vòng thử vượt giới hạn — khoá bí mật này có lẽ đã hỏng.', 'Could not sign: the attempt loop hit its limit — this private key is probably corrupted.')); }
    D.sig.set(o.r.sig);
    var cd = ctxDesc(), v = dsa.kat, its = o.r.iterations;
    var sub = bi(cd[0] + ' · ' + its + ' lần thử', cd[1] + ' · ' + its + (its === 1 ? ' attempt' : ' attempts')) + ms(o.t);
    if (v && sha(sk) === v.sk_sha256 && T.toHex(rnd) === v.rnd && T.toHex(pre) === v.pre && T.toHex(mc[0]) === v.msg) {
      var ok = sha(o.r.sig) === v.sig_sha256;
      return DX.note((ok ? '✓ ' : '✕ ') + (ok ? bi('Đã ký. Chữ ký trùng từng byte với mục KAT chính thức count = 0.', 'Signed. The signature equals, byte for byte, the official KAT entry count = 0.')
        : bi('Chữ ký KHÁC mục KAT chính thức.', 'The signature DIFFERS from the official KAT entry.')), sub, ok ? 'ok' : 'bad');
    }
    DX.note('✓ ' + bi('Đã ký · chữ ký ' + dsaSet() + ' dài ' + num(o.r.sig.length) + ' byte.', 'Signed · ' + num(o.r.sig.length) + '-byte ' + dsaSet() + ' signature.'), sub, 'ok');
  });
  $('dsa-verify').addEventListener('click', function () {
    var z = dsaSz(), pk = need(D.pk, DX.fail, bi('Chưa có khoá kiểm tra.', 'No verification key yet.'), z.pk);
    if (!pk) return;
    var sig = need(D.sig, DX.fail, bi('Chưa có chữ ký: bấm Ký, hoặc dán / nạp một chữ ký.', 'No signature yet: press Sign, or paste / load one.'));
    if (!sig) return;
    var mc = msgCtx();
    if (!mc) return;
    var cd = ctxDesc();
    var o = timed(function () { return HA.verifyInternal(dsaSet(), pk, mc[0], sig, preOf(mc[1])); });
    if (o.r.ok) return DX.note('✓ ' + bi('Chữ ký hợp lệ.', 'The signature is valid.'), bi(cd[0], cd[1]) + ms(o.t), 'ok');
    var w = WHY[o.r.why] || (o.r.why.indexOf('rans') === 0 ? WHY.rans : [esc(o.r.why), esc(o.r.why)]);
    DX.note('✕ ' + bi('Chữ ký KHÔNG hợp lệ: ' + w[0] + '.', 'The signature is NOT valid: ' + w[1] + '.'),
      bi('Đang kiểm theo ' + cd[0] + '; lý do theo bộ xác minh: ', 'Checked with ' + cd[1] + '; the verifier\'s reason: ') + nb(esc(o.r.why)) + ms(o.t), 'bad');
  });
  $('dsa-rnd0').addEventListener('click', function () {
    $('dsa-rnd-rnd').checked = false; D.rnd.set(new Uint8Array(32));
    DX.note(bi('rnd = 32 byte 00: ký tất định, cùng khoá và cùng thông điệp thì luôn ra cùng chữ ký.', 'rnd = 32 zero bytes: deterministic signing, the same key and message always give the same signature.'));
  });
  $('dsa-flip').addEventListener('click', function () {
    var s = D.sig.peek();
    if (!s || !s.length) return DX.fail(bi('Chưa có chữ ký để lật bit.', 'There is no signature to flip a bit in.'));
    s[0] ^= 1; D.sig.set(s);
    DX.note(bi('Đã lật bit đầu tiên của chữ ký. Bấm Xác minh.', 'The first bit of the signature was flipped. Press Verify.'));
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
  var TABS = ['kem', 'dsa', 'cvt'];
  function selectTab(k) {
    TABS.forEach(function (t) { $('tab-' + t).setAttribute('aria-selected', String(t === k)); $('panel-' + t).hidden = t !== k; });
  }
  TABS.forEach(function (t) { $('tab-' + t).addEventListener('click', function () { selectTab(t); }); });

  /* ================================================================ tự kiểm chứng (SHA-256 của trình duyệt, không phải của trang) */
  async function sha256hex(b) { return T.toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', b.slice().buffer))); }
  function tick() { return new Promise(function (r) { setTimeout(r, 0); }); }
  $('bt-selftest').addEventListener('click', async function () {
    var st = $('st-status'), det = $('st-detail'), lines = [], pass = 0, total = 0, g = null, groups = [];
    st.className = 'pill wait'; st.innerHTML = bi('đang chạy…', 'running…');
    det.hidden = false; det.textContent = '';
    await tick();
    if (!window.crypto || !crypto.subtle) {
      st.className = 'pill bad'; st.innerHTML = bi('trình duyệt không có crypto.subtle', 'this browser has no crypto.subtle'); return;
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
    var name, v, enc = new TextEncoder(), abc = enc.encode('abc');
    group('Tầng Keccak: SHA3 và SHAKE (FIPS 202)', 'Keccak layer: SHA3 and SHAKE (FIPS 202)');
    chk('SHA3-256("abc")', T.toHex(PH.sha3_256(abc)), V.hash.sha3_256);
    chk('SHA3-512("abc")', T.toHex(PH.sha3_512(abc)), V.hash.sha3_512);
    chk('SHAKE128("abc", 32)', T.toHex(PH.shake128xof(abc).squeeze(32)), V.hash.shake128_32);
    chk('SHAKE256("abc", 64)', T.toHex(PH.shake256(abc, 64)), V.hash.shake256_64);
    flush(); await tick();
    group('SMAUG-T: mục KAT chính thức count = 0', 'SMAUG-T: official KAT entry count = 0');
    for (name in V.smaugt) {
      v = V.smaugt[name].kat;
      var kg = SM.keygenInternal(name, unhex(v.d), unhex(v.seed)), en = SM.encapsInternal(name, kg.pk, unhex(v.mu));
      chk(name + ' pk', await sha256hex(kg.pk), v.pk_sha256);
      chk(name + ' sk', await sha256hex(kg.sk), v.sk_sha256);
      chk(name + ' ct', await sha256hex(en.ct), v.ct_sha256);
      chk(name + ' ss', T.toHex(en.K), v.ss);
      chk(name + ' decaps', T.toHex(SM.decapsInternal(name, kg.sk, en.ct).K), v.ss);
      flush(); await tick();
    }
    group('SMAUG-T: seed cố định, từ chối ngầm', 'SMAUG-T: fixed seed, implicit rejection');
    for (name in V.smaugt) {
      v = V.smaugt[name].det;
      var k2 = SM.keygenInternal(name, unhex(v.d), unhex(v.seed)), e2 = SM.encapsInternal(name, k2.pk, unhex(v.mu));
      chk(name + ' pk', await sha256hex(k2.pk), v.pk_sha256);
      chk(name + ' sk', await sha256hex(k2.sk), v.sk_sha256);
      chk(name + ' ct', await sha256hex(e2.ct), v.ct_sha256);
      chk(name + ' ss', T.toHex(e2.K), v.ss);
      var bad = Uint8Array.from(e2.ct); bad[v.ct_flip_byte] ^= 1;
      chk(name + ' implicit rejection', T.toHex(SM.decapsInternal(name, k2.sk, bad).K), v.ss_reject);
      flush(); await tick();
    }
    group('HAETAE: mục KAT chính thức count = 0', 'HAETAE: official KAT entry count = 0');
    for (name in V.haetae) {
      v = V.haetae[name].kat;
      var k3 = HA.keygenInternal(name, unhex(v.seed)), s3 = HA.signInternal(name, k3.sk, unhex(v.msg), unhex(v.pre), unhex(v.rnd)).sig;
      chk(name + ' vk', await sha256hex(k3.pk), v.pk_sha256);
      chk(name + ' sk', await sha256hex(k3.sk), v.sk_sha256);
      chk(name + ' sig', await sha256hex(s3), v.sig_sha256);
      chk(name + ' verify', HA.verifyInternal(name, k3.pk, unhex(v.msg), s3, unhex(v.pre)).ok, true);
      flush(); await tick();
    }
    group('HAETAE: seed cố định, chữ ký sai', 'HAETAE: fixed seed, wrong signatures');
    for (name in V.haetae) {
      v = V.haetae[name].det;
      var k4 = HA.keygenInternal(name, unhex(v.seed)), s4 = HA.signInternal(name, k4.sk, unhex(v.msg), unhex(v.pre), unhex(v.rnd)).sig;
      chk(name + ' vk', await sha256hex(k4.pk), v.pk_sha256);
      chk(name + ' sk', await sha256hex(k4.sk), v.sk_sha256);
      chk(name + ' sig', await sha256hex(s4), v.sig_sha256);
      chk(name + ' verify', HA.verifyInternal(name, k4.pk, unhex(v.msg), s4, unhex(v.pre)).ok, true);
      var b4 = Uint8Array.from(s4); b4[0] ^= 1;
      chk(name + ' flipped signature', HA.verifyInternal(name, k4.pk, unhex(v.msg), b4, unhex(v.pre)).ok, false);
      chk(name + ' other context', HA.verifyInternal(name, k4.pk, unhex(v.msg), s4, new Uint8Array([0])).ok, false);
      flush(); await tick();
    }
    group('Bộ chuyển đổi dữ liệu', 'Data converter');
    V.codec.forEach(function (c) {
      var got; try { got = T.toHex(T.parseInput(c.in, c.fmt)); } catch (e) { got = 'error ' + e.code; }
      chk(c.fmt + ' ' + c.in, got, c.out);
    });
    flush();
    st.className = 'pill ' + (pass === total ? 'ok' : 'bad');
    st.innerHTML = nb(pass + '/' + total) + ' ' + (pass === total ? bi('phép kiểm khớp', 'checks match') : bi('phép kiểm — CÓ LỖI', 'checks — FAILED'));
  });

  /* ================================================================ khởi động */
  mpUpdate(); kemUpdate(); dsaUpdate(); cvtUpdate();
  window.KPQCCalc = {                                   // cửa cho bộ kiểm thử tự động; trang không tự dùng
    K: K, D: D, C: C,
    loadKey: function (tab, bytes, name) { keyLoader(tab === 'kem' ? KX : DX)(null, bytes, name); },
    loadBytes: function (field, bytes, name) { bytesLoader(field.id.indexOf('kem') === 0 ? KX : DX)(field, bytes, name); },
    loadMsg: function (bytes, name) { msgLoader(D.msg, bytes, name); },
    flush: function () { clearTimeout(pending.kem); clearTimeout(pending.dsa); delete pending.kem; delete pending.dsa; kemPairNow(); dsaPairNow(); }
  };
})();
