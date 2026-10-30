/* Giao diện máy tính PQC: ba thẻ (trao đổi khoá ML-KEM, ký / xác minh ML-DSA, chuyển đổi dữ liệu); ô dữ liệu có
   bộ đếm byte, nút định dạng, nạp file, chép, mở rộng, xoá; dòng kiểm tra cặp khoá; nút tự kiểm chứng.
   Mọi chuỗi hiển thị có hai bản qua bi(vi, en). Cần pqc-mlkem/sha2/mldsa/tools/vectors.js nạp trước.
   Original implementation for the ChiU·SoC PQC demo page. */
(function () {
  'use strict';
  var T = window.PQCTools, V = window.PQC_VECTORS, MLKEM = window.MLKEM, MLDSA = window.MLDSA;

  /* ================================================================ tiện ích */
  function $(id) { var e = document.getElementById(id); if (!e) throw new Error('missing #' + id); return e; }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function bi(vi, en) { return '<span lang="vi">' + vi + '</span><span lang="en">' + en + '</span>'; }
  function nb(s) { return '<span data-i18n="neutral">' + s + '</span>'; }
  function num(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ' '); }
  function fill(s, a) { return s.replace(/\{(\w+)\}/g, function (m, k) { return a && a[k] !== undefined ? esc(a[k]) : m; }); }
  function timed(fn) { var t0 = performance.now(); var r = fn(); return { r: r, t: performance.now() - t0 }; }
  function ms(t) { return nb(' · ' + t.toFixed(1) + ' ms'); }
  function checked(name) { var r = document.querySelector('input[name="' + name + '"]:checked'); return r ? r.value : null; }
  function radios(name) { return Array.prototype.slice.call(document.querySelectorAll('input[name="' + name + '"]')); }
  function onRadio(name, fn) { radios(name).forEach(function (r) { r.addEventListener('change', fn); }); }
  function setRadio(name, v) { radios(name).forEach(function (r) { r.checked = r.value === v; }); }
  function phLabel(id) { for (var i = 0; i < MLDSA.PH_LIST.length; i++) if (MLDSA.PH_LIST[i].id === id) return MLDSA.PH_LIST[i].label; return id; }
  function show(el, cls, main, sub) {
    el.className = 'result ' + cls;
    el.innerHTML = main + (sub ? '<span class="sub">' + sub + '</span>' : '');
  }

  /* thông báo lỗi theo mã (PQCTools ném Error có .code) */
  var MSG = {
    HEX_CHAR: ['có ký tự không phải hex', 'contains a character that is not hex'],
    HEX_ODD: ['có số chữ số hex lẻ', 'has an odd number of hex digits'],
    B64: ['không phải Base64 hợp lệ', 'is not valid Base64'],
    ARRAY_ITEM: ['có phần tử mảng "{item}" không phải là số', 'has an array item "{item}" that is not a number'],
    ARRAY_RANGE: ['có phần tử {item} nằm ngoài khoảng byte -128 … 255', 'has an item {item} outside the byte range -128 … 255'],
    ARRAY_CLOSE: ['thiếu dấu "{close}" ở cuối mảng', 'is missing the closing "{close}" of the array'],
    AUTO: ['không phải hex hay mảng; với dữ liệu khác hãy chọn Base64 hoặc Văn bản', 'is neither hex nor an array; pick Base64 or Text for other data'],
    NOT_UTF8: ['chứa các byte không phải văn bản UTF-8, hãy xem ở dạng hex', 'holds bytes that are not UTF-8 text; view them as hex'],
    OTHER_TAB: ['File này chứa khoá {alg}. Hãy nạp ở thẻ "{tabvi}".', 'This file holds an {alg} key. Load it in the "{taben}" tab.'],
    UNSUPPORTED_ALG: ['File này chứa khoá {alg}, không phải ML-KEM hay ML-DSA.', 'This file holds a {alg} key, not ML-KEM or ML-DSA.'],
    ENCRYPTED: ['Khoá này được mã hoá bằng mật khẩu, trang chưa đọc được; hãy xuất khoá không mã hoá.', 'This key is password-encrypted, which the page cannot read; export it unencrypted.'],
    PKCS12: ['File PKCS#12 (.pfx / .p12) chưa được hỗ trợ; hãy xuất khoá ra PEM hoặc DER.', 'PKCS#12 files (.pfx / .p12) are not supported; export the key as PEM or DER.'],
    SEED_MISMATCH: ['Seed và khoá mở rộng trong file này không thuộc cùng một cặp khoá. RFC 9935 và RFC 9881 bắt phải từ chối một file như vậy.', 'The seed and the expanded key in this file do not belong together. RFC 9935 and RFC 9881 require rejecting such a file.'],
    SEED_LEN: ['Seed của khoá bí mật phải đủ {want} byte, file có {got} byte.', 'The private key seed must be {want} bytes; the file has {got}.'],
    KEY_LEN: ['Khoá {alg} cần {want} byte, file có {got} byte.', 'An {alg} key needs {want} bytes; the file has {got}.'],
    NO_SIZE_MATCH: ['{len} byte không khớp kích thước khoá nào của ML-KEM hay ML-DSA.', '{len} bytes matches no ML-KEM or ML-DSA key size.'],
    MIXED: ['File trộn khoá của nhiều bộ tham số khác nhau.', 'The file mixes keys of different parameter sets.'],
    SPKI_PARAMS: ['Khoá công khai {alg} có tham số trong AlgorithmIdentifier; RFC cấm điều này.', 'The {alg} public key has parameters in its AlgorithmIdentifier, which the RFC forbids.'],
    BAD_PEM_BLOCK: ['Khối PEM "{label}" không chứa khoá hay chứng chỉ đọc được.', 'The PEM block "{label}" holds no readable key or certificate.'],
    BAD_PEM: ['File PEM dị dạng: không có khối BEGIN / END hoàn chỉnh.', 'Malformed PEM file: no complete BEGIN / END block.'],
    TOO_BIG: ['File quá lớn (hơn 1 MB).', 'The file is too large (over 1 MB).'],
    UNRECOGNIZED: ['Không nhận ra file. Cần chứng chỉ, khoá PEM / DER, hoặc khoá thô dạng hex, Base64 hay nhị phân.', 'File not recognised. A certificate, a PEM / DER key, or a raw key in hex, Base64 or binary is needed.'],
    DER: ['Cấu trúc DER bị hỏng.', 'The DER structure is broken.']
  };
  function parts(e) {
    var m = MSG[e && e.code] || ['lỗi không mong đợi: ' + esc(e && e.message), 'unexpected error: ' + esc(e && e.message)];
    var a = (e && e.info) || {};
    if (e && e.code === 'OTHER_TAB') { a.tabvi = a.tab === 'kem' ? 'Trao đổi khoá' : 'Ký & xác minh'; a.taben = a.tab === 'kem' ? 'Key exchange' : 'Sign & verify'; }
    return [fill(m[0], a), fill(m[1], a)];
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

  /* ================================================================ ô dữ liệu */
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
  Field.prototype.bytes = function () {                 // ném lỗi có .code nếu chữ trong ô không đọc được
    var s = this.ta.value;
    if (this.parse) return this.parse(s);
    if (this.fmt === 'text') return new TextEncoder().encode(s);
    if (this.fmt === 'base64') return T.parseInput(s, 'base64');
    return T.parseAuto(s).bytes;
  };
  Field.prototype.peek = function () { try { return this.bytes(); } catch (e) { return null; } };
  Field.prototype.full = function () {                  // bytes nếu ô có dữ liệu đúng độ dài, ngược lại null
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

  /* đọc một ô bắt buộc: trả bytes, hoặc null sau khi đã báo lỗi qua fail(html) */
  function need(f, fail, emptyMsg, len) {
    if (f.empty()) { fail(emptyMsg); return null; }
    var b;
    try { b = f.bytes(); } catch (e) { fail(f.err(e)); return null; }
    if (len !== undefined && len !== null && b.length !== len) { fail(f.lenErr(b, len)); return null; }
    return b;
  }
  /* ô dữ liệu thường (seed, m, ct, rnd, chữ ký): nạp nội dung file, hex / Base64 nếu là chữ */
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
    pk_check: ['Khoá công khai qua kiểm tra modulus (FIPS 203, mục 7.2)', 'The public key passes the modulus check (FIPS 203, section 7.2)'],
    sk_check: ['Khoá bí mật qua kiểm tra băm (FIPS 203, mục 7.3)', 'The private key passes the hash check (FIPS 203, section 7.3)'],
    range: ['Hệ số s1, s2 trong khoá bí mật nằm trong [−η, η]', 'The s1, s2 coefficients in the private key lie in [−η, η]'],
    derived_pk: ['Khoá công khai suy ra từ khoá bí mật trùng ô khoá công khai', 'The public key derived from the private key equals the Public key field'],
    tr: ['Giá trị tr = H(pk) lưu trong khoá bí mật khớp', 'The stored tr = H(pk) matches'],
    t0: ['Phần t0 lưu trong khoá bí mật khớp A·s1 + s2 (RFC 9881, phụ lục C.4)', 'The stored t0 matches A·s1 + s2 (RFC 9881, Appendix C.4)'],
    roundtrip_kem: ['Khứ hồi: đóng gói tới khoá công khai, giải bằng khoá bí mật, hai khoá chung trùng nhau', 'Round trip: encapsulate to the public key, decapsulate with the private key, the secrets match'],
    roundtrip_sig: ['Khứ hồi: ký bằng khoá bí mật, xác minh bằng khoá công khai', 'Round trip: sign with the private key, verify with the public key'],
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

  /* ================================================================ nạp file khoá */
  var FORM = {
    seed: ['PKCS#8, chỉ seed', 'PKCS#8, seed only'], expandedKey: ['PKCS#8, khoá mở rộng', 'PKCS#8, expanded key'],
    both: ['PKCS#8, seed và khoá mở rộng', 'PKCS#8, seed and expanded key'], raw: ['khoá thô', 'raw key'],
    spki: ['SPKI', 'SPKI'], cert: ['chứng chỉ X.509', 'X.509 certificate']
  };
  function keyLoader(X) {
    return function (f, bytes, name, err) {
      if (err) return X.fail(msg(err));
      var items, alg;
      try { items = T.readKeyFile(bytes, name); alg = T.identify(items, X.family, X.set()); }
      catch (e) { return X.fail(msg(e)); }
      if (alg !== X.set()) X.setLevel(alg, true);
      var got = [], pub = null, priv = null, derived = false;
      items.forEach(function (it) {
        var fm = FORM[it.form] || FORM.raw, enc = it.enc ? it.enc + ' · ' : '';
        if (it.kind === 'public') { X.pk.set(it.data); pub = it; got.push(['khoá công khai (' + enc + fm[0] + ')', 'public key (' + enc + fm[1] + ')']); }
        else { X.sk.set(it.data); priv = it; got.push(['khoá bí mật (' + enc + fm[0] + ')', 'private key (' + enc + fm[1] + ')']); }
      });
      if (priv) {
        if (priv.seed) { X.seed.set(priv.seed); $(X.seedRnd).checked = false; } else X.seed.set(null);
        if (!pub) {
          X.pk.set(priv.pkFromSeed || (X.family === 'kem' ? MLKEM.ekFromDk(MLKEM.PARAMS[alg], priv.data) : MLDSA.recompute(MLDSA.PARAMS[alg], priv.data).pk));
          derived = true;
        }
      }
      X.keysLoaded();
      var vi = got.map(function (g) { return g[0]; }).join(' và '), en = got.map(function (g) { return g[1]; }).join(' and ');
      var sub = (derived ? bi('Khoá công khai được suy ra từ khoá bí mật. ', 'The public key was derived from the private key. ') : '') +
        (priv && priv.notes.indexOf('SK_WARN') >= 0 ? bi('Cảnh báo: khoá bí mật không qua kiểm tra băm của FIPS 203 (mục 7.3).', 'Warning: the private key fails the FIPS 203 hash check (section 7.3).') : '');
      X.note(bi('Đã nạp ' + vi + ' của ' + alg + ' từ ' + esc(name) + '.', 'Loaded the ' + alg + ' ' + en + ' from ' + esc(name) + '.'), sub);
      var text = looksText(bytes) ? String.fromCharCode.apply(null, Array.prototype.slice.call(bytes, 0)) : '';
      var pem = $(X.tab + '-pem');
      pem.hidden = text.indexOf('-----BEGIN') < 0;
      $(X.tab + '-pem-text').textContent = pem.hidden ? '' : text;
      if (f && f.ta.value.indexOf('-----BEGIN') >= 0 && !f.full()) f.set(null);
    };
  }
  function pemPasted(f, X) {                            // dán cả file PEM vào một ô khoá
    var s = f.ta.value;
    if (s.indexOf('-----BEGIN') < 0 || s.indexOf('-----END') < 0) return false;
    var before = s;
    keyLoader(X)(null, new TextEncoder().encode(s), 'PEM');
    if (f.ta.value === before) f.set(null);
    return true;
  }
  function rfcExample(X) {
    var r = V.rfc.filter(function (x) { return x.set === X.set(); })[0];
    keyLoader(X)(null, new TextEncoder().encode(r.pem), r.rfc + ' (' + r.set + ', seed)');
    var pub = T.readKeyFile(new TextEncoder().encode(r.pub_pem), 'pub.pem')[0].data;
    var same = T.eq(X.pk.full(), pub);
    X.note(same ? '✓ ' + bi('Đã nạp khoá mẫu dạng seed trong phụ lục C.1 của ' + r.rfc + '. Khoá công khai mở rộng ra trùng từng byte với khoá in trong phụ lục C.2 của chính RFC đó.',
      'Loaded the seed-form example key from Appendix C.1 of ' + r.rfc + '. The expanded public key equals, byte for byte, the one printed in Appendix C.2 of the same RFC.')
      : '✕ ' + bi('Khoá công khai mở rộng ra KHÁC khoá in trong ' + r.rfc + '.', 'The expanded public key DIFFERS from the one printed in ' + r.rfc + '.'), null, same ? 'ok' : 'bad');
  }

  /* ================================================================ thẻ ML-KEM */
  var kem = { msg: null, res: $('kem-result') };
  function kemSet() { return checked('kem-set'); }
  function kemP() { return MLKEM.PARAMS[kemSet()]; }
  function kemSz() { return MLKEM.sizes(kemP()); }
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
  K.ek = new Field('kem-ek', { name: ['khoá đóng gói', 'Encapsulation key'], need: function () { return kemSz().ek; }, load: keyLoader(KX),
    onEdit: function (f) { if (pemPasted(f, KX)) return; clear(K.ct, K.ss, K.ss2); kem.msg = null; kemPair(); kemUpdate(); } });
  K.dk = new Field('kem-dk', { name: ['khoá giải đóng gói', 'Decapsulation key'], need: function () { return kemSz().dk; }, load: keyLoader(KX),
    onEdit: function (f) { if (pemPasted(f, KX)) return; clear(K.ss2); kem.msg = null; kemPair(); kemUpdate(); } });
  K.m = new Field('kem-m', { name: ['m', 'm'], need: function () { return 32; }, load: bytesLoader(KX),
    onEdit: function () { $('kem-m-rnd').checked = false; } });
  K.ct = new Field('kem-ct', { name: ['bản mã', 'Ciphertext'], need: function () { return kemSz().ct; }, load: bytesLoader(KX),
    onEdit: function () { clear(K.ss2); kem.msg = null; kemUpdate(); } });
  K.ss = new Field('kem-ss', { name: ['khoá chung K', 'Shared secret K'], need: function () { return 32; },
    onEdit: function () { kem.msg = null; kemUpdate(); } });
  K.ss2 = new Field('kem-ss2', { name: ['khoá chung K′', 'Shared secret K′'], need: function () { return 32; },
    onEdit: function () { kem.msg = null; kemUpdate(); } });
  KX.pk = K.ek; KX.sk = K.dk; KX.seed = K.seed;

  function kemPairNow() {
    var el = $('kem-pair');
    if (K.ek.empty() && K.dk.empty()) { el.className = 'pairline'; el.innerHTML = ''; return; }
    var seed = K.seed.empty() ? null : K.seed.peek();
    renderPair(el, true, T.pairCheck(kemSet(), K.ek.peek(), K.dk.peek(), seed));
  }
  function kemPair() { pairLater('kem', kemPairNow); }
  function kemUpdate() {
    var z = kemSz(), ek = !!K.ek.full(), dk = !!K.dk.full(), ct = !!K.ct.full(), ss = !!K.ss.full(), ss2 = !!K.ss2.full();
    var next = !ek ? 1 : (!ct ? 3 : (!ss2 ? 5 : 0));
    [[1, ek && dk], [3, ct && ss], [5, ss2]].forEach(function (c) {
      var card = $('kem-c' + c[0]);
      card.classList.toggle('done', c[1]); card.classList.toggle('next', next === c[0]);
    });
    $('kem-a2').classList.toggle('lit', ek); $('kem-a4').classList.toggle('lit', ct);
    $('kem-a2-txt').innerHTML = bi('khoá đóng gói ek, ' + num(z.ek) + ' byte, gửi cho bên gửi', 'encapsulation key ek, ' + num(z.ek) + ' bytes, to the sender');
    $('kem-a4-txt').innerHTML = bi('bản mã ct, ' + num(z.ct) + ' byte, gửi lại bên nhận', 'ciphertext ct, ' + num(z.ct) + ' bytes, back to the receiver');
    var m = kem.msg, el = kem.res;
    if (m && m.cls === 'bad') return show(el, 'bad', m.html, m.sub);
    if (m && m.cls === 'ok') return show(el, 'ok', m.html, m.sub);
    var note = m ? m.html + (m.sub ? ' ' + m.sub : '') : '';
    if (ss2) {
      if (!ss) return show(el, 'info', 'i ' + bi('Đã tính K′. Ô K của bên gửi đang trống nên chưa có gì để so.', 'K′ computed. The sender\'s K field is empty, so there is nothing to compare with yet.'), note);
      if (T.eq(K.ss.full(), K.ss2.full()))
        return show(el, 'ok', '✓ ' + bi('Hai khoá chung trùng nhau: hai bên đã có cùng một bí mật 32 byte, và nó chưa từng đi trên đường truyền.',
          'The shared secrets match: both sides now hold the same 32-byte secret, and it never travelled.'), note);
      return show(el, 'bad', '✕ ' + bi('Hai khoá chung KHÁC nhau. Bản mã hoặc khoá đã bị đổi trên đường đi. ML-KEM không báo lỗi mà trả về một bí mật không liên quan — đó là <em>từ chối ngầm</em> của FIPS 203.',
        'The shared secrets do NOT match. The ciphertext or a key was changed on the way. ML-KEM raises no error and returns an unrelated secret instead — FIPS 203 <em>implicit rejection</em>.'), note);
    }
    var L = {
      1: bi('Bắt đầu với bước 1: bên nhận sinh (hoặc nạp) một cặp khoá.', 'Start with step 1: the receiver generates (or loads) a key pair.'),
      3: bi('Tiếp theo: bước 3 — bên gửi đóng gói tới khoá công khai.', 'Next: step 3 — the sender encapsulates to the public key.'),
      5: bi('Tiếp theo: bước 5 — bên nhận giải đóng gói bản mã.', 'Next: step 5 — the receiver decapsulates the ciphertext.')
    };
    show(el, 'info', '→ ' + L[next], note);
  }
  function kemLevel(quiet) {
    clear(K.ek, K.dk, K.ct, K.ss, K.ss2);
    $('kem-pem').hidden = true;
    [K.seed, K.ek, K.dk, K.m, K.ct, K.ss, K.ss2].forEach(function (f) { f.count(); });
    kem.msg = quiet ? null : { cls: 'note', html: bi('Đã chuyển sang ' + kemSet() + ': khoá và bản mã cũ đã được xoá vì độ dài khác.', 'Switched to ' + kemSet() + ': the old keys and ciphertext were cleared because the sizes differ.') };
    kemPair(); kemUpdate();
  }
  onRadio('kem-set', function () { kemLevel(false); });
  $('kem-clear').addEventListener('click', function () {
    clear(K.seed, K.ek, K.dk, K.m, K.ct, K.ss, K.ss2); $('kem-pem').hidden = true; kem.msg = null; kemPair(); kemUpdate();
  });
  $('kem-keygen').addEventListener('click', function () {
    var seed;
    if ($('kem-seed-rnd').checked) { seed = MLKEM.randomBytes(64); K.seed.set(seed); }
    else if (!(seed = need(K.seed, KX.fail, bi('Ô Seed đang trống: đánh dấu "seed ngẫu nhiên" hoặc nhập 64 byte.', 'The Seed field is empty: tick "random seed" or enter 64 bytes.'), 64))) return;
    var o = timed(function () { return MLKEM.keygenInternal(kemP(), seed.subarray(0, 32), seed.subarray(32, 64)); });
    K.ek.set(o.r.ek); K.dk.set(o.r.dk); clear(K.ct, K.ss, K.ss2); $('kem-pem').hidden = true;
    KX.note(bi('Đã sinh cặp khoá ' + kemSet() + '.', 'Generated an ' + kemSet() + ' key pair.') + ms(o.t));
    kemPair();
  });
  $('kem-rfc').addEventListener('click', function () { rfcExample(KX); });
  $('kem-encaps').addEventListener('click', function () {
    var ek = need(K.ek, KX.fail, bi('Chưa có khoá đóng gói: làm bước 1, hoặc dán / nạp một khoá công khai.', 'No encapsulation key yet: do step 1, or paste / load a public key.'));
    if (!ek) return;
    var chk = MLKEM.ekCheck(kemP(), ek);
    if (chk === 'TYPE') return KX.fail(bi('Khoá đóng gói dài ' + num(ek.length) + ' byte, ' + kemSet() + ' cần ' + num(kemSz().ek) + ' byte: không qua kiểm tra kiểu của FIPS 203 (mục 7.2).',
      'The encapsulation key is ' + num(ek.length) + ' bytes; ' + kemSet() + ' needs ' + num(kemSz().ek) + ': it fails the FIPS 203 type check (section 7.2).'));
    if (chk === 'MODULUS') return KX.fail(bi('Khoá đóng gói có một hệ số không nhỏ hơn q = 3329: không qua kiểm tra modulus của FIPS 203 (mục 7.2).',
      'The encapsulation key has a coefficient that is not below q = 3329: it fails the FIPS 203 modulus check (section 7.2).'));
    var m;
    if ($('kem-m-rnd').checked) { m = MLKEM.randomBytes(32); K.m.set(m); }
    else if (!(m = need(K.m, KX.fail, bi('Ô m đang trống: đánh dấu "m ngẫu nhiên" hoặc nhập 32 byte.', 'The m field is empty: tick "random m" or enter 32 bytes.'), 32))) return;
    var o = timed(function () { return MLKEM.encapsInternal(kemP(), ek, m); });
    K.ct.set(o.r.ct); K.ss.set(o.r.K); clear(K.ss2);
    KX.note(bi('Đã đóng gói.', 'Encapsulated.') + ms(o.t));
  });
  $('kem-decaps').addEventListener('click', function () {
    var dk = need(K.dk, KX.fail, bi('Chưa có khoá giải đóng gói: làm bước 1, hoặc dán / nạp một khoá bí mật.', 'No decapsulation key yet: do step 1, or paste / load a private key.'));
    if (!dk) return;
    var chk = MLKEM.dkCheck(kemP(), dk), z = kemSz();
    if (chk === 'TYPE') return KX.fail(bi('Khoá giải đóng gói dài ' + num(dk.length) + ' byte, ' + kemSet() + ' cần ' + num(z.dk) + ' byte: không qua kiểm tra kiểu của FIPS 203 (mục 7.3).',
      'The decapsulation key is ' + num(dk.length) + ' bytes; ' + kemSet() + ' needs ' + num(z.dk) + ': it fails the FIPS 203 type check (section 7.3).'));
    if (chk === 'HASH') return KX.fail(bi('Khoá giải đóng gói không qua kiểm tra băm của FIPS 203 (mục 7.3): giá trị H(ek) lưu bên trong không khớp phần ek nhúng trong chính nó.',
      'The decapsulation key fails the FIPS 203 hash check (section 7.3): the H(ek) stored inside does not match the ek embedded in it.'));
    var ct = need(K.ct, KX.fail, bi('Chưa có bản mã: làm bước 3 trước.', 'No ciphertext yet: do step 3 first.'));
    if (!ct) return;
    if (ct.length !== z.ct) return KX.fail(bi('Bản mã dài ' + num(ct.length) + ' byte, ' + kemSet() + ' cần ' + num(z.ct) + ' byte: không qua kiểm tra kiểu của FIPS 203 (mục 7.3).',
      'The ciphertext is ' + num(ct.length) + ' bytes; ' + kemSet() + ' needs ' + num(z.ct) + ': it fails the FIPS 203 type check (section 7.3).'));
    var o = timed(function () { return MLKEM.decapsInternal(kemP(), dk, ct); });
    K.ss2.set(o.r.K);
    KX.note(bi('Đã giải đóng gói.', 'Decapsulated.') + ms(o.t));
  });
  $('kem-flip').addEventListener('click', function () {
    var ct = K.ct.peek();
    if (!ct || !ct.length) return KX.fail(bi('Chưa có bản mã để lật bit.', 'There is no ciphertext to flip a bit in.'));
    ct[0] ^= 1; K.ct.set(ct); clear(K.ss2);
    KX.note(bi('Đã lật bit đầu tiên của bản mã. Bấm Giải đóng gói để xem chuyện gì xảy ra.', 'The first bit of the ciphertext was flipped. Press Decapsulate to see what happens.'));
  });

  /* ================================================================ thẻ ML-DSA */
  var dsa = { msg: null, res: $('dsa-result') };
  function dsaSet() { return checked('dsa-set'); }
  function dsaP() { return MLDSA.PARAMS[dsaSet()]; }
  function dsaSz() { return MLDSA.sizes(dsaP()); }
  function phValue() { var v = checked('dsa-ph'); return v === 'none' ? null : v; }
  var DX = {
    tab: 'dsa', family: 'sig', set: dsaSet, seedRnd: 'dsa-seed-rnd',
    fail: function (html) { dsa.msg = { cls: 'bad', html: '✕ ' + html }; dsaUpdate(); },
    note: function (html, sub, cls) { dsa.msg = { cls: cls || 'note', html: html, sub: sub }; dsaUpdate(); },
    setLevel: function (name, quiet) { setRadio('dsa-set', name); dsaLevel(quiet); },
    keysLoaded: function () { dsaPair(); }
  };
  function stale() { dsa.msg = null; dsaUpdate(); }
  var D = {};
  D.seed = new Field('dsa-seed', { name: ['Seed', 'Seed'], need: function () { return 32; }, load: bytesLoader(DX),
    onEdit: function () { $('dsa-seed-rnd').checked = false; dsaPair(); } });
  D.pk = new Field('dsa-pk', { name: ['khoá công khai', 'Public key'], need: function () { return dsaSz().pk; }, load: keyLoader(DX),
    onEdit: function (f) { if (pemPasted(f, DX)) return; dsaPair(); stale(); } });
  D.sk = new Field('dsa-sk', { name: ['khoá bí mật', 'Private key'], need: function () { return dsaSz().sk; }, load: keyLoader(DX),
    onEdit: function (f) { if (pemPasted(f, DX)) return; dsaPair(); stale(); } });
  function msgLoader(f, bytes, name, err) {            // văn bản UTF-8 thì giữ dạng chữ, nhị phân thì chuyển sang hex
    if (err) return DX.fail(msg(err));
    var text = null;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (e) { text = null; }
    if (text !== null && /[\u0000-\u0008\u000e-\u001f]/.test(text)) text = null;
    if (text !== null) { f.fmt = 'text'; f.mark(); f.ta.value = text; f.count(); }
    else { f.fmt = 'hex'; f.mark(); f.set(bytes); }
    f.edited();
    DX.note(bi('Đã nạp ' + num(bytes.length) + ' byte từ ' + esc(name) + ' làm thông điệp.', 'Loaded ' + num(bytes.length) + ' bytes from ' + esc(name) + ' as the message.'));
  }
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
    renderPair(el, false, T.pairCheck(dsaSet(), D.pk.peek(), D.sk.peek(), seed));
  }
  function dsaPair() { pairLater('dsa', dsaPairNow); }
  function mpUpdate() {
    var m = D.msg.peek(), c = D.ctx.peek();
    D.mp.set(m && c && c.length <= 255 ? MLDSA.prepare(m, c, phValue()) : null);
  }
  function mode() {
    var ph = phValue(), c = D.ctx.peek() || new Uint8Array(0);
    var a = ph ? ['HashML-DSA với ' + phLabel(ph), 'HashML-DSA with ' + phLabel(ph)] : ['ML-DSA thuần', 'pure ML-DSA'];
    var b = c.length ? ['ngữ cảnh ' + num(c.length) + ' byte', num(c.length) + '-byte context'] : ['ngữ cảnh rỗng', 'empty context'];
    return [a[0] + ' · ' + b[0], a[1] + ' · ' + b[1]];
  }
  function phSync(levelChanged) {
    var P = dsaP(), reset = null, note = $('dsa-ph-note');
    radios('dsa-ph').forEach(function (r) {
      if (r.value === 'none') return;
      var ok = MLDSA.prehashAllowed(P, r.value);
      r.disabled = !ok;
      if (!ok && r.checked) reset = r.value;
    });
    if (reset) {
      setRadio('dsa-ph', 'none');
      note.innerHTML = bi(phLabel(reset) + ' quá yếu cho ' + dsaSet() + ' nên đã được đặt lại về "Không".', phLabel(reset) + ' is too weak for ' + dsaSet() + ', so it was reset to None.');
    } else if (levelChanged) note.innerHTML = '';
    $('dsa-ph-why').innerHTML = bi('Ở ' + dsaSet() + ' (λ = ' + P.lam + ' bit), hàm băm phải cho ít nhất ' + 2 * P.lam + ' bit đầu ra; các hàm bị gạch là quá yếu.',
      'At ' + dsaSet() + ' (λ = ' + P.lam + ' bits) the hash must output at least ' + 2 * P.lam + ' bits; the struck-out functions are too weak.');
    return reset;
  }
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
    $('dsa-pem').hidden = true;
    var reset = phSync(true);
    [D.seed, D.pk, D.sk, D.rnd, D.sig].forEach(function (f) { f.count(); });
    mpUpdate();
    dsa.msg = quiet ? null : { cls: 'note', html: bi('Đã chuyển sang ' + dsaSet() + ': khoá và chữ ký cũ đã được xoá vì độ dài khác.', 'Switched to ' + dsaSet() + ': the old keys and signature were cleared because the sizes differ.') + (reset ? ' ' + $('dsa-ph-note').innerHTML : '') };
    dsaPair(); dsaUpdate();
  }
  onRadio('dsa-set', function () { dsaLevel(false); });
  onRadio('dsa-ph', function () { $('dsa-ph-note').innerHTML = ''; mpUpdate(); stale(); });
  $('dsa-clear').addEventListener('click', function () {
    clear(D.seed, D.pk, D.sk, D.rnd, D.sig); $('dsa-pem').hidden = true; dsa.msg = null; dsaPair(); dsaUpdate();
  });
  $('dsa-keygen').addEventListener('click', function () {
    var seed;
    if ($('dsa-seed-rnd').checked) { seed = window.PQCHash.randomBytes(32); D.seed.set(seed); }
    else if (!(seed = need(D.seed, DX.fail, bi('Ô Seed đang trống: đánh dấu "seed ngẫu nhiên" hoặc nhập 32 byte.', 'The Seed field is empty: tick "random seed" or enter 32 bytes.'), 32))) return;
    var o = timed(function () { return MLDSA.keygenInternal(dsaP(), seed); });
    D.pk.set(o.r.pk); D.sk.set(o.r.sk); clear(D.sig); $('dsa-pem').hidden = true;
    DX.note(bi('Đã sinh cặp khoá ' + dsaSet() + '.', 'Generated an ' + dsaSet() + ' key pair.') + ms(o.t));
    dsaPair();
  });
  $('dsa-rfc').addEventListener('click', function () { rfcExample(DX); });
  function msgCtx() {                                   // [msg, ctx] hoặc null sau khi đã báo lỗi
    var m, c;
    try { m = D.msg.bytes(); } catch (e) { DX.fail(D.msg.err(e)); return null; }
    try { c = D.ctx.bytes(); } catch (e) { DX.fail(D.ctx.err(e)); return null; }
    if (c.length > 255) { DX.fail(bi('Ngữ cảnh dài ' + num(c.length) + ' byte; FIPS 204 cho tối đa 255 byte.', 'The context is ' + num(c.length) + ' bytes; FIPS 204 allows at most 255.')); return null; }
    return [m, c];
  }
  $('dsa-sign').addEventListener('click', function () {
    var z = dsaSz(), sk = need(D.sk, DX.fail, bi('Chưa có khoá bí mật: làm bước 1, hoặc dán / nạp một khoá.', 'No private key yet: do step 1, or paste / load a key.'), z.sk);
    if (!sk) return;
    if (MLDSA.skCheck(dsaP(), sk) !== 'OK') return DX.fail(bi('Khoá bí mật có hệ số s1 hoặc s2 nằm ngoài [−η, η]: khoá đã hỏng.', 'The private key has an s1 or s2 coefficient outside [−η, η]: the key is corrupted.'));
    var mc = msgCtx();
    if (!mc) return;
    if (!mc[0].length) return DX.fail(bi('Thông điệp đang trống. Hãy nhập nội dung cần ký.', 'The message is empty. Enter what you want to sign.'));
    var rnd;
    if ($('dsa-rnd-rnd').checked) { rnd = window.PQCHash.randomBytes(32); D.rnd.set(rnd); }
    else if (!(rnd = need(D.rnd, DX.fail, bi('Ô rnd đang trống: đánh dấu "rnd ngẫu nhiên" hoặc nhập 32 byte.', 'The rnd field is empty: tick "random rnd" or enter 32 bytes.'), 32))) return;
    var Mp = MLDSA.prepare(mc[0], mc[1], phValue());
    var o = timed(function () { return MLDSA.signInternal(dsaP(), sk, Mp, rnd); });
    D.sig.set(o.r.sig);
    var md = mode();
    DX.note('✓ ' + bi('Đã ký · chữ ký ' + dsaSet() + ' dài ' + num(o.r.sig.length) + ' byte.', 'Signed · ' + num(o.r.sig.length) + '-byte ' + dsaSet() + ' signature.'),
      bi(md[0] + ' · ' + o.r.iterations + ' lần thử', md[1] + ' · ' + o.r.iterations + (o.r.iterations === 1 ? ' attempt' : ' attempts')) + ms(o.t), 'ok');
  });
  $('dsa-verify').addEventListener('click', function () {
    var z = dsaSz(), pk = need(D.pk, DX.fail, bi('Chưa có khoá công khai.', 'No public key yet.'), z.pk);
    if (!pk) return;
    var sig = need(D.sig, DX.fail, bi('Chưa có chữ ký: bấm Ký, hoặc dán / nạp một chữ ký.', 'No signature yet: press Sign, or paste / load one.'));
    if (!sig) return;
    var mc = msgCtx();
    if (!mc) return;
    var md = mode();
    if (sig.length !== z.sig) return DX.note('✕ ' + bi('Chữ ký KHÔNG hợp lệ.', 'The signature is NOT valid.'),
      bi('Chữ ký ' + dsaSet() + ' phải dài ' + num(z.sig) + ' byte, ô đang có ' + num(sig.length) + ' byte.', 'An ' + dsaSet() + ' signature is ' + num(z.sig) + ' bytes; the field holds ' + num(sig.length) + '.'), 'bad');
    var o = timed(function () { return MLDSA.verifyInternal(dsaP(), pk, MLDSA.prepare(mc[0], mc[1], phValue()), sig); });
    if (o.r) DX.note('✓ ' + bi('Chữ ký hợp lệ.', 'The signature is valid.'), bi(md[0], md[1]) + ms(o.t), 'ok');
    else DX.note('✕ ' + bi('Chữ ký KHÔNG hợp lệ.', 'The signature is NOT valid.'),
      bi('Khoá, thông điệp, ngữ cảnh hoặc pre-hash khác với lúc ký — hoặc chữ ký đã bị sửa. Đang kiểm theo: ' + md[0] + '.',
        'The key, message, context or pre-hash differs from signing time — or the signature was altered. Checked as: ' + md[1] + '.') + ms(o.t), 'bad');
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

  /* ================================================================ tự kiểm chứng */
  function unhex(s) { return T.parseHex(s); }
  async function sha256hex(b) { return T.toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', b.slice().buffer))); }
  function tick() { return new Promise(function (r) { setTimeout(r, 0); }); }
  $('bt-selftest').addEventListener('click', async function () {
    var st = $('st-status'), det = $('st-detail'), lines = [], pass = 0, total = 0, g = null;
    var groups = [];
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
    var name, i, k, v, enc = new TextEncoder();
    group('Hàm băm SHA-2 / SHA-3 / SHAKE (FIPS 180-4, FIPS 202)', 'SHA-2 / SHA-3 / SHAKE hashes (FIPS 180-4, FIPS 202)');
    var m200 = new Uint8Array(200).map(function (_, j) { return (j * 37 + 11) & 255; });
    MLDSA.PH_LIST.forEach(function (e) {
      chk(e.label + '("abc")', T.toHex(e.fn(enc.encode('abc'))), V.hash[e.id].abc);
      chk(e.label + '(200 B)', T.toHex(e.fn(m200)), V.hash[e.id].m200);
    });
    flush(); await tick();
    group('ML-KEM (FIPS 203)', 'ML-KEM (FIPS 203)');
    for (name in V.mlkem) {
      v = V.mlkem[name]; var p = MLKEM.PARAMS[name];
      var kg = MLKEM.keygenInternal(p, unhex(v.d), unhex(v.z)), en = MLKEM.encapsInternal(p, kg.ek, unhex(v.m));
      chk(name + ' ek', await sha256hex(kg.ek), v.ek_sha256);
      chk(name + ' dk', await sha256hex(kg.dk), v.dk_sha256);
      chk(name + ' ct', await sha256hex(en.ct), v.ct_sha256);
      chk(name + ' K', T.toHex(en.K), v.K);
      chk(name + " K'", T.toHex(MLKEM.decapsInternal(p, kg.dk, en.ct).K), v.K);
      var bad = Uint8Array.from(en.ct); bad[0] ^= 1;
      chk(name + ' implicit rejection', T.toHex(MLKEM.decapsInternal(p, kg.dk, bad).K), v.K_implicit_reject);
      flush(); await tick();
    }
    group('ML-DSA (FIPS 204)', 'ML-DSA (FIPS 204)');
    var dkeys = {};
    for (name in V.mldsa) {
      v = V.mldsa[name]; var q = MLDSA.PARAMS[name];
      var k2 = MLDSA.keygenInternal(q, unhex(v.xi)); dkeys[name] = k2;
      var Mp = MLDSA.prepare(unhex(v.msg), new Uint8Array(0), null), sg = MLDSA.signInternal(q, k2.sk, Mp, unhex(v.rnd));
      chk(name + ' pk', await sha256hex(k2.pk), v.pk_sha256);
      chk(name + ' sk', await sha256hex(k2.sk), v.sk_sha256);
      chk(name + ' sig', await sha256hex(sg.sig), v.sig_sha256);
      chk(name + ' verify', MLDSA.verifyInternal(q, k2.pk, Mp, sg.sig), true);
      var bs = Uint8Array.from(sg.sig); bs[0] ^= 1;
      chk(name + ' tampered', MLDSA.verifyInternal(q, k2.pk, Mp, bs), false);
      flush(); await tick();
    }
    group('HashML-DSA (FIPS 204, thuật toán 4)', 'HashML-DSA (FIPS 204, Algorithm 4)');
    for (i = 0; i < V.prehash.length; i++) {
      v = V.prehash[i];
      var qq = MLDSA.PARAMS[v.set], mp2 = MLDSA.prepare(unhex(V.mldsa[v.set].msg), unhex(v.ctx), v.ph);
      var s2 = MLDSA.signInternal(qq, dkeys[v.set].sk, mp2, new Uint8Array(32)).sig;
      chk(v.set + ' ' + phLabel(v.ph) + ' sig', await sha256hex(s2), v.sig_sha256);
      chk(v.set + ' ' + phLabel(v.ph) + ' verify', MLDSA.verifyInternal(qq, dkeys[v.set].pk, mp2, s2), true);
      if (i % 3 === 2) { flush(); await tick(); }
    }
    group('Kiểm tra đầu vào của FIPS 203 · t0 của ML-DSA', 'FIPS 203 input checks · ML-DSA t0');
    for (name in V.kemcheck) {
      v = V.kemcheck[name]; var pk3 = MLKEM.PARAMS[name], kk = MLKEM.keygenInternal(pk3, unhex(V.mlkem[name].d), unhex(V.mlkem[name].z));
      var e2 = Uint8Array.from(kk.ek); e2[0] = 0xFF; e2[1] |= 0x0F;
      var d2 = Uint8Array.from(kk.dk); d2[768 * pk3.k + 40] ^= 1;
      chk(name + ' ek good', MLKEM.ekCheck(pk3, kk.ek), v.ek_good);
      chk(name + ' ek coefficient >= q', MLKEM.ekCheck(pk3, e2), v.ek_modulus);
      chk(name + ' dk good', MLKEM.dkCheck(pk3, kk.dk), v.dk_good);
      chk(name + ' dk hash', MLKEM.dkCheck(pk3, d2), v.dk_hash);
    }
    for (name in V.dsacheck) {
      var sk4 = Uint8Array.from(dkeys[name].sk); sk4[sk4.length - 3] ^= 1;
      var rc = MLDSA.recompute(MLDSA.PARAMS[name], sk4);
      chk(name + ' t0 flipped: t0 caught', rc.t0Ok, V.dsacheck[name].t0_flip_t0ok);
      chk(name + ' t0 flipped: tr still ok', rc.trOk, V.dsacheck[name].t0_flip_trok);
    }
    flush(); await tick();
    group('Khoá mẫu trong phụ lục C của RFC 9935 / RFC 9881', 'Example keys in Appendix C of RFC 9935 / RFC 9881');
    for (i = 0; i < V.rfc.length; i++) {
      v = V.rfc[i];
      try {
        var tabv = MLKEM.PARAMS[v.set] ? 'kem' : 'sig', it = T.readKeyFile(enc.encode(v.pem), 'x.pem');
        T.identify(it, tabv, v.set);
        chk(v.set + ' seed PEM -> public key', await sha256hex(it[0].pkFromSeed), v.pk_sha256);
        var pubi = T.readKeyFile(enc.encode(v.pub_pem), 'x.pem'); T.identify(pubi, tabv, v.set);
        chk(v.set + ' public-key PEM', await sha256hex(pubi[0].data), v.pk_sha256);
      } catch (e) { chk(v.set + ' PEM', 'error ' + (e.code || e.message), 'ok'); }
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
  phSync(true); mpUpdate(); kemUpdate(); dsaUpdate(); cvtUpdate();
  window.PQCCalc = {                                    // cửa cho bộ kiểm thử tự động; trang không tự dùng
    K: K, D: D, C: C,
    loadKey: function (tab, bytes, name) { keyLoader(tab === 'kem' ? KX : DX)(null, bytes, name); },
    loadBytes: function (field, bytes, name) { bytesLoader(field.id.indexOf('kem') === 0 ? KX : DX)(field, bytes, name); },
    loadMsg: function (bytes, name) { msgLoader(D.msg, bytes, name); },
    flush: function () { clearTimeout(pending.kem); clearTimeout(pending.dsa); delete pending.kem; delete pending.dsa; kemPairNow(); dsaPairNow(); }
  };
})();
