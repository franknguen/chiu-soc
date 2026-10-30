/* Công cụ cho máy tính PQC: định dạng dữ liệu (hex / Base64 / mảng C / mảng Java / văn bản), đọc file khoá
   (PEM, DER, SPKI, PKCS#8 ba dạng seed / expandedKey / both của RFC 9935 và RFC 9881, chứng chỉ X.509, khoá thô)
   và kiểm tra cặp khoá. Hàm thuần, không đụng tới DOM. Cần pqc-mlkem.js và pqc-mldsa.js nạp trước.
   Original implementation for the ChiU·SoC PQC demo page. */
(function (root) {
  'use strict';
  var MLKEM = root.MLKEM, MLDSA = root.MLDSA;
  if (!MLKEM || !MLDSA) throw new Error('pqc-mlkem.js và pqc-mldsa.js phải được nạp trước pqc-tools.js');

  function Err(code, info) { var e = new Error(code); e.code = code; e.info = info || {}; return e; }

  /* ================================================================ định dạng */
  var HEXD = '0123456789abcdef';
  function h2(x) { return HEXD[x >> 4] + HEXD[x & 15]; }
  function toHex(b) { var s = '', i; for (i = 0; i < b.length; i++) s += h2(b[i]); return s; }
  function list(b, f) { var a = [], i; for (i = 0; i < b.length; i++) a.push(f(h2(b[i]).toUpperCase())); return a; }
  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  function toBase64(b) {
    var s = '', i, v;
    for (i = 0; i + 2 < b.length; i += 3) {
      v = (b[i] << 16) | (b[i + 1] << 8) | b[i + 2];
      s += B64[v >> 18] + B64[(v >> 12) & 63] + B64[(v >> 6) & 63] + B64[v & 63];
    }
    if (b.length - i === 1) { v = b[i] << 16; s += B64[v >> 18] + B64[(v >> 12) & 63] + '=='; }
    else if (b.length - i === 2) { v = (b[i] << 16) | (b[i + 1] << 8); s += B64[v >> 18] + B64[(v >> 12) & 63] + B64[(v >> 6) & 63] + '='; }
    return s;
  }
  function toText(b) {
    try { return new TextDecoder('utf-8', { fatal: true }).decode(b); }
    catch (e) { throw Err('NOT_UTF8'); }
  }
  var FORMATS = {
    hex:    function (b) { return toHex(b); },
    HEX:    function (b) { return toHex(b).toUpperCase(); },
    spaced: function (b) { return list(b, function (x) { return x; }).join(' '); },
    colon:  function (b) { return list(b, function (x) { return x; }).join(':'); },
    c:      function (b) { return b.length ? '{ ' + list(b, function (x) { return '0x' + x; }).join(', ') + ' }' : ''; },
    java:   function (b) { return b.length ? '{ ' + list(b, function (x) { return '(byte) 0x' + x; }).join(', ') + ' }' : ''; },
    base64: toBase64,
    text:   toText
  };
  function format(b, fmt) {
    var f = FORMATS[fmt];
    if (!f) throw new Error('unknown format ' + fmt);
    return f(b);
  }

  /* ================================================================ đọc đầu vào */
  function fromHexDigits(s) {
    var a = new Uint8Array(s.length / 2), i;
    for (i = 0; i < a.length; i++) a[i] = parseInt(s.substr(2 * i, 2), 16);
    return a;
  }
  function parseHex(s) {                       // hex liền, cho phép 0x đầu và khoảng trắng
    s = s.replace(/\s+/g, '');
    if (s.slice(0, 2).toLowerCase() === '0x') s = s.slice(2);
    if (!/^[0-9a-fA-F]*$/.test(s)) throw Err('HEX_CHAR');
    if (s.length % 2) throw Err('HEX_ODD');
    return fromHexDigits(s);
  }
  function parseB64(s) {                       // Base64 chuẩn hoặc URL-safe, có hay không có '='
    s = s.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 === 1) throw Err('B64');
    while (s.length % 4) s += '=';
    var body = s.replace(/=+$/, '');
    if (s.length - body.length > 2) throw Err('B64');   // ví dụ "A==" thành "A===": thiếu dữ liệu
    var out = new Uint8Array(Math.floor(body.length * 3 / 4)), v = 0, bits = 0, o = 0, i;
    for (i = 0; i < body.length; i++) {
      v = ((v << 6) | B64.indexOf(body[i])) & 0xFFFF; bits += 6;
      if (bits >= 8) { bits -= 8; out[o++] = (v >> bits) & 0xFF; }
    }
    return out.subarray(0, o);                 // bit thừa cuối bị bỏ qua, như b64decode
  }
  var CAST = /^\((?:byte|u?int8_t|unsigned\s+char|signed\s+char|char)\)\s*/i;
  function parseArray(body) {
    var items = body.split(',').map(function (x) { return x.trim(); }).filter(function (x) { return x; });
    var out = new Uint8Array(items.length), i, item, v;
    for (i = 0; i < items.length; i++) {
      item = items[i].replace(CAST, '');
      if (/^[+-]?0x[0-9a-fA-F]+$/i.test(item)) {
        v = parseInt(item.replace(/^[+-]/, '').slice(2), 16);
        if (item[0] === '-') v = -v;           // một lần đổi dấu (trang mẫu đổi hai lần: -0x01 thành 0x01)
      } else if (/^[+-]?\d+$/.test(item)) v = parseInt(item, 10);
      else throw Err('ARRAY_ITEM', { item: items[i] });
      if (v < -128 || v > 255) throw Err('ARRAY_RANGE', { item: items[i] });
      out[i] = v & 0xFF;
    }
    return out;
  }
  function parseAuto(s) {                      // ô "Auto": hex (có dấu cách / hai chấm) hoặc mảng C / Java / thập phân
    s = s.trim();
    if (!s) return { bytes: new Uint8Array(0), kind: '' };
    var open = s.indexOf('{') >= 0 ? '{' : (s.indexOf('[') >= 0 ? '[' : '');
    if (open) {
      var close = open === '{' ? '}' : ']', a = s.indexOf(open), b = s.lastIndexOf(close);
      if (b < a) throw Err('ARRAY_CLOSE', { close: close });
      var data = parseArray(s.slice(a + 1, b));
      var kind = /\(byte\)|new\s+byte|byte\s*\[/i.test(s) ? 'java' : (/0x/i.test(s) ? 'c' : 'dec');
      return { bytes: data, kind: kind };
    }
    var toks = s.split(/[\s,:;-]+/).filter(function (t) { return t; })
      .map(function (t) { return t.slice(0, 2).toLowerCase() === '0x' ? t.slice(2) : t; });
    if (!toks.every(function (t) { return /^[0-9a-fA-F]+$/.test(t); })) throw Err('AUTO');
    if (toks.length === 1 && toks[0].length % 2) throw Err('HEX_ODD');
    if (toks.length > 1 && toks.some(function (t) { return t.length > 1 && t.length % 2; })) throw Err('HEX_ODD');
    return { bytes: fromHexDigits(toks.map(function (t) { return t.length === 1 ? '0' + t : t; }).join('')), kind: 'hex' };
  }
  function parseInput(s, fmt) {                // auto | hex | base64 | text | c | java
    if (fmt === 'text') return new TextEncoder().encode(s);
    if (fmt === 'auto' || fmt === 'c' || fmt === 'java') return parseAuto(s).bytes;
    if (fmt === 'hex') return s.trim() ? parseHex(s) : new Uint8Array(0);
    if (fmt === 'base64') return s.trim() ? parseB64(s) : new Uint8Array(0);
    throw new Error('unknown format ' + fmt);
  }

  /* ================================================================ DER tối thiểu */
  var T = { SEQ: 0x30, INT: 0x02, BIT: 0x03, OCT: 0x04, OID: 0x06, CTX0P: 0x80, CTX0C: 0xA0 };
  function tlv(b, p) {
    var hdr = p;
    if (p + 2 > b.length) throw Err('DER');
    var tag = b[p], ln = b[p + 1]; p += 2;
    if (ln & 0x80) {
      var n = ln & 0x7F, i;
      if (n < 1 || n > 4) throw Err('DER');
      if (p + n > b.length) throw Err('DER');
      for (ln = 0, i = 0; i < n; i++) ln = ln * 256 + b[p + i];
      p += n;
    }
    if (p + ln > b.length) throw Err('DER');
    return { tag: tag, start: p, end: p + ln, hdr: hdr, b: b, val: b.subarray(p, p + ln) };
  }
  function kids(node) {
    var out = [], p = node.start, k;
    while (p < node.end) { k = tlv(node.b, p); out.push(k); p = k.end; }
    if (p !== node.end) throw Err('DER');
    return out;
  }
  function oidDecode(c) {
    var parts = [], v = 0, i;
    for (i = 0; i < c.length; i++) {
      v = v * 128 + (c[i] & 0x7F);
      if (!(c[i] & 0x80)) {
        if (!parts.length) { var f = v < 40 ? 0 : (v < 80 ? 1 : 2); parts.push(f, v - 40 * f); }
        else parts.push(v);
        v = 0;
      } else if (i === c.length - 1) throw Err('DER');
    }
    return parts.join('.');
  }

  /* ================================================================ thuật toán theo OID / độ dài */
  var OIDS = {
    '2.16.840.1.101.3.4.4.1': 'ML-KEM-512', '2.16.840.1.101.3.4.4.2': 'ML-KEM-768', '2.16.840.1.101.3.4.4.3': 'ML-KEM-1024',
    '2.16.840.1.101.3.4.3.17': 'ML-DSA-44', '2.16.840.1.101.3.4.3.18': 'ML-DSA-65', '2.16.840.1.101.3.4.3.19': 'ML-DSA-87'
  };
  var OTHER_OIDS = {
    '1.2.840.113549.1.1.1': 'RSA', '1.2.840.113549.1.1.10': 'RSA-PSS', '1.2.840.10045.2.1': 'EC',
    '1.3.101.110': 'X25519', '1.3.101.111': 'X448', '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448'
  };
  function info(name) {                        // độ dài và loại của một bộ tham số
    if (MLKEM.PARAMS[name]) {
      var z = MLKEM.sizes(MLKEM.PARAMS[name]);
      return { name: name, tab: 'kem', pk: z.ek, sk: z.dk, seed: 64 };
    }
    var y = MLDSA.sizes(MLDSA.PARAMS[name]);
    return { name: name, tab: 'sig', pk: y.pk, sk: y.sk, seed: 32 };
  }
  var KEMS = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'], SIGS = ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'];
  function keygenFromSeed(name, seed) {
    if (MLKEM.PARAMS[name]) { var r = MLKEM.keygenInternal(MLKEM.PARAMS[name], seed.subarray(0, 32), seed.subarray(32, 64)); return { pk: r.ek, sk: r.dk }; }
    return MLDSA.keygenInternal(MLDSA.PARAMS[name], seed);
  }
  function eq(a, b) { if (!a || !b || a.length !== b.length) return false; for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }

  /* ================================================================ đọc file khoá */
  function spki(node) {
    var k = node.tag === T.SEQ ? kids(node) : [];
    if (k.length !== 2 || k[0].tag !== T.SEQ || k[1].tag !== T.BIT) throw Err('DER');
    var alg = kids(k[0]);
    if (!alg.length || alg[0].tag !== T.OID) throw Err('DER');
    var oid = oidDecode(alg[0].val);
    if (alg.length !== 1 && OIDS[oid]) throw Err('SPKI_PARAMS', { alg: OIDS[oid] });
    var bits = k[1].val;
    if (!bits.length || bits[0] !== 0) throw Err('DER');
    return { kind: 'public', oid: oid, data: bits.slice(1) };
  }
  function classifyDer(der, enc) {             // chứng chỉ X.509 | SPKI | PKCS#8, nếu không: Err('DER')
    var top = tlv(der, 0);
    if (top.tag !== T.SEQ || top.end !== der.length) throw Err('DER');
    var c = kids(top);
    if (c.length && c[0].tag === T.INT) {                                  // PKCS#8 / OneAsymmetricKey
      var k1 = c.length > 1 && c[1].tag === T.SEQ ? kids(c[1]) : [];
      var oid = k1.length && k1[0].tag === T.OID ? oidDecode(k1[0].val) : '';
      if (oid.indexOf('1.2.840.113549.1.7.') === 0) throw Err('PKCS12');
      if (!oid || c.length < 3 || c[2].tag !== T.OCT) throw Err('DER');
      var inner = c[2].val, seed = null, expanded = null, form;
      try {
        var t = tlv(inner, 0);
        if (t.end !== inner.length) throw Err('DER');
        if (t.tag === T.CTX0P) { seed = t.val.slice(); form = 'seed'; }
        else if (t.tag === T.OCT) { expanded = t.val.slice(); form = 'expandedKey'; }
        else if (t.tag === T.SEQ) {
          var kk = kids(t);
          if (kk.length !== 2 || kk[0].tag !== T.OCT || kk[1].tag !== T.OCT) throw Err('DER');
          seed = kk[0].val.slice(); expanded = kk[1].val.slice(); form = 'both';
        } else throw Err('DER');
      } catch (e) {
        if (e.code !== 'DER') throw e;
        expanded = inner.slice(); form = 'raw';                             // bản nháp trước RFC: khoá thô trong OCTET STRING
      }
      return { kind: 'private', oid: oid, data: expanded, seed: seed, expanded: expanded, form: form, enc: enc };
    }
    if (c.length && c[0].tag === T.SEQ) {
      var k0 = kids(c[0]);
      if (k0.length && k0[0].tag === T.OID) {                              // SPKI
        if (c.length > 1 && c[1].tag === T.OCT) throw Err('ENCRYPTED');
        var it = spki(top); it.enc = enc; it.form = 'spki'; return it;
      }
      var i = k0.length && k0[0].tag === T.CTX0C ? 1 : 0;                  // chứng chỉ: [0] version tuỳ chọn
      if (k0.length <= i + 5 || c.length !== 3) throw Err('DER');
      var cert = spki(k0[i + 5]); cert.enc = enc; cert.form = 'cert'; cert.cert = true;
      return cert;
    }
    throw Err('DER');
  }
  function isText(b) { for (var i = 0; i < b.length; i++) { var x = b[i]; if (!(x === 9 || x === 10 || x === 13 || (x >= 32 && x < 127))) return false; } return true; }
  function fromBytes(b, enc) {
    try { return [classifyDer(b, enc)]; }
    catch (e) { if (e.code !== 'DER') throw e; return [{ kind: null, oid: null, data: b, enc: enc, form: 'raw' }]; }
  }
  function pemBlocks(text) {
    var re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g, m, out = [];
    while ((m = re.exec(text))) {
      var body = m[2].split(/\r\n|\r|\n/).filter(function (l) { return l.indexOf(':') < 0; }).join('').replace(/\s+/g, '');
      var der;
      try { der = parseB64(body); } catch (e) { throw Err('BAD_PEM_BLOCK', { label: m[1] }); }
      out.push({ label: m[1], der: der });
    }
    return out;
  }
  /* nội dung file (hoặc chữ dán vào) -> các mục khoá chưa gắn thuật toán */
  function readKeyFile(buf, fname) {
    fname = (fname || '').toLowerCase();
    if (/\.(pfx|p12)$/.test(fname)) throw Err('PKCS12');
    if (buf.length > (1 << 20)) throw Err('TOO_BIG');
    if (buf[0] === 0xEF && buf[1] === 0xBB && buf[2] === 0xBF) buf = buf.subarray(3);
    if (!isText(buf)) return fromBytes(buf, 'DER');
    var text = String.fromCharCode.apply(null, Array.prototype.slice.call(buf, 0));
    if (text.indexOf('-----BEGIN') >= 0) {
      var blocks = pemBlocks(text), items = [], i;
      for (i = 0; i < blocks.length; i++) {
        if (blocks[i].label.indexOf('ENCRYPTED') >= 0) throw Err('ENCRYPTED');
        try { items.push(classifyDer(blocks[i].der, 'PEM')); }
        catch (e) { if (e.code === 'DER') throw Err('BAD_PEM_BLOCK', { label: blocks[i].label }); throw e; }
      }
      if (!items.length) throw Err('BAD_PEM');
      return items;
    }
    var s = text.replace(/\s+/g, ''), b;
    try { b = parseHex(s); if (b.length) return fromBytes(b, 'hex'); } catch (e) { if (!e.code || e.code === 'DER') throw e; }
    try { b = parseB64(s); if (b.length) return fromBytes(b, 'base64'); } catch (e) { if (!e.code || e.code === 'DER') throw e; }
    throw Err('UNRECOGNIZED');
  }
  /* gắn thuật toán (OID hoặc độ dài), mở rộng seed, kiểm seed <-> expandedKey. tab: 'kem' | 'sig' */
  function identify(items, tab, current) {
    var ds = tab === 'kem' ? KEMS : SIGS, other = tab === 'kem' ? SIGS : KEMS, i, j;
    for (i = 0; i < items.length; i++) {
      var it = items[i];
      it.notes = it.notes || [];
      if (it.oid) {
        var name = OIDS[it.oid];
        if (!name) throw Err('UNSUPPORTED_ALG', { alg: OTHER_OIDS[it.oid] || it.oid });
        if (info(name).tab !== tab) throw Err('OTHER_TAB', { alg: name, tab: info(name).tab });
        it.alg = name;
      } else {
        var n = it.data.length, hop = [];
        ds.forEach(function (a) { if (info(a).pk === n) hop.push([a, 'public']); });
        ds.forEach(function (a) { if (info(a).sk === n) hop.push([a, 'private']); });
        if (!hop.length) {
          for (j = 0; j < other.length; j++) {
            var o = info(other[j]);
            if (n === o.pk || n === o.sk)
              throw Err('OTHER_TAB', { alg: other[j], tab: o.tab, len: n, kind: n === o.pk ? 'public' : 'private' });
          }
          throw Err('NO_SIZE_MATCH', { len: n });
        }
        var pick = hop.filter(function (h) { return h[0] === current; });
        if (!pick.length) { pick = hop; if (hop.length > 1) it.notes.push('MULTI_MATCH'); }
        it.alg = pick[0][0]; it.kind = pick[0][1];
      }
    }
    for (i = 1; i < items.length; i++) if (items[i].alg !== items[0].alg) throw Err('MIXED');
    for (i = 0; i < items.length; i++) expand(items[i]);
    return items[0].alg;
  }
  function expand(it) {
    var a = info(it.alg);
    if (it.kind === 'private' && it.oid) {
      if (it.seed) {
        if (it.seed.length !== a.seed) throw Err('SEED_LEN', { want: a.seed, got: it.seed.length });
        var kp = keygenFromSeed(it.alg, it.seed);
        if (it.expanded && !eq(it.expanded, kp.sk)) throw Err('SEED_MISMATCH');
        it.data = kp.sk; it.pkFromSeed = kp.pk;
      } else it.data = it.expanded;
    }
    var want = it.kind === 'public' ? a.pk : a.sk;
    if (it.data.length !== want) throw Err('KEY_LEN', { want: want, got: it.data.length, kind: it.kind, alg: it.alg });
    if (it.kind === 'private' && a.tab === 'kem' && MLKEM.dkCheck(MLKEM.PARAMS[it.alg], it.data) !== 'OK') it.notes.push('SK_WARN');
  }

  /* ================================================================ kiểm tra cặp khoá */
  /* state: 'match' | 'other' (khoá bí mật của cặp khác) | 'corrupt' (hỏng / không nhất quán) | 'missing'.
     rows: [id, true/false/null] theo thứ tự đã kiểm. Cùng thang kiểm như trang mẫu (getPublicKey(sk) rồi khứ hồi),
     thêm kiểm tra đầu vào FIPS 203, tr và t0 của ML-DSA (RFC 9881 C.4) và seed (chỉ để thông tin). */
  function pairCheck(name, pk, sk, seed) {
    var a = info(name), rows = [], bad = false, ok;
    if (!pk || !sk || pk.length !== a.pk || sk.length !== a.sk) { rows.push(['len', false]); return { state: 'missing', rows: rows }; }
    rows.push(['len', true]);
    var kem = a.tab === 'kem', P = kem ? MLKEM.PARAMS[name] : MLDSA.PARAMS[name], ekOk = true, dkOk = true, rc;
    if (kem) {
      ekOk = MLKEM.ekCheck(P, pk) === 'OK'; rows.push(['pk_check', ekOk]); bad = bad || !ekOk;
      dkOk = MLKEM.dkCheck(P, sk) === 'OK'; rows.push(['sk_check', dkOk]); bad = bad || !dkOk;
      if (!eq(MLKEM.ekFromDk(P, sk), pk)) { rows.push(['derived_pk', false]); return { state: 'other', rows: rows }; }
      rows.push(['derived_pk', true]);
    } else {
      ok = MLDSA.skCheck(P, sk) === 'OK'; rows.push(['range', ok]);
      if (!ok) return { state: 'corrupt', rows: rows };
      rc = MLDSA.recompute(P, sk);
      if (!eq(rc.pk, pk)) { rows.push(['derived_pk', false]); return { state: 'other', rows: rows }; }
      rows.push(['derived_pk', true]);
      rows.push(['tr', rc.trOk]); rows.push(['t0', rc.t0Ok]);
      bad = bad || !(rc.trOk && rc.t0Ok);
    }
    if (kem) {                                  // khứ hồi: đóng gói tới pk rồi giải bằng sk
      ok = false;
      if (ekOk && dkOk) {
        var en = MLKEM.encapsInternal(P, pk, MLKEM.randomBytes(32));
        ok = eq(en.K, MLKEM.decapsInternal(P, sk, en.ct).K);
      }
    } else {
      var Mp = MLDSA.prepare(new TextEncoder().encode('pairwise consistency check'), new Uint8Array(0), null);
      ok = MLDSA.verifyInternal(P, pk, Mp, MLDSA.signInternal(P, sk, Mp, new Uint8Array(32)).sig);
    }
    rows.push(['roundtrip', ok]); bad = bad || !ok;
    if (seed && seed.length) {
      if (seed.length !== a.seed) rows.push(['seed', null]);
      else { var kp = keygenFromSeed(name, seed); rows.push(['seed', eq(kp.pk, pk) && eq(kp.sk, sk)]); }
    }
    return { state: bad ? 'corrupt' : 'match', rows: rows };
  }

  root.PQCTools = {
    FORMATS: Object.keys(FORMATS), format: format, toHex: toHex, toBase64: toBase64,
    parseHex: parseHex, parseB64: parseB64, parseAuto: parseAuto, parseInput: parseInput,
    readKeyFile: readKeyFile, identify: identify, pemBlocks: pemBlocks, info: info,
    KEMS: KEMS, SIGS: SIGS, OIDS: OIDS, keygenFromSeed: keygenFromSeed, pairCheck: pairCheck, eq: eq
  };
})(typeof window !== 'undefined' ? window : globalThis);
