/* Công cụ cho máy tính KpqC (SMAUG-T, HAETAE): kích thước theo bộ tham số, nhận dạng khoá thô theo độ dài, kiểm tra
   cặp khoá. Hai thuật toán chưa có OID / định dạng file chuẩn hoá nên chỉ có khoá thô; file PEM / DER của ML-KEM,
   ML-DSA được nhận ra để chỉ người đọc sang trang kia. Cần pqc-tools.js, pqc-smaugt.js, pqc-haetae.js nạp trước.
   Original implementation for the ChiU·SoC PQC demo page. */
(function (root) {
  'use strict';
  function Err(code, info) { var e = new Error(code); e.code = code; e.info = info || {}; return e; }
  var KEMS = ['TiMER', 'SMAUG-T128', 'SMAUG-T192', 'SMAUG-T256'], SIGS = ['HAETAE-2', 'HAETAE-3', 'HAETAE-5'];
  /* thông điệp của phép thử khứ hồi: tất định theo pk, để cùng cặp khoá luôn cho cùng kết luận */
  function pctMessage(pk, n) {
    var pre = new TextEncoder().encode('pairwise consistency check|'), b = new Uint8Array(pre.length + pk.length);
    b.set(pre); b.set(pk, pre.length);
    return root.PQCHash.sha3_256(b).subarray(0, n);
  }
  function eq(a, b) { if (!a || !b || a.length !== b.length) return false; for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }

  function info(name) {                        // độ dài và loại của một bộ tham số
    if (KEMS.indexOf(name) >= 0) {
      var z = root.SMAUGT.sizes(name);
      return { name: name, tab: 'kem', pk: z.pk, sk: z.sk, seed: 64, ct: z.ct, msg: z.msg, skPke: z.skPke };
    }
    var y = root.HAETAE.sizes(name);
    return { name: name, tab: 'sig', pk: y.pk, sk: y.sk, seed: 32, sig: y.sig, lam: y.lam };
  }
  function keygenFromSeed(name, seed) {
    if (KEMS.indexOf(name) >= 0) return root.SMAUGT.keygenInternal(name, seed.subarray(0, 32), seed.subarray(32, 64));
    return root.HAETAE.keygenInternal(name, seed);
  }
  /* kích thước khoá ML-KEM / ML-DSA, để chỉ đường sang trang máy tính kia */
  function mlMatch(n) {
    var T = root.PQCTools, all = T ? T.KEMS.concat(T.SIGS) : [], i, a;
    for (i = 0; i < all.length; i++) { a = T.info(all[i]); if (n === a.pk || n === a.sk) return all[i]; }
    return null;
  }

  /* gắn thuật toán cho các mục đọc từ file (PQCTools.readKeyFile). tab: 'kem' | 'sig' */
  function identify(items, tab, current) {
    var ds = tab === 'kem' ? KEMS : SIGS, other = tab === 'kem' ? SIGS : KEMS, i, j;
    for (i = 0; i < items.length; i++) {
      var it = items[i];
      it.notes = it.notes || [];
      if (it.oid) {                            // có OID: chỉ có thể là ML-KEM / ML-DSA hoặc thuật toán khác
        var ml = root.PQCTools && root.PQCTools.OIDS[it.oid];
        throw Err(ml ? 'OTHER_PAGE' : 'UNSUPPORTED_ALG', { alg: ml || it.oid });
      }
      var n = it.data.length, hop = [];
      ds.forEach(function (a) { if (info(a).pk === n) hop.push([a, 'public']); });
      ds.forEach(function (a) { if (info(a).sk === n) hop.push([a, 'private']); });
      if (!hop.length) {
        for (j = 0; j < other.length; j++) {
          var o = info(other[j]);
          if (n === o.pk || n === o.sk) throw Err('OTHER_TAB', { alg: other[j], tab: o.tab, len: n });
        }
        throw Err('NO_SIZE_MATCH', { len: n, ml: mlMatch(n) });
      }
      var pick = hop.filter(function (h) { return h[0] === current; });
      if (!pick.length) { pick = hop; if (hop.length > 1) it.notes.push('MULTI_MATCH'); }
      it.alg = pick[0][0]; it.kind = pick[0][1];
    }
    for (i = 1; i < items.length; i++) if (items[i].alg !== items[0].alg) throw Err('MIXED');
    return items[0].alg;
  }

  /* kiểm tra cặp khoá: cùng thang như trang ML-KEM / ML-DSA. state: 'match' | 'other' | 'corrupt' | 'missing'.
     SMAUG-T: độ dài, khoá công khai (chỉ có kiểm tra độ dài), khoá bí mật (mã 2 bit, trọng số h_s), pk nhúng trong sk,
     khứ hồi. HAETAE: độ dài, vk nhúng trong sk, khứ hồi ký -> xác minh. Seed (nếu có) chỉ để thông tin. */
  function pairCheck(name, pk, sk, seed) {
    var a = info(name), rows = [], bad = false, ok;
    if (!pk || !sk || pk.length !== a.pk || sk.length !== a.sk) { rows.push(['len', false]); return { state: 'missing', rows: rows }; }
    rows.push(['len', true]);
    if (a.tab === 'kem') {
      rows.push(['pk_check', true]);
      ok = root.SMAUGT.skCheck(name, sk) === 'OK'; rows.push(['sk_check', ok]); bad = bad || !ok;
      if (!eq(root.SMAUGT.pkFromSk(name, sk), pk)) { rows.push(['derived_pk', false]); return { state: 'other', rows: rows }; }
      rows.push(['derived_pk', true]);
      try {
        var en = root.SMAUGT.encapsInternal(name, pk, pctMessage(pk, a.msg));
        ok = eq(en.K, root.SMAUGT.decapsInternal(name, sk, en.ct).K);
      } catch (e) { ok = false; }
    } else {
      if (!eq(root.HAETAE.pkFromSk(name, sk), pk)) { rows.push(['derived_pk', false]); return { state: 'other', rows: rows }; }
      rows.push(['derived_pk', true]);
      try {
        var m = new TextEncoder().encode('pairwise consistency check'), pre = new Uint8Array([0]);
        /* 150 vòng: khoá đúng cần quá 150 vòng với xác suất cỡ (5/6)^150 ~ 1e-12; khoá hỏng thì không treo trang 3-5 giây */
        ok = root.HAETAE.verifyInternal(name, pk, m, root.HAETAE.signInternal(name, sk, m, pre, new Uint8Array(32), 150).sig, pre).ok;
      } catch (e2) { ok = false; }
    }
    rows.push(['roundtrip', ok]); bad = bad || !ok;
    if (seed && seed.length) {
      if (seed.length !== a.seed) rows.push(['seed', null]);
      else { var kp = keygenFromSeed(name, seed); rows.push(['seed', eq(kp.pk, pk) && eq(kp.sk, sk)]); }
    }
    return { state: bad ? 'corrupt' : 'match', rows: rows };
  }

  root.KPQCTools = { KEMS: KEMS, SIGS: SIGS, info: info, identify: identify, pairCheck: pairCheck, keygenFromSeed: keygenFromSeed, eq: eq, mlMatch: mlMatch };
})(typeof window !== 'undefined' ? window : globalThis);
