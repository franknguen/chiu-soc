/* Công cụ cho máy tính SLH-DSA / FN-DSA / HQC-KEM: kích thước theo bộ tham số, quy tắc hàm băm của HashSLH-DSA,
   nhận dạng khoá thô theo độ dài, kiểm tra cặp khoá. Hàm thuần, không đụng DOM; chạy được cả trong Web Worker
   (các thuật toán được tra lúc gọi, không lúc nạp). Original implementation for the ChiU·SoC PQC demo page. */
(function (root) {
  'use strict';
  function Err(code, info) { var e = new Error(code); e.code = code; e.info = info || {}; return e; }
  function eq(a, b) { if (!a || !b || a.length !== b.length) return false; for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }
  function sub(b, i, j) { return b.subarray(i, j); }
  var FAMILY = { slh: 'SLHDSA', fn: 'FNDSA', hqc: 'HQC' };
  function lib(alg) { var L = root[FAMILY[alg]]; if (!L) throw new Error(FAMILY[alg] + ' chưa được nạp'); return L; }
  function names(alg) { return lib(alg).NAMES; }

  /* kích thước thống nhất: pk / sk là hai khoá của cặp, seed là đầu vào sinh khoá */
  function info(alg, name) {
    var z = lib(alg).sizes(name);
    if (alg === 'slh') return { alg: alg, name: name, pk: z.pk, sk: z.sk, seed: 3 * z.n, sig: z.sig, n: z.n, fast: !!z.fast };
    if (alg === 'fn') return { alg: alg, name: name, pk: z.pk, sk: z.sk, seed: 48, sig: z.sig, salt: 40, sseed: 48 };
    return { alg: alg, name: name, pk: z.ek, sk: z.dk, seed: z.dk, ct: z.ct, m: z.m, salt: z.salt };
  }
  /* FIPS 205 mục 10.2.2: giá trị băm đem ký phải dài ít nhất 2n byte (>= 8n bit an ninh chống va chạm) */
  function prehashAllowed(name, ph) {
    var n = lib('slh').sizes(name).n, L = root.MLDSA && root.MLDSA.PH_LIST, i;
    for (i = 0; L && i < L.length; i++) if (L[i].id === ph) return L[i].bytes >= 2 * n;
    return false;
  }

  /* khoá ML-KEM / ML-DSA: chỉ để chỉ đường sang trang máy tính kia */
  function mlMatch(n) {
    var T = root.PQCTools, all = T ? T.KEMS.concat(T.SIGS) : [], i, a;
    for (i = 0; i < all.length; i++) { a = T.info(all[i]); if (n === a.pk || n === a.sk) return all[i]; }
    return null;
  }
  /* gắn thuật toán cho các mục đọc từ file (PQCTools.readKeyFile). Khoá thô: theo độ dài, ưu tiên bộ đang mở, rồi
     loại khoá của nút đã bấm (prefer: 'public' | 'private'). Nhiều bộ cùng độ dài thì chọn bộ đầu và ghi MULTI_MATCH. */
  function identify(items, alg, current, prefer) {
    var others = ['slh', 'fn', 'hqc'].filter(function (x) { return x !== alg; }), i, j, k;
    for (i = 0; i < items.length; i++) {
      var it = items[i];
      it.notes = it.notes || [];
      if (it.oid) {
        var ml = root.PQCTools && root.PQCTools.OIDS[it.oid];
        throw Err(ml ? 'OTHER_PAGE' : 'UNSUPPORTED_ALG', { alg: ml || it.oid });
      }
      var n = it.data.length, hop = [];
      names(alg).forEach(function (a) { if (info(alg, a).pk === n) hop.push([a, 'public']); });
      names(alg).forEach(function (a) { if (info(alg, a).sk === n) hop.push([a, 'private']); });
      if (!hop.length) {
        for (j = 0; j < others.length; j++) {
          if (!root[FAMILY[others[j]]]) continue;
          var nm = names(others[j]);
          for (k = 0; k < nm.length; k++) {
            var o = info(others[j], nm[k]);
            if (n === o.pk || n === o.sk) throw Err('OTHER_TAB', { alg: nm[k], tab: others[j], len: n });
          }
        }
        throw Err('NO_SIZE_MATCH', { len: n, ml: mlMatch(n) });
      }
      var pick = hop.filter(function (h) { return h[0] === current; });
      if (pick.length > 1 && prefer) pick = pick.filter(function (h) { return h[1] === prefer; });
      if (!pick.length) {
        pick = prefer ? hop.filter(function (h) { return h[1] === prefer; }) : [];
        if (!pick.length) pick = hop;
        var sets = {}; pick.forEach(function (h) { sets[h[0]] = 1; });
        if (Object.keys(sets).length > 1) it.notes.push('MULTI_MATCH');
      }
      it.alg = pick[0][0]; it.kind = pick[0][1];
    }
    for (i = 1; i < items.length; i++) if (items[i].alg !== items[0].alg) throw Err('MIXED');
    return items[0].alg;
  }

  /* thông điệp của phép thử khứ hồi: tất định theo pk, như hai trang anh em */
  function pctMessage(pk, len) {
    var pre = new TextEncoder().encode('pairwise consistency check|'), b = new Uint8Array(pre.length + pk.length);
    b.set(pre); b.set(pk, pre.length);
    return root.PQCHash.sha3_256(b).subarray(0, len);
  }
  /* kiểm tra cặp khoá. state: 'match' | 'other' | 'corrupt' | 'missing'; rows: [id, true / false / null].
     SLH-DSA: độ dài, pk lưu trong sk, gốc cây trên cùng tính lại từ SK.seed và PK.seed, seed (thông tin).
     FN-DSA: độ dài, giải mã sk, h = g/f mod q, phương trình NTRU fG - gF = q giải được, khứ hồi ký -> xác minh, seed.
     HQC-KEM: độ dài, Keygen(dk) cho đúng ek (dk chính là seed), khứ hồi đóng gói -> giải đóng gói. */
  function pairCheck(alg, name, pk, sk, seed) {
    var a = info(alg, name), rows = [], ok, kp;
    if (!pk || !sk || pk.length !== a.pk || sk.length !== a.sk) return { state: 'missing', rows: [['len', false]] };
    rows.push(['len', true]);
    if (alg === 'slh') {
      var n = a.n, S = lib('slh');
      if (!eq(sub(sk, 2 * n, 4 * n), pk)) { rows.push(['derived_pk', false]); return { state: 'other', rows: rows }; }
      rows.push(['derived_pk', true]);
      kp = S.keygenInternal(name, sub(sk, 0, n), sub(sk, n, 2 * n), sub(sk, 2 * n, 3 * n));
      ok = eq(sub(kp.pk, n, 2 * n), sub(sk, 3 * n, 4 * n));
      rows.push(['root', ok]);
      if (seed && seed.length) {
        if (seed.length !== a.seed) rows.push(['seed', null]);
        else { var k2 = S.keygenInternal(name, sub(seed, 0, n), sub(seed, n, 2 * n), sub(seed, 2 * n, 3 * n)); rows.push(['seed', eq(k2.pk, pk) && eq(k2.sk, sk)]); }
      }
      return { state: ok ? 'match' : 'corrupt', rows: rows };
    }
    if (alg === 'fn') {
      var F = lib('fn'), c = F.checkSk(name, sk), bad;
      rows.push(['sk_decode', !!c.decoded]);
      if (!c.decoded) return { state: 'corrupt', rows: rows };
      if (!c.pk || !eq(c.pk, pk)) { rows.push(['derived_pk', false]); return { state: 'other', rows: rows }; }
      rows.push(['derived_pk', true]);
      rows.push(['ntru', !!c.ntru]); bad = !c.ntru; ok = false;
      if (c.ntru) {
        try {
          var m = new TextEncoder().encode('pairwise consistency check');
          ok = F.verify(name, pk, m, F.sign(name, sk, m, new Uint8Array(40), new Uint8Array(48)).sig).ok;
        } catch (e) { ok = false; }
      }
      rows.push(['roundtrip', ok]); bad = bad || !ok;
      if (seed && seed.length) {
        if (seed.length !== 48) rows.push(['seed', null]);
        else { kp = F.keygen(name, seed); rows.push(['seed', eq(kp.pk, pk) && eq(kp.sk, sk)]); }
      }
      return { state: bad ? 'corrupt' : 'match', rows: rows };
    }
    var H = lib('hqc');
    if (!eq(H.keygenInternal(name, sk).ek, pk)) { rows.push(['derived_pk', false]); return { state: 'other', rows: rows }; }
    rows.push(['derived_pk', true]);
    var en = H.encapsInternal(name, pk, pctMessage(pk, a.m), new Uint8Array(16));
    ok = eq(H.decaps(name, sk, en.ct).K, en.K);
    rows.push(['roundtrip', ok]);
    return { state: ok ? 'match' : 'corrupt', rows: rows };
  }

  root.NIST3Tools = { info: info, names: names, identify: identify, pairCheck: pairCheck, prehashAllowed: prehashAllowed, eq: eq, mlMatch: mlMatch };
})(typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : globalThis));
