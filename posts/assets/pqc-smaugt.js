/* SMAUG-T (KpqC, KEM trên Module-LWE / Module-LWR) — hiện thực JavaScript thuần, viết từ đặc tả và mã tham chiếu 1.2.0.
   Bốn bộ tham số TiMER, SMAUG-T128/192/256; dùng tầng Keccak của pqc-mlkem.js (PQCHash). Bảng dGaussian được tính khi nạp.
   Original implementation for the ChiU·SoC PQC demo page. */
(function (root) {
  'use strict';
  var H = root.PQCHash;
  if (!H) throw new Error('pqc-mlkem.js phải được nạp trước pqc-smaugt.js');

  var N = 256, SEED = 32;
  var HWT_RAND = 308, HWT_SEEDBYTES = 2 * HWT_RAND;   // HWT: 308 số 16 bit, rồi 64 byte dấu
  var DG_BITS = 10;                                    // dGaussian: 9 bit độ lớn + 1 bit dấu mỗi mẫu
  var Q_HALF16 = 0x7FFF;                               // TiMER: q/2 dạng 16 bit của mã tham chiếu là 2^15 - 1
  /* hs = trọng số Hamming của MỖI đa thức của s (h_s của đặc tả = k * hs); r = P(+1) = P(-1) của spCBD */
  var PARAMS = {
    'TiMER':      { k: 2, logQ: 10, logP: 8, logP2: 3, hs: 70, r: [1, 8],  d2: true },
    'SMAUG-T128': { k: 2, logQ: 10, logP: 8, logP2: 5, hs: 70, r: [1, 8],  d2: false },
    'SMAUG-T192': { k: 3, logQ: 11, logP: 9, logP2: 4, hs: 88, r: [1, 4],  d2: false },
    'SMAUG-T256': { k: 4, logQ: 11, logP: 9, logP2: 7, hs: 87, r: [3, 16], d2: false }
  };
  function bitlen(x) { var n = 0; while (x > 0) { n++; x >>>= 1; } return n; }
  Object.keys(PARAMS).forEach(function (name) {
    var p = PARAMS[name];
    p.name = name; p.q = 1 << p.logQ; p.p = 1 << p.logP; p.p2 = 1 << p.logP2;
    p.cbdBits = bitlen(p.r[1]) - 1;                    // r = 1/8, 1/4, 3/16 -> 3, 2, 4 bit mỗi hệ số
    p.cbdSeed = p.cbdBits * N / 8;
    p.pkPoly = p.logQ * N / 8; p.ctPoly1 = p.logP * N / 8; p.ctPoly2 = p.logP2 * N / 8; p.skPoly = N / 4;
    p.msg = N / 8 / (p.d2 ? 2 : 1);                    // D2: mỗi bit thông điệp chiếm hai hệ số
    p.pkLen = SEED + p.k * p.pkPoly; p.skPke = p.k * p.skPoly; p.skLen = p.skPke + SEED + p.pkLen;
    p.ctLen = p.k * p.ctPoly1 + p.ctPoly2;
    p.rdAdd2 = 1 << (15 - p.logP2); p.rdAnd2 = 0x10000 - (1 << (16 - p.logP2));
  });
  function pset(name) { var p = PARAMS[name]; if (!p) throw new Error('bộ tham số không có: ' + name); return p; }
  function sizes(name) {
    var p = pset(name);
    return { pk: p.pkLen, sk: p.skLen, ct: p.ctLen, ss: 32, msg: p.msg, skPke: p.skPke };
  }

  /* ---------- băm ---------- */
  function cat(arrs) { var n = 0, i; for (i = 0; i < arrs.length; i++) n += arrs[i].length; var o = new Uint8Array(n), q = 0; for (i = 0; i < arrs.length; i++) { o.set(arrs[i], q); q += arrs[i].length; } return o; }
  function hashH(d) { return H.sha3_256(d); }                       // H = SHA3-256
  function hashG(a, b) { return H.shake256(cat([a, b]), 64); }      // G = SHAKE256(a || b): [0:32] hạt của Enc, [32:64] khoá
  function xof(d, len) { return H.shake128xof(d).squeeze(len); }    // XOF = SHAKE128, PRF = SHAKE256

  /* ---------- đóng gói bit little-endian, d bit mỗi hệ số ---------- */
  function pack(vals, d) {
    var out = new Uint8Array((vals.length * d) >> 3), m = (1 << d) - 1, acc = 0, nb = 0, o = 0, i;
    for (i = 0; i < vals.length; i++) {
      acc |= (vals[i] & m) << nb; nb += d;
      while (nb >= 8) { out[o++] = acc & 0xFF; acc >>>= 8; nb -= 8; }
    }
    return out;
  }
  function unpack(buf, d, count) {
    var f = new Int32Array(count), m = (1 << d) - 1, acc = 0, nb = 0, o = 0, i;
    for (i = 0; i < count; i++) {
      while (nb < d) { acc |= (buf[o++] | 0) << nb; nb += 8; }
      f[i] = acc & m; acc >>>= d; nb -= d;
    }
    return f;
  }
  /* s: mã 2 bit = (1 - s) & 3 (+1 -> 0, 0 -> 1, -1 -> 2); giải mã s = 1 - mã, mã 3 cho -2 (không từ chối) */
  function packS(s) { var c = new Int32Array(N), i; for (i = 0; i < N; i++) c[i] = (1 - s[i]) & 3; return pack(c, 2); }
  function unpackS(buf) { var c = unpack(buf, 2, N), i; for (i = 0; i < N; i++) c[i] = 1 - c[i]; return c; }

  /* ---------- lấy mẫu: A, HWT ---------- */
  function expandA(p, seedA) {
    var A = [], sd = new Uint8Array(SEED + 2), i, j;
    sd.set(seedA);
    for (i = 0; i < p.k; i++) {
      A.push([]);
      for (j = 0; j < p.k; j++) { sd[SEED] = i; sd[SEED + 1] = j; A[i].push(unpack(xof(sd, p.pkPoly), p.logQ, N)); }
    }
    return A;
  }
  /* REJ_SAMPLE_MOD: si[i] đều trên [0, N - i) kiểu nhân-lấy-phần-cao; hết dự trữ -> null */
  function rejSampleMod(rand) {
    var si = new Int32Array(N), j = N, i, s, t, m;
    for (i = 0; i < N; i++) {
      s = N - i; t = 65536 % s; m = rand[i] * s;
      while ((m & 0xFFFF) < t) {
        if (j >= HWT_RAND) return null;
        m = rand[j++] * s;
      }
      si[i] = m >>> 16;
    }
    return si;
  }
  function hwt(seed34, hs) {
    var st = H.shake256(seed34, HWT_SEEDBYTES + N / 4), rand = new Int32Array(HWT_RAND), res, si, c0, t0, v, sg, i;
    for (i = 0; i < HWT_RAND; i++) rand[i] = st[2 * i] | (st[2 * i + 1] << 8);
    si = rejSampleMod(rand);
    if (!si) return null;
    res = new Int32Array(N); c0 = N - hs;                // c0 = số vị trí 0 còn phải đặt
    for (i = 0; i < N; i++) {
      t0 = si[i] < c0 ? -1 : 0; c0 += t0; v = 1 + t0;
      sg = (st[HWT_SEEDBYTES + ((i >> 7) << 4) + (i & 15)] >> ((i >> 4) & 7)) & 1;   // chỉ 32 byte dấu đầu được dùng
      res[i] = sg ? v : -v;
    }
    return res;
  }
  function expandS(p, seed) {
    var s = [], sd = new Uint8Array(SEED + 2), i, j, v;
    sd.set(seed);
    for (i = 0; i < p.k; i++) {
      sd[SEED] = (i * p.k) & 0xFF;
      for (j = 0; ; j++) { sd[SEED + 1] = j; v = hwt(sd, p.hs); if (v) break; }   // đổi byte đếm khi cạn
      s.push(v);
    }
    return s;
  }

  /* ---------- lấy mẫu: dGaussian_1.0625 (hàm Boole 10 bit) -> bảng chân trị 1024 ô ---------- */
  function dgBool(x) {
    var x0 = x & 1, x1 = (x >> 1) & 1, x2 = (x >> 2) & 1, x3 = (x >> 3) & 1, x4 = (x >> 4) & 1;
    var x5 = (x >> 5) & 1, x6 = (x >> 6) & 1, x7 = (x >> 7) & 1, x8 = (x >> 8) & 1, x9 = (x >> 9) & 1;
    var n2 = 1 - x2, n1 = 1 - x1, n3 = 1 - x3, n4 = 1 - x4, n5 = 1 - x5, n6 = 1 - x6, n7 = 1 - x7, n8 = 1 - x8;
    var s0 = (x0 & x1 & x2 & x3 & x4 & x5 & x7 & n8) | (x0 & x3 & x4 & x5 & x6 & x8) |
             (x1 & x3 & x4 & x5 & x6 & x8) | (x2 & x3 & x4 & x5 & x6 & x8) |
             (n2 & n3 & n6 & x8) | (n1 & n3 & n6 & x8) |
             (x6 & x7 & n8) | (n5 & n6 & x8) | (n4 & n6 & x8) | (n7 & x8);
    var s1 = (x1 & x2 & x4 & x5 & x7 & x8) | (x3 & x4 & x5 & x7 & x8) | (x6 & x7 & x8);
    var v = s0 | (s1 << 1);
    return x9 ? -v : v;
  }
  var DG = new Int8Array(1 << DG_BITS);
  (function () { for (var x = 0; x < DG.length; x++) DG[x] = dgBool(x); })();
  /* SHAKE256 -> 4 khối x 64 làn cắt lát bit: bit j của mẫu kk trong khối blk nằm ở byte 80 blk + j + 10 (kk >> 3) */
  function dgPoly(seed33) {
    var buf = H.shake256(seed33, DG_BITS * N / 8), out = new Int32Array(N), blk, kk, j, idx, base;
    for (blk = 0; blk < N / 64; blk++) {
      base = DG_BITS * 8 * blk;
      for (kk = 0; kk < 64; kk++) {
        idx = 0;
        for (j = 0; j < DG_BITS; j++) idx |= ((buf[base + j + DG_BITS * (kk >> 3)] >> (kk & 7)) & 1) << j;
        out[64 * blk + kk] = DG[idx];
      }
    }
    return out;
  }
  function dgVec(p, seed) {
    var e = [], sd = new Uint8Array(SEED + 1), i;
    sd.set(seed);
    for (i = 0; i < p.k; i++) { sd[SEED] = (p.k * i) & 0xFF; e.push(dgPoly(sd)); }
    return e;
  }

  /* ---------- lấy mẫu: spCBD_r (dấu: bit 0 -> +1, bit 1 -> -1) ---------- */
  function spCbd(p, buf) {
    var f = new Int32Array(N), nb = p.cbdBits, i, t, b0, b1, b2, nz, sg;
    function bit(x) { return (buf[x >> 3] >> (x & 7)) & 1; }
    for (i = 0; i < N; i++) {
      t = nb * i; b0 = bit(t); b1 = bit(t + 1);
      if (nb === 2) { f[i] = b0 - b1; continue; }                    // r = 1/4: CBD_1
      b2 = bit(t + 2);
      if (nb === 3) { nz = b0 & b1; sg = b2; }                       // r = 1/8
      else { nz = (b0 | b1) & b2; sg = bit(t + 3); }                 // r = 3/16
      f[i] = nz ? (sg ? -1 : 1) : 0;
    }
    return f;
  }
  function expandR(p, seedR) {
    var r = [], sd = new Uint8Array(SEED + 1), i;
    sd.set(seedR);
    for (i = 0; i < p.k; i++) { sd[SEED] = i; r.push(spCbd(p, H.shake256(sd, p.cbdSeed))); }
    return r;
  }

  /* ---------- nhân thưa: acc += a * s trong Z[x]/(x^256 + 1), s có hệ số nhỏ -> chỉ cộng bản xoay x^j a ---------- */
  function mulAcc(acc, a, s) {
    var i, j, v, lim;
    for (j = 0; j < N; j++) {
      v = s[j]; if (!v) continue;
      v = v > 0 ? 1 : -1;                                             // chỉ lấy dấu: hệ số -2 (mã 3 hỏng) tính như -1, như mô hình tham chiếu
      lim = N - j;
      for (i = 0; i < lim; i++) acc[i + j] += v * a[i];
      for (; i < N; i++) acc[i - lim] -= v * a[i];                    // hệ số tràn đổi dấu
    }
    return acc;
  }

  /* ---------- SMAUG-T.PKE ---------- */
  function pkeKeygen(p, seed) {
    var ext = H.sha3_512(seed), seedSE = ext.subarray(0, 32), seedA = ext.subarray(32, 64);
    var s = expandS(p, seedSE), A = expandA(p, seedA), e = dgVec(p, seedSE), parts = [seedA], sk = [], i, j, b;
    for (i = 0; i < p.k; i++) {
      b = new Int32Array(N);
      for (j = 0; j < p.k; j++) mulAcc(b, A[i][j], s[j]);           // (A s)_i dùng A[i][j]
      for (j = 0; j < N; j++) b[j] = (e[i][j] - b[j]) & (p.q - 1);  // b = e - A s mod q
      parts.push(pack(b, p.logQ));
      sk.push(packS(s[i]));
    }
    return { pk: cat(parts), skPke: cat(sk) };
  }
  function msgTo16(p, mu) {
    var m = new Int32Array(N), i, bit;
    if (p.d2) {                                                      // D2: bit i đặt vào hệ số i và i + 128
      for (i = 0; i < N / 2; i++) { bit = (mu[i >> 3] >> (i & 7)) & 1; m[i] = m[i + N / 2] = bit ? Q_HALF16 : 0; }
    } else {
      for (i = 0; i < N; i++) m[i] = ((mu[i >> 3] >> (i & 7)) & 1) << 15;
    }
    return m;
  }
  function pkeEnc(p, pk, mu, seedR) {
    var A = expandA(p, pk.subarray(0, SEED)), r = expandR(p, seedR), parts = [], sh = p.logQ - p.logP;
    var i, j, u, br, m16, c2, v;
    for (i = 0; i < p.k; i++) {
      u = new Int32Array(N);
      for (j = 0; j < p.k; j++) mulAcc(u, A[j][i], r[j]);           // (A^T r)_i dùng A[j][i]
      for (j = 0; j < N; j++) u[j] = (((u[j] & (p.q - 1)) + (1 << (sh - 1))) >> sh) & (p.p - 1);   // làm tròn q -> p
      parts.push(pack(u, p.logP));
    }
    br = new Int32Array(N);
    for (i = 0; i < p.k; i++) mulAcc(br, unpack(pk.subarray(SEED + i * p.pkPoly, SEED + (i + 1) * p.pkPoly), p.logQ, N), r[i]);
    m16 = msgTo16(p, mu); c2 = new Int32Array(N);
    for (j = 0; j < N; j++) {                                        // thông điệp cộng TRƯỚC khi làm tròn q -> p', dạng 16 bit
      v = (m16[j] + ((br[j] & (p.q - 1)) << (16 - p.logQ))) & 0xFFFF;
      c2[j] = ((v + p.rdAdd2) & p.rdAnd2) >> (16 - p.logP2);
    }
    parts.push(pack(c2, p.logP2));
    return cat(parts);
  }
  function flipabs(x) { var t = (x - Q_HALF16) & 0xFFFF; if (t & 0x8000) t -= 0x10000; return Math.abs(t) & 0xFFFF; }
  function d2Decode16(v) {
    var msg = new Uint8Array(N / 16), i, t;
    for (i = 0; i < N / 2; i++) {                                    // bit = dấu của |v_i - q/2| + |v_{i+128} - q/2| - q/2
      t = (flipabs(v[i]) + flipabs(v[i + N / 2])) & 0xFFFF;
      t = ((t - Q_HALF16) & 0xFFFF) >> 15;
      msg[i >> 3] |= t << (i & 7);
    }
    return msg;
  }
  function pkeDec(p, skPke, ct) {
    var cs = new Int32Array(N), v = new Int32Array(N), c2, i, mu;
    for (i = 0; i < p.k; i++)
      mulAcc(cs, unpack(ct.subarray(i * p.ctPoly1, (i + 1) * p.ctPoly1), p.logP, N), unpackS(skPke.subarray(i * p.skPoly, (i + 1) * p.skPoly)));
    c2 = unpack(ct.subarray(p.k * p.ctPoly1), p.logP2, N);
    for (i = 0; i < N; i++) v[i] = ((c2[i] << (16 - p.logP2)) + ((cs[i] & (p.p - 1)) << (16 - p.logP))) & 0xFFFF;
    if (p.d2) return d2Decode16(v);
    mu = new Uint8Array(p.msg);
    for (i = 0; i < N; i++) mu[i >> 3] |= (((v[i] + 0x4000) & 0xFFFF) >> 15) << (i & 7);   // làm tròn về t = 2
    return mu;
  }

  /* ---------- SMAUG-T.KEM (biến đổi FO, từ chối ngầm bằng G(d || H(ct))) ---------- */
  function keygenInternal(name, d, seed) {
    var p = pset(name), r = pkeKeygen(p, seed);
    return { pk: r.pk, sk: cat([r.skPke, d, r.pk]) };
  }
  function encapsInternal(name, pk, mu) {
    var p = pset(name), g = hashG(mu, hashH(pk));
    return { ct: pkeEnc(p, pk, mu, g.subarray(0, 32)), K: g.slice(32) };
  }
  function decapsInternal(name, sk, ct) {
    var p = pset(name), skPke = sk.subarray(0, p.skPke), d = sk.subarray(p.skPke, p.skPke + SEED), pk = sk.subarray(p.skPke + SEED);
    var mu = pkeDec(p, skPke, ct), g = hashG(mu, hashH(pk)), ct2 = pkeEnc(p, pk, mu, g.subarray(0, 32));
    var kbar = hashG(d, hashH(ct)).slice(32), diff = 0, i, n = Math.min(ct.length, ct2.length), ok;
    for (i = 0; i < n; i++) diff |= ct[i] ^ ct2[i];                  // so toàn bộ, không thoát sớm
    ok = diff === 0 && ct.length === ct2.length;
    return { K: ok ? g.slice(32) : kbar, rejected: !ok };
  }
  /* kiểm tra mà mã tham chiếu không làm: độ dài, không có mã 3, đúng hs hệ số khác 0 mỗi đa thức */
  function skCheck(name, sk) {
    var p = pset(name), codes, i, j, w;
    if (sk.length !== p.skLen) return 'LENGTH';
    codes = unpack(sk.subarray(0, p.skPke), 2, p.k * N);
    for (i = 0; i < codes.length; i++) if (codes[i] === 3) return 'CODE3';
    for (i = 0; i < p.k; i++) {
      for (w = 0, j = 0; j < N; j++) if (codes[i * N + j] !== 1) w++;
      if (w !== p.hs) return 'WEIGHT';
    }
    return 'OK';
  }
  function pkFromSk(name, sk) { var p = pset(name); return sk.slice(p.skPke + SEED); }

  root.SMAUGT = {
    PARAMS: PARAMS, sizes: sizes,
    keygenInternal: keygenInternal, encapsInternal: encapsInternal, decapsInternal: decapsInternal,
    skCheck: skCheck, pkFromSk: pkFromSk
  };
})(typeof window !== 'undefined' ? window : globalThis);
