/* HQC-KEM (HQC-1/3/5; the HQC specification (2026-10-12), ngữ nghĩa mã tham chiếu v5.1.0) — JavaScript thuần.
   Bảng GF(2^8), đa thức sinh RS và ma trận sinh RM được TÍNH khi nạp, không chép tay.
   Original implementation for the ChiU·SoC PQC demo page. */
(function (root) {
  'use strict';

  function HS() {                                // tầng Keccak của pqc-mlkem.js (nạp trước)
    if (!root.PQCHash) throw new Error('HQC: PQCHash missing (load pqc-mlkem.js first)');
    return root.PQCHash;
  }
  function cat(arrs) {
    var len = 0, i, o = 0;
    for (i = 0; i < arrs.length; i++) len += arrs[i].length;
    var out = new Uint8Array(len);
    for (i = 0; i < arrs.length; i++) { out.set(arrs[i], o); o += arrs[i].length; }
    return out;
  }

  /* ---------- hàm băm có byte miền (Bảng 2-3) ---------- */
  function G(d) { return HS().sha3_512(cat([d, [0x00]])); }   // (K, theta)
  function H(d) { return HS().sha3_256(cat([d, [0x01]])); }   // băm ek
  function I(d) { return HS().sha3_512(cat([d, [0x02]])); }   // (seed_dk, seed_ek)
  function J(d) { return HS().sha3_256(cat([d, [0x03]])); }   // khoá từ chối ngầm
  function xofPke(seed) { return HS().shake256xof(Uint8Array.from(seed)); }        // PKE: không byte miền
  function xofKem(seed, P) { return HS().shake256xof(cat([seed, [P.k1]])); }       // KEM: seed || k

  /* ---------- GF(2^8): p = 0x11B, alpha = 0x03 (Bảng 1-2) ---------- */
  var GF_EXP = new Uint8Array(512), GF_LOG = new Uint8Array(256);
  (function () {
    var x = 1, seen = 0, i;
    for (i = 0; i < 255; i++) {
      GF_EXP[i] = x; GF_LOG[x] = i; if (x === 1) seen++;
      var a = x, b = 3, r = 0;                   // x * alpha bằng dịch-XOR
      while (b) { if (b & 1) r ^= a; a <<= 1; if (a & 0x100) a ^= 0x11B; b >>= 1; }
      x = r;
    }
    if (x !== 1 || seen !== 1) throw new Error('HQC: alpha not primitive');
    for (i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
  })();
  function gfMul(a, b) { return (a === 0 || b === 0) ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]]; }
  function gfInv(a) { return GF_EXP[(255 - GF_LOG[a]) % 255]; }
  function zeros(n) { var a = new Array(n); for (var i = 0; i < n; i++) a[i] = 0; return a; }

  /* ---------- tham số (Bảng 6-8): n, n1, k1, t1, mult, w, wr = we ---------- */
  var SETS = { 'HQC-1': [17669, 46, 16, 15, 3, 67, 76], 'HQC-3': [35851, 56, 24, 16, 5, 101, 114], 'HQC-5': [57637, 90, 32, 29, 5, 132, 150] };
  var NAMES = ['HQC-1', 'HQC-3', 'HQC-5'], PARAMS = {};

  function rsGenerator(t1) {                     // g(X) = (X + a)(X + a^2)..(X + a^(2 t1)), hệ số bậc 0 trước
    var g = [1], i, j;
    for (i = 1; i <= 2 * t1; i++) {
      var a = GF_EXP[i % 255], ng = zeros(g.length + 1);
      for (j = 0; j < g.length; j++) { ng[j] ^= gfMul(g[j], a); ng[j + 1] ^= g[j]; }
      g = ng;
    }
    return g;
  }
  function mkParams(name) {
    var s = SETS[name], P = { name: name, n: s[0], n1: s[1], k1: s[2], t1: s[3], mult: s[4], w: s[5], wr: s[6], we: s[6] };
    P.n2 = 16 * P.mult;                          // byte mỗi khối dRM
    P.n1n2 = P.n1 * 128 * P.mult;                // độ dài mã nối (bit), bội của 32
    P.nbytes = (P.n + 7) >> 3; P.vbytes = P.n1n2 >> 3;
    P.nw = (P.n + 31) >> 5; P.tw = P.n1n2 >> 5;
    P.lastMask = (P.n & 31) ? ((1 << (P.n & 31)) - 1) >>> 0 : 0xFFFFFFFF;
    P.maskN = (P.n & 7) ? (1 << (P.n & 7)) - 1 : 0xFF;
    P.threshold = Math.floor(16777216 / P.n) * P.n;  // rejection_threshold_n (Bảng 4)
    P.ekBytes = 32 + P.nbytes; P.ctBytes = P.nbytes + P.vbytes + 16;
    P.rsGen = rsGenerator(P.t1);
    return P;
  }
  for (var ni = 0; ni < NAMES.length; ni++) PARAMS[NAMES[ni]] = mkParams(NAMES[ni]);
  function par(name) {
    var P = PARAMS[name];
    if (!P) throw new Error('HQC: unknown parameter set ' + name);
    return P;
  }

  /* ---------- RM(1,7): ma trận sinh 8 x 16 byte, vị trí i ở byte i>>3, bit 7-(i&7) (§3.5.3) ---------- */
  var RM_G = [];
  (function () {
    for (var r = 0; r < 8; r++) {
      var row = new Uint8Array(16);
      for (var i = 0; i < 128; i++) {
        var bit = r === 0 ? 1 : (i >> (7 - r)) & 1;
        if (bit) row[i >> 3] |= 1 << (7 - (i & 7));
      }
      RM_G.push(row);
    }
  })();

  /* ---------- vector GF(2)^n trên từ 32 bit (little-endian) ---------- */
  function toWords(b, nw) {
    var w = new Uint32Array(nw);
    for (var i = 0; i < b.length; i++) w[i >> 2] |= b[i] << (8 * (i & 3));
    return w;
  }
  function toBytes(w, nb) {
    var b = new Uint8Array(nb);
    for (var i = 0; i < nb; i++) b[i] = (w[i >> 2] >>> (8 * (i & 3))) & 0xFF;
    return b;
  }
  function xorSupport(v, sup, P) {               // v ^= ComputeVectorFromSupport(sup) (dựng bằng OR trước)
    var x = new Uint32Array(P.nw), i;
    for (i = 0; i < sup.length; i++) x[sup[i] >> 5] |= 1 << (sup[i] & 31);
    for (i = 0; i < P.nw; i++) v[i] ^= x[i];
  }

  /* tích thưa x đặc trong F2[X]/(X^n - 1): XOR các bản xoay X^k * v; E = v || v nên rot(v,k) = E[n-k .. 2n-k) */
  function mulSparse(sup, v, P) {
    var n = P.n, nw = P.nw, E = new Uint32Array(2 * nw + 2), acc = new Uint32Array(nw), i, s;
    for (i = 0; i < nw; i++) E[i] = v[i];
    E[nw - 1] &= P.lastMask;
    var hi = (n & 31) ? (v[nw - 1] >>> (n & 31)) : 0;    // bit >= n (chỉ có khi ek / u lạ)
    var wo = n >> 5, bo = n & 31;
    for (i = 0; i < nw; i++) {                   // chép v_lo lần hai tại bit n (đọc từ v, không từ E)
      var x = (i === nw - 1) ? (v[i] & P.lastMask) >>> 0 : v[i];
      E[wo + i] |= x << bo;
      if (bo) E[wo + i + 1] |= x >>> (32 - bo);
    }
    for (s = 0; s < sup.length; s++) {
      var off = n - sup[s], w0 = off >> 5, b0 = off & 31;
      if (b0 === 0) for (i = 0; i < nw; i++) acc[i] ^= E[w0 + i];
      else {
        var rb = 32 - b0;
        for (i = 0; i < nw; i++) acc[i] ^= (E[w0 + i] >>> b0) | (E[w0 + i + 1] << rb);
      }
    }
    if (hi) {                                    // phép xoay số nguyên: rot(v) = rot(v_lo) OR (v_hi << k), k != 0
      for (s = 0; s < sup.length; s++) {
        var k = sup[s];
        if (k === 0) continue;
        for (var b = 0; b < 8; b++) {
          var q = k + b;
          if (((hi >>> b) & 1) && !((E[0] >>> b) & 1) && q < n) acc[q >> 5] ^= 1 << (q & 31);
        }
      }
    }
    acc[nw - 1] &= P.lastMask;                   // bit >= n chỉ rơi vào phần bị Truncate
    return acc;
  }

  /* ---------- lấy mẫu (§3.3) ---------- */
  function sampleVect(ctx, P) {
    var b = ctx.squeeze(P.nbytes);
    b[P.nbytes - 1] &= P.maskN;
    return toWords(b, P.nw);
  }
  function support1(ctx, w, P) {                 // từ chối: >= threshold, rồi trùng; phân bố đều
    var sup = [], b, c, j, dup;
    while (sup.length < w) {
      b = ctx.squeeze(3);
      c = b[0] | (b[1] << 8) | (b[2] << 16);
      if (c >= P.threshold) continue;
      c = c % P.n;
      dup = false;
      for (j = 0; j < sup.length; j++) if (sup[j] === c) dup = true;
      if (!dup) sup.push(c);
    }
    return sup;
  }
  function support2(ctx, w, P) {                 // 4w byte một lần; i + floor(r (n - i) / 2^32); quét ngược thay trùng
    var rnd = ctx.squeeze(4 * w), sup = new Array(w), i, j, r;
    for (i = 0; i < w; i++) {
      r = (rnd[4 * i] | (rnd[4 * i + 1] << 8) | (rnd[4 * i + 2] << 16) | (rnd[4 * i + 3] << 24)) >>> 0;
      sup[i] = i + Math.floor(r * (P.n - i) / 4294967296);
    }
    for (i = w - 1; i >= 0; i--) for (j = i + 1; j < w; j++) if (sup[i] === sup[j]) sup[i] = i;
    return sup;
  }

  /* ---------- Reed-Solomon rút gọn (§3.5.2) ---------- */
  function rsEncode(msg, P) {                    // LFSR; từ mã = parity (n1-k1) || thông điệp
    var g = P.rsGen, nk = P.n1 - P.k1, cw = new Uint8Array(P.n1), i, j, gate;
    for (i = 0; i < P.k1; i++) {
      gate = msg[P.k1 - 1 - i] ^ cw[nk - 1];
      for (j = nk - 1; j > 0; j--) cw[j] = cw[j - 1] ^ gfMul(gate, g[j]);
      cw[0] = gfMul(gate, g[0]);
    }
    cw.set(msg, nk);
    return cw;
  }
  function rsEval(poly, deg, pt) {
    var pp = pt, ev = poly[0];
    for (var i = 1; i <= deg; i++) { ev ^= gfMul(poly[i], pp); pp = gfMul(pp, pt); }
    return ev;
  }
  function rsDecode(r, P) {                      // syndrome -> Berlekamp -> nghiệm -> Forney; không báo lỗi
    var t1 = P.t1, n1 = P.n1, k1 = P.k1, syn = [], i, j, pos, x;
    for (i = 0; i < 2 * t1; i++) syn.push(rsEval(r, n1 - 1, GF_EXP[(i + 1) % 255]));
    var sigma = zeros(t1 + 1), d = 0, sr = zeros(t1 + 1), dsr = 0, rho = -1, drho = 1, dmu = syn[0], mu;
    sigma[0] = 1; sr[0] = 1;
    for (mu = 0; mu < 2 * t1; mu++) {            // dạng bảng của đặc tả, có chặn d <= t1
      if (dmu !== 0) {
        var smu = sigma.slice(), dsmu = d, coef = gfMul(dmu, gfInv(drho)), lim = Math.min(dsr, t1 - (mu - rho));
        for (i = 0; i <= lim; i++) sigma[i + mu - rho] ^= gfMul(coef, sr[i]);
        d = Math.min(t1, Math.max(d, mu - rho + dsr));
        if ((mu - dsmu) > (rho - dsr)) { sr = smu; dsr = dsmu; rho = mu; drho = dmu; }
      }
      if (mu + 1 < 2 * t1) {
        dmu = syn[mu + 1];
        for (i = 1; i <= d; i++) dmu ^= gfMul(sigma[i], syn[mu + 1 - i]);
      }
    }
    var ep = [];                                 // chỉ k1 vị trí thông điệp
    for (i = 0; i < k1; i++) ep.push(rsEval(sigma, t1, gfInv(GF_EXP[(n1 - k1 + i) % 255])) === 0 ? 1 : 0);
    var z = zeros(t1 + 1), so = zeros(t1 + 1);
    z[0] = 1;
    for (i = 0; i < t1; i++) {
      z[i + 1] = syn[i];
      for (j = 0; j < i; j++) z[i + 1] ^= gfMul(sigma[j + 1], syn[i - 1 - j]);
      z[i + 1] ^= sigma[i + 1];
    }
    for (i = 1; i <= t1; i += 2) so[i] = sigma[i];
    var msg = new Uint8Array(k1);
    for (i = 0; i < k1; i++) {
      pos = n1 - k1 + i; x = gfInv(GF_EXP[pos % 255]);
      var num = rsEval(z, t1, x), den = rsEval(so, t1, x);
      msg[i] = r[pos] ^ ((ep[i] && den !== 0) ? gfMul(num, gfInv(den)) : 0);
    }
    return msg;
  }

  /* ---------- Reed-Muller nhân bản (§3.5.3) và mã nối (§3.5.1) ---------- */
  function cEncode(m, P) {
    var rs = rsEncode(m, P), out = new Uint8Array(P.vbytes), i, j, c, o = 0;
    for (i = 0; i < P.n1; i++) {
      var cw = new Uint8Array(16);
      for (j = 0; j < 8; j++) if ((rs[i] >> (7 - j)) & 1) for (c = 0; c < 16; c++) cw[c] ^= RM_G[j][c];
      for (j = 0; j < P.mult; j++) { out.set(cw, o); o += 16; }
    }
    return out;
  }
  function cDecode(wb, P) {
    var rs = new Uint8Array(P.n1), A = new Int32Array(128), B = new Int32Array(128), i, j, k, s, t;
    for (i = 0; i < P.n1; i++) {
      for (j = 0; j < 128; j++) A[j] = 0;
      for (s = 0; s < P.mult; s++) for (j = 0; j < 16; j++) {   // ExpandAndSum
        var byte = wb[i * P.n2 + 16 * s + j];
        for (k = 0; k < 8; k++) A[8 * j + k] += (byte >> (7 - k)) & 1;
      }
      var src = A, dst = B;                      // Hadamard nhanh: 7 tầng a+b / a-b
      for (s = 0; s < 7; s++) {
        for (j = 0; j < 64; j++) { var a = src[2 * j], b = src[2 * j + 1]; dst[j] = a + b; dst[j + 64] = a - b; }
        if (s !== 6) { t = src; src = dst; dst = t; }
      }
      dst[0] -= 64 * P.mult;
      var best = 0, peak = 0;                    // FindPeaks: đỉnh đầu tiên
      for (j = 0; j < 128; j++) { var av = Math.abs(dst[j]); if (av > best) { best = av; peak = j; } }
      if (dst[peak] > 0) peak |= 0x80;
      rs[i] = peak;
    }
    return rsDecode(rs, P);
  }

  /* ---------- HQC-PKE (§3.6) ---------- */
  function pkeKeygen(seedPke, P) {
    var ks = I(seedPke), seedDk = ks.subarray(0, 32), seedEk = ks.subarray(32, 64);
    var ctx = xofPke(seedDk), ysup = support1(ctx, P.w, P), xsup = support1(ctx, P.w, P);   // y TRƯỚC x
    var s = mulSparse(ysup, sampleVect(xofPke(seedEk), P), P);
    xorSupport(s, xsup, P);                      // s = x + h y
    return { ek: cat([seedEk, toBytes(s, P.nbytes)]), dkPke: Uint8Array.from(seedDk) };
  }
  function pkeEncrypt(ek, m, theta, P) {
    var s = toWords(ek.subarray(32), P.nw), h = sampleVect(xofPke(ek.subarray(0, 32)), P), ctx = xofPke(theta);
    var r2s = support2(ctx, P.wr, P), es = support2(ctx, P.we, P), r1s = support2(ctx, P.wr, P);   // r2, e, r1
    var u = mulSparse(r2s, h, P);
    xorSupport(u, r1s, P);                       // u = r1 + h r2
    var t = mulSparse(r2s, s, P);
    xorSupport(t, es, P);                        // s r2 + e, rồi Truncate
    var v = toWords(cEncode(m, P), P.tw), i;
    for (i = 0; i < P.tw; i++) v[i] ^= t[i];
    return { u: toBytes(u, P.nbytes), v: toBytes(v, P.vbytes) };
  }
  function pkeDecrypt(dkPke, ub, vb, P) {
    var ysup = support1(xofPke(dkPke), P.w, P), uy = mulSparse(ysup, toWords(ub, P.nw), P);
    var w = toWords(vb, P.tw), i;
    for (i = 0; i < P.tw; i++) w[i] ^= uy[i];    // v - Truncate(u y)
    return cDecode(toBytes(w, P.vbytes), P);
  }

  /* ---------- HQC-KEM (§3.7) ---------- */
  function need(b, len, what) {
    if (!b || b.length !== len) throw new Error('HQC: ' + what + ' must be ' + len + ' bytes');
  }
  function keygenInternal(name, seedKem) {
    var P = par(name);
    need(seedKem, 32, 'seed_KEM');
    seedKem = Uint8Array.from(seedKem);
    var kp = pkeKeygen(xofKem(seedKem, P).squeeze(32), P);
    return { ek: kp.ek, dk: Uint8Array.from(seedKem) };    // dk = seed_KEM (v5.1.0)
  }
  function encapsInternal(name, ek, m, salt) {
    var P = par(name);
    need(ek, P.ekBytes, 'ek'); need(m, P.k1, 'm'); need(salt, 16, 'salt');
    ek = Uint8Array.from(ek); m = Uint8Array.from(m); salt = Uint8Array.from(salt);
    var kt = G(cat([H(ek), m, salt])), c = pkeEncrypt(ek, m, kt.subarray(32, 64), P);
    return { K: Uint8Array.from(kt.subarray(0, 32)), ct: cat([c.u, c.v, salt]) };
  }
  function decaps(name, dk, ct) {
    var P = par(name);
    need(dk, 32, 'dk'); need(ct, P.ctBytes, 'ct');
    dk = Uint8Array.from(dk); ct = Uint8Array.from(ct);
    var ctx = xofKem(dk, P), kp = pkeKeygen(ctx.squeeze(32), P), sigma = ctx.squeeze(P.k1);
    var u = ct.subarray(0, P.nbytes), v = ct.subarray(P.nbytes, P.nbytes + P.vbytes), salt = ct.subarray(P.nbytes + P.vbytes);
    var m2 = pkeDecrypt(kp.dkPke, u, v, P), hek = H(kp.ek);
    var kt = G(cat([hek, m2, salt])), c2 = pkeEncrypt(kp.ek, m2, kt.subarray(32, 64), P);
    var kbar = J(cat([hek, sigma, ct])), diff = 0, i;
    for (i = 0; i < P.nbytes; i++) diff |= c2.u[i] ^ u[i];   // so sánh không rẽ nhánh
    for (i = 0; i < P.vbytes; i++) diff |= c2.v[i] ^ v[i];
    var mask = ((diff - 1) >> 8) & 0xFF, K = new Uint8Array(32);   // 0xFF khi khớp, 0 khi khác
    for (i = 0; i < 32; i++) K[i] = (kt[i] & mask) ^ (kbar[i] & ~mask & 0xFF);
    return { K: K, rejected: diff !== 0 };
  }

  root.HQC = {
    NAMES: NAMES.slice(),
    sizes: function (name) {
      var P = par(name);
      return { ek: P.ekBytes, dk: 32, ct: P.ctBytes, ss: 32, m: P.k1, salt: 16 };
    },
    keygenInternal: keygenInternal,
    encapsInternal: encapsInternal,
    decaps: decaps,
    /* chỉ để kiểm thử bộ giải mã nối RM/RS: m' = Decrypt(dk_PKE, u, v) (KAT không bao giờ cần RS sửa lỗi) */
    pkeDecrypt: function (name, dk, ct) {
      var P = par(name), kp = pkeKeygen(xofKem(Uint8Array.from(dk), P).squeeze(32), P);
      return pkeDecrypt(kp.dkPke, ct.subarray(0, P.nbytes), ct.subarray(P.nbytes, P.nbytes + P.vbytes), P);
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);
