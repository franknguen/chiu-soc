/* HAETAE (KpqC, mã tham chiếu 1.2.0) — chữ ký số trên siêu cầu hai đỉnh, JavaScript thuần, khớp từng byte với KAT.
   Dùng tầng Keccak của pqc-mlkem.js (PQCHash); bộ lấy mẫu Gaussian bản 1.2.0 (CDT 83 bit + exp bậc 10).
   Original implementation for the ChiU·SoC PQC demo page. */
(function (root) {
  'use strict';
  var H = root.PQCHash;
  if (!H) throw new Error('pqc-mlkem.js phải được nạp trước pqc-haetae.js');

  var N = 256, Q = 64513, DQ = 2 * Q, ZETA = 426, SEEDBYTES = 32, CRHBYTES = 64;
  var LN = 8192, SCALE_BITS = 10, RANS_L = 1 << 23;
  var DQREC = Math.floor(4294967296 / DQ);
  // giới hạn vòng lặp có từ chối: khoá/chữ ký hỏng phải dừng bằng lỗi, không treo trình duyệt
  var MAX_KEYGEN_ATTEMPTS = 1000, MAX_SIGN_ITERATIONS = 1000, MAX_HYPERBALL_TRIES = 64;
  var P2_16 = 65536, P2_20 = 1048576, P2_24 = 16777216, P2_27 = 134217728, P2_28 = 268435456;
  var P2_32 = 4294967296, P2_47 = 140737488355328, P2_48 = 281474976710656;

  /* ---------- bảng hằng: trích bằng chương trình từ đặc tả và mã tham chiếu 1.2.0 ---------- */
  // Bảng 1 của đặc tả: sec, k, l, tau, gamma, d, M, B, B', B'', alpha_h; Bảng 2: cut_h, offset_h, |S_h|, cut_z1, |S_z1|, base_h, base_z1
  var SPEC_T1 = {
    2: { sec: 120, k: 2, l: 4, tau: 58, gamma: 48.858, d: 1, M: 6.0, B: 9846.02, B1: 9838.98, B2: 12777.52, alpha_h: 512 },
    3: { sec: 180, k: 3, l: 6, tau: 80, gamma: 57.707, d: 1, M: 5.0, B: 18314.98, B1: 18307.7, B2: 21906.65, alpha_h: 512 },
    5: { sec: 260, k: 4, l: 7, tau: 128, gamma: 55.13, d: 0, M: 6.0, B: 22343.66, B1: 22334.95, B2: 24441.49, alpha_h: 256 }
  };
  var SPEC_T2 = { 2: [6, 239, 13, 6, 13, 7, 132], 3: [8, 235, 17, 8, 17, 127, 376], 5: [16, 471, 33, 9, 19, 358, 501] };
  var SIG_BYTES = { 2: 1474, 3: 2349, 5: 2948 };   // HAETAE_CRYPTO_BYTES
  // CDT 83 bit của bộ lấy mẫu 1.2.0: 19 bit cao (mục thiếu = 0x7FFFF) và 64 bit thấp (hex)
  var CDT83_HI = [
    0x063a5, 0x0c718, 0x129f6, 0x18bdf, 0x1ec73, 0x24b59, 0x2a83a, 0x302c6, 0x35ab6, 0x3afc7, 0x401be, 0x4506a,
    0x49ba1, 0x4e343, 0x52736, 0x5676c, 0x5a3dc, 0x5dc86, 0x61172, 0x642ad, 0x6704c, 0x69a68, 0x6c120, 0x6e496,
    0x704ef, 0x72255, 0x73cf1, 0x754f0, 0x76a7c, 0x77dc4, 0x78ef2, 0x79e32, 0x7abaf, 0x7b78f, 0x7c1fb, 0x7cb17,
    0x7d304, 0x7d9e4, 0x7dfd4, 0x7e4f0, 0x7e950, 0x7ed0d, 0x7f03b, 0x7f2ec, 0x7f531, 0x7f71a, 0x7f8b3, 0x7fa08,
    0x7fb24, 0x7fc0e, 0x7fccf, 0x7fd6e, 0x7fdf0, 0x7fe5a, 0x7feaf, 0x7fef5, 0x7ff2c, 0x7ff59, 0x7ff7d, 0x7ff99,
    0x7ffb0, 0x7ffc2, 0x7ffd0, 0x7ffdb, 0x7ffe3, 0x7ffea, 0x7ffef, 0x7fff3, 0x7fff6, 0x7fff8, 0x7fffa, 0x7fffb,
    0x7fffd, 0x7fffd, 0x7fffe, 0x7fffe
  ];
  var CDT83_LO = [
    '0aa572bc88db1e28', '4f3820e69064b2ee', 'd68dc44dd1418704', '6587a04d9b97b1dd', '9b843ce0a65d0050', '02b62cb869003e7d',
    '0d44f194f8bf43c6', 'faa0c7acb211b4db', 'a11387f7f524be80', '18526ca6f2ceb77f', '42a01a906b7dad17', '32e5337a1966b9a7',
    '6f00f7ac9735f58a', '0e6c48f40642ba60', 'b6192fa1afb5e4ec', '7339dba8ffc2fcf5', '7746cbe1ac90c9eb', 'b83004341d78466f',
    '781dcca572bb3d8a', 'b880376cc82a5384', '9c68a5c477dfecb9', 'be45ceb02a25fef3', '7d1a8ccd208dbaa1', '452c002b9085e7db',
    'd7ef361c5551378d', '96b4ff49d9e5a8bb', 'd337c94ede732d83', '28c75b8d3fe83c38', 'e05d7bd130fe20e0', '6170e60b76d85108',
    'b0e59892414901ff', 'ff05cf70b911f3de', '4501460fdfd508c9', 'f20b1303a2a54906', 'a7d3badbeb04b20c', '05ce666b741b666d',
    '826e689fded20430', '5155d1354fcf6ff6', '55469226a1d318f6', '1c8d3820cfa9cabc', 'e68d83bbf700fc40', 'b1152d8944042803',
    '4c1e741aabe53700', '72b94c56e0f9a967', 'e7e5a80a79e4539c', '9641c5d11feb4d12', 'b18b71598b73dde0', 'd9112fb5a7904d7e',
    '3a4f57cbefabc820', 'b314025fd5022976', 'f2a2b228aab1981b', '996ce1e60378cd98', '570ec64b38e3ca90', '0657269615dcd7c6',
    'c7360038bdc85312', '167fa02a57a8ae1a', 'e380fab2ea9b2bef', 'a36e6abd6509b5a2', '62bfcf1d6ba81c37', 'd4946e8bf96caa93',
    '603e6262ea8cda2d', '2d18c8b333ae9203', '2ccdedb5a7718d61', '24333ecab8497c0a', 'b2e06eb33bf2b7d9', '59a5f6c550dfe7e2',
    '800548f3927f906e', '78cac146b573bc40', '85e6dadec4b6aff1', 'dba17dfa17def8ec', 'a33f84d06ce20a93', 'fd2fe967c5186746',
    '02d37ecd7e9b180f', 'c7efafa8bd33f0bb', '5bda826341e791cc', 'ca6c1c6ce045599f', '1cc02c0faa9a526e', '59d002901a4a4e52',
    '86ecbd139ce07540', 'a81f9f15ffb47f4c', 'c075b17481687af0', 'd23ad13e68301c65', 'df27955fae1c84cb', 'e884cdb07368c266',
    'ef46d4f897fc83f6', 'f4227e46663ec049', 'f79d091c1b5aff07', 'fa183c533c3890a6', 'fbdb8a602066b0f2', 'fd1af06df3db86b7',
    'fdfc1a818587e2aa', 'fe9a37a348ac2a93', 'ff08d0797970dbfe', 'ff55df73fd7a00bc', 'ff8b5aa573bca5ce', 'ffb053c109f51681',
    'ffc9c9bd39a036ec', 'ffdb40bd4ee1f846', 'ffe72fa859b20a4a', 'ffef4edda93d266d', 'fff4d07a9fb0d4e0', 'fff88868ef31b1cc',
    'fffb08c16a3f5f0c', 'fffcb5d30be5cabf', 'fffdd43465d95fe6', 'fffe929a538ad2fa', 'ffff10b1c2119732', 'ffff63df8795a2c9',
    'ffff9a87a0a9f2af', 'ffffbe4df6f0f4a9', 'ffffd5a10f204910', 'ffffe4c6f1668b32', 'ffffee939680bfaf', 'fffff4e4216290db',
    'fffff8f1c044613e', 'fffffb892dc2b174', 'fffffd2fb4188608', 'fffffe3bc0a56eba', 'fffffee523b218c6', 'ffffff4fc31097e3',
    'ffffff929d76dbeb', 'ffffffbc5e7c0350', 'ffffffd6586c6684', 'ffffffe6716865f7', 'fffffff0613c76e2', 'fffffff67d62ab64',
    'fffffffa3b6664c0', 'fffffffc83e13d66', 'fffffffde713ef71', 'fffffffebe18936f', 'ffffffff3fbfc997', 'ffffffff8d9fa29a',
    'ffffffffbc372590', 'ffffffffd7fb7dfd', 'ffffffffe87747f9', 'fffffffff2368b89', 'fffffffff7f44d88', 'fffffffffb52a49b',
    'fffffffffd4a9ffb', 'fffffffffe700579', 'ffffffffff1a287f', 'ffffffffff7c6f06', 'ffffffffffb4fa99', 'ffffffffffd56300',
    'ffffffffffe7e364', 'fffffffffff268d7', 'fffffffffff85e8e', 'fffffffffffbbb6f', 'fffffffffffd9f49', 'fffffffffffeae2c',
    'ffffffffffff453d', 'ffffffffffff9928', 'ffffffffffffc797', 'ffffffffffffe12f', 'ffffffffffffef3c', 'fffffffffffff6eb',
    'fffffffffffffb1b', 'fffffffffffffd60', 'fffffffffffffe9a', 'ffffffffffffff43', 'ffffffffffffff9e', 'ffffffffffffffce',
    'ffffffffffffffe7', 'fffffffffffffff4', 'fffffffffffffffb', 'fffffffffffffffe'
  ];
  // hệ số xấp xỉ exp bậc 10 (2^48 exp(-x / 2^48))
  var EXP_V120 = [
    55868746, -743564434, 6953427278, -55833338892,
    390932311155, -2345623661771, 11728123872951, -46912496106200,
    140737488354861, -281474976710650, 281474976710657
  ];
  // tần suất rANS trên 2^10: [h, HighBits(z1)]
  var RANS_FREQ = {
    2: [[382, 246, 65, 7, 1, 1, 1, 1, 1, 1, 7, 65, 246],
        [1, 1, 1, 5, 58, 246, 398, 247, 59, 5, 1, 1, 1]],
    3: [[266, 213, 113, 40, 9, 1, 1, 1, 1, 1, 1, 1, 1, 9, 40, 113, 213],
        [1, 1, 1, 1, 8, 37, 112, 216, 269, 216, 112, 38, 8, 1, 1, 1, 1]],
    5: [[122, 117, 102, 81, 59, 39, 23, 13, 6, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 6, 13, 24, 39, 59, 81, 102, 118],
        [1, 1, 1, 1, 2, 13, 48, 118, 204, 245, 204, 118, 48, 14, 2, 1, 1, 1, 1]]
  };

  /* ---------- bộ tham số (kích thước tính từ cách đóng gói) ---------- */
  function bitLength(x) { var n = 0; while (x > 0) { n++; x = Math.floor(x / 2); } return n; }
  function makeParams(mode) {
    var t = SPEC_T1[mode], u = SPEC_T2[mode], p = { mode: mode, name: 'HAETAE-' + mode };
    p.sec = t.sec; p.k = t.k; p.l = t.l; p.m = t.l - 1; p.tau = t.tau; p.gamma = t.gamma; p.d = t.d;
    p.B0 = t.B; p.B1 = t.B1; p.B2 = t.B2; p.M = t.M; p.alphaH = t.alpha_h;
    p.logAlphaH = bitLength(t.alpha_h) - 1;
    p.hbM = Math.floor((DQ - 2) / t.alpha_h);
    p.sqnm = Math.sqrt(N * (p.k + p.l));
    p.B0SQ = Math.trunc(p.B0 * p.B0); p.B1SQ = Math.trunc(p.B1 * p.B1); p.B2SQ = Math.trunc(p.B2 * p.B2);
    p.gammaThr = p.gamma * p.gamma * N;                         // ngưỡng N(s), số thực như C
    p.radiusConst = Math.trunc(p.B0 * LN + p.sqnm / 2) * 32768;  // (uint64)(B LN + sqrt(nm)/2) << 15
    p.cutH = u[0]; p.offsetH = u[1]; p.mH = u[2]; p.cutZ1 = u[3]; p.mHbZ1 = u[4]; p.baseH = u[5]; p.baseHbZ1 = u[6];
    p.polyqBits = p.d === 1 ? 15 : 16; p.polyqBytes = N * p.polyqBits / 8;
    p.poly2etaBytes = p.d === 1 ? 96 : 64;
    p.highbitsBytes = N * 9 / 8;
    p.pkBytes = SEEDBYTES + p.k * p.polyqBytes;
    p.skBytes = p.pkBytes + p.m * 64 + p.k * p.poly2etaBytes + SEEDBYTES;
    p.sigBytes = SIG_BYTES[mode];
    p.nonceA = p.k << 8;
    return p;
  }

  function cat(arrs) { var n = 0, i; for (i = 0; i < arrs.length; i++) n += arrs[i].length; var o = new Uint8Array(n), q = 0; for (i = 0; i < arrs.length; i++) { o.set(arrs[i], q); q += arrs[i].length; } return o; }
  function nb(n) { return new Uint8Array([n & 255, n >> 8]); }   // nonce LE16
  function modq(f) { var a = new Int32Array(N); for (var i = 0; i < N; i++) { var v = f[i] % Q; a[i] = v < 0 ? v + Q : v; } return a; }

  /* ---------- NTT âm-vòng mod q (thuần, ra chính tắc [0, q)) ---------- */
  function powmod(b, e, m) { var r = 1; b %= m; while (e > 0) { if (e & 1) r = (r * b) % m; b = (b * b) % m; e = Math.floor(e / 2); } return r; }
  function brv8(i) { var r = 0; for (var j = 0; j < 8; j++) r = (r << 1) | ((i >> j) & 1); return r; }
  var BRV8 = new Int32Array(256), ZETAS = new Int32Array(256), NINV = powmod(N, Q - 2, Q);
  (function () { for (var i = 0; i < 256; i++) { BRV8[i] = brv8(i); ZETAS[i] = powmod(ZETA, BRV8[i], Q); } })();

  function ntt(f) {                              // f chính tắc
    var a = Int32Array.from(f), k = 0, len, start, j, z, t;
    for (len = 128; len >= 1; len >>= 1) {
      for (start = 0; start < N; start += 2 * len) {
        z = ZETAS[++k];
        for (j = start; j < start + len; j++) {
          t = (z * a[j + len]) % Q;
          a[j + len] = (a[j] - t + Q) % Q;
          a[j] = (a[j] + t) % Q;
        }
      }
    }
    return a;
  }
  function intt(f) {
    var a = Int32Array.from(f), k = 256, len, start, j, z, t;
    for (len = 1; len < N; len <<= 1) {
      for (start = 0; start < N; start += 2 * len) {
        z = Q - ZETAS[--k];
        for (j = start; j < start + len; j++) {
          t = a[j];
          a[j] = (t + a[j + len]) % Q;
          a[j + len] = ((t - a[j + len] + Q) * z) % Q;
        }
      }
    }
    for (j = 0; j < N; j++) a[j] = (a[j] * NINV) % Q;
    return a;
  }
  function pmul(a, b) { var c = new Int32Array(N); for (var i = 0; i < N; i++) c[i] = (a[i] * b[i]) % Q; return c; }
  function rowDot(row, x) {                      // sum_j row[j] o x[j] (miền NTT)
    var acc = new Float64Array(N), j, t, c = new Int32Array(N);
    for (j = 0; j < row.length; j++) for (t = 0; t < N; t++) acc[t] += row[j][t] * x[j][t];
    for (t = 0; t < N; t++) c[t] = acc[t] % Q;
    return c;
  }
  function centered(x) { return x > (Q >> 1) ? x - Q : x; }
  function negMulSmall(ch, sh) { var r = intt(pmul(ch, sh)); for (var i = 0; i < N; i++) r[i] = centered(r[i]); return r; }

  /* ---------- rút gọn mod 2q ---------- */
  function freeze2q(a) {
    var t = a - Math.floor(a * DQREC / P2_32) * DQ;
    if (t < 0) t += 2 * DQ;
    if (t >= DQ) t -= DQ;
    return t;
  }
  function reduce32_2q(a) { var t = freeze2q(a); return t >= Q ? t - DQ : t; }

  /* ---------- luồng SHAKE đọc dần ---------- */
  function Xof(sponge, first, chunk) { this.s = sponge; this.c = chunk; this.b = sponge.squeeze(first); this.p = 0; }
  Xof.prototype.byte = function () {
    if (this.p === this.b.length) { this.b = this.s.squeeze(this.c); this.p = 0; }
    return this.b[this.p++];
  };

  /* ---------- mở rộng ma trận và bí mật ---------- */
  function polyUniform(rho, nonce) {            // SHAKE128(rho || nonce), mẫu 16 bit LE < q
    var x = new Xof(H.shake128xof(cat([rho, nb(nonce)])), 4 * 168, 168), a = new Int32Array(N), n = 0, t;
    while (n < N) { t = x.byte(); t |= x.byte() << 8; if (t < Q) a[n++] = t; }
    return a;
  }
  var TRIT = [0, 1, -1];
  function polyUniformEta(seed, nonce) {        // SHAKE256(seed || nonce): byte < 243 -> 5 trit
    var x = new Xof(H.shake256xof(cat([seed, nb(nonce)])), 136, 136), a = new Int32Array(N), n = 0, t, i;
    while (n < N) {
      t = x.byte();
      if (t < 243) for (i = 0; i < 5 && n < N; i++) { a[n++] = TRIT[t % 3]; t = (t / 3) | 0; }
    }
    return a;
  }
  function expandA(p, rho) {
    var A = [], i, j;
    for (i = 0; i < p.k; i++) { A.push([]); for (j = 0; j < p.m; j++) A[i].push(polyUniform(rho, (i << 8) + j)); }
    return A;
  }
  function expandVecA(p, rho) { var a = [], i; for (i = 0; i < p.k; i++) a.push(polyUniform(rho, p.nonceA + p.m + i)); return a; }
  function expandS(p, sigma, counter) {
    var s1 = [], s2 = [], i;
    for (i = 0; i < p.m; i++) s1.push(polyUniformEta(sigma, counter + i));
    for (i = 0; i < p.k; i++) s2.push(polyUniformEta(sigma, counter + p.m + i));
    return [s1, s2];
  }

  /* ---------- thử thách c ---------- */
  function popcount8(x) { var n = 0; while (x) { n += x & 1; x >>= 1; } return n; }
  function challenge(p, buf, mu) {
    var data = cat([buf, mu.subarray(0, SEEDBYTES)]), c = new Int32Array(N), i, b;
    if (p.mode !== 5) {                          // tau vị trí 1
      var x = new Xof(H.shake256xof(data), 136, 136);
      for (i = N - p.tau; i < N; i++) { do { b = x.byte(); } while (b > i); c[i] = c[b]; c[b] = 1; }
      return c;
    }
    var raw = H.shake256(data, 32), hw = 0, flip;
    for (i = 0; i < 32; i++) hw += popcount8(raw[i]);
    flip = (hw > 128 || (hw === 128 && (raw[0] & 1) === 1)) ? 0xFF : 0;   // HAETAE-5: lật nếu trọng số > n/2
    for (i = 0; i < N; i++) c[i] = ((raw[i >> 3] ^ flip) >> (i & 7)) & 1;
    return c;
  }

  /* ---------- phân tách bit ---------- */
  function decomposeHint(p, r) { var hb = (r + (p.alphaH >> 1)) >> p.logAlphaH; return hb >= p.hbM ? hb - p.hbM : hb; }

  /* ---------- FFT dấu phẩy tĩnh 16.16 và từ chối khoá N(s) ---------- */
  function roundHalfEven(x) { var f = Math.floor(x), d = x - f; return d > 0.5 ? f + 1 : d < 0.5 ? f : (f % 2 === 0 ? f : f + 1); }
  var FFT_RE = new Int32Array(256), FFT_IM = new Int32Array(256);
  (function () {
    for (var j = 0; j < 256; j++) {
      FFT_RE[j] = roundHalfEven(65536 * Math.cos(Math.PI * j / 256));
      FFT_IM[j] = roundHalfEven(-65536 * Math.sin(Math.PI * j / 256));
    }
  })();
  function mulrnd16(x, y) { return Math.floor((x * y + 32768) / P2_16) | 0; }
  function fftFixed(poly, re, im) {              // nhân trước e^{-i pi j/256}, 8 tầng DIT, làm tròn 16 bit
    var i, r, m, md2, sh, n0, k, e, o, wr, wi, xr, xi, tr, ti, ur, ui;
    for (i = 0; i < N; i++) { re[BRV8[i]] = poly[i] * FFT_RE[i]; im[BRV8[i]] = poly[i] * FFT_IM[i]; }
    for (r = 1; r <= 8; r++) {
      m = 1 << r; md2 = m >> 1; sh = 9 - r;
      for (n0 = 0; n0 < N; n0 += m) {
        for (k = 0; k < md2; k++) {
          e = n0 + k; o = e + md2;
          wr = FFT_RE[k << sh]; wi = FFT_IM[k << sh];
          xr = re[o]; xi = im[o];
          tr = mulrnd16(wr, xr) - mulrnd16(wi, xi);
          ti = mulrnd16(wr, xi) + mulrnd16(wi, xr);
          ur = re[e]; ui = im[e];
          re[e] = ur + tr; im[e] = ui + ti;
          re[o] = ur - tr; im[o] = ui - ti;
        }
      }
    }
  }
  function skSingularValue(p, polys) {
    var sums = new Int32Array(N), re = new Float64Array(N), im = new Float64Array(N), i, j;
    for (i = 0; i < polys.length; i++) {
      fftFixed(polys[i], re, im);
      for (j = 0; j < N; j++) sums[j] = (sums[j] + mulrnd16(re[j], re[j]) + mulrnd16(im[j], im[j])) | 0;
    }
    return nsumFromSums(p, sums);
  }
  function nsumFromSums(p, sums) {              // giữ m + 1 giá trị lớn nhất (mạng minmax), trọng số tau / n mod tau
    var m1 = Math.floor(N / p.tau) + 1, best = Array.prototype.slice.call(sums, 0, m1), i, j, v, w, mn, res = 0;
    for (i = m1; i < N; i++) {
      v = sums[i];
      for (j = 0; j < m1; j++) if (best[j] < v) { w = best[j]; best[j] = v; v = w; }
    }
    mn = Math.min.apply(null, best);
    for (j = 0; j < m1; j++) res = (res + Math.floor((best[j] + 0x10200) / 1024) * (best[j] > mn ? p.tau : N % p.tau)) | 0;
    return Math.floor((res + 32) / 64);
  }

  /* ---------- fp96_76: hai limb 48 bit, giá trị (l1 2^48 + l0) / 2^76 — BigInt cho bước Newton ---------- */
  var M64 = 0xFFFFFFFFFFFFFFFFn, M48 = 0xFFFFFFFFFFFFn;
  function mul48(b, a) { var p = a * b, lo = p & M64, hi = (p >> 64n) & M64; return [lo & M48, ((hi << 16n) & M64) ^ (lo >> 48n)]; }
  function renorm(l0, l1) { return [l0 & M48, (l1 + (l0 >> 48n)) & M64]; }
  function fpMul(x, y) {
    var a = mul48(x[0], y[0]), l0 = (a[1] + (((a[0] >> 47n) + 1n) >> 1n)) & M64, l1, t, p;
    t = mul48(x[0], y[1]); l0 = (l0 + t[0]) & M64; l1 = t[1];
    t = mul48(x[1], y[0]); l0 = (l0 + t[0]) & M64; l1 = (l1 + t[1]) & M64;
    l0 = ((l0 + (1n << 27n)) & M64) >> 28n;
    l0 = (l0 + ((l1 << 20n) & M48)) & M64;
    l1 >>= 28n;
    p = x[1] * y[1];
    l0 = (l0 + (((p & M64) << 20n) & M48)) & M64;
    l1 = (l1 + ((p & M64) >> 28n) + ((((p >> 64n) & M64) << 36n) & M64)) & M64;
    return renorm(l0, l1);
  }
  function fpSquare(x) {
    var p = x[0] * x[0], lo = p & M64, hi = (p >> 64n) & M64, l0, l1, t;
    l0 = (((lo & M48) >> 48n) + (((hi << 16n) & M64) ^ (lo >> 48n))) & M64;
    t = mul48(x[0], x[1]);
    l0 = (l0 + ((t[0] << 1n) & M64)) & M64;
    l1 = (t[1] << 1n) & M64;
    l0 >>= 28n;                                  // không làm tròn (như mã tham chiếu)
    l0 = (l0 + ((l1 << 20n) & M48)) & M64;
    l1 >>= 28n;
    p = x[1] * x[1];
    l0 = (l0 + (((p & M64) << 20n) & M48)) & M64;
    l1 = (l1 + ((p & M64) >> 28n) + ((((p >> 64n) & M64) << 36n) & M64)) & M64;
    return renorm(l0, l1);
  }
  function fpMulHigh(x, y) {
    var a = mul48(x[0], y), t = mul48(x[1], y), l0, l1 = (a[1] + t[0]) & M64;
    l0 = ((a[0] + (1n << 27n)) & M64) >> 28n;
    l0 = (l0 + ((l1 << 20n) & M48)) & M64;
    l1 >>= 28n;
    l1 = (l1 + ((t[1] << 20n) & M64)) & M64;
    return renorm(l0, l1);
  }
  function fpCopyCneg(x, sign) {
    var msk = sign ? M64 : 0n;
    return renorm((((msk & M48) ^ x[0]) + BigInt(sign)) & M64, (x[1] ^ msk) & M64);
  }
  function fpSub(x, y) { var z = fpCopyCneg(y, 1); return [(x[0] + z[0]) & M64, (x[1] + z[1]) & M64]; }
  function fpSubFromThreeHalves(x) { var z = fpCopyCneg(x, 1); return renorm(z[0], (z[1] + (3n << 27n)) & M64); }
  function fpUnsignedSignedMul(xy, y) { var s = Number((y[1] >> 63n) & 1n); return fpCopyCneg(fpMul(fpCopyCneg(y, s), xy), s); }

  function isqrt(n) {                            // floor(sqrt(n)), BigInt
    if (n < 2n) return n;
    var x = 1n << BigInt((n.toString(2).length >> 1) + 1), y;
    for (;;) { y = (x + n / x) >> 1n; if (y >= x) return x; x = y; }
  }
  var BIG = {};                                  // hằng BigInt theo mode (để PARAMS vẫn JSON hoá được)
  function bigConsts(p) {
    // Newton: s = 1/sqrt(n(k+l) + 2) -> (s^3, 1.5 s) làm tròn về 76 bit phần lẻ; ngưỡng B^2 LN^2, B'^2 LN^2
    var n0 = BigInt(N * (p.k + p.l) + 2), th = 3n << 75n, one = 1n << 76n;
    function fp(numer2, denom) { var v = (isqrt(numer2 * 4n / denom) + 1n) / 2n; return [v & M48, v >> 48n]; }
    BIG[p.mode] = { newton: [fp(one * one, n0 * n0 * n0), fp(th * th, n0)],
      lim0: BigInt(p.B0SQ) * BigInt(LN * LN), lim1: BigInt(p.B1SQ) * BigInt(LN * LN) };
  }
  function newtonInvsqrt(p, xhalf) {             // y0 = 1.5 s - xhalf s^3, rồi 6 vòng y = y (1.5 - xhalf y^2)
    var nw = BIG[p.mode].newton, inv = fpSub(nw[1], fpMul(xhalf, nw[0])), i;
    for (i = 0; i < 6; i++) inv = fpUnsignedSignedMul(inv, fpSubFromThreeHalves(fpMul(xhalf, fpSquare(inv))));
    return inv;
  }

  /* ---------- cùng phép tính bằng Number (đường nóng): tích 48 x 48 bit tách limb 24 bit ---------- */
  var mlo = 0, mhi = 0;
  function mul48n(a, b) {                        // a, b < 2^48: mlo = ab mod 2^48, mhi = floor(ab / 2^48)
    var ah = Math.floor(a / P2_24), al = a - ah * P2_24, bh = Math.floor(b / P2_24), bl = b - bh * P2_24;
    var mid = ah * bl + al * bh, midh = Math.floor(mid / P2_24), s = al * bl + (mid - midh * P2_24) * P2_24;
    var c = s >= P2_48 ? 1 : 0;
    mlo = s - c * P2_48; mhi = ah * bh + midh + c;
  }
  function mulRnd13(rhi, rlo, y0, y1, sign) {    // fixpoint_mul_rnd13: (r << 16 limb) * scale, làm tròn về 13 bit
    var l0, l1, t;
    mul48n(rlo * P2_16, y0); l0 = mhi + (mlo >= P2_47 ? 1 : 0);
    mul48n(rlo * P2_16, y1); l0 += mlo; l1 = mhi;
    mul48n(rhi, y0); l0 += mlo; l1 += mhi;
    l0 = Math.floor((l0 + P2_27) / P2_28);
    t = l1 % P2_28; l0 += t * P2_20; l1 = (l1 - t) / P2_28;
    mul48n(rhi, y1); t = mlo % P2_28; l0 += t * P2_20; l1 += mhi * P2_20 + (mlo - t) / P2_28;
    l1 += Math.floor(l0 / P2_48);
    t = Math.floor((l1 + 16384) / 32768);
    return (sign ? -t : t) | 0;
  }
  function mulRnd13Big(rhi, rlo, scale, sign) {  // dự phòng khi scale ngoài miền của đường Number
    var t = fpMul([BigInt(rlo) << 16n, BigInt(rhi)], scale), res = ((t[1] + (1n << 14n)) & M64) >> 15n;
    return Number(BigInt.asIntN(32, sign ? -res : res));
  }

  /* ---------- bộ lấy mẫu Gaussian sigma = 2^76 (bản 1.2.0) ---------- */
  var CDT_LEN = CDT83_LO.length, CDT_H = new Int32Array(CDT_LEN), CDT_LH = new Float64Array(CDT_LEN), CDT_LL = new Float64Array(CDT_LEN);
  (function () {
    for (var i = 0; i < CDT_LEN; i++) {
      CDT_H[i] = i < CDT83_HI.length ? CDT83_HI[i] : 0x7FFFF;
      CDT_LH[i] = parseInt(CDT83_LO[i].slice(0, 8), 16); CDT_LL[i] = parseInt(CDT83_LO[i].slice(8), 16);
    }
  })();
  var RB = 26, FIRST_BLOCKS = Math.ceil(RB * N / 136);   // 72 + 83 + 48 bit mỗi ứng viên; 49 khối SHAKE256 đầu
  var CB = new Uint8Array(RB), cand = { rhi: 0, rlo: 0, sq0: 0, sq1: 0, ok: 0, x: 0 };
  function approxExp(xi) {                       // 2^48 exp(-xi / 2^48), Horner bậc 10, mỗi bước làm tròn LÊN
    var r = EXP_V120[0], xh = Math.floor(xi / P2_24), xl = xi - xh * P2_24, rh, rl, low, lowh, M, Mq, k;
    for (k = 1; k < EXP_V120.length; k++) {
      rh = Math.floor(r / P2_24); rl = r - rh * P2_24;
      low = rl * xl; lowh = Math.floor(low / P2_24);
      M = rh * xl + rl * xh + lowh; Mq = Math.floor(M / P2_24);
      r = rh * xh + Mq + ((M - Mq * P2_24 !== 0 || low - lowh * P2_24 !== 0) ? 1 : 0) + EXP_V120[k];
    }
    return r;
  }
  function candidate(b) {                        // một ứng viên 26 byte -> cand
    var vll = (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
    var vlh = (b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)) >>> 0;
    var vh = (b[8] | (b[9] << 8) | (b[10] << 16)) & 0x7FFFF, lo = 0, hi = CDT_LEN, mid, x;
    while (lo < hi) {                            // x = số mục CDT < rnd (83 bit)
      mid = (lo + hi) >> 1;
      if (CDT_H[mid] < vh || (CDT_H[mid] === vh && (CDT_LH[mid] < vlh || (CDT_LH[mid] === vlh && CDT_LL[mid] < vll)))) lo = mid + 1;
      else hi = mid;
    }
    x = lo;
    var rej = b[11] + b[12] * 256 + b[13] * 65536 + b[14] * P2_24 + b[15] * P2_32 + b[16] * 1099511627776;
    var y0 = b[17] + b[18] * 256 + b[19] * 65536 + b[20] * P2_24 + b[21] * P2_32 + b[22] * 1099511627776;
    var y1 = b[23] + b[24] * 256 + b[25] * 65536 + x * P2_24;
    var rlo = Math.floor((Math.floor(y0 / 32768) + 1) / 2), rhi = y1;
    if (rlo === P2_32) { rlo = 0; rhi += 1; }
    // sqr = fp_square((y0, y1))
    var l0, l1, t;
    mul48n(y0, y0); l0 = mhi;
    mul48n(y0, y1); l0 += 2 * mlo; l1 = 2 * mhi;
    l0 = Math.floor(l0 / P2_28);
    t = l1 % P2_28; l0 += t * P2_20; l1 = (l1 - t) / P2_28;
    mul48n(y1, y1); t = mlo % P2_28; l0 += t * P2_20; l1 += mhi * P2_20 + (mlo - t) / P2_28;
    t = Math.floor(l0 / P2_48); l0 -= t * P2_48; l1 += t;
    // exp_in = (y^2 - (x/16)^2) 2^47, rồi phép thử từ chối
    var ei = (l1 - x * x * P2_20) * P2_20 + Math.floor(l0 / P2_28);
    ei = Math.floor((ei + 1) / 2);
    var e = approxExp(ei), rb = rej % 2;
    cand.rhi = rhi; cand.rlo = rlo; cand.sq0 = l0; cand.sq1 = l1; cand.x = x;
    cand.ok = ((rej - rb) - e < 0 && (rlo !== 0 || rhi !== 0 || rb === 1)) ? 1 : 0;
  }
  function sampleGaussPoly(seed, nonce, length, sq, outHi, outLo) {
    // SHAKE256(seed || nonce): length/8 byte dấu, rồi ứng viên đến khi nhận đủ length; mẫu thứ 257 chỉ vào tổng bình phương
    var x = new Xof(H.shake256xof(cat([seed, nb(nonce)])), FIRST_BLOCKS * 136, 136), signs = new Uint8Array(length >> 3), i, acc = 0;
    for (i = 0; i < signs.length; i++) signs[i] = x.byte();
    while (acc < length) {
      for (i = 0; i < RB; i++) CB[i] = x.byte();
      candidate(CB);
      if (cand.ok) {
        if (acc < N) { outHi[acc] = cand.rhi; outLo[acc] = cand.rlo; }
        acc++;
        sq[0] += cand.sq0; if (sq[0] >= P2_48) { sq[0] -= P2_48; sq[1] += 1; }
        sq[1] += cand.sq1;
      }
    }
    return signs;
  }
  function sqNorm(polys, sub) {                  // tổng bình phương chính xác (có thể > 2^53) -> BigInt; sub: ||2z - y||^2
    var hi = 0, lo = 0, i, j, v, a, ah, al, c, P = polys.length;
    for (i = 0; i < P; i++) for (j = 0; j < N; j++) {
      v = sub ? 2 * polys[i][j] - sub[i][j] : polys[i][j];
      a = v < 0 ? -v : v; ah = Math.floor(a / P2_16); al = a - ah * P2_16;
      hi += ah * ah; lo += ah * al * 131072 + al * al;
      c = Math.floor(lo / P2_32); hi += c; lo -= c * P2_32;
    }
    return BigInt(hi) * 4294967296n + BigInt(lo);
  }
  function sampleHyperball(p, seed, nonce) {
    // (y1, y2) đều trên siêu cầu rời rạc bán kính B (13 bit phần lẻ); C không tăng nonce sau khi rút byte b
    var ni = nonce, tries = 0, T = p.l + p.k, i, j, ys, signs, his, los, sq, l0, l1, scale, y0n, y1n, big;
    for (;;) {
      if (++tries > MAX_HYPERBALL_TRIES) throw new Error('siêu cầu: quá ' + MAX_HYPERBALL_TRIES + ' lần lấy');
      sq = [0, 0]; signs = []; his = []; los = [];
      for (i = 0; i < T; i++) {
        his.push(new Float64Array(N)); los.push(new Float64Array(N));
        signs.push(sampleGaussPoly(seed, ni, i < 2 ? N + 1 : N, sq, his[i], los[i]));
        ni++;
      }
      l0 = Math.floor((sq[0] + 1) / 2) + (sq[1] % 2) * P2_47;          // xhalf = sqsum / 2
      l1 = Math.floor(sq[1] / 2) + Math.floor(l0 / P2_48);
      l0 %= P2_48;
      scale = fpMulHigh(newtonInvsqrt(p, [BigInt(l0), BigInt(l1)]), BigInt(p.radiusConst));
      big = scale[1] >= (1n << 47n);
      y0n = Number(scale[0]); y1n = big ? 0 : Number(scale[1]);
      ys = [];
      for (i = 0; i < T; i++) {
        var y = new Int32Array(N), sg = signs[i];
        for (j = 0; j < N; j++) {
          var s = (sg[j >> 3] >> (j & 7)) & 1;
          y[j] = big ? mulRnd13Big(his[i][j], los[i][j], scale, s) : mulRnd13(his[i][j], los[i][j], y0n, y1n, s);
        }
        ys.push(y);
      }
      if (sqNorm(ys) <= BIG[p.mode].lim0) break;
    }
    return { y1: ys.slice(0, p.l), y2: ys.slice(p.l), b: H.shake256(cat([seed, nb(ni)]), 1)[0], nonce: ni };
  }
  function fixRound(v) { return (v + (LN >> 1)) >> 13; }

  /* ---------- rANS (bảng mã tính từ tần suất) ---------- */
  function mulhi32(a, b) {                       // floor(a b / 2^32), a, b < 2^32
    var ah = a >>> 16, al = a & 0xFFFF, bh = b >>> 16, bl = b & 0xFFFF;
    return ah * bh + Math.floor((ah * bl + al * bh + ((al * bl) >>> 16)) / P2_16);
  }
  function RansTable(freqs) {
    var s = 0, i, j, f, n = 0, shift, A, rcp;
    this.freq = freqs; this.start = []; this.symbol = new Uint8Array(1 << SCALE_BITS); this.esyms = [];
    this.symbol.fill(255);
    for (i = 0; i < freqs.length; i++) { this.start.push(s); s += freqs[i]; }
    for (i = 0; i < freqs.length; i++) for (j = 0; j < freqs[i] && n < this.symbol.length; j++) this.symbol[n++] = i;
    for (i = 0; i < freqs.length; i++) {
      f = freqs[i];
      var xmax = ((RANS_L >> SCALE_BITS) << 8) * f, cmpl = (1 << SCALE_BITS) - f;
      if (f < 2) { this.esyms.push([xmax, P2_32 - 1, this.start[i] + (1 << SCALE_BITS) - 1, cmpl, 0]); continue; }
      shift = 0; while (f > (1 << shift)) shift++;
      A = Math.pow(2, shift + 31) + f - 1; rcp = Math.floor(A / f); if (rcp * f > A) rcp--;
      this.esyms.push([xmax, rcp % P2_32, this.start[i], cmpl, shift - 1]);
    }
  }
  var RANS = {};
  [2, 3, 5].forEach(function (m) { RANS[m] = [new RansTable(RANS_FREQ[m][0]), new RansTable(RANS_FREQ[m][1])]; });

  function ransEncode(tab, syms, bufsize) {      // mã hoá theo thứ tự NGƯỢC; null khi đệm gần đầy
    var buf = new Uint8Array(bufsize), ptr = bufsize, x = RANS_L, i, e;
    for (i = syms.length - 1; i >= 0; i--) {
      e = tab.esyms[syms[i]];
      while (x >= e[0]) { buf[--ptr] = x & 255; x = x >>> 8; }
      x = (x + e[2] + (mulhi32(x, e[1]) >>> e[4]) * e[3]) % P2_32;
      if (ptr < 4) return null;
    }
    ptr -= 4;
    buf[ptr] = x & 255; buf[ptr + 1] = (x >>> 8) & 255; buf[ptr + 2] = (x >>> 16) & 255; buf[ptr + 3] = x >>> 24;
    return buf.slice(ptr);
  }
  function ransDecode(tab, data, off, sizeIn, count) {   // {syms} hoặc {why}
    var end = off + sizeIn, ptr = off + 4, out = new Int32Array(count), i, s;
    var x = (data[off] | (data[off + 1] << 8) | (data[off + 2] << 16) | (data[off + 3] << 24)) >>> 0;
    if (x < RANS_L || x >= RANS_L * 256) return { why: 'init' };
    for (i = 0; i < count; i++) {
      s = tab.symbol[x & 1023];
      if (s >= tab.freq.length) return { why: 'symbol' };
      out[i] = s;
      x = tab.freq[s] * Math.floor(x / 1024) + (x & 1023) - tab.start[s];
      if (x < RANS_L && ptr < end) do { x = (x * 256 + data[ptr]) % P2_32; ptr++; } while (x < RANS_L && ptr < end);
    }
    if (x !== RANS_L) return { why: 'final' };
    if (ptr - off !== sizeIn) return { why: 'used' };
    return { syms: out };
  }

  /* ---------- đóng gói ---------- */
  function packBits(vals, w, out, o) {
    var acc = 0, n = 0, mask = (1 << w) - 1, i;
    for (i = 0; i < vals.length; i++) {
      acc |= (vals[i] & mask) << n; n += w;
      while (n >= 8) { out[o++] = acc & 255; acc >>>= 8; n -= 8; }
    }
    return o;
  }
  function unpackBits(data, off, end, w, count) {   // byte ngoài [off, end) hoặc ngoài dữ liệu = 0
    var out = new Int32Array(count), acc = 0, n = 0, q = off, mask = (1 << w) - 1, i;
    for (i = 0; i < count; i++) {
      while (n < w) { acc |= ((q < end && q < data.length) ? data[q] : 0) << n; q++; n += 8; }
      out[i] = acc & mask; acc >>>= w; n -= w;
    }
    return out;
  }
  function packVk(p, rho, b) {
    var out = new Uint8Array(p.pkBytes), o = SEEDBYTES, i;
    out.set(rho);
    for (i = 0; i < p.k; i++) o = packBits(b[i], p.polyqBits, out, o);
    return out;
  }
  function unpackVk(p, vk) {                     // A1 = (A1[:,0] | 2 A_gen) k x l, miền NTT
    var rho = vk.subarray(0, SEEDBYTES), Ag = expandA(p, rho), a = p.d === 1 ? expandVecA(p, rho) : null, A1 = [], i, j, t, b, row, f;
    for (i = 0; i < p.k; i++) {
      b = unpackBits(vk, SEEDBYTES + i * p.polyqBytes, SEEDBYTES + (i + 1) * p.polyqBytes, p.polyqBits, N);
      f = new Int32Array(N);
      if (p.d === 1) { for (t = 0; t < N; t++) { f[t] = (2 * (a[i][t] - 2 * b[t])) % Q; if (f[t] < 0) f[t] += Q; } f = ntt(f); }
      else for (t = 0; t < N; t++) f[t] = b[t] % Q;
      row = [f];
      for (j = 0; j < p.m; j++) { var g = new Int32Array(N); for (t = 0; t < N; t++) g[t] = (2 * Ag[i][j][t]) % Q; row.push(g); }
      A1.push(row);
    }
    return A1;
  }
  function packEta(f, out, o) {
    for (var i = 0; i < N / 4; i++) {
      var v = 0;
      for (var j = 0; j < 4; j++) v |= ((1 - f[4 * i + j]) & 3) << (2 * j);
      out[o++] = v;
    }
    return o;
  }
  function unpackEta(data, off) { var f = new Int32Array(N); for (var i = 0; i < N; i++) f[i] = 1 - ((data[off + (i >> 2)] >> (2 * (i & 3))) & 3); return f; }
  function packSk(p, vk, s1, s2, key) {
    var out = new Uint8Array(p.skBytes), o = p.pkBytes, i, t;
    out.set(vk);
    for (i = 0; i < p.m; i++) o = packEta(s1[i], out, o);
    for (i = 0; i < p.k; i++) {
      if (p.d === 1) { var v = new Int32Array(N); for (t = 0; t < N; t++) v[t] = 2 - s2[i][t]; o = packBits(v, 3, out, o); }
      else o = packEta(s2[i], out, o);
    }
    out.set(key, o);
    return out;
  }
  function unpackSk(p, sk) {
    if (sk.length < p.skBytes) throw new Error('sk phải dài ' + p.skBytes + ' byte');
    var off = p.pkBytes, s1 = [], s2 = [], i, t, f;
    for (i = 0; i < p.m; i++) s1.push(unpackEta(sk, off + 64 * i));
    off += 64 * p.m;
    for (i = 0; i < p.k; i++) {
      if (p.d === 1) {
        f = unpackBits(sk, off + 96 * i, off + 96 * (i + 1), 3, N);
        for (t = 0; t < N; t++) f[t] = 2 - f[t];
      } else f = unpackEta(sk, off + 64 * i);
      s2.push(f);
    }
    off += p.poly2etaBytes * p.k;
    return { A1: unpackVk(p, sk.subarray(0, p.pkBytes)), s1: s1, s2: s2, key: sk.slice(off, off + SEEDBYTES) };
  }
  function packHighbits(p, w) {                  // HAETAE-2/3: 1 byte/hệ số + 32 byte 0 mỗi đa thức; HAETAE-5: 9 bit
    var out = new Uint8Array(p.k * p.highbitsBytes), i;
    for (i = 0; i < p.k; i++) {
      if (p.mode !== 5) out.set(w[i], i * p.highbitsBytes);
      else packBits(w[i], 9, out, i * p.highbitsBytes);
    }
    return out;
  }
  function packLsb(bits) { var out = new Uint8Array(N / 8); packBits(bits, 1, out, 0); return out; }

  function encodeH(p, h) {                       // h trong [0, m): vùng giữa (cut_h, cut_h + offset_h] -> thất bại
    var syms = new Int32Array(N * p.k), i, j, v, n = 0;
    for (i = 0; i < p.k; i++) for (j = 0; j < N; j++) {
      v = h[i][j];
      if (p.cutH < v && v <= p.cutH + p.offsetH) return null;
      syms[n++] = v > p.cutH + p.offsetH ? v - p.offsetH : v;
    }
    return ransEncode(RANS[p.mode][0], syms, N * p.k);
  }
  function encodeHbZ1(p, hb) {
    var syms = new Int32Array(N * p.l), i, j, t, n = 0;
    for (i = 0; i < p.l; i++) for (j = 0; j < N; j++) {
      t = hb[i][j] + p.cutZ1;
      if (t < 0 || t >= p.mHbZ1) return null;
      syms[n++] = t;
    }
    return ransEncode(RANS[p.mode][1], syms, N * p.l);
  }
  function packSig(p, c, lb, hb, h) {            // c || LowBits(z1) int8 || 2 byte cỡ || rANS(HighBits z1) || rANS(h) || 0..
    var encHb = encodeHbZ1(p, hb), encH = encodeH(p, h), out, o, i, j;
    if (encH === null || encHb === null) return { why: 'encode' };
    if (!(p.baseH <= encH.length && encH.length <= p.baseH + 255 && p.baseHbZ1 <= encHb.length && encHb.length <= p.baseHbZ1 + 255)) return { why: 'base' };
    if (SEEDBYTES + p.l * N + 2 + encHb.length + encH.length > p.sigBytes) return { why: 'length' };
    out = new Uint8Array(p.sigBytes);
    o = packBits(c, 1, out, 0);
    for (i = 0; i < p.l; i++) for (j = 0; j < N; j++) out[o++] = lb[i][j] & 255;
    out[o++] = encHb.length - p.baseHbZ1; out[o++] = encH.length - p.baseH;
    out.set(encHb, o); out.set(encH, o + encHb.length);
    return { sig: out };
  }
  function unpackSig(p, sig) {
    var c = unpackBits(sig, 0, 32, 1, N), off = 32, lowz = [], highz = [], hv = [], i, j, f, sizeHb, sizeH, d;
    for (i = 0; i < p.l; i++) { f = new Int32Array(N); for (j = 0; j < N; j++) f[j] = (sig[off + N * i + j] ^ 0x80) - 0x80; lowz.push(f); }
    off += p.l * N;
    sizeHb = sig[off] + p.baseHbZ1; sizeH = sig[off + 1] + p.baseH;
    off += 2;
    if (p.sigBytes < 2 + p.l * N + SEEDBYTES + sizeH + sizeHb) return { why: 'sizes' };
    d = ransDecode(RANS[p.mode][1], sig, off, sizeHb, N * p.l);
    if (!d.syms) return { why: 'rans_hb_z1_' + d.why };
    for (i = 0; i < p.l; i++) { f = new Int32Array(N); for (j = 0; j < N; j++) f[j] = d.syms[N * i + j] - p.cutZ1; highz.push(f); }
    off += sizeHb;
    d = ransDecode(RANS[p.mode][0], sig, off, sizeH, N * p.k);
    if (!d.syms) return { why: 'rans_h_' + d.why };
    for (i = 0; i < p.k; i++) { f = new Int32Array(N); for (j = 0; j < N; j++) { var s = d.syms[N * i + j]; f[j] = s > p.cutH ? s + p.offsetH : s; } hv.push(f); }
    off += sizeH;
    for (i = off; i < sig.length; i++) if (sig[i]) return { why: 'padding' };
    return { c: c, lowz: lowz, highz: highz, h: hv };
  }

  /* ---------- KeyGen / Sign / Verify ---------- */
  function keygenInternal(p, seed) {
    // (rho, sigma, key) = SHAKE256(seed); lặp ExpandS đến khi N(s) <= gamma^2 n
    var sb = H.shake256(seed, 2 * SEEDBYTES + CRHBYTES), rho = sb.slice(0, 32), sigma = sb.slice(32, 96), key = sb.slice(96, 128);
    var Ah = expandA(p, rho), a = p.d === 1 ? expandVecA(p, rho) : null, counter = 0, attempts = 0, S, s1, s2, i, t, v, vk;
    for (;;) {
      if (++attempts > MAX_KEYGEN_ATTEMPTS) throw new Error('KeyGen: quá ' + MAX_KEYGEN_ATTEMPTS + ' lần thử');
      S = expandS(p, sigma, counter); s1 = S[0]; s2 = S[1];
      counter += p.m + p.k;
      var s1h = s1.map(function (f) { return ntt(modq(f)); });
      if (p.d === 1) {                           // b = A s1 + s2 + a, cắt b = 2 b1' + b0, s2 <- s2 - b0
        var b1 = [], s2m = [];
        for (i = 0; i < p.k; i++) {
          var As = intt(rowDot(Ah[i], s1h)), r1 = new Int32Array(N), r2 = new Int32Array(N);
          for (t = 0; t < N; t++) {
            var bb = (As[t] + s2[i][t] + a[i][t]) % Q; if (bb < 0) bb += Q;
            var a0 = bb & 1; a0 -= ((bb >> 1) & a0) << 1;
            r1[t] = (bb - a0) >> 1; r2[t] = s2[i][t] - a0;
          }
          b1.push(r1); s2m.push(r2);
        }
        v = skSingularValue(p, s1.concat(s2m));
        if (v > p.gammaThr) continue;
        vk = packVk(p, rho, b1);
        return { pk: vk, sk: packSk(p, vk, s1, s2m, key) };
      }
      v = skSingularValue(p, s1.concat(s2));     // d = 0: b-hat = -2 (A s1 + s2)
      if (v > p.gammaThr) continue;
      var bh = [];
      for (i = 0; i < p.k; i++) {
        var As5 = rowDot(Ah[i], s1h), s2h = ntt(modq(s2[i])), r = new Int32Array(N);
        for (t = 0; t < N; t++) { var w = (-2 * ((As5[t] + s2h[t]) % Q)) % Q; r[t] = w < 0 ? w + Q : w; }
        bh.push(r);
      }
      vk = packVk(p, rho, bh);
      return { pk: vk, sk: packSk(p, vk, s1, s2, key) };
    }
  }

  function ay2q(p, A1, z1r, z2r) {               // A1 round(y1) + 2 round(y2) mod q, ghép bit chẵn lẻ -> [0, 2q)
    var zh = z1r.map(function (f) { return ntt(modq(f)); }), out = [], i, t, u, par, Az, row;
    for (i = 0; i < p.k; i++) {
      Az = intt(rowDot(A1[i], zh)); row = new Int32Array(N);
      for (t = 0; t < N; t++) {
        u = (Az[t] + 2 * z2r[i][t]) % Q; if (u < 0) u += Q;
        par = i === 0 ? (z1r[0][t] & 1) : 0;
        row[t] = (u & 1) === par ? u : u + Q;
      }
      out.push(row);
    }
    return out;
  }
  function mapPolys(ps, fn) { return ps.map(function (f) { var g = new Int32Array(N); for (var t = 0; t < N; t++) g[t] = fn(f[t], t); return g; }); }

  function signInternal(p, sk, m, pre, rnd, maxIter) {          // maxIter: giới hạn vòng thấp hơn cho phép thử khứ hồi
    var cap = maxIter || MAX_SIGN_ITERATIONS;
    // mu = SHAKE256(vk || pre || m); lặp: siêu cầu -> w = A round(y) mod 2q -> c -> z = y +- c s -> từ chối -> nén
    var U = unpackSk(p, sk), vk = sk.subarray(0, p.pkBytes);
    var mu = H.shake256(cat([vk, pre, m]), CRHBYTES), seedbuf = H.shake256(cat([U.key, rnd, mu]), CRHBYTES);
    var s1h = U.s1.map(function (f) { return ntt(modq(f)); }), s2h = U.s2.map(function (f) { return ntt(modq(f)); });
    var counter = 0, iters = 0, i, t;
    for (;;) {
      if (iters >= cap) throw new Error('Sign: quá ' + cap + ' vòng');
      iters++;
      var hy = sampleHyperball(p, seedbuf, counter), y1 = hy.y1, y2 = hy.y2, b = hy.b;
      counter = hy.nonce;
      var z1r = mapPolys(y1, fixRound), z2r = mapPolys(y2, fixRound);
      var Ay = ay2q(p, U.A1, z1r, z2r);
      var highbits = mapPolys(Ay, function (v) { return decomposeHint(p, v); });
      var lsb = new Int32Array(N); for (t = 0; t < N; t++) lsb[t] = z1r[0][t] & 1;
      var c = challenge(p, cat([packHighbits(p, highbits), packLsb(lsb)]), mu), ch = ntt(c);
      var cs1 = [c].concat(s1h.map(function (s) { return negMulSmall(ch, s); })), cs2 = s2h.map(function (s) { return negMulSmall(ch, s); });
      var k8 = (b & 1) ? -LN : LN;
      var yy = y1.concat(y2), cs = cs1.concat(cs2), zz = [];
      for (i = 0; i < yy.length; i++) { var zi = new Int32Array(N); for (t = 0; t < N; t++) zi[t] = yy[i][t] + k8 * cs[i][t]; zz.push(zi); }
      var z1 = zz.slice(0, p.l), z2 = zz.slice(p.l);
      if (sqNorm(zz) > BIG[p.mode].lim1) continue;                              // ||z||^2 > B'^2
      if (sqNorm(zz, yy) < BIG[p.mode].lim0 && ((b >> 1) & 1) === 1) continue; // ||2z - y||^2 < B^2 và bit b'
      z1r = mapPolys(z1, fixRound); z2r = mapPolys(z2, fixRound);
      var h = [];
      for (i = 0; i < p.k; i++) {
        var hr = new Int32Array(N);
        for (t = 0; t < N; t++) {
          var dlt = (highbits[i][t] - decomposeHint(p, freeze2q(Ay[i][t] - 2 * z2r[i][t]))) % p.hbM;
          hr[t] = dlt < 0 ? dlt + p.hbM : dlt;
        }
        h.push(hr);
      }
      var hbz = mapPolys(z1r, function (v) { return (v + 128) >> 8; });
      var lbz = mapPolys(z1r, function (v) { var lb = v & 255; return lb >= 128 ? lb - 256 : lb; });
      var ps = packSig(p, c, lbz, hbz, h);
      if (!ps.sig) continue;
      return { sig: ps.sig, iterations: iters };
    }
  }

  function verifyInternal(p, vk, m, sig, pre) {
    // (ok, lý do): siglen, sizes, rans_*, padding, norm, challenge; z2 khôi phục từ HighBits_h(A1 z1 - q c j) + h
    if (sig.length !== p.sigBytes) return { ok: false, why: 'siglen' };
    var A1 = unpackVk(p, vk), u = unpackSig(p, sig), i, t, v;
    if (u.why) return { ok: false, why: u.why };
    var c = u.c, h = u.h, z1 = [], sq = 0;
    for (i = 0; i < p.l; i++) { var f = new Int32Array(N); for (t = 0; t < N; t++) { f[t] = u.highz[i][t] * 256 + u.lowz[i][t]; sq += f[t] * f[t]; } z1.push(f); }
    var wp = new Int32Array(N); for (t = 0; t < N; t++) wp[t] = (z1[0][t] - c[t]) & 1;
    var zh = z1.map(function (g) { return ntt(modq(g)); }), w = [];
    for (i = 0; i < p.k; i++) {
      var Az = intt(rowDot(A1[i], zh)), wr = new Int32Array(N);
      for (t = 0; t < N; t++) {
        var par = i === 0 ? wp[t] : 0, hb = (Az[t] & 1) === par ? Az[t] : Az[t] + Q;
        wr[t] = (decomposeHint(p, hb) + h[i][t]) % p.hbM;
        v = reduce32_2q(wr[t] * p.alphaH - hb + par) >> 1;
        sq += v * v;
      }
      w.push(wr);
    }
    if (sq > p.B2SQ) return { ok: false, why: 'norm' };
    var mu = H.shake256(cat([vk, pre, m]), SEEDBYTES), c2 = challenge(p, cat([packHighbits(p, w), packLsb(wp)]), mu);
    for (t = 0; t < N; t++) if (c2[t] !== c[t]) return { ok: false, why: 'challenge' };
    return { ok: true, why: 'ok' };
  }

  /* ---------- API ---------- */
  var PARAMS = {};
  [2, 3, 5].forEach(function (m) { var p = makeParams(m); bigConsts(p); PARAMS[p.name] = p; });
  function P(name) { var p = PARAMS[name]; if (!p) throw new Error('bộ tham số không có: ' + name); return p; }
  var ZERO = new Uint8Array(SEEDBYTES), PRE0 = new Uint8Array([0]);

  root.HAETAE = {
    PARAMS: PARAMS,
    sizes: function (name) { var p = P(name); return { pk: p.pkBytes, sk: p.skBytes, sig: p.sigBytes, lam: p.sec }; },
    keygenInternal: function (name, seed) { return keygenInternal(P(name), seed); },
    signInternal: function (name, sk, msg, pre, rnd, maxIter) { return signInternal(P(name), sk, msg, pre || PRE0, rnd || ZERO, maxIter); },
    verifyInternal: function (name, pk, msg, sig, pre) {
      var p = P(name);
      try { return verifyInternal(p, pk, msg, sig, pre || PRE0); } catch (e) { return { ok: false, why: 'error' }; }
    },
    pkFromSk: function (name, sk) { return sk.slice(0, P(name).pkBytes); }
  };
})(typeof window !== 'undefined' ? window : globalThis);
