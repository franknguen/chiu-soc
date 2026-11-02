/* SHA-1 và họ SHA-2 (FIPS 180-4), Keccak-p[1600, 24] cùng SHA3-* / SHAKE* (FIPS 202) và cSHAKE (SP 800-185), viết lại
   từ đầu theo văn bản chuẩn và CÓ GHI VẾT: bảng từng bước của một khối, trạng thái 5 x 5 lane sau θ, ρ, π, χ, ι của
   một vòng bất kỳ, bản đồ phần đệm của khối cuối. Không dùng chung dòng nào với pqc-sha2.js / pqc-mlkem.js, để trang
   so được hai phép tính độc lập của cùng một digest.
   - Mọi hằng số được TÍNH khi nạp: K và IV của SHA-2 từ căn bậc ba / bậc hai nguyên của số nguyên tố (BigInt), K của
     SHA-1 = floor(2^30 sqrt(x)), IV của SHA-512/t bằng hàm sinh IV của FIPS 180-4 mục 5.3.6, độ dịch ρ bằng đường đi
     (x, y) của FIPS 202 Thuật toán 2, hằng số vòng RC bằng thanh ghi LFSR của Thuật toán 5.
   - Thông điệp lẻ bit: SHA-1 / SHA-2 đọc bit từ bit cao (byte cuối căn trái, như file CAVS); SHA-3 theo FIPS 202 phụ
     lục B.1 (byte cuối căn phải, bit đầu là bit thấp). ACVP căn trái cả hai: lớp giao diện đổi trước khi gọi.
   - Không dùng DOM: chạy được trong Web Worker. Viết cho việc học, không chống kênh kề.
   Original implementation for the ChiU·SoC hash article. */
(function (root) {
  'use strict';

  /* ================================================================ số học BigInt cho bảng hằng số */
  function primes(n) {
    var out = [], c = 2, i, ok;
    while (out.length < n) {
      ok = true;
      for (i = 0; i < out.length && out[i] * out[i] <= c; i++) if (c % out[i] === 0) { ok = false; break; }
      if (ok) out.push(c);
      c++;
    }
    return out;
  }
  function iroot(n, k) {                       // phần nguyên của căn bậc k của n (BigInt), Newton từ trên xuống
    if (n < 2n) return n;
    var K = BigInt(k), x = 1n << (BigInt(n.toString(2).length) / K + 1n), y;
    for (;;) {
      y = ((K - 1n) * x + n / (x ** (K - 1n))) / K;
      if (y >= x) return x;
      x = y;
    }
  }
  /* w bit đầu của phần lẻ của căn bậc k của p: floor(p^(1/k) * 2^w) mod 2^w */
  function fracRoot(p, k, w) { return iroot(BigInt(p) << BigInt(k * w), k) & ((1n << BigInt(w)) - 1n); }
  function hi32(b) { return Number((b >> 32n) & 0xFFFFFFFFn); }
  function lo32(b) { return Number(b & 0xFFFFFFFFn); }

  var P80 = primes(80);
  /* FIPS 180-4 mục 4.2.2 / 4.2.3: K = 32 / 64 bit đầu phần lẻ căn bậc ba của 64 / 80 số nguyên tố đầu */
  var K256 = new Uint32Array(64), K512 = new Uint32Array(160), i;
  for (i = 0; i < 64; i++) K256[i] = lo32(fracRoot(P80[i], 3, 32));
  for (i = 0; i < 80; i++) { var k5 = fracRoot(P80[i], 3, 64); K512[2 * i] = hi32(k5); K512[2 * i + 1] = lo32(k5); }
  /* mục 5.3: IV = phần lẻ căn bậc hai: SHA-256 (8 số nguyên tố đầu), SHA-512 (64 bit), SHA-384 (số thứ 9 - 16),
     SHA-224 = 32 bit THẤP của 64 bit đó (tức 32 bit thứ hai của phần lẻ) */
  var IV = {};
  IV['SHA-256'] = new Uint32Array(8); IV['SHA-224'] = new Uint32Array(8);
  IV['SHA-512'] = new Uint32Array(16); IV['SHA-384'] = new Uint32Array(16);
  for (i = 0; i < 8; i++) {
    IV['SHA-256'][i] = lo32(fracRoot(P80[i], 2, 32));
    var a5 = fracRoot(P80[i], 2, 64), b5 = fracRoot(P80[i + 8], 2, 64);
    IV['SHA-512'][2 * i] = hi32(a5); IV['SHA-512'][2 * i + 1] = lo32(a5);
    IV['SHA-384'][2 * i] = hi32(b5); IV['SHA-384'][2 * i + 1] = lo32(b5);
    IV['SHA-224'][i] = lo32(b5);
  }
  /* SHA-1 (mục 4.2.1, 5.3.1): bốn K bằng floor(2^30 sqrt(x)), x = 2, 3, 5, 10; IV thì chuẩn cho sẵn, không có công thức */
  var K1 = new Uint32Array([2, 3, 5, 10].map(function (x) { return Number(iroot(BigInt(x) << 60n, 2)); }));
  IV['SHA-1'] = new Uint32Array([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);

  /* ================================================================ máy 32 bit: SHA-1, SHA-224, SHA-256 */
  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
  function rotl(x, n) { return (x << n) | (x >>> (32 - n)); }
  function h8(x) { return ('0000000' + (x >>> 0).toString(16)).slice(-8); }
  var W32 = new Uint32Array(80);
  /* nén một khối 64 byte (blk[off..off+63]) vào H; trace (mảng) nhận [t, W_t, a, b, ...] sau mỗi bước */
  function compress256(H, blk, off, trace) {
    var W = W32, t, a, b, c, d, e, f, g, h, T1, T2;
    for (t = 0; t < 16; t++) W[t] = (blk[off + 4 * t] << 24) | (blk[off + 4 * t + 1] << 16) | (blk[off + 4 * t + 2] << 8) | blk[off + 4 * t + 3];
    for (t = 16; t < 64; t++) {
      var x = W[t - 2], y = W[t - 15];
      var s1 = rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10), s0 = rotr(y, 7) ^ rotr(y, 18) ^ (y >>> 3);
      W[t] = (s1 + W[t - 7] + s0 + W[t - 16]) >>> 0;
    }
    a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4]; f = H[5]; g = H[6]; h = H[7];
    for (t = 0; t < 64; t++) {
      T1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[t] + W[t]) >>> 0;
      T2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + T1) >>> 0; d = c; c = b; b = a; a = (T1 + T2) >>> 0;
      if (trace) trace.push([t, h8(W[t]), h8(a), h8(b), h8(c), h8(d), h8(e), h8(f), h8(g), h8(h)]);
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  function compress1(H, blk, off, trace) {
    var W = W32, t, a, b, c, d, e, f, T;
    for (t = 0; t < 16; t++) W[t] = (blk[off + 4 * t] << 24) | (blk[off + 4 * t + 1] << 16) | (blk[off + 4 * t + 2] << 8) | blk[off + 4 * t + 3];
    for (t = 16; t < 80; t++) W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4];
    for (t = 0; t < 80; t++) {
      if (t < 20) f = (b & c) ^ (~b & d);                 // Ch
      else if (t < 40 || t >= 60) f = b ^ c ^ d;          // Parity
      else f = (b & c) ^ (b & d) ^ (c & d);               // Maj
      T = (rotl(a, 5) + f + e + K1[(t / 20) | 0] + W[t]) >>> 0;
      e = d; d = c; c = rotl(b, 30) >>> 0; b = a; a = T;
      if (trace) trace.push([t, h8(W[t]), h8(a), h8(b), h8(c), h8(d), h8(e)]);
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0; H[4] = (H[4] + e) >>> 0;
  }

  /* ================================================================ máy 64 bit: SHA-384, SHA-512, SHA-512/t
     mỗi từ 64 bit là hai số 32 bit (cao, thấp); kết quả của các hàm phụ trả qua hai biến rh / rl */
  var rh = 0, rl = 0;
  function rr64(h, l, n) {                    // xoay phải n bit, 0 < n < 64, n != 32
    if (n < 32) { rh = (h >>> n) | (l << (32 - n)); rl = (l >>> n) | (h << (32 - n)); }
    else { n -= 32; rh = (l >>> n) | (h << (32 - n)); rl = (h >>> n) | (l << (32 - n)); }
  }
  function S0_64(h, l) {                      // Σ0 = ROTR28 ^ ROTR34 ^ ROTR39
    rr64(h, l, 28); var xh = rh, xl = rl; rr64(h, l, 34); xh ^= rh; xl ^= rl; rr64(h, l, 39); rh ^= xh; rl ^= xl;
  }
  function S1_64(h, l) {                      // Σ1 = ROTR14 ^ ROTR18 ^ ROTR41
    rr64(h, l, 14); var xh = rh, xl = rl; rr64(h, l, 18); xh ^= rh; xl ^= rl; rr64(h, l, 41); rh ^= xh; rl ^= xl;
  }
  function s0_64(h, l) {                      // σ0 = ROTR1 ^ ROTR8 ^ SHR7
    rr64(h, l, 1); var xh = rh, xl = rl; rr64(h, l, 8); xh ^= rh; xl ^= rl;
    rh = xh ^ (h >>> 7); rl = xl ^ ((l >>> 7) | (h << 25));
  }
  function s1_64(h, l) {                      // σ1 = ROTR19 ^ ROTR61 ^ SHR6
    rr64(h, l, 19); var xh = rh, xl = rl; rr64(h, l, 61); xh ^= rh; xl ^= rl;
    rh = xh ^ (h >>> 6); rl = xl ^ ((l >>> 6) | (h << 26));
  }
  var TW = 4294967296;
  function h16(h, l) { return h8(h) + h8(l); }
  var W64 = new Uint32Array(160);
  function compress512(H, blk, off, trace) {
    var W = W64, t, j, sl, sh;
    for (t = 0; t < 32; t++) W[t] = (blk[off + 4 * t] << 24) | (blk[off + 4 * t + 1] << 16) | (blk[off + 4 * t + 2] << 8) | blk[off + 4 * t + 3];
    for (t = 16; t < 80; t++) {
      j = 2 * t;
      s1_64(W[j - 4], W[j - 3]); var ah = rh, al = rl;
      s0_64(W[j - 30], W[j - 29]);
      sl = (al >>> 0) + W[j - 13] + (rl >>> 0) + W[j - 31];
      sh = ah + W[j - 14] + rh + W[j - 32] + Math.floor(sl / TW);
      W[j] = sh >>> 0; W[j + 1] = sl >>> 0;
    }
    var ah0 = H[0], al0 = H[1], bh = H[2], bl = H[3], ch = H[4], cl = H[5], dh = H[6], dl = H[7],
      eh = H[8], el = H[9], fh = H[10], fl = H[11], gh = H[12], gl = H[13], hh = H[14], hl = H[15];
    for (t = 0; t < 80; t++) {
      j = 2 * t;
      S1_64(eh, el); var s1h = rh, s1l = rl;
      var chh = (eh & fh) ^ (~eh & gh), chl = (el & fl) ^ (~el & gl);
      sl = (hl >>> 0) + (s1l >>> 0) + (chl >>> 0) + K512[j + 1] + W[j + 1];
      var t1h = (hh + s1h + chh + K512[j] + W[j] + Math.floor(sl / TW)) >>> 0, t1l = sl >>> 0;
      S0_64(ah0, al0); var s0h = rh, s0l = rl;
      var mjh = (ah0 & bh) ^ (ah0 & ch) ^ (bh & ch), mjl = (al0 & bl) ^ (al0 & cl) ^ (bl & cl);
      sl = (s0l >>> 0) + (mjl >>> 0);
      var t2h = (s0h + mjh + Math.floor(sl / TW)) >>> 0, t2l = sl >>> 0;
      hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
      sl = (dl >>> 0) + t1l; eh = (dh + t1h + Math.floor(sl / TW)) >>> 0; el = sl >>> 0;
      dh = ch; dl = cl; ch = bh; cl = bl; bh = ah0; bl = al0;
      sl = t1l + t2l; ah0 = (t1h + t2h + Math.floor(sl / TW)) >>> 0; al0 = sl >>> 0;
      if (trace) trace.push([t, h16(W[j], W[j + 1]), h16(ah0, al0), h16(bh, bl), h16(ch, cl), h16(dh, dl),
        h16(eh, el), h16(fh, fl), h16(gh, gl), h16(hh, hl)]);
    }
    var v = [ah0, al0, bh, bl, ch, cl, dh, dl, eh, el, fh, fl, gh, gl, hh, hl];
    for (t = 0; t < 8; t++) {
      sl = H[2 * t + 1] + (v[2 * t + 1] >>> 0);
      H[2 * t] = (H[2 * t] + v[2 * t] + Math.floor(sl / TW)) >>> 0; H[2 * t + 1] = sl >>> 0;
    }
  }

  /* ================================================================ khung Merkle–Damgård chung */
  var MD = {
    'SHA-1':       { w: 32, block: 64,  lenBytes: 8,  out: 20, rounds: 80, cf: compress1 },
    'SHA-224':     { w: 32, block: 64,  lenBytes: 8,  out: 28, rounds: 64, cf: compress256 },
    'SHA-256':     { w: 32, block: 64,  lenBytes: 8,  out: 32, rounds: 64, cf: compress256 },
    'SHA-384':     { w: 64, block: 128, lenBytes: 16, out: 48, rounds: 80, cf: compress512 },
    'SHA-512':     { w: 64, block: 128, lenBytes: 16, out: 64, rounds: 80, cf: compress512 },
    'SHA-512/224': { w: 64, block: 128, lenBytes: 16, out: 28, rounds: 80, cf: compress512 },
    'SHA-512/256': { w: 64, block: 128, lenBytes: 16, out: 32, rounds: 80, cf: compress512 }
  };
  /* phần đệm của mục 5.1: bit 1, các bit 0, rồi độ dài thông điệp (bit) big-endian trong lenBytes byte.
     Trả về các khối cuối (từ khối chứa byte thông điệp cuối cùng chưa đủ khối) và nhãn từng byte:
     m = thông điệp, x = byte đánh dấu 0x80, mx = byte lẻ bit chứa cả bit thông điệp lẫn bit 1, z = 0, l = độ dài */
  function mdTail(p, msg, nbits) {
    var full = Math.floor(nbits / 8), k = nbits % 8, start = full - (full % p.block), rest = full - start;
    var need = rest + 1 + p.lenBytes, nblk = Math.ceil(need / p.block), tail = new Uint8Array(nblk * p.block),
      cls = new Array(tail.length), j;
    for (j = 0; j < rest; j++) { tail[j] = msg[start + j]; cls[j] = 'm'; }
    if (k) { tail[rest] = (msg[full] & ((0xFF << (8 - k)) & 0xFF)) | (0x80 >>> k); cls[rest] = 'mx'; }
    else { tail[rest] = 0x80; cls[rest] = 'x'; }
    for (j = rest + 1; j < tail.length - p.lenBytes; j++) cls[j] = 'z';
    var L = nbits, pos = tail.length - 1;
    for (j = 0; j < p.lenBytes; j++) {           // độ dài: byte thấp ở cuối khối
      tail[pos - j] = j < 6 ? (L % 256) : 0; L = Math.floor(L / 256);
      cls[pos - j] = 'l';
    }
    return { tail: tail, cls: cls, start: start };
  }
  function mdState(fn) {
    if (fn === 'SHA-512/224' || fn === 'SHA-512/256') return new Uint32Array(IV[fn]);
    return new Uint32Array(IV[fn]);
  }
  /* băm: msg (Uint8Array), nbits (mặc định 8 * độ dài). o.traceBlock = số thứ tự khối cần bảng từng bước */
  function mdRun(fn, msg, nbits, o) {
    var p = MD[fn], H = mdState(fn), T = mdTail(p, msg, nbits), nblk = T.start / p.block + T.tail.length / p.block,
      want = o && o.traceBlock !== undefined ? o.traceBlock : -1, rows = null, hin = null, b;
    for (b = 0; b < T.start / p.block; b++) {
      if (b === want) { rows = []; hin = hexWords(H, p.w); }
      p.cf(H, msg, b * p.block, b === want ? rows : null);
    }
    for (var q = 0; q < T.tail.length / p.block; q++, b++) {
      if (b === want) { rows = []; hin = hexWords(H, p.w); }
      p.cf(H, T.tail, q * p.block, b === want ? rows : null);
    }
    var out = new Uint8Array(p.out);
    for (var j = 0; j < p.out; j++) out[j] = (H[j >> 2] >>> (24 - 8 * (j & 3))) & 0xFF;
    return { digest: out, blocks: nblk, tail: T.tail, cls: T.cls, tailStart: T.start, block: p.block,
      trace: rows ? { block: want, rows: rows, hin: hin, hout: null } : null };
  }

  /* FIPS 180-4 mục 5.3.6: IV của SHA-512/t = SHA-512 với IV mỗi từ XOR a5a5a5a5a5a5a5a5, băm chuỗi ASCII "SHA-512/t" */
  function sha512tIV(t) {
    var H = new Uint32Array(IV['SHA-512']), j;
    for (j = 0; j < 16; j++) H[j] = (H[j] ^ 0xA5A5A5A5) >>> 0;
    var start = Array.from(H), s = 'SHA-512/' + t, m = new Uint8Array(s.length);
    for (j = 0; j < s.length; j++) m[j] = s.charCodeAt(j);
    var T = mdTail(MD['SHA-512'], m, 8 * m.length);
    compress512(H, T.tail, 0, null);
    return { start: start, text: s, padded: T.tail, iv: H };
  }
  IV['SHA-512/224'] = sha512tIV(224).iv;
  IV['SHA-512/256'] = sha512tIV(256).iv;

  /* ================================================================ Keccak-p[1600, 24]
     trạng thái: Uint32Array(50), lane i = x + 5y nằm ở [2i] (32 bit thấp) và [2i + 1] (32 bit cao); FIPS 202 mục 3.1.2:
     byte thứ 8i..8i+7 của luồng là lane i, little-endian. */
  var RHO = new Int32Array(25), RC = new Uint32Array(48);
  (function () {
    var x = 1, y = 0, t, nx;                    // Thuật toán 2: đi (x, y) <- (y, 2x + 3y), độ dịch (t + 1)(t + 2) / 2
    for (t = 0; t < 24; t++) {
      RHO[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;
      nx = y; y = (2 * x + 3 * y) % 5; x = nx;
    }
    function rc(t) {                            // Thuật toán 5: LFSR x^8 + x^6 + x^5 + x^4 + 1
      if (t % 255 === 0) return 1;
      var R = [1, 0, 0, 0, 0, 0, 0, 0], i, r8;
      for (i = 1; i <= t % 255; i++) {
        R.unshift(0);
        r8 = R[8];
        R[0] ^= r8; R[4] ^= r8; R[5] ^= r8; R[6] ^= r8;
        R.length = 8;
      }
      return R[0];
    }
    for (var ir = 0; ir < 24; ir++) {           // Thuật toán 6: bit 2^j - 1 của RC[ir] = rc(j + 7 ir), j = 0..6
      var lo = 0, hi = 0;
      for (var j = 0; j <= 6; j++) {
        if (!rc(j + 7 * ir)) continue;
        var pos = (1 << j) - 1;
        if (pos < 32) lo |= 1 << pos; else hi |= 1 << (pos - 32);
      }
      RC[2 * ir] = lo >>> 0; RC[2 * ir + 1] = hi >>> 0;
    }
  })();
  var tl = 0, th = 0;
  function rotl64(l, h, n) {                    // xoay trái lane (thấp l, cao h) n bit, 0 <= n < 64
    if (n === 0) { tl = l; th = h; }
    else if (n === 32) { tl = h; th = l; }
    else if (n < 32) { tl = (l << n) | (h >>> (32 - n)); th = (h << n) | (l >>> (32 - n)); }
    else { n -= 32; tl = (h << n) | (l >>> (32 - n)); th = (l << n) | (h >>> (32 - n)); }
  }
  var CL = new Uint32Array(5), CH = new Uint32Array(5);
  function theta(A, B) {                        // mục 3.2.1: C[x] = chẵn lẻ cột; D[x] = C[x-1] ^ ROT(C[x+1], 1)
    var x, y;
    for (x = 0; x < 5; x++) {
      CL[x] = A[2 * x] ^ A[2 * x + 10] ^ A[2 * x + 20] ^ A[2 * x + 30] ^ A[2 * x + 40];
      CH[x] = A[2 * x + 1] ^ A[2 * x + 11] ^ A[2 * x + 21] ^ A[2 * x + 31] ^ A[2 * x + 41];
    }
    for (x = 0; x < 5; x++) {
      var p = (x + 4) % 5, q = (x + 1) % 5;
      rotl64(CL[q], CH[q], 1);
      var dl = CL[p] ^ tl, dh = CH[p] ^ th;
      for (y = 0; y < 5; y++) { B[2 * (x + 5 * y)] = A[2 * (x + 5 * y)] ^ dl; B[2 * (x + 5 * y) + 1] = A[2 * (x + 5 * y) + 1] ^ dh; }
    }
  }
  function rho(A, B) {                          // mục 3.2.2
    for (var i = 0; i < 25; i++) { rotl64(A[2 * i], A[2 * i + 1], RHO[i]); B[2 * i] = tl; B[2 * i + 1] = th; }
  }
  function pi(A, B) {                           // mục 3.2.3: A'[x, y] = A[(x + 3y) mod 5, x]
    for (var y = 0; y < 5; y++) for (var x = 0; x < 5; x++) {
      var s = (x + 3 * y) % 5 + 5 * x, d = x + 5 * y;
      B[2 * d] = A[2 * s]; B[2 * d + 1] = A[2 * s + 1];
    }
  }
  function chi(A, B) {                          // mục 3.2.4: A'[x, y] = A[x, y] ^ (NOT A[x+1, y] AND A[x+2, y])
    for (var y = 0; y < 5; y++) for (var x = 0; x < 5; x++) {
      var d = x + 5 * y, u = (x + 1) % 5 + 5 * y, v = (x + 2) % 5 + 5 * y;
      B[2 * d] = A[2 * d] ^ (~A[2 * u] & A[2 * v]);
      B[2 * d + 1] = A[2 * d + 1] ^ (~A[2 * u + 1] & A[2 * v + 1]);
    }
  }
  function iota(A, ir) { A[0] ^= RC[2 * ir]; A[1] ^= RC[2 * ir + 1]; }   // mục 3.2.5
  function lanes(A) {
    var o = [];
    for (var i = 0; i < 25; i++) o.push(h8(A[2 * i + 1]) + h8(A[2 * i]));
    return o;
  }
  var KB = new Uint32Array(50);
  /* 24 vòng trên A (tại chỗ). tr = { round: r, out: {} } nhận trạng thái vào và sau từng bước của vòng r */
  function keccakP(A, tr) {
    for (var ir = 0; ir < 24; ir++) {
      var rec = tr && tr.round === ir;
      if (rec) tr.out.in = lanes(A);
      theta(A, KB); if (rec) tr.out.theta = lanes(KB);
      rho(KB, A); if (rec) tr.out.rho = lanes(A);
      pi(A, KB); if (rec) tr.out.pi = lanes(KB);
      chi(KB, A); if (rec) tr.out.chi = lanes(A);
      iota(A, ir); if (rec) tr.out.iota = lanes(A);
    }
  }

  /* ================================================================ sponge (FIPS 202 mục 4, 5.1, 6) */
  var SP = {
    'SHA3-224':  { rate: 144, cap: 448,  out: 28, sfx: 0x2, sbits: 2, kind: 'sha3' },
    'SHA3-256':  { rate: 136, cap: 512,  out: 32, sfx: 0x2, sbits: 2, kind: 'sha3' },
    'SHA3-384':  { rate: 104, cap: 768,  out: 48, sfx: 0x2, sbits: 2, kind: 'sha3' },
    'SHA3-512':  { rate: 72,  cap: 1024, out: 64, sfx: 0x2, sbits: 2, kind: 'sha3' },
    'SHAKE128':  { rate: 168, cap: 256,  out: 0,  sfx: 0xF, sbits: 4, kind: 'shake' },
    'SHAKE256':  { rate: 136, cap: 512,  out: 0,  sfx: 0xF, sbits: 4, kind: 'shake' },
    'cSHAKE128': { rate: 168, cap: 256,  out: 0,  sfx: 0x0, sbits: 2, kind: 'cshake' },
    'cSHAKE256': { rate: 136, cap: 512,  out: 0,  sfx: 0x0, sbits: 2, kind: 'cshake' }
  };
  /* SP 800-185 mục 2.3 */
  function leftEncode(x) {
    var b = [];
    do { b.unshift(x % 256); x = Math.floor(x / 256); } while (x > 0);
    b.unshift(b.length);
    return b;
  }
  function encodeString(s) { return leftEncode(8 * s.length).concat(Array.from(s)); }
  function bytepad(arr, w) {
    var z = leftEncode(w).concat(arr);
    while (z.length % w) z.push(0);
    return new Uint8Array(z);
  }
  function cshakePrefix(fn, N, S) { return bytepad(encodeString(N || []).concat(encodeString(S || [])), SP[fn].rate); }
  /* thông điệp msg dài nbits bit (byte cuối căn phải theo FIPS 202 B.1), sau prefix (đủ khối) -> đệm.
     o: { outBits, N, S, tracePerm, traceRound }. Trả về digest + các khối cuối + nhãn từng byte:
     c = tiền tố cSHAKE, m = thông điệp, ms = byte lẻ bit chứa cả thông điệp lẫn hậu tố, s = hậu tố miền + bit 1 đầu
     của pad10*1, z = 0, e = bit 1 cuối (0x80), se = hậu tố và bit cuối chung một byte (0x86 / 0x9f / 0x84) */
  function spRun(fn, msg, nbits, o) {
    o = o || {};
    var p = SP[fn], r = p.rate, sfx = p.sfx, sb = p.sbits, pre = null;
    if (p.kind === 'cshake') {
      var N = o.N || new Uint8Array(0), S = o.S || new Uint8Array(0);
      if (N.length || S.length) pre = cshakePrefix(fn, N, S);
      else { sfx = 0xF; sb = 4; }                // N = S = "": cSHAKE chính là SHAKE (SP 800-185 mục 3.3)
    }
    var preLen = pre ? pre.length : 0, full = Math.floor(nbits / 8), k = nbits % 8, total = preLen + full;
    var start = total - (total % r), rest = total - start;
    var P = 8 * rest + k + sb, tailBytes = Math.ceil((P + 2) / (8 * r)) * r;
    var tail = new Uint8Array(tailBytes), cls = new Array(tailBytes), j;
    function byteAt(i) { return i < preLen ? pre[i] : msg[i - preLen]; }
    for (j = 0; j < rest; j++) { tail[j] = byteAt(start + j); cls[j] = start + j < preLen ? 'c' : 'm'; }
    var bits = (k ? (msg[full] & ((1 << k) - 1)) : 0) | (sfx << k) | (1 << (k + sb));   // thông điệp lẻ, hậu tố, bit 1
    tail[rest] = bits & 0xFF; cls[rest] = k ? 'ms' : 's';
    if (bits > 0xFF) { tail[rest + 1] = bits >>> 8; cls[rest + 1] = 's'; }
    for (j = rest + 1 + (bits > 0xFF ? 1 : 0); j < tailBytes; j++) cls[j] = 'z';
    tail[tailBytes - 1] |= 0x80;
    cls[tailBytes - 1] = cls[tailBytes - 1] === 'z' ? 'e' : (cls[tailBytes - 1] === 'ms' ? 'mse' : 'se');
    var outBits = o.outBits || 8 * p.out, outBytes = Math.ceil(outBits / 8);
    var A = new Uint32Array(50), perms = [], nAbs = start / r + tailBytes / r, nSq = Math.max(0, Math.ceil(outBytes / r) - 1);
    var want = o.tracePerm !== undefined ? o.tracePerm : -1, tr = null, pn = 0, q;
    function absorb(get, base) {
      for (q = 0; q < r; q += 4) {
        var w = q >> 2;
        A[w] ^= get(base + q) | (get(base + q + 1) << 8) | (get(base + q + 2) << 16) | (get(base + q + 3) << 24);
      }
    }
    function perm(kind, from) {
      var t = pn === want ? { round: o.traceRound || 0, out: {} } : null;
      if (t) t.before = lanes(A);
      keccakP(A, t);
      if (t) { t.after = lanes(A); tr = t.out; tr.before = t.before; tr.after = t.after; tr.perm = pn; tr.round = t.round; }
      if (o.listPerms) perms.push({ kind: kind, from: from });
      pn++;
    }
    for (var b = 0; b < start; b += r) {
      if (pre && b + r <= preLen) absorb(function (i) { return pre[i]; }, b);
      else if (!pre) absorb(function (i) { return msg[i]; }, b);
      else absorb(byteAt, b);
      perm('absorb', b);
    }
    for (b = 0; b < tailBytes; b += r) { absorb(function (i) { return tail[i]; }, b); perm('absorb', start + b); }
    var out = new Uint8Array(outBytes), pos = 0;
    for (;;) {
      for (q = 0; q < r && pos < outBytes; q++, pos++) out[pos] = (A[q >> 2] >>> (8 * (q & 3))) & 0xFF;
      if (pos >= outBytes) break;
      perm('squeeze', pos);
    }
    if (outBits % 8) out[outBytes - 1] &= (1 << (outBits % 8)) - 1;
    return { digest: out, absorbs: nAbs, squeezes: nSq, perms: perms, tail: tail, cls: cls, tailStart: start,
      block: r, prefixLen: preLen, trace: tr };
  }

  /* ================================================================ giao diện chung */
  var ORDER = ['SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA-512/224', 'SHA-512/256',
    'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'SHAKE128', 'SHAKE256', 'cSHAKE128', 'cSHAKE256'];
  function info(fn) {
    if (MD[fn]) { var m = MD[fn]; return { kind: 'md', w: m.w, block: m.block, lenBytes: m.lenBytes, out: m.out, rounds: m.rounds }; }
    var s = SP[fn];
    if (!s) throw new Error('unknown function ' + fn);
    return { kind: s.kind, rate: s.rate, cap: s.cap, out: s.out, block: s.rate, suffix: s.kind === 'sha3' ? 0x06 : (s.kind === 'shake' ? 0x1F : 0x04) };
  }
  /* run(fn, msg, o): o.bits (độ dài bit, mặc định 8 * msg.length), o.outBits / o.outLen (XOF), o.N, o.S (Uint8Array),
     o.traceBlock (SHA-1 / SHA-2) hoặc o.tracePerm + o.traceRound (Keccak), o.listPerms */
  function run(fn, msg, o) {
    o = o || {};
    var nbits = o.bits !== undefined && o.bits !== null ? o.bits : 8 * msg.length;
    if (nbits > 8 * msg.length) throw new Error('bits > message');
    if (MD[fn]) return mdRun(fn, msg, nbits, o);
    var p = SP[fn];
    if (!p) throw new Error('unknown function ' + fn);
    var q = {};
    for (var k in o) q[k] = o[k];
    if (p.kind !== 'sha3') {
      q.outBits = o.outBits || (o.outLen ? 8 * o.outLen : 0);
      if (!(q.outBits > 0)) throw new Error('XOF output length missing');
    }
    return spRun(fn, msg, nbits, q);
  }
  function digest(fn, msg, o) { return run(fn, msg, o).digest; }

  /* ================================================================ tấn công mở rộng độ dài (length extension)
     Biết digest = H(bí mật || m) và độ dài origLen của (bí mật || m), nhưng KHÔNG biết bí mật: nạp digest làm trạng
     thái, coi như đã nén xong (bí mật || m || đệm), băm tiếp ext. Chỉ làm được khi digest là TOÀN BỘ trạng thái
     (SHA-1, SHA-256, SHA-512); các hàm cắt ngắn giấu (bit trạng thái - bit digest) bit. */
  function lengthExtend(fn, known, origLen, ext) {
    var p = MD[fn], j;
    if (!p) return { ok: false, hidden: null };
    var stateBytes = p.w === 32 ? (p.cf === compress1 ? 20 : 32) : 64;
    if (p.out !== stateBytes) return { ok: false, hidden: 8 * (stateBytes - p.out) };
    var H = new Uint32Array(p.w === 32 ? stateBytes / 4 : 16);
    for (j = 0; j < H.length; j++) H[j] = ((known[4 * j] << 24) | (known[4 * j + 1] << 16) | (known[4 * j + 2] << 8) | known[4 * j + 3]) >>> 0;
    var g = mdTail(p, new Uint8Array(origLen % p.block), 8 * origLen), glue = g.tail.subarray(origLen % p.block);
    var done = origLen + glue.length, T = mdTail(p, ext, 8 * ext.length), L = 8 * (done + ext.length), pos = T.tail.length - 1;
    for (j = 0; j < p.lenBytes; j++) { T.tail[pos - j] = j < 6 ? L % 256 : 0; L = Math.floor(L / 256); }
    for (j = 0; j < T.start; j += p.block) p.cf(H, ext, j, null);
    for (j = 0; j < T.tail.length; j += p.block) p.cf(H, T.tail, j, null);
    var out = new Uint8Array(p.out);
    for (j = 0; j < p.out; j++) out[j] = (H[j >> 2] >>> (24 - 8 * (j & 3))) & 0xFF;
    return { ok: true, glue: Uint8Array.from(glue), forged: out };
  }

  /* ================================================================ Monte Carlo (CAVP SHAVS / SHA3VS, ACVP)
     job: { fn, variant: 'md-standard' | 'md-alternate' | 'sha3' | 'shake', seed (Uint8Array), seedBits,
            minOutBits, maxOutBits }; st (trạng thái giữa hai checkpoint) bắt đầu là null.
     mctStep(job, st) -> { md, outBits, st }: đúng MỘT checkpoint = 1000 lần băm. */
  function cat3(a, b, c) { var o = new Uint8Array(a.length + b.length + c.length); o.set(a, 0); o.set(b, a.length); o.set(c, a.length + b.length); return o; }
  function mctStep(job, st) {
    var fn = job.fn, i, md;
    if (!st) {
      st = { seed: job.seed };
      if (job.variant === 'shake') st.outBits = Math.floor(job.maxOutBits / 8) * 8;
    }
    if (job.variant === 'md-standard') {            // SHAVS 6.4: MD0 = MD1 = MD2 = Seed; MDi = SHA(MDi-3 || MDi-2 || MDi-1)
      var a = st.seed, b = st.seed, c = st.seed;
      for (i = 0; i < 1000; i++) { md = digest(fn, cat3(a, b, c)); a = b; b = c; c = md; }
      return { md: md, st: { seed: md } };
    }
    if (job.variant === 'md-alternate') {           // ACVP: MSG = A || B || C cắt / đệm 0 về đúng độ dài seed
      var A = st.seed, B = st.seed, C = st.seed, nb = job.seedBits / 8;
      for (i = 0; i < 1000; i++) {
        var all = cat3(A, B, C), m = new Uint8Array(nb);
        m.set(all.subarray(0, Math.min(nb, all.length)));
        md = digest(fn, m); A = B; B = C; C = md;
      }
      return { md: md, st: { seed: md } };
    }
    if (job.variant === 'sha3') {                   // SHA3VS: MDi = SHA3(MDi-1), 1000 lần
      md = st.seed;
      for (i = 0; i < 1000; i++) md = digest(fn, md);
      return { md: md, st: { seed: md } };
    }
    if (job.variant === 'shake') {                  // SHA3VS SHAKE: tin nhắn = 128 bit trái nhất của đầu ra trước
      var prev = st.seed, ob = st.outBits, used = ob, minB = Math.ceil(job.minOutBits / 8),
        range = Math.floor(job.maxOutBits / 8) - minB + 1;
      for (i = 0; i < 1000; i++) {
        var m16 = new Uint8Array(16);
        m16.set(prev.subarray(0, Math.min(16, prev.length)));
        prev = digest(fn, m16, { outBits: ob });
        used = ob;
        var right = (prev[prev.length - 2] << 8) | prev[prev.length - 1];
        ob = 8 * (minB + (right % range));
      }
      return { md: prev, outBits: used, st: { seed: prev, outBits: ob } };
    }
    throw new Error('unknown MCT variant ' + job.variant);
  }

  /* ================================================================ tiện ích */
  function toHex(b) { var s = ''; for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16); return s; }
  function fromHex(s) {
    s = String(s).replace(/\s+/g, '');
    if (s.length % 2) throw new Error('odd hex');
    var o = new Uint8Array(s.length / 2);
    for (var i = 0; i < o.length; i++) {
      var v = parseInt(s.substr(2 * i, 2), 16);
      if (isNaN(v) || !/^[0-9a-fA-F]{2}$/.test(s.substr(2 * i, 2))) throw new Error('bad hex');
      o[i] = v;
    }
    return o;
  }
  /* ACVP ghi byte lẻ cuối căn trái; FIPS 202 căn phải (chỉ khác ở SHA-3; SHA-1 / SHA-2 đều căn trái) */
  function acvpToFips(m, nbits) {
    var k = nbits % 8;
    if (!k || !m.length) return m;
    var o = Uint8Array.from(m.subarray(0, Math.ceil(nbits / 8)));
    o[o.length - 1] = o[o.length - 1] >>> (8 - k);
    return o;
  }
  function fipsToAcvp(d, nbits) {
    var k = nbits % 8;
    if (!k || !d.length) return d;
    var o = Uint8Array.from(d);
    o[o.length - 1] = (o[o.length - 1] << (8 - k)) & 0xFF;
    return o;
  }

  function hexWords(a, w) {
    var o = [];
    if (w === 32) for (var i = 0; i < a.length; i++) o.push(h8(a[i]));
    else for (var j = 0; j < a.length; j += 2) o.push(h8(a[j]) + h8(a[j + 1]));
    return o;
  }
  var consts = {
    K256: hexWords(K256, 32), K512: hexWords(K512, 64), SHA1K: hexWords(K1, 32),
    IV: (function () { var o = {}; for (var f in MD) o[f] = hexWords(IV[f], MD[f].w); return o; })(),
    RC: (function () { var o = []; for (var ir = 0; ir < 24; ir++) o.push(h8(RC[2 * ir + 1]) + h8(RC[2 * ir])); return o; })(),
    RHO: Array.from(RHO)
  };

  root.HashTrace = {
    ORDER: ORDER, info: info, run: run, digest: digest, mctStep: mctStep, consts: consts,
    sha512tIV: function (t) { var r = sha512tIV(t); return { start: hexWords(r.start, 64), text: r.text, padded: r.padded, iv: hexWords(r.iv, 64) }; },
    cshakePrefix: cshakePrefix, keccakP: keccakP, lanes: lanes, lengthExtend: lengthExtend,
    toHex: toHex, fromHex: fromHex, acvpToFips: acvpToFips, fipsToAcvp: fipsToAcvp
  };
})(typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : globalThis));
