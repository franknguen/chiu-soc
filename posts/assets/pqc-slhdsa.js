/* SLH-DSA (NIST FIPS 205) — hiện thực JavaScript thuần, viết từ đặc tả: 12 bộ tham số SHA2/SHAKE × 128/192/256 × s/f.
   Tầng băm: PQCHash.keccakP / shake256 (pqc-mlkem.js), nén một khối SHA-256/512 (pqc-sha2.js); M' lấy từ pqc-mldsa.js.
   Original implementation for the ChiU·SoC PQC demo page. */
(function (root) {
  'use strict';
  var KH = root.PQCHash, S2 = root.PQCSHA2;
  if (!KH || !KH.keccakP || !S2 || !S2.compress256) throw new Error('pqc-mlkem.js và pqc-sha2.js phải được nạp trước pqc-slhdsa.js');
  var keccakP = KH.keccakP, c256 = S2.compress256, c512 = S2.compress512;

  /* ---------- tham số: Bảng 2 của FIPS 205 (n, h, d, h', a, k, lg w); mọi cột khác được TÍNH ---------- */
  var TABLE2 = [['128s', 16, 63, 7, 9, 12, 14, 4], ['128f', 16, 66, 22, 3, 6, 33, 4],
                ['192s', 24, 63, 7, 9, 14, 17, 4], ['192f', 24, 66, 22, 3, 8, 33, 4],
                ['256s', 32, 64, 8, 8, 14, 22, 4], ['256f', 32, 68, 17, 4, 9, 35, 4]];
  function genLen2(n, lgw) {                   // Alg. 1
    var w = 1 << lgw, len1 = Math.ceil(8 * n / lgw), maxc = len1 * (w - 1), len2 = 1, cap = w;
    while (cap <= maxc) { len2++; cap *= w; }
    return len2;
  }
  var NAMES = [], PARAMS = {};
  ['SHA2', 'SHAKE'].forEach(function (fam) {
    TABLE2.forEach(function (r) {
      var n = r[1], h = r[2], d = r[3], hp = r[4], a = r[5], k = r[6], lgw = r[7];
      var p = { name: 'SLH-DSA-' + fam + '-' + r[0], n: n, h: h, d: d, hp: hp, a: a, k: k, lgw: lgw, w: 1 << lgw,
                shake: fam === 'SHAKE', fast: r[0].charAt(3) === 'f' };
      p.len1 = Math.ceil(8 * n / lgw); p.len2 = genLen2(n, lgw); p.len = p.len1 + p.len2;
      p.mdBytes = Math.ceil(k * a / 8); p.treeBits = h - hp; p.leafBits = hp;
      p.treeBytes = Math.ceil(p.treeBits / 8); p.leafBytes = Math.ceil(h / (8 * d));
      p.m = p.mdBytes + p.treeBytes + p.leafBytes;
      p.pk = 2 * n; p.sk = 4 * n; p.sig = (1 + k * (1 + a) + h + d * p.len) * n;
      NAMES.push(p.name); PARAMS[p.name] = p;
    });
  });
  function P(name) { var p = PARAMS[name]; if (!p) throw new Error('bộ tham số SLH-DSA không có: ' + name); return p; }

  /* ---------- byte, ADRS (§4.2, Bảng 1) ---------- */
  var WOTS_HASH = 0, WOTS_PK = 1, TREE = 2, FORS_TREE = 3, FORS_ROOTS = 4, WOTS_PRF = 5, FORS_PRF = 6;
  function put32(a, o, v) { a[o] = v >>> 24; a[o + 1] = v >>> 16; a[o + 2] = v >>> 8; a[o + 3] = v; }
  function get32(a, o) { return ((a[o] << 24) | (a[o + 1] << 16) | (a[o + 2] << 8) | a[o + 3]) >>> 0; }
  function be32(a, o) { return (a[o] << 24) | (a[o + 1] << 16) | (a[o + 2] << 8) | a[o + 3]; }
  function le32(a, o) { return a[o] | (a[o + 1] << 8) | (a[o + 2] << 16) | (a[o + 3] << 24); }
  function setTypeAndClear(a, t) { put32(a, 16, t); for (var i = 20; i < 32; i++) a[i] = 0; }
  function setTree(a, hi, lo) { a[4] = a[5] = a[6] = a[7] = 0; put32(a, 8, hi); put32(a, 12, lo); }   // 12 byte, giá trị <= 64 bit
  function copyN(src, so, dst, dO, n) { for (var i = 0; i < n; i++) dst[dO + i] = src[so + i]; }
  function cat(arrs) { var n = 0, i, q = 0; for (i = 0; i < arrs.length; i++) n += arrs[i].length; var o = new Uint8Array(n); for (i = 0; i < arrs.length; i++) { o.set(arrs[i], q); q += arrs[i].length; } return o; }
  function base2b(X, xo, b, outLen, out, oo) { // Alg. 4: chữ số b bit, bit cao trước
    var i = xo, bits = 0, total = 0, mask = (1 << b) - 1, q;
    for (q = 0; q < outLen; q++) {
      while (bits < b) { total = (total << 8) | X[i++]; bits += 8; }
      bits -= b; out[oo + q] = (total >>> bits) & mask; total &= (1 << bits) - 1;
    }
  }

  /* ---------- ngữ cảnh băm gắn với PK.seed (§11): mọi bộ đệm cấp một lần ---------- */
  function Ctx(p, pkSeed, skSeed) {
    var n = p.n, nw = n >> 2, q, blk = Math.max(p.len, p.k) * n;
    this.p = p; this.n = n; this.nw = nw; this.shake = p.shake; this.skSeed = skSeed;
    this.A = new Uint8Array(32); this.B = new Uint8Array(32);
    this.x = new Int32Array(8); this.dig = new Int32Array(Math.max(p.len, p.k)); this.cs = new Uint8Array(4);
    this.tmp = new Uint8Array(blk); this.stk = new Uint8Array((Math.max(p.hp, p.a) + 1) * 2 * n);
    this.nd = new Uint8Array(n); this.hb = new Uint8Array(2 * n); this.lf = new Uint8Array(n);
    this.rt = new Uint8Array(n); this.pkf = new Uint8Array(n);
    if (p.shake) {
      this.s = new Int32Array(50); this.seedW = new Int32Array(nw);
      for (q = 0; q < nw; q++) this.seedW[q] = le32(pkSeed, 4 * q);
    } else {                                   // trạng thái giữa sau khối PK.seed || toByte(0, 64 - n) (và 128 - n)
      var b = new Uint8Array(128); b.set(pkSeed);
      this.w = new Int32Array(64); this.st = new Int32Array(8); this.mid = S2.iv256();
      for (q = 0; q < 16; q++) this.w[q] = be32(b, 4 * q);
      c256(this.mid, this.w);
      this.mb = new Uint8Array(22 + blk + 256);
      if (n > 16) {
        this.w5 = new Int32Array(160); this.st5 = new Int32Array(16); this.mid5 = S2.iv512();
        for (q = 0; q < 32; q++) this.w5[q] = be32(b, 4 * q);
        c512(this.mid5, this.w5);
      }
    }
  }

  /* F / H / T_l / PRF = Hash(PK.seed, ADRS, l khối n byte): SHAKE256 (§11.1) hoặc SHA-256/512 với ADRSc (§11.2) */
  function thash(C, adrs, src, so, l, dst, dO) {
    var n = C.n, nw = C.nw, q, b, e, v;
    if (C.shake) {
      var s = C.s, pos = nw + 8;
      for (q = 0; q < 50; q++) s[q] = 0;
      for (q = 0; q < nw; q++) s[q] = C.seedW[q];
      for (q = 0; q < 8; q++) s[nw + q] = le32(adrs, 4 * q);
      for (b = so, e = so + l * n; b < e; b += 4) {
        s[pos] ^= le32(src, b);
        if (++pos === 34) { keccakP(s); pos = 0; }
      }
      s[pos] ^= 0x1F; s[33] ^= -2147483648; // đệm SHAKE: 0x1F … 0x80 trong khối 136 byte
      keccakP(s);
      for (q = 0; q < nw; q++) { v = s[q]; b = dO + 4 * q; dst[b] = v; dst[b + 1] = v >>> 8; dst[b + 2] = v >>> 16; dst[b + 3] = v >>> 24; }
      return;
    }
    var mb = C.mb, L = 22 + l * n, big = n > 16 && l > 1, bs = big ? 128 : 64, Pn, off, st, w;
    mb[0] = adrs[3]; for (q = 0; q < 8; q++) mb[1 + q] = adrs[8 + q];   // ADRSc: ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]
    mb[9] = adrs[19]; for (q = 0; q < 12; q++) mb[10 + q] = adrs[20 + q];
    copyN(src, so, mb, 22, l * n);
    Pn = Math.ceil((L + 1 + (big ? 16 : 8)) / bs) * bs;
    mb[L] = 0x80; for (q = L + 1; q < Pn - 4; q++) mb[q] = 0;
    put32(mb, Pn - 4, (bs + L) * 8);
    if (!big) {
      st = C.st; w = C.w; st.set(C.mid);
      for (off = 0; off < Pn; off += 64) { for (q = 0; q < 16; q++) w[q] = be32(mb, off + 4 * q); c256(st, w); }
    } else {
      st = C.st5; w = C.w5; st.set(C.mid5);
      for (off = 0; off < Pn; off += 128) { for (q = 0; q < 32; q++) w[q] = be32(mb, off + 4 * q); c512(st, w); }
    }
    for (q = 0; q < nw; q++) put32(dst, dO + 4 * q, st[q]);
  }

  /* Alg. 5 chain: tại chỗ trên buf[off..off+n), giữ giá trị ở dạng từ 32 bit giữa các bước;
     chỉ địa chỉ băm (ADRS[28:32] = j < 16) đổi giữa các lần gọi F */
  function chain(C, buf, off, i, s, adrs) {
    if (s <= 0) return;
    var x = C.x, nw = C.nw, end = i + s, j, q, v, b;
    if (C.shake) {
      var st = C.s, sw = C.seedW, pad = 2 * nw + 8;
      var a0 = le32(adrs, 0), a1 = le32(adrs, 4), a2 = le32(adrs, 8), a3 = le32(adrs, 12);
      var a4 = le32(adrs, 16), a5 = le32(adrs, 20), a6 = le32(adrs, 24);
      for (q = 0; q < nw; q++) x[q] = le32(buf, off + 4 * q);
      for (j = i; j < end; j++) {
        for (q = 0; q < nw; q++) st[q] = sw[q];
        st[nw] = a0; st[nw + 1] = a1; st[nw + 2] = a2; st[nw + 3] = a3;
        st[nw + 4] = a4; st[nw + 5] = a5; st[nw + 6] = a6; st[nw + 7] = j << 24;
        for (q = 0; q < nw; q++) st[nw + 8 + q] = x[q];
        st[pad] = 0x1F; for (q = pad + 1; q < 50; q++) st[q] = 0;
        st[33] = -2147483648;
        keccakP(st);
        for (q = 0; q < nw; q++) x[q] = st[q];
      }
      for (q = 0; q < nw; q++) { v = x[q]; b = off + 4 * q; buf[b] = v; buf[b + 1] = v >>> 8; buf[b + 2] = v >>> 16; buf[b + 3] = v >>> 24; }
    } else {                                   // một khối SHA-256 sau trạng thái giữa: ADRSc (22 byte) || X || đệm
      var W = C.w, S = C.st, m = C.mid, last = 5 + nw, bits = (64 + 22 + C.n) * 8;
      var w0 = (adrs[3] << 24) | (adrs[8] << 16) | (adrs[9] << 8) | adrs[10];
      var w1 = (adrs[11] << 24) | (adrs[12] << 16) | (adrs[13] << 8) | adrs[14];
      var w2 = (adrs[15] << 24) | (adrs[19] << 16) | (adrs[20] << 8) | adrs[21];
      var w3 = (adrs[22] << 24) | (adrs[23] << 16) | (adrs[24] << 8) | adrs[25];
      var w4 = (adrs[26] << 24) | (adrs[27] << 16);
      var m0 = m[0], m1 = m[1], m2 = m[2], m3 = m[3], m4 = m[4], m5 = m[5], m6 = m[6], m7 = m[7];
      for (q = 0; q < nw; q++) x[q] = be32(buf, off + 4 * q);
      for (j = i; j < end; j++) {
        W[0] = w0; W[1] = w1; W[2] = w2; W[3] = w3; W[4] = w4;
        W[5] = (j << 16) | (x[0] >>> 16);
        for (q = 1; q < nw; q++) W[5 + q] = (x[q - 1] << 16) | (x[q] >>> 16);
        W[last] = (x[nw - 1] << 16) | 0x8000;
        for (q = last + 1; q < 15; q++) W[q] = 0;
        W[15] = bits;
        S[0] = m0; S[1] = m1; S[2] = m2; S[3] = m3; S[4] = m4; S[5] = m5; S[6] = m6; S[7] = m7;
        c256(S, W);
        for (q = 0; q < nw; q++) x[q] = S[q];
      }
      for (q = 0; q < nw; q++) put32(buf, off + 4 * q, x[q]);
    }
    put32(adrs, 28, end - 1);
  }

  /* ---------- WOTS+ (Alg. 6-8) ---------- */
  function wotsDigits(C, M, mo) {              // msg = base_2b(M) || base_2b(csum)
    var p = C.p, dig = C.dig, i, csum = 0, lgw = p.lgw, cb = Math.ceil(p.len2 * lgw / 8);
    base2b(M, mo, lgw, p.len1, dig, 0);
    for (i = 0; i < p.len1; i++) csum += p.w - 1 - dig[i];
    csum = csum << ((8 - ((p.len2 * lgw) % 8)) % 8);
    for (i = 0; i < cb; i++) C.cs[i] = csum >>> (8 * (cb - 1 - i));
    base2b(C.cs, 0, lgw, p.len2, dig, p.len1);
  }
  function wotsSkAdrs(C, adrs) { var B = C.B; B.set(adrs); setTypeAndClear(B, WOTS_PRF); copyN(adrs, 20, B, 20, 4); return B; }
  function wotsPkGen(C, adrs, dst, dO) {       // Alg. 6
    var p = C.p, n = C.n, tmp = C.tmp, B = wotsSkAdrs(C, adrs), i;
    for (i = 0; i < p.len; i++) {
      put32(B, 24, i); thash(C, B, C.skSeed, 0, 1, tmp, i * n);
      put32(adrs, 24, i); chain(C, tmp, i * n, 0, p.w - 1, adrs);
    }
    B.set(adrs); setTypeAndClear(B, WOTS_PK); copyN(adrs, 20, B, 20, 4);
    thash(C, B, tmp, 0, p.len, dst, dO);
  }
  function wotsSign(C, M, mo, adrs, sig, so) { // Alg. 7
    var p = C.p, n = C.n, dig = C.dig, B, i;
    wotsDigits(C, M, mo);
    B = wotsSkAdrs(C, adrs);
    for (i = 0; i < p.len; i++) {
      put32(B, 24, i); thash(C, B, C.skSeed, 0, 1, sig, so + i * n);
      put32(adrs, 24, i); chain(C, sig, so + i * n, 0, dig[i], adrs);
    }
  }
  function wotsPkFromSig(C, sig, so, M, mo, adrs, dst, dO) {   // Alg. 8
    var p = C.p, n = C.n, dig = C.dig, tmp = C.tmp, B = C.B, i;
    wotsDigits(C, M, mo);
    for (i = 0; i < p.len; i++) {
      copyN(sig, so + i * n, tmp, i * n, n);
      put32(adrs, 24, i); chain(C, tmp, i * n, dig[i], p.w - 1 - dig[i], adrs);
    }
    B.set(adrs); setTypeAndClear(B, WOTS_PK); copyN(adrs, 20, B, 20, 4);
    thash(C, B, tmp, 0, p.len, dst, dO);
  }

  /* ---------- XMSS (Alg. 9-11); nút con nằm trên ngăn xếp C.stk, mỗi độ cao một ngăn 2n byte ---------- */
  function xmssNode(C, i, z, adrs, dst, dO) {  // Alg. 9
    if (z === 0) { setTypeAndClear(adrs, WOTS_HASH); put32(adrs, 20, i); wotsPkGen(C, adrs, dst, dO); return; }
    var stk = C.stk, o = z * 2 * C.n;
    xmssNode(C, 2 * i, z - 1, adrs, stk, o);
    xmssNode(C, 2 * i + 1, z - 1, adrs, stk, o + C.n);
    setTypeAndClear(adrs, TREE); put32(adrs, 24, z); put32(adrs, 28, i);
    thash(C, adrs, stk, o, 2, dst, dO);
  }
  function xmssSign(C, M, mo, idx, adrs, sig, so) {   // Alg. 10: SIG_XMSS = chữ ký WOTS+ || AUTH
    var p = C.p, n = C.n, ao = so + p.len * n, j;
    for (j = 0; j < p.hp; j++) xmssNode(C, (idx >>> j) ^ 1, j, adrs, sig, ao + j * n);
    setTypeAndClear(adrs, WOTS_HASH); put32(adrs, 20, idx);
    wotsSign(C, M, mo, adrs, sig, so);
  }
  function xmssPkFromSig(C, idx, sig, so, M, mo, adrs, dst, dO) {   // Alg. 11
    var p = C.p, n = C.n, nd = C.nd, hb = C.hb, ao = so + p.len * n, k;
    setTypeAndClear(adrs, WOTS_HASH); put32(adrs, 20, idx);
    wotsPkFromSig(C, sig, so, M, mo, adrs, nd, 0);
    setTypeAndClear(adrs, TREE); put32(adrs, 28, idx);
    for (k = 0; k < p.hp; k++) {
      put32(adrs, 24, k + 1); put32(adrs, 28, idx >>> (k + 1));
      if (((idx >>> k) & 1) === 0) { copyN(nd, 0, hb, 0, n); copyN(sig, ao + k * n, hb, n, n); }
      else { copyN(sig, ao + k * n, hb, 0, n); copyN(nd, 0, hb, n, n); }
      thash(C, adrs, hb, 0, 2, nd, 0);
    }
    copyN(nd, 0, dst, dO, n);
  }

  /* ---------- hypertree (Alg. 12-13); idx_tree đến 64 bit = (hi, lo) ---------- */
  function htSign(C, M, mo, tHi, tLo, leaf, sig, so) {
    var p = C.p, A = C.A, xs = (p.hp + p.len) * C.n, mask = (1 << p.hp) - 1, j;
    A.fill(0); setTree(A, tHi, tLo);
    xmssSign(C, M, mo, leaf, A, sig, so);
    xmssPkFromSig(C, leaf, sig, so, M, mo, A, C.rt, 0);
    for (j = 1; j < p.d; j++) {
      leaf = tLo & mask; tLo = (tLo >>> p.hp) | (tHi << (32 - p.hp)); tHi = tHi >>> p.hp;
      put32(A, 0, j); setTree(A, tHi, tLo);
      xmssSign(C, C.rt, 0, leaf, A, sig, so + j * xs);
      if (j < p.d - 1) xmssPkFromSig(C, leaf, sig, so + j * xs, C.rt, 0, A, C.rt, 0);
    }
  }
  function htVerify(C, M, mo, sig, so, tHi, tLo, leaf, pkRoot) {
    var p = C.p, A = C.A, xs = (p.hp + p.len) * C.n, mask = (1 << p.hp) - 1, j, ok = 0;
    A.fill(0); setTree(A, tHi, tLo);
    xmssPkFromSig(C, leaf, sig, so, M, mo, A, C.rt, 0);
    for (j = 1; j < p.d; j++) {
      leaf = tLo & mask; tLo = (tLo >>> p.hp) | (tHi << (32 - p.hp)); tHi = tHi >>> p.hp;
      put32(A, 0, j); setTree(A, tHi, tLo);
      xmssPkFromSig(C, leaf, sig, so + j * xs, C.rt, 0, A, C.rt, 0);
    }
    for (j = 0; j < C.n; j++) ok |= C.rt[j] ^ pkRoot[j];
    return ok === 0;
  }

  /* ---------- FORS (Alg. 14-17) ---------- */
  function forsSkGen(C, adrs, idx, dst, dO) {  // Alg. 14
    var B = C.B; B.set(adrs); setTypeAndClear(B, FORS_PRF); copyN(adrs, 20, B, 20, 4); put32(B, 28, idx);
    thash(C, B, C.skSeed, 0, 1, dst, dO);
  }
  function forsNode(C, i, z, adrs, dst, dO) {  // Alg. 15
    if (z === 0) {
      forsSkGen(C, adrs, i, C.lf, 0);
      put32(adrs, 24, 0); put32(adrs, 28, i);
      thash(C, adrs, C.lf, 0, 1, dst, dO);
      return;
    }
    var stk = C.stk, o = z * 2 * C.n;
    forsNode(C, 2 * i, z - 1, adrs, stk, o);
    forsNode(C, 2 * i + 1, z - 1, adrs, stk, o + C.n);
    put32(adrs, 24, z); put32(adrs, 28, i);
    thash(C, adrs, stk, o, 2, dst, dO);
  }
  function forsSign(C, md, adrs, sig, so) {    // Alg. 16: k × (sk || AUTH)
    var p = C.p, n = C.n, a = p.a, idx = C.dig, i, j, o;
    base2b(md, 0, a, p.k, idx, 0);
    for (i = 0; i < p.k; i++) {
      o = so + i * (a + 1) * n;
      forsSkGen(C, adrs, i * (1 << a) + idx[i], sig, o);
      for (j = 0; j < a; j++) forsNode(C, i * (1 << (a - j)) + ((idx[i] >>> j) ^ 1), j, adrs, sig, o + (j + 1) * n);
    }
  }
  function forsPkFromSig(C, sig, so, md, adrs, dst, dO) {   // Alg. 17
    var p = C.p, n = C.n, a = p.a, idx = C.dig, nd = C.nd, hb = C.hb, i, j, o, ti;
    base2b(md, 0, a, p.k, idx, 0);
    for (i = 0; i < p.k; i++) {
      o = so + i * (a + 1) * n; ti = i * (1 << a) + idx[i];
      put32(adrs, 24, 0); put32(adrs, 28, ti);
      thash(C, adrs, sig, o, 1, nd, 0);
      for (j = 0; j < a; j++) {
        ti = ti >>> 1; put32(adrs, 24, j + 1); put32(adrs, 28, ti);
        if (((idx[i] >>> j) & 1) === 0) { copyN(nd, 0, hb, 0, n); copyN(sig, o + (j + 1) * n, hb, n, n); }
        else { copyN(sig, o + (j + 1) * n, hb, 0, n); copyN(nd, 0, hb, n, n); }
        thash(C, adrs, hb, 0, 2, nd, 0);
      }
      copyN(nd, 0, C.tmp, i * n, n);
    }
    var B = C.B; B.set(adrs); setTypeAndClear(B, FORS_ROOTS); copyN(adrs, 20, B, 20, 4);
    thash(C, B, C.tmp, 0, p.k, dst, dO);
  }

  /* ---------- H_msg, PRF_msg (§11): SHAKE256, hoặc MGF1 / HMAC trên SHA-256 (n = 16) / SHA-512 ---------- */
  function sha2Of(p) { return p.n === 16 ? { f: S2.sha256, bs: 64 } : { f: S2.sha512, bs: 128 }; }
  function hmac(hf, key, msg) {
    var k0 = new Uint8Array(hf.bs), ip = new Uint8Array(hf.bs), op = new Uint8Array(hf.bs), i;
    k0.set(key.length > hf.bs ? hf.f(key) : key);
    for (i = 0; i < hf.bs; i++) { ip[i] = k0[i] ^ 0x36; op[i] = k0[i] ^ 0x5C; }
    return hf.f(cat([op, hf.f(cat([ip, msg]))]));
  }
  function mgf1(hf, seed, len) {
    var out = new Uint8Array(len), c, pos = 0, blk, sz = new Uint8Array(4), q;
    for (c = 0; pos < len; c++) {
      put32(sz, 0, c); blk = hf.f(cat([seed, sz]));
      for (q = 0; q < blk.length && pos < len; q++) out[pos++] = blk[q];
    }
    return out;
  }
  function prfMsg(p, skPrf, optRand, M) {
    if (p.shake) return KH.shake256(cat([skPrf, optRand, M]), p.n);
    return hmac(sha2Of(p), skPrf, cat([optRand, M])).slice(0, p.n);
  }
  function hMsg(p, R, pkSeed, pkRoot, M) {
    if (p.shake) return KH.shake256(cat([R, pkSeed, pkRoot, M]), p.m);
    var hf = sha2Of(p);
    return mgf1(hf, cat([R, pkSeed, hf.f(cat([R, pkSeed, pkRoot, M]))]), p.m);
  }
  function splitDigest(p, dg) {                // Alg. 19 bước 6-10: md, idx_tree (hi, lo), idx_leaf
    var o = p.mdBytes, hi = 0, lo = 0, leaf = 0, i, tb = p.treeBits;
    for (i = 0; i < p.treeBytes; i++) { hi = ((hi << 8) | (lo >>> 24)) >>> 0; lo = ((lo << 8) | dg[o + i]) >>> 0; }
    if (tb < 32) { hi = 0; lo = (lo & ((1 << tb) - 1)) >>> 0; }
    else if (tb < 64) hi = (hi & (Math.pow(2, tb - 32) - 1)) >>> 0;
    o += p.treeBytes;
    for (i = 0; i < p.leafBytes; i++) leaf = (leaf << 8) | dg[o + i];
    return { md: dg.subarray(0, p.mdBytes), hi: hi, lo: lo, leaf: leaf & ((1 << p.leafBits) - 1) };
  }
  function need(b, len, what) { if (!b || b.length !== len) throw new Error(what + ' phải dài ' + len + ' byte'); }

  /* ---------- Alg. 18-20 ---------- */
  function keygenInternal(name, skSeed, skPrf, pkSeed) {
    var p = P(name), n = p.n;
    need(skSeed, n, 'SK.seed'); need(skPrf, n, 'SK.prf'); need(pkSeed, n, 'PK.seed');
    var C = new Ctx(p, pkSeed, skSeed), A = C.A, pkRoot = new Uint8Array(n);
    put32(A, 0, p.d - 1);
    xmssNode(C, 0, p.hp, A, pkRoot, 0);
    return { pk: cat([pkSeed, pkRoot]), sk: cat([skSeed, skPrf, pkSeed, pkRoot]) };
  }
  function signInternal(name, M, sk, addrnd) {
    var p = P(name), n = p.n;
    need(sk, 4 * n, 'SK');
    var skSeed = sk.slice(0, n), skPrf = sk.slice(n, 2 * n), pkSeed = sk.slice(2 * n, 3 * n), pkRoot = sk.slice(3 * n);
    var optRand = addrnd == null ? pkSeed : addrnd;           // tất định: opt_rand = PK.seed
    need(optRand, n, 'addrnd');
    var C = new Ctx(p, pkSeed, skSeed), sig = new Uint8Array(p.sig), A = C.A;
    var R = prfMsg(p, skPrf, optRand, M);
    sig.set(R, 0);
    var dg = splitDigest(p, hMsg(p, R, pkSeed, pkRoot, M));
    setTree(A, dg.hi, dg.lo); setTypeAndClear(A, FORS_TREE); put32(A, 20, dg.leaf);
    forsSign(C, dg.md, A, sig, n);
    forsPkFromSig(C, sig, n, dg.md, A, C.pkf, 0);
    htSign(C, C.pkf, 0, dg.hi, dg.lo, dg.leaf, sig, (1 + p.k * (1 + p.a)) * n);
    return sig;
  }
  function verifyInternal(name, M, sig, pk) {
    var p = P(name), n = p.n;
    if (!sig || sig.length !== p.sig || !pk || pk.length !== 2 * n || !M) return false;
    var pkSeed = pk.slice(0, n), pkRoot = pk.slice(n), C = new Ctx(p, pkSeed, null), A = C.A;
    var dg = splitDigest(p, hMsg(p, sig.subarray(0, n), pkSeed, pkRoot, M));
    setTree(A, dg.hi, dg.lo); setTypeAndClear(A, FORS_TREE); put32(A, 20, dg.leaf);
    forsPkFromSig(C, sig, n, dg.md, A, C.pkf, 0);
    return htVerify(C, C.pkf, 0, sig, (1 + p.k * (1 + p.a)) * n, dg.hi, dg.lo, dg.leaf, pkRoot);
  }

  /* ---------- Alg. 22-25: M' như FIPS 204 (00 || |ctx| || ctx || M, hoặc 01 || |ctx| || ctx || OID || PH(M)) ---------- */
  var PH_ALIAS = { 'SHA-256': 'SHA2-256', 'SHA-512': 'SHA2-512', 'SHAKE128': 'SHAKE-128', 'SHAKE256': 'SHAKE-256' };
  function prepare(msg, ctx, ph) {
    if (!root.MLDSA) throw new Error('pqc-mldsa.js phải được nạp trước (dựng M\')');
    try { return root.MLDSA.prepare(msg, ctx, (ph && PH_ALIAS[ph]) || ph || null); } catch (e) { return null; }   // hàm pre-hash lạ -> ⊥
  }
  function sign(name, msg, ctx, sk, addrnd, ph) {
    ctx = ctx || new Uint8Array(0);
    if (ctx.length > 255) return null;
    var Mp = prepare(msg, ctx, ph);
    return Mp ? signInternal(name, Mp, sk, addrnd) : null;
  }
  function verify(name, msg, sig, ctx, pk, ph) {
    ctx = ctx || new Uint8Array(0);
    if (ctx.length > 255) return false;
    var Mp = prepare(msg, ctx, ph);
    return Mp ? verifyInternal(name, Mp, sig, pk) : false;
  }

  root.SLHDSA = {
    NAMES: NAMES.slice(),
    sizes: function (name) { var p = P(name); return { n: p.n, pk: p.pk, sk: p.sk, sig: p.sig, fast: p.fast }; },
    params: function (name) {
      var p = P(name);
      return { name: p.name, n: p.n, h: p.h, d: p.d, hp: p.hp, a: p.a, k: p.k, lgw: p.lgw, m: p.m, len: p.len,
               family: p.shake ? 'SHAKE' : 'SHA2', fast: p.fast, pk: p.pk, sk: p.sk, sig: p.sig };
    },
    keygenInternal: keygenInternal, signInternal: signInternal, verifyInternal: verifyInternal,
    sign: sign, verify: verify
  };
})(typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : globalThis));
