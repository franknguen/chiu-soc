/* ML-KEM (NIST FIPS 203) — hiện thực JavaScript thuần, viết từ đặc tả.
   Mọi bảng hằng số được TÍNH khi nạp, không chép tay.
   Original implementation for the ChiU·SoC PQC demo page. */
(function (root) {
  'use strict';

  /* ---------- Keccak-f[1600] trên các nửa 32 bit ---------- */
  var RC_LO = new Int32Array(24), RC_HI = new Int32Array(24);
  (function () {                               // sinh hằng số vòng bằng LFSR
    var R = 1;
    for (var i = 0; i < 24; i++) {
      for (var j = 0; j < 7; j++) {
        R = ((R << 1) ^ ((R >> 7) * 0x71)) % 256;
        if (R & 2) {
          var p = (1 << j) - 1;                // 0,1,3,7,15,31,63
          if (p < 32) RC_LO[i] ^= (1 << p); else RC_HI[i] ^= (1 << (p - 32));
        }
      }
    }
  })();
  var RHO = new Int32Array(25);                // độ dịch rho, tính bằng bước (x,y)
  (function () {
    var x = 1, y = 0;
    for (var t = 0; t < 24; t++) {
      RHO[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;
      var nx = y, ny = (2 * x + 3 * y) % 5;
      x = nx; y = ny;
    }
  })();

  function keccakF(sl, sh) {
    var cl = new Int32Array(5), ch = new Int32Array(5);
    var bl = new Int32Array(25), bh = new Int32Array(25);
    for (var r = 0; r < 24; r++) {
      var x, y, i, lo, hi, n;
      for (x = 0; x < 5; x++) {
        cl[x] = sl[x] ^ sl[x + 5] ^ sl[x + 10] ^ sl[x + 15] ^ sl[x + 20];
        ch[x] = sh[x] ^ sh[x + 5] ^ sh[x + 10] ^ sh[x + 15] ^ sh[x + 20];
      }
      for (x = 0; x < 5; x++) {
        var p = (x + 4) % 5, q = (x + 1) % 5;
        var dl = cl[p] ^ (((cl[q] << 1) | (ch[q] >>> 31)) | 0);
        var dh = ch[p] ^ (((ch[q] << 1) | (cl[q] >>> 31)) | 0);
        for (y = 0; y < 25; y += 5) { sl[x + y] ^= dl; sh[x + y] ^= dh; }
      }
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) {
        i = x + 5 * y; n = RHO[i]; lo = sl[i]; hi = sh[i];
        var rl, rh;
        if (n === 0) { rl = lo; rh = hi; }
        else if (n < 32) { rl = (lo << n) | (hi >>> (32 - n)); rh = (hi << n) | (lo >>> (32 - n)); }
        else if (n === 32) { rl = hi; rh = lo; }
        else { n -= 32; rl = (hi << n) | (lo >>> (32 - n)); rh = (lo << n) | (hi >>> (32 - n)); }
        var j = y + 5 * ((2 * x + 3 * y) % 5);   // pi: B[y][2x+3y] <- rot(A[x][y])
        bl[j] = rl | 0; bh[j] = rh | 0;
      }
      for (y = 0; y < 25; y += 5) for (x = 0; x < 5; x++) {
        sl[x + y] = bl[x + y] ^ (~bl[(x + 1) % 5 + y] & bl[(x + 2) % 5 + y]);
        sh[x + y] = bh[x + y] ^ (~bh[(x + 1) % 5 + y] & bh[(x + 2) % 5 + y]);
      }
      sl[0] ^= RC_LO[r]; sh[0] ^= RC_HI[r];
    }
  }

  function Sponge(rate, pad) {
    this.rate = rate; this.pad = pad;
    this.sl = new Int32Array(25); this.sh = new Int32Array(25);
    this.buf = new Uint8Array(rate); this.n = 0; this.squeezing = false; this.pos = rate;
  }
  Sponge.prototype._xorBlock = function () {
    for (var i = 0; i < this.rate; i++) {
      var w = i >> 2, lane = i >> 3, half = (i >> 2) & 1, sh = (i & 3) * 8;
      if (half) this.sh[lane] ^= (this.buf[i] << sh); else this.sl[lane] ^= (this.buf[i] << sh);
      void w;
    }
    keccakF(this.sl, this.sh);
  };
  Sponge.prototype.absorb = function (data) {
    for (var i = 0; i < data.length; i++) {
      this.buf[this.n++] = data[i];
      if (this.n === this.rate) { this._xorBlock(); this.n = 0; }
    }
    return this;
  };
  Sponge.prototype._finish = function () {
    for (var i = this.n; i < this.rate; i++) this.buf[i] = 0;
    this.buf[this.n] ^= this.pad;
    this.buf[this.rate - 1] ^= 0x80;
    this._xorBlock();
    this.squeezing = true; this.pos = 0;
  };
  Sponge.prototype.squeeze = function (len) {
    if (!this.squeezing) this._finish();
    var out = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
      if (this.pos === this.rate) { keccakF(this.sl, this.sh); this.pos = 0; }
      var b = this.pos, lane = b >> 3, half = (b >> 2) & 1, sh = (b & 3) * 8;
      out[i] = ((half ? this.sh[lane] : this.sl[lane]) >>> sh) & 0xFF;
      this.pos++;
    }
    return out;
  };
  function hashOf(rate, pad, data, len) { return new Sponge(rate, pad).absorb(data).squeeze(len); }
  function sha3_256(d) { return hashOf(136, 0x06, d, 32); }
  function sha3_512(d) { return hashOf(72, 0x06, d, 64); }
  function shake256(d, l) { return hashOf(136, 0x1F, d, l); }
  function shake128xof(d) { return new Sponge(168, 0x1F).absorb(d); }

  /* ---------- tham số và bảng NTT ---------- */
  var Q = 3329, N = 256;
  var PARAMS = {
    'ML-KEM-512':  { k: 2, eta1: 3, eta2: 2, du: 10, dv: 4 },
    'ML-KEM-768':  { k: 3, eta1: 2, eta2: 2, du: 10, dv: 4 },
    'ML-KEM-1024': { k: 4, eta1: 2, eta2: 2, du: 11, dv: 5 }
  };
  function sizes(p) {
    return { ek: 384 * p.k + 32, dk: 768 * p.k + 96, ct: 32 * (p.du * p.k + p.dv), ss: 32 };
  }
  function powmod(b, e, m) { var r = 1; b %= m; while (e > 0) { if (e & 1) r = (r * b) % m; b = (b * b) % m; e >>= 1; } return r; }
  function bitrev7(i) { var r = 0; for (var j = 0; j < 7; j++) { r = (r << 1) | ((i >> j) & 1); } return r; }
  var ZETA = new Int16Array(128), GAMMA = new Int16Array(128);
  (function () {
    for (var i = 0; i < 128; i++) {
      ZETA[i] = powmod(17, bitrev7(i), Q);
      GAMMA[i] = powmod(17, 2 * bitrev7(i) + 1, Q);
    }
  })();

  /* ---------- số học đa thức ---------- */
  function ntt(f) {
    var a = Int16Array.from(f), i = 1, len, start, j, zeta, t;
    for (len = 128; len >= 2; len >>= 1) {
      for (start = 0; start < N; start += 2 * len) {
        zeta = ZETA[i++];
        for (j = start; j < start + len; j++) {
          t = (zeta * a[j + len]) % Q;
          a[j + len] = (a[j] - t + Q) % Q;
          a[j] = (a[j] + t) % Q;
        }
      }
    }
    return a;
  }
  function intt(f) {
    var a = Int16Array.from(f), i = 127, len, start, j, zeta, t;
    for (len = 2; len <= 128; len <<= 1) {
      for (start = 0; start < N; start += 2 * len) {
        zeta = ZETA[i--];
        for (j = start; j < start + len; j++) {
          t = a[j];
          a[j] = (t + a[j + len]) % Q;
          a[j + len] = (zeta * (a[j + len] - t + Q)) % Q;
        }
      }
    }
    for (j = 0; j < N; j++) a[j] = (a[j] * 3303) % Q;   // 3303 = 128^-1 mod q
    return a;
  }
  function mulNTT(f, g) {
    var h = new Int16Array(N), i, a0, a1, b0, b1, gm;
    for (i = 0; i < 128; i++) {
      a0 = f[2 * i]; a1 = f[2 * i + 1]; b0 = g[2 * i]; b1 = g[2 * i + 1]; gm = GAMMA[i];
      h[2 * i]     = (a0 * b0 + ((a1 * b1) % Q) * gm) % Q;
      h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q;
    }
    return h;
  }
  function padd(a, b) { var c = new Int16Array(N); for (var i = 0; i < N; i++) c[i] = (a[i] + b[i]) % Q; return c; }
  function psub(a, b) { var c = new Int16Array(N); for (var i = 0; i < N; i++) c[i] = (a[i] - b[i] + Q) % Q; return c; }

  /* ---------- mã hoá / nén ---------- */
  function byteEncode(f, d) {
    var out = new Uint8Array(32 * d), bit = 0, i, j, v;
    for (i = 0; i < N; i++) {
      v = f[i];
      for (j = 0; j < d; j++) { if ((v >> j) & 1) out[bit >> 3] |= (1 << (bit & 7)); bit++; }
    }
    return out;
  }
  function byteDecode(B, d) {
    var f = new Int16Array(N), bit = 0, i, j, v;
    for (i = 0; i < N; i++) {
      v = 0;
      for (j = 0; j < d; j++) { v |= ((B[bit >> 3] >> (bit & 7)) & 1) << j; bit++; }
      f[i] = (d === 12) ? v % Q : v;
    }
    return f;
  }
  function compress(x, d) {                      // round(2^d·x/q), làm tròn nửa lên
    return Math.floor((x * (1 << (d + 1)) + Q) / (2 * Q)) & ((1 << d) - 1);
  }
  function decompress(y, d) {                    // round(q·y/2^d)
    return Math.floor((2 * Q * y + (1 << d)) / (1 << (d + 1)));
  }
  function compressPoly(f, d) { var g = new Int16Array(N); for (var i = 0; i < N; i++) g[i] = compress(f[i], d); return g; }
  function decompressPoly(f, d) { var g = new Int16Array(N); for (var i = 0; i < N; i++) g[i] = decompress(f[i], d); return g; }

  /* ---------- lấy mẫu ---------- */
  function sampleNTT(seed32, j, i) {
    var inp = new Uint8Array(34); inp.set(seed32); inp[32] = j; inp[33] = i;
    var xof = shake128xof(inp), a = new Int16Array(N), n = 0, b, d1, d2;
    while (n < N) {
      b = xof.squeeze(3);
      d1 = b[0] + 256 * (b[1] & 0x0F);
      d2 = (b[1] >> 4) + 16 * b[2];
      if (d1 < Q) a[n++] = d1;
      if (d2 < Q && n < N) a[n++] = d2;
    }
    return a;
  }
  function samplePolyCBD(bytes, eta) {
    var f = new Int16Array(N), i, j, x, y, bit = 0;
    function nextBit() { var v = (bytes[bit >> 3] >> (bit & 7)) & 1; bit++; return v; }
    for (i = 0; i < N; i++) {
      x = 0; y = 0;
      for (j = 0; j < eta; j++) x += nextBit();
      for (j = 0; j < eta; j++) y += nextBit();
      f[i] = (x - y + Q) % Q;
    }
    return f;
  }
  function prf(eta, s, b) {
    var inp = new Uint8Array(33); inp.set(s); inp[32] = b;
    return shake256(inp, 64 * eta);
  }

  /* ---------- K-PKE ---------- */
  function cat(arrs) {
    var n = 0, i; for (i = 0; i < arrs.length; i++) n += arrs[i].length;
    var out = new Uint8Array(n), o = 0;
    for (i = 0; i < arrs.length; i++) { out.set(arrs[i], o); o += arrs[i].length; }
    return out;
  }
  function matrixA(rho, k) {
    var A = [], i, j;
    for (i = 0; i < k; i++) { A.push([]); for (j = 0; j < k; j++) A[i].push(sampleNTT(rho, j, i)); }
    return A;
  }
  function kpkeKeygen(p, d) {
    var k = p.k;
    var g = sha3_512(cat([d, new Uint8Array([k])]));      // (rho, sigma) = G(d || k)
    var rho = g.subarray(0, 32), sigma = g.subarray(32, 64);
    var A = matrixA(rho, k), nn = 0, i, j;
    var s = [], e = [];
    for (i = 0; i < k; i++) s.push(ntt(samplePolyCBD(prf(p.eta1, sigma, nn++), p.eta1)));
    for (i = 0; i < k; i++) e.push(ntt(samplePolyCBD(prf(p.eta1, sigma, nn++), p.eta1)));
    var t = [];
    for (i = 0; i < k; i++) {
      var acc = new Int16Array(N);
      for (j = 0; j < k; j++) acc = padd(acc, mulNTT(A[i][j], s[j]));
      t.push(padd(acc, e[i]));
    }
    var ekParts = [], dkParts = [];
    for (i = 0; i < k; i++) ekParts.push(byteEncode(t[i], 12));
    ekParts.push(rho);
    for (i = 0; i < k; i++) dkParts.push(byteEncode(s[i], 12));
    return { ek: cat(ekParts), dkPke: cat(dkParts) };
  }
  function kpkeEncrypt(p, ek, m, r) {
    var k = p.k, i, j;
    var t = [], rho = ek.subarray(384 * k, 384 * k + 32);
    for (i = 0; i < k; i++) t.push(byteDecode(ek.subarray(384 * i, 384 * (i + 1)), 12));
    var A = matrixA(rho, k), nn = 0;
    var y = [], e1 = [];
    for (i = 0; i < k; i++) y.push(ntt(samplePolyCBD(prf(p.eta1, r, nn++), p.eta1)));
    for (i = 0; i < k; i++) e1.push(samplePolyCBD(prf(p.eta2, r, nn++), p.eta2));
    var e2 = samplePolyCBD(prf(p.eta2, r, nn++), p.eta2);
    var u = [];
    for (i = 0; i < k; i++) {
      var acc = new Int16Array(N);
      for (j = 0; j < k; j++) acc = padd(acc, mulNTT(A[j][i], y[j]));   // A^T
      u.push(padd(intt(acc), e1[i]));
    }
    var mu = decompressPoly(byteDecode(m, 1), 1);
    var accv = new Int16Array(N);
    for (j = 0; j < k; j++) accv = padd(accv, mulNTT(t[j], y[j]));
    var v = padd(padd(intt(accv), e2), mu);
    var parts = [];
    for (i = 0; i < k; i++) parts.push(byteEncode(compressPoly(u[i], p.du), p.du));
    parts.push(byteEncode(compressPoly(v, p.dv), p.dv));
    return cat(parts);
  }
  function kpkeDecrypt(p, dkPke, c) {
    var k = p.k, i, j, off = 32 * p.du * k;
    var u = [];
    for (i = 0; i < k; i++)
      u.push(decompressPoly(byteDecode(c.subarray(32 * p.du * i, 32 * p.du * (i + 1)), p.du), p.du));
    var v = decompressPoly(byteDecode(c.subarray(off, off + 32 * p.dv), p.dv), p.dv);
    var s = [];
    for (i = 0; i < k; i++) s.push(byteDecode(dkPke.subarray(384 * i, 384 * (i + 1)), 12));
    var acc = new Int16Array(N);
    for (j = 0; j < k; j++) acc = padd(acc, mulNTT(s[j], ntt(u[j])));
    var w = psub(v, intt(acc));
    return byteEncode(compressPoly(w, 1), 1);
  }

  /* ---------- ML-KEM ---------- */
  function keygenInternal(p, d, z) {
    var r = kpkeKeygen(p, d);
    return { ek: r.ek, dk: cat([r.dkPke, r.ek, sha3_256(r.ek), z]) };
  }
  function encapsInternal(p, ek, m) {
    var g = sha3_512(cat([m, sha3_256(ek)]));
    var K = g.subarray(0, 32), r = g.subarray(32, 64);
    return { K: Uint8Array.from(K), ct: kpkeEncrypt(p, ek, m, r) };
  }
  function decapsInternal(p, dk, c) {
    var k = p.k;
    var dkPke = dk.subarray(0, 384 * k);
    var ek = dk.subarray(384 * k, 768 * k + 32);
    var h = dk.subarray(768 * k + 32, 768 * k + 64);
    var z = dk.subarray(768 * k + 64, 768 * k + 96);
    var mp = kpkeDecrypt(p, dkPke, c);
    var g = sha3_512(cat([mp, h]));
    var Kp = g.subarray(0, 32), rp = g.subarray(32, 64);
    var Kbar = shake256(cat([z, c]), 32);
    var cp = kpkeEncrypt(p, ek, mp, rp);
    var same = cp.length === c.length;
    if (same) for (var i = 0; i < c.length; i++) if (cp[i] !== c[i]) { same = false; break; }
    return { K: same ? Uint8Array.from(Kp) : Kbar, rejected: !same };
  }

  function randomBytes(n) {
    var a = new Uint8Array(n);
    if (root.crypto && root.crypto.getRandomValues) root.crypto.getRandomValues(a);
    else throw new Error('No secure RNG available');
    return a;
  }

  root.MLKEM = {
    PARAMS: PARAMS, sizes: sizes, randomBytes: randomBytes,
    paramsOf: function (name) { var p = PARAMS[name]; return { name: name, k: p.k, eta1: p.eta1, eta2: p.eta2, du: p.du, dv: p.dv }; },
    keygenInternal: keygenInternal, encapsInternal: encapsInternal, decapsInternal: decapsInternal,
    keygen: function (name) { var p = PARAMS[name]; return keygenInternal(p, randomBytes(32), randomBytes(32)); },
    encaps: function (name, ek) { var p = PARAMS[name]; return encapsInternal(p, ek, randomBytes(32)); },
    decaps: function (name, dk, ct) { return decapsInternal(PARAMS[name], dk, ct); },
    _hash: { sha3_256: sha3_256, sha3_512: sha3_512, shake256: shake256 }
  };
  /* tầng Keccak dùng chung cho ML-DSA */
  root.PQCHash = {
    sha3_256: sha3_256, sha3_512: sha3_512, shake256: shake256,
    shake128xof: shake128xof,
    shake256xof: function (d) { return new Sponge(136, 0x1F).absorb(d); },
    randomBytes: randomBytes
  };
})(typeof window !== 'undefined' ? window : globalThis);
