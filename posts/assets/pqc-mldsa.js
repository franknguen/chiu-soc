/* ML-DSA (NIST FIPS 204) — hiện thực JavaScript thuần, viết từ đặc tả.
   Dùng tầng Keccak của pqc-mlkem.js (PQCHash). Bảng NTT được tính khi nạp.
   Original implementation for the ChiU·SoC PQC demo page. */
(function (root) {
  'use strict';
  var H = root.PQCHash;
  if (!H) throw new Error('pqc-mlkem.js phải được nạp trước pqc-mldsa.js');

  var Q = 8380417, N = 256, D = 13;
  var PARAMS = {
    'ML-DSA-44': { k: 4, l: 4, eta: 2, tau: 39, lam: 128, gamma1: 1 << 17, gamma2: (Q - 1) / 88, omega: 80 },
    'ML-DSA-65': { k: 6, l: 5, eta: 4, tau: 49, lam: 192, gamma1: 1 << 19, gamma2: (Q - 1) / 32, omega: 55 },
    'ML-DSA-87': { k: 8, l: 7, eta: 2, tau: 60, lam: 256, gamma1: 1 << 19, gamma2: (Q - 1) / 32, omega: 75 }
  };
  function bitlen(x) { var n = 0; while (x > 0) { n++; x = Math.floor(x / 2); } return n; }
  function sizes(p) {
    var pk = 32 + 32 * p.k * (bitlen(Q - 1) - D);
    var sk = 128 + 32 * ((p.l + p.k) * bitlen(2 * p.eta) + D * p.k);
    var sig = p.lam / 4 + p.l * 32 * (1 + bitlen(p.gamma1 - 1)) + p.omega + p.k;
    return { pk: pk, sk: sk, sig: sig, beta: p.tau * p.eta };
  }

  /* ---------- NTT ---------- */
  function powmod(b, e, m) { var r = 1; b %= m; while (e > 0) { if (e & 1) r = (r * b) % m; b = (b * b) % m; e = Math.floor(e / 2); } return r; }
  function brv8(i) { var r = 0; for (var j = 0; j < 8; j++) r = (r << 1) | ((i >> j) & 1); return r; }
  var ZETA = new Int32Array(256);
  (function () { for (var i = 0; i < 256; i++) ZETA[i] = powmod(1753, brv8(i), Q); })();

  function norm(f) { var a = new Int32Array(N); for (var i = 0; i < N; i++) a[i] = ((f[i] % Q) + Q) % Q; return a; }
  function ntt(f) {
    var a = norm(f), m = 0, len, start, j, z, t;
    for (len = 128; len >= 1; len >>= 1) {
      for (start = 0; start < N; start += 2 * len) {
        z = ZETA[++m];
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
    var a = Int32Array.from(f), m = 256, len, start, j, z, t;
    for (len = 1; len < N; len <<= 1) {
      for (start = 0; start < N; start += 2 * len) {
        z = Q - ZETA[--m];
        for (j = start; j < start + len; j++) {
          t = a[j];
          a[j] = (t + a[j + len]) % Q;
          a[j + len] = (z * (t - a[j + len] + Q)) % Q;
        }
      }
    }
    var f256 = 8347681;                       // 256^-1 mod q
    for (j = 0; j < N; j++) a[j] = (a[j] * f256) % Q;
    return a;
  }
  function pmul(a, b) { var c = new Int32Array(N); for (var i = 0; i < N; i++) c[i] = (a[i] * b[i]) % Q; return c; }
  function padd(a, b) { var c = new Int32Array(N); for (var i = 0; i < N; i++) c[i] = (a[i] + b[i]) % Q; return c; }
  function psub(a, b) { var c = new Int32Array(N); for (var i = 0; i < N; i++) c[i] = (a[i] - b[i] + Q) % Q; return c; }
  function modpm(r, alpha) { var x = ((r % alpha) + alpha) % alpha; if (x > alpha / 2) x -= alpha; return x; }
  function infNorm(poly) { var m = 0, i, v; for (i = 0; i < N; i++) { v = Math.abs(modpm(poly[i], Q)); if (v > m) m = v; } return m; }
  function vecInfNorm(v) { var m = 0, i, t; for (i = 0; i < v.length; i++) { t = infNorm(v[i]); if (t > m) m = t; } return m; }

  /* ---------- làm tròn ---------- */
  function power2round(r) { var rp = ((r % Q) + Q) % Q, r0 = modpm(rp, 1 << D); return [(rp - r0) / (1 << D), r0]; }
  function decompose(r, g2) {
    var rp = ((r % Q) + Q) % Q, r0 = modpm(rp, 2 * g2), r1;
    if (rp - r0 === Q - 1) { r1 = 0; r0 = r0 - 1; } else { r1 = (rp - r0) / (2 * g2); }
    return [r1, r0];
  }
  function highBits(r, g2) { return decompose(r, g2)[0]; }
  function makeHint(z, r, g2) { return highBits(r, g2) !== highBits(((r + z) % Q + Q) % Q, g2) ? 1 : 0; }
  function useHint(h, r, g2) {
    var m = (Q - 1) / (2 * g2), d = decompose(r, g2), r1 = d[0], r0 = d[1];
    if (h === 1) return r0 > 0 ? (r1 + 1) % m : ((r1 - 1) % m + m) % m;
    return r1;
  }

  /* ---------- đóng gói bit ---------- */
  function BitWriter(len) { this.b = new Uint8Array(len); this.p = 0; }
  BitWriter.prototype.put = function (v, bits) {
    for (var i = 0; i < bits; i++) { if ((v >> i) & 1) this.b[this.p >> 3] |= (1 << (this.p & 7)); this.p++; }
  };
  function BitReader(buf) { this.b = buf; this.p = 0; }
  BitReader.prototype.get = function (bits) {
    var v = 0;
    for (var i = 0; i < bits; i++) { v |= ((this.b[this.p >> 3] >> (this.p & 7)) & 1) << i; this.p++; }
    return v >>> 0;
  };
  function simpleBitPack(w, b) { var bits = bitlen(b), o = new BitWriter(32 * bits), i; for (i = 0; i < N; i++) o.put(w[i], bits); return o.b; }
  function bitPack(w, a, b) { var bits = bitlen(a + b), o = new BitWriter(32 * bits), i; for (i = 0; i < N; i++) o.put(b - w[i], bits); return o.b; }
  function simpleBitUnpack(buf, b) { var bits = bitlen(b), r = new BitReader(buf), f = new Int32Array(N), i; for (i = 0; i < N; i++) f[i] = r.get(bits); return f; }
  function bitUnpack(buf, a, b) { var bits = bitlen(a + b), r = new BitReader(buf), f = new Int32Array(N), i; for (i = 0; i < N; i++) f[i] = b - r.get(bits); return f; }
  function cat(arrs) { var n = 0, i; for (i = 0; i < arrs.length; i++) n += arrs[i].length; var o = new Uint8Array(n), q = 0; for (i = 0; i < arrs.length; i++) { o.set(arrs[i], q); q += arrs[i].length; } return o; }

  /* ---------- lấy mẫu ---------- */
  function rejNTTPoly(seed34) {
    var xof = H.shake128xof(seed34), a = new Int32Array(N), j = 0, b, z;
    while (j < N) {
      b = xof.squeeze(3);
      z = b[0] + 256 * b[1] + 65536 * (b[2] & 0x7F);
      if (z < Q) a[j++] = z;
    }
    return a;
  }
  function rejBoundedPoly(seed66, eta) {
    var xof = H.shake256xof(seed66), a = new Int32Array(N), j = 0, b, i, z, half;
    while (j < N) {
      b = xof.squeeze(1)[0];
      for (i = 0; i < 2 && j < N; i++) {
        half = i === 0 ? (b & 0x0F) : (b >> 4);
        z = null;
        if (eta === 2) { if (half < 15) z = 2 - (half % 5); }
        else { if (half < 9) z = 4 - half; }
        if (z !== null) a[j++] = z;            // giữ dạng tâm đối xứng cho bitPack
      }
    }
    return a;
  }
  function expandA(p, rho) {
    var A = [], r, s, seed;
    for (r = 0; r < p.k; r++) {
      A.push([]);
      for (s = 0; s < p.l; s++) {
        seed = new Uint8Array(34); seed.set(rho); seed[32] = s; seed[33] = r;
        A[r].push(rejNTTPoly(seed));
      }
    }
    return A;
  }
  function expandS(p, rhop) {
    var s1 = [], s2 = [], i, seed;
    function mk(idx) { var sd = new Uint8Array(66); sd.set(rhop); sd[64] = idx & 0xFF; sd[65] = (idx >> 8) & 0xFF; return sd; }
    for (i = 0; i < p.l; i++) s1.push(rejBoundedPoly(mk(i), p.eta));
    for (i = 0; i < p.k; i++) s2.push(rejBoundedPoly(mk(i + p.l), p.eta));
    return [s1, s2];
  }
  function expandMask(p, rhopp, mu) {
    var c = 1 + bitlen(p.gamma1 - 1), y = [], r, sd, v;
    for (r = 0; r < p.l; r++) {
      sd = new Uint8Array(66); sd.set(rhopp);
      sd[64] = (mu + r) & 0xFF; sd[65] = ((mu + r) >> 8) & 0xFF;
      v = H.shake256(sd, 32 * c);
      y.push(bitUnpack(v, p.gamma1 - 1, p.gamma1));   // tâm đối xứng
    }
    return y;
  }
  function sampleInBall(p, ctilde) {
    var xof = H.shake256xof(ctilde), c = new Int32Array(N), s = xof.squeeze(8), i, j, bit = 0, b;
    for (i = N - p.tau; i < N; i++) {
      do { j = xof.squeeze(1)[0]; } while (j > i);
      c[i] = c[j];
      b = (s[bit >> 3] >> (bit & 7)) & 1; bit++;
      c[j] = b ? Q - 1 : 1;
    }
    return c;
  }

  /* ---------- mã hoá khoá / chữ ký ---------- */
  function pkEncode(p, rho, t1) {
    var parts = [rho], i, top = (1 << (bitlen(Q - 1) - D)) - 1;
    for (i = 0; i < p.k; i++) parts.push(simpleBitPack(t1[i], top));
    return cat(parts);
  }
  function pkDecode(p, pk) {
    var top = (1 << (bitlen(Q - 1) - D)) - 1, bits = bitlen(top), sz = 32 * bits;
    var rho = pk.subarray(0, 32), t1 = [], i;
    for (i = 0; i < p.k; i++) t1.push(simpleBitUnpack(pk.subarray(32 + sz * i, 32 + sz * (i + 1)), top));
    return [rho, t1];
  }
  function skEncode(p, rho, K, tr, s1, s2, t0) {
    var parts = [rho, K, tr], i, lim = 1 << (D - 1);
    for (i = 0; i < p.l; i++) parts.push(bitPack(s1[i], p.eta, p.eta));
    for (i = 0; i < p.k; i++) parts.push(bitPack(s2[i], p.eta, p.eta));
    for (i = 0; i < p.k; i++) parts.push(bitPack(t0[i], lim - 1, lim));
    return cat(parts);
  }
  function skDecode(p, sk) {
    var be = bitlen(2 * p.eta) * 32, lim = 1 << (D - 1), bt = bitlen(2 * lim - 1) * 32;
    var o = 128, rho = sk.subarray(0, 32), K = sk.subarray(32, 64), tr = sk.subarray(64, 128);
    var s1 = [], s2 = [], t0 = [], i;
    for (i = 0; i < p.l; i++) { s1.push(bitUnpack(sk.subarray(o, o + be), p.eta, p.eta)); o += be; }
    for (i = 0; i < p.k; i++) { s2.push(bitUnpack(sk.subarray(o, o + be), p.eta, p.eta)); o += be; }
    for (i = 0; i < p.k; i++) { t0.push(bitUnpack(sk.subarray(o, o + bt), lim - 1, lim)); o += bt; }
    return [rho, K, tr, s1, s2, t0];
  }
  function hintBitPack(p, h) {
    var y = new Uint8Array(p.omega + p.k), idx = 0, i, j;
    for (i = 0; i < p.k; i++) { for (j = 0; j < N; j++) if (h[i][j]) y[idx++] = j; y[p.omega + i] = idx; }
    return y;
  }
  function hintBitUnpack(p, y) {
    var h = [], idx = 0, i, j, first;
    for (i = 0; i < p.k; i++) h.push(new Uint8Array(N));
    for (i = 0; i < p.k; i++) {
      if (y[p.omega + i] < idx || y[p.omega + i] > p.omega) return null;
      first = idx;
      while (idx < y[p.omega + i]) {
        if (idx > first && y[idx - 1] >= y[idx]) return null;
        h[i][y[idx]] = 1; idx++;
      }
    }
    for (j = idx; j < p.omega; j++) if (y[j] !== 0) return null;
    return h;
  }
  function sigEncode(p, ctilde, z, h) {
    var parts = [ctilde], i;
    for (i = 0; i < p.l; i++) parts.push(bitPack(z[i], p.gamma1 - 1, p.gamma1));
    parts.push(hintBitPack(p, h));
    return cat(parts);
  }
  function sigDecode(p, sig) {
    var cl = p.lam / 4, zb = 32 * (1 + bitlen(p.gamma1 - 1)), o = cl, z = [], i;
    var ctilde = sig.subarray(0, cl);
    for (i = 0; i < p.l; i++) { z.push(bitUnpack(sig.subarray(o, o + zb), p.gamma1 - 1, p.gamma1)); o += zb; }
    return [ctilde, z, hintBitUnpack(p, sig.subarray(o))];
  }
  function w1Encode(p, w1) {
    var parts = [], top = (Q - 1) / (2 * p.gamma2) - 1, i;
    for (i = 0; i < p.k; i++) parts.push(simpleBitPack(w1[i], top));
    return cat(parts);
  }

  /* ---------- ML-DSA ---------- */
  function matVec(A, v, k, l) {
    var out = [], i, j, acc;
    for (i = 0; i < k; i++) { acc = new Int32Array(N); for (j = 0; j < l; j++) acc = padd(acc, pmul(A[i][j], v[j])); out.push(acc); }
    return out;
  }
  function keygenInternal(p, xi) {
    var seed = new Uint8Array(34); seed.set(xi); seed[32] = p.k; seed[33] = p.l;
    var h = H.shake256(seed, 128);
    var rho = h.subarray(0, 32), rhop = h.subarray(32, 96), K = h.subarray(96, 128);
    var A = expandA(p, rho), es = expandS(p, rhop), s1 = es[0], s2 = es[1], i, j;
    var s1h = s1.map(function (x) { return ntt(x); });
    var t = matVec(A, s1h, p.k, p.l).map(function (x, idx) { return padd(intt(x), s2[idx]); });
    var t1 = [], t0 = [];
    for (i = 0; i < p.k; i++) {
      var a1 = new Int32Array(N), a0 = new Int32Array(N);
      for (j = 0; j < N; j++) { var pr = power2round(t[i][j]); a1[j] = pr[0]; a0[j] = pr[1]; }
      t1.push(a1); t0.push(a0);
    }
    var pk = pkEncode(p, rho, t1);
    var tr = H.shake256(pk, 64);
    return { pk: pk, sk: skEncode(p, rho, K, tr, s1, s2, t0) };
  }
  function signInternal(p, sk, Mp, rnd) {
    var dec = skDecode(p, sk), rho = dec[0], K = dec[1], tr = dec[2], s1 = dec[3], s2 = dec[4], t0 = dec[5];
    var s1h = s1.map(ntt), s2h = s2.map(ntt), t0h = t0.map(ntt);
    var A = expandA(p, rho);
    var mu = H.shake256(cat([tr, Mp]), 64);
    var rhopp = H.shake256(cat([K, rnd, mu]), 64);
    var beta = p.tau * p.eta, kappa = 0, i, j, iters = 0;
    for (;;) {
      iters++;
      var y = expandMask(p, rhopp, kappa);
      var w = matVec(A, y.map(ntt), p.k, p.l).map(intt);
      var w1 = [];
      for (i = 0; i < p.k; i++) { var a = new Int32Array(N); for (j = 0; j < N; j++) a[j] = highBits(w[i][j], p.gamma2); w1.push(a); }
      var ctilde = H.shake256(cat([mu, w1Encode(p, w1)]), p.lam / 4);
      var ch = ntt(sampleInBall(p, ctilde));
      var cs1 = s1h.map(function (x) { return intt(pmul(ch, x)); });
      var cs2 = s2h.map(function (x) { return intt(pmul(ch, x)); });
      var z = [], r0 = [];
      for (i = 0; i < p.l; i++) z.push(padd(norm(y[i]), cs1[i]));
      for (i = 0; i < p.k; i++) { var d = psub(w[i], cs2[i]), a0 = new Int32Array(N); for (j = 0; j < N; j++) a0[j] = decompose(d[j], p.gamma2)[1]; r0.push(a0); }
      var r0max = 0; for (i = 0; i < p.k; i++) for (j = 0; j < N; j++) { var v = Math.abs(r0[i][j]); if (v > r0max) r0max = v; }
      kappa += p.l;
      if (vecInfNorm(z) >= p.gamma1 - beta || r0max >= p.gamma2 - beta) continue;
      var ct0 = t0h.map(function (x) { return intt(pmul(ch, x)); });
      var h = [], ones = 0;
      for (i = 0; i < p.k; i++) {
        var hi = new Uint8Array(N), wc = psub(w[i], cs2[i]);
        for (j = 0; j < N; j++) {
          var negct0 = (Q - ct0[i][j]) % Q;
          hi[j] = makeHint(negct0, (wc[j] + ct0[i][j]) % Q, p.gamma2);
          ones += hi[j];
        }
        h.push(hi);
      }
      if (vecInfNorm(ct0) >= p.gamma2 || ones > p.omega) continue;
      var zc = z.map(function (poly) { var a = new Int32Array(N); for (var t = 0; t < N; t++) a[t] = modpm(poly[t], Q); return a; });
      return { sig: sigEncode(p, ctilde, zc, h), iterations: iters };
    }
  }
  function verifyInternal(p, pk, Mp, sig) {
    var sz = sizes(p);
    if (pk.length !== sz.pk || sig.length !== sz.sig) return false;
    var pd = pkDecode(p, pk), rho = pd[0], t1 = pd[1];
    var sd = sigDecode(p, sig), ctilde = sd[0], z = sd[1], h = sd[2];
    if (h === null) return false;
    var beta = p.tau * p.eta;
    if (vecInfNorm(z) >= p.gamma1 - beta) return false;
    var A = expandA(p, rho);
    var mu = H.shake256(cat([H.shake256(pk, 64), Mp]), 64);
    var c = ntt(sampleInBall(p, ctilde));
    var i, j;
    var t1s = t1.map(function (poly) { var a = new Int32Array(N); for (j = 0; j < N; j++) a[j] = (poly[j] * (1 << D)) % Q; return ntt(a); });
    var az = matVec(A, z.map(ntt), p.k, p.l);
    var wapp = [];
    for (i = 0; i < p.k; i++) wapp.push(intt(psub(az[i], pmul(c, t1s[i]))));
    var w1 = [];
    for (i = 0; i < p.k; i++) { var a = new Int32Array(N); for (j = 0; j < N; j++) a[j] = useHint(h[i][j], wapp[i][j], p.gamma2); w1.push(a); }
    var ct2 = H.shake256(cat([mu, w1Encode(p, w1)]), p.lam / 4);
    if (ct2.length !== ctilde.length) return false;
    for (i = 0; i < ct2.length; i++) if (ct2[i] !== ctilde[i]) return false;
    return true;
  }
  /* ---------- M' : ML-DSA thuần (Alg. 2) và HashML-DSA (Alg. 4) ---------- */
  var PH = {                                   // arc của OID 2.16.840.1.101.3.4.2.<arc>
    'SHA2-256':  { arc: 1,  fn: function (m) { return root.PQCSHA2.sha256(m); } },
    'SHA2-512':  { arc: 3,  fn: function (m) { return root.PQCSHA2.sha512(m); } },
    'SHA3-256':  { arc: 8,  fn: function (m) { return H.sha3_256(m); } },
    'SHA3-512':  { arc: 10, fn: function (m) { return H.sha3_512(m); } },
    'SHAKE-128': { arc: 11, fn: function (m) { return H.shake128xof(m).squeeze(32); } },
    'SHAKE-256': { arc: 12, fn: function (m) { return H.shake256(m, 64); } }
  };
  function oidDer(arc) { return new Uint8Array([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, arc]); }
  function prepare(msg, ctx, ph) {
    ctx = ctx || new Uint8Array(0);
    if (ctx.length > 255) throw new Error('ctx > 255 byte');
    if (!ph || ph === 'none')
      return cat([new Uint8Array([0, ctx.length]), ctx, msg]);
    var e = PH[ph];
    if (!e) throw new Error('hàm pre-hash không hỗ trợ: ' + ph);
    return cat([new Uint8Array([1, ctx.length]), ctx, oidDer(e.arc), e.fn(msg)]);
  }

  root.MLDSA = {
    PARAMS: PARAMS, sizes: sizes, prepare: prepare,
    keygenInternal: keygenInternal, signInternal: signInternal, verifyInternal: verifyInternal,
    PH_NAMES: Object.keys(PH), oidDer: oidDer,
    keygen: function (name, seed) { return keygenInternal(PARAMS[name], seed || H.randomBytes(32)); },
    sign: function (name, sk, msg, ctx, ph, rnd) {
      return signInternal(PARAMS[name], sk, prepare(msg, ctx, ph), rnd || H.randomBytes(32));
    },
    signDet: function (name, sk, msg, ctx, ph) {
      return signInternal(PARAMS[name], sk, prepare(msg, ctx, ph), new Uint8Array(32));
    },
    verify: function (name, pk, msg, sig, ctx, ph) {
      return verifyInternal(PARAMS[name], pk, prepare(msg, ctx, ph), sig);
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);
