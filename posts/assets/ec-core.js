/* ec-core.js - đường cong elliptic trên trường nguyên tố, viết từ các chuẩn công khai: SP 800-186 (tham số miền P-192 ... P-521),
   FIPS 186-5 (sinh khoá A.2.1 / A.2.2, ECDSA mục 6.4), SP 800-56A r3 (kiểm tra khoá công khai 5.6.2.3.3, nguyên thuỷ ECC CDH 5.7.1.2),
   RFC 6979 (nonce tất định). Dùng BigInt; không che kênh bên - chỉ để học.
   Elliptic curves over prime fields, written from the public standards above. BigInt, not constant-time: for learning only.
   Original implementation for the ChiU·SoC site. Global: EC. */
(function (root) {
  'use strict';
  var B = BigInt, Z = B(0), ONE = B(1), TWO = B(2), THREE = B(3);

  /* ================================================================ số học modulo */
  function mod(a, m) { var r = a % m; return r < Z ? r + m : r; }
  function inv(a, m) {                                    // Euclid mở rộng; ném lỗi khi a ≡ 0
    a = mod(a, m);
    if (a === Z) throw new Error('inverse of 0');
    var t = Z, nt = ONE, r = m, nr = a, q, tmp;
    while (nr !== Z) { q = r / nr; tmp = t - q * nt; t = nt; nt = tmp; tmp = r - q * nr; r = nr; nr = tmp; }
    if (r !== ONE) throw new Error('not invertible');
    return mod(t, m);
  }
  function powmod(b, e, m) { var r = ONE; b = mod(b, m); while (e > Z) { if (e & ONE) r = r * b % m; b = b * b % m; e >>= ONE; } return r; }
  function bitlen(x) { return x === Z ? 0 : x.toString(2).length; }
  function hexToBig(h) { h = String(h).replace(/^0x/i, '').replace(/[\s:]/g, ''); if (!h) return Z; if (!/^[0-9a-fA-F]+$/.test(h)) throw new Error('not hex'); return B('0x' + h); }
  function bigToHex(x, bytes) { var s = x.toString(16); if (bytes) while (s.length < 2 * bytes) s = '0' + s; return s; }
  function bytesToBig(b) { var x = Z; for (var i = 0; i < b.length; i++) x = (x << B(8)) | B(b[i]); return x; }
  function bigToBytes(x, len) { var out = new Uint8Array(len); for (var i = len - 1; i >= 0; i--) { out[i] = Number(x & B(255)); x >>= B(8); } return out; }
  function jacobi(a, p) {                                  // chỉ để kiểm tra "x có trên đường cong không" trên trường nhỏ
    a = mod(a, p); var r = ONE, t;
    while (a !== Z) {
      while ((a & ONE) === Z) { a >>= ONE; t = mod(p, B(8)); if (t === THREE || t === B(5)) r = -r; }
      t = a; a = p; p = t;
      if (mod(a, B(4)) === THREE && mod(p, B(4)) === THREE) r = -r;
      a = mod(a, p);
    }
    return p === ONE ? r : Z;
  }

  /* ================================================================ đường cong: y^2 = x^3 + a x + b trên F_p */
  function curve(o) {
    var c = { name: o.name, p: o.p, a: mod(o.a, o.p), b: mod(o.b, o.p), n: o.n || null, G: o.gx !== undefined ? [o.gx, o.gy] : null, bits: o.bits || bitlen(o.p) };
    c.N = c.n ? bitlen(c.n) : null;                       // độ dài bit của bậc n (FIPS 186-5 mục 6.4.1 dùng N)
    c.bytes = (c.bits + 7) >> 3;
    c.disc = mod(B(4) * c.a * c.a * c.a + B(27) * c.b * c.b, c.p);   // 4a^3 + 27b^2 ≠ 0: không suy biến
    return c;
  }
  function H(h) { return B('0x' + h); }
  var CURVES = {
    'P-192': curve({ name: 'P-192', bits: 192, p: H('fffffffffffffffffffffffffffffffeffffffffffffffff'), a: B(-3),
      b: H('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'), n: H('ffffffffffffffffffffffff99def836146bc9b1b4d22831'),
      gx: H('188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'), gy: H('07192b95ffc8da78631011ed6b24cdd573f977a11e794811') }),
    'P-224': curve({ name: 'P-224', bits: 224, p: H('ffffffffffffffffffffffffffffffff000000000000000000000001'), a: B(-3),
      b: H('b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4'), n: H('ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d'),
      gx: H('b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21'), gy: H('bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34') }),
    'P-256': curve({ name: 'P-256', bits: 256, p: H('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'), a: B(-3),
      b: H('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'), n: H('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
      gx: H('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'), gy: H('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5') }),
    'P-384': curve({ name: 'P-384', bits: 384, p: (ONE << B(384)) - (ONE << B(128)) - (ONE << B(96)) + (ONE << B(32)) - ONE, a: B(-3),
      b: H('b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef'),
      n: H('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'),
      gx: H('aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7'),
      gy: H('3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f') }),
    'P-521': curve({ name: 'P-521', bits: 521, p: (ONE << B(521)) - ONE, a: B(-3),
      b: H('0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00'),
      n: H('01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409'),
      gx: H('00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66'),
      gy: H('011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650') })
  };
  var NAMES = ['P-192', 'P-224', 'P-256', 'P-384', 'P-521'];
  var STRENGTH = { 'P-192': 80, 'P-224': 112, 'P-256': 128, 'P-384': 192, 'P-521': 256 };   // SP 800-57 part 1 rev. 5, table 2
  function toy(p, a, b) { return curve({ name: 'toy', p: B(p), a: B(a), b: B(b) }); }

  /* ================================================================ luật nhóm affine (dây cung - tiếp tuyến), có vết */
  function onCurve(c, P) {
    if (P === null) return true;
    var x = P[0], y = P[1];
    if (x < Z || x >= c.p || y < Z || y >= c.p) return false;
    return mod(y * y - (x * x * x + c.a * x + c.b), c.p) === Z;
  }
  function neg(c, P) { return P === null ? null : [P[0], mod(-P[1], c.p)]; }
  function eq(P, Q) { return P === null || Q === null ? P === Q : P[0] === Q[0] && P[1] === Q[1]; }
  /* trả về {R, kind, lam, num, den, inv}: kind = ident | inf | dbl | add */
  function addTrace(c, P, Q) {
    if (P === null) return { R: Q, kind: 'ident' };
    if (Q === null) return { R: P, kind: 'ident' };
    var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1], num, den, iv, lam, kind;
    if (x1 === x2 && mod(y1 + y2, c.p) === Z) return { R: null, kind: 'inf' };
    if (x1 === x2) { num = mod(THREE * x1 * x1 + c.a, c.p); den = mod(TWO * y1, c.p); kind = 'dbl'; }
    else { num = mod(y2 - y1, c.p); den = mod(x2 - x1, c.p); kind = 'add'; }
    iv = inv(den, c.p); lam = num * iv % c.p;
    var x3 = mod(lam * lam - x1 - x2, c.p), y3 = mod(lam * (x1 - x3) - y1, c.p);
    return { R: [x3, y3], kind: kind, lam: lam, num: num, den: den, inv: iv };
  }
  function add(c, P, Q) { return addTrace(c, P, Q).R; }
  function dbl(c, P) { return addTrace(c, P, P).R; }

  /* ================================================================ Jacobian (X, Y, Z) ~ (X/Z^2, Y/Z^3): không nghịch đảo trong vòng lặp */
  function toJ(P) { return P === null ? null : [P[0], P[1], ONE]; }
  function fromJ(c, J) {
    if (J === null || J[2] === Z) return null;
    var zi = inv(J[2], c.p), zi2 = zi * zi % c.p;
    return [J[0] * zi2 % c.p, J[1] * zi2 % c.p * zi % c.p];
  }
  function dblJ(c, J) {                                   // công thức tổng quát theo a (cost 4M + 6S với a bất kỳ)
    if (J === null || J[1] === Z) return null;
    var p = c.p, X = J[0], Y = J[1], W = J[2], Y2 = Y * Y % p, S = mod(B(4) * X * Y2, p), Z2 = W * W % p,
      M = mod(THREE * X * X + c.a * Z2 % p * Z2, p), X3 = mod(M * M - TWO * S, p),
      Y3 = mod(M * (S - X3) - B(8) * Y2 * Y2, p), Z3 = mod(TWO * Y * W, p);
    return [X3, Y3, Z3];
  }
  function addJ(c, J1, J2) {
    if (J1 === null) return J2;
    if (J2 === null) return J1;
    var p = c.p, Z1 = J1[2], Z2 = J2[2], Z1s = Z1 * Z1 % p, Z2s = Z2 * Z2 % p,
      U1 = J1[0] * Z2s % p, U2 = J2[0] * Z1s % p, S1 = J1[1] * Z2s % p * Z2 % p, S2 = J2[1] * Z1s % p * Z1 % p;
    if (U1 === U2) return S1 === S2 ? dblJ(c, J1) : null;
    var Hh = mod(U2 - U1, p), R = mod(S2 - S1, p), H2 = Hh * Hh % p, H3 = H2 * Hh % p, U1H2 = U1 * H2 % p,
      X3 = mod(R * R - H3 - TWO * U1H2, p), Y3 = mod(R * (U1H2 - X3) - S1 * H3, p), Z3 = Hh * Z1 % p * Z2 % p;
    return [X3, Y3, Z3];
  }
  /* thang Montgomery: mỗi bit một cộng + một nhân đôi, cùng thứ tự dù bit là 0 hay 1 (Joye-Yen). R1 - R0 = P luôn luôn. */
  function mulLadder(c, k, P) {
    if (P === null || k === Z) return null;
    if (k < Z) throw new Error('negative scalar');
    var R0 = null, R1 = toJ(P), bits = k.toString(2), i;
    for (i = 0; i < bits.length; i++) {
      if (bits[i] === '1') { R0 = addJ(c, R0, R1); R1 = dblJ(c, R1); }
      else { R1 = addJ(c, R0, R1); R0 = dblJ(c, R0); }
    }
    return fromJ(c, R0);
  }
  /* nhân đôi-và-cộng trái sang phải: số phép cộng = số bit 1 (lộ k qua công suất / thời gian) */
  function mulDA(c, k, P) {
    if (P === null || k === Z) return null;
    var R = null, bits = k.toString(2), i;
    for (i = 0; i < bits.length; i++) { R = dblJ(c, R); if (bits[i] === '1') R = addJ(c, R, toJ(P)); }
    return fromJ(c, R);
  }
  var mul = mulLadder;
  /* vết từng bit (affine) cho đồ thị 3: hai thuật toán cạnh nhau */
  function mulTrace(c, k, P) {
    var bits = k.toString(2), da = [], lad = [], R = null, R0 = null, R1 = P, nd = 0, na = 0, i, bt;
    for (i = 0; i < bits.length; i++) {
      bt = bits[i]; R = add(c, R, R); nd++;
      if (bt === '1') { R = add(c, R, P); na++; }
      da.push({ bit: bt, op: bt === '1' ? 'DA' : 'D', R: R });
    }
    for (i = 0; i < bits.length; i++) {
      bt = bits[i];
      if (bt === '1') { R0 = add(c, R0, R1); R1 = add(c, R1, R1); }
      else { R1 = add(c, R0, R1); R0 = add(c, R0, R0); }
      lad.push({ bit: bt, R0: R0, R1: R1 });
    }
    return { k: k, bits: bits, da: da, daOps: { dbl: nd, add: na }, ladder: lad, ladderOps: { dbl: bits.length, add: bits.length }, kP: R };
  }
  /* u1 G + u2 Q cho xác minh (hai thang rồi cộng; "mẹo Shamir" là tối ưu phần cứng, kết quả như nhau) */
  function mul2(c, u1, P, u2, Q) { return add(c, mul(c, u1, P), mul(c, u2, Q)); }

  /* ================================================================ trường nhỏ: liệt kê điểm, bậc, quỹ đạo (đồ thị 2) */
  function enumerate(c) {                                 // mọi điểm affine, theo x rồi y; chỉ cho p nhỏ (≤ 1000)
    var pts = [], p = Number(c.p), x, y, rhs, yy;
    if (p > 1000) throw new Error('field too large to enumerate');
    for (x = 0; x < p; x++) {
      rhs = Number(mod(B(x) * B(x) * B(x) + c.a * B(x) + c.b, c.p));
      for (y = 0; y < p; y++) { yy = (y * y) % p; if (yy === rhs) pts.push([B(x), B(y)]); }
    }
    return pts;
  }
  function hasse(c, count) { var s = 2 * Math.sqrt(Number(c.p)), p1 = Number(c.p) + 1; return { lo: p1 - s, hi: p1 + s, ok: Math.abs(count - p1) <= s }; }
  function orbit(c, G, cap) {                             // G, 2G, ..., O (phần tử cuối là null); cap chặn vòng lặp
    var out = [], R = null, i;
    for (i = 0; i < (cap || 2000); i++) { R = add(c, R, G); out.push(R); if (R === null) return out; }
    return out;
  }
  function yOf(c, x) {                                    // các y với (x, y) trên đường cong (trường nhỏ): [] | [y] | [y1, y2]
    var rhs = mod(x * x * x + c.a * x + c.b, c.p), out = [], y;
    for (y = Z; y < c.p; y++) if (y * y % c.p === rhs) out.push(y);
    return out;
  }

  /* ================================================================ sinh khoá FIPS 186-5 A.2 */
  function keygenExtra(c, cbits) {                        // A.2.1: c có N + 64 bit; d = (c mod (n - 1)) + 1
    var d = mod(cbits, c.n - ONE) + ONE;
    return { d: d, Q: mul(c, d, c.G), method: 'A.2.1', c: cbits };
  }
  function keygenCandidate(c, cbits) {                    // A.2.2: c có N bit; loại nếu c > n - 2; d = c + 1
    if (cbits > c.n - TWO) return { reject: true, c: cbits, method: 'A.2.2' };
    var d = cbits + ONE;
    return { d: d, Q: mul(c, d, c.G), method: 'A.2.2', c: cbits };
  }
  function randomBits(nbits, rnd) {                       // rnd: hàm trả về Uint8Array ngẫu nhiên
    var nb = (nbits + 7) >> 3, b = rnd(nb), x = bytesToBig(b), extra = 8 * nb - nbits;
    return extra ? x >> B(extra) : x;
  }
  function keygen(c, method, rnd) {
    if (method === 'A.2.2') {
      for (var tries = 1; ; tries++) {
        var r = keygenCandidate(c, randomBits(c.N, rnd));
        if (!r.reject) { r.tries = tries; return r; }
      }
    }
    return keygenExtra(c, randomBits(c.N + 64, rnd));
  }
  function publicOf(c, d) { return mul(c, d, c.G); }
  function scalarOk(c, d) { return d >= ONE && d <= c.n - ONE; }

  /* ================================================================ kiểm tra khoá công khai đầy đủ (SP 800-56A r3 mục 5.6.2.3.3) */
  var PKV_STEPS = ['INFINITY', 'RANGE', 'NOT_ON_CURVE', 'ORDER'];
  function validate(c, Q, partial) {
    var steps = [];
    if (Q === null) { steps.push(['INFINITY', false]); return { ok: false, reason: 'INFINITY', steps: steps }; }
    steps.push(['INFINITY', true]);
    var inRange = Q[0] >= Z && Q[0] < c.p && Q[1] >= Z && Q[1] < c.p;
    steps.push(['RANGE', inRange]);
    if (!inRange) return { ok: false, reason: 'RANGE', steps: steps };
    var on = onCurve(c, Q);
    steps.push(['NOT_ON_CURVE', on]);
    if (!on) return { ok: false, reason: 'NOT_ON_CURVE', steps: steps };
    if (!partial) {
      var nQ = mul(c, c.n, Q) === null;                   // bước 4: n Q = O (với h = 1, mọi điểm trên đường cong đều có bậc n)
      steps.push(['ORDER', nQ]);
      if (!nQ) return { ok: false, reason: 'ORDER', steps: steps };
    }
    return { ok: true, reason: null, steps: steps };
  }

  /* ================================================================ ECC CDH (SP 800-56A r3 mục 5.7.1.2): Z = x(h d Q), h = 1 */
  function ecdh(c, d, Q) {
    var v = validate(c, Q, false);
    if (!v.ok) return { err: 'KEY_' + v.reason, pkv: v };
    if (!scalarOk(c, d)) return { err: 'SCALAR', pkv: v };
    var P = mul(c, d, Q);
    if (P === null) return { err: 'INFINITY', pkv: v };
    return { Z: P[0], P: P, pkv: v };
  }

  /* ================================================================ ECDSA (FIPS 186-5 mục 6.4) */
  function bits2int(c, h) {                               // mục 6.4.1 bước 2: min(N, 8·len) bit trái nhất của H(M)
    var e = bytesToBig(h), hb = 8 * h.length, shift = hb > c.N ? hb - c.N : 0;
    return { e: shift ? e >> B(shift) : e, hbits: hb, N: c.N, shift: shift };
  }
  function sign(c, d, e, k) {
    if (!scalarOk(c, k)) return { err: 'K_RANGE' };
    if (!scalarOk(c, d)) return { err: 'D_RANGE' };
    var R = mul(c, k, c.G), r = mod(R[0], c.n);
    if (r === Z) return { err: 'R_ZERO', R: R };
    var kinv = inv(k, c.n), s = kinv * mod(e + d * r, c.n) % c.n;
    if (s === Z) return { err: 'S_ZERO', R: R, r: r };
    return { r: r, s: s, R: R, kinv: kinv, e: e };
  }
  function verify(c, Q, e, r, s) {
    var t = {};
    if (!(r >= ONE && r <= c.n - ONE)) return { ok: false, reason: 'R_RANGE', trace: t };
    if (!(s >= ONE && s <= c.n - ONE)) return { ok: false, reason: 'S_RANGE', trace: t };
    var v = validate(c, Q, true);                         // kiểm tra một phần: O, phạm vi, trên đường cong
    if (!v.ok) return { ok: false, reason: 'KEY_' + v.reason, trace: t };
    t.w = inv(s, c.n); t.u1 = e * t.w % c.n; t.u2 = r * t.w % c.n;
    t.R = mul2(c, t.u1, c.G, t.u2, Q);
    if (t.R === null) return { ok: false, reason: 'INFINITY', trace: t };
    t.v = mod(t.R[0], c.n);
    return { ok: t.v === r, reason: t.v === r ? null : 'MISMATCH', trace: t };
  }

  /* ================================================================ RFC 6979: k tất định từ (d, H(M)) bằng HMAC_DRBG */
  function hmac(hashFn, blockLen, key, msg) {
    var k = key.length > blockLen ? hashFn(key) : key, kb = new Uint8Array(blockLen), i;
    kb.set(k);
    var ipad = new Uint8Array(blockLen + msg.length), opad;
    for (i = 0; i < blockLen; i++) ipad[i] = kb[i] ^ 0x36;
    ipad.set(msg, blockLen);
    var inner = hashFn(ipad);
    opad = new Uint8Array(blockLen + inner.length);
    for (i = 0; i < blockLen; i++) opad[i] = kb[i] ^ 0x5c;
    opad.set(inner, blockLen);
    return hashFn(opad);
  }
  function cat() { var n = 0, i, o, off = 0; for (i = 0; i < arguments.length; i++) n += arguments[i].length; o = new Uint8Array(n); for (i = 0; i < arguments.length; i++) { o.set(arguments[i], off); off += arguments[i].length; } return o; }
  /* hash = {fn: bytes -> digest, block: độ dài khối byte, len: độ dài digest}; trả về {k, rounds} */
  function rfc6979(c, d, h1, hash) {
    var hlen = hash.len, qlen = (c.N + 7) >> 3, V = new Uint8Array(hlen).fill(1), K = new Uint8Array(hlen), rounds = 0;
    var int2octets = function (x) { return bigToBytes(x, qlen); };
    var bits2octets = function (b) { return int2octets(mod(bits2int(c, b).e, c.n)); };
    var mac = function (key, m) { return hmac(hash.fn, hash.block, key, m); };
    K = mac(K, cat(V, Uint8Array.of(0), int2octets(d), bits2octets(h1)));
    V = mac(K, V);
    K = mac(K, cat(V, Uint8Array.of(1), int2octets(d), bits2octets(h1)));
    V = mac(K, V);
    for (;;) {
      var T = new Uint8Array(0);
      while (T.length < qlen) { V = mac(K, V); T = cat(T, V); }
      rounds++;
      var k = bits2int(c, T.subarray(0, qlen)).e;        // qlen byte -> lấy N bit trái nhất
      if (k >= ONE && k <= c.n - ONE) return { k: k, rounds: rounds };
      K = mac(K, cat(V, Uint8Array.of(0)));
      V = mac(K, V);
    }
  }

  /* ================================================================ tấn công: lặp nonce, lộ nonce */
  function nonceReuse(c, e1, s1, e2, s2, r) {              // cùng k -> cùng r; k = (e1 - e2)/(s1 - s2); d = (s1 k - e1)/r
    var ds = mod(s1 - s2, c.n);
    if (ds === Z) return { err: 'SAME_S' };
    var k = mod(e1 - e2, c.n) * inv(ds, c.n) % c.n, d = mod(s1 * k - e1, c.n) * inv(r, c.n) % c.n;
    return { k: k, d: d };
  }
  function leakedK(c, e, r, s, k) { return mod(s * k - e, c.n) * inv(r, c.n) % c.n; }

  /* hàm băm cho ECDSA / RFC 6979, lấy từ hai file dùng chung của trang (PQCSHA2: SHA-2; PQCHash: SHA-3); block = độ dài khối cho HMAC */
  var HASH_NAMES = ['SHA2-224', 'SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA2-512/224', 'SHA2-512/256', 'SHA3-224', 'SHA3-256', 'SHA3-384', 'SHA3-512'];
  function hash(name) {
    var S2 = root.PQCSHA2, S3 = root.PQCHash, t = {
      'SHA2-224': [S2 && S2.sha224, 64, 28], 'SHA2-256': [S2 && S2.sha256, 64, 32], 'SHA2-384': [S2 && S2.sha384, 128, 48], 'SHA2-512': [S2 && S2.sha512, 128, 64],
      'SHA2-512/224': [S2 && S2.sha512_224, 128, 28], 'SHA2-512/256': [S2 && S2.sha512_256, 128, 32],
      'SHA3-224': [S3 && S3.sha3_224, 144, 28], 'SHA3-256': [S3 && S3.sha3_256, 136, 32], 'SHA3-384': [S3 && S3.sha3_384, 104, 48], 'SHA3-512': [S3 && S3.sha3_512, 72, 64]
    }[name];
    if (!t || !t[0]) throw new Error('hash not available: ' + name);
    return { name: name, fn: t[0], block: t[1], len: t[2] };
  }

  root.EC = {
    CURVES: CURVES, NAMES: NAMES, STRENGTH: STRENGTH, HASH_NAMES: HASH_NAMES, hash: hash, toy: toy, curve: curve,
    mod: mod, inv: inv, powmod: powmod, jacobi: jacobi, bitlen: bitlen, hexToBig: hexToBig, bigToHex: bigToHex, bytesToBig: bytesToBig, bigToBytes: bigToBytes,
    onCurve: onCurve, neg: neg, eq: eq, addTrace: addTrace, add: add, dbl: dbl,
    toJ: toJ, fromJ: fromJ, dblJ: dblJ, addJ: addJ, mulLadder: mulLadder, mulDA: mulDA, mul: mul, mulTrace: mulTrace, mul2: mul2,
    enumerate: enumerate, hasse: hasse, orbit: orbit, yOf: yOf,
    keygenExtra: keygenExtra, keygenCandidate: keygenCandidate, keygen: keygen, publicOf: publicOf, scalarOk: scalarOk, randomBits: randomBits,
    PKV_STEPS: PKV_STEPS, validate: validate, ecdh: ecdh, bits2int: bits2int, sign: sign, verify: verify, hmac: hmac, rfc6979: rfc6979,
    nonceReuse: nonceReuse, leakedK: leakedK
  };
})(typeof window !== 'undefined' ? window : globalThis);
