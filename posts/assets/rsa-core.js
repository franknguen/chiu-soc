/* RSA cho phòng thí nghiệm của bài viết — BigInt, không đụng tới DOM, chạy được trong Web Worker.
   Viết từ văn bản chuẩn: FIPS 186-5 (Phụ lục A.1.1, A.1.3, B.3.1, Bảng B.1, Phụ lục C.1, mục 5.4), SP 800-56B r2
   (mục 7.1, Phụ lục D) và RFC 8017 (mục 5, 7.1, 8, 9, B.2.1).
   Bit ngẫu nhiên khi sinh khoá lấy từ một bộ sinh TẤT ĐỊNH, ghi rõ trên trang để ai cũng tái tạo được khoá:
   khối thứ j = SHAKE256(seed || I2OSP(j, 4)), lấy nbits bit đầu. Đây KHÔNG phải DRBG được NIST phê duyệt.
   Mã để học: thời gian chạy phụ thuộc dữ liệu, khoá nằm trong bộ nhớ JavaScript.
   Original implementation for the ChiU·SoC RSA lab. */
(function (root) {
  'use strict';
  var PH = root.PQCHash, S2 = root.PQCSHA2;
  function Err(code, info) { var e = new Error(code); e.code = code; if (info) e.info = info; return e; }

  /* ================================================================ số nguyên lớn và chuỗi byte */
  function hexToBig(s) {
    s = String(s).replace(/\s+/g, '').replace(/^0x/i, '');
    if (!s) return 0n;
    if (!/^[0-9a-fA-F]+$/.test(s)) throw Err('HEX');
    return BigInt('0x' + s);
  }
  function bigToHex(x, nbytes) {
    var h = x.toString(16);
    if (nbytes !== undefined) {
      if (h.length > 2 * nbytes) throw Err('I2OSP');
      while (h.length < 2 * nbytes) h = '0' + h;
    } else if (h.length % 2) h = '0' + h;
    return h;
  }
  function bytesToHex(b) { var s = ''; for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16); return s; }
  function hexToBytes(h) {
    h = String(h).replace(/\s+/g, '').replace(/^0x/i, '');
    if (h.length % 2) throw Err('HEX_ODD');
    if (!/^[0-9a-fA-F]*$/.test(h)) throw Err('HEX');
    var o = new Uint8Array(h.length / 2);
    for (var i = 0; i < o.length; i++) o[i] = parseInt(h.substr(2 * i, 2), 16);
    return o;
  }
  function os2ip(b) { return b.length ? BigInt('0x' + bytesToHex(b)) : 0n; }        // RFC 8017 4.2
  function i2osp(x, len) { if (x < 0n) throw Err('I2OSP'); return hexToBytes(bigToHex(x, len)); }   // RFC 8017 4.1
  function bitLen(x) {
    if (x <= 0n) return 0;
    var h = x.toString(16);
    return (h.length - 1) * 4 + (32 - Math.clz32(parseInt(h[0], 16)));
  }
  function byteLen(x) { return (bitLen(x) + 7) >> 3; }
  function cat(list) {
    var n = 0, i, o, off = 0;
    for (i = 0; i < list.length; i++) n += list[i].length;
    o = new Uint8Array(n);
    for (i = 0; i < list.length; i++) { o.set(list[i], off); off += list[i].length; }
    return o;
  }
  function xor(a, b) { var o = new Uint8Array(a.length); for (var i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; }
  function same(a, b) { if (a.length !== b.length) return false; for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }
  function popcount(x) { var s = x.toString(2), c = 0; for (var i = 0; i < s.length; i++) if (s.charCodeAt(i) === 49) c++; return c; }

  function gcd(a, b) { if (a < 0n) a = -a; if (b < 0n) b = -b; while (b) { var t = a % b; a = b; b = t; } return a; }
  function lcm(a, b) { return a / gcd(a, b) * b; }
  function mod(a, m) { var r = a % m; return r < 0n ? r + m : r; }
  function modInv(a, m) {                                   // Euclid mở rộng
    var r0 = mod(a, m), r1 = m, s0 = 1n, s1 = 0n, q, t;
    while (r1) { q = r0 / r1; t = r0 - q * r1; r0 = r1; r1 = t; t = s0 - q * s1; s0 = s1; s1 = t; }
    if (r0 !== 1n) throw Err('NOT_INVERTIBLE', { g: r0 });
    return mod(s0, m);
  }
  function isqrt(n) {                                       // phần nguyên của căn bậc hai (Newton)
    if (n < 2n) return n;
    var x = 1n << BigInt((bitLen(n) >> 1) + 1), y;
    while (true) { y = (x + n / x) >> 1n; if (y >= x) return x; x = y; }
  }

  /* bình phương-và-nhân từ trái sang phải: bắt đầu bằng bit cao nhất, mỗi bit sau: bình phương, bit 1 thì nhân thêm */
  function modPow(b, e, n) {
    if (n === 1n) return 0n;
    if (e === 0n) return 1n;
    b = mod(b, n);
    var s = e.toString(2), x = b;
    for (var i = 1; i < s.length; i++) { x = x * x % n; if (s.charCodeAt(i) === 49) x = x * b % n; }
    return x;
  }
  /* cùng phép tính, có ghi lại: số lần bình phương S = len(e) - 1, số lần nhân M = (số bit 1 của e) - 1 */
  function modPowTrace(b, e, n, keep) {
    keep = keep || 8;
    b = mod(b, n);
    var s = e.toString(2), x = b, S = 0, M = 0, steps = [], sq;
    for (var i = 1; i < s.length; i++) {
      x = x * x % n; S++; sq = x;
      if (s.charCodeAt(i) === 49) { x = x * b % n; M++; }
      if (i <= keep || i > s.length - 1 - 3) steps.push({ i: i, bit: s[i], sq: sq, x: x });
    }
    return { r: e === 0n ? 1n % n : x, S: S, M: M, bits: s.length, steps: steps };
  }
  /* thang Montgomery: mỗi bit đúng một phép nhân và một phép bình phương, bất kể bit là 0 hay 1 */
  function modPowLadder(b, e, n) {
    var R0 = 1n % n, R1 = mod(b, n), s = e.toString(2), ops = 0;
    for (var i = 0; i < s.length; i++) {
      if (s.charCodeAt(i) === 49) { R0 = R0 * R1 % n; R1 = R1 * R1 % n; } else { R1 = R0 * R1 % n; R0 = R0 * R0 % n; }
      ops += 2;
    }
    return { r: R0, ops: ops };
  }

  /* Montgomery (1985): R = 2^(32k) với k = số từ 32 bit của n; n0' = -n^-1 mod 2^32 (hằng số của mạch theo từ);
     n' = -n^-1 mod R; R^2 mod n để đưa một số vào miền Montgomery: REDC(a * R^2) = a * R mod n. */
  function montConst(n) {
    if (n % 2n === 0n) throw Err('EVEN_MODULUS');
    var k = (bitLen(n) + 31) >> 5, kb = BigInt(32 * k), R = 1n << kb, W = 1n << 32n;
    return { k: k, R: R, kbits: 32 * k, n0p: W - modInv(n % W, W), np: R - modInv(n, R), R2: R * R % n };
  }
  function redc(T, n, mc) {
    var mask = mc.R - 1n, m = ((T & mask) * mc.np) & mask, u = (T + m * n) >> BigInt(mc.kbits);
    return u >= n ? u - n : u;
  }
  function montPow(b, e, n) {
    var mc = montConst(n), s = e.toString(2), xb = redc(mod(b, n) * mc.R2, n, mc), acc = xb;
    for (var i = 1; i < s.length; i++) { acc = redc(acc * acc, n, mc); if (s.charCodeAt(i) === 49) acc = redc(acc * xb, n, mc); }
    return redc(acc, n, mc);
  }

  /* ================================================================ bảng của chuẩn, tính khi nạp */
  /* FIPS 186-5 Phụ lục C.1, công thức (1) và (2): t nhỏ nhất để p_{k,t} <= p_target với một M nào đó */
  function c1Rounds(k, log2pt) {
    var pt = Math.pow(2, log2pt), c = 8 * (Math.PI * Math.PI - 6) / 3, mmax = Math.floor(2 * Math.sqrt(k - 1) - 1), t, M, m;
    var inner = [];
    for (m = 3; m <= mmax; m++) { var s = 0; for (var j = 2; j <= m; j++) s += Math.pow(2, -(j + (k - 1) / j)); inner[m] = s; }
    for (t = 1; t <= -log2pt / 2; t++) {
      var acc = 0;
      for (M = 3; M <= mmax; M++) {
        acc += Math.pow(2, M - (M - 1) * t) * inner[M];
        var p = 2.00743 * Math.LN2 * k * (Math.pow(2, -2 - M * t) + c * 0.25 * acc);
        if (p <= pt) return t;
      }
    }
    return Math.floor(-log2pt / 2);
  }
  /* Bảng B.1 (p và q 1024 / 1536 / 2048 bit) với xác suất lỗi khớp độ mạnh an ninh; cỡ chỉ-để-thử dùng C.1 với 2^-100 */
  var TABLE_B1 = { 1024: { '-100': 4, '-112': 5 }, 1536: { '-100': 3, '-128': 4 }, 2048: { '-100': 2, '-144': 4 } };
  var MR_TARGET = { 512: -100, 1024: -100, 2048: -112, 3072: -128, 4096: -144 };
  var ROUNDS = {};
  [512, 1024, 2048, 3072, 4096].forEach(function (nl) {
    var k = nl / 2, row = TABLE_B1[k];
    ROUNDS[nl] = row ? { t: row[String(MR_TARGET[nl])], src: 'B.1', perr: MR_TARGET[nl] } : { t: c1Rounds(k, MR_TARGET[nl]), src: 'C.1', perr: MR_TARGET[nl] };
  });
  function mrRounds(nlen) { return ROUNDS[nlen] || { t: c1Rounds(nlen / 2, -100), src: 'C.1', perr: -100 }; }
  /* SP 800-56B r2 Phụ lục D: độ mạnh ước lượng E và ES = bội số của 8 gần nhất */
  function strength(nbits) {
    var x = nbits * Math.LN2, E = (1.923 * Math.cbrt(x) * Math.cbrt(Math.log(x) * Math.log(x)) - 4.69) / Math.LN2;
    return { E: E, ES: 8 * Math.round(E / 8) };
  }
  /* cận dưới của p, q: ceil(sqrt(2) * 2^(nlen/2 - 1)) = isqrt(2^(nlen-1)) + 1 (2^(nlen-1) không phải số chính phương) */
  function lowerBound(nlen) { return isqrt(1n << BigInt(nlen - 1)) + 1n; }

  /* chia thử (B.3: giới hạn L trong khoảng 10^3 … 10^5; ở đây L = 10 000), số nguyên tố tính bằng sàng khi nạp */
  var TD_LIMIT = 10000, SMALL = [], GROUPS = [];
  (function () {
    var s = new Uint8Array(TD_LIMIT + 1), i, j;
    for (i = 2; i <= TD_LIMIT; i++) if (!s[i]) { SMALL.push(i); for (j = i * i; j <= TD_LIMIT; j += i) s[j] = 1; }
    var g = [], prod = 1;
    SMALL.forEach(function (p) {
      if (prod * p > 9007199254740991) { GROUPS.push({ big: BigInt(prod), ps: g }); g = []; prod = 1; }
      g.push(p); prod *= p;
    });
    if (g.length) GROUPS.push({ big: BigInt(prod), ps: g });
  })();
  function trialDivisor(w) {                                // số nguyên tố nhỏ nhất ≤ L chia hết w (0 nếu không có, hoặc w chính là nó)
    for (var i = 0; i < GROUPS.length; i++) {
      var r = Number(w % GROUPS[i].big), ps = GROUPS[i].ps;
      for (var j = 0; j < ps.length; j++) if (r % ps[j] === 0) return w === BigInt(ps[j]) ? 0 : ps[j];
    }
    return 0;
  }

  /* bộ sinh tất định của trang: khối j = SHAKE256(seed || I2OSP(j, 4)), giá trị = nbits bit đầu */
  function Stream(seed) { this.seed = seed; this.ctr = 0; }
  Stream.prototype.draw = function (nbits) {
    var L = (nbits + 7) >> 3, inp = new Uint8Array(this.seed.length + 4), c = this.ctr++;
    inp.set(this.seed, 0);
    inp[this.seed.length] = (c >>> 24) & 255; inp[this.seed.length + 1] = (c >>> 16) & 255;
    inp[this.seed.length + 2] = (c >>> 8) & 255; inp[this.seed.length + 3] = c & 255;
    return os2ip(PH.shake256(inp, L)) >> BigInt(8 * L - nbits);
  };

  /* FIPS 186-5 B.3.1 Miller-Rabin; cơ số b là chuỗi wlen bit từ bộ sinh, rút lại khi b <= 1 hoặc b >= w - 1 */
  function millerRabin(w, t, g) {
    if (w < 5n) return { prime: w === 2n || w === 3n, rounds: 0, draws: 0 };
    if (w % 2n === 0n) return { prime: false, rounds: 0, draws: 0 };
    var a = 0, m = w - 1n, wlen = bitLen(w), draws = 0, i, j, b, z, wm1 = w - 1n;
    while (m % 2n === 0n) { m >>= 1n; a++; }
    for (i = 1; i <= t; i++) {
      do { b = g.draw(wlen); draws++; } while (b <= 1n || b >= wm1);
      z = modPow(b, m, w);
      if (z === 1n || z === wm1) continue;
      var ok = false;
      for (j = 1; j < a; j++) {
        z = z * z % w;
        if (z === wm1) { ok = true; break; }
        if (z === 1n) break;
      }
      if (!ok) return { prime: false, rounds: i, draws: draws };
    }
    return { prime: true, rounds: t, draws: draws };
  }

  /* A.1.3 bước 4 (p) và bước 5 (q): rút nlen/2 bit, làm lẻ, cận dưới, |p - q| (chỉ với q), gcd(x - 1, e), chia thử, M-R */
  function genPrime(g, nlen, e, t, other) {
    var half = nlen / 2, low = lowerBound(nlen), close = 1n << BigInt(half - 100), em1, x;
    var st = { draws: 0, lb: 0, close: 0, gcd: 0, td: 0, mr: 0, mrRounds: 0, baseDraws: 0, i: 0 }, cap = (other === undefined ? 5 : 10) * nlen;
    while (true) {
      x = g.draw(half); st.draws++;
      if (x % 2n === 0n) x += 1n;                           // 4.3 / 5.3
      if (x < low) { st.lb++; continue; }                   // 4.4 / 5.4
      if (other !== undefined) {                            // 5.5
        var dd = other > x ? other - x : x - other;
        if (dd <= close) { st.close++; continue; }
      }
      em1 = x - 1n;
      if (gcd(em1, e) !== 1n) st.gcd++;                     // 4.5 / 5.6
      else if (trialDivisor(x)) st.td++;
      else {
        var r = millerRabin(x, t, g);
        st.mrRounds += r.rounds; st.baseDraws += r.draws;
        if (r.prime) return { x: x, st: st };
        st.mr++;
      }
      st.i++;                                               // 4.6 / 5.7
      if (st.i >= cap) throw Err('FAILURE', { which: other === undefined ? 'p' : 'q' });   // 4.7 / 5.8
    }
  }
  function checkE(e) {
    if (e % 2n === 0n) throw Err('E_EVEN');
    if (!(e > 65536n && e < (1n << 256n))) throw Err('E_RANGE');
  }
  function keygen(nlen, e, seed) {
    if (nlen % 2 || nlen < 512 || nlen > 8192) throw Err('NLEN');
    checkE(e);
    var t = mrRounds(nlen).t, g = new Stream(seed), restarts = 0, P, Q, lam, d;
    while (true) {
      P = genPrime(g, nlen, e, t);
      Q = genPrime(g, nlen, e, t, P.x);
      lam = lcm(P.x - 1n, Q.x - 1n);
      d = modInv(e, lam);
      if (d > (1n << BigInt(nlen / 2))) break;              // A.1.1 3(a): rất hiếm khi d <= 2^(nlen/2) - khi đó sinh lại
      restarts++;
    }
    var key = fromPQ(P.x, Q.x, e);
    key.statsP = P.st; key.statsQ = Q.st; key.restarts = restarts; key.ctr = g.ctr; key.rounds = t;
    return key;
  }
  /* khoá từ p, q, e cho trước (kiểu ACVP RSA-KeyGen): d = e^-1 mod lambda(n), dP, dQ, qInv */
  function fromPQ(p, q, e) {
    var lam = lcm(p - 1n, q - 1n), phi = (p - 1n) * (q - 1n), d = modInv(e, lam);
    return { n: p * q, e: e, d: d, p: p, q: q, dP: d % (p - 1n), dQ: d % (q - 1n), qInv: modInv(q, p), lam: lam, phi: phi };
  }
  /* kiểm tra số nguyên tố khi thẩm định khoá: chia thử rồi M-R, cơ số rút từ SHAKE256("RSA lab primality check" || w || j) */
  var CHECK_TAG = [82, 83, 65, 32, 108, 97, 98, 32, 112, 114, 105, 109, 97, 108, 105, 116, 121, 32, 99, 104, 101, 99, 107];
  function primality(w, t) {
    if (w < 2n) return { prime: false, td: 0, rounds: 0 };
    if (w <= BigInt(TD_LIMIT)) return { prime: SMALL.indexOf(Number(w)) >= 0, td: 0, rounds: 0, small: true };
    var td = trialDivisor(w);
    if (td) return { prime: false, td: td, rounds: 0 };
    var r = millerRabin(w, t, new Stream(cat([new Uint8Array(CHECK_TAG), i2osp(w, byteLen(w))])));
    return { prime: r.prime, td: 0, rounds: r.rounds };
  }
  /* các điều kiện của FIPS 186-5 A.1.1 / A.1.3 cho một khoá; mỗi mục true / false */
  function checkKey(p, q, e, d, nlen) {
    var half = BigInt(nlen / 2), low = lowerBound(nlen), lam = lcm(p - 1n, q - 1n), inv = gcd(e, lam) === 1n, t = mrRounds(nlen).t;
    if (d === null || d === undefined) d = inv ? modInv(e, lam) : 0n;
    var pp = primality(p, t), qp = primality(q, t);
    return {
      rows: {
        e_odd: e % 2n === 1n, e_range: e > 65536n && e < (1n << 256n), nlen_ok: nlen >= 2048,
        p_low: p >= low, q_low: q >= low, p_high: p < (1n << half), q_high: q < (1n << half),
        p_gcd: gcd(p - 1n, e) === 1n, q_gcd: gcd(q - 1n, e) === 1n, p_prime: pp.prime, q_prime: qp.prime,
        pq_dist: (p > q ? p - q : q - p) > (1n << (half - 100n)), d_inv: inv && e * d % lam === 1n,
        d_size: inv && d > (1n << half) && d < lam, n_len: bitLen(p * q) === nlen
      },
      p_mr: pp, q_mr: qp, d: d, lam: lam, low: low, t: t
    };
  }
  /* kiểm tra một cặp khoá đầy đủ (n, e, d, p, q, dP, dQ, qInv) */
  function pairCheck(k) {
    var lam = lcm(k.p - 1n, k.q - 1n), two = 2n % k.n;
    return {
      pq_n: k.p * k.q === k.n, ed: k.e * k.d % lam === 1n, dP: k.dP === k.d % (k.p - 1n), dQ: k.dQ === k.d % (k.q - 1n),
      qInv: k.q * k.qInv % k.p === 1n, roundtrip: modPow(modPow(two, k.e, k.n), k.d, k.n) === two
    };
  }

  /* ================================================================ nguyên thuỷ RSAEP / RSADP (RFC 8017 5.1; SP 800-56B r2 7.1) */
  function inRange(x, n, rule) { return rule === 'sp56b' ? (x > 1n && x < n - 1n) : (x >= 0n && x < n); }
  function rsaep(n, e, m, rule) {
    if (!inRange(m, n, rule || 'rfc')) throw Err('RANGE', { rule: rule || 'rfc' });
    return modPow(m, e, n);
  }
  function hasCrt(k) { return !!(k.p && k.q && k.dP !== undefined && k.dQ !== undefined && k.qInv !== undefined && k.p > 1n && k.q > 1n); }
  /* CRT theo Garner (RFC 8017 5.1.2 bước 2.b): m1 = c^dP mod p, m2 = c^dQ mod q, h = (m1 - m2) qInv mod p, m = m2 + q h.
     faultBit >= 0 mô phỏng một lỗi phần cứng: lật bit đó của m1 trước khi ghép */
  function crt(k, c, faultBit) {
    var m1 = modPow(c % k.p, k.dP, k.p), m2 = modPow(c % k.q, k.dQ, k.q), m1u = m1;
    if (faultBit !== undefined && faultBit !== null && faultBit >= 0) m1 = m1 ^ (1n << BigInt(faultBit));
    var h = mod((m1 - m2) * k.qInv, k.p);
    return { m1: m1u, m1f: m1, m2: m2, h: h, m: m2 + k.q * h };
  }
  function privateOp(k, x) { return hasCrt(k) ? crt(k, x).m : modPow(x, k.d, k.n); }
  function rsadp(k, c, rule) {
    if (!inRange(c, k.n, rule || 'rfc')) throw Err('RANGE', { rule: rule || 'rfc' });
    return privateOp(k, c);
  }
  /* Bellcore (Boneh-DeMillo-Lipton 1997): nếu m' đúng theo mod q nhưng sai theo mod p thì gcd(m'^e - c, n) = q */
  function bellcore(n, e, c, mf) { return gcd(mod(modPow(mf, e, n) - c, n), n); }

  /* ================================================================ hàm băm (FIPS 180-4, FIPS 202) và DigestInfo */
  var HASHES = [
    ['SHA2-224', 'SHA-224', 28, 4, function (m) { return S2.sha224(m); }],
    ['SHA2-256', 'SHA-256', 32, 1, function (m) { return S2.sha256(m); }],
    ['SHA2-384', 'SHA-384', 48, 2, function (m) { return S2.sha384(m); }],
    ['SHA2-512', 'SHA-512', 64, 3, function (m) { return S2.sha512(m); }],
    ['SHA2-512/224', 'SHA-512/224', 28, 5, function (m) { return S2.sha512_224(m); }],
    ['SHA2-512/256', 'SHA-512/256', 32, 6, function (m) { return S2.sha512_256(m); }],
    ['SHA3-224', 'SHA3-224', 28, 7, function (m) { return PH.sha3_224(m); }],
    ['SHA3-256', 'SHA3-256', 32, 8, function (m) { return PH.sha3_256(m); }],
    ['SHA3-384', 'SHA3-384', 48, 9, function (m) { return PH.sha3_384(m); }],
    ['SHA3-512', 'SHA3-512', 64, 10, function (m) { return PH.sha3_512(m); }]
  ].map(function (r) { return { id: r[0], label: r[1], len: r[2], oid: [2, 16, 840, 1, 101, 3, 4, 2, r[3]], fn: r[4] }; });
  var SHA1_INFO = { id: 'SHA-1', label: 'SHA-1', len: 20, oid: [1, 3, 14, 3, 2, 26] };   // chỉ để NHẬN RA chữ ký cũ, không để ký
  function hinfo(id) { for (var i = 0; i < HASHES.length; i++) if (HASHES[i].id === id) return HASHES[i]; throw Err('HASH', { id: id }); }
  function hash(id, m) { return hinfo(id).fn(m); }
  function derLen(n) { return n < 128 ? [n] : [0x81, n]; }
  /* DigestInfo = SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING digest } (RFC 8017 9.2 ghi chú 1), mã DER tính từ OID */
  function digestInfoPrefix(h) {
    var body = [], arcs = h.oid, i, v, chunk;
    var first = 40 * arcs[0] + arcs[1], vals = [first].concat(arcs.slice(2));
    for (i = 0; i < vals.length; i++) {
      v = vals[i]; chunk = [v & 0x7f]; v = Math.floor(v / 128);
      while (v) { chunk.unshift(0x80 | (v & 0x7f)); v = Math.floor(v / 128); }
      body = body.concat(chunk);
    }
    var oid = [0x06].concat(derLen(body.length), body), alg = oid.concat([0x05, 0x00]);
    alg = [0x30].concat(derLen(alg.length), alg);
    var inner = alg.concat([0x04, h.len]);
    return new Uint8Array([0x30].concat(derLen(inner.length + h.len), inner));
  }
  var DI = {};
  HASHES.concat([SHA1_INFO]).forEach(function (h) { DI[h.id] = digestInfoPrefix(h); });
  /* MGF1 (RFC 8017 B.2.1) */
  function mgf1(id, seed, len) {
    var h = hinfo(id), out = new Uint8Array(len), off = 0, c = 0;
    while (off < len) {
      var blk = h.fn(cat([seed, new Uint8Array([(c >>> 24) & 255, (c >>> 16) & 255, (c >>> 8) & 255, c & 255])]));
      out.set(blk.subarray(0, Math.min(blk.length, len - off)), off); off += blk.length; c++;
    }
    return out;
  }

  /* ================================================================ RSAES-OAEP (RFC 8017 7.1) */
  function oaepEncrypt(n, e, M, L, seed, hid) {
    hid = hid || 'SHA2-256';
    var h = hinfo(hid), k = byteLen(n), hL = h.len, max = k - 2 * hL - 2;
    if (M.length > max) throw Err('MSG_TOO_LONG', { max: max, k: k, len: M.length });
    if (seed.length !== hL) throw Err('SEED_LEN', { need: hL });
    var lHash = h.fn(L), PS = new Uint8Array(k - M.length - 2 * hL - 2);
    var DB = cat([lHash, PS, new Uint8Array([1]), M]), dbMask = mgf1(hid, seed, k - hL - 1), maskedDB = xor(DB, dbMask);
    var seedMask = mgf1(hid, maskedDB, hL), maskedSeed = xor(seed, seedMask), EM = cat([new Uint8Array([0]), maskedSeed, maskedDB]);
    var m = os2ip(EM), c = modPow(m, e, n);
    return { k: k, hLen: hL, lHash: lHash, psLen: PS.length, DB: DB, dbMask: dbMask, maskedDB: maskedDB, seedMask: seedMask,
      maskedSeed: maskedSeed, EM: EM, m: m, c: c, C: i2osp(c, k) };
  }
  /* giải mã; báo bước hỏng ĐẦU TIÊN theo thứ tự Y, lHash, dấu phân cách — một bộ giải mã thật KHÔNG được để lộ điều này */
  function oaepDecrypt(key, c, L, hid) {
    hid = hid || 'SHA2-256';
    var h = hinfo(hid), k = byteLen(key.n), hL = h.len;
    if (k < 2 * hL + 2) return { ok: false, reason: 'K_SMALL', k: k };
    if (!(c >= 0n && c < key.n)) return { ok: false, reason: 'RANGE' };
    var m = privateOp(key, c), EM = i2osp(m, k), Y = EM[0], maskedSeed = EM.subarray(1, 1 + hL), maskedDB = EM.subarray(1 + hL);
    var seed = xor(maskedSeed, mgf1(hid, maskedDB, hL)), DB = xor(maskedDB, mgf1(hid, seed, k - hL - 1)), lHash = h.fn(L);
    var out = { EM: EM, Y: Y, seed: seed, DB: DB, lHash: lHash, lHash2: DB.subarray(0, hL) };
    if (Y !== 0) { out.ok = false; out.reason = 'Y_NONZERO'; return out; }
    if (!same(DB.subarray(0, hL), lHash)) { out.ok = false; out.reason = 'LHASH'; return out; }
    var i = hL;
    while (i < DB.length && DB[i] === 0) i++;
    if (i >= DB.length || DB[i] !== 1) { out.ok = false; out.reason = 'SEPARATOR'; return out; }
    out.ok = true; out.psLen = i - hL; out.M = DB.slice(i + 1);
    return out;
  }

  /* ================================================================ chữ ký RSASSA-PKCS1-v1_5 (RFC 8017 8.2, 9.2) */
  function emsaPkcs1(hid, M, emLen) {
    var T = cat([DI[hid], hash(hid, M)]);
    if (emLen < T.length + 11) throw Err('EM_TOO_SHORT', { need: T.length + 11, have: emLen });
    var PS = new Uint8Array(emLen - T.length - 3).fill(0xff);
    return { EM: cat([new Uint8Array([0, 1]), PS, new Uint8Array([0]), T]), T: T, psLen: PS.length };
  }
  function signPkcs1(key, hid, M) {
    var k = byteLen(key.n), enc = emsaPkcs1(hid, M, k), m = os2ip(enc.EM), s = privateOp(key, m);
    return { EM: enc.EM, T: enc.T, m: m, s: s, S: i2osp(s, k) };
  }
  /* xác minh: so EM với EM' đầy đủ; khi khác, đọc EM để nói VÌ SAO (sai hàm băm, sai tóm lược, hay hỏng cấu trúc) */
  function verifyPkcs1(n, e, hid, M, S) {
    var k = byteLen(n);
    if (S.length !== k) return { ok: false, reason: 'SIG_LEN', k: k };
    var s = os2ip(S);
    if (s >= n) return { ok: false, reason: 'SIG_RANGE' };
    var EM = i2osp(modPow(s, e, n), k), enc;
    try { enc = emsaPkcs1(hid, M, k); } catch (x) { return { ok: false, reason: 'EM_TOO_SHORT', EM: EM }; }
    if (same(EM, enc.EM)) return { ok: true, reason: 'OK', EM: EM, EMp: enc.EM };
    var r = { ok: false, EM: EM, EMp: enc.EM, reason: 'ENCODING' };
    if (EM[0] !== 0 || EM[1] !== 1) return r;
    var i = 2;
    while (i < k && EM[i] === 0xff) i++;
    if (i - 2 < 8 || i >= k || EM[i] !== 0) return r;
    var T = EM.subarray(i + 1), ids = HASHES.concat([SHA1_INFO]);
    for (var j = 0; j < ids.length; j++) {
      var pre = DI[ids[j].id];
      if (T.length === pre.length + ids[j].len && same(T.subarray(0, pre.length), pre)) {
        if (ids[j].id === hid) r.reason = 'DIGEST'; else { r.reason = 'HASH_ALG'; r.alg = ids[j].id; }
        r.digest = T.subarray(pre.length);
        return r;
      }
    }
    return r;
  }

  /* ================================================================ RSASSA-PSS (RFC 8017 8.1, 9.1; FIPS 186-5 5.4(g): 0 <= sLen <= hLen) */
  function emsaPssEncode(hid, M, emBits, salt) {
    var h = hinfo(hid), hL = h.len, emLen = (emBits + 7) >> 3;
    if (salt.length > hL) throw Err('SLEN', { hLen: hL });
    if (emLen < hL + salt.length + 2) throw Err('EM_TOO_SHORT', { need: hL + salt.length + 2, have: emLen });
    var mHash = h.fn(M), Mp = cat([new Uint8Array(8), mHash, salt]), H = h.fn(Mp);
    var DB = cat([new Uint8Array(emLen - salt.length - hL - 2), new Uint8Array([1]), salt]);
    var dbMask = mgf1(hid, H, emLen - hL - 1), maskedDB = xor(DB, dbMask);
    maskedDB[0] &= 0xff >> (8 * emLen - emBits);
    return { mHash: mHash, Mp: Mp, H: H, DB: DB, dbMask: dbMask, maskedDB: maskedDB, EM: cat([maskedDB, H, new Uint8Array([0xbc])]) };
  }
  function signPss(key, hid, M, salt) {
    var modBits = bitLen(key.n), k = byteLen(key.n), enc = emsaPssEncode(hid, M, modBits - 1, salt), m = os2ip(enc.EM), s = privateOp(key, m);
    enc.m = m; enc.s = s; enc.S = i2osp(s, k);
    return enc;
  }
  function verifyPss(n, e, hid, M, S, sLen) {
    var h = hinfo(hid), hL = h.len;
    if (sLen > hL) return { ok: false, reason: 'SLEN' };
    var modBits = bitLen(n), k = byteLen(n);
    if (S.length !== k) return { ok: false, reason: 'SIG_LEN', k: k };
    var s = os2ip(S);
    if (s >= n) return { ok: false, reason: 'SIG_RANGE' };
    var emBits = modBits - 1, emLen = (emBits + 7) >> 3, m = modPow(s, e, n);
    if (m >= (1n << BigInt(8 * emLen))) return { ok: false, reason: 'EM_LARGE' };
    var EM = i2osp(m, emLen), r = { ok: false, EM: EM };
    if (emLen < hL + sLen + 2) { r.reason = 'INCONSISTENT'; return r; }
    if (EM[emLen - 1] !== 0xbc) { r.reason = 'TRAILER'; return r; }
    var maskedDB = EM.subarray(0, emLen - hL - 1), H = EM.subarray(emLen - hL - 1, emLen - 1), top = 8 * emLen - emBits;
    if (maskedDB[0] & (0xff << (8 - top)) & 0xff) { r.reason = 'TOP_BITS'; return r; }
    var DB = xor(maskedDB, mgf1(hid, H, emLen - hL - 1));
    DB[0] &= 0xff >> top;
    var pad = emLen - hL - sLen - 2;
    for (var i = 0; i < pad; i++) if (DB[i] !== 0) { r.reason = 'PADDING'; return r; }
    if (DB[pad] !== 1) { r.reason = 'PADDING'; return r; }
    var salt = DB.slice(pad + 1), H2 = h.fn(cat([new Uint8Array(8), h.fn(M), salt]));
    r.salt = salt; r.H = H; r.H2 = H2;
    if (!same(H, H2)) { r.reason = 'HASH'; return r; }
    r.ok = true; r.reason = 'OK';
    return r;
  }
  /* RSASP1 / RSAVP1 (RFC 8017 5.2): chính phép tính với khoá riêng / khoá công khai, đầu vào phải 0 <= x < n */
  function rsasp1(key, m) { if (!(m >= 0n && m < key.n)) throw Err('RANGE', { rule: 'rfc' }); return privateOp(key, m); }
  function rsavp1(n, e, s) { if (!(s >= 0n && s < n)) throw Err('RANGE', { rule: 'rfc' }); return modPow(s, e, n); }

  /* ================================================================ việc dài, đầu vào / ra là hex (đi qua postMessage của Worker) */
  function H_(x) { return x === null || x === undefined ? null : x.toString(16); }
  function keyIn(o) {
    var k = {};
    ['n', 'e', 'd', 'p', 'q', 'dP', 'dQ', 'qInv'].forEach(function (f) { if (o[f]) k[f] = hexToBig(o[f]); });
    return k;
  }
  function keyOut(k) {
    var o = {};
    ['n', 'e', 'd', 'p', 'q', 'dP', 'dQ', 'qInv', 'lam', 'phi'].forEach(function (f) { if (k[f] !== undefined) o[f] = H_(k[f]); });
    return o;
  }
  var jobs = {
    keygen: function (nlen, eHex, seedHex) {
      var t0 = Date.now(), k = keygen(nlen, hexToBig(eHex), hexToBytes(seedHex)), o = keyOut(k), lam = k.lam;
      o.statsP = k.statsP; o.statsQ = k.statsQ; o.restarts = k.restarts; o.ctr = k.ctr; o.rounds = k.rounds; o.ms = Date.now() - t0;
      o.check = checkOut(checkKey(k.p, k.q, k.e, k.d, nlen));
      o.dPhi = H_(modInv(k.e, k.phi)); o.lamBits = bitLen(lam);
      return o;
    },
    check: function (nlen, kh) {                            // p, q, e (và d nếu có) -> các điều kiện A.1.1
      var k = keyIn(kh), out = { check: checkOut(checkKey(k.p, k.q, k.e, kh.d ? k.d : null, nlen)) };
      try { var f = fromPQ(k.p, k.q, k.e); out.key = keyOut(f); out.dPhi = H_(modInv(k.e, f.phi)); }
      catch (x) { out.error = x.code || String(x.message); }
      if (k.n && k.d && k.dP !== undefined && k.dQ !== undefined && k.qInv !== undefined) out.pair = pairCheck(k);
      return out;
    },
    decrypt: function (kh, cHex, o) {                       // RSADP thường + CRT + thang + làm mù + lỗi Bellcore
      var k = keyIn(kh), c = hexToBig(cHex), res = { plain: null }, t0 = Date.now();
      res.plain = H_(modPow(c, k.d, k.n));
      if (o.ladder) { var L = modPowLadder(c, k.d, k.n); res.ladder = H_(L.r); res.ladderOps = L.ops; }
      res.dS = bitLen(k.d) - 1; res.dM = popcount(k.d) - 1;
      if (hasCrt(k)) {
        var C = crt(k, c);
        res.crt = { m1: H_(C.m1), m2: H_(C.m2), h: H_(C.h), m: H_(C.m), cp: H_(c % k.p), cq: H_(c % k.q) };
        if (o.fault !== undefined && o.fault !== null && o.fault >= 0) {
          var F = crt(k, c, o.fault), g = bellcore(k.n, k.e, c, F.m);
          res.fault = { m1f: H_(F.m1f), h: H_(F.h), m: H_(F.m), gcd: H_(g), detected: modPow(F.m, k.e, k.n) !== c };
        }
      }
      if (o.r) {
        var r = hexToBig(o.r), cb = modPow(r, k.e, k.n) * c % k.n, mb = privateOp(k, cb);
        res.blind = { r: H_(r), cb: H_(cb), mb: H_(mb), rinv: H_(modInv(r, k.n)), m: H_(mb * modInv(r, k.n) % k.n) };
      }
      res.ms = Date.now() - t0;
      return res;
    }
  };
  function checkOut(c) {
    return { rows: c.rows, d: H_(c.d), lam: H_(c.lam), low: H_(c.low), t: c.t,
      p_mr: c.p_mr, q_mr: c.q_mr };
  }

  root.RSACore = {
    hexToBig: hexToBig, bigToHex: bigToHex, bytesToHex: bytesToHex, hexToBytes: hexToBytes, os2ip: os2ip, i2osp: i2osp,
    bitLen: bitLen, byteLen: byteLen, popcount: popcount, gcd: gcd, lcm: lcm, mod: mod, modInv: modInv, isqrt: isqrt,
    modPow: modPow, modPowTrace: modPowTrace, modPowLadder: modPowLadder, montConst: montConst, montPow: montPow,
    c1Rounds: c1Rounds, TABLE_B1: TABLE_B1, ROUNDS: ROUNDS, mrRounds: mrRounds, strength: strength, lowerBound: lowerBound,
    TD_LIMIT: TD_LIMIT, SMALL_PRIMES: SMALL, trialDivisor: trialDivisor, Stream: Stream, millerRabin: millerRabin,
    genPrime: genPrime, keygen: keygen, fromPQ: fromPQ, checkE: checkE, checkKey: checkKey, primality: primality, pairCheck: pairCheck,
    inRange: inRange, rsaep: rsaep, rsadp: rsadp, crt: crt, hasCrt: hasCrt, privateOp: privateOp, bellcore: bellcore,
    HASHES: HASHES, hinfo: hinfo, hash: hash, DI: DI, mgf1: mgf1,
    oaepEncrypt: oaepEncrypt, oaepDecrypt: oaepDecrypt,
    emsaPkcs1: emsaPkcs1, signPkcs1: signPkcs1, verifyPkcs1: verifyPkcs1,
    emsaPssEncode: emsaPssEncode, signPss: signPss, verifyPss: verifyPss, rsasp1: rsasp1, rsavp1: rsavp1,
    jobs: jobs
  };
})(typeof window !== 'undefined' ? window : globalThis);
