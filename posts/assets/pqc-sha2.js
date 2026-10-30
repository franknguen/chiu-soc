/* Họ SHA-2 (FIPS 180-4) cho tuỳ chọn pre-hash của HashML-DSA: SHA-224, SHA-256, SHA-384, SHA-512,
   SHA-512/224, SHA-512/256.
   Mọi hằng số được TÍNH khi nạp bằng BigInt (căn bậc hai / bậc ba nguyên của các số nguyên tố),
   không chép bảng — chép 80 hằng số 64 bit bằng tay là cách chắc chắn để lọt một lỗi đánh máy.
   IV của SHA-512/t cũng được tính đúng như FIPS 180-4 §5.3.6: chạy SHA-512 (IV XOR a5…a5) trên chuỗi "SHA-512/t". */
(function (root) {
  'use strict';

  function primes(n) {
    var out = [], c = 2;
    while (out.length < n) {
      var ok = true;
      for (var i = 2; i * i <= c; i++) if (c % i === 0) { ok = false; break; }
      if (ok) out.push(c);
      c++;
    }
    return out;
  }
  function iroot(n, k) {                      // căn bậc k nguyên của BigInt, Newton
    if (n < 2n) return n;
    var K = BigInt(k), x = 1n << (BigInt(n.toString(2).length) / K + 1n);
    for (;;) {
      var y = ((K - 1n) * x + n / (x ** (K - 1n))) / K;
      if (y >= x) return x;
      x = y;
    }
  }
  function frac(p, k, bits) {                 // phần lẻ của căn bậc k của p, lấy `bits` bit đầu
    var B = BigInt(bits), P = BigInt(p);
    var scaled = iroot(P << (B * BigInt(k)), k);   // floor(root(p) * 2^bits)
    var whole = iroot(P, k) << B;
    return scaled - whole;
  }
  var PR = primes(80);
  var K256 = new Uint32Array(64), H256 = new Uint32Array(8);
  var K512h = new Uint32Array(80), K512l = new Uint32Array(80);
  var H512h = new Uint32Array(8),  H512l = new Uint32Array(8);
  var H224 = new Uint32Array(8), H384h = new Uint32Array(8), H384l = new Uint32Array(8);
  (function () {
    var i, v;
    for (i = 0; i < 64; i++) K256[i] = Number(frac(PR[i], 3, 32));
    for (i = 0; i < 8; i++)  H256[i] = Number(frac(PR[i], 2, 32));
    for (i = 0; i < 80; i++) {
      v = frac(PR[i], 3, 64);
      K512h[i] = Number(v >> 32n); K512l[i] = Number(v & 0xFFFFFFFFn);
    }
    for (i = 0; i < 8; i++) {
      v = frac(PR[i], 2, 64);
      H512h[i] = Number(v >> 32n); H512l[i] = Number(v & 0xFFFFFFFFn);
    }
    for (i = 0; i < 8; i++) {                 // số nguyên tố thứ 9..16: SHA-384 lấy 64 bit, SHA-224 lấy 32 bit thấp
      v = frac(PR[i + 8], 2, 64);
      H384h[i] = Number(v >> 32n); H384l[i] = Number(v & 0xFFFFFFFFn);
      H224[i] = H384l[i];
    }
  })();

  function pad(msgLen, blockBytes, lenBytes) {
    var total = msgLen + 1 + lenBytes;
    var padLen = (blockBytes - (total % blockBytes)) % blockBytes;
    return 1 + padLen + lenBytes;
  }

  function sha256core(msg, iv, outLen) {
    var rot = function (x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; };
    var tail = pad(msg.length, 64, 8), buf = new Uint8Array(msg.length + tail);
    buf.set(msg); buf[msg.length] = 0x80;
    var bits = msg.length * 8;
    buf[buf.length - 4] = (bits >>> 24) & 0xFF; buf[buf.length - 3] = (bits >>> 16) & 0xFF;
    buf[buf.length - 2] = (bits >>> 8) & 0xFF;  buf[buf.length - 1] = bits & 0xFF;
    var H = Uint32Array.from(iv), w = new Uint32Array(64), i, t;
    for (var off = 0; off < buf.length; off += 64) {
      for (i = 0; i < 16; i++)
        w[i] = (buf[off + 4 * i] << 24 | buf[off + 4 * i + 1] << 16 | buf[off + 4 * i + 2] << 8 | buf[off + 4 * i + 3]) >>> 0;
      for (i = 16; i < 64; i++) {
        var s0 = rot(w[i - 15], 7) ^ rot(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rot(w[i - 2], 17) ^ rot(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = rot(e, 6) ^ rot(e, 11) ^ rot(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
        var S0 = rot(a, 2) ^ rot(a, 13) ^ rot(a, 22);
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
      t = 0; void t;
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) {
      out[4 * i] = (H[i] >>> 24) & 0xFF; out[4 * i + 1] = (H[i] >>> 16) & 0xFF;
      out[4 * i + 2] = (H[i] >>> 8) & 0xFF; out[4 * i + 3] = H[i] & 0xFF;
    }
    return out.slice(0, outLen);
  }

  function sha512core(msg, ivh, ivl, outLen) {
    /* 64 bit = cặp (hi, lo) 32 bit */
    var hi = new Uint32Array(80), lo = new Uint32Array(80);
    function rotrH(h, l, n) { return n < 32 ? ((h >>> n) | (l << (32 - n))) : ((l >>> (n - 32)) | (h << (64 - n))); }
    function rotrL(h, l, n) { return n < 32 ? ((l >>> n) | (h << (32 - n))) : ((h >>> (n - 32)) | (l << (64 - n))); }
    var tail = pad(msg.length, 128, 16), buf = new Uint8Array(msg.length + tail);
    buf.set(msg); buf[msg.length] = 0x80;
    var bits = msg.length * 8;                       // < 2^53, nên 8 byte cao luôn bằng 0
    buf[buf.length - 5] = (bits / 0x100000000) & 0xFF;
    buf[buf.length - 4] = (bits >>> 24) & 0xFF; buf[buf.length - 3] = (bits >>> 16) & 0xFF;
    buf[buf.length - 2] = (bits >>> 8) & 0xFF;  buf[buf.length - 1] = bits & 0xFF;
    var Hh = Uint32Array.from(ivh), Hl = Uint32Array.from(ivl), i;
    for (var off = 0; off < buf.length; off += 128) {
      for (i = 0; i < 16; i++) {
        hi[i] = (buf[off + 8 * i] << 24 | buf[off + 8 * i + 1] << 16 | buf[off + 8 * i + 2] << 8 | buf[off + 8 * i + 3]) >>> 0;
        lo[i] = (buf[off + 8 * i + 4] << 24 | buf[off + 8 * i + 5] << 16 | buf[off + 8 * i + 6] << 8 | buf[off + 8 * i + 7]) >>> 0;
      }
      for (i = 16; i < 80; i++) {
        var h15 = hi[i - 15], l15 = lo[i - 15];
        var s0h = (rotrH(h15, l15, 1) ^ rotrH(h15, l15, 8) ^ (h15 >>> 7)) >>> 0;
        var s0l = (rotrL(h15, l15, 1) ^ rotrL(h15, l15, 8) ^ ((l15 >>> 7) | (h15 << 25))) >>> 0;
        var h2 = hi[i - 2], l2 = lo[i - 2];
        var s1h = (rotrH(h2, l2, 19) ^ rotrH(h2, l2, 61) ^ (h2 >>> 6)) >>> 0;
        var s1l = (rotrL(h2, l2, 19) ^ rotrL(h2, l2, 61) ^ ((l2 >>> 6) | (h2 << 26))) >>> 0;
        var l = (lo[i - 16] + s0l) >>> 0, carry = l < s0l ? 1 : 0;
        var h = (hi[i - 16] + s0h + carry) >>> 0;
        var l2b = (l + lo[i - 7]) >>> 0; carry = l2b < lo[i - 7] ? 1 : 0;
        h = (h + hi[i - 7] + carry) >>> 0;
        var l3 = (l2b + s1l) >>> 0; carry = l3 < s1l ? 1 : 0;
        h = (h + s1h + carry) >>> 0;
        hi[i] = h; lo[i] = l3;
      }
      var ah = Hh[0], al = Hl[0], bh = Hh[1], bl = Hl[1], ch = Hh[2], cl = Hl[2], dh = Hh[3], dl = Hl[3];
      var eh = Hh[4], el = Hl[4], fh = Hh[5], fl = Hl[5], gh = Hh[6], gl = Hl[6], hh = Hh[7], hl = Hl[7];
      for (i = 0; i < 80; i++) {
        var S1h = (rotrH(eh, el, 14) ^ rotrH(eh, el, 18) ^ rotrH(eh, el, 41)) >>> 0;
        var S1l = (rotrL(eh, el, 14) ^ rotrL(eh, el, 18) ^ rotrL(eh, el, 41)) >>> 0;
        var chh = ((eh & fh) ^ (~eh & gh)) >>> 0, chl = ((el & fl) ^ (~el & gl)) >>> 0;
        var t1l = (hl + S1l) >>> 0, cy = t1l < S1l ? 1 : 0;
        var t1h = (hh + S1h + cy) >>> 0;
        t1l = (t1l + chl) >>> 0; cy = t1l < chl ? 1 : 0; t1h = (t1h + chh + cy) >>> 0;
        t1l = (t1l + K512l[i]) >>> 0; cy = t1l < K512l[i] ? 1 : 0; t1h = (t1h + K512h[i] + cy) >>> 0;
        t1l = (t1l + lo[i]) >>> 0; cy = t1l < lo[i] ? 1 : 0; t1h = (t1h + hi[i] + cy) >>> 0;
        var S0h = (rotrH(ah, al, 28) ^ rotrH(ah, al, 34) ^ rotrH(ah, al, 39)) >>> 0;
        var S0l = (rotrL(ah, al, 28) ^ rotrL(ah, al, 34) ^ rotrL(ah, al, 39)) >>> 0;
        var mjh = ((ah & bh) ^ (ah & ch) ^ (bh & ch)) >>> 0, mjl = ((al & bl) ^ (al & cl) ^ (bl & cl)) >>> 0;
        var t2l = (S0l + mjl) >>> 0; cy = t2l < mjl ? 1 : 0;
        var t2h = (S0h + mjh + cy) >>> 0;
        hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
        el = (dl + t1l) >>> 0; cy = el < t1l ? 1 : 0; eh = (dh + t1h + cy) >>> 0;
        dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
        al = (t1l + t2l) >>> 0; cy = al < t2l ? 1 : 0; ah = (t1h + t2h + cy) >>> 0;
      }
      function add(idx, xh, xl) {
        var l = (Hl[idx] + xl) >>> 0, c = l < xl ? 1 : 0;
        Hl[idx] = l; Hh[idx] = (Hh[idx] + xh + c) >>> 0;
      }
      add(0, ah, al); add(1, bh, bl); add(2, ch, cl); add(3, dh, dl);
      add(4, eh, el); add(5, fh, fl); add(6, gh, gl); add(7, hh, hl);
    }
    var out = new Uint8Array(64);
    for (i = 0; i < 8; i++) {
      out[8 * i]     = (Hh[i] >>> 24) & 0xFF; out[8 * i + 1] = (Hh[i] >>> 16) & 0xFF;
      out[8 * i + 2] = (Hh[i] >>> 8) & 0xFF;  out[8 * i + 3] = Hh[i] & 0xFF;
      out[8 * i + 4] = (Hl[i] >>> 24) & 0xFF; out[8 * i + 5] = (Hl[i] >>> 16) & 0xFF;
      out[8 * i + 6] = (Hl[i] >>> 8) & 0xFF;  out[8 * i + 7] = Hl[i] & 0xFF;
    }
    return out.slice(0, outLen);
  }

  /* IV của SHA-512/t (FIPS 180-4 §5.3.6): SHA-512 với IV XOR a5a5…a5 trên chuỗi ASCII "SHA-512/t" */
  function ivFor512t(t) {
    var ih = new Uint32Array(8), il = new Uint32Array(8), i;
    for (i = 0; i < 8; i++) { ih[i] = (H512h[i] ^ 0xA5A5A5A5) >>> 0; il[i] = (H512l[i] ^ 0xA5A5A5A5) >>> 0; }
    var name = 'SHA-512/' + t, b = new Uint8Array(name.length);
    for (i = 0; i < name.length; i++) b[i] = name.charCodeAt(i);
    var d = sha512core(b, ih, il, 64), oh = new Uint32Array(8), ol = new Uint32Array(8);
    for (i = 0; i < 8; i++) {
      oh[i] = (d[8 * i] << 24 | d[8 * i + 1] << 16 | d[8 * i + 2] << 8 | d[8 * i + 3]) >>> 0;
      ol[i] = (d[8 * i + 4] << 24 | d[8 * i + 5] << 16 | d[8 * i + 6] << 8 | d[8 * i + 7]) >>> 0;
    }
    return [oh, ol];
  }
  var IV224t = ivFor512t(224), IV256t = ivFor512t(256);

  root.PQCSHA2 = {
    sha224: function (m) { return sha256core(m, H224, 28); },
    sha256: function (m) { return sha256core(m, H256, 32); },
    sha384: function (m) { return sha512core(m, H384h, H384l, 48); },
    sha512: function (m) { return sha512core(m, H512h, H512l, 64); },
    sha512_224: function (m) { return sha512core(m, IV224t[0], IV224t[1], 28); },
    sha512_256: function (m) { return sha512core(m, IV256t[0], IV256t[1], 32); }
  };
})(typeof window !== 'undefined' ? window : globalThis);
