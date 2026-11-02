/* Mô hình cho hai trình mô phỏng mục 6 và 7 của bài "Từ mã sửa lỗi lượng tử đến ECC trong con chip":
   - ECCHam: mã Hamming (7, 4), (12, 8) rút gọn - đúng ví dụ trong bài - và (15, 11). Vị trí 1..n, bit kiểm ở các luỹ
     thừa của 2, dữ liệu D0.. ở các vị trí còn lại theo thứ tự tăng. Hội chứng = XOR số thứ tự của mọi ô bằng 1, nên
     một lỗi ở ô p cho đúng S = p. Không có bit P: hai lỗi cho S = a ⊕ b và bộ giải mã lật nhầm ô thứ ba.
   - ECCBch: mã BCH nhị phân dài 15 trên GF(16) sinh bởi x⁴ + x + 1, t = 1, 2, 3. Mã hoá hệ thống: c(x) = x^(n−k)·d(x) +
     phần dư chia g(x), nên ô 0..n−k−1 là bit kiểm, ô n−k..14 là dữ liệu. Giải mã đúng ba khâu của phần cứng: hội chứng
     S_j = r(α^j) -> Berlekamp–Massey ra đa thức định vị lỗi Λ(x) -> dò nghiệm Chien Λ(α^−i) = 0 thì ô i lỗi.
   Phần tử GF(16) là số 0..15, bit j = hệ số của α^j. Mọi bit là số 0/1 trong mảng thường. Chạy cả trong trình duyệt
   lẫn Node (không có DOM, không cần thư viện).
   Original implementation for the ChiU·SoC ECC note. */
(function (root) {
  'use strict';
  function bits(x, what) {
    if (!x || typeof x.length !== 'number') throw new Error(what + ' phải là mảng bit');
    var out = new Array(x.length), i;
    for (i = 0; i < x.length; i++) out[i] = x[i] & 1;
    return out;
  }
  function same(a, b) { var i; if (a.length !== b.length) return false; for (i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }
  function combos(n, w) {                       // mọi tập w vị trí trong 0..n-1, thứ tự từ điển
    var out = [], cur = [];
    (function rec(s) {
      if (cur.length === w) { out.push(cur.slice()); return; }
      for (var i = s; i < n; i++) { cur.push(i); rec(i + 1); cur.pop(); }
    })(0);
    return out;
  }

  /* ================================================================ Hamming */
  var HCODES = [{ id: '7,4', n: 7, k: 4, r: 3 }, { id: '12,8', n: 12, k: 8, r: 4 }, { id: '15,11', n: 15, k: 11, r: 4 }];
  var hcache = {};
  function hcode(id) {
    if (hcache[id]) return hcache[id];
    var b = null, i, p, C;
    for (i = 0; i < HCODES.length; i++) if (HCODES[i].id === id) b = HCODES[i];
    if (!b) throw new Error('không có mã Hamming ' + id);
    C = { id: b.id, n: b.n, k: b.k, r: b.r, checkPos: [], dataPos: [], labels: [] };
    for (p = 1; p <= b.n; p++) {
      if ((p & (p - 1)) === 0) { C.checkPos.push(p); C.labels.push('C' + p); }
      else { C.labels.push('D' + C.dataPos.length); C.dataPos.push(p); }
    }
    return (hcache[id] = C);
  }
  /* vị trí mà bit kiểm thứ i (ở ô 2^i) phụ trách: mọi ô có bit i trong chỉ số nhị phân, trừ chính nó */
  function hcoverage(C, i) {
    var out = [], p;
    for (p = 1; p <= C.n; p++) if (((p >> i) & 1) && p !== (1 << i)) out.push(p);
    return out;
  }
  function hencode(C, d) {
    d = bits(d, 'dữ liệu');
    if (d.length !== C.k) throw new Error('cần đúng ' + C.k + ' bit dữ liệu');
    var c = [], i, p, x;
    for (i = 0; i < C.n; i++) c.push(0);
    for (i = 0; i < C.k; i++) c[C.dataPos[i] - 1] = d[i];
    for (i = 0; i < C.r; i++) {
      x = 0;
      for (p = 1; p <= C.n; p++) if ((p >> i) & 1) x ^= c[p - 1];   // ô kiểm còn là 0 nên không tự cộng
      c[(1 << i) - 1] = x;
    }
    return c;
  }
  function hsyndrome(C, c) {
    c = bits(c, 'từ mã');
    if (c.length !== C.n) throw new Error('cần đúng ' + C.n + ' bit');
    var s = 0, p;
    for (p = 1; p <= C.n; p++) if (c[p - 1]) s ^= p;
    return s;
  }
  /* ok (S = 0) | single (lật ô S) | invalid (S > n: chỉ mã rút gọn mới có - không ô nào mang số ấy) */
  function hdecode(C, c) {
    var word = bits(c, 'từ mã'), s = hsyndrome(C, word), kind, pos = 0;
    if (s === 0) kind = 'ok';
    else if (s <= C.n) { kind = 'single'; pos = s; word[s - 1] ^= 1; }
    else kind = 'invalid';
    return { kind: kind, s: s, pos: pos, word: word, data: C.dataPos.map(function (p) { return word[p - 1]; }) };
  }
  /* tự kiểm: mọi mã x mọi dữ liệu x mọi mẫu lỗi tới 2 bit. ≤ 1 lỗi phải về đúng; 2 lỗi a, b phải cho S = a ⊕ b và
     lật nhầm ô ấy (hoặc invalid khi a ⊕ b > n). Gọi qua api.* để một bản vá từ ngoài làm nó đỏ được. */
  function hselfTest() {
    var n = 0, fail = 0, ci, C, d, i, j, a, dd, cw, w, r, s;
    function chk(ok) { n++; if (!ok) fail++; }
    for (ci = 0; ci < HCODES.length; ci++) {
      C = api.ham.code(HCODES[ci].id);
      for (d = 0; d < (1 << C.k); d++) {
        dd = [];
        for (i = 0; i < C.k; i++) dd.push((d >> i) & 1);
        cw = api.ham.encode(C, dd);
        r = api.ham.decode(C, cw);
        chk(r.kind === 'ok' && same(r.data, dd));
        for (a = 1; a <= C.n; a++) {
          w = cw.slice(); w[a - 1] ^= 1; r = api.ham.decode(C, w);
          chk(r.kind === 'single' && r.pos === a && same(r.word, cw) && same(r.data, dd));
          for (j = a + 1; j <= C.n; j++) {
            w = cw.slice(); w[a - 1] ^= 1; w[j - 1] ^= 1; r = api.ham.decode(C, w); s = a ^ j;
            chk(r.s === s && (s <= C.n ? r.kind === 'single' && r.pos === s && !same(r.word, cw) : r.kind === 'invalid'));
          }
        }
      }
    }
    C = api.ham.code('12,8');                                        // ví dụ trong bài
    cw = api.ham.encode(C, [0, 1, 0, 0, 1, 1, 1, 1]);
    w = cw.slice(); w[4] ^= 1; r = api.ham.decode(C, w);
    if (cw.join('') !== '100010001111' || r.kind !== 'single' || r.s !== 5) fail++;
    return { n: n, fail: fail };                                    // n = 268 496; ví dụ chỉ cộng vào fail
  }

  /* ================================================================ GF(16) và BCH (15, k) */
  var NB = 15, EXP = [], LOG = [];
  (function () { var x = 1, i; for (i = 0; i < NB; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 16) x ^= 0x13; } for (i = NB; i < 2 * NB; i++) EXP[i] = EXP[i - NB]; })();
  function mul(a, b) { return a && b ? EXP[LOG[a] + LOG[b]] : 0; }
  function div(a, b) { if (!b) throw new Error('chia cho 0'); return a ? EXP[(LOG[a] - LOG[b] + NB) % NB] : 0; }
  function apow(e) { return EXP[((e % NB) + NB) % NB]; }
  function pmul(a, b) {                          // nhân hai đa thức hệ số GF(16), thấp -> cao
    var out = [], i, j;
    for (i = 0; i < a.length + b.length - 1; i++) out.push(0);
    for (i = 0; i < a.length; i++) for (j = 0; j < b.length; j++) out[i + j] ^= mul(a[i], b[j]);
    return out;
  }
  function peval(p, x) { var v = 0, i; for (i = p.length - 1; i >= 0; i--) v = mul(v, x) ^ p[i]; return v; }
  function coset(j) { var out = [], x = j % NB; while (out.indexOf(x) < 0) { out.push(x); x = (x * 2) % NB; } return out; }
  /* m_j(x) = tích (x + α^i) trên lớp kề {j, 2j, 4j, ...}: hệ số ra 0/1 */
  function minimal(j) { var p = [1], cs = coset(j), i; for (i = 0; i < cs.length; i++) p = pmul(p, [EXP[cs[i]], 1]); return { j: j, coset: cs, poly: p }; }
  var bcache = {};
  function bcode(t) {
    if (bcache[t]) return bcache[t];
    if (t !== 1 && t !== 2 && t !== 3) throw new Error('t phải là 1, 2 hoặc 3');
    var ms = [], seen = [], g = [1], j, m;
    for (j = 1; j < 2 * t; j += 2) {
      if (seen.indexOf(j) >= 0) continue;
      m = minimal(j); seen = seen.concat(m.coset); ms.push(m); g = pmul(g, m.poly);
    }
    return (bcache[t] = { t: t, n: NB, k: NB - (g.length - 1), g: g, m: ms });
  }
  function bencode(C, d) {
    d = bits(d, 'dữ liệu');
    if (d.length !== C.k) throw new Error('cần đúng ' + C.k + ' bit dữ liệu');
    var nk = C.n - C.k, a = [], rem, i, q;
    for (i = 0; i < C.n; i++) a.push(i < nk ? 0 : d[i - nk]);
    rem = a.slice();
    for (i = C.n - 1; i >= nk; i--) if (rem[i]) for (q = 0; q <= nk; q++) rem[i - nk + q] ^= C.g[q];   // chia dài cho g(x)
    for (i = 0; i < nk; i++) a[i] = rem[i];
    return a;
  }
  function bsyndromes(C, r) {
    r = bits(r, 'từ nhận');
    if (r.length !== C.n) throw new Error('cần đúng 15 bit');
    var S = [], j, i, s;
    for (j = 1; j <= 2 * C.t; j++) { s = 0; for (i = 0; i < C.n; i++) if (r[i]) s ^= EXP[(i * j) % NB]; S.push(s); }
    return S;
  }
  /* Berlekamp–Massey: thanh ghi ngắn nhất sinh ra S1..S2t. Trả { lam: hệ số Λ thấp -> cao (bỏ số 0 ở đuôi), L: độ dài
     thanh ghi }. Giải mã được khi L ≤ t và Λ có đúng L nghiệm. */
  function bmFull(S) {
    var Lam = [1], B = [1], L = 0, m = 1, b = 1, n, d, i, T, coef;
    for (n = 0; n < S.length; n++) {
      d = S[n];
      for (i = 1; i <= L; i++) d ^= mul(Lam[i] || 0, S[n - i]);
      if (d === 0) { m++; continue; }
      T = Lam.slice(); coef = div(d, b);
      while (Lam.length < B.length + m) Lam.push(0);
      for (i = 0; i < B.length; i++) Lam[i + m] ^= mul(coef, B[i]);
      if (2 * L <= n) { L = n + 1 - L; B = T; b = d; m = 1; } else m++;
    }
    while (Lam.length > 1 && Lam[Lam.length - 1] === 0) Lam.pop();
    return { lam: Lam, L: L };
  }
  function berlekampMassey(S) { return bmFull(S).lam; }
  /* dò nghiệm Chien: ô i lỗi khi Λ(α^−i) = 0 - thử cả 15 vị trí, như phần cứng thử từng chu kỳ */
  function chien(L) {
    var vals = [], roots = [], i, v;
    for (i = 0; i < NB; i++) { v = peval(L, apow(-i)); vals.push(v); if (v === 0) roots.push(i); }
    return { vals: vals, roots: roots };
  }
  /* ok (mọi S = 0) | fixed (lật các ô gốc của Λ) | fail (L > t, hoặc Λ thiếu nghiệm: phát hiện, không sửa) */
  function bdecode(C, r) {
    var word = bits(r, 'từ nhận'), S = api.bch.syndromes(C, word), zero = true, i, bm, ch;
    for (i = 0; i < S.length; i++) if (S[i]) zero = false;
    var res = { kind: 'ok', S: S, L: [1], reg: 0, pos: [], word: word };
    if (!zero) {
      bm = bmFull(S); ch = chien(bm.lam);
      res.L = bm.lam; res.reg = bm.L;
      /* đủ điều kiện này thì từ sau khi sửa chắc chắn là từ mã: với mã nhị phân S₂ⱼ = Sⱼ² ép mọi giá trị lỗi bằng 1, nên
         lật L ô gốc của Λ triệt tiêu cả 2t hội chứng. Không cần tính lại hội chứng (đã thử: bỏ bước tính lại không đổi
         một bản ghi nào trong 3 x 32 768 từ nhận so với bộ giải mã khoảng cách bị chặn của mô hình Python). */
      if (bm.L <= C.t && bm.lam.length - 1 === bm.L && ch.roots.length === bm.L) {
        for (i = 0; i < ch.roots.length; i++) word[ch.roots[i]] ^= 1;
        res.kind = 'fixed'; res.pos = ch.roots;
      } else res.kind = 'fail';
    }
    res.data = word.slice(C.n - C.k);
    return res;
  }
  /* vách đá: mọi mẫu lỗi e trên từ mã 0. Mã tuyến tính và bộ giải mã chỉ nhìn hội chứng, nên kết quả không phụ thuộc dữ
     liệu: 2^15 mẫu là đủ mọi trường hợp. right = về đúng từ 0, detected = fail, wrong = còn lại (kể cả "ok" sai). */
  function cliff(C) {
    var out = [], e, p, i, r, w, res, zero;
    for (e = 0; e <= NB; e++) out.push({ e: e, total: 0, right: 0, detected: 0, wrong: 0 });
    for (p = 0; p < (1 << NB); p++) {
      r = []; w = 0;
      for (i = 0; i < NB; i++) { r.push((p >> i) & 1); w += r[i]; }
      res = api.bch.decode(C, r);
      zero = res.word.every(function (b) { return b === 0; });
      out[w].total++;
      if (res.kind === 'fail') out[w].detected++; else if (zero) out[w].right++; else out[w].wrong++;
    }
    return out;
  }
  /* tự kiểm: mọi t x mọi dữ liệu x mọi mẫu lỗi tới t bit phải về đúng từ mã, đúng các ô lỗi */
  function bselfTest() {
    var n = 0, fail = 0, t, C, d, i, w, sets, dd, cw, r, res, e;
    for (t = 1; t <= 3; t++) {
      C = api.bch.code(t); sets = [];
      for (w = 0; w <= t; w++) sets = sets.concat(combos(NB, w));
      for (d = 0; d < (1 << C.k); d++) {
        dd = [];
        for (i = 0; i < C.k; i++) dd.push((d >> i) & 1);
        cw = api.bch.encode(C, dd);
        for (e = 0; e < sets.length; e++) {
          r = cw.slice();
          for (i = 0; i < sets[e].length; i++) r[sets[e][i]] ^= 1;
          res = api.bch.decode(C, r);
          n++;
          if (res.kind !== (sets[e].length ? 'fixed' : 'ok') || !same(res.word, cw) || !same(res.data, dd) || res.pos.join() !== sets[e].join()) fail++;
        }
      }
    }
    return { n: n, fail: fail };                                    // n = 66 688
  }

  var api = {
    ham: { CODES: HCODES, code: hcode, coverage: hcoverage, encode: hencode, syndrome: hsyndrome, decode: hdecode, selfTest: hselfTest },
    bch: { N: NB, exp: EXP, log: LOG, mul: mul, div: div, pow: apow, peval: peval, code: bcode, encode: bencode, syndromes: bsyndromes,
      berlekampMassey: berlekampMassey, bm: bmFull, chien: chien, decode: bdecode, cliff: cliff, selfTest: bselfTest, combos: combos }
  };
  root.ECCHam = api.ham;
  root.ECCBch = api.bch;
})(typeof window !== 'undefined' ? window : globalThis);
