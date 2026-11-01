/* Mô hình cho hai trình mô phỏng của bài "Từ mã sửa lỗi lượng tử đến ECC trong con chip":
   - SECDED (13, 8): cách xếp đúng như ví dụ trong bài - bit kiểm C1 C2 C4 C8 ở vị trí 1 2 4 8, tám bit dữ liệu
     D0..D7 ở các vị trí 3 5 6 7 9 10 11 12, thêm bit P ở vị trí 0 là chẵn lẻ của cả 12 bit. Hội chứng S (4 bit)
     đọc ra đúng số thứ tự của vị trí hỏng; P' tách "một lỗi" khỏi "hai lỗi".
   - Sketch hội chứng cho PUF: dấu vân tay R = 4 khối x 13 bit; dữ liệu trợ giúp W = (S, P) của từng khối; khi
     đọc lại R' = R ^ e thì (S', P') ^ W = hội chứng của riêng e, và bộ giải mã SECDED tìm e như với một từ mã.
   Mọi bit là số 0/1 trong mảng thường, chỉ số = vị trí. Chạy cả trong trình duyệt lẫn Node (không có DOM).
   Original implementation for the ChiU·SoC ECC note. */
(function (root) {
  'use strict';
  var N = 13, K = 8, NB = 4;
  var DATA_POS = [3, 5, 6, 7, 9, 10, 11, 12], CHECK_POS = [1, 2, 4, 8];

  function bits(x, what) {
    if (!x || typeof x.length !== 'number') throw new Error(what + ' phải là mảng bit');
    var out = new Array(x.length), i;
    for (i = 0; i < x.length; i++) out[i] = x[i] & 1;
    return out;
  }
  /* vị trí mà bit kiểm thứ i phụ trách: mọi vị trí 1..12 có bit i trong chỉ số nhị phân (trừ chính nó) */
  function coverage(i) {
    var out = [], p;
    for (p = 1; p < N; p++) if (((p >> i) & 1) && p !== CHECK_POS[i]) out.push(p);
    return out;
  }
  function encode(d) {
    d = bits(d, 'dữ liệu');
    if (d.length !== K) throw new Error('cần đúng 8 bit dữ liệu');
    var c = [], i, p, x;
    for (i = 0; i < N; i++) c.push(0);
    for (i = 0; i < K; i++) c[DATA_POS[i]] = d[i];
    for (i = 0; i < 4; i++) {
      x = 0;
      for (p = 1; p < N; p++) if ((p >> i) & 1) x ^= c[p];            // bit kiểm còn là 0 nên không tự cộng
      c[CHECK_POS[i]] = x;
    }
    x = 0;
    for (p = 1; p < N; p++) x ^= c[p];
    c[0] = x;
    return c;
  }
  /* S = C1'C2'C4'C8' tính lại trên từ nhận; P' = chẵn lẻ của cả 13 bit */
  function syndrome(c) {
    c = bits(c, 'từ mã');
    if (c.length !== N) throw new Error('cần đúng 13 bit');
    var s = 0, i, p, x, q = 0;
    for (i = 0; i < 4; i++) {
      x = 0;
      for (p = 1; p < N; p++) if ((p >> i) & 1) x ^= c[p];
      s |= x << i;
    }
    for (p = 0; p < N; p++) q ^= c[p];
    return { s: s, p: q };
  }
  function dataOf(c) { return DATA_POS.map(function (p) { return c[p]; }); }
  /* quyết định SECDED từ (S, P'): ok | parity (chỉ bit P hỏng) | single (lật vị trí S) | double (phát hiện,
     KHÔNG sửa) | invalid (S = 13..15 không là vị trí nào: từ 3 lỗi trở lên) */
  function decodeSyn(c, s, p) {
    var out = bits(c, 'từ mã'), kind, pos = -1;
    if (s === 0 && p === 0) kind = 'ok';
    else if (s === 0) { kind = 'parity'; pos = 0; out[0] ^= 1; }
    else if (p === 1) { if (s < N) { kind = 'single'; pos = s; out[pos] ^= 1; } else kind = 'invalid'; }
    else kind = 'double';
    return { kind: kind, pos: pos, s: s, p: p, word: out, data: dataOf(out), fixed: kind === 'ok' || kind === 'single' || kind === 'parity' };
  }
  function decode(c) { var sp = syndrome(c); return decodeSyn(c, sp.s, sp.p); }

  /* ---------------- PUF: sketch hội chứng trên 4 khối */
  function enroll(R) {
    R = bits(R, 'R');
    if (R.length !== NB * N) throw new Error('R cần ' + NB * N + ' bit');
    var W = [], b;
    for (b = 0; b < NB; b++) W.push(syndrome(R.slice(b * N, b * N + N)));
    return W;
  }
  function reconstruct(Rp, W) {
    Rp = bits(Rp, "R'");
    if (Rp.length !== NB * N || !W || W.length !== NB) throw new Error('R′ cần ' + NB * N + ' bit và W cần ' + NB + ' khối');
    var word = [], blocks = [], ok = true, b, blk, sp, r;
    for (b = 0; b < NB; b++) {
      blk = Rp.slice(b * N, b * N + N);
      sp = syndrome(blk);
      r = api.decodeSyn(blk, sp.s ^ W[b].s, sp.p ^ W[b].p);
      blocks.push(r);
      word = word.concat(r.word);
      if (!r.fixed) ok = false;
    }
    return { word: word, blocks: blocks, ok: ok };
  }
  /* 52 bit -> 7 byte (bit đầu là MSB của byte đầu, 4 bit cuối của byte 7 là 0) -> SHA-256 -> 16 byte đầu, hex */
  function pack(R) {
    var out = new Uint8Array(Math.ceil(R.length / 8)), i;
    for (i = 0; i < R.length; i++) if (R[i] & 1) out[i >> 3] |= 0x80 >> (i & 7);
    return out;
  }
  function keyOf(R) {
    if (!root.PQCSHA2 || !root.PQCSHA2.sha256) throw new Error('thiếu pqc-sha2.js');
    var h = root.PQCSHA2.sha256(pack(bits(R, 'R'))), s = '', i;
    for (i = 0; i < 16; i++) s += (h[i] < 16 ? '0' : '') + h[i].toString(16);
    return s;
  }

  /* ---------------- tự kiểm: mọi dữ liệu x mọi mẫu lỗi tới 2 bit = 256 x (1 + 13 + 78) = 23 552 trường hợp.
     Dùng api.encode / api.decode (không phải hàm trong closure) để một bản vá từ ngoài làm nó đỏ được. */
  function selfTest() {
    var n = 0, fail = 0, d, i, j, k, dd, cw, w, r, ex;
    function chk(ok) { n++; if (!ok) fail++; }
    function same(a, b) { for (var t = 0; t < a.length; t++) if (a[t] !== b[t]) return false; return true; }
    for (d = 0; d < 256; d++) {
      dd = [];
      for (i = 0; i < K; i++) dd.push((d >> i) & 1);
      cw = api.encode(dd);
      r = api.decode(cw);
      chk(r.kind === 'ok' && same(r.data, dd));
      for (i = 0; i < N; i++) {
        w = cw.slice(); w[i] ^= 1; r = api.decode(w);
        chk((r.kind === 'single' || r.kind === 'parity') && r.pos === i && same(r.data, dd) && same(r.word, cw));
        for (j = i + 1; j < N; j++) {
          w = cw.slice(); w[i] ^= 1; w[j] ^= 1; r = api.decode(w);
          chk(r.kind === 'double' && !r.fixed);
        }
      }
    }
    ex = api.encode([0, 1, 0, 0, 1, 1, 1, 1]);                      // ví dụ trong bài: 12 bit sau P
    k = ex.slice(); k[5] ^= 1; r = api.decode(k);
    if (ex.slice(1).join('') !== '100010001111' || r.kind !== 'single' || r.pos !== 5 || r.s !== 5) fail++;
    return { n: n, fail: fail };                                    // n = 23 552 mẫu; ví dụ trong bài chỉ cộng vào fail
  }

  var api = {
    N: N, K: K, NB: NB, DATA_POS: DATA_POS, CHECK_POS: CHECK_POS,
    coverage: coverage, encode: encode, syndrome: syndrome, decodeSyn: decodeSyn, decode: decode, dataOf: dataOf,
    enroll: enroll, reconstruct: reconstruct, pack: pack, keyOf: keyOf, selfTest: selfTest
  };
  root.ECCSim = api;
})(typeof window !== 'undefined' ? window : globalThis);
