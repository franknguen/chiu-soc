/* Giao diện hai trình mô phỏng mục 6 và 7 của bài "Từ mã sửa lỗi lượng tử đến ECC trong con chip":
   - Hamming bốn bước (chọn mã + dữ liệu -> từ mã -> kênh nhiễu -> giải mã trên MA TRẬN KIỂM: mỗi hàng một phép kiểm,
     mỗi cột một vị trí; cột của ô hỏng có đúng hình các hàng báo lỗi, nên hội chứng đọc ra chính số thứ tự ô ấy).
   - BCH (15, k) năm bước (chọn t -> dữ liệu và từ mã -> kênh nhiễu -> ba khâu giải mã: hội chứng, Berlekamp–Massey,
     dò nghiệm Chien -> vách đá: đếm mọi mẫu lỗi).
   Mọi chuỗi hiện ra đều qua bi(vi, en). Mô hình ở ecc-hamming-bch.js; ô bit và vài hàm nhỏ dùng lại từ ecc-sim-ui.js.
   Original implementation for the ChiU·SoC ECC note. */
(function (root, doc) {
  'use strict';
  var H = root.ECCHam, B = root.ECCBch, lib = root.ECCSimPage.lib;
  var bi = lib.bi, num = lib.num, same = lib.same, randBits = lib.randBits, pick = lib.pick, renderBits = lib.renderBits;
  function $(id) { var el = doc.getElementById(id); if (!el) throw new Error('missing #' + id); return el; }
  var SUP = { '0': '⁰', '1': '¹', '2': '²', '3': '³', '4': '⁴', '5': '⁵', '6': '⁶', '7': '⁷', '8': '⁸', '9': '⁹', '-': '⁻' };
  var SUB = { '0': '₀', '1': '₁', '2': '₂', '3': '₃', '4': '₄', '5': '₅', '6': '₆', '7': '₇', '8': '₈', '9': '₉' };
  function sup(n) { return String(n).replace(/[-0-9]/g, function (c) { return SUP[c]; }); }
  function sub(n) { return String(n).replace(/[0-9]/g, function (c) { return SUB[c]; }); }
  function range(a, b) { var o = [], i; for (i = a; i <= b; i++) o.push(i); return o; }
  function diffs(a, b) { var o = [], i; for (i = 0; i < a.length; i++) if (a[i] !== b[i]) o.push(i); return o; }
  function checked(name) { var el = doc.querySelector('input[name="' + name + '"]:checked'); return el ? el.value : null; }
  function setChecked(name, v) { var el = doc.querySelector('input[name="' + name + '"][value="' + v + '"]'); if (el) el.checked = true; }
  function onChange(name, fn) { Array.prototype.forEach.call(doc.querySelectorAll('input[name="' + name + '"]'), function (el) { el.addEventListener('change', fn); }); }

  /* ================================================================ Hamming */
  var DEF_H = [0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1];   // 8 bit đầu = ví dụ trong bài
  var HM = { C: null, data: null, code: null, recv: null };
  function hmSet(id, data, flips) {
    HM.C = H.code(id); HM.data = data.slice(); HM.code = H.encode(HM.C, HM.data); HM.recv = HM.code.slice();
    (flips || []).forEach(function (p) { HM.recv[p - 1] ^= 1; });
    setChecked('hm-code', id); hmRender();
  }
  function hmEncode() { HM.code = H.encode(HM.C, HM.data); HM.recv = HM.code.slice(); }
  function hmRender() {
    var C = HM.C, two = 1 << C.r, roles = C.labels.map(function (l) { return l[0] === 'C' ? 'c' : 'd'; }), tops = range(1, C.n), i, cov = '';
    $('hm-rule').innerHTML = 'r = ' + C.r + ': 2' + sup(C.r) + ' = ' + two + ' ≥ k + r + 1 = ' + (C.k + C.r + 1) + ' ✓ · r = ' + (C.r - 1) + ': 2' + sup(C.r - 1) + ' = ' + (two >> 1) + ' &lt; ' + (C.k + C.r) + ' ✗ — ' +
      (two === C.n + 1 ? bi('vừa khít: mọi hội chứng khác 0 đều trỏ vào một ô — mã hoàn hảo.', 'an exact fit: every nonzero syndrome names a cell — a perfect code.')
        : bi('thừa ' + (two - C.n - 1) + ' hội chứng (' + range(C.n + 1, two - 1).join(', ') + ') không trỏ vào ô nào — mã rút gọn.', (two - C.n - 1) + ' syndromes (' + range(C.n + 1, two - 1).join(', ') + ') name no cell — a shortened code.'));
    renderBits($('hm-data'), HM.data, { labels: C.dataPos.map(function (p, j) { return 'D' + j; }), click: function (p) { HM.data[p] ^= 1; hmEncode(); hmRender(); } });
    renderBits($('hm-code'), HM.code, { tops: tops, labels: C.labels, roles: roles });
    for (i = 0; i < C.r; i++) {
      cov += '<div><b>C' + (1 << i) + '</b> = ' + H.coverage(C, i).map(function (p) { return C.labels[p - 1]; }).join(' ⊕ ') + ' = <b>' + HM.code[(1 << i) - 1] + '</b></div>';
    }
    $('hm-cover').innerHTML = cov;
    var fl = diffs(HM.recv, HM.code), fmap = {};
    fl.forEach(function (i) { fmap[i] = 1; });
    renderBits($('hm-recv'), HM.recv, { tops: tops, labels: C.labels, roles: roles, flips: fmap, click: function (p) { HM.recv[p] ^= 1; hmRender(); } });
    $('hm-nerr').innerHTML = fl.length === 0 ? bi('chưa có lỗi — bấm vào một ô', 'no error yet — click a cell')
      : bi(fl.length + ' bit đang lật (ô cam)', fl.length + (fl.length === 1 ? ' bit' : ' bits') + ' flipped (orange)');
    hmDecode(fl);
  }
  /* ma trận kiểm: hàng C8 ở trên, C1 ở dưới, để cột ⊕ đọc từ trên xuống chính là S viết nhị phân */
  function hmMatrix(r, fl) {
    var C = HM.C, p, i, f, row, h, v, cls, flipped = {};
    fl.forEach(function (i) { flipped[i + 1] = 1; });
    function colc(p) { return (flipped[p] ? ' cf' : '') + (r.kind === 'single' && p === r.pos ? (flipped[p] && fl.length === 1 ? ' cs' : ' cs bad') : ''); }
    h = '<table class="hmx"><tr><th class="rl">' + bi('vị trí', 'position') + '</th>';
    for (p = 1; p <= C.n; p++) h += '<th class="' + colc(p).trim() + '">' + p + '</th>';
    h += '<th>⊕</th></tr><tr><th class="rl">' + bi('từ nhận', 'received') + '</th>';
    for (p = 1; p <= C.n; p++) h += '<td class="rv' + colc(p) + '">' + HM.recv[p - 1] + '</td>';
    h += '<td></td></tr>';
    for (i = C.r - 1; i >= 0; i--) {
      row = '<tr><th class="rl">C' + (1 << i) + '′</th>'; v = 0;
      for (p = 1; p <= C.n; p++) {
        f = (p >> i) & 1;
        if (f) v ^= HM.recv[p - 1];
        row += '<td class="' + ((f ? 'cv' : '') + colc(p)).trim() + '">' + (f ? HM.recv[p - 1] : '') + '</td>';
      }
      cls = v ? 'res bad' : 'res ok';
      h += row + '<td class="' + cls + '">' + v + (v ? ' ✗' : ' ✓') + '</td></tr>';
    }
    return h + '</table>';
  }
  function hmDecode(fl) {
    var C = HM.C, r = H.decode(C, HM.recv), good = same(r.data, HM.data) && (r.kind !== 'invalid'), nerr = fl.length, cls, txt, i, bitsS = [], terms = [];
    $('hm-matrix').innerHTML = hmMatrix(r, fl);
    for (i = C.r - 1; i >= 0; i--) { bitsS.push((r.s >> i) & 1); if ((r.s >> i) & 1) terms.push(1 << i); }
    $('hm-syn').innerHTML = 'S = (' + range(0, C.r - 1).reverse().map(function (i) { return 'C' + (1 << i) + '′'; }).join(' ') + ') = ' + bitsS.join(' ') +
      (terms.length > 1 ? ' = ' + terms.join(' + ') : '') + ' = <b>' + r.s + '</b>';
    var where = fl.map(function (i) { return i + 1; }).join(', ');
    if (r.kind === 'ok') {
      cls = nerr ? 'bad' : 'ok';
      txt = nerr === 0 ? bi('S = 0: mọi phép kiểm đều đúng — không lỗi.', 'S = 0: every check passes — no error.')
        : bi('S = 0 nên bộ giải mã nói "không lỗi" — nhưng có ' + nerr + ' bit lật (ô ' + where + '): lỗi đã biến từ mã này thành đúng một từ mã khác, và không gì phát hiện được.',
          'S = 0, so the decoder says "no error" — yet ' + nerr + ' bits are flipped (cells ' + where + '): the errors turned this codeword into another valid one, and nothing can tell.');
    } else if (r.kind === 'single' && good) {
      cls = 'ok';
      txt = bi('Một lỗi: hàng ✗ đọc từ trên xuống cho S = ' + r.s + ', và cột ' + r.s + ' của ma trận có đúng hình ấy → lật lại ô ' + r.s + ' (' + C.labels[r.s - 1] + '). Dữ liệu trở về nguyên vẹn.',
        'One error: the ✗ rows read top to bottom give S = ' + r.s + ', and column ' + r.s + ' of the matrix has exactly that shape → flip cell ' + r.s + ' (' + C.labels[r.s - 1] + ') back. The data is whole again.');
    } else if (r.kind === 'single') {
      cls = 'bad';
      txt = nerr === 2
        ? bi('<strong>Sửa sai:</strong> thực ra có 2 bit lật (ô ' + where + '), nhưng S = ' + (fl[0] + 1) + ' ⊕ ' + (fl[1] + 1) + ' = ' + r.s + ' trỏ vào ô ' + r.s + ' — một ô lành. Sau khi "sửa", từ có 3 bit sai mà bộ giải mã vẫn tin mình đúng. Mã Hamming không phân biệt được một lỗi với hai lỗi; thêm một bit chẵn lẻ P là thành SECDED ở trình mô phỏng bên dưới.',
          '<strong>Mis-corrected:</strong> 2 bits are really flipped (cells ' + where + '), but S = ' + (fl[0] + 1) + ' ⊕ ' + (fl[1] + 1) + ' = ' + r.s + ' points at cell ' + r.s + ' — a healthy one. After the "fix" the word has 3 wrong bits and the decoder still believes it. A Hamming code cannot tell one error from two; add a parity bit P and you get the SECDED code of the simulator below.')
        : bi('<strong>Sửa sai mà không biết:</strong> có ' + nerr + ' bit lật (ô ' + where + '), bộ giải mã lật ô ' + r.s + ' và tin là mình đúng. Hamming chỉ hứa sửa một lỗi.',
          '<strong>Silently mis-corrected:</strong> ' + nerr + ' bits are flipped (cells ' + where + '), the decoder flips cell ' + r.s + ' and believes it. Hamming only promises to fix one error.');
    } else {
      cls = 'warn';
      txt = bi('S = ' + r.s + ' không trỏ vào ô nào (mã rút gọn này chỉ có ' + C.n + ' ô): chắc chắn có hơn một lỗi — <strong>phát hiện được, không sửa</strong>. Mã đầy đủ (7, 4) và (15, 11) không có hội chứng "thừa" như vậy, nên hai lỗi luôn bị sửa sai.',
        'S = ' + r.s + ' names no cell (this shortened code has only ' + C.n + ' cells): more than one error for certain — <strong>detected, not corrected</strong>. The full codes (7, 4) and (15, 11) have no spare syndromes like this, so two errors are always mis-corrected.');
    }
    $('hm-verdict').className = 'verdict ' + cls;
    $('hm-verdict').innerHTML = txt;
    $('hm-out').innerHTML = r.kind === 'invalid' ? bi('Không có dữ liệu ra: bộ giải mã từ chối sửa.', 'No data out: the decoder refuses to correct.')
      : bi('Dữ liệu sau giải mã: ', 'Data after decoding: ') + '<b>' + r.data.join(' ') + '</b> — ' +
        (good ? bi('bằng dữ liệu gốc ✓', 'equals the original ✓') : bi('<strong>khác dữ liệu gốc ✗</strong>', '<strong>differs from the original ✗</strong>'));
  }
  function hmFlipRandom(k, fresh) {
    if (fresh) HM.recv = HM.code.slice();
    var cand = [], i;
    for (i = 0; i < HM.C.n; i++) if (HM.recv[i] === HM.code[i]) cand.push(i);
    pick(cand.length, k).forEach(function (j) { HM.recv[cand[j]] ^= 1; });
    hmRender();
  }
  onChange('hm-code', function () { var C = H.code(checked('hm-code')); hmSet(C.id, DEF_H.slice(0, C.k), [5]); });
  $('hm-example').addEventListener('click', function () { hmSet('12,8', DEF_H.slice(0, 8), [5]); });
  $('hm-rand').addEventListener('click', function () { HM.data = randBits(HM.C.k); hmEncode(); hmRender(); });
  $('hm-flip1').addEventListener('click', function () { hmFlipRandom(1, false); });
  $('hm-flip2').addEventListener('click', function () { hmFlipRandom(2, true); });
  $('hm-clear').addEventListener('click', function () { HM.recv = HM.code.slice(); hmRender(); });
  $('hm-selftest').addEventListener('click', function () {
    var r = H.selfTest(), el = $('hm-st');
    el.className = 'st ' + (r.fail ? 'bad' : 'ok');
    el.innerHTML = r.fail ? bi('✗ ' + num(r.fail) + ' trường hợp sai trong ' + num(r.n), '✗ ' + num(r.fail) + ' of ' + num(r.n) + ' cases wrong')
      : bi('✓ ' + num(r.n) + ' / ' + num(r.n) + ' — mọi từ có ≤ 1 lỗi được sửa đúng, mọi từ có 2 lỗi cho S = a ⊕ b', '✓ ' + num(r.n) + ' / ' + num(r.n) + ' — every word with ≤ 1 error recovers, every 2-error word gives S = a ⊕ b');
  });

  /* ================================================================ BCH */
  var DEF_B = [1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1], DEF_E = [3, 10, 13];
  var BC = { C: null, data: null, code: null, recv: null }, CLIFF = {};
  function gfs(v) { return v === 0 ? '0' : v === 1 ? '1' : 'α' + sup(B.log[v]); }
  function bin4(v) { return [8, 4, 2, 1].map(function (b) { return (v & b) ? 1 : 0; }).join(''); }
  function poly2(c) {                             // đa thức hệ số 0/1, viết từ bậc cao xuống
    var t = [], i;
    for (i = c.length - 1; i >= 0; i--) if (c[i]) t.push(i === 0 ? '1' : i === 1 ? 'x' : 'x' + sup(i));
    return t.length ? t.join(' + ') : '0';
  }
  function polyGF(L) {                            // Λ(x), hệ số GF(16), viết từ bậc thấp lên
    var t = [], i;
    for (i = 0; i < L.length; i++) if (L[i]) t.push(i === 0 ? gfs(L[i]) : (L[i] === 1 ? '' : gfs(L[i])) + (i === 1 ? 'x' : 'x' + sup(i)));
    return t.join(' + ');
  }
  function bcSet(t, data, flips) {
    BC.C = B.code(t); BC.data = data.slice(); BC.code = B.encode(BC.C, BC.data); BC.recv = BC.code.slice();
    (flips || []).forEach(function (p) { BC.recv[p] ^= 1; });
    setChecked('bc-t', String(t)); bcRender();
  }
  function bcEncode() { BC.code = B.encode(BC.C, BC.data); BC.recv = BC.code.slice(); }
  function bcRender() {
    var C = BC.C, nk = C.n - C.k, labels = [], roles = [], i, prev;
    for (i = 0; i < C.n; i++) { labels.push(i < nk ? 'C' + i : 'D' + (i - nk)); roles.push(i < nk ? 'c' : 'd'); }
    $('bc-g').innerHTML = 'g(x) = ' + C.m.map(function (m) { return 'm' + sub(m.j) + '(x)'; }).join(' · ') + ' = ' +
      (C.m.length > 1 ? C.m.map(function (m) { return '(' + poly2(m.poly) + ')'; }).join('') + ' = ' : '') + '<b>' + poly2(C.g) + '</b>';
    prev = C.t > 1 ? nk - (B.code(C.t - 1).n - B.code(C.t - 1).k) : 0;
    $('bc-param').innerHTML = bi('bậc ' + nk + ' → ' + nk + ' bit kiểm, k = 15 − ' + nk + ' = ' + C.k + ' bit dữ liệu, tỉ lệ mã R = ' + C.k + '/15 ≈ ' + (C.k / 15).toFixed(2).replace('.', ',') + ', d<sub>min</sub> = ' + (2 * C.t + 1) + '.',
      'degree ' + nk + ' → ' + nk + ' check bits, k = 15 − ' + nk + ' = ' + C.k + ' data bits, code rate R = ' + C.k + '/15 ≈ ' + (C.k / 15).toFixed(2) + ', d<sub>min</sub> = ' + (2 * C.t + 1) + '.') +
      (C.t === 2 ? ' ' + bi('So với t = 1: thêm ' + prev + ' bit kiểm.', 'Compared with t = 1: ' + prev + ' more check bits.') : '') +
      (C.t === 3 ? ' ' + bi('So với t = 2: chỉ thêm ' + prev + ' bit kiểm — vì α⁵ chỉ có hai "anh em" {α⁵, α¹⁰}, nên m₅(x) chỉ bậc 2.', 'Compared with t = 2: only ' + prev + ' more check bits — α⁵ has just two "siblings" {α⁵, α¹⁰}, so m₅(x) has degree 2.') : '');
    renderBits($('bc-data'), BC.data, { labels: range(0, C.k - 1).map(function (j) { return 'D' + j; }), click: function (p) { BC.data[p] ^= 1; bcEncode(); bcRender(); } });
    renderBits($('bc-code'), BC.code, { tops: range(0, C.n - 1), labels: labels, roles: roles });
    $('bc-poly').innerHTML = 'c(x) = ' + poly2(BC.code);
    var fl = diffs(BC.recv, BC.code), fmap = {};
    fl.forEach(function (i) { fmap[i] = 1; });
    renderBits($('bc-recv'), BC.recv, { tops: range(0, C.n - 1), labels: labels, roles: roles, flips: fmap, click: function (p) { BC.recv[p] ^= 1; bcRender(); } });
    $('bc-nerr').innerHTML = fl.length === 0 ? bi('chưa có lỗi — bấm vào một ô', 'no error yet — click a cell')
      : bi(fl.length + ' bit đang lật (ô cam) — mã này sửa được tới t = ' + C.t, fl.length + (fl.length === 1 ? ' bit' : ' bits') + ' flipped (orange) — this code fixes up to t = ' + C.t);
    bcDecode(fl);
    bcCliff(fl.length);
  }
  function bcDecode(fl) {
    var C = BC.C, r = B.decode(C, BC.recv), good = r.kind !== 'fail' && same(r.word, BC.code), nerr = fl.length, fmap = {}, i, h, cls, txt, ch, deg;
    fl.forEach(function (i) { fmap[i] = 1; });
    h = '';
    for (i = 0; i < r.S.length; i++) h += '<div>S' + sub(i + 1) + ' = r(α' + (i ? sup(i + 1) : '') + ') = <b>' + gfs(r.S[i]) + '</b> <span class="gfb">= ' + bin4(r.S[i]) + '</span></div>';
    $('bc-syn').innerHTML = h;
    var zero = r.S.every(function (s) { return s === 0; });
    deg = r.L.length - 1;
    $('bc-lam').innerHTML = zero ? bi('Mọi S = 0 → không có gì để giải.', 'Every S = 0 → nothing to solve.')
      : 'Λ(x) = <b>' + polyGF(r.L) + '</b> · ' + bi('bậc ' + r.reg + ' → đoán có ' + r.reg + ' ô lỗi', 'degree ' + r.reg + ' → it guesses ' + r.reg + (r.reg === 1 ? ' broken cell' : ' broken cells'));
    ch = B.chien(r.L);
    h = '';
    for (i = 0; i < C.n; i++) {
      cls = 'gfv' + (zero ? (fmap[i] ? ' miss' : '') : ch.vals[i] === 0 ? (fmap[i] ? ' root' : ' root bad') : (fmap[i] ? ' miss' : ''));
      h += '<span class="bitc"><span>' + i + '</span><span class="' + cls + '">' + (zero ? '·' : gfs(ch.vals[i])) + '</span></span>';
    }
    $('bc-chien').innerHTML = h;
    var where = fl.join(', ');
    if (r.kind === 'ok') {
      cls = nerr ? 'bad' : 'ok';
      txt = nerr === 0 ? bi('Mọi hội chứng bằng 0: r(x) chia hết cho g(x) — không lỗi.', 'Every syndrome is 0: r(x) is divisible by g(x) — no error.')
        : bi('Mọi hội chứng bằng 0 nên bộ giải mã nói "không lỗi" — nhưng có ' + nerr + ' bit lật (ô ' + where + '): mẫu lỗi trùng đúng một từ mã khác (cần ít nhất d<sub>min</sub> = ' + (2 * C.t + 1) + ' bit), không gì phát hiện được.',
          'Every syndrome is 0, so the decoder says "no error" — yet ' + nerr + ' bits are flipped (cells ' + where + '): the error pattern is itself another codeword (it takes at least d<sub>min</sub> = ' + (2 * C.t + 1) + ' bits), and nothing can tell.');
    } else if (r.kind === 'fixed' && good) {
      cls = 'ok';
      txt = bi('Λ(x) bậc ' + deg + ' có đúng ' + deg + ' nghiệm → lật lại ô ' + r.pos.join(', ') + '. Từ mã trở về nguyên vẹn ✓', 'Λ(x) of degree ' + deg + ' has exactly ' + deg + (deg === 1 ? ' root' : ' roots') + ' → flip cells ' + r.pos.join(', ') + ' back. The codeword is whole again ✓');
    } else if (r.kind === 'fixed') {
      cls = 'bad';
      txt = bi('<strong>Sửa sai mà không biết:</strong> thực ra có ' + nerr + ' bit lật (ô ' + where + '), nhiều hơn t = ' + C.t + '. Bộ giải mã tìm thấy một từ mã KHÁC cách r(x) không quá t bit, lật ô ' + r.pos.join(', ') + ' và tin là mình đúng. Đây là vách đá ở mục 9.',
        '<strong>Silently mis-corrected:</strong> ' + nerr + ' bits are really flipped (cells ' + where + '), more than t = ' + C.t + '. The decoder found a DIFFERENT codeword within t bits of r(x), flipped cells ' + r.pos.join(', ') + ' and believes it. This is the cliff of section 9.');
    } else {
      cls = 'warn';
      txt = bi((r.reg > C.t ? 'Muốn giải thích các hội chứng, Berlekamp–Massey cần tới ' + r.reg + ' lỗi, nhiều hơn t = ' + C.t : 'Λ(x) bậc ' + deg + ' nhưng chỉ có ' + ch.roots.length + ' nghiệm trong 15 vị trí') + ' → không từ mã nào cách r(x) ≤ ' + C.t + ' bit: <strong>phát hiện được, không sửa</strong>. Hệ thống phải đọc lại hoặc báo lỗi.',
        (r.reg > C.t ? 'To explain the syndromes Berlekamp–Massey needs ' + r.reg + ' errors, more than t = ' + C.t : 'Λ(x) has degree ' + deg + ' but only ' + ch.roots.length + (ch.roots.length === 1 ? ' root' : ' roots') + ' among the 15 positions') + ' → no codeword lies within ' + C.t + ' bits of r(x): <strong>detected, not corrected</strong>. The system must re-read or raise an error.');
    }
    $('bc-verdict').className = 'verdict ' + cls;
    $('bc-verdict').innerHTML = txt;
    $('bc-out').innerHTML = r.kind === 'fail' ? bi('Không có dữ liệu ra: bộ giải mã từ chối sửa.', 'No data out: the decoder refuses to correct.')
      : bi('Dữ liệu sau giải mã: ', 'Data after decoding: ') + '<b>' + r.data.join(' ') + '</b> — ' +
        (same(r.data, BC.data) ? bi('bằng dữ liệu gốc ✓', 'equals the original ✓') : bi('<strong>khác dữ liệu gốc ✗</strong>', '<strong>differs from the original ✗</strong>'));
  }
  /* vách đá: đếm trên mọi mẫu lỗi (2^15), tính một lần cho mỗi t */
  function bcCliff(nerr) {
    var C = BC.C, rows = CLIFF[C.t] || (CLIFF[C.t] = B.cliff(C)), h, e, x, w3;
    h = '<table class="cliff"><tr><th>' + bi('số bit lỗi', 'bits flipped') + '</th><th>' + bi('số mẫu', 'patterns') + '</th><th>' + bi('sửa đúng', 'fixed right') +
      '</th><th>' + bi('phát hiện', 'detected') + '</th><th>' + bi('sửa sai / bỏ lọt', 'mis-corrected / missed') + '</th><th class="barh"></th></tr>';
    for (e = 1; e <= 6; e++) {
      x = rows[e];
      h += '<tr class="' + (e === nerr ? 'cur' : '') + (e === C.t + 1 ? ' edge' : '') + '"><td>' + e + '</td><td>' + num(x.total) + '</td><td class="g">' + num(x.right) + '</td><td class="a">' + num(x.detected) + '</td><td class="r">' + num(x.wrong) + '</td>' +
        '<td class="barc"><span class="bar"><i class="g" style="width:' + (100 * x.right / x.total) + '%"></i><i class="a" style="width:' + (100 * x.detected / x.total) + '%"></i><i class="r" style="width:' + (100 * x.wrong / x.total) + '%"></i></span></td></tr>';
    }
    $('bc-cliff').innerHTML = h + '</table>';
    w3 = rows[C.t + 1];
    $('bc-cliff-note').innerHTML = bi('Tới t = ' + C.t + ' lỗi: mọi mẫu được sửa đúng. Chỉ thêm một lỗi (' + (C.t + 1) + '): ' + num(w3.wrong) + ' / ' + num(w3.total) + ' mẫu bị sửa sai mà bộ giải mã không biết, ' + num(w3.detected) + ' mẫu bị phát hiện, không mẫu nào được sửa đúng.',
      'Up to t = ' + C.t + ' errors: every pattern is fixed right. One more error (' + (C.t + 1) + '): ' + num(w3.wrong) + ' / ' + num(w3.total) + ' patterns are mis-corrected without the decoder knowing, ' + num(w3.detected) + ' are detected, none is fixed right.') +
      (C.t === 1 ? ' ' + bi('Với t = 1, mã này chính là một mã Hamming (15, 11) viết dạng vòng — mã hoàn hảo, nên không có hội chứng nào để "phát hiện".', 'With t = 1 this code is a Hamming (15, 11) code in cyclic form — a perfect code, so there is no syndrome left over to "detect" with.') : '');
  }
  function bcFlipRandom(k) {
    BC.recv = BC.code.slice();
    pick(BC.C.n, k).forEach(function (p) { BC.recv[p] ^= 1; });
    bcRender();
  }
  onChange('bc-t', function () { var t = +checked('bc-t'), C = B.code(t); bcSet(t, DEF_B.slice(0, C.k), DEF_E.slice(0, t)); });
  $('bc-rand').addEventListener('click', function () { BC.data = randBits(BC.C.k); bcEncode(); bcRender(); });
  $('bc-flipt').addEventListener('click', function () { bcFlipRandom(BC.C.t); });
  $('bc-flipt1').addEventListener('click', function () { bcFlipRandom(BC.C.t + 1); });
  $('bc-clear').addEventListener('click', function () { BC.recv = BC.code.slice(); bcRender(); });
  $('bc-selftest').addEventListener('click', function () {
    var r = B.selfTest(), el = $('bc-st');
    el.className = 'st ' + (r.fail ? 'bad' : 'ok');
    el.innerHTML = r.fail ? bi('✗ ' + num(r.fail) + ' trường hợp sai trong ' + num(r.n), '✗ ' + num(r.fail) + ' of ' + num(r.n) + ' cases wrong')
      : bi('✓ ' + num(r.n) + ' / ' + num(r.n) + ' — mọi từ có ≤ t lỗi trở về đúng từ mã, đúng các ô lỗi', '✓ ' + num(r.n) + ' / ' + num(r.n) + ' — every word with ≤ t errors returns to its codeword, at the right cells');
  });
  (function () {                                  // bảng GF(16), vẽ một lần
    var h = '<span class="gfe"><b>0</b> = 0000</span>', i;
    for (i = 0; i < 15; i++) h += '<span class="gfe"><b>α' + sup(i) + '</b> = ' + bin4(B.exp[i]) + '</span>';
    $('bc-gf').innerHTML = h;
  })();

  /* ================================================================ khởi động: đúng ví dụ trong bài, bit 5 lật */
  hmSet('12,8', DEF_H.slice(0, 8), [5]);
  bcSet(2, DEF_B.slice(0, 7), DEF_E.slice(0, 2));

  root.ECCHbPage = {
    HM: HM, BC: BC,
    hamSet: hmSet, hamFlip: function (p) { HM.recv[p - 1] ^= 1; hmRender(); }, hamData: function (j) { HM.data[j] ^= 1; hmEncode(); hmRender(); },
    bchSet: bcSet, bchFlip: function (p) { BC.recv[p] ^= 1; bcRender(); }
  };
})(window, document);
