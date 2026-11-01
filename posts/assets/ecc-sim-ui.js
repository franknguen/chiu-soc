/* Giao diện hai trình mô phỏng trong bài "Từ mã sửa lỗi lượng tử đến ECC trong con chip": SECDED (13, 8) bốn bước
   (dữ liệu -> từ mã -> kênh nhiễu -> giải mã) và khoá PUF ba bước (xuất xưởng -> đọc lại -> sửa rồi băm).
   Mọi chuỗi hiện ra đều qua bi(vi, en) để nút VI | EN của trang vẫn đổi được. Mô hình nằm ở ecc-sim.js.
   Original implementation for the ChiU·SoC ECC note. */
(function (root, doc) {
  'use strict';
  var E = root.ECCSim;
  function $(id) { var el = doc.getElementById(id); if (!el) throw new Error('missing #' + id); return el; }
  function bi(vi, en) { return '<span lang="vi">' + vi + '</span><span lang="en">' + en + '</span>'; }
  function num(n) { var s = String(n), o = ''; while (s.length > 3) { o = ' ' + s.slice(-3) + o; s = s.slice(0, -3); } return s + o; }
  function hex2(bits) { var v = 0, i; for (i = 0; i < bits.length; i++) v |= bits[i] << i; return '0x' + (v < 16 ? '0' : '') + v.toString(16).toUpperCase(); }
  function same(a, b) { var i; if (a.length !== b.length) return false; for (i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }
  function randBits(n) {
    var a = new Uint8Array(n), out = [], i;
    if (root.crypto && root.crypto.getRandomValues) root.crypto.getRandomValues(a); else for (i = 0; i < n; i++) a[i] = Math.random() * 256;
    for (i = 0; i < n; i++) out.push(a[i] & 1);
    return out;
  }
  function pick(n, k) {                       // k vị trí khác nhau trong 0..n-1
    var pool = [], out = [], i, j, r = randBits(0);
    for (i = 0; i < n; i++) pool.push(i);
    for (i = 0; i < k && pool.length; i++) { j = Math.floor(Math.random() * pool.length); out.push(pool.splice(j, 1)[0]); }
    return out.sort(function (a, b) { return a - b; });
  }
  var ROLE = [], LABEL = [];
  (function () { var p, d = 0; for (p = 0; p < E.N; p++) { if (p === 0) { ROLE.push('p'); LABEL.push('P'); } else if (E.CHECK_POS.indexOf(p) >= 0) { ROLE.push('c'); LABEL.push('C' + p); } else { ROLE.push('d'); LABEL.push('D' + (d++)); } } })();
  function dlabel(pos) { return LABEL[pos]; }

  /* một hàng ô bit. opts: labels (dưới), tops (trên), roles, flips (Set vị trí), fixed (Set), wrong (Set), click(pos) */
  function renderBits(el, bits, opts) {
    opts = opts || {};
    var html = '', i, cls;
    for (i = 0; i < bits.length; i++) {
      cls = 'bit' + (bits[i] ? ' on' : '') + (opts.roles ? ' role-' + opts.roles[i] : '');
      if (opts.flips && opts.flips[i]) cls += ' flip';
      if (opts.fixed && opts.fixed[i]) cls += ' fixed';
      if (opts.click) cls += ' click';
      html += '<span class="bitc">' + (opts.tops ? '<span>' + opts.tops[i] + '</span>' : '') +
        '<button type="button" class="' + cls + '" data-pos="' + i + '"' + (opts.click ? '' : ' tabindex="-1"') + '>' + bits[i] + '</button>' +
        (opts.labels ? '<span>' + opts.labels[i] + '</span>' : '') + '</span>';
    }
    el.innerHTML = html;
    if (opts.click) el.onclick = function (ev) { var b = ev.target.closest ? ev.target.closest('button[data-pos]') : null; if (b) opts.click(+b.getAttribute('data-pos')); };
    else el.onclick = null;
  }
  var POS = [], DL = [];
  (function () { var i; for (i = 0; i < E.N; i++) { POS.push(String(i)); DL.push(LABEL[i]); } })();

  /* ================================================================ SECDED */
  var S = { data: [0, 1, 0, 0, 1, 1, 1, 1], code: null, recv: null };
  function sdEncode() { S.code = E.encode(S.data); S.recv = S.code.slice(); }
  function sdFlips() { var f = {}, n = 0, i; for (i = 0; i < E.N; i++) if (S.recv[i] !== S.code[i]) { f[i] = 1; n++; } return { map: f, n: n }; }
  function sdRender() {
    renderBits($('sd-data'), S.data, { labels: ['D0', 'D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7'], click: function (p) { S.data[p] ^= 1; sdEncode(); sdRender(); } });
    $('sd-hex').textContent = hex2(S.data);
    renderBits($('sd-code'), S.code, { tops: POS, labels: DL, roles: ROLE });
    var cov = '', i, j, terms, v;
    for (i = 0; i < 4; i++) {
      terms = E.coverage(i).map(function (p) { return dlabel(p); }).join(' ⊕ ');
      v = S.code[E.CHECK_POS[i]];
      cov += '<div><b>C' + E.CHECK_POS[i] + '</b> = ' + terms + ' = <b>' + v + '</b></div>';
    }
    cov += '<div><b>P</b> = ' + bi('chẵn lẻ của cả 12 bit', 'parity of all 12 bits') + ' = <b>' + S.code[0] + '</b></div>';
    $('sd-cover').innerHTML = cov;
    var f = sdFlips();
    renderBits($('sd-recv'), S.recv, { tops: POS, labels: DL, roles: ROLE, flips: f.map, click: function (p) { S.recv[p] ^= 1; sdRender(); } });
    $('sd-nerr').innerHTML = f.n === 0 ? bi('chưa có lỗi — bấm vào một ô', 'no error yet — click a cell')
      : bi(f.n + ' bit đang lật (ô cam)', f.n + (f.n === 1 ? ' bit' : ' bits') + ' flipped (orange)');
    sdDecode(f.n);
  }
  function sbits(s) { return [8, 4, 2, 1].map(function (b) { return (s & b) ? 1 : 0; }).join(' '); }
  function sdDecode(nerr) {
    var r = E.decode(S.recv), good = same(r.data, S.data), cls, txt, out;
    $('sd-syn').innerHTML = 'S = (C8′ C4′ C2′ C1′) = ' + sbits(r.s) + ' = <b>' + r.s + '</b> · P′ = <b>' + r.p + '</b>';
    if (r.kind === 'ok') {
      cls = good ? 'ok' : 'bad';
      txt = good ? bi('Không lỗi: S = 0 và P′ = 0.', 'No error: S = 0 and P′ = 0.')
        : bi('S = 0 và P′ = 0 nên bộ giải mã nói "không lỗi" — nhưng từ nhận có ' + nerr + ' bit lật: các lỗi đã đẩy sang một từ mã khác, và không gì phát hiện được.',
          'S = 0 and P′ = 0, so the decoder says "no error" — yet ' + nerr + ' bits are flipped: the errors landed on another valid codeword, and nothing can tell.');
    } else if (r.kind === 'parity') {
      cls = good ? 'ok' : 'bad';
      txt = bi('Chỉ bit P hỏng (S = 0, P′ = 1): lật lại ô 0, dữ liệu không bị động tới.', 'Only bit P is wrong (S = 0, P′ = 1): flip cell 0 back, the data was never touched.');
      if (!good) txt += ' ' + bi('Nhưng thực ra có ' + nerr + ' bit lật — dữ liệu ra sai mà bộ giải mã không biết.', 'But ' + nerr + ' bits are really flipped — the data is wrong and the decoder cannot know.');
    } else if (r.kind === 'single') {
      cls = good ? 'ok' : 'bad';
      txt = bi('Một lỗi (S ≠ 0, P′ = 1): S = ' + r.pos + ' là số thứ tự của ô hỏng → lật lại ô ' + r.pos + ' (' + dlabel(r.pos) + ').',
        'One error (S ≠ 0, P′ = 1): S = ' + r.pos + ' names the broken cell → flip cell ' + r.pos + ' (' + dlabel(r.pos) + ') back.');
      if (!good) txt += ' ' + bi('<strong>Sửa sai mà không biết:</strong> từ nhận có ' + nerr + ' bit lật, bộ giải mã "sửa" sang một từ mã khác và tin là mình đúng. Đây là vách đá ở mục 9.',
        '<strong>Mis-corrected without knowing:</strong> ' + nerr + ' bits are flipped, the decoder "fixes" towards another codeword and believes it. This is the cliff of section 9.');
    } else if (r.kind === 'double') {
      cls = 'warn';
      txt = bi('Hai lỗi (S ≠ 0, P′ = 0): <strong>phát hiện được, không sửa</strong> — đúng như thiết kế SECDED. Hệ thống phải đọc lại hoặc báo lỗi.' + (nerr !== 2 ? ' (Thực tế có ' + nerr + ' bit lật: số chẵn lỗi nào cũng ra P′ = 0.)' : ''),
        'Two errors (S ≠ 0, P′ = 0): <strong>detected, not corrected</strong> — exactly what SECDED is designed to do. The system must re-read or raise an error.' + (nerr !== 2 ? ' (Really ' + nerr + ' bits flipped: any even number gives P′ = 0.)' : ''));
    } else {
      cls = 'bad';
      txt = bi('S = ' + r.s + ' không phải vị trí nào trong 0..12 (P′ = 1): chắc chắn từ 3 lỗi trở lên, không sửa được.',
        'S = ' + r.s + ' is no position in 0..12 (P′ = 1): three or more errors for certain, nothing to correct.');
    }
    $('sd-verdict').className = 'verdict ' + cls;
    $('sd-verdict').innerHTML = txt;
    out = r.fixed ? bi('Dữ liệu sau giải mã: ', 'Data after decoding: ') + '<b>' + r.data.join(' ') + '</b> (' + hex2(r.data) + ') — ' +
      (good ? bi('bằng dữ liệu gốc ✓', 'equals the original ✓') : bi('<strong>khác dữ liệu gốc ✗</strong>', '<strong>differs from the original ✗</strong>'))
      : bi('Không có dữ liệu ra: bộ giải mã từ chối sửa.', 'No data out: the decoder refuses to correct.');
    $('sd-out').innerHTML = out;
  }
  function sdFlipRandom(k) {
    var f = sdFlips(), cand = [], i, ps;
    for (i = 0; i < E.N; i++) if (!f.map[i]) cand.push(i);
    ps = pick(cand.length, k).map(function (j) { return cand[j]; });
    ps.forEach(function (p) { S.recv[p] ^= 1; });
    sdRender();
  }
  $('sd-example').addEventListener('click', function () { S.data = [0, 1, 0, 0, 1, 1, 1, 1]; sdEncode(); sdRender(); });
  $('sd-rand').addEventListener('click', function () { S.data = randBits(E.K); sdEncode(); sdRender(); });
  $('sd-flip1').addEventListener('click', function () { sdFlipRandom(1); });
  $('sd-flip2').addEventListener('click', function () { S.recv = S.code.slice(); sdFlipRandom(2); });
  $('sd-flip3').addEventListener('click', function () { S.recv = S.code.slice(); sdFlipRandom(3); });
  $('sd-clear').addEventListener('click', function () { S.recv = S.code.slice(); sdRender(); });
  $('sd-selftest').addEventListener('click', function () {
    var r = E.selfTest(), el = $('sd-st');
    el.className = r.fail ? 'bad' : 'ok';
    el.innerHTML = r.fail ? bi('✗ ' + num(r.fail) + ' trường hợp sai trong ' + num(r.n), '✗ ' + num(r.fail) + ' of ' + num(r.n) + ' cases wrong')
      : bi('✓ ' + num(r.n) + ' / ' + num(r.n) + ' — mọi từ có ≤ 1 lỗi được sửa đúng, mọi từ có 2 lỗi bị phát hiện', '✓ ' + num(r.n) + ' / ' + num(r.n) + ' — every word with ≤ 1 error recovers, every 2-error word is flagged');
  });

  /* ================================================================ PUF */
  var P = { R: null, W: null, key: null, Rp: null };
  function noise() { var el = doc.querySelector('input[name="pf-noise"]:checked'); return el ? +el.value : 2; }
  function pfEnroll(R) {
    P.R = R || randBits(E.NB * E.N); P.W = E.enroll(P.R); P.key = E.keyOf(P.R); P.Rp = null;
    renderBits($('pf-R'), P.R, {});
    $('pf-W').innerHTML = P.W.map(function (w, b) { return bi('khối ' + (b + 1), 'block ' + (b + 1)) + ': S = ' + sbits(w.s) + ', P = ' + w.p; }).join(' · ');
    $('pf-key').textContent = P.key;
    $('pf-s1-note').innerHTML = bi('R bị quên ngay sau bước này. Chỉ W — 4 × 5 = 20 bit — được ghi vào bộ nhớ; W công khai cũng được, nhưng nó lộ tối đa 20 bit về R, nên R thật phải dài hơn khoá cần có nhiều.',
      'R is forgotten right after this step. Only W — 4 × 5 = 20 bits — is written to memory; W may be public, but it leaks up to 20 bits about R, so a real R must be much longer than the key it protects.');
    $('pf-read').disabled = false;
    $('pf-Rp').innerHTML = ''; $('pf-s2-note').innerHTML = bi('Chọn số ô dao động rồi bấm "Đọc lại".', 'Pick how many cells drift, then press "Read again".');
    $('pf-blocks').innerHTML = ''; $('pf-Rpp').innerHTML = ''; $('pf-key2').textContent = '';
    $('pf-verdict').className = 'verdict'; $('pf-verdict').innerHTML = bi('Chưa có lần đọc lại.', 'No second read yet.');
  }
  function pfRead(flips) {
    if (!P.R) return;
    P.Rp = P.R.slice();
    (flips || pick(E.NB * E.N, noise())).forEach(function (p) { P.Rp[p] ^= 1; });
    pfRender();
  }
  function pfRender() {
    var flips = {}, n = 0, i, rc, fixed = {}, wrong = {}, lines = '', b, r, good, cls, txt;
    for (i = 0; i < P.R.length; i++) if (P.Rp[i] !== P.R[i]) { flips[i] = 1; n++; }
    renderBits($('pf-Rp'), P.Rp, { flips: flips, click: function (p) { P.Rp[p] ^= 1; pfRender(); } });
    $('pf-s2-note').innerHTML = (n === 0 ? bi('R′ = R: lần này không ô nào lệch. Bấm vào một ô để tự tạo lệch.', 'R′ = R: nothing drifted this time. Click a cell to drift one yourself.')
      : bi(n + ' ô lệch so với R (ô cam) — bấm vào ô để lật thêm hay lật lại. Khoá nếu dùng R′ chưa sửa: ', n + (n === 1 ? ' cell drifted' : ' cells drifted') + ' from R (orange) — click a cell to flip more, or back. The key if R′ were used unrepaired: ') +
        '<span class="mono">' + E.keyOf(P.Rp) + '</span> ≠ K ✗ — ' + bi('lệch một bit, khoá khác hẳn.', 'one bit off, a completely different key.'));
    rc = E.reconstruct(P.Rp, P.W);
    for (b = 0; b < E.NB; b++) {
      r = rc.blocks[b];
      lines += '<div>' + bi('Khối ' + (b + 1), 'Block ' + (b + 1)) + ': S′⊕S = ' + sbits(r.s) + ', P′⊕P = ' + r.p + ' → ';
      if (r.kind === 'ok') lines += bi('không lệch', 'no drift');
      else if (r.kind === 'parity') { lines += bi('lệch ở ô 0 → sửa', 'drift at cell 0 → fixed'); fixed[b * E.N] = 1; }
      else if (r.kind === 'single') { lines += bi('một ô lệch, số ' + r.pos + ' → sửa', 'one cell drifted, number ' + r.pos + ' → fixed'); fixed[b * E.N + r.pos] = 1; }
      else if (r.kind === 'double') lines += '<strong>' + bi('hai ô lệch → phát hiện, không sửa được ✗', 'two cells drifted → detected, cannot fix ✗') + '</strong>';
      else lines += '<strong>' + bi('S = ' + r.s + ' vô nghĩa → từ 3 ô lệch, không sửa được ✗', 'S = ' + r.s + ' is meaningless → 3 or more drifted, cannot fix ✗') + '</strong>';
      lines += '</div>';
    }
    $('pf-blocks').innerHTML = lines;
    for (i = 0; i < rc.word.length; i++) if (rc.word[i] !== P.R[i]) wrong[i] = 1;
    renderBits($('pf-Rpp'), rc.word, { fixed: fixed, flips: wrong });
    var k2 = E.keyOf(rc.word);
    $('pf-key2').textContent = k2;
    good = k2 === P.key;
    if (rc.ok && good) { cls = 'ok'; txt = bi('K′ = K ✓ — khoá dựng lại đúng' + (n ? ', ' + n + ' ô lệch đã được sửa nhờ W.' : ' (không cần sửa gì).'), 'K′ = K ✓ — the key is rebuilt' + (n ? ', ' + n + ' drifted cells repaired thanks to W.' : ' (nothing to repair).')); }
    else if (!rc.ok) { cls = 'bad'; txt = bi('K′ ≠ K ✗ — có khối lệch quá sức sửa của mã (mỗi khối 13 bit chỉ sửa được 1 ô). Hệ thống <strong>phải báo lỗi và không dùng khoá này</strong>; PUF thật giảm rủi ro ấy bằng bỏ phiếu nhiều lần và mã mạnh hơn (BCH).',
      'K′ ≠ K ✗ — a block drifted past what the code can fix (each 13-bit block fixes one cell). The system <strong>must raise an error and not use this key</strong>; real PUFs cut that risk with repeated voting and a stronger code (BCH).'); }
    else { cls = 'bad'; txt = bi('K′ ≠ K ✗ nhưng bộ giải mã tưởng đã sửa xong: một khối có 3 ô lệch và bị "sửa" sang chỗ khác. Chip thật vì thế lưu thêm một giá trị kiểm khoá (băm của K) để tự nhận ra — mã sửa lỗi không bao giờ là người gác cổng duy nhất.',
      'K′ ≠ K ✗ yet the decoder believes it succeeded: a block had 3 drifted cells and was "fixed" elsewhere. This is why a real chip also stores a key-check value (a hash of K) to notice — an error-correcting code is never the only guard.'); }
    $('pf-verdict').className = 'verdict ' + cls;
    $('pf-verdict').innerHTML = txt;
  }
  $('pf-enroll').addEventListener('click', function () { pfEnroll(); });
  $('pf-read').addEventListener('click', function () { pfRead(); });

  /* ================================================================ khởi động */
  Array.prototype.forEach.call(doc.querySelectorAll('.nojs'), function (el) { el.style.display = 'none'; });
  sdEncode(); sdRender();
  $('pf-read').disabled = true;
  $('pf-verdict').innerHTML = bi('Bắt đầu ở bước 1.', 'Start at step 1.');
  $('pf-s2-note').innerHTML = bi('Cần đọc dấu vân tay lần đầu trước.', 'The first read has to happen first.');

  root.ECCSimPage = {
    S: S, P: P,
    setData: function (b) { S.data = b.slice(); sdEncode(); sdRender(); },
    setRecv: function (b) { S.recv = b.slice(); sdRender(); },
    flipRecv: function (p) { S.recv[p] ^= 1; sdRender(); },
    enroll: pfEnroll, read: pfRead, flipRp: function (p) { P.Rp[p] ^= 1; pfRender(); }
  };
})(window, document);
