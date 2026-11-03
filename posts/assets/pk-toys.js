/* pk-toys.js - three hand-sized public-key toys for posts/mat-ma-khoa-cong-khai-ba-viec.html.
   Global PKToys. Pure functions (no DOM): PKToys.rsa, PKToys.ec, PKToys.ecdsa. Widgets mount on DOMContentLoaded into every
   [data-toy="rsa" | "ecdh" | "ecdsa"] element that exists. Every visible string is a <span lang="vi"> / <span lang="en"> pair
   made by bi(). Plain Number arithmetic only (all values are tiny); modular exponentiation is square-and-multiply.
   Learning toys: 12-bit RSA and a 19-point curve are broken by hand - never use these sizes for anything real. */
(function (root) {
  'use strict';

  /* ================================================================ arithmetic */
  function md(x, m) { return ((x % m) + m) % m; }
  /* extended Euclid inverse of a modulo m (null when gcd != 1) */
  function inv(a, m) {
    var r0 = m, r1 = md(a, m), t0 = 0, t1 = 1;
    while (r1 !== 0) { var q = Math.floor(r0 / r1), t = r0 - q * r1; r0 = r1; r1 = t; t = t0 - q * t1; t0 = t1; t1 = t; }
    return r0 === 1 ? md(t0, m) : null;
  }
  function bitsOf(e) { return e.toString(2); }
  /* left-to-right square-and-multiply, recording every step */
  function modpowSteps(b, e, m) {
    var bits = bitsOf(e), steps = [], r = md(b, m), i;
    steps.push({ op: 'init', bit: 1, inp: r, out: r });
    for (i = 1; i < bits.length; i++) {
      var sq = (r * r) % m;
      steps.push({ op: 'sq', bit: +bits[i], inp: r, out: sq }); r = sq;
      if (bits[i] === '1') { var ml = (r * md(b, m)) % m; steps.push({ op: 'mul', bit: 1, inp: r, out: ml }); r = ml; }
    }
    return { bits: bits, steps: steps, value: r % m, squarings: steps.filter(function (s) { return s.op === 'sq'; }).length, multiplications: steps.filter(function (s) { return s.op === 'mul'; }).length };
  }
  function modpow(b, e, m) { return modpowSteps(b, e, m).value; }

  /* ================================================================ RSA */
  var rsa = (function () {
    var p = 61, q = 53, n = p * q, e = 17, d = 413, dPhi = 2753;
    return {
      p: p, q: q, n: n, e: e, d: d, dPhi: dPhi, lambda: 780, phi: 3120,
      modpow: modpow, modpowSteps: modpowSteps, inv: inv,
      encrypt: function (m) { return modpow(m, e, n); },
      decrypt: function (c) { return modpow(c, d, n); },
      sign: function (h) { return modpow(h, d, n); },
      recover: function (s) { return modpow(s, e, n); },
      verify: function (s, h) { return modpow(s, e, n) === md(h, n); }
    };
  })();

  /* ================================================================ elliptic curve y^2 = x^3 + 2x + 2 over F17 */
  var ec = (function () {
    var P = 17, A = 2, B = 2, N = 19, G = [5, 1];
    function onCurve(Q) { return Q === null || md(Q[1] * Q[1] - (Q[0] * Q[0] * Q[0] + A * Q[0] + B), P) === 0; }
    function add(Q1, Q2) {                      /* null = point at infinity O */
      if (Q1 === null) return Q2;
      if (Q2 === null) return Q1;
      var x1 = Q1[0], y1 = Q1[1], x2 = Q2[0], y2 = Q2[1], lm;
      if (x1 === x2 && md(y1 + y2, P) === 0) return null;
      if (x1 === x2 && y1 === y2) lm = md((3 * x1 * x1 + A) * inv(2 * y1, P), P);
      else lm = md((y2 - y1) * inv(x2 - x1, P), P);
      var x3 = md(lm * lm - x1 - x2, P);
      return [x3, md(lm * (x1 - x3) - y1, P)];
    }
    function dbl(Q) { return add(Q, Q); }
    function mul(k, Q) {                        /* double-and-add, left to right */
      var R = null, bits = bitsOf(md(k, N)), i;
      if (md(k, N) === 0) return null;
      for (i = 0; i < bits.length; i++) { R = dbl(R); if (bits[i] === '1') R = add(R, Q); }
      return R;
    }
    function points() {
      var out = [], x, y;
      for (x = 0; x < P; x++) for (y = 0; y < P; y++) if (onCurve([x, y])) out.push([x, y]);
      return out;
    }
    return { p: P, a: A, b: B, n: N, G: G, inv: inv, add: add, dbl: dbl, mul: mul, onCurve: onCurve, points: points,
      count: function () { return points().length + 1; } };
  })();

  /* ================================================================ ECDSA on that curve (order 19) */
  var ecdsa = (function () {
    var N = ec.n, G = ec.G;
    function pub(d) { return ec.mul(d, G); }
    function sign(d, h, k) {
      var R = ec.mul(k, G), r = md(R[0], N);
      if (r === 0) return { ok: false, reason: 'r0', R: R, r: 0, s: null, kinv: inv(k, N) };
      var kinv = inv(k, N), s = md(kinv * (h + r * d), N);
      if (s === 0) return { ok: false, reason: 's0', R: R, r: r, s: 0, kinv: kinv };
      return { ok: true, reason: null, R: R, r: r, s: s, kinv: kinv };
    }
    function verify(Q, h, r, s) {
      if (!(r >= 1 && r < N && s >= 1 && s < N)) return { valid: false, why: 'range' };
      var w = inv(s, N), u1 = md(h * w, N), u2 = md(r * w, N);
      var R = ec.add(ec.mul(u1, G), ec.mul(u2, Q));
      if (R === null) return { valid: false, why: 'inf', w: w, u1: u1, u2: u2, R: null, xr: null };
      var xr = md(R[0], N);
      return { valid: xr === r, why: xr === r ? 'ok' : 'mismatch', w: w, u1: u1, u2: u2, R: R, xr: xr };
    }
    /* two signatures with the same k (hence the same r) over hashes h1 != h2 */
    function recover(r, h1, s1, h2, s2) {
      var ds = md(s1 - s2, N), ir = inv(r, N);
      if (ds === 0 || ir === null || md(h1 - h2, N) === 0) return { ok: false };
      var k = md((h1 - h2) * inv(ds, N), N), d = md((s1 * k - h1) * ir, N);
      return { ok: true, k: k, d: d, dsInv: inv(ds, N), rInv: ir };
    }
    /* the second hash the toy uses: the first h after h1 (wrapping mod 19) whose signature is not refused */
    function reusePick(d, h1, k) {
      var i, h2;
      for (i = 1; i < N; i++) { h2 = (h1 + i) % N; if (sign(d, h2, k).ok) return h2; }
      return null;
    }
    return { n: N, pub: pub, sign: sign, verify: verify, recover: recover, reusePick: reusePick };
  })();

  /* ================================================================ UI helpers */
  function bi(vi, en) { return '<span lang="vi">' + vi + '</span><span lang="en">' + en + '</span>'; }
  function pt(Q) { return Q === null ? 'O' : '(' + Q[0] + ', ' + Q[1] + ')'; }
  function el(tag, cls, html) { var x = document.createElement(tag); if (cls) x.className = cls; if (html !== undefined) x.innerHTML = html; return x; }
  function parseInt_(input, lo, hi) {
    var v = input.value;
    if (!/^-?\d+$/.test(v)) return null;
    v = +v;
    return v >= lo && v <= hi ? v : null;
  }
  /* one computed line: formula (neutral code), its value, a one-line bilingual explanation */
  function row(key, formula, value, vi, en) {
    return '<div class="toy-row" data-row="' + key + '"><code class="toy-f">' + formula + '</code> <b class="toy-val" data-k="' + key + '">' + value + '</b>' +
      '<small class="toy-e">' + bi(vi, en) + '</small></div>';
  }
  function verdict(key, kind, vi, en) {
    return '<div class="toy-verdict ' + (kind === 'ok' ? 'toy-ok' : kind === 'bad' ? 'toy-bad' : 'toy-warn') + '" data-k="' + key + '" data-v="' + kind + '" role="status">' + bi(vi, en) + '</div>';
  }
  function bad(inputsVi, inputsEn) { return '<div class="toy-verdict toy-warn" data-k="input-error" data-v="input">' + bi(inputsVi, inputsEn) + '</div>'; }

  var CSS = [
    '.toy-box{border:1px solid #cfd8e3;border-left:4px solid #14538f;border-radius:10px;background:#fbfcfe;padding:14px 16px;margin:18px 0;font-size:15px;line-height:1.5;color:#1b2430}',
    '.toy-box *{box-sizing:border-box}',
    '.toy-h{margin:0 0 4px;font-size:16px;font-weight:700;color:#14538f}',
    '.toy-sub{margin:0 0 10px;color:#5f6b7a;font-size:14px}',
    '.toy-ctl{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:flex-end;margin:8px 0 12px}',
    '.toy-fld{display:flex;flex-direction:column;gap:3px;font-size:14px;color:#1b2430}',
    '.toy-fld input{width:96px;padding:5px 7px;border:1px solid #9aa8ba;border-radius:6px;font:inherit;font-family:ui-monospace,Menlo,Consolas,monospace;background:#fff}',
    '.toy-fld input:focus-visible,.toy-btn:focus-visible,.toy-chip input:focus-visible{outline:2px solid #14538f;outline-offset:2px}',
    '.toy-chips{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 8px}',
    '.toy-chip{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border:1px solid #9aa8ba;border-radius:999px;background:#fff;cursor:pointer;font-size:14px}',
    '.toy-chip:has(input:checked){background:#14538f;border-color:#14538f;color:#fff}',
    '.toy-btn{padding:6px 12px;border:1px solid #14538f;border-radius:7px;background:#fff;color:#14538f;font:inherit;font-size:14px;cursor:pointer}',
    '.toy-btn:hover:not(:disabled){background:#e9f0f8}',
    '.toy-btn:disabled{opacity:.45;cursor:not-allowed}',
    '.toy-btn.toy-danger{border-color:#9b1d28;color:#9b1d28}',
    '.toy-btn.toy-danger:hover:not(:disabled){background:#fbeced}',
    '.toy-sec{margin:12px 0 4px;font-weight:700;font-size:14px;color:#14213d}',
    '.toy-row{padding:5px 0;border-top:1px dashed #dde4ec}',
    '.toy-row:first-of-type{border-top:0}',
    '.toy-f,.toy-box code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13.5px;background:#eef2f7;padding:1px 5px;border-radius:4px;overflow-wrap:anywhere}',
    '.toy-val{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:15px;color:#14213d;margin-left:4px}',
    '.toy-e{display:block;color:#5f6b7a;font-size:13.5px;margin-top:1px}',
    '.toy-pub{color:#1f7a6f}.toy-sec-key{color:#9b1d28}',
    '.toy-verdict{margin:10px 0 4px;padding:8px 12px;border-radius:8px;font-weight:700;font-size:14.5px}',
    '.toy-ok{background:#e8f5f3;border:1px solid #2a9d8f;color:#14574f}',
    '.toy-bad{background:#fbeced;border:1px solid #9b1d28;color:#7d1620}',
    '.toy-warn{background:#fff6e0;border:1px solid #c58b00;color:#6b4a00}',
    '.toy-tblw{overflow-x:auto;margin:6px 0}',
    '.toy-tbl{border-collapse:collapse;font-size:13.5px;min-width:420px}',
    '.toy-tbl th,.toy-tbl td{border:1px solid #cfd8e3;padding:4px 9px;text-align:left}',
    '.toy-tbl th{background:#eef2f7}',
    '.toy-svgw{overflow-x:auto;margin:8px 0}',
    '.toy-svgw svg{display:block;max-width:100%;min-width:300px;height:auto}',
    '.toy-legend{display:flex;flex-wrap:wrap;gap:4px 16px;font-size:13px;color:#5f6b7a;margin:2px 0 8px}',
    '.toy-dot{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:5px;vertical-align:-1px;border:2px solid transparent}',
    '.toy-note{font-size:13px;color:#5f6b7a;margin:8px 0 0}'
  ].join('\n');

  function injectCss() {
    if (document.getElementById('pk-toys-css')) return;
    var s = document.createElement('style'); s.id = 'pk-toys-css'; s.textContent = CSS; document.head.appendChild(s);
  }
  function field(id, labelHtml, min, max, val) {
    var f = el('label', 'toy-fld'); f.setAttribute('for', id);
    var lab = el('span', '', labelHtml); f.appendChild(lab);
    var i = el('input'); i.type = 'number'; i.id = id; i.min = min; i.max = max; i.step = 1; i.value = val; i.inputMode = 'numeric';
    f.appendChild(i);
    return { wrap: f, input: i, label: lab };
  }
  function button(id, cls, html) { var b = el('button', 'toy-btn ' + (cls || ''), html); b.type = 'button'; b.id = id; return b; }
  function onInput(node, fn) { node.addEventListener('input', fn); node.addEventListener('change', fn); }

  /* ================================================================ RSA toy */
  function mountRsa(host) {
    host.classList.add('toy-box');
    var st = { tamper: false };
    host.innerHTML = '<p class="toy-h">' + bi('Thử RSA với số nhỏ: p = 61, q = 53', 'Try RSA with small numbers: p = 61, q = 53') + '</p>' +
      '<p class="toy-sub">' + bi('Khoá công khai (n, e) = (3233, 17). Khoá bí mật d = 413, tính theo λ(n) = bội chung nhỏ nhất của 60 và 52 = 780 (cách của FIPS 186-5). Cách sách giáo khoa dùng φ(n) = 3120 cho d = 2753; cả hai đều chạy đúng.',
        'Public key (n, e) = (3233, 17). Secret key d = 413, computed from λ(n) = lcm(60, 52) = 780 (the FIPS 186-5 way). The textbook way uses φ(n) = 3120 and gives d = 2753; both work.') + '</p>';
    var chips = el('div', 'toy-chips'); chips.setAttribute('role', 'radiogroup');
    chips.innerHTML = '<label class="toy-chip"><input type="radio" name="toy-rsa-mode" id="toy-rsa-mode-enc" value="enc" checked>' + bi('Mã hoá', 'Encrypt') + '</label>' +
      '<label class="toy-chip"><input type="radio" name="toy-rsa-mode" id="toy-rsa-mode-sig" value="sig">' + bi('Ký', 'Sign') + '</label>';
    host.appendChild(chips);
    var ctl = el('div', 'toy-ctl'); host.appendChild(ctl);
    var fx = field('toy-rsa-x', '', 0, 3232, 65); ctl.appendChild(fx.wrap);
    var btn = button('toy-rsa-tamper', 'toy-danger', ''); ctl.appendChild(btn);
    var out = el('div', 'toy-out'); out.setAttribute('aria-live', 'polite'); host.appendChild(out);
    var mode = function () { return host.querySelector('input[name="toy-rsa-mode"]:checked').value; };

    function render() {
      var md_ = mode(), x = parseInt_(fx.input, 0, 3232), n = rsa.n, h = '';
      fx.label.innerHTML = md_ === 'enc' ? bi('Thông điệp m (0 đến 3232)', 'Message m (0 to 3232)') : bi('Giá trị băm h (0 đến 3232)', 'Hash value h (0 to 3232)');
      btn.innerHTML = st.tamper ? bi('Khôi phục', 'Restore') : bi('Sửa thông điệp (h + 1)', 'Tamper with the message (h + 1)');
      btn.style.display = md_ === 'sig' ? '' : 'none';
      btn.setAttribute('aria-pressed', st.tamper ? 'true' : 'false');
      if (x === null) { out.innerHTML = bad('Hãy nhập một số nguyên từ 0 đến 3232.', 'Enter a whole number from 0 to 3232.'); return; }
      if (md_ === 'enc') {
        var c = rsa.encrypt(x), S = modpowSteps(x, rsa.e, n), back = rsa.decrypt(c), D = modpowSteps(c, rsa.d, n);
        h += '<p class="toy-sec">' + bi('1. Người gửi mã hoá bằng khoá công khai', '1. The sender encrypts with the public key') + '</p>';
        h += row('c', 'c = m^e mod n = ' + x + '^' + rsa.e + ' mod ' + n, c, 'Bản mã: lấy m nâng lên luỹ thừa e rồi chia dư cho n.', 'The ciphertext: raise m to the power e, then keep the remainder modulo n.');
        h += '<div class="toy-tblw"><table class="toy-tbl" data-k="steps"><thead><tr><th>#</th><th>' + bi('Phép tính', 'Operation') + '</th><th>' + bi('Biểu thức', 'Expression') + '</th><th>' + bi('Kết quả', 'Result') + '</th></tr></thead><tbody>';
        S.steps.forEach(function (s, i) {
          var op = s.op === 'init' ? bi('bit đầu của e là 1: bắt đầu từ m', 'the leading bit of e is 1: start from m') : s.op === 'sq' ? bi('bình phương', 'square') : bi('nhân với m', 'multiply by m');
          var ex = s.op === 'init' ? 'r = m = ' + s.out : s.op === 'sq' ? 'r = ' + s.inp + '² mod ' + n : 'r = ' + s.inp + ' · ' + x + ' mod ' + n;
          h += '<tr data-step="' + i + '" data-op="' + s.op + '"><td>' + i + '</td><td>' + op + '</td><td><code>' + ex + '</code></td><td><b data-k="step' + i + '">' + s.out + '</b></td></tr>';
        });
        h += '</tbody></table></div>';
        h += row('e-bits', 'e = ' + rsa.e + ' = ' + S.bits + '₂', S.squarings + ' + ' + S.multiplications,
          'Số lần bình phương + số lần nhân: cách "bình phương rồi nhân" chỉ cần vài phép tính thay vì 17 phép nhân.', 'Squarings + multiplications: square-and-multiply needs a handful of operations instead of 17 multiplications.');
        h += '<p class="toy-sec">' + bi('2. Người nhận giải mã bằng khoá bí mật', '2. The receiver decrypts with the secret key') + '</p>';
        h += row('m2', 'c^d mod n = ' + c + '^' + rsa.d + ' mod ' + n, back, 'Cùng cách tính, với số mũ bí mật d = 413 (' + D.squarings + ' lần bình phương, ' + D.multiplications + ' lần nhân).', 'The same method with the secret exponent d = 413 (' + D.squarings + ' squarings, ' + D.multiplications + ' multiplications).');
        h += back === x ? verdict('verdict', 'ok', 'ĐÚNG: giải mã ra ' + back + ', đúng bằng thông điệp m = ' + x + '.', 'OK: decrypting gives ' + back + ', exactly the message m = ' + x + '.')
          : verdict('verdict', 'bad', 'SAI: ' + back + ' khác ' + x + '.', 'WRONG: ' + back + ' differs from ' + x + '.');
        h += '<p class="toy-note">' + bi('Thông điệp thật luôn được đệm (OAEP) trước khi mã hoá; ở đây ta mã hoá trực tiếp một con số để thấy phép tính.', 'A real message is always padded (OAEP) before encrypting; here we encrypt a bare number to see the arithmetic.') + '</p>';
      } else {
        var s = rsa.sign(x), hv = st.tamper ? md(x + 1, n) : x, back2 = rsa.recover(s), ok = rsa.verify(s, hv);
        h += '<p class="toy-sec">' + bi('1. Người ký dùng khoá bí mật', '1. The signer uses the secret key') + '</p>';
        h += row('s', 's = h^d mod n = ' + x + '^' + rsa.d + ' mod ' + n, s, 'Chữ ký: chỉ ai có d mới tính được số này.', 'The signature: only someone who knows d can compute this number.');
        h += '<p class="toy-sec">' + bi('2. Người kiểm dùng khoá công khai', '2. The verifier uses the public key') + '</p>';
        h += row('v', 's^e mod n = ' + s + '^' + rsa.e + ' mod ' + n, back2, 'Số lấy lại được từ chữ ký bằng khoá công khai (n, e).', 'The number the public key (n, e) pulls back out of the signature.');
        h += row('hv', st.tamper ? 'h′ = h + 1 mod n' : 'h', hv, st.tamper ? 'Thông điệp đã bị sửa: người kiểm nhận giá trị băm h + 1 thay vì h.' : 'Giá trị băm của thông điệp mà người kiểm nhận được.',
          st.tamper ? 'The message was altered: the verifier receives the hash h + 1 instead of h.' : 'The hash of the message that the verifier received.');
        h += ok ? verdict('verdict', 'ok', 'HỢP LỆ: ' + back2 + ' = ' + hv + ', chữ ký đúng với thông điệp này.', 'VALID: ' + back2 + ' = ' + hv + ', the signature fits this message.')
          : verdict('verdict', 'bad', 'KHÔNG HỢP LỆ: chữ ký cho ra ' + back2 + ' nhưng thông điệp nhận được có giá trị băm ' + hv + '; hai số khác nhau nên thông điệp đã bị đổi.',
            'INVALID: the signature gives ' + back2 + ' but the received message hashes to ' + hv + '; the two numbers differ, so the message was changed.');
        h += '<p class="toy-note">' + bi('Thật ra RSA ký giá trị băm đã được đệm (PSS), không ký thẳng một con số.', 'In practice RSA signs a padded hash (PSS), not a bare number.') + '</p>';
      }
      out.innerHTML = h;
    }
    onInput(fx.input, function () { st.tamper = false; render(); });
    chips.addEventListener('change', function () { st.tamper = false; render(); });
    btn.addEventListener('click', function () { st.tamper = !st.tamper; render(); });
    render();
  }

  /* ================================================================ ECDH toy */
  function gridSvg(A, B, S) {
    var cell = 20, ox = 30, oy = 12, W = ox + 16 * cell + 14, H = oy + 16 * cell + 36, i;
    var X = function (x) { return ox + x * cell; }, Y = function (y) { return oy + (16 - y) * cell; };
    var g = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="y² = x³ + 2x + 2 mod 17" data-k="grid" xmlns="http://www.w3.org/2000/svg" font-family="Inter,Arial,sans-serif">';
    for (i = 0; i <= 16; i++) {
      g += '<line x1="' + X(i) + '" y1="' + Y(0) + '" x2="' + X(i) + '" y2="' + Y(16) + '" stroke="#e1e7ef"/>';
      g += '<line x1="' + X(0) + '" y1="' + Y(i) + '" x2="' + X(16) + '" y2="' + Y(i) + '" stroke="#e1e7ef"/>';
      g += '<text x="' + X(i) + '" y="' + (Y(0) + 15) + '" font-size="9" text-anchor="middle" fill="#5f6b7a">' + i + '</text>';
      g += '<text x="' + (ox - 8) + '" y="' + (Y(i) + 3) + '" font-size="9" text-anchor="end" fill="#5f6b7a">' + i + '</text>';
    }
    g += '<text x="' + X(8) + '" y="' + (Y(0) + 30) + '" font-size="11" text-anchor="middle" fill="#14213d">x</text><text x="6" y="' + (Y(8) + 4) + '" font-size="11" fill="#14213d">y</text>';
    var labels = {};
    function tag(Q, name) { var k = Q.join(','); (labels[k] = labels[k] || []).push(name); }
    tag(ec.G, 'G'); tag(A, 'A'); tag(B, 'B'); tag(S, 'S');
    ec.points().forEach(function (Q) {
      var k = Q.join(','), roles = labels[k] || [];
      g += '<circle cx="' + X(Q[0]) + '" cy="' + Y(Q[1]) + '" r="3.6" fill="#5f6b7a" data-pt="' + k + '" data-roles="' + roles.join('') + '"/>';
    });
    g += '<circle cx="' + X(S[0]) + '" cy="' + Y(S[1]) + '" r="11" fill="none" stroke="#9b1d28" stroke-width="2.5" data-role="S"/>';
    g += '<circle cx="' + X(ec.G[0]) + '" cy="' + Y(ec.G[1]) + '" r="8" fill="none" stroke="#14213d" stroke-width="2" data-role="G"/>';
    g += '<circle cx="' + X(A[0]) + '" cy="' + Y(A[1]) + '" r="5.5" fill="#2a9d8f" data-role="A"/>';
    g += '<circle cx="' + X(B[0]) + '" cy="' + Y(B[1]) + '" r="5.5" fill="#14538f" data-role="B"/>';
    Object.keys(labels).forEach(function (k) {
      var Q = k.split(',').map(Number);
      g += '<text x="' + (X(Q[0]) + 13) + '" y="' + (Y(Q[1]) - 9) + '" font-size="11" font-weight="700" fill="#14213d" data-label="' + k + '">' + labels[k].join('=') + '</text>';
    });
    return g + '</svg>';
  }
  function mountEcdh(host) {
    host.classList.add('toy-box');
    host.innerHTML = '<p class="toy-h">' + bi('Thử trao đổi khoá ECDH trên một đường cong nhỏ', 'Try an ECDH key agreement on a tiny curve') + '</p>' +
      '<p class="toy-sub">' + bi('Đường cong y² = x³ + 2x + 2 trên F17 (các số từ 0 đến 16), điểm gốc G = (5, 1), cấp n = 19: có 18 điểm cộng thêm điểm vô cực. Alice giữ bí mật a, Bob giữ bí mật b.',
        'The curve y² = x³ + 2x + 2 over F17 (numbers 0 to 16), base point G = (5, 1), order n = 19: 18 points plus the point at infinity. Alice keeps a secret number a, Bob a secret number b.') + '</p>';
    var ctl = el('div', 'toy-ctl'); host.appendChild(ctl);
    var fa = field('toy-ecdh-a', bi('Bí mật của Alice a (1 đến 18)', 'Alice’s secret a (1 to 18)'), 1, 18, 3);
    var fb = field('toy-ecdh-b', bi('Bí mật của Bob b (1 đến 18)', 'Bob’s secret b (1 to 18)'), 1, 18, 7);
    ctl.appendChild(fa.wrap); ctl.appendChild(fb.wrap);
    var out = el('div', 'toy-out'); out.setAttribute('aria-live', 'polite'); host.appendChild(out);
    function render() {
      var a = parseInt_(fa.input, 1, 18), b = parseInt_(fb.input, 1, 18), h = '';
      if (a === null || b === null) { out.innerHTML = bad('Hãy nhập hai số nguyên từ 1 đến 18.', 'Enter two whole numbers from 1 to 18.'); return; }
      var A = ec.mul(a, ec.G), B = ec.mul(b, ec.G), SA = ec.mul(a, B), SB = ec.mul(b, A), k = (a * b) % ec.n, S = ec.mul(k, ec.G);
      h += '<p class="toy-sec">' + bi('1. Mỗi bên công bố một điểm công khai', '1. Each side publishes a public point') + '</p>';
      h += row('A', 'A = a·G = ' + a + '·(5, 1)', pt(A), 'Alice gửi điểm A cho Bob. Từ A không ai tính ngược được a (ở cỡ thật).', 'Alice sends the point A to Bob. Nobody can get a back from A (at real size).');
      h += row('B', 'B = b·G = ' + b + '·(5, 1)', pt(B), 'Bob gửi điểm B cho Alice.', 'Bob sends the point B to Alice.');
      h += '<p class="toy-sec">' + bi('2. Mỗi bên nhân điểm của bên kia với bí mật của mình', '2. Each side multiplies the other side’s point by its own secret') + '</p>';
      h += row('SA', 'a·B = ' + a + '·' + pt(B), pt(SA), 'Alice tính. Cô chỉ biết a và B.', 'Alice computes. She only knows a and B.');
      h += row('SB', 'b·A = ' + b + '·' + pt(A), pt(SB), 'Bob tính. Anh chỉ biết b và A.', 'Bob computes. He only knows b and A.');
      h += row('k', '(a·b) mod n = ' + a + '·' + b + ' mod 19', k, 'Cả hai đều ra (a·b)·G, nên điểm chung là ' + k + '·G.', 'Both end up at (a·b)·G, so the shared point is ' + k + '·G.');
      h += row('S', k + '·G', pt(S), 'Kiểm tra độc lập: nhân thẳng G với a·b mod 19.', 'An independent check: multiply G directly by a·b mod 19.');
      h += SA && SB && SA[0] === SB[0] && SA[1] === SB[1] && SA[0] === S[0] && SA[1] === S[1]
        ? verdict('verdict', 'ok', 'KHỚP: cả hai cùng ra ' + pt(SA) + '. Đó là bí mật chung; người nghe lén chỉ thấy G, A, B.', 'MATCH: both reach ' + pt(SA) + '. That is the shared secret; an eavesdropper only sees G, A and B.')
        : verdict('verdict', 'bad', 'KHÔNG KHỚP: ' + pt(SA) + ' khác ' + pt(SB) + '.', 'NO MATCH: ' + pt(SA) + ' differs from ' + pt(SB) + '.');
      h += '<div class="toy-svgw">' + gridSvg(A, B, S) + '</div>';
      h += '<div class="toy-legend"><span><i class="toy-dot" style="background:#5f6b7a"></i>' + bi('điểm trên đường cong (18)', 'curve point (18 in all)') + '</span>' +
        '<span><i class="toy-dot" style="border-color:#14213d"></i>' + bi('G, điểm gốc', 'G, the base point') + '</span>' +
        '<span><i class="toy-dot" style="background:#2a9d8f"></i>' + bi('A, của Alice', 'A, Alice’s point') + '</span>' +
        '<span><i class="toy-dot" style="background:#14538f"></i>' + bi('B, của Bob', 'B, Bob’s point') + '</span>' +
        '<span><i class="toy-dot" style="border-color:#9b1d28"></i>' + bi('S, điểm chung', 'S, the shared point') + '</span></div>';
      out.innerHTML = h;
    }
    onInput(fa.input, render); onInput(fb.input, render);
    render();
  }

  /* ================================================================ ECDSA toy */
  function mountEcdsa(host) {
    host.classList.add('toy-box');
    var st = { tamper: false, reuse: false };
    host.innerHTML = '<p class="toy-h">' + bi('Thử chữ ký ECDSA trên cùng đường cong nhỏ', 'Try an ECDSA signature on the same tiny curve') + '</p>' +
      '<p class="toy-sub">' + bi('Các phép tính trên r, s lấy dư cho n = 19 (toạ độ điểm tính theo 17). Khoá bí mật d, giá trị băm h, số dùng một lần k (nonce).', 'Arithmetic on r, s is modulo n = 19 (point coordinates are mod 17). Secret key d, hash h, one-time number k (the nonce).') + '</p>';
    var ctl = el('div', 'toy-ctl'); host.appendChild(ctl);
    var fd = field('toy-ecdsa-d', bi('Khoá bí mật d (1 đến 18)', 'Secret key d (1 to 18)'), 1, 18, 7);
    var fh = field('toy-ecdsa-h', bi('Giá trị băm h (0 đến 18)', 'Hash h (0 to 18)'), 0, 18, 4);
    var fk = field('toy-ecdsa-k', bi('Số dùng một lần k (1 đến 18)', 'Nonce k (1 to 18)'), 1, 18, 3);
    ctl.appendChild(fd.wrap); ctl.appendChild(fh.wrap); ctl.appendChild(fk.wrap);
    var bt = button('toy-ecdsa-tamper', 'toy-danger', ''), br = button('toy-ecdsa-reuse', 'toy-danger', '');
    var ctl2 = el('div', 'toy-ctl'); ctl2.appendChild(bt); ctl2.appendChild(br); host.appendChild(ctl2);
    var out = el('div', 'toy-out'); out.setAttribute('aria-live', 'polite'); host.appendChild(out);

    function render() {
      var d = parseInt_(fd.input, 1, 18), hh = parseInt_(fh.input, 0, 18), k = parseInt_(fk.input, 1, 18), h = '', n = ec.n;
      bt.innerHTML = st.tamper ? bi('Khôi phục thông điệp', 'Restore the message') : bi('Sửa thông điệp (h + 1)', 'Tamper with the message (h + 1)');
      br.innerHTML = st.reuse ? bi('Ẩn phần dùng lại số k', 'Hide the k-reuse part') : bi('Dùng lại số k (nonce) cho thông điệp thứ hai', 'Reuse the nonce k for a second message');
      bt.setAttribute('aria-pressed', st.tamper ? 'true' : 'false'); br.setAttribute('aria-pressed', st.reuse ? 'true' : 'false');
      if (d === null || hh === null || k === null) {
        bt.disabled = br.disabled = true;
        out.innerHTML = bad('Hãy nhập d từ 1 đến 18, h từ 0 đến 18, k từ 1 đến 18 (số nguyên).', 'Enter d from 1 to 18, h from 0 to 18, k from 1 to 18 (whole numbers).'); return;
      }
      var Q = ecdsa.pub(d), sg = ecdsa.sign(d, hh, k);
      h += '<p class="toy-sec">' + bi('1. Khoá công khai', '1. The public key') + '</p>';
      h += row('Q', 'Q = d·G = ' + d + '·(5, 1)', pt(Q), 'Điểm Q được công bố; d thì giữ kín.', 'The point Q is published; d stays secret.');
      h += '<p class="toy-sec">' + bi('2. Ký', '2. Signing') + '</p>';
      h += row('R', 'R = k·G = ' + k + '·(5, 1)', pt(sg.R), 'Điểm tạm thời sinh ra từ nonce k.', 'A throw-away point made from the nonce k.');
      h += row('r', 'r = x(R) mod n = ' + sg.R[0] + ' mod 19', sg.r, 'r là hoành độ của R.', 'r is the x-coordinate of R.');
      if (sg.reason === 'r0') {
        h += verdict('verdict', 'warn', 'TỪ CHỐI: r = 0 (hoành độ của k·G bằng 0). Chọn k khác.', 'REFUSED: r = 0 (the x-coordinate of k·G is 0). Pick another k.');
        bt.disabled = br.disabled = true; out.innerHTML = h; return;
      }
      h += row('kinv', 'k⁻¹ mod n = ' + k + '⁻¹ mod 19', sg.kinv, 'Số nghịch đảo của k: k · k⁻¹ = 1 (mod 19).', 'The inverse of k: k · k⁻¹ = 1 (mod 19).');
      h += row('s', 's = k⁻¹(h + r·d) mod n = ' + sg.kinv + '·(' + hh + ' + ' + sg.r + '·' + d + ') mod 19', sg.s === null ? 0 : sg.s, 'Chỉ người biết d mới tính được s.', 'Only someone who knows d can compute s.');
      if (sg.reason === 's0') {
        h += verdict('verdict', 'warn', 'TỪ CHỐI: s = 0. Chọn k khác.', 'REFUSED: s = 0. Pick another k.');
        bt.disabled = br.disabled = true; out.innerHTML = h; return;
      }
      bt.disabled = br.disabled = false;
      h += verdict('signed', 'ok', 'ĐÃ KÝ: chữ ký (r, s) = (' + sg.r + ', ' + sg.s + ').', 'SIGNED: the signature (r, s) = (' + sg.r + ', ' + sg.s + ').');
      var hv = st.tamper ? (hh + 1) % n : hh, V = ecdsa.verify(Q, hv, sg.r, sg.s);
      h += '<p class="toy-sec">' + bi('3. Kiểm tra bằng khoá công khai Q', '3. Verifying with the public key Q') + '</p>';
      h += row('hv', st.tamper ? 'h′ = (h + 1) mod n' : 'h', hv, st.tamper ? 'Thông điệp đã bị sửa: người kiểm nhận h + 1 thay vì h.' : 'Giá trị băm của thông điệp nhận được.', st.tamper ? 'The message was altered: the verifier receives h + 1 instead of h.' : 'The hash of the message that was received.');
      h += row('w', 'w = s⁻¹ mod n', V.w, 'Nghịch đảo của s.', 'The inverse of s.');
      h += row('u1', 'u1 = h·w mod n = ' + hv + '·' + V.w + ' mod 19', V.u1, 'Hệ số của G.', 'The multiplier for G.');
      h += row('u2', 'u2 = r·w mod n = ' + sg.r + '·' + V.w + ' mod 19', V.u2, 'Hệ số của Q.', 'The multiplier for Q.');
      h += row('R2', 'R′ = u1·G + u2·Q', pt(V.R), 'Nếu mọi thứ đúng thì R′ chính là R, vì (h + r·d)·w·G = k·G.', 'If everything is right, R′ is exactly R, because (h + r·d)·w·G = k·G.');
      h += row('xr', 'x(R′) mod n', V.xr === null ? '-' : V.xr, 'So sánh với r = ' + sg.r + '.', 'Compare it with r = ' + sg.r + '.');
      if (V.valid) {
        h += st.tamper
          ? verdict('verdict', 'warn', 'HỢP LỆ, dù thông điệp đã bị sửa: đây là một trùng hợp (khoảng 1 trên 19) chỉ có ở cỡ đồ chơi. Ở cỡ thật, xác suất này là 2^-256.', 'VALID even though the message was altered: a coincidence (about 1 in 19) that only happens at toy size. At real size the chance is 2^-256.')
          : verdict('verdict', 'ok', 'HỢP LỆ: x(R′) = r = ' + sg.r + ', chữ ký đúng với thông điệp này.', 'VALID: x(R′) = r = ' + sg.r + ', the signature fits this message.');
      } else {
        h += verdict('verdict', 'bad', V.why === 'inf' ? 'KHÔNG HỢP LỆ: R′ là điểm vô cực nên không có hoành độ để so với r.' : 'KHÔNG HỢP LỆ: x(R′) = ' + V.xr + ' khác r = ' + sg.r + '; thông điệp đã bị đổi.',
          V.why === 'inf' ? 'INVALID: R′ is the point at infinity, so there is no x-coordinate to compare with r.' : 'INVALID: x(R′) = ' + V.xr + ' differs from r = ' + sg.r + '; the message was changed.');
      }
      if (st.reuse) {
        var h2 = ecdsa.reusePick(d, hh, k), s2 = ecdsa.sign(d, h2, k), rc = ecdsa.recover(sg.r, hh, sg.s, h2, s2.s);
        h += '<p class="toy-sec toy-sec-key">' + bi('4. Lỗi nghiêm trọng: dùng lại nonce k', '4. The serious mistake: reusing the nonce k') + '</p>';
        h += row('h2', 'h2 (' + 'h + 1, h + 2, ...)', h2, 'Thông điệp thứ hai, ký với cùng d và cùng k.', 'A second message, signed with the same d and the same k.');
        h += row('s2', 's2 = k⁻¹(h2 + r·d) mod n', s2.s, 'Chữ ký thứ hai (r, s2) có cùng r = ' + sg.r + ' - dấu hiệu cho kẻ tấn công biết k bị dùng lại.', 'The second signature (r, s2) has the same r = ' + sg.r + ' - the giveaway that k was reused.');
        h += row('krec', 'k = (h − h2) / (s − s2) mod n = (' + hh + ' − ' + h2 + ') / (' + sg.s + ' − ' + s2.s + ') mod 19', rc.k, 'Trừ hai công thức s cho nhau thì d biến mất, chỉ còn k.', 'Subtract the two s formulas and d cancels, leaving only k.');
        h += row('drec', 'd = (s·k − h) / r mod n = (' + sg.s + '·' + rc.k + ' − ' + hh + ') / ' + sg.r + ' mod 19', rc.d, 'Biết k thì giải ra khoá bí mật d.', 'Once k is known, the secret key d falls out.');
        h += rc.ok && rc.d === d && rc.k === k
          ? verdict('recovered', 'bad', 'KHOÁ BÍ MẬT BỊ LỘ: d = ' + rc.d + ', đúng bằng khoá bí mật ' + d + '. Chỉ cần hai chữ ký dùng chung nonce.', 'SECRET KEY RECOVERED: d = ' + rc.d + ', exactly the secret key ' + d + '. Two signatures sharing a nonce are enough.')
          : verdict('recovered', 'warn', 'Không khôi phục được.', 'Could not recover it.');
      }
      out.innerHTML = h;
    }
    [fd, fh, fk].forEach(function (f) { onInput(f.input, function () { st.tamper = false; st.reuse = false; render(); }); });
    bt.addEventListener('click', function () { st.tamper = !st.tamper; render(); });
    br.addEventListener('click', function () { st.reuse = !st.reuse; render(); });
    render();
  }

  /* ================================================================ mounting */
  var MOUNT = { rsa: mountRsa, ecdh: mountEcdh, ecdsa: mountEcdsa };
  function mountAll() {
    if (typeof document === 'undefined') return;
    injectCss();
    Object.keys(MOUNT).forEach(function (name) {
      var hosts = document.querySelectorAll('[data-toy="' + name + '"]');
      for (var i = 0; i < hosts.length; i++) MOUNT[name](hosts[i]);
    });
  }
  var PKToys = { rsa: rsa, ec: ec, ecdsa: ecdsa, mountAll: mountAll, bi: bi };
  root.PKToys = PKToys;
  if (typeof module !== 'undefined' && module.exports) module.exports = PKToys;
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mountAll);
    else mountAll();
  }
})(typeof window !== 'undefined' ? window : globalThis);
