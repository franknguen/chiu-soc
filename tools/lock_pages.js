#!/usr/bin/env node
/* lock_pages.js — khoá / mở khoá các trang nội dung giới hạn của ChiU·SoC.
 *
 *   node tools/lock_pages.js lock      # _plain/<tên>.html  ->  posts/<tên>.html (đã mã hoá)
 *   node tools/lock_pages.js restore   # posts/<tên>.html   ->  _plain/<tên>.html (giải mã)
 *   node tools/lock_pages.js status    # không cần mật khẩu: trang nào sửa trong _plain/ mà chưa khoá lại
 *   node tools/lock_pages.js adopt     # không cần mật khẩu: ghi dấu vân tay lần đầu (khi mọi trang đều mới theo mtime)
 *   node tools/lock_pages.js restore --force   # ghi đè cả trang có bản sửa chưa khoá (mặc định: từ chối)
 *
 * Dấu vân tay (04/11/2026): lock / restore / adopt ghi SHA-256 của bản rõ và của bản mã vào
 * _plain/.lock-state.json (bị .gitignore cùng _plain/). status so NỘI DUNG, không chỉ thời điểm sửa: git pull /
 * checkout đổi mtime của posts/ và từng làm một bản sửa chưa khoá "biến mất" khỏi status; restore từng ghi đè
 * thẳng lên bản sửa chưa khoá. Hook tools/git-hooks/pre-commit dựa vào mã thoát của status.
 *
 * Mật khẩu lấy từ biến môi trường CHIUSOC_LOCK_PW. KHÔNG bao giờ ghi mật khẩu vào kho mã nguồn.
 *
 * Cơ chế: toàn bộ trang gốc được mã hoá AES-256-GCM; khoá dẫn từ mật khẩu bằng PBKDF2-SHA256.
 * Trang phục vụ cho người đọc chỉ chứa bản mã. Không có mật khẩu thì không có bản rõ ở đâu cả —
 * khác hẳn kiểu "if (password === ...)" vốn chỉ cần xem mã nguồn là qua.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const PLAIN = path.join(ROOT, '_plain');
const POSTS = path.join(ROOT, 'posts');
const ITER = 600000;   // PBKDF2-HMAC-SHA256 — mức OWASP 2023 (310 000 là con số năm 2021)
const PAGES = [
  'pqc-calculator.html',
  'kpqc-calculator.html',
  'nist-205-206-207-calculator.html',
  'rsa-fips-186-5.html',
  'ecdh-ecdsa-nist-curves.html',
  'sha2-sha3-keccak.html',
  'tu-ma-luong-tu-den-ecc.html'
];

const STATE = path.join(PLAIN, '.lock-state.json');
const sha = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
function loadState() { try { return JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch (e) { return {}; } }
function saveState(st) { fs.mkdirSync(PLAIN, { recursive: true }); fs.writeFileSync(STATE, JSON.stringify(st, null, 1) + '\n'); }
function mark(st, name) {
  st[name] = { plain: sha(fs.readFileSync(path.join(PLAIN, name))), shell: sha(fs.readFileSync(path.join(POSTS, name))),
               at: new Date().toISOString() };
}
/* trạng thái một trang: 'ok' | 'plain' (bản rõ sửa sau lần khoá cuối) | 'shell' (bản mã đổi từ bên ngoài) | 'both' | null (chưa có dấu vân tay) */
function drift(st, name) {
  const e = st[name];
  if (!e) return null;
  const p = sha(fs.readFileSync(path.join(PLAIN, name))) !== e.plain;
  const s = sha(fs.readFileSync(path.join(POSTS, name))) !== e.shell;
  return p && s ? 'both' : p ? 'plain' : s ? 'shell' : 'ok';
}

function pw() {
  const p = process.env.CHIUSOC_LOCK_PW;
  if (!p) { console.error('Thiếu biến môi trường CHIUSOC_LOCK_PW'); process.exit(2); }
  return p;
}
function shellTemplate(payloadJson) {
  const houseCss = fs.readFileSync(path.join(ROOT, 'tools', 'lock-shell.css'), 'utf8');
  return `<!DOCTYPE html>
<html lang="vi" data-lang="vi"
      data-title-vi="Nội dung giới hạn — ChiU·SoC"
      data-title-en="Limited access — ChiU·SoC">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<meta name="robots" content="noindex, nofollow"/>
<title>Nội dung giới hạn — ChiU·SoC</title>
<meta name="description" content="Trang này cần mật khẩu. This page requires a password."/>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Inter:ital,wght@0,400;0,600;0,700;0,800;1,400&amp;display=swap" rel="stylesheet"/>
<style>
${houseCss}</style>
</head>
<body>

<header>
  <div class="header-inner">
    <div class="site-title"><a href="../index.html">ChiU<span class="dot">·</span>SoC</a></div>
    <a class="back-home" href="../index.html"><span lang="vi">← Trang chủ</span><span lang="en">← Home</span></a>
    <div class="lang-switch" role="group" aria-label="Language / Ngôn ngữ">
      <button type="button" class="lang-btn" data-lang="vi" aria-pressed="true">VI</button>
      <button type="button" class="lang-btn" data-lang="en" aria-pressed="false">EN</button>
    </div>
  </div>
</header>

<main>
<section class="lockbox" id="lock-gate">
  <div class="lock-icon" aria-hidden="true">
    <svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
      <rect x="4" y="10.5" width="16" height="10" rx="2.5"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/>
    </svg>
  </div>
  <h1><span lang="vi">Nội dung giới hạn</span><span lang="en">Limited access</span></h1>
  <p class="lock-lede">
    <span lang="vi">Bài này tôi chỉ chia sẻ riêng. Nếu bạn đã có mật khẩu, nhập vào đây để đọc.</span>
    <span lang="en">I share this article privately. If you have the password, enter it here to read it.</span>
  </p>
  <noscript>
    <p class="lock-msg bad">
      <span lang="vi">Trang này cần JavaScript để giải mã nội dung. Hãy bật JavaScript rồi tải lại trang.</span>
      <span lang="en">This page needs JavaScript to decrypt its contents. Please enable JavaScript and reload.</span>
    </p>
  </noscript>
  <form id="lock-form" autocomplete="off">
    <label for="lock-pw" class="lock-label"><span lang="vi">Mật khẩu</span><span lang="en">Password</span></label>
    <input type="password" id="lock-pw" autocomplete="current-password"
           spellcheck="false" autofocus/>
    <button class="btn" type="submit" id="lock-go"><span lang="vi">Mở khoá</span><span lang="en">Unlock</span></button>
  </form>
  <label class="lock-remember">
    <input type="checkbox" id="lock-keep" checked/>
    <span lang="vi">Nhớ mật khẩu cho đến khi đóng thẻ này</span><span lang="en">Remember the password until this tab is closed</span>
  </label>
  <p class="lock-msg" id="lock-msg" role="status" aria-live="polite"></p>
  <p class="lock-foot">
    <span lang="vi">Nếu bạn muốn đọc bài này, hãy nhắn cho tôi qua địa chỉ ở trang chủ.</span>
    <span lang="en">If you would like to read it, write to me at the address on the home page.</span>
  </p>
</section>
</main>

<footer>
  <span lang="vi">© 2026 Frank Nguyen · <strong>ChiU·SoC</strong></span>
  <span lang="en">© 2026 Frank Nguyen · <strong>ChiU·SoC</strong></span>
</footer>

<script id="lock-payload" type="application/json">${payloadJson}</script>
<script src="assets/unlock.js"></script>
<script>
(function () {
  var KEY = 'chiusoc-lang';
  var root = document.documentElement;
  function apply(lang) {
    if (lang !== 'vi' && lang !== 'en') { lang = 'vi'; }
    root.setAttribute('data-lang', lang);
    root.setAttribute('lang', lang);
    var t = root.getAttribute('data-title-' + lang);
    if (t) { document.title = t; }
    var btns = document.querySelectorAll('.lang-btn');
    for (var i = 0; i < btns.length; i++) {
      btns[i].setAttribute('aria-pressed', btns[i].getAttribute('data-lang') === lang ? 'true' : 'false');
    }
    try { localStorage.setItem(KEY, lang); } catch (e) {}
  }
  var saved = null;
  try { saved = localStorage.getItem(KEY); } catch (e) {}
  if (saved) { apply(saved); }
  document.addEventListener('click', function (ev) {
    var el = ev.target;
    while (el && el !== document) {
      if (el.classList && el.classList.contains('lang-btn')) { apply(el.getAttribute('data-lang')); return; }
      el = el.parentNode;
    }
  });
})();
</script>

</body>
</html>
`;
}

function lock(password) {
  let n = 0;
  const st = loadState();
  for (const name of PAGES) {
    const srcPath = path.join(PLAIN, name);
    if (!fs.existsSync(srcPath)) { console.error('  thiếu nguồn: _plain/' + name); process.exitCode = 1; continue; }
    const plain = fs.readFileSync(srcPath);
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const key = crypto.pbkdf2Sync(password, salt, ITER, 32, 'sha256');
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
    const payload = JSON.stringify({
      v: 1, kdf: 'PBKDF2-SHA256', iter: ITER,
      salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64')
    });
    fs.writeFileSync(path.join(POSTS, name), shellTemplate(payload));
    const kb = (x) => (x / 1024).toFixed(0).padStart(4) + ' KB';
    console.log(`  khoá  ${name.padEnd(34)} ${kb(plain.length)} -> ${kb(fs.statSync(path.join(POSTS, name)).size)}`);
    mark(st, name);
    n++;
  }
  saveState(st);
  console.log(`\n${n}/${PAGES.length} trang đã khoá`);
  return n === PAGES.length;
}

function restore(password, force) {
  let n = 0;
  const st = loadState();
  for (const name of PAGES) {
    const plainPath = path.join(PLAIN, name);
    if (!force && fs.existsSync(plainPath)) {
      const d = drift(st, name);
      const unlocked = d === 'plain' || d === 'both' ||
        (d === null && fs.statSync(plainPath).mtimeMs - fs.statSync(path.join(POSTS, name)).mtimeMs > 1000);
      if (unlocked) {
        console.error('  TỪ CHỐI ghi đè _plain/' + name + ': có bản sửa chưa khoá (chạy lock trước, hoặc restore --force)');
        process.exitCode = 1; continue;
      }
    }
    const html = fs.readFileSync(path.join(POSTS, name), 'utf8');
    const m = html.match(/<script id="lock-payload" type="application\/json">([\s\S]*?)<\/script>/);
    if (!m) { console.error('  không phải trang đã khoá: posts/' + name); process.exitCode = 1; continue; }
    const p = JSON.parse(m[1]);
    const key = crypto.pbkdf2Sync(password, Buffer.from(p.salt, 'base64'), p.iter, 32, 'sha256');
    const raw = Buffer.from(p.ct, 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(p.iv, 'base64'));
    d.setAuthTag(raw.subarray(raw.length - 16));
    let out;
    try { out = Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]); }
    catch (e) { console.error('  SAI MẬT KHẨU hoặc bản mã hỏng: ' + name); process.exitCode = 1; continue; }
    fs.mkdirSync(PLAIN, { recursive: true });
    fs.writeFileSync(path.join(PLAIN, name), out);
    mark(st, name);
    console.log('  khôi phục  ' + name);
    n++;
  }
  saveState(st);
  console.log(`\n${n}/${PAGES.length} trang đã khôi phục về _plain/`);
  return n === PAGES.length;
}

/* status: không cần mật khẩu. Bắt lỗi hay gặp nhất — sửa _plain/ rồi quên khoá,
   nên GitHub Pages vẫn phục vụ bản mã cũ. So sánh thời điểm sửa, không đọc nội dung. */
function status() {
  let stale = 0, missing = 0, legacy = 0;
  const st = loadState();
  for (const name of PAGES) {
    const post = path.join(POSTS, name), plain = path.join(PLAIN, name);
    if (!fs.existsSync(post)) { console.log('  THIẾU TRANG   ' + name); missing++; continue; }
    const locked = fs.readFileSync(post, 'utf8').includes('id="lock-payload"');
    if (!locked) { console.log('  CHƯA KHOÁ     ' + name + '   (chạy: lock)'); stale++; continue; }
    if (!fs.existsSync(plain)) { console.log('  khoá, no _plain  ' + name + '   (chạy: restore nếu muốn sửa)'); continue; }
    const d = drift(st, name);
    if (d === 'plain') { console.log('  BẢN MÃ CŨ     ' + name + '   (bản rõ đã sửa sau lần khoá cuối — chạy: lock)'); stale++; continue; }
    if (d === 'shell') { console.log('  BẢN MÃ ĐÃ ĐỔI ' + name + '   (posts/ khác lần khoá/khôi phục cuối, vd. sau git pull — chạy: restore trước khi sửa)'); stale++; continue; }
    if (d === 'both')  { console.log('  XUNG ĐỘT      ' + name + '   (cả bản rõ lẫn bản mã đều đổi — so sánh trước khi lock hay restore)'); stale++; continue; }
    if (d === 'ok')    { console.log('  ok            ' + name); continue; }
    legacy++;                                     /* chưa có dấu vân tay: quy tắc cũ theo thời điểm sửa */
    const dt = fs.statSync(plain).mtimeMs - fs.statSync(post).mtimeMs;
    if (dt > 1000) { console.log('  BẢN MÃ CŨ     ' + name + '   (_plain mới hơn — chạy: lock)'); stale++; }
    else console.log('  ok (mtime)    ' + name);
  }
  if (legacy) console.log(`\n  ${legacy} trang chưa có dấu vân tay nội dung — chỉ so được thời điểm sửa. Chạy lock (hoặc adopt) một lần.`);
  console.log(stale || missing ? `\n${stale + missing} trang cần xử lý` : `\n${PAGES.length}/${PAGES.length} trang đã khoá và còn mới`);
  return stale === 0 && missing === 0;
}

/* adopt: ghi dấu vân tay lần đầu, không cần mật khẩu — chỉ khi MỌI trang đều mới theo quy tắc thời điểm sửa. */
function adopt() {
  const st = loadState();
  for (const name of PAGES) {
    const post = path.join(POSTS, name), plain = path.join(PLAIN, name);
    if (!fs.existsSync(post) || !fs.existsSync(plain) || !fs.readFileSync(post, 'utf8').includes('id="lock-payload"')) {
      console.error('  không adopt được: ' + name + ' (thiếu bản rõ / bản mã)'); return false;
    }
    if (fs.statSync(plain).mtimeMs - fs.statSync(post).mtimeMs > 1000) {
      console.error('  không adopt được: ' + name + ' có bản sửa chưa khoá — chạy lock'); return false;
    }
  }
  for (const name of PAGES) mark(st, name);
  saveState(st);
  console.log(`  đã ghi dấu vân tay cho ${PAGES.length} trang vào _plain/.lock-state.json`);
  return true;
}

const cmd = process.argv[2];
if (cmd === 'lock') process.exit(lock(pw()) ? 0 : 1);
else if (cmd === 'restore') process.exit(restore(pw(), process.argv.includes('--force')) ? 0 : 1);
else if (cmd === 'adopt') process.exit(adopt() ? 0 : 1);
else if (cmd === 'status') process.exit(status() ? 0 : 1);
else { console.error('dùng: node tools/lock_pages.js lock|restore [--force]|status|adopt'); process.exit(2); }
