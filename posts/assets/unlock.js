/* unlock.js — mở khoá trang nội dung giới hạn của ChiU·SoC.
 *
 * Trang phục vụ cho người đọc KHÔNG chứa bản rõ: chỉ có bản mã AES-256-GCM. Mật khẩu được
 * đưa qua PBKDF2-SHA256 để dẫn ra khoá; GCM tự xác thực, nên sai mật khẩu là giải mã thất bại
 * chứ không cần so sánh chuỗi nào cả — không có gì để đọc trộm trong mã nguồn.
 */
(function () {
  'use strict';
  var SS_KEY = 'chiusoc-access';
  var $ = function (id) { return document.getElementById(id); };
  function bi(vi, en) { return '<span lang="vi">' + vi + '</span><span lang="en">' + en + '</span>'; }
  function say(cls, html) { var m = $('lock-msg'); m.className = 'lock-msg ' + cls; m.innerHTML = html; }

  function b64(s) {
    var bin = atob(s), a = new Uint8Array(bin.length), i;
    for (i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
  }

  var payload;
  try { payload = JSON.parse($('lock-payload').textContent); }
  catch (e) {
    say('bad', bi('Trang hỏng: không đọc được dữ liệu.', 'Broken page: the data could not be read.'));
    return;
  }

  function subtleOk() { return window.crypto && window.crypto.subtle && window.isSecureContext !== false; }

  /* Báo ngay lúc tải, đừng bắt người đọc gõ xong mật khẩu rồi mới nói là không dùng được. */
  var NO_CRYPTO = bi('Trình duyệt không giải mã được ở đây (bản lưu về máy, hoặc địa chỉ http://). ' +
                     'Hãy mở lại bài từ trang chủ qua https://.',
                     'The browser will not decrypt here (a saved copy, or an http:// address). ' +
                     'Open the article again from the home page over https://.');

  async function decrypt(password) {
    var enc = new TextEncoder();
    var base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    var key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: b64(payload.salt), iterations: payload.iter, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    var plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(payload.iv) }, key, b64(payload.ct));
    return new TextDecoder().decode(plain);
  }

  function reveal(html) {
    document.open();
    document.write(html);
    document.close();
  }

  function busy(on) { $('lock-go').disabled = on; $('lock-pw').disabled = on; }

  async function attempt(password, quiet) {
    if (!subtleOk()) { say('bad', NO_CRYPTO); return false; }
    busy(true);
    /* quiet = mở lại bằng mật khẩu đã nhớ. Vẫn phải nói đang làm gì, nếu không người đọc
       thấy một ô nhập bị khoá rồi trang đổi dưới tay mình. */
    say('wait', quiet ? bi('Đang mở lại bài…', 'Opening the article…')
                      : bi('Đang mở khoá…', 'Unlocking…'));
    var html = null;
    try { html = await decrypt(password); } catch (e) { html = null; }
    busy(false);
    if (html === null) {
      try { sessionStorage.removeItem(SS_KEY); } catch (e) {}
      say('bad', bi('<strong>Nội dung giới hạn.</strong> Mật khẩu không đúng, bạn thử lại nhé.',
                    '<strong>Limited access.</strong> That password is not right — please try again.'));
      if (!quiet) { $('lock-pw').value = ''; $('lock-pw').focus(); }
      return false;
    }
    if ($('lock-keep') && $('lock-keep').checked) {
      try { sessionStorage.setItem(SS_KEY, password); } catch (e) {}
    }
    reveal(html);
    return true;
  }

  $('lock-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var p = $('lock-pw').value;
    if (!p) {
      say('bad', bi('Hãy nhập mật khẩu.', 'Please enter the password.'));
      return;
    }
    attempt(p, false);
  });

  if (!subtleOk()) {
    say('bad', NO_CRYPTO);
    $('lock-pw').disabled = true;
    $('lock-go').disabled = true;
    return;
  }

  /* đã mở khoá ở thẻ này rồi thì vào thẳng */
  var remembered = null;
  try { remembered = sessionStorage.getItem(SS_KEY); } catch (e) {}
  if (remembered) { attempt(remembered, true); }
})();
