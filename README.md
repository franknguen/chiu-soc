# frank.github.io

Trang cá nhân **ChiU·SoC** — ghi chú & chia sẻ kinh nghiệm thiết kế vi mạch.
Song ngữ Việt / English, chuyển bằng nút **VI | EN** trên thanh tiêu đề.

## Cấu trúc

```
index.html    # trang chủ: giới thiệu + mục lục + 4 chuyên mục (#s1..#s4) + #about
posts/        # mỗi ghi chú là một file HTML độc lập, cũng song ngữ
```

Chuyên mục: `#s1` Thiết kế vi mạch · `#s2` Kinh nghiệm · `#s3` Nghĩ suy cùng đất nước ·
`#s4` Vần thơ & Giai điệu.

## Cơ chế song ngữ

Không dùng thư viện, không có bước build. Mỗi đoạn văn bản có hai bản,
đánh dấu bằng thuộc tính `lang`:

```html
<p lang="vi">Bản tiếng Việt…</p>
<p lang="en">The English version…</p>
<span lang="vi">ngắn</span><span lang="en">short</span>
```

CSS chỉ hiện ngôn ngữ đang chọn:

```css
html[data-lang="vi"] [lang="en"]{ display:none; }
html[data-lang="en"] [lang="vi"]{ display:none; }
```

`<html>` mặc định `data-lang="vi"` nên **không có JavaScript vẫn đọc được bản tiếng Việt**.
Script nhỏ ở cuối trang đổi `data-lang`, đổi luôn `document.title`
(lấy từ `data-title-vi` / `data-title-en` trên thẻ `<html>`) và nhớ lựa chọn
trong `localStorage` (khoá `chiusoc-lang`).

**Quy tắc:** mỗi khối `lang="vi"` phải có đúng một khối `lang="en"` cùng cấp cha —
nếu thiếu, đoạn đó biến mất khi đổi ngôn ngữ. Phần không cần dịch (tên riêng, mã,
công thức, danh mục tài liệu tham chiếu) thì để ngoài, không gắn `lang`.

## Thêm một bài mới

1. Copy `posts/md5-rfc1321.html` thành `posts/<ten-bai>.html`, sửa tiêu đề
   (`<title>`, `data-title-vi`, `data-title-en`) và nội dung — nhớ viết cả hai ngôn ngữ.
2. Trong `index.html`, thêm một `<li class="art-item">` vào chuyên mục phù hợp (`#s1`…`#s4`):
   tiêu đề (`art-title`), mô tả (`art-desc`), link (`art-links`), trích dẫn (`art-quotes`, tuỳ chọn).
3. Bài chưa viết xong thì giữ nhãn `<span class="wip">…</span>` thay cho link.

Số thứ tự bài được đánh tự động, liên tục qua các chuyên mục (CSS counter) — không đánh tay.

## Kiểm tra trước khi đăng

```bash
python3 -m http.server -d .      # xem thử tại http://localhost:8000
```

Nên kiểm: thẻ HTML cân, mọi `#anchor` và file đích tồn tại, và số khối
`lang="vi"` bằng số khối `lang="en"` trong từng phần tử cha.
