# frank.github.io

Trang cá nhân **ChiU·SoC** — ghi chú & chia sẻ kinh nghiệm thiết kế vi mạch.

## Cấu trúc

```
index.html    # trang chủ: giới thiệu + mục lục + danh sách bài theo chủ đề
posts/        # mỗi ghi chú là một file HTML độc lập
```

## Thêm một bài mới

1. Copy `posts/regression-khong-the-fail.html` thành `posts/<ten-bai>.html`, sửa tiêu đề + nội dung.
2. Trong `index.html`, thêm một `<li class="art-item">` vào section phù hợp (`#s1`…`#s4`):
   tiêu đề (`art-title`), mô tả ngắn (`art-desc`), link (`art-links`), trích dẫn (`art-quotes`, tuỳ chọn).
3. Bài chưa viết xong thì giữ nhãn `<span class="wip">đang viết</span>` thay cho link.

Số thứ tự bài được đánh tự động, liên tục qua các section (CSS counter).
