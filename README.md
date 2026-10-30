# frank.github.io

Trang cá nhân **ChiU·SoC** — ghi chú & chia sẻ kinh nghiệm thiết kế vi mạch, mật mã hậu lượng tử
và những điều ngoài nghề. Song ngữ Việt / English, chuyển bằng nút **VI | EN** trên thanh tiêu đề.
Không framework, không bước build: mở `index.html` là chạy.

## Cấu trúc

```
index.html          trang chủ: giới thiệu + mục lục + 4 chuyên mục (#s1..#s4) + #about
posts/              mỗi bài là một file HTML độc lập, cũng song ngữ
posts/assets/       ảnh, hình SVG tự vẽ, PDF bài giảng, và mã JavaScript của máy tính PQC
```

Chuyên mục:

| id | tiếng Việt | English |
|---|---|---|
| `#s1` | Thiết kế vi mạch — RTL, SoC & Công cụ | Chip design — RTL, SoC & tools |
| `#s2` | Mật mã hậu lượng tử, AI & Mã sửa lỗi | Post-Quantum Cryptography, AI & Error-Correcting Codes |
| `#s3` | Nghĩ suy cùng đất nước | Thoughts on our country |
| `#s4` | Vần thơ & Giai điệu | Poetry & Melody |

Mật mã hậu lượng tử là chủ đề số một của trang: bài mới về PQC đứng đầu chuyên mục `#s2`.

## Cơ chế song ngữ

Không dùng thư viện. Mỗi đoạn văn bản có hai bản, đánh dấu bằng thuộc tính `lang`:

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
Script nhỏ ở cuối trang đổi `data-lang`, đổi luôn `document.title` (lấy từ `data-title-vi` /
`data-title-en` trên thẻ `<html>`) và nhớ lựa chọn trong `localStorage` (khoá `chiusoc-lang`).

**Quy tắc:**

- Mỗi khối `lang="vi"` phải có đúng một khối `lang="en"` cùng cấp cha — nếu thiếu, đoạn đó biến
  mất khi đổi ngôn ngữ.
- Hai bản dịch mà **không** gắn `lang` thì cả hai cùng hiện. Chữ tiếng Việt nằm ngoài mọi khối
  `lang` là lỗi.
- Phần không cần dịch (tên riêng, mã, công thức, danh mục tài liệu) để ngoài, không gắn `lang`;
  phần cố ý giữ nguyên ở cả hai ngôn ngữ thì gắn `data-i18n="neutral"` vào phần tử nhỏ nhất bao nó.
- Chuỗi do JavaScript chèn vào trang lúc chạy cũng phải có hai bản (`bi(vi, en)` trong mã của máy
  tính PQC).
- Không đặt `<span lang>` trong `<option>` của `<select>`: trình duyệt bỏ thẻ và hiện cả hai
  bản dính liền. Dùng nút chọn (`<input type="radio">` + `<label>`) như máy tính PQC.

## Máy tính PQC — `posts/pqc-calculator.html`

Máy tính ML-KEM (FIPS 203) và ML-DSA (FIPS 204) chạy hoàn toàn trong trình duyệt, không máy chủ,
không thư viện ngoài. Cách tương tác đi theo trang mẫu
[PQC Calculator của jNet Secure](https://www.jnet-secure.com/pqc-calculator); mã và thiết kế giao
diện là mã tự viết từ các văn bản chuẩn.

Ba thẻ:

- **Trao đổi khoá · ML-KEM** — năm bước, hai vai: bên nhận sinh cặp khoá (seed 64 byte ngẫu nhiên
  hoặc tự nhập) → khoá công khai sang bên gửi → bên gửi đóng gói (m 32 byte) ra bản mã và khoá chung
  → bản mã về bên nhận → bên nhận giải đóng gói. Dòng kết quả luôn nói bước tiếp theo; lật một bit
  của bản mã để thấy từ chối ngầm. Khoá đóng gói / giải đóng gói được kiểm theo FIPS 203 mục 7.2 / 7.3.
- **Ký & xác minh · ML-DSA** — khoá (seed 32 byte), thông điệp (văn bản / hex / Base64 / mảng C /
  mảng Java), ngữ cảnh tối đa 255 byte, pre-hash với cả 12 hàm băm của FIPS 204 (hàm quá yếu cho mức
  đang chọn bị gạch, và bị đặt lại về "Không" khi đổi mức), ô M′ cho thấy chuỗi byte thực sự được ký,
  rnd ngẫu nhiên hoặc rnd = 0 để ký tất định.
- **Chuyển đổi dữ liệu** — hex, hex hoa, hex cách, hex hai chấm, mảng C, mảng Java, Base64, văn bản.

Ở cả hai thẻ đầu: nạp file khoá (PEM, DER, SPKI, PKCS#8 ba dạng seed / expandedKey / both theo
RFC 9935 và RFC 9881, chứng chỉ X.509, khoá thô) hoặc dán thẳng file PEM vào ô khoá; nút nạp khoá
mẫu của RFC; dòng kiểm tra cặp khoá với ba trạng thái *khớp / thuộc cặp khác / khoá hỏng* và danh
sách từng phép kiểm. Mỗi ô dữ liệu có bộ đếm byte và các nút Hex / Base64 / C / Java, Nạp file,
Chép, Mở rộng, Xoá.

### Các file

Nạp theo đúng thứ tự này (mỗi file cần các file trước nó):

| file | nội dung | biến toàn cục |
|---|---|---|
| `assets/pqc-mlkem.js` | Keccak-f[1600], SHA3-224/256/384/512, SHAKE128/256; ML-KEM: keygen / encaps / decaps, kiểm tra đầu vào `ekCheck` / `dkCheck` | `PQCHash`, `MLKEM` |
| `assets/pqc-sha2.js` | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 | `PQCSHA2` |
| `assets/pqc-mldsa.js` | ML-DSA: keygen / sign / verify, M′ thuần và HashML-DSA (12 hàm băm + quy tắc khoá hàm yếu), `skCheck`, `recompute` (tính lại pk, tr, t0 từ sk) | `MLDSA` |
| `assets/pqc-tools.js` | định dạng dữ liệu, đọc DER / PEM / PKCS#8 / X.509, nhận dạng khoá theo OID hoặc độ dài, `pairCheck` | `PQCTools` |
| `assets/pqc-vectors.js` | vector tất định cho nút "Chạy kiểm chứng" (giá trị băm, khoá mẫu công khai của RFC) | `PQC_VECTORS` |
| `assets/pqc-calc-ui.js` | giao diện ba thẻ, ô dữ liệu, thông báo song ngữ, nút tự kiểm chứng | `PQCCalc` (cửa cho kiểm thử tự động) |

```
pqc-calc-ui.js ──► pqc-tools.js ──► pqc-mldsa.js ──► pqc-sha2.js
      │                  │               └──────────► pqc-mlkem.js (PQCHash: Keccak dùng chung)
      │                  └─────────────────────────► pqc-mlkem.js
      └─► pqc-vectors.js (chỉ cho nút kiểm chứng)
```

Nguyên tắc của mã:

- **Không chép bảng hằng số.** Bảng NTT của cả hai thuật toán, hằng số vòng và độ dịch của Keccak,
  hằng số và giá trị đầu của SHA-2 (kể cả IV của SHA-512/t) đều được tính khi nạp trang. Chép tay
  là cách chắc chắn để lọt lỗi đánh máy; tính ra thì cũng là một phép kiểm.
- **Mọi giá trị ngẫu nhiên đều là một ô trên màn hình** (seed, m, rnd): bỏ dấu "ngẫu nhiên" và nhập
  giá trị cố định thì kết quả lặp lại được từng byte.
- Ba file thuật toán và `pqc-tools.js` là **hàm thuần, không đụng DOM**, nên chạy được trong Node
  để kiểm thử.
- Không gửi gì ra mạng; khoá chỉ nằm trong bộ nhớ của trang.

### Kiểm chứng

- **Trên trang:** nút "Chạy kiểm chứng" chạy 125 phép kiểm ngay trong trình duyệt của người đọc —
  12 hàm băm, sáu bộ tham số, HashML-DSA với mọi hàm được phép, kiểm tra đầu vào, mở rộng khoá mẫu
  dạng seed của RFC 9935 / RFC 9881 và so với khoá công khai in trong chính RFC — rồi in
  `125/125 phép kiểm khớp`. Phép băm SHA-256 để so dùng `crypto.subtle` của trình duyệt, không dùng
  mã của trang.
- **Ngoài repo** (bộ kiểm thử dùng một mô hình tham chiếu riêng nên không công bố ở đây):
  843 phép so từng byte với mô hình tham chiếu đã đối chiếu vector NIST ACVP, gồm cả 37 khối PEM
  trong phụ lục C của hai RFC; 101 phép kiểm giao diện trên trang thật bằng trình duyệt giả lập
  (jsdom), soát cả hai ngôn ngữ sau mỗi cú bấm; và 40 đột biến cố ý — mỗi đột biến phải làm bộ kiểm báo đỏ.

### Khi sửa máy tính

1. Sửa mã. Giữ mọi chuỗi hiển thị ở dạng `bi('tiếng Việt', 'English')`.
2. Mở trang, bấm **Chạy kiểm chứng**: phải ra `125/125`. Thử cả hai ngôn ngữ, cả ba thẻ.
3. Một ô mới trong HTML cần đủ bộ ba `id`: `<id>`, `<id>-cnt`, `<id>-tools` — thiếu một cái thì
   `pqc-calc-ui.js` dừng ngay khi nạp và báo `missing #<id>` trong console.
4. Đổi thuật toán hay định dạng file khoá thì phải sinh lại `pqc-vectors.js` và chạy lại bộ kiểm
   thử ngoài repo, không sửa tay các giá trị băm trong đó.

Giới hạn: mã viết để **học**, không để bảo vệ dữ liệu thật — không chống tấn công kênh bên, thời
gian chạy phụ thuộc dữ liệu, khoá nằm trong bộ nhớ JavaScript.

## Thêm một bài mới

1. Copy một bài cùng loại trong `posts/` thành `posts/<ten-bai>.html`, sửa tiêu đề (`<title>`,
   `data-title-vi`, `data-title-en` — sửa riêng từng chỗ) và nội dung — nhớ viết cả hai ngôn ngữ.
2. Trong `index.html`, thêm một `<li class="art-item">` vào chuyên mục phù hợp (`#s1`…`#s4`):
   tiêu đề (`art-title`), mô tả (`art-desc`), link (`art-links`), trích dẫn (`art-quotes`, tuỳ chọn).
3. Bài chưa viết xong thì giữ nhãn `<span class="wip">…</span>` thay cho link.
4. Đổi tên một chuyên mục thì tìm tên cũ trong mọi file `posts/*.html`: dòng tác giả và nút
   "← quay lại chuyên mục" ở cuối mỗi bài cũng ghi tên chuyên mục.

Số thứ tự bài được đánh tự động, liên tục qua các chuyên mục (CSS counter) — không đánh tay.

## Kiểm tra trước khi đăng

```bash
python3 -m http.server -d .      # xem thử tại http://localhost:8000
```

Nên kiểm: thẻ HTML cân; mọi `#anchor` và file đích tồn tại; số khối `lang="vi"` bằng số khối
`lang="en"` trong từng phần tử cha; không còn chữ tiếng Việt nằm ngoài mọi khối `lang`; và không có
tên công ty, đường dẫn máy nội bộ hay email công việc nào trong trang.
