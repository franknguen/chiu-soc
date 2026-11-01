# frank.github.io

Trang cá nhân **ChiU·SoC** — ghi chú những gì học được khi làm nghiên cứu sinh Ph.D. và trong công việc
kỹ sư thiết kế vi mạch số / SoC — thuật toán mật mã (cổ điển và hậu lượng tử), mã sửa lỗi, thiết kế và
verification SoC / ASIC, EDA mã nguồn mở — cùng những điều ngoài nghề. Song ngữ Việt / English, chuyển
bằng nút **VI | EN** trên thanh tiêu đề.
Không framework, không bước build: mở `index.html` là chạy.

## Cấu trúc

```
index.html          trang chủ: giới thiệu + mục lục + 4 chuyên mục (#s1..#s4) + #about
posts/              mỗi bài là một file HTML độc lập, cũng song ngữ
posts/assets/       ảnh, hình SVG tự vẽ, PDF bài giảng, và mã JavaScript của ba máy tính PQC
                    (ML-KEM / ML-DSA, SMAUG-T / HAETAE, SLH-DSA / FN-DSA / HQC-KEM)
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

## Máy tính KpqC — `posts/kpqc-calculator.html`

Trang anh em của máy tính PQC, cho hai thuật toán lattice mà cuộc thi KpqC của Hàn Quốc chọn năm 2025:
**SMAUG-T** (trao đổi khoá; TiMER, SMAUG-T128 / 192 / 256) và **HAETAE** (chữ ký; HAETAE-2 / 3 / 5).
Cùng ba thẻ, cùng cách tương tác, cùng các ô và nút. Khác ở chỗ:

- **Phiên bản được ghi rõ:** SMAUG-T mã tham chiếu 1.2.0 (đặc tả 260521), HAETAE mã tham chiếu 1.2.0
  (đặc tả 260904, bộ lấy mẫu mới từ 260825). Đặc tả của cả hai đổi trong năm 2026; đổi phiên bản thì
  phải sinh lại vector và chạy lại bộ kiểm thử.
- **Nút "Nạp ví dụ KAT chính thức"** thay cho khoá mẫu RFC: điền đầu vào của mục count = 0 trong file KAT
  của nhóm tác giả, rồi báo từng bước (khoá, bản mã / chữ ký) có trùng file đó không.
- **Chỉ có khoá thô** (nhị phân / hex / Base64), nhận theo độ dài, vì hai thuật toán chưa có OID hay định
  dạng file chuẩn. TiMER và SMAUG-T128 có khoá cùng kích thước: trang chọn mức đang mở và nói rõ. File
  PEM / DER của ML-KEM / ML-DSA được nhận ra và chỉ sang trang máy tính PQC.
- **SMAUG-T:** μ dài 16 byte với TiMER, 32 byte với các mức khác; khoá bí mật có mã 2 bit bằng 3 hoặc sai
  trọng số Hamming bị từ chối trước khi giải đóng gói (mã tham chiếu C không kiểm hai điều này).
- **HAETAE:** không có pre-hash; ô M′ = độ dài ngữ cảnh ‖ ngữ cảnh ‖ thông điệp; chữ ký sai được gọi
  đúng tên lý do (sai độ dài, rANS, phần đệm, chuẩn, thử thách); số lần thử của mỗi lần ký được hiện ra.

Các file (nạp theo thứ tự này; ba file đầu dùng chung với trang ML-KEM / ML-DSA):

| file | nội dung | biến toàn cục |
|---|---|---|
| `assets/pqc-mlkem.js`, `pqc-sha2.js`, `pqc-mldsa.js`, `pqc-tools.js` | tầng Keccak, SHA-2, định dạng dữ liệu, đọc file khoá (để nhận ra file ML-KEM / ML-DSA) | `PQCHash`, `PQCSHA2`, `MLDSA`, `PQCTools` |
| `assets/pqc-smaugt.js` | SMAUG-T: keygen / encaps / decaps, `skCheck`, `pkFromSk` | `SMAUGT` |
| `assets/pqc-haetae.js` | HAETAE: keygen / sign / verify (lý do thất bại có tên), `pkFromSk` | `HAETAE` |
| `assets/kpqc-tools.js` | kích thước, nhận dạng khoá thô theo độ dài, `pairCheck` | `KPQCTools` |
| `assets/kpqc-vectors.js` | đầu vào + giá trị băm của mục KAT chính thức count = 0, vector seed cố định | `KPQC_VECTORS` |
| `assets/kpqc-calc-ui.js` | giao diện ba thẻ, thông báo song ngữ, nút KAT, nút tự kiểm chứng | `KPQCCalc` (cửa cho kiểm thử tự động) |

Kiểm chứng: nút "Chạy kiểm chứng" chạy 77 phép kiểm trong trình duyệt (tầng Keccak, mục KAT chính thức
count = 0 và một seed cố định cho mỗi bộ tham số, chữ ký sai, bộ chuyển đổi). Ngoài repo: 453 phép so
từng byte với cả 21 mục KAT chính thức (12 SMAUG-T, 9 HAETAE) và một mô hình tham chiếu; 71 phép kiểm
giao diện bằng trình duyệt giả lập, soát hai ngôn ngữ sau mỗi cú bấm; 32 đột biến cố ý — 30 bị bắt, hai còn lại là hai giới hạn
được ghi rõ: ngưỡng chuẩn B″ của bộ xác minh HAETAE không với tới được bằng chữ ký giải mã được, và 32 bit
thấp nhất của bảng Gaussian 83 bit (sai ở đó chỉ đổi khoảng một mẫu trong 2^51). Mã HAETAE dùng `BigInt`
(Chrome 67+, Firefox 68+, Safari 14+).

Khi sửa trang này, giữ cùng quy tắc như máy tính PQC ở trên (chuỗi `bi()`, bộ ba `id`, bấm kiểm chứng phải ra
toàn xanh).

## Máy tính SLH-DSA / FN-DSA / HQC-KEM — `posts/nist-205-206-207-calculator.html`

Trang thứ ba của loạt máy tính, cho ba thuật toán hậu lượng tử còn lại của NIST, cùng cách tương tác:

| thẻ | chuẩn | trạng thái (kiểm 31/10/2026) | trang hiện thực |
|---|---|---|---|
| Ký · SLH-DSA | FIPS 205 | đã ban hành 13/08/2024 | đúng FIPS 205, cả 12 bộ tham số (SHA2 / SHAKE × 128 / 192 / 256 × s / f) |
| Ký · FN-DSA | FIPS 206 | chưa công bố dự thảo | Falcon v1.2 + hành vi của mã tham chiếu vòng 3 (Falcon-512 / 1024), chữ ký dạng có đệm của đặc tả |
| Trao đổi khoá · HQC-KEM | FIPS 207 | chưa công bố dự thảo (HQC được chọn 03/2025, NIST IR 8545) | đặc tả HQC 12/10/2026 + mã tham chiếu 5.1.0 (dk = seed 32 byte) |

Khác với hai trang trước:

- **Web Worker.** Ký SLH-DSA bộ "s" mất từ khoảng 1 giây (SHA2-128s) tới khoảng 11 giây (SHAKE-192s), đo bằng Node; sinh khoá Falcon-1024 và kiểm tra cặp khoá cũng lâu.
  Các phép này chạy trong `assets/nist-worker.js` để trang không đứng; dòng kết quả đếm giây trong lúc chờ. Trình duyệt chặn
  Worker khi mở file trực tiếp từ đĩa (`file://`) — khi đó trang tự chạy ở luồng chính, sau khi kịp vẽ dòng "đang tính".
  Xem thử bằng `python3 -m http.server` để có Worker.
- **SLH-DSA:** ba nhóm nút chọn bộ tham số (hàm băm, mức, biến thể); pre-hash với 12 hàm, hàm có giá trị băm ngắn hơn 2n byte
  bị gạch (FIPS 205 mục 10.2.2); addrnd để trống = ký tất định. Nút "Nạp ví dụ ACVP của NIST" dùng vector keyGen chính thức.
- **FN-DSA:** không có ngữ cảnh / pre-hash vì FIPS 206 chưa định nghĩa; hai ô ngẫu nhiên của lần ký (muối r 40 byte, seed bộ lấy
  mẫu 48 byte). Sinh khoá giải phương trình NTRU **chính xác**: với một số ít seed (ví dụ mục 1 của KAT Falcon-1024) mã C tham
  chiếu — giải với độ chính xác cố định — chọn một ứng viên khác, nên khoá khác KAT; chữ ký ký từ khoá của KAT thì luôn trùng.
- **HQC-KEM:** năm bước như ML-KEM; khoá giải đóng gói chính là seed 32 byte; `HQC.pkeDecrypt` là cửa chỉ dành cho kiểm thử bộ
  giải mã nối Reed–Solomon × Reed–Muller (bộ KAT không bao giờ cần Reed–Solomon sửa lỗi).
- Khoá thô cho cả ba (chưa có định dạng file chuẩn dùng chung); SLH-DSA có nhiều bộ cùng độ dài khoá, trang ưu tiên bộ đang mở và
  nút đã bấm, rồi nói rõ khi phải đoán.

Các file mới (nạp sau `pqc-mlkem.js`, `pqc-sha2.js`, `pqc-mldsa.js`, `pqc-tools.js`):

| file | nội dung | biến toàn cục |
|---|---|---|
| `assets/pqc-slhdsa.js` | SLH-DSA (FIPS 205): 12 bộ, Alg. 18–25, giao diện trong / ngoài, HashSLH-DSA | `SLHDSA` |
| `assets/pqc-fndsa.js` | Falcon-512 / 1024: keygen (NTRUSolve bằng `BigInt`), ký (FFT số thực IEEE-754, ffSampling), xác minh có lý do | `FNDSA` |
| `assets/pqc-hqc.js` | HQC-1 / 3 / 5: keygen, encaps, decaps, mã nối RS × RM | `HQC` |
| `assets/nist-tools.js` | kích thước, quy tắc pre-hash 2n, nhận dạng khoá thô, kiểm tra cặp khoá — chạy được cả trong Worker | `NIST3Tools` |
| `assets/nist-worker.js` | Web Worker: chạy một phép của `SLHDSA` / `FNDSA` / `HQC` / `NIST3Tools` mỗi thông điệp | — |
| `assets/nist-vectors.js` | vector ACVP (SLH-DSA), mục KAT count = 0 (Falcon, HQC), vector seed cố định | `NIST3_VECTORS` |
| `assets/nist-calc-ui.js` | giao diện bốn thẻ, gọi Worker, nút ví dụ ACVP / KAT, nút tự kiểm chứng | `NIST3Calc` (cửa cho kiểm thử) |

Kiểm chứng: nút "Chạy kiểm chứng" chạy 59 phép kiểm trong trình duyệt. Ngoài repo: 463 phép so từng byte với vector ACVP
của NIST (SLH-DSA, kể cả bộ "s" khi chạy đầy đủ), KAT vòng 3 của Falcon, KAT 5.1.0 của HQC, một mô hình tham chiếu, các ca bộ
giải mã HQC hỏng đúng tới giới hạn sửa lỗi t1 rồi quá một khối, và chữ ký Falcon mã hoá "+0" / "−0"; 67 phép kiểm giao diện
bằng trình duyệt giả lập, soát hai ngôn ngữ sau mỗi cú bấm; 28 đột biến cố ý — cả 28 bị bắt. Lượt đột biến đầu còn ba đột biến
sống, chỉ ra ba chỗ phép kiểm hở; vá chỗ thứ hai lộ ra một lỗi thật ở `pqc-tools.js` dùng chung: file khoá nhị phân mà byte
nào cũng in được (ví dụ dk 32 byte toàn 0x09) bị từ chối — nay `readKeyFile` coi chính các byte là khoá thô khi văn bản không
phải PEM / hex / Base64. Hai trang ML và KpqC đã chạy lại xanh sau thay đổi này.

## Thêm một bài mới

1. Copy một bài cùng loại trong `posts/` thành `posts/<ten-bai>.html`, sửa tiêu đề (`<title>`,
   `data-title-vi`, `data-title-en` — sửa riêng từng chỗ) và nội dung — nhớ viết cả hai ngôn ngữ.
2. Trong `index.html`, thêm một `<li class="art-item">` vào chuyên mục phù hợp (`#s1`…`#s4`):
   tiêu đề (`art-title`), mô tả (`art-desc`), link (`art-links`), trích dẫn (`art-quotes`, tuỳ chọn).
3. Bài chưa viết xong thì giữ nhãn `<span class="wip">…</span>` thay cho link.
4. Đổi tên một chuyên mục thì tìm tên cũ trong mọi file `posts/*.html`: dòng tác giả và nút
   "← quay lại chuyên mục" ở cuối mỗi bài cũng ghi tên chuyên mục.

Số thứ tự bài được đánh tự động, liên tục qua các chuyên mục (CSS counter) — không đánh tay.

## Định dạng chung của mọi trang

Mỗi trang mang `<style>` riêng (không có stylesheet dùng chung, không bước build), nên quy tắc trình bày
chung chỉ tồn tại khi **mọi trang lặp lại đúng một khối CSS**. Khối đó nằm cuối `<style>` của từng trang,
kẹp giữa hai dòng chú thích `/* ==== house-format v1 … */` và `/* ==== /house-format ==== */`:

- Văn xuôi **canh đều hai bên** (`text-align:justify`, có `hyphens:auto`): mọi `p`, `li`, `blockquote`,
  `dd`, `.art-desc`, `.art-quote` trong `<main>`.
- Trả về **canh trái** cho các danh sách thực chất là hàng link (`.refs`, `.art-links`, `.songlist`, mục lục,
  dòng kiểm tra cặp khoá / kết quả của máy tính PQC, mọi thứ trong bảng) — canh đều sẽ kéo giãn dòng đầu
  của một mục hai dòng thành khoảng trắng lớn.
- Giữ **canh giữa** cho dòng ghi tác giả dưới bài thơ, chú thích video và chú thích hình.
- Không ngắt từ bằng gạch nối trong `code`, `pre`, `kbd`, `samp` và link — một tên file bị ngắt thành
  `calcu-lator` đọc như gạch nối thật.

Header, nav và footer không bị khối này chạm tới. Muốn đổi định dạng thì đổi khối này **ở cả mười trang** cho
giống hệt nhau (ngoài repo có script chèn / thay khối này cho mọi trang trong một lần); một trang thiếu khối
hay có khối bị sửa tay sẽ bị bước kiểm tra trước khi đăng từ chối.

## Kiểm tra trước khi đăng

```bash
python3 -m http.server -d .      # xem thử tại http://localhost:8000
```

Nên kiểm: thẻ HTML cân; mọi `#anchor` và file đích tồn tại; số khối `lang="vi"` bằng số khối
`lang="en"` trong từng phần tử cha; không còn chữ tiếng Việt nằm ngoài mọi khối `lang`; không có
tên công ty, đường dẫn máy nội bộ hay email công việc nào trong trang; và khối CSS `house-format` có mặt
nguyên vẹn trên mọi trang.
