# frank.github.io

Trang cá nhân **ChiU·SoC** — ghi chú những gì học được khi làm nghiên cứu sinh Ph.D. và trong công việc
kỹ sư thiết kế vi mạch số / SoC — thuật toán mật mã (cổ điển và hậu lượng tử), mã sửa lỗi, thiết kế và
verification SoC / ASIC, EDA mã nguồn mở, AI (NPU và tự động hoá) — cùng những điều ngoài nghề. Song ngữ
Việt / English, chuyển bằng nút **VI | EN** trên thanh tiêu đề.
Không framework, không bước build: mở `index.html` là chạy.

## Cấu trúc

```
index.html          trang chủ: giới thiệu + mục lục + 4 chuyên mục (#s1..#s4) + #about
posts/              mỗi bài là một file HTML độc lập, cũng song ngữ
posts/assets/       ảnh, hình SVG tự vẽ, PDF bài giảng, và mã JavaScript của ba máy tính PQC
                    (ML-KEM / ML-DSA, SMAUG-T / HAETAE, SLH-DSA / FN-DSA / HQC-KEM), của ba phòng
                    thí nghiệm mật mã cổ điển (RSA, đường cong elliptic, SHA-2 / SHA-3) và của các
                    trình mô phỏng mã sửa lỗi
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

## Bốn trình mô phỏng ECC — trong `posts/tu-ma-luong-tu-den-ecc.html`

Bốn trình mô phỏng nằm ngay trong bài viết về ECC, cùng một kiểu dùng (bấm là thấy, không nhập liệu, mọi
chuỗi hiện ra đều song ngữ): mỗi bit là một ô bấm được, số vị trí ở trên, vai trò ở dưới (D dữ liệu, C bit
kiểm, P chẵn lẻ), ô cam = bit đã lật, ô xanh = bit bộ giải mã sửa; các bước đánh số 1, 2, 3…; khung kết luận
xanh / vàng / đỏ **nói cả điều bộ giải mã tin lẫn sự thật** (trang còn nhớ dữ liệu gốc).

- **Hamming — mục 6** (thay cho khung ví dụ nền đen cũ). Chọn mã (7, 4), (12, 8) — đúng ví dụ tính tay —
  hoặc (15, 11); dòng quy tắc `2^r ≥ k + r + 1` tính sống và nói mã hoàn hảo hay rút gọn. Mở sẵn đúng ví dụ
  của bài (dữ liệu 0 1 0 0 1 1 1 1, bit 5 lật). Bước 4 là **ma trận kiểm** bấm-là-đổi: mỗi hàng một phép
  kiểm (C8 ở trên, C1 ở dưới), mỗi cột một vị trí, ô tô xanh là vị trí phép kiểm phụ trách và hiện bit nhận
  được; cột cuối ⊕ ghi ✓ / ✗. Cột ✗ đọc từ trên xuống chính là S viết nhị phân, và cột của ô hỏng có đúng
  hình ấy. Nút "Đúng 2 bit" cho thấy vì sao cần SECDED: S = a ⊕ b, bộ giải mã lật nhầm một ô lành (hoặc
  với mã rút gọn, S > n: phát hiện mà không sửa). Tự kiểm 268 496 trường hợp.
- **BCH (15, k) trên GF(16) — mục 7** (thay cho khung g(x) nền đen cũ). Chọn t = 1 / 2 / 3 → g(x) dạng tích
  các đa thức tối tiểu và dạng khai triển, số bit kiểm, k, tỉ lệ mã, d_min. Bấm ô dữ liệu → từ mã hệ thống
  và c(x); bấm ô để gây lỗi (hoặc "đúng t bit", "t + 1 bit"). Giải mã hiện đủ ba khâu của phần cứng:
  ① hội chứng S_j = r(α^j) (dạng α^i và 4 bit) → ② Berlekamp–Massey ra Λ(x) → ③ dò nghiệm Chien: hàng 15 ô
  Λ(α^−i), ô bằng 0 là ô lỗi (xanh nếu đúng, đỏ nếu nghiệm rơi vào ô lành). Bảng GF(16) trong một mục mở
  rộng. Bước 5 là **vách đá**: đếm trên mọi 2^15 mẫu lỗi xem bao nhiêu được sửa đúng / bị phát hiện / bị sửa
  sai, với hàng của số lỗi đang có được tô đậm — ví dụ t = 2, 3 lỗi: 180 / 455 sửa sai, 275 phát hiện.
  Tự kiểm 66 688 trường hợp.

- **SECDED (13, 8)** — đúng cách xếp của ví dụ trong bài: bit kiểm C1 C2 C4 C8 ở vị trí 1 2 4 8, dữ liệu
  D0..D7 ở các vị trí còn lại, bit P ở vị trí 0. Bốn bước: bấm ô để đổi dữ liệu → từ mã 13 bit kèm các
  dòng `C1 = D0 ⊕ D1 ⊕ …` tính sống → bấm ô của từ nhận để lật bit (hoặc nút 1 / 2 / 3 bit ngẫu nhiên) →
  bộ giải mã nêu S, P′, kết luận, **và nói thật kết luận ấy có đúng không** (trang còn nhớ dữ liệu gốc):
  3 lỗi thường bị "sửa" sang dữ liệu sai mà bộ giải mã vẫn tin mình đúng — bài học vách đá ở mục 9.
  Nút "Kiểm tra toàn bộ 23 552 trường hợp" chạy mọi dữ liệu × mọi mẫu lỗi ≤ 2 bit ngay trong trình duyệt.
- **Khoá PUF với dữ liệu trợ giúp** — dấu vân tay R = 4 khối × 13 bit, dùng lại đúng mã SECDED trên.
  Ba bước: đọc R lần đầu → W = (S, P) từng khối (20 bit, được phép công khai), K = SHA-256(R) → chọn số ô
  dao động (0 / 1 / 2 / 4 / 6, hoặc bấm vào ô) và đọc lại R′ → sửa bằng W, băm lại, so K′ với K. Ba kết
  cục đều hiện rõ: dựng lại đúng; vượt sức sửa (hai ô lệch trong một khối) → phải báo lỗi; và sửa sai mà
  không biết (ba ô lệch trong một khối) → lý do chip thật lưu thêm một giá trị kiểm khoá.

| File | Nội dung | Đối tượng |
|---|---|---|
| `assets/ecc-sim.js` | mã hoá / hội chứng / giải mã SECDED (13, 8), sketch hội chứng 4 khối, đóng gói 52 bit → 7 byte → SHA-256, tự kiểm 23 552 trường hợp | `ECCSim` |
| `assets/ecc-sim-ui.js` | ô bit bấm được, bốn bước SECDED, ba bước PUF, mọi chuỗi qua `bi(vi, en)` | `ECCSimPage` (cửa cho kiểm thử) |
| `assets/ecc-hamming-bch.js` | Hamming (7,4) / (12,8) / (15,11): mã hoá, hội chứng, giải mã, tự kiểm 268 496; GF(16), BCH (15, k) t = 1..3: đa thức tối tiểu, g(x), mã hoá hệ thống, hội chứng, Berlekamp–Massey, Chien, bảng vách đá, tự kiểm 66 688 | `ECCHam`, `ECCBch` |
| `assets/ecc-hamming-bch-ui.js` | ma trận kiểm của Hamming, ba khâu giải mã BCH, bảng vách đá; ô bit và `bi()` dùng lại từ `ecc-sim-ui.js` (`ECCSimPage.lib`) | `ECCHbPage` (cửa cho kiểm thử) |
| `assets/pqc-sha2.js` | SHA-256 dùng chung với các máy tính PQC | `PQCSHA2` |

Kiểm chứng (ngoài repo): một mô hình Python viết riêng theo định nghĩa (ma trận kiểm H) — 332 phép so,
gồm ví dụ trong bài, toàn bộ 23 552 trường hợp qua một giá trị băm, 120 từ 3 lỗi (88 bị sửa sai) và 16 lần
dựng khoá PUF với SHA-256 của `hashlib`; 44 phép kiểm giao diện bằng trình duyệt giả lập, soát hai ngôn ngữ
sau mỗi cú bấm; 16 đột biến cố ý — cả 16 bị bắt (8 bởi bộ so mô hình, 8 bởi bộ kiểm giao diện). Nút tự kiểm trên trang được chứng minh đỏ được bằng một bộ giải mã cài sai.

Hamming và BCH kiểm theo cùng cách (ngoài repo), với một mô hình Python thứ hai cố ý tính theo lối khác: BCH giải bằng bảng
phần dư của mọi mẫu lỗi ≤ t bit (không Berlekamp–Massey, không bảng log GF(16)), Λ(x) nhân thẳng từ vị trí lỗi — 153 phép so,
gồm giá trị băm của mọi dữ liệu × mẫu lỗi ≤ 2 bit cho cả ba mã Hamming, mọi 2^15 từ nhận cho mỗi t, hội chứng + Λ(x) của mọi
mẫu ≤ t bit và ba bảng vách đá; 141 phép kiểm giao diện (soát hai ngôn ngữ sau ~280 cú bấm); 22 đột biến cố ý — cả 22 bị bắt (11 bởi bộ so mô hình, 11 bởi bộ kiểm giao diện; 3 phút 20 giây).
Một bản xem lại độc lập (đọc mã, không chạy) chỉ ra câu cũ "mỗi bit sửa thêm tốn thêm bốn bit kiểm" là sai (t = 2 → 3 chỉ
thêm 2) và vài chỗ chữ / ký hiệu khó hiểu; đã sửa. Chưa xem trên trình duyệt thật — trên điện thoại, hàng 15 ô xuống hai dòng.

### Mạch bài viết ECC (lời dẫn, mục 1–2 — viết lại 2026-11-03)

Hai ý của tác giả, không hơn: **mã sửa lỗi lượng tử được phát triển từ mã sửa lỗi cổ điển** (Shor 1995 dùng mã lặp
ba bit hai tầng; mã CSS của Calderbank–Shor và Steane năm 1996 dựng từ một cặp mã tuyến tính cổ điển lồng nhau; mã Steane 7 qubit là
Hamming (7, 4) dùng hai lần), và **tác giả học mã cổ điển trước, rồi mới sang mã lượng tử**. Mối liên hệ vì thế là
chuyện tự nhiên: đừng viết lại kiểu "hội chứng là chiếc cầu giữa hai thế giới" hay "điều làm tôi ngạc nhiên khi
chuyển sang làm chip" — tác giả đã bác cách kể ấy. Lời dẫn, chú thích sơ đồ `ecc-khung-chung.svg` (làn trên cổ điển,
làn dưới lượng tử dựng trên làn trên), câu đầu mục 11 và mục Đọc thêm (thêm Calderbank–Shor / Steane 1996) đã
được chỉnh cho khớp.

Trang này là **trang đã khoá**: `posts/tu-ma-luong-tu-den-ecc.html` chỉ chứa bản mã. Sửa nội dung ở
`_plain/tu-ma-luong-tu-den-ecc.html` (không commit), chạy `check_site.py` trên một bản sao đầy đủ của site có bản rõ
thay vào `posts/`, rồi khoá lại bằng `node tools/lock_pages.js lock` (mật khẩu qua biến môi trường `CHIUSOC_LOCK_PW`).
Đừng chạy `restore` khi `_plain/` đang có bản sửa chưa khoá: nó ghi đè bản rõ bằng nội dung giải mã từ bản mã cũ.

## Ba bài mật mã cổ điển có phòng thí nghiệm — RSA, đường cong elliptic, SHA-2 / SHA-3

Ba bài viết cho người không chuyên (giải thích trước, công thức sau, ví dụ tính tay được, góc nhìn của người làm
phần cứng), mỗi bài kèm một **phòng thí nghiệm** chạy trong trình duyệt. Mỗi thẻ của phòng thí nghiệm là một loại
phép kiểm của NIST (CAVP / ACVP): nhập hoặc sinh ngẫu nhiên đầu vào, bấm chạy, xem **từng giá trị trung gian** kèm
một dòng giải thích hai thứ tiếng, và một dòng kết luận rõ ràng (với phép xác minh / thẩm định thì nêu cả lý do
hỏng). Nút **"Nạp ví dụ của NIST"** điền đầu vào lấy từ file vector công khai của NIST (ghi đúng tên file / tcId /
COUNT của NIST), chạy, rồi đánh dấu ✓ / ✗ từng giá trị so với giá trị NIST ghi. Mã viết từ văn bản chuẩn công khai,
số học lớn bằng `BigInt`, không thư viện ngoài, không gửi gì ra mạng.

| bài | chuẩn | các thẻ = loại phép kiểm NIST |
|---|---|---|
| `posts/rsa-fips-186-5.html` | FIPS 186-5, SP 800-56B r2, RFC 8017 | **KeyGen** (sinh khoá theo phụ lục A.1.3 với mọi phép kiểm hiện ✓ / ✗, hoặc từ p, q cho trước, hoặc kiểm một cặp khoá), **Mã hoá** (RSAEP, RSAES-OAEP SHA-256), **Giải mã** (RSADP thường và theo CRT đặt cạnh nhau, làm mù, tấn công Bellcore), **Ký / xác minh** (PKCS#1 v1.5, PSS). Khoá 512 / 1024 (chỉ để thử, có nhãn) / 2048 / 3072 / 4096 bit |
| `posts/ecdh-ecdsa-nist-curves.html` | FIPS 186-5, SP 800-186, SP 800-56A r3, RFC 6979 | ba hình tương tác (cộng điểm trên đường cong thực; mọi điểm, quỹ đạo k·G và chặn Hasse trên trường F_p nhỏ; nhân vô hướng từng bit: nhân đôi-và-cộng so với thang Montgomery) + **Sinh cặp khoá** (A.2.1 / A.2.2), **Kiểm tra khoá công khai** (SP 800-56A mục 5.6.2.3.3), **ECDH** (nguyên thuỷ KAS-ECC CDH, hai bên), **Ký ECDSA** (k ngẫu nhiên / tất định RFC 6979 / cho trước), **Xác minh** có lý do, **Tấn công** dùng lại nonce. P-192 chỉ xác minh, P-224, P-256, P-384, P-521 |
| `posts/sha2-sha3-keccak.html` | FIPS 180-4, FIPS 202, SP 800-185 | **Băm + vết** (15 hàm: SHA-1 cũ, sáu SHA-2, bốn SHA3, SHAKE128 / 256, cSHAKE128 / 256; bản đồ đệm khối cuối, bảng từng vòng, lưới 5 × 5 lane sau θ ρ π χ ι), **ShortMsg / LongMsg** (kể cả thông điệp lẻ bit), **Monte Carlo** 100 điểm kiểm, **SHAKE VariableOut**, lật bit / số khối theo độ dài / ngày sinh; ô tấn công mở rộng độ dài và ô sinh IV của SHA-512/t |

Các file (mỗi trang nạp `pqc-mlkem.js` và `pqc-sha2.js` dùng chung với các máy tính PQC trước, rồi các file riêng
theo thứ tự trong bảng):

| file | nội dung | biến toàn cục |
|---|---|---|
| `assets/rsa-core.js` | Miller–Rabin + chia thử, sinh khoá A.1.3 từ seed (luật SHAKE256(seed ‖ bộ đếm) ghi trên trang, để khoá lặp lại được), khoá từ p, q, RSAEP / RSADP theo hai miền giá trị (RFC 8017 và SP 800-56B), CRT theo Garner, Bellcore, OAEP, PKCS#1 v1.5 (DigestInfo tính từ OID), PSS, Montgomery — không đụng DOM | `RSACore` |
| `assets/rsa-vectors.js` | ví dụ CAVP / ACVP + một khoá ví dụ riêng cho mỗi cỡ NIST không có | `RSA_VECTORS` |
| `assets/rsa-ui.js` | thẻ khoá dùng chung, bốn thẻ, nút ví dụ NIST, tự kiểm | `RSALab` (cửa cho kiểm thử) |
| `assets/rsa-worker.js` | Web Worker cho sinh khoá 3072 / 4096 bit (vài giây) | — |
| `assets/ec-core.js` | năm đường cong NIST, luật nhóm affine có vết λ, Jacobian, thang Montgomery, nhân đôi-và-cộng, sinh khoá A.2.1 / A.2.2, thẩm định khoá công khai có tên bước hỏng, ECDH, bits2int, ECDSA có mã lý do, HMAC + RFC 6979, khôi phục khoá khi lặp nonce | `EC` |
| `assets/ec-plot.js` | ba hình SVG (đường cong thực, lưới F_p, bảng thang từng bit), theo màu sáng / tối của trang | `ECPlot` |
| `assets/ec-vectors.js` | tập con nhỏ của KeyPair.rsp, PKV.rsp, KAS_ECC_CDH_PrimitiveTest.txt, SigGen.txt, SigVer.rsp và các file ACVP tương ứng | `EC_VECTORS` |
| `assets/ec-ui.js` | ba hình, sáu thẻ, nút ví dụ NIST, tự kiểm | `ECLab` (cửa cho kiểm thử) |
| `assets/hash-trace.js` | SHA-1, sáu SHA-2, Keccak-p[1600,24], SHA3 / SHAKE / cSHAKE viết riêng để có vết — **độc lập** với `pqc-sha2.js` / `pqc-mlkem.js`, trang tính mỗi digest bằng cả hai và hiện dấu "khớp"; mọi hằng số tính khi nạp | `HashTrace` |
| `assets/hash-vectors.js` | ví dụ ShortMsg / LongMsg / VariableOut, điểm kiểm Monte Carlo (đủ giá trị ở điểm 0–9 và 99, 8 byte đầu ở các điểm khác — lỗi lan xuống mọi điểm sau nên vẫn bắt được) | `HASH_VECTORS` |
| `assets/hash-ui.js` | năm thẻ, bản đồ đệm, bảng vòng, lưới lane, Monte Carlo có thanh tiến độ và nút dừng, tự kiểm | `HashLab` (cửa cho kiểm thử) |
| `assets/hash-worker.js` | Web Worker cho Monte Carlo | — |

Như trang SLH-DSA / FN-DSA / HQC-KEM: phép chậm chạy trong Web Worker; mở trang trực tiếp từ đĩa (`file://`) thì
trình duyệt chặn Worker và trang tự chạy ở luồng chính sau khi kịp vẽ dòng "đang tính".

Kiểm chứng:

| | RSA | đường cong elliptic | SHA-2 / SHA-3 |
|---|---|---|---|
| nút "Chạy kiểm chứng" trên trang | 137 phép kiểm | 112 phép kiểm | 290 phép kiểm |
| ngoài repo: so với mô hình tham chiếu Python + file vector NIST | 3 358 | 1 676 | 14 363 (cả 6 872 thông điệp lẻ bit) |
| ngoài repo: kiểm giao diện bằng trình duyệt giả lập, soát hai ngôn ngữ sau mỗi cú bấm | 136 | 165 | 447 |
| ngoài repo: đột biến cố ý, mỗi cái phải làm bộ kiểm báo đỏ | 45 / 45 bị bắt | 37 / 37 | 45 / 45 |
| ngoài repo: đối chiếu độc lập với OpenSSL (qua Node) trên khoá / thông điệp ngẫu nhiên | 525 | 800 | 13 176 |

Mỗi nút ví dụ và nút tự kiểm cũng đã được chứng minh **đỏ được**: cài một giá trị sai vào file vector thì trang
phải báo đúng giá trị đó. Giới hạn: như các máy tính PQC — để học, không để bảo vệ dữ liệu thật (`BigInt` chạy
thời gian phụ thuộc dữ liệu, không chống kênh bên, khoá nằm trong bộ nhớ JavaScript). Khi sửa: giữ chuỗi `bi()`,
bấm "Chạy kiểm chứng" phải ra toàn xanh, và đổi thuật toán thì sinh lại file `*-vectors.js` bằng bộ kiểm thử ngoài
repo, không sửa tay.

### Cập nhật 03/11/2026: ba thao tác của RSA, và mô hình ứng dụng trên cả hai trang khoá công khai

Bài RSA được cập nhật theo bản mới của ghi chú khái niệm RSA của tác giả; cả bài RSA và bài đường cong elliptic có thêm
một mục **"Mô hình ứng dụng"** (`#ung-dung`, ngay trước phòng thí nghiệm): thuật toán chạy ở đâu trong một hệ thống thật,
ai giữ khoá riêng, ai chỉ chạy phép công khai, và con chip ở mỗi vai phải làm gì.

| trang | phần mới |
|---|---|
| `posts/rsa-fips-186-5.html` | **Ba thao tác** (`#ba-thao-tac`): hình SVG tổng quan sinh khoá → khoá công khai / khoá riêng dạng CRT → RSAEP = RSAVP1 / RSADP = RSASP1, bảng vào–ra–tên trong chuẩn–chi phí, hai dạng khoá riêng (RFC 8017 mục 3.2). Mục lũy thừa: câu cũ "giải mã và ký chậm hơn hàng trăm lần" chỉ đúng khi không dùng CRT — nay là số đếm (~180 lần không CRT, ~45 lần có CRT) và số đo OpenSSL (RSA-2048 / 3072 / 4096: 29 / 46 / 59 lần). Mục CRT: hệ số đếm trên khoá thật 3,96–3,97 (2048 bit), 3,98 (3072, 4096). **Mô hình ứng dụng**: chứng chỉ + TLS 1.3 (RFC 9846, RFC 9963), firmware ký số + khởi động an toàn (SP 800-193), bọc khoá bằng OAEP (CMS, RFC 8017 mục 7); bảng tổng hợp; hai kịch bản chạy thử — cập nhật firmware ký PSS rồi lật một byte, bọc khoá OAEP rồi lật một byte |
| `posts/ecdh-ecdsa-nist-curves.html` | **Mô hình ứng dụng**: bắt tay TLS 1.3 = ECDHE + ECDSA (RFC 9846, lai hậu lượng tử RFC 10024), khoá FIDO2 / WebAuthn (W3C WebAuthn mức 3, ES256), firmware ký bằng ECDSA, HPKE (RFC 9180) trong bảng; kịch bản bắt tay rút gọn trên P-256 / P-384, có nút cho kẻ đứng giữa thay key share của máy chủ — Z hai bên lệch nhau và chữ ký không qua |

Mã của hai kịch bản nằm **trong chính trang** (một `<script>` cuối trang, cửa kiểm thử `RSAApps` / `ECApps`), không
trong `assets/`: như vậy chuỗi tiếng Việt của nó nằm trong trang đã khoá, còn file `assets/*.js` thì ai cũng tải được.
Kịch bản chỉ gọi lõi đã kiểm (`RSACore`, `EC`, `PQCSHA2`); không file `assets/` nào bị sửa.

Kiểm chứng (bộ kiểm ngoài repo, trình duyệt giả lập, soát hai ngôn ngữ sau mỗi cú bấm, Node `crypto` = OpenSSL làm
nhân chứng độc lập cho từng giá trị kịch bản in ra):

| | RSA | đường cong elliptic |
|---|---|---|
| kiểm giao diện cũ (không đổi) | 136 / 136 | 165 / 165 |
| kịch bản mới | 140 / 140 | 190 / 190 |
| đột biến vào mã kịch bản, mỗi cái phải chết ở một phép kiểm có tên | 22 / 22 | 15 / 15 |
| hình mới nhìn bằng mắt (Edge chạy ẩn, VI và EN) | 4 hình | 3 hình |

Số đo tốc độ trên hai trang là của **một máy**, hai lượt đo; tỷ lệ RSA-3072 / ECDSA khi xác minh ghi thành khoảng
(P-256: 1,5–1,7 lần, P-384: 10–15 lần) vì hai lượt cho hai con số, và vì đường tính P-256 của OpenSSL được tối ưu riêng.
Hai trang này đang khoá: phần sửa nằm trong `_plain/`, phải chạy `node tools/lock_pages.js lock` thì trang trên mạng mới
đổi (`status` báo "BẢN MÃ CŨ" cho hai trang này cho tới lúc đó).

### Cập nhật 04/11/2026: hình hai bên A – B cho RSA, ECDH và ECDSA

Hai bài khoá công khai có thêm bốn hình **"Bên A | kênh công khai | Bên B"** theo cách vẽ quen thuộc của sách mật mã:
mỗi cột là một bên và chỉ chứa những gì bên đó tự tính; mũi tên xanh là đúng thứ đi qua kênh; chữ đỏ là bí mật không bao
giờ rời bên giữ nó; dòng chữ xám là một ví dụ số nhỏ tính được bằng tay. Hình tĩnh (SVG viết sẵn trong trang, không
JavaScript), song ngữ, cuộn ngang trên điện thoại.

| trang | hình mới | ví dụ số |
|---|---|---|
| `posts/rsa-fips-186-5.html` | mục con **"Giữa hai bên A và B"** (`#hai-ben`, cuối mục Ba thao tác): mã hoá A → B (RSAES-OAEP, RFC 8017 mục 7.1) và chữ ký A → B (RSASSA-PSS, mục 8.1), thêm đoạn dẫn và đoạn "hai điều hình không vẽ" (chứng chỉ, khoá đối xứng) | khoá của B: p = 61, q = 53, e = 17 (65 → 2790 → 65, CRT m₁ = 4, m₂ = 12, h = 1); khoá **khác** của A để ký: p = 47, q = 59 (EM = 100 → s = 1605; đổi s thành 1604 → 2610) — RFC 8017 mục 6: mỗi cặp khoá một lược đồ |
| `posts/ecdh-ecdsa-nist-curves.html` | **Hình 4** ECDH (SP 800-56A r3 mục 5.7.1.2, kiểm tra khoá mục 5.6.2.3.3) và **Hình 5** ECDSA (FIPS 186-5 mục 6.4), ngay dưới hai tiêu đề con của mục "ECDH và ECDSA, từng bước" (nay có `id="tung-buoc"`); ba hình mô hình ứng dụng cũ đổi số 4–6 → **6–8** | đường cong của Hình 2: y² = x³ + 2x + 2 (mod 17), G = (5, 1), n = 19; ECDH d_A = 3, d_B = 10 → Z = 13; ECDSA d = 7, k = 4, e = 11 → (r, s) = (3, 8), sửa M → R′ = (10, 11) |

Kiểm chứng (bộ kiểm ngoài repo): mọi con số trong hình và chú thích được tính **hai lần độc lập** (Python từ định nghĩa,
JavaScript BigInt trong bộ kiểm) rồi so với chữ trên trang, ở cả hai ngôn ngữ.

| | kết quả |
|---|---|
| kiểm hình mới (vị trí, cặp VI/EN, không còn dấu cách đôi trong SVG, marker, số liệu, thứ tự Hình 1–8, link chéo hai trang) | 55 / 55 |
| đột biến cài vào trang / oracle, mỗi cái phải làm bộ kiểm đỏ | 12 / 12 |
| kiểm giao diện + kịch bản cũ của hai trang (không đổi) | RSA 136 + 140, đường cong 165 + 190 |
| cổng của site (`check_site.py`) | 21 / 21 trang |
| nhìn bằng mắt (Edge chạy ẩn, VI và EN) | 4 hình × 2 ngôn ngữ |

Hai trang này đang khoá: phần sửa nằm trong `_plain/`; phải chạy `node tools/lock_pages.js lock` thì trang trên mạng mới
đổi (`status` báo "BẢN MÃ CŨ" cho tới lúc đó).

## Bài nhập môn khoá công khai, đọc tự do — `posts/mat-ma-khoa-cong-khai-ba-viec.html`

"Mật mã khoá công khai trong đời thường: ba việc, ba hình vẽ, và chúng chạy ở đâu quanh bạn" — bài viết cho người
không chuyên, **không khoá** (không nằm trong `tools/lock_pages.js`, sửa thẳng trong `posts/`). Mạch bài: bốn cảnh
đời thường → một ý tưởng (hộp thư, cửa sập, quy tắc nhớ hướng khoá) → ba việc, mỗi việc một mục với một hình hai làn
A | B, một so sánh đời thường, thuật toán hôm nay và hậu lượng tử, một cạm bẫy có thật (gập trong `<details>`) và
một đồ chơi số nhỏ → bảng so sánh + biểu đồ kích thước → **mô hình ứng dụng** (bản đồ cảnh → việc; TLS 1.3, passkey,
cập nhật có chữ ký / khởi động an toàn, mã hoá lai cho email và tệp) → khối mật mã trong một con chip (vẽ chung chung)
→ máy tính lượng tử thay đổi gì → ba điều mang về, thuật ngữ, đọc thêm. Mười hai hình SVG viết tay, song ngữ.

| file | nội dung |
|---|---|
| `posts/mat-ma-khoa-cong-khai-ba-viec.html` | bài viết, 12 hình, chỗ gắn ba đồ chơi (`data-toy="rsa" / "ecdh" / "ecdsa"`) |
| `posts/assets/pk-toys.js` | ba đồ chơi (biến toàn cục `PKToys`): RSA p = 61, q = 53, e = 17, d = 413 (mã hoá có từng bước bình phương-và-nhân; ký, sửa thông điệp → không hợp lệ); ECDH và ECDSA trên đường cong y² = x³ + 2x + 2 trên F₁₇ (19 điểm; lưới điểm vẽ bằng SVG; ECDSA từ chối r = 0 / s = 0, nút sửa thông điệp, nút dùng lại số k để thấy khoá bí mật bị tính ngược ra). Số học `Number` thường (số nhỏ), không thư viện ngoài, tự chèn CSS `.toy-*` |

Kiểm chứng (bộ kiểm ngoài repo):

| | kết quả |
|---|---|
| mô hình tham chiếu Python viết từ định nghĩa, **vét cạn**: mọi m, h trong 0..3232, mọi (a, b), mọi (d, h, k) = 6 156 bộ, 88 128 cặp dùng lại số k | 26 / 26 phép kiểm, 106 258 trường hợp |
| trình duyệt giả lập: bấm mọi nút ở cả hai ngôn ngữ, so từng giá trị với mô hình, soát ngôn ngữ trong ba đồ chơi sau mỗi cú bấm | 29 / 29, 45 004 thao tác |
| đột biến cố ý vào `pk-toys.js`, mỗi cái phải chết ở một phép kiểm có tên | 24 / 24 |
| đối chiếu với các con số của tài liệu gốc (65 → 2790, chữ ký 123 → 2746, ECDSA (10, 7), khôi phục k = 3 và d = 7, k = 9 / 10 bị từ chối) | 11 / 11 |
| 12 hình xem bằng mắt (Edge chạy ẩn, VI và EN) | sau hai lượt sửa |

Các con số "chỉ có ở đồ chơi" bài viết phải nói thật: trên đường cong 19 điểm, sửa thông điệp thành h + 1 vẫn được chấp
nhận do trùng hợp ở 288 / 5 184 chữ ký (ở cỡ thật xác suất cỡ 2⁻²⁵⁶). Bảng thuật ngữ cho hiện cột tiếng Việt ở cả hai
ngôn ngữ bằng ngoại lệ có đếm `data-i18n="neutral"` (18 ô). Bài dài khoảng 20–23 phút đọc.

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

Header, nav và footer không bị khối này chạm tới. Muốn đổi định dạng thì đổi khối này **ở mọi trang** cho
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

## Trang giới hạn truy cập — bảy bài phải nhập mật khẩu

Bảy bài trong mục *Mật mã hậu lượng tử, AI & Mã sửa lỗi* (`pqc-calculator`, `kpqc-calculator`,
`nist-205-206-207-calculator`, `rsa-fips-186-5`, `ecdh-ecdsa-nist-curves`, `sha2-sha3-keccak`,
`tu-ma-luong-tu-den-ecc`) chỉ mở ra sau khi người đọc nhập đúng mật khẩu. Bài MD5 vẫn công khai.

**Vì sao không dùng `if (password === "...")`.** Đây là trang tĩnh trên GitHub Pages: không có
máy chủ nào để kiểm tra mật khẩu. Một phép so sánh trong JavaScript thì ai bấm *View Source* cũng
đọc được cả mật khẩu lẫn toàn bộ bài viết — nó chỉ là tấm rèm. Nên bài viết được **mã hoá thật**:
file nằm trên GitHub Pages không chứa một câu bản rõ nào.

- AES-256-GCM; khoá sinh bằng PBKDF2-HMAC-SHA256, **600 000 vòng** — mức OWASP khuyến nghị hiện
  hành cho PBKDF2-SHA256 (310 000 là con số của bản năm 2021).
- Mỗi trang có `salt` 16 byte và `iv` 12 byte ngẫu nhiên riêng.
- **Không lưu băm mật khẩu ở đâu cả**: nhập sai thì GCM không xác thực được và phép giải mã hỏng —
  chính cái hỏng đó là tín hiệu "sai mật khẩu". Nói cho công bằng: thẻ xác thực GCM cũng là một bộ
  kiểm mật khẩu y như một giá trị băm, nên mục *dò ngoại tuyến* bên dưới vẫn áp dụng nguyên vẹn. Nhập sai hiện màn hình *Nội dung giới hạn /
  Limited access*; nhập đúng thì trang thật hiện ra ngay trong cùng một tab.
- Mật khẩu **không nằm trong repo**. Nó chỉ đi vào công cụ qua biến môi trường `CHIUSOC_LOCK_PW`.
- Ô *Nhớ mật khẩu cho đến khi đóng thẻ này* lưu **mật khẩu dạng rõ** vào `sessionStorage` của đúng
  thẻ trình duyệt đó: mở thẻ mới là phải nhập lại, đóng thẻ là mất. Không có gì ghi xuống đĩa.

### Các file

| File | Vai trò |
|---|---|
| `_plain/<tên>.html` | **bản rõ — nguồn để sửa bài.** Đã nằm trong `.gitignore`, không bao giờ commit |
| `posts/<tên>.html` | vỏ khoá đã mã hoá, chính là thứ đăng lên Pages |
| `tools/lock_pages.js` | `lock` / `restore [--force]` / `status` / `adopt` |
| `_plain/.lock-state.json` | dấu vân tay SHA-256 của bản rõ và bản mã ở lần `lock` / `restore` / `adopt` cuối (bị ignore cùng `_plain/`) |
| `tools/git-hooks/pre-commit` | chặn commit khi còn trang chưa khoá lại (xem dưới) |
| `tools/lock-shell.css` | giao diện màn hình khoá (gồm cả khối `house-format`) |
| `posts/assets/unlock.js` | phần chạy trên trình duyệt: hỏi mật khẩu, giải mã, mở trang |

### Quy trình sửa một bài đã khoá

```bash
export CHIUSOC_LOCK_PW='...'            # không viết mật khẩu vào file nào trong repo
node tools/lock_pages.js restore        # chỉ cần khi chưa có _plain/
#   sửa _plain/<tên>.html
python3 <đường dẫn>/check_site.py .   # kèm tham số --banned như mọi lần
node tools/lock_pages.js lock           # mã hoá lại — BẮT BUỘC, nếu quên thì web vẫn là bản cũ
node tools/lock_pages.js status         # phải in "7/7 trang đã khoá và còn mới"
unset CHIUSOC_LOCK_PW
```

`status` không cần mật khẩu. Nó bắt đúng cái lỗi dễ mắc nhất: sửa `_plain/` rồi quên chạy `lock`,
khiến trang web vẫn phục vụ bản mã cũ.

### Chốt chặn khi commit (04/11/2026)

**Sự cố.** Ngày 04/11, `README.md` và `index.html` mô tả các mục mới của bài RSA và bài đường cong elliptic đã
được commit và đẩy lên, trong khi hai trang ấy vẫn là bản mã cũ: bản sửa chỉ nằm trong `_plain/` (bị ignore), nên git
không thấy thiếu gì. Trên site, thẻ bài hứa những mục mà trang chưa có, cho tới lúc khoá lại (commit `re-lock RSA + EC`).

**Hai lớp chặn:**

1. `status` so **nội dung**, không chỉ thời điểm sửa. `lock`, `restore` và `adopt` ghi SHA-256 của bản rõ và bản mã
   vào `_plain/.lock-state.json`. `status` báo `BẢN MÃ CŨ` (bản rõ sửa sau lần khoá cuối), `BẢN MÃ ĐÃ ĐỔI` (bản mã
   trong `posts/` đổi từ bên ngoài, vd. sau `git pull` — chạy `restore` trước khi sửa) hoặc `XUNG ĐỘT` (cả hai đều
   đổi), và trả mã thoát 1. Quy tắc cũ chỉ so thời điểm sửa nên bị lừa khi `git pull` / `checkout` ghi lại các file
   trong `posts/`. `restore` nay **từ chối** ghi đè một trang có bản sửa chưa khoá (`--force` để cố ý ghi đè).
2. `tools/git-hooks/pre-commit` từ chối commit khi `status` báo trang cần xử lý, khi một trang đang khoá sắp được
   commit ở dạng bản rõ, và khi có file `_plain/` bị `git add -f`. Bật **một lần cho mỗi bản clone**:

```bash
git config core.hooksPath tools/git-hooks
node tools/lock_pages.js adopt     # bản clone mới có _plain/ nhưng chưa có dấu vân tay: ghi lần đầu, không cần mật khẩu
```

Cố ý commit việc khác trong lúc đang sửa dở một trang khoá: `CHIUSOC_ALLOW_STALE=1 git commit ...`. Hai kiểm tra
còn lại (bản rõ đè lên trang khoá, `_plain/` trong commit) không có đường tắt nào ngoài `git commit --no-verify`.
Đã thử trên một bản clone với mật khẩu thử: 24 / 24 tình huống đúng (sửa bản rõ nhưng đặt thời điểm sửa cũ hơn bản mã,
bản mã đổi kiểu `git pull`, cả hai cùng đổi, `restore` không đè bản sửa chưa khoá, sai mật khẩu, `adopt`, sáu tình
huống của hook).

Cổng kiểm `check_site.py` đọc `_plain/<tên>.html` thay cho trang đã khoá (nó không đọc được bên
trong bản mã). Nếu không có `_plain/`, cổng in `LOCKED ... content NOT checked` và **vẫn xanh** —
đó là cố ý, để một bản clone mới không bị báo đỏ oan; nhưng khi sửa bài thì phải có `_plain/`.

### Lớp khoá này che được gì, và không che được gì

Che được: toàn văn bảy bài; tiêu đề thật không nằm trong file trang (vỏ khoá chỉ ghi *Nội dung giới
hạn*, còn mục lục thì vẫn ghi tên bài); và trang mang `noindex, nofollow` nên không vào kết quả tìm
kiếm.

**Không** che được, cần biết rõ:

1. **Lịch sử git.** Bảy bài này từng được commit ở dạng bản rõ và đã đẩy lên remote. Mã hoá cây làm
   việc không xoá được các blob cũ: ai `git clone` vẫn đọc được bài. Muốn dọn thì phải viết lại lịch
   sử (`git filter-repo`) rồi force-push, hoặc lập repo mới — việc này xoá dấu vết cũ của cả repo
   nên chỉ chủ repo quyết định.
2. **Các file dùng chung trong `posts/assets/*.js`** vẫn tải được bằng URL trực tiếp, và trong đó có
   chuỗi giao diện tiếng Việt. Muốn giấu nốt thì phải nhúng JS vào phần mã hoá, kèm việc dựng lại
   ba Web Worker thành blob (`nist-worker.js`, `hash-worker.js`, `rsa-worker.js` đang dùng
   `importScripts`).
3. **`posts/assets/ecc-lecture-2026.pdf`** (bài giảng gốc) vẫn công khai và còn được liên kết từ
   `index.html`.
4. **Mục lục** vẫn hiện tên bảy bài và phần mô tả.
5. **Dò mật khẩu ngoại tuyến.** Ai tải file về thì thử mật khẩu bao nhiêu lần cũng được; thứ duy
   nhất cản là 600 000 vòng PBKDF2. Mật khẩu ngắn hoặc dễ đoán sẽ vỡ — nên dùng cụm từ bốn chữ
   ngẫu nhiên trở lên, hoặc mười sáu ký tự ngẫu nhiên trở lên. Kiểu *tên + năm sinh* thì một máy
   có GPU phá trong vài phút.

Nói gọn: lớp này đủ để người lướt web, công cụ tìm kiếm và người tình cờ gặp link không đọc được
bài — đúng mức "đề phòng cho chắc". Nó không phải là lớp bảo vệ chống một người quyết tâm.
