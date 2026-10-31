/* Web Worker của máy tính SLH-DSA / FN-DSA / HQC-KEM: những phép tính dài (ký SLH-DSA bộ "s" mất từ khoảng một tới hơn
   mười giây, sinh khoá Falcon, kiểm tra cặp khoá) chạy ở luồng riêng để trang không đứng. Mỗi thông điệp:
   {id, lib: 'SLHDSA' | 'FNDSA' | 'HQC' | 'NIST3Tools', op, args} -> {id, ok, v | err, ms}.
   Original implementation for the ChiU·SoC PQC demo page. */
importScripts('pqc-mlkem.js', 'pqc-sha2.js', 'pqc-mldsa.js', 'pqc-slhdsa.js', 'pqc-fndsa.js', 'pqc-hqc.js', 'nist-tools.js');
self.onmessage = function (e) {
  var d = e.data, t0 = Date.now(), out;
  try {
    var v = self[d.lib][d.op].apply(null, d.args);
    out = { id: d.id, ok: true, v: v, ms: Date.now() - t0 };
  } catch (x) {
    out = { id: d.id, ok: false, err: String((x && x.message) || x), code: x && x.code, ms: Date.now() - t0 };
  }
  self.postMessage(out);
};
