/* Web Worker của phòng thí nghiệm RSA: sinh khoá (RSA-3072 / 4096 mất vài giây), kiểm khoá và giải mã chạy ở luồng
   riêng để trang không đứng. Mỗi thông điệp: {id, op, args} -> {id, ok, v | err, code, ms}; op là một hàm trong
   RSACore.jobs, đầu vào / ra là hex và đối tượng thường. Original implementation for the ChiU·SoC RSA lab. */
importScripts('pqc-mlkem.js', 'pqc-sha2.js', 'rsa-core.js');
self.onmessage = function (e) {
  var d = e.data, t0 = Date.now(), out;
  try {
    out = { id: d.id, ok: true, v: self.RSACore.jobs[d.op].apply(null, d.args), ms: Date.now() - t0 };
  } catch (x) {
    out = { id: d.id, ok: false, err: String((x && x.message) || x), code: x && x.code, ms: Date.now() - t0 };
  }
  self.postMessage(out);
};
