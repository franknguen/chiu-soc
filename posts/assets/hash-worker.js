/* Web Worker của trang SHA-2 / SHA-3: chạy Monte Carlo (100 checkpoint x 1000 lần băm) ở luồng riêng để trang không
   đứng. Thông điệp vào: { id, op: 'mct', job: { fn, variant, seed (hex), seedBits, minOutBits, maxOutBits }, count };
   trả về từng checkpoint { id, kind: 'cp', i, md (hex), outBits, ms }, rồi { id, kind: 'done' } hoặc { id, kind: 'error', err }.
   Original implementation for the ChiU·SoC hash article. */
importScripts('hash-trace.js');
self.onmessage = function (e) {
  var d = e.data, H = self.HashTrace;
  try {
    if (d.op !== 'mct') throw new Error('unknown op ' + d.op);
    var j = d.job, job = { fn: j.fn, variant: j.variant, seed: H.fromHex(j.seed), seedBits: j.seedBits,
      minOutBits: j.minOutBits, maxOutBits: j.maxOutBits }, st = null;
    for (var i = 0; i < d.count; i++) {
      var t0 = Date.now(), r = H.mctStep(job, st);
      st = r.st;
      self.postMessage({ id: d.id, kind: 'cp', i: i, md: H.toHex(r.md), outBits: r.outBits, ms: Date.now() - t0 });
    }
    self.postMessage({ id: d.id, kind: 'done' });
  } catch (x) {
    self.postMessage({ id: d.id, kind: 'error', err: String((x && x.message) || x) });
  }
};
