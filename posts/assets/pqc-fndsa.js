/* FN-DSA / Falcon (Falcon v1.2: Falcon-512, Falcon-1024) — hiện thực JavaScript thuần, khớp từng byte với KAT vòng 3.
   Số thực IEEE-754 theo đúng thứ tự phép tính của bản tham chiếu vòng 3; NTRUSolve chính xác bằng BigInt.
   Original implementation for the ChiU·SoC PQC demo page. */
(function (root) {
  'use strict';
  var H = root.PQCHash;
  if (!H) throw new Error('pqc-mlkem.js phải được nạp trước pqc-fndsa.js');

  var DV = new DataView(new ArrayBuffer(8));
  function u2f(u) { DV.setBigUint64(0, u); return DV.getFloat64(0); }

  // ---- hằng số do CHƯƠNG TRÌNH chép từ mô hình tham chiếu (bit IEEE-754 / số nguyên), không gõ tay ----
  var C_INV_SIGMA = { 9: u2f(0x3F78B6C2DE64C7CAn), 10: u2f(0x3F78531EF6311AE3n) };   // fpr_inv_sigma (bản tham chiếu vòng 3)
  var C_SIGMA_MIN = { 9: u2f(0x3FF47201BF1F7A75n), 10: u2f(0x3FF4C5C19990C764n) };   // fpr_sigma_min
  var C_L2BOUND = { 9: 34034726, 10: 70265242 };       // floor(beta^2) của bản C (ký)
  var C_BETA2 = { 9: 34034726, 10: 70265242 };         // floor(beta^2) tính từ định nghĩa (xác minh)
  var C_FG_BITS = { 9: 6, 10: 5 };       // max_fg_bits
  var NORM_FG_MAX = 16822;                    // ||(g,-f)||^2 <= 16822
  var BNORM_MAX = u2f(0x40D06D9A5FD8ADACn);   // 1.17^2 q
  var LN2 = u2f(0x3FE62E42FEFA39EFn);         // ln 2
  var INV_2SQRSIGMA0 = u2f(0x3FC34F8BC183BBC2n);   // 1/(2 sigma_max^2)
  var GAUSS_KG = [[0x11D137D8, 0x2DF2AB58], [0x590C40F6, 0x3FF5F974], [0x3898E41D, 0x85B975B7], [0x20A964EF, 0x50858FF9], [0x1107D1AE, 0x973857EB], [0x07FE1EC2, 0x9220EA37], [0x035DAFCA, 0xCD37A439], [0x0144D983, 0x06216D42], [0x006D6BEE, 0xEAF81655], [0x0020E1A0, 0x0D6FA84C], [0x0008CDDD, 0xCD9DDA9C], [0x0002192F, 0xC3DCDCB4], [0x000071DF, 0xCD3C57E9], [0x00001574, 0x938D76EB], [0x00000397, 0x4B0C33E5], [0x00000088, 0x9D3DA6FE], [0x00000012, 0x04DDC6CB], [0x00000002, 0x1BD3B27A], [0x00000000, 0x38091F5E], [0x00000000, 0x05287DB0], [0x00000000, 0x006BC528], [0x00000000, 0x0007CBFB], [0x00000000, 0x00007FFC], [0x00000000, 0x00000746], [0x00000000, 0x0000005E], [0x00000000, 0x00000004], [0x00000000, 0x00000000]];
  var RCDT = [[0xA3, 0xF7F42ED3, 0xAC391802], [0x54, 0xD32B181F, 0x3F7DDB82], [0x22, 0x7DCDD093, 0x4829C1FF], [0x0A, 0xD1754377, 0xC7994AE4], [0x02, 0x95846CAE, 0xF33F1F6F], [0x00, 0x774AC754, 0xED74BD5F], [0x00, 0x1024DD54, 0x2B776AE4], [0x00, 0x01A1FFDC, 0x65AD63DA], [0x00, 0x001F80D8, 0x8A7B6428], [0x00, 0x0001C3FD, 0xB2040C69], [0x00, 0x000012CF, 0x24D031FB], [0x00, 0x00000094, 0x9F8B091F], [0x00, 0x00000003, 0x665DA998], [0x00, 0x00000000, 0x0EBF6EBB], [0x00, 0x00000000, 0x002F5D7E], [0x00, 0x00000000, 0x00007098], [0x00, 0x00000000, 0x000000C6], [0x00, 0x00000000, 0x00000001]];
  var EXPM_C = [0x00000004741183A3n, 0x00000036548CFC06n, 0x0000024FDCBF140An, 0x0000171D939DE045n, 0x0000D00CF58F6F84n, 0x000680681CF796E3n, 0x002D82D8305B0FEAn, 0x011111110E066FD0n, 0x0555555555070F00n, 0x155555555581FF00n, 0x400000000002B400n, 0x7FFFFFFFFFFF4800n, 0x8000000000000000n];
  // cos(pi t/1024), t = 1..511: bit binary64 (16 chữ số hex mỗi số) của bảng mà mô hình tính bằng Decimal;
  // dựng lại GM[k] = exp(i pi brv10(k)/1024) đã được đối chiếu từng bit với bảng đầy đủ khi sinh tệp.
  var GM_COS_HEX =
    '3feffff621621d023fefffd8858e8a923fefffa72c978c4f3fefff62169b92db3fefff0943c53bd13feffe9cb44b51a13feffe1c6870cb773feffd886084cd0d' +
    '3feffce09ce2a6793feffc251df1d3f83feffb55e425fdae3feffa72effef75d3feff97c4208c0143feff871dadb81df3feff753bb1b91643feff621e3796d7e' +
    '3feff4dc54b1bed33feff3830f8d575c3feff21614e131ed3feff095658e71ad3fefef01028261913fefed58ecb673c43fefeb9d2530410f3fefe9cdad01883a' +
    '3fefe7ea85482d603fefe5f3af2e39403fefe3e92be9d8863fefe1cafcbd5b093fefdf9922f733073fefdd539ff1f4563fefdafa7514538c3fefd88da3d12526' +
    '3fefd60d2da75c9e3fefd37914220b843fefd0d158d860873fefce15fd6da67b3fefcb47039143543fefc8646cfeb7213fefc56e3b7d9af63fefc26470e19fd3' +
    '3fefbf470f0a8d883fefbc1617e441863fefb8d18d66adb73fefb5797195d7413fefb20dc681d54d3fefae8e8e46cfbb3fefaafbcb0cfddc3fefa7557f08a517' +
    '3fefa39bac7a17913fef9fce55adb2c83fef9bed7cfbde293fef97f924c9099b3fef93f14f85ac083fef8fd5ffae41db3fef8ba737cb4b783fef8764fa714ba9' +
    '3fef830f4a40c60c3fef7ea629e63d6e3fef7a299c1a322a3fef7599a3a120773fef70f6434b7eb73fef6c3f7df5bbb73fef677556883cee3fef6297cff75cb0' +
    '3fef5da6ed43685d3fef58a2b1789e843fef538b1faf2d073fef4e603b0b2f2d3fef492206bcabb43fef43d085ff92dd3fef3e6bbc1bbc653fef38f3ac64e589' +
    '3fef33685a3aaef03fef2dc9c9089a9d3fef2817fc4609ce3fef2252f7763ada3fef1c7abe2847083fef168f53f7205d3fef1090bc898f5f3fef0a7efb9230d7' +
    '3fef045a14cf738c3feefe220c0b95ec3feef7d6e51ca3c03feef178a3e473c23feeeb074c50a5443feee482e25a9dbc3feeddeb6a0786513feed740e7684963' +
    '3feed0835e9990093feec9b2d3c3bf843feec2cf4b1af6b23feebbd8c8df0b743feeb4cf515b88113feeadb2e8e7a88e3feea68393e658003fee9f4156c62dda' +
    '3fee97ec36016b303fee9084361df7f23fee89095bad60253fee817bab4cd10d3fee79db29a5165a3fee7227db6a97443fee6a61c55d53a73fee6288ec48e112' +
    '3fee5a9d550467d33fee529f04729ffc3fee4a8dff81ce5e3fee426a4b2bc17e3fee3a33ec75ce853fee31eae870ce253fee298f4439197a3fee212104f686e5' +
    '3fee18a02fdc66d93fee100cca2980ac3fee0766d9280f543fedfeae622dbe2b3fedf5e36a9ba59c3feded05f7de47da3fede4160f6d8d813feddb13b6ccc23c' +
    '3fedd1fef38a915a3fedc8d7cb4102603fedbf9e4395759a3fedb6526238a09b3fedacf42ce68ab93feda383a96689883fed9a00dd8b3d463fed906bcf328d46' +
    '3fed86c48445a44f3fed7d0b02b8ecf93fed733f508c0dff3fed696173c9e68b3fed5f7172888a7f3fed556f52e93eb13fed4b5b1b1875243fed4134d14dc93a' +
    '3fed36fc7bcbfbdc3fed2cb220e0ef9f3fed2255c6e5a4e13fed17e7743e35dc3fed0d672f59d2b93fed02d4feb2bd923fecf830e8ce467b3feced7af43cc773' +
    '3fece2b32799a0603fecd7d9898b32f63fecccee20c2dea03fecc1f0f3fcfc5c3fecb6e20a00da993fecabc169a0b9003feca08f19b9c4493fec954b213411f5' +
    '3fec89f587029c133fec7e8e52233cf33fec7315899eaad73fec678b3488739b3fec5bef59fef85a3fec5042012b69073fec44833141c0043fec38b2f180bdb1' +
    '3fec2cd14931e3f13fec20de3fa971b03fec14d9dc465e573fec08c4267255493febfc9d25a1b1473febf064e15377dd3febe41b611154c13febd7c0ac6f952a' +
    '3febcb54cb0d23273febbed7c49380ea3febb249a0b6c40d3feba5aa673590d23feb98fa1fd9155e3feb8c38d27504e93feb7f6686e792e93feb728345196e3e' +
    '3feb658f14fdbc473feb5889fe9214053feb4b7409de79253feb3e4d3ef557123feb3115a5f37bf33feb23cd470013b43feb16742a4ca2f53feb090a58150200' +
    '3feafb8fd89f57b63feaee04b43c14743feae068f345ecef3fead2bc9e21d5113feac4ffbd3efac83feab7325916c0d43feaa9547a2cb98e3fea9b66290ea1a3' +
    '3fea8d676e545ad23fea7f58529fe69d3fea7138de9d60f53fea63091b02fae23fea54c91090f5233fea4678c8119ac83fea38184a593bc63fea29a7a0462782' +
    '3fea1b26d2c0a75e3fea0c95eabaf9373fe9fdf4f13149de3fe9ef43ef29af943fe9e082edb424723fe9d1b1f5ea80d53fe9c2d110f075c23fe9b3e047f38741' +
    '3fe9a4dfa42b06b23fe995cf2ed80d223fe986aef14575943fe9777ef4c7d7423fe9683f42bd7fe13fe958efe48e6dd73fe94990e3ac4a6c3fe93a22499263fb' +
    '3fe92aa41fc5a8153fe91b166fd49da23fe90b7943575efe3fe8fbcca3ef940d3fe8ec109b486c493fe8dc45331698cc3fe8cc6a751846553fe8bc806b151741' +
    '3fe8ac871ede1d883fe89c7e9a4dd4aa3fe88c66e7481ba13fe87c400fba2ebf3fe86c0a1d9aa1953fe85bc51ae958cc3fe84b7111af83fa3fe83b0e0bff976e' +
    '3fe82a9c13f545ff3fe81a1b33b57acc3fe8098b756e52fa3fe7f8ece35717713fe7e83f87b036863fe7d7836cc33db23fe7c6b89ce2d3333fe7b5df226aafaf' +
    '3fe7a4f707bf97d23fe79400574f55e53fe782fb1b90b35b3fe771e75f0372613fe760c52c3047643fe74f948da8d28d3fe73e558e0799423fe72d0837efff96' +
    '3fe71bac960e41bf3fe70a42b3176d7a3fe6f8ca99c95b753fe6e74454eaa8af3fe6d5afef4aafcd3fe6c40d73c182753fe6b25ced2fe29c3fe6a09e667f3bcd' +
    '3fe68ed1eaa19c713fe67cf78491af103fe66b0f3f52b3863fe6591925f0783d3fe64715437f535b3fe63503a31c1be93fe622e44fec22ff3fe610b7551d2cdf' +
    '3fe5fe7cbde56a103fe5ec34958370743fe5d9dee73e345c3fe5c77bbe65018c3fe5b50b264f74483fe5a28d2a5d72503fe59001d5f723df3fe57d69348ceca0' +
    '3fe56ac35197649f3fe55810389751373fe5454ff5159dfc3fe5328292a355963fe51fa81cd99aa63fe50cc09f59a09b3fe4f9cc25cca4863fe4e6cabbe3e5e9' +
    '3fe4d3bc6d589f7f3fe4c0a145ec00043fe4ad79516722f13fe49a449b9b09393fe48703306091ff3fe473b51b9873473fe4605a692b32a23fe44cf325091dd6' +
    '3fe4397f5b2a43803fe425ff178e6bb13fe41272663d108c3fe3fed9534556d43fe3eb33eabe06803fe3d78238c583443fe3c3c44981c5183fe3affa292050b9' +
    '3fe39c23e3d630293fe3884185dfeb223fe374531b817f8d3fe36058b10659f33fe34c5252c14de13fe338400d0c8e573fe32421ec49a61f3fe30ff7fce17035' +
    '3fe2fbc24b4410153fe2e780e3e8ea173fe2d333d34e9bb83fe2bedb25faf3ea3fe2aa76e87aeb583fe2960727629ca83fe2818bef4d3cba3fe26d054cdd12df' +
    '3fe258734cbb71103fe243d5fb98ac1f3fe22f2d662c13e23fe21a799933eb593fe205baa17560d63fe1f0f08bbc861b3fe1dc1b64dc48723fe1c73b39ae68c8' +
    '3fe1b250171373bf3fe19d5a09f2b9b83fe188591f3a46e53fe1734d63dedb493fe15e36e4dbe2bc3fe14915af336ceb3fe133e9cfee254f3fe11eb3541b4b23' +
    '3fe1097248d0a9573fe0f426bb2a8e7e3fe0ded0b84bc4b63fe0c9704d5d898f3fe0b405878f85ec3fe09e907417c5e13fe089112032b08c3fe073879922ffee' +
    '3fe05df3ec31b8b73fe0485626ae221a3fe032ae55edbd963fe01cfc874c3eb73fe00740c82b82e13fdfe2f64be712103fdfb7575c24d2de3fdf8ba4dbf89aba' +
    '3fdf5fdee656cda33fdf3405963fd0673fdf081906bff7fe3fdedc1952ef78d63fdeb00695f256203fde83e0eaf851143fde57a86d3cd8253fde2b5d3806f63b' +
    '3fddfeff66a941de3fddd28f1481cc583fdda60c5cfa10d93fdd79775b86e3893fdd4cd02ba8609d3fdd2016e8e9db5b3fdcf34baee1cd213fdcc66e9931c45e' +
    '3fdc997fc38653893fdc6c7f4997000b3fdc3f6d472631293fdc1249d8011ee73fdbe51517ffc0d93fdbb7cf2304bd013fdb8a7814fd56933fdb5d1009e15cc0' +
    '3fdb2f971db319723fdb020d6c7f40093fdad473125cdc093fdaa6c82b6d3fca3fda790cd3dbf31b3fda4b4127dea1e53fda1d6543b50ac03fd9ef7943a8ed8a' +
    '3fd9c17d440df9f23fd993716141bdff3fd96555b7ab948f3fd9372a63bc93d73fd908ef81ef7bd13fd8daa52ec8a4b03fd8ac4b86d5ed443fd87de2a6aea963' +
    '3fd84f6aaaf3903f3fd820e3b04eaac43fd7f24dd37341e43fd7c3a9311dcce73fd794f5e613dfae3fd766340f2418f63fd73763c92610923fd7088530fa459f' +
    '3fd6d998638a0cb63fd6aa9d7dc77e173fd67b949cad63cb3fd64c7ddd3f27c63fd61d595c88c2023fd5ee27379ea6933fd5bee78b9db3b63fd58f9a75ab1fdd' +
    '3fd5604012f467b43fd530d880af3c243fd50163dc1970483fd4d1e24278e76a3fd4a253d11b82f33fd472b8a55710543fd44310dc8936f03fd4135c94176601' +
    '3fd3e39be96ec2713fd3b3cefa0414b73fd383f5e353b6ab3fd35410c2e181523fd3241fb638baaf3fd2f422daec03873fd2c41a4e9545203fd294062ed59f06' +
    '3fd263e6995554ba3fd233bbabc3bb713fd2038583d727be3fd1d3443f4cdb3e3fd1a2f7fbe8f2433fd172a0d77651773fd1423eefc693783fd111d262b1f677' +
    '3fd0e15b4e1749ce3fd0b0d9cfdbdb903fd0804e05eb661e3fd04fb80e37fdae3fd01f1806b9fdd23fcfdcdc1adfedf93fcf7b7480bd38023fcf19f97b215f1b' +
    '3fceb86b462de3483fce56ca1e101a1b3fcdf5163f01099a3fcd934fe54543113fcd31774d2cbdee3fcccf8cb312b2863fcc6d90535d74dd3fcc0b826a7e4f63' +
    '3fcba96334f15dad3fcb4732ef3d67223fcae4f1d5f3b9ab3fca82a025b004513fca203e1b1831da3fc9bdcbf2dc43663fc95b49e9b62afa3fc8f8b83c69a60b' +
    '3fc8961727c418043fc83366e89c64c63fc7d0a7bbd2cb1c3fc76dd9de50bf313fc70afd8d08c4ff3fc6a81304f64ab23fc6451a831d830d3fc5e214448b3fc6' +
    '3fc57f008654cbde3fc51bdf8597c5f23fc4b8b17f79fa883fc45576b1293e5a3fc3f22f57db48933fc38edbb0cd8d143fc32b7bf94516a73fc2c8106e8e613a' +
    '3fc264994dfd34093fc20116d4ec7bcf3fc19d8940be24e73fc139f0cedaf5773fc0d64dbcb267863fc072a047ba831d3fc00ee8ad6fb85b3fbf564e56a9730e' +
    '3fbe8eb7fde4aa3f3fbdc70ecbae9fc93fbcff533b307dc13fbc3785c79ec2d53fbb6fa6ec38f64c3fbaa7b724495c033fb9dfb6eb24a85c3fb917a6bc29b42c' +
    '3fb84f8712c130a13fb787586a5d5b213fb6bf1b3e79b1293fb5f6d00a9aa4193fb52e774a4d4d0a3fb46611792720963fb39d9f12c5a2993fb2d52092ce19f6' +
    '3fb20c9674ed444d3fb1440134d709b33fb07b614e4630643faf656e79f820e03fadd406f9808ec93fac428d12c0d7e33faab101bd5f83173fa91f65f10dd814' +
    '3fa78dbaa58746863fa5fc00d290cd433fa46a396ff861793fa2d865759455cd3fa14685db42c17f3f9f693731d1cf013f9c454f4ce53b1d3f992155f7a3667e' +
    '3f95fd4d21fab2263f92d936bbe30efd3f8f6a296ab997cb3f8921d1fcdec7843f82d96b0e5097033f7921f0fe6700713f6921f8becca4ba';

  var Q = 12289, QB = 12289n, M64 = 0xFFFFFFFFFFFFFFFFn, P63 = Math.pow(2, 63), INV_LN2 = 1.0 / LN2;
  var TWO52 = 4503599627370496;
  var MAX_CAND = 500, MAX_ATTEMPTS = 16, MAX_RESIGN = 16, MAX_SAMPLER_ITER = 4096, MAX_REDUCE = 2000;

  function mk(logn, sbytelen) {
    var n = 1 << logn, fgb = logn === 9 ? 6 : 5;
    return {
      logn: logn, n: n, sbytelen: sbytelen, fgBits: fgb,
      pkLen: 1 + ((14 * n + 7) >> 3), skLen: 1 + ((2 * fgb * n + 8 * n + 7) >> 3), slenBits: 8 * sbytelen - 328,
      invSigma: C_INV_SIGMA[logn], sigmaMin: C_SIGMA_MIN[logn], l2bound: C_L2BOUND[logn], beta2: C_BETA2[logn],
      fgBitsC: C_FG_BITS[logn]
    };
  }
  var PARAMS = { 'Falcon-512': mk(9, 666), 'Falcon-1024': mk(10, 1280) };
  function param(name) {
    var P = Object.prototype.hasOwnProperty.call(PARAMS, name) ? PARAMS[name] : null;
    if (!P) throw new Error('Không có bộ tham số: ' + name);
    return P;
  }

  function bitrev(x, bits) { var r = 0; for (var i = 0; i < bits; i++) { r = (r << 1) | (x & 1); x >>= 1; } return r; }

  // bảng căn GM (miền FFT) dựng lại từ một phần tư vòng tròn
  var GM_RE = new Float64Array(1024), GM_IM = new Float64Array(1024);
  (function () {
    var cs = new Float64Array(512), k, j;
    for (k = 1; k < 512; k++) cs[k] = u2f(BigInt('0x' + GM_COS_HEX.substr((k - 1) * 16, 16)));
    for (k = 1; k < 1024; k++) {
      j = bitrev(k, 10);
      if (j === 512) { GM_RE[k] = -0; GM_IM[k] = 1; }
      else if (j < 512) { GM_RE[k] = cs[j]; GM_IM[k] = cs[512 - j]; }
      else { GM_RE[k] = -cs[1024 - j]; GM_IM[k] = cs[j - 512]; }
    }
  })();

  // ---------------------------------------------------------------- SHAKE256 đọc tuần tự
  function Stream(data) { this.x = H.shake256xof(data); this.b = this.x.squeeze(1088); this.p = 0; }
  Stream.prototype.byte = function () {
    if (this.p === this.b.length) { this.b = this.x.squeeze(1088); this.p = 0; }
    return this.b[this.p++];
  };
  Stream.prototype.read = function (k) { var o = new Uint8Array(k); for (var i = 0; i < k; i++) o[i] = this.byte(); return o; };
  Stream.prototype.u32 = function () {
    var a = this.byte(), b = this.byte(), c = this.byte(), d = this.byte();
    return (a | (b << 8) | (c << 16) | (d << 24)) >>> 0;
  };

  function concat(a, b) { var o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; }

  // ---------------------------------------------------------------- NTT mod q (kiểu vrfy.c, Montgomery R = 2^16)
  function modpow(b, e, m) { var r = 1; b %= m; while (e > 0) { if (e & 1) r = (r * b) % m; b = (b * b) % m; e >>= 1; } return r; }
  var R_MOD_Q = 65536 % Q, R2 = (R_MOD_Q * R_MOD_Q) % Q, Q0I = (function () {
    var y = 1; while (((Q * y) & 0xFFFF) !== 1) y += 2; return 65536 - y;   // -1/q mod 2^16
  })();
  var GMB = new Int32Array(1024), IGMB = new Int32Array(1024);
  (function () {
    var ipsi = modpow(7, Q - 2, Q);
    for (var k = 0; k < 1024; k++) {
      GMB[k] = (R_MOD_Q * modpow(7, bitrev(k, 10), Q)) % Q;
      IGMB[k] = (R_MOD_Q * modpow(ipsi, bitrev(k, 10), Q)) % Q;
    }
  })();
  function mmul(x, y) {
    var z = x * y, w = ((((z & 0xFFFF) * Q0I) & 0xFFFF) * Q);
    z = (z + w) >>> 16; z -= Q;
    return z < 0 ? z + Q : z;
  }
  function modq(x) { x %= Q; return x < 0 ? x + Q : x; }
  function center(x) { x = modq(x); return x > (Q >> 1) ? x - Q : x; }
  function mqNtt(src, logn) {
    var n = 1 << logn, a = new Int32Array(n), t = n, m = 1, ht, i, j, j1, s, u, v;
    for (i = 0; i < n; i++) a[i] = modq(src[i]);
    while (m < n) {
      ht = t >> 1; j1 = 0;
      for (i = 0; i < m; i++) {
        s = GMB[m + i];
        for (j = j1; j < j1 + ht; j++) {
          u = a[j]; v = mmul(a[j + ht], s);
          a[j] = (u + v) % Q; a[j + ht] = (u - v + Q) % Q;
        }
        j1 += t;
      }
      t = ht; m <<= 1;
    }
    return a;
  }
  function mqIntt(src, logn) {
    var n = 1 << logn, a = Int32Array.from(src), t = 1, m = n, hm, dt, i, j, j1, s, u, v, ni;
    while (m > 1) {
      hm = m >> 1; dt = t << 1; j1 = 0;
      for (i = 0; i < hm; i++) {
        s = IGMB[hm + i];
        for (j = j1; j < j1 + t; j++) {
          u = a[j]; v = a[j + t];
          a[j] = (u + v) % Q; a[j + t] = mmul((u - v + Q) % Q, s);
        }
        j1 += dt;
      }
      t = dt; m = hm;
    }
    ni = R_MOD_Q;
    for (i = 0; i < logn; i++) ni = (ni + ((ni & 1) ? Q : 0)) >> 1;
    for (i = 0; i < n; i++) a[i] = mmul(a[i], ni);
    return a;
  }
  function mqDiv(x, y) { return (x * modpow(y, Q - 2, Q)) % Q; }

  // h = g/f mod q; null nếu f không khả nghịch
  function computePublic(f, g, logn) {
    var tf = mqNtt(f, logn), tg = mqNtt(g, logn), n = 1 << logn, t = new Int32Array(n), i;
    for (i = 0; i < n; i++) if (tf[i] === 0) return null;
    for (i = 0; i < n; i++) t[i] = mqDiv(tg[i], tf[i]);
    return mqIntt(t, logn);
  }
  // G = gF/f mod q, hệ số đối xứng; null nếu |G_i| > 127 hoặc f không khả nghịch
  function completePrivate(f, g, F, logn) {
    var tg = mqNtt(g, logn), tF = mqNtt(F, logn), tf = mqNtt(f, logn), n = 1 << logn, t = new Int32Array(n), i, G;
    for (i = 0; i < n; i++) if (tf[i] === 0) return null;
    for (i = 0; i < n; i++) t[i] = mqDiv((tg[i] * tF[i]) % Q, tf[i]);
    t = mqIntt(t, logn); G = new Array(n);
    for (i = 0; i < n; i++) { G[i] = center(t[i]); if (G[i] > 127 || G[i] < -127) return null; }
    return G;
  }

  // ---------------------------------------------------------------- HashToPoint (Alg. 3)
  function hashToPoint(data, logn) {
    var n = 1 << logn, c = new Int32Array(n), st = new Stream(data), cnt = 0, t;
    while (cnt < n) {
      t = (st.byte() << 8) | st.byte();
      if (t < 61445) c[cnt++] = t % Q;
    }
    return c;
  }

  // ---------------------------------------------------------------- mã hoá (§3.11)
  function modqEncode(h) {
    var n = h.length, out = new Uint8Array((14 * n + 7) >> 3), acc = 0, na = 0, p = 0, i;
    for (i = 0; i < n; i++) {
      if (!(h[i] >= 0 && h[i] < Q)) return null;
      acc = (acc << 14) | h[i]; na += 14;
      while (na >= 8) { na -= 8; out[p++] = (acc >>> na) & 0xFF; }
      acc &= (1 << na) - 1;
    }
    if (na > 0) out[p] = (acc << (8 - na)) & 0xFF;
    return out;
  }
  function modqDecode(d, off, n) {
    if (d.length - off !== ((14 * n + 7) >> 3)) return null;
    var h = new Int32Array(n), acc = 0, na = 0, p = off, i, v;
    for (i = 0; i < n; i++) {
      while (na < 14) { acc = (acc << 8) | d[p++]; na += 8; }
      na -= 14; v = (acc >>> na) & 0x3FFF; acc &= (1 << na) - 1;
      if (v >= Q) return null;
      h[i] = v;
    }
    if (acc !== 0) return null;                  // bit đệm phải bằng 0
    for (; p < d.length; p++) if (d[p] !== 0) return null;
    return h;
  }
  function trimEncode(f, bits) {
    var n = f.length, lim = (1 << (bits - 1)) - 1, mask = (1 << bits) - 1, out = new Uint8Array((n * bits + 7) >> 3);
    var acc = 0, na = 0, p = 0, i;
    for (i = 0; i < n; i++) {
      if (f[i] < -lim || f[i] > lim) return null;
      acc = (acc << bits) | (f[i] & mask); na += bits;
      while (na >= 8) { na -= 8; out[p++] = (acc >>> na) & 0xFF; }
      acc &= (1 << na) - 1;
    }
    if (na > 0) out[p] = (acc << (8 - na)) & 0xFF;
    return out;
  }
  // trả [f, số byte đã dùng] hoặc null
  function trimDecode(d, off, n, bits) {
    var need = (n * bits + 7) >> 3, out, acc = 0, na = 0, p = off, i, v, top = 1 << (bits - 1);
    if (d.length - off < need) return null;
    out = new Array(n);
    for (i = 0; i < n; i++) {
      while (na < bits) { acc = (acc << 8) | d[p++]; na += 8; }
      na -= bits; v = (acc >>> na) & ((1 << bits) - 1); acc &= (1 << na) - 1;
      if (v === top) return null;                // -2^(bits-1) bị cấm
      out[i] = v & top ? v - (1 << bits) : v;
    }
    if (acc !== 0) return null;
    return [out, need];
  }
  function pkEncode(h, P) { var b = modqEncode(h); return b ? concat([P.logn], b) : null; }
  function pkDecode(pk, P) {
    if (!pk || pk.length !== P.pkLen || pk[0] !== P.logn) return null;
    return modqDecode(pk, 1, P.n);
  }
  function skEncode(f, g, F, P) {
    var a = trimEncode(f, P.fgBits), b = trimEncode(g, P.fgBits), c = trimEncode(F, 8);
    if (!a || !b || !c) return null;
    return concat(concat([0x50 + P.logn], a), concat(b, c));
  }
  function skDecode(sk, P) {
    if (!sk || sk.length !== P.skLen || sk[0] !== 0x50 + P.logn) return null;
    var pos = 1, out = [], bl = [P.fgBits, P.fgBits, 8], i, r;
    for (i = 0; i < 3; i++) {
      r = trimDecode(sk, pos, P.n, bl[i]);
      if (!r) return null;
      out.push(r[0]); pos += r[1];
    }
    return pos === sk.length ? out : null;
  }
  // Alg. 17 Compress + header 0x30+logn || r || chuỗi bit đệm tới slen
  function sigEncodePadded(r, s2, P) {
    var slen = P.slenBits, body = new Uint8Array(slen >> 3), pos = 0, i, j, a, k;
    function put(b) { if (b) body[pos >> 3] |= 0x80 >> (pos & 7); pos++; }
    for (i = 0; i < s2.length; i++) {
      a = Math.abs(s2[i]); k = Math.floor(a / 128);
      if (pos + 9 + k > slen) return null;      // ⊥: không vừa slen
      put(s2[i] < 0 ? 1 : 0);
      for (j = 6; j >= 0; j--) put((a >> j) & 1);
      pos += k; put(1);
    }
    return concat(concat([0x30 + P.logn], r), body);
  }
  // Alg. 18 Decompress; null = ⊥
  function decompress(d, off, slen, n) {
    var len = (d.length - off) * 8, s = new Array(n), pos = 0, i, j, sp, k, si, sg;
    function bit(x) { return (d[off + (x >> 3)] >> (7 - (x & 7))) & 1; }
    if (len !== slen) return null;
    for (i = 0; i < n; i++) {
      if (pos + 9 > len) return null;
      sp = 0;
      for (j = 0; j < 7; j++) sp |= bit(pos + 1 + j) << (6 - j);
      k = 0;
      while (bit(pos + 8 + k) === 0) {
        k++;
        if (pos + 8 + k >= len) return null;
      }
      sg = bit(pos);
      si = (sg ? -1 : 1) * (sp + k * 128);
      if (si === 0 && sg === 1) return null;   // '-0'
      s[i] = si + 0;
      pos += 9 + k;
    }
    for (; pos < len; pos++) if (bit(pos)) return null;
    return s;
  }

  // ---------------------------------------------------------------- Verify (Alg. 16, định dạng đệm)
  function verifyP(P, pk, msg, sig) {
    var h = pkDecode(pk, P), s2, c;
    if (!h) return { ok: false, why: 'pk' };
    if (!sig || sig.length !== P.sbytelen || sig[0] !== 0x30 + P.logn) return { ok: false, why: 'format' };
    s2 = decompress(sig, 41, P.slenBits, P.n);
    if (!s2) return { ok: false, why: 'decompress' };
    c = hashToPoint(concat(sig.subarray(1, 41), msg), P.logn);
    return verifyCore(P, c, s2, h).ok ? { ok: true, why: 'ok' } : { ok: false, why: 'norm' };
  }
  /* Alg. 16 dòng 5-9: s1 = c - s2 h mod q; nhận khi ||(s1, s2)||^2 <= floor(beta^2) (biên được tính là nhận) */
  function verifyCore(P, c, s2, h) {
    var n = P.n, hm = mqNtt(h, P.logn), t, i, nn = 0, s1;
    for (i = 0; i < n; i++) hm[i] = mmul(hm[i], R2);
    t = mqNtt(s2, P.logn);
    for (i = 0; i < n; i++) t[i] = mmul(t[i], hm[i]);
    t = mqIntt(t, P.logn);
    for (i = 0; i < n; i++) { s1 = center(c[i] - t[i]); nn += s1 * s1; }
    for (i = 0; i < n; i++) nn += s2[i] * s2[i];
    return { ok: nn <= P.beta2, norm: nn };
  }

  // ---------------------------------------------------------------- FFT kiểu C (re ở [0, n/2), im ở [n/2, n))
  function fft(src, logn) {
    var n = 1 << logn, f = new Float64Array(n), hn = n >> 1, t = hn, m = 2, lv, ht, hm, i1, j, j1, sr, si, xr, xi, yr, yi, tr;
    for (j = 0; j < n; j++) f[j] = src[j];
    for (lv = 1; lv < logn; lv++) {
      ht = t >> 1; hm = m >> 1; j1 = 0;
      for (i1 = 0; i1 < hm; i1++) {
        sr = GM_RE[m + i1]; si = GM_IM[m + i1];
        for (j = j1; j < j1 + ht; j++) {
          xr = f[j]; xi = f[j + hn]; yr = f[j + ht]; yi = f[j + ht + hn];
          tr = yr * sr - yi * si; yi = yr * si + yi * sr; yr = tr;
          f[j] = xr + yr; f[j + hn] = xi + yi;
          f[j + ht] = xr - yr; f[j + ht + hn] = xi - yi;
        }
        j1 += t;
      }
      t = ht; m <<= 1;
    }
    return f;
  }
  function ifft(src, logn) {
    var n = 1 << logn, f = Float64Array.from(src), hn = n >> 1, t = 1, m = n, lv, hm, dt, i1, j1, j, sr, si, xr, xi, yr, yi, ni;
    for (lv = logn; lv > 1; lv--) {
      hm = m >> 1; dt = t << 1; i1 = 0; j1 = 0;
      while (j1 < hn) {
        sr = GM_RE[hm + i1]; si = -GM_IM[hm + i1];
        for (j = j1; j < j1 + t; j++) {
          xr = f[j]; xi = f[j + hn]; yr = f[j + t]; yi = f[j + t + hn];
          f[j] = xr + yr; f[j + hn] = xi + yi;
          xr = xr - yr; xi = xi - yi;
          f[j + t] = xr * sr - xi * si; f[j + t + hn] = xr * si + xi * sr;
        }
        i1++; j1 += dt;
      }
      t = dt; m = hm;
    }
    if (logn > 0) { ni = 2.0 / n; for (j = 0; j < n; j++) f[j] = f[j] * ni; }
    return f;
  }
  function pAdd(a, b) { var r = new Float64Array(a.length); for (var i = 0; i < a.length; i++) r[i] = a[i] + b[i]; return r; }
  function pSub(a, b) { var r = new Float64Array(a.length); for (var i = 0; i < a.length; i++) r[i] = a[i] - b[i]; return r; }
  function pNeg(a) { var r = new Float64Array(a.length); for (var i = 0; i < a.length; i++) r[i] = -a[i]; return r; }
  function pMulConst(a, x) { var r = new Float64Array(a.length); for (var i = 0; i < a.length; i++) r[i] = a[i] * x; return r; }
  function pMulFft(a, b) {
    var hn = a.length >> 1, r = new Float64Array(a.length), u, ar, ai, br, bi;
    for (u = 0; u < hn; u++) {
      ar = a[u]; ai = a[u + hn]; br = b[u]; bi = b[u + hn];
      r[u] = ar * br - ai * bi; r[u + hn] = ar * bi + ai * br;
    }
    return r;
  }
  function pMulAdjFft(a, b) {
    var hn = a.length >> 1, r = new Float64Array(a.length), u, ar, ai, br, bi;
    for (u = 0; u < hn; u++) {
      ar = a[u]; ai = a[u + hn]; br = b[u]; bi = -b[u + hn];
      r[u] = ar * br - ai * bi; r[u + hn] = ar * bi + ai * br;
    }
    return r;
  }
  function pMulSelfAdjFft(a) {
    var hn = a.length >> 1, r = new Float64Array(a.length), u;
    for (u = 0; u < hn; u++) { r[u] = a[u] * a[u] + a[u + hn] * a[u + hn]; r[u + hn] = 0.0; }
    return r;
  }
  function pAdjFft(a) {
    var hn = a.length >> 1, r = Float64Array.from(a);
    for (var u = hn; u < a.length; u++) r[u] = -a[u];
    return r;
  }
  // Alg. 1 splitfft / Alg. 2 mergefft
  function splitFft(f, logn) {
    var n = 1 << logn, hn = n >> 1, qn = n >> 2, f0 = new Float64Array(hn), f1 = new Float64Array(hn), u, ar, ai, br, bi, xr, xi, sr, si;
    f0[0] = f[0]; f1[0] = f[hn];
    for (u = 0; u < qn; u++) {
      ar = f[u << 1]; ai = f[(u << 1) + hn]; br = f[(u << 1) + 1]; bi = f[(u << 1) + 1 + hn];
      f0[u] = (ar + br) * 0.5; f0[u + qn] = (ai + bi) * 0.5;
      xr = ar - br; xi = ai - bi; sr = GM_RE[u + hn]; si = -GM_IM[u + hn];
      f1[u] = (xr * sr - xi * si) * 0.5; f1[u + qn] = (xr * si + xi * sr) * 0.5;
    }
    return [f0, f1];
  }
  function mergeFft(f0, f1, logn) {
    var n = 1 << logn, hn = n >> 1, qn = n >> 2, f = new Float64Array(n), u, ar, ai, br, bi, xr, xi, sr, si;
    f[0] = f0[0]; f[hn] = f1[0];
    for (u = 0; u < qn; u++) {
      ar = f0[u]; ai = f0[u + qn];
      xr = f1[u]; xi = f1[u + qn]; sr = GM_RE[u + hn]; si = GM_IM[u + hn];
      br = xr * sr - xi * si; bi = xr * si + xi * sr;
      f[u << 1] = ar + br; f[(u << 1) + hn] = ai + bi;
      f[(u << 1) + 1] = ar - br; f[(u << 1) + 1 + hn] = ai - bi;
    }
    return f;
  }
  // Alg. 8 LDL*: trả [L10, D11]
  function ldlFft(g00, g01, g11) {
    var hn = g00.length >> 1, l10 = Float64Array.from(g01), d11 = Float64Array.from(g11), u, m, ar, ai, br, bi, mr, mi, cr, ci;
    for (u = 0; u < hn; u++) {
      ar = g01[u]; ai = g01[u + hn]; br = g00[u]; bi = g00[u + hn];
      m = 1.0 / (br * br + bi * bi); br = br * m; bi = (-bi) * m;          // FPC_DIV
      mr = ar * br - ai * bi; mi = ar * bi + ai * br;
      cr = g01[u]; ci = -g01[u + hn];
      d11[u] = g11[u] - (mr * cr - mi * ci); d11[u + hn] = g11[u + hn] - (mr * ci + mi * cr);
      l10[u] = mr; l10[u + hn] = -mi;
    }
    return [l10, d11];
  }

  // ---------------------------------------------------------------- KeyGen: f, g Gauss (keygen.c mkgauss)
  function lt63(hi, lo, T) { return hi < T[0] || (hi === T[0] && lo < T[1]); }
  function mkgauss(st, logn) {
    var val = 0, it, lo, hi, neg, f, v, k, t;
    for (it = 0; it < (1 << (10 - logn)); it++) {
      lo = st.u32(); hi = st.u32();
      neg = hi >>> 31; hi = hi & 0x7FFFFFFF;
      f = lt63(hi, lo, GAUSS_KG[0]) ? 1 : 0;
      v = 0;
      lo = st.u32(); hi = st.u32() & 0x7FFFFFFF;
      for (k = 1; k < GAUSS_KG.length; k++) {
        t = lt63(hi, lo, GAUSS_KG[k]) ? 0 : 1;
        if (t && !f) v = k;
        f |= t;
      }
      val += neg ? -v : v;
    }
    return val;
  }
  // hệ số cuối lấy lại tới khi tổng các hệ số lẻ (Res(f) lẻ)
  function polySmall(st, logn) {
    var n = 1 << logn, out = new Array(n), mod2 = 0, u, s;
    for (u = 0; u < n; u++) {
      for (;;) {
        s = mkgauss(st, logn);
        if (s < -127 || s > 127) continue;
        if (u === n - 1) { if ((mod2 ^ (s & 1)) === 0) continue; }
        else mod2 ^= s & 1;
        break;
      }
      out[u] = s;
    }
    return out;
  }
  // chuẩn trực giao hoá Gram-Schmidt như keygen.c
  function gsNorm(f, g, logn) {
    var rt1 = fft(f, logn), rt2 = fft(g, logn), n = rt1.length, hn = n >> 1, rt3 = new Float64Array(hn), u, b;
    for (u = 0; u < hn; u++) {
      rt3[u] = 1.0 / ((rt1[u] * rt1[u] + rt1[u + hn] * rt1[u + hn]) + (rt2[u] * rt2[u] + rt2[u + hn] * rt2[u + hn]));
    }
    rt1 = pMulConst(pAdjFft(rt1), Q); rt2 = pMulConst(pAdjFft(rt2), Q);
    for (u = 0; u < n; u++) { rt1[u] = rt1[u] * rt3[u % hn]; rt2[u] = rt2[u] * rt3[u % hn]; }
    rt1 = ifft(rt1, logn); rt2 = ifft(rt2, logn);
    b = 0.0;
    for (u = 0; u < n; u++) { b += rt1[u] * rt1[u]; b += rt2[u] * rt2[u]; }
    return b;
  }

  // ---------------------------------------------------------------- NTRUSolve (Alg. 6-7) trên BigInt
  function bitLen(x) {                        // x >= 0n
    if (x === 0n) return 0;
    var s = x.toString(16);
    return (s.length - 1) * 4 + (32 - Math.clz32(parseInt(s.charAt(0), 16)));
  }
  function maxAbs(a) { var m = 0n, i, x; for (i = 0; i < a.length; i++) { x = a[i] < 0n ? -a[i] : a[i]; if (x > m) m = x; } return m; }
  function bitsize(a) { return bitLen(maxAbs(a)); }
  var ZEROS = '';
  function zeros(d) { while (ZEROS.length < d) ZEROS += ZEROS.length ? ZEROS : '0000000000000000'; return ZEROS.substr(0, d); }
  // đóng gói hệ số (dấu tách riêng) thành một số nguyên lớn, mỗi ô d chữ số hex
  function packHex(a, d, neg) {
    var n = a.length, parts = new Array(n), Z = zeros(d), i, x, s, any = false;
    for (i = 0; i < n; i++) {
      x = a[n - 1 - i];
      if (neg ? x < 0n : x > 0n) { s = (neg ? -x : x).toString(16); parts[i] = Z.substr(s.length) + s; any = true; }
      else parts[i] = Z;
    }
    return any ? BigInt('0x' + parts.join('')) : 0n;
  }
  // nhân âm-vòng CHÍNH XÁC trong Z[x]/(x^n+1) bằng thế Kronecker
  function pmulZ(a, b) {
    var n = a.length, ma, mb, w, d, A, B, C, Z, half, L, s, out, c, i;
    if (n === 1) return [a[0] * b[0]];
    ma = maxAbs(a); mb = maxAbs(b);
    w = bitLen(ma || 1n) + bitLen(mb || 1n) + (32 - Math.clz32(n)) + 2;
    d = (w + 3) >> 2; w = d * 4;
    A = packHex(a, d, false) - packHex(a, d, true);
    B = packHex(b, d, false) - packHex(b, d, true);
    Z = zeros(d);
    half = BigInt('0x8' + Z.substr(1));
    L = (2 * n - 1) * d;
    C = A * B + BigInt('0x' + ('8' + Z.substr(1)).repeat(2 * n - 1));   // mỗi ô cộng 2^(w-1): hết số âm
    s = C.toString(16);
    if (s.length < L) s = zeros(L - s.length) + s;
    c = new Array(2 * n - 1);
    for (i = 0; i < 2 * n - 1; i++) c[i] = BigInt('0x' + s.substr(L - (i + 1) * d, d)) - half;
    out = new Array(n);
    for (i = 0; i < n; i++) out[i] = i + n < 2 * n - 1 ? c[i] - c[i + n] : c[i];
    return out;
  }
  function galoisConj(f) { var r = new Array(f.length); for (var i = 0; i < f.length; i++) r[i] = i & 1 ? -f[i] : f[i]; return r; }
  function fieldNorm(f) {
    var hn = f.length >> 1, f0 = new Array(hn), f1 = new Array(hn), a, b, r = new Array(hn), i;
    for (i = 0; i < hn; i++) { f0[i] = f[2 * i]; f1[i] = f[2 * i + 1]; }
    a = pmulZ(f0, f0); b = pmulZ(f1, f1);
    r[0] = a[0] + b[hn - 1];
    for (i = 1; i < hn; i++) r[i] = a[i] - b[i - 1];
    return r;
  }
  function lift(fp) { var r = new Array(2 * fp.length), i; for (i = 0; i < fp.length; i++) { r[2 * i] = fp[i]; r[2 * i + 1] = 0n; } return r; }
  function floorDiv(a, b) { var q = a / b; if (a % b !== 0n && ((a < 0n) !== (b < 0n))) q -= 1n; return q; }
  function xgcd(a, b) {
    var x0 = 1n, x1 = 0n, y0 = 0n, y1 = 1n, qq, t;
    while (b !== 0n) {
      qq = floorDiv(a, b);
      t = a - qq * b; a = b; b = t;
      t = x0 - qq * x1; x0 = x1; x1 = t;
      t = y0 - qq * y1; y0 = y1; y1 = t;
    }
    return [a, x0, y0];
  }
  function rint(x) {                          // làm tròn gần nhất, hoà về chẵn (= round() của Python)
    if (x >= 0) return x < TWO52 ? (x + TWO52) - TWO52 : x;
    return x > -TWO52 ? (x - TWO52) + TWO52 : x;
  }
  function topBits(a, sh) { var r = new Float64Array(a.length), s = BigInt(sh); for (var i = 0; i < a.length; i++) r[i] = Number(a[i] >> s); return r; }
  // Alg. 7 Reduce: k xấp xỉ bằng FFT trên 53 bit cao, mỗi vòng bớt tới 30 bit; phép trừ chính xác
  function reduceFG(f, g, F, G) {
    var n = f.length, logn = 31 - Math.clz32(n), hn = n >> 1, size, fa, ga, dre, dim, it, Size, Fa, Ga, qv, u, v,
      ar, ai, br, bi, Ar, Ai, Br, Bi, nre, nim, xr, xi, yr, yi, ratio, den, e, sc, k, any, fk, gk, sh, i, r, num, d0;
    if (n === 1) {
      d0 = f[0] * f[0] + g[0] * g[0]; num = F[0] * f[0] + G[0] * g[0];
      r = floorDiv(2n * num + d0, 2n * d0);
      return [[F[0] - r * f[0]], [G[0] - r * g[0]]];
    }
    size = Math.max(53, bitsize(f), bitsize(g));
    fa = fft(topBits(f, size - 53), logn); ga = fft(topBits(g, size - 53), logn);
    dre = new Float64Array(hn); dim = new Float64Array(hn);
    for (u = 0; u < hn; u++) {                 // a conj(a) + b conj(b) (phép nhân số phức của Python)
      ar = fa[u]; ai = fa[u + hn]; br = ga[u]; bi = ga[u + hn];
      dre[u] = (ar * ar - ai * (-ai)) + (br * br - bi * (-bi));
      dim[u] = (ar * (-ai) + ai * ar) + (br * (-bi) + bi * br);
    }
    for (it = 0; it < MAX_REDUCE; it++) {
      Size = Math.max(53, bitsize(F), bitsize(G));
      if (Size < size) return [F, G];
      Fa = fft(topBits(F, Size - 53), logn); Ga = fft(topBits(G, Size - 53), logn);
      qv = new Float64Array(n);
      for (u = 0; u < hn; u++) {
        ar = fa[u]; ai = fa[u + hn]; br = ga[u]; bi = ga[u + hn];
        Ar = Fa[u]; Ai = Fa[u + hn]; Br = Ga[u]; Bi = Ga[u + hn];
        nre = (Ar * ar - Ai * (-ai)) + (Br * br - Bi * (-bi));
        nim = (Ar * (-ai) + Ai * ar) + (Br * (-bi) + Bi * br);
        yr = dre[u]; yi = dim[u];              // phép chia số phức của Python (tỉ số theo thành phần lớn hơn)
        if (Math.abs(yr) >= Math.abs(yi)) {
          if (yr === 0) throw new Error('NTRUSolve: chia cho 0');
          ratio = yi / yr; den = yr + yi * ratio;
          xr = (nre + nim * ratio) / den; xi = (nim - nre * ratio) / den;
        } else if (Math.abs(yi) >= Math.abs(yr)) {
          ratio = yr / yi; den = yr * ratio + yi;
          xr = (nre * ratio + nim) / den; xi = (nim * ratio - nre) / den;
        } else throw new Error('NTRUSolve: NaN');
        qv[u] = xr; qv[u + hn] = xi;
      }
      v = ifft(qv, logn);
      e = Math.min(Size - size, 30); sc = Math.pow(2, e);
      k = new Array(n); any = false;
      for (i = 0; i < n; i++) {
        r = rint(v[i] * sc);
        if (!isFinite(r)) throw new Error('NTRUSolve: k không hữu hạn');
        k[i] = BigInt(r);
        if (r !== 0) any = true;
      }
      if (!any) return [F, G];
      fk = pmulZ(f, k); gk = pmulZ(g, k); sh = BigInt(Size - size - e);
      for (i = 0; i < n; i++) { F[i] = F[i] - (fk[i] << sh); G[i] = G[i] - (gk[i] << sh); }
    }
    throw new Error('NTRUSolve: Reduce không hội tụ');
  }
  // Alg. 6: F, G với fG - gF = q; null nếu gcd != 1
  function ntruSolve(f, g) {
    var n = f.length, r, F, G;
    if (n === 1) {
      r = xgcd(f[0], g[0]);
      if (r[0] !== 1n) return null;
      return [[-r[2] * QB], [r[1] * QB]];
    }
    r = ntruSolve(fieldNorm(f), fieldNorm(g));
    if (!r) return null;
    F = pmulZ(lift(r[0]), galoisConj(g));
    G = pmulZ(lift(r[1]), galoisConj(f));
    return reduceFG(f, g, F, G);
  }
  function toBig(a) { var r = new Array(a.length); for (var i = 0; i < a.length; i++) r[i] = BigInt(a[i]); return r; }

  // Alg. 5 NTRUGen theo đúng trình tự quyết định của bản tham chiếu vòng 3
  function ntrugen(P, st) {
    var logn = P.logn, n = P.n, lim = 1 << (P.fgBitsC - 1), cand = 0, f, g, h, r, i, bad, nn, F, G;
    for (;;) {
      if (++cand > MAX_CAND) throw new Error('KeyGen: quá ' + MAX_CAND + ' ứng viên (f, g)');
      f = polySmall(st, logn); g = polySmall(st, logn);
      bad = false; nn = 0;
      for (i = 0; i < n; i++) {
        if (!(-lim < f[i] && f[i] < lim) || !(-lim < g[i] && g[i] < lim)) bad = true;
        nn += f[i] * f[i] + g[i] * g[i];
      }
      if (bad || nn > NORM_FG_MAX) continue;
      if (!(gsNorm(f, g, logn) < BNORM_MAX)) continue;
      h = computePublic(f, g, logn);
      if (!h) continue;
      r = ntruSolve(toBig(f), toBig(g));
      if (!r) continue;
      F = new Array(n); G = new Array(n); bad = false;
      for (i = 0; i < n; i++) {
        if (r[0][i] > 127n || r[0][i] < -127n || r[1][i] > 127n || r[1][i] < -127n) { bad = true; break; }
        F[i] = Number(r[0][i]); G[i] = Number(r[1][i]);
      }
      if (bad) continue;
      return { f: f, g: g, F: F, G: G, h: h };
    }
  }

  // ---------------------------------------------------------------- SamplerZ (Alg. 12-15) + PRNG ChaCha20 vòng 3
  var CW = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574];
  function rotl(v, c) { return (v << c) | (v >>> (32 - c)); }
  function chachaBlock(st, out) {
    var x = st.slice(), i;
    function qr(a, b, c, d) {
      x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 16);
      x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 12);
      x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 8);
      x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 7);
    }
    for (i = 0; i < 10; i++) {
      qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
      qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
    }
    for (i = 0; i < 16; i++) out[i] = (x[i] + st[i]) | 0;
  }
  function le32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
  // khoá 32 byte || IV 16 byte || bộ đếm 8 byte; 8 khối mỗi lần nạp, byte ra xen kẽ như bản AVX2
  function ChaCha(seed56) {
    this.kiv = [];
    for (var i = 0; i < 12; i++) this.kiv.push(le32(seed56, 4 * i) | 0);
    this.cl = le32(seed56, 48); this.ch = le32(seed56, 52);
    this.buf = new Uint8Array(512); this.ptr = 0; this.lo = 0; this.hi = 0; this.out = new Array(16);
    this.refill();
  }
  ChaCha.prototype.refill = function () {
    var u, v, st, o, w;
    for (u = 0; u < 8; u++) {
      st = CW.concat(this.kiv);
      st[14] = st[14] ^ this.cl; st[15] = st[15] ^ this.ch;
      chachaBlock(st, this.out);
      this.cl = (this.cl + 1) >>> 0;
      if (this.cl === 0) this.ch = (this.ch + 1) >>> 0;
      for (v = 0; v < 16; v++) {
        o = (u << 2) + (v << 5); w = this.out[v];
        this.buf[o] = w & 0xFF; this.buf[o + 1] = (w >>> 8) & 0xFF; this.buf[o + 2] = (w >>> 16) & 0xFF; this.buf[o + 3] = w >>> 24;
      }
    }
    this.ptr = 0;
  };
  ChaCha.prototype.u64 = function () {             // đặt this.lo / this.hi
    if (this.ptr >= 512 - 9) this.refill();
    this.lo = le32(this.buf, this.ptr); this.hi = le32(this.buf, this.ptr + 4);
    this.ptr += 8;
  };
  ChaCha.prototype.u8 = function () {
    var v = this.buf[this.ptr++];
    if (this.ptr === 512) this.refill();
    return v;
  };
  // Alg. 12 BaseSampler: số phần tử RCDT lớn hơn u (u 72 bit = u64 + 2^64 u8)
  function baseSampler(lo, hi, top) {
    var z = 0, i, t;
    for (i = 0; i < RCDT.length; i++) {
      t = RCDT[i];
      if (top < t[0] || (top === t[0] && (hi < t[1] || (hi === t[1] && lo < t[2])))) z++;
    }
    return z;
  }
  // Alg. 13 ApproxExp: ~ 2^63 ccs exp(-x)
  function approxExp(x, ccs) {
    var y = EXPM_C[0], z = BigInt(Math.trunc(x * P63)), i;
    for (i = 1; i < EXPM_C.length; i++) y = (EXPM_C[i] - ((z * y) >> 63n)) & M64;
    z = BigInt(Math.trunc(ccs * P63));
    return (z * y) >> 63n;
  }
  // Alg. 14 BerExp: so sánh lười từng byte
  function berExp(rng, x, ccs) {
    var s = Math.trunc(x * INV_LN2), r, z, zhi, zlo, i, w;
    if (!(s >= 0)) throw new Error('SamplerZ: x không hợp lệ');
    r = x - s * LN2;
    if (s > 63) s = 63;
    z = (((approxExp(r, ccs) << 1n) - 1n) & M64) >> BigInt(s);
    zhi = Number(z >> 32n); zlo = Number(z & 0xFFFFFFFFn);
    i = 64;
    do {
      i -= 8;
      w = rng.u8() - (i >= 32 ? (zhi >>> (i - 32)) & 0xFF : (zlo >>> i) & 0xFF);
    } while (w === 0 && i > 0);
    return w < 0;
  }
  // Alg. 15 SamplerZ(mu, sigma'), tham số là 1/sigma'
  function samplerZ(rng, mu, isigma, sigmaMin) {
    var s = Math.floor(mu), r = mu - s, dss = (isigma * isigma) * 0.5, ccs = isigma * sigmaMin, it, z0, b, z, x;
    for (it = 0; it < MAX_SAMPLER_ITER; it++) {
      rng.u64();
      z0 = baseSampler(rng.lo, rng.hi, rng.u8());
      b = rng.u8() & 1;
      z = b + ((b << 1) - 1) * z0;
      x = ((z - r) * (z - r)) * dss;
      x = x - (z0 * z0) * INV_2SQRSIGMA0;
      if (berExp(rng, x, ccs)) return s + z;
    }
    throw new Error('SamplerZ: quá nhiều vòng lặp (khoá hỏng?)');
  }

  // ---------------------------------------------------------------- Sign (Alg. 10-11, kiểu sign_dyn)
  // Alg. 11 ffSampling: cây LDL dựng tại chỗ ở mỗi mức, con phải (t1) trước
  function ffSampling(samp, t0, t1, g00, g01, g11, logn) {
    var ld, d00, d11, tt1, z1p, z1, tb0, tt0, z0p;
    if (logn === 0) return [[samp(t0[0], g00[0])], [samp(t1[0], g00[0])]];
    ld = ldlFft(g00, g01, g11);
    d00 = splitFft(g00, logn);
    d11 = splitFft(ld[1], logn);
    tt1 = splitFft(t1, logn);
    z1p = ffSampling(samp, tt1[0], tt1[1], d11[0], d11[1], d11[0], logn - 1);
    z1 = mergeFft(z1p[0], z1p[1], logn);
    tb0 = pAdd(t0, pMulFft(ld[0], pSub(t1, z1)));
    tt0 = splitFft(tb0, logn);
    z0p = ffSampling(samp, tt0[0], tt0[1], d00[0], d00[1], d00[0], logn - 1);
    return [mergeFft(z0p[0], z0p[1], logn), z1];
  }
  function basis(key, logn) {
    var b00 = fft(key.g, logn), b01 = pNeg(fft(key.f, logn)), b10 = fft(key.G, logn), b11 = pNeg(fft(key.F, logn));
    return {
      b00: b00, b01: b01, b10: b10, b11: b11,
      g00: pAdd(pMulSelfAdjFft(b00), pMulSelfAdjFft(b01)),
      g01: pAdd(pMulAdjFft(b01, b11), pMulAdjFft(b00, b10)),
      g11: pAdd(pMulSelfAdjFft(b10), pMulSelfAdjFft(b11))
    };
  }
  // một lần thử: trả [s2, ||(s1, s2)||^2]
  function signCore(B, hm, rng, P) {
    var logn = P.logn, n = P.n, ni = 1.0 / Q, t0, t1, z, v0, v1, s2 = new Array(n), nn = 0, i, a;
    t0 = fft(hm, logn);
    t1 = pMulConst(pMulFft(t0, B.b01), -ni);
    t0 = pMulConst(pMulFft(t0, B.b11), ni);
    z = ffSampling(function (mu, leafG) {
      var isig = Math.sqrt(leafG) * P.invSigma;
      if (!isFinite(isig)) throw new Error('Sign: lá cây LDL không hợp lệ (khoá hỏng?)');
      return samplerZ(rng, mu, isig, P.sigmaMin);
    }, t0, t1, B.g00, B.g01, B.g11, logn);
    v0 = ifft(pAdd(pMulFft(z[0], B.b00), pMulFft(z[1], B.b10)), logn);
    v1 = ifft(pAdd(pMulFft(z[1], B.b11), pMulFft(z[0], B.b01)), logn);
    for (i = 0; i < n; i++) {
      a = hm[i] - rint(v0[i]); nn += a * a;
      s2[i] = 0 - rint(v1[i]); nn += s2[i] * s2[i];
    }
    return [s2, nn];
  }
  // vòng ngoài: mỗi lần thử nạp lại ChaCha20 từ 56 byte tiếp theo của SHAKE256(seed); ký lại nếu Compress = ⊥
  function signPadded(P, key, msg, salt, seed) {
    var hm = hashToPoint(concat(salt, msg), P.logn), shake = new Stream(seed), B = basis(key, P.logn), total = 0,
      rs, att, res, sig;
    for (rs = 0; rs < MAX_RESIGN; rs++) {
      for (att = 1; att <= MAX_ATTEMPTS; att++) {
        total++;
        res = signCore(B, hm, new ChaCha(shake.read(56)), P);
        if (res[1] <= P.l2bound) break;
      }
      if (att > MAX_ATTEMPTS) throw new Error('Sign: không ký được sau ' + MAX_ATTEMPTS + ' lần');
      sig = sigEncodePadded(salt, res[0], P);
      if (sig) return { sig: sig, attempts: total };
    }
    throw new Error('Sign: chữ ký nén không vừa sau ' + MAX_RESIGN + ' lần');
  }

  function bytes(x, what) {                       // nhận mọi khung nhìn byte, kể cả từ realm khác (iframe, bộ kiểm thử)
    if (!x || !ArrayBuffer.isView(x) || x.BYTES_PER_ELEMENT !== 1) throw new Error(what + ' phải là Uint8Array');
    return x instanceof Uint8Array ? x : new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  }

  root.FNDSA = {
    NAMES: ['Falcon-512', 'Falcon-1024'],
    /* chỉ để kiểm thử: phép so chuẩn ở biên beta^2 (không dựng được chữ ký trọn vẹn nằm đúng biên nếu không có khoá bí mật) */
    verifyCore: function (name, c, s2, h) { return verifyCore(param(name), c, s2, h); },
    sizes: function (name) { var P = param(name); return { pk: P.pkLen, sk: P.skLen, sig: P.sbytelen }; },
    keygen: function (name, seed48) {
      var P = param(name), k = ntrugen(P, new Stream(bytes(seed48, 'seed'))), pk = pkEncode(k.h, P), sk = skEncode(k.f, k.g, k.F, P);
      if (!pk || !sk) throw new Error('KeyGen: không mã hoá được khoá');
      return { pk: pk, sk: sk };
    },
    sign: function (name, sk, msg, salt40, seed48) {
      var P = param(name), d = skDecode(bytes(sk, 'sk'), P), G;
      if (!d) throw new Error('Khoá bí mật không giải mã được');
      G = completePrivate(d[0], d[1], d[2], P.logn);
      if (!G || !computePublic(d[0], d[1], P.logn)) throw new Error('Khoá bí mật không đầy đủ (không tính được G hoặc h)');
      if (bytes(salt40, 'salt').length !== 40) throw new Error('salt phải dài 40 byte');
      return signPadded(P, { f: d[0], g: d[1], F: d[2], G: G }, bytes(msg, 'msg'), salt40, bytes(seed48, 'seed'));
    },
    verify: function (name, pk, msg, sig) {
      try {
        var P = param(name);
        if (!(pk instanceof Uint8Array)) return { ok: false, why: 'pk' };
        if (!(sig instanceof Uint8Array) || !(msg instanceof Uint8Array)) return { ok: false, why: 'format' };
        return verifyP(P, pk, msg, sig);
      } catch (e) { return { ok: false, why: 'format' }; }
    },
    checkSk: function (name, sk) {
      var P = param(name), d = sk instanceof Uint8Array ? skDecode(sk, P) : null, h;
      if (!d) return { decoded: false, pk: null, ntru: false };
      h = computePublic(d[0], d[1], P.logn);
      return { decoded: true, pk: h ? pkEncode(h, P) : null, ntru: !!completePrivate(d[0], d[1], d[2], P.logn) };
    }
  };
})(typeof window !== 'undefined' ? window : globalThis);
