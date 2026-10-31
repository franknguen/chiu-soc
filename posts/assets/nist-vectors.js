/* Vector kiểm chứng cho nút "Chạy kiểm chứng" của máy tính SLH-DSA / FN-DSA / HQC-KEM: vector ACVP của NIST
   (SLH-DSA), mục KAT chính thức count = 0 (Falcon vòng 3, HQC 5.1.0; đầu vào rút lại qua AES-256 CTR_DRBG), và
   vector seed cố định từ một mô hình tham chiếu đã khớp các nguồn đó. Chỉ có khoá thử nghiệm công khai. */
window.NIST3_VECTORS = {
 "codec": [
  {
   "fmt": "auto",
   "in": "{ 0x01, -1, 127 }",
   "out": "01ff7f"
  },
  {
   "fmt": "base64",
   "in": "AQL/",
   "out": "0102ff"
  }
 ],
 "fn": {
  "det": {
   "Falcon-1024": {
    "kseed": "83fce8fe71eb290b5756421c0a6214b89d7476fb4f04f327fa45bf64cd19172c984ea334288471b038008e4916b8e712",
    "msg": "75fd5adf5f8d4fce482257d267366a4125c7fb48219ed5a7f79b12e485905aae95c0611f38611c75e2e1d86789146e83a1160431c5a813ffa7161b3f3ceda08b72057bc2c72905b71641fb97c48682c9f8d0bfdb21e359bbeaaee0ac2329c6b062472a",
    "pk_sha256": "e4694aa136880981881a71c5753bed3a8dc0ebf2e42463fc306580b23e0962e6",
    "salt": "a9ff2ad263840b4d28f0b7af2d3b4b9e3fb16fcdc490e940d5bbf282d6ba54c11ac925fd379b7792",
    "sig_sha256": "6cea9bb1929e08e09b03c510663869dfc868e42b8103f6609fc0a3fc46bc468e",
    "sk_sha256": "7cdb6b341b86c1ca91f9350896632d7f26cf52a44a20484451c99c93b7e10bcc",
    "sseed": "7ff8797a4e916d3b4c15e2ddc5af902031e731a3ec02ed2581ffa0db3c77403ed703a2fea4a4861d8a82846b5e46002a"
   },
   "Falcon-512": {
    "kseed": "214b43e7139c7934c6566865742c66558d0c5c15ade2060e295a2d201570dc08cf19e9fbc2d0bab18d09ec9c118e0e05",
    "msg": "144575511323910ca68e05669e7bbcf6cfdb61cb17aa503617153b5b9dcb34f05df0e70e7afaeceb5eefbd63a5655f7c6e5f6a501445db80631a118f5505889cd937665ca5b660749cece41704d1ef42f0e4d3d636475b23e0c0222fd097635fe582c6",
    "pk_sha256": "f2e13137c1332d40ef099b4dc3364826a94f0b3cda02dcb4cd860c094deccb67",
    "salt": "8674d15fabb62672ee0f673392bb2077b7e948c4c1953c891973e7889f01ad259d444f2826b2b9ab",
    "sig_sha256": "7a84e37e753e28b924093acf694cdd4b8081864a89aa93f23e587b6fc5c81bbc",
    "sk_sha256": "d2b9f51ed11f5e2386fc81ca0709fbabeacc6fa6d729177160338e6f0482c2eb",
    "sseed": "7a9b599ea1a1d9728cca9a5b924f73f0268158b6bde827c4bf8be539fa0c40cef3b33e6bd74071a00b98101ba39657ba"
   }
  },
  "kat": {
   "Falcon-1024": {
    "kseed": "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e47",
    "msg": "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
    "pk_sha256": "f392083048bb1bc08d77ef3782dd114154480adebbf5ee0c3853816cba0a7341",
    "salt": "33b3c07507e4201748494d832b6ee2a6c93bff9b0ee343b550d1f85a3d0de0d704c6d17842951309",
    "sig_sha256": "790e7885ba504f023b4c6a21955c2edd2909aa17e00dbe0a588f176d0378e219",
    "sk_sha256": "5b93be961746f89a4c1d339ba7b6c6c82baab915f36d51e2afe9d655cf435464",
    "sseed": "c4731c3819f29b78474da5eaa38b5e98b253547d766cf23d50e88731c01ca6e1186cf7504e36ae12b4e9e814c06e68eb"
   },
   "Falcon-512": {
    "kseed": "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e47",
    "msg": "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
    "pk_sha256": "e74cb05c857846d8c768a2d3a2461d589482e770461fdbbe9e2e9dc6415e2daf",
    "salt": "33b3c07507e4201748494d832b6ee2a6c93bff9b0ee343b550d1f85a3d0de0d704c6d17842951309",
    "sig_sha256": "dec532c785e52c297728bdb2e612947f8b04dee11a7d7a777e8614c435f3a316",
    "sk_sha256": "0dfaaa352b95059488f1fdad55848bb814f18bca1de5194e5f9994c40a8730b6",
    "sseed": "c4731c3819f29b78474da5eaa38b5e98b253547d766cf23d50e88731c01ca6e1186cf7504e36ae12b4e9e814c06e68eb"
   }
  }
 },
 "hqc": {
  "det": {
   "HQC-1": {
    "K": "4c05f506812cebe9523b3f7b4d51cb4bf1b53ad63ee9c075f94b581a68dec6e8",
    "K_reject": "bd4d411f8dbe04646921ca34f7188a7c066572b1e99a794dcf458bf8490c5ea3",
    "ct_flip_byte": 7,
    "ct_sha256": "3cfa8261f278fcd8c84e7dcba5862799e81799e852a4b5ed2eb97448053faeac",
    "ek_sha256": "3feda6e003b329aee3faa38b3d987e97312decc72b602f5d80a4a759717850c7",
    "m": "57a0e5e478176dbc337978229bc647df",
    "salt": "3794107e6809c48af5981d9efc32dac6",
    "seed_kem": "8ab9bfcfeae518c1388f937923d91e44a959601bbba24c21e6ae75cccefaa068"
   },
   "HQC-3": {
    "K": "bf861d2c086c102060e84e5c53620f6dc7ea714b12944de27ec45a7fec4787ed",
    "K_reject": "93d264cc3ee100a3fa2551999b7bdb77d42f88de5311181ab3e13c04ec0c144b",
    "ct_flip_byte": 7,
    "ct_sha256": "6da10b442838f13252657a8252c83d708fd9ec268715e20d5b423a62f45b6ce3",
    "ek_sha256": "860618a74a0ef5c781cfe37fee4f845b3e46f94df9b1d818edf4a8fa082c11c1",
    "m": "191640480c24dbd9eba3d1d6f4c35a6d496335bcfb65aee0",
    "salt": "583f45160f61b43400c167248cf105cc",
    "seed_kem": "024ab2504c353c34a9693400eb58ed2826b6bd09f4225799df330cf83555dee1"
   },
   "HQC-5": {
    "K": "7be20722258190cf64f1f0f8b385cdb559fb5ce7d7df103fbf92497f3666bb00",
    "K_reject": "d4aa94f804ddfbbbe45eee4cd9a902c999c5c6a1afeef2fddac8ef714c545415",
    "ct_flip_byte": 7,
    "ct_sha256": "bde379e68052e7f217a7289f3d2b6cfad1bf70345de41c21f0f12a4e4febd439",
    "ek_sha256": "5664efa22668dc901bf35f47a850ea6a5c6befcde83328874e752e608652a3a0",
    "m": "49ff2ba17085f35ad78c30e079445a5be64797cd73b4bdf7229224ad4d3483f8",
    "salt": "167dfef767a8ad32bfcdd2cc5a081c9d",
    "seed_kem": "6db42817ba8e2e176e98337bdfd4ba002800f522349a004983a623dec26d56dc"
   }
  },
  "kat": {
   "HQC-1": {
    "ct_sha256": "ed9be65c0dc1174c7340f8cf97961a41614b69421c0d4d60061f8a4deed0c8d0",
    "dk": "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d",
    "ek_sha256": "bcdb395f7b6b95c6526bdf9bd5a0570e28037ccb0e1bdb44e23d7c7ed98500f3",
    "m": "8626ed79d451140800e03b59b956f821",
    "salt": "efb3b24da2bcf2c843ff1580ef5a1c1b",
    "seed_kem": "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d",
    "ss": "68e999c2931d37540dbc4a295c505ac3fc778a68917276cc66703b5217678f48"
   },
   "HQC-3": {
    "ct_sha256": "1358850b9b18e841139e918642725895e769b3fa365b63d11ea624a9dc34246f",
    "dk": "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d",
    "ek_sha256": "56d8770b54af7deb645c83f996580dbf5c0c82793b5a79003c61885468bdb62c",
    "m": "8626ed79d451140800e03b59b956f8210e556067407d13dc",
    "salt": "147c03f7a5bebba406c8fae1874d7f13",
    "seed_kem": "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d",
    "ss": "8b7e784fd0a71aa2ad8ba0bb603787158206af84d0c68a5334cada2f930a411f"
   },
   "HQC-5": {
    "ct_sha256": "c85b8be0a406ef1e8b14bc06a4b523c40e2eebd460c1bc1bfadc6eca38190d89",
    "dk": "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d",
    "ek_sha256": "3223da019014e832c23548b0614b93aedeb0dbeaa9c0a75547e937e8e9a03b9d",
    "m": "8626ed79d451140800e03b59b956f8210e556067407d13dc90fa9e8b872bfb8f",
    "salt": "147c03f7a5bebba406c8fae1874d7f13",
    "seed_kem": "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d",
    "ss": "5f6ec41a35aad41d438c9096b96838e49b98cbc5b0d7d2a18330572f37beebb3"
   }
  }
 },
 "slh": {
  "keygen": [
   {
    "pk_sha256": "e7484e41b32f205939f202c3a29a72a1d43118f5ffc588323f81bf5b547c7b43",
    "seed": "173d04c938c1c36bf289c3c022d04b1463ae23c41aa546da589774ac20b745c40d794777914c99766827f0f09ca972be",
    "set": "SLH-DSA-SHA2-128s",
    "sk_sha256": "9087eb86d94a35bb52afc858b1e95d03a5c581b9321eb4ef7b56919c50b26f5b",
    "slow": true,
    "tcId": 1
   },
   {
    "pk_sha256": "25ee9c66d71febbe37e3886dbede0bb4d20958de72c0be86195a6b2f84fab4ce",
    "seed": "c151951f3811029239b74add24c506afdd30363e156e6fe936ec6ed0231feb5c529ffe86200d1f32c2b60d0cd909f190",
    "set": "SLH-DSA-SHAKE-128s",
    "sk_sha256": "6662e9cf7208c5641b2b96e5918a23aa3d9eedbabd954f242831eec178ec5f81",
    "slow": true,
    "tcId": 11
   },
   {
    "pk_sha256": "f588f376e9f44d86021b382d7fa07ebf01fa9d2dcfa4377d0b36493ff027716e",
    "seed": "c42bcb3b5a6f331f5cce899253c6d9e29ff2b7ead7a04bab1794db8cc659c3b4a868f1bd5debc12d4c9fad66aabd0a94",
    "set": "SLH-DSA-SHA2-128f",
    "sk_sha256": "adff9b5440c5b229436e33b4fb4eea1c592d4ea065556e0f3d826c223059d287",
    "slow": false,
    "tcId": 21
   },
   {
    "pk_sha256": "5107ab7cd0834360d91f144e2447c1774f4290099a127e83a2ffd01b4788aff5",
    "seed": "3956ab391b4d22fc907af0740326d061ab0eb206436f2b86ebe086d77739b3e456505c229f4e7fa6b201714c7dcc9da3",
    "set": "SLH-DSA-SHAKE-128f",
    "sk_sha256": "ca36947ceddfa6e6728ab7ca5d3114711a325b73f00f8eb7011e1fd33b7c0f9e",
    "slow": false,
    "tcId": 31
   },
   {
    "pk_sha256": "498ec4eab28a1b253b5a8a293b16cc8e09c2d18c05a1d0f05c159256ac8e347e",
    "seed": "040266529c1864088925506c20a624a2b6d50cd77c1c6f0d2841150ae8157512ef34a343ffea77ff7d9e814b45a8b41464462665f4202886206a8f632267186ca6a1cad08a2b9a86",
    "set": "SLH-DSA-SHA2-192s",
    "sk_sha256": "113db7c2e1d0cc8f11d2a447698a1736958f991157b0d26111e27862debb646a",
    "slow": true,
    "tcId": 41
   },
   {
    "pk_sha256": "5a2b44b7b015601dfb0392a5bebb3f5e2c97b80e0d21d02daf9e97251927422b",
    "seed": "8732621860e9a6e1887be55f7af692b98eb4c10b2599f94ad5cc9d6470d8b21136158e8b1710f1fbe03eced37ed4ac6853fc64d46d7e1653ebbb36ed5fbc12c6e7cef3cb756482c8",
    "set": "SLH-DSA-SHAKE-192s",
    "sk_sha256": "f3d10c6c87839472b50b489b36bd94f66a4fec103de18a5f7ae013befc02f39d",
    "slow": true,
    "tcId": 51
   },
   {
    "pk_sha256": "aa4c793154ef9545179d3a5186279961765b13baea9b465a1321bc3447fb7c8d",
    "seed": "a021b4b9d6dee168722bc10225e50a946642af630c3c7c7d69e3a40ba09df2ac165b792a07f064ac5fc28d8c99a580f4ee4823d09e79854706daa80ae3179b5bc8c2e9409d6328a3",
    "set": "SLH-DSA-SHA2-192f",
    "sk_sha256": "a034c8138b9e52583381a4ce84fe9c592f681b4177a04dab4eebf22621fb2731",
    "slow": false,
    "tcId": 61
   },
   {
    "pk_sha256": "19e63a15a01a9d882ab679b4d56c627e2f2f5471af24f17c4ffad0ecdda961d9",
    "seed": "fb7a2c2c75ce6c96b5f4328e0ab300476fc6f864cb5b0b99990ecb726ca822a4e3652dd92ec0aab7637ea41c0482ae2868dcc671e3534f81a352c275b6a25f906d2ed0ff62b8b4e3",
    "set": "SLH-DSA-SHAKE-192f",
    "sk_sha256": "c0c8d9e1c1587c65de2aa86193b4124ce8822516f9178536ceab72af2a84ff89",
    "slow": false,
    "tcId": 71
   },
   {
    "pk_sha256": "8dc17bc9c27953af4d7b5eafa534f2e0c73d6a1fc7a89d93e42574ae5b4146d5",
    "seed": "fcbf36a9807b30697be063a5105e091b412a391dd39e1326eba23cbd4096ca77ef4121c08dd71be913572f1f91e57d0acbcd5cec28539ac275832bbaa6c11081a0b4f5549ebcadb951dc2e512c76b0620d8fb8100b4ee886ef8784780d52a254",
    "set": "SLH-DSA-SHA2-256s",
    "sk_sha256": "664ef5fa151c6212b06336553adcc1b0db5e8820d1c7519169df8daac3e548e9",
    "slow": true,
    "tcId": 81
   },
   {
    "pk_sha256": "49a30ef4ed23a45399324c774fab8572e668f0266575c152783c8187395d9365",
    "seed": "e440e39644a11a6a58e850c09c8f03c273e465237f3bef7c58de62281e676cea99c199c00db30f8499a61b5b9dc8a361725f6ae80e97037176f408c30b38844dd7b5e755b4879fde3288a21af3e32fbb006fd9b8bc2b180eb9b0d82c9f3157af",
    "set": "SLH-DSA-SHAKE-256s",
    "sk_sha256": "3411ecdfeac0db9c1bba94f9d3384e8ef0e82b08bdb373c71884e9a6348ae86d",
    "slow": true,
    "tcId": 91
   },
   {
    "pk_sha256": "437f7d433ea72359d569ca5508d7ffed7089a4d42ff6a64fd9c986a01cf089f6",
    "seed": "18523702a0fe2c9e488948b127185bab93d3f02c3d7c23a1b379f762de0509e56ab0d9f93540bd809d1d2e8a050440aa81e853750470e2b00c959dbd3be40e2bd7125f5d00ba47f1fc8d4c32c2f57c444bd384d7ce770bc50dd5980c1d1264d0",
    "set": "SLH-DSA-SHA2-256f",
    "sk_sha256": "0b811ade3bec0de9334623eb5033211b9add743843b6c681d1320aca216c25f9",
    "slow": false,
    "tcId": 101
   },
   {
    "pk_sha256": "8cdec44cfd91c2b990cc535cf5951475b9bddbb6d9b4b01d5f2885a7fdd9806c",
    "seed": "2ac9403858d186b172edd8df9c78a11449893681487d3af0dad0ec341e8aca48afa2771bae6c17dd6f77b4e3808b05f56f31b8f4128df2ccb677f0283cfb18da559bc883105e8ba0264648b532626155f87edb4bedcfc12a24204d3b696d5370",
    "set": "SLH-DSA-SHAKE-256f",
    "sk_sha256": "950afffde864c4283a8ac5b89d55f3a0a074c1e8ab967c4123934fae80052603",
    "slow": false,
    "tcId": 111
   }
  ],
  "sign": [
   {
    "addrnd": "",
    "context": "0574b468e6d8487d5a61e3eb9ed9013f778ff989a25bc7726db90c9febecbd42c3066cc8212efc8ad827e9c34d5f",
    "deterministic": true,
    "hashAlg": "none",
    "message": "00ffdca5c6f2279728713dd597e26220a44424314b9ed8dee43e812121cacd0548049c6fc08f31e2740ea444a6066c7eabfaf2b6c896649c6e9c35f8d49ba6cdb6e3dc03600e1a96fbecc7af3b477a193656bcc79783e82408fc7ddb262ccf3cbedf8c2120a3d468c1893ab1bb6c99ec785b25a4d764ad4205fca73576dc20359e831cd434f2755cfa942b44c5ee20b032f4b747626dbfdab4c01495ffcffdedce009fdb1ccbe02fa38811973f61031a91a70473c9ef363d5f399f142218e40c2b6aa6c908b2573667813698ab1e1454d537aee3dc285774c9a88e740248b0d920bdb553b5d851408be19c2164ffe6edada25cd3f204cae1be5b",
    "preHash": "pure",
    "set": "SLH-DSA-SHAKE-128f",
    "sig_sha256": "987f710aee822acb0ed6baaceea7220e3ef24bc3bff264472bf8300590de4630",
    "sk": "29b12fefb5411a79aaf84b3cbf8a02218e2b5a524fdc4a8d8279db47dd74b5a84f190b458385ef8ebd1c6fcaf8f41657e9a0392166a29a3b05ab262627011dc9"
   },
   {
    "addrnd": "06895c8c220738ff4dde0aba0b1d0b15",
    "context": "d57689297c7d6a1be131d19c4c5c01669df00e58f884a5d6",
    "deterministic": false,
    "hashAlg": "SHA3-256",
    "message": "7a",
    "preHash": "preHash",
    "set": "SLH-DSA-SHAKE-128f",
    "sig_sha256": "6ea9c10e60dce490e0d888f23c2dcdedb745f820b6db01717b31b16df1837a9a",
    "sk": "2ce877ed18850e3b7214b3f1ab393e5ee3020f86d60c07314abc5939418646906518ee14cf2ff8cd3dd8eab94e1c91b3beb90886ea25e8fb63b50493a71f42e6"
   }
  ]
 }
};
