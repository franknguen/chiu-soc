/* Vector mẫu công khai cho trang đường cong elliptic: một tập con nhỏ của các file CAVP / ACVP của NIST (KeyPair.rsp, PKV.rsp,
   KAS_ECC_CDH_PrimitiveTest.txt, SigGen.txt, SigVer.rsp; ECDSA-KeyGen / KeyVer / SigGen / DetECDSA-SigGen / SigVer FIPS186-5;
   KAS-ECC-CDH-Component Sp800-56Ar3) và RFC 6979 A.2.5. Sinh tự động; mỗi nút "Nạp ví dụ NIST" và nút tự kiểm chứng đọc từ đây.
   Public example vectors for the elliptic-curve page: a small subset of NIST's CAVP / ACVP files and RFC 6979 A.2.5. Generated. */
window.EC_VECTORS = {
 "keygen": [
  {
   "src": "CAVS KeyPair.rsp",
   "curve": "P-192",
   "d": "e5ce89a34adddf25ff3bf1ffe6803f57d0220de3118798ea",
   "qx": "8abf7b3ceb2b02438af19543d3e5b1d573fa9ac60085840f",
   "qy": "a87f80182dcd56a6a061f81f7da393e7cffd5e0738c6b245"
  },
  {
   "src": "CAVS KeyPair.rsp",
   "curve": "P-224",
   "d": "e7c92383846a4e6887a10498d8eaca2bd0487d985bd7d3f92ce3ab30",
   "qx": "0a3682d2aaa4dd931bee042d32e95755507ab164b12f84843f4b7b96",
   "qy": "a6313a938eff7a293222e0e3c7b4c6132489b33255a61c3fc1ce2256"
  },
  {
   "src": "ACVP ECDSA-KeyGen-FIPS186-5",
   "tcId": 1,
   "mode": "testing candidates",
   "curve": "P-224",
   "d": "777f94a9292d0e72aa07e6a98fb2c38ed56fb5b2d48d2b5db8614502",
   "qx": "f84d2ece75a81b1219961f0c5a5da991bf64f571816f2350f230fb34",
   "qy": "3992af920d84e46becb6eb93e14523c6af3126a1aec1cef12e3aa4ff"
  },
  {
   "src": "CAVS KeyPair.rsp",
   "curve": "P-256",
   "d": "c9806898a0334916c860748880a541f093b579a9b1f32934d86c363c39800357",
   "qx": "d0720dc691aa80096ba32fed1cb97c2b620690d06de0317b8618d5ce65eb728f",
   "qy": "9681b517b1cda17d0d83d335d9c4a8a9a9b0b1b3c7106d8f3c72bc5093dc275f"
  },
  {
   "src": "ACVP ECDSA-KeyGen-FIPS186-5",
   "tcId": 7,
   "mode": "testing candidates",
   "curve": "P-256",
   "d": "bf049d775057f1199612f4bd6ab0af695a78fb488453e261ca3c277ad57e55db",
   "qx": "c6e20135457dc6f738e60cf6999d2416f31d7c12afea248434a547a9aa8a34b0",
   "qy": "6e5610c1cfc091ad58aa43f2b8a96d9561ee80594c5bc5dc4cb08be679aa45ff"
  },
  {
   "src": "CAVS KeyPair.rsp",
   "curve": "P-384",
   "d": "5394f7973ea868c52bf3ff8d8ceeb4db90a683653b12485d5f627c3ce5abd8978fc9673d14a71d925747931662493c37",
   "qx": "fd3c84e5689bed270e601b3d80f90d67a9ae451cce890f53e583229ad0e2ee645611fa9936dfa45306ec18066774aa24",
   "qy": "b83ca4126cfc4c4d1d18a4b6c21c7f699d5123dd9c24f66f833846eeb58296196b42ec06425db5b70a4b81b7fcf705a0"
  },
  {
   "src": "ACVP ECDSA-KeyGen-FIPS186-5",
   "tcId": 13,
   "mode": "testing candidates",
   "curve": "P-384",
   "d": "958baeccb7bb953aa92fce3a136a7b8a68001c4ed00cf7da6fcf83c0f552636d0063e7c8a511cc45534f1a7f0f7dd959",
   "qx": "19f324cf1cbc7d17c1284f1d887eecafb1e11f4c9709566b3094fe3152f63fdbc937018f93918b80a84d4a9ffb8e132c",
   "qy": "75a66d983f39cca1dddebb881969adeabe03b8c84b16e9e8b1de4b79ba3c41701145762eb90cc59c5f61f568d0601c08"
  },
  {
   "src": "CAVS KeyPair.rsp",
   "curve": "P-521",
   "d": "0184258ea667ab99d09d4363b3f51384fc0acd2f3b66258ef31203ed30363fcda7661b6a817daaf831415a1f21cb1cda3a74cc1865f2ef40f683c14174ea72803cff",
   "qx": "019ee818048f86ada6db866b7e49a9b535750c3673cb61bbfe5585c2df263860fe4d8aa8f7486aed5ea2a4d733e346eaefa87ac515c78b9a986ee861584926ce4860",
   "qy": "01b6809c89c0aa7fb057a32acbb9ab4d7b06ba39dba8833b9b54424add2956e95fe48b7fbf60c3df5172bf386f2505f1e1bb2893da3b96d4f5ae78f2544881a238f7"
  },
  {
   "src": "ACVP ECDSA-KeyGen-FIPS186-5",
   "tcId": 19,
   "mode": "testing candidates",
   "curve": "P-521",
   "d": "010908fcb3d3b1a132582f345d5f40f757e1365bb3bd063223acdf8f0d4be29c9d433715c566630bf67f129585d361367ddd05e304d83a381ece6317dea82144eeb6",
   "qx": "005c23f1bcb1d88ba116aacfa5ab8684a2b2a171e4409420993d98ffd152a5707faaae233cf1c00e589708b6de17c1de67a83d473499a8a2dbb11170411cfd94ea4e",
   "qy": "009feda1ce1e1952f917124d3cf6592deaaba8a08cf7b09f52d32d1cf14c5ee9a8da83fddf5cb65024f5e67b656d64c3b5d4d10df1c42a7fe3e81fff17589cf18b88"
  }
 ],
 "pkv": [
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-192",
   "qx": "a9ee43654ce0b400c40b8d4ad9a4a53cac9662c56f3c4bde",
   "qy": "f376f44a79c50ac3fdfd25ab684af439b5938bee11a63f21",
   "valid": true,
   "comment": "P (0 )"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-192",
   "qx": "472a620598e6715eff9cc022805d8cc8e8219f0e32042538",
   "qy": "1971ca86edb3471b2a16b9aae9de90f366f371b26385027e6",
   "valid": false,
   "comment": "F (1 - Q_x or Q_y out of range)"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-192",
   "qx": "c07ce28e4c846d7327f0554119ddb7e865fa1dd448ba2b40",
   "qy": "33aefa3177b99901d9ab6c12eb0749197420296ccb9d4e4a",
   "valid": false,
   "comment": "F (2 - Point not on curve)"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-224",
   "qx": "7fb5f1881188022d9b0a8b808834dfdc0c7388459350983e4aee1412",
   "qy": "661c3e17be24b038b1532d90675747482c238911093fb7035cc9b2cd",
   "valid": true,
   "comment": "P (0 )"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-224",
   "qx": "7a9369e2173bbf29589bf47e3ae0ccf47df6d2268c2292f906cc9261",
   "qy": "11afc53c7c1b085029f53b41fcd5a336bafb35b89d302f2bd04df44e6",
   "valid": false,
   "comment": "F (1 - Q_x or Q_y out of range)"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-224",
   "qx": "c01795a001b6b8a5b3db9acbdb55c2f97f4a50aa0a0cfed1d50a4c28",
   "qy": "b79dbe52a47a4640100cc939b435377f0bcb8db4ec52ecaadac5d919",
   "valid": false,
   "comment": "F (2 - Point not on curve)"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-256",
   "qx": "e0f7449c5588f24492c338f2bc8f7865f755b958d48edb0f2d0056e50c3fd5b7",
   "qy": "86d7e9255d0f4b6f44fa2cd6f8ba3c0aa828321d6d8cc430ca6284ce1d5b43a0",
   "valid": true,
   "comment": "P (0 )"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-256",
   "qx": "d17c446237d9df87266ba3a91ff27f45abfdcb77bfd83536e92903efb861a9a9",
   "qy": "1eabb6a349ce2cd447d777b6739c5fc066add2002d2029052c408d0701066231c",
   "valid": false,
   "comment": "F (1 - Q_x or Q_y out of range)"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-256",
   "qx": "f2d1c0dc0852c3d8a2a2500a23a44813ccce1ac4e58444175b440469ffc12273",
   "qy": "32bfe992831b305d8c37b9672df5d29fcb5c29b4a40534683e3ace23d24647dd",
   "valid": false,
   "comment": "F (2 - Point not on curve)"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-384",
   "qx": "6e9c7e92ee23713fabb05d0b50e088eb534fd1e2b257c03304cfa33598f88a07c7e31a13e24707a7057ca2919323058e",
   "qy": "a218a485e22eae08c3618cfd73befcfcd13c3f196c08df99d7f79ebffe9f127b896aa0cb36cfdf2fc4818b8cd766f185",
   "valid": true,
   "comment": "P (0 )"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-384",
   "qx": "11a14be72dd023667047c260dd1960dd16555289d9570001d53ea3e494c1c107800dc5b24dd4de8490a071658702a0962",
   "qy": "78d65f6975d10df838b96a16cba873b59c28f2c7d05654b8c8b78bd193694ae45d6c6e046a20b984c3467c72d49395fe",
   "valid": false,
   "comment": "F (1 - Q_x or Q_y out of range)"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-384",
   "qx": "e87cc868cdf196471d3fc78c324be2c4a0de8dbde182afea88baa51666f3cc9993eae5f1d60d4aec58894f0357273c48",
   "qy": "187219b0adc398c835791798053cc6a0bcc6e43228ac23101ee93dfce0e508be988a55fa495eb93b832064dc035e7720",
   "valid": false,
   "comment": "F (2 - Point not on curve)"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-521",
   "qx": "089a576c7b31c5848afb9eaeb92bb28ab2fc3bdd58338438051680e4cf0fede6caa63135fb7b6f5d7f2f0743f3d141fd1d67ef55f200d9cfb5fa7ef004929d1b938",
   "qy": "00868b8e12a141d97eb3b8c500eb211d6e70b661665edcadb7a7f989d174fd4ed5d148f6588769122b8ce8a784b3027c5777520a20a368983b01743c27e42c49039",
   "valid": true,
   "comment": "P (0 )"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-521",
   "qx": "0bec1326722dd943f750fda964cb485f31469095e5b4b5c4fa02041e2f443693ac36c09f371aea7d501881fc4e369f68e071bb14c5003b31dce504bd14338eb8104",
   "qy": "36cd502b0a4e91e1080a5b94886a819a823687693ce878408b59183730c69e5ab2d6e05ea5f3d32855cf8c7c20da59a28913025a1fa6835a3751ec6da69502f0547",
   "valid": false,
   "comment": "F (1 - Q_x or Q_y out of range)"
  },
  {
   "src": "CAVS PKV.rsp",
   "curve": "P-521",
   "qx": "165252970b786685babd0463f7314275c44ac1b558ab5a8e4bde60a441623b204982dcba2d3c0e7d379d5b637fd3edc0b0d2e0b7a33f7b36c03bb8bf3c6c5469ebe",
   "qy": "1300db0f0bc9b21ecff15eff4ed3bbe3dc1ac403dc96c89344d0030304da7ce57f1dc757af6816279464c61a0ab33645c3cd6583842cff0928081660b30775f594f",
   "valid": false,
   "comment": "F (2 - Point not on curve)"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 1,
   "curve": "P-224",
   "qx": "f91bae4b064040c9fdc9023eb55641ec02edd29f260f998d22039e50",
   "qy": "418b65902a00a304d24d753f5bdbdc7fa0bb14104b2f42a244a6a66f",
   "valid": false,
   "comment": "point not on curve"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 2,
   "curve": "P-224",
   "qx": "fa5c7b21ef2e5bc3280d6786ceb77511817530f8ed4febc152fb1a08",
   "qy": "01a125bc8811cd09efbf3f59cb789e7b6068ab636b92f8aacbf56903ca",
   "valid": false,
   "comment": "x or y out of range"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 3,
   "curve": "P-224",
   "qx": "34ddfe808d863e28da01bcbdaa68325d1e565bf8c816836efff48f0b",
   "qy": "158a9894836a740716e340181ac0429d4b287b18ed4592bac18d4db7",
   "valid": true,
   "comment": "none"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 4,
   "curve": "P-256",
   "qx": "7e01d79021449d59c97ce27dd7221110acfd86bfc11255058981ea2d20eca111",
   "qy": "eada8cdbae1835a6cb19f3d36f91c0b30394808dc3a9faa3333d9deb8e7e7ceb",
   "valid": true,
   "comment": "none"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 5,
   "curve": "P-256",
   "qx": "0153e4349d53d820d44172a0424d82d8a2570a60c9a81819c974fb79a49786b967",
   "qy": "5b8ba4edfc093eae4cbb88e09c88909b57066b9c35f4fd8a274c52522322ff52",
   "valid": false,
   "comment": "x or y out of range"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 6,
   "curve": "P-256",
   "qx": "618cf3688603ae38589c95aff36ed517ea4ad327a295bbdbbd88202ddba4b980",
   "qy": "cd5e352f7f7ed94515ea7eef8ac8191f792dd34f0bedf8034c29eb462e92ede3",
   "valid": false,
   "comment": "point not on curve"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 7,
   "curve": "P-384",
   "qx": "379ef74d6803ee0a6cf3303bcaf06ce7082632be5d59124d89c1f92aaee8c4ba2b8341e6dfa610f4688122d4c880eb82",
   "qy": "015e804d2f627c9690673314611e22987bb9183e166f6549620897698f3f1bd0426aa395192f77254ddf84ca00cd9dacae",
   "valid": false,
   "comment": "x or y out of range"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 8,
   "curve": "P-384",
   "qx": "fbd76d79f50928c6920fcff70bbb4a7788b24f7e2f36ec00cfbfd0affe16925a76b06a22f5d7b240d7b183ae1509a45b",
   "qy": "aca995c43f87d79d8b93bb1dab70ef76f4129873b3bec31a1a39cd66076fb7c18993cfb971ffd5fde29ec8251d098f72",
   "valid": true,
   "comment": "none"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 9,
   "curve": "P-384",
   "qx": "a5723b5e82cf703e93dc73a43a3a30d76858c3dce6cde2ce75b981f04cd3e9d08c2695581c3aca21e72c0490a10b71fe",
   "qy": "ef24bb74c339ed8c19b2d95bbfff39bb1542426df0b6bd68bf6a3890fa858abed668a8e4eb9e838bd535e5f75d564aa1",
   "valid": false,
   "comment": "point not on curve"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 10,
   "curve": "P-521",
   "qx": "002f7c2cb2aed780a5a38942972014c3d415844deca89236341cc044f545461d178270db628b47e9d70f9d77806ac66b4918cc063f719863fdbdaa16ae18dc1f1e0b",
   "qy": "002ca61a47cb546ae3e50b54c07d85e24ae6cfef4ed41bdc39dd8f5b89d768daa05a7af26e5e9b50b2320a8cd2fe89c6e7f16f46774e61981924041743433d1ea572",
   "valid": false,
   "comment": "point not on curve"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 11,
   "curve": "P-521",
   "qx": "035cb1098807803f8bfa7eb3a70e43097f6fecafc39c77a7e53029ba189f37c9f400034693198630db207b98dfdedba248fb02d88fc395a2cf5867bac50e86fe0eb2",
   "qy": "0138942ddc06b6482afd2593be835da7fbaa6fef7c8973bf45003348290761585f0e1bcce52dd729d04358c13ef46f3009e3a1d2a9715f141af5cabf7455c05f67e2",
   "valid": false,
   "comment": "x or y out of range"
  },
  {
   "src": "ACVP ECDSA-KeyVer-FIPS186-5",
   "tcId": 12,
   "curve": "P-521",
   "qx": "01e70c8b3b501b9537fd0a182ddf9a1244d5f6885e1ba03eb23e6a5b0b558be03cdf0b282f72beedcc9417cedea7cb6c6188e567105a5cb0fd89648fb6a55148b891",
   "qy": "00b1949040f8c34f8f201ee63c1a203ba01154fa02ef9a80ba1f8d2a6438fe73ead16b9a7867a8aab03559c80948a08b8b44e90df90b94ed8f0ce3062ec98be7290a",
   "valid": true,
   "comment": "none"
  }
 ],
 "cdh": [
  {
   "src": "CAVS KAS_ECC_CDH_PrimitiveTest.txt",
   "count": 0,
   "curve": "P-192",
   "d": "f17d3fea367b74d340851ca4270dcb24c271f445bed9d527",
   "qx": "b15053401f57285637ec324c1cd2139e3a67de3739234b37",
   "qy": "f269c158637482aad644cd692dd1d3ef2c8a7c49e389f7f6",
   "z": "803d8ab2e5b6e6fca715737c3a82f7ce3c783124f6d51cd0",
   "peer_x": "42ea6dd9969dd2a61fea1aac7f8e98edcc896c6e55857cc0",
   "peer_y": "dfbe5d7c61fac88b11811bde328e8a0d12bf01a9d204b523"
  },
  {
   "src": "CAVS KAS_ECC_CDH_PrimitiveTest.txt",
   "count": 0,
   "curve": "P-224",
   "d": "8346a60fc6f293ca5a0d2af68ba71d1dd389e5e40837942df3e43cbd",
   "qx": "8de2e26adf72c582d6568ef638c4fd59b18da171bdf501f1d929e048",
   "qy": "4a68a1c2b0fb22930d120555c1ece50ea98dea8407f71be36efac0de",
   "z": "7d96f9a3bd3c05cf5cc37feb8b9d5209d5c2597464dec3e9983743e8",
   "peer_x": "af33cd0629bc7e996320a3f40368f74de8704fa37b8fab69abaae280",
   "peer_y": "882092ccbba7930f419a8a4f9bb16978bbc3838729992559a6f2e2d7"
  },
  {
   "src": "CAVS KAS_ECC_CDH_PrimitiveTest.txt",
   "count": 0,
   "curve": "P-256",
   "d": "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
   "qx": "ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230",
   "qy": "28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
   "z": "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
   "peer_x": "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
   "peer_y": "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac"
  },
  {
   "src": "CAVS KAS_ECC_CDH_PrimitiveTest.txt",
   "count": 0,
   "curve": "P-384",
   "d": "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1",
   "qx": "9803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d34fe4a97bef60cff548355c015dbb3e5f",
   "qy": "ba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad54dd8b7d73a8abb06a3a3be47d650cc99",
   "z": "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1",
   "peer_x": "a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066",
   "peer_y": "ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a"
  },
  {
   "src": "CAVS KAS_ECC_CDH_PrimitiveTest.txt",
   "count": 0,
   "curve": "P-521",
   "d": "0000017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47",
   "qx": "000000602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240ba42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bbd945f550a5",
   "qy": "000001b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee5cdc88cd2d",
   "z": "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831",
   "peer_x": "000000685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d",
   "peer_y": "000001ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676"
  },
  {
   "src": "ACVP KAS-ECC-CDH-Component-Sp800-56Ar3",
   "tcId": 1,
   "curve": "P-192",
   "d": "0070eb63a4cf125a846b8d085d966378979fec75ea1969f9",
   "qx": "ad56863995294caac896e584ddf1d0f16f5bf6fcc8420033",
   "qy": "afb29b2ef8ef854c52711b677698dcc2981b306a056ef735",
   "z": "4f552a55898fb2c5a6eb1bb3bca7a13add5338edde6f055a",
   "peer_x": "60f79a69a744e0439709f81b9d93d70f87d11b8575aced85",
   "peer_y": "ba4c48713240f662970c18b56b5867e0fcb1426e0993f015",
   "peer_d": "706fff2ce0227d9b01be70c6ce48a61bf73a41956948a27b"
  }
 ],
 "siggen": [
  {
   "src": "CAVS SigGen.txt",
   "curve": "P-224",
   "hash": "SHA2-256",
   "msg": "2b49de971bb0f705a3fb5914eb7638d72884a6c3550667dbfdf301adf26bde02f387fd426a31be6c9ff8bfe8690c8113c88576427f1466508458349fc86036afcfb66448b947707e791e71f558b2bf4e7e7507773aaf4e9af51eda95cbce0a0f752b216f8a54a045d47801ff410ee411a1b66a516f278327df2462fb5619470e",
   "d": "888fc992893bdd8aa02c80768832605d020b81ae0b25474154ec89aa",
   "qx": "4c741e4d20103670b7161ae72271082155838418084335338ac38fa4",
   "qy": "db7919151ac28587b72bad7ab180ec8e95ab9e2c8d81d9b9d7e2e383",
   "k": "06f7a56007825433c4c61153df1a135eee2f38ec687b492ed40d9c90",
   "r": "0909c9b9cae8d2790e29db6afdb45c04f5b072c4c20410c7dc9b6772",
   "s": "298f4fcae1fe271da1e0345d11d07a1fca43f58af4c113b909eedea0"
  },
  {
   "src": "CAVS SigGen.txt",
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8",
   "d": "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464",
   "qx": "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83",
   "qy": "ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9",
   "k": "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de",
   "r": "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac",
   "s": "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903"
  },
  {
   "src": "CAVS SigGen.txt",
   "curve": "P-384",
   "hash": "SHA2-256",
   "msg": "663b12ebf44b7ed3872b385477381f4b11adeb0aec9e0e2478776313d536376dc8fd5f3c715bb6ddf32c01ee1d6f8b731785732c0d8441df636d8145577e7b3138e43c32a61bc1242e0e73d62d624cdc924856076bdbbf1ec04ad4420732ef0c53d42479a08235fcfc4db4d869c4eb2828c73928cdc3e3758362d1b770809997",
   "d": "c602bc74a34592c311a6569661e0832c84f7207274676cc42a89f058162630184b52f0d99b855a7783c987476d7f9e6b",
   "qx": "0400193b21f07cd059826e9453d3e96dd145041c97d49ff6b7047f86bb0b0439e909274cb9c282bfab88674c0765bc75",
   "qy": "f70d89c52acbc70468d2c5ae75c76d7f69b76af62dcf95e99eba5dd11adf8f42ec9a425b0c5ec98e2f234a926b82a147",
   "k": "c10b5c25c4683d0b7827d0d88697cdc0932496b5299b798c0dd1e7af6cc757ccb30fcd3d36ead4a804877e24f3a32443",
   "r": "b11db00cdaf53286d4483f38cd02785948477ed7ebc2ad609054551da0ab0359978c61851788aa2ec3267946d440e878",
   "s": "16007873c5b0604ce68112a8fee973e8e2b6e3319c683a762ff5065a076512d7c98b27e74b7887671048ac027df8cbf2"
  },
  {
   "src": "CAVS SigGen.txt",
   "curve": "P-521",
   "hash": "SHA2-256",
   "msg": "8ab8176b16278db54f84328ae0b75ef8f0cd18afdf40c04ad0927ed0f6d9e47470396c8e87cde7a9be2ffbfe6c9658c88b7de4d582111119c433b2e4a504493f0a1166e3a3ea0d7b93358f4a297d63f65a5e752f94e2ee7f49ebcc742fa3eb03a617d00c574245b77a20033854d82964b2949e2247637239ab00baf4d170d97c",
   "d": "1e8c05996b85e6f3f875712a09c1b40672b5e7a78d5852de01585c5fb990bf3812c3245534a714389ae9014d677a449efd658254e610da8e6cad33414b9d33e0d7a",
   "qx": "07d042ca19408524e68b981f1419351e3b84736c77fe58fee7d11317df2e850d960c7dd10d10ba714c8a609d163502b79d682e8bbecd4f52591d2748533e45a867a",
   "qy": "197ac6416111ccf987d290459ebc8ad9ec56e49059c992155539a36a626631f4a2d89164b985154f2dddc0281ee5b5178271f3a76a0914c3fcd1f97be8e8376efb3",
   "k": "0dc8daaacddb8fd2ff5c34a5ce183a42261ad3c64dbfc095e58924364dc47ea1c05e2599aae917c2c95f47d6bb37da008af9f55730ddbe4d8ded24f9e8daa46db6a",
   "r": "09dd1f2a716843eedec7a6645ac834d4336e7b18e35701f06cae9d6b290d41491424735f3b57e829ad5de055eaeef1778f051c1ee152bf2131a081e53df2a567a8a",
   "s": "02148e8428d70a72bc9fa986c38c2c97deda0420f222f9dc99d32c0acba699dc7ba0a2b79ce5999ff61bd0b233c744a893bc105bca5c235423e531612da65d72e62"
  },
  {
   "src": "CAVS SigGen.txt",
   "curve": "P-256",
   "hash": "SHA2-512",
   "msg": "6c8572b6a3a4a9e8e03dbeed99334d41661b8a8417074f335ab1845f6cc852adb8c01d9820fcf8e10699cc827a8fbdca2cbd46cc66e4e6b7ba41ec3efa733587e4a30ec552cd8ddab8163e148e50f4d090782897f3ddac84a41e1fcfe8c56b6152c0097b0d634b41011471ffd004f43eb4aafc038197ec6bae2b4470e869bded",
   "d": "9dd0d3a3d514c2a8adb162b81e3adfba3299309f7d2018f607bdb15b1a25f499",
   "qx": "6b738de3398b6ac57b9591f9d7985dd4f32137ad3460dcf8970c1390cb9eaf8d",
   "qy": "83bc61e26d2bbbd3cf2d2ab445a2bc4ab5dde41f4a13078fd1d3cc36ab596d57",
   "k": "9106192170ccb3c64684d48287bb81bbed51b40d503462c900e5c7aae43e380a",
   "r": "275fa760878b4dc05e9d157fedfd8e9b1c9c861222a712748cb4b7754c043fb1",
   "s": "699d906bb8435a05345af3b37e3b357786939e94caae257852f0503adb1e0f7e"
  },
  {
   "src": "ACVP ECDSA-SigGen-FIPS186-5",
   "tcId": 311,
   "curve": "P-384",
   "hash": "SHA3-256",
   "msg": "5bb54782864367762e21c1c128cbfc5cac400aa52c94cd6e207d48048038aa38ffcd6cb8821134a09304be8afc0e116c53e01dd1ff670ac76dc994bae4fa7bedacbed03a37503cc912090c365c3b38b5372cfffc2556f7cf07a408bfdb46aaa03b1bc534c4499853dd4328f637126b768970008e9bb70871f39484d0a3190d3b",
   "d": "698649ea5841d2f66cfe87ebf1ddc9b0e0e6fd56abbbc4546bcd03da22117a35d846fa0609e3ca8e3cf9a60a7bad5e14",
   "qx": "7ad192837f00e082124c9c6614903abb306820fdbdde0c1a2333720663ca094742baf22154fa192f9b1f48923cdb54c4",
   "qy": "48f309dcc8633921de5c466bb9f717f7301440fd41601f7f16770aeecbc9980728c42939ba833f1abac172a76f70c8f8",
   "k": "aa35aa00ca72d19b0fa1319439b5c9dbee635892f645394bb941745cbd58134a7a4f95767b4033946c59f676a0e585cd",
   "r": "1df77dc9d1ff0a746a718691eafeef431480807f393425968abfbacde3f28d66360b39e18cb95d373537efe158f9bef9",
   "s": "4f6e64d7260acb8f541a0e354662fbe21ccf0896488bfb2dfb4106533aa931857ddbf4adce8af8f764cfbc8aa0776c83"
  }
 ],
 "det": [
  {
   "src": "ACVP DetECDSA-SigGen-FIPS186-5",
   "tcId": 1,
   "curve": "P-224",
   "hash": "SHA2-224",
   "msg": "ccbb95cd94304ab252b49cc6b97b1e89f2ff55339e04ad02bc65ad5bd462c7f0d38b0422768a877cc6bb2e2486147841adf83ae50c7d89d1dd0b581cad106d81d922db31bdcb822de561b027d58b0d15825a6c41e3a012aebdc2edf8b86cde77e203b09429fa9c1a3a1e851f2c4693cb0411898b88508489b7042c5ae5bc4c6b",
   "d": "e716797f530ac83e6aad61a0119b99652b3560f30c39811db4d60613",
   "qx": "19c6b1e1bd9ae055161d2bc6ad76688fbc4794347ee33a9cada97ada",
   "qy": "fe3067a8da2e101d6d02aac0c5aa1ed686403c4e140325c8f2a3a35e",
   "k": "0949abfb2b5c8cbdfd1cf7b05c30ec741cf756cb20e946843e8be175",
   "r": "2540010a4640dfe32d8a9b8d8523918e6fb1cbca6e994ebe5aaec158",
   "s": "09a9668aa26fc92bac5611791be8cbc3aa592681284a1e84a935fb5e"
  },
  {
   "src": "ACVP DetECDSA-SigGen-FIPS186-5",
   "tcId": 111,
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "0cce12ccf2f17bda8c1192f4557a8410fd65fa8dca174bb57c9b2a1e29597b6a44ad055d23aba4928b72c67a3e0093bc3686f68de6cee2122c35779684074c538cd1f5e836ba96f4f3e05cac2977ebf332ae2576ac083c3a963c18ba9f9872e71ef0f229f4c66a5cfca3952208784e44ef172ff7ee6b437efbe9afa116939789",
   "d": "f69a77b56caf234368df0d69f96cf04f435f967ff39e28371c6fe7a8146b865d",
   "qx": "0106fffbaa17060d23c9b90e84ecbbf369f853afa0ccf82a5c506ec443e6fb4b",
   "qy": "948bd0f661ef839d65180012e85feef4a8e181dc732793ae08a8b4d2c7ff0fe7",
   "k": "6076ca39385f822aa0f528f418b1aa74a929590baa1b79a2a68855d033a9116e",
   "r": "46aeb40043eaf16df463894fc8d3161837930afbd621519f51d02d5a28012df6",
   "s": "6255be755fcf2e6dd4b7187158dc6253dde36e81dc114e09e6f6ed778acb2128"
  },
  {
   "src": "ACVP DetECDSA-SigGen-FIPS186-5",
   "tcId": 281,
   "curve": "P-384",
   "hash": "SHA3-384",
   "msg": "290002f3c829a66d6aad1825340334742dd3a751bca7dbd0e914ad44c722214e7bdf8e93fd094af25e5cd06e9abda3024f08b125b3a4edb894fffd121b04ca3a1cb2e3d706837ddef95af5a95f70d0e627c949915c3d015fb795177be8434c54062fdf6aa4cbcb989a0d63b403a44dab7be5566859d069fb1d88a3d21b17ec5c",
   "d": "62df9e92f5acab77235ad4ab3796f37bf4783ad0d5c0c247adeb3541548abb5214fb0b878fcc770136a3e21f2d29da98",
   "qx": "4ec3f41d24314f59fadcc28c905cfb1dbb7d470233c20edf6c9e640f8314ea92fe89e775971eb3642810629ec637d1fa",
   "qy": "3c5d0ffe718837bf9e3cff69d3f8246eb57f4cb176f64261bb6edfb7f8377bc6954020cb0dffa13e84edaee7427bde27",
   "k": "2a5b31feace4120968b3188751df6066a4d8f1b36794c8a4d35a5afbfb141b19348b0f2b5a2d5736c14e595cea8ac3bd",
   "r": "c011b1a4da2b0013c05c009fcf8311929454e0364a88b0156e1d7411c27d3acd08cd8f15996bedf051993ee37e8e2f0a",
   "s": "841f50fb417a3247dcc370a23f36bc30ee1e2d9e514be9fd29df333c9ec2517d93b03de2cb96e4b13cb696ad1154309e"
  },
  {
   "src": "ACVP DetECDSA-SigGen-FIPS186-5",
   "tcId": 331,
   "curve": "P-521",
   "hash": "SHA2-512",
   "msg": "b76d44595bad41c52572c91143fabbdc05e6f8a948f65afca14882349576459b0f9818dffb2dd924994ac59d2b042d9ccc182438e42cf1cf4d408735d1da10eb0ff516719687f4291eddd53ac6a73c287d540fa5625590250aae67ef57f8016f848c45672cabf0dcbe868d7551fc7eb42fde2dd34a9577555c431d8663b2b0ac",
   "d": "01f3eb5b7b1fd5b252b5abf208c52c344dba19607bc41aff7898144a7bb65a23174e9edd373d22325d16cb4aa48841d71123d9f34bbb8720d123999d5133c81eff50",
   "qx": "01827fabd414050b4571dca371db6d12443100c73a68683b68c966ce99cfb110d4b030bfbb336b5e5c504111311db14278b2b33a55e2675abeda1dbbc148705c8a8c",
   "qy": "01843492bcc6802727f137f49a8ca268f5724a490da01878b49e516db192e31df28c5334f349b13fee9786de4e6d71fc883596ccde7af9af8c3d26ec1cf5ecf0a493",
   "k": "0124182ad1c7328ce41127ae5a6439cd2ec2f2b13c155b5f70af236edbec8ad8086c4ae2271838cbca55ebc66816b40a9e36685d08184419b9a8c375137f5de11280",
   "r": "00cc98db506b8f5939cb99c2d270d5a1ff7acf4aad200860ad8918a707d229f2a8718a5b2b19d3b22f0ceec0321e8bee7da4bca175675f6a09f391304ab507cc7ca8",
   "s": "00ce2ca3f1bd1537e8279761c64c2ed47bcb57b9a11a47aceb1da719bd21496fd1d8014c83425e42a5f6ff5c89af0393cb1fc4f471ec05ccd595a97898d009c3201f"
  },
  {
   "src": "RFC 6979 A.2.5",
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "73616d706c65",
   "text": "sample",
   "d": "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
   "qx": "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
   "qy": "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
   "k": "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
   "r": "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
   "s": "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
  },
  {
   "src": "RFC 6979 A.2.5",
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "74657374",
   "text": "test",
   "d": "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
   "qx": "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
   "qy": "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
   "k": "d16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0",
   "r": "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
   "s": "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083"
  }
 ],
 "sigver": [
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-192",
   "hash": "SHA2-256",
   "msg": "76f44a2dbb96d50840a37bcdb23f0d56e159bf4663c22c116963ada3df2431450019aa8ab922612dbe80f2d35b5096de41273f648edf09929a698c7e9028565afd16bd976e76a5a96360bf89a0908ce379c9f69c508c6cf6811e1cf5946e09a0d2d5a92387bd5a95aea5e1229b7810b5757bf88381ad2d3075e85cd47d28eec4",
   "qx": "b870597b4b8dc8fc07ed59b6f079e87936d56d0326c17249",
   "qy": "e54c404920cd530f0680d8aa2a4fb70b5f8605e6ebbf2751",
   "r": "b53dc1abd4f65d5e0506fa146bee65ecb6cd5353830b67ea",
   "s": "aa44232f2fa6613f85fda824ded69e4137cdf5688c6b3ba9",
   "valid": true,
   "comment": "P (0 )"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-192",
   "hash": "SHA2-256",
   "msg": "b15b9c059c4cfb771e717d72bb1d79578fe58296bf20497105ca099feaccbe0c1283db5d78799f3db39dcd3591c8ffbaf096c84a864d10d9bed843b479a433893de945bc7b4b6f15a28e86f83875a9a223e785af3467d8efda2342a916d183bf30ee33fc4cc688b74a196ee0e318990fc09afc3471a131b240d128c6a28acfe9",
   "qx": "001e75261da06eba07f3ee911276b4b6e25ee37abf54fa41",
   "qy": "5da176ff885ca3345508bc4c917128b2c87f6ab182113505",
   "r": "e5e6bb6133dc7dc8926d3705cbced15d5820a29e7ac2de8d",
   "s": "46a6e3818a7286818250cea5a023be5b401b1026ea316843",
   "valid": false,
   "comment": "F (4 - Q changed)"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-224",
   "hash": "SHA2-256",
   "msg": "c8b10d4e5a1f5f6a3c0f4c15dc2dc84f0f36b219076e27bae6d26e3b4a414473186472ec793527bb8704f69285b96eaf9473085060603584bca5f1fce4e909203dcf0eb50cf05adaf89804c420e91d1226d9449bebf2e9b3ea7cb23bd094a0bb04b579789c800f58831489d25179db015d751e470c0b21c7ae03fc0e4a949970",
   "qx": "34c5ff3de565b85bfdd9f0a8b3fb0d46f924c57b276bcc830a1ed580",
   "qy": "609d22200ef38b410da77f7a8ff2f58448188042978fd9ae1b2b4477",
   "r": "f0138024fe0516738f3bd0e0fec10defaca8c3b89c161a77489cf2b7",
   "s": "4ae0934266d9e3d64c2a12f546b132ba0f33ef50abc90e7ef5974805",
   "valid": true,
   "comment": "P (0 )"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-224",
   "hash": "SHA2-256",
   "msg": "2b0ae1a73f7169ff23d1b8c4804484434f06ca2d6b9e65630bd8c6692b85bcf4556b880bb574ab4f538410e9a535b2054896ee817b8c8412e82cb785444ad042725d01b9ce7dec1a821d9bf12d60538ac93a1b6e1251b37e62ecc15c92b7823cf08f0ca5665fcd84cb2c26509cfec97103af02f5a34a5ebe7ab43297af3ca273",
   "qx": "8856fb8b81a4eacd971a954560018f33cbb71cc1fc243d03f63cabcb",
   "qy": "28afa26baf31b4d89de1dadd2289006f836f23a11383817ec7e4e799",
   "r": "efccef331805e71bbf876cbbc2342a6bc4508aea7c691029c8396aef",
   "s": "bed544d09e28dbf01a30b2cfb61b98ad6201a9818f22b4f543f3e7f5",
   "valid": false,
   "comment": "F (4 - Q changed)"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45fd75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce470a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3",
   "qx": "e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c",
   "qy": "970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927",
   "r": "bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f",
   "s": "17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c",
   "valid": true,
   "comment": "P (0 )"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "1669bfb657fdc62c3ddd63269787fc1c969f1850fb04c933dda063ef74a56ce13e3a649700820f0061efabf849a85d474326c8a541d99830eea8131eaea584f22d88c353965dabcdc4bf6b55949fd529507dfb803ab6b480cd73ca0ba00ca19c438849e2cea262a1c57d8f81cd257fb58e19dec7904da97d8386e87b84948169",
   "qx": "69b7667056e1e11d6caf6e45643f8b21e7a4bebda463c7fdbc13bc98efbd0214",
   "qy": "d3f9b12eb46c7c6fda0da3fc85bc1fd831557f9abc902a3be3cb3e8be7d1aa2f",
   "r": "288f7a1cd391842cce21f00e6f15471c04dc182fe4b14d92dc18910879799790",
   "s": "247b3c4e89a3bcadfea73c7bfd361def43715fa382b8c3edf4ae15d6e55e9979",
   "valid": false,
   "comment": "F (1 - Message changed)"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "069a6e6b93dfee6df6ef6997cd80dd2182c36653cef10c655d524585655462d683877f95ecc6d6c81623d8fac4e900ed0019964094e7de91f1481989ae1873004565789cbf5dc56c62aedc63f62f3b894c9c6f7788c8ecaadc9bd0e81ad91b2b3569ea12260e93924fdddd3972af5273198f5efda0746219475017557616170e",
   "qx": "5cf02a00d205bdfee2016f7421807fc38ae69e6b7ccd064ee689fc1a94a9f7d2",
   "qy": "ec530ce3cc5c9d1af463f264d685afe2b4db4b5828d7e61b748930f3ce622a85",
   "r": "dc23d130c6117fb5751201455e99f36f59aba1a6a21cf2d0e7481a97451d6693",
   "s": "d6ce7708c18dbf35d4f8aa7240922dc6823f2e7058cbc1484fcad1599db5018c",
   "valid": false,
   "comment": "F (2 - R changed)"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d9aa60326d88cde1a23c7745351392ca2288d632c264f197d05cd424a30336c19fd09bb229654f0222fcb881a4b35c290a093ac159ce13409111ff0358411133c24f5b8e2090d6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0",
   "qx": "87f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad41555",
   "qy": "e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205e9",
   "r": "d19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0",
   "s": "a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6",
   "valid": false,
   "comment": "F (3 - S changed)"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "df04a346cf4d0e331a6db78cca2d456d31b0a000aa51441defdb97bbeb20b94d8d746429a393ba88840d661615e07def615a342abedfa4ce912e562af714959896858af817317a840dcff85a057bb91a3c2bf90105500362754a6dd321cdd86128cfc5f04667b57aa78c112411e42da304f1012d48cd6a7052d7de44ebcc01de",
   "qx": "2ddfd145767883ffbb0ac003ab4a44346d08fa2570b3120dcce94562422244cb",
   "qy": "5f70c7d11ac2b7a435ccfbbae02c3df1ea6b532cc0e9db74f93fffca7c6f9a64",
   "r": "9913111cff6f20c5bf453a99cd2c2019a4e749a49724a08774d14e4c113edda8",
   "s": "9467cd4cd21ecb56b0cab0a9a453b43386845459127a952421f5c6382866c5cc",
   "valid": false,
   "comment": "F (4 - Q changed)"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-384",
   "hash": "SHA2-256",
   "msg": "862cf14c65ff85f4fdd8a39302056355c89c6ea1789c056262b077dab33abbfda0070fce188c6330de84dfc512744e9fa0f7b03ce0c14858db1952750d7bbe6bd9c8726c0eae61e6cf2877c655b1f0e0ce825430a9796e7420e5c174eab7a50459e291510bc515141738900d390217c5a522e4bde547e57287d8139dc916504e",
   "qx": "86ac12dd0a7fe5b81fdae86b12435d316ef9392a3f50b307ab65d9c6079dd0d2d819dc09e22861459c2ed99fbab66fae",
   "qy": "ac8444077aaed6d6ccacbe67a4caacee0b5a094a3575ca12ea4b4774c030fe1c870c9249023f5dc4d9ad6e333668cc38",
   "r": "798065f1d1cbd3a1897794f4a025ed47565df773843f4fa74c85fe4d30e3a394783ec5723b530fc5f57906f946ce15e8",
   "s": "b57166044c57c7d9582066805b5885abc06e0bfc02433850c2b74973205ca357a2da94a65172086f5a1580baa697400b",
   "valid": true,
   "comment": "P (0 )"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-384",
   "hash": "SHA2-256",
   "msg": "a444216c9072caf87fa57c1f04aff9cb83dc2ede9968bda41c9d918825e526c2397cb7d771a7e120582424bbea8ecd56a69bb468cd61437f5a65f04953f9d4018c599afd9edbd4d26e861f86829b9496f829f2b601df73e931fff96559e091417c0d8b8c8129443f7efb985d286c7167b66d2b4d5903583a928db3ed6a883117",
   "qx": "97c3f446803a61a7014f61cb7f8b3f36486c7ea96d90ee1767f5c7e1d896dd5114255abb36c74be218c1f0a4e7ebba3d",
   "qy": "553ed1fed72c62851e042f0171454f120029adba4ee26855ab881d9470355f1947aa1d2e806a7ff2583660fedbd037a0",
   "r": "7b06d6c2b63f1cc3bfdaa897d07dc15a83bdf35d979f70c34578332b3f4920422bb24867c51bde10831324df424e04ec",
   "s": "4bef715161f400dc98d4b63bd13ff4ad4a6c981ead44bfc662fe9bca4b56cd790698e4deddf9a4bd69327f26bfe801e6",
   "valid": false,
   "comment": "F (4 - Q changed)"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-521",
   "hash": "SHA2-256",
   "msg": "961c9451bbb298e17f503680099244d969a0ff3d0ce6cf15b5bcc73d6edc3e8c8535a18531d885664612cad97da174f1daee6aad95220f6e2fd8c734c57747e46db21e169a03dd673df07aff30848e8370c0960d732e74f9b1d8b53847b69d2cad80f346b50e89d7993cb758fc218668c771422f804d3c9162da98cb30821912",
   "qx": "0397714abcc503eaa0c18abd1fd26586d28ec1b1035d37ac710f2823911ec9afa429b41ea89cec13d5bcae9d6d7147794407e409f3b267cf4dd27e8c77e7ccf4d36",
   "qy": "0a3a4b749d19b84708e42b59e9faa5a99ac0f0a01121655fab87785fca38c8cd4277c8c2c9a0024ff608c3cce954596315dfe0e3b133aeab08bb5389eb2a4f1fb42",
   "r": "19da96a866db12948e0aec7231f797061f345739d439bdaaba63e4d03e0bb52c3fea2fb593347d983f24a3afa6a77f476e6bb49a5de843b4c4755cddce97b8b909e",
   "s": "01bb442f428b2ca445a75ad88ed49d965d6659d748d02cebf78faa1ecc187b606f284d11d47791d585dc371c2d91848a55ca7b092f06d561efcf64e0de0814e1db4",
   "valid": true,
   "comment": "P (0 )"
  },
  {
   "src": "CAVS SigVer.rsp",
   "curve": "P-521",
   "hash": "SHA2-256",
   "msg": "93e6fa311b9cf278babcd49a6739d312e5f12e05bc9dfee9bb37ccfb2f9ce57d2a3c0336674e094834a9fb80143c3c8ca82b34949596ad17ae6fc7592d1d93f143e7e7c842e17a7d230ace2d2be15c757c37ba0b1f34810c6e51786af718136db22c1f8336540cae5e2fc762ca43cd94c4babb1b11f8fd93a2ac9525324bab88",
   "qx": "15bd9bf7a35cc60147b32b64e0e4e54bf9ac2173cc6784b3d4ebd076aa5d45c1e3d0846b20b61d6342341a8801a2f63028c991831318245c2fe31f8acde6bf2003e",
   "qy": "1afb67c9c700ed332b47a2d148e6ddd3571e138f02a81c3cfe6d4dee0f512d92e76574fe5797c5566c05b3239fabb212c735615e719e718fb40fa6783c964357f72",
   "r": "1a341d0e8906239faace79554b90d1445bd28f703d7c7cc8eb163337ad3d4bfb3725cb06e618991491534d399866df5c5bdef897c889947b21148d89c657e64124d",
   "s": "05c5b728837d44b7b6935efb2b721b4f45c1675d803d87f70158e451434176d9682034c9b356b5f9181e07599bdcb55e5bc808fdd36fef9c19ddb6342c975262024",
   "valid": false,
   "comment": "F (1 - Message changed)"
  },
  {
   "src": "ACVP ECDSA-SigVer-FIPS186-5",
   "tcId": 54,
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "cf9838b2e0e94584cfb7edb86af4ea09458ffdd81c024e54fe7899babb52977723fc7f04118528a7fb830af205786168458d85bacc0df74f9d493809904107d9aaf230cc5c2f97ca49c9e51451eb9d368129fbc32c416a53c9dc33a8507170e1975cdea2aee3924051b2fb3660c02bd1f1887a01229f368895dfb0ef6fe87d44",
   "qx": "93167a1567dfa211c10829919113eab92591ce6d01ca9d75283a66206cd5ca0d",
   "qy": "d647da83c25592c03332dc2a057e1ef61eaed77fa413275beee034512f31c97d",
   "r": "8f3c091eec05deeca81cd5e42aa7365736011c41fdda8b4c9973962645ae59bf",
   "s": "597b95068c79b5c6ef763eea19836a3a6478101b3fea1c0811845f7366387d65",
   "valid": true,
   "comment": "none"
  },
  {
   "src": "ACVP ECDSA-SigVer-FIPS186-5",
   "tcId": 51,
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "6146082a6d1e3895562d085cfca2810784d74c66b78335b825fccc13b59c865a6f654c72c3ceed5f2f052adf317ccdcc60dc75410fa61cadb9cbf95b7d689a810d39d8c96fe1e4f9195c0cd431ee831e584a7b4f1d9394482fbc54a7c807bb3cd95bceb59a2517dc2c92d5a3ee4c690e72c16339a473dcdbef73ef86be108cee",
   "qx": "bfa50b874ad5c75d6d09fd77ba123aaf8cb78d42e4f07116a85b9496a70f2320",
   "qy": "6ca842d14b537beac3b067cba884d56b56d880a6b946d26ceb71e97d71891aae",
   "r": "eafb309bb59e5b9d7d4e596b39f5211148bd6d9e2e81fdfbb41ca5c11a0db945",
   "s": "0c9cda7ec5bdeb469309af85e7b1106a4e57b3b4dd145ee9654a5c2fb2609eb3",
   "valid": false,
   "comment": "modify message"
  },
  {
   "src": "ACVP ECDSA-SigVer-FIPS186-5",
   "tcId": 50,
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "50d310baf99931f07eb492a22b1056b6965a656143ae8c24463c5b85a17255f640f05b81e01b799ba5b507997c70c8ea10325fbfcb23caac55f1d57235d6a6864d0e12f3fb67e8f61930850e5ae1151caf905b47f9a30553e457e9c91192cb2ac4617b928c787b6c7a5862d076ae033ebae60500006ae8c9a19f6c76d3624e7b",
   "qx": "5fd0e5cd5ed27067f2746ca0ab0f82aeb964446d457abcedd99322d536f8b6cf",
   "qy": "744788f88666ee9dd47b7d322dc56960cbd128429d93e919d8cd83b56618e5af",
   "r": "79fc74d87c63917d48d27f0111278ece484189281d0742f1d4c20be66af3170d",
   "s": "9aa823f15209eea6523e92ba6d851d53f7418d7b3520d86e52f25c88616e0488",
   "valid": false,
   "comment": "modify r"
  },
  {
   "src": "ACVP ECDSA-SigVer-FIPS186-5",
   "tcId": 53,
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "7a4b054d3f491f7db094ed93f86349c032ffe4779a92858cb185274287a1da0fb90875e8f4c1d6bf10aaf82082b2a548525f01b4cec16cef33f90f16093027a8b46f469eac9b2034b4b3380681b985c09c3172af4a8e7effa6218314f68a7349b17ad908734179c40f4c434dc11310b70e05a17c79d8228d78b9df25602f80f7",
   "qx": "a1f394019a369573c530600b7b3e859b73498db0ae9421137d49b5e67a17dc20",
   "qy": "22dd016d7b5bdff54a75bd9ac059aa1cf2e7636c4470800b287fe1eec8c106ea",
   "r": "594e223c438dad6e92fb5c9f403b6eef5ddaf9ce33d38fc800ff9f5c373c4eec",
   "s": "f40ea03cf25863cc69704dc858860b5e6c82a903c581d15010d9f6df33bd7263",
   "valid": false,
   "comment": "modify s"
  },
  {
   "src": "ACVP ECDSA-SigVer-FIPS186-5",
   "tcId": 55,
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "9d9352f6951968f02fcb77428174fa9b0b5c07a03cdfc01f46a333a228f68bfefd13dc80878ea2b935a4f4d6136653369d8a0d7d7703857914d98538d39e9523a18aa9d5ab972618d97ea3c259d4f8cbdc0641bd1a2d89a7e98718ada77c38d9674dab0c32303dde4828aa01aa6f012d872cb50b78fc714d96db05e8766f4184",
   "qx": "9e2b110e46437b1c6dec75fe16c6f9d611e33ba8b410a62fadfd83236d800991",
   "qy": "9ad4ab38432878f08a322e020e57ab904eb142040425268da90136bbe0139cca",
   "r": "48318ec59fbc5982e67031f87816bbbd65365d7b9e6ca9993ffb87dfdca31859",
   "s": "cbf1ca8561d0ed5c70d1276dbab2c4b6b7c2b01db6eabf7c40b5fb60fdf24a33",
   "valid": false,
   "comment": "modify key"
  },
  {
   "src": "ACVP ECDSA-SigVer-FIPS186-5",
   "tcId": 52,
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "03d98f6e1795a52eb55b54bafe1e453e7963d60d5347d3685198d199b6c3aab998c8f2f2d6c393815b369c06644ab6662c742ad79bec91f5cc6632ab1601645261b804b48472b2a33b72f9e53d9fce8343e79b1b150c729d7c77658967cef3541bd9a633cdfa4ec88f40e30e890e6d31ef99790956802c08ecd2aed23a41e31e",
   "qx": "17fd2cfc845798c42b3831232284df02ff0b209bb6eeaebd14cd9e0854e1e77d",
   "qy": "1d89dfc6be883a778c5bd5bef58bbe6949d8a40715d4c26dc82b3b8628aa9f06",
   "r": "0000000000000000000000000000000000000000000000000000000000000000",
   "s": "d4a7dd178f0ae5b8bb0e84f97c36ed113fd62da6a1744c3aeb6f46bfbc41c96e",
   "valid": false,
   "comment": "zero r"
  },
  {
   "src": "ACVP ECDSA-SigVer-FIPS186-5",
   "tcId": 56,
   "curve": "P-256",
   "hash": "SHA2-256",
   "msg": "0c1a0ef8fc8674ee683ec5aebad6563adc2559d698443f1897cbaa706ec80f04d790049edaee136d8f40c44b770bc9ca58d452dfb30c5611b9e9e70ff3032f2d893db984a1af0f2e040ce2ef55f8027edb9e739ef599419115a54eea1d1879722f1a44798aa469cc724878f49d6cb707d304286d765e47cdb644290a7c82767d",
   "qx": "3f4a10ae572f44f3b8408b3e68bd4288ffe2e812fd338587902af603b50a1fd9",
   "qy": "8a7d59774cdd50a8a9d50af1d0c2b721bc732e6ea5fcab99a7c95cb6a5e8bf20",
   "r": "fcfed67ecaef336448c4d374ebbfa3adbb3fdebab632bbd8eb455eb69208ee0a",
   "s": "0000000000000000000000000000000000000000000000000000000000000000",
   "valid": false,
   "comment": "zero s"
  },
  {
   "src": "ACVP ECDSA-SigVer-FIPS186-5",
   "tcId": 176,
   "curve": "P-521",
   "hash": "SHA3-512",
   "msg": "012ab139c9bc3a03a87b5d5d2cec70a2ddb016618282789b67336bbbd19f5f397c1f77d4d60d908992d91e059f6f0c146075b516dafd2079fe88465946cddcc781fccd3801d01792c7f05ea2fb7723ae8db189ae67e0364a5779a4eea0577af17b1a7cc31d9ac6e9241cf7104778f2a376e7b1c1be58e1fec0ebd3c8b93bafbe",
   "qx": "015224b2e09880dfba91107e7dea063317c1223833673c1d9b2686f24ab51e1d795d53b58f86b702d35bc8eb639a365c06fdad741eaea8e1f16473693b360e0d983d",
   "qy": "00defaa38cfe25baf56fcf5474caf49c6de8cfcf9919c347371e7aeff5671d26b34425aa81c8b5bc6938a27b99597c9eeb1a05685deac5866c1d0c91fce586fed2bf",
   "r": "015229bc795da7e37b6b8251151f0b4a191ffae71893b443c95df06124deef57d4ca5470ab4e0aee15b3c32b8ee9ecd1244aa50b660e3415021a126ab181651a7227",
   "s": "00378af35e10292ae94e26d39433ec9448ed4f71df06a64c225177db4efceea18d519f5c593ecc618e57c208e7d87263cbc6e63c8fbce3244c0759384677f038ef44",
   "valid": true,
   "comment": "none"
  }
 ],
 "attacks": {
  "nonce_reuse": {
   "curve": "P-256",
   "hash": "SHA2-256",
   "d": "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464",
   "qx": "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83",
   "qy": "ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9",
   "k": "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de",
   "msg1": "5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8",
   "msg2": "7468c3b46e6720c49169e1bb8770207468e1bba920686169202f207365636f6e64206d657373616765",
   "msg2_text": "thông điệp thứ hai / second message",
   "e1": "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56",
   "e2": "f48cf2cbfd779de0c4aeef741be541224022a1051711fbd432814678f6f614f9",
   "r": "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac",
   "s1": "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903",
   "s2": "0ba68c14671d684b00c8859b08b6970bdf17d92b4d765ca9386eff268697142b",
   "k_recovered": "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de",
   "d_recovered": "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"
  },
  "leaked_k": {
   "curve": "P-256",
   "e": "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56",
   "r": "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac",
   "s": "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903",
   "k": "94a1bbb14b906a61a280f245f9e93c7f3b4a6247824f5d33b9670787642a68de",
   "d": "519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"
  }
 },
 "edges": [
  {
   "curve": "P-192",
   "k": "1",
   "label": "d = 1",
   "qx": "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
   "qy": "07192b95ffc8da78631011ed6b24cdd573f977a11e794811"
  },
  {
   "curve": "P-192",
   "k": "ffffffffffffffffffffffff99def836146bc9b1b4d22830",
   "label": "d = n - 1 (Q = -G)",
   "qx": "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
   "qy": "f8e6d46a003725879cefee1294db32298c06885ee186b7ee"
  },
  {
   "curve": "P-224",
   "k": "1",
   "label": "d = 1",
   "qx": "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
   "qy": "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"
  },
  {
   "curve": "P-224",
   "k": "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3c",
   "label": "d = n - 1 (Q = -G)",
   "qx": "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
   "qy": "42c89c774a08dc04b3dd201932bc8a5ea5f8b89bbb2a7e667aff81cd"
  },
  {
   "curve": "P-256",
   "k": "1",
   "label": "d = 1",
   "qx": "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
   "qy": "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
  },
  {
   "curve": "P-256",
   "k": "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
   "label": "d = n - 1 (Q = -G)",
   "qx": "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
   "qy": "b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a"
  },
  {
   "curve": "P-384",
   "k": "1",
   "label": "d = 1",
   "qx": "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
   "qy": "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
  },
  {
   "curve": "P-384",
   "k": "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972",
   "label": "d = n - 1 (Q = -G)",
   "qx": "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
   "qy": "c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0"
  },
  {
   "curve": "P-521",
   "k": "1",
   "label": "d = 1",
   "qx": "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
   "qy": "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"
  },
  {
   "curve": "P-521",
   "k": "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386408",
   "label": "d = n - 1 (Q = -G)",
   "qx": "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
   "qy": "00e7c6d6958765c43ffba375a04bd382e426670abbb6a864bb97e85042e8d8c199d368118d66a10bd9bf3aaf46fec052f89ecac38f795d8d3dbf77416b89602e99af"
  }
 ]
};
