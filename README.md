# RSADemo


[![travis-ci](https://travis-ci.org/gzu-liyujiang/RSAUtils.svg?branch=master)](https://travis-ci.org/gzu-liyujiang/RSAUtils)
[![MulanPSL](https://img.shields.io/badge/license-MulanPSL-blue.svg)](http://license.coscl.org.cn/MulanPSL)

RSA算法工具类及其demo   

- 公钥加密，私钥解密。
- 私钥签名，公钥验证。

### 封装的方法

```text
generateKeyPair
encodeToString
encryptData
decryptData
signData
verifyData
obtainPublicKeyFromEncoded
obtainPrivateKeyFromEncoded
obtainPublicKeyFromFile
obtainPrivateKeyFromFile
obtainPublicKeyFromModulus
obtainPrivateKeyFromModulus
savePublicKeyToFile
savePrivateKeyToFile
printPublicKeyInfo
printPrivateKeyInfo
```

### 示例日志

```text
W/liyujiang: ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────
W/liyujiang: │ MainActivity.decodeKeyAndGenerateLicenseKey  (MainActivity.java:104)
W/liyujiang: │    RSAUtils.printPublicKeyInfo  (RSAUtils.java:360)
W/liyujiang: ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
W/liyujiang: │ RSA Public Key Info:
W/liyujiang: │ Format=X.509
W/liyujiang: │ Algorithm=RSA
W/liyujiang: │ Modulus.length=1024
W/liyujiang: │ Modulus=104953803252028535197426100160657684922668618375493745112597393524175584479063111015683560753019906356938393418213334898199604429170091987276594508471023132331190972106077487573027767020111492019066956800371029468935761969205063997496659622858083336985459361235058905357735117119541539005051586887557928882149
W/liyujiang: │ PublicExponent.length=17
W/liyujiang: │ PublicExponent=65537
W/liyujiang: └────────────────────────────────────────────────────────────────────────────────────────────────────────────────
W/liyujiang: ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────
W/liyujiang: │ MainActivity.decodeKeyAndGenerateLicenseKey  (MainActivity.java:106)
W/liyujiang: │    RSAUtils.printPrivateKeyInfo  (RSAUtils.java:372)
W/liyujiang: ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
W/liyujiang: │ RSA Private Key Info:
W/liyujiang: │ Format=PKCS#8
W/liyujiang: │ Algorithm=RSA
W/liyujiang: │ Modulus.length=1024
W/liyujiang: │ Modulus=104953803252028535197426100160657684922668618375493745112597393524175584479063111015683560753019906356938393418213334898199604429170091987276594508471023132331190972106077487573027767020111492019066956800371029468935761969205063997496659622858083336985459361235058905357735117119541539005051586887557928882149
W/liyujiang: │ PrivateExponent.length=1023
W/liyujiang: │ PrivatecExponent=87100911013238018231728766370722047473320772766906164501412326416930678307395265957123658174710464117178422564707036815511516933917209104719268485301897798360238205447720504724819155252062546440415064221202758352446471555751599779280866802775656372630844608280309935707858867334254177374357594610201663973181
W/liyujiang: └────────────────────────────────────────────────────────────────────────────────────────────────────────────────
W/liyujiang: ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────
W/liyujiang: │ Method.invoke  (Method.java:-2)
W/liyujiang: │    MainActivity.decodeKeyAndGenerateLicenseKey  (MainActivity.java:108)
W/liyujiang: ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
W/liyujiang: │ registerCode=DDDSSFSSSSFFFF
W/liyujiang: └────────────────────────────────────────────────────────────────────────────────────────────────────────────────
W/liyujiang: ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────
W/liyujiang: │ Method.invoke  (Method.java:-2)
W/liyujiang: │    MainActivity.decodeKeyAndGenerateLicenseKey  (MainActivity.java:113)
W/liyujiang: ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
W/liyujiang: │ licenseKey: 
W/liyujiang: │ -----BEGIN LICENSE KEY-----
W/liyujiang: │ NF2i/7a/VhBkFrDgckLNq/F4YdB6s7JL2BNfoDe735vt1pQjHjkDZ7TB6VQClguRYoOIib1Nwb81
W/liyujiang: │ xfsHtj1lRq3NxlvYcEJcmeWM2lCRYd8rf7G5czNQl4GrZtfLknPevvZYQkIZV2nwvzoEYD4DkOYE
W/liyujiang: │ abni0mqwIioVuf9jEnI=
W/liyujiang: │ -----END LICENSE KEY-----
W/liyujiang: └────────────────────────────────────────────────────────────────────────────────────────────────────────────────
W/liyujiang: ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────
W/liyujiang: │ Method.invoke  (Method.java:-2)
W/liyujiang: │    MainActivity.decodeKeyAndGenerateLicenseKey  (MainActivity.java:125)
W/liyujiang: ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
W/liyujiang: │ licenseKey equals=true
W/liyujiang: └────────────────────────────────────────────────────────────────────────────────────────────────────────────────
W/liyujiang: ┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────
W/liyujiang: │ Method.invoke  (Method.java:-2)
W/liyujiang: │    MainActivity.decodeKeyAndGenerateLicenseKey  (MainActivity.java:127)
W/liyujiang: ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
W/liyujiang: │ verify result=true
W/liyujiang: └────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```