# RSAUtils

[![API 17+](https://img.shields.io/badge/API-17%2B-green.svg)](https://github.com/gzu-liyujiang/RSAUtils)
[![bintray](https://api.bintray.com/packages/gzu-liyujiang/maven/RSAUtils/images/download.svg) ](https://bintray.com/gzu-liyujiang/maven/RSAUtils/_latestVersion)
[![jitpack](https://jitpack.io/v/gzu-liyujiang/RSAUtils.svg)](https://jitpack.io/#gzu-liyujiang/RSAUtils)
[![travis-ci](https://travis-ci.org/gzu-liyujiang/RSAUtils.svg?branch=master)](https://travis-ci.org/gzu-liyujiang/RSAUtils)
[![MulanPSL](https://img.shields.io/badge/license-MulanPSL-blue.svg)](http://license.coscl.org.cn/MulanPSL)

RSA+RC4/AES+BASE64加密解密。Java及Android平台通用的RSA算法工具类及其例子（敏感信息加密传输、私钥签名&公钥验签、公钥加密&私钥解密、软件注册码/授权码）。

- BASE64编码，BASE64解码。
- SHA1、MD5、CRC32等校验值。
- RC4加密，RC4解密。
- AES加密，AES解密。
- RSA公钥加密，RSA私钥解密。
- RSA私钥签名，RSA公钥验证。
- 软件注册码/授权码。

### 远程依赖

```groovy
allprojects {
    repositories {
        maven { url "https://jitpack.io" }
    }
}

dependencies {
    implementation 'com.github.gzu-liyujiang:RSAUtils:2020.6.15'
}
```

### 封装的方法

#### Base64Utils

```text
isBase64
encodeToString
encodeNoThrown
encode
decodeNoThrown
decode
```

#### ChecksumUtils

```text
sha1
sha256
sha512
md5
crc32
```

#### RC4Utils

```text
convert
encryptToBase64
decryptFromBase64
```

#### AESUtils

```text
convert
encryptToBase64
decryptFromBase64
```

#### RSAUtils

```text
说明：RSA只支持小数据加密，对于大批量数据加密，不建议对数据分段加密，强烈建议使用以下方案：
第一步：客户端选择合适的对称加密算法（如AES、RC4、XXTEA），该算法须服务端也支持；
第二步：客户端随机生成一个对称加密算法所用的密码，使用该密码加密数据，再使用RSA公钥加密该密码；
第三步：服务端使用RSA私钥解密出对称加密算法所用的密码，再使用该密码及同样的对称加密算法解密数据。
推荐查阅这篇文章帮助理解：https://www.cnblogs.com/JeffreySun/archive/2010/06/24/1627247.html
```
```text
encrypt
encryptToBase64
decrypt
decryptFromBase64
signature
signatureMD5
signatureSHA1
verify
verifyMD5
verifySHA1
generateKeyPair
generateCertificate
generatePublicKey
generatePrivateKey
encodePublicKeyToString
encodePrivateKeyToString
printPublicKeyInfo
printPrivateKeyInfo
```

### 示例日志

```java
    private static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJV1jJ6vjuSlsj8rwKIF0NJAonad\n" +
            "E0PIAQtDuo86ByWrkIeMVPLIBRxhutsAUJ761ewN16zdoaSGJBqT4dazN7lb9Nn9Us71UIxHCMc/\n" +
            "pQljSFPrr1GD2vUfFJu1/HBzpPrOjwBLC80TAuBgQBJ7Uln2kFtdCMFVzYq9FbWSfo/lAgMBAAEC\n" +
            "gYB8CSsjgsUO4qh0HqZmkHcGFpf94kvbo7+iDppkRR8rVx/CLmdNeUwsirrdB3zhA4DHv5EvKFv+\n" +
            "w0hxOith2Cg0hYFmmsJtaeWQgGvZO5NxaK8chL/5fUmEU5pO+qqN+uiTEs/CnGL7WYPEKxzKLXDE\n" +
            "yT9P/I0UnuHkh6THpzUnPQJBAOsE7Y4D0Gk3JG5+M8yVLWUSUi7CwCfdE9Cg5exnucYhlktp1jIk\n" +
            "2ap0b7Vt0kVaZumuc+LGVPsWCRjTyjDDBr8CQQCizUCk3hOZcqs70ieIrCximIscv4qGFvDsVJEj\n" +
            "39J7zAwijC+GCDJI4P10NnoOhVUNHghtEhLn5o3SBUU/2VZbAkEAodeb659OxxX1Ha4E586XGzIZ\n" +
            "rB/rCcihm5shmsH3WazJfhddLNzZlBtozgzZr27IzgWXwkQIQ3xyOUmnxBqZqwJAUJwUwA194uLW\n" +
            "Sl56WL/3kjI531gv/MjrLfmJjBvNGqMj9w82kMUKMO/GT36R3RLD1CTkwyzJ061i13Tonv68NQJB\n" +
            "AM3uOj58rPOAFPmMyy2x+SADvGUvp4YtStfIApSrk297WKSocjmv7LIVC4Izh8vBr/scz70PqTkn\n" +
            "6sZfw+qKdi0=\n" +
            "-----END RSA PRIVATE KEY-----";
    private static final String PUBLIC_KEY = "-----BEGIN RSA PUBLIC KEY-----\n" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVdYyer47kpbI/K8CiBdDSQKJ2nRNDyAELQ7qP\n" +
            "Ogclq5CHjFTyyAUcYbrbAFCe+tXsDdes3aGkhiQak+HWsze5W/TZ/VLO9VCMRwjHP6UJY0hT669R\n" +
            "g9r1HxSbtfxwc6T6zo8ASwvNEwLgYEASe1JZ9pBbXQjBVc2KvRW1kn6P5QIDAQAB\n" +
            "-----END RSA PUBLIC KEY-----";

    public void onRSAAndRC4Encrypt(View view) {
        String data = edtPlainText.getText().toString();
        if (TextUtils.isEmpty(data)) {
            Toast.makeText(this, "请输入要加密的内容", Toast.LENGTH_SHORT).show();
            return;
        }
        String password = "123456";
        Logger.print("明文密码：" + password);
        String encryptedData = RC4Utils.encryptToBase64(data.getBytes(CHARSET), password);
        Logger.print("RC4加密：" + encryptedData);
        String encryptedPassword = RSAUtils.encryptToBase64(password.getBytes(CHARSET), RSAUtils.generatePublicKey(PUBLIC_KEY));
        Logger.print("密文密码：" + encryptedPassword);
        if (TextUtils.isEmpty(encryptedData) || TextUtils.isEmpty(encryptedPassword)) {
            Toast.makeText(this, "加密失败", Toast.LENGTH_SHORT).show();
            return;
        }
        tvEncryptedData.setText(encryptedData);
        tvEncryptedPassword.setText(encryptedPassword);
    }

    public void onRSAAndRC4Decrypt(View view) {
        String encryptedData = tvEncryptedData.getText().toString();
        Logger.print("RC4密文：" + encryptedData);
        String encryptedPassword = tvEncryptedPassword.getText().toString();
        Logger.print("密文密码：" + encryptedPassword);
        if (TextUtils.isEmpty(encryptedData) || TextUtils.isEmpty(encryptedPassword)) {
            Toast.makeText(this, "还没有加密过数据", Toast.LENGTH_SHORT).show();
            return;
        }
        byte[] decryptedPassword = RSAUtils.decryptFromBase64(encryptedPassword, RSAUtils.generatePrivateKey(PRIVATE_KEY));
        if (decryptedPassword == null) {
            Toast.makeText(this, "密码解密失败", Toast.LENGTH_SHORT).show();
            return;
        }
        String password = new String(decryptedPassword, CHARSET);
        Logger.print("明文密码：" + password);
        byte[] decryptedData = RC4Utils.decryptFromBase64(encryptedData, password);
        if (decryptedData == null) {
            Toast.makeText(this, "使用" + password + "解密失败", Toast.LENGTH_SHORT).show();
            return;
        }
        String data = new String(decryptedData, CHARSET);
        Logger.print("RC4解密：" + data);
        Toast.makeText(this, data, Toast.LENGTH_LONG).show();
    }
```
```text
W/liyujiang: 明文密码：123456
W/liyujiang: RC4加密：6EzLgpOt8jXA3r8kHYT7
W/liyujiang: 密文密码：kMN5bTOmiPJeEvhICc5f3phxRJBkIGzv5rFCxhLISYtDQwF4/1SSRy75QHiR445ZIOCAP4vQM8Tf
    uaRt0b1wyZ3y1wvVzW9kyBqQvrRUK/p4Vik0KQWoNo/53gx6OSkBQMyufKyR+AKmnA7hybhtw6rI
    byStBdKUFnuedj4wilk=
W/liyujiang: RC4密文：6EzLgpOt8jXA3r8kHYT7
W/liyujiang: 密文密码：kMN5bTOmiPJeEvhICc5f3phxRJBkIGzv5rFCxhLISYtDQwF4/1SSRy75QHiR445ZIOCAP4vQM8Tf
    uaRt0b1wyZ3y1wvVzW9kyBqQvrRUK/p4Vik0KQWoNo/53gx6OSkBQMyufKyR+AKmnA7hybhtw6rI
    byStBdKUFnuedj4wilk=
W/liyujiang: 明文密码：123456
W/liyujiang: RC4解密：贵州穿青人
W/liyujiang: 明文密码：123456
W/liyujiang: AES加密：8Nm9QEl1ns2CB2h3SXdwEiJBgJXdKXzQq9fV+zDvyw==
W/liyujiang: 密文密码：ADXpK5q5FRK2K+3OcYw7g+0FWkZUXmXCwlU8wds0e/UVLsZEsCb3PRFVjrixgDJ29VFf0fUt8q5f
    yQF0aCVXjp9XhvcG8bd+uvfyz843+JYuJCkxG07c5ew8V5b3jaZvbXJSmqeke9OIYzW1uAF06J0v
    /xOy3Mj6HB4EqtytQn0=
W/liyujiang: AES密文：8Nm9QEl1ns2CB2h3SXdwEiJBgJXdKXzQq9fV+zDvyw==
W/liyujiang: 密文密码：ADXpK5q5FRK2K+3OcYw7g+0FWkZUXmXCwlU8wds0e/UVLsZEsCb3PRFVjrixgDJ29VFf0fUt8q5f
    yQF0aCVXjp9XhvcG8bd+uvfyz843+JYuJCkxG07c5ew8V5b3jaZvbXJSmqeke9OIYzW1uAF06J0v
    /xOy3Mj6HB4EqtytQn0=
W/liyujiang: 明文密码：123456
W/liyujiang: AES解密：贵州穿青人
W/liyujiang: RSA Public Key Info:
    Format=X.509
    Algorithm=RSA
    Modulus.length=1024
    Modulus=104953803252028535197426100160657684922668618375493745112597393524175584479063111015683560753019906356938393418213334898199604429170091987276594508471023132331190972106077487573027767020111492019066956800371029468935761969205063997496659622858083336985459361235058905357735117119541539005051586887557928882149
    PublicExponent.length=17
    PublicExponent=65537
W/liyujiang: RSA Private Key Info:
    Format=PKCS#8
    Algorithm=RSA
    Modulus.length=1024
    Modulus=104953803252028535197426100160657684922668618375493745112597393524175584479063111015683560753019906356938393418213334898199604429170091987276594508471023132331190972106077487573027767020111492019066956800371029468935761969205063997496659622858083336985459361235058905357735117119541539005051586887557928882149
    PrivateExponent.length=1023
    PrivateExponent=87100911013238018231728766370722047473320772766906164501412326416930678307395265957123658174710464117178422564707036815511516933917209104719268485301897798360238205447720504724819155252062546440415064221202758352446471555751599779280866802775656372630844608280309935707858867334254177374357594610201663973181
W/liyujiang: registerCode=d0013db0-bc78-4c15-94d9-29e868edbd1b
W/liyujiang: licenseKey: 
    -----BEGIN LICENSE KEY-----
    FaBuWoxwwgN3zxy2a1wJ+1j/PdA49OL/PE5Xs5H7Z25gRFMre3mOGqx/2bk4o8AM1vohWQ4w+3XP
    gmiIrRLSyvNrQJsJyx9UiIRzU4whbmAvY311YDh4hGnDSdsnNzAjfKk1zmme37KciHOXt2ppEs0F
    8G6PWfUgOp2ju3FUkco=
    -----END LICENSE KEY-----
W/liyujiang: licenseKey equals=false
W/liyujiang: verify result=true
W/liyujiang: RSA Public Key Info:
    Format=X.509
    Algorithm=RSA
    Modulus.length=1024
    Modulus=124106268603826661795048085340022418257596887588967694744956976430489086723635626648329590644563639581213759446781317223888301144846473903643152592239713921440575435198781130132381230014534207093431850518652618902266376531123249857646944632569295429814341185407768924940085057500672798877043125502923175896459
    PublicExponent.length=17
    PublicExponent=65537
W/liyujiang: RSA Private Key Info:
    Format=PKCS#8
    Algorithm=RSA
    Modulus.length=1024
    Modulus=124106268603826661795048085340022418257596887588967694744956976430489086723635626648329590644563639581213759446781317223888301144846473903643152592239713921440575435198781130132381230014534207093431850518652618902266376531123249857646944632569295429814341185407768924940085057500672798877043125502923175896459
    PrivateExponent.length=1021
    PrivateExponent=15590056619300603186058245020511943310018910079661484478543659326691891419607004221332703814839621233688946349983495189972042569721013638464676863060238002338303423173947064359393044541216098073843489560820472589984830927213073876715459716982667392850434596591535425879524656324236522962422495572034945137361
```

### 许可授权
```text
Copyright (c) 2019-2020 gzu-liyujiang <1032694760@qq.com>

RSAUtils is licensed under the Mulan PSL v1.
You can use this software according to the terms and conditions of the Mulan PSL v1.
You may obtain a copy of Mulan PSL v1 at:
    http://license.coscl.org.cn/MulanPSL
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
PURPOSE.
See the Mulan PSL v1 for more details.
```
