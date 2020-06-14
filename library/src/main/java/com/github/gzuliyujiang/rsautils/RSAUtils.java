/*
 * Copyright (c) 2019-2020 gzu-liyujiang <1032694760@qq.com>
 *
 * RSAUtils is licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 */
package com.github.gzuliyujiang.rsautils;


import com.github.gzuliyujiang.logger.Logger;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * <pre>
 * 安卓密钥库、RSA公钥私钥、加密解密、签名验签。
 * 对于RSA算法，Android上默认提供是"RSA/None/NoPadding"，标准JDK的默认提供是"RSA/ECB/PKCS1Padding"。
 *
 * 字符串格式的密钥未在特殊说明情况下都为BASE64编码格式。
 * 非对称加密算法可以用来对对称加密的密钥加密，典型的应用是：RSA加密解密密钥+AES加密解密数据。
 *
 * 参阅：
 * http://blog.csdn.net/jdsjlzx/article/details/41441147
 * http://blog.csdn.net/boonya/article/details/52091957
 * https://github.com/joetsaitw/AndroidKeyStore
 * </pre>
 *
 * @author 大定府羡民
 */
@SuppressWarnings({"unused", "WeakerAccess", "UnusedReturnValue"})
public final class RSAUtils {
    private static final String PUBLIC_KEY_BEGIN = "-----BEGIN RSA PUBLIC KEY-----";
    private static final String PUBLIC_KEY_END = "-----END RSA PUBLIC KEY-----";
    private static final String PRIVATE_KEY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PRIVATE_KEY_END = "-----END RSA PRIVATE KEY-----";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";

    private RSAUtils() {
        super();
    }

    /**
     * 使用RSA公钥加密对称加密算法所使用的明文密码。
     * 说明：RSA只支持小数据加密，对于大批量数据加密，不建议对数据分段加密，强烈建议使用以下方案：
     * 第一步：客户端选择合适的对称加密算法（如AES、RC4、XXTEA），该算法须服务端也支持；
     * 第二步：客户端随机生成一个对称加密算法所用的密码，使用该密码加密数据，再使用RSA公钥加密该密码；
     * 第三步：服务端使用RSA私钥解密出对称加密算法所用的密码，再使用该密码及同样的对称加密算法解密数据。
     * 推荐查阅这篇文章帮助理解：https://www.cnblogs.com/JeffreySun/archive/2010/06/24/1627247.html
     */
    public static String encrypt(byte[] plainSecretKey, RSAPublicKey publicKey) {
        if (plainSecretKey == null || plainSecretKey.length == 0) {
            Logger.print("plain SecretKey is empty");
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(RSA_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedData = cipher.doFinal(plainSecretKey);
            return Base64Utils.encodeToString(encryptedData);
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    /**
     * 使用RSA公钥加密对称加密算法所使用的明文密码
     */
    public static String encrypt(byte[] plainSecretKey, String publicKeyBase64) {
        if (plainSecretKey == null || plainSecretKey.length == 0) {
            Logger.print("plain SecretKey is empty");
            return null;
        }
        RSAPublicKey publicKey = generatePublicKey(publicKeyBase64);
        return encrypt(plainSecretKey, publicKey);
    }

    /**
     * 使用RSA私钥解密对称加密算法所使用的密文密码
     */
    public static byte[] decrypt(String encryptedSecretKey, RSAPrivateKey privateKey) {
        if (encryptedSecretKey == null || encryptedSecretKey.length() == 0) {
            Logger.print("encrypted SecretKey is empty");
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(RSA_MODE);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(Base64Utils.decodeFromString(encryptedSecretKey));
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    /**
     * 使用RSA私钥解密对称加密算法所使用的密文密码
     */
    public static byte[] decrypt(String encryptedSecretKey, String privateKeyBase64) {
        if (encryptedSecretKey == null || encryptedSecretKey.length() == 0) {
            Logger.print("encrypted SecretKey is empty");
            return null;
        }
        RSAPrivateKey privateKey = generatePrivateKey(privateKeyBase64);
        return decrypt(encryptedSecretKey, privateKey);
    }

    /**
     * 使用私钥对数据签名
     */
    public static byte[] sign(byte[] data, String privateKeyBase64) {
        if (data == null || data.length == 0) {
            Logger.print("data is empty");
            return null;
        }
        RSAPrivateKey privateKey = generatePrivateKey(privateKeyBase64);
        if (privateKey == null) {
            Logger.print("private key is null");
            return null;
        }
        return sign(data, privateKey);
    }

    /**
     * 使用私钥对数据签名
     */
    public static byte[] sign(byte[] data, RSAPrivateKey privateKey) {
        if (data == null || data.length == 0) {
            Logger.print("data is empty");
            return null;
        }
        if (privateKey == null) {
            Logger.print("private key is null");
            return null;
        }
        try {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    /**
     * 使用公钥验证数据签名
     */
    public static boolean verify(byte[] data, String publicKeyBase64, byte[] sign) {
        if (data == null || data.length == 0) {
            Logger.print("data is empty");
            return false;
        }
        RSAPublicKey publicKey = generatePublicKey(publicKeyBase64);
        if (publicKey == null) {
            Logger.print("public key is null");
            return false;
        }
        return verify(data, publicKey, sign);
    }

    /**
     * 使用公钥验证数据签名
     */
    public static boolean verify(byte[] data, RSAPublicKey publicKey, byte[] sign) {
        if (data == null || data.length == 0) {
            Logger.print("data is empty");
            return false;
        }
        if (publicKey == null) {
            Logger.print("public key is null");
            return false;
        }
        try {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(sign);
        } catch (Exception e) {
            Logger.print(e);
            return false;
        }
    }

    /**
     * 随机生成RSA密钥对
     */
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            //密钥长度范围：512～2048，一般1024
            generator.initialize(1024);
            return generator.genKeyPair();
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    /**
     * 根据二进制BASE64编码的X509证书生成X509证书
     */
    public static X509Certificate generateCertificate(byte[] base64) {
        if (base64 == null || base64.length == 0) {
            Logger.print("base64 is empty");
            return null;
        }
        try {
            ByteArrayInputStream stream = new ByteArrayInputStream(base64);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(stream);
        } catch (Exception e) {
            Logger.print(e);
        }
        return null;
    }

    /**
     * 根据字符串BASE64编码的X509证书生成X509证书
     */
    public static X509Certificate generateCertificate(String base64) {
        base64 = ignoreIdentifier(base64);
        byte[] data = Base64Utils.decode(base64.getBytes());
        if (data == null) {
            return null;
        }
        return generateCertificate(data);
    }

    /**
     * 根据二进制BASE64编码的公钥生成RSA公钥
     */
    public static RSAPublicKey generatePublicKey(byte[] base64) {
        if (base64 == null || base64.length == 0) {
            Logger.print("base64 is empty");
            return null;
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            //Only RSAPublicKeySpec and X509EncodedKeySpec supported for RSA public keys
            return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(base64));
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    /**
     * 根据字符串BASE64编码的公钥生成RSA公钥
     */
    public static RSAPublicKey generatePublicKey(String base64) {
        base64 = ignoreIdentifier(base64);
        byte[] data = Base64Utils.decode(base64.getBytes());
        if (data == null) {
            return null;
        }
        return generatePublicKey(data);
    }

    /**
     * 根据二进制BASE64编码的私钥生成RSA私钥
     */
    public static RSAPrivateKey generatePrivateKey(byte[] base64) {
        if (base64 == null || base64.length == 0) {
            Logger.print("base64 is empty");
            return null;
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            try {
                return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(base64));
            } catch (InvalidKeySpecException e) {
                Logger.print(e);
                return (RSAPrivateKey) keyFactory.generatePrivate(new X509EncodedKeySpec(base64));
            }
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    /**
     * 根据字符串BASE64编码的私钥生成RSA私钥
     */
    public static RSAPrivateKey generatePrivateKey(String base64) {
        base64 = ignoreIdentifier(base64);
        byte[] data = Base64Utils.decode(base64.getBytes());
        if (data == null) {
            return null;
        }
        return generatePrivateKey(data);
    }

    private static String ignoreIdentifier(String str) {
        StringBuilder sb = new StringBuilder();
        String[] lines = str.split("\n");
        for (String line : lines) {
            //忽略证书及秘钥串首尾的标识符
            if (line.charAt(0) != '-') {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    /**
     * 根据模数及公钥指数生成RSA公钥
     */
    public static RSAPublicKey generatePublicKey(String modulus, String publicExponent) {
        try {
            BigInteger bigIntModulus = new BigInteger(modulus);
            BigInteger bigIntExponent = new BigInteger(publicExponent);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    /**
     * 根据模数及私钥指数生成RSA私钥
     */
    public static RSAPrivateKey generatePrivateKey(String modulus, String privateExponent) {
        try {
            BigInteger bigIntModulus = new BigInteger(modulus);
            BigInteger bigIntExponent = new BigInteger(privateExponent);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    /**
     * 将RSA公钥编码为BASE64字符串
     */
    public static String encodePublicKeyToString(RSAPublicKey publicKey) {
        return encodePublicKeyToString(publicKey, false);
    }

    /**
     * 将RSA公钥编码为BASE64字符串
     */
    public static String encodePublicKeyToString(RSAPublicKey publicKey, boolean excludeIdentifier) {
        String encode = Base64Utils.encodeToString(publicKey.getEncoded());
        if (excludeIdentifier) {
            return encode;
        }
        return PUBLIC_KEY_BEGIN + "\n" + encode + "\n" + PUBLIC_KEY_END;
    }

    /**
     * 将RSA私钥编码为BASE64字符串
     */
    public static String encodePrivateKeyToString(RSAPrivateKey privateKey) {
        return encodePrivateKeyToString(privateKey, false);
    }

    /**
     * 将RSA私钥编码为BASE64字符串
     */
    public static String encodePrivateKeyToString(RSAPrivateKey privateKey, boolean excludeIdentifier) {
        String encode = Base64Utils.encodeToString(privateKey.getEncoded());
        if (excludeIdentifier) {
            return encode;
        }
        return PRIVATE_KEY_BEGIN + "\n" + encode + "\n" + PRIVATE_KEY_END;
    }


    public static void printPublicKeyInfo(RSAPublicKey publicKey) {
        StringBuilder sb = new StringBuilder();
        try {
            sb.append("RSA Public Key Info:").append("\n");
            sb.append("Format=").append(publicKey.getFormat()).append("\n");
            sb.append("Algorithm=").append(publicKey.getAlgorithm()).append("\n");
            sb.append("Modulus.length=").append(publicKey.getModulus().bitLength()).append("\n");
            sb.append("Modulus=").append(publicKey.getModulus().toString()).append("\n");
            sb.append("PublicExponent.length=").append(publicKey.getPublicExponent().bitLength()).append("\n");
            sb.append("PublicExponent=").append(publicKey.getPublicExponent().toString()).append("\n");
        } catch (Exception e) {
            sb.append(e);
        }
        Logger.print(sb);
    }

    public static void printPrivateKeyInfo(RSAPrivateKey privateKey) {
        StringBuilder sb = new StringBuilder();
        try {
            sb.append("RSA Private Key Info:").append("\n");
            sb.append("Format=").append(privateKey.getFormat()).append("\n");
            sb.append("Algorithm=").append(privateKey.getAlgorithm()).append("\n");
            sb.append("Modulus.length=").append(privateKey.getModulus().bitLength()).append("\n");
            sb.append("Modulus=").append(privateKey.getModulus().toString()).append("\n");
            sb.append("PrivateExponent.length=").append(privateKey.getPrivateExponent().bitLength()).append("\n");
            sb.append("PrivateExponent=").append(privateKey.getPrivateExponent().toString()).append("\n");
        } catch (Exception e) {
            sb.append(e);
        }
        Logger.print(sb);
    }

}