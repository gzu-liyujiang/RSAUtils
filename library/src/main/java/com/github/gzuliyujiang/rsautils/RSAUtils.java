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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * <pre>
 * RSA公钥/私钥/签名工具类。
 * 对于RSA算法，Android上的实现是"RSA/None/NoPadding"，标准JDK的实现是"RSA/ECB/PKCS1Padding"。
 *
 * 字符串格式的密钥未在特殊说明情况下都为BASE64编码格式
 * 由于非对称加密速度极其缓慢，一般文件不使用它来加密而是使用对称加密，
 * 非对称加密算法可以用来对对称加密的密钥加密，这样保证密钥的安全也就保证了数据的安全
 *
 * 参阅：
 * http://blog.csdn.net/jdsjlzx/article/details/41441147
 * http://blog.csdn.net/boonya/article/details/52091957
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
    private static final int MAX_ENCRYPT_BLOCK = 117;
    private static final int MAX_DECRYPT_BLOCK = 128;

    private RSAUtils() {
        super();
    }

    public static KeyPair generateKeyPair(File jksFile, String jksPwd, String alias, String pwd) {
        try {
            return generateKeyPair(new FileInputStream(jksFile), jksPwd, alias, pwd);
        } catch (FileNotFoundException e) {
            Logger.print(e);
            return null;
        }
    }

    public static KeyPair generateKeyPair(InputStream jksStream, String jksPwd, String alias, String pwd) {
        try {
            KeyStore keystore = KeyStore.getInstance("jks");
            keystore.load(jksStream, jksPwd.toCharArray());
            Key key = keystore.getKey(alias, pwd.toCharArray());
            if (key instanceof PrivateKey) {
                PrivateKey privateKey = (PrivateKey) key;
                Certificate certificate = keystore.getCertificateChain(alias)[0];
                PublicKey publicKey = certificate.getPublicKey();
                return new KeyPair(publicKey, privateKey);
            }
        } catch (Exception e) {
            Logger.print(e);
        } finally {
            try {
                jksStream.close();
            } catch (IOException ignore) {
            }
        }
        return null;
    }

    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            //密钥长度范围：512～2048， 一般1024
            generator.initialize(1024);
            return generator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            Logger.print(e);
            return null;
        }
    }

    public static String encodeToString(RSAPublicKey publicKey, boolean excludeTag) {
        String encode = Base64Utils.encode(publicKey.getEncoded());
        if (excludeTag) {
            return encode;
        }
        return PUBLIC_KEY_BEGIN + "\n" + encode + "\n" + PUBLIC_KEY_END;
    }

    public static String encodeToString(RSAPrivateKey privateKey, boolean excludeTag) {
        String encode = Base64Utils.encode(privateKey.getEncoded());
        if (excludeTag) {
            return encode;
        }
        return PRIVATE_KEY_BEGIN + "\n" + encode + "\n" + PRIVATE_KEY_END;
    }

    public static byte[] encryptData(byte[] data, String publicKeyStr) {
        RSAPublicKey publicKey = obtainPublicKeyFromBase64(publicKeyStr);
        return encryptData(data, publicKey);
    }

    public static byte[] encryptData(byte[] data, RSAPublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int length = data.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段加密
            while (length - offSet > 0) {
                if (length - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data, offSet, length - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] encryptedData = out.toByteArray();
            out.close();
            return encryptedData;
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    public static byte[] decryptData(byte[] data, String privateKeyStr) {
        RSAPrivateKey privateKey = obtainPrivateKeyFromBase64(privateKeyStr);
        return decryptData(data, privateKey);
    }

    public static byte[] decryptData(byte[] data, RSAPrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            int length = data.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段解密
            while (length - offSet > 0) {
                if (length - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(data, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data, offSet, length - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_DECRYPT_BLOCK;
            }
            byte[] decryptedData = out.toByteArray();
            out.close();
            return decryptedData;
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    public static String signData(byte[] data, String privateKeyStr) {
        RSAPrivateKey privateKey = obtainPrivateKeyFromBase64(privateKeyStr);
        return signData(data, privateKeyStr);
    }

    public static String signData(byte[] data, RSAPrivateKey privateKey) {
        if (privateKey == null) {
            Logger.print("private key is null");
            return null;
        }
        try {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            return Base64Utils.encode(signature.sign());
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    public static boolean verifyData(byte[] data, String publicKeyStr, String sign) {
        RSAPublicKey publicKey = obtainPublicKeyFromBase64(publicKeyStr);
        return verifyData(data, publicKey, sign);
    }

    public static boolean verifyData(byte[] data, RSAPublicKey publicKey, String sign) {
        if (publicKey == null) {
            Logger.print("public key is null");
            return false;
        }
        try {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(Base64Utils.decode(sign.getBytes()));
        } catch (Exception e) {
            Logger.print(e);
            return false;
        }
    }

    public static RSAPublicKey obtainPublicKeyFromEncoded(byte[] data) {
        if (data.length == 0) {
            Logger.print("data is empty");
            return null;
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            //Only RSAPublicKeySpec and X509EncodedKeySpec supported for RSA public keys
            return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(data));
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    public static RSAPrivateKey obtainPrivateKeyFromEncoded(byte[] data) {
        if (data.length == 0) {
            Logger.print("data is empty");
            return null;
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            try {
                return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(data));
            } catch (InvalidKeySpecException e) {
                Logger.print(e);
                return (RSAPrivateKey) keyFactory.generatePrivate(new X509EncodedKeySpec(data));
            }
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    public static RSAPublicKey obtainPublicKeyFromBase64(String publicKeyStr) {
        publicKeyStr = ignoreKeyStringTag(publicKeyStr);
        byte[] data = Base64Utils.decode(publicKeyStr.getBytes());
        return obtainPublicKeyFromEncoded(data);
    }

    public static RSAPrivateKey obtainPrivateKeyFromBase64(String privateKeyStr) {
        privateKeyStr = ignoreKeyStringTag(privateKeyStr);
        byte[] data = Base64Utils.decode(privateKeyStr.getBytes());
        return obtainPrivateKeyFromEncoded(data);
    }

    private static String ignoreKeyStringTag(String keyStr) {
        StringBuilder sb = new StringBuilder();
        String[] lines = keyStr.split("\n");
        for (String line : lines) {
            //忽略秘钥串首尾的标识串
            if (line.charAt(0) != '-') {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    public static RSAPublicKey obtainPublicKeyFromFile(File pemFile) {
        try {
            return obtainPublicKeyFromBase64(FileUtils.readText(pemFile));
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    public static RSAPrivateKey obtainPrivateKeyFromFile(File pemFile) {
        try {
            return obtainPrivateKeyFromBase64(FileUtils.readText(pemFile));
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    public static RSAPublicKey obtainPublicKeyFromModulus(String modulus, String publicExponent) {
        try {
            BigInteger bigIntModulus = new BigInteger(modulus);
            BigInteger bigIntPrivateExponent = new BigInteger(publicExponent);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    public static RSAPrivateKey obtainPrivateKeyFromModulus(String modulus, String privateExponent) {
        try {
            BigInteger bigIntModulus = new BigInteger(modulus);
            BigInteger bigIntPrivateExponent = new BigInteger(privateExponent);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    public static boolean savePublicKeyToFile(File file, RSAPublicKey publicKey) {
        return FileUtils.writeText(file, encodeToString(publicKey, false));
    }

    public static boolean savePrivateKeyToFile(File file, RSAPrivateKey privateKey) {
        return FileUtils.writeText(file, encodeToString(privateKey, false));
    }

    public static void printPublicKeyInfo(RSAPublicKey publicKey) {
        StringBuilder sb = new StringBuilder();
        sb.append("RSA Public Key Info:").append("\n");
        sb.append("Format=").append(publicKey.getFormat()).append("\n");
        sb.append("Algorithm=").append(publicKey.getAlgorithm()).append("\n");
        sb.append("Modulus.length=").append(publicKey.getModulus().bitLength()).append("\n");
        sb.append("Modulus=").append(publicKey.getModulus().toString()).append("\n");
        sb.append("PublicExponent.length=").append(publicKey.getPublicExponent().bitLength()).append("\n");
        sb.append("PublicExponent=").append(publicKey.getPublicExponent().toString()).append("\n");
        Logger.print(sb);
    }

    public static void printPrivateKeyInfo(RSAPrivateKey privateKey) {
        StringBuilder sb = new StringBuilder();
        sb.append("RSA Private Key Info:").append("\n");
        sb.append("Format=").append(privateKey.getFormat()).append("\n");
        sb.append("Algorithm=").append(privateKey.getAlgorithm()).append("\n");
        sb.append("Modulus.length=").append(privateKey.getModulus().bitLength()).append("\n");
        sb.append("Modulus=").append(privateKey.getModulus().toString()).append("\n");
        sb.append("PrivateExponent.length=").append(privateKey.getPrivateExponent().bitLength()).append("\n");
        sb.append("PrivatecExponent=").append(privateKey.getPrivateExponent().toString()).append("\n");
        Logger.print(sb);
    }

}