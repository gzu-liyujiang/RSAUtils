package com.gitee.li_yu_jiang.toolkit;

import com.gitee.li_yu_jiang.logger.LiLog;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

import javax.crypto.Cipher;

/**
 * <pre>
 * RSA公钥/私钥/签名工具类。
 * 对于RSA算法，Android上的实现是"RSA/None/NoPadding"，
 * 标准JDK的实现是"RSA/None/PKCS1Padding"，需要添加"bcprov-jdk15-143.jar"来兼容。
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
@SuppressWarnings({"unused", "WeakerAccess", "InfiniteRecursion", "UnusedReturnValue"})
public final class LiRSA {
    private static final String PUBLIC_KEY_BEGIN = "-----BEGIN RSA PUBLIC KEY-----";
    private static final String PUBLIC_KEY_END = "-----END RSA PUBLIC KEY-----";
    private static final String PRIVATE_KEY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PRIVATE_KEY_END = "-----END RSA PRIVATE KEY-----";
    private static final int MAX_ENCRYPT_BLOCK = 117;
    private static final int MAX_DECRYPT_BLOCK = 128;

    private LiRSA() {
    }

    public static KeyPair genKeyPairByJKSFile(String jksPath, String jksPassword,
                                              String alias, String password) {
        try {
            File file = new File(jksPath);
            FileInputStream inputStream = new FileInputStream(file);
            KeyStore keystore = KeyStore.getInstance("jks");
            keystore.load(inputStream, jksPassword.toCharArray());
            Key key = keystore.getKey(alias, password.toCharArray());
            if (key instanceof PrivateKey) {
                PrivateKey privateKey = (PrivateKey) key;
                Certificate certificate = keystore.getCertificateChain(alias)[0];
                PublicKey publicKey = certificate.getPublicKey();
                return new KeyPair(publicKey, privateKey);
            }
            inputStream.close();
        } catch (Exception e) {
            LiLog.debug(e);
        }
        return null;
    }

    public static KeyPair genKeyPairByRandom() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            //密钥长度范围：512～2048， 一般1024
            generator.initialize(1024);
            return generator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            LiLog.debug(e);
            return null;
        }
    }

    public static String encodeToString(RSAPublicKey publicKey, boolean excludeTag) {
        String encode = LiBase64.encode(publicKey.getEncoded());
        if (excludeTag) {
            return encode;
        }
        return PUBLIC_KEY_BEGIN + "\n" + encode + "\n" + PUBLIC_KEY_END;
    }

    public static String encodeToString(RSAPrivateKey privateKey, boolean excludeTag) {
        String encode = LiBase64.encode(privateKey.getEncoded());
        if (excludeTag) {
            return encode;
        }
        return PRIVATE_KEY_BEGIN + "\n" + encode + "\n" + PRIVATE_KEY_END;
    }

    public static byte[] encrypt(byte[] data, String publicKeyStr) {
        RSAPublicKey publicKey = obtainPublicKeyFromBase64(publicKeyStr);
        return encrypt(data, publicKey);
    }

    public static byte[] encrypt(byte[] data, RSAPublicKey publicKey) {
        try {
            //Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA");
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
            LiLog.debug(e);
            return null;
        }
    }

    public static byte[] decrypt(byte[] data, String privateKeyStr) {
        RSAPrivateKey privateKey = obtainPrivateKeyFromBase64(privateKeyStr);
        return decrypt(data, privateKey);
    }

    public static byte[] decrypt(byte[] data, RSAPrivateKey privateKey) {
        try {
            //Cipher cipher = Cipher.getInstance("RSA", new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA");
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
            LiLog.debug(e);
            return null;
        }
    }

    public static String sign(byte[] data, String privateKeyStr) {
        RSAPrivateKey privateKey = obtainPrivateKeyFromBase64(privateKeyStr);
        return sign(data, privateKeyStr);
    }

    public static String sign(byte[] data, RSAPrivateKey privateKey) {
        if (privateKey == null) {
            LiLog.debug("private key is null");
            return null;
        }
        try {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            return LiBase64.encode(signature.sign());
        } catch (Exception e) {
            LiLog.debug(e);
            return null;
        }
    }

    public static boolean verify(byte[] data, String publicKeyStr, String sign) {
        RSAPublicKey publicKey = obtainPublicKeyFromBase64(publicKeyStr);
        return verify(data, publicKey, sign);
    }

    public static boolean verify(byte[] data, RSAPublicKey publicKey, String sign) {
        if (publicKey == null) {
            LiLog.debug("public key is null");
            return false;
        }
        try {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(LiBase64.decode(sign));
        } catch (Exception e) {
            LiLog.debug(e);
            return false;
        }
    }

    public static RSAPublicKey obtainPublicKeyFormEncoded(byte[] data) {
        if (data.length == 0) {
            LiLog.debug("data is empty");
            return null;
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            //Only RSAPublicKeySpec and X509EncodedKeySpec supported for RSA public keys
            return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(data));
        } catch (Exception e) {
            LiLog.debug(e);
            return null;
        }
    }

    public static RSAPrivateKey obtainPrivateKeyFormEncoded(byte[] data) {
        if (data.length == 0) {
            LiLog.debug("data is empty");
            return null;
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            try {
                return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(data));
            } catch (InvalidKeySpecException e) {
                LiLog.debug(e);
                return (RSAPrivateKey) keyFactory.generatePrivate(new X509EncodedKeySpec(data));
            }
        } catch (Exception e) {
            LiLog.debug(e);
            return null;
        }
    }

    public static RSAPublicKey obtainPublicKeyFromBase64(String publicKeyStr) {
        publicKeyStr = ignoreKeyStringTag(publicKeyStr);
        byte[] data = LiBase64.decode(publicKeyStr);
        return obtainPublicKeyFormEncoded(data);
    }

    public static RSAPrivateKey obtainPrivateKeyFromBase64(String privateKeyStr) {
        privateKeyStr = ignoreKeyStringTag(privateKeyStr);
        byte[] data = LiBase64.decode(privateKeyStr);
        return obtainPrivateKeyFormEncoded(data);
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

    public static RSAPublicKey obtainPublicKeyFromFile(String pemPath) {
        try {
            return obtainPublicKeyFromBase64(LiFile.readText(pemPath));
        } catch (Exception e) {
            LiLog.debug(e);
            return null;
        }
    }

    public static RSAPrivateKey obtainPrivateKeyFromFile(String pemPath) {
        try {
            return obtainPrivateKeyFromBase64(LiFile.readText(pemPath));
        } catch (Exception e) {
            LiLog.debug(e);
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
            LiLog.debug(e);
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
            LiLog.debug(e);
            return null;
        }
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
        LiLog.debug(sb);
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
        LiLog.debug(sb);
    }

}