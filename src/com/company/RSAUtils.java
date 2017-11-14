package com.company;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * RSA工具类，参阅：http://blog.csdn.net/jdsjlzx/article/details/41441147、http://blog.csdn.net/boonya/article/details/52091957
 */
public final class RSAUtils {
    private static final String PUBLIC_KEY_BEGIN = "-----BEGIN RSA PUBLIC KEY-----";
    private static final String PUBLIC_KEY_END = "-----END RSA PUBLIC KEY-----";
    private static final String PRIVATE_KEY_BEGIN = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PRIVATE_KEY_END = "-----END RSA PRIVATE KEY-----";
    private static final int MAX_ENCRYPT_BLOCK = 117;//RSA最大加密明文大小
    private static final int MAX_DECRYPT_BLOCK = 128;//RSA最大解密密文大小

    public static void generateRSAKeyFile(String publicKeyPath, String privateKeyPath) {
        KeyPair keyPair = generateRSAKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        byte[] publicKeyData = publicKey.getEncoded();
        String publicKeyStr = PUBLIC_KEY_BEGIN + "\n" + Base64Utils.encode(publicKeyData) + "\n" + PUBLIC_KEY_END;
        FileUtils.writeText(publicKeyPath, publicKeyStr);
        byte[] privateKeyData = privateKey.getEncoded();
        String privateKeyStr = PRIVATE_KEY_BEGIN + "\n" + Base64Utils.encode(privateKeyData) + "\n" + PRIVATE_KEY_END;
        FileUtils.writeText(privateKeyPath, privateKeyStr);
    }

    /**
     * 随机生成RSA密钥对
     */
    public static KeyPair generateRSAKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);//密钥长度范围：512～2048， 一般1024
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用公钥加密，每次加密的字节数，不能超过密钥的长度值减去11。
     * 对于RSA加解密算法，Android上的RSA实现是"RSA/None/NoPadding"，标准JDK实现是"RSA/None/PKCS1Padding"，需要添加bcprov-jdk15-143.jar来兼容。
     *
     * @param decryptedData 需加密数据的byte数据
     * @param publicKey     公钥
     * @return 加密后的byte型数据
     */
    public static byte[] encryptDataByPublicKey(byte[] decryptedData, RSAPublicKey publicKey) {
        try {
            //Cipher cipher = Cipher.getInstance("RSA",new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int length = decryptedData.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段加密
            while (length - offSet > 0) {
                if (length - offSet > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(decryptedData, offSet, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(decryptedData, offSet, length - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] encryptedData = out.toByteArray();
            out.close();
            return encryptedData;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 用私钥解密
     *
     * @param encryptedData 经过{@link #encryptDataByPublicKey(byte[], RSAPublicKey)}加密返回的byte数据
     * @param privateKey    私钥
     */
    public static byte[] decryptDataByPrivatekey(byte[] encryptedData, RSAPrivateKey privateKey) {
        try {
            //Cipher cipher = Cipher.getInstance("RSA",new BouncyCastleProvider());
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            int length = encryptedData.length;
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;
            // 对数据分段解密
            while (length - offSet > 0) {
                if (length - offSet > MAX_DECRYPT_BLOCK) {
                    cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(encryptedData, offSet, length - offSet);
                }
                out.write(cache, 0, cache.length);
                i++;
                offSet = i * MAX_DECRYPT_BLOCK;
            }
            byte[] decryptedData = out.toByteArray();
            out.close();
            return decryptedData;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 通过公钥byte[](publicKey.getEncoded())将公钥还原，适用于RSA算法
     */
    public static RSAPublicKey loadPublicKeyFormEncoded(byte[] keyBytes) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 通过私钥byte[]将公钥还原，适用于RSA算法
     */
    public static RSAPrivateKey loadPrivateKeyFormEncoded(byte[] keyBytes) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 使用N、e值还原公钥
     */
    public static RSAPublicKey loadPublicKeyFromModulus(String modulus, String publicExponent) {
        try {
            BigInteger bigIntModulus = new BigInteger(modulus);
            BigInteger bigIntPrivateExponent = new BigInteger(publicExponent);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 使用N、d值还原私钥
     */
    public static RSAPrivateKey loadPrivateKeyFromModulus(String modulus, String privateExponent) {
        try {
            BigInteger bigIntModulus = new BigInteger(modulus);
            BigInteger bigIntPrivateExponent = new BigInteger(privateExponent);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bigIntModulus, bigIntPrivateExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 从字符串中加载公钥
     *
     * @param publicKeyStr 公钥数据字符串
     */
    public static RSAPublicKey loadPublicKeyFromBase64(String publicKeyStr) {
        try {
            byte[] buffer = Base64Utils.decode(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            return null;
        }
    }

    public static RSAPrivateKey loadPrivateKeyFromBase64(String privateKeyStr) {
        return loadPrivateKeyFromBase64(privateKeyStr, "PKCS#8");
    }

    /**
     * 从字符串中加载私钥<br>
     * 加载时使用的是PKCS8EncodedKeySpec（PKCS#8编码的Key指令）。
     */
    public static RSAPrivateKey loadPrivateKeyFromBase64(String privateKeyStr, String format) {
        try {
            byte[] buffer = Base64Utils.decode(privateKeyStr);
            KeySpec keySpec;
            if (format.equals("PKCS#8")) {
                keySpec = new PKCS8EncodedKeySpec(buffer);
            } else {
                keySpec = new X509EncodedKeySpec(buffer);
            }
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 从文件中输入流中加载公钥
     *
     * @param path 公钥文件名
     */
    public static RSAPublicKey loadPublicKeyFromFile(String path) {
        try {
            return loadPublicKeyFromBase64(readKeyFromFile(path));
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 从文件中加载私钥
     *
     * @param path 私钥文件名
     */
    public static RSAPrivateKey loadPrivateKeyFromFile(String path) {
        try {
            return loadPrivateKeyFromBase64(readKeyFromFile(path));
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 读取密钥信息
     */
    private static String readKeyFromFile(String path) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(path)));
        StringBuilder sb = new StringBuilder();
        while (true) {
            String readLine = br.readLine();
            if (readLine == null) {
                break;
            } else {
                //忽略秘钥文件首尾的标识串
                if (readLine.charAt(0) != '-') {
                    sb.append(readLine).append('\n');
                }
            }
        }
        return sb.toString();
    }

    /**
     * 打印公钥信息
     */
    public static void printPublicKeyInfo(RSAPublicKey publicKey) {
        System.out.println("----------RSA PublicKey----------");
        System.out.println("Format=" + publicKey.getFormat());
        System.out.println("Algorithm=" + publicKey.getAlgorithm());
        System.out.println("Modulus.length=" + publicKey.getModulus().bitLength());
        System.out.println("Modulus=" + publicKey.getModulus().toString());
        System.out.println("PublicExponent.length=" + publicKey.getPublicExponent().bitLength());
        System.out.println("PublicExponent=" + publicKey.getPublicExponent().toString());
    }

    public static void printPrivateKeyInfo(RSAPrivateKey privateKey) {
        System.out.println("----------RSA PrivateKey ----------");
        System.out.println("Format=" + privateKey.getFormat());
        System.out.println("Algorithm=" + privateKey.getAlgorithm());
        System.out.println("Modulus.length=" + privateKey.getModulus().bitLength());
        System.out.println("Modulus=" + privateKey.getModulus().toString());
        System.out.println("PrivateExponent.length=" + privateKey.getPrivateExponent().bitLength());
        System.out.println("PrivatecExponent=" + privateKey.getPrivateExponent().toString());
    }

}