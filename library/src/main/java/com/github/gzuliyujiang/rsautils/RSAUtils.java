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

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import com.github.gzuliyujiang.logger.Logger;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

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
    private static final int MAX_ENCRYPT_BLOCK = 117;
    private static final int MAX_DECRYPT_BLOCK = 128;
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final String PREF_KEY_AES_KEY = "pk.aes_key";
    private static final String PREF_KEY_IV = "pk.iv";
    @SuppressWarnings("CharsetObjectCanBeUsed")
    private static final Charset CHARSET = Charset.forName("UTF-8");
    private SharedPreferences sharedPreferences;
    private String alias;
    private KeyStore keyStore;

    private RSAUtils(Context context, String alias) {
        try {
            sharedPreferences = context.getSharedPreferences("KEYSTORE_SETTINGS", Context.MODE_PRIVATE);
            this.alias = alias;
            keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            if (!keyStore.containsAlias(alias)) {
                generateKeyPairUseAKS(context, alias);
                generateAESKey();
            }
        } catch (Exception e) {
            Logger.print(e);
        }
    }

    @Nullable
    public static byte[] encryptUseAKS(Context context, String alias, byte[] plainBytes) {
        try {
            RSAUtils rsaUtils = new RSAUtils(context, alias);
            return rsaUtils.encryptByAES(plainBytes);
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    @Nullable
    public static byte[] decryptUseAKS(Context context, String alias, byte[] encryptedBytes) {
        try {
            RSAUtils rsaUtils = new RSAUtils(context, alias);
            return rsaUtils.decryptByAES(encryptedBytes);
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    private String encryptByRSA(String plainText) throws Exception {
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(CHARSET));
        return Base64Utils.encode(encryptedBytes, CHARSET);
    }

    private byte[] decryptByRSA(String encryptedText) throws Exception {
        //noinspection CharsetObjectCanBeUsed
        Charset charset = Charset.forName("UTF-8");
        byte[] encryptedBytes = Base64Utils.decode(encryptedText.getBytes(CHARSET));
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedBytes);
    }

    private void generateAESKey() throws Exception {
        byte[] aesKey = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(aesKey);
        byte[] generated = secureRandom.generateSeed(12);
        String iv = Base64Utils.encode(generated, CHARSET);
        String encryptAESKey = encryptByRSA(Base64Utils.encode(aesKey, CHARSET));
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString(PREF_KEY_IV, iv);
        editor.putString(PREF_KEY_AES_KEY, encryptAESKey);
        editor.apply();
    }

    private byte[] encryptByAES(byte[] plainBytes) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, getAESKey(), new IvParameterSpec(getIV()));
        return cipher.doFinal(plainBytes);
    }

    private byte[] decryptByAES(byte[] encryptedBytes) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.DECRYPT_MODE, getAESKey(), new IvParameterSpec(getIV()));
        return cipher.doFinal(encryptedBytes);
    }

    private byte[] getIV() {
        String prefIV = sharedPreferences.getString(PREF_KEY_IV, "");
        return Base64Utils.decode(prefIV, CHARSET);
    }

    private SecretKeySpec getAESKey() throws Exception {
        String prefAESKey = sharedPreferences.getString(PREF_KEY_AES_KEY, "");
        byte[] aesKey = decryptByRSA(Objects.requireNonNull(prefAESKey));
        return new SecretKeySpec(aesKey, AES_MODE);
    }

    @Nullable
    public static KeyPair generateKeyPairUseAKS(Context context, String alias) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                return generateKeyPairAboveApi23(alias);
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                return generateKeyPairApi18ToApi22(context, alias);
            } else {
                throw new RuntimeException(KEYSTORE_PROVIDER + "不支持 Android SDK " + Build.VERSION.SDK_INT);
            }
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private static KeyPair generateKeyPairAboveApi23(String alias) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,
                KEYSTORE_PROVIDER);
        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec
                .Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .build();
        keyPairGenerator.initialize(keyGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    private static KeyPair generateKeyPairApi18ToApi22(Context context, String alias) throws Exception {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 30);
        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setSubject(new X500Principal("CN=" + alias))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", KEYSTORE_PROVIDER);
        keyPairGenerator.initialize(spec);
        return keyPairGenerator.generateKeyPair();
    }

    @Nullable
    public static KeyPair generateKeyPairUseJKS(File jksFile, String jksPwd, String alias, String pwd) {
        try {
            return generateKeyPairUseJKS(new FileInputStream(jksFile), jksPwd, alias, pwd);
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    @Nullable
    public static KeyPair generateKeyPairUseJKS(InputStream jksStream, String jksPwd, String alias, String pwd) {
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

    @Nullable
    public static KeyPair generateKeyPairUseRandom() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            //密钥长度范围：512～2048， 一般1024
            generator.initialize(1024);
            return generator.genKeyPair();
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    public static String encodePublicKeyToString(RSAPublicKey publicKey, boolean excludeTag) {
        String encode = Base64Utils.encode(publicKey.getEncoded(), CHARSET);
        if (excludeTag) {
            return encode;
        }
        return PUBLIC_KEY_BEGIN + "\n" + encode + "\n" + PUBLIC_KEY_END;
    }

    public static String encodePrivateKeyToString(RSAPrivateKey privateKey, boolean excludeTag) {
        String encode = Base64Utils.encode(privateKey.getEncoded(), CHARSET);
        if (excludeTag) {
            return encode;
        }
        return PRIVATE_KEY_BEGIN + "\n" + encode + "\n" + PRIVATE_KEY_END;
    }

    public static byte[] encryptUsePK(byte[] data, String publicKeyStr) {
        RSAPublicKey publicKey = obtainPublicKeyFromBase64(publicKeyStr);
        return encryptUsePK(data, publicKey);
    }

    public static byte[] encryptUsePK(byte[] data, RSAPublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_MODE);
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

    public static byte[] decryptUsePK(byte[] data, String privateKeyStr) {
        RSAPrivateKey privateKey = obtainPrivateKeyFromBase64(privateKeyStr);
        return decryptUsePK(data, privateKey);
    }

    public static byte[] decryptUsePK(byte[] data, RSAPrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_MODE);
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

    public static String sign(byte[] data, String privateKeyStr) {
        RSAPrivateKey privateKey = obtainPrivateKeyFromBase64(privateKeyStr);
        return sign(data, privateKey);
    }

    public static String sign(byte[] data, RSAPrivateKey privateKey) {
        if (privateKey == null) {
            Logger.print("private key is null");
            return null;
        }
        try {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            return Base64Utils.encode(signature.sign(), CHARSET);
        } catch (Exception e) {
            Logger.print(e);
            return null;
        }
    }

    public static boolean verify(byte[] data, String publicKeyStr, String sign) {
        RSAPublicKey publicKey = obtainPublicKeyFromBase64(publicKeyStr);
        return verify(data, publicKey, sign);
    }

    public static boolean verify(byte[] data, RSAPublicKey publicKey, String sign) {
        if (publicKey == null) {
            Logger.print("public key is null");
            return false;
        }
        try {
            Signature signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(Base64Utils.decode(sign, CHARSET));
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
        byte[] data = Base64Utils.decode(publicKeyStr, CHARSET);
        return obtainPublicKeyFromEncoded(data);
    }

    public static RSAPrivateKey obtainPrivateKeyFromBase64(String privateKeyStr) {
        privateKeyStr = ignoreKeyStringTag(privateKeyStr);
        byte[] data = Base64Utils.decode(privateKeyStr, CHARSET);
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
        return FileUtils.writeText(file, encodePublicKeyToString(publicKey, false));
    }

    public static boolean savePrivateKeyToFile(File file, RSAPrivateKey privateKey) {
        return FileUtils.writeText(file, encodePrivateKeyToString(privateKey, false));
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