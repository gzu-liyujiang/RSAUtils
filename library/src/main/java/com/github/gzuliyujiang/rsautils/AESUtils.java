/*
 * Copyright (c) 2019-2020 gzu-liyujiang <1032694760@qq.com>
 *
 * The software is licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 *
 */
package com.github.gzuliyujiang.rsautils;

import com.github.gzuliyujiang.logger.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES加解密
 * Created by liyujiang on 2020/06/15
 */
public class AESUtils {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    public static String encryptToBase64(byte[] data, String secretKey) {
        try {
            return Base64Utils.encodeToString(encrypt(data, secretKey));
        } catch (Throwable e) {
            Logger.print(e);
        }
        return "";
    }

    public static byte[] encrypt(byte[] data, String secretKey) throws Exception {
        return convert(data, secretKey, Cipher.ENCRYPT_MODE);
    }

    public static byte[] decryptFromBase64(String base64, String secretKey) {
        try {
            return decrypt(Base64Utils.decodeFromString(base64), secretKey);
        } catch (Throwable e) {
            Logger.print(e);
        }
        return null;
    }

    public static byte[] decrypt(byte[] data, String secretKey) throws Exception {
        return convert(data, secretKey, Cipher.DECRYPT_MODE);
    }

    private static byte[] convert(byte[] data, String secretKey, int opMode) throws Exception {
        if (data == null || data.length == 0) {
            throw new IllegalArgumentException("data cannot be empty");
        }
        // AES密钥长度须为16位
        String secretKey16 = ChecksumUtils.md5(secretKey.getBytes(), true);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey16.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(secretKey.getBytes());
        cipher.init(opMode, secretKeySpec, ivParameterSpec);
        return cipher.doFinal(data);
    }

}
