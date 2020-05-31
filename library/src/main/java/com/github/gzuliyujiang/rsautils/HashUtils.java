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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 哈希编码类。
 *
 * @author 大定府羡民
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public final class HashUtils {

    private HashUtils() {
        super();
    }

    public static String sha1(String str) {
        return calculate(str.getBytes(), "SHA-1");
    }

    public static String sha256(String str) {
        return calculate(str.getBytes(), "SHA-256");
    }

    public static String md5(String str) {
        return md5(str, false);
    }

    public static String md5(String str, boolean length16) {
        return md5(str.getBytes(), length16);
    }

    public static String md5(byte[] data, boolean length16) {
        String str = calculate(data, "MD5");
        //MD5值一般分16位和32位，默认为32位，16位实际上是从32位字符串中去掉前8位和后8位
        if (length16) {
            return str.substring(8, 24);
        }
        return str;
    }

    /**
     * 计算哈希值，算法可以是MD2、MD5、SHA-1、SHA-256等
     */
    public static String calculate(byte[] data, String algorithm) {
        try {
            byte[] bytes = MessageDigest.getInstance(algorithm).digest(data);
//            char chars[] = new char[bytes.length * 2];
//            final char HEX_CODE[] = {'0', '1', '2', '3', '4', '5', '6', '7',
//                    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
//            int i = 0;
//            for (byte b : bytes) {
//                chars[i++] = HEX_CODE[b >>> 4 & 0xf];
//                chars[i++] = HEX_CODE[b & 0xf];
//            }
//            String str = new String(chars);
            StringBuilder sb = new StringBuilder();
            for (byte aByte : bytes) {
                sb.append(String.format("%02x", aByte));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

}
