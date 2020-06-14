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

/**
 * RC4加解密
 * 在线工具：http://tool.chacuo.net/cryptrc4
 * 参阅：https://blog.csdn.net/u012722296/article/details/81040266\
 * Created by liyujiang on 2019/11/11
 */
public class RC4Utils {

    /**
     * RC4加解密，会自动识别传入的是密文还是明文
     */
    public static byte[] convert(byte[] data, String secretKey) {
        if (data == null || data.length == 0) {
            return new byte[0];
        }
        if (secretKey == null || secretKey.trim().length() == 0) {
            throw new IllegalArgumentException("Key cannot be empty");
        }
        //初始化密钥
        byte[] bkey = secretKey.getBytes();
        if (bkey.length > 256) {
            throw new IllegalArgumentException("Key length must 1-256");
        }
        byte[] key = new byte[256];
        for (int i = 0; i < 256; i++) {
            key[i] = (byte) i;
        }
        int index1 = 0;
        int index2 = 0;
        if (bkey.length == 0) {
            return null;
        }
        for (int i = 0; i < 256; i++) {
            index2 = ((bkey[index1] & 0xff) + (key[i] & 0xff) + index2) & 0xff;
            byte tmp = key[i];
            key[i] = key[index2];
            key[index2] = tmp;
            index1 = (index1 + 1) % bkey.length;
        }
        //开始加解密
        int x = 0;
        int y = 0;
        int xorIndex;
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            x = (x + 1) & 0xff;
            y = ((key[x] & 0xff) + y) & 0xff;
            byte tmp = key[x];
            key[x] = key[y];
            key[y] = tmp;
            xorIndex = ((key[x] & 0xff) + (key[y] & 0xff)) & 0xff;
            result[i] = (byte) (data[i] ^ key[xorIndex]);
        }
        return result;
    }

}
