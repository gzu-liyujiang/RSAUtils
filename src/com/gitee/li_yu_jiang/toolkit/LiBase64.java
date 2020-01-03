package com.gitee.li_yu_jiang.toolkit;

import android.util.Base64;

import java.util.regex.Pattern;

/**
 * BASE64编码解码工具类。
 *
 * @author 大定府羡民
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public final class LiBase64 {

    private LiBase64() {
    }

    /**
     * 判断字符串是否BASE64编码：
     * 1.字符串只可能包含A-Z，a-z，0-9，+，/，=字符
     * 2.字符串长度是4的倍数
     * 3.=只会出现在字符串最后，可能没有或者一个等号或者两个等号
     */
    public static boolean isBase64(String str) {
        if (LiString.isBlank(str)) {
            return false;
        }
        String base64Pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";
        return Pattern.matches(base64Pattern, str);
    }

    public static String encode(byte[] data) {
        return Base64.encodeToString(data, Base64.DEFAULT).trim();
    }

    public static byte[] decode(String str) {
        return Base64.decode(str, Base64.DEFAULT);
    }

}
