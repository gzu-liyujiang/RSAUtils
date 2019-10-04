package com.gitee.li_yu_jiang.toolkit;

/**
 * 字符串工具类
 *
 * @author 大定府羡民
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public final class LiString {

    private LiString() {
    }

    public static boolean isBlank(String str) {
        return str == null || str.trim().length() == 0;
    }

    /**
     * Copy from android.text.TextUtils#isEmpty
     */
    public static boolean isEmpty(CharSequence str) {
        return str == null || str.length() == 0;
    }

    /**
     * Copy from android.text.TextUtils#nullIfEmpty
     */
    public static String nullIfEmpty(String str) {
        return isEmpty(str) ? null : str;
    }

    /**
     * Copy from android.text.TextUtils#emptyIfNull
     */
    public static String emptyIfNull(String str) {
        return str == null ? "" : str;
    }

}
