package com.gitee.li_yu_jiang.logger;

import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * <pre>
 * 调试日志输出接口，{@link IPrinter}可选择使用以下开源项目进行实现：
 * https://github.com/orhanobut/logger
 * https://github.com/elvishew/xLog
 * https://github.com/ZhaoKaiQiang/KLog
 * https://github.com/fengzhizi715/SAF-Kotlin-log
 * https://github.com/EsotericSoftware/minlog
 * </pre>
 *
 * @author 大定府羡民
 */
@SuppressWarnings({"unused"})
public class LiLog implements IPrinter {
    public static final String TAG = "liyujiang";
    private static final LiLog LOG = new LiLog();
    private IPrinter instance = new DefaultPrinter();
    private boolean enable = false;

    private LiLog() {
    }

    public static void enable(boolean enable) {
        LOG.enable = enable;
    }

    public static void usePrinter(IPrinter printer) {
        if (printer == null) {
            return;
        }
        LOG.instance = printer;
    }

    public static void debug(Object object) {
        if (!LOG.enable) {
            return;
        }
        String msg;
        if (object instanceof Throwable) {
            msg = toStackTraceString((Throwable) object);
        } else {
            msg = object.toString();
        }
        LOG.instance.print(msg);
    }

    /**
     * Adapted from android.util.Log#getStackTraceString
     */
    private static String toStackTraceString(Throwable tr) {
        if (tr == null) {
            return "";
        }
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw, false);
        tr.printStackTrace(pw);
        pw.flush();
        return sw.toString();
    }

    @Override
    public void print(String msg) {
        LOG.instance.print(msg);
    }

}
