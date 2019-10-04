package com.gitee.li_yu_jiang.logger;

/**
 * 默认的日志打印器
 *
 * @author 大定府羡民
 */
class DefaultPrinter implements IPrinter {

    @Override
    public void print(String msg) {
        System.out.println(msg);
    }

}
