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

import com.github.gzuliyujiang.logger.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;

/**
 * 文件操作工具类
 *
 * @author 大定府羡民
 */
@SuppressWarnings({"UnusedReturnValue", "unused", "WeakerAccess"})
public final class FileUtils {

    private FileUtils() {
        super();
    }

    public static boolean writeText(File file, String content) {
        boolean successful = true;
        FileOutputStream fout = null;
        try {
            File parentFile = file.getParentFile();
            if (parentFile != null && !parentFile.exists()) {
                //noinspection ResultOfMethodCallIgnored
                parentFile.mkdirs();
            }
            fout = new FileOutputStream(file, false);
            //noinspection CharsetObjectCanBeUsed
            fout.write(content.getBytes(Charset.forName("UTF-8")));
        } catch (IOException e) {
            Logger.print(e);
            successful = false;
        } finally {
            if (fout != null) {
                try {
                    fout.close();
                } catch (IOException ignore) {
                }
            }
        }
        return successful;
    }

    public static String readText(File file) {
        FileInputStream inputStream = null;
        try {
            if (!file.exists()) {
                Logger.print("file not exists " + file);
                return "";
            }
            StringBuilder sb = new StringBuilder();
            inputStream = new FileInputStream(file);
            byte[] buffer = new byte[2048];
            while (true) {
                int len = inputStream.read(buffer);
                if (len == -1) {
                    break;
                } else {
                    //noinspection CharsetObjectCanBeUsed
                    sb.append(new String(buffer, 0, len, Charset.forName("UTF-8")));
                }
            }
            return sb.toString();
        } catch (Exception e) {
            Logger.print(e);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException ignore) {
                }
            }
        }
        return "";
    }

}
