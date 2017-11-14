package com.company;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 文件操作工具类
 */
public class FileUtils {

    public static boolean writeText(String filePath, String content) {
        boolean successful = true;
        FileOutputStream fout = null;
        try {
            File file = new File(filePath);
            File parentFile = file.getParentFile();
            if (!parentFile.exists()) {
                //noinspection ResultOfMethodCallIgnored
                parentFile.mkdirs();
            }
            fout = new FileOutputStream(file, false);
            fout.write(content.getBytes("utf-8"));
        } catch (FileNotFoundException e1) {
            successful = false;
        } catch (IOException e) {
            e.printStackTrace();
            successful = false;
        } finally {
            if (fout != null) {
                try {
                    fout.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return successful;
    }

    public static String readText(String filePath) {
        FileInputStream fin = null;
        try {
            File file = new File(filePath);
            if (!file.exists()) {
                return "";
            }
            StringBuilder sb = new StringBuilder();
            fin = new FileInputStream(file);
            byte[] buffer = new byte[2048];
            while (true) {
                int len = fin.read(buffer);
                if (len == -1) {
                    break;
                } else {
                    sb.append(new String(buffer, 0, len, "utf-8"));
                }
            }
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (fin != null) {
                try {
                    fin.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return "";
    }

}
