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
package com.github.gzuliyujiang.demo;

import android.Manifest;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.github.gzuliyujiang.logger.Logger;
import com.github.gzuliyujiang.rsautils.Base64Utils;
import com.github.gzuliyujiang.rsautils.RC4Utils;
import com.github.gzuliyujiang.rsautils.RSAUtils;
import com.yanzhenjie.permission.Action;
import com.yanzhenjie.permission.AndPermission;

import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

@RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
public class MainActivity extends AppCompatActivity {
    private static final String[] PERMISSIONS_All_NEED = {
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE,
    };
    private static final String PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJV1jJ6vjuSlsj8rwKIF0NJAonad\n" +
            "E0PIAQtDuo86ByWrkIeMVPLIBRxhutsAUJ761ewN16zdoaSGJBqT4dazN7lb9Nn9Us71UIxHCMc/\n" +
            "pQljSFPrr1GD2vUfFJu1/HBzpPrOjwBLC80TAuBgQBJ7Uln2kFtdCMFVzYq9FbWSfo/lAgMBAAEC\n" +
            "gYB8CSsjgsUO4qh0HqZmkHcGFpf94kvbo7+iDppkRR8rVx/CLmdNeUwsirrdB3zhA4DHv5EvKFv+\n" +
            "w0hxOith2Cg0hYFmmsJtaeWQgGvZO5NxaK8chL/5fUmEU5pO+qqN+uiTEs/CnGL7WYPEKxzKLXDE\n" +
            "yT9P/I0UnuHkh6THpzUnPQJBAOsE7Y4D0Gk3JG5+M8yVLWUSUi7CwCfdE9Cg5exnucYhlktp1jIk\n" +
            "2ap0b7Vt0kVaZumuc+LGVPsWCRjTyjDDBr8CQQCizUCk3hOZcqs70ieIrCximIscv4qGFvDsVJEj\n" +
            "39J7zAwijC+GCDJI4P10NnoOhVUNHghtEhLn5o3SBUU/2VZbAkEAodeb659OxxX1Ha4E586XGzIZ\n" +
            "rB/rCcihm5shmsH3WazJfhddLNzZlBtozgzZr27IzgWXwkQIQ3xyOUmnxBqZqwJAUJwUwA194uLW\n" +
            "Sl56WL/3kjI531gv/MjrLfmJjBvNGqMj9w82kMUKMO/GT36R3RLD1CTkwyzJ061i13Tonv68NQJB\n" +
            "AM3uOj58rPOAFPmMyy2x+SADvGUvp4YtStfIApSrk297WKSocjmv7LIVC4Izh8vBr/scz70PqTkn\n" +
            "6sZfw+qKdi0=\n" +
            "-----END RSA PRIVATE KEY-----";
    private static final String PUBLIC_KEY = "-----BEGIN RSA PUBLIC KEY-----\n" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVdYyer47kpbI/K8CiBdDSQKJ2nRNDyAELQ7qP\n" +
            "Ogclq5CHjFTyyAUcYbrbAFCe+tXsDdes3aGkhiQak+HWsze5W/TZ/VLO9VCMRwjHP6UJY0hT669R\n" +
            "g9r1HxSbtfxwc6T6zo8ASwvNEwLgYEASe1JZ9pBbXQjBVc2KvRW1kn6P5QIDAQAB\n" +
            "-----END RSA PUBLIC KEY-----";
    @SuppressWarnings("CharsetObjectCanBeUsed")
    private static final Charset CHARSET = Charset.forName("UTF-8");
    private EditText edtPlainText;
    private TextView tvEncryptedData;
    private TextView tvEncryptedPassword;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        checkAllPermissions(this);
        setContentView(R.layout.activity_main);
        edtPlainText = findViewById(R.id.edtPlainText);
        tvEncryptedData = findViewById(R.id.tvEncryptedData);
        tvEncryptedPassword = findViewById(R.id.tvEncryptedPassword);
    }

    private void checkAllPermissions(final Context context) {
        AndPermission.with(context)
                .permission(PERMISSIONS_All_NEED)
                .onDenied(new Action() {
                    @Override
                    public void onAction(List<String> list) {
                        if (AndPermission.hasAlwaysDeniedPermission(context, PERMISSIONS_All_NEED)) {
                            Toast.makeText(context, "部分功能被禁止，被禁止的功能将无法使用", Toast.LENGTH_SHORT).show();
                            Logger.print("部分功能被禁止");
                            MainActivity.this.showNormalDialog(MainActivity.this);
                        }
                    }
                }).start();
    }

    private void showNormalDialog(final Context context) {
        final AlertDialog.Builder normalDialog =
                new AlertDialog.Builder(context);
        normalDialog.setTitle("去申请权限");
        normalDialog.setMessage("部分权限被你禁止了，可能误操作，可能会影响部分功能，是否去要去重新设置？");
        normalDialog.setPositiveButton("是",
                new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        getAppDetailSettingIntent(context);
                    }
                });
        normalDialog.setNegativeButton("否",
                new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                });
        normalDialog.show();
    }

    public void onRSAAndRC4Encrypt(View view) {
        String data = edtPlainText.getText().toString();
        if (TextUtils.isEmpty(data)) {
            Toast.makeText(this, "请输入要加密的内容", Toast.LENGTH_SHORT).show();
            return;
        }
        String password = "123456";
        Logger.print("明文密码：" + password);
        String encryptedData = Base64Utils.encodeToString(RC4Utils.convert(data.getBytes(CHARSET), password));
        Logger.print("RC4加密：" + encryptedData);
        String encryptedPassword = RSAUtils.encrypt(password.getBytes(CHARSET), PUBLIC_KEY);
        Logger.print("密文密码：" + encryptedPassword);
        if (TextUtils.isEmpty(encryptedData) || TextUtils.isEmpty(encryptedPassword)) {
            Toast.makeText(this, "加密失败", Toast.LENGTH_SHORT).show();
            return;
        }
        tvEncryptedData.setText(encryptedData);
        tvEncryptedPassword.setText(encryptedPassword);
    }

    public void onRSAAndRC4Decrypt(View view) {
        String encryptedData = tvEncryptedData.getText().toString();
        Logger.print("RC4密文：" + encryptedData);
        String encryptedPassword = tvEncryptedPassword.getText().toString();
        Logger.print("密文密码：" + encryptedPassword);
        if (TextUtils.isEmpty(encryptedData) || TextUtils.isEmpty(encryptedPassword)) {
            Toast.makeText(this, "还没有加密过数据", Toast.LENGTH_SHORT).show();
            return;
        }
        byte[] decryptedPassword = RSAUtils.decrypt(encryptedPassword, PRIVATE_KEY);
        if (decryptedPassword == null) {
            Toast.makeText(this, "密码解密失败", Toast.LENGTH_SHORT).show();
            return;
        }
        String password = new String(decryptedPassword, CHARSET);
        Logger.print("明文密码：" + password);
        byte[] decryptedData = RC4Utils.convert(Base64Utils.decodeFromString(encryptedData), password);
        if (decryptedData == null) {
            Toast.makeText(this, "使用" + password + "解密失败", Toast.LENGTH_SHORT).show();
            return;
        }
        String data = new String(decryptedData, CHARSET);
        Logger.print("RC4解密：" + data);
        Toast.makeText(this, data, Toast.LENGTH_LONG).show();
    }

    private static void getAppDetailSettingIntent(Context context) {
        Intent intent = new Intent();
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.setAction("android.settings.APPLICATION_DETAILS_SETTINGS");
        intent.setData(Uri.fromParts("package", context.getPackageName(), null));
        context.startActivity(intent);
    }

    public void decodeKeyAndGenerateLicenseKey(View view) {
        RSAPublicKey publicKey = RSAUtils.generatePublicKey(PUBLIC_KEY);
        RSAUtils.printPublicKeyInfo(publicKey);
        RSAPrivateKey privateKey = RSAUtils.generatePrivateKey(PRIVATE_KEY);
        RSAUtils.printPrivateKeyInfo(privateKey);
        final String registerCode = "d0013db0-bc78-4c15-94d9-29e868edbd1b";
        Logger.print("registerCode=" + registerCode);
        String LICENSE_KEY_BEGIN = "-----BEGIN LICENSE KEY-----";
        String LICENSE_KEY_END = "-----END LICENSE KEY-----";
        byte[] sign = RSAUtils.sign(registerCode.getBytes(), privateKey);
        String licenseKey = LICENSE_KEY_BEGIN + "\n" + Base64Utils.encodeToString(sign) + "\n" + LICENSE_KEY_END;
        Logger.print("licenseKey: \n" + licenseKey);
        boolean result = licenseKey.equals("-----BEGIN LICENSE KEY-----\n" +
                "HIgNAP/wjy4vbUQK9hhhtrlkNtjS9/RuNLbHPih3ZO4uf5sE7UfFoNXlmIDHnvxHVuRPE1GS3Uz3\n" +
                "uhHxpkVuJEn6/b4Rg+XUCxbLyYpmzfVhu6JCebChl8taq5uFvfZPhbXiAPVIVL68BYmSYgsoF5u/\n" +
                "AcGXpl5n3Vr4BBwumQg=\n" +
                "-----END LICENSE KEY-----");
        Logger.print("licenseKey equals=" + result);
        result = RSAUtils.verify(registerCode.getBytes(), publicKey, sign);
        Logger.print("verify result=" + result);
        Toast.makeText(this, "LICENSE KEY已生成", Toast.LENGTH_SHORT).show();
    }

    public void generateKeyPair(View view) {
        KeyPair keyPair = RSAUtils.generateKeyPair();
        assert keyPair != null;
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAUtils.printPublicKeyInfo(publicKey);
        RSAUtils.printPrivateKeyInfo(privateKey);
        Toast.makeText(this, "密钥对已生成", Toast.LENGTH_SHORT).show();
    }

}
