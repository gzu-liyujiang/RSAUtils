package com.gitee.li_yu_jiang.demo;

import com.gitee.li_yu_jiang.toolkit.LiHash;
import com.gitee.li_yu_jiang.toolkit.LiRSA;
import com.gitee.li_yu_jiang.logger.LiLog;
import com.gitee.li_yu_jiang.toolkit.LiFile;

import java.io.File;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Main {
    private static final String PROJECT_PATH = new File(System.getProperty("user.dir")).getAbsolutePath() + File.separator;
    private static final String JKS_PATH = PROJECT_PATH + "test.jks";
    private static final String JKS_STORE_PASSWORD = "123456";
    private static final String JKS_ALIAS = "test";
    private static final String JKS_KEY_PASSWORD = "666666";
    private static final String PRIVATE_KEY_PEM_PATH = PROJECT_PATH + "private_key.pem";
    private static final String PUBLIC_KEY_PEM_PATH = PROJECT_PATH + "public_key.pem";

    static {
        LiLog.enable(true);
    }

    public static void main(String[] args) {
        //generatePemFile();
        //printKayPairInfo();
        //signAndVerify();
        loadJKSFile();
    }

    private static void generatePemFile() {
        KeyPair keyPair = LiRSA.genKeyPairByRandom();
        assert keyPair != null;
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        LiFile.writeText(PUBLIC_KEY_PEM_PATH, LiRSA.encodeToString(publicKey, false));
        LiFile.writeText(PRIVATE_KEY_PEM_PATH, LiRSA.encodeToString(privateKey, false));
    }

    private static void printKayPairInfo() {
        RSAPublicKey publicKey = LiRSA.obtainPublicKeyFromFile(PUBLIC_KEY_PEM_PATH);
        assert publicKey != null;
        LiRSA.printPublicKeyInfo(publicKey);
        RSAPrivateKey privateKey = LiRSA.obtainPrivateKeyFromFile(PRIVATE_KEY_PEM_PATH);
        assert privateKey != null;
        LiRSA.printPrivateKeyInfo(privateKey);
    }

    private static void signAndVerify() {
        String serial = "这是序列号";
        LiLog.debug("serial: " + serial);
        String hash = LiHash.md5(serial);
        LiLog.debug("serial MD5: " + hash);
        RSAPrivateKey privateKey = LiRSA.obtainPrivateKeyFromFile(PRIVATE_KEY_PEM_PATH);
        String sign = LiRSA.sign(serial.getBytes(), privateKey);
        LiLog.debug("signature: " + sign);
        RSAPublicKey publicKey = LiRSA.obtainPublicKeyFromFile(PUBLIC_KEY_PEM_PATH);
        boolean result = LiRSA.verify(serial.getBytes(), publicKey, sign);
        LiLog.debug("verify result: " + result);
    }

    private static void loadJKSFile() {
        KeyPair keyPair = LiRSA.genKeyPairByJKSFile(JKS_PATH, JKS_STORE_PASSWORD, JKS_ALIAS, JKS_KEY_PASSWORD);
        assert keyPair != null;
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        LiRSA.printPublicKeyInfo(publicKey);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        LiRSA.printPrivateKeyInfo(privateKey);
        final String machineCode = "DDDSSFSSSSFFFF";
        LiLog.debug("machineCode=" + machineCode);
        String ACTIVATION_CODE_BEGIN = "-----BEGIN ACTIVATION CODE-----";
        String ACTIVATION_CODE_END = "-----END ACTIVATION CODE-----";
        String sign = LiRSA.sign(machineCode.getBytes(), privateKey);
        String activationCode = ACTIVATION_CODE_BEGIN + "\n" + sign + "\n" + ACTIVATION_CODE_END;
        LiLog.debug("activationCode: \n" + activationCode);
        boolean result = activationCode.equals("-----BEGIN ACTIVATION CODE-----\n" +
                "aoMS0j8x9UXEB7RDMLnWFnrm8L0yBlpwKuuB4/" +
                "N1sk7Rsg4RtlG3X6A9gEKNoFSeowchbt7Qa6Iw1" +
                "fxFkGD7euKPb3/snP0WXp9HA0IxE1ILCuNkolfK4" +
                "1v7+zwda7xgk3EkBdPkOsxAdJEHzO/ji55v8aEj" +
                "0EpDIua+ieia8Q3mT3dXkobQDN50buQI06IFybef" +
                "PECmHnWOcT2EeHtJPLE84okiT+bxOiSTM0fQvWX" +
                "BD29XjIAQ2XkQqPHzk6AOSJraKlVASaTaEqSDY+" +
                "3pWYN3DSqKelN8mbmr3mBDs0Yi0xatcjph1R1qU" +
                "wNEdtff/nfbn8bVEZYUG+nItYMWfQ==\n" +
                "-----END ACTIVATION CODE-----");
        LiLog.debug("activationCode equals=" + result);
        result = LiRSA.verify(machineCode.getBytes(), publicKey, sign);
        LiLog.debug("verify result=" + result);
    }

}
