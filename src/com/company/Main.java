package com.company;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Main {

    public static void main(String[] args) {
        //RSAUtils.generateRSAKeyFile("F:/java/RSADemo/public_key.pem", "F:/java/RSADemo/private_key.pem");
        RSAPublicKey publicKey = RSAUtils.loadPublicKeyFromFile("F:/java/RSADemo/public_key.pem");
        RSAUtils.printPublicKeyInfo(publicKey);
        RSAPrivateKey privateKey = RSAUtils.loadPrivateKeyFromFile("F:/java/RSADemo/private_key.pem");
        RSAUtils.printPrivateKeyInfo(privateKey);
    }

}
