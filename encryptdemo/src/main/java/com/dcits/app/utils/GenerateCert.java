package com.dcits.app.utils;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

import java.math.BigInteger;
import java.security.*;

public class GenerateCert {

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        SecureRandom sr = new SecureRandom();
        keygen.initialize(2048, sr);
        KeyPair keyPair = keygen.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
        System.out.println("privateKey:" + privKey + ",publicKey:" + pubKey);
        return keyPair;
    }

    public void generateKeyPair_bc() {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(3), new SecureRandom(), 2048, 80));
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
        RSAKeyParameters pubKey = (RSAKeyParameters) keyPair.getPublic();
        RSAPrivateCrtKeyParameters priKey = (RSAPrivateCrtKeyParameters) keyPair.getPrivate();
    }
}
