package com.dcits.test;

import sun.misc.BASE64Encoder;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class CATest {
    public static void main(String[] args) {
        final String KEYSTORE_FILE = "D://ROOTCA1.pfx";
        final String KEYSTORE_PASSWORD = "123456";
        final String KEYSTORE_ALIAS = "RootCA";

        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            FileInputStream fis = new FileInputStream(KEYSTORE_FILE);

            char[] nPassword = null;
            if ((KEYSTORE_PASSWORD == null) || KEYSTORE_PASSWORD.trim().equals("")) {
                nPassword = null;
            } else {
                nPassword = KEYSTORE_PASSWORD.toCharArray();
            }
            ks.load(fis, nPassword);
            fis.close();

            System.out.println("keystore type=" + ks.getType());

            Enumeration enum1 = ks.aliases();
            String keyAlias = null;
            if (enum1.hasMoreElements()) // we are readin just one certificate.
            {
                keyAlias = (String) enum1.nextElement();
                System.out.println("alias=[" + keyAlias + "]");
            }

            System.out.println("is key entry=" + ks.isKeyEntry(keyAlias));
            PrivateKey prikey = (PrivateKey) ks.getKey(keyAlias, nPassword);
            Certificate cert = ks.getCertificate(keyAlias);
            PublicKey pubkey = cert.getPublicKey();
            BASE64Encoder bse = new BASE64Encoder();
            System.out.println("pk:" + bse.encode(pubkey.getEncoded()));
            System.out.println("cert class = " + cert.getClass().getName());
            System.out.println("cert = " + cert);
            System.out.println("public key = " + pubkey);
            System.out.println("pubkey.getAlgorithm()：" + pubkey.getAlgorithm());
            System.out.println("pubkey.getEncoded()：" + pubkey.getEncoded());
            System.out.println("pubkey.getFormat()：" + pubkey.getFormat());
            System.out.println("private key = " + prikey);

            ///
            String encoded = bse.encode(prikey.getEncoded());
            System.out.println("—–BEGIN PRIVATE KEY—–\n");
            System.out.println(encoded);
            System.out.println("—–END PRIVATE KEY—–");
            ///
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
