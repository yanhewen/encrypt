package com.dcits.app.utils;

import sun.security.x509.*;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

public class X509CertTest {

    private SecureRandom secureRandom;

    public X509CertTest() {
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    /**
     * 颁布证书
     *
     * @param issue
     * @param subject
     * @param issueAlias
     * @param issuePfxPath
     * @param issuePassword
     * @param issueCrtPath
     * @param subjectAlias
     * @param subjectPfxPath
     * @param subjectPassword
     * @param subjectCrtPath
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws CertificateException
     * @throws IOException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @throws SignatureException
     */
    public void createIssueCert(
            X500Name issue,
            X500Name subject,
            String issueAlias,
            String issuePfxPath,
            String issuePassword,
            String issueCrtPath,
            String subjectAlias,
            String subjectPfxPath,
            String subjectPassword,
            String subjectCrtPath)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            CertificateException, IOException, KeyStoreException, UnrecoverableKeyException,
            SignatureException {

        CertAndKeyGen certAndKeyGen = new CertAndKeyGen("RSA", "MD5WithRSA", null);
        certAndKeyGen.setRandom(secureRandom);
        certAndKeyGen.generate(1024);
        String sigAlg = "MD5WithRSA";
        long validity = 3650 * 24L * 60L * 60L;
        Date firstDate = new Date();
        Date lastDate;
        lastDate = new Date();
        lastDate.setTime(firstDate.getTime() + validity * 1000);
        CertificateValidity interval = new CertificateValidity(firstDate, lastDate);
        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(
                X509CertInfo.SERIAL_NUMBER,
                new CertificateSerialNumber(new java.util.Random().nextInt() & 0x7fffffff));
        AlgorithmId algID = AlgorithmId.get(sigAlg);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algID));
        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(subject));
        info.set(X509CertInfo.KEY, new CertificateX509Key(certAndKeyGen.getPublicKey()));
        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(issue));
        PrivateKey privateKey = readPrivateKey(issueAlias, issuePfxPath, issuePassword);
        System.out.println("privateKey:");
        System.out.println(privateKey);
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privateKey, sigAlg);
        X509Certificate certificate = cert;
        X509Certificate issueCertificate = readX509Certificate(issueCrtPath);
        X509Certificate[] X509Certificates = new X509Certificate[]{certificate, issueCertificate};
        createKeyStore(
                subjectAlias,
                certAndKeyGen.getPrivateKey(),
                subjectPassword.toCharArray(),
                X509Certificates,
                subjectPfxPath);

        FileOutputStream fos = new FileOutputStream(new File(subjectCrtPath));
        fos.write(certificate.getEncoded());
        fos.close();
    }

    /**
     * 创建根证书（证书有效期10年，私钥保存密码“123456”，公钥算法“RSA”，签名算法“MD5WithRSA”）
     *
     * @param issuePfxPath Personal Information Exchange 路径
     * @param issueCrtPath 证书路径
     * @param issue        颁发者&接收颁发者
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws CertificateException
     * @throws SignatureException
     * @throws KeyStoreException
     */
    public void createRootCert(String issuePfxPath, String issueCrtPath, X500Name issue)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException,
            CertificateException, SignatureException, KeyStoreException {

        CertAndKeyGen rootCertAndKeyGen = new CertAndKeyGen("RSA", "MD5WithRSA", null);
        rootCertAndKeyGen.setRandom(secureRandom);
        rootCertAndKeyGen.generate(1024);
        X509Certificate rootCertificate =
                rootCertAndKeyGen.getSelfCertificate(issue, 3650 * 24L * 60L * 60L);
        X509Certificate[] X509Certificates = new X509Certificate[]{rootCertificate};
        System.out.println();
        String password = "123456";

        createKeyStore(
                "RootCA",
                rootCertAndKeyGen.getPrivateKey(),
                password.toCharArray(),
                X509Certificates,
                issuePfxPath);

        FileOutputStream fos = new FileOutputStream(new File(issueCrtPath));

        fos.write(rootCertificate.getEncoded());

        fos.close();
    }

    /**
     * 证书私钥存储设施
     *
     * @param alias    KeyStore别名
     * @param key      密钥（这里是私钥）
     * @param password 保存密码
     * @param chain    证书链
     * @param filePath PFX文件路径
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     */
    private void createKeyStore(
            String alias, Key key, char[] password, Certificate[] chain, String filePath)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

        KeyStore keyStore = KeyStore.getInstance("pkcs12");

        keyStore.load(null, password);

        keyStore.setKeyEntry(alias, key, password, chain);

        FileOutputStream fos = new FileOutputStream(filePath);

        keyStore.store(fos, password);

        fos.close();
    }

    /**
     * 读取PFX文件中的私钥
     *
     * @param alias    别名
     * @param pfxPath  PFX文件路径
     * @param password 密码
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws IOException
     * @throws UnrecoverableKeyException
     */
    public PrivateKey readPrivateKey(String alias, String pfxPath, String password)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
            UnrecoverableKeyException {

        KeyStore keyStore = KeyStore.getInstance("pkcs12");

        FileInputStream fis = null;

        fis = new FileInputStream(pfxPath);

        keyStore.load(fis, password.toCharArray());

        fis.close();

        return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
    }

    /**
     * 读取X.509证书
     *
     * @param crtPath 证书路径
     * @return
     * @throws CertificateException
     * @throws IOException
     */
    public X509Certificate readX509Certificate(String crtPath)
            throws CertificateException, IOException {

        InputStream inStream = null;

        inStream = new FileInputStream(crtPath);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);

        inStream.close();

        return cert;
    }

    public static void main(String args[]) throws IOException {

        // CN commonName 一般名字
        // L localityName 地方名
        // ST stateOrProvinceName 州省名
        // O organizationName 组织名
        // OU organizationalUnitName 组织单位名
        // C countryName 国家
        // STREET streetAddress 街道地址
        // DC domainComponent 领域
        // UID user id 用户ID

        X500Name issue = new X500Name("CN=RootCA,OU=ISI,O=BenZeph,L=CD,ST=SC,C=CN");

        X500Name subject = new X500Name("CN=subject,OU=ISI,O=BenZeph,L=CD,ST=SC,C=CN");

        String issuePfxPath = "D://ROOTCA.pfx";
        String issueCrtPath = "D://ROOTCA.crt";

        String subjectPfxPath = "D://ISSUE.pfx";
        String subjectCrtPath = "D://ISSUE.crt";

        String issueAlias = "RootCA";
        String subjectAlias = "subject";

        String issuePassword = "123456";
        String subjectPassword = "123456";

        X509CertTest test = new X509CertTest();

        try {
            test.createRootCert(issuePfxPath, issueCrtPath, issue);
        } catch (InvalidKeyException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch (NoSuchProviderException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch (CertificateException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch (SignatureException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch (KeyStoreException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }

        try {
            test.createIssueCert(
                    issue,
                    subject,
                    issueAlias,
                    issuePfxPath,
                    issuePassword,
                    issueCrtPath,
                    subjectAlias,
                    subjectPfxPath,
                    subjectPassword,
                    subjectCrtPath);
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (SignatureException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
