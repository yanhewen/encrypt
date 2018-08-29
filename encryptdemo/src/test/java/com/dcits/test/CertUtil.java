package com.dcits.test;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * 类名: CertUtil 描述: p12证书工具类 版本: V1.0 modify 2017年4月3日 上午09:06:37 copyright.
 */
public class CertUtil {

    private static Logger logger = Logger.getLogger(CertUtil.class);
    private static KeyStore keyStore;

    private static String CERT_PATH;
    private static String CERT_PWD;
    private static final String KEY_STORE_TYPE = "PKCS12";

    static {
        Properties prop = new Properties();
        try {
            prop.load(
                    Thread.currentThread()
                            .getContextClassLoader()
                            .getResourceAsStream("test/test/cert.properties"));
        } catch (Exception e) {
            logger.error("fail to read cert.properties...");
        }
        CERT_PATH = prop.getProperty("cert_path");
        CERT_PWD = prop.getProperty("cert_pwd");

        if (keyStore == null) {
            try {
                keyStore = initKeyStore();
            } catch (Exception e) {
                logger.error("fail to init keystore...");
            }
        }
    }

    /**
     * 方法: getPrivateKey 描述: 获取私钥
     *
     * @return
     */
    public static PrivateKey getPrivateKey() throws Exception {
        return (PrivateKey) keyStore.getKey(getAlias(), CertUtil.CERT_PWD.toCharArray());
    }

    /**
     * 方法: getPublicKey 描述: 获取公钥
     *
     * @return
     */
    public static PublicKey getPublicKey() throws Exception {
        return getCertificate().getPublicKey();
    }

    /**
     * 方法: getAlias 描述: 获取第一个别名
     *
     * @return
     */
    public static String getAlias() throws Exception {
        Enumeration<String> aliases = keyStore.aliases();
        if (aliases.hasMoreElements()) {
            return aliases.nextElement();
        }
        return null;
    }

    /**
     * 方法: initKeyStore 描述: 获取密钥库
     *
     * @return
     */
    public static KeyStore initKeyStore() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = KeyStore.getInstance(CertUtil.KEY_STORE_TYPE);
        // 绝对路径
        InputStream is = new FileInputStream(new File(CertUtil.CERT_PATH));
        // 相对路径
        // InputStream is =
        // Thread.currentThread().getContextClassLoader().getResourceAsStream(CertUtil.CERT_PATH);
        ks.load(is, CertUtil.CERT_PWD.toCharArray());
        is.close();
        return ks;
    }

    /**
     * 方法: getCertificate 描述: 获取证书
     *
     * @return
     */
    public static Certificate getCertificate() throws Exception {
        return keyStore.getCertificate(getAlias());
    }

    /**
     * 方法: getCipher 描述: 获取Cipher
     *
     * @param isPublic 是否公钥模式
     * @param mode     加密/解密
     * @return
     */
    public static Cipher getCipher(boolean isPublic, int mode) throws Exception {
        Cipher cipher = null;
        if (isPublic) {
            PublicKey publicKey = getPublicKey();
            cipher = Cipher.getInstance(publicKey.getAlgorithm());
            cipher.init(mode, publicKey);
        } else {
            PrivateKey privateKey = getPrivateKey();
            cipher = Cipher.getInstance(privateKey.getAlgorithm());
            cipher.init(mode, privateKey);
        }
        return cipher;
    }

    /**
     * 方法: bytesToStrHex 描述: 数组转换成16进制字符串
     *
     * @param bytes 源数组
     * @return String
     */
    public static final String bytesToStrHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer(bytes.length);
        String sTemp;
        for (int i = 0; i < bytes.length; i++) {
            sTemp = Integer.toHexString(0xFF & bytes[i]);
            if (sTemp.length() < 2) sb.append(0);
            sb.append(sTemp.toUpperCase());
        }
        return sb.toString();
    }

    /**
     * 方法: hexStrToBytes 描述: 将16进制字符串还原为字节数组
     *
     * @param str 16进制字符串
     * @return byte[]
     */
    private static final byte[] hexStrToBytes(String str) {
        byte[] bytes;
        bytes = new byte[str.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(str.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

    /*==========================================签名================================================*/

    /**
     * 方法: sign 描述: 数字签名并转换进制
     *
     * @param requestMap 源数据
     * @return
     */
    public static String sign(Map<String, String> requestMap) throws Exception {
        // 把请求参数拼接成功字符串：value1value2value3...
        StringBuffer sourceData = new StringBuffer();
        for (Iterator<Map.Entry<String, String>> iter = requestMap.entrySet().iterator();
             iter.hasNext(); ) {
            Map.Entry<String, String> entry = iter.next();
            sourceData.append(entry.getValue());
        }
        byte[] bytes = sign(sourceData.toString().getBytes());
        return bytesToStrHex(bytes);
    }

    /**
     * 方法: sign 描述: 数字签名
     *
     * @param byteData 源字节
     * @return
     */
    public static byte[] sign(byte[] byteData) throws Exception {
        PrivateKey privateKey = getPrivateKey();
        X509Certificate x509Certificate = (X509Certificate) getCertificate();
        Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
        signature.initSign(privateKey);
        signature.update(byteData);
        return signature.sign();
    }

    /**
     * 方法: verify 描述: 进制转换并验签
     *
     * @param signStr    签名字符串
     * @param requestMap 源数据
     * @return
     */
    public static boolean verify(String signStr, Map<String, String> requestMap) throws Exception {
        byte[] signData = hexStrToBytes(signStr);

        StringBuffer sourceData = new StringBuffer();
        for (Iterator<Map.Entry<String, String>> iter = requestMap.entrySet().iterator();
             iter.hasNext(); ) {
            Map.Entry<String, String> entry = iter.next();
            sourceData.append(entry.getValue());
        }

        return verify(sourceData.toString().getBytes(), signData);
    }

    /**
     * 方法: verify 描述: 证书所含公钥校验签名
     *
     * @param sourceData 源字节
     * @param signData   签名字节
     * @return
     */
    public static boolean verify(byte[] sourceData, byte[] signData) throws Exception {
        X509Certificate x509Certificate = (X509Certificate) getCertificate();
        Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
        signature.initVerify(x509Certificate);
        signature.update(sourceData);
        return signature.verify(signData);
    }

    /*==========================================加密=======================================*/

    /**
     * 方法: encrypt 描述: 加密并转换进制
     *
     * @param requestMap   源数据
     * @param isPubEncrypt 是否使用公钥加密
     * @return
     */
    public static String encrypt(Map<String, String> requestMap, boolean isPubEncrypt)
            throws Exception {
        // 把请求参数拼接成功字符串：value1value2value3...
        StringBuffer sourceData = new StringBuffer();
        for (Iterator<Map.Entry<String, String>> iter = requestMap.entrySet().iterator();
             iter.hasNext(); ) {
            Map.Entry<String, String> entry = iter.next();
            sourceData.append(entry.getValue());
        }
        byte[] encryptData = encrypt(sourceData.toString().getBytes(), isPubEncrypt);
        return bytesToStrHex(encryptData);
    }

    /**
     * 方法: encrypt 描述: 加密
     *
     * @param encryptData  待加密字节
     * @param isPubEncrypt 是否使用公钥加密
     * @return
     */
    public static byte[] encrypt(byte[] encryptData, boolean isPubEncrypt) throws Exception {
        Cipher cipher = getCipher(isPubEncrypt, Cipher.ENCRYPT_MODE);
        return cipher.doFinal(encryptData);
    }

    /**
     * 方法: decrypt 描述: 转换进制并解密
     *
     * @param decryptStr   加密字符串
     * @param isPubDecrypt 是否使用公钥解密
     * @return
     */
    public static String decrypt(String decryptStr, boolean isPubDecrypt) throws Exception {
        byte[] decryptData = hexStrToBytes(decryptStr);
        return new String(decrypt(decryptData, isPubDecrypt));
    }

    /**
     * 方法: decrypt 描述: 解密
     *
     * @param decryptData  加密字节
     * @param isPubDecrypt 是否使用公钥解密
     * @return
     */
    public static byte[] decrypt(byte[] decryptData, boolean isPubDecrypt) throws Exception {
        Cipher cipher = getCipher(isPubDecrypt, Cipher.DECRYPT_MODE);
        return cipher.doFinal(decryptData);
    }

    public static void main(String[] args) throws Exception {

        Map<String, String> requestMap = new LinkedHashMap();
        requestMap.put("batchno", "17005846899643554");
        requestMap.put("amount", "100005");
        requestMap.put("uapcode", "152516");
        System.out.println("请求数据：" + requestMap.toString());

        String signStr = CertUtil.sign(requestMap);
        System.out.println("签名数据：" + signStr);
        System.out.println("验签结果：" + CertUtil.verify(signStr, requestMap));

        String priEncryptStr = CertUtil.encrypt(requestMap, false);
        System.out.println("私钥加密" + priEncryptStr);
        System.out.println("公钥解密" + CertUtil.decrypt(priEncryptStr, true));

        String pubEncryptStr = CertUtil.encrypt(requestMap, true);
        System.out.println("公钥加密" + pubEncryptStr);
        System.out.println("私钥解密" + CertUtil.decrypt(pubEncryptStr, false));
    }
}
