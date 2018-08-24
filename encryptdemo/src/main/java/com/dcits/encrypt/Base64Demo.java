package com.dcits.encrypt;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;

public class Base64Demo {
  /**
   * Base64加密
   *
   * @param key 待加密的key
   * @return 加密后字符串
   */
  public static String encryptBASE64(byte[] key) {
    BASE64Encoder encoder = new BASE64Encoder();
    return encoder.encode(key);
  }

  /**
   * Base64解密
   * @param key
   * @return
   * @throws IOException
   */
  public static byte[] decryptBASE64(String key) throws IOException {
    BASE64Decoder decoder = new BASE64Decoder();
    return decoder.decodeBuffer(key);
  }

  public static void main(String[] args) throws IOException {
    String key = "a123";
    String password = encryptBASE64(key.getBytes());
    System.out.println("password:" + password);
    byte[] b = decryptBASE64(password);
    System.out.println("str:" + new String(b));
  }
}
