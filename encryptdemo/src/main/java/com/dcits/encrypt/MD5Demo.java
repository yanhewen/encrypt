package com.dcits.encrypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Demo {

  /**
   * MD5加密
   *
   * @param data
   * @return
   * @throws NoSuchAlgorithmException
   */
  public static byte[] encryptMD5(byte[] data) throws NoSuchAlgorithmException {
    MessageDigest md5 = MessageDigest.getInstance("MD5");
    md5.update(data);
    return md5.digest();
  }
}
