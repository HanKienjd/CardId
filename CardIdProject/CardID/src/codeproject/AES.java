/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package codeproject;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author kienn
 */
public class AES {
    public static String encrypt(String text,String myKey){
        try {
            MessageDigest sha = MessageDigest.getInstance("MD5");
            byte[] key = myKey.getBytes("UTF-8");
            key = sha.digest(key);
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(text.getBytes("UTF-8")));
      } catch (Exception e) {
            System.out.println(e.toString());
      }
        return "";
    }
    public static String decrypt(String encrypted,String myKey){
        try {
            MessageDigest sha = MessageDigest.getInstance("MD5");
            byte[] key = myKey.getBytes("UTF-8");
            key = sha.digest(key);
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(encrypted)));
      } catch (Exception e) {
            System.out.println(e.toString());
       }
        return "";
    }
}
