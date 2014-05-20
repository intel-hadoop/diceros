package com.intel.diceros.test.aes;

import com.intel.diceros.provider.DicerosProvider;
import com.intel.diceros.provider.util.Arrays;
import com.intel.diceros.test.util.Entity;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.*;

public class TestCipher {
  public static void main(String[] args) {
    try {
      FileInputStream fis = new FileInputStream("/tmp/Entity0");
      ObjectInputStream ois = new ObjectInputStream(fis);
      Entity entity = (Entity)ois.readObject();

      byte[] encryptResult = new byte[entity.input.length+18];
      byte[] decryptResult = new byte[entity.input.length];

      Security.addProvider(new DicerosProvider());
      Cipher cipher = Cipher.getInstance("AES/MBCBC/PKCS5Padding", "DC");
      IvParameterSpec ivSpec = new IvParameterSpec(entity.iv);
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(entity.key, "AES"), ivSpec);
      cipher.doFinal(entity.input, 0, entity.input.length, encryptResult, 0);

      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(entity.key, "AES"), ivSpec);
      decryptResult = cipher.doFinal(entity.encontent);

     /* if (Arrays.areEqual(encryptResult, entity.encontent)) {
        System.out.println("encry same");
      } else {
        System.out.println("encry error");
      }*/

      if (Arrays.areEqual(decryptResult, entity.input)) {
        System.out.println("decry right");
      } else if (Arrays.areEqual(decryptResult, entity.decontent)){
        System.out.println("same error");
      } else {
        System.out.println("error");
      }
      printArray(entity.decontent);
      printArray(decryptResult);
      printArray(entity.input);

      System.out.println();

      printArray(entity.encontent);
      printArray(encryptResult);

    } catch (IOException e) {
      e.printStackTrace();
    } catch (ClassNotFoundException e) {
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (BadPaddingException e) {
      e.printStackTrace();
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
    } catch (ShortBufferException e) {
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }
  }

  public static void printArray(byte[] barray) {
    System.out.print("content: ");
    for (int i = 0; i < barray.length; i++) {
      System.out.print(barray[i] + "\t");
    }
    System.out.println(" size:" + barray.length);
  }
}
