/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.intel.diceros.test.aes;

import com.intel.diceros.provider.DicerosProvider;
import com.intel.diceros.provider.util.Arrays;
import com.intel.diceros.test.BaseBlockCipherTest;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.HashMap;
import java.util.Map;

/**
 * This class does the performance and correctness test of AES CTR mode
 * algorithm.
 */
public class AESPerfTest2 extends BaseBlockCipherTest {
  private static int INPUT_BUFFER_SIZE = 1024 * 256;
  private static int RUNS = 1024 * 1024 * 1024 * 1024 / INPUT_BUFFER_SIZE; //input size: 1GB

  private void setINPUT_BUFFER_SIZE(int input_buffer_size) {
    INPUT_BUFFER_SIZE = input_buffer_size;
    RUNS = 1024 * 1024 * 1024 / INPUT_BUFFER_SIZE;
  }

  private static SecureRandom rand = new SecureRandom();

  public AESPerfTest2() {
    super("AES Performance");
  }

  public void testPerf() {
    Security.addProvider(new DicerosProvider());
    runTest(new AESPerfTest2());
  }

  /**
   * Perform the aes performance and correctness test of both aes from SunJCE
   * provider and DC provider. Use byte array as input data.
   *
   * @param input    the input byte array
   * @param provider the provider of aes algorithm
   * @throws InterruptedException
   * @throws java.security.InvalidKeyException
   *
   * @throws java.security.NoSuchAlgorithmException
   *
   * @throws java.security.NoSuchProviderException
   *
   * @throws javax.crypto.NoSuchPaddingException
   *
   * @throws javax.crypto.ShortBufferException
   *
   * @throws java.security.InvalidAlgorithmParameterException
   *
   * @throws javax.crypto.IllegalBlockSizeException
   *
   * @throws javax.crypto.BadPaddingException
   *
   */
  private void speedTestCipher(byte[] input, String provider, String mode)
          throws InterruptedException, InvalidKeyException,
          NoSuchAlgorithmException, NoSuchProviderException,
          NoSuchPaddingException, ShortBufferException,
          InvalidAlgorithmParameterException, IllegalBlockSizeException,
          BadPaddingException {
    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    rand.nextBytes(key);
    rand.nextBytes(iv);
    key = entity.key;
    iv = entity.iv;
    int encryptResultSize = INPUT_BUFFER_SIZE;
    int decryptResultSize = INPUT_BUFFER_SIZE;
    if (!mode.contains("NoPadding")) {
      encryptResultSize = INPUT_BUFFER_SIZE + 16 - (INPUT_BUFFER_SIZE % 16);
      decryptResultSize = INPUT_BUFFER_SIZE + 16 - (INPUT_BUFFER_SIZE % 16);
    }
    if (mode.contains("MB")) {
      encryptResultSize = INPUT_BUFFER_SIZE + 16 - (INPUT_BUFFER_SIZE % 16) + 2;
      decryptResultSize = INPUT_BUFFER_SIZE + 16 - (INPUT_BUFFER_SIZE % 16) + 2;
    }
    byte[] encryptResult = new byte[encryptResultSize];
    byte[] decryptResult = new byte[decryptResultSize];
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    Cipher cipher = Cipher.getInstance(mode, provider);
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), ivSpec);
    speedTestCipherForMode("encrypt", cipher, input, encryptResult);

    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivSpec);
    speedTestCipherForMode("decrypt", cipher, encryptResult, decryptResult);

    if (!mode.contains("NoPadding")) {
      byte[] tmp = new byte[INPUT_BUFFER_SIZE];
      System.arraycopy(decryptResult, 0, tmp, 0, INPUT_BUFFER_SIZE);
      decryptResult = tmp;
    }

    if (!Arrays.areEqual(decryptResult, input)) {
      fail("AES failed decryption");
    }
  }

  /**
   * Perform the aes performance and correctness test of both aes from SunJCE
   * provider and DC provider. Use direct byte buffer as input data.
   *
   * @param input    the input bytebuffer
   * @param provider the provider of aes algorithm
   * @throws InterruptedException
   * @throws java.security.InvalidKeyException
   *
   * @throws java.security.NoSuchAlgorithmException
   *
   * @throws java.security.NoSuchProviderException
   *
   * @throws javax.crypto.NoSuchPaddingException
   *
   * @throws javax.crypto.ShortBufferException
   *
   * @throws java.security.InvalidAlgorithmParameterException
   *
   * @throws javax.crypto.IllegalBlockSizeException
   *
   * @throws javax.crypto.BadPaddingException
   *
   */
  private void speedTestCipher(ByteBuffer input, String provider, String mode)
          throws InterruptedException, InvalidKeyException,
          NoSuchAlgorithmException, NoSuchProviderException,
          NoSuchPaddingException, ShortBufferException,
          InvalidAlgorithmParameterException, IllegalBlockSizeException,
          BadPaddingException {
    byte[] key = new byte[16];
    byte[] iv = new byte[16];
    rand.nextBytes(key);
    rand.nextBytes(iv);
    key = entity.key;
    iv = entity.iv;
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    int encryptResultSize = INPUT_BUFFER_SIZE;
    int decryptResultSize = INPUT_BUFFER_SIZE;
    if (!mode.contains("NoPadding")) {
      encryptResultSize = INPUT_BUFFER_SIZE + 16 - (INPUT_BUFFER_SIZE % 16);
      decryptResultSize = INPUT_BUFFER_SIZE + 16 - (INPUT_BUFFER_SIZE % 16);
    }
    if (mode.contains("MB")) {
      encryptResultSize = INPUT_BUFFER_SIZE + 16 - (INPUT_BUFFER_SIZE % 16) + 2;
      decryptResultSize = INPUT_BUFFER_SIZE + 16 - (INPUT_BUFFER_SIZE % 16) + 2;
    }
    ByteBuffer encryptResult = ByteBuffer.allocateDirect(encryptResultSize);
    ByteBuffer decryptResult = ByteBuffer.allocateDirect(decryptResultSize);
    Cipher cipher = Cipher.getInstance(mode, provider);
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), ivSpec);
    speedTestCipherForMode("encrypt", cipher, input, encryptResult);
    //printBuffer(encryptResult);
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivSpec);
    speedTestCipherForMode("decrypt", cipher, encryptResult, decryptResult);


    if (!mode.contains("NoPadding")) {
      decryptResult.limit(INPUT_BUFFER_SIZE);
    }

    if (!decryptResult.equals(input)) {
      printBuffer(input);
      printBuffer(encryptResult);
      byte[] tmpInput = new byte[input.remaining()];
      byte[] tmpEncry = new byte[encryptResult.remaining()];
      byte[] tmpDecry = new byte[input.remaining()];
      input.get(tmpInput);
      decryptResult.get(tmpDecry);
      encryptResult.get(tmpEncry);
      saveEntity(new Entity(tmpInput, key, iv, tmpDecry, tmpEncry));
      fail("AES failed decryption");
      //System.out.println(iv);
      //System.out.println(key);
      //printBuffer(decryptResult);
    }

  }

  public static void saveEntity(Entity entity){
    try {
      FileOutputStream fos = new FileOutputStream("/tmp/Entity0");
      ObjectOutputStream oos = new ObjectOutputStream(fos);
      oos.writeObject(entity);
      oos.flush();
      oos.close();
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public static void printBuffer(ByteBuffer byteBuffer) {
    System.out.print("content: ");
    for (int i = 0; i < byteBuffer.remaining(); i++) {
      System.out.print(byteBuffer.get(i) + "\t");
    }
    System.out.println(" size:" + byteBuffer.position());
  }

  private void speedTestCipherForMode(String mode, Cipher cipher, byte[] input,
                                      byte[] output) throws InterruptedException, ShortBufferException,
          IllegalBlockSizeException, BadPaddingException {
    //System.out.println("======");
    //System.out.println("Testing " + cipher.getAlgorithm() + " "
    //        + cipher.getBlockSize() * 8 + " " + mode);

    long start = System.nanoTime();
    for (int i = 0; i < RUNS; i++) {
      testCipher(cipher, input, output);
    }
    long end = System.nanoTime();
    long total = end - start;

    long averageRuntime = total / RUNS;
    final long mbPerSecond = (long) ((double) INPUT_BUFFER_SIZE / averageRuntime
            * 1000000000 / (1024 * 1024));
    System.out.println(cipher.getAlgorithm() + " " + mode + "\t"
            + mbPerSecond + "");
  }

  private void speedTestCipherForMode(String mode, Cipher cipher,
                                      ByteBuffer input, ByteBuffer output) throws InterruptedException,
          ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    /*System.out.println("======");
    System.out.println("Testing " + cipher.getAlgorithm() + " "
            + cipher.getBlockSize() * 8 + " " + mode);*/

    long start = System.nanoTime();
    for (int i = 0; i < RUNS; i++) {
      testCipher(cipher, input, output);
      input.flip();
      input.limit(input.capacity());
      output.flip();
      output.limit(output.capacity());
    }
    long end = System.nanoTime();
    long total = end - start;

    long averageRuntime = total / RUNS;
    final long mbPerSecond = (long) ((double) INPUT_BUFFER_SIZE / averageRuntime
            * 1000000000 / (1024 * 1024));
    System.out.println(cipher.getAlgorithm() + " " + mode + "\t"
            + mbPerSecond + "");
  }

  private void testCipher(Cipher cipher, byte[] input, byte[] output)
          throws ShortBufferException, IllegalBlockSizeException,
          BadPaddingException {
//		int outputOffset = cipher.update(input, 0, input.length, output);
//		cipher.doFinal(output, outputOffset);
    cipher.doFinal(input, 0, input.length, output, 0);
    if(Arrays.areEqual(output,entity.encontent)){
      System.out.println("pls pay attenion");
    }
  }

  private void testCipher(Cipher cipher, ByteBuffer input, ByteBuffer output)
          throws ShortBufferException, IllegalBlockSizeException,
          BadPaddingException {
    cipher.doFinal(input, output);

    byte[] tmpDecry = new byte[input.remaining()];
    input.get(tmpDecry);
    if(Arrays.areEqual(tmpDecry,entity.encontent)){
      System.out.println("pls pay attenion");
    }
  }

  /**
   * Perform the aes performance and correctness test of both aes from SunJCE
   * provider and DC provider. First use byte array as input data, and then use
   * direct byte buffer as input data.
   */
  @Override
  public void performTest() throws Exception {
    //System.out.println("Initialising test data.");
    byte[] input = new byte[INPUT_BUFFER_SIZE];
    //rand.nextBytes(input);
    //System.out.println("Init test data complete.");

    String[] providers = {/*"SunJCE",*/ "DC"};
    String[] sunJCEModes = {"AES/CTR/NoPadding", "AES/CBC/PKCS5Padding", "AES/CBC/NoPadding"};
    String[] DCModes = {/*"AES/CTR/NoPadding", "AES/CBC/PKCS5Padding", "AES/CBC/NoPadding",*/ "AES/MBCBC/PKCS5Padding"};

    Map<String, String[]> modesMap = new HashMap<String, String[]>(2);
    modesMap.put("SunJCE", sunJCEModes);
    modesMap.put("DC", DCModes);

    //System.out.println("##############################################");
    //System.out.println("using ByteArray as input and output");
    //System.out.println("##############################################");
    setINPUT_BUFFER_SIZE(INPUT_BUFFER_SIZE * 2);
    for (int i = 0; i < 15; i++) {
      setINPUT_BUFFER_SIZE(INPUT_BUFFER_SIZE / 2);
      System.out.println(INPUT_BUFFER_SIZE + "B\t" + INPUT_BUFFER_SIZE / 1024);
      input = new byte[INPUT_BUFFER_SIZE];
      rand.nextBytes(input);
      input = entity.input;
      setINPUT_BUFFER_SIZE(entity.input.length);
      for (String provider : providers) {
        System.out.println("ByteArray " + provider + "\t" + INPUT_BUFFER_SIZE / 1024 + "KB");
        for (String mode : modesMap.get(provider)) {
          speedTestCipher(input, provider, mode);
        }
      }

      //System.out.println("###############################################################");
      //System.out.println("using ByteBuffer as input and output");
      System.out.println("###############################################################");
      for (String provider : providers) {
        System.out.println("ByteBuffer " + provider + "\t" + INPUT_BUFFER_SIZE / 1024 + "KB");
        for (String mode : modesMap.get(provider)) {
          ByteBuffer inputBB = ByteBuffer.allocateDirect(INPUT_BUFFER_SIZE);
          inputBB.put(input);
          inputBB.flip();
          speedTestCipher(inputBB, provider, mode);
        }
      }
    }
  }

  static Entity entity = null;
  static {
    try {
      FileInputStream fis = null;
      fis = new FileInputStream("/tmp/Entity2");
      ObjectInputStream ois = new ObjectInputStream(fis);
      entity = (Entity)ois.readObject();
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    } catch (ClassNotFoundException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
  public static void main(String[] args) {
    new AESPerfTest2().testPerf();
  }
}
