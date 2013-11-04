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
import java.nio.ByteBuffer;
import java.security.*;
import java.util.HashMap;
import java.util.Map;

/**
 * This class does the performance and correctness test of AES CTR mode
 * algorithm.
 */
public class AESPerfTest extends BaseBlockCipherTest {
  private static final int INPUT_BUFFER_SIZE = 256 * 1024;
  private static final int RUNS = 1024 * 1024 * 1024 / INPUT_BUFFER_SIZE; //input size: 1GB

  private static SecureRandom rand = new SecureRandom();

  public AESPerfTest() {
    super("AES Performance");
  }

  public void testPerf() {
    Security.addProvider(new DicerosProvider());
    runTest(new AESPerfTest());
  }

  /**
   * Perform the aes performance and correctness test of both aes from SunJCE
   * provider and DC provider. Use byte array as input data.
   *
   * @param input    the input byte array
   * @param provider the provider of aes algorithm
   * @throws InterruptedException
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws ShortBufferException
   * @throws InvalidAlgorithmParameterException
   *
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
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
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws ShortBufferException
   * @throws InvalidAlgorithmParameterException
   *
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
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
      printBuffer(decryptResult);
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
    System.out.println("======");
    System.out.println("Testing " + cipher.getAlgorithm() + " "
            + cipher.getBlockSize() * 8 + " " + mode);

    long start = System.nanoTime();
    for (int i = 0; i < RUNS; i++) {
      testCipher(cipher, input, output);
    }
    long end = System.nanoTime();
    long total = end - start;

    long averageRuntime = total / RUNS;
    final long mbPerSecond = (long) ((double) INPUT_BUFFER_SIZE / averageRuntime
            * 1000000000 / (1024 * 1024));
    System.out.println(cipher.getAlgorithm() + " Average speed:    "
            + mbPerSecond + " MB/s");
  }

  private void speedTestCipherForMode(String mode, Cipher cipher,
                                      ByteBuffer input, ByteBuffer output) throws InterruptedException,
          ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    System.out.println("======");
    System.out.println("Testing " + cipher.getAlgorithm() + " "
            + cipher.getBlockSize() * 8 + " " + mode);

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
    System.out.println(cipher.getAlgorithm() + " Average speed:    "
            + mbPerSecond + " MB/s");
  }

  private void testCipher(Cipher cipher, byte[] input, byte[] output)
          throws ShortBufferException, IllegalBlockSizeException,
          BadPaddingException {
//		int outputOffset = cipher.update(input, 0, input.length, output);
//		cipher.doFinal(output, outputOffset);
    cipher.doFinal(input, 0, input.length, output, 0);
  }

  private void testCipher(Cipher cipher, ByteBuffer input, ByteBuffer output)
          throws ShortBufferException, IllegalBlockSizeException,
          BadPaddingException {
    cipher.doFinal(input, output);
  }

  /**
   * Perform the aes performance and correctness test of both aes from SunJCE
   * provider and DC provider. First use byte array as input data, and then use
   * direct byte buffer as input data.
   */
  @Override
  public void performTest() throws Exception {
    System.out.println("Initialising test data.");
    byte[] input = new byte[INPUT_BUFFER_SIZE];
    rand.nextBytes(input);
    System.out.println("Init test data complete.");

    String[] providers = {"SunJCE", "DC"};
    String[] sunJCEModes = {"AES/CTR/NoPadding", "AES/CBC/NoPadding", "AES/CBC/PKCS5Padding"};
    String[] DCModes = {"AES/CTR/NoPadding", "AES/CBC/NoPadding", "AES/CBC/PKCS5Padding", "AES/MBCBC/PKCS5Padding"};

    Map<String, String[]> modesMap = new HashMap<String, String[]>(2);
    modesMap.put("SunJCE", sunJCEModes);
    modesMap.put("DC", DCModes);

    System.out.println("##############################################");
    System.out.println("using ByteArray as input and output");
    System.out.println("##############################################");
    for (String provider : providers) {
      System.out.println("provider:" + provider);
      for (String mode : modesMap.get(provider)) {
        speedTestCipher(input, provider, mode);
      }
    }

    System.out
            .println("###############################################################");
    System.out.println("using ByteBuffer as input and output");
    System.out
            .println("###############################################################");
    for (String provider : providers) {
      System.out.println("provider:" + provider);
      for (String mode : modesMap.get(provider)) {
        ByteBuffer inputBB = ByteBuffer.allocateDirect(INPUT_BUFFER_SIZE);
        inputBB.put(input);
        inputBB.flip();
        speedTestCipher(inputBB, provider, mode);
      }
    }
  }

  public static void main(String[] args) {
    new AESPerfTest().testPerf();
  }
}
