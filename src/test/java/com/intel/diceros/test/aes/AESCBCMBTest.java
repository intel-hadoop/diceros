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

import java.nio.ByteBuffer;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import com.intel.diceros.provider.DicerosProvider;
import com.intel.diceros.provider.util.Arrays;
import com.intel.diceros.test.util.Hex;

public class AESCBCMBTest extends AESAbstarctTest {
  private static String[] cipherTests = {
    "000102030405060708090a0b0c0d0e0f", // key data, length 128
    //"123456789abcdef1123456789abcdef1", // iv data
    "hello world hello world hello world hello world hello world hello world123456789"}; // input data

  public AESCBCMBTest() {

  }

  public AESCBCMBTest(String cipherName, String providerName) {
    super(cipherName, providerName, cipherTests);
  }
  /**
   * AES Test with byte array as input data, first encrypt the<code>input</code>,
   * then decrypt the ciphertext result and compare it with the <code>input</code>.
   *
   * @param keyBytes
   * @param input the input data
   * @throws Exception
   */

  public void byteArrayTest(byte[] keyBytes, byte[] input) throws Exception {
    Key key;
    Cipher in, out;

    key = new SecretKeySpec(keyBytes, "AES");

    in = Cipher.getInstance(this.cipherName, this.providerName);
    out = Cipher.getInstance(this.cipherName, this.providerName);

    try {
      out.init(Cipher.ENCRYPT_MODE, key);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    try {
      in.init(Cipher.DECRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(
              out.getIV()));
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    //
    // encryption pass
    //
    byte[] encrytion = new byte[input.length + 16 + 2];
    int encryptLen = out.doFinal(input, 0, input.length, encrytion, 0);

    byte[] decrytion = in.doFinal(encrytion, 0, encryptLen);

    if (!Arrays.areEqual(decrytion, input)) {
      fail("AES failed decryption");
    }
  }
  /**
   * AES Test with direct byte buffer as input data, first encrypt the
   * <code>input</code>, then decrypt the ciphertext result and compare it with
   * the <code>input</code>.
   *
   * @param keyBytes the key data
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws ShortBufferException
   * @throws Exception
   * @throws BadPaddingException
   */
  protected void byteBufferTest(byte[] keyBytes, ByteBuffer input)
      throws NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, ShortBufferException, 
      BadPaddingException, IllegalBlockSizeException {
    ByteBuffer output = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    ByteBuffer decResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);

    Key key = new SecretKeySpec(keyBytes, "AES");
    Cipher enc = Cipher.getInstance(this.cipherName, this.providerName);
    Cipher dec = Cipher.getInstance(this.cipherName, this.providerName);

    try {
      enc.init(Cipher.ENCRYPT_MODE, key);
      dec.init(Cipher.DECRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(
          enc.getIV()));
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    // encryption
    enc.doFinal(input, output);
    output.flip();

    // decryption
    dec.doFinal(output, decResult);
    input.flip();
    decResult.flip();

    if (!input.equals(decResult)) {
      byte[] inArray = new byte[input.remaining()];
      byte[] decResultArray = new byte[decResult.remaining()];
      input.get(inArray);
      decResult.get(decResultArray);
      fail("AES failed decryption - expected "
          + new String(Hex.encode(inArray)) + " got "
          + new String(Hex.encode(decResultArray)));
    }
  }

  @Override
  public void performTest() throws Exception {
    for (int i = 0; i != cipherTests.length; i += 2) {
      byteArrayTest(Hex.decode(cipherTests[i]), cipherTests[i + 1].getBytes());
    }

    for (int i = 0; i != cipherTests.length; i += 2) {
      byte[] inputBytes = cipherTests[i + 1].getBytes();
      ByteBuffer inputBuffer = ByteBuffer.allocateDirect(inputBytes.length);
      inputBuffer.put(inputBytes);
      inputBuffer.flip();
      byteBufferTest(Hex.decode(cipherTests[i]), inputBuffer);
    }
  }

  public void testAESCBCMB() {
    Security.addProvider(new DicerosProvider());
    runTest(new AESCBCMBTest("AES/MBCBC/PKCS5Padding", "DC"));
  }
  
  public static void main(String[] args) {
    new AESCBCMBTest().testAESCBCMB();
  }

}
