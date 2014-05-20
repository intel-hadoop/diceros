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

import com.intel.diceros.provider.util.Arrays;
import com.intel.diceros.test.BaseBlockCipherTest;
import com.intel.diceros.test.util.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * This class does the correctness test of AES algorithm
 */
public abstract class AESAbstarctTest extends BaseBlockCipherTest {
  
  private static final int BYTEBUFFER_SIZE = 1000;
  
  protected String cipherName;
  protected String providerName;

  protected static String[] cipherTests = {
    "000102030405060708090a0b0c0d0e0f", // key data, length 128
    "123456789abcdef1123456789abcdef1", // iv data
    "hello world hello world hello world hello world hello world hello world123456789"}; // input data

//  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", // key data, length 256
//  "123456789abcdef1123456789abcdef1", // iv data
//  "hello world hello world hello world hello world hello world hello world123456789",}; // input data

  public AESAbstarctTest(String cipherName, String providerName) {
    super("AES");
    this.cipherName = cipherName;
    this.providerName = providerName;
  }

  public AESAbstarctTest() {
    super("AES");
  }
  
  public void checkEqual(byte[] arg1, byte[] arg2) {
    if (!Arrays.areEqual(arg1, arg2)) {
      fail("AES failed decryption");
    }
  }
  
  public void checkEqual(ByteBuffer arg1, ByteBuffer arg2) {
    int arg1Len = arg1.limit();
    int arg2Len = arg2.limit();
    if (arg1Len == arg2Len) {
      int index = 0;
      while (index < arg1Len) {
        if (arg1.get(index) != arg2.get(index)) {
          fail("AES failed decryption");
          return;
        }
        index++;
      }
    } else {
      fail("AES failed decryption");
    }
  }

  /**
   * AES Test with byte array as input data, first encrypt the<code>input</code>,
   * then decrypt the ciphertext result and compare it with the <code>input</code>.
   *
   * @param input the input data
   * @throws Exception
   */
  protected void byteArrayTest(byte[] keyBytes, byte[] ivBytes, byte[] input) throws Exception {
    CipherInputStream cIn;
    CipherOutputStream cOut;
    ByteArrayInputStream bIn;
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    Cipher dec = Cipher.getInstance(this.cipherName, this.providerName);
    Cipher enc = Cipher.getInstance(this.cipherName, this.providerName);
    Key key = new SecretKeySpec(keyBytes, "AES");
    IvParameterSpec iv = new IvParameterSpec(ivBytes);
    try {
      enc.init(Cipher.ENCRYPT_MODE, key, iv);
      dec.init(Cipher.DECRYPT_MODE, key, iv);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    // encryption pass
    cOut = new CipherOutputStream(bOut, enc);
    try {
      for (int i = 0; i != input.length / 2; i++) {
        cOut.write(input[i]);
      }
      cOut.write(input, input.length / 2, input.length - input.length / 2);
      cOut.close();
    } catch (IOException e) {
      fail("AES failed encryption - " + e.toString(), e);
    }

    byte[] encBytes = bOut.toByteArray();

    // decryption pass
    bIn = new ByteArrayInputStream(encBytes);
    cIn = new CipherInputStream(bIn, dec);
    byte[] decBytes = null;
    try {
      DataInputStream dIn = new DataInputStream(cIn);
      decBytes = new byte[input.length];
      for (int i = 0; i != input.length / 2; i++) {
        decBytes[i] = (byte) dIn.read();
      }
      dIn.readFully(decBytes, input.length / 2, decBytes.length - input.length / 2);
    } catch (Exception e) {
      fail("AES failed encryption - " + e.toString(), e);
    }
    
    checkEqual(decBytes, input);
  }

  /**
   * AES Test with direct byte buffer as input data, first encrypt the
   * <code>input</code>, then decrypt the ciphertext result and compare it with
   * the <code>input</code>.
   *
   * @param keyBytes the key data
   * @param input    the input data
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws ShortBufferException
   * @throws Exception
   * @throws BadPaddingException
   */
  protected void byteBufferTest(byte[] keyBytes, byte[] ivBytes, ByteBuffer input)
      throws NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
    ByteBuffer output = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    ByteBuffer decResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);

    Key key = new SecretKeySpec(keyBytes, "AES");
    IvParameterSpec iv = new IvParameterSpec(ivBytes);
    Cipher enc = Cipher.getInstance(this.cipherName, this.providerName);
    Cipher dec = Cipher.getInstance(this.cipherName, this.providerName);

    try {
      enc.init(Cipher.ENCRYPT_MODE, key, iv);
      dec.init(Cipher.DECRYPT_MODE, key, iv);
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

    checkEqual(input, decResult);
  }

  /**
   * AES Test with both byte arry and direct byte buffer as input data, first
   * encrypt the <code>inputByteArray</code> and <code>inputByteBuffer</code>,
   * then decrypt the ciphertext result and compare it with the
   * <code>inputByteArray</code> and <code>inputByteBuffer</code>.
   *
   * @param keyBytes        the key data
   * @param inputByteArray  the input byte array
   * @param inputByteBuffer the input direct byte buffer
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws ShortBufferException
   * @throws Exception
   * @throws BadPaddingException
   */
  protected void mixTest(byte[] keyBytes, byte[] ivBytes, byte[] inputByteArray,
      ByteBuffer inputByteBuffer) throws NoSuchAlgorithmException,
        NoSuchProviderException, NoSuchPaddingException, ShortBufferException,
        Exception, BadPaddingException {
    ByteBuffer output = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    ByteBuffer decResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);

    Key key = new SecretKeySpec(keyBytes, "AES");
    IvParameterSpec iv = new IvParameterSpec(ivBytes);
    Cipher enc = Cipher.getInstance(this.cipherName, this.providerName);
    Cipher dec = Cipher.getInstance(this.cipherName, this.providerName);
    try {
      enc.init(Cipher.ENCRYPT_MODE, key, iv);
      dec.init(Cipher.DECRYPT_MODE, key, iv);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    // encryption pass
    output.put(enc.update(inputByteArray));
    enc.update(inputByteBuffer, output);
    output.put(enc.doFinal());
    output.flip();

    // decryption pass
    dec.doFinal(output, decResult);
    inputByteBuffer.flip();
    decResult.flip();

    ByteBuffer totalInput = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    totalInput.put(inputByteArray);
    totalInput.put(inputByteBuffer);
    totalInput.flip();
    
    checkEqual(totalInput, decResult);
  }

  /**
   * Perform the AES function test.
   */
  public void performTest() throws Exception {
    for (int i = 0; i != cipherTests.length; i += 3) {
      byteArrayTest(Hex.decode(cipherTests[i]), Hex.decode(cipherTests[i + 1].getBytes()),
          cipherTests[i + 2].getBytes());
    }

    for (int i = 0; i != cipherTests.length; i += 3) {
      byte[] inputBytes = cipherTests[i + 2].getBytes();
      ByteBuffer inputBuffer = ByteBuffer.allocateDirect(inputBytes.length);
      inputBuffer.put(inputBytes);
      inputBuffer.flip();
      byteBufferTest(Hex.decode(cipherTests[i]), Hex.decode(cipherTests[i + 1].getBytes()),
          inputBuffer);
    }

    for (int i = 0; i != cipherTests.length; i += 3) {
      byte[] inputBytes = cipherTests[i + 2].getBytes();
      ByteBuffer inputBuffer = ByteBuffer.allocateDirect(inputBytes.length);
      inputBuffer.put(inputBytes);
      inputBuffer.flip();
      mixTest(Hex.decode(cipherTests[i]), Hex.decode(cipherTests[i + 1].getBytes()),
          inputBytes, inputBuffer);
    }
  }

}
