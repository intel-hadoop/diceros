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
 * This class does the correctness test of AES CTR mode algorithm
 */
public abstract class AESAbstarctTest extends BaseBlockCipherTest {

  protected String cipherName;

  protected String providerName;

  protected static String[] cipherTests = {
          "000102030405060708090a0b0c0d0e0f", // key data, length 128
          "hello world hello world hello world hello world hello world hello world123456789", // input
          // data

          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", // key
          // data,
          // length
          // 256
          "hello world hello world hello world hello world hello world hello world123456789",}; // input
  // data
  public static final int BYTEBUFFER_SIZE = 1000;

  public AESAbstarctTest(String cipherName, String providerName) {
    super("AES");
    this.cipherName = cipherName;
    this.providerName = providerName;
  }

  public AESAbstarctTest() {
    super("AES");
  }

  /**
   * AES Test with byte array as input data, first encrypt the
   * <code>input</code>, then decrypt the ciphertext result and compare it with
   * the <code>input</code>.
   *
   * @param input the input data
   * @throws Exception
   */
  protected void byteArrayTest(byte[] keyBytes, byte[] input) throws Exception {
    Key key;
    Cipher in, out;
    CipherInputStream cIn;
    CipherOutputStream cOut;
    ByteArrayInputStream bIn;
    ByteArrayOutputStream bOut;

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
    bOut = new ByteArrayOutputStream();
    cOut = new CipherOutputStream(bOut, out);
    try {
      for (int i = 0; i != input.length / 2; i++) {
        cOut.write(input[i]);
      }
      cOut.write(input, input.length / 2, input.length - input.length / 2);
      cOut.close();
    } catch (IOException e) {
      fail("AES failed encryption - " + e.toString(), e);
    }

    byte[] bytes;

    bytes = bOut.toByteArray();

    //
    // decryption pass
    //
    bIn = new ByteArrayInputStream(bytes);
    cIn = new CipherInputStream(bIn, in);
    byte[] decBytes = null;
    try {
      DataInputStream dIn = new DataInputStream(cIn);
      decBytes = new byte[input.length];
      for (int i = 0; i != input.length / 2; i++) {
        decBytes[i] = (byte) dIn.read();
      }
      dIn.readFully(decBytes, input.length / 2, decBytes.length - input.length
              / 2);
    } catch (Exception e) {
      fail("AES failed encryption - " + e.toString(), e);
    }

    if (!Arrays.areEqual(decBytes, input)) {
      fail("AES failed decryption - expected " + new String(Hex.encode(input))
              + " got " + new String(Hex.encode(bytes)));
    }
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
  protected void byteBufferTest(byte[] keyBytes, ByteBuffer input)
      throws NoSuchAlgorithmException, NoSuchProviderException,
      NoSuchPaddingException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
    ByteBuffer output = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    ByteBuffer decResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    Key key;
    Cipher enc, dec;

    key = new SecretKeySpec(keyBytes, "AES");

    enc = Cipher.getInstance(this.cipherName, this.providerName);
    dec = Cipher.getInstance(this.cipherName, this.providerName);

    try {
      enc.init(Cipher.ENCRYPT_MODE, key);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    try {
      dec.init(Cipher.DECRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(
              enc.getIV()));
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    //
    // encryption pass
    //
    enc.doFinal(input, output);
    output.flip();

    //
    // decryption pass
    //
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
  protected void mixTest(byte[] keyBytes, byte[] inputByteArray,
                         ByteBuffer inputByteBuffer) throws NoSuchAlgorithmException,
          NoSuchProviderException, NoSuchPaddingException, ShortBufferException,
          Exception, BadPaddingException {
    ByteBuffer output = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    ByteBuffer decResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    Key key;
    Cipher enc, dec;

    key = new SecretKeySpec(keyBytes, "AES");

    enc = Cipher.getInstance(this.cipherName, this.providerName);
    dec = Cipher.getInstance(this.cipherName, this.providerName);

    try {
      enc.init(Cipher.ENCRYPT_MODE, key);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    try {
      dec.init(Cipher.DECRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(
              enc.getIV()));
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    //
    // encryption pass
    //
    output.put(enc.update(inputByteArray));
    enc.update(inputByteBuffer, output);
    output.put(enc.doFinal());
    output.flip();

    //
    // decryption pass
    //
    dec.doFinal(output, decResult);
    inputByteBuffer.flip();
    decResult.flip();

    ByteBuffer totalInput = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    totalInput.put(inputByteArray);
    totalInput.put(inputByteBuffer);
    totalInput.flip();
    //inputByteBuffer.flip();
    if (!totalInput.equals(decResult)) {
      byte[] inArray = new byte[totalInput.remaining()];
      byte[] decResultArray = new byte[decResult.remaining()];
      totalInput.get(inArray);
      decResult.get(decResultArray);
      fail("AES failed decryption - expected "
              + new String(Hex.encode(inArray)) + " got "
              + new String(Hex.encode(decResultArray)));
    }
  }

  /**
   * Perform the aes correctness test.
   */
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

    for (int i = 0; i != cipherTests.length; i += 2) {
      byte[] inputBytes = cipherTests[i + 1].getBytes();
      ByteBuffer inputBuffer = ByteBuffer.allocateDirect(inputBytes.length);
      inputBuffer.put(inputBytes);
      inputBuffer.flip();
      mixTest(Hex.decode(cipherTests[i]), inputBytes, inputBuffer);
    }
  }

}
