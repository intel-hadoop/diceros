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
 * This class does the correctness test of AES CTR mode algorithm
 */
public abstract class AESAbstarctTest extends BaseBlockCipherTest {

  protected String cipherName;

  protected String providerName;

  protected String[] cipherTests;

  // data
  public static final int BYTEBUFFER_SIZE = 1000;

  public AESAbstarctTest(String cipherName, String providerName,
      String[] cipherTests) {
    super("AES");
    this.cipherName = cipherName;
    this.providerName = providerName;
    this.cipherTests = cipherTests;
  }

  public AESAbstarctTest() {
    super("AES");
  }

  /**
   * AES Test with byte array as input data, first encrypt the
   * <code>input</code>, compare the cipherText with the <code>output</code> to
   * verify the encryption then decrypt the cipherText, compare the plainText
   * with the <code>input</code> to verify the decryption
   * 
   * @param strength
   *          the key length
   * @param keyBytes
   *          the key
   * @param ivBytes
   *          the intialize vector
   * @param input
   *          the plainText data
   * @param output
   *          the cipherText data
   * @throws Exception
   */
  protected void byteArrayTest(int strength, byte[] keyBytes, byte[] ivBytes,
      byte[] input, byte[] output) throws Exception {
    Key key;
    IvParameterSpec iv;
    Cipher in, out;
    CipherInputStream cIn;
    CipherOutputStream cOut;
    ByteArrayInputStream bIn;
    ByteArrayOutputStream bOut;

    key = new SecretKeySpec(keyBytes, "AES");
    iv = new IvParameterSpec(ivBytes);

    in = Cipher.getInstance(this.cipherName, this.providerName);
    out = Cipher.getInstance(this.cipherName, this.providerName);

    try {
      out.init(Cipher.ENCRYPT_MODE, key, iv);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    try {
      in.init(Cipher.DECRYPT_MODE, key, iv);
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

    if (!Arrays.areEqual(bytes, output)) {
      fail("AES failed encryption - expected " + new String(Hex.encode(output))
          + " got " + new String(Hex.encode(bytes)));
    }
    //
    // decryption pass
    //
    bIn = new ByteArrayInputStream(output);
    cIn = new CipherInputStream(bIn, in);
    byte[] decByte = null;//= in.doFinal(bytes);
    try {
      DataInputStream dIn = new DataInputStream(cIn);
      decByte = new byte[input.length];
      for (int i = 0; i != input.length / 2; i++) {
        decByte[i] = (byte) dIn.read();
      }
      dIn.readFully(decByte, input.length / 2, decByte.length - input.length
          / 2);
    } catch (Exception e) {
      fail("AES failed encryption - " + e.toString(), e);
    }

    if (!Arrays.areEqual(decByte, input)) {
      fail("AES failed decryption - expected " + new String(Hex.encode(input))
          + " got " + new String(Hex.encode(decByte)));
    }
  }

  /**
   * AES Test with byteBuffer as input data, first encrypt the
   * <code>input</code>, compare the cipherText with the <code>output</code> to
   * verify the encryption then decrypt the cipherText, compare the plainText
   * with the <code>input</code> to verify the decryption
   * 
   * @param strength
   *          the key length
   * @param keyBytes
   *          the key
   * @param ivBytes
   *          the intialize vector
   * @param input
   *          the plainText data
   * @param output
   *          the cipherText data
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws ShortBufferException
   * @throws Exception
   * @throws BadPaddingException
   */
  protected void byteBufferTest(int strength, byte[] keyBytes, byte[] ivBytes,
      ByteBuffer input, ByteBuffer output) throws NoSuchAlgorithmException,
      NoSuchProviderException, NoSuchPaddingException, ShortBufferException,
      BadPaddingException, IllegalBlockSizeException {
    ByteBuffer decResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    ByteBuffer encResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    Key key;
    Cipher enc, dec;
    IvParameterSpec iv;

    key = new SecretKeySpec(keyBytes, "AES");
    iv = new IvParameterSpec(ivBytes);

    enc = Cipher.getInstance(this.cipherName, this.providerName);
    dec = Cipher.getInstance(this.cipherName, this.providerName);

    try {
      enc.init(Cipher.ENCRYPT_MODE, key, iv);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    try {
      dec.init(Cipher.DECRYPT_MODE, key, iv);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    //
    // encryption pass
    //
    enc.doFinal(input, encResult);
    input.flip();
    encResult.flip();
    if (!output.equals(encResult)) {
      fail("AES failed encryption - expected " + new String(Hex.encode(output.array()))
      + " got " + new String(Hex.encode(encResult.array())));
    }

    //
    // decryption pass
    //
    dec.doFinal(encResult, decResult);
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
   * @param strength
   *          the key length
   * @param keyBytes
   *          the key data
   * @param inputByteArray
   *          the input byte array
   * @param inputByteBuffer
   *          the input direct byte buffer
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   * @throws NoSuchPaddingException
   * @throws ShortBufferException
   * @throws Exception
   * @throws BadPaddingException
   */
  protected void mixTest(int strength,byte[] keyBytes, byte[] ivBytes, byte[] inputByteArray,
      ByteBuffer inputByteBuffer) throws NoSuchAlgorithmException,NoSuchProviderException, 
      NoSuchPaddingException, ShortBufferException, Exception, BadPaddingException {
    ByteBuffer output = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    ByteBuffer decResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    Key key;
    IvParameterSpec iv;
    Cipher enc, dec;

    key = new SecretKeySpec(keyBytes, "AES");
    iv = new IvParameterSpec(ivBytes);
    
    enc = Cipher.getInstance(this.cipherName, this.providerName);
    dec = Cipher.getInstance(this.cipherName, this.providerName);

    try {
      enc.init(Cipher.ENCRYPT_MODE, key, iv);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    try {
      dec.init(Cipher.DECRYPT_MODE, key, iv);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    //
    // encryption pass
    //
    byte[] bytes = null;
    bytes = enc.update(inputByteArray);
    if (bytes != null) {
      output.put(bytes);
    }
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
    // inputByteBuffer.flip();
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
    for (int i = 0; i != cipherTests.length; i += 5) {
      byteArrayTest(Integer.parseInt(cipherTests[i]),
          Hex.decode(cipherTests[i + 1]), Hex.decode(cipherTests[i + 2]),
          Hex.decode(cipherTests[i + 3]), Hex.decode(cipherTests[i + 4]));
    }

    for (int i = 0; i != cipherTests.length; i += 5) {
      byte[] inputBytes = Hex.decode(cipherTests[i + 3]);
      byte[] outputBytes = Hex.decode(cipherTests[i + 4]);
      ByteBuffer inputBuffer = ByteBuffer.allocateDirect(inputBytes.length);
      ByteBuffer outputBuffer = ByteBuffer.allocateDirect(outputBytes.length);
      inputBuffer.put(inputBytes);
      inputBuffer.flip();
      outputBuffer.put(outputBytes);
      outputBuffer.flip();
      byteBufferTest(Integer.parseInt(cipherTests[i]),
          Hex.decode(cipherTests[i + 1]), Hex.decode(cipherTests[i + 2]),
          inputBuffer, outputBuffer);
    }

    for (int i = 0; i != cipherTests.length; i += 5) {
      byte[] inputBytes = Hex.decode(cipherTests[i+3]);
      ByteBuffer inputBuffer = ByteBuffer.allocateDirect(inputBytes.length);
      inputBuffer.put(inputBytes);
      inputBuffer.flip();
      mixTest(Integer.parseInt(cipherTests[i]),
              Hex.decode(cipherTests[i+1]), Hex.decode(cipherTests[i+2]), inputBytes, 
              inputBuffer);
    }
  }

}
