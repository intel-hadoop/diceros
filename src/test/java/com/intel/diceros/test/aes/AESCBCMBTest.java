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
import com.intel.diceros.test.util.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.Security;

public class AESCBCMBTest extends AESAbstarctTest {

  public AESCBCMBTest() {

  }

  public AESCBCMBTest(String cipherName, String providerName) {
    super(cipherName, providerName);
  }

  @Override
  protected void byteArrayTest(byte[] keyBytes, byte[] ivBytes, byte[] input)
      throws Exception {
    Key key = new SecretKeySpec(keyBytes, "AES");
    IvParameterSpec iv = new IvParameterSpec(ivBytes);
    Cipher dec = Cipher.getInstance(this.cipherName, this.providerName);
    Cipher enc = Cipher.getInstance(this.cipherName, this.providerName);

    try {
      enc.init(Cipher.ENCRYPT_MODE, key, iv);
      dec.init(Cipher.DECRYPT_MODE, key, iv);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    // encryption pass
    byte[] encResult = new byte[input.length + 16 + 2];
    int encLen = enc.doFinal(input, 0, input.length, encResult, 0);
    if (encResult.length != encLen) {
      fail("AES failed encryption");
    }

    // decryption pass
    byte[] decrytion = dec.doFinal(encResult, 0, encResult.length);
    checkEqual(decrytion, input);
  }

  @Override
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
      byteBufferTest(Hex.decode(cipherTests[i]), Hex.decode(cipherTests[i+1]), inputBuffer);
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
