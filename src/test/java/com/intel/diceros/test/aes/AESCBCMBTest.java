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
import com.intel.diceros.test.util.Hex;

import javax.crypto.Cipher;
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

  protected void testByteArray(byte[] keyBytes, byte[] input) throws Exception {
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
    out.doFinal(input, 0, input.length, encrytion, 0);
    if (encrytion.length != input.length + 16 + 2) {
      fail("AES failed encryption - ");
    }

    byte[] decrytion = in.doFinal(encrytion, 0, encrytion.length);

    if (!Arrays.areEqual(decrytion, input)) {
      fail("AES failed decryption");
    }

  }

  @Override
  public void performTest() throws Exception {
    for (int i = 0; i != cipherTests.length; i += 2) {
      testByteArray(Hex.decode(cipherTests[i]), cipherTests[i + 1].getBytes());
    }

    for (int i = 0; i != cipherTests.length; i += 2) {
      byte[] inputBytes = cipherTests[i + 1].getBytes();
      ByteBuffer inputBuffer = ByteBuffer.allocateDirect(inputBytes.length);
      inputBuffer.put(inputBytes);
      inputBuffer.flip();
      testByteBuffer(Hex.decode(cipherTests[i]), inputBuffer);
    }
  }

  public void testAES_CBCMB() {
    Security.addProvider(new DicerosProvider());
    runTest(new AESCBCMBTest("AES/MBCBC/NoPadding", "DC"));
    runTest(new AESCBCMBTest("AES/MBCBC/PKCS5Padding", "DC"));
  }

}
