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
import com.intel.diceros.test.util.Hex;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESXTSTest extends BaseBlockCipherTest {
  private String cipherName;
  private String providerName;
  static String[] cipherXTSTests = {
  /*
   * key_len,key,iv,plainText,cipherText
   */
  "128",
  "a1b90cba3f06ac353b2c343876081762090923026e91771815f29dab01932f2f",
  "4faef7117cda59c66e4b92013e768ad5",
  "ebabce95b14d3c8d6fb350390790311c",
  "778ae8b43cb98d5a825081d5be471c63",

  "128",
  "8f59462c1327fd6411cb6b02c04bf0a129f145c276a38693c745de3118c90a2f",
  "f2b86793b29e730e4a627b6ee161706c",
  "f7049f8aa312aeb1ab99ad11a1d7a720",
  "e59fca86c3c906f3df67418636a28767",

  "128",
  "e4eb402fae4395ff08e1280b0cd4d356e7a1e8c28aad13b9a6fef8b88ccd2e84",
  "b611ff70e6653cb68b14354f2b3cba74",
  "132097c5236eddea183235ba1e7b50f9",
  "268160fa57392906007199d45e988e56",

  "256",
  "1ea661c58d943a0e4801e42f4b0947149e7f9f8e3e68d0c7505210bd311a0e7cd6e13ffdf2418d8d1911c004cda58da3d619b7e2b9141e58318eea392cf41b08",
  "adf8d92627464ad2f0428e84a9f87564",
  "2eedea52cd8215e1acc647e810bbc3642e87287f8d2e57e36c0a24fbc12a202e",
  "cbaad0e2f6cea3f50b37f934d46a9b130b9d54f07e34f36af793e86f73c6d7db",

  "256",
  "e149be00177d76b7c1d85bcbb6b5054ee10b9f51cd73f59e0840628b9e7d854e2e1c0ab0537186a2a7c314bbc5eb23b6876a26bcdbf9e6b758d1cae053c2f278",
  "0ea18818fab95289b1caab4e61349501",
  "f5f101d8e3a7681b1ddb21bd2826b24e32990bca49b39291b5369a9bca277d75",
  "5bf2479393cc673306fbb15e72600598e33d4d8a470727ce098730fd80afa959",

  "256",
  "522499839449864b0f59ac861b0b8923a1e4e204f8a255febb9ef0a8078942e8ab26a30a3bd6d14fd291efaeacd088169a6bb1218f3ffe9a482a439d2ef78628",
  "04782cd3c9161fd2eaa9e911c23af4c8",
  "1614c98391c1dece1a3d165af0101c872a31730c407b07a2bc97f8c8741e7fcb",
  "4d8ee472b5c9367b364cf284738ef5b490f4c131a4badc316a175f3d55d28711" };

  public AESXTSTest() {
    super("AES");
    cipherName = "AES/XTS/NoPadding";
    providerName = "DC";
  }

  public void testAESXTS() {
    Security.addProvider(new DicerosProvider());
    runTest(new AESXTSTest());
  }

  @Override
  public void performTest() throws Exception {
    for (int i = 0; i != cipherXTSTests.length; i += 5) {
      byteArrayTest(Integer.parseInt(cipherXTSTests[i]),
          Hex.decode(cipherXTSTests[i + 1]), Hex.decode(cipherXTSTests[i + 2]),
          Hex.decode(cipherXTSTests[i + 3]), Hex.decode(cipherXTSTests[i + 4]));
    }
  }

  private void byteArrayTest(int strength, byte[] keyBytes, byte[] ivBytes,
      byte[] plainText, byte[] cipherText) throws Exception {
    Key key;
    IvParameterSpec iv;
    Cipher dec, enc;

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
    byte[] encResult = new byte[plainText.length];
    enc.update(plainText, 0, plainText.length, encResult, 0);
    if (!Arrays.areEqual(encResult, cipherText)) {
      fail("AES failed encryption - expected " + new String(Hex.encode(cipherText))
          + " got " + new String(Hex.encode(encResult)));
    }

    //
    // decryption pass
    //
    byte[] decResult = new byte[plainText.length];
    dec.update(cipherText, 0, cipherText.length, decResult, 0);
    if (!Arrays.areEqual(decResult, plainText)) {
      fail("AES failed decryption - expected " + new String(Hex.encode(plainText))
          + " got " + new String(Hex.encode(decResult)));
    }
  }

  public static void main(String[] args) {
    new AESXTSTest().testAESXTS();
  }
}
