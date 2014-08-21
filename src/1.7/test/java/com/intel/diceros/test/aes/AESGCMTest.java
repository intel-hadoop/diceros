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
import com.intel.diceros.test.BaseBlockCipherTest;
import com.intel.diceros.test.util.Hex;

import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESGCMTest extends BaseBlockCipherTest {
  private String cipherName;
  private String providerName;

  static String[] cipherGCMTests = {
  /*
   * key_len,key,iv,plainText,cipherText,AAD,tag
   */
  "128",
  "0e00c76561d2bd9b40c3c15427e2b08f",
  "492cadaccd3ca3fbc9cf9f06eb3325c4e159850b0dbe98199b89b7af528806610b6f63998e1eae80c348e74cbb921d8326631631fc6a5d304f39166daf7ea15fa1977f101819adb510b50fe9932e12c5a85aa3fd1e73d8d760af218be829903a77c63359d75edd91b4f6ed5465a72662f5055999e059e7654a8edc921aa0d496",
  "fef03c2d7fb15bf0d2df18007d99f967c878ad59359034f7bb2c19af120685d78e32f6b8b83b032019956ca9c0195721476b85",
  "4f6cf471be7cbd2575cd5a1747aea8fe9dea83e51936beac3e68f66206922060c697ffa7af80ad6bb68f2cf4fc97416ee52abe",
  "d8f1163d8c840292a2b2dacf4ac7c36aff8733f18fabb4fa5594544125e03d1e6e5d6d0fd61656c8d8f327c92839ae5539bb469c9257f109ebff85aad7bd220fdaa95c022dbd0c7bb2d878ad504122c943045d3c5eba8f1f56c0",
  "e20b6655",

  "256",
  "cd670a8ac109d0f0e436ee42e490d5576bb7c13230f727b150b473bde659826d",
  "719191db1dc5ae92cf75cd8ff02ff036e78d6bef59714e5d40c24301443952148c61ab2e7e15d95f8d1792ee307a27c0112ec1b28c4a0416f76290b77d89088542d13649d17af09d6c5302438895534dedbb587f543c0d76b1e3e065ce6a261473d27dab6a928ad1fc786333dac512f3b521760dd1f67907292d868423a4f64b",
  "c94ebec7d8aa421bfa9a0203520e02570338d12359c5b16d51050cd3f802351b17cad85b52ea9b42147f528a25e52c170c6308",
  "286b594cf9a92b2d7348f0c75619e14916f2cafb990cc2d6aa07162d0703a9f7591e40eae402edfc64cafbedfc7ec2147acd51",
  "abdf817a7ff3f28bd0b5ef0c2ec02ccde1799d4dea806580941f63b7840b2deedd3873ad1c3186ee3c6b6fa95062fcb56e33c6737532e7c326e116f2da4cc920c8bb354e8d2e27c1920962e16a4c89521c4e1699f2145f742d36",
  "22d3ec0f"
 };

  public AESGCMTest() {
    super("AES");
    this.cipherName = "AES/GCM/NoPadding";
    this.providerName  = "DC";
  }

  public void testAESGCM() {
    Security.addProvider(new DicerosProvider());
    runTest(new AESGCMTest());
  }

  public static void main(String[] args) {
    new AESGCMTest().testAESGCM();
  }

  @Override
  public void performTest() throws Exception {
    for (int i = 0; i != cipherGCMTests.length; i += 7) {
      byteArrayTest(Integer.parseInt(cipherGCMTests[i]),
          Hex.decode(cipherGCMTests[i + 1]), Hex.decode(cipherGCMTests[i + 2]),
          Hex.decode(cipherGCMTests[i + 3]), Hex.decode(cipherGCMTests[i + 4]),
          Hex.decode(cipherGCMTests[i + 5]), Hex.decode(cipherGCMTests[i + 6]));
    }
  }

  private void byteArrayTest(int strength, byte[] keyBytes, byte[] ivBytes,
      byte[] plainText, byte[] cipherText, byte[] aad, byte[] tag) throws Exception {
    Key key;
    GCMParameterSpec spec;
    Cipher dec, enc;

    key = new SecretKeySpec(keyBytes, "AES");
    spec = new GCMParameterSpec(tag.length * 8, ivBytes);

    enc = Cipher.getInstance(this.cipherName, this.providerName);
    dec = Cipher.getInstance(this.cipherName, this.providerName);

    try {
      enc.init(Cipher.ENCRYPT_MODE, key, spec);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    try {
      dec.init(Cipher.DECRYPT_MODE, key, spec);
    } catch (Exception e) {
      fail("AES failed initialisation - " + e.toString(), e);
    }

    //
    // encryption pass
    //
    
    enc.updateAAD(aad);
    byte[] encResult = new byte[plainText.length + tag.length];
    int updateLen1ForEnc = enc.update(plainText, 0, plainText.length, encResult, 0);
    enc.doFinal(encResult, updateLen1ForEnc);
    /*
    for (int i=0; i<cipherText.length; i++) {
      if (cipherText[i] != encResult[i]) {
        fail("AES/GCM failed encryption");
      }
    }
    for (int i=0; i<tag.length; i++) {
      if (tag[i] != encResult[cipherText.length + i]) {
        fail("AES/GCM tag verify failed for encryption");
      }
    }*/

    //
    // decryption pass
    //
    byte[] decResult = new byte[plainText.length];
    dec.updateAAD(aad);
    int updateLen1 = dec.update(encResult, 0, encResult.length, decResult, 0);
    int finalLen = dec.doFinal(decResult, updateLen1);
    if (finalLen + updateLen1 != plainText.length) {
      fail("AES/GCM failed decryption");
    }
    for (int i=0; i<plainText.length; i++) {
      if (plainText[i] != decResult[i]) {
        fail("AES/GCM failed decryption");
      }
    }
  }
}
