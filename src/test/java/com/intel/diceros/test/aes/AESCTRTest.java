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

import java.security.Security;

public class AESCTRTest extends AESAbstarctTest {
  static String[] cipherCTRTests = {
  /*
   * key_len,key,iv,plainText,cipherText
   */
  "128",
  "2b7e151628aed2a6abf7158809cf4f3c",
  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
  "6bc1bee22e409f96e93d7e117393172a",
  "874d6191b620e3261bef6864990db6ce",

  "128",
  "2b7e151628aed2a6abf7158809cf4f3c",
  "f0f1f2f3f4f5f6f7f8f9fafbfcfdff00",
  "ae2d8a571e03ac9c9eb76fac45af8e51",
  "9806f66b7970fdff8617187bb9fffdff",

  "128",
  "2b7e151628aed2a6abf7158809cf4f3c",
  "f0f1f2f3f4f5f6f7f8f9fafbfcfdff01",
  "30c81c46a35ce411e5fbc1191a0a52ef",
  "5ae4df3edbd5d35e5b4f09020db03eab",

  "128",
  "2b7e151628aed2a6abf7158809cf4f3c",
  "f0f1f2f3f4f5f6f7f8f9fafbfcfdff02",
  "f69f2445df4f9b17ad2b417be66c3710",
  "1e031dda2fbe03d1792170a0f3009cee",

  "256",
  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
  "6bc1bee22e409f96e93d7e117393172a",
  "601ec313775789a5b7a7f504bbf3d228",

  "256",
  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  "f0f1f2f3f4f5f6f7f8f9fafbfcfdff00",
  "ae2d8a571e03ac9c9eb76fac45af8e51",
  "f443e3ca4d62b59aca84e990cacaf5c5",

  "256",
  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  "f0f1f2f3f4f5f6f7f8f9fafbfcfdff01",
  "30c81c46a35ce411e5fbc1191a0a52ef",
  "2b0930daa23de94ce87017ba2d84988d",

  "256",
  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
  "f0f1f2f3f4f5f6f7f8f9fafbfcfdff02",
  "f69f2445df4f9b17ad2b417be66c3710",
  "dfc9c58db67aada613c2dd08457941a6" };

  public AESCTRTest() {
    super("AES/CTR/NoPadding", "DC", cipherCTRTests);
  }

  public AESCTRTest(String cipherName, String providerName) {
    super(cipherName, providerName, cipherCTRTests);
  }

  public void testAESCTR() {
    Security.addProvider(new DicerosProvider());
    runTest(new AESCTRTest("AES/CTR/NoPadding", "DC"));
  }

}
