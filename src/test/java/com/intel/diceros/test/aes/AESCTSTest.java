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

import java.nio.ByteBuffer;
import java.security.Security;

public class AESCTSTest extends AESAbstarctTest {

  public AESCTSTest() {

  }

  public AESCTSTest(String cipherName, String providerName) {
    super(cipherName, providerName);
  }

  public void testAESCTS() {
    Security.addProvider(new DicerosProvider());
    runTest(new AESCTSTest("AES/CTS/NoPadding", "DC"));
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

}
