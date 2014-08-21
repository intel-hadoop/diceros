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

package com.intel.diceros.provider.symmetric;

import com.intel.diceros.provider.config.ConfigurableProvider;
import com.intel.diceros.provider.util.AlgorithmProvider;

public class AESAlgorithmProvider extends AlgorithmProvider {
  private static final String PREFIX = AES.class.getName(); // the outer class

  public AESAlgorithmProvider() {
  }

  @Override
  public void configure(ConfigurableProvider provider) {
    provider.addAlgorithm("Cipher.AES", PREFIX + "$CTR");
    provider.addAlgorithm("Cipher.AES/CTR", PREFIX + "$CTR");
    provider.addAlgorithm("Cipher.AES/CBC", PREFIX + "$CBC");
    provider.addAlgorithm("Cipher.AES/MBCBC", PREFIX + "$MBCBC");
    provider.addAlgorithm("Cipher.AES/XTS", PREFIX + "$XTS");
    provider.addAlgorithm("Cipher.AES SupportedModes",
        "CTR128|CTR192|CTR256|CTR|CBC128|CBC192|CBC256|CBC|XTS|XTS128|XTS256");
    provider.addAlgorithm("Cipher.AES SupportedPaddings",
        "NOPADDING|PKCS5PADDING");
  }
}
