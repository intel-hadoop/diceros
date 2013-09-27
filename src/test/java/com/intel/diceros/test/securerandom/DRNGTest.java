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

package com.intel.diceros.test.securerandom;

import java.security.SecureRandom;
import java.security.Security;

import com.intel.diceros.provider.DicerosProvider;
import com.intel.diceros.test.BaseBlockCipherTest;

/**
 * This class does the correctness test of SecureRandom based on DRNG(Intel®
 * Digital Random Number Generator).
 */
public class DRNGTest extends BaseBlockCipherTest {

	public DRNGTest() {
		super("DRNG");
	}

	public void testDRNG() {
		Security.addProvider(new DicerosProvider());
		runTest(new DRNGTest());
	}

	@Override
	public void performTest() throws Exception {
		SecureRandom random = SecureRandom.getInstance("DRNG", "DC");
		random.nextDouble();
		byte[] bytes = new byte[20];
		random.nextBytes(bytes);
	}
}
