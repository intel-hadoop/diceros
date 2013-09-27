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

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import com.intel.diceros.provider.DicerosProvider;
import com.intel.diceros.provider.util.Arrays;
import com.intel.diceros.test.BaseBlockCipherTest;

/**
 * This class does the performance and correctness test of AES CTR mode
 * algorithm.
 */
public class AESPerfTest extends BaseBlockCipherTest {
	private static final int DATA_SIZE = 256 * 1024;
	private static final int RUNS = 3;

	private static SecureRandom rand = new SecureRandom();

	public AESPerfTest() {
		super("AES Performance");
	}

	public void testPerf() {
		Security.addProvider(new DicerosProvider());
		runTest(new AESPerfTest());
	}

	/**
	 * Perform the aes performance and correctness test of both aes from SunJCE
	 * provider and DC provider. Use byte array as input data.
	 * 
	 * @param input
	 *          the input byte array
	 * @param provider
	 *          the provider of aes algorithm
	 * @throws InterruptedException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws ShortBufferException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private void speedTestCipher(byte[] input, String provider)
			throws InterruptedException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, ShortBufferException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		byte[] key = new byte[16];
		rand.nextBytes(key);

		byte[] encryptResult = new byte[DATA_SIZE];
		byte[] decryptResult = new byte[DATA_SIZE];
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", provider);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
		speedTestCipherForMode("encrypt", cipher, input, encryptResult);

		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
				new javax.crypto.spec.IvParameterSpec(cipher.getIV()));
		speedTestCipherForMode("decrypt", cipher, encryptResult, decryptResult);

		if (!Arrays.areEqual(decryptResult, input)) {
			fail("AES failed decryption");
		}
	}

	/**
	 * Perform the aes performance and correctness test of both aes from SunJCE
	 * provider and DC provider. Use direct byte buffer as input data.
	 * 
	 * @param input
	 *          the input bytebuffer
	 * @param provider
	 *          the provider of aes algorithm
	 * @throws InterruptedException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws ShortBufferException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private void speedTestCipher(ByteBuffer input, String provider)
			throws InterruptedException, InvalidKeyException,
			NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, ShortBufferException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		byte[] key = new byte[16];
		rand.nextBytes(key);

		ByteBuffer encryptResult = ByteBuffer.allocateDirect(DATA_SIZE);
		ByteBuffer decryptResult = ByteBuffer.allocateDirect(DATA_SIZE);
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", provider);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
		speedTestCipherForMode("encrypt", cipher, input, encryptResult);

		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
				new javax.crypto.spec.IvParameterSpec(cipher.getIV()));
		speedTestCipherForMode("decrypt", cipher, encryptResult, decryptResult);

		if (!decryptResult.equals(input)) {
			fail("AES failed decryption");
		}
	}

	private void speedTestCipherForMode(String mode, Cipher cipher, byte[] input,
			byte[] output) throws InterruptedException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException {
		System.out.println("======");
		System.out.println("Testing " + cipher.getAlgorithm() + " "
				+ cipher.getBlockSize() * 8 + " " + mode);

		long[] runtimes = new long[RUNS];
		long total = 0;
		for (int i = 0; i < RUNS; i++) {
			runtimes[i] = testCipher(cipher, input, output);
			total += runtimes[i];
		}
		long averageRuntime = total / RUNS;
		System.out.println(cipher.getAlgorithm() + " Average run time: "
				+ averageRuntime / 1000000 + "ms");
		final long mbPerSecond = (long) ((double) DATA_SIZE / averageRuntime
				* 1000000000 / (1024 * 1024));
		System.out.println(cipher.getAlgorithm() + " Average speed:    "
				+ mbPerSecond + " MB/s");
	}

	private void speedTestCipherForMode(String mode, Cipher cipher,
			ByteBuffer input, ByteBuffer output) throws InterruptedException,
			ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("======");
		System.out.println("Testing " + cipher.getAlgorithm() + " "
				+ cipher.getBlockSize() * 8 + " " + mode);

		long[] runtimes = new long[RUNS];
		long total = 0;
		for (int i = 0; i < RUNS; i++) {
			runtimes[i] = testCipher(cipher, input, output);
			input.flip();
			output.flip();
			total += runtimes[i];
		}
		long averageRuntime = total / RUNS;
		System.out.println(cipher.getAlgorithm() + " Average run time: "
				+ averageRuntime / 1000000 + "ms");
		final long mbPerSecond = (long) ((double) DATA_SIZE / averageRuntime
				* 1000000000 / (1024 * 1024));
		System.out.println(cipher.getAlgorithm() + " Average speed:    "
				+ mbPerSecond + " MB/s");
	}

	private long testCipher(Cipher cipher, byte[] input, byte[] output)
			throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {
		long start = System.nanoTime();

		int outputOffset = 0;
		outputOffset += cipher.update(input, 0, input.length, output);

		cipher.doFinal(output, outputOffset);

		long end = System.nanoTime();
		long delta = end - start;
		return delta;
	}

	private long testCipher(Cipher cipher, ByteBuffer input, ByteBuffer output)
			throws ShortBufferException, IllegalBlockSizeException,
			BadPaddingException {
		long start = System.nanoTime();

		cipher.doFinal(input, output);

		long end = System.nanoTime();
		long delta = end - start;
		return delta;
	}

	/**
	 * Perform the aes performance and correctness test of both aes from SunJCE
	 * provider and DC provider. First use byte array as input data, and then use
	 * direct byte buffer as input data.
	 */
	@Override
	public void performTest() throws Exception {
		System.out.println("Initialising test data.");
		byte[] input = new byte[DATA_SIZE];
		rand.nextBytes(input);
		System.out.println("Init test data complete.");

		String[] providers = { "SunJCE", "DC" };

		System.out.println("##############################################");
		System.out.println("using ByteArray as input and output");
		System.out.println("##############################################");
		for (String provider : providers) {
			System.out.println("provider:" + provider);
			speedTestCipher(input, provider);
		}

		System.out
				.println("###############################################################");
		System.out.println("using ByteBuffer as input and output");
		System.out
				.println("###############################################################");
		for (String provider : providers) {
			System.out.println("provider:" + provider);

			ByteBuffer inputBB = ByteBuffer.allocateDirect(DATA_SIZE);
			inputBB.put(input);
			inputBB.flip();
			speedTestCipher(inputBB, provider);
		}
	}

	public static void main(String[] args) {
		new AESPerfTest().testPerf();
	}
}
