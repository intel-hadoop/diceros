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

package com.intel.diceros.crypto;

import com.intel.diceros.crypto.params.CipherParameters;

import java.nio.ByteBuffer;

/**
 * Block cipher engines are expected to conform to this interface.
 */
public interface BlockCipher {
  /**
   * Initialise the cipher.
   *
   * @param forEncryption if true the cipher is initialised for encryption, if false for
   *                      decryption
   * @param params        the key and other data required by the cipher
   * @throws IllegalArgumentException if the <code>params</code> argument is inappropriate
   */
  public void init(boolean forEncryption, CipherParameters params)
          throws IllegalArgumentException;

  /**
   * Return the name of the algorithm the cipher implements.
   *
   * @return the name of the algorithm the cipher implements
   */
  public String getAlgorithmName();

  /**
   * Return the block size for this cipher (in bytes).
   *
   * @return the block size for this cipher in bytes
   */
  public int getBlockSize();

  /**
   * Set the initialization vector (IV) for the cipher.
   *
   * @param IV initialization vector for the cipher
   */
  public void setIV(byte[] IV);

  /**
   * Process one block of input from the array in and write it to the out array.
   * <p/>
   * <p/>
   * The first <code>inLen</code> bytes in the <code>in</code> buffer, starting
   * at <code>inOff</code> inclusive, are processed, and the result is stored in
   * the <code>out</code> buffer, starting at <code>outOff</code> inclusive.
   *
   * @param in     the input buffer
   * @param inOff  the offset in <code>in</code> where the input starts
   * @param inLen  the input length
   * @param out    the buffer for the result
   * @param outOff the offset in <code>out</code> where the result is stored
   * @return the number of bytes stored in <code>out</code>
   * @throws DataLengthException   if there isn't enough data in <code>in</code>, or space in
   *                               <code>out</code>
   * @throws IllegalStateException if the cipher isn't initialized
   */
  public int processBlock(byte[] in, int inOff, int inLen, byte[] out,
                          int outOff) throws DataLengthException, IllegalStateException;

  /**
   * Process the partial block cached and write it to the out array.
   *
   * @param out    the buffer for the result
   * @param outOff the offset in <code>out</code> where the result is stored
   * @return the number of bytes processed and produced.
   */
  public int doFinal(byte[] out, int outOff);

  /**
   * Process data from input ByteBuffer and write it to output ByteBuffer. Only
   * direct byte buffer is supported.
   * <p/>
   * <p/>
   * All <code>input.remaining()</code> bytes starting at
   * <code>input.position()</code> are processed. The result is stored in the
   * <code>output</code> buffer.
   *
   * @param input    the input ByteBuffer
   * @param output   the output ByteBuffer
   * @param isUpdate if true the cipher is doing engineUpdate, if false the cipher is
   *                 doing engineDoFinal
   * @return the number of bytes stored in <code>output</code>
   */
  public int bufferCrypt(ByteBuffer input, ByteBuffer output, boolean isUpdate);

  /**
   * Reset the cipher. After resetting the cipher is in the same state as it was
   * after the last init (if there was one).
   */
  public void reset();

  /**
   * Set the padding type for the cipher.
   *
   * @param padding padding type for the cipher
   */
  public void setPadding(String padding);

  /**
   * Get the mode of the cipher.
   *
   * @return get the mode of the cipher
   */
  public String getMode();

  public String getPadding();

  public int getHeadLength();
}
