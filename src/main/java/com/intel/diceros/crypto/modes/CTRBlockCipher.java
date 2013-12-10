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

package com.intel.diceros.crypto.modes;

import com.intel.diceros.crypto.BlockCipher;
import com.intel.diceros.crypto.DataLengthException;
import com.intel.diceros.crypto.params.CipherParameters;
import com.intel.diceros.crypto.params.KeyParameter;
import com.intel.diceros.crypto.params.ParametersWithIV;

import java.nio.ByteBuffer;

/**
 * Implements the CTR mode on top of a simple block cipher. This mode is also
 * known as Segmented Integer Counter (SIC) mode.
 */
public class CTRBlockCipher implements BlockCipher {
  private final BlockCipher cipher;
  private int blockSize;
  private byte[] IV;

  /**
   * Basic constructor.
   *
   * @param c the underlying block cipher to be used
   */
  public CTRBlockCipher(BlockCipher c) {
    this.cipher = c;
    this.blockSize = cipher.getBlockSize();
    this.IV = new byte[this.blockSize];
  }

  /**
   * return the underlying block cipher that we are wrapping.
   *
   * @return the underlying block cipher that we are wrapping
   */
  public BlockCipher getUnderlyingCipher() {
    return cipher;
  }

  @Override
  public void init(boolean forEncryption, CipherParameters params)
          throws IllegalArgumentException {
    if (params instanceof ParametersWithIV) {
      ParametersWithIV ivParam = (ParametersWithIV) params;
      byte[] iv = ivParam.getIV();
      System.arraycopy(iv, 0, IV, 0, IV.length);

      cipher.setIV(this.IV);

      CipherParameters param = ivParam.getParameters();
      if ((param instanceof KeyParameter)
              && (((KeyParameter) param).getKey().length * 8 == 128 || ((KeyParameter) param)
              .getKey().length * 8 == 256)) {
        cipher.init(forEncryption, param);
      } else {
        throw new IllegalArgumentException(
                "CTR mode requires KeyParameter with key length 128 or 256");
      }
    } else {
      throw new IllegalArgumentException("CTR mode requires ParametersWithIV");
    }
  }

  @Override
  public String getAlgorithmName() {
    return cipher.getAlgorithmName() + "/CTR" + (blockSize * 8);
  }

  @Override
  public int getBlockSize() {
    return cipher.getBlockSize();
  }

  @Override
  public int processBlock(byte[] in, int inOff, int inLen, byte[] out,
                          int outOff) throws DataLengthException, IllegalStateException {
    return cipher.processBlock(in, inOff, inLen, out, outOff);
  }

  @Override
  public int doFinal(byte[] out, int outOff) {
    return cipher.doFinal(out, outOff);
  }

  @Override
  public int bufferCrypt(ByteBuffer input, ByteBuffer output, boolean isUpdate) {
    return cipher.bufferCrypt(input, output, isUpdate);
  }

  @Override
  public void reset() {
    cipher.reset();
  }

  @Override
  public void setPadding(int padding) {
    cipher.setPadding(padding);
  }

  @Override
  public void setIV(byte[] IV) {
    this.IV = IV;
    cipher.setIV(this.IV);
  }

  @Override
  public int getMode() {
    return cipher.getMode();
  }

  @Override
  public int getPadding() {
    return cipher.getPadding();
  }

  @Override
  public int getHeadLength() {
    return cipher.getHeadLength();
  }
}
