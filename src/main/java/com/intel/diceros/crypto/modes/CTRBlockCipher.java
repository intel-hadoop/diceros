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

  /**
   * Basic constructor.
   *
   * @param c the underlying block cipher to be used
   */
  public CTRBlockCipher(BlockCipher c) {
    this.cipher = c;
  }

  @Override
  public void init(boolean forEncryption, CipherParameters params)
      throws IllegalArgumentException {
    if (params instanceof ParametersWithIV) {
      ParametersWithIV ivParam = (ParametersWithIV) params;
      cipher.setIV(ivParam.getIV());

      CipherParameters param = ivParam.getParameters();
      if (param instanceof KeyParameter) {
        cipher.init(forEncryption, param);
      } else {
        throw new IllegalArgumentException(
                "CTR mode requires IvParameterSpec");
      }
    } else {
      throw new IllegalArgumentException("CTR mode requires IvParameterSpec");
    }
  }

  @Override
  public String getAlgorithmName() {
    return cipher.getAlgorithmName() + "/CTR";
  }

  @Override
  public int getBlockSize() {
    return cipher.getBlockSize();
  }

  @Override
  public int getIVSize() {
    return getBlockSize();
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
  public int processByteBuffer(ByteBuffer input, ByteBuffer output, boolean isUpdate) {
    return cipher.processByteBuffer(input, output, isUpdate);
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
    cipher.setIV(IV);
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

  @Override
  public void setTag(byte[] tag, int tagOff, int tLen) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void getTag(byte[] out, int outOff, int tLen) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int getTagLen(){
    throw new UnsupportedOperationException();
  }

  @Override
  public void updateAAD(byte[] src, int offset, int len) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void updateAAD(ByteBuffer src) {
    throw new UnsupportedOperationException();
  }
}
