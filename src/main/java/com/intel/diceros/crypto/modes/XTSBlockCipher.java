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

import java.nio.ByteBuffer;
import java.security.ProviderException;

import com.intel.diceros.crypto.BlockCipher;
import com.intel.diceros.crypto.DataLengthException;
import com.intel.diceros.crypto.params.CipherParameters;
import com.intel.diceros.crypto.params.KeyParameter;
import com.intel.diceros.crypto.params.ParametersWithIV;
import com.intel.diceros.provider.symmetric.util.Constants;

public class XTSBlockCipher implements BlockCipher{
  private BlockCipher cipher;

  public XTSBlockCipher(BlockCipher c) {
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
                "XTS mode requires IvParameterSpec");
      }
    } else {
      throw new IllegalArgumentException("XTS mode requires IvParameterSpec");
    }
  }

  @Override
  public String getAlgorithmName() {
    return cipher.getAlgorithmName() + "/XTS";
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
  public void setIV(byte[] IV) {
    cipher.setIV(IV);
  }

  @Override
  public int processBlock(byte[] in, int inOff, int inLen, byte[] out,
      int outOff) throws DataLengthException, IllegalStateException {
    if (inLen < getBlockSize()) {
      throw new ProviderException("input is too short!");
    }
    return cipher.processBlock(in, inOff, inLen, out, outOff);
  }

  @Override
  public int doFinal(byte[] out, int outOff) {
    return cipher.doFinal(out, outOff);
  }

  @Override
  public int processByteBuffer(ByteBuffer input, ByteBuffer output,
      boolean isUpdate) {
    int inLen = input.limit() - input.position();
    if (inLen < getBlockSize()) {
      throw new ProviderException("input is too short!");
    }
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
  public int getMode() {
    return Constants.MODE_XTS;
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
