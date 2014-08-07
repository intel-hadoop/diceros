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

package com.intel.diceros.crypto.engines;

import com.intel.diceros.crypto.BlockCipher;
import com.intel.diceros.crypto.DataLengthException;
import com.intel.diceros.crypto.params.CipherParameters;
import com.intel.diceros.crypto.params.KeyParameter;
import com.intel.diceros.provider.symmetric.util.Constants;

import java.nio.ByteBuffer;

public class AESMutliBufferEngine implements BlockCipher {

  private boolean forEncryption = false;
  private int blockSize = 16;
  private int mode;
  private int padding = Constants.PADDING_PKCS5PADDING;
  private byte[] IV;
  private int head = 2;
  CipherParameters params = null;
  private long aesContext = 0; // context used by openssl

  public AESMutliBufferEngine(int mode) {
    this.mode = mode;
  }

  public AESMutliBufferEngine(int mode, int padding) {
    this.mode = mode;
    this.padding = padding;
  }

  @Override
  public void init(boolean forEncryption, CipherParameters params)
          throws IllegalArgumentException {
    if (params instanceof KeyParameter) {
      this.forEncryption = forEncryption;
      this.params = params;
      aesContext = init(forEncryption, ((KeyParameter) params).getKey(), IV, padding, aesContext);
    } else {
      throw new IllegalArgumentException(
              "invalid parameter passed to AES init - "
                      + params.getClass().getName());
    }
  }

  @Override
  public String getAlgorithmName() {
    return "AES";
  }

  @Override
  public int getBlockSize() {
    return blockSize;
  }

  @Override
  public int processBlock(byte[] in, int inOff, int inLen, byte[] out,
      int outOff) throws DataLengthException, IllegalStateException {
    checkCipherInit();
    return processBlock(aesContext, in, inOff, inLen, out, outOff);
  }

  @Override
  public int doFinal(byte[] out, int outOff) {
    return 0;
  }

  @Override
  public void reset() {
    if (aesContext != 0) {
      destoryCipherContext(aesContext);
      aesContext = 0;
    }
  }

  @Override
  protected void finalize() throws Throwable {
    try {
      reset();
    } finally {
      super.finalize();
    }
  }

  @Override
  public int bufferCrypt(ByteBuffer input, ByteBuffer output, boolean isUpdate) {
    if (isUpdate) {
      throw new UnsupportedOperationException("Mutli Buffer don't support the update method.");
    }
    checkCipherInit();
    return bufferCrypt(aesContext, input, input.position(), input.limit()-input.position(), output,
            output.position(), isUpdate);
  }

  private native int bufferCrypt(long context, ByteBuffer inputDirectBuffer, int start,
      int inputLength, ByteBuffer outputDirectBuffer, int begin, boolean isUpdate);

  protected native long init(boolean forEncryption, byte[] key, byte[] iv, int padding, long oldContext);

  private native int processBlock(long context, byte[] in, int inOff, int inLen, byte[] out, int outOff);

  private native int destoryCipherContext(long context);

  @Override
  public void setIV(byte[] IV) {
    this.IV = IV;
  }

  @Override
  public void setPadding(int padding) {
    this.padding = padding;
  }

  @Override
  public int getMode() {
    return this.mode;
  }

  @Override
  public int getPadding() {
    return this.padding;
  }

  @Override
  public int getHeadLength() {
    return this.head;
  }

  private void checkCipherInit() {
    if (aesContext == 0) {
      init(forEncryption, params);
    }
  }
}
