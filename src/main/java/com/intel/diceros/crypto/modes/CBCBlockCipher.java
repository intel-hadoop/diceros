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
import com.intel.diceros.crypto.params.ParametersWithIV;
import com.intel.diceros.provider.symmetric.util.Constants;

import java.nio.ByteBuffer;

/**
 * Implements Cipher-Block-Chaining (CBC) mode on top of a simple cipher.
 */
public class CBCBlockCipher implements BlockCipher {
  private BlockCipher cipher = null;
  private boolean encrypting;

  /**
   * Basic constructor.
   *
   * @param cipher the block cipher to be used as the basis of chaining.
   */
  public CBCBlockCipher(BlockCipher cipher) {
    this.cipher = cipher;
  }

  /**
   * Initialize the cipher and, possibly, the initialization vector (IV).
   * If an IV isn't passed as part of the parameter, the IV will be all zeros.
   *
   * @param encrypting if true the cipher is initialized for
   *                   encryption, if false for decryption.
   * @param params     the key and other data required by the cipher.
   * @throws IllegalArgumentException if the params argument is inappropriate.
   */
  public void init(boolean encrypting, CipherParameters params)
      throws IllegalArgumentException {
    boolean oldEncrypting = this.encrypting;
    this.encrypting = encrypting;

    CipherParameters keyParam = null;
    if (params instanceof ParametersWithIV) {
      ParametersWithIV ivParam = (ParametersWithIV) params;
      cipher.setIV(ivParam.getIV());
      keyParam = ivParam.getParameters();
    } else {
      keyParam = params;
    }

    // if it's null, key is to be reused.
    if (keyParam != null || oldEncrypting == encrypting) {
      cipher.init(encrypting, keyParam);
    } else {
      throw new IllegalArgumentException("cannot change encrypting state without providing key.");
    }
  }

  @Override
  public String getAlgorithmName() {
    return cipher.getAlgorithmName() + "/CBC";
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
  public int processBlock(byte[] in, int inOff, int inLen, byte[] out, int outOff)
      throws DataLengthException, IllegalStateException {
    /**
     * EVP_DecryptInit_ex(), EVP_DecryptUpdate() and EVP_DecryptFinal_ex() are the corresponding
     * decryption operations. EVP_DecryptFinal() will return an error code if padding is enabled
     * and the final block is not correctly formatted. The parameters and restrictions are identical
     * to the encryption operations except that if padding is enabled the decrypted data buffer out
     * passed to EVP_DecryptUpdate() should have sufficient room for (inl + cipher_block_size) bytes
     * unless the cipher block size is 1 in which case inl bytes is sufficient.
     */
    if (!this.encrypting && this.cipher.getPadding() == Constants.PADDING_PKCS5PADDING
            && inLen > out.length - outOff) {
      throw new DataLengthException("Need at least " + inLen +
              " bytes of space in output.");
    }
    return cipher.processBlock(in, inOff, inLen, out, 0);
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
  public void setIV(byte[] IV) {
    cipher.setIV(IV);
  }

  @Override
  public void setPadding(int padding) {
    cipher.setPadding(padding);
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
