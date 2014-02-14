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
 * Implements the CTS mode on top of a simple block cipher.
 * <p>NOTE: CTS requires the input data to be at least one block long.
 * Callers must buffer the input data to make sure the input data passed
 * in is not shorter than one block.
 *
 */
public class CTSBlockCipher implements BlockCipher {
  private final BlockCipher cipher;
  private boolean forEncryption;
  private int blockSize;

  /**
   * Basic constructor.
   *
   * @param c the underlying block cipher to be used
   */
  public CTSBlockCipher(BlockCipher c) {
    this.cipher = c;
    this.blockSize = cipher.getBlockSize();
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
    this.forEncryption = forEncryption;
    cipher.init(forEncryption, params);
  }

  @Override
  public String getAlgorithmName() {
    return cipher.getAlgorithmName() + "/CTS" + (blockSize * 8);
  }

  @Override
  public int getBlockSize() {
    return cipher.getBlockSize();
  }

  @Override
  public int processBlock(byte[] in, int inOff, int inLen, byte[] out,
      int outOff) throws DataLengthException, IllegalStateException {
    if (forEncryption) {
      return encryptCTS(in, inOff, inLen, out, outOff);
    } else {
      return decryptCTS(in, inOff, inLen, out, outOff);
    }
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
  public byte[] getIV() {
    return cipher.getIV();
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

  protected int encryptCTS(byte[] in, int inOffset, int inLen,
      byte[] out, int outOffset) throws IllegalStateException {
    if (inLen < blockSize) {
      throw new IllegalStateException("CTS input too short, must be at least " +
        blockSize + " bytes (we have " + inLen + ")");
    } else if (inLen == blockSize) {
      cipher.processBlock(in, inOffset, inLen, out, outOffset);
    } else {
      // number of bytes in the last block
      int nLeft = inLen % blockSize;
      if (nLeft == 0) {
        cipher.processBlock(in, inOffset, inLen, out, outOffset);
        // swap the last two blocks after encryption
        int lastBlkIndex = outOffset + inLen - blockSize;
        int nextToLastBlkIndex = lastBlkIndex - blockSize;
        byte[] tmp = new byte[blockSize];
        System.arraycopy(out, lastBlkIndex, tmp, 0, blockSize);
        System.arraycopy(out, nextToLastBlkIndex, out, lastBlkIndex, blockSize);
        System.arraycopy(tmp, 0, out, nextToLastBlkIndex, blockSize);
      } else {
        int newInLen = inLen - (blockSize + nLeft);
        if (newInLen > 0) {
          cipher.processBlock(in, inOffset, newInLen, out, outOffset);
          inOffset += newInLen;
          outOffset += newInLen;
        }
        // Do final CTS step for last two blocks (the second of which
        // may or may not be incomplete).
        byte[] tmp = new byte[blockSize];
	byte[] iv = cipher.getIV();
        for (int i = 0; i < blockSize; i++) {
          tmp[i] = (byte) (in[inOffset+i] ^ iv[i]);
        }
        byte[] tmp2 = new byte[blockSize];
        cipher.processBlock(tmp, 0, blockSize, tmp2, 0);
        System.arraycopy(tmp2, 0, out, outOffset+blockSize, nLeft);
        for (int i=0; i<nLeft; i++) {
          tmp2[i] = (byte)(in[inOffset+blockSize+i] ^ tmp2[i]);
        }
        cipher.processBlock(tmp2, 0, blockSize, out, outOffset);
      }
    }
    return inLen;
  }

  protected int decryptCTS(byte[] in, int inOffset, int inLen,
      byte[] out, int outOffset) throws IllegalStateException {
    if (inLen < blockSize) {
      throw new IllegalStateException("CTS input too short, must be at least " +
        blockSize + " bytes (we have " + inLen + ")");
    } else if (inLen == blockSize) {
      cipher.processBlock(in, inOffset, inLen, out, outOffset);
    } else {
      // number of bytes in the last block
      int nLeft = inLen % blockSize;
      if (nLeft == 0) {
        // swap the last two blocks before decryption
        int lastBlkIndex = inOffset + inLen - blockSize;
        int nextToLastBlkIndex = inOffset + inLen - 2*blockSize;
        byte[] tmp = new byte[2*blockSize];
        System.arraycopy(in, lastBlkIndex, tmp, 0, blockSize);
        System.arraycopy(in, nextToLastBlkIndex, tmp, blockSize, blockSize);
        int inLen2 = inLen-2*blockSize;
        cipher.processBlock(in, inOffset, inLen2, out, outOffset);
        cipher.processBlock(tmp, 0, 2*blockSize, out, outOffset+inLen2);
      } else {
        int newInLen = inLen-(blockSize+nLeft);
        if (newInLen > 0) {
          cipher.processBlock(in, inOffset, newInLen, out, outOffset);
          inOffset += newInLen;
          outOffset += newInLen;
        }
        // Do final CTS step for last two blocks (the second of which
        // may or may not be incomplete).
        byte[] tmp = new byte[blockSize];
        cipher.processBlock(in, inOffset, blockSize, tmp, 0);
        for (int i = 0; i < nLeft; i++) {
          out[outOffset+blockSize+i] = (byte)(in[inOffset+blockSize+i] ^ tmp[i]);
        }
        System.arraycopy(in, inOffset+blockSize, tmp, 0, nLeft);
	cipher.processBlock(tmp, 0, blockSize, out, outOffset);
	byte[] iv = cipher.getIV();
        for (int i=0; i<blockSize; i++) {
          out[outOffset+i] = (byte)(out[outOffset+i]^iv[i]);
        }
      }
    }
    return inLen;
  }

}
