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
import com.intel.diceros.crypto.params.ParametersWithTagLen;
import com.intel.diceros.provider.symmetric.util.Constants;

public class GCMBlockCipher implements BlockCipher{
  private BlockCipher cipher;
  private int tLen = -1;
  private byte[] tag;
  // point to the start index of the tag array
  private int tagStartIndex = -1;
  // point to the next available index of the tag array
  private int tagEndIndex = -1;
  private boolean forEncryption;

  public GCMBlockCipher(BlockCipher c) {
    this.cipher = c;
  }

  @Override
  public void init(boolean forEncryption, CipherParameters params)
      throws IllegalArgumentException {
    this.forEncryption = forEncryption;
    if (params instanceof ParametersWithTagLen) {
      ParametersWithTagLen tLenParam = (ParametersWithTagLen) params;
      cipher.setIV(tLenParam.getIV());
      setTLen(tLenParam.getTLen());
      tag = new byte[tLen * 2];
      tagStartIndex = 0;
      tagEndIndex = 0;

      CipherParameters param = tLenParam.getParameters();
      if (param instanceof KeyParameter) {
        cipher.init(forEncryption, param);
      } else {
        throw new IllegalArgumentException(
                "GCM mode requires GCMParameterSpec");
      }
    } else {
      throw new IllegalArgumentException("GCM mode requires GCMParameterSpec");
    }
  }

  @Override
  public String getAlgorithmName() {
    return cipher.getAlgorithmName() + "/GCM";
  }

  @Override
  public int getBlockSize() {
    return cipher.getBlockSize();
  }

  @Override
  public int getIVSize() {
    //iv can be any size for GCM mode
    return 0;
  }

  @Override
  public void setIV(byte[] IV) {
    cipher.setIV(IV);
  }

  @Override
  public int processBlock(byte[] in, int inOff, int inLen, byte[] out,
      int outOff) throws DataLengthException, IllegalStateException {
    if (forEncryption) {
      return cipher.processBlock(in, inOff, inLen, out, outOff);
    }

    if (inLen + (tagEndIndex - tagStartIndex) <= tLen) {
      // If tag buffer len + input len <= tLen, just putting input into tag buffer.
      put2TagBuffer(in, inOff, inLen, false);
      return 0;
    } else if (inLen < tLen) {
      // If tag buffer len + input len > tLen and input len < tlen, then tag buffer
      // is made up of both original tag buffer and input.
      put2TagBuffer(in, inOff, inLen, false);
      inLen = tagEndIndex - tagStartIndex - tLen;
      int outStored = cipher.processBlock(tag, tagStartIndex, inLen, out, outOff);
      tagStartIndex += inLen;
      return outStored;
    } else {
      // If input len > tlen, then tag buffer is filled up with data from input.
      int outStored1 = 0;
      if (tagEndIndex - tagStartIndex > 0) {
        outStored1 = cipher.processBlock(tag, tagStartIndex,
            tagEndIndex - tagStartIndex, out, outOff);
      }
      int outStored2 = cipher.processBlock(in, inOff,
          inLen - tLen, out, outOff + outStored1);
      put2TagBuffer(in, inOff + inLen - tLen, tLen, true);
      return outStored1 + outStored2;
    }
  }

  @Override
  public int doFinal(byte[] out, int outOff) {
    if (!forEncryption && tagEndIndex - tagStartIndex != tLen) {
      throw new ProviderException("input is too short");
    } else if (!forEncryption) {
      setTag(tag, tagStartIndex, tLen);
      return cipher.doFinal(out, outOff);
    } else {
      int outStored = cipher.doFinal(out, outOff);
      getTag(out, outOff + outStored, tLen);
      return outStored + tLen;
    }
  }

  @Override
  public int processByteBuffer(ByteBuffer input, ByteBuffer output,
      boolean isUpdate) {
    int inLen = input.limit() - input.position();

    if (isUpdate) {
      if (forEncryption) {
        return cipher.processByteBuffer(input, output, isUpdate);
      }

      if (inLen + (tagEndIndex - tagStartIndex) <= tLen) {
        // If tag buffer len + input len <= tLen, just putting input into tag buffer.
        put2TagBuffer(input, false);
        return 0;
      } else if (inLen < tLen) {
        // If tag buffer len + input len > tLen and input len < tlen, then tag buffer
        // is made up of both original tag buffer and input.
        put2TagBuffer(input, false);
        inLen = tagEndIndex - tagStartIndex - tLen;
        int outStored = 0;
        if (output.hasArray()) {
          outStored = cipher.processBlock(tag, tagStartIndex, inLen, output.array(),
              output.arrayOffset() + output.position());
        } else {
          byte[] tmp = new byte[inLen];
          outStored = cipher.processBlock(tag, tagStartIndex, inLen, tmp, 0);
          int outputOldPos = output.position();
          output.put(tmp, 0, outStored);
          output.position(outputOldPos);
        }
        tagStartIndex += inLen;
        return outStored;
      } else {
        // If input len > tlen, then tag buffer is filled up with data from input.
        int outStored1 = 0;
        if (tagEndIndex - tagStartIndex > 0) {
          if (output.hasArray()) {
            outStored1 = cipher.processBlock(tag, tagStartIndex,
                tagEndIndex - tagStartIndex, output.array(),
                output.position() + output.arrayOffset());
            output.position(output.position() + outStored1);
          } else {
            byte[] tmp = new byte[tagEndIndex - tagStartIndex];
            outStored1 = cipher.processBlock(tag, tagStartIndex, tagEndIndex - tagStartIndex, tmp, 0);
            output.put(tmp, 0, outStored1);
          }
        }
        input.limit(input.limit() - tLen);
        int outStored2 = cipher.processByteBuffer(input, output, isUpdate);
        output.position(output.position() - outStored1);

        input.limit(input.limit() + tLen);
        input.position(input.limit() - tLen);
        put2TagBuffer(input, true);

        return outStored1 + outStored2;
      }
    } else {
      if (forEncryption) {
        int outStored = cipher.processByteBuffer(input, output, isUpdate);

        byte[] tmp = new byte[tLen];
        getTag(tmp, 0, tLen);
        int outputOldPos = output.position();
        output.position(outputOldPos + outStored);
        output.put(tmp);
        output.position(outputOldPos);

        return outStored + tLen;
      }

      if (inLen + (tagEndIndex - tagStartIndex) < tLen) {
        throw new ProviderException("input is too short");
      } else if (inLen < tLen) {
        // If tag buffer len + input len >= tLen and input len < tlen, then tag buffer
        // is made up of both original tag buffer and input.
        put2TagBuffer(input, false);
        inLen = tagEndIndex - tagStartIndex - tLen;
        setTag(tag, tagStartIndex + inLen, tLen);
        int outStored = 0;
        if (output.hasArray()) {
          outStored = cipher.processBlock(tag, tagStartIndex, inLen, output.array(),
              output.arrayOffset() + output.position());
        } else {
          byte[] tmp = new byte[inLen];
          outStored = cipher.processBlock(tag, tagStartIndex, inLen, tmp, 0);
          int outputOldPos = output.position();
          output.put(tmp, 0, outStored);
          output.position(outputOldPos);
        }
        tagStartIndex += inLen;
        return outStored;
      } else {
        // If input len > tlen, then tag buffer is filled up with data from input.
        byte[] tagTmp = new byte[tLen];

        int dataStart = input.position();
        int inputOldLimit = input.limit();
        int tagStart = inputOldLimit - tLen;
        input.position(tagStart);
        input.get(tagTmp);
        input.position(dataStart);
        input.limit(tagStart);

        setTag(tagTmp, 0, tLen);

        int outStored1 = 0;
        if (tagEndIndex - tagStartIndex > 0) {
          if (output.hasArray()) {
            outStored1 = cipher.processBlock(tag, tagStartIndex,
                tagEndIndex - tagStartIndex, output.array(),
                output.position() + output.arrayOffset());
            output.position(output.position() + outStored1);
          } else {
            byte[] tmp = new byte[tagEndIndex - tagStartIndex];
            outStored1 = cipher.processBlock(tag, tagStartIndex, tagEndIndex - tagStartIndex, tmp, 0);
            output.put(tmp, 0, outStored1);
          }
        }

        int outStored2 = cipher.processByteBuffer(input, output, isUpdate);
        output.position(output.position() - outStored1);

        input.limit(input.limit() + tLen);

        return outStored1 + outStored2;
      }
    }
  }

  @Override
  public void reset() {
    this.tagStartIndex = this.tagEndIndex = 0;
    cipher.reset();
  }

  @Override
  public void setPadding(int padding) {
    cipher.setPadding(padding);
  }

  @Override
  public int getMode() {
    return Constants.MODE_GCM;
  }

  @Override
  public int getPadding() {
    return cipher.getPadding();
  }

  @Override
  public int getHeadLength() {
    return cipher.getHeadLength();
  }

  private void setTLen(int tLen) {
    if (tLen <=0 || tLen > 128 || (tLen & 0x07) != 0) {
      throw new IllegalArgumentException("Unsupported TagLen Value;" +
          " must be one of {8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128}");
    }

    tLen >>= 3;
    this.tLen = tLen;
  }

  @Override
  public void setTag(byte[] tag, int tagOff, int tLen) {
    cipher.setTag(tag, tagOff, tLen);
  }

  @Override
  public void getTag(byte[] out, int outOff, int tLen) {
    cipher.getTag(out, outOff, tLen);
  }

  @Override
  public int getTagLen() {
    return tLen;
  }

  @Override
  public void updateAAD(byte[] src, int offset, int len) {
    cipher.updateAAD(src, offset, len);
  }

  @Override
  public void updateAAD(ByteBuffer src) {
    cipher.updateAAD(src);
  }

  private void put2TagBuffer(byte[] in, int inOff, int inLen, boolean fromBegining) {
    if (fromBegining) {
      System.arraycopy(in, inOff, tag, 0, inLen);
      tagStartIndex = 0;
      tagEndIndex = inLen;
    } else {
      if (tagEndIndex + inLen <= tag.length) {
        System.arraycopy(in, inOff, tag, tagEndIndex, inLen);
        tagEndIndex += inLen;
      } else {
        int existingBytes = tagEndIndex - tagStartIndex;
        System.arraycopy(tag, tagStartIndex, tag, 0, existingBytes);
        System.arraycopy(in, inOff, tag, existingBytes, inLen);
        tagStartIndex = 0;
        tagEndIndex = existingBytes + inLen;
      }
    }
  }

  private void put2TagBuffer(ByteBuffer input, boolean fromBegining) {
    int inLen = input.limit() - input.position();
    if (fromBegining) {
      input.get(tag, 0, inLen);
      tagStartIndex = 0;
      tagEndIndex = inLen;
    } else {
      if (tagEndIndex + inLen <= tag.length) {
        input.get(tag, tagEndIndex, inLen);
        tagEndIndex += inLen;
      } else {
        int existingBytes = tagEndIndex - tagStartIndex;
        System.arraycopy(tag, tagStartIndex, tag, 0, existingBytes);
        input.get(tag, existingBytes, inLen);
        tagStartIndex = 0;
        tagEndIndex = existingBytes + inLen;
      }
    }
  }
}

