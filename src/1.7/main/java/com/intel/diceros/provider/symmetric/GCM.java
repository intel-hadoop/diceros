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

package com.intel.diceros.provider.symmetric;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import com.intel.diceros.crypto.BlockCipher;
import com.intel.diceros.crypto.engines.AESOpensslEngine;
import com.intel.diceros.crypto.modes.GCMBlockCipher;
import com.intel.diceros.crypto.params.KeyParameter;
import com.intel.diceros.crypto.params.ParametersWithIV;
import com.intel.diceros.crypto.params.ParametersWithTagLen;
import com.intel.diceros.provider.symmetric.util.BaseBlockCipher;
import com.intel.diceros.provider.symmetric.util.BlockCipherProvider;
import com.intel.diceros.provider.symmetric.util.Constants;

public class GCM extends BaseBlockCipher {
  // Use the algorithm provided by default provider if Openssl is unavailable.
  private static boolean DCProviderAvailable =
      AESOpensslEngine.opensslEngineAvailable;
  private Cipher defaultCipher = null;

  
  /**
   * the constructor of GCM mode AES algorithm
   *
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws NoSuchProviderException
   */
  public GCM() throws NoSuchAlgorithmException, NoSuchPaddingException,
          NoSuchProviderException {
    super(new BlockCipherProvider() {
      public BlockCipher get() {
        return new GCMBlockCipher(new AESOpensslEngine(Constants.MODE_GCM));
      }
    });

    if (!DCProviderAvailable) {
      defaultCipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    }
  }

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    if (DCProviderAvailable) {
      super.engineSetMode(mode);
    }
  }

  @Override
  protected void engineSetPadding(String padding)
          throws NoSuchPaddingException {
    if (DCProviderAvailable) {
      super.engineSetPadding(padding);
    }
  }

  @Override
  protected int engineGetBlockSize() {
    if (DCProviderAvailable) {
      return super.engineGetBlockSize();
    } else {
      return defaultCipher.getBlockSize();
    }
  }

  @Override
  protected int engineGetOutputSize(int inputLen) {
    if (DCProviderAvailable) {
      return super.engineGetOutputSize(inputLen);
    } else {
      return defaultCipher.getOutputSize(inputLen);
    }
  }

  @Override
  protected byte[] engineGetIV() {
    if (DCProviderAvailable) {
      return super.engineGetIV();
    } else {
      return defaultCipher.getIV();
    }
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    if (DCProviderAvailable) {
      return super.engineGetParameters();
    } else {
      return defaultCipher.getParameters();
    }
  }

  @Override
  protected AlgorithmParameterSpec getAlgorithmParametersSpec()
      throws NoSuchAlgorithmException, NoSuchProviderException {
    IvParameterSpec ivSpec = (IvParameterSpec)super.getAlgorithmParametersSpec();
    int tLen = ((ParametersWithTagLen)ivParam).getTLen();
    return new GCMParameterSpec(tLen, ivSpec.getIV());
  }

  @Override
  protected void engineInit(int opmode, Key key, SecureRandom random)
          throws InvalidKeyException {
    if (DCProviderAvailable) {
      super.engineInit(opmode, key, random);
    } else {
      defaultCipher.init(opmode, key, random);
    }
  }

  @Override
  protected void engineInit(int opmode, Key key,
                            AlgorithmParameterSpec params, SecureRandom random)
          throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (DCProviderAvailable) {
      super.engineInit(opmode, key, params, random);
    } else {
      defaultCipher.init(opmode, key, params, random);
    }
  }

  @Override
  protected ParametersWithIV retrieveParam(Key key, AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    KeyParameter keyParam = new KeyParameter(key.getEncoded());
    byte[] iv = null;
    int tLen = Constants.GCM_DEFAULT_TAG_LEN;
    if (params == null) {
      iv = null;
    } else if (params instanceof GCMParameterSpec) {
      iv = ((GCMParameterSpec)params).getIV();
      if (iv == null && !cipher.isEncryption()) {
        throw new InvalidAlgorithmParameterException("Must provide IV for decryption.");
      }
      tLen = ((GCMParameterSpec)params).getTLen();
    } else {
      throw new InvalidAlgorithmParameterException("Unsupported parameter: " + params);
    }
    ParametersWithTagLen cipherParam = new ParametersWithTagLen(keyParam, iv, tLen);

    ivParam = cipherParam;

    return cipherParam;
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                            SecureRandom random) throws InvalidKeyException,
          InvalidAlgorithmParameterException {
    if (DCProviderAvailable) {
      super.engineInit(opmode, key, params, random);
    } else {
      defaultCipher.init(opmode, key, params, random);
    }
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    if (DCProviderAvailable) {
      return super.engineUpdate(input, inputOffset, inputLen);
    } else {
      return defaultCipher.update(input, inputOffset, inputLen);
    }
  }

  @Override
  protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                             byte[] output, int outputOffset) throws ShortBufferException {
    if (DCProviderAvailable) {
      return super.engineUpdate(input, inputOffset, inputLen, output,
              outputOffset);
    } else {
      return defaultCipher.update(input, inputOffset, inputLen, output,
              outputOffset);
    }
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
          throws IllegalBlockSizeException, BadPaddingException {
    if (DCProviderAvailable) {
      return super.engineDoFinal(input, inputOffset, inputLen);
    } else {
      if (input == null && inputOffset == 0 && inputLen == 0) {
        return defaultCipher.doFinal();
      } else {
        return defaultCipher.doFinal(input, inputOffset, inputLen);
      }
    }
  }

  @Override
  protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                              byte[] output, int outputOffset) throws ShortBufferException,
          IllegalBlockSizeException, BadPaddingException {
    if (DCProviderAvailable) {
      return super.engineDoFinal(input, inputOffset, inputLen, output,
              outputOffset);
    } else {
      if (input == null && inputOffset == 0 && inputLen == 0) {
        return defaultCipher.doFinal(output, outputOffset);
      } else {
        return defaultCipher.doFinal(input, inputOffset, inputLen, output,
                outputOffset);
      }
    }
  }

  @Override
  protected int engineUpdate(ByteBuffer input, ByteBuffer output)
          throws ShortBufferException {
    if (DCProviderAvailable) {
      return super.engineUpdate(input, output);
    } else {
      return defaultCipher.update(input, output);
    }
  }

  @Override
  protected int engineDoFinal(ByteBuffer input, ByteBuffer output)
          throws ShortBufferException, IllegalBlockSizeException,
          BadPaddingException {
    if (DCProviderAvailable) {
      return super.engineDoFinal(input, output);
    } else {
      return defaultCipher.doFinal(input, output);
    }
  }

  @Override
  protected void engineUpdateAAD(byte[] src, int offset, int len) {
    if (DCProviderAvailable) {
      cipher.updateAAD(src, offset, len);
    } else {
      defaultCipher.updateAAD(src, offset, len);
    }
  }

  @Override
  protected void engineUpdateAAD(ByteBuffer src) {
    if (DCProviderAvailable) {
      cipher.updateAAD(src);
    } else {
      defaultCipher.updateAAD(src);
    }
  }
}

