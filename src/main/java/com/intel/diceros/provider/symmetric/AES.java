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

import com.intel.diceros.crypto.BlockCipher;
import com.intel.diceros.crypto.engines.AESMutliBufferEngine;
import com.intel.diceros.crypto.engines.AESOpensslEngine;
import com.intel.diceros.crypto.modes.CTSBlockCipher;
import com.intel.diceros.provider.config.ConfigurableProvider;
import com.intel.diceros.provider.symmetric.util.BaseBlockCipher;
import com.intel.diceros.provider.symmetric.util.BlockCipherProvider;
import com.intel.diceros.provider.symmetric.util.Constants;
import com.intel.diceros.provider.util.AlgorithmProvider;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class implements the AES algorithm in the mode <code>CTR</code> and
 * padding schemes <code>NoPadding</code>
 */
public class AES {
  private AES() {
  }

  public static final class CTR extends BaseBlockCipher {
    private static boolean DCProviderAvailable = true;
    private Cipher defaultCipher = null;

    // load the libraries needed by AES algorithm, when failed, use the
    // algorithm provided by "SunJCE" provider
    static {
      try {
        System.loadLibrary("crypto");
        System.loadLibrary("diceros");
      } catch (UnsatisfiedLinkError e) {
        DCProviderAvailable = false;
      }
    }

    /**
     * the constructor of CTR mode AES algorithm
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public CTR() throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException {
      super(new BlockCipherProvider() {
        public BlockCipher get() {
          return new AESOpensslEngine(Constants.MODE_CTR);
        }
      });

      if (!DCProviderAvailable) {
        defaultCipher = Cipher.getInstance("AES/CTR/NoPadding", "SunJCE");
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
  }

  public static final class CBC extends BaseBlockCipher {
    protected static boolean DCProviderAvailable = true;
    protected Cipher defaultCipher = null;

    // load the libraries needed by AES algorithm, when failed, use the
    // algorithm provided by "SunJCE" provider
    static {
      try {
        System.loadLibrary("crypto");
        System.loadLibrary("diceros");
      } catch (UnsatisfiedLinkError e) {
        DCProviderAvailable = false;
      }
    }

    /**
     * the constructor of CTR mode AES algorithm
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public CBC() throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException {
      super(new BlockCipherProvider() {
        public BlockCipher get() {
          return new AESOpensslEngine(Constants.MODE_CBC);
        }
      });

      if (!DCProviderAvailable) {
        defaultCipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
      }
    }

    public CBC(BlockCipherProvider blockCipherProvider) {
      super(blockCipherProvider);
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
  }

  public static final class CTS extends BaseBlockCipher {
    protected static boolean DCProviderAvailable = true;
    protected Cipher defaultCipher = null;

    // load the libraries needed by AES algorithm, when failed, use the
    // algorithm provided by "SunJCE" provider
    static {
      try {
        System.loadLibrary("crypto");
        System.loadLibrary("diceros");
      } catch (UnsatisfiedLinkError e) {
        DCProviderAvailable = false;
      }
    }

    /**
     * the constructor of CTR mode AES algorithm
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public CTS() throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException {
      super(new BlockCipherProvider() {
        public BlockCipher get() {
          return new CTSBlockCipher(new AESOpensslEngine(Constants.MODE_CBC));
        }
      });

      if (!DCProviderAvailable) {
        defaultCipher = Cipher.getInstance("AES/CTS/NoPadding", "SunJCE");
      }
    }

    public CTS(BlockCipherProvider blockCipherProvider) {
      super(blockCipherProvider);
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
  }

  public static final class MBCBC extends BaseBlockCipher {
    protected static boolean DCProviderAvailable = true;
    private Cipher defaultCipher = null;

    // load the libraries needed by AES algorithm, when failed, use the
    // algorithm provided by "SunJCE" provider
    static {
      try {
        System.loadLibrary("crypto");
        System.loadLibrary("diceros");
      } catch (UnsatisfiedLinkError e) {
        DCProviderAvailable = false;
        throw new UnsatisfiedLinkError(e.getMessage());
      }
    }

    /**
     * the constructor of MBCBC mode AES algorithm
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     */
    public MBCBC() throws NoSuchAlgorithmException, NoSuchPaddingException,
            NoSuchProviderException {
      super(new BlockCipherProvider() {
        public BlockCipher get() {
          return new AESMutliBufferEngine(Constants.MODE_CBC);
        }
      });

      if (!DCProviderAvailable) {
        defaultCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
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
        throw new UnsupportedOperationException("Multi Buffer didn't support this method");
      } else {
        return defaultCipher.update(input, inputOffset, inputLen);
      }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset) throws ShortBufferException {
      if (DCProviderAvailable) {
        throw new UnsupportedOperationException("Multi Buffer didn't support this method");
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
        throw new UnsupportedOperationException("Multi Buffer didn't support this method");
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
  }

  public static class Mappings extends AlgorithmProvider {
    private static final String PREFIX = AES.class.getName(); // the outer class
    // name

    public Mappings() {
    }

    @Override
    public void configure(ConfigurableProvider provider) {
      provider.addAlgorithm("Cipher.AES/CTR", PREFIX + "$CTR");
      provider.addAlgorithm("Cipher.AES/CBC", PREFIX + "$CBC");
      provider.addAlgorithm("Cipher.AES/CTS", PREFIX + "$CTS");
      provider.addAlgorithm("Cipher.AES/MBCBC", PREFIX + "$MBCBC");
      provider.addAlgorithm("Cipher.AES SupportedModes", "CTR128|CTR256|CTR|CBC128|CBC256|CBC|CTS128|CTS256|CTS");
      provider.addAlgorithm("Cipher.AES SupportedPaddings", "NOPADDING|PKCS5PADDING");
    }
  }
}
