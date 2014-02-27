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

package com.intel.diceros.provider.symmetric.util;

import com.intel.diceros.crypto.BlockCipher;
import com.intel.diceros.crypto.DataLengthException;
import com.intel.diceros.crypto.InvalidCipherTextException;
import com.intel.diceros.crypto.OutputLengthException;
import com.intel.diceros.crypto.modes.CBCBlockCipher;
import com.intel.diceros.crypto.modes.CTRBlockCipher;
import com.intel.diceros.crypto.modes.CTSBlockCipher;
import com.intel.diceros.crypto.params.CipherParameters;
import com.intel.diceros.crypto.params.KeyParameter;
import com.intel.diceros.crypto.params.ParametersWithIV;
import com.intel.diceros.provider.DicerosProvider;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Locale;

/**
 * Base Class for BlockCipher.
 */
public abstract class BaseBlockCipher extends CipherSpi {

  @SuppressWarnings("rawtypes")
  private Class[] availableSpecs = {IvParameterSpec.class,};

  private BlockCipher baseEngine; // the underlying cipher engine, do the actual
  // encryption and decryption work
  private GenericBlockCipher cipher; // wrapping baseEngine, do some pre
  // processing work
  private ParametersWithIV ivParam; // parameter of key data, initialization
  // vector, etc
  private int ivLength = 0; // the initialization vector length
  protected AlgorithmParameters engineParams = null;
  //private String modeName = null;

  /**
   * Constructor
   *
   * @param engine the underlying cipher engine, do the actual encryption and
   *               decryption work
   */
  protected BaseBlockCipher(BlockCipher engine) {
    baseEngine = engine;
    cipher = new GenericBlockCipherImpl(engine);
  }

  /**
   * Constructor
   *
   * @param provider provide the the underlying cipher engine which does the actual
   *                 encryption and decryption work
   */
  protected BaseBlockCipher(BlockCipherProvider provider) {
    baseEngine = provider.get();
    cipher = new GenericBlockCipherImpl(baseEngine);

    int modeName = baseEngine.getMode();
    if (modeName == Constants.MODE_CTR) {
      cipher = new GenericBlockCipherImpl(new CTRBlockCipher(baseEngine));
      ivLength = baseEngine.getBlockSize();
    } else if (modeName == Constants.MODE_CBC) {
      cipher = new GenericBlockCipherImpl(new CBCBlockCipher(baseEngine));
      ivLength = baseEngine.getBlockSize();
    } else if (modeName == Constants.MODE_CTS) {
      cipher = new GenericBlockCipherImpl(new CTSBlockCipher(baseEngine));
      ivLength = baseEngine.getBlockSize();
    }
  }

  @Override
  protected int engineGetBlockSize() {
    return baseEngine.getBlockSize();
  }

  @Override
  protected byte[] engineGetIV() {
    return (ivParam != null) ? ivParam.getIV() : null;
  }

  @Override
  protected int engineGetKeySize(Key key) {
    return key.getEncoded().length * 8;
  }

  @Override
  protected int engineGetOutputSize(int inputLen) {
    if (inputLen < 0) {
      throw new IllegalArgumentException("Input size must be equal "
              + "to or greater than zero");
    }
    return cipher.getOutputSize(inputLen);
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    if (engineParams == null && ivParam != null) {
      String name = cipher.getUnderlyingCipher().getAlgorithmName();

      if (name.indexOf('/') >= 0) {
        name = name.substring(0, name.indexOf('/'));
      }

      try {
        engineParams = AlgorithmParameters.getInstance(name);
        engineParams.init(ivParam.getIV());
      } catch (Exception e) {
        throw new RuntimeException(e.toString());
      }
    }

    return engineParams;
  }

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    String modeName = mode.toUpperCase(Locale.ENGLISH);
    if (!modeName.startsWith("CTR") && 
	!modeName.startsWith("CBC") &&
	!modeName.startsWith("CTS")) {
      throw new NoSuchAlgorithmException("can't support mode " + mode);
    }
  }

  @Override
  protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    String paddingName = padding.toUpperCase(Locale.ENGLISH);
    if (paddingName.equals("NOPADDING") || paddingName.equals("PKCS5PADDING")) {
      cipher = new GenericBlockCipherImpl(cipher.getUnderlyingCipher());
      cipher.setPadding(paddingName);
    } else {
      throw new NoSuchPaddingException("Padding " + padding + " unknown.");
    }
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
                            SecureRandom random) throws InvalidKeyException,
          InvalidAlgorithmParameterException {
    CipherParameters param;

    this.engineParams = null;

    // basic key check
    if (!(key instanceof SecretKey)) {
      throw new InvalidKeyException("Key for algorithm " + key.getAlgorithm()
              + " not suitable for symmetric enryption.");
    }

    // a note on iv's - if ivLength is zero the IV gets ignored (we don't use
    // it).
    if (params == null) {
      param = new KeyParameter(key.getEncoded());
    } else if (params instanceof IvParameterSpec) {
      if (ivLength != 0) {
        IvParameterSpec p = (IvParameterSpec) params;

        if (p.getIV().length != ivLength) {
          throw new InvalidAlgorithmParameterException("IV must be " + ivLength
                  + " bytes long.");
        }

        param = new ParametersWithIV(new KeyParameter(key.getEncoded()),
                p.getIV());
        ivParam = (ParametersWithIV) param;
      } else {
        param = new KeyParameter(key.getEncoded());
      }
    } else {
      throw new InvalidAlgorithmParameterException("unknown parameter type.");
    }

    if ((ivLength != 0) && !(param instanceof ParametersWithIV)) {
      SecureRandom ivRandom = random;

      if (ivRandom == null) {
        try {
          ivRandom = SecureRandom.getInstance("DRNG",
                  DicerosProvider.PROVIDER_NAME);
        } catch (Exception e) {
          ivRandom = new SecureRandom();
        }
      }

      if ((opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.WRAP_MODE)) {
        byte[] iv = new byte[ivLength];

        ivRandom.nextBytes(iv);
        param = new ParametersWithIV(param, iv);
        ivParam = (ParametersWithIV) param;
      } else {
        throw new InvalidAlgorithmParameterException(
                "no IV set when one expected");
      }
    }

    try {
      switch (opmode) {
        case Cipher.ENCRYPT_MODE:
        case Cipher.WRAP_MODE:
          cipher.init(true, param);
          break;
        case Cipher.DECRYPT_MODE:
        case Cipher.UNWRAP_MODE:
          cipher.init(false, param);
          break;
        default:
          throw new InvalidParameterException("unknown opmode " + opmode
                  + " passed");
      }
    } catch (Exception e) {
      throw new InvalidKeyException(e.getMessage());
    }
  }

  @SuppressWarnings("unchecked")
  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                            SecureRandom random) throws InvalidKeyException,
          InvalidAlgorithmParameterException {
    AlgorithmParameterSpec paramSpec = null;

    if (params != null) {
      for (int i = 0; i != availableSpecs.length; i++) {
        try {
          paramSpec = params.getParameterSpec(availableSpecs[i]);
          break;
        } catch (Exception e) {
          // try another if possible
        }
      }

      if (paramSpec == null) {
        throw new InvalidAlgorithmParameterException("can't handle parameter "
                + params.toString());
      }
    }

    engineInit(opmode, key, paramSpec, random);

    engineParams = params;
  }

  @Override
  protected void engineInit(int opmode, Key key, SecureRandom random)
          throws InvalidKeyException {
    try {
      engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new InvalidKeyException(e.getMessage());
    }
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    int length = cipher.getOutputSize(inputLen);

    if (inputOffset < 0 || inputLen < 0
            || (input != null && (inputOffset + inputLen) > input.length)) {
      throw new IllegalArgumentException(
              "input offset or input length is nagetive, or input exceeds the array boundary!");
    }

    if (length > 0) {
      byte[] out = new byte[length];
      int len = cipher.processBytes(input, inputOffset, inputLen, out, 0);
      if (len == 0) {
        return null;
      } else if (len != out.length) {
        byte[] tmp = new byte[len];
        System.arraycopy(out, 0, tmp, 0, len);
        return tmp;
      }
      return out;
    }

    cipher.processBytes(input, inputOffset, inputLen, null, 0);
    return null;
  }

  @Override
  protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                             byte[] output, int outputOffset) throws ShortBufferException {
    if (inputOffset < 0 || inputLen < 0 || outputOffset < 0
            || (input != null && (inputOffset + inputLen) > input.length)) {
      throw new IllegalArgumentException(
              "input offset or input length or output offset is nagetive, or input exceeds the array boundary!");
    }

    try {
      return cipher.processBytes(input, inputOffset, inputLen, output,
              outputOffset);
    } catch (DataLengthException e) {
      throw new ShortBufferException(e.getMessage());
    }
  }

  @Override
  protected int engineUpdate(ByteBuffer input, ByteBuffer output)
          throws ShortBufferException {
    if ((input == null) || (output == null)) {
      throw new IllegalArgumentException("Buffers must not be null");
    }
    if (input == output) {
      throw new IllegalArgumentException("Input and output buffers must "
              + "not be the same object, consider using buffer.duplicate()");
    }
    if (output.isReadOnly()) {
      throw new ReadOnlyBufferException();
    }
    return cipher.processBytes(input, output);
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
          throws IllegalBlockSizeException, BadPaddingException {
    if (inputOffset < 0 || inputLen < 0
            || (input != null && (inputOffset + inputLen) > input.length)) {
      throw new IllegalArgumentException(
              "input offset or input length is nagetive, or input exceeds the array boundary!");
    }

    int len = 0;
    byte[] tmp = new byte[engineGetOutputSize(inputLen)];

    if (inputLen != 0) {
      len = cipher.processBytes(input, inputOffset, inputLen, tmp, 0);
    }

    try {
      len += cipher.doFinal(tmp, len);
    } catch (DataLengthException e) {
      throw new IllegalBlockSizeException(e.getMessage());
    } catch (InvalidCipherTextException e) {
      throw new BadPaddingException(e.getMessage());
    }

    if (len == tmp.length) {
      return tmp;
    }

    byte[] out = new byte[len];
    System.arraycopy(tmp, 0, out, 0, len);
    return out;
  }

  @Override
  protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                              byte[] output, int outputOffset) throws IllegalBlockSizeException,
          BadPaddingException, ShortBufferException {
    if (inputOffset < 0 || inputLen < 0 || outputOffset < 0
            || (input != null && (inputOffset + inputLen) > input.length)) {
      throw new IllegalArgumentException(
              "input offset or input length or output offset is nagetive, or input exceeds the array boundary!");
    }

    try {
      int len = 0;

      if (inputLen != 0) {
        len = cipher.processBytes(input, inputOffset, inputLen, output,
                outputOffset);
      }

      return (len + cipher.doFinal(output, outputOffset + len));
    } catch (OutputLengthException e) {
      throw new ShortBufferException(e.getMessage());
    } catch (DataLengthException e) {
      throw new IllegalBlockSizeException(e.getMessage());
    } catch (InvalidCipherTextException e) {
      throw new BadPaddingException(e.getMessage());
    }
  }

  @Override
  protected int engineDoFinal(ByteBuffer input, ByteBuffer output)
          throws ShortBufferException, IllegalBlockSizeException,
          BadPaddingException {
    if ((input == null) || (output == null)) {
      throw new IllegalArgumentException("Buffers must not be null");
    }
    if (input == output) {
      throw new IllegalArgumentException("Input and output buffers must "
              + "not be the same object, consider using buffer.duplicate()");
    }
    if (output.isReadOnly()) {
      throw new ReadOnlyBufferException();
    }
    return cipher.doFinal(input, output);
  }

  static private interface GenericBlockCipher {
    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException;

    public String getAlgorithmName();

    public BlockCipher getUnderlyingCipher();

    public int getOutputSize(int len);

    public int processBytes(byte[] in, int inOff, int len, byte[] out,
                            int outOff) throws DataLengthException;

    public int processBytes(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException;

    public int doFinal(byte[] out, int outOff) throws IllegalStateException,
            InvalidCipherTextException;

    public int doFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException;

    public void setPadding(String padding) throws NoSuchPaddingException;
  }

  private static class GenericBlockCipherImpl implements GenericBlockCipher {

    /*
     *
     */
    private BlockCipher cipher;

    /*
     * the Padding type
     */
    private String padding = NOPADDING;

    /*
     * the value of NoPadding
     */
    private static final String NOPADDING = "NOPADDING";

    /*
     * are we encrypting or not?
     */
    private boolean forEncryption;

    /*
     * index of the content size left in the buffer
     */
    private int buffered = 0;

    /*
     * the head length of encryption
     */
    private int head = 0;

    /*
     * internal buffer
     */
    private int blockSize = 0;

    GenericBlockCipherImpl(BlockCipher cipher) {
      this.cipher = cipher;
      this.head = cipher.getHeadLength();
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params)
            throws IllegalArgumentException {
      this.buffered = 0;
      this.forEncryption = forEncryption;
      cipher.init(forEncryption, params);
      blockSize = cipher.getBlockSize();

    }

    @Override
    public String getAlgorithmName() {
      return cipher.getAlgorithmName();
    }

    @Override
    public BlockCipher getUnderlyingCipher() {
      return cipher;
    }

    @Override
    public int getOutputSize(int len) {

      if (len == 0 && head == 2) {
        return 0;
      }

      int totalLen = buffered + len;

      if (padding.equals(NOPADDING))
        return totalLen;

      if (!forEncryption)
        return totalLen;

      if (totalLen < blockSize)
        return blockSize;

      return totalLen + blockSize - (len % blockSize) + head;
    }

    /**
     * process an array of bytes, producing output if necessary.
     *
     * @param in     the input byte array.
     * @param inOff  the offset at which the input data starts.
     * @param len    the number of bytes to be copied out of the input array.
     * @param out    the space for any output that might be produced.
     * @param outOff the offset from which the output will be copied.
     * @return the number of output bytes copied to out.
     * @throws DataLengthException   if there isn't enough space in out.
     * @throws IllegalStateException if the cipher isn't initialised.
     */
    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out,
                            int outOff) throws DataLengthException {

      if (len < 0) {
        throw new IllegalArgumentException(
                "Can't have a negative input length!");
      }

      int length = getOutputSize(len);

      if (length > 0) {
        if ((((forEncryption && padding.equals(NOPADDING)) &&
                (outOff + length) > out.length) ||
                (!forEncryption && (outOff + length - blockSize) > out.length))) {
          throw new OutputLengthException("output buffer too short");
        }
      }

      int outConsumed = cipher.processBlock(in, inOff, len, out, outOff);

      if (cipher.getMode() == Constants.MODE_CBC)
        buffered = (buffered + len) % blockSize;
      return outConsumed;
    }

    @Override
    public int processBytes(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException {
      return bufferCrypt(input, output, true);
    }

    @Override
    public int doFinal(byte[] out, int outOff) throws IllegalStateException,
            InvalidCipherTextException {
      try {
        int length = getOutputSize(0);
        if (outOff + length > out.length) {
          throw new OutputLengthException(
                  "output buffer too short for doFinal()");
        }

        return cipher.doFinal(out, outOff);
      } catch (Exception e) {
        throw new RuntimeException(e);
      } finally {
        buffered = 0;
        reset();
      }
    }

    @Override
    public int doFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException {
      int result = 0;
      try {
        result = bufferCrypt(input, output, false);
      } catch (ShortBufferException e) {
        throw e;
      } finally {
        reset();
        buffered = 0;
      }
      return result;

    }

    private int bufferCrypt(ByteBuffer input, ByteBuffer output,
                            boolean isUpdate) throws ShortBufferException {
      if ((input == null) || (output == null)) {
        throw new NullPointerException(
                "Input and output buffers must not be null");
      }
      int inPos = input.position();
      int inLimit = input.limit();
      int inLen = inLimit - inPos;
      if (isUpdate && inLen == 0) {
        return 0;
      }

      // input + data unprocessed = 0
      int outLenNeeded = getOutputSize(inLen);
      if (!isUpdate && outLenNeeded == 0) {
        return 0;
      }

      if (!input.isDirect() || !output.isDirect()) {
        throw new IllegalArgumentException(
                "ByteBuffer of input and output must be direct");
      }

      if (output.remaining() < outLenNeeded) {
        throw new ShortBufferException("Need at least " + outLenNeeded
                + " bytes of space in output buffer");
      }

      // need native process
      int n = cipher.bufferCrypt(input, output, isUpdate);

      if (cipher.getMode() == Constants.MODE_CBC)
        buffered = (buffered + inLen) % blockSize;
      input.position(input.limit());
      output.position(output.position() + n);
      return n;
    }

    /**
     * Reset the buffer and cipher. After resetting the object is in the same
     * state as it was after the last init (if there was one).
     */
    public void reset() {
      cipher.reset();
    }

    public void setPadding(String padding) throws NoSuchPaddingException {
      String paddingName = padding.toUpperCase(Locale.ENGLISH);

      if (paddingName == null) {
        throw new NoSuchPaddingException("null padding");
      }
      if (paddingName.equalsIgnoreCase("NoPadding")) {
        padding = NOPADDING;
      } else if (!paddingName.equalsIgnoreCase("PKCS5Padding")) {
        throw new NoSuchPaddingException("Padding: " + paddingName
                + " not implemented");
      }
      if ((!padding.equals(NOPADDING)) && (cipher.getAlgorithmName().contains("CTR"))) {
        this.padding = NOPADDING;
        throw new NoSuchPaddingException(cipher.getAlgorithmName() +
                " mode must be used with NoPadding");
      }
      this.padding = paddingName;
      
      if (paddingName.equalsIgnoreCase("NoPadding")) {
      	cipher.setPadding(Constants.PADDING_NOPADDING);
      } else if (paddingName.equalsIgnoreCase("PKCS5Padding")) {
      	cipher.setPadding(Constants.PADDING_PKCS5PADDING);
      }
    }
  }
}
