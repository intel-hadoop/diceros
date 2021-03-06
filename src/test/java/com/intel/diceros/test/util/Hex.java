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

package com.intel.diceros.test.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class Hex {
  private static final Encoder encoder = new HexEncoder();

  public static String toHexString(byte[] data) {
    return toHexString(data, 0, data.length);
  }

  public static String toHexString(
          byte[] data,
          int off,
          int length) {
    byte[] encoded = encode(data, off, length);
    return Strings.fromByteArray(encoded);
  }

  /**
   * encode the input data producing a Hex encoded byte array.
   *
   * @return a byte array containing the Hex encoded data.
   */
  public static byte[] encode(byte[] data) {
    return encode(data, 0, data.length);
  }

  /**
   * encode the input data producing a Hex encoded byte array.
   *
   * @return a byte array containing the Hex encoded data.
   */
  public static byte[] encode(
          byte[] data,
          int off,
          int length) {
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    try {
      encoder.encode(data, off, length, bOut);
    } catch (Exception e) {
      throw new EncoderException("exception encoding Hex string: " + e.getMessage(), e);
    }

    return bOut.toByteArray();
  }

  /**
   * Hex encode the byte data writing it to the given output stream.
   *
   * @return the number of bytes produced.
   */
  public static int encode(
          byte[] data,
          OutputStream out)
          throws IOException {
    return encoder.encode(data, 0, data.length, out);
  }

  /**
   * Hex encode the byte data writing it to the given output stream.
   *
   * @return the number of bytes produced.
   */
  public static int encode(
          byte[] data,
          int off,
          int length,
          OutputStream out)
          throws IOException {
    return encoder.encode(data, off, length, out);
  }

  /**
   * decode the Hex encoded input data. It is assumed the input data is valid.
   *
   * @return a byte array representing the decoded data.
   */
  public static byte[] decode(byte[] data) {
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    try {
      encoder.decode(data, 0, data.length, bOut);
    } catch (Exception e) {
      throw new DecoderException("exception decoding Hex data: " + e.getMessage(), e);
    }

    return bOut.toByteArray();
  }

  /**
   * decode the Hex encoded String data - whitespace will be ignored.
   *
   * @return a byte array representing the decoded data.
   */
  public static byte[] decode(String data) {
    ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    try {
      encoder.decode(data, bOut);
    } catch (Exception e) {
      throw new DecoderException("exception decoding Hex string: " + e.getMessage(), e);
    }

    return bOut.toByteArray();
  }

  /**
   * decode the Hex encoded String data writing it to the given output stream,
   * whitespace characters will be ignored.
   *
   * @return the number of bytes produced.
   */
  public static int decode(String data, OutputStream out) throws IOException {
    return encoder.decode(data, out);
  }
}
