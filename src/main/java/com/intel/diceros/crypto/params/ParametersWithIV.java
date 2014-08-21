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

package com.intel.diceros.crypto.params;

/**
 * Parameter class containing initialization vector and wrap other
 * CipherParameters.
 */
public class ParametersWithIV implements CipherParameters {
  private byte[] iv;
  private CipherParameters parameters;

  public ParametersWithIV(CipherParameters parameters, byte[] iv) {
    if (iv != null) {
      this.iv = new byte[iv.length];
      this.parameters = parameters;

      System.arraycopy(iv, 0, this.iv, 0, iv.length);
    } else {
      this.parameters = parameters;
      this.iv = null;
    }
  }

  public ParametersWithIV(CipherParameters parameters, byte[] iv, int ivOff,
                          int ivLen) {
    this.iv = new byte[ivLen];
    this.parameters = parameters;

    System.arraycopy(iv, ivOff, this.iv, 0, ivLen);
  }

  public byte[] getIV() {
    return iv;
  }

  public void setIV(byte[] iv) {
    this.iv = iv;
  }

  public CipherParameters getParameters() {
    return parameters;
  }
}
