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

/*
 * The Known Answer Test for AES algorithm validation suite
 * GFSbox 
 * KeySbox 
 * Variable Key 
 * Variable Text 
 * 
 */
package com.intel.diceros.test.aes;

import com.intel.diceros.test.util.Hex;

public class KatSuite {
  private static final byte[] EMPTY = new byte[0];
  private byte[] key = EMPTY;
  private byte[] iv = EMPTY;
  private byte[] plainText = EMPTY;
  private byte[] cipherText = EMPTY;
  private boolean encrypt = true;

  public byte[] getKey() {
    return key;
  }

  public void setKey(byte[] key) {
    this.key = key;
  }

  public byte[] getIv() {
    return iv;
  }

  public void setIv(byte[] iv) {
    this.iv = iv;
  }

  public byte[] getPlainText() {
    return plainText;
  }

  public void setPlainText(byte[] plainText) {
    this.plainText = plainText;
  }

  public byte[] getCipherText() {
    return cipherText;
  }

  public void setCipherText(byte[] cipherText) {
    this.cipherText = cipherText;
  }

  public boolean isEncrypt() {
    return encrypt;
  }

  public void setEncrypt(boolean encrypt) {
    this.encrypt = encrypt;
  }

  @Override
  public String toString() {
    return "[key = " + Hex.toHexString(key) + " , iv = " + Hex.toHexString(iv)
        + ", plainText = " + Hex.toHexString(plainText) + ", cipherText = "
        + Hex.toHexString(cipherText) + " ]";
  }

  public enum KATTYPE {
    GFSBOX("GFSbox"),
    KEYSBOX("keySbox"),
    VARKEY("Variable Key"),
    VARTEXT("Variable Text"),

    TWEAK("tweak");
    //DATAUNITSEQNUMBER("DataUnitSeqNumber");

    private String name;

    private KATTYPE(String name) {
      this.name = name;
    }

    public String getName() {
      return name;
    }
  }
}
