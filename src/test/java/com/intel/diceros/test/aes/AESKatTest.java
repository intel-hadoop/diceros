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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.AssertionFailedError;

import com.intel.diceros.provider.util.Arrays;
import com.intel.diceros.test.BaseBlockCipherTest;
import com.intel.diceros.test.aes.KatSuite.KATTYPE;
import com.intel.diceros.test.util.Hex;

/*
 * This junit class test the Known Answer Test for AES CBC mode 
 * The response file for 128,256 key length testing with AES CBC Mode
 * There are four types of Known Answer Test: 
   GFSbox 
   KeySbox 
   Variable Key 
   Variable Text 
 
 * The REQUEST file for each of these KAT tests contains a series of data sets consisting of 
 * a key, an initialization vector (IV) (for all modes except ECB), and a plaintext for 
 * encryption (or a ciphertext for decryption). The following is a sample data set: 
 
   KEY = 00000000000000000000000000000000 
   IV = 00000000000000000000000000000000 
   PLAINTEXT = 6a84867cd77e12ad07ea1be895c53fa3 
 
 * The RESPONSE file for the KAT tests contains the same data as the REQUEST file with 
 * the addition of the ciphertext for encryption (or plaintext for decryption).  The following 
 * is a sample data set: 
 
   KEY = 00000000000000000000000000000000 
   IV = 00000000000000000000000000000000 
   PLAINTEXT = 6a84867cd77e12ad07ea1be895c53fa3 
   CIPHERTEXT = 732281c0a0aab8f7a54a0c67a0c45ecf  
   The testing resources contain the values for each of the four types of Known Answer Test. 
 * 
 */

public class AESKatTest extends BaseBlockCipherTest{
  private static int INPUT_BUFFER_SIZE = 1024;
  private static String[] CBC_GFSBOX_RSP = { "CBCGFSbox128.rsp" ,"CBCGFSbox256.rsp"};
  private static String[] CBC_KEYSBOX_RSP = { "CBCKeySbox128.rsp" , "CBCKeySbox256.rsp"};
  private static String[] CBC_VARKEY_RSP = { "CBCVarKey128.rsp" , "CBCVarKey256.rsp"};
  private static String[] CBC_VARTEXT_RSP = { "CBCVarTxt128.rsp" , "CBCVarTxt256.rsp"};
  private static Map<String, String[]> CBC_KAT_SUITE = new HashMap<String, String[]>();
  static {
    CBC_KAT_SUITE.put(KATTYPE.GFSBOX.getName(), CBC_GFSBOX_RSP);
    CBC_KAT_SUITE.put(KATTYPE.KEYSBOX.getName(), CBC_KEYSBOX_RSP);
    CBC_KAT_SUITE.put(KATTYPE.VARKEY.getName(), CBC_VARKEY_RSP);
    CBC_KAT_SUITE.put(KATTYPE.VARTEXT.getName(), CBC_VARTEXT_RSP);
  }
  /*
   * 
   */
  private static Map<String, Map<String, String[]>> ALL_KAT_SUITE = 
      new HashMap<String, Map<String, String[]>>();
  static {
    ALL_KAT_SUITE.put("AES/CBC/NoPadding", CBC_KAT_SUITE);
  }
  public static final String RESOURCES_PREFIX = "/rsp/";
  
  private Cipher cipher;
  private byte[] result = new byte[INPUT_BUFFER_SIZE];
  
  public AESKatTest() {
    super("AES");
  }

  public void performTest() throws Exception {
    for (String cipherName : ALL_KAT_SUITE.keySet()) {
      cipher = Cipher.getInstance(cipherName, "DC");
      for (KATTYPE type : KATTYPE.values()) {
        for (KatSuite suite : loadKatSuites(cipherName, type)) {
          if (suite.isEncrypt()) {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(suite.getKey(),
                "AES"), new IvParameterSpec(suite.getIv()));
            cipher.doFinal(suite.getPlainText(), 0,
                suite.getPlainText().length, result, 0);
            byte[] tmp = new byte[suite.getCipherText().length];
            System.arraycopy(result, 0, tmp, 0, suite.getCipherText().length);
            if (!Arrays.areEqual(suite.getCipherText(), tmp)) {
              throw new AssertionFailedError("AES failed encryption, KatSuite="
                  + suite);
            }
          } else {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(suite.getKey(),
                "AES"), new IvParameterSpec(suite.getIv()));
            cipher.doFinal(suite.getCipherText(), 0,
                suite.getCipherText().length, result, 0);
            byte[] tmp = new byte[suite.getPlainText().length];
            System.arraycopy(result, 0, tmp, 0, suite.getPlainText().length);
            if (!Arrays.areEqual(suite.getPlainText(), tmp)) {
              throw new AssertionFailedError("AES failed decryption, KatSuite="
                  + suite);
            }
          }
        }
      }
    }
  }
  
  private List<KatSuite> loadKatSuites(String mode, KATTYPE type)
      throws Exception {
    Map<String, String[]> modeSuite = ALL_KAT_SUITE.get(mode);
    String[] rsps = modeSuite.get(type.getName());
    return parseSuites(rsps);
  }
  
  private List<KatSuite> parseSuites(String[] filenames) throws Exception {
    List<KatSuite> suites = new ArrayList<KatSuite>();
    try {
      for (Reader r : getReaders(filenames)) {
        BufferedReader reader = null;
        try {
          reader = new BufferedReader(r);
          boolean encryptSuite = true;
          KatSuite suite = null;
          String line = null;
          while ((line = reader.readLine()) != null ) {
            if (line.trim().isEmpty()) {
              continue;
            }
            if (line.contains("[DECRYPT]")) {
              encryptSuite = false;
              continue;
            }
            if (line.contains("SUITE")) {
              if (suite != null) {
                suites.add(suite);
              }
              suite = new KatSuite();
              if (encryptSuite) {
                suite.setEncrypt(true);
              } else {
                suite.setEncrypt(false);
              }
              continue;
            }
            List<String> tokens = tokenize(line, "=", true, true);
            if (tokens.size() != 2) {
              continue;
            }
            String name = tokens.get(0);
            String data = tokens.get(1);
            if (name.equalsIgnoreCase("KEY")) {
              suite.setKey(Hex.decode(data));
            } else if (name.equalsIgnoreCase("IV")) {
              suite.setIv(Hex.decode(data));
            } else if (name.equalsIgnoreCase("PLAINTEXT")) {
              suite.setPlainText(Hex.decode(data));
            } else if (name.equalsIgnoreCase("CIPHERTEXT")) {
              suite.setCipherText(Hex.decode(data));
            } else {
            }
          }
        } finally {
          if (reader != null) {
            try {
              reader.close();
            } catch (IOException e) {
              // ignore
            }
          }
        }
      }

    } catch (IOException ex) {
      throw new RuntimeException("Error reading suites list", ex);
    }

    return suites;
  }
  
  private List<Reader> getReaders(String[] filenames) {
    String resource = RESOURCES_PREFIX.startsWith("/") ? RESOURCES_PREFIX
        .substring(1) : RESOURCES_PREFIX;
    Enumeration<URL> urls;
    List<Reader> readers = new ArrayList<Reader>();
    for (String filename : filenames) {
      try {
        urls = getClass().getClassLoader().getResources(resource + filename);
      } catch (IOException e) {
        throw new RuntimeException("IOException while obtaining resource: "
            + resource + filename, e);
      }
      if (urls != null) {
        URL url = null;
        try {
          while (urls.hasMoreElements()) {
            url = urls.nextElement();
            InputStream stream = url.openStream();
            readers.add(new InputStreamReader(stream));
          }
        } catch (IOException e) {
          for (Reader r : readers) {
            try {
              r.close();
            } catch (IOException e1) {
              // ignore
            }
          }
          throw new RuntimeException("IOException while opening resource: "
              + url, e);
        }
      } else {
        throw new RuntimeException("Unable to find the resource: " + resource
            + filename);
      }
    }
    return readers;
  }
  
  private List<String> tokenize(String string, String delimiters,
      boolean trimTokens, boolean ignoreEmptyTokens) {
    if (string == null) {
      return Collections.emptyList();
    }
    StringTokenizer st = new StringTokenizer(string, delimiters);
    List<String> tokens = new ArrayList<String>();
    while (st.hasMoreTokens()) {
      String token = st.nextToken();
      if (trimTokens) {
        token = token.trim();
      }
      if (!ignoreEmptyTokens || token.length() > 0) {
        tokens.add(token);
      }
    }
    return tokens;
  }
  
  public void testAESKat() {
    runTest(new AESKatTest());
  }
  public static void main(String[] args) throws Exception{
    new AESKatTest().testAESKat();
  }
  

}
