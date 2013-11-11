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

package com.intel.diceros.provider;

import com.intel.diceros.provider.config.ConfigurableProvider;
import com.intel.diceros.provider.util.AlgorithmProvider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * The "DC" Cryptographic Service Provider.
 * <p/>
 * <p>Defines the "DC" provider.
 * <p>Supported algorithms and their names:
 * <p>- AES (CTR mode)
 * <p>- SecureRandom (DRNG)
 */
public final class DicerosProvider extends Provider implements
        ConfigurableProvider {

  public static final String PROVIDER_NAME = "DC"; // DICEROS

  private static final long serialVersionUID = -5933716767994628685L;

  private static String info = "Diceros Provider v1.0, implementing AES encryption of CTR mode and SecureRandom based on DRNG";
  private static final String SYMMETRIC_PACKAGE = "com.intel.diceros.provider.symmetric.";
  private static final String[] SYMMETRIC_CIPHERS = {"AES"};
  private static final String SECURERANDOM_PACKAGE = "com.intel.diceros.provider.securerandom.";
  private static final String[] SECURERANDOM = {"SecureRandom"};

  public DicerosProvider() {
    super(PROVIDER_NAME, 1.0, info);

    AccessController.doPrivileged(new PrivilegedAction<Object>() {
      public Object run() {
        setup();
        return null;
      }
    });
  }

  /**
   * Load all algorithms implemented by this provider to the JCE Framework.
   */
  private void setup() {
    loadAlgorithms(SYMMETRIC_PACKAGE, SYMMETRIC_CIPHERS);
    loadAlgorithms(SECURERANDOM_PACKAGE, SECURERANDOM);
  }

  private void loadAlgorithms(String packageName, String[] names) {
    for (int i = 0; i != names.length; i++) {
      Class<?> clazz = null;
      try {
        ClassLoader loader = this.getClass().getClassLoader();

        if (loader != null) {
          clazz = loader.loadClass(packageName + names[i] + "$Mappings");
        } else {
          clazz = Class.forName(packageName + names[i] + "$Mappings");
        }
      } catch (ClassNotFoundException e) {
        // ignore
      }

      if (clazz != null) {
        try {
          ((AlgorithmProvider) clazz.newInstance()).configure(this);
        } catch (Exception e) { // this should never ever happen!!
          throw new InternalError("cannot create instance of " + packageName
                  + names[i] + "$Mappings : " + e);
        }
      }
    }
  }

  @Override
  public void addAlgorithm(String key, String value) {
    if (containsKey(key)) {
      throw new IllegalStateException("duplicate provider key (" + key
              + ") found");
    }

    put(key, value);
  }

  @Override
  public boolean hasAlgorithm(String type, String name) {
    return containsKey(type + "." + name)
            || containsKey("Alg.Alias." + type + "." + name);
  }
}
