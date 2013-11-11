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

package com.intel.diceros.provider.config;

/**
 * Provider class should implement this class.
 */
public interface ConfigurableProvider {

  /**
   * Add the <code>key</code> property with the specified <code>value</code> to
   * the JCE Provider Framework.
   *
   * @param key   the property key
   * @param value the property value
   */
  void addAlgorithm(String key, String value);

  /**
   * Check whether the <code>type.name</code> property has been added.
   *
   * @param type the algorithm type, such Cipher, SecureRandom, Signature, etc
   * @param name the algorithm name
   * @return whether the <code>type.name</code> property has been added
   */
  boolean hasAlgorithm(String type, String name);
}
