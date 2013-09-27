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

package com.intel.diceros.crypto;

/**
 * the foundation class for the hard exceptions thrown by the crypto packages.
 */
public class CryptoException extends Exception {
	private static final long serialVersionUID = -6961424805824709978L;
	private Throwable cause;

	public CryptoException() {
	}

	/**
	 * create a CryptoException with the given message.
	 * 
	 * @param message
	 *          the message to be carried with the exception.
	 */
	public CryptoException(String message) {
		super(message);
	}

	/**
	 * Create a CryptoException with the given message and underlying cause.
	 * 
	 * @param message
	 *          message describing exception.
	 * @param cause
	 *          the throwable that was the underlying cause.
	 */
	public CryptoException(String message, Throwable cause) {
		super(message);

		this.cause = cause;
	}

	public Throwable getCause() {
		return cause;
	}
}
