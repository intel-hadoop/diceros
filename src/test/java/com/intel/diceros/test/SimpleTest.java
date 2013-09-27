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

package com.intel.diceros.test;

import java.io.PrintStream;

import junit.framework.TestCase;


public abstract class SimpleTest extends TestCase implements Test{
	protected void fail(String message, Throwable throwable) {
		throw new TestFailedException(SimpleTestResult.failed(this, message,
				throwable));
	}

	protected void fail(String message, Object expected, Object found) {
		throw new TestFailedException(SimpleTestResult.failed(this, message,
				expected, found));
	}
	
	private TestResult success() {
		return SimpleTestResult.successful(this, "Okay");
	}

	public TestResult perform() {
		try {
			performTest();

			return success();
		} catch (TestFailedException e) {
			return e.getResult();
		} catch (Exception e) {
			return SimpleTestResult.failed(this, "Exception: " + e, e);
		}
	}

	protected static void runTest(Test test) {
		runTest(test, System.out);
	}

	protected static void runTest(Test test, PrintStream out) {
		TestResult result = test.perform();

		if (result.getException() != null) {
			result.getException().printStackTrace();
			fail(result.getException().getMessage());
		}
	}
	
	public abstract String getName();
	
	public abstract void performTest()
	        throws Exception;
}
