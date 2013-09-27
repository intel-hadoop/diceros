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

public class SimpleTestResult implements TestResult {

	private static final String SEPARATOR = System.getProperty("line.separator");

    private boolean             success;
    private String              message;
    private Throwable           exception;

    public SimpleTestResult(boolean success, String message)
    {
        this.success = success;
        this.message = message;
    }

    public SimpleTestResult(boolean success, String message, Throwable exception)
    {
        this.success = success;
        this.message = message;
        this.exception = exception;
    }

    public static TestResult successful(
        Test test, 
        String message)
    {
        return new SimpleTestResult(true, test.getName() + ": " + message);
    }

    public static TestResult failed(
        Test test, 
        String message)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message);
    }
    
    public static TestResult failed(
        Test test, 
        String message, 
        Throwable t)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message, t);
    }
    
    public static TestResult failed(
        Test test, 
        String message, 
        Object expected, 
        Object found)
    {
        return failed(test, message + SEPARATOR + "Expected: " + expected + SEPARATOR + "Found   : " + found);
    }
    
    public static String failedMessage(String algorithm, String testName, String expected,
            String actual)
    {
        StringBuffer sb = new StringBuffer(algorithm);
        sb.append(" failing ").append(testName);
        sb.append(SEPARATOR).append("    expected: ").append(expected);
        sb.append(SEPARATOR).append("    got     : ").append(actual);

        return sb.toString();
    }

    public boolean isSuccessful()
    {
        return success;
    }

    public String toString()
    {
        return message;
    }

    public Throwable getException()
    {
        return exception;
    }
}
