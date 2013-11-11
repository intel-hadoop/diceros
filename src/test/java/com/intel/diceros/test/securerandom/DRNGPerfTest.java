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

package com.intel.diceros.test.securerandom;

import com.intel.diceros.provider.DicerosProvider;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * This class does the performance test of SecureRandom based on DRNG(Intel®
 * Digital Random Number Generator).
 */
public class DRNGPerfTest {
  public static class Task implements Runnable {
    private static int BUFFER_SIZE = 512;
    private long[] stat_array = null;
    private int index = -1;
    private String provider = null;

    public Task(long[] stat_array, String provider, int index) {
      this.stat_array = stat_array;
      this.provider = provider;
      this.index = index;
    }

    @Override
    public void run() {
      byte[] randOut = new byte[BUFFER_SIZE];
      int randTimes = 0;
      SecureRandom random = null;
      if (this.provider.equalsIgnoreCase("DC")) {
        try {
          random = SecureRandom.getInstance("DRNG", "DC");
        } catch (NoSuchAlgorithmException e) {
          // TODO Auto-generated catch block
          e.printStackTrace();
        } catch (NoSuchProviderException e) {
          // TODO Auto-generated catch block
          e.printStackTrace();
        }
      } else {
        random = new SecureRandom();
      }

      while (true && !Thread.currentThread().isInterrupted()) {
        random.nextBytes(randOut);
        randTimes++;
      }
      long genBytes = randTimes * BUFFER_SIZE;
      stat_array[index] = genBytes;
    }
  }

  /**
   * Perform the performance test of SecureRandom. First use SecureRandom from
   * the jdk or jre, then use SecureRandom from provider DC.
   *
   * @param args the thread number, default thread number is 1
   * @throws NoSuchAlgorithmException
   * @throws NoSuchProviderException
   */
  public static void main(String[] args) throws NoSuchAlgorithmException,
          NoSuchProviderException {
    int threadNum = args.length > 0 ? Integer.parseInt(args[0]) : 1;
    Security.addProvider(new DicerosProvider());

    System.out.println("default securerandom");
    speedTestDRNG(threadNum, "SunJCE");

    System.out.println("drng securerandom");
    speedTestDRNG(threadNum, "DC");
  }

  /**
   * Perform the performance test of SecureRandom.
   *
   * @param threadNum the number of threads which perform the generation of random data
   * @param provider  the provider name
   */
  private static void speedTestDRNG(int threadNum, String provider) {
    ThreadGroup tg = new ThreadGroup("group");
    long[] stat_array = new long[threadNum];
    for (int tn = 0; tn < threadNum; tn++) {
      Thread t1 = new Thread(tg, new Task(stat_array, provider, tn));
      t1.start();
    }

    try {
      Thread.sleep(10 * 1000);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    tg.interrupt();
    try {
      Thread.sleep(1 * 1000);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }

    long totalBytes = 0;
    for (int tn = 0; tn < threadNum; tn++) {
      totalBytes += stat_array[tn];
    }
    double mbbytespers = totalBytes / 10.0 / 1024.0 / 1024.0;
    System.out.println("thread num: " + threadNum + " " + mbbytespers + "MB/s");
  }
}
