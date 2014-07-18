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
import com.intel.diceros.provider.util.Arrays;
import com.intel.diceros.test.BaseBlockCipherTest;
import org.apache.commons.math3.complex.Complex;
import org.apache.commons.math3.special.Erf;
import org.apache.commons.math3.special.Gamma;
import org.apache.commons.math3.transform.DftNormalization;
import org.apache.commons.math3.transform.FastFourierTransformer;
import org.apache.commons.math3.transform.TransformType;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Statistical test suite for DRNG(Intel® Digital Random Number Generator).
 * The test suite is based on
 * <a herf="http://csrc.nist.gov/publications/nistpubs/800-22-rev1a/SP800-22rev1a.pdf">NIST SP800-22rev1a</a>
 */
public class DRNGTest extends BaseBlockCipherTest {

    public DRNGTest() {
        super("DRNG");
    }

    public void testDRNG() {
        Security.addProvider(new DicerosProvider());
        runTest(new DRNGTest());
    }

    private int[] bytes2Ints(byte[] bs) {
        int[] rs = new int[bs.length * 8];
        for (int i = 0; i < bs.length; i++) {
            byte b = bs[i];
            for (int j = 0; j < 8; j++) {
                if (((b >> j) & 1) > 0) {
                    rs[i * 8 + 7 - j] = 1;
                } else {
                    rs[i * 8 + 7 - j] = 0;
                }
            }
        }
        return rs;
    }

    @Override
    public void performTest() throws Exception {
        SecureRandom random = SecureRandom.getInstance("DRNG", "DC");
        random.nextDouble();
        byte[] bytes = new byte[65536];
        random.nextBytes(bytes);

        final int[] epsilon = bytes2Ints(bytes);
        testFrequency(epsilon);
        testBlockFrequency(epsilon, 10);
        testRuns(epsilon);
        testLongestRunOfOnes(epsilon);
        testRank(epsilon);
        testDiscreteFourierTransform(epsilon);
        testNonOverlappingTemplateMatching(epsilon, 4);
        testOverlappingTemplateMatchings(epsilon, 9);
        testUniversal(epsilon);
        testLinearComplexity(epsilon, 1000);
        testSerial(epsilon, 2);
        testApproximateEntropy(epsilon, 2);
        testCumulativeSums(epsilon);
        testRandomExcursions(epsilon);
        testRandomExcursionsVariant(epsilon);
    }

    /**
     * Frequency(Monobit) Test
     * <p/>
     * The focus of the test is the proportion of zeros and ones for
     * the entire sequence. The purpose of this test is to determine
     * whether the number of ones and zeros in a sequence are approximately
     * the same as would be expected for a truly random sequence.
     */
    private void testFrequency(final int[] epsilon) {
        final int n = epsilon.length;

        double sum = 0.0;
        for (int i = 0; i < n; i++) {
            sum += 2 * epsilon[i] - 1;
        }
        double s_obs = Math.abs(sum) / Math.sqrt(n);
        double f = s_obs / Math.sqrt(2);
        double p_value = Erf.erfc(f);

        assertTrue("RNG test failed, test frequency.", p_value >= 0.01);
    }

    /**
     * Frequency Test with a Block
     * <p>
     * The focus of the test is the proportion of ones within M-bit
     * blocks. The purpose of this test is to determine whether the
     * frequency of ones in an M-bit block is approximately block_size/2,
     * as would be expected under an assumption of randomness. For block
     * size = 1, this test degenerates to test 1, frequency test for RNG.
     */
    private void testBlockFrequency(final int[] epsilon, final int M) {
        final int n = epsilon.length;
        final int N = n / M;

        double sum = 0.0;

        for (int i = 0; i < N; i++) {
            int blockSum = 0;
            for (int j = 0; j < M; j++) {
                blockSum += epsilon[j + i * M];
            }
            double pi = (double) blockSum / (double) M;
            double v = pi - 0.5;
            sum += v * v;
        }
        double chi_squared = 4.0 * M * sum;
        double p_value = Gamma.regularizedGammaQ(N / 2, chi_squared / 2);

        assertTrue("RNG test failed, test block frequency.", p_value >= 0.01);
    }

    /**
     * Run Test
     * <p>
     * The focus of the test is the total number of runs in the sequence,
     * where a run is an uninterrupted sequence of identical bits. A run
     * of length k consists of exactly k identical bits and is bounded
     * before and after with a bit of the opposite value. The purpose of
     * the runs test is to determined whether the number of runs of ones
     * and zeros of various lengths is as expected for a random sequence.
     * In particular, this test determines whether the oscillation between
     * such zeros and ones is too fast or too slow.
     */
    private void testRuns(final int[] epsilon) {
        final int n = epsilon.length;

        int s = 0;
        for (int k = 0; k < n; k++)
            if (epsilon[k] == 0)
                ++s;
        double pi = (double) s / (double) n;

        double p_value;
        if (Math.abs(pi - 0.5) > (2.0 / Math.sqrt(n))) {
            p_value = 0.0;
        } else {
            double v = 1;
            for (int k = 1; k < n; k++)
                if (epsilon[k] != epsilon[k - 1])
                    ++v;
            double erfc_arg = Math.abs(v - 2.0 * n * pi * (1 - pi))
                    / (2.0 * pi * (1 - pi) * Math.sqrt(2 * n));
            p_value = Erf.erfc(erfc_arg);
        }
        assertTrue("RNG test failed, test runs.", p_value >= 0.01);
    }

    /**
     * Test for the Longest Run of Ones in a Block
     * <p>
     * The focus of the test is the longest run of ones within M-bit blocks.
     * The purpose of this test is to determine whether the length of the
     * longest run of ones within the tested sequence is consistent with the
     * length of the longest run of ones that would be expected in a random
     * sequence. Note that an irregularity in the exported length of the
     * longest run of ones implies that there is also an irregularity in the
     * expected length of the longest run of zeros. Therefor, ony a test for
     * ones is necessary.
     */
    private void testLongestRunOfOnes(final int[] epsilon) {
        final int n = epsilon.length;

        int k, m, v_n_obs, run;
        int[] v = new int[7];
        int[] nu = {0, 0, 0, 0, 0, 0, 0};
        double[] pi = new double[7];

        if (n < 128) return;

        if (n < 6272) {
            k = 3;
            m = 8;
            v[0] = 1;
            v[1] = 2;
            v[2] = 3;
            v[3] = 4;
            pi[0] = 0.21484375;
            pi[1] = 0.3671875;
            pi[2] = 0.23046875;
            pi[3] = 0.1875;
        } else if (n < 750000) {
            k = 5;
            m = 128;
            v[0] = 4;
            v[1] = 5;
            v[2] = 6;
            v[3] = 7;
            v[4] = 8;
            v[5] = 9;
            pi[0] = 0.1174035788;
            pi[1] = 0.242955959;
            pi[2] = 0.249363483;
            pi[3] = 0.17517706;
            pi[4] = 0.102701071;
            pi[5] = 0.112398847;
        } else {
            k = 6;
            m = 10000;
            v[0] = 10;
            v[1] = 11;
            v[2] = 12;
            v[3] = 13;
            v[4] = 14;
            v[5] = 15;
            v[6] = 16;
            pi[0] = 0.0882;
            pi[1] = 0.2092;
            pi[2] = 0.2483;
            pi[3] = 0.1933;
            pi[4] = 0.1208;
            pi[5] = 0.0675;
            pi[6] = 0.0727;
        }

        int N = n / m;
        for (int i = 0; i < N; i++) {
            v_n_obs = 0;
            run = 0;
            for (int j = 0; j < m; j++) {
                if (epsilon[i * m + j] == 1) {
                    if (++run > v_n_obs)
                        v_n_obs = run;
                } else
                    run = 0;
            }
            if (v_n_obs < v[0])
                nu[0]++;
            for (int j = 0; j <= k; j++) {
                if (v_n_obs == v[j])
                    nu[j]++;
            }
            if (v_n_obs > v[k])
                nu[k]++;
        }

        double chi2 = 0.0;
        for (int i = 0; i < k; i++)
            chi2 += ((nu[i] - N * pi[i]) * (nu[i] - N * pi[i])) / (N * pi[i]);

        double p_value = Gamma.regularizedGammaQ(k / 2.0, chi2 / 2.0);
        assertTrue("RNG test failed, test longest run of ones.", p_value >= 0.01);
    }

    private void defMatrix(int M, int Q, int[][] m, int k, int[] epsilon) {
        for (int i = 0; i < M; i++) {
            for (int j = 0; j < Q; j++) {
                m[i][j] = epsilon[k * M * Q + j + i * M];
            }
        }
    }

    private static final int MATRIX_FORWARD_ELIMINATION = 0;
    private static final int MATRIX_BACKWARD_ELIMINATION = 1;

    private int computeRank(int M, int Q, int[][] matrix) {
        int m = Math.min(M, Q);

        /* FORWARD APPLICATION OF ELEMENTARY ROW OPERATIONS */
        for (int i = 0; i < m - 1; i++) {
            if (matrix[i][i] == 1) {
                performElementaryRowOperations(MATRIX_FORWARD_ELIMINATION, i, M, Q, matrix);
            } else {
                if (findUnitElementAndSwap(MATRIX_FORWARD_ELIMINATION, i, M, Q, matrix) == 1) {
                    performElementaryRowOperations(MATRIX_FORWARD_ELIMINATION, i, M, Q, matrix);
                }
            }
        }

        /* BACKWARD APPLICATION OF ELEMENTARY ROW OPERATIONS */
        for (int i = m - 1; i > 0; i--) {
            if (matrix[i][i] == 1)
                performElementaryRowOperations(MATRIX_BACKWARD_ELIMINATION, i, M, Q, matrix);
            else {
                if (findUnitElementAndSwap(MATRIX_BACKWARD_ELIMINATION, i, M, Q, matrix) == 1)
                    performElementaryRowOperations(MATRIX_BACKWARD_ELIMINATION, i, M, Q, matrix);
            }
        }
        return determineRank(m, M, Q, matrix);
    }

    private void performElementaryRowOperations(int flag, int i, int M, int Q, int[][] matrix) {
        if (MATRIX_FORWARD_ELIMINATION == flag) {
            for (int j = i + 1; j < M; j++) {
                if (matrix[j][i] == 1)
                    for (int k = i; k < Q; k++)
                        matrix[j][k] = (matrix[j][k] + matrix[i][k]) % 2;
            }
        } else {
            for (int j = i - 1; j >= 0; j--) {
                if (matrix[j][i] == 1) {
                    for (int k = 0; k < Q; k++)
                        matrix[j][k] = (matrix[j][k] + matrix[i][k]) % 2;
                }
            }
        }
    }

    private int swapRows(int i, int index, int Q, int[][] matrix) {
        for (int p = 0; p < Q; p++) {
            int temp = matrix[i][p];
            matrix[i][p] = matrix[index][p];
            matrix[index][p] = temp;
        }
        return 1;
    }

    private int findUnitElementAndSwap(int flag, int i, int M, int Q, int[][] matrix) {
        int index, row_op = 0;

        if (MATRIX_FORWARD_ELIMINATION == flag) {
            index = i + 1;
            while (index < M && matrix[index][i] == 0)
                ++index;
            if (index < M)
                row_op = swapRows(i, index, Q, matrix);
        } else {
            index = i - 1;
            while (index >= 0 && matrix[index][i] == 0)
                --index;
            if (index >= 0)
                row_op = swapRows(i, index, Q, matrix);
        }
        return row_op;
    }

    private int determineRank(int m, int M, int Q, int[][] matrix) {
        int rank = m, allZeroes;
        for (int i = 0; i < M; i++) {
            allZeroes = 1;
            for (int j = 0; j < Q; j++) {
                if (matrix[i][j] == 1) {
                    allZeroes = 0;
                    break;
                }
            }
            if (allZeroes == 1) --rank;
        }
        return rank;
    }

    /**
     * Binary Matrix Rank Test
     * <p>
     * The focus of the test is the rank of disjoint sub-matrices of the
     * entire sequence. The purpose of this test is to check for linear
     * dependence among fixed length substrings of the original sequence.
     */
    private void testRank(final int[] epsilon) {
        int N, i, k, r, n = epsilon.length;
        double p_value, product, chi_squared, arg1, p_32, p_31, p_30, R, F_32, F_31, F_30;
        int[][] matrix = new int[32][32];

        N = n / (32 * 32);
        if (N == 0) {
            p_value = 0.0;
        } else {
            r = 32;
            product = 1;
            for (i = 0; i <= r - 1; i++)
                product *= ((1.e0 - Math.pow(2, i - 32)) * (1.e0 - Math.pow(2, i - 32))) / (1.e0 - Math.pow(2, i - r));
            p_32 = Math.pow(2, r * (32 + 32 - r) - 32 * 32) * product;

            r = 31;
            product = 1;
            for (i = 0; i <= r - 1; i++)
                product *= ((1.e0 - Math.pow(2, i - 32)) * (1.e0 - Math.pow(2, i - 32))) / (1.e0 - Math.pow(2, i - r));
            p_31 = Math.pow(2, r * (32 + 32 - r) - 32 * 32) * product;

            p_30 = 1 - (p_32 + p_31);

            F_32 = 0;
            F_31 = 0;
            for (k = 0; k < N; k++) {			/* FOR EACH 32x32 MATRIX   */
                defMatrix(32, 32, matrix, k, epsilon);
                R = computeRank(32, 32, matrix);
                if (R == 32)
                    F_32++;			/* DETERMINE FREQUENCIES */
                if (R == 31)
                    F_31++;
            }
            F_30 = (double) N - (F_32 + F_31);

            System.out.println(F_32);
            System.out.println(F_31);
            System.out.println(F_30);

            chi_squared = (
                    Math.pow(F_32 - N * p_32, 2) / (N * p_32) +
                            Math.pow(F_31 - N * p_31, 2) / (N * p_31) +
                            Math.pow(F_30 - N * p_30, 2) / (N * p_30)
            );
            arg1 = -chi_squared / 2.e0;
            p_value = Math.exp(arg1);
        }
        System.out.println(p_value);
        assertTrue("RNG test failed, test rank.", p_value >= 0.01);
    }

    /**
     * Discrete Fourier Transform (Spectral) Test
     * <p>
     * The focus of this test is the peak heights in the Discrete Fourier
     * Transform of the sequence. The purpose of this test is to detect
     * periodic features (i.e., repetitive patterns that are near each other)
     * in the tested sequence that would indicate a deviation from the
     * assumption of randomness. The intention is to detect whether the number
     * of peaks exceeding the 95% threshold is significantly different than 5%.
     */
    private void testDiscreteFourierTransform(final int[] epsilon) {
        final int n = epsilon.length;

        double p_value, upperBound, N_l, N_o, d;
        double[] m = new double[n / 2 + 1], X = new double[n];
        int i, count;

        for (i = 0; i < n; i++)
            X[i] = 2 * epsilon[i] - 1;

        double[] X1 = new double[n];
        for (i = 0; i < X.length; i++) {
            X1[i] = X[i];
        }

        FastFourierTransformer fft = new FastFourierTransformer(DftNormalization.STANDARD);
        Complex[] Xc = fft.transform(X, TransformType.FORWARD);
        m[0] = Math.sqrt((Xc[0].multiply(Xc[0])).getReal());

        for (i = 0; i < n / 2; i++)
            m[i + 1] = Math.sqrt(
                    Math.pow(Xc[2 * i].getReal(), 2)
                            + Math.pow(Xc[2 * i + 1].getReal(), 2));
        count = 0;
        upperBound = Math.sqrt(2.995732274 * n);
        for (i = 0; i < n / 2; i++)
            if (m[i] < upperBound) count++;
        N_l = (double) count;
        N_o = 0.95 * n / 2.0;
        d = (N_l - N_o) / Math.sqrt(n / 4.0 * 0.95 * 0.05);
        p_value = Erf.erfc(Math.abs(d) / Math.sqrt(2.0));

        assertTrue("RNG test failed, test discrete fourier transform.", p_value >= 0.01);
    }

    private static final String RESOURCES_PREFIX = "templates/";

    private List<Reader> getReaders(String... filenames) {
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

    /**
     * Test Non-overlapping Template Matching Test
     * <p>
     * The focus of this test is the number of occurrences of pre-specified target
     * strings. The purpose of this test is to detect generators that produce too
     * many occurrences of a given non-periodic (aperiodic) pattern. For this test
     * an m-bit window is used to search for a specific m-bit pattern. If the
     * pattern is not found, the window slides one bit position. If the pattern is
     * found, the window is reset to the bit after the found pattern, and the search
     * resumes.
     */
    private void testNonOverlappingTemplateMatching(final int[] epsilon, final int m)
            throws IOException {

        int[] numOfTemplates = {
                0, 0, 2, 4, 6, 12, 20, 40, 74, 148, 284, 568,
                1116, 2232, 4424, 8848, 17622, 35244, 70340,
                140680, 281076, 562152
        };
        final int maxNumOfTemplates = numOfTemplates.length;
        numOfTemplates = Arrays.copyOf(numOfTemplates, 100);

        int i, j, jj, k, match, skip, M, N, K = 5, n = epsilon.length;
        N = 8;
        M = n / N;
        int w_obs;
        int[] nu = new int[6], wj = new int[N], sequence = new int[m];
        double sum, chi2, p_value, lambda, varWj;
        double[] pi = new double[6];

        lambda = (M - m + 1) / Math.pow(2, m);
        assertTrue("Lambda not being positive!", lambda > 0);

        varWj = M * (1.0 / Math.pow(2.0, m) - (2.0 * m - 1.0) / Math.pow(2.0, 2.0 * m));

        if (numOfTemplates[m] < maxNumOfTemplates)
            skip = 1;
        else
            skip = numOfTemplates[m] / maxNumOfTemplates;
        numOfTemplates[m] /= skip;

        sum = 0.0;
        for (i = 0; i < 2; i++) {
            pi[i] = Math.exp(-lambda + i * Math.log(lambda) - Gamma.logGamma(i + 1));
            sum += pi[i];
        }
        pi[0] = sum;
        for (i = 2; i < K; i++) {
            pi[i - 1] = Math.exp(-lambda + i * Math.log(lambda) - Gamma.logGamma(i + 1));
            sum += pi[i - 1];
        }
        pi[K] = 1 - sum;

        final String templateName = "template" + m;
        Reader reader = null;
        try {
            reader = getReaders(templateName).get(0);
            for (jj = 0; jj < Math.min(maxNumOfTemplates, numOfTemplates[m]); jj++) {
                sum = 0;
                for (k = 0; k < m; k++) {
                    int b = reader.read();
                    if (b == -1) assertTrue("Template issue.", false);
                    sequence[k] = b - 48;
                }
                for (k = 0; k <= K; k++)
                    nu[k] = 0;
                for (i = 0; i < N; i++) {
                    w_obs = 0;
                    for (j = 0; j < M - m + 1; j++) {
                        match = 1;
                        for (k = 0; k < m; k++) {
                            if (sequence[k] != epsilon[i * M + j + k]) {
                                match = 0;
                                break;
                            }
                        }
                        if (match == 1)
                            w_obs++;
                    }
                    wj[i] = w_obs;
                }
//            sum = 0;
                chi2 = 0.0;                                   /* Compute Chi Square */
                for (i = 0; i < N; i++) {
                    chi2 += Math.pow(((double) wj[i] - lambda) / Math.pow(varWj, 0.5), 2);
                }
                p_value = Gamma.regularizedGammaQ(N / 2.0, chi2 / 2.0);
                assertTrue("RNG test failed, test non-overlapping template matching.", p_value >= 0.01);
                if (skip > 1)
                    for (i = 0; i < (skip - 1) * 2 * m; i++)
                        reader.read();
            }
        } finally {
            if (reader != null)
                reader.close();
        }
    }

    private double pr(int u, double eta) {
        int l;
        double sum, p;

        if (u == 0)
            p = Math.exp(-eta);
        else {
            sum = 0.0;
            for (l = 1; l <= u; l++)
                sum += Math.exp(-eta - u * Math.log(2)
                        + l * Math.log(eta) - Gamma.logGamma(l + 1)
                        + Gamma.logGamma(u) - Gamma.logGamma(l)
                        - Gamma.logGamma(u - l + 1));
            p = sum;
        }
        return p;
    }

    /**
     * Overlapping Template Matching Test
     * <p>
     * The focus of the Overlapping Template Matching test is the number of
     * occurrences of pre-specified target strings. Both this test uses an
     * m-bit window to search for a specific m-bit pattern. If the pattern
     * is not found, the window slides one bit position.
     */
    private void testOverlappingTemplateMatchings(final int[] epsilon, final int m) {
        int i, k, match;
        double w_obs, eta, sum, chi2, p_value, lambda;
        int M, N, j, K = 5;
        int[] nu = {0, 0, 0, 0, 0, 0}, sequence = new int[m];
        double[] pi = {0.143783, 0.139430, 0.137319, 0.124314, 0.106209, 0.348945};
        final int n = epsilon.length;
        M = 1032;
        N = n / M;

        for (i = 0; i < m; i++)
            sequence[i] = 1;

        lambda = (double) (M - m + 1) / Math.pow(2, m);
        eta = lambda / 2.0;
        sum = 0.0;
        for (i = 0; i < K; i++) {			/* Compute Probabilities */
            pi[i] = pr(i, eta);
            sum += pi[i];
        }
        pi[K] = 1 - sum;

        for (i = 0; i < N; i++) {
            w_obs = 0;
            for (j = 0; j < M - m + 1; j++) {
                match = 1;
                for (k = 0; k < m; k++) {
                    if (sequence[k] != epsilon[i * M + j + k])
                        match = 0;
                }
                if (match == 1)
                    w_obs++;
            }
            if (w_obs <= 4)
                nu[(int) w_obs]++;
            else
                nu[K]++;
        }
        sum = 0;
        chi2 = 0.0;                                   /* Compute Chi Square */
        for (i = 0; i < K + 1; i++) {
            chi2 += Math.pow((double) nu[i] - (double) N * pi[i], 2) / ((double) N * pi[i]);
            sum += nu[i];
        }
        p_value = Gamma.regularizedGammaQ(K / 2.0, chi2 / 2.0);
        assertTrue("RNG test failed, test overlapping template matching.", p_value >= 0.01);
    }

    /**
     * Maurer's "Universal Statistical" Test
     * <p>
     * The focus of this test is the number of bits between matching patterns
     * (a measure that is related to the length of a compressed sequence). The
     * purpose of the test is to detect whether or not the sequence can be
     * significantly compressed without loss of information. A significantly
     * compressible sequence is considered to be non-random.
     */
    private void testUniversal(final int[] epsilon) {
        int i, j, p, L, Q, K, n = epsilon.length;
        double arg, sqrt2, sigma, phi, sum, p_value, c;
        int decRep;
        long[] T;
        double[] expected_value = {
                0, 0, 0, 0, 0, 0, 5.2177052, 6.1962507,
                7.1836656, 8.1764248, 9.1723243, 10.170032,
                11.168765, 12.168070, 13.167693, 14.167488,
                15.167379
        };
        double[] variance = {
                0, 0, 0, 0, 0, 0, 2.954, 3.125, 3.238, 3.311,
                3.356, 3.384, 3.401, 3.410, 3.416, 3.419, 3.421
        };

        L = 5;
        if (n >= 387840) L = 6;
        if (n >= 904960) L = 7;
        if (n >= 2068480) L = 8;
        if (n >= 4654080) L = 9;
        if (n >= 10342400) L = 10;
        if (n >= 22753280) L = 11;
        if (n >= 49643520) L = 12;
        if (n >= 107560960) L = 13;
        if (n >= 231669760) L = 14;
        if (n >= 496435200) L = 15;
        if (n >= 1059061760) L = 16;

        Q = 10 * (int) Math.pow(2, L);
        K = (int) (Math.floor(n / L) - (double) Q);	 		    /* BLOCKS TO TEST */

        p = (int) Math.pow(2, L);
        T = new long[p];
        assertTrue("L is out of range.", L >= 6 && L <= 16);
        assertTrue("Q is less than " + (10 * Math.pow(2, L)), ((double) Q >= 10 * Math.pow(2, L)));

        c = 0.7 - 0.8 / (double) L + (4 + 32 / (double) L) * Math.pow(K, -3 / (double) L) / 15;
        sigma = c * Math.sqrt(variance[L] / (double) K);
        sqrt2 = Math.sqrt(2);
        sum = 0.0;
        for (i = 0; i < p; i++)
            T[i] = 0;
        for (i = 1; i <= Q; i++) {		/* INITIALIZE TABLE */
            decRep = 0;
            for (j = 0; j < L; j++)
                decRep += epsilon[(i - 1) * L + j] * (long) Math.pow(2, L - 1 - j);
            T[decRep] = i;
        }
        for (i = Q + 1; i <= Q + K; i++) { 	/* PROCESS BLOCKS */
            decRep = 0;
            for (j = 0; j < L; j++)
                decRep += epsilon[(i - 1) * L + j] * (long) Math.pow(2, L - 1 - j);
            sum += Math.log(i - T[decRep]) / Math.log(2);
            T[decRep] = i;
        }
        phi = sum / (double) K;

        arg = Math.abs(phi - expected_value[L]) / (sqrt2 * sigma);
        p_value = Erf.erfc(arg);

        assertTrue("RNG test failed, test universal.", p_value >= 0.01);
    }

    /**
     * Linear Complexity Test
     * <p>
     * The focus of this test is the length of a linear feedback
     * shift register (LFSR). The purpose of this test is to determine
     * whether or not the sequence is complex enough to be considered
     * random. Random sequences are characterized by longer LFSRs. An
     * LFSR that is too short implies non-randomness.
     */
    private void testLinearComplexity(final int[] epsilon, int M) {
        int i, ii, j, d, N, L, m, N_, parity, sign, K = 6, n = epsilon.length;
        double p_value, T_, mean, chi2;
        double[] pi = {0.01047, 0.03125, 0.12500, 0.50000, 0.25000, 0.06250, 0.020833}, nu = new double[7];
        int[] T = new int[M], P = new int[M], B_ = new int[M], C = new int[M];

        N = (int) Math.floor(n / M);
        for (i = 0; i < K + 1; i++)
            nu[i] = 0.00;
        for (ii = 0; ii < N; ii++) {
            for (i = 0; i < M; i++) {
                B_[i] = 0;
                C[i] = 0;
                T[i] = 0;
                P[i] = 0;
            }
            L = 0;
            m = -1;
            d = 0;
            C[0] = 1;
            B_[0] = 1;

		    /* DETERMINE LINEAR COMPLEXITY */
            N_ = 0;
            while (N_ < M) {
                d = epsilon[ii * M + N_];
                for (i = 1; i <= L; i++)
                    d += C[i] * epsilon[ii * M + N_ - i];
                d = d % 2;
                if (d == 1) {
                    for (i = 0; i < M; i++) {
                        T[i] = C[i];
                        P[i] = 0;
                    }
                    for (j = 0; j < M; j++)
                        if (B_[j] == 1)
                            P[j + N_ - m] = 1;
                    for (i = 0; i < M; i++)
                        C[i] = (C[i] + P[i]) % 2;
                    if (L <= N_ / 2) {
                        L = N_ + 1 - L;
                        m = N_;
                        for (i = 0; i < M; i++)
                            B_[i] = T[i];
                    }
                }
                N_++;
            }
            if ((parity = (M + 1) % 2) == 0)
                sign = -1;
            else
                sign = 1;
            mean = M / 2.0 + (9.0 + sign) / 36.0 - 1.0 / Math.pow(2, M) * (M / 3.0 + 2.0 / 9.0);
            if ((parity = M % 2) == 0)
                sign = 1;
            else
                sign = -1;
            T_ = sign * (L - mean) + 2.0 / 9.0;

            if (T_ <= -2.5)
                nu[0]++;
            else if (T_ > -2.5 && T_ <= -1.5)
                nu[1]++;
            else if (T_ > -1.5 && T_ <= -0.5)
                nu[2]++;
            else if (T_ > -0.5 && T_ <= 0.5)
                nu[3]++;
            else if (T_ > 0.5 && T_ <= 1.5)
                nu[4]++;
            else if (T_ > 1.5 && T_ <= 2.5)
                nu[5]++;
            else
                nu[6]++;
        }
        chi2 = 0.00;
        for (i = 0; i < K + 1; i++)
            chi2 += Math.pow(nu[i] - N * pi[i], 2) / (N * pi[i]);
        p_value = Gamma.regularizedGammaQ(K / 2.0, chi2 / 2.0);

        assertTrue("RNG test failed, test linear complexity.", p_value >= 0.01);
    }

    private double psi2(final int[] epsilon, int m) {
        int i, j, k, powLen, n = epsilon.length;
        double sum, numOfBlocks;
        int[] P;

        if ((m == 0) || (m == -1))
            return 0.0;
        numOfBlocks = n;
        powLen = (int) Math.pow(2, m + 1) - 1;
        P = new int[powLen];
        for (i = 1; i < powLen - 1; i++)
            P[i] = 0;	  /* INITIALIZE NODES */
        for (i = 0; i < numOfBlocks; i++) {		 /* COMPUTE FREQUENCY */
            k = 1;
            for (j = 0; j < m; j++) {
                if (epsilon[(i + j) % n] == 0)
                    k *= 2;
                else if (epsilon[(i + j) % n] == 1)
                    k = 2 * k + 1;
            }
            P[k - 1]++;
        }
        sum = 0.0;
        for (i = (int) Math.pow(2, m) - 1; i < (int) Math.pow(2, m + 1) - 1; i++)
            sum += Math.pow(P[i], 2);
        sum = (sum * Math.pow(2, m) / (double) n) - (double) n;

        return sum;
    }

    /**
     * Serial Test
     * <p>
     * The focus of this test is the frequency of all possible overlapping m-bit
     * patterns across the entire sequence. The purpose of this test is to determine
     * whether the number of occurrences of the 2mm-bit overlapping patterns is
     * approximately the same as would be expected for a random sequence. Random
     * sequences have uniformity; that is, every m-bit pattern has the same chance
     * of appearing as every other m-bit pattern. Note that for m = 1, the Serial
     * test is equivalent to the Frequency test of Section 2.1.
     */
    private void testSerial(final int[] epsilon, int m) {
        double p_value1, p_value2, psim0, psim1, psim2, del1, del2;
        psim0 = psi2(epsilon, m);
        psim1 = psi2(epsilon, m - 1);
        psim2 = psi2(epsilon, m - 2);
        del1 = psim0 - psim1;
        del2 = psim0 - 2.0 * psim1 + psim2;
        p_value1 = Gamma.regularizedGammaQ(Math.pow(2, m - 1) / 2, del1 / 2.0);
        p_value2 = Gamma.regularizedGammaQ(Math.pow(2, m - 2) / 2, del2 / 2.0);

        assertTrue("RNG test failed(p_value1), test linear complexity.", p_value1 >= 0.01);
        assertTrue("RNG test failed(p_value2), test linear complexity.", p_value2 >= 0.01);
    }

    /**
     * Approximate Entropy Test
     * <p>
     * As with the Serial test of Section 2.11, the focus of this test is the frequency
     * of all possible overlapping m-bit patterns across the entire sequence.
     * The purpose of the test is to compare the frequency of overlapping blocks of
     * two consecutive/adjacent lengths (m and m+1) against the expected result for
     * a random sequence.
     */
    private void testApproximateEntropy(final int[] epsilon, int m) {
        final int n = epsilon.length;
        int i, j, k, r, blockSize, seqLength, powLen, index;
        double sum, numOfBlocks, apen, chi_squared, p_value;
        double[] ApEn = new double[2];
        int[] P;

        seqLength = n;
        r = 0;
        for (blockSize = m; blockSize <= m + 1; blockSize++) {
            if (blockSize == 0) {
                ApEn[0] = 0.00;
                r++;
            } else {
                numOfBlocks = (double) seqLength;
                powLen = (int) Math.pow(2, blockSize + 1) - 1;
                P = new int[powLen];
                for (i = 1; i < powLen - 1; i++)
                    P[i] = 0;
                for (i = 0; i < numOfBlocks; i++) { /* COMPUTE FREQUENCY */
                    k = 1;
                    for (j = 0; j < blockSize; j++) {
                        k <<= 1;
                        if ((int) epsilon[(i + j) % seqLength] == 1)
                            k++;
                    }
                    P[k - 1]++;
                }
                /* DISPLAY FREQUENCY */
                sum = 0.0;
                index = (int) Math.pow(2, blockSize) - 1;
                for (i = 0; i < (int) Math.pow(2, blockSize); i++) {
                    if (P[index] > 0)
                        sum += P[index] * Math.log(P[index] / numOfBlocks);
                    index++;
                }
                sum /= numOfBlocks;
                ApEn[r] = sum;
                r++;
            }
        }
        apen = ApEn[0] - ApEn[1];

        chi_squared = 2.0 * seqLength * (Math.log(2) - apen);
        p_value = Gamma.regularizedGammaQ(Math.pow(2, m - 1), chi_squared / 2.0);

        assertTrue("RNG test failed, test approximate entropy.", p_value >= 0.01);
    }

    private double normal(double x) {
        double arg, result, sqrt2 = 1.414213562373095048801688724209698078569672;
        if (x > 0) {
            arg = x / sqrt2;
            result = 0.5 * (1 + Erf.erf(arg));
        } else {
            arg = -x / sqrt2;
            result = 0.5 * (1 - Erf.erf(arg));
        }
        return result;
    }

    /**
     * Cumulative Sums (Cusum) Test
     * <p>
     * The focus of this test is the maximal excursion (from zero) of the random
     * walk defined by the cumulative sum of adjusted (-1, +1) digits in the
     * sequence. The purpose of the test is to determine whether the cumulative
     * sum of the partial sequences occurring in the tested sequence is too large
     * or too small relative to the expected behavior of that cumulative sum for
     * random sequences. This cumulative sum may be considered as a random walk.
     * For a random sequence, the excursions of the random walk should be near
     * zero. For certain types of non-random sequences, the excursions of this
     * random walk from zero will be large.
     */
    public void testCumulativeSums(final int[] epsilon) {
        final int n = epsilon.length;
        int S = 0, sup = 0, inf = 0, k, z = 0, zrev = 0;
        double sum1, sum2, p_value;
        for (k = 0; k < n; k++) {
            S = S + 2 * epsilon[k] - 1;
            if (S > sup)
                sup++;
            if (S < inf)
                inf--;
            z = (sup > -inf) ? sup : -inf;
            zrev = (sup - S > S - inf) ? sup - S : S - inf;
        }

        // forward
        sum1 = 0.0;
        for (k = (-n / z + 1) / 4; k <= (n / z - 1) / 4; k++) {
            sum1 += normal(((4 * k + 1) * z) / Math.sqrt(n));
            sum1 -= normal(((4 * k - 1) * z) / Math.sqrt(n));
        }
        sum2 = 0.0;
        for (k = (-n / z - 3) / 4; k <= (n / z - 1) / 4; k++) {
            sum2 += normal(((4 * k + 3) * z) / Math.sqrt(n));
            sum2 -= normal(((4 * k + 1) * z) / Math.sqrt(n));
        }
        p_value = 1.0 - sum1 + sum2;
        assertTrue("RNG test failed, test cumulative sums.", p_value >= 0.01);

        //backward
        sum1 = 0.0;
        for (k = (-n / zrev + 1) / 4; k <= (n / zrev - 1) / 4; k++) {
            sum1 += normal(((4 * k + 1) * zrev) / Math.sqrt(n));
            sum1 -= normal(((4 * k - 1) * zrev) / Math.sqrt(n));
        }
        sum2 = 0.0;
        for (k = (-n / zrev - 3) / 4; k <= (n / zrev - 1) / 4; k++) {
            sum2 += normal(((4 * k + 3) * zrev) / Math.sqrt(n));
            sum2 -= normal(((4 * k + 1) * zrev) / Math.sqrt(n));
        }
        p_value = 1.0 - sum1 + sum2;
        assertTrue("RNG test failed, test cumulative sums.", p_value >= 0.01);
    }

    /**
     * Random Excursions Test
     * <p>
     * The focus of this test is the number of cycles having exactly K visits
     * in a cumulative sum random walk. The cumulative sum random walk is
     * derived from partial sums after the (0,1) sequence is transferred to
     * the appropriate (-1, +1) sequence. A cycle of a random walk consists
     * of a sequence of steps of unit length taken at random that begin at
     * and return to the origin. The purpose of this test is to determine if
     * the number of visits to a particular state within a cycle deviates
     * from what one would expect for a random sequence. This test is actually
     * a series of eight tests (and conclusions), one test and conclusion
     * for each of the states: -4, -3, -2, -1 and +1, +2, +3, +4.
     */
    public void testRandomExcursions(final int[] epsilon) {
        final int n = epsilon.length;
        int[] stateX = {-4, -3, -2, -1, 1, 2, 3, 4};
        int[] S_k = new int[n];
        int cycleMaxLength = Math.max(1000, n / 100);
        int[] cycle = new int[cycleMaxLength];
        int J = 0, i;
        S_k[0] = 2 * epsilon[0] - 1;
        for (i = 1; i < n; i++) {
            S_k[i] = S_k[i - 1] + 2 * epsilon[i] - 1;
            if (0 == S_k[i]) {
                J++;
                assertTrue("Exceeding the max number of cycles expected.", J <= cycleMaxLength);
                cycle[J] = i;
            }
        }
        if (0 != S_k[n - 1]) {
            J++;
            cycle[J] = n;
        }
        //int constraint = (int) Math.max(0.005 * Math.pow(n, 0.5), 500);
        int cycleStart = 0, cycleStop = cycle[1], j, k, b;
        double[][] nu = new double[6][8];
        int[] counter = {0, 0, 0, 0, 0, 0, 0, 0};
        double pi[][] = {
                {0.0000000000, 0.00000000000, 0.00000000000, 0.00000000000, 0.00000000000, 0.0000000000},
                {0.5000000000, 0.25000000000, 0.12500000000, 0.06250000000, 0.03125000000, 0.0312500000},
                {0.7500000000, 0.06250000000, 0.04687500000, 0.03515625000, 0.02636718750, 0.0791015625},
                {0.8333333333, 0.02777777778, 0.02314814815, 0.01929012346, 0.01607510288, 0.0803755143},
                {0.8750000000, 0.01562500000, 0.01367187500, 0.01196289063, 0.01046752930, 0.0732727051}
        };
        for (k = 0; k < 6; k++) {
            for (i = 0; i < 8; i++) {
                nu[k][i] = 0;
            }
        }
        for (j = 1; j <= J; j++) {
            for (i = 0; i < 8; i++) {
                counter[i] = 0;
            }
            for (i = cycleStart; i < cycleStop; i++) {
                if ((S_k[i] >= 1 && S_k[i] <= 4) || (S_k[i] >= -4 && S_k[i] <= -1)) {
                    if (S_k[i] < 0)
                        b = 4;
                    else
                        b = 3;
                    counter[S_k[i] + b]++;
                }
            }
            cycleStart = cycle[j] + 1;
            if (j < J)
                cycleStop = cycle[j + 1];

            for (i = 0; i < 8; i++) {
                if ((counter[i] >= 0) && (counter[i] <= 4))
                    nu[counter[i]][i]++;
                else if (counter[i] >= 5)
                    nu[5][i]++;
            }
        }
        int x;
        double sum, p_value;
        for (i = 0; i < 8; i++) {
            x = stateX[i];
            sum = 0.;
            for (k = 0; k < 6; k++)
                sum += Math.pow(nu[k][i] - J * pi[(int) Math.abs(x)][k], 2) / (J * pi[(int) Math.abs(x)][k]);
            p_value = Gamma.regularizedGammaQ(2.5, sum / 2.0);
            assertTrue("RNG test failed, test random excursions.", p_value >= 0.01);
        }
    }

    /**
     * Random Excursions Variant Test
     * <p>
     * The focus of this test is the total number of times that a particular
     * state is visited (i.e., occurs) in a cumulative sum random walk. The
     * purpose of this test is to detect deviations from the expected number
     * of visits to various states in the random walk. This test is actually
     * a series of eighteen tests (and conclusions), one test and conclusion
     * for each of the states: -9, -8, …, -1 and +1, +2, …, +9.
     */
    public void testRandomExcursionsVariant(final int[] epsilon) {
        final int n = epsilon.length;
        int[] stateX = {-9, -8, -7, -6, -5, -4, -3, -2, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        int[] S_k = new int[n];
        int J = 0, i;
        S_k[0] = 2 * epsilon[0] - 1;
        for (i = 1; i < n; i++) {
            S_k[i] = S_k[i - 1] + 2 * epsilon[i] - 1;
            if (0 == S_k[i]) {
                J++;
            }
        }
        if (0 != S_k[n - 1]) {
            J++;
        }
//        int constraint = (int) Math.max(0.005 * Math.pow(n, 0.5), 500);
        int p, x, count;
        double p_value;
        for (p = 0; p < 18; p++) {
            x = stateX[p];
            count = 0;
            for (i = 0; i < n; i++) {
                if (S_k[i] == x) {
                    count++;
                }
            }
            p_value = Erf.erfc(Math.abs(count - J) / (Math.sqrt(2.0 * J * (4.0 * Math.abs(x) - 2))));
            assertTrue("RNG test failed, test random excursions variant.", p_value >= 0.01);
        }
    }

}
