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
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "aes_multibuffer.h"

static signed char key[] = { 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, };

static signed char iv[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, };

const char * in = "dicerosCipher@12dicerosCipher@12dicerosCipher@12"
    "dicerosCipher@12dicerosCipher@12dicerosCipher@12"
    "dicerosCipher@12dicerosCipher@12dicerosCipher@12";

int main() {

	int inputLength = 16 * 3 * 3;

	char * enc = malloc((inputLength + 18) * sizeof(char));
	char * dec = malloc((inputLength + 18) * sizeof(char));

	long context = 0;

	int enc_len = 0;
	int dec_len = 0;

	int i,j;
	int result = 0;
	for (j = 0; j < 1; j++) {
		context = init(1, key, 16, iv, 16, 1, context, &result);
		enc_len = bufferCrypt((CipherContext*) context, in, inputLength, enc);

		context = init(0, key, 16, iv, 16, 1, context, &result);
		dec_len = bufferCrypt((CipherContext*) context, enc, enc_len, dec);
	}
	cleanup(context);
	printf("enc_len: %d\n", enc_len);
	printf("dec_len: %d\n", dec_len);

	printf("\noriginal:\t");
	for (i = 0; i < inputLength; i++)
		printf("%c", *(in + i));
	printf("\n\nencrypted:\t");
	for (i = 0; i < enc_len; i++)
		printf("%x ", *(enc + i));
	printf("\n\ndecrypted:\t");
	for (i = 0; i < dec_len; i++)
		printf("%c", *(dec + i));

	printf("\n");
	printf("\n");
	printf("\n");

	free(enc);
	free(dec);

	return 0;
}
