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

	char * out = malloc(inputLength + 18 * sizeof(char));
	char * de = malloc(inputLength * sizeof(char));

	long context = 0;

	int enc_len = 0;
	int dec_len = 0;

	int j;
	int result = 0;
	for (j = 0; j < 1; j++) {
		context = init(1, key, 16, iv, 16, 1, context, &result);
		enc_len = bufferCrypt((CipherContext*) context, in, inputLength, out);
		context = init(0, key, 16, iv, 16, 1, context, &result);
		dec_len = bufferCrypt((CipherContext*) context, out, enc_len, de);

	}
	printf("enc_len: %d\n", enc_len);
	printf("dec_len: %d\n", dec_len);
	int i;
	printf("\noriginal:\t");
	for (i = 0; i < inputLength; i++)
		printf("%c", *(in + i));
	printf("\n\nencrypted:\t");
	for (i = 0; i < enc_len; i++)
		printf("%c ", *(out + i));
	printf("\n\ndecrypted:\t");
	for (i = 0; i < dec_len; i++)
		printf("%c", *(de + i));
	printf("\n");

	return 0;
}
