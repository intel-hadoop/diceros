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

#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "com_intel_diceros.h"
#include "aes_common.h"
#include "com_intel_diceros_crypto_engines_AESOpensslEngine.h"



AESContext* preInitContext(JNIEnv *env, AESContext* aesCtx, jint mode, jbyteArray key, jbyteArray IV) {
	if (aesCtx != NULL) {
		if (aesCtx->context != NULL && mode == MODE_CBC) {
			EVP_CIPHER_CTX_cleanup(aesCtx->context);
			free(aesCtx->context);
			aesCtx->context = (EVP_CIPHER_CTX *) malloc(
					sizeof(EVP_CIPHER_CTX));
			EVP_CIPHER_CTX_init(aesCtx->context);
		}
	} else {
		aesCtx = (AESContext*)malloc(sizeof(AESContext));
		aesCtx->context = (EVP_CIPHER_CTX *) malloc(
				sizeof(EVP_CIPHER_CTX));
		EVP_CIPHER_CTX_init(aesCtx->context);
		aesCtx->nativeKey = NULL;
		aesCtx->keyLength = 0;
		aesCtx->nativeIv = NULL;
		aesCtx->ivLength = 0;
	}
	int keyLength = (*env)->GetArrayLength(env, key);
	if (aesCtx->nativeKey == NULL || aesCtx->keyLength != keyLength) {
		aesCtx->keyLength = keyLength;
		if (aesCtx->nativeKey != NULL) {
			free(aesCtx->nativeKey);
		}
		aesCtx->nativeKey = (jbyte*) malloc(aesCtx->keyLength);
	}
	int ivLength = (*env)->GetArrayLength(env, IV);
	if (aesCtx->nativeIv == NULL || aesCtx->ivLength != ivLength) {
		aesCtx->ivLength =  ivLength;
		if (aesCtx->nativeIv != NULL) {
			free(aesCtx->nativeIv);
		}
		aesCtx->nativeIv =  (jbyte*) malloc(aesCtx->ivLength);
	}
	return aesCtx;
}

JNIEXPORT jlong JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_initWorkingKey(
		JNIEnv *env, jobject object, jbyteArray key, jboolean forEncryption,
		jint mode, jint padding, jbyteArray IV, jlong aesContext) {
	AESContext* aesCtx = (AESContext*) aesContext;
	aesCtx = preInitContext(env, aesCtx, mode, key, IV);

	(*env)->GetByteArrayRegion(env, key, 0, aesCtx->keyLength, aesCtx->nativeKey);
	(*env)->GetByteArrayRegion(env, IV, 0, aesCtx->ivLength, aesCtx->nativeIv);

	cryptInit cryptInitFunc = getCryptInitFunc(forEncryption);

	if (mode == MODE_CTR) {
		if (aesCtx->keyLength == 32) {
			cryptInitFunc(aesCtx->context, EVP_aes_256_ctr(), NULL,
					(unsigned char *) aesCtx->nativeKey, (unsigned char *) aesCtx->nativeIv);
		} else {
			cryptInitFunc(aesCtx->context, EVP_aes_128_ctr(), NULL,
					(unsigned char *) aesCtx->nativeKey, (unsigned char *) aesCtx->nativeIv);
		}
	} else if (mode == MODE_CBC) {
		if (aesCtx->keyLength == 32) {
			cryptInitFunc(aesCtx->context, EVP_aes_256_cbc(), NULL,
					(unsigned char *) aesCtx->nativeKey, (unsigned char *) aesCtx->nativeIv);
		} else {
			cryptInitFunc(aesCtx->context, EVP_aes_128_cbc(), NULL,
					(unsigned char *) aesCtx->nativeKey, (unsigned char *) aesCtx->nativeIv);
		}
	}

	if (padding == PADDING_NOPADDING) {
		EVP_CIPHER_CTX_set_padding(aesCtx->context, 0);
	} else if (padding == PADDING_PKCS5PADDING) {
		EVP_CIPHER_CTX_set_padding(aesCtx->context, 1);
	}

	return (long) aesCtx;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_processBlock(
		JNIEnv *env, jobject object, jlong aesContext, jbyteArray in, jint inOff,
		jint inLen, jbyteArray out, jint outOff) {
	unsigned char * input = (unsigned char *) (*env)->GetByteArrayElements(env,
			in, 0);
	unsigned char * output = (unsigned char *) (*env)->GetByteArrayElements(env,
			out, 0);

	AESContext* aesCtx = (AESContext*) aesContext;
	EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) aesCtx->context;

	int outLength = 0;

	cryptUpdate cryptUpdateFunc = getCryptUpdateFunc(
			ctx->encrypt == ENCRYPTION);

	if (!cryptUpdateFunc(ctx, output + outOff, &outLength, input + inOff,
			inLen)) {
		THROW(env, "java/security/GeneralSecurityException",
				"Error in EVP_EncryptUpdate or EVP_DecryptUpdate");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	(*env)->ReleaseByteArrayElements(env, in, (jbyte *) input, 0);
	(*env)->ReleaseByteArrayElements(env, out, (jbyte *) output, 0);

	return outLength;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_doFinal(
		JNIEnv *env, jobject object, jlong aesContext, jbyteArray out, jint outOff) {
	unsigned char * output = (unsigned char *) (*env)->GetByteArrayElements(env,
			out, 0);

	AESContext* aesCtx = (AESContext*) aesContext;
	EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) aesCtx->context;
	cryptFinal cryptFinalFunc = getCryptFinalFunc(ctx->encrypt == ENCRYPTION);
	int outLength = 0;
	if (!cryptFinalFunc(ctx, (unsigned char *) output + outOff, &outLength)) {
		THROW(env, "javax/crypto/IllegalBlockSizeException",
				"Input length not multiple of 16 bytes");
		//THROW(env, "java/security/GeneralSecurityException",
		//          "Error in EVP_EncryptFinal_ex or EVP_DecryptFinal_ex");
		ERR_print_errors_fp(stderr);
		return 0;
	}
	(*env)->ReleaseByteArrayElements(env, out, (jbyte *) output, 0);
	return outLength;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_bufferCrypt(
		JNIEnv *env, jobject object, jlong aesContext, jobject input,
		jint inputPos, jint inputLimit, jobject output, jint outputPos,
		jboolean isUpdate) {
	jbyte* bInput = (*env)->GetDirectBufferAddress(env, input);
	jbyte* bOutput = (*env)->GetDirectBufferAddress(env, output);

	if (NULL == bInput || NULL == bOutput) {
		return 0;
	}
	//EVP_CIPHER_CTX_set_padding(context, 0);
	AESContext* aesCtx = (AESContext*) aesContext;
	EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) aesCtx->context;

	cryptUpdate cryptUpdateFunc = getCryptUpdateFunc(
			ctx->encrypt == ENCRYPTION);
	cryptFinal cryptFinalFunc = getCryptFinalFunc(ctx->encrypt == ENCRYPTION);

	int outLenUpdate = 0;
	int outLengthFinal = 0;
	int inputLength = inputLimit - inputPos;

	if (!cryptUpdateFunc(ctx, (unsigned char *) bOutput + outputPos,
			&outLenUpdate, (const unsigned char *) bInput + inputPos,
			inputLength)) {
		THROW(env, "java/security/GeneralSecurityException",
				"Error in EVP_EncryptUpdate or EVP_DecryptUpdate");
		ERR_print_errors_fp(stderr);
		return 0;
	}
	if (isUpdate == JNI_FALSE) {
		if (!cryptFinalFunc(ctx,
				(unsigned char *) bOutput + outputPos + outLenUpdate,
				&outLengthFinal)) {
			//THROW(env, "javax/crypto/IllegalBlockSizeException",
			//               "Input length not multiple of 16 bytes...");
			THROW(env, "java/security/GeneralSecurityException",
					"Error in EVP_EncryptFinal_ex or EVP_DecryptFinal_ex");
			ERR_print_errors_fp(stderr);
			return 0;
		}
	}
	return outLenUpdate + outLengthFinal;
}
