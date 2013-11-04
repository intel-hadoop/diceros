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
#include "com_intel_diceros_crypto_engines_AESOpensslEngine.h"

#define ENCRYPTION 1
#define DECRYPTION 0

#define THROW(env, exception_name, message) \
  { \
     jclass ecls = (*env)->FindClass(env, exception_name); \
     if (ecls) { \
       (*env)->ThrowNew(env, ecls, message); \
       (*env)->DeleteLocalRef(env, ecls); \
     } \
  }

typedef int (*cryptInit)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
          const unsigned char *, const unsigned char *);
typedef int (*cryptUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *,
          const unsigned char *, int);
typedef int (*cryptFinal)(EVP_CIPHER_CTX*, unsigned char *, int *);

cryptInit getCryptInitFunc(jboolean forEncryption) {
     if (forEncryption == JNI_TRUE) {
          return EVP_EncryptInit_ex;
     } else {
          return EVP_DecryptInit_ex;
     }
}

cryptUpdate getCryptUpdateFunc(jboolean forEncryption) {
     if (forEncryption == JNI_TRUE) {
          return EVP_EncryptUpdate;
     } else {
          return EVP_DecryptUpdate;
     }
}

cryptFinal getCryptFinalFunc(jboolean forEncryption) {
     if (forEncryption == JNI_TRUE) {
          return EVP_EncryptFinal_ex;
     } else {
          return EVP_DecryptFinal_ex;
     }
}

JNIEXPORT jlong JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_initWorkingKey(
          JNIEnv *env, jobject object, jbyteArray key, jboolean forEncryption,
          jstring mode, jstring padding, jbyteArray IV, jlong oldContext) {
     EVP_CIPHER_CTX * context =  (EVP_CIPHER_CTX *) oldContext;
     if (context != NULL) {
        EVP_CIPHER_CTX_cleanup(context);
        free(context);
     }
      context = (EVP_CIPHER_CTX *) malloc(
                             sizeof(EVP_CIPHER_CTX));

     int keyLength = (*env)->GetArrayLength(env, key);
     int ivLength = (*env)->GetArrayLength(env, IV);
     jbyte * nativeKey = (jbyte*) malloc(keyLength);
     jbyte * nativeIv = (jbyte*) malloc(ivLength);

     (*env)->GetByteArrayRegion(env, key, 0, keyLength, nativeKey);
     (*env)->GetByteArrayRegion(env, IV, 0, ivLength, nativeIv);
     EVP_CIPHER_CTX_init(context);

     const char* cstr_mode = (*env)->GetStringUTFChars(env, mode, 0);
     const char* cstr_padding = (*env)->GetStringUTFChars(env, padding, 0);

     int ctrModeResult = strncmp(cstr_mode, "CTR", 3);
     int cbcModeResult = strncmp(cstr_mode, "CBC", 3);

     int noPadding = strncmp(cstr_padding,"NOPADDING",9);
     int pkcs5Padding = strncmp(cstr_padding,"PKCS5PADDING",12);

     (*env)->ReleaseStringUTFChars(env, mode, cstr_mode);
     (*env)->ReleaseStringUTFChars(env, padding, cstr_padding);

     cryptInit cryptInitFunc = getCryptInitFunc(forEncryption);

     if (ctrModeResult == 0) {
          if (keyLength == 32) {
               cryptInitFunc(context, EVP_aes_256_ctr(), NULL,
                         (unsigned char *) nativeKey, (unsigned char *) nativeIv);
          } else {
               cryptInitFunc(context, EVP_aes_128_ctr(), NULL,
                         (unsigned char *) nativeKey, (unsigned char *) nativeIv);
          }
     } else if (cbcModeResult == 0) {
        if (keyLength == 32) {
            cryptInitFunc(context, EVP_aes_256_cbc(), NULL,
                    (unsigned char *) nativeKey, (unsigned char *) nativeIv);
        } else {
            cryptInitFunc(context, EVP_aes_128_cbc(), NULL,
                    (unsigned char *) nativeKey, (unsigned char *) nativeIv);
        }
    }

    if (pkcs5Padding == 0) {
        EVP_CIPHER_CTX_set_padding(context, 1);
    } else {
        EVP_CIPHER_CTX_set_padding(context, 0);
    }

     free(nativeKey);
     free(nativeIv);
     return (long) context;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_processBlock(
          JNIEnv *env, jobject object, jlong context, jbyteArray in, jint inOff,
          jint inLen, jbyteArray out, jint outOff) {
     unsigned char * input = (unsigned char *) (*env)->GetByteArrayElements(env,
               in, 0);
     unsigned char * output = (unsigned char *) (*env)->GetByteArrayElements(env,
               out, 0);

     EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) context;

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

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_getBlockSize(
          JNIEnv *env, jobject object, jlong context) {
     EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) context;
     return EVP_CIPHER_CTX_block_size(ctx);
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_doFinal(
          JNIEnv *env, jobject object, jlong context, jbyteArray out, jint outOff) {
     unsigned char * output = (unsigned char *) (*env)->GetByteArrayElements(env,
               out, 0);

     EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) context;
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
          JNIEnv *env, jobject object, jlong context, jobject input,
          jint inputPos, jint inputLimit, jobject output, jint outputPos,
          jboolean isUpdate) {
     jbyte* bInput = (*env)->GetDirectBufferAddress(env, input);
     jbyte* bOutput = (*env)->GetDirectBufferAddress(env, output);

     if (NULL == bInput || NULL == bOutput) {
          return 0;
     }
     EVP_CIPHER_CTX_set_padding(context, 0);
     EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) context;

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
