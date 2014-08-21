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
#include "aes_utils.h"
#include "com_intel_diceros_crypto_engines_AESOpensslEngine.h"

CipherContext* preInitContext(JNIEnv *env, CipherContext* cipherCtx, jint mode,
    jbyteArray key, jbyteArray IV) {
  if (cipherCtx != NULL) {
    if (cipherCtx->opensslCtx != NULL && mode == MODE_CBC) {
      EVP_CIPHER_CTX_cleanup(cipherCtx->opensslCtx);
      free(cipherCtx->opensslCtx);
      cipherCtx->opensslCtx = (EVP_CIPHER_CTX *) malloc(
          sizeof(EVP_CIPHER_CTX));
      EVP_CIPHER_CTX_init(cipherCtx->opensslCtx);
    }
  } else {
    cipherCtx = (CipherContext*)malloc(sizeof(CipherContext));
    cipherCtx->opensslCtx = (EVP_CIPHER_CTX *) malloc(
        sizeof(EVP_CIPHER_CTX));
    EVP_CIPHER_CTX_init(cipherCtx->opensslCtx);
    cipherCtx->key = NULL;
    cipherCtx->keyLength = 0;
    cipherCtx->iv = NULL;
    cipherCtx->ivLength = 0;
    cipherCtx->aesmbCtx = NULL;
  }
  int keyLength = (*env)->GetArrayLength(env, key);
  if (cipherCtx->key == NULL || cipherCtx->keyLength != keyLength) {
    cipherCtx->keyLength = keyLength;
    if (cipherCtx->key != NULL) {
      free(cipherCtx->key);
    }
    cipherCtx->key = (jbyte*) malloc(cipherCtx->keyLength);
  }
  int ivLength = (*env)->GetArrayLength(env, IV);
  if (cipherCtx->iv == NULL || cipherCtx->ivLength != ivLength) {
    cipherCtx->ivLength =  ivLength;
    if (cipherCtx->iv != NULL) {
      free(cipherCtx->iv);
    }
    cipherCtx->iv = (jbyte*) malloc(cipherCtx->ivLength);
  }
  return cipherCtx;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_destoryCipherContext(
    JNIEnv *env, jobject object, jlong cipherContext) {
  CipherContext* cipherCtx = (CipherContext*) cipherContext;
  destroyCipherContext(cipherCtx);
  return 0;
}

JNIEXPORT jlong JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_initWorkingKey(
    JNIEnv *env, jobject object, jbyteArray key, jboolean forEncryption,
    jint mode, jint padding, jbyteArray IV, jlong cipherContext) {
  CipherContext* cipherCtx = (CipherContext*) cipherContext;
  cipherCtx = preInitContext(env, cipherCtx, mode, key, IV);

  (*env)->GetByteArrayRegion(env, key, 0, cipherCtx->keyLength, cipherCtx->key);
  (*env)->GetByteArrayRegion(env, IV, 0, cipherCtx->ivLength, cipherCtx->iv);

  cryptInit cryptInitFunc = getCryptInitFunc(forEncryption);
  EVP_CIPHER* cipher = getCipher(mode, cipherCtx->keyLength);
  if (cipher != NULL) {
    cryptInitFunc(cipherCtx->opensslCtx, cipher, NULL,
        (unsigned char *) cipherCtx->key, (unsigned char *) cipherCtx->iv);
  } else {
    THROW(env, "java/lang/IllegalArgumentException", "unsupportted mode or key size");
  }

  if (padding == PADDING_NOPADDING) {
    EVP_CIPHER_CTX_set_padding(cipherCtx->opensslCtx, 0);
  } else if (padding == PADDING_PKCS5PADDING) {
    EVP_CIPHER_CTX_set_padding(cipherCtx->opensslCtx, 1);
  }

  return (long) cipherCtx;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_processBlock(
    JNIEnv *env, jobject object, jlong cipherContext, jbyteArray in, jint inOff,
    jint inLen, jbyteArray out, jint outOff) {
  unsigned char * input = (unsigned char *) (*env)->GetByteArrayElements(env,
      in, 0);
  unsigned char * output = (unsigned char *) (*env)->GetByteArrayElements(env,
      out, 0);

  CipherContext* cipherCtx = (CipherContext*) cipherContext;
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  int outLength = 0;

  cryptUpdate cryptUpdateFunc = getCryptUpdateFunc(
      ctx->encrypt == ENCRYPTION);

  if (!cryptUpdateFunc(ctx, output + outOff, &outLength, input + inOff,
      inLen)) {
    fprintf(stderr, "inLen: %d, outLen: %d\n", inLen, outLength);
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
    JNIEnv *env, jobject object, jlong cipherContext, jbyteArray out, jint outOff) {
  unsigned char * output = (unsigned char *) (*env)->GetByteArrayElements(env,
      out, 0);

  CipherContext* cipherCtx = (CipherContext*) cipherContext;
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;
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

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_processByteBuffer(
    JNIEnv *env, jobject object, jlong cipherContext, jobject input,
    jint inputPos, jint inputLimit, jobject output, jint outputPos,
    jboolean isUpdate) {
  jbyte* bInput = (*env)->GetDirectBufferAddress(env, input);
  jbyte* bOutput = (*env)->GetDirectBufferAddress(env, output);

  if (NULL == bInput || NULL == bOutput) {
    return 0;
  }
  //EVP_CIPHER_CTX_set_padding(context, 0);
  CipherContext* cipherCtx = (CipherContext*) cipherContext;
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

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

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_setTag(
    JNIEnv *env, jobject object, jlong cipherContext, jbyteArray tag, jint tagOff, jint tLen) {
  unsigned char * input = (unsigned char *) (*env)->GetByteArrayElements(env,
      tag, 0);

  CipherContext* cipherCtx = (CipherContext*) cipherContext;
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tLen, input + tagOff);

  (*env)->ReleaseByteArrayElements(env, tag, (jbyte *) input, 0);
}

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_getTag(
    JNIEnv *env, jobject object, jlong cipherContext, jbyteArray out, jint outOff, jint tLen) {
  unsigned char * tagOut = (unsigned char *) (*env)->GetByteArrayElements(env,
        out, 0);

  CipherContext* cipherCtx = (CipherContext*) cipherContext;
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tLen, tagOut + outOff);

  (*env)->ReleaseByteArrayElements(env, out, (jbyte *) tagOut, 0);
}

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_updateAADFromByteArray(
    JNIEnv *env, jobject object, jlong cipherContext, jbyteArray src, jint offset, jint len) {
  unsigned char * aad = (unsigned char *) (*env)->GetByteArrayElements(env,
      src, 0);

  CipherContext* cipherCtx = (CipherContext*) cipherContext;
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  int outlen;
  cryptUpdate cryptUpdateFunc = getCryptUpdateFunc(
        ctx->encrypt == ENCRYPTION);
  if (!cryptUpdateFunc(ctx, NULL, &outlen, aad + offset, len)) {
    THROW(env, "java/security/GeneralSecurityException",
            "Error in updateAAD");
  }

  (*env)->ReleaseByteArrayElements(env, src, (jbyte *) aad, 0);
}

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_updateAADFromByteBuffer(
    JNIEnv *env, jobject object, jlong cipherContext, jobject src, jint inputPos, jint inputLimit) {
  jbyte* aad = (*env)->GetDirectBufferAddress(env, src);

  if (NULL == aad) {
    return 0;
  }

  CipherContext* cipherCtx = (CipherContext*) cipherContext;
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  int inputLen = inputLimit - inputPos;
  int outlen;

  cryptUpdate cryptUpdateFunc = getCryptUpdateFunc(
        ctx->encrypt == ENCRYPTION);
  if (!cryptUpdateFunc(ctx, NULL, &outlen, (unsigned char *)aad + inputPos, inputLen)) {
    THROW(env, "java/security/GeneralSecurityException",
            "Error in updateAAD");
  }
}
