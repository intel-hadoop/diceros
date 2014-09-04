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
#include "aes_utils.h"
#include "com_intel_diceros_crypto_engines_AESOpensslEngine.h"

CipherContext* preInitContext(JNIEnv *env, CipherContext* cipherCtx, jint mode,
    jbyteArray key, jbyteArray IV) {
  int keyLength, ivLength;
  if (cipherCtx != NULL) {
    if (cipherCtx->opensslCtx != NULL && mode == MODE_CBC) {
      dlsym_EVP_CIPHER_CTX_cleanup(cipherCtx->opensslCtx);
      dlsym_EVP_CIPHER_CTX_free(cipherCtx->opensslCtx);
      cipherCtx->opensslCtx = dlsym_EVP_CIPHER_CTX_new();
      dlsym_EVP_CIPHER_CTX_init(cipherCtx->opensslCtx);
    }
  } else {
    cipherCtx = (CipherContext*)malloc(sizeof(CipherContext));
    cipherCtx->opensslCtx = dlsym_EVP_CIPHER_CTX_new();
    dlsym_EVP_CIPHER_CTX_init(cipherCtx->opensslCtx);
    cipherCtx->key = NULL;
    cipherCtx->keyLength = 0;
    cipherCtx->iv = NULL;
    cipherCtx->ivLength = 0;
    cipherCtx->aesmbCtx = NULL;
  }
  keyLength = (*env)->GetArrayLength(env, key);
  if (cipherCtx->key == NULL || cipherCtx->keyLength != keyLength) {
    cipherCtx->keyLength = keyLength;
    if (cipherCtx->key != NULL) {
      free(cipherCtx->key);
    }
    cipherCtx->key = (jbyte*) malloc(cipherCtx->keyLength);
  }
  ivLength = (*env)->GetArrayLength(env, IV);
  if (cipherCtx->iv == NULL || cipherCtx->ivLength != ivLength) {
    cipherCtx->ivLength =  ivLength;
    if (cipherCtx->iv != NULL) {
      free(cipherCtx->iv);
    }
    cipherCtx->iv = (jbyte*) malloc(cipherCtx->ivLength);
  }
  return cipherCtx;
}

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_initIDs(
    JNIEnv *env, jclass clazz) {
  initOpensslIDs(env);
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
  EVP_CIPHER* cipher = NULL;
  CipherContext* cipherCtx = (CipherContext*) cipherContext;
  cipherCtx = preInitContext(env, cipherCtx, mode, key, IV);

  (*env)->GetByteArrayRegion(env, key, 0, cipherCtx->keyLength, cipherCtx->key);
  (*env)->GetByteArrayRegion(env, IV, 0, cipherCtx->ivLength, cipherCtx->iv);

  cipher = getCipher(mode, cipherCtx->keyLength);
  if (cipher != NULL) {
    dlsym_EVP_CipherInit_ex(cipherCtx->opensslCtx, cipher, NULL,
        (unsigned char *) cipherCtx->key, (unsigned char *) cipherCtx->iv, forEncryption);
  } else {
    THROW(env, "java/lang/IllegalArgumentException", "unsupportted mode or key size");
  }

  if (padding == PADDING_NOPADDING) {
    dlsym_EVP_CIPHER_CTX_set_padding(cipherCtx->opensslCtx, 0);
  } else if (padding == PADDING_PKCS5PADDING) {
    dlsym_EVP_CIPHER_CTX_set_padding(cipherCtx->opensslCtx, 1);
  }

  return (long) cipherCtx;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_processBlock(
    JNIEnv *env, jobject object, jlong cipherContext, jbyteArray in, jint inOff,
    jint inLen, jbyteArray out, jint outOff) {
  unsigned char *input, *output;
  CipherContext* cipherCtx;
  EVP_CIPHER_CTX * ctx;
  int outLength = 0;

  input = (unsigned char *) (*env)->GetByteArrayElements(env,
      in, 0);
  output = (unsigned char *) (*env)->GetByteArrayElements(env,
      out, 0);

  cipherCtx = (CipherContext*) cipherContext;
  ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  if (!dlsym_EVP_CipherUpdate(ctx, output + outOff, &outLength, input + inOff,
      inLen)) {
    THROW(env, "java/security/GeneralSecurityException",
        "Error in EVP_EncryptUpdate or EVP_DecryptUpdate");
    return 0;
  }

  (*env)->ReleaseByteArrayElements(env, in, (jbyte *) input, 0);
  (*env)->ReleaseByteArrayElements(env, out, (jbyte *) output, 0);

  return outLength;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_doFinal(
    JNIEnv *env, jobject object, jlong cipherContext, jbyteArray out, jint outOff) {
  unsigned char * output;
  CipherContext* cipherCtx;
  EVP_CIPHER_CTX * ctx;
  int outLength = 0;

  output = (unsigned char *) (*env)->GetByteArrayElements(env,
      out, 0);

  cipherCtx = (CipherContext*) cipherContext;
  ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  if (!dlsym_EVP_CipherFinal_ex(ctx, (unsigned char *) output + outOff, &outLength)) {
    THROW(env, "javax/crypto/IllegalBlockSizeException",
        "Input length not multiple of 16 bytes");
    //THROW(env, "java/security/GeneralSecurityException",
    //          "Error in EVP_EncryptFinal_ex or EVP_DecryptFinal_ex");
    return 0;
  }

  (*env)->ReleaseByteArrayElements(env, out, (jbyte *) output, 0);
  return outLength;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_processByteBuffer(
    JNIEnv *env, jobject object, jlong cipherContext, jobject input,
    jint inputPos, jint inputLimit, jobject output, jint outputPos,
    jboolean isUpdate) {
  jbyte *bInput, *bOutput;
  int outLenUpdate, outLengthFinal, inputLength;
  EVP_CIPHER_CTX *ctx;
  CipherContext* cipherCtx;

  bInput = (*env)->GetDirectBufferAddress(env, input);
  bOutput = (*env)->GetDirectBufferAddress(env, output);

  if (NULL == bInput || NULL == bOutput) {
    return 0;
  }
  //EVP_CIPHER_CTX_set_padding(context, 0);
  cipherCtx = (CipherContext*) cipherContext;
  ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  outLenUpdate = 0;
  outLengthFinal = 0;
  inputLength = inputLimit - inputPos;

  if (!dlsym_EVP_CipherUpdate(ctx, (unsigned char *) bOutput + outputPos,
      &outLenUpdate, (const unsigned char *) bInput + inputPos,
      inputLength)) {
    THROW(env, "java/security/GeneralSecurityException",
        "Error in EVP_EncryptUpdate or EVP_DecryptUpdate");
    return 0;
  }
  if (isUpdate == JNI_FALSE) {
    if (!dlsym_EVP_CipherFinal_ex(ctx,
        (unsigned char *) bOutput + outputPos + outLenUpdate,
        &outLengthFinal)) {
      //THROW(env, "javax/crypto/IllegalBlockSizeException",
      //               "Input length not multiple of 16 bytes...");
      THROW(env, "java/security/GeneralSecurityException",
          "Error in EVP_EncryptFinal_ex or EVP_DecryptFinal_ex");
      return 0;
    }
  }
  return outLenUpdate + outLengthFinal;
}

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_setTag(
    JNIEnv *env, jobject object, jlong cipherContext, jbyteArray tag, jint tagOff, jint tLen) {
  unsigned char * input;
  CipherContext* cipherCtx;
  EVP_CIPHER_CTX * ctx;

  input = (unsigned char *) (*env)->GetByteArrayElements(env, tag, 0);

  cipherCtx = (CipherContext*) cipherContext;
  ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  dlsym_EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tLen, input + tagOff);

  (*env)->ReleaseByteArrayElements(env, tag, (jbyte *) input, 0);
}

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_getTag(
    JNIEnv *env, jobject object, jlong cipherContext, jbyteArray out, jint outOff, jint tLen) {
  unsigned char * tagOut;
  CipherContext* cipherCtx;
  EVP_CIPHER_CTX * ctx;

  tagOut = (unsigned char *) (*env)->GetByteArrayElements(env, out, 0);

  cipherCtx = (CipherContext*) cipherContext;
  ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  dlsym_EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tLen, tagOut + outOff);

  (*env)->ReleaseByteArrayElements(env, out, (jbyte *) tagOut, 0);
}

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_updateAADFromByteArray(
    JNIEnv *env, jobject object, jlong cipherContext, jbyteArray src, jint offset, jint len) {
  unsigned char * aad;
  CipherContext* cipherCtx;
  EVP_CIPHER_CTX * ctx;
  int outlen;

  aad = (unsigned char *) (*env)->GetByteArrayElements(env,
      src, 0);

  cipherCtx = (CipherContext*) cipherContext;
  ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  if (!dlsym_EVP_CipherUpdate(ctx, NULL, &outlen, aad + offset, len)) {
    THROW(env, "java/security/GeneralSecurityException",
            "Error in updateAAD");
  }

  (*env)->ReleaseByteArrayElements(env, src, (jbyte *) aad, 0);
}

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESOpensslEngine_updateAADFromByteBuffer(
    JNIEnv *env, jobject object, jlong cipherContext, jobject src, jint inputPos, jint inputLimit) {
  jbyte* aad;
  CipherContext* cipherCtx;
  EVP_CIPHER_CTX * ctx;
  int inputLen, outlen;

  aad = (*env)->GetDirectBufferAddress(env, src);

  if (NULL == aad) {
    return;
  }

  cipherCtx = (CipherContext*) cipherContext;
  ctx = (EVP_CIPHER_CTX *) cipherCtx->opensslCtx;

  inputLen = inputLimit - inputPos;

  if (!dlsym_EVP_CipherUpdate(ctx, NULL, &outlen, (unsigned char *)aad + inputPos, inputLen)) {
    THROW(env, "java/security/GeneralSecurityException",
            "Error in updateAAD");
  }
}
