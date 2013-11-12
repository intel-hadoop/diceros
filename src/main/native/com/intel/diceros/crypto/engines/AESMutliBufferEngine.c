/*
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
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "config.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include "com_intel_diceros.h"
#include "com_intel_diceros_crypto_engines_AESMutliBufferEngine.h"
#include "aes_utils.h"

#define ENCRYPTION 1
#define DECRYPTION 0

typedef struct _CipherContext {
  EVP_CIPHER_CTX* opensslCtx;
  sAesContext* aesmbCtx;
  int aesEnabled;
} CipherContext;

//-------- begin dlerror handling functions -----
void traceDLError(const char* libname)
{
  DTRACE("Can not load library [%s]: <%s>\n", libname, dlerror());
}

void throwDLError(JNIEnv* env, const char* lib)
{
  char msg[1000];
  snprintf(msg, 1000, "Cannot load %s (%s)!", lib, dlerror());
  THROW(env, "java/lang/UnsatisfiedLinkError", msg);
}

void cleanDLError()
{
  dlerror();
}
//-------- end dlerror handling functions -----


CipherContext* initContext(void* handle, jbyte* key, int keylen, jbyte* iv, int ivlen)
{
  CipherContext* ctx = (CipherContext*) malloc (sizeof(CipherContext));

  // init openssl context
  ctx->opensslCtx = (EVP_CIPHER_CTX*) malloc (sizeof(EVP_CIPHER_CTX));

  // init iv and key
  ctx->aesmbCtx = aesmb_ctxcreate(keylen, ivlen);
  int result = aesmb_ctxinit(ctx->aesmbCtx, handle, (uint8_t*)key, keylen, (uint8_t*)iv, ivlen); 

  // cache AES-NI bit
  ctx->aesEnabled = aesni_supported() && result == 0;
  
  return ctx;
}

void opensslResetContext(int mode, EVP_CIPHER_CTX* context, sAesContext* aesmbCtx)
{
  opensslResetContextMB(mode, context, aesmbCtx, 0);
}

void opensslResetContextMB(int mode, EVP_CIPHER_CTX* context, sAesContext* aesmbCtx, int count)
{
  int keyLength = aesmbCtx->keyLength;
  unsigned char* nativeKey = (unsigned char*)aesmbCtx->key;
  unsigned char* nativeIv = (unsigned char*)aesmbCtx->iv + count*16;

  EVP_CIPHER_CTX_init(context);
  
  if (mode == ENCRYPTION) {
    if (keyLength == 32) {
      EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), NULL, (unsigned char *)nativeKey, (unsigned char *)nativeIv);
    }
    else if (keyLength == 16) {
      EVP_EncryptInit_ex(context, EVP_aes_128_cbc(), NULL, (unsigned char *)nativeKey, (unsigned char *)nativeIv);
    }
  }
  else {
    if (keyLength == 32) {
      EVP_DecryptInit_ex(context, EVP_aes_256_cbc(), NULL, (unsigned char *)nativeKey, (unsigned char *)nativeIv);
    }
    else if (keyLength == 16) {
      EVP_DecryptInit_ex(context, EVP_aes_128_cbc(), NULL, (unsigned char *)nativeKey, (unsigned char *)nativeIv);
    }
  }
}

int opensslEncrypt(EVP_CIPHER_CTX* ctx, unsigned char* output, int* outLength, unsigned char* input, int inLength)
{
  int outLengthFinal;
  *outLength = 0;
  
  if(inLength && !EVP_EncryptUpdate(ctx, output, outLength, input, inLength)){
    printf("ERROR in EVP_EncryptUpdate \n");
    ERR_print_errors_fp(stderr);
    return 0;
  }
  
  /* update ciphertext with the final remaining bytes */
  if(!EVP_EncryptFinal_ex(ctx, output + *outLength, &outLengthFinal)){
    printf("ERROR in EVP_EncryptFinal_ex \n");
    ERR_print_errors_fp(stderr);
    return 0;
  }

  *outLength = *outLength + outLengthFinal;
  
  return 1;
}

int opensslDecrypt(EVP_CIPHER_CTX* ctx, unsigned char* output, int* outLength, unsigned char* input, int inLength)
{
  int outLengthFinal;
  *outLength = 0;
  
  if(inLength && !EVP_DecryptUpdate(ctx, output, outLength, input, inLength)){
    printf("ERROR in EVP_DecryptUpdate\n");
    ERR_print_errors_fp(stderr);
    return 0;
  }
  
  if(!EVP_DecryptFinal_ex(ctx, output + *outLength, &outLengthFinal)){
    printf("ERROR in EVP_DecryptFinal_ex\n");
    ERR_print_errors_fp(stderr);
    return 0;
  }

  *outLength = *outLength + outLengthFinal;

  return 1;
}

void destroyContext(CipherContext* ctx)
{
  aesmb_ctxdest(ctx->aesmbCtx);
  EVP_CIPHER_CTX_cleanup(ctx->opensslCtx);
  free(ctx->opensslCtx);
  free(ctx);
}

void reportError(JNIEnv* env, char* msg)
{
  THROW(env, "java/security/GeneralSecurityException", msg);
}

/*
 * Class:     sec_util_OpenSSLCrypto
 * mode: 0, ENCRYPTION, 1: DECRYPTION
 * return: context Id
 * Method:    init
 */
JNIEXPORT jlong JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_init
(JNIEnv * env, jobject object, jint mode, jbyteArray key, jbyteArray iv,  jstring padding , jlong oldContext) {

  if (oldContext != NULL) {
    Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_cleanup(env, object, oldContext);
  }

  // Load libcrypto.so, if error, throw java exception
  if (!loadLibrary(HADOOP_CRYPTO_LIBRARY)) {
    throwDLError(env, HADOOP_CRYPTO_LIBRARY);
    return 0;
  }

  // load libaesmb.so, if error, print debug message
  void* handle = loadLibrary(HADOOP_AESMB_LIBRARY);
  if (NULL == handle) {
    traceDLError(HADOOP_AESMB_LIBRARY);
  }

  // cleanup error
  cleanDLError();

  // init overall struction, for memory allocation
  int keyLength = (*env)->GetArrayLength(env, key);
  int ivLength = (*env)->GetArrayLength(env, iv);

  const char* cstr_padding = (*env)->GetStringUTFChars(env, padding, 0);
  int pkcs5Padding = strncmp(cstr_padding,"PKCS5PADDING",12);

  (*env)->ReleaseStringUTFChars(env, padding, cstr_padding);

  // localize key and iv
  jbyte nativeKey[32];
  jbyte nativeIv[32];
  (*env)->GetByteArrayRegion(env, key, 0, keyLength, nativeKey);
  (*env)->GetByteArrayRegion(env, iv, 0, ivLength, nativeIv);

  // init all context
  CipherContext* ctx = initContext(handle, nativeKey, keyLength, nativeIv, ivLength);

  // init openssl context, by using localized key & iv
  opensslResetContext(mode, ctx->opensslCtx, ctx->aesmbCtx);

  if (pkcs5Padding == 0) {
    EVP_CIPHER_CTX_set_padding(ctx, 1);
  } else {
    EVP_CIPHER_CTX_set_padding(ctx, 0);
  }

  return (long)ctx;
}

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_reset
(JNIEnv * env, jobject object, jlong context, jbyteArray key, jbyteArray iv) {
  CipherContext* cipherContext = (CipherContext*)context;
  sAesContext* aesCtx = cipherContext->aesmbCtx;
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *)(cipherContext->opensslCtx);
  jbyte * nativeKey = NULL;
  jbyte * nativeIv = NULL;

  // localize key
  if (NULL != key) {
    nativeKey = (*env)->GetByteArrayElements(env, key, NULL);
  } 

  // localize iv
  if (NULL != iv) {
    nativeIv = (*env)->GetByteArrayElements(env, iv, NULL);
  }

  // reinit openssl context by localized key&iv
  aesmb_keyivinit(aesCtx, (uint8_t*)nativeKey, aesCtx->keyLength, (uint8_t*)nativeIv, aesCtx->ivLength);

  // unlock gc
  if (NULL != key) {
    (*env)->ReleaseByteArrayElements(env, key, nativeKey, 0);
  }

  if (NULL != iv) {
    (*env)->ReleaseByteArrayElements(env, iv, nativeIv, 0);
  }

  EVP_CIPHER_CTX_cleanup(ctx);
  opensslResetContext(ctx->encrypt, ctx, aesCtx);
}

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_cleanup
(JNIEnv * env, jobject object, jlong context) {
  CipherContext * ctx = (CipherContext*)context;
  
  destroyContext(ctx);
}


/*
 * Class:     com_intel_diceros_crypto_engines_AESMutliBufferEngine
 * Method:    doFinal
 */
#define HEADER_LENGTH 2

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_bufferCrypt
(JNIEnv * env, jobject object, jlong context, jobject inputDirectBuffer, jint start, jint inputLength, jobject outputDirectBuffer, jint begin, jboolean isUpdate) {
  unsigned char * input = (unsigned char *)(*env)->GetDirectBufferAddress(env, inputDirectBuffer) + start;
  unsigned char * output = (unsigned char *)(*env)->GetDirectBufferAddress(env, outputDirectBuffer) + begin;

  CipherContext* cipherContext = (CipherContext*) context;
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *)cipherContext->opensslCtx;
  sAesContext* aesCtx = (sAesContext*) cipherContext->aesmbCtx;
  int aesEnabled = cipherContext->aesEnabled;
  int aesmbApplied = 0; // 0 for not applied

  int outLength = 0;
  int outLengthFinal = 0;

  unsigned char * header = NULL;
  int extraOutputLength = 0;
  if (ctx->encrypt == ENCRYPTION) {
    header = output;
    output = header + HEADER_LENGTH;
    extraOutputLength = HEADER_LENGTH;
  } else {
    header = input;
    input = header + HEADER_LENGTH;
    inputLength -= HEADER_LENGTH;
  }

  if (ctx->encrypt == ENCRYPTION) {
    if (aesEnabled) {
      // try to apply multi-buffer optimization
      int encrypted = aesmb_encrypt(aesCtx, input, inputLength, output, &outLength);
      if (encrypted < 0) {
        reportError(env, "AES multi-buffer encryption failed.");
        return 0;
      }
      aesmbApplied = encrypted;
      input += encrypted;
      inputLength -=encrypted;
      output +=outLength; // rest of data will use openssl to perform encryption
    }

    // encrypt with padding
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    // encrypt the rest
    opensslEncrypt(ctx, output, &outLengthFinal, input, inputLength);

    if (aesmbApplied) {
      header[0] = 1; // enabled
      header[1] = outLengthFinal - inputLength; // padding
    } else {
      header[0] = 0;
      header[1] = 0;
    }
  } else {
    // read custom header
    if (header[0]) {
      int padding = (int)header[1] ;
      if (aesEnabled) {
        int decrypted = aesmb_decrypt(aesCtx, input, inputLength - padding, output, &outLengthFinal);
        if (decrypted < 0) {
          reportError(env, "Data can not be decrypted correctly");
          return 0;
        }
        
        input += outLengthFinal;
        inputLength -= outLengthFinal;
        output += outLengthFinal;
        outLength += outLengthFinal;
      } else {
        int step = aesmb_streamlength(inputLength - padding) ;
        outLength = 0;
        int i;
        for (i = 0 ; i < PARALLEL_LEVEL; i++) {
          //reset open ssl context
          EVP_CIPHER_CTX_cleanup(ctx);
          opensslResetContextMB(ctx->encrypt, ctx, aesCtx,i);
          //clear padding, since multi-buffer AES did not have padding
          EVP_CIPHER_CTX_set_padding(ctx, 0);
          //decrypt using open ssl
          opensslDecrypt(ctx, output, &outLengthFinal, input, step);
          
          input += step;
          inputLength -= step;
          output += outLengthFinal;
          outLength += outLengthFinal;
        }
      }
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    //reset open ssl context
    opensslResetContext(ctx->encrypt, ctx, aesCtx);
    //enable padding, the last buffer need padding
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    //decrypt using open ssl
    opensslDecrypt(ctx, output, &outLengthFinal, input, inputLength);
  }
  Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_reset(env, object, context, NULL, NULL);
  return outLength + outLengthFinal + extraOutputLength;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_getBlockSize(
    JNIEnv *env, jobject object, jlong context) {
  return 16;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_doFinalArray(
    JNIEnv *env, jobject object, jlong context, jbyteArray in, jint inOff,
    jint inputLength, jbyteArray out, jint outOff) {

  unsigned char * inputTmp = (unsigned char *) (*env)->GetByteArrayElements(env, in, inOff);
  unsigned char * outputTmp = (unsigned char *) (*env)->GetByteArrayElements(env, out, outOff);
  unsigned char * input = inputTmp;
  unsigned char * output = outputTmp;
  CipherContext* cipherContext = (CipherContext*) context;
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *)cipherContext->opensslCtx;
  sAesContext* aesCtx = (sAesContext*) cipherContext->aesmbCtx;
  int aesEnabled = cipherContext->aesEnabled;
  int aesmbApplied = 0; // 0 for not applied

  int outLength = 0;
  int outLengthFinal = 0;

  unsigned char * header = NULL;
  int extraOutputLength = 0;
  if (ctx->encrypt == ENCRYPTION) {
    header = output;
    output = header + HEADER_LENGTH;
    extraOutputLength = HEADER_LENGTH;
  } else {
    header = input;
    input = header + HEADER_LENGTH;
    inputLength -= HEADER_LENGTH;
  }

  if (ctx->encrypt == ENCRYPTION) {
    if (aesEnabled) {
      // try to apply multi-buffer optimization
      int encrypted = aesmb_encrypt(aesCtx, input, inputLength, output, &outLength);
      if (encrypted < 0) {
        reportError(env, "AES multi-buffer encryption failed.");
        return 0;
      }
      aesmbApplied = encrypted;
      input += encrypted;
      inputLength -=encrypted;
      output +=outLength; // rest of data will use openssl to perform encryption
    }

    // encrypt with padding
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    // encrypt the rest
    opensslEncrypt(ctx, output, &outLengthFinal, input, inputLength);

    if (aesmbApplied) {
      header[0] = 1; // enabled
      header[1] = outLengthFinal - inputLength; // padding
    } else {
      header[0] = 0;
      header[1] = 0;
    }
    (*env)->ReleaseByteArrayElements(env, in, (jbyte *) inputTmp, 0);
    (*env)->ReleaseByteArrayElements(env, out, (jbyte *) outputTmp, 0);
  } else {
    // read custom header
    if (header[0]) {
      int padding = (int)header[1] ;
      if (aesEnabled) {
        int decrypted = aesmb_decrypt(aesCtx, input, inputLength - padding, output, &outLengthFinal);
        if (decrypted < 0) {
          reportError(env, "Data can not be decrypted correctly");
          return 0;
        }

        input += outLengthFinal;
        inputLength -= outLengthFinal;
        output += outLengthFinal;
        outLength += outLengthFinal;
      } else {
        int step = aesmb_streamlength(inputLength - padding) ;
        outLength = 0;
        int i;
        for (i = 0 ; i < PARALLEL_LEVEL; i++) {
          //reset open ssl context
          EVP_CIPHER_CTX_cleanup(ctx);
          opensslResetContextMB(ctx->encrypt, ctx, aesCtx, i);
          //clear padding, since multi-buffer AES did not have padding
          EVP_CIPHER_CTX_set_padding(ctx, 0);
          //decrypt using open ssl
          opensslDecrypt(ctx, output, &outLengthFinal, input, step);

          input += step;
          inputLength -= step;
          output += outLengthFinal;
          outLength += outLengthFinal;
        }
      }
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    //reset open ssl context
    opensslResetContext(ctx->encrypt, ctx, aesCtx);
    //enable padding, the last buffer need padding
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    //decrypt using open ssl
    opensslDecrypt(ctx, output, &outLengthFinal, input, inputLength);

    (*env)->ReleaseByteArrayElements(env, in, (jbyte *) inputTmp, 0);
    (*env)->ReleaseByteArrayElements(env, out, (jbyte *) outputTmp, 0);
  }

  Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_reset(env, object, context, NULL, NULL);
  return outLength + outLengthFinal + extraOutputLength;

}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_doFinal(
          JNIEnv *env, jobject object, jlong context, jbyteArray out, jint outOff) {
  return 0;
}