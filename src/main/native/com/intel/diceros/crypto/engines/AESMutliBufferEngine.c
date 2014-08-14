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
#include "config.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include "com_intel_diceros.h"
#include "com_intel_diceros_crypto_engines_AESMutliBufferEngine.h"
#include "aes_multibuffer.h"

//-------- begin dlerror handling functions -----
void throwDLError(JNIEnv* env, const char* lib)
{
  char msg[1000];
  snprintf(msg, 1000, "Cannot load %s (%s)!", lib, dlerror());
  THROW(env, "java/lang/UnsatisfiedLinkError", msg);
}
//-------- end dlerror handling functions -----

/*
 * mode: 0, ENCRYPTION, 1: DECRYPTION
 * return: context Id
 * Method:    init
 */
JNIEXPORT jlong JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_init(JNIEnv * env,
    jobject object, jboolean forEncryption, jbyteArray key, jbyteArray iv, jint padding, jlong oldContext) {
  // init overall struction, for memory allocation
  int keyLength = (*env)->GetArrayLength(env, key);
  int ivLength = (*env)->GetArrayLength(env, iv);

  // localize key and iv
  jbyte nativeKey[32];
  jbyte nativeIv[32];
  (*env)->GetByteArrayRegion(env, key, 0, keyLength, nativeKey);
  (*env)->GetByteArrayRegion(env, iv, 0, ivLength, nativeIv);

  if (keyLength != 32 && keyLength != 24 && keyLength != 16) {
    THROW(env, "java/lang/IllegalArgumentException", "Illegal key size");
  }

  int loadLibraryResult = 0;
  long ctx = init(env, forEncryption, nativeKey, keyLength, nativeIv, ivLength, padding ,
      oldContext, &loadLibraryResult);
  if (loadLibraryResult == -1) {
     throwDLError(env, HADOOP_CRYPTO_LIBRARY);
     return 0;
  } else if (loadLibraryResult == -2) {
     traceDLError(HADOOP_AESMB_LIBRARY);
  }

  return ctx;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_destoryCipherContext(
    JNIEnv *env, jobject object, jlong cipherContext) {
  CipherContext* cipherCtx = (CipherContext*) cipherContext;
  destroyCipherContext(cipherCtx);
  return 0;
}

/*
 * Class:     com_intel_diceros_crypto_engines_AESMutliBufferEngine
 * Method:    doFinal
 */
JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_processByteBuffer(JNIEnv * env,
    jobject object, jlong context, jobject inputDirectBuffer, jint start, jint inputLength,
    jobject outputDirectBuffer, jint begin, jboolean isUpdate) {
  unsigned char * input = (unsigned char *)(*env)->GetDirectBufferAddress(env, inputDirectBuffer) + start;
  unsigned char * output = (unsigned char *)(*env)->GetDirectBufferAddress(env, outputDirectBuffer) + begin;

  CipherContext* cipherContext = (CipherContext*) context;
  int encrypt_length = bufferCrypt(cipherContext, input, inputLength, output);
  reset(cipherContext, NULL, NULL);
  return encrypt_length;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_processBlock(JNIEnv *env,
    jobject object, jlong context, jbyteArray in, jint inOff, jint inputLength, jbyteArray out, jint outOff) {
  unsigned char * inputTmp = (unsigned char *) (*env)->GetByteArrayElements(env, in, 0);
  unsigned char * outputTmp = (unsigned char *) (*env)->GetByteArrayElements(env, out, 0);
  unsigned char * input = inputTmp;
  unsigned char * output = outputTmp;

  CipherContext* cipherContext = (CipherContext*) context;
  int encrypt_length = bufferCrypt(cipherContext, input, inputLength, output);

  (*env)->ReleaseByteArrayElements(env, in, (jbyte *) inputTmp, 0);
  (*env)->ReleaseByteArrayElements(env, out, (jbyte *) outputTmp, 0);

  reset(cipherContext, NULL, NULL);
  return encrypt_length;
}
