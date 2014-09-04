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

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_initIDs(
    JNIEnv *env, jclass clazz) {
  initOpensslIDs(env);
  initAesmbIDs(env);
}

JNIEXPORT jlong JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_init(JNIEnv * env,
    jobject object, jboolean forEncryption, jbyteArray key, jbyteArray iv, jint padding, jlong oldContext) {
  int keyLength, ivLength;
  long ctx;
  jbyte nativeKey[32];
  jbyte nativeIv[32];
  // init overall struction, for memory allocation
  keyLength = (*env)->GetArrayLength(env, key);
  ivLength = (*env)->GetArrayLength(env, iv);

  (*env)->GetByteArrayRegion(env, key, 0, keyLength, nativeKey);
  (*env)->GetByteArrayRegion(env, iv, 0, ivLength, nativeIv);

  if (keyLength != 32 && keyLength != 24 && keyLength != 16) {
    THROW(env, "java/lang/IllegalArgumentException", "Illegal key size");
  }

  ctx = init(env, forEncryption, nativeKey, keyLength, nativeIv, ivLength, padding ,
      oldContext);

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
  unsigned char *input;
  unsigned char *output;
  int encrypt_length;
  CipherContext* cipherContext;

  input = (unsigned char *)(*env)->GetDirectBufferAddress(env, inputDirectBuffer) + start;
  output = (unsigned char *)(*env)->GetDirectBufferAddress(env, outputDirectBuffer) + begin;

  cipherContext = (CipherContext*) context;
  encrypt_length = bufferCrypt(cipherContext, input, inputLength, output);
  reset(cipherContext, NULL, NULL);
  return encrypt_length;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_processBlock(JNIEnv *env,
    jobject object, jlong context, jbyteArray in, jint inOff, jint inputLength, jbyteArray out, jint outOff) {
  unsigned char *inputTmp, *outputTmp, *input, *output;
  int encrypt_length;
  CipherContext* cipherContext;

  inputTmp = (unsigned char *) (*env)->GetByteArrayElements(env, in, 0);
  outputTmp = (unsigned char *) (*env)->GetByteArrayElements(env, out, 0);
  input = inputTmp;
  output = outputTmp;

  cipherContext = (CipherContext*) context;
  encrypt_length = bufferCrypt(cipherContext, input, inputLength, output);

  (*env)->ReleaseByteArrayElements(env, in, (jbyte *) inputTmp, 0);
  (*env)->ReleaseByteArrayElements(env, out, (jbyte *) outputTmp, 0);

  reset(cipherContext, NULL, NULL);
  return encrypt_length;
}
