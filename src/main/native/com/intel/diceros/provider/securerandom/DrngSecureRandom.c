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

#include <jni.h>
#include <stdio.h>
#include "com_intel_diceros_provider_securerandom_SecureRandom_DRNG.h"
#include "rdrand-api.h"

JNIEXPORT jboolean JNICALL Java_com_intel_diceros_provider_securerandom_SecureRandom_00024DRNG_drngInit 
  (JNIEnv *env, jclass thisObj) {
  if (0 == drngInit())
    return JNI_TRUE;
  else
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_com_intel_diceros_provider_securerandom_SecureRandom_00024DRNG_drngRandBytes___3B 
  (JNIEnv *env, jobject thisObj, jbyteArray buffer) {
  if (NULL == buffer)
    return JNI_FALSE;
  jbyte* b = (*env)->GetByteArrayElements(env, buffer, 0);
  jsize buffer_len = (*env)->GetArrayLength(env, buffer);
  int rtn = drngRandBytes((uint8_t *)b, buffer_len);
  (*env)->ReleaseByteArrayElements(env, buffer, b, 0);

  if (0 == rtn)
    return JNI_TRUE;
  else
    return JNI_FALSE;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_provider_securerandom_SecureRandom_00024DRNG_drngRandBytes__Ljava_nio_ByteBuffer_2 
  (JNIEnv *env, jobject thisObj, jobject buffer) {
  if (NULL == buffer)
    return JNI_FALSE;
  jbyte* b = (*env)->GetDirectBufferAddress(env, buffer);
  jlong buffer_len = (*env)->GetDirectBufferCapacity(env, buffer);

  if (NULL == b || -1 == buffer_len) {
    return -2;
  } else {
    int rtn = drngRandBytes((uint8_t *)b, buffer_len);
    if (0 == rtn)
      return 0;
    else
      return -1;
  }
}
