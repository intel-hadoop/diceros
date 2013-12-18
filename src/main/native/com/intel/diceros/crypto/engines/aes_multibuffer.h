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

#ifndef __AES_MULTIBUFFER_H
#define __AES_MULTIBUFFER_H

#include "aes_utils.h"

#define HEADER_LENGTH 2

typedef struct _CipherContext {
  EVP_CIPHER_CTX* opensslCtx;
  sAesContext* aesmbCtx;
  int aesEnabled;
} CipherContext;

void cleanDLError();

void cleanup(long context);

int bufferCrypt(CipherContext* cipherContext, const char* input, int inputLength, char* output);

void reset(CipherContext* cipherContext, uint8_t* nativeKey, uint8_t* nativeIv);

long init(int forEncryption, signed char* nativeKey, int keyLength, signed char* nativeIv, int ivLength, int padding , long oldContext, int* loadLibraryResult);

CipherContext* initContext(void* handle, signed char* key, int keylen, signed char* iv, int ivlen);

void opensslResetContext(int forEncryption, EVP_CIPHER_CTX* context, sAesContext* aesmbCtx);

void opensslResetContextMB(int forEncryption, EVP_CIPHER_CTX* context,
		sAesContext* aesmbCtx, int count);

#endif