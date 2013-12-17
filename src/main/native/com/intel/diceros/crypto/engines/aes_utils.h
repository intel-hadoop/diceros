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

#ifndef __AES_UTILS_H
#define __AES_UTILS_H

#include <stdlib.h>
#include <aes_api.h>
#include <openssl/evp.h>

#ifdef DEBUG
#include <stdio.h>
#define DTRACE(X,...) printf((X),##__VA_ARGS__)
#else
#define DTRACE(X,...)
#endif

#define PARALLEL_LEVEL 8

#define ENCRYPTION 1
#define DECRYPTION 0

#define MODE_CTR 0
#define MODE_CBC 1

#define PADDING_NOPADDING 0
#define PADDING_PKCS5PADDING 1

typedef void (*EncryptX8)(sAesData_x8* data);
typedef void (*DecryptX1)(sAesData* data);
typedef void (*KeySched)(uint8_t *key, uint8_t *enc_exp_keys);

typedef struct _sAesContext {
  void* handle;
  uint8_t* key;
  uint8_t  keyLength;
  uint8_t* iv;
  uint8_t  ivLength;
  uint8_t  encryptKeysched[16*15];
  uint8_t  decryptKeysched[16*15];
  EncryptX8 efunc;
  DecryptX1 dfunc;
} sAesContext;

void* loadLibrary(const char* libname);
int aesmb_streamlength(int inputLength);
int aesni_supported();
int aesmb_ctxinit(sAesContext* ctx, void* handle, uint8_t* key, uint8_t  keyLength, uint8_t* iv, uint8_t ivLength);
sAesContext* aesmb_ctxcreate();
void aesmb_ctxdest(sAesContext* ctx);
int aesmb_keyivinit(sAesContext* ctx, uint8_t* key, int keyLength, uint8_t* iv, int ivLength);
int aesmb_encrypt(sAesContext* ctx, uint8_t* input, int inputLength, uint8_t* output, int* outputLength);
int aesmb_decrypt(sAesContext* ctx, uint8_t* input, int inputLength, uint8_t* output, int* outputLength);

typedef int (*cryptInit)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
		const unsigned char *, const unsigned char *);
typedef int (*cryptUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *,
		const unsigned char *, int);
typedef int (*cryptFinal)(EVP_CIPHER_CTX*, unsigned char *, int *);

cryptInit getCryptInitFunc(int forEncryption);

cryptUpdate getCryptUpdateFunc(int forEncryption);

cryptFinal getCryptFinalFunc(int forEncryption);

#endif
