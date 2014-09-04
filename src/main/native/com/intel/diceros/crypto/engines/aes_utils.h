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
#include <jni.h>
#include <aes_api.h>
#include <openssl/evp.h>
#include <stdint.h>
#include "com_intel_diceros.h"

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
#define MODE_XTS 2
#define MODE_GCM 3

#define PADDING_NOPADDING 0
#define PADDING_PKCS5PADDING 1

#ifdef UNIX
EVP_CIPHER_CTX * (*dlsym_EVP_CIPHER_CTX_new)(void);
void (*dlsym_EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *);
int (*dlsym_EVP_CIPHER_CTX_cleanup)(EVP_CIPHER_CTX *);
void (*dlsym_EVP_CIPHER_CTX_init)(EVP_CIPHER_CTX *);
int (*dlsym_EVP_CIPHER_CTX_set_padding)(EVP_CIPHER_CTX *, int);
int (*dlsym_EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int (*dlsym_EVP_CipherInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *,  \
           ENGINE *, const unsigned char *, const unsigned char *, int);
int (*dlsym_EVP_CipherUpdate)(EVP_CIPHER_CTX *, unsigned char *,  \
           int *, const unsigned char *, int);
int (*dlsym_EVP_CipherFinal_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
EVP_CIPHER * (*dlsym_EVP_aes_256_ctr)(void);
EVP_CIPHER * (*dlsym_EVP_aes_192_ctr)(void);
EVP_CIPHER * (*dlsym_EVP_aes_128_ctr)(void);
EVP_CIPHER * (*dlsym_EVP_aes_256_cbc)(void);
EVP_CIPHER * (*dlsym_EVP_aes_192_cbc)(void);
EVP_CIPHER * (*dlsym_EVP_aes_128_cbc)(void);
EVP_CIPHER * (*dlsym_EVP_aes_256_xts)(void);
EVP_CIPHER * (*dlsym_EVP_aes_128_xts)(void);
EVP_CIPHER * (*dlsym_EVP_aes_256_gcm)(void);
EVP_CIPHER * (*dlsym_EVP_aes_192_gcm)(void);
EVP_CIPHER * (*dlsym_EVP_aes_128_gcm)(void);
#endif

#ifdef WINDOWS
typedef EVP_CIPHER_CTX * (__cdecl *__dlsym_EVP_CIPHER_CTX_new)(void);
typedef void (__cdecl *__dlsym_EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *);
typedef int (__cdecl *__dlsym_EVP_CIPHER_CTX_cleanup)(EVP_CIPHER_CTX *);
typedef void (__cdecl *__dlsym_EVP_CIPHER_CTX_init)(EVP_CIPHER_CTX *);
typedef int (__cdecl *__dlsym_EVP_CIPHER_CTX_set_padding)(EVP_CIPHER_CTX *, int);
typedef int (__cdecl *__dlsym_EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
typedef int (__cdecl *__dlsym_EVP_CipherInit_ex)(EVP_CIPHER_CTX *,  \
             const EVP_CIPHER *, ENGINE *, const unsigned char *,  \
             const unsigned char *, int);
typedef int (__cdecl *__dlsym_EVP_CipherUpdate)(EVP_CIPHER_CTX *,  \
             unsigned char *, int *, const unsigned char *, int);
typedef int (__cdecl *__dlsym_EVP_CipherFinal_ex)(EVP_CIPHER_CTX *,  \
             unsigned char *, int *);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_256_ctr)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_192_ctr)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_128_ctr)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_256_cbc)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_192_cbc)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_128_cbc)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_256_xts)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_128_xts)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_256_gcm)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_192_gcm)(void);
typedef EVP_CIPHER * (__cdecl *__dlsym_EVP_aes_128_gcm)(void);
__dlsym_EVP_CIPHER_CTX_new dlsym_EVP_CIPHER_CTX_new;
__dlsym_EVP_CIPHER_CTX_free dlsym_EVP_CIPHER_CTX_free;
__dlsym_EVP_CIPHER_CTX_cleanup dlsym_EVP_CIPHER_CTX_cleanup;
__dlsym_EVP_CIPHER_CTX_init dlsym_EVP_CIPHER_CTX_init;
__dlsym_EVP_CIPHER_CTX_set_padding dlsym_EVP_CIPHER_CTX_set_padding;
__dlsym_EVP_CIPHER_CTX_ctrl dlsym_EVP_CIPHER_CTX_ctrl;
__dlsym_EVP_CipherInit_ex dlsym_EVP_CipherInit_ex;
__dlsym_EVP_CipherUpdate dlsym_EVP_CipherUpdate;
__dlsym_EVP_CipherFinal_ex dlsym_EVP_CipherFinal_ex;
__dlsym_EVP_aes_256_ctr dlsym_EVP_aes_256_ctr;
__dlsym_EVP_aes_192_ctr dlsym_EVP_aes_192_ctr;
__dlsym_EVP_aes_128_ctr dlsym_EVP_aes_128_ctr;
__dlsym_EVP_aes_256_ctr dlsym_EVP_aes_256_cbc;
__dlsym_EVP_aes_192_ctr dlsym_EVP_aes_192_cbc;
__dlsym_EVP_aes_128_ctr dlsym_EVP_aes_128_cbc;
__dlsym_EVP_aes_256_ctr dlsym_EVP_aes_256_xts;
__dlsym_EVP_aes_128_ctr dlsym_EVP_aes_128_xts;
__dlsym_EVP_aes_256_ctr dlsym_EVP_aes_256_gcm;
__dlsym_EVP_aes_192_ctr dlsym_EVP_aes_192_gcm;
__dlsym_EVP_aes_128_ctr dlsym_EVP_aes_128_gcm;
#endif

typedef void (*EncryptX8)(sAesData_x8* data);
typedef void (*DecryptX1)(sAesData* data);
typedef void (*KeySched)(uint8_t *key, uint8_t *enc_exp_keys);

typedef struct _sAesContext {
  void* handle;
  uint8_t encryptKeysched[16*15];
  uint8_t decryptKeysched[16*15];
  EncryptX8 efunc;
  DecryptX1 dfunc;
  int aesEnabled;
} sAesContext;

typedef struct _CipherContext {
  EVP_CIPHER_CTX* opensslCtx;
  uint8_t* key;
  uint8_t  keyLength;
  uint8_t* iv;
  uint8_t  ivLength;
  sAesContext* aesmbCtx;
} CipherContext;

void destroyCipherContext(CipherContext* ctx);

void initOpensslIDs(JNIEnv *env);

EVP_CIPHER* getCipher(int mode, int keyLen);

#endif
