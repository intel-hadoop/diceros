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
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "aes_multibuffer.h"
#include "config.h"

#ifdef UNIX
#include <cpuid.h>
#endif

#ifdef WINDOWS
#include <intrin.h>
#endif

#define BLOCKSIZE 16

#ifdef UNIX
static void (*dlsym_iDec128_CBC_by8)(sAesData *data);
static void (*dlsym_iDec192_CBC_by8)(sAesData *data);
static void (*dlsym_iDec256_CBC_by8)(sAesData *data);
static void (*dlsym_aes_cbc_enc_128_x8)(sAesData_x8 *args);
static void (*dlsym_aes_cbc_enc_192_x8)(sAesData_x8 *args);
static void (*dlsym_aes_cbc_enc_256_x8)(sAesData_x8 *args);
static void (*dlsym_aes_keyexp_128_enc)(uint8_t *key, uint8_t *enc_exp_keys);
static void (*dlsym_aes_keyexp_192_enc)(uint8_t *key, uint8_t *enc_exp_keys);
static void (*dlsym_aes_keyexp_256_enc)(uint8_t *key, uint8_t *enc_exp_keys);
static void (*dlsym_aes_keyexp_128_dec)(uint8_t *key, uint8_t *enc_exp_keys);
static void (*dlsym_aes_keyexp_192_dec)(uint8_t *key, uint8_t *enc_exp_keys);
static void (*dlsym_aes_keyexp_256_dec)(uint8_t *key, uint8_t *enc_exp_keys);
static void *aesmbHandle;
#endif

#ifdef WINDOWS
typedef void (__cdecl *__dlsym_iDec128_CBC_by8)(sAesData *data);
typedef void (__cdecl *__dlsym_iDec192_CBC_by8)(sAesData *data);
typedef void (__cdecl *__dlsym_iDec256_CBC_by8)(sAesData *data);
typedef void (__cdecl *__dlsym_aes_cbc_enc_128_x8)(sAesData_x8 *args);
typedef void (__cdecl *__dlsym_aes_cbc_enc_192_x8)(sAesData_x8 *args);
typedef void (__cdecl *__dlsym_aes_cbc_enc_256_x8)(sAesData_x8 *args);
typedef void (__cdecl *__dlsym_aes_keyexp_128_enc)(uint8_t *key, uint8_t *enc_exp_keys);
typedef void (__cdecl *__dlsym_aes_keyexp_192_enc)(uint8_t *key, uint8_t *enc_exp_keys);
typedef void (__cdecl *__dlsym_aes_keyexp_256_enc)(uint8_t *key, uint8_t *enc_exp_keys);
typedef void (__cdecl *__dlsym_aes_keyexp_128_dec)(uint8_t *key, uint8_t *enc_exp_keys);
typedef void (__cdecl *__dlsym_aes_keyexp_192_dec)(uint8_t *key, uint8_t *enc_exp_keys);
typedef void (__cdecl *__dlsym_aes_keyexp_256_dec)(uint8_t *key, uint8_t *enc_exp_keys);
static __dlsym_iDec128_CBC_by8 dlsym_iDec128_CBC_by8;
static __dlsym_iDec192_CBC_by8 dlsym_iDec192_CBC_by8;
static __dlsym_iDec256_CBC_by8 dlsym_iDec256_CBC_by8;
static __dlsym_aes_cbc_enc_128_x8 dlsym_aes_cbc_enc_128_x8;
static __dlsym_aes_cbc_enc_192_x8 dlsym_aes_cbc_enc_192_x8;
static __dlsym_aes_cbc_enc_256_x8 dlsym_aes_cbc_enc_256_x8;
static __dlsym_aes_keyexp_128_enc dlsym_aes_keyexp_128_enc;
static __dlsym_aes_keyexp_192_enc dlsym_aes_keyexp_192_enc;
static __dlsym_aes_keyexp_256_enc dlsym_aes_keyexp_256_enc;
static __dlsym_aes_keyexp_128_dec dlsym_aes_keyexp_128_dec;
static __dlsym_aes_keyexp_192_dec dlsym_aes_keyexp_192_dec;
static __dlsym_aes_keyexp_256_dec dlsym_aes_keyexp_256_dec;
static HMODULE aesmbHandle;
#endif

int aesmbLibraryLoaded = 0;
int aesmbAvailable = 0;

void initAesmbIDs(JNIEnv *env) {
  if (aesmbLibraryLoaded) {
    return;
  }

#ifdef UNIX
  aesmbHandle = dlopen(HADOOP_AESMB_LIBRARY, RTLD_LAZY | RTLD_GLOBAL);
#endif
#ifdef WINDOWS
  aesmbHandle = LoadLibrary(HADOOP_AESMB_LIBRARY);
#endif

  if (aesmbHandle) {
#ifdef UNIX
    dlerror(); // Clear any existing error
    LOAD_DYNAMIC_SYMBOL(dlsym_iDec128_CBC_by8, env, aesmbHandle, \
    "iDec128_CBC_by8");
    LOAD_DYNAMIC_SYMBOL(dlsym_iDec192_CBC_by8, env, aesmbHandle, \
    "iDec192_CBC_by8");
    LOAD_DYNAMIC_SYMBOL(dlsym_iDec256_CBC_by8, env, aesmbHandle, \
    "iDec256_CBC_by8");
    LOAD_DYNAMIC_SYMBOL(dlsym_aes_cbc_enc_128_x8, env, aesmbHandle, \
    "aes_cbc_enc_128_x8");
    LOAD_DYNAMIC_SYMBOL(dlsym_aes_cbc_enc_192_x8, env, aesmbHandle, \
    "aes_cbc_enc_192_x8");
    LOAD_DYNAMIC_SYMBOL(dlsym_aes_cbc_enc_256_x8, env, aesmbHandle, \
    "aes_cbc_enc_256_x8");
    LOAD_DYNAMIC_SYMBOL(dlsym_aes_keyexp_128_enc, env, aesmbHandle, \
    "aes_keyexp_128_enc");
    LOAD_DYNAMIC_SYMBOL(dlsym_aes_keyexp_192_enc, env, aesmbHandle, \
    "aes_keyexp_192_enc");
    LOAD_DYNAMIC_SYMBOL(dlsym_aes_keyexp_256_enc, env, aesmbHandle, \
    "aes_keyexp_256_enc");
    LOAD_DYNAMIC_SYMBOL(dlsym_aes_keyexp_128_dec, env, aesmbHandle, \
    "aes_keyexp_128_dec");
    LOAD_DYNAMIC_SYMBOL(dlsym_aes_keyexp_192_dec, env, aesmbHandle, \
    "aes_keyexp_192_dec");
    LOAD_DYNAMIC_SYMBOL(dlsym_aes_keyexp_256_dec, env, aesmbHandle, \
    "aes_keyexp_256_dec");
#endif
#ifdef WINDOWS
    LOAD_DYNAMIC_SYMBOL(__dlsym_iDec128_CBC_by8, dlsym_iDec128_CBC_by8, \
    env, aesmbHandle, "iDec128_CBC_by8");
    LOAD_DYNAMIC_SYMBOL(__dlsym_iDec192_CBC_by8, dlsym_iDec192_CBC_by8, \
    env, aesmbHandle, "iDec192_CBC_by8");
    LOAD_DYNAMIC_SYMBOL(__dlsym_iDec256_CBC_by8, dlsym_iDec256_CBC_by8, \
    env, aesmbHandle, "iDec256_CBC_by8");
    LOAD_DYNAMIC_SYMBOL(__dlsym_aes_cbc_enc_128_x8, dlsym_aes_cbc_enc_128_x8, \
    env, aesmbHandle, "aes_cbc_enc_128_x8");
    LOAD_DYNAMIC_SYMBOL(__dlsym_aes_cbc_enc_192_x8, dlsym_aes_cbc_enc_192_x8, \
    env, aesmbHandle, "aes_cbc_enc_192_x8");
    LOAD_DYNAMIC_SYMBOL(__dlsym_aes_cbc_enc_256_x8, dlsym_aes_cbc_enc_256_x8,  \
    env, aesmbHandle, "aes_cbc_enc_256_x8");
    LOAD_DYNAMIC_SYMBOL(__dlsym_aes_keyexp_128_enc, dlsym_aes_keyexp_128_enc, \
    env, aesmbHandle, "aes_keyexp_128_enc");
    LOAD_DYNAMIC_SYMBOL(__dlsym_aes_keyexp_192_enc, dlsym_aes_keyexp_192_enc, \
    env, aesmbHandle, "aes_keyexp_192_enc");
    LOAD_DYNAMIC_SYMBOL(__dlsym_aes_keyexp_256_enc, dlsym_aes_keyexp_256_enc, \
    env, aesmbHandle, "aes_keyexp_256_enc");
    LOAD_DYNAMIC_SYMBOL(__dlsym_aes_keyexp_128_dec, dlsym_aes_keyexp_128_dec, \
    env, aesmbHandle, "aes_keyexp_128_dec");
    LOAD_DYNAMIC_SYMBOL(__dlsym_aes_keyexp_192_dec, dlsym_aes_keyexp_192_dec, \
    env, aesmbHandle, "aes_keyexp_192_dec");
    LOAD_DYNAMIC_SYMBOL(__dlsym_aes_keyexp_256_dec, dlsym_aes_keyexp_256_dec, \
    env, aesmbHandle, "aes_keyexp_256_dec");
#endif
    aesmbAvailable = 1;
  }

  aesmbLibraryLoaded = 1;
}

static EncryptX8 encrypt(int keyLength)
{
  EncryptX8 result = NULL;

  if (!aesmbAvailable) {
    return NULL;
  }

  switch (keyLength) {
  case 16:
    result = dlsym_aes_cbc_enc_128_x8;
    break;
  case 24:
    result = dlsym_aes_cbc_enc_192_x8;
    break;
  case 32:
    result = dlsym_aes_cbc_enc_256_x8;
    break;
  default:
    result = NULL;
    break;
  }

  if (NULL == result) {
    DTRACE("invalid key length %d\n", keyLength);
  }

  return result;
}

static DecryptX1 decrypt(int keyLength)
{
  DecryptX1 result = NULL;

  if (!aesmbAvailable) {
    return NULL;
  }

  switch (keyLength) {
  case 16:
    result = dlsym_iDec128_CBC_by8;
    break;
  case 24:
    result = dlsym_iDec192_CBC_by8;
    break;
  case 32:
    result = dlsym_iDec256_CBC_by8;
    break;
  default:
    result = NULL;
    break;
  }

  if (NULL == result) {
    DTRACE("invalid key length %d\n", keyLength);
  }
  return result ;
}

// mode: 1 for encrypt, 0 for decrypt
static KeySched keyexp(int keyLength, int mode) {
  KeySched result = NULL;

  if (!aesmbAvailable) {
    return NULL;
  }

  switch (keyLength + mode) {
  case 16:
    result = dlsym_aes_keyexp_128_dec;
    break;
  case 24:
    result = dlsym_aes_keyexp_192_dec;
    break;
  case 32:
    result = dlsym_aes_keyexp_256_dec;
    break;
  case 16 + 1:
    result = dlsym_aes_keyexp_128_enc;
    break;
  case 24 + 1:
    result = dlsym_aes_keyexp_192_enc;
    break;
  case 32 + 1:
    result = dlsym_aes_keyexp_256_enc;
    break;
  default:
    result = NULL;
    break;
  }

  if (NULL == result) {
    DTRACE("invalid key length %d\n", keyLength);
  }
  return result ;
}

int aesni_supported() {
#ifdef UNIX
  int a, b, c, d;
  __cpuid(1, a, b, c, d);
  return (c >> 25) & 1;
#endif

#ifdef WINDOWS
  int cpuInfo[4], ecx;
  __cpuidex(cpuInfo, 1, 0);
  ecx = cpuInfo[2];
  return ecx >> 25 & 1;
#endif
}

int aesmb_keyexp(CipherContext* ctx) {
  KeySched keySchedFunc = NULL;

  if (NULL == ctx || NULL == ctx->aesmbCtx) {
    DTRACE("Invalid parameter: ctx or key or iv is NULL!");
    return -1;
  }

  // init encryption key expension
  keySchedFunc = keyexp(ctx->keyLength, 1);
  if (NULL == keySchedFunc) {
    DTRACE("Invalid parameter: key length(%d) is not supported", keyLength);
    return -2;
  }
  keySchedFunc(ctx->key, ctx->aesmbCtx->encryptKeysched);
  // init decryption key expension
  keySchedFunc = keyexp(ctx->keyLength, 0);
  if (NULL == keySchedFunc) {
    DTRACE("Invalid parameter: key length(%d) is not supported", keyLength);
    return -2;
  }
  keySchedFunc(ctx->key, ctx->aesmbCtx->decryptKeysched);

  return 0;
}

int aesmb_keyinit(CipherContext* ctx, uint8_t* key, int keyLength) {
  if (NULL == key || NULL == ctx) {
    return 0;
  }

  if (keyLength != ctx->keyLength) {
    free(ctx->key);
    ctx->keyLength = keyLength;
    ctx->key = (uint8_t*) malloc (keyLength * sizeof(uint8_t));

    ctx->aesmbCtx->efunc = encrypt(keyLength);
    ctx->aesmbCtx->dfunc = decrypt(keyLength);
  }

  memcpy(ctx->key, key, keyLength);

  if (NULL == ctx->aesmbCtx->efunc || NULL == ctx->aesmbCtx->dfunc) {
    DTRACE("Invalid parameter: key length(%d) is not supported", keyLength);
    return -3;
  }

  if (!aesni_supported()) {
    return -4;
  }

  return aesmb_keyexp(ctx);
}

int aesmb_ivinit(CipherContext* ctx, uint8_t* iv, int ivLength) {
  int i,j;

  if (NULL == iv || NULL == ctx) {
    return 0;
  }

  if (ivLength != ctx->ivLength) {
    free(ctx->iv);
    ctx->ivLength = ivLength;
    ctx->iv = (uint8_t*) malloc (ivLength * sizeof(uint8_t) * PARALLEL_LEVEL);
  }

  for (i = 0 ; i < PARALLEL_LEVEL ; i++) {
    memcpy(ctx->iv + i * ivLength, iv, ivLength);
    // generate seven different IVs
    for(j = 0; j < 16; j++){
      *(ctx->iv + i * ivLength + j) = *(ctx->iv + i * ivLength + j) + 1;
    }
  }

  return ivLength - BLOCKSIZE;
}

int aesmb_keyivinit(CipherContext* ctx, uint8_t* key, int keyLength, uint8_t* iv, int ivLength) {
  int result1, result2;
  result1 = aesmb_keyinit(ctx, key, keyLength);
  result2 = aesmb_ivinit(ctx, iv, ivLength);

  if (result1 || result2) {
    return -1;
  }

  return 0;
}

int aesmb_ctxinit(CipherContext* ctx,
              uint8_t* key,
              uint8_t  keyLength,
              uint8_t* iv,
              uint8_t  ivLength) {
  // Do not check handle, since key and iv will need to be stored in context,
  // even handle is NULL
  if (NULL == ctx || NULL == key || NULL == iv) {
    DTRACE("Invalid parameter: ctx or key or iv is NULL!");
    return -1;
  }

  if (ivLength != BLOCKSIZE) {
    DTRACE("Invalid parameter: iv length is not 128bit!");
    return -2;
  }

  return aesmb_keyivinit(ctx, key, keyLength, iv, ivLength);
}

int aesmb_streamlength(int inputLength) {
  int mbUnit, mbBlocks;
  mbUnit = PARALLEL_LEVEL * BLOCKSIZE;
  mbBlocks = inputLength / mbUnit;
  return BLOCKSIZE * mbBlocks;
}

int aesmb_encrypt(CipherContext* ctx,
              uint8_t* input,
              int inputLength,
              uint8_t* output,
              int* outputLength
              )
{
  int mbUnit, mbBlocks, mbTotal, i, step;
  sAesData_x8 data;
  uint8_t iv[PARALLEL_LEVEL * BLOCKSIZE];

  if (NULL == ctx || NULL == input || NULL == output || inputLength < 0 ) {
    DTRACE("Invalid parameter: ctx or input or output is NULL!");
    return -1;
  }

  mbUnit = PARALLEL_LEVEL * BLOCKSIZE;
  mbBlocks = inputLength / mbUnit;
  mbTotal = inputLength - inputLength % mbUnit;
  *outputLength = mbTotal;

  if (mbBlocks == 0) {
    return *outputLength;
  }

  data.keysched = ctx->aesmbCtx->encryptKeysched;
  data.numblocks = mbBlocks;

  memcpy(iv, ctx->iv, PARALLEL_LEVEL*BLOCKSIZE);

  for (i = 0; i < PARALLEL_LEVEL; i++) {
    step = i * BLOCKSIZE * mbBlocks;
    data.inbuf[i] = input + step;
    data.outbuf[i] = output + step;
    data.iv[i] = iv + i*BLOCKSIZE;
  }

  (ctx->aesmbCtx->efunc) (&data); // encrypt in parallel

  return *outputLength;
}

int aesmb_decrypt(CipherContext* ctx,
              uint8_t* input,
              int inputLength,
              uint8_t* output,
              int* outputLength
              )
{
  int mbUnit, mbBlocks, mbTotal, i, step;
  sAesData data;
  // init iv
  uint8_t iv[PARALLEL_LEVEL*BLOCKSIZE];
  if (NULL == ctx || NULL == input || NULL == output || inputLength < 0 ) {
    DTRACE("Invalid parameter: ctx or input or output is NULL!");
    return -1;
  }

  mbUnit = BLOCKSIZE * PARALLEL_LEVEL;
  mbBlocks = inputLength / mbUnit;
  mbTotal = inputLength - inputLength % mbUnit;
  *outputLength = mbTotal;

  if (mbBlocks == 0) {
    return *outputLength;
  }

  data.keysched = ctx->aesmbCtx->decryptKeysched;
  data.numblocks = mbBlocks;

  memcpy(iv, ctx->iv, PARALLEL_LEVEL*BLOCKSIZE);

  for (i =0; i < PARALLEL_LEVEL; i++) {
    step = i * BLOCKSIZE * mbBlocks;
    data.inbuf = input + step;
    data.outbuf = output + step;
    data.iv = iv + i*BLOCKSIZE;
    (ctx->aesmbCtx->dfunc)(&data); // decrypt by each stream
  }

  return *outputLength;
}

CipherContext* createCipherContextMB(signed char* key, int keylen, signed char* iv, int ivlen) {
  int result;

  CipherContext* ctx = (CipherContext*) malloc(sizeof(CipherContext));
  memset(ctx, 0, sizeof(CipherContext));

  ctx->opensslCtx = dlsym_EVP_CIPHER_CTX_new();

  ctx->aesmbCtx = (sAesContext*) malloc(sizeof(sAesContext));
  memset(ctx->aesmbCtx, 0, sizeof(sAesContext));

  // init iv and key
  result = aesmb_ctxinit(ctx, (uint8_t*)key, keylen, (uint8_t*)iv, ivlen);

  ctx->aesmbCtx->aesEnabled = aesni_supported() && result == 0;
  return ctx;
}

long init(JNIEnv* env, int forEncryption, signed char* nativeKey, int keyLength, signed char* nativeIv,
    int ivLength, int padding , long oldContext) {
  CipherContext* ctx = NULL;

  if (oldContext != NULL) {
    destroyCipherContext((CipherContext*)oldContext);
  }

  // init all context
  ctx = createCipherContextMB(nativeKey, keyLength, nativeIv, ivLength);
  // init openssl context, by using localized key & iv
  dlsym_EVP_CIPHER_CTX_init(ctx->opensslCtx);
  if (-1 == opensslResetContext(forEncryption, ctx->opensslCtx, ctx)) {
    destroyCipherContext(ctx);
    THROW(env, "java/lang/IllegalArgumentException", "unsupportted key size");
    return 0;
  }
  if (PADDING_NOPADDING == padding) {
    dlsym_EVP_CIPHER_CTX_set_padding(ctx->opensslCtx, 0);
  } else if (PADDING_PKCS5PADDING == padding){
    dlsym_EVP_CIPHER_CTX_set_padding(ctx->opensslCtx, 1);
  }
  return (long)ctx;
}

int opensslResetContext(int forEncryption, EVP_CIPHER_CTX* context, CipherContext* cipherContext) {
  return opensslResetContextMB(forEncryption, context, cipherContext, 0);
}

int opensslResetContextMB(int forEncryption, EVP_CIPHER_CTX* context,
    CipherContext* cipherContext, int count) {
  int keyLength;
  unsigned char* nativeKey, *nativeIv;
  EVP_CIPHER* cipher = NULL;

  keyLength = cipherContext->keyLength;
  nativeKey = (unsigned char*) cipherContext->key;
  nativeIv = (unsigned char*) cipherContext->iv + count * 16;

  cipher = getCipher(MODE_CBC, keyLength);
  if (cipher != NULL) {
    dlsym_EVP_CipherInit_ex(context, cipher, NULL,
        (unsigned char *) nativeKey, (unsigned char *) nativeIv, forEncryption);
    return 0;
  }
  return -1;
}

void reset(CipherContext* cipherContext, uint8_t* nativeKey, uint8_t* nativeIv) {
  EVP_CIPHER_CTX * ctx = NULL;
  // reinit openssl context by localized key&iv
  aesmb_keyivinit(cipherContext, nativeKey, cipherContext->keyLength, (uint8_t*)nativeIv, cipherContext->ivLength);

  ctx = (EVP_CIPHER_CTX *)(cipherContext->opensslCtx);
  opensslResetContext(ctx->encrypt, ctx, cipherContext);
}

int opensslEncrypt(EVP_CIPHER_CTX* ctx, unsigned char* output, int* outLength, unsigned char* input, int inLength) {
  int outLengthFinal;
  *outLength = 0;

  if(inLength && !dlsym_EVP_CipherUpdate(ctx, output, outLength, input, inLength)){
    printf("ERROR in EVP_EncryptUpdate \n");
    return -1;
  }

  if(!dlsym_EVP_CipherFinal_ex(ctx, output + *outLength, &outLengthFinal)){
    printf("ERROR in EVP_EncryptFinal_ex \n");
    return -1;
  }

  *outLength = *outLength + outLengthFinal;
  return 0;
}

int opensslDecrypt(EVP_CIPHER_CTX* ctx, unsigned char* output, int* outLength, unsigned char* input, int inLength) {
  int outLengthFinal;
  *outLength = 0;

  if(inLength && !dlsym_EVP_CipherUpdate(ctx, output, outLength, input, inLength)){
    printf("ERROR in EVP_DecryptUpdate\n");
    return -1;
  }

  if(!dlsym_EVP_CipherFinal_ex(ctx, output + *outLength, &outLengthFinal)){
    printf("ERROR in EVP_DecryptFinal_ex\n");
    return -1;
  }

  *outLength = *outLength + outLengthFinal;
  return 0;
}

int bufferCrypt(CipherContext* cipherContext, const char* input, int inputLength, char* output) {
  int aesEnabled, aesmbApplied, outLength, outLengthFinal, extraOutputLength, encrypted, padding, decrypted, step, i;
  EVP_CIPHER_CTX * ctx;
  unsigned char * header = NULL;
  sAesContext* aesCtx = NULL;

  ctx = (EVP_CIPHER_CTX *)cipherContext->opensslCtx;
  aesCtx = (sAesContext*) cipherContext->aesmbCtx;
  aesEnabled = aesCtx->aesEnabled;
  aesmbApplied = 0; // 0 for not applied

  outLength = 0;
  outLengthFinal = 0;

  extraOutputLength = 0;
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
      encrypted = aesmb_encrypt(cipherContext, input, inputLength, output, &outLength);
      if (encrypted < 0) {
      // reportError(env, "AES multi-buffer encryption failed.");
        return 0;
      }
      aesmbApplied = encrypted;
      input += encrypted;
      inputLength -=encrypted;
      output +=outLength; // rest of data will use openssl to perform encryption
    }

    // encrypt with padding
    dlsym_EVP_CIPHER_CTX_set_padding(ctx, 1);
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
      padding = (int) header[1];
      if (aesEnabled) {
        decrypted = aesmb_decrypt(cipherContext, input, inputLength - padding, output, &outLengthFinal);
        if (decrypted < 0) {
        // todo?
        // reportError(env, "Data can not be decrypted correctly");
          return 0;
        }

        input += outLengthFinal;
        inputLength -= outLengthFinal;
        output += outLengthFinal;
        outLength += outLengthFinal;
      } else {
        step = aesmb_streamlength(inputLength - padding);
        outLength = 0;
        for (i = 0; i < PARALLEL_LEVEL; i++) {
          //reset open ssl context
          opensslResetContextMB(ctx->encrypt, ctx, cipherContext, i);
          //clear padding, since multi-buffer AES did not have padding
          dlsym_EVP_CIPHER_CTX_set_padding(ctx, 0);
          //decrypt using open ssl
          opensslDecrypt(ctx, output, &outLengthFinal, input, step);

          input += step;
          inputLength -= step;
          output += outLengthFinal;
          outLength += outLengthFinal;
        }
      }
    }

    //reset open ssl context
    opensslResetContext(ctx->encrypt, ctx, cipherContext);
    //enable padding, the last buffer need padding
    dlsym_EVP_CIPHER_CTX_set_padding(ctx, 1);
    //decrypt using open ssl
    opensslDecrypt(ctx, output, &outLengthFinal, input, inputLength);
  }

  return outLength + outLengthFinal + extraOutputLength;
}
