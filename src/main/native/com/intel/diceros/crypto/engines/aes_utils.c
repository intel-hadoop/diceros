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
#include <dlfcn.h>
#include <cpuid.h>
#include "aes_utils.h"

#define BLOCKSIZE 16

void* loadLibrary(const char * libname)
{
  void *handle = dlopen(libname, RTLD_LAZY | RTLD_GLOBAL);

  return handle;
}

static EncryptX8 encrypt(void* handle, int keyLength)
{
  if (NULL == handle) {
    return NULL;
  }
  
  static EncryptX8 X8128 = NULL;
  static EncryptX8 X8192 = NULL;
  static EncryptX8 X8256 = NULL;
  
  EncryptX8 result = NULL;
  char* funcName = NULL;
  
  switch (keyLength) {
  case 16:
    funcName = "aes_cbc_enc_128_x8";
    if (NULL == X8128) {
      X8128 = dlsym(handle, funcName);
    }
    result = X8128;
    break;
  case 24:
    funcName = "aes_cbc_enc_192_x8";
    if (NULL == X8192) {
      X8192 = dlsym(handle, funcName);
    }
    result = X8192;
    break;
  case 32:
    funcName = "aes_cbc_enc_256_x8";
    if (NULL == X8256) {
      X8256 = dlsym(handle, funcName);
    }
    result = X8256;
    break;
  default:
    result = NULL;
    break;
  }

  if (NULL == result) {
    DTRACE("invalid key length %d or symbol %s\n", keyLength, funcName);
  }
  
  return result;
}

static DecryptX1 decrypt(void* handle, int keyLength)
{
  if (NULL == handle) {
    return NULL;
  }
  
  static DecryptX1 X1128 = NULL;
  static DecryptX1 X1192 = NULL;
  static DecryptX1 X1256 = NULL;
  

  DecryptX1 result = NULL;
  char* funcName = NULL;
  
  switch (keyLength) {
  case 16:
    funcName = "iDec128_CBC_by8";
    if (NULL == X1128) {
      X1128 = dlsym(handle, funcName);
    }
    result = X1128;
    break;
  case 24:
    funcName = "iDec192_CBC_by8";
    if (NULL == X1192) {
      X1192 = dlsym(handle, funcName);
    }
    result = X1192;
    break;
  case 32:
    funcName = "iDec256_CBC_by8";
    if (NULL == X1256) {
      X1256 = dlsym(handle, funcName);
    }
    result = X1256;
    break;
  default:
    result = NULL;
    break;
  }
  
  if (NULL == result) {
    DTRACE("invalid key length %d or symbol %s\n", keyLength, funcName);
  }
  return result ;
}


// mode: 1 for encrypt, 0 for decrypt
static KeySched keyexp(void* handle, int keyLength, int mode)
{
  if (NULL == handle) {
    return NULL;
  }
  
  static KeySched EncKeyExp128 = NULL;
  static KeySched EncKeyExp192 = NULL;
  static KeySched EncKeyExp256 = NULL;

  static KeySched DecKeyExp128 = NULL;
  static KeySched DecKeyExp192 = NULL;
  static KeySched DecKeyExp256 = NULL;
  

  KeySched result = NULL;
  char* funcName = NULL;
  
  switch (keyLength + mode) {
  case 16:
    funcName = "aes_keyexp_128_dec";
    if (NULL == DecKeyExp128) {
      DecKeyExp128 = dlsym(handle, funcName);
    }
    result = DecKeyExp128;
    break;
  case 24:
    funcName = "aes_keyexp_192_dec";
    if (NULL == DecKeyExp192) {
      DecKeyExp192 = dlsym(handle, funcName);
    }
    result = DecKeyExp192;
    break;
  case 32:
    funcName = "aes_keyexp_256_dec";
    if (NULL == DecKeyExp256) {
      DecKeyExp256 = dlsym(handle, funcName);
    }
    result = DecKeyExp256;
    break;
  case 16 + 1:
    funcName = "aes_keyexp_128_enc";
    if (NULL == EncKeyExp128) {
      EncKeyExp128 = dlsym(handle, funcName);
    }
    result = EncKeyExp128;
    break;
  case 24 + 1:
    funcName = "aes_keyexp_192_enc";
    if (NULL == EncKeyExp192) {
      EncKeyExp192 = dlsym(handle, funcName);
    }
    result = EncKeyExp192;
    break;
  case 32 + 1:
    funcName = "aes_keyexp_256_enc";
    if (NULL == EncKeyExp256) {
      EncKeyExp256 = dlsym(handle, funcName);
    }
    result = EncKeyExp256;
    break;
  default:
    result = NULL;
    break;
  }
  
  if (NULL == result) {
    DTRACE("invalid key length %d or symbol %s\n", keyLength, funcName);
  }
  return result ;
}

int
aesni_supported()
{
  int a, b, c, d;
  __cpuid(1, a, b, c, d);

  return (c >> 25) & 1;
}

int
aesmb_keyexp(sAesContext* ctx)
{
  if (NULL == ctx || NULL == ctx->handle) {
    DTRACE("Invalid parameter: ctx or key or iv is NULL!");
    return -1;
  }

  void* handle = ctx->handle;
  
  KeySched keySchedFunc = NULL;
  // init encryption key expension
  keySchedFunc = keyexp(handle, ctx->keyLength, 1);
  if (NULL == keySchedFunc) {
    DTRACE("Invalid parameter: key length(%d) is not supported", keyLength);
    return -2;
  }
  keySchedFunc(ctx->key, ctx->encryptKeysched);
  //logContext(ctx->encryptKeysched);
  // init decryption key expension
  keySchedFunc = keyexp(handle, ctx->keyLength, 0);
  if (NULL == keySchedFunc) {
    DTRACE("Invalid parameter: key length(%d) is not supported", keyLength);
    return -2;
  }
  keySchedFunc(ctx->key, ctx->decryptKeysched);

  return 0;
}


int aesmb_keyinit(sAesContext* ctx, uint8_t* key, int keyLength)
{
  if (NULL == key || NULL == ctx) {
    return 0;
  }
  
  if (keyLength != ctx->keyLength) {
    free(ctx->key);
    ctx->keyLength = keyLength;
    ctx->key = (uint8_t*) malloc (keyLength * sizeof(uint8_t));

    ctx->efunc = encrypt(ctx->handle,keyLength);
    ctx->dfunc = decrypt(ctx->handle,keyLength);
  }

  memcpy(ctx->key, key, keyLength);

  if (NULL == ctx->efunc || NULL == ctx->dfunc) {
    DTRACE("Invalid parameter: key length(%d) is not supported", keyLength);
    return -3;
  }
  
  if (!aesni_supported()) {
    return -4;
  } 
  
  return aesmb_keyexp(ctx);
}

int aesmb_ivinit(sAesContext* ctx, uint8_t* iv, int ivLength)
{
  if (NULL == iv || NULL == ctx) {
    return 0;
  }
  
  if (ivLength != ctx->ivLength) {
    free(ctx->iv);
    ctx->ivLength = ivLength;
    ctx->iv = (uint8_t*) malloc (ivLength * sizeof(uint8_t) * PARALLEL_LEVEL);
  }

  int i,j = 0;
  for (i = 0 ; i < PARALLEL_LEVEL ; i++) {
    memcpy(ctx->iv + i * ivLength, iv, ivLength);
    // generate seven different IVs
    for(j=0 ;j <16 ;j++){
      *(iv+j) = *(iv+j) +1 ;
    }
  }

  return ivLength - BLOCKSIZE;
}

int aesmb_keyivinit(sAesContext* ctx, uint8_t* key, int keyLength, uint8_t* iv, int ivLength)
{
  int result1 = aesmb_keyinit(ctx, key, keyLength);
  int result2 = aesmb_ivinit(ctx, iv, ivLength);
  
  if (result1 || result2) {
    return -1;
  } 

  return 0;
}

int
aesmb_ctxinit(sAesContext* ctx,
              void* handle,
              uint8_t* key,
              uint8_t  keyLength,
              uint8_t* iv,
              uint8_t  ivLength
              )
{
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
  
  // init members
  ctx->handle = handle;
  return aesmb_keyivinit(ctx, key, keyLength, iv, ivLength);
}

sAesContext* aesmb_ctxcreate()
{
  sAesContext* ctx = (sAesContext*) malloc (sizeof(sAesContext));
  memset(ctx, 0, sizeof(sAesContext));

  return ctx;
}

void aesmb_ctxdest(sAesContext* ctx)
{
  free(ctx->key);
  free(ctx->iv);
  free(ctx);
}

int aesmb_streamlength(int inputLength)
{
  int mbUnit = PARALLEL_LEVEL * BLOCKSIZE;
  int mbBlocks = inputLength / mbUnit;

  return BLOCKSIZE * mbBlocks;
}

int
aesmb_encrypt(sAesContext* ctx,
              uint8_t* input,
              int inputLength,
              uint8_t* output,
              int* outputLength
              )
{
  if (NULL == ctx || NULL == input || NULL == output || inputLength < 0 ) {
    DTRACE("Invalid parameter: ctx or input or output is NULL!");
    return -1;
  }

  int mbUnit = PARALLEL_LEVEL * BLOCKSIZE;
  int mbBlocks = inputLength / mbUnit;
  int mbTotal = inputLength - inputLength % mbUnit;    
  *outputLength = mbTotal;

  if (mbBlocks == 0) {
    return *outputLength;
  }
  
  sAesData_x8 data;
  data.keysched = ctx->encryptKeysched;
  data.numblocks = mbBlocks;

  // init iv
  uint8_t iv[PARALLEL_LEVEL*BLOCKSIZE];
  memcpy(iv, ctx->iv, PARALLEL_LEVEL*BLOCKSIZE);

  int i;
  for (i =0; i < PARALLEL_LEVEL; i++) {
    int step = i * BLOCKSIZE * mbBlocks;
    data.inbuf[i] = input + step;
    data.outbuf[i] = output + step;
    data.iv[i] = iv + i*BLOCKSIZE;
  }

  (ctx->efunc) (&data); // encrypt in parallel

  return *outputLength;
}

int
aesmb_decrypt(sAesContext* ctx,
              uint8_t* input,
              int inputLength,
              uint8_t* output,
              int* outputLength
              )
{
  if (NULL == ctx || NULL == input || NULL == output || inputLength < 0 ) {
    DTRACE("Invalid parameter: ctx or input or output is NULL!");
    return -1;
  }

  int mbUnit = BLOCKSIZE * PARALLEL_LEVEL;
  int mbBlocks = inputLength / mbUnit;
  int mbTotal = inputLength - inputLength % mbUnit;    
  *outputLength = mbTotal;

  if (mbBlocks == 0) {
    return *outputLength;
  }
  
  sAesData data;
  data.keysched = ctx->decryptKeysched;
  data.numblocks = mbBlocks;

  // init iv
  uint8_t iv[PARALLEL_LEVEL*BLOCKSIZE];
  memcpy(iv, ctx->iv, PARALLEL_LEVEL*BLOCKSIZE);

  int i;
  for (i =0; i < PARALLEL_LEVEL; i++) {
    int step = i * BLOCKSIZE * mbBlocks;
    data.inbuf = input + step;
    data.outbuf = output + step;
    data.iv = iv + i*BLOCKSIZE;
    (ctx->dfunc)(&data); // decrypt by each stream
  }

  return *outputLength;
}


void logContext(char *key)
{
	FILE *fp;
	fp=fopen("/ramcache/keycache.txt", "w+");
    if(fp==NULL)
       puts("File open error");
    fputs("log ",fp);
    fputc(':\n', fp);

    //fprintf(fp, "input \n");
    //printlog(fp,input,1,513);

    fprintf(fp, "keycache \n");
    printlog(fp,key,1,241);

    if(fclose(fp)==0)
      ;//printf("O.K\n");
    else
      puts("File close error\n");
}

