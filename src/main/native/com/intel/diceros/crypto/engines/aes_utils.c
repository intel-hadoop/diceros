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
#include "aes_utils.h"

#define BLOCKSIZE 16

void* loadLibrary(const char * libname) {
  void *handle = dlopen(libname, RTLD_LAZY | RTLD_GLOBAL);
  return handle;
}

int aesmb_keyinit(CipherContext* ctx, uint8_t* key, int keyLength) {
  if (NULL == key || NULL == ctx) {
    return 0;
  }
  
  if (keyLength != ctx->keyLength) {
    free(ctx->key);
    ctx->keyLength = keyLength;
    ctx->key = (uint8_t*) malloc (keyLength * sizeof(uint8_t));
  }

  memcpy(ctx->key, key, keyLength);
  return 0;
}

int aesmb_ivinit(CipherContext* ctx, uint8_t* iv, int ivLength) {
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
      *(ctx->iv + i * ivLength + j) = *(ctx->iv + i * ivLength + j) +1;
    }
  }

  return ivLength - BLOCKSIZE;
}

int aesmb_keyivinit(CipherContext* ctx, uint8_t* key, int keyLength, uint8_t* iv, int ivLength) {
  int result1 = aesmb_keyinit(ctx, key, keyLength);
  int result2 = aesmb_ivinit(ctx, iv, ivLength);
  
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

void aesmb_ctxdest(CipherContext* ctx) {
  free(ctx->key);
  ctx->key = NULL;
  free(ctx->iv);
  ctx->iv = NULL;
}

int aesmb_streamlength(int inputLength) {
  int mbUnit = PARALLEL_LEVEL * BLOCKSIZE;
  int mbBlocks = inputLength / mbUnit;
  return BLOCKSIZE * mbBlocks;
}

cryptInit getCryptInitFunc(int forEncryption) {
  if (forEncryption == 1) {
    return EVP_EncryptInit_ex;
  } else {
    return EVP_DecryptInit_ex;
  }
}

cryptUpdate getCryptUpdateFunc(int forEncryption) {
  if (forEncryption == 1) {
    return EVP_EncryptUpdate;
  } else {
    return EVP_DecryptUpdate;
  }
}

cryptFinal getCryptFinalFunc(int forEncryption) {
  if (forEncryption == 1) {
    return EVP_EncryptFinal_ex;
  } else {
    return EVP_DecryptFinal_ex;
  }
}
