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
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "aes_multibuffer.h"
#include "config.h"

void cleanDLError() {
  dlerror();
}

void destroyCipherContext(CipherContext* ctx) {
  aesmb_ctxdest(ctx);
  EVP_CIPHER_CTX_cleanup(ctx->opensslCtx);
  free(ctx->opensslCtx);
  free(ctx);
}

CipherContext* createCipherContext(signed char* key, int keylen, signed char* iv, int ivlen) {
  CipherContext* ctx = (CipherContext*) malloc (sizeof(CipherContext));
  memset(ctx, 0, sizeof(CipherContext));

  ctx->opensslCtx = (EVP_CIPHER_CTX*) malloc (sizeof(EVP_CIPHER_CTX));
  // init iv and key
  int result = aesmb_ctxinit(ctx, (uint8_t*)key, keylen, (uint8_t*)iv, ivlen);

  return ctx;
}

long init(int forEncryption, signed char* nativeKey, int keyLength, signed char* nativeIv,
    int ivLength, int padding , long oldContext, int* loadLibraryResult) {
  // Load libcrypto.so, if error, throw java exception
  if (!loadLibrary(HADOOP_CRYPTO_LIBRARY)) {
    *loadLibraryResult = -1;
    return 0;
  }

  // cleanup error
  cleanDLError();

  if (oldContext != NULL) {
    destroyCipherContext((CipherContext*)oldContext);
  }

  // init all context
  CipherContext* ctx = createCipherContext(nativeKey, keyLength, nativeIv, ivLength);
  // init openssl context, by using localized key & iv
  EVP_CIPHER_CTX_init(ctx->opensslCtx);
  opensslResetContext(forEncryption, ctx->opensslCtx, ctx);
  if (PADDING_NOPADDING == padding) {
    EVP_CIPHER_CTX_set_padding(ctx->opensslCtx, 0);
  } else if (PADDING_PKCS5PADDING == padding){
    EVP_CIPHER_CTX_set_padding(ctx->opensslCtx, 1);
  }
  return (long)ctx;
}

void opensslResetContext(int forEncryption, EVP_CIPHER_CTX* context, CipherContext* cipherContext) {
  opensslResetContextMB(forEncryption, context, cipherContext, 0);
}

void opensslResetContextMB(int forEncryption, EVP_CIPHER_CTX* context,
    CipherContext* cipherContext, int count) {
  int keyLength = cipherContext->keyLength;
  unsigned char* nativeKey = (unsigned char*) cipherContext->key;
  unsigned char* nativeIv = (unsigned char*) cipherContext->iv + count * 16;

  cryptInit cryptInitFunc = getCryptInitFunc(forEncryption);
  if (keyLength == 32) {
    cryptInitFunc(context, EVP_aes_256_cbc(), NULL,
        (unsigned char *) nativeKey, (unsigned char *) nativeIv);
  } else if (keyLength == 16) {
    cryptInitFunc(context, EVP_aes_128_cbc(), NULL,
        (unsigned char *) nativeKey, (unsigned char *) nativeIv);
  }
}

void reset(CipherContext* cipherContext, uint8_t* nativeKey, uint8_t* nativeIv) {
    // reinit openssl context by localized key&iv
    aesmb_keyivinit(cipherContext, nativeKey, cipherContext->keyLength, (uint8_t*)nativeIv, cipherContext->ivLength);

    EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *)(cipherContext->opensslCtx);
    opensslResetContext(ctx->encrypt, ctx, cipherContext);
}

int opensslEncrypt(EVP_CIPHER_CTX* ctx, unsigned char* output, int* outLength, unsigned char* input, int inLength) {
  int outLengthFinal;
  *outLength = 0;

  if(inLength && !EVP_EncryptUpdate(ctx, output, outLength, input, inLength)){
    printf("ERROR in EVP_EncryptUpdate \n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if(!EVP_EncryptFinal_ex(ctx, output + *outLength, &outLengthFinal)){
    printf("ERROR in EVP_EncryptFinal_ex \n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  *outLength = *outLength + outLengthFinal;
  return 0;
}

int opensslDecrypt(EVP_CIPHER_CTX* ctx, unsigned char* output, int* outLength, unsigned char* input, int inLength) {
  int outLengthFinal;
  *outLength = 0;

  if(inLength && !EVP_DecryptUpdate(ctx, output, outLength, input, inLength)){
    printf("ERROR in EVP_DecryptUpdate\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if(!EVP_DecryptFinal_ex(ctx, output + *outLength, &outLengthFinal)){
    printf("ERROR in EVP_DecryptFinal_ex\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  *outLength = *outLength + outLengthFinal;
  return 0;
}

int bufferCrypt(CipherContext* cipherContext, const char* input, int inputLength, char* output) {
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *)cipherContext->opensslCtx;

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
    // encrypt with padding
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    // encrypt the rest
    opensslEncrypt(ctx, output, &outLengthFinal, input, inputLength);

    header[0] = 0;
    header[1] = 0;
  } else {
    // read custom header
    if (header[0]) {
      int padding = (int) header[1];
      int step = aesmb_streamlength(inputLength - padding);
      outLength = 0;
      int i;
      for (i = 0; i < PARALLEL_LEVEL; i++) {
        //reset open ssl context
        opensslResetContextMB(ctx->encrypt, ctx, cipherContext, i);
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

    //reset open ssl context
    opensslResetContext(ctx->encrypt, ctx, cipherContext);
    //enable padding, the last buffer need padding
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    //decrypt using open ssl
    opensslDecrypt(ctx, output, &outLengthFinal, input, inputLength);
  }

  return outLength + outLengthFinal + extraOutputLength;
}
