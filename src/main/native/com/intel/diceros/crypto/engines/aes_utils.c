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

void* loadLibrary(const char * libname) {
  void *handle = dlopen(libname, RTLD_LAZY | RTLD_GLOBAL);
  return handle;
}

void destroyCipherContext(CipherContext* ctx) {
  EVP_CIPHER_CTX_cleanup(ctx->opensslCtx);
  free(ctx->opensslCtx);
  ctx->opensslCtx = NULL;
  free(ctx->key);
  ctx->key = NULL;
  free(ctx->iv);
  ctx->iv = NULL;
  free(ctx);
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
