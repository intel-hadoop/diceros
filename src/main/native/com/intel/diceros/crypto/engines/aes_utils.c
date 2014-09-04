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
#include "config.h"
#include "aes_utils.h"

#ifdef UNIX
#include <dlfcn.h>
static void *openssl;
#endif

#ifdef WINDOWS
static HMODULE openssl;
#endif

int opensslLibraryLoaded = 0;

void destroyCipherContext(CipherContext* ctx) {
  dlsym_EVP_CIPHER_CTX_cleanup(ctx->opensslCtx);
  dlsym_EVP_CIPHER_CTX_free(ctx->opensslCtx);
  ctx->opensslCtx = NULL;
  free(ctx->key);
  ctx->key = NULL;
  free(ctx->iv);
  ctx->iv = NULL;

  // destroy AESMB context
  free(ctx->aesmbCtx);
  ctx->aesmbCtx = NULL;

  free(ctx);
}

static void loadAesCtr(JNIEnv *env) {
  jthrowable jthr;

#ifdef UNIX
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_256_ctr, env, openssl, "EVP_aes_256_ctr");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_192_ctr, env, openssl, "EVP_aes_192_ctr");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_128_ctr, env, openssl, "EVP_aes_128_ctr");
#endif

#ifdef WINDOWS
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_256_ctr, dlsym_EVP_aes_256_ctr,  \
                      env, openssl, "EVP_aes_256_ctr");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_192_ctr, dlsym_EVP_aes_192_ctr,  \
                      env, openssl, "EVP_aes_192_ctr");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_128_ctr, dlsym_EVP_aes_128_ctr,  \
                      env, openssl, "EVP_aes_128_ctr");
#endif

  jthr = (*env)->ExceptionOccurred(env);
  if (jthr) {
    (*env)->DeleteLocalRef(env, jthr);
    THROW(env, "java/lang/UnsatisfiedLinkError", \
    "Cannot find AES-CTR support, is your version of Openssl new enough?");
    return;
  }
}

static void loadAesCbc(JNIEnv *env) {
  jthrowable jthr;

#ifdef UNIX
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_256_cbc, env, openssl, "EVP_aes_256_cbc");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_192_cbc, env, openssl, "EVP_aes_192_cbc");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_128_cbc, env, openssl, "EVP_aes_128_cbc");
#endif

#ifdef WINDOWS
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_256_cbc, dlsym_EVP_aes_256_cbc,  \
                      env, openssl, "EVP_aes_256_cbc");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_192_cbc, dlsym_EVP_aes_192_cbc,  \
                      env, openssl, "EVP_aes_192_cbc");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_128_cbc, dlsym_EVP_aes_128_cbc,  \
                      env, openssl, "EVP_aes_128_cbc");
#endif

  jthr = (*env)->ExceptionOccurred(env);
  if (jthr) {
    (*env)->DeleteLocalRef(env, jthr);
    THROW(env, "java/lang/UnsatisfiedLinkError", \
    "Cannot find AES-CBC support, is your version of Openssl new enough?");
    return;
  }
}

static void loadAesXts(JNIEnv *env) {
  jthrowable jthr;

#ifdef UNIX
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_256_xts, env, openssl, "EVP_aes_256_xts");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_128_xts, env, openssl, "EVP_aes_128_xts");
#endif

#ifdef WINDOWS
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_256_xts, dlsym_EVP_aes_256_xts,  \
                      env, openssl, "EVP_aes_256_xts");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_128_xts, dlsym_EVP_aes_128_xts,  \
                      env, openssl, "EVP_aes_128_xts");
#endif

  jthr = (*env)->ExceptionOccurred(env);
  if (jthr) {
    (*env)->DeleteLocalRef(env, jthr);
    THROW(env, "java/lang/UnsatisfiedLinkError", \
    "Cannot find AES-XTS support, is your version of Openssl new enough?");
    return;
  }
}

static void loadAesGcm(JNIEnv *env) {
  jthrowable jthr;

#ifdef UNIX
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_256_gcm, env, openssl, "EVP_aes_256_gcm");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_192_gcm, env, openssl, "EVP_aes_192_gcm");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_aes_128_gcm, env, openssl, "EVP_aes_128_gcm");
#endif

#ifdef WINDOWS
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_256_gcm, dlsym_EVP_aes_256_gcm,  \
                      env, openssl, "EVP_aes_256_gcm");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_192_gcm, dlsym_EVP_aes_192_gcm,  \
                      env, openssl, "EVP_aes_192_gcm");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_aes_128_gcm, dlsym_EVP_aes_128_gcm,  \
                      env, openssl, "EVP_aes_128_gcm");
#endif

  jthr = (*env)->ExceptionOccurred(env);
  if (jthr) {
    (*env)->DeleteLocalRef(env, jthr);
    THROW(env, "java/lang/UnsatisfiedLinkError", \
    "Cannot find AES-GCM support, is your version of Openssl new enough?");
    return;
  }
}

void initOpensslIDs(JNIEnv *env) {
  char msg[200];

#ifdef WINDOWS
  wchar_t wmsg[400];
  int wmsgLen;
  char *cryptoPtr = msg;
#endif

  if (opensslLibraryLoaded) {
    return;
  }

#ifdef UNIX
  openssl = dlopen(HADOOP_CRYPTO_LIBRARY, RTLD_LAZY | RTLD_GLOBAL);
#endif
#ifdef WINDOWS
  snprintf(msg, sizeof(msg), "%s", HADOOP_CRYPTO_LIBRARY);
  wmsgLen = mbsrtowcs(wmsg, (const char**)&cryptoPtr, 400, NULL);
  wmsg[wmsgLen] = L'\0';
  openssl = LoadLibrary(wmsg);
#endif
  if (!openssl) {
    snprintf(msg, sizeof(msg), "Cannot load %s!", HADOOP_CRYPTO_LIBRARY);
    THROW(env, "java/lang/UnsatisfiedLinkError", msg);
    return;
  }
#ifdef UNIX
  dlerror(); // Clear any existing error
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_new, env, openssl, \
  "EVP_CIPHER_CTX_new");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_free, env, openssl, \
  "EVP_CIPHER_CTX_free");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_cleanup, env, openssl, \
  "EVP_CIPHER_CTX_cleanup");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_init, env, openssl, \
  "EVP_CIPHER_CTX_init");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_set_padding, env, openssl, \
  "EVP_CIPHER_CTX_set_padding");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CIPHER_CTX_ctrl, env, openssl, \
  "EVP_CIPHER_CTX_ctrl");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CipherInit_ex, env, openssl, \
  "EVP_CipherInit_ex");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CipherUpdate, env, openssl, \
  "EVP_CipherUpdate");
  LOAD_DYNAMIC_SYMBOL(dlsym_EVP_CipherFinal_ex, env, openssl, \
  "EVP_CipherFinal_ex");
#endif
#ifdef WINDOWS
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CIPHER_CTX_new, dlsym_EVP_CIPHER_CTX_new, \
  env, openssl, "EVP_CIPHER_CTX_new");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CIPHER_CTX_free, dlsym_EVP_CIPHER_CTX_free, \
  env, openssl, "EVP_CIPHER_CTX_free");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CIPHER_CTX_cleanup, \
  dlsym_EVP_CIPHER_CTX_cleanup, env,
  openssl, "EVP_CIPHER_CTX_cleanup");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CIPHER_CTX_init, dlsym_EVP_CIPHER_CTX_init, \
  env, openssl, "EVP_CIPHER_CTX_init");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CIPHER_CTX_set_padding, \
  dlsym_EVP_CIPHER_CTX_set_padding, env, \
  openssl, "EVP_CIPHER_CTX_set_padding");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CIPHER_CTX_ctrl, dlsym_EVP_CIPHER_CTX_ctrl,  \
  env, openssl, "EVP_CIPHER_CTX_ctrl");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CipherInit_ex, dlsym_EVP_CipherInit_ex, \
  env, openssl, "EVP_CipherInit_ex");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CipherUpdate, dlsym_EVP_CipherUpdate, \
  env, openssl, "EVP_CipherUpdate");
  LOAD_DYNAMIC_SYMBOL(__dlsym_EVP_CipherFinal_ex, dlsym_EVP_CipherFinal_ex, \
  env, openssl, "EVP_CipherFinal_ex");
#endif
  loadAesCtr(env);
  loadAesCbc(env);
  loadAesXts(env);
  loadAesGcm(env);
  opensslLibraryLoaded = 1;
}

EVP_CIPHER* getCipher(int mode, int keyLen) {
  if (mode == MODE_CTR) {
    switch (keyLen) {
    case 16:
      return dlsym_EVP_aes_128_ctr();
    case 24:
      return dlsym_EVP_aes_192_ctr();
    case 32:
      return dlsym_EVP_aes_256_ctr();
    default:
      return NULL;
    }
  } else if (mode == MODE_CBC) {
    switch (keyLen) {
    case 16:
      return dlsym_EVP_aes_128_cbc();
    case 24:
      return dlsym_EVP_aes_192_cbc();
    case 32:
      return dlsym_EVP_aes_256_cbc();
    default:
      return NULL;
    }
  } else if (mode == MODE_XTS) {
    switch (keyLen) {
    case 32:
      return dlsym_EVP_aes_128_xts();
    case 64:
      return dlsym_EVP_aes_256_xts();
    default:
      return NULL;
    }
  } else if (mode == MODE_GCM) {
    switch (keyLen) {
    case 16:
      return dlsym_EVP_aes_128_gcm();
    case 24:
      return dlsym_EVP_aes_192_gcm();
    case 32:
      return dlsym_EVP_aes_256_gcm();
    default:
      return NULL;
    }
  }
  return NULL;
}
