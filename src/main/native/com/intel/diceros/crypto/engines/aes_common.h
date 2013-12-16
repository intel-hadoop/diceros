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
#ifndef AES_COMMON_H
#define AES_COMMON_H

#include <openssl/evp.h>

#define ENCRYPTION 1
#define DECRYPTION 0

#define MODE_CTR 0
#define MODE_CBC 1

#define PADDING_NOPADDING 0
#define PADDING_PKCS5PADDING 1

typedef int (*cryptInit)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
		const unsigned char *, const unsigned char *);
typedef int (*cryptUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *,
		const unsigned char *, int);
typedef int (*cryptFinal)(EVP_CIPHER_CTX*, unsigned char *, int *);

cryptInit getCryptInitFunc(int forEncryption);

cryptUpdate getCryptUpdateFunc(int forEncryption);

cryptFinal getCryptFinalFunc(int forEncryption);

#endif