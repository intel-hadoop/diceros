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
#include <stdlib.h>
#include "config.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include "com_intel_diceros.h"
#include "com_intel_diceros_crypto_engines_AESMutliBufferEngine.h"
#include "aes_utils.h"
#include "aes_common.h"
#include "aes_multibuffer.h"


//-------- begin dlerror handling functions -----
void traceDLError(const char* libname)
{
  DTRACE("Can not load library [%s]: <%s>\n", libname, dlerror());
}

void throwDLError(JNIEnv* env, const char* lib)
{
  char msg[1000];
  snprintf(msg, 1000, "Cannot load %s (%s)!", lib, dlerror());
  THROW(env, "java/lang/UnsatisfiedLinkError", msg);
}
//-------- end dlerror handling functions -----

int opensslEncrypt(EVP_CIPHER_CTX* ctx, unsigned char* output, int* outLength, unsigned char* input, int inLength)
{
  int outLengthFinal;
  *outLength = 0;
  
  if(inLength && !EVP_EncryptUpdate(ctx, output, outLength, input, inLength)){
    printf("ERROR in EVP_EncryptUpdate \n");
    ERR_print_errors_fp(stderr);
    return 0;
  }
  
  /* update ciphertext with the final remaining bytes */
  if(!EVP_EncryptFinal_ex(ctx, output + *outLength, &outLengthFinal)){
    printf("ERROR in EVP_EncryptFinal_ex \n");
    ERR_print_errors_fp(stderr);
    return 0;
  }

  *outLength = *outLength + outLengthFinal;
  
  return 1;
}

void reportError(JNIEnv* env, char* msg)
{
  THROW(env, "java/security/GeneralSecurityException", msg);
}

/*
 * Class:     sec_util_OpenSSLCrypto
 * mode: 0, ENCRYPTION, 1: DECRYPTION
 * return: context Id
 * Method:    init
 */
JNIEXPORT jlong JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_init
(JNIEnv * env, jobject object, jboolean forEncryption, jbyteArray key, jbyteArray iv,  jint padding , jlong oldContext) {
  // init overall struction, for memory allocation
  int keyLength = (*env)->GetArrayLength(env, key);
  int ivLength = (*env)->GetArrayLength(env, iv);

  // localize key and iv
  jbyte nativeKey[32];
  jbyte nativeIv[32];
  (*env)->GetByteArrayRegion(env, key, 0, keyLength, nativeKey);
  (*env)->GetByteArrayRegion(env, iv, 0, ivLength, nativeIv);

  int loadLibraryResult = 0;
  long ctx = init(forEncryption, nativeKey, keyLength, nativeIv, ivLength, padding , oldContext, &loadLibraryResult);
  if (loadLibraryResult == -1) {
     throwDLError(env, HADOOP_CRYPTO_LIBRARY);
     return 0;
  }  else if (loadLibraryResult == -2) {
     traceDLError(HADOOP_AESMB_LIBRARY);
  }

  return ctx;
}

JNIEXPORT void JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_reset
(JNIEnv * env, jobject object, jlong context, jbyteArray key, jbyteArray iv) {
  CipherContext* cipherContext = (CipherContext*)context;

  jbyte * nativeKey = NULL;
  jbyte * nativeIv = NULL;

  // localize key
  if (NULL != key) {
    //int keyLength = (*env)->GetArrayLength(env, key);
    //(*env)->GetByteArrayRegion(env, key, 0, keyLength, nativeKey);
    nativeKey = (*env)->GetByteArrayElements(env, key, NULL);
  }

  // localize iv
  if (NULL != iv) {
    //int ivLength = (*env)->GetArrayLength(env, iv);
    //(*env)->GetByteArrayRegion(env, iv, 0, ivLength, nativeIv);
    nativeIv = (*env)->GetByteArrayElements(env, iv, NULL);
  }

  reset(cipherContext, nativeKey, nativeIv);

  // unlock gc
  if (NULL != key) {
    (*env)->ReleaseByteArrayElements(env, key, nativeKey, 0);
  }

  if (NULL != iv) {
    (*env)->ReleaseByteArrayElements(env, iv, nativeIv, 0);
  }
}

/*
 * Class:     com_intel_diceros_crypto_engines_AESMutliBufferEngine
 * Method:    doFinal
 */
JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_bufferCrypt
(JNIEnv * env, jobject object, jlong context, jobject inputDirectBuffer, jint start, jint inputLength, jobject outputDirectBuffer, jint begin, jboolean isUpdate) {
  unsigned char * input = (unsigned char *)(*env)->GetDirectBufferAddress(env, inputDirectBuffer) + start;
  unsigned char * output = (unsigned char *)(*env)->GetDirectBufferAddress(env, outputDirectBuffer) + begin;

  CipherContext* cipherContext = (CipherContext*) context;
  int encrypt_length = bufferCrypt(cipherContext, input, inputLength, output);
  Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_reset(env, object, context, NULL, NULL);
  return encrypt_length;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_getBlockSize(
    JNIEnv *env, jobject object, jlong context) {
  return 16;
}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_doFinalArray(
    JNIEnv *env, jobject object, jlong context, jbyteArray in, jint inOff,
    jint inputLength, jbyteArray out, jint outOff) {

  unsigned char * inputTmp = (unsigned char *) (*env)->GetByteArrayElements(env, in, 0);
  unsigned char * outputTmp = (unsigned char *) (*env)->GetByteArrayElements(env, out, 0);
  unsigned char * input = inputTmp;
  unsigned char * output = outputTmp;


  CipherContext* cipherContext = (CipherContext*) context;
  int encrypt_length = bufferCrypt(cipherContext, input, inputLength, output);

  (*env)->ReleaseByteArrayElements(env, in, (jbyte *) inputTmp, JNI_COMMIT);
  (*env)->ReleaseByteArrayElements(env, out, (jbyte *) outputTmp, JNI_COMMIT);

  Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_reset(env, object, context, NULL, NULL);
  return encrypt_length;

}

JNIEXPORT jint JNICALL Java_com_intel_diceros_crypto_engines_AESMutliBufferEngine_doFinal(
          JNIEnv *env, jobject object, jlong context, jbyteArray out, jint outOff) {
  return 0;
}

void logDeContext(char *input,char *iv, char *key,char *encry)
{
	FILE *fp;
	fp=fopen("/ramcache/de.txt", "w+");
    if(fp==NULL)
       puts("File open error");
    fputs("log ",fp);
    fputc(':\n', fp);

    fprintf(fp, "input \n");
    printlog(fp,input,1,531);

    fprintf(fp, "iv \n");
    printlog(fp,iv,1,17);

    fprintf(fp, "key \n");
    printlog(fp,key,1,17);

    fprintf(fp, "encry \n");
    printlog(fp,encry,1,513);

    if(fclose(fp)==0)
      ;//printf("O.K\n");
    else
      puts("File close error\n");
}

void logEnContext(char *input,char *iv, char *key,char *encry)
{
	FILE *fp;
	fp=fopen("/ramcache/en.txt", "w+");
    if(fp==NULL)
       puts("File open error");
    fputs("log ",fp);
    fputc(':\n', fp);

    fprintf(fp, "input \n");
    printlog(fp,input,1,513);

    fprintf(fp, "iv \n");
    printlog(fp,iv,1,17);

    fprintf(fp, "key \n");
    printlog(fp,key,1,17);

    fprintf(fp, "encry \n");
    printlog(fp,encry,1,531);

    if(fclose(fp)==0)
      ;//printf("O.K\n");
    else
      puts("File close error\n");
}

void printlog(FILE *fp,char *s,int size,int length){
	int i=0;
	for(i=0;i<length/size;i++){
		fprintf(fp, "%d ", *(s+i*size));
	}
	fprintf(fp,"\n");
}