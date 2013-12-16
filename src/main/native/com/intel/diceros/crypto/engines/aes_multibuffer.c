#include <openssl/evp.h>
#include <openssl/err.h>
#include "aes_multibuffer.h"
#include "aes_utils.h"
#include "aes_common.h"

int bufferCrypt(CipherContext* cipherContext, const char* input, int inputLength, char* output) {
  EVP_CIPHER_CTX * ctx = (EVP_CIPHER_CTX *)cipherContext->opensslCtx;
  sAesContext* aesCtx = (sAesContext*) cipherContext->aesmbCtx;
  int aesEnabled = cipherContext->aesEnabled;
  int aesmbApplied = 0; // 0 for not applied

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
    if (aesEnabled) {
      // try to apply multi-buffer optimization
      int encrypted = aesmb_encrypt(aesCtx, input, inputLength, output, &outLength);
      if (encrypted < 0) {
  //      reportError(env, "AES multi-buffer encryption failed.");
        return 0;
      }
      aesmbApplied = encrypted;
      input += encrypted;
      inputLength -=encrypted;
      output +=outLength; // rest of data will use openssl to perform encryption
    }

    // encrypt with padding
    EVP_CIPHER_CTX_set_padding(ctx, 1);
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
      int padding = (int)header[1] ;
      if (aesEnabled) {
        int decrypted = aesmb_decrypt(aesCtx, input, inputLength - padding, output, &outLengthFinal);
        if (decrypted < 0) {
        //   todo?
       //   reportError(env, "Data can not be decrypted correctly");
          return 0;
        }

        input += outLengthFinal;
        inputLength -= outLengthFinal;
        output += outLengthFinal;
        outLength += outLengthFinal;
      } else {
        int step = aesmb_streamlength(inputLength - padding) ;
        outLength = 0;
        int i;
        for (i = 0 ; i < PARALLEL_LEVEL; i++) {
          //reset open ssl context
          EVP_CIPHER_CTX_cleanup(ctx);
          opensslResetContextMB(ctx->encrypt, ctx, aesCtx,i);
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
    }

    EVP_CIPHER_CTX_cleanup(ctx);
    //reset open ssl context
    opensslResetContext(ctx->encrypt, ctx, aesCtx);
    //enable padding, the last buffer need padding
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    //decrypt using open ssl
    opensslDecrypt(ctx, output, &outLengthFinal, input, inputLength);
  }

  return outLength + outLengthFinal + extraOutputLength;
}