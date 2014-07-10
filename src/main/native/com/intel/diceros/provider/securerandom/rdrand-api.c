#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "rdrand-api.h"

static pthread_mutex_t *lockarray = NULL;

static void lock_callback(int mode, int type, char *file, int line) {
  (void)file;
  (void)line;
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lockarray[type]));
  } else {
    pthread_mutex_unlock(&(lockarray[type]));
  }
}

static unsigned long thread_id(void) {
  unsigned long ret;

  ret=(unsigned long)syscall(SYS_gettid);
  return(ret);
}

static void init_locks(void) {
  int i;

  lockarray=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *
      sizeof(pthread_mutex_t));
  for (i=0; i<CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&(lockarray[i]),NULL);
  }

  CRYPTO_set_id_callback((unsigned long (*)())thread_id);
  CRYPTO_set_locking_callback((void (*)())lock_callback);
}

static void destroy_locks(void) {
  int i;

  CRYPTO_set_locking_callback(NULL);
  for (i=0; i<CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&(lockarray[i]));

  OPENSSL_free(lockarray);
}

int drngInited = 0;
int drngInitResult = 0;

int drngInit() {
  if (drngInited != 0) {
    return drngInitResult;
  }

  init_locks();
  ENGINE_load_rdrand();
  ENGINE* eng = ENGINE_by_id("rdrand");

  int ret = 0;
  do {
    if (NULL == eng) {
      /*fprintf(stderr, "ENGINE_load_rdrand failed, err = 0x%lx\n",
          ERR_get_error());*/
      ret = 0;
      break;
    } else {
      int rc = ENGINE_set_default(eng, ENGINE_METHOD_RAND);
      if(1 != rc) {
        /*fprintf(stderr, "ENGINE_set_default failed, err = 0x%lx\n",
          ERR_get_error());*/
        ret = -1;
        break;
      }
    }
  } while(0);

  if (NULL != eng)
    ENGINE_free(eng);
  if (-1 == ret)
    destroy_locks();

  drngInited = 1;
  drngInitResult = ret;

  return ret;
}

/*
 * here we do not consider the situation that ENGINE_METHOD_RAND is
 * changed to other rng methods by other threads.
 * */
int drngRandBytes(uint8_t* buffer, size_t buffer_len) {
  int ret = 0;
  int rc = RAND_bytes(buffer, buffer_len);
  if (1 != rc) {
    /*fprintf(stderr, "RAND_bytes (1) failed, err = 0x%lx\n",
        ERR_get_error());*/
    ret = -1;
  }

  return ret;
}
