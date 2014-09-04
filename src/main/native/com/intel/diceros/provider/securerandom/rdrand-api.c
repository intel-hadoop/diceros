#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <jni.h>

#include "com_intel_diceros.h"
#include "rdrand-api.h"
#include "config.h"

#ifdef UNIX
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#endif

#ifdef WINDOWS
#include <windows.h>
#endif

#ifdef UNIX
static void * (*dlsym_CRYPTO_malloc) (int, const char *, int);
static void (*dlsym_CRYPTO_free) (void *);
static int (*dlsym_CRYPTO_num_locks) (void);
static void (*dlsym_CRYPTO_set_locking_callback) (void (*)());
static void (*dlsym_CRYPTO_set_id_callback) (unsigned long (*)());
static void (*dlsym_ENGINE_load_rdrand) (void);
static ENGINE * (*dlsym_ENGINE_by_id) (const char *);
static int (*dlsym_ENGINE_init) (ENGINE *);
static int (*dlsym_ENGINE_set_default) (ENGINE *, unsigned int);
static int (*dlsym_ENGINE_finish) (ENGINE *);
static int (*dlsym_ENGINE_free) (ENGINE *);
static void (*dlsym_ENGINE_cleanup) (void);
static int (*dlsym_RAND_bytes) (unsigned char *, int);
#endif
#ifdef WINDOWS
typedef void * (__cdecl *__dlsym_CRYPTO_malloc) (int, const char *, int);
typedef void (__cdecl *__dlsym_CRYPTO_free) (void *);
typedef int (__cdecl *__dlsym_CRYPTO_num_locks) (void);
typedef void (__cdecl *__dlsym_CRYPTO_set_locking_callback) \
(void (*)(int, int, char *, int));
typedef void (__cdecl *__dlsym_ENGINE_load_rdrand) (void);
typedef ENGINE * (__cdecl *__dlsym_ENGINE_by_id) (const char *);
typedef int (__cdecl *__dlsym_ENGINE_init) (ENGINE *);
typedef int (__cdecl *__dlsym_ENGINE_set_default) (ENGINE *, unsigned int);
typedef int (__cdecl *__dlsym_ENGINE_finish) (ENGINE *);
typedef int (__cdecl *__dlsym_ENGINE_free) (ENGINE *);
typedef void (__cdecl *__dlsym_ENGINE_cleanup) (void);
typedef int (__cdecl *__dlsym_RAND_bytes) (unsigned char *, int);
static __dlsym_CRYPTO_malloc dlsym_CRYPTO_malloc;
static __dlsym_CRYPTO_free dlsym_CRYPTO_free;
static __dlsym_CRYPTO_num_locks dlsym_CRYPTO_num_locks;
static __dlsym_CRYPTO_set_locking_callback dlsym_CRYPTO_set_locking_callback;
static __dlsym_ENGINE_load_rdrand dlsym_ENGINE_load_rdrand;
static __dlsym_ENGINE_by_id dlsym_ENGINE_by_id;
static __dlsym_ENGINE_init dlsym_ENGINE_init;
static __dlsym_ENGINE_set_default dlsym_ENGINE_set_default;
static __dlsym_ENGINE_finish dlsym_ENGINE_finish;
static __dlsym_ENGINE_free dlsym_ENGINE_free;
static __dlsym_ENGINE_cleanup dlsym_ENGINE_cleanup;
static __dlsym_RAND_bytes dlsym_RAND_bytes;
#endif

#ifdef UNIX
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
  return (unsigned long)syscall(SYS_gettid);
}

static void init_locks(void) {
  int i;

  lockarray = dlsym_CRYPTO_malloc(dlsym_CRYPTO_num_locks() *
      sizeof(pthread_mutex_t), __FILE__, __LINE__);
  for (i=0; i<dlsym_CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&(lockarray[i]), NULL);
  }

  dlsym_CRYPTO_set_id_callback((unsigned long (*)())thread_id);
  dlsym_CRYPTO_set_locking_callback((void (*)())lock_callback);
}

static void destroy_locks(void) {
  int i;

  dlsym_CRYPTO_set_locking_callback(NULL);
  for (i=0; i<dlsym_CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&(lockarray[i]));

  dlsym_CRYPTO_free(lockarray);
}
#endif

#ifdef WINDOWS
static HANDLE *lockarray;

static void lock_callback(int mode, int type, char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    WaitForSingleObject(lockarray[type], INFINITE);
  } else {
    ReleaseMutex(lockarray[type]);
  }
}

static void init_locks(void) {
  int i;
  lockarray = dlsym_CRYPTO_malloc(dlsym_CRYPTO_num_locks() * sizeof(HANDLE), \
      __FILE__, __LINE__);
  for (i = 0; i < dlsym_CRYPTO_num_locks(); i++) {
    lockarray[i] = CreateMutex(NULL, FALSE, NULL);
  }
  dlsym_CRYPTO_set_locking_callback((void (*)(int, int, char *, int)) \
      lock_callback);
}

static void destroy_locks(void) {
  int i;
  dlsym_CRYPTO_set_locking_callback(NULL);
  for (i = 0; i < dlsym_CRYPTO_num_locks(); i++) {
    CloseHandle(lockarray[i]);
  }
  dlsym_CRYPTO_free(lockarray);
}
#endif

int drngInit(JNIEnv *env) {
  char msg[1000];
  int rc, ret;
  ENGINE* eng;

#ifdef UNIX
  void *openssl = dlopen(HADOOP_CRYPTO_LIBRARY, RTLD_LAZY | RTLD_GLOBAL);
#endif
#ifdef WINDOWS
  HMODULE openssl = LoadLibrary(HADOOP_CRYPTO_LIBRARY);
#endif
  if (!openssl) {
    snprintf(msg, sizeof(msg), "Cannot load %s!", HADOOP_CRYPTO_LIBRARY);
    THROW(env, "java/lang/UnsatisfiedLinkError", msg);
    return;
  }
#ifdef UNIX
  dlerror(); // Clear any existing error
  LOAD_DYNAMIC_SYMBOL(dlsym_CRYPTO_malloc, env, openssl, "CRYPTO_malloc");
  LOAD_DYNAMIC_SYMBOL(dlsym_CRYPTO_free, env, openssl, "CRYPTO_free");
  LOAD_DYNAMIC_SYMBOL(dlsym_CRYPTO_num_locks, env, openssl, "CRYPTO_num_locks");
  LOAD_DYNAMIC_SYMBOL(dlsym_CRYPTO_set_locking_callback, \
  env, openssl, "CRYPTO_set_locking_callback");
  LOAD_DYNAMIC_SYMBOL(dlsym_CRYPTO_set_id_callback, env, \
  openssl, "CRYPTO_set_id_callback");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_load_rdrand, env, \
  openssl, "ENGINE_load_rdrand");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_by_id, env, openssl, "ENGINE_by_id");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_init, env, openssl, "ENGINE_init");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_set_default, env, \
  openssl, "ENGINE_set_default");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_finish, env, openssl, "ENGINE_finish");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_free, env, openssl, "ENGINE_free");
  LOAD_DYNAMIC_SYMBOL(dlsym_ENGINE_cleanup, env, openssl, "ENGINE_cleanup");
  LOAD_DYNAMIC_SYMBOL(dlsym_RAND_bytes, env, openssl, "RAND_bytes");
#endif
#ifdef WINDOWS
  LOAD_DYNAMIC_SYMBOL(__dlsym_CRYPTO_malloc, dlsym_CRYPTO_malloc, \
  env, openssl, "CRYPTO_malloc");
  LOAD_DYNAMIC_SYMBOL(__dlsym_CRYPTO_free, dlsym_CRYPTO_free, \
  env, openssl, "CRYPTO_free");
  LOAD_DYNAMIC_SYMBOL(__dlsym_CRYPTO_num_locks, dlsym_CRYPTO_num_locks, \
  env, openssl, "CRYPTO_num_locks");
  LOAD_DYNAMIC_SYMBOL(__dlsym_CRYPTO_set_locking_callback, \
  dlsym_CRYPTO_set_locking_callback, \
  env, openssl, "CRYPTO_set_locking_callback");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_load_rdrand, dlsym_ENGINE_load_rdrand, \
  env, openssl, "ENGINE_load_rdrand");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_by_id, dlsym_ENGINE_by_id, \
  env, openssl, "ENGINE_by_id");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_init, dlsym_ENGINE_init, \
  env, openssl, "ENGINE_init");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_set_default, dlsym_ENGINE_set_default, \
  env, openssl, "ENGINE_set_default");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_finish, dlsym_ENGINE_finish, \
  env, openssl, "ENGINE_finish");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_free, dlsym_ENGINE_free, \
  env, openssl, "ENGINE_free");
  LOAD_DYNAMIC_SYMBOL(__dlsym_ENGINE_cleanup, dlsym_ENGINE_cleanup, \
  env, openssl, "ENGINE_cleanup");
  LOAD_DYNAMIC_SYMBOL(__dlsym_RAND_bytes, dlsym_RAND_bytes, \
  env, openssl, "RAND_bytes");
#endif

  init_locks();
  dlsym_ENGINE_load_rdrand();
  eng = dlsym_ENGINE_by_id("rdrand");
  ret = -1;
  do {
    if (NULL == eng) {
      break;
    }

    rc = dlsym_ENGINE_init(eng);
    if (1 != rc) {
      break;
    }

    rc = dlsym_ENGINE_set_default(eng, ENGINE_METHOD_RAND);
    if(1 != rc) {
      break;
    }

    ret = 0;
  } while(0);
  if (ret == -1) {
    if (NULL != eng) {
      dlsym_ENGINE_finish(eng);
      dlsym_ENGINE_free(eng);
    }
    dlsym_ENGINE_cleanup();
    destroy_locks();
  }
  return ret;
}

/*
 * here we do not consider the situation that ENGINE_METHOD_RAND is
 * changed to other rng methods by other threads.
 * */
int drngRandBytes(uint8_t* buffer, size_t buffer_len) {
  int ret = 0;
  int rc = dlsym_RAND_bytes(buffer, buffer_len);
  if (1 != rc) {
    ret = -1;
  }

  return ret;
}
