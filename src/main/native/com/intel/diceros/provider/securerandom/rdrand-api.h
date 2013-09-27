#ifndef _Included_RDRANDAPI
#define _Included_RDRANDAPI

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int drngInit();
int drngRandBytes(uint8_t* buffer, size_t buffer_len);

#ifdef __cplusplus
}
#endif

#endif
