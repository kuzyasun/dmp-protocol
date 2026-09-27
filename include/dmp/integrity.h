#ifndef DMP_INTEGRITY_H
#define DMP_INTEGRITY_H
#include "dmp/base.h"
#ifdef __cplusplus
extern "C" {
#endif
/* P06 implementation. Standard CRC32C over bytes; *out unchanged on error.
 * Empty {NULL,0} is valid. Output is numeric CRC, not native-endian wire bytes. */
dmp_status dmp_crc32c(dmp_bytes input, uint32_t *out);
#ifdef __cplusplus
}
#endif
#endif
