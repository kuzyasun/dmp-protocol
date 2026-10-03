#ifndef DMP_FUZZ_CORE_H
#define DMP_FUZZ_CORE_H

#include <stddef.h>
#include <stdint.h>

/* Structural parse of one admitted frame. Returns 0 after bounded work.
 * The return value is not a protocol status and not acceptance. */
int dmp_fuzz_core(const uint8_t *data, size_t size);

/* Harness sink incremented only when the callback reaches libdmp. */
uint32_t dmp_fuzz_core_observations(void);

#endif
