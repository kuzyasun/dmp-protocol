#ifndef DMP_TEST_OPAQUE_H
#define DMP_TEST_OPAQUE_H

#include <stddef.h>
#include <stdint.h>

/* Test-only service 2 bytes. Not a protocol codec and not JSON. */

void dmp_test_opaque_fill(uint8_t *out, size_t size, uint8_t seed);

/* Exact stride is count * chunk. A short tail is (count-1)*chunk + 1.
 * Returns 0 when count < 2 or the product would overflow size_t. */
size_t dmp_test_opaque_len(uint32_t chunk, uint32_t count, int short_tail);

#endif
