/* Deterministic test-only startup entropy for checked-backend regressions. */
#include "dmp_sodium_entropy.h"
#include <stdint.h>
#ifdef DMP_TEST_NOISE_ENTROPY_PORT
#include <noise/protocol.h>
#endif
static uint64_t test_entropy_sequence;
int dmp_sodium_entropy_ready(void) { return 0; }
int dmp_sodium_entropy_read(void *bytes, size_t size)
{
    uint8_t *output = bytes;
    size_t i;
    ++test_entropy_sequence;
    for (i = 0; i < size; ++i)
        output[i] = (uint8_t)(0x53U + i * 17U +
            (test_entropy_sequence >> ((i % 8U) * 8U)));
    return 0;
}
#ifdef DMP_TEST_NOISE_ENTROPY_PORT
int noise_rand_bytes_checked(void *bytes, size_t size)
{
    return dmp_sodium_entropy_read(bytes, size);
}
#endif
