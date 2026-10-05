#include "opaque.h"

#include <stdint.h>

void dmp_test_opaque_fill(uint8_t *out, size_t size, uint8_t seed)
{
    size_t index;

    if (out == NULL) {
        return;
    }
    for (index = 0U; index < size; index++) {
        out[index] = (uint8_t)(seed + (uint8_t)(index & 0xffU));
    }
}

size_t dmp_test_opaque_len(uint32_t chunk, uint32_t count, int short_tail)
{
    uint64_t bytes;

    if (chunk == 0U || count < 2U) {
        return 0U;
    }
    if (short_tail) {
        bytes = (uint64_t)(count - 1U) * (uint64_t)chunk + 1U;
    } else {
        bytes = (uint64_t)count * (uint64_t)chunk;
    }
    if (bytes > (uint64_t)SIZE_MAX) {
        return 0U;
    }
    return (size_t)bytes;
}
