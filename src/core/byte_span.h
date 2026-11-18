#ifndef DMP_PRIVATE_BYTE_SPAN_H
#define DMP_PRIVATE_BYTE_SPAN_H

#include "dmp/base.h"

static inline bool dmp_bytes_valid(dmp_bytes bytes)
{
    return bytes.data != NULL || bytes.size == 0U;
}

static inline bool dmp_buffer_valid(dmp_buffer buffer)
{
    return buffer.data != NULL || buffer.capacity == 0U;
}

/* Treat an unrepresentable range end as overlap before adding the length. */
static inline bool dmp_ranges_overlap(const void *left, size_t left_size,
                                      const void *right, size_t right_size)
{
    uintptr_t a, b;

    if (left_size == 0U || right_size == 0U || left == NULL || right == NULL) {
        return false;
    }
    a = (uintptr_t)left;
    b = (uintptr_t)right;
    if (left_size > UINTPTR_MAX - a || right_size > UINTPTR_MAX - b) {
        return true;
    }
    return a < b + right_size && b < a + left_size;
}

#endif
