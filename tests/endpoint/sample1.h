#ifndef DMP_TEST_SAMPLE1_H
#define DMP_TEST_SAMPLE1_H

#include <stddef.h>
#include <stdint.h>

/* SAMPLE-1 revision 2 payload layout from docs/DMP_v2_Reference_Application.md.
 * This codec is the application, not libdmp. Integers are unsigned
 * little-endian. No padding, strings, or trailing bytes. */

enum {
    SAMPLE1_READ = 1,
    SAMPLE1_STATUS = 2,
    SAMPLE1_TELEM_BYTES = 16,
    SAMPLE1_READ_BYTES = 17,
    SAMPLE1_STATUS_BYTES = 2
};

static inline void sample1_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8U);
    out[2] = (uint8_t)(value >> 16U);
    out[3] = (uint8_t)(value >> 24U);
}

static inline void sample1_u64(uint8_t *out, uint64_t value)
{
    unsigned i;
    for (i = 0U; i < 8U; i++) {
        out[i] = (uint8_t)(value & 0xffU);
        value >>= 8U;
    }
}

static inline uint32_t sample1_load_u32(const uint8_t *in)
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8U) | ((uint32_t)in[2] << 16U) |
           ((uint32_t)in[3] << 24U);
}

static inline uint64_t sample1_load_u64(const uint8_t *in)
{
    uint64_t value = 0U;
    unsigned i;
    for (i = 8U; i > 0U; i--) {
        value = (value << 8U) | in[i - 1U];
    }
    return value;
}

static inline size_t sample1_telem(uint8_t out[SAMPLE1_TELEM_BYTES], uint64_t epoch, uint32_t index,
                                   uint32_t value)
{
    sample1_u64(out, epoch);
    sample1_u32(out + 8, index);
    sample1_u32(out + 12, value);
    return SAMPLE1_TELEM_BYTES;
}

static inline size_t sample1_read_req(uint8_t out[1])
{
    out[0] = SAMPLE1_READ;
    return 1U;
}

static inline size_t sample1_read_rsp(uint8_t out[SAMPLE1_READ_BYTES], uint64_t epoch, uint32_t index,
                                      uint32_t value)
{
    out[0] = SAMPLE1_READ;
    (void)sample1_telem(out + 1, epoch, index, value);
    return SAMPLE1_READ_BYTES;
}

static inline size_t sample1_status_req(uint8_t out[1])
{
    out[0] = SAMPLE1_STATUS;
    return 1U;
}

static inline size_t sample1_status_rsp(uint8_t out[SAMPLE1_STATUS_BYTES], uint8_t ready)
{
    out[0] = SAMPLE1_STATUS;
    out[1] = ready;
    return SAMPLE1_STATUS_BYTES;
}

#endif
