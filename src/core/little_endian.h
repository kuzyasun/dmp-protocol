#ifndef DMP_PRIVATE_LITTLE_ENDIAN_H
#define DMP_PRIVATE_LITTLE_ENDIAN_H

#include <stdint.h>

/* Callers check the available bytes before loading or storing. */
static inline uint32_t dmp_load_le32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
           ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

static inline void dmp_store_le32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8U);
    bytes[2] = (uint8_t)(value >> 16U);
    bytes[3] = (uint8_t)(value >> 24U);
}

static inline uint64_t dmp_load_le64(const uint8_t *bytes)
{
    uint64_t value = 0U;
    unsigned index;

    for (index = 0U; index < 8U; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8U);
    }
    return value;
}

static inline void dmp_store_le64(uint8_t *bytes, uint64_t value)
{
    unsigned index;

    for (index = 0U; index < 8U; ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8U));
    }
}

#endif
