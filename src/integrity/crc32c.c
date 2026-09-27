#include "dmp/integrity.h"

dmp_status dmp_crc32c(dmp_bytes input, uint32_t *out)
{
    uint32_t crc = UINT32_C(0xFFFFFFFF);
    size_t index;

    if (out == NULL || (input.data == NULL && input.size != 0U)) {
        return DMP_INVALID_ARGUMENT;
    }

    for (index = 0U; index < input.size; ++index) {
        unsigned bit;
        crc ^= input.data[index];
        for (bit = 0U; bit < 8U; ++bit) {
            crc = (crc >> 1U) ^
                  ((crc & 1U) != 0U ? UINT32_C(0x82F63B78) : 0U);
        }
    }

    *out = ~crc;
    return DMP_OK;
}
