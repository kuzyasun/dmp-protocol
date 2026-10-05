#include "opaque.h"

#include <stdio.h>

int main(void)
{
    uint8_t body[8];

    if (dmp_test_opaque_len(32U, 2U, 0) != 64U || dmp_test_opaque_len(32U, 2U, 1) != 33U ||
        dmp_test_opaque_len(32U, 8U, 0) != 256U || dmp_test_opaque_len(32U, 32U, 0) != 1024U ||
        dmp_test_opaque_len(32U, 32U, 1) != 993U || dmp_test_opaque_len(64U, 16U, 0) != 1024U ||
        dmp_test_opaque_len(64U, 16U, 1) != 961U || dmp_test_opaque_len(0U, 2U, 0) != 0U) {
        (void)fprintf(stderr, "opaque length mismatch\n");
        return 1;
    }
    dmp_test_opaque_fill(body, sizeof body, 0x40U);
    if (body[0] != 0x40U || body[7] != (uint8_t)(0x40U + 7U)) {
        return 1;
    }
    return 0;
}
