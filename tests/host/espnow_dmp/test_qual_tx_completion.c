#include "qual_tx_completion.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main(void)
{
    dmp_qual_tx_completion_slot slot = {0};
    dmp_qual_tx_completion_event first = {
        .mac = { 0x20, 0x6e, 0xf1, 0xb0, 0xf0, 0x2c },
        .status = 0
    };
    dmp_qual_tx_completion_event duplicate = {
        .mac = { 0x20, 0x6e, 0xf1, 0xb0, 0xf0, 0x2d },
        .status = 1
    };
    dmp_qual_tx_completion_event received = {0};

    CHECK(dmp_qual_tx_completion_post(&slot, &first));
    CHECK(!dmp_qual_tx_completion_post(&slot, &duplicate));
    CHECK(dmp_qual_tx_completion_take(&slot, &received));
    CHECK(memcmp(received.mac, first.mac, sizeof first.mac) == 0);
    CHECK(received.status == first.status);
    CHECK(!dmp_qual_tx_completion_take(&slot, &received));

    CHECK(dmp_qual_tx_completion_post(&slot, &duplicate));
    CHECK(dmp_qual_tx_completion_take(&slot, &received));
    CHECK(memcmp(received.mac, duplicate.mac, sizeof duplicate.mac) == 0);
    CHECK(received.status == duplicate.status);
    return 0;
}
