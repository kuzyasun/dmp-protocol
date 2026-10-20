#include <stdio.h>
#include <string.h>

#include "profile_hashes.h"

_Static_assert(sizeof(DMP_RETRY_2_PROFILE_HASH_BYTES) == 32U,
               "retry profile hash must be exactly 32 bytes");
_Static_assert(sizeof(DMP_MULTI_PEER_PROFILE_HASH_BYTES) == 32U,
               "multi-peer profile hash must be exactly 32 bytes");

int main(void)
{
    unsigned char active_profile_hash[32];
    unsigned char copied_hashes[64];

    /* Match the production main.c call shape: memcpy from typed hash arrays. */
    memcpy(active_profile_hash, DMP_RETRY_2_PROFILE_HASH_BYTES,
           sizeof(DMP_RETRY_2_PROFILE_HASH_BYTES));
    memcpy(copied_hashes, active_profile_hash, sizeof(active_profile_hash));
    memcpy(active_profile_hash, DMP_MULTI_PEER_PROFILE_HASH_BYTES,
           sizeof(DMP_MULTI_PEER_PROFILE_HASH_BYTES));
    memcpy(copied_hashes + 32U, active_profile_hash,
           sizeof(active_profile_hash));

    for (size_t i = 0U; i < sizeof(copied_hashes); ++i) {
        if (printf("%02x", copied_hashes[i]) < 0) {
            return 1;
        }
    }
    return putchar('\n') == EOF ? 1 : 0;
}
