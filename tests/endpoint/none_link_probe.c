#include "dmp/endpoint.h"
#include "dmp/identity.h"
#include "sample1_endpoint.h"

#include <stdint.h>

typedef dmp_status (*endpoint_init_fn)(dmp_endpoint *, const dmp_endpoint_storage *,
                                      dmp_time_ms);
typedef dmp_sample1_owner_result (*sample_init_fn)(
    dmp_sample1_endpoint *, dmp_endpoint *, dmp_sample1_principal,
    const dmp_sample1_endpoint_hooks *, dmp_sample1_peer_epoch *, size_t);

static endpoint_init_fn volatile endpoint_init_reference;
static sample_init_fn volatile sample_init_reference;

static dmp_status fixed_random(void *user, uint8_t *out, size_t len)
{
    size_t i;
    uint8_t value = *(const uint8_t *)user;
    for (i = 0U; i < len; i++) out[i] = (uint8_t)(value + i);
    return DMP_OK;
}

int main(void)
{
    uint8_t seed = 1U;
    uint64_t epoch = 0U;
    endpoint_init_reference = dmp_endpoint_init;
    sample_init_reference = dmp_sample1_endpoint_init_with_peer_storage;
    if (endpoint_init_reference == NULL || sample_init_reference == NULL ||
        dmp_none_boot_epoch_generate(fixed_random, &seed, &epoch) != DMP_OK || epoch == 0U) {
        return 1;
    }
    return 0;
}
