#include "dmp/identity.h"

/* Typed admission. Derived byte lengths, each checked for uint32 overflow:
 * sender_slots * message_bytes, result_slots * message_bytes, message_bytes,
 * history_slots * DMP_MAX_HEADER_BYTES, correlation_slots * DMP_MAX_HEADER_BYTES,
 * adapter_slots * encoded_mtu, assembly_slots * message_bytes,
 * assembly_slots * DMP_MAX_HEADER_BYTES.
 * peers * assembly_tombstones_per_peer is the tombstone-slot product. */

static int product_fits(uint32_t left, uint32_t right)
{
    return ((uint64_t)left * (uint64_t)right) <= 0xFFFFFFFFULL;
}

static int service_selected(const dmp_config *in)
{
    return in->default_service == in->service_id[0] ||
           in->default_service == in->service_id[1];
}

dmp_status dmp_config_admit(const dmp_config *in, dmp_admitted_profile *out)
{
    uint64_t tombstones;
    dmp_config admitted;

    if (in == NULL || out == NULL || (const void *)in == (const void *)out) {
        return DMP_INVALID_ARGUMENT;
    }
    if (in->message_bytes == 0U || in->chunk_bytes == 0U || in->encoded_mtu == 0U ||
        in->fragments == 0U || in->fragments > 32U) {
        return DMP_INVALID_ARGUMENT;
    }
    tombstones = (uint64_t)in->peers * (uint64_t)in->assembly_tombstones_per_peer;
    if (!product_fits(in->sender_slots, in->message_bytes) ||
        !product_fits(in->result_slots, in->message_bytes) ||
        !product_fits(in->history_slots, (uint32_t)DMP_MAX_HEADER_BYTES) ||
        !product_fits(in->correlation_slots, (uint32_t)DMP_MAX_HEADER_BYTES) ||
        !product_fits(in->adapter_slots, in->encoded_mtu) ||
        !product_fits(in->assembly_slots, in->message_bytes) ||
        !product_fits(in->assembly_slots, (uint32_t)DMP_MAX_HEADER_BYTES) ||
        tombstones > 0xFFFFFFFFULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (in->default_service == 0U || !service_selected(in) ||
        in->service_id[0] == in->service_id[1] || in->chunk_bytes >= in->message_bytes ||
        in->peers == 0U || in->assembly_tombstones_per_peer < in->assemblies_per_peer ||
        (uint64_t)in->assembly_tombstone_slots < tombstones) {
        return DMP_UNSUPPORTED;
    }
    admitted = *in;
    *out = admitted;
    return DMP_OK;
}
