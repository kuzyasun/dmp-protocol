#include "dmp/identity.h"

/* Typed admission. Derived byte lengths, each checked for uint32 overflow:
 * sender_slots * message_bytes, result_slots * message_bytes, message_bytes,
 * history_slots * DMP_MAX_HEADER_BYTES, correlation_slots * DMP_MAX_HEADER_BYTES,
 * adapter_slots * encoded_mtu, assembly_slots * message_bytes,
 * assembly_slots * DMP_MAX_HEADER_BYTES.
 * peers * assembly_tombstones_per_peer is the tombstone-slot product.
 * The control reserve matches dmp_reliability_init: min(control_slots,
 * adapter_slots) must be non-zero and adapter_slots must be strictly greater.
 * It is the same rule, not a stricter one. */

static int product_fits(uint32_t left, uint32_t right)
{
    return ((uint64_t)left * (uint64_t)right) <= 0xFFFFFFFFULL;
}

static int service_selected(const dmp_config *in)
{
    return in->default_service == in->service_id[0] ||
           in->default_service == in->service_id[1];
}

/* Same branch as reliability control_reserve. Do not tighten it. */
static uint32_t control_reserve(const dmp_config *in)
{
    if (in->control_slots < in->adapter_slots) {
        return in->control_slots;
    }
    return in->adapter_slots;
}

static int add_u32(uint32_t left, uint32_t right, uint32_t *out)
{
    if (left > 0xFFFFFFFFU - right) {
        return 0;
    }
    *out = left + right;
    return 1;
}

/* R3 and main §11.1 only. The test-manifest symmetric max() is a profile
 * choice, not an extra admission limit. Retry-all is not checked here. */
static dmp_status admit_selective(const dmp_config *in)
{
    uint32_t twice;
    uint32_t floor;
    uint32_t life;
    uint32_t cover;
    int selective;

    selective = in->recovery[0] == DMP_PROFILE_RECOVERY_SELECTIVE32 ||
                in->recovery[1] == DMP_PROFILE_RECOVERY_SELECTIVE32;
    if (!selective) {
        return DMP_OK;
    }
    if (in->fragments < 2U || in->burst_span_ms == 0U || in->forward_delay_ms == 0U ||
        in->return_delay_ms == 0U || in->feedback_guard_ms == 0U ||
        in->feedback_delay_ms == 0U || in->record_margin_ms == 0U || in->max_probes == 0U ||
        in->max_status == 0U || in->max_bursts == 0U || in->return_mtu == 0U ||
        in->max_probes > in->max_bursts - 1U) {
        return DMP_UNSUPPORTED;
    }
    if (!add_u32(in->forward_delay_ms, in->forward_delay_ms, &twice) ||
        !add_u32(twice, in->burst_span_ms, &floor) ||
        !add_u32(floor, in->feedback_guard_ms, &floor) ||
        !add_u32(floor, in->feedback_delay_ms, &floor) ||
        !add_u32(floor, in->return_delay_ms, &floor) ||
        !add_u32(in->send_horizon_ms, in->forward_delay_ms, &life) ||
        !add_u32(life, in->record_margin_ms, &life) ||
        !add_u32(in->collect_ms, in->record_margin_ms, &cover)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (in->response_timeout_ms < floor || in->assembly_ms < life || in->assembly_ms < cover) {
        return DMP_UNSUPPORTED;
    }
    return DMP_OK;
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
    {
        uint32_t reserve = control_reserve(in);
        if (reserve == 0U || in->adapter_slots <= reserve) {
            return DMP_UNSUPPORTED;
        }
    }
    {
        dmp_status selective = admit_selective(in);
        if (selective != DMP_OK) {
            return selective;
        }
    }
    admitted = *in;
    *out = admitted;
    return DMP_OK;
}
