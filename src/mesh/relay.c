#include "dmp/mesh.h"

#include "dmp/integrity.h"

#include <stdint.h>
#include <string.h>

#define DMP_MESH_PN_LIMIT (UINT64_C(1) << 24)

static int add_u64(uint64_t left, uint64_t right, uint64_t *out)
{
    if (left > UINT64_MAX - right) {
        return 0;
    }
    *out = left + right;
    return 1;
}

static int add_u32(uint32_t left, uint32_t right, uint32_t *out)
{
    if (left > 0xFFFFFFFFU - right) {
        return 0;
    }
    *out = left + right;
    return 1;
}

static int read_uleb32(dmp_bytes in, size_t *at, uint32_t *value)
{
    uint32_t acc = 0U;
    unsigned i;
    size_t start;

    if (at == NULL || *at > in.size) {
        return 0;
    }
    start = *at;
    for (i = 0U; i < 5U; i++) {
        uint8_t byte;
        uint8_t chunk;
        if (*at >= in.size) {
            return 0;
        }
        byte = in.data[(*at)++];
        chunk = (uint8_t)(byte & 0x7fU);
        if (i == 4U && chunk > 0x0fU) {
            return 0;
        }
        acc |= (uint32_t)chunk << (7U * i);
        if ((byte & 0x80U) == 0U) {
            size_t n = 1U;
            uint32_t probe = acc;
            while (probe >= 128U) {
                probe >>= 7;
                n++;
            }
            if (*at - start != n) {
                return 0;
            }
            *value = acc;
            return 1;
        }
    }
    return 0;
}

static int read_context(dmp_bytes extensions, uint32_t *namespace_id, uint64_t *epoch)
{
    size_t cursor = 0U;
    int found = 0;

    while (cursor < extensions.size) {
        dmp_extension_view ext;
        dmp_status status = dmp_extension_next(extensions, &cursor, &ext);
        uint32_t ns = 0U;
        uint64_t ep = 0U;
        size_t at = 0U;
        unsigned b;
        if (status != DMP_OK) {
            return 0;
        }
        if ((ext.tag >> 2) != 2U) {
            continue;
        }
        if (found || !read_uleb32(ext.value, &at, &ns) || ext.value.size - at != 8U) {
            return 0;
        }
        for (b = 0U; b < 8U; b++) {
            ep |= (uint64_t)ext.value.data[at + b] << (8U * b);
        }
        *namespace_id = ns;
        *epoch = ep;
        found = 1;
    }
    return found;
}

static int same_identity(const dmp_mesh_cache_slot *slot, const dmp_message_origin *origin, uint32_t seq)
{
    return slot->occupied && slot->origin.namespace_id == origin->namespace_id &&
           slot->origin.origin_id == origin->origin_id && slot->origin.epoch == origin->epoch &&
           slot->seq == seq;
}

static int same_key(const dmp_mesh_cache_slot *slot, const dmp_message_origin *origin, uint32_t seq,
                    uint8_t unfragmented, uint32_t fragment_index)
{
    return same_identity(slot, origin, seq) && slot->unfragmented == unfragmented &&
           (unfragmented || slot->fragment_index == fragment_index);
}

static uint32_t path_delay(const dmp_admitted_profile *profile)
{
    if (profile->forward_delay_ms > profile->return_delay_ms) {
        return profile->forward_delay_ms;
    }
    return profile->return_delay_ms;
}

static dmp_status transmit_at_for(const dmp_mesh_relay *relay, const dmp_mesh_forward_in *in,
                                  dmp_time_ms *transmit_at)
{
    if (in->direction == DMP_MESH_FORWARD) {
        uint64_t period = relay->return_period_ms;
        uint64_t k;
        uint64_t candidate;
        if (period == 0U) {
            return DMP_UNSUPPORTED;
        }
        k = in->now / period;
        if (in->now % period != 0U) {
            if (k == UINT64_MAX) {
                return DMP_BUSY;
            }
            k++;
        }
        if (period != 0U && k > UINT64_MAX / period) {
            return DMP_BUSY;
        }
        candidate = k * period;
        if (candidate < in->now || candidate - in->now > relay->profile->queue_ms) {
            return DMP_BUSY;
        }
        *transmit_at = candidate;
        return DMP_OK;
    }
    if (in->direction != DMP_MESH_RETURN || (in->return_slot != 1U && in->return_slot != 2U)) {
        return DMP_INVALID_ARGUMENT;
    }
    {
        uint64_t slot;
        uint64_t traversal;
        if (!add_u64(in->source_start_ms, relay->return_period_ms, &slot) ||
            slot < relay->return_width_ms) {
            return DMP_BUSY;
        }
        slot -= relay->return_width_ms;
        if (in->return_slot == 2U) {
            if (!add_u64(relay->frame_tx_ms, path_delay(relay->profile), &traversal) ||
                !add_u64(slot, traversal, &slot)) {
                return DMP_BUSY;
            }
        }
        if (in->now > slot || slot - in->now > relay->profile->queue_ms) {
            return DMP_BUSY;
        }
        *transmit_at = slot;
        return DMP_OK;
    }
}

static int crc_matches(dmp_bytes frame)
{
    dmp_bytes covered;
    uint32_t actual = 0U;
    uint32_t expect;
    const uint8_t *tail;
    if (frame.size < 4U) {
        return 0;
    }
    covered.data = frame.data;
    covered.size = frame.size - 4U;
    if (dmp_crc32c(covered, &actual) != DMP_OK) {
        return 0;
    }
    tail = frame.data + frame.size - 4U;
    expect = (uint32_t)tail[0] | ((uint32_t)tail[1] << 8) | ((uint32_t)tail[2] << 16) |
             ((uint32_t)tail[3] << 24);
    return actual == expect;
}

static void write_crc(uint8_t *frame, size_t size)
{
    dmp_bytes covered;
    uint32_t crc = 0U;
    covered.data = frame;
    covered.size = size - 4U;
    if (dmp_crc32c(covered, &crc) != DMP_OK) {
        return;
    }
    frame[size - 4U] = (uint8_t)crc;
    frame[size - 3U] = (uint8_t)(crc >> 8);
    frame[size - 2U] = (uint8_t)(crc >> 16);
    frame[size - 1U] = (uint8_t)(crc >> 24);
}

dmp_status dmp_mesh_relay_init(dmp_mesh_relay *relay)
{
    if (relay == NULL || relay->profile == NULL || relay->routes == NULL || relay->route_count == 0U ||
        relay->cache == NULL || relay->cache_count == 0U || relay->airtime == NULL ||
        relay->airtime_count == 0U || relay->self_node == 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    if (relay->profile->jitter_ms != 0U || relay->pn_filter != DMP_MESH_PN_REJECT_GE_2POW24 ||
        relay->cooldown_ms == 0U || relay->expiry_ms == 0U || relay->max_forwards_per_key == 0U ||
        relay->frame_tx_ms == 0U || relay->per_origin_airtime_ms == 0U ||
        relay->global_airtime_ms == 0U || relay->return_period_ms == 0U ||
        relay->return_width_ms == 0U || relay->return_period_ms < relay->return_width_ms ||
        relay->profile->queue_ms == 0U || relay->profile->forward_mtu == 0U ||
        relay->profile->return_mtu == 0U) {
        return DMP_UNSUPPORTED;
    }
    memset(relay->cache, 0, relay->cache_count * sizeof *relay->cache);
    memset(relay->airtime, 0, relay->airtime_count * sizeof *relay->airtime);
    relay->global_used_ms = 0U;
    return DMP_OK;
}

dmp_status dmp_mesh_relay_forward(dmp_mesh_relay *relay, const dmp_mesh_forward_in *in, dmp_buffer output,
                                  dmp_mesh_forward_out *out)
{
    dmp_frame_view view;
    dmp_parse_result parsed;
    dmp_role_policy policy;
    dmp_frame_spec spec;
    dmp_message_origin origin;
    dmp_time_ms transmit_at = 0U;
    dmp_time_ms ready = 0U;
    dmp_time_ms expires = 0U;
    uint32_t next_hop = 0U;
    uint32_t mtu;
    size_t written = 0U;
    size_t index;
    size_t cache_index = relay == NULL ? 0U : relay->cache_count;
    size_t air_index = relay == NULL ? 0U : relay->airtime_count;
    int have_route = 0;
    int fresh = 0;
    uint32_t origin_used = 0U;
    uint32_t global_used = 0U;

    if (relay == NULL || relay->profile == NULL || in == NULL || out == NULL ||
        in->frame.data == NULL || in->frame.size == 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    parsed = dmp_core_parse(in->frame, &in->limits, &view);
    if (parsed.status != DMP_OK) {
        return parsed.status;
    }
    memset(&policy, 0, sizeof policy);
    policy.role = DMP_ROLE_FORWARDER;
    policy.default_service = relay->profile->default_service;
    policy.selective32 = relay->profile->recovery[0] == DMP_PROFILE_RECOVERY_SELECTIVE32 ||
                         relay->profile->recovery[1] == DMP_PROFILE_RECOVERY_SELECTIVE32;
    {
        dmp_status role = dmp_core_check_role(&view, &policy);
        if (role != DMP_OK) {
            return role;
        }
    }
    if ((view.fields.options & DMP_OPT_INTEGRITY) != 0U && !crc_matches(in->frame)) {
        return DMP_INTEGRITY_FAILURE;
    }
    if ((view.fields.options & DMP_OPT_SECURITY) != 0U && view.fields.security.pn >= DMP_MESH_PN_LIMIT) {
        return DMP_LIMIT_EXHAUSTED;
    }
    if ((view.fields.options & DMP_OPT_ROUTE) == 0U || (view.fields.options & DMP_OPT_SEQ) == 0U) {
        return DMP_MALFORMED;
    }
    if (view.fields.route.mode != 1U) {
        return DMP_UNSUPPORTED;
    }
    if (view.fields.route.ttl == 0U || view.fields.route.destination == relay->self_node) {
        return DMP_LIMIT_EXHAUSTED;
    }
    mtu = in->direction == DMP_MESH_FORWARD ? relay->profile->forward_mtu : relay->profile->return_mtu;
    if (in->frame.size > mtu) {
        return DMP_LIMIT_EXHAUSTED;
    }
    for (index = 0U; index < relay->route_count; index++) {
        if (relay->routes[index].destination == view.fields.route.destination) {
            next_hop = relay->routes[index].next_hop;
            have_route = 1;
            break;
        }
    }
    if (!have_route) {
        return DMP_UNSUPPORTED;
    }
    memset(&origin, 0, sizeof origin);
    if (!read_context(view.extensions, &origin.namespace_id, &origin.epoch)) {
        return DMP_CONTEXT_REQUIRED;
    }
    origin.origin_id = view.fields.route.source;
    {
        dmp_status schedule = transmit_at_for(relay, in, &transmit_at);
        if (schedule != DMP_OK) {
            return schedule;
        }
    }
    if (in->tx_complete_at < transmit_at) {
        return DMP_INVALID_ARGUMENT;
    }
    for (index = 0U; index < relay->cache_count; index++) {
        dmp_mesh_cache_slot *slot = &relay->cache[index];
        if (!same_identity(slot, &origin, view.fields.seq)) {
            continue;
        }
        if (slot->unfragmented != ((view.fields.options & DMP_OPT_FRAG) == 0U)) {
            return DMP_MALFORMED;
        }
    }
    for (index = 0U; index < relay->cache_count; index++) {
        if (same_key(&relay->cache[index], &origin, view.fields.seq,
                     (uint8_t)((view.fields.options & DMP_OPT_FRAG) == 0U), view.fields.fragment.index)) {
            cache_index = index;
            break;
        }
        if (!relay->cache[index].occupied && cache_index == relay->cache_count) {
            cache_index = index;
            fresh = 1;
        }
    }
    if (cache_index == relay->cache_count) {
        return DMP_QUOTA_EXHAUSTED;
    }
    if (relay->cache[cache_index].occupied) {
        fresh = 0;
        if (!add_u64(relay->cache[cache_index].last_completion, relay->cooldown_ms, &ready)) {
            return DMP_INVALID_ARGUMENT;
        }
        if (in->now < ready) {
            return DMP_BUSY;
        }
        if (in->now >= relay->cache[cache_index].expires_at) {
            return DMP_DEADLINE_EXPIRED;
        }
        if (relay->cache[cache_index].forwards >= relay->max_forwards_per_key) {
            return DMP_QUOTA_EXHAUSTED;
        }
        expires = relay->cache[cache_index].expires_at;
    } else {
        fresh = 1;
        if (!add_u64(in->now, relay->expiry_ms, &expires)) {
            return DMP_INVALID_ARGUMENT;
        }
    }
    for (index = 0U; index < relay->airtime_count; index++) {
        if (relay->airtime[index].occupied && relay->airtime[index].origin_id == origin.origin_id) {
            air_index = index;
            origin_used = relay->airtime[index].used_ms;
            break;
        }
        if (!relay->airtime[index].occupied && air_index == relay->airtime_count) {
            air_index = index;
        }
    }
    if (air_index == relay->airtime_count) {
        return DMP_QUOTA_EXHAUSTED;
    }
    if (!add_u32(origin_used, relay->frame_tx_ms, &origin_used) ||
        origin_used > relay->per_origin_airtime_ms ||
        !add_u32(relay->global_used_ms, relay->frame_tx_ms, &global_used) ||
        global_used > relay->global_airtime_ms) {
        return DMP_QUOTA_EXHAUSTED;
    }
    memset(&spec, 0, sizeof spec);
    spec.fields = view.fields;
    spec.fields.route.ttl = (uint8_t)(view.fields.route.ttl - 1U);
    spec.extensions = view.extensions;
    spec.payload = view.payload;
    spec.trailer = view.trailer;
    {
        dmp_status encoded = dmp_core_encode(&spec, &in->limits, output, &written);
        if (encoded != DMP_OK) {
            return encoded;
        }
    }
    if ((view.fields.options & DMP_OPT_INTEGRITY) != 0U && written >= 4U) {
        write_crc(output.data, written);
    }
    if (fresh) {
        memset(&relay->cache[cache_index], 0, sizeof relay->cache[cache_index]);
        relay->cache[cache_index].origin = origin;
        relay->cache[cache_index].seq = view.fields.seq;
        relay->cache[cache_index].unfragmented = (uint8_t)((view.fields.options & DMP_OPT_FRAG) == 0U);
        relay->cache[cache_index].fragment_index = view.fields.fragment.index;
        relay->cache[cache_index].admitted_at = in->now;
        relay->cache[cache_index].expires_at = expires;
        relay->cache[cache_index].occupied = 1U;
    }
    relay->cache[cache_index].last_completion = in->tx_complete_at;
    relay->cache[cache_index].forwards++;
    if (!relay->airtime[air_index].occupied) {
        relay->airtime[air_index].origin_id = origin.origin_id;
        relay->airtime[air_index].occupied = 1U;
        relay->airtime[air_index].used_ms = 0U;
    }
    relay->airtime[air_index].used_ms = origin_used;
    relay->global_used_ms = global_used;
    out->next_hop = next_hop;
    out->transmit_at = transmit_at;
    out->written = written;
    return DMP_OK;
}
