#include "handshake_transport.h"

#include "dmp/integrity.h"
#include "dmp/identity.h"
#include "dmp/stream.h"

#include <string.h>

#define DMP_HS_TX_MAGIC UINT32_C(0xD3137A01)
#define DMP_HS_CONTEXT_TAG 0x0BU
#define DMP_HS_ORIGIN_TAG 0x0FU
#define DMP_HS_BOOT_VERSION 2U
#define DMP_HS_BOOT_MAX_FRAGMENTS 256U

struct hs_tx_peer_sync {
    dmp_peer_handle peer;
    int live;
    int sync_pending;
};

struct hs_tx_slot {
    uint64_t token_generation;
    uint64_t handshake_generation;
    uint64_t deadline_ms;
    dmp_peer_handle peer;
    uint32_t attempt_index;
    int live;
    int result_ready;
    int accepted;
    int sync_action;
    int expired;
    int cancellation_requested;
    dmp_tx_outcome outcome;
    dmp_time_ms completed_at;
    dmp_hs_tx_reservation reservation;
};

struct dmp_hs_tx {
    uint32_t magic;
    dmp_hs *handshake;
    dmp_transport *transport;
    dmp_hs_tx_lifetime *lifetime;
    dmp_hs_tx_config config;
    dmp_hs_tx_buffer buffers[DMP_HS_TX_SLOT_MAX];
    struct hs_tx_slot slots[DMP_HS_TX_SLOT_MAX];
    struct hs_tx_peer_sync peer_sync[DMP_PROFILE_MAX_PEERS];
    uint8_t core_scratch[DMP_HS_TX_CORE_MAX];
    uint8_t sync_byte;
};

typedef struct bootstrap_geometry {
    dmp_hs_bootstrap_context context;
    uint32_t sequence;
    size_t payload_size;
    size_t chunk_size;
    size_t fragment_count;
} bootstrap_geometry;

static int state_live(const dmp_hs_tx *state)
{
    return state != NULL && state->magic == DMP_HS_TX_MAGIC &&
           state->handshake != NULL && state->transport != NULL &&
           state->transport->submit != NULL && state->transport->cancel != NULL;
}

static int same_peer(dmp_peer_handle left, dmp_peer_handle right)
{
    return left.slot == right.slot && left.generation == right.generation;
}

static int peer_has_live_tx(const dmp_hs_tx *state, dmp_peer_handle peer)
{
    uint32_t index;
    for (index = 0U; index < DMP_HS_TX_SLOT_MAX; ++index) {
        if (state->slots[index].live && same_peer(state->slots[index].peer, peer)) {
            return 1;
        }
    }
    return 0;
}

static int peer_sync_index(dmp_hs_tx *state, dmp_peer_handle peer, int create)
{
    uint32_t index;
    int empty = -1;
    int stale = -1;

    if (peer.generation == 0U) return -1;
    for (index = 0U; index < DMP_PROFILE_MAX_PEERS; ++index) {
        struct hs_tx_peer_sync *entry = &state->peer_sync[index];
        if (!entry->live) {
            if (empty < 0) empty = (int)index;
        } else if (same_peer(entry->peer, peer)) {
            return (int)index;
        } else if (entry->peer.slot == peer.slot) {
            stale = (int)index;
        }
    }
    if (!create) return -1;
    if (stale >= 0) {
        struct hs_tx_peer_sync *entry = &state->peer_sync[stale];
        if (peer_has_live_tx(state, entry->peer)) return -1;
        memset(entry, 0, sizeof(*entry));
        entry->peer = peer;
        entry->live = 1;
        entry->sync_pending = 1;
        return stale;
    }
    if (empty >= 0) {
        struct hs_tx_peer_sync *entry = &state->peer_sync[empty];
        entry->peer = peer;
        entry->live = 1;
        entry->sync_pending = 1;
        return empty;
    }
    return -1;
}

static int ranges_overlap(const void *left, size_t left_size,
                          const void *right, size_t right_size)
{
    uintptr_t a, b;

    if (left_size == 0U || right_size == 0U || left == NULL || right == NULL) return 0;
    a = (uintptr_t)left;
    b = (uintptr_t)right;
    if (left_size > UINTPTR_MAX - a || right_size > UINTPTR_MAX - b) return 1;
    return a < b + right_size && b < a + left_size;
}

/* The binding's max_frame_bytes applies to one complete Stream R wire frame,
 * while the configured limit applies to decoded Core bytes. The open/reset
 * synchronization delimiter is a separate one-byte operation, not frame MTU. */
static int stream_wire_bound(size_t core_size, size_t *bound)
{
    size_t encoded_bound = 0U;

    if (bound == NULL ||
        dmp_stream_encoded_bound(DMP_STREAM_R, core_size, &encoded_bound) != DMP_OK) {
        return 0;
    }
    *bound = encoded_bound;
    return 1;
}

static int transport_wire_bound(const dmp_hs_tx *state, size_t core_size,
                                size_t *bound)
{
    if (state->config.framing == DMP_HS_TX_STREAM_R) {
        return stream_wire_bound(core_size, bound);
    }
    if (state->config.framing == DMP_HS_TX_CORE_PACKET && bound != NULL) {
        *bound = core_size;
        return 1;
    }
    return 0;
}

static size_t effective_core_limit(const dmp_hs_tx *state)
{
    size_t core_limit = state->config.max_core_frame_bytes;
    size_t wire_bound = 0U;

    if (state->transport->caps.max_frame_bytes == 0U) return core_limit;
    while (core_limit >= 32U) {
        if (transport_wire_bound(state, core_limit, &wire_bound) &&
            wire_bound <= state->transport->caps.max_frame_bytes) {
            return core_limit;
        }
        core_limit--;
    }
    return 0U;
}

static int token_matches(const struct hs_tx_slot *slot, dmp_tx_token token,
                         uint32_t index)
{
    return slot->live && token.slot == index && token.generation != 0U &&
           slot->token_generation == token.generation;
}

static int attempt_is_current_active(dmp_hs_tx *state, const struct hs_tx_slot *slot)
{
    return dmp_hs_generation(state->handshake, slot->attempt_index) ==
               slot->handshake_generation &&
           dmp_hs_view_of(state->handshake, slot->attempt_index) == DMP_HS_VIEW_ACTIVE;
}

static void abort_attempt_if_current(dmp_hs_tx *state, const struct hs_tx_slot *slot)
{
    if (dmp_hs_generation(state->handshake, slot->attempt_index) ==
        slot->handshake_generation &&
        !dmp_hs_terminal(state->handshake, slot->attempt_index)) {
        (void)dmp_hs_cancel(state->handshake, slot->attempt_index);
    }
}

static void tx_complete(void *owner, dmp_tx_token token, dmp_tx_outcome outcome,
                        dmp_time_ms when)
{
    dmp_hs_tx *state = (dmp_hs_tx *)owner;
    struct hs_tx_slot *slot;

    if (!state_live(state) || token.slot >= DMP_HS_TX_SLOT_MAX) {
        return;
    }
    slot = &state->slots[token.slot];
    if (!token_matches(slot, token, token.slot) || slot->result_ready) {
        return;
    }
    if (outcome < DMP_TX_TRANSMITTED || outcome > DMP_TX_POSSIBLY_TRANSMITTED) {
        outcome = DMP_TX_POSSIBLY_TRANSMITTED;
    }
    if (!slot->sync_action && when >= slot->deadline_ms &&
        !attempt_is_current_active(state, slot)) {
        slot->expired = 1;
        abort_attempt_if_current(state, slot);
    }
    slot->outcome = outcome;
    slot->completed_at = when;
    slot->result_ready = 1;
    if (slot->accepted && slot->sync_action && outcome == DMP_TX_TRANSMITTED) {
        int sync_index = peer_sync_index(state, slot->peer, 0);
        if (sync_index >= 0) state->peer_sync[sync_index].sync_pending = 0;
    }
}

static size_t uleb32(uint8_t *out, uint32_t value)
{
    size_t count = 0U;
    do {
        uint8_t byte = (uint8_t)(value & 0x7FU);
        value >>= 7U;
        if (value != 0U) byte |= 0x80U;
        out[count++] = byte;
    } while (value != 0U);
    return count;
}

static void store_le64(uint8_t *out, uint64_t value)
{
    size_t i;
    for (i = 0U; i < 8U; ++i) out[i] = (uint8_t)(value >> (8U * i));
}

static int bootstrap_flight(const uint8_t *payload, size_t length, uint32_t *sequence)
{
    if (payload == NULL || sequence == NULL || length < 2U || length > DMP_HS_PAYLOAD_MAX ||
        payload[0] != DMP_HS_BOOT_VERSION) {
        return 0;
    }
    if (length >= 4U && payload[3] == 1U) {
        *sequence = 1U;
        return 1;
    }
    if (payload[1] == 2U || payload[1] == 3U) {
        *sequence = payload[1];
        return 1;
    }
    return 0;
}

static int bootstrap_extensions(const dmp_hs_bootstrap_context *context,
                                uint8_t *extensions, size_t capacity,
                                size_t *length)
{
    uint8_t value[16];
    size_t namespace_len;
    size_t used = 0U;

    namespace_len = uleb32(value, context->namespace_id);
    store_le64(value + namespace_len, context->provisional_epoch);
    if (used + 2U + namespace_len + 8U > capacity) return 0;
    extensions[used++] = DMP_HS_CONTEXT_TAG;
    extensions[used++] = (uint8_t)(namespace_len + 8U);
    memcpy(extensions + used, value, namespace_len + 8U);
    used += namespace_len + 8U;
    if (context->route_ttl == 0U) {
        size_t origin_len = uleb32(value, context->origin_id);
        extensions[used++] = DMP_HS_ORIGIN_TAG;
        extensions[used++] = (uint8_t)origin_len;
        memcpy(extensions + used, value, origin_len);
        used += origin_len;
    }
    *length = used;
    return 1;
}

static int build_bootstrap_spec(const dmp_hs_bootstrap_context *context,
                                uint32_t sequence, size_t chunk_size,
                                size_t total_size, size_t fragment_index,
                                size_t fragment_count, dmp_bytes payload,
                                uint8_t *extensions, size_t extension_capacity,
                                size_t *extension_size, dmp_frame_spec *spec)
{
    if (!bootstrap_extensions(context, extensions, extension_capacity, extension_size)) {
        return 0;
    }
    memset(spec, 0, sizeof(*spec));
    spec->fields.type = DMP_TYPE_HELLO;
    spec->fields.options = DMP_OPT_SEQ | DMP_OPT_EXT | DMP_OPT_INTEGRITY;
    spec->fields.seq = sequence;
    if (context->route_ttl != 0U) {
        spec->fields.options |= DMP_OPT_ROUTE;
        spec->fields.route.mode = 1U; /* TO_NODE */
        spec->fields.route.ttl = context->route_ttl;
        spec->fields.route.source = context->origin_id;
        spec->fields.route.destination = context->destination_id;
    }
    if (fragment_count > 1U) {
        if (fragment_index >= fragment_count || fragment_count > DMP_HS_BOOT_MAX_FRAGMENTS ||
            chunk_size > UINT32_MAX || total_size > UINT32_MAX) return 0;
        spec->fields.options |= DMP_OPT_FRAG;
        spec->fields.fragment.index = (uint32_t)fragment_index;
        spec->fields.fragment.chunk_size = (uint32_t)chunk_size;
        spec->fields.fragment.total_size = (uint32_t)total_size;
    }
    spec->fields.integrity = 1U;
    spec->extensions.data = extensions;
    spec->extensions.size = *extension_size;
    spec->payload = payload;
    spec->trailer.size = 4U;
    return 1;
}

static dmp_status bootstrap_header_size(dmp_hs_tx *state,
                                        const dmp_hs_bootstrap_context *context,
                                        uint32_t sequence, size_t chunk_size,
                                        size_t total_size, size_t fragment_index,
                                        size_t fragment_count, size_t *header_size)
{
    uint8_t extensions[32];
    size_t extension_size = 0U;
    size_t written = 0U;
    dmp_frame_spec spec;
    dmp_core_limits limits = { DMP_HS_TX_CORE_MAX, DMP_HS_PAYLOAD_MAX,
                               DMP_HS_BOOT_MAX_FRAGMENTS };
    dmp_status status;

    if (!build_bootstrap_spec(context, sequence, chunk_size, total_size,
                              fragment_index, fragment_count,
                              (dmp_bytes){ NULL, chunk_size }, extensions,
                              sizeof(extensions), &extension_size, &spec)) {
        return DMP_INVALID_ARGUMENT;
    }
    status = dmp_core_encode_header(&spec, &limits,
                                    (dmp_buffer){ state->core_scratch,
                                                  sizeof(state->core_scratch) },
                                    &written);
    if (status == DMP_OK) *header_size = written;
    return status;
}

static dmp_hs_tx_status bootstrap_geometry_of(dmp_hs_tx *state,
                                               uint32_t attempt_index,
                                               bootstrap_geometry *geometry)
{
    const uint8_t *payload;
    size_t length = 0U;
    size_t chunk;
    uint32_t sequence;
    size_t header_size;
    size_t core_limit = effective_core_limit(state);
    dmp_status status;

    payload = dmp_hs_cached_flight(state->handshake, attempt_index, &length);
    if (core_limit == 0U || !bootstrap_flight(payload, length, &sequence) ||
        !dmp_hs_bootstrap_context_of(state->handshake, attempt_index,
                                     &geometry->context)) {
        return DMP_HS_TX_NO_OUTPUT;
    }
    geometry->sequence = sequence;
    geometry->payload_size = length;
    status = bootstrap_header_size(state, &geometry->context, sequence, length,
                                   length, 0U, 1U, &header_size);
    if (status == DMP_OK && header_size + length + 4U <= core_limit) {
        geometry->chunk_size = length;
        geometry->fragment_count = 1U;
        return DMP_HS_TX_ACCEPTED;
    }
    for (chunk = length; chunk != 0U; --chunk) {
        size_t count = (length + chunk - 1U) / chunk;
        size_t worst_index = count - 1U;
        if (count > state->config.max_bootstrap_fragments ||
            count > DMP_HS_BOOT_MAX_FRAGMENTS) continue;
        status = bootstrap_header_size(state, &geometry->context, sequence, chunk,
                                       length, worst_index, count, &header_size);
        if (status == DMP_OK && header_size + chunk + 4U <= core_limit) {
            geometry->chunk_size = chunk;
            geometry->fragment_count = count;
            return DMP_HS_TX_ACCEPTED;
        }
    }
    return DMP_HS_TX_INVALID;
}

static dmp_hs_tx_status encode_bootstrap_core(dmp_hs_tx *state,
                                              uint32_t attempt_index,
                                              size_t fragment_index,
                                              bootstrap_geometry *geometry,
                                              size_t *core_size)
{
    const uint8_t *source;
    size_t source_len = 0U;
    size_t offset, slice_len, header_size = 0U, extension_size = 0U;
    uint8_t extensions[32];
    uint32_t crc;
    size_t written = 0U;
    dmp_frame_spec spec;
    dmp_core_limits limits = { DMP_HS_TX_CORE_MAX, DMP_HS_PAYLOAD_MAX,
                               DMP_HS_BOOT_MAX_FRAGMENTS };
    dmp_status status;

    source = dmp_hs_cached_flight(state->handshake, attempt_index, &source_len);
    if (source == NULL || source_len != geometry->payload_size ||
        fragment_index >= geometry->fragment_count) return DMP_HS_TX_STALE;
    offset = fragment_index * geometry->chunk_size;
    slice_len = source_len - offset;
    if (slice_len > geometry->chunk_size) slice_len = geometry->chunk_size;
    if (!build_bootstrap_spec(&geometry->context, geometry->sequence,
                              geometry->chunk_size, geometry->payload_size,
                              fragment_index, geometry->fragment_count,
                              (dmp_bytes){ source + offset, slice_len }, extensions,
                              sizeof(extensions), &extension_size, &spec)) {
        return DMP_HS_TX_INVALID;
    }
    spec.trailer.size = 4U;
    status = dmp_core_encode_header(&spec, &limits,
                                    (dmp_buffer){ state->core_scratch,
                                                  sizeof(state->core_scratch) },
                                    &header_size);
    if (status != DMP_OK || header_size + slice_len + 4U > sizeof(state->core_scratch) ||
        header_size + slice_len + 4U > effective_core_limit(state)) {
        return DMP_HS_TX_INVALID;
    }
    memcpy(state->core_scratch + header_size, source + offset, slice_len);
    status = dmp_crc32c((dmp_bytes){ state->core_scratch, header_size + slice_len }, &crc);
    if (status != DMP_OK) return DMP_HS_TX_INVALID;
    state->core_scratch[header_size + slice_len] = (uint8_t)crc;
    state->core_scratch[header_size + slice_len + 1U] = (uint8_t)(crc >> 8U);
    state->core_scratch[header_size + slice_len + 2U] = (uint8_t)(crc >> 16U);
    state->core_scratch[header_size + slice_len + 3U] = (uint8_t)(crc >> 24U);
    *core_size = header_size + slice_len + 4U;
    (void)written;
    return DMP_HS_TX_ACCEPTED;
}

size_t dmp_hs_tx_size(void)
{
    return sizeof(dmp_hs_tx);
}

dmp_hs_tx_status dmp_hs_tx_init(dmp_hs_tx *state, dmp_hs *handshake,
                                dmp_transport *transport,
                                const dmp_hs_tx_config *config,
                                dmp_hs_tx_lifetime *lifetime,
                                const dmp_hs_tx_buffer buffers[DMP_HS_TX_SLOT_MAX])
{
    size_t encoded_bound;
    uint32_t i;

    if (state == NULL || handshake == NULL || transport == NULL || config == NULL ||
        lifetime == NULL || buffers == NULL || transport->submit == NULL ||
        transport->cancel == NULL ||
        (transport->caps.ownership != DMP_TX_COPY &&
         transport->caps.ownership != DMP_TX_BORROW) ||
        config->max_core_frame_bytes < 32U ||
        config->max_core_frame_bytes > DMP_HS_TX_CORE_MAX ||
        (config->framing != DMP_HS_TX_STREAM_R &&
         config->framing != DMP_HS_TX_CORE_PACKET) ||
        config->max_bootstrap_fragments == 0U ||
        config->max_bootstrap_fragments > DMP_HS_BOOT_MAX_FRAGMENTS ||
        (config->framing == DMP_HS_TX_STREAM_R &&
         (dmp_stream_encoded_bound(DMP_STREAM_R, config->max_core_frame_bytes,
                                   &encoded_bound) != DMP_OK ||
          encoded_bound == SIZE_MAX))) {
        return DMP_HS_TX_INVALID;
    }
    if (config->framing == DMP_HS_TX_CORE_PACKET) encoded_bound = config->max_core_frame_bytes;
    if (state->magic == DMP_HS_TX_MAGIC) {
        if (state->lifetime != lifetime) return DMP_HS_TX_INVALID;
        for (i = 0U; i < DMP_HS_TX_SLOT_MAX; ++i) {
            if (state->slots[i].live) return DMP_HS_TX_BUSY;
        }
    }
    for (i = 0U; i < DMP_HS_TX_SLOT_MAX; ++i) {
        uint32_t j;
        if (buffers[i].data == NULL || buffers[i].capacity < encoded_bound) {
            return DMP_HS_TX_INVALID;
        }
        if (ranges_overlap(state, sizeof(*state), buffers[i].data, buffers[i].capacity)) {
            return DMP_HS_TX_INVALID;
        }
        for (j = 0U; j < i; ++j) {
            if (ranges_overlap(buffers[i].data, buffers[i].capacity,
                              buffers[j].data, buffers[j].capacity)) return DMP_HS_TX_INVALID;
        }
    }
    memset(state, 0, sizeof(*state));
    state->handshake = handshake;
    state->transport = transport;
    state->lifetime = lifetime;
    state->config = *config;
    for (i = 0U; i < DMP_HS_TX_SLOT_MAX; ++i) state->buffers[i] = buffers[i];
    state->magic = DMP_HS_TX_MAGIC;
    return DMP_HS_TX_ACCEPTED;
}

dmp_hs_tx_status dmp_hs_tx_sync(dmp_hs_tx *state, dmp_peer_handle peer,
                                dmp_tx_token *token)
{
    dmp_tx_submission submission;
    struct hs_tx_slot *slot;
    uint32_t index;
    int sync_index;
    dmp_tx_token local_token;
    dmp_status status;

    if (!state_live(state) || token == NULL || peer.generation == 0U) {
        return DMP_HS_TX_INVALID;
    }
    if (state->config.framing != DMP_HS_TX_STREAM_R) {
        return DMP_HS_TX_NO_OUTPUT;
    }
    sync_index = peer_sync_index(state, peer, 1);
    if (sync_index < 0) return DMP_HS_TX_NO_SLOT;
    if (!state->peer_sync[sync_index].sync_pending) return DMP_HS_TX_NO_OUTPUT;
    for (index = 0U; index < DMP_HS_TX_SLOT_MAX; ++index) {
        if (state->slots[index].live && state->slots[index].sync_action &&
            same_peer(state->slots[index].peer, peer)) {
            return DMP_HS_TX_BUSY;
        }
    }
    for (index = 0U; index < DMP_HS_TX_SLOT_MAX; ++index) {
        if (!state->slots[index].live) break;
    }
    if (index == DMP_HS_TX_SLOT_MAX) return DMP_HS_TX_NO_SLOT;
    slot = &state->slots[index];
    memset(slot, 0, sizeof(*slot));
    slot->live = 1;
    slot->sync_action = 1;
    slot->peer = peer;
    slot->deadline_ms = UINT64_MAX;
    if (dmp_generation_next(state->lifetime->token_generation,
                            &state->lifetime->token_generation) != DMP_OK) {
        memset(slot, 0, sizeof(*slot));
        return DMP_HS_TX_INVALID;
    }
    slot->token_generation = state->lifetime->token_generation;
    local_token.slot = index;
    local_token.generation = slot->token_generation;
    state->sync_byte = 0U;
    memset(&submission, 0, sizeof(submission));
    submission.token = local_token;
    submission.peer = peer;
    submission.frame.data = &state->sync_byte;
    submission.frame.size = 1U;
    submission.not_after = UINT64_MAX;
    submission.complete = tx_complete;
    submission.owner = state;
    status = state->transport->submit(state->transport->context, &submission);
    if (status != DMP_OK) {
        if (slot->result_ready) {
            /* A callback for a rejected submit violates the binding contract. */
            slot->outcome = DMP_TX_POSSIBLY_TRANSMITTED;
            slot->accepted = 1;
            *token = local_token;
            return DMP_HS_TX_ACCEPTED;
        }
        memset(slot, 0, sizeof(*slot));
        return status == DMP_BUSY ? DMP_HS_TX_BUSY : DMP_HS_TX_TRANSPORT_REJECTED;
    }
    slot->accepted = 1;
    if (slot->result_ready && slot->outcome == DMP_TX_TRANSMITTED) {
        state->peer_sync[sync_index].sync_pending = 0;
    }
    *token = local_token;
    return DMP_HS_TX_ACCEPTED;
}

dmp_hs_tx_status dmp_hs_tx_binding_reset(dmp_hs_tx *state,
                                         dmp_peer_handle peer)
{
    uint32_t index;
    int sync_index;

    if (!state_live(state) || peer.generation == 0U) return DMP_HS_TX_INVALID;
    if (state->config.framing != DMP_HS_TX_STREAM_R) return DMP_HS_TX_ACCEPTED;
    sync_index = peer_sync_index(state, peer, 1);
    if (sync_index < 0) return DMP_HS_TX_NO_SLOT;
    for (index = 0U; index < DMP_HS_TX_SLOT_MAX; ++index) {
        if (state->slots[index].live && same_peer(state->slots[index].peer, peer)) {
            return DMP_HS_TX_BUSY;
        }
    }
    state->peer_sync[sync_index].sync_pending = 1;
    state->sync_byte = 0U;
    return DMP_HS_TX_ACCEPTED;
}

dmp_hs_tx_status dmp_hs_tx_fragment_plan(dmp_hs_tx *state,
                                         uint32_t attempt_index,
                                         dmp_hs_tx_output output,
                                         size_t *fragment_count,
                                         size_t *chunk_size)
{
    bootstrap_geometry geometry;
    const uint8_t *frame;
    size_t frame_len = 0U;
    size_t wire_bound = 0U;

    if (!state_live(state) || attempt_index >= DMP_HS_ATTEMPT_MAX ||
        fragment_count == NULL || chunk_size == NULL) return DMP_HS_TX_INVALID;
    if (dmp_hs_terminal(state->handshake, attempt_index)) return DMP_HS_TX_STALE;
    if (output == DMP_HS_TX_CACHED_FLIGHT) {
        dmp_hs_tx_status planned = bootstrap_geometry_of(state, attempt_index, &geometry);
        if (planned != DMP_HS_TX_ACCEPTED) return planned;
        *fragment_count = geometry.fragment_count;
        *chunk_size = geometry.chunk_size;
        return DMP_HS_TX_ACCEPTED;
    }
    if (output != DMP_HS_TX_PROTECTED_FRAME) return DMP_HS_TX_INVALID;
    frame = dmp_hs_protected_frame(state->handshake, attempt_index, &frame_len);
    if (frame == NULL || frame_len == 0U) return DMP_HS_TX_NO_OUTPUT;
    if (frame_len > state->config.max_core_frame_bytes ||
        !transport_wire_bound(state, frame_len, &wire_bound) ||
        (state->transport->caps.max_frame_bytes != 0U &&
         wire_bound > state->transport->caps.max_frame_bytes)) return DMP_HS_TX_INVALID;
    *fragment_count = 1U;
    *chunk_size = frame_len;
    return DMP_HS_TX_ACCEPTED;
}

dmp_hs_tx_status dmp_hs_tx_submit(dmp_hs_tx *state, uint32_t attempt_index,
                                  dmp_hs_tx_output output, dmp_peer_handle peer,
                                  size_t fragment_index, dmp_time_ms now_ms,
                                  dmp_tx_token *token)
{
    uint64_t hs_generation, deadline;
    uint32_t index;
    struct hs_tx_slot *slot;
    dmp_hs_tx_status planned;
    size_t fragment_count, chunk_size, core_size = 0U, encoded_size = 0U;
    bootstrap_geometry geometry;
    const uint8_t *source;
    size_t source_len = 0U;
    dmp_status status;
    dmp_hs_status hs_status;
    dmp_tx_submission submission;
    dmp_tx_token local_token;

    if (!state_live(state) || token == NULL || attempt_index >= DMP_HS_ATTEMPT_MAX ||
        (output != DMP_HS_TX_CACHED_FLIGHT && output != DMP_HS_TX_PROTECTED_FRAME) ||
        peer.generation == 0U) return DMP_HS_TX_INVALID;
    hs_generation = dmp_hs_generation(state->handshake, attempt_index);
    deadline = dmp_hs_deadline(state->handshake, attempt_index);
    if (hs_generation == 0U || dmp_hs_terminal(state->handshake, attempt_index)) return DMP_HS_TX_STALE;
    if (now_ms >= deadline) {
        (void)dmp_hs_cancel(state->handshake, attempt_index);
        return DMP_HS_TX_EXPIRED;
    }
    if (state->config.framing == DMP_HS_TX_STREAM_R) {
        int sync_index = peer_sync_index(state, peer, 0);
        if (sync_index < 0 || state->peer_sync[sync_index].sync_pending) {
            return DMP_HS_TX_BUSY;
        }
    }
    planned = dmp_hs_tx_fragment_plan(state, attempt_index, output,
                                      &fragment_count, &chunk_size);
    if (planned != DMP_HS_TX_ACCEPTED) return planned;
    if (fragment_index >= fragment_count) return DMP_HS_TX_INVALID;
    if (output == DMP_HS_TX_CACHED_FLIGHT) {
        hs_status = dmp_hs_cached_flight_tx_check(state->handshake, attempt_index,
                                                   (uint32_t)fragment_count,
                                                   (uint32_t)fragment_index);
        if (hs_status != DMP_HS_OK) {
            return hs_status == DMP_HS_REFUSED ? DMP_HS_TX_REFUSED :
                   hs_status == DMP_HS_INVALID ? DMP_HS_TX_INVALID : DMP_HS_TX_STALE;
        }
    }

    for (index = 0U; index < DMP_HS_TX_SLOT_MAX; ++index) {
        if (!state->slots[index].live) break;
    }
    if (index == DMP_HS_TX_SLOT_MAX) return DMP_HS_TX_NO_SLOT;
    slot = &state->slots[index];
    memset(slot, 0, sizeof(*slot));
    slot->live = 1;
    slot->attempt_index = attempt_index;
    slot->peer = peer;
    slot->handshake_generation = hs_generation;
    slot->deadline_ms = deadline;
    slot->sync_action = 0;
    if (dmp_generation_next(state->lifetime->token_generation,
                            &state->lifetime->token_generation) != DMP_OK) {
        memset(slot, 0, sizeof(*slot));
        return DMP_HS_TX_INVALID;
    }
    slot->token_generation = state->lifetime->token_generation;
    hs_status = dmp_hs_retain_tx_reservation(state->handshake, attempt_index,
                                             &slot->reservation);
    if (hs_status != DMP_HS_OK) {
        memset(slot, 0, sizeof(*slot));
        return hs_status == DMP_HS_REFUSED ? DMP_HS_TX_REFUSED : DMP_HS_TX_STALE;
    }

    if (output == DMP_HS_TX_CACHED_FLIGHT) {
        planned = bootstrap_geometry_of(state, attempt_index, &geometry);
        if (planned != DMP_HS_TX_ACCEPTED || fragment_index >= geometry.fragment_count) {
            (void)dmp_hs_release_tx_reservation(state->handshake, &slot->reservation);
            memset(slot, 0, sizeof(*slot));
            return planned == DMP_HS_TX_ACCEPTED ? DMP_HS_TX_INVALID : planned;
        }
        planned = encode_bootstrap_core(state, attempt_index, fragment_index,
                                        &geometry, &core_size);
        if (planned != DMP_HS_TX_ACCEPTED) {
            (void)dmp_hs_release_tx_reservation(state->handshake, &slot->reservation);
            memset(slot, 0, sizeof(*slot));
            return planned;
        }
    } else {
        source = dmp_hs_protected_frame(state->handshake, attempt_index, &source_len);
        if (fragment_index != 0U || source == NULL || source_len == 0U ||
            source_len > state->config.max_core_frame_bytes) {
            (void)dmp_hs_release_tx_reservation(state->handshake, &slot->reservation);
            memset(slot, 0, sizeof(*slot));
            return DMP_HS_TX_INVALID;
        }
        if (state->config.framing == DMP_HS_TX_STREAM_R) {
            status = dmp_stream_encode(DMP_STREAM_R,
                                       (dmp_bytes){ source, source_len },
                                       (dmp_buffer){ state->buffers[index].data,
                                                     state->buffers[index].capacity },
                                       &encoded_size);
        } else {
            memcpy(state->buffers[index].data, source, source_len);
            encoded_size = source_len;
            status = DMP_OK;
        }
        if (status != DMP_OK) {
            (void)dmp_hs_release_tx_reservation(state->handshake, &slot->reservation);
            memset(state->buffers[index].data, 0, state->buffers[index].capacity);
            memset(slot, 0, sizeof(*slot));
            return DMP_HS_TX_INVALID;
        }
    }
    if (output == DMP_HS_TX_CACHED_FLIGHT) {
        if (state->config.framing == DMP_HS_TX_STREAM_R) {
            status = dmp_stream_encode(DMP_STREAM_R,
                                       (dmp_bytes){ state->core_scratch, core_size },
                                       (dmp_buffer){ state->buffers[index].data,
                                                     state->buffers[index].capacity },
                                       &encoded_size);
        } else {
            memcpy(state->buffers[index].data, state->core_scratch, core_size);
            encoded_size = core_size;
            status = DMP_OK;
        }
        if (status != DMP_OK) {
            (void)dmp_hs_release_tx_reservation(state->handshake, &slot->reservation);
            memset(state->buffers[index].data, 0, state->buffers[index].capacity);
            memset(slot, 0, sizeof(*slot));
            return DMP_HS_TX_INVALID;
        }
    }
    (void)chunk_size;
    if (state->transport->caps.max_frame_bytes != 0U &&
        encoded_size > state->transport->caps.max_frame_bytes) {
        (void)dmp_hs_release_tx_reservation(state->handshake, &slot->reservation);
        memset(state->buffers[index].data, 0, encoded_size);
        memset(slot, 0, sizeof(*slot));
        return DMP_HS_TX_INVALID;
    }
    local_token.slot = index;
    local_token.generation = slot->token_generation;
    memset(&submission, 0, sizeof(submission));
    submission.token = local_token;
    submission.peer = peer;
    submission.frame.data = state->buffers[index].data;
    submission.frame.size = encoded_size;
    submission.not_after = deadline;
    submission.complete = tx_complete;
    submission.owner = state;
    status = state->transport->submit(state->transport->context, &submission);
    if (status != DMP_OK) {
        if (slot->result_ready) {
            /* A callback for a rejected submit violates the binding contract. */
            slot->outcome = DMP_TX_POSSIBLY_TRANSMITTED;
            slot->accepted = 1;
            if (output == DMP_HS_TX_CACHED_FLIGHT) {
                (void)dmp_hs_cached_flight_tx_accept(state->handshake, attempt_index,
                                                      (uint32_t)fragment_count,
                                                      (uint32_t)fragment_index);
            }
            *token = local_token;
            return DMP_HS_TX_ACCEPTED;
        }
        if (output == DMP_HS_TX_CACHED_FLIGHT) {
            /* No callback follows a rejected submit. Return an unused retry
             * grant on pre-accept BUSY/rejection; accepted earlier slices keep
             * the flight permit pinned until the remaining fragments settle. */
            (void)dmp_hs_cached_flight_tx_reject(state->handshake, attempt_index);
        }
        (void)dmp_hs_release_tx_reservation(state->handshake, &slot->reservation);
        memset(state->buffers[index].data, 0, encoded_size);
        memset(slot, 0, sizeof(*slot));
        return status == DMP_BUSY ? DMP_HS_TX_BUSY : DMP_HS_TX_TRANSPORT_REJECTED;
    }
    slot->accepted = 1;
    if (output == DMP_HS_TX_CACHED_FLIGHT) {
        (void)dmp_hs_cached_flight_tx_accept(state->handshake, attempt_index,
                                              (uint32_t)fragment_count,
                                              (uint32_t)fragment_index);
    }
    *token = local_token;
    return DMP_HS_TX_ACCEPTED;
}

static dmp_hs_tx_status request_cancel(dmp_hs_tx *state, struct hs_tx_slot *slot,
                                       uint32_t index)
{
    dmp_tx_token token = { index, slot->token_generation };
    dmp_status status;

    if (slot->cancellation_requested) return DMP_HS_TX_ACCEPTED;
    status = state->transport->cancel(state->transport->context, token);
    if (status == DMP_OK) slot->cancellation_requested = 1;
    /* Keep admission tokens and frame storage pinned even if cancel refuses. */
    if (!slot->sync_action) abort_attempt_if_current(state, slot);
    return status == DMP_OK ? DMP_HS_TX_ACCEPTED : DMP_HS_TX_TRANSPORT_REJECTED;
}

dmp_hs_tx_status dmp_hs_tx_cancel(dmp_hs_tx *state, dmp_tx_token token)
{
    struct hs_tx_slot *slot;
    if (!state_live(state) || token.slot >= DMP_HS_TX_SLOT_MAX || token.generation == 0U)
        return DMP_HS_TX_INVALID;
    slot = &state->slots[token.slot];
    if (!token_matches(slot, token, token.slot) || slot->result_ready) return DMP_HS_TX_STALE;
    return request_cancel(state, slot, token.slot);
}

void dmp_hs_tx_expire(dmp_hs_tx *state, dmp_time_ms now_ms)
{
    uint32_t i;
    if (!state_live(state)) return;
    for (i = 0U; i < DMP_HS_TX_SLOT_MAX; ++i) {
        struct hs_tx_slot *slot = &state->slots[i];
        if (slot->live && !slot->result_ready && now_ms >= slot->deadline_ms) {
            /* READY may activate the attempt while its accepted transport
             * callback is still delayed. The old handshake deadline no
             * longer expires that active association; keep the slot pinned
             * until the transport settles it. */
            if (!slot->sync_action && attempt_is_current_active(state, slot)) continue;
            slot->expired = 1;
            (void)request_cancel(state, slot, i);
        }
    }
}

dmp_hs_tx_status dmp_hs_tx_take(dmp_hs_tx *state, dmp_hs_tx_result *result)
{
    uint32_t i;
    if (!state_live(state) || result == NULL) return DMP_HS_TX_INVALID;
    for (i = 0U; i < DMP_HS_TX_SLOT_MAX; ++i) {
        struct hs_tx_slot *slot = &state->slots[i];
        if (!slot->live || !slot->result_ready) continue;
        result->token.slot = i;
        result->token.generation = slot->token_generation;
        result->attempt_index = slot->attempt_index;
        result->handshake_generation = slot->handshake_generation;
        result->outcome = slot->outcome;
        result->completed_at = slot->completed_at;
        result->synchronization = slot->sync_action;
        result->expired = slot->expired;
        result->cancellation_requested = slot->cancellation_requested;
        if (!slot->sync_action &&
            dmp_hs_release_tx_reservation(state->handshake,
                                          &slot->reservation) != DMP_HS_OK) {
            return DMP_HS_TX_STALE;
        }
        if (slot->sync_action) state->sync_byte = 0U;
        else memset(state->buffers[i].data, 0, state->buffers[i].capacity);
        memset(slot, 0, sizeof(*slot));
        return DMP_HS_TX_ACCEPTED;
    }
    return DMP_HS_TX_NO_OUTPUT;
}
