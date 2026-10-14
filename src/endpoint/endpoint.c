#include "dmp/endpoint.h"

#include "../security/handshake.h"

#include <string.h>

#define PEER(endpoint, field) ((endpoint)->peers[(endpoint)->active_peer_slot].field)

static void freshness_consume_key(dmp_endpoint *endpoint, dmp_message_key key,
                                  uint32_t service);
static void freshness_consume_frame(dmp_endpoint *endpoint, const dmp_frame_view *frame,
                                    uint32_t service, dmp_identity_handle context,
                                    dmp_time_ms now);
static void use_context(dmp_endpoint *endpoint, dmp_identity_handle handle);
static void release_peer_buffer_contexts(dmp_endpoint *endpoint,
                                         dmp_endpoint_peer_state *peer);
static int freshness_command(uint8_t type);
static void freshness_maintenance(dmp_endpoint *endpoint, dmp_time_ms now);
static void freshness_clear_attempt(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                    uint32_t attempt);

/* Endpoint codec. Reliability owns unfragmented retry, duplicate
 * suppression, receipts and results. Reassembly owns fixed-stride fragments.
 * SEC-1 records are the P14 seal/open path. RADIO-1 origin_route emits
 * TO_NODE and the sender's own CONTEXT; DIRECT-1 leaves both off.
 * This file does not allocate, parse JSON, or hash epochs on receive. */

enum { KIND_REL = 0, KIND_FRAG = 1, KIND_TELEM = 2, KIND_STATUS = 3, KIND_SYNC = 4 };

static int ready(const dmp_endpoint *endpoint)
{
    return endpoint != NULL && endpoint->initialized != 0U;
}

static dmp_status select_peer(dmp_endpoint *endpoint, dmp_peer_handle handle)
{
    dmp_endpoint_peer_state *peer;
    if (endpoint == NULL || handle.generation == 0U || handle.slot >= endpoint->profile.peers ||
        handle.slot >= DMP_PROFILE_MAX_PEERS) {
        return DMP_INVALID_ARGUMENT;
    }
    peer = &endpoint->peers[handle.slot];
    if (peer->live == 0U || peer->handle.slot != handle.slot ||
        peer->handle.generation != handle.generation) {
        return DMP_STALE_HANDLE;
    }
    endpoint->active_peer_slot = handle.slot;
    return DMP_OK;
}

static int peer_equal(dmp_peer_handle a, dmp_peer_handle b)
{
    return a.slot == b.slot && a.generation == b.generation;
}

static dmp_status select_active_route(dmp_endpoint *endpoint)
{
    if (PEER(endpoint, live) == 0U) {
        return DMP_STALE_HANDLE;
    }
    return dmp_reliability_select_route(&endpoint->reliability, PEER(endpoint, handle),
                                        PEER(endpoint, context));
}

static int peer_owns_context(const dmp_endpoint_peer_state *peer, dmp_identity_handle context)
{
    return (peer->context.slot == context.slot && peer->context.generation == context.generation) ||
           (peer->drain_live != 0U && peer->drain_context.slot == context.slot &&
            peer->drain_context.generation == context.generation);
}

static dmp_peer_handle peer_for_context(const dmp_endpoint *endpoint,
                                        dmp_identity_handle context, int *found)
{
    uint32_t i;
    dmp_peer_handle none = {0U, 0U};
    *found = 0;
    for (i = 0U; i < endpoint->profile.peers; i++) {
        if (endpoint->peers[i].live != 0U && peer_owns_context(&endpoint->peers[i], context)) {
            *found = 1;
            return endpoint->peers[i].handle;
        }
    }
    return none;
}

static uint32_t local_core_mtu(const dmp_endpoint *endpoint)
{
    const dmp_endpoint_peer_state *peer = &endpoint->peers[endpoint->active_peer_slot];
    const dmp_identity_slot *slot;
    if (peer->context.slot >= endpoint->identity.capacity) {
        return 0U;
    }
    slot = &endpoint->identity.slots[peer->context.slot];
    if (slot->generation != peer->context.generation) {
        return 0U;
    }
    if (slot->local.origin_id == endpoint->profile.node_id[0]) {
        return endpoint->profile.forward_mtu;
    }
    if (slot->local.origin_id == endpoint->profile.node_id[1]) {
        return endpoint->profile.return_mtu;
    }
    return 0U;
}

static uint32_t receive_core_mtu(const dmp_endpoint *endpoint)
{
    const dmp_endpoint_peer_state *peer = &endpoint->peers[endpoint->active_peer_slot];
    const dmp_identity_slot *slot;
    if (peer->context.slot >= endpoint->identity.capacity) {
        return 0U;
    }
    slot = &endpoint->identity.slots[peer->context.slot];
    if (slot->generation != peer->context.generation) {
        return 0U;
    }
    if (slot->local.origin_id == endpoint->profile.node_id[0]) {
        return endpoint->profile.return_mtu;
    }
    if (slot->local.origin_id == endpoint->profile.node_id[1]) {
        return endpoint->profile.forward_mtu;
    }
    return 0U;
}

static uint32_t max_core_mtu(const dmp_admitted_profile *profile)
{
    return profile->forward_mtu > profile->return_mtu ? profile->forward_mtu
                                                      : profile->return_mtu;
}

static uint8_t *peer_fragment_buffer(dmp_endpoint *endpoint)
{
    return endpoint->mem.fragment_message +
           (size_t)endpoint->active_peer_slot * endpoint->profile.message_bytes;
}

static uint8_t *peer_telemetry_buffer(dmp_endpoint *endpoint)
{
    return endpoint->mem.telemetry_payload +
           (size_t)endpoint->active_peer_slot * endpoint->profile.message_bytes;
}

static uint8_t *peer_telemetry_next_buffer(dmp_endpoint *endpoint)
{
    return endpoint->mem.telemetry_next +
           (size_t)endpoint->active_peer_slot * endpoint->profile.message_bytes;
}

static int bytes_ok(dmp_bytes bytes)
{
    return bytes.size == 0U || bytes.data != NULL;
}

static int service_allowed(const dmp_admitted_profile *profile, uint32_t service)
{
    return service == 0U || service == profile->service_id[0] || service == profile->service_id[1];
}

static int message_key_eq(dmp_message_key a, dmp_message_key b)
{
    return a.seq == b.seq && a.origin.namespace_id == b.origin.namespace_id &&
           a.origin.origin_id == b.origin.origin_id && a.origin.epoch == b.origin.epoch;
}

static int message_origin_eq(dmp_message_origin a, dmp_message_origin b)
{
    return a.namespace_id == b.namespace_id && a.origin_id == b.origin_id &&
           a.epoch == b.epoch;
}

static int freshness_service_index(const dmp_admitted_profile *profile, uint32_t service)
{
    if (service == profile->service_id[0]) {
        return 0;
    }
    if (service == profile->service_id[1]) {
        return 1;
    }
    return -1;
}

static int freshness_required(const dmp_admitted_profile *profile, uint32_t service)
{
    int index = freshness_service_index(profile, service);
    return index >= 0 &&
           (profile->freshness_required_mask & (uint8_t)(1U << (unsigned)index)) != 0U;
}

static int freshness_enabled(const dmp_endpoint *endpoint)
{
    return endpoint->profile.freshness_required_mask != 0U;
}

static dmp_core_limits limits_of(const dmp_endpoint *endpoint)
{
    dmp_core_limits limits;
    limits.max_frame_bytes = local_core_mtu(endpoint);
    limits.max_message_bytes = endpoint->profile.message_bytes;
    limits.max_fragments = endpoint->profile.fragments;
    return limits;
}

/* Receive a structurally valid over-profile REQ far enough to return its
 * authenticated STATUS=3 decision. Reassembly and all non-REQ traffic still
 * enforce the admitted message limit before state changes. */
static dmp_core_limits receive_limits_of(const dmp_endpoint *endpoint)
{
    dmp_core_limits limits = limits_of(endpoint);
    uint32_t core_mtu = receive_core_mtu(endpoint);
    limits.max_frame_bytes = core_mtu;
    if (limits.max_message_bytes < core_mtu) {
        limits.max_message_bytes = core_mtu;
    }
    return limits;
}

static int put_byte(uint8_t *data, size_t *n, size_t cap, uint8_t value)
{
    if (*n >= cap) {
        return 0;
    }
    data[(*n)++] = value;
    return 1;
}

static int put_uleb(uint8_t *data, size_t *n, size_t cap, uint32_t value)
{
    do {
        uint8_t byte = (uint8_t)(value & 0x7fU);
        value >>= 7U;
        if (value != 0U) {
            byte = (uint8_t)(byte | 0x80U);
        }
        if (!put_byte(data, n, cap, byte)) {
            return 0;
        }
    } while (value != 0U);
    return 1;
}

static int put_u64(uint8_t *data, size_t *n, size_t cap, uint64_t value)
{
    unsigned i;
    for (i = 0U; i < 8U; i++) {
        if (!put_byte(data, n, cap, (uint8_t)(value & 0xffU))) {
            return 0;
        }
        value >>= 8U;
    }
    return 1;
}

static int put_tlv(uint8_t *data, size_t *n, size_t cap, uint32_t tag, const uint8_t *value,
                   size_t value_n)
{
    size_t i;
    if (!put_uleb(data, n, cap, tag) || !put_uleb(data, n, cap, (uint32_t)value_n)) {
        return 0;
    }
    for (i = 0U; i < value_n; i++) {
        if (!put_byte(data, n, cap, value[i])) {
            return 0;
        }
    }
    return 1;
}

static int read_uleb32(dmp_bytes in, size_t *at, uint32_t *value)
{
    uint64_t acc = 0U;
    unsigned i;
    for (i = 0U; i < 5U; i++) {
        uint8_t byte;
        uint32_t chunk;
        if (*at >= in.size || in.data == NULL) {
            return 0;
        }
        byte = in.data[(*at)++];
        chunk = (uint32_t)(byte & 0x7fU);
        if (i == 4U && chunk > 0x0fU) {
            return 0;
        }
        acc |= (uint64_t)chunk << (7U * i);
        if ((byte & 0x80U) == 0U) {
            if (acc > 0xFFFFFFFFULL) {
                return 0;
            }
            *value = (uint32_t)acc;
            return 1;
        }
    }
    return 0;
}

static void emit_with_context(dmp_endpoint *endpoint, dmp_endpoint_event event,
                              dmp_reliability_handle request, uint32_t service,
                              uint32_t wire_status, dmp_bytes payload,
                              dmp_message_key source, dmp_identity_handle context)
{
    dmp_endpoint_notice notice;
    if (endpoint->notice == NULL) {
        return;
    }
    memset(&notice, 0, sizeof notice);
    notice.event = event;
    notice.peer = PEER(endpoint, handle);
    notice.association = context;
    notice.request = request;
    notice.service_id = service;
    notice.wire_status = wire_status;
    notice.source = source;
    notice.payload = payload;
    endpoint->notice(endpoint->notice_user, &notice);
}

static int secured(const dmp_endpoint *endpoint)
{
    return endpoint->mem.context.security == 1U;
}

static dmp_status from_hs(dmp_hs_status status)
{
    if (status == DMP_HS_OK) {
        return DMP_OK;
    }
    if (status == DMP_HS_EXPIRED) {
        return DMP_DEADLINE_EXPIRED;
    }
    if (status == DMP_HS_UNSUPPORTED) {
        return DMP_UNSUPPORTED;
    }
    if (status == DMP_HS_INVALID) {
        return DMP_INVALID_ARGUMENT;
    }
    if (status == DMP_HS_REFUSED) {
        return DMP_LIMIT_EXHAUSTED;
    }
    return DMP_AUTHENTICATION_FAILURE;
}

static void store_association_reservation(dmp_endpoint_peer_state *peer,
                                          const dmp_hs_tx_reservation *reservation,
                                          int draining)
{
    uint32_t *slots = draining ? peer->drain_reservation_slots
                               : peer->association_reservation_slots;
    uint64_t *generations = draining ? peer->drain_reservation_generations
                                     : peer->association_reservation_generations;
    uint8_t *live = draining ? &peer->drain_reservation_live
                             : &peer->association_reservation_live;
    uint32_t index;

    memset(slots, 0, 3U * sizeof(*slots));
    memset(generations, 0, 3U * sizeof(*generations));
    *live = 0U;
    if (reservation == NULL || reservation->count != 3U) {
        return;
    }
    for (index = 0U; index < reservation->count; index++) {
        slots[index] = reservation->tokens[index].slot;
        generations[index] = reservation->tokens[index].generation;
    }
    *live = 1U;
}

static int load_association_reservation(const dmp_endpoint_peer_state *peer,
                                        dmp_hs_tx_reservation *reservation,
                                        int draining)
{
    const uint32_t *slots = draining ? peer->drain_reservation_slots
                                     : peer->association_reservation_slots;
    const uint64_t *generations = draining ? peer->drain_reservation_generations
                                           : peer->association_reservation_generations;
    uint32_t index;

    if (peer == NULL || reservation == NULL ||
        (draining ? peer->drain_reservation_live : peer->association_reservation_live) == 0U) {
        return 0;
    }
    memset(reservation, 0, sizeof(*reservation));
    reservation->count = 3U;
    for (index = 0U; index < reservation->count; index++) {
        reservation->tokens[index].slot = slots[index];
        reservation->tokens[index].generation = generations[index];
    }
    return 1;
}

static void clear_association_reservation(dmp_endpoint_peer_state *peer, int draining)
{
    uint32_t *slots = draining ? peer->drain_reservation_slots
                               : peer->association_reservation_slots;
    uint64_t *generations = draining ? peer->drain_reservation_generations
                                     : peer->association_reservation_generations;
    uint8_t *live = draining ? &peer->drain_reservation_live
                             : &peer->association_reservation_live;
    memset(slots, 0, 3U * sizeof(*slots));
    memset(generations, 0, 3U * sizeof(*generations));
    *live = 0U;
}

static void move_active_reservation_to_drain(dmp_endpoint_peer_state *peer)
{
    memcpy(peer->drain_reservation_slots, peer->association_reservation_slots,
           sizeof peer->drain_reservation_slots);
    memcpy(peer->drain_reservation_generations,
           peer->association_reservation_generations,
           sizeof peer->drain_reservation_generations);
    peer->drain_reservation_live = peer->association_reservation_live;
    clear_association_reservation(peer, 0);
}

static dmp_status release_association_reservation(dmp_endpoint *endpoint,
                                                  dmp_endpoint_peer_state *peer,
                                                  int draining)
{
    dmp_hs_tx_reservation reservation;
    dmp_hs_status status;

    if (peer == NULL ||
        (draining ? peer->drain_reservation_live : peer->association_reservation_live) == 0U) {
        return DMP_OK;
    }
    if (peer->association == NULL || !load_association_reservation(peer, &reservation, draining)) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    status = dmp_hs_release_tx_reservation(peer->association, &reservation);
    if (status != DMP_HS_OK) {
        return from_hs(status);
    }
    clear_association_reservation(peer, draining);
    (void)endpoint;
    return DMP_OK;
}

static dmp_status install_epochs(dmp_endpoint *endpoint)
{
    dmp_identity_slot *slot;
    uint32_t namespace_id = 0U;
    uint32_t local_id = 0U;
    uint32_t peer_id = 0U;
    uint64_t local_epoch = 0U;
    uint64_t peer_epoch = 0U;

    if (!secured(endpoint)) {
        return DMP_OK;
    }
    if (PEER(endpoint, association_bound) == 0U || PEER(endpoint, association) == NULL) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!dmp_hs_traffic_identity(PEER(endpoint, association), PEER(endpoint, association_attempt), &namespace_id,
                                 &local_id, &peer_id, &local_epoch, &peer_epoch)) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (PEER(endpoint, context).slot >= endpoint->identity.capacity) {
        return DMP_STALE_HANDLE;
    }
    slot = &endpoint->identity.slots[PEER(endpoint, context).slot];
    if (slot->generation != PEER(endpoint, context).generation || slot->security != 1U ||
        slot->local.namespace_id != namespace_id || slot->local.origin_id != local_id ||
        slot->peer.origin_id != peer_id) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    /* Traffic epochs exist once the attempt is hashed. They are not activation. */
    if (slot->local.epoch != local_epoch || slot->peer.epoch != peer_epoch) {
        /* FINISH/READY reserve SEQ=0 in each direction. A new association
         * therefore starts application sequence allocation at one. */
        endpoint->identity.slots[PEER(endpoint, context).slot].next_seq = 1U;
        endpoint->identity.slots[PEER(endpoint, context).slot].seq_exhausted = false;
    }
    slot->local.epoch = local_epoch;
    slot->peer.epoch = peer_epoch;
    return DMP_OK;
}

static dmp_status retain_active_association(dmp_endpoint *endpoint)
{
    dmp_hs_tx_reservation reservation;
    dmp_hs_status hs_status;

    if (!secured(endpoint) || PEER(endpoint, association) == NULL ||
        PEER(endpoint, association_bound) == 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (PEER(endpoint, association_reservation_live) != 0U) {
        return DMP_OK;
    }
    hs_status = dmp_hs_send_application(PEER(endpoint, association),
                                        PEER(endpoint, association_attempt));
    if (hs_status == DMP_HS_NOT_ACTIVE &&
        !dmp_hs_terminal(PEER(endpoint, association), PEER(endpoint, association_attempt))) {
        return DMP_BUSY;
    }
    if (hs_status != DMP_HS_OK) {
        return from_hs(hs_status);
    }
    memset(&reservation, 0, sizeof reservation);
    hs_status = dmp_hs_retain_association_reservation(
        PEER(endpoint, association), PEER(endpoint, association_attempt), &reservation);
    if (hs_status != DMP_HS_OK) {
        return from_hs(hs_status);
    }
    store_association_reservation(&endpoint->peers[endpoint->active_peer_slot],
                                  &reservation, 0);
    return DMP_OK;
}

static dmp_status require_attempt(dmp_endpoint *endpoint, uint32_t attempt)
{
    if (!secured(endpoint)) {
        return DMP_OK;
    }
    if (PEER(endpoint, revoked) != 0U || PEER(endpoint, association_bound) == 0U || PEER(endpoint, association) == NULL) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (PEER(endpoint, drain_live) != 0U && attempt == PEER(endpoint, drain_attempt)) {
        if (dmp_hs_send_application(PEER(endpoint, association), attempt) != DMP_HS_OK) {
            return DMP_DEADLINE_EXPIRED;
        }
        return DMP_OK;
    }
    if (attempt != PEER(endpoint, association_attempt)) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    {
        dmp_hs_status hs = dmp_hs_send_application(PEER(endpoint, association), attempt);
        if (hs == DMP_HS_OK) {
            return retain_active_association(endpoint);
        }
        /* Not confirmed yet, and the attempt is still alive. Reliability
         * treats DMP_BUSY as non-destructive, so the admitted REQ stays queued
         * until activation. A cancelled or otherwise terminal attempt is not
         * this case. */
        if (hs == DMP_HS_NOT_ACTIVE && !dmp_hs_terminal(PEER(endpoint, association), attempt)) {
            return DMP_BUSY;
        }
    }
    return DMP_AUTHENTICATION_FAILURE;
}

static dmp_status encode_core(dmp_endpoint *endpoint, uint8_t type, uint32_t service, uint32_t seq,
                              int ack_req, int fragmented, uint32_t index, uint32_t chunk,
                              uint32_t total, dmp_bytes payload, int has_reply, dmp_message_key reply,
                              int status_present, uint32_t wire_status, int compact, int protect,
                              uint32_t seal_attempt, dmp_buffer out, size_t *written)
{
    dmp_frame_spec spec;
    dmp_core_limits limits;
    uint8_t value[32];
    size_t value_n;
    size_t ext_n = 0U;
    dmp_hs_status sealed;
    dmp_identity_handle route_context = endpoint->reliability.selected_context;

    memset(&spec, 0, sizeof spec);
    spec.fields.type = type;
    spec.fields.options = DMP_OPT_SEQ;
    spec.fields.seq = seq;
    if (ack_req) {
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_ACK_REQ);
    }
    if (fragmented) {
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_FRAG);
        spec.fields.fragment.index = index;
        spec.fields.fragment.chunk_size = chunk;
        spec.fields.fragment.total_size = total;
    }
    if (has_reply) {
        value_n = 0U;
        if (compact) {
            if (!put_uleb(value, &value_n, sizeof value, reply.seq)) {
                return DMP_LIMIT_EXHAUSTED;
            }
        } else if (!put_uleb(value, &value_n, sizeof value, reply.origin.namespace_id) ||
                   !put_uleb(value, &value_n, sizeof value, reply.origin.origin_id) ||
                   !put_u64(value, &value_n, sizeof value, reply.origin.epoch) ||
                   !put_uleb(value, &value_n, sizeof value, reply.seq)) {
            return DMP_LIMIT_EXHAUSTED;
        }
        if (!put_tlv(endpoint->ext_scratch, &ext_n, sizeof endpoint->ext_scratch, 5U, value,
                     value_n)) {
            return DMP_LIMIT_EXHAUSTED;
        }
    }
    if (endpoint->profile.origin_route == 1U) {
        const dmp_identity_slot *slot;
        uint64_t epoch;
        if (route_context.slot >= endpoint->identity.capacity) {
            return DMP_STALE_HANDLE;
        }
        slot = &endpoint->identity.slots[route_context.slot];
        if (slot->generation != route_context.generation) {
            return DMP_STALE_HANDLE;
        }
        epoch = slot->local.epoch;
        if (PEER(endpoint, drain_live) != 0U && seal_attempt == PEER(endpoint, drain_attempt)) {
            epoch = PEER(endpoint, drain_local_epoch);
        }
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_ROUTE);
        spec.fields.route.mode = 1U;
        spec.fields.route.ttl = endpoint->profile.origin_ttl;
        spec.fields.route.source = slot->local.origin_id;
        spec.fields.route.destination = slot->peer.origin_id;
        value_n = 0U;
        if (!put_uleb(value, &value_n, sizeof value, slot->local.namespace_id) ||
            !put_u64(value, &value_n, sizeof value, epoch) ||
            !put_tlv(endpoint->ext_scratch, &ext_n, sizeof endpoint->ext_scratch, 11U, value,
                     value_n)) {
            return DMP_LIMIT_EXHAUSTED;
        }
    }
    if (service != endpoint->profile.default_service) {
        value_n = 0U;
        if (!put_uleb(value, &value_n, sizeof value, service) ||
            !put_tlv(endpoint->ext_scratch, &ext_n, sizeof endpoint->ext_scratch, 17U, value,
                     value_n)) {
            return DMP_LIMIT_EXHAUSTED;
        }
    }
    if (status_present) {
        value_n = 0U;
        if (!put_uleb(value, &value_n, sizeof value, wire_status) ||
            !put_tlv(endpoint->ext_scratch, &ext_n, sizeof endpoint->ext_scratch, 21U, value,
                     value_n)) {
            return DMP_LIMIT_EXHAUSTED;
        }
    }
    if (PEER(endpoint, encode_freshness_live) != 0U &&
        !put_tlv(endpoint->ext_scratch, &ext_n, sizeof endpoint->ext_scratch, 25U,
                 PEER(endpoint, encode_freshness_token), sizeof PEER(endpoint, encode_freshness_token))) {
        return DMP_LIMIT_EXHAUSTED;
    }
    if (ext_n != 0U) {
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_EXT);
        spec.extensions.data = endpoint->ext_scratch;
        spec.extensions.size = ext_n;
    }
    spec.payload = payload;
    /* Dry run: header plus payload plus the 16-byte tag, compared with the
     * directional decoded-core MTU. The outer Stream R envelope is checked
     * against encoded_mtu after encoding. Does not seal or require activation.
     * DMP_HS_APP_PLAIN_MAX remains the protected plaintext buffer ceiling. */
    if (out.data == NULL) {
        dmp_core_limits dry_run_limits;
        dmp_buffer header_buf;
        uint8_t header[DMP_MAX_HEADER_BYTES];
        size_t header_len = 0U;
        if (written != NULL) {
            *written = 0U;
        }
        if (protect) {
            if (payload.size > DMP_HS_APP_PLAIN_MAX) {
                return DMP_LIMIT_EXHAUSTED;
            }
            spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_SECURITY);
            spec.fields.security.cipher = 1U;
            spec.fields.security.receive_cid = 0U;
            spec.fields.security.pn = 0U;
            spec.trailer.size = 16U;
            /* S5 admission and geometry use the largest permitted PN width,
             * regardless of the association's current counter. Protected
             * retries can cross a ULEB boundary while the logical frame and
             * path remain unchanged. */
            spec.fields.security.pn = (UINT64_C(1) << 24) - 1U;
            if (PEER(endpoint, association_bound) != 0U && PEER(endpoint, association) != NULL) {
                uint32_t cid = dmp_hs_remote_rx_cid(PEER(endpoint, association), seal_attempt);
                spec.fields.security.receive_cid = cid;
            }
        }
        dry_run_limits = limits_of(endpoint);
        header_buf.data = header;
        header_buf.capacity = sizeof header;
        return dmp_core_encode_header(&spec, &dry_run_limits, header_buf, &header_len);
    }
    if (protect) {
        dmp_status ready_status;
        if (payload.size > DMP_HS_APP_PLAIN_MAX) {
            return DMP_LIMIT_EXHAUSTED;
        }
        ready_status = require_attempt(endpoint, seal_attempt);
        if (ready_status != DMP_OK) {
            return ready_status;
        }
        if (out.data == NULL) {
            return DMP_INVALID_ARGUMENT;
        }
        /* One attempt, one PN counter. A refusal is not retried on another association. */
        sealed = dmp_hs_seal_logical(PEER(endpoint, association), seal_attempt, &spec, out.data,
                                     out.capacity, written);
        return from_hs(sealed);
    }
    limits = limits_of(endpoint);
    return dmp_core_encode(&spec, &limits, out, written);
}

static uint32_t seal_attempt_for(const dmp_endpoint *endpoint, const dmp_reliability_logical *logical)
{
    if (PEER(endpoint, drain_live) != 0U && logical->has_reply_to &&
        logical->reply_to.origin.epoch == PEER(endpoint, drain_peer_epoch)) {
        return PEER(endpoint, drain_attempt);
    }
    if (PEER(endpoint, drain_live) != 0U && logical->own.origin.epoch == PEER(endpoint, drain_local_epoch)) {
        return PEER(endpoint, drain_attempt);
    }
    return PEER(endpoint, association_attempt);
}

static dmp_status encode_logical(void *context, const dmp_reliability_logical *logical, dmp_buffer out,
                                 size_t *written)
{
    dmp_endpoint *endpoint = context;
    int status_present;
    dmp_bytes token;
    dmp_status status;
    if (endpoint == NULL || logical == NULL || written == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    status = select_peer(endpoint, logical->peer);
    if (status != DMP_OK || select_active_route(endpoint) != DMP_OK) {
        return DMP_STALE_HANDLE;
    }
    token = logical->freshness_token;
    if (!bytes_ok(token) || (token.size != 0U && token.size != 16U)) {
        return DMP_INVALID_ARGUMENT;
    }
    PEER(endpoint, encode_freshness_live) = token.size == 16U ? 1U : 0U;
    if (PEER(endpoint, encode_freshness_live) != 0U) {
        memcpy(PEER(endpoint, encode_freshness_token), token.data, sizeof PEER(endpoint, encode_freshness_token));
    }
    use_context(endpoint, logical->context);
    status_present = logical->type == DMP_TYPE_ERR ||
                     (logical->type == DMP_TYPE_RSP && logical->wire_status != 0U);
    status = encode_core(endpoint, (uint8_t)logical->type, logical->service_id, logical->own.seq,
                         logical->ack_req ? 1 : 0, logical->total_size != 0U,
                         logical->fragment_index, logical->chunk_size, logical->total_size,
                         logical->payload, logical->has_reply_to ? 1 : 0, logical->reply_to,
                         status_present, logical->wire_status, secured(endpoint),
                         secured(endpoint), seal_attempt_for(endpoint, logical), out, written);
    PEER(endpoint, encode_freshness_live) = 0U;
    memset(PEER(endpoint, encode_freshness_token), 0, sizeof PEER(endpoint, encode_freshness_token));
    use_context(endpoint, PEER(endpoint, context));
    return status;
}

static void on_reliability_notice(void *user, const dmp_reliability_notice *notice)
{
    dmp_endpoint *endpoint = user;
    dmp_endpoint_event event;
    uint32_t previous_slot;
    dmp_peer_handle previous_peer;
    dmp_identity_handle previous_context;
    int previous_live = 0;
    if (endpoint == NULL || notice == NULL) {
        return;
    }
    previous_slot = endpoint->active_peer_slot;
    previous_context = endpoint->reliability.selected_context;
    memset(&previous_peer, 0, sizeof previous_peer);
    if (previous_slot < endpoint->profile.peers &&
        endpoint->peers[previous_slot].live != 0U) {
        previous_peer = endpoint->peers[previous_slot].handle;
        previous_live = 1;
    }
    if (select_peer(endpoint, notice->peer) != DMP_OK) {
        goto restore_route;
    }
    if (notice->event == DMP_REL_EVENT_REQUEST_ACCEPTED) {
        if (notice->service_id == 0U) {
            if (PEER(endpoint, prepared_grant_live) != 0U &&
                message_key_eq(PEER(endpoint, prepared_grant_key), notice->key)) {
                PEER(endpoint, pending_grant_request) = notice->handle;
                PEER(endpoint, pending_grant_live) = 1U;
            }
            goto restore_route;
        }
        freshness_consume_key(endpoint, notice->key, notice->service_id);
        event = DMP_ENDPOINT_REQUEST;
    } else if (notice->event == DMP_REL_EVENT_RESULT) {
        event = DMP_ENDPOINT_RESULT;
    } else if (notice->event == DMP_REL_EVENT_DATA_ACCEPTED) {
        freshness_consume_key(endpoint, notice->key, notice->service_id);
        event = DMP_ENDPOINT_DATA;
    } else if (notice->event == DMP_REL_EVENT_DATA_DELIVERED) {
        event = DMP_ENDPOINT_DATA_DELIVERED;
    } else if (notice->event == DMP_REL_EVENT_UNKNOWN) {
        event = DMP_ENDPOINT_UNKNOWN;
    } else if (notice->event == DMP_REL_EVENT_DATA_UNKNOWN) {
        event = DMP_ENDPOINT_DATA_UNKNOWN;
    } else if (notice->event == DMP_REL_EVENT_LOCAL_UNSENT) {
        event = DMP_ENDPOINT_LOCAL_UNSENT;
    } else if (notice->event == DMP_REL_EVENT_DATA_LOCAL_UNSENT) {
        event = DMP_ENDPOINT_DATA_LOCAL_UNSENT;
    } else {
        goto restore_route;
    }
    emit_with_context(endpoint, event, notice->handle, notice->service_id,
                      notice->wire_status, notice->payload, notice->key,
                      notice->context);

restore_route:
    /* Reliability expiry/dispatch can notify a different peer in the middle
     * of another peer's RX. Restore both selectors before that RX consumes its
     * next frame or uses its already selected identity context. */
    if (previous_live != 0 && previous_slot < endpoint->profile.peers &&
        endpoint->peers[previous_slot].live != 0U &&
        peer_equal(endpoint->peers[previous_slot].handle, previous_peer)) {
        dmp_endpoint_peer_state *previous = &endpoint->peers[previous_slot];
        endpoint->active_peer_slot = previous_slot;
        if (peer_owns_context(previous, previous_context)) {
            (void)dmp_reliability_select_route(&endpoint->reliability, previous_peer,
                                               previous_context);
        } else {
            use_context(endpoint, previous->context);
        }
    } else {
        endpoint->active_peer_slot = previous_slot;
    }
}

static int find_tx(const dmp_endpoint *endpoint)
{
    int i;
    for (i = 0; i < DMP_ENDPOINT_TX_SLOTS; i++) {
        if (endpoint->tx[i].live == 0U) {
            return i;
        }
    }
    return -1;
}

static void on_wire_complete(void *owner, dmp_tx_token token, dmp_tx_outcome outcome, dmp_time_ms when)
{
    dmp_endpoint *endpoint = owner;
    int i;
    if (endpoint == NULL) {
        return;
    }
    for (i = 0; i < DMP_ENDPOINT_TX_SLOTS; i++) {
        dmp_endpoint_tx *tx = &endpoint->tx[i];
        dmp_tx_complete_fn complete;
        void *complete_owner;
        dmp_tx_token inner;
        dmp_identity_handle context;
        uint8_t context_retained;
        uint8_t kind;
        if (tx->live == 0U || tx->outer_token.slot != token.slot ||
            tx->outer_token.generation != token.generation) {
            continue;
        }
        kind = tx->kind;
        complete = tx->complete;
        complete_owner = tx->owner;
        inner = tx->inner_token;
        context = tx->context;
        context_retained = tx->context_retained;
        {
            dmp_peer_handle peer = tx->peer;
            int peer_live = select_peer(endpoint, peer) == DMP_OK;
        memset(tx, 0, sizeof *tx);
        endpoint->wire_busy = 0U;
        if (kind == KIND_REL && complete != NULL) {
            complete(complete_owner, inner, outcome, when);
        } else if (kind == KIND_FRAG) {
            if (peer_live) PEER(endpoint, frag_tx) = 0U;
            if (peer_live && PEER(endpoint, revoked) != 0U) {
                release_peer_buffer_contexts(endpoint, &endpoint->peers[endpoint->active_peer_slot]);
            } else if (outcome != DMP_TX_FAILED_UNSENT && outcome != DMP_TX_CANCELLED_UNSENT) {
                if (peer_live && PEER(endpoint, frag_index) + 1U >= PEER(endpoint, frag_count)) {
                    if (PEER(endpoint, frag_context_retained) != 0U) {
                        (void)dmp_identity_context_release(&endpoint->identity,
                                                           PEER(endpoint, frag_context));
                        PEER(endpoint, frag_context_retained) = 0U;
                    }
                    PEER(endpoint, frag_live) = 0U;
                } else if (peer_live) {
                    PEER(endpoint, frag_index)++;
                }
            }
        } else if (kind == KIND_TELEM) {
            if (peer_live) PEER(endpoint, telem_tx) = 0U;
            if (peer_live && PEER(endpoint, revoked) != 0U) {
                release_peer_buffer_contexts(endpoint, &endpoint->peers[endpoint->active_peer_slot]);
            } else if (outcome == DMP_TX_FAILED_UNSENT || outcome == DMP_TX_CANCELLED_UNSENT) {
                if (peer_live) PEER(endpoint, telem_pending) = 1U;
            } else {
                if (peer_live) PEER(endpoint, telem_pending) = 0U;
                if (peer_live) PEER(endpoint, telem_seq_set) = 0U;
                if (peer_live && PEER(endpoint, telem_context_retained) != 0U) {
                    (void)dmp_identity_context_release(&endpoint->identity,
                                                       PEER(endpoint, telem_context));
                    PEER(endpoint, telem_context_retained) = 0U;
                }
                if (peer_live && PEER(endpoint, telem_hold) != 0U) {
                    memcpy(peer_telemetry_buffer(endpoint), peer_telemetry_next_buffer(endpoint),
                           PEER(endpoint, telem_next_len));
                    PEER(endpoint, telem_len) = PEER(endpoint, telem_next_len);
                    PEER(endpoint, telem_context) = PEER(endpoint, telem_next_context);
                    PEER(endpoint, telem_attempt) = PEER(endpoint, telem_next_attempt);
                    PEER(endpoint, telem_context_retained) =
                        PEER(endpoint, telem_next_context_retained);
                    PEER(endpoint, telem_next_context_retained) = 0U;
                    PEER(endpoint, telem_hold) = 0U;
                    PEER(endpoint, telem_pending) = 1U;
                    PEER(endpoint, telem_seq_set) = 0U;
                }
            }
        } else if (kind == KIND_SYNC && peer_live) {
            PEER(endpoint, sync_tx) = 0U;
            if (outcome == DMP_TX_TRANSMITTED) {
                PEER(endpoint, sync_pending) = 0U;
            }
        }
        if (context_retained != 0U) {
            (void)dmp_identity_context_release(&endpoint->identity, context);
        }
        }
        return;
    }
}

static dmp_status submit_wire(dmp_endpoint *endpoint, uint8_t kind, dmp_bytes core,
                              dmp_identity_handle context,
                              dmp_tx_complete_fn complete, void *complete_owner, dmp_tx_token inner,
                              dmp_time_ms not_after)
{
    dmp_tx_submission submission;
    dmp_buffer encoded;
    size_t written = 0U;
    int slot;
    dmp_status status;
    if (endpoint->wire_busy != 0U) {
        return DMP_BUSY;
    }
    if (core.size == 0U || core.size > local_core_mtu(endpoint) || core.data == NULL ||
        core.size > endpoint->profile.encoded_mtu) {
        return DMP_LIMIT_EXHAUSTED;
    }
    if (PEER(endpoint, sync_pending) != 0U || PEER(endpoint, sync_tx) != 0U) {
        return DMP_BUSY;
    }
    slot = find_tx(endpoint);
    if (slot < 0 || endpoint->tx_generation == UINT64_MAX) {
        return DMP_QUOTA_EXHAUSTED;
    }
    if (endpoint->mem.framing_mode == DMP_ENDPOINT_FRAMING_PACKET) {
        encoded.data = (uint8_t *)core.data;
        written = core.size;
    } else {
        encoded.data = endpoint->mem.stream_tx;
        encoded.capacity = endpoint->mem.stream_tx_capacity;
        status = dmp_stream_encode(DMP_STREAM_R, core, encoded, &written);
        if (status != DMP_OK) {
            return status;
        }
        if (written > endpoint->profile.encoded_mtu) {
            return DMP_LIMIT_EXHAUSTED;
        }
    }
    status = dmp_identity_context_retain(&endpoint->identity, context);
    if (status != DMP_OK) {
        return status;
    }
    endpoint->tx_generation++;
    memset(&endpoint->tx[slot], 0, sizeof endpoint->tx[slot]);
    endpoint->tx[slot].live = 1U;
    endpoint->tx[slot].kind = kind;
    endpoint->tx[slot].context = context;
    endpoint->tx[slot].context_retained = 1U;
    endpoint->tx[slot].peer = PEER(endpoint, handle);
    endpoint->tx[slot].outer_token.slot = (uint32_t)slot;
    endpoint->tx[slot].outer_token.generation = endpoint->tx_generation;
    endpoint->tx[slot].inner_token = inner;
    endpoint->tx[slot].complete = complete;
    endpoint->tx[slot].owner = complete_owner;
    endpoint->wire_busy = 1U;
    memset(&submission, 0, sizeof submission);
    submission.token = endpoint->tx[slot].outer_token;
    submission.peer = PEER(endpoint, handle);
    submission.frame.data = encoded.data;
    submission.frame.size = written;
    submission.not_after = not_after;
    submission.complete = on_wire_complete;
    submission.owner = endpoint;
    status = endpoint->outer.submit(endpoint->outer.context, &submission);
    if (status != DMP_OK) {
        dmp_status release_status = dmp_identity_context_release(&endpoint->identity, context);
        memset(&endpoint->tx[slot], 0, sizeof endpoint->tx[slot]);
        endpoint->wire_busy = 0U;
        return release_status == DMP_OK ? status : release_status;
    }
    endpoint->accepted_tx_generation++;
    return DMP_OK;
}

static dmp_status submit_sync(dmp_endpoint *endpoint, dmp_time_ms now)
{
    dmp_tx_submission submission;
    int slot;
    dmp_status status;
    if (endpoint->wire_busy != 0U || PEER(endpoint, sync_pending) == 0U ||
        PEER(endpoint, sync_tx) != 0U) {
        return DMP_BUSY;
    }
    if (endpoint->mem.stream_tx_capacity == 0U || endpoint->outer.caps.max_frame_bytes < 1U) {
        return DMP_QUOTA_EXHAUSTED;
    }
    slot = find_tx(endpoint);
    if (slot < 0 || endpoint->tx_generation == UINT64_MAX) {
        return DMP_QUOTA_EXHAUSTED;
    }
    endpoint->tx_generation++;
    memset(&endpoint->tx[slot], 0, sizeof endpoint->tx[slot]);
    endpoint->tx[slot].live = 1U;
    endpoint->tx[slot].kind = KIND_SYNC;
    endpoint->tx[slot].peer = PEER(endpoint, handle);
    endpoint->tx[slot].outer_token.slot = (uint32_t)slot;
    endpoint->tx[slot].outer_token.generation = endpoint->tx_generation;
    PEER(endpoint, sync_tx) = 1U;
    endpoint->wire_busy = 1U;
    endpoint->mem.stream_tx[0] = 0U;
    memset(&submission, 0, sizeof submission);
    submission.token = endpoint->tx[slot].outer_token;
    submission.peer = PEER(endpoint, handle);
    submission.frame.data = endpoint->mem.stream_tx;
    submission.frame.size = 1U;
    (void)now;
    submission.not_after = UINT64_MAX;
    submission.complete = on_wire_complete;
    submission.owner = endpoint;
    status = endpoint->outer.submit(endpoint->outer.context, &submission);
    if (status != DMP_OK) {
        memset(&endpoint->tx[slot], 0, sizeof endpoint->tx[slot]);
        endpoint->wire_busy = 0U;
        PEER(endpoint, sync_tx) = 0U;
        return status;
    }
    endpoint->accepted_tx_generation++;
    return DMP_OK;
}

static dmp_status inner_submit(void *context, const dmp_tx_submission *submission)
{
    dmp_endpoint *endpoint = context;
    const dmp_reliability_adapter_slot *adapter;
    if (endpoint == NULL || submission == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (select_peer(endpoint, submission->peer) != DMP_OK) {
        return DMP_STALE_HANDLE;
    }
    if (submission->token.slot >= endpoint->reliability.storage.adapter_capacity) {
        return DMP_STALE_HANDLE;
    }
    adapter = &endpoint->reliability.storage.adapters[submission->token.slot];
    if (adapter->live == 0U || adapter->generation != submission->token.generation ||
        !peer_equal(adapter->peer, submission->peer)) {
        return DMP_STALE_HANDLE;
    }
    return submit_wire(endpoint, KIND_REL, submission->frame, adapter->context,
                       submission->complete, submission->owner, submission->token,
                       submission->not_after);
}

static dmp_status inner_cancel(void *context, dmp_tx_token token)
{
    dmp_endpoint *endpoint = context;
    int i;
    if (endpoint == NULL || endpoint->outer.cancel == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    for (i = 0; i < DMP_ENDPOINT_TX_SLOTS; i++) {
        dmp_endpoint_tx *tx = &endpoint->tx[i];
        if (tx->live != 0U && tx->kind == KIND_REL && tx->inner_token.slot == token.slot &&
            tx->inner_token.generation == token.generation) {
            return endpoint->outer.cancel(endpoint->outer.context, tx->outer_token);
        }
    }
    return DMP_INVALID_ARGUMENT;
}

static dmp_status require_span(size_t need, const void *data, size_t have)
{
    if (need == 0U) {
        return DMP_OK;
    }
    if (data == NULL || have < need) {
        return DMP_INVALID_ARGUMENT;
    }
    return DMP_OK;
}

dmp_status dmp_endpoint_init(dmp_endpoint *endpoint, const dmp_endpoint_storage *storage,
                             dmp_time_ms now)
{
    dmp_reliability_storage rel;
    dmp_reassembly_storage assembly;
    dmp_stream_config stream;
    dmp_buffer stream_storage;
    dmp_hs_admission_limits hs_limits;
    size_t stream_bound = 0U;
    size_t stream_rx_need = 0U;
    size_t peer_message_need = 0U;
    uint64_t required_freshness = 0U;
    dmp_status status;
    if (endpoint == NULL || storage == NULL || storage->profile == NULL ||
        storage->transport == NULL || storage->notice == NULL || storage->context.security > 1U) {
        return DMP_INVALID_ARGUMENT;
    }
    if (storage->profile->peers == 0U || storage->profile->peers > DMP_PROFILE_MAX_PEERS ||
        storage->peer_states == NULL ||
        storage->peer_state_capacity < storage->profile->peers ||
        storage->identity_capacity < (size_t)storage->profile->peers * 2U) {
        return DMP_INVALID_ARGUMENT;
    }
    if (storage->profile->peers > 1U &&
        (storage->context.security != 1U || storage->handshake_admission == NULL ||
         storage->handshake_admission_capacity < dmp_hs_admission_size() ||
         storage->handshake_max_pending == 0U || storage->handshake_max_scratch == 0U ||
         storage->handshake_global_work == 0U || storage->handshake_ingress_work == 0U)) {
        return DMP_UNSUPPORTED;
    }
    if (storage->framing_mode == DMP_ENDPOINT_FRAMING_STREAM_R) {
        status = dmp_stream_encoded_bound(DMP_STREAM_R, max_core_mtu(storage->profile),
                                          &stream_bound);
        if (status != DMP_OK) {
            return status;
        }
    } else if (storage->framing_mode == DMP_ENDPOINT_FRAMING_PACKET) {
        stream_bound = 0U;
        if (storage->profile->encoded_mtu < max_core_mtu(storage->profile)) {
            return DMP_INVALID_ARGUMENT;
        }
    } else {
        return DMP_INVALID_ARGUMENT;
    }
    if (stream_bound != 0U && storage->profile->peers > SIZE_MAX / stream_bound) {
        return DMP_LIMIT_EXHAUSTED;
    }
    stream_rx_need = (size_t)storage->profile->peers * stream_bound;
    if (storage->profile->message_bytes == 0U ||
        storage->profile->peers > SIZE_MAX / storage->profile->message_bytes) {
        return DMP_LIMIT_EXHAUSTED;
    }
    peer_message_need = (size_t)storage->profile->peers * storage->profile->message_bytes;
    if (storage->transport->submit == NULL || storage->transport->cancel == NULL ||
        (storage->framing_mode == DMP_ENDPOINT_FRAMING_STREAM_R &&
         storage->profile->encoded_mtu < stream_bound) ||
        storage->transport->caps.max_frame_bytes < storage->profile->encoded_mtu ||
        (storage->profile->tx_borrow ? 1 : 0) !=
            (storage->transport->caps.ownership == DMP_TX_BORROW ? 1 : 0) ||
        storage->profile->synchronous_completion != storage->transport->caps.synchronous_completion) {
        return DMP_INVALID_ARGUMENT;
    }
    if (storage->profile->freshness_required_mask != 0U) {
        required_freshness = (uint64_t)storage->profile->freshness_tokens_per_association * 2U *
                             storage->profile->peers;
        if (storage->context.security != 1U) {
            return DMP_UNSUPPORTED;
        }
        if (required_freshness > (uint64_t)SIZE_MAX / sizeof(dmp_endpoint_freshness_slot) ||
            storage->freshness_capacity < required_freshness || storage->freshness_slots == NULL) {
            return DMP_INVALID_ARGUMENT;
        }
    }
    if (require_span(1U, storage->identity_slots, storage->identity_capacity) != DMP_OK ||
        require_span(peer_message_need, storage->fragment_message,
                     storage->fragment_message_capacity) != DMP_OK ||
        require_span(max_core_mtu(storage->profile), storage->fragment_frame,
                     storage->fragment_frame_capacity) != DMP_OK ||
        require_span(peer_message_need, storage->telemetry_payload,
                     storage->telemetry_payload_capacity) != DMP_OK ||
        require_span(peer_message_need, storage->telemetry_next,
                     storage->telemetry_next_capacity) != DMP_OK ||
        require_span(max_core_mtu(storage->profile), storage->telemetry_frame,
                     storage->telemetry_frame_capacity) != DMP_OK ||
        (storage->framing_mode == DMP_ENDPOINT_FRAMING_STREAM_R &&
         require_span(storage->profile->encoded_mtu, storage->stream_tx,
                      storage->stream_tx_capacity) != DMP_OK) ||
        (storage->framing_mode == DMP_ENDPOINT_FRAMING_STREAM_R &&
         require_span(stream_rx_need, storage->stream_rx, storage->stream_rx_capacity) != DMP_OK) ||
        storage->assembly_capacity < storage->profile->assembly_slots ||
        storage->tombstone_capacity < storage->profile->assembly_tombstone_slots) {
        return DMP_INVALID_ARGUMENT;
    }
    memset(endpoint, 0, sizeof *endpoint);
    endpoint->profile = *storage->profile;
    endpoint->mem = *storage;
    endpoint->mem.profile = &endpoint->profile;
    endpoint->peers = storage->peer_states;
    memset(endpoint->peers, 0,
           (size_t)endpoint->profile.peers * sizeof *endpoint->peers);
    endpoint->notice = storage->notice;
    endpoint->notice_user = storage->notice_user;
    endpoint->validate_request = storage->validate_request;
    endpoint->validate_request_user = storage->validate_request_user;
    endpoint->validate_result = storage->validate_result;
    endpoint->outer = *storage->transport;
    endpoint->handshake_admission = storage->handshake_admission;
    endpoint->tx_generation = 1U;
    endpoint->stream_rx_stride = stream_bound;
    endpoint->peers[0].handle.slot = 0U;
    endpoint->peers[0].handle.generation = 1U;
    endpoint->peers[0].live = 1U;
    endpoint->peers[0].sync_pending =
        storage->framing_mode == DMP_ENDPOINT_FRAMING_STREAM_R ? 1U : 0U;
    endpoint->peer_count = 1U;
    endpoint->active_peer_slot = 0U;
    if (required_freshness != 0U) {
        memset(storage->freshness_slots, 0,
               (size_t)required_freshness * sizeof(dmp_endpoint_freshness_slot));
    }
    status = dmp_identity_table_init(&endpoint->identity, storage->identity_slots,
                                     storage->identity_capacity);
    if (status != DMP_OK) {
        return status;
    }
    if (endpoint->handshake_admission != NULL) {
        hs_limits.max_pending = storage->handshake_max_pending;
        hs_limits.max_scratch = storage->handshake_max_scratch;
        hs_limits.global_work = storage->handshake_global_work;
        hs_limits.ingress_work = storage->handshake_ingress_work;
        status = from_hs(dmp_hs_admission_init(endpoint->handshake_admission, &hs_limits));
        if (status != DMP_OK) {
            return status;
        }
    }
    status = dmp_identity_context_open(&endpoint->identity, &storage->context, &PEER(endpoint, context));
    if (status != DMP_OK) {
        return status;
    }
    if (endpoint->profile.peers > 1U) {
        status = dmp_identity_context_retain(&endpoint->identity, PEER(endpoint, context));
        if (status != DMP_OK) {
            return status;
        }
        PEER(endpoint, context_owned) = 1U;
    }
    memset(&assembly, 0, sizeof assembly);
    assembly.profile = &endpoint->profile;
    assembly.identity = &endpoint->identity;
    assembly.assemblies = storage->assemblies;
    assembly.assembly_capacity = storage->assembly_capacity;
    assembly.tombstones = storage->tombstones;
    assembly.tombstone_capacity = storage->tombstone_capacity;
    assembly.payloads = storage->assembly_payload;
    assembly.payload_capacity = storage->assembly_payload_capacity;
    assembly.metadata = storage->assembly_metadata;
    assembly.metadata_capacity = storage->assembly_metadata_capacity;
    /* A profile with fragments == 1 explicitly disables fragmentation. Keep
     * the reassembly engine uninitialized in that case; the parser's matching
     * max_fragments bound rejects every FRAG frame before take_fragment(). */
    if (endpoint->profile.fragments >= 2U) {
        status = dmp_reassembly_init(&endpoint->reassembly, &assembly, &endpoint->profile,
                                     &endpoint->identity);
        if (status != DMP_OK) {
            return status;
        }
    }
    endpoint->inner.context = endpoint;
    endpoint->inner.submit = inner_submit;
    endpoint->inner.cancel = inner_cancel;
    endpoint->inner.caps.max_frame_bytes = max_core_mtu(&endpoint->profile);
    endpoint->inner.caps.ownership = endpoint->profile.tx_borrow ? DMP_TX_BORROW : DMP_TX_COPY;
    endpoint->inner.caps.synchronous_completion = endpoint->profile.synchronous_completion;
    memset(&rel, 0, sizeof rel);
    rel.profile = &endpoint->profile;
    rel.identity = &endpoint->identity;
    rel.context = PEER(endpoint, context);
    rel.transport = &endpoint->inner;
    rel.encode = encode_logical;
    rel.encode_context = endpoint;
    rel.notice = on_reliability_notice;
    rel.notice_user = endpoint;
    rel.senders = storage->senders;
    rel.sender_capacity = storage->sender_capacity;
    rel.sender_payload = storage->sender_payload;
    rel.sender_payload_capacity = storage->sender_payload_capacity;
    rel.results = storage->results;
    rel.result_capacity = storage->result_capacity;
    rel.result_payload = storage->result_payload;
    rel.result_payload_capacity = storage->result_payload_capacity;
    rel.history = storage->history;
    rel.history_capacity = storage->history_capacity;
    rel.correlations = storage->correlations;
    rel.correlation_capacity = storage->correlation_capacity;
    rel.history_metadata = storage->history_metadata;
    rel.history_metadata_capacity = storage->history_metadata_capacity;
    rel.correlation_metadata = storage->correlation_metadata;
    rel.correlation_metadata_capacity = storage->correlation_metadata_capacity;
    rel.adapters = storage->adapters;
    rel.adapter_capacity = storage->adapter_capacity;
    rel.frames = storage->frames;
    rel.frame_capacity = storage->frame_capacity;
    rel.receive_payload = storage->receive_payload;
    rel.receive_payload_capacity = storage->receive_payload_capacity;
    status = dmp_reliability_init(&endpoint->reliability, &rel);
    if (status != DMP_OK) {
        return status;
    }
    status = select_active_route(endpoint);
    if (status != DMP_OK) {
        (void)dmp_reliability_close(&endpoint->reliability, now);
        return status;
    }
    if (endpoint->mem.framing_mode == DMP_ENDPOINT_FRAMING_STREAM_R) {
        memset(&stream, 0, sizeof stream);
        stream.mode = DMP_STREAM_R;
        stream.max_core_bytes = receive_core_mtu(endpoint);
        stream.partial_timeout_ms =
            endpoint->profile.collect_ms != 0U ? endpoint->profile.collect_ms : 1U;
        stream_storage.data = storage->stream_rx;
        stream_storage.capacity = endpoint->stream_rx_stride;
        status = dmp_stream_init(&PEER(endpoint, decoder), stream, stream_storage, now);
        if (status != DMP_OK) {
            (void)dmp_reliability_close(&endpoint->reliability, now);
            return status;
        }
    }
    endpoint->initialized = 1U;
    return DMP_OK;
}

dmp_status dmp_endpoint_add_peer(dmp_endpoint *endpoint,
                                 const dmp_identity_context_config *context,
                                 dmp_time_ms now, dmp_peer_handle *out)
{
    dmp_endpoint_peer_state *peer = NULL;
    dmp_stream_config stream;
    dmp_buffer stream_storage;
    dmp_identity_handle identity;
    uint32_t slot;
    uint64_t generation;
    dmp_status status;
    if (!ready(endpoint) || context == NULL || out == NULL ||
        endpoint->profile.peers <= 1U || endpoint->peer_count >= endpoint->profile.peers ||
        context->security > 1U || context->security != endpoint->mem.context.security ||
        context->local.namespace_id != endpoint->profile.namespace_id ||
        context->peer.namespace_id != endpoint->profile.namespace_id ||
        context->peer.origin_id == 0U || context->peer.origin_id == context->local.origin_id ||
        context->local.origin_id != endpoint->mem.context.local.origin_id) {
        return DMP_INVALID_ARGUMENT;
    }
    /* Check every live identity before choosing a reusable slot. Otherwise an
     * early free slot can hide a duplicate principal in a later slot. */
    for (slot = 0U; slot < endpoint->profile.peers; slot++) {
        dmp_endpoint_peer_state *candidate = &endpoint->peers[slot];
        if (candidate->live != 0U) {
            const dmp_identity_slot *identity_slot =
                candidate->context.slot < endpoint->identity.capacity
                    ? &endpoint->identity.slots[candidate->context.slot]
                    : NULL;
            if (identity_slot != NULL && identity_slot->generation == candidate->context.generation &&
                identity_slot->peer.namespace_id == context->peer.namespace_id &&
                identity_slot->peer.origin_id == context->peer.origin_id) {
                return DMP_DUPLICATE;
            }
        }
    }
    for (slot = 0U; slot < endpoint->profile.peers; slot++) {
        dmp_endpoint_peer_state *candidate = &endpoint->peers[slot];
        if (candidate->live != 0U || candidate->retirement_requested != 0U) {
            continue;
        }
        if (candidate->retirement_requested == 0U && candidate->handle.generation == 0U) {
            peer = candidate;
            break;
        }
        if (candidate->retirement_requested == 0U && candidate->handle.generation != 0U) {
            peer = candidate;
            break;
        }
    }
    if (peer == NULL) {
        return DMP_QUOTA_EXHAUSTED;
    }
    slot = (uint32_t)(peer - endpoint->peers);
    generation = peer->handle.generation == 0U ? 1U : peer->handle.generation;
    status = dmp_identity_context_open(&endpoint->identity, context, &identity);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_identity_context_retain(&endpoint->identity, identity);
    if (status != DMP_OK) {
        (void)dmp_identity_context_begin_drain(&endpoint->identity, identity, 0U);
        (void)dmp_identity_context_retire(&endpoint->identity, identity, 0U);
        return status;
    }
    memset(peer, 0, sizeof *peer);
    peer->handle.slot = slot;
    peer->handle.generation = generation;
    peer->context = identity;
    peer->context_owned = 1U;
    peer->live = 1U;
    peer->sync_pending =
        endpoint->mem.framing_mode == DMP_ENDPOINT_FRAMING_STREAM_R ? 1U : 0U;
    endpoint->active_peer_slot = slot;
    if (endpoint->mem.framing_mode == DMP_ENDPOINT_FRAMING_STREAM_R) {
        memset(&stream, 0, sizeof stream);
        stream.mode = DMP_STREAM_R;
        stream.max_core_bytes = receive_core_mtu(endpoint);
        stream.partial_timeout_ms =
            endpoint->profile.collect_ms != 0U ? endpoint->profile.collect_ms : 1U;
        stream_storage.data = endpoint->mem.stream_rx + (size_t)slot * endpoint->stream_rx_stride;
        stream_storage.capacity = endpoint->stream_rx_stride;
        status = dmp_stream_init(&peer->decoder, stream, stream_storage, now);
        if (status != DMP_OK) {
            (void)dmp_identity_context_release(&endpoint->identity, identity);
            (void)dmp_identity_context_begin_drain(&endpoint->identity, identity, 0U);
            (void)dmp_identity_context_retire(&endpoint->identity, identity, 0U);
            memset(peer, 0, sizeof *peer);
            peer->handle.slot = slot;
            peer->handle.generation = generation;
            return status;
        }
    }
    endpoint->peer_count++;
    status = select_active_route(endpoint);
    if (status != DMP_OK) {
        endpoint->peer_count--;
        (void)dmp_identity_context_release(&endpoint->identity, identity);
        (void)dmp_identity_context_begin_drain(&endpoint->identity, identity, now);
        (void)dmp_identity_context_retire(&endpoint->identity, identity, now);
        memset(peer, 0, sizeof *peer);
        peer->handle.slot = slot;
        peer->handle.generation = generation;
        return status;
    }
    *out = peer->handle;
    return DMP_OK;
}

struct dmp_hs_admission *dmp_endpoint_handshake_admission(dmp_endpoint *endpoint)
{
    if (!ready(endpoint) || endpoint->handshake_admission == NULL) {
        return NULL;
    }
    return endpoint->handshake_admission;
}

static uint32_t permit_mask(const dmp_endpoint *endpoint, uint32_t principal, uint32_t service)
{
    uint32_t mask = 0U;
    uint8_t index;

    if (PEER(endpoint, grants_set) == 0U) {
        return 0U;
    }
    for (index = 0U; index < PEER(endpoint, grant_count); index++) {
        const dmp_endpoint_grant *grant = &PEER(endpoint, grants)[index];
        if (grant->principal == principal && grant->service_id == service) {
            mask |= grant->permit;
        }
    }
    return mask;
}

static int action_allowed(const dmp_endpoint *endpoint, uint32_t principal, uint32_t service,
                          uint32_t need)
{
    if (!secured(endpoint)) {
        return 1;
    }
    if (PEER(endpoint, revoked) != 0U || PEER(endpoint, grants_set) == 0U || need == 0U) {
        return 0;
    }
    return (permit_mask(endpoint, principal, service) & need) == need;
}

static int local_action(const dmp_endpoint *endpoint, uint32_t service, uint32_t need)
{
    const dmp_identity_slot *slot;

    if (!secured(endpoint)) {
        return 1;
    }
    if (PEER(endpoint, context).slot >= endpoint->identity.capacity) {
        return 0;
    }
    slot = &endpoint->identity.slots[PEER(endpoint, context).slot];
    if (slot->generation != PEER(endpoint, context).generation) {
        return 0;
    }
    if (service == 0U) {
        return action_allowed(endpoint, slot->local.origin_id, 0U, DMP_ENDPOINT_PERMIT_CONTROL);
    }
    return action_allowed(endpoint, slot->local.origin_id, service, need);
}

static size_t freshness_slot_count(const dmp_endpoint *endpoint)
{
    uint64_t admitted = (uint64_t)endpoint->profile.freshness_tokens_per_association * 2U *
                        endpoint->profile.peers;
    return admitted < endpoint->mem.freshness_capacity ? (size_t)admitted
                                                       : endpoint->mem.freshness_capacity;
}

static void freshness_clear_attempt(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                    uint32_t attempt)
{
    size_t i;
    size_t count = freshness_slot_count(endpoint);
    for (i = 0U; i < count; i++) {
        dmp_endpoint_freshness_slot *slot = &endpoint->mem.freshness_slots[i];
        if (slot->state != DMP_ENDPOINT_FRESHNESS_EMPTY && peer_equal(slot->peer, peer) &&
            slot->attempt == attempt) {
            memset(slot, 0, sizeof *slot);
        }
    }
}

static void freshness_consume_key(dmp_endpoint *endpoint, dmp_message_key key, uint32_t service)
{
    size_t i;
    size_t count = freshness_slot_count(endpoint);
    for (i = 0U; i < count; i++) {
        dmp_endpoint_freshness_slot *slot = &endpoint->mem.freshness_slots[i];
        if (slot->state == DMP_ENDPOINT_FRESHNESS_BOUND && peer_equal(slot->peer, PEER(endpoint, handle)) &&
            slot->principal == key.origin.origin_id &&
            slot->peer_epoch == key.origin.epoch && slot->bound_seq == key.seq &&
            slot->service_id == service) {
            slot->state = DMP_ENDPOINT_FRESHNESS_CONSUMED;
        }
    }
}

static void freshness_consume_frame(dmp_endpoint *endpoint, const dmp_frame_view *frame,
                                    uint32_t service, dmp_identity_handle context,
                                    dmp_time_ms now)
{
    dmp_message_key source;
    if (frame != NULL && freshness_required(&endpoint->profile, service) &&
        freshness_command(frame->fields.type) &&
        dmp_identity_source_key(frame, &endpoint->identity, context, now, &source) == DMP_OK) {
        freshness_consume_key(endpoint, source, service);
    }
}

static void freshness_maintenance(dmp_endpoint *endpoint, dmp_time_ms now)
{
    size_t i;
    size_t count = freshness_slot_count(endpoint);
    for (i = 0U; i < count; i++) {
        dmp_endpoint_freshness_slot *slot = &endpoint->mem.freshness_slots[i];
        if (slot->state == DMP_ENDPOINT_FRESHNESS_EMPTY ||
            slot->state == DMP_ENDPOINT_FRESHNESS_RESERVED) {
            continue;
        }
        if (slot->state == DMP_ENDPOINT_FRESHNESS_ISSUED &&
            dmp_deadline_reached(now, slot->expires_at)) {
            slot->state = DMP_ENDPOINT_FRESHNESS_CONSUMED;
        }
        if (slot->grant_request_live != 0U &&
            (slot->result_slot >= endpoint->mem.result_capacity ||
             endpoint->mem.results == NULL ||
             endpoint->mem.results[slot->result_slot].live == 0U ||
             endpoint->mem.results[slot->result_slot].generation != slot->result_generation)) {
            slot->grant_request_live = 0U;
        }
        if (slot->grant_request_live == 0U && dmp_deadline_reached(now, slot->record_until)) {
            memset(slot, 0, sizeof *slot);
        }
    }
}

static int freshness_identity_retained(const dmp_endpoint *endpoint, dmp_message_key key,
                                       uint32_t service, uint8_t type)
{
    size_t i;
    for (i = 0U; i < endpoint->mem.history_capacity; i++) {
        const dmp_reliability_history_slot *history = &endpoint->mem.history[i];
        if (history->live != 0U && peer_equal(history->peer, PEER(endpoint, handle)) &&
            message_key_eq(history->source, key) &&
            history->service_id == service && history->type == type) {
            return 1;
        }
    }
    for (i = 0U; i < endpoint->mem.result_capacity; i++) {
        const dmp_reliability_result_slot *result = &endpoint->mem.results[i];
        if (result->live != 0U && peer_equal(result->peer, PEER(endpoint, handle)) &&
            message_key_eq(result->request, key) &&
            result->service_id == service) {
            return 1;
        }
    }
    return 0;
}

static void use_context(dmp_endpoint *endpoint, dmp_identity_handle handle)
{
    (void)dmp_reliability_select_route(&endpoint->reliability, PEER(endpoint, handle), handle);
}

static void release_peer_buffer_contexts(dmp_endpoint *endpoint,
                                         dmp_endpoint_peer_state *peer)
{
    if (peer->frag_context_retained != 0U) {
        (void)dmp_identity_context_release(&endpoint->identity, peer->frag_context);
        peer->frag_context_retained = 0U;
        peer->frag_live = 0U;
        peer->frag_tx = 0U;
    }
    if (peer->telem_context_retained != 0U) {
        (void)dmp_identity_context_release(&endpoint->identity, peer->telem_context);
        peer->telem_context_retained = 0U;
    }
    if (peer->telem_next_context_retained != 0U) {
        (void)dmp_identity_context_release(&endpoint->identity, peer->telem_next_context);
        peer->telem_next_context_retained = 0U;
    }
    peer->telem_pending = 0U;
    peer->telem_hold = 0U;
    peer->telem_tx = 0U;
    peer->telem_seq_set = 0U;
}

static void cancel_epoch_senders(dmp_endpoint *endpoint, dmp_time_ms now, int only_past_drain)
{
    size_t index;

    if (endpoint->mem.senders == NULL) {
        return;
    }
    for (index = 0U; index < endpoint->mem.sender_capacity; index++) {
        dmp_reliability_sender_slot *sender = &endpoint->mem.senders[index];
        dmp_reliability_handle handle;

        if (sender->live == 0U ||
            !peer_equal(sender->peer, PEER(endpoint, handle)) ||
            (sender->kind != DMP_REL_SENDER_REQUEST && sender->kind != DMP_REL_SENDER_DATA) ||
            sender->phase == DMP_REL_PHASE_TERMINAL) {
            continue;
        }
        if (PEER(endpoint, drain_live) != 0U && sender->own.origin.epoch != PEER(endpoint, drain_local_epoch)) {
            continue;
        }
        if (only_past_drain && PEER(endpoint, drain_live) != 0U &&
            sender->send_deadline <= PEER(endpoint, drain_not_after) &&
            sender->result_deadline <= PEER(endpoint, drain_not_after)) {
            continue;
        }
        handle.slot = (uint32_t)index;
        handle.generation = sender->generation;
        handle.peer = sender->peer;
        (void)dmp_reliability_cancel(&endpoint->reliability, handle, now);
    }
}

static dmp_status retire_identity_context(dmp_endpoint *endpoint, dmp_identity_handle context,
                                          dmp_time_ms now)
{
    dmp_status status = dmp_identity_context_retire(&endpoint->identity, context, now);

    if (endpoint->profile.fragments >= 2U &&
        (status == DMP_OK || status == DMP_STALE_HANDLE) &&
        (size_t)context.slot < endpoint->identity.capacity) {
        const dmp_identity_slot *slot = &endpoint->identity.slots[context.slot];

        /* A stale result can mean an earlier retirement succeeded but its
         * reassembly cleanup had to be retried. Require the same unused
         * generation before clearing any context-scoped tombstones. */
        if (slot->generation == context.generation && slot->state == DMP_IDENTITY_SLOT_UNUSED) {
            dmp_status cleanup = dmp_reassembly_context_retired(&endpoint->reassembly, context);
            if (cleanup != DMP_OK) {
                return cleanup;
            }
        }
    }
    return status;
}

static void end_drain(dmp_endpoint *endpoint, dmp_time_ms now)
{
    dmp_status retired;

    if (PEER(endpoint, drain_live) == 0U) {
        return;
    }
    cancel_epoch_senders(endpoint, now, 0);
    if (PEER(endpoint, association) != NULL) {
        (void)dmp_hs_cancel(PEER(endpoint, association), PEER(endpoint, drain_attempt));
    }
    /* Reassembly may still retain the draining context. Leave the slot and
     * retry on a later poll once that retain drops. */
    retired = retire_identity_context(endpoint, PEER(endpoint, drain_context), now);
    if (retired != DMP_OK && retired != DMP_STALE_HANDLE) {
        return;
    }
    if (release_association_reservation(endpoint,
                                        &endpoint->peers[endpoint->active_peer_slot], 1) != DMP_OK) {
        return;
    }
    freshness_clear_attempt(endpoint, PEER(endpoint, handle), PEER(endpoint, drain_attempt));
    PEER(endpoint, drain_live) = 0U;
}

static void expire_drain(dmp_endpoint *endpoint, dmp_time_ms now)
{
    if (PEER(endpoint, drain_live) != 0U && now >= PEER(endpoint, drain_not_after)) {
        end_drain(endpoint, now);
    }
}

static void clear_peer_freshness(dmp_endpoint *endpoint, dmp_peer_handle peer)
{
    size_t i;
    for (i = 0U; i < freshness_slot_count(endpoint); i++) {
        if (endpoint->mem.freshness_slots[i].state != DMP_ENDPOINT_FRESHNESS_EMPTY &&
            peer_equal(endpoint->mem.freshness_slots[i].peer, peer)) {
            memset(&endpoint->mem.freshness_slots[i], 0,
                   sizeof endpoint->mem.freshness_slots[i]);
        }
    }
}

static int peer_has_outer_tx(const dmp_endpoint *endpoint, dmp_peer_handle peer)
{
    size_t i;
    for (i = 0U; i < DMP_ENDPOINT_TX_SLOTS; i++) {
        if (endpoint->tx[i].live != 0U && peer_equal(endpoint->tx[i].peer, peer)) {
            return 1;
        }
    }
    return 0;
}

static void retire_revoked_peers(dmp_endpoint *endpoint, dmp_time_ms now)
{
    uint32_t i;
    for (i = 0U; i < endpoint->profile.peers; i++) {
        dmp_endpoint_peer_state *peer = &endpoint->peers[i];
        dmp_identity_slot *slot;
        dmp_status status;
        if (peer->live == 0U || peer->retirement_requested == 0U ||
            peer_has_outer_tx(endpoint, peer->handle)) {
            continue;
        }
        endpoint->active_peer_slot = i;
        if (peer->drain_live != 0U) {
            if (peer->drain_context.slot < endpoint->identity.capacity) {
                slot = &endpoint->identity.slots[peer->drain_context.slot];
                if (slot->generation == peer->drain_context.generation &&
                    slot->state == DMP_IDENTITY_SLOT_DRAINING) {
                    slot->not_after = now;
                }
            }
            end_drain(endpoint, now);
            if (peer->drain_live != 0U) {
                continue;
            }
        }
        if (peer->context.slot >= endpoint->identity.capacity) {
            continue;
        }
        slot = &endpoint->identity.slots[peer->context.slot];
        if (slot->generation != peer->context.generation) {
            continue;
        }
        if (slot->state == DMP_IDENTITY_SLOT_ACTIVE) {
            (void)dmp_identity_context_begin_drain(&endpoint->identity, peer->context, now);
        }
        if (peer->context_owned != 0U) {
            status = dmp_identity_context_release(&endpoint->identity, peer->context);
            if (status != DMP_OK) {
                continue;
            }
            peer->context_owned = 0U;
        }
        status = retire_identity_context(endpoint, peer->context, now);
        if (status != DMP_OK && status != DMP_STALE_HANDLE) {
            continue;
        }
        if (release_association_reservation(endpoint, peer, 0) != DMP_OK) {
            continue;
        }
        {
            uint64_t generation = peer->handle.generation;
            if (endpoint->peer_count != 0U) {
                endpoint->peer_count--;
            }
            memset(peer, 0, sizeof *peer);
            peer->handle.slot = i;
            if (generation == UINT64_MAX) {
                peer->handle.generation = UINT64_MAX;
                peer->retirement_requested = 1U;
            } else {
                peer->handle.generation = generation + 1U;
            }
        }
    }
    for (i = 0U; i < endpoint->profile.peers; i++) {
        if (endpoint->peers[i].live != 0U) {
            endpoint->active_peer_slot = i;
            (void)select_active_route(endpoint);
            break;
        }
    }
}

dmp_status dmp_endpoint_set_peer_grants(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                        const dmp_endpoint_grant *grants, size_t count)
{
    size_t index;

    if (!ready(endpoint) || count > DMP_ENDPOINT_GRANT_MAX || (count != 0U && grants == NULL)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (select_peer(endpoint, peer) != DMP_OK) {
        return DMP_STALE_HANDLE;
    }
    for (index = 0U; index < count; index++) {
        PEER(endpoint, grants)[index] = grants[index];
    }
    PEER(endpoint, grant_count) = (uint8_t)count;
    PEER(endpoint, grants_set) = 1U;
    return DMP_OK;
}

dmp_status dmp_endpoint_set_grants(dmp_endpoint *endpoint, const dmp_endpoint_grant *grants,
                                   size_t count)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) {
        return DMP_INVALID_ARGUMENT;
    }
    return dmp_endpoint_set_peer_grants(endpoint, peer, grants, count);
}

dmp_status dmp_endpoint_set_peer_drain_ms(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                          uint32_t drain_ms)
{
    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (select_peer(endpoint, peer) != DMP_OK) {
        return DMP_STALE_HANDLE;
    }
    PEER(endpoint, drain_ms) = drain_ms;
    return DMP_OK;
}

dmp_status dmp_endpoint_set_drain_ms(dmp_endpoint *endpoint, uint32_t drain_ms)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) {
        return DMP_INVALID_ARGUMENT;
    }
    return dmp_endpoint_set_peer_drain_ms(endpoint, peer, drain_ms);
}

dmp_status dmp_endpoint_rotate_peer(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                    uint32_t attempt_index, dmp_time_ms now)
{
    dmp_identity_context_config config;
    dmp_identity_handle fresh;
    dmp_identity_handle old_context;
    dmp_hs_tx_reservation reservation;
    dmp_identity_slot *slot;
    uint32_t namespace_id = 0U;
    uint32_t local_id = 0U;
    uint32_t peer_id = 0U;
    uint64_t local_epoch = 0U;
    uint64_t peer_epoch = 0U;
    uint64_t bound;
    dmp_status status;

    memset(&reservation, 0, sizeof reservation);

    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    status = select_peer(endpoint, peer);
    if (status != DMP_OK) return status;
    status = select_active_route(endpoint);
    if (status != DMP_OK) return status;
    if (PEER(endpoint, revoked) != 0U || PEER(endpoint, association_bound) == 0U || PEER(endpoint, association) == NULL) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (PEER(endpoint, drain_live) != 0U || attempt_index == PEER(endpoint, association_attempt)) {
        return DMP_BUSY;
    }
    if (dmp_hs_send_application(PEER(endpoint, association), attempt_index) != DMP_HS_OK) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!dmp_hs_traffic_identity(PEER(endpoint, association), attempt_index, &namespace_id, &local_id,
                                 &peer_id, &local_epoch, &peer_epoch)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (local_id != endpoint->mem.context.local.origin_id) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (PEER(endpoint, context).slot >= endpoint->identity.capacity) {
        return DMP_STALE_HANDLE;
    }
    slot = &endpoint->identity.slots[PEER(endpoint, context).slot];
    if (slot->generation != PEER(endpoint, context).generation || slot->local.namespace_id != namespace_id ||
        slot->local.origin_id != local_id || slot->peer.origin_id != peer_id) {
        return DMP_INVALID_ARGUMENT;
    }
    memset(&config, 0, sizeof config);
    config.local = slot->local;
    config.peer = slot->peer;
    config.local.epoch = local_epoch;
    config.peer.epoch = peer_epoch;
    config.security = 1U;
    status = dmp_identity_context_open(&endpoint->identity, &config, &fresh);
    if (status != DMP_OK) {
        return status;
    }
    if (endpoint->profile.peers > 1U) {
        status = dmp_identity_context_retain(&endpoint->identity, fresh);
        if (status != DMP_OK) {
            (void)dmp_identity_context_begin_drain(&endpoint->identity, fresh, now);
            (void)dmp_identity_context_retire(&endpoint->identity, fresh, now);
            return status;
        }
    }
    old_context = PEER(endpoint, context);
    bound = (uint64_t)PEER(endpoint, drain_ms) > UINT64_MAX - now ? UINT64_MAX
                                                           : now + (uint64_t)PEER(endpoint, drain_ms);
    if (secured(endpoint)) {
        dmp_hs_status retain_status = dmp_hs_retain_association_reservation(
            PEER(endpoint, association), attempt_index, &reservation);
        if (retain_status != DMP_HS_OK) {
            if (endpoint->profile.peers > 1U) {
                (void)dmp_identity_context_release(&endpoint->identity, fresh);
            }
            (void)dmp_identity_context_begin_drain(&endpoint->identity, fresh, now);
            (void)dmp_identity_context_retire(&endpoint->identity, fresh, now);
            return from_hs(retain_status);
        }
    }
    status = dmp_identity_context_begin_drain(&endpoint->identity, old_context, bound);
    if (status != DMP_OK) {
        if (endpoint->profile.peers > 1U) {
            (void)dmp_identity_context_release(&endpoint->identity, fresh);
        }
        (void)dmp_identity_context_begin_drain(&endpoint->identity, fresh, now);
        (void)dmp_identity_context_retire(&endpoint->identity, fresh, now);
        if (reservation.count != 0U) {
            (void)dmp_hs_release_tx_reservation(PEER(endpoint, association), &reservation);
        }
        return status;
    }
    move_active_reservation_to_drain(&endpoint->peers[endpoint->active_peer_slot]);
    if (reservation.count != 0U) {
        store_association_reservation(&endpoint->peers[endpoint->active_peer_slot],
                                      &reservation, 0);
    }
    PEER(endpoint, drain_context) = old_context;
    PEER(endpoint, drain_attempt) = PEER(endpoint, association_attempt);
    PEER(endpoint, drain_local_epoch) = slot->local.epoch;
    PEER(endpoint, drain_peer_epoch) = slot->peer.epoch;
    PEER(endpoint, drain_not_after) = bound;
    PEER(endpoint, drain_live) = 1U;
    PEER(endpoint, context) = fresh;
    PEER(endpoint, association_attempt) = attempt_index;
    status = dmp_reliability_select_route(&endpoint->reliability, PEER(endpoint, handle), fresh);
    if (status == DMP_OK && endpoint->profile.peers > 1U) {
        status = dmp_identity_context_release(&endpoint->identity, old_context);
    }
    if (status != DMP_OK) {
        /* The route has already moved and the old context is recorded as a
         * drain. A failed release is an ownership fault; revoke both sides. */
        (void)dmp_endpoint_revoke_peer(endpoint, PEER(endpoint, handle), now);
        return status;
    }
    /* Original deadlines stay. Work that runs past the drain bound is not moved. */
    cancel_epoch_senders(endpoint, now, 1);
    if (now >= bound) {
        end_drain(endpoint, now);
    }
    return DMP_OK;
}

dmp_status dmp_endpoint_rotate(dmp_endpoint *endpoint, uint32_t attempt_index, dmp_time_ms now)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) {
        return DMP_INVALID_ARGUMENT;
    }
    return dmp_endpoint_rotate_peer(endpoint, peer, attempt_index, now);
}

dmp_status dmp_endpoint_revoke_peer(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                    dmp_time_ms now)
{
    size_t index;
    uint32_t attempt;
    dmp_status status;

    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    status = select_peer(endpoint, peer);
    if (status != DMP_OK) {
        return status;
    }
    (void)select_active_route(endpoint);
    PEER(endpoint, revoked) = 1U;
    PEER(endpoint, retirement_requested) = 1U;
    clear_peer_freshness(endpoint, peer);
    release_peer_buffer_contexts(endpoint, &endpoint->peers[endpoint->active_peer_slot]);
    if (endpoint->mem.senders != NULL) {
        for (index = 0U; index < endpoint->mem.sender_capacity; index++) {
            dmp_reliability_sender_slot *sender = &endpoint->mem.senders[index];
            dmp_reliability_handle handle;

            if (sender->live == 0U ||
                !peer_equal(sender->peer, peer) ||
                (sender->kind != DMP_REL_SENDER_REQUEST && sender->kind != DMP_REL_SENDER_DATA) ||
                sender->phase == DMP_REL_PHASE_TERMINAL) {
                continue;
            }
            handle.slot = (uint32_t)index;
            handle.generation = sender->generation;
            handle.peer = sender->peer;
            (void)dmp_reliability_cancel(&endpoint->reliability, handle, now);
        }
    }
    if (PEER(endpoint, association) != NULL) {
        for (attempt = 0U; attempt < DMP_HS_ATTEMPT_MAX; attempt++) {
            if (!dmp_hs_terminal(PEER(endpoint, association), attempt)) {
                (void)dmp_hs_cancel(PEER(endpoint, association), attempt);
            }
        }
    }
    end_drain(endpoint, now);
    retire_revoked_peers(endpoint, now);
    return DMP_OK;
}

dmp_status dmp_endpoint_peer_association(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                         dmp_identity_handle *association)
{
    dmp_status status;
    if (!ready(endpoint) || association == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    status = select_peer(endpoint, peer);
    if (status != DMP_OK) {
        return status;
    }
    if (PEER(endpoint, revoked) != 0U || PEER(endpoint, association_bound) == 0U ||
        PEER(endpoint, association) == NULL ||
        dmp_hs_send_application(PEER(endpoint, association), PEER(endpoint, association_attempt)) !=
            DMP_HS_OK) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    *association = PEER(endpoint, context);
    return DMP_OK;
}

dmp_status dmp_endpoint_peer_fence_status(dmp_endpoint *endpoint, dmp_peer_handle peer)
{
    dmp_status status;
    if (!ready(endpoint) || peer.generation == 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    status = select_peer(endpoint, peer);
    if (status != DMP_OK) {
        return status;
    }
    if (PEER(endpoint, revoked) == 0U || PEER(endpoint, retirement_requested) == 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    return peer_has_outer_tx(endpoint, peer) ? DMP_BUSY : DMP_OK;
}

dmp_status dmp_endpoint_validate_association(const dmp_endpoint *endpoint,
                                             dmp_identity_handle association,
                                             uint32_t namespace_id, uint32_t origin_id)
{
    uint32_t index;
    if (!ready(endpoint) || association.generation == 0U ||
        namespace_id != endpoint->profile.namespace_id ||
        origin_id != endpoint->mem.context.local.origin_id) {
        return DMP_INVALID_ARGUMENT;
    }
    for (index = 0U; index < endpoint->profile.peers; index++) {
        const dmp_endpoint_peer_state *peer = &endpoint->peers[index];
        dmp_identity_handle route_context;
        uint32_t attempt;
        const dmp_identity_slot *slot;
        int current;
        if (peer->live == 0U || peer->revoked != 0U || peer->association_bound == 0U ||
            peer->association == NULL) {
            continue;
        }
        current = peer->context.slot == association.slot &&
                  peer->context.generation == association.generation;
        if (current) {
            route_context = peer->context;
            attempt = peer->association_attempt;
        } else if (peer->drain_live != 0U &&
                   peer->drain_context.slot == association.slot &&
                   peer->drain_context.generation == association.generation) {
            route_context = peer->drain_context;
            attempt = peer->drain_attempt;
        } else {
            continue;
        }
        if (route_context.slot >= endpoint->identity.capacity) {
            continue;
        }
        slot = &endpoint->identity.slots[route_context.slot];
        if (slot->generation == association.generation && slot->state == DMP_IDENTITY_SLOT_ACTIVE &&
            current &&
            slot->local.namespace_id == namespace_id && slot->local.origin_id == origin_id &&
            dmp_hs_send_application(peer->association, attempt) == DMP_HS_OK) {
            return DMP_OK;
        }
        if (!current && slot->generation == association.generation &&
            slot->state == DMP_IDENTITY_SLOT_DRAINING &&
            slot->local.namespace_id == namespace_id && slot->local.origin_id == origin_id &&
            dmp_hs_send_application(peer->association, attempt) == DMP_HS_OK) {
            return DMP_OK;
        }
    }
    return DMP_AUTHENTICATION_FAILURE;
}

dmp_status dmp_endpoint_revoke(dmp_endpoint *endpoint, dmp_time_ms now)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) {
        return DMP_INVALID_ARGUMENT;
    }
    return dmp_endpoint_revoke_peer(endpoint, peer, now);
}

dmp_status dmp_endpoint_bind_peer(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                  struct dmp_hs *handshake, uint32_t attempt_index)
{
    dmp_hs_tx_reservation reservation;
    dmp_hs_status retain_status;
    dmp_identity_slot *slot;
    uint32_t namespace_id = 0U;
    uint32_t local_id = 0U;
    uint32_t peer_id = 0U;
    uint64_t local_epoch = 0U;
    uint64_t peer_epoch = 0U;

    if (!ready(endpoint) || handshake == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (endpoint->profile.peers > 1U &&
        !dmp_hs_uses_admission(handshake, endpoint->handshake_admission)) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    {
        dmp_status status = select_peer(endpoint, peer);
        if (status != DMP_OK) return status;
        status = select_active_route(endpoint);
        if (status != DMP_OK) return status;
    }
    if (PEER(endpoint, association_bound) != 0U) {
        if (handshake != PEER(endpoint, association) ||
            attempt_index != PEER(endpoint, association_attempt)) {
            return DMP_BUSY;
        }
        return install_epochs(endpoint);
    }
    if (PEER(endpoint, revoked) != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (PEER(endpoint, context).slot >= endpoint->identity.capacity) {
        return DMP_STALE_HANDLE;
    }
    slot = &endpoint->identity.slots[PEER(endpoint, context).slot];
    if (slot->generation != PEER(endpoint, context).generation || slot->security != 1U) {
        return DMP_INVALID_ARGUMENT;
    }
    if (!dmp_hs_traffic_identity(handshake, attempt_index, &namespace_id, &local_id, &peer_id,
                                 &local_epoch, &peer_epoch)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (slot->local.namespace_id != namespace_id || slot->local.origin_id != local_id ||
        slot->peer.namespace_id != namespace_id || slot->peer.origin_id != peer_id) {
        return DMP_INVALID_ARGUMENT;
    }
    if (local_id != endpoint->mem.context.local.origin_id) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    (void)peer_epoch;
    memset(&reservation, 0, sizeof reservation);
    if (secured(endpoint)) {
        retain_status = dmp_hs_send_application(handshake, attempt_index);
        if (retain_status == DMP_HS_OK) {
            retain_status = dmp_hs_retain_association_reservation(handshake, attempt_index,
                                                                  &reservation);
            if (retain_status != DMP_HS_OK) {
                return from_hs(retain_status);
            }
        } else if (retain_status != DMP_HS_NOT_ACTIVE ||
                   dmp_hs_terminal(handshake, attempt_index)) {
            return from_hs(retain_status);
        }
    }
    PEER(endpoint, association) = handshake;
    PEER(endpoint, association_attempt) = attempt_index;
    PEER(endpoint, association_bound) = 1U;
    {
        dmp_status status = install_epochs(endpoint);
        if (status != DMP_OK) {
            PEER(endpoint, association) = NULL;
            PEER(endpoint, association_bound) = 0U;
            if (reservation.count != 0U) {
                (void)dmp_hs_release_tx_reservation(handshake, &reservation);
            }
            return status;
        }
    }
    if (reservation.count != 0U) {
        store_association_reservation(&endpoint->peers[endpoint->active_peer_slot],
                                      &reservation, 0);
    }
    return DMP_OK;
}

dmp_status dmp_endpoint_bind(dmp_endpoint *endpoint, struct dmp_hs *handshake, uint32_t attempt_index)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) {
        return DMP_INVALID_ARGUMENT;
    }
    return dmp_endpoint_bind_peer(endpoint, peer, handshake, attempt_index);
}

static dmp_status submit_req_with_token(dmp_endpoint *endpoint, uint32_t service_id,
                                        dmp_bytes payload, dmp_bytes token, dmp_time_ms now,
                                        dmp_reliability_handle *out)
{
    dmp_buffer probe;
    size_t written = 0U;
    dmp_status status;
    if (!ready(endpoint) || out == NULL || !bytes_ok(payload) || !bytes_ok(token) ||
        (token.size != 0U && token.size != 16U)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (PEER(endpoint, revoked) != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (service_id == 0U) {
        if (!secured(endpoint) || token.size != 0U) {
            return DMP_UNSUPPORTED;
        }
    } else if (!service_allowed(&endpoint->profile, service_id) ||
               (freshness_required(&endpoint->profile, service_id) != (token.size == 16U))) {
        return DMP_UNSUPPORTED;
    }
    if (!local_action(endpoint, service_id, DMP_ENDPOINT_PERMIT_REQ)) {
        return DMP_UNSUPPORTED;
    }
    probe.data = NULL;
    probe.capacity = local_core_mtu(endpoint);
    PEER(endpoint, encode_freshness_live) = token.size == 16U ? 1U : 0U;
    if (PEER(endpoint, encode_freshness_live) != 0U) {
        memcpy(PEER(endpoint, encode_freshness_token), token.data, sizeof PEER(endpoint, encode_freshness_token));
    }
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_REQ, service_id, 0U, 1, 0, 0U, 0U, 0U, payload,
                         0, (dmp_message_key){0}, 0, 0U, secured(endpoint), secured(endpoint),
                         PEER(endpoint, association_attempt), probe, &written);
    PEER(endpoint, encode_freshness_live) = 0U;
    memset(PEER(endpoint, encode_freshness_token), 0, sizeof PEER(endpoint, encode_freshness_token));
    /* Fragment only when this exact non-FRAG frame does not fit the
     * directional decoded-core MTU.
     * DMP_LIMIT_EXHAUSTED from the size check is that miss. A protected body
     * above DMP_HS_APP_PLAIN_MAX is the same miss: the seal buffer cannot
     * hold it as one record. */
    if (status == DMP_LIMIT_EXHAUSTED && endpoint->profile.chunk_bytes != 0U &&
        payload.size > endpoint->profile.chunk_bytes) {
        uint32_t count = 1U + ((uint32_t)payload.size - 1U) / endpoint->profile.chunk_bytes;
        if (count >= 2U && count <= 32U && count <= endpoint->profile.fragments) {
            return token.size == 16U
                       ? dmp_reliability_submit_req_fresh(&endpoint->reliability, service_id,
                                                          payload, token, now, 0U, out)
                       : dmp_reliability_submit_req(&endpoint->reliability, service_id, payload,
                                                    now, 0U, out);
        }
        return DMP_LIMIT_EXHAUSTED;
    }
    if (status != DMP_OK) {
        return status;
    }
    return token.size == 16U
               ? dmp_reliability_submit_req_fresh(&endpoint->reliability, service_id, payload,
                                                  token, now, 0U, out)
               : dmp_reliability_submit_req(&endpoint->reliability, service_id, payload, now, 0U,
                                            out);
}

dmp_status dmp_endpoint_submit_req_to(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                     uint32_t service_id, dmp_bytes payload,
                                     dmp_time_ms now, dmp_reliability_handle *out)
{
    dmp_bytes empty = {NULL, 0U};
    dmp_status status;
    if (!ready(endpoint)) return DMP_INVALID_ARGUMENT;
    status = select_peer(endpoint, peer);
    if (status != DMP_OK) return status;
    status = select_active_route(endpoint);
    if (status != DMP_OK) return status;
    return submit_req_with_token(endpoint, service_id, payload, empty, now, out);
}

dmp_status dmp_endpoint_submit_req(dmp_endpoint *endpoint, uint32_t service_id, dmp_bytes payload,
                                   dmp_time_ms now, dmp_reliability_handle *out)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) return DMP_INVALID_ARGUMENT;
    return dmp_endpoint_submit_req_to(endpoint, peer, service_id, payload, now, out);
}

dmp_status dmp_endpoint_submit_req_fresh_to(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                            uint32_t service_id, dmp_bytes payload,
                                            dmp_bytes token, dmp_time_ms now,
                                            dmp_reliability_handle *out)
{
    if (token.size != 16U || token.data == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (!ready(endpoint)) return DMP_INVALID_ARGUMENT;
    {
        dmp_status status = select_peer(endpoint, peer);
        if (status != DMP_OK) return status;
        status = select_active_route(endpoint);
        if (status != DMP_OK) return status;
    }
    return submit_req_with_token(endpoint, service_id, payload, token, now, out);
}

dmp_status dmp_endpoint_submit_req_fresh(dmp_endpoint *endpoint, uint32_t service_id,
                                         dmp_bytes payload, dmp_bytes token,
                                         dmp_time_ms now, dmp_reliability_handle *out)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) return DMP_INVALID_ARGUMENT;
    return dmp_endpoint_submit_req_fresh_to(endpoint, peer, service_id, payload, token, now, out);
}

static dmp_status probe_reliable_unfragmented(dmp_endpoint *endpoint, uint8_t type,
                                              uint32_t service_id, dmp_bytes payload,
                                              dmp_bytes token)
{
    dmp_buffer probe = {secured(endpoint) != 0 ? NULL : endpoint->mem.fragment_frame,
                        local_core_mtu(endpoint)};
    size_t written = 0U;
    dmp_status status;
    PEER(endpoint, encode_freshness_live) = token.size == 16U ? 1U : 0U;
    if (PEER(endpoint, encode_freshness_live) != 0U) {
        memcpy(PEER(endpoint, encode_freshness_token), token.data,
               sizeof PEER(endpoint, encode_freshness_token));
    }
    status = encode_core(endpoint, type, service_id, 0U, 1, 0, 0U, 0U, 0U, payload, 0,
                         (dmp_message_key){0}, 0, 0U, secured(endpoint), secured(endpoint),
                         PEER(endpoint, association_attempt), probe, &written);
    PEER(endpoint, encode_freshness_live) = 0U;
    memset(PEER(endpoint, encode_freshness_token), 0, sizeof PEER(endpoint, encode_freshness_token));
    return status;
}

static dmp_status submit_reliable_data_type(dmp_endpoint *endpoint, uint8_t type,
                                            uint32_t service_id, dmp_bytes payload,
                                            dmp_bytes token, dmp_time_ms now,
                                            dmp_reliability_handle *out)
{
    uint32_t count;
    dmp_status status;
    if (payload.size > endpoint->profile.message_bytes) {
        return DMP_LIMIT_EXHAUSTED;
    }
    status = probe_reliable_unfragmented(endpoint, type, service_id, payload, token);
    if (status == DMP_LIMIT_EXHAUSTED && endpoint->profile.chunk_bytes != 0U &&
        payload.size > endpoint->profile.chunk_bytes) {
        count = 1U + ((uint32_t)payload.size - 1U) / endpoint->profile.chunk_bytes;
        if (count < 2U || count > 32U || count > endpoint->profile.fragments) {
            return DMP_LIMIT_EXHAUSTED;
        }
        if (type == DMP_TYPE_DATA) {
            return token.size == 16U
                       ? dmp_reliability_submit_data_fresh(&endpoint->reliability, service_id,
                                                           payload, token, now, out)
                       : dmp_reliability_submit_data(&endpoint->reliability, service_id, payload,
                                                     now, out);
        }
        return token.size == 16U
                   ? dmp_reliability_submit_event_fresh(&endpoint->reliability, service_id,
                                                        payload, token, now, out)
                   : dmp_reliability_submit_event(&endpoint->reliability, service_id, payload,
                                                  now, out);
    }
    if (status != DMP_OK) {
        return status;
    }
    if (type == DMP_TYPE_DATA) {
        return token.size == 16U
                   ? dmp_reliability_submit_data_fresh(&endpoint->reliability, service_id,
                                                       payload, token, now, out)
                   : dmp_reliability_submit_data(&endpoint->reliability, service_id, payload,
                                                 now, out);
    }
    return token.size == 16U
               ? dmp_reliability_submit_event_fresh(&endpoint->reliability, service_id, payload,
                                                    token, now, out)
               : dmp_reliability_submit_event(&endpoint->reliability, service_id, payload, now,
                                              out);
}

dmp_status dmp_endpoint_submit_data_to(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                       uint32_t service_id, dmp_bytes payload,
                                       dmp_bytes token, dmp_time_ms now,
                                       dmp_reliability_handle *out)
{
    if (!ready(endpoint) || out == NULL || !bytes_ok(payload) || !bytes_ok(token) ||
        (token.size != 0U && token.size != 16U)) {
        return DMP_INVALID_ARGUMENT;
    }
    {
        dmp_status status = select_peer(endpoint, peer);
        if (status != DMP_OK) return status;
        status = select_active_route(endpoint);
        if (status != DMP_OK) return status;
    }
    if (PEER(endpoint, revoked) != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!service_allowed(&endpoint->profile, service_id) || service_id == 0U ||
        (freshness_required(&endpoint->profile, service_id) != (token.size == 16U))) {
        return DMP_UNSUPPORTED;
    }
    if (!local_action(endpoint, service_id, DMP_ENDPOINT_PERMIT_REQ)) {
        return DMP_UNSUPPORTED;
    }
    return submit_reliable_data_type(endpoint, (uint8_t)DMP_TYPE_DATA, service_id, payload,
                                     token, now, out);
}

dmp_status dmp_endpoint_submit_data(dmp_endpoint *endpoint, uint32_t service_id,
                                    dmp_bytes payload, dmp_bytes token, dmp_time_ms now,
                                    dmp_reliability_handle *out)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) return DMP_INVALID_ARGUMENT;
    return dmp_endpoint_submit_data_to(endpoint, peer, service_id, payload, token, now, out);
}

dmp_status dmp_endpoint_submit_event_to(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                        uint32_t service_id, dmp_bytes payload,
                                        dmp_bytes token, dmp_time_ms now,
                                        dmp_reliability_handle *out)
{
    if (!ready(endpoint) || out == NULL || !bytes_ok(payload) || !bytes_ok(token) ||
        (token.size != 0U && token.size != 16U)) {
        return DMP_INVALID_ARGUMENT;
    }
    {
        dmp_status status = select_peer(endpoint, peer);
        if (status != DMP_OK) return status;
        status = select_active_route(endpoint);
        if (status != DMP_OK) return status;
    }
    if (PEER(endpoint, revoked) != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!service_allowed(&endpoint->profile, service_id) || service_id == 0U ||
        (freshness_required(&endpoint->profile, service_id) != (token.size == 16U))) {
        return DMP_UNSUPPORTED;
    }
    if (!local_action(endpoint, service_id, DMP_ENDPOINT_PERMIT_REQ)) {
        return DMP_UNSUPPORTED;
    }
    return submit_reliable_data_type(endpoint, (uint8_t)DMP_TYPE_EVENT, service_id, payload,
                                     token, now, out);
}

dmp_status dmp_endpoint_submit_event(dmp_endpoint *endpoint, uint32_t service_id,
                                     dmp_bytes payload, dmp_bytes token, dmp_time_ms now,
                                     dmp_reliability_handle *out)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) return DMP_INVALID_ARGUMENT;
    return dmp_endpoint_submit_event_to(endpoint, peer, service_id, payload, token, now, out);
}

static dmp_status endpoint_complete_for_lifetime(dmp_endpoint *endpoint,
                                                dmp_reliability_handle request,
                                                bool application_err, uint32_t wire_status,
                                                dmp_bytes payload, uint32_t result_lifetime_ms,
                                                dmp_time_ms now)
{
    dmp_status status;
    int swapped = 0;

    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    status = select_peer(endpoint, request.peer);
    if (status != DMP_OK || select_active_route(endpoint) != DMP_OK) {
        return DMP_STALE_HANDLE;
    }
    if (PEER(endpoint, revoked) != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (request.slot < endpoint->mem.history_capacity && endpoint->mem.history != NULL) {
        dmp_reliability_history_slot *history = &endpoint->mem.history[request.slot];
        if (history->live != 0U && history->generation == request.generation &&
            peer_equal(history->peer, request.peer)) {
            dmp_identity_slot *active = NULL;
            dmp_identity_slot *draining = NULL;
            int source_is_active = 0;
            int source_is_draining = 0;

            if (PEER(endpoint, context).slot < endpoint->identity.capacity) {
                active = &endpoint->identity.slots[PEER(endpoint, context).slot];
                source_is_active = active->generation == PEER(endpoint, context).generation &&
                                   active->state == DMP_IDENTITY_SLOT_ACTIVE &&
                                   message_origin_eq(history->source.origin, active->peer);
            }
            if (PEER(endpoint, drain_live) != 0U &&
                PEER(endpoint, drain_context).slot < endpoint->identity.capacity) {
                draining = &endpoint->identity.slots[PEER(endpoint, drain_context).slot];
                source_is_draining = draining->generation == PEER(endpoint, drain_context).generation &&
                                    draining->state == DMP_IDENTITY_SLOT_DRAINING &&
                                    message_origin_eq(history->source.origin, draining->peer);
            }
            if (!source_is_active && !source_is_draining) {
                return DMP_STALE_HANDLE;
            }
            if (source_is_draining && dmp_deadline_reached(now, draining->not_after)) {
                return DMP_DEADLINE_EXPIRED;
            }
            /* Local RESULT permission applies with or without a live drain. */
            if (!local_action(endpoint, history->service_id, DMP_ENDPOINT_PERMIT_RESULT)) {
                return DMP_UNSUPPORTED;
            }
            if (source_is_draining) {
                use_context(endpoint, PEER(endpoint, drain_context));
                swapped = 1;
            }
        }
    }
    status = dmp_reliability_complete_for_lifetime(&endpoint->reliability, request,
                                                   application_err, wire_status, payload,
                                                   result_lifetime_ms, now);
    if (swapped) {
        use_context(endpoint, PEER(endpoint, context));
    }
    return status;
}

dmp_status dmp_endpoint_complete(dmp_endpoint *endpoint, dmp_reliability_handle request,
                                 bool application_err, uint32_t wire_status, dmp_bytes payload,
                                 dmp_time_ms now)
{
    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    return endpoint_complete_for_lifetime(endpoint, request, application_err, wire_status, payload,
                                          endpoint->profile.result_cache_ms, now);
}

dmp_status dmp_endpoint_abandon_request(dmp_endpoint *endpoint,
                                        dmp_reliability_handle request,
                                        dmp_time_ms now)
{
    dmp_reliability_history_slot *history;
    dmp_status status;

    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    status = select_peer(endpoint, request.peer);
    if (status != DMP_OK || select_active_route(endpoint) != DMP_OK) {
        return DMP_STALE_HANDLE;
    }
    if (request.slot >= endpoint->mem.history_capacity || endpoint->mem.history == NULL) {
        return DMP_STALE_HANDLE;
    }
    history = &endpoint->mem.history[request.slot];
    if (history->live == 0U || history->generation != request.generation ||
        !peer_equal(history->peer, request.peer) || history->decision != 0U) {
        return DMP_STALE_HANDLE;
    }
    if (PEER(endpoint, pending_grant_live) != 0U &&
        PEER(endpoint, pending_grant_request).slot == request.slot &&
        PEER(endpoint, pending_grant_request).generation == request.generation &&
        peer_equal(PEER(endpoint, pending_grant_request).peer, request.peer)) {
        return DMP_BUSY;
    }
    if (PEER(endpoint, revoked) == 0U && PEER(endpoint, context).slot < endpoint->identity.capacity) {
        const dmp_identity_slot *active = &endpoint->identity.slots[PEER(endpoint, context).slot];
        if (active->generation == PEER(endpoint, context).generation &&
            active->state == DMP_IDENTITY_SLOT_ACTIVE &&
            message_origin_eq(history->source.origin, active->peer)) {
            return DMP_BUSY;
        }
    }
    if (PEER(endpoint, drain_live) != 0U &&
        PEER(endpoint, drain_context).slot < endpoint->identity.capacity) {
        const dmp_identity_slot *draining =
            &endpoint->identity.slots[PEER(endpoint, drain_context).slot];
        if (draining->generation == PEER(endpoint, drain_context).generation &&
            draining->state == DMP_IDENTITY_SLOT_DRAINING &&
            message_origin_eq(history->source.origin, draining->peer) &&
            !dmp_deadline_reached(now, draining->not_after)) {
            return DMP_BUSY;
        }
    }

    status = dmp_reliability_abandon_request(&endpoint->reliability, request);
    if (status == DMP_OK) {
        expire_drain(endpoint, now);
    }
    return status;
}

static dmp_status stage_telem(dmp_endpoint *endpoint, uint32_t service_id, dmp_bytes payload,
                              int replace)
{
    dmp_buffer probe;
    size_t written = 0U;
    dmp_status status;
    if (!service_allowed(&endpoint->profile, service_id) || service_id == 0U ||
        freshness_required(&endpoint->profile, service_id) || !bytes_ok(payload) ||
        payload.size > endpoint->profile.message_bytes) {
        return payload.size > endpoint->profile.message_bytes ? DMP_LIMIT_EXHAUSTED
                                                             : DMP_UNSUPPORTED;
    }
    if (PEER(endpoint, revoked) != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!local_action(endpoint, service_id, DMP_ENDPOINT_PERMIT_TELEM)) {
        return DMP_UNSUPPORTED;
    }
    /* Validate geometry without writing into a frame that an accepted BORROW
     * transport may still own through its terminal callback. */
    probe.data = NULL;
    probe.capacity = 0U;
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_TELEM, service_id, 0U, 0, 0, 0U, 0U, 0U,
                         payload, 0, (dmp_message_key){0}, 0, 0U, 0, 0, 0U, probe, &written);
    if (status != DMP_OK) {
        return status;
    }
    if (replace) {
        if (PEER(endpoint, telem_next_context_retained) != 0U) {
            (void)dmp_identity_context_release(&endpoint->identity,
                                               PEER(endpoint, telem_next_context));
            PEER(endpoint, telem_next_context_retained) = 0U;
        }
        status = dmp_identity_context_retain(&endpoint->identity, PEER(endpoint, context));
        if (status != DMP_OK) return status;
        if (payload.size != 0U) {
            memcpy(peer_telemetry_next_buffer(endpoint), payload.data, payload.size);
        }
        PEER(endpoint, telem_next_len) = (uint32_t)payload.size;
        PEER(endpoint, telem_next_context) = PEER(endpoint, context);
        PEER(endpoint, telem_next_attempt) = PEER(endpoint, association_attempt);
        PEER(endpoint, telem_next_context_retained) = 1U;
        PEER(endpoint, telem_hold) = 1U;
        return DMP_OK;
    }
    if (PEER(endpoint, telem_context_retained) != 0U) {
        (void)dmp_identity_context_release(&endpoint->identity, PEER(endpoint, telem_context));
        PEER(endpoint, telem_context_retained) = 0U;
    }
    status = dmp_identity_context_retain(&endpoint->identity, PEER(endpoint, context));
    if (status != DMP_OK) return status;
    if (payload.size != 0U) {
        memcpy(peer_telemetry_buffer(endpoint), payload.data, payload.size);
    }
    PEER(endpoint, telem_context) = PEER(endpoint, context);
    PEER(endpoint, telem_context_retained) = 1U;
    PEER(endpoint, telem_attempt) = PEER(endpoint, association_attempt);
    PEER(endpoint, telem_len) = (uint32_t)payload.size;
    PEER(endpoint, telem_service) = service_id;
    PEER(endpoint, telem_pending) = 1U;
    PEER(endpoint, telem_seq_set) = 0U;
    return DMP_OK;
}

dmp_status dmp_endpoint_submit_telem_to(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                        uint32_t service_id, dmp_bytes payload, dmp_time_ms now)
{
    (void)now;
    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    {
        dmp_status status = select_peer(endpoint, peer);
        if (status != DMP_OK) return status;
        status = select_active_route(endpoint);
        if (status != DMP_OK) return status;
    }
    if (PEER(endpoint, telem_tx) != 0U) {
        return stage_telem(endpoint, service_id, payload, 1);
    }
    if (PEER(endpoint, telem_pending) != 0U) {
        PEER(endpoint, telem_seq_set) = 0U;
    }
    return stage_telem(endpoint, service_id, payload, 0);
}

dmp_status dmp_endpoint_submit_telem(dmp_endpoint *endpoint, uint32_t service_id,
                                     dmp_bytes payload, dmp_time_ms now)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) return DMP_INVALID_ARGUMENT;
    return dmp_endpoint_submit_telem_to(endpoint, peer, service_id, payload, now);
}

static dmp_status send_telem(dmp_endpoint *endpoint, dmp_time_ms now)
{
    dmp_buffer out;
    dmp_bytes payload;
    dmp_time_ms not_after;
    size_t written = 0U;
    dmp_status status;
    if (PEER(endpoint, revoked) != 0U || PEER(endpoint, telem_context_retained) == 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (PEER(endpoint, telem_context).slot >= endpoint->identity.capacity) {
        return DMP_STALE_HANDLE;
    }
    {
        const dmp_identity_slot *saved =
            &endpoint->identity.slots[PEER(endpoint, telem_context).slot];
        if (saved->generation != PEER(endpoint, telem_context).generation ||
            (PEER(endpoint, telem_context).slot != PEER(endpoint, context).slot &&
             (PEER(endpoint, drain_live) == 0U ||
              PEER(endpoint, telem_context).slot != PEER(endpoint, drain_context).slot ||
              dmp_deadline_reached(now, PEER(endpoint, drain_not_after))))) {
            return DMP_DEADLINE_EXPIRED;
        }
    }
    if (PEER(endpoint, telem_seq_set) == 0U) {
        status = dmp_identity_next_seq(&endpoint->identity, PEER(endpoint, telem_context), &PEER(endpoint, telem_seq));
        if (status != DMP_OK) {
            return status;
        }
        PEER(endpoint, telem_seq_set) = 1U;
    }
    payload.data = PEER(endpoint, telem_len) == 0U ? NULL : peer_telemetry_buffer(endpoint);
    payload.size = PEER(endpoint, telem_len);
    out.data = endpoint->mem.telemetry_frame;
    out.capacity = local_core_mtu(endpoint);
    use_context(endpoint, PEER(endpoint, telem_context));
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_TELEM, PEER(endpoint, telem_service),
                         PEER(endpoint, telem_seq), 0, 0, 0U, 0U, 0U, payload, 0, (dmp_message_key){0}, 0,
                         0U, secured(endpoint), secured(endpoint), PEER(endpoint, telem_attempt), out,
                         &written);
    use_context(endpoint, PEER(endpoint, context));
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_deadline_after(now, endpoint->profile.send_horizon_ms, &not_after);
    if (status != DMP_OK) {
        return status;
    }
    PEER(endpoint, telem_tx) = 1U;
    payload.data = endpoint->mem.telemetry_frame;
    payload.size = written;
    status = submit_wire(endpoint, KIND_TELEM, payload, PEER(endpoint, telem_context), NULL, NULL,
                         (dmp_tx_token){0}, not_after);
    if (status != DMP_OK) {
        PEER(endpoint, telem_tx) = 0U;
        return status;
    }
    return DMP_OK;
}

static dmp_status send_fragment(dmp_endpoint *endpoint, dmp_time_ms now)
{
    dmp_buffer out;
    dmp_bytes slice;
    dmp_bytes frame;
    dmp_time_ms not_after;
    uint32_t offset;
    uint32_t expect;
    size_t written = 0U;
    dmp_status status;
    if (PEER(endpoint, revoked) != 0U || PEER(endpoint, frag_context_retained) == 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (PEER(endpoint, frag_context).slot >= endpoint->identity.capacity) {
        return DMP_STALE_HANDLE;
    }
    {
        const dmp_identity_slot *saved =
            &endpoint->identity.slots[PEER(endpoint, frag_context).slot];
        if (saved->generation != PEER(endpoint, frag_context).generation ||
            (PEER(endpoint, frag_context).slot != PEER(endpoint, context).slot &&
             (PEER(endpoint, drain_live) == 0U ||
              PEER(endpoint, frag_context).slot != PEER(endpoint, drain_context).slot ||
              dmp_deadline_reached(now, PEER(endpoint, drain_not_after))))) {
            return DMP_DEADLINE_EXPIRED;
        }
    }
    offset = PEER(endpoint, frag_index) * endpoint->profile.chunk_bytes;
    expect = PEER(endpoint, frag_total) - offset;
    if (expect > endpoint->profile.chunk_bytes) {
        expect = endpoint->profile.chunk_bytes;
    }
    slice.data = peer_fragment_buffer(endpoint) + offset;
    slice.size = expect;
    out.data = endpoint->mem.fragment_frame;
    out.capacity = local_core_mtu(endpoint);
    use_context(endpoint, PEER(endpoint, frag_context));
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_DATA, PEER(endpoint, frag_service), PEER(endpoint, frag_seq),
                         0, 1, PEER(endpoint, frag_index), endpoint->profile.chunk_bytes,
                         PEER(endpoint, frag_total), slice, 0, (dmp_message_key){0}, 0, 0U,
                         secured(endpoint), secured(endpoint), PEER(endpoint, frag_attempt), out, &written);
    use_context(endpoint, PEER(endpoint, context));
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_deadline_after(now, endpoint->profile.send_horizon_ms, &not_after);
    if (status != DMP_OK) {
        return status;
    }
    PEER(endpoint, frag_tx) = 1U;
    frame.data = endpoint->mem.fragment_frame;
    frame.size = written;
    status = submit_wire(endpoint, KIND_FRAG, frame, PEER(endpoint, frag_context), NULL, NULL,
                         (dmp_tx_token){0}, not_after);
    if (status != DMP_OK) {
        PEER(endpoint, frag_tx) = 0U;
        return status;
    }
    return DMP_OK;
}

dmp_status dmp_endpoint_submit_fragmented_to(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                             uint32_t service_id, dmp_bytes payload,
                                             dmp_time_ms now)
{
    const dmp_identity_slot *slot;
    dmp_buffer probe;
    dmp_bytes slice;
    size_t written = 0U;
    uint32_t chunk;
    uint32_t count;
    uint32_t seq = 0U;
    dmp_status status;
    (void)now;
    if (!ready(endpoint) || !bytes_ok(payload) || payload.size == 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    {
        dmp_status route = select_peer(endpoint, peer);
        if (route != DMP_OK) return route;
        route = select_active_route(endpoint);
        if (route != DMP_OK) return route;
    }
    if (!service_allowed(&endpoint->profile, service_id)) {
        return DMP_UNSUPPORTED;
    }
    if (service_id == 0U || freshness_required(&endpoint->profile, service_id)) {
        return DMP_UNSUPPORTED;
    }
    if (PEER(endpoint, revoked) != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!local_action(endpoint, service_id, DMP_ENDPOINT_PERMIT_REQ)) {
        return DMP_UNSUPPORTED;
    }
    if (PEER(endpoint, frag_live) != 0U) {
        return DMP_QUOTA_EXHAUSTED;
    }
    if (payload.size > endpoint->profile.message_bytes) {
        return DMP_LIMIT_EXHAUSTED;
    }
    if (PEER(endpoint, context).slot >= endpoint->identity.capacity) {
        return DMP_STALE_HANDLE;
    }
    slot = &endpoint->identity.slots[PEER(endpoint, context).slot];
    if (slot->generation != PEER(endpoint, context).generation || slot->seq_exhausted) {
        return DMP_STALE_HANDLE;
    }
    probe.data = secured(endpoint) != 0 ? NULL : endpoint->mem.fragment_frame;
    probe.capacity = local_core_mtu(endpoint);
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_DATA, service_id, slot->next_seq, 0, 0, 0U, 0U,
                         0U, payload, 0, (dmp_message_key){0}, 0, 0U, secured(endpoint),
                         secured(endpoint), PEER(endpoint, association_attempt), probe, &written);
    if (status == DMP_OK) {
        return DMP_INVALID_ARGUMENT;
    }
    if (status != DMP_LIMIT_EXHAUSTED) {
        return status;
    }
    chunk = endpoint->profile.chunk_bytes;
    if (chunk == 0U || chunk >= payload.size) {
        return DMP_LIMIT_EXHAUSTED;
    }
    count = 1U + ((uint32_t)payload.size - 1U) / chunk;
    if (count < 2U || count > endpoint->profile.fragments || count > 32U) {
        return DMP_LIMIT_EXHAUSTED;
    }
    /* Every non-final slice is full-sized. Admission must check one before
     * retaining the message or consuming its SEQ; probing only the short tail
     * can accept a transfer whose first frame cannot fit the protected MTU. */
    slice.data = payload.data;
    slice.size = chunk;
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_DATA, service_id, slot->next_seq, 0, 1, 0U,
                         chunk, (uint32_t)payload.size, slice, 0, (dmp_message_key){0}, 0, 0U,
                         secured(endpoint), secured(endpoint), PEER(endpoint, association_attempt),
                         probe, &written);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_identity_context_retain(&endpoint->identity, PEER(endpoint, context));
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_identity_next_seq(&endpoint->identity, PEER(endpoint, context), &seq);
    if (status != DMP_OK) {
        (void)dmp_identity_context_release(&endpoint->identity, PEER(endpoint, context));
        return status;
    }
    PEER(endpoint, frag_context) = PEER(endpoint, context);
    PEER(endpoint, frag_context_retained) = 1U;
    PEER(endpoint, frag_attempt) = PEER(endpoint, association_attempt);
    memcpy(peer_fragment_buffer(endpoint), payload.data, payload.size);
    PEER(endpoint, frag_service) = service_id;
    PEER(endpoint, frag_seq) = seq;
    PEER(endpoint, frag_total) = (uint32_t)payload.size;
    PEER(endpoint, frag_count) = count;
    PEER(endpoint, frag_index) = 0U;
    PEER(endpoint, frag_tx) = 0U;
    PEER(endpoint, frag_live) = 1U;
    return DMP_OK;
}

dmp_status dmp_endpoint_submit_fragmented(dmp_endpoint *endpoint, uint32_t service_id,
                                          dmp_bytes payload, dmp_time_ms now)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) return DMP_INVALID_ARGUMENT;
    return dmp_endpoint_submit_fragmented_to(endpoint, peer, service_id, payload, now);
}

static int service_selective(const dmp_admitted_profile *profile, uint32_t service)
{
    if (service == profile->service_id[0]) {
        return profile->recovery[0] == DMP_PROFILE_RECOVERY_SELECTIVE32;
    }
    if (service == profile->service_id[1]) {
        return profile->recovery[1] == DMP_PROFILE_RECOVERY_SELECTIVE32;
    }
    return 0;
}

static uint32_t assembly_missing(const dmp_reassembly_slot *slot)
{
    uint32_t count;
    uint32_t all;

    if (slot->chunk_size == 0U || slot->total_size <= slot->chunk_size) {
        return 0U;
    }
    count = 1U + (slot->total_size - 1U) / slot->chunk_size;
    if (count < 2U || count > 32U) {
        return 0U;
    }
    all = count == 32U ? 0xFFFFFFFFU : (1U << count) - 1U;
    return all & ~slot->received_bitmap;
}

/* One FRAG_STATUS, sealed at construction so the PN is fresh. Not a reliable
 * retry. fragment_frame is free while the one-shot DATA burst is idle. */
static dmp_status send_pending_status(dmp_endpoint *endpoint, dmp_time_ms now)
{
    size_t i;

    if (!secured(endpoint) || endpoint->wire_busy != 0U) {
        return DMP_OK;
    }
    for (i = 0U; i < endpoint->reassembly.storage.assembly_capacity; i++) {
        dmp_reassembly_slot *slot = &endpoint->reassembly.storage.assemblies[i];
        dmp_peer_handle owner_peer;
        int found = 0;
        uint8_t mask_bytes[4];
        uint32_t mask;
        uint32_t seq = 0U;
        uint32_t attempt;
        dmp_buffer out;
        dmp_bytes payload;
        dmp_bytes frame;
        dmp_time_ms not_after;
        size_t written = 0U;
        dmp_status status;

        if (slot->live == 0U || slot->complete != 0U || slot->status_expected == 0U) {
            continue;
        }
        owner_peer = peer_for_context(endpoint, slot->context, &found);
        if (!found || !peer_equal(owner_peer, PEER(endpoint, handle))) {
            continue;
        }
        if (!service_selective(&endpoint->profile, slot->service_id)) {
            slot->status_expected = 0U;
            continue;
        }
        mask = assembly_missing(slot);
        if (mask == 0U) {
            slot->status_expected = 0U;
            continue;
        }
        use_context(endpoint, slot->context);
        status = dmp_identity_next_seq(&endpoint->identity, slot->context, &seq);
        if (status != DMP_OK) {
            use_context(endpoint, PEER(endpoint, context));
            return status;
        }
        mask_bytes[0] = (uint8_t)mask;
        mask_bytes[1] = (uint8_t)(mask >> 8U);
        mask_bytes[2] = (uint8_t)(mask >> 16U);
        mask_bytes[3] = (uint8_t)(mask >> 24U);
        payload.data = mask_bytes;
        payload.size = 4U;
        attempt = PEER(endpoint, association_attempt);
        if (PEER(endpoint, drain_live) != 0U && slot->context.slot == PEER(endpoint, drain_context).slot &&
            slot->context.generation == PEER(endpoint, drain_context).generation) {
            attempt = PEER(endpoint, drain_attempt);
        } else if (slot->context.slot != PEER(endpoint, context).slot ||
                   slot->context.generation != PEER(endpoint, context).generation) {
            use_context(endpoint, PEER(endpoint, context));
            continue;
        }
        out.data = endpoint->mem.fragment_frame;
        out.capacity = local_core_mtu(endpoint);
        status = encode_core(endpoint, (uint8_t)DMP_TYPE_FRAG_STATUS, slot->service_id, seq, 0, 0,
                             0U, 0U, 0U, payload, 1, slot->source, 0, 0U, 1, 1, attempt, out,
                             &written);
        use_context(endpoint, PEER(endpoint, context));
        if (status != DMP_OK) {
            return status;
        }
        status = dmp_deadline_after(now, endpoint->profile.feedback_delay_ms, &not_after);
        if (status != DMP_OK) {
            return status;
        }
        frame.data = endpoint->mem.fragment_frame;
        frame.size = written;
        status = submit_wire(endpoint, KIND_STATUS, frame, slot->context, NULL, NULL,
                             (dmp_tx_token){0}, not_after);
        if (status != DMP_OK) {
            return status;
        }
        slot->status_mask = mask;
        slot->status_expected = 0U;
        return DMP_OK;
    }
    return DMP_OK;
}

static dmp_status poll_endpoint_peer_outputs(dmp_endpoint *endpoint, dmp_time_ms now,
                                              uint32_t peer_index)
{
    dmp_status status;
    uint64_t accepted_before;
    if (endpoint->wire_busy != 0U || peer_index >= endpoint->profile.peers ||
        endpoint->peers[peer_index].live == 0U) {
        return DMP_BUSY;
    }
    endpoint->active_peer_slot = peer_index;
    status = select_active_route(endpoint);
    if (status != DMP_OK) {
        return status;
    }
    if (PEER(endpoint, sync_pending) != 0U && PEER(endpoint, sync_tx) == 0U) {
        status = submit_sync(endpoint, now);
        if (status == DMP_OK) {
            return DMP_OK;
        }
        if (status != DMP_BUSY) {
            return status;
        }
        if (endpoint->wire_busy != 0U) {
            return DMP_BUSY;
        }
    }
    accepted_before = endpoint->accepted_tx_generation;
    status = send_pending_status(endpoint, now);
    if (endpoint->accepted_tx_generation != accepted_before) {
        return DMP_OK;
    }
    if (status != DMP_OK && status != DMP_BUSY) {
        return status;
    }
    if (PEER(endpoint, frag_live) != 0U && PEER(endpoint, frag_tx) == 0U) {
        status = send_fragment(endpoint, now);
        if (status == DMP_OK) {
            return DMP_OK;
        }
        if (status != DMP_BUSY) {
            if (PEER(endpoint, revoked) != 0U || status == DMP_DEADLINE_EXPIRED ||
                status == DMP_STALE_HANDLE || status == DMP_AUTHENTICATION_FAILURE) {
                if (PEER(endpoint, frag_context_retained) != 0U) {
                    (void)dmp_identity_context_release(&endpoint->identity,
                                                       PEER(endpoint, frag_context));
                    PEER(endpoint, frag_context_retained) = 0U;
                }
                PEER(endpoint, frag_live) = 0U;
                PEER(endpoint, frag_tx) = 0U;
            } else {
                return status;
            }
        }
    }
    if (PEER(endpoint, telem_pending) != 0U && PEER(endpoint, telem_tx) == 0U) {
        status = send_telem(endpoint, now);
        if (status == DMP_OK) {
            return DMP_OK;
        }
        if (status != DMP_BUSY) {
            if (PEER(endpoint, revoked) != 0U || status == DMP_DEADLINE_EXPIRED ||
                status == DMP_STALE_HANDLE || status == DMP_AUTHENTICATION_FAILURE) {
                if (PEER(endpoint, telem_context_retained) != 0U) {
                    (void)dmp_identity_context_release(&endpoint->identity,
                                                       PEER(endpoint, telem_context));
                    PEER(endpoint, telem_context_retained) = 0U;
                }
                PEER(endpoint, telem_pending) = 0U;
                PEER(endpoint, telem_tx) = 0U;
            } else {
                return status;
            }
        }
    }
    return DMP_OK;
}

dmp_status dmp_endpoint_poll(dmp_endpoint *endpoint, dmp_time_ms now)
{
    dmp_status reliability = DMP_OK;
    dmp_status status;
    size_t expired = 0U;
    uint32_t peer_index;
    uint32_t start_peer;
    uint32_t peers;
    bool accepted;
    dmp_peer_handle peer;
    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    peers = endpoint->profile.peers;
    if (peers == 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    start_peer = endpoint->poll_peer_cursor % peers;
    for (peer_index = 0U; peer_index < peers; peer_index++) {
        if (endpoint->peers[peer_index].live != 0U) {
            endpoint->active_peer_slot = peer_index;
            expire_drain(endpoint, now);
        }
    }
    freshness_maintenance(endpoint, now);
    status = dmp_reliability_maintain(&endpoint->reliability, now);
    if (status != DMP_OK) {
        return status;
    }
    freshness_maintenance(endpoint, now);
    if (endpoint->profile.fragments >= 2U) {
        status = dmp_reassembly_poll(&endpoint->reassembly, now, &expired);
        if (status != DMP_OK) {
            return status;
        }
    }
    /* The same poll may have released the assembly retain. Retry retire. */
    for (peer_index = 0U; peer_index < peers; peer_index++) {
        if (endpoint->peers[peer_index].live != 0U) {
            endpoint->active_peer_slot = peer_index;
            expire_drain(endpoint, now);
        }
    }
    retire_revoked_peers(endpoint, now);

    if (endpoint->wire_busy == 0U) {
        for (uint32_t offset = 0U; offset < peers; offset++) {
            uint32_t peer_index = (start_peer + offset) % peers;
            if (endpoint->peers[peer_index].live == 0U) {
                continue;
            }
            endpoint->active_peer_slot = peer_index;
            status = select_active_route(endpoint);
            if (status != DMP_OK) {
                return status;
            }
            peer = PEER(endpoint, handle);
            accepted = false;
            status = dmp_reliability_poll_peer(&endpoint->reliability, now, peer,
                                               &accepted);
            if (accepted) {
                endpoint->poll_peer_cursor = (peer_index + 1U) % peers;
                return status;
            }
            if (status != DMP_OK && reliability == DMP_OK) {
                reliability = status;
            }
            if (endpoint->wire_busy != 0U) {
                break;
            }
            {
                uint64_t accepted_before = endpoint->accepted_tx_generation;
                status = poll_endpoint_peer_outputs(endpoint, now, peer_index);
                if (endpoint->accepted_tx_generation != accepted_before) {
                    endpoint->poll_peer_cursor = (peer_index + 1U) % peers;
                    return reliability;
                }
            }
            if (status != DMP_OK && status != DMP_BUSY) {
                return status;
            }
        }
    }
    return reliability;
}

static int read_wire_status(const dmp_frame_view *frame, uint32_t *status_out)
{
    size_t cursor = 0U;
    int found = 0;
    uint32_t wire = 0U;

    if (frame->extensions.size != 0U && frame->extensions.data == NULL) {
        return 0;
    }
    while (cursor < frame->extensions.size) {
        dmp_extension_view view;
        dmp_status status = dmp_extension_next(frame->extensions, &cursor, &view);
        size_t at = 0U;
        if (status == DMP_INCOMPLETE) {
            break;
        }
        if (status != DMP_OK) {
            return 0;
        }
        if ((view.tag >> 2) != 5U) {
            continue;
        }
        if (found != 0 || (view.tag & 3U) != 1U || !read_uleb32(view.value, &at, &wire) ||
            at != view.value.size) {
            return 0;
        }
        found = 1;
    }
    if (found == 0) {
        return 0;
    }
    *status_out = wire;
    return 1;
}

static dmp_status resolve_service(const dmp_endpoint *endpoint, const dmp_frame_view *frame,
                                  uint32_t *out)
{
    size_t cursor = 0U;
    int found = 0;
    uint32_t wire = 0U;
    if (frame->extensions.size != 0U && frame->extensions.data == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    while (cursor < frame->extensions.size) {
        dmp_extension_view view;
        dmp_status status = dmp_extension_next(frame->extensions, &cursor, &view);
        size_t at = 0U;
        if (status == DMP_INCOMPLETE) {
            break;
        }
        if (status != DMP_OK) {
            return status;
        }
        if ((view.tag >> 2) != 4U) {
            continue;
        }
        if (found != 0 || (view.tag & 3U) != 1U || !read_uleb32(view.value, &at, &wire) ||
            at != view.value.size) {
            return DMP_MALFORMED;
        }
        found = 1;
    }
    if (found) {
        if (wire == endpoint->profile.default_service) {
            return DMP_MALFORMED;
        }
        *out = wire;
    } else {
        *out = endpoint->profile.default_service;
    }
    if (*out == 0U) {
        if (!found) {
            return DMP_MALFORMED;
        }
        if (!secured(endpoint) || (frame->fields.options & DMP_OPT_SECURITY) == 0U) {
            return DMP_AUTHENTICATION_FAILURE;
        }
        return DMP_OK;
    }
    if (!service_allowed(&endpoint->profile, *out)) {
        return DMP_UNSUPPORTED;
    }
    return DMP_OK;
}

static dmp_status read_freshness_extension(const dmp_frame_view *frame, dmp_bytes *token,
                                           int *present)
{
    size_t cursor = 0U;
    *present = 0;
    token->data = NULL;
    token->size = 0U;
    while (cursor < frame->extensions.size) {
        dmp_extension_view ext;
        dmp_status status = dmp_extension_next(frame->extensions, &cursor, &ext);
        if (status != DMP_OK) {
            return status;
        }
        if ((ext.tag >> 2) != 6U) {
            continue;
        }
        if (*present != 0 || ext.tag != 25U || ext.value.size != 16U) {
            return DMP_MALFORMED;
        }
        *present = 1;
        *token = ext.value;
    }
    if (*present != 0 && (frame->fields.options & DMP_OPT_SECURITY) == 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    return DMP_OK;
}

static dmp_status immutable_metadata(dmp_endpoint *endpoint, const dmp_frame_view *frame,
                                    dmp_bytes *metadata)
{
    size_t cursor = 0U;
    size_t written = 0U;
    metadata->data = endpoint->ext_scratch;
    metadata->size = 0U;
    while (cursor < frame->extensions.size) {
        size_t start = cursor;
        dmp_extension_view ext;
        size_t span;
        dmp_status status = dmp_extension_next(frame->extensions, &cursor, &ext);
        if (status != DMP_OK) {
            return status;
        }
        /* The reliability engine separately resolves REPLY_TO, SERVICE and
         * the contextual source/destination identity. Retain FRESHNESS and
         * all other safe extensions byte-for-byte as logical metadata. */
        if ((ext.tag >> 2) == 1U || (ext.tag >> 2) == 4U || (ext.tag >> 2) == 11U) {
            continue;
        }
        span = cursor - start;
        if (span > sizeof endpoint->ext_scratch - written) {
            return DMP_LIMIT_EXHAUSTED;
        }
        memcpy(endpoint->ext_scratch + written, frame->extensions.data + start, span);
        written += span;
    }
    metadata->size = written;
    if (written == 0U) {
        metadata->data = NULL;
    }
    return DMP_OK;
}

static int token_equal(const uint8_t *a, const uint8_t *b)
{
    uint8_t diff = 0U;
    size_t i;
    for (i = 0U; i < 16U; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0U;
}

static dmp_status bind_freshness(dmp_endpoint *endpoint, const dmp_frame_view *frame,
                                 uint32_t service, dmp_identity_handle context,
                                 uint32_t attempt, dmp_time_ms now)
{
    dmp_bytes token;
    dmp_message_key source;
    const dmp_identity_slot *identity;
    int present = 0;
    size_t i;
    dmp_status status = read_freshness_extension(frame, &token, &present);
    if (status != DMP_OK) {
        return status;
    }
    if (!freshness_required(&endpoint->profile, service)) {
        return present != 0 ? DMP_MALFORMED : DMP_OK;
    }
    if (frame->fields.type != DMP_TYPE_REQ && frame->fields.type != DMP_TYPE_DATA &&
        frame->fields.type != DMP_TYPE_EVENT) {
        return present != 0 ? DMP_MALFORMED : DMP_OK;
    }
    if (present == 0) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    status = dmp_identity_source_key(frame, &endpoint->identity, context, now, &source);
    if (status != DMP_OK) {
        return status;
    }
    if (freshness_identity_retained(endpoint, source, service, frame->fields.type)) {
        return DMP_DUPLICATE;
    }
    if (context.slot >= endpoint->identity.capacity) {
        return DMP_STALE_HANDLE;
    }
    identity = &endpoint->identity.slots[context.slot];
    if (identity->generation != context.generation || identity->security != 1U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    for (i = 0U; i < freshness_slot_count(endpoint); i++) {
        dmp_endpoint_freshness_slot *slot = &endpoint->mem.freshness_slots[i];
        if (slot->state == DMP_ENDPOINT_FRESHNESS_BOUND && peer_equal(slot->peer, PEER(endpoint, handle)) &&
            slot->principal == source.origin.origin_id && slot->peer_epoch == source.origin.epoch &&
            slot->bound_seq == source.seq && slot->service_id == service &&
            !token_equal(slot->token, token.data)) {
            return DMP_AUTHENTICATION_FAILURE;
        }
        if (slot->state == DMP_ENDPOINT_FRESHNESS_EMPTY ||
            !token_equal(slot->token, token.data)) {
            continue;
        }
        if (!peer_equal(slot->peer, PEER(endpoint, handle)) ||
            slot->principal != source.origin.origin_id || slot->peer_epoch != source.origin.epoch ||
            slot->attempt != attempt) {
            return DMP_AUTHENTICATION_FAILURE;
        }
        if (dmp_deadline_reached(now, slot->expires_at)) {
            slot->state = DMP_ENDPOINT_FRESHNESS_CONSUMED;
            return DMP_DEADLINE_EXPIRED;
        }
        if (slot->state == DMP_ENDPOINT_FRESHNESS_ISSUED) {
            slot->state = DMP_ENDPOINT_FRESHNESS_BOUND;
            slot->bound_seq = source.seq;
            slot->service_id = service;
            return DMP_OK;
        }
        if (slot->state == DMP_ENDPOINT_FRESHNESS_BOUND && slot->bound_seq == source.seq &&
            slot->service_id == service) {
            return DMP_OK;
        }
        return DMP_AUTHENTICATION_FAILURE;
    }
    return DMP_AUTHENTICATION_FAILURE;
}

static dmp_status reject_authenticated_req(dmp_endpoint *endpoint, const dmp_frame_view *frame,
                                           uint32_t service, dmp_identity_handle context,
                                           uint32_t status_code, dmp_time_ms now)
{
    dmp_frame_view logical = *frame;
    dmp_reliability_input input;
    dmp_bytes metadata;
    dmp_status status;
    if (frame->fields.type != DMP_TYPE_REQ) {
        return DMP_OK;
    }
    logical.fields.options = (uint8_t)(logical.fields.options & (uint8_t)~DMP_OPT_FRAG);
    memset(&logical.fields.fragment, 0, sizeof logical.fields.fragment);
    memset(&input, 0, sizeof input);
    input.frame = &logical;
    input.service_id = service;
    input.plaintext = frame->payload;
    status = immutable_metadata(endpoint, &logical, &metadata);
    if (status != DMP_OK) {
        freshness_consume_frame(endpoint, frame, service, context, now);
        return status;
    }
    input.immutable_metadata = metadata;
    use_context(endpoint, context);
    status = dmp_reliability_reject_req(&endpoint->reliability, &input, status_code, now);
    if (status == DMP_DUPLICATE) {
        status = dmp_reliability_on_rx(&endpoint->reliability, &input, now);
    }
    use_context(endpoint, PEER(endpoint, context));
    freshness_consume_frame(endpoint, frame, service, context, now);
    return status == DMP_OK || status == DMP_DUPLICATE ? DMP_OK : status;
}

static dmp_status validate_request_before_accept(dmp_endpoint *endpoint,
                                                 const dmp_frame_view *frame,
                                                 uint32_t service,
                                                 dmp_identity_handle context,
                                                 dmp_bytes payload,
                                                 int run_application_validator,
                                                 dmp_time_ms now, int *handled,
                                                 int *retained_rejection)
{
    uint32_t protocol_status = 0U;
    uint32_t message_size;
    dmp_status status;

    if (handled == NULL || retained_rejection == NULL || !bytes_ok(payload)) {
        return DMP_INVALID_ARGUMENT;
    }
    *handled = 0;
    *retained_rejection = 0;
    if (frame->fields.type != DMP_TYPE_REQ || service == 0U) {
        return DMP_OK;
    }

    /* SEC-1 duplicates are resolved from retained identity state before any
     * application policy runs again. A new request remains unaccepted until
     * all policy checks below have passed. */
    if (secured(endpoint) && (frame->fields.options & DMP_OPT_FRAG) == 0U) {
        dmp_reliability_input input;
        dmp_bytes metadata;
        memset(&input, 0, sizeof input);
        input.frame = frame;
        input.service_id = service;
        input.plaintext = payload;
        status = immutable_metadata(endpoint, frame, &metadata);
        if (status != DMP_OK) {
            freshness_consume_frame(endpoint, frame, service, context, now);
            *handled = 1;
            return status;
        }
        input.immutable_metadata = metadata;
        use_context(endpoint, context);
        {
            bool was_rejected = false;
            status = dmp_reliability_req_is_retained(&endpoint->reliability, &input,
                                                     &was_rejected, now);
            if (status == DMP_DUPLICATE && was_rejected) {
                *retained_rejection = 1;
            }
        }
        use_context(endpoint, PEER(endpoint, context));
        if (status == DMP_DUPLICATE) {
            return DMP_OK;
        }
        if (status != DMP_OK) {
            freshness_consume_frame(endpoint, frame, service, context, now);
            *handled = 1;
            return status;
        }
    }
    if ((frame->fields.options & DMP_OPT_ACK_REQ) == 0U) {
        protocol_status = 7U;
    } else {
        message_size = (frame->fields.options & DMP_OPT_FRAG) != 0U
                           ? frame->fields.fragment.total_size
                           : (uint32_t)payload.size;
        if (message_size > endpoint->profile.message_bytes) {
            protocol_status = 3U;
        } else if (run_application_validator && secured(endpoint) &&
                   endpoint->validate_request != NULL) {
            protocol_status = endpoint->validate_request(endpoint->validate_request_user, frame,
                                                         service, payload);
            if (protocol_status > 7U) {
                freshness_consume_frame(endpoint, frame, service, context, now);
                return DMP_INVALID_ARGUMENT;
            }
        }
    }
    if (protocol_status == 0U) {
        return DMP_OK;
    }
    *handled = 1;
    /* Protocol errors must not become an unauthenticated response oracle. An
     * unsecured endpoint drops the invalid request without accepting it. */
    if (!secured(endpoint)) {
        return DMP_OK;
    }
    return reject_authenticated_req(endpoint, frame, service, context, protocol_status, now);
}

static dmp_status validate_result_before_accept(dmp_endpoint *endpoint,
                                                const dmp_frame_view *frame,
                                                uint32_t service, dmp_bytes payload,
                                                int *handled)
{
    if (endpoint == NULL || frame == NULL || handled == NULL || !bytes_ok(payload)) {
        return DMP_INVALID_ARGUMENT;
    }
    *handled = 0;
    if (frame->fields.type != DMP_TYPE_RSP || service == 0U ||
        endpoint->validate_result == NULL) {
        return DMP_OK;
    }
    if (!endpoint->validate_result(endpoint->validate_request_user, frame, service, payload)) {
        *handled = 1;
    }
    return DMP_OK;
}

static int freshness_duplicate_grant(dmp_endpoint *endpoint, dmp_message_key key,
                                     uint32_t attempt, uint32_t requested_lifetime)
{
    size_t i;
    for (i = 0U; i < freshness_slot_count(endpoint); i++) {
        const dmp_endpoint_freshness_slot *slot = &endpoint->mem.freshness_slots[i];
        if (slot->state != DMP_ENDPOINT_FRESHNESS_EMPTY &&
            peer_equal(slot->peer, PEER(endpoint, handle)) && slot->principal == key.origin.origin_id &&
            slot->peer_epoch == key.origin.epoch && slot->attempt == attempt &&
            slot->grant_request_seq == key.seq) {
            return slot->grant_request_lifetime_ms == requested_lifetime ? 1 : -1;
        }
    }
    return 0;
}

static uint32_t freshness_live_count(const dmp_endpoint *endpoint, dmp_peer_handle peer,
                                    uint32_t principal,
                                    uint32_t attempt, int match_attempt, int grants_only)
{
    size_t i;
    uint32_t count = 0U;
    for (i = 0U; i < freshness_slot_count(endpoint); i++) {
        const dmp_endpoint_freshness_slot *slot = &endpoint->mem.freshness_slots[i];
        if (slot->state == DMP_ENDPOINT_FRESHNESS_EMPTY || !peer_equal(slot->peer, peer) ||
            slot->principal != principal ||
            (match_attempt && slot->attempt != attempt) ||
            (grants_only && slot->grant_request_live == 0U)) {
            continue;
        }
        count++;
    }
    return count;
}

static dmp_status prepare_freshness_grant(dmp_endpoint *endpoint, const dmp_frame_view *frame,
                                          uint32_t attempt, dmp_time_ms now,
                                          uint32_t *protocol_status)
{
    dmp_message_key source;
    dmp_identity_slot *context;
    dmp_endpoint_freshness_slot *record = NULL;
    dmp_bytes token;
    uint32_t requested;
    uint32_t granted;
    dmp_time_ms expires;
    dmp_time_ms record_until;
    size_t i;
    dmp_status status;

    *protocol_status = 0U;
    {
        int has_token = 0;
        status = read_freshness_extension(frame, &token, &has_token);
        if ((frame->fields.options & (DMP_OPT_FRAG | DMP_OPT_PAYLOAD_DESC)) != 0U ||
            status != DMP_OK || has_token != 0) {
            *protocol_status = 7U;
            return DMP_MALFORMED;
        }
    }
    if (!freshness_enabled(endpoint)) {
        *protocol_status = 1U;
        return DMP_UNSUPPORTED;
    }
    if (frame->payload.size != 5U || frame->payload.data == NULL) {
        *protocol_status = 7U;
        return DMP_MALFORMED;
    }
    if (frame->payload.data[0] != 0x10U) {
        *protocol_status = 1U;
        return DMP_UNSUPPORTED;
    }
    requested = (uint32_t)frame->payload.data[1] |
                ((uint32_t)frame->payload.data[2] << 8U) |
                ((uint32_t)frame->payload.data[3] << 16U) |
                ((uint32_t)frame->payload.data[4] << 24U);
    if (requested == 0U || requested > 60000U) {
        *protocol_status = 7U;
        return DMP_MALFORMED;
    }
    if (PEER(endpoint, context).slot >= endpoint->identity.capacity) {
        *protocol_status = 6U;
        return DMP_STALE_HANDLE;
    }
    context = &endpoint->identity.slots[PEER(endpoint, context).slot];
    if (context->generation != PEER(endpoint, context).generation || context->state != DMP_IDENTITY_SLOT_ACTIVE ||
        attempt != PEER(endpoint, association_attempt) || require_attempt(endpoint, attempt) != DMP_OK) {
        *protocol_status = 6U;
        return DMP_AUTHENTICATION_FAILURE;
    }
    status = dmp_identity_source_key(frame, &endpoint->identity, PEER(endpoint, context), now, &source);
    if (status != DMP_OK) {
        *protocol_status = 6U;
        return status;
    }
    {
        int authorized_service = 0;
        uint32_t peer_id = context->peer.origin_id;
        if (!action_allowed(endpoint, peer_id, 0U, DMP_ENDPOINT_PERMIT_CONTROL)) {
            *protocol_status = 6U;
            return DMP_AUTHENTICATION_FAILURE;
        }
        for (i = 0U; i < DMP_PROFILE_SERVICE_COUNT; i++) {
            uint32_t service = endpoint->profile.service_id[i];
            if (freshness_required(&endpoint->profile, service) &&
                action_allowed(endpoint, peer_id, service, DMP_ENDPOINT_PERMIT_REQ)) {
                authorized_service = 1;
            }
        }
        if (!authorized_service) {
            *protocol_status = 6U;
            return DMP_AUTHENTICATION_FAILURE;
        }
    }
    {
        int duplicate = freshness_duplicate_grant(endpoint, source, attempt, requested);
        if (duplicate != 0) {
            if (duplicate < 0) {
                *protocol_status = 7U;
                return DMP_MALFORMED;
            }
            if (!freshness_identity_retained(endpoint, source, 0U, DMP_TYPE_REQ)) {
                /* The token/request record outlived the reliable duplicate
                 * record. Never dispatch this grant request again or rebuild
                 * a result that has already been released. */
                *protocol_status = 6U;
                return DMP_AUTHENTICATION_FAILURE;
            }
            return DMP_DUPLICATE;
        }
    }
    if (freshness_identity_retained(endpoint, source, 0U, DMP_TYPE_REQ)) {
        return DMP_DUPLICATE;
    }
    if (freshness_live_count(endpoint, PEER(endpoint, handle), context->peer.origin_id, attempt, 1, 0) >=
            endpoint->profile.freshness_tokens_per_association ||
        freshness_live_count(endpoint, PEER(endpoint, handle), context->peer.origin_id, attempt, 0, 0) >=
            endpoint->profile.freshness_tokens_per_principal ||
        freshness_live_count(endpoint, PEER(endpoint, handle), context->peer.origin_id, attempt, 0, 1) >=
            endpoint->profile.freshness_grant_requests_per_pair) {
        *protocol_status = 4U;
        return DMP_QUOTA_EXHAUSTED;
    }
    for (i = 0U; i < freshness_slot_count(endpoint); i++) {
        if (endpoint->mem.freshness_slots[i].state == DMP_ENDPOINT_FRESHNESS_EMPTY) {
            record = &endpoint->mem.freshness_slots[i];
            break;
        }
    }
    if (record == NULL) {
        *protocol_status = 4U;
        return DMP_QUOTA_EXHAUSTED;
    }
    granted = requested < endpoint->profile.freshness_lease_ms
                  ? requested
                  : endpoint->profile.freshness_lease_ms;
    status = dmp_deadline_after(now, granted, &expires);
    if (status != DMP_OK) {
        *protocol_status = 4U;
        return status;
    }
    status = dmp_deadline_after(now, endpoint->profile.freshness_token_record_ms, &record_until);
    if (status != DMP_OK) {
        *protocol_status = 4U;
        return status;
    }
    memset(record, 0, sizeof *record);
    record->peer = PEER(endpoint, handle);
    record->state = DMP_ENDPOINT_FRESHNESS_RESERVED;
    record->principal = context->peer.origin_id;
    record->peer_epoch = context->peer.epoch;
    record->attempt = attempt;
    record->grant_request_seq = source.seq;
    record->grant_request_lifetime_ms = requested;
    record->granted_lifetime_ms = granted;
    record->expires_at = expires;
    record->record_until = record_until;
    if (PEER(endpoint, association) == NULL ||
        dmp_hs_entropy(PEER(endpoint, association), record->token, sizeof record->token) != DMP_HS_OK) {
        memset(record, 0, sizeof *record);
        *protocol_status = 4U;
        return DMP_AUTHENTICATION_FAILURE;
    }
    for (i = 0U; i < freshness_slot_count(endpoint); i++) {
        const dmp_endpoint_freshness_slot *other = &endpoint->mem.freshness_slots[i];
        if (other != record && other->state != DMP_ENDPOINT_FRESHNESS_EMPTY &&
            token_equal(other->token, record->token)) {
            memset(record, 0, sizeof *record);
            *protocol_status = 4U;
            return DMP_AUTHENTICATION_FAILURE;
        }
    }
    PEER(endpoint, prepared_grant_key) = source;
    PEER(endpoint, prepared_grant_live) = 1U;
    PEER(endpoint, pending_grant_slot) = (uint32_t)(record - endpoint->mem.freshness_slots);
    return DMP_OK;
}

static dmp_status finish_freshness_grant(dmp_endpoint *endpoint, dmp_time_ms now)
{
    dmp_endpoint_freshness_slot *record;
    dmp_reliability_history_slot *history;
    uint8_t response[21];
    dmp_bytes payload;
    dmp_status status;
    if (PEER(endpoint, pending_grant_live) == 0U) {
        return DMP_OK;
    }
    if (PEER(endpoint, pending_grant_slot) >= freshness_slot_count(endpoint) ||
        PEER(endpoint, pending_grant_request).slot >= endpoint->mem.history_capacity) {
        PEER(endpoint, pending_grant_live) = 0U;
        PEER(endpoint, prepared_grant_live) = 0U;
        return DMP_STALE_HANDLE;
    }
    record = &endpoint->mem.freshness_slots[PEER(endpoint, pending_grant_slot)];
    history = &endpoint->mem.history[PEER(endpoint, pending_grant_request).slot];
    if (record->state != DMP_ENDPOINT_FRESHNESS_RESERVED || history->live == 0U ||
        history->generation != PEER(endpoint, pending_grant_request).generation) {
        memset(record, 0, sizeof *record);
        PEER(endpoint, pending_grant_live) = 0U;
        PEER(endpoint, prepared_grant_live) = 0U;
        return DMP_STALE_HANDLE;
    }
    response[0] = 0x11U;
    memcpy(response + 1U, record->token, sizeof record->token);
    response[17] = (uint8_t)record->granted_lifetime_ms;
    response[18] = (uint8_t)(record->granted_lifetime_ms >> 8U);
    response[19] = (uint8_t)(record->granted_lifetime_ms >> 16U);
    response[20] = (uint8_t)(record->granted_lifetime_ms >> 24U);
    payload.data = response;
    payload.size = sizeof response;
    status = endpoint_complete_for_lifetime(endpoint, PEER(endpoint, pending_grant_request), false, 0U,
                                            payload, endpoint->profile.freshness_grant_result_ms,
                                            now);
    if (status == DMP_OK) {
        record->state = DMP_ENDPOINT_FRESHNESS_ISSUED;
        record->result_slot = history->result_slot;
        record->result_generation = history->result_generation;
        record->grant_request_live = 1U;
    } else {
        record->state = DMP_ENDPOINT_FRESHNESS_CONSUMED;
    }
    PEER(endpoint, pending_grant_live) = 0U;
    PEER(endpoint, prepared_grant_live) = 0U;
    return status;
}

static void discard_prepared_freshness_grant(dmp_endpoint *endpoint)
{
    if (PEER(endpoint, prepared_grant_live) != 0U && PEER(endpoint, pending_grant_live) == 0U &&
        PEER(endpoint, pending_grant_slot) < freshness_slot_count(endpoint)) {
        dmp_endpoint_freshness_slot *record =
            &endpoint->mem.freshness_slots[PEER(endpoint, pending_grant_slot)];
        if (record->state == DMP_ENDPOINT_FRESHNESS_RESERVED) {
            memset(record, 0, sizeof *record);
        }
    }
    PEER(endpoint, prepared_grant_live) = 0U;
}

static int ack_req_logical(const dmp_frame_view *frame)
{
    uint8_t type;

    if (frame == NULL || (frame->fields.options & DMP_OPT_ACK_REQ) == 0U) {
        return 0;
    }
    type = frame->fields.type;
    return type == DMP_TYPE_REQ || type == DMP_TYPE_RSP || type == DMP_TYPE_ERR ||
           type == DMP_TYPE_DATA || type == DMP_TYPE_EVENT;
}

static int freshness_command(uint8_t type)
{
    return type == DMP_TYPE_REQ || type == DMP_TYPE_DATA || type == DMP_TYPE_EVENT;
}

/* R4.4 / R4.5. Reassembly has the full plaintext. Reliability still owns the
 * single acceptance, receipt and result. The FRAG option is cleared only on
 * this local view: the saved assembly and the wire bytes stay fragmented. */
static dmp_status present_assembled(dmp_endpoint *endpoint, const dmp_frame_view *frame,
                                    uint32_t service, dmp_identity_handle context, dmp_bytes full,
                                    dmp_time_ms now, int *deliver_assembled)
{
    dmp_frame_view logical;
    dmp_reliability_input input;
    dmp_bytes metadata;
    dmp_status status;
    int handled = 0;
    int retained_rejection = 0;

    if (deliver_assembled == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    *deliver_assembled = 0;

    logical = *frame;
    logical.fields.options = (uint8_t)(logical.fields.options & (uint8_t)~DMP_OPT_FRAG);
    memset(&logical.fields.fragment, 0, sizeof logical.fields.fragment);
    logical.payload = full;
    status = validate_request_before_accept(endpoint, &logical, service, context, full, 1, now,
                                            &handled, &retained_rejection);
    if (status != DMP_OK || handled != 0) {
        return status;
    }
    status = validate_result_before_accept(endpoint, &logical, service, full, &handled);
    if (status != DMP_OK || handled != 0) {
        return status;
    }
    memset(&input, 0, sizeof input);
    input.frame = &logical;
    input.service_id = service;
    input.plaintext = full;
    status = immutable_metadata(endpoint, &logical, &metadata);
    if (status != DMP_OK) {
        freshness_consume_frame(endpoint, frame, service, context, now);
        return status;
    }
    input.immutable_metadata = metadata;
    use_context(endpoint, context);
    status = dmp_reliability_on_rx(&endpoint->reliability, &input, now);
    use_context(endpoint, PEER(endpoint, context));
    if (status != DMP_BUSY && status != DMP_INCOMPLETE) {
        freshness_consume_frame(endpoint, frame, service, context, now);
    }
    if ((status == DMP_OK || status == DMP_DUPLICATE) && retained_rejection == 0) {
        *deliver_assembled = 1;
    }
    return status;
}

static const dmp_reassembly_slot *complete_assembly(const dmp_endpoint *endpoint, dmp_message_key key,
                                                    dmp_identity_handle context)
{
    size_t index;

    for (index = 0U; index < endpoint->reassembly.storage.assembly_capacity; index++) {
        const dmp_reassembly_slot *slot = &endpoint->reassembly.storage.assemblies[index];
        if (slot->live == 0U || slot->complete == 0U || slot->context.slot != context.slot ||
            slot->context.generation != context.generation) {
            continue;
        }
        if (slot->source.seq == key.seq && slot->source.origin.namespace_id == key.origin.namespace_id &&
            slot->source.origin.origin_id == key.origin.origin_id &&
            slot->source.origin.epoch == key.origin.epoch) {
            return slot;
        }
    }
    return NULL;
}

static dmp_bytes assembly_bytes(const dmp_endpoint *endpoint, const dmp_reassembly_slot *slot)
{
    size_t index = (size_t)(slot - endpoint->reassembly.storage.assemblies);
    dmp_bytes bytes;

    bytes.data = endpoint->mem.assembly_payload + index * (size_t)endpoint->profile.message_bytes;
    bytes.size = slot->total_size;
    return bytes;
}

static dmp_status take_fragment(dmp_endpoint *endpoint, const dmp_frame_view *frame, uint32_t service,
                                dmp_identity_handle context, dmp_time_ms now)
{
    dmp_reassembly_input input;
    dmp_reassembly_handle handle;
    dmp_status status;
    memset(&input, 0, sizeof input);
    memset(&handle, 0, sizeof handle);
    input.frame = frame;
    input.context = context;
    input.service_id = service;
    input.plaintext = frame->payload;
    /* Parsed EXT TLVs in wire order. The SECURITY option, PN and tag are not
     * in this span. The engine copies the bytes and rejects a later mismatch. */
    input.immutable_metadata = frame->extensions;
    status = dmp_reassembly_on_fragment(&endpoint->reassembly, &input, now, &handle);
    if (status == DMP_DUPLICATE && ack_req_logical(frame)) {
        dmp_message_key source;
        const dmp_reassembly_slot *slot;
        dmp_status accepted;
        int deliver_assembled;

        if (dmp_identity_source_key(frame, &endpoint->identity, context, now, &source) != DMP_OK) {
            return DMP_DUPLICATE;
        }
        slot = complete_assembly(endpoint, source, context);
        if (slot == NULL) {
            return DMP_DUPLICATE;
        }
        /* A fresh-PN probe of an accepted transfer repeats the receipt. It
         * does not dispatch the payload again. */
        accepted = present_assembled(endpoint, frame, service, context, assembly_bytes(endpoint, slot),
                                     now, &deliver_assembled);
        if (accepted != DMP_OK && accepted != DMP_DUPLICATE && accepted != DMP_BUSY) {
            return accepted;
        }
        if (accepted == DMP_OK && deliver_assembled == 0) {
            dmp_reassembly_handle rejected;
            rejected.slot = (uint32_t)(slot - endpoint->reassembly.storage.assemblies);
            rejected.generation = slot->generation;
            accepted = dmp_reassembly_reject(&endpoint->reassembly, rejected);
            if (accepted != DMP_OK) {
                return accepted;
            }
        }
        return DMP_DUPLICATE;
    }
    if (status != DMP_OK) {
        return status;
    }
    {
        dmp_reassembly_message message;
        dmp_reliability_handle none;
        int deliver_assembled = 1;
        memset(&none, 0, sizeof none);
        status = dmp_reassembly_get(&endpoint->reassembly, handle, &message);
        if (status != DMP_OK) {
            return status;
        }
        if (ack_req_logical(frame)) {
            status = present_assembled(endpoint, frame, service, context, message.payload, now,
                                       &deliver_assembled);
            if (status != DMP_OK && status != DMP_DUPLICATE) {
                return status;
            }
            if (status == DMP_OK && deliver_assembled == 0) {
                status = dmp_reassembly_reject(&endpoint->reassembly, handle);
                if (status != DMP_OK) {
                    return status;
                }
            }
        }
        if (deliver_assembled != 0) {
            emit_with_context(endpoint, DMP_ENDPOINT_ASSEMBLED, none, message.service_id, 0U,
                              message.payload, message.source, context);
        }
        /* Accepted complete slots retain their payload for duplicate receipt
         * handling. Terminally rejected messages use a REJECTED tombstone and
         * return the payload/metadata slot to the bounded assembly pool. */
        return DMP_OK;
    }
}

static int matching_attempt(const dmp_endpoint *endpoint, dmp_bytes core, uint32_t *attempt,
                            uint64_t *peer_epoch)
{
    dmp_frame_view view;
    dmp_parse_result parsed;
    dmp_core_limits limits;
    uint32_t cid;

    memset(&view, 0, sizeof view);
    limits = receive_limits_of(endpoint);
    parsed = dmp_core_parse(core, &limits, &view);
    if (parsed.status != DMP_OK || (view.fields.options & DMP_OPT_SECURITY) == 0U ||
        PEER(endpoint, association) == NULL) {
        return 0;
    }
    cid = view.fields.security.receive_cid;
    if (cid == 0U) {
        return 0;
    }
    if (PEER(endpoint, association_bound) != 0U &&
        dmp_hs_rx_cid(PEER(endpoint, association), PEER(endpoint, association_attempt)) == cid) {
        if (PEER(endpoint, context).slot >= endpoint->identity.capacity) {
            return 0;
        }
        *attempt = PEER(endpoint, association_attempt);
        *peer_epoch = endpoint->identity.slots[PEER(endpoint, context).slot].peer.epoch;
        return 1;
    }
    if (PEER(endpoint, drain_live) != 0U &&
        dmp_hs_rx_cid(PEER(endpoint, association), PEER(endpoint, drain_attempt)) == cid) {
        *attempt = PEER(endpoint, drain_attempt);
        *peer_epoch = PEER(endpoint, drain_peer_epoch);
        return 1;
    }
    return 0;
}

static dmp_status open_protected(dmp_endpoint *endpoint, dmp_bytes core, dmp_frame_view *view,
                                  uint8_t *plain, size_t plain_cap, size_t *plain_len,
                                  uint32_t *attempt_out)
{
    dmp_hs_protected incoming;
    dmp_identity_slot *slot;
    uint32_t attempt = 0U;
    uint64_t peer_epoch = 0U;
    dmp_hs_status opened;

    if (PEER(endpoint, revoked) != 0U || PEER(endpoint, context).slot >= endpoint->identity.capacity ||
        !matching_attempt(endpoint, core, &attempt, &peer_epoch)) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    slot = &endpoint->identity.slots[PEER(endpoint, context).slot];
    memset(&incoming, 0, sizeof incoming);
    incoming.frame = core.data;
    incoming.frame_len = core.size;
    incoming.origin_id = slot->peer.origin_id;
    incoming.destination_id = slot->local.origin_id;
    incoming.namespace_id = slot->local.namespace_id;
    incoming.context_epoch = peer_epoch;
    opened = dmp_hs_open_logical(PEER(endpoint, association), attempt, &incoming, plain, plain_cap,
                                 plain_len, view);
    if (opened != DMP_HS_OK) {
        return from_hs(opened);
    }
    *attempt_out = attempt;
    return DMP_OK;
}

static dmp_status take_frame(dmp_endpoint *endpoint, dmp_bytes core, dmp_time_ms now)
{
    dmp_frame_view view;
    dmp_parse_result parsed;
    dmp_core_limits limits;
    dmp_role_policy policy;
    dmp_reliability_input input;
    dmp_bytes empty;
    dmp_bytes metadata;
    uint8_t plain[DMP_HS_APP_PLAIN_MAX];
    size_t plain_len = 0U;
    uint32_t service = 0U;
    uint32_t opened_attempt = 0U;
    uint32_t control_reject_status = 0U;
    dmp_identity_handle rx_context;
    dmp_status status;
    memset(&view, 0, sizeof view);
    rx_context = PEER(endpoint, context);
    if (secured(endpoint)) {
        /* Epochs are the attempt values installed above. No hash and no
         * allocation on this path. */
        status = open_protected(endpoint, core, &view, plain, sizeof plain, &plain_len,
                                &opened_attempt);
        if (status != DMP_OK) {
            return status;
        }
        if (plain_len != view.payload.size) {
            return DMP_AUTHENTICATION_FAILURE;
        }
        if (PEER(endpoint, drain_live) != 0U && opened_attempt == PEER(endpoint, drain_attempt)) {
            rx_context = PEER(endpoint, drain_context);
        }
    } else {
        limits = receive_limits_of(endpoint);
        parsed = dmp_core_parse(core, &limits, &view);
        if (parsed.status != DMP_OK) {
            return parsed.status;
        }
    }
    memset(&policy, 0, sizeof policy);
    policy.role = DMP_ROLE_ENDPOINT;
    policy.default_service = endpoint->profile.default_service;
    policy.selective32 = endpoint->profile.recovery[0] == DMP_PROFILE_RECOVERY_SELECTIVE32 ||
                         endpoint->profile.recovery[1] == DMP_PROFILE_RECOVERY_SELECTIVE32;
    status = dmp_core_check_role(&view, &policy);
    if (status != DMP_OK) {
        return status;
    }
    status = resolve_service(endpoint, &view, &service);
    if (status != DMP_OK) {
        return status;
    }
    freshness_maintenance(endpoint, now);
    if (service == 0U) {
        dmp_bytes token;
        int token_present = 0;
        if ((view.fields.type != DMP_TYPE_REQ && view.fields.type != DMP_TYPE_RSP &&
             view.fields.type != DMP_TYPE_ERR && view.fields.type != DMP_TYPE_ACK) ||
            (view.fields.options & (DMP_OPT_FRAG | DMP_OPT_PAYLOAD_DESC)) != 0U ||
            read_freshness_extension(&view, &token, &token_present) != DMP_OK ||
            token_present != 0) {
            if (view.fields.type == DMP_TYPE_REQ &&
                (view.fields.options & DMP_OPT_ACK_REQ) != 0U) {
                return reject_authenticated_req(endpoint, &view, service, rx_context, 7U, now);
            }
            return DMP_MALFORMED;
        }
        if (view.fields.type == DMP_TYPE_REQ) {
            const dmp_identity_slot *peer_slot;
            int authorized_service = 0;
            size_t service_index;
            if (rx_context.slot >= endpoint->identity.capacity ||
                (peer_slot = &endpoint->identity.slots[rx_context.slot])->generation !=
                    rx_context.generation ||
                opened_attempt != PEER(endpoint, association_attempt) ||
                require_attempt(endpoint, opened_attempt) != DMP_OK ||
                !action_allowed(endpoint, peer_slot->peer.origin_id, 0U,
                                DMP_ENDPOINT_PERMIT_CONTROL)) {
                return reject_authenticated_req(endpoint, &view, service, rx_context, 6U, now);
            }
            for (service_index = 0U; service_index < DMP_PROFILE_SERVICE_COUNT; service_index++) {
                uint32_t app_service = endpoint->profile.service_id[service_index];
                if (freshness_required(&endpoint->profile, app_service) &&
                    action_allowed(endpoint, peer_slot->peer.origin_id, app_service,
                                   DMP_ENDPOINT_PERMIT_REQ)) {
                    authorized_service = 1;
                }
            }
            if (authorized_service == 0) {
                return reject_authenticated_req(endpoint, &view, service, rx_context, 6U, now);
            }
            status = prepare_freshness_grant(endpoint, &view, opened_attempt, now,
                                             &control_reject_status);
            if (status != DMP_OK && status != DMP_DUPLICATE) {
                return reject_authenticated_req(endpoint, &view, service, rx_context,
                                               control_reject_status == 0U ? 6U
                                                                          : control_reject_status,
                                               now);
            }
        }
    } else {
        status = bind_freshness(endpoint, &view, service, rx_context, opened_attempt, now);
        if (status != DMP_OK && status != DMP_DUPLICATE) {
            dmp_message_key source;
            if (dmp_identity_source_key(&view, &endpoint->identity, rx_context, now, &source) == DMP_OK) {
                freshness_consume_key(endpoint, source, service);
            }
            if (status == DMP_DEADLINE_EXPIRED || status == DMP_AUTHENTICATION_FAILURE ||
                status == DMP_STALE_HANDLE) {
                if (view.fields.type == DMP_TYPE_REQ &&
                    (view.fields.options & DMP_OPT_ACK_REQ) != 0U) {
                    return reject_authenticated_req(endpoint, &view, service, rx_context, 6U, now);
                }
                return DMP_OK;
            }
            return status;
        }
    }
    if (secured(endpoint)) {
        const dmp_identity_slot *peer_slot;
        uint32_t need = 0U;
        if (rx_context.slot >= endpoint->identity.capacity) {
            return DMP_STALE_HANDLE;
        }
        peer_slot = &endpoint->identity.slots[rx_context.slot];
        if (view.fields.type == DMP_TYPE_REQ || view.fields.type == DMP_TYPE_DATA ||
            view.fields.type == DMP_TYPE_EVENT) {
            need = DMP_ENDPOINT_PERMIT_REQ;
        } else if (view.fields.type == DMP_TYPE_TELEM) {
            need = DMP_ENDPOINT_PERMIT_TELEM;
        } else if (view.fields.type == DMP_TYPE_RSP) {
            need = DMP_ENDPOINT_PERMIT_RESULT;
        } else if (view.fields.type == DMP_TYPE_ERR) {
            uint32_t wire_status = 0U;
            if (!read_wire_status(&view, &wire_status)) {
                return DMP_MALFORMED;
            }
            if (wire_status >= 64U) {
                need = DMP_ENDPOINT_PERMIT_RESULT;
            } else if (wire_status < 1U || wire_status > 7U) {
                return DMP_MALFORMED;
            }
        }
        if (service == 0U) {
            need = DMP_ENDPOINT_PERMIT_CONTROL;
        }
        if (need != 0U &&
            !action_allowed(endpoint, peer_slot->peer.origin_id, service, need)) {
            if (freshness_required(&endpoint->profile, service) &&
                freshness_command(view.fields.type)) {
                dmp_message_key source;
                if (dmp_identity_source_key(&view, &endpoint->identity, rx_context, now, &source) ==
                    DMP_OK) {
                    freshness_consume_key(endpoint, source, service);
                }
            }
            /* PN is already marked. Do not call the application handler.
             * A fragmented REQ is not admitted to reassembly. Reliability
             * rejects FRAG, so the best-effort STATUS=6 uses the same
             * unfragmented rejection path. */
            if (view.fields.type == DMP_TYPE_REQ &&
                (view.fields.options & DMP_OPT_ACK_REQ) != 0U) {
                return reject_authenticated_req(endpoint, &view, service, rx_context, 6U, now);
            }
            return DMP_OK;
        }
    }
    if (view.fields.type == DMP_TYPE_REQ && service != 0U) {
        int handled = 0;
        int retained_rejection = 0;
        int run_validator = (view.fields.options & DMP_OPT_FRAG) == 0U;
        status = validate_request_before_accept(endpoint, &view, service, rx_context, view.payload,
                                                run_validator, now, &handled,
                                                &retained_rejection);
        if (status != DMP_OK || handled != 0) {
            return status;
        }
    } else if (service != 0U) {
        uint32_t message_size = (view.fields.options & DMP_OPT_FRAG) != 0U
                                    ? view.fields.fragment.total_size
                                    : (uint32_t)view.payload.size;
        if (message_size > endpoint->profile.message_bytes) {
            return DMP_LIMIT_EXHAUSTED;
        }
    }
    if (view.fields.type == DMP_TYPE_RSP && service != 0U &&
        (view.fields.options & DMP_OPT_FRAG) == 0U) {
        int handled = 0;
        status = validate_result_before_accept(endpoint, &view, service, view.payload, &handled);
        if (status != DMP_OK || handled != 0) {
            return status;
        }
    }
    if (view.fields.type == DMP_TYPE_FRAG_STATUS) {
        dmp_message_key source;
        empty.data = NULL;
        empty.size = 0U;
        /* AEAD authenticates the bytes, but recovery is scoped to the
         * endpoint's complete peer identity. In particular, routed feedback
         * must carry the matching source, destination and CONTEXT. Validate
         * before reliability can advance its feedback sequence or queue a
         * repair burst. */
        status = dmp_identity_source_key(&view, &endpoint->identity, rx_context, now, &source);
        if (status != DMP_OK) {
            return status;
        }
        memset(&input, 0, sizeof input);
        input.frame = &view;
        input.service_id = service;
        input.plaintext = view.payload;
        input.immutable_metadata = empty;
        use_context(endpoint, rx_context);
        status = dmp_reliability_on_rx(&endpoint->reliability, &input, now);
        use_context(endpoint, PEER(endpoint, context));
        return status;
    }
    if ((view.fields.options & DMP_OPT_FRAG) != 0U) {
        status = take_fragment(endpoint, &view, service, rx_context, now);
        if (status != DMP_OK && status != DMP_DUPLICATE && status != DMP_INCOMPLETE &&
            freshness_required(&endpoint->profile, service)) {
            dmp_message_key source;
            if (dmp_identity_source_key(&view, &endpoint->identity, rx_context, now, &source) ==
                DMP_OK) {
                freshness_consume_key(endpoint, source, service);
            }
            if (view.fields.type == DMP_TYPE_REQ &&
                (view.fields.options & DMP_OPT_ACK_REQ) != 0U) {
                return reject_authenticated_req(endpoint, &view, service, rx_context, 6U, now);
            }
        }
        return status;
    }
    if (view.fields.type == DMP_TYPE_TELEM) {
        dmp_reliability_handle none;
        dmp_message_key source;
        memset(&none, 0, sizeof none);
        status = dmp_identity_source_key(&view, &endpoint->identity, rx_context, now, &source);
        if (status != DMP_OK) {
            return status;
        }
        emit_with_context(endpoint, DMP_ENDPOINT_TELEMETRY, none, service, 0U, view.payload,
                          source, rx_context);
        return DMP_OK;
    }
    if (view.fields.type != DMP_TYPE_REQ && view.fields.type != DMP_TYPE_RSP &&
        view.fields.type != DMP_TYPE_ERR && view.fields.type != DMP_TYPE_ACK &&
        view.fields.type != DMP_TYPE_DATA && view.fields.type != DMP_TYPE_EVENT) {
        return DMP_UNSUPPORTED;
    }
    status = immutable_metadata(endpoint, &view, &metadata);
    if (status != DMP_OK) {
        if (freshness_required(&endpoint->profile, service)) {
            dmp_message_key source;
            if (dmp_identity_source_key(&view, &endpoint->identity, rx_context, now, &source) ==
                DMP_OK) {
                freshness_consume_key(endpoint, source, service);
            }
        }
        return status;
    }
    memset(&input, 0, sizeof input);
    input.frame = &view;
    input.service_id = service;
    input.plaintext = view.payload;
    input.immutable_metadata = metadata;
    use_context(endpoint, rx_context);
    status = dmp_reliability_on_rx(&endpoint->reliability, &input, now);
    use_context(endpoint, PEER(endpoint, context));
    if (status != DMP_BUSY && status != DMP_INCOMPLETE &&
        freshness_required(&endpoint->profile, service) && freshness_command(view.fields.type)) {
        dmp_message_key source;
        if (dmp_identity_source_key(&view, &endpoint->identity, rx_context, now, &source) == DMP_OK) {
            freshness_consume_key(endpoint, source, service);
        }
    }
    if (service == 0U && PEER(endpoint, prepared_grant_live) != 0U) {
        if (PEER(endpoint, pending_grant_live) != 0U) {
            dmp_status grant_status = finish_freshness_grant(endpoint, now);
            if (grant_status != DMP_OK) {
                return grant_status;
            }
        } else {
            discard_prepared_freshness_grant(endpoint);
        }
    }
    return status;
}

dmp_status dmp_endpoint_rx_from(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                dmp_bytes input, dmp_time_ms now)
{
    dmp_status status = DMP_OK;
    if (!ready(endpoint) || !bytes_ok(input)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (endpoint->mem.framing_mode != DMP_ENDPOINT_FRAMING_STREAM_R) {
        return DMP_UNSUPPORTED;
    }
    status = select_peer(endpoint, peer);
    if (status != DMP_OK) {
        return status;
    }
    status = select_active_route(endpoint);
    if (status != DMP_OK) {
        return status;
    }
    status = DMP_OK;
    while (input.size != 0U) {
        dmp_stream_result fed = dmp_stream_feed(&PEER(endpoint, decoder), input, now);
        if (fed.status != DMP_OK) {
            return fed.status;
        }
        if (fed.consumed == 0U || fed.consumed > input.size) {
            return fed.consumed == 0U ? status : DMP_MALFORMED;
        }
        input.data += fed.consumed;
        input.size -= fed.consumed;
        if (fed.event == DMP_STREAM_NONE) {
            return status;
        }
        if (fed.event != DMP_STREAM_FRAME) {
            return fed.status == DMP_OK ? DMP_MALFORMED : fed.status;
        }
        status = take_frame(endpoint, fed.frame, now);
        if (status != DMP_OK && status != DMP_INCOMPLETE && status != DMP_DUPLICATE) {
            return status;
        }
    }
    (void)select_active_route(endpoint);
    return status;
}

dmp_status dmp_endpoint_rx(dmp_endpoint *endpoint, dmp_bytes input, dmp_time_ms now)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) {
        return DMP_INVALID_ARGUMENT;
    }
    return dmp_endpoint_rx_from(endpoint, peer, input, now);
}

dmp_status dmp_endpoint_rx_packet_from(dmp_endpoint *endpoint, dmp_peer_handle peer,
                                       dmp_bytes frame, dmp_time_ms now)
{
    dmp_status status;
    if (!ready(endpoint) || !bytes_ok(frame) || frame.size == 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    if (endpoint->mem.framing_mode != DMP_ENDPOINT_FRAMING_PACKET) {
        return DMP_UNSUPPORTED;
    }
    status = select_peer(endpoint, peer);
    if (status != DMP_OK) {
        return status;
    }
    status = select_active_route(endpoint);
    if (status != DMP_OK) {
        return status;
    }
    if (frame.size > receive_core_mtu(endpoint)) {
        return DMP_LIMIT_EXHAUSTED;
    }
    status = take_frame(endpoint, frame, now);
    (void)select_active_route(endpoint);
    return status;
}

dmp_status dmp_endpoint_rx_packet(dmp_endpoint *endpoint, dmp_bytes frame, dmp_time_ms now)
{
    dmp_peer_handle peer = {0U, 1U};
    if (endpoint == NULL || endpoint->profile.peers != 1U) {
        return DMP_INVALID_ARGUMENT;
    }
    return dmp_endpoint_rx_packet_from(endpoint, peer, frame, now);
}
