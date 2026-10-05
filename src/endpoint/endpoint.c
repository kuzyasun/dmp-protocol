#include "dmp/endpoint.h"

#include "../security/handshake.h"

#include <string.h>

static void freshness_consume_key(dmp_endpoint *endpoint, dmp_message_key key,
                                  uint32_t service);
static void freshness_maintenance(dmp_endpoint *endpoint, dmp_time_ms now);
static void freshness_clear_attempt(dmp_endpoint *endpoint, uint32_t attempt);

/* Endpoint codec. Reliability owns unfragmented retry, duplicate
 * suppression, receipts and results. Reassembly owns fixed-stride fragments.
 * SEC-1 records are the P14 seal/open path. RADIO-1 origin_route emits
 * TO_NODE and the sender's own CONTEXT; DIRECT-1 leaves both off.
 * This file does not allocate, parse JSON, or hash epochs on receive. */

enum { KIND_REL = 0, KIND_FRAG = 1, KIND_TELEM = 2, KIND_STATUS = 3 };

static int ready(const dmp_endpoint *endpoint)
{
    return endpoint != NULL && endpoint->initialized != 0U;
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
    limits.max_frame_bytes = endpoint->profile.encoded_mtu;
    limits.max_message_bytes = endpoint->profile.message_bytes;
    limits.max_fragments = endpoint->profile.fragments;
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

static void emit(dmp_endpoint *endpoint, dmp_endpoint_event event, dmp_reliability_handle request,
                 uint32_t service, uint32_t wire_status, dmp_bytes payload, dmp_message_key source)
{
    dmp_endpoint_notice notice;
    if (endpoint->notice == NULL) {
        return;
    }
    memset(&notice, 0, sizeof notice);
    notice.event = event;
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
    if (endpoint->association_bound == 0U || endpoint->association == NULL) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!dmp_hs_traffic_identity(endpoint->association, endpoint->association_attempt, &namespace_id,
                                 &local_id, &peer_id, &local_epoch, &peer_epoch)) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (endpoint->context.slot >= endpoint->identity.capacity) {
        return DMP_STALE_HANDLE;
    }
    slot = &endpoint->identity.slots[endpoint->context.slot];
    if (slot->generation != endpoint->context.generation || slot->security != 1U ||
        slot->local.namespace_id != namespace_id || slot->local.origin_id != local_id ||
        slot->peer.origin_id != peer_id) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    /* Traffic epochs exist once the attempt is hashed. They are not activation. */
    slot->local.epoch = local_epoch;
    slot->peer.epoch = peer_epoch;
    return DMP_OK;
}

static dmp_status require_attempt(const dmp_endpoint *endpoint, uint32_t attempt)
{
    if (!secured(endpoint)) {
        return DMP_OK;
    }
    if (endpoint->revoked != 0U || endpoint->association_bound == 0U || endpoint->association == NULL) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (endpoint->drain_live != 0U && attempt == endpoint->drain_attempt) {
        if (dmp_hs_send_application(endpoint->association, attempt) != DMP_HS_OK) {
            return DMP_DEADLINE_EXPIRED;
        }
        return DMP_OK;
    }
    if (attempt != endpoint->association_attempt) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    {
        dmp_hs_status hs = dmp_hs_send_application(endpoint->association, attempt);
        if (hs == DMP_HS_OK) {
            return DMP_OK;
        }
        /* Not confirmed yet, and the attempt is still alive. Reliability
         * treats DMP_BUSY as non-destructive, so the admitted REQ stays queued
         * until activation. A cancelled or otherwise terminal attempt is not
         * this case. */
        if (hs == DMP_HS_NOT_ACTIVE && !dmp_hs_terminal(endpoint->association, attempt)) {
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
        if (endpoint->context.slot >= endpoint->identity.capacity) {
            return DMP_STALE_HANDLE;
        }
        slot = &endpoint->identity.slots[endpoint->context.slot];
        epoch = slot->local.epoch;
        if (endpoint->drain_live != 0U && seal_attempt == endpoint->drain_attempt) {
            epoch = endpoint->drain_local_epoch;
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
    if (endpoint->encode_freshness_live != 0U &&
        !put_tlv(endpoint->ext_scratch, &ext_n, sizeof endpoint->ext_scratch, 25U,
                 endpoint->encode_freshness_token, sizeof endpoint->encode_freshness_token)) {
        return DMP_LIMIT_EXHAUSTED;
    }
    if (ext_n != 0U) {
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_EXT);
        spec.extensions.data = endpoint->ext_scratch;
        spec.extensions.size = ext_n;
    }
    spec.payload = payload;
    /* Dry run: header plus payload plus the 16-byte tag, compared with
     * encoded_mtu. Does not seal and does not require an active attempt.
     * DMP_HS_APP_PLAIN_MAX remains the protected plaintext buffer ceiling. */
    if (out.data == NULL) {
        dmp_core_limits limits;
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
            if (endpoint->association_bound != 0U && endpoint->association != NULL) {
                uint32_t cid = dmp_hs_remote_rx_cid(endpoint->association, seal_attempt);
                spec.fields.security.receive_cid = cid;
                spec.fields.security.pn = dmp_hs_next_pn(endpoint->association, seal_attempt);
            }
        }
        limits = limits_of(endpoint);
        header_buf.data = header;
        header_buf.capacity = sizeof header;
        return dmp_core_encode_header(&spec, &limits, header_buf, &header_len);
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
        sealed = dmp_hs_seal_logical(endpoint->association, seal_attempt, &spec, out.data,
                                     out.capacity, written);
        return from_hs(sealed);
    }
    limits = limits_of(endpoint);
    return dmp_core_encode(&spec, &limits, out, written);
}

static uint32_t seal_attempt_for(const dmp_endpoint *endpoint, const dmp_reliability_logical *logical)
{
    if (endpoint->drain_live != 0U && logical->has_reply_to &&
        logical->reply_to.origin.epoch == endpoint->drain_peer_epoch) {
        return endpoint->drain_attempt;
    }
    if (endpoint->drain_live != 0U && logical->own.origin.epoch == endpoint->drain_local_epoch) {
        return endpoint->drain_attempt;
    }
    return endpoint->association_attempt;
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
    token = logical->freshness_token;
    if (!bytes_ok(token) || (token.size != 0U && token.size != 16U)) {
        return DMP_INVALID_ARGUMENT;
    }
    endpoint->encode_freshness_live = token.size == 16U ? 1U : 0U;
    if (endpoint->encode_freshness_live != 0U) {
        memcpy(endpoint->encode_freshness_token, token.data, sizeof endpoint->encode_freshness_token);
    }
    status_present = logical->type == DMP_TYPE_ERR ||
                     (logical->type == DMP_TYPE_RSP && logical->wire_status != 0U);
    status = encode_core(endpoint, (uint8_t)logical->type, logical->service_id, logical->own.seq,
                         logical->ack_req ? 1 : 0, logical->total_size != 0U,
                         logical->fragment_index, logical->chunk_size, logical->total_size,
                         logical->payload, logical->has_reply_to ? 1 : 0, logical->reply_to,
                         status_present, logical->wire_status, secured(endpoint),
                         secured(endpoint), seal_attempt_for(endpoint, logical), out, written);
    endpoint->encode_freshness_live = 0U;
    memset(endpoint->encode_freshness_token, 0, sizeof endpoint->encode_freshness_token);
    return status;
}

static void on_reliability_notice(void *user, const dmp_reliability_notice *notice)
{
    dmp_endpoint *endpoint = user;
    dmp_endpoint_event event;
    if (endpoint == NULL || notice == NULL) {
        return;
    }
    if (notice->event == DMP_REL_EVENT_REQUEST_ACCEPTED) {
        if (notice->service_id == 0U) {
            if (endpoint->prepared_grant_live != 0U &&
                message_key_eq(endpoint->prepared_grant_key, notice->key)) {
                endpoint->pending_grant_request = notice->handle;
                endpoint->pending_grant_live = 1U;
            }
            return;
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
        return;
    }
    emit(endpoint, event, notice->handle, notice->service_id, notice->wire_status, notice->payload,
         notice->key);
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
        uint8_t kind;
        if (tx->live == 0U || tx->outer_token.slot != token.slot ||
            tx->outer_token.generation != token.generation) {
            continue;
        }
        kind = tx->kind;
        complete = tx->complete;
        complete_owner = tx->owner;
        inner = tx->inner_token;
        memset(tx, 0, sizeof *tx);
        endpoint->wire_busy = 0U;
        if (kind == KIND_REL && complete != NULL) {
            complete(complete_owner, inner, outcome, when);
        } else if (kind == KIND_FRAG) {
            endpoint->frag_tx = 0U;
            if (outcome != DMP_TX_FAILED_UNSENT && outcome != DMP_TX_CANCELLED_UNSENT) {
                if (endpoint->frag_index + 1U >= endpoint->frag_count) {
                    endpoint->frag_live = 0U;
                } else {
                    endpoint->frag_index++;
                }
            }
        } else if (kind == KIND_TELEM) {
            endpoint->telem_tx = 0U;
            if (outcome == DMP_TX_FAILED_UNSENT || outcome == DMP_TX_CANCELLED_UNSENT) {
                endpoint->telem_pending = 1U;
            } else {
                endpoint->telem_pending = 0U;
                endpoint->telem_seq_set = 0U;
                if (endpoint->telem_hold != 0U) {
                    memcpy(endpoint->mem.telemetry_payload, endpoint->mem.telemetry_next,
                           endpoint->telem_next_len);
                    endpoint->telem_len = endpoint->telem_next_len;
                    endpoint->telem_hold = 0U;
                    endpoint->telem_pending = 1U;
                    endpoint->telem_seq_set = 0U;
                }
            }
        }
        return;
    }
}

static dmp_status submit_wire(dmp_endpoint *endpoint, uint8_t kind, dmp_bytes core,
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
    if (core.size == 0U || core.size > endpoint->profile.encoded_mtu || core.data == NULL) {
        return DMP_LIMIT_EXHAUSTED;
    }
    slot = find_tx(endpoint);
    if (slot < 0 || endpoint->tx_generation == UINT64_MAX) {
        return DMP_QUOTA_EXHAUSTED;
    }
    /* Leading delimiter on every frame. A lost opening frame must not leave
     * the peer discarding the retransmission. Stream R allows this prefix. */
    if (endpoint->mem.stream_tx_capacity < 1U) {
        return DMP_QUOTA_EXHAUSTED;
    }
    encoded.data = endpoint->mem.stream_tx + 1U;
    encoded.capacity = endpoint->mem.stream_tx_capacity - 1U;
    status = dmp_stream_encode(DMP_STREAM_R, core, encoded, &written);
    if (status != DMP_OK) {
        return status;
    }
    endpoint->mem.stream_tx[0] = 0U;
    written++;
    endpoint->tx_generation++;
    memset(&endpoint->tx[slot], 0, sizeof endpoint->tx[slot]);
    endpoint->tx[slot].live = 1U;
    endpoint->tx[slot].kind = kind;
    endpoint->tx[slot].outer_token.slot = (uint32_t)slot;
    endpoint->tx[slot].outer_token.generation = endpoint->tx_generation;
    endpoint->tx[slot].inner_token = inner;
    endpoint->tx[slot].complete = complete;
    endpoint->tx[slot].owner = complete_owner;
    endpoint->wire_busy = 1U;
    memset(&submission, 0, sizeof submission);
    submission.token = endpoint->tx[slot].outer_token;
    submission.frame.data = endpoint->mem.stream_tx;
    submission.frame.size = written;
    submission.not_after = not_after;
    submission.complete = on_wire_complete;
    submission.owner = endpoint;
    status = endpoint->outer.submit(endpoint->outer.context, &submission);
    if (status != DMP_OK) {
        memset(&endpoint->tx[slot], 0, sizeof endpoint->tx[slot]);
        endpoint->wire_busy = 0U;
        return status;
    }
    return DMP_OK;
}

static dmp_status inner_submit(void *context, const dmp_tx_submission *submission)
{
    dmp_endpoint *endpoint = context;
    if (endpoint == NULL || submission == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    return submit_wire(endpoint, KIND_REL, submission->frame, submission->complete, submission->owner,
                       submission->token, submission->not_after);
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
    size_t stream_bound = 0U;
    uint64_t required_freshness = 0U;
    dmp_status status;
    if (endpoint == NULL || storage == NULL || storage->profile == NULL ||
        storage->transport == NULL || storage->notice == NULL || storage->context.security > 1U) {
        return DMP_INVALID_ARGUMENT;
    }
    status = dmp_stream_encoded_bound(DMP_STREAM_R, storage->profile->encoded_mtu, &stream_bound);
    if (status != DMP_OK) {
        return status;
    }
    if (storage->transport->submit == NULL || storage->transport->cancel == NULL ||
        storage->transport->caps.max_frame_bytes < stream_bound + 1U ||
        (storage->profile->tx_borrow ? 1 : 0) !=
            (storage->transport->caps.ownership == DMP_TX_BORROW ? 1 : 0) ||
        storage->profile->synchronous_completion != storage->transport->caps.synchronous_completion) {
        return DMP_INVALID_ARGUMENT;
    }
    if (storage->profile->freshness_required_mask != 0U) {
        required_freshness = (uint64_t)storage->profile->freshness_tokens_per_association * 2U;
        if (storage->context.security != 1U) {
            return DMP_UNSUPPORTED;
        }
        if (required_freshness > (uint64_t)SIZE_MAX / sizeof(dmp_endpoint_freshness_slot) ||
            storage->freshness_capacity < required_freshness || storage->freshness_slots == NULL) {
            return DMP_INVALID_ARGUMENT;
        }
    }
    if (require_span(1U, storage->identity_slots, storage->identity_capacity) != DMP_OK ||
        require_span(storage->profile->message_bytes, storage->fragment_message,
                     storage->fragment_message_capacity) != DMP_OK ||
        require_span(storage->profile->encoded_mtu, storage->fragment_frame,
                     storage->fragment_frame_capacity) != DMP_OK ||
        require_span(storage->profile->message_bytes, storage->telemetry_payload,
                     storage->telemetry_payload_capacity) != DMP_OK ||
        require_span(storage->profile->message_bytes, storage->telemetry_next,
                     storage->telemetry_next_capacity) != DMP_OK ||
        require_span(storage->profile->encoded_mtu, storage->telemetry_frame,
                     storage->telemetry_frame_capacity) != DMP_OK ||
        require_span(stream_bound + 1U, storage->stream_tx, storage->stream_tx_capacity) != DMP_OK ||
        require_span(stream_bound, storage->stream_rx, storage->stream_rx_capacity) != DMP_OK ||
        storage->assembly_capacity < storage->profile->assembly_slots ||
        storage->tombstone_capacity < storage->profile->assembly_tombstone_slots) {
        return DMP_INVALID_ARGUMENT;
    }
    memset(endpoint, 0, sizeof *endpoint);
    endpoint->profile = *storage->profile;
    endpoint->mem = *storage;
    endpoint->mem.profile = &endpoint->profile;
    endpoint->notice = storage->notice;
    endpoint->notice_user = storage->notice_user;
    endpoint->outer = *storage->transport;
    endpoint->tx_generation = 1U;
    if (required_freshness != 0U) {
        memset(storage->freshness_slots, 0,
               (size_t)required_freshness * sizeof(dmp_endpoint_freshness_slot));
    }
    status = dmp_identity_table_init(&endpoint->identity, storage->identity_slots,
                                     storage->identity_capacity);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_identity_context_open(&endpoint->identity, &storage->context, &endpoint->context);
    if (status != DMP_OK) {
        return status;
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
    status = dmp_reassembly_init(&endpoint->reassembly, &assembly, &endpoint->profile,
                                 &endpoint->identity);
    if (status != DMP_OK) {
        return status;
    }
    endpoint->inner.context = endpoint;
    endpoint->inner.submit = inner_submit;
    endpoint->inner.cancel = inner_cancel;
    endpoint->inner.caps.max_frame_bytes = endpoint->profile.encoded_mtu;
    endpoint->inner.caps.ownership = endpoint->profile.tx_borrow ? DMP_TX_BORROW : DMP_TX_COPY;
    endpoint->inner.caps.synchronous_completion = endpoint->profile.synchronous_completion;
    memset(&rel, 0, sizeof rel);
    rel.profile = &endpoint->profile;
    rel.identity = &endpoint->identity;
    rel.context = endpoint->context;
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
    memset(&stream, 0, sizeof stream);
    stream.mode = DMP_STREAM_R;
    stream.max_core_bytes = endpoint->profile.encoded_mtu;
    stream.partial_timeout_ms =
        endpoint->profile.collect_ms != 0U ? endpoint->profile.collect_ms : 1U;
    stream_storage.data = storage->stream_rx;
    stream_storage.capacity = storage->stream_rx_capacity;
    status = dmp_stream_init(&endpoint->decoder, stream, stream_storage, now);
    if (status != DMP_OK) {
        (void)dmp_reliability_close(&endpoint->reliability, now);
        return status;
    }
    endpoint->initialized = 1U;
    return DMP_OK;
}

static uint32_t permit_mask(const dmp_endpoint *endpoint, uint32_t principal, uint32_t service)
{
    uint32_t mask = 0U;
    uint8_t index;

    if (endpoint->grants_set == 0U) {
        return 0U;
    }
    for (index = 0U; index < endpoint->grant_count; index++) {
        const dmp_endpoint_grant *grant = &endpoint->grants[index];
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
    if (endpoint->revoked != 0U || endpoint->grants_set == 0U || need == 0U) {
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
    if (endpoint->context.slot >= endpoint->identity.capacity) {
        return 0;
    }
    slot = &endpoint->identity.slots[endpoint->context.slot];
    if (slot->generation != endpoint->context.generation) {
        return 0;
    }
    if (service == 0U) {
        return action_allowed(endpoint, slot->local.origin_id, 0U, DMP_ENDPOINT_PERMIT_CONTROL);
    }
    return action_allowed(endpoint, slot->local.origin_id, service, need);
}

static size_t freshness_slot_count(const dmp_endpoint *endpoint)
{
    uint64_t admitted = (uint64_t)endpoint->profile.freshness_tokens_per_association * 2U;
    return admitted < endpoint->mem.freshness_capacity ? (size_t)admitted
                                                       : endpoint->mem.freshness_capacity;
}

static void freshness_clear_attempt(dmp_endpoint *endpoint, uint32_t attempt)
{
    size_t i;
    size_t count = freshness_slot_count(endpoint);
    for (i = 0U; i < count; i++) {
        dmp_endpoint_freshness_slot *slot = &endpoint->mem.freshness_slots[i];
        if (slot->state != DMP_ENDPOINT_FRESHNESS_EMPTY && slot->attempt == attempt) {
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
        if (slot->state == DMP_ENDPOINT_FRESHNESS_BOUND && slot->principal == key.origin.origin_id &&
            slot->peer_epoch == key.origin.epoch && slot->bound_seq == key.seq &&
            slot->service_id == service) {
            slot->state = DMP_ENDPOINT_FRESHNESS_CONSUMED;
        }
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
        if (history->live != 0U && message_key_eq(history->source, key) &&
            history->service_id == service && history->type == type) {
            return 1;
        }
    }
    for (i = 0U; i < endpoint->mem.result_capacity; i++) {
        const dmp_reliability_result_slot *result = &endpoint->mem.results[i];
        if (result->live != 0U && message_key_eq(result->request, key) &&
            result->service_id == service) {
            return 1;
        }
    }
    return 0;
}

static void use_context(dmp_endpoint *endpoint, dmp_identity_handle handle)
{
    endpoint->reliability.storage.context = handle;
}

static void cancel_epoch_requests(dmp_endpoint *endpoint, dmp_time_ms now, int only_past_drain)
{
    size_t index;

    if (endpoint->mem.senders == NULL) {
        return;
    }
    for (index = 0U; index < endpoint->mem.sender_capacity; index++) {
        dmp_reliability_sender_slot *sender = &endpoint->mem.senders[index];
        dmp_reliability_handle handle;

        if (sender->live == 0U || sender->kind != DMP_REL_SENDER_REQUEST ||
            sender->phase == DMP_REL_PHASE_TERMINAL) {
            continue;
        }
        if (endpoint->drain_live != 0U && sender->own.origin.epoch != endpoint->drain_local_epoch) {
            continue;
        }
        if (only_past_drain && endpoint->drain_live != 0U &&
            sender->send_deadline <= endpoint->drain_not_after &&
            sender->result_deadline <= endpoint->drain_not_after) {
            continue;
        }
        handle.slot = (uint32_t)index;
        handle.generation = sender->generation;
        (void)dmp_reliability_cancel(&endpoint->reliability, handle, now);
    }
}

static void end_drain(dmp_endpoint *endpoint, dmp_time_ms now)
{
    dmp_status retired;

    if (endpoint->drain_live == 0U) {
        return;
    }
    cancel_epoch_requests(endpoint, now, 0);
    if (endpoint->association != NULL) {
        (void)dmp_hs_cancel(endpoint->association, endpoint->drain_attempt);
    }
    /* Reassembly may still retain the draining context. Leave the slot and
     * retry on a later poll once that retain drops. */
    retired = dmp_identity_context_retire(&endpoint->identity, endpoint->drain_context, now);
    if (retired != DMP_OK && retired != DMP_STALE_HANDLE) {
        return;
    }
    freshness_clear_attempt(endpoint, endpoint->drain_attempt);
    endpoint->drain_live = 0U;
}

static void expire_drain(dmp_endpoint *endpoint, dmp_time_ms now)
{
    if (endpoint->drain_live != 0U && now >= endpoint->drain_not_after) {
        end_drain(endpoint, now);
    }
}

dmp_status dmp_endpoint_set_grants(dmp_endpoint *endpoint, const dmp_endpoint_grant *grants,
                                   size_t count)
{
    size_t index;

    if (!ready(endpoint) || count > DMP_ENDPOINT_GRANT_MAX || (count != 0U && grants == NULL)) {
        return DMP_INVALID_ARGUMENT;
    }
    for (index = 0U; index < count; index++) {
        endpoint->grants[index] = grants[index];
    }
    endpoint->grant_count = (uint8_t)count;
    endpoint->grants_set = 1U;
    return DMP_OK;
}

dmp_status dmp_endpoint_set_drain_ms(dmp_endpoint *endpoint, uint32_t drain_ms)
{
    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    endpoint->drain_ms = drain_ms;
    return DMP_OK;
}

dmp_status dmp_endpoint_rotate(dmp_endpoint *endpoint, uint32_t attempt_index, dmp_time_ms now)
{
    dmp_identity_context_config config;
    dmp_identity_handle fresh;
    dmp_identity_slot *slot;
    uint32_t namespace_id = 0U;
    uint32_t local_id = 0U;
    uint32_t peer_id = 0U;
    uint64_t local_epoch = 0U;
    uint64_t peer_epoch = 0U;
    uint64_t bound;
    dmp_status status;

    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (endpoint->revoked != 0U || endpoint->association_bound == 0U || endpoint->association == NULL) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (endpoint->drain_live != 0U || attempt_index == endpoint->association_attempt) {
        return DMP_BUSY;
    }
    if (dmp_hs_send_application(endpoint->association, attempt_index) != DMP_HS_OK) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!dmp_hs_traffic_identity(endpoint->association, attempt_index, &namespace_id, &local_id,
                                 &peer_id, &local_epoch, &peer_epoch)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (endpoint->context.slot >= endpoint->identity.capacity) {
        return DMP_STALE_HANDLE;
    }
    slot = &endpoint->identity.slots[endpoint->context.slot];
    if (slot->generation != endpoint->context.generation || slot->local.namespace_id != namespace_id ||
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
    bound = (uint64_t)endpoint->drain_ms > UINT64_MAX - now ? UINT64_MAX
                                                           : now + (uint64_t)endpoint->drain_ms;
    status = dmp_identity_context_begin_drain(&endpoint->identity, endpoint->context, bound);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_identity_context_retain(&endpoint->identity, fresh);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_identity_context_release(&endpoint->identity, endpoint->context);
    if (status != DMP_OK) {
        return status;
    }
    endpoint->drain_context = endpoint->context;
    endpoint->drain_attempt = endpoint->association_attempt;
    endpoint->drain_local_epoch = slot->local.epoch;
    endpoint->drain_peer_epoch = slot->peer.epoch;
    endpoint->drain_not_after = bound;
    endpoint->drain_live = 1U;
    endpoint->context = fresh;
    endpoint->association_attempt = attempt_index;
    use_context(endpoint, fresh);
    /* Original deadlines stay. Work that runs past the drain bound is not moved. */
    cancel_epoch_requests(endpoint, now, 1);
    if (now >= bound) {
        end_drain(endpoint, now);
    }
    return DMP_OK;
}

dmp_status dmp_endpoint_revoke(dmp_endpoint *endpoint, dmp_time_ms now)
{
    size_t index;

    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    endpoint->revoked = 1U;
    if (endpoint->mem.freshness_slots != NULL) {
        memset(endpoint->mem.freshness_slots, 0,
               freshness_slot_count(endpoint) * sizeof *endpoint->mem.freshness_slots);
    }
    if (endpoint->mem.senders != NULL) {
        for (index = 0U; index < endpoint->mem.sender_capacity; index++) {
            dmp_reliability_sender_slot *sender = &endpoint->mem.senders[index];
            dmp_reliability_handle handle;

            if (sender->live == 0U || sender->kind != DMP_REL_SENDER_REQUEST ||
                sender->phase == DMP_REL_PHASE_TERMINAL) {
                continue;
            }
            handle.slot = (uint32_t)index;
            handle.generation = sender->generation;
            (void)dmp_reliability_cancel(&endpoint->reliability, handle, now);
        }
    }
    if (endpoint->association != NULL && endpoint->association_bound != 0U) {
        (void)dmp_hs_cancel(endpoint->association, endpoint->association_attempt);
    }
    end_drain(endpoint, now);
    return DMP_OK;
}

dmp_status dmp_endpoint_bind(dmp_endpoint *endpoint, struct dmp_hs *handshake, uint32_t attempt_index)
{
    dmp_identity_slot *slot;
    uint32_t namespace_id = 0U;
    uint32_t local_id = 0U;
    uint32_t peer_id = 0U;
    uint64_t local_epoch = 0U;
    uint64_t peer_epoch = 0U;

    if (!ready(endpoint) || handshake == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (endpoint->association_bound != 0U &&
        (handshake != endpoint->association || attempt_index != endpoint->association_attempt)) {
        return DMP_BUSY;
    }
    if (endpoint->context.slot >= endpoint->identity.capacity) {
        return DMP_STALE_HANDLE;
    }
    slot = &endpoint->identity.slots[endpoint->context.slot];
    if (slot->generation != endpoint->context.generation || slot->security != 1U) {
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
    (void)local_epoch;
    (void)peer_epoch;
    endpoint->association = handshake;
    endpoint->association_attempt = attempt_index;
    endpoint->association_bound = 1U;
    return install_epochs(endpoint);
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
    if (endpoint->revoked != 0U) {
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
    probe.capacity = endpoint->profile.encoded_mtu;
    endpoint->encode_freshness_live = token.size == 16U ? 1U : 0U;
    if (endpoint->encode_freshness_live != 0U) {
        memcpy(endpoint->encode_freshness_token, token.data, sizeof endpoint->encode_freshness_token);
    }
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_REQ, service_id, 0U, 1, 0, 0U, 0U, 0U, payload,
                         0, (dmp_message_key){0}, 0, 0U, secured(endpoint), secured(endpoint),
                         endpoint->association_attempt, probe, &written);
    endpoint->encode_freshness_live = 0U;
    memset(endpoint->encode_freshness_token, 0, sizeof endpoint->encode_freshness_token);
    /* Fragment only when this exact non-FRAG frame does not fit encoded_mtu.
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

dmp_status dmp_endpoint_submit_req(dmp_endpoint *endpoint, uint32_t service_id, dmp_bytes payload,
                                   dmp_time_ms now, dmp_reliability_handle *out)
{
    dmp_bytes empty = {NULL, 0U};
    return submit_req_with_token(endpoint, service_id, payload, empty, now, out);
}

dmp_status dmp_endpoint_submit_req_fresh(dmp_endpoint *endpoint, uint32_t service_id,
                                         dmp_bytes payload, dmp_bytes token,
                                         dmp_time_ms now, dmp_reliability_handle *out)
{
    if (token.size != 16U || token.data == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    return submit_req_with_token(endpoint, service_id, payload, token, now, out);
}

dmp_status dmp_endpoint_submit_data(dmp_endpoint *endpoint, uint32_t service_id,
                                    dmp_bytes payload, dmp_bytes token, dmp_time_ms now,
                                    dmp_reliability_handle *out)
{
    if (!ready(endpoint) || out == NULL || !bytes_ok(payload) || !bytes_ok(token) ||
        (token.size != 0U && token.size != 16U)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (endpoint->revoked != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!service_allowed(&endpoint->profile, service_id) || service_id == 0U ||
        (freshness_required(&endpoint->profile, service_id) != (token.size == 16U))) {
        return DMP_UNSUPPORTED;
    }
    if (!local_action(endpoint, service_id, DMP_ENDPOINT_PERMIT_REQ)) {
        return DMP_UNSUPPORTED;
    }
    return token.size == 16U
               ? dmp_reliability_submit_data_fresh(&endpoint->reliability, service_id, payload,
                                                   token, now, out)
               : dmp_reliability_submit_data(&endpoint->reliability, service_id, payload, now,
                                             out);
}

dmp_status dmp_endpoint_submit_event(dmp_endpoint *endpoint, uint32_t service_id,
                                     dmp_bytes payload, dmp_bytes token, dmp_time_ms now,
                                     dmp_reliability_handle *out)
{
    if (!ready(endpoint) || out == NULL || !bytes_ok(payload) || !bytes_ok(token) ||
        (token.size != 0U && token.size != 16U)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (endpoint->revoked != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!service_allowed(&endpoint->profile, service_id) || service_id == 0U ||
        (freshness_required(&endpoint->profile, service_id) != (token.size == 16U))) {
        return DMP_UNSUPPORTED;
    }
    if (!local_action(endpoint, service_id, DMP_ENDPOINT_PERMIT_REQ)) {
        return DMP_UNSUPPORTED;
    }
    return token.size == 16U
               ? dmp_reliability_submit_event_fresh(&endpoint->reliability, service_id, payload,
                                                    token, now, out)
               : dmp_reliability_submit_event(&endpoint->reliability, service_id, payload, now,
                                              out);
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
    if (endpoint->revoked != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (request.slot < endpoint->mem.history_capacity && endpoint->mem.history != NULL) {
        dmp_reliability_history_slot *history = &endpoint->mem.history[request.slot];
        if (history->live != 0U && history->generation == request.generation) {
            /* Local RESULT permission applies with or without a live drain. */
            if (!local_action(endpoint, history->service_id, DMP_ENDPOINT_PERMIT_RESULT)) {
                return DMP_UNSUPPORTED;
            }
            if (endpoint->drain_live != 0U &&
                history->source.origin.epoch == endpoint->drain_peer_epoch) {
                use_context(endpoint, endpoint->drain_context);
                swapped = 1;
            }
        }
    }
    status = dmp_reliability_complete_for_lifetime(&endpoint->reliability, request,
                                                   application_err, wire_status, payload,
                                                   result_lifetime_ms, now);
    if (swapped) {
        use_context(endpoint, endpoint->context);
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
    if (endpoint->revoked != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!local_action(endpoint, service_id, DMP_ENDPOINT_PERMIT_TELEM)) {
        return DMP_UNSUPPORTED;
    }
    probe.data = endpoint->mem.telemetry_frame;
    probe.capacity = endpoint->profile.encoded_mtu;
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_TELEM, service_id, 0U, 0, 0, 0U, 0U, 0U,
                         payload, 0, (dmp_message_key){0}, 0, 0U, 0, 0, 0U, probe, &written);
    if (status != DMP_OK) {
        return status;
    }
    if (replace) {
        memcpy(endpoint->mem.telemetry_next, payload.data, payload.size);
        endpoint->telem_next_len = (uint32_t)payload.size;
        endpoint->telem_hold = 1U;
        return DMP_OK;
    }
    if (payload.size != 0U) {
        memcpy(endpoint->mem.telemetry_payload, payload.data, payload.size);
    }
    endpoint->telem_len = (uint32_t)payload.size;
    endpoint->telem_service = service_id;
    endpoint->telem_pending = 1U;
    endpoint->telem_seq_set = 0U;
    return DMP_OK;
}

dmp_status dmp_endpoint_submit_telem(dmp_endpoint *endpoint, uint32_t service_id, dmp_bytes payload,
                                     dmp_time_ms now)
{
    (void)now;
    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (endpoint->telem_tx != 0U) {
        return stage_telem(endpoint, service_id, payload, 1);
    }
    if (endpoint->telem_pending != 0U) {
        endpoint->telem_seq_set = 0U;
    }
    return stage_telem(endpoint, service_id, payload, 0);
}

static dmp_status send_telem(dmp_endpoint *endpoint, dmp_time_ms now)
{
    dmp_buffer out;
    dmp_bytes payload;
    dmp_time_ms not_after;
    size_t written = 0U;
    dmp_status status;
    if (endpoint->telem_seq_set == 0U) {
        status = dmp_identity_next_seq(&endpoint->identity, endpoint->context, &endpoint->telem_seq);
        if (status != DMP_OK) {
            return status;
        }
        endpoint->telem_attempt = endpoint->association_attempt;
        endpoint->telem_seq_set = 1U;
    }
    payload.data = endpoint->telem_len == 0U ? NULL : endpoint->mem.telemetry_payload;
    payload.size = endpoint->telem_len;
    out.data = endpoint->mem.telemetry_frame;
    out.capacity = endpoint->profile.encoded_mtu;
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_TELEM, endpoint->telem_service,
                         endpoint->telem_seq, 0, 0, 0U, 0U, 0U, payload, 0, (dmp_message_key){0}, 0,
                         0U, secured(endpoint), secured(endpoint), endpoint->telem_attempt, out,
                         &written);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_deadline_after(now, endpoint->profile.send_horizon_ms, &not_after);
    if (status != DMP_OK) {
        return status;
    }
    endpoint->telem_tx = 1U;
    payload.data = endpoint->mem.telemetry_frame;
    payload.size = written;
    status = submit_wire(endpoint, KIND_TELEM, payload, NULL, NULL, (dmp_tx_token){0}, not_after);
    if (status != DMP_OK) {
        endpoint->telem_tx = 0U;
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
    offset = endpoint->frag_index * endpoint->profile.chunk_bytes;
    expect = endpoint->frag_total - offset;
    if (expect > endpoint->profile.chunk_bytes) {
        expect = endpoint->profile.chunk_bytes;
    }
    slice.data = endpoint->mem.fragment_message + offset;
    slice.size = expect;
    out.data = endpoint->mem.fragment_frame;
    out.capacity = endpoint->profile.encoded_mtu;
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_DATA, endpoint->frag_service, endpoint->frag_seq,
                         0, 1, endpoint->frag_index, endpoint->profile.chunk_bytes,
                         endpoint->frag_total, slice, 0, (dmp_message_key){0}, 0, 0U,
                         secured(endpoint), secured(endpoint), endpoint->frag_attempt, out, &written);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_deadline_after(now, endpoint->profile.send_horizon_ms, &not_after);
    if (status != DMP_OK) {
        return status;
    }
    endpoint->frag_tx = 1U;
    frame.data = endpoint->mem.fragment_frame;
    frame.size = written;
    status = submit_wire(endpoint, KIND_FRAG, frame, NULL, NULL, (dmp_tx_token){0}, not_after);
    if (status != DMP_OK) {
        endpoint->frag_tx = 0U;
        return status;
    }
    return DMP_OK;
}

dmp_status dmp_endpoint_submit_fragmented(dmp_endpoint *endpoint, uint32_t service_id,
                                          dmp_bytes payload, dmp_time_ms now)
{
    const dmp_identity_slot *slot;
    dmp_buffer probe;
    dmp_bytes slice;
    size_t written = 0U;
    uint32_t chunk;
    uint32_t count;
    uint32_t last;
    uint32_t seq = 0U;
    dmp_status status;
    (void)now;
    if (!ready(endpoint) || !bytes_ok(payload) || payload.size == 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    if (!service_allowed(&endpoint->profile, service_id)) {
        return DMP_UNSUPPORTED;
    }
    if (service_id == 0U || freshness_required(&endpoint->profile, service_id)) {
        return DMP_UNSUPPORTED;
    }
    if (endpoint->revoked != 0U) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    if (!local_action(endpoint, service_id, DMP_ENDPOINT_PERMIT_REQ)) {
        return DMP_UNSUPPORTED;
    }
    if (endpoint->frag_live != 0U) {
        return DMP_QUOTA_EXHAUSTED;
    }
    if (payload.size > endpoint->profile.message_bytes) {
        return DMP_LIMIT_EXHAUSTED;
    }
    if (endpoint->context.slot >= endpoint->identity.capacity) {
        return DMP_STALE_HANDLE;
    }
    slot = &endpoint->identity.slots[endpoint->context.slot];
    if (slot->generation != endpoint->context.generation || slot->seq_exhausted) {
        return DMP_STALE_HANDLE;
    }
    probe.data = endpoint->mem.fragment_frame;
    probe.capacity = endpoint->profile.encoded_mtu;
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_DATA, service_id, slot->next_seq, 0, 0, 0U, 0U,
                         0U, payload, 0, (dmp_message_key){0}, 0, 0U, 0, 0, 0U, probe, &written);
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
    status = dmp_identity_next_seq(&endpoint->identity, endpoint->context, &seq);
    if (status != DMP_OK) {
        return status;
    }
    endpoint->frag_attempt = endpoint->association_attempt;
    last = count - 1U;
    slice.data = payload.data + (size_t)last * (size_t)chunk;
    slice.size = payload.size - (size_t)last * (size_t)chunk;
    status = encode_core(endpoint, (uint8_t)DMP_TYPE_DATA, service_id, seq, 0, 1, last, chunk,
                         (uint32_t)payload.size, slice, 0, (dmp_message_key){0}, 0, 0U, 0, 0, 0U,
                         probe, &written);
    if (status != DMP_OK) {
        return status;
    }
    memcpy(endpoint->mem.fragment_message, payload.data, payload.size);
    endpoint->frag_service = service_id;
    endpoint->frag_seq = seq;
    endpoint->frag_total = (uint32_t)payload.size;
    endpoint->frag_count = count;
    endpoint->frag_index = 0U;
    endpoint->frag_tx = 0U;
    endpoint->frag_live = 1U;
    return DMP_OK;
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

    if (!secured(endpoint) || endpoint->frag_live != 0U || endpoint->wire_busy != 0U) {
        return DMP_OK;
    }
    for (i = 0U; i < endpoint->reassembly.storage.assembly_capacity; i++) {
        dmp_reassembly_slot *slot = &endpoint->reassembly.storage.assemblies[i];
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
        if (!service_selective(&endpoint->profile, slot->service_id)) {
            slot->status_expected = 0U;
            continue;
        }
        mask = assembly_missing(slot);
        if (mask == 0U) {
            slot->status_expected = 0U;
            continue;
        }
        status = dmp_identity_next_seq(&endpoint->identity, endpoint->context, &seq);
        if (status != DMP_OK) {
            return status;
        }
        mask_bytes[0] = (uint8_t)mask;
        mask_bytes[1] = (uint8_t)(mask >> 8U);
        mask_bytes[2] = (uint8_t)(mask >> 16U);
        mask_bytes[3] = (uint8_t)(mask >> 24U);
        payload.data = mask_bytes;
        payload.size = 4U;
        attempt = endpoint->association_attempt;
        if (endpoint->drain_live != 0U && slot->context.slot == endpoint->drain_context.slot &&
            slot->context.generation == endpoint->drain_context.generation) {
            attempt = endpoint->drain_attempt;
        }
        out.data = endpoint->mem.fragment_frame;
        out.capacity = endpoint->profile.encoded_mtu;
        status = encode_core(endpoint, (uint8_t)DMP_TYPE_FRAG_STATUS, slot->service_id, seq, 0, 0,
                             0U, 0U, 0U, payload, 1, slot->source, 0, 0U, 1, 1, attempt, out,
                             &written);
        if (status != DMP_OK) {
            return status;
        }
        status = dmp_deadline_after(now, endpoint->profile.feedback_delay_ms, &not_after);
        if (status != DMP_OK) {
            return status;
        }
        frame.data = endpoint->mem.fragment_frame;
        frame.size = written;
        status = submit_wire(endpoint, KIND_STATUS, frame, NULL, NULL, (dmp_tx_token){0}, not_after);
        if (status != DMP_OK) {
            return status;
        }
        slot->status_mask = mask;
        slot->status_expected = 0U;
        return DMP_OK;
    }
    return DMP_OK;
}

dmp_status dmp_endpoint_poll(dmp_endpoint *endpoint, dmp_time_ms now)
{
    dmp_status reliability;
    dmp_status status;
    size_t expired = 0U;
    uint32_t guard;
    if (!ready(endpoint)) {
        return DMP_INVALID_ARGUMENT;
    }
    expire_drain(endpoint, now);
    freshness_maintenance(endpoint, now);
    reliability = dmp_reliability_poll(&endpoint->reliability, now);
    freshness_maintenance(endpoint, now);
    status = dmp_reassembly_poll(&endpoint->reassembly, now, &expired);
    if (status != DMP_OK) {
        return status;
    }
    /* The same poll may have released the assembly retain. Retry retire. */
    expire_drain(endpoint, now);
    status = send_pending_status(endpoint, now);
    if (status != DMP_OK && status != DMP_BUSY) {
        return status;
    }
    for (guard = 0U; guard < endpoint->profile.fragments + 4U; guard++) {
        if (endpoint->frag_live != 0U && endpoint->frag_tx == 0U && endpoint->wire_busy == 0U) {
            status = send_fragment(endpoint, now);
            if (status == DMP_BUSY) {
                break;
            }
            if (status != DMP_OK) {
                if (endpoint->frag_attempt != endpoint->association_attempt) {
                    endpoint->frag_live = 0U;
                    endpoint->frag_tx = 0U;
                    continue;
                }
                return status;
            }
            continue;
        }
        if (endpoint->telem_pending != 0U && endpoint->telem_tx == 0U && endpoint->wire_busy == 0U &&
            endpoint->frag_live == 0U) {
            status = send_telem(endpoint, now);
            if (status == DMP_BUSY) {
                break;
            }
            if (status != DMP_OK) {
                if (endpoint->telem_seq_set != 0U &&
                    endpoint->telem_attempt != endpoint->association_attempt) {
                    endpoint->telem_pending = 0U;
                    endpoint->telem_tx = 0U;
                    continue;
                }
                return status;
            }
            continue;
        }
        break;
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
        if (slot->state == DMP_ENDPOINT_FRESHNESS_BOUND &&
            slot->principal == source.origin.origin_id && slot->peer_epoch == source.origin.epoch &&
            slot->bound_seq == source.seq && slot->service_id == service &&
            !token_equal(slot->token, token.data)) {
            return DMP_AUTHENTICATION_FAILURE;
        }
        if (slot->state == DMP_ENDPOINT_FRESHNESS_EMPTY ||
            !token_equal(slot->token, token.data)) {
            continue;
        }
        if (slot->principal != source.origin.origin_id || slot->peer_epoch != source.origin.epoch ||
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
    if (frame->fields.type != DMP_TYPE_REQ ||
        (frame->fields.options & DMP_OPT_ACK_REQ) == 0U) {
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
        return status;
    }
    input.immutable_metadata = metadata;
    use_context(endpoint, context);
    status = dmp_reliability_reject_req(&endpoint->reliability, &input, status_code, now);
    if (status == DMP_DUPLICATE) {
        status = dmp_reliability_on_rx(&endpoint->reliability, &input, now);
    }
    use_context(endpoint, endpoint->context);
    return status == DMP_OK || status == DMP_DUPLICATE ? DMP_OK : status;
}

static int freshness_duplicate_grant(dmp_endpoint *endpoint, dmp_message_key key,
                                     uint32_t attempt, uint32_t requested_lifetime)
{
    size_t i;
    for (i = 0U; i < freshness_slot_count(endpoint); i++) {
        const dmp_endpoint_freshness_slot *slot = &endpoint->mem.freshness_slots[i];
        if (slot->state != DMP_ENDPOINT_FRESHNESS_EMPTY && slot->principal == key.origin.origin_id &&
            slot->peer_epoch == key.origin.epoch && slot->attempt == attempt &&
            slot->grant_request_seq == key.seq) {
            return slot->grant_request_lifetime_ms == requested_lifetime ? 1 : -1;
        }
    }
    return 0;
}

static uint32_t freshness_live_count(const dmp_endpoint *endpoint, uint32_t principal,
                                    uint32_t attempt, int match_attempt, int grants_only)
{
    size_t i;
    uint32_t count = 0U;
    for (i = 0U; i < freshness_slot_count(endpoint); i++) {
        const dmp_endpoint_freshness_slot *slot = &endpoint->mem.freshness_slots[i];
        if (slot->state == DMP_ENDPOINT_FRESHNESS_EMPTY || slot->principal != principal ||
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
    if (endpoint->context.slot >= endpoint->identity.capacity) {
        *protocol_status = 6U;
        return DMP_STALE_HANDLE;
    }
    context = &endpoint->identity.slots[endpoint->context.slot];
    if (context->generation != endpoint->context.generation || context->state != DMP_IDENTITY_SLOT_ACTIVE ||
        attempt != endpoint->association_attempt || require_attempt(endpoint, attempt) != DMP_OK) {
        *protocol_status = 6U;
        return DMP_AUTHENTICATION_FAILURE;
    }
    status = dmp_identity_source_key(frame, &endpoint->identity, endpoint->context, now, &source);
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
    if (freshness_live_count(endpoint, context->peer.origin_id, attempt, 1, 0) >=
            endpoint->profile.freshness_tokens_per_association ||
        freshness_live_count(endpoint, context->peer.origin_id, attempt, 0, 0) >=
            endpoint->profile.freshness_tokens_per_principal ||
        freshness_live_count(endpoint, context->peer.origin_id, attempt, 0, 1) >=
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
    record->state = DMP_ENDPOINT_FRESHNESS_RESERVED;
    record->principal = context->peer.origin_id;
    record->peer_epoch = context->peer.epoch;
    record->attempt = attempt;
    record->grant_request_seq = source.seq;
    record->grant_request_lifetime_ms = requested;
    record->granted_lifetime_ms = granted;
    record->expires_at = expires;
    record->record_until = record_until;
    if (endpoint->association == NULL ||
        dmp_hs_entropy(endpoint->association, record->token, sizeof record->token) != DMP_HS_OK) {
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
    endpoint->prepared_grant_key = source;
    endpoint->prepared_grant_live = 1U;
    endpoint->pending_grant_slot = (uint32_t)(record - endpoint->mem.freshness_slots);
    return DMP_OK;
}

static dmp_status finish_freshness_grant(dmp_endpoint *endpoint, dmp_time_ms now)
{
    dmp_endpoint_freshness_slot *record;
    dmp_reliability_history_slot *history;
    uint8_t response[21];
    dmp_bytes payload;
    dmp_status status;
    if (endpoint->pending_grant_live == 0U) {
        return DMP_OK;
    }
    if (endpoint->pending_grant_slot >= freshness_slot_count(endpoint) ||
        endpoint->pending_grant_request.slot >= endpoint->mem.history_capacity) {
        endpoint->pending_grant_live = 0U;
        endpoint->prepared_grant_live = 0U;
        return DMP_STALE_HANDLE;
    }
    record = &endpoint->mem.freshness_slots[endpoint->pending_grant_slot];
    history = &endpoint->mem.history[endpoint->pending_grant_request.slot];
    if (record->state != DMP_ENDPOINT_FRESHNESS_RESERVED || history->live == 0U ||
        history->generation != endpoint->pending_grant_request.generation) {
        memset(record, 0, sizeof *record);
        endpoint->pending_grant_live = 0U;
        endpoint->prepared_grant_live = 0U;
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
    status = endpoint_complete_for_lifetime(endpoint, endpoint->pending_grant_request, false, 0U,
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
    endpoint->pending_grant_live = 0U;
    endpoint->prepared_grant_live = 0U;
    return status;
}

static void discard_prepared_freshness_grant(dmp_endpoint *endpoint)
{
    if (endpoint->prepared_grant_live != 0U && endpoint->pending_grant_live == 0U &&
        endpoint->pending_grant_slot < freshness_slot_count(endpoint)) {
        dmp_endpoint_freshness_slot *record =
            &endpoint->mem.freshness_slots[endpoint->pending_grant_slot];
        if (record->state == DMP_ENDPOINT_FRESHNESS_RESERVED) {
            memset(record, 0, sizeof *record);
        }
    }
    endpoint->prepared_grant_live = 0U;
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
                                    dmp_time_ms now)
{
    dmp_frame_view logical;
    dmp_reliability_input input;
    dmp_bytes metadata;
    dmp_status status;

    logical = *frame;
    logical.fields.options = (uint8_t)(logical.fields.options & (uint8_t)~DMP_OPT_FRAG);
    memset(&logical.fields.fragment, 0, sizeof logical.fields.fragment);
    logical.payload = full;
    memset(&input, 0, sizeof input);
    input.frame = &logical;
    input.service_id = service;
    input.plaintext = full;
    status = immutable_metadata(endpoint, &logical, &metadata);
    if (status != DMP_OK) {
        if (freshness_required(&endpoint->profile, service)) {
            dmp_message_key source;
            if (dmp_identity_source_key(frame, &endpoint->identity, context, now, &source) == DMP_OK) {
                freshness_consume_key(endpoint, source, service);
            }
        }
        return status;
    }
    input.immutable_metadata = metadata;
    use_context(endpoint, context);
    status = dmp_reliability_on_rx(&endpoint->reliability, &input, now);
    use_context(endpoint, endpoint->context);
    if (status != DMP_BUSY && status != DMP_INCOMPLETE &&
        freshness_required(&endpoint->profile, service) && freshness_command(frame->fields.type)) {
        dmp_message_key source;
        if (dmp_identity_source_key(frame, &endpoint->identity, context, now, &source) == DMP_OK) {
            freshness_consume_key(endpoint, source, service);
        }
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
                                     now);
        if (accepted != DMP_OK && accepted != DMP_DUPLICATE && accepted != DMP_BUSY) {
            return accepted;
        }
        return DMP_DUPLICATE;
    }
    if (status != DMP_OK) {
        return status;
    }
    {
        dmp_reassembly_message message;
        dmp_reliability_handle none;
        memset(&none, 0, sizeof none);
        status = dmp_reassembly_get(&endpoint->reassembly, handle, &message);
        if (status != DMP_OK) {
            return status;
        }
        if (ack_req_logical(frame)) {
            status = present_assembled(endpoint, frame, service, context, message.payload, now);
            if (status != DMP_OK && status != DMP_DUPLICATE) {
                return status;
            }
        }
        emit(endpoint, DMP_ENDPOINT_ASSEMBLED, none, message.service_id, 0U, message.payload,
             message.source);
        /* Keep the completed slot. release clears the RESERVED tombstone, so
         * the same SEQ could be assembled again. Replay is DMP_DUPLICATE while
         * this assembly remains. Poll expires only an incomplete transfer. */
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
    limits = limits_of(endpoint);
    parsed = dmp_core_parse(core, &limits, &view);
    if (parsed.status != DMP_OK || (view.fields.options & DMP_OPT_SECURITY) == 0U ||
        endpoint->association == NULL) {
        return 0;
    }
    cid = view.fields.security.receive_cid;
    if (cid == 0U) {
        return 0;
    }
    if (endpoint->association_bound != 0U &&
        dmp_hs_rx_cid(endpoint->association, endpoint->association_attempt) == cid) {
        if (endpoint->context.slot >= endpoint->identity.capacity) {
            return 0;
        }
        *attempt = endpoint->association_attempt;
        *peer_epoch = endpoint->identity.slots[endpoint->context.slot].peer.epoch;
        return 1;
    }
    if (endpoint->drain_live != 0U &&
        dmp_hs_rx_cid(endpoint->association, endpoint->drain_attempt) == cid) {
        *attempt = endpoint->drain_attempt;
        *peer_epoch = endpoint->drain_peer_epoch;
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

    if (endpoint->revoked != 0U || endpoint->context.slot >= endpoint->identity.capacity ||
        !matching_attempt(endpoint, core, &attempt, &peer_epoch)) {
        return DMP_AUTHENTICATION_FAILURE;
    }
    slot = &endpoint->identity.slots[endpoint->context.slot];
    memset(&incoming, 0, sizeof incoming);
    incoming.frame = core.data;
    incoming.frame_len = core.size;
    incoming.origin_id = slot->peer.origin_id;
    incoming.destination_id = slot->local.origin_id;
    incoming.namespace_id = slot->local.namespace_id;
    incoming.context_epoch = peer_epoch;
    opened = dmp_hs_open_logical(endpoint->association, attempt, &incoming, plain, plain_cap,
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
    rx_context = endpoint->context;
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
        if (endpoint->drain_live != 0U && opened_attempt == endpoint->drain_attempt) {
            rx_context = endpoint->drain_context;
        }
    } else {
        limits = limits_of(endpoint);
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
                opened_attempt != endpoint->association_attempt ||
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
    if (view.fields.type == DMP_TYPE_FRAG_STATUS) {
        empty.data = NULL;
        empty.size = 0U;
        memset(&input, 0, sizeof input);
        input.frame = &view;
        input.service_id = service;
        input.plaintext = view.payload;
        input.immutable_metadata = empty;
        use_context(endpoint, rx_context);
        status = dmp_reliability_on_rx(&endpoint->reliability, &input, now);
        use_context(endpoint, endpoint->context);
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
        emit(endpoint, DMP_ENDPOINT_TELEMETRY, none, service, 0U, view.payload, source);
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
    use_context(endpoint, endpoint->context);
    if (status != DMP_BUSY && status != DMP_INCOMPLETE &&
        freshness_required(&endpoint->profile, service) && freshness_command(view.fields.type)) {
        dmp_message_key source;
        if (dmp_identity_source_key(&view, &endpoint->identity, rx_context, now, &source) == DMP_OK) {
            freshness_consume_key(endpoint, source, service);
        }
    }
    if (service == 0U && endpoint->prepared_grant_live != 0U) {
        if (endpoint->pending_grant_live != 0U) {
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

dmp_status dmp_endpoint_rx(dmp_endpoint *endpoint, dmp_bytes input, dmp_time_ms now)
{
    dmp_status status = DMP_OK;
    if (!ready(endpoint) || !bytes_ok(input)) {
        return DMP_INVALID_ARGUMENT;
    }
    while (input.size != 0U) {
        dmp_stream_result fed = dmp_stream_feed(&endpoint->decoder, input, now);
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
    return status;
}
