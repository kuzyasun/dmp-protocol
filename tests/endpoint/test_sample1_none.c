/* Focused production SAMPLE-1 adapter integration over two NONE endpoints.
 * Host-only loopback: this does not prove physical transport or persistence. */
#include "dmp/endpoint.h"
#include "dmp/stream.h"
#include "sample1_endpoint.h"

#include <stdio.h>
#include <string.h>

#ifndef SAMPLE_PEERS
#define SAMPLE_PEERS 1U
#endif
#ifndef SAMPLE_FRAMING_MODE
#define SAMPLE_FRAMING_MODE DMP_ENDPOINT_FRAMING_PACKET
#endif
#ifndef SAMPLE_RADIO
#define SAMPLE_RADIO 0
#endif

#define CHECK(condition)                                                          \
    do {                                                                          \
        if (!(condition)) {                                                       \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,       \
                          __LINE__, #condition);                                 \
            return 1;                                                             \
        }                                                                         \
    } while (0)

enum {
    MESSAGE_BYTES = 1024,
    CORE_MTU = 263,
    SENDERS = SAMPLE_PEERS > 4U ? SAMPLE_PEERS : 4U,
    RESULTS = SAMPLE_PEERS > 2U ? SAMPLE_PEERS * 2U : 4U,
    HISTORY = SAMPLE_PEERS > 2U ? SAMPLE_PEERS * 4U : 8U,
    CORRELATIONS = SAMPLE_PEERS > 4U ? SAMPLE_PEERS : 4U,
    ADAPTERS = SAMPLE_PEERS > 4U ? SAMPLE_PEERS + 2U : 6U,
    ASSEMBLIES = 1,
    TOMBSTONES = 16,
    QUEUE_CAPACITY = 16,
    MAX_SAMPLE_PEERS = 16
};

typedef struct node node;

typedef struct {
    dmp_tx_complete_fn complete;
    void *owner;
    dmp_tx_token token;
    const uint8_t *borrowed_data;
    size_t borrowed_size;
    uint8_t borrowed_snapshot[CORE_MTU];
    uint8_t live;
} delayed_tx_completion;

typedef struct {
    uint8_t frame[QUEUE_CAPACITY][CORE_MTU];
    size_t length[QUEUE_CAPACITY];
    uint32_t peer_slot[QUEUE_CAPACITY];
    size_t count;
    dmp_time_ms now;
    uint32_t route_peer_slot;
    uint8_t route_peer_override;
    uint32_t blocked_peer_slot;
    uint8_t block_peer;
    uint32_t delayed_peer_slot;
    uint8_t delay_peer_completion;
    delayed_tx_completion delayed;
} loopback;

typedef struct {
    uint64_t committed_epoch;
    uint64_t next_epoch;
    uint64_t published_epoch;
    uint32_t published_index;
    uint32_t published_value;
    uint8_t published_payload[DMP_SAMPLE1_TELEM_BYTES];
    uint32_t reservations;
    uint32_t publications;
    uint8_t locked;
} application_store;

struct node {
    dmp_endpoint endpoint;
    dmp_endpoint_peer_state peers[MAX_SAMPLE_PEERS];
    dmp_transport transport;
    loopback tx;
    dmp_identity_slot identities[MAX_SAMPLE_PEERS * 2];
    dmp_reliability_sender_slot senders[SENDERS];
    uint8_t sender_payload[SENDERS * MESSAGE_BYTES];
    dmp_reliability_result_slot results[RESULTS];
    uint8_t result_payload[RESULTS * MESSAGE_BYTES];
    dmp_reliability_history_slot history[HISTORY];
    dmp_reliability_correlation_slot correlations[CORRELATIONS];
    uint8_t history_metadata[HISTORY * DMP_RELIABILITY_METADATA_BYTES];
    uint8_t correlation_metadata[CORRELATIONS * DMP_RELIABILITY_METADATA_BYTES];
    dmp_reliability_adapter_slot adapters[ADAPTERS];
    uint8_t frames[ADAPTERS * CORE_MTU];
    uint8_t receive_payload[MESSAGE_BYTES];
    dmp_reassembly_slot assemblies[ASSEMBLIES * SAMPLE_PEERS];
    dmp_reassembly_tombstone tombstones[TOMBSTONES * SAMPLE_PEERS];
    uint8_t assembly_payload[ASSEMBLIES * SAMPLE_PEERS * MESSAGE_BYTES];
    uint8_t assembly_metadata[ASSEMBLIES * SAMPLE_PEERS * DMP_REASSEMBLY_METADATA_BYTES];
    uint8_t fragment_message[SAMPLE_PEERS * MESSAGE_BYTES];
    uint8_t fragment_frame[CORE_MTU];
    uint8_t telemetry_payload[SAMPLE_PEERS * MESSAGE_BYTES];
    uint8_t telemetry_next[SAMPLE_PEERS * MESSAGE_BYTES];
    uint8_t telemetry_frame[CORE_MTU];
    uint8_t stream_tx[CORE_MTU];
    uint8_t stream_rx[CORE_MTU * SAMPLE_PEERS];
    uint8_t parsed_view_storage[CORE_MTU];
    dmp_sample1_endpoint sample_endpoint;
    dmp_sample1_peer_epoch sample_peers[SAMPLE_PEERS];
    dmp_sample1_queued_result sample_results[SAMPLE_PEERS];
    application_store *store;
    uint8_t is_producer;
    uint8_t pending_read;
    dmp_endpoint_notice read_notice;
    uint8_t read_payload[1];
    uint8_t telem_count;
    uint8_t result_count;
    uint8_t last_telem[DMP_SAMPLE1_TELEM_BYTES];
    uint8_t last_result[DMP_SAMPLE1_READ_BYTES];
    uint8_t result_opcode;
    dmp_message_origin result_source;
    dmp_reliability_handle result_request;
};

static node producer;
static node consumer;
static node persistent_consumers[MAX_SAMPLE_PEERS];
static application_store store;
static uint32_t g_route_peer_slot;
static uint8_t g_persistent_consumers_active;
static uint8_t g_defer_sample_flush;
static uint8_t g_last_response_frame[CORE_MTU];
static size_t g_last_response_frame_len;
static uint32_t g_last_response_peer_slot;

static dmp_bytes span(const void *data, size_t size)
{
    dmp_bytes bytes;
    bytes.data = (const uint8_t *)data;
    bytes.size = size;
    return bytes;
}

static dmp_parse_result parse_outbound_core(const uint8_t *data, size_t size,
                                            dmp_time_ms now,
                                            dmp_frame_view *view,
                                            uint8_t view_storage[CORE_MTU])
{
    dmp_core_limits limits = {CORE_MTU, MESSAGE_BYTES, 16U};
    if (SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_PACKET) {
        return dmp_core_parse(span(data, size), &limits, view);
    }
    {
        uint8_t storage[CORE_MTU * 2U + 16U];
        uint8_t input[CORE_MTU + 1U];
        dmp_stream_decoder decoder;
        dmp_stream_config config = {DMP_STREAM_R, CORE_MTU, 1000U};
        dmp_buffer buffer = {storage, sizeof(storage)};
        dmp_stream_result fed;
        size_t consumed = 0U;
        dmp_parse_result invalid = {DMP_INVALID_ARGUMENT, 0U};
        dmp_status stream_init_status = dmp_stream_init(&decoder, config, buffer, now);
        if (size + 1U > sizeof(input) || stream_init_status != DMP_OK) {
            return invalid;
        }
        input[0] = 0U;
        (void)memcpy(input + 1U, data, size);
        while (consumed < size + 1U) {
            fed = dmp_stream_feed(&decoder,
                                  span(input + consumed, size + 1U - consumed), now);
            if (fed.status != DMP_OK || fed.consumed == 0U ||
                fed.consumed > size + 1U - consumed) {
                invalid.status = fed.status == DMP_OK ? DMP_MALFORMED : fed.status;
                return invalid;
            }
            consumed += fed.consumed;
            if (fed.event == DMP_STREAM_FRAME) {
                if (fed.frame.size > CORE_MTU) {
                    invalid.status = DMP_MALFORMED;
                    return invalid;
                }
                (void)memcpy(view_storage, fed.frame.data, fed.frame.size);
                return dmp_core_parse(span(view_storage, fed.frame.size),
                                      &limits, view);
            }
        }
        invalid.status = DMP_MALFORMED;
        return invalid;
    }
}

#if SAMPLE_PEERS > 1U
#if defined(__GNUC__)
__attribute__((noinline))
#endif
static uint8_t churn_stack(void)
{
    volatile uint8_t bytes[CORE_MTU * 2U];
    size_t i;
    for (i = 0U; i < sizeof(bytes); i++) {
        bytes[i] = (uint8_t)(i ^ 0x5aU);
    }
    return bytes[sizeof(bytes) - 1U];
}
#endif

static void store_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8U);
    out[2] = (uint8_t)(value >> 16U);
    out[3] = (uint8_t)(value >> 24U);
}

static void store_u64_le(uint8_t *out, uint64_t value)
{
    store_u32_le(out, (uint32_t)value);
    store_u32_le(out + 4U, (uint32_t)(value >> 32U));
}

static void expected_telem(uint8_t out[DMP_SAMPLE1_TELEM_BYTES], uint64_t epoch,
                           uint32_t index, uint32_t value)
{
    store_u64_le(out, epoch);
    store_u32_le(out + 8U, index);
    store_u32_le(out + 12U, value);
}

static void expected_read(uint8_t out[DMP_SAMPLE1_READ_BYTES], uint64_t epoch,
                          uint32_t index, uint32_t value)
{
    out[0] = DMP_SAMPLE1_READ_OPCODE;
    store_u64_le(out + 1U, epoch);
    store_u32_le(out + 9U, index);
    store_u32_le(out + 13U, value);
}

static void fill_none_profile(dmp_config *config, uint32_t local_id,
                              uint32_t peer_id)
{
    static const uint8_t manifest_digest[DMP_PROFILE_SHA256_BYTES] = {
        0x29U, 0xcbU, 0x7bU, 0x91U, 0xeeU, 0x0cU, 0x26U, 0x9bU,
        0xc1U, 0x4aU, 0xc4U, 0x3eU, 0x3aU, 0x7cU, 0x8fU, 0xd8U,
        0xbdU, 0xcfU, 0xe1U, 0x1eU, 0x9eU, 0x05U, 0x2eU, 0x8bU,
        0xd9U, 0xe6U, 0xafU, 0x00U, 0xfbU, 0x89U, 0xc3U, 0xbfU
    };
    (void)memset(config, 0, sizeof(*config));
    (void)memcpy(config->sha256, manifest_digest, sizeof(manifest_digest));
    config->namespace_id = 1U;
    config->node_id[0] = local_id;
    config->node_id[1] = peer_id;
    config->default_service = 1U;
    config->security_mode = DMP_PROFILE_SECURITY_NONE;
    config->service_id[0] = 1U;
    config->service_id[1] = 2U;
#if SAMPLE_RADIO
    config->recovery[0] = DMP_PROFILE_RECOVERY_SELECTIVE32;
    config->recovery[1] = DMP_PROFILE_RECOVERY_SELECTIVE32;
    config->origin_route = 1U;
#else
    config->recovery[0] = DMP_PROFILE_RECOVERY_RETRY_ALL;
    config->recovery[1] = DMP_PROFILE_RECOVERY_RETRY_ALL;
#endif
    config->peers = SAMPLE_PEERS;
    config->operations_per_service = 1U;
    config->assemblies_per_peer = 1U;
    config->assembly_tombstones_per_peer = TOMBSTONES;
    config->sender_slots = SENDERS;
    config->assembly_slots = ASSEMBLIES * SAMPLE_PEERS;
    config->assembly_tombstone_slots = TOMBSTONES * SAMPLE_PEERS;
    config->result_slots = RESULTS;
    config->history_slots = HISTORY;
    config->correlation_slots = CORRELATIONS;
    config->adapter_slots = ADAPTERS;
    config->application_queue_slots = 2U;
    config->control_slots = 2U;
    config->message_bytes = MESSAGE_BYTES;
    config->fragments = 16U;
    config->chunk_bytes = 64U;
    config->encoded_mtu = CORE_MTU;
    config->frame_tx_ms = 1U;
    config->forward_mtu = 256U;
    config->return_mtu = 256U;
    config->queue_ms = 64U;
    config->response_timeout_ms = 1280U;
    config->send_horizon_ms = 5632U;
    config->max_bursts = 3U;
#if SAMPLE_RADIO
    config->forward_delay_ms = 20U;
    config->return_delay_ms = 20U;
    config->record_margin_ms = 5U;
    config->burst_span_ms = 1U;
    config->feedback_guard_ms = 1U;
    config->feedback_delay_ms = 1U;
    config->max_probes = 1U;
    config->max_status = 1U;
    config->receipt_delay_ms = 110U;
    config->receipt_limit = 3U;
    config->dedup_ms = 6000U;
    config->rejection_ms = 6000U;
    config->result_cache_ms = 6000U;
    config->result_deadline_ms = 12000U;
    config->correlation_ms = 12288U;
    config->tombstone_ms = 12288U;
    config->late_result_ms = 64U;
    config->collect_ms = 5652U;
    config->assembly_ms = 5657U;
#endif
    config->receipt_delay_ms = 110U;
    config->receipt_limit = 3U;
    config->dedup_ms = 6000U;
    config->rejection_ms = 6000U;
    config->result_cache_ms = 6000U;
    config->result_deadline_ms = 12000U;
    config->correlation_ms = 12288U;
    config->tombstone_ms = 12288U;
    config->late_result_ms = 64U;
    config->collect_ms = 5652U;
    config->assembly_ms = 5657U;
    config->forward_delay_ms = 20U;
    config->return_delay_ms = 20U;
    config->record_margin_ms = 5U;
    config->tx_borrow = true;
    config->synchronous_completion = true;
}

static dmp_status tx_submit(void *context, const dmp_tx_submission *submission)
{
    loopback *wire = (loopback *)context;
    uint32_t peer_slot;
    if (wire == NULL || submission == NULL || submission->frame.data == NULL ||
        submission->complete == NULL || submission->frame.size > CORE_MTU ||
        wire->count >= QUEUE_CAPACITY) {
        return DMP_BUSY;
    }
    if (wire->block_peer != 0U &&
        (wire->route_peer_override != 0U ? wire->route_peer_slot
                                         : submission->peer.slot) ==
            wire->blocked_peer_slot) {
        return DMP_BUSY;
    }
    peer_slot = wire->route_peer_override != 0U ? wire->route_peer_slot
                                                : submission->peer.slot;
    if (wire->delay_peer_completion != 0U &&
        peer_slot == wire->delayed_peer_slot && wire->delayed.live != 0U) {
        return DMP_BUSY;
    }
    (void)memcpy(wire->frame[wire->count], submission->frame.data,
                 submission->frame.size);
    wire->length[wire->count] = submission->frame.size;
    wire->peer_slot[wire->count] = peer_slot;
    wire->count++;
    if (wire->delay_peer_completion != 0U &&
        peer_slot == wire->delayed_peer_slot) {
        wire->delayed.complete = submission->complete;
        wire->delayed.owner = submission->owner;
        wire->delayed.token = submission->token;
        wire->delayed.borrowed_data = submission->frame.data;
        wire->delayed.borrowed_size = submission->frame.size;
        (void)memcpy(wire->delayed.borrowed_snapshot, submission->frame.data,
                     submission->frame.size);
        wire->delayed.live = 1U;
        wire->delay_peer_completion = 0U;
        return DMP_OK;
    }
    submission->complete(submission->owner, submission->token,
                         DMP_TX_TRANSMITTED, wire->now);
    return DMP_OK;
}

#if SAMPLE_PEERS > 1U
static int complete_delayed_tx(node *self, dmp_time_ms now)
{
    delayed_tx_completion completion;
    if (self == NULL || self->tx.delayed.live == 0U) {
        return -1;
    }
    completion = self->tx.delayed;
    (void)memset(&self->tx.delayed, 0, sizeof(self->tx.delayed));
    completion.complete(completion.owner, completion.token,
                        DMP_TX_TRANSMITTED, now);
    return 0;
}
#endif

static dmp_status tx_cancel(void *context, dmp_tx_token token)
{
    (void)context;
    (void)token;
    return DMP_OK;
}

static void on_notice(void *user, const dmp_endpoint_notice *notice)
{
    node *self = (node *)user;
    if (notice->event == DMP_ENDPOINT_REQUEST && self->is_producer != 0U &&
        notice->service_id == 1U && notice->payload.size == 1U &&
        notice->payload.data != NULL &&
        (notice->payload.data[0] == DMP_SAMPLE1_READ_OPCODE ||
         notice->payload.data[0] == DMP_SAMPLE1_STATUS_OPCODE)) {
        self->read_notice = *notice;
        self->read_payload[0] = notice->payload.data[0];
        self->read_notice.payload.data = self->read_payload;
        self->pending_read = 1U;
    } else if (notice->event == DMP_ENDPOINT_TELEMETRY && self->is_producer == 0U &&
               notice->service_id == 1U &&
               notice->payload.size == DMP_SAMPLE1_TELEM_BYTES) {
        (void)memcpy(self->last_telem, notice->payload.data, sizeof(self->last_telem));
        self->telem_count++;
    } else if (notice->event == DMP_ENDPOINT_RESULT && self->is_producer == 0U &&
               notice->service_id == 1U && notice->wire_status == 0U &&
               ((notice->payload.size == DMP_SAMPLE1_READ_BYTES &&
                 notice->payload.data[0] == DMP_SAMPLE1_READ_OPCODE) ||
                (notice->payload.size == DMP_SAMPLE1_STATUS_BYTES &&
                 notice->payload.data[0] == DMP_SAMPLE1_STATUS_OPCODE))) {
        self->result_opcode = notice->payload.data[0];
        (void)memcpy(self->last_result, notice->payload.data, notice->payload.size);
        self->result_source = notice->source.origin;
        self->result_request = notice->request;
        self->result_count++;
    } else if (notice->event == DMP_ENDPOINT_RESULT && self->is_producer == 0U) {
        (void)fprintf(stderr,
                      "unexpected SAMPLE-1 result: service=%u status=%u payload=%zu\n",
                      (unsigned)notice->service_id, (unsigned)notice->wire_status,
                      notice->payload.size);
    }
}

#if SAMPLE_PEERS > 1U
static uint32_t live_senders_for_peer(const node *self, dmp_peer_handle peer)
{
    uint32_t count = 0U;
    uint32_t i;
    for (i = 0U; i < SENDERS; i++) {
        const dmp_reliability_sender_slot *sender = &self->senders[i];
        if (sender->live != 0U && sender->peer.slot == peer.slot &&
            sender->peer.generation == peer.generation) {
            count++;
        }
    }
    return count;
}
#endif

static bool hook_try_enter(void *user)
{
    application_store *state = (application_store *)user;
    if (state->locked != 0U) {
        return false;
    }
    state->locked = 1U;
    return true;
}

static void hook_leave(void *user)
{
    application_store *state = (application_store *)user;
    state->locked = 0U;
}

static dmp_sample1_port_result hook_reserve(void *user, dmp_sample1_principal principal,
                                           bool *has_previous, uint64_t *previous_epoch,
                                           uint64_t *reserved_epoch)
{
    application_store *state = (application_store *)user;
    (void)principal;
    if (state == NULL || has_previous == NULL || previous_epoch == NULL ||
        reserved_epoch == NULL || state->next_epoch == UINT64_MAX) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    *has_previous = state->committed_epoch != 0U;
    *previous_epoch = state->committed_epoch;
    *reserved_epoch = ++state->next_epoch;
    state->committed_epoch = *reserved_epoch;
    state->reservations++;
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static dmp_sample1_port_result hook_publish(void *user, dmp_sample1_principal principal,
                                           uint64_t sample_epoch, uint32_t sample_index,
                                           const uint8_t payload[DMP_SAMPLE1_TELEM_BYTES])
{
    application_store *state = (application_store *)user;
    (void)principal;
    if (state == NULL || payload == NULL || sample_epoch != state->committed_epoch ||
        sample_index == 0U) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    state->published_epoch = sample_epoch;
    state->published_index = sample_index;
    state->published_value = (uint32_t)payload[12] |
                             ((uint32_t)payload[13] << 8U) |
                             ((uint32_t)payload[14] << 16U) |
                             ((uint32_t)payload[15] << 24U);
    (void)memcpy(state->published_payload, payload, DMP_SAMPLE1_TELEM_BYTES);
    state->publications++;
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static void fill_storage(node *self, dmp_endpoint_storage *storage,
                         const dmp_admitted_profile *profile, uint32_t local_id,
                         uint32_t peer_id, uint64_t local_epoch, uint64_t peer_epoch)
{
    (void)memset(storage, 0, sizeof(*storage));
    storage->profile = profile;
    storage->framing_mode = SAMPLE_FRAMING_MODE;
    storage->peer_states = self->peers;
    storage->peer_state_capacity = SAMPLE_PEERS;
    storage->identity_slots = self->identities;
    storage->identity_capacity = SAMPLE_PEERS * 2U;
    storage->context.local.namespace_id = 1U;
    storage->context.local.origin_id = local_id;
    storage->context.local.epoch = local_epoch;
    storage->context.peer.namespace_id = 1U;
    storage->context.peer.origin_id = peer_id;
    storage->context.peer.epoch = peer_epoch;
    storage->context.security = 0U;
    storage->transport = &self->transport;
    storage->notice = on_notice;
    storage->notice_user = self;
    storage->senders = self->senders;
    storage->sender_capacity = SENDERS;
    storage->sender_payload = self->sender_payload;
    storage->sender_payload_capacity = sizeof(self->sender_payload);
    storage->results = self->results;
    storage->result_capacity = RESULTS;
    storage->result_payload = self->result_payload;
    storage->result_payload_capacity = sizeof(self->result_payload);
    storage->history = self->history;
    storage->history_capacity = HISTORY;
    storage->correlations = self->correlations;
    storage->correlation_capacity = CORRELATIONS;
    storage->history_metadata = self->history_metadata;
    storage->history_metadata_capacity = sizeof(self->history_metadata);
    storage->correlation_metadata = self->correlation_metadata;
    storage->correlation_metadata_capacity = sizeof(self->correlation_metadata);
    storage->adapters = self->adapters;
    storage->adapter_capacity = ADAPTERS;
    storage->frames = self->frames;
    storage->frame_capacity = sizeof(self->frames);
    storage->receive_payload = self->receive_payload;
    storage->receive_payload_capacity = sizeof(self->receive_payload);
    storage->assemblies = self->assemblies;
    storage->assembly_capacity = ASSEMBLIES * SAMPLE_PEERS;
    storage->tombstones = self->tombstones;
    storage->tombstone_capacity = TOMBSTONES * SAMPLE_PEERS;
    storage->assembly_payload = self->assembly_payload;
    storage->assembly_payload_capacity = sizeof(self->assembly_payload);
    storage->assembly_metadata = self->assembly_metadata;
    storage->assembly_metadata_capacity = sizeof(self->assembly_metadata);
    storage->fragment_message = self->fragment_message;
    storage->fragment_message_capacity = sizeof(self->fragment_message);
    storage->fragment_frame = self->fragment_frame;
    storage->fragment_frame_capacity = sizeof(self->fragment_frame);
    storage->telemetry_payload = self->telemetry_payload;
    storage->telemetry_payload_capacity = sizeof(self->telemetry_payload);
    storage->telemetry_next = self->telemetry_next;
    storage->telemetry_next_capacity = sizeof(self->telemetry_next);
    storage->telemetry_frame = self->telemetry_frame;
    storage->telemetry_frame_capacity = sizeof(self->telemetry_frame);
    if (SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_STREAM_R) {
        storage->stream_tx = self->stream_tx;
        storage->stream_tx_capacity = sizeof(self->stream_tx);
        storage->stream_rx = self->stream_rx;
        storage->stream_rx_capacity = sizeof(self->stream_rx);
    }
}

static int init_node(node *self, application_store *app_store, bool is_producer,
                     uint32_t local_id, uint32_t peer_id,
                     uint64_t local_epoch, uint64_t peer_epoch, dmp_time_ms now)
{
    dmp_config input;
    dmp_admitted_profile admitted;
    dmp_endpoint_storage storage;
    (void)memset(self, 0, sizeof(*self));
    self->store = app_store;
    self->is_producer = is_producer ? 1U : 0U;
    self->tx.now = now;
    self->transport.context = &self->tx;
    self->transport.submit = tx_submit;
    self->transport.cancel = tx_cancel;
    self->transport.caps.max_frame_bytes = CORE_MTU;
    self->transport.caps.ownership = DMP_TX_BORROW;
    self->transport.caps.synchronous_completion = true;
    fill_none_profile(&input, local_id, peer_id);
    if (!is_producer && SAMPLE_PEERS > 1U) {
        input.peers = 1U;
    }
    {
        dmp_status status = dmp_config_admit(&input, &admitted);
        if (status != DMP_OK) {
            (void)fprintf(stderr, "NONE SAMPLE test config admission failed: %u peers=%u\n",
                          (unsigned)status, (unsigned)input.peers);
            return 1;
        }
    }
    fill_storage(self, &storage, &admitted, local_id, peer_id, local_epoch,
                 peer_epoch);
    {
        dmp_status status = dmp_endpoint_init(&self->endpoint, &storage, now);
        if (status != DMP_OK) {
            (void)fprintf(stderr, "NONE SAMPLE endpoint init failed: %u peers=%u\n",
                          (unsigned)status, (unsigned)SAMPLE_PEERS);
        }
        return status == DMP_OK ? 0 : 1;
    }
}

static int init_sample_endpoint(node *self)
{
    dmp_sample1_endpoint_hooks hooks;
    dmp_sample1_principal principal;
    principal.namespace_id = 1U;
    principal.origin_id = 10U;
    (void)memset(&hooks, 0, sizeof(hooks));
    hooks.user = self->store;
    hooks.try_enter = hook_try_enter;
    hooks.leave = hook_leave;
    hooks.reserve_next = hook_reserve;
    hooks.publish_telem = hook_publish;
    if (SAMPLE_PEERS > DMP_SAMPLE1_ENDPOINT_RESULT_SLOTS &&
        dmp_sample1_endpoint_init_with_peer_storage(
            &self->sample_endpoint, &self->endpoint, principal, &hooks,
            self->sample_peers, SAMPLE_PEERS) != DMP_SAMPLE1_OWNER_INVALID) {
        return 1;
    }
    return dmp_sample1_endpoint_init_with_storage(
               &self->sample_endpoint, &self->endpoint, principal, &hooks,
               self->sample_peers, SAMPLE_PEERS, self->sample_results,
               SAMPLE_PEERS) == DMP_SAMPLE1_OWNER_OK
               ? 0
               : 1;
}

static int replace_node_context(node *self, uint64_t local_epoch,
                               uint64_t peer_epoch, dmp_time_ms now)
{
    dmp_identity_context_config context;
    dmp_peer_handle old_peer = {0U, 1U};
    dmp_peer_handle new_peer;
    dmp_status status;
    uint32_t local_id = self->is_producer != 0U ? 10U : 20U;
    uint32_t peer_id = self->is_producer != 0U ? 20U : 10U;

    (void)memset(&context, 0, sizeof(context));
    context.local.namespace_id = 1U;
    context.local.origin_id = local_id;
    context.local.epoch = local_epoch;
    context.peer.namespace_id = 1U;
    context.peer.origin_id = peer_id;
    context.peer.epoch = peer_epoch;
    context.security = 0U;
    {
        dmp_identity_context_config invalid = context;
        invalid.local.origin_id++;
        status = dmp_endpoint_replace_none_peer_context(
            &self->endpoint, old_peer, &invalid, now, &new_peer);
        if (status != DMP_INVALID_ARGUMENT ||
            self->endpoint.peers[old_peer.slot].live == 0U ||
            self->endpoint.peers[old_peer.slot].handle.generation !=
                old_peer.generation) {
            (void)fprintf(stderr,
                          "invalid replacement changed live peer: status=%u live=%u generation=%llu\n",
                          (unsigned)status,
                          (unsigned)self->endpoint.peers[old_peer.slot].live,
                          (unsigned long long)self->endpoint.peers[old_peer.slot]
                              .handle.generation);
            return 1;
        }
    }
    status = dmp_endpoint_replace_none_peer_context(&self->endpoint, old_peer,
                                                    &context, now, &new_peer);
    if (status != DMP_OK) {
        (void)fprintf(stderr,
                      "NONE context replacement failed: %u live=%u count=%u tx0=%u identity=%u retained=%u\n",
                      (unsigned)status, (unsigned)self->endpoint.peers[0].live,
                      (unsigned)self->endpoint.peer_count,
                      (unsigned)self->endpoint.tx[0].live,
                      (unsigned)self->identities[0].state,
                      (unsigned)self->identities[0].retained);
        return 1;
    }
    if (new_peer.slot != old_peer.slot ||
        new_peer.generation != old_peer.generation + 1U) {
        (void)fprintf(stderr, "NONE peer generation changed unexpectedly: slot=%u generation=%llu\n",
                      (unsigned)new_peer.slot,
                      (unsigned long long)new_peer.generation);
        return 1;
    }
    (void)memset(&self->sample_endpoint, 0, sizeof(self->sample_endpoint));
    (void)memset(self->sample_peers, 0, sizeof(self->sample_peers));
    self->pending_read = 0U;
    self->telem_count = 0U;
    self->result_count = 0U;
    return self->is_producer != 0U ? init_sample_endpoint(self) : 0;
}

static int process_sample_notice(node *self, dmp_time_ms now)
{
    if (self->pending_read == 0U) {
        return 0;
    }
    self->pending_read = 0U;
    if (dmp_sample1_endpoint_handle_notice(&self->sample_endpoint,
                                           &self->read_notice, now) !=
        DMP_SAMPLE1_OWNER_OK) {
        return -1;
    }
    if (g_defer_sample_flush == 0U &&
        dmp_sample1_endpoint_flush(&self->sample_endpoint, now) !=
            DMP_SAMPLE1_OWNER_OK) {
        return -1;
    }
    return 1;
}

static int deliver(node *from, node *to, dmp_time_ms now)
{
    size_t i;
    size_t count = from->tx.count;
    size_t retained = 0U;
    int sample_work = 0;
    for (i = 0U; i < count; i++) {
        uint32_t route_slot = from->tx.peer_slot[i];
        dmp_peer_handle receive_peer;
        if (route_slot != g_route_peer_slot) {
            if (retained != i) {
                (void)memcpy(from->tx.frame[retained], from->tx.frame[i],
                             from->tx.length[i]);
                from->tx.length[retained] = from->tx.length[i];
                from->tx.peer_slot[retained] = route_slot;
            }
            retained++;
            continue;
        }
        if (from == &producer) {
            dmp_frame_view view;
            dmp_parse_result parsed = parse_outbound_core(
                from->tx.frame[i], from->tx.length[i], now, &view,
                from->parsed_view_storage);
            if (parsed.status == DMP_OK && view.fields.type == DMP_TYPE_RSP) {
                (void)memcpy(g_last_response_frame, from->tx.frame[i],
                             from->tx.length[i]);
                g_last_response_frame_len = from->tx.length[i];
                g_last_response_peer_slot = route_slot;
            }
        }
        node *recipient = to;
        if (to == &consumer && g_persistent_consumers_active != 0U) {
            if (route_slot >= SAMPLE_PEERS) {
                return -1;
            }
            recipient = &persistent_consumers[route_slot];
        }
        receive_peer = recipient == &producer
                           ? recipient->endpoint.peers[route_slot].handle
                           : recipient->endpoint.peers[0].handle;
        dmp_status status = SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_STREAM_R
                                ? dmp_endpoint_rx_from(
                                      &recipient->endpoint, receive_peer,
                                      span(from->tx.frame[i], from->tx.length[i]), now)
                                : dmp_endpoint_rx_packet_from(
                                      &recipient->endpoint, receive_peer,
                                      span(from->tx.frame[i], from->tx.length[i]), now);
        int processed;
        if (status != DMP_OK && status != DMP_DUPLICATE &&
            status != DMP_INCOMPLETE) {
            dmp_core_limits limits = {CORE_MTU, MESSAGE_BYTES, 16U};
            dmp_frame_view view;
            dmp_parse_result parsed = dmp_core_parse(
                span(from->tx.frame[i], from->tx.length[i]), &limits, &view);
            (void)fprintf(stderr,
                          "packet RX rejected frame %zu status=%u parse=%u type=%u seq=%u opts=%u tx_count=%zu peer_gen=%llu context=%u/%llu\n",
                          i, (unsigned)status, (unsigned)parsed.status,
                          (unsigned)view.fields.type, (unsigned)view.fields.seq,
                          (unsigned)view.fields.options, count,
                          (unsigned long long)receive_peer.generation,
                          (unsigned)recipient->endpoint.peers[receive_peer.slot].context.slot,
                          (unsigned long long)recipient->endpoint.peers[receive_peer.slot].context.generation);
            for (size_t j = 0U; j < from->tx.length[i]; j++) {
                (void)fprintf(stderr, "%02x", (unsigned)from->tx.frame[i][j]);
            }
            (void)fprintf(stderr, "\n");
            return -1;
        }
        processed = process_sample_notice(recipient, now);
        if (processed < 0) {
            return -1;
        }
        if (processed > 0) {
            sample_work = 1;
        }
    }
    from->tx.count = retained;
    return sample_work;
}

#if SAMPLE_PEERS > 1U
static int collect_sample_responses(dmp_time_ms now, uint32_t expected_responses,
                                    uint8_t response_frames[MAX_SAMPLE_PEERS][CORE_MTU],
                                    size_t response_lengths[MAX_SAMPLE_PEERS])
{
    uint8_t seen[MAX_SAMPLE_PEERS] = {0U};
    uint32_t received = 0U;
    uint32_t attempt;
    for (attempt = 0U; attempt < SAMPLE_PEERS * 4U &&
                       received < expected_responses; attempt++) {
        size_t i;
        producer.tx.now = now;
        if (dmp_endpoint_poll(&producer.endpoint, now) != DMP_OK) {
            return -1;
        }
        for (i = 0U; i < producer.tx.count; i++) {
            uint32_t peer = producer.tx.peer_slot[i];
            dmp_frame_view view;
            if (peer >= SAMPLE_PEERS ||
                parse_outbound_core(producer.tx.frame[i], producer.tx.length[i],
                                    now, &view,
                                    producer.parsed_view_storage).status != DMP_OK) {
                return -1;
            }
            if (view.fields.type == DMP_TYPE_ACK) {
                dmp_peer_handle destination =
                    persistent_consumers[peer].endpoint.peers[0].handle;
                dmp_status status = dmp_endpoint_rx_packet_from(
                    &persistent_consumers[peer].endpoint, destination,
                    span(producer.tx.frame[i], producer.tx.length[i]), now);
                if (status != DMP_OK && status != DMP_DUPLICATE) {
                    return -1;
                }
            } else if (view.fields.type == DMP_TYPE_RSP) {
                if (seen[peer] != 0U) {
                    return -1;
                }
                seen[peer] = 1U;
                response_lengths[peer] = producer.tx.length[i];
                (void)memcpy(response_frames[peer], producer.tx.frame[i],
                             response_lengths[peer]);
                received++;
            } else {
                (void)fprintf(stderr, "unexpected sample frame peer=%u type=%u received=%u/%u\n",
                              peer, (unsigned)view.fields.type, received,
                              expected_responses);
                return -1;
            }
        }
        producer.tx.count = 0U;
    }
    /* Polling is bounded by four calls per provisioned peer. The blocked
     * peer's work stays pending and can progress when that transport accepts. */
    if (received != expected_responses) {
        (void)fprintf(stderr, "sample drain incomplete: responses=%u/%u\n",
                      received, expected_responses);
        return -1;
    }
    return 0;
}
#endif

static int pump(dmp_time_ms now)
{
    unsigned round;
    for (round = 0U; round < 32U; round++) {
        int sample_work = 0;
        int delivered;
        producer.tx.now = now;
        consumer.tx.now = now;
        if (dmp_endpoint_poll(&producer.endpoint, now) != DMP_OK ||
            dmp_endpoint_poll(&consumer.endpoint, now) != DMP_OK) {
            return 1;
        }
        delivered = deliver(&producer, &consumer, now);
        if (delivered < 0) {
            return 1;
        }
        sample_work |= delivered;
        delivered = deliver(&consumer, &producer, now);
        if (delivered < 0) {
            return 1;
        }
        sample_work |= delivered;
        {
            size_t pending_for_route = 0U;
            size_t index;
            for (index = 0U; index < producer.tx.count; index++) {
                pending_for_route += producer.tx.peer_slot[index] == g_route_peer_slot;
            }
            if (pending_for_route == 0U && consumer.tx.count == 0U &&
            producer.pending_read == 0U) {
                if (sample_work == 0) {
                    return 0;
                }
            }
        }
    }
    return 1;
}

#if SAMPLE_PEERS > 1U
static int pump_sample_peer(dmp_time_ms now, uint32_t peer_slot,
                            uint8_t prior_result_count)
{
    unsigned round;
    for (round = 0U; round < 64U; round++) {
        int delivered;
        producer.tx.now = now;
        consumer.tx.now = now;
        producer.endpoint.poll_peer_cursor = peer_slot;
        if (dmp_endpoint_poll(&producer.endpoint, now) != DMP_OK ||
            dmp_endpoint_poll(&consumer.endpoint, now) != DMP_OK) {
            return 1;
        }
        delivered = deliver(&producer, &consumer, now);
        if (delivered < 0) {
            return 1;
        }
        delivered = deliver(&consumer, &producer, now);
        if (delivered < 0) {
            return 1;
        }
        if (consumer.result_count > prior_result_count) {
            return 0;
        }
    }
    return 1;
}
#endif

#if SAMPLE_PEERS > 1U
static int run_multi_peer_round_trips(void)
{
    const dmp_time_ms now = 100U;
    const uint64_t producer_epoch = 0x501U;
    const uint64_t consumer_epoch = 0x601U;
    const uint64_t sample_epoch = 700U;
    dmp_peer_handle handles[MAX_SAMPLE_PEERS];
    dmp_identity_context_config context;
    uint8_t status_request[1] = {DMP_SAMPLE1_STATUS_OPCODE};
    uint8_t read_request[1] = {DMP_SAMPLE1_READ_OPCODE};
    uint8_t expected[DMP_SAMPLE1_READ_BYTES];
    uint8_t duplicate_status_frame[CORE_MTU];
    size_t duplicate_status_frame_len = 0U;
    uint32_t first_status_seq = UINT32_MAX;
    uint32_t first_read_seq = UINT32_MAX;
    uint32_t i;

    (void)memset(&store, 0, sizeof(store));
    store.next_epoch = sample_epoch - 1U;
    CHECK(init_node(&producer, &store, true, 10U, 20U,
                    producer_epoch, consumer_epoch, now) == 0);
    handles[0] = producer.endpoint.peers[0].handle;
    for (i = 1U; i < SAMPLE_PEERS; i++) {
        (void)memset(&context, 0, sizeof(context));
        context.local.namespace_id = 1U;
        context.local.origin_id = 10U;
        context.local.epoch = producer_epoch;
        context.peer.namespace_id = 1U;
        context.peer.origin_id = 20U + i;
        context.peer.epoch = consumer_epoch;
        context.security = 0U;
        CHECK(dmp_endpoint_add_peer(&producer.endpoint, &context, now,
                                    &handles[i]) == DMP_OK);
    }
    CHECK(producer.endpoint.peer_count == SAMPLE_PEERS);
    CHECK(init_sample_endpoint(&producer) == 0);
    CHECK(dmp_sample1_endpoint_begin_epoch(&producer.sample_endpoint, now) ==
          DMP_SAMPLE1_OWNER_OK);
    for (i = 0U; i < SAMPLE_PEERS; i++) {
        uint32_t j;
        CHECK(dmp_sample1_endpoint_activate_peer(&producer.sample_endpoint,
                                                  handles[i]) ==
              DMP_SAMPLE1_OWNER_OK);
        CHECK(producer.sample_peers[i].live != 0U);
        CHECK(producer.sample_peers[i].peer.slot == handles[i].slot);
        CHECK(producer.sample_peers[i].peer.generation == handles[i].generation);
        for (j = 0U; j < i; j++) {
            CHECK(handles[i].slot != handles[j].slot ||
                  handles[i].generation != handles[j].generation);
        }
    }
    CHECK(dmp_sample1_endpoint_publish(&producer.sample_endpoint, 0xabcU, now) ==
          DMP_SAMPLE1_OWNER_OK);
    for (i = 0U; i < SAMPLE_PEERS; i++) {
        CHECK(dmp_endpoint_poll(&producer.endpoint, now) == DMP_OK);
    }
    CHECK(producer.tx.count == SAMPLE_PEERS);
    for (i = 0U; i < SAMPLE_PEERS; i++) {
        if (SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_STREAM_R) {
            /* Each independent peer must establish its own stream decoder
             * before any Core frame is encoded for that route. */
            CHECK(producer.tx.length[i] == 1U);
            CHECK(producer.tx.frame[i][0] == 0U);
            continue;
        }
        dmp_frame_view telem_view;
        dmp_parse_result parsed = parse_outbound_core(
            producer.tx.frame[i], producer.tx.length[i], now, &telem_view,
            producer.parsed_view_storage);
        CHECK(parsed.status == DMP_OK);
        CHECK(telem_view.fields.type == DMP_TYPE_TELEM);
        CHECK((telem_view.fields.options & DMP_OPT_INTEGRITY) != 0U);
#if SAMPLE_RADIO
        CHECK((telem_view.fields.options & DMP_OPT_ROUTE) != 0U);
        CHECK(telem_view.fields.route.mode == 1U);
        CHECK(telem_view.fields.route.source == 10U);
        CHECK(telem_view.fields.route.destination == 20U + i);
#else
        CHECK((telem_view.fields.options & DMP_OPT_ROUTE) == 0U);
#endif
    }

    for (i = 0U; i < SAMPLE_PEERS; i++) {
        dmp_reliability_handle request;
        dmp_frame_view request_view;
        dmp_parse_result parsed;
        uint8_t completed_status_response[CORE_MTU];
        size_t completed_status_response_len;
        uint32_t local_id = 20U + i;
        g_route_peer_slot = i;
        CHECK(init_node(&consumer, &store, false, local_id, 10U,
                        consumer_epoch, producer_epoch, now) == 0);
        consumer.tx.route_peer_override = 1U;
        consumer.tx.route_peer_slot = i;
        CHECK(consumer.endpoint.peer_count == 1U);
        if (SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_STREAM_R) {
            /* Drain the producer's per-peer open delimiter and establish the
             * independent reverse decoder before issuing app traffic. */
            CHECK(deliver(&producer, &consumer, now) == 0);
            CHECK(dmp_endpoint_poll(&consumer.endpoint, now) == DMP_OK);
            CHECK(consumer.tx.count == 1U);
            CHECK(consumer.tx.length[0] == 1U && consumer.tx.frame[0][0] == 0U);
            CHECK(deliver(&consumer, &producer, now) == 0);
            CHECK(consumer.tx.count == 0U);
        }
        CHECK(dmp_endpoint_submit_req_to(
                  &consumer.endpoint, consumer.endpoint.peers[0].handle, 1U,
                  span(status_request, sizeof(status_request)), now + 1U,
                  &request) == DMP_OK);
        CHECK(dmp_endpoint_poll(&consumer.endpoint, now + 1U) == DMP_OK);
        CHECK(consumer.tx.count == 1U);
        parsed = parse_outbound_core(consumer.tx.frame[0],
                                     consumer.tx.length[0], now + 1U,
                                     &request_view,
                                     consumer.parsed_view_storage);
        CHECK(parsed.status == DMP_OK);
        CHECK(request_view.fields.type == DMP_TYPE_REQ);
#if SAMPLE_RADIO
        CHECK((request_view.fields.options & DMP_OPT_ROUTE) != 0U);
        CHECK(request_view.fields.route.mode == 1U);
        CHECK(request_view.fields.route.source == local_id);
        CHECK(request_view.fields.route.destination == 10U);
#else
        CHECK((request_view.fields.options & DMP_OPT_ROUTE) == 0U);
#endif
        if (i == 0U) {
            first_status_seq = request_view.fields.seq;
            duplicate_status_frame_len = consumer.tx.length[0];
            (void)memcpy(duplicate_status_frame, consumer.tx.frame[0],
                         duplicate_status_frame_len);
        } else {
            /* Distinct peer identities intentionally reuse the same wire
             * SEQ; their request/result histories must remain independent. */
            CHECK(request_view.fields.seq == first_status_seq);
        }
        if (SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_STREAM_R) {
            producer.endpoint.poll_peer_cursor = i;
        }
        if (SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_STREAM_R) {
            CHECK(pump_sample_peer(now + 1U, i, 0U) == 0);
        } else {
            CHECK(pump(now + 1U) == 0);
        }
        CHECK(consumer.telem_count == 1U);
        CHECK(consumer.result_count == 1U);
        CHECK(consumer.result_opcode == DMP_SAMPLE1_STATUS_OPCODE);
        CHECK(consumer.last_result[0] == DMP_SAMPLE1_STATUS_OPCODE);
        CHECK(consumer.last_result[1] == 1U);
        CHECK(consumer.result_source.namespace_id == 1U);
        CHECK(consumer.result_source.origin_id == 10U);
        CHECK(consumer.result_source.epoch == producer_epoch);
        CHECK(consumer.result_request.peer.slot == request.peer.slot);
        CHECK(consumer.result_request.peer.generation == request.peer.generation);
        CHECK(consumer.result_request.slot == request.slot);
        CHECK(g_last_response_frame_len != 0U);
        CHECK(g_last_response_peer_slot == i);
        completed_status_response_len = g_last_response_frame_len;
        (void)memcpy(completed_status_response, g_last_response_frame,
                     completed_status_response_len);

        /* Replaying the captured, completed STATUS RSP must not deliver a
         * second application result. */
        {
            dmp_status replay_status = SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_STREAM_R
                ? dmp_endpoint_rx_from(&consumer.endpoint,
                      consumer.endpoint.peers[0].handle,
                      span(completed_status_response,
                           completed_status_response_len), now + 2U)
                : dmp_endpoint_rx_packet_from(
                &consumer.endpoint, consumer.endpoint.peers[0].handle,
                span(completed_status_response,
                     completed_status_response_len),
                now + 2U);
            CHECK(replay_status == DMP_OK || replay_status == DMP_DUPLICATE);
            CHECK(consumer.result_count == 1U);
            CHECK(consumer.result_opcode == DMP_SAMPLE1_STATUS_OPCODE);
        }

        if (i == 0U) {
            dmp_status duplicate_status;
            duplicate_status = SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_STREAM_R
                ? dmp_endpoint_rx_from(&producer.endpoint, handles[i],
                      span(duplicate_status_frame, duplicate_status_frame_len), now + 2U)
                : dmp_endpoint_rx_packet_from(
                &producer.endpoint, handles[i],
                span(duplicate_status_frame, duplicate_status_frame_len),
                now + 2U);
            CHECK(duplicate_status == DMP_OK ||
                  duplicate_status == DMP_DUPLICATE);
            CHECK(producer.pending_read == 0U);
            CHECK(deliver(&producer, &consumer, now + 2U) >= 0);
            CHECK(consumer.result_count == 1U);
        }
        CHECK(deliver(&consumer, &producer, now + 2U) >= 0);

        consumer.result_count = 0U;
        CHECK(dmp_endpoint_submit_req_to(
                  &consumer.endpoint, consumer.endpoint.peers[0].handle, 1U,
                  span(read_request, sizeof(read_request)), now + 2U,
                  &request) == DMP_OK);
        CHECK(dmp_endpoint_poll(&consumer.endpoint, now + 2U) == DMP_OK);
        CHECK(consumer.tx.count == 1U);
        parsed = parse_outbound_core(consumer.tx.frame[0],
                                     consumer.tx.length[0], now + 2U,
                                     &request_view,
                                     consumer.parsed_view_storage);
        CHECK(parsed.status == DMP_OK);
        CHECK(request_view.fields.type == DMP_TYPE_REQ);
        if (i == 0U) {
            first_read_seq = request_view.fields.seq;
        } else {
            CHECK(request_view.fields.seq == first_read_seq);
        }
        CHECK(deliver(&consumer, &producer, now + 2U) >= 0);
        if (SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_STREAM_R) {
            producer.endpoint.poll_peer_cursor = i;
        }
        CHECK(dmp_endpoint_poll(&producer.endpoint, now + 2U) == DMP_OK);
        {
            bool has_read_response = false;
            size_t j;
            for (j = 0U; j < producer.tx.count; j++) {
                dmp_frame_view view;
                if (producer.tx.peer_slot[j] != i) {
                    continue;
                }
                parsed = parse_outbound_core(producer.tx.frame[j],
                                             producer.tx.length[j], now + 2U,
                                             &view,
                                             producer.parsed_view_storage);
                if (parsed.status == DMP_OK && view.fields.type == DMP_TYPE_RSP) {
                    has_read_response = true;
                    break;
                }
            }
            CHECK(has_read_response);
        }
        /* The old status response is a syntactically valid captured frame,
         * but its REPLY_TO cannot complete this subsequent READ request. */
        {
            dmp_frame_view old_response_view;
            dmp_message_key old_reply_to;
            dmp_status late_status = SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_STREAM_R
                ? dmp_endpoint_rx_from(&consumer.endpoint,
                      consumer.endpoint.peers[0].handle,
                      span(completed_status_response,
                           completed_status_response_len), now + 2U)
                : dmp_endpoint_rx_packet_from(
                &consumer.endpoint, consumer.endpoint.peers[0].handle,
                span(completed_status_response,
                     completed_status_response_len),
                now + 2U);
            parsed = parse_outbound_core(completed_status_response,
                                         completed_status_response_len,
                                         now + 2U, &old_response_view,
                                         consumer.parsed_view_storage);
            (void)churn_stack();
            CHECK(parsed.status == DMP_OK);
            CHECK(dmp_identity_reply_to(
                      &old_response_view, &consumer.endpoint.identity,
                      consumer.endpoint.peers[0].context, now + 2U,
                      &old_reply_to) == DMP_OK);
            CHECK(old_reply_to.seq == first_status_seq);
            CHECK(old_reply_to.seq != request_view.fields.seq);
            CHECK(late_status == DMP_OK || late_status == DMP_DUPLICATE);
        }
        CHECK(consumer.result_count == 0U);
        CHECK(consumer.result_opcode == DMP_SAMPLE1_STATUS_OPCODE);
        CHECK(request.slot < SENDERS);
        CHECK(consumer.senders[request.slot].live != 0U);
        CHECK(consumer.senders[request.slot].peer.generation ==
              request.peer.generation);
        CHECK(deliver(&producer, &consumer, now + 2U) >= 0);
        CHECK(consumer.result_count == 1U);
        CHECK(consumer.result_opcode == DMP_SAMPLE1_READ_OPCODE);
        expected_read(expected, sample_epoch, 1U, 0xabcU);
        CHECK(memcmp(consumer.last_result, expected, sizeof(expected)) == 0);
        CHECK(consumer.result_source.namespace_id == 1U);
        CHECK(consumer.result_source.origin_id == 10U);
        CHECK(consumer.result_source.epoch == producer_epoch);
        CHECK(consumer.result_request.peer.slot == request.peer.slot);
        CHECK(consumer.result_request.peer.generation == request.peer.generation);
        CHECK(consumer.result_request.slot == request.slot);
        CHECK(producer.sample_peers[i].peer.slot == handles[i].slot);
        CHECK(producer.sample_peers[i].peer.generation == handles[i].generation);
        if (SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_STREAM_R) {
            CHECK(pump_sample_peer(now + 3U, i, 0U) == 0);
        } else {
            CHECK(pump(now + 3U) == 0);
        }
    }
    CHECK(producer.endpoint.peer_count == SAMPLE_PEERS);

    /* Keep real endpoint work accepted on peer 1 while replacing a distinct
     * peer whose earlier telemetry send has drained. */
    if (SAMPLE_PEERS > 1U) {
        dmp_peer_handle replacement;
        dmp_peer_handle peer1 = handles[1U];
        dmp_peer_handle replaced_peer = handles[SAMPLE_PEERS - 1U];
        dmp_reliability_handle accepted_request;
        dmp_identity_context_config replacement_context;
        dmp_status replace_status;
        uint32_t old_replaced_generation =
            producer.endpoint.peers[replaced_peer.slot].handle.generation;

        CHECK(dmp_endpoint_submit_req_to(
                  &producer.endpoint, peer1, 1U,
                  span(status_request, sizeof(status_request)), now + 4U,
                  &accepted_request) == DMP_OK);
        CHECK(dmp_endpoint_poll(&producer.endpoint, now + 4U) == DMP_OK);
        CHECK(producer.tx.count != 0U);
        CHECK(producer.tx.peer_slot[producer.tx.count - 1U] == peer1.slot);
        CHECK(accepted_request.slot < SENDERS);
        CHECK(producer.senders[accepted_request.slot].live != 0U);
        CHECK(producer.senders[accepted_request.slot].peer.slot == peer1.slot);
        CHECK(producer.senders[accepted_request.slot].peer.generation ==
              peer1.generation);

        (void)memset(&replacement_context, 0, sizeof(replacement_context));
        replacement_context.local.namespace_id = 1U;
        replacement_context.local.origin_id = 10U;
        replacement_context.local.epoch = producer_epoch;
        replacement_context.peer.namespace_id = 1U;
        replacement_context.peer.origin_id = 20U + SAMPLE_PEERS - 1U;
        replacement_context.peer.epoch = consumer_epoch;
        replacement_context.security = 0U;
        replace_status = dmp_endpoint_replace_none_peer_context(
            &producer.endpoint, replaced_peer, &replacement_context, now + 5U,
            &replacement);
        CHECK(replace_status == DMP_OK);
        CHECK(replacement.slot == replaced_peer.slot);
        CHECK(replacement.generation == old_replaced_generation + 1U);
        CHECK(producer.endpoint.peer_count == SAMPLE_PEERS);
        CHECK(producer.endpoint.peers[peer1.slot].live != 0U);
        CHECK(producer.endpoint.peers[peer1.slot].handle.generation ==
              peer1.generation);
        CHECK(producer.sample_peers[1U].live != 0U);
        CHECK(producer.sample_peers[1U].peer.slot == peer1.slot);
        CHECK(producer.sample_peers[1U].peer.generation == peer1.generation);
        CHECK(accepted_request.peer.slot == peer1.slot);
        CHECK(accepted_request.peer.generation == peer1.generation);
        CHECK(producer.senders[accepted_request.slot].live != 0U);
        CHECK(producer.senders[accepted_request.slot].peer.generation ==
              peer1.generation);
    }
    return 0;
}

static int run_persistent_consumer_history(void)
{
    const dmp_time_ms now = 9000U;
    const uint64_t producer_epoch = 0x901U;
    const uint64_t consumer_epoch = 0xa01U;
    const uint64_t sample_epoch = 1100U;
    uint8_t request_frames[MAX_SAMPLE_PEERS][CORE_MTU];
    size_t request_lengths[MAX_SAMPLE_PEERS] = {0U};
    uint8_t response_frames[MAX_SAMPLE_PEERS][CORE_MTU];
    size_t response_lengths[MAX_SAMPLE_PEERS] = {0U};
    uint8_t read_request[1] = {DMP_SAMPLE1_READ_OPCODE};
    uint8_t expected[DMP_SAMPLE1_READ_BYTES];
    dmp_peer_handle handles[MAX_SAMPLE_PEERS];
    dmp_reliability_handle request_handles[MAX_SAMPLE_PEERS];
    dmp_message_key request_keys[MAX_SAMPLE_PEERS];
    dmp_peer_handle replacement_handle;
    dmp_identity_context_config context;
    uint32_t i;

    CHECK(SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_PACKET);
    (void)memset(&store, 0, sizeof(store));
    store.next_epoch = sample_epoch - 1U;
    CHECK(init_node(&producer, &store, true, 10U, 20U,
                    producer_epoch, consumer_epoch, now) == 0);
    handles[0] = producer.endpoint.peers[0].handle;
    for (i = 1U; i < SAMPLE_PEERS; i++) {
        (void)memset(&context, 0, sizeof(context));
        context.local.namespace_id = 1U;
        context.local.origin_id = 10U;
        context.local.epoch = producer_epoch;
        context.peer.namespace_id = 1U;
        context.peer.origin_id = 20U + i;
        context.peer.epoch = consumer_epoch;
        context.security = 0U;
        CHECK(dmp_endpoint_add_peer(&producer.endpoint, &context, now,
                                    &handles[i]) == DMP_OK);
    }
    CHECK(producer.endpoint.peer_count == SAMPLE_PEERS);
    CHECK(init_sample_endpoint(&producer) == 0);
    CHECK(dmp_sample1_endpoint_begin_epoch(&producer.sample_endpoint, now) ==
          DMP_SAMPLE1_OWNER_OK);
    for (i = 0U; i < SAMPLE_PEERS; i++) {
        CHECK(dmp_sample1_endpoint_activate_peer(&producer.sample_endpoint,
                                                  handles[i]) ==
              DMP_SAMPLE1_OWNER_OK);
    }
    CHECK(dmp_sample1_endpoint_publish(&producer.sample_endpoint, 0x111U, now) ==
          DMP_SAMPLE1_OWNER_OK);
    for (i = 0U; i < SAMPLE_PEERS; i++) {
        CHECK(dmp_endpoint_poll(&producer.endpoint, now) == DMP_OK);
    }
    CHECK(producer.tx.count == SAMPLE_PEERS);
    g_persistent_consumers_active = 1U;
    for (i = 0U; i < SAMPLE_PEERS; i++) {
        g_route_peer_slot = i;
        CHECK(init_node(&persistent_consumers[i], &store, false, 20U + i,
                        10U, consumer_epoch, producer_epoch, now) == 0);
        persistent_consumers[i].tx.route_peer_override = 1U;
        persistent_consumers[i].tx.route_peer_slot = i;
        CHECK(persistent_consumers[i].endpoint.peer_count == 1U);
        CHECK(deliver(&producer, &consumer, now) >= 0);
        CHECK(persistent_consumers[i].telem_count == 1U);
        expected_telem(expected, sample_epoch, 1U, 0x111U);
        CHECK(memcmp(persistent_consumers[i].last_telem, expected,
                     DMP_SAMPLE1_TELEM_BYTES) == 0);
    }

    /* Keep all N consumers alive with independent READs pending at once. */
    g_defer_sample_flush = 1U;
    for (i = 0U; i < SAMPLE_PEERS; i++) {
        node *c = &persistent_consumers[i];
        dmp_reliability_handle request;
        dmp_frame_view view;
        CHECK(dmp_endpoint_submit_req_to(
                  &c->endpoint, c->endpoint.peers[0].handle, 1U,
                  span(read_request, sizeof(read_request)), now + 1U,
                  &request) == DMP_OK);
        CHECK(dmp_endpoint_poll(&c->endpoint, now + 1U) == DMP_OK);
        CHECK(c->tx.count == 1U);
        CHECK(parse_outbound_core(c->tx.frame[0], c->tx.length[0], now + 1U,
                                  &view, c->parsed_view_storage).status == DMP_OK);
        CHECK(view.fields.type == DMP_TYPE_REQ);
        request_keys[i].origin.namespace_id = 1U;
        request_keys[i].origin.origin_id = 20U + i;
        request_keys[i].origin.epoch = consumer_epoch;
        request_keys[i].seq = view.fields.seq;
        request_handles[i] = request;
        request_lengths[i] = c->tx.length[0];
        (void)memcpy(request_frames[i], c->tx.frame[0], request_lengths[i]);
        g_route_peer_slot = i;
        CHECK(deliver(c, &producer, now + 1U) >= 0);
        CHECK(c->tx.count == 0U);
    }
    {
        uint32_t queued = 0U;
        for (i = 0U; i < producer.sample_endpoint.result_capacity; i++) {
            queued += producer.sample_endpoint.results[i].live != 0U;
        }
        CHECK(queued == SAMPLE_PEERS);
    }
    g_defer_sample_flush = 0U;
    producer.tx.delayed_peer_slot = 1U;
    producer.tx.delay_peer_completion = 1U;
    CHECK(dmp_sample1_endpoint_flush(&producer.sample_endpoint, now + 1U) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(collect_sample_responses(now + 1U, 2U,
                                   response_frames, response_lengths) == 0);
    CHECK(producer.tx.delayed.live != 0U);
    CHECK(response_lengths[0] != 0U);
    CHECK(dmp_endpoint_rx_packet_from(
              &persistent_consumers[0].endpoint,
              persistent_consumers[0].endpoint.peers[0].handle,
              span(response_frames[0], response_lengths[0]), now + 2U) ==
          DMP_OK);
    CHECK(persistent_consumers[0].result_count == 1U);
    expected_read(expected, sample_epoch, 1U, 0x111U);
    CHECK(memcmp(persistent_consumers[0].last_result, expected,
                 sizeof(expected)) == 0);
    CHECK(persistent_consumers[0].tx.count == 1U);
    g_route_peer_slot = 0U;
    CHECK(deliver(&persistent_consumers[0], &producer, now + 2U) >= 0);
    producer.tx.count = 0U;
    CHECK(complete_delayed_tx(&producer, now + 2U) == 0);
    CHECK(collect_sample_responses(now + 2U, SAMPLE_PEERS - 2U,
                                   response_frames, response_lengths) == 0);

    /* A valid RSP for peer i must not complete peer i+1, even when the
     * remote producer identity and wire SEQ collide. Destination and full
     * REPLY_TO identity are checked by the real endpoint. */
    for (i = 1U; i < SAMPLE_PEERS; i++) {
        uint32_t wrong = i + 1U == SAMPLE_PEERS ? 1U : i + 1U;
        node *c = &persistent_consumers[wrong];
        dmp_status status = dmp_endpoint_rx_packet_from(
            &c->endpoint, c->endpoint.peers[0].handle,
            span(response_frames[i], response_lengths[i]), now + 2U);
        (void)status;
        CHECK(c->result_count == 0U);
    }

    /* Return the correlated responses in reverse order to keep every peer's
     * result and retained request history separate. */
    for (i = SAMPLE_PEERS; i > 1U; i--) {
        uint32_t peer = i - 1U;
        g_route_peer_slot = peer;
        producer.tx.count = 1U;
        producer.tx.peer_slot[0] = peer;
        producer.tx.length[0] = response_lengths[peer];
        (void)memcpy(producer.tx.frame[0], response_frames[peer],
                     response_lengths[peer]);
        CHECK(deliver(&producer, &consumer, now + 2U) >= 0);
        node *c = &persistent_consumers[peer];
        CHECK(c->result_count == 1U);
        CHECK(c->result_opcode == DMP_SAMPLE1_READ_OPCODE);
        CHECK(c->result_request.peer.slot == request_handles[peer].peer.slot);
        CHECK(c->result_request.peer.generation ==
              request_handles[peer].peer.generation);
        CHECK(c->result_request.slot == request_handles[peer].slot);
        {
            dmp_frame_view response_view;
            dmp_message_key reply_key;
            CHECK(parse_outbound_core(response_frames[peer],
                                      response_lengths[peer], now + 2U,
                                      &response_view,
                                      c->parsed_view_storage).status == DMP_OK);
            CHECK(dmp_identity_reply_to(
                      &response_view, &c->endpoint.identity,
                      c->endpoint.peers[0].context, now + 2U,
                      &reply_key) == DMP_OK);
            CHECK(reply_key.origin.namespace_id ==
                  request_keys[peer].origin.namespace_id);
            CHECK(reply_key.origin.origin_id == request_keys[peer].origin.origin_id);
            CHECK(reply_key.origin.epoch == request_keys[peer].origin.epoch);
            CHECK(reply_key.seq == request_keys[peer].seq);
        }
        expected_read(expected, sample_epoch, 1U, 0x111U);
        CHECK(memcmp(c->last_result, expected, sizeof(expected)) == 0);
        CHECK(c->result_source.origin_id == 10U);
        CHECK(c->result_source.epoch == producer_epoch);
        CHECK(c->tx.count == 1U);
        {
            dmp_frame_view result_ack;
            CHECK(parse_outbound_core(c->tx.frame[0], c->tx.length[0],
                                      now + 2U, &result_ack,
                                      c->parsed_view_storage).status == DMP_OK);
            CHECK(result_ack.fields.type == DMP_TYPE_ACK);
        }
        g_route_peer_slot = peer;
        CHECK(deliver(c, &producer, now + 2U) >= 0);
    }
    CHECK(persistent_consumers[0].result_count == 1U);
    producer.tx.count = 0U;
    for (i = 0U; i < SENDERS; i++) {
        CHECK(producer.senders[i].live == 0U);
    }

    /* Keep READs accepted by peers 1..N-1 while replacing the idle consumer
     * context 0. Its old generation must reject a retained response addressed
     * to peer 1; every unaffected consumer still completes its own READ. */
    for (i = 1U; i < SAMPLE_PEERS; i++) {
        node *c = &persistent_consumers[i];
        dmp_reliability_handle request;
        CHECK(dmp_endpoint_submit_req_to(
                  &c->endpoint, c->endpoint.peers[0].handle, 1U,
                  span(read_request, sizeof(read_request)), now + 3U,
                  &request) == DMP_OK);
        CHECK(dmp_endpoint_poll(&c->endpoint, now + 3U) == DMP_OK);
        CHECK(c->tx.count == 1U);
        request_lengths[i] = c->tx.length[0];
        (void)memcpy(request_frames[i], c->tx.frame[0], request_lengths[i]);
        g_route_peer_slot = i;
        CHECK(deliver(c, &producer, now + 3U) >= 0);
    }
    for (i = 1U; i < SAMPLE_PEERS; i++) {
        CHECK(dmp_endpoint_poll(&producer.endpoint, now + 3U) == DMP_OK);
    }
    CHECK(producer.tx.count == SAMPLE_PEERS - 1U);
    for (i = 0U; i < producer.tx.count; i++) {
        uint32_t peer = producer.tx.peer_slot[i];
        CHECK(peer > 0U && peer < SAMPLE_PEERS);
        response_lengths[peer] = producer.tx.length[i];
        (void)memcpy(response_frames[peer], producer.tx.frame[i],
                     response_lengths[peer]);
    }
    {
        node *idle = &persistent_consumers[0];
        dmp_identity_context_config replacement_context;
        dmp_peer_handle old_handle = idle->endpoint.peers[0].handle;
        dmp_peer_handle replacement;
        uint8_t idle_results_before = idle->result_count;
        (void)memset(&replacement_context, 0, sizeof(replacement_context));
        replacement_context.local.namespace_id = 1U;
        replacement_context.local.origin_id = 20U;
        replacement_context.local.epoch = consumer_epoch;
        replacement_context.peer.namespace_id = 1U;
        replacement_context.peer.origin_id = 10U;
        replacement_context.peer.epoch = producer_epoch + 1U;
        replacement_context.security = 0U;
        CHECK(dmp_endpoint_replace_none_peer_context(
                  &idle->endpoint, old_handle, &replacement_context,
                  now + 4U, &replacement) == DMP_OK);
        CHECK(replacement.slot == old_handle.slot);
        CHECK(replacement.generation == old_handle.generation + 1U);
        CHECK(idle->endpoint.peer_count == 1U);
        CHECK(idle->result_count == idle_results_before);
        CHECK(dmp_endpoint_rx_packet_from(
                  &idle->endpoint, replacement,
                  span(response_frames[1U], response_lengths[1U]),
                  now + 4U) != DMP_OK);
        CHECK(idle->result_count == idle_results_before);
        for (i = SAMPLE_PEERS; i > 1U; i--) {
            uint32_t peer = i - 1U;
            g_route_peer_slot = peer;
            producer.tx.count = 1U;
            producer.tx.peer_slot[0] = peer;
            producer.tx.length[0] = response_lengths[peer];
            (void)memcpy(producer.tx.frame[0], response_frames[peer],
                         response_lengths[peer]);
            CHECK(deliver(&producer, &consumer, now + 4U) >= 0);
            CHECK(persistent_consumers[peer].result_count == 2U);
            expected_read(expected, sample_epoch, 1U, 0x111U);
            CHECK(memcmp(persistent_consumers[peer].last_result, expected,
                         sizeof(expected)) == 0);
            CHECK(deliver(&persistent_consumers[peer], &producer,
                          now + 4U) >= 0);
        }
        replacement_context.peer.epoch = producer_epoch;
        CHECK(dmp_endpoint_replace_none_peer_context(
                  &idle->endpoint, replacement, &replacement_context,
                  now + 5U, &old_handle) == DMP_OK);
        CHECK(old_handle.generation == replacement.generation + 1U);
    }

    /* Publish a newer snapshot, then replay peer 0's exact completed request.
     * It is acknowledged without re-running application work or rolling the
     * current snapshot/history back. */
    CHECK(dmp_sample1_endpoint_publish(&producer.sample_endpoint, 0x222U,
                                       now + 3U) == DMP_SAMPLE1_OWNER_OK);
    for (i = 0U; i < SAMPLE_PEERS; i++) {
        CHECK(dmp_endpoint_poll(&producer.endpoint, now + 3U) == DMP_OK);
    }
    CHECK(producer.tx.count == SAMPLE_PEERS);
    for (i = 0U; i < SAMPLE_PEERS; i++) {
        g_route_peer_slot = i;
        CHECK(deliver(&producer, &consumer, now + 3U) >= 0);
        CHECK(persistent_consumers[i].telem_count == 2U);
        expected_telem(expected, sample_epoch, 2U, 0x222U);
        CHECK(memcmp(persistent_consumers[i].last_telem, expected,
                     DMP_SAMPLE1_TELEM_BYTES) == 0);
    }
    {
        uint32_t reservations_before = store.reservations;
        node *c = &persistent_consumers[0];
        dmp_status duplicate = dmp_endpoint_rx_packet_from(
            &producer.endpoint, handles[0],
            span(request_frames[0], request_lengths[0]), now + 4U);
        CHECK(duplicate == DMP_DUPLICATE || duplicate == DMP_OK);
        CHECK(store.reservations == reservations_before);
        CHECK(producer.pending_read == 0U);
        CHECK(dmp_endpoint_poll(&producer.endpoint, now + 4U) == DMP_OK);
        CHECK(producer.tx.count == 1U);
        {
            dmp_frame_view duplicate_ack;
            CHECK(parse_outbound_core(producer.tx.frame[0],
                                      producer.tx.length[0], now + 4U,
                                      &duplicate_ack,
                                      producer.parsed_view_storage).status == DMP_OK);
            CHECK(duplicate_ack.fields.type == DMP_TYPE_ACK);
            CHECK(producer.tx.peer_slot[0] == 0U);
        }
        producer.tx.count = 0U;
        CHECK(c->result_count == 1U);
        CHECK(c->telem_count == 2U);
        expected_telem(expected, sample_epoch, 2U, 0x222U);
        CHECK(memcmp(c->last_telem, expected,
                     DMP_SAMPLE1_TELEM_BYTES) == 0);

        /* A new request identity observes the newer snapshot. */
        {
            dmp_reliability_handle newer;
            CHECK(dmp_endpoint_submit_req_to(
                      &c->endpoint, c->endpoint.peers[0].handle, 1U,
                      span(read_request, sizeof(read_request)), now + 5U,
                      &newer) == DMP_OK);
            CHECK(dmp_endpoint_poll(&c->endpoint, now + 5U) == DMP_OK);
            g_route_peer_slot = 0U;
            CHECK(deliver(c, &producer, now + 5U) >= 0);
            CHECK(dmp_endpoint_poll(&producer.endpoint, now + 5U) == DMP_OK);
            CHECK(deliver(&producer, &consumer, now + 5U) >= 0);
            CHECK(c->result_count == 2U);
            expected_read(expected, sample_epoch, 2U, 0x222U);
            CHECK(memcmp(c->last_result, expected, sizeof(expected)) == 0);
            CHECK(c->result_request.slot == newer.slot);
            CHECK(c->result_request.peer.generation == newer.peer.generation);
        }
    }
    {
        dmp_identity_context_config replacement_context;
        dmp_peer_handle old_a = handles[0];
        dmp_peer_handle peer_b = handles[1];
        (void)memset(&replacement_context, 0, sizeof(replacement_context));
        replacement_context.local.namespace_id = 1U;
        replacement_context.local.origin_id = 10U;
        replacement_context.local.epoch = producer_epoch;
        replacement_context.peer.namespace_id = 1U;
        replacement_context.peer.origin_id = 20U;
        replacement_context.peer.epoch = consumer_epoch + 1U;
        replacement_context.security = 0U;
        CHECK(dmp_endpoint_replace_none_peer_context(
                  &producer.endpoint, old_a, &replacement_context, now + 6U,
                  &replacement_handle) == DMP_OK);
        CHECK(replacement_handle.slot == old_a.slot);
        CHECK(replacement_handle.generation == old_a.generation + 1U);
        CHECK(producer.endpoint.peer_count == SAMPLE_PEERS);
        CHECK(producer.endpoint.peers[peer_b.slot].live != 0U);
        CHECK(producer.endpoint.peers[peer_b.slot].handle.generation ==
              peer_b.generation);
        CHECK(producer.sample_peers[peer_b.slot].live != 0U);
        CHECK(producer.sample_peers[peer_b.slot].peer.generation ==
              peer_b.generation);
        CHECK(dmp_endpoint_rx_packet_from(
                  &producer.endpoint, replacement_handle,
                  span(request_frames[0], request_lengths[0]), now + 6U) !=
              DMP_OK);
        CHECK(producer.pending_read == 0U);
        CHECK(producer.endpoint.peer_count == SAMPLE_PEERS);
    }
    g_persistent_consumers_active = 0U;
    return 0;
}

static int run_shared_replace_borrow_fence(void)
{
    const dmp_time_ms now = 20000U;
    const uint64_t producer_epoch = 0x1901U;
    const uint64_t consumer_epoch = 0x1a01U;
    const uint64_t sample_epoch = 2100U;
    uint8_t read_request[1] = {DMP_SAMPLE1_READ_OPCODE};
    uint8_t request_frame[2][CORE_MTU];
    size_t request_length[2] = {0U, 0U};
    uint8_t response_frame[MAX_SAMPLE_PEERS][CORE_MTU];
    uint8_t old_a_response[CORE_MTU];
    size_t response_length[MAX_SAMPLE_PEERS] = {0U};
    size_t old_a_response_length;
    uint8_t expected[DMP_SAMPLE1_READ_BYTES];
    dmp_reliability_handle request_handle[2];
    dmp_message_key request_key[2];
    dmp_peer_handle producer_peer[2];
    dmp_peer_handle replacement;
    dmp_identity_context_config context;
    delayed_tx_completion stale_completion;
    uint32_t i;

    (void)memset(&store, 0, sizeof(store));
    store.next_epoch = sample_epoch - 1U;
    CHECK(init_node(&producer, &store, true, 10U, 20U,
                    producer_epoch, consumer_epoch, now) == 0);
    producer_peer[0] = producer.endpoint.peers[0].handle;
    (void)memset(&context, 0, sizeof(context));
    context.local.namespace_id = 1U;
    context.local.origin_id = 10U;
    context.local.epoch = producer_epoch;
    context.peer.namespace_id = 1U;
    context.peer.origin_id = 21U;
    context.peer.epoch = consumer_epoch;
    context.security = 0U;
    CHECK(dmp_endpoint_add_peer(&producer.endpoint, &context, now,
                                &producer_peer[1]) == DMP_OK);
    CHECK(init_sample_endpoint(&producer) == 0);
    CHECK(dmp_sample1_endpoint_begin_epoch(&producer.sample_endpoint, now) ==
          DMP_SAMPLE1_OWNER_OK);
    for (i = 0U; i < 2U; i++) {
        CHECK(dmp_sample1_endpoint_activate_peer(&producer.sample_endpoint,
                                                  producer_peer[i]) ==
              DMP_SAMPLE1_OWNER_OK);
        g_route_peer_slot = i;
        CHECK(init_node(&persistent_consumers[i], &store, false, 20U + i,
                        10U, consumer_epoch, producer_epoch, now) == 0);
        persistent_consumers[i].tx.route_peer_override = 1U;
        persistent_consumers[i].tx.route_peer_slot = i;
    }
    g_persistent_consumers_active = 1U;
    CHECK(dmp_sample1_endpoint_publish(&producer.sample_endpoint, 0x123U, now) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_endpoint_poll(&producer.endpoint, now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&producer.endpoint, now) == DMP_OK);
    CHECK(producer.tx.count == 2U);
    for (i = 0U; i < 2U; i++) {
        g_route_peer_slot = i;
        CHECK(deliver(&producer, &consumer, now) >= 0);
        CHECK(persistent_consumers[i].telem_count == 1U);
    }

    /* Both SAMPLE-1 requests are accepted by the same production endpoint.
     * Keep their copied result work queued until A's delayed transport send is
     * fenced, while B's exact result remains outstanding across replacement. */
    g_defer_sample_flush = 1U;
    for (i = 0U; i < 2U; i++) {
        node *c = &persistent_consumers[i];
        dmp_frame_view view;
        CHECK(dmp_endpoint_submit_req_to(
                  &c->endpoint, c->endpoint.peers[0].handle, 1U,
                  span(read_request, sizeof(read_request)), now + 1U,
                  &request_handle[i]) == DMP_OK);
        CHECK(dmp_endpoint_poll(&c->endpoint, now + 1U) == DMP_OK);
        CHECK(c->tx.count == 1U);
        CHECK(parse_outbound_core(c->tx.frame[0], c->tx.length[0], now + 1U,
                                  &view, c->parsed_view_storage).status == DMP_OK);
        CHECK(view.fields.type == DMP_TYPE_REQ);
        request_key[i].origin.namespace_id = 1U;
        request_key[i].origin.origin_id = 20U + i;
        request_key[i].origin.epoch = consumer_epoch;
        request_key[i].seq = view.fields.seq;
        request_length[i] = c->tx.length[0];
        (void)memcpy(request_frame[i], c->tx.frame[0], request_length[i]);
        g_route_peer_slot = i;
        CHECK(deliver(c, &producer, now + 1U) >= 0);
    }
    CHECK(producer.sample_endpoint.results[0].live != 0U);
    CHECK(producer.sample_endpoint.results[1].live != 0U);
    g_defer_sample_flush = 0U;
    producer.tx.delayed_peer_slot = 0U;
    producer.tx.delay_peer_completion = 1U;
    CHECK(dmp_sample1_endpoint_flush(&producer.sample_endpoint, now + 1U) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(collect_sample_responses(now + 1U, 1U, response_frame,
                                   response_length) == 0);
    CHECK(producer.tx.delayed.live != 0U);
    CHECK(response_length[0] != 0U);
    old_a_response_length = response_length[0];
    (void)memcpy(old_a_response, response_frame[0], old_a_response_length);
    CHECK(producer.endpoint.peers[0].revoked == 0U);
    CHECK(producer.endpoint.peer_count == 2U);
    CHECK(live_senders_for_peer(&producer, producer_peer[1]) == 1U);

    (void)memset(&context, 0, sizeof(context));
    context.local.namespace_id = 1U;
    context.local.origin_id = 10U;
    context.local.epoch = producer_epoch;
    context.peer.namespace_id = 1U;
    context.peer.origin_id = 20U;
    context.peer.epoch = consumer_epoch + 1U;
    context.security = 0U;
    CHECK(dmp_endpoint_replace_none_peer_context(
              &producer.endpoint, producer_peer[0], &context, now + 2U,
              &replacement) == DMP_BUSY);
    CHECK(producer.endpoint.peers[0].live != 0U);
    CHECK(producer.endpoint.peers[0].revoked != 0U);
    CHECK(producer.endpoint.peers[0].handle.generation ==
          producer_peer[0].generation);
    CHECK(producer.endpoint.peer_count == 2U);
    CHECK(producer.tx.delayed.borrowed_data != NULL);
    CHECK(producer.tx.delayed.borrowed_size != 0U);
    CHECK(memcmp(producer.tx.delayed.borrowed_data,
                 producer.tx.delayed.borrowed_snapshot,
                 producer.tx.delayed.borrowed_size) == 0);
    stale_completion = producer.tx.delayed;
    CHECK(complete_delayed_tx(&producer, now + 2U) == 0);
    CHECK(dmp_endpoint_poll(&producer.endpoint, now + 2U) == DMP_OK);
    CHECK(dmp_endpoint_replace_none_peer_context(
              &producer.endpoint, producer_peer[0], &context, now + 3U,
              &replacement) == DMP_OK);
    CHECK(replacement.slot == producer_peer[0].slot);
    CHECK(replacement.generation == producer_peer[0].generation + 1U);
    CHECK(producer.endpoint.peer_count == 2U);
    CHECK(producer.endpoint.peers[1].handle.generation ==
          producer_peer[1].generation);
    CHECK(live_senders_for_peer(&producer, producer_peer[1]) == 1U);
    CHECK(dmp_sample1_endpoint_activate_peer(&producer.sample_endpoint,
                                              replacement) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(collect_sample_responses(now + 3U, 1U, response_frame,
                                   response_length) == 0);
    CHECK(response_length[1] != 0U);

    /* B's accepted READ completes only after A has been fenced and the slot
     * reused. Verify exact full correlation, payload, source and ACK release. */
    producer.tx.count = 1U;
    producer.tx.peer_slot[0] = 1U;
    producer.tx.length[0] = response_length[1];
    (void)memcpy(producer.tx.frame[0], response_frame[1], response_length[1]);
    g_route_peer_slot = 1U;
    CHECK(deliver(&producer, &consumer, now + 4U) >= 0);
    CHECK(persistent_consumers[1].result_count == 1U);
    expected_read(expected, sample_epoch, 1U, 0x123U);
    CHECK(memcmp(persistent_consumers[1].last_result, expected,
                 sizeof(expected)) == 0);
    CHECK(persistent_consumers[1].result_source.origin_id == 10U);
    CHECK(persistent_consumers[1].result_source.epoch == producer_epoch);
    CHECK(persistent_consumers[1].result_request.slot == request_handle[1].slot);
    CHECK(persistent_consumers[1].result_request.peer.generation ==
          request_handle[1].peer.generation);
    {
        dmp_frame_view view;
        dmp_message_key reply;
        CHECK(parse_outbound_core(response_frame[1], response_length[1], now + 4U,
                                  &view, persistent_consumers[1].parsed_view_storage).status == DMP_OK);
        CHECK(dmp_identity_reply_to(&view,
                                    &persistent_consumers[1].endpoint.identity,
                                    persistent_consumers[1].endpoint.peers[0].context,
                                    now + 4U, &reply) == DMP_OK);
        CHECK(reply.origin.origin_id == request_key[1].origin.origin_id);
        CHECK(reply.origin.namespace_id == request_key[1].origin.namespace_id);
        CHECK(reply.origin.epoch == request_key[1].origin.epoch);
        CHECK(reply.seq == request_key[1].seq);
    }
    g_route_peer_slot = 1U;
    CHECK(deliver(&persistent_consumers[1], &producer, now + 4U) >= 0);
    CHECK(live_senders_for_peer(&producer, producer_peer[1]) == 0U);

    /* Restart A under its explicitly selected new boot epoch. A's old RSP is
     * rejected while a fresh READ is live, then that new READ completes. */
    CHECK(init_node(&persistent_consumers[0], &store, false, 20U, 10U,
                    consumer_epoch + 1U, producer_epoch, now + 5U) == 0);
    persistent_consumers[0].tx.route_peer_override = 1U;
    persistent_consumers[0].tx.route_peer_slot = 0U;
    CHECK(dmp_endpoint_submit_req_to(
              &persistent_consumers[0].endpoint,
              persistent_consumers[0].endpoint.peers[0].handle, 1U,
              span(read_request, sizeof(read_request)), now + 5U,
              &request_handle[0]) == DMP_OK);
    CHECK(dmp_endpoint_poll(&persistent_consumers[0].endpoint, now + 5U) == DMP_OK);
    CHECK(persistent_consumers[0].tx.count == 1U);
    g_route_peer_slot = 0U;
    g_defer_sample_flush = 1U;
    CHECK(deliver(&persistent_consumers[0], &producer, now + 5U) >= 0);
    CHECK(producer.sample_endpoint.results[0].live != 0U);
    producer.tx.delayed_peer_slot = 0U;
    producer.tx.delay_peer_completion = 1U;
    g_defer_sample_flush = 0U;
    CHECK(dmp_sample1_endpoint_flush(&producer.sample_endpoint, now + 6U) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(collect_sample_responses(now + 6U, 1U, response_frame,
                                   response_length) == 0);
    CHECK(producer.tx.delayed.live != 0U);
    CHECK(producer.tx.delayed.token.generation != stale_completion.token.generation ||
          producer.tx.delayed.token.slot != stale_completion.token.slot);
    /* Deliberately invalid duplicate terminal callback: transport contract
     * permits exactly one terminal completion per accepted submission. This
     * robustness injection must not match or release the newer TX generation. */
    stale_completion.complete(stale_completion.owner, stale_completion.token,
                              DMP_TX_TRANSMITTED, now + 7U);
    CHECK(producer.tx.delayed.live != 0U);
    CHECK(producer.tx.delayed.borrowed_data != NULL);
    CHECK(memcmp(producer.tx.delayed.borrowed_data,
                 producer.tx.delayed.borrowed_snapshot,
                 producer.tx.delayed.borrowed_size) == 0);
    CHECK(persistent_consumers[0].result_count == 0U);
    producer.tx.count = 1U;
    producer.tx.peer_slot[0] = 0U;
    producer.tx.length[0] = old_a_response_length;
    (void)memcpy(producer.tx.frame[0], old_a_response,
                 old_a_response_length);
    CHECK(dmp_endpoint_rx_packet_from(
              &persistent_consumers[0].endpoint,
              persistent_consumers[0].endpoint.peers[0].handle,
              span(old_a_response, old_a_response_length), now + 7U) != DMP_OK);
    CHECK(persistent_consumers[0].result_count == 0U);
    CHECK(persistent_consumers[0].senders[request_handle[0].slot].live != 0U);
    CHECK(complete_delayed_tx(&producer, now + 8U) == 0);
    CHECK(dmp_endpoint_rx_packet_from(
              &persistent_consumers[0].endpoint,
              persistent_consumers[0].endpoint.peers[0].handle,
              span(response_frame[0], response_length[0]), now + 8U) == DMP_OK);
    CHECK(persistent_consumers[0].result_count == 1U);
    expected_read(expected, sample_epoch, 1U, 0x123U);
    CHECK(memcmp(persistent_consumers[0].last_result, expected,
                 sizeof(expected)) == 0);
    CHECK(persistent_consumers[0].result_request.slot == request_handle[0].slot);
    CHECK(persistent_consumers[0].result_request.peer.generation ==
          request_handle[0].peer.generation);
    g_persistent_consumers_active = 0U;
    return 0;
}
#endif

static int begin_and_activate_sample(dmp_time_ms now)
{
    dmp_peer_handle peer = producer.endpoint.peers[0].handle;
    dmp_sample1_owner_result result =
        dmp_sample1_endpoint_begin_epoch(&producer.sample_endpoint, now);
    if (result != DMP_SAMPLE1_OWNER_OK) {
        (void)fprintf(stderr, "SAMPLE-1 begin_epoch returned %d\n", (int)result);
        return 1;
    }
    result = dmp_sample1_endpoint_activate_peer(&producer.sample_endpoint, peer);
    if (result != DMP_SAMPLE1_OWNER_OK) {
        (void)fprintf(stderr, "SAMPLE-1 activate_peer returned %d\n", (int)result);
        return 1;
    }
    return 0;
}

static int publish_and_check(dmp_time_ms now, uint32_t value,
                             uint64_t expected_epoch)
{
    uint8_t expected[DMP_SAMPLE1_TELEM_BYTES];
    if (dmp_sample1_endpoint_publish(&producer.sample_endpoint, value, now) !=
        DMP_SAMPLE1_OWNER_OK ||
        dmp_endpoint_poll(&producer.endpoint, now) != DMP_OK ||
        producer.tx.count != 1U) {
        return 1;
    }
    expected_telem(expected, expected_epoch, 1U, value);
    if (memcmp(producer.store->published_payload, expected, sizeof(expected)) != 0) {
        return 1;
    }
    return 0;
}

int main(void)
{
    const dmp_time_ms now = 100U;
    const uint64_t first_sample_epoch = 700U;
    const uint64_t second_sample_epoch = 701U;
    const uint64_t producer_boot_1 = 0x101U;
    const uint64_t consumer_boot_1 = 0x201U;
    const uint64_t producer_boot_2 = 0x102U;
    uint8_t stale_frame[CORE_MTU];
    size_t stale_frame_len;
    uint8_t read_request[DMP_SAMPLE1_READ_OPCODE] = {DMP_SAMPLE1_READ_OPCODE};
    uint8_t status_request[DMP_SAMPLE1_READ_OPCODE] = {DMP_SAMPLE1_STATUS_OPCODE};
    uint8_t expected[DMP_SAMPLE1_READ_BYTES];
    dmp_reliability_handle request;
    dmp_status stale_status;

#if SAMPLE_PEERS > 1U
    if (run_multi_peer_round_trips() != 0) {
        return 1;
    }
    if (SAMPLE_RADIO == 0 &&
        SAMPLE_FRAMING_MODE == DMP_ENDPOINT_FRAMING_PACKET) {
        if (run_persistent_consumer_history() != 0) {
            return 1;
        }
        return run_shared_replace_borrow_fence();
    }
    return 0;
#endif

    (void)memset(&store, 0, sizeof(store));
    store.next_epoch = first_sample_epoch - 1U;
    CHECK(init_node(&producer, &store, true, 10U, 20U,
                    producer_boot_1, consumer_boot_1,
                    now) == 0);
    CHECK(init_node(&consumer, &store, false, 20U, 10U,
                    consumer_boot_1, producer_boot_1,
                    now) == 0);
    CHECK(init_sample_endpoint(&producer) == 0);
    CHECK(dmp_endpoint_submit_req_to(&consumer.endpoint,
                                     consumer.endpoint.peers[0].handle, 1U,
                                     span(status_request, sizeof(status_request)), now,
                                     &request) == DMP_OK);
    CHECK(pump(now) == 0);
    CHECK(consumer.result_opcode == DMP_SAMPLE1_STATUS_OPCODE);
    CHECK(consumer.last_result[0] == DMP_SAMPLE1_STATUS_OPCODE);
    CHECK(consumer.last_result[1] == 0U);
    CHECK(consumer.result_request.peer.slot == request.peer.slot);
    CHECK(consumer.result_request.peer.generation == request.peer.generation);
    CHECK(consumer.result_request.slot == request.slot);
    consumer.result_count = 0U;
    CHECK(begin_and_activate_sample(now) == 0);
    CHECK(store.committed_epoch == first_sample_epoch);
    CHECK(publish_and_check(now, 300U, first_sample_epoch) == 0);
    stale_frame_len = producer.tx.length[0];
    (void)memcpy(stale_frame, producer.tx.frame[0], stale_frame_len);
    CHECK(pump(now) == 0);
    CHECK(consumer.telem_count == 1U);
    expected_telem(expected, first_sample_epoch, 1U, 300U);
    CHECK(memcmp(consumer.last_telem, expected, DMP_SAMPLE1_TELEM_BYTES) == 0);

    CHECK(dmp_endpoint_submit_req_to(&consumer.endpoint,
                                     consumer.endpoint.peers[0].handle, 1U,
                                     span(read_request, sizeof(read_request)), now,
                                     &request) == DMP_OK);
    CHECK(pump(now + 1U) == 0);
    CHECK(store.reservations == 1U);
    CHECK(store.publications == 1U);
    CHECK(consumer.result_count == 1U);
    CHECK(consumer.result_source.namespace_id == 1U);
    CHECK(consumer.result_source.origin_id == 10U);
    CHECK(consumer.result_source.epoch == producer_boot_1);
    expected_read(expected, first_sample_epoch, 1U, 300U);
    CHECK(memcmp(consumer.last_result, expected, sizeof(expected)) == 0);

    /* The producer restarts with a new local boot epoch. Rebind the existing
     * consumer endpoint explicitly; the prior CRC-valid frame must not select
     * its old peer epoch. */
    CHECK(init_node(&producer, &store, true, 10U, 20U,
                    producer_boot_2, consumer_boot_1,
                    now + 2U) == 0);
    CHECK(init_sample_endpoint(&producer) == 0);
    CHECK(begin_and_activate_sample(now + 2U) == 0);
    CHECK(store.committed_epoch == second_sample_epoch);
    CHECK(replace_node_context(&consumer, consumer_boot_1, producer_boot_2,
                               now + 2U) == 0);
    stale_status = dmp_endpoint_rx_packet_from(
        &consumer.endpoint, consumer.endpoint.peers[0].handle,
        span(stale_frame, stale_frame_len), now + 2U);
    CHECK(stale_status != DMP_OK && stale_status != DMP_DUPLICATE);
    CHECK(consumer.telem_count == 0U);

    CHECK(publish_and_check(now + 3U, 301U, second_sample_epoch) == 0);
    {
        dmp_core_limits limits = {CORE_MTU, MESSAGE_BYTES, 16U};
        dmp_frame_view frame;
        dmp_parse_result parsed = dmp_core_parse(
            span(producer.tx.frame[0], producer.tx.length[0]), &limits, &frame);
        dmp_message_key key;
        if (parsed.status != DMP_OK ||
            dmp_identity_source_key(&frame, &consumer.endpoint.identity,
                                    consumer.endpoint.peers[0].context,
                                    now + 3U, &key) != DMP_OK) {
            (void)fprintf(stderr, "replacement TELEM failed identity preflight: parse=%u\n",
                          (unsigned)parsed.status);
            return 1;
        }
    }
    CHECK(pump(now + 3U) == 0);
    CHECK(consumer.telem_count == 1U);
    expected_telem(expected, second_sample_epoch, 1U, 301U);
    CHECK(memcmp(consumer.last_telem, expected, DMP_SAMPLE1_TELEM_BYTES) == 0);
    CHECK(dmp_endpoint_submit_req_to(&consumer.endpoint,
                                     consumer.endpoint.peers[0].handle, 1U,
                                     span(read_request, sizeof(read_request)), now + 4U,
                                     &request) == DMP_OK);
    CHECK(pump(now + 4U) == 0);
    CHECK(store.reservations == 2U);
    CHECK(store.publications == 2U);
    CHECK(consumer.result_count == 1U);
    CHECK(consumer.result_source.epoch == producer_boot_2);
    expected_read(expected, second_sample_epoch, 1U, 301U);
    CHECK(memcmp(consumer.last_result, expected, sizeof(expected)) == 0);
    CHECK(consumer.result_request.peer.slot == request.peer.slot);
    CHECK(consumer.result_request.peer.generation == request.peer.generation);
    CHECK(consumer.result_request.slot == request.slot);
    CHECK(dmp_endpoint_submit_req_to(&consumer.endpoint,
                                     consumer.endpoint.peers[0].handle, 1U,
                                     span(status_request, sizeof(status_request)), now + 5U,
                                     &request) == DMP_OK);
    CHECK(pump(now + 5U) == 0);
    CHECK(consumer.result_opcode == DMP_SAMPLE1_STATUS_OPCODE);
    CHECK(consumer.last_result[0] == DMP_SAMPLE1_STATUS_OPCODE);
    CHECK(consumer.last_result[1] == 1U);
    CHECK(consumer.result_request.peer.slot == request.peer.slot);
    CHECK(consumer.result_request.peer.generation == request.peer.generation);
    CHECK(consumer.result_request.slot == request.slot);
    (void)printf("production SAMPLE-1 NONE endpoint integration passed\n");
    return 0;
}
