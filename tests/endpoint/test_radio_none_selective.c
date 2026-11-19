#include "dmp/core.h"
#include "dmp/endpoint.h"
#include "dmp/integrity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(DMP_NONE_MANIFEST_PROBE)
#include "none_manifest.h"
#endif

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,   \
                          __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

enum {
#if defined(DMP_NONE_MANIFEST_PROBE)
    PEERS = DMP_NONE_PEERS,
    MESSAGE_BYTES = DMP_NONE_MESSAGE_BYTES,
    MTU = DMP_NONE_ENCODED_MTU,
    SENDER_SLOTS = DMP_NONE_SENDER_SLOTS,
    RESULT_SLOTS = DMP_NONE_RESULT_SLOTS,
    HISTORY_SLOTS = DMP_NONE_HISTORY_SLOTS,
    CORRELATION_SLOTS = DMP_NONE_CORRELATION_SLOTS,
    ADAPTER_SLOTS = DMP_NONE_ADAPTER_SLOTS,
    CHUNK_BYTES = DMP_NONE_CHUNK_BYTES,
    TOMBSTONES = DMP_NONE_ASSEMBLY_TOMBSTONE_SLOTS,
    FRAGMENT_COUNT = DMP_NONE_PROBE_FRAGMENTS,
#else
    PEERS = 1,
    MESSAGE_BYTES = 512,
    MTU = 263,
    SENDER_SLOTS = 4,
    RESULT_SLOTS = 4,
    HISTORY_SLOTS = 8,
    CORRELATION_SLOTS = 4,
    ADAPTER_SLOTS = 3,
    CHUNK_BYTES = 32,
    TOMBSTONES = 2,
    FRAGMENT_COUNT = 8,
#endif
    QUEUE_CAPACITY = 16,
    BODY_BYTES = FRAGMENT_COUNT * CHUNK_BYTES,
};

typedef struct {
    uint8_t bytes[MTU];
    size_t size;
} packet;

typedef struct {
    packet packets[QUEUE_CAPACITY];
    size_t count;
    dmp_time_ms now;
} wire;

typedef struct endpoint_fixture endpoint_fixture;
struct endpoint_fixture {
    dmp_endpoint endpoint;
    dmp_endpoint_peer_state peer_state[PEERS];
    dmp_transport transport;
    wire wire;
    dmp_identity_slot identities[2];
    dmp_reliability_sender_slot senders[SENDER_SLOTS];
    uint8_t sender_payload[SENDER_SLOTS * MESSAGE_BYTES];
    dmp_reliability_result_slot results[RESULT_SLOTS];
    uint8_t result_payload[RESULT_SLOTS * MESSAGE_BYTES];
    dmp_reliability_history_slot history[HISTORY_SLOTS];
    dmp_reliability_correlation_slot correlations[CORRELATION_SLOTS];
    uint8_t history_metadata[HISTORY_SLOTS * DMP_RELIABILITY_METADATA_BYTES];
    uint8_t correlation_metadata[CORRELATION_SLOTS * DMP_RELIABILITY_METADATA_BYTES];
    dmp_reliability_adapter_slot adapters[ADAPTER_SLOTS];
    uint8_t frames[ADAPTER_SLOTS * MTU];
    uint8_t receive_payload[MESSAGE_BYTES];
    dmp_reassembly_slot assemblies[PEERS];
    dmp_reassembly_tombstone tombstones[TOMBSTONES];
    uint8_t assembly_payload[PEERS * MESSAGE_BYTES];
    uint8_t assembly_metadata[PEERS * DMP_REASSEMBLY_METADATA_BYTES];
    uint8_t fragment_message[MESSAGE_BYTES];
    uint8_t fragment_frame[MTU];
    uint8_t telemetry_payload[PEERS * MESSAGE_BYTES];
    uint8_t telemetry_next[PEERS * MESSAGE_BYTES];
    uint8_t telemetry_frame[MTU];
    uint32_t assembled;
    uint32_t data_delivered;
    size_t assembled_bytes;
    uint8_t assembled_payload[BODY_BYTES];
};

static endpoint_fixture sender;
static endpoint_fixture receiver;

static dmp_bytes span(const void *data, size_t size)
{
    dmp_bytes result;
    result.data = (const uint8_t *)data;
    result.size = size;
    return result;
}

static dmp_status wire_submit(void *user, const dmp_tx_submission *submission)
{
    wire *link = (wire *)user;
    if (link == NULL || submission == NULL || submission->complete == NULL ||
        submission->frame.data == NULL || submission->frame.size > MTU ||
        link->count >= QUEUE_CAPACITY) {
        return DMP_BUSY;
    }
    packet *out = &link->packets[link->count++];
    memcpy(out->bytes, submission->frame.data, submission->frame.size);
    out->size = submission->frame.size;
    submission->complete(submission->owner, submission->token,
                         DMP_TX_TRANSMITTED, link->now);
    return DMP_OK;
}

static dmp_status wire_cancel(void *user, dmp_tx_token token)
{
    (void)user;
    (void)token;
    return DMP_OK;
}

static void notice(void *user, const dmp_endpoint_notice *event)
{
    endpoint_fixture *fixture = (endpoint_fixture *)user;
    if (event->event == DMP_ENDPOINT_ASSEMBLED) {
        fixture->assembled++;
        fixture->assembled_bytes = event->payload.size;
        if (event->payload.size <= sizeof fixture->assembled_payload) {
            memcpy(fixture->assembled_payload, event->payload.data,
                   event->payload.size);
        }
    } else if (event->event == DMP_ENDPOINT_DATA_DELIVERED) {
        fixture->data_delivered++;
    }
}

static void selective_profile(dmp_config *config)
{
#if defined(DMP_NONE_MANIFEST_PROBE)
    *config = dmp_none_manifest;
#else
    memset(config, 0, sizeof *config);
    config->namespace_id = 7U;
    config->node_id[0] = 10U;
    config->node_id[1] = 20U;
    config->default_service = 1U;
    config->service_id[0] = 1U;
    config->service_id[1] = 2U;
    config->recovery[0] = DMP_PROFILE_RECOVERY_SELECTIVE32;
    config->recovery[1] = DMP_PROFILE_RECOVERY_SELECTIVE32;
    config->security_mode = DMP_PROFILE_SECURITY_NONE;
    config->origin_route = 1U;
    config->peers = PEERS;
    config->operations_per_service = 1U;
    config->assemblies_per_peer = 1U;
    config->assembly_tombstones_per_peer = TOMBSTONES;
    config->sender_slots = SENDER_SLOTS;
    config->assembly_slots = PEERS;
    config->assembly_tombstone_slots = TOMBSTONES;
    config->result_slots = RESULT_SLOTS;
    config->history_slots = HISTORY_SLOTS;
    config->correlation_slots = CORRELATION_SLOTS;
    config->adapter_slots = ADAPTER_SLOTS;
    config->application_queue_slots = 2U;
    config->control_slots = 2U;
    config->message_bytes = MESSAGE_BYTES;
    config->fragments = FRAGMENT_COUNT;
    config->chunk_bytes = CHUNK_BYTES;
    config->encoded_mtu = MTU;
    config->frame_tx_ms = 1U;
    config->forward_mtu = 256U;
    config->return_mtu = 256U;
    config->forward_delay_ms = 1U;
    config->return_delay_ms = 1U;
    config->record_margin_ms = 1U;
    config->queue_ms = 64U;
    config->response_timeout_ms = 1280U;
    config->send_horizon_ms = 5632U;
    config->jitter_ms = 0U;
    config->burst_span_ms = 1U;
    config->feedback_guard_ms = 1U;
    config->feedback_delay_ms = 1U;
    config->max_probes = 1U;
    config->max_status = 1U;
    config->max_bursts = 3U;
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
    config->tx_borrow = true;
    config->synchronous_completion = true;
#endif
}

static int boot(endpoint_fixture *fixture, int is_sender, dmp_time_ms now)
{
    dmp_config config;
    dmp_admitted_profile profile;
    dmp_endpoint_storage storage;
    dmp_identity_context_config context;

    memset(fixture, 0, sizeof *fixture);
    selective_profile(&config);
    CHECK(dmp_config_admit(&config, &profile) == DMP_OK);
    memset(&context, 0, sizeof context);
    context.local.namespace_id = profile.namespace_id;
    context.peer.namespace_id = profile.namespace_id;
    context.local.origin_id = profile.node_id[is_sender ? 0 : 1];
    context.peer.origin_id = profile.node_id[is_sender ? 1 : 0];
    context.local.epoch = is_sender ? 0x1001U : 0x2002U;
    context.peer.epoch = is_sender ? 0x2002U : 0x1001U;
    context.security = 0U;
    fixture->wire.now = now;
    fixture->transport.context = &fixture->wire;
    fixture->transport.submit = wire_submit;
    fixture->transport.cancel = wire_cancel;
    fixture->transport.caps.max_frame_bytes = MTU;
    fixture->transport.caps.ownership = DMP_TX_BORROW;
    fixture->transport.caps.synchronous_completion = true;

    memset(&storage, 0, sizeof storage);
    storage.profile = &profile;
    storage.framing_mode = DMP_ENDPOINT_FRAMING_PACKET;
    storage.peer_states = fixture->peer_state;
    storage.peer_state_capacity = PEERS;
    storage.identity_slots = fixture->identities;
    storage.identity_capacity = 2U;
    storage.context = context;
    storage.transport = &fixture->transport;
    storage.notice = notice;
    storage.notice_user = fixture;
    storage.senders = fixture->senders;
    storage.sender_capacity = SENDER_SLOTS;
    storage.sender_payload = fixture->sender_payload;
    storage.sender_payload_capacity = sizeof fixture->sender_payload;
    storage.results = fixture->results;
    storage.result_capacity = RESULT_SLOTS;
    storage.result_payload = fixture->result_payload;
    storage.result_payload_capacity = sizeof fixture->result_payload;
    storage.history = fixture->history;
    storage.history_capacity = HISTORY_SLOTS;
    storage.correlations = fixture->correlations;
    storage.correlation_capacity = CORRELATION_SLOTS;
    storage.history_metadata = fixture->history_metadata;
    storage.history_metadata_capacity = sizeof fixture->history_metadata;
    storage.correlation_metadata = fixture->correlation_metadata;
    storage.correlation_metadata_capacity = sizeof fixture->correlation_metadata;
    storage.adapters = fixture->adapters;
    storage.adapter_capacity = ADAPTER_SLOTS;
    storage.frames = fixture->frames;
    storage.frame_capacity = sizeof fixture->frames;
    storage.receive_payload = fixture->receive_payload;
    storage.receive_payload_capacity = sizeof fixture->receive_payload;
    storage.assemblies = fixture->assemblies;
    storage.assembly_capacity = PEERS;
    storage.tombstones = fixture->tombstones;
    storage.tombstone_capacity = TOMBSTONES;
    storage.assembly_payload = fixture->assembly_payload;
    storage.assembly_payload_capacity = sizeof fixture->assembly_payload;
    storage.assembly_metadata = fixture->assembly_metadata;
    storage.assembly_metadata_capacity = sizeof fixture->assembly_metadata;
    storage.fragment_message = fixture->fragment_message;
    storage.fragment_message_capacity = sizeof fixture->fragment_message;
    storage.fragment_frame = fixture->fragment_frame;
    storage.fragment_frame_capacity = sizeof fixture->fragment_frame;
    storage.telemetry_payload = fixture->telemetry_payload;
    storage.telemetry_payload_capacity = sizeof fixture->telemetry_payload;
    storage.telemetry_next = fixture->telemetry_next;
    storage.telemetry_next_capacity = sizeof fixture->telemetry_next;
    storage.telemetry_frame = fixture->telemetry_frame;
    storage.telemetry_frame_capacity = sizeof fixture->telemetry_frame;
    CHECK(dmp_endpoint_init(&fixture->endpoint, &storage, now) == DMP_OK);
    return 0;
}

static dmp_status parse(const packet *input, dmp_frame_view *view)
{
    const dmp_core_limits limits = {MTU, MESSAGE_BYTES, FRAGMENT_COUNT};
    return dmp_core_parse(span(input->bytes, input->size), &limits, view).status;
}

static int deliver(endpoint_fixture *from, endpoint_fixture *to, size_t index,
                    dmp_time_ms now, dmp_status expected)
{
    dmp_status status = dmp_endpoint_rx_packet(&to->endpoint,
                                               span(from->wire.packets[index].bytes,
                                                    from->wire.packets[index].size),
                                               now);
    CHECK(status == expected);
    return 0;
}

static dmp_reliability_sender_slot *live_sender(void)
{
    size_t i;
    for (i = 0U; i < SENDER_SLOTS; i++) {
        if (sender.senders[i].live != 0U && sender.senders[i].frag_count == FRAGMENT_COUNT) {
            return &sender.senders[i];
        }
    }
    return NULL;
}

static int test_selective_repair_none(void)
{
    static const uint32_t dropped[] = {1U, 6U};
    uint8_t body[BODY_BYTES];
    dmp_reliability_handle operation;
    dmp_reliability_sender_slot *state;
    dmp_frame_view view;
    dmp_time_ms now = 20000U;
    dmp_time_ms feedback_at;
    dmp_time_ms repair_at;
    uint32_t index;
    uint32_t active_before;
    size_t i;
    size_t bad_crc_index = 0U;
    size_t malformed_index = 0U;
    uint32_t crc;
    packet mutated;

    CHECK(boot(&sender, 1, now) == 0);
    CHECK(boot(&receiver, 0, now) == 0);
#if defined(DMP_NONE_PACKET_ONLY_PROBE) && !defined(ESP_PLATFORM)
    {
        dmp_endpoint_storage storage = sender.endpoint.mem;
        unsigned char before[sizeof(sender.endpoint)];
        const uint8_t delimiter = 0U;
        memcpy(before, &sender.endpoint, sizeof before);
        storage.framing_mode = DMP_ENDPOINT_FRAMING_STREAM_R;
        CHECK(dmp_endpoint_init(&sender.endpoint, &storage, now) == DMP_UNSUPPORTED);
        CHECK(dmp_endpoint_rx_from(&sender.endpoint, sender.endpoint.peers[0].handle,
                                   span(&delimiter, 1U), now) == DMP_UNSUPPORTED);
        CHECK(memcmp(before, &sender.endpoint, sizeof before) == 0);
    }
#endif
    feedback_at = now + receiver.endpoint.profile.burst_span_ms +
                  receiver.endpoint.profile.forward_delay_ms +
                  receiver.endpoint.profile.feedback_guard_ms;
#if defined(DMP_NONE_MANIFEST_PROBE)
    repair_at = now + DMP_NONE_SECOND_BURST_MS;
#else
    repair_at = feedback_at + 3U;
#endif
    for (i = 0U; i < sizeof body; i++) {
        body[i] = (uint8_t)(0x40U + (uint8_t)i);
    }
    sender.wire.now = now;
    receiver.wire.now = now;
    CHECK(dmp_endpoint_submit_data(&sender.endpoint, 2U, span(body, sizeof body),
                                   span(NULL, 0U), now, &operation) == DMP_OK);
    for (i = 0U; i < 64U && sender.wire.count < FRAGMENT_COUNT; i++) {
        CHECK(dmp_endpoint_poll(&sender.endpoint, now) == DMP_OK);
    }
    CHECK(sender.wire.count == FRAGMENT_COUNT);
    for (i = 0U; i < sender.wire.count; i++) {
        CHECK(parse(&sender.wire.packets[i], &view) == DMP_OK);
        CHECK(view.fields.type == DMP_TYPE_DATA);
        CHECK((view.fields.options & DMP_OPT_FRAG) != 0U);
        CHECK((view.fields.options & DMP_OPT_INTEGRITY) != 0U);
        CHECK((view.fields.options & DMP_OPT_ROUTE) != 0U);
        CHECK(view.fields.route.mode == 1U &&
              view.fields.route.destination == 20U);
        index = view.fields.fragment.index;
        if (index == dropped[0] || index == dropped[1]) {
            continue;
        }
        CHECK(deliver(&sender, &receiver, i, now, DMP_INCOMPLETE) == 0);
    }
    CHECK(receiver.assembled == 0U);
    receiver.wire.now = feedback_at;
    CHECK(dmp_endpoint_poll(&receiver.endpoint, feedback_at) == DMP_OK);
    CHECK(receiver.wire.count == 1U);
    CHECK(parse(&receiver.wire.packets[0], &view) == DMP_OK);
    CHECK(view.fields.type == DMP_TYPE_FRAG_STATUS);
    CHECK((view.fields.options & DMP_OPT_INTEGRITY) != 0U);
    CHECK((view.fields.options & DMP_OPT_ROUTE) != 0U);
    CHECK(view.fields.route.mode == 1U &&
          view.fields.route.destination == 10U);
    CHECK(view.payload.size == 4U);

    state = live_sender();
    CHECK(state != NULL);
    CHECK(state->feedback_valid == 0U);
    active_before = state->active_mask;
    CHECK(state->phase != DMP_REL_PHASE_TERMINAL);

    /* A CRC-invalid NONE feedback frame must not advance feedback or alter the
     * selected initial burst. */
    mutated = receiver.wire.packets[0];
    bad_crc_index = mutated.size - 1U;
    mutated.bytes[bad_crc_index] ^= 0x80U;
    CHECK(dmp_endpoint_rx_packet(&sender.endpoint, span(mutated.bytes, mutated.size),
                                 feedback_at + 1U) == DMP_INTEGRITY_FAILURE);
    CHECK(state->feedback_valid == 0U);
    CHECK(state->active_mask == active_before);
    CHECK(sender.wire.count == FRAGMENT_COUNT);

    /* A structurally valid but impossible all-fragments mask is ignored and
     * leaves the active reliable DATA transfer untouched. Recompute CRC32C so
     * this specifically reaches recovery validation. */
    mutated = receiver.wire.packets[0];
    CHECK(parse(&mutated, &view) == DMP_OK);
    CHECK(view.payload.size == 4U);
    malformed_index = (size_t)(view.payload.data - mutated.bytes);
    memset(mutated.bytes + malformed_index, 0xFF, 4U);
    CHECK(dmp_crc32c(span(mutated.bytes, mutated.size - 4U), &crc) == DMP_OK);
    mutated.bytes[mutated.size - 4U] = (uint8_t)crc;
    mutated.bytes[mutated.size - 3U] = (uint8_t)(crc >> 8U);
    mutated.bytes[mutated.size - 2U] = (uint8_t)(crc >> 16U);
    mutated.bytes[mutated.size - 1U] = (uint8_t)(crc >> 24U);
    CHECK(dmp_endpoint_rx_packet(&sender.endpoint, span(mutated.bytes, mutated.size),
                                 feedback_at + 1U) == DMP_OK);
    CHECK(state->feedback_valid == 0U);
    CHECK(state->active_mask == active_before);
    CHECK(sender.wire.count == FRAGMENT_COUNT);

    CHECK(deliver(&receiver, &sender, 0U, feedback_at + 2U, DMP_OK) == 0);
    CHECK(state->feedback_valid != 0U);
    CHECK(state->active_mask == ((1U << dropped[0]) | (1U << dropped[1])));
    sender.wire.now = repair_at;
    receiver.wire.now = repair_at;
    for (i = 0U; i < 64U && sender.wire.count < FRAGMENT_COUNT + 2U; i++) {
        CHECK(dmp_endpoint_poll(&sender.endpoint, repair_at) == DMP_OK);
    }
    CHECK(sender.wire.count == FRAGMENT_COUNT + 2U);
    for (i = FRAGMENT_COUNT; i < sender.wire.count; i++) {
        CHECK(parse(&sender.wire.packets[i], &view) == DMP_OK);
        CHECK(view.fields.type == DMP_TYPE_DATA);
        CHECK((view.fields.options & DMP_OPT_FRAG) != 0U);
        CHECK(view.fields.fragment.index == dropped[i - FRAGMENT_COUNT]);
        CHECK(deliver(&sender, &receiver, i, repair_at,
                      i + 1U == sender.wire.count ? DMP_OK : DMP_INCOMPLETE) == 0);
    }
    CHECK(receiver.assembled == 1U);
    CHECK(receiver.assembled_bytes == sizeof body);
    CHECK(memcmp(receiver.assembled_payload, body, sizeof body) == 0);

    /* Exchange the receiver's terminal receipt and verify reliable DATA
     * delivery reaches the sender's terminal state. */
    for (i = 0U; i < 12U && sender.data_delivered == 0U; i++) {
        size_t j;
        dmp_time_ms at = repair_at + i;
        sender.wire.now = at;
        receiver.wire.now = at;
        CHECK(dmp_endpoint_poll(&receiver.endpoint, at) == DMP_OK);
        for (j = 0U; j < receiver.wire.count; j++) {
            CHECK(dmp_endpoint_rx_packet(&sender.endpoint,
                                         span(receiver.wire.packets[j].bytes,
                                              receiver.wire.packets[j].size),
                                         at) == DMP_OK);
        }
        receiver.wire.count = 0U;
        CHECK(dmp_endpoint_poll(&sender.endpoint, at) == DMP_OK);
    }
    CHECK(sender.data_delivered == 1U);
    CHECK(state->live == 0U || state->phase == DMP_REL_PHASE_TERMINAL);
#if defined(DMP_NONE_MANIFEST_PROBE)
    (void)printf("RADIO-1 NONE %s\n", DMP_NONE_MANIFEST_SHA256);
#endif
    return 0;
}

#if defined(ESP_PLATFORM)
void app_main(void)
{
    if (test_selective_repair_none() != 0) {
        abort();
    }
}
#else
int main(void)
{
    return test_selective_repair_none();
}
#endif
