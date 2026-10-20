#include "dmp/core.h"
#include "dmp/endpoint.h"
#include "dmp/integrity.h"
#include "sample1_endpoint.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,     \
                          __LINE__, #condition);                                \
            return 1;                                                           \
        }                                                                       \
    } while (0)

enum {
    MAX_PEERS = 16,
    MESSAGE_BYTES = 1024,
    ENCODED_MTU = 263,
    SENDER_SLOTS = 4,
    RESULT_SLOTS = 4,
    HISTORY_SLOTS = 8,
    CORRELATION_SLOTS = 4,
    ADAPTER_SLOTS = 3,
    TOMBSTONES_PER_PEER = 1
};

typedef struct {
    dmp_endpoint endpoint;
    dmp_endpoint_peer_state peers[MAX_PEERS];
    dmp_identity_slot identities[MAX_PEERS * 2];
    dmp_reliability_sender_slot senders[SENDER_SLOTS];
    uint8_t sender_payload[SENDER_SLOTS * MESSAGE_BYTES];
    dmp_reliability_result_slot results[RESULT_SLOTS];
    uint8_t result_payload[RESULT_SLOTS * MESSAGE_BYTES];
    dmp_reliability_history_slot history[HISTORY_SLOTS];
    dmp_reliability_correlation_slot correlations[CORRELATION_SLOTS];
    uint8_t history_metadata[HISTORY_SLOTS * DMP_MAX_HEADER_BYTES];
    uint8_t correlation_metadata[CORRELATION_SLOTS * DMP_MAX_HEADER_BYTES];
    dmp_reliability_adapter_slot adapters[ADAPTER_SLOTS];
    uint8_t frames[ADAPTER_SLOTS * ENCODED_MTU];
    uint8_t receive_payload[ADAPTER_SLOTS * MESSAGE_BYTES];
    dmp_reassembly_slot assemblies[MAX_PEERS];
    dmp_reassembly_tombstone tombstones[MAX_PEERS];
    uint8_t assembly_payload[MAX_PEERS * MESSAGE_BYTES];
    uint8_t assembly_metadata[MAX_PEERS * DMP_MAX_HEADER_BYTES];
    uint8_t fragment_message[MAX_PEERS * MESSAGE_BYTES];
    uint8_t fragment_frame[ENCODED_MTU];
    uint8_t telemetry_payload[MAX_PEERS * MESSAGE_BYTES];
    uint8_t telemetry_next[MAX_PEERS * MESSAGE_BYTES];
    uint8_t telemetry_frame[ENCODED_MTU];
    dmp_admitted_profile profile;
    dmp_transport transport;
} fixture;

static dmp_status discard_submit(void *user, const dmp_tx_submission *submission)
{
    (void)user;
    (void)submission;
    return DMP_OK;
}

static dmp_status discard_cancel(void *user, dmp_tx_token token)
{
    (void)user;
    (void)token;
    return DMP_OK;
}

static void discard_notice(void *user, const dmp_endpoint_notice *notice)
{
    (void)user;
    (void)notice;
}

static void make_profile(dmp_config *profile, uint32_t peers)
{
    (void)memset(profile, 0, sizeof *profile);
    profile->namespace_id = 1U;
    profile->node_id[0] = 10U;
    profile->node_id[1] = 20U;
    profile->default_service = 1U;
    profile->service_id[0] = 1U;
    profile->service_id[1] = 2U;
    profile->recovery[0] = DMP_PROFILE_RECOVERY_RETRY_ALL;
    profile->recovery[1] = DMP_PROFILE_RECOVERY_RETRY_ALL;
    profile->security_mode = DMP_PROFILE_SECURITY_NONE;
    profile->peers = peers;
    profile->operations_per_service = peers;
    profile->assemblies_per_peer = 1U;
    profile->assembly_tombstones_per_peer = TOMBSTONES_PER_PEER;
    profile->sender_slots = SENDER_SLOTS;
    profile->assembly_slots = peers;
    profile->assembly_tombstone_slots = peers * TOMBSTONES_PER_PEER;
    profile->result_slots = RESULT_SLOTS;
    profile->history_slots = HISTORY_SLOTS;
    profile->correlation_slots = CORRELATION_SLOTS;
    profile->adapter_slots = ADAPTER_SLOTS;
    profile->application_queue_slots = 2U;
    profile->control_slots = 2U;
    profile->message_bytes = MESSAGE_BYTES;
    profile->fragments = 16U;
    profile->chunk_bytes = 64U;
    profile->encoded_mtu = ENCODED_MTU;
    profile->frame_tx_ms = 1U;
    profile->forward_mtu = 256U;
    profile->return_mtu = 256U;
    profile->forward_delay_ms = 20U;
    profile->return_delay_ms = 20U;
    profile->record_margin_ms = 5U;
    profile->queue_ms = 64U;
    profile->response_timeout_ms = 1280U;
    profile->send_horizon_ms = 5632U;
    profile->max_bursts = 3U;
    profile->receipt_delay_ms = 110U;
    profile->receipt_limit = 3U;
    profile->dedup_ms = 6000U;
    profile->rejection_ms = 6000U;
    profile->result_cache_ms = 6000U;
    profile->result_deadline_ms = 12000U;
    profile->correlation_ms = 12288U;
    profile->tombstone_ms = 12288U;
    profile->late_result_ms = 64U;
    profile->collect_ms = 5652U;
    profile->assembly_ms = 5657U;
    profile->tx_borrow = true;
    profile->synchronous_completion = true;
}

static dmp_identity_context_config context_for(uint32_t peer_origin)
{
    dmp_identity_context_config context;
    (void)memset(&context, 0, sizeof context);
    context.local.namespace_id = 1U;
    context.local.origin_id = 10U;
    context.local.epoch = 7U;
    context.peer.namespace_id = 1U;
    context.peer.origin_id = peer_origin;
    context.peer.epoch = 1000U + peer_origin;
    context.security = 0U;
    return context;
}

static int boot(fixture *f, uint32_t peers)
{
    dmp_config input;
    dmp_endpoint_storage storage;
    dmp_identity_context_config initial = context_for(20U);
    (void)memset(f, 0, sizeof *f);
    make_profile(&input, peers);
    CHECK(dmp_config_admit(&input, &f->profile) == DMP_OK);
    f->transport.submit = discard_submit;
    f->transport.cancel = discard_cancel;
    f->transport.caps.max_frame_bytes = ENCODED_MTU;
    f->transport.caps.ownership = DMP_TX_BORROW;
    f->transport.caps.synchronous_completion = true;
    (void)memset(&storage, 0, sizeof storage);
    storage.profile = &f->profile;
    storage.framing_mode = DMP_ENDPOINT_FRAMING_PACKET;
    storage.peer_states = f->peers;
    storage.peer_state_capacity = peers;
    storage.identity_slots = f->identities;
    storage.identity_capacity = peers * 2U;
    storage.context = initial;
    storage.transport = &f->transport;
    storage.notice = discard_notice;
    storage.senders = f->senders;
    storage.sender_capacity = SENDER_SLOTS;
    storage.sender_payload = f->sender_payload;
    storage.sender_payload_capacity = sizeof f->sender_payload;
    storage.results = f->results;
    storage.result_capacity = RESULT_SLOTS;
    storage.result_payload = f->result_payload;
    storage.result_payload_capacity = sizeof f->result_payload;
    storage.history = f->history;
    storage.history_capacity = HISTORY_SLOTS;
    storage.correlations = f->correlations;
    storage.correlation_capacity = CORRELATION_SLOTS;
    storage.history_metadata = f->history_metadata;
    storage.history_metadata_capacity = sizeof f->history_metadata;
    storage.correlation_metadata = f->correlation_metadata;
    storage.correlation_metadata_capacity = sizeof f->correlation_metadata;
    storage.adapters = f->adapters;
    storage.adapter_capacity = ADAPTER_SLOTS;
    storage.frames = f->frames;
    storage.frame_capacity = sizeof f->frames;
    storage.receive_payload = f->receive_payload;
    storage.receive_payload_capacity = sizeof f->receive_payload;
    storage.assemblies = f->assemblies;
    storage.assembly_capacity = peers;
    storage.tombstones = f->tombstones;
    storage.tombstone_capacity = peers;
    storage.assembly_payload = f->assembly_payload;
    storage.assembly_payload_capacity = sizeof f->assembly_payload;
    storage.assembly_metadata = f->assembly_metadata;
    storage.assembly_metadata_capacity = sizeof f->assembly_metadata;
    storage.fragment_message = f->fragment_message;
    storage.fragment_message_capacity = sizeof f->fragment_message;
    storage.fragment_frame = f->fragment_frame;
    storage.fragment_frame_capacity = sizeof f->fragment_frame;
    storage.telemetry_payload = f->telemetry_payload;
    storage.telemetry_payload_capacity = sizeof f->telemetry_payload;
    storage.telemetry_next = f->telemetry_next;
    storage.telemetry_next_capacity = sizeof f->telemetry_next;
    storage.telemetry_frame = f->telemetry_frame;
    storage.telemetry_frame_capacity = sizeof f->telemetry_frame;
    CHECK(dmp_endpoint_init(&f->endpoint, &storage, 100U) == DMP_OK);
    return 0;
}

static int test_capacity(uint32_t peers)
{
    fixture f;
    dmp_peer_handle admitted[MAX_PEERS];
    dmp_identity_context_config context;
    dmp_status status;
    uint32_t i;
    CHECK(peers == 1U || peers == 5U || peers == MAX_PEERS);
    CHECK(boot(&f, peers) == 0);
    CHECK(f.endpoint.profile.security_mode == DMP_PROFILE_SECURITY_NONE);
    CHECK(f.endpoint.peer_count == 1U);
    for (i = 1U; i < peers; i++) {
        context = context_for(100U + i);
        status = dmp_endpoint_add_peer(&f.endpoint, &context, 101U + i, &admitted[i]);
        CHECK(status == DMP_OK);
        CHECK(admitted[i].slot == i);
        CHECK(f.endpoint.peer_count == i + 1U);
    }
    admitted[0] = f.endpoint.peers[0].handle;
    if (peers > 1U) {
        dmp_peer_handle replacement;
        dmp_reliability_handle work;
        dmp_identity_context_config wrong_epoch;
        uint8_t body = 0x5aU;
        uint32_t active_senders = 0U;
        context = context_for(101U);
        status = dmp_endpoint_replace_none_peer_context(
            &f.endpoint, admitted[0], &context, 201U, &replacement);
        CHECK(status == DMP_DUPLICATE);
        CHECK(f.endpoint.peers[0].live != 0U);
        CHECK(f.endpoint.peers[0].handle.generation == admitted[0].generation);
        CHECK(f.endpoint.peer_count == peers);

        CHECK(dmp_endpoint_submit_data_to(&f.endpoint, admitted[0], 2U,
                                          (dmp_bytes){&body, 1U},
                                          (dmp_bytes){NULL, 0U}, 210U, &work) == DMP_OK);
        for (i = 0U; i < SENDER_SLOTS; i++) {
            active_senders += f.senders[i].live != 0U ? 1U : 0U;
        }
        CHECK(active_senders != 0U);
        wrong_epoch = context_for(501U);
        wrong_epoch.local.epoch = 8U;
        status = dmp_endpoint_replace_none_peer_context(
            &f.endpoint, admitted[0], &wrong_epoch, 220U, &replacement);
        CHECK(status == DMP_INVALID_ARGUMENT);
        CHECK(f.endpoint.peer_count == peers);
        CHECK(f.endpoint.peers[0].live != 0U);
        CHECK(f.endpoint.peers[0].handle.slot == admitted[0].slot);
        CHECK(f.endpoint.peers[0].handle.generation == admitted[0].generation);
        {
            uint32_t after_senders = 0U;
            for (i = 0U; i < SENDER_SLOTS; i++) {
                after_senders += f.senders[i].live != 0U ? 1U : 0U;
            }
            CHECK(after_senders == active_senders);
        }
    }
    context = context_for(500U);
    status = dmp_endpoint_add_peer(&f.endpoint, &context, 200U, &admitted[0]);
    CHECK(status == DMP_QUOTA_EXHAUSTED);
    CHECK(f.endpoint.peer_count == peers);
    return 0;
}

static int test_unknown_traffic(void)
{
    fixture f;
    dmp_frame_spec spec;
    dmp_core_limits limits;
    dmp_buffer output;
    dmp_bytes empty = {NULL, 0U};
    uint8_t ext[] = {15U, 1U, 99U}; /* ORIGIN_ID, origin 99, not the configured peer. */
    uint8_t trailer[4] = {0U, 0U, 0U, 0U};
    uint8_t frame[ENCODED_MTU];
    size_t written = 0U;
    uint32_t crc;
    dmp_status status;
    CHECK(boot(&f, 5U) == 0);
    (void)memset(&spec, 0, sizeof spec);
    spec.fields.type = DMP_TYPE_REQ;
    spec.fields.options = DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_INTEGRITY | DMP_OPT_EXT;
    spec.fields.seq = 1U;
    spec.fields.integrity = 1U;
    spec.extensions.data = ext;
    spec.extensions.size = sizeof ext;
    spec.payload = empty;
    spec.trailer.data = trailer;
    spec.trailer.size = sizeof trailer;
    limits.max_frame_bytes = sizeof frame;
    limits.max_message_bytes = MESSAGE_BYTES;
    limits.max_fragments = 16U;
    output.data = frame;
    output.capacity = sizeof frame;
    CHECK(dmp_core_encode(&spec, &limits, output, &written) == DMP_OK);
    CHECK(written >= sizeof trailer);
    CHECK(dmp_crc32c((dmp_bytes){frame, written - sizeof trailer}, &crc) == DMP_OK);
    frame[written - 4U] = (uint8_t)crc;
    frame[written - 3U] = (uint8_t)(crc >> 8U);
    frame[written - 2U] = (uint8_t)(crc >> 16U);
    frame[written - 1U] = (uint8_t)(crc >> 24U);
    status = dmp_endpoint_rx_packet_from(&f.endpoint, (dmp_peer_handle){0U, 1U},
                                         (dmp_bytes){frame, written}, 300U);
    CHECK(status == DMP_CONTEXT_REQUIRED);
    CHECK(f.endpoint.peer_count == 1U);
    CHECK(f.endpoint.peers[1].live == 0U);
    return 0;
}

static int report_layout(uint32_t peers)
{
    fixture f;
    size_t fixed_bytes;
    size_t per_peer_bytes;
    size_t configured_endpoint_bytes;
    CHECK(peers == 1U || peers == 5U || peers == MAX_PEERS);
    CHECK(boot(&f, peers) == 0);
    fixed_bytes = sizeof(f.endpoint) + sizeof(f.profile) + sizeof(f.transport) +
                  sizeof(f.senders) + sizeof(f.sender_payload) + sizeof(f.results) +
                  sizeof(f.result_payload) + sizeof(f.history) +
                  sizeof(f.correlations) + sizeof(f.history_metadata) +
                  sizeof(f.correlation_metadata) + sizeof(f.adapters) +
                  sizeof(f.frames) + sizeof(f.receive_payload) +
                  sizeof(f.fragment_frame) + sizeof(f.telemetry_frame);
    per_peer_bytes = sizeof(dmp_endpoint_peer_state) +
                     2U * sizeof(dmp_identity_slot) +
                     sizeof(dmp_reassembly_slot) +
                     TOMBSTONES_PER_PEER * sizeof(dmp_reassembly_tombstone) +
                     MESSAGE_BYTES + DMP_MAX_HEADER_BYTES + MESSAGE_BYTES +
                     MESSAGE_BYTES + MESSAGE_BYTES;
    configured_endpoint_bytes = fixed_bytes + peers * per_peer_bytes;
    (void)printf("NONE host layout: peers=%u, sizeof(dmp_endpoint)=%zu, "
                 "sizeof(peer_state)=%zu, sizeof(identity_slot)=%zu, "
                 "sizeof(sample1_peer_epoch)=%zu, fixed_endpoint_bytes=%zu, "
                 "per_peer_endpoint_bytes=%zu, configured_endpoint_bytes=%zu, "
                 "fixture_actual_bytes=%zu, sample1_control_bytes=%zu, "
                 "sample1_peer_table_bytes=%zu\n",
                 peers, sizeof(dmp_endpoint), sizeof(dmp_endpoint_peer_state),
                 sizeof(dmp_identity_slot), sizeof(dmp_sample1_peer_epoch),
                 fixed_bytes, per_peer_bytes, configured_endpoint_bytes,
                 sizeof(f), sizeof(dmp_sample1_endpoint),
                 peers * sizeof(dmp_sample1_peer_epoch));
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        (void)fprintf(stderr, "usage: %s <5|16|unknown>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "5") == 0) {
        return test_capacity(5U);
    }
    if (strcmp(argv[1], "1") == 0) {
        return test_capacity(1U);
    }
    if (strcmp(argv[1], "16") == 0) {
        return test_capacity(MAX_PEERS);
    }
    if (strcmp(argv[1], "unknown") == 0) {
        return test_unknown_traffic();
    }
    if (strcmp(argv[1], "layout5") == 0) {
        return report_layout(5U);
    }
    if (strcmp(argv[1], "layout16") == 0) {
        return report_layout(MAX_PEERS);
    }
    return 2;
}
