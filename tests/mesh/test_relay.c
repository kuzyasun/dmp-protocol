#include "dmp/endpoint.h"
#include "dmp/mesh.h"
#include "dmp/stream.h"
#include "harness.h"
#include "replay_window.h"

#include <stdio.h>
#include <string.h>

/* RADIO-1 schedule and relay row, copied as admitted numbers. Not a JSON parse. */
enum {
    RADIO_QUEUE_MS = 64,
    RADIO_FORWARD_DELAY_MS = 20,
    RADIO_RETURN_DELAY_MS = 20,
    RADIO_COOLDOWN_MS = 50,
    RADIO_EXPIRY_MS = 20000,
    RADIO_MAX_FORWARDS = 12,
    RADIO_FRAME_TX_MS = 1,
    RADIO_ORIGIN_AIRTIME_MS = 10000,
    RADIO_GLOBAL_AIRTIME_MS = 20000,
    RADIO_PERIOD_MS = 64,
    RADIO_WIDTH_MS = 42,
    RADIO_MTU = 256,
    RADIO_MESSAGE = 64
};

static int failures = 0;

static void check(int cond, const char *text, int line)
{
    if (!cond) {
        fprintf(stderr, "fail %s:%d %s\n", "test_relay.c", line, text);
        failures++;
    }
}

#define CHECK(cond)                                                                                 \
    do {                                                                                            \
        check((cond), #cond, __LINE__);                                                            \
        if (failures != 0) {                                                                        \
            return failures;                                                                        \
        }                                                                                           \
    } while (0)

static size_t put_uleb(uint8_t *out, size_t cap, size_t at, uint32_t value)
{
    do {
        uint8_t byte = (uint8_t)(value & 0x7fU);
        value >>= 7U;
        if (value != 0U) {
            byte = (uint8_t)(byte | 0x80U);
        }
        if (at < cap) {
            out[at++] = byte;
        }
    } while (value != 0U);
    return at;
}

static void fill_profile(dmp_config *in)
{
    memset(in, 0, sizeof *in);
    in->namespace_id = 1U;
    in->node_id[0] = 10U;
    in->node_id[1] = 20U;
    in->default_service = 1U;
    in->service_id[0] = 1U;
    in->service_id[1] = 2U;
    in->recovery[0] = DMP_PROFILE_RECOVERY_SELECTIVE32;
    in->recovery[1] = DMP_PROFILE_RECOVERY_SELECTIVE32;
    in->peers = 1U;
    in->operations_per_service = 1U;
    in->assemblies_per_peer = 1U;
    in->assembly_tombstones_per_peer = 1U;
    in->sender_slots = 2U;
    in->assembly_slots = 1U;
    in->assembly_tombstone_slots = 1U;
    in->result_slots = 2U;
    in->history_slots = 2U;
    in->correlation_slots = 2U;
    in->adapter_slots = 4U;
    in->application_queue_slots = 2U;
    in->control_slots = 2U;
    in->message_bytes = RADIO_MESSAGE;
    in->fragments = 32U;
    in->chunk_bytes = 32U;
    in->encoded_mtu = RADIO_MTU;
    in->forward_mtu = RADIO_MTU;
    in->return_mtu = RADIO_MTU;
    in->queue_ms = RADIO_QUEUE_MS;
    in->response_timeout_ms = 2304U;
    in->jitter_ms = 0U;
    in->send_horizon_ms = 10752U;
    in->max_bursts = 3U;
    in->receipt_delay_ms = 110U;
    in->receipt_limit = 3U;
    in->dedup_ms = 11000U;
    in->rejection_ms = 11000U;
    in->result_cache_ms = 11000U;
    in->result_deadline_ms = 22000U;
    in->correlation_ms = 23040U;
    in->tombstone_ms = 23040U;
    in->late_result_ms = 64U;
    in->collect_ms = 10772U;
    in->assembly_ms = 10777U;
    in->burst_span_ms = 2048U;
    in->forward_delay_ms = RADIO_FORWARD_DELAY_MS;
    in->return_delay_ms = RADIO_RETURN_DELAY_MS;
    in->feedback_guard_ms = 4U;
    in->feedback_delay_ms = 110U;
    in->max_probes = 2U;
    in->max_status = 3U;
    in->record_margin_ms = 5U;
    in->tx_borrow = true;
    in->synchronous_completion = true;
}

static int build_frame(uint8_t *out, size_t cap, size_t *written, uint32_t seq, uint8_t ttl,
                       uint32_t source, uint32_t dest, uint64_t pn, int fragmented,
                       const uint8_t *payload, size_t payload_n)
{
    uint8_t ext[24];
    uint8_t context[9];
    uint8_t tag[16];
    dmp_frame_spec spec;
    dmp_core_limits limits;
    size_t n = 0U;
    unsigned i;
    memset(context, 0, sizeof context);
    context[0] = 1U;
    context[1] = 0x08U;
    for (i = 0U; i < sizeof tag; i++) {
        tag[i] = (uint8_t)(0xC0U + i);
    }
    n = put_uleb(ext, sizeof ext, 0U, 11U);
    n = put_uleb(ext, sizeof ext, n, 9U);
    memcpy(ext + n, context, sizeof context);
    n += sizeof context;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_DATA;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ROUTE | DMP_OPT_SECURITY | DMP_OPT_EXT);
    spec.fields.seq = seq;
    spec.fields.route.ttl = ttl;
    spec.fields.route.mode = 1U;
    spec.fields.route.source = source;
    spec.fields.route.destination = dest;
    spec.fields.security.cipher = 1U;
    spec.fields.security.receive_cid = 7U;
    spec.fields.security.pn = pn;
    if (fragmented) {
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_FRAG);
        spec.fields.fragment.index = 0U;
        spec.fields.fragment.chunk_size = 32U;
        spec.fields.fragment.total_size = 64U;
    }
    spec.extensions.data = ext;
    spec.extensions.size = n;
    spec.payload.data = payload;
    spec.payload.size = payload_n;
    spec.trailer.data = tag;
    spec.trailer.size = sizeof tag;
    limits.max_frame_bytes = RADIO_MTU;
    limits.max_message_bytes = RADIO_MESSAGE;
    limits.max_fragments = 32U;
    return dmp_core_encode(&spec, &limits, (dmp_buffer){out, cap}, written) == DMP_OK;
}

static int differs_only_by_ttl(const uint8_t *before, const uint8_t *after, size_t n)
{
    size_t i;
    size_t diffs = 0U;
    for (i = 0U; i < n; i++) {
        if (before[i] != after[i]) {
            if ((before[i] & 0x0fU) != (after[i] & 0x0fU) || before[i] - after[i] != 0x10U) {
                return 0;
            }
            diffs++;
        }
    }
    return diffs == 1U;
}

static size_t occupied(const dmp_mesh_cache_slot *cache, size_t n)
{
    size_t i;
    size_t count = 0U;
    for (i = 0U; i < n; i++) {
        if (cache[i].occupied) {
            count++;
        }
    }
    return count;
}

static int notices = 0;

static void on_tx(void *owner, dmp_tx_token token, dmp_tx_outcome outcome, dmp_time_ms when)
{
    (void)owner;
    (void)token;
    (void)outcome;
    (void)when;
}

static void on_notice(void *user, const dmp_endpoint_notice *notice)
{
    (void)user;
    (void)notice;
    notices++;
}

static int run(void)
{
    dmp_config input;
    dmp_admitted_profile admitted;
    dmp_mesh_route routes[2];
    dmp_mesh_cache_slot cache[8];
    dmp_mesh_airtime airtime[4];
    dmp_mesh_relay relay;
    dmp_mesh_forward_in req;
    dmp_mesh_forward_out fwd;
    dmp_core_limits limits;
    dmp_frame_view parsed;
    dmp_parse_result result;
    uint8_t payload[4] = {0x11U, 0x22U, 0x33U, 0x44U};
    uint8_t frag_payload[32];
    uint8_t frame[RADIO_MTU];
    uint8_t outbuf[RADIO_MTU];
    uint8_t high[RADIO_MTU];
    uint8_t sentinel[RADIO_MTU];
    size_t frame_n = 0U;
    size_t high_n = 0U;
    size_t frag_n = 0U;
    size_t slots_before;
    dmp_time_ms expires_at = 0U;
    unsigned step;
    harness_binding binding;
    harness_adapter *adapter;
    dmp_transport *transport;
    dmp_tx_submission submission;
    dmp_replay_window replay;
    dmp_replay_window replay_before;
    dmp_endpoint endpoint;
    dmp_endpoint_storage storage;
    dmp_identity_slot ids[2];
    dmp_identity_slot id_before;
    dmp_reliability_sender_slot senders[2];
    dmp_reliability_sender_slot sender_before;
    dmp_reliability_result_slot results[2];
    dmp_reliability_history_slot history[2];
    dmp_reliability_correlation_slot correlations[2];
    dmp_reliability_adapter_slot adapters[4];
    dmp_reassembly_slot assemblies[1];
    dmp_reassembly_slot assembly_before;
    dmp_reassembly_tombstone tombstones[1];
    uint8_t sender_payload[2 * RADIO_MESSAGE];
    uint8_t result_payload[2 * RADIO_MESSAGE];
    uint8_t history_metadata[2 * DMP_RELIABILITY_METADATA_BYTES];
    uint8_t correlation_metadata[2 * DMP_RELIABILITY_METADATA_BYTES];
    uint8_t frames[4 * RADIO_MTU];
    uint8_t receive_payload[RADIO_MESSAGE];
    uint8_t assembly_payload[RADIO_MESSAGE];
    uint8_t assembly_metadata[DMP_REASSEMBLY_METADATA_BYTES];
    uint8_t fragment_message[RADIO_MESSAGE];
    uint8_t fragment_frame[RADIO_MTU];
    uint8_t telemetry_payload[RADIO_MESSAGE];
    uint8_t telemetry_next[RADIO_MESSAGE];
    uint8_t telemetry_frame[RADIO_MTU];
    uint8_t stream_tx[1024];
    uint8_t stream_rx[1024];
    size_t stream_bound = 0U;
    harness_adapter *endpoint_adapter;
    dmp_transport *endpoint_transport;

    memset(frag_payload, 0x5AU, sizeof frag_payload);
    fill_profile(&input);
    CHECK(dmp_config_admit(&input, &admitted) == DMP_OK);
    CHECK(admitted.jitter_ms == 0U);
    CHECK(admitted.recovery[0] == DMP_PROFILE_RECOVERY_SELECTIVE32);
    CHECK(admitted.forward_delay_ms == RADIO_FORWARD_DELAY_MS);
    CHECK(admitted.return_delay_ms == RADIO_RETURN_DELAY_MS);

    routes[0].destination = 20U;
    routes[0].next_hop = 40U;
    routes[1].destination = 10U;
    routes[1].next_hop = 10U;
    memset(&relay, 0, sizeof relay);
    relay.profile = &admitted;
    relay.self_node = 30U;
    relay.pn_filter = DMP_MESH_PN_REJECT_GE_2POW24;
    relay.cooldown_ms = RADIO_COOLDOWN_MS;
    relay.expiry_ms = RADIO_EXPIRY_MS;
    relay.max_forwards_per_key = RADIO_MAX_FORWARDS;
    relay.frame_tx_ms = RADIO_FRAME_TX_MS;
    relay.per_origin_airtime_ms = RADIO_ORIGIN_AIRTIME_MS;
    relay.global_airtime_ms = RADIO_GLOBAL_AIRTIME_MS;
    relay.return_period_ms = RADIO_PERIOD_MS;
    relay.return_width_ms = RADIO_WIDTH_MS;
    relay.routes = routes;
    relay.route_count = 2U;
    relay.cache = cache;
    relay.cache_count = 8U;
    relay.airtime = airtime;
    relay.airtime_count = 4U;
    CHECK(dmp_mesh_relay_init(&relay) == DMP_OK);
    {
        dmp_admitted_profile jittered = admitted;
        dmp_mesh_cache_slot one_cache;
        dmp_mesh_airtime one_air;
        dmp_mesh_relay probe = relay;
        jittered.jitter_ms = 1U;
        probe.profile = &jittered;
        probe.cache = &one_cache;
        probe.cache_count = 1U;
        probe.airtime = &one_air;
        probe.airtime_count = 1U;
        CHECK(dmp_mesh_relay_init(&probe) == DMP_UNSUPPORTED);
    }

    CHECK(build_frame(frame, sizeof frame, &frame_n, 1U, 2U, 10U, 20U, 4U, 0, payload,
                      sizeof payload));
    memset(&req, 0, sizeof req);
    req.direction = DMP_MESH_FORWARD;
    req.now = 0U;
    req.tx_complete_at = RADIO_FRAME_TX_MS;
    req.frame.data = frame;
    req.frame.size = frame_n;
    req.limits.max_frame_bytes = RADIO_MTU;
    req.limits.max_message_bytes = RADIO_MESSAGE;
    req.limits.max_fragments = 32U;
    memset(&fwd, 0, sizeof fwd);
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) == DMP_OK);
    CHECK(fwd.next_hop == 40U);
    CHECK(fwd.transmit_at == 0U);
    CHECK(fwd.written == frame_n);
    CHECK(differs_only_by_ttl(frame, outbuf, frame_n));
    limits = req.limits;
    result = dmp_core_parse((dmp_bytes){outbuf, fwd.written}, &limits, &parsed);
    CHECK(result.status == DMP_OK);
    CHECK(parsed.fields.route.ttl == 1U);
    CHECK(parsed.fields.route.mode == 1U);
    CHECK(parsed.fields.route.source == 10U);
    CHECK(parsed.fields.route.destination == 20U);
    CHECK(parsed.fields.seq == 1U);
    CHECK(parsed.fields.security.pn == 4U);
    CHECK(parsed.fields.security.receive_cid == 7U);
    CHECK(parsed.payload.size == sizeof payload);
    CHECK(memcmp(parsed.payload.data, payload, sizeof payload) == 0);
    CHECK(parsed.trailer.size == 16U);
    CHECK(memcmp(parsed.trailer.data, frame + frame_n - 16U, 16U) == 0);
    expires_at = cache[0].expires_at;
    CHECK(expires_at == RADIO_EXPIRY_MS);

    req.now = RADIO_FRAME_TX_MS + RADIO_COOLDOWN_MS - 1U;
    req.tx_complete_at = RADIO_PERIOD_MS + RADIO_FRAME_TX_MS;
    memset(sentinel, 0xA5, sizeof sentinel);
    memcpy(outbuf, sentinel, sizeof outbuf);
    fwd.written = 99U;
    fwd.transmit_at = 99U;
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) == DMP_BUSY);
    CHECK(fwd.written == 99U);
    CHECK(memcmp(outbuf, sentinel, sizeof outbuf) == 0);
    CHECK(cache[0].expires_at == expires_at);
    CHECK(cache[0].forwards == 1U);
    CHECK(cache[0].last_completion == RADIO_FRAME_TX_MS);

    req.now = RADIO_PERIOD_MS;
    req.tx_complete_at = req.now + RADIO_FRAME_TX_MS;
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) == DMP_OK);
    CHECK(differs_only_by_ttl(frame, outbuf, frame_n));
    CHECK(cache[0].expires_at == expires_at);
    CHECK(cache[0].forwards == 2U);

    req.now = expires_at;
    if (req.now % RADIO_PERIOD_MS != 0U) {
        req.now += RADIO_PERIOD_MS - (req.now % RADIO_PERIOD_MS);
    }
    req.tx_complete_at = req.now + RADIO_FRAME_TX_MS;
    memcpy(outbuf, sentinel, sizeof outbuf);
    fwd.written = 99U;
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) ==
          DMP_DEADLINE_EXPIRED);
    CHECK(memcmp(outbuf, sentinel, sizeof outbuf) == 0);
    CHECK(cache[0].expires_at == expires_at);
    CHECK(cache[0].forwards == 2U);

    CHECK(build_frame(frame, sizeof frame, &frame_n, 3U, 2U, 20U, 10U, 8U, 0, payload,
                      sizeof payload));
    req.direction = DMP_MESH_RETURN;
    req.now = 10U;
    req.source_start_ms = 0U;
    req.return_slot = 1U;
    req.tx_complete_at = 22U + RADIO_FRAME_TX_MS;
    req.frame.data = frame;
    req.frame.size = frame_n;
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) == DMP_OK);
    CHECK(fwd.transmit_at == 22U);
    CHECK(fwd.next_hop == 10U);
    CHECK(differs_only_by_ttl(frame, outbuf, frame_n));
    result = dmp_core_parse((dmp_bytes){outbuf, fwd.written}, &limits, &parsed);
    CHECK(result.status == DMP_OK);
    CHECK(memcmp(parsed.payload.data, payload, sizeof payload) == 0);

    memset(&binding, 0, sizeof binding);
    binding.encoded_mtu = RADIO_MTU;
    binding.frame_tx_ms = RADIO_FRAME_TX_MS;
    binding.delay_ms[0] = admitted.forward_delay_ms;
    binding.delay_ms[1] = admitted.return_delay_ms;
    binding.period_ms = RADIO_PERIOD_MS;
    binding.width_ms = RADIO_WIDTH_MS;
    binding.queue_ms = admitted.queue_ms;
    binding.adapter_slots = 4U;
    binding.borrow = 1;
    binding.synchronous_completion = 1;
    binding.until_ms = 1000U;
    binding.seed = 1U;
    adapter = harness_adapter_create(&binding);
    CHECK(adapter != NULL);
    transport = harness_adapter_transport(adapter);
    memset(&submission, 0, sizeof submission);
    submission.frame.data = outbuf;
    submission.frame.size = fwd.written;
    submission.not_after = 1000U;
    submission.complete = on_tx;
    harness_adapter_set_now(adapter, 0U);
    harness_adapter_arm(adapter, 0U, 1U, 0, 0U, 0U, 0U, 0U, 0U, 0);
    CHECK(transport->submit(transport->context, &submission) == DMP_OK);
    submission.frame.data = outbuf;
    submission.frame.size = fwd.written;
    harness_adapter_set_now(adapter, 10U);
    harness_adapter_arm(adapter, 1U, 2U, 1, 1U, 1U, 0U, 0U, 0U, 0);
    CHECK(transport->submit(transport->context, &submission) == DMP_OK);
    harness_adapter_set_now(adapter, 23U);
    harness_adapter_arm(adapter, 1U, 3U, 1, 1U, 1U, 0U, 0U, 0U, 0);
    CHECK(transport->submit(transport->context, &submission) == DMP_BUSY);

    CHECK(build_frame(frame, sizeof frame, &frame_n, 13U, 2U, 20U, 10U, 9U, 0, payload, sizeof payload));
    req.now = 23U;
    req.tx_complete_at = 23U + RADIO_FRAME_TX_MS;
    req.frame.data = frame;
    req.frame.size = frame_n;
    memcpy(outbuf, sentinel, sizeof outbuf);
    fwd.written = 77U;
    fwd.transmit_at = 77U;
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) == DMP_BUSY);
    CHECK(fwd.transmit_at == 77U);
    CHECK(fwd.written == 77U);
    CHECK(memcmp(outbuf, sentinel, sizeof outbuf) == 0);

    slots_before = occupied(cache, 8U);
    CHECK(build_frame(high, sizeof high, &high_n, 4U, 2U, 10U, 20U, UINT64_C(1) << 24, 0, payload,
                      sizeof payload));
    memset(&endpoint, 0, sizeof endpoint);
    memset(&storage, 0, sizeof storage);
    CHECK(dmp_stream_encoded_bound(DMP_STREAM_R, admitted.encoded_mtu, &stream_bound) == DMP_OK);
    CHECK(stream_bound + 1U <= sizeof stream_tx);
    binding.encoded_mtu = (uint32_t)(stream_bound + 1U);
    endpoint_adapter = harness_adapter_create(&binding);
    CHECK(endpoint_adapter != NULL);
    endpoint_transport = harness_adapter_transport(endpoint_adapter);
    storage.profile = &admitted;
    storage.identity_slots = ids;
    storage.identity_capacity = 2U;
    storage.context.local.namespace_id = 1U;
    storage.context.local.origin_id = 10U;
    storage.context.local.epoch = 1U;
    storage.context.peer.namespace_id = 1U;
    storage.context.peer.origin_id = 20U;
    storage.context.peer.epoch = 2U;
    storage.context.security = 0U;
    storage.transport = endpoint_transport;
    storage.notice = on_notice;
    storage.senders = senders;
    storage.sender_capacity = 2U;
    storage.sender_payload = sender_payload;
    storage.sender_payload_capacity = sizeof sender_payload;
    storage.results = results;
    storage.result_capacity = 2U;
    storage.result_payload = result_payload;
    storage.result_payload_capacity = sizeof result_payload;
    storage.history = history;
    storage.history_capacity = 2U;
    storage.correlations = correlations;
    storage.correlation_capacity = 2U;
    storage.history_metadata = history_metadata;
    storage.history_metadata_capacity = sizeof history_metadata;
    storage.correlation_metadata = correlation_metadata;
    storage.correlation_metadata_capacity = sizeof correlation_metadata;
    storage.adapters = adapters;
    storage.adapter_capacity = 4U;
    storage.frames = frames;
    storage.frame_capacity = sizeof frames;
    storage.receive_payload = receive_payload;
    storage.receive_payload_capacity = sizeof receive_payload;
    storage.assemblies = assemblies;
    storage.assembly_capacity = 1U;
    storage.tombstones = tombstones;
    storage.tombstone_capacity = 1U;
    storage.assembly_payload = assembly_payload;
    storage.assembly_payload_capacity = sizeof assembly_payload;
    storage.assembly_metadata = assembly_metadata;
    storage.assembly_metadata_capacity = sizeof assembly_metadata;
    storage.fragment_message = fragment_message;
    storage.fragment_message_capacity = sizeof fragment_message;
    storage.fragment_frame = fragment_frame;
    storage.fragment_frame_capacity = sizeof fragment_frame;
    storage.telemetry_payload = telemetry_payload;
    storage.telemetry_payload_capacity = sizeof telemetry_payload;
    storage.telemetry_next = telemetry_next;
    storage.telemetry_next_capacity = sizeof telemetry_next;
    storage.telemetry_frame = telemetry_frame;
    storage.telemetry_frame_capacity = sizeof telemetry_frame;
    storage.stream_tx = stream_tx;
    storage.stream_tx_capacity = sizeof stream_tx;
    storage.stream_rx = stream_rx;
    storage.stream_rx_capacity = sizeof stream_rx;
    CHECK(dmp_endpoint_init(&endpoint, &storage, 0U) == DMP_OK);
    CHECK(dmp_endpoint_poll(&endpoint, 0U) == DMP_OK);
    id_before = ids[endpoint.context.slot];
    sender_before = senders[0];
    assembly_before = assemblies[0];
    dmp_replay_window_init(&replay, DMP_REPLAY_WINDOW_DEFAULT);
    replay_before = replay;
    req.direction = DMP_MESH_FORWARD;
    req.now = 0U;
    req.tx_complete_at = RADIO_FRAME_TX_MS;
    req.frame.data = high;
    req.frame.size = high_n;
    memcpy(outbuf, sentinel, sizeof outbuf);
    fwd.written = 55U;
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) ==
          DMP_LIMIT_EXHAUSTED);
    CHECK(fwd.written == 55U);
    CHECK(memcmp(outbuf, sentinel, sizeof outbuf) == 0);
    CHECK(occupied(cache, 8U) == slots_before);
    CHECK(memcmp(&ids[endpoint.context.slot], &id_before, sizeof id_before) == 0);
    CHECK(memcmp(&senders[0], &sender_before, sizeof sender_before) == 0);
    CHECK(memcmp(&assemblies[0], &assembly_before, sizeof assembly_before) == 0);
    CHECK(memcmp(&replay, &replay_before, sizeof replay) == 0);
    CHECK(notices == 0);
    CHECK(dmp_endpoint_poll(&endpoint, 1U) == DMP_OK);
    CHECK(notices == 0);
    CHECK(memcmp(&replay, &replay_before, sizeof replay) == 0);

    CHECK(build_frame(frame, sizeof frame, &frame_n, 5U, 2U, 10U, 20U, (UINT64_C(1) << 24) - 1U, 0,
                      payload, sizeof payload));
    req.frame.data = frame;
    req.frame.size = frame_n;
    req.now = 64U;
    req.tx_complete_at = 64U + RADIO_FRAME_TX_MS;
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) == DMP_OK);
    CHECK(fwd.transmit_at == 64U);
    CHECK(differs_only_by_ttl(frame, outbuf, frame_n));

    CHECK(build_frame(frame, sizeof frame, &frame_n, 9U, 2U, 10U, 20U, 1U, 0, payload, sizeof payload));
    req.frame.data = frame;
    req.frame.size = frame_n;
    for (step = 0U; step < RADIO_MAX_FORWARDS; step++) {
        req.now = (dmp_time_ms)step * RADIO_PERIOD_MS;
        req.tx_complete_at = req.now + RADIO_FRAME_TX_MS;
        CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) == DMP_OK);
        CHECK(fwd.transmit_at == req.now);
    }
    req.now = (dmp_time_ms)RADIO_MAX_FORWARDS * RADIO_PERIOD_MS;
    req.tx_complete_at = req.now + RADIO_FRAME_TX_MS;
    memcpy(outbuf, sentinel, sizeof outbuf);
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) ==
          DMP_QUOTA_EXHAUSTED);
    CHECK(memcmp(outbuf, sentinel, sizeof outbuf) == 0);

    CHECK(build_frame(frame, sizeof frame, &frag_n, 6U, 2U, 10U, 20U, 3U, 1, frag_payload,
                      sizeof frag_payload));
    req.frame.data = frame;
    req.frame.size = frag_n;
    req.now = 128U;
    req.tx_complete_at = 128U + RADIO_FRAME_TX_MS;
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) == DMP_OK);
    CHECK(differs_only_by_ttl(frame, outbuf, frag_n));
    result = dmp_core_parse((dmp_bytes){outbuf, fwd.written}, &limits, &parsed);
    CHECK(result.status == DMP_OK);
    CHECK(parsed.payload.size == sizeof frag_payload);
    CHECK(memcmp(parsed.payload.data, frag_payload, sizeof frag_payload) == 0);
    CHECK(build_frame(frame, sizeof frame, &frame_n, 6U, 2U, 10U, 20U, 3U, 0, payload, sizeof payload));
    req.frame.data = frame;
    req.frame.size = frame_n;
    memcpy(outbuf, sentinel, sizeof outbuf);
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) == DMP_MALFORMED);
    CHECK(memcmp(outbuf, sentinel, sizeof outbuf) == 0);

    req.now = 1U;
    req.tx_complete_at = 2U;
    CHECK(build_frame(frame, sizeof frame, &frame_n, 11U, 2U, 10U, 20U, 2U, 0, payload, sizeof payload));
    req.frame.data = frame;
    req.frame.size = frame_n;
    memcpy(outbuf, sentinel, sizeof outbuf);
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) ==
          DMP_INVALID_ARGUMENT);
    CHECK(memcmp(outbuf, sentinel, sizeof outbuf) == 0);
    req.tx_complete_at = 64U + RADIO_FRAME_TX_MS;
    CHECK(dmp_mesh_relay_forward(&relay, &req, (dmp_buffer){outbuf, sizeof outbuf}, &fwd) == DMP_OK);
    CHECK(fwd.transmit_at == 64U);

    harness_adapter_destroy(adapter);
    harness_adapter_destroy(endpoint_adapter);
    return failures;
}

int main(void)
{
    int result = run();
    if (result != 0) {
        fprintf(stderr, "relay failures %d\n", result);
        return 1;
    }
    return 0;
}
