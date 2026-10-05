/* Host loopback and one static relay. Not physical-transport evidence.
 * Faults are drops before dmp_endpoint_rx. The harness supplies the seed
 * helper only; it does not implement a second DMP state machine.
 */
#include "dmp/endpoint.h"
#include "dmp/mesh.h"
#include "dmp/stream.h"
#include "harness.h"
#include "handshake.h"
#include "noise_fixture_probe.h"
#include "opaque.h"
#include "sample1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition);  \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

enum {
    SENDERS = 4,
    RESULTS = 4,
    HISTORY = 8,
    CORRELATIONS = 4,
    ADAPTERS = 5,
    MESSAGE = 1024,
    MTU = 320,
    ASSEMBLIES = 1,
    TOMBSTONES = 16,
    STREAM_CAP = 640,
    QUEUE = 64,
    FRAME_CAP = 512,
    LOCAL_NS = 1,
    ID_INIT = 0x0a,
    ID_RESP = 0x14,
    CID_INIT = 7,
    CID_RESP = 9,
    KEY_HINT = 5,
    RADIO_COLLECT_MS = 2072,
    RADIO_RESPONSE_MS = 2304,
    RADIO_RECEIPT_MS = 110,
    RADIO_ASSEMBLY_MS = 10777,
    RADIO_RESULT_MS = 22000
};

enum { PROF_RADIO = 0, PROF_RETRY = 1, PROF_DIRECT = 2, PROF_RADIO_N2 = 3, PROF_DIRECT_ASYNC = 4 };

typedef struct node node;

typedef struct {
    int used;
    uint8_t frame[FRAME_CAP];
    size_t len;
} queued;

typedef struct {
    dmp_tx_complete_fn complete;
    void *owner;
    dmp_tx_token token;
} delayed_completion;

typedef struct {
    node *self;
    queued q[QUEUE];
    int n;
    uint32_t tx_bytes;
    uint32_t rx_bytes;
    dmp_time_ms now;
    delayed_completion delayed[QUEUE];
    int delayed_count;
    int defer_completion;
} wire;

typedef struct {
    int have_pending;
    dmp_reliability_handle pending;
    int accepts;
    int results;
    int assembled;
    int data_accepted;
    int data_delivered;
    int unknowns;
    int local_unsents;
    dmp_message_key unsent_key;
    size_t unsent_n;
    uint32_t service;
    uint8_t req_body[MESSAGE];
    size_t req_n;
    uint8_t asm_body[MESSAGE];
    size_t asm_n;
    uint8_t result_body[MESSAGE];
    size_t result_n;
    uint8_t grant_body[32];
    size_t grant_n;
    int grants;
    uint32_t wire_status;
} app;

struct node {
    dmp_endpoint endpoint;
    dmp_transport transport;
    wire wire;
    app app;
    dmp_identity_slot ids[2];
    dmp_endpoint_freshness_slot freshness[8];
    dmp_reliability_sender_slot senders[SENDERS];
    uint8_t sender_payload[SENDERS * MESSAGE];
    dmp_reliability_result_slot results[RESULTS];
    uint8_t result_payload[RESULTS * MESSAGE];
    dmp_reliability_history_slot history[HISTORY];
    dmp_reliability_correlation_slot correlations[CORRELATIONS];
    uint8_t history_metadata[HISTORY * DMP_RELIABILITY_METADATA_BYTES];
    uint8_t correlation_metadata[CORRELATIONS * DMP_RELIABILITY_METADATA_BYTES];
    dmp_reliability_adapter_slot adapters[ADAPTERS];
    uint8_t frames[ADAPTERS * MTU];
    uint8_t receive_payload[MESSAGE];
    dmp_reassembly_slot assemblies[ASSEMBLIES];
    dmp_reassembly_tombstone tombstones[TOMBSTONES];
    uint8_t assembly_payload[ASSEMBLIES * MESSAGE];
    uint8_t assembly_metadata[ASSEMBLIES * DMP_REASSEMBLY_METADATA_BYTES];
    uint8_t fragment_message[MESSAGE];
    uint8_t fragment_frame[MTU];
    uint8_t telemetry_payload[MESSAGE];
    uint8_t telemetry_next[MESSAGE];
    uint8_t telemetry_frame[MTU];
    uint8_t stream_tx[STREAM_CAP];
    uint8_t stream_rx[STREAM_CAP];
};

typedef struct {
    uint8_t frame[FRAME_CAP];
    size_t len;
    uint8_t type;
    uint32_t index;
} captured;

typedef struct {
    const uint8_t *data[16];
    size_t len[16];
    size_t count;
    size_t index;
} script;

typedef struct {
    int calls;
} store;

typedef struct {
    uint64_t *now;
    script *entropy_script;
    store *pin_store;
} box;

typedef struct {
    uint64_t now;
    script init_script;
    script resp_script;
    uint8_t token_entropy[2][6][16];
    store init_store;
    store resp_store;
    box init_box;
    box resp_box;
    dmp_provider *provider;
    dmp_hs *initiator;
    dmp_hs *responder;
} session;

typedef struct {
    unsigned alloc_calls;
    size_t live;
    size_t peak;
    size_t peak_one;
} port_ctx;

static node left;
static node right;
static uint32_t g_peak;
static uint32_t g_tx;
static uint32_t g_rx;
static size_t g_provider;
static int g_hold;

static const uint8_t RADIO_SHA[32] = {
    0xee, 0x9b, 0xc2, 0x81, 0x87, 0x46, 0x56, 0x3a,
    0xfd, 0x2a, 0x84, 0xb7, 0x21, 0x85, 0x9c, 0x4a,
    0xc7, 0xb9, 0x6c, 0xe9, 0xf9, 0x81, 0x95, 0xe0,
    0x9d, 0x90, 0x57, 0xa6, 0xf7, 0x1b, 0xfa, 0x73};
static const uint8_t RETRY_SHA[32] = {
    0x72, 0xad, 0xe6, 0x72, 0xa9, 0xa9, 0xe1, 0x42,
    0x91, 0x7a, 0x20, 0x1b, 0xab, 0xf9, 0xbe, 0xb4,
    0xb6, 0x99, 0x5e, 0x13, 0xb5, 0xfd, 0x25, 0xd6,
    0xc4, 0xb2, 0xab, 0xf8, 0xf4, 0x12, 0xe1, 0x90};
static const uint8_t DIRECT_SHA[32] = {
    0x83, 0xba, 0x9a, 0x49, 0x04, 0x9a, 0x0f, 0x5f,
    0x0f, 0x93, 0x87, 0x22, 0x9c, 0xba, 0x12, 0x60,
    0x9c, 0xcf, 0xa8, 0x68, 0xf4, 0xca, 0xb2, 0xb0,
    0x5f, 0x22, 0xf0, 0xcd, 0x96, 0x16, 0xc5, 0x48};
static const uint8_t N2_SHA[32] = {
    0xdd, 0xa9, 0xc4, 0x3b, 0xbf, 0xd7, 0xb0, 0x51,
    0x4b, 0x26, 0x3e, 0x15, 0xed, 0x7b, 0xcd, 0xc7,
    0xff, 0xe4, 0x50, 0x80, 0xfe, 0x0e, 0x74, 0xa0,
    0x7f, 0x49, 0x33, 0x73, 0x12, 0x0a, 0xdf, 0x84};
static const uint8_t ASYNC_SHA[32] = {
    0x8c, 0x7e, 0x88, 0x52, 0x03, 0xe2, 0x4e, 0x6e,
    0x94, 0xe5, 0xae, 0xe6, 0xae, 0x31, 0x9a, 0x0a,
    0xbb, 0xd5, 0x86, 0x56, 0xa9, 0xc3, 0x7a, 0x8d,
    0xfc, 0xe5, 0xc9, 0xb1, 0x00, 0x27, 0x53, 0xe5};

static dmp_bytes span(const void *data, size_t size)
{
    dmp_bytes bytes;
    bytes.data = (const uint8_t *)data;
    bytes.size = size;
    return bytes;
}

static void copy_body(uint8_t *dst, size_t *n, size_t cap, dmp_bytes src)
{
    if (src.size > cap) {
        *n = 0U;
        return;
    }
    if (src.size != 0U) {
        memcpy(dst, src.data, src.size);
    }
    *n = src.size;
}

static void on_notice(void *user, const dmp_endpoint_notice *notice)
{
    node *self = user;
    if (self == NULL || notice == NULL) {
        return;
    }
    if (notice->event == DMP_ENDPOINT_REQUEST) {
        self->app.accepts++;
        self->app.service = notice->service_id;
        self->app.pending = notice->request;
        self->app.have_pending = 1;
        copy_body(self->app.req_body, &self->app.req_n, sizeof self->app.req_body, notice->payload);
    } else if (notice->event == DMP_ENDPOINT_ASSEMBLED) {
        self->app.assembled++;
        copy_body(self->app.asm_body, &self->app.asm_n, sizeof self->app.asm_body, notice->payload);
    } else if (notice->event == DMP_ENDPOINT_DATA) {
        self->app.data_accepted++;
    } else if (notice->event == DMP_ENDPOINT_DATA_DELIVERED) {
        self->app.data_delivered++;
    } else if (notice->event == DMP_ENDPOINT_RESULT) {
        self->app.results++;
        self->app.wire_status = notice->wire_status;
        copy_body(self->app.result_body, &self->app.result_n, sizeof self->app.result_body,
                  notice->payload);
        if (notice->service_id == 0U) {
            copy_body(self->app.grant_body, &self->app.grant_n, sizeof self->app.grant_body,
                      notice->payload);
            self->app.grants++;
        }
    } else if (notice->event == DMP_ENDPOINT_UNKNOWN) {
        self->app.unknowns++;
    } else if (notice->event == DMP_ENDPOINT_LOCAL_UNSENT) {
        self->app.local_unsents++;
        self->app.unsent_key = notice->source;
        self->app.unsent_n = notice->payload.size;
    }
}

static int same_key(dmp_message_key left_key, dmp_message_key right_key)
{
    return left_key.seq == right_key.seq &&
           left_key.origin.namespace_id == right_key.origin.namespace_id &&
           left_key.origin.origin_id == right_key.origin.origin_id &&
           left_key.origin.epoch == right_key.origin.epoch;
}

static dmp_status wire_submit(void *context, const dmp_tx_submission *submission)
{
    wire *link = context;
    if (link == NULL || submission == NULL || submission->frame.data == NULL ||
        submission->complete == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (submission->frame.size > FRAME_CAP || link->n >= QUEUE) {
        return DMP_BUSY;
    }
    memcpy(link->q[link->n].frame, submission->frame.data, submission->frame.size);
    link->q[link->n].len = submission->frame.size;
    link->q[link->n].used = 1;
    link->tx_bytes += (uint32_t)submission->frame.size;
    g_tx += (uint32_t)submission->frame.size;
    link->n++;
    if (link->defer_completion != 0) {
        if (link->delayed_count >= QUEUE) {
            link->n--;
            return DMP_BUSY;
        }
        link->delayed[link->delayed_count].complete = submission->complete;
        link->delayed[link->delayed_count].owner = submission->owner;
        link->delayed[link->delayed_count].token = submission->token;
        link->delayed_count++;
    } else {
        submission->complete(submission->owner, submission->token, DMP_TX_TRANSMITTED, link->now);
    }
    return DMP_OK;
}

static int wire_complete_one(node *self, dmp_time_ms when, dmp_tx_outcome outcome,
                             delayed_completion *saved)
{
    delayed_completion delayed;
    int remaining;
    if (self == NULL || self->wire.delayed_count <= 0) {
        return 0;
    }
    delayed = self->wire.delayed[0];
    remaining = self->wire.delayed_count - 1;
    if (remaining > 0) {
        memmove(&self->wire.delayed[0], &self->wire.delayed[1],
                (size_t)remaining * sizeof self->wire.delayed[0]);
    }
    memset(&self->wire.delayed[remaining], 0, sizeof self->wire.delayed[0]);
    self->wire.delayed_count = remaining;
    if (delayed.complete == NULL) {
        return 0;
    }
    if (saved != NULL) {
        *saved = delayed;
    }
    self->wire.now = when;
    delayed.complete(delayed.owner, delayed.token, outcome, when);
    return 1;
}

static int wire_complete_delayed(node *self, dmp_time_ms when)
{
    int count = 0;
    while (self != NULL && self->wire.delayed_count > 0) {
        if (wire_complete_one(self, when, DMP_TX_TRANSMITTED, NULL) != 1) {
            return 0;
        }
        count++;
    }
    return count;
}

static dmp_status wire_cancel(void *context, dmp_tx_token token)
{
    (void)context;
    (void)token;
    return DMP_OK;
}

static void fill_common(dmp_config *config)
{
    memset(config, 0, sizeof *config);
    config->namespace_id = LOCAL_NS;
    config->node_id[0] = ID_INIT;
    config->node_id[1] = ID_RESP;
    config->default_service = 1U;
    config->service_id[0] = 1U;
    config->service_id[1] = 2U;
    config->peers = 1U;
    config->operations_per_service = 1U;
    config->assemblies_per_peer = 1U;
    config->assembly_tombstones_per_peer = TOMBSTONES;
    config->sender_slots = SENDERS;
    config->assembly_slots = ASSEMBLIES;
    config->assembly_tombstone_slots = TOMBSTONES;
    config->result_slots = RESULTS;
    config->history_slots = HISTORY;
    config->correlation_slots = CORRELATIONS;
    config->application_queue_slots = 2U;
    config->message_bytes = MESSAGE;
    config->queue_ms = 64U;
    config->jitter_ms = 0U;
    config->receipt_delay_ms = RADIO_RECEIPT_MS;
    config->receipt_limit = 3U;
    config->late_result_ms = 64U;
    config->tx_borrow = true;
    config->synchronous_completion = true;
}

static void fill_radio_numbers(dmp_config *config, int retry_all)
{
    fill_common(config);
    memcpy(config->sha256, retry_all ? RETRY_SHA : RADIO_SHA, 32U);
    config->recovery[0] = retry_all ? DMP_PROFILE_RECOVERY_RETRY_ALL : DMP_PROFILE_RECOVERY_SELECTIVE32;
    config->recovery[1] = config->recovery[0];
    config->adapter_slots = 5U;
    config->control_slots = 4U;
    config->fragments = 32U;
    config->chunk_bytes = 32U;
    config->encoded_mtu = 256U;
    config->forward_mtu = 256U;
    config->return_mtu = 256U;
    config->response_timeout_ms = RADIO_RESPONSE_MS;
    config->send_horizon_ms = 10752U;
    config->max_bursts = 3U;
    config->dedup_ms = 11000U;
    config->rejection_ms = 11000U;
    config->result_cache_ms = 11000U;
    config->result_deadline_ms = RADIO_RESULT_MS;
    config->correlation_ms = 23040U;
    config->tombstone_ms = 23040U;
    config->collect_ms = 10772U;
    config->assembly_ms = RADIO_ASSEMBLY_MS;
    config->burst_span_ms = retry_all ? 0U : 2048U;
    config->forward_delay_ms = retry_all ? 0U : 20U;
    config->return_delay_ms = retry_all ? 0U : 20U;
    config->feedback_guard_ms = retry_all ? 0U : 4U;
    config->feedback_delay_ms = retry_all ? 0U : 110U;
    config->max_probes = retry_all ? 0U : 2U;
    config->max_status = retry_all ? 0U : 3U;
    config->record_margin_ms = retry_all ? 0U : 5U;
    config->origin_route = 1U;
    config->origin_ttl = 2U;
    config->freshness_required_mask = 2U;
    config->freshness_lease_ms = 12000U;
    config->freshness_grant_delivery_age_ms = 100U;
    config->freshness_tokens_per_association = 4U;
    config->freshness_tokens_per_principal = 8U;
    config->freshness_grant_requests_per_pair = 2U;
    config->freshness_token_record_ms = 12000U;
    config->freshness_grant_result_ms = 11000U;
}

static void fill_direct_numbers(dmp_config *config)
{
    fill_common(config);
    memcpy(config->sha256, DIRECT_SHA, 32U);
    config->recovery[0] = DMP_PROFILE_RECOVERY_RETRY_ALL;
    config->recovery[1] = DMP_PROFILE_RECOVERY_RETRY_ALL;
    config->adapter_slots = 3U;
    config->control_slots = 2U;
    config->fragments = 16U;
    config->chunk_bytes = 64U;
    config->encoded_mtu = 263U;
    config->forward_mtu = 256U;
    config->return_mtu = 256U;
    config->response_timeout_ms = 1280U;
    config->send_horizon_ms = 5632U;
    config->max_bursts = 3U;
    config->dedup_ms = 6000U;
    config->rejection_ms = 6000U;
    config->result_cache_ms = 6000U;
    config->result_deadline_ms = 12000U;
    config->correlation_ms = 12288U;
    config->tombstone_ms = 12288U;
    config->collect_ms = 5652U;
    config->assembly_ms = 5657U;
}

static int install_grants(node *self, int deny_service2)
{
    dmp_endpoint_grant grants[6];
    memset(grants, 0, sizeof grants);
    grants[0].principal = ID_INIT;
    grants[0].service_id = 1U;
    grants[0].permit = DMP_ENDPOINT_PERMIT_TELEM | DMP_ENDPOINT_PERMIT_RESULT;
    grants[1].principal = ID_RESP;
    grants[1].service_id = 1U;
    grants[1].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[2].principal = ID_INIT;
    grants[2].service_id = 2U;
    grants[2].permit = deny_service2 ? 0U : (DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT);
    grants[3].principal = ID_RESP;
    grants[3].service_id = 2U;
    grants[3].permit = deny_service2 ? 0U : (DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT);
    grants[4].principal = ID_INIT;
    grants[4].service_id = 0U;
    grants[4].permit = DMP_ENDPOINT_PERMIT_CONTROL;
    grants[5].principal = ID_RESP;
    grants[5].service_id = 0U;
    grants[5].permit = DMP_ENDPOINT_PERMIT_CONTROL;
    return dmp_endpoint_set_grants(&self->endpoint, grants, 6U) == DMP_OK ? 0 : 1;
}

static int allow_service1_request(node *self)
{
    dmp_endpoint_grant grants[DMP_ENDPOINT_GRANT_MAX];
    size_t count;
    if (self == NULL || self->endpoint.grant_count >= DMP_ENDPOINT_GRANT_MAX) {
        return 1;
    }
    count = self->endpoint.grant_count;
    memcpy(grants, self->endpoint.grants, count * sizeof grants[0]);
    grants[count].principal = ID_INIT;
    grants[count].service_id = 1U;
    grants[count].permit = DMP_ENDPOINT_PERMIT_REQ;
    return dmp_endpoint_set_grants(&self->endpoint, grants, count + 1U) == DMP_OK ? 0 : 1;
}

static int allow_service1_result(node *self)
{
    dmp_endpoint_grant grants[DMP_ENDPOINT_GRANT_MAX];
    size_t count;
    size_t i;
    if (self == NULL) {
        return 1;
    }
    count = self->endpoint.grant_count;
    memcpy(grants, self->endpoint.grants, count * sizeof grants[0]);
    for (i = 0U; i < count; i++) {
        if (grants[i].principal == ID_RESP && grants[i].service_id == 1U) {
            grants[i].permit |= DMP_ENDPOINT_PERMIT_RESULT;
            return dmp_endpoint_set_grants(&self->endpoint, grants, count) == DMP_OK ? 0 : 1;
        }
    }
    if (count >= DMP_ENDPOINT_GRANT_MAX) {
        return 1;
    }
    grants[count].principal = ID_RESP;
    grants[count].service_id = 1U;
    grants[count].permit = DMP_ENDPOINT_PERMIT_RESULT;
    return dmp_endpoint_set_grants(&self->endpoint, grants, count + 1U) == DMP_OK ? 0 : 1;
}

static int boot_node(node *self, int producer, int profile, dmp_time_ms now, int deny_service2)
{
    dmp_config input;
    dmp_admitted_profile admitted;
    dmp_endpoint_storage storage;
    dmp_identity_context_config identity;
    memset(self, 0, sizeof *self);
    if (profile == PROF_DIRECT || profile == PROF_DIRECT_ASYNC) {
        fill_direct_numbers(&input);
        if (profile == PROF_DIRECT_ASYNC) {
            memcpy(input.sha256, ASYNC_SHA, sizeof ASYNC_SHA);
            input.synchronous_completion = false;
        }
    } else if (profile == PROF_RADIO_N2) {
        fill_radio_numbers(&input, 0);
        memcpy(input.sha256, N2_SHA, sizeof N2_SHA);
        input.forward_mtu = 128U;
        input.return_mtu = 128U;
        input.encoded_mtu = 128U;
        input.synchronous_completion = false;
    } else {
        fill_radio_numbers(&input, profile == PROF_RETRY);
    }
    if (dmp_config_admit(&input, &admitted) != DMP_OK) {
        return 1;
    }
    memset(&identity, 0, sizeof identity);
    identity.local.namespace_id = LOCAL_NS;
    identity.peer.namespace_id = LOCAL_NS;
    identity.local.origin_id = producer ? ID_INIT : ID_RESP;
    identity.peer.origin_id = producer ? ID_RESP : ID_INIT;
    identity.security = 1U;
    self->wire.self = self;
    self->wire.now = now;
    self->transport.context = &self->wire;
    self->transport.submit = wire_submit;
    self->transport.cancel = wire_cancel;
    self->transport.caps.max_frame_bytes = FRAME_CAP;
    self->transport.caps.ownership = DMP_TX_BORROW;
    self->transport.caps.synchronous_completion = admitted.synchronous_completion;
    self->wire.defer_completion = admitted.synchronous_completion ? 0 : 1;
    memset(&storage, 0, sizeof storage);
    storage.profile = &admitted;
    storage.identity_slots = self->ids;
    storage.identity_capacity = 2U;
    storage.context = identity;
    storage.transport = &self->transport;
    storage.notice = on_notice;
    storage.notice_user = self;
    storage.senders = self->senders;
    storage.sender_capacity = SENDERS;
    storage.sender_payload = self->sender_payload;
    storage.sender_payload_capacity = sizeof self->sender_payload;
    storage.results = self->results;
    storage.result_capacity = RESULTS;
    storage.result_payload = self->result_payload;
    storage.result_payload_capacity = sizeof self->result_payload;
    storage.history = self->history;
    storage.history_capacity = HISTORY;
    storage.correlations = self->correlations;
    storage.correlation_capacity = CORRELATIONS;
    storage.history_metadata = self->history_metadata;
    storage.history_metadata_capacity = sizeof self->history_metadata;
    storage.correlation_metadata = self->correlation_metadata;
    storage.correlation_metadata_capacity = sizeof self->correlation_metadata;
    storage.adapters = self->adapters;
    storage.adapter_capacity = ADAPTERS;
    storage.frames = self->frames;
    storage.frame_capacity = sizeof self->frames;
    storage.receive_payload = self->receive_payload;
    storage.receive_payload_capacity = sizeof self->receive_payload;
    storage.assemblies = self->assemblies;
    storage.assembly_capacity = ASSEMBLIES;
    storage.tombstones = self->tombstones;
    storage.tombstone_capacity = TOMBSTONES;
    storage.freshness_slots = self->freshness;
    storage.freshness_capacity = sizeof self->freshness / sizeof self->freshness[0];
    storage.assembly_payload = self->assembly_payload;
    storage.assembly_payload_capacity = sizeof self->assembly_payload;
    storage.assembly_metadata = self->assembly_metadata;
    storage.assembly_metadata_capacity = sizeof self->assembly_metadata;
    storage.fragment_message = self->fragment_message;
    storage.fragment_message_capacity = sizeof self->fragment_message;
    storage.fragment_frame = self->fragment_frame;
    storage.fragment_frame_capacity = sizeof self->fragment_frame;
    storage.telemetry_payload = self->telemetry_payload;
    storage.telemetry_payload_capacity = sizeof self->telemetry_payload;
    storage.telemetry_next = self->telemetry_next;
    storage.telemetry_next_capacity = sizeof self->telemetry_next;
    storage.telemetry_frame = self->telemetry_frame;
    storage.telemetry_frame_capacity = sizeof self->telemetry_frame;
    storage.stream_tx = self->stream_tx;
    storage.stream_tx_capacity = sizeof self->stream_tx;
    storage.stream_rx = self->stream_rx;
    storage.stream_rx_capacity = sizeof self->stream_rx;
    if (dmp_endpoint_init(&self->endpoint, &storage, now) != DMP_OK) {
        return 1;
    }
    return install_grants(self, deny_service2);
}

static uint32_t retained_payload(const node *n)
{
    uint32_t sum = 0U;
    size_t index;
    for (index = 0U; index < SENDERS; index++) {
        if (n->senders[index].live != 0U) {
            sum += n->senders[index].payload_len;
        }
    }
    for (index = 0U; index < RESULTS; index++) {
        if (n->results[index].live != 0U) {
            sum += n->results[index].payload_len;
        }
    }
    for (index = 0U; index < ASSEMBLIES; index++) {
        if (n->assemblies[index].live != 0U) {
            sum += n->assemblies[index].total_size;
        }
    }
    if (n->endpoint.frag_live != 0U) {
        sum += n->endpoint.frag_total;
    }
    return sum;
}

static void note_peak(void)
{
    uint32_t now = retained_payload(&left) + retained_payload(&right);
    if (now > g_peak) {
        g_peak = now;
    }
}

static void report(const char *name, const port_ctx *port, const char *outcome)
{
    (void)printf("P19 %s tx_bytes=%u rx_bytes=%u retained_payload=%u provider_peak=%u "
                 "caller_node=%u outcome=%s\n",
                 name, g_tx, g_rx, g_peak, (unsigned)g_provider, (unsigned)sizeof(node), outcome);
    (void)port;
    (void)fflush(stdout);
}

static const noise_fixture_probe_fixture_t *find_fixture(void)
{
    size_t index;
    for (index = 0U; index < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; index++) {
        if (strcmp(noise_fixture_probe_fixtures[index].name, "nnpsk0") == 0) {
            return &noise_fixture_probe_fixtures[index];
        }
    }
    return NULL;
}

static int startup_ready(void *ctx)
{
    (void)ctx;
    return 0;
}

static int startup_read(void *ctx, void *bytes, size_t size)
{
    uint8_t *out = (uint8_t *)bytes;
    size_t index;
    (void)ctx;
    for (index = 0U; index < size; index++) {
        out[index] = (uint8_t)(0x3DU + (uint8_t)index);
    }
    return 0;
}

static int provider_entropy(void *ctx, void *bytes, size_t size)
{
    uint8_t *out = (uint8_t *)bytes;
    size_t index;
    (void)ctx;
    for (index = 0U; index < size; index++) {
        out[index] = (uint8_t)(0x71U + (uint8_t)index);
    }
    return 0;
}

static void *port_allocate(void *ctx, size_t size)
{
    port_ctx *port = (port_ctx *)ctx;
    void *ptr = calloc(1, size);
    port->alloc_calls++;
    if (ptr == NULL) {
        return NULL;
    }
    port->live += size;
    if (port->live > port->peak) {
        port->peak = port->live;
    }
    if (port->peak > g_provider) {
        g_provider = port->peak;
    }
    if (size > port->peak_one) {
        port->peak_one = size;
    }
    return ptr;
}

static void port_release(void *ctx, void *ptr, size_t size)
{
    port_ctx *port = (port_ctx *)ctx;
    if (port->live >= size) {
        port->live -= size;
    } else {
        port->live = 0U;
    }
    free(ptr);
}

static uint64_t now_of(void *ctx)
{
    box *env = (box *)ctx;
    return *env->now;
}

static int entropy_of(void *ctx, uint8_t *bytes, size_t size)
{
    box *env = (box *)ctx;
    script *src = env->entropy_script;
    if (src->index >= src->count || src->len[src->index] != size) {
        memset(bytes, 0, size);
        return 1;
    }
    memcpy(bytes, src->data[src->index], size);
    src->index++;
    return 0;
}

static int commit_of(void *ctx, const dmp_hs_pin_record *record)
{
    box *env = (box *)ctx;
    (void)record;
    env->pin_store->calls++;
    return 0;
}

static void script_add(script *src, const uint8_t *data, size_t len)
{
    if (src->count >= sizeof src->data / sizeof src->data[0]) {
        abort();
    }
    src->data[src->count] = data;
    src->len[src->count] = len;
    src->count++;
}

static void fill_budget(dmp_hs_budget *budget)
{
    memset(budget, 0, sizeof *budget);
    budget->max_pending = 2U;
    budget->max_scratch = 2U;
    budget->episode_attempts = 3U;
    budget->episode_deadline_ms = 100000U;
    budget->episode_work = 1000U;
    budget->episode_traffic = 100000U;
    budget->restart_backoff_ms = 1000U;
    budget->attempt_deadline_ms = 60000U;
    budget->cached_responses = 3U;
    budget->global_work = 1000U;
    budget->ingress_work = 1000U;
    budget->later_episodes = 1U;
    budget->admit_burst = 4U;
    budget->provisional_bytes = 240U;
    budget->confirmation_timeout_ms = 1000U;
    budget->confirmation_attempts = 3U;
}

static void fill_hs(dmp_hs_config *config, const noise_fixture_probe_fixture_t *fixture,
                    const uint8_t profile_hash[32], int initiator)
{
    memset(config, 0, sizeof *config);
    fill_budget(&config->budget);
    config->namespace_id = LOCAL_NS;
    config->local_id = initiator ? ID_INIT : ID_RESP;
    config->peer_id = initiator ? ID_RESP : ID_INIT;
    memcpy(config->profile_hash, profile_hash, 32U);
    config->mode = 1U;
    config->cipher = 1U;
    config->key_hint = KEY_HINT;
    config->permissions = 2U;
    config->next_rx_cid = initiator ? CID_INIT : CID_RESP;
    memcpy(config->psk, fixture->psk.data, 32U);
    config->has_psk = 1;
}

static void close_session(session *env)
{
    if (env->initiator != NULL) {
        dmp_hs_cleanup(env->initiator);
    }
    if (env->responder != NULL) {
        dmp_hs_cleanup(env->responder);
    }
    if (env->provider != NULL) {
        dmp_provider_cleanup(env->provider);
    }
    free(env->initiator);
    free(env->responder);
    free(env->provider);
    env->initiator = NULL;
    env->responder = NULL;
    env->provider = NULL;
}

static int make_pair(session *env, port_ctx *port, const noise_fixture_probe_fixture_t *fixture,
                     const uint8_t profile_hash[32])
{
    dmp_hs_config init_config;
    dmp_hs_config resp_config;
    dmp_hs_ports init_ports;
    dmp_hs_ports resp_ports;
    dmp_provider_ports ports;
    memset(env, 0, sizeof *env);
    env->now = 10000U;
    memset(port, 0, sizeof *port);
    memset(&ports, 0, sizeof ports);
    ports.startup_ready = startup_ready;
    ports.startup_read = startup_read;
    ports.entropy = provider_entropy;
    ports.allocate = port_allocate;
    ports.release = port_release;
    ports.ctx = port;
    ports.scratch_limit = DMP_PROVIDER_SCRATCH_MAX;
    ports.retained_limit = DMP_PROVIDER_RETAINED_MAX;
    env->provider = (dmp_provider *)calloc(1, dmp_provider_size());
    env->initiator = (dmp_hs *)calloc(1, dmp_hs_size());
    env->responder = (dmp_hs *)calloc(1, dmp_hs_size());
    if (env->provider == NULL || env->initiator == NULL || env->responder == NULL ||
        dmp_provider_setup(env->provider, &ports) != DMP_PROVIDER_OK) {
        close_session(env);
        return 0;
    }
    fill_hs(&init_config, fixture, profile_hash, 1);
    fill_hs(&resp_config, fixture, profile_hash, 0);
    script_add(&env->init_script, fixture->attempt_id.data, fixture->attempt_id.size);
    script_add(&env->init_script, fixture->init_ephemeral.data, fixture->init_ephemeral.size);
    script_add(&env->resp_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
    for (size_t draw = 0U; draw < 6U; ++draw) {
        for (size_t byte = 0U; byte < sizeof env->token_entropy[0][draw]; ++byte) {
            env->token_entropy[0][draw][byte] = (uint8_t)(0x31U + draw * 19U + byte);
            env->token_entropy[1][draw][byte] = (uint8_t)(0x91U + draw * 19U + byte);
        }
        script_add(&env->init_script, env->token_entropy[0][draw],
                   sizeof env->token_entropy[0][draw]);
        script_add(&env->resp_script, env->token_entropy[1][draw],
                   sizeof env->token_entropy[1][draw]);
    }
    env->init_box.now = &env->now;
    env->init_box.entropy_script = &env->init_script;
    env->init_box.pin_store = &env->init_store;
    env->resp_box.now = &env->now;
    env->resp_box.entropy_script = &env->resp_script;
    env->resp_box.pin_store = &env->resp_store;
    memset(&init_ports, 0, sizeof init_ports);
    memset(&resp_ports, 0, sizeof resp_ports);
    init_ports.now_ms = now_of;
    init_ports.entropy = entropy_of;
    init_ports.commit_pin = commit_of;
    init_ports.ctx = &env->init_box;
    resp_ports.now_ms = now_of;
    resp_ports.entropy = entropy_of;
    resp_ports.commit_pin = commit_of;
    resp_ports.ctx = &env->resp_box;
    if (dmp_hs_init(env->initiator, env->provider, &init_config, &init_ports) != DMP_HS_OK ||
        dmp_hs_init(env->responder, env->provider, &resp_config, &resp_ports) != DMP_HS_OK ||
        dmp_hs_begin_episode(env->initiator) != DMP_HS_OK) {
        close_session(env);
        return 0;
    }
    return 1;
}

static int drive_flight(dmp_hs *hs, const uint8_t *payload, size_t length, uint32_t origin,
                        uint32_t destination, uint32_t seq, uint64_t epoch, dmp_hs_status expected)
{
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    dmp_hs_status status;
    memset(&ingress, 0, sizeof ingress);
    ingress.payload = payload;
    ingress.payload_len = length;
    ingress.origin_id = origin;
    ingress.destination_id = destination;
    ingress.namespace_id = LOCAL_NS;
    ingress.context_epoch = epoch;
    ingress.seq = seq;
    status = dmp_hs_offer(hs, &ingress, &completion);
    if (status == DMP_HS_AWAITING) {
        status = dmp_hs_accept(hs, &completion);
    }
    return status == expected;
}

static int drive_nn(session *env, uint32_t *index)
{
    const uint8_t *cached;
    size_t length = 0U;
    uint64_t boot;
    if (dmp_hs_schedule(env->initiator, index) != DMP_HS_OK) {
        return 0;
    }
    boot = dmp_hs_boot_epoch(env->initiator, *index);
    cached = dmp_hs_cached_flight(env->initiator, *index, &length);
    if (boot == 0U || cached == NULL ||
        !drive_flight(env->responder, cached, length, ID_INIT, ID_RESP, 1U, boot, DMP_HS_CANDIDATE)) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->responder, 0U, &length);
    return cached != NULL &&
           drive_flight(env->initiator, cached, length, ID_RESP, ID_INIT, 2U, boot, DMP_HS_CANDIDATE);
}

static int offer_protected(dmp_hs *hs, const uint8_t *frame, size_t length, uint32_t origin,
                           uint32_t destination, uint64_t epoch)
{
    dmp_hs_protected incoming;
    memset(&incoming, 0, sizeof incoming);
    incoming.frame = frame;
    incoming.frame_len = length;
    incoming.origin_id = origin;
    incoming.destination_id = destination;
    incoming.namespace_id = LOCAL_NS;
    incoming.context_epoch = epoch;
    return dmp_hs_offer_protected(hs, &incoming) == DMP_HS_OK;
}

static int activate(session *env, uint32_t index)
{
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    const uint8_t *frame;
    size_t length = 0U;
    if (!dmp_hs_epochs(env->initiator, index, &epoch_i, &epoch_r) ||
        dmp_hs_confirm(env->initiator, index) != DMP_HS_OK) {
        return 0;
    }
    frame = dmp_hs_protected_frame(env->initiator, index, &length);
    if (frame == NULL || !offer_protected(env->responder, frame, length, ID_INIT, ID_RESP, epoch_i)) {
        return 0;
    }
    frame = dmp_hs_protected_frame(env->responder, 0U, &length);
    if (frame == NULL || !offer_protected(env->initiator, frame, length, ID_RESP, ID_INIT, epoch_r)) {
        return 0;
    }
    return dmp_hs_association_active(env->initiator) && dmp_hs_association_active(env->responder);
}

static int bind_pair(session *env, uint32_t index)
{
    return dmp_endpoint_bind(&left.endpoint, env->initiator, index) == DMP_OK &&
           dmp_endpoint_bind(&right.endpoint, env->responder, 0U) == DMP_OK;
}

static int open_pair(session *env, port_ctx *port, int profile, dmp_time_ms now, int deny_service2,
                     uint32_t *index)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture();
    const uint8_t *profile_hash = profile == PROF_RETRY ? RETRY_SHA :
                                  profile == PROF_DIRECT ? DIRECT_SHA :
                                  profile == PROF_DIRECT_ASYNC ? ASYNC_SHA :
                                  profile == PROF_RADIO_N2 ? N2_SHA : RADIO_SHA;
    if (fixture == NULL || !make_pair(env, port, fixture, profile_hash) || !drive_nn(env, index) ||
        !activate(env, *index)) {
        return 1;
    }
    if (boot_node(&left, 1, profile, now, deny_service2) != 0 ||
        boot_node(&right, 0, profile, now, deny_service2) != 0 || !bind_pair(env, *index)) {
        return 1;
    }
    left.wire.now = now;
    right.wire.now = now;
    return 0;
}

/* Handshake is up and bound, but the attempt is not active yet. */
static int open_inactive(session *env, port_ctx *port, int profile, dmp_time_ms now, uint32_t *index)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture();
    const uint8_t *profile_hash = profile == PROF_RETRY ? RETRY_SHA :
                                  profile == PROF_DIRECT ? DIRECT_SHA :
                                  profile == PROF_DIRECT_ASYNC ? ASYNC_SHA :
                                  profile == PROF_RADIO_N2 ? N2_SHA : RADIO_SHA;
    if (fixture == NULL || !make_pair(env, port, fixture, profile_hash) || !drive_nn(env, index) ||
        dmp_hs_association_active(env->initiator) != 0) {
        return 1;
    }
    if (boot_node(&left, 1, profile, now, 0) != 0 || boot_node(&right, 0, profile, now, 0) != 0 ||
        !bind_pair(env, *index)) {
        return 1;
    }
    left.wire.now = now;
    right.wire.now = now;
    return 0;
}

static int unwrap_core(const uint8_t *framed, size_t n, uint8_t *core, size_t cap, size_t *core_n,
                       dmp_time_ms now)
{
    dmp_stream_decoder decoder;
    dmp_stream_config config;
    dmp_buffer storage;
    uint8_t scratch[STREAM_CAP];
    dmp_bytes input;
    memset(&decoder, 0, sizeof decoder);
    memset(&config, 0, sizeof config);
    config.mode = DMP_STREAM_R;
    config.max_core_bytes = MTU;
    config.partial_timeout_ms = 1U;
    storage.data = scratch;
    storage.capacity = sizeof scratch;
    if (dmp_stream_init(&decoder, config, storage, now) != DMP_OK) {
        return 0;
    }
    input = span(framed, n);
    while (input.size != 0U) {
        dmp_stream_result fed = dmp_stream_feed(&decoder, input, now);
        if (fed.status != DMP_OK || fed.consumed == 0U || fed.consumed > input.size) {
            return 0;
        }
        input.data += fed.consumed;
        input.size -= fed.consumed;
        if (fed.event == DMP_STREAM_FRAME) {
            if (fed.frame.size > cap) {
                return 0;
            }
            if (fed.frame.size != 0U) {
                memcpy(core, fed.frame.data, fed.frame.size);
            }
            *core_n = fed.frame.size;
            return 1;
        }
    }
    return 0;
}

static int wrap_core(const uint8_t *core, size_t n, uint8_t *out, size_t cap, size_t *out_n)
{
    dmp_buffer encoded;
    size_t written = 0U;
    if (cap < 2U) {
        return 0;
    }
    encoded.data = out + 1U;
    encoded.capacity = cap - 1U;
    if (dmp_stream_encode(DMP_STREAM_R, span(core, n), encoded, &written) != DMP_OK) {
        return 0;
    }
    out[0] = 0U;
    *out_n = written + 1U;
    return 1;
}

static int classify(const uint8_t *framed, size_t n, dmp_time_ms now, uint8_t *type, uint32_t *index)
{
    uint8_t core[MTU];
    size_t core_n = 0U;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_parse_result parsed;
    if (!unwrap_core(framed, n, core, sizeof core, &core_n, now)) {
        return 0;
    }
    memset(&view, 0, sizeof view);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    parsed = dmp_core_parse(span(core, core_n), &limits, &view);
    if (parsed.status != DMP_OK) {
        return 0;
    }
    *type = view.fields.type;
    if ((view.fields.options & DMP_OPT_FRAG) != 0U) {
        *index = view.fields.fragment.index;
    } else {
        *index = 0xffffffffU;
    }
    return 1;
}

static int take_queue(node *from, captured *out, int cap, dmp_time_ms now)
{
    int count = 0;
    int index;
    for (index = 0; index < from->wire.n && count < cap; index++) {
        captured *slot = &out[count];
        memset(slot, 0, sizeof *slot);
        if (from->wire.q[index].len > FRAME_CAP) {
            return -1;
        }
        memcpy(slot->frame, from->wire.q[index].frame, from->wire.q[index].len);
        slot->len = from->wire.q[index].len;
        if (!classify(slot->frame, slot->len, now, &slot->type, &slot->index)) {
            return -1;
        }
        count++;
    }
    from->wire.n = 0;
    return count;
}

static int captured_view(const captured *frame, dmp_time_ms now, uint8_t core[MTU],
                         size_t *core_n, dmp_frame_view *view)
{
    dmp_core_limits limits;
    dmp_parse_result parsed;
    if (frame == NULL || view == NULL ||
        !unwrap_core(frame->frame, frame->len, core, MTU, core_n, now)) {
        return 0;
    }
    memset(view, 0, sizeof *view);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    parsed = dmp_core_parse(span(core, *core_n), &limits, view);
    return parsed.status == DMP_OK;
}

static int captured_seq(const captured *frame, dmp_time_ms now, uint32_t *seq)
{
    uint8_t core[MTU];
    size_t core_n = 0U;
    dmp_frame_view view;
    if (seq == NULL || !captured_view(frame, now, core, &core_n, &view) ||
        (view.fields.options & DMP_OPT_SEQ) == 0U) {
        return 0;
    }
    *seq = view.fields.seq;
    return 1;
}

/* Re-encode an otherwise genuine protected frame with a selected SEC-1 PN.
 * The stale tag makes the below-limit variant an authenticated receive failure;
 * the limit variant exercises the endpoint's PN admission guard. */
static int captured_with_pn(const captured *original, dmp_time_ms now, uint64_t pn,
                            captured *out)
{
    uint8_t original_core[MTU];
    uint8_t encoded_core[MTU];
    size_t original_n = 0U;
    size_t encoded_n = 0U;
    dmp_frame_view view;
    dmp_frame_spec spec;
    dmp_core_limits limits;
    dmp_buffer output;
    if (original == NULL || out == NULL ||
        !captured_view(original, now, original_core, &original_n, &view) ||
        (view.fields.options & DMP_OPT_SECURITY) == 0U) {
        return 0;
    }
    memset(&spec, 0, sizeof spec);
    spec.fields = view.fields;
    spec.fields.security.pn = pn;
    spec.extensions = view.extensions;
    spec.payload = view.payload;
    spec.trailer = view.trailer;
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    output.data = encoded_core;
    output.capacity = sizeof encoded_core;
    if (dmp_core_encode(&spec, &limits, output, &encoded_n) != DMP_OK ||
        !wrap_core(encoded_core, encoded_n, out->frame, sizeof out->frame, &out->len)) {
        return 0;
    }
    return classify(out->frame, out->len, now, &out->type, &out->index);
}

/* Re-protect a saved logical packet with a fresh PN while retaining its
 * sequence, route, context and immutable extensions. Used to model a logical
 * retry, not byte-identical packet replay. */
static int reseal_new_pn(session *env, uint32_t attempt, const captured *original,
                         dmp_bytes plaintext, dmp_time_ms now, captured *out)
{
    uint8_t core[MTU];
    uint8_t sealed[MTU];
    dmp_frame_view view;
    dmp_frame_spec spec;
    size_t core_n = 0U;
    size_t sealed_n = 0U;
    if (env == NULL || out == NULL ||
        (plaintext.size != 0U && plaintext.data == NULL) ||
        !captured_view(original, now, core, &core_n, &view)) {
        return 0;
    }
    memset(&spec, 0, sizeof spec);
    spec.fields = view.fields;
    spec.fields.options = (uint8_t)(spec.fields.options & (uint8_t)~DMP_OPT_SECURITY);
    memset(&spec.fields.security, 0, sizeof spec.fields.security);
    spec.extensions = view.extensions;
    spec.payload = plaintext;
    if (dmp_hs_seal_logical(env->initiator, attempt, &spec, sealed, sizeof sealed, &sealed_n) !=
            DMP_HS_OK ||
        !wrap_core(sealed, sealed_n, out->frame, sizeof out->frame, &out->len)) {
        return 0;
    }
    return classify(out->frame, out->len, now, &out->type, &out->index);
}

static int open_captured(session *env, uint32_t attempt, const captured *frame, dmp_time_ms now,
                         dmp_frame_view *view, uint8_t *plain, size_t plain_cap,
                         size_t *plain_n)
{
    uint8_t core[MTU];
    size_t core_n = 0U;
    uint32_t namespace_id = 0U;
    uint32_t local_id = 0U;
    uint32_t peer_id = 0U;
    uint64_t local_epoch = 0U;
    uint64_t peer_epoch = 0U;
    dmp_hs_protected incoming;
    dmp_frame_view parsed;

    if (env == NULL || frame == NULL || view == NULL || plain_n == NULL ||
        !unwrap_core(frame->frame, frame->len, core, sizeof core, &core_n, now) ||
        !dmp_hs_traffic_identity(env->initiator, attempt, &namespace_id, &local_id, &peer_id,
                                 &local_epoch, &peer_epoch)) {
        return 0;
    }
    memset(&parsed, 0, sizeof parsed);
    if (!captured_view(frame, now, core, &core_n, &parsed)) {
        return 0;
    }
    memset(&incoming, 0, sizeof incoming);
    incoming.frame = core;
    incoming.frame_len = core_n;
    incoming.namespace_id = namespace_id;
    incoming.origin_id = peer_id;
    incoming.destination_id = local_id;
    incoming.context_epoch = peer_epoch;
    if (dmp_hs_open_logical(env->initiator, attempt, &incoming, plain, plain_cap, plain_n,
                            view) != DMP_HS_OK) {
        return 0;
    }
    (void)local_epoch;
    return 1;
}

static int pump_sender(node *self, dmp_time_ms now, int minimum)
{
    int guard;
    for (guard = 0; guard < 48 && self->wire.n < minimum; guard++) {
        self->wire.now = now;
        if (dmp_endpoint_poll(&self->endpoint, now) != DMP_OK) {
            return 1;
        }
        note_peak();
    }
    return self->wire.n >= minimum ? 0 : 1;
}

static int pump_sender_complete(node *self, dmp_time_ms now, int minimum)
{
    int guard;
    for (guard = 0; guard < 96 && self->wire.n < minimum; guard++) {
        dmp_time_ms when = now + (dmp_time_ms)(unsigned)guard;
        self->wire.now = when;
        if (dmp_endpoint_poll(&self->endpoint, when) != DMP_OK) {
            return 1;
        }
        note_peak();
        if (self->wire.n >= minimum) {
            break;
        }
        if (self->wire.delayed_count != 0 &&
            wire_complete_one(self, when + 1U, DMP_TX_TRANSMITTED, NULL) != 1) {
            return 1;
        }
    }
    return self->wire.n >= minimum ? 0 : 1;
}

static int deliver_one(node *to, const captured *frame, dmp_time_ms now, dmp_status *status)
{
    dmp_status got;
    to->wire.now = now;
    to->wire.rx_bytes += (uint32_t)frame->len;
    g_rx += (uint32_t)frame->len;
    got = dmp_endpoint_rx(&to->endpoint, span(frame->frame, frame->len), now);
    if (status != NULL) {
        *status = got;
    }
    note_peak();
    return 0;
}

static int local_service_action(const node *self, uint32_t service, uint32_t action)
{
    uint32_t principal;
    size_t i;
    const dmp_identity_slot *identity;
    if (self->endpoint.context.slot >= self->endpoint.identity.capacity) {
        return 0;
    }
    identity = &self->endpoint.identity.slots[self->endpoint.context.slot];
    if (identity->generation != self->endpoint.context.generation) {
        return 0;
    }
    principal = identity->local.origin_id;
    for (i = 0U; i < self->endpoint.grant_count; i++) {
        const dmp_endpoint_grant *grant = &self->endpoint.grants[i];
        if (grant->principal == principal && grant->service_id == service &&
            (grant->permit & action) == action) {
            return 1;
        }
    }
    return 0;
}

/* Obtain an actual S7.1 grant over the protected, reliable service-0 path.
 * The single-use token is then bound to the service-2 transfer by its sender. */
static int request_freshness_token(node *self, dmp_time_ms now, uint32_t requested_lifetime,
                                   uint8_t token[16],
                                   captured *request_out, captured *response_out,
                                   int acknowledge_response)
{
    node *peer = self == &left ? &right : &left;
    uint8_t request[5] = {0x10U, (uint8_t)requested_lifetime,
                          (uint8_t)(requested_lifetime >> 8U),
                          (uint8_t)(requested_lifetime >> 16U),
                          (uint8_t)(requested_lifetime >> 24U)};
    captured frames[QUEUE];
    dmp_reliability_handle handle;
    dmp_status status = DMP_OK;
    int count;
    int i;
    int before = self->app.grants;

    if (self->endpoint.profile.freshness_required_mask == 0U ||
        !local_service_action(self, 2U, DMP_ENDPOINT_PERMIT_REQ)) {
        return 0;
    }
    self->app.grant_n = 0U;
    status = dmp_endpoint_submit_req(&self->endpoint, 0U, span(request, sizeof request), now, &handle);
    if (status != DMP_OK) {
        return 0;
    }
    if (pump_sender_complete(self, now, 1) != 0) {
        return 0;
    }
    count = take_queue(self, frames, QUEUE, now);
    if (count != 1 || frames[0].type != DMP_TYPE_REQ ||
        deliver_one(peer, &frames[0], now, &status) != 0 || status != DMP_OK ||
        pump_sender_complete(peer, now, 1) != 0) {
        return 0;
    }
    if (request_out != NULL) {
        *request_out = frames[0];
    }
    count = take_queue(peer, frames, QUEUE, now);
    if (count <= 0) {
        return 0;
    }
    for (i = 0; i < count; i++) {
        if (response_out != NULL && frames[i].type == DMP_TYPE_RSP) {
            *response_out = frames[i];
        }
        if (deliver_one(self, &frames[i], now, &status) != 0 ||
            (status != DMP_OK && status != DMP_DUPLICATE)) {
            return 0;
        }
    }
    if (self->app.grants != before + 1 || self->app.grant_n != 21U ||
        self->app.grant_body[0] != 0x11U ||
        ((uint32_t)self->app.grant_body[17] |
         ((uint32_t)self->app.grant_body[18] << 8U) |
         ((uint32_t)self->app.grant_body[19] << 16U) |
         ((uint32_t)self->app.grant_body[20] << 24U)) != requested_lifetime) {
        return 0;
    }
    memcpy(token, self->app.grant_body + 1U, 16U);
    if (acknowledge_response != 0 && pump_sender_complete(self, now, 1) == 0) {
        count = take_queue(self, frames, QUEUE, now);
        for (i = 0; i < count; i++) {
            if (deliver_one(peer, &frames[i], now, &status) != 0 ||
                (status != DMP_OK && status != DMP_DUPLICATE)) {
                return 0;
            }
        }
    }
    /* The loopback delivered these control frames, so report their independent
     * local transmit completions before handing the endpoint to the data case. */
    (void)wire_complete_delayed(self, now + 1U);
    (void)wire_complete_delayed(peer, now + 1U);
    /* A test failure must not leak control frames into the data scenario. */
    self->wire.n = 0;
    peer->wire.n = 0;
    return 1;
}

static dmp_endpoint_freshness_slot *freshness_record(node *self, const uint8_t token[16])
{
    size_t i;
    for (i = 0U; i < sizeof self->freshness / sizeof self->freshness[0]; i++) {
        if (self->freshness[i].state != DMP_ENDPOINT_FRESHNESS_EMPTY &&
            memcmp(self->freshness[i].token, token, 16U) == 0) {
            return &self->freshness[i];
        }
    }
    return NULL;
}

static int freshness_result_retained(const node *self,
                                     const dmp_endpoint_freshness_slot *record)
{
    const dmp_reliability_result_slot *result;
    if (record == NULL || record->result_slot >= self->endpoint.mem.result_capacity) {
        return 0;
    }
    result = &self->results[record->result_slot];
    return result->live != 0U && result->generation == record->result_generation;
}

static dmp_status submit_req(node *self, uint32_t service, dmp_bytes payload,
                             dmp_time_ms now, dmp_reliability_handle *out)
{
    uint8_t token[16];
    dmp_status status;
    int requires_freshness = 0;
    size_t index;
    for (index = 0U; index < DMP_PROFILE_SERVICE_COUNT; index++) {
        if (self->endpoint.profile.service_id[index] == service &&
            (self->endpoint.profile.freshness_required_mask &
             (uint8_t)(1U << (unsigned)index)) != 0U) {
            requires_freshness = 1;
            break;
        }
    }
    if (service != 0U && requires_freshness != 0) {
        if (!local_service_action(self, service, DMP_ENDPOINT_PERMIT_REQ)) {
            return DMP_UNSUPPORTED;
        }
        if (!request_freshness_token(self, now, 12000U, token, NULL, NULL, 1)) {
            return DMP_AUTHENTICATION_FAILURE;
        }
        status = dmp_endpoint_submit_req_fresh(&self->endpoint, service, payload,
                                               span(token, sizeof token), now, out);
        memset(token, 0, sizeof token);
        return status;
    }
    return dmp_endpoint_submit_req(&self->endpoint, service, payload, now, out);
}

static int index_dropped(uint32_t index, const uint32_t *drop, int ndrop)
{
    int i;
    if (index == 0xffffffffU) {
        return 0;
    }
    for (i = 0; i < ndrop; i++) {
        if (drop[i] == index) {
            return 1;
        }
    }
    return 0;
}

static int deliver_mask(const captured *frames, int count, node *to, dmp_time_ms now,
                        const uint32_t *drop, int ndrop, captured *held, int *nheld, int hold_status)
{
    int index;
    dmp_status status = DMP_OK;
    for (index = 0; index < count; index++) {
        int hold = 0;
        if (hold_status && frames[index].type == DMP_TYPE_FRAG_STATUS) {
            hold = 1;
        }
        if (index_dropped(frames[index].index, drop, ndrop)) {
            hold = 1;
        }
        if (hold) {
            if (*nheld >= QUEUE) {
                return 1;
            }
            held[*nheld] = frames[index];
            (*nheld)++;
            continue;
        }
        if (deliver_one(to, &frames[index], now, &status) != 0) {
            return 1;
        }
        if (status != DMP_OK && status != DMP_INCOMPLETE && status != DMP_DUPLICATE) {
            (void)fprintf(stderr, "deliver status %d type %u index %u\n", (int)status,
                          (unsigned)frames[index].type, frames[index].index);
            return 1;
        }
    }
    return 0;
}

static int count_type(const captured *frames, int count, uint8_t type)
{
    int index;
    int n = 0;
    for (index = 0; index < count; index++) {
        if (frames[index].type == type) {
            n++;
        }
    }
    return n;
}

static int frame_seq_pn(const captured *frame, dmp_time_ms now, uint32_t *seq, uint64_t *pn)
{
    uint8_t core[MTU];
    size_t core_n = 0U;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_parse_result parsed;

    if (!unwrap_core(frame->frame, frame->len, core, sizeof core, &core_n, now)) {
        return 0;
    }
    memset(&view, 0, sizeof view);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    parsed = dmp_core_parse(span(core, core_n), &limits, &view);
    if (parsed.status != DMP_OK || (view.fields.options & DMP_OPT_SECURITY) == 0U) {
        return 0;
    }
    *seq = view.fields.seq;
    *pn = view.fields.security.pn;
    return 1;
}

static const dmp_reliability_sender_slot *live_frag_sender(const node *n)
{
    size_t index;
    for (index = 0U; index < SENDERS; index++) {
        if (n->senders[index].live != 0U && n->senders[index].frag_count >= 2U) {
            return &n->senders[index];
        }
    }
    return NULL;
}

static int service_sample(node *self, dmp_time_ms now)
{
    uint8_t payload[SAMPLE1_READ_BYTES];
    size_t n;
    if (!self->app.have_pending) {
        return 0;
    }
    if (self->app.service != 1U || self->app.req_n != 1U || self->app.req_body[0] != SAMPLE1_READ) {
        return 0;
    }
    n = sample1_read_rsp(payload, 1U, 2U, 300U);
    if (dmp_endpoint_complete(&self->endpoint, self->app.pending, false, 0U, span(payload, n), now) !=
        DMP_OK) {
        return 1;
    }
    self->app.have_pending = 0;
    return 0;
}

static void reset_measures(void)
{
    g_peak = 0U;
    g_tx = 0U;
    g_rx = 0U;
    g_provider = 0U;
}

static int captured_core_len(const captured *frame, dmp_time_ms now, size_t *out)
{
    uint8_t core[MTU];
    size_t n = 0U;
    if (frame == NULL || out == NULL ||
        !unwrap_core(frame->frame, frame->len, core, sizeof core, &n, now)) {
        return 0;
    }
    *out = n;
    return 1;
}

/* Largest service-2 body that is one protected frame, then that body plus one
 * byte, which must carry FRAG. The limit is measured from a one-byte frame
 * the encoder actually emitted. */
static int fit_boundary(session *env, port_ctx *port, int profile, uint32_t mtu, uint32_t chunk,
                        dmp_time_ms now)
{
    uint32_t index = 0U;
    uint8_t tiny[1] = {0x5aU};
    uint8_t body[512];
    captured frames[8];
    dmp_reliability_handle handle;
    size_t core_n = 0U;
    size_t overhead;
    size_t fit;
    int count;
    uint32_t pieces;

    CHECK(open_pair(env, port, profile, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(tiny, sizeof tiny), now, &handle) ==
          DMP_OK);
    CHECK(pump_sender_complete(&left, now, 1) == 0);
    count = take_queue(&left, frames, 8, now);
    CHECK(count == 1);
    CHECK(frames[0].index == 0xffffffffU);
    CHECK(captured_core_len(&frames[0], now, &core_n) == 1);
    CHECK(core_n > 1U && core_n < (size_t)mtu);
    overhead = core_n - 1U;
    fit = (size_t)mtu - overhead;
    CHECK(fit >= 1U && fit + 1U <= sizeof body);
    close_session(env);

    dmp_test_opaque_fill(body, fit, 0x71U);
    CHECK(open_pair(env, port, profile, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, fit), now, &handle) == DMP_OK);
    CHECK(pump_sender_complete(&left, now, 1) == 0);
    count = take_queue(&left, frames, 8, now);
    CHECK(count == 1);
    CHECK(frames[0].index == 0xffffffffU);
    CHECK(captured_core_len(&frames[0], now, &core_n) == 1);
    CHECK(core_n == (size_t)mtu);
    close_session(env);

    dmp_test_opaque_fill(body, fit + 1U, 0x72U);
    pieces = 1U + (uint32_t)fit / chunk;
    CHECK(pieces >= 2U && pieces <= 8U);
    CHECK(open_pair(env, port, profile, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, fit + 1U), now, &handle) ==
          DMP_OK);
    CHECK(pump_sender_complete(&left, now, (int)pieces) == 0);
    count = take_queue(&left, frames, 8, now);
    CHECK(count == (int)pieces);
    CHECK(frames[0].index == 0U);
    close_session(env);
    return 0;
}

static int test_geometry(session *env, port_ctx *port)
{
    reset_measures();
    uint32_t index = 0U;
    dmp_time_ms now = 20000U;
    dmp_reliability_handle handle;
    uint8_t body[MESSAGE];
    captured frames[QUEUE];
    int count;
    size_t n2 = dmp_test_opaque_len(32U, 2U, 0);
    size_t n8 = dmp_test_opaque_len(32U, 8U, 0);
    size_t n16 = dmp_test_opaque_len(32U, 16U, 0);
    size_t n32 = dmp_test_opaque_len(32U, 32U, 0);
    size_t n32s = dmp_test_opaque_len(32U, 32U, 1);
    size_t d16 = dmp_test_opaque_len(64U, 16U, 0);
    size_t d16s = dmp_test_opaque_len(64U, 16U, 1);
    const dmp_reliability_sender_slot *sender;
    (void)printf("P19 caller_node_bytes=%u\n", (unsigned)sizeof(node));
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    dmp_test_opaque_fill(body, n2, 0x11U);
    CHECK(submit_req(&left, 2U, span(body, n2), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 1) == 0);
    count = take_queue(&left, frames, QUEUE, now);
    /* 64 bytes fit one protected frame at MTU 256, so FRAG is omitted. */
    CHECK(count == 1);
    CHECK(frames[0].index == 0xffffffffU);
    g_hold = 0;
    CHECK(deliver_mask(frames, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == n2);
    CHECK(memcmp(right.app.req_body, body, n2) == 0);
    sender = live_frag_sender(&left);
    CHECK(sender == NULL);
    close_session(env);
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    dmp_test_opaque_fill(body, n8, 0x21U);
    CHECK(submit_req(&left, 2U, span(body, n8), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, frames, QUEUE, now);
    CHECK(count == 8);
    CHECK(count_type(frames, count, DMP_TYPE_REQ) == 8);
    CHECK(deliver_mask(frames, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.assembled == 1);
    CHECK(right.app.req_n == n8);
    CHECK(memcmp(right.app.req_body, body, n8) == 0);
    CHECK(right.app.asm_n == n8);
    CHECK(memcmp(right.app.asm_body, body, n8) == 0);
    close_session(env);
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    dmp_test_opaque_fill(body, n16, 0x31U);
    CHECK(submit_req(&left, 2U, span(body, n16), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 16) == 0);
    count = take_queue(&left, frames, QUEUE, now);
    CHECK(count == 16);
    CHECK(frames[0].index == 0U);
    CHECK(frames[15].index == 15U);
    g_hold = 0;
    CHECK(deliver_mask(frames, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == n16);
    CHECK(memcmp(right.app.req_body, body, n16) == 0);
    close_session(env);
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    dmp_test_opaque_fill(body, n32, 0x41U);
    CHECK(submit_req(&left, 2U, span(body, n32), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 32) == 0);
    count = take_queue(&left, frames, QUEUE, now);
    CHECK(count == 32);
    CHECK(frames[31].index == 31U);
    g_hold = 0;
    CHECK(deliver_mask(frames, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == n32);
    CHECK(memcmp(right.app.req_body, body, n32) == 0);
    close_session(env);
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    dmp_test_opaque_fill(body, n32s, 0x42U);
    CHECK(submit_req(&left, 2U, span(body, n32s), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 32) == 0);
    count = take_queue(&left, frames, QUEUE, now);
    CHECK(count == 32);
    CHECK(deliver_mask(frames, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == n32s);
    CHECK(memcmp(right.app.req_body, body, n32s) == 0);
    {
        dmp_status second =
            submit_req(&left, 2U, span(body, n32s), now, &handle);
        CHECK(second == DMP_QUOTA_EXHAUSTED || second == DMP_BUSY);
    }
    close_session(env);
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    {
        uint8_t over[1025];
        memset(over, 0x7e, sizeof over);
        CHECK(submit_req(&left, 2U, span(over, sizeof over), now, &handle) ==
              DMP_LIMIT_EXHAUSTED);
    }
    CHECK(left.wire.n == 0);
    CHECK(left.endpoint.frag_live == 0U);
    close_session(env);
    CHECK(d16 == 1024U);
    CHECK(d16s == 961U);
    CHECK(open_pair(env, port, PROF_DIRECT, now, 0, &index) == 0);
    dmp_test_opaque_fill(body, 16U, 0x51U);
    CHECK(submit_req(&left, 2U, span(body, 16U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 1) == 0);
    count = take_queue(&left, frames, QUEUE, now);
    CHECK(count == 1);
    g_hold = 0;
    CHECK(deliver_mask(frames, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == 16U);
    close_session(env);
    CHECK(open_pair(env, port, PROF_DIRECT, now, 0, &index) == 0);
    dmp_test_opaque_fill(body, d16, 0x52U);
    CHECK(submit_req(&left, 2U, span(body, d16), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 16) == 0);
    count = take_queue(&left, frames, QUEUE, now);
    CHECK(count == 16);
    CHECK(frames[0].index == 0U);
    CHECK(frames[15].index == 15U);
    g_hold = 0;
    CHECK(deliver_mask(frames, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == d16);
    CHECK(memcmp(right.app.req_body, body, d16) == 0);
    close_session(env);
    CHECK(open_pair(env, port, PROF_DIRECT, now, 0, &index) == 0);
    dmp_test_opaque_fill(body, d16s, 0x53U);
    CHECK(submit_req(&left, 2U, span(body, d16s), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 16) == 0);
    count = take_queue(&left, frames, QUEUE, now);
    CHECK(count == 16);
    g_hold = 0;
    CHECK(deliver_mask(frames, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == d16s);
    CHECK(memcmp(right.app.req_body, body, d16s) == 0);
    {
        uint8_t over[1025];
        memset(over, 0x7e, sizeof over);
        CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(over, sizeof over), now) ==
              DMP_LIMIT_EXHAUSTED);
    }
    close_session(env);
    CHECK(fit_boundary(env, port, PROF_RADIO, 256U, 32U, now) == 0);
    CHECK(open_pair(env, port, PROF_RADIO_N2, now, 0, &index) == 0);
    dmp_test_opaque_fill(body, 96U, 0x61U);
    CHECK(submit_req(&left, 2U, span(body, 96U), now, &handle) == DMP_OK);
    CHECK(pump_sender_complete(&left, now, 2) == 0);
    count = take_queue(&left, frames, QUEUE, now);
    CHECK(count == 2);
    CHECK(frames[0].index == 0U && frames[1].index == 1U);
    g_hold = 0;
    CHECK(deliver_mask(frames, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 0);
    CHECK(wire_complete_delayed(&left, now + 1U) >= 1);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 1U) == DMP_OK);
    count = take_queue(&left, frames, QUEUE, now + 1U);
    CHECK(count == 1 && frames[0].index == 2U);
    CHECK(deliver_one(&right, &frames[0], now + 1U, NULL) == 0);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == 96U);
    CHECK(memcmp(right.app.req_body, body, 96U) == 0);
    close_session(env);
    CHECK(fit_boundary(env, port, PROF_RADIO_N2, 128U, 32U, now) == 0);
    CHECK(fit_boundary(env, port, PROF_DIRECT, 263U, 64U, now) == 0);
    note_peak();
    CHECK(g_provider > 0U && g_provider <= 3U * 12288U);
    CHECK(g_peak > 0U && g_peak <= 4U * 1536U + 1536U + 1536U);
    report("geometry", port, "direct-n16");
    close_session(env);
    return 0;
}

static int test_async(session *env, port_ctx *port)
{
    dmp_time_ms now = 30000U;
    uint32_t index = 0U;
    uint8_t payload[48];
    uint8_t reply[9];
    dmp_bytes empty = {NULL, 0U};
    dmp_reliability_handle handle;
    captured frames[QUEUE];
    delayed_completion stale;
    dmp_status status = DMP_OK;
    int count;

    reset_measures();
    dmp_test_opaque_fill(payload, sizeof payload, 0xa1U);
    CHECK(open_pair(env, port, PROF_DIRECT_ASYNC, now, 0, &index) == 0);
    CHECK(left.endpoint.profile.synchronous_completion == 0U);
    CHECK(left.transport.caps.synchronous_completion == 0U);
    CHECK(dmp_endpoint_submit_data(&left.endpoint, 2U, span(payload, sizeof payload), empty,
                                   now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 1) == 0);
    CHECK(left.wire.delayed_count == 1);
    CHECK(left.endpoint.wire_busy != 0U);
    count = take_queue(&left, frames, QUEUE, now);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_DATA);
    CHECK(deliver_one(&right, &frames[0], now, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(right.app.data_accepted == 1);
    CHECK(right.wire.delayed_count == 1);
    CHECK(wire_complete_delayed(&left, now + 1U) == 1);
    CHECK(left.endpoint.wire_busy == 0U);
    CHECK(wire_complete_delayed(&right, now + 2U) == 1);
    count = take_queue(&right, frames, QUEUE, now + 2U);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_ACK);
    CHECK(deliver_one(&left, &frames[0], now + 2U, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(left.app.data_delivered == 1);
    close_session(env);

    /* EVENT uses the same reliable delivery receipt and remains independently
     * covered from the DATA API. The caller buffer may be reused after submit. */
    CHECK(open_pair(env, port, PROF_DIRECT_ASYNC, now + 10U, 0, &index) == 0);
    dmp_test_opaque_fill(payload, sizeof payload, 0xb2U);
    CHECK(dmp_endpoint_submit_event(&left.endpoint, 2U, span(payload, sizeof payload), empty,
                                    now + 10U, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now + 10U, 1) == 0);
    count = take_queue(&left, frames, QUEUE, now + 10U);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_EVENT);
    memset(payload, 0, sizeof payload);
    CHECK(deliver_one(&right, &frames[0], now + 10U, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(right.app.data_accepted == 1);
    CHECK(right.wire.delayed_count == 1);
    CHECK(wire_complete_delayed(&left, now + 11U) == 1);
    CHECK(wire_complete_delayed(&right, now + 12U) == 1);
    count = take_queue(&right, frames, QUEUE, now + 12U);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_ACK);
    CHECK(deliver_one(&left, &frames[0], now + 12U, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(left.app.data_delivered == 1);
    close_session(env);

    /* A valid peer result can arrive before the origin's local TX completion.
     * That result is authoritative; the delayed callback must not emit UNKNOWN. */
    CHECK(open_pair(env, port, PROF_DIRECT_ASYNC, now + 20U, 0, &index) == 0);
    dmp_test_opaque_fill(payload, sizeof payload, 0xc3U);
    dmp_test_opaque_fill(reply, sizeof reply, 0xd4U);
    CHECK(dmp_endpoint_submit_req(&left.endpoint, 2U, span(payload, sizeof payload), now + 20U,
                                  &handle) == DMP_OK);
    CHECK(pump_sender(&left, now + 20U, 1) == 0);
    count = take_queue(&left, frames, QUEUE, now + 20U);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_REQ);
    CHECK(deliver_one(&right, &frames[0], now + 20U, &status) == 0);
    CHECK(status == DMP_OK && right.app.accepts == 1 && right.app.have_pending != 0);
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 20U + RADIO_RECEIPT_MS) == DMP_OK);
    count = take_queue(&right, frames, QUEUE, now + 20U + RADIO_RECEIPT_MS);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_ACK);
    CHECK(deliver_one(&left, &frames[0], now + 20U + RADIO_RECEIPT_MS, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(wire_complete_delayed(&right, now + 21U + RADIO_RECEIPT_MS) == 1);
    CHECK(dmp_endpoint_complete(&right.endpoint, right.app.pending, false, 0U,
                                span(reply, sizeof reply), now + 21U + RADIO_RECEIPT_MS) == DMP_OK);
    CHECK(pump_sender(&right, now + 21U + RADIO_RECEIPT_MS, 1) == 0);
    count = take_queue(&right, frames, QUEUE, now + 21U + RADIO_RECEIPT_MS);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_RSP);
    CHECK(deliver_one(&left, &frames[0], now + 21U + RADIO_RECEIPT_MS, &status) == 0);
    CHECK(status == DMP_OK && left.app.results == 1);
    CHECK(left.app.unknowns == 0 && left.app.local_unsents == 0);
    CHECK(wire_complete_delayed(&left, now + 22U + RADIO_RECEIPT_MS) >= 1);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 22U + RADIO_RECEIPT_MS) == DMP_OK);
    CHECK(left.app.results == 1 && left.app.unknowns == 0);
    close_session(env);

    /* Accepted local submit plus cancellation is uncertain until the terminal
     * callback. A duplicate callback carrying an old generation cannot consume
     * the adapter slot after it has been reused by new work. */
    CHECK(open_pair(env, port, PROF_DIRECT_ASYNC, now + 30U, 0, &index) == 0);
    CHECK(dmp_endpoint_submit_req(&left.endpoint, 2U, span(payload, sizeof payload), now + 30U,
                                  &handle) == DMP_OK);
    CHECK(pump_sender(&left, now + 30U, 1) == 0);
    CHECK(left.wire.delayed_count == 1);
    stale = left.wire.delayed[0];
    CHECK(dmp_reliability_cancel(&left.endpoint.reliability, handle, now + 31U) == DMP_OK);
    CHECK(left.app.unknowns == 0 && left.app.local_unsents == 0);
    CHECK(wire_complete_one(&left, now + 32U, DMP_TX_TRANSMITTED, NULL) == 1);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 32U) == DMP_OK);
    CHECK(left.app.unknowns == 1 && left.app.local_unsents == 0);
    CHECK(dmp_endpoint_submit_req(&left.endpoint, 2U, span(payload, sizeof payload), now + 33U,
                                  &handle) == DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 33U) == DMP_OK);
    CHECK(left.wire.delayed_count == 1);
    stale.complete(stale.owner, stale.token, DMP_TX_TRANSMITTED, now + 34U);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 34U) == DMP_OK);
    CHECK(left.wire.delayed_count == 1);
    CHECK(wire_complete_delayed(&left, now + 35U) == 1);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 35U) == DMP_OK);
    report("async-data-event-result-cancel-stale", port, "pass");
    close_session(env);
    return 0;
}

static int test_async_radio(session *env, port_ctx *port)
{
    dmp_time_ms now = 40000U;
    uint32_t index = 0U;
    uint8_t payload[96];
    dmp_reliability_handle handle;
    captured frames[QUEUE];
    dmp_status status = DMP_OK;
    int count;

    reset_measures();
    dmp_test_opaque_fill(payload, sizeof payload, 0xe5U);
    CHECK(open_pair(env, port, PROF_RADIO_N2, now, 0, &index) == 0);
    CHECK(left.endpoint.profile.synchronous_completion == 0U);
    CHECK(right.endpoint.profile.synchronous_completion == 0U);
    CHECK(submit_req(&left, 2U, span(payload, sizeof payload), now, &handle) == DMP_OK);

    /* The first fragment is physically delivered, while its ordinary local
     * completion callback is still pending. The receiver's delayed FRAG_STATUS
     * must update the live sender without requiring synchronous completion. */
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 1 && left.wire.delayed_count == 1);
    count = take_queue(&left, frames, QUEUE, now);
    CHECK(count == 1 && frames[0].index == 0U);
    CHECK(deliver_one(&right, &frames[0], now, &status) == 0);
    CHECK(status == DMP_INCOMPLETE);
    right.wire.now = now + RADIO_COLLECT_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS) == DMP_OK);
    count = take_queue(&right, frames, QUEUE, now + RADIO_COLLECT_MS);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_FRAG_STATUS);
    CHECK(deliver_one(&left, &frames[0], now + RADIO_COLLECT_MS, &status) == 0);
    CHECK(status == DMP_OK || status == DMP_DUPLICATE);
    CHECK(wire_complete_delayed(&right, now + RADIO_COLLECT_MS + 1U) == 1);
    CHECK(live_frag_sender(&left) != NULL);

    CHECK(wire_complete_one(&left, now + RADIO_COLLECT_MS + 1U,
                            DMP_TX_TRANSMITTED, NULL) == 1);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_COLLECT_MS + 1U) == DMP_OK);
    count = take_queue(&left, frames, QUEUE, now + RADIO_COLLECT_MS + 1U);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_REQ && frames[0].index == 1U);
    CHECK(deliver_one(&right, &frames[0], now + RADIO_COLLECT_MS + 1U, &status) == 0);
    CHECK(status == DMP_INCOMPLETE && right.app.accepts == 0);
    CHECK(wire_complete_delayed(&left, now + RADIO_COLLECT_MS + 2U) == 1);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_COLLECT_MS + 2U) == DMP_OK);
    count = take_queue(&left, frames, QUEUE, now + RADIO_COLLECT_MS + 2U);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_REQ && frames[0].index == 2U);
    CHECK(deliver_one(&right, &frames[0], now + RADIO_COLLECT_MS + 2U, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == 1 && right.app.req_n == sizeof payload);
    CHECK(memcmp(right.app.req_body, payload, sizeof payload) == 0);
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS + 2U + RADIO_RECEIPT_MS) ==
          DMP_OK);
    count = take_queue(&right, frames, QUEUE,
                       now + RADIO_COLLECT_MS + 2U + RADIO_RECEIPT_MS);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_ACK);
    CHECK(deliver_one(&left, &frames[0], now + RADIO_COLLECT_MS + 2U + RADIO_RECEIPT_MS,
                      &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(left.app.unknowns == 0 && left.app.local_unsents == 0);

    /* Complete both ordinary callbacks only after feedback and acceptance have
     * crossed in the opposite direction. No callback means remote delivery. */
    CHECK(wire_complete_delayed(&left, now + RADIO_COLLECT_MS + 3U) >= 1);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_COLLECT_MS + 3U) == DMP_OK);
    CHECK(wire_complete_delayed(&right, now + RADIO_COLLECT_MS + 3U) >= 1);
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS + 3U) == DMP_OK);
    report("async-radio-delayed-status", port, "pass");
    close_session(env);

    /* N=2 with index 0 lost: feedback asks for the missing first slice while
     * the last slice is also absent. A local callback is not remote delivery. */
    CHECK(open_pair(env, port, PROF_RADIO_N2, now + 10U, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(payload, sizeof payload), now + 10U, &handle) == DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 10U) == DMP_OK);
    CHECK(left.wire.n == 1 && left.wire.delayed_count == 1);
    count = take_queue(&left, frames, QUEUE, now + 10U);
    CHECK(count == 1 && frames[0].index == 0U);
    /* Drop index 0. Completing its local send permits the genuine index 1. */
    CHECK(wire_complete_delayed(&left, now + 11U) == 1);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 11U) == DMP_OK);
    CHECK(left.wire.n == 1 && left.wire.delayed_count == 1);
    count = take_queue(&left, frames, QUEUE, now + 11U);
    CHECK(count == 1 && frames[0].index == 1U);
    CHECK(deliver_one(&right, &frames[0], now + 11U, &status) == 0);
    CHECK(status == DMP_INCOMPLETE && right.app.accepts == 0);
    right.wire.now = now + 11U + RADIO_COLLECT_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 11U + RADIO_COLLECT_MS) == DMP_OK);
    count = take_queue(&right, frames, QUEUE, now + 11U + RADIO_COLLECT_MS);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_FRAG_STATUS);
    CHECK(right.assemblies[0].status_mask == 0x05U);
    CHECK(deliver_one(&left, &frames[0], now + 11U + RADIO_COLLECT_MS, &status) == 0);
    CHECK(status == DMP_OK || status == DMP_DUPLICATE);
    CHECK(wire_complete_delayed(&right, now + 11U + RADIO_COLLECT_MS + 1U) == 1);
    CHECK(live_frag_sender(&left) != NULL);
    /* The sender finishes the current burst before applying the requested
     * repair mask. */
    CHECK(wire_complete_delayed(&left, now + 12U + RADIO_COLLECT_MS) == 1);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 12U + RADIO_COLLECT_MS) == DMP_OK);
    count = take_queue(&left, frames, QUEUE, now + 12U + RADIO_COLLECT_MS);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_REQ && frames[0].index == 2U);
    CHECK(deliver_one(&right, &frames[0], now + 12U + RADIO_COLLECT_MS, &status) == 0);
    CHECK(status == DMP_INCOMPLETE && right.app.accepts == 0);
    CHECK(wire_complete_delayed(&left, now + 13U + RADIO_COLLECT_MS) == 1);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 13U + RADIO_COLLECT_MS) == DMP_OK);
    count = take_queue(&left, frames, QUEUE, now + 13U + RADIO_COLLECT_MS);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_REQ && frames[0].index == 0U);
    CHECK(deliver_one(&right, &frames[0], now + 13U + RADIO_COLLECT_MS, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == 1 && right.app.req_n == sizeof payload);
    CHECK(right.app.accepts == 1 && right.app.req_n == sizeof payload);
    CHECK(memcmp(right.app.req_body, payload, sizeof payload) == 0);
    report("async-radio-n2-index0-repair", port, "pass");
    close_session(env);
    return 0;
}

static int test_freshness(session *env, port_ctx *port)
{
    dmp_time_ms now = 50000U;
    uint32_t index = 0U;
    uint8_t token[16];
    uint8_t request[5] = {0x10U, 0xe0U, 0x2eU, 0U, 0U};
    uint8_t body[64];
    uint8_t fragmented_body[MESSAGE];
    size_t fragmented_size;
    size_t fragmented_count;
    captured grant_req;
    captured first_rsp;
    captured duplicate_rsp;
    captured duplicate_req;
    captured frames[QUEUE];
    dmp_reliability_handle handle;
    dmp_status status = DMP_OK;
    uint32_t grant_req_seq = 0U;
    uint32_t result_seq = 0U;
    uint32_t duplicate_seq = 0U;
    int count;
    size_t i;

    reset_measures();
    dmp_test_opaque_fill(body, sizeof body, 0x6bU);
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    memset(&grant_req, 0, sizeof grant_req);
    memset(&first_rsp, 0, sizeof first_rsp);
    CHECK(request_freshness_token(&left, now, 12000U, token, &grant_req, &first_rsp, 0));
    CHECK(grant_req.len != 0U && first_rsp.len != 0U);
    CHECK(left.app.grants == 1 && left.app.grant_n == 21U &&
          memcmp(left.app.grant_body + 1U, token, sizeof token) == 0);
    CHECK(captured_seq(&first_rsp, now, &result_seq));

    /* Duplicate the exact control REQ identity under a fresh SEC-1 PN while
     * the original result remains unacknowledged. It must resend the cached
     * result identity and its original token/lifetime, not mint another grant. */
    CHECK(reseal_new_pn(env, index, &grant_req, span(request, sizeof request), now + 1U,
                        &duplicate_req));
    CHECK(captured_seq(&grant_req, now, &grant_req_seq));
    CHECK(captured_seq(&duplicate_req, now + 1U, &duplicate_seq));
    CHECK(grant_req_seq == duplicate_seq);
    CHECK(deliver_one(&right, &duplicate_req, now + 1U, &status) == 0);
    CHECK(status == DMP_DUPLICATE || status == DMP_OK);
    CHECK(right.app.accepts == 0);
    CHECK(pump_sender(&right, now + 1U, 1) == 0);
    count = take_queue(&right, frames, QUEUE, now + 1U);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_RSP);
    duplicate_rsp = frames[0];
    CHECK(captured_seq(&frames[0], now + 1U, &duplicate_seq));
    CHECK(duplicate_seq == result_seq);

    /* Deliver that cached result to the real origin. Its callback remains
     * exactly once; the origin's ACK releases the responder's result slot. */
    CHECK(deliver_one(&left, &frames[0], now + 2U, &status) == 0);
    CHECK(status == DMP_DUPLICATE || status == DMP_OK);
    CHECK(left.app.grants == 1 && memcmp(left.app.grant_body + 1U, token, sizeof token) == 0);
    count = take_queue(&left, frames, QUEUE, now + 2U);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_ACK);
    CHECK(deliver_one(&right, &frames[0], now + 2U, &status) == 0);
    CHECK(status == DMP_OK || status == DMP_DUPLICATE);

    /* Once the cached RSP is released, the retained grant identity gets only
     * receipt ACKs; it cannot recreate a token or redispatch control. */
    CHECK(reseal_new_pn(env, index, &grant_req, span(request, sizeof request), now + 3U,
                        &duplicate_req));
    CHECK(deliver_one(&right, &duplicate_req, now + 3U, &status) == 0);
    CHECK(status == DMP_DUPLICATE || status == DMP_OK);
    CHECK(pump_sender(&right, now + 3U, 1) == 0);
    count = take_queue(&right, frames, QUEUE, now + 3U);
    CHECK(count >= 1 && count <= QUEUE);
    for (i = 0U; i < (size_t)count; i++) {
        CHECK(frames[i].type == DMP_TYPE_ACK);
        CHECK(deliver_one(&left, &frames[i], now + 3U, &status) == 0);
        CHECK(status == DMP_OK || status == DMP_DUPLICATE);
    }
    for (i = 0U; i < sizeof right.freshness / sizeof right.freshness[0]; i++) {
        CHECK(right.freshness[i].state != DMP_ENDPOINT_FRESHNESS_RESERVED);
    }
    CHECK(left.app.grants == 1);
    close_session(env);

    /* An independent fresh association with the same deterministic public
     * fixture opens the retransmitted ciphertext for a byte-exact grant check.
     * Keep this sequential because the provider adapter has one active owner. */
    {
        const noise_fixture_probe_fixture_t *fixture = find_fixture();
        session inspector;
        port_ctx inspect_port;
        uint32_t inspect_index = 0U;
        uint8_t plain[DMP_HS_APP_PLAIN_MAX];
        size_t plain_n = 0U;
        dmp_frame_view view;
        CHECK(fixture != NULL && make_pair(&inspector, &inspect_port, fixture, RADIO_SHA) &&
              drive_nn(&inspector, &inspect_index) && activate(&inspector, inspect_index));
        CHECK(open_captured(&inspector, inspect_index, &duplicate_rsp, now + 1U, &view, plain,
                            sizeof plain, &plain_n));
        CHECK(view.fields.type == DMP_TYPE_RSP && plain_n == 21U && plain[0] == 0x11U);
        CHECK(memcmp(plain + 1U, token, sizeof token) == 0);
        CHECK(plain[17] == 0xe0U && plain[18] == 0x2eU && plain[19] == 0U && plain[20] == 0U);
        close_session(&inspector);
    }

    /* A token remains independently usable after its grant RSP sender is
     * acknowledged. The dedup result slot remains retained through its TTL. */
    CHECK(open_pair(env, port, PROF_RADIO, now + 10U, 0, &index) == 0);
    CHECK(request_freshness_token(&left, now + 10U, 12000U, token, NULL, NULL, 1));
    {
        dmp_endpoint_freshness_slot *record = freshness_record(&right, token);
        CHECK(record != NULL && record->state == DMP_ENDPOINT_FRESHNESS_ISSUED);
        CHECK(record->expires_at == now + 12010U);
        CHECK(freshness_result_retained(&right, record));
        CHECK(right.results[record->result_slot].acknowledged != 0U);
        CHECK(dmp_endpoint_submit_req_fresh(&left.endpoint, 2U, span(body, sizeof body),
                                            span(token, sizeof token), now + 11U,
                                            &handle) == DMP_OK);
        CHECK(pump_sender(&left, now + 11U, 1) == 0);
        count = take_queue(&left, frames, QUEUE, now + 11U);
        CHECK(count == 1 && frames[0].type == DMP_TYPE_REQ);
        CHECK(deliver_one(&right, &frames[0], now + 11U, &status) == 0);
        CHECK(status == DMP_OK && right.app.accepts == 1);
        CHECK(record->state == DMP_ENDPOINT_FRESHNESS_CONSUMED);
    }
    close_session(env);

    /* The token's lease can expire before the independent retained grant RSP.
     * At the exact receiver expiry boundary it cannot authorize dispatch. */
    CHECK(open_pair(env, port, PROF_RADIO, now + 20U, 0, &index) == 0);
    CHECK(request_freshness_token(&left, now + 20U, 5000U, token, NULL, NULL, 0));
    {
        dmp_endpoint_freshness_slot *record = freshness_record(&right, token);
        dmp_time_ms expiry = now + 5020U;
        CHECK(record != NULL && record->state == DMP_ENDPOINT_FRESHNESS_ISSUED);
        CHECK(record->expires_at == expiry && freshness_result_retained(&right, record));
        CHECK(dmp_endpoint_submit_req_fresh(&left.endpoint, 2U, span(body, sizeof body),
                                            span(token, sizeof token), expiry,
                                            &handle) == DMP_OK);
        CHECK(pump_sender(&left, expiry, 1) == 0);
        count = take_queue(&left, frames, QUEUE, expiry);
        {
            int request_index = -1;
            for (i = 0U; i < (size_t)count; i++) {
                if (frames[i].type == DMP_TYPE_REQ) {
                    request_index = i;
                }
            }
            CHECK(request_index >= 0);
            CHECK(deliver_one(&right, &frames[request_index], expiry, &status) == 0);
        }
        CHECK(right.app.accepts == 0);
        CHECK(record->state == DMP_ENDPOINT_FRESHNESS_CONSUMED);
        CHECK(freshness_result_retained(&right, record));
    }
    close_session(env);

    /* A fragmented command binds on its first slice, then expiry is checked
     * again when the final slice arrives exactly at the lease deadline. */
    CHECK(open_pair(env, port, PROF_RADIO, now + 30U, 0, &index) == 0);
    CHECK(request_freshness_token(&left, now + 30U, 5000U, token, NULL, NULL, 1));
    /* Force the protected unfragmented size probe over its encoded MTU. */
    fragmented_size = left.endpoint.profile.encoded_mtu;
    CHECK(fragmented_size <= sizeof fragmented_body);
    CHECK(fragmented_size > left.endpoint.profile.chunk_bytes);
    fragmented_count = 1U + (fragmented_size - 1U) / left.endpoint.profile.chunk_bytes;
    CHECK(fragmented_count >= 2U && fragmented_count <= QUEUE);
    dmp_test_opaque_fill(fragmented_body, fragmented_size, 0x75U);
    CHECK(dmp_endpoint_submit_req_fresh(&left.endpoint, 2U, span(fragmented_body, fragmented_size),
                                        span(token, sizeof token), now + 31U, &handle) == DMP_OK);
    CHECK(left.senders[handle.slot].frag_count == fragmented_count);
    CHECK(pump_sender(&left, now + 31U, 1) == 0);
    count = take_queue(&left, frames, QUEUE, now + 31U);
    CHECK(count == (int)fragmented_count);
    for (i = 0U; i < (size_t)count; i++) {
        CHECK(frames[i].type == DMP_TYPE_REQ && frames[i].index == (uint32_t)i);
    }
    /* Deliver only the establishing slice; all others are lost. */
    CHECK(deliver_one(&right, &frames[0], now + 31U, &status) == 0);
    CHECK(status == DMP_INCOMPLETE && right.app.accepts == 0);
    {
        dmp_time_ms collect_at = now + 31U + RADIO_COLLECT_MS;
        dmp_time_ms expiry = now + 5030U;
        CHECK(dmp_endpoint_poll(&right.endpoint, collect_at) == DMP_OK);
        count = take_queue(&right, frames, QUEUE, collect_at);
        CHECK(count == 1 && frames[0].type == DMP_TYPE_FRAG_STATUS);
        CHECK(deliver_one(&left, &frames[0], collect_at, &status) == 0);
        CHECK(status == DMP_OK || status == DMP_DUPLICATE);
        CHECK(pump_sender(&left, collect_at, (int)fragmented_count - 1) == 0);
        count = take_queue(&left, frames, QUEUE, collect_at);
        CHECK(count == (int)fragmented_count - 1);
        CHECK(right.assemblies[0].live != 0U && right.app.accepts == 0);
        for (i = 0U; i < (size_t)count; i++) {
            CHECK(frames[i].type == DMP_TYPE_REQ && frames[i].index == (uint32_t)i + 1U);
            if (i + 1U == (size_t)count) {
                CHECK(deliver_one(&right, &frames[i], expiry, &status) == 0);
            } else {
                CHECK(deliver_one(&right, &frames[i], collect_at, &status) == 0);
                CHECK(status == DMP_INCOMPLETE);
            }
        }
        CHECK(right.app.accepts == 0 && right.app.assembled == 0);
        {
            dmp_endpoint_freshness_slot *record = freshness_record(&right, token);
            CHECK(record != NULL && record->state == DMP_ENDPOINT_FRESHNESS_CONSUMED);
        }
    }
    close_session(env);

    /* The manifest allows two grant requests per peer/association. A third
     * fresh REQ identity receives STATUS=4 without minting or dispatching a
     * token; the two existing token records remain intact. */
    CHECK(open_pair(env, port, PROF_RADIO, now + 40U, 0, &index) == 0);
    {
        uint8_t token_a[16];
        uint8_t token_b[16];
        uint8_t request_body[5] = {0x10U, 0xe0U, 0x2eU, 0U, 0U};
        size_t live_tokens = 0U;
        CHECK(request_freshness_token(&left, now + 40U, 12000U, token_a, NULL, NULL, 1));
        CHECK(request_freshness_token(&left, now + 41U, 12000U, token_b, NULL, NULL, 1));
        CHECK(memcmp(token_a, token_b, sizeof token_a) != 0);
        CHECK(dmp_endpoint_submit_req(&left.endpoint, 0U, span(request_body, sizeof request_body),
                                      now + 42U, &handle) == DMP_OK);
        CHECK(pump_sender(&left, now + 42U, 1) == 0);
        count = take_queue(&left, frames, QUEUE, now + 42U);
        CHECK(count == 1 && frames[0].type == DMP_TYPE_REQ);
        CHECK(deliver_one(&right, &frames[0], now + 42U, &status) == 0);
        CHECK(left.app.grants == 2);
        CHECK(pump_sender(&right, now + 42U, 1) == 0);
        count = take_queue(&right, frames, QUEUE, now + 42U);
        CHECK(count == 1 && frames[0].type == DMP_TYPE_ERR);
        {
            uint8_t core[MTU];
            size_t core_n = 0U;
            size_t cursor = 0U;
            int status_found = 0;
            dmp_frame_view view;
            CHECK(captured_view(&frames[0], now + 42U, core, &core_n, &view));
            while (cursor < view.extensions.size) {
                dmp_extension_view extension;
                CHECK(dmp_extension_next(view.extensions, &cursor, &extension) == DMP_OK);
                if ((extension.tag >> 2U) == 5U) {
                    CHECK(extension.value.size == 1U && extension.value.data[0] == 4U);
                    status_found = 1;
                    break;
                }
            }
            CHECK(status_found != 0);
        }
        CHECK(deliver_one(&left, &frames[0], now + 42U, &status) == 0);
        CHECK(left.app.grants == 2);
        CHECK(freshness_record(&right, token_a) != NULL &&
              freshness_record(&right, token_b) != NULL);
        for (i = 0U; i < sizeof right.freshness / sizeof right.freshness[0]; i++) {
            if (right.freshness[i].state != DMP_ENDPOINT_FRESHNESS_EMPTY) {
                live_tokens++;
            }
        }
        CHECK(live_tokens == 2U);
    }
    close_session(env);

    /* Destroying the association fences its token table. Replaying that token
     * under fresh traffic keys for the same peer IDs cannot authorize service
     * 2, while service 1 (which has no freshness requirement) still works. */
    CHECK(open_pair(env, port, PROF_RADIO, now + 50U, 0, &index) == 0);
    CHECK(request_freshness_token(&left, now + 50U, 12000U, token, NULL, NULL, 1));
    close_session(env);
    CHECK(open_pair(env, port, PROF_RADIO, now + 60U, 0, &index) == 0);
    CHECK(allow_service1_request(&left) == 0 && allow_service1_request(&right) == 0);
    CHECK(freshness_record(&right, token) == NULL);
    CHECK(dmp_endpoint_submit_req_fresh(&left.endpoint, 2U, span(body, sizeof body),
                                        span(token, sizeof token), now + 61U, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now + 61U, 1) == 0);
    count = take_queue(&left, frames, QUEUE, now + 61U);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_REQ);
    CHECK(deliver_one(&right, &frames[0], now + 61U, &status) == 0);
    CHECK(right.app.accepts == 0);
    CHECK(freshness_record(&right, token) == NULL);
    {
        uint8_t nonfresh_body[1] = {0x42U};
        CHECK(submit_req(&left, 1U, span(nonfresh_body, sizeof nonfresh_body), now + 62U,
                         &handle) == DMP_OK);
    }
    CHECK(pump_sender(&left, now + 62U, 1) == 0);
    count = take_queue(&left, frames, QUEUE, now + 62U);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_REQ);
    CHECK(deliver_one(&right, &frames[0], now + 62U, &status) == 0);
    CHECK(status == DMP_OK && right.app.accepts == 1 && right.app.service == 1U);
    close_session(env);

    /* Missing sender token is refused before any frame. A valid token is then
     * single-use and remains consumed through a fresh-PN duplicate REQ. */
    CHECK(open_pair(env, port, PROF_RADIO, now + 10U, 0, &index) == 0);
    CHECK(request_freshness_token(&left, now + 10U, 12000U, token, NULL, NULL, 1));
    {
        dmp_bytes empty = {NULL, 0U};
        CHECK(dmp_endpoint_submit_req_fresh(&left.endpoint, 2U, span(body, sizeof body), empty,
                                            now + 11U, &handle) == DMP_INVALID_ARGUMENT);
        CHECK(left.wire.n == 0);
    }
    CHECK(dmp_endpoint_submit_req_fresh(&left.endpoint, 2U, span(body, sizeof body),
                                        span(token, sizeof token), now + 11U, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now + 11U, 1) == 0);
    count = take_queue(&left, frames, QUEUE, now + 11U);
    CHECK(count == 1 && frames[0].type == DMP_TYPE_REQ && frames[0].index == 0xffffffffU);
    {
        captured accepted_req = frames[0];
        CHECK(deliver_one(&right, &accepted_req, now + 11U, &status) == 0);
        CHECK(status == DMP_OK && right.app.accepts == 1);
        CHECK(right.app.req_n == sizeof body && memcmp(right.app.req_body, body, sizeof body) == 0);
        for (i = 0U; i < sizeof right.freshness / sizeof right.freshness[0]; i++) {
            if (memcmp(right.freshness[i].token, token, sizeof token) == 0) {
                CHECK(right.freshness[i].state == DMP_ENDPOINT_FRESHNESS_CONSUMED);
            }
        }
        CHECK(reseal_new_pn(env, index, &accepted_req, span(body, sizeof body), now + 12U,
                            &duplicate_req));
        CHECK(deliver_one(&right, &duplicate_req, now + 12U, &status) == 0);
        CHECK((status == DMP_DUPLICATE || status == DMP_OK) && right.app.accepts == 1);
    }
    report("freshness-grant-duplicate-consume", port, "pass");
    close_session(env);
    return 0;
}

static int test_r6(session *env, port_ctx *port)
{
    reset_measures();
    uint32_t index = 0U;
    dmp_time_ms now = 20000U;
    dmp_reliability_handle handle;
    uint8_t body[256];
    uint8_t result[96];
    captured burst[QUEUE];
    captured status_frames[QUEUE];
    captured repair[QUEUE];
    captured held[QUEUE];
    captured ack[QUEUE];
    int count;
    int nheld;
    int nstatus;
    int nrepair;
    int nack;
    uint32_t drop2[2];
    const dmp_reliability_sender_slot *sender;
    dmp_status status = DMP_OK;
    uint32_t seed = 0x19a6u;
    uint32_t mask_a;
    uint32_t mask_b;
    int i;

    dmp_test_opaque_fill(body, sizeof body, 0x44U);
    dmp_test_opaque_fill(result, sizeof result, 0x91U);
    drop2[0] = 2U;
    drop2[1] = 6U;
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(count == 8);
    nheld = 0;
    CHECK(deliver_mask(burst, count, &right, now, drop2, 2, held, &nheld, 0) == 0);
    CHECK(nheld == 2);
    CHECK(right.app.accepts == 0);
    CHECK(right.app.assembled == 0);
    right.wire.now = now + RADIO_COLLECT_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS) == DMP_OK);
    nstatus = take_queue(&right, status_frames, QUEUE, now + RADIO_COLLECT_MS);
    CHECK(nstatus == 1);
    CHECK(status_frames[0].type == DMP_TYPE_FRAG_STATUS);
    CHECK(right.assemblies[0].status_mask == 0x44U);
    mask_a = right.assemblies[0].status_mask;
    CHECK(deliver_one(&left, &status_frames[0], now + RADIO_COLLECT_MS, &status) == 0);
    CHECK(status == DMP_OK);
    sender = live_frag_sender(&left);
    CHECK(sender != NULL);
    CHECK(sender->active_mask == 0x44U);
    CHECK(pump_sender(&left, now + RADIO_COLLECT_MS, 2) == 0);
    nrepair = take_queue(&left, repair, QUEUE, now + RADIO_COLLECT_MS);
    CHECK(nrepair == 2);
    CHECK(repair[0].index == 2U || repair[1].index == 2U);
    CHECK(repair[0].index == 6U || repair[1].index == 6U);
    CHECK(deliver_mask(repair, nrepair, &right, now + RADIO_COLLECT_MS, NULL, 0, NULL, &g_hold, 0) ==
          0);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == sizeof body);
    CHECK(memcmp(right.app.req_body, body, sizeof body) == 0);
    CHECK(right.app.asm_n == sizeof body);
    /* Stale SEQ with a fresh PN must not replace the accepted mask. */
    {
        dmp_frame_spec spec;
        uint8_t ext[8];
        uint8_t mask[4] = {0x01U, 0x00U, 0x00U, 0x00U};
        uint8_t sealed[MTU];
        uint8_t wrapped[FRAME_CAP];
        size_t ext_n = 0U;
        size_t sealed_n = 0U;
        size_t wrapped_n = 0U;
        size_t value_n = 0U;
        uint8_t value[4];
        value[value_n++] = (uint8_t)sender->own.seq;
        ext[ext_n++] = 5U;
        ext[ext_n++] = (uint8_t)value_n;
        memcpy(ext + ext_n, value, value_n);
        ext_n += value_n;
        value_n = 0U;
        value[value_n++] = 2U;
        ext[ext_n++] = 17U;
        ext[ext_n++] = 1U;
        ext[ext_n++] = 2U;
        (void)value;
        memset(&spec, 0, sizeof spec);
        spec.fields.type = (uint8_t)DMP_TYPE_FRAG_STATUS;
        spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_EXT);
        spec.fields.seq = 0U;
        spec.extensions = span(ext, ext_n);
        spec.payload = span(mask, sizeof mask);
        CHECK(dmp_hs_seal_logical(env->responder, 0U, &spec, sealed, sizeof sealed, &sealed_n) ==
              DMP_HS_OK);
        CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
        {
            captured stale;
            memset(&stale, 0, sizeof stale);
            memcpy(stale.frame, wrapped, wrapped_n);
            stale.len = wrapped_n;
            stale.type = (uint8_t)DMP_TYPE_FRAG_STATUS;
            CHECK(deliver_one(&left, &stale, now + RADIO_COLLECT_MS, &status) == 0);
        }
        sender = live_frag_sender(&left);
        CHECK(sender != NULL);
        CHECK(sender->active_mask != 0x01U);
    }
    /* Replay of the real status is an old PN. */
    CHECK(deliver_one(&left, &status_frames[0], now + RADIO_COLLECT_MS, &status) == 0);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    right.wire.now = now + RADIO_COLLECT_MS + RADIO_RECEIPT_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS + RADIO_RECEIPT_MS) == DMP_OK);
    nack = take_queue(&right, ack, QUEUE, now + RADIO_COLLECT_MS + RADIO_RECEIPT_MS);
    CHECK(nack >= 1);
    CHECK(ack[0].type == DMP_TYPE_ACK);
    CHECK(deliver_one(&left, &ack[0], now + RADIO_COLLECT_MS + RADIO_RECEIPT_MS, &status) == 0);
    CHECK(left.app.unknowns == 0);
    note_peak();
    mask_b = mask_a;
    seed = harness_xorshift32(seed);
    (void)seed;
    (void)mask_b;
    report("r6-2of8", port, "pass");
    close_session(env);

    /* Final slice lost: probe is index N-1, then the rest complete once. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(count == 8);
    nheld = 0;
    {
        uint32_t last = 7U;
        CHECK(deliver_mask(burst, count, &right, now, &last, 1, held, &nheld, 0) == 0);
    }
    CHECK(right.app.accepts == 0);
    left.wire.now = now + RADIO_RESPONSE_MS;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_RESPONSE_MS) == DMP_OK);
    nrepair = take_queue(&left, repair, QUEUE, now + RADIO_RESPONSE_MS);
    CHECK(nrepair == 1);
    CHECK(repair[0].index == 7U);
    CHECK(deliver_one(&right, &repair[0], now + RADIO_RESPONSE_MS, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == sizeof body);
    CHECK(memcmp(right.app.req_body, body, sizeof body) == 0);
    report("r6-final-loss", port, "pass");
    close_session(env);

    /* Entire initial burst lost. The probe admits the transfer. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(count == 8);
    left.wire.now = now + RADIO_RESPONSE_MS;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_RESPONSE_MS) == DMP_OK);
    nrepair = take_queue(&left, repair, QUEUE, now + RADIO_RESPONSE_MS);
    CHECK(nrepair == 1);
    CHECK(repair[0].index == 7U);
    CHECK(deliver_one(&right, &repair[0], now + RADIO_RESPONSE_MS, &status) == 0);
    CHECK(status == DMP_INCOMPLETE);
    CHECK(right.app.accepts == 0);
    report("r6-all-loss", port, "pass");
    close_session(env);

    /* Status lost: the probe produces another status and does not storm. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    nheld = 0;
    CHECK(deliver_mask(burst, count, &right, now, drop2, 2, held, &nheld, 0) == 0);
    right.wire.now = now + RADIO_COLLECT_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS) == DMP_OK);
    nstatus = take_queue(&right, status_frames, QUEUE, now + RADIO_COLLECT_MS);
    CHECK(nstatus == 1);
    CHECK(right.assemblies[0].status_mask == 0x44U);
    {
        captured first_status = status_frames[0];
        uint32_t seq_a = 0U;
        uint32_t seq_b = 0U;
        uint64_t pn_a = 0U;
        uint64_t pn_b = 0U;
        CHECK(frame_seq_pn(&first_status, now + RADIO_COLLECT_MS, &seq_a, &pn_a) == 1);
        /* Drop that status. Probe, then one new status. Further polls do not storm. */
        left.wire.now = now + RADIO_RESPONSE_MS;
        CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_RESPONSE_MS) == DMP_OK);
        nrepair = take_queue(&left, repair, QUEUE, now + RADIO_RESPONSE_MS);
        CHECK(nrepair == 1);
        CHECK(repair[0].index == 7U);
        CHECK(deliver_one(&right, &repair[0], now + RADIO_RESPONSE_MS, &status) == 0);
        right.wire.now = now + RADIO_RESPONSE_MS + RADIO_COLLECT_MS;
        CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_RESPONSE_MS + RADIO_COLLECT_MS) == DMP_OK);
        nstatus = take_queue(&right, status_frames, QUEUE, now + RADIO_RESPONSE_MS + RADIO_COLLECT_MS);
        CHECK(nstatus == 1);
        CHECK(status_frames[0].type == DMP_TYPE_FRAG_STATUS);
        CHECK(right.assemblies[0].status_mask == 0x44U);
        CHECK(frame_seq_pn(&status_frames[0], now + RADIO_RESPONSE_MS + RADIO_COLLECT_MS, &seq_b,
                           &pn_b) == 1);
        CHECK(seq_b != seq_a);
        CHECK(pn_b != pn_a);
        CHECK(status_frames[0].len != first_status.len ||
              memcmp(status_frames[0].frame, first_status.frame, first_status.len) != 0);
    }
    for (i = 0; i < 5; i++) {
        CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_RESPONSE_MS + RADIO_COLLECT_MS + (dmp_time_ms)i) ==
              DMP_OK);
    }
    CHECK(right.wire.n == 0);
    CHECK(right.assemblies[0].status_count <= 3U);
    report("r6-status-loss", port, "pass");
    close_session(env);

    /* Tombstone: an expired identity is not reopened by a late slice. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(deliver_one(&right, &burst[0], now, &status) == 0);
    CHECK(status == DMP_INCOMPLETE);
    right.wire.now = now + RADIO_ASSEMBLY_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_ASSEMBLY_MS) == DMP_OK);
    CHECK(right.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_EXPIRED);
    CHECK(deliver_one(&right, &burst[1], now + RADIO_ASSEMBLY_MS, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == 0);
    CHECK(right.app.assembled == 0);
    report("r6-tombstone", port, "pass");
    close_session(env);

    /* Restart destroys the association. The old slice cannot resume. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(deliver_one(&right, &burst[0], now, &status) == 0);
    CHECK(dmp_hs_cancel(env->initiator, index) == DMP_HS_OK);
    CHECK(dmp_hs_cancel(env->responder, 0U) == DMP_HS_OK);
    CHECK(deliver_one(&right, &burst[1], now, &status) == 0);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.accepts == 0);
    report("r6-restart", port, "pass");
    close_session(env);

    /* Zero return MTU is rejected at admission. No retry-all fallback. */
    {
        dmp_config input;
        dmp_admitted_profile admitted;
        fill_radio_numbers(&input, 0);
        input.return_mtu = 0U;
        CHECK(dmp_config_admit(&input, &admitted) == DMP_UNSUPPORTED);
    }
    report("r6-mtu", port, "pass");
    return 0;
}

static int test_r7(session *env, port_ctx *port)
{
    reset_measures();
    uint32_t index = 0U;
    dmp_time_ms now = 20000U;
    dmp_reliability_handle handle;
    uint8_t body[256];
    captured burst[QUEUE];
    int count;
    int round;
    int expired = 0;
    dmp_status status = DMP_OK;
    uint32_t drop_one = 1U;
    captured held[4];
    int nheld;

    dmp_test_opaque_fill(body, sizeof body, 0x71U);
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(allow_service1_request(&left) == 0);
    CHECK(allow_service1_request(&right) == 0);
    for (round = 0; round < TOMBSTONES; round++) {
        dmp_time_ms at = now + (dmp_time_ms)round * (RADIO_RESULT_MS + 1U);
        CHECK(submit_req(&left, 1U, span(body, sizeof body), at, &handle) ==
              DMP_OK);
        CHECK(pump_sender(&left, at, 1) == 0);
        count = take_queue(&left, burst, QUEUE, at);
        CHECK(count >= 1);
        CHECK(deliver_one(&right, &burst[0], at, &status) == 0);
        CHECK(status == DMP_INCOMPLETE);
        left.wire.now = at + RADIO_RESULT_MS;
        right.wire.now = at + RADIO_RESULT_MS;
        CHECK(dmp_endpoint_poll(&left.endpoint, at + RADIO_RESULT_MS) == DMP_OK);
        CHECK(dmp_endpoint_poll(&right.endpoint, at + RADIO_ASSEMBLY_MS) == DMP_OK);
        CHECK(dmp_endpoint_poll(&right.endpoint, at + RADIO_RESULT_MS) == DMP_OK);
        left.wire.n = 0;
        right.wire.n = 0;
        expired++;
    }
    CHECK(expired == TOMBSTONES);
    {
        dmp_time_ms at = now + (dmp_time_ms)TOMBSTONES * (RADIO_RESULT_MS + 1U);
        CHECK(submit_req(&left, 1U, span(body, sizeof body), at, &handle) ==
              DMP_OK);
        CHECK(pump_sender(&left, at, 1) == 0);
        count = take_queue(&left, burst, QUEUE, at);
        CHECK(deliver_one(&right, &burst[0], at, &status) == 0);
        CHECK(status == DMP_QUOTA_EXHAUSTED);
        CHECK(right.app.accepts == 0);
    }
    report("r7-tombstone-pressure", port, "pass");
    close_session(env);

    CHECK(open_pair(env, port, PROF_RADIO, now, 1, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) ==
          DMP_UNSUPPORTED);
    CHECK(left.wire.n == 0);
    report("r7-acl", port, "pass");
    close_session(env);

    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    nheld = 0;
    CHECK(deliver_mask(burst, count, &right, now, &drop_one, 1, held, &nheld, 0) == 0);
    CHECK(right.app.accepts == 0);
    left.wire.now = now + RADIO_RESULT_MS;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_RESULT_MS) == DMP_OK);
    CHECK(left.app.unknowns == 1);
    CHECK(left.app.local_unsents == 0);
    {
        int before = left.wire.n;
        CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_RESULT_MS + RADIO_RESPONSE_MS) == DMP_OK);
        CHECK(left.wire.n == before);
    }
    report("r7-expiry", port, "pass");
    close_session(env);

    /* Conflicting slice does not dispatch a partial message. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(deliver_one(&right, &burst[0], now, &status) == 0);
    CHECK(right.app.accepts == 0);
    {
        dmp_frame_spec spec;
        uint8_t ext[4];
        uint8_t slice[32];
        uint8_t sealed[MTU];
        uint8_t wrapped[FRAME_CAP];
        size_t sealed_n = 0U;
        size_t wrapped_n = 0U;
        const dmp_reliability_sender_slot *sender = live_frag_sender(&left);
        captured bad;
        CHECK(sender != NULL);
        memset(slice, 0xff, sizeof slice);
        ext[0] = 17U;
        ext[1] = 1U;
        ext[2] = 2U;
        memset(&spec, 0, sizeof spec);
        spec.fields.type = (uint8_t)DMP_TYPE_REQ;
        spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_FRAG | DMP_OPT_EXT);
        spec.fields.seq = sender->own.seq;
        spec.fields.fragment.index = 0U;
        spec.fields.fragment.chunk_size = 32U;
        spec.fields.fragment.total_size = (uint32_t)sizeof body;
        spec.extensions = span(ext, 3U);
        spec.payload = span(slice, sizeof slice);
        CHECK(dmp_hs_seal_logical(env->initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
              DMP_HS_OK);
        CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
        memset(&bad, 0, sizeof bad);
        memcpy(bad.frame, wrapped, wrapped_n);
        bad.len = wrapped_n;
        CHECK(deliver_one(&right, &bad, now, &status) == 0);
        CHECK(status == DMP_OK);
        CHECK(right.app.accepts == 0);
        CHECK(right.app.assembled == 0);
    }
    report("r7-conflict", port, "pass");
    close_session(env);
    return 0;
}

static int test_retry_all(session *env, port_ctx *port)
{
    reset_measures();
    uint32_t index = 0U;
    dmp_time_ms now = 20000U;
    dmp_reliability_handle handle;
    uint8_t body[256];
    captured burst[QUEUE];
    captured repair[QUEUE];
    captured held[8];
    int count;
    int nheld = 0;
    int nrepair;
    uint32_t drop = 3U;
    dmp_status status = DMP_OK;
    dmp_test_opaque_fill(body, sizeof body, 0x81U);
    CHECK(open_pair(env, port, PROF_RETRY, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(count == 8);
    CHECK(deliver_mask(burst, count, &right, now, &drop, 1, held, &nheld, 0) == 0);
    CHECK(right.app.accepts == 0);
    right.wire.now = now + RADIO_COLLECT_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS) == DMP_OK);
    CHECK(right.wire.n == 0);
    CHECK(count_type(burst, count, DMP_TYPE_FRAG_STATUS) == 0);
    left.wire.now = now + RADIO_RESPONSE_MS;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_RESPONSE_MS) == DMP_OK);
    nrepair = take_queue(&left, repair, QUEUE, now + RADIO_RESPONSE_MS);
    CHECK(nrepair == 8);
    CHECK(count_type(repair, nrepair, DMP_TYPE_FRAG_STATUS) == 0);
    CHECK(deliver_mask(repair, nrepair, &right, now + RADIO_RESPONSE_MS, NULL, 0, NULL, &g_hold, 0) ==
          0);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == sizeof body);
    CHECK(memcmp(right.app.req_body, body, sizeof body) == 0);
    report("retry-all-loss", port, "pass");
    close_session(env);

    CHECK(open_pair(env, port, PROF_RETRY, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(deliver_one(&right, &burst[0], now, &status) == 0);
    left.wire.now = now + RADIO_RESULT_MS;
    right.wire.now = now + RADIO_RESULT_MS;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_RESULT_MS) == DMP_OK);
    CHECK(left.app.unknowns == 1);
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_ASSEMBLY_MS) == DMP_OK);
    CHECK(deliver_one(&right, &burst[1], now + RADIO_RESULT_MS, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == 0);
    {
        int before = left.wire.n;
        CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_RESULT_MS + RADIO_RESPONSE_MS) == DMP_OK);
        CHECK(left.wire.n == before);
    }
    report("retry-all-expiry", port, "pass");
    close_session(env);
    return 0;
}

static void print_core_header(const char *label, const uint8_t *core, size_t n)
{
    size_t header;
    size_t i;
    if (n < 2U) {
        return;
    }
    header = core[1];
    if (header > n) {
        header = n;
    }
    (void)printf("%s ", label);
    for (i = 0U; i < header; i++) {
        (void)printf("%02x", core[i]);
    }
    (void)printf("\n");
}

static int parse_core(const uint8_t *core, size_t n, dmp_frame_view *view)
{
    dmp_core_limits limits;
    dmp_parse_result parsed;
    memset(view, 0, sizeof *view);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    parsed = dmp_core_parse(span(core, n), &limits, view);
    return parsed.status == DMP_OK;
}

static int context_epoch_of(const dmp_frame_view *view, uint64_t *epoch)
{
    size_t cursor = 0U;
    while (cursor < view->extensions.size) {
        dmp_extension_view ext;
        dmp_status status = dmp_extension_next(view->extensions, &cursor, &ext);
        unsigned i;
        if (status == DMP_INCOMPLETE) {
            break;
        }
        if (status != DMP_OK || (ext.tag >> 2) != 2U || ext.value.size < 9U) {
            if (status != DMP_OK) {
                return 0;
            }
            continue;
        }
        *epoch = 0U;
        for (i = 0U; i < 8U; i++) {
            *epoch |= (uint64_t)ext.value.data[1U + i] << (8U * i);
        }
        return 1;
    }
    return 0;
}

static int arm_radio_relay(dmp_mesh_relay *relay, const dmp_admitted_profile *profile,
                           dmp_mesh_route *routes, dmp_mesh_cache_slot *cache, dmp_mesh_airtime *air)
{
    memset(relay, 0, sizeof *relay);
    memset(cache, 0, 16U * sizeof *cache);
    memset(air, 0, 4U * sizeof *air);
    routes[0].destination = ID_RESP;
    routes[0].next_hop = ID_RESP;
    routes[1].destination = ID_INIT;
    routes[1].next_hop = ID_INIT;
    relay->profile = profile;
    relay->self_node = 30U;
    relay->pn_filter = DMP_MESH_PN_REJECT_GE_2POW24;
    relay->cooldown_ms = 50U;
    relay->expiry_ms = 20000U;
    relay->max_forwards_per_key = 12U;
    relay->frame_tx_ms = 1U;
    relay->per_origin_airtime_ms = 10000U;
    relay->global_airtime_ms = 20000U;
    relay->return_period_ms = 64U;
    relay->return_width_ms = 42U;
    relay->routes = routes;
    relay->route_count = 2U;
    relay->cache = cache;
    relay->cache_count = 16U;
    relay->airtime = air;
    relay->airtime_count = 4U;
    return dmp_mesh_relay_init(relay) == DMP_OK ? 0 : 1;
}

static dmp_status forward_core(dmp_mesh_relay *relay, const uint8_t *core, size_t core_n,
                               dmp_time_ms now, uint8_t *out, size_t cap, dmp_mesh_forward_out *fwd)
{
    dmp_frame_view view;
    dmp_mesh_forward_in in;
    dmp_core_limits limits;
    if (!parse_core(core, core_n, &view)) {
        return DMP_MALFORMED;
    }
    memset(&in, 0, sizeof in);
    limits.max_frame_bytes = 256U;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    in.now = now;
    in.tx_complete_at = now + 64U;
    in.frame = span(core, core_n);
    in.limits = limits;
    if ((view.fields.options & DMP_OPT_ROUTE) != 0U && view.fields.route.destination == ID_INIT) {
        in.direction = DMP_MESH_RETURN;
        in.return_slot = 1U;
        in.source_start_ms = now;
    } else {
        in.direction = DMP_MESH_FORWARD;
    }
    return dmp_mesh_relay_forward(relay, &in, (dmp_buffer){out, cap}, fwd);
}

static int hop_deliver(dmp_mesh_relay *relay, const captured *frame, node *to, dmp_time_ms now,
                       dmp_status *rx_status)
{
    uint8_t core[MTU];
    uint8_t forwarded[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t core_n = 0U;
    size_t wrapped_n = 0U;
    dmp_mesh_forward_out fwd;
    dmp_status relay_status;
    captured delivered;
    if (unwrap_core(frame->frame, frame->len, core, sizeof core, &core_n, now) != 1) {
        return 1;
    }
    memset(&fwd, 0, sizeof fwd);
    relay_status = forward_core(relay, core, core_n, now, forwarded, sizeof forwarded, &fwd);
    if (relay_status != DMP_OK) {
        (void)fprintf(stderr, "relay forward status %d core %u at %u\n", (int)relay_status,
                      (unsigned)core_n, (unsigned)now);
        if (rx_status != NULL) {
            *rx_status = relay_status;
        }
        return 1;
    }
    if (wrap_core(forwarded, fwd.written, wrapped, sizeof wrapped, &wrapped_n) != 1) {
        return 1;
    }
    memset(&delivered, 0, sizeof delivered);
    if (wrapped_n > sizeof delivered.frame) {
        return 1;
    }
    memcpy(delivered.frame, wrapped, wrapped_n);
    delivered.len = wrapped_n;
    return deliver_one(to, &delivered, now, rx_status);
}

static int vector_header_matches(void)
{
    static const uint8_t published[] = {
        0x48, 0x18, 0xc5, 0x0d, 0x31, 0x14, 0x0a, 0x01, 0x07, 0x14, 0x05, 0x01, 0x05,
        0x0b, 0x09, 0x01, 0xb8, 0x49, 0x42, 0xd7, 0x28, 0xfe, 0x50, 0x30};
    static const uint8_t ext[] = {0x05, 0x01, 0x05, 0x0b, 0x09, 0x01, 0xb8, 0x49,
                                  0x42, 0xd7, 0x28, 0xfe, 0x50, 0x30};
    uint8_t payload[4] = {0x44, 0x00, 0x00, 0x00};
    uint8_t tag[16];
    uint8_t header[64];
    dmp_frame_spec spec;
    dmp_core_limits limits;
    size_t written = 0U;
    memset(tag, 0, sizeof tag);
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_FRAG_STATUS;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ROUTE | DMP_OPT_SECURITY | DMP_OPT_EXT);
    spec.fields.seq = 13U;
    spec.fields.route.ttl = 3U;
    spec.fields.route.mode = 1U;
    spec.fields.route.source = 20U;
    spec.fields.route.destination = 10U;
    spec.fields.security.cipher = 1U;
    spec.fields.security.receive_cid = 7U;
    spec.fields.security.pn = 20U;
    spec.extensions = span(ext, sizeof ext);
    spec.payload = span(payload, sizeof payload);
    spec.trailer = span(tag, sizeof tag);
    limits.max_frame_bytes = 256U;
    limits.max_message_bytes = 1024U;
    limits.max_fragments = 32U;
    if (dmp_core_encode_header(&spec, &limits, (dmp_buffer){header, sizeof header}, &written) !=
        DMP_OK) {
        return 1;
    }
    return written == sizeof published && memcmp(header, published, sizeof published) == 0 ? 0 : 1;
}

static int test_relay_sample(session *env, port_ctx *port)
{
    reset_measures();
    uint32_t index = 0U;
    dmp_time_ms now = 19968U;
    dmp_config input;
    dmp_admitted_profile admitted;
    dmp_mesh_route routes[2];
    dmp_mesh_cache_slot cache[16];
    dmp_mesh_airtime air[4];
    dmp_mesh_relay relay;
    dmp_mesh_forward_out fwd;
    uint8_t forwarded[MTU];
    uint8_t core[MTU];
    uint8_t again[MTU];
    size_t core_n = 0U;
    dmp_status relay_status;
    dmp_status rx_status = DMP_OK;
    dmp_frame_view view;
    uint8_t req[1];
    uint8_t small[16];
    uint8_t body[256];
    uint8_t result[16];
    dmp_reliability_handle handle;
    int round;
    int count;
    int i;
    int saw_ack = 0;
    captured burst[8];
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    uint64_t wire_epoch = 0U;
    dmp_time_ms later;
    uint8_t telem[2] = {0x11U, 0x22U};

    CHECK(vector_header_matches() == 0);
    CHECK(open_pair(env, port, PROF_DIRECT, now, 0, &index) == 0);
    memset(small, 0x21, sizeof small);
    CHECK(submit_req(&left, 2U, span(small, sizeof small), now, &handle) ==
          DMP_OK);
    CHECK(pump_sender(&left, now, 1) == 0);
    CHECK(unwrap_core(left.wire.q[0].frame, left.wire.q[0].len, core, sizeof core, &core_n, now) == 1);
    CHECK(parse_core(core, core_n, &view) == 1);
    CHECK((view.fields.options & DMP_OPT_ROUTE) == 0U);
    CHECK(context_epoch_of(&view, &wire_epoch) == 0);
    close_session(env);

    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    fill_radio_numbers(&input, 0);
    CHECK(dmp_config_admit(&input, &admitted) == DMP_OK);
    CHECK(admitted.origin_route == 1U);
    CHECK(admitted.origin_ttl == 2U);
    CHECK(arm_radio_relay(&relay, &admitted, routes, cache, air) == 0);
    CHECK(dmp_hs_epochs(env->initiator, index, &epoch_i, &epoch_r) == 1);
    left.endpoint.profile.origin_ttl = 1U;
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now) == DMP_OK);
    CHECK(pump_sender(&left, now, 1) == 0);
    CHECK(unwrap_core(left.wire.q[0].frame, left.wire.q[0].len, core, sizeof core, &core_n, now) == 1);
    left.wire.n = 0;
    CHECK(parse_core(core, core_n, &view) == 1);
    CHECK(view.fields.route.mode == 1U);
    CHECK(view.fields.route.ttl == 1U);
    CHECK(view.fields.route.source == ID_INIT);
    CHECK(view.fields.route.destination == ID_RESP);
    relay_status = forward_core(&relay, core, core_n, now, forwarded, sizeof forwarded, &fwd);
    CHECK(relay_status == DMP_OK);
    CHECK(parse_core(forwarded, fwd.written, &view) == 1);
    CHECK(view.fields.route.ttl == 0U);
    memcpy(again, forwarded, fwd.written);
    relay_status = forward_core(&relay, again, fwd.written, now, forwarded, sizeof forwarded, &fwd);
    CHECK(relay_status == DMP_LIMIT_EXHAUSTED);
    CHECK(dmp_mesh_relay_init(&relay) == DMP_OK);
    left.endpoint.profile.origin_ttl = 15U;
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now) == DMP_OK);
    CHECK(pump_sender(&left, now, 1) == 0);
    CHECK(unwrap_core(left.wire.q[0].frame, left.wire.q[0].len, core, sizeof core, &core_n, now) == 1);
    left.wire.n = 0;
    CHECK(parse_core(core, core_n, &view) == 1);
    CHECK(view.fields.route.ttl == 15U);
    relay_status = forward_core(&relay, core, core_n, now, forwarded, sizeof forwarded, &fwd);
    CHECK(relay_status == DMP_OK);
    CHECK(parse_core(forwarded, fwd.written, &view) == 1);
    CHECK(view.fields.route.ttl == 14U);
    left.endpoint.profile.origin_ttl = 2U;
    CHECK(dmp_mesh_relay_init(&relay) == DMP_OK);

    memset(small, 0x5a, sizeof small);
    CHECK(submit_req(&left, 2U, span(small, sizeof small), now, &handle) ==
          DMP_OK);
    /* Exclude the service-0 freshness-grant RESULT from the application count. */
    left.app.results = 0;
    CHECK(pump_sender(&left, now, 1) == 0);
    count = take_queue(&left, burst, 8, now);
    CHECK(count == 1);
    CHECK(burst[0].index == 0xffffffffU);
    CHECK(unwrap_core(burst[0].frame, burst[0].len, core, sizeof core, &core_n, now) == 1);
    CHECK(parse_core(core, core_n, &view) == 1);
    CHECK(view.fields.type == DMP_TYPE_REQ);
    CHECK(view.fields.route.mode == 1U);
    CHECK(view.fields.route.ttl == 2U);
    CHECK(view.fields.route.source == ID_INIT);
    CHECK(view.fields.route.destination == ID_RESP);
    CHECK(context_epoch_of(&view, &wire_epoch) == 1);
    CHECK(wire_epoch == epoch_i);
    print_core_header("route-req-header", core, core_n);
    relay_status = forward_core(&relay, core, core_n, now, forwarded, sizeof forwarded, &fwd);
    CHECK(relay_status == DMP_OK);
    CHECK(cache[0].occupied == 1U);
    relay_status = forward_core(&relay, core, core_n, now, again, sizeof again, &fwd);
    CHECK(relay_status == DMP_BUSY);
    CHECK(hop_deliver(&relay, &burst[0], &right, now + 128U, &rx_status) == 0);
    CHECK(rx_status == DMP_OK);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == sizeof small);
    CHECK(memcmp(right.app.req_body, small, sizeof small) == 0);
    later = now + 128U + RADIO_RECEIPT_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, later) == DMP_OK);
    count = take_queue(&right, burst, 8, later);
    CHECK(count >= 1);
    for (i = 0; i < count; i++) {
        CHECK(unwrap_core(burst[i].frame, burst[i].len, core, sizeof core, &core_n, later) == 1);
        CHECK(parse_core(core, core_n, &view) == 1);
        CHECK(view.fields.route.mode == 1U);
        CHECK(view.fields.route.ttl == 2U);
        CHECK(view.fields.route.source == ID_RESP);
        CHECK(view.fields.route.destination == ID_INIT);
        CHECK(context_epoch_of(&view, &wire_epoch) == 1);
        CHECK(wire_epoch == epoch_r);
        if (view.fields.type == DMP_TYPE_ACK) {
            saw_ack = 1;
        }
        CHECK(hop_deliver(&relay, &burst[i], &left, later, &rx_status) == 0);
        CHECK(rx_status == DMP_OK);
    }
    CHECK(saw_ack == 1);
    dmp_test_opaque_fill(result, sizeof result, 0x91U);
    CHECK(dmp_endpoint_complete(&right.endpoint, right.app.pending, false, 0U,
                                span(result, sizeof result), later) == DMP_OK);
    CHECK(pump_sender(&right, later, 1) == 0);
    count = take_queue(&right, burst, 8, later);
    CHECK(count == 1);
    CHECK(burst[0].type == DMP_TYPE_RSP);
    CHECK(hop_deliver(&relay, &burst[0], &left, later + 64U, &rx_status) == 0);
    CHECK(rx_status == DMP_OK);
    CHECK(left.app.results == 1);
    CHECK(left.app.result_n == sizeof result);
    CHECK(memcmp(left.app.result_body, result, sizeof result) == 0);
    CHECK(dmp_endpoint_poll(&left.endpoint, later + 64U + RADIO_RECEIPT_MS) == DMP_OK);
    count = take_queue(&left, burst, 8, later + 64U + RADIO_RECEIPT_MS);
    for (i = 0; i < count; i++) {
        CHECK(hop_deliver(&relay, &burst[i], &right, later + 64U + RADIO_RECEIPT_MS, &rx_status) == 0);
    }
    report("s10-06-relay", port, "pass");
    close_session(env);

    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    fill_radio_numbers(&input, 0);
    CHECK(dmp_config_admit(&input, &admitted) == DMP_OK);
    CHECK(arm_radio_relay(&relay, &admitted, routes, cache, air) == 0);
    CHECK(dmp_hs_epochs(env->initiator, index, &epoch_i, &epoch_r) == 1);
    memset(body, 0x44, sizeof body);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) ==
          DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, 8, now);
    CHECK(count == 8);
    for (i = 0; i < count; i++) {
        if (burst[i].index == 1U) {
            continue;
        }
        CHECK(hop_deliver(&relay, &burst[i], &right, now, &rx_status) == 0);
        CHECK(rx_status == DMP_INCOMPLETE || rx_status == DMP_OK);
    }
    CHECK(right.app.accepts == 0);
    later = now + RADIO_COLLECT_MS;
    right.wire.now = later;
    CHECK(dmp_endpoint_poll(&right.endpoint, later) == DMP_OK);
    count = take_queue(&right, burst, 8, later);
    CHECK(count == 1);
    CHECK(burst[0].type == DMP_TYPE_FRAG_STATUS);
    CHECK(unwrap_core(burst[0].frame, burst[0].len, core, sizeof core, &core_n, later) == 1);
    CHECK(parse_core(core, core_n, &view) == 1);
    CHECK(view.fields.route.mode == 1U);
    CHECK(view.fields.route.ttl == 2U);
    CHECK(view.fields.route.source == ID_RESP);
    CHECK(view.fields.route.destination == ID_INIT);
    CHECK(context_epoch_of(&view, &wire_epoch) == 1);
    CHECK(wire_epoch == epoch_r);
    print_core_header("route-status-header", core, core_n);
    CHECK(hop_deliver(&relay, &burst[0], &left, later, &rx_status) == 0);
    CHECK(rx_status == DMP_OK);
    CHECK(pump_sender(&left, later, 1) == 0);
    count = take_queue(&left, burst, 8, later);
    CHECK(count == 1);
    CHECK(burst[0].index == 1U);
    CHECK(hop_deliver(&relay, &burst[0], &right, later, &rx_status) == 0);
    CHECK(rx_status == DMP_OK);
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == sizeof body);
    CHECK(memcmp(right.app.req_body, body, sizeof body) == 0);
    report("routed-repair", port, "pass");
    close_session(env);

    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    sample1_read_req(req);
    CHECK(submit_req(&right, 1U, span(req, 1U), now, &handle) == DMP_OK);
    for (round = 0; round < 8; round++) {
        captured from_right[QUEUE];
        captured from_left[QUEUE];
        int nr;
        int nl;
        CHECK(service_sample(&left, now) == 0);
        CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
        CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
        nr = take_queue(&right, from_right, QUEUE, now);
        nl = take_queue(&left, from_left, QUEUE, now);
        CHECK(nr >= 0 && nl >= 0);
        if (round == 0 && nr > 0) {
            uint8_t sample_core[MTU];
            size_t sample_n = 0U;
            dmp_frame_view sample_view;
            CHECK(unwrap_core(from_right[0].frame, from_right[0].len, sample_core, sizeof sample_core,
                              &sample_n, now) == 1);
            CHECK(parse_core(sample_core, sample_n, &sample_view) == 1);
            CHECK((sample_view.fields.options & DMP_OPT_ROUTE) != 0U);
            CHECK(sample_view.fields.route.ttl == 2U);
            CHECK(sample_view.fields.route.mode == 1U);
            print_core_header("route-req-header", sample_core, sample_n);
        }
        CHECK(deliver_mask(from_right, nr, &left, now, NULL, 0, NULL, &g_hold, 0) == 0);
        CHECK(deliver_mask(from_left, nl, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
        CHECK(service_sample(&left, now) == 0);
    }
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(right.app.result_n == SAMPLE1_READ_BYTES);
    {
        uint8_t expect[SAMPLE1_READ_BYTES];
        (void)sample1_read_rsp(expect, 1U, 2U, 300U);
        CHECK(memcmp(right.app.result_body, expect, SAMPLE1_READ_BYTES) == 0);
    }
    note_peak();
    report("sample1", port, "pass");
    close_session(env);
    return 0;
}

static int test_feedback(session *env, port_ctx *port)
{
    reset_measures();
    uint32_t index = 0U;
    dmp_time_ms now = 20000U;
    dmp_reliability_handle handle;
    uint8_t small[16];
    uint8_t body[256];
    captured burst[8];
    int count;
    dmp_status status = DMP_OK;
    const dmp_reliability_sender_slot *sender;
    dmp_frame_spec spec;
    uint8_t ext[8];
    uint8_t mask[4] = {0x01U, 0x00U, 0x00U, 0x00U};
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    captured forged;
    uint32_t seq;
    int before;

    memset(small, 0x22, sizeof small);
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(small, sizeof small), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 1) == 0);
    count = take_queue(&left, burst, 8, now);
    CHECK(count == 1);
    CHECK(burst[0].index == 0xffffffffU);
    sender = live_frag_sender(&left);
    CHECK(sender == NULL);
    seq = left.senders[0].live != 0U ? left.senders[0].own.seq : 0U;
    ext[0] = 5U;
    ext[1] = 1U;
    ext[2] = (uint8_t)seq;
    ext[3] = 17U;
    ext[4] = 1U;
    ext[5] = 2U;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_FRAG_STATUS;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_EXT);
    spec.fields.seq = 3U;
    spec.extensions = span(ext, 6U);
    spec.payload = span(mask, sizeof mask);
    CHECK(dmp_hs_seal_logical(env->responder, 0U, &spec, sealed, sizeof sealed, &sealed_n) == DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    memset(&forged, 0, sizeof forged);
    memcpy(forged.frame, wrapped, wrapped_n);
    forged.len = wrapped_n;
    before = left.wire.n;
    CHECK(deliver_one(&left, &forged, now, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == before);
    CHECK(live_frag_sender(&left) == NULL);
    report("feedback-ineligible", port, "pass");
    close_session(env);

    dmp_test_opaque_fill(body, sizeof body, 0x44U);
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, 8, now);
    CHECK(deliver_mask(burst, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 1);
    right.wire.now = now + RADIO_RECEIPT_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_RECEIPT_MS) == DMP_OK);
    {
        captured ack[4];
        int nack = take_queue(&right, ack, 4, now + RADIO_RECEIPT_MS);
        CHECK(nack >= 1);
        CHECK(deliver_one(&left, &ack[0], now + RADIO_RECEIPT_MS, &status) == 0);
    }
    sender = live_frag_sender(&left);
    before = left.wire.n;
    ext[2] = sender == NULL ? 0U : (uint8_t)sender->own.seq;
    if (sender == NULL) {
        size_t s;
        for (s = 0U; s < SENDERS; s++) {
            if (left.senders[s].payload_len == sizeof body) {
                ext[2] = (uint8_t)left.senders[s].own.seq;
                break;
            }
        }
    }
    spec.fields.seq = 4U;
    CHECK(dmp_hs_seal_logical(env->responder, 0U, &spec, sealed, sizeof sealed, &sealed_n) == DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    memcpy(forged.frame, wrapped, wrapped_n);
    forged.len = wrapped_n;
    CHECK(deliver_one(&left, &forged, now + RADIO_RECEIPT_MS, &status) == 0);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_RECEIPT_MS) == DMP_OK);
    CHECK(left.wire.n == before);
    report("feedback-terminal", port, "pass");
    close_session(env);

    /* Same seed drives the same drops, repairs, mask and wire bytes. */
    {
        uint32_t seed = 0x0d19u;
        captured burst_a[8];
        captured burst_b[8];
        captured repair_a[8];
        captured repair_b[8];
        captured status_a[2];
        captured status_b[2];
        uint32_t drop_a[3];
        uint32_t drop_b[3];
        int count_a;
        int count_b;
        int nrepair_a;
        int nrepair_b;
        int nstatus_a;
        int nstatus_b;
        int held_n;
        int di;
        captured held_frames[8];
        uint32_t state;
        state = seed;
        for (di = 0; di < 3; di++) {
            uint32_t pick;
            int unique = 0;
            while (!unique) {
                int seen = 0;
                int s;
                state = harness_xorshift32(state);
                pick = state % 8U;
                for (s = 0; s < di; s++) {
                    if (drop_a[s] == pick) {
                        seen = 1;
                    }
                }
                unique = !seen;
            }
            drop_a[di] = pick;
        }
        state = seed;
        for (di = 0; di < 3; di++) {
            uint32_t pick;
            int unique = 0;
            while (!unique) {
                int seen = 0;
                int s;
                state = harness_xorshift32(state);
                pick = state % 8U;
                for (s = 0; s < di; s++) {
                    if (drop_b[s] == pick) {
                        seen = 1;
                    }
                }
                unique = !seen;
            }
            drop_b[di] = pick;
        }
        CHECK(drop_a[0] == drop_b[0] && drop_a[1] == drop_b[1] && drop_a[2] == drop_b[2]);
        CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
        CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) ==
              DMP_OK);
        CHECK(pump_sender(&left, now, 8) == 0);
        count_a = take_queue(&left, burst_a, 8, now);
        CHECK(count_a == 8);
        held_n = 0;
        CHECK(deliver_mask(burst_a, count_a, &right, now, drop_a, 3, held_frames, &held_n, 0) == 0);
        right.wire.now = now + RADIO_COLLECT_MS;
        CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS) == DMP_OK);
        nstatus_a = take_queue(&right, status_a, 2, now + RADIO_COLLECT_MS);
        CHECK(nstatus_a == 1);
        CHECK(deliver_one(&left, &status_a[0], now + RADIO_COLLECT_MS, &status) == 0);
        CHECK(pump_sender(&left, now + RADIO_COLLECT_MS, 1) == 0);
        nrepair_a = take_queue(&left, repair_a, 8, now + RADIO_COLLECT_MS);
        close_session(env);
        CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
        CHECK(submit_req(&left, 2U, span(body, sizeof body), now, &handle) ==
              DMP_OK);
        CHECK(pump_sender(&left, now, 8) == 0);
        count_b = take_queue(&left, burst_b, 8, now);
        CHECK(count_b == 8);
        held_n = 0;
        CHECK(deliver_mask(burst_b, count_b, &right, now, drop_b, 3, held_frames, &held_n, 0) == 0);
        right.wire.now = now + RADIO_COLLECT_MS;
        CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS) == DMP_OK);
        nstatus_b = take_queue(&right, status_b, 2, now + RADIO_COLLECT_MS);
        CHECK(nstatus_b == 1);
        CHECK(deliver_one(&left, &status_b[0], now + RADIO_COLLECT_MS, &status) == 0);
        CHECK(pump_sender(&left, now + RADIO_COLLECT_MS, 1) == 0);
        nrepair_b = take_queue(&left, repair_b, 8, now + RADIO_COLLECT_MS);
        CHECK(nrepair_a == nrepair_b);
        CHECK(nrepair_a >= 1);
        for (di = 0; di < count_a; di++) {
            CHECK(burst_a[di].len == burst_b[di].len);
            CHECK(memcmp(burst_a[di].frame, burst_b[di].frame, burst_a[di].len) == 0);
            CHECK(burst_a[di].index == burst_b[di].index);
        }
        CHECK(status_a[0].len == status_b[0].len);
        CHECK(memcmp(status_a[0].frame, status_b[0].frame, status_a[0].len) == 0);
        for (di = 0; di < nrepair_a; di++) {
            CHECK(repair_a[di].index == repair_b[di].index);
            CHECK(repair_a[di].len == repair_b[di].len);
            CHECK(memcmp(repair_a[di].frame, repair_b[di].frame, repair_a[di].len) == 0);
        }
        report("r7-determinism", port, "pass");
        close_session(env);
    }
    return 0;
}

static int seal_status(session *env, int from_responder, uint32_t attempt, uint32_t seq,
                       uint32_t reply_seq, uint32_t service, const uint8_t *mask, size_t mask_n,
                       captured *out)
{
    dmp_frame_spec spec;
    dmp_hs *hs = from_responder ? env->responder : env->initiator;
    uint8_t ext[8];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;

    ext[0] = 5U;
    ext[1] = 1U;
    ext[2] = (uint8_t)reply_seq;
    ext[3] = 17U;
    ext[4] = 1U;
    ext[5] = (uint8_t)service;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_FRAG_STATUS;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_EXT);
    spec.fields.seq = seq;
    spec.extensions = span(ext, 6U);
    spec.payload = span(mask, mask_n);
    if (dmp_hs_seal_logical(hs, attempt, &spec, sealed, sizeof sealed, &sealed_n) != DMP_HS_OK) {
        return 1;
    }
    if (wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) != 1) {
        return 1;
    }
    memset(out, 0, sizeof *out);
    memcpy(out->frame, wrapped, wrapped_n);
    out->len = wrapped_n;
    out->type = (uint8_t)DMP_TYPE_FRAG_STATUS;
    return 0;
}

static int test_gaps(session *env, port_ctx *port)
{
    uint32_t index = 0U;
    dmp_time_ms now = 20000U;
    dmp_reliability_handle handle;
    dmp_status status = DMP_OK;
    uint8_t body[512];
    uint8_t result[512];
    captured burst[QUEUE];
    captured extra[8];
    int count;
    int i;
    size_t live;

    reset_measures();
    dmp_test_opaque_fill(body, 256U, 0x61U);

    /* Seal/encode failure after admission frees the sender and sends nothing. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(live_frag_sender(&left) != NULL);
    CHECK(dmp_hs_cancel(env->initiator, index) == DMP_HS_OK);
    status = dmp_endpoint_poll(&left.endpoint, now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(left.wire.n == 0);
    CHECK(live_frag_sender(&left) == NULL);
    live = 0U;
    for (i = 0; i < SENDERS; i++) {
        live += left.senders[i].live != 0U ? 1U : 0U;
        CHECK(left.senders[i].burst_inflight == 0U);
    }
    CHECK(live == 0U);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 1U) == DMP_OK);
    CHECK(left.wire.n == 0);
    report("seal-after-admit", port, "pass");
    close_session(env);

    /* Deadline before any transmission is a local unsent outcome. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 16U), now, &handle) == DMP_OK);
    CHECK(handle.slot < SENDERS);
    {
        dmp_message_key key = left.senders[handle.slot].own;
        CHECK(dmp_endpoint_poll(&left.endpoint, now + 64U) == DMP_OK);
        CHECK(left.wire.n == 0);
        CHECK(left.app.unknowns == 0);
        CHECK(left.app.local_unsents == 1);
        CHECK(left.app.unsent_n == 0U);
        CHECK(same_key(left.app.unsent_key, key));
    }
    for (i = 0; i < SENDERS; i++) {
        CHECK(left.senders[i].live == 0U);
    }
    report("deadline-before-tx", port, "pass");
    close_session(env);

    /* Queue deadline while the attempt is alive but not active: nothing could
     * have been sent, so the outcome is local-unsent rather than unknown. */
    CHECK(open_inactive(env, port, PROF_RADIO, now, &index) == 0);
    CHECK(allow_service1_request(&left) == 0);
    CHECK(submit_req(&left, 1U, span(body, 16U), now, &handle) == DMP_OK);
    CHECK(handle.slot < SENDERS);
    {
        dmp_message_key key = left.senders[handle.slot].own;
        CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
        CHECK(left.wire.n == 0);
        CHECK(left.app.local_unsents == 0);
        CHECK(left.app.unknowns == 0);
        CHECK(left.senders[handle.slot].live == 1U);
        CHECK(dmp_endpoint_poll(&left.endpoint, now + 64U) == DMP_OK);
        CHECK(left.wire.n == 0);
        CHECK(left.app.unknowns == 0);
        CHECK(left.app.local_unsents == 1);
        CHECK(left.app.unsent_n == 0U);
        CHECK(same_key(left.app.unsent_key, key));
    }
    for (i = 0; i < SENDERS; i++) {
        CHECK(left.senders[i].live == 0U);
    }
    report("deadline-before-activation", port, "pass");
    close_session(env);

    /* Duplicate of an accepted index after the deadline, before poll, does not arm. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(count == 8);
    CHECK(deliver_one(&right, &burst[0], now, &status) == 0);
    CHECK(status == DMP_INCOMPLETE);
    CHECK(right.assemblies[0].collection_armed == 1U);
    CHECK(right.assemblies[0].collection_due == now + RADIO_COLLECT_MS);
    CHECK(deliver_one(&right, &burst[1], now + 10U, &status) == 0);
    CHECK(right.assemblies[0].collection_due == now + RADIO_COLLECT_MS);
    right.wire.now = now + RADIO_COLLECT_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS) == DMP_OK);
    CHECK(right.assemblies[0].collection_armed == 0U);
    {
        int before = right.wire.n;
        CHECK(before >= 1);
        right.wire.n = 0;
    }
    {
        dmp_frame_spec spec;
        uint8_t ext[4] = {17U, 1U, 2U, 0U};
        uint8_t sealed[MTU];
        uint8_t wrapped[FRAME_CAP];
        size_t sealed_n = 0U;
        size_t wrapped_n = 0U;
        const dmp_reliability_sender_slot *sender = live_frag_sender(&left);
        captured again;
        CHECK(sender != NULL);
        memset(&spec, 0, sizeof spec);
        spec.fields.type = (uint8_t)DMP_TYPE_REQ;
        spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_FRAG | DMP_OPT_EXT);
        spec.fields.seq = sender->own.seq;
        spec.fields.fragment.index = 0U;
        spec.fields.fragment.chunk_size = 32U;
        spec.fields.fragment.total_size = 256U;
        spec.extensions = span(ext, 3U);
        spec.payload = span(body, 32U);
        CHECK(dmp_hs_seal_logical(env->initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
              DMP_HS_OK);
        CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
        memset(&again, 0, sizeof again);
        memcpy(again.frame, wrapped, wrapped_n);
        again.len = wrapped_n;
        CHECK(deliver_one(&right, &again, now + RADIO_ASSEMBLY_MS, &status) == 0);
    }
    CHECK(status == DMP_OK);
    CHECK(right.assemblies[0].live == 1U);
    CHECK(right.assemblies[0].collection_armed == 0U);
    CHECK(right.app.accepts == 0);
    report("duplicate-after-deadline", port, "pass");
    close_session(env);

    /* Out-of-order slices complete once. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(count == 8);
    {
        static const int order[8] = {7, 0, 3, 1, 2, 4, 5, 6};
        for (i = 0; i < 8; i++) {
            CHECK(deliver_one(&right, &burst[order[i]], now, &status) == 0);
        }
    }
    CHECK(right.app.accepts == 1);
    CHECK(right.app.req_n == 256U);
    CHECK(memcmp(right.app.req_body, body, 256U) == 0);
    report("out-of-order", port, "pass");
    close_session(env);

    /* Lost repair slice, then a later status still names it. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    {
        uint32_t drop = 2U;
        int held_n = 0;
        captured held[4];
        captured status_frame[2];
        captured repair[4];
        int nstatus;
        int nrepair;
        CHECK(deliver_mask(burst, count, &right, now, &drop, 1, held, &held_n, 0) == 0);
        right.wire.now = now + RADIO_COLLECT_MS;
        CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS) == DMP_OK);
        nstatus = take_queue(&right, status_frame, 2, now + RADIO_COLLECT_MS);
        CHECK(nstatus == 1);
        CHECK(right.assemblies[0].status_mask == 0x04U);
        CHECK(deliver_one(&left, &status_frame[0], now + RADIO_COLLECT_MS, &status) == 0);
        CHECK(pump_sender(&left, now + RADIO_COLLECT_MS, 1) == 0);
        nrepair = take_queue(&left, repair, 4, now + RADIO_COLLECT_MS);
        CHECK(nrepair == 1);
        CHECK(repair[0].index == 2U);
        held[0] = repair[0];
        left.wire.now = now + RADIO_COLLECT_MS + RADIO_RESPONSE_MS;
        CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_COLLECT_MS + RADIO_RESPONSE_MS) == DMP_OK);
        nrepair = take_queue(&left, repair, 4, now + RADIO_COLLECT_MS + RADIO_RESPONSE_MS);
        CHECK(nrepair == 1);
        CHECK(deliver_one(&right, &repair[0], now + RADIO_COLLECT_MS + RADIO_RESPONSE_MS, &status) ==
              0);
        right.wire.now = now + RADIO_COLLECT_MS + RADIO_RESPONSE_MS + RADIO_COLLECT_MS;
        CHECK(dmp_endpoint_poll(&right.endpoint,
                               now + RADIO_COLLECT_MS + RADIO_RESPONSE_MS + RADIO_COLLECT_MS) ==
              DMP_OK);
        nstatus = take_queue(&right, status_frame, 2,
                             now + RADIO_COLLECT_MS + RADIO_RESPONSE_MS + RADIO_COLLECT_MS);
        CHECK(nstatus == 1);
        CHECK((right.assemblies[0].status_mask & 0x04U) != 0U);
        CHECK(right.app.accepts == 0);
        CHECK(deliver_one(&right, &held[0],
                          now + RADIO_COLLECT_MS + RADIO_RESPONSE_MS + RADIO_COLLECT_MS, &status) ==
              0);
        CHECK(right.app.accepts == 1);
        CHECK(memcmp(right.app.req_body, body, 256U) == 0);
    }
    report("lost-repair", port, "pass");
    close_session(env);

    /* Lost final ACK: the probe draws another receipt and does not re-execute. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    g_hold = 0;
    CHECK(deliver_mask(burst, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 1);
    right.wire.now = now + RADIO_RECEIPT_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_RECEIPT_MS) == DMP_OK);
    {
        captured ack[4];
        captured probe[4];
        int nack = take_queue(&right, ack, 4, now + RADIO_RECEIPT_MS);
        int nprobe;
        CHECK(nack >= 1);
        CHECK(ack[0].type == DMP_TYPE_ACK);
        left.wire.now = now + RADIO_RESPONSE_MS;
        CHECK(dmp_endpoint_poll(&left.endpoint, now + RADIO_RESPONSE_MS) == DMP_OK);
        nprobe = take_queue(&left, probe, 4, now + RADIO_RESPONSE_MS);
        CHECK(nprobe == 1);
        CHECK(deliver_one(&right, &probe[0], now + RADIO_RESPONSE_MS, &status) == 0);
        CHECK(right.app.accepts == 1);
        right.wire.now = now + RADIO_RESPONSE_MS + RADIO_RECEIPT_MS;
        CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_RESPONSE_MS + RADIO_RECEIPT_MS) ==
              DMP_OK);
        nack = take_queue(&right, ack, 4, now + RADIO_RESPONSE_MS + RADIO_RECEIPT_MS);
        CHECK(nack >= 1);
        CHECK(ack[0].type == DMP_TYPE_ACK);
        CHECK(deliver_one(&left, &ack[0], now + RADIO_RESPONSE_MS + RADIO_RECEIPT_MS, &status) == 0);
        CHECK(left.app.unknowns == 0);
        CHECK(right.app.accepts == 1);
    }
    report("lost-ack", port, "pass");
    close_session(env);

    /* N=32 missing index 31 is 00 00 00 80. */
    dmp_test_opaque_fill(body, 512U, 0x71U);
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    {
        uint8_t wide[1024];
        uint32_t drop = 31U;
        int held_n = 0;
        captured held[4];
        dmp_test_opaque_fill(wide, sizeof wide, 0x81U);
        CHECK(submit_req(&left, 2U, span(wide, sizeof wide), now, &handle) ==
              DMP_OK);
        CHECK(pump_sender(&left, now, 32) == 0);
        count = take_queue(&left, burst, QUEUE, now);
        CHECK(count == 32);
        CHECK(deliver_mask(burst, count, &right, now, &drop, 1, held, &held_n, 0) == 0);
        CHECK(right.app.accepts == 0);
        right.wire.now = now + RADIO_COLLECT_MS;
        CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS) == DMP_OK);
        CHECK(right.assemblies[0].status_mask == 0x80000000U);
        CHECK(right.wire.n >= 1);
    }
    report("mask-n32-index31", port, "pass");
    close_session(env);

    /* Negative masks and the wrong service do not schedule a repair. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(count == 8);
    {
        const dmp_reliability_sender_slot *sender = live_frag_sender(&left);
        uint32_t reply_seq;
        uint8_t zero[4] = {0, 0, 0, 0};
        uint8_t alln[4] = {0xff, 0, 0, 0};
        uint8_t oor[4] = {0x00, 0x01, 0x00, 0x00};
        uint8_t short_mask[3] = {0x01, 0x00, 0x00};
        uint8_t good[4] = {0x01, 0x00, 0x00, 0x00};
        captured forged;
        int before;
        CHECK(sender != NULL);
        reply_seq = sender->own.seq;
        uint32_t mask_before;
        uint32_t repair_before;
        before = 0;
        left.wire.n = 0;
        mask_before = sender->active_mask;
        repair_before = sender->repair_mask;
        CHECK(seal_status(env, 1, 0U, 11U, reply_seq, 2U, zero, 4U, &forged) == 0);
        CHECK(deliver_one(&left, &forged, now, &status) == 0);
        CHECK(seal_status(env, 1, 0U, 12U, reply_seq, 2U, alln, 4U, &forged) == 0);
        CHECK(deliver_one(&left, &forged, now, &status) == 0);
        CHECK(seal_status(env, 1, 0U, 13U, reply_seq, 2U, oor, 4U, &forged) == 0);
        CHECK(deliver_one(&left, &forged, now, &status) == 0);
        CHECK(seal_status(env, 1, 0U, 14U, reply_seq, 1U, good, 4U, &forged) == 0);
        CHECK(deliver_one(&left, &forged, now, &status) == 0);
        {
            dmp_frame_spec spec;
            uint8_t ext[6] = {5U, 1U, (uint8_t)reply_seq, 17U, 1U, 2U};
            uint8_t sealed[MTU];
            size_t sealed_n = 0U;
            memset(&spec, 0, sizeof spec);
            spec.fields.type = (uint8_t)DMP_TYPE_FRAG_STATUS;
            spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_EXT);
            spec.fields.seq = 15U;
            spec.extensions = span(ext, 6U);
            spec.payload = span(short_mask, 3U);
            CHECK(dmp_hs_seal_logical(env->responder, 0U, &spec, sealed, sizeof sealed, &sealed_n) !=
                  DMP_HS_OK);
        }
        CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
        CHECK(left.wire.n == before);
        sender = live_frag_sender(&left);
        CHECK(sender != NULL);
        CHECK(sender->active_mask == mask_before);
        CHECK(sender->repair_mask == repair_before);
    }
    report("negative-status", port, "pass");
    close_session(env);

    /* The responder does not accept a status sealed to the initiator CID.
     * Replaying that status to the initiator is an old PN. A second
     * association with different keys is not constructed here: this fixture
     * repeats the same PSK, CID and entropy, so a new pair derives the same
     * traffic keys. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    {
        captured forged;
        uint8_t good[4] = {0x01, 0, 0, 0};
        const dmp_reliability_sender_slot *sender = live_frag_sender(&left);
        int before;
        CHECK(sender != NULL);
        CHECK(seal_status(env, 1, 0U, 9U, sender->own.seq, 2U, good, 4U, &forged) == 0);
        CHECK(deliver_one(&right, &forged, now, &status) == 0);
        CHECK(status == DMP_AUTHENTICATION_FAILURE);
        CHECK(right.wire.n == 0);
        left.wire.n = 0;
        CHECK(deliver_one(&left, &forged, now, &status) == 0);
        CHECK(status == DMP_OK);
        CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
        before = take_queue(&left, extra, 8, now);
        CHECK(before >= 1);
        CHECK(deliver_one(&left, &forged, now, &status) == 0);
        CHECK(status == DMP_AUTHENTICATION_FAILURE);
        CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
        CHECK(left.wire.n == 0);
    }
    report("status-wrong-association", port, "pass");
    close_session(env);

    /* Wholly unheard transfer: the receiver emits no FRAG_STATUS. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(count == 8);
    (void)burst;
    right.wire.now = now + RADIO_COLLECT_MS;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_COLLECT_MS) == DMP_OK);
    CHECK(right.wire.n == 0);
    CHECK(right.app.accepts == 0);
    report("feedback-silence", port, "pass");
    close_session(env);

    /* The SEC-1 receive path attempts authentication for PN=2^24-1, but rejects
     * PN=2^24 before AEAD accounting. Both frames retain a stale tag, so neither
     * can create an assembly or dispatch the REQ. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(count == 8 && burst[0].type == DMP_TYPE_REQ);
    {
        captured near_limit;
        captured at_limit;
        uint32_t failed_before = dmp_hs_failed_aead(env->responder, 0U);
        CHECK(captured_with_pn(&burst[0], now, UINT64_C(0x00ffffff), &near_limit));
        CHECK(deliver_one(&right, &near_limit, now, &status) == 0);
        CHECK(status == DMP_AUTHENTICATION_FAILURE);
        CHECK(dmp_hs_failed_aead(env->responder, 0U) == failed_before + 1U);
        CHECK(captured_with_pn(&burst[0], now, UINT64_C(0x01000000), &at_limit));
        CHECK(deliver_one(&right, &at_limit, now + 1U, &status) == 0);
        CHECK(status == DMP_AUTHENTICATION_FAILURE);
        CHECK(dmp_hs_failed_aead(env->responder, 0U) == failed_before + 1U);
        CHECK(right.app.accepts == 0 && right.wire.n == 0);
        CHECK(right.assemblies[0].live == 0U);
    }
    report("pn-limit-receive-guard", port, "pass");
    close_session(env);

    /* A second real SEC-1 association uses the same profile/IDs/CIDs but a
     * distinct public test PSK. A genuine request from the first association
     * must fail on the second receiver without assembly or application state. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    CHECK(count == 8);
    {
        const noise_fixture_probe_fixture_t *fixture = find_fixture();
        noise_fixture_probe_fixture_t alternate;
        session distinct;
        port_ctx distinct_port;
        node foreign_receiver;
        uint8_t alternate_psk[32];
        uint8_t primary_hash[32];
        uint8_t alternate_hash[32];
        uint32_t alternate_index = 0U;
        dmp_status received;
        CHECK(fixture != NULL && fixture->psk.size == sizeof alternate_psk);
        CHECK(dmp_hs_copy_hash(env->initiator, index, primary_hash));
        close_session(env);
        alternate = *fixture;
        memcpy(alternate_psk, fixture->psk.data, sizeof alternate_psk);
        alternate_psk[0] ^= 0x80U;
        alternate.psk.data = alternate_psk;
        CHECK(make_pair(&distinct, &distinct_port, &alternate, RADIO_SHA));
        CHECK(drive_nn(&distinct, &alternate_index));
        CHECK(activate(&distinct, alternate_index));
        CHECK(dmp_hs_copy_hash(distinct.initiator, alternate_index, alternate_hash));
        CHECK(memcmp(primary_hash, alternate_hash, sizeof primary_hash) != 0);
        CHECK(boot_node(&foreign_receiver, 0, PROF_RADIO, now, 0) == 0);
        CHECK(dmp_endpoint_bind(&foreign_receiver.endpoint, distinct.responder, 0U) == DMP_OK);
        CHECK(deliver_one(&foreign_receiver, &burst[0], now, &received) == 0);
        CHECK(received == DMP_AUTHENTICATION_FAILURE);
        CHECK(foreign_receiver.app.accepts == 0 && foreign_receiver.wire.n == 0);
        CHECK(foreign_receiver.assemblies[0].live == 0U);
        close_session(&distinct);
    }
    report("distinct-key-association-mismatch", port, "pass");
    close_session(env);

    /* Fragmented exchange: lose one RSP slice and its result ACK. Fresh-PN
     * duplicate REQs during processing and after result release never execute
     * the request again or allocate a second result transfer. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    dmp_test_opaque_fill(body, 256U, 0x93U);
    dmp_test_opaque_fill(result, sizeof result, 0x92U);
    CHECK(allow_service1_request(&left) == 0 && allow_service1_request(&right) == 0 &&
          allow_service1_result(&left) == 0 && allow_service1_result(&right) == 0);
    CHECK(submit_req(&left, 1U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    {
        captured request_frames[8];
        captured processing_duplicates[8];
        captured retained_duplicates[8];
        captured responses[16];
        captured status_frame[2];
        captured repair[4];
        captured ack[4];
        captured probe[4];
        captured discard[QUEUE];
        captured held[4];
        uint32_t drop = 3U;
        int held_n = 0;
        int nstatus;
        int nrepair;
        int nack;
        int nprobe;
        int live_result_senders;
        size_t i;
        dmp_time_ms result_at = now + RADIO_RECEIPT_MS + 1U;
        dmp_time_ms status_at = result_at + RADIO_COLLECT_MS;
        dmp_time_ms probe_at;
        dmp_time_ms duplicate_at;
        dmp_reliability_handle pending = right.app.pending;

        count = take_queue(&left, request_frames, 8, now);
        CHECK(count == 8);
        for (i = 0U; i < 8U; i++) {
            CHECK(request_frames[i].type == DMP_TYPE_REQ && request_frames[i].index == i);
            CHECK(deliver_one(&right, &request_frames[i], now, &status) == 0);
            CHECK(status == DMP_OK || status == DMP_INCOMPLETE || status == DMP_DUPLICATE);
        }
        CHECK(right.app.accepts == 1 && right.app.have_pending != 0);
        pending = right.app.pending;

        /* Resend every request slice with the same logical SEQ and fresh PN
         * while application processing is pending. */
        for (i = 0U; i < 8U; i++) {
            CHECK(reseal_new_pn(env, index, &request_frames[i],
                                span(body + i * 32U, 32U), now + 1U,
                                &processing_duplicates[i]));
            CHECK(processing_duplicates[i].index == i);
            CHECK(deliver_one(&right, &processing_duplicates[i], now + 1U, &status) == 0);
            CHECK(status == DMP_OK || status == DMP_DUPLICATE);
        }
        CHECK(right.app.accepts == 1 && right.app.pending.slot == pending.slot &&
              right.app.pending.generation == pending.generation);
        right.wire.now = now + RADIO_RECEIPT_MS;
        CHECK(dmp_endpoint_poll(&right.endpoint, now + RADIO_RECEIPT_MS) == DMP_OK);
        nack = take_queue(&right, ack, 4, now + RADIO_RECEIPT_MS);
        CHECK(nack >= 1 && nack <= 4);
        for (i = 0U; i < (size_t)nack; i++) {
            CHECK(ack[i].type == DMP_TYPE_ACK);
            CHECK(deliver_one(&left, &ack[i], now + RADIO_RECEIPT_MS, &status) == 0);
            CHECK(status == DMP_OK || status == DMP_DUPLICATE);
        }

        /* Completing the pending request produces the one fragmented RSP. */
        CHECK(dmp_endpoint_complete(&right.endpoint, pending, false, 0U,
                                    span(result, sizeof result), result_at) == DMP_OK);
        CHECK(pump_sender(&right, result_at, 16) == 0);
        count = take_queue(&right, responses, 16, result_at);
        CHECK(count == 16);
        for (i = 0U; i < 16U; i++) {
            CHECK(responses[i].type == DMP_TYPE_RSP && responses[i].index == i);
        }
        CHECK(deliver_mask(responses, count, &left, result_at, &drop, 1, held, &held_n, 0) == 0);
        CHECK(held_n == 1 && held[0].index == 3U);
        CHECK(left.app.results == 0);

        /* A duplicate during the cached result transfer cannot start a second
         * RSP burst. The active transfer continues on its existing schedule. */
        for (i = 0U; i < 8U; i++) {
            CHECK(reseal_new_pn(env, index, &request_frames[i], span(body + i * 32U, 32U),
                                result_at + 1U, &retained_duplicates[i]));
            CHECK(deliver_one(&right, &retained_duplicates[i], result_at + 1U, &status) == 0);
            CHECK(status == DMP_OK || status == DMP_DUPLICATE);
        }
        CHECK(right.app.accepts == 1 && right.wire.n == 0);
        CHECK(dmp_endpoint_poll(&right.endpoint, result_at + 1U) == DMP_OK);
        CHECK(right.wire.n == 0);
        left.wire.now = status_at;
        CHECK(dmp_endpoint_poll(&left.endpoint, status_at) == DMP_OK);
        CHECK(left.assemblies[0].status_mask == (UINT32_C(1) << 3U));
        nstatus = take_queue(&left, status_frame, 2, status_at);
        CHECK(nstatus == 1 && status_frame[0].type == DMP_TYPE_FRAG_STATUS);
        CHECK(deliver_one(&right, &status_frame[0], status_at, &status) == 0);
        CHECK(status == DMP_OK || status == DMP_DUPLICATE);
        CHECK(dmp_endpoint_poll(&right.endpoint, status_at) == DMP_OK);
        nrepair = take_queue(&right, repair, 4, status_at);
        CHECK(nrepair == 1 && repair[0].type == DMP_TYPE_RSP && repair[0].index == 3U);
        CHECK(deliver_one(&left, &repair[0], status_at, &status) == 0);
        CHECK(status == DMP_OK || status == DMP_DUPLICATE);
        CHECK(left.app.results == 1 && left.app.result_n == sizeof result);
        CHECK(memcmp(left.app.result_body, result, sizeof result) == 0);

        /* Drop the result receipt, then let the sender's real timeout probe
         * recover an ACK without invoking the result callback twice. */
        left.wire.now = status_at + RADIO_RECEIPT_MS;
        CHECK(dmp_endpoint_poll(&left.endpoint, status_at + RADIO_RECEIPT_MS) == DMP_OK);
        nack = take_queue(&left, ack, 4, status_at + RADIO_RECEIPT_MS);
        CHECK(nack == 1 && ack[0].type == DMP_TYPE_ACK);
        probe_at = status_at + RADIO_RECEIPT_MS + RADIO_RESPONSE_MS;
        right.wire.now = probe_at;
        CHECK(dmp_endpoint_poll(&right.endpoint, probe_at) == DMP_OK);
        nprobe = take_queue(&right, probe, 4, probe_at);
        CHECK(nprobe == 1 && probe[0].type == DMP_TYPE_RSP && probe[0].index == 15U);
        CHECK(deliver_one(&left, &probe[0], probe_at, &status) == 0);
        CHECK(status == DMP_OK || status == DMP_DUPLICATE);
        CHECK(left.app.results == 1 && memcmp(left.app.result_body, result, sizeof result) == 0);
        left.wire.now = probe_at + RADIO_RECEIPT_MS;
        CHECK(dmp_endpoint_poll(&left.endpoint, probe_at + RADIO_RECEIPT_MS) == DMP_OK);
        nack = take_queue(&left, ack, 4, probe_at + RADIO_RECEIPT_MS);
        CHECK(nack == 1 && ack[0].type == DMP_TYPE_ACK);
        CHECK(deliver_one(&right, &ack[0], probe_at + RADIO_RECEIPT_MS, &status) == 0);
        CHECK(status == DMP_OK || status == DMP_DUPLICATE);
        live_result_senders = 0;
        for (i = 0U; i < SENDERS; i++) {
            if (right.senders[i].live != 0U &&
                right.senders[i].kind == DMP_REL_SENDER_RESULT) {
                live_result_senders++;
            }
        }
        CHECK(live_result_senders == 0 && right.app.accepts == 1);

        /* The receipt retry budget is already spent. After result release the
         * retained request identity emits nothing and is not redispatched. */
        duplicate_at = probe_at + RADIO_RECEIPT_MS + 1U;
        for (i = 0U; i < 8U; i++) {
            CHECK(reseal_new_pn(env, index, &request_frames[i], span(body + i * 32U, 32U),
                                duplicate_at, &retained_duplicates[i]));
            CHECK(deliver_one(&right, &retained_duplicates[i], duplicate_at, &status) == 0);
            CHECK(status == DMP_OK || status == DMP_DUPLICATE);
        }
        CHECK(right.app.accepts == 1 && left.app.results == 1);
        right.wire.now = duplicate_at + RADIO_RECEIPT_MS;
        CHECK(dmp_endpoint_poll(&right.endpoint, duplicate_at + RADIO_RECEIPT_MS) == DMP_OK);
        nack = take_queue(&right, discard, QUEUE, duplicate_at + RADIO_RECEIPT_MS);
        CHECK(nack == 0);
        CHECK(left.app.results == 1 && right.app.accepts == 1);
    }
    report("fragmented-result-loss-duplicate-req", port, "pass");
    close_session(env);

    /* Accepted duplicate with a different payload does not dispatch again. */
    CHECK(open_pair(env, port, PROF_RADIO, now, 0, &index) == 0);
    CHECK(submit_req(&left, 2U, span(body, 256U), now, &handle) == DMP_OK);
    CHECK(pump_sender(&left, now, 8) == 0);
    count = take_queue(&left, burst, QUEUE, now);
    g_hold = 0;
    CHECK(deliver_mask(burst, count, &right, now, NULL, 0, NULL, &g_hold, 0) == 0);
    CHECK(right.app.accepts == 1);
    {
        dmp_frame_spec spec;
        uint8_t ext[4] = {17U, 1U, 2U, 0U};
        uint8_t slice[32];
        uint8_t sealed[MTU];
        uint8_t wrapped[FRAME_CAP];
        size_t sealed_n = 0U;
        size_t wrapped_n = 0U;
        const dmp_reliability_sender_slot *sender = NULL;
        size_t s;
        captured bad;
        for (s = 0U; s < SENDERS; s++) {
            if (left.senders[s].payload_len == 256U) {
                sender = &left.senders[s];
                break;
            }
        }
        CHECK(sender != NULL);
        memset(slice, 0xa5, sizeof slice);
        memset(&spec, 0, sizeof spec);
        spec.fields.type = (uint8_t)DMP_TYPE_REQ;
        spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_FRAG | DMP_OPT_EXT);
        spec.fields.seq = sender->own.seq;
        spec.fields.fragment.index = 0U;
        spec.fields.fragment.chunk_size = 32U;
        spec.fields.fragment.total_size = 256U;
        spec.extensions = span(ext, 3U);
        spec.payload = span(slice, sizeof slice);
        CHECK(dmp_hs_seal_logical(env->initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
              DMP_HS_OK);
        CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
        memset(&bad, 0, sizeof bad);
        memcpy(bad.frame, wrapped, wrapped_n);
        bad.len = wrapped_n;
        CHECK(deliver_one(&right, &bad, now, &status) == 0);
        CHECK(right.app.accepts == 1);
        CHECK(memcmp(right.app.req_body, body, 256U) == 0);
    }
    report("duplicate-payload", port, "pass");
    close_session(env);

    (void)extra;
    CHECK(g_provider > 0U && g_provider <= 3U * 12288U);
    note_peak();
    report("gaps", port, "pass");
    return 0;
}

int main(int argc, char **argv)
{
    const char *name = argc > 1 ? argv[1] : "all";
    session env;
    port_ctx port;
    int failed = 0;
    memset(&env, 0, sizeof env);
    if (strcmp(name, "geometry") == 0 || strcmp(name, "all") == 0) {
        failed |= test_geometry(&env, &port);
        close_session(&env);
    }
    if (failed == 0 && (strcmp(name, "r6") == 0 || strcmp(name, "all") == 0)) {
        failed |= test_r6(&env, &port);
        close_session(&env);
    }
    if (failed == 0 && (strcmp(name, "r7") == 0 || strcmp(name, "all") == 0)) {
        failed |= test_r7(&env, &port);
        close_session(&env);
    }
    if (failed == 0 && (strcmp(name, "retry_all") == 0 || strcmp(name, "all") == 0)) {
        failed |= test_retry_all(&env, &port);
        close_session(&env);
    }
    if (failed == 0 && (strcmp(name, "relay_sample") == 0 || strcmp(name, "all") == 0)) {
        failed |= test_relay_sample(&env, &port);
        close_session(&env);
    }
    if (failed == 0 && (strcmp(name, "feedback") == 0 || strcmp(name, "all") == 0)) {
        failed |= test_feedback(&env, &port);
        close_session(&env);
    }
    if (failed == 0 && (strcmp(name, "gaps") == 0 || strcmp(name, "all") == 0)) {
        failed |= test_gaps(&env, &port);
        close_session(&env);
    }
    if (failed == 0 && (strcmp(name, "async") == 0 || strcmp(name, "all") == 0)) {
        failed |= test_async(&env, &port);
        close_session(&env);
    }
    if (failed == 0 && (strcmp(name, "async_radio") == 0 || strcmp(name, "all") == 0)) {
        failed |= test_async_radio(&env, &port);
        close_session(&env);
    }
    if (failed == 0 && (strcmp(name, "freshness") == 0 || strcmp(name, "all") == 0)) {
        failed |= test_freshness(&env, &port);
        close_session(&env);
    }
    if (strcmp(name, "geometry") != 0 && strcmp(name, "r6") != 0 && strcmp(name, "r7") != 0 &&
        strcmp(name, "retry_all") != 0 && strcmp(name, "relay_sample") != 0 &&
        strcmp(name, "feedback") != 0 && strcmp(name, "gaps") != 0 &&
        strcmp(name, "async") != 0 && strcmp(name, "async_radio") != 0 &&
        strcmp(name, "freshness") != 0 &&
        strcmp(name, "all") != 0) {
        (void)fprintf(stderr, "unknown scenario %s\n", name);
        return 2;
    }
    return failed == 0 ? 0 : 1;
}
