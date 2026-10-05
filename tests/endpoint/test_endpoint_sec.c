/* Host loopback only. This is not physical-transport evidence.
 *
 * Two libdmp endpoints exchange after the real P14 association activates.
 * Protection is dmp_hs_seal_logical / dmp_hs_open_logical on the existing
 * provider cipher. Reliability and reassembly are the existing engines.
 *
 * Deferred, not implemented here: S10 case 6 relay-state (P19) and S10 case 11
 * multi-binding forwarding (P23). Freshness case 10 stays omitted: the admitted
 * services set freshness false and lease_ms 0. S10 case 8 is host context
 * destruction only; it is not a physical reboot and it does not add NVS.
 * Host loopback is not physical-transport evidence.
 * S3.1 still does not define a jitter distribution; restart jitter stays 0.
 */
#include "dmp/core.h"
#include "dmp/endpoint.h"
#include "dmp/stream.h"

#include "handshake.h"
#include "noise_fixture_probe.h"
#include "sample1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,     \
                          __LINE__, #condition);                             \
            return 1;                                                        \
        }                                                                    \
    } while (0)

enum {
    SENDERS = 4,
    RESULTS = 4,
    HISTORY = 8,
    CORRELATIONS = 4,
    ADAPTERS = 3,
    MESSAGE = 1024,
    MTU = 263,
    ASSEMBLIES = 1,
    TOMBSTONES = 16,
    STREAM_CAP = 512,
    QUEUE = 24,
    FRAME_CAP = 512,
    LOCAL_NS = 1,
    ID_INIT = 0x0a,
    ID_RESP = 0x14,
    CID_INIT = 7,
    CID_RESP = 9,
    KEY_HINT = 5,
    FRAG_BYTES = 300,
    FRAG_CHUNK = 16
};

typedef struct node node;

typedef struct {
    int used;
    uint8_t frame[FRAME_CAP];
    size_t len;
} held;

typedef struct {
    node *self;
    held q[QUEUE];
    int n;
    int submits;
    int drop_remaining;
    uint8_t saved[FRAME_CAP];
    size_t saved_len;
    uint8_t last[FRAME_CAP];
    size_t last_len;
    dmp_time_ms now;
} wire;

typedef struct {
    int producer;
    int have_pending;
    dmp_reliability_handle pending;
    int accepts;
    int results;
    int telems;
    int assembled;
    int unknowns;
    uint8_t req[8];
    size_t req_n;
    uint8_t result[32];
    size_t result_n;
    uint8_t body[MESSAGE];
    size_t body_n;
} app;

struct node {
    dmp_endpoint endpoint;
    dmp_transport transport;
    wire wire;
    app app;
    dmp_identity_slot ids[2];
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

typedef struct script {
    const uint8_t *data[8];
    size_t len[8];
    size_t count;
    size_t index;
    int fail;
} script;

typedef struct store {
    int fail;
    int calls;
    int has;
    uint8_t saved[32];
} store;

typedef struct box {
    uint64_t *now;
    script *entropy_script;
    store *pin_store;
} box;

typedef struct session {
    uint64_t now;
    script init_script;
    script resp_script;
    store init_store;
    store resp_store;
    box init_box;
    box resp_box;
    dmp_provider *provider;
    dmp_hs *initiator;
    dmp_hs *responder;
    uint8_t alt_attempt[16];
    uint8_t rot_id[16];
    uint8_t rot_init_eph[32];
    uint8_t rot_resp_eph[32];
} session;

typedef struct port_ctx {
    unsigned alloc_calls;
    size_t live;
    size_t peak;
    size_t peak_one;
} port_ctx;

typedef void (*tune_fn)(dmp_hs_config *initiator, dmp_hs_config *responder);

static node left;
static node right;

static const uint8_t DIRECT_SHA[DMP_PROFILE_SHA256_BYTES] = {
    0x29, 0xcb, 0x7b, 0x91, 0xee, 0x0c, 0x26, 0x9b, 0xc1, 0x4a, 0xc4, 0x3e, 0x3a, 0x7c, 0x8f, 0xd8,
    0xbd, 0xcf, 0xe1, 0x1e, 0x9e, 0x05, 0x2e, 0x8b, 0xd9, 0xe6, 0xaf, 0x00, 0xfb, 0x89, 0xc3, 0xbf};

static const uint8_t READ_RSP[SAMPLE1_READ_BYTES] = {
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2c, 0x01, 0x00,
    0x00};

static dmp_bytes span(const void *data, size_t size)
{
    dmp_bytes bytes;
    bytes.data = (const uint8_t *)data;
    bytes.size = size;
    return bytes;
}

static void on_notice(void *user, const dmp_endpoint_notice *notice)
{
    node *self = user;
    if (self == NULL || notice == NULL) {
        return;
    }
    if (notice->event == DMP_ENDPOINT_REQUEST) {
        self->app.accepts++;
        self->app.req_n = notice->payload.size < sizeof self->app.req ? notice->payload.size : 0U;
        if (self->app.req_n != 0U && notice->payload.data != NULL) {
            memcpy(self->app.req, notice->payload.data, self->app.req_n);
        }
        self->app.pending = notice->request;
        self->app.have_pending = 1;
        return;
    }
    if (notice->event == DMP_ENDPOINT_RESULT) {
        self->app.results++;
        self->app.result_n =
            notice->payload.size < sizeof self->app.result ? notice->payload.size : 0U;
        if (self->app.result_n != 0U && notice->payload.data != NULL) {
            memcpy(self->app.result, notice->payload.data, self->app.result_n);
        }
        return;
    }
    if (notice->event == DMP_ENDPOINT_TELEMETRY) {
        self->app.telems++;
        return;
    }
    if (notice->event == DMP_ENDPOINT_ASSEMBLED) {
        self->app.assembled++;
        self->app.body_n = notice->payload.size <= sizeof self->app.body ? notice->payload.size : 0U;
        if (self->app.body_n != 0U && notice->payload.data != NULL) {
            memcpy(self->app.body, notice->payload.data, self->app.body_n);
        }
        return;
    }
    if (notice->event == DMP_ENDPOINT_UNKNOWN) {
        self->app.unknowns++;
    }
}

static dmp_status wire_submit(void *context, const dmp_tx_submission *submission)
{
    wire *link = context;
    if (link == NULL || submission == NULL || submission->frame.data == NULL ||
        submission->complete == NULL || submission->frame.size > FRAME_CAP) {
        return DMP_INVALID_ARGUMENT;
    }
    link->submits++;
    memcpy(link->last, submission->frame.data, submission->frame.size);
    link->last_len = submission->frame.size;
    if (link->drop_remaining > 0) {
        link->drop_remaining--;
        if (link->saved_len == 0U) {
            memcpy(link->saved, submission->frame.data, submission->frame.size);
            link->saved_len = submission->frame.size;
        }
        submission->complete(submission->owner, submission->token, DMP_TX_TRANSMITTED, link->now);
        return DMP_OK;
    }
    if (link->n >= QUEUE) {
        return DMP_BUSY;
    }
    memcpy(link->q[link->n].frame, submission->frame.data, submission->frame.size);
    link->q[link->n].len = submission->frame.size;
    link->q[link->n].used = 1;
    link->n++;
    submission->complete(submission->owner, submission->token, DMP_TX_TRANSMITTED, link->now);
    return DMP_OK;
}

static dmp_status wire_cancel(void *context, dmp_tx_token token)
{
    (void)context;
    (void)token;
    return DMP_OK;
}

static int g_fill_selective;

static void fill_direct(dmp_config *config, uint32_t chunk, uint32_t fragments)
{
    memset(config, 0, sizeof *config);
    memcpy(config->sha256, DIRECT_SHA, sizeof DIRECT_SHA);
    config->namespace_id = LOCAL_NS;
    config->node_id[0] = ID_INIT;
    config->node_id[1] = ID_RESP;
    config->default_service = 1U;
    config->service_id[0] = 1U;
    config->service_id[1] = 2U;
    config->recovery[0] = DMP_PROFILE_RECOVERY_RETRY_ALL;
    config->recovery[1] = DMP_PROFILE_RECOVERY_RETRY_ALL;
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
    config->adapter_slots = ADAPTERS;
    config->application_queue_slots = 2U;
    config->control_slots = 2U;
    config->message_bytes = MESSAGE;
    config->fragments = fragments;
    config->chunk_bytes = chunk;
    config->encoded_mtu = MTU;
    config->forward_mtu = 256U;
    config->return_mtu = 256U;
    config->queue_ms = 64U;
    config->response_timeout_ms = 1280U;
    config->jitter_ms = 0U;
    config->send_horizon_ms = 5632U;
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
    if (g_fill_selective) {
        config->recovery[0] = DMP_PROFILE_RECOVERY_SELECTIVE32;
        config->recovery[1] = DMP_PROFILE_RECOVERY_SELECTIVE32;
        config->burst_span_ms = 1U;
        config->forward_delay_ms = 1U;
        config->return_delay_ms = 1U;
        config->feedback_guard_ms = 1U;
        config->feedback_delay_ms = 1U;
        config->max_probes = 1U;
        config->max_status = 1U;
        config->record_margin_ms = 1U;
    }
}

static int install_manifest_grants(node *self)
{
    dmp_endpoint_grant grants[4];

    memset(grants, 0, sizeof grants);
    grants[0].principal = ID_INIT;
    grants[0].service_id = 1U;
    grants[0].permit = DMP_ENDPOINT_PERMIT_TELEM | DMP_ENDPOINT_PERMIT_RESULT;
    grants[1].principal = ID_RESP;
    grants[1].service_id = 1U;
    grants[1].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[2].principal = ID_INIT;
    grants[2].service_id = 2U;
    grants[2].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    grants[3].principal = ID_RESP;
    grants[3].service_id = 2U;
    grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    return dmp_endpoint_set_grants(&self->endpoint, grants, 4U) == DMP_OK ? 0 : 1;
}

static int boot_node_slots(node *self, int producer, uint32_t chunk, uint32_t fragments,
                           dmp_time_ms now, size_t slots)
{
    dmp_config input;
    dmp_admitted_profile admitted;
    dmp_endpoint_storage storage;
    dmp_identity_context_config identity;
    memset(self, 0, sizeof *self);
    fill_direct(&input, chunk, fragments);
    CHECK(dmp_config_admit(&input, &admitted) == DMP_OK);
    memset(&identity, 0, sizeof identity);
    identity.local.namespace_id = LOCAL_NS;
    identity.peer.namespace_id = LOCAL_NS;
    if (producer) {
        identity.local.origin_id = ID_INIT;
        identity.peer.origin_id = ID_RESP;
    } else {
        identity.local.origin_id = ID_RESP;
        identity.peer.origin_id = ID_INIT;
    }
    identity.security = 1U;
    self->app.producer = producer;
    self->wire.self = self;
    self->wire.now = now;
    self->transport.context = &self->wire;
    self->transport.submit = wire_submit;
    self->transport.cancel = wire_cancel;
    self->transport.caps.max_frame_bytes = FRAME_CAP;
    self->transport.caps.ownership = DMP_TX_BORROW;
    self->transport.caps.synchronous_completion = true;
    memset(&storage, 0, sizeof storage);
    storage.profile = &admitted;
    storage.identity_slots = self->ids;
    storage.identity_capacity = slots;
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
    CHECK(dmp_endpoint_init(&self->endpoint, &storage, now) == DMP_OK);
    return install_manifest_grants(self);
}

static int boot_node(node *self, int producer, uint32_t chunk, uint32_t fragments, dmp_time_ms now)
{
    return boot_node_slots(self, producer, chunk, fragments, now, 1U);
}

static int boot_selective(node *self, int producer, uint32_t chunk, uint32_t fragments, dmp_time_ms now)
{
    int rc;

    g_fill_selective = 1;
    rc = boot_node(self, producer, chunk, fragments, now);
    g_fill_selective = 0;
    return rc;
}

static int unwrap_core(const uint8_t *framed, size_t n, uint8_t *core, size_t cap, size_t *core_n,
                       dmp_time_ms now);

static int stream_fragment(const uint8_t *framed, size_t n, dmp_time_ms now, uint32_t *index,
                           uint64_t *pn)
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
    if (parsed.status != DMP_OK || (view.fields.options & DMP_OPT_FRAG) == 0U) {
        return 0;
    }
    if (index != NULL) {
        *index = view.fields.fragment.index;
    }
    if (pn != NULL) {
        *pn = view.fields.security.pn;
    }
    return 1;
}

static int service(node *self, dmp_time_ms now)
{
    uint8_t payload[SAMPLE1_READ_BYTES];
    size_t n;
    if (!self->app.producer || !self->app.have_pending) {
        return 0;
    }
    if (self->app.req_n != 1U || self->app.req[0] != SAMPLE1_READ) {
        return 1;
    }
    n = sample1_read_rsp(payload, 1U, 2U, 300U);
    CHECK(dmp_endpoint_complete(&self->endpoint, self->app.pending, false, 0U, span(payload, n),
                                now) == DMP_OK);
    self->app.have_pending = 0;
    return 0;
}

static int deliver_one(node *from, node *to, int index, dmp_time_ms now, dmp_status *status_out)
{
    dmp_bytes bytes;
    dmp_status status;
    if (index < 0 || index >= from->wire.n) {
        return 1;
    }
    bytes = span(from->wire.q[index].frame, from->wire.q[index].len);
    status = dmp_endpoint_rx(&to->endpoint, bytes, now);
    if (status_out != NULL) {
        *status_out = status;
    }
    return 0;
}

static int deliver_all(node *from, node *to, dmp_time_ms now)
{
    int i;
    int n = from->wire.n;
    for (i = 0; i < n; i++) {
        dmp_status status = DMP_OK;
        CHECK(deliver_one(from, to, i, now, &status) == 0);
        CHECK(status == DMP_OK || status == DMP_INCOMPLETE || status == DMP_DUPLICATE);
    }
    from->wire.n = 0;
    return 0;
}

static int pump(dmp_time_ms now, int rounds)
{
    int i;
    left.wire.now = now;
    right.wire.now = now;
    for (i = 0; i < rounds; i++) {
        CHECK(service(&left, now) == 0);
        CHECK(service(&right, now) == 0);
        CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
        CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
        CHECK(deliver_all(&left, &right, now) == 0);
        CHECK(deliver_all(&right, &left, now) == 0);
    }
    CHECK(service(&left, now) == 0);
    CHECK(service(&right, now) == 0);
    return 0;
}

static const noise_fixture_probe_fixture_t *find_fixture(const char *name)
{
    size_t index;
    for (index = 0U; index < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++index) {
        if (strcmp(noise_fixture_probe_fixtures[index].name, name) == 0) {
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
    for (index = 0U; index < size; ++index) {
        out[index] = (uint8_t)(0x3DU + (uint8_t)index);
    }
    return 0;
}

static int provider_entropy(void *ctx, void *bytes, size_t size)
{
    uint8_t *out = (uint8_t *)bytes;
    size_t index;
    (void)ctx;
    for (index = 0U; index < size; ++index) {
        out[index] = (uint8_t)(0x71U + (uint8_t)index);
    }
    return 0;
}

static void *port_allocate(void *ctx, size_t size)
{
    port_ctx *port = (port_ctx *)ctx;
    void *ptr;
    port->alloc_calls++;
    ptr = calloc(1, size);
    if (ptr == NULL) {
        return NULL;
    }
    port->live += size;
    if (port->live > port->peak) {
        port->peak = port->live;
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

static void note_provider(const char *label, const port_ctx *port, const dmp_provider *provider)
{
    (void)fprintf(stderr,
                  "provider-measure %s peak_retained=%zu peak_single=%zu live=%zu "
                  "provider_retained=%zu blocks=%zu\n",
                  label, port->peak, port->peak_one, port->live, dmp_provider_retained(provider),
                  dmp_provider_block_count(provider));
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
    if (src->fail || src->index >= src->count || src->len[src->index] != size) {
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

static void fill_hs(dmp_hs_config *config, const noise_fixture_probe_fixture_t *fixture, int initiator)
{
    memset(config, 0, sizeof *config);
    fill_budget(&config->budget);
    config->namespace_id = LOCAL_NS;
    config->local_id = initiator ? ID_INIT : ID_RESP;
    config->peer_id = initiator ? ID_RESP : ID_INIT;
    memcpy(config->profile_hash, fixture->profile_hash.data, 32U);
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
                     tune_fn tune, dmp_provider *existing, int alt_entropy)
{
    dmp_hs_config init_config;
    dmp_hs_config resp_config;
    dmp_hs_ports init_ports;
    dmp_hs_ports resp_ports;
    dmp_provider_ports ports;
    dmp_provider *provider;
    memset(env, 0, sizeof *env);
    env->now = 10000U;
    memset(port, 0, sizeof *port);
    provider = existing;
    if (existing == NULL) {
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
        if (env->provider == NULL || dmp_provider_setup(env->provider, &ports) != DMP_PROVIDER_OK) {
            close_session(env);
            return 0;
        }
        provider = env->provider;
    }
    env->initiator = (dmp_hs *)calloc(1, dmp_hs_size());
    env->responder = (dmp_hs *)calloc(1, dmp_hs_size());
    if (env->initiator == NULL || env->responder == NULL) {
        close_session(env);
        return 0;
    }
    fill_hs(&init_config, fixture, 1);
    fill_hs(&resp_config, fixture, 0);
    if (tune != NULL) {
        tune(&init_config, &resp_config);
    }
    if (alt_entropy) {
        memset(env->alt_attempt, 0x42, sizeof env->alt_attempt);
        script_add(&env->init_script, env->alt_attempt, sizeof env->alt_attempt);
        script_add(&env->init_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
        script_add(&env->resp_script, fixture->init_ephemeral.data, fixture->init_ephemeral.size);
    } else {
        script_add(&env->init_script, fixture->attempt_id.data, fixture->attempt_id.size);
        script_add(&env->init_script, fixture->init_ephemeral.data, fixture->init_ephemeral.size);
        script_add(&env->resp_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
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
    if (dmp_hs_init(env->initiator, provider, &init_config, &init_ports) != DMP_HS_OK ||
        dmp_hs_init(env->responder, provider, &resp_config, &resp_ports) != DMP_HS_OK ||
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
    if (boot == 0U) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->initiator, *index, &length);
    if (!drive_flight(env->responder, cached, length, ID_INIT, ID_RESP, 1U, boot, DMP_HS_CANDIDATE)) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->responder, 0U, &length);
    return drive_flight(env->initiator, cached, length, ID_RESP, ID_INIT, 2U, boot, DMP_HS_CANDIDATE);
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
    if (!dmp_hs_epochs(env->initiator, index, &epoch_i, &epoch_r)) {
        return 0;
    }
    if (dmp_hs_confirm(env->initiator, index) != DMP_HS_OK) {
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
    CHECK(dmp_endpoint_bind(&left.endpoint, env->initiator, index) == DMP_OK);
    CHECK(dmp_endpoint_bind(&right.endpoint, env->responder, 0U) == DMP_OK);
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

static int test_activation(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t req[1];
    uint8_t plain[32];
    uint8_t wrapped[128];
    dmp_frame_spec spec;
    dmp_core_limits limits;
    dmp_buffer out;
    size_t written = 0U;
    size_t wrapped_n = 0U;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    dmp_status status;
    int failed = 1;
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index)) {
        return 1;
    }
    if (boot_node(&left, 1, 64U, 16U, now) != 0 || boot_node(&right, 0, 64U, 16U, now) != 0 ||
        bind_pair(&env, index) != 0) {
        close_session(&env);
        return 1;
    }
    CHECK(dmp_hs_association_active(env.initiator) == 0);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    status = dmp_endpoint_poll(&right.endpoint, now);
    /* A live attempt that is not active yet keeps the admitted REQ.
     * Poll stays DMP_OK because reliability treats that wait as DMP_BUSY. */
    CHECK(status == DMP_OK);
    CHECK(right.wire.n == 0);
    CHECK(left.app.accepts == 0);
    CHECK(activate(&env, index) == 1);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(right.app.result_n == sizeof READ_RSP);
    CHECK(memcmp(right.app.result, READ_RSP, sizeof READ_RSP) == 0);
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ);
    spec.fields.seq = 1U;
    spec.payload = span(req, 1U);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 16U;
    out.data = plain;
    out.capacity = sizeof plain;
    CHECK(dmp_core_encode(&spec, &limits, out, &written) == DMP_OK);
    CHECK(wrap_core(plain, written, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(left.app.accepts == 1);
    failed = 0;
    close_session(&env);
    return failed;
}

static int test_alter(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t req[1];
    uint8_t core[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t core_n = 0U;
    size_t wrapped_n = 0U;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    dmp_status status = DMP_OK;
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(service(&left, now) == 0);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 1);
    CHECK(unwrap_core(left.wire.q[0].frame, left.wire.q[0].len, core, sizeof core, &core_n, now) == 1);
    CHECK(core_n > 1U);
    core[core_n - 1U] ^= 0x01U;
    CHECK(wrap_core(core, core_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.results == 0);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(right.app.results == 1);
    CHECK(right.app.result_n == sizeof READ_RSP);
    CHECK(memcmp(right.app.result, READ_RSP, sizeof READ_RSP) == 0);
    close_session(&env);
    return 0;
}

static int test_loss(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t req[1];
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    /* The existing reliability engine retries the request. The dropped frame is
     * not replayed: the later submit is a newly sealed record. */
    right.wire.drop_remaining = 1;
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 4) == 0);
    CHECK(left.app.accepts == 0);
    CHECK(right.app.results == 0);
    CHECK(right.wire.saved_len > 0U);
    CHECK(pump(now + 1280U, 8) == 0);
    CHECK(right.wire.submits >= 2);
    CHECK(right.wire.last_len > 0U);
    CHECK(right.wire.saved_len != right.wire.last_len ||
          memcmp(right.wire.saved, right.wire.last, right.wire.saved_len) != 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(memcmp(right.app.result, READ_RSP, sizeof READ_RSP) == 0);
    close_session(&env);
    return 0;
}

static void tune_alt(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    initiator->next_rx_cid = 100U;
    responder->next_rx_cid = 200U;
}

static int test_isolate(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    session other;
    port_ctx port;
    port_ctx other_port;
    uint32_t index = 0U;
    uint32_t other_index = 0U;
    uint8_t req[1];
    uint8_t stolen[FRAME_CAP];
    size_t stolen_len = 0U;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    dmp_status status = DMP_OK;
    memset(&env, 0, sizeof env);
    memset(&other, 0, sizeof other);
    if (fixture == NULL || !make_pair(&other, &other_port, fixture, tune_alt, NULL, 1) ||
        !drive_nn(&other, &other_index) || !activate(&other, other_index)) {
        close_session(&other);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(dmp_endpoint_bind(&left.endpoint, other.initiator, other_index) == DMP_OK);
    CHECK(dmp_endpoint_bind(&right.endpoint, other.responder, 0U) == DMP_OK);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n == 1);
    CHECK(right.wire.q[0].len <= sizeof stolen);
    memcpy(stolen, right.wire.q[0].frame, right.wire.q[0].len);
    stolen_len = right.wire.q[0].len;
    close_session(&other);
    if (!make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    status = dmp_endpoint_rx(&left.endpoint, span(stolen, stolen_len), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(left.app.accepts == 0);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    close_session(&env);
    return 0;
}

static int test_reassembly(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    session other;
    port_ctx port;
    port_ctx other_port;
    uint32_t index = 0U;
    uint32_t other_index = 0U;
    uint8_t body[FRAG_BYTES];
    uint8_t stolen[FRAME_CAP];
    size_t stolen_len = 0U;
    uint8_t conflict_bytes[FRAG_CHUNK];
    uint8_t ext[3];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    uint8_t core[MTU];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    size_t core_n = 0U;
    dmp_frame_spec spec;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_parse_result parsed;
    dmp_time_ms now = 20000U;
    dmp_status status = DMP_OK;
    int i;
    size_t n;
    memset(&env, 0, sizeof env);
    memset(&other, 0, sizeof other);
    if (fixture == NULL || !make_pair(&other, &other_port, fixture, tune_alt, NULL, 1) ||
        !drive_nn(&other, &other_index) || !activate(&other, other_index)) {
        close_session(&other);
        return 1;
    }
    CHECK(boot_node(&left, 1, FRAG_CHUNK, 32U, now) == 0);
    CHECK(dmp_endpoint_bind(&left.endpoint, other.initiator, other_index) == DMP_OK);
    for (n = 0U; n < sizeof body; n++) {
        body[n] = (uint8_t)(0x40U + (uint8_t)(n & 0x0fU));
    }
    left.wire.now = now;
    CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(body, sizeof body), now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n >= 1);
    CHECK(left.wire.q[0].len <= sizeof stolen);
    memcpy(stolen, left.wire.q[0].frame, left.wire.q[0].len);
    stolen_len = left.wire.q[0].len;
    close_session(&other);
    if (!make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, FRAG_CHUNK, 32U, now) == 0);
    CHECK(boot_node(&right, 0, FRAG_CHUNK, 32U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    for (n = 0U; n < sizeof body; n++) {
        body[n] = (uint8_t)(0x40U + (uint8_t)(n & 0x0fU));
    }
    memset(conflict_bytes, 0xff, sizeof conflict_bytes);
    left.wire.now = now;
    CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(body, sizeof body), now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n >= 2);
    status = dmp_endpoint_rx(&right.endpoint, span(stolen, stolen_len), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.assembled == 0);
    CHECK(deliver_one(&left, &right, 0, now, &status) == 0);
    CHECK(status == DMP_INCOMPLETE);
    CHECK(unwrap_core(left.wire.q[0].frame, left.wire.q[0].len, core, sizeof core, &core_n, now) == 1);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    parsed = dmp_core_parse(span(core, core_n), &limits, &view);
    CHECK(parsed.status == DMP_OK);
    ext[0] = 17U;
    ext[1] = 1U;
    ext[2] = 2U;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_DATA;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_FRAG | DMP_OPT_EXT);
    spec.fields.seq = view.fields.seq;
    spec.fields.fragment.index = 0U;
    spec.fields.fragment.chunk_size = FRAG_CHUNK;
    spec.fields.fragment.total_size = FRAG_BYTES;
    spec.extensions = span(ext, sizeof ext);
    spec.payload = span(conflict_bytes, sizeof conflict_bytes);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_MALFORMED);
    CHECK(right.app.assembled == 0);
    for (i = left.wire.n - 1; i >= 1; i--) {
        CHECK(deliver_one(&left, &right, i, now, &status) == 0);
        CHECK(status == DMP_OK || status == DMP_INCOMPLETE || status == DMP_DUPLICATE);
    }
    CHECK(right.app.assembled == 1);
    CHECK(right.app.body_n == sizeof body);
    CHECK(memcmp(right.app.body, body, sizeof body) == 0);
    close_session(&env);
    return 0;
}

static int test_ttl(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t payload[2] = {0x11, 0x22};
    uint8_t ext[16];
    uint8_t sealed[MTU];
    uint8_t ttl_only[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t ext_n = 0U;
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    size_t at;
    unsigned b;
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    dmp_frame_spec spec;
    dmp_time_ms now = 20000U;
    dmp_status status;
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_hs_epochs(env.initiator, index, &epoch_i, &epoch_r) == 1);
    (void)epoch_r;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_TELEM;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ROUTE);
    spec.fields.seq = 1U;
    spec.fields.route.mode = 1U;
    spec.fields.route.ttl = 4U;
    spec.fields.route.source = ID_INIT;
    spec.fields.route.destination = ID_RESP;
    spec.payload = span(payload, sizeof payload);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_CONTEXT_REQUIRED);
    CHECK(right.app.telems == 0);
    ext[ext_n++] = 11U;
    ext[ext_n++] = 9U;
    ext[ext_n++] = 1U;
    for (b = 0U; b < 8U; b++) {
        ext[ext_n++] = (uint8_t)(epoch_i >> (8U * b));
    }
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ROUTE | DMP_OPT_EXT);
    spec.fields.seq = 2U;
    spec.extensions = span(ext, ext_n);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(sealed_n > 4U);
    memcpy(ttl_only, sealed, sealed_n);
    at = 3U;
    while (at < sealed_n && (ttl_only[at] & 0x80U) != 0U) {
        at++;
    }
    at++;
    CHECK(at + 2U < sealed_n);
    ttl_only[at + 2U] ^= 0x01U;
    CHECK(wrap_core(ttl_only, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.telems == 0);
    ttl_only[at + 2U] ^= 0x01U;
    ttl_only[at] = (uint8_t)((9U << 4) | (ttl_only[at] & 0x0fU));
    CHECK(wrap_core(ttl_only, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.telems == 1);
    close_session(&env);
    return 0;
}

static int offer_indexed(dmp_hs *hs, const uint8_t *payload, size_t length, uint32_t origin,
                         uint32_t destination, uint32_t seq, uint64_t epoch, dmp_hs_status expected,
                         uint32_t *index_out)
{
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    dmp_hs_status status;

    memset(&ingress, 0, sizeof ingress);
    memset(&completion, 0, sizeof completion);
    ingress.payload = payload;
    ingress.payload_len = length;
    ingress.origin_id = origin;
    ingress.destination_id = destination;
    ingress.namespace_id = LOCAL_NS;
    ingress.context_epoch = epoch;
    ingress.seq = seq;
    status = dmp_hs_offer(hs, &ingress, &completion);
    if (status == DMP_HS_AWAITING) {
        if (index_out != NULL) {
            *index_out = completion.attempt_index;
        }
        status = dmp_hs_accept(hs, &completion);
    }
    return status == expected;
}

static int drive_rotation(session *env, const noise_fixture_probe_fixture_t *fixture,
                          uint32_t *init_index, uint32_t *resp_index, uint8_t salt)
{
    const uint8_t *cached;
    size_t length = 0U;
    uint64_t boot;

    memcpy(env->rot_id, fixture->attempt_id.data, 16U);
    env->rot_id[0] ^= salt;
    memcpy(env->rot_init_eph, fixture->init_ephemeral.data, 32U);
    memcpy(env->rot_resp_eph, fixture->resp_ephemeral.data, 32U);
    /* A new attempt id is not a new ephemeral. Flip an unclamped scalar byte. */
    env->rot_init_eph[8] ^= salt;
    env->rot_resp_eph[8] ^= salt;
    script_add(&env->init_script, env->rot_id, sizeof env->rot_id);
    script_add(&env->init_script, env->rot_init_eph, sizeof env->rot_init_eph);
    script_add(&env->resp_script, env->rot_resp_eph, sizeof env->rot_resp_eph);
    if (dmp_hs_schedule(env->initiator, init_index) != DMP_HS_OK) {
        return 0;
    }
    boot = dmp_hs_boot_epoch(env->initiator, *init_index);
    cached = dmp_hs_cached_flight(env->initiator, *init_index, &length);
    if (cached == NULL ||
        !offer_indexed(env->responder, cached, length, ID_INIT, ID_RESP, 1U, boot, DMP_HS_CANDIDATE,
                       resp_index)) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->responder, *resp_index, &length);
    return cached != NULL &&
           offer_indexed(env->initiator, cached, length, ID_RESP, ID_INIT, 2U, boot, DMP_HS_CANDIDATE,
                         NULL);
}

static int activate_at(session *env, uint32_t init_index, uint32_t resp_index)
{
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    const uint8_t *frame;
    size_t length = 0U;

    if (!dmp_hs_epochs(env->initiator, init_index, &epoch_i, &epoch_r)) {
        return 0;
    }
    if (dmp_hs_confirm(env->initiator, init_index) != DMP_HS_OK) {
        return 0;
    }
    frame = dmp_hs_protected_frame(env->initiator, init_index, &length);
    if (frame == NULL || !offer_protected(env->responder, frame, length, ID_INIT, ID_RESP, epoch_i)) {
        return 0;
    }
    frame = dmp_hs_protected_frame(env->responder, resp_index, &length);
    if (frame == NULL || !offer_protected(env->initiator, frame, length, ID_RESP, ID_INIT, epoch_r)) {
        return 0;
    }
    return dmp_hs_send_application(env->initiator, init_index) == DMP_HS_OK &&
           dmp_hs_send_application(env->responder, resp_index) == DMP_HS_OK;
}

static int stream_protection(const uint8_t *framed, size_t n, dmp_time_ms now, uint32_t *cid,
                             uint64_t *pn, uint8_t *type_out)
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
    if (parsed.status != DMP_OK || (view.fields.options & DMP_OPT_SECURITY) == 0U) {
        return 0;
    }
    if (cid != NULL) {
        *cid = view.fields.security.receive_cid;
    }
    if (pn != NULL) {
        *pn = view.fields.security.pn;
    }
    if (type_out != NULL) {
        *type_out = view.fields.type;
    }
    return 1;
}

static int protected_err_status(const uint8_t *framed, size_t n, dmp_time_ms now, uint32_t *status_out)
{
    uint8_t core[MTU];
    size_t core_n = 0U;
    size_t cursor = 0U;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_parse_result parsed;
    int found = 0;
    uint32_t wire = 0U;

    if (!unwrap_core(framed, n, core, sizeof core, &core_n, now) || status_out == NULL) {
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
    while (cursor < view.extensions.size) {
        dmp_extension_view ext;
        size_t at = 0U;
        uint32_t value = 0U;
        dmp_status step = dmp_extension_next(view.extensions, &cursor, &ext);
        if (step == DMP_INCOMPLETE) {
            break;
        }
        if (step != DMP_OK) {
            return 0;
        }
        if ((ext.tag >> 2) != 5U) {
            continue;
        }
        if (found != 0 || (ext.tag & 3U) != 1U || ext.value.size == 0U || ext.value.data == NULL) {
            return 0;
        }
        while (at < ext.value.size) {
            uint8_t byte = ext.value.data[at++];
            value = (value << 7) | (uint32_t)(byte & 0x7fU);
            if ((byte & 0x80U) == 0U) {
                break;
            }
        }
        wire = value;
        found = 1;
    }
    if (found == 0) {
        return 0;
    }
    *status_out = wire;
    return 1;
}

static int test_acl(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_endpoint_grant control_only[1];
    dmp_frame_spec spec;
    uint32_t index = 0U;
    uint32_t cid = 0U;
    uint8_t req[1];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    uint8_t type = 0U;
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    dmp_status status;
    int accepts_before;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    sample1_read_req(req);
    /* Node 10 may produce and answer. It may not issue READ. */
    CHECK(dmp_endpoint_submit_req(&left.endpoint, 1U, span(req, 1U), now, &handle) ==
          DMP_UNSUPPORTED);
    CHECK(left.wire.n == 0);
    CHECK(right.app.accepts == 0);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);

    memset(control_only, 0, sizeof control_only);
    control_only[0].principal = ID_INIT;
    control_only[0].service_id = 0U;
    control_only[0].permit = DMP_ENDPOINT_PERMIT_CONTROL;
    CHECK(dmp_endpoint_set_grants(&right.endpoint, control_only, 1U) == DMP_OK);
    accepts_before = right.app.accepts;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ);
    spec.fields.seq = 40U;
    spec.payload = span(req, 1U);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == accepts_before);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n >= 1);
    CHECK(stream_protection(right.wire.q[right.wire.n - 1].frame, right.wire.q[right.wire.n - 1].len, now,
                            &cid, NULL, &type) == 1);
    CHECK(type == (uint8_t)DMP_TYPE_ERR);
    {
        uint32_t wire_status = 0U;
        CHECK(protected_err_status(right.wire.q[right.wire.n - 1].frame,
                                   right.wire.q[right.wire.n - 1].len, now, &wire_status) == 1);
        CHECK(wire_status == 6U);
    }
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == accepts_before);
    close_session(&env);
    return 0;
}

static int test_rotation(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint32_t next_init = 0U;
    uint32_t next_resp = 0U;
    uint32_t old_cid = 0U;
    uint32_t new_cid = 0U;
    uint8_t req[1];
    uint8_t saved[FRAME_CAP];
    size_t saved_len = 0U;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    int accepts;

    /* One identity slot cannot overlap. The live association stays. */
    memset(&env, 0, sizeof env);
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_rotate(&left.endpoint, index, now) == DMP_BUSY);
    if (!drive_rotation(&env, fixture, &next_init, &next_resp, 0x5aU) ||
        !activate_at(&env, next_init, next_resp)) {
        close_session(&env);
        return 1;
    }
    CHECK(dmp_endpoint_rotate(&left.endpoint, next_init, now) == DMP_QUOTA_EXHAUSTED);
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_QUOTA_EXHAUSTED);
    CHECK(left.endpoint.drain_live == 0U);
    CHECK(right.endpoint.drain_live == 0U);
    CHECK(dmp_hs_send_application(env.initiator, index) == DMP_HS_OK);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 6) == 0);
    CHECK(left.app.accepts == 1);
    close_session(&env);

    /* Overlap: new messages wait for activation, then stay off the old association. */
    memset(&env, 0, sizeof env);
    if (!make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node_slots(&left, 1, 64U, 16U, now, 2U) == 0);
    CHECK(boot_node_slots(&right, 0, 64U, 16U, now, 2U) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_set_drain_ms(&left.endpoint, 30000U) == DMP_OK);
    CHECK(dmp_endpoint_set_drain_ms(&right.endpoint, 30000U) == DMP_OK);
    sample1_read_req(req);
    right.wire.drop_remaining = 1;
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.saved_len > 0U);
    memcpy(saved, right.wire.saved, right.wire.saved_len);
    saved_len = right.wire.saved_len;
    CHECK(stream_protection(saved, saved_len, now, &old_cid, NULL, NULL) == 1);
    if (!drive_rotation(&env, fixture, &next_init, &next_resp, 0x5aU)) {
        close_session(&env);
        return 1;
    }
    /* FINISH is sealed and READY is not delivered, so the new attempt is not active. */
    CHECK(dmp_hs_confirm(env.initiator, next_init) == DMP_HS_OK);
    CHECK(dmp_endpoint_rotate(&left.endpoint, next_init, now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(dmp_hs_send_application(env.initiator, index) == DMP_HS_OK);
    {
        uint64_t epoch_i = 0U;
        uint64_t epoch_r = 0U;
        const uint8_t *frame;
        size_t length = 0U;
        CHECK(dmp_hs_epochs(env.initiator, next_init, &epoch_i, &epoch_r) == 1);
        frame = dmp_hs_protected_frame(env.initiator, next_init, &length);
        CHECK(frame != NULL);
        CHECK(offer_protected(env.responder, frame, length, ID_INIT, ID_RESP, epoch_i) == 1);
        frame = dmp_hs_protected_frame(env.responder, next_resp, &length);
        CHECK(frame != NULL);
        CHECK(offer_protected(env.initiator, frame, length, ID_RESP, ID_INIT, epoch_r) == 1);
    }
    CHECK(dmp_hs_send_application(env.initiator, next_init) == DMP_HS_OK);
    CHECK(dmp_endpoint_rotate(&left.endpoint, next_init, now) == DMP_OK);
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_OK);
    CHECK(right.app.unknowns == 0);
    CHECK(pump(now + 1280U, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    accepts = left.app.accepts;
    {
        dmp_time_ms later = now + 1280U;
        dmp_status replay = dmp_endpoint_rx(&left.endpoint, span(saved, saved_len), later);
        CHECK(replay == DMP_OK || replay == DMP_DUPLICATE);
        CHECK(left.app.accepts == accepts);
        right.wire.n = 0;
        CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), later, &handle) == DMP_OK);
        right.wire.now = later;
        CHECK(dmp_endpoint_poll(&right.endpoint, later) == DMP_OK);
        CHECK(right.wire.n >= 1);
        CHECK(stream_protection(right.wire.q[0].frame, right.wire.q[0].len, later, &new_cid, NULL,
                                NULL) == 1);
        CHECK(new_cid != old_cid);
        CHECK(pump(later, 6) == 0);
        CHECK(left.app.accepts == accepts + 1);
    }

    now = 20000U + 30000U;
    left.wire.now = now;
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(dmp_hs_send_application(env.initiator, index) != DMP_HS_OK);
    accepts = left.app.accepts;
    CHECK(dmp_endpoint_rx(&left.endpoint, span(saved, saved_len), now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(left.app.accepts == accepts);

    /* A request that cannot finish inside the drain bound is unknown, not moved. */
    close_session(&env);
    memset(&env, 0, sizeof env);
    now = 20000U;
    if (!make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node_slots(&left, 1, 64U, 16U, now, 2U) == 0);
    CHECK(boot_node_slots(&right, 0, 64U, 16U, now, 2U) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_set_drain_ms(&right.endpoint, 1000U) == DMP_OK);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(stream_protection(right.wire.q[0].frame, right.wire.q[0].len, now, &old_cid, NULL, NULL) == 1);
    if (!drive_rotation(&env, fixture, &next_init, &next_resp, 0x5aU) || !activate_at(&env, next_init, next_resp)) {
        close_session(&env);
        return 1;
    }
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_OK);
    CHECK(right.app.unknowns == 1);
    CHECK(left.app.accepts == 0);
    right.wire.n = 0;
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n >= 1);
    CHECK(stream_protection(right.wire.q[0].frame, right.wire.q[0].len, now, &new_cid, NULL, NULL) == 1);
    CHECK(new_cid != old_cid);

    /* A short unauthenticated buffer is not a revoke command. */
    CHECK(dmp_endpoint_rx(&right.endpoint, span(req, 1U), now) == DMP_OK);
    CHECK(dmp_hs_send_application(env.responder, next_resp) == DMP_HS_OK);
    CHECK(dmp_endpoint_revoke(&right.endpoint, now) == DMP_OK);
    CHECK(right.app.unknowns >= 1);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) ==
          DMP_AUTHENTICATION_FAILURE);
    CHECK(dmp_hs_send_application(env.responder, next_resp) != DMP_HS_OK);
    close_session(&env);
    return 0;
}

static int test_result_permit(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_endpoint_grant grants[2];
    uint32_t index = 0U;
    uint8_t req[1];
    uint8_t payload[SAMPLE1_READ_BYTES];
    size_t n;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    dmp_status status = DMP_OK;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    memset(grants, 0, sizeof grants);
    grants[0].principal = ID_INIT;
    grants[0].service_id = 1U;
    grants[0].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[1].principal = ID_RESP;
    grants[1].service_id = 1U;
    grants[1].permit = DMP_ENDPOINT_PERMIT_REQ;
    CHECK(dmp_endpoint_set_grants(&left.endpoint, grants, 2U) == DMP_OK);
    CHECK(dmp_endpoint_set_grants(&right.endpoint, grants, 2U) == DMP_OK);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_one(&right, &left, 0, now, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(left.app.accepts == 1);
    CHECK(left.wire.n == 0);
    n = sample1_read_rsp(payload, 1U, 2U, 300U);
    CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, false, 0U, span(payload, n), now) ==
          DMP_UNSUPPORTED);
    CHECK(left.wire.n == 0);
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 0);
    close_session(&env);
    return 0;
}

static int test_frag_deny(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_endpoint_grant control_only[1];
    dmp_frame_spec spec;
    uint32_t index = 0U;
    uint32_t cid = 0U;
    uint8_t body[16];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    uint8_t type = 0U;
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    dmp_time_ms now = 20000U;
    dmp_status status;
    int accepts_before;
    size_t i;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    memset(control_only, 0, sizeof control_only);
    control_only[0].principal = ID_INIT;
    control_only[0].service_id = 0U;
    control_only[0].permit = DMP_ENDPOINT_PERMIT_CONTROL;
    CHECK(dmp_endpoint_set_grants(&right.endpoint, control_only, 1U) == DMP_OK);
    accepts_before = right.app.accepts;
    for (i = 0U; i < sizeof body; i++) {
        body[i] = (uint8_t)(0x30U + (uint8_t)i);
    }
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_FRAG);
    spec.fields.seq = 41U;
    spec.fields.fragment.index = 0U;
    spec.fields.fragment.chunk_size = 16U;
    spec.fields.fragment.total_size = 32U;
    spec.payload = span(body, sizeof body);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    right.wire.n = 0;
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == accepts_before);
    CHECK(right.app.assembled == 0);
    CHECK(right.assemblies[0].live == 0U);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n >= 1);
    CHECK(stream_protection(right.wire.q[right.wire.n - 1].frame, right.wire.q[right.wire.n - 1].len, now,
                            &cid, NULL, &type) == 1);
    CHECK(type == (uint8_t)DMP_TYPE_ERR);
    {
        uint32_t wire_status = 0U;
        CHECK(protected_err_status(right.wire.q[right.wire.n - 1].frame,
                                   right.wire.q[right.wire.n - 1].len, now, &wire_status) == 1);
        CHECK(wire_status == 6U);
    }
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == accepts_before);
    CHECK(right.assemblies[0].live == 0U);
    close_session(&env);
    return 0;
}

static void tune_pending(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    initiator->budget.max_pending = 3U;
    initiator->budget.episode_attempts = 4U;
    responder->budget.max_pending = 3U;
    responder->budget.episode_attempts = 4U;
}

static int test_drain_retain(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_frame_spec spec;
    dmp_identity_slot *draining;
    uint32_t index = 0U;
    uint32_t next_init = 0U;
    uint32_t next_resp = 0U;
    uint32_t later_init = 0U;
    uint32_t later_resp = 0U;
    uint8_t body[16];
    uint8_t ext[3];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    size_t i;
    dmp_time_ms now = 20000U;
    dmp_time_ms accept_at;
    dmp_time_ms drain_at;
    dmp_time_ms assembly_at;
    dmp_status status = DMP_OK;

    memset(&env, 0, sizeof env);
    if (fixture == NULL || !make_pair(&env, &port, fixture, tune_pending, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node_slots(&right, 0, 64U, 16U, now, 2U) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_set_drain_ms(&right.endpoint, 1000U) == DMP_OK);
    CHECK(right.endpoint.profile.assembly_ms > 1000U);
    if (!drive_rotation(&env, fixture, &next_init, &next_resp, 0x5aU) ||
        !activate_at(&env, next_init, next_resp)) {
        close_session(&env);
        return 1;
    }
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_OK);
    CHECK(right.endpoint.drain_live == 1U);
    CHECK(right.endpoint.drain_attempt == index);
    drain_at = right.endpoint.drain_not_after;
    accept_at = drain_at - 100U;
    assembly_at = accept_at + right.endpoint.profile.assembly_ms;
    CHECK(accept_at < drain_at);
    CHECK(drain_at < assembly_at);
    for (i = 0U; i < sizeof body; i++) {
        body[i] = 0x21U;
    }
    ext[0] = 17U;
    ext[1] = 1U;
    ext[2] = 2U;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_DATA;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_FRAG | DMP_OPT_EXT);
    spec.fields.seq = 8U;
    spec.fields.fragment.index = 0U;
    spec.fields.fragment.chunk_size = 16U;
    spec.fields.fragment.total_size = 32U;
    spec.extensions = span(ext, sizeof ext);
    spec.payload = span(body, sizeof body);
    env.now = accept_at;
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), accept_at);
    CHECK(status == DMP_INCOMPLETE);
    CHECK(right.app.assembled == 0);
    CHECK(right.app.accepts == 0);
    note_provider("drain-overlap", &port, env.provider);
    CHECK(dmp_endpoint_poll(&right.endpoint, drain_at) == DMP_OK);
    draining = &right.endpoint.identity.slots[right.endpoint.drain_context.slot];
    CHECK(right.endpoint.drain_live == 1U);
    CHECK(draining->state == DMP_IDENTITY_SLOT_DRAINING);
    CHECK(draining->retained != 0U);
    CHECK(dmp_endpoint_poll(&right.endpoint, assembly_at) == DMP_OK);
    CHECK(right.endpoint.drain_live == 0U);
    CHECK(draining->state == DMP_IDENTITY_SLOT_UNUSED);
    if (!drive_rotation(&env, fixture, &later_init, &later_resp, 0xa5U) ||
        !activate_at(&env, later_init, later_resp)) {
        close_session(&env);
        return 1;
    }
    env.now = assembly_at;
    CHECK(dmp_endpoint_rotate(&right.endpoint, later_resp, assembly_at) == DMP_OK);
    CHECK(right.endpoint.drain_live == 1U);
    close_session(&env);
    return 0;
}

static int drive_nn_save(session *env, uint32_t *index, uint8_t *saved, size_t cap, size_t *saved_n)
{
    const uint8_t *cached;
    size_t length = 0U;
    uint64_t boot;

    if (dmp_hs_schedule(env->initiator, index) != DMP_HS_OK) {
        return 0;
    }
    boot = dmp_hs_boot_epoch(env->initiator, *index);
    if (boot == 0U) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->initiator, *index, &length);
    if (cached == NULL || length == 0U || length > cap) {
        return 0;
    }
    memcpy(saved, cached, length);
    *saved_n = length;
    if (!drive_flight(env->responder, saved, length, ID_INIT, ID_RESP, 1U, boot, DMP_HS_CANDIDATE)) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->responder, 0U, &length);
    return cached != NULL &&
           drive_flight(env->initiator, cached, length, ID_RESP, ID_INIT, 2U, boot, DMP_HS_CANDIDATE);
}

static int reopen_hs(session *env, const noise_fixture_probe_fixture_t *fixture, uint32_t init_cid,
                     uint32_t resp_cid)
{
    dmp_hs_config init_config;
    dmp_hs_config resp_config;
    dmp_hs_ports init_ports;
    dmp_hs_ports resp_ports;

    dmp_hs_cleanup(env->initiator);
    dmp_hs_cleanup(env->responder);
    fill_hs(&init_config, fixture, 1);
    fill_hs(&resp_config, fixture, 0);
    init_config.next_rx_cid = init_cid;
    resp_config.next_rx_cid = resp_cid;
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
        return 0;
    }
    return 1;
}

static int test_context(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_frame_spec spec;
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    uint32_t index = 0U;
    uint32_t fresh = 0U;
    uint32_t old_cid = 0U;
    uint32_t init_cid = 0U;
    uint64_t old_epoch_i = 0U;
    uint64_t old_epoch_r = 0U;
    uint64_t new_epoch_i = 0U;
    uint64_t new_epoch_r = 0U;
    uint64_t boot = 0U;
    uint8_t bootstrap[512];
    uint8_t replay_eph[32];
    uint8_t payload[2] = {0x41, 0x42};
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    uint8_t fresh_wrapped[FRAME_CAP];
    size_t boot_n = 0U;
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    size_t fresh_n = 0U;
    dmp_time_ms now = 20000U;
    dmp_status status;

    memset(&env, 0, sizeof env);
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn_save(&env, &index, bootstrap, sizeof bootstrap, &boot_n) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_hs_epochs(env.initiator, index, &old_epoch_i, &old_epoch_r) == 1);
    old_cid = dmp_hs_rx_cid(env.responder, 0U);
    init_cid = dmp_hs_rx_cid(env.initiator, index);
    boot = dmp_hs_boot_epoch(env.initiator, index);
    CHECK(old_cid != 0U);
    CHECK(boot != 0U);
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_TELEM;
    spec.fields.options = (uint8_t)DMP_OPT_SEQ;
    spec.fields.seq = 4U;
    spec.payload = span(payload, sizeof payload);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.telems == 1);
    note_provider("active-pair", &port, env.provider);
    CHECK(dmp_hs_cancel(env.initiator, index) == DMP_HS_OK);
    CHECK(dmp_hs_cancel(env.responder, 0U) == DMP_HS_OK);
    CHECK(dmp_hs_secrets_wiped(env.initiator, index) == 1);
    CHECK(dmp_hs_secrets_wiped(env.responder, 0U) == 1);
    CHECK(dmp_hs_send_application(env.initiator, index) != DMP_HS_OK);
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.telems == 1);
    if (!reopen_hs(&env, fixture, init_cid, old_cid)) {
        close_session(&env);
        return 1;
    }
    memcpy(replay_eph, fixture->resp_ephemeral.data, sizeof replay_eph);
    replay_eph[8] ^= 0x3cU;
    script_add(&env.resp_script, replay_eph, sizeof replay_eph);
    memset(&ingress, 0, sizeof ingress);
    memset(&completion, 0, sizeof completion);
    ingress.payload = bootstrap;
    ingress.payload_len = boot_n;
    ingress.origin_id = ID_INIT;
    ingress.destination_id = ID_RESP;
    ingress.namespace_id = LOCAL_NS;
    ingress.context_epoch = boot;
    ingress.seq = 1U;
    {
        dmp_hs_status offered = dmp_hs_offer(env.responder, &ingress, &completion);
        if (offered == DMP_HS_AWAITING) {
            offered = dmp_hs_accept(env.responder, &completion);
        }
        (void)offered;
    }
    CHECK(dmp_hs_send_application(env.initiator, index) != DMP_HS_OK);
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.telems == 1);
    memcpy(env.rot_id, fixture->attempt_id.data, 16U);
    env.rot_id[0] ^= 0x11U;
    memcpy(env.rot_init_eph, fixture->init_ephemeral.data, 32U);
    memcpy(env.rot_resp_eph, fixture->resp_ephemeral.data, 32U);
    env.rot_init_eph[8] ^= 0x11U;
    env.rot_resp_eph[8] ^= 0x11U;
    script_add(&env.init_script, env.rot_id, sizeof env.rot_id);
    script_add(&env.init_script, env.rot_init_eph, sizeof env.rot_init_eph);
    script_add(&env.resp_script, env.rot_resp_eph, sizeof env.rot_resp_eph);
    if (!reopen_hs(&env, fixture, init_cid, old_cid) || !drive_nn(&env, &fresh) || !activate(&env, fresh)) {
        close_session(&env);
        return 1;
    }
    CHECK(dmp_hs_rx_cid(env.responder, 0U) == old_cid);
    CHECK(dmp_hs_epochs(env.initiator, fresh, &new_epoch_i, &new_epoch_r) == 1);
    CHECK(new_epoch_i != old_epoch_i);
    CHECK(new_epoch_r != old_epoch_r);
    CHECK(dmp_endpoint_bind(&left.endpoint, env.initiator, fresh) == DMP_OK);
    CHECK(dmp_endpoint_bind(&right.endpoint, env.responder, 0U) == DMP_OK);
    spec.fields.seq = 5U;
    CHECK(dmp_hs_seal_logical(env.initiator, fresh, &spec, sealed, sizeof sealed, &sealed_n) == DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, fresh_wrapped, sizeof fresh_wrapped, &fresh_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(fresh_wrapped, fresh_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.telems == 2);
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.telems == 2);
    close_session(&env);
    return 0;
}

static int test_selective_repair(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t body[256];
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    uint32_t frag_index = 0U;
    uint64_t tail_pn = 0U;
    uint64_t repair_pn = 0U;
    int tail = -1;
    int i;
    int repair;
    dmp_status status = DMP_OK;
    size_t n;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_selective(&left, 1, 32U, 16U, now) == 0);
    CHECK(boot_selective(&right, 0, 32U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    for (n = 0U; n < sizeof body; n++) {
        body[n] = (uint8_t)(0x40U + (uint8_t)n);
    }
    right.wire.now = now;
    left.wire.now = now;
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n == 8);
    for (i = 0; i < right.wire.n; i++) {
        CHECK(stream_fragment(right.wire.q[i].frame, right.wire.q[i].len, now, &frag_index, &tail_pn) ==
              1);
        if (frag_index == 7U) {
            tail = i;
        } else {
            CHECK(deliver_one(&right, &left, i, now, &status) == 0);
            CHECK(status == DMP_INCOMPLETE);
        }
    }
    CHECK(tail >= 0);
    CHECK(status == DMP_INCOMPLETE);
    CHECK(left.app.assembled == 0);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 0);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 3U) == DMP_OK);
    CHECK(left.wire.n == 1);
    CHECK(deliver_one(&left, &right, 0, now + 3U, &status) == 0);
    CHECK(status == DMP_OK);
    repair = right.wire.n;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 3U) == DMP_OK);
    CHECK(right.wire.n == repair + 1);
    CHECK(stream_fragment(right.wire.q[repair].frame, right.wire.q[repair].len, now + 3U, &frag_index,
                          &repair_pn) == 1);
    CHECK(frag_index == 7U);
    CHECK(repair_pn != tail_pn);
    CHECK(right.wire.q[repair].len != right.wire.q[tail].len ||
          memcmp(right.wire.q[repair].frame, right.wire.q[tail].frame, right.wire.q[tail].len) != 0);
    CHECK(deliver_one(&right, &left, repair, now + 3U, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(left.app.assembled == 1);
    CHECK(left.app.body_n == sizeof body);
    CHECK(memcmp(left.app.body, body, sizeof body) == 0);
    CHECK(deliver_one(&right, &left, repair, now + 3U, &status) == 0);
    CHECK(left.app.assembled == 1);
    close_session(&env);
    return 0;
}

int main(int argc, char **argv)
{
    const char *name = argc > 1 ? argv[1] : "all";
    int failed = 0;
    if (strcmp(name, "activation") == 0 || strcmp(name, "all") == 0) {
        failed |= test_activation();
    }
    if (strcmp(name, "alter") == 0 || strcmp(name, "all") == 0) {
        failed |= test_alter();
    }
    if (strcmp(name, "loss") == 0 || strcmp(name, "all") == 0) {
        failed |= test_loss();
    }
    if (strcmp(name, "isolate") == 0 || strcmp(name, "all") == 0) {
        failed |= test_isolate();
    }
    if (strcmp(name, "reassembly") == 0 || strcmp(name, "all") == 0) {
        failed |= test_reassembly();
    }
    if (strcmp(name, "ttl") == 0 || strcmp(name, "all") == 0) {
        failed |= test_ttl();
    }
    if (strcmp(name, "acl") == 0 || strcmp(name, "all") == 0) {
        failed |= test_acl();
    }
    if (strcmp(name, "rotation") == 0 || strcmp(name, "all") == 0) {
        failed |= test_rotation();
    }
    if (strcmp(name, "result") == 0 || strcmp(name, "all") == 0) {
        failed |= test_result_permit();
    }
    if (strcmp(name, "fragdeny") == 0 || strcmp(name, "all") == 0) {
        failed |= test_frag_deny();
    }
    if (strcmp(name, "drain") == 0 || strcmp(name, "all") == 0) {
        failed |= test_drain_retain();
    }
    if (strcmp(name, "context") == 0 || strcmp(name, "all") == 0) {
        failed |= test_context();
    }
    if (strcmp(name, "repair") == 0 || strcmp(name, "all") == 0) {
        failed |= test_selective_repair();
    }
    if (strcmp(name, "activation") != 0 && strcmp(name, "alter") != 0 && strcmp(name, "loss") != 0 &&
        strcmp(name, "isolate") != 0 && strcmp(name, "reassembly") != 0 && strcmp(name, "ttl") != 0 &&
        strcmp(name, "acl") != 0 && strcmp(name, "rotation") != 0 && strcmp(name, "result") != 0 &&
        strcmp(name, "fragdeny") != 0 && strcmp(name, "drain") != 0 && strcmp(name, "context") != 0 &&
        strcmp(name, "repair") != 0 && strcmp(name, "all") != 0) {
        (void)fprintf(stderr, "unknown test %s\n", name);
        return 2;
    }
    return failed == 0 ? 0 : 1;
}
