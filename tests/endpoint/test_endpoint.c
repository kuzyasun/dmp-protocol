#include "dmp/endpoint.h"

#include "sample1.h"

#include <stdio.h>
#include <string.h>

/* Two libdmp endpoints on a host loopback. This is not physical-transport
 * evidence and not a SEC-1 run. SAMPLE-1 requires SEC-1; these plaintext
 * exchanges are provisional and must be repeated at P15. The test does not
 * reimplement retry, duplicate suppression, reassembly, or admission. */

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
    QUEUE = 16,
    FRAME_CAP = 512,
    BODY = 320,
    /* profiles/deployments/direct-nnpsk0.json sample budget. Not parsed here. */
    SAMPLE_INIT_ATTEMPTS = 1,
    SAMPLE_INIT_RETRY_MS = 5,
    SAMPLE_INIT_DEADLINE_MS = 12000,
    SAMPLE_NO_SAMPLE = 64
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
    int delay;
    int drop_remaining;
    int duplicate_next;
    int pending;
    dmp_time_ms now;
    dmp_tx_complete_fn complete;
    void *owner;
    dmp_tx_token token;
} wire;

typedef struct {
    int producer;
    int have_sample;
    uint64_t epoch;
    uint32_t index;
    uint32_t value;
    int hold_complete;
    int have_snapshot;
    uint64_t snap_epoch;
    uint32_t snap_index;
    uint32_t snap_value;
    int have_designated;
    dmp_reliability_handle designated;
    int have_association;
    dmp_message_origin association;
    uint64_t generation;
    uint64_t sync_generation;
    int have_cache;
    uint64_t cache_epoch;
    uint32_t cache_index;
    uint32_t cache_value;
    int init_used;
    int init_failed;
    int init_pending;
    int init_reads;
    int want_retry;
    dmp_time_ms retry_at;
    dmp_time_ms init_deadline;
    int no_samples;
    int invalid_results;
    int synchronized;
    int accepts;
    int results;
    int telems;
    int discarded;
    int violations;
    int rollbacks;
    int bad_result;
    uint32_t last_status;
    dmp_message_origin last_source;
    int assembled;
    int duplicates;
    int have_pending;
    dmp_reliability_handle pending;
    uint8_t req[32];
    size_t req_n;
    uint8_t result[64];
    size_t result_n;
    uint8_t telem[SAMPLE1_TELEM_BYTES];
    size_t telem_n;
    uint8_t body[MESSAGE];
    size_t body_n;
    uint32_t live_index;
    uint32_t live_value;
} app;

struct node {
    dmp_endpoint endpoint;
    dmp_transport transport;
    wire wire;
    app app;
    dmp_identity_slot ids[1];
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

static node left;
static node right;

static const uint8_t READ_RSP[SAMPLE1_READ_BYTES] = {
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2C, 0x01, 0x00,
    0x00};
static const uint8_t TELEM_CANON[SAMPLE1_TELEM_BYTES] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2C, 0x01, 0x00, 0x00};
static const uint8_t STATUS_RSP[SAMPLE1_STATUS_BYTES] = {0x02, 0x01};
/* SHA-256 of profiles/deployments/direct-nnpsk0.json. Admission copies this
 * opaque value and does not hash the file. */
static const uint8_t DIRECT_SHA[DMP_PROFILE_SHA256_BYTES] = {
    0x29, 0xcb, 0x7b, 0x91, 0xee, 0x0c, 0x26, 0x9b, 0xc1, 0x4a, 0xc4, 0x3e, 0x3a, 0x7c, 0x8f, 0xd8,
    0xbd, 0xcf, 0xe1, 0x1e, 0x9e, 0x05, 0x2e, 0x8b, 0xd9, 0xe6, 0xaf, 0x00, 0xfb, 0x89, 0xc3, 0xbf};

static dmp_bytes span(const void *data, size_t size)
{
    dmp_bytes bytes;
    bytes.data = (const uint8_t *)data;
    bytes.size = size;
    return bytes;
}

static void fill_direct(dmp_config *config)
{
    memset(config, 0, sizeof *config);
    memcpy(config->sha256, DIRECT_SHA, sizeof DIRECT_SHA);
    config->namespace_id = 1U;
    config->node_id[0] = 10U;
    config->node_id[1] = 20U;
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
    config->fragments = 16U;
    config->chunk_bytes = 64U;
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
}

static int same_request(dmp_reliability_handle left_handle, dmp_reliability_handle right_handle)
{
    return left_handle.slot == right_handle.slot && left_handle.generation == right_handle.generation;
}

static int same_origin(dmp_message_origin left_origin, dmp_message_origin right_origin)
{
    return left_origin.namespace_id == right_origin.namespace_id &&
           left_origin.origin_id == right_origin.origin_id &&
           left_origin.epoch == right_origin.epoch;
}

static int designated_request(const app *state, dmp_reliability_handle request)
{
    return state->have_designated && state->generation == state->sync_generation &&
           same_request(request, state->designated);
}

/* A2 step 3. The current tuple is association, initialization generation, and
 * the designated request. Association identity is the producer origin. */
static int designated_result(const app *state, dmp_reliability_handle request,
                             dmp_message_origin source)
{
    return designated_request(state, request) && state->have_association &&
           same_origin(source, state->association);
}

static void remember_cache(app *state)
{
    state->have_cache = 1;
    state->cache_epoch = state->epoch;
    state->cache_index = state->live_index;
    state->cache_value = state->live_value;
}

/* A2 step 3. A different epoch replaces the cache. The same epoch keeps the
 * greatest index: an older READ may finish synchronization and must not roll
 * the cached sample back. */
static void select_snapshot(app *state, uint64_t epoch, uint32_t index, uint32_t value)
{
    if (state->have_cache && epoch == state->cache_epoch) {
        if (index > state->cache_index) {
            state->cache_index = index;
            state->cache_value = value;
        }
    } else {
        state->cache_epoch = epoch;
        state->cache_index = index;
        state->cache_value = value;
        state->have_cache = 1;
    }
    state->epoch = state->cache_epoch;
    state->live_index = state->cache_index;
    state->live_value = state->cache_value;
    state->synchronized = 1;
}

static void note_read(app *state, uint64_t epoch, uint32_t index, uint32_t value, int designated)
{
    if (!state->synchronized) {
        /* A local initialization failure invalidates the designated READ. */
        if (!designated || state->init_failed) {
            return;
        }
        select_snapshot(state, epoch, index, value);
        return;
    }
    if (epoch != state->epoch) {
        state->violations++;
        return;
    }
    if (index <= state->live_index) {
        state->rollbacks++;
        return;
    }
    state->live_index = index;
    state->live_value = value;
    remember_cache(state);
}

static void on_notice(void *user, const dmp_endpoint_notice *notice)
{
    node *self = user;
    app *state = &self->app;
    if (notice->event == DMP_ENDPOINT_REQUEST) {
        state->accepts++;
        state->pending = notice->request;
        state->have_pending = 1;
        state->have_snapshot = 0;
        state->req_n = notice->payload.size < sizeof state->req ? notice->payload.size : 0U;
        if (state->req_n != 0U) {
            memcpy(state->req, notice->payload.data, state->req_n);
        }
        if (state->producer && state->have_sample && state->req_n == 1U &&
            state->req[0] == SAMPLE1_READ) {
            state->snap_epoch = state->epoch;
            state->snap_index = state->index;
            state->snap_value = state->value;
            state->have_snapshot = 1;
        }
        return;
    }
    if (notice->event == DMP_ENDPOINT_UNKNOWN) {
        if (!state->producer && designated_request(state, notice->request)) {
            state->init_pending = 1;
        }
        return;
    }
    if (notice->event == DMP_ENDPOINT_RESULT) {
        int init_match;
        state->results++;
        state->last_status = notice->wire_status;
        state->last_source = notice->source.origin;
        state->result_n = notice->payload.size < sizeof state->result ? notice->payload.size : 0U;
        if (state->result_n != 0U) {
            memcpy(state->result, notice->payload.data, state->result_n);
        }
        if (state->producer) {
            return;
        }
        init_match = designated_result(state, notice->request, notice->source.origin);
        if (notice->wire_status == SAMPLE_NO_SAMPLE && notice->payload.size == 0U) {
            if (init_match) {
                state->no_samples++;
                state->init_pending = 1;
            }
            return;
        }
        if (notice->wire_status == 0U && state->result_n == SAMPLE1_READ_BYTES &&
            state->result[0] == SAMPLE1_READ) {
            if (!state->synchronized && (state->init_failed || !init_match)) {
                return;
            }
            if (state->synchronized && state->have_association &&
                !same_origin(notice->source.origin, state->association)) {
                return;
            }
            note_read(state, sample1_load_u64(state->result + 1),
                      sample1_load_u32(state->result + 9),
                      sample1_load_u32(state->result + 13), init_match);
            return;
        }
        if (init_match) {
            state->invalid_results++;
        }
        return;
    }
    if (notice->event == DMP_ENDPOINT_TELEMETRY) {
        state->telems++;
        state->last_source = notice->source.origin;
        state->telem_n =
            notice->payload.size == SAMPLE1_TELEM_BYTES ? notice->payload.size : 0U;
        if (state->telem_n == 0U) {
            return;
        }
        memcpy(state->telem, notice->payload.data, state->telem_n);
        if (!state->synchronized) {
            state->discarded++;
            return;
        }
        if (state->have_association && !same_origin(notice->source.origin, state->association)) {
            return;
        }
        {
            uint64_t epoch = sample1_load_u64(state->telem);
            uint32_t index = sample1_load_u32(state->telem + 8);
            uint32_t value = sample1_load_u32(state->telem + 12);
            if (epoch != state->epoch) {
                state->violations++;
                return;
            }
            if (index <= state->live_index) {
                state->rollbacks++;
                return;
            }
            state->live_index = index;
            state->live_value = value;
            remember_cache(state);
        }
        return;
    }
    if (notice->event == DMP_ENDPOINT_ASSEMBLED) {
        state->assembled++;
        state->body_n = notice->payload.size <= sizeof state->body ? notice->payload.size : 0U;
        if (state->body_n != 0U) {
            memcpy(state->body, notice->payload.data, state->body_n);
        }
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
    if (link->drop_remaining > 0) {
        link->drop_remaining--;
        if (link->delay) {
            if (link->pending) {
                return DMP_BUSY;
            }
            link->pending = 1;
            link->complete = submission->complete;
            link->owner = submission->owner;
            link->token = submission->token;
            return DMP_OK;
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
    if (link->duplicate_next && link->n < QUEUE) {
        link->q[link->n] = link->q[link->n - 1];
        link->n++;
        link->duplicate_next = 0;
    }
    if (link->delay) {
        if (link->pending) {
            return DMP_BUSY;
        }
        link->pending = 1;
        link->complete = submission->complete;
        link->owner = submission->owner;
        link->token = submission->token;
        return DMP_OK;
    }
    submission->complete(submission->owner, submission->token, DMP_TX_TRANSMITTED, link->now);
    return DMP_OK;
}

static dmp_status wire_cancel(void *context, dmp_tx_token token)
{
    (void)context;
    (void)token;
    return DMP_OK;
}

static void wire_finish(wire *link, dmp_tx_outcome outcome)
{
    dmp_tx_complete_fn complete;
    void *owner;
    dmp_tx_token token;
    if (!link->pending) {
        return;
    }
    complete = link->complete;
    owner = link->owner;
    token = link->token;
    link->pending = 0;
    complete(owner, token, outcome, link->now);
}

static int boot(node *self, int producer, dmp_time_ms now)
{
    dmp_config input;
    dmp_admitted_profile admitted;
    dmp_endpoint_storage storage;
    dmp_identity_context_config identity;
    dmp_message_origin local;
    dmp_message_origin peer;
    memset(self, 0, sizeof *self);
    fill_direct(&input);
    CHECK(dmp_config_admit(&input, &admitted) == DMP_OK);
    memset(&local, 0, sizeof local);
    memset(&peer, 0, sizeof peer);
    local.namespace_id = 1U;
    peer.namespace_id = 1U;
    if (producer) {
        local.origin_id = 10U;
        local.epoch = 7U;
        peer.origin_id = 20U;
        peer.epoch = 9U;
    } else {
        local.origin_id = 20U;
        local.epoch = 9U;
        peer.origin_id = 10U;
        peer.epoch = 7U;
    }
    memset(&identity, 0, sizeof identity);
    identity.local = local;
    identity.peer = peer;
    identity.security = 0U;
    self->app.producer = producer;
    self->app.generation = 1U;
    self->app.sync_generation = 1U;
    self->app.init_deadline = now + SAMPLE_INIT_DEADLINE_MS;
    if (!producer) {
        self->app.have_association = 1;
        self->app.association.namespace_id = 1U;
        self->app.association.origin_id = 10U;
        self->app.association.epoch = 7U;
    }
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
    storage.identity_capacity = 1U;
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
    CHECK(sizeof(dmp_reassembly_tombstone) == 48U);
    CHECK(self->endpoint.profile.assembly_tombstone_slots == TOMBSTONES);
    CHECK(self->endpoint.profile.control_slots == 2U);
    CHECK(self->endpoint.profile.adapter_slots == 3U);
    return 0;
}

static int deliver(node *from, node *to, dmp_time_ms now, int limit)
{
    int count;
    int i;
    int processed = 0;
    count = from->wire.n;
    if (limit >= 0 && limit < count) {
        count = limit;
    }
    for (i = 0; i < count; i++) {
        dmp_status status;
        dmp_bytes bytes = span(from->wire.q[i].frame, from->wire.q[i].len);
        status = dmp_endpoint_rx(&to->endpoint, bytes, now);
        processed++;
        if (status == DMP_DUPLICATE) {
            to->app.duplicates++;
        }
        if (status != DMP_OK && status != DMP_INCOMPLETE && status != DMP_DUPLICATE) {
            from->wire.n -= processed;
            if (from->wire.n > 0) {
                memmove(&from->wire.q[0], &from->wire.q[processed],
                        (size_t)from->wire.n * sizeof from->wire.q[0]);
            }
            return status == DMP_QUOTA_EXHAUSTED ? 2 : 1;
        }
    }
    from->wire.n -= processed;
    if (from->wire.n > 0 && processed > 0) {
        memmove(&from->wire.q[0], &from->wire.q[processed],
                (size_t)from->wire.n * sizeof from->wire.q[0]);
    }
    return 0;
}

static int service(node *self, dmp_time_ms now)
{
    uint8_t payload[SAMPLE1_READ_BYTES];
    size_t n = 0U;
    dmp_status status;
    if (!self->app.producer || !self->app.have_pending) {
        return 0;
    }
    if (self->app.hold_complete) {
        return 0;
    }
    if (self->app.req_n == 1U && self->app.req[0] == SAMPLE1_READ) {
        dmp_bytes empty;
        if (self->app.bad_result) {
            payload[0] = 0x03U;
            status = dmp_endpoint_complete(&self->endpoint, self->app.pending, false, 0U,
                                           span(payload, 1U), now);
            CHECK(status == DMP_OK);
            self->app.have_pending = 0;
            return 0;
        }
        if (!self->app.have_snapshot) {
            empty.data = NULL;
            empty.size = 0U;
            status = dmp_endpoint_complete(&self->endpoint, self->app.pending, true,
                                           SAMPLE_NO_SAMPLE, empty, now);
            CHECK(status == DMP_OK);
            self->app.have_pending = 0;
            return 0;
        }
        n = sample1_read_rsp(payload, self->app.snap_epoch, self->app.snap_index,
                             self->app.snap_value);
    } else if (self->app.req_n == 1U && self->app.req[0] == SAMPLE1_STATUS) {
        n = sample1_status_rsp(payload, 1U);
    } else {
        return 1;
    }
    status = dmp_endpoint_complete(&self->endpoint, self->app.pending, false, 0U, span(payload, n),
                                   now);
    CHECK(status == DMP_OK);
    self->app.have_pending = 0;
    return 0;
}

/* A2 step 4. The consumer clock is init_deadline, not reliability's
 * result_deadline_ms. Reaching it, or exhausting attempts so the next READ
 * would start outside it, is a local initialization failure. */
static void fail_init(app *state)
{
    state->init_failed = 1;
    state->init_pending = 0;
    state->have_designated = 0;
    state->want_retry = 0;
}

static void observe_init_deadline(app *state, dmp_time_ms now)
{
    if (state->producer || state->synchronized || state->init_failed) {
        return;
    }
    if (!state->have_designated && !state->want_retry && !state->init_pending) {
        return;
    }
    if (now < state->init_deadline) {
        return;
    }
    fail_init(state);
}

static void close_init_attempt(app *state, dmp_time_ms now)
{
    dmp_time_ms retry_at = 0U;
    if (state->init_failed) {
        state->init_pending = 0;
        state->want_retry = 0;
        return;
    }
    if (!state->init_pending) {
        return;
    }
    state->init_pending = 0;
    state->have_designated = 0;
    state->init_used++;
    if ((uint32_t)state->init_used < (uint32_t)SAMPLE_INIT_ATTEMPTS &&
        dmp_deadline_after(now, (uint64_t)SAMPLE_INIT_RETRY_MS, &retry_at) == DMP_OK &&
        retry_at < state->init_deadline) {
        state->want_retry = 1;
        state->retry_at = retry_at;
        return;
    }
    fail_init(state);
}

static int consider_init(node *self, dmp_time_ms now)
{
    uint8_t req[1];
    dmp_reliability_handle handle;
    if (self->app.producer || !self->app.want_retry || now < self->app.retry_at ||
        self->app.init_failed || self->app.synchronized) {
        return 0;
    }
    self->app.want_retry = 0;
    CHECK(sample1_read_req(req) == 1U);
    CHECK(dmp_endpoint_submit_req(&self->endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    self->app.have_designated = 1;
    self->app.designated = handle;
    self->app.sync_generation = self->app.generation;
    self->app.init_reads++;
    return 0;
}

static int pump(dmp_time_ms now, int rounds)
{
    int i;
    left.wire.now = now;
    right.wire.now = now;
    for (i = 0; i < rounds; i++) {
        observe_init_deadline(&left.app, now);
        observe_init_deadline(&right.app, now);
        CHECK(consider_init(&left, now) == 0);
        CHECK(consider_init(&right, now) == 0);
        CHECK(service(&left, now) == 0);
        CHECK(service(&right, now) == 0);
        CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
        CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
        CHECK(deliver(&left, &right, now, -1) == 0);
        CHECK(deliver(&right, &left, now, -1) == 0);
        close_init_attempt(&left.app, now);
        close_init_attempt(&right.app, now);
    }
    CHECK(service(&left, now) == 0);
    CHECK(service(&right, now) == 0);
    close_init_attempt(&left.app, now);
    close_init_attempt(&right.app, now);
    return 0;
}

static int designate_read(node *self, dmp_time_ms now, dmp_reliability_handle *out)
{
    uint8_t req[1];
    CHECK(sample1_read_req(req) == 1U);
    CHECK(dmp_endpoint_submit_req(&self->endpoint, 1U, span(req, 1U), now, out) == DMP_OK);
    self->app.have_designated = 1;
    self->app.designated = *out;
    self->app.sync_generation = self->app.generation;
    self->app.init_reads++;
    return 0;
}

/* Step 1 of a later initialization. The retained sample cache stays, and it is
 * not presented as synchronized. */
static void begin_init(app *state, dmp_time_ms now)
{
    state->synchronized = 0;
    state->generation++;
    state->have_designated = 0;
    state->init_used = 0;
    state->init_failed = 0;
    state->init_pending = 0;
    state->want_retry = 0;
    state->init_deadline = now + SAMPLE_INIT_DEADLINE_MS;
}

static int test_sample1(void)
{
    uint8_t built[SAMPLE1_READ_BYTES];
    uint8_t telem[SAMPLE1_TELEM_BYTES];
    uint8_t req[1];
    uint8_t older[SAMPLE1_TELEM_BYTES];
    dmp_reliability_handle handle;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    CHECK(sample1_read_rsp(built, 1U, 2U, 300U) == sizeof READ_RSP);
    CHECK(memcmp(built, READ_RSP, sizeof READ_RSP) == 0);
    CHECK(sample1_telem(built, 1U, 2U, 300U) == sizeof TELEM_CANON);
    CHECK(memcmp(built, TELEM_CANON, sizeof TELEM_CANON) == 0);
    left.app.have_sample = 1;
    left.app.epoch = 1U;
    left.app.index = 2U;
    left.app.value = 300U;
    CHECK(sample1_telem(older, 1U, 2U, 1U) == sizeof older);
    CHECK(sample1_telem(telem, 1U, 2U, 300U) == sizeof telem);
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(older, sizeof older), now) == DMP_OK);
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now) == DMP_OK);
    CHECK(pump(now, 4) == 0);
    CHECK(right.app.telems == 1);
    CHECK(right.app.telem_n == sizeof TELEM_CANON);
    CHECK(memcmp(right.app.telem, TELEM_CANON, sizeof TELEM_CANON) == 0);
    CHECK(right.app.discarded == 1);
    CHECK(right.app.synchronized == 0);
    CHECK(sample1_read_req(req) == 1U);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.app.have_designated = 1;
    right.app.designated = handle;
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(right.app.result_n == sizeof READ_RSP);
    CHECK(memcmp(right.app.result, READ_RSP, sizeof READ_RSP) == 0);
    CHECK(right.app.synchronized == 1);
    CHECK(right.app.live_index == 2U);
    CHECK(right.app.live_value == 300U);
    CHECK(sample1_status_req(req) == 1U);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 2);
    CHECK(right.app.results == 2);
    CHECK(right.app.result_n == sizeof STATUS_RSP);
    CHECK(memcmp(right.app.result, STATUS_RSP, sizeof STATUS_RSP) == 0);
    CHECK(sample1_telem(telem, 1U, 3U, 400U) == sizeof telem);
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now) == DMP_OK);
    CHECK(pump(now, 4) == 0);
    CHECK(right.app.live_index == 3U);
    CHECK(right.app.live_value == 400U);
    CHECK(sample1_telem(telem, 1U, 2U, 1U) == sizeof telem);
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now) == DMP_OK);
    CHECK(pump(now, 4) == 0);
    CHECK(right.app.rollbacks == 1);
    CHECK(right.app.live_index == 3U);
    CHECK(right.app.live_value == 400U);
    CHECK(sample1_telem(telem, 99U, 1U, 5U) == sizeof telem);
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now) == DMP_OK);
    CHECK(pump(now, 4) == 0);
    CHECK(right.app.violations == 1);
    CHECK(right.app.live_index == 3U);
    CHECK(right.app.live_value == 400U);
    /* sample_order: a later READ snapshot must not roll the live sample back. */
    left.app.epoch = 1U;
    left.app.index = 2U;
    left.app.value = 1U;
    CHECK(sample1_read_req(req) == 1U);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 8) == 0);
    CHECK(right.app.results == 3);
    {
        uint8_t older[SAMPLE1_READ_BYTES];
        CHECK(sample1_read_rsp(older, 1U, 2U, 1U) == sizeof older);
        CHECK(right.app.result_n == sizeof older);
        CHECK(memcmp(right.app.result, older, sizeof older) == 0);
    }
    CHECK(right.app.live_index == 3U);
    CHECK(right.app.live_value == 400U);
    return 0;
}

static void pattern(uint8_t *data, size_t n, uint8_t tag)
{
    size_t i;
    for (i = 0U; i < n; i++) {
        data[i] = (uint8_t)(tag + (uint8_t)(i & 0x0fU));
    }
}

static int test_fragment(void)
{
    uint8_t body[BODY];
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    pattern(body, sizeof body, 0x40U);
    left.wire.duplicate_next = 1;
    CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(body, sizeof body), now) ==
          DMP_OK);
    CHECK(pump(now, 2) == 0);
    CHECK(left.wire.submits == 5);
    CHECK(right.app.duplicates >= 1);
    CHECK(right.app.assembled == 1);
    CHECK(right.app.body_n == sizeof body);
    CHECK(memcmp(right.app.body, body, sizeof body) == 0);
    return 0;
}

static int test_retry(void)
{
    uint8_t req[1];
    dmp_reliability_handle handle;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    left.app.have_sample = 1;
    left.app.epoch = 1U;
    left.app.index = 2U;
    left.app.value = 300U;
    right.wire.drop_remaining = 1;
    CHECK(sample1_read_req(req) == 1U);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 3) == 0);
    CHECK(right.wire.submits == 1);
    CHECK(left.app.accepts == 0);
    CHECK(right.app.results == 0);
    CHECK(pump(now + 1280U, 8) == 0);
    CHECK(right.wire.submits >= 2);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(right.app.result_n == sizeof READ_RSP);
    CHECK(memcmp(right.app.result, READ_RSP, sizeof READ_RSP) == 0);
    return 0;
}

static int test_duplicate(void)
{
    uint8_t req[1];
    dmp_reliability_handle handle;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    left.app.have_sample = 1;
    left.app.epoch = 1U;
    left.app.index = 2U;
    left.app.value = 300U;
    right.wire.duplicate_next = 1;
    CHECK(sample1_read_req(req) == 1U);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(memcmp(right.app.result, READ_RSP, sizeof READ_RSP) == 0);
    return 0;
}

static int test_quota(void)
{
    uint8_t first[BODY];
    uint8_t second[BODY];
    held saved;
    dmp_time_ms now = 1000U;
    uint32_t sentinel;
    int rc;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    pattern(first, sizeof first, 0x40U);
    left.wire.delay = 1;
    CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(first, sizeof first), now) ==
          DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(first, sizeof first), now) ==
          DMP_QUOTA_EXHAUSTED);
    CHECK(right.app.assembled == 0);
    CHECK(right.app.accepts == 0);
    CHECK(right.app.results == 0);
    left.wire.delay = 0;
    left.wire.now = now;
    wire_finish(&left.wire, DMP_TX_TRANSMITTED);
    left.wire.n = 0;
    left.wire.drop_remaining = 8;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);

    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    pattern(first, sizeof first, 0x40U);
    pattern(second, sizeof second, 0x80U);
    left.app.value = 300U;
    sentinel = left.app.value;
    CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(first, sizeof first), now) ==
          DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.submits == 5);
    CHECK(left.wire.n == 5);
    saved = left.wire.q[4];
    left.wire.n = 4;
    CHECK(deliver(&left, &right, now, -1) == 0);
    CHECK(right.app.assembled == 0);
    CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(second, sizeof second), now) ==
          DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    rc = deliver(&left, &right, now, 1);
    CHECK(rc == 2);
    CHECK(right.app.assembled == 0);
    CHECK(left.app.value == sentinel);
    {
        dmp_status status =
            dmp_endpoint_rx(&right.endpoint, span(saved.frame, saved.len), now);
        CHECK(status == DMP_OK);
    }
    CHECK(right.app.assembled == 1);
    CHECK(right.app.body_n == sizeof first);
    CHECK(memcmp(right.app.body, first, sizeof first) == 0);
    CHECK(left.app.value == sentinel);
    return 0;
}

static int test_sample_snapshot(void)
{
    uint8_t req[1];
    uint8_t expect[SAMPLE1_READ_BYTES];
    dmp_reliability_handle handle;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    left.app.have_sample = 1;
    left.app.epoch = 1U;
    left.app.index = 2U;
    left.app.value = 300U;
    left.app.hold_complete = 1;
    CHECK(sample1_read_req(req) == 1U);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.app.have_designated = 1;
    right.app.designated = handle;
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(left.app.have_snapshot == 1);
    CHECK(left.app.snap_value == 300U);
    CHECK(right.app.results == 0);
    left.app.value = 400U;
    left.app.hold_complete = 0;
    CHECK(pump(now, 8) == 0);
    CHECK(sample1_read_rsp(expect, 1U, 2U, 300U) == sizeof expect);
    CHECK(right.app.results == 1);
    CHECK(right.app.result_n == sizeof expect);
    CHECK(memcmp(right.app.result, expect, sizeof expect) == 0);
    CHECK(right.app.synchronized == 1);
    CHECK(right.app.live_value == 300U);
    return 0;
}

static int test_fragment_replay(void)
{
    uint8_t body[BODY];
    held saved[8];
    uint8_t seen[BODY];
    int n;
    int i;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    pattern(body, sizeof body, 0x40U);
    CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(body, sizeof body), now) ==
          DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 5);
    n = left.wire.n;
    for (i = 0; i < n; i++) {
        saved[i] = left.wire.q[i];
    }
    CHECK(deliver(&left, &right, now, -1) == 0);
    CHECK(right.app.assembled == 1);
    CHECK(right.app.body_n == sizeof body);
    CHECK(memcmp(right.app.body, body, sizeof body) == 0);
    memcpy(seen, right.app.body, sizeof seen);
    right.app.body[0] = (uint8_t)(right.app.body[0] ^ 0xffU);
    for (i = 0; i < n; i++) {
        left.wire.q[i] = saved[i];
    }
    left.wire.n = n;
    CHECK(deliver(&left, &right, now, -1) == 0);
    CHECK(right.app.assembled == 1);
    CHECK(right.app.body[0] == (uint8_t)(seen[0] ^ 0xffU));
    CHECK(memcmp(right.app.body + 1, seen + 1, sizeof seen - 1U) == 0);
    return 0;
}

/* Extension 64, C=0, U=0, empty value. Appended after SERVICE_ID. */
static const uint8_t UNKNOWN_SAFE[] = {0x80, 0x02, 0x00};

static int core_of(const held *in, uint8_t *core, size_t cap, size_t *n, dmp_time_ms now)
{
    dmp_stream_decoder decoder;
    uint8_t storage[STREAM_CAP];
    dmp_stream_config config;
    dmp_buffer buffer;
    dmp_stream_result fed;
    memset(&decoder, 0, sizeof decoder);
    memset(&config, 0, sizeof config);
    config.mode = DMP_STREAM_R;
    config.max_core_bytes = MTU;
    config.partial_timeout_ms = 5652U;
    buffer.data = storage;
    buffer.capacity = sizeof storage;
    CHECK(dmp_stream_init(&decoder, config, buffer, now) == DMP_OK);
    fed = dmp_stream_feed(&decoder, span(in->frame, in->len), now);
    CHECK(fed.status == DMP_OK);
    CHECK(fed.event == DMP_STREAM_FRAME);
    CHECK(fed.frame.size <= cap);
    memcpy(core, fed.frame.data, fed.frame.size);
    *n = fed.frame.size;
    return 0;
}

static int with_unknown(const held *in, held *out, dmp_time_ms now)
{
    uint8_t core[MTU];
    uint8_t ext[128];
    uint8_t encoded[MTU];
    uint8_t stream[FRAME_CAP];
    size_t core_n = 0U;
    size_t written = 0U;
    size_t framed = 0U;
    dmp_core_limits limits;
    dmp_frame_view view;
    dmp_parse_result parsed;
    dmp_frame_spec spec;
    dmp_buffer buf;
    CHECK(core_of(in, core, sizeof core, &core_n, now) == 0);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 16U;
    parsed = dmp_core_parse(span(core, core_n), &limits, &view);
    CHECK(parsed.status == DMP_OK);
    CHECK(view.extensions.size + sizeof UNKNOWN_SAFE <= sizeof ext);
    if (view.extensions.size != 0U) {
        memcpy(ext, view.extensions.data, view.extensions.size);
    }
    memcpy(ext + view.extensions.size, UNKNOWN_SAFE, sizeof UNKNOWN_SAFE);
    memset(&spec, 0, sizeof spec);
    spec.fields = view.fields;
    spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_EXT);
    spec.extensions = span(ext, view.extensions.size + sizeof UNKNOWN_SAFE);
    spec.payload = view.payload;
    buf.data = encoded;
    buf.capacity = sizeof encoded;
    CHECK(dmp_core_encode(&spec, &limits, buf, &written) == DMP_OK);
    buf.data = stream + 1;
    buf.capacity = sizeof stream - 1U;
    CHECK(dmp_stream_encode(DMP_STREAM_R, span(encoded, written), buf, &framed) == DMP_OK);
    stream[0] = 0U;
    CHECK(framed + 1U <= sizeof stream);
    memcpy(out->frame, stream, framed + 1U);
    out->len = framed + 1U;
    out->used = 1;
    return 0;
}

static int test_fragment_tlv(void)
{
    uint8_t body[BODY];
    held saved[8];
    held mutated;
    dmp_status status;
    int n;
    int i;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    pattern(body, sizeof body, 0x40U);
    CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(body, sizeof body), now) ==
          DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 5);
    n = left.wire.n;
    for (i = 0; i < n; i++) {
        saved[i] = left.wire.q[i];
    }
    left.wire.n = 0;
    status = dmp_endpoint_rx(&right.endpoint, span(saved[0].frame, saved[0].len), now);
    CHECK(status == DMP_INCOMPLETE);
    CHECK(with_unknown(&saved[1], &mutated, now) == 0);
    status = dmp_endpoint_rx(&right.endpoint, span(mutated.frame, mutated.len), now);
    CHECK(status == DMP_MALFORMED);
    for (i = 2; i < n; i++) {
        status = dmp_endpoint_rx(&right.endpoint, span(saved[i].frame, saved[i].len), now);
        CHECK(status == DMP_INCOMPLETE);
    }
    CHECK(right.app.assembled == 0);
    CHECK(right.app.body_n == 0U);
    return 0;
}

/* A1 ERR NO_SAMPLE and A4: NO_SAMPLE, then a new sample and a new READ identity.
 * direct-nnpsk0 init_attempts is 1, so the new identity is an ordinary READ.
 * It returns the new snapshot and does not initialize. The old identity still
 * resolves to the retained empty STATUS 64. */
static int test_sample_no_sample(void)
{
    uint8_t req[1];
    uint8_t telem[SAMPLE1_TELEM_BYTES];
    uint8_t expect[SAMPLE1_READ_BYTES];
    held saved;
    dmp_reliability_handle handle;
    dmp_status status;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    CHECK(designate_read(&right, now, &handle) == 0);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n >= 1);
    saved = right.wire.q[0];
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(right.app.last_status == SAMPLE_NO_SAMPLE);
    CHECK(right.app.result_n == 0U);
    CHECK(right.app.no_samples == 1);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.init_failed == 1);
    CHECK(right.app.init_reads == 1);
    CHECK(right.app.live_index == 0U);
    left.app.have_sample = 1;
    left.app.epoch = 1U;
    left.app.index = 4U;
    left.app.value = 50U;
    CHECK(sample1_telem(telem, 1U, 4U, 50U) == sizeof telem);
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now) == DMP_OK);
    CHECK(pump(now, 4) == 0);
    CHECK(right.app.discarded >= 1);
    CHECK(right.app.synchronized == 0);
    status = dmp_endpoint_rx(&left.endpoint, span(saved.frame, saved.len), now);
    CHECK(status == DMP_OK || status == DMP_DUPLICATE);
    CHECK(pump(now, 4) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.last_status == SAMPLE_NO_SAMPLE);
    CHECK(right.app.result_n == 0U);
    CHECK(sample1_read_req(req) == 1U);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 2);
    CHECK(sample1_read_rsp(expect, 1U, 4U, 50U) == sizeof expect);
    CHECK(right.app.result_n == sizeof expect);
    CHECK(memcmp(right.app.result, expect, sizeof expect) == 0);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.init_failed == 1);
    CHECK(right.app.init_reads == 1);
    CHECK(right.app.live_index == 0U);
    return 0;
}

/* A2 steps 2 and 4. Consumer init clock is 5000 ms; reliability
 * result_deadline_ms stays 12000. 5000 is handwritten, not the manifest. */
static int test_sample_init_budget(void)
{
    dmp_reliability_handle handle;
    dmp_time_ms now = 1000U;
    const dmp_time_ms init_clock_ms = 5000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    right.app.init_deadline = now + init_clock_ms;
    left.app.have_sample = 1;
    left.app.epoch = 1U;
    left.app.index = 2U;
    left.app.value = 300U;
    left.app.hold_complete = 1;
    CHECK(designate_read(&right, now, &handle) == 0);
    CHECK(pump(now, 4) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 0);
    CHECK(right.app.init_failed == 0);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.init_reads == 1);
    CHECK(pump(now + init_clock_ms - 1U, 4) == 0);
    CHECK(right.app.init_failed == 0);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.live_index == 0U);
    CHECK(right.app.init_reads == 1);
    CHECK(pump(now + init_clock_ms, 4) == 0);
    CHECK(right.app.init_failed == 1);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.results == 0);
    CHECK(right.app.live_index == 0U);
    CHECK(right.app.init_reads == 1);
    CHECK(pump(now + init_clock_ms + (dmp_time_ms)SAMPLE_INIT_RETRY_MS, 4) == 0);
    CHECK(right.app.init_reads == 1);
    CHECK(right.app.init_failed == 1);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.live_index == 0U);
    left.app.hold_complete = 0;
    CHECK(pump(now + init_clock_ms + (dmp_time_ms)SAMPLE_INIT_RETRY_MS, 8) == 0);
    CHECK(right.app.results == 1);
    CHECK(right.app.init_failed == 1);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.live_index == 0U);
    CHECK(right.app.live_value == 0U);
    CHECK(right.app.init_reads == 1);
    return 0;
}

/* A2 step 3 and A4 same-epoch reconnect. The older READ snapshot is visible
 * as the correlated result and must not replace the greater cached sample. */
static int test_sample_same_epoch(void)
{
    uint8_t older[SAMPLE1_READ_BYTES];
    dmp_reliability_handle handle;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    left.app.have_sample = 1;
    left.app.epoch = 1U;
    left.app.index = 5U;
    left.app.value = 9U;
    CHECK(designate_read(&right, now, &handle) == 0);
    CHECK(pump(now, 8) == 0);
    CHECK(right.app.synchronized == 1);
    CHECK(right.app.live_index == 5U);
    CHECK(right.app.live_value == 9U);
    CHECK(right.app.cache_index == 5U);
    begin_init(&right.app, now);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.have_cache == 1);
    CHECK(right.app.cache_index == 5U);
    left.app.index = 2U;
    left.app.value = 1U;
    CHECK(designate_read(&right, now, &handle) == 0);
    CHECK(pump(now, 8) == 0);
    CHECK(sample1_read_rsp(older, 1U, 2U, 1U) == sizeof older);
    CHECK(right.app.result_n == sizeof older);
    CHECK(memcmp(right.app.result, older, sizeof older) == 0);
    CHECK(right.app.synchronized == 1);
    CHECK(right.app.epoch == 1U);
    CHECK(right.app.live_index == 5U);
    CHECK(right.app.live_value == 9U);
    CHECK(right.app.cache_index == 5U);
    return 0;
}

/* A2 step 3. A designated READ with a different epoch clears the cache.
 * Epochs are not ordered, so a numerically smaller epoch still replaces.
 * Telemetry of another epoch does not adopt it. */
static int test_sample_new_epoch(void)
{
    uint8_t telem[SAMPLE1_TELEM_BYTES];
    uint8_t expect[SAMPLE1_READ_BYTES];
    dmp_reliability_handle handle;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    left.app.have_sample = 1;
    left.app.epoch = 9U;
    left.app.index = 5U;
    left.app.value = 1U;
    CHECK(designate_read(&right, now, &handle) == 0);
    CHECK(pump(now, 8) == 0);
    CHECK(right.app.synchronized == 1);
    CHECK(right.app.epoch == 9U);
    CHECK(right.app.cache_index == 5U);
    begin_init(&right.app, now);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.cache_epoch == 9U);
    left.app.epoch = 4U;
    left.app.index = 1U;
    left.app.value = 8U;
    CHECK(designate_read(&right, now, &handle) == 0);
    CHECK(pump(now, 8) == 0);
    CHECK(sample1_read_rsp(expect, 4U, 1U, 8U) == sizeof expect);
    CHECK(memcmp(right.app.result, expect, sizeof expect) == 0);
    CHECK(right.app.synchronized == 1);
    CHECK(right.app.epoch == 4U);
    CHECK(right.app.live_index == 1U);
    CHECK(right.app.live_value == 8U);
    CHECK(right.app.cache_epoch == 4U);
    CHECK(right.app.cache_index == 1U);
    CHECK(sample1_telem(telem, 9U, 100U, 3U) == sizeof telem);
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now) == DMP_OK);
    CHECK(pump(now, 4) == 0);
    CHECK(right.app.violations == 1);
    CHECK(right.app.epoch == 4U);
    CHECK(right.app.live_index == 1U);
    CHECK(right.app.live_value == 8U);
    return 0;
}

/* A2 step 5 and A4 association replacement while a result is outstanding.
 * Generation and the designated handle still match; only the association
 * changes. The newer snapshot must not become the live sample. */
static int test_sample_late_assoc(void)
{
    dmp_reliability_handle handle;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    left.app.have_sample = 1;
    left.app.epoch = 1U;
    left.app.index = 5U;
    left.app.value = 9U;
    CHECK(designate_read(&right, now, &handle) == 0);
    CHECK(pump(now, 8) == 0);
    CHECK(right.app.synchronized == 1);
    CHECK(right.app.cache_index == 5U);
    left.app.hold_complete = 1;
    left.app.index = 9U;
    left.app.value = 1U;
    CHECK(designate_read(&right, now, &handle) == 0);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 2);
    CHECK(left.app.snap_index == 9U);
    CHECK(right.app.results == 1);
    right.app.association.epoch = 11U;
    right.app.synchronized = 0;
    left.app.hold_complete = 0;
    CHECK(pump(now, 8) == 0);
    CHECK(right.app.results == 2);
    CHECK(right.app.last_source.namespace_id == 1U);
    CHECK(right.app.last_source.origin_id == 10U);
    CHECK(right.app.last_source.epoch == 7U);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.cache_index == 5U);
    CHECK(right.app.live_index == 5U);
    CHECK(right.app.live_value == 9U);
    return 0;
}

/* A2 step 2. Cancel/supersession drops the previous designation. The result
 * still arrives and must not select an epoch. */
static int test_sample_superseded(void)
{
    uint8_t expect[SAMPLE1_READ_BYTES];
    dmp_reliability_handle handle;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    left.app.have_sample = 1;
    left.app.epoch = 1U;
    left.app.index = 2U;
    left.app.value = 300U;
    left.app.hold_complete = 1;
    CHECK(designate_read(&right, now, &handle) == 0);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 0);
    right.app.have_designated = 0;
    left.app.hold_complete = 0;
    CHECK(pump(now, 8) == 0);
    CHECK(sample1_read_rsp(expect, 1U, 2U, 300U) == sizeof expect);
    CHECK(right.app.results == 1);
    CHECK(right.app.result_n == sizeof expect);
    CHECK(memcmp(right.app.result, expect, sizeof expect) == 0);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.live_index == 0U);
    CHECK(right.app.init_failed == 0);
    return 0;
}

/* A2 step 4. An invalid correlated result never completes synchronization. */
static int test_sample_invalid(void)
{
    dmp_reliability_handle handle;
    dmp_time_ms now = 1000U;
    CHECK(boot(&left, 1, now) == 0);
    CHECK(boot(&right, 0, now) == 0);
    left.app.have_sample = 1;
    left.app.epoch = 1U;
    left.app.index = 2U;
    left.app.value = 300U;
    left.app.bad_result = 1;
    CHECK(designate_read(&right, now, &handle) == 0);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(right.app.invalid_results == 1);
    CHECK(right.app.synchronized == 0);
    CHECK(right.app.live_index == 0U);
    CHECK(right.app.init_failed == 0);
    return 0;
}

int main(int argc, char **argv)
{
    const char *name = argc > 1 ? argv[1] : "all";
    int failed = 0;
    if (strcmp(name, "sample1") == 0 || strcmp(name, "all") == 0) {
        failed |= test_sample1();
    }
    if (strcmp(name, "sample_snapshot") == 0 || strcmp(name, "all") == 0) {
        failed |= test_sample_snapshot();
    }
    if (strcmp(name, "fragment") == 0 || strcmp(name, "all") == 0) {
        failed |= test_fragment();
    }
    if (strcmp(name, "fragment_replay") == 0 || strcmp(name, "all") == 0) {
        failed |= test_fragment_replay();
    }
    if (strcmp(name, "fragment_tlv") == 0 || strcmp(name, "all") == 0) {
        failed |= test_fragment_tlv();
    }
    if (strcmp(name, "retry") == 0 || strcmp(name, "all") == 0) {
        failed |= test_retry();
    }
    if (strcmp(name, "duplicate") == 0 || strcmp(name, "all") == 0) {
        failed |= test_duplicate();
    }
    if (strcmp(name, "quota") == 0 || strcmp(name, "all") == 0) {
        failed |= test_quota();
    }
    if (strcmp(name, "sample_no_sample") == 0 || strcmp(name, "all") == 0) {
        failed |= test_sample_no_sample();
    }
    if (strcmp(name, "sample_init_budget") == 0 || strcmp(name, "all") == 0) {
        failed |= test_sample_init_budget();
    }
    if (strcmp(name, "sample_same_epoch") == 0 || strcmp(name, "all") == 0) {
        failed |= test_sample_same_epoch();
    }
    if (strcmp(name, "sample_new_epoch") == 0 || strcmp(name, "all") == 0) {
        failed |= test_sample_new_epoch();
    }
    if (strcmp(name, "sample_late_assoc") == 0 || strcmp(name, "all") == 0) {
        failed |= test_sample_late_assoc();
    }
    if (strcmp(name, "sample_superseded") == 0 || strcmp(name, "all") == 0) {
        failed |= test_sample_superseded();
    }
    if (strcmp(name, "sample_invalid") == 0 || strcmp(name, "all") == 0) {
        failed |= test_sample_invalid();
    }
    if (strcmp(name, "sample1") != 0 && strcmp(name, "sample_snapshot") != 0 &&
        strcmp(name, "fragment") != 0 && strcmp(name, "fragment_replay") != 0 &&
        strcmp(name, "fragment_tlv") != 0 && strcmp(name, "retry") != 0 &&
        strcmp(name, "duplicate") != 0 && strcmp(name, "quota") != 0 &&
        strcmp(name, "sample_no_sample") != 0 && strcmp(name, "sample_init_budget") != 0 &&
        strcmp(name, "sample_same_epoch") != 0 && strcmp(name, "sample_new_epoch") != 0 &&
        strcmp(name, "sample_late_assoc") != 0 && strcmp(name, "sample_superseded") != 0 &&
        strcmp(name, "sample_invalid") != 0 &&
        strcmp(name, "all") != 0) {
        (void)fprintf(stderr, "unknown test %s\n", name);
        return 2;
    }
    return failed == 0 ? 0 : 1;
}
