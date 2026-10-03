#include "dmp/reliability.h"

#include <stdio.h>
#include <string.h>

/* Host structural tests for direct REQ/RSP/ERR/ACK. Secured cases below use the
 * P09 test-only authenticated context and a compact REPLY_TO. They do not
 * perform a handshake, AEAD, or replay check and are not SEC-1 evidence. */

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,     \
                          __LINE__, #condition);                             \
            return 1;                                                        \
        }                                                                    \
    } while (0)

dmp_status dmp_test_open_authenticated_context(dmp_identity_table *table,
                                              const dmp_identity_context_config *config,
                                              dmp_identity_handle *out);

enum {
    MAX_SLOTS = 8,
    MAX_MSG = 48,
    MAX_MTU = 192,
    MAX_NOTES = 32,
    TX_LOG = 32,
    Q_MS = 1000,
    RESP_MS = 50,
    JITTER_MS = 5,
    HORIZON_MS = 100000,
    RECEIPT_DELAY = 20,
    RECEIPT_LIMIT = 3,
    DEDUP_MS = 5000,
    REJECTION_MS = 5000,
    CACHE_MS = 500,
    RESULT_DL = 100000,
    CORR_MS = 200000,
    TOMB_MS = 300000
};

static const uint8_t PING[] = { 'p', 'i', 'n', 'g' };
static const uint8_t PONG[] = { 'p', 'o', 'n', 'g' };
static const uint8_t META1[] = { 0xA1, 0x5C };
static const uint8_t META2[] = { 0xA1, 0x5D };

typedef struct {
    int depth;
    int max_depth;
    int fail_status;
    int inline_complete;
    dmp_tx_outcome inline_outcome;
    int cancel_inline;
    dmp_tx_outcome cancel_outcome;
    int submits;
    int cancels;
    int pin_ok;
    struct {
        int used;
        int done;
        dmp_tx_token token;
        dmp_tx_complete_fn complete;
        void *owner;
        uint8_t frame[MAX_MTU];
        size_t len;
        const uint8_t *borrowed;
        dmp_time_ms not_after;
    } hold[TX_LOG];
    int n;
} fake_tx;

typedef struct {
    int count;
    int overflow;
    int during_tx;
    int *depth;
    dmp_reliability_notice items[MAX_NOTES];
    uint8_t bytes[MAX_NOTES][MAX_MSG];
} note_log;

typedef struct {
    int secured;
    int force_service;
    int descriptor;
    uint64_t pn;
    int calls;
    uint32_t default_service;
    dmp_core_limits limits;
    uint8_t ext[160];
    uint8_t trailer[16];
} enc_ctx;

typedef struct {
    dmp_reliability engine;
    dmp_admitted_profile profile;
    dmp_identity_slot ids[2];
    dmp_identity_table table;
    dmp_identity_handle handle;
    dmp_transport transport;
    fake_tx tx;
    enc_ctx enc;
    note_log notes;
    dmp_reliability_storage storage;
    dmp_reliability_sender_slot senders[MAX_SLOTS];
    uint8_t sender_payload[MAX_SLOTS * MAX_MSG];
    dmp_reliability_result_slot results[MAX_SLOTS];
    uint8_t result_payload[MAX_SLOTS * MAX_MSG];
    dmp_reliability_history_slot history[MAX_SLOTS];
    dmp_reliability_correlation_slot correlations[MAX_SLOTS];
    uint8_t history_metadata[MAX_SLOTS * DMP_RELIABILITY_METADATA_BYTES];
    uint8_t correlation_metadata[MAX_SLOTS * DMP_RELIABILITY_METADATA_BYTES];
    dmp_reliability_adapter_slot adapters[MAX_SLOTS];
    uint8_t frames[MAX_SLOTS * MAX_MTU];
    uint8_t receive_payload[MAX_MSG + 1];
} node;

static node side_a;
static node side_b;

static dmp_bytes span(const void *data, size_t size)
{
    dmp_bytes bytes;
    bytes.data = (const uint8_t *)data;
    bytes.size = size;
    return bytes;
}

static dmp_message_origin origin_of(uint32_t id, uint64_t epoch)
{
    dmp_message_origin origin;
    memset(&origin, 0, sizeof origin);
    origin.namespace_id = 1U;
    origin.origin_id = id;
    origin.epoch = epoch;
    return origin;
}

static dmp_message_key origin_key(uint32_t id, uint64_t epoch, uint32_t seq)
{
    dmp_message_key key;
    key.origin = origin_of(id, epoch);
    key.seq = seq;
    return key;
}

static void fill_profile(dmp_admitted_profile *profile)
{
    memset(profile, 0, sizeof *profile);
    profile->namespace_id = 1U;
    profile->node_id[0] = 10U;
    profile->node_id[1] = 20U;
    profile->default_service = 1U;
    profile->service_id[0] = 1U;
    profile->service_id[1] = 2U;
    profile->peers = 1U;
    profile->operations_per_service = 2U;
    profile->assemblies_per_peer = 1U;
    profile->sender_slots = 4U;
    profile->assembly_slots = 1U;
    profile->result_slots = 2U;
    profile->history_slots = 4U;
    profile->correlation_slots = 2U;
    profile->adapter_slots = 4U;
    profile->application_queue_slots = 2U;
    profile->control_slots = 2U;
    profile->message_bytes = MAX_MSG;
    profile->fragments = 2U;
    profile->chunk_bytes = MAX_MSG;
    profile->encoded_mtu = MAX_MTU;
    profile->forward_mtu = MAX_MTU;
    profile->return_mtu = MAX_MTU;
    profile->queue_ms = Q_MS;
    profile->response_timeout_ms = RESP_MS;
    profile->jitter_ms = JITTER_MS;
    profile->send_horizon_ms = HORIZON_MS;
    profile->receipt_delay_ms = RECEIPT_DELAY;
    profile->receipt_limit = RECEIPT_LIMIT;
    profile->dedup_ms = DEDUP_MS;
    profile->rejection_ms = REJECTION_MS;
    profile->result_cache_ms = CACHE_MS;
    profile->result_deadline_ms = RESULT_DL;
    profile->correlation_ms = CORR_MS;
    profile->tombstone_ms = TOMB_MS;
    profile->late_result_ms = 1000U;
}

static void add_uleb(uint8_t *data, size_t *n, size_t cap, uint32_t value)
{
    do {
        uint8_t byte = (uint8_t)(value & 0x7fU);
        value >>= 7U;
        if (value != 0U) {
            byte = (uint8_t)(byte | 0x80U);
        }
        if (*n < cap) {
            data[(*n)++] = byte;
        }
    } while (value != 0U);
}

static void add_u64le(uint8_t *data, size_t *n, size_t cap, uint64_t value)
{
    unsigned i;
    for (i = 0U; i < 8U; i++) {
        if (*n < cap) {
            data[(*n)++] = (uint8_t)(value & 0xffU);
        }
        value >>= 8U;
    }
}

static void add_tlv(uint8_t *data, size_t *n, size_t cap, uint32_t tag, const uint8_t *value,
                    size_t value_n)
{
    size_t i;
    add_uleb(data, n, cap, tag);
    add_uleb(data, n, cap, (uint32_t)value_n);
    for (i = 0U; i < value_n; i++) {
        if (*n < cap) {
            data[(*n)++] = value[i];
        }
    }
}

static dmp_status encode_frame(void *context, const dmp_reliability_logical *logical, dmp_buffer out,
                               size_t *written)
{
    enc_ctx *enc = context;
    dmp_frame_spec spec;
    uint8_t value[32];
    size_t value_n;
    size_t ext_n = 0U;
    uint32_t service;

    if (enc == NULL || logical == NULL || written == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    enc->calls++;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)logical->type;
    spec.fields.options = DMP_OPT_SEQ;
    spec.fields.seq = logical->own.seq;
    if (logical->ack_req) {
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_ACK_REQ);
    }
    if (enc->secured) {
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_SECURITY);
        spec.fields.security.cipher = 1U;
        spec.fields.security.receive_cid = 1U;
        spec.fields.security.pn = enc->pn++;
        memset(enc->trailer, 0, sizeof enc->trailer);
        spec.trailer.data = enc->trailer;
        spec.trailer.size = 16U;
    }
    if (logical->has_reply_to) {
        value_n = 0U;
        if (enc->secured) {
            add_uleb(value, &value_n, sizeof value, logical->reply_to.seq);
        } else {
            add_uleb(value, &value_n, sizeof value, logical->reply_to.origin.namespace_id);
            add_uleb(value, &value_n, sizeof value, logical->reply_to.origin.origin_id);
            add_u64le(value, &value_n, sizeof value, logical->reply_to.origin.epoch);
            add_uleb(value, &value_n, sizeof value, logical->reply_to.seq);
        }
        add_tlv(enc->ext, &ext_n, sizeof enc->ext, 5U, value, value_n);
    }
    service = enc->force_service != 0 ? (uint32_t)enc->force_service : logical->service_id;
    if (enc->force_service != 0 || (service != 0U && service != enc->default_service)) {
        value_n = 0U;
        add_uleb(value, &value_n, sizeof value, service);
        add_tlv(enc->ext, &ext_n, sizeof enc->ext, 17U, value, value_n);
    }
    if (logical->type == DMP_TYPE_ERR ||
        (logical->type == DMP_TYPE_RSP && logical->wire_status != 0U)) {
        value_n = 0U;
        add_uleb(value, &value_n, sizeof value, logical->wire_status);
        add_tlv(enc->ext, &ext_n, sizeof enc->ext, 21U, value, value_n);
    }
    if (ext_n != 0U) {
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_EXT);
        spec.extensions.data = enc->ext;
        spec.extensions.size = ext_n;
    }
    if (enc->descriptor) {
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_PAYLOAD_DESC);
        spec.fields.descriptor.flags = 0U;
        spec.fields.descriptor.codec = 7U;
    }
    spec.payload = logical->payload;
    return dmp_core_encode(&spec, &enc->limits, out, written);
}

static dmp_status fake_submit(void *context, const dmp_tx_submission *submission)
{
    fake_tx *tx = context;
    if (tx == NULL || submission == NULL || submission->frame.size > MAX_MTU) {
        return DMP_INVALID_ARGUMENT;
    }
    tx->depth++;
    if (tx->depth > tx->max_depth) {
        tx->max_depth = tx->depth;
    }
    if (tx->fail_status != 0) {
        tx->depth--;
        return (dmp_status)tx->fail_status;
    }
    if (tx->n >= TX_LOG) {
        tx->depth--;
        return DMP_BUSY;
    }
    tx->hold[tx->n].used = 1;
    tx->hold[tx->n].done = 0;
    tx->hold[tx->n].token = submission->token;
    tx->hold[tx->n].complete = submission->complete;
    tx->hold[tx->n].owner = submission->owner;
    tx->hold[tx->n].len = submission->frame.size;
    tx->hold[tx->n].borrowed = submission->frame.data;
    tx->hold[tx->n].not_after = submission->not_after;
    memcpy(tx->hold[tx->n].frame, submission->frame.data, submission->frame.size);
    tx->submits++;
    if (tx->inline_complete) {
        tx->pin_ok = memcmp(submission->frame.data, tx->hold[tx->n].frame, submission->frame.size) == 0;
        tx->hold[tx->n].done = 1;
        submission->complete(submission->owner, submission->token, tx->inline_outcome, 0U);
    }
    tx->n++;
    tx->depth--;
    return DMP_OK;
}

static dmp_status fake_cancel(void *context, dmp_tx_token token)
{
    fake_tx *tx = context;
    int i;
    tx->depth++;
    tx->cancels++;
    for (i = 0; i < tx->n; i++) {
        if (tx->hold[i].used && !tx->hold[i].done && tx->hold[i].token.slot == token.slot &&
            tx->hold[i].token.generation == token.generation) {
            if (tx->cancel_inline) {
                tx->hold[i].done = 1;
                tx->hold[i].complete(tx->hold[i].owner, tx->hold[i].token, tx->cancel_outcome, 0U);
            }
            break;
        }
    }
    tx->depth--;
    return DMP_OK;
}

static void on_notice(void *user, const dmp_reliability_notice *notice)
{
    note_log *log = user;
    dmp_reliability_notice copy;
    if (log->depth != NULL && *log->depth > 0) {
        log->during_tx++;
    }
    if (log->count >= MAX_NOTES) {
        log->overflow = 1;
        return;
    }
    copy = *notice;
    if (notice->payload.size > 0U && notice->payload.size <= MAX_MSG && notice->payload.data != NULL) {
        memcpy(log->bytes[log->count], notice->payload.data, notice->payload.size);
        copy.payload.data = log->bytes[log->count];
        copy.payload.size = notice->payload.size;
    } else {
        copy.payload.data = NULL;
        copy.payload.size = notice->payload.size;
    }
    log->items[log->count++] = copy;
}

static int event_count(const note_log *log, dmp_reliability_event event)
{
    int i;
    int count = 0;
    for (i = 0; i < log->count; i++) {
        if (log->items[i].event == event) {
            count++;
        }
    }
    return count;
}

static int prepare(node *n, int responder, int secured)
{
    dmp_identity_context_config config;
    dmp_message_origin local = origin_of(responder ? 20U : 10U, responder ? 9U : 7U);
    dmp_message_origin peer = origin_of(responder ? 10U : 20U, responder ? 7U : 9U);
    memset(n, 0, sizeof *n);
    fill_profile(&n->profile);
    CHECK(dmp_identity_table_init(&n->table, n->ids, 2U) == DMP_OK);
    memset(&config, 0, sizeof config);
    config.local = local;
    config.peer = peer;
    config.security = 0U;
    if (secured) {
        CHECK(dmp_test_open_authenticated_context(&n->table, &config, &n->handle) == DMP_OK);
    } else {
        CHECK(dmp_identity_context_open(&n->table, &config, &n->handle) == DMP_OK);
    }
    n->tx.pin_ok = 1;
    n->notes.depth = &n->tx.depth;
    n->enc.pn = 1U;
    return 0;
}

static void bind_node(node *n)
{
    dmp_reliability_storage *storage = &n->storage;
    memset(storage, 0, sizeof *storage);
    n->transport.context = &n->tx;
    n->transport.submit = fake_submit;
    n->transport.cancel = fake_cancel;
    n->transport.caps.max_frame_bytes = n->profile.encoded_mtu;
    n->transport.caps.ownership = n->profile.tx_borrow ? DMP_TX_BORROW : DMP_TX_COPY;
    n->transport.caps.synchronous_completion = n->profile.synchronous_completion;
    n->enc.secured = n->ids[n->handle.slot].security == 1U;
    n->enc.default_service = n->profile.default_service;
    n->enc.limits.max_frame_bytes = n->profile.encoded_mtu;
    n->enc.limits.max_message_bytes = n->profile.message_bytes;
    n->enc.limits.max_fragments = 2U;
    storage->profile = &n->profile;
    storage->identity = &n->table;
    storage->context = n->handle;
    storage->transport = &n->transport;
    storage->encode = encode_frame;
    storage->encode_context = &n->enc;
    storage->notice = on_notice;
    storage->notice_user = &n->notes;
    storage->senders = n->senders;
    storage->sender_capacity = n->profile.sender_slots;
    storage->sender_payload = n->sender_payload;
    storage->sender_payload_capacity = (size_t)n->profile.sender_slots * n->profile.message_bytes;
    storage->results = n->results;
    storage->result_capacity = n->profile.result_slots;
    storage->result_payload = n->result_payload;
    storage->result_payload_capacity = (size_t)n->profile.result_slots * n->profile.message_bytes;
    storage->history = n->history;
    storage->history_capacity = n->profile.history_slots;
    storage->correlations = n->correlations;
    storage->correlation_capacity = n->profile.correlation_slots;
    storage->history_metadata = n->history_metadata;
    storage->history_metadata_capacity =
        (size_t)n->profile.history_slots * (size_t)DMP_RELIABILITY_METADATA_BYTES;
    storage->correlation_metadata = n->correlation_metadata;
    storage->correlation_metadata_capacity =
        (size_t)n->profile.correlation_slots * (size_t)DMP_RELIABILITY_METADATA_BYTES;
    storage->adapters = n->adapters;
    storage->adapter_capacity = n->profile.adapter_slots;
    storage->frames = n->frames;
    storage->frame_capacity = (size_t)n->profile.adapter_slots * n->profile.encoded_mtu;
    storage->receive_payload = n->receive_payload;
    storage->receive_payload_capacity = n->profile.message_bytes;
}

static int boot(node *n, int responder, int secured)
{
    CHECK(prepare(n, responder, secured) == 0);
    bind_node(n);
    CHECK(dmp_reliability_init(&n->engine, &n->storage) == DMP_OK);
    CHECK(n->ids[n->handle.slot].retained == 1U);
    return 0;
}

static void finish_all(node *n, dmp_tx_outcome outcome, dmp_time_ms when)
{
    int i;
    for (i = 0; i < n->tx.n; i++) {
        if (n->tx.hold[i].used && !n->tx.hold[i].done) {
            n->tx.hold[i].done = 1;
            n->tx.depth++;
            n->tx.hold[i].complete(n->tx.hold[i].owner, n->tx.hold[i].token, outcome, when);
            n->tx.depth--;
        }
    }
}

static int parse_hold(const node *n, int index, dmp_frame_view *view)
{
    dmp_bytes input;
    dmp_core_limits limits;
    dmp_parse_result parsed;
    input.data = n->tx.hold[index].frame;
    input.size = n->tx.hold[index].len;
    limits.max_frame_bytes = n->profile.encoded_mtu;
    limits.max_message_bytes = n->profile.message_bytes;
    limits.max_fragments = 2U;
    parsed = dmp_core_parse(input, &limits, view);
    return parsed.status == DMP_OK ? 0 : 1;
}

static int extension_value(const dmp_frame_view *frame, uint32_t id, dmp_bytes *value)
{
    size_t cursor = 0U;
    while (cursor < frame->extensions.size) {
        dmp_extension_view view;
        dmp_status status = dmp_extension_next(frame->extensions, &cursor, &view);
        if (status != DMP_OK) {
            return 1;
        }
        if ((view.tag >> 2) == id) {
            *value = view.value;
            return 0;
        }
    }
    return 1;
}

static int count_type(const node *n, uint8_t type)
{
    int i;
    int count = 0;
    for (i = 0; i < n->tx.n; i++) {
        dmp_frame_view view;
        if (parse_hold(n, i, &view) == 0 && view.fields.type == type) {
            count++;
        }
    }
    return count;
}

static int deliver_index(node *src, int index, node *dst, uint32_t service, dmp_bytes metadata,
                         dmp_bytes plaintext, dmp_time_ms now, dmp_status expect)
{
    dmp_frame_view view;
    dmp_reliability_input input;
    CHECK(parse_hold(src, index, &view) == 0);
    if (plaintext.data == NULL && plaintext.size == 0U) {
        plaintext = view.payload;
    }
    input.frame = &view;
    input.service_id = service;
    input.plaintext = plaintext;
    input.immutable_metadata = metadata;
    CHECK(dmp_reliability_on_rx(&dst->engine, &input, now) == expect);
    return 0;
}

static int test_init_and_close(void)
{
    dmp_reliability_handle stale;
    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.sender_slots = 4U;
    bind_node(&side_a);
    side_a.storage.sender_capacity = 3U;
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_INVALID_ARGUMENT);
    CHECK(side_a.ids[side_a.handle.slot].retained == 0U);
    CHECK(side_a.engine.initialized == 0U);

    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.peers = 2U;
    bind_node(&side_a);
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_INVALID_ARGUMENT);
    CHECK(side_a.ids[side_a.handle.slot].retained == 0U);

    CHECK(prepare(&side_a, 0, 0) == 0);
    bind_node(&side_a);
    side_a.storage.sender_capacity++;
    side_a.storage.sender_payload_capacity += side_a.profile.message_bytes;
    side_a.storage.result_capacity++;
    side_a.storage.result_payload_capacity += side_a.profile.message_bytes;
    side_a.storage.history_capacity++;
    side_a.storage.history_metadata_capacity += DMP_RELIABILITY_METADATA_BYTES;
    side_a.storage.correlation_capacity++;
    side_a.storage.correlation_metadata_capacity += DMP_RELIABILITY_METADATA_BYTES;
    side_a.storage.adapter_capacity++;
    side_a.storage.frame_capacity += side_a.profile.encoded_mtu;
    side_a.storage.receive_payload_capacity++;
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_OK);
    CHECK(side_a.engine.storage.sender_capacity == side_a.profile.sender_slots);
    CHECK(side_a.engine.storage.result_capacity == side_a.profile.result_slots);
    CHECK(side_a.engine.storage.history_capacity == side_a.profile.history_slots);
    CHECK(side_a.engine.storage.correlation_capacity == side_a.profile.correlation_slots);
    CHECK(side_a.engine.storage.adapter_capacity == side_a.profile.adapter_slots);
    CHECK(dmp_reliability_close(&side_a.engine, 0U) == DMP_OK);

    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.tx_borrow = true;
    bind_node(&side_a);
    side_a.transport.caps.ownership = DMP_TX_COPY;
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_INVALID_ARGUMENT);
    CHECK(side_a.ids[side_a.handle.slot].retained == 0U);

    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.control_slots = 0U;
    bind_node(&side_a);
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_UNSUPPORTED);

    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.control_slots = 2U;
    side_a.profile.adapter_slots = 2U;
    bind_node(&side_a);
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_UNSUPPORTED);

    CHECK(prepare(&side_a, 0, 0) == 0);
    bind_node(&side_a);
    side_a.transport.caps.max_frame_bytes = 16U;
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_INVALID_ARGUMENT);

    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_INVALID_ARGUMENT);
    CHECK(side_a.ids[side_a.handle.slot].retained == 1U);
    CHECK(dmp_reliability_close(&side_a.engine, 0U) == DMP_OK);
    CHECK(side_a.ids[side_a.handle.slot].retained == 0U);
    CHECK(side_a.engine.initialized == 0U);

    CHECK(boot(&side_a, 0, 0) == 0);
    stale.slot = 9U;
    stale.generation = 99U;
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PING, sizeof PING), 1000U, JITTER_MS,
                                     &stale) == DMP_OK);
    CHECK(stale.slot == 0U);
    CHECK(stale.generation == 1U);
    CHECK(side_a.senders[0].own.seq == 0U);
    CHECK(side_a.senders[0].own.origin.origin_id == 10U);
    CHECK(side_a.senders[0].own.origin.epoch == 7U);
    CHECK(side_a.senders[0].own.origin.namespace_id == 1U);
    CHECK(side_a.senders[0].queue_deadline == 1000U + Q_MS);
    CHECK(side_a.senders[0].send_deadline == 1000U + HORIZON_MS);
    CHECK(side_a.senders[0].result_deadline == 1000U + RESULT_DL);
    CHECK(side_a.senders[0].retain_deadline == 1000U + TOMB_MS);
    CHECK(side_a.correlations[0].correlation_deadline == 1000U + CORR_MS);
    CHECK(side_a.correlations[0].tombstone_deadline == 1000U + TOMB_MS);
    CHECK(side_a.senders[0].phase == DMP_REL_PHASE_QUEUED);
    CHECK(dmp_reliability_close(&side_a.engine, 1000U) == DMP_BUSY);
    CHECK(side_a.ids[side_a.handle.slot].retained == 1U);
    CHECK(dmp_reliability_cancel(&side_a.engine, stale, 1000U) == DMP_OK);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_LOCAL_UNSENT) == 1);
    CHECK(side_a.tx.submits == 0);
    CHECK(dmp_reliability_close(&side_a.engine, 1000U) == DMP_BUSY);
    CHECK(dmp_reliability_poll(&side_a.engine, 1000U + TOMB_MS) == DMP_OK);
    CHECK(side_a.correlations[0].live == 0U);
    CHECK(dmp_reliability_close(&side_a.engine, 1000U + TOMB_MS) == DMP_OK);
    CHECK(side_a.ids[side_a.handle.slot].retained == 0U);
    CHECK(side_a.notes.during_tx == 0);
    return 0;
}

static int test_quota_and_validation(void)
{
    dmp_reliability_handle first;
    dmp_reliability_handle second;
    uint8_t saved[sizeof PING];
    dmp_time_ms deadline;
    CHECK(boot(&side_a, 0, 0) == 0);
    second.slot = 4U;
    second.generation = 8U;
    CHECK(dmp_reliability_submit_req(&side_a.engine, 0U, span(PING, sizeof PING), 0U, 0U, &second) ==
          DMP_INVALID_ARGUMENT);
    CHECK(second.slot == 4U && second.generation == 8U);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 3U, span(PING, sizeof PING), 0U, 0U, &second) ==
          DMP_INVALID_ARGUMENT);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PING, sizeof PING), 0U, JITTER_MS + 1U,
                                     &second) == DMP_INVALID_ARGUMENT);
    CHECK(second.slot == 4U && second.generation == 8U);
    CHECK(side_a.senders[0].live == 0U);

    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.sender_slots = 1U;
    side_a.profile.application_queue_slots = 4U;
    side_a.profile.operations_per_service = 4U;
    side_a.profile.correlation_slots = 2U;
    bind_node(&side_a);
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_OK);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PING, sizeof PING), 50U, 1U, &first) ==
          DMP_OK);
    memcpy(saved, side_a.sender_payload, sizeof PING);
    deadline = side_a.correlations[0].correlation_deadline;
    second.slot = 4U;
    second.generation = 8U;
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PONG, sizeof PONG), 50U, 1U, &second) ==
          DMP_QUOTA_EXHAUSTED);
    CHECK(second.slot == 4U && second.generation == 8U);
    CHECK(side_a.senders[0].live == 1U);
    CHECK(memcmp(side_a.sender_payload, saved, sizeof PING) == 0);
    CHECK(side_a.correlations[0].correlation_deadline == deadline);
    CHECK(side_a.correlations[0].live == 1U);

    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.application_queue_slots = 1U;
    side_a.profile.operations_per_service = 2U;
    bind_node(&side_a);
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_OK);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PING, sizeof PING), 0U, 0U, &first) ==
          DMP_OK);
    second.slot = 3U;
    second.generation = 5U;
    CHECK(dmp_reliability_submit_req(&side_a.engine, 2U, span(PONG, sizeof PONG), 0U, 0U, &second) ==
          DMP_BUSY);
    CHECK(second.slot == 3U && second.generation == 5U);
    CHECK(side_a.senders[0].live == 1U);
    CHECK(side_a.senders[0].payload_len == sizeof PING);
    CHECK(side_a.senders[1].live == 0U);

    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.operations_per_service = 1U;
    bind_node(&side_a);
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_OK);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PING, sizeof PING), 0U, 0U, &first) ==
          DMP_OK);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PONG, sizeof PONG), 0U, 0U, &second) ==
          DMP_BUSY);
    CHECK(side_a.senders[0].generation == first.generation);
    CHECK(side_a.correlations[1].live == 0U);
    return 0;
}

static int submit_and_air(node *n, uint32_t service, dmp_bytes payload, dmp_time_ms now,
                          dmp_reliability_handle *out)
{
    int before = n->tx.n;
    CHECK(dmp_reliability_submit_req(&n->engine, service, payload, now, JITTER_MS, out) == DMP_OK);
    CHECK(dmp_reliability_poll(&n->engine, now) == DMP_OK);
    CHECK(n->tx.n == before + 1);
    finish_all(n, DMP_TX_TRANSMITTED, now);
    CHECK(dmp_reliability_poll(&n->engine, now) == DMP_OK);
    CHECK(n->senders[out->slot].possibly_sent == 1U);
    CHECK(n->senders[out->slot].phase == DMP_REL_PHASE_AWAIT_RECEIPT);
    return 0;
}

static int test_substitution_and_identity(void)
{
    dmp_reliability_handle req;
    dmp_frame_view view;
    dmp_bytes reply;
    dmp_message_key resolved;
    uint8_t expect_reply[11];
    size_t expect_n = 0U;
    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(boot(&side_b, 1, 0) == 0);
    CHECK(submit_and_air(&side_a, 1U, span(PING, sizeof PING), 0U, &req) == 0);
    CHECK(parse_hold(&side_a, 0, &view) == 0);
    CHECK(view.fields.type == DMP_TYPE_REQ);
    CHECK((view.fields.options & DMP_OPT_ACK_REQ) != 0U);
    CHECK(view.fields.seq == 0U);
    CHECK(extension_value(&view, 4U, &reply) != 0);
    CHECK(deliver_index(&side_a, 0, &side_b, 1U, span(META1, sizeof META1), span(NULL, 0), 0U,
                        DMP_OK) == 0);
    CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == 1);
    CHECK(side_b.notes.items[0].payload.size == sizeof PING);
    CHECK(memcmp(side_b.notes.items[0].payload.data, PING, sizeof PING) == 0);
    CHECK(side_b.notes.items[0].key.origin.origin_id == 10U);
    CHECK(side_b.notes.items[0].key.seq == 0U);
    CHECK(side_b.history[0].deadline == DEDUP_MS);
    CHECK(side_b.history[0].destination.origin_id == 20U);
    CHECK(dmp_reliability_complete(&side_b.engine, side_b.notes.items[0].handle, false, 0U,
                                   span(PONG, sizeof PONG), 10U) == DMP_OK);
    CHECK(side_b.results[0].deadline == 10U + CACHE_MS);
    CHECK(dmp_reliability_poll(&side_b.engine, 10U) == DMP_OK);
    CHECK(count_type(&side_b, DMP_TYPE_ACK) == 0);
    CHECK(count_type(&side_b, DMP_TYPE_RSP) == 1);
    CHECK(parse_hold(&side_b, 0, &view) == 0);
    CHECK(view.fields.seq == 0U);
    CHECK((view.fields.options & DMP_OPT_ACK_REQ) != 0U);
    CHECK(extension_value(&view, 1U, &reply) == 0);
    add_uleb(expect_reply, &expect_n, sizeof expect_reply, 1U);
    add_uleb(expect_reply, &expect_n, sizeof expect_reply, 10U);
    add_u64le(expect_reply, &expect_n, sizeof expect_reply, 7U);
    add_uleb(expect_reply, &expect_n, sizeof expect_reply, 0U);
    CHECK(reply.size == expect_n);
    CHECK(memcmp(reply.data, expect_reply, expect_n) == 0);
    CHECK(dmp_identity_reply_to(&view, &side_a.table, side_a.handle, 10U, &resolved) == DMP_OK);
    CHECK(resolved.origin.origin_id == 10U);
    CHECK(resolved.origin.epoch == 7U);
    CHECK(resolved.seq == 0U);
    finish_all(&side_b, DMP_TX_TRANSMITTED, 10U);
    CHECK(dmp_reliability_poll(&side_b.engine, 10U) == DMP_OK);
    CHECK(deliver_index(&side_b, 0, &side_a, 1U, span(META1, sizeof META1), span(NULL, 0), 10U,
                        DMP_OK) == 0);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RECEIPT) == 0);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RESULT) == 1);
    CHECK(side_a.notes.items[0].payload.size == sizeof PONG);
    CHECK(memcmp(side_a.notes.items[0].payload.data, PONG, sizeof PONG) == 0);
    CHECK(side_a.notes.items[0].key.origin.origin_id == 20U);
    CHECK(side_a.notes.items[0].key.seq == 0U);
    CHECK(side_a.notes.items[0].handle.slot == req.slot);
    CHECK(count_type(&side_a, DMP_TYPE_ACK) == 1);
    CHECK(parse_hold(&side_a, 1, &view) == 0);
    CHECK(view.fields.seq == 1U);
    CHECK(extension_value(&view, 1U, &reply) == 0);
    expect_n = 0U;
    add_uleb(expect_reply, &expect_n, sizeof expect_reply, 1U);
    add_uleb(expect_reply, &expect_n, sizeof expect_reply, 20U);
    add_u64le(expect_reply, &expect_n, sizeof expect_reply, 9U);
    add_uleb(expect_reply, &expect_n, sizeof expect_reply, 0U);
    CHECK(reply.size == expect_n);
    CHECK(memcmp(reply.data, expect_reply, expect_n) == 0);
    CHECK(side_a.notes.during_tx == 0);
    return 0;
}

static int test_receipt_loss_and_retry(void)
{
    dmp_reliability_handle req;
    dmp_time_ms history_deadline;
    int encodes;
    int accepted;
    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(boot(&side_b, 1, 0) == 0);
    CHECK(submit_and_air(&side_a, 1U, span(PING, sizeof PING), 0U, &req) == 0);
    CHECK(side_a.senders[0].receipt_deadline == RESP_MS);
    CHECK(side_a.senders[0].next_attempt == RESP_MS + JITTER_MS);
    CHECK(deliver_index(&side_a, 0, &side_b, 1U, span(META1, sizeof META1), span(NULL, 0), 0U,
                        DMP_OK) == 0);
    history_deadline = side_b.history[0].deadline;
    CHECK(dmp_reliability_poll(&side_b.engine, RECEIPT_DELAY) == DMP_OK);
    CHECK(count_type(&side_b, DMP_TYPE_ACK) == 1);
    CHECK(dmp_reliability_poll(&side_a.engine, RESP_MS + JITTER_MS - 1U) == DMP_OK);
    CHECK(side_a.enc.calls == 1);
    encodes = side_a.enc.calls;
    CHECK(dmp_reliability_poll(&side_a.engine, RESP_MS + JITTER_MS) == DMP_OK);
    CHECK(side_a.enc.calls == encodes + 1);
    CHECK(side_a.tx.n >= 2);
    {
        dmp_frame_view first;
        dmp_frame_view second;
        CHECK(parse_hold(&side_a, 0, &first) == 0);
        CHECK(parse_hold(&side_a, side_a.tx.n - 1, &second) == 0);
        CHECK(first.fields.seq == 0U);
        CHECK(second.fields.seq == 0U);
        CHECK(first.fields.type == DMP_TYPE_REQ);
        CHECK(second.fields.type == DMP_TYPE_REQ);
    }
    finish_all(&side_a, DMP_TX_TRANSMITTED, RESP_MS + JITTER_MS);
    CHECK(dmp_reliability_poll(&side_a.engine, RESP_MS + JITTER_MS) == DMP_OK);
    accepted = event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED);
    CHECK(deliver_index(&side_a, side_a.tx.n - 1, &side_b, 1U, span(META1, sizeof META1), span(NULL, 0),
                        RESP_MS + JITTER_MS, DMP_OK) == 0);
    CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == accepted);
    CHECK(side_b.history[0].deadline == history_deadline);
    CHECK(side_b.tx.n >= 2);
    {
        dmp_frame_view ack;
        CHECK(parse_hold(&side_b, side_b.tx.n - 1, &ack) == 0);
        CHECK(ack.fields.type == DMP_TYPE_ACK);
    }
    finish_all(&side_b, DMP_TX_TRANSMITTED, RECEIPT_DELAY);
    CHECK(deliver_index(&side_b, 0, &side_a, 1U, span(META1, sizeof META1), span(NULL, 0),
                        RESP_MS + JITTER_MS, DMP_OK) == 0);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RECEIPT) == 1);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RESULT) == 0);
    CHECK(side_a.senders[req.slot].phase == DMP_REL_PHASE_AWAIT_RESULT);
    encodes = side_a.enc.calls;
    CHECK(dmp_reliability_poll(&side_a.engine, RESP_MS + JITTER_MS + 1000U) == DMP_OK);
    CHECK(side_a.enc.calls == encodes);
    CHECK(dmp_reliability_complete(&side_b.engine, side_b.notes.items[0].handle, false, 0U,
                                   span(PONG, sizeof PONG), RECEIPT_DELAY + 5U) == DMP_OK);
    CHECK(dmp_reliability_poll(&side_b.engine, RECEIPT_DELAY + 5U) == DMP_OK);
    {
        int i;
        int rsp = -1;
        for (i = 0; i < side_b.tx.n; i++) {
            dmp_frame_view view;
            CHECK(parse_hold(&side_b, i, &view) == 0);
            if (view.fields.type == DMP_TYPE_RSP) {
                rsp = i;
                CHECK((view.fields.options & DMP_OPT_ACK_REQ) != 0U);
                CHECK(view.fields.seq != 0U);
            }
        }
        CHECK(rsp >= 0);
        finish_all(&side_b, DMP_TX_TRANSMITTED, RECEIPT_DELAY + 5U);
        CHECK(dmp_reliability_poll(&side_b.engine, RECEIPT_DELAY + 5U) == DMP_OK);
        CHECK(deliver_index(&side_b, rsp, &side_a, 1U, span(META1, sizeof META1), span(NULL, 0),
                            RECEIPT_DELAY + 5U, DMP_OK) == 0);
    }
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RESULT) == 1);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RECEIPT) == 1);
    return 0;
}

static int test_duplicate_metadata_and_service(void)
{
    dmp_reliability_handle req;
    dmp_frame_view view;
    dmp_reliability_input input;
    uint8_t mutated[MAX_MTU];
    dmp_bytes meta = span(META1, sizeof META1);
    dmp_time_ms deadline;
    enc_ctx craft;
    dmp_reliability_logical logical;
    uint8_t raw[MAX_MTU];
    size_t written = 0U;
    dmp_buffer out;
    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(boot(&side_b, 1, 0) == 0);
    CHECK(submit_and_air(&side_a, 2U, span(PING, sizeof PING), 0U, &req) == 0);
    CHECK(parse_hold(&side_a, 0, &view) == 0);
    CHECK(extension_value(&view, 4U, &meta) == 0);
    CHECK(meta.size == 1U && meta.data[0] == 2U);
    CHECK(deliver_index(&side_a, 0, &side_b, 2U, span(META1, sizeof META1), span(NULL, 0), 0U,
                        DMP_OK) == 0);
    deadline = side_b.history[0].deadline;
    memcpy(mutated, side_a.tx.hold[0].frame, side_a.tx.hold[0].len);
    CHECK(parse_hold(&side_a, 0, &view) == 0);
    CHECK(view.payload.size == sizeof PING);
    memcpy(mutated + (view.payload.data - side_a.tx.hold[0].frame), PONG, sizeof PONG);
    {
        dmp_bytes bytes = span(mutated, side_a.tx.hold[0].len);
        dmp_core_limits limits = side_b.enc.limits;
        dmp_parse_result parsed = dmp_core_parse(bytes, &limits, &view);
        CHECK(parsed.status == DMP_OK);
        input.frame = &view;
        input.service_id = 2U;
        input.plaintext = view.payload;
        input.immutable_metadata = span(META1, sizeof META1);
        CHECK(dmp_reliability_on_rx(&side_b.engine, &input, 10U) == DMP_OK);
    }
    CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == 1);
    CHECK(side_b.history[0].deadline == deadline);
    input.immutable_metadata = span(META2, sizeof META2);
    CHECK(dmp_reliability_on_rx(&side_b.engine, &input, 11U) == DMP_MALFORMED);
    CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == 1);
    CHECK(side_b.history[0].deadline == deadline);

    memset(&craft, 0, sizeof craft);
    craft.default_service = 1U;
    craft.limits = side_a.enc.limits;
    craft.pn = 1U;
    craft.descriptor = 1;
    memset(&logical, 0, sizeof logical);
    logical.type = DMP_TYPE_REQ;
    logical.service_id = 2U;
    logical.own = side_a.senders[0].own;
    logical.ack_req = true;
    logical.payload = span(PING, sizeof PING);
    out.data = raw;
    out.capacity = sizeof raw;
    CHECK(encode_frame(&craft, &logical, out, &written) == DMP_OK);
    {
        dmp_bytes bytes = span(raw, written);
        dmp_parse_result parsed = dmp_core_parse(bytes, &craft.limits, &view);
        CHECK(parsed.status == DMP_OK);
        input.frame = &view;
        input.service_id = 2U;
        input.plaintext = span(PING, sizeof PING);
        input.immutable_metadata = span(META1, sizeof META1);
        CHECK(dmp_reliability_on_rx(&side_b.engine, &input, 12U) == DMP_MALFORMED);
    }
    CHECK(side_b.history[0].deadline == deadline);
    CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == 1);

    craft.descriptor = 0;
    craft.force_service = 1;
    logical.service_id = 1U;
    logical.own.seq = 9U;
    CHECK(encode_frame(&craft, &logical, out, &written) == DMP_OK);
    {
        dmp_bytes bytes = span(raw, written);
        dmp_parse_result parsed = dmp_core_parse(bytes, &craft.limits, &view);
        CHECK(parsed.status == DMP_OK);
        input.frame = &view;
        input.service_id = 1U;
        input.plaintext = span(PING, sizeof PING);
        CHECK(dmp_reliability_on_rx(&side_b.engine, &input, 13U) == DMP_MALFORMED);
    }
    CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == 1);

    memset(&view, 0, sizeof view);
    view.fields.type = DMP_TYPE_DATA;
    input.frame = &view;
    CHECK(dmp_reliability_on_rx(&side_b.engine, &input, 14U) == DMP_UNSUPPORTED);
    view.fields.type = DMP_TYPE_REQ;
    view.fields.options = DMP_OPT_FRAG | DMP_OPT_ACK_REQ | DMP_OPT_SEQ;
    CHECK(dmp_reliability_on_rx(&side_b.engine, &input, 14U) == DMP_UNSUPPORTED);
    view.fields.options = DMP_OPT_SEQ;
    CHECK(dmp_reliability_on_rx(&side_b.engine, &input, 14U) == DMP_UNSUPPORTED);
    view.fields.options = DMP_OPT_ROUTE | DMP_OPT_ACK_REQ | DMP_OPT_SEQ;
    input.frame = &view;
    CHECK(dmp_reliability_on_rx(&side_b.engine, &input, 14U) == DMP_UNSUPPORTED);
    CHECK(dmp_reliability_reject_req(&side_b.engine, &input, 4U, 14U) == DMP_UNSUPPORTED);
    CHECK(side_b.history[1].live == 0U);
    return 0;
}

static int test_rejection_and_status(void)
{
    dmp_reliability_handle req;
    dmp_frame_view view;
    dmp_time_ms deadline;
    int err_frames;
    uint32_t first_seq = 0U;
    uint32_t second_seq = 0U;
    enc_ctx craft;
    dmp_reliability_logical logical;
    uint8_t raw[MAX_MTU];
    size_t written = 0U;
    dmp_buffer out;
    uint8_t ext[64];
    size_t ext_n;
    uint8_t value[24];
    size_t value_n;
    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(boot(&side_b, 1, 0) == 0);
    CHECK(submit_and_air(&side_a, 1U, span(PING, sizeof PING), 0U, &req) == 0);
    CHECK(deliver_index(&side_a, 0, &side_b, 1U, span(META1, sizeof META1), span(NULL, 0), 0U,
                        DMP_OK) == 0);
    CHECK(dmp_reliability_reject_req(&side_b.engine, NULL, 8U, 0U) == DMP_INVALID_ARGUMENT);
    {
        dmp_reliability_input input;
        dmp_frame_view held;
        CHECK(parse_hold(&side_a, 0, &held) == 0);
        input.frame = &held;
        input.service_id = 1U;
        input.plaintext = span(PING, sizeof PING);
        input.immutable_metadata = span(META1, sizeof META1);
        CHECK(dmp_reliability_reject_req(&side_b.engine, &input, 8U, 1U) == DMP_INVALID_ARGUMENT);
        CHECK(dmp_reliability_reject_req(&side_b.engine, &input, 64U, 1U) == DMP_INVALID_ARGUMENT);
        CHECK(side_b.history[0].decision == 0U);
        CHECK(dmp_reliability_reject_req(&side_b.engine, &input, 7U, 1U) == DMP_DUPLICATE);
        CHECK(side_b.history[0].deadline == DEDUP_MS);
    }
    CHECK(dmp_reliability_complete(&side_b.engine, side_b.notes.items[0].handle, true, 64U,
                                   span(PONG, sizeof PONG), 30U) == DMP_OK);
    CHECK(dmp_reliability_poll(&side_b.engine, 30U) == DMP_OK);
    {
        int i;
        int err = -1;
        for (i = 0; i < side_b.tx.n; i++) {
            CHECK(parse_hold(&side_b, i, &view) == 0);
            if (view.fields.type == DMP_TYPE_ERR) {
                err = i;
                CHECK((view.fields.options & DMP_OPT_ACK_REQ) != 0U);
                CHECK(view.fields.seq != 0U || count_type(&side_b, DMP_TYPE_ACK) == 0);
            }
        }
        CHECK(err >= 0);
        finish_all(&side_b, DMP_TX_TRANSMITTED, 30U);
        CHECK(dmp_reliability_poll(&side_b.engine, 30U) == DMP_OK);
        CHECK(deliver_index(&side_b, err, &side_a, 1U, span(META1, sizeof META1), span(NULL, 0), 30U,
                            DMP_OK) == 0);
    }
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RESULT) == 1);
    CHECK(side_a.notes.items[0].wire_status == 64U);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_REJECTED) == 0);
    CHECK(count_type(&side_a, DMP_TYPE_ACK) == 1);

    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(boot(&side_b, 1, 0) == 0);
    CHECK(submit_and_air(&side_a, 1U, span(PING, sizeof PING), 0U, &req) == 0);
    {
        dmp_reliability_input input;
        dmp_frame_view held;
        CHECK(parse_hold(&side_a, 0, &held) == 0);
        input.frame = &held;
        input.service_id = 1U;
        input.plaintext = span(PING, sizeof PING);
        input.immutable_metadata = span(META1, sizeof META1);
        CHECK(dmp_reliability_reject_req(&side_b.engine, &input, 4U, 0U) == DMP_OK);
    }
    CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == 0);
    CHECK(side_b.results[0].live == 0U);
    deadline = side_b.history[0].deadline;
    CHECK(deadline == REJECTION_MS);
    CHECK(dmp_reliability_poll(&side_b.engine, 0U) == DMP_OK);
    CHECK(count_type(&side_b, DMP_TYPE_ERR) == 1);
    CHECK(parse_hold(&side_b, 0, &view) == 0);
    CHECK((view.fields.options & DMP_OPT_ACK_REQ) == 0U);
    first_seq = view.fields.seq;
    finish_all(&side_b, DMP_TX_TRANSMITTED, 0U);
    CHECK(dmp_reliability_poll(&side_b.engine, 0U) == DMP_OK);
    CHECK(dmp_reliability_poll(&side_a.engine, RESP_MS + JITTER_MS) == DMP_OK);
    finish_all(&side_a, DMP_TX_TRANSMITTED, RESP_MS + JITTER_MS);
    CHECK(dmp_reliability_poll(&side_a.engine, RESP_MS + JITTER_MS) == DMP_OK);
    err_frames = side_b.tx.n;
    CHECK(deliver_index(&side_a, side_a.tx.n - 1, &side_b, 1U, span(META1, sizeof META1), span(NULL, 0),
                        RESP_MS + JITTER_MS, DMP_OK) == 0);
    CHECK(side_b.history[0].deadline == deadline);
    CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == 0);
    CHECK(dmp_reliability_poll(&side_b.engine, RESP_MS + JITTER_MS) == DMP_OK);
    CHECK(side_b.tx.n > err_frames);
    CHECK(parse_hold(&side_b, side_b.tx.n - 1, &view) == 0);
    CHECK(view.fields.type == DMP_TYPE_ERR);
    CHECK((view.fields.options & DMP_OPT_ACK_REQ) == 0U);
    second_seq = view.fields.seq;
    CHECK(second_seq != first_seq);
    finish_all(&side_b, DMP_TX_TRANSMITTED, RESP_MS + JITTER_MS);
    CHECK(deliver_index(&side_b, side_b.tx.n - 1, &side_a, 1U, span(META1, sizeof META1), span(NULL, 0),
                        RESP_MS + JITTER_MS, DMP_OK) == 0);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_REJECTED) == 1);
    CHECK(side_a.notes.items[0].wire_status == 4U);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RESULT) == 0);

    memset(&craft, 0, sizeof craft);
    craft.default_service = 1U;
    craft.limits = side_b.enc.limits;
    memset(&logical, 0, sizeof logical);
    logical.type = DMP_TYPE_ERR;
    logical.service_id = 1U;
    logical.own = origin_key(20U, 9U, 9U);
    logical.reply_to = origin_key(10U, 7U, 0U);
    logical.has_reply_to = true;
    logical.ack_req = false;
    logical.wire_status = 9U;
    out.data = raw;
    out.capacity = sizeof raw;
    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(submit_and_air(&side_a, 1U, span(PING, sizeof PING), 0U, &req) == 0);
    CHECK(encode_frame(&craft, &logical, out, &written) == DMP_OK);
    {
        dmp_bytes bytes = span(raw, written);
        dmp_reliability_input input;
        dmp_parse_result parsed = dmp_core_parse(bytes, &craft.limits, &view);
        CHECK(parsed.status == DMP_OK);
        input.frame = &view;
        input.service_id = 1U;
        input.plaintext = span(NULL, 0);
        input.immutable_metadata = span(META1, sizeof META1);
        CHECK(dmp_reliability_on_rx(&side_a.engine, &input, 10U) == DMP_MALFORMED);
    }
    CHECK(side_a.senders[req.slot].live == 1U);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_REJECTED) == 0);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RESULT) == 0);

    ext_n = 0U;
    value_n = 0U;
    add_uleb(value, &value_n, sizeof value, 1U);
    add_uleb(value, &value_n, sizeof value, 10U);
    add_u64le(value, &value_n, sizeof value, 7U);
    add_uleb(value, &value_n, sizeof value, 0U);
    add_tlv(ext, &ext_n, sizeof ext, 5U, value, value_n);
    value_n = 0U;
    add_uleb(value, &value_n, sizeof value, 7U);
    add_tlv(ext, &ext_n, sizeof ext, 21U, value, value_n);
    memset(&view, 0, sizeof view);
    view.fields.type = DMP_TYPE_ERR;
    view.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_EXT);
    view.fields.seq = 11U;
    view.extensions = span(ext, ext_n);
    {
        dmp_reliability_input input;
        input.frame = &view;
        input.service_id = 1U;
        input.plaintext = span(NULL, 0);
        input.immutable_metadata = span(META1, sizeof META1);
        CHECK(dmp_reliability_on_rx(&side_a.engine, &input, 11U) == DMP_MALFORMED);
    }
    CHECK(side_a.senders[req.slot].live == 1U);
    CHECK(side_a.senders[req.slot].phase == DMP_REL_PHASE_AWAIT_RECEIPT);
    return 0;
}

static int test_late_cancel_and_retention(void)
{
    dmp_reliability_handle req;
    enc_ctx craft;
    dmp_reliability_logical logical;
    uint8_t raw[MAX_MTU];
    size_t written = 0U;
    dmp_buffer out;
    dmp_frame_view view;
    int acks;
    dmp_time_ms result_deadline;
    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.result_deadline_ms = 400U;
    side_a.profile.correlation_ms = 800U;
    side_a.profile.tombstone_ms = 1200U;
    bind_node(&side_a);
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_OK);
    CHECK(submit_and_air(&side_a, 1U, span(PING, sizeof PING), 1000U, &req) == 0);
    CHECK(side_a.correlations[0].correlation_deadline == 1800U);
    CHECK(side_a.correlations[0].tombstone_deadline == 2200U);
    memset(&craft, 0, sizeof craft);
    craft.default_service = 1U;
    craft.limits = side_a.enc.limits;
    memset(&logical, 0, sizeof logical);
    logical.type = DMP_TYPE_RSP;
    logical.service_id = 1U;
    logical.own = origin_key(20U, 9U, 4U);
    logical.reply_to = origin_key(10U, 7U, 0U);
    logical.has_reply_to = true;
    logical.ack_req = true;
    logical.payload = span(PONG, sizeof PONG);
    out.data = raw;
    out.capacity = sizeof raw;
    CHECK(encode_frame(&craft, &logical, out, &written) == DMP_OK);
    {
        dmp_bytes bytes = span(raw, written);
        dmp_reliability_input input;
        dmp_parse_result parsed = dmp_core_parse(bytes, &craft.limits, &view);
        CHECK(parsed.status == DMP_OK);
        input.frame = &view;
        input.service_id = 1U;
        input.plaintext = span(PONG, sizeof PONG);
        input.immutable_metadata = span(META1, sizeof META1);
        CHECK(dmp_reliability_on_rx(&side_a.engine, &input, 1500U) == DMP_OK);
    }
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_UNKNOWN) == 1);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RESULT) == 0);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_LATE_RESULT) == 1);
    CHECK(side_a.notes.items[1].payload.size == 0U);
    CHECK(side_a.notes.items[1].key.seq == 4U);
    CHECK(side_a.notes.items[1].key.origin.origin_id == 20U);
    finish_all(&side_a, DMP_TX_TRANSMITTED, 1500U);
    CHECK(dmp_reliability_poll(&side_a.engine, 1500U) == DMP_OK);
    acks = count_type(&side_a, DMP_TYPE_ACK);
    CHECK(acks == 1);
    {
        dmp_bytes bytes = span(raw, written);
        dmp_reliability_input input;
        dmp_parse_result parsed = dmp_core_parse(bytes, &craft.limits, &view);
        CHECK(parsed.status == DMP_OK);
        input.frame = &view;
        input.service_id = 1U;
        input.plaintext = span(PONG, sizeof PONG);
        input.immutable_metadata = span(META1, sizeof META1);
        CHECK(dmp_reliability_on_rx(&side_a.engine, &input, 1600U) == DMP_OK);
        CHECK(event_count(&side_a.notes, DMP_REL_EVENT_LATE_RESULT) == 1);
        finish_all(&side_a, DMP_TX_TRANSMITTED, 1600U);
        CHECK(dmp_reliability_poll(&side_a.engine, 1600U) == DMP_OK);
        CHECK(dmp_reliability_on_rx(&side_a.engine, &input, 1800U) == DMP_OK);
        CHECK(event_count(&side_a.notes, DMP_REL_EVENT_LATE_RESULT) == 1);
        finish_all(&side_a, DMP_TX_TRANSMITTED, 1800U);
        CHECK(dmp_reliability_poll(&side_a.engine, 1800U) == DMP_OK);
        acks = count_type(&side_a, DMP_TYPE_ACK);
        CHECK(dmp_reliability_on_rx(&side_a.engine, &input, 2200U) == DMP_OK);
    }
    CHECK(count_type(&side_a, DMP_TYPE_ACK) == acks);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RESULT) == 0);
    CHECK(side_a.correlations[0].live == 0U);

    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PING, sizeof PING), 0U, 0U, &req) ==
          DMP_OK);
    CHECK(dmp_reliability_cancel(&side_a.engine, req, 0U) == DMP_OK);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_LOCAL_UNSENT) == 1);
    CHECK(side_a.tx.submits == 0);
    CHECK(dmp_reliability_cancel(&side_a.engine, req, 1U) == DMP_STALE_HANDLE);

    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(submit_and_air(&side_a, 1U, span(PING, sizeof PING), 0U, &req) == 0);
    CHECK(dmp_reliability_cancel(&side_a.engine, req, 1U) == DMP_OK);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_UNKNOWN) == 1);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_LOCAL_UNSENT) == 0);

    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PING, sizeof PING), 0U, 0U, &req) ==
          DMP_OK);
    CHECK(dmp_reliability_poll(&side_a.engine, 0U) == DMP_OK);
    side_a.tx.cancel_inline = 1;
    side_a.tx.cancel_outcome = DMP_TX_CANCELLED_UNSENT;
    CHECK(dmp_reliability_cancel(&side_a.engine, req, 0U) == DMP_OK);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_LOCAL_UNSENT) == 1);
    CHECK(side_a.notes.during_tx == 0);

    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PING, sizeof PING), 0U, 0U, &req) ==
          DMP_OK);
    CHECK(dmp_reliability_poll(&side_a.engine, 0U) == DMP_OK);
    finish_all(&side_a, DMP_TX_POSSIBLY_TRANSMITTED, 0U);
    CHECK(dmp_reliability_poll(&side_a.engine, 0U) == DMP_OK);
    CHECK(side_a.senders[req.slot].possibly_sent == 1U);
    CHECK(dmp_reliability_cancel(&side_a.engine, req, 1U) == DMP_OK);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_UNKNOWN) == 1);

    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PING, sizeof PING), 0U, 0U, &req) ==
          DMP_OK);
    CHECK(dmp_reliability_poll(&side_a.engine, 0U) == DMP_OK);
    finish_all(&side_a, DMP_TX_FAILED_UNSENT, 0U);
    CHECK(dmp_reliability_poll(&side_a.engine, 0U) == DMP_OK);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_UNKNOWN) == 0);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_LOCAL_UNSENT) == 0);
    CHECK(side_a.senders[req.slot].possibly_sent == 0U);

    CHECK(boot(&side_b, 1, 0) == 0);
    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(submit_and_air(&side_a, 1U, span(PING, sizeof PING), 0U, &req) == 0);
    CHECK(deliver_index(&side_a, 0, &side_b, 1U, span(META1, sizeof META1), span(NULL, 0), 0U,
                        DMP_OK) == 0);
    CHECK(dmp_reliability_complete(&side_b.engine, side_b.notes.items[0].handle, false, 0U,
                                   span(PONG, sizeof PONG), 0U) == DMP_OK);
    result_deadline = side_b.results[0].deadline;
    CHECK(result_deadline == CACHE_MS);
    CHECK(dmp_reliability_poll(&side_b.engine, 0U) == DMP_OK);
    finish_all(&side_b, DMP_TX_TRANSMITTED, 0U);
    CHECK(dmp_reliability_poll(&side_b.engine, 0U) == DMP_OK);
    CHECK(deliver_index(&side_a, 0, &side_b, 1U, span(META1, sizeof META1), span(NULL, 0), 100U,
                        DMP_OK) == 0);
    CHECK(side_b.results[0].deadline == result_deadline);
    CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == 1);
    {
        uint32_t seqs[8];
        int nseq = 0;
        int i;
        for (i = 0; i < side_b.tx.n; i++) {
            CHECK(parse_hold(&side_b, i, &view) == 0);
            if (view.fields.type == DMP_TYPE_RSP && nseq < 8) {
                seqs[nseq++] = view.fields.seq;
            }
        }
        CHECK(nseq >= 1);
        CHECK(dmp_reliability_poll(&side_b.engine, CACHE_MS) == DMP_OK);
        CHECK(side_b.results[0].live == 0U);
        CHECK(side_b.history[0].live == 1U);
        CHECK(deliver_index(&side_a, 0, &side_b, 1U, span(META1, sizeof META1), span(NULL, 0),
                            CACHE_MS, DMP_OK) == 0);
        CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == 1);
        for (i = 0; i < side_b.tx.n; i++) {
            CHECK(parse_hold(&side_b, i, &view) == 0);
            if (view.fields.type == DMP_TYPE_RSP) {
                int seen = 0;
                int s;
                for (s = 0; s < nseq; s++) {
                    if (seqs[s] == view.fields.seq) {
                        seen = 1;
                    }
                }
                CHECK(seen == 1);
            }
        }
    }
    return 0;
}

static int test_gate_queue_and_ack_bypass(void)
{
    dmp_reliability_handle first;
    dmp_reliability_handle second;
    dmp_reliability_handle inbound;
    int submits;
    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.operations_per_service = 2U;
    side_a.profile.application_queue_slots = 2U;
    bind_node(&side_a);
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_OK);
    CHECK(submit_and_air(&side_a, 1U, span(PING, sizeof PING), 0U, &first) == 0);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PONG, sizeof PONG), 0U, 0U, &second) ==
          DMP_OK);
    submits = side_a.tx.submits;
    CHECK(dmp_reliability_poll(&side_a.engine, 0U) == DMP_OK);
    CHECK(side_a.tx.submits == submits);
    CHECK(side_a.senders[second.slot].phase == DMP_REL_PHASE_QUEUED);
    CHECK(boot(&side_b, 1, 0) == 0);
    CHECK(deliver_index(&side_a, 0, &side_b, 1U, span(META1, sizeof META1), span(NULL, 0), 0U,
                        DMP_OK) == 0);
    CHECK(dmp_reliability_poll(&side_b.engine, RECEIPT_DELAY) == DMP_OK);
    finish_all(&side_b, DMP_TX_TRANSMITTED, RECEIPT_DELAY);
    CHECK(deliver_index(&side_b, 0, &side_a, 1U, span(META1, sizeof META1), span(NULL, 0),
                        RECEIPT_DELAY, DMP_OK) == 0);
    CHECK(side_a.senders[first.slot].phase == DMP_REL_PHASE_AWAIT_RESULT);
    CHECK(dmp_reliability_poll(&side_a.engine, RECEIPT_DELAY) == DMP_OK);
    CHECK(side_a.tx.submits == submits + 1);
    CHECK(side_a.senders[second.slot].phase != DMP_REL_PHASE_QUEUED);

    CHECK(prepare(&side_b, 1, 0) == 0);
    side_b.profile.adapter_slots = 2U;
    side_b.profile.control_slots = 1U;
    side_b.profile.application_queue_slots = 1U;
    side_b.profile.operations_per_service = 4U;
    side_b.profile.sender_slots = 4U;
    bind_node(&side_b);
    CHECK(dmp_reliability_init(&side_b.engine, &side_b.storage) == DMP_OK);
    CHECK(boot(&side_a, 0, 0) == 0);
    CHECK(dmp_reliability_submit_req(&side_b.engine, 1U, span(PING, sizeof PING), 0U, 0U, &first) ==
          DMP_OK);
    CHECK(dmp_reliability_poll(&side_b.engine, 0U) == DMP_OK);
    CHECK(side_b.senders[first.slot].phase == DMP_REL_PHASE_TRANSMITTING);
    CHECK(dmp_reliability_submit_req(&side_b.engine, 2U, span(PONG, sizeof PONG), 0U, 0U, &second) ==
          DMP_OK);
    CHECK(dmp_reliability_submit_req(&side_b.engine, 2U, span(PING, sizeof PING), 0U, 0U, &inbound) ==
          DMP_BUSY);
    CHECK(submit_and_air(&side_a, 1U, span(PING, sizeof PING), 0U, &inbound) == 0);
    CHECK(deliver_index(&side_a, 0, &side_b, 1U, span(META1, sizeof META1), span(NULL, 0), 0U,
                        DMP_OK) == 0);
    CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == 1);
    CHECK(dmp_reliability_poll(&side_b.engine, RECEIPT_DELAY) == DMP_OK);
    CHECK(count_type(&side_b, DMP_TYPE_ACK) == 1);
    CHECK(side_b.senders[first.slot].tx_live);
    CHECK(side_b.senders[second.slot].attempts == 0U);
    CHECK(side_b.senders[second.slot].phase == DMP_REL_PHASE_QUEUED);
    return 0;
}

static int test_buffer_ownership(void)
{
    dmp_reliability_handle req;
    int calls;
    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.tx_borrow = false;
    side_a.profile.synchronous_completion = false;
    bind_node(&side_a);
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_OK);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PING, sizeof PING), 0U, JITTER_MS,
                                     &req) == DMP_OK);
    CHECK(dmp_reliability_poll(&side_a.engine, 0U) == DMP_OK);
    CHECK(side_a.enc.calls == 1);
    CHECK(side_a.senders[req.slot].phase == DMP_REL_PHASE_TRANSMITTING);
    CHECK(side_a.senders[req.slot].tx_live);
    CHECK(memcmp(side_a.tx.hold[0].borrowed, side_a.tx.hold[0].frame, side_a.tx.hold[0].len) == 0);
    CHECK(dmp_reliability_poll(&side_a.engine, 0U) == DMP_OK);
    CHECK(side_a.enc.calls == 1);
    CHECK(memcmp(side_a.tx.hold[0].borrowed, side_a.tx.hold[0].frame, side_a.tx.hold[0].len) == 0);
    finish_all(&side_a, DMP_TX_TRANSMITTED, 0U);
    CHECK(dmp_reliability_poll(&side_a.engine, 0U) == DMP_OK);
    calls = side_a.enc.calls;
    CHECK(dmp_reliability_poll(&side_a.engine, RESP_MS + JITTER_MS) == DMP_OK);
    CHECK(side_a.enc.calls == calls + 1);
    CHECK(side_a.notes.during_tx == 0);

    CHECK(prepare(&side_a, 0, 0) == 0);
    side_a.profile.tx_borrow = true;
    side_a.profile.synchronous_completion = true;
    side_a.tx.inline_complete = 1;
    side_a.tx.inline_outcome = DMP_TX_TRANSMITTED;
    bind_node(&side_a);
    CHECK(dmp_reliability_init(&side_a.engine, &side_a.storage) == DMP_OK);
    CHECK(dmp_reliability_submit_req(&side_a.engine, 1U, span(PING, sizeof PING), 0U, 0U, &req) ==
          DMP_OK);
    CHECK(dmp_reliability_poll(&side_a.engine, 0U) == DMP_OK);
    CHECK(side_a.tx.max_depth == 1);
    CHECK(side_a.tx.pin_ok == 1);
    CHECK(side_a.notes.during_tx == 0);
    CHECK(side_a.senders[req.slot].phase == DMP_REL_PHASE_AWAIT_RECEIPT);
    CHECK(side_a.senders[req.slot].possibly_sent == 1U);
    return 0;
}

static int test_secured_provisional(void)
{
    dmp_reliability_handle req;
    dmp_frame_view view;
    dmp_bytes reply;
    dmp_bytes plain;
    dmp_message_key resolved;
    uint8_t plain_buf[sizeof PONG];
    uint64_t first_pn;
    uint64_t second_pn;
    /* Provisional: authenticated context stub plus compact REPLY_TO only. */
    CHECK(boot(&side_a, 0, 1) == 0);
    CHECK(boot(&side_b, 1, 1) == 0);
    CHECK(side_a.ids[side_a.handle.slot].security == 1U);
    CHECK(submit_and_air(&side_a, 1U, span(PING, sizeof PING), 0U, &req) == 0);
    CHECK(parse_hold(&side_a, 0, &view) == 0);
    CHECK((view.fields.options & DMP_OPT_SECURITY) != 0U);
    first_pn = view.fields.security.pn;
    CHECK(dmp_reliability_poll(&side_a.engine, RESP_MS + JITTER_MS) == DMP_OK);
    CHECK(parse_hold(&side_a, side_a.tx.n - 1, &view) == 0);
    second_pn = view.fields.security.pn;
    CHECK(second_pn == first_pn + 1U);
    CHECK(view.fields.seq == 0U);
    finish_all(&side_a, DMP_TX_TRANSMITTED, RESP_MS + JITTER_MS);
    CHECK(dmp_reliability_poll(&side_a.engine, RESP_MS + JITTER_MS) == DMP_OK);
    memcpy(plain_buf, PING, sizeof PING);
    plain = span(plain_buf, sizeof PING);
    CHECK(plain.data != side_a.tx.hold[0].frame);
    CHECK(deliver_index(&side_a, 0, &side_b, 1U, span(META1, sizeof META1), plain, 0U, DMP_OK) == 0);
    CHECK(event_count(&side_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED) == 1);
    CHECK(memcmp(side_b.notes.items[0].payload.data, plain_buf, sizeof PING) == 0);
    CHECK(dmp_reliability_complete(&side_b.engine, side_b.notes.items[0].handle, false, 0U,
                                   span(PONG, sizeof PONG), 0U) == DMP_OK);
    CHECK(dmp_reliability_poll(&side_b.engine, 0U) == DMP_OK);
    CHECK(parse_hold(&side_b, 0, &view) == 0);
    CHECK(view.fields.type == DMP_TYPE_RSP);
    CHECK((view.fields.options & DMP_OPT_SECURITY) != 0U);
    CHECK(extension_value(&view, 1U, &reply) == 0);
    CHECK(reply.size == 1U);
    CHECK(reply.data[0] == 0U);
    CHECK(dmp_identity_reply_to(&view, &side_a.table, side_a.handle, 0U, &resolved) == DMP_OK);
    CHECK(resolved.origin.namespace_id == 1U);
    CHECK(resolved.origin.origin_id == 10U);
    CHECK(resolved.origin.epoch == 7U);
    CHECK(resolved.seq == 0U);
    memcpy(plain_buf, PONG, sizeof PONG);
    plain = span(plain_buf, sizeof PONG);
    finish_all(&side_b, DMP_TX_TRANSMITTED, 0U);
    CHECK(deliver_index(&side_b, 0, &side_a, 1U, span(META1, sizeof META1), plain, 0U, DMP_OK) == 0);
    CHECK(event_count(&side_a.notes, DMP_REL_EVENT_RESULT) == 1);
    CHECK(memcmp(side_a.notes.items[0].payload.data, PONG, sizeof PONG) == 0);
    CHECK(side_a.notes.during_tx == 0);
    return 0;
}

int main(void)
{
    int failed = 0;
    failed |= test_init_and_close();
    failed |= test_quota_and_validation();
    failed |= test_substitution_and_identity();
    failed |= test_receipt_loss_and_retry();
    failed |= test_duplicate_metadata_and_service();
    failed |= test_rejection_and_status();
    failed |= test_late_cancel_and_retention();
    failed |= test_gate_queue_and_ack_bypass();
    failed |= test_buffer_ownership();
    failed |= test_secured_provisional();
    if (failed != 0) {
        (void)fprintf(stderr, "reliability tests failed\n");
        return 1;
    }
    return 0;
}
