#include "dmp/reassembly.h"
#include "dmp/reliability.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(DMP_PROFILE_ADMIT_SCRATCH_BYTES) || defined(DMP_PROFILE_MAX_BYTES)
#error removed profile admission constants
#endif

#ifndef DMP_SOURCE_DIR
#error DMP_SOURCE_DIR is required
#endif

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,     \
                          __LINE__, #condition);                             \
            return 1;                                                        \
        }                                                                    \
    } while (0)

enum {
    DIRECT_MESSAGE = 1024,
    DIRECT_FRAGMENTS = 16,
    DIRECT_CHUNK = 64,
    DIRECT_MTU = 263,
    DIRECT_SENDER = 4,
    DIRECT_RESULT = 4,
    DIRECT_HISTORY = 8,
    DIRECT_CORRELATION = 4,
    DIRECT_ASSEMBLY = 1,
    DIRECT_TOMBSTONES = 16,
    DIRECT_ADAPTER = 3,
    DIRECT_CONTROL = 2
};

static void valid_config(dmp_config *config)
{
    unsigned i;
    memset(config, 0, sizeof *config);
    for (i = 0U; i < DMP_PROFILE_SHA256_BYTES; i++) {
        config->sha256[i] = (uint8_t)(0xA0U + i);
    }
    config->namespace_id = 1U;
    config->node_id[0] = 10U;
    config->node_id[1] = 20U;
    config->default_service = 1U;
    config->service_id[0] = 1U;
    config->service_id[1] = 2U;
    config->peers = 1U;
    config->operations_per_service = 1U;
    config->assemblies_per_peer = 1U;
    config->assembly_tombstones_per_peer = 1U;
    config->sender_slots = 1U;
    config->assembly_slots = 1U;
    config->assembly_tombstone_slots = 1U;
    config->result_slots = 1U;
    config->history_slots = 1U;
    config->correlation_slots = 1U;
    config->adapter_slots = 2U;
    config->application_queue_slots = 1U;
    config->control_slots = 1U;
    config->message_bytes = 64U;
    config->fragments = 2U;
    config->chunk_bytes = 16U;
    config->encoded_mtu = 32U;
    config->forward_mtu = 32U;
    config->return_mtu = 32U;
    config->tx_borrow = true;
    config->synchronous_completion = false;
}

#define REJECT(setup, status)                                                \
    do {                                                                     \
        dmp_config in_;                                                      \
        dmp_admitted_profile out_;                                           \
        dmp_admitted_profile saved_;                                         \
        valid_config(&in_);                                                  \
        setup;                                                               \
        memset(&out_, 0x3C, sizeof out_);                                    \
        saved_ = out_;                                                       \
        CHECK(dmp_config_admit(&in_, &out_) == (status));                    \
        if ((status) == DMP_OK) {                                            \
            CHECK(memcmp(&in_, &out_, sizeof in_) == 0);                     \
        } else {                                                             \
            CHECK(memcmp(&out_, &saved_, sizeof out_) == 0);                 \
        }                                                                    \
    } while (0)

static int test_arguments_and_copy(void)
{
    dmp_config in;
    dmp_admitted_profile out;
    dmp_admitted_profile same;
    dmp_admitted_profile saved;
    unsigned i;

    memset(&out, 0x3C, sizeof out);
    saved = out;
    CHECK(dmp_config_admit(NULL, &out) == DMP_INVALID_ARGUMENT);
    CHECK(memcmp(&out, &saved, sizeof out) == 0);
    valid_config(&in);
    CHECK(dmp_config_admit(&in, NULL) == DMP_INVALID_ARGUMENT);

    memset(&same, 0xA5, sizeof same);
    saved = same;
    CHECK(dmp_config_admit(&same, &same) == DMP_INVALID_ARGUMENT);
    CHECK(memcmp(&same, &saved, sizeof same) == 0);

    valid_config(&in);
    memset(&out, 0x3C, sizeof out);
    CHECK(dmp_config_admit(&in, &out) == DMP_OK);
    CHECK(memcmp(&in, &out, sizeof in) == 0);
    for (i = 0U; i < DMP_PROFILE_SHA256_BYTES; i++) {
        CHECK(out.sha256[i] == (uint8_t)(0xA0U + i));
    }
    CHECK(out.tx_borrow == true);
    CHECK(out.synchronous_completion == false);

    REJECT(in_.message_bytes = 0U, DMP_INVALID_ARGUMENT);
    REJECT(in_.chunk_bytes = 0U, DMP_INVALID_ARGUMENT);
    REJECT(in_.encoded_mtu = 0U, DMP_INVALID_ARGUMENT);
    REJECT(in_.fragments = 0U, DMP_INVALID_ARGUMENT);
    REJECT(in_.fragments = 33U, DMP_INVALID_ARGUMENT);
    REJECT(in_.fragments = 1U, DMP_OK);
    REJECT(in_.fragments = 32U, DMP_OK);
    REJECT(in_.recovery[0] = DMP_PROFILE_RECOVERY_SELECTIVE32, DMP_UNSUPPORTED);
    REJECT(in_.recovery[0] = DMP_PROFILE_RECOVERY_SELECTIVE32; in_.burst_span_ms = 1U;
           in_.forward_delay_ms = 1U; in_.return_delay_ms = 1U; in_.feedback_guard_ms = 1U;
           in_.feedback_delay_ms = 1U; in_.record_margin_ms = 1U; in_.max_probes = 2U;
           in_.max_status = 1U; in_.max_bursts = 2U; in_.response_timeout_ms = 6U;
           in_.send_horizon_ms = 10U; in_.collect_ms = 4U; in_.assembly_ms = 12U,
           DMP_UNSUPPORTED);
    REJECT(in_.recovery[0] = DMP_PROFILE_RECOVERY_SELECTIVE32; in_.burst_span_ms = 1U;
           in_.forward_delay_ms = 1U; in_.return_delay_ms = 1U; in_.feedback_guard_ms = 1U;
           in_.feedback_delay_ms = 1U; in_.record_margin_ms = 1U; in_.max_probes = 1U;
           in_.max_status = 1U; in_.max_bursts = 2U; in_.response_timeout_ms = 6U;
           in_.send_horizon_ms = 10U; in_.collect_ms = 4U; in_.assembly_ms = 12U, DMP_OK);
    REJECT(in_.sender_slots = 0x80000000U, DMP_INVALID_ARGUMENT);
    REJECT(in_.result_slots = 0x80000000U, DMP_INVALID_ARGUMENT);
    REJECT(in_.history_slots = 16843010U, DMP_INVALID_ARGUMENT);
    REJECT(in_.correlation_slots = 16843010U, DMP_INVALID_ARGUMENT);
    REJECT(in_.adapter_slots = 0x80000000U, DMP_INVALID_ARGUMENT);
    REJECT(in_.assembly_slots = 0x80000000U, DMP_INVALID_ARGUMENT);
    REJECT(in_.assembly_slots = 16843010U; in_.message_bytes = 64U;
           in_.chunk_bytes = 16U, DMP_INVALID_ARGUMENT);
    REJECT(in_.peers = 65536U; in_.assembly_tombstones_per_peer = 65536U;
           in_.assembly_tombstone_slots = 0U, DMP_INVALID_ARGUMENT);

    REJECT(in_.default_service = 0U, DMP_UNSUPPORTED);
    REJECT(in_.default_service = 3U, DMP_UNSUPPORTED);
    REJECT(in_.service_id[0] = 1U; in_.service_id[1] = 1U; in_.default_service = 1U,
           DMP_UNSUPPORTED);
    REJECT(in_.chunk_bytes = in_.message_bytes, DMP_UNSUPPORTED);
    REJECT(in_.chunk_bytes = in_.message_bytes + 1U, DMP_UNSUPPORTED);
    REJECT(in_.peers = 0U, DMP_UNSUPPORTED);
    REJECT(in_.assembly_tombstones_per_peer = 0U, DMP_UNSUPPORTED);
    REJECT(in_.peers = 2U; in_.assembly_tombstone_slots = 1U, DMP_UNSUPPORTED);
    REJECT(in_.adapter_slots = 2U; in_.control_slots = 2U, DMP_UNSUPPORTED);
    REJECT(in_.adapter_slots = 1U; in_.control_slots = 2U, DMP_UNSUPPORTED);
    REJECT(in_.adapter_slots = 1U; in_.control_slots = 1U, DMP_UNSUPPORTED);
    REJECT(in_.control_slots = 0U, DMP_UNSUPPORTED);
    REJECT(in_.default_service = 2U, DMP_OK);
    REJECT(in_.peers = 2U; in_.assembly_tombstone_slots = 2U, DMP_OK);
    return 0;
}

static int header_closed(void)
{
    FILE *in;
    char chunk[1024];
    size_t n;
    int saw_new = 0;
    char window[2048];
    size_t filled = 0U;
    static const char scratch[] = "419936";
    static const char old_fn[] = "dmp_profile_admit";
    static const char old_scratch[] = "DMP_PROFILE_ADMIT_SCRATCH_BYTES";
    static const char old_max[] = "DMP_PROFILE_MAX_BYTES";
    static const char new_fn[] = "dmp_config_admit";

    in = fopen(DMP_SOURCE_DIR "/include/dmp/identity.h", "rb");
    CHECK(in != NULL);
    memset(window, 0, sizeof window);
    while ((n = fread(chunk, 1U, sizeof chunk, in)) != 0U) {
        size_t i;
        for (i = 0U; i < n; i++) {
            if (filled + 1U >= sizeof window) {
                memmove(window, window + filled / 2U, filled - filled / 2U);
                filled -= filled / 2U;
            }
            window[filled++] = chunk[i];
            window[filled] = '\0';
            if (strstr(window, scratch) != NULL || strstr(window, old_fn) != NULL ||
                strstr(window, old_scratch) != NULL || strstr(window, old_max) != NULL) {
                (void)fclose(in);
                (void)fprintf(stderr, "public header still exposes removed admission API\n");
                return 1;
            }
            if (strstr(window, new_fn) != NULL) {
                saw_new = 1;
            }
        }
    }
    CHECK(ferror(in) == 0);
    (void)fclose(in);
    CHECK(saw_new == 1);
    return 0;
}

static void direct_limits(dmp_config *config, uint32_t adapter_slots)
{
    memset(config, 0, sizeof *config);
    config->namespace_id = 1U;
    config->node_id[0] = 10U;
    config->node_id[1] = 20U;
    config->default_service = 1U;
    config->service_id[0] = 1U;
    config->service_id[1] = 2U;
    config->peers = 1U;
    config->operations_per_service = 1U;
    config->assemblies_per_peer = 1U;
    config->assembly_tombstones_per_peer = DIRECT_TOMBSTONES;
    config->sender_slots = DIRECT_SENDER;
    config->assembly_slots = DIRECT_ASSEMBLY;
    config->assembly_tombstone_slots = DIRECT_TOMBSTONES;
    config->result_slots = DIRECT_RESULT;
    config->history_slots = DIRECT_HISTORY;
    config->correlation_slots = DIRECT_CORRELATION;
    config->adapter_slots = adapter_slots;
    config->application_queue_slots = 2U;
    config->control_slots = DIRECT_CONTROL;
    config->message_bytes = DIRECT_MESSAGE;
    config->fragments = DIRECT_FRAGMENTS;
    config->chunk_bytes = DIRECT_CHUNK;
    config->encoded_mtu = DIRECT_MTU;
    config->forward_mtu = 256U;
    config->return_mtu = 256U;
}

static uint64_t eight_sum(const dmp_config *config, int include_assembly)
{
    uint64_t sum = (uint64_t)config->sender_slots * config->message_bytes +
                   (uint64_t)config->result_slots * config->message_bytes +
                   config->message_bytes +
                   (uint64_t)config->history_slots * (uint64_t)DMP_MAX_HEADER_BYTES +
                   (uint64_t)config->correlation_slots * (uint64_t)DMP_MAX_HEADER_BYTES +
                   (uint64_t)config->adapter_slots * config->encoded_mtu;
    if (include_assembly) {
        sum += (uint64_t)config->assembly_slots * config->message_bytes +
               (uint64_t)config->assembly_slots * (uint64_t)DMP_REASSEMBLY_METADATA_BYTES;
    }
    return sum;
}

static size_t state_bytes(int reassembly, uint32_t assembly_slots)
{
    size_t bytes = sizeof(dmp_identity_slot) + sizeof(dmp_reliability);
    if (reassembly) {
        bytes += sizeof(dmp_reassembly_slot) * (size_t)assembly_slots + sizeof(dmp_reassembly);
    }
    return bytes;
}

enum {
    BUDGET_SLOTS = 8,
    BUDGET_MSG = 1024,
    BUDGET_MTU = 1088,
    BUDGET_ADAPTERS = 4,
    BUDGET_TX = 8,
    BUDGET_NOTES = 8
};

typedef struct {
    uint32_t budget;
    int reassembly;
    uint32_t message_bytes;
    uint32_t fragments;
    uint32_t chunk_bytes;
    uint32_t encoded_mtu;
    uint32_t sender_slots;
    uint32_t result_slots;
    uint32_t history_slots;
    uint32_t correlation_slots;
    uint32_t adapter_slots;
    uint32_t control_slots;
    uint32_t application_queue_slots;
    uint32_t assembly_slots;
    uint32_t tombstone_slots;
    uint32_t assemblies_per_peer;
    uint32_t tombstones_per_peer;
    uint32_t exchange_bytes;
    uint32_t assembly_total;
    uint64_t expect_sum;
    const char *capability;
} budget_spec;

typedef struct {
    int depth;
    int n;
    uint32_t mtu;
    struct {
        int used;
        int done;
        dmp_tx_token token;
        dmp_tx_complete_fn complete;
        void *owner;
        uint8_t frame[BUDGET_MTU];
        size_t len;
    } hold[BUDGET_TX];
} budget_tx;

typedef struct {
    int count;
    int during_tx;
    int *depth;
    dmp_reliability_notice items[BUDGET_NOTES];
    uint8_t bytes[BUDGET_NOTES][BUDGET_MSG];
} budget_notes;

typedef struct {
    uint32_t default_service;
    dmp_core_limits limits;
    uint8_t ext[64];
} budget_enc;

typedef struct {
    dmp_reliability engine;
    dmp_admitted_profile profile;
    dmp_identity_slot ids[2];
    dmp_identity_table table;
    dmp_identity_handle handle;
    dmp_transport transport;
    budget_tx tx;
    budget_enc enc;
    budget_notes notes;
    dmp_reliability_storage storage;
    dmp_reliability_sender_slot senders[BUDGET_SLOTS];
    uint8_t sender_payload[BUDGET_SLOTS * BUDGET_MSG];
    dmp_reliability_result_slot results[BUDGET_SLOTS];
    uint8_t result_payload[BUDGET_SLOTS * BUDGET_MSG];
    dmp_reliability_history_slot history[BUDGET_SLOTS];
    dmp_reliability_correlation_slot correlations[BUDGET_SLOTS];
    uint8_t history_metadata[BUDGET_SLOTS * DMP_RELIABILITY_METADATA_BYTES];
    uint8_t correlation_metadata[BUDGET_SLOTS * DMP_RELIABILITY_METADATA_BYTES];
    dmp_reliability_adapter_slot adapters[BUDGET_ADAPTERS];
    uint8_t frames[BUDGET_ADAPTERS * BUDGET_MTU];
    uint8_t receive_payload[BUDGET_MSG];
} budget_node;

static budget_node budget_a;
static budget_node budget_b;

static const uint8_t BUDGET_META[] = {0xA1, 0x5C};

static dmp_bytes budget_span(const void *data, size_t size)
{
    dmp_bytes bytes;
    bytes.data = (const uint8_t *)data;
    bytes.size = size;
    return bytes;
}

static void budget_add_uleb(uint8_t *data, size_t *n, size_t cap, uint32_t value)
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

static void budget_add_u64le(uint8_t *data, size_t *n, size_t cap, uint64_t value)
{
    unsigned i;
    for (i = 0U; i < 8U; i++) {
        if (*n < cap) {
            data[(*n)++] = (uint8_t)(value & 0xffU);
        }
        value >>= 8U;
    }
}

static void budget_add_tlv(uint8_t *data, size_t *n, size_t cap, uint32_t tag, const uint8_t *value,
                           size_t value_n)
{
    size_t i;
    budget_add_uleb(data, n, cap, tag);
    budget_add_uleb(data, n, cap, (uint32_t)value_n);
    for (i = 0U; i < value_n; i++) {
        if (*n < cap) {
            data[(*n)++] = value[i];
        }
    }
}

static dmp_status budget_encode(void *context, const dmp_reliability_logical *logical, dmp_buffer out,
                                size_t *written)
{
    budget_enc *enc = context;
    dmp_frame_spec spec;
    uint8_t value[32];
    size_t value_n;
    size_t ext_n = 0U;

    if (enc == NULL || logical == NULL || written == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)logical->type;
    spec.fields.options = DMP_OPT_SEQ;
    spec.fields.seq = logical->own.seq;
    if (logical->ack_req) {
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_ACK_REQ);
    }
    if (logical->has_reply_to) {
        value_n = 0U;
        budget_add_uleb(value, &value_n, sizeof value, logical->reply_to.origin.namespace_id);
        budget_add_uleb(value, &value_n, sizeof value, logical->reply_to.origin.origin_id);
        budget_add_u64le(value, &value_n, sizeof value, logical->reply_to.origin.epoch);
        budget_add_uleb(value, &value_n, sizeof value, logical->reply_to.seq);
        budget_add_tlv(enc->ext, &ext_n, sizeof enc->ext, 5U, value, value_n);
    }
    if (logical->service_id != 0U && logical->service_id != enc->default_service) {
        value_n = 0U;
        budget_add_uleb(value, &value_n, sizeof value, logical->service_id);
        budget_add_tlv(enc->ext, &ext_n, sizeof enc->ext, 17U, value, value_n);
    }
    if (ext_n != 0U) {
        spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_EXT);
        spec.extensions.data = enc->ext;
        spec.extensions.size = ext_n;
    }
    spec.payload = logical->payload;
    return dmp_core_encode(&spec, &enc->limits, out, written);
}

static dmp_status budget_submit(void *context, const dmp_tx_submission *submission)
{
    budget_tx *tx = context;
    if (tx == NULL || submission == NULL || submission->frame.data == NULL ||
        submission->frame.size > tx->mtu || submission->frame.size > BUDGET_MTU) {
        return DMP_INVALID_ARGUMENT;
    }
    if (tx->n >= BUDGET_TX) {
        return DMP_BUSY;
    }
    tx->depth++;
    tx->hold[tx->n].used = 1;
    tx->hold[tx->n].done = 0;
    tx->hold[tx->n].token = submission->token;
    tx->hold[tx->n].complete = submission->complete;
    tx->hold[tx->n].owner = submission->owner;
    tx->hold[tx->n].len = submission->frame.size;
    memcpy(tx->hold[tx->n].frame, submission->frame.data, submission->frame.size);
    tx->n++;
    tx->depth--;
    return DMP_OK;
}

static dmp_status budget_cancel(void *context, dmp_tx_token token)
{
    (void)context;
    (void)token;
    return DMP_OK;
}

static void budget_on_notice(void *user, const dmp_reliability_notice *notice)
{
    budget_notes *log = user;
    dmp_reliability_notice copy;
    if (log->depth != NULL && *log->depth > 0) {
        log->during_tx++;
    }
    if (log->count >= BUDGET_NOTES || notice->payload.size > BUDGET_MSG) {
        return;
    }
    copy = *notice;
    if (notice->payload.size > 0U && notice->payload.data != NULL) {
        memcpy(log->bytes[log->count], notice->payload.data, notice->payload.size);
        copy.payload.data = log->bytes[log->count];
        copy.payload.size = notice->payload.size;
    } else {
        copy.payload.data = NULL;
        copy.payload.size = 0U;
    }
    log->items[log->count++] = copy;
}

static void budget_finish(budget_node *node, dmp_time_ms when)
{
    int i;
    for (i = 0; i < node->tx.n; i++) {
        if (node->tx.hold[i].used && !node->tx.hold[i].done) {
            node->tx.hold[i].done = 1;
            node->tx.depth++;
            node->tx.hold[i].complete(node->tx.hold[i].owner, node->tx.hold[i].token,
                                      DMP_TX_TRANSMITTED, when);
            node->tx.depth--;
        }
    }
}

static int budget_deliver(budget_node *src, int index, budget_node *dst, dmp_time_ms now)
{
    dmp_frame_view view;
    dmp_reliability_input input;
    dmp_bytes raw;
    dmp_core_limits limits;
    dmp_parse_result parsed;
    raw.data = src->tx.hold[index].frame;
    raw.size = src->tx.hold[index].len;
    limits.max_frame_bytes = src->profile.encoded_mtu;
    limits.max_message_bytes = src->profile.message_bytes;
    limits.max_fragments = src->profile.fragments < 2U ? 2U : src->profile.fragments;
    parsed = dmp_core_parse(raw, &limits, &view);
    CHECK(parsed.status == DMP_OK);
    memset(&input, 0, sizeof input);
    input.frame = &view;
    input.service_id = 1U;
    input.plaintext = view.payload;
    input.immutable_metadata = budget_span(BUDGET_META, sizeof BUDGET_META);
    CHECK(dmp_reliability_on_rx(&dst->engine, &input, now) == DMP_OK);
    return 0;
}

static int budget_notice(const budget_notes *log, dmp_reliability_event event, const uint8_t *expect,
                         size_t expect_n)
{
    int i;
    for (i = 0; i < log->count; i++) {
        if (log->items[i].event == event && log->items[i].payload.size == expect_n &&
            (expect_n == 0U || memcmp(log->items[i].payload.data, expect, expect_n) == 0)) {
            return i;
        }
    }
    return -1;
}

static int budget_boot(budget_node *node, const dmp_admitted_profile *profile, int responder)
{
    dmp_identity_context_config config;
    dmp_reliability_storage *storage;
    memset(node, 0, sizeof *node);
    node->profile = *profile;
    node->profile.tx_borrow = false;
    node->profile.synchronous_completion = false;
    CHECK(dmp_identity_table_init(&node->table, node->ids, 2U) == DMP_OK);
    memset(&config, 0, sizeof config);
    config.local.namespace_id = 1U;
    config.local.origin_id = responder ? 20U : 10U;
    config.local.epoch = responder ? 9U : 7U;
    config.peer.namespace_id = 1U;
    config.peer.origin_id = responder ? 10U : 20U;
    config.peer.epoch = responder ? 7U : 9U;
    config.security = 0U;
    CHECK(dmp_identity_context_open(&node->table, &config, &node->handle) == DMP_OK);
    node->tx.mtu = node->profile.encoded_mtu;
    node->notes.depth = &node->tx.depth;
    node->enc.default_service = node->profile.default_service;
    node->enc.limits.max_frame_bytes = node->profile.encoded_mtu;
    node->enc.limits.max_message_bytes = node->profile.message_bytes;
    node->enc.limits.max_fragments = node->profile.fragments < 2U ? 2U : node->profile.fragments;
    node->transport.context = &node->tx;
    node->transport.submit = budget_submit;
    node->transport.cancel = budget_cancel;
    node->transport.caps.max_frame_bytes = node->profile.encoded_mtu;
    node->transport.caps.ownership = DMP_TX_COPY;
    node->transport.caps.synchronous_completion = false;
    storage = &node->storage;
    storage->profile = &node->profile;
    storage->identity = &node->table;
    storage->context = node->handle;
    storage->transport = &node->transport;
    storage->encode = budget_encode;
    storage->encode_context = &node->enc;
    storage->notice = budget_on_notice;
    storage->notice_user = &node->notes;
    storage->senders = node->senders;
    storage->sender_capacity = node->profile.sender_slots;
    storage->sender_payload = node->sender_payload;
    storage->sender_payload_capacity = (size_t)node->profile.sender_slots * node->profile.message_bytes;
    storage->results = node->results;
    storage->result_capacity = node->profile.result_slots;
    storage->result_payload = node->result_payload;
    storage->result_payload_capacity = (size_t)node->profile.result_slots * node->profile.message_bytes;
    storage->history = node->history;
    storage->history_capacity = node->profile.history_slots;
    storage->correlations = node->correlations;
    storage->correlation_capacity = node->profile.correlation_slots;
    storage->history_metadata = node->history_metadata;
    storage->history_metadata_capacity =
        (size_t)node->profile.history_slots * (size_t)DMP_RELIABILITY_METADATA_BYTES;
    storage->correlation_metadata = node->correlation_metadata;
    storage->correlation_metadata_capacity =
        (size_t)node->profile.correlation_slots * (size_t)DMP_RELIABILITY_METADATA_BYTES;
    storage->adapters = node->adapters;
    storage->adapter_capacity = node->profile.adapter_slots;
    storage->frames = node->frames;
    storage->frame_capacity = (size_t)node->profile.adapter_slots * node->profile.encoded_mtu;
    storage->receive_payload = node->receive_payload;
    storage->receive_payload_capacity = node->profile.message_bytes;
    CHECK(node->profile.sender_slots <= BUDGET_SLOTS);
    CHECK(node->profile.result_slots <= BUDGET_SLOTS);
    CHECK(node->profile.history_slots <= BUDGET_SLOTS);
    CHECK(node->profile.correlation_slots <= BUDGET_SLOTS);
    CHECK(node->profile.adapter_slots <= BUDGET_ADAPTERS);
    CHECK(node->profile.message_bytes <= BUDGET_MSG);
    CHECK(node->profile.encoded_mtu <= BUDGET_MTU);
    CHECK(dmp_reliability_init(&node->engine, storage) == DMP_OK);
    return 0;
}

static int budget_reliability_exchange(const dmp_admitted_profile *profile, uint32_t bytes)
{
    uint8_t request[BUDGET_MSG];
    uint8_t response[BUDGET_MSG];
    dmp_reliability_handle req;
    int accepted;
    int before;
    CHECK(bytes > 0U && bytes <= profile->message_bytes);
    CHECK(bytes + 48U <= profile->encoded_mtu);
    memset(request, 0x11, bytes);
    memset(response, 0x22, bytes);
    CHECK(budget_boot(&budget_a, profile, 0) == 0);
    CHECK(budget_boot(&budget_b, profile, 1) == 0);
    CHECK(dmp_reliability_submit_req(&budget_a.engine, 1U, budget_span(request, bytes), 0U, 0U,
                                     &req) == DMP_OK);
    before = budget_a.tx.n;
    CHECK(dmp_reliability_poll(&budget_a.engine, 0U) == DMP_OK);
    CHECK(budget_a.tx.n == before + 1);
    budget_finish(&budget_a, 0U);
    CHECK(dmp_reliability_poll(&budget_a.engine, 0U) == DMP_OK);
    CHECK(budget_deliver(&budget_a, before, &budget_b, 0U) == 0);
    accepted = budget_notice(&budget_b.notes, DMP_REL_EVENT_REQUEST_ACCEPTED, request, bytes);
    CHECK(accepted >= 0);
    CHECK(dmp_reliability_complete(&budget_b.engine, budget_b.notes.items[accepted].handle, false, 0U,
                                   budget_span(response, bytes), 10U) == DMP_OK);
    before = budget_b.tx.n;
    CHECK(dmp_reliability_poll(&budget_b.engine, 10U) == DMP_OK);
    CHECK(budget_b.tx.n == before + 1);
    budget_finish(&budget_b, 10U);
    CHECK(dmp_reliability_poll(&budget_b.engine, 10U) == DMP_OK);
    CHECK(budget_deliver(&budget_b, before, &budget_a, 10U) == 0);
    CHECK(budget_notice(&budget_a.notes, DMP_REL_EVENT_RESULT, response, bytes) >= 0);
    CHECK(budget_a.notes.during_tx == 0);
    CHECK(budget_b.notes.during_tx == 0);
    return 0;
}

static int budget_encode_slice(uint32_t seq, uint32_t index, uint32_t chunk, uint32_t total,
                               const uint8_t *plain, size_t nplain, uint32_t mtu, uint32_t message,
                               uint32_t fragments, uint8_t *raw, size_t raw_cap, dmp_frame_view *view)
{
    dmp_frame_spec spec;
    dmp_core_limits limits;
    dmp_buffer out;
    dmp_parse_result parsed;
    size_t written = 0U;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = DMP_TYPE_DATA;
    spec.fields.options =
        (uint8_t)(DMP_OPT_SEQ | DMP_OPT_FRAG | DMP_OPT_ACK_REQ | DMP_OPT_PAYLOAD_DESC);
    spec.fields.seq = seq;
    spec.fields.fragment.index = index;
    spec.fields.fragment.chunk_size = chunk;
    spec.fields.fragment.total_size = total;
    spec.fields.descriptor.codec = 7U;
    spec.payload = budget_span(plain, nplain);
    limits.max_frame_bytes = mtu;
    limits.max_message_bytes = message;
    limits.max_fragments = fragments < 2U ? 2U : fragments;
    out.data = raw;
    out.capacity = raw_cap;
    CHECK(dmp_core_encode(&spec, &limits, out, &written) == DMP_OK);
    parsed = dmp_core_parse(budget_span(raw, written), &limits, view);
    CHECK(parsed.status == DMP_OK);
    return 0;
}

static int budget_reassembly_exchange(const dmp_admitted_profile *profile, uint32_t total)
{
    static dmp_reassembly engine;
    static dmp_reassembly_slot assemblies[1];
    static dmp_reassembly_tombstone tombstones[DIRECT_TOMBSTONES];
    static uint8_t payloads[BUDGET_MSG];
    static uint8_t metadata[DMP_REASSEMBLY_METADATA_BYTES];
    static dmp_identity_slot ids[2];
    dmp_identity_table table;
    dmp_identity_handle ctx;
    dmp_identity_context_config config;
    dmp_reassembly_storage storage;
    dmp_admitted_profile admitted;
    uint8_t body[BUDGET_MSG];
    uint8_t raw[BUDGET_MTU];
    dmp_frame_view view;
    dmp_reassembly_input input;
    dmp_reassembly_handle handle;
    dmp_reassembly_message message;
    uint32_t chunk;
    uint32_t fragments;
    uint32_t index;
    CHECK(profile->assembly_slots == 1U);
    CHECK(profile->assembly_tombstone_slots <= DIRECT_TOMBSTONES);
    CHECK(total == profile->message_bytes);
    CHECK(total > profile->chunk_bytes && total <= BUDGET_MSG);
    chunk = profile->chunk_bytes;
    fragments = 1U + (total - 1U) / chunk;
    CHECK(fragments == profile->fragments);
    CHECK(fragments >= 2U && fragments <= 32U);
    admitted = *profile;
    memset(&engine, 0, sizeof engine);
    memset(assemblies, 0, sizeof assemblies);
    memset(tombstones, 0, sizeof tombstones);
    memset(ids, 0, sizeof ids);
    CHECK(dmp_identity_table_init(&table, ids, 2U) == DMP_OK);
    memset(&config, 0, sizeof config);
    config.local.namespace_id = 1U;
    config.local.origin_id = 10U;
    config.local.epoch = 9U;
    config.peer.namespace_id = 1U;
    config.peer.origin_id = 20U;
    config.peer.epoch = 7U;
    CHECK(dmp_identity_context_open(&table, &config, &ctx) == DMP_OK);
    memset(&storage, 0, sizeof storage);
    storage.profile = &admitted;
    storage.identity = &table;
    storage.assemblies = assemblies;
    storage.assembly_capacity = admitted.assembly_slots;
    storage.tombstones = tombstones;
    storage.tombstone_capacity = admitted.assembly_tombstone_slots;
    storage.payloads = payloads;
    storage.payload_capacity = (size_t)admitted.assembly_slots * admitted.message_bytes;
    storage.metadata = metadata;
    storage.metadata_capacity = (size_t)admitted.assembly_slots * (size_t)DMP_REASSEMBLY_METADATA_BYTES;
    CHECK(dmp_reassembly_init(&engine, &storage, &admitted, &table) == DMP_OK);
    memset(body, 0x31, total);
    memset(&input, 0, sizeof input);
    input.context = ctx;
    input.service_id = 1U;
    input.immutable_metadata = budget_span(NULL, 0U);
    handle.slot = 99U;
    handle.generation = 99U;
    for (index = 0U; index < fragments; index++) {
        uint32_t offset = index * chunk;
        uint32_t slice = total - offset;
        dmp_status expect = index + 1U == fragments ? DMP_OK : DMP_INCOMPLETE;
        if (slice > chunk) {
            slice = chunk;
        }
        CHECK(budget_encode_slice(4U, index, chunk, total, body + offset, slice, admitted.encoded_mtu,
                                  admitted.message_bytes, fragments, raw, sizeof raw, &view) == 0);
        input.frame = &view;
        input.plaintext = view.payload;
        CHECK(view.payload.size == slice);
        CHECK(dmp_reassembly_on_fragment(&engine, &input, 100U + index, &handle) == expect);
    }
    CHECK(dmp_reassembly_get(&engine, handle, &message) == DMP_OK);
    CHECK(message.payload.size == total);
    CHECK(memcmp(message.payload.data, body, total) == 0);
    return 0;
}

static void fill_budget(dmp_config *config, const budget_spec *spec)
{
    memset(config, 0, sizeof *config);
    config->namespace_id = 1U;
    config->node_id[0] = 10U;
    config->node_id[1] = 20U;
    config->default_service = 1U;
    config->service_id[0] = 1U;
    config->service_id[1] = 2U;
    config->peers = 1U;
    config->operations_per_service = 1U;
    config->assemblies_per_peer = spec->assemblies_per_peer;
    config->assembly_tombstones_per_peer = spec->tombstones_per_peer;
    config->sender_slots = spec->sender_slots;
    config->assembly_slots = spec->assembly_slots;
    config->assembly_tombstone_slots = spec->tombstone_slots;
    config->result_slots = spec->result_slots;
    config->history_slots = spec->history_slots;
    config->correlation_slots = spec->correlation_slots;
    config->adapter_slots = spec->adapter_slots;
    config->application_queue_slots = spec->application_queue_slots;
    config->control_slots = spec->control_slots;
    config->message_bytes = spec->message_bytes;
    config->fragments = spec->fragments;
    config->chunk_bytes = spec->chunk_bytes;
    config->encoded_mtu = spec->encoded_mtu;
    config->forward_mtu = spec->encoded_mtu;
    config->return_mtu = spec->encoded_mtu;
    config->queue_ms = 1000U;
    config->response_timeout_ms = 50U;
    config->jitter_ms = 5U;
    config->send_horizon_ms = 100000U;
    config->receipt_delay_ms = 20U;
    config->receipt_limit = 3U;
    config->dedup_ms = 5000U;
    config->rejection_ms = 5000U;
    config->result_cache_ms = 500U;
    config->result_deadline_ms = 100000U;
    config->correlation_ms = 200000U;
    config->tombstone_ms = 300000U;
    config->late_result_ms = 1000U;
    config->assembly_ms = 10000U;
}

static int test_budget(void)
{
    static const budget_spec rows[6] = {
        {1024U, 0, 64U, 1U, 32U, 112U, 1U, 1U, 1U, 1U, 2U, 1U, 1U, 0U, 0U, 0U, 0U, 64U, 0U, 926ULL,
         "unfragmented reliability; omits assembly payload and metadata; no reassembly tombstones; "
         "message 64, one sender/result/history/correlation, control 1, adapter 2"},
        {2048U, 0, 256U, 1U, 128U, 304U, 1U, 1U, 1U, 1U, 2U, 1U, 1U, 0U, 0U, 0U, 0U, 256U, 0U, 1886ULL,
         "unfragmented reliability; omits assembly payload and metadata; no reassembly tombstones; "
         "message 256, one sender/result/history/correlation, control 1, adapter 2"},
        {3072U, 0, 384U, 1U, 128U, 432U, 1U, 1U, 1U, 1U, 2U, 1U, 1U, 0U, 0U, 0U, 0U, 384U, 0U, 2526ULL,
         "unfragmented reliability; omits assembly payload and metadata; no reassembly tombstones; "
         "message 384, one sender/result/history/correlation, control 1, adapter 2"},
        {4096U, 1, 256U, 2U, 128U, 304U, 1U, 1U, 1U, 1U, 2U, 1U, 1U, 1U, 1U, 1U, 1U, 256U, 256U, 2397ULL,
         "reliability exchange of the full 256-byte message plus reassembly of the same 256 bytes "
         "as two 128-byte slices; one tombstone, not the direct 16; control 1, adapter 2"},
        {8192U, 0, 1024U, 1U, 512U, 1072U, 1U, 1U, 1U, 1U, 2U, 1U, 1U, 0U, 0U, 0U, 0U, 1024U, 0U,
         5726ULL,
         "unfragmented reliability of a 1024-byte message; omits assembly payload and metadata; "
         "not direct-nnpsk0 (encoded_mtu 1072, fragments 1, one slot of each kind)"},
        {16384U, 1, DIRECT_MESSAGE, DIRECT_FRAGMENTS, DIRECT_CHUNK, DIRECT_MTU, DIRECT_SENDER,
         DIRECT_RESULT, DIRECT_HISTORY, DIRECT_CORRELATION, DIRECT_ADAPTER, DIRECT_CONTROL, 2U,
         DIRECT_ASSEMBLY, DIRECT_TOMBSTONES, 1U, DIRECT_TOMBSTONES, 64U, DIRECT_MESSAGE, 14344ULL,
         "direct-nnpsk0 limits with adapter 3 and control 2; the 64-byte reliability call only "
         "fits inside encoded_mtu 263 and is not an exchange of message_bytes; reassembly init "
         "completes all 1024 bytes as 16 slices of 64; 16 tombstones stay outside the eight-array sum"},
    };
    dmp_config manifest;
    dmp_config illegal;
    dmp_admitted_profile out;
    dmp_admitted_profile saved;
    unsigned i;

    CHECK(sizeof(dmp_reassembly_tombstone) == 48U);
    direct_limits(&manifest, DIRECT_ADAPTER);
    CHECK(dmp_config_admit(&manifest, &out) == DMP_OK);
    CHECK(memcmp(&manifest, &out, sizeof manifest) == 0);
    CHECK(manifest.adapter_slots == 3U);
    CHECK(manifest.control_slots == 2U);
    CHECK(manifest.adapter_slots > manifest.control_slots);
    CHECK(eight_sum(&manifest, 1) == 14344ULL);
    illegal = manifest;
    illegal.adapter_slots = 2U;
    illegal.control_slots = 2U;
    memset(&out, 0x3C, sizeof out);
    saved = out;
    CHECK(dmp_config_admit(&illegal, &out) == DMP_UNSUPPORTED);
    CHECK(memcmp(&out, &saved, sizeof out) == 0);
    (void)printf("SIZE identity_slot=%zu reliability=%zu reassembly_slot=%zu "
                 "reassembly=%zu tombstone=%zu\n",
                 sizeof(dmp_identity_slot), sizeof(dmp_reliability),
                 sizeof(dmp_reassembly_slot), sizeof(dmp_reassembly),
                 sizeof(dmp_reassembly_tombstone));
    (void)printf("NOTE direct manifest pair adapter_slots=%u control_slots=%u admits; "
                 "reliability reserve formula unchanged\n",
                 manifest.adapter_slots, manifest.control_slots);

    for (i = 0U; i < 6U; i++) {
        const budget_spec *spec = &rows[i];
        dmp_config config;
        dmp_admitted_profile admitted;
        uint64_t sum;
        size_t tombs;
        size_t state;
        fill_budget(&config, spec);
        sum = eight_sum(&config, spec->reassembly);
        CHECK(sum == spec->expect_sum);
        CHECK(sum <= spec->budget);
        CHECK(config.adapter_slots > config.control_slots);
        CHECK(config.control_slots >= 1U);
        CHECK(spec->exchange_bytes > 0U && spec->exchange_bytes <= spec->message_bytes);
        CHECK(spec->exchange_bytes + 48U <= spec->encoded_mtu);
        if (spec->message_bytes + 48U <= spec->encoded_mtu) {
            CHECK(spec->exchange_bytes == spec->message_bytes);
        }
        if (spec->reassembly) {
            CHECK(spec->assembly_total == spec->message_bytes);
            CHECK(spec->fragments == 1U + (spec->message_bytes - 1U) / spec->chunk_bytes);
            CHECK(spec->tombstone_slots > 0U);
        } else {
            CHECK(spec->exchange_bytes == spec->message_bytes);
            CHECK(spec->fragments == 1U);
            CHECK(spec->assembly_total == 0U);
        }
        CHECK(dmp_config_admit(&config, &admitted) == DMP_OK);
        CHECK(budget_reliability_exchange(&admitted, spec->exchange_bytes) == 0);
        if (spec->reassembly) {
            CHECK(config.assembly_slots == 1U);
            CHECK(budget_reassembly_exchange(&admitted, spec->assembly_total) == 0);
            tombs = (size_t)config.assembly_tombstone_slots * sizeof(dmp_reassembly_tombstone);
        } else {
            CHECK(config.assembly_slots == 0U);
            CHECK(config.fragments == 1U);
            tombs = 0U;
        }
        state = state_bytes(spec->reassembly, config.assembly_slots);
        {
            const char *delivered_by = "reliability";
            if (spec->reassembly && spec->exchange_bytes == spec->message_bytes) {
                delivered_by = "reliability+reassembly";
            } else if (spec->reassembly) {
                delivered_by = "reassembly";
            }
            (void)printf(
                "BUDGET_ROW budget=%u supported=1 capability=\"%s\" message_bytes=%u "
                "fragments=%u chunk_bytes=%u peers=%u sender=%u result=%u history=%u "
                "correlation=%u adapter=%u control=%u assembly=%u tombstone_slots=%u "
                "eight_sum=%llu state_bytes=%zu tombstone_bytes=%zu crypto=excluded "
                "stack=excluded json_scratch=0 delivered_bytes=%u delivered_fragments=%u "
                "delivered_by=%s reliability_frame_bytes=%u reassembly_bytes=%u "
                "init=dmp_config_admit+dmp_reliability_init%s\n",
                spec->budget, spec->capability, config.message_bytes, config.fragments,
                config.chunk_bytes, config.peers, config.sender_slots, config.result_slots,
                config.history_slots, config.correlation_slots, config.adapter_slots,
                config.control_slots, config.assembly_slots, config.assembly_tombstone_slots,
                (unsigned long long)sum, state, tombs, spec->message_bytes, config.fragments,
                delivered_by, spec->exchange_bytes, spec->reassembly ? spec->assembly_total : 0U,
                spec->reassembly ? "+dmp_reassembly_init+reassembly_on_fragment" : "");
        }
    }
    return 0;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int parse_hex(const char *text, uint8_t out[32])
{
    unsigned i;
    for (i = 0U; i < 32U; i++) {
        int hi = hex_nibble(text[i * 2U]);
        int lo = hex_nibble(text[i * 2U + 1U]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return text[64] == '\0';
}

static void print_hex(const uint8_t raw[32])
{
    unsigned i;
    for (i = 0U; i < 32U; i++) {
        (void)printf("%02x", raw[i]);
    }
}

static int read_u32(const char *text, uint32_t *out)
{
    char *end = NULL;
    unsigned long value;
    if (text == NULL || text[0] == '\0' || text[0] == '-') {
        return 0;
    }
    value = strtoul(text, &end, 10);
    if (end == text || *end != '\0' || value > 0xFFFFFFFFUL) {
        return 0;
    }
    *out = (uint32_t)value;
    return 1;
}

static char *trim(char *line)
{
    size_t n;
    while (*line == ' ' || *line == '\t') {
        line++;
    }
    n = strlen(line);
    while (n > 0U && (line[n - 1U] == '\n' || line[n - 1U] == '\r' || line[n - 1U] == ' ')) {
        line[--n] = '\0';
    }
    return line;
}

static int take_line(char *key, size_t key_n, char *value, size_t value_n)
{
    char line[256];
    char *body;
    char *split;
    if (fgets(line, (int)sizeof line, stdin) == NULL) {
        return 0;
    }
    body = trim(line);
    split = strchr(body, ' ');
    if (split == NULL) {
        return 0;
    }
    *split = '\0';
    if (strlen(body) + 1U > key_n || strlen(split + 1) + 1U > value_n) {
        return 0;
    }
    memcpy(key, body, strlen(body) + 1U);
    memcpy(value, split + 1, strlen(split + 1) + 1U);
    return 1;
}

static int expect_key(const char *name, char *value, size_t value_n)
{
    char key[64];
    if (!take_line(key, sizeof key, value, value_n) || strcmp(key, name) != 0) {
        (void)fprintf(stderr, "expected field %s\n", name);
        return 0;
    }
    return 1;
}

static int expect_u32(const char *name, uint32_t *out)
{
    char value[64];
    if (!expect_key(name, value, sizeof value) || !read_u32(value, out)) {
        return 0;
    }
    return 1;
}

static int admit_config_stdio(void)
{
    dmp_config in;
    dmp_admitted_profile out;
    dmp_status status;
    char value[80];
    uint32_t recovery0;
    uint32_t recovery1;
    uint32_t flag;

    memset(&in, 0, sizeof in);
    memset(&out, 0x5A, sizeof out);
    if (!expect_key("sha256", value, sizeof value) || !parse_hex(value, in.sha256) ||
        !expect_u32("namespace_id", &in.namespace_id) ||
        !expect_u32("node_id0", &in.node_id[0]) || !expect_u32("node_id1", &in.node_id[1]) ||
        !expect_u32("default_service", &in.default_service) ||
        !expect_u32("service_id0", &in.service_id[0]) ||
        !expect_u32("service_id1", &in.service_id[1]) || !expect_u32("recovery0", &recovery0) ||
        !expect_u32("recovery1", &recovery1) || !expect_u32("peers", &in.peers) ||
        !expect_u32("operations_per_service", &in.operations_per_service) ||
        !expect_u32("assemblies_per_peer", &in.assemblies_per_peer) ||
        !expect_u32("assembly_tombstones_per_peer", &in.assembly_tombstones_per_peer) ||
        !expect_u32("sender_slots", &in.sender_slots) ||
        !expect_u32("assembly_slots", &in.assembly_slots) ||
        !expect_u32("assembly_tombstone_slots", &in.assembly_tombstone_slots) ||
        !expect_u32("result_slots", &in.result_slots) ||
        !expect_u32("history_slots", &in.history_slots) ||
        !expect_u32("correlation_slots", &in.correlation_slots) ||
        !expect_u32("adapter_slots", &in.adapter_slots) ||
        !expect_u32("application_queue_slots", &in.application_queue_slots) ||
        !expect_u32("control_slots", &in.control_slots) ||
        !expect_u32("message_bytes", &in.message_bytes) ||
        !expect_u32("fragments", &in.fragments) || !expect_u32("chunk_bytes", &in.chunk_bytes) ||
        !expect_u32("encoded_mtu", &in.encoded_mtu) ||
        !expect_u32("forward_mtu", &in.forward_mtu) ||
        !expect_u32("return_mtu", &in.return_mtu) || !expect_u32("queue_ms", &in.queue_ms) ||
        !expect_u32("response_timeout_ms", &in.response_timeout_ms) ||
        !expect_u32("jitter_ms", &in.jitter_ms) ||
        !expect_u32("send_horizon_ms", &in.send_horizon_ms) ||
        !expect_u32("max_bursts", &in.max_bursts) ||
        !expect_u32("receipt_delay_ms", &in.receipt_delay_ms) ||
        !expect_u32("receipt_limit", &in.receipt_limit) ||
        !expect_u32("dedup_ms", &in.dedup_ms) || !expect_u32("rejection_ms", &in.rejection_ms) ||
        !expect_u32("result_cache_ms", &in.result_cache_ms) ||
        !expect_u32("result_deadline_ms", &in.result_deadline_ms) ||
        !expect_u32("correlation_ms", &in.correlation_ms) ||
        !expect_u32("tombstone_ms", &in.tombstone_ms) ||
        !expect_u32("late_result_ms", &in.late_result_ms) ||
        !expect_u32("collect_ms", &in.collect_ms) ||
        !expect_u32("assembly_ms", &in.assembly_ms) ||
        !expect_u32("burst_span_ms", &in.burst_span_ms) ||
        !expect_u32("forward_delay_ms", &in.forward_delay_ms) ||
        !expect_u32("return_delay_ms", &in.return_delay_ms) ||
        !expect_u32("feedback_guard_ms", &in.feedback_guard_ms) ||
        !expect_u32("feedback_delay_ms", &in.feedback_delay_ms) ||
        !expect_u32("max_probes", &in.max_probes) || !expect_u32("max_status", &in.max_status) ||
        !expect_u32("record_margin_ms", &in.record_margin_ms) || !expect_u32("tx_borrow", &flag)) {
        return 2;
    }
    if (flag > 1U) {
        return 2;
    }
    in.tx_borrow = flag == 1U;
    if (!expect_u32("synchronous_completion", &flag) || flag > 1U || recovery0 > 1U ||
        recovery1 > 1U) {
        return 2;
    }
    in.synchronous_completion = flag == 1U;
    in.recovery[0] = (dmp_profile_recovery)recovery0;
    in.recovery[1] = (dmp_profile_recovery)recovery1;
    status = dmp_config_admit(&in, &out);
    (void)printf("status %s\nsha256 ", dmp_status_name(status));
    if (status == DMP_OK) {
        print_hex(out.sha256);
    }
    (void)printf("\n");
    if (status != DMP_OK) {
        return 0;
    }
    (void)printf(
        "namespace_id %u\nnode_id0 %u\nnode_id1 %u\ndefault_service %u\n"
        "service_id0 %u\nservice_id1 %u\nrecovery0 %u\nrecovery1 %u\npeers %u\n"
        "operations_per_service %u\nassemblies_per_peer %u\n"
        "assembly_tombstones_per_peer %u\nsender_slots %u\nassembly_slots %u\n"
        "assembly_tombstone_slots %u\nresult_slots %u\nhistory_slots %u\n"
        "correlation_slots %u\nadapter_slots %u\napplication_queue_slots %u\n"
        "control_slots %u\nmessage_bytes %u\nfragments %u\nchunk_bytes %u\n"
        "encoded_mtu %u\nforward_mtu %u\nreturn_mtu %u\nqueue_ms %u\n"
        "response_timeout_ms %u\njitter_ms %u\nsend_horizon_ms %u\nmax_bursts %u\n"
        "receipt_delay_ms %u\nreceipt_limit %u\ndedup_ms %u\nrejection_ms %u\n"
        "result_cache_ms %u\nresult_deadline_ms %u\ncorrelation_ms %u\n"
        "tombstone_ms %u\nlate_result_ms %u\ncollect_ms %u\nassembly_ms %u\n"
        "burst_span_ms %u\nforward_delay_ms %u\nreturn_delay_ms %u\n"
        "feedback_guard_ms %u\nfeedback_delay_ms %u\nmax_probes %u\nmax_status %u\n"
        "record_margin_ms %u\ntx_borrow %u\nsynchronous_completion %u\n",
        out.namespace_id, out.node_id[0], out.node_id[1], out.default_service, out.service_id[0],
        out.service_id[1], (unsigned)out.recovery[0], (unsigned)out.recovery[1], out.peers,
        out.operations_per_service, out.assemblies_per_peer, out.assembly_tombstones_per_peer,
        out.sender_slots, out.assembly_slots, out.assembly_tombstone_slots, out.result_slots,
        out.history_slots, out.correlation_slots, out.adapter_slots, out.application_queue_slots,
        out.control_slots, out.message_bytes, out.fragments, out.chunk_bytes, out.encoded_mtu,
        out.forward_mtu, out.return_mtu, out.queue_ms, out.response_timeout_ms, out.jitter_ms,
        out.send_horizon_ms, out.max_bursts, out.receipt_delay_ms, out.receipt_limit, out.dedup_ms,
        out.rejection_ms, out.result_cache_ms, out.result_deadline_ms, out.correlation_ms,
        out.tombstone_ms, out.late_result_ms, out.collect_ms, out.assembly_ms, out.burst_span_ms,
        out.forward_delay_ms, out.return_delay_ms, out.feedback_guard_ms, out.feedback_delay_ms,
        out.max_probes, out.max_status, out.record_margin_ms, out.tx_borrow ? 1U : 0U,
        out.synchronous_completion ? 1U : 0U);
    return 0;
}

static int run_tests(void)
{
    CHECK(test_arguments_and_copy() == 0);
    CHECK(header_closed() == 0);
    CHECK(test_budget() == 0);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--config") == 0) {
        return admit_config_stdio();
    }
    if (argc != 1) {
        (void)fprintf(stderr, "usage: dmp_test_profile_admit [--config]\n");
        return 2;
    }
    return run_tests();
}
