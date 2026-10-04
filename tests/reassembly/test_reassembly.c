#include "dmp/reassembly.h"

#include <stdio.h>
#include <string.h>

/* Host tests for fixed-stride reassembly. Secured cases use the P09 test-only
 * authenticated context. They do not perform a handshake, AEAD, or replay
 * check and are not SEC-1 evidence. */

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
    MAX_ASM = 4,
    MAX_TOMB = 8,
    MAX_MSG = 32,
    MAX_MTU = 128,
    LOCAL_ID = 10,
    PEER_ID = 20,
    OTHER_ID = 30,
    LOCAL_EPOCH = 9,
    PEER_EPOCH = 7
};

/* Canonical REPLY_TO (id 1, C=1) for namespace 1, origin 10, epoch 9, seq 4.
 * A one-byte change is a different immutable metadata blob. */
static const uint8_t META_A[] = {0x05, 0x0B, 0x01, 0x0A, 0x09, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x04};
static const uint8_t META_B[] = {0x05, 0x0B, 0x01, 0x0A, 0x09, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x05};
static const uint8_t SVC1[] = {0x11, 0x01, 0x01};
static const uint8_t SVC2[] = {0x11, 0x01, 0x02};
static const uint8_t SVC3[] = {0x11, 0x01, 0x03};

static uint8_t frame_pad[160];

typedef struct {
    dmp_reassembly engine;
    dmp_admitted_profile profile;
    dmp_identity_slot ids[4];
    dmp_identity_table table;
    dmp_identity_handle ctx;
    dmp_reassembly_slot assemblies[MAX_ASM];
    dmp_reassembly_tombstone tombstones[MAX_TOMB];
    uint8_t payloads[MAX_ASM * MAX_MSG];
    uint8_t metadata[MAX_ASM * DMP_REASSEMBLY_METADATA_BYTES];
} rig;

static rig g;
static dmp_reassembly_slot saved_slot;
static dmp_reassembly_tombstone saved_tomb;
static uint8_t saved_payload[MAX_MSG];
static uint32_t saved_retained;

typedef struct {
    dmp_identity_handle ctx;
    uint8_t type;
    uint8_t extra;
    int no_seq;
    int no_frag;
    uint32_t seq;
    uint32_t index;
    uint32_t chunk;
    uint32_t total;
    uint32_t service;
    const uint8_t *plain;
    size_t nplain;
    const uint8_t *meta;
    size_t nmeta;
    const uint8_t *ext;
    size_t next;
    int use_route;
    uint8_t ttl;
    uint8_t mode;
    uint32_t route_src;
    uint32_t route_dst;
    int use_security;
    uint8_t cipher;
    uint32_t cid;
    uint64_t pn;
    int use_desc;
    uint32_t codec;
    uint32_t schema;
    int use_integrity;
    uint8_t ialg;
    const uint8_t *trailer;
    size_t ntrailer;
    size_t frame_size;
} frag;

static dmp_bytes span(const void *data, size_t size)
{
    dmp_bytes bytes;
    bytes.data = (const uint8_t *)data;
    bytes.size = size;
    return bytes;
}

static dmp_reassembly_handle sentinel(void)
{
    dmp_reassembly_handle handle;
    handle.slot = 0xFFFFFFFFU;
    handle.generation = 0xDEADBEEFU;
    return handle;
}

static int untouched(dmp_reassembly_handle handle)
{
    return handle.slot == 0xFFFFFFFFU && handle.generation == 0xDEADBEEFU;
}

static void save_state(void)
{
    saved_slot = g.assemblies[0];
    saved_tomb = g.tombstones[0];
    memcpy(saved_payload, g.payloads, g.profile.message_bytes);
    saved_retained = g.ids[g.ctx.slot].retained;
}

static int same_state(void)
{
    return memcmp(&saved_slot, &g.assemblies[0], sizeof saved_slot) == 0 &&
           memcmp(&saved_tomb, &g.tombstones[0], sizeof saved_tomb) == 0 &&
           memcmp(saved_payload, g.payloads, g.profile.message_bytes) == 0 &&
           saved_retained == g.ids[g.ctx.slot].retained;
}

static frag base_frag(uint32_t seq, uint32_t index, uint32_t chunk, uint32_t total,
                      const uint8_t *plain, size_t nplain)
{
    frag frame;
    memset(&frame, 0, sizeof frame);
    frame.ctx = g.ctx;
    frame.type = DMP_TYPE_DATA;
    frame.seq = seq;
    frame.index = index;
    frame.chunk = chunk;
    frame.total = total;
    frame.service = 1U;
    frame.plain = plain;
    frame.nplain = nplain;
    return frame;
}

static dmp_status apply(const frag *frame, dmp_time_ms now, dmp_reassembly_handle *completed)
{
    dmp_frame_view view;
    dmp_reassembly_input input;

    memset(&view, 0, sizeof view);
    view.fields.type = frame->type;
    view.fields.options = frame->extra;
    if (frame->no_seq == 0) {
        view.fields.options = (uint8_t)(view.fields.options | DMP_OPT_SEQ);
    }
    if (frame->no_frag == 0) {
        view.fields.options = (uint8_t)(view.fields.options | DMP_OPT_FRAG);
    }
    view.fields.seq = frame->seq;
    view.fields.fragment.index = frame->index;
    view.fields.fragment.chunk_size = frame->chunk;
    view.fields.fragment.total_size = frame->total;
    if (frame->next != 0U) {
        view.fields.options = (uint8_t)(view.fields.options | DMP_OPT_EXT);
        view.extensions = span(frame->ext, frame->next);
    }
    if (frame->use_route) {
        view.fields.options = (uint8_t)(view.fields.options | DMP_OPT_ROUTE);
        view.fields.route.mode = frame->mode;
        view.fields.route.ttl = frame->ttl;
        view.fields.route.source = frame->route_src;
        view.fields.route.destination = frame->route_dst;
    }
    if (frame->use_security) {
        view.fields.options = (uint8_t)(view.fields.options | DMP_OPT_SECURITY);
        view.fields.security.cipher = frame->cipher;
        view.fields.security.receive_cid = frame->cid;
        view.fields.security.pn = frame->pn;
    }
    if (frame->use_desc) {
        view.fields.options = (uint8_t)(view.fields.options | DMP_OPT_PAYLOAD_DESC);
        view.fields.descriptor.codec = frame->codec;
        view.fields.descriptor.schema = frame->schema;
    }
    if (frame->use_integrity) {
        view.fields.options = (uint8_t)(view.fields.options | DMP_OPT_INTEGRITY);
        view.fields.integrity = frame->ialg;
    }
    if (frame->ntrailer != 0U) {
        view.trailer = span(frame->trailer, frame->ntrailer);
    }
    if (frame->frame_size != 0U) {
        view.frame.data = frame_pad;
        view.frame.size = frame->frame_size;
    }
    memset(&input, 0, sizeof input);
    input.frame = &view;
    input.context = frame->ctx;
    input.service_id = frame->service;
    input.plaintext = span(frame->plain, frame->nplain);
    input.immutable_metadata = span(frame->meta, frame->nmeta);
    return dmp_reassembly_on_fragment(&g.engine, &input, now, completed);
}

static int open_peer(uint32_t origin, uint64_t epoch, int secured, dmp_identity_handle *out)
{
    dmp_identity_context_config config;
    dmp_status status;

    memset(&config, 0, sizeof config);
    config.local.namespace_id = 1U;
    config.local.origin_id = LOCAL_ID;
    config.local.epoch = LOCAL_EPOCH;
    config.peer.namespace_id = 1U;
    config.peer.origin_id = origin;
    config.peer.epoch = epoch;
    if (secured) {
        status = dmp_test_open_authenticated_context(&g.table, &config, out);
    } else {
        config.security = 0U;
        status = dmp_identity_context_open(&g.table, &config, out);
    }
    return status == DMP_OK;
}

/* Copy the profile only when admission returns DMP_OK. Any other status leaves
 * g.profile unchanged, and the caller must not initialize the engine. */
static int gate_profile(void)
{
    dmp_config in = g.profile;
    dmp_admitted_profile out;
    dmp_status status;

    memset(&out, 0, sizeof out);
    status = dmp_config_admit(&in, &out);
    if (status != DMP_OK) {
        return 1;
    }
    g.profile = out;
    return 0;
}

static int g_selective_boot;

static int boot(uint32_t assemblies, uint32_t tombstones, uint32_t per_asm, uint32_t per_tomb,
                uint32_t fragments, uint32_t chunk_bytes, uint32_t mtu, uint32_t assembly_ms,
                int secured)
{
    dmp_reassembly_storage storage;

    memset(&g, 0, sizeof g);
    g.profile.namespace_id = 1U;
    g.profile.node_id[0] = LOCAL_ID;
    g.profile.node_id[1] = PEER_ID;
    g.profile.default_service = 1U;
    g.profile.service_id[0] = 1U;
    g.profile.service_id[1] = 2U;
    /* Reassembly does not read peers. 1 keeps slots >= peers * per-peer for the
     * ordinary one-slot fixture. Assembly and tombstone quotas stay as passed. */
    g.profile.peers = 1U;
    g.profile.assemblies_per_peer = per_asm;
    g.profile.assembly_tombstones_per_peer = per_tomb;
    g.profile.assembly_slots = assemblies;
    g.profile.assembly_tombstone_slots = tombstones;
    g.profile.message_bytes = MAX_MSG;
    g.profile.fragments = fragments;
    g.profile.chunk_bytes = chunk_bytes;
    g.profile.encoded_mtu = mtu;
    g.profile.assembly_ms = assembly_ms;
    if (g_selective_boot) {
        g.profile.recovery[0] = DMP_PROFILE_RECOVERY_SELECTIVE32;
        g.profile.recovery[1] = DMP_PROFILE_RECOVERY_SELECTIVE32;
        g.profile.burst_span_ms = 1U;
        g.profile.forward_delay_ms = 1U;
        g.profile.return_delay_ms = 1U;
        g.profile.feedback_guard_ms = 1U;
        g.profile.feedback_delay_ms = 1U;
        g.profile.record_margin_ms = 1U;
        g.profile.max_probes = 1U;
        g.profile.max_status = 1U;
        g.profile.max_bursts = 2U;
        g.profile.response_timeout_ms = 6U;
        g.profile.send_horizon_ms = 10U;
        g.profile.collect_ms = 100U;
        g.profile.return_mtu = mtu;
    }
    /* Admission uses the same control reserve as reliability. */
    g.profile.control_slots = 1U;
    g.profile.adapter_slots = 2U;
    if (dmp_identity_table_init(&g.table, g.ids, 4U) != DMP_OK ||
        !open_peer(PEER_ID, PEER_EPOCH, secured, &g.ctx)) {
        return 1;
    }
    storage.profile = &g.profile;
    storage.identity = &g.table;
    storage.assemblies = g.assemblies;
    storage.assembly_capacity = MAX_ASM;
    storage.tombstones = g.tombstones;
    storage.tombstone_capacity = MAX_TOMB;
    storage.payloads = g.payloads;
    storage.payload_capacity = sizeof g.payloads;
    storage.metadata = g.metadata;
    storage.metadata_capacity = sizeof g.metadata;
    if (gate_profile() != 0 ||
        dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) != DMP_OK) {
        return 1;
    }
    return 0;
}

static void pattern(uint8_t *dst, size_t size, uint8_t value)
{
    memset(dst, value, size);
}

static int test_init_bounds(void)
{
    dmp_reassembly_storage storage;
    dmp_reassembly_handle handle;
    uint8_t body[16];
    frag frame;

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    pattern(body, sizeof body, 0x11);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    handle = sentinel();
    CHECK(apply(&frame, 10U, &handle) == DMP_INCOMPLETE);
    CHECK(dmp_reassembly_init(&g.engine, &g.engine.storage, &g.engine.profile, &g.table) ==
          DMP_INVALID_ARGUMENT);
    CHECK(g.assemblies[0].received_bitmap == 1U);
    CHECK(g.ids[g.ctx.slot].retained == 1U);

    memset(&g, 0, sizeof g);
    g.profile.fragments = 1U;
    g.profile.message_bytes = MAX_MSG;
    g.profile.chunk_bytes = 16U;
    g.profile.encoded_mtu = MAX_MTU;
    g.profile.assembly_slots = 1U;
    g.profile.assembly_tombstone_slots = 1U;
    g.engine.generation = 99U;
    storage.profile = &g.profile;
    storage.identity = &g.table;
    storage.assemblies = g.assemblies;
    storage.assembly_capacity = 1U;
    storage.tombstones = g.tombstones;
    storage.tombstone_capacity = 1U;
    storage.payloads = g.payloads;
    storage.payload_capacity = MAX_MSG;
    storage.metadata = g.metadata;
    storage.metadata_capacity = DMP_REASSEMBLY_METADATA_BYTES;
    CHECK(dmp_identity_table_init(&g.table, g.ids, 1U) == DMP_OK);
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    CHECK(g.engine.generation == 99U);
    CHECK(g.engine.initialized == 0U);

    g.profile.fragments = 33U;
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    g.profile.fragments = 8U;
    g.profile.message_bytes = 0U;
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    g.profile.message_bytes = MAX_MSG;
    g.profile.chunk_bytes = 0U;
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    g.profile.chunk_bytes = 16U;
    g.profile.encoded_mtu = 0U;
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    g.profile.encoded_mtu = MAX_MTU;
    storage.payload_capacity = MAX_MSG - 1U;
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    CHECK(g.engine.generation == 99U);
    storage.payload_capacity = MAX_MSG;
    storage.metadata_capacity = DMP_REASSEMBLY_METADATA_BYTES - 1U;
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    storage.metadata_capacity = DMP_REASSEMBLY_METADATA_BYTES;
    storage.tombstone_capacity = 0U;
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    storage.tombstone_capacity = 1U;
    storage.assembly_capacity = 0U;
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    storage.assembly_capacity = 1U;
    storage.assemblies = NULL;
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    storage.assemblies = g.assemblies;
    storage.payloads = NULL;
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    CHECK(g.engine.initialized == 0U);
    CHECK(dmp_reassembly_init(NULL, &storage, &g.profile, &g.table) == DMP_INVALID_ARGUMENT);
    return 0;
}

static int test_extra_storage(void)
{
    dmp_reassembly_storage storage;
    dmp_reassembly_handle handle;
    uint8_t body[16];
    frag frame;

    memset(&g, 0, sizeof g);
    g.assemblies[1].live = 9U;
    g.profile.default_service = 1U;
    g.profile.service_id[0] = 1U;
    g.profile.service_id[1] = 2U;
    g.profile.peers = 1U;
    g.profile.assemblies_per_peer = 1U;
    g.profile.assembly_tombstones_per_peer = 1U;
    g.profile.assembly_slots = 1U;
    g.profile.assembly_tombstone_slots = 1U;
    g.profile.message_bytes = MAX_MSG;
    g.profile.fragments = 8U;
    g.profile.chunk_bytes = 16U;
    g.profile.encoded_mtu = MAX_MTU;
    g.profile.assembly_ms = 1000U;
    g.profile.control_slots = 1U;
    g.profile.adapter_slots = 2U;
    CHECK(dmp_identity_table_init(&g.table, g.ids, 4U) == DMP_OK);
    CHECK(open_peer(PEER_ID, PEER_EPOCH, 0, &g.ctx));
    storage.profile = &g.profile;
    storage.identity = &g.table;
    storage.assemblies = g.assemblies;
    storage.assembly_capacity = MAX_ASM;
    storage.tombstones = g.tombstones;
    storage.tombstone_capacity = MAX_TOMB;
    storage.payloads = g.payloads;
    storage.payload_capacity = sizeof g.payloads;
    storage.metadata = g.metadata;
    storage.metadata_capacity = sizeof g.metadata;
    CHECK(gate_profile() == 0);
    CHECK(dmp_reassembly_init(&g.engine, &storage, &g.profile, &g.table) == DMP_OK);
    CHECK(g.assemblies[1].live == 9U);
    CHECK(g.engine.storage.assembly_capacity == 1U);
    pattern(body, sizeof body, 0x21);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    handle = sentinel();
    CHECK(apply(&frame, 1U, &handle) == DMP_INCOMPLETE);
    frame.seq = 2U;
    handle = sentinel();
    CHECK(apply(&frame, 1U, &handle) == DMP_QUOTA_EXHAUSTED);
    CHECK(untouched(handle));
    CHECK(g.assemblies[1].live == 9U);
    CHECK(g.assemblies[0].live == 1U);

    CHECK(boot(2U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    pattern(body, sizeof body, 0x22);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    handle = sentinel();
    CHECK(apply(&frame, 1U, &handle) == DMP_INCOMPLETE);
    frame.seq = 2U;
    handle = sentinel();
    CHECK(apply(&frame, 1U, &handle) == DMP_QUOTA_EXHAUSTED);
    CHECK(untouched(handle));
    CHECK(g.engine.storage.tombstone_capacity == 1U);
    CHECK(g.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_RESERVED);
    CHECK(g.tombstones[1].state == DMP_REASSEMBLY_TOMBSTONE_UNUSED);
    CHECK(g.assemblies[1].live == 0U);
    return 0;
}

static int encode_slice(uint32_t seq, uint32_t index, uint32_t chunk, uint32_t total,
                        const uint8_t *plain, size_t nplain, uint8_t *raw, size_t raw_cap,
                        dmp_frame_view *view)
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
    spec.payload = span(plain, nplain);
    limits.max_frame_bytes = MAX_MTU;
    limits.max_message_bytes = MAX_MSG;
    limits.max_fragments = 8U;
    out.data = raw;
    out.capacity = raw_cap;
    if (dmp_core_encode(&spec, &limits, out, &written) != DMP_OK) {
        return 1;
    }
    parsed = dmp_core_parse(span(raw, written), &limits, view);
    return parsed.status == DMP_OK ? 0 : 1;
}

static int test_stride_and_order(void)
{
    uint8_t head[16];
    uint8_t tail[16];
    uint8_t short_tail[4];
    uint8_t raw_a[MAX_MTU];
    uint8_t raw_b[MAX_MTU];
    uint8_t expect[32];
    dmp_frame_view view;
    dmp_reassembly_input input;
    dmp_reassembly_handle handle;
    dmp_reassembly_handle hidden;
    dmp_reassembly_message message;
    dmp_time_ms deadline;
    size_t expired = 7U;

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    pattern(head, sizeof head, 0xA1);
    pattern(tail, sizeof tail, 0xA2);
    CHECK(encode_slice(4U, 1U, 16U, 32U, tail, sizeof tail, raw_a, sizeof raw_a, &view) == 0);
    memset(&input, 0, sizeof input);
    input.frame = &view;
    input.context = g.ctx;
    input.service_id = 1U;
    input.plaintext = view.payload;
    input.immutable_metadata = span(NULL, 0U);
    handle = sentinel();
    CHECK(dmp_reassembly_on_fragment(&g.engine, &input, 100U, &handle) == DMP_INCOMPLETE);
    CHECK(untouched(handle));
    CHECK(g.assemblies[0].complete == 0U);
    hidden.slot = 0U;
    hidden.generation = g.assemblies[0].generation;
    memset(&message, 0x5A, sizeof message);
    CHECK(dmp_reassembly_get(&g.engine, hidden, &message) == DMP_STALE_HANDLE);
    CHECK(((uint8_t *)&message)[0] == 0x5A);
    deadline = g.assemblies[0].deadline;
    CHECK(deadline == 1100U);
    CHECK(encode_slice(4U, 0U, 16U, 32U, head, sizeof head, raw_b, sizeof raw_b, &view) == 0);
    input.frame = &view;
    input.plaintext = view.payload;
    CHECK(dmp_reassembly_on_fragment(&g.engine, &input, 500U, &handle) == DMP_OK);
    CHECK(handle.slot == 0U);
    CHECK(handle.generation == hidden.generation);
    CHECK(g.assemblies[0].deadline == deadline);
    CHECK(dmp_reassembly_get(&g.engine, handle, &message) == DMP_OK);
    CHECK(message.payload.size == 32U);
    CHECK(memcmp(message.payload.data, head, 16U) == 0);
    CHECK(memcmp(message.payload.data + 16, tail, 16U) == 0);
    CHECK((message.fields.options & DMP_OPT_FRAG) == 0U);
    CHECK((message.fields.options & DMP_OPT_ACK_REQ) != 0U);
    CHECK(message.fields.fragment.index == 0U);
    CHECK(message.fields.fragment.chunk_size == 0U);
    CHECK(message.fields.fragment.total_size == 0U);
    CHECK(message.fields.descriptor.codec == 7U);
    CHECK(message.fields.seq == 4U);
    CHECK(message.fields.route.ttl == 0U);
    CHECK(message.fields.security.pn == 0U);
    CHECK(message.service_id == 1U);
    CHECK(message.source.seq == 4U);
    CHECK(message.source.origin.origin_id == PEER_ID);
    expired = 3U;
    CHECK(dmp_reassembly_poll(&g.engine, 100000U, &expired) == DMP_OK);
    CHECK(expired == 0U);
    CHECK(dmp_reassembly_get(&g.engine, handle, &message) == DMP_OK);

    pattern(short_tail, sizeof short_tail, 0xB2);
    pattern(head, sizeof head, 0xB1);
    CHECK(encode_slice(5U, 1U, 16U, 20U, short_tail, sizeof short_tail, raw_a, sizeof raw_a,
                       &view) == 0);
    input.frame = &view;
    input.plaintext = view.payload;
    handle = sentinel();
    CHECK(dmp_reassembly_on_fragment(&g.engine, &input, 2000U, &handle) == DMP_QUOTA_EXHAUSTED);
    CHECK(dmp_reassembly_release(&g.engine, hidden) == DMP_OK);
    CHECK(dmp_reassembly_get(&g.engine, hidden, &message) == DMP_STALE_HANDLE);
    CHECK(dmp_reassembly_on_fragment(&g.engine, &input, 2000U, &handle) == DMP_INCOMPLETE);
    CHECK(untouched(handle));
    CHECK(encode_slice(5U, 0U, 16U, 20U, head, sizeof head, raw_b, sizeof raw_b, &view) == 0);
    input.frame = &view;
    input.plaintext = view.payload;
    CHECK(dmp_reassembly_on_fragment(&g.engine, &input, 2001U, &handle) == DMP_OK);
    CHECK(dmp_reassembly_get(&g.engine, handle, &message) == DMP_OK);
    memcpy(expect, head, 16U);
    memcpy(expect + 16, short_tail, 4U);
    CHECK(message.payload.size == 20U);
    CHECK(memcmp(message.payload.data, expect, 20U) == 0);
    CHECK(hidden.generation != handle.generation);
    CHECK(dmp_reassembly_get(&g.engine, hidden, &message) == DMP_STALE_HANDLE);
    return 0;
}

static int test_conflicts_and_retries(void)
{
    uint8_t body[16];
    uint8_t other[16];
    uint8_t rest[16];
    frag frame;
    dmp_reassembly_handle handle;
    dmp_time_ms deadline;
    uint8_t trailer_a[4] = {1, 2, 3, 4};
    uint8_t trailer_b[4] = {9, 9, 9, 9};
    dmp_reassembly_message message;

    CHECK(boot(1U, 2U, 1U, 2U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    pattern(body, sizeof body, 0x31);
    pattern(other, sizeof other, 0x32);
    pattern(rest, sizeof rest, 0x33);
    frame = base_frag(7U, 0U, 16U, 32U, body, sizeof body);
    frame.extra = DMP_OPT_ACK_REQ;
    frame.meta = META_A;
    frame.nmeta = sizeof META_A;
    frame.use_desc = 1;
    frame.codec = 7U;
    frame.use_integrity = 1;
    frame.ialg = 1U;
    frame.use_route = 1;
    frame.mode = 1U;
    frame.ttl = 5U;
    frame.route_src = PEER_ID;
    frame.route_dst = LOCAL_ID;
    frame.trailer = trailer_a;
    frame.ntrailer = sizeof trailer_a;
    handle = sentinel();
    CHECK(apply(&frame, 100U, &handle) == DMP_INCOMPLETE);
    deadline = g.assemblies[0].deadline;
    CHECK(deadline == 1100U);
    save_state();

    frame.ttl = 1U;
    frame.pn = 0U;
    frame.trailer = trailer_b;
    frame.ntrailer = sizeof trailer_b;
    handle = sentinel();
    CHECK(apply(&frame, 500U, &handle) == DMP_DUPLICATE);
    CHECK(untouched(handle));
    CHECK(same_state());
    CHECK(g.assemblies[0].deadline == deadline);

    frame.plain = other;
    handle = sentinel();
    CHECK(apply(&frame, 501U, &handle) == DMP_MALFORMED);
    CHECK(untouched(handle));
    CHECK(same_state());

    frame.plain = body;
    frame.chunk = 8U;
    frame.total = 32U;
    frame.nplain = 8U;
    CHECK(apply(&frame, 502U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    frame.chunk = 16U;
    frame.nplain = 16U;

    frame.meta = META_B;
    frame.nmeta = sizeof META_B;
    CHECK(apply(&frame, 503U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    frame.meta = META_A;
    frame.nmeta = sizeof META_A;

    frame.type = DMP_TYPE_EVENT;
    CHECK(apply(&frame, 504U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    frame.type = DMP_TYPE_DATA;

    frame.extra = 0U;
    CHECK(apply(&frame, 505U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    frame.extra = DMP_OPT_ACK_REQ;

    frame.codec = 8U;
    CHECK(apply(&frame, 506U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    frame.codec = 7U;

    frame.ialg = 2U;
    CHECK(apply(&frame, 507U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    frame.ialg = 1U;

    frame.route_dst = LOCAL_ID + 1U;
    CHECK(apply(&frame, 508U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    frame.route_dst = LOCAL_ID;

    frame.mode = 0U;
    CHECK(apply(&frame, 509U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    frame.mode = 1U;

    frame.route_src = PEER_ID + 50U;
    CHECK(apply(&frame, 510U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    frame.route_src = PEER_ID;

    frame.service = 2U;
    frame.ext = SVC2;
    frame.next = sizeof SVC2;
    CHECK(apply(&frame, 511U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    frame.service = 1U;
    frame.ext = NULL;
    frame.next = 0U;

    frame.index = 1U;
    frame.plain = rest;
    frame.ttl = 4U;
    handle = sentinel();
    CHECK(apply(&frame, 1099U, &handle) == DMP_OK);
    CHECK(g.assemblies[0].deadline == deadline);
    CHECK(dmp_reassembly_get(&g.engine, handle, &message) == DMP_OK);
    CHECK(memcmp(message.payload.data, body, 16U) == 0);
    CHECK(memcmp(message.payload.data + 16, rest, 16U) == 0);
    CHECK(message.fields.route.ttl == 0U);
    CHECK(message.fields.route.destination == LOCAL_ID);
    CHECK(message.immutable_metadata.size == sizeof META_A);
    CHECK(memcmp(message.immutable_metadata.data, META_A, sizeof META_A) == 0);
    return 0;
}

static int test_three_fragments(void)
{
    uint8_t a[10];
    uint8_t b[10];
    uint8_t c[5];
    uint8_t bad[10];
    frag frame;
    dmp_reassembly_handle handle;
    dmp_reassembly_message message;
    uint8_t expect[25];

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 5000U, 0) == 0);
    pattern(a, sizeof a, 0x41);
    pattern(b, sizeof b, 0x42);
    pattern(c, sizeof c, 0x43);
    pattern(bad, sizeof bad, 0x44);
    frame = base_frag(3U, 2U, 10U, 25U, c, sizeof c);
    handle = sentinel();
    CHECK(apply(&frame, 10U, &handle) == DMP_INCOMPLETE);
    frame.index = 0U;
    frame.plain = a;
    frame.nplain = sizeof a;
    CHECK(apply(&frame, 11U, &handle) == DMP_INCOMPLETE);
    save_state();
    frame.index = 2U;
    frame.plain = c;
    frame.nplain = sizeof c;
    CHECK(apply(&frame, 12U, &handle) == DMP_DUPLICATE);
    CHECK(same_state());
    frame.index = 0U;
    frame.plain = bad;
    frame.nplain = sizeof bad;
    CHECK(apply(&frame, 13U, &handle) == DMP_MALFORMED);
    CHECK(untouched(handle));
    CHECK(same_state());
    frame.index = 1U;
    frame.plain = b;
    frame.nplain = sizeof b;
    CHECK(apply(&frame, 14U, &handle) == DMP_OK);
    CHECK(dmp_reassembly_get(&g.engine, handle, &message) == DMP_OK);
    memcpy(expect, a, 10U);
    memcpy(expect + 10, b, 10U);
    memcpy(expect + 20, c, 5U);
    CHECK(message.payload.size == 25U);
    CHECK(memcmp(message.payload.data, expect, 25U) == 0);
    return 0;
}

static int reject_keeps_empty(const frag *frame, dmp_time_ms now, dmp_status expect)
{
    dmp_reassembly_handle handle = sentinel();

    memset(g.payloads, 0xA5, sizeof g.payloads);
    save_state();
    CHECK(apply(frame, now, &handle) == expect);
    CHECK(untouched(handle));
    CHECK(same_state());
    CHECK(g.assemblies[0].live == 0U);
    CHECK(g.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_UNUSED);
    CHECK(g.ids[g.ctx.slot].retained == 0U);
    return 0;
}

static int test_limits_do_not_reserve(void)
{
    uint8_t body[16];
    uint8_t meta[256];
    frag frame;
    dmp_reassembly_handle handle;

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    pattern(body, sizeof body, 0x51);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    frame.no_frag = 1;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_MALFORMED) == 0);
    frame.no_frag = 0;
    frame.no_seq = 1;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_CONTEXT_REQUIRED) == 0);
    frame.no_seq = 0;
    frame.chunk = 0U;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_MALFORMED) == 0);
    frame.chunk = 32U;
    frame.total = 32U;
    frame.nplain = 32U;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_MALFORMED) == 0);
    frame.chunk = 16U;
    frame.total = 32U;
    frame.index = 2U;
    frame.nplain = 16U;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_MALFORMED) == 0);
    frame.index = 0U;
    frame.nplain = 15U;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_MALFORMED) == 0);
    frame.nplain = 17U;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_MALFORMED) == 0);
    frame.nplain = 16U;
    frame.total = 33U;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_LIMIT_EXHAUSTED) == 0);
    frame.total = 32U;
    frame.chunk = 17U;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_LIMIT_EXHAUSTED) == 0);
    frame.chunk = 16U;
    frame.frame_size = (size_t)MAX_MTU + 1U;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_LIMIT_EXHAUSTED) == 0);
    frame.frame_size = 0U;
    frame.service = 2U;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_MALFORMED) == 0);
    frame.service = 1U;
    frame.ext = SVC1;
    frame.next = sizeof SVC1;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_MALFORMED) == 0);
    frame.ext = SVC3;
    frame.next = sizeof SVC3;
    frame.service = 3U;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_UNSUPPORTED) == 0);
    frame.ext = NULL;
    frame.next = 0U;
    frame.service = 1U;
    memset(meta, 0x7E, sizeof meta);
    frame.meta = meta;
    frame.nmeta = sizeof meta;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_LIMIT_EXHAUSTED) == 0);
    frame.meta = NULL;
    frame.nmeta = 0U;
    frame.plain = NULL;
    frame.nplain = 4U;
    handle = sentinel();
    CHECK(apply(&frame, 1U, &handle) == DMP_INVALID_ARGUMENT);
    CHECK(g.ids[g.ctx.slot].retained == 0U);

    CHECK(boot(1U, 1U, 1U, 1U, 2U, 16U, MAX_MTU, 1000U, 0) == 0);
    pattern(body, 10U, 0x52);
    frame = base_frag(1U, 0U, 10U, 25U, body, 10U);
    CHECK(reject_keeps_empty(&frame, 1U, DMP_LIMIT_EXHAUSTED) == 0);

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, 8U, 1000U, 0) == 0);
    frame = base_frag(1U, 0U, 16U, 32U, body, 16U);
    CHECK(reject_keeps_empty(&frame, 1U, DMP_LIMIT_EXHAUSTED) == 0);

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    frame = base_frag(1U, 0U, 16U, 32U, body, 16U);
    handle = sentinel();
    CHECK(dmp_reassembly_on_fragment(&g.engine, NULL, 1U, &handle) == DMP_INVALID_ARGUMENT);
    CHECK(dmp_reassembly_on_fragment(&g.engine, NULL, 1U, NULL) == DMP_INVALID_ARGUMENT);
    CHECK(g.ids[g.ctx.slot].retained == 0U);
    return 0;
}

static int test_quotas(void)
{
    uint8_t body[16];
    frag frame;
    dmp_reassembly_handle handle = sentinel();
    dmp_reassembly_handle first = sentinel();
    dmp_identity_handle other;

    CHECK(boot(2U, 4U, 1U, 4U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    pattern(body, sizeof body, 0x61);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    handle = sentinel();
    CHECK(apply(&frame, 10U, &handle) == DMP_INCOMPLETE);
    CHECK(g.ids[g.ctx.slot].retained == 1U);
    CHECK(g.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_RESERVED);
    save_state();
    frame.seq = 2U;
    handle = sentinel();
    CHECK(apply(&frame, 11U, &handle) == DMP_QUOTA_EXHAUSTED);
    CHECK(untouched(handle));
    CHECK(same_state());
    CHECK(g.assemblies[1].live == 0U);
    CHECK(g.tombstones[1].state == DMP_REASSEMBLY_TOMBSTONE_UNUSED);

    /* per-peer tombstones below per-peer assemblies is not an engine case. */
    {
        dmp_config rejected;
        dmp_admitted_profile out;
        dmp_admitted_profile saved;

        memset(&rejected, 0, sizeof rejected);
        rejected.namespace_id = 1U;
        rejected.node_id[0] = LOCAL_ID;
        rejected.node_id[1] = PEER_ID;
        rejected.default_service = 1U;
        rejected.service_id[0] = 1U;
        rejected.service_id[1] = 2U;
        rejected.peers = 1U;
        rejected.assemblies_per_peer = 2U;
        rejected.assembly_tombstones_per_peer = 1U;
        rejected.assembly_slots = 2U;
        rejected.assembly_tombstone_slots = 4U;
        rejected.message_bytes = MAX_MSG;
        rejected.fragments = 8U;
        rejected.chunk_bytes = 16U;
        rejected.encoded_mtu = MAX_MTU;
        rejected.assembly_ms = 1000U;
        rejected.control_slots = 1U;
        rejected.adapter_slots = 2U;
        memset(&out, 0x5A, sizeof out);
        saved = out;
        CHECK(dmp_config_admit(&rejected, &out) == DMP_UNSUPPORTED);
        CHECK(memcmp(&out, &saved, sizeof out) == 0);
    }

    CHECK(boot(2U, 2U, 1U, 2U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    CHECK(open_peer(OTHER_ID, PEER_EPOCH, 0, &other));
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    CHECK(apply(&frame, 10U, &handle) == DMP_INCOMPLETE);
    frame.ctx = other;
    frame.seq = 1U;
    pattern(body, sizeof body, 0x62);
    CHECK(apply(&frame, 10U, &handle) == DMP_INCOMPLETE);
    CHECK(g.assemblies[0].live == 1U);
    CHECK(g.assemblies[1].live == 1U);
    CHECK(memcmp(g.payloads, body, 16U) != 0);
    frame.ctx = g.ctx;
    frame.seq = 2U;
    pattern(body, sizeof body, 0x63);
    CHECK(apply(&frame, 12U, &handle) == DMP_QUOTA_EXHAUSTED);
    CHECK(g.assemblies[1].source.seq == 1U);

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    pattern(body, sizeof body, 0x64);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    frame.index = 0U;
    CHECK(apply(&frame, 1U, &handle) == DMP_INCOMPLETE);
    frame.index = 1U;
    pattern(body, sizeof body, 0x65);
    CHECK(apply(&frame, 2U, &first) == DMP_OK);
    frame.seq = 2U;
    frame.index = 0U;
    CHECK(apply(&frame, 3U, &handle) == DMP_QUOTA_EXHAUSTED);
    CHECK(g.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_RESERVED);
    CHECK(dmp_reassembly_release(&g.engine, first) == DMP_OK);
    CHECK(g.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_UNUSED);
    CHECK(g.ids[g.ctx.slot].retained == 0U);
    CHECK(apply(&frame, 4U, &handle) == DMP_INCOMPLETE);
    return 0;
}

static int test_expiry_and_fence(void)
{
    uint8_t body[16];
    uint8_t rest[16];
    frag frame;
    dmp_reassembly_handle handle;
    dmp_reassembly_handle held;
    dmp_reassembly_message message;
    size_t expired = 9U;
    dmp_message_key fenced;

    CHECK(boot(2U, 2U, 2U, 2U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    pattern(body, sizeof body, 0x71);
    pattern(rest, sizeof rest, 0x72);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    handle = sentinel();
    CHECK(apply(&frame, 0U, &handle) == DMP_INCOMPLETE);
    frame.index = 1U;
    frame.plain = rest;
    CHECK(apply(&frame, 10U, &held) == DMP_OK);
    frame.seq = 2U;
    frame.index = 0U;
    frame.plain = body;
    CHECK(apply(&frame, 0U, &handle) == DMP_INCOMPLETE);
    expired = 4U;
    CHECK(dmp_reassembly_poll(&g.engine, 999U, &expired) == DMP_OK);
    CHECK(expired == 0U);
    CHECK(dmp_reassembly_poll(&g.engine, 1000U, &expired) == DMP_OK);
    CHECK(expired == 1U);
    CHECK(dmp_reassembly_get(&g.engine, held, &message) == DMP_OK);
    CHECK(g.assemblies[1].live == 0U);
    CHECK(g.tombstones[1].state == DMP_REASSEMBLY_TOMBSTONE_EXPIRED);
    CHECK(g.ids[g.ctx.slot].retained == 1U);
    save_state();
    frame.seq = 2U;
    frame.index = 1U;
    frame.plain = rest;
    handle = sentinel();
    CHECK(apply(&frame, 1001U, &handle) == DMP_DEADLINE_EXPIRED);
    CHECK(untouched(handle));
    CHECK(g.tombstones[1].state == DMP_REASSEMBLY_TOMBSTONE_EXPIRED);
    CHECK(g.assemblies[1].live == 0U);

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    frame = base_frag(8U, 0U, 16U, 32U, body, sizeof body);
    CHECK(apply(&frame, 100U, &handle) == DMP_INCOMPLETE);
    CHECK(g.assemblies[0].deadline == 1100U);
    save_state();
    CHECK(apply(&frame, 1100U, &handle) == DMP_DUPLICATE);
    CHECK(same_state());
    frame.index = 1U;
    frame.plain = rest;
    CHECK(apply(&frame, 1100U, &handle) == DMP_DEADLINE_EXPIRED);
    CHECK(same_state());
    CHECK(dmp_reassembly_poll(NULL, 1100U, &expired) == DMP_INVALID_ARGUMENT);
    CHECK(dmp_reassembly_poll(&g.engine, 1100U, NULL) == DMP_INVALID_ARGUMENT);
    CHECK(g.assemblies[0].live == 1U);
    CHECK(dmp_reassembly_poll(&g.engine, 1100U, &expired) == DMP_OK);
    CHECK(expired == 1U);
    CHECK(g.assemblies[0].live == 0U);
    CHECK(g.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_EXPIRED);
    CHECK(g.ids[g.ctx.slot].retained == 0U);
    CHECK(g.payloads[0] == 0U);
    fenced = g.tombstones[0].source;
    CHECK(fenced.seq == 8U);
    CHECK(apply(&frame, 1101U, &handle) == DMP_DEADLINE_EXPIRED);
    CHECK(g.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_EXPIRED);
    CHECK(g.assemblies[0].live == 0U);

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 0U, 0) == 0);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    CHECK(apply(&frame, 50U, &handle) == DMP_INCOMPLETE);
    CHECK(g.assemblies[0].deadline == 50U);
    frame.index = 1U;
    CHECK(apply(&frame, 50U, &handle) == DMP_DEADLINE_EXPIRED);
    CHECK(g.assemblies[0].received_bitmap == 1U);
    CHECK(dmp_reassembly_poll(&g.engine, 50U, &expired) == DMP_OK);
    CHECK(expired == 1U);
    CHECK(apply(&frame, 51U, &handle) == DMP_DEADLINE_EXPIRED);
    return 0;
}

static int test_retirement(void)
{
    uint8_t body[16];
    frag frame;
    dmp_reassembly_handle handle;
    dmp_identity_handle other;
    dmp_identity_handle retired;
    size_t expired = 0U;

    CHECK(boot(2U, 4U, 1U, 2U, 8U, 16U, MAX_MTU, 100U, 0) == 0);
    CHECK(open_peer(OTHER_ID, PEER_EPOCH, 0, &other));
    pattern(body, sizeof body, 0x81);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    handle = sentinel();
    CHECK(apply(&frame, 0U, &handle) == DMP_INCOMPLETE);
    frame.ctx = other;
    frame.seq = 4U;
    CHECK(apply(&frame, 0U, &handle) == DMP_INCOMPLETE);
    CHECK(dmp_reassembly_poll(&g.engine, 100U, &expired) == DMP_OK);
    CHECK(expired == 2U);
    CHECK(g.ids[g.ctx.slot].retained == 0U);
    CHECK(g.ids[other.slot].retained == 0U);
    CHECK(dmp_reassembly_context_retired(&g.engine, g.ctx) == DMP_CONTEXT_REQUIRED);
    CHECK(g.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_EXPIRED);
    CHECK(dmp_identity_context_begin_drain(&g.table, g.ctx, 500U) == DMP_OK);
    CHECK(dmp_reassembly_context_retired(&g.engine, g.ctx) == DMP_CONTEXT_REQUIRED);
    CHECK(dmp_identity_context_retire(&g.table, g.ctx, 499U) == DMP_CONTEXT_REQUIRED);
    CHECK(dmp_identity_context_retire(&g.table, g.ctx, 500U) == DMP_OK);
    retired = g.ctx;
    CHECK(dmp_reassembly_context_retired(&g.engine, retired) == DMP_OK);
    CHECK(g.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_UNUSED);
    CHECK(g.tombstones[1].state == DMP_REASSEMBLY_TOMBSTONE_EXPIRED);
    CHECK(g.tombstones[1].context.generation == other.generation);
    frame.ctx = other;
    CHECK(apply(&frame, 600U, &handle) == DMP_DEADLINE_EXPIRED);
    CHECK(dmp_reassembly_context_retired(&g.engine, retired) == DMP_OK);
    CHECK(open_peer(PEER_ID, PEER_EPOCH, 0, &g.ctx));
    CHECK(g.ctx.generation != retired.generation);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    CHECK(apply(&frame, 700U, &handle) == DMP_INCOMPLETE);
    frame.ctx = retired;
    CHECK(apply(&frame, 701U, &handle) == DMP_STALE_HANDLE);
    CHECK(g.assemblies[0].live == 1U);
    CHECK(dmp_reassembly_context_retired(&g.engine, retired) == DMP_STALE_HANDLE);
    CHECK(g.assemblies[0].live == 1U);

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 10U, 0) == 0);
    frame = base_frag(9U, 0U, 16U, 32U, body, sizeof body);
    CHECK(apply(&frame, 0U, &handle) == DMP_INCOMPLETE);
    CHECK(dmp_reassembly_poll(&g.engine, 10U, &expired) == DMP_OK);
    frame.seq = 10U;
    CHECK(apply(&frame, 11U, &handle) == DMP_QUOTA_EXHAUSTED);
    CHECK(g.tombstones[0].source.seq == 9U);
    CHECK(g.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_EXPIRED);
    CHECK(g.ids[g.ctx.slot].retained == 0U);
    return 0;
}

static int test_handles_and_overflow(void)
{
    uint8_t body[16];
    uint8_t rest[16];
    frag frame;
    dmp_reassembly_handle handle;
    dmp_reassembly_handle missing;
    dmp_reassembly_message message;
    dmp_reassembly_message painted;

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    pattern(body, sizeof body, 0x91);
    pattern(rest, sizeof rest, 0x92);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    CHECK(dmp_reassembly_on_fragment(&g.engine, NULL, 1U, NULL) == DMP_INVALID_ARGUMENT);
    handle = sentinel();
    CHECK(apply(&frame, 10U, NULL) == DMP_INVALID_ARGUMENT);
    CHECK(g.assemblies[0].live == 0U);
    CHECK(apply(&frame, 10U, &handle) == DMP_INCOMPLETE);
    missing.slot = 0U;
    missing.generation = g.assemblies[0].generation;
    CHECK(dmp_reassembly_release(&g.engine, missing) == DMP_STALE_HANDLE);
    CHECK(g.assemblies[0].live == 1U);
    CHECK(g.ids[g.ctx.slot].retained == 1U);
    frame.index = 1U;
    frame.plain = rest;
    CHECK(apply(&frame, 11U, NULL) == DMP_INVALID_ARGUMENT);
    CHECK(g.assemblies[0].complete == 0U);
    CHECK(g.assemblies[0].received_bitmap == 1U);
    CHECK(apply(&frame, 12U, &handle) == DMP_OK);
    memset(&painted, 0x5A, sizeof painted);
    message = painted;
    missing.generation ^= 1U;
    CHECK(dmp_reassembly_get(&g.engine, missing, &message) == DMP_STALE_HANDLE);
    CHECK(memcmp(&message, &painted, sizeof message) == 0);
    CHECK(dmp_reassembly_release(&g.engine, handle) == DMP_OK);
    CHECK(dmp_reassembly_get(&g.engine, handle, &message) == DMP_STALE_HANDLE);
    CHECK(dmp_reassembly_release(&g.engine, handle) == DMP_STALE_HANDLE);
    frame.index = 0U;
    frame.seq = 2U;
    frame.plain = body;
    CHECK(apply(&frame, 20U, &missing) == DMP_INCOMPLETE);
    CHECK(g.assemblies[0].generation != handle.generation);
    CHECK(dmp_reassembly_get(&g.engine, handle, &message) == DMP_STALE_HANDLE);
    CHECK(dmp_reassembly_get(&g.engine, missing, &message) == DMP_STALE_HANDLE);
    missing.slot = 9U;
    missing.generation = 1U;
    CHECK(dmp_reassembly_get(&g.engine, missing, &message) == DMP_STALE_HANDLE);
    CHECK(dmp_reassembly_get(&g.engine, handle, NULL) == DMP_INVALID_ARGUMENT);

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    handle = sentinel();
    /* Identity not_after is UINT64_MAX, so the clock stays inside that context
     * while assembly_ms still overflows the absolute deadline. */
    CHECK(apply(&frame, UINT64_MAX - 5U, &handle) == DMP_LIMIT_EXHAUSTED);
    CHECK(untouched(handle));
    CHECK(g.assemblies[0].live == 0U);
    CHECK(g.tombstones[0].state == DMP_REASSEMBLY_TOMBSTONE_UNUSED);
    CHECK(g.ids[g.ctx.slot].retained == 0U);
    return 0;
}

static int test_associations(void)
{
    uint8_t body[16];
    uint8_t other[16];
    frag frame;
    dmp_reassembly_handle handle;
    dmp_identity_handle second;
    uint8_t trailer_a[2] = {1, 2};
    uint8_t trailer_b[2] = {3, 4};

    CHECK(boot(2U, 4U, 2U, 4U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    CHECK(open_peer(PEER_ID, PEER_EPOCH, 0, &second));
    pattern(body, sizeof body, 0xA5);
    pattern(other, sizeof other, 0x5A);
    frame = base_frag(6U, 0U, 16U, 32U, body, sizeof body);
    handle = sentinel();
    CHECK(apply(&frame, 1U, &handle) == DMP_INCOMPLETE);
    frame.ctx = second;
    frame.plain = other;
    CHECK(apply(&frame, 1U, &handle) == DMP_INCOMPLETE);
    CHECK(memcmp(g.payloads, body, 16U) == 0);
    CHECK(memcmp(g.payloads + MAX_MSG, other, 16U) == 0);
    CHECK(g.assemblies[0].context.generation != g.assemblies[1].context.generation ||
          g.assemblies[0].context.slot != g.assemblies[1].context.slot);
    frame.ctx = g.ctx;
    frame.plain = other;
    save_state();
    CHECK(apply(&frame, 2U, &handle) == DMP_MALFORMED);
    CHECK(same_state());

    CHECK(boot(1U, 2U, 1U, 2U, 8U, 16U, MAX_MTU, 1000U, 1) == 0);
    frame = base_frag(6U, 0U, 16U, 32U, body, sizeof body);
    CHECK(reject_keeps_empty(&frame, 1U, DMP_MALFORMED) == 0);
    frame.use_security = 1;
    frame.cipher = 1U;
    frame.cid = 4U;
    frame.pn = 1U;
    frame.trailer = trailer_a;
    frame.ntrailer = sizeof trailer_a;
    CHECK(apply(&frame, 10U, &handle) == DMP_INCOMPLETE);
    CHECK(g.assemblies[0].fields.security.pn == 0U);
    CHECK(g.assemblies[0].fields.security.cipher == 1U);
    CHECK(g.assemblies[0].fields.security.receive_cid == 4U);
    save_state();
    frame.pn = 99U;
    frame.trailer = trailer_b;
    frame.ntrailer = sizeof trailer_b;
    CHECK(apply(&frame, 20U, &handle) == DMP_DUPLICATE);
    CHECK(same_state());
    frame.cid = 5U;
    frame.pn = 100U;
    CHECK(apply(&frame, 21U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    frame.cid = 4U;
    frame.cipher = 2U;
    CHECK(apply(&frame, 22U, &handle) == DMP_MALFORMED);
    CHECK(same_state());
    CHECK(g.assemblies[0].deadline == 1010U);

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    frame = base_frag(1U, 0U, 16U, 32U, body, sizeof body);
    frame.use_security = 1;
    frame.cipher = 1U;
    frame.cid = 1U;
    frame.pn = 1U;
    CHECK(reject_keeps_empty(&frame, 1U, DMP_MALFORMED) == 0);
    return 0;
}

static int test_service_two(void)
{
    uint8_t body[16];
    uint8_t rest[16];
    frag frame;
    dmp_reassembly_handle handle;
    dmp_reassembly_message message;

    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    pattern(body, sizeof body, 0xC1);
    pattern(rest, sizeof rest, 0xC2);
    frame = base_frag(2U, 1U, 16U, 32U, rest, sizeof rest);
    frame.service = 2U;
    frame.ext = SVC2;
    frame.next = sizeof SVC2;
    frame.meta = SVC2;
    frame.nmeta = sizeof SVC2;
    handle = sentinel();
    CHECK(apply(&frame, 5U, &handle) == DMP_INCOMPLETE);
    frame.index = 0U;
    frame.plain = body;
    CHECK(apply(&frame, 6U, &handle) == DMP_OK);
    CHECK(dmp_reassembly_get(&g.engine, handle, &message) == DMP_OK);
    CHECK(message.service_id == 2U);
    CHECK(memcmp(message.payload.data, body, 16U) == 0);
    CHECK(memcmp(message.payload.data + 16, rest, 16U) == 0);
    CHECK(message.immutable_metadata.size == sizeof SVC2);
    return 0;
}

static int test_selective_tail(void)
{
    uint8_t body[16];
    uint8_t rest[16];
    uint8_t joined[32];
    frag frame;
    dmp_reassembly_handle handle;
    dmp_reassembly_message message;
    dmp_time_ms arrival = 10U;

    g_selective_boot = 1;
    CHECK(boot(1U, 1U, 1U, 1U, 8U, 16U, MAX_MTU, 1000U, 0) == 0);
    g_selective_boot = 0;
    pattern(body, sizeof body, 0x11);
    pattern(rest, sizeof rest, 0x22);
    memcpy(joined, body, sizeof body);
    memcpy(joined + sizeof body, rest, sizeof rest);
    frame = base_frag(4U, 0U, 16U, 32U, body, sizeof body);
    handle = sentinel();
    CHECK(apply(&frame, arrival, &handle) == DMP_INCOMPLETE);
    CHECK(g.assemblies[0].collection_armed == 1U);
    CHECK(g.assemblies[0].collection_due == arrival + 3U);
    CHECK(g.assemblies[0].status_expected == 0U);
    frame.index = 0U;
    CHECK(apply(&frame, arrival + 1U, &handle) == DMP_DUPLICATE);
    CHECK(g.assemblies[0].collection_due == arrival + 3U);
    CHECK(dmp_reassembly_poll(&g.engine, arrival + 2U, &(size_t){0}) == DMP_OK);
    CHECK(g.assemblies[0].status_expected == 0U);
    CHECK(g.assemblies[0].status_count == 0U);
    CHECK(dmp_reassembly_poll(&g.engine, arrival + 3U, &(size_t){0}) == DMP_OK);
    CHECK(g.assemblies[0].collection_armed == 0U);
    CHECK(g.assemblies[0].status_expected == 1U);
    CHECK(g.assemblies[0].status_count == 1U);
    CHECK(g.assemblies[0].status_mask == 0x00000002U);
    CHECK(dmp_reassembly_poll(&g.engine, arrival + 4U, &(size_t){0}) == DMP_OK);
    CHECK(g.assemblies[0].status_count == 1U);
    frame.index = 1U;
    frame.plain = rest;
    CHECK(apply(&frame, arrival + 5U, &handle) == DMP_OK);
    CHECK(g.assemblies[0].status_expected == 0U);
    CHECK(apply(&frame, arrival + 6U, &handle) == DMP_DUPLICATE);
    CHECK(dmp_reassembly_get(&g.engine, handle, &message) == DMP_OK);
    CHECK(message.payload.size == sizeof joined);
    CHECK(memcmp(message.payload.data, joined, sizeof joined) == 0);
    CHECK(dmp_reassembly_get(&g.engine, handle, &message) == DMP_OK);
    CHECK(message.payload.size == sizeof joined);
    return 0;
}

int main(void)
{
    if (test_init_bounds() != 0) {
        return 1;
    }
    if (test_extra_storage() != 0) {
        return 1;
    }
    if (test_stride_and_order() != 0) {
        return 1;
    }
    if (test_conflicts_and_retries() != 0) {
        return 1;
    }
    if (test_three_fragments() != 0) {
        return 1;
    }
    if (test_limits_do_not_reserve() != 0) {
        return 1;
    }
    if (test_quotas() != 0) {
        return 1;
    }
    if (test_expiry_and_fence() != 0) {
        return 1;
    }
    if (test_retirement() != 0) {
        return 1;
    }
    if (test_handles_and_overflow() != 0) {
        return 1;
    }
    if (test_associations() != 0) {
        return 1;
    }
    if (test_service_two() != 0) {
        return 1;
    }
    if (test_selective_tail() != 0) {
        return 1;
    }
    return 0;
}
