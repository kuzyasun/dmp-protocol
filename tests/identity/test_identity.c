#include "dmp/identity.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

typedef struct {
    uint8_t data[96];
    size_t n;
} bytes;

static void add_uleb(bytes *out, uint32_t value)
{
    do {
        uint8_t byte = (uint8_t)(value & 0x7fU);
        value >>= 7U;
        if (value != 0U) {
            byte = (uint8_t)(byte | 0x80U);
        }
        out->data[out->n++] = byte;
    } while (value != 0U);
}

static void add_u64le(bytes *out, uint64_t value)
{
    unsigned i;
    for (i = 0U; i < 8U; i++) {
        out->data[out->n++] = (uint8_t)(value & 0xffU);
        value >>= 8U;
    }
}

static void add_tlv(bytes *out, uint32_t tag, const bytes *value)
{
    add_uleb(out, tag);
    add_uleb(out, (uint32_t)value->n);
    memcpy(out->data + out->n, value->data, value->n);
    out->n += value->n;
}

static dmp_identity_context_config sample_config(uint8_t security)
{
    dmp_identity_context_config config;
    memset(&config, 0, sizeof config);
    config.local.namespace_id = 1U;
    config.local.origin_id = 10U;
    config.local.epoch = 7U;
    config.peer.namespace_id = 1U;
    config.peer.origin_id = 20U;
    config.peer.epoch = 9U;
    config.security = security;
    return config;
}

static dmp_frame_view frame_with(uint8_t options, uint32_t seq, uint32_t source,
                                 const bytes *ext)
{
    dmp_frame_view frame;
    memset(&frame, 0, sizeof frame);
    frame.fields.options = options;
    frame.fields.seq = seq;
    frame.fields.route.source = source;
    if (ext != NULL && ext->n != 0U) {
        frame.extensions.data = ext->data;
        frame.extensions.size = ext->n;
    }
    return frame;
}

static int test_slots(void)
{
    dmp_identity_slot slots[2];
    dmp_identity_table table;
    dmp_identity_context_config config = sample_config(0U);
    dmp_identity_handle handle;
    dmp_identity_handle stale = { 0U, 1U };
    uint32_t seq = 99U;
    uint32_t sentinel = 0xabcdefU;

    CHECK(dmp_identity_table_init(NULL, slots, 2U) == DMP_INVALID_ARGUMENT);
    CHECK(dmp_identity_table_init(&table, NULL, 1U) == DMP_INVALID_ARGUMENT);
    CHECK(dmp_identity_table_init(&table, slots, 2U) == DMP_OK);
    CHECK(slots[0].generation == 0U);
    CHECK(slots[0].state == DMP_IDENTITY_SLOT_UNUSED);

    handle.slot = 7U;
    handle.generation = 3U;
    config.security = 2U;
    CHECK(dmp_identity_context_open(&table, &config, &handle) == DMP_INVALID_ARGUMENT);
    CHECK(handle.slot == 7U);
    CHECK(handle.generation == 3U);
    CHECK(slots[0].state == DMP_IDENTITY_SLOT_UNUSED);

    config = sample_config(0U);
    CHECK(dmp_identity_context_open(&table, &config, &handle) == DMP_OK);
    CHECK(handle.slot == 0U);
    CHECK(handle.generation == 1U);
    CHECK(slots[0].not_after == UINT64_MAX);
    CHECK(slots[0].next_seq == 0U);
    CHECK(dmp_identity_next_seq(&table, handle, &seq) == DMP_OK);
    CHECK(seq == 0U);
    CHECK(dmp_identity_next_seq(&table, handle, &seq) == DMP_OK);
    CHECK(seq == 1U);

    slots[0].next_seq = UINT32_MAX;
    sentinel = 0xabcdefU;
    CHECK(dmp_identity_next_seq(&table, handle, &sentinel) == DMP_OK);
    CHECK(sentinel == UINT32_MAX);
    sentinel = 0xabcdefU;
    CHECK(dmp_identity_next_seq(&table, handle, &sentinel) == DMP_LIMIT_EXHAUSTED);
    CHECK(sentinel == 0xabcdefU);

    CHECK(dmp_identity_context_retain(&table, handle) == DMP_OK);
    CHECK(slots[0].retained == 1U);
    CHECK(dmp_identity_context_release(&table, handle) == DMP_OK);
    CHECK(dmp_identity_context_release(&table, handle) == DMP_INVALID_ARGUMENT);
    slots[0].retained = UINT32_MAX;
    CHECK(dmp_identity_context_retain(&table, handle) == DMP_LIMIT_EXHAUSTED);
    CHECK(slots[0].retained == UINT32_MAX);
    slots[0].retained = 0U;

    CHECK(dmp_identity_context_begin_drain(&table, handle, 50U) == DMP_OK);
    CHECK(slots[0].state == DMP_IDENTITY_SLOT_DRAINING);
    CHECK(slots[0].not_after == 50U);
    CHECK(dmp_identity_context_begin_drain(&table, handle, 90U) == DMP_DUPLICATE);
    CHECK(slots[0].not_after == 50U);
    CHECK(dmp_identity_context_retire(&table, handle, 49U) == DMP_CONTEXT_REQUIRED);
    CHECK(slots[0].state == DMP_IDENTITY_SLOT_DRAINING);
    CHECK(dmp_identity_context_retain(&table, handle) == DMP_OK);
    CHECK(dmp_identity_context_retire(&table, handle, 50U) == DMP_CONTEXT_REQUIRED);
    CHECK(dmp_identity_context_release(&table, handle) == DMP_OK);
    CHECK(dmp_identity_context_retire(&table, handle, 50U) == DMP_OK);
    CHECK(slots[0].state == DMP_IDENTITY_SLOT_UNUSED);
    CHECK(slots[0].generation == 1U);
    CHECK(dmp_identity_next_seq(&table, handle, &seq) == DMP_STALE_HANDLE);

    CHECK(dmp_identity_context_open(&table, &config, &handle) == DMP_OK);
    CHECK(handle.generation == 2U);
    CHECK(dmp_identity_context_open(&table, &config, &stale) == DMP_OK);
    CHECK(stale.generation == 1U);
    slots[0].generation = UINT64_MAX;
    slots[0].state = DMP_IDENTITY_SLOT_UNUSED;
    stale.slot = 9U;
    stale.generation = 4U;
    CHECK(dmp_identity_context_open(&table, &config, &stale) == DMP_LIMIT_EXHAUSTED);
    CHECK(stale.slot == 9U);
    CHECK(slots[0].state == DMP_IDENTITY_SLOT_UNUSED);
    CHECK(dmp_identity_context_open(NULL, &config, &handle) == DMP_INVALID_ARGUMENT);
    return 0;
}

static int test_resolution(void)
{
    dmp_identity_slot slots[1];
    dmp_identity_table table;
    dmp_identity_context_config config = sample_config(0U);
    dmp_identity_handle handle;
    dmp_message_key key;
    dmp_message_key sentinel;
    dmp_frame_view frame;
    bytes ext;
    bytes value;
    uint8_t saved;
    uint32_t seq_out = 0U;

    memset(&sentinel, 0x5a, sizeof sentinel);
    key = sentinel;
    CHECK(dmp_identity_table_init(&table, slots, 1U) == DMP_OK);
    CHECK(dmp_identity_context_open(&table, &config, &handle) == DMP_OK);
    CHECK(dmp_identity_source_key(NULL, &table, handle, 0U, &key) == DMP_INVALID_ARGUMENT);
    CHECK(memcmp(&key, &sentinel, sizeof key) == 0);

    memset(&ext, 0, sizeof ext);
    frame = frame_with(0U, 4U, 0U, &ext);
    CHECK(dmp_identity_source_key(&frame, &table, handle, 0U, &key) == DMP_CONTEXT_REQUIRED);

    frame = frame_with(DMP_OPT_SEQ, 4U, 0U, &ext);
    CHECK(dmp_identity_source_key(&frame, &table, handle, 0U, &key) == DMP_OK);
    CHECK(key.origin.namespace_id == 1U);
    CHECK(key.origin.origin_id == 20U);
    CHECK(key.origin.epoch == 9U);
    CHECK(key.seq == 4U);

    frame = frame_with((uint8_t)(DMP_OPT_SEQ | DMP_OPT_ROUTE), 4U, 20U, &ext);
    CHECK(dmp_identity_source_key(&frame, &table, handle, 0U, &key) == DMP_OK);
    frame.fields.route.source = 99U;
    key = sentinel;
    CHECK(dmp_identity_source_key(&frame, &table, handle, 0U, &key) == DMP_MALFORMED);
    CHECK(memcmp(&key, &sentinel, sizeof key) == 0);

    memset(&value, 0, sizeof value);
    add_uleb(&value, 99U);
    memset(&ext, 0, sizeof ext);
    add_tlv(&ext, 15U, &value);
    frame = frame_with((uint8_t)(DMP_OPT_SEQ | DMP_OPT_ROUTE | DMP_OPT_EXT), 4U, 20U, &ext);
    CHECK(dmp_identity_source_key(&frame, &table, handle, 0U, &key) == DMP_MALFORMED);

    memset(&ext, 0, sizeof ext);
    memset(&value, 0, sizeof value);
    add_uleb(&value, 99U);
    add_tlv(&ext, 15U, &value);
    frame = frame_with((uint8_t)(DMP_OPT_SEQ | DMP_OPT_EXT), 4U, 0U, &ext);
    CHECK(dmp_identity_source_key(&frame, &table, handle, 0U, &key) == DMP_MALFORMED);

    memset(&ext, 0, sizeof ext);
    memset(&value, 0, sizeof value);
    add_uleb(&value, 1U);
    add_u64le(&value, 3U);
    add_tlv(&ext, 11U, &value);
    frame = frame_with((uint8_t)(DMP_OPT_SEQ | DMP_OPT_EXT), 4U, 0U, &ext);
    CHECK(dmp_identity_source_key(&frame, &table, handle, 0U, &key) == DMP_MALFORMED);

    memset(&ext, 0, sizeof ext);
    memset(&value, 0, sizeof value);
    add_uleb(&value, 1U);
    add_tlv(&ext, 17U, &value);
    frame = frame_with((uint8_t)(DMP_OPT_SEQ | DMP_OPT_EXT), 4U, 0U, &ext);
    CHECK(dmp_identity_source_key(&frame, &table, handle, 0U, &key) == DMP_MALFORMED);

    memset(&ext, 0, sizeof ext);
    memset(&value, 0, sizeof value);
    add_uleb(&value, 2U);
    add_tlv(&ext, 17U, &value);
    frame = frame_with((uint8_t)(DMP_OPT_SEQ | DMP_OPT_EXT), 8U, 0U, &ext);
    CHECK(dmp_identity_source_key(&frame, &table, handle, 0U, &key) == DMP_OK);
    CHECK(key.seq == 8U);

    CHECK(dmp_identity_reply_to(&frame, &table, handle, 0U, &key) == DMP_CONTEXT_REQUIRED);
    memset(&ext, 0, sizeof ext);
    memset(&value, 0, sizeof value);
    add_uleb(&value, 3U);
    add_tlv(&ext, 5U, &value);
    frame = frame_with((uint8_t)(DMP_OPT_EXT), 0U, 0U, &ext);
    CHECK(dmp_identity_reply_to(&frame, &table, handle, 0U, &key) == DMP_MALFORMED);

    memset(&ext, 0, sizeof ext);
    memset(&value, 0, sizeof value);
    add_uleb(&value, 1U);
    add_uleb(&value, 10U);
    add_u64le(&value, 7U);
    add_uleb(&value, 15U);
    add_tlv(&ext, 5U, &value);
    frame = frame_with(DMP_OPT_EXT, 0U, 0U, &ext);
    CHECK(dmp_identity_reply_to(&frame, &table, handle, 0U, &key) == DMP_OK);
    CHECK(key.origin.origin_id == 10U);
    CHECK(key.origin.epoch == 7U);
    CHECK(key.seq == 15U);

    saved = value.data[0];
    value.data[0] = 2U;
    memset(&ext, 0, sizeof ext);
    add_tlv(&ext, 5U, &value);
    frame = frame_with(DMP_OPT_EXT, 0U, 0U, &ext);
    key = sentinel;
    CHECK(dmp_identity_reply_to(&frame, &table, handle, 0U, &key) == DMP_MALFORMED);
    CHECK(memcmp(&key, &sentinel, sizeof key) == 0);
    value.data[0] = saved;

    CHECK(dmp_identity_context_begin_drain(&table, handle, 10U) == DMP_OK);
    CHECK(dmp_identity_source_key(&frame, &table, handle, 10U, &key) == DMP_DEADLINE_EXPIRED);
    CHECK(dmp_identity_next_seq(&table, handle, &seq_out) == DMP_OK);
    CHECK(seq_out == 0U);
    (void)saved;
    return 0;
}

static int test_authenticated_compact(void)
{
    dmp_identity_slot slots[1];
    dmp_identity_table table;
    dmp_identity_context_config config = sample_config(0U);
    dmp_identity_handle handle;
    dmp_message_key key;
    dmp_frame_view frame;
    bytes ext;
    bytes value;

    CHECK(dmp_identity_table_init(&table, slots, 1U) == DMP_OK);
    CHECK(dmp_test_open_authenticated_context(&table, &config, &handle) == DMP_OK);
    CHECK(slots[0].security == 1U);

    memset(&ext, 0, sizeof ext);
    memset(&value, 0, sizeof value);
    add_uleb(&value, 22U);
    add_tlv(&ext, 5U, &value);
    frame = frame_with((uint8_t)(DMP_OPT_EXT | DMP_OPT_SECURITY), 0U, 0U, &ext);
    CHECK(dmp_identity_reply_to(&frame, &table, handle, 0U, &key) == DMP_OK);
    CHECK(key.origin.namespace_id == 1U);
    CHECK(key.origin.origin_id == 10U);
    CHECK(key.origin.epoch == 7U);
    CHECK(key.seq == 22U);

    memset(&ext, 0, sizeof ext);
    memset(&value, 0, sizeof value);
    add_uleb(&value, 1U);
    add_uleb(&value, 10U);
    add_u64le(&value, 7U);
    add_uleb(&value, 1U);
    add_tlv(&ext, 5U, &value);
    frame = frame_with((uint8_t)(DMP_OPT_EXT | DMP_OPT_SECURITY), 0U, 0U, &ext);
    CHECK(dmp_identity_reply_to(&frame, &table, handle, 0U, &key) == DMP_MALFORMED);

    frame = frame_with(DMP_OPT_SEQ, 5U, 0U, NULL);
    CHECK(dmp_identity_source_key(&frame, &table, handle, 0U, &key) == DMP_MALFORMED);
    frame = frame_with((uint8_t)(DMP_OPT_SEQ | DMP_OPT_SECURITY), 5U, 0U, NULL);
    CHECK(dmp_identity_source_key(&frame, &table, handle, 0U, &key) == DMP_OK);
    CHECK(key.origin.origin_id == 20U);
    CHECK(key.seq == 5U);

    handle.generation = 99U;
    CHECK(dmp_identity_reply_to(&frame, &table, handle, 0U, &key) == DMP_STALE_HANDLE);
    return 0;
}

static int test_quota(void)
{
    dmp_identity_slot slot;
    dmp_identity_table table;
    dmp_identity_context_config config = sample_config(0U);
    dmp_identity_handle handle;
    dmp_identity_handle blocked = { 4U, 4U };

    CHECK(dmp_identity_table_init(&table, NULL, 0U) == DMP_OK);
    CHECK(dmp_identity_context_open(&table, &config, &blocked) == DMP_QUOTA_EXHAUSTED);
    CHECK(blocked.slot == 4U);
    CHECK(dmp_identity_table_init(&table, &slot, 1U) == DMP_OK);
    CHECK(dmp_identity_context_open(&table, &config, &handle) == DMP_OK);
    CHECK(dmp_identity_context_open(&table, &config, &blocked) == DMP_QUOTA_EXHAUSTED);
    CHECK(blocked.slot == 4U);
    CHECK(slot.state == DMP_IDENTITY_SLOT_ACTIVE);
    return 0;
}

static int test_generation_scan(void)
{
    dmp_identity_slot slots[2];
    dmp_identity_table table;
    dmp_identity_context_config config = sample_config(0U);
    dmp_identity_handle handle = { 7U, 9U };

    CHECK(dmp_identity_table_init(&table, slots, 2U) == DMP_OK);
    slots[0].generation = UINT64_MAX;
    CHECK(dmp_identity_context_open(&table, &config, &handle) == DMP_OK);
    CHECK(handle.slot == 1U);
    CHECK(handle.generation == 1U);
    CHECK(slots[0].state == DMP_IDENTITY_SLOT_UNUSED);
    CHECK(slots[1].state == DMP_IDENTITY_SLOT_ACTIVE);
    return 0;
}

int main(void)
{
    if (test_slots() != 0 || test_quota() != 0 || test_generation_scan() != 0 || test_resolution() != 0 ||
        test_authenticated_compact() != 0) {
        return 1;
    }
    return 0;
}
