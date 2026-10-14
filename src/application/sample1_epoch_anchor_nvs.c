#include "sample1_epoch_anchor_nvs.h"

#include <string.h>

#include "dmp/integrity.h"

enum {
    ANCHOR_RECORD_V1_BYTES = 44U,
    ANCHOR_RECORD_V1_VERSION = 1U,
    ANCHOR_OFFSET_MAGIC = 0U,
    ANCHOR_OFFSET_VERSION = 4U,
    ANCHOR_OFFSET_FLAGS = 8U,
    ANCHOR_OFFSET_NAMESPACE = 12U,
    ANCHOR_OFFSET_ORIGIN = 16U,
    ANCHOR_OFFSET_FLOOR = 20U,
    ANCHOR_OFFSET_PENDING = 28U,
    ANCHOR_OFFSET_RESERVED = 36U,
    ANCHOR_OFFSET_CRC32C = 40U,
    ANCHOR_FLAG_HAS_FLOOR = 1U,
    ANCHOR_FLAG_PENDING = 2U
};

static const uint8_t g_anchor_magic[4] = { 'S', '1', 'A', 'N' };

typedef struct {
    bool has_floor;
    uint64_t floor;
    bool is_pending;
    uint64_t pending_epoch;
} anchor_record_state;

static void encode_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value & 0xFFU);
    out[1] = (uint8_t)((value >> 8U) & 0xFFU);
    out[2] = (uint8_t)((value >> 16U) & 0xFFU);
    out[3] = (uint8_t)((value >> 24U) & 0xFFU);
}

static uint32_t decode_u32_le(const uint8_t *in)
{
    return ((uint32_t)in[0]) |
           (((uint32_t)in[1]) << 8U) |
           (((uint32_t)in[2]) << 16U) |
           (((uint32_t)in[3]) << 24U);
}

static void encode_u64_le(uint8_t *out, uint64_t value)
{
    size_t i;
    for (i = 0U; i < 8U; ++i) {
        out[i] = (uint8_t)((value >> (i * 8U)) & 0xFFU);
    }
}

static uint64_t decode_u64_le(const uint8_t *in)
{
    uint64_t value = 0U;
    size_t i;
    for (i = 0U; i < 8U; ++i) {
        value |= ((uint64_t)in[i]) << (i * 8U);
    }
    return value;
}

static bool encode_state(uint8_t out[ANCHOR_RECORD_V1_BYTES],
                         dmp_sample1_principal principal,
                         const anchor_record_state *state)
{
    uint32_t flags = 0U;
    uint32_t crc = 0U;

    if (out == NULL || state == NULL ||
        (state->has_floor && state->floor == 0U) ||
        (!state->has_floor && state->floor != 0U) ||
        (state->is_pending && state->pending_epoch == 0U) ||
        (!state->is_pending && state->pending_epoch != 0U) ||
        (state->has_floor && state->is_pending && state->pending_epoch <= state->floor)) {
        return false;
    }

    (void)memset(out, 0, ANCHOR_RECORD_V1_BYTES);
    (void)memcpy(&out[ANCHOR_OFFSET_MAGIC], g_anchor_magic, sizeof(g_anchor_magic));
    encode_u32_le(&out[ANCHOR_OFFSET_VERSION], ANCHOR_RECORD_V1_VERSION);
    if (state->has_floor) {
        flags |= ANCHOR_FLAG_HAS_FLOOR;
    }
    if (state->is_pending) {
        flags |= ANCHOR_FLAG_PENDING;
    }
    encode_u32_le(&out[ANCHOR_OFFSET_FLAGS], flags);
    encode_u32_le(&out[ANCHOR_OFFSET_NAMESPACE], principal.namespace_id);
    encode_u32_le(&out[ANCHOR_OFFSET_ORIGIN], principal.origin_id);
    encode_u64_le(&out[ANCHOR_OFFSET_FLOOR], state->floor);
    encode_u64_le(&out[ANCHOR_OFFSET_PENDING], state->pending_epoch);
    if (dmp_crc32c((dmp_bytes){ out, ANCHOR_OFFSET_CRC32C }, &crc) != DMP_OK) {
        return false;
    }
    encode_u32_le(&out[ANCHOR_OFFSET_CRC32C], crc);
    return true;
}

static bool decode_state(const uint8_t in[ANCHOR_RECORD_V1_BYTES],
                         dmp_sample1_principal expected_principal,
                         anchor_record_state *state)
{
    uint32_t crc = 0U;
    uint32_t flags;
    uint32_t ns;
    uint32_t origin;
    size_t i;
    anchor_record_state decoded;

    if (in == NULL || state == NULL ||
        memcmp(&in[ANCHOR_OFFSET_MAGIC], g_anchor_magic, sizeof(g_anchor_magic)) != 0 ||
        decode_u32_le(&in[ANCHOR_OFFSET_VERSION]) != ANCHOR_RECORD_V1_VERSION ||
        dmp_crc32c((dmp_bytes){ in, ANCHOR_OFFSET_CRC32C }, &crc) != DMP_OK ||
        crc != decode_u32_le(&in[ANCHOR_OFFSET_CRC32C])) {
        return false;
    }

    flags = decode_u32_le(&in[ANCHOR_OFFSET_FLAGS]);
    if ((flags & ~(uint32_t)(ANCHOR_FLAG_HAS_FLOOR | ANCHOR_FLAG_PENDING)) != 0U) {
        return false;
    }
    for (i = ANCHOR_OFFSET_RESERVED; i < ANCHOR_OFFSET_CRC32C; ++i) {
        if (in[i] != 0U) {
            return false;
        }
    }

    ns = decode_u32_le(&in[ANCHOR_OFFSET_NAMESPACE]);
    origin = decode_u32_le(&in[ANCHOR_OFFSET_ORIGIN]);
    if (ns != expected_principal.namespace_id || origin != expected_principal.origin_id) {
        return false;
    }

    decoded.has_floor = (flags & ANCHOR_FLAG_HAS_FLOOR) != 0U;
    decoded.is_pending = (flags & ANCHOR_FLAG_PENDING) != 0U;
    decoded.floor = decode_u64_le(&in[ANCHOR_OFFSET_FLOOR]);
    decoded.pending_epoch = decode_u64_le(&in[ANCHOR_OFFSET_PENDING]);
    if ((decoded.has_floor && decoded.floor == 0U) ||
        (!decoded.has_floor && decoded.floor != 0U) ||
        (decoded.is_pending && decoded.pending_epoch == 0U) ||
        (!decoded.is_pending && decoded.pending_epoch != 0U) ||
        (decoded.has_floor && decoded.is_pending && decoded.pending_epoch <= decoded.floor)) {
        return false;
    }

    *state = decoded;
    return true;
}

static const char *anchor_key(const dmp_sample1_nvs_epoch_anchor *anchor)
{
    return (anchor->key != NULL) ? anchor->key : "s1_anchor";
}

static esp_err_t do_get_blob(const dmp_sample1_nvs_epoch_anchor *anchor,
                             void *out,
                             size_t *length)
{
    if (anchor->ops != NULL) {
        return anchor->ops->get_blob(anchor->nvs_handle, anchor_key(anchor), out, length);
    }
#if defined(ESP_PLATFORM)
    return nvs_get_blob(anchor->nvs_handle, anchor_key(anchor), out, length);
#else
    (void)out;
    (void)length;
    return -1;
#endif
}

static esp_err_t do_set_blob(const dmp_sample1_nvs_epoch_anchor *anchor,
                             const void *value,
                             size_t length)
{
    if (anchor->ops != NULL) {
        return anchor->ops->set_blob(anchor->nvs_handle, anchor_key(anchor), value, length);
    }
#if defined(ESP_PLATFORM)
    return nvs_set_blob(anchor->nvs_handle, anchor_key(anchor), value, length);
#else
    (void)value;
    (void)length;
    return -1;
#endif
}

static esp_err_t do_commit(const dmp_sample1_nvs_epoch_anchor *anchor)
{
    if (anchor->ops != NULL) {
        return anchor->ops->commit(anchor->nvs_handle);
    }
#if defined(ESP_PLATFORM)
    return nvs_commit(anchor->nvs_handle);
#else
    return -1;
#endif
}

static bool valid_adapter(const dmp_sample1_nvs_epoch_anchor *anchor)
{
    return anchor != NULL &&
           (anchor->ops == NULL ||
            (anchor->ops->get_blob != NULL && anchor->ops->set_blob != NULL &&
             anchor->ops->commit != NULL));
}

/* Returns true for a valid record or a clean missing key. A corrupt record or
 * storage error fails closed. No candidate epoch is exposed by this adapter. */
static bool read_state(const dmp_sample1_nvs_epoch_anchor *anchor,
                       dmp_sample1_principal principal,
                       anchor_record_state *state)
{
    uint8_t record[ANCHOR_RECORD_V1_BYTES];
    size_t length = sizeof(record);
    esp_err_t err;

    if (!valid_adapter(anchor) || state == NULL) {
        return false;
    }

    err = do_get_blob(anchor, record, &length);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        (void)memset(state, 0, sizeof(*state));
        return true;
    }
    if (err != ESP_OK || length != sizeof(record)) {
        return false;
    }
    return decode_state(record, principal, state);
}

static bool write_state(const dmp_sample1_nvs_epoch_anchor *anchor,
                        dmp_sample1_principal principal,
                        const anchor_record_state *state)
{
    uint8_t record[ANCHOR_RECORD_V1_BYTES];

    if (!valid_adapter(anchor) || !encode_state(record, principal, state)) {
        return false;
    }
    if (do_set_blob(anchor, record, sizeof(record)) != ESP_OK) {
        return false;
    }
    return do_commit(anchor) == ESP_OK;
}

static bool get_status(void *user,
                       dmp_sample1_principal principal,
                       dmp_sample1_anchor_status *status)
{
    anchor_record_state state;
    dmp_sample1_anchor_status decoded;

    if (status == NULL || !read_state((const dmp_sample1_nvs_epoch_anchor *)user,
                                      principal, &state)) {
        return false;
    }
    decoded.has_floor = state.has_floor;
    decoded.floor = state.floor;
    decoded.is_pending = state.is_pending;
    decoded.pending_epoch = state.pending_epoch;
    *status = decoded;
    return true;
}

static bool begin_reservation(void *user,
                              dmp_sample1_principal principal,
                              bool has_expected_floor,
                              uint64_t expected_floor,
                              bool is_recovery,
                              uint64_t expected_pending,
                              uint64_t candidate_epoch)
{
    dmp_sample1_nvs_epoch_anchor *anchor = (dmp_sample1_nvs_epoch_anchor *)user;
    anchor_record_state state;

    if (candidate_epoch == 0U || !read_state(anchor, principal, &state)) {
        return false;
    }

    if (is_recovery) {
        if (!state.is_pending || state.pending_epoch != expected_pending ||
            candidate_epoch <= expected_pending) {
            return false;
        }
    } else {
        if (state.is_pending || state.has_floor != has_expected_floor ||
            (state.has_floor && state.floor != expected_floor) ||
            (!state.has_floor && expected_floor != 0U) ||
            (state.has_floor && candidate_epoch <= state.floor)) {
            return false;
        }
    }

    state.is_pending = true;
    state.pending_epoch = candidate_epoch;
    return write_state(anchor, principal, &state);
}

static bool complete_reservation(void *user,
                                 dmp_sample1_principal principal,
                                 uint64_t committed_epoch)
{
    dmp_sample1_nvs_epoch_anchor *anchor = (dmp_sample1_nvs_epoch_anchor *)user;
    anchor_record_state state;

    if (committed_epoch == 0U || !read_state(anchor, principal, &state) ||
        !state.is_pending || state.pending_epoch != committed_epoch ||
        (state.has_floor && committed_epoch <= state.floor)) {
        return false;
    }

    state.has_floor = true;
    state.floor = committed_epoch;
    state.is_pending = false;
    state.pending_epoch = 0U;
    return write_state(anchor, principal, &state);
}

const dmp_sample1_epoch_anchor_ops dmp_sample1_nvs_anchor_ops = {
    .get_status = get_status,
    .begin_reservation = begin_reservation,
    .complete_reservation = complete_reservation
};

void dmp_sample1_nvs_epoch_anchor_init(dmp_sample1_nvs_epoch_anchor *anchor,
                                       nvs_handle_t nvs_handle,
                                       const char *key,
                                       const dmp_sample1_nvs_ops *ops)
{
    if (anchor == NULL) {
        return;
    }
    anchor->nvs_handle = nvs_handle;
    anchor->key = (key != NULL) ? key : "s1_anchor";
    anchor->ops = ops;
}
