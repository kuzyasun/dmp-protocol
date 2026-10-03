#include "dmp/identity.h"

#include <string.h>

/* Caller-owned association slots.
 * Generation 0 is never a live handle. Init stores 0; the first open uses
 * dmp_generation_next, so the first live generation is 1. Retirement keeps the
 * numeric generation and marks the slot unused, which makes outstanding handles
 * stale. The next open increments that generation and never wraps.
 * not_after is UINT64_MAX until begin_drain. dmp_deadline_reached is therefore
 * true for an undrained slot only when now is UINT64_MAX. Drain does not renew
 * a deadline and does not by itself stop sequence allocation. source/reply
 * resolution stops at the deadline even if the slot has not been retired yet.
 * Explicit SERVICE_ID 1 is the only admissible manifest default and is rejected
 * as noncanonical. This module does not verify AEAD: security==1 means the
 * caller asserts that the association direction is already authenticated. */

static int slot_index(const dmp_identity_table *table, dmp_identity_handle handle)
{
    return table != NULL && handle.generation != 0U && table->slots != NULL &&
           (size_t)handle.slot < table->capacity;
}

static dmp_identity_slot *live_slot(dmp_identity_table *table,
                                    dmp_identity_handle handle)
{
    dmp_identity_slot *slot;

    if (!slot_index(table, handle)) {
        return NULL;
    }
    slot = &table->slots[handle.slot];
    if (slot->generation != handle.generation ||
        slot->state == DMP_IDENTITY_SLOT_UNUSED) {
        return NULL;
    }
    return slot;
}

static const dmp_identity_slot *live_slot_const(const dmp_identity_table *table,
                                                dmp_identity_handle handle)
{
    return live_slot((dmp_identity_table *)table, handle);
}

dmp_status dmp_identity_table_init(dmp_identity_table *table,
                                   dmp_identity_slot *slots, size_t capacity)
{
    size_t i;

    if (table == NULL || (slots == NULL && capacity != 0U)) {
        return DMP_INVALID_ARGUMENT;
    }
    for (i = 0U; i < capacity; i++) {
        memset(&slots[i], 0, sizeof slots[i]);
    }
    table->slots = slots;
    table->capacity = capacity;
    return DMP_OK;
}

dmp_status dmp_identity_context_open(dmp_identity_table *table,
                                     const dmp_identity_context_config *config,
                                     dmp_identity_handle *out)
{
    size_t i;
    uint64_t generation = 0U;
    int generation_exhausted = 0;

    if (table == NULL || config == NULL || out == NULL ||
        (config->security != 0U && config->security != 1U) ||
        (table->capacity != 0U && table->slots == NULL)) {
        return DMP_INVALID_ARGUMENT;
    }
    for (i = 0U; i < table->capacity; i++) {
        dmp_identity_slot *slot = &table->slots[i];
        if (slot->state != DMP_IDENTITY_SLOT_UNUSED) {
            continue;
        }
        if (dmp_generation_next(slot->generation, &generation) != DMP_OK) {
            generation_exhausted = 1;
            continue;
        }
        slot->local = config->local;
        slot->peer = config->peer;
        slot->not_after = UINT64_MAX;
        slot->generation = generation;
        slot->next_seq = 0U;
        slot->retained = 0U;
        slot->security = config->security;
        slot->state = DMP_IDENTITY_SLOT_ACTIVE;
        slot->seq_exhausted = false;
        out->slot = (uint32_t)i;
        out->generation = generation;
        return DMP_OK;
    }
    return generation_exhausted ? DMP_LIMIT_EXHAUSTED : DMP_QUOTA_EXHAUSTED;
}

dmp_status dmp_identity_context_retain(dmp_identity_table *table,
                                       dmp_identity_handle handle)
{
    dmp_identity_slot *slot = live_slot(table, handle);

    if (table == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (slot == NULL) {
        return DMP_STALE_HANDLE;
    }
    if (slot->retained == UINT32_MAX) {
        return DMP_LIMIT_EXHAUSTED;
    }
    slot->retained++;
    return DMP_OK;
}

dmp_status dmp_identity_context_release(dmp_identity_table *table,
                                        dmp_identity_handle handle)
{
    dmp_identity_slot *slot = live_slot(table, handle);

    if (table == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (slot == NULL) {
        return DMP_STALE_HANDLE;
    }
    if (slot->retained == 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    slot->retained--;
    return DMP_OK;
}

dmp_status dmp_identity_context_begin_drain(dmp_identity_table *table,
                                            dmp_identity_handle handle,
                                            dmp_time_ms not_after)
{
    dmp_identity_slot *slot = live_slot(table, handle);

    if (table == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (slot == NULL) {
        return DMP_STALE_HANDLE;
    }
    /* A second drain would extend or replace the original deadline. */
    if (slot->state == DMP_IDENTITY_SLOT_DRAINING) {
        return DMP_DUPLICATE;
    }
    slot->state = DMP_IDENTITY_SLOT_DRAINING;
    slot->not_after = not_after;
    return DMP_OK;
}

dmp_status dmp_identity_context_retire(dmp_identity_table *table,
                                       dmp_identity_handle handle,
                                       dmp_time_ms now)
{
    dmp_identity_slot *slot = live_slot(table, handle);
    uint64_t generation;

    if (table == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (slot == NULL) {
        return DMP_STALE_HANDLE;
    }
    if (slot->state != DMP_IDENTITY_SLOT_DRAINING || slot->retained != 0U ||
        !dmp_deadline_reached(now, slot->not_after)) {
        return DMP_CONTEXT_REQUIRED;
    }
    generation = slot->generation;
    memset(slot, 0, sizeof *slot);
    slot->generation = generation;
    slot->state = DMP_IDENTITY_SLOT_UNUSED;
    return DMP_OK;
}

dmp_status dmp_identity_next_seq(dmp_identity_table *table,
                                 dmp_identity_handle handle, uint32_t *out)
{
    dmp_identity_slot *slot = live_slot(table, handle);
    uint32_t seq;

    if (table == NULL || out == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (slot == NULL) {
        return DMP_STALE_HANDLE;
    }
    if (slot->seq_exhausted) {
        return DMP_LIMIT_EXHAUSTED;
    }
    seq = slot->next_seq;
    if (seq == UINT32_MAX) {
        slot->seq_exhausted = true;
    } else {
        slot->next_seq = seq + 1U;
    }
    *out = seq;
    return DMP_OK;
}

static int read_uleb32(dmp_bytes in, size_t *at, uint32_t *value)
{
    uint64_t acc = 0U;
    size_t start = *at;
    unsigned i;

    for (i = 0U; i < 5U; i++) {
        uint8_t byte;
        uint32_t chunk;
        if (*at >= in.size || in.data == NULL) {
            return 0;
        }
        byte = in.data[(*at)++];
        chunk = (uint32_t)(byte & 0x7fU);
        if (i == 4U && chunk > 0x0fU) {
            return 0;
        }
        acc |= (uint64_t)chunk << (7U * i);
        if ((byte & 0x80U) == 0U) {
            size_t used = *at - start;
            uint64_t check = acc;
            size_t need = 1U;
            while (check >= 0x80U) {
                check >>= 7U;
                need++;
            }
            if (used != need) {
                return 0;
            }
            *value = (uint32_t)acc;
            return 1;
        }
    }
    return 0;
}

static uint64_t read_u64le(const uint8_t *p)
{
    uint64_t value = 0U;
    unsigned i;
    for (i = 0U; i < 8U; i++) {
        value |= (uint64_t)p[i] << (8U * i);
    }
    return value;
}

typedef struct {
    int have_reply;
    int have_context;
    int have_origin;
    int have_service;
    int reply_full;
    uint32_t reply_ns;
    uint32_t reply_origin;
    uint64_t reply_epoch;
    uint32_t reply_seq;
    uint32_t context_ns;
    uint64_t context_epoch;
    uint32_t origin;
    uint32_t service;
} id_ext;

static dmp_status decode_reply(dmp_bytes value, int secured, id_ext *ext)
{
    size_t at = 0U;
    if (secured) {
        if (value.size < 1U || value.size > 5U ||
            !read_uleb32(value, &at, &ext->reply_seq) || at != value.size) {
            return DMP_MALFORMED;
        }
        ext->reply_full = 0;
    } else {
        if (!read_uleb32(value, &at, &ext->reply_ns) ||
            !read_uleb32(value, &at, &ext->reply_origin) ||
            value.size - at < 8U) {
            return DMP_MALFORMED;
        }
        ext->reply_epoch = read_u64le(value.data + at);
        at += 8U;
        if (!read_uleb32(value, &at, &ext->reply_seq) || at != value.size) {
            return DMP_MALFORMED;
        }
        ext->reply_full = 1;
    }
    ext->have_reply = 1;
    return DMP_OK;
}

static dmp_status read_extensions(const dmp_frame_view *frame, int secured, id_ext *ext)
{
    size_t cursor = 0U;
    memset(ext, 0, sizeof *ext);
    if (frame->extensions.size != 0U && frame->extensions.data == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    while (cursor < frame->extensions.size) {
        dmp_extension_view view;
        dmp_status status = dmp_extension_next(frame->extensions, &cursor, &view);
        uint32_t id;
        uint8_t flags;
        size_t at = 0U;
        if (status == DMP_INCOMPLETE) {
            break;
        }
        if (status != DMP_OK) {
            return status;
        }
        id = view.tag >> 2;
        flags = (uint8_t)(view.tag & 3U);
        if (id == 1U) {
            if (flags != 1U || ext->have_reply) {
                return DMP_MALFORMED;
            }
            status = decode_reply(view.value, secured, ext);
            if (status != DMP_OK) {
                return status;
            }
        } else if (id == 2U) {
            if (flags != 3U || ext->have_context ||
                !read_uleb32(view.value, &at, &ext->context_ns) ||
                view.value.size - at != 8U) {
                return DMP_MALFORMED;
            }
            ext->context_epoch = read_u64le(view.value.data + at);
            ext->have_context = 1;
        } else if (id == 3U) {
            if (flags != 3U || ext->have_origin ||
                !read_uleb32(view.value, &at, &ext->origin) || at != view.value.size) {
                return DMP_MALFORMED;
            }
            ext->have_origin = 1;
        } else if (id == 4U) {
            if (flags != 1U || ext->have_service ||
                !read_uleb32(view.value, &at, &ext->service) || at != view.value.size) {
                return DMP_MALFORMED;
            }
            /* The manifest contract fixes the omitted default at service 1. */
            if (ext->service == 1U) {
                return DMP_MALFORMED;
            }
            ext->have_service = 1;
        }
    }
    return DMP_OK;
}

static dmp_status ready_slot(const dmp_identity_table *table, dmp_identity_handle handle,
                             dmp_time_ms now, const dmp_identity_slot **out)
{
    const dmp_identity_slot *slot;
    if (table == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    slot = live_slot_const(table, handle);
    if (slot == NULL) {
        return DMP_STALE_HANDLE;
    }
    if (dmp_deadline_reached(now, slot->not_after)) {
        return DMP_DEADLINE_EXPIRED;
    }
    *out = slot;
    return DMP_OK;
}

static dmp_status source_identity(const dmp_frame_view *frame, const dmp_identity_slot *slot,
                                  const id_ext *ext, dmp_message_key *key)
{
    int secured = (frame->fields.options & DMP_OPT_SECURITY) != 0U;
    int routed = (frame->fields.options & DMP_OPT_ROUTE) != 0U;
    uint32_t origin;

    if ((secured ? 1U : 0U) != slot->security) {
        return DMP_MALFORMED;
    }
    if (routed && ext->have_origin) {
        return DMP_MALFORMED;
    }
    if ((frame->fields.options & DMP_OPT_SEQ) == 0U) {
        return DMP_CONTEXT_REQUIRED;
    }
    if (ext->have_context &&
        (ext->context_ns != slot->peer.namespace_id ||
         ext->context_epoch != slot->peer.epoch)) {
        return DMP_MALFORMED;
    }
    if (routed) {
        origin = frame->fields.route.source;
    } else if (ext->have_origin) {
        origin = ext->origin;
    } else {
        origin = slot->peer.origin_id;
    }
    if (origin != slot->peer.origin_id) {
        return DMP_MALFORMED;
    }
    key->origin.namespace_id = slot->peer.namespace_id;
    key->origin.origin_id = origin;
    key->origin.epoch = ext->have_context ? ext->context_epoch : slot->peer.epoch;
    key->seq = frame->fields.seq;
    return DMP_OK;
}

dmp_status dmp_identity_source_key(const dmp_frame_view *frame,
                                   const dmp_identity_table *table,
                                   dmp_identity_handle handle,
                                   dmp_time_ms now, dmp_message_key *out)
{
    const dmp_identity_slot *slot = NULL;
    id_ext ext;
    dmp_message_key key;
    dmp_status status;
    int secured;

    if (frame == NULL || out == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    status = ready_slot(table, handle, now, &slot);
    if (status != DMP_OK) {
        return status;
    }
    secured = slot->security == 1U;
    status = read_extensions(frame, secured, &ext);
    if (status != DMP_OK) {
        return status;
    }
    if (ext.have_reply && ext.reply_full == secured) {
        return DMP_MALFORMED;
    }
    status = source_identity(frame, slot, &ext, &key);
    if (status != DMP_OK) {
        return status;
    }
    *out = key;
    return DMP_OK;
}

dmp_status dmp_identity_reply_to(const dmp_frame_view *frame,
                                 const dmp_identity_table *table,
                                 dmp_identity_handle handle,
                                 dmp_time_ms now, dmp_message_key *out)
{
    const dmp_identity_slot *slot = NULL;
    id_ext ext;
    dmp_message_key key;
    dmp_status status;

    if (frame == NULL || out == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    status = ready_slot(table, handle, now, &slot);
    if (status != DMP_OK) {
        return status;
    }
    if (((frame->fields.options & DMP_OPT_SECURITY) != 0U) != (slot->security == 1U)) {
        return DMP_MALFORMED;
    }
    status = read_extensions(frame, slot->security == 1U, &ext);
    if (status != DMP_OK) {
        return status;
    }
    if (!ext.have_reply) {
        return DMP_CONTEXT_REQUIRED;
    }
    if (ext.reply_full == (slot->security == 1U)) {
        return DMP_MALFORMED;
    }
    if (slot->security == 1U) {
        key.origin = slot->local;
        key.seq = ext.reply_seq;
    } else {
        if (ext.reply_ns != slot->local.namespace_id ||
            ext.reply_origin != slot->local.origin_id ||
            ext.reply_epoch != slot->local.epoch) {
            return DMP_MALFORMED;
        }
        key.origin.namespace_id = ext.reply_ns;
        key.origin.origin_id = ext.reply_origin;
        key.origin.epoch = ext.reply_epoch;
        key.seq = ext.reply_seq;
    }
    *out = key;
    return DMP_OK;
}
