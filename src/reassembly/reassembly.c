#include "dmp/reassembly.h"

#include <stdint.h>
#include <string.h>

/* Fixed-stride reassembly. The caller has already authenticated each frame and
 * resolved authorization. This module copies plaintext and canonical immutable
 * metadata into caller-owned slots. It does not allocate, ACK, or dispatch a
 * partial message. One owner serializes every call.
 *
 * The first accepted slice reserves one assembly slot, its full payload and
 * metadata rows, one identity retain, and one RESERVED tombstone. That
 * tombstone becomes an EXPIRED no-reopen fence only from poll. Successful
 * release returns the still-RESERVED tombstone; expiry fences are cleared only
 * by context_retired after the identity context itself has been retired.
 * Tombstones are never evicted to make room. */

_Static_assert(sizeof(dmp_reassembly_tombstone) == 48,
               "profile assembly_tombstone charge is 48 bytes");
_Static_assert(sizeof(dmp_reassembly_slot) + DMP_REASSEMBLY_METADATA_BYTES <= 512,
               "manifest assembly metadata reserve is 512 bytes");

static int ready(const dmp_reassembly *engine)
{
    return engine != NULL && engine->initialized != 0U;
}

static int bytes_ok(dmp_bytes bytes)
{
    return bytes.size == 0U || bytes.data != NULL;
}

static int key_eq(dmp_message_key a, dmp_message_key b)
{
    return a.seq == b.seq && a.origin.namespace_id == b.origin.namespace_id &&
           a.origin.origin_id == b.origin.origin_id && a.origin.epoch == b.origin.epoch;
}

static int origin_eq(dmp_message_origin a, dmp_message_origin b)
{
    return a.namespace_id == b.namespace_id && a.origin_id == b.origin_id && a.epoch == b.epoch;
}

static int context_eq(dmp_identity_handle a, dmp_identity_handle b)
{
    return a.slot == b.slot && a.generation == b.generation;
}

static int service_allowed(const dmp_admitted_profile *profile, uint32_t service)
{
    return service != 0U &&
           (service == profile->service_id[0] || service == profile->service_id[1]);
}

static int selective_service(const dmp_admitted_profile *profile, uint32_t service)
{
    if (service == profile->service_id[0]) {
        return profile->recovery[0] == DMP_PROFILE_RECOVERY_SELECTIVE32;
    }
    if (service == profile->service_id[1]) {
        return profile->recovery[1] == DMP_PROFILE_RECOVERY_SELECTIVE32;
    }
    return 0;
}

static uint32_t missing_mask(const dmp_reassembly_slot *slot)
{
    uint32_t count;
    uint32_t all;

    if (slot->chunk_size == 0U || slot->total_size <= slot->chunk_size) {
        return 0U;
    }
    count = 1U + (slot->total_size - 1U) / slot->chunk_size;
    if (count < 2U || count > 32U) {
        return 0U;
    }
    all = count == 32U ? 0xFFFFFFFFU : (1U << count) - 1U;
    return all & ~slot->received_bitmap;
}

/* R4.2. The due time is arrival plus burst_span+forward_delay+feedback_guard.
 * collect_ms is not this timer. A later slice does not move an armed due time.
 * A pending status is not a second timer. */
static void note_collection(dmp_reassembly_slot *slot, const dmp_admitted_profile *profile,
                            uint32_t service, dmp_time_ms now, int complete)
{
    uint32_t sum;
    uint32_t span;

    if (complete) {
        slot->collection_armed = 0U;
        slot->status_expected = 0U;
        return;
    }
    if (!selective_service(profile, service) || slot->collection_armed != 0U ||
        slot->status_expected != 0U) {
        return;
    }
    if (profile->burst_span_ms > 0xFFFFFFFFU - profile->forward_delay_ms) {
        return;
    }
    sum = profile->burst_span_ms + profile->forward_delay_ms;
    if (sum > 0xFFFFFFFFU - profile->feedback_guard_ms) {
        return;
    }
    span = sum + profile->feedback_guard_ms;
    if (dmp_deadline_after(now, span, &slot->collection_due) != DMP_OK) {
        return;
    }
    slot->collection_armed = 1U;
}

static dmp_status check_minimum_capacity(uint32_t count, uint32_t elem, size_t actual)
{
    size_t minimum;

    if (elem != 0U && (size_t)count > SIZE_MAX / (size_t)elem) {
        return DMP_INVALID_ARGUMENT;
    }
    minimum = (size_t)count * (size_t)elem;
    if (actual < minimum) {
        return DMP_INVALID_ARGUMENT;
    }
    return DMP_OK;
}

static dmp_status require_array(size_t count, const void *pointer)
{
    if (count != 0U && pointer == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    return DMP_OK;
}

static uint8_t *payload_ptr(dmp_reassembly *engine, size_t index)
{
    return engine->storage.payloads + index * (size_t)engine->profile.message_bytes;
}

static const uint8_t *payload_ptr_const(const dmp_reassembly *engine, size_t index)
{
    return engine->storage.payloads + index * (size_t)engine->profile.message_bytes;
}

static uint8_t *metadata_ptr(dmp_reassembly *engine, size_t index)
{
    return engine->storage.metadata + index * (size_t)DMP_REASSEMBLY_METADATA_BYTES;
}

static const uint8_t *metadata_ptr_const(const dmp_reassembly *engine, size_t index)
{
    return engine->storage.metadata + index * (size_t)DMP_REASSEMBLY_METADATA_BYTES;
}

static uint32_t fragment_bit(uint32_t index)
{
    return 1U << index;
}

static uint32_t fragment_mask(uint32_t count)
{
    if (count >= 32U) {
        return 0xFFFFFFFFU;
    }
    return (1U << count) - 1U;
}

static void clear_assembly(dmp_reassembly_slot *slot)
{
    uint64_t generation = slot->generation;

    memset(slot, 0, sizeof *slot);
    slot->generation = generation;
}

static void normalize_fields(const dmp_header_fields *in, dmp_header_fields *out)
{
    memset(out, 0, sizeof *out);
    out->type = in->type;
    out->options = (uint8_t)(in->options & (uint8_t) ~(uint8_t)DMP_OPT_FRAG);
    out->seq = in->seq;
    if ((out->options & DMP_OPT_ROUTE) != 0U) {
        out->route = in->route;
        /* Main §11: TTL may differ along a path and is not an immutable
         * reassembly field. Mode, source and destination still have to agree. */
        out->route.ttl = 0U;
    }
    if ((out->options & DMP_OPT_PAYLOAD_DESC) != 0U) {
        out->descriptor = in->descriptor;
    }
    if ((out->options & DMP_OPT_INTEGRITY) != 0U) {
        out->integrity = in->integrity;
    }
    if ((out->options & DMP_OPT_SECURITY) != 0U) {
        out->security.cipher = in->security.cipher;
        out->security.receive_cid = in->security.receive_cid;
    }
}

static int fields_match(const dmp_header_fields *stored, const dmp_header_fields *incoming)
{
    dmp_header_fields norm;

    normalize_fields(incoming, &norm);
    return stored->type == norm.type && stored->options == norm.options &&
           stored->seq == norm.seq && stored->route.mode == norm.route.mode &&
           stored->route.ttl == norm.route.ttl && stored->route.source == norm.route.source &&
           stored->route.destination == norm.route.destination &&
           stored->descriptor.flags == norm.descriptor.flags &&
           stored->descriptor.codec == norm.descriptor.codec &&
           stored->descriptor.schema == norm.descriptor.schema &&
           stored->descriptor.schema_version == norm.descriptor.schema_version &&
           stored->integrity == norm.integrity && stored->security.cipher == norm.security.cipher &&
           stored->security.receive_cid == norm.security.receive_cid &&
           stored->security.pn == norm.security.pn &&
           stored->fragment.index == norm.fragment.index &&
           stored->fragment.chunk_size == norm.fragment.chunk_size &&
           stored->fragment.total_size == norm.fragment.total_size;
}

static int read_uleb32(dmp_bytes in, size_t *at, uint32_t *value)
{
    uint64_t acc = 0U;
    size_t start = *at;
    unsigned i;

    for (i = 0U; i < 5U; i++) {
        uint8_t byte;
        uint32_t chunk;
        size_t used;
        size_t need;
        uint64_t check;

        if (*at >= in.size || in.data == NULL) {
            return 0;
        }
        byte = in.data[(*at)++];
        chunk = (uint32_t)(byte & 0x7fU);
        if (i == 4U && chunk > 0x0fU) {
            return 0;
        }
        acc |= (uint64_t)chunk << (7U * i);
        if ((byte & 0x80U) != 0U) {
            continue;
        }
        used = *at - start;
        check = acc;
        need = 1U;
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
    return 0;
}

static dmp_status check_service(const dmp_reassembly *engine, const dmp_reassembly_input *input)
{
    size_t cursor = 0U;
    int seen = 0;
    uint32_t wire = 0U;
    dmp_bytes extensions = input->frame->extensions;

    if (extensions.size != 0U && extensions.data == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    while (cursor < extensions.size) {
        dmp_extension_view view;
        dmp_status status = dmp_extension_next(extensions, &cursor, &view);
        uint32_t id;
        size_t at = 0U;

        if (status == DMP_INCOMPLETE) {
            break;
        }
        if (status != DMP_OK) {
            return status;
        }
        id = view.tag >> 2;
        if (id != 4U) {
            continue;
        }
        if (seen != 0 || (view.tag & 3U) != 1U ||
            !read_uleb32(view.value, &at, &wire) || at != view.value.size) {
            return DMP_MALFORMED;
        }
        seen = 1;
    }
    if (seen) {
        if (wire != input->service_id || wire == engine->profile.default_service) {
            return DMP_MALFORMED;
        }
    } else if (input->service_id != engine->profile.default_service) {
        return DMP_MALFORMED;
    }
    if (!service_allowed(&engine->profile, input->service_id)) {
        return DMP_UNSUPPORTED;
    }
    return DMP_OK;
}

/* Geometry is in plaintext bytes. Invalid shapes are malformed; configured
 * ceilings are limit failures. Nothing here writes engine state. */
static dmp_status slice_geometry(const dmp_admitted_profile *profile, uint32_t index,
                                 uint32_t chunk, uint32_t total, size_t plaintext_len,
                                 uint32_t *count_out, uint32_t *offset_out)
{
    uint32_t count;
    uint64_t offset;
    uint32_t expect;

    if (chunk == 0U || chunk >= total) {
        return DMP_MALFORMED;
    }
    if (chunk > profile->chunk_bytes || total > profile->message_bytes ||
        chunk > profile->encoded_mtu || plaintext_len > profile->encoded_mtu) {
        return DMP_LIMIT_EXHAUSTED;
    }
    count = 1U + (total - 1U) / chunk;
    if (count < 2U) {
        return DMP_MALFORMED;
    }
    if (count > profile->fragments || count > 32U) {
        return DMP_LIMIT_EXHAUSTED;
    }
    if (index >= count) {
        return DMP_MALFORMED;
    }
    offset = (uint64_t)index * (uint64_t)chunk;
    if (offset >= total || offset > UINT32_MAX) {
        return DMP_MALFORMED;
    }
    expect = total - (uint32_t)offset;
    if (expect > chunk) {
        expect = chunk;
    }
    if (plaintext_len != (size_t)expect) {
        return DMP_MALFORMED;
    }
    *count_out = count;
    *offset_out = (uint32_t)offset;
    return DMP_OK;
}

static int find_assembly(const dmp_reassembly *engine, dmp_message_key key,
                         dmp_identity_handle context, size_t *out)
{
    size_t i;

    for (i = 0U; i < engine->storage.assembly_capacity; i++) {
        const dmp_reassembly_slot *slot = &engine->storage.assemblies[i];
        if (slot->live != 0U && key_eq(slot->source, key) && context_eq(slot->context, context)) {
            *out = i;
            return 1;
        }
    }
    return 0;
}

static int find_expired(const dmp_reassembly *engine, dmp_message_key key,
                        dmp_identity_handle context)
{
    size_t i;

    for (i = 0U; i < engine->storage.tombstone_capacity; i++) {
        const dmp_reassembly_tombstone *tomb = &engine->storage.tombstones[i];
        if (tomb->state == DMP_REASSEMBLY_TOMBSTONE_EXPIRED && key_eq(tomb->source, key) &&
            context_eq(tomb->context, context)) {
            return 1;
        }
    }
    return 0;
}

static size_t count_origin_assemblies(const dmp_reassembly *engine, dmp_message_origin origin)
{
    size_t i;
    size_t n = 0U;

    for (i = 0U; i < engine->storage.assembly_capacity; i++) {
        const dmp_reassembly_slot *slot = &engine->storage.assemblies[i];
        if (slot->live != 0U && origin_eq(slot->source.origin, origin)) {
            n++;
        }
    }
    return n;
}

static size_t count_origin_tombstones(const dmp_reassembly *engine, dmp_message_origin origin)
{
    size_t i;
    size_t n = 0U;

    for (i = 0U; i < engine->storage.tombstone_capacity; i++) {
        const dmp_reassembly_tombstone *tomb = &engine->storage.tombstones[i];
        if (tomb->state != DMP_REASSEMBLY_TOMBSTONE_UNUSED &&
            origin_eq(tomb->source.origin, origin)) {
            n++;
        }
    }
    return n;
}

static int find_free_assembly(const dmp_reassembly *engine, size_t *out)
{
    size_t i;

    for (i = 0U; i < engine->storage.assembly_capacity; i++) {
        if (engine->storage.assemblies[i].live == 0U) {
            *out = i;
            return 1;
        }
    }
    return 0;
}

static int find_free_tombstone(const dmp_reassembly *engine, size_t *out)
{
    size_t i;

    for (i = 0U; i < engine->storage.tombstone_capacity; i++) {
        if (engine->storage.tombstones[i].state == DMP_REASSEMBLY_TOMBSTONE_UNUSED) {
            *out = i;
            return 1;
        }
    }
    return 0;
}

static int metadata_match(const dmp_reassembly *engine, const dmp_reassembly_slot *slot,
                          size_t slot_index, dmp_bytes metadata)
{
    if ((size_t)slot->metadata_len != metadata.size) {
        return 0;
    }
    if (metadata.size == 0U) {
        return 1;
    }
    return memcmp(metadata_ptr_const(engine, slot_index), metadata.data, metadata.size) == 0;
}

static dmp_status accept_existing(dmp_reassembly *engine, size_t slot_index,
                                  const dmp_reassembly_input *input, dmp_time_ms now,
                                  dmp_reassembly_handle *completed)
{
    dmp_reassembly_slot *slot = &engine->storage.assemblies[slot_index];
    const dmp_header_fields *fields = &input->frame->fields;
    uint32_t count = 0U;
    uint32_t offset = 0U;
    uint32_t bit;
    uint8_t *payload;
    dmp_status status;

    if (input->service_id != slot->service_id ||
        !metadata_match(engine, slot, slot_index, input->immutable_metadata) ||
        !fields_match(&slot->fields, fields) || fields->fragment.chunk_size != slot->chunk_size ||
        fields->fragment.total_size != slot->total_size) {
        return DMP_MALFORMED;
    }
    status = slice_geometry(&engine->profile, fields->fragment.index, slot->chunk_size,
                            slot->total_size, input->plaintext.size, &count, &offset);
    if (status != DMP_OK) {
        return status;
    }
    if (fields->fragment.index >= 32U) {
        return DMP_MALFORMED;
    }
    bit = fragment_bit(fields->fragment.index);
    payload = payload_ptr(engine, slot_index);
    if ((slot->received_bitmap & bit) != 0U) {
        if (memcmp(payload + offset, input->plaintext.data, input->plaintext.size) != 0) {
            return DMP_MALFORMED;
        }
        /* An accepted index after the assembly deadline is expiry, including
         * before poll records the tombstone. Do not arm collection. */
        if (slot->complete == 0U && dmp_deadline_reached(now, slot->deadline)) {
            return DMP_DEADLINE_EXPIRED;
        }
        /* R4: after a feedback opportunity, a later probe re-arms collection.
         * An already armed timer does not move. A complete transfer does not. */
        if (slot->complete == 0U) {
            note_collection(slot, &engine->profile, slot->service_id, now, 0);
        }
        return DMP_DUPLICATE;
    }
    if (slot->complete == 0U && dmp_deadline_reached(now, slot->deadline)) {
        return DMP_DEADLINE_EXPIRED;
    }
    memcpy(payload + offset, input->plaintext.data, input->plaintext.size);
    slot->received_bitmap |= bit;
    if ((slot->received_bitmap & fragment_mask(count)) == fragment_mask(count)) {
        slot->complete = 1U;
        note_collection(slot, &engine->profile, slot->service_id, now, 1);
        completed->slot = (uint32_t)slot_index;
        completed->generation = slot->generation;
        return DMP_OK;
    }
    note_collection(slot, &engine->profile, slot->service_id, now, 0);
    return DMP_INCOMPLETE;
}

static dmp_status accept_new(dmp_reassembly *engine, dmp_message_key key,
                             const dmp_reassembly_input *input, dmp_time_ms now,
                             dmp_reassembly_handle *completed)
{
    const dmp_header_fields *fields = &input->frame->fields;
    dmp_reassembly_slot *slot;
    dmp_reassembly_tombstone *tomb;
    size_t slot_index = 0U;
    size_t tomb_index = 0U;
    uint32_t count = 0U;
    uint32_t offset = 0U;
    uint64_t generation = 0U;
    dmp_time_ms deadline = 0U;
    dmp_status status;

    if (find_expired(engine, key, input->context)) {
        return DMP_DEADLINE_EXPIRED;
    }
    status = slice_geometry(&engine->profile, fields->fragment.index, fields->fragment.chunk_size,
                            fields->fragment.total_size, input->plaintext.size, &count, &offset);
    if (status != DMP_OK) {
        return status;
    }
    if (input->immutable_metadata.size > (size_t)DMP_REASSEMBLY_METADATA_BYTES) {
        return DMP_LIMIT_EXHAUSTED;
    }
    if (fields->fragment.index >= 32U) {
        return DMP_MALFORMED;
    }
    if (count_origin_assemblies(engine, key.origin) >= engine->profile.assemblies_per_peer ||
        !find_free_assembly(engine, &slot_index) ||
        count_origin_tombstones(engine, key.origin) >=
            engine->profile.assembly_tombstones_per_peer ||
        !find_free_tombstone(engine, &tomb_index)) {
        return DMP_QUOTA_EXHAUSTED;
    }
    status = dmp_deadline_after(now, engine->profile.assembly_ms, &deadline);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_generation_next(engine->storage.assemblies[slot_index].generation, &generation);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_identity_context_retain(engine->storage.identity, input->context);
    if (status != DMP_OK) {
        return status;
    }

    slot = &engine->storage.assemblies[slot_index];
    tomb = &engine->storage.tombstones[tomb_index];
    memset(payload_ptr(engine, slot_index), 0, engine->profile.message_bytes);
    memset(metadata_ptr(engine, slot_index), 0, (size_t)DMP_REASSEMBLY_METADATA_BYTES);
    memset(slot, 0, sizeof *slot);
    memset(tomb, 0, sizeof *tomb);
    tomb->source = key;
    tomb->context = input->context;
    tomb->state = DMP_REASSEMBLY_TOMBSTONE_RESERVED;
    slot->generation = generation;
    slot->source = key;
    slot->context = input->context;
    normalize_fields(fields, &slot->fields);
    slot->deadline = deadline;
    slot->service_id = input->service_id;
    slot->chunk_size = fields->fragment.chunk_size;
    slot->total_size = fields->fragment.total_size;
    slot->tombstone_slot = (uint32_t)tomb_index;
    slot->metadata_len = (uint16_t)input->immutable_metadata.size;
    slot->live = 1U;
    if (input->immutable_metadata.size != 0U) {
        memcpy(metadata_ptr(engine, slot_index), input->immutable_metadata.data,
               input->immutable_metadata.size);
    }
    /* The establishing slice starts the absolute lifetime; it is not rejected
     * for the deadline it just created. One slice cannot finish a transfer. */
    memcpy(payload_ptr(engine, slot_index) + offset, input->plaintext.data, input->plaintext.size);
    slot->received_bitmap = fragment_bit(fields->fragment.index);
    if ((slot->received_bitmap & fragment_mask(count)) == fragment_mask(count)) {
        slot->complete = 1U;
        note_collection(slot, &engine->profile, slot->service_id, now, 1);
        completed->slot = (uint32_t)slot_index;
        completed->generation = generation;
        return DMP_OK;
    }
    note_collection(slot, &engine->profile, slot->service_id, now, 0);
    return DMP_INCOMPLETE;
}

dmp_status dmp_reassembly_init(dmp_reassembly *engine, const dmp_reassembly_storage *storage,
                               const dmp_admitted_profile *profile, dmp_identity_table *identity)
{
    dmp_status status;

    if (engine == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (engine->initialized != 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    if (storage == NULL || profile == NULL || identity == NULL || storage->profile != profile ||
        storage->identity != identity ||
        (identity->capacity != 0U && identity->slots == NULL)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (profile->fragments < 2U || profile->fragments > 32U || profile->message_bytes == 0U ||
        profile->chunk_bytes == 0U || profile->encoded_mtu == 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    if (storage->assembly_capacity < profile->assembly_slots ||
        storage->tombstone_capacity < profile->assembly_tombstone_slots) {
        return DMP_INVALID_ARGUMENT;
    }
    status = check_minimum_capacity(profile->assembly_slots, profile->message_bytes,
                                    storage->payload_capacity);
    if (status != DMP_OK) {
        return status;
    }
    status = check_minimum_capacity(profile->assembly_slots,
                                    (uint32_t)DMP_REASSEMBLY_METADATA_BYTES,
                                    storage->metadata_capacity);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(profile->assembly_slots, storage->assemblies);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(profile->assembly_tombstone_slots, storage->tombstones);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array((size_t)profile->assembly_slots * (size_t)profile->message_bytes,
                           storage->payloads);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array((size_t)profile->assembly_slots * (size_t)DMP_REASSEMBLY_METADATA_BYTES,
                           storage->metadata);
    if (status != DMP_OK) {
        return status;
    }

    memset(engine, 0, sizeof *engine);
    engine->storage = *storage;
    engine->profile = *profile;
    engine->storage.profile = &engine->profile;
    engine->storage.identity = identity;
    /* Extra caller storage is retained on the byte spans but must not raise quotas. */
    engine->storage.assembly_capacity = profile->assembly_slots;
    engine->storage.tombstone_capacity = profile->assembly_tombstone_slots;
    engine->generation = 1U;
    if (profile->assembly_slots != 0U) {
        memset(engine->storage.assemblies, 0,
               (size_t)profile->assembly_slots * sizeof *engine->storage.assemblies);
    }
    if (profile->assembly_tombstone_slots != 0U) {
        memset(engine->storage.tombstones, 0,
               (size_t)profile->assembly_tombstone_slots * sizeof *engine->storage.tombstones);
    }
    engine->initialized = 1U;
    return DMP_OK;
}

dmp_status dmp_reassembly_on_fragment(dmp_reassembly *engine, const dmp_reassembly_input *input,
                                      dmp_time_ms now, dmp_reassembly_handle *completed)
{
    dmp_message_key key;
    size_t slot_index = 0U;
    dmp_status status;

    if (!ready(engine) || input == NULL || input->frame == NULL || completed == NULL ||
        !bytes_ok(input->plaintext) || !bytes_ok(input->immutable_metadata)) {
        return DMP_INVALID_ARGUMENT;
    }
    if ((input->frame->fields.options & DMP_OPT_FRAG) == 0U) {
        return DMP_MALFORMED;
    }
    if (input->frame->frame.size != 0U && input->frame->frame.data == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (input->plaintext.size > engine->profile.encoded_mtu ||
        input->frame->frame.size > engine->profile.encoded_mtu) {
        return DMP_LIMIT_EXHAUSTED;
    }
    status = dmp_identity_source_key(input->frame, engine->storage.identity, input->context, now,
                                     &key);
    if (status != DMP_OK) {
        return status;
    }
    status = check_service(engine, input);
    if (status != DMP_OK) {
        return status;
    }
    if (find_assembly(engine, key, input->context, &slot_index)) {
        return accept_existing(engine, slot_index, input, now, completed);
    }
    return accept_new(engine, key, input, now, completed);
}

static dmp_status expire_assembly(dmp_reassembly *engine, size_t slot_index)
{
    dmp_reassembly_slot *slot = &engine->storage.assemblies[slot_index];
    uint32_t tomb_index = slot->tombstone_slot;
    dmp_identity_handle context = slot->context;
    dmp_status status;

    if ((size_t)tomb_index >= engine->storage.tombstone_capacity) {
        return DMP_INVALID_ARGUMENT;
    }
    status = dmp_identity_context_release(engine->storage.identity, context);
    if (status != DMP_OK) {
        return status;
    }
    engine->storage.tombstones[tomb_index].state = DMP_REASSEMBLY_TOMBSTONE_EXPIRED;
    memset(payload_ptr(engine, slot_index), 0, engine->profile.message_bytes);
    memset(metadata_ptr(engine, slot_index), 0, (size_t)DMP_REASSEMBLY_METADATA_BYTES);
    clear_assembly(slot);
    return DMP_OK;
}

dmp_status dmp_reassembly_poll(dmp_reassembly *engine, dmp_time_ms now, size_t *expired_count)
{
    size_t i;
    size_t expired = 0U;

    if (!ready(engine) || expired_count == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    for (i = 0U; i < engine->storage.assembly_capacity; i++) {
        dmp_reassembly_slot *slot = &engine->storage.assemblies[i];
        uint32_t missing;

        if (slot->live == 0U || slot->complete != 0U || slot->collection_armed == 0U ||
            dmp_deadline_reached(now, slot->deadline) ||
            !dmp_deadline_reached(now, slot->collection_due)) {
            continue;
        }
        slot->collection_armed = 0U;
        missing = missing_mask(slot);
        if (missing == 0U || slot->status_count >= engine->profile.max_status) {
            continue;
        }
        slot->status_count++;
        slot->status_mask = missing;
        slot->status_expected = 1U;
    }
    for (i = 0U; i < engine->storage.assembly_capacity; i++) {
        dmp_reassembly_slot *slot = &engine->storage.assemblies[i];
        dmp_status status;

        if (slot->live == 0U || slot->complete != 0U ||
            !dmp_deadline_reached(now, slot->deadline)) {
            continue;
        }
        status = expire_assembly(engine, i);
        if (status != DMP_OK) {
            return status;
        }
        expired++;
    }
    *expired_count = expired;
    return DMP_OK;
}

static const dmp_reassembly_slot *complete_slot(const dmp_reassembly *engine,
                                                dmp_reassembly_handle handle)
{
    const dmp_reassembly_slot *slot;

    if (!ready(engine) || handle.generation == 0U ||
        (size_t)handle.slot >= engine->storage.assembly_capacity) {
        return NULL;
    }
    slot = &engine->storage.assemblies[handle.slot];
    if (slot->live == 0U || slot->complete == 0U || slot->generation != handle.generation) {
        return NULL;
    }
    return slot;
}

dmp_status dmp_reassembly_get(const dmp_reassembly *engine, dmp_reassembly_handle handle,
                              dmp_reassembly_message *out)
{
    const dmp_reassembly_slot *slot = complete_slot(engine, handle);
    dmp_reassembly_message message;

    if (!ready(engine) || out == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (slot == NULL) {
        return DMP_STALE_HANDLE;
    }
    memset(&message, 0, sizeof message);
    message.source = slot->source;
    message.context = slot->context;
    message.service_id = slot->service_id;
    message.fields = slot->fields;
    message.payload.data = payload_ptr_const(engine, handle.slot);
    message.payload.size = slot->total_size;
    message.immutable_metadata.data = metadata_ptr_const(engine, handle.slot);
    message.immutable_metadata.size = slot->metadata_len;
    *out = message;
    return DMP_OK;
}

dmp_status dmp_reassembly_release(dmp_reassembly *engine, dmp_reassembly_handle handle)
{
    dmp_reassembly_slot *slot;
    uint32_t tomb_index;
    dmp_status status;

    if (!ready(engine)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (complete_slot(engine, handle) == NULL) {
        return DMP_STALE_HANDLE;
    }
    slot = &engine->storage.assemblies[handle.slot];
    tomb_index = slot->tombstone_slot;
    if ((size_t)tomb_index >= engine->storage.tombstone_capacity) {
        return DMP_INVALID_ARGUMENT;
    }
    status = dmp_identity_context_release(engine->storage.identity, slot->context);
    if (status != DMP_OK) {
        return status;
    }
    memset(&engine->storage.tombstones[tomb_index], 0, sizeof engine->storage.tombstones[tomb_index]);
    memset(payload_ptr(engine, handle.slot), 0, engine->profile.message_bytes);
    memset(metadata_ptr(engine, handle.slot), 0, (size_t)DMP_REASSEMBLY_METADATA_BYTES);
    clear_assembly(slot);
    return DMP_OK;
}

dmp_status dmp_reassembly_context_retired(dmp_reassembly *engine, dmp_identity_handle context)
{
    dmp_identity_table *table;
    dmp_identity_slot *id;
    size_t i;

    if (!ready(engine)) {
        return DMP_INVALID_ARGUMENT;
    }
    table = engine->storage.identity;
    if (table == NULL || (table->capacity != 0U && table->slots == NULL)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (context.generation == 0U || (size_t)context.slot >= table->capacity) {
        return DMP_STALE_HANDLE;
    }
    id = &table->slots[context.slot];
    if (id->generation != context.generation) {
        return DMP_STALE_HANDLE;
    }
    if (id->state != DMP_IDENTITY_SLOT_UNUSED) {
        return DMP_CONTEXT_REQUIRED;
    }
    for (i = 0U; i < engine->storage.tombstone_capacity; i++) {
        dmp_reassembly_tombstone *tomb = &engine->storage.tombstones[i];
        if (tomb->state == DMP_REASSEMBLY_TOMBSTONE_EXPIRED &&
            context_eq(tomb->context, context)) {
            memset(tomb, 0, sizeof *tomb);
        }
    }
    return DMP_OK;
}
