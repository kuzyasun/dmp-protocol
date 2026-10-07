#include "dmp/reliability.h"

#include <stdint.h>
#include <string.h>

/* Direct REQ/RSP/ERR/ACK, plus fragmented recovery when the saved payload does
 * not fit one frame. Each attempt calls the injected encoder. A fragment retry
 * keeps the saved plaintext and logical identity and is encoded again, so a
 * protected path allocates a new PN. Ciphertext is not cached. SELECTIVE-32
 * repairs only the admitted missing mask. retry-all resends every slice.
 * A large RSP and a large terminal ERR (status >= 64) are slices of the one
 * saved result, under the same rules as a fragmented REQ. Deadlines stay
 * absolute. This file does not authenticate, decrypt, or forward ROUTE frames. */

enum {
    KIND_REQ = 0,
    KIND_RESULT = 1,
    KIND_REJECT = 2,
    KIND_DATA = 3
};

static int ready(const dmp_reliability *engine)
{
    return engine != NULL && engine->initialized;
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

static int service_allowed(const dmp_admitted_profile *profile, uint32_t service)
{
    return service == 0U || service == profile->service_id[0] || service == profile->service_id[1];
}

static int service_requires_freshness(const dmp_admitted_profile *profile, uint32_t service)
{
    if (service == profile->service_id[0]) {
        return (profile->freshness_required_mask & 1U) != 0U;
    }
    if (service == profile->service_id[1]) {
        return (profile->freshness_required_mask & 2U) != 0U;
    }
    return 0;
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

static int lowest_fragment(uint32_t mask, uint32_t *index)
{
    uint32_t i;

    for (i = 0U; i < 32U; i++) {
        if ((mask & fragment_bit(i)) != 0U) {
            *index = i;
            return 1;
        }
    }
    return 0;
}

static int plan_fragments(const dmp_admitted_profile *profile, size_t payload, uint32_t *count_out)
{
    uint32_t count;

    if (payload <= (size_t)profile->chunk_bytes || profile->chunk_bytes == 0U) {
        return 0;
    }
    count = 1U + ((uint32_t)payload - 1U) / profile->chunk_bytes;
    if (count < 2U || count > 32U || count > profile->fragments) {
        return 0;
    }
    *count_out = count;
    return 1;
}

/* *fits is 1 or 0 only when the return is DMP_OK. A NULL output buffer whose
 * capacity is encoded_mtu asks whether this exact logical frame fits, including
 * its fragment geometry when present. The encoder must return DMP_OK or
 * DMP_LIMIT_EXHAUSTED and must not seal or allocate a PN. Any other status is a
 * local failure. */
static dmp_status probe_unfragmented(dmp_reliability *engine,
                                     const dmp_reliability_sender_slot *sender, int *fits);
static dmp_status probe_saved_fragment(dmp_reliability *engine,
                                      const dmp_reliability_sender_slot *sender, int *fits);

/* Empty and single-packet messages omit FRAG. For a multi-frame message, probe
 * its first full-size slice before admitting the fixed chunk geometry. */
static dmp_status arm_saved_fragments(dmp_reliability *engine, dmp_reliability_sender_slot *sender,
                                      size_t payload)
{
    uint32_t frag_count = 0U;
    int fits = 0;
    dmp_status status;

    status = probe_unfragmented(engine, sender, &fits);
    if (status != DMP_OK) {
        return status;
    }
    sender->frag_count = 0U;
    sender->chunk_size = 0U;
    sender->total_size = 0U;
    sender->active_mask = 0U;
    if (!fits) {
        if (!plan_fragments(&engine->profile, payload, &frag_count)) {
            return DMP_LIMIT_EXHAUSTED;
        }
        sender->frag_count = frag_count;
        sender->chunk_size = engine->profile.chunk_bytes;
        sender->total_size = (uint32_t)payload;
        sender->active_mask = fragment_mask(frag_count);
        status = probe_saved_fragment(engine, sender, &fits);
        if (status != DMP_OK) {
            return status;
        }
        if (!fits) {
            return DMP_LIMIT_EXHAUSTED;
        }
    }
    return DMP_OK;
}

static uint32_t control_reserve(const dmp_admitted_profile *profile)
{
    if (profile->control_slots < profile->adapter_slots) {
        return profile->control_slots;
    }
    return profile->adapter_slots;
}

static const dmp_identity_slot *bound(const dmp_reliability *engine)
{
    const dmp_identity_table *table = engine->storage.identity;
    dmp_identity_handle handle = engine->storage.context;
    const dmp_identity_slot *slot;

    if (table == NULL || table->slots == NULL || handle.slot >= table->capacity) {
        return NULL;
    }
    slot = &table->slots[handle.slot];
    if (slot->state == DMP_IDENTITY_SLOT_UNUSED || slot->generation != handle.generation) {
        return NULL;
    }
    return slot;
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

static uint8_t *sender_bytes(dmp_reliability *engine, size_t index)
{
    return engine->storage.sender_payload + index * (size_t)engine->profile.message_bytes;
}

static uint8_t *result_bytes(dmp_reliability *engine, size_t index)
{
    return engine->storage.result_payload + index * (size_t)engine->profile.message_bytes;
}

static uint8_t *history_meta(dmp_reliability *engine, size_t index)
{
    return engine->storage.history_metadata + index * (size_t)DMP_RELIABILITY_METADATA_BYTES;
}

static uint8_t *correlation_meta(dmp_reliability *engine, size_t index)
{
    return engine->storage.correlation_metadata +
           index * (size_t)DMP_RELIABILITY_METADATA_BYTES;
}

static uint8_t *frame_bytes(dmp_reliability *engine, size_t index)
{
    return engine->storage.frames + index * (size_t)engine->profile.encoded_mtu;
}

static void release_sender(dmp_reliability_sender_slot *slot)
{
    uint64_t generation = slot->generation;
    memset(slot, 0, sizeof *slot);
    slot->generation = generation;
}

static void release_result(dmp_reliability_result_slot *slot)
{
    uint64_t generation = slot->generation;
    memset(slot, 0, sizeof *slot);
    slot->generation = generation;
}

static void release_history(dmp_reliability_history_slot *slot)
{
    uint64_t generation = slot->generation;
    memset(slot, 0, sizeof *slot);
    slot->generation = generation;
}

static void release_correlation(dmp_reliability_correlation_slot *slot)
{
    uint64_t generation = slot->generation;
    memset(slot, 0, sizeof *slot);
    slot->generation = generation;
}

static void release_adapter(dmp_reliability_adapter_slot *slot)
{
    uint64_t generation = slot->generation;
    memset(slot, 0, sizeof *slot);
    slot->generation = generation;
}

static int find_unused_sender(const dmp_reliability *engine)
{
    size_t i;
    for (i = 0U; i < engine->storage.sender_capacity; i++) {
        if (engine->storage.senders[i].live == 0U && !engine->storage.senders[i].tx_live) {
            return (int)i;
        }
    }
    return -1;
}

static int find_unused_result(const dmp_reliability *engine)
{
    size_t i;
    for (i = 0U; i < engine->storage.result_capacity; i++) {
        if (engine->storage.results[i].live == 0U) {
            return (int)i;
        }
    }
    return -1;
}

static int find_unused_history(const dmp_reliability *engine)
{
    size_t i;
    for (i = 0U; i < engine->storage.history_capacity; i++) {
        if (engine->storage.history[i].live == 0U) {
            return (int)i;
        }
    }
    return -1;
}

static int find_unused_correlation(const dmp_reliability *engine)
{
    size_t i;
    for (i = 0U; i < engine->storage.correlation_capacity; i++) {
        if (engine->storage.correlations[i].live == 0U) {
            return (int)i;
        }
    }
    return -1;
}

static int find_adapter(const dmp_reliability *engine, int control_only, int allow_control)
{
    size_t reserve = control_reserve(&engine->profile);
    size_t i;
    if (!control_only) {
        for (i = reserve; i < engine->storage.adapter_capacity; i++) {
            if (engine->storage.adapters[i].live == 0U) {
                return (int)i;
            }
        }
        if (!allow_control) {
            return -1;
        }
    }
    for (i = 0U; i < reserve; i++) {
        if (engine->storage.adapters[i].live == 0U) {
            return (int)i;
        }
    }
    return -1;
}

static size_t queued_application(const dmp_reliability *engine)
{
    size_t i;
    size_t count = 0U;
    for (i = 0U; i < engine->storage.sender_capacity; i++) {
        const dmp_reliability_sender_slot *sender = &engine->storage.senders[i];
        if (sender->live != 0U && sender->phase == DMP_REL_PHASE_QUEUED &&
            (sender->kind == KIND_REQ || sender->kind == KIND_RESULT || sender->kind == KIND_DATA)) {
            count++;
        }
    }
    return count;
}

static int gate_held(const dmp_reliability *engine, uint32_t service, size_t self)
{
    size_t i;
    for (i = 0U; i < engine->storage.sender_capacity; i++) {
        const dmp_reliability_sender_slot *sender = &engine->storage.senders[i];
        if (i == self || sender->live == 0U || sender->service_id != service) {
            continue;
        }
        if (sender->kind != KIND_REQ && sender->kind != KIND_RESULT && sender->kind != KIND_DATA) {
            continue;
        }
        if (sender->phase == DMP_REL_PHASE_TRANSMITTING ||
            sender->phase == DMP_REL_PHASE_AWAIT_RECEIPT) {
            return 1;
        }
    }
    return 0;
}

static size_t operations_used(const dmp_reliability *engine, uint32_t service)
{
    size_t i;
    size_t count = 0U;
    for (i = 0U; i < engine->storage.sender_capacity; i++) {
        const dmp_reliability_sender_slot *sender = &engine->storage.senders[i];
        if (sender->live != 0U &&
            (sender->kind == KIND_REQ || sender->kind == KIND_DATA) &&
            sender->service_id == service) {
            count++;
        }
    }
    for (i = 0U; i < engine->storage.history_capacity; i++) {
        const dmp_reliability_history_slot *history = &engine->storage.history[i];
        const dmp_reliability_result_slot *result;
        if (history->live == 0U || history->decision != 0U || history->service_id != service) {
            continue;
        }
        if (history->result_slot >= engine->storage.result_capacity) {
            continue;
        }
        result = &engine->storage.results[history->result_slot];
        if (result->live != 0U && result->generation == history->result_generation &&
            result->deadline == 0U) {
            count++;
        }
    }
    return count;
}

static void emit(dmp_reliability *engine, dmp_reliability_event event,
                 dmp_reliability_handle handle, dmp_message_key key, uint32_t service,
                 uint32_t wire_status, dmp_bytes payload)
{
    dmp_reliability_notice notice;
    notice.event = event;
    notice.handle = handle;
    notice.key = key;
    notice.service_id = service;
    notice.wire_status = wire_status;
    notice.payload = payload;
    engine->storage.notice(engine->storage.notice_user, &notice);
}

static dmp_bytes stage_bytes(dmp_reliability *engine, const uint8_t *data, size_t size)
{
    dmp_bytes out;
    out.data = NULL;
    out.size = 0U;
    if (size == 0U) {
        return out;
    }
    memmove(engine->storage.receive_payload, data, size);
    out.data = engine->storage.receive_payload;
    out.size = size;
    return out;
}

static dmp_reliability_handle sender_handle(const dmp_reliability *engine,
                                            const dmp_reliability_sender_slot *sender)
{
    dmp_reliability_handle handle;
    handle.slot = (uint32_t)(sender - engine->storage.senders);
    handle.generation = sender->generation;
    return handle;
}

static dmp_reliability_correlation_slot *correlation_of(dmp_reliability *engine,
                                                        const dmp_reliability_sender_slot *sender)
{
    dmp_reliability_correlation_slot *correlation;
    if (sender->related_slot >= engine->storage.correlation_capacity) {
        return NULL;
    }
    correlation = &engine->storage.correlations[sender->related_slot];
    if (correlation->live == 0U || correlation->generation != sender->related_generation) {
        return NULL;
    }
    return correlation;
}

static dmp_reliability_result_slot *result_of_sender(dmp_reliability *engine,
                                                     const dmp_reliability_sender_slot *sender)
{
    dmp_reliability_result_slot *result;
    if (sender->kind != KIND_RESULT || sender->related_slot >= engine->storage.result_capacity) {
        return NULL;
    }
    result = &engine->storage.results[sender->related_slot];
    if (result->live == 0U || result->generation != sender->related_generation) {
        return NULL;
    }
    return result;
}

static dmp_status sender_logical(dmp_reliability *engine,
                                 const dmp_reliability_sender_slot *sender,
                                 dmp_reliability_logical *logical)
{
    dmp_reliability_result_slot *result;
    size_t index;

    if (engine == NULL || sender == NULL || logical == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    memset(logical, 0, sizeof *logical);
    logical->service_id = sender->service_id;
    logical->own = sender->own;
    index = (size_t)(sender - engine->storage.senders);
    if (sender->kind == KIND_REQ || sender->kind == KIND_DATA) {
        logical->type = sender->kind == KIND_REQ ? DMP_TYPE_REQ : (dmp_type)sender->message_type;
        logical->ack_req = true;
        logical->payload.size = sender->payload_len;
        logical->payload.data = sender->payload_len == 0U ? NULL : sender_bytes(engine, index);
        if (sender->freshness_live != 0U) {
            logical->freshness_token.data = (uint8_t *)sender->freshness_token;
            logical->freshness_token.size = sizeof sender->freshness_token;
        }
    } else if (sender->kind == KIND_RESULT) {
        result = result_of_sender(engine, sender);
        if (result == NULL) {
            return DMP_INVALID_ARGUMENT;
        }
        logical->type = result->application_err != 0U ? DMP_TYPE_ERR : DMP_TYPE_RSP;
        logical->own = result->reserved != 0U ? result->result : sender->own;
        logical->reply_to = result->request;
        logical->has_reply_to = true;
        logical->ack_req = true;
        logical->wire_status = result->wire_status;
        logical->payload.size = result->payload_len;
        logical->payload.data = result->payload_len == 0U ? NULL
                                                          : result_bytes(engine, sender->related_slot);
    } else {
        return DMP_INVALID_ARGUMENT;
    }
    return DMP_OK;
}

static dmp_status probe_sender_frame(dmp_reliability *engine,
                                     const dmp_reliability_sender_slot *sender,
                                     int fragmented, int *fits)
{
    dmp_reliability_logical logical;
    dmp_buffer probe;
    size_t written = 0U;
    dmp_status status;

    if (fits == NULL || sender == NULL || engine->storage.encode == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    *fits = 0;
    status = sender_logical(engine, sender, &logical);
    if (status != DMP_OK) {
        return status;
    }
    if (fragmented != 0) {
        if (engine->profile.chunk_bytes == 0U ||
            logical.payload.size <= (size_t)engine->profile.chunk_bytes) {
            return DMP_INVALID_ARGUMENT;
        }
        logical.fragment_index = 0U;
        logical.chunk_size = engine->profile.chunk_bytes;
        logical.total_size = (uint32_t)logical.payload.size;
        logical.payload.size = engine->profile.chunk_bytes;
    }
    probe.data = NULL;
    probe.capacity = engine->profile.encoded_mtu;
    status = engine->storage.encode(engine->storage.encode_context, &logical, probe, &written);
    if (status == DMP_OK) {
        *fits = 1;
        return DMP_OK;
    }
    if (status == DMP_LIMIT_EXHAUSTED) {
        *fits = 0;
        return DMP_OK;
    }
    return status;
}

static dmp_status probe_unfragmented(dmp_reliability *engine,
                                     const dmp_reliability_sender_slot *sender, int *fits)
{
    return probe_sender_frame(engine, sender, 0, fits);
}

static dmp_status probe_saved_fragment(dmp_reliability *engine,
                                      const dmp_reliability_sender_slot *sender, int *fits)
{
    return probe_sender_frame(engine, sender, 1, fits);
}

static dmp_reliability_history_slot *history_of_sender(dmp_reliability *engine,
                                                       const dmp_reliability_sender_slot *sender)
{
    dmp_reliability_history_slot *history;
    if (sender->related_slot >= engine->storage.history_capacity) {
        return NULL;
    }
    history = &engine->storage.history[sender->related_slot];
    if (history->live == 0U || history->generation != sender->related_generation) {
        return NULL;
    }
    return history;
}

static dmp_reliability_sender_slot *sender_of_result(dmp_reliability *engine,
                                                     const dmp_reliability_result_slot *result)
{
    dmp_reliability_sender_slot *sender;
    if (result->sender_slot >= engine->storage.sender_capacity) {
        return NULL;
    }
    sender = &engine->storage.senders[result->sender_slot];
    if (sender->live == 0U || sender->generation != result->sender_generation) {
        return NULL;
    }
    return sender;
}

static dmp_reliability_history_slot *history_of_result(
    dmp_reliability *engine, const dmp_reliability_result_slot *result)
{
    dmp_reliability_history_slot *history;
    if (result->history_slot >= engine->storage.history_capacity) {
        return NULL;
    }
    history = &engine->storage.history[result->history_slot];
    if (history->live == 0U || history->generation != result->history_generation) {
        return NULL;
    }
    return history;
}

static void settle_sender(dmp_reliability *engine, dmp_reliability_sender_slot *sender)
{
    dmp_reliability_correlation_slot *correlation;
    dmp_reliability_handle handle;
    dmp_bytes empty;
    int unknown;

    if (sender->live == 0U || sender->tx_live) {
        return;
    }
    empty.data = NULL;
    empty.size = 0U;
    if (sender->kind == KIND_DATA) {
        if (sender->phase == DMP_REL_PHASE_TERMINAL && !sender->result_seen) {
            emit(engine, sender->possibly_sent != 0U ? DMP_REL_EVENT_DATA_UNKNOWN
                                                     : DMP_REL_EVENT_DATA_LOCAL_UNSENT,
                 sender_handle(engine, sender), sender->own, sender->service_id, 0U, empty);
        }
        release_sender(sender);
        return;
    }
    if (sender->kind != KIND_REQ) {
        release_sender(sender);
        return;
    }
    if (sender->phase == DMP_REL_PHASE_TERMINAL && !sender->result_seen) {
        correlation = correlation_of(engine, sender);
        unknown = sender->possibly_sent != 0U;
        if (correlation != NULL && unknown) {
            correlation->terminal_unknown = 1U;
        }
        handle = sender_handle(engine, sender);
        emit(engine, unknown ? DMP_REL_EVENT_UNKNOWN : DMP_REL_EVENT_LOCAL_UNSENT, handle,
             sender->own, sender->service_id, 0U, empty);
    }
    if (sender->phase == DMP_REL_PHASE_TERMINAL || sender->result_seen) {
        release_sender(sender);
    }
}

static void on_tx_complete(void *owner, dmp_tx_token token, dmp_tx_outcome outcome,
                           dmp_time_ms when)
{
    dmp_reliability *engine = owner;
    dmp_reliability_adapter_slot *adapter;

    if (engine == NULL || token.slot >= engine->storage.adapter_capacity) {
        return;
    }
    adapter = &engine->storage.adapters[token.slot];
    if (adapter->live == 0U || adapter->generation != token.generation ||
        adapter->completion_ready != 0U) {
        return;
    }
    adapter->outcome = outcome;
    adapter->completed_at = when;
    adapter->completion_ready = 1U;
}

static void apply_tx(dmp_reliability *engine, dmp_reliability_sender_slot *sender,
                     dmp_tx_outcome outcome, dmp_time_ms when)
{
    dmp_reliability_result_slot *result;
    sender->tx_live = false;
    if (outcome == DMP_TX_TRANSMITTED || outcome == DMP_TX_POSSIBLY_TRANSMITTED) {
        sender->possibly_sent = 1U;
    }
    if (sender->phase == DMP_REL_PHASE_TERMINAL || sender->result_seen) {
        settle_sender(engine, sender);
        return;
    }
    if (sender->kind == KIND_REJECT) {
        if (outcome == DMP_TX_FAILED_UNSENT) {
            sender->phase = DMP_REL_PHASE_QUEUED;
            sender->next_attempt = when;
        } else {
            release_sender(sender);
        }
        return;
    }
    if (outcome == DMP_TX_FAILED_UNSENT || outcome == DMP_TX_CANCELLED_UNSENT) {
        sender->phase = DMP_REL_PHASE_QUEUED;
        sender->next_attempt = when;
        return;
    }
    if ((sender->kind == KIND_REQ || sender->kind == KIND_RESULT || sender->kind == KIND_DATA) &&
        sender->frag_count != 0U) {
        if (sender->burst_counted == 0U) {
            sender->packet_count++;
            if (sender->probe_burst != 0U) {
                sender->probe_count++;
            }
            sender->burst_counted = 1U;
        }
        if (sender->sending_index < 32U) {
            sender->active_mask &= ~fragment_bit(sender->sending_index);
        }
        if (sender->active_mask != 0U) {
            sender->phase = DMP_REL_PHASE_QUEUED;
            sender->next_attempt = when;
            return;
        }
        sender->burst_inflight = 0U;
        sender->burst_counted = 0U;
        sender->probe_burst = 0U;
        if (selective_service(&engine->profile, sender->service_id) && sender->repair_mask != 0U) {
            sender->active_mask = sender->repair_mask;
            sender->repair_mask = 0U;
            sender->phase = DMP_REL_PHASE_QUEUED;
            sender->next_attempt = when;
            return;
        }
    }
    if (sender->kind == KIND_RESULT) {
        result = result_of_sender(engine, sender);
        if (result != NULL && result->acknowledged != 0U) {
            release_sender(sender);
            return;
        }
    }
    sender->phase = DMP_REL_PHASE_AWAIT_RECEIPT;
    if (dmp_deadline_after(when, engine->profile.response_timeout_ms,
                           &sender->receipt_deadline) != DMP_OK ||
        dmp_deadline_after(sender->receipt_deadline, sender->jitter_ms,
                           &sender->next_attempt) != DMP_OK) {
        sender->phase = DMP_REL_PHASE_TERMINAL;
        settle_sender(engine, sender);
    }
}

static void consume(dmp_reliability *engine)
{
    size_t i;
    for (i = 0U; i < engine->storage.adapter_capacity; i++) {
        dmp_reliability_adapter_slot *adapter = &engine->storage.adapters[i];
        dmp_reliability_sender_slot *sender;
        dmp_tx_outcome outcome;
        dmp_time_ms when;
        if (adapter->live == 0U || adapter->completion_ready == 0U) {
            continue;
        }
        outcome = adapter->outcome;
        when = adapter->completed_at;
        if (adapter->control != 0U) {
            release_adapter(adapter);
            continue;
        }
        if (adapter->sender_slot >= engine->storage.sender_capacity) {
            release_adapter(adapter);
            continue;
        }
        sender = &engine->storage.senders[adapter->sender_slot];
        if (sender->live == 0U || sender->generation != adapter->sender_generation ||
            !sender->tx_live) {
            release_adapter(adapter);
            continue;
        }
        release_adapter(adapter);
        apply_tx(engine, sender, outcome, when);
    }
}

static void cancel_tx(dmp_reliability *engine, dmp_reliability_sender_slot *sender)
{
    dmp_tx_token token;
    if (!sender->tx_live) {
        return;
    }
    token.slot = sender->tx_slot;
    token.generation = sender->tx_generation;
    (void)engine->transport.cancel(engine->transport.context, token);
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

static dmp_status find_extension(const dmp_frame_view *frame, uint32_t id, dmp_bytes *value,
                                 int *found)
{
    size_t cursor = 0U;
    *found = 0;
    value->data = NULL;
    value->size = 0U;
    if (frame->extensions.size != 0U && frame->extensions.data == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    while (cursor < frame->extensions.size) {
        dmp_extension_view view;
        dmp_status status = dmp_extension_next(frame->extensions, &cursor, &view);
        if (status == DMP_INCOMPLETE) {
            break;
        }
        if (status != DMP_OK) {
            return status;
        }
        if ((view.tag >> 2) == id) {
            *value = view.value;
            *found = 1;
            return DMP_OK;
        }
    }
    return DMP_OK;
}

static dmp_status resolve_service(const dmp_reliability *engine, const dmp_frame_view *frame,
                                  uint32_t claimed, uint32_t *out)
{
    dmp_bytes value;
    int found = 0;
    uint32_t wire = 0U;
    dmp_status status = find_extension(frame, 4U, &value, &found);
    size_t at = 0U;
    if (status != DMP_OK) {
        return status;
    }
    if (found) {
        if (!read_uleb32(value, &at, &wire) || at != value.size || wire != claimed) {
            return DMP_MALFORMED;
        }
    } else if (claimed != engine->profile.default_service || claimed == 0U) {
        return DMP_MALFORMED;
    }
    if (!service_allowed(&engine->profile, claimed)) {
        return DMP_UNSUPPORTED;
    }
    *out = claimed;
    return DMP_OK;
}

static dmp_status read_wire_status(const dmp_frame_view *frame, int *present, uint32_t *status_out)
{
    dmp_bytes value;
    int found = 0;
    size_t at = 0U;
    dmp_status status = find_extension(frame, 5U, &value, &found);
    *present = 0;
    *status_out = 0U;
    if (status != DMP_OK) {
        return status;
    }
    if (!found) {
        return DMP_OK;
    }
    if (!read_uleb32(value, &at, status_out) || at != value.size) {
        return DMP_MALFORMED;
    }
    *present = 1;
    return DMP_OK;
}

static dmp_message_origin frame_destination(const dmp_reliability *engine,
                                            const dmp_frame_view *frame)
{
    const dmp_identity_slot *slot = bound(engine);
    dmp_message_origin destination;
    memset(&destination, 0, sizeof destination);
    if (slot == NULL) {
        return destination;
    }
    destination = slot->local;
    if ((frame->fields.options & DMP_OPT_ROUTE) != 0U && frame->fields.route.mode == 1U) {
        destination.origin_id = frame->fields.route.destination;
    }
    return destination;
}

static int metadata_match(const dmp_reliability *engine, const dmp_reliability_history_slot *history,
                          const dmp_frame_view *frame, uint32_t service, dmp_bytes metadata,
                          dmp_message_origin destination)
{
    const uint8_t *stored;
    uint8_t ack = (frame->fields.options & DMP_OPT_ACK_REQ) != 0U ? 1U : 0U;
    if (history->type != frame->fields.type || history->ack_req != ack ||
        history->service_id != service || !origin_eq(history->destination, destination)) {
        return 0;
    }
    if ((frame->fields.options & DMP_OPT_PAYLOAD_DESC) != 0U) {
        if (history->descriptor_flags != frame->fields.descriptor.flags ||
            history->descriptor_codec != frame->fields.descriptor.codec ||
            history->descriptor_schema != frame->fields.descriptor.schema ||
            history->descriptor_version != frame->fields.descriptor.schema_version) {
            return 0;
        }
    } else if (history->descriptor_flags != 0U || history->descriptor_codec != 0U ||
               history->descriptor_schema != 0U || history->descriptor_version != 0U) {
        return 0;
    }
    if ((size_t)history->metadata_len != metadata.size) {
        return 0;
    }
    if (history->metadata_len == 0U) {
        return 1;
    }
    stored = engine->storage.history_metadata +
             (size_t)(history - engine->storage.history) * (size_t)DMP_RELIABILITY_METADATA_BYTES;
    return memcmp(stored, metadata.data, metadata.size) == 0;
}

static void remember_descriptor(dmp_reliability_history_slot *history, const dmp_frame_view *frame)
{
    if ((frame->fields.options & DMP_OPT_PAYLOAD_DESC) != 0U) {
        history->descriptor_flags = frame->fields.descriptor.flags;
        history->descriptor_codec = frame->fields.descriptor.codec;
        history->descriptor_schema = frame->fields.descriptor.schema;
        history->descriptor_version = frame->fields.descriptor.schema_version;
    }
}

static int find_history_key(const dmp_reliability *engine, dmp_message_key key)
{
    size_t i;
    for (i = 0U; i < engine->storage.history_capacity; i++) {
        const dmp_reliability_history_slot *history = &engine->storage.history[i];
        if (history->live != 0U && key_eq(history->source, key)) {
            return (int)i;
        }
    }
    return -1;
}

static int find_result_key(const dmp_reliability *engine, dmp_message_key key)
{
    size_t i;
    for (i = 0U; i < engine->storage.result_capacity; i++) {
        const dmp_reliability_result_slot *result = &engine->storage.results[i];
        if (result->live != 0U && key_eq(result->request, key)) {
            return (int)i;
        }
    }
    return -1;
}

static int result_cached(const dmp_reliability_result_slot *result, dmp_time_ms now)
{
    return result != NULL && result->live != 0U && result->deadline != 0U &&
           !dmp_deadline_reached(now, result->deadline);
}

static int reject_pending(const dmp_reliability *engine, uint32_t history_slot,
                          uint64_t generation)
{
    size_t i;
    for (i = 0U; i < engine->storage.sender_capacity; i++) {
        const dmp_reliability_sender_slot *sender = &engine->storage.senders[i];
        if (sender->live != 0U && sender->kind == KIND_REJECT &&
            sender->related_slot == history_slot && sender->related_generation == generation) {
            return 1;
        }
    }
    return 0;
}

static dmp_status arm_adapter(dmp_reliability *engine, int index, int control,
                              uint32_t sender_slot, uint64_t sender_generation,
                              dmp_reliability_adapter_slot **out)
{
    dmp_reliability_adapter_slot *adapter = &engine->storage.adapters[index];
    uint64_t generation;
    dmp_status status = dmp_generation_next(adapter->generation, &generation);
    if (status != DMP_OK) {
        return status;
    }
    memset(adapter, 0, sizeof *adapter);
    adapter->generation = generation;
    adapter->live = 1U;
    adapter->control = control ? 1U : 0U;
    adapter->token.slot = (uint32_t)index;
    adapter->token.generation = generation;
    adapter->sender_slot = sender_slot;
    adapter->sender_generation = sender_generation;
    adapter->result_slot = UINT32_MAX;
    *out = adapter;
    return DMP_OK;
}

static dmp_status submit_frame(dmp_reliability *engine, dmp_reliability_adapter_slot *adapter,
                               size_t written, dmp_time_ms not_after)
{
    dmp_tx_submission submission;
    dmp_status status;
    submission.token = adapter->token;
    submission.frame.data = frame_bytes(engine, adapter->token.slot);
    submission.frame.size = written;
    submission.not_after = not_after;
    submission.complete = on_tx_complete;
    submission.owner = engine;
    adapter->frame_len = written;
    status = engine->transport.submit(engine->transport.context, &submission);
    if (status != DMP_OK) {
        release_adapter(adapter);
        return status;
    }
    consume(engine);
    return DMP_OK;
}

static dmp_status send_ack(dmp_reliability *engine, uint32_t service, dmp_message_key reply_to,
                           dmp_message_origin destination, dmp_time_ms now)
{
    const dmp_identity_slot *slot = bound(engine);
    dmp_reliability_logical logical;
    dmp_reliability_adapter_slot *adapter = NULL;
    dmp_buffer out;
    dmp_time_ms not_after;
    uint32_t seq = 0U;
    size_t written = 0U;
    int index;
    dmp_status status;
    if (slot == NULL) {
        return DMP_STALE_HANDLE;
    }
    if (dmp_deadline_after(now, 1U, &not_after) != DMP_OK) {
        return DMP_LIMIT_EXHAUSTED;
    }
    index = find_adapter(engine, 1, 0);
    if (index < 0) {
        return DMP_BUSY;
    }
    status = dmp_identity_next_seq(engine->storage.identity, engine->storage.context, &seq);
    if (status != DMP_OK) {
        return status;
    }
    status = arm_adapter(engine, index, 1, UINT32_MAX, 0U, &adapter);
    if (status != DMP_OK) {
        return status;
    }
    memset(&logical, 0, sizeof logical);
    logical.type = DMP_TYPE_ACK;
    logical.service_id = service;
    logical.destination = destination;
    logical.own.origin = slot->local;
    logical.own.seq = seq;
    logical.reply_to = reply_to;
    logical.has_reply_to = true;
    logical.ack_req = false;
    out.data = frame_bytes(engine, (size_t)index);
    out.capacity = engine->profile.encoded_mtu;
    status = engine->storage.encode(engine->storage.encode_context, &logical, out, &written);
    if (status != DMP_OK || written == 0U || written > out.capacity) {
        release_adapter(adapter);
        return status == DMP_OK ? DMP_MALFORMED : status;
    }
    return submit_frame(engine, adapter, written, not_after);
}

static dmp_bytes slice_at(const uint8_t *base, uint32_t index, uint32_t chunk, uint32_t total)
{
    dmp_bytes slice;
    uint64_t offset = (uint64_t)index * (uint64_t)chunk;
    uint32_t expect;

    slice.data = NULL;
    slice.size = 0U;
    if (base == NULL || chunk == 0U || offset >= total) {
        return slice;
    }
    expect = total - (uint32_t)offset;
    if (expect > chunk) {
        expect = chunk;
    }
    slice.data = base + (size_t)offset;
    slice.size = expect;
    return slice;
}

static dmp_bytes slice_view(dmp_reliability *engine, size_t sender_index, uint32_t index,
                            uint32_t chunk, uint32_t total)
{
    return slice_at(sender_bytes(engine, sender_index), index, chunk, total);
}

static dmp_status begin_send(dmp_reliability *engine, size_t index, dmp_time_ms now)
{
    dmp_reliability_sender_slot *sender = &engine->storage.senders[index];
    const dmp_identity_slot *slot = bound(engine);
    dmp_reliability_logical logical;
    dmp_reliability_adapter_slot *adapter = NULL;
    dmp_buffer out;
    size_t written = 0U;
    int adapter_index;
    int allow_control = sender->kind == KIND_REJECT;
    dmp_status status;
    if (slot == NULL) {
        return DMP_STALE_HANDLE;
    }
    if (dmp_deadline_reached(now, sender->send_deadline) ||
        !dmp_deadline_reached(now, sender->next_attempt)) {
        return DMP_DEADLINE_EXPIRED;
    }
    memset(&logical, 0, sizeof logical);
    logical.service_id = sender->service_id;
    logical.own = sender->own;
    if (sender->kind == KIND_REQ || sender->kind == KIND_DATA) {
        logical.type = sender->kind == KIND_REQ ? DMP_TYPE_REQ : (dmp_type)sender->message_type;
        logical.destination = slot->peer;
        logical.ack_req = true;
        logical.payload.data = sender->payload_len == 0U ? NULL : sender_bytes(engine, index);
        logical.payload.size = sender->payload_len;
        if (sender->freshness_live != 0U) {
            logical.freshness_token.data = sender->freshness_token;
            logical.freshness_token.size = sizeof sender->freshness_token;
        }
    } else if (sender->kind == KIND_RESULT) {
        dmp_reliability_result_slot *result = result_of_sender(engine, sender);
        if (result == NULL) {
            return DMP_STALE_HANDLE;
        }
        if (result->reserved == 0U) {
            uint32_t seq = 0U;
            status = dmp_identity_next_seq(engine->storage.identity, engine->storage.context,
                                           &seq);
            if (status != DMP_OK) {
                return status;
            }
            result->result.origin = slot->local;
            result->result.seq = seq;
            result->reserved = 1U;
            sender->own = result->result;
        }
        logical.own = sender->own;
        logical.type = result->application_err != 0U ? DMP_TYPE_ERR : DMP_TYPE_RSP;
        logical.destination = result->destination;
        logical.reply_to = result->request;
        logical.has_reply_to = true;
        logical.ack_req = true;
        logical.wire_status = result->wire_status;
        logical.payload.data = result->payload_len == 0U ? NULL : result_bytes(engine, sender->related_slot);
        logical.payload.size = result->payload_len;
    } else {
        dmp_reliability_history_slot *history = history_of_sender(engine, sender);
        if (history == NULL) {
            release_sender(sender);
            return DMP_OK;
        }
        logical.type = DMP_TYPE_ERR;
        logical.destination = history->source.origin;
        logical.reply_to = history->source;
        logical.has_reply_to = true;
        logical.ack_req = false;
        logical.wire_status = history->wire_status;
    }
    if ((sender->kind == KIND_REQ || sender->kind == KIND_RESULT || sender->kind == KIND_DATA) &&
        sender->frag_count != 0U) {
        uint32_t frag_index = 0U;
        int starting = sender->burst_inflight == 0U;

        if (sender->active_mask == 0U || !lowest_fragment(sender->active_mask, &frag_index)) {
            sender->phase = DMP_REL_PHASE_TERMINAL;
            settle_sender(engine, sender);
            return DMP_OK;
        }
        if (starting &&
            ((engine->profile.max_bursts != 0U &&
              sender->packet_count >= engine->profile.max_bursts) ||
             (sender->probe_burst != 0U && engine->profile.max_probes != 0U &&
              sender->probe_count >= engine->profile.max_probes))) {
            sender->phase = DMP_REL_PHASE_TERMINAL;
            settle_sender(engine, sender);
            return DMP_OK;
        }
        if (starting) {
            sender->burst_inflight = 1U;
        }
        sender->sending_index = frag_index;
        logical.fragment_index = frag_index;
        logical.chunk_size = sender->chunk_size;
        logical.total_size = sender->total_size;
        if (sender->kind == KIND_RESULT) {
            logical.payload = slice_at(result_bytes(engine, sender->related_slot), frag_index,
                                      sender->chunk_size, sender->total_size);
        } else {
            logical.payload = slice_view(engine, index, frag_index, sender->chunk_size,
                                         sender->total_size);
        }
        if (logical.payload.data == NULL || logical.payload.size == 0U) {
            if (starting) {
                sender->burst_inflight = 0U;
            }
            return DMP_MALFORMED;
        }
    }
    adapter_index = find_adapter(engine, 0, allow_control);
    if (adapter_index < 0) {
        return DMP_BUSY;
    }
    if (sender->kind == KIND_REJECT) {
        uint32_t seq = 0U;
        status = dmp_identity_next_seq(engine->storage.identity, engine->storage.context, &seq);
        if (status != DMP_OK) {
            return status;
        }
        sender->own.origin = slot->local;
        sender->own.seq = seq;
        logical.own = sender->own;
    }
    status = arm_adapter(engine, adapter_index, 0, (uint32_t)index, sender->generation, &adapter);
    if (status != DMP_OK) {
        return status;
    }
    out.data = frame_bytes(engine, (size_t)adapter_index);
    out.capacity = engine->profile.encoded_mtu;
    status = engine->storage.encode(engine->storage.encode_context, &logical, out, &written);
    if (status == DMP_BUSY) {
        /* The attempt is alive but not active yet. Keep the admitted sender. */
        release_adapter(adapter);
        if (sender->live != 0U && sender->frag_count != 0U && sender->burst_counted == 0U) {
            sender->burst_inflight = 0U;
        }
        return DMP_BUSY;
    }
    if (status != DMP_OK || written == 0U || written > out.capacity) {
        dmp_status failed = status == DMP_OK ? DMP_MALFORMED : status;
        /* A terminal seal or encode failure is local: no frame is submitted
         * and the slot does not stay live until a later deadline.
         * possibly_sent stays clear, so the outcome is unsent. */
        release_adapter(adapter);
        if (sender->live != 0U) {
            sender->burst_inflight = 0U;
            sender->phase = DMP_REL_PHASE_TERMINAL;
            settle_sender(engine, sender);
        }
        return failed;
    }
    sender->tx_slot = adapter->token.slot;
    sender->tx_generation = adapter->token.generation;
    sender->tx_live = true;
    sender->phase = DMP_REL_PHASE_TRANSMITTING;
    sender->attempts++;
    status = submit_frame(engine, adapter, written, sender->send_deadline);
    if (status != DMP_OK) {
        if (sender->live != 0U && sender->tx_slot == (uint32_t)adapter_index) {
            sender->tx_live = false;
            sender->phase = DMP_REL_PHASE_QUEUED;
            if (sender->attempts > 0U) {
                sender->attempts--;
            }
            if (sender->frag_count != 0U && sender->burst_counted == 0U) {
                sender->burst_inflight = 0U;
            }
        }
        return status;
    }
    return DMP_OK;
}

static int sender_waiting(const dmp_reliability *engine,
                          const dmp_reliability_correlation_slot *correlation)
{
    const dmp_reliability_sender_slot *sender;
    if (correlation->request.slot >= engine->storage.sender_capacity) {
        return 0;
    }
    sender = &engine->storage.senders[correlation->request.slot];
    return sender->live != 0U && sender->generation == correlation->request.generation &&
           sender->kind == KIND_REQ && !sender->result_seen;
}

static void stop_request(dmp_reliability *engine, dmp_reliability_sender_slot *sender, int outcome_seen)
{
    if (sender == NULL || sender->live == 0U) {
        return;
    }
    if (outcome_seen) {
        sender->result_seen = true;
    }
    sender->phase = DMP_REL_PHASE_TERMINAL;
    if (sender->tx_live) {
        cancel_tx(engine, sender);
        consume(engine);
    } else {
        settle_sender(engine, sender);
    }
}

/* Returns 1 when recovery has ended and the caller must leave this sender. */
static int finish_fragment_wait(dmp_reliability *engine, dmp_reliability_sender_slot *sender)
{
    int selective;

    if (sender->frag_count == 0U) {
        return 0;
    }
    selective = selective_service(&engine->profile, sender->service_id);
    if (selective && sender->repair_mask != 0U) {
        sender->active_mask = sender->repair_mask;
        sender->repair_mask = 0U;
        sender->probe_burst = 0U;
    } else if (selective) {
        if (sender->packet_count >= engine->profile.max_bursts ||
            sender->probe_count >= engine->profile.max_probes) {
            sender->phase = DMP_REL_PHASE_TERMINAL;
            settle_sender(engine, sender);
            return 1;
        }
        sender->active_mask = fragment_bit(sender->frag_count - 1U);
        sender->probe_burst = 1U;
    } else {
        if (engine->profile.max_bursts != 0U &&
            sender->packet_count >= engine->profile.max_bursts) {
            sender->phase = DMP_REL_PHASE_TERMINAL;
            settle_sender(engine, sender);
            return 1;
        }
        sender->active_mask = fragment_mask(sender->frag_count);
        sender->probe_burst = 0U;
    }
    return 0;
}

static void expire(dmp_reliability *engine, dmp_time_ms now)
{
    size_t i;
    for (i = 0U; i < engine->storage.result_capacity; i++) {
        dmp_reliability_result_slot *result = &engine->storage.results[i];
        dmp_reliability_sender_slot *sender;
        if (result->live == 0U || result->deadline == 0U ||
            !dmp_deadline_reached(now, result->deadline)) {
            continue;
        }
        sender = sender_of_result(engine, result);
        if (sender != NULL && sender->tx_live) {
            continue;
        }
        if (sender != NULL) {
            release_sender(sender);
        }
        release_result(result);
    }
    for (i = 0U; i < engine->storage.history_capacity; i++) {
        dmp_reliability_history_slot *history = &engine->storage.history[i];
        if (history->live != 0U && dmp_deadline_reached(now, history->deadline)) {
            release_history(history);
        }
    }
    for (i = 0U; i < engine->storage.correlation_capacity; i++) {
        dmp_reliability_correlation_slot *correlation = &engine->storage.correlations[i];
        if (correlation->live != 0U &&
            dmp_deadline_reached(now, correlation->tombstone_deadline)) {
            release_correlation(correlation);
        }
    }
    for (i = 0U; i < engine->storage.sender_capacity; i++) {
        dmp_reliability_sender_slot *sender = &engine->storage.senders[i];
        if (sender->live == 0U) {
            continue;
        }
        if ((sender->kind == KIND_REQ || sender->kind == KIND_DATA) && !sender->result_seen &&
            dmp_deadline_reached(now, sender->result_deadline)) {
            sender->phase = DMP_REL_PHASE_TERMINAL;
            if (sender->tx_live) {
                cancel_tx(engine, sender);
            } else {
                settle_sender(engine, sender);
            }
            continue;
        }
        if ((sender->kind == KIND_REQ || sender->kind == KIND_DATA) && !sender->tx_live &&
            sender->possibly_sent == 0U &&
            sender->attempts == 0U && sender->phase == DMP_REL_PHASE_QUEUED &&
            (dmp_deadline_reached(now, sender->queue_deadline) ||
             dmp_deadline_reached(now, sender->send_deadline))) {
            sender->phase = DMP_REL_PHASE_TERMINAL;
            settle_sender(engine, sender);
            continue;
        }
        if ((sender->kind == KIND_REQ || sender->kind == KIND_DATA) && !sender->tx_live &&
            sender->phase == DMP_REL_PHASE_AWAIT_RECEIPT && !sender->receipt_seen &&
            !sender->result_seen && dmp_deadline_reached(now, sender->next_attempt) &&
            !dmp_deadline_reached(now, sender->send_deadline) &&
            !dmp_deadline_reached(now, sender->result_deadline)) {
            if (finish_fragment_wait(engine, sender)) {
                continue;
            }
            sender->phase = DMP_REL_PHASE_QUEUED;
        }
        if (sender->kind == KIND_RESULT && sender->frag_count != 0U && !sender->tx_live &&
            sender->phase == DMP_REL_PHASE_AWAIT_RECEIPT && !sender->result_seen &&
            dmp_deadline_reached(now, sender->next_attempt) &&
            !dmp_deadline_reached(now, sender->send_deadline) &&
            !dmp_deadline_reached(now, sender->result_deadline)) {
            dmp_reliability_result_slot *result = result_of_sender(engine, sender);
            if (result != NULL && result->acknowledged == 0U) {
                if (finish_fragment_wait(engine, sender)) {
                    continue;
                }
                sender->phase = DMP_REL_PHASE_QUEUED;
            }
        }
        if (sender->kind == KIND_RESULT && dmp_deadline_reached(now, sender->send_deadline)) {
            if (sender->tx_live) {
                sender->phase = DMP_REL_PHASE_TERMINAL;
                cancel_tx(engine, sender);
            } else {
                dmp_reliability_result_slot *result = result_of_sender(engine, sender);
                if (result != NULL && result->deadline == 0U) {
                    release_result(result);
                }
                release_sender(sender);
            }
            continue;
        }
        if (sender->kind == KIND_REJECT) {
            dmp_reliability_history_slot *history = history_of_sender(engine, sender);
            if (history == NULL || dmp_deadline_reached(now, history->deadline)) {
                if (sender->tx_live) {
                    sender->phase = DMP_REL_PHASE_TERMINAL;
                    cancel_tx(engine, sender);
                } else {
                    release_sender(sender);
                }
            }
        }
    }
    consume(engine);
}

static void send_due_receipts(dmp_reliability *engine, dmp_time_ms now, dmp_status *acc)
{
    size_t i;
    for (i = 0U; i < engine->storage.history_capacity; i++) {
        dmp_reliability_history_slot *history = &engine->storage.history[i];
        dmp_reliability_result_slot *result;
        dmp_reliability_sender_slot *sender;
        int due;
        dmp_status status;
        if (history->live == 0U || history->decision != 0U ||
            history->receipt_count >= engine->profile.receipt_limit) {
            continue;
        }
        if (history->result_slot >= engine->storage.result_capacity) {
            continue;
        }
        result = &engine->storage.results[history->result_slot];
        if (result->live == 0U || result->generation != history->result_generation) {
            continue;
        }
        sender = sender_of_result(engine, result);
        if (sender == NULL || sender->receipt_seen) {
            continue;
        }
        due = 0;
        if (result->deadline == 0U && dmp_deadline_reached(now, sender->next_attempt) &&
            history->receipt_count == 0U) {
            due = 1;
        }
        if (result->deadline != 0U && history->receipt_count == 0U &&
            !dmp_deadline_reached(now, result->deadline)) {
            due = 1;
        }
        if (!due) {
            continue;
        }
        status = send_ack(engine, history->service_id, history->source, history->source.origin, now);
        if (status == DMP_OK) {
            history->receipt_count++;
            sender->receipt_seen = true;
        } else if (status != DMP_BUSY && *acc == DMP_OK) {
            *acc = status;
        }
    }
}

static void send_ready(dmp_reliability *engine, dmp_time_ms now, dmp_status *acc)
{
    size_t i;
    for (i = 0U; i < engine->storage.sender_capacity; i++) {
        dmp_reliability_sender_slot *sender = &engine->storage.senders[i];
        dmp_status status;
        if (sender->live == 0U || sender->tx_live || sender->phase != DMP_REL_PHASE_QUEUED) {
            continue;
        }
        if (sender->kind == KIND_RESULT && sender->receipt_seen == 0U &&
            dmp_deadline_reached(now, sender->next_attempt)) {
            dmp_reliability_result_slot *result = result_of_sender(engine, sender);
            dmp_reliability_history_slot *history = result == NULL ? NULL :
                                                    history_of_result(engine, result);
            if (result != NULL && result->reserved == 0U && history != NULL &&
                history->receipt_count < engine->profile.receipt_limit) {
                continue;
            }
        }
        if (!dmp_deadline_reached(now, sender->next_attempt) ||
            dmp_deadline_reached(now, sender->send_deadline)) {
            continue;
        }
        if (sender->kind != KIND_REJECT && gate_held(engine, sender->service_id, i)) {
            continue;
        }
        status = begin_send(engine, i, now);
        if (status == DMP_DEADLINE_EXPIRED || status == DMP_BUSY) {
            continue;
        }
        if (status != DMP_OK && *acc == DMP_OK) {
            *acc = status;
        }
    }
}

static int any_live(const dmp_reliability *engine)
{
    size_t i;
    for (i = 0U; i < engine->storage.sender_capacity; i++) {
        if (engine->storage.senders[i].live != 0U || engine->storage.senders[i].tx_live) {
            return 1;
        }
    }
    for (i = 0U; i < engine->storage.result_capacity; i++) {
        if (engine->storage.results[i].live != 0U) {
            return 1;
        }
    }
    for (i = 0U; i < engine->storage.history_capacity; i++) {
        if (engine->storage.history[i].live != 0U) {
            return 1;
        }
    }
    for (i = 0U; i < engine->storage.correlation_capacity; i++) {
        if (engine->storage.correlations[i].live != 0U) {
            return 1;
        }
    }
    for (i = 0U; i < engine->storage.adapter_capacity; i++) {
        if (engine->storage.adapters[i].live != 0U) {
            return 1;
        }
    }
    return 0;
}

static dmp_status rearm_result(dmp_reliability *engine, int result_index, dmp_time_ms now)
{
    dmp_reliability_result_slot *result = &engine->storage.results[result_index];
    dmp_reliability_sender_slot *existing = sender_of_result(engine, result);
    dmp_reliability_sender_slot *sender;
    uint64_t generation;
    int index;
    dmp_status status;
    if (!result_cached(result, now) || result->acknowledged != 0U) {
        return DMP_OK;
    }
    if (existing != NULL) {
        /* Freshness grants are short control results; an exact duplicate
         * grant request immediately retries its retained response. Ordinary
         * application results keep their existing receipt/recovery cadence. */
        if (result->service_id == 0U && !existing->tx_live &&
            existing->phase != DMP_REL_PHASE_TERMINAL &&
            !dmp_deadline_reached(now, existing->send_deadline)) {
            existing->phase = DMP_REL_PHASE_QUEUED;
            existing->next_attempt = now;
        }
        return DMP_OK;
    }
    index = find_unused_sender(engine);
    if (index < 0) {
        return DMP_OK;
    }
    sender = &engine->storage.senders[index];
    status = dmp_generation_next(sender->generation, &generation);
    if (status != DMP_OK) {
        return status;
    }
    memset(sender, 0, sizeof *sender);
    sender->generation = generation;
    sender->live = 1U;
    sender->phase = DMP_REL_PHASE_QUEUED;
    sender->kind = KIND_RESULT;
    sender->service_id = result->service_id;
    sender->own = result->result;
    sender->reply_to = result->request;
    sender->send_deadline = result->deadline;
    sender->queue_deadline = result->deadline;
    sender->retain_deadline = result->deadline;
    sender->result_deadline = result->deadline;
    sender->next_attempt = now;
    sender->payload_len = result->payload_len;
    sender->related_slot = (uint32_t)result_index;
    sender->related_generation = result->generation;
    status = arm_saved_fragments(engine, sender, result->payload_len);
    if (status != DMP_OK) {
        /* The encoder refused the size probe. No frame, and this new sender
         * does not stay queued. */
        release_sender(sender);
        return status;
    }
    result->sender_slot = (uint32_t)index;
    result->sender_generation = generation;
    return DMP_OK;
}

static dmp_status queue_rejection_sender(dmp_reliability *engine, int history_index,
                                         dmp_time_ms now)
{
    dmp_reliability_history_slot *history = &engine->storage.history[history_index];
    dmp_reliability_sender_slot *sender;
    uint64_t generation;
    int index;
    dmp_status status;
    if (reject_pending(engine, (uint32_t)history_index, history->generation)) {
        return DMP_OK;
    }
    index = find_unused_sender(engine);
    if (index < 0) {
        return DMP_QUOTA_EXHAUSTED;
    }
    sender = &engine->storage.senders[index];
    status = dmp_generation_next(sender->generation, &generation);
    if (status != DMP_OK) {
        return status;
    }
    memset(sender, 0, sizeof *sender);
    sender->generation = generation;
    sender->live = 1U;
    sender->phase = DMP_REL_PHASE_QUEUED;
    sender->kind = KIND_REJECT;
    sender->service_id = history->service_id;
    sender->reply_to = history->source;
    sender->queue_deadline = history->deadline;
    sender->send_deadline = history->deadline;
    sender->retain_deadline = history->deadline;
    sender->next_attempt = now;
    sender->related_slot = (uint32_t)history_index;
    sender->related_generation = history->generation;
    return DMP_OK;
}

static dmp_status resend_receipt(dmp_reliability *engine, dmp_reliability_history_slot *history,
                                 dmp_time_ms now)
{
    dmp_reliability_sender_slot *sender = NULL;
    dmp_status status;
    if (history->receipt_count >= engine->profile.receipt_limit) {
        return DMP_OK;
    }
    if (history->result_slot < engine->storage.result_capacity) {
        dmp_reliability_result_slot *result = &engine->storage.results[history->result_slot];
        if (result->live != 0U && result->generation == history->result_generation) {
            sender = sender_of_result(engine, result);
        }
    }
    status = send_ack(engine, history->service_id, history->source, history->source.origin, now);
    if (status == DMP_OK) {
        history->receipt_count++;
        if (sender != NULL) {
            sender->receipt_seen = true;
        }
        return DMP_OK;
    }
    return status == DMP_BUSY ? DMP_OK : status;
}

static int correlation_meta_same(const dmp_reliability *engine,
                                 const dmp_reliability_correlation_slot *correlation,
                                 dmp_bytes metadata)
{
    const uint8_t *stored;
    if ((size_t)correlation->result_metadata_len != metadata.size) {
        return 0;
    }
    if (metadata.size == 0U) {
        return 1;
    }
    stored = engine->storage.correlation_metadata +
             (size_t)(correlation - engine->storage.correlations) *
                 (size_t)DMP_RELIABILITY_METADATA_BYTES;
    return memcmp(stored, metadata.data, metadata.size) == 0;
}

static void store_result_meta(dmp_reliability *engine,
                              dmp_reliability_correlation_slot *correlation, dmp_bytes metadata)
{
    if (metadata.size != 0U) {
        memcpy(correlation_meta(engine, (size_t)(correlation - engine->storage.correlations)),
               metadata.data, metadata.size);
    }
    correlation->result_metadata_len = (uint16_t)metadata.size;
}

static dmp_reliability_sender_slot *live_request_sender(dmp_reliability *engine,
                                                        const dmp_reliability_correlation_slot *correlation)
{
    dmp_reliability_sender_slot *sender;
    if (!sender_waiting(engine, correlation)) {
        return NULL;
    }
    sender = &engine->storage.senders[correlation->request.slot];
    return sender;
}

static dmp_status handle_ack(dmp_reliability *engine, dmp_message_key reply, uint32_t service)
{
    size_t i;
    dmp_bytes empty;
    empty.data = NULL;
    empty.size = 0U;
    for (i = 0U; i < engine->storage.sender_capacity; i++) {
        dmp_reliability_sender_slot *sender = &engine->storage.senders[i];
        if (sender->live == 0U ||
            (sender->kind != KIND_REQ && sender->kind != KIND_DATA) ||
            sender->service_id != service ||
            !key_eq(sender->own, reply)) {
            continue;
        }
        if (sender->kind == KIND_DATA) {
            if (!sender->result_seen) {
                dmp_bytes empty;
                empty.data = NULL;
                empty.size = 0U;
                sender->result_seen = true;
                sender->phase = DMP_REL_PHASE_TERMINAL;
                emit(engine, DMP_REL_EVENT_DATA_DELIVERED, sender_handle(engine, sender),
                     sender->own, service, 0U, empty);
            }
            if (sender->tx_live) {
                cancel_tx(engine, sender);
                consume(engine);
            } else {
                release_sender(sender);
            }
            return DMP_OK;
        }
        if (!sender->receipt_seen && !sender->result_seen) {
            sender->receipt_seen = true;
            sender->phase = DMP_REL_PHASE_AWAIT_RESULT;
            emit(engine, DMP_REL_EVENT_RECEIPT, sender_handle(engine, sender), sender->own,
                 service, 0U, empty);
        }
        return DMP_OK;
    }
    for (i = 0U; i < engine->storage.result_capacity; i++) {
        dmp_reliability_result_slot *result = &engine->storage.results[i];
        dmp_reliability_sender_slot *sender;
        if (result->live == 0U || result->service_id != service || !key_eq(result->result, reply)) {
            continue;
        }
        result->acknowledged = 1U;
        sender = sender_of_result(engine, result);
        if (sender != NULL) {
            if (sender->tx_live) {
                sender->result_seen = true;
                sender->phase = DMP_REL_PHASE_TERMINAL;
                cancel_tx(engine, sender);
                consume(engine);
            } else {
                release_sender(sender);
            }
        }
        return DMP_OK;
    }
    return DMP_OK;
}

static dmp_status handle_reply(dmp_reliability *engine, const dmp_frame_view *frame,
                               dmp_message_key reply, dmp_message_key source, uint32_t service,
                               dmp_bytes plaintext, dmp_bytes metadata, int status_present,
                               uint32_t wire_status, dmp_time_ms now)
{
    dmp_reliability_correlation_slot *correlation = NULL;
    dmp_reliability_sender_slot *sender;
    dmp_bytes payload;
    int ack_req = (frame->fields.options & DMP_OPT_ACK_REQ) != 0U;
    size_t i;
    dmp_status status;
    if (frame->fields.type == DMP_TYPE_ERR) {
        if (!status_present || wire_status == 0U || (wire_status >= 8U && wire_status <= 63U) ||
            (wire_status <= 7U && ack_req) || (wire_status >= 64U && !ack_req)) {
            return DMP_MALFORMED;
        }
    } else if (frame->fields.type == DMP_TYPE_RSP) {
        if (!ack_req) {
            return DMP_UNSUPPORTED;
        }
        if (status_present && wire_status >= 1U && wire_status <= 63U) {
            return DMP_MALFORMED;
        }
    } else {
        return DMP_UNSUPPORTED;
    }
    for (i = 0U; i < engine->storage.correlation_capacity; i++) {
        dmp_reliability_correlation_slot *candidate = &engine->storage.correlations[i];
        if (candidate->live != 0U && candidate->service_id == service &&
            key_eq(candidate->request_key, reply) &&
            !dmp_deadline_reached(now, candidate->tombstone_deadline)) {
            correlation = candidate;
            break;
        }
    }
    if (correlation == NULL) {
        return DMP_OK;
    }
    if (frame->fields.type == DMP_TYPE_ERR && wire_status <= 7U) {
        if (correlation->result_delivered != 0U) {
            return DMP_MALFORMED;
        }
        if (correlation->terminal_unknown != 0U || !sender_waiting(engine, correlation)) {
            return DMP_OK;
        }
        sender = live_request_sender(engine, correlation);
        payload.data = NULL;
        payload.size = 0U;
        emit(engine, DMP_REL_EVENT_REJECTED, correlation->request, correlation->request_key,
             service, wire_status, payload);
        stop_request(engine, sender, 1);
        return DMP_OK;
    }
    if (correlation->result_delivered != 0U) {
        if (!key_eq(correlation->result_key, source) ||
            !correlation_meta_same(engine, correlation, metadata)) {
            return DMP_MALFORMED;
        }
        if (!dmp_deadline_reached(now, correlation->correlation_deadline) &&
            correlation->reserved == 0U) {
            payload.data = NULL;
            payload.size = 0U;
            correlation->reserved = 1U;
            emit(engine, DMP_REL_EVENT_LATE_RESULT, correlation->request, source, service,
                 wire_status, payload);
        }
        if (!dmp_deadline_reached(now, correlation->tombstone_deadline)) {
            status = send_ack(engine, service, source, source.origin, now);
            if (status != DMP_OK && status != DMP_BUSY) {
                return status;
            }
        }
        return DMP_OK;
    }
    if (correlation->terminal_unknown != 0U) {
        correlation->result_key = source;
        store_result_meta(engine, correlation, metadata);
        correlation->result_delivered = 1U;
        if (!dmp_deadline_reached(now, correlation->correlation_deadline)) {
            payload.data = NULL;
            payload.size = 0U;
            correlation->reserved = 1U;
            emit(engine, DMP_REL_EVENT_LATE_RESULT, correlation->request, source, service,
                 wire_status, payload);
        }
        status = send_ack(engine, service, source, source.origin, now);
        if (status != DMP_OK && status != DMP_BUSY) {
            return status;
        }
        return DMP_OK;
    }
    if (!sender_waiting(engine, correlation)) {
        return DMP_OK;
    }
    if (plaintext.size > engine->storage.receive_payload_capacity) {
        return DMP_LIMIT_EXHAUSTED;
    }
    sender = live_request_sender(engine, correlation);
    correlation->result_key = source;
    store_result_meta(engine, correlation, metadata);
    correlation->result_delivered = 1U;
    payload = stage_bytes(engine, plaintext.data, plaintext.size);
    emit(engine, DMP_REL_EVENT_RESULT, correlation->request, source, service, wire_status, payload);
    if (sender != NULL) {
        sender->receipt_seen = true;
    }
    stop_request(engine, sender, 1);
    status = send_ack(engine, service, source, source.origin, now);
    if (status != DMP_OK && status != DMP_BUSY) {
        return status;
    }
    return DMP_OK;
}

static dmp_status accept_request(dmp_reliability *engine, const dmp_frame_view *frame,
                                 dmp_message_key source, uint32_t service, dmp_bytes plaintext,
                                 dmp_bytes metadata, dmp_message_origin destination, dmp_time_ms now)
{
    dmp_reliability_history_slot *history;
    dmp_reliability_result_slot *result;
    dmp_reliability_sender_slot *sender;
    dmp_time_ms dedup;
    dmp_time_ms receipt_due;
    dmp_time_ms result_due;
    uint64_t history_gen;
    uint64_t result_gen;
    uint64_t sender_gen;
    int history_index;
    int result_index;
    int sender_index;
    dmp_status status;
    dmp_bytes payload;
    dmp_reliability_handle handle;
    if (operations_used(engine, service) >= engine->profile.operations_per_service) {
        return DMP_BUSY;
    }
    if (metadata.size > DMP_RELIABILITY_METADATA_BYTES ||
        plaintext.size > engine->profile.message_bytes) {
        return DMP_LIMIT_EXHAUSTED;
    }
    history_index = find_unused_history(engine);
    result_index = find_unused_result(engine);
    sender_index = find_unused_sender(engine);
    if (history_index < 0 || result_index < 0 || sender_index < 0) {
        return DMP_QUOTA_EXHAUSTED;
    }
    history = &engine->storage.history[history_index];
    result = &engine->storage.results[result_index];
    sender = &engine->storage.senders[sender_index];
    status = dmp_deadline_after(now, engine->profile.dedup_ms, &dedup);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_deadline_after(now, engine->profile.receipt_delay_ms, &receipt_due);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_deadline_after(now, engine->profile.result_deadline_ms, &result_due);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_generation_next(history->generation, &history_gen);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_generation_next(result->generation, &result_gen);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_generation_next(sender->generation, &sender_gen);
    if (status != DMP_OK) {
        return status;
    }
    memset(history, 0, sizeof *history);
    memset(result, 0, sizeof *result);
    memset(sender, 0, sizeof *sender);
    history->generation = history_gen;
    result->generation = result_gen;
    sender->generation = sender_gen;
    if (metadata.size != 0U) {
        memcpy(history_meta(engine, (size_t)history_index), metadata.data, metadata.size);
    }
    history->live = 1U;
    history->decision = 0U;
    history->type = frame->fields.type;
    history->ack_req = 1U;
    history->service_id = service;
    history->metadata_len = (uint16_t)metadata.size;
    history->source = source;
    history->destination = destination;
    history->deadline = dedup;
    history->result_slot = (uint32_t)result_index;
    history->result_generation = result_gen;
    remember_descriptor(history, frame);
    result->live = 1U;
    result->request = source;
    result->destination = source.origin;
    result->service_id = service;
    result->sender_slot = (uint32_t)sender_index;
    result->sender_generation = sender_gen;
    result->history_slot = (uint32_t)history_index;
    result->history_generation = history_gen;
    sender->live = 1U;
    sender->phase = DMP_REL_PHASE_AWAIT_RESULT;
    sender->kind = KIND_RESULT;
    sender->service_id = service;
    sender->reply_to = source;
    sender->queue_deadline = result_due;
    sender->send_deadline = result_due;
    sender->result_deadline = result_due;
    sender->retain_deadline = dedup;
    sender->next_attempt = receipt_due;
    sender->related_slot = (uint32_t)result_index;
    sender->related_generation = result_gen;
    handle.slot = (uint32_t)history_index;
    handle.generation = history_gen;
    payload = stage_bytes(engine, plaintext.data, plaintext.size);
    emit(engine, DMP_REL_EVENT_REQUEST_ACCEPTED, handle, source, service, 0U, payload);
    return DMP_OK;
}

static dmp_status handle_request(dmp_reliability *engine, const dmp_frame_view *frame,
                                 dmp_message_key source, uint32_t service, dmp_bytes plaintext,
                                 dmp_bytes metadata, dmp_time_ms now)
{
    dmp_message_origin destination = frame_destination(engine, frame);
    int history_index = find_history_key(engine, source);
    int result_index = find_result_key(engine, source);
    if (history_index >= 0) {
        dmp_reliability_history_slot *history = &engine->storage.history[history_index];
        dmp_reliability_result_slot *result = NULL;
        if (!metadata_match(engine, history, frame, service, metadata, destination)) {
            return DMP_MALFORMED;
        }
        if (history->decision != 0U) {
            dmp_status status = queue_rejection_sender(engine, history_index, now);
            return status == DMP_QUOTA_EXHAUSTED ? DMP_OK : status;
        }
        if (result_index >= 0) {
            result = &engine->storage.results[result_index];
        }
        if (result_cached(result, now)) {
            if (result->acknowledged != 0U) {
                return resend_receipt(engine, history, now);
            }
            return rearm_result(engine, result_index, now);
        }
        return resend_receipt(engine, history, now);
    }
    if (result_index >= 0) {
        dmp_reliability_result_slot *result = &engine->storage.results[result_index];
        if (result->service_id != service) {
            return DMP_MALFORMED;
        }
        if (result_cached(result, now)) {
            return rearm_result(engine, result_index, now);
        }
        /* History retention ended, or the accept record is gone, but this request
         * identity is still reserved. Never dispatch it again. */
        return DMP_OK;
    }
    return accept_request(engine, frame, source, service, plaintext, metadata, destination, now);
}

static dmp_status handle_data(dmp_reliability *engine, const dmp_frame_view *frame,
                              dmp_message_key source, uint32_t service, dmp_bytes plaintext,
                              dmp_bytes metadata, dmp_time_ms now)
{
    dmp_message_origin destination = frame_destination(engine, frame);
    dmp_reliability_history_slot *history;
    dmp_reliability_handle handle;
    dmp_time_ms deadline;
    dmp_bytes payload;
    uint64_t generation;
    int history_index = find_history_key(engine, source);
    dmp_status status;

    if ((frame->fields.options & DMP_OPT_ACK_REQ) == 0U || metadata.size > DMP_RELIABILITY_METADATA_BYTES ||
        plaintext.size > engine->profile.message_bytes) {
        return DMP_UNSUPPORTED;
    }
    if (history_index >= 0) {
        history = &engine->storage.history[history_index];
        if (!metadata_match(engine, history, frame, service, metadata, destination)) {
            return DMP_MALFORMED;
        }
        return resend_receipt(engine, history, now);
    }
    if (metadata.size != 0U && metadata.data == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    history_index = find_unused_history(engine);
    if (history_index < 0) {
        return DMP_QUOTA_EXHAUSTED;
    }
    history = &engine->storage.history[history_index];
    status = dmp_deadline_after(now, engine->profile.dedup_ms, &deadline);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_generation_next(history->generation, &generation);
    if (status != DMP_OK) {
        return status;
    }
    memset(history, 0, sizeof *history);
    history->generation = generation;
    if (metadata.size != 0U) {
        memcpy(history_meta(engine, (size_t)history_index), metadata.data, metadata.size);
    }
    history->live = 1U;
    history->decision = DMP_REL_HISTORY_ACCEPTED;
    history->type = frame->fields.type;
    history->ack_req = 1U;
    history->service_id = service;
    history->metadata_len = (uint16_t)metadata.size;
    history->source = source;
    history->destination = destination;
    history->deadline = deadline;
    history->result_slot = UINT32_MAX;
    remember_descriptor(history, frame);
    handle.slot = (uint32_t)history_index;
    handle.generation = generation;
    payload = stage_bytes(engine, plaintext.data, plaintext.size);
    emit(engine, DMP_REL_EVENT_DATA_ACCEPTED, handle, source, service, 0U, payload);
    status = send_ack(engine, service, source, source.origin, now);
    if (status == DMP_OK) {
        history->receipt_count = 1U;
    }
    /* Delivery is accepted once its bounded history is installed. A full
     * return slot is recovered by the sender's next fresh-PN retry. */
    return DMP_OK;
}

static dmp_status validate_storage(const dmp_reliability_storage *storage,
                                   const dmp_admitted_profile *profile)
{
    dmp_status status;
    uint32_t reserve;
    if (storage == NULL || profile == NULL || storage->identity == NULL ||
        storage->transport == NULL || storage->encode == NULL || storage->notice == NULL ||
        storage->transport->submit == NULL || storage->transport->cancel == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (profile->peers != 1U || profile->encoded_mtu == 0U || profile->default_service == 0U ||
        !service_allowed(profile, profile->default_service)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (storage->sender_capacity < profile->sender_slots ||
        storage->result_capacity < profile->result_slots ||
        storage->history_capacity < profile->history_slots ||
        storage->correlation_capacity < profile->correlation_slots ||
        storage->adapter_capacity < profile->adapter_slots) {
        return DMP_INVALID_ARGUMENT;
    }
    status = check_minimum_capacity(profile->sender_slots, profile->message_bytes,
                                    storage->sender_payload_capacity);
    if (status != DMP_OK) {
        return status;
    }
    status = check_minimum_capacity(profile->result_slots, profile->message_bytes,
                                    storage->result_payload_capacity);
    if (status != DMP_OK) {
        return status;
    }
    status = check_minimum_capacity(profile->history_slots,
                                    (uint32_t)DMP_RELIABILITY_METADATA_BYTES,
                                    storage->history_metadata_capacity);
    if (status != DMP_OK) {
        return status;
    }
    status = check_minimum_capacity(profile->correlation_slots,
                                    (uint32_t)DMP_RELIABILITY_METADATA_BYTES,
                                    storage->correlation_metadata_capacity);
    if (status != DMP_OK) {
        return status;
    }
    status = check_minimum_capacity(profile->adapter_slots, profile->encoded_mtu,
                                    storage->frame_capacity);
    if (status != DMP_OK) {
        return status;
    }
    if (storage->receive_payload_capacity < profile->message_bytes) {
        return DMP_INVALID_ARGUMENT;
    }
    status = require_array(storage->sender_capacity, storage->senders);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(storage->sender_payload_capacity, storage->sender_payload);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(storage->result_capacity, storage->results);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(storage->result_payload_capacity, storage->result_payload);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(storage->history_capacity, storage->history);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(storage->correlation_capacity, storage->correlations);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(storage->history_metadata_capacity, storage->history_metadata);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(storage->correlation_metadata_capacity, storage->correlation_metadata);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(storage->adapter_capacity, storage->adapters);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(storage->frame_capacity, storage->frames);
    if (status != DMP_OK) {
        return status;
    }
    status = require_array(storage->receive_payload_capacity, storage->receive_payload);
    if (status != DMP_OK) {
        return status;
    }
    if ((profile->tx_borrow ? 1 : 0) !=
            (storage->transport->caps.ownership == DMP_TX_BORROW ? 1 : 0) ||
        profile->synchronous_completion != storage->transport->caps.synchronous_completion ||
        storage->transport->caps.max_frame_bytes < profile->encoded_mtu) {
        return DMP_INVALID_ARGUMENT;
    }
    reserve = control_reserve(profile);
    if (reserve == 0U || profile->adapter_slots <= reserve) {
        return DMP_UNSUPPORTED;
    }
    return DMP_OK;
}

dmp_status dmp_reliability_init(dmp_reliability *engine, const dmp_reliability_storage *storage)
{
    const dmp_admitted_profile *profile;
    dmp_status status;
    if (engine == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (engine->initialized) {
        return DMP_INVALID_ARGUMENT;
    }
    if (storage == NULL || storage->profile == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    profile = storage->profile;
    status = validate_storage(storage, profile);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_identity_context_retain(storage->identity, storage->context);
    if (status != DMP_OK) {
        return status;
    }
    memset(engine, 0, sizeof *engine);
    engine->storage = *storage;
    engine->profile = *profile;
    engine->transport = *storage->transport;
    engine->storage.profile = &engine->profile;
    engine->storage.transport = &engine->transport;
    /* Extra caller-provided storage is accepted but must not raise admitted quotas. */
    engine->storage.sender_capacity = engine->profile.sender_slots;
    engine->storage.result_capacity = engine->profile.result_slots;
    engine->storage.history_capacity = engine->profile.history_slots;
    engine->storage.correlation_capacity = engine->profile.correlation_slots;
    engine->storage.adapter_capacity = engine->profile.adapter_slots;
    engine->generation = 1U;
    engine->context_retained = 1U;
    if (engine->storage.sender_capacity != 0U) {
        memset(engine->storage.senders, 0,
               engine->storage.sender_capacity * sizeof *engine->storage.senders);
    }
    if (engine->storage.result_capacity != 0U) {
        memset(engine->storage.results, 0,
               engine->storage.result_capacity * sizeof *engine->storage.results);
    }
    if (engine->storage.history_capacity != 0U) {
        memset(engine->storage.history, 0,
               engine->storage.history_capacity * sizeof *engine->storage.history);
    }
    if (engine->storage.correlation_capacity != 0U) {
        memset(engine->storage.correlations, 0,
               engine->storage.correlation_capacity * sizeof *engine->storage.correlations);
    }
    if (engine->storage.adapter_capacity != 0U) {
        memset(engine->storage.adapters, 0,
               engine->storage.adapter_capacity * sizeof *engine->storage.adapters);
    }
    engine->initialized = 1U;
    return DMP_OK;
}

dmp_status dmp_reliability_close(dmp_reliability *engine, dmp_time_ms now)
{
    dmp_status status;
    (void)now;
    if (!ready(engine)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (any_live(engine)) {
        return DMP_BUSY;
    }
    status = dmp_identity_context_release(engine->storage.identity, engine->storage.context);
    if (status != DMP_OK) {
        return status;
    }
    engine->context_retained = 0U;
    engine->initialized = 0U;
    return DMP_OK;
}

static dmp_status submit_outbound(dmp_reliability *engine, uint32_t service_id,
                                  dmp_bytes payload, dmp_bytes token, dmp_time_ms now,
                                  uint32_t jitter_ms, uint8_t kind, uint8_t message_type,
                                  dmp_reliability_handle *out)
{
    const dmp_identity_slot *slot;
    dmp_reliability_sender_slot *sender;
    dmp_reliability_correlation_slot *correlation = NULL;
    dmp_time_ms queue_deadline;
    dmp_time_ms send_deadline;
    dmp_time_ms result_deadline;
    dmp_time_ms correlation_deadline;
    dmp_time_ms tombstone_deadline;
    uint64_t sender_gen;
    uint64_t correlation_gen = 0U;
    uint32_t seq = 0U;
    int sender_index;
    int correlation_index = -1;
    dmp_status status;
    if (!ready(engine) || out == NULL || !bytes_ok(payload) || !bytes_ok(token) ||
        (kind != KIND_REQ && kind != KIND_DATA) ||
        (message_type != DMP_TYPE_REQ && message_type != DMP_TYPE_DATA &&
         message_type != DMP_TYPE_EVENT) ||
        ((kind == KIND_REQ) != (message_type == DMP_TYPE_REQ))) {
        return DMP_INVALID_ARGUMENT;
    }
    if (!service_allowed(&engine->profile, service_id) || jitter_ms > engine->profile.jitter_ms ||
        payload.size > engine->profile.message_bytes ||
        (token.size != 0U && token.size != 16U) ||
        (service_requires_freshness(&engine->profile, service_id) && token.size != 16U) ||
        (token.size != 0U && !service_requires_freshness(&engine->profile, service_id)) ||
        (service_id == 0U && token.size != 0U)) {
        return DMP_INVALID_ARGUMENT;
    }
    slot = bound(engine);
    if (slot == NULL) {
        return DMP_STALE_HANDLE;
    }
    if (operations_used(engine, service_id) >= engine->profile.operations_per_service ||
        queued_application(engine) >= engine->profile.application_queue_slots) {
        return DMP_BUSY;
    }
    sender_index = find_unused_sender(engine);
    if (kind == KIND_REQ) {
        correlation_index = find_unused_correlation(engine);
    }
    if (sender_index < 0 || (kind == KIND_REQ && correlation_index < 0)) {
        return DMP_QUOTA_EXHAUSTED;
    }
    status = dmp_deadline_after(now, engine->profile.queue_ms, &queue_deadline);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_deadline_after(now, engine->profile.send_horizon_ms, &send_deadline);
    if (status != DMP_OK) {
        return status;
    }
    status = dmp_deadline_after(now, engine->profile.result_deadline_ms, &result_deadline);
    if (status != DMP_OK) {
        return status;
    }
    if (kind == KIND_REQ) {
        status = dmp_deadline_after(now, engine->profile.correlation_ms, &correlation_deadline);
        if (status != DMP_OK) {
            return status;
        }
        status = dmp_deadline_after(now, engine->profile.tombstone_ms, &tombstone_deadline);
        if (status != DMP_OK) {
            return status;
        }
    } else {
        correlation_deadline = 0U;
        tombstone_deadline = result_deadline;
    }
    sender = &engine->storage.senders[sender_index];
    status = dmp_generation_next(sender->generation, &sender_gen);
    if (status != DMP_OK) {
        return status;
    }
    if (kind == KIND_REQ) {
        correlation = &engine->storage.correlations[correlation_index];
        status = dmp_generation_next(correlation->generation, &correlation_gen);
        if (status != DMP_OK) {
            return status;
        }
    }
    status = dmp_identity_next_seq(engine->storage.identity, engine->storage.context, &seq);
    if (status != DMP_OK) {
        return status;
    }
    memset(sender, 0, sizeof *sender);
    if (correlation != NULL) {
        memset(correlation, 0, sizeof *correlation);
        correlation->generation = correlation_gen;
    }
    sender->generation = sender_gen;
    if (payload.size != 0U) {
        memcpy(sender_bytes(engine, (size_t)sender_index), payload.data, payload.size);
    }
    if (token.size != 0U) {
        memcpy(sender->freshness_token, token.data, sizeof sender->freshness_token);
        sender->freshness_live = 1U;
    }
    sender->live = 1U;
    sender->phase = DMP_REL_PHASE_QUEUED;
    sender->kind = kind;
    sender->message_type = message_type;
    sender->service_id = service_id;
    sender->own.origin = slot->local;
    sender->own.seq = seq;
    sender->queue_deadline = queue_deadline;
    sender->send_deadline = send_deadline;
    sender->result_deadline = result_deadline;
    sender->retain_deadline = tombstone_deadline;
    sender->next_attempt = now;
    sender->jitter_ms = jitter_ms;
    sender->payload_len = (uint32_t)payload.size;
    status = arm_saved_fragments(engine, sender, payload.size);
    if (status != DMP_OK) {
        /* Nothing was submitted. Report the request's own key, then free it. */
        sender->phase = DMP_REL_PHASE_TERMINAL;
        settle_sender(engine, sender);
        return status;
    }
    if (correlation != NULL) {
        sender->related_slot = (uint32_t)correlation_index;
        sender->related_generation = correlation_gen;
        correlation->live = 1U;
        correlation->request.slot = (uint32_t)sender_index;
        correlation->request.generation = sender_gen;
        correlation->request_key = sender->own;
        correlation->service_id = service_id;
        correlation->correlation_deadline = correlation_deadline;
        correlation->tombstone_deadline = tombstone_deadline;
    }
    out->slot = (uint32_t)sender_index;
    out->generation = sender_gen;
    return DMP_OK;
}

dmp_status dmp_reliability_submit_req(dmp_reliability *engine, uint32_t service_id,
                                      dmp_bytes payload, dmp_time_ms now, uint32_t jitter_ms,
                                      dmp_reliability_handle *out)
{
    dmp_bytes empty = {NULL, 0U};
    return submit_outbound(engine, service_id, payload, empty, now, jitter_ms, KIND_REQ,
                           DMP_TYPE_REQ, out);
}

dmp_status dmp_reliability_submit_req_fresh(dmp_reliability *engine, uint32_t service_id,
                                            dmp_bytes payload, dmp_bytes token,
                                            dmp_time_ms now, uint32_t jitter_ms,
                                            dmp_reliability_handle *out)
{
    return submit_outbound(engine, service_id, payload, token, now, jitter_ms, KIND_REQ,
                           DMP_TYPE_REQ, out);
}

dmp_status dmp_reliability_submit_data(dmp_reliability *engine, uint32_t service_id,
                                       dmp_bytes payload, dmp_time_ms now,
                                       dmp_reliability_handle *out)
{
    dmp_bytes empty = {NULL, 0U};
    return submit_outbound(engine, service_id, payload, empty, now, 0U, KIND_DATA,
                           DMP_TYPE_DATA, out);
}

dmp_status dmp_reliability_submit_data_fresh(dmp_reliability *engine, uint32_t service_id,
                                             dmp_bytes payload, dmp_bytes token,
                                             dmp_time_ms now,
                                             dmp_reliability_handle *out)
{
    return submit_outbound(engine, service_id, payload, token, now, 0U, KIND_DATA,
                           DMP_TYPE_DATA, out);
}

dmp_status dmp_reliability_submit_event(dmp_reliability *engine, uint32_t service_id,
                                        dmp_bytes payload, dmp_time_ms now,
                                        dmp_reliability_handle *out)
{
    dmp_bytes empty = {NULL, 0U};
    return submit_outbound(engine, service_id, payload, empty, now, 0U, KIND_DATA,
                           DMP_TYPE_EVENT, out);
}

dmp_status dmp_reliability_submit_event_fresh(dmp_reliability *engine, uint32_t service_id,
                                              dmp_bytes payload, dmp_bytes token,
                                              dmp_time_ms now,
                                              dmp_reliability_handle *out)
{
    return submit_outbound(engine, service_id, payload, token, now, 0U, KIND_DATA,
                           DMP_TYPE_EVENT, out);
}

dmp_status dmp_reliability_cancel(dmp_reliability *engine, dmp_reliability_handle handle,
                                  dmp_time_ms now)
{
    dmp_reliability_sender_slot *sender;
    (void)now;
    if (!ready(engine)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (handle.slot >= engine->storage.sender_capacity) {
        return DMP_STALE_HANDLE;
    }
    sender = &engine->storage.senders[handle.slot];
    if (sender->live == 0U || sender->generation != handle.generation || sender->kind != KIND_REQ) {
        return DMP_STALE_HANDLE;
    }
    if (sender->phase == DMP_REL_PHASE_TERMINAL) {
        return DMP_OK;
    }
    sender->phase = DMP_REL_PHASE_TERMINAL;
    if (sender->tx_live) {
        cancel_tx(engine, sender);
        consume(engine);
    } else {
        settle_sender(engine, sender);
    }
    return DMP_OK;
}

dmp_status dmp_reliability_poll(dmp_reliability *engine, dmp_time_ms now)
{
    dmp_status status = DMP_OK;
    size_t guard;
    size_t pass;
    if (!ready(engine)) {
        return DMP_INVALID_ARGUMENT;
    }
    guard = engine->storage.sender_capacity + engine->storage.adapter_capacity + 2U;
    for (pass = 0U; pass < guard; pass++) {
        consume(engine);
        expire(engine, now);
        send_due_receipts(engine, now, &status);
        send_ready(engine, now, &status);
    }
    return status;
}

dmp_status dmp_reliability_on_rx(dmp_reliability *engine, const dmp_reliability_input *input,
                                 dmp_time_ms now)
{
    const dmp_frame_view *frame;
    dmp_message_key source;
    uint32_t service = 0U;
    int ack_req;
    dmp_status status;
    if (!ready(engine) || input == NULL || input->frame == NULL || !bytes_ok(input->plaintext) ||
        !bytes_ok(input->immutable_metadata)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (input->immutable_metadata.size > DMP_RELIABILITY_METADATA_BYTES ||
        input->plaintext.size > engine->profile.message_bytes) {
        return DMP_LIMIT_EXHAUSTED;
    }
    frame = input->frame;
    ack_req = (frame->fields.options & DMP_OPT_ACK_REQ) != 0U;
    if (frame->fields.type == DMP_TYPE_FRAG_STATUS) {
        dmp_message_key reply;
        dmp_reliability_sender_slot *sender;
        uint32_t mask;
        uint32_t all;
        uint32_t service_id = 0U;
        if (input->plaintext.size != 4U || input->plaintext.data == NULL) {
            return DMP_OK;
        }
        status = resolve_service(engine, frame, input->service_id, &service_id);
        if (status != DMP_OK || !selective_service(&engine->profile, service_id)) {
            return status == DMP_OK ? DMP_OK : status;
        }
        status = dmp_identity_reply_to(frame, engine->storage.identity, engine->storage.context, now,
                                       &reply);
        if (status != DMP_OK) {
            return DMP_OK;
        }
        sender = NULL;
        {
            size_t i;
            for (i = 0U; i < engine->storage.sender_capacity; i++) {
                dmp_reliability_sender_slot *candidate = &engine->storage.senders[i];
                if (candidate->live != 0U &&
                    (candidate->kind == KIND_REQ || candidate->kind == KIND_RESULT) &&
                    candidate->service_id == service_id && key_eq(candidate->own, reply)) {
                    sender = candidate;
                    break;
                }
            }
        }
        if (sender == NULL || sender->frag_count < 2U || sender->phase == DMP_REL_PHASE_TERMINAL ||
            sender->result_seen || (sender->kind == KIND_REQ && sender->receipt_seen)) {
            return DMP_OK;
        }
        mask = (uint32_t)input->plaintext.data[0] |
               ((uint32_t)input->plaintext.data[1] << 8) |
               ((uint32_t)input->plaintext.data[2] << 16) |
               ((uint32_t)input->plaintext.data[3] << 24);
        all = fragment_mask(sender->frag_count);
        if (mask == 0U || mask == all || (mask & ~all) != 0U) {
            return DMP_OK;
        }
        if (sender->feedback_valid != 0U && frame->fields.seq <= sender->feedback_seq) {
            return DMP_OK;
        }
        sender->feedback_seq = frame->fields.seq;
        sender->feedback_valid = 1U;
        if (sender->burst_inflight != 0U) {
            sender->repair_mask = mask;
            return DMP_OK;
        }
        sender->repair_mask = 0U;
        sender->active_mask = mask;
        sender->probe_burst = 0U;
        sender->phase = DMP_REL_PHASE_QUEUED;
        sender->next_attempt = now;
        return DMP_OK;
    }
    if (frame->fields.type != DMP_TYPE_REQ && frame->fields.type != DMP_TYPE_RSP &&
        frame->fields.type != DMP_TYPE_ERR && frame->fields.type != DMP_TYPE_ACK &&
        frame->fields.type != DMP_TYPE_DATA && frame->fields.type != DMP_TYPE_EVENT) {
        return DMP_UNSUPPORTED;
    }
    if ((frame->fields.options & DMP_OPT_FRAG) != 0U ||
        ((frame->fields.type == DMP_TYPE_REQ || frame->fields.type == DMP_TYPE_DATA ||
          frame->fields.type == DMP_TYPE_EVENT) && !ack_req)) {
        return DMP_UNSUPPORTED;
    }
    expire(engine, now);
    status = dmp_identity_source_key(frame, engine->storage.identity, engine->storage.context, now,
                                     &source);
    if (status != DMP_OK) {
        return status;
    }
    status = resolve_service(engine, frame, input->service_id, &service);
    if (status != DMP_OK) {
        return status;
    }
    if (frame->fields.type == DMP_TYPE_REQ) {
        return handle_request(engine, frame, source, service, input->plaintext,
                              input->immutable_metadata, now);
    }
    if (frame->fields.type == DMP_TYPE_DATA || frame->fields.type == DMP_TYPE_EVENT) {
        return handle_data(engine, frame, source, service, input->plaintext,
                           input->immutable_metadata, now);
    }
    if (frame->fields.type == DMP_TYPE_ACK) {
        dmp_message_key reply;
        int status_present = 0;
        uint32_t wire_status = 0U;
        if (ack_req || frame->payload.size != 0U) {
            return DMP_MALFORMED;
        }
        status = read_wire_status(frame, &status_present, &wire_status);
        if (status != DMP_OK) {
            return status;
        }
        if (status_present) {
            return DMP_MALFORMED;
        }
        status = dmp_identity_reply_to(frame, engine->storage.identity, engine->storage.context,
                                       now, &reply);
        if (status != DMP_OK) {
            return status;
        }
        return handle_ack(engine, reply, service);
    }
    {
        dmp_message_key reply;
        int status_present = 0;
        uint32_t wire_status = 0U;
        status = read_wire_status(frame, &status_present, &wire_status);
        if (status != DMP_OK) {
            return status;
        }
        status = dmp_identity_reply_to(frame, engine->storage.identity, engine->storage.context,
                                       now, &reply);
        if (status != DMP_OK) {
            return status;
        }
        return handle_reply(engine, frame, reply, source, service, input->plaintext,
                            input->immutable_metadata, status_present, wire_status, now);
    }
}

dmp_status dmp_reliability_reject_req(dmp_reliability *engine, const dmp_reliability_input *input,
                                      uint32_t protocol_status, dmp_time_ms now)
{
    const dmp_frame_view *frame;
    dmp_message_key source;
    dmp_message_origin destination;
    uint32_t service = 0U;
    dmp_time_ms deadline;
    int history_index;
    int ack_req;
    dmp_status status;
    if (!ready(engine) || input == NULL || input->frame == NULL ||
        !bytes_ok(input->immutable_metadata)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (protocol_status < 1U || protocol_status > 7U) {
        return DMP_INVALID_ARGUMENT;
    }
    frame = input->frame;
    ack_req = (frame->fields.options & DMP_OPT_ACK_REQ) != 0U;
    if ((frame->fields.options & DMP_OPT_FRAG) != 0U ||
        frame->fields.type != DMP_TYPE_REQ || !ack_req) {
        return DMP_UNSUPPORTED;
    }
    if (input->immutable_metadata.size > DMP_RELIABILITY_METADATA_BYTES) {
        return DMP_LIMIT_EXHAUSTED;
    }
    status = dmp_identity_source_key(frame, engine->storage.identity, engine->storage.context, now,
                                     &source);
    if (status != DMP_OK) {
        return status;
    }
    status = resolve_service(engine, frame, input->service_id, &service);
    if (status != DMP_OK) {
        return status;
    }
    destination = frame_destination(engine, frame);
    history_index = find_history_key(engine, source);
    if (history_index >= 0) {
        dmp_reliability_history_slot *history = &engine->storage.history[history_index];
        if (!metadata_match(engine, history, frame, service, input->immutable_metadata,
                            destination)) {
            return DMP_MALFORMED;
        }
        return DMP_DUPLICATE;
    }
    status = dmp_deadline_after(now, engine->profile.rejection_ms, &deadline);
    if (status != DMP_OK) {
        return status;
    }
    history_index = find_unused_history(engine);
    if (history_index < 0 || find_unused_sender(engine) < 0) {
        return DMP_QUOTA_EXHAUSTED;
    }
    {
        dmp_reliability_history_slot *history = &engine->storage.history[history_index];
        uint64_t generation;
        status = dmp_generation_next(history->generation, &generation);
        if (status != DMP_OK) {
            return status;
        }
        memset(history, 0, sizeof *history);
        history->generation = generation;
        if (input->immutable_metadata.size != 0U) {
            memcpy(history_meta(engine, (size_t)history_index), input->immutable_metadata.data,
                   input->immutable_metadata.size);
        }
        history->live = 1U;
        history->decision = 1U;
        history->type = DMP_TYPE_REQ;
        history->ack_req = 1U;
        history->service_id = service;
        history->metadata_len = (uint16_t)input->immutable_metadata.size;
        history->source = source;
        history->destination = destination;
        history->wire_status = protocol_status;
        history->deadline = deadline;
        history->result_slot = UINT32_MAX;
        remember_descriptor(history, frame);
        status = queue_rejection_sender(engine, history_index, now);
        if (status != DMP_OK) {
            release_history(history);
            return status;
        }
    }
    return DMP_OK;
}

dmp_status dmp_reliability_complete_for_lifetime(
    dmp_reliability *engine, dmp_reliability_handle request, bool application_err,
    uint32_t wire_status, dmp_bytes payload, uint32_t result_lifetime_ms, dmp_time_ms now)
{
    dmp_reliability_history_slot *history;
    dmp_reliability_result_slot *result;
    dmp_reliability_sender_slot *sender;
    const dmp_identity_slot *slot;
    dmp_time_ms cache_deadline;
    uint32_t seq = 0U;
    int suppress;
    int defer_sequence;
    dmp_status status;
    if (!ready(engine) || !bytes_ok(payload) || result_lifetime_ms == 0U ||
        result_lifetime_ms > engine->profile.result_cache_ms) {
        return DMP_INVALID_ARGUMENT;
    }
    if (request.slot >= engine->storage.history_capacity) {
        return DMP_STALE_HANDLE;
    }
    history = &engine->storage.history[request.slot];
    if (history->live == 0U || history->generation != request.generation || history->decision != 0U) {
        return DMP_STALE_HANDLE;
    }
    if (history->result_slot >= engine->storage.result_capacity) {
        return DMP_STALE_HANDLE;
    }
    result = &engine->storage.results[history->result_slot];
    if (result->live == 0U || result->generation != history->result_generation) {
        return DMP_STALE_HANDLE;
    }
    if (result->deadline != 0U) {
        return DMP_DUPLICATE;
    }
    sender = sender_of_result(engine, result);
    if (sender == NULL || sender->kind != KIND_RESULT) {
        return DMP_STALE_HANDLE;
    }
    if (application_err) {
        if (wire_status < 64U) {
            return DMP_INVALID_ARGUMENT;
        }
    } else if (wire_status >= 1U && wire_status <= 63U) {
        return DMP_INVALID_ARGUMENT;
    }
    if (payload.size > engine->profile.message_bytes) {
        return DMP_INVALID_ARGUMENT;
    }
    slot = bound(engine);
    if (slot == NULL) {
        return DMP_STALE_HANDLE;
    }
    status = dmp_deadline_after(now, result_lifetime_ms, &cache_deadline);
    if (status != DMP_OK) {
        return status;
    }
    suppress = history->receipt_count == 0U && !sender->receipt_seen &&
               !dmp_deadline_reached(now, sender->next_attempt);
    defer_sequence = history->receipt_count == 0U && !sender->receipt_seen && !suppress &&
                     history->receipt_count < engine->profile.receipt_limit;
    if (!defer_sequence) {
        status = dmp_identity_next_seq(engine->storage.identity, engine->storage.context, &seq);
        if (status != DMP_OK) {
            return status;
        }
    }
    if (payload.size != 0U) {
        memcpy(result_bytes(engine, history->result_slot), payload.data, payload.size);
    }
    result->application_err = application_err ? 1U : 0U;
    result->wire_status = wire_status;
    result->payload_len = (uint32_t)payload.size;
    if (defer_sequence) {
        memset(&result->result, 0, sizeof result->result);
        result->reserved = 0U;
    } else {
        result->result.origin = slot->local;
        result->result.seq = seq;
        result->reserved = 1U;
    }
    sender->own = result->result;
    sender->payload_len = result->payload_len;
    status = arm_saved_fragments(engine, sender, payload.size);
    if (status != DMP_OK) {
        /* No result frame. Drop the sender; the deadline stays unset so this
         * is not reported as a duplicate completion. */
        sender->phase = DMP_REL_PHASE_TERMINAL;
        release_sender(sender);
        return status;
    }
    result->deadline = cache_deadline;
    sender->repair_mask = 0U;
    sender->feedback_seq = 0U;
    sender->packet_count = 0U;
    sender->probe_count = 0U;
    sender->sending_index = 0U;
    sender->feedback_valid = 0U;
    sender->burst_inflight = 0U;
    sender->burst_counted = 0U;
    sender->probe_burst = 0U;
    sender->phase = DMP_REL_PHASE_QUEUED;
    sender->next_attempt = now;
    sender->send_deadline = cache_deadline;
    sender->queue_deadline = cache_deadline;
    sender->retain_deadline = cache_deadline;
    sender->result_deadline = cache_deadline;
    sender->jitter_ms = 0U;
    sender->attempts = 0U;
    sender->possibly_sent = 0U;
    if (suppress) {
        sender->receipt_seen = true;
    }
    return DMP_OK;
}

dmp_status dmp_reliability_complete(dmp_reliability *engine, dmp_reliability_handle request,
                                    bool application_err, uint32_t wire_status, dmp_bytes payload,
                                    dmp_time_ms now)
{
    if (!ready(engine)) {
        return DMP_INVALID_ARGUMENT;
    }
    return dmp_reliability_complete_for_lifetime(
        engine, request, application_err, wire_status, payload,
        engine->profile.result_cache_ms, now);
}
