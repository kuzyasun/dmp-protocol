#include "sample1_endpoint.h"

#include <string.h>

static dmp_sample1_port_result from_endpoint(dmp_status status)
{
    if (status == DMP_OK) {
        return DMP_SAMPLE1_PORT_ACCEPTED;
    }
    if (status == DMP_BUSY || status == DMP_QUOTA_EXHAUSTED) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    return DMP_SAMPLE1_PORT_UNKNOWN;
}

static bool try_enter(void *user)
{
    dmp_sample1_endpoint *sample = user;
    return sample->hooks.try_enter(sample->hooks.user);
}

static int handle_equal(dmp_peer_handle a, dmp_peer_handle b)
{
    return a.slot == b.slot && a.generation == b.generation;
}

static int identity_equal(dmp_identity_handle a, dmp_identity_handle b)
{
    return a.slot == b.slot && a.generation == b.generation;
}

static dmp_sample1_peer_epoch *peer_record(dmp_sample1_endpoint *sample,
                                           dmp_peer_handle peer)
{
    dmp_sample1_peer_epoch *record;
    if (sample == NULL || peer.generation == 0U || peer.slot >= sample->endpoint->profile.peers ||
        peer.slot >= DMP_PROFILE_MAX_PEERS) {
        return NULL;
    }
    record = &sample->peers[peer.slot];
    if (record->live != 0U && !handle_equal(record->peer, peer)) {
        return NULL;
    }
    return record;
}

static dmp_sample1_peer_epoch *association_record(dmp_sample1_endpoint *sample,
                                                   dmp_identity_handle association,
                                                   uint64_t sample_epoch)
{
    uint32_t i;
    for (i = 0U; i < sample->endpoint->profile.peers; i++) {
        dmp_sample1_peer_epoch *record = &sample->peers[i];
        if (record->live == 0U) {
            continue;
        }
        if (identity_equal(record->active_association, association) &&
            record->active_epoch == sample_epoch) {
            return record;
        }
        if (identity_equal(record->draining_association, association) &&
            record->draining_epoch == sample_epoch) {
            return record;
        }
    }
    return NULL;
}

static void leave(void *user)
{
    dmp_sample1_endpoint *sample = user;
    sample->hooks.leave(sample->hooks.user);
}

static dmp_sample1_port_result reserve_next(void *user,
                                            dmp_sample1_principal principal,
                                            bool *has_previous,
                                            uint64_t *previous_epoch,
                                            uint64_t *reserved_epoch)
{
    dmp_sample1_endpoint *sample = user;
    return sample->hooks.reserve_next(sample->hooks.user, principal, has_previous,
                                      previous_epoch, reserved_epoch);
}

static dmp_sample1_port_result fence_epoch(void *user,
                                          dmp_sample1_principal principal,
                                          uint64_t old_epoch)
{
    dmp_sample1_endpoint *sample = user;
    uint32_t i;
    if (principal.namespace_id != sample->endpoint->profile.namespace_id ||
        principal.origin_id != sample->endpoint->mem.context.local.origin_id || old_epoch == 0U) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    for (i = 0U; i < DMP_SAMPLE1_ENDPOINT_RESULT_SLOTS; i++) {
        if (sample->results[i].live != 0U && sample->results[i].sample_epoch == old_epoch) {
            (void)memset(&sample->results[i], 0, sizeof(sample->results[i]));
        }
    }
    for (i = 0U; i < sample->endpoint->profile.peers; i++) {
        dmp_sample1_peer_epoch *record = &sample->peers[i];
        dmp_peer_handle peer;
        dmp_status status;
        if (record->live == 0U ||
            (record->active_epoch != old_epoch && record->draining_epoch != old_epoch)) {
            continue;
        }
        peer = record->peer;
        status = dmp_endpoint_revoke_peer(sample->endpoint, peer, sample->owner.now);
        if (status == DMP_STALE_HANDLE) {
            (void)memset(record, 0, sizeof(*record));
            continue;
        }
        if (status != DMP_OK) {
            return from_endpoint(status);
        }
        status = dmp_endpoint_peer_fence_status(sample->endpoint, peer);
        if (status == DMP_BUSY) {
            return DMP_SAMPLE1_PORT_BUSY;
        }
        if (status == DMP_STALE_HANDLE) {
            (void)memset(record, 0, sizeof(*record));
            continue;
        }
        if (status != DMP_OK) {
            return from_endpoint(status);
        }
        (void)memset(record, 0, sizeof(*record));
    }
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static dmp_sample1_port_result activate_epoch(void *user,
                                             dmp_sample1_principal principal,
                                             uint64_t new_epoch)
{
    dmp_sample1_endpoint *sample = user;
    uint32_t i;
    if (principal.namespace_id != sample->endpoint->profile.namespace_id ||
        principal.origin_id != sample->endpoint->mem.context.local.origin_id || new_epoch == 0U) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    for (i = 0U; i < sample->endpoint->profile.peers; i++) {
        if (sample->peers[i].live != 0U) {
            return DMP_SAMPLE1_PORT_UNKNOWN;
        }
    }
    for (i = 0U; i < DMP_SAMPLE1_ENDPOINT_RESULT_SLOTS; i++) {
        if (sample->results[i].live != 0U) {
            return DMP_SAMPLE1_PORT_UNKNOWN;
        }
    }
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static dmp_sample1_port_result activate_association(void *user,
                                                    dmp_sample1_principal principal,
                                                    dmp_identity_handle association,
                                                    uint64_t sample_epoch)
{
    dmp_sample1_endpoint *sample = user;
    dmp_sample1_peer_epoch *record;
    if (principal.namespace_id != sample->endpoint->profile.namespace_id ||
        principal.origin_id != sample->endpoint->mem.context.local.origin_id ||
        sample_epoch == 0U) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    record = association_record(sample, association, sample_epoch);
    return record != NULL ? DMP_SAMPLE1_PORT_ACCEPTED : DMP_SAMPLE1_PORT_FAILED;
}

static dmp_sample1_port_result queue_read_result(void *user,
                                                dmp_sample1_principal principal,
                                                dmp_identity_handle association,
                                                dmp_reliability_handle request_handle,
                                                dmp_message_key request,
                                                uint32_t wire_status,
                                                const uint8_t *payload,
                                                size_t payload_len)
{
    dmp_sample1_endpoint *sample = user;
    dmp_sample1_peer_epoch *record;
    uint32_t i;

    if (principal.namespace_id != sample->endpoint->profile.namespace_id ||
        principal.origin_id != sample->endpoint->mem.context.local.origin_id ||
        association.generation == 0U || payload_len > DMP_SAMPLE1_READ_BYTES ||
        (payload_len != 0U && payload == NULL) ||
        request_handle.peer.slot >= sample->endpoint->profile.peers ||
        request_handle.peer.slot >= DMP_PROFILE_MAX_PEERS ||
        request_handle.peer.generation == 0U) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    record = peer_record(sample, request_handle.peer);
    if (record == NULL || record->live == 0U ||
        !handle_equal(record->peer, request_handle.peer) ||
        association_record(sample, association, sample->owner.epoch) != record ||
        dmp_endpoint_validate_association(sample->endpoint, association,
                                           sample->owner.principal.namespace_id,
                                           sample->owner.principal.origin_id) != DMP_OK) {
        return DMP_SAMPLE1_PORT_REJECTED;
    }
    for (i = 0U; i < DMP_SAMPLE1_ENDPOINT_RESULT_SLOTS; i++) {
        dmp_sample1_queued_result *queued = &sample->results[i];
        if (queued->live != 0U) {
            continue;
        }
        queued->request_handle = request_handle;
        queued->association = association;
        queued->request = request;
        queued->sample_epoch = sample->owner.epoch;
        queued->wire_status = wire_status;
        queued->payload_len = (uint8_t)payload_len;
        if (payload_len != 0U) {
            (void)memcpy(queued->payload, payload, payload_len);
        }
        queued->live = 1U;
        return DMP_SAMPLE1_PORT_ACCEPTED;
    }
    return DMP_SAMPLE1_PORT_FAILED;
}

static dmp_sample1_port_result publish_telem(void *user,
                                             dmp_sample1_principal principal,
                                             uint64_t sample_epoch,
                                             uint32_t sample_index,
                                             const uint8_t payload[DMP_SAMPLE1_TELEM_BYTES])
{
    dmp_sample1_endpoint *sample = user;
    uint32_t i;
    if (principal.namespace_id != sample->endpoint->profile.namespace_id ||
        principal.origin_id != sample->endpoint->mem.context.local.origin_id ||
        sample_epoch != sample->owner.epoch || payload == NULL) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    if (sample->hooks.publish_telem(sample->hooks.user, principal, sample_epoch,
                                    sample_index, payload) != DMP_SAMPLE1_PORT_ACCEPTED) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    for (i = 0U; i < sample->endpoint->profile.peers; i++) {
        const dmp_sample1_peer_epoch *record = &sample->peers[i];
        dmp_status status;
        dmp_bytes bytes;
        if (record->live == 0U || record->active_epoch != sample_epoch) {
            continue;
        }
        bytes.data = payload;
        bytes.size = DMP_SAMPLE1_TELEM_BYTES;
        status = dmp_endpoint_submit_telem_to(sample->endpoint, record->peer, 1U,
                                              bytes, sample->owner.now);
        if (status != DMP_OK) {
            return from_endpoint(status);
        }
    }
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

dmp_sample1_owner_result dmp_sample1_endpoint_init(
    dmp_sample1_endpoint *sample, dmp_endpoint *endpoint,
    dmp_sample1_principal principal, const dmp_sample1_endpoint_hooks *hooks)
{
    dmp_sample1_epoch_owner_ports ports;

    if (sample == NULL || endpoint == NULL || endpoint->initialized == 0U || hooks == NULL ||
        hooks->try_enter == NULL || hooks->leave == NULL || hooks->reserve_next == NULL ||
        hooks->publish_telem == NULL || principal.namespace_id != endpoint->profile.namespace_id ||
        principal.origin_id != endpoint->mem.context.local.origin_id) {
        return DMP_SAMPLE1_OWNER_INVALID;
    }

    (void)memset(sample, 0, sizeof(*sample));
    sample->endpoint = endpoint;
    sample->hooks = *hooks;
    (void)memset(&ports, 0, sizeof ports);
    ports.user = sample;
    ports.try_enter = try_enter;
    ports.leave = leave;
    ports.reserve_next = reserve_next;
    ports.fence_epoch = fence_epoch;
    ports.activate_epoch = activate_epoch;
    ports.activate_association = activate_association;
    ports.queue_read_result = queue_read_result;
    ports.publish_telem = publish_telem;
    if (dmp_sample1_epoch_owner_init(&sample->owner, principal, &ports) !=
        DMP_SAMPLE1_OWNER_OK) {
        return DMP_SAMPLE1_OWNER_INVALID;
    }
    sample->initialized = 1U;
    return DMP_SAMPLE1_OWNER_OK;
}

dmp_sample1_owner_result dmp_sample1_endpoint_begin_epoch(dmp_sample1_endpoint *sample,
                                                          dmp_time_ms now)
{
    if (sample == NULL || sample->initialized == 0U) {
        return DMP_SAMPLE1_OWNER_INVALID;
    }
    return dmp_sample1_epoch_owner_begin_epoch(&sample->owner, now);
}

dmp_sample1_owner_result dmp_sample1_endpoint_activate_peer(
    dmp_sample1_endpoint *sample, dmp_peer_handle peer)
{
    dmp_identity_handle association;
    dmp_sample1_peer_epoch *record;
    dmp_sample1_peer_epoch previous;
    dmp_status status;
    if (sample == NULL || sample->initialized == 0U) {
        return DMP_SAMPLE1_OWNER_INVALID;
    }
    if (!sample->owner.active || sample->owner.stopped) {
        return sample->owner.stopped ? DMP_SAMPLE1_OWNER_STOPPED : DMP_SAMPLE1_OWNER_NOT_READY;
    }
    record = peer_record(sample, peer);
    if (record == NULL) {
        return DMP_SAMPLE1_OWNER_NOT_READY;
    }
    status = dmp_endpoint_peer_association(sample->endpoint, peer, &association);
    if (status != DMP_OK) {
        return DMP_SAMPLE1_OWNER_NOT_READY;
    }
    if (dmp_endpoint_validate_association(sample->endpoint, association,
                                          sample->owner.principal.namespace_id,
                                          sample->owner.principal.origin_id) != DMP_OK) {
        return DMP_SAMPLE1_OWNER_NOT_READY;
    }
    previous = *record;
    if (record->live != 0U && handle_equal(record->peer, peer) &&
        !identity_equal(record->active_association, association)) {
        if (record->draining_epoch != 0U) {
            status = dmp_endpoint_validate_association(sample->endpoint,
                                                       record->draining_association,
                                                       sample->owner.principal.namespace_id,
                                                       sample->owner.principal.origin_id);
            if (status == DMP_OK) {
                return DMP_SAMPLE1_OWNER_BUSY;
            }
        }
        record->draining_association = record->active_association;
        record->draining_epoch = record->active_epoch;
    }
    record->peer = peer;
    record->active_association = association;
    record->active_epoch = sample->owner.epoch;
    record->live = 1U;
    {
        dmp_sample1_owner_result result =
            dmp_sample1_epoch_owner_activate_association(&sample->owner, association);
        if (result != DMP_SAMPLE1_OWNER_OK) {
            *record = previous;
        }
        return result;
    }
}

dmp_sample1_owner_result dmp_sample1_endpoint_handle_notice(
    dmp_sample1_endpoint *sample, const dmp_endpoint_notice *notice, dmp_time_ms now)
{
    if (sample == NULL || sample->initialized == 0U || notice == NULL) {
        return DMP_SAMPLE1_OWNER_INVALID;
    }
    if (notice->event != DMP_ENDPOINT_REQUEST || notice->service_id != 1U ||
        notice->payload.data == NULL || notice->payload.size != 1U ||
        notice->payload.data[0] != DMP_SAMPLE1_READ_OPCODE ||
        notice->association.generation == 0U ||
        notice->request.peer.slot != notice->peer.slot ||
        notice->request.peer.generation != notice->peer.generation) {
        return DMP_SAMPLE1_OWNER_NOT_READY;
    }
    return dmp_sample1_epoch_owner_accept_read(&sample->owner, notice->association,
                                               notice->request, notice->source, now);
}

dmp_sample1_owner_result dmp_sample1_endpoint_flush(dmp_sample1_endpoint *sample,
                                                    dmp_time_ms now)
{
    uint32_t i;
    dmp_sample1_owner_result result = DMP_SAMPLE1_OWNER_OK;
    if (sample == NULL || sample->initialized == 0U) {
        return DMP_SAMPLE1_OWNER_INVALID;
    }
    if (!sample->hooks.try_enter(sample->hooks.user)) {
        return DMP_SAMPLE1_OWNER_BUSY;
    }
    for (i = 0U; i < DMP_SAMPLE1_ENDPOINT_RESULT_SLOTS; i++) {
        dmp_sample1_queued_result *queued = &sample->results[i];
        dmp_sample1_peer_epoch *record;
        dmp_bytes payload;
        dmp_status status;
        if (queued->live == 0U) {
            continue;
        }
        record = peer_record(sample, queued->request_handle.peer);
        if (queued->sample_epoch != sample->owner.epoch || record == NULL ||
            record->live == 0U ||
            (!identity_equal(record->active_association, queued->association) &&
             !identity_equal(record->draining_association, queued->association))) {
            (void)memset(queued, 0, sizeof(*queued));
            result = DMP_SAMPLE1_OWNER_NOT_READY;
            continue;
        }
        status = dmp_endpoint_validate_association(sample->endpoint, queued->association,
                                                   sample->owner.principal.namespace_id,
                                                   sample->owner.principal.origin_id);
        if (status != DMP_OK) {
            (void)memset(queued, 0, sizeof(*queued));
            result = DMP_SAMPLE1_OWNER_NOT_READY;
            continue;
        }
        payload.data = queued->payload_len != 0U ? queued->payload : NULL;
        payload.size = queued->payload_len;
        status = dmp_endpoint_complete(sample->endpoint, queued->request_handle,
                                       queued->wire_status >= 64U, queued->wire_status,
                                       payload, now);
        if (status == DMP_OK) {
            (void)memset(queued, 0, sizeof(*queued));
        } else if (status == DMP_BUSY || status == DMP_QUOTA_EXHAUSTED) {
            result = DMP_SAMPLE1_OWNER_BUSY;
            break;
        } else {
            (void)memset(queued, 0, sizeof(*queued));
            result = DMP_SAMPLE1_OWNER_NOT_READY;
        }
    }
    sample->hooks.leave(sample->hooks.user);
    return result;
}

dmp_sample1_owner_result dmp_sample1_endpoint_publish(
    dmp_sample1_endpoint *sample, uint32_t value, dmp_time_ms now)
{
    if (sample == NULL || sample->initialized == 0U) {
        return DMP_SAMPLE1_OWNER_INVALID;
    }
    return dmp_sample1_epoch_owner_publish(&sample->owner, value, now);
}
