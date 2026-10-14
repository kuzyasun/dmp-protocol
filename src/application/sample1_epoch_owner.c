#include "sample1_epoch_owner.h"

#include <string.h>

static void store_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8U);
    out[2] = (uint8_t)(value >> 16U);
    out[3] = (uint8_t)(value >> 24U);
}

static void store_u64_le(uint8_t *out, uint64_t value)
{
    store_u32_le(out, (uint32_t)value);
    store_u32_le(out + 4U, (uint32_t)(value >> 32U));
}

static dmp_sample1_owner_result enter_owner(dmp_sample1_epoch_owner *owner)
{
    if (owner == NULL || !owner->initialized || owner->ports.try_enter == NULL ||
        owner->ports.leave == NULL) {
        return DMP_SAMPLE1_OWNER_INVALID;
    }
    return owner->ports.try_enter(owner->ports.user) ? DMP_SAMPLE1_OWNER_OK
                                                     : DMP_SAMPLE1_OWNER_BUSY;
}

static void stop_owner(dmp_sample1_epoch_owner *owner)
{
    owner->stopped = true;
    owner->active = false;
    owner->epoch = 0U;
    owner->sample_index = 0U;
    owner->sample_value = 0U;
    owner->have_sample = false;
    owner->transition_state = DMP_SAMPLE1_TRANSITION_IDLE;
    owner->transition_has_previous = false;
    owner->transition_previous_epoch = 0U;
    owner->transition_reserved_epoch = 0U;
}

static dmp_sample1_owner_result begin_epoch_locked(dmp_sample1_epoch_owner *owner)
{
    dmp_sample1_port_result port_result;

    if (owner->stopped) {
        return DMP_SAMPLE1_OWNER_STOPPED;
    }

    if (owner->transition_state == DMP_SAMPLE1_TRANSITION_IDLE) {
        bool has_previous = false;
        bool was_active = owner->active;
        uint64_t previous_epoch = 0U;
        uint64_t current_epoch = owner->epoch;
        uint64_t reserved_epoch = 0U;

        port_result = owner->ports.reserve_next(owner->ports.user, owner->principal,
                                                 &has_previous, &previous_epoch,
                                                 &reserved_epoch);
        if (port_result == DMP_SAMPLE1_PORT_BUSY) {
            return DMP_SAMPLE1_OWNER_BUSY;
        }
        if (port_result != DMP_SAMPLE1_PORT_ACCEPTED || reserved_epoch == 0U ||
            (has_previous && previous_epoch == 0U) ||
            (!has_previous && previous_epoch != 0U) ||
            (was_active && (!has_previous || previous_epoch != current_epoch)) ||
            (has_previous && reserved_epoch <= previous_epoch)) {
            stop_owner(owner);
            return DMP_SAMPLE1_OWNER_STOPPED;
        }

        owner->transition_has_previous = has_previous;
        owner->transition_previous_epoch = previous_epoch;
        owner->transition_reserved_epoch = reserved_epoch;
        owner->transition_state = DMP_SAMPLE1_TRANSITION_RESERVED;
        owner->active = false;
    }

    if (owner->transition_state == DMP_SAMPLE1_TRANSITION_RESERVED) {
        if (owner->transition_has_previous) {
            port_result = owner->ports.fence_epoch(
                owner->ports.user, owner->principal, owner->transition_previous_epoch);
            if (port_result == DMP_SAMPLE1_PORT_BUSY) {
                return DMP_SAMPLE1_OWNER_BUSY;
            }
            if (port_result != DMP_SAMPLE1_PORT_ACCEPTED) {
                stop_owner(owner);
                return DMP_SAMPLE1_OWNER_STOPPED;
            }
        }
        owner->transition_state = DMP_SAMPLE1_TRANSITION_FENCED;
    }

    if (owner->transition_state != DMP_SAMPLE1_TRANSITION_FENCED) {
        stop_owner(owner);
        return DMP_SAMPLE1_OWNER_STOPPED;
    }

    port_result = owner->ports.activate_epoch(owner->ports.user, owner->principal,
                                               owner->transition_reserved_epoch);
    if (port_result == DMP_SAMPLE1_PORT_BUSY) {
        return DMP_SAMPLE1_OWNER_BUSY;
    }
    if (port_result != DMP_SAMPLE1_PORT_ACCEPTED) {
        stop_owner(owner);
        return DMP_SAMPLE1_OWNER_STOPPED;
    }

    owner->epoch = owner->transition_reserved_epoch;
    owner->sample_index = 0U;
    owner->sample_value = 0U;
    owner->have_sample = false;
    owner->active = true;
    owner->transition_state = DMP_SAMPLE1_TRANSITION_IDLE;
    owner->transition_has_previous = false;
    owner->transition_previous_epoch = 0U;
    owner->transition_reserved_epoch = 0U;
    return DMP_SAMPLE1_OWNER_OK;
}

dmp_sample1_owner_result dmp_sample1_epoch_owner_init(
    dmp_sample1_epoch_owner *owner, dmp_sample1_principal principal,
    const dmp_sample1_epoch_owner_ports *ports)
{
    if (owner == NULL || ports == NULL || ports->try_enter == NULL ||
        ports->leave == NULL || ports->reserve_next == NULL ||
        ports->fence_epoch == NULL || ports->activate_epoch == NULL ||
        ports->activate_association == NULL || ports->queue_read_result == NULL ||
        ports->publish_telem == NULL) {
        return DMP_SAMPLE1_OWNER_INVALID;
    }

    (void)memset(owner, 0, sizeof(*owner));
    owner->ports = *ports;
    owner->principal = principal;
    owner->initialized = true;
    return DMP_SAMPLE1_OWNER_OK;
}

dmp_sample1_owner_result dmp_sample1_epoch_owner_begin_epoch(
    dmp_sample1_epoch_owner *owner, dmp_time_ms now)
{
    dmp_sample1_owner_result result = enter_owner(owner);

    if (result != DMP_SAMPLE1_OWNER_OK) {
        return result;
    }
    if (owner->stopped) {
        owner->ports.leave(owner->ports.user);
        return DMP_SAMPLE1_OWNER_STOPPED;
    }
    owner->now = now;
    result = begin_epoch_locked(owner);
    owner->ports.leave(owner->ports.user);
    return result;
}

dmp_sample1_owner_result dmp_sample1_epoch_owner_activate_association(
    dmp_sample1_epoch_owner *owner, dmp_identity_handle association)
{
    dmp_sample1_owner_result result = enter_owner(owner);
    dmp_sample1_port_result port_result;

    if (result != DMP_SAMPLE1_OWNER_OK) {
        return result;
    }
    if (owner->stopped) {
        result = DMP_SAMPLE1_OWNER_STOPPED;
    } else if (!owner->active) {
        result = DMP_SAMPLE1_OWNER_NOT_READY;
    } else {
        port_result = owner->ports.activate_association(owner->ports.user,
                                                         owner->principal,
                                                         association,
                                                         owner->epoch);
        if (port_result == DMP_SAMPLE1_PORT_BUSY) {
            result = DMP_SAMPLE1_OWNER_BUSY;
        } else if (port_result != DMP_SAMPLE1_PORT_ACCEPTED) {
            stop_owner(owner);
            result = DMP_SAMPLE1_OWNER_STOPPED;
        }
    }
    owner->ports.leave(owner->ports.user);
    return result;
}

dmp_sample1_owner_result dmp_sample1_epoch_owner_accept_read(
    dmp_sample1_epoch_owner *owner, dmp_identity_handle association,
    dmp_reliability_handle request_handle, dmp_message_key request,
    dmp_time_ms now)
{
    dmp_sample1_owner_result result = enter_owner(owner);
    dmp_sample1_port_result port_result;
    uint8_t payload[DMP_SAMPLE1_READ_BYTES];
    uint32_t wire_status = DMP_SAMPLE1_NO_SAMPLE_STATUS;
    const uint8_t *payload_ptr = NULL;
    size_t payload_len = 0U;

    if (result != DMP_SAMPLE1_OWNER_OK) {
        return result;
    }
    if (owner->stopped) {
        result = DMP_SAMPLE1_OWNER_STOPPED;
    } else if (!owner->active) {
        result = DMP_SAMPLE1_OWNER_NOT_READY;
    } else {
        owner->now = now;
        if (owner->have_sample) {
            payload[0] = DMP_SAMPLE1_READ_OPCODE;
            store_u64_le(payload + 1U, owner->epoch);
            store_u32_le(payload + 9U, owner->sample_index);
            store_u32_le(payload + 13U, owner->sample_value);
            wire_status = 0U;
            payload_ptr = payload;
            payload_len = sizeof(payload);
        }
        port_result = owner->ports.queue_read_result(owner->ports.user,
                                                      owner->principal,
                                                      association, request_handle, request,
                                                      wire_status, payload_ptr,
                                                      payload_len);
        if (port_result == DMP_SAMPLE1_PORT_BUSY) {
            result = DMP_SAMPLE1_OWNER_BUSY;
        } else if (port_result == DMP_SAMPLE1_PORT_REJECTED) {
            result = DMP_SAMPLE1_OWNER_NOT_READY;
        } else if (port_result != DMP_SAMPLE1_PORT_ACCEPTED) {
            stop_owner(owner);
            result = DMP_SAMPLE1_OWNER_STOPPED;
        }
    }
    owner->ports.leave(owner->ports.user);
    return result;
}

dmp_sample1_owner_result dmp_sample1_epoch_owner_publish(
    dmp_sample1_epoch_owner *owner, uint32_t value, dmp_time_ms now)
{
    dmp_sample1_owner_result result = enter_owner(owner);
    dmp_sample1_port_result port_result;
    uint8_t payload[DMP_SAMPLE1_TELEM_BYTES];
    uint32_t next_index;

    if (result != DMP_SAMPLE1_OWNER_OK) {
        return result;
    }
    if (owner->stopped) {
        result = DMP_SAMPLE1_OWNER_STOPPED;
    } else {
        owner->now = now;
        if (!owner->active) {
            if (owner->transition_state == DMP_SAMPLE1_TRANSITION_IDLE) {
                result = DMP_SAMPLE1_OWNER_NOT_READY;
            } else {
                result = begin_epoch_locked(owner);
            }
        } else if (owner->sample_index == UINT32_MAX) {
            result = begin_epoch_locked(owner);
        }
        if (result == DMP_SAMPLE1_OWNER_OK && owner->active) {
            next_index = owner->sample_index + 1U;
            store_u64_le(payload, owner->epoch);
            store_u32_le(payload + 8U, next_index);
            store_u32_le(payload + 12U, value);
            port_result = owner->ports.publish_telem(owner->ports.user,
                                                      owner->principal,
                                                      owner->epoch, next_index,
                                                      payload);
            if (port_result == DMP_SAMPLE1_PORT_BUSY) {
                result = DMP_SAMPLE1_OWNER_BUSY;
            } else if (port_result != DMP_SAMPLE1_PORT_ACCEPTED) {
                stop_owner(owner);
                result = DMP_SAMPLE1_OWNER_STOPPED;
            } else {
                owner->sample_index = next_index;
                owner->sample_value = value;
                owner->have_sample = true;
            }
        }
    }
    owner->ports.leave(owner->ports.user);
    return result;
}

