#ifndef DMP_APPLICATION_SAMPLE1_EPOCH_OWNER_H
#define DMP_APPLICATION_SAMPLE1_EPOCH_OWNER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dmp/reliability.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    DMP_SAMPLE1_TELEM_BYTES = 16U,
    DMP_SAMPLE1_READ_BYTES = 17U,
    DMP_SAMPLE1_READ_OPCODE = 1U,
    DMP_SAMPLE1_NO_SAMPLE_STATUS = 64U
};

typedef struct {
    uint32_t namespace_id;
    uint32_t origin_id;
} dmp_sample1_principal;

typedef enum {
    DMP_SAMPLE1_PORT_ACCEPTED = 0,
    DMP_SAMPLE1_PORT_BUSY,
    DMP_SAMPLE1_PORT_FAILED,
    DMP_SAMPLE1_PORT_UNKNOWN,
    DMP_SAMPLE1_PORT_REJECTED
} dmp_sample1_port_result;

typedef enum {
    DMP_SAMPLE1_TRANSITION_IDLE = 0,
    DMP_SAMPLE1_TRANSITION_RESERVED,
    DMP_SAMPLE1_TRANSITION_FENCED
} dmp_sample1_transition_state;

typedef enum {
    DMP_SAMPLE1_OWNER_OK = 0,
    DMP_SAMPLE1_OWNER_BUSY,
    DMP_SAMPLE1_OWNER_NOT_READY,
    DMP_SAMPLE1_OWNER_STOPPED,
    DMP_SAMPLE1_OWNER_INVALID
} dmp_sample1_owner_result;

/* All callbacks run while the injected gate is held. They must be bounded,
 * synchronous admission/lifecycle operations and must not reenter this owner.
 * The gate's try_enter returns true only when acquired; false means BUSY and
 * causes no owner-side or port-side operation. */
typedef struct {
    void *user;
    bool (*try_enter)(void *user);
    void (*leave)(void *user);

    /* Atomically reserve and durably commit a nonzero epoch under the backing
     * store's rollback guarantees. Ordinary NVS cannot detect restoration of a
     * complete older flash image; use a separately protected monotonic counter
     * if that threat must be covered.
     * On ACCEPTED, set has_previous and previous_epoch to the prior durable
     * value (or false/0 for first provisioning), and reserved_epoch to the new
     * committed value. BUSY must have no durable side effect and leaves outputs
     * unchanged; the owner may retry. Crashes may skip a committed value. The
     * adapter must fail closed on inaccessible or corrupt durable state and
     * must not guess an epoch. FAILED and UNKNOWN are fail-closed outcomes. */
    dmp_sample1_port_result (*reserve_next)(void *user,
                                            dmp_sample1_principal principal,
                                            bool *has_previous,
                                            uint64_t *previous_epoch,
                                            uint64_t *reserved_epoch);

    /* Close/fence every association for this producer principal and old sample
     * epoch, including active and draining associations; discard its pending
     * SAMPLE-1 work (queued telemetry and READ results). BUSY means revocation
     * is in progress but an accepted transport send still awaits its terminal
     * callback; retry the fence without reserving another epoch. ACCEPTED
     * confirms the complete fence. FAILED/UNKNOWN poison the owner. */
    dmp_sample1_port_result (*fence_epoch)(void *user,
                                           dmp_sample1_principal principal,
                                           uint64_t old_epoch);

    /* Make the new epoch eligible for association binding. Called only after
     * the old-epoch fence has completed. */
    dmp_sample1_port_result (*activate_epoch)(void *user,
                                              dmp_sample1_principal principal,
                                              uint64_t new_epoch);

    /* Bind a generation-safe association handle to the owner's current epoch.
     * The port validates that the association is live and belongs to principal. */
    dmp_sample1_port_result (*activate_association)(void *user,
                                                    dmp_sample1_principal principal,
                                                    dmp_identity_handle association,
                                                    uint64_t sample_epoch);

    /* Queue the terminal READ result for an already accepted, correlated READ.
     * The complete DMP request key and association handle are provided so the
     * endpoint can retain its normal reliable result identity. For NO_SAMPLE,
     * wire_status is 64 and payload is NULL/empty. For a sample, status is zero
     * and payload is the exact 17-byte SAMPLE-1 READ result. */
    dmp_sample1_port_result (*queue_read_result)(void *user,
                                                 dmp_sample1_principal principal,
                                                 dmp_identity_handle association,
                                                 dmp_reliability_handle request_handle,
                                                 dmp_message_key request,
                                                 uint32_t wire_status,
                                                 const uint8_t *payload,
                                                 size_t payload_len);

    /* Admit one best-effort SAMPLE-1 telemetry item. ACCEPTED means the
     * endpoint has taken ownership under its bounded queue policy. */
    dmp_sample1_port_result (*publish_telem)(void *user,
                                             dmp_sample1_principal principal,
                                             uint64_t sample_epoch,
                                             uint32_t sample_index,
                                             const uint8_t payload[DMP_SAMPLE1_TELEM_BYTES]);
} dmp_sample1_epoch_owner_ports;

typedef struct {
    dmp_sample1_epoch_owner_ports ports;
    dmp_sample1_principal principal;
    dmp_time_ms now;
    uint64_t epoch;
    uint32_t sample_index;
    uint32_t sample_value;
    bool initialized;
    bool active;
    bool have_sample;
    bool stopped;
    dmp_sample1_transition_state transition_state;
    bool transition_has_previous;
    uint64_t transition_previous_epoch;
    uint64_t transition_reserved_epoch;
} dmp_sample1_epoch_owner;

/* Initialize caller-owned state and validate every required injected port. */
dmp_sample1_owner_result dmp_sample1_epoch_owner_init(
    dmp_sample1_epoch_owner *owner, dmp_sample1_principal principal,
    const dmp_sample1_epoch_owner_ports *ports);

/* Reserve a fresh durable epoch, fence the prior durable epoch (including
 * after process restart), then activate the new epoch. Any uncertain port
 * outcome or inconsistent durable record permanently stops this owner. */
dmp_sample1_owner_result dmp_sample1_epoch_owner_begin_epoch(
    dmp_sample1_epoch_owner *owner, dmp_time_ms now);

/* Bind one live generation-safe association to the active epoch. */
dmp_sample1_owner_result dmp_sample1_epoch_owner_activate_association(
    dmp_sample1_epoch_owner *owner, dmp_identity_handle association);

/* Linearize an already accepted READ and queue its snapshot result before
 * releasing the transition gate. The endpoint still owns request correlation
 * and authorization; this owner serializes that accepted result with rollover. */
dmp_sample1_owner_result dmp_sample1_epoch_owner_accept_read(
    dmp_sample1_epoch_owner *owner, dmp_identity_handle association,
    dmp_reliability_handle request_handle, dmp_message_key request,
    dmp_time_ms now);

/* Publish one value under the active epoch. Index exhaustion automatically
 * reserves/fences/activates a fresh epoch before publishing index 1. Any
 * non-accepted lifecycle or publication result permanently stops this owner. */
dmp_sample1_owner_result dmp_sample1_epoch_owner_publish(
    dmp_sample1_epoch_owner *owner, uint32_t value, dmp_time_ms now);

#ifdef __cplusplus
}
#endif

#endif
