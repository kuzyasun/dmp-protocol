#ifndef DMP_IDENTITY_H
#define DMP_IDENTITY_H

#include "dmp/base.h"
#include "dmp/core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Logical identity is the complete protocol key; SEQ alone is never global. */
typedef struct {
    uint32_t namespace_id;
    uint32_t origin_id;
    uint64_t epoch;
} dmp_message_origin;

typedef struct {
    dmp_message_origin origin;
    uint32_t seq;
} dmp_message_key;

typedef struct {
    uint32_t slot;
    uint64_t generation;
} dmp_identity_handle;

typedef enum {
    DMP_IDENTITY_SLOT_UNUSED = 0,
    DMP_IDENTITY_SLOT_ACTIVE,
    DMP_IDENTITY_SLOT_DRAINING
} dmp_identity_slot_state;

/* Caller-owned fixed storage. Do not edit fields after table initialization.
 * Retained records/callbacks pin a draining slot until released. The generation
 * survives retirement and increases before reuse; zero and wrap are forbidden. */
typedef struct {
    dmp_message_origin local;
    dmp_message_origin peer;
    dmp_time_ms not_after;
    uint64_t generation;
    uint32_t next_seq;
    uint32_t retained;
    uint8_t security;
    uint8_t state;
    bool seq_exhausted;
} dmp_identity_slot;

typedef struct {
    dmp_identity_slot *slots;
    size_t capacity;
} dmp_identity_table;

typedef struct {
    dmp_message_origin local;
    dmp_message_origin peer;
    uint8_t security; /* 0 for unprotected; 1 for an authenticated SEC-1 context. */
} dmp_identity_context_config;

dmp_status dmp_identity_table_init(dmp_identity_table *table,
                                   dmp_identity_slot *slots, size_t capacity);
dmp_status dmp_identity_context_open(dmp_identity_table *table,
                                     const dmp_identity_context_config *config,
                                     dmp_identity_handle *out);
dmp_status dmp_identity_context_retain(dmp_identity_table *table,
                                       dmp_identity_handle handle);
dmp_status dmp_identity_context_release(dmp_identity_table *table,
                                        dmp_identity_handle handle);
dmp_status dmp_identity_context_begin_drain(dmp_identity_table *table,
                                            dmp_identity_handle handle,
                                            dmp_time_ms not_after);
/* Retire only after the absolute deadline and after every retained record/callback
 * has settled. Failure leaves the slot and output unchanged. */
dmp_status dmp_identity_context_retire(dmp_identity_table *table,
                                       dmp_identity_handle handle,
                                       dmp_time_ms now);

/* Sequence allocation starts at zero and never wraps. UINT32_MAX may be issued
 * once; later calls fail with DMP_LIMIT_EXHAUSTED until a new epoch/context. */
dmp_status dmp_identity_next_seq(dmp_identity_table *table,
                                 dmp_identity_handle handle, uint32_t *out);

/* Resolve a structural frame only with its bound association/profile context.
 * SECURITY=1 callers must invoke this after authentication and context checks;
 * this module performs identity resolution, not cryptographic verification.
 * Source identity uses the peer direction. REPLY_TO uses the local sending
 * direction for compact SEC-1 references and the full on-wire key for SECURITY=0.
 * Both operations enforce slot generation and the original association deadline. */
dmp_status dmp_identity_source_key(const dmp_frame_view *frame,
                                   const dmp_identity_table *table,
                                   dmp_identity_handle handle,
                                   dmp_time_ms now, dmp_message_key *out);
dmp_status dmp_identity_reply_to(const dmp_frame_view *frame,
                                 const dmp_identity_table *table,
                                 dmp_identity_handle handle,
                                 dmp_time_ms now, dmp_message_key *out);

enum {
    DMP_PROFILE_SHA256_BYTES = 32,
    DMP_PROFILE_MAX_BYTES = 262144,
    DMP_PROFILE_ADMIT_SCRATCH_BYTES = 419936,
    DMP_PROFILE_NODE_COUNT = 2,
    DMP_PROFILE_SERVICE_COUNT = 2
};

typedef dmp_status (*dmp_profile_sha256_fn)(void *context, dmp_bytes input,
                                           uint8_t output[DMP_PROFILE_SHA256_BYTES]);

typedef enum {
    DMP_PROFILE_RECOVERY_RETRY_ALL = 0,
    DMP_PROFILE_RECOVERY_SELECTIVE32 = 1
} dmp_profile_recovery;

/* The admitted view is copied from validated manifest bytes. It contains only
 * identity, operation/reassembly bounds and deadlines consumed by P10/P11; all
 * other manifest fields are still validated before admission. The sender,
 * assembly, result, history, correlation and adapter slot counts come from the
 * endpoint resource row. control_slots and application_queue_slots remain the
 * operational limits; admission verifies the endpoint charges fund those
 * limits. */
typedef struct {
    uint8_t sha256[DMP_PROFILE_SHA256_BYTES];
    uint32_t namespace_id;
    uint32_t node_id[DMP_PROFILE_NODE_COUNT];
    uint32_t default_service;
    uint32_t service_id[DMP_PROFILE_SERVICE_COUNT];
    dmp_profile_recovery recovery[DMP_PROFILE_SERVICE_COUNT];
    uint32_t peers;
    uint32_t operations_per_service;
    uint32_t assemblies_per_peer;
    uint32_t sender_slots;
    uint32_t assembly_slots;
    uint32_t result_slots;
    uint32_t history_slots;
    uint32_t correlation_slots;
    uint32_t adapter_slots;
    uint32_t application_queue_slots;
    uint32_t control_slots;
    uint32_t message_bytes;
    uint32_t fragments;
    uint32_t chunk_bytes;
    uint32_t encoded_mtu;
    uint32_t forward_mtu;
    uint32_t return_mtu;
    uint32_t queue_ms;
    uint32_t response_timeout_ms;
    uint32_t jitter_ms;
    uint32_t send_horizon_ms;
    uint32_t max_bursts;
    uint32_t receipt_delay_ms;
    uint32_t receipt_limit;
    uint32_t dedup_ms;
    uint32_t rejection_ms;
    uint32_t result_cache_ms;
    uint32_t result_deadline_ms;
    uint32_t correlation_ms;
    uint32_t tombstone_ms;
    uint32_t late_result_ms;
    uint32_t collect_ms;
    uint32_t assembly_ms;
    bool tx_borrow;
    bool synchronous_completion;
} dmp_admitted_profile;

typedef struct {
    char code[32];
    char path[192];
} dmp_profile_failure;

/* Validate exact UTF-8 manifest bytes with the complete P02 field and
 * cross-field contract before any traffic can start. scratch is caller-owned
 * and must be at least DMP_PROFILE_ADMIT_SCRATCH_BYTES; neither raw nor scratch
 * is retained. sha256 is mandatory and hashes the unmodified input bytes. The
 * optional expected digest is compared only after the profile itself validates.
 * On failure, *out is unchanged. Profile contract errors publish a stable code
 * and JSON path through failure; malformed bytes return DMP_MALFORMED,
 * unsupported profiles return DMP_UNSUPPORTED, and digest mismatch returns
 * DMP_INTEGRITY_FAILURE. */
dmp_status dmp_profile_admit(dmp_bytes raw,
                              const uint8_t expected_sha256[DMP_PROFILE_SHA256_BYTES],
                              dmp_profile_sha256_fn sha256, void *sha256_context,
                              dmp_buffer scratch, dmp_admitted_profile *out,
                              dmp_profile_failure *failure);

#ifdef __cplusplus
}
#endif
#endif
