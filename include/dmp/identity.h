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
    DMP_PROFILE_NODE_COUNT = 2,
    DMP_PROFILE_SERVICE_COUNT = 2
};

typedef enum {
    DMP_PROFILE_RECOVERY_RETRY_ALL = 0,
    DMP_PROFILE_RECOVERY_SELECTIVE32 = 1
} dmp_profile_recovery;

/* One layout. dmp_config is borrowed for the call. dmp_admitted_profile is the
 * caller-owned admitted copy. sha256 is opaque and is never hashed here.
 * Slot counts and message_bytes are inputs. Admission does not own TX buffers;
 * tx_borrow and synchronous_completion are flags only. */
typedef struct dmp_config {
    uint8_t sha256[DMP_PROFILE_SHA256_BYTES];
    uint32_t namespace_id;
    uint32_t node_id[DMP_PROFILE_NODE_COUNT];
    uint32_t default_service;
    uint32_t service_id[DMP_PROFILE_SERVICE_COUNT];
    dmp_profile_recovery recovery[DMP_PROFILE_SERVICE_COUNT];
    uint32_t peers;
    uint32_t operations_per_service;
    uint32_t assemblies_per_peer;
    uint32_t assembly_tombstones_per_peer;
    uint32_t sender_slots;
    uint32_t assembly_slots;
    uint32_t assembly_tombstone_slots;
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
} dmp_config;

typedef dmp_config dmp_admitted_profile;

/* Borrow in until return. Copy into caller-owned *out only after every check
 * passes. Failure leaves *out unchanged. No scratch and no allocation.
 * DMP_INVALID_ARGUMENT: null, in == out, a zero message/chunk/encoded_mtu/
 * fragments, fragments > 32, or overflow of a derived product.
 * DMP_UNSUPPORTED: default_service is 0 or outside service_id[], the two
 * service ids are equal, chunk_bytes >= message_bytes, peers == 0,
 * assembly_tombstones_per_peer < assemblies_per_peer,
 * assembly_tombstone_slots < peers * assembly_tombstones_per_peer, or
 * adapter_slots is not strictly greater than the reliability control reserve
 * min(control_slots, adapter_slots), including a zero reserve. That reserve
 * check matches dmp_reliability_init.
 * JSON syntax and digest mismatch are not admission results. */
dmp_status dmp_config_admit(const dmp_config *in, dmp_admitted_profile *out);

#ifdef __cplusplus
}
#endif
#endif
