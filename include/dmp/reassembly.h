#ifndef DMP_REASSEMBLY_H
#define DMP_REASSEMBLY_H

#include "dmp/identity.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { DMP_REASSEMBLY_METADATA_BYTES = DMP_MAX_HEADER_BYTES };

typedef struct {
    uint32_t slot;
    uint64_t generation;
} dmp_reassembly_handle;

typedef enum {
    DMP_REASSEMBLY_TOMBSTONE_UNUSED = 0,
    DMP_REASSEMBLY_TOMBSTONE_RESERVED,
    DMP_REASSEMBLY_TOMBSTONE_EXPIRED
} dmp_reassembly_tombstone_state;

/* Caller-owned bounded state. Do not edit while the engine is initialized. */
typedef struct {
    uint64_t generation;
    dmp_message_key source;
    dmp_identity_handle context;
    dmp_header_fields fields;
    dmp_time_ms deadline;
    uint32_t service_id;
    uint32_t chunk_size;
    uint32_t total_size;
    uint32_t received_bitmap;
    uint32_t tombstone_slot;
    uint16_t metadata_len;
    uint8_t live;
    uint8_t complete;
} dmp_reassembly_slot;

/* Tombstones keep only identity/context keys; they never retain payload or pin
 * an identity-table slot. 48 bytes are reserved by the profile contract. */
typedef struct {
    dmp_message_key source;
    dmp_identity_handle context;
    uint8_t state; /* dmp_reassembly_tombstone_state */
    uint8_t reserved[7];
} dmp_reassembly_tombstone;

typedef struct {
    const dmp_frame_view *frame;
    dmp_identity_handle context;
    uint32_t service_id;
    dmp_bytes plaintext;
    /* Canonical immutable TLVs in wire order, with the per-frame SECURITY TLV
     * omitted. Preserve identity, REPLY_TO, service and unknown safe TLVs. */
    dmp_bytes immutable_metadata;
} dmp_reassembly_input;

typedef struct {
    dmp_message_key source;
    dmp_identity_handle context;
    uint32_t service_id;
    /* FRAG is cleared; fragment fields, route TTL and per-frame PN are zero. */
    dmp_header_fields fields;
    dmp_bytes payload;
    dmp_bytes immutable_metadata;
} dmp_reassembly_message;

typedef struct {
    const dmp_admitted_profile *profile;
    dmp_identity_table *identity;
    dmp_reassembly_slot *assemblies;
    size_t assembly_capacity;
    dmp_reassembly_tombstone *tombstones;
    size_t tombstone_capacity;
    uint8_t *payloads;
    size_t payload_capacity;
    uint8_t *metadata;
    size_t metadata_capacity;
} dmp_reassembly_storage;

typedef struct {
    dmp_reassembly_storage storage;
    dmp_admitted_profile profile;
    uint64_t generation;
    uint8_t initialized;
    uint8_t reserved[7];
} dmp_reassembly;

/* Storage remains caller-owned for the engine lifetime. Init requires at least
 * the admitted active/tombstone counts, assembly_slots*message_bytes payload
 * bytes, and assembly_slots*DMP_REASSEMBLY_METADATA_BYTES metadata bytes. Any
 * extra storage does not raise admitted quotas. */
dmp_status dmp_reassembly_init(dmp_reassembly *engine,
                               const dmp_reassembly_storage *storage,
                               const dmp_admitted_profile *profile,
                               dmp_identity_table *identity);

/* Accept one already parsed and per-frame verified fragment. New/partial
 * acceptance returns INCOMPLETE; identical repeats return DUPLICATE; the
 * completing slice returns OK and publishes a generation-safe handle. Output
 * is unchanged for all other statuses. Calls are serialized by one owner. */
dmp_status dmp_reassembly_on_fragment(dmp_reassembly *engine,
                                      const dmp_reassembly_input *input,
                                      dmp_time_ms now,
                                      dmp_reassembly_handle *completed);

/* Expires every due incomplete transfer, turning each reserved tombstone into
 * a no-reopen identity fence. expired_count is published on success. */
dmp_status dmp_reassembly_poll(dmp_reassembly *engine, dmp_time_ms now,
                               size_t *expired_count);

/* The returned spans borrow engine storage until release. Only complete
 * handles can be read or released. */
dmp_status dmp_reassembly_get(const dmp_reassembly *engine,
                              dmp_reassembly_handle handle,
                              dmp_reassembly_message *out);
dmp_status dmp_reassembly_release(dmp_reassembly *engine,
                                  dmp_reassembly_handle handle);

/* Call only after dmp_identity_context_retire succeeded for this exact
 * generation. It releases that context's expired-transfer tombstones. */
dmp_status dmp_reassembly_context_retired(dmp_reassembly *engine,
                                          dmp_identity_handle context);

#ifdef __cplusplus
}
#endif
#endif
