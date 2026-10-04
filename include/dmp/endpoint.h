#ifndef DMP_ENDPOINT_H
#define DMP_ENDPOINT_H

#include "dmp/reassembly.h"
#include "dmp/reliability.h"
#include "dmp/stream.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Direct endpoint. Composes the identity, reliability, reassembly and Stream R
 * engines in src/. Payload bytes stay opaque. SAMPLE-1 layout is an application
 * codec outside libdmp. No heap and no JSON parsing.
 *
 * security == 0 is the plaintext path. security == 1 delivers application
 * traffic only after dmp_endpoint_bind and association activation. Protection
 * is the existing P14 record path; this module does not open a second
 * handshake, cipher, or KDF. Receive does not allocate for epoch hashing.
 * The object must not be moved after a successful init. Calls are serialized. */

struct dmp_hs;

typedef enum {
    DMP_ENDPOINT_REQUEST = 1,
    DMP_ENDPOINT_RESULT = 2,
    DMP_ENDPOINT_TELEMETRY = 3,
    DMP_ENDPOINT_ASSEMBLED = 4,
    /* Local reliable REQ ended without a result. possibly-sent is unknown. */
    DMP_ENDPOINT_UNKNOWN = 5
} dmp_endpoint_event;

typedef struct {
    dmp_endpoint_event event;
    dmp_reliability_handle request;
    uint32_t service_id;
    uint32_t wire_status;
    /* Peer source for REQUEST, RESULT and TELEMETRY. Own request key for UNKNOWN.
     * Association identity is this origin, not a CID. */
    dmp_message_key source;
    /* Borrows engine or decoder storage until this callback returns. */
    dmp_bytes payload;
} dmp_endpoint_notice;

/* Synchronous, serialized, and must not reenter the endpoint. */
typedef void (*dmp_endpoint_notice_fn)(void *user, const dmp_endpoint_notice *notice);

/* Every buffer is caller-owned for the whole endpoint lifetime. Slot counts
 * must be at least the admitted profile. Extra bytes do not raise quotas.
 * stream_tx must hold one Stream R encoding of encoded_mtu plus the one-byte
 * opening delimiter. stream_rx must hold one Stream R decoder candidate. */
typedef struct {
    const dmp_admitted_profile *profile;
    dmp_identity_slot *identity_slots;
    size_t identity_capacity;
    dmp_identity_context_config context;
    dmp_transport *transport;
    dmp_endpoint_notice_fn notice;
    void *notice_user;
    dmp_reliability_sender_slot *senders;
    size_t sender_capacity;
    uint8_t *sender_payload;
    size_t sender_payload_capacity;
    dmp_reliability_result_slot *results;
    size_t result_capacity;
    uint8_t *result_payload;
    size_t result_payload_capacity;
    dmp_reliability_history_slot *history;
    size_t history_capacity;
    dmp_reliability_correlation_slot *correlations;
    size_t correlation_capacity;
    uint8_t *history_metadata;
    size_t history_metadata_capacity;
    uint8_t *correlation_metadata;
    size_t correlation_metadata_capacity;
    dmp_reliability_adapter_slot *adapters;
    size_t adapter_capacity;
    uint8_t *frames;
    size_t frame_capacity;
    uint8_t *receive_payload;
    size_t receive_payload_capacity;
    dmp_reassembly_slot *assemblies;
    size_t assembly_capacity;
    dmp_reassembly_tombstone *tombstones;
    size_t tombstone_capacity;
    uint8_t *assembly_payload;
    size_t assembly_payload_capacity;
    uint8_t *assembly_metadata;
    size_t assembly_metadata_capacity;
    uint8_t *fragment_message;
    size_t fragment_message_capacity;
    uint8_t *fragment_frame;
    size_t fragment_frame_capacity;
    uint8_t *telemetry_payload;
    size_t telemetry_payload_capacity;
    uint8_t *telemetry_next;
    size_t telemetry_next_capacity;
    uint8_t *telemetry_frame;
    size_t telemetry_frame_capacity;
    uint8_t *stream_tx;
    size_t stream_tx_capacity;
    uint8_t *stream_rx;
    size_t stream_rx_capacity;
} dmp_endpoint_storage;

enum { DMP_ENDPOINT_TX_SLOTS = 4 };

typedef struct {
    uint8_t live;
    uint8_t kind;
    dmp_tx_token outer_token;
    dmp_tx_token inner_token;
    dmp_tx_complete_fn complete;
    void *owner;
} dmp_endpoint_tx;

typedef struct {
    dmp_reliability reliability;
    dmp_reassembly reassembly;
    dmp_identity_table identity;
    dmp_identity_handle context;
    dmp_admitted_profile profile;
    dmp_transport outer;
    dmp_transport inner;
    dmp_stream_decoder decoder;
    dmp_endpoint_notice_fn notice;
    void *notice_user;
    dmp_endpoint_storage mem;
    dmp_endpoint_tx tx[DMP_ENDPOINT_TX_SLOTS];
    uint64_t tx_generation;
    uint8_t wire_busy;
    uint8_t initialized;
    uint8_t frag_live;
    uint8_t frag_tx;
    uint32_t frag_index;
    uint32_t frag_count;
    uint32_t frag_total;
    uint32_t frag_seq;
    uint32_t frag_service;
    uint8_t telem_pending;
    uint8_t telem_hold;
    uint8_t telem_tx;
    uint8_t telem_seq_set;
    uint32_t telem_len;
    uint32_t telem_next_len;
    uint32_t telem_service;
    uint32_t telem_seq;
    uint8_t ext_scratch[DMP_MAX_HEADER_BYTES];
    struct dmp_hs *association;
    uint32_t association_attempt;
    uint8_t association_bound;
} dmp_endpoint;

/* now is the first monotonic time the Stream R decoder may observe. Failure
 * leaves *endpoint uninitialized only when the caller zeros it before retry;
 * a context may already be open in the caller table. */
dmp_status dmp_endpoint_init(dmp_endpoint *endpoint, const dmp_endpoint_storage *storage,
                             dmp_time_ms now);

/* Attach one real handshake attempt. Requires security == 1 and a hashed
 * attempt whose namespace and node ids match the open context. Activation is
 * separate: application send and receive fail until that attempt is active. */
dmp_status dmp_endpoint_bind(dmp_endpoint *endpoint, struct dmp_hs *handshake,
                             uint32_t attempt_index);

/* Unfragmented reliable REQ. Payload must fit in one core frame. Copies on
 * success. A second live operation that exceeds the admitted queue returns the
 * reliability status (DMP_BUSY or DMP_QUOTA_EXHAUSTED) and changes nothing. */
dmp_status dmp_endpoint_submit_req(dmp_endpoint *endpoint, uint32_t service_id,
                                   dmp_bytes payload, dmp_time_ms now,
                                   dmp_reliability_handle *out);

/* RSP, or terminal application ERR when application_err is true and
 * wire_status >= 64. Payload is copied on success. */
dmp_status dmp_endpoint_complete(dmp_endpoint *endpoint, dmp_reliability_handle request,
                                 bool application_err, uint32_t wire_status,
                                 dmp_bytes payload, dmp_time_ms now);

/* Best-effort unfragmented TELEM. An unsent staged sample is replaced.
 * A sample that does not fit one frame returns DMP_LIMIT_EXHAUSTED. */
dmp_status dmp_endpoint_submit_telem(dmp_endpoint *endpoint, uint32_t service_id,
                                     dmp_bytes payload, dmp_time_ms now);

/* One caller-owned fragmented transfer of an opaque payload that does not fit
 * in one core frame. Fixed stride is the admitted chunk_bytes. The caller
 * buffer is copied before return. A live transfer returns DMP_QUOTA_EXHAUSTED
 * and does not change the peer. The peer reassembles through dmp_reassembly.
 * The completed assembly is endpoint state until that engine's fence ends.
 * Delivery does not call dmp_reassembly_release: release clears the reserved
 * tombstone and would accept the same SEQ again. A replay is DMP_DUPLICATE,
 * or the engine's existing fence status, and does not raise another assembled
 * notice. Incomplete transfers expire only through dmp_reassembly_poll. This
 * path does not invent a second reassembly or retry machine; unfragmented
 * retries stay in dmp_reliability. */
dmp_status dmp_endpoint_submit_fragmented(dmp_endpoint *endpoint, uint32_t service_id,
                                          dmp_bytes payload, dmp_time_ms now);

dmp_status dmp_endpoint_poll(dmp_endpoint *endpoint, dmp_time_ms now);

/* One direction of a Stream R byte stream. DMP_QUOTA_EXHAUSTED is the admitted
 * reassembly refusal and does not evict an existing assembly. DMP_DUPLICATE
 * means an identical fragment was ignored. DMP_INCOMPLETE means the transfer
 * is still short of its last slice. A completed assembly stays held in the
 * endpoint until the reassembly fence ends; the notice payload borrows that
 * storage only until the callback returns. */
dmp_status dmp_endpoint_rx(dmp_endpoint *endpoint, dmp_bytes input, dmp_time_ms now);

#ifdef __cplusplus
}
#endif
#endif
