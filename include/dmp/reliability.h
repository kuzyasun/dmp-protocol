#ifndef DMP_RELIABILITY_H
#define DMP_RELIABILITY_H

#include "dmp/identity.h"
#include "dmp/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t slot;
    uint64_t generation;
} dmp_reliability_handle;

typedef enum {
    DMP_REL_PHASE_UNUSED = 0,
    DMP_REL_PHASE_QUEUED,
    DMP_REL_PHASE_TRANSMITTING,
    DMP_REL_PHASE_AWAIT_RECEIPT,
    DMP_REL_PHASE_AWAIT_RESULT,
    DMP_REL_PHASE_TERMINAL
} dmp_reliability_phase;

typedef enum {
    DMP_REL_EVENT_REQUEST_ACCEPTED = 1,
    DMP_REL_EVENT_LOCAL_UNSENT,
    DMP_REL_EVENT_UNKNOWN,
    DMP_REL_EVENT_REJECTED,
    DMP_REL_EVENT_RECEIPT,
    DMP_REL_EVENT_RESULT,
    DMP_REL_EVENT_LATE_RESULT
} dmp_reliability_event;

typedef enum {
    DMP_REL_SENDER_REQUEST = 0,
    DMP_REL_SENDER_RESULT = 1
} dmp_reliability_sender_kind;

typedef enum {
    DMP_REL_HISTORY_ACCEPTED = 0,
    DMP_REL_HISTORY_REJECTED = 1
} dmp_reliability_history_decision;

typedef struct {
    dmp_reliability_event event;
    dmp_reliability_handle handle;
    dmp_message_key key;
    uint32_t service_id;
    uint32_t wire_status;
    dmp_bytes payload;
} dmp_reliability_notice;

/* Notices are synchronous, serialized callbacks and must not reenter the
 * engine. For REQUEST_ACCEPTED and RESULT, payload is verified plaintext copied
 * to receive_payload and is valid only until this callback returns. Never
 * expose frame->payload for SECURITY frames. LATE_RESULT always has an empty
 * payload and is diagnostic only; it never repeats RESULT or the application
 * result callback. */
typedef void (*dmp_reliability_notice_fn)(
    void *user, const dmp_reliability_notice *notice);

typedef struct {
    dmp_type type;
    uint32_t service_id;
    dmp_message_origin destination;
    dmp_message_key own;
    dmp_message_key reply_to;
    bool has_reply_to;
    bool ack_req;
    uint32_t wire_status;
    dmp_bytes payload;
    /* Zero total_size is one unfragmented frame. Otherwise payload is one
     * slice of the saved message: index, chunk_size and total_size are that
     * slice's geometry. The engine does not copy the message per fragment. */
    uint32_t fragment_index;
    uint32_t chunk_size;
    uint32_t total_size;
} dmp_reliability_logical;

/* The encoder constructs one fresh direct logical frame per attempt. For a
 * secured identity context it must invoke the future SEC-1 protection path and
 * allocate a fresh PN; P10 does not protect or resend cached ciphertext. */
typedef dmp_status (*dmp_reliability_encode_fn)(
    void *context, const dmp_reliability_logical *logical, dmp_buffer out,
    size_t *written);

/* frame remains the structural wire view. plaintext is supplied separately
 * because frame->payload is ciphertext for SECURITY frames. The caller must
 * already have verified integrity/authentication, resolved the association and
 * service, and validated the application payload. P10 accepts direct,
 * unfragmented request/result traffic only. */
typedef struct {
    const dmp_frame_view *frame;
    uint32_t service_id;
    dmp_bytes plaintext;
    /* Canonical TLV bytes, in wire order, for every immutable extension not
     * already represented by the resolved service, descriptor, or full source/
     * REPLY_TO identity. Include unknown safe extensions exactly; exclude the
     * SECURITY TLV/PN and any per-transmission integrity value. Do not include
     * ROUTE or FRAG (unsupported in P10). Empty is valid only when no such TLV
     * is present. Matching retransmissions must supply identical bytes. */
    dmp_bytes immutable_metadata;
} dmp_reliability_input;

enum { DMP_RELIABILITY_METADATA_BYTES = DMP_MAX_HEADER_BYTES };

typedef struct {
    uint64_t generation;
    uint8_t live;
    uint8_t phase;
    uint8_t kind; /* dmp_reliability_sender_kind */
    uint8_t possibly_sent;
    uint32_t service_id;
    dmp_message_key own;
    dmp_message_key reply_to;
    dmp_time_ms queue_deadline;
    dmp_time_ms send_deadline;
    dmp_time_ms receipt_deadline;
    dmp_time_ms result_deadline;
    dmp_time_ms retain_deadline;
    dmp_time_ms next_attempt;
    uint32_t attempts;
    uint32_t jitter_ms;
    uint32_t payload_len;
    uint32_t related_slot;
    uint64_t related_generation;
    uint32_t tx_slot;
    uint64_t tx_generation;
    bool tx_live;
    bool receipt_seen;
    bool result_seen;
    /* Selective repair state. repair_mask is the newest pending missing mask.
     * active_mask is the burst still being sent. feedback_seq is the greatest
     * accepted FRAG_STATUS SEQ once feedback_valid is set. packet_count counts
     * started bursts. probe_count counts probes. Zero frag_count is the
     * unfragmented path. */
    uint32_t repair_mask;
    uint32_t active_mask;
    uint32_t feedback_seq;
    uint32_t packet_count;
    uint32_t probe_count;
    uint32_t frag_count;
    uint32_t chunk_size;
    uint32_t total_size;
    uint32_t sending_index;
    uint8_t feedback_valid;
    uint8_t burst_inflight;
    uint8_t burst_counted;
    uint8_t probe_burst;
} dmp_reliability_sender_slot;

typedef struct {
    uint64_t generation;
    uint8_t live;
    uint8_t application_err;
    uint8_t acknowledged;
    uint8_t reserved;
    dmp_message_key request;
    dmp_message_key result;
    dmp_message_origin destination;
    uint32_t service_id;
    uint32_t wire_status;
    dmp_time_ms deadline;
    dmp_time_ms next_attempt;
    uint32_t payload_len;
    uint32_t sender_slot;
    uint64_t sender_generation;
    uint32_t history_slot;
    uint64_t history_generation;
} dmp_reliability_result_slot;

typedef struct {
    uint64_t generation;
    uint8_t live;
    uint8_t decision; /* dmp_reliability_history_decision */
    uint8_t type;
    uint8_t ack_req;
    uint8_t descriptor_flags;
    uint8_t reserved[3];
    uint32_t service_id;
    uint32_t descriptor_codec;
    uint32_t descriptor_schema;
    uint32_t descriptor_version;
    uint16_t metadata_len;
    uint16_t reserved2;
    dmp_message_key source;
    dmp_message_origin destination;
    uint32_t wire_status;
    dmp_time_ms deadline;
    uint32_t result_slot;
    uint64_t result_generation;
    uint32_t receipt_count;
} dmp_reliability_history_slot;

typedef struct {
    uint64_t generation;
    uint8_t live;
    uint8_t result_delivered;
    uint8_t terminal_unknown;
    uint8_t reserved;
    dmp_reliability_handle request;
    dmp_message_key request_key;
    dmp_message_key result_key;
    uint16_t result_metadata_len;
    uint16_t reserved2;
    uint32_t service_id;
    dmp_time_ms correlation_deadline;
    dmp_time_ms tombstone_deadline;
} dmp_reliability_correlation_slot;

typedef struct {
    uint64_t generation;
    uint8_t live;
    uint8_t control;
    uint8_t completion_ready;
    uint8_t reserved;
    dmp_tx_token token;
    dmp_tx_outcome outcome;
    dmp_time_ms completed_at;
    size_t frame_len;
    uint32_t sender_slot;
    uint64_t sender_generation;
    uint32_t result_slot;
    uint64_t result_generation;
} dmp_reliability_adapter_slot;

/* Every capacity is measured in elements or bytes, as its field name states.
 * The caller owns all storage for the entire engine lifetime. */
typedef struct {
    const dmp_admitted_profile *profile;
    dmp_identity_table *identity;
    dmp_identity_handle context;
    dmp_transport *transport;
    dmp_reliability_encode_fn encode;
    void *encode_context;
    dmp_reliability_notice_fn notice;
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
} dmp_reliability_storage;

typedef struct {
    dmp_reliability_storage storage;
    dmp_admitted_profile profile;
    dmp_transport transport;
    uint64_t generation;
    uint8_t initialized;
    uint8_t closing;
    uint8_t context_retained;
    uint8_t reserved;
} dmp_reliability;

/* P10 v1 binds one engine to one identity context and supports admitted direct
 * profiles with peers == 1. init validates every profile-derived array count
 * (each capacity must be at least its corresponding sender/result/history/
 * correlation/adapter slot count) and checked byte minima before publishing
 * state:
 * sender_payload >= sender_slots*message_bytes;
 * result_payload >= result_slots*message_bytes;
 * frame storage >= adapter_slots*encoded_mtu;
 * each metadata store >= its slot count*DMP_RELIABILITY_METADATA_BYTES;
 * receive_payload >= message_bytes. All required pointers must be non-NULL,
 * products must be overflow checked, and undersized storage returns
 * DMP_INVALID_ARGUMENT without publishing engine state. The application queue
 * and live control transmissions are separately capped by
 * application_queue_slots and control_slots; resource charges never raise
 * those limits. ACKs bypass the application queue and stop-and-wait gate and
 * use only admitted control/adapter reserves. init also checks direct transport
 * MTU/caps and the identity context. It retains context until close. close
 * succeeds only after logical records and TX callbacks settle. Calls are
 * serialized by one owner. */
dmp_status dmp_reliability_init(dmp_reliability *engine,
                                const dmp_reliability_storage *storage);
dmp_status dmp_reliability_close(dmp_reliability *engine, dmp_time_ms now);

/* Submit one reliable REQ. Payload is copied on success. jitter_ms is the
 * caller-selected bounded jitter for each admitted schedule; no RNG is used.
 * Failure leaves out and all live slots unchanged. */
dmp_status dmp_reliability_submit_req(dmp_reliability *engine,
                                      uint32_t service_id, dmp_bytes payload,
                                      dmp_time_ms now, uint32_t jitter_ms,
                                      dmp_reliability_handle *out);
/* Cancellation is local only. Classify the whole exchange as follows:
 * - If no transport submission has been accepted, settle LOCAL_UNSENT.
 * - DMP_TX_CANCELLED_UNSENT and DMP_TX_FAILED_UNSENT prove that the respective
 *   accepted attempt did not transmit.
 * - If any attempt settles as DMP_TX_TRANSMITTED or
 *   DMP_TX_POSSIBLY_TRANSMITTED, the exchange is UNKNOWN.
 * - Once all accepted attempts have settled, if every one is proven unsent,
 *   the exchange is LOCAL_UNSENT.
 * A rejected submit has no callback and did not reach the transport. A
 * successful transport cancel request does not release any frame/token pin.
 * Keep each adapter slot and encoded bytes immutable until its terminal
 * completion callback has settled. */
dmp_status dmp_reliability_cancel(dmp_reliability *engine,
                                  dmp_reliability_handle handle,
                                  dmp_time_ms now);

/* Process one already integrity/authentication/context/application-validated
 * input. Resolve and match full identity and service before changing exchange
 * state. A REQ must have ACK_REQ, SEQ and supported direct/unfragmented shape.
 * Check its history key before admission: a cached rejection repeats only that
 * rejection, a cached acceptance never dispatches again, and metadata mismatch
 * is rejected locally. A new valid REQ is accepted only after history, result
 * and sender capacity are reserved. Rejected requests must use reject_req.
 * Protocol ERR 1..7 is valid only with ACK_REQ=0; it may reject only the exact
 * outstanding request. ERR 8..63, ERR 1..7 with ACK_REQ, and unmatched/invalid
 * replies do not stop retries. RSP requires ACK_REQ, own SEQ, and exact
 * peer/service/full REPLY_TO correlation; ACK it by its own identity and
 * deliver its result once. Application-result ERR >=64 has the same reliable
 * correlation/ACK rule. ACK itself has no ACK_REQ and only a full match to the
 * outstanding request or retained local result changes state. One unacknowledged
 * ACK_REQ transmission per peer/service shares a gate across REQ and result
 * sends; ACK traffic bypasses that gate. */
dmp_status dmp_reliability_on_rx(dmp_reliability *engine,
                                 const dmp_reliability_input *input,
                                 dmp_time_ms now);

/* Cache and send a protocol rejection for a request the application rejected
 * before acceptance. status must be 1..7. On a matching duplicate, repeat only
 * this retained best-effort rejection; it must never be accepted later. A
 * metadata mismatch is dropped/rejected locally. Rejected REQs never create
 * reliable-result state and are never ACKed. */
dmp_status dmp_reliability_reject_req(dmp_reliability *engine,
                                      const dmp_reliability_input *input,
                                      uint32_t protocol_status,
                                      dmp_time_ms now);

/* Complete a previously accepted inbound request with RSP (application_err ==
 * false and wire_status == 0) or terminal application ERR (application_err ==
 * true and wire_status >= 64). Any mismatched flag/status pair returns
 * DMP_INVALID_ARGUMENT without changing state. Payload is copied on success. */
dmp_status dmp_reliability_complete(dmp_reliability *engine,
                                    dmp_reliability_handle request,
                                    bool application_err,
                                    uint32_t wire_status,
                                    dmp_bytes payload, dmp_time_ms now);

/* Advances deadlines/retries and consumes delayed transport completions.
 * Transport callbacks only publish terminal outcomes; notices and later sends
 * are driven here or by the serialized receive/API calls. */
dmp_status dmp_reliability_poll(dmp_reliability *engine, dmp_time_ms now);

#ifdef __cplusplus
}
#endif
#endif
