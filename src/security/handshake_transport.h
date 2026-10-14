/* Private SEC-1 handshake-to-transport adapter. Not a public libdmp header.
 *
 * This adapter owns no heap memory and does not implement Noise or handshake
 * transitions. The caller supplies the adapter state and one writable frame
 * buffer for each in-flight slot. It copies the selected immutable handshake
 * output into that buffer before submitting it, so the handshake owner may
 * replace its cached output immediately after this function returns.
 */
#ifndef DMP_HANDSHAKE_TRANSPORT_H
#define DMP_HANDSHAKE_TRANSPORT_H

#include "handshake.h"
#include "dmp/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMP_HS_TX_SLOT_MAX DMP_HS_ATTEMPT_MAX
#define DMP_HS_TX_CORE_MAX 512u

typedef enum dmp_hs_tx_output {
    DMP_HS_TX_CACHED_FLIGHT = 0,
    DMP_HS_TX_PROTECTED_FRAME = 1
} dmp_hs_tx_output;

typedef enum dmp_hs_tx_status {
    DMP_HS_TX_ACCEPTED = 0,
    DMP_HS_TX_BUSY,
    DMP_HS_TX_EXPIRED,
    DMP_HS_TX_NO_OUTPUT,
    DMP_HS_TX_NO_SLOT,
    DMP_HS_TX_REFUSED,
    DMP_HS_TX_TRANSPORT_REJECTED,
    DMP_HS_TX_STALE,
    DMP_HS_TX_INVALID
} dmp_hs_tx_status;

typedef enum dmp_hs_tx_framing {
    DMP_HS_TX_STREAM_R = 0,
    DMP_HS_TX_CORE_PACKET = 1
} dmp_hs_tx_framing;

typedef struct dmp_hs_tx_buffer {
    uint8_t *data;
    size_t capacity;
} dmp_hs_tx_buffer;

/* Token generations belong to the transport context, not one adapter init.
 * Keep this zero-initialized object alive across every reset/re-init that can
 * still receive stale tokens for the same context. */
typedef struct dmp_hs_tx_lifetime {
    uint64_t token_generation;
} dmp_hs_tx_lifetime;

typedef struct dmp_hs_tx_config {
    /* Maximum decoded Core frame permitted by policy. */
    size_t max_core_frame_bytes;
    /* Finite cap for the number of Core FRAG slices in a bootstrap flight. */
    uint32_t max_bootstrap_fragments;
    /* Stream R frames include COBS/envelope; its open/reset sync delimiter is
     * a separate one-byte submission. Packet mode submits one Core frame. */
    dmp_hs_tx_framing framing;
} dmp_hs_tx_config;

typedef struct dmp_hs_tx dmp_hs_tx;

typedef struct dmp_hs_tx_result {
    dmp_tx_token token;
    uint32_t attempt_index;
    uint64_t handshake_generation;
    dmp_tx_outcome outcome;
    dmp_time_ms completed_at;
    int synchronization;
    int expired;
    int cancellation_requested;
} dmp_hs_tx_result;

size_t dmp_hs_tx_size(void);

/* Initialize caller-owned state. Zero-initialize state before its first init;
 * re-init is allowed only after every accepted callback has been taken. The
 * state storage returned by size() must be
 * aligned to alignof(max_align_t). There must be exactly DMP_HS_TX_SLOT_MAX
 * distinct writable buffers, each large enough for dmp_stream_encoded_bound()
 * at the configured maximum Core size in Stream R, or that Core size in packet
 * mode. On ACCEPTED,
 * the selected buffer contains a complete frame in the configured framing.
 * It remains immutable and unavailable for
 * reuse until the terminal callback has run and dmp_hs_tx_take() releases the
 * slot, for BOTH COPY and BORROW bindings. A COPY binding must copy the bytes
 * before submit() returns; a BORROW binding may read them through its terminal
 * callback. The transport and handshake owners, adapter state, buffers, and
 * callback owner must outlive all accepted callbacks. `lifetime` must be
 * zero-initialized once and reused for every initialization using the same
 * transport context; never reset it while that context can present stale
 * tokens. For Stream R, initialize the receiver before calling dmp_hs_tx_sync();
 * the adapter blocks frame submissions until that separate delimiter
 * submission is definitely transmitted. Calls, cancellation and callbacks for
 * this adapter must be serialized. */
dmp_hs_tx_status dmp_hs_tx_init(dmp_hs_tx *state, dmp_hs *handshake,
                                dmp_transport *transport,
                                const dmp_hs_tx_config *config,
                                dmp_hs_tx_lifetime *lifetime,
                                const dmp_hs_tx_buffer buffers[DMP_HS_TX_SLOT_MAX]);

/* Submit the initial empty Stream R delimiter as its own binding operation.
 * For packet mode or an already-synchronized binding, returns NO_OUTPUT. BUSY,
 * rejection, or any outcome other than TRANSMITTED leaves sync pending. An
 * accepted submission has a callback and must be taken like any other token.
 * `peer` selects the routed binding being opened. */
dmp_hs_tx_status dmp_hs_tx_sync(dmp_hs_tx *state, dmp_peer_handle peer,
                                dmp_tx_token *token);

/* Call after a coordinated Stream R peer-binding reset, once that peer's old
 * callbacks have settled. It rearms only that route's separate delimiter. */
dmp_hs_tx_status dmp_hs_tx_binding_reset(dmp_hs_tx *state,
                                         dmp_peer_handle peer);

/* Plan the fixed geometry for one cached bootstrap flight. The returned count
 * is one when unfragmented; otherwise the caller submits each index with the
 * same handshake state and no intervening handshake transition. Protected
 * SEC-1 frames always have count one here: Core FRAG must be chosen before
 * sealing, and Stream R then wraps the complete protected Core frame. */
dmp_hs_tx_status dmp_hs_tx_fragment_plan(dmp_hs_tx *state,
                                         uint32_t attempt_index,
                                         dmp_hs_tx_output output,
                                         size_t *fragment_count,
                                         size_t *chunk_size);

/* Submit one cached bootstrap flight slice or one protected SEC-1 Core frame.
 * Bootstrap output is wrapped in HELLO with SEQ, CONTEXT, route/origin and
 * Core CRC32C; it is DMP-FRAG fragmented when needed to fit the configured
 * Core MTU. Protected output is passed through unchanged inside Stream R;
 * each Stream R frame submission contains no lifecycle synchronization byte.
 * The returned token is valid only after ACCEPTED. BUSY/rejection means no
 * callback will follow and releases the slot. A binding callback may run
 * synchronously inside submit(). now_ms is monotonic. Each cached-flight
 * fragment may be accepted once under the current handshake-owned send
 * permit. After a complete flight, call dmp_hs_retransmit() to authorize a
 * retry; a pre-accept rejection returns an unused retry permit. Submissions
 * at/after the attempt deadline are rejected and abort that handshake. */
dmp_hs_tx_status dmp_hs_tx_submit(dmp_hs_tx *state, uint32_t attempt_index,
                                  dmp_hs_tx_output output, dmp_peer_handle peer,
                                  size_t fragment_index, dmp_time_ms now_ms,
                                  dmp_tx_token *token);

/* Abort the matching handshake attempt and ask the binding to cancel the TX.
 * A successful transport cancel is only a request: the slot and frame buffer
 * stay pinned until its terminal callback. If cancel is rejected, a later
 * cancel/expire call may retry. The result is returned by take(). */
dmp_hs_tx_status dmp_hs_tx_cancel(dmp_hs_tx *state, dmp_tx_token token);

/* Expire accepted sends at or after their deadline. This aborts the matching
 * handshake and attempts transport cancellation; rejected requests may be
 * retried by a later call. It does not release a slot or infer that a possibly
 * transmitted frame was prevented. */
void dmp_hs_tx_expire(dmp_hs_tx *state, dmp_time_ms now_ms);

/* Retrieve one terminal callback result and release its slot. Until taken,
 * the slot cannot be reused. A stale or duplicate callback whose full
 * slot/generation token does not match a live slot has no effect. */
dmp_hs_tx_status dmp_hs_tx_take(dmp_hs_tx *state, dmp_hs_tx_result *result);

/* Required caller flow:
 * 1. Allocate dmp_hs_tx_size() bytes aligned for max_align_t and initialize
 *    exactly DMP_HS_TX_SLOT_MAX distinct frame buffers.
 * 2. For CACHED_FLIGHT, call fragment_plan(); submit each returned fragment
 *    index once in order under one handshake-owned permit, then await each
 *    accepted token's terminal callback. Call dmp_hs_retransmit() before
 *    intentionally sending the same cached flight again.
 *    For PROTECTED_FRAME, submit index zero only.
 * 3. Treat BUSY and all other non-ACCEPTED returns as having no callback.
 *    For ACCEPTED, keep every owner alive; cancel/expire only requests
 *    cancellation and does not release the frame.
 * 4. After the terminal callback, call take() to obtain the outcome and free
 *    the frame/admission reservation. Do not reuse a token or slot sooner.
 *
 * A callback may run inside submit(); callers must therefore tolerate a
 * completed token before submit() returns. Possibly-transmitted is an
 * uncertain terminal outcome and must be handled by the handshake owner as
 * such; this adapter never retries or changes Noise state. */

#ifdef __cplusplus
}
#endif

#endif
