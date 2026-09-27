#ifndef DMP_TRANSPORT_H
#define DMP_TRANSPORT_H

#include "dmp/base.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct { uint32_t slot; uint64_t generation; } dmp_tx_token;
typedef enum { DMP_TX_COPY = 0, DMP_TX_BORROW = 1 } dmp_tx_ownership;
typedef enum {
    DMP_TX_TRANSMITTED = 0,
    DMP_TX_CANCELLED_UNSENT,
    DMP_TX_FAILED_UNSENT,
    DMP_TX_POSSIBLY_TRANSMITTED
} dmp_tx_outcome;
typedef struct {
    size_t max_frame_bytes;
    dmp_tx_ownership ownership;
    bool synchronous_completion;
} dmp_transport_caps;
typedef void (*dmp_tx_complete_fn)(void *owner, dmp_tx_token token,
                                  dmp_tx_outcome outcome, dmp_time_ms when);
typedef struct {
    dmp_tx_token token;
    dmp_bytes frame;
    dmp_time_ms not_after;
    dmp_tx_complete_fn complete;
    void *owner;
} dmp_tx_submission;
typedef struct {
    void *context;
    dmp_transport_caps caps;
    dmp_status (*submit)(void *context, const dmp_tx_submission *submission);
    dmp_status (*cancel)(void *context, dmp_tx_token token);
} dmp_transport;

/* Adapter seam, not a driver or reliable endpoint implementation.
 * submit: OK accepts; any other status rejects with no callback. BUSY is bounded
 * backpressure. Copy mode copies frame bytes before return; borrow mode keeps
 * them immutable/exclusively owned through exactly one terminal callback.
 * The submission struct itself is call-local: copy token/owner/callback/deadline.
 * All accepted submissions get exactly one terminal callback, including after
 * disconnect/reset/timeout; it proves no further DMA access is possible.
 * Copy completion releases adapter-owned storage, never caller logical retries.
 * synchronous_completion=true permits both synchronous and delayed callbacks;
 * false permits only callbacks after submit returns. Owner must register
 * token and pin storage BEFORE calling submit, and must not overwrite terminal
 * state when submit subsequently returns OK. Callback may not recursively submit.
 * cancel OK means request accepted, NOT ownership returned; even rejected cancel
 * leaves submission live. Only CANCELLED_UNSENT proves transmission prevented;
 * failure/disconnect after possible transmission uses POSSIBLY_TRANSMITTED.
 * not_after is an absolute local send deadline; no new transmission starts at
 * or after it. Expiry cannot claim remote cancellation of a possibly sent frame.
 * Serialize submit/cancel/completion for each owner (marshal ISR/threads first).
 * Each context belongs to exactly one owner for its lifetime; shared physical
 * drivers expose distinct contexts per owner. Tokens are unique within context,
 * including across resets, so cancel(context, token) is unambiguous.
 * Never reuse a live generation or
 * destroy owner/storage before callbacks settle. Exhausted generation fails.
 * Local terminal outcomes never imply DMP receipt, result or authentication.
 */

#ifdef __cplusplus
}
#endif
#endif
