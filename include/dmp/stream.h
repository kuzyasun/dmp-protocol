#ifndef DMP_STREAM_H
#define DMP_STREAM_H

#include "dmp/base.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Bounded framing implemented in src/stream/; events are not DMP acceptance. */
typedef enum { DMP_STREAM_L = 0, DMP_STREAM_R = 1 } dmp_stream_mode;
typedef enum {
    DMP_STREAM_NONE = 0, DMP_STREAM_FRAME, DMP_STREAM_DISCARDED,
    DMP_STREAM_SESSION_FAILED
} dmp_stream_event;
typedef struct {
    dmp_stream_mode mode;
    size_t max_core_bytes;
    uint64_t partial_timeout_ms;
} dmp_stream_config;

/* Caller-owned state and scratch; members are implementation-private. No global
 * state, heap or OS. Do not copy an initialized decoder or edit these fields. */
typedef struct {
    dmp_stream_config config;
    dmp_buffer storage;
    size_t used, expected;
    dmp_time_ms deadline, last_now;
    uint32_t length_value;
    uint8_t phase, length_bytes;
    bool timer_armed, failed;
} dmp_stream_decoder;
typedef struct {
    dmp_status status;
    dmp_stream_event event;
    size_t consumed;
    dmp_bytes frame;
} dmp_stream_result;

/* Capacity includes framing scratch: encoded_bound(max_core) for R, max_core
 * for L. Init rejects insufficient storage, zero timeout or invalid geometry.
 * Failure leaves decoder and storage unchanged. Reinitialization/reset requires
 * no outstanding borrowed result view. Storage must not overlap the decoder. */
dmp_status dmp_stream_init(dmp_stream_decoder *decoder,
                            dmp_stream_config config, dmp_buffer storage,
                            dmp_time_ms now);
/* Initialized decoder required. Backward time fails without mutation. */
dmp_status dmp_stream_reset(dmp_stream_decoder *decoder, dmp_time_ms now);
/* Overflow fails with LIMIT_EXHAUSTED; failure leaves *out unchanged. */
dmp_status dmp_stream_encoded_bound(dmp_stream_mode mode, size_t core_size,
                                     size_t *out);
/* Complete preflight: failure sets *written=0 (when non-NULL), leaves destination
 * unchanged. Core bytes and destination must not overlap. */
dmp_status dmp_stream_encode(dmp_stream_mode mode, dmp_bytes core,
                              dmp_buffer output, size_t *written);

/* Pull at most one event; caller advances input by consumed and repeats.
 * FRAME borrows decoder storage until next feed/poll/reset/init. It has only
 * framing integrity, never core validity/authentication/endpoint acceptance.
 * Process all available input at t before poll(t). Feed expires a pending frame
 * before new bytes only if now > deadline; poll expires at now >= deadline.
 * L arms on the first magic/prefix byte; R arms on the first nonzero candidate
 * byte after synchronization, never while discarding or on empty delimiters.
 * Neither partial bytes nor empty R delimiters renew an armed absolute timer.
 * Backward time/invalid arguments return INVALID_ARGUMENT, NONE, consumed=0 and
 * an empty frame without mutation. Input must not overlap decoder or storage.
 * Other errors publish no frame. Failure to represent a new absolute deadline
 * latches SESSION_FAILED with LIMIT_EXHAUSTED; reset requires a new session.
 * Framing/length/oversize errors: MALFORMED; CRC: INTEGRITY_FAILURE;
 * timeout: DEADLINE_EXPIRED. These emit DISCARDED in R, SESSION_FAILED in L.
 * A candidate rejected at its delimiter is already synchronized there; errors
 * detected before a delimiter discard through the next delimiter in R.
 * Init/encode capacity failure is QUOTA_EXHAUSTED; overflow LIMIT_EXHAUSTED. */
dmp_stream_result dmp_stream_feed(dmp_stream_decoder *decoder,
                                   dmp_bytes input, dmp_time_ms now);
dmp_stream_result dmp_stream_poll(dmp_stream_decoder *decoder, dmp_time_ms now);

/* R starts discarding through a delimiter; encode emits only a frame, so the
 * adapter must emit initial 00 after receiver readiness on each coordinated open.
 * R errors/timeout discard through delimiter. L errors/timeout latch session
 * failure; never scan for magic. Core-invalid L frames require adapter closure.
 * Reset is a new logical session boundary, not permission to scan arbitrary L. */

#ifdef __cplusplus
}
#endif
#endif
