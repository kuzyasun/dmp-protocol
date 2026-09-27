#ifndef DMP_BASE_H
#define DMP_BASE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Local API results, never wire STATUS values or evidence of peer acceptance. */
typedef enum {
    DMP_OK = 0,
    DMP_INVALID_ARGUMENT,
    DMP_MALFORMED,
    DMP_UNSUPPORTED,
    DMP_INTEGRITY_FAILURE,
    DMP_AUTHENTICATION_FAILURE,
    DMP_CONTEXT_REQUIRED,
    DMP_INCOMPLETE,
    DMP_DUPLICATE,
    DMP_QUOTA_EXHAUSTED,
    DMP_DEADLINE_EXPIRED,
    DMP_BUSY,
    DMP_CANCELLED,
    DMP_STALE_HANDLE,
    DMP_LIMIT_EXHAUSTED
} dmp_status;

typedef struct { const uint8_t *data; size_t size; } dmp_bytes;
typedef struct { uint8_t *data; size_t capacity; } dmp_buffer;
typedef struct { dmp_status status; size_t offset; } dmp_parse_result;
typedef uint64_t dmp_time_ms;

/* A nonempty span requires real readable backing; a zero-size NULL span is valid.
 * Failure leaves *out unchanged. No pointer arithmetic on NULL, even at size 0. */
dmp_status dmp_bytes_slice(dmp_bytes input, size_t offset, size_t size,
                           dmp_bytes *out);

/* Absolute monotonic milliseconds. No wrap, wall-clock queries or magic infinity.
 * Duration 0 means now. Overflow fails and leaves *out unchanged. */
dmp_status dmp_deadline_after(dmp_time_ms now, uint64_t duration_ms,
                            dmp_time_ms *out);
bool dmp_deadline_reached(dmp_time_ms now, dmp_time_ms deadline);

/* Generation 0 is invalid. Exhaustion refuses reuse, never wraps. The owner must
 * preserve the counter across slot reuse/reset until every old callback settles. */
dmp_status dmp_generation_next(uint64_t current, uint64_t *out);
const char *dmp_status_name(dmp_status status);

#ifdef __cplusplus
}
#endif
#endif
