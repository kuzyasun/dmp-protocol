#include "dmp/base.h"

static const char *const STATUS_NAMES[] = {
    "ok",
    "invalid_argument",
    "malformed",
    "unsupported",
    "integrity_failure",
    "authentication_failure",
    "context_required",
    "incomplete",
    "duplicate",
    "quota_exhausted",
    "deadline_expired",
    "busy",
    "cancelled",
    "stale_handle",
    "limit_exhausted",
};

dmp_status dmp_bytes_slice(dmp_bytes input, size_t offset, size_t size,
                           dmp_bytes *out)
{
    dmp_bytes slice;

    if (out == NULL || (input.data == NULL && input.size != 0U)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (offset > input.size || size > input.size - offset) {
        return DMP_INVALID_ARGUMENT;
    }

    slice.data = input.data;
    if (input.data != NULL) {
        slice.data = input.data + offset;
    }
    slice.size = size;
    *out = slice;
    return DMP_OK;
}

dmp_status dmp_deadline_after(dmp_time_ms now, uint64_t duration_ms,
                              dmp_time_ms *out)
{
    if (out == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (duration_ms > UINT64_MAX - now) {
        return DMP_LIMIT_EXHAUSTED;
    }

    *out = now + duration_ms;
    return DMP_OK;
}

bool dmp_deadline_reached(dmp_time_ms now, dmp_time_ms deadline)
{
    return now >= deadline;
}

dmp_status dmp_generation_next(uint64_t current, uint64_t *out)
{
    if (out == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (current == UINT64_MAX) {
        return DMP_LIMIT_EXHAUSTED;
    }

    *out = current == 0U ? 1U : current + 1U;
    return DMP_OK;
}

const char *dmp_status_name(dmp_status status)
{
    if ((int)status < 0 || (size_t)status >= sizeof STATUS_NAMES / sizeof STATUS_NAMES[0]) {
        return "unknown";
    }
    return STATUS_NAMES[(size_t)status];
}
