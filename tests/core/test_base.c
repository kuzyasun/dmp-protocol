#include "dmp/base.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,    \
                          __LINE__, #condition);                                \
            return 1;                                                          \
        }                                                                       \
    } while (0)

static int test_bytes_slice(void)
{
    const uint8_t storage[] = { 0x10U, 0x20U, 0x30U };
    const dmp_bytes input = { storage, sizeof storage };
    dmp_bytes out = { (const uint8_t *)"sentinel", 99U };
    const dmp_bytes original = out;

    CHECK(dmp_bytes_slice(input, 1U, 2U, &out) == DMP_OK);
    CHECK(out.data == &storage[1]);
    CHECK(out.size == 2U);

    out = original;
    CHECK(dmp_bytes_slice(input, sizeof storage, 0U, &out) == DMP_OK);
    CHECK(out.data == storage + sizeof storage);
    CHECK(out.size == 0U);

    out = original;
    CHECK(dmp_bytes_slice(input, 0U, sizeof storage, &out) == DMP_OK);
    CHECK(out.data == storage);
    CHECK(out.size == sizeof storage);

    out = original;
    CHECK(dmp_bytes_slice(input, 2U, 2U, &out) == DMP_INVALID_ARGUMENT);
    CHECK(out.data == original.data && out.size == original.size);
    CHECK(dmp_bytes_slice(input, sizeof storage + 1U, 0U, &out) == DMP_INVALID_ARGUMENT);
    CHECK(out.data == original.data && out.size == original.size);
    CHECK(dmp_bytes_slice(input, SIZE_MAX, 1U, &out) == DMP_INVALID_ARGUMENT);
    CHECK(out.data == original.data && out.size == original.size);
    CHECK(dmp_bytes_slice(input, 0U, 0U, NULL) == DMP_INVALID_ARGUMENT);

    {
        const dmp_bytes empty = { NULL, 0U };
        out = original;
        CHECK(dmp_bytes_slice(empty, 0U, 0U, &out) == DMP_OK);
        CHECK(out.data == NULL && out.size == 0U);

        out = original;
        CHECK(dmp_bytes_slice(empty, 0U, 1U, &out) == DMP_INVALID_ARGUMENT);
        CHECK(out.data == original.data && out.size == original.size);
    }
    {
        const dmp_bytes invalid = { NULL, 1U };
        out = original;
        CHECK(dmp_bytes_slice(invalid, 0U, 0U, &out) == DMP_INVALID_ARGUMENT);
        CHECK(out.data == original.data && out.size == original.size);
    }

    return 0;
}

static int test_deadlines(void)
{
    dmp_time_ms out = UINT64_C(123456);

    CHECK(dmp_deadline_after(0U, 0U, &out) == DMP_OK && out == 0U);
    CHECK(dmp_deadline_after(UINT64_MAX, 0U, &out) == DMP_OK && out == UINT64_MAX);
    CHECK(dmp_deadline_after(UINT64_MAX - 1U, 1U, &out) == DMP_OK && out == UINT64_MAX);

    out = UINT64_C(123456);
    CHECK(dmp_deadline_after(UINT64_MAX, 1U, &out) == DMP_LIMIT_EXHAUSTED);
    CHECK(out == UINT64_C(123456));
    CHECK(dmp_deadline_after(1U, 1U, NULL) == DMP_INVALID_ARGUMENT);

    CHECK(!dmp_deadline_reached(9U, 10U));
    CHECK(dmp_deadline_reached(10U, 10U));
    CHECK(dmp_deadline_reached(11U, 10U));
    CHECK(dmp_deadline_reached(UINT64_MAX, UINT64_MAX));
    return 0;
}

static int test_generations(void)
{
    uint64_t out = UINT64_C(123456);

    CHECK(dmp_generation_next(0U, &out) == DMP_OK && out == 1U);
    CHECK(dmp_generation_next(1U, &out) == DMP_OK && out == 2U);
    CHECK(dmp_generation_next(UINT64_MAX - 1U, &out) == DMP_OK && out == UINT64_MAX);

    out = UINT64_C(123456);
    CHECK(dmp_generation_next(UINT64_MAX, &out) == DMP_LIMIT_EXHAUSTED);
    CHECK(out == UINT64_C(123456));
    CHECK(dmp_generation_next(0U, NULL) == DMP_INVALID_ARGUMENT);
    return 0;
}

static int test_status_names(void)
{
    static const char *const expected[] = {
        "ok", "invalid_argument", "malformed", "unsupported",
        "integrity_failure", "authentication_failure", "context_required",
        "incomplete", "duplicate", "quota_exhausted", "deadline_expired",
        "busy", "cancelled", "stale_handle", "limit_exhausted",
    };
    size_t index;

    for (index = 0U; index < sizeof expected / sizeof expected[0]; ++index) {
        CHECK(strcmp(dmp_status_name((dmp_status)index), expected[index]) == 0);
    }
    CHECK(strcmp(dmp_status_name((dmp_status)-1), "unknown") == 0);
    CHECK(strcmp(dmp_status_name((dmp_status)INT32_MAX), "unknown") == 0);
    return 0;
}

int main(void)
{
    CHECK(test_bytes_slice() == 0);
    CHECK(test_deadlines() == 0);
    CHECK(test_generations() == 0);
    CHECK(test_status_names() == 0);
    return 0;
}
