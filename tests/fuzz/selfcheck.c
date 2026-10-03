#include "fuzz_core.h"
#include "fuzz_limits.h"
#include "fuzz_stream.h"

#include "dmp/core.h"
#include "dmp/stream.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,     \
                          __LINE__, #condition);                              \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int test_bounds_and_cap(void)
{
    uint8_t oversized[DMP_FUZZ_MAX_INPUT + 1U];
    uint8_t storage[DMP_FUZZ_STREAM_STORAGE];
    dmp_stream_decoder decoder;
    dmp_stream_config config;
    size_t bound = 0U;
    uint32_t core_before;
    uint32_t stream_before;

    CHECK(dmp_stream_encoded_bound(DMP_STREAM_R, DMP_FUZZ_STREAM_MAX_CORE,
                                   &bound) == DMP_OK);
    CHECK(bound == DMP_FUZZ_STREAM_STORAGE);
    CHECK(dmp_stream_encoded_bound(DMP_STREAM_L, DMP_FUZZ_STREAM_MAX_CORE,
                                   &bound) == DMP_OK);
    CHECK(bound >= DMP_FUZZ_STREAM_MAX_CORE);
    CHECK(DMP_FUZZ_STREAM_MAX_CORE <= DMP_FUZZ_STREAM_STORAGE);

    config.mode = DMP_STREAM_L;
    config.max_core_bytes = DMP_FUZZ_STREAM_MAX_CORE;
    config.partial_timeout_ms = DMP_FUZZ_STREAM_TIMEOUT_MS;
    CHECK(dmp_stream_init(&decoder, config,
                          (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
    config.mode = DMP_STREAM_R;
    CHECK(dmp_stream_init(&decoder, config,
                          (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);

    memset(oversized, 0xA5, sizeof oversized);
    core_before = dmp_fuzz_core_observations();
    stream_before = dmp_fuzz_stream_observations();
    CHECK(dmp_fuzz_core(NULL, 1U) == 0);
    CHECK(dmp_fuzz_stream(NULL, 1U) == 0);
    CHECK(dmp_fuzz_core(oversized, sizeof oversized) == 0);
    CHECK(dmp_fuzz_stream(oversized, sizeof oversized) == 0);
    CHECK(dmp_fuzz_core_observations() == core_before);
    CHECK(dmp_fuzz_stream_observations() == stream_before);
    return 0;
}

static int test_core_structural(void)
{
    static const uint8_t minimal[] = { 0x45U, 0x02U, 0xAAU, 0xBBU };
    const dmp_core_limits limits = {
        .max_frame_bytes = DMP_FUZZ_MAX_INPUT,
        .max_message_bytes = DMP_FUZZ_CORE_MAX_MESSAGE,
        .max_fragments = DMP_FUZZ_CORE_MAX_FRAGMENTS
    };
    dmp_frame_view view;
    dmp_parse_result parsed;
    uint32_t before;

    parsed = dmp_core_parse((dmp_bytes){ minimal, sizeof minimal }, &limits, &view);
    CHECK(parsed.status == DMP_OK);
    CHECK(parsed.offset == sizeof minimal);
    CHECK(view.payload.size == 2U);

    before = dmp_fuzz_core_observations();
    CHECK(dmp_fuzz_core(NULL, 0U) == 0);
    CHECK(dmp_fuzz_core(minimal, sizeof minimal) == 0);
    CHECK(dmp_fuzz_core_observations() != before);
    return 0;
}

static int test_stream_framing(void)
{
    static const uint8_t core_bytes[] = { 0x45U, 0x02U, 0xAAU, 0xBBU };
    uint8_t wire[64];
    size_t written = 0U;
    uint32_t before;
    int mode;

    for (mode = (int)DMP_STREAM_L; mode <= (int)DMP_STREAM_R; ++mode) {
        CHECK(dmp_stream_encode((dmp_stream_mode)mode,
                                (dmp_bytes){ core_bytes, sizeof core_bytes },
                                (dmp_buffer){ wire, sizeof wire },
                                &written) == DMP_OK);
        CHECK(written > 0U && written <= DMP_FUZZ_MAX_INPUT);
        before = dmp_fuzz_stream_observations();
        CHECK(dmp_fuzz_stream(wire, written) == 0);
        CHECK(dmp_fuzz_stream_observations() != before);
    }
    before = dmp_fuzz_stream_observations();
    CHECK(dmp_fuzz_stream(NULL, 0U) == 0);
    CHECK(dmp_fuzz_stream_observations() != before);
    return 0;
}

int main(void)
{
    CHECK(test_bounds_and_cap() == 0);
    CHECK(test_core_structural() == 0);
    CHECK(test_stream_framing() == 0);
    (void)printf("dmp fuzz selfcheck ok\n");
    return 0;
}
