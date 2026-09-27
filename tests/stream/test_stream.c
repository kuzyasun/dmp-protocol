#include "dmp/integrity.h"
#include "dmp/stream.h"
#include "cobs.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,     \
                          __LINE__, #condition);                                \
            return 1;                                                           \
        }                                                                       \
    } while (0)

static const uint8_t CORE[] = { 0x45U, 0x02U, 0xAAU, 0xBBU };
static const uint8_t L_GOLDEN[] = {
    0x44U, 0x4DU, 0x50U, 0x04U, 0x45U, 0x02U, 0xAAU, 0xBBU,
};
static const uint8_t R_GOLDEN[] = {
    0x09U, 0x45U, 0x02U, 0xAAU, 0xBBU, 0x39U, 0xEEU, 0x4CU, 0x1FU, 0x00U,
};

static int test_crc(void)
{
    static const uint8_t input[] = "123456789";
    uint32_t out = UINT32_C(0xDEADBEEF);
    CHECK(dmp_crc32c((dmp_bytes){ input, sizeof input - 1U }, &out) == DMP_OK);
    CHECK(out == UINT32_C(0xE3069283));
    CHECK(dmp_crc32c((dmp_bytes){ NULL, 0U }, &out) == DMP_OK);
    CHECK(out == 0U);
    out = UINT32_C(0x12345678);
    CHECK(dmp_crc32c((dmp_bytes){ NULL, 1U }, &out) == DMP_INVALID_ARGUMENT);
    CHECK(out == UINT32_C(0x12345678));
    CHECK(dmp_crc32c((dmp_bytes){ NULL, 0U }, NULL) == DMP_INVALID_ARGUMENT);
    return 0;
}

static int test_raw_cobs(void)
{
    static const uint8_t simple[] = { 0x11U, 0x00U, 0x22U };
    static const uint8_t simple_expected[] = { 0x02U, 0x11U, 0x02U, 0x22U };
    uint8_t input[508], encoded[520], decode[520];
    size_t written = 0U, decoded = 0U, i;

    CHECK(dmp_cobs_encode((dmp_bytes){ simple, sizeof simple },
                          (dmp_buffer){ encoded, sizeof encoded }, &written) == DMP_OK);
    CHECK(written == sizeof simple_expected);
    CHECK(memcmp(encoded, simple_expected, sizeof simple_expected) == 0);

    memset(input, 0x11, sizeof input);
    CHECK(dmp_cobs_encode((dmp_bytes){ input, 254U },
                          (dmp_buffer){ encoded, sizeof encoded }, &written) == DMP_OK);
    CHECK(written == 256U && encoded[0] == 0xFFU && encoded[255] == 0x01U);
    for (i = 1U; i <= 254U; ++i) CHECK(encoded[i] == 0x11U);
    memcpy(decode, encoded, written);
    CHECK(dmp_cobs_decode_canonical(decode, written, sizeof decode, &decoded) == DMP_OK);
    CHECK(decoded == 254U && memcmp(decode, input, decoded) == 0);
    CHECK(dmp_cobs_decode_canonical(encoded, written - 1U, sizeof decode,
                                     &decoded) == DMP_MALFORMED);

    CHECK(dmp_cobs_encode((dmp_bytes){ input, 255U },
                          (dmp_buffer){ encoded, sizeof encoded }, &written) == DMP_OK);
    CHECK(written == 257U && encoded[0] == 0xFFU && encoded[255] == 0x02U &&
          encoded[256] == 0x11U);
    CHECK(dmp_cobs_encode((dmp_bytes){ input, 508U },
                          (dmp_buffer){ encoded, sizeof encoded }, &written) == DMP_OK);
    CHECK(written == 511U && encoded[0] == 0xFFU && encoded[255] == 0xFFU &&
          encoded[510] == 0x01U);
    memcpy(decode, encoded, written);
    CHECK(dmp_cobs_decode_canonical(decode, written, sizeof decode, &decoded) == DMP_OK);
    CHECK(decoded == 508U && memcmp(decode, input, decoded) == 0);
    CHECK(dmp_cobs_decode_canonical(encoded, written - 1U, sizeof decode,
                                     &decoded) == DMP_MALFORMED);
    return 0;
}

static int test_encoding(void)
{
    uint8_t out[32], before[32];
    size_t written;

    memset(out, 0xA5, sizeof out);
    CHECK(dmp_stream_encode(DMP_STREAM_L, (dmp_bytes){ CORE, sizeof CORE },
                            (dmp_buffer){ out, sizeof out }, &written) == DMP_OK);
    CHECK(written == sizeof L_GOLDEN && memcmp(out, L_GOLDEN, written) == 0);
    memset(out, 0xA5, sizeof out);
    CHECK(dmp_stream_encode(DMP_STREAM_R, (dmp_bytes){ CORE, sizeof CORE },
                            (dmp_buffer){ out, sizeof out }, &written) == DMP_OK);
    CHECK(written == sizeof R_GOLDEN && memcmp(out, R_GOLDEN, written) == 0);

    memset(out, 0x6D, sizeof out);
    memcpy(before, out, sizeof out);
    written = 99U;
    CHECK(dmp_stream_encode(DMP_STREAM_L, (dmp_bytes){ CORE, sizeof CORE },
                            (dmp_buffer){ out, sizeof L_GOLDEN - 1U }, &written) ==
          DMP_QUOTA_EXHAUSTED);
    CHECK(written == 0U && memcmp(out, before, sizeof out) == 0);
    memset(out, 0x6D, sizeof out);
    memcpy(before, out, sizeof out);
    written = 99U;
    CHECK(dmp_stream_encode(DMP_STREAM_R, (dmp_bytes){ CORE, sizeof CORE },
                            (dmp_buffer){ out, sizeof R_GOLDEN - 1U }, &written) ==
          DMP_QUOTA_EXHAUSTED);
    CHECK(written == 0U && memcmp(out, before, sizeof out) == 0);
    CHECK(dmp_stream_encoded_bound(DMP_STREAM_R, SIZE_MAX, &written) ==
          DMP_LIMIT_EXHAUSTED);
    CHECK(dmp_stream_encoded_bound(DMP_STREAM_L, 4U, &written) == DMP_OK &&
          written == 12U);
    return 0;
}

static int test_zero_adjacent_full_block(void)
{
    uint8_t input[256], encoded[260], decoded[260];
    size_t written, size, i;
    memset(input, 0x11, 254U);
    input[254] = 0U;
    input[255] = 0x22U;
    CHECK(dmp_cobs_encode((dmp_bytes){ input, sizeof input },
                          (dmp_buffer){ encoded, sizeof encoded }, &written) == DMP_OK);
    CHECK(written == 258U && encoded[0] == 0xffU);
    for (i = 1U; i <= 254U; ++i) CHECK(encoded[i] == 0x11U);
    CHECK(encoded[255] == 1U && encoded[256] == 2U && encoded[257] == 0x22U);
    memcpy(decoded, encoded, written);
    CHECK(dmp_cobs_decode_canonical(decoded, written, sizeof decoded, &size) == DMP_OK);
    CHECK(size == sizeof input && memcmp(decoded, input, size) == 0);

    input[0] = 0U;
    memset(input + 1U, 0x11, 254U);
    CHECK(dmp_cobs_encode((dmp_bytes){ input, 255U },
                          (dmp_buffer){ encoded, sizeof encoded }, &written) == DMP_OK);
    CHECK(written == 257U && encoded[0] == 1U && encoded[1] == 0xffU && encoded[256] == 1U);
    memcpy(decoded, encoded, written);
    CHECK(dmp_cobs_decode_canonical(decoded, written, sizeof decoded, &size) == DMP_OK);
    CHECK(size == 255U && memcmp(decoded, input, size) == 0);
    return 0;
}

static dmp_stream_config config(dmp_stream_mode mode)
{
    dmp_stream_config value = { mode, 32U, 10U };
    return value;
}

static int test_l_splits_and_concat(void)
{
    uint8_t storage[40], wire[32];
    size_t split, written;

    CHECK(dmp_stream_encode(DMP_STREAM_L, (dmp_bytes){ CORE, sizeof CORE },
                            (dmp_buffer){ wire, sizeof wire }, &written) == DMP_OK);
    for (split = 0U; split <= written; ++split) {
        dmp_stream_decoder decoder;
        dmp_stream_result first, second;
        CHECK(dmp_stream_init(&decoder, config(DMP_STREAM_L),
                              (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
        first = dmp_stream_feed(&decoder, (dmp_bytes){ wire, split }, 1U);
        CHECK(first.status == DMP_OK && first.consumed == split);
        if (split < written) {
            second = dmp_stream_feed(&decoder,
                (dmp_bytes){ wire + split, written - split }, 1U);
            CHECK(second.status == DMP_OK && second.event == DMP_STREAM_FRAME);
            CHECK(second.consumed == written - split && second.frame.size == sizeof CORE);
            CHECK(memcmp(second.frame.data, CORE, sizeof CORE) == 0);
        } else {
            CHECK(first.event == DMP_STREAM_FRAME && first.frame.size == sizeof CORE);
            CHECK(memcmp(first.frame.data, CORE, sizeof CORE) == 0);
        }
    }
    {
        dmp_stream_decoder decoder;
        uint8_t pair[sizeof L_GOLDEN * 2U];
        dmp_stream_result one, two;
        memcpy(pair, L_GOLDEN, sizeof L_GOLDEN);
        memcpy(pair + sizeof L_GOLDEN, L_GOLDEN, sizeof L_GOLDEN);
        CHECK(dmp_stream_init(&decoder, config(DMP_STREAM_L),
                              (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
        one = dmp_stream_feed(&decoder, (dmp_bytes){ pair, sizeof pair }, 1U);
        CHECK(one.event == DMP_STREAM_FRAME && one.consumed == sizeof L_GOLDEN);
        CHECK(memcmp(one.frame.data, CORE, sizeof CORE) == 0);
        two = dmp_stream_feed(&decoder,
            (dmp_bytes){ pair + one.consumed, sizeof pair - one.consumed }, 1U);
        CHECK(two.event == DMP_STREAM_FRAME && two.consumed == sizeof L_GOLDEN);
        CHECK(memcmp(two.frame.data, CORE, sizeof CORE) == 0);
    }
    return 0;
}

static int test_r_splits_and_resync(void)
{
    uint8_t storage[40], wire[32];
    size_t split, written;

    CHECK(dmp_stream_encode(DMP_STREAM_R, (dmp_bytes){ CORE, sizeof CORE },
                            (dmp_buffer){ wire, sizeof wire }, &written) == DMP_OK);
    for (split = 0U; split <= written + 1U; ++split) {
        uint8_t stream[sizeof R_GOLDEN + 1U];
        dmp_stream_decoder decoder;
        dmp_stream_result first, second;
        stream[0] = 0U;
        memcpy(stream + 1U, wire, written);
        CHECK(dmp_stream_init(&decoder, config(DMP_STREAM_R),
                              (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
        first = dmp_stream_feed(&decoder, (dmp_bytes){ stream, split }, 1U);
        CHECK(first.status == DMP_OK && first.consumed == split);
        if (split < written + 1U) {
            second = dmp_stream_feed(&decoder,
                (dmp_bytes){ stream + split, written + 1U - split }, 1U);
            CHECK(second.status == DMP_OK && second.event == DMP_STREAM_FRAME);
            CHECK(second.frame.size == sizeof CORE &&
                  memcmp(second.frame.data, CORE, sizeof CORE) == 0);
        } else {
            CHECK(first.event == DMP_STREAM_FRAME && first.frame.size == sizeof CORE);
            CHECK(memcmp(first.frame.data, CORE, sizeof CORE) == 0);
        }
    }
    {
        dmp_stream_decoder decoder;
        uint8_t corrupt[sizeof R_GOLDEN * 2U + 1U];
        dmp_stream_result bad, good;
        corrupt[0] = 0U;
        memcpy(corrupt + 1U, R_GOLDEN, sizeof R_GOLDEN - 1U);
        corrupt[sizeof R_GOLDEN] = 0U;
        memcpy(corrupt + sizeof R_GOLDEN + 1U, R_GOLDEN, sizeof R_GOLDEN - 1U);
        corrupt[sizeof corrupt - 1U] = 0U;
        corrupt[2] ^= 0x01U;
        CHECK(dmp_stream_init(&decoder, config(DMP_STREAM_R),
                              (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
        bad = dmp_stream_feed(&decoder, (dmp_bytes){ corrupt, sizeof corrupt }, 1U);
        CHECK(bad.event == DMP_STREAM_DISCARDED &&
              bad.status == DMP_INTEGRITY_FAILURE);
        good = dmp_stream_feed(&decoder,
            (dmp_bytes){ corrupt + bad.consumed, sizeof corrupt - bad.consumed }, 1U);
        CHECK(good.event == DMP_STREAM_FRAME && good.frame.size == sizeof CORE);
        CHECK(memcmp(good.frame.data, CORE, sizeof CORE) == 0);
    }
    return 0;
}

static int test_l_errors_and_deadline(void)
{
    uint8_t storage[40], bad_magic[] = { 0x44U, 0x00U };
    uint8_t bad_len[] = { 0x44U, 0x4DU, 0x50U, 0x84U, 0x00U };
    dmp_stream_decoder decoder, before;
    dmp_stream_result event;

    CHECK(dmp_stream_init(&decoder, config(DMP_STREAM_L),
                          (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ bad_magic, sizeof bad_magic }, 1U);
    CHECK(event.status == DMP_MALFORMED && event.event == DMP_STREAM_SESSION_FAILED);
    CHECK(dmp_stream_reset(&decoder, 1U) == DMP_OK);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ bad_len, sizeof bad_len }, 2U);
    CHECK(event.status == DMP_MALFORMED && event.event == DMP_STREAM_SESSION_FAILED);

    CHECK(dmp_stream_reset(&decoder, 3U) == DMP_OK);
    before = decoder;
    CHECK(dmp_stream_reset(&decoder, 2U) == DMP_INVALID_ARGUMENT);
    CHECK(memcmp(&decoder, &before, sizeof decoder) == 0);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ L_GOLDEN, 1U }, 5U);
    CHECK(event.event == DMP_STREAM_NONE && decoder.deadline == 15U);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ L_GOLDEN + 1U, 2U }, 14U);
    CHECK(event.event == DMP_STREAM_NONE && decoder.deadline == 15U);
    event = dmp_stream_poll(&decoder, 15U);
    CHECK(event.status == DMP_DEADLINE_EXPIRED &&
          event.event == DMP_STREAM_SESSION_FAILED);
    before = decoder;
    event = dmp_stream_feed(&decoder, (dmp_bytes){ CORE, 1U }, 14U);
    CHECK(event.status == DMP_INVALID_ARGUMENT && event.consumed == 0U);
    CHECK(memcmp(&decoder, &before, sizeof decoder) == 0);

    CHECK(dmp_stream_reset(&decoder, 15U) == DMP_OK);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ L_GOLDEN, 1U }, 20U);
    CHECK(event.event == DMP_STREAM_NONE);
    event = dmp_stream_feed(&decoder,
        (dmp_bytes){ L_GOLDEN + 1U, sizeof L_GOLDEN - 1U }, 30U);
    CHECK(event.event == DMP_STREAM_FRAME); /* equality is admitted before poll */
    event = dmp_stream_feed(&decoder, (dmp_bytes){ L_GOLDEN, 1U }, UINT64_MAX);
    CHECK(event.status == DMP_LIMIT_EXHAUSTED &&
          event.event == DMP_STREAM_SESSION_FAILED && event.consumed == 1U);
    return 0;
}

static int test_r_deadline_overflow_and_canaries(void)
{
    uint8_t raw[80], guarded[42], storage_guarded[42];
    dmp_stream_decoder decoder, before;
    dmp_stream_result event;
    size_t written;

    memset(guarded, 0xC7, sizeof guarded);
    CHECK(dmp_stream_encode(DMP_STREAM_R, (dmp_bytes){ CORE, sizeof CORE },
                            (dmp_buffer){ guarded + 1U, sizeof R_GOLDEN }, &written) == DMP_OK);
    CHECK(written == sizeof R_GOLDEN);
    CHECK(guarded[0] == 0xC7U && guarded[sizeof R_GOLDEN + 1U] == 0xC7U);
    CHECK(dmp_stream_encode(DMP_STREAM_R, (dmp_bytes){ CORE, sizeof CORE },
                            (dmp_buffer){ guarded + 1U, sizeof R_GOLDEN - 1U }, &written) ==
          DMP_QUOTA_EXHAUSTED);
    CHECK(written == 0U && guarded[0] == 0xC7U && guarded[sizeof R_GOLDEN + 1U] == 0xC7U);

    memset(storage_guarded, 0xB4, sizeof storage_guarded);
    CHECK(dmp_stream_init(&decoder, config(DMP_STREAM_R),
                          (dmp_buffer){ storage_guarded + 1U, 40U }, 0U) == DMP_OK);
    CHECK(storage_guarded[0] == 0xB4U && storage_guarded[41] == 0xB4U);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ (const uint8_t *)"\0\x09", 2U }, 1U);
    CHECK(event.event == DMP_STREAM_NONE && decoder.deadline == 11U);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ (const uint8_t *)"\x45", 1U }, 10U);
    CHECK(event.event == DMP_STREAM_NONE && decoder.deadline == 11U);
    event = dmp_stream_poll(&decoder, 11U);
    CHECK(event.status == DMP_DEADLINE_EXPIRED && event.event == DMP_STREAM_DISCARDED);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, sizeof R_GOLDEN }, 11U);
    CHECK(event.event == DMP_STREAM_NONE); /* still discarding through delimiter */
    event = dmp_stream_feed(&decoder, (dmp_bytes){ (const uint8_t *)"\0", 1U }, 11U);
    CHECK(event.event == DMP_STREAM_NONE);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, sizeof R_GOLDEN }, 11U);
    CHECK(event.event == DMP_STREAM_FRAME && event.frame.size == sizeof CORE);

    CHECK(dmp_stream_reset(&decoder, 11U) == DMP_OK);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ (const uint8_t *)"\0\x09", 2U }, 12U);
    CHECK(event.event == DMP_STREAM_NONE);
    event = dmp_stream_feed(&decoder,
        (dmp_bytes){ R_GOLDEN + 1U, sizeof R_GOLDEN - 1U }, 22U);
    CHECK(event.event == DMP_STREAM_FRAME); /* delimiter at exact deadline wins */

    CHECK(dmp_stream_reset(&decoder, 22U) == DMP_OK);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ (const uint8_t *)"\0", 1U }, UINT64_MAX);
    CHECK(event.status == DMP_OK);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, 1U }, UINT64_MAX);
    CHECK(event.status == DMP_LIMIT_EXHAUSTED &&
          event.event == DMP_STREAM_SESSION_FAILED && event.consumed == 1U);

    before = decoder;
    raw[0] = 0x01U;
    event = dmp_stream_feed(&decoder, (dmp_bytes){ raw, 1U }, UINT64_MAX - 1U);
    CHECK(event.status == DMP_INVALID_ARGUMENT && event.consumed == 0U);
    CHECK(memcmp(&decoder, &before, sizeof decoder) == 0);
    event = dmp_stream_feed(&decoder,
        (dmp_bytes){ decoder.storage.data, 1U }, UINT64_MAX);
    CHECK(event.status == DMP_INVALID_ARGUMENT && event.consumed == 0U);
    CHECK(memcmp(&decoder, &before, sizeof decoder) == 0);
    return 0;
}

static int test_startup_size_and_reset(void)
{
    uint8_t small[7], exact_l[32], storage[80], marker = 0U;
    dmp_stream_decoder decoder, before;
    dmp_stream_result event;
    dmp_stream_config cfg = config(DMP_STREAM_R);

    memset(&decoder, 0x5A, sizeof decoder);
    before = decoder;
    CHECK(dmp_stream_init(&decoder, cfg, (dmp_buffer){ small, sizeof small }, 0U) ==
          DMP_QUOTA_EXHAUSTED);
    CHECK(memcmp(&decoder, &before, sizeof decoder) == 0);
    cfg.mode = DMP_STREAM_L;
    cfg.max_core_bytes = sizeof CORE;
    CHECK(dmp_stream_init(&decoder, cfg, (dmp_buffer){ exact_l, sizeof CORE }, 0U) == DMP_OK);
    CHECK(dmp_stream_init(&decoder, cfg, (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
    cfg.mode = DMP_STREAM_R;
    cfg.max_core_bytes = 32U;
    CHECK(dmp_stream_init(&decoder, cfg, (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ CORE, sizeof CORE }, 1U);
    CHECK(event.event == DMP_STREAM_NONE); /* startup waits for a delimiter */
    event = dmp_stream_feed(&decoder, (dmp_bytes){ &marker, 1U }, 1U);
    CHECK(event.event == DMP_STREAM_NONE);
    CHECK(dmp_stream_reset(&decoder, 0U) == DMP_INVALID_ARGUMENT);

    /* An oversized caller buffer does not increase the configured R limit. */
    {
        uint8_t oversized[40];
        oversized[0] = 0U;
        memset(oversized + 1U, 0x11, 38U);
        oversized[39] = 0U;
        CHECK(dmp_stream_init(&decoder, cfg, (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
        event = dmp_stream_feed(&decoder, (dmp_bytes){ oversized, sizeof oversized }, 1U);
        CHECK(event.event == DMP_STREAM_DISCARDED && event.status == DMP_MALFORMED);
        CHECK(event.consumed == 39U);
        event = dmp_stream_feed(&decoder, (dmp_bytes){ oversized + 39U, 1U }, 1U);
        CHECK(event.event == DMP_STREAM_NONE);
        event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, sizeof R_GOLDEN }, 1U);
        CHECK(event.event == DMP_STREAM_FRAME && event.frame.size == sizeof CORE);
    }
    return 0;
}

static int test_restart_prefix_and_bad_lengths(void)
{
    uint8_t storage[40], prefixed[sizeof R_GOLDEN + 1U];
    dmp_stream_decoder decoder;
    dmp_stream_result event;
    const uint8_t invalid_lengths[][8] = {
        {0x44,0x4d,0x50,0x00}, {0x44,0x4d,0x50,0x01},
        {0x44,0x4d,0x50,0x21},
        {0x44,0x4d,0x50,0x80,0x80,0x80,0x80,0x10},
        {0x44,0x4d,0x50,0x80,0x80,0x80,0x80,0x80}
    };
    const size_t lengths[] = {4U,4U,4U,8U,8U};
    size_t i;
    for (i = 0U; i < sizeof lengths / sizeof lengths[0]; ++i) {
        CHECK(dmp_stream_init(&decoder, config(DMP_STREAM_L),
                              (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
        event = dmp_stream_feed(&decoder, (dmp_bytes){ invalid_lengths[i], lengths[i] }, 0U);
        CHECK(event.event == DMP_STREAM_SESSION_FAILED && event.status == DMP_MALFORMED);
        event = dmp_stream_feed(&decoder, (dmp_bytes){ L_GOLDEN, sizeof L_GOLDEN }, 1U);
        CHECK(event.status != DMP_OK && event.consumed == 0U && event.frame.size == 0U);
        event = dmp_stream_poll(&decoder, 100U);
        CHECK(event.status != DMP_OK);
        CHECK(dmp_stream_reset(&decoder, 2U) == DMP_INVALID_ARGUMENT);
        CHECK(dmp_stream_reset(&decoder, 100U) == DMP_OK);
    }
    CHECK(dmp_stream_init(&decoder, config(DMP_STREAM_R),
                          (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, sizeof R_GOLDEN }, 0U);
    CHECK(event.event == DMP_STREAM_NONE && event.consumed == sizeof R_GOLDEN);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, sizeof R_GOLDEN }, 1U);
    CHECK(event.event == DMP_STREAM_FRAME);
    CHECK(dmp_stream_reset(&decoder, 2U) == DMP_OK);
    /* Independent restart in a frame loses the remaining tail through delimiter. */
    event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN + 3U, sizeof R_GOLDEN - 3U }, 2U);
    CHECK(event.event == DMP_STREAM_NONE);
    CHECK(dmp_stream_reset(&decoder, 3U) == DMP_OK);
    prefixed[0] = 0U;
    memcpy(prefixed + 1U, R_GOLDEN, sizeof R_GOLDEN);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ prefixed, sizeof prefixed }, 3U);
    CHECK(event.event == DMP_STREAM_FRAME && event.consumed == sizeof prefixed);
    CHECK(memcmp(event.frame.data, CORE, sizeof CORE) == 0);
    return 0;
}

static int test_r_malformed_and_late_feed(void)
{
    uint8_t storage[272], wire[272], large[251] = {0};
    const uint8_t sync = 0U;
    const uint8_t bad[][4] = { {1,0}, {4,0x11,0x22,0}, {2,0x11,0} };
    const size_t lengths[] = {2U,4U,3U};
    dmp_stream_decoder decoder;
    dmp_stream_result event;
    size_t i, written;
    for (i = 0U; i < sizeof lengths / sizeof lengths[0]; ++i) {
        CHECK(dmp_stream_init(&decoder, config(DMP_STREAM_R),
                              (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
        event = dmp_stream_feed(&decoder, (dmp_bytes){ &sync, 1U }, 0U);
        CHECK(event.event == DMP_STREAM_NONE);
        event = dmp_stream_feed(&decoder, (dmp_bytes){ bad[i], lengths[i] }, 1U);
        CHECK(event.event == DMP_STREAM_DISCARDED && event.status == DMP_MALFORMED);
        CHECK(event.frame.data == NULL && event.frame.size == 0U);
        event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, sizeof R_GOLDEN }, 1U);
        CHECK(event.event == DMP_STREAM_FRAME);
    }
    CHECK(dmp_stream_encode(DMP_STREAM_R, (dmp_bytes){ large, sizeof large },
                            (dmp_buffer){ wire, sizeof wire }, &written) == DMP_OK);
    CHECK(dmp_stream_init(&decoder, (dmp_stream_config){ DMP_STREAM_R, 250U, 10U },
                          (dmp_buffer){ storage, sizeof storage }, 0U) == DMP_OK);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ &sync, 1U }, 0U);
    CHECK(event.event == DMP_STREAM_NONE);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ wire, written }, 1U);
    CHECK(event.event == DMP_STREAM_DISCARDED && event.status == DMP_MALFORMED);
    CHECK(event.consumed == written); /* Encoded candidate fits, decoded bytes do not. */
    event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, sizeof R_GOLDEN }, 1U);
    CHECK(event.event == DMP_STREAM_FRAME);

    CHECK(dmp_stream_reset(&decoder, 2U) == DMP_OK);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ &sync, 1U }, 2U);
    CHECK(event.event == DMP_STREAM_NONE);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, 1U }, 2U);
    CHECK(event.event == DMP_STREAM_NONE);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, sizeof R_GOLDEN }, 13U);
    CHECK(event.event == DMP_STREAM_DISCARDED && event.status == DMP_DEADLINE_EXPIRED);
    CHECK(event.consumed == 0U);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, sizeof R_GOLDEN }, 13U);
    CHECK(event.event == DMP_STREAM_NONE);
    event = dmp_stream_feed(&decoder, (dmp_bytes){ R_GOLDEN, sizeof R_GOLDEN }, 13U);
    CHECK(event.event == DMP_STREAM_FRAME);
    return 0;
}

int main(void)
{
    CHECK(test_crc() == 0);
    CHECK(test_raw_cobs() == 0);
    CHECK(test_encoding() == 0);
    CHECK(test_zero_adjacent_full_block() == 0);
    CHECK(test_l_splits_and_concat() == 0);
    CHECK(test_r_splits_and_resync() == 0);
    CHECK(test_l_errors_and_deadline() == 0);
    CHECK(test_r_deadline_overflow_and_canaries() == 0);
    CHECK(test_startup_size_and_reset() == 0);
    CHECK(test_restart_prefix_and_bad_lengths() == 0);
    CHECK(test_r_malformed_and_late_feed() == 0);
    return 0;
}
