#include "dmp/core.h"
#include "dmp/integrity.h"

#if defined(DMP_SIZE_PROBE_STREAM_R)
#include "dmp/stream.h"
#endif

#if defined(ESP_PLATFORM)
#include <stdio.h>
#include <stdlib.h>
#endif
#include <string.h>

#if defined(DMP_SIZE_PROBE_STREAM_R)
static dmp_bytes stream_round_trip(dmp_bytes core)
{
    static uint8_t scratch[263];
    const dmp_stream_config config = { DMP_STREAM_R, 256U, 26U };
    const uint8_t delimiter = 0U;
    uint8_t wire[263];
    size_t written;
    dmp_stream_decoder decoder;
    dmp_stream_result rx;

    if (dmp_stream_encode(DMP_STREAM_R, core, (dmp_buffer){ wire, sizeof wire },
                          &written) != DMP_OK ||
        dmp_stream_init(&decoder, config, (dmp_buffer){ scratch, sizeof scratch },
                        0U) != DMP_OK) {
        return (dmp_bytes){ NULL, 0U };
    }
    rx = dmp_stream_feed(&decoder, (dmp_bytes){ &delimiter, 1U }, 0U);
    if (rx.status != DMP_OK || rx.event != DMP_STREAM_NONE || rx.consumed != 1U) {
        return (dmp_bytes){ NULL, 0U };
    }
    rx = dmp_stream_feed(&decoder, (dmp_bytes){ wire, written }, 1U);
    if (rx.status != DMP_OK || rx.event != DMP_STREAM_FRAME || rx.consumed != written) {
        return (dmp_bytes){ NULL, 0U };
    }
    return rx.frame;
}
#endif

static int run_probe(void)
{
    /* Fixed CRC-protected telemetry vector also used by core.pipeline. */
    static const uint8_t expected[] = {
        0x45U, 0x04U, 0x10U, 0x01U, 0xaaU, 0xbbU, 0xa3U, 0xd5U, 0x0eU, 0xbdU
    };
    const dmp_core_limits limits = { 256U, 1024U, 32U };
    const dmp_frame_spec spec = {
        .fields = { .type = DMP_TYPE_TELEM, .options = DMP_OPT_INTEGRITY, .integrity = 1U },
        .payload = { expected + 4U, 2U },
        .trailer = { expected + 6U, 4U },
    };
    uint8_t encoded[256];
    size_t written;
    uint32_t crc;
    dmp_frame_view frame;
    dmp_bytes input;

    if (dmp_core_encode(&spec, &limits, (dmp_buffer){ encoded, sizeof encoded },
                        &written) != DMP_OK) {
        return 1;
    }
    input = (dmp_bytes){ encoded, written };
#if defined(DMP_SIZE_PROBE_STREAM_R)
    input = stream_round_trip(input);
#endif
    if (input.size != sizeof expected || memcmp(input.data, expected, sizeof expected) != 0) {
        return 2;
    }
    dmp_parse_result result = dmp_core_parse(input, &limits, &frame);
    if (result.status != DMP_OK || result.offset != input.size ||
        frame.fields.type != DMP_TYPE_TELEM || frame.fields.integrity != 1U ||
        frame.payload.size != spec.payload.size || frame.trailer.size != spec.trailer.size) {
        return 3;
    }
    if (dmp_crc32c((dmp_bytes){ input.data, input.size - frame.trailer.size },
                   &crc) != DMP_OK || crc != UINT32_C(0xbd0ed5a3)) {
        return 4;
    }
    return 0;
}

#if defined(ESP_PLATFORM)
void app_main(void)
{
    int result = run_probe();
    printf("dmp_size_probe: %d\n", result);
    if (result != 0) {
        abort();
    }
}
#else
int main(void)
{
    return run_probe();
}
#endif
