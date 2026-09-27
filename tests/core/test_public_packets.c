#include "dmp/core.h"
#include "dmp/stream.h"
#include <stdio.h>
#include <string.h>
#include "public_packets.h"

#define CHECK(condition) do { \
    if (!(condition)) { \
        (void)fprintf(stderr, "%s:%d: packet %zu: %s\n", __FILE__, __LINE__, index, #condition); \
        return 1; \
    } \
} while (0)

int main(void)
{
    const dmp_core_limits limits = { 4096U, 65519U, 32U };
    const dmp_stream_config config = { DMP_STREAM_R, 4096U, 26U };
    const uint8_t sync = 0;
    uint8_t output[4096], wire[4120], scratch[4120];
    size_t index;
    for (index = 0; index < sizeof packets / sizeof packets[0]; ++index) {
        const public_packet *packet = &packets[index];
        dmp_frame_view view;
        dmp_frame_spec spec;
        dmp_stream_decoder decoder;
        dmp_stream_result result;
        size_t written;
        CHECK(dmp_core_parse((dmp_bytes){ packet->data, packet->size }, &limits, &view).status == DMP_OK);
        CHECK(view.header.size == packet->header_size && view.payload.size == packet->payload_size);
        CHECK(view.fields.seq == packet->seq && view.fields.security.pn == packet->pn);
        CHECK(view.fields.security.cipher == packet->cipher && view.trailer.size == 16U);
        CHECK(view.payload.data == packet->data + packet->header_size);
        spec.fields = view.fields;
        spec.extensions = view.extensions;
        spec.payload = (dmp_bytes){ NULL, view.payload.size };
        spec.trailer = (dmp_bytes){ NULL, 16U };
        CHECK(dmp_core_encode_header(&spec, &limits,
              (dmp_buffer){ output, sizeof output }, &written) == DMP_OK);
        CHECK(written == packet->header_size && memcmp(output, packet->data, written) == 0);
        spec.payload = view.payload;
        spec.trailer = view.trailer;
        CHECK(dmp_core_encode(&spec, &limits,
              (dmp_buffer){ output, sizeof output }, &written) == DMP_OK);
        CHECK(written == packet->size && memcmp(output, packet->data, written) == 0);
        CHECK(dmp_stream_encode(DMP_STREAM_R, (dmp_bytes){ output, written },
              (dmp_buffer){ wire, sizeof wire }, &written) == DMP_OK);
        CHECK(dmp_stream_init(&decoder, config,
              (dmp_buffer){ scratch, sizeof scratch }, 0U) == DMP_OK);
        result = dmp_stream_feed(&decoder, (dmp_bytes){ &sync, 1U }, 0U);
        CHECK(result.event == DMP_STREAM_NONE);
        result = dmp_stream_feed(&decoder, (dmp_bytes){ wire, written }, 1U);
        CHECK(result.event == DMP_STREAM_FRAME && result.frame.size == packet->size);
        CHECK(memcmp(result.frame.data, packet->data, packet->size) == 0);
        /* A bad tag is still structurally parseable; P14 must authenticate it. */
        output[packet->size - 1U] ^= 1U;
        CHECK(dmp_core_parse((dmp_bytes){ output, packet->size }, &limits, &view).status == DMP_OK);
    }
    (void)printf("%zu published protected packets: structural/header/full/Stream-R checks passed; no AEAD claim\n",
                 sizeof packets / sizeof packets[0]);
    return 0;
}
