/* Isolated compile/link probe. This is not a DTrack component or board image. */
#include "dmp/core.h"
#include "dmp/stream.h"

#include <string.h>

static const uint8_t payload[] = { 0xAAU, 0xBBU };
static const dmp_core_limits limits = { 256U, 128U, 8U };
static volatile int g_probe_result;

void app_main(void)
{
    dmp_frame_spec frame;
    dmp_frame_view view;
    dmp_role_policy role = { DMP_ROLE_ENDPOINT, 1U, false };
    uint8_t core[64];
    uint8_t wire_l[80];
    uint8_t wire_r[80];
    size_t core_size = 0U;
    size_t wire_l_size = 0U;
    size_t wire_r_size = 0U;
    dmp_stream_decoder decoder;
    dmp_stream_config config = { DMP_STREAM_L, 128U, 10U };
    uint8_t storage[128];
    dmp_stream_result result;

    memset(&frame, 0, sizeof frame);
    frame.fields.type = DMP_TYPE_TELEM;
    frame.payload = (dmp_bytes){ payload, sizeof payload };
    if (dmp_core_encode(&frame, &limits, (dmp_buffer){ core, sizeof core },
                        &core_size) != DMP_OK ||
        dmp_core_parse((dmp_bytes){ core, core_size }, &limits, &view).status !=
            DMP_OK ||
        dmp_core_check_role(&view, &role) != DMP_OK ||
        dmp_stream_encode(DMP_STREAM_L, (dmp_bytes){ core, core_size },
                          (dmp_buffer){ wire_l, sizeof wire_l },
                          &wire_l_size) != DMP_OK ||
        dmp_stream_encode(DMP_STREAM_R, (dmp_bytes){ core, core_size },
                          (dmp_buffer){ wire_r, sizeof wire_r },
                          &wire_r_size) != DMP_OK ||
        dmp_stream_init(&decoder, config, (dmp_buffer){ storage, sizeof storage },
                        0U) != DMP_OK) {
        g_probe_result = 1;
        return;
    }
    result = dmp_stream_feed(&decoder, (dmp_bytes){ wire_l, wire_l_size }, 1U);
    g_probe_result = result.status == DMP_OK && result.event == DMP_STREAM_FRAME
                         ? 0
                         : 1;
    /* Keep both format encoders in the linked image without a hardware run. */
    if (wire_r_size == 0U) {
        g_probe_result = 1;
    }
}
