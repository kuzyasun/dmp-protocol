/* Isolated compile/link probe. This is not a DTrack component or board image. */
#include "dmp/core.h"
#include "dmp/stream.h"
#include "sample1_epoch_anchor_nvs.h"
#include "sample1_epoch_owner.h"
#include "sample1_epoch_store.h"

#include <string.h>

void dmp_pre_hardware_link_probe(void);

typedef dmp_sample1_owner_result (*sample1_owner_init_fn)(
    dmp_sample1_epoch_owner *owner, dmp_sample1_principal principal,
    const dmp_sample1_epoch_owner_ports *ports);
typedef dmp_sample1_owner_result (*sample1_owner_begin_fn)(
    dmp_sample1_epoch_owner *owner, dmp_time_ms now);
typedef void (*sample1_store_init_fn)(
    dmp_sample1_nvs_epoch_store *store, nvs_handle_t nvs_handle,
    const char *key, dmp_sample1_first_provision_cb allow_first_provisioning,
    void *provision_user, dmp_sample1_reprovision_cb allow_reprovision_after_failure,
    void *reprovision_user, const dmp_sample1_nvs_ops *ops,
    const dmp_sample1_epoch_anchor_ops *anchor_ops, void *anchor_user);
typedef dmp_sample1_port_result (*sample1_reserve_next_fn)(
    void *user, dmp_sample1_principal principal, bool *has_previous,
    uint64_t *previous_epoch, uint64_t *reserved_epoch);
typedef void (*sample1_anchor_init_fn)(
    dmp_sample1_nvs_epoch_anchor *anchor, nvs_handle_t nvs_handle,
    const char *key, const dmp_sample1_nvs_ops *ops);

/* Volatile references make the compile-only link probe retain the app-level
 * SAMPLE-1 objects. The probe never calls these functions or touches NVS. */
static sample1_owner_init_fn volatile g_sample1_owner_init_ref;
static sample1_owner_begin_fn volatile g_sample1_owner_begin_ref;
static sample1_store_init_fn volatile g_sample1_store_init_ref;
static sample1_reserve_next_fn volatile g_sample1_reserve_next_ref;
static sample1_anchor_init_fn volatile g_sample1_anchor_init_ref;
static const dmp_sample1_epoch_anchor_ops * volatile g_sample1_anchor_ops_ref;

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

    dmp_pre_hardware_link_probe();

    /* Keep SAMPLE-1 owner, storage adapter and the ESP-IDF-backed NVS anchor
     * in the image for both ESP32 compile/link probes, without performing any
     * storage operation at runtime. */
    g_sample1_owner_init_ref = dmp_sample1_epoch_owner_init;
    g_sample1_owner_begin_ref = dmp_sample1_epoch_owner_begin_epoch;
    g_sample1_store_init_ref = dmp_sample1_nvs_epoch_store_init;
    g_sample1_reserve_next_ref = dmp_sample1_nvs_reserve_next;
    g_sample1_anchor_init_ref = dmp_sample1_nvs_epoch_anchor_init;
    g_sample1_anchor_ops_ref = &dmp_sample1_nvs_anchor_ops;

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
