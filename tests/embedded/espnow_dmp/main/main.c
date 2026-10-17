/*
 * ESP-NOW DMP Qualification Application.
 *
 * Exercises the production dmp_endpoint, dmp_hs, dmp_hs_tx, and SAMPLE-1 NVS
 * adapter over an ESP-NOW packet transport on ESP32-S3 and ESP32-C3.
 *
 * This test image is strictly test-only. Fixed credentials and identities
 * are for qualification testing only and MUST NOT be used in production.
 */

#include "dmp/core.h"
#include "dmp/endpoint.h"
#include "dmp/identity.h"
#include "dmp/integrity.h"
#include "dmp/stream.h"
#include "dmp/transport.h"

#include "handshake.h"
#include "handshake_transport.h"
#include "provider_port.h"
#include "sample1_endpoint.h"
#include "sample1_epoch_anchor_nvs.h"
#include "sample1_epoch_store.h"
#include "qual_console_line.h"
#include "qual_handshake_frame.h"
#include "qual_handshake_readiness.h"
#include "qual_tx_completion.h"
#include "qual_transport_outcome.h"

#include "esp_err.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include <inttypes.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define QUAL_CHANNEL 1U
#define QUAL_DECODED_CORE_MTU_BYTES 256U
#define QUAL_STREAM_R_ENCODED_MTU_BYTES 263U
#define QUAL_ESPNOW_V1_PAYLOAD_MTU_BYTES 250U
#define QUAL_ESPNOW_V2_PAYLOAD_MTU_BYTES 1470U
#define QUAL_MAX_PEERS 4U
#define QUAL_MAX_PAYLOAD_BYTES 4096U
#define QUAL_CHUNK_BYTES 128U
#define QUAL_SERVICE_SAMPLE1 1U
#define QUAL_SERVICE_DATA 2U
#define QUAL_SESSION_BYTES 8U
#define QUAL_COMMAND_BYTES 128U
#define QUAL_EVENT_QUEUE_LENGTH 16U
#define QUAL_COMMAND_QUEUE_LENGTH 8U
#define QUAL_TIMEOUT_US 5000000LL
#define QUAL_ENTROPY_DIAGNOSTIC_BYTES 4096U
#define QUAL_ENTROPY_BUCKETS 256U

/* Compile-time check on flash layout and ESP-NOW constants */
_Static_assert(ESP_NOW_MAX_DATA_LEN == 250,
               "ESP-NOW v1 maximum payload is 250 bytes");
_Static_assert(ESP_NOW_MAX_TOTAL_PEER_NUM >= QUAL_MAX_PEERS,
               "ESP-NOW peer table must fit qualification peers");

/*
 * TEST-ONLY FIXED CREDENTIALS - NOT FOR PRODUCTION USE.
 * Used for deterministic qualification of real SEC-1 Noise handshake.
 */
static const uint8_t TEST_ONLY_PSK[32] = {
    0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0, 0xb1,
    0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28, 0x39,
    0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0, 0xb1,
    0xc2, 0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28, 0x39
};

static const uint8_t RETRY_2_PROFILE_HASH[32] = {
    0x47, 0x8a, 0xf0, 0xbc, 0x49, 0x12, 0xd0, 0xfc,
    0x46, 0xed, 0x76, 0xc2, 0x49, 0xec, 0x5f, 0x30,
    0xf8, 0xf6, 0x4b, 0xc8, 0x9e, 0xd7, 0x41, 0x1e,
    0x9b, 0x92, 0x31, 0xbb, 0xf4, 0x87, 0xdb, 0x5c
};

static const uint8_t MULTI_PEER_PROFILE_HASH[32] = {
    0x00, 0x1e, 0xb4, 0x2d, 0x8f, 0x44, 0x0e, 0x0c,
    0xea, 0xf1, 0x71, 0x1e, 0x76, 0x4c, 0xea, 0xcf,
    0xc3, 0xc1, 0xdd, 0x03, 0x4c, 0xfb, 0x2d, 0x7f,
    0x32, 0x0b, 0xe7, 0xd8, 0x77, 0xf7, 0x45, 0x4f
};

#define TEST_ONLY_NAMESPACE_ID 1U
#define RETRY_2_CONTROLLER_NODE_ID 10U
#define RETRY_2_PEER_NODE_ID 20U
#define MULTI_PEER_CONTROLLER_NODE_ID 20U
#define QUAL_MAX_ADAPTER_SLOTS 3U
#define QUAL_MAX_ASSEMBLY_SLOTS QUAL_MAX_PEERS
#define QUAL_MAX_TOMBSTONE_SLOTS (QUAL_MAX_PEERS * 16U)

static const uint32_t MULTI_PEER_NODE_IDS[QUAL_MAX_PEERS] = { 10U, 35U, 34U, 36U };

typedef enum {
    EVENT_RX = 1,
    EVENT_RX_OVERSIZE = 2
} qual_event_kind;

typedef struct {
    qual_event_kind kind;
    uint8_t mac[6];
    size_t length;
    uint8_t bytes[ESP_NOW_MAX_DATA_LEN_V2];
} qual_wifi_event;

typedef struct {
    char line[QUAL_COMMAND_BYTES];
} qual_command_message;

typedef enum {
    ROLE_UNSET = 0,
    ROLE_CONTROLLER = 1,
    ROLE_PEER = 2
} qual_role;

typedef struct {
    uint8_t mac[6];
    uint32_t node_id;
    dmp_peer_handle handle;
    bool in_use;
    bool handshake_done;
    bool handshake_tx_ready;
    bool handshake_poll_failed;
    bool handshake_activation_failed;
    dmp_hs *hs;
    dmp_hs_tx *hs_tx;
    dmp_hs_tx_lifetime hs_lifetime;
    dmp_hs_tx_buffer hs_buffers[DMP_HS_TX_SLOT_MAX];
    uint8_t hs_buffer_bytes[DMP_HS_TX_SLOT_MAX][QUAL_STREAM_R_ENCODED_MTU_BYTES];
    dmp_stream_decoder hs_rx_decoder;
    uint8_t hs_rx_bytes[QUAL_DECODED_CORE_MTU_BYTES + 32U];
    uint32_t attempt_index;
    uint32_t resp_attempt_index;
    dmp_tx_token pending_hs_token;
    bool pending_hs_submit;
    bool hs_sync_requested;
    bool hs_rx_ready;
    uint64_t handshake_started_us;
} qual_peer_entry;

typedef struct {
    qual_role role;
    uint32_t local_node_id;
    uint8_t own_mac[6];
    uint8_t session_token[QUAL_SESSION_BYTES];
    bool session_set;
    uint32_t espnow_version;
    uint32_t handshake_scratch_slots;
    char profile_name[32];
    uint8_t active_profile_hash[32];
    bool stack_initialized;

    qual_peer_entry peers[QUAL_MAX_PEERS];
    uint32_t peer_count;

    /* Transport TX tracking */
    bool tx_live;
    bool current_tx_probe;
    uint32_t current_tx_peer_idx;
    dmp_tx_token current_tx_token;
    dmp_tx_complete_fn current_tx_complete;
    void *current_tx_owner;
    uint8_t current_tx_mac[6];
    size_t current_tx_len;

    /* Statistics */
    uint32_t stats_tx_frames;
    uint32_t stats_rx_frames;
    uint32_t stats_tx_ok;
    uint32_t stats_tx_failed;
    uint32_t stats_assembled_transfers;
    size_t max_observed_rx_frame_bytes;
    size_t max_observed_tx_frame_bytes;
} qual_state;

static qual_state g_state;
static QueueHandle_t g_wifi_events = NULL;
static QueueHandle_t g_commands = NULL;
static dmp_qual_tx_completion_slot g_tx_completion;
static uint32_t g_tx_callback_duplicates;

static uint32_t profile_controller_node_id(const char *profile_name)
{
    return strcmp(profile_name, "retry-2") == 0
               ? RETRY_2_CONTROLLER_NODE_ID
               : MULTI_PEER_CONTROLLER_NODE_ID;
}

static const char *profile_sample1_epoch_key(const char *profile_name)
{
    return strcmp(profile_name, "retry-2") == 0 ? "s1_epoch_test" : "s1_epoch_mp";
}

static const char *profile_sample1_anchor_key(const char *profile_name)
{
    return strcmp(profile_name, "retry-2") == 0 ? "s1_anch_test" : "s1_anch_mp";
}

static uint32_t profile_peer_capacity(const char *profile_name)
{
    return strcmp(profile_name, "retry-2") == 0 ? 1U : QUAL_MAX_PEERS;
}

static uint32_t profile_peer_node_id(const char *profile_name, uint32_t index)
{
    if (strcmp(profile_name, "retry-2") == 0) {
        return index == 0U ? RETRY_2_PEER_NODE_ID : 0U;
    }
    return index < QUAL_MAX_PEERS ? MULTI_PEER_NODE_IDS[index] : 0U;
}

static bool profile_role_node_id_valid(const char *profile_name, qual_role role,
                                       uint32_t node_id)
{
    if (role == ROLE_CONTROLLER) {
        return node_id == profile_controller_node_id(profile_name);
    }
    for (uint32_t i = 0U; i < profile_peer_capacity(profile_name); ++i) {
        if (node_id == profile_peer_node_id(profile_name, i)) {
            return true;
        }
    }
    return false;
}

/* DMP endpoint and memory structures */
static dmp_endpoint g_endpoint;
static dmp_transport g_transport;
static dmp_config g_profile_config;
static dmp_admitted_profile g_admitted_profile;
static dmp_provider *g_provider = NULL;

/* Endpoint storage buffers */
static dmp_endpoint_peer_state g_peer_states[QUAL_MAX_PEERS];
static dmp_identity_slot g_identity_slots[QUAL_MAX_PEERS * 3U];
static uint8_t *g_admission_storage = NULL;

static dmp_reliability_sender_slot g_senders[4];
static uint8_t g_sender_payload[4 * QUAL_MAX_PAYLOAD_BYTES];
static dmp_reliability_result_slot g_results[4];
static uint8_t g_result_payload[4 * QUAL_MAX_PAYLOAD_BYTES];
static dmp_reliability_history_slot g_history[8];
static uint8_t g_history_metadata[8 * DMP_RELIABILITY_METADATA_BYTES];
static dmp_reliability_correlation_slot g_correlations[4];
static uint8_t g_correlation_metadata[4 * DMP_RELIABILITY_METADATA_BYTES];
static dmp_reliability_adapter_slot g_adapters[QUAL_MAX_ADAPTER_SLOTS];
static uint8_t g_frames[QUAL_MAX_ADAPTER_SLOTS * QUAL_STREAM_R_ENCODED_MTU_BYTES];
static uint8_t g_receive_payload[QUAL_MAX_PAYLOAD_BYTES];
static uint8_t g_stream_tx[QUAL_STREAM_R_ENCODED_MTU_BYTES];
static uint8_t g_stream_rx[QUAL_MAX_PEERS * QUAL_STREAM_R_ENCODED_MTU_BYTES];
static dmp_reassembly_slot g_assemblies[QUAL_MAX_ASSEMBLY_SLOTS];
static dmp_reassembly_tombstone g_tombstones[QUAL_MAX_TOMBSTONE_SLOTS];
static dmp_endpoint_freshness_slot g_freshness[8];
static uint8_t g_assembly_payload[QUAL_MAX_ASSEMBLY_SLOTS * QUAL_MAX_PAYLOAD_BYTES];
static uint8_t g_assembly_metadata[QUAL_MAX_ASSEMBLY_SLOTS * DMP_REASSEMBLY_METADATA_BYTES];
static uint8_t g_fragment_message[QUAL_MAX_PEERS * QUAL_MAX_PAYLOAD_BYTES];
static uint8_t g_fragment_frame[256];
static uint8_t g_telemetry_payload[QUAL_MAX_PEERS * QUAL_MAX_PAYLOAD_BYTES];
static uint8_t g_telemetry_next[QUAL_MAX_PEERS * QUAL_MAX_PAYLOAD_BYTES];
static portMUX_TYPE g_callback_diag_mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t g_rx_callback_count;
static uint32_t g_rx_callback_queue_drops;
static uint8_t g_telemetry_frame[256];
static uint8_t g_entropy_sample[QUAL_ENTROPY_DIAGNOSTIC_BYTES];
static uint16_t g_entropy_bucket_counts[QUAL_ENTROPY_BUCKETS];
static portMUX_TYPE g_provider_alloc_mux = portMUX_INITIALIZER_UNLOCKED;
static size_t g_provider_live_requested_bytes;
static size_t g_provider_peak_requested_bytes;
static size_t g_provider_largest_single_request_bytes;
static size_t g_wifi_rx_stack_min_free_bytes = SIZE_MAX;
static size_t g_wifi_tx_stack_min_free_bytes = SIZE_MAX;
static TaskHandle_t g_command_reader_task;
static bool g_entropy_ready;
static uint64_t g_boot_id;
static size_t g_internal_heap_free_at_ready_bytes;
static bool g_internal_heap_baseline_available;

static uint8_t g_test_transfer_payload[QUAL_MAX_PAYLOAD_BYTES];

static const char *TAG = "dmp_espnow_qual";

/* Forward declarations */
static dmp_status espnow_transport_submit(void *context,
                                         const dmp_tx_submission *submission);
static dmp_status espnow_transport_cancel(void *context, dmp_tx_token token);
static void on_endpoint_notice(void *user, const dmp_endpoint_notice *notice);

static void format_mac(const uint8_t mac[6], char out[18])
{
    (void)snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static uint32_t load_u32_le(const uint8_t bytes[4])
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
           ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

static uint64_t load_u64_le(const uint8_t bytes[8])
{
    return (uint64_t)load_u32_le(bytes) |
           ((uint64_t)load_u32_le(bytes + 4U) << 32U);
}

static const char *hs_tx_status_name(dmp_hs_tx_status status)
{
    switch (status) {
    case DMP_HS_TX_ACCEPTED: return "accepted";
    case DMP_HS_TX_BUSY: return "busy";
    case DMP_HS_TX_EXPIRED: return "expired";
    case DMP_HS_TX_NO_OUTPUT: return "no-output";
    case DMP_HS_TX_NO_SLOT: return "no-slot";
    case DMP_HS_TX_REFUSED: return "refused";
    case DMP_HS_TX_TRANSPORT_REJECTED: return "transport-rejected";
    case DMP_HS_TX_STALE: return "stale";
    case DMP_HS_TX_INVALID: return "invalid";
    default: return "unknown";
    }
}

static bool parse_mac(const char *in, uint8_t mac[6])
{
    unsigned int bytes[6];
    if (sscanf(in, "%02x:%02x:%02x:%02x:%02x:%02x",
               &bytes[0], &bytes[1], &bytes[2],
               &bytes[3], &bytes[4], &bytes[5]) != 6) {
        return false;
    }
    for (size_t i = 0; i < 6; ++i) {
        mac[i] = (uint8_t)bytes[i];
    }
    return true;
}

static void format_session(char out[QUAL_SESSION_BYTES * 2U + 1U])
{
    for (size_t i = 0; i < QUAL_SESSION_BYTES; ++i) {
        (void)snprintf(out + i * 2U, 3U, "%02x", g_state.session_token[i]);
    }
    out[QUAL_SESSION_BYTES * 2U] = '\0';
}

void dmp_handshake_qual_diagnostic(void *context, const char *stage, int status)
{
    const qual_peer_entry *peer = (const qual_peer_entry *)context;
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    char peer_mac[18] = "00:00:00:00:00:00";
    uint32_t peer_handle = UINT32_MAX;

    format_session(session);
    if (peer != NULL) {
        format_mac(peer->mac, peer_mac);
        peer_handle = peer->handle.slot;
    }
    printf("{\"event\":\"handshake_schedule_diagnostic\",\"session\":\"%s\","
           "\"peer_mac\":\"%s\",\"peer_handle\":%" PRIu32 ","
           "\"stage\":\"%s\",\"status\":%d}\n",
           session, peer_mac, peer_handle, stage != NULL ? stage : "unknown", status);
}

static void format_hex(const uint8_t *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; ++i) {
        (void)snprintf(out + i * 2U, 3U, "%02x", in[i]);
    }
    out[len * 2U] = '\0';
}

static int find_peer_by_mac(const uint8_t mac[6])
{
    for (size_t i = 0; i < QUAL_MAX_PEERS; ++i) {
        if (g_state.peers[i].in_use && memcmp(g_state.peers[i].mac, mac, 6) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* Provider ports for hardware execution */
static int hw_startup_ready(void *ctx)
{
    (void)ctx;
    /* The provider contract uses nonzero to mean startup is not eligible. */
    return g_entropy_ready ? 0 : 1;
}

static int hw_startup_read(void *ctx, void *bytes, size_t size)
{
    (void)ctx;
    if (!g_entropy_ready || bytes == NULL || size == 0U) {
        return -1;
    }
    esp_fill_random(bytes, size);
    return 0;
}

static int hw_entropy(void *ctx, void *bytes, size_t size)
{
    (void)ctx;
    if (!g_entropy_ready || bytes == NULL || size == 0U) {
        return -1;
    }
    esp_fill_random(bytes, size);
    return 0;
}

static void *hw_allocate(void *ctx, size_t size)
{
    (void)ctx;
    void *ptr = malloc(size);
    if (ptr == NULL) {
        return NULL;
    }

    portENTER_CRITICAL(&g_provider_alloc_mux);
    if (SIZE_MAX - g_provider_live_requested_bytes < size) {
        portEXIT_CRITICAL(&g_provider_alloc_mux);
        free(ptr);
        return NULL;
    }
    g_provider_live_requested_bytes += size;
    if (g_provider_live_requested_bytes > g_provider_peak_requested_bytes) {
        g_provider_peak_requested_bytes = g_provider_live_requested_bytes;
    }
    if (size > g_provider_largest_single_request_bytes) {
        g_provider_largest_single_request_bytes = size;
    }
    portEXIT_CRITICAL(&g_provider_alloc_mux);
    return ptr;
}

static void hw_release(void *ctx, void *ptr, size_t size)
{
    (void)ctx;
    if (ptr == NULL) {
        return;
    }
    portENTER_CRITICAL(&g_provider_alloc_mux);
    g_provider_live_requested_bytes =
        g_provider_live_requested_bytes >= size
            ? g_provider_live_requested_bytes - size
            : 0U;
    portEXIT_CRITICAL(&g_provider_alloc_mux);
    free(ptr);
}

static uint64_t hw_hs_now_ms(void *ctx)
{
    (void)ctx;
    return (uint64_t)(esp_timer_get_time() / 1000LL);
}

static int hw_hs_entropy(void *ctx, uint8_t *bytes, size_t size)
{
    (void)ctx;
    if (!g_entropy_ready || bytes == NULL || size == 0U) {
        return -1;
    }
    esp_fill_random(bytes, size);
    return 0;
}

static int hw_hs_commit_pin(void *ctx, const dmp_hs_pin_record *record)
{
    (void)ctx;
    (void)record;
    return 0;
}

static bool cb_allow_first_provisioning(void *user, dmp_sample1_principal principal)
{
    (void)user;
    return principal.namespace_id == TEST_ONLY_NAMESPACE_ID;
}

static dmp_sample1_endpoint g_sample_endpoint;
static dmp_sample1_nvs_epoch_anchor g_sample_anchor;
static dmp_sample1_nvs_epoch_store g_sample_store;
static nvs_handle_t g_sample_nvs_handle = 0;
static bool g_sample1_active = false;

static size_t qualification_static_storage_bytes(void)
{
    return sizeof(g_state) + sizeof(g_endpoint) + sizeof(g_transport) +
           sizeof(g_profile_config) + sizeof(g_admitted_profile) +
           sizeof(g_peer_states) + sizeof(g_identity_slots) +
           sizeof(g_senders) + sizeof(g_sender_payload) + sizeof(g_results) +
           sizeof(g_result_payload) + sizeof(g_history) +
           sizeof(g_history_metadata) + sizeof(g_correlations) +
           sizeof(g_correlation_metadata) + sizeof(g_adapters) + sizeof(g_frames) +
           sizeof(g_receive_payload) + sizeof(g_stream_tx) + sizeof(g_stream_rx) +
           sizeof(g_assemblies) + sizeof(g_tombstones) + sizeof(g_freshness) +
           sizeof(g_assembly_payload) + sizeof(g_assembly_metadata) +
           sizeof(g_fragment_message) + sizeof(g_fragment_frame) +
           sizeof(g_telemetry_payload) + sizeof(g_telemetry_next) +
           sizeof(g_telemetry_frame) + sizeof(g_test_transfer_payload) +
           sizeof(g_sample_endpoint) + sizeof(g_sample_anchor) +
           sizeof(g_sample_store) + sizeof(g_entropy_sample) +
           sizeof(g_entropy_bucket_counts);
}

static size_t qualification_dynamic_object_bytes(void)
{
    size_t bytes = 0U;
    if (g_provider != NULL) {
        bytes += dmp_provider_size();
    }
    if (g_admission_storage != NULL) {
        bytes += dmp_hs_admission_size();
    }
    for (size_t i = 0U; i < QUAL_MAX_PEERS; ++i) {
        if (g_state.peers[i].hs != NULL) {
            bytes += dmp_hs_size();
        }
        if (g_state.peers[i].hs_tx != NULL) {
            bytes += dmp_hs_tx_size();
        }
    }
    return bytes;
}

static void report_resources(void)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    size_t internal_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    size_t internal_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    size_t internal_largest = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    size_t spiram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    size_t spiram_min = heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    size_t spiram_largest = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    size_t provider_live;
    size_t provider_peak;
    size_t provider_largest;
    size_t rx_stack;
    size_t tx_stack;
    size_t main_stack = (size_t)uxTaskGetStackHighWaterMark(NULL);
    size_t command_stack = g_command_reader_task != NULL
                               ? (size_t)uxTaskGetStackHighWaterMark(g_command_reader_task)
                               : 0U;
    int64_t internal_used_since_ready = 0;

    format_session(session);
    if (g_internal_heap_baseline_available) {
        internal_used_since_ready = (int64_t)g_internal_heap_free_at_ready_bytes -
                                    (int64_t)internal_free;
    }
    portENTER_CRITICAL(&g_provider_alloc_mux);
    provider_live = g_provider_live_requested_bytes;
    provider_peak = g_provider_peak_requested_bytes;
    provider_largest = g_provider_largest_single_request_bytes;
    portEXIT_CRITICAL(&g_provider_alloc_mux);
    portENTER_CRITICAL(&g_callback_diag_mux);
    rx_stack = g_wifi_rx_stack_min_free_bytes;
    tx_stack = g_wifi_tx_stack_min_free_bytes;
    portEXIT_CRITICAL(&g_callback_diag_mux);

#ifdef CONFIG_ESP_MAIN_TASK_STACK_SIZE
    const unsigned main_stack_configured = CONFIG_ESP_MAIN_TASK_STACK_SIZE;
#else
    const unsigned main_stack_configured = 0U;
#endif
    printf("{\"event\":\"resources\",\"session\":\"%s\",\"target\":\"%s\","
           "\"status\":\"ok\",\"entropy_ready\":%s,"
           "\"heap_internal_free_bytes\":%zu,\"heap_internal_min_free_bytes\":%zu,"
           "\"heap_internal_largest_block_bytes\":%zu,"
           "\"heap_internal_used_since_ready_bytes\":%" PRId64 ","
           "\"heap_spiram_free_bytes\":%zu,\"heap_spiram_min_free_bytes\":%zu,"
           "\"heap_spiram_largest_block_bytes\":%zu,"
           "\"qualification_static_bytes\":%zu,\"qualification_dynamic_object_bytes\":%zu,"
           "\"provider_live_requested_bytes\":%zu,\"provider_peak_requested_bytes\":%zu,"
           "\"provider_largest_allocation_bytes\":%zu,\"provider_retained_bytes\":%zu,"
           "\"provider_scratch_limit_bytes\":%u,\"provider_retained_limit_bytes\":%u,"
           "\"main_stack_min_free_bytes\":%zu,\"main_stack_configured_bytes\":%u,"
           "\"command_stack_min_free_bytes\":%zu,\"command_stack_configured_bytes\":4096,"
           "\"wifi_rx_callback_stack_sampled\":%s,\"wifi_rx_callback_stack_min_free_bytes\":%zu,"
           "\"wifi_tx_callback_stack_sampled\":%s,\"wifi_tx_callback_stack_min_free_bytes\":%zu,"
           "\"decoded_core_mtu_bytes\":%u,\"stream_r_encoded_mtu_bytes\":%u,"
           "\"espnow_v1_payload_mtu_bytes\":%u,\"espnow_v2_payload_mtu_bytes\":%u}\n",
           session, CONFIG_IDF_TARGET, g_entropy_ready ? "true" : "false",
           internal_free, internal_min, internal_largest, internal_used_since_ready,
           spiram_free, spiram_min, spiram_largest,
           qualification_static_storage_bytes(), qualification_dynamic_object_bytes(),
           provider_live, provider_peak, provider_largest,
           g_provider != NULL ? dmp_provider_retained(g_provider) : 0U,
           (unsigned)DMP_PROVIDER_SCRATCH_MAX, (unsigned)DMP_PROVIDER_RETAINED_MAX,
           main_stack, main_stack_configured, command_stack,
           rx_stack != SIZE_MAX ? "true" : "false", rx_stack != SIZE_MAX ? rx_stack : 0U,
           tx_stack != SIZE_MAX ? "true" : "false", tx_stack != SIZE_MAX ? tx_stack : 0U,
           QUAL_DECODED_CORE_MTU_BYTES, QUAL_STREAM_R_ENCODED_MTU_BYTES,
           QUAL_ESPNOW_V1_PAYLOAD_MTU_BYTES, QUAL_ESPNOW_V2_PAYLOAD_MTU_BYTES);
}

static void report_entropy_diagnostic(void)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    uint32_t unique_bytes = 0U;
    uint16_t min_bucket = UINT16_MAX;
    uint16_t max_bucket = 0U;
    uint64_t squared_deviation = 0U;
    uint64_t started_us = (uint64_t)esp_timer_get_time();

    format_session(session);
    if (!g_entropy_ready) {
        printf("{\"event\":\"entropy_diagnostic\",\"session\":\"%s\","
               "\"status\":\"fail_closed\",\"entropy_ready\":false}\n", session);
        return;
    }
    memset(g_entropy_bucket_counts, 0, sizeof(g_entropy_bucket_counts));
    esp_fill_random(g_entropy_sample, sizeof(g_entropy_sample));
    for (size_t i = 0U; i < sizeof(g_entropy_sample); ++i) {
        ++g_entropy_bucket_counts[g_entropy_sample[i]];
    }
    for (size_t i = 0U; i < QUAL_ENTROPY_BUCKETS; ++i) {
        uint16_t count = g_entropy_bucket_counts[i];
        uint32_t delta = count > 16U ? (uint32_t)(count - 16U) : (uint32_t)(16U - count);
        if (count != 0U) {
            ++unique_bytes;
        }
        if (count < min_bucket) {
            min_bucket = count;
        }
        if (count > max_bucket) {
            max_bucket = count;
        }
        squared_deviation += (uint64_t)delta * (uint64_t)delta;
    }
    memset(g_entropy_sample, 0, sizeof(g_entropy_sample));
    uint64_t elapsed_us = (uint64_t)esp_timer_get_time() - started_us;
    printf("{\"event\":\"entropy_diagnostic\",\"session\":\"%s\","
           "\"status\":\"ok\",\"entropy_ready\":true,"
           "\"source\":\"esp_fill_random_wifi_active\",\"sample_bytes\":%u,"
           "\"unique_byte_values\":%" PRIu32 ",\"minimum_bucket_count\":%u,"
           "\"maximum_bucket_count\":%u,\"chi_square_x1000\":%" PRIu64 ","
           "\"elapsed_us\":%" PRIu64 ",\"quality_certified\":false,"
           "\"interpretation\":\"statistical diagnostic only\"}\n",
           session, QUAL_ENTROPY_DIAGNOSTIC_BYTES, unique_bytes,
           (unsigned)min_bucket, (unsigned)max_bucket,
           (squared_deviation * UINT64_C(1000)) / UINT64_C(16), elapsed_us);
}

static bool sample1_hook_try_enter(void *user)
{
    (void)user;
    return true;
}

static void sample1_hook_leave(void *user)
{
    (void)user;
}

static dmp_sample1_port_result sample1_hook_dummy_publish(
    void *user, dmp_sample1_principal principal, uint64_t epoch,
    uint32_t index, const uint8_t payload[DMP_SAMPLE1_TELEM_BYTES])
{
    (void)user;
    (void)principal;
    (void)epoch;
    (void)index;
    (void)payload;
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

/* SAMPLE-1 NVS epoch check */
static void execute_nvs_check(void)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    uint64_t started_us = (uint64_t)esp_timer_get_time();
    format_session(session);

    if (!g_state.stack_initialized ||
        g_state.local_node_id != profile_controller_node_id(g_state.profile_name)) {
        printf("{\"event\":\"nvs_epoch_check\",\"session\":\"%s\","
               "\"status\":\"fail_not_producer\"}\n", session);
        return;
    }

    nvs_handle_t nvs_handle;
    esp_err_t err = nvs_open("dmp_test_nvs", NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        printf("{\"event\":\"nvs_epoch_check\",\"session\":\"%s\",\"status\":\"fail_open\","
               "\"error\":%d}\n", session, (int)err);
        return;
    }

    dmp_sample1_nvs_epoch_anchor anchor;
    dmp_sample1_nvs_epoch_store store;
    const char *epoch_key = profile_sample1_epoch_key(g_state.profile_name);
    const char *anchor_key = profile_sample1_anchor_key(g_state.profile_name);
    dmp_sample1_nvs_epoch_anchor_init(&anchor, nvs_handle, anchor_key, NULL);
    dmp_sample1_nvs_epoch_store_init(&store, nvs_handle, epoch_key,
                                     cb_allow_first_provisioning, NULL, NULL, NULL, NULL,
                                     &dmp_sample1_nvs_anchor_ops, &anchor);

    dmp_sample1_principal principal = {
        .namespace_id = TEST_ONLY_NAMESPACE_ID,
        .origin_id = profile_controller_node_id(g_state.profile_name)
    };
    bool has_prev = false;
    uint64_t prev_epoch = 0U;
    uint64_t reserved_epoch = 0U;

    dmp_sample1_port_result res = dmp_sample1_nvs_reserve_next(
        &store, principal, &has_prev, &prev_epoch, &reserved_epoch);
    nvs_close(nvs_handle);

    if (res != DMP_SAMPLE1_PORT_ACCEPTED) {
        printf("{\"event\":\"nvs_epoch_check\",\"session\":\"%s\",\"status\":\"fail_reserve\","
               "\"port_error\":%d}\n", session, (int)res);
        return;
    }

    if (has_prev && reserved_epoch <= prev_epoch) {
        printf("{\"event\":\"nvs_epoch_check\",\"session\":\"%s\",\"status\":\"fail_monotonic\","
               "\"previous_epoch\":%" PRIu64 ",\"reserved_epoch\":%" PRIu64 "}\n",
               session, prev_epoch, reserved_epoch);
        return;
    }

    printf("{\"event\":\"nvs_epoch_check\",\"session\":\"%s\",\"status\":\"ok\","
           "\"namespace\":\"dmp_test_nvs\",\"key\":\"%s\","
           "\"has_previous\":%s,\"previous_epoch\":%" PRIu64 ",\"reserved_epoch\":%" PRIu64 ","
           "\"elapsed_us\":%" PRIu64 "}\n",
           session, epoch_key, has_prev ? "true" : "false", prev_epoch, reserved_epoch,
           (uint64_t)esp_timer_get_time() - started_us);
}

/* Endpoint notice callback */
static void on_endpoint_notice(void *user, const dmp_endpoint_notice *notice)
{
    (void)user;
    if (notice == NULL) return;

    char session[QUAL_SESSION_BYTES * 2U + 1U];
    format_session(session);

    if (notice->event == DMP_ENDPOINT_ASSEMBLED) {
        ++g_state.stats_assembled_transfers;
        uint32_t chunk_bytes = g_profile_config.chunk_bytes;
        if (chunk_bytes == 0U) {
            ESP_LOGE(TAG, "assembled Service-2 message without an active profile chunk size");
            return;
        }
        uint32_t fragments = (uint32_t)((notice->payload.size + chunk_bytes - 1U) / chunk_bytes);
        bool match = true;
        for (size_t i = 0; i < notice->payload.size; ++i) {
            uint8_t expected = (uint8_t)((i * 31U + 17U) & 0xFFU);
            if (notice->payload.data[i] != expected) {
                match = false;
                break;
            }
        }
        printf("{\"event\":\"rx_assembled\",\"session\":\"%s\",\"peer_handle\":%u,"
               "\"service_id\":%" PRIu32 ",\"bytes\":%u,\"fragments\":%" PRIu32 ","
               "\"chunk_bytes\":%" PRIu32 ",\"payload_match\":%s,\"max_frame_bytes\":%u}\n",
               session, (unsigned)notice->peer.slot, notice->service_id,
               (unsigned)notice->payload.size, fragments, chunk_bytes,
               match ? "true" : "false",
               (unsigned)g_state.max_observed_rx_frame_bytes);
    } else if (notice->event == DMP_ENDPOINT_REQUEST) {
        printf("{\"event\":\"rx_request\",\"session\":\"%s\",\"peer_handle\":%u,"
               "\"service_id\":%" PRIu32 ",\"bytes\":%u}\n",
               session, (unsigned)notice->peer.slot, notice->service_id,
               (unsigned)notice->payload.size);
        if (notice->service_id == QUAL_SERVICE_SAMPLE1 && g_sample1_active) {
            dmp_time_ms now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);
            dmp_sample1_owner_result res = dmp_sample1_endpoint_handle_notice(&g_sample_endpoint, notice, now);
            if (res == DMP_SAMPLE1_OWNER_OK) {
                (void)dmp_sample1_endpoint_flush(&g_sample_endpoint, now);
            }
        }
    } else if (notice->event == DMP_ENDPOINT_RESULT) {
        printf("{\"event\":\"rx_result\",\"session\":\"%s\",\"peer_handle\":%u,"
               "\"service_id\":%" PRIu32 ",\"wire_status\":%" PRIu32 ",\"bytes\":%u}\n",
               session, (unsigned)notice->peer.slot, notice->service_id,
               notice->wire_status, (unsigned)notice->payload.size);
        if (notice->service_id == QUAL_SERVICE_SAMPLE1 &&
            notice->wire_status == 0U && notice->payload.data != NULL &&
            notice->payload.size == DMP_SAMPLE1_READ_BYTES &&
            notice->payload.data[0] == DMP_SAMPLE1_READ_OPCODE) {
            printf("{\"event\":\"sample1_read_result\",\"session\":\"%s\","
                   "\"peer_handle\":%u,\"epoch\":%" PRIu64 ","
                   "\"sample_index\":%" PRIu32 ",\"sample_value\":%" PRIu32 "}\n",
                   session, (unsigned)notice->peer.slot,
                   load_u64_le(notice->payload.data + 1U),
                   load_u32_le(notice->payload.data + 9U),
                   load_u32_le(notice->payload.data + 13U));
        }
    } else if (notice->event == DMP_ENDPOINT_TELEMETRY) {
        printf("{\"event\":\"rx_telemetry\",\"session\":\"%s\",\"peer_handle\":%u,"
               "\"service_id\":%" PRIu32 ",\"bytes\":%u}\n",
               session, (unsigned)notice->peer.slot, notice->service_id,
               (unsigned)notice->payload.size);
    }
}

/* Transport submit implementation */
static dmp_status espnow_transport_submit(void *context,
                                         const dmp_tx_submission *submission)
{
    (void)context;

    if (submission == NULL || submission->frame.data == NULL || submission->frame.size == 0U) {
        return DMP_INVALID_ARGUMENT;
    }
    if (submission->frame.size > g_transport.caps.max_frame_bytes ||
        submission->frame.size > QUAL_ESPNOW_V2_PAYLOAD_MTU_BYTES) {
        return DMP_LIMIT_EXHAUSTED;
    }
    uint32_t peer_idx = submission->peer.slot;
    if (peer_idx >= QUAL_MAX_PEERS || !g_state.peers[peer_idx].in_use) {
        return DMP_STALE_HANDLE;
    }
    /* Endpoint application TX requires both local activation and confirmation
     * transport readiness. Handshake TX uses its adapter as owner and remains
     * available to complete the confirmation exchange. */
    if (submission->owner == &g_endpoint &&
        !dmp_qual_application_tx_allowed(g_state.peers[peer_idx].handshake_done,
                                         g_state.peers[peer_idx].handshake_tx_ready)) {
        return DMP_BUSY;
    }
    if (g_state.tx_live) {
        return DMP_BUSY;
    }

    g_state.tx_live = true;
    g_state.current_tx_peer_idx = peer_idx;
    g_state.current_tx_complete = submission->complete;
    g_state.current_tx_owner = submission->owner;
    g_state.current_tx_token = submission->token;
    g_state.current_tx_len = submission->frame.size;
    memcpy(g_state.current_tx_mac, g_state.peers[peer_idx].mac, 6);

    if (submission->frame.size > g_state.max_observed_tx_frame_bytes) {
        g_state.max_observed_tx_frame_bytes = submission->frame.size;
    }

    esp_err_t err = esp_now_send(g_state.peers[peer_idx].mac, submission->frame.data, submission->frame.size);
    if (err != ESP_OK) {
        g_state.tx_live = false;
        return DMP_BUSY;
    }
    return DMP_OK;
}

static dmp_status espnow_transport_cancel(void *context, dmp_tx_token token)
{
    (void)context;
    (void)token;
    return DMP_INVALID_ARGUMENT;
}

static void send_callback(const esp_now_send_info_t *info,
                          esp_now_send_status_t status)
{
    dmp_qual_tx_completion_event event;
    size_t stack_free;
    if (info == NULL || info->des_addr == NULL) return;
    stack_free = (size_t)uxTaskGetStackHighWaterMark(NULL);
    memcpy(event.mac, info->des_addr, sizeof event.mac);
    event.status = (int)status;

    /* One transport TX may be live at a time. Keep its terminal callback in a
     * dedicated single-slot mailbox so RX queue pressure cannot drop it and
     * strand a COPY/BORROW frame. Serialize with the event-loop consumer. */
    portENTER_CRITICAL(&g_callback_diag_mux);
    if (stack_free < g_wifi_tx_stack_min_free_bytes) {
        g_wifi_tx_stack_min_free_bytes = stack_free;
    }
    if (!dmp_qual_tx_completion_post(&g_tx_completion, &event)) {
        ++g_tx_callback_duplicates;
    }
    portEXIT_CRITICAL(&g_callback_diag_mux);
}

static void receive_callback(const esp_now_recv_info_t *info,
                             const uint8_t *data, int data_length)
{
    qual_wifi_event event;
    size_t stack_free;
    if (g_wifi_events == NULL || info == NULL || info->src_addr == NULL ||
        data_length < 0 || (data_length > 0 && data == NULL)) {
        return;
    }
    stack_free = (size_t)uxTaskGetStackHighWaterMark(NULL);
    portENTER_CRITICAL(&g_callback_diag_mux);
    ++g_rx_callback_count;
    if (stack_free < g_wifi_rx_stack_min_free_bytes) {
        g_wifi_rx_stack_min_free_bytes = stack_free;
    }
    portEXIT_CRITICAL(&g_callback_diag_mux);

    memset(&event, 0, sizeof event);
    memcpy(event.mac, info->src_addr, 6);
    event.length = (size_t)data_length;
    if (event.length > sizeof event.bytes) {
        event.kind = EVENT_RX_OVERSIZE;
    } else {
        event.kind = EVENT_RX;
        if (event.length != 0U) {
            memcpy(event.bytes, data, event.length);
        }
    }
    if (xQueueSend(g_wifi_events, &event, 0U) != pdTRUE) {
        portENTER_CRITICAL(&g_callback_diag_mux);
        ++g_rx_callback_queue_drops;
        portEXIT_CRITICAL(&g_callback_diag_mux);
    }
}

static void command_reader_task(void *unused)
{
    dmp_qual_console_line_reader reader;
    (void)unused;
    dmp_qual_console_line_reader_init(&reader);

    for (;;) {
        char chunk[QUAL_COMMAND_BYTES];
        ssize_t chunk_length = read(STDIN_FILENO, chunk, sizeof chunk);
        if (chunk_length <= 0) {
            if (chunk_length < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                printf("{\"event\":\"command_input_error\",\"errno\":%d}\n", errno);
            }
            vTaskDelay(pdMS_TO_TICKS(10));
            continue;
        }
        for (ssize_t i = 0; i < chunk_length; ++i) {
            qual_command_message command;
            dmp_qual_console_line_result result = dmp_qual_console_line_reader_feed(
                &reader, (uint8_t)chunk[i], command.line);
            if (result == DMP_QUAL_CONSOLE_LINE_READY) {
                uint32_t line_bytes = (uint32_t)strlen(command.line);
                BaseType_t queued = xQueueSend(g_commands, &command, pdMS_TO_TICKS(100));
                printf("{\"event\":\"console_command_received\",\"line_bytes\":%" PRIu32 ","
                       "\"queued\":%s}\n",
                       line_bytes, queued == pdTRUE ? "true" : "false");
                if (queued != pdTRUE) {
                    printf("{\"event\":\"command_queue_overflow\"}\n");
                }
            } else if (result == DMP_QUAL_CONSOLE_LINE_TOO_LONG) {
                printf("{\"event\":\"command_rejected\",\"reason\":\"command-too-long\"}\n");
            }
        }
    }
}

static const char *reset_reason_name(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_UNKNOWN: return "unknown";
        case ESP_RST_POWERON: return "power_on";
        case ESP_RST_EXT: return "external_pin";
        case ESP_RST_SW: return "software";
        case ESP_RST_PANIC: return "panic";
        case ESP_RST_INT_WDT: return "interrupt_watchdog";
        case ESP_RST_TASK_WDT: return "task_watchdog";
        case ESP_RST_WDT: return "watchdog";
        case ESP_RST_DEEPSLEEP: return "deep_sleep";
        case ESP_RST_BROWNOUT: return "brownout";
        case ESP_RST_SDIO: return "sdio";
        case ESP_RST_USB: return "usb";
        case ESP_RST_JTAG: return "jtag";
        case ESP_RST_EFUSE: return "efuse";
        case ESP_RST_PWR_GLITCH: return "power_glitch";
        case ESP_RST_CPU_LOCKUP: return "cpu_lockup";
        default: return "other";
    }
}

static void log_ready(void)
{
    char mac_text[18];
    format_mac(g_state.own_mac, mac_text);
    printf("{\"event\":\"ready\",\"target\":\"%s\",\"idf\":\"ESP-IDF v6.1\","
           "\"firmware\":\"dmp-espnow-dmp/0.1\",\"mac\":\"%s\",\"channel\":%u,"
           "\"boot_id\":\"%016" PRIx64 "\","
           "\"reset_reason\":\"%s\","
           "\"decoded_core_mtu_bytes\":%u,\"stream_r_encoded_mtu_bytes\":%u,"
           "\"espnow_v1_payload_mtu_bytes\":%u,\"espnow_v2_payload_mtu_bytes\":%u,"
           "\"espnow_version\":%" PRIu32 ",\"peer_capacity\":%u,"
           "\"entropy_ready\":%s,"
           "\"test_mode\":\"authenticated-dmp-endpoint\"}\n",
           CONFIG_IDF_TARGET, mac_text, QUAL_CHANNEL, g_boot_id,
           reset_reason_name(esp_reset_reason()),
           QUAL_DECODED_CORE_MTU_BYTES, QUAL_STREAM_R_ENCODED_MTU_BYTES,
           QUAL_ESPNOW_V1_PAYLOAD_MTU_BYTES, QUAL_ESPNOW_V2_PAYLOAD_MTU_BYTES,
           g_state.espnow_version, QUAL_MAX_PEERS,
           g_entropy_ready ? "true" : "false");
}

static bool init_dmp_stack(const char *profile_name)
{
    if (profile_name == NULL) return false;
    (void)snprintf(g_state.profile_name, sizeof(g_state.profile_name), "%s", profile_name);

    memset(&g_profile_config, 0, sizeof g_profile_config);
    g_profile_config.namespace_id = TEST_ONLY_NAMESPACE_ID;
    g_profile_config.node_id[0] = g_state.local_node_id;
    g_profile_config.node_id[1] = g_state.role == ROLE_CONTROLLER
                                      ? profile_peer_node_id(profile_name, 0U)
                                      : profile_controller_node_id(profile_name);
    if (strcmp(profile_name, "retry-2") == 0) {
        memcpy(g_state.active_profile_hash, RETRY_2_PROFILE_HASH, 32U);
        g_profile_config.peers = 1U;
        g_profile_config.message_bytes = 1024U;
        g_profile_config.chunk_bytes = 64U;
        g_profile_config.fragments = 16U;
        g_profile_config.encoded_mtu = QUAL_STREAM_R_ENCODED_MTU_BYTES;
        g_profile_config.forward_mtu = QUAL_DECODED_CORE_MTU_BYTES;
        g_profile_config.return_mtu = QUAL_DECODED_CORE_MTU_BYTES;
        g_profile_config.default_service = QUAL_SERVICE_SAMPLE1;
        g_profile_config.service_id[0] = QUAL_SERVICE_SAMPLE1;
        g_profile_config.service_id[1] = QUAL_SERVICE_DATA;
    } else if (strcmp(profile_name, "multi-peer") == 0) {
        memcpy(g_state.active_profile_hash, MULTI_PEER_PROFILE_HASH, 32U);
        g_profile_config.peers = QUAL_MAX_PEERS;
        g_profile_config.message_bytes = QUAL_MAX_PAYLOAD_BYTES;
        g_profile_config.chunk_bytes = QUAL_CHUNK_BYTES;
        g_profile_config.fragments = 32U;
        g_profile_config.encoded_mtu = QUAL_STREAM_R_ENCODED_MTU_BYTES;
        g_profile_config.forward_mtu = QUAL_DECODED_CORE_MTU_BYTES;
        g_profile_config.return_mtu = QUAL_DECODED_CORE_MTU_BYTES;
        g_profile_config.default_service = QUAL_SERVICE_SAMPLE1;
        g_profile_config.service_id[0] = QUAL_SERVICE_SAMPLE1;
        g_profile_config.service_id[1] = QUAL_SERVICE_DATA;
    } else {
        return false;
    }

    /* Keep runtime scheduling bounds aligned with the selected deployment
     * manifest. Stream R endpoint initialization needs frame and record bounds;
     * the reliability and reassembly layers also consume the remaining timers. */
    g_profile_config.frame_tx_ms = 1U;
    g_profile_config.forward_delay_ms = 20U;
    g_profile_config.return_delay_ms = 20U;
    g_profile_config.feedback_guard_ms = 4U;
    g_profile_config.record_margin_ms = 5U;
    g_profile_config.max_bursts = 3U;
    g_profile_config.max_probes = 0U;
    g_profile_config.max_status = 0U;
    g_profile_config.jitter_ms = 0U;
    g_profile_config.receipt_limit = 3U;
    g_profile_config.late_result_ms = 64U;
    if (strcmp(profile_name, "retry-2") == 0) {
        g_profile_config.queue_ms = 64U;
        g_profile_config.receipt_delay_ms = 110U;
        g_profile_config.burst_span_ms = 1024U;
        g_profile_config.feedback_delay_ms = 110U;
        g_profile_config.response_timeout_ms = 1280U;
        g_profile_config.send_horizon_ms = 5632U;
        g_profile_config.collect_ms = 5652U;
        g_profile_config.assembly_ms = 5657U;
        g_profile_config.dedup_ms = 6000U;
        g_profile_config.rejection_ms = 6000U;
        g_profile_config.result_cache_ms = 6000U;
        g_profile_config.result_deadline_ms = 12000U;
        g_profile_config.correlation_ms = 12288U;
        g_profile_config.tombstone_ms = 12288U;
    } else {
        g_profile_config.queue_ms = 1000U;
        g_profile_config.receipt_delay_ms = 1500U;
        g_profile_config.burst_span_ms = 35000U;
        g_profile_config.feedback_delay_ms = 1500U;
        g_profile_config.response_timeout_ms = 2000U;
        g_profile_config.send_horizon_ms = 120000U;
        g_profile_config.collect_ms = 120100U;
        g_profile_config.assembly_ms = 120105U;
        g_profile_config.dedup_ms = 130000U;
        g_profile_config.rejection_ms = 130000U;
        g_profile_config.result_cache_ms = 130000U;
        g_profile_config.result_deadline_ms = 250000U;
        g_profile_config.correlation_ms = 260000U;
        g_profile_config.tombstone_ms = 260000U;
    }

    g_profile_config.recovery[0] = DMP_PROFILE_RECOVERY_RETRY_ALL;
    g_profile_config.recovery[1] = DMP_PROFILE_RECOVERY_RETRY_ALL;
    g_profile_config.origin_route = 1U;
    g_profile_config.origin_ttl = 2U;
    g_profile_config.tx_borrow = true;
    g_profile_config.synchronous_completion = false;
    g_profile_config.operations_per_service = 1U;
    g_profile_config.control_slots = 2U;
    g_profile_config.adapter_slots = QUAL_MAX_ADAPTER_SLOTS;
    g_profile_config.sender_slots = 4U;
    g_profile_config.result_slots = 4U;
    g_profile_config.history_slots = 8U;
    g_profile_config.correlation_slots = 4U;
    g_profile_config.application_queue_slots =
        strcmp(profile_name, "retry-2") == 0 ? 2U : 1U;
    g_profile_config.assemblies_per_peer = 1U;
    g_profile_config.assembly_slots = g_profile_config.peers;
    g_profile_config.assembly_tombstones_per_peer = 16U;
    g_profile_config.assembly_tombstone_slots = g_profile_config.peers * 16U;

    dmp_status status = dmp_config_admit(&g_profile_config, &g_admitted_profile);
    if (status != DMP_OK) {
        ESP_LOGE(TAG, "dmp_config_admit failed: %d", (int)status);
        return false;
    }

    /* Provider setup */
    if (g_provider == NULL) {
        dmp_provider_ports provider_ports;
        memset(&provider_ports, 0, sizeof provider_ports);
        provider_ports.startup_ready = hw_startup_ready;
        provider_ports.startup_read = hw_startup_read;
        provider_ports.entropy = hw_entropy;
        provider_ports.allocate = hw_allocate;
        provider_ports.release = hw_release;
        provider_ports.scratch_limit = DMP_PROVIDER_SCRATCH_MAX;
        provider_ports.retained_limit = DMP_PROVIDER_RETAINED_MAX;

        g_provider = (dmp_provider *)calloc(1U, dmp_provider_size());
        if (g_provider == NULL || dmp_provider_setup(g_provider, &provider_ports) != DMP_PROVIDER_OK) {
            ESP_LOGE(TAG, "dmp_provider_setup failed");
            return false;
        }
    }

    /* Transport setup - caps set to manifest encoded MTU 263 */
    memset(&g_transport, 0, sizeof g_transport);
    g_transport.context = &g_state;
    g_transport.submit = espnow_transport_submit;
    g_transport.cancel = espnow_transport_cancel;
    g_transport.caps.max_frame_bytes = QUAL_STREAM_R_ENCODED_MTU_BYTES;
    g_transport.caps.ownership = DMP_TX_BORROW;
    g_transport.caps.synchronous_completion = 0;

    /* Endpoint storage */
    dmp_endpoint_storage storage;
    memset(&storage, 0, sizeof storage);
    storage.profile = &g_admitted_profile;
    storage.framing_mode = DMP_ENDPOINT_FRAMING_STREAM_R;
    storage.peer_states = g_peer_states;
    storage.peer_state_capacity = g_profile_config.peers;
    storage.identity_slots = g_identity_slots;
    storage.identity_capacity = g_profile_config.peers * 3U;

    dmp_identity_context_config context;
    memset(&context, 0, sizeof context);
    context.local.namespace_id = TEST_ONLY_NAMESPACE_ID;
    context.peer.namespace_id = TEST_ONLY_NAMESPACE_ID;
    context.local.origin_id = g_state.local_node_id;
    context.peer.origin_id = g_state.role == ROLE_CONTROLLER
                                 ? profile_peer_node_id(profile_name, 0U)
                                 : profile_controller_node_id(profile_name);
    context.security = 1U;
    storage.context = context;
    storage.transport = &g_transport;
    storage.notice = on_endpoint_notice;
    storage.notice_user = &g_state;

    /* Shared admission arena for multi-peer endpoints */
    if (g_admission_storage == NULL) {
        size_t admission_size = dmp_hs_admission_size();
        g_admission_storage = (uint8_t *)calloc(1U, admission_size);
        if (g_admission_storage == NULL) {
            ESP_LOGE(TAG, "admission storage allocation failed");
            return false;
        }
    }
    storage.handshake_admission = (struct dmp_hs_admission *)g_admission_storage;
    storage.handshake_admission_capacity = dmp_hs_admission_size();
    storage.handshake_max_pending = g_profile_config.peers;
    storage.handshake_max_scratch = g_state.handshake_scratch_slots;
    storage.handshake_global_work = 100000U;
    storage.handshake_ingress_work = 10000U;

    storage.senders = g_senders;
    storage.sender_capacity = g_profile_config.sender_slots;
    storage.sender_payload = g_sender_payload;
    storage.sender_payload_capacity = sizeof(g_sender_payload);
    storage.results = g_results;
    storage.result_capacity = g_profile_config.result_slots;
    storage.result_payload = g_result_payload;
    storage.result_payload_capacity = sizeof(g_result_payload);
    storage.history = g_history;
    storage.history_capacity = g_profile_config.history_slots;
    storage.correlations = g_correlations;
    storage.correlation_capacity = g_profile_config.correlation_slots;
    storage.history_metadata = g_history_metadata;
    storage.history_metadata_capacity = sizeof(g_history_metadata);
    storage.correlation_metadata = g_correlation_metadata;
    storage.correlation_metadata_capacity = sizeof(g_correlation_metadata);
    storage.adapters = g_adapters;
    storage.adapter_capacity = g_profile_config.adapter_slots;
    storage.frames = g_frames;
    storage.frame_capacity = sizeof(g_frames);
    storage.receive_payload = g_receive_payload;
    storage.receive_payload_capacity = sizeof(g_receive_payload);
    storage.stream_tx = g_stream_tx;
    storage.stream_tx_capacity = sizeof(g_stream_tx);
    storage.stream_rx = g_stream_rx;
    storage.stream_rx_capacity = sizeof(g_stream_rx);
    storage.assemblies = g_assemblies;
    storage.assembly_capacity = g_profile_config.assembly_slots;
    storage.tombstones = g_tombstones;
    storage.tombstone_capacity = g_profile_config.assembly_tombstone_slots;
    storage.freshness_slots = g_freshness;
    storage.freshness_capacity = 8U;
    storage.assembly_payload = g_assembly_payload;
    storage.assembly_payload_capacity = sizeof(g_assembly_payload);
    storage.assembly_metadata = g_assembly_metadata;
    storage.assembly_metadata_capacity = sizeof(g_assembly_metadata);
    storage.fragment_message = g_fragment_message;
    storage.fragment_message_capacity = sizeof(g_fragment_message);
    storage.fragment_frame = g_fragment_frame;
    storage.fragment_frame_capacity = sizeof(g_fragment_frame);
    storage.telemetry_payload = g_telemetry_payload;
    storage.telemetry_payload_capacity = sizeof(g_telemetry_payload);
    storage.telemetry_next = g_telemetry_next;
    storage.telemetry_next_capacity = sizeof(g_telemetry_next);
    storage.telemetry_frame = g_telemetry_frame;
    storage.telemetry_frame_capacity = sizeof(g_telemetry_frame);

    dmp_time_ms now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);
    status = dmp_endpoint_init(&g_endpoint, &storage, now);
    if (status != DMP_OK) {
        ESP_LOGE(TAG, "dmp_endpoint_init failed: %d", (int)status);
        return false;
    }

    /* Only the manifest SAMPLE-1 producer owns the durable epoch and sample. */
    g_sample1_active = false;
    if (g_state.local_node_id == profile_controller_node_id(profile_name)) {
        if (g_sample_nvs_handle == 0) {
            esp_err_t nvs_status = nvs_open("dmp_test_nvs", NVS_READWRITE,
                                            &g_sample_nvs_handle);
            if (nvs_status != ESP_OK) {
                ESP_LOGE(TAG, "SAMPLE-1 NVS open failed: %s", esp_err_to_name(nvs_status));
                return false;
            }
        }
        dmp_sample1_nvs_epoch_anchor_init(&g_sample_anchor, g_sample_nvs_handle,
                                          profile_sample1_anchor_key(profile_name), NULL);
        dmp_sample1_nvs_epoch_store_init(&g_sample_store, g_sample_nvs_handle,
                                         profile_sample1_epoch_key(profile_name),
                                         cb_allow_first_provisioning, NULL, NULL, NULL, NULL,
                                         &dmp_sample1_nvs_anchor_ops, &g_sample_anchor);
        dmp_sample1_endpoint_hooks hooks;
        memset(&hooks, 0, sizeof hooks);
        hooks.user = &g_sample_store;
        hooks.try_enter = sample1_hook_try_enter;
        hooks.leave = sample1_hook_leave;
        hooks.reserve_next = dmp_sample1_nvs_reserve_next;
        hooks.publish_telem = sample1_hook_dummy_publish;

        dmp_sample1_principal principal = {
            .namespace_id = TEST_ONLY_NAMESPACE_ID,
            .origin_id = profile_controller_node_id(profile_name)
        };
        if (dmp_sample1_endpoint_init(&g_sample_endpoint, &g_endpoint, principal,
                                      &hooks) != DMP_SAMPLE1_OWNER_OK) {
            ESP_LOGE(TAG, "SAMPLE-1 endpoint initialization failed");
            return false;
        }
        uint64_t epoch_started_us = (uint64_t)esp_timer_get_time();
        if (dmp_sample1_endpoint_begin_epoch(&g_sample_endpoint, now) != DMP_SAMPLE1_OWNER_OK) {
            ESP_LOGE(TAG, "SAMPLE-1 epoch reservation failed");
            return false;
        }
        char epoch_session[QUAL_SESSION_BYTES * 2U + 1U];
        format_session(epoch_session);
        printf("{\"event\":\"sample1_epoch_reserved\",\"session\":\"%s\","
               "\"epoch\":%" PRIu64 ",\"elapsed_us\":%" PRIu64 "}\n",
               epoch_session,
               g_sample_endpoint.owner.epoch,
               (uint64_t)esp_timer_get_time() - epoch_started_us);
        if (dmp_sample1_endpoint_publish(&g_sample_endpoint,
                                         UINT32_C(0x11223344), now) != DMP_SAMPLE1_OWNER_OK) {
            ESP_LOGE(TAG, "SAMPLE-1 initial publication failed");
            return false;
        }
        g_sample1_active = true;
    }

    return true;
}

static void log_peer_setup_stage(const char *stage, uint64_t started_us)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    uint64_t now_us = (uint64_t)esp_timer_get_time();
    format_session(session);
    printf("{\"event\":\"peer_setup_stage\",\"session\":\"%s\","
           "\"stage\":\"%s\",\"elapsed_us\":%" PRIu64 "}\n",
           session, stage, now_us >= started_us ? now_us - started_us : 0U);
}

static bool setup_peer_handshake(qual_peer_entry *peer)
{
    uint64_t started_us = (uint64_t)esp_timer_get_time();
    dmp_hs_config hs_cfg;
    log_peer_setup_stage("handshake_begin", started_us);
    memset(&hs_cfg, 0, sizeof hs_cfg);
    hs_cfg.namespace_id = TEST_ONLY_NAMESPACE_ID;
    hs_cfg.local_id = g_state.local_node_id;
    hs_cfg.peer_id = peer->node_id;
    memcpy(hs_cfg.profile_hash, g_state.active_profile_hash, 32U);
    hs_cfg.mode = 1U; /* NNpsk0 */
    hs_cfg.cipher = 1U; /* ChaChaPoly */
    hs_cfg.key_hint = 5U;
    memcpy(hs_cfg.psk, TEST_ONLY_PSK, 32U);
    hs_cfg.has_psk = 1;
    hs_cfg.permissions = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT |
                         DMP_ENDPOINT_PERMIT_TELEM | DMP_ENDPOINT_PERMIT_CONTROL;
    hs_cfg.next_rx_cid = (g_state.role == ROLE_CONTROLLER) ? (7U + peer->handle.slot * 2U)
                                                           : (8U + peer->handle.slot * 2U);

    hs_cfg.budget.max_pending = g_profile_config.peers;
    hs_cfg.budget.max_scratch = g_state.handshake_scratch_slots;
    hs_cfg.budget.episode_work = 1000U;
    if (strcmp(g_state.profile_name, "retry-2") == 0) {
        hs_cfg.budget.episode_attempts = 2U;
        hs_cfg.budget.episode_deadline_ms = 41000U;
        hs_cfg.budget.attempt_deadline_ms = 20000U;
        hs_cfg.budget.confirmation_timeout_ms = 512U;
        hs_cfg.budget.confirmation_attempts = 2U;
    } else {
        hs_cfg.budget.episode_attempts = 2U;
        hs_cfg.budget.episode_deadline_ms = 110000U;
        hs_cfg.budget.attempt_deadline_ms = 50000U;
        hs_cfg.budget.confirmation_timeout_ms = 4000U;
        hs_cfg.budget.confirmation_attempts = 2U;
    }
    hs_cfg.budget.replay_window = 1024U;
    hs_cfg.budget.failed_aead_limit = 1000U;
    hs_cfg.budget.association_lifetime_ms = 100000000U;
    hs_cfg.budget.global_work = 100000U;
    hs_cfg.budget.ingress_work = 10000U;
    hs_cfg.budget.episode_traffic = 16384U;
    hs_cfg.budget.restart_backoff_ms = 1000U;
    hs_cfg.budget.later_episodes = 2U;
    hs_cfg.budget.provisional_bytes = 120U;
    hs_cfg.budget.cached_responses = 1U;
    hs_cfg.budget.admit_burst = 100U;
    hs_cfg.budget.admit_window_ms = 1000U;

    dmp_hs_ports hs_ports;
    memset(&hs_ports, 0, sizeof hs_ports);
    hs_ports.now_ms = hw_hs_now_ms;
    hs_ports.entropy = hw_hs_entropy;
    hs_ports.commit_pin = hw_hs_commit_pin;
    hs_ports.ctx = peer;

    peer->hs = (dmp_hs *)calloc(1U, dmp_hs_size());
    if (peer->hs == NULL) return false;
    log_peer_setup_stage("handshake_storage_allocated", started_us);

    struct dmp_hs_admission *adm = dmp_endpoint_handshake_admission(&g_endpoint);
    dmp_hs_status st = dmp_hs_init_shared(peer->hs, g_provider, &hs_cfg, &hs_ports, adm);
    log_peer_setup_stage("handshake_init_returned", started_us);
    if (st != DMP_HS_OK) {
        ESP_LOGE(TAG, "dmp_hs_init_shared failed: %d", (int)st);
        return false;
    }
    if (dmp_hs_begin_episode(peer->hs) != DMP_HS_OK) {
        ESP_LOGE(TAG, "dmp_hs_begin_episode failed");
        return false;
    }
    log_peer_setup_stage("handshake_episode_started", started_us);

    peer->hs_tx = (dmp_hs_tx *)calloc(1U, dmp_hs_tx_size());
    if (peer->hs_tx == NULL) return false;

    dmp_hs_tx_config hs_tx_cfg = {
        .max_core_frame_bytes = QUAL_DECODED_CORE_MTU_BYTES,
        .max_bootstrap_fragments = 4U,
        .framing = DMP_HS_TX_STREAM_R
    };
    for (size_t s = 0; s < DMP_HS_TX_SLOT_MAX; ++s) {
        peer->hs_buffers[s].data = peer->hs_buffer_bytes[s];
        peer->hs_buffers[s].capacity = sizeof(peer->hs_buffer_bytes[s]);
    }
    dmp_hs_tx_status tx_st = dmp_hs_tx_init(peer->hs_tx, peer->hs, &g_transport,
                                           &hs_tx_cfg, &peer->hs_lifetime,
                                           peer->hs_buffers);
    log_peer_setup_stage("handshake_tx_init_returned", started_us);
    if (tx_st != DMP_HS_TX_ACCEPTED) {
        ESP_LOGE(TAG, "dmp_hs_tx_init failed: %d", (int)tx_st);
        return false;
    }

    dmp_stream_config rx_config = {
        .mode = DMP_STREAM_R,
        .max_core_bytes = QUAL_DECODED_CORE_MTU_BYTES,
        .partial_timeout_ms = (uint64_t)g_profile_config.frame_tx_ms +
                              (g_profile_config.forward_delay_ms > g_profile_config.return_delay_ms
                                   ? g_profile_config.forward_delay_ms
                                   : g_profile_config.return_delay_ms) +
                              g_profile_config.record_margin_ms
    };
    dmp_status rx_status = dmp_stream_init(
        &peer->hs_rx_decoder, rx_config,
        (dmp_buffer){ peer->hs_rx_bytes, sizeof(peer->hs_rx_bytes) },
        (dmp_time_ms)(esp_timer_get_time() / 1000LL));
    if (rx_status != DMP_OK) {
        ESP_LOGE(TAG, "handshake receive stream init failed: %d", (int)rx_status);
        return false;
    }
    peer->hs_rx_ready = true;
    log_peer_setup_stage("handshake_stream_ready", started_us);
    return true;
}

static void rollback_peer_setup(qual_peer_entry *peer, uint32_t peer_idx,
                                bool endpoint_peer_registered, bool esp_peer_added)
{
    dmp_time_ms now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);

    /* Slot zero is the endpoint's configured initial peer. Keep that context
     * intact so the same peer command can retry after a transient setup error. */
    if (endpoint_peer_registered && peer_idx != 0U && peer->handle.generation != 0U) {
        dmp_status revoke_status = dmp_endpoint_revoke_peer(&g_endpoint, peer->handle, now);
        if (revoke_status != DMP_OK) {
            ESP_LOGE(TAG, "endpoint peer rollback failed: %d", (int)revoke_status);
        }
    }

    if (peer->hs != NULL) {
        /* Cleanup is safe for a zeroed or partially initialized handshake and
         * wipes provider-owned state before the storage is released. */
        dmp_hs_cleanup(peer->hs);
        free(peer->hs);
    }
    free(peer->hs_tx);

    if (esp_peer_added) {
        esp_err_t delete_status = esp_now_del_peer(peer->mac);
        if (delete_status != ESP_OK) {
            ESP_LOGW(TAG, "ESP-NOW peer rollback failed: %s", esp_err_to_name(delete_status));
        }
    }
    memset(peer, 0, sizeof *peer);
}

static void trigger_handshake_sync(qual_peer_entry *peer)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    char peer_mac[18];
    dmp_tx_token token = {0};
    format_session(session);
    format_mac(peer->mac, peer_mac);

    if (peer->hs_sync_requested) {
        printf("{\"event\":\"handshake_stream_sync_failed\",\"session\":\"%s\","
               "\"peer_mac\":\"%s\",\"peer_handle\":%u,\"reason\":\"already-requested\"}\n",
               session, peer_mac, (unsigned)peer->handle.slot);
        return;
    }
    dmp_hs_tx_status status = dmp_hs_tx_sync(peer->hs_tx, peer->handle, &token);
    if (status != DMP_HS_TX_ACCEPTED) {
        printf("{\"event\":\"handshake_stream_sync_failed\",\"session\":\"%s\","
               "\"peer_mac\":\"%s\",\"peer_handle\":%u,\"status\":%d}\n",
               session, peer_mac, (unsigned)peer->handle.slot, (int)status);
        return;
    }
    peer->hs_sync_requested = true;
    printf("{\"event\":\"handshake_stream_sync_submitted\",\"session\":\"%s\","
           "\"peer_mac\":\"%s\",\"peer_handle\":%u}\n",
           session, peer_mac, (unsigned)peer->handle.slot);
}

static void trigger_handshake(qual_peer_entry *peer)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    char peer_mac[18];
    format_session(session);
    format_mac(peer->mac, peer_mac);

    printf("{\"event\":\"handshake_schedule_started\",\"session\":\"%s\","
           "\"peer_mac\":\"%s\",\"peer_handle\":%u}\n",
           session, peer_mac, (unsigned)peer->handle.slot);

    if (peer->handshake_poll_failed) {
        printf("{\"event\":\"handshake_failed\",\"session\":\"%s\",\"peer_mac\":\"%s\","
               "\"peer_handle\":%u,\"reason\":\"handshake-poll-failed\"}\n",
               session, peer_mac, (unsigned)peer->handle.slot);
        return;
    }

    dmp_time_ms now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);
    peer->handshake_started_us = (uint64_t)esp_timer_get_time();
    dmp_hs_status st = dmp_hs_schedule(peer->hs, &peer->attempt_index);
    printf("{\"event\":\"handshake_schedule_done\",\"session\":\"%s\","
           "\"peer_mac\":\"%s\",\"peer_handle\":%u,\"status\":%d}\n",
           session, peer_mac, (unsigned)peer->handle.slot, (int)st);
    if (st != DMP_HS_OK) {
        printf("{\"event\":\"handshake_failed\",\"session\":\"%s\",\"peer_mac\":\"%s\","
               "\"reason\":\"schedule-failed\",\"status\":%d}\n",
               session, peer_mac, (int)st);
        return;
    }

    dmp_tx_token token = {0};
    printf("{\"event\":\"handshake_submit_started\",\"session\":\"%s\","
           "\"peer_mac\":\"%s\",\"peer_handle\":%u}\n",
           session, peer_mac, (unsigned)peer->handle.slot);
    dmp_hs_tx_status tx_st = dmp_hs_tx_submit(peer->hs_tx, peer->attempt_index,
                                             DMP_HS_TX_CACHED_FLIGHT,
                                             peer->handle, 0U, now, &token);
    printf("{\"event\":\"handshake_submit_done\",\"session\":\"%s\","
           "\"peer_mac\":\"%s\",\"peer_handle\":%u,\"status\":%d}\n",
           session, peer_mac, (unsigned)peer->handle.slot, (int)tx_st);
    if (tx_st != DMP_HS_TX_ACCEPTED) {
        printf("{\"event\":\"handshake_failed\",\"session\":\"%s\",\"peer_mac\":\"%s\","
               "\"reason\":\"m1-submit-failed\",\"status\":%d}\n",
               session, peer_mac, (int)tx_st);
        return;
    }
    peer->pending_hs_token = token;
    peer->pending_hs_submit = true;
    printf("{\"event\":\"handshake_started\",\"session\":\"%s\",\"peer_mac\":\"%s\","
           "\"peer_handle\":%u}\n", session, peer_mac, (unsigned)peer->handle.slot);
}

static bool activate_authenticated_peer(qual_peer_entry *peer, uint32_t attempt_index)
{
    const uint32_t permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT |
                            DMP_ENDPOINT_PERMIT_TELEM | DMP_ENDPOINT_PERMIT_CONTROL;
    dmp_endpoint_grant grants[4] = {
        { g_state.local_node_id, QUAL_SERVICE_DATA, permit },
        { peer->node_id, QUAL_SERVICE_DATA, permit },
        { g_state.local_node_id, QUAL_SERVICE_SAMPLE1, permit },
        { peer->node_id, QUAL_SERVICE_SAMPLE1, permit },
    };
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    char peer_mac[18];
    dmp_time_ms now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);
    dmp_status endpoint_status = dmp_endpoint_bind_peer(
        &g_endpoint, peer->handle, peer->hs, attempt_index);
    dmp_sample1_owner_result sample_status = DMP_SAMPLE1_OWNER_OK;

    if (endpoint_status == DMP_OK) {
        endpoint_status = dmp_endpoint_set_peer_grants(
            &g_endpoint, peer->handle, grants, sizeof grants / sizeof grants[0]);
    }
    if (endpoint_status == DMP_OK && g_sample1_active) {
        sample_status = dmp_sample1_endpoint_activate_peer(
            &g_sample_endpoint, peer->handle);
    }

    format_session(session);
    format_mac(peer->mac, peer_mac);
    if (endpoint_status != DMP_OK || sample_status != DMP_SAMPLE1_OWNER_OK) {
        peer->handshake_activation_failed = true;
        dmp_status revoke_status = dmp_endpoint_revoke_peer(
            &g_endpoint, peer->handle, now);
        printf("{\"event\":\"handshake_failed\",\"session\":\"%s\","
               "\"peer_mac\":\"%s\",\"peer_handle\":%u,"
               "\"reason\":\"endpoint-activation-failed\","
               "\"endpoint_status\":%d,\"sample_status\":%d,"
               "\"revoke_status\":%d}\n",
               session, peer_mac, (unsigned)peer->handle.slot,
               (int)endpoint_status, (int)sample_status, (int)revoke_status);
        return false;
    }

    peer->handshake_done = true;
    uint64_t handshake_elapsed_us = peer->handshake_started_us != 0U &&
                                    (uint64_t)esp_timer_get_time() >= peer->handshake_started_us
                                        ? (uint64_t)esp_timer_get_time() - peer->handshake_started_us
                                        : 0U;
    printf("{\"event\":\"handshake_done\",\"session\":\"%s\","
           "\"peer_mac\":\"%s\",\"peer_handle\":%u,\"status\":\"success\","
           "\"elapsed_us\":%" PRIu64 "}\n",
           session, peer_mac, (unsigned)peer->handle.slot, handshake_elapsed_us);
    return true;
}

static void handle_rx_packet(const qual_wifi_event *event)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    char src_mac[18];
    format_session(session);
    format_mac(event->mac, src_mac);

    int peer_idx = find_peer_by_mac(event->mac);
    if (peer_idx < 0) {
        printf("{\"event\":\"rx_rejected\",\"session\":\"%s\",\"src_mac\":\"%s\","
               "\"reason\":\"unknown-peer\"}\n", session, src_mac);
        return;
    }
    qual_peer_entry *peer = &g_state.peers[peer_idx];
    dmp_time_ms now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);

    if (peer->handshake_poll_failed) {
        printf("{\"event\":\"rx_rejected\",\"session\":\"%s\",\"src_mac\":\"%s\","
               "\"reason\":\"handshake-poll-failed\"}\n",
               session, src_mac);
        return;
    }

    if (event->length > g_state.max_observed_rx_frame_bytes) {
        g_state.max_observed_rx_frame_bytes = event->length;
    }
    ++g_state.stats_rx_frames;

    /* Keep a decoder per peer because ESP-NOW reports each datagram separately,
     * while Stream R synchronization and candidate state span submissions. */
    if (!peer->hs_rx_ready) {
        printf("{\"event\":\"rx_rejected\",\"session\":\"%s\",\"src_mac\":\"%s\","
               "\"reason\":\"handshake-stream-not-initialized\"}\n", session, src_mac);
        return;
    }
    dmp_stream_result stream_result = dmp_stream_feed(
        &peer->hs_rx_decoder, (dmp_bytes){ event->bytes, event->length }, now);
    if (!peer->handshake_done) {
        printf("{\"event\":\"handshake_rx_datagram\",\"session\":\"%s\","
               "\"src_mac\":\"%s\",\"bytes\":%u,\"stream_event\":%d}\n",
               session, src_mac, (unsigned)event->length, (int)stream_result.event);
    }
    if (event->length == 1U && event->bytes[0] == 0U) {
        /* The endpoint and handshake adapter own separate Stream R decoders. */
        (void)dmp_endpoint_rx_from(&g_endpoint, peer->handle,
                                   (dmp_bytes){ event->bytes, event->length }, now);
    }
    if (stream_result.event == DMP_STREAM_NONE) {
        return;
    }
    if (stream_result.event != DMP_STREAM_FRAME) {
        printf("{\"event\":\"rx_rejected\",\"session\":\"%s\",\"src_mac\":\"%s\","
               "\"reason\":\"incomplete-or-invalid-stream-r-frame\",\"bytes\":%u}\n",
               session, src_mac, (unsigned)event->length);
        return;
    }

    dmp_frame_view view;
    dmp_core_limits limits = {
        QUAL_DECODED_CORE_MTU_BYTES, QUAL_MAX_PAYLOAD_BYTES, 32U
    };
    dmp_parse_result parse_res = dmp_core_parse(stream_result.frame, &limits, &view);
    if (parse_res.status != DMP_OK) {
        printf("{\"event\":\"rx_rejected\",\"session\":\"%s\",\"src_mac\":\"%s\","
               "\"reason\":\"invalid-decoded-core-frame\",\"status\":%d}\n",
               session, src_mac, (int)parse_res.status);
        return;
    }

    dmp_qual_handshake_frame_kind handshake_frame =
        dmp_qual_classify_handshake_frame(&view);
    if (handshake_frame == DMP_QUAL_FRAME_BOOTSTRAP) {
        /* Handshake M1 or M2 */
        if (peer->handshake_started_us == 0U) {
            peer->handshake_started_us = (uint64_t)esp_timer_get_time();
        }
        dmp_hs_ingress ingress;
        dmp_hs_completion completion;
        dmp_qual_bootstrap_context wire_context;
        memset(&ingress, 0, sizeof ingress);
        ingress.payload = view.payload.data;
        ingress.payload_len = view.payload.size;
        if (dmp_qual_parse_bootstrap_context(&view, &wire_context) != DMP_OK) {
            printf("{\"event\":\"handshake_bootstrap_context_rejected\","
                   "\"session\":\"%s\",\"src_mac\":\"%s\","
                   "\"sequence\":%u}\n",
                   session, src_mac, (unsigned)view.fields.seq);
            return;
        }
        ingress.origin_id = wire_context.origin_id;
        ingress.destination_id = g_state.local_node_id;
        ingress.namespace_id = wire_context.namespace_id;
        ingress.context_epoch = wire_context.provisional_epoch;
        ingress.seq = view.fields.seq;

        dmp_hs_status offer_status = dmp_hs_offer(peer->hs, &ingress, &completion);
        dmp_hs_status hst = offer_status;
        if (hst == DMP_HS_AWAITING) {
            hst = dmp_hs_accept(peer->hs, &completion);
        }
        printf("{\"event\":\"handshake_ingress_result\",\"session\":\"%s\","
               "\"src_mac\":\"%s\",\"role\":%u,\"sequence\":%u,"
               "\"context_epoch\":%" PRIu64 ",\"payload_bytes\":%u,"
               "\"offer_status\":%d,\"final_status\":%d}\n",
               session, src_mac, (unsigned)g_state.role, (unsigned)ingress.seq,
               ingress.context_epoch, (unsigned)ingress.payload_len,
               (int)offer_status, (int)hst);

        if (hst == DMP_HS_CANDIDATE) {
            if (g_state.role == ROLE_PEER) {
                /* Responder: M1 received, M2 produced -> send M2 */
                peer->resp_attempt_index = completion.attempt_index;
                dmp_tx_token token = {0};
                dmp_hs_tx_status s = dmp_hs_tx_submit(peer->hs_tx, peer->resp_attempt_index,
                                                     DMP_HS_TX_CACHED_FLIGHT,
                                                     peer->handle, 0U, now, &token);
                printf("{\"event\":\"handshake_response_submit\",\"session\":\"%s\","
                       "\"peer_mac\":\"%s\",\"peer_handle\":%u,"
                       "\"attempt_index\":%" PRIu32 ",\"status\":%d}\n",
                       session, src_mac, (unsigned)peer->handle.slot,
                       peer->resp_attempt_index, (int)s);
                if (s == DMP_HS_TX_ACCEPTED) {
                    peer->pending_hs_token = token;
                    peer->pending_hs_submit = true;
                }
            } else if (g_state.role == ROLE_CONTROLLER) {
                /* Initiator: M2 received -> confirm attempt -> send FINISH */
                if (dmp_hs_confirm(peer->hs, peer->attempt_index) == DMP_HS_OK) {
                    dmp_tx_token token = {0};
                    dmp_hs_tx_status s = dmp_hs_tx_submit(peer->hs_tx, peer->attempt_index,
                                                         DMP_HS_TX_PROTECTED_FRAME,
                                                         peer->handle, 0U, now, &token);
                    if (s == DMP_HS_TX_ACCEPTED) {
                        peer->pending_hs_token = token;
                        peer->pending_hs_submit = true;
                    }
                }
            }
        }
        return;
    }

    if (handshake_frame == DMP_QUAL_FRAME_PROTECTED_HELLO) {
        /* FINISH/READY are protected HELLO frames. Keep routing duplicates
         * through SEC-1 after activation so fresh-PN retries can be answered. */
        dmp_hs_protected incoming;
        memset(&incoming, 0, sizeof incoming);
        incoming.frame = stream_result.frame.data;
        incoming.frame_len = stream_result.frame.size;
        incoming.origin_id = peer->node_id;
        incoming.destination_id = g_state.local_node_id;
        incoming.namespace_id = TEST_ONLY_NAMESPACE_ID;
        uint32_t attempt_index = g_state.role == ROLE_CONTROLLER
                                     ? peer->attempt_index
                                     : peer->resp_attempt_index;
        uint64_t initiator_epoch = 0U;
        uint64_t responder_epoch = 0U;
        if (!dmp_hs_epochs(peer->hs, attempt_index, &initiator_epoch, &responder_epoch)) {
            printf("{\"event\":\"handshake_protected_context_failed\","
                   "\"session\":\"%s\",\"src_mac\":\"%s\","
                   "\"peer_handle\":%u,\"attempt_index\":%" PRIu32 "}\n",
                   session, src_mac, (unsigned)peer->handle.slot, attempt_index);
            return;
        }
        incoming.context_epoch = g_state.role == ROLE_CONTROLLER
                                     ? responder_epoch
                                     : initiator_epoch;

        dmp_hs_status protected_status = dmp_hs_offer_protected(peer->hs, &incoming);
        if (protected_status == DMP_HS_OK) {
            if (g_state.role == ROLE_PEER) {
                /* Responder received FINISH -> send READY */
                dmp_tx_token token = {0};
                dmp_hs_tx_status s = dmp_hs_tx_submit(peer->hs_tx, peer->resp_attempt_index,
                                                     DMP_HS_TX_PROTECTED_FRAME,
                                                     peer->handle, 0U, now, &token);
                printf("{\"event\":\"handshake_ready_submit\",\"session\":\"%s\","
                       "\"peer_mac\":\"%s\",\"peer_handle\":%u,"
                       "\"attempt_index\":%" PRIu32 ",\"accepted\":%s,"
                       "\"status\":%d,\"status_name\":\"%s\"}\n",
                       session, src_mac, (unsigned)peer->handle.slot,
                       peer->resp_attempt_index,
                       s == DMP_HS_TX_ACCEPTED ? "true" : "false", (int)s,
                       hs_tx_status_name(s));
                if (s == DMP_HS_TX_ACCEPTED) {
                    peer->pending_hs_token = token;
                    peer->pending_hs_submit = true;
                    peer->handshake_tx_ready = true;
                }
            } else if (g_state.role == ROLE_CONTROLLER) {
                /* A valid protected READY is the initiator's confirmation. */
                peer->handshake_tx_ready = true;
            }
            if (!peer->handshake_done && !peer->handshake_activation_failed &&
                dmp_hs_association_active(peer->hs)) {
                uint32_t active_idx = (g_state.role == ROLE_CONTROLLER) ? peer->attempt_index
                                                                       : peer->resp_attempt_index;
                (void)activate_authenticated_peer(peer, active_idx);
            }
        }
        return;
    }

    if (!peer->handshake_done) {
        return;
    }

    static const uint8_t probe_magic[8] = { 'D', 'M', 'P', 'V', '2', 'P', 'R', 'B' };
    if (view.fields.type == DMP_TYPE_DATA && view.payload.size >= 16U &&
        memcmp(view.payload.data, probe_magic, sizeof(probe_magic)) == 0 &&
        memcmp(view.payload.data + sizeof(probe_magic), g_state.session_token,
               QUAL_SESSION_BYTES) == 0) {
        printf("{\"event\":\"v2_frame_received\",\"session\":\"%s\","
               "\"peer_handle\":%u,\"decoded_bytes\":%u,\"encoded_bytes\":%u,"
               "\"authenticated\":false,\"classification\":\"raw-v2-capability-probe\"}\n",
               session, (unsigned)peer_idx, (unsigned)stream_result.frame.size,
               (unsigned)event->length);
        return;
    }

    /* Deliver application/endpoint traffic through the manifest Stream R path. */
    (void)dmp_endpoint_rx_from(&g_endpoint, peer->handle,
                               (dmp_bytes){ event->bytes, event->length }, now);
}

static void handle_tx_done(const dmp_qual_tx_completion_event *event)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    char peer_mac[18];
    format_session(session);

    if (!g_state.tx_live) {
        format_mac(event->mac, peer_mac);
        printf("{\"event\":\"stale_tx_callback\",\"peer_mac\":\"%s\"}\n", peer_mac);
        return;
    }

    bool is_probe = g_state.current_tx_probe;
    g_state.tx_live = false;
    g_state.current_tx_probe = false;
    ++g_state.stats_tx_frames;
    const bool ok = (event->status == (int)ESP_NOW_SEND_SUCCESS);
    if (ok) {
        ++g_state.stats_tx_ok;
    } else {
        ++g_state.stats_tx_failed;
    }

    format_mac(g_state.current_tx_mac, peer_mac);
    if (is_probe) {
        printf("{\"event\":\"v2_frame_tx_done\",\"session\":\"%s\",\"peer_mac\":\"%s\","
               "\"peer_handle\":%u,\"encoded_bytes\":%u,\"status\":\"%s\","
               "\"authenticated\":false}\n",
               session, peer_mac, (unsigned)g_state.current_tx_peer_idx,
               (unsigned)g_state.current_tx_len, ok ? "success" : "failed");
        return;
    }
    printf("{\"event\":\"tx_done\",\"session\":\"%s\",\"peer_mac\":\"%s\","
           "\"peer_handle\":%u,\"frame_bytes\":%u,\"status\":\"%s\","
           "\"transport_outcome\":\"%s\"}\n",
           session, peer_mac, (unsigned)g_state.current_tx_peer_idx,
           (unsigned)g_state.current_tx_len, ok ? "success" : "failed",
           ok ? "transmitted" : "possibly-transmitted");

    dmp_time_ms now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);
    dmp_tx_outcome outcome = dmp_qual_espnow_tx_outcome(ok);

    if (g_state.current_tx_complete != NULL) {
        dmp_tx_complete_fn fn = g_state.current_tx_complete;
        void *owner = g_state.current_tx_owner;
        dmp_tx_token token = g_state.current_tx_token;
        g_state.current_tx_complete = NULL;
        fn(owner, token, outcome, now);
    }

    /* Release slot in handshake transport if active */
    for (size_t i = 0; i < QUAL_MAX_PEERS; ++i) {
        if (g_state.peers[i].hs_tx != NULL) {
            dmp_hs_tx_result res;
            while (dmp_hs_tx_take(g_state.peers[i].hs_tx, &res) == DMP_HS_TX_ACCEPTED) {
                if (res.synchronization) {
                    char sync_peer_mac[18];
                    format_mac(g_state.peers[i].mac, sync_peer_mac);
                    printf("{\"event\":\"handshake_stream_sync_done\",\"session\":\"%s\","
                           "\"peer_mac\":\"%s\",\"peer_handle\":%u,\"status\":\"%s\"}\n",
                           session, sync_peer_mac,
                           (unsigned)g_state.peers[i].handle.slot,
                           res.outcome == DMP_TX_TRANSMITTED ? "success" : "failed");
                    continue;
                }
                if (g_state.peers[i].in_use && !g_state.peers[i].handshake_poll_failed &&
                    dmp_hs_association_active(g_state.peers[i].hs) &&
                    !g_state.peers[i].handshake_done &&
                    !g_state.peers[i].handshake_activation_failed) {
                    uint32_t active_idx = (g_state.role == ROLE_CONTROLLER)
                                              ? g_state.peers[i].attempt_index
                                              : g_state.peers[i].resp_attempt_index;
                    (void)activate_authenticated_peer(&g_state.peers[i], active_idx);
                }
            }
        }
    }
}

static void trigger_service2_transfer(uint32_t peer_idx, size_t bytes)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    char peer_mac[18];
    format_session(session);

    if (peer_idx >= QUAL_MAX_PEERS || !g_state.peers[peer_idx].in_use) {
        printf("{\"event\":\"transfer_failed\",\"session\":\"%s\",\"peer_handle\":%u,"
               "\"reason\":\"invalid-peer-handle\"}\n", session, (unsigned)peer_idx);
        return;
    }
    format_mac(g_state.peers[peer_idx].mac, peer_mac);

    if (bytes == 0U || bytes > QUAL_MAX_PAYLOAD_BYTES) {
        printf("{\"event\":\"transfer_failed\",\"session\":\"%s\",\"peer_handle\":%u,"
               "\"reason\":\"invalid-bytes\"}\n", session, (unsigned)peer_idx);
        return;
    }
    if (!g_state.peers[peer_idx].handshake_done) {
        printf("{\"event\":\"transfer_failed\",\"session\":\"%s\",\"peer_handle\":%u,"
               "\"reason\":\"unauthenticated-peer\"}\n", session, (unsigned)peer_idx);
        return;
    }
    if (!g_state.peers[peer_idx].handshake_tx_ready) {
        printf("{\"event\":\"transfer_failed\",\"session\":\"%s\",\"peer_handle\":%u,"
               "\"reason\":\"confirmation-not-ready\"}\n",
               session, (unsigned)peer_idx);
        return;
    }
    uint32_t chunk_bytes = g_profile_config.chunk_bytes;
    if (chunk_bytes == 0U) {
        printf("{\"event\":\"transfer_failed\",\"session\":\"%s\",\"peer_handle\":%u,"
               "\"reason\":\"profile-chunk-size-unavailable\"}\n",
               session, (unsigned)peer_idx);
        return;
    }

    /* Initialize deterministic test pattern */
    for (size_t i = 0; i < bytes; ++i) {
        g_test_transfer_payload[i] = (uint8_t)((i * 31U + 17U) & 0xFFU);
    }

    dmp_time_ms now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);
    dmp_status st = dmp_endpoint_submit_fragmented_to(
        &g_endpoint, g_state.peers[peer_idx].handle, QUAL_SERVICE_DATA,
        (dmp_bytes){ g_test_transfer_payload, bytes }, now);

    if (st != DMP_OK) {
        printf("{\"event\":\"transfer_failed\",\"session\":\"%s\",\"peer_handle\":%u,"
               "\"reason\":\"endpoint-submit-failed\",\"status\":%d}\n",
               session, (unsigned)peer_idx, (int)st);
        return;
    }

    uint32_t fragments = (uint32_t)((bytes + chunk_bytes - 1U) / chunk_bytes);
    printf("{\"event\":\"transfer_started\",\"session\":\"%s\",\"peer_handle\":%u,"
           "\"peer_mac\":\"%s\",\"bytes\":%u,\"chunk_bytes\":%" PRIu32 ",\"fragments\":%" PRIu32 ","
           "\"sender_ack_required\":false,\"delivery_evidence\":\"receiver-rx_assembled\"}\n",
           session, (unsigned)peer_idx, peer_mac, (unsigned)bytes, chunk_bytes, fragments);
}

static void trigger_v2_frame(uint32_t peer_idx)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    format_session(session);

    if (peer_idx >= QUAL_MAX_PEERS || !g_state.peers[peer_idx].in_use) {
        printf("{\"event\":\"command_rejected\",\"reason\":\"invalid-peer-handle\"}\n");
        return;
    }
    if (g_state.tx_live) {
        printf("{\"event\":\"v2_frame_failed\",\"session\":\"%s\","
               "\"reason\":\"transport-busy\"}\n", session);
        return;
    }
    qual_peer_entry *peer = &g_state.peers[peer_idx];
    if (!peer->handshake_done || !peer->handshake_tx_ready) {
        printf("{\"event\":\"v2_frame_failed\",\"session\":\"%s\","
               "\"reason\":\"confirmation-not-ready\"}\n", session);
        return;
    }

    /* Build a valid 256-byte Core frame: 2-byte header + 254-byte payload */
    uint8_t core_buf[QUAL_DECODED_CORE_MTU_BYTES];
    uint8_t payload[QUAL_DECODED_CORE_MTU_BYTES - 2U];
    static const uint8_t probe_magic[8] = { 'D', 'M', 'P', 'V', '2', 'P', 'R', 'B' };
    for (size_t i = 0; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)((i * 13U + 7U) & 0xFFU);
    }
    memcpy(payload, probe_magic, sizeof(probe_magic));
    memcpy(payload + sizeof(probe_magic), g_state.session_token, QUAL_SESSION_BYTES);

    dmp_frame_spec spec;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = DMP_TYPE_DATA;
    spec.payload.data = payload;
    spec.payload.size = sizeof(payload);

    dmp_core_limits limits = {
        .max_frame_bytes = QUAL_DECODED_CORE_MTU_BYTES,
        .max_message_bytes = QUAL_MAX_PAYLOAD_BYTES,
        .max_fragments = 32U
    };
    size_t core_written = 0;
    dmp_status cst = dmp_core_encode(&spec, &limits,
                                     (dmp_buffer){ core_buf, sizeof(core_buf) },
                                     &core_written);
    if (cst != DMP_OK || core_written != QUAL_DECODED_CORE_MTU_BYTES) {
        printf("{\"event\":\"v2_frame_failed\",\"session\":\"%s\",\"reason\":\"core-encode-failed\",\"status\":%d}\n",
               session, (int)cst);
        return;
    }

    /* Encode with Stream R -> produces frame > 250 bytes bounded by 263 */
    uint8_t encoded_buf[QUAL_STREAM_R_ENCODED_MTU_BYTES];
    size_t encoded_written = 0;
    dmp_status sst = dmp_stream_encode(DMP_STREAM_R,
                                       (dmp_bytes){ core_buf, core_written },
                                       (dmp_buffer){ encoded_buf, sizeof(encoded_buf) },
                                       &encoded_written);
    if (sst != DMP_OK || encoded_written <= QUAL_ESPNOW_V1_PAYLOAD_MTU_BYTES ||
        encoded_written > QUAL_STREAM_R_ENCODED_MTU_BYTES) {
        printf("{\"event\":\"v2_frame_failed\",\"session\":\"%s\",\"reason\":\"stream-encode-failed\",\"status\":%d}\n",
               session, (int)sst);
        return;
    }

    g_state.tx_live = true;
    g_state.current_tx_probe = true;
    g_state.current_tx_peer_idx = peer_idx;
    g_state.current_tx_complete = NULL;
    g_state.current_tx_owner = NULL;
    g_state.current_tx_len = encoded_written;
    memcpy(g_state.current_tx_mac, peer->mac, sizeof(g_state.current_tx_mac));
    esp_err_t err = esp_now_send(peer->mac, encoded_buf, encoded_written);
    if (err != ESP_OK) {
        g_state.tx_live = false;
        g_state.current_tx_probe = false;
        printf("{\"event\":\"v2_frame_failed\",\"session\":\"%s\",\"reason\":\"espnow-send-failed\",\"error\":%d}\n",
               session, (int)err);
        return;
    }

    if (encoded_written > g_state.max_observed_tx_frame_bytes) {
        g_state.max_observed_tx_frame_bytes = encoded_written;
    }

    printf("{\"event\":\"v2_frame_emitted\",\"session\":\"%s\",\"peer_handle\":%u,"
           "\"decoded_bytes\":%u,\"encoded_bytes\":%u,\"authenticated\":false}\n",
           session, (unsigned)peer_idx, (unsigned)core_written, (unsigned)encoded_written);
}

static const char *sample_owner_result_name(dmp_sample1_owner_result result)
{
    switch (result) {
    case DMP_SAMPLE1_OWNER_OK: return "ok";
    case DMP_SAMPLE1_OWNER_BUSY: return "busy";
    case DMP_SAMPLE1_OWNER_NOT_READY: return "not-ready";
    case DMP_SAMPLE1_OWNER_STOPPED: return "stopped";
    case DMP_SAMPLE1_OWNER_INVALID: return "invalid";
    default: return "unknown";
    }
}

static uint32_t sample_endpoint_live_peer_records(void)
{
    uint32_t count = 0U;
    for (uint32_t i = 0U; i < DMP_PROFILE_MAX_PEERS; ++i) {
        count += g_sample_endpoint.peers[i].live != 0U ? 1U : 0U;
    }
    return count;
}

static void rotate_sample1_epoch(uint32_t sample_value)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    uint64_t previous_epoch = g_sample_endpoint.owner.epoch;
    uint64_t reserved_epoch = 0U;
    uint64_t new_epoch = 0U;
    uint32_t peer_records_before = sample_endpoint_live_peer_records();
    dmp_sample1_owner_result result;
    dmp_time_ms now;

    format_session(session);
    if (g_state.role != ROLE_CONTROLLER || g_sample_endpoint.initialized == 0U ||
        g_sample_endpoint.owner.stopped) {
        printf("{\"event\":\"sample1_epoch_transition\",\"session\":\"%s\","
               "\"status\":\"not-ready\",\"owner_status\":%d}\n",
               session, (int)DMP_SAMPLE1_OWNER_NOT_READY);
        return;
    }

    now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);
    result = dmp_sample1_endpoint_begin_epoch(&g_sample_endpoint, now);
    if (result == DMP_SAMPLE1_OWNER_OK) {
        new_epoch = g_sample_endpoint.owner.epoch;
        reserved_epoch = new_epoch;
        result = dmp_sample1_endpoint_publish(&g_sample_endpoint, sample_value, now);
    } else {
        reserved_epoch = g_sample_endpoint.owner.transition_reserved_epoch;
    }
    g_sample1_active = g_sample_endpoint.owner.active &&
                       !g_sample_endpoint.owner.stopped;

    printf("{\"event\":\"sample1_epoch_transition\",\"session\":\"%s\","
           "\"status\":\"%s\",\"owner_status\":%d,"
           "\"previous_epoch\":%" PRIu64 ",\"reserved_epoch\":%" PRIu64 ","
           "\"new_epoch\":%" PRIu64 ","
           "\"sample_value\":%" PRIu32 ","
           "\"peer_records_before\":%" PRIu32 ",\"peer_records_after\":%" PRIu32 ","
           "\"owner_active\":%s,\"sample_published\":%s}\n",
           session, sample_owner_result_name(result), (int)result, previous_epoch,
           reserved_epoch, new_epoch, sample_value,
           peer_records_before, sample_endpoint_live_peer_records(),
           g_sample_endpoint.owner.active ? "true" : "false",
           (result == DMP_SAMPLE1_OWNER_OK && g_sample_endpoint.owner.have_sample)
               ? "true" : "false");
}

static void handle_command(const char *line)
{
    char session[QUAL_SESSION_BYTES * 2U + 1U];
    char arg1[32] = { 0 };
    char arg2[32] = { 0 };
    char extra = '\0';
    format_session(session);

    if (strcmp(line, "REBOOT") == 0) {
        printf("{\"event\":\"reboot_requested\",\"target\":\"%s\","
               "\"boot_id\":\"%016" PRIx64 "\"}\n",
               CONFIG_IDF_TARGET, g_boot_id);
        (void)fflush(stdout);
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    } else if (strcmp(line, "INFO") == 0) {
        log_ready();
    } else if (sscanf(line, "SESSION %16s %c", arg1, &extra) == 1) {
        uint8_t token[QUAL_SESSION_BYTES];
        for (size_t i = 0; i < QUAL_SESSION_BYTES; ++i) {
            unsigned int byte_val;
            if (sscanf(arg1 + i * 2U, "%02x", &byte_val) != 1) {
                printf("{\"event\":\"command_rejected\",\"reason\":\"invalid-session-hex\"}\n");
                return;
            }
            token[i] = (uint8_t)byte_val;
        }
        memcpy(g_state.session_token, token, QUAL_SESSION_BYTES);
        g_state.session_set = true;
        char mac_text[18];
        format_mac(g_state.own_mac, mac_text);
        format_session(session);
        printf("{\"event\":\"session_set\",\"session\":\"%s\",\"target\":\"%s\",\"mac\":\"%s\"}\n",
               session, CONFIG_IDF_TARGET, mac_text);
    } else if (sscanf(line, "PROFILE %31s", arg1) == 1) {
        if (!g_state.session_set) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"session-not-set\"}\n");
            return;
        }
        if (g_state.stack_initialized) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"profile-already-initialized-in-session\"}\n");
            return;
        }
        if (strcmp(arg1, "retry-2") != 0 && strcmp(arg1, "multi-peer") != 0) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"unknown-profile\"}\n");
            return;
        }
        (void)snprintf(g_state.profile_name, sizeof(g_state.profile_name), "%s", arg1);
        g_state.handshake_scratch_slots = strcmp(arg1, "retry-2") == 0 ? 1U : 2U;
        printf("{\"event\":\"profile_set\",\"session\":\"%s\",\"profile\":\"%s\"}\n", session, arg1);
    } else if (strncmp(line, "ROLE ", 5U) == 0) {
        unsigned int requested_node_id = 0U;
        unsigned int requested_scratch_slots = 0U;
        int fields = sscanf(line, "ROLE %15s %31s %u %u %c",
                            arg1, arg2, &requested_node_id, &requested_scratch_slots, &extra);
        if (!g_state.session_set) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"session-not-set\"}\n");
            return;
        }
        if (g_state.stack_initialized) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"already-initialized\"}\n");
            return;
        }
        if (fields != 4) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"role-usage\","
                   "\"expected\":\"ROLE <controller|peer> <profile> <local_node_id> <handshake_scratch_slots>\"}\n");
            return;
        }
        if (strcmp(arg1, "controller") == 0) {
            g_state.role = ROLE_CONTROLLER;
        } else if (strcmp(arg1, "peer") == 0) {
            g_state.role = ROLE_PEER;
        } else {
            printf("{\"event\":\"command_rejected\",\"reason\":\"unknown-role\"}\n");
            return;
        }
        const char *prof = arg2;
        if (strcmp(prof, "retry-2") != 0 && strcmp(prof, "multi-peer") != 0) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"unknown-profile\"}\n");
            return;
        }
        if (requested_scratch_slots < 1U || requested_scratch_slots > 2U ||
            (strcmp(prof, "retry-2") == 0 && requested_scratch_slots != 1U)) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"invalid-handshake-scratch-slots\"}\n");
            g_state.role = ROLE_UNSET;
            return;
        }
        if (!profile_role_node_id_valid(prof, g_state.role, requested_node_id)) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"node-id-not-in-profile\","
                   "\"node_id\":%u}\n", requested_node_id);
            g_state.role = ROLE_UNSET;
            return;
        }
        g_state.local_node_id = requested_node_id;
        g_state.handshake_scratch_slots = requested_scratch_slots;
        if (!init_dmp_stack(prof)) {
            printf("{\"event\":\"role_failed\",\"session\":\"%s\",\"role\":\"%s\",\"reason\":\"stack-init-failed\"}\n",
                   session, arg1);
            g_state.role = ROLE_UNSET;
            g_state.local_node_id = 0U;
            return;
        }
        g_state.stack_initialized = true;
        char hash_hex[65];
        format_hex(g_state.active_profile_hash, 32U, hash_hex);
        printf("{\"event\":\"role_set\",\"session\":\"%s\",\"role\":\"%s\",\"profile\":\"%s\","
               "\"profile_hash\":\"%s\",\"node_id\":%" PRIu32 ",\"handshake_scratch_slots\":%" PRIu32 "}\n",
               session, arg1, prof, hash_hex, g_state.local_node_id, g_state.handshake_scratch_slots);
    } else if (strncmp(line, "PEER ", 5U) == 0) {
        memset(arg1, 0, sizeof arg1);
        memset(arg2, 0, sizeof arg2);
        extra = '\0';
        int fields = sscanf(line, "PEER %17s %31s %c", arg1, arg2, &extra);
        if (!g_state.session_set || g_state.role == ROLE_UNSET) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"role-or-session-not-set\"}\n");
            return;
        }
        if (fields < 1 || fields > 2) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"peer-usage\","
                   "\"expected\":\"PEER <mac> [remote_node_id]\"}\n");
            return;
        }
        uint8_t mac[6];
        if (!parse_mac(arg1, mac) || memcmp(mac, g_state.own_mac, 6) == 0) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"invalid-mac\"}\n");
            return;
        }
        if (find_peer_by_mac(mac) >= 0) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"duplicate-peer\"}\n");
            return;
        }
        if (g_state.peer_count >= profile_peer_capacity(g_state.profile_name)) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"peer-capacity-exceeded\"}\n");
            return;
        }

        uint32_t peer_idx = g_state.peer_count;
        uint32_t expected_node_id = g_state.role == ROLE_CONTROLLER
                                        ? profile_peer_node_id(g_state.profile_name, peer_idx)
                                        : profile_controller_node_id(g_state.profile_name);
        if (expected_node_id == 0U) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"peer-node-unavailable\"}\n");
            return;
        }
        if (fields == 2) {
            char *end = NULL;
            unsigned long requested_node_id = strtoul(arg2, &end, 0);
            if (arg2[0] == '\0' || end == arg2 || *end != '\0' ||
                requested_node_id != (unsigned long)expected_node_id) {
                printf("{\"event\":\"command_rejected\",\"reason\":\"peer-node-mismatch\","
                       "\"expected_node_id\":%" PRIu32 "}\n", expected_node_id);
                return;
            }
        }
        qual_peer_entry *peer = &g_state.peers[peer_idx];
        uint64_t peer_setup_started_us = (uint64_t)esp_timer_get_time();
        log_peer_setup_stage("peer_setup_begin", peer_setup_started_us);
        memcpy(peer->mac, mac, 6);
        peer->node_id = expected_node_id;
        peer->in_use = true;
        peer->handshake_done = false;
        peer->handshake_tx_ready = false;
        peer->handshake_poll_failed = false;
        peer->handshake_activation_failed = false;

        /* Register in ESP-NOW driver */
        esp_now_peer_info_t esp_peer;
        bool esp_peer_added = false;
        memset(&esp_peer, 0, sizeof esp_peer);
        memcpy(esp_peer.peer_addr, mac, 6);
        esp_peer.channel = QUAL_CHANNEL;
        esp_peer.ifidx = WIFI_IF_STA;
        esp_peer.encrypt = false;
        if (!esp_now_is_peer_exist(mac)) {
            ESP_ERROR_CHECK(esp_now_add_peer(&esp_peer));
            esp_peer_added = true;
        }
        log_peer_setup_stage("esp_now_peer_ready", peer_setup_started_us);

        /* Register in DMP endpoint */
        dmp_identity_context_config ctx;
        memset(&ctx, 0, sizeof ctx);
        ctx.local.namespace_id = TEST_ONLY_NAMESPACE_ID;
        ctx.peer.namespace_id = TEST_ONLY_NAMESPACE_ID;
        ctx.local.origin_id = g_state.local_node_id;
        ctx.peer.origin_id = peer->node_id;
        ctx.security = 1U;
        dmp_time_ms now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);
        dmp_peer_handle out_handle = {0U, 0U};
        dmp_status ast = DMP_OK;
        if (peer_idx == 0U) {
            /* dmp_endpoint_init installs the configured initial context in
             * slot zero. The add_peer API is only for additional peers and
             * correctly rejects endpoints whose configured capacity is one. */
            if (g_endpoint.peers == NULL || g_endpoint.peer_count == 0U ||
                g_endpoint.peers[0].live == 0U) {
                ast = DMP_INVALID_ARGUMENT;
            } else {
                out_handle = g_endpoint.peers[0].handle;
            }
        } else {
            ast = dmp_endpoint_add_peer(&g_endpoint, &ctx, now, &out_handle);
        }
        log_peer_setup_stage("endpoint_peer_add_returned", peer_setup_started_us);
        if (ast != DMP_OK) {
            rollback_peer_setup(peer, peer_idx, false, esp_peer_added);
            printf("{\"event\":\"command_rejected\",\"reason\":\"endpoint-add-peer-failed\","
                   "\"status\":%d}\n", (int)ast);
            return;
        }
        peer->handle = out_handle;

        /* Setup handshake structures for peer */
        bool handshake_setup_ok = setup_peer_handshake(peer);
        log_peer_setup_stage("handshake_setup_returned", peer_setup_started_us);
        if (!handshake_setup_ok) {
            rollback_peer_setup(peer, peer_idx, peer_idx != 0U, esp_peer_added);
            printf("{\"event\":\"command_rejected\",\"reason\":\"handshake-setup-failed\"}\n");
            return;
        }

        ++g_state.peer_count;
        log_peer_setup_stage("peer_count_incremented", peer_setup_started_us);
        log_peer_setup_stage("peer_added_emit_begin", peer_setup_started_us);
        printf("{\"event\":\"peer_added\",\"session\":\"%s\",\"peer_mac\":\"%s\","
               "\"node_id\":%" PRIu32 ",\"peer_handle\":%u,\"peer_count\":%" PRIu32 "}\n",
               session, arg1, peer->node_id, (unsigned)peer->handle.slot, g_state.peer_count);
        log_peer_setup_stage("peer_added_emit_returned", peer_setup_started_us);
    } else if (strcmp(line, "NVS_CHECK") == 0) {
        execute_nvs_check();
    } else if (strncmp(line, "SAMPLE_ROTATE ", 14U) == 0) {
        unsigned int sample_value = 0U;
        if (sscanf(line, "SAMPLE_ROTATE %u %c", &sample_value, &extra) != 1) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"sample-rotate-usage\","
                   "\"expected\":\"SAMPLE_ROTATE <sample_value>\"}\n");
            return;
        }
        rotate_sample1_epoch((uint32_t)sample_value);
    } else if (strncmp(line, "HS_SYNC ", 8U) == 0) {
        unsigned int h = 0U;
        if (sscanf(line, "HS_SYNC %u %c", &h, &extra) != 1) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"handshake-stream-sync-usage\"}\n");
            return;
        }
        if (h >= g_state.peer_count || !g_state.peers[h].in_use ||
            g_state.peers[h].hs_tx == NULL) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"invalid-peer-handle\"}\n");
            return;
        }
        trigger_handshake_sync(&g_state.peers[h]);
    } else if (strncmp(line, "HANDSHAKE ", 10U) == 0) {
        unsigned int h = 0;
        if (sscanf(line, "HANDSHAKE %u %c", &h, &extra) != 1) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"handshake-usage\"}\n");
            return;
        }
        if (h >= g_state.peer_count || !g_state.peers[h].in_use) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"invalid-peer-handle\"}\n");
            return;
        }
        printf("{\"event\":\"handshake_command_received\",\"session\":\"%s\","
               "\"peer_handle\":%u}\n", session, h);
        trigger_handshake(&g_state.peers[h]);
    } else if (strncmp(line, "TRANSFER ", 9U) == 0) {
        unsigned int h = 0;
        unsigned int b = 0;
        if (sscanf(line, "TRANSFER %u %u %c", &h, &b, &extra) != 2) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"transfer-usage\"}\n");
            return;
        }
        if (h >= g_state.peer_count || !g_state.peers[h].in_use) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"invalid-peer-handle\"}\n");
            return;
        }
        trigger_service2_transfer((uint32_t)h, (size_t)b);
    } else if (strncmp(line, "SAMPLE_READ ", 12U) == 0) {
        unsigned int h = 0;
        if (sscanf(line, "SAMPLE_READ %u %c", &h, &extra) != 1) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"sample-read-usage\"}\n");
            return;
        }
        if (h >= g_state.peer_count || !g_state.peers[h].in_use) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"invalid-peer-handle\"}\n");
            return;
        }
        if (g_state.role != ROLE_PEER || !g_state.peers[h].handshake_done ||
            !g_state.peers[h].handshake_tx_ready) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"sample-read-requires-active-reader\"}\n");
            return;
        }
        dmp_time_ms now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);
        uint8_t req_body[1] = { DMP_SAMPLE1_READ_OPCODE };
        dmp_reliability_handle req_h = {0};
        dmp_status s = dmp_endpoint_submit_req_to(&g_endpoint, g_state.peers[h].handle,
                                                 QUAL_SERVICE_SAMPLE1,
                                                 (dmp_bytes){ req_body, 1U },
                                                 now, &req_h);
        printf("{\"event\":\"sample_read_submitted\",\"session\":\"%s\",\"peer_handle\":%u,"
               "\"status\":%d}\n", session, h, (int)s);
    } else if (strncmp(line, "V2_FRAME ", 9U) == 0) {
        unsigned int h = 0;
        if (sscanf(line, "V2_FRAME %u %c", &h, &extra) != 1) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"v2-frame-usage\"}\n");
            return;
        }
        if (h >= g_state.peer_count || !g_state.peers[h].in_use) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"invalid-peer-handle\"}\n");
            return;
        }
        trigger_v2_frame((uint32_t)h);
    } else if (strncmp(line, "RUN_PAIR", 8U) == 0 && (line[8] == ' ' || line[8] == '\0')) {
        printf("{\"event\":\"command_rejected\",\"reason\":\"runner-owned-scheduling\"}\n");
    } else if (strncmp(line, "RUN_FOUR_SERIAL", 15U) == 0 && (line[15] == ' ' || line[15] == '\0')) {
        printf("{\"event\":\"command_rejected\",\"reason\":\"runner-owned-scheduling\"}\n");
    } else if (strncmp(line, "RUN_FOUR_PARALLEL", 17U) == 0 && (line[17] == ' ' || line[17] == '\0')) {
        printf("{\"event\":\"command_rejected\",\"reason\":\"runner-owned-scheduling\"}\n");
    } else if (strcmp(line, "STATS") == 0) {
        printf("{\"event\":\"stats\",\"session\":\"%s\",\"tx_frames\":%" PRIu32 ","
               "\"rx_frames\":%" PRIu32 ",\"tx_ok\":%" PRIu32 ",\"tx_failed\":%" PRIu32 ","
               "\"assembled_transfers\":%" PRIu32 ",\"max_rx_frame_bytes\":%u,"
               "\"max_tx_frame_bytes\":%u}\n",
               session, g_state.stats_tx_frames, g_state.stats_rx_frames,
               g_state.stats_tx_ok, g_state.stats_tx_failed,
               g_state.stats_assembled_transfers,
               (unsigned)g_state.max_observed_rx_frame_bytes,
               (unsigned)g_state.max_observed_tx_frame_bytes);
    } else if (strcmp(line, "RESOURCES") == 0) {
        if (!g_state.stack_initialized) {
            printf("{\"event\":\"resources\",\"session\":\"%s\","
                   "\"status\":\"unavailable\",\"reason\":\"endpoint-not-initialized\"}\n",
                   session);
            return;
        }
        report_resources();
    } else if (strcmp(line, "ENTROPY_DIAGNOSTIC") == 0) {
        report_entropy_diagnostic();
    } else if (strcmp(line, "CORE_DUMP_TEST") == 0) {
        printf("{\"event\":\"core_dump_test\",\"action\":\"intentional-abort\"}\n");
        (void)fflush(stdout);
        abort();
    } else {
        printf("{\"event\":\"command_rejected\",\"reason\":\"unknown-command\"}\n");
    }
}

void app_main(void)
{
    wifi_init_config_t wifi_config = WIFI_INIT_CONFIG_DEFAULT();
    qual_command_message command;
    qual_wifi_event event;
    dmp_qual_tx_completion_event tx_event;
    dmp_time_ms last_rx_callback_diag_ms = 0U;
    uint32_t last_rx_callback_count = 0U;
    uint32_t last_rx_callback_queue_drops = 0U;
    uint32_t last_tx_callback_duplicates = 0U;

    (void)setvbuf(stdout, NULL, _IONBF, 0);
    memset(&g_state, 0, sizeof g_state);

    g_wifi_events = xQueueCreate(QUAL_EVENT_QUEUE_LENGTH, sizeof(qual_wifi_event));
    g_commands = xQueueCreate(QUAL_COMMAND_QUEUE_LENGTH, sizeof(qual_command_message));
    if (g_wifi_events == NULL || g_commands == NULL) {
        ESP_LOGE(TAG, "Queue allocation failed");
        return;
    }

    /* Initialize NVS for SAMPLE-1 storage adapter */
    esp_err_t ret = nvs_flash_init();
    if (ret != ESP_OK) {
        printf("{\"event\":\"startup_failed\",\"status\":\"fail_closed\","
               "\"reason\":\"nvs-init\",\"error\":%d,\"erase_attempted\":false}\n",
               (int)ret);
        return;
    }

    /* Initialize network interface and WiFi in Station mode */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    if (esp_netif_create_default_wifi_sta() == NULL) {
        ESP_LOGE(TAG, "Default STA creation failed");
        return;
    }

    wifi_config.nvs_enable = false;
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_config));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    do {
        esp_fill_random(&g_boot_id, sizeof(g_boot_id));
    } while (g_boot_id == 0U);
    g_entropy_ready = true;
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_channel(QUAL_CHANNEL, WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, g_state.own_mac));

    /* Initialize ESP-NOW and query driver version - fail closed unless native v2 */
    ESP_ERROR_CHECK(esp_now_init());
    uint32_t version = 0U;
    esp_err_t v_err = esp_now_get_version(&version);
    if (v_err != ESP_OK || version < 2U) {
        printf("{\"event\":\"error\",\"status\":\"fail_closed\",\"reason\":\"espnow-v2-required\","
               "\"espnow_version\":%" PRIu32 "}\n", version);
        return;
    }
    g_state.espnow_version = version;

    ESP_ERROR_CHECK(esp_now_register_send_cb(send_callback));
    ESP_ERROR_CHECK(esp_now_register_recv_cb(receive_callback));

    g_internal_heap_free_at_ready_bytes =
        heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    g_internal_heap_baseline_available = true;

    log_ready();

    if (xTaskCreate(command_reader_task, "qual_cmd", 4096U, NULL, 4U,
                    &g_command_reader_task) != pdPASS) {
        ESP_LOGE(TAG, "command reader task creation failed");
        return;
    }

    for (;;) {
        dmp_time_ms now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);
        bool tx_event_pending;
        uint32_t tx_callback_duplicates;

        portENTER_CRITICAL(&g_callback_diag_mux);
        tx_event_pending = dmp_qual_tx_completion_take(&g_tx_completion, &tx_event);
        tx_callback_duplicates = g_tx_callback_duplicates;
        portEXIT_CRITICAL(&g_callback_diag_mux);

        if (tx_event_pending) {
            handle_tx_done(&tx_event);
        }
        if (tx_callback_duplicates != last_tx_callback_duplicates) {
            char session[QUAL_SESSION_BYTES * 2U + 1U];
            format_session(session);
            printf("{\"event\":\"error\",\"session\":\"%s\","
                   "\"status\":\"fail_closed\","
                   "\"reason\":\"duplicate-espnow-send-callback\","
                   "\"callbacks\":%" PRIu32 "}\n",
                   session, tx_callback_duplicates);
            last_tx_callback_duplicates = tx_callback_duplicates;
        }

        /* Process WiFi event */
        if (xQueueReceive(g_wifi_events, &event, pdMS_TO_TICKS(10)) == pdTRUE) {
            if (event.kind == EVENT_RX_OVERSIZE) {
                printf("{\"event\":\"rx_rejected\",\"reason\":\"oversize-espnow-payload\","
                       "\"bytes\":%u,\"v1_limit\":%u,\"v2_limit\":%u}\n",
                       (unsigned)event.length, QUAL_ESPNOW_V1_PAYLOAD_MTU_BYTES,
                       QUAL_ESPNOW_V2_PAYLOAD_MTU_BYTES);
            } else if (event.kind == EVENT_RX) {
                handle_rx_packet(&event);
            }
        }

        /* Process console command */
        if (xQueueReceive(g_commands, &command, 0U) == pdTRUE) {
            printf("{\"event\":\"console_command_dispatch\",\"line_bytes\":%u}\n",
                   (unsigned)strlen(command.line));
            handle_command(command.line);
        }

        /* Refresh monotonic now after queue wait */
        now = (dmp_time_ms)(esp_timer_get_time() / 1000LL);

        /* Distinguish an RF receive callback from a dropped qualification
         * event without printing from the high-priority Wi-Fi callback. */
        if (now - last_rx_callback_diag_ms >= 1000U) {
            uint32_t callback_count;
            uint32_t queue_drops;
            portENTER_CRITICAL(&g_callback_diag_mux);
            callback_count = g_rx_callback_count;
            queue_drops = g_rx_callback_queue_drops;
            portEXIT_CRITICAL(&g_callback_diag_mux);
            if (callback_count != last_rx_callback_count ||
                queue_drops != last_rx_callback_queue_drops) {
                char session[QUAL_SESSION_BYTES * 2U + 1U];
                format_session(session);
                printf("{\"event\":\"rx_callback_stats\",\"session\":\"%s\","
                       "\"callbacks\":%" PRIu32 ",\"queue_drops\":%" PRIu32 ","
                       "\"handled_frames\":%" PRIu32 "}\n",
                       session, callback_count, queue_drops, g_state.stats_rx_frames);
                last_rx_callback_count = callback_count;
                last_rx_callback_queue_drops = queue_drops;
            }
            last_rx_callback_diag_ms = now;
        }

        /* Service handshake polling and TX expiry for all in-use peers */
        for (size_t i = 0; i < QUAL_MAX_PEERS; ++i) {
            qual_peer_entry *peer = &g_state.peers[i];
            if (peer->in_use && peer->hs != NULL && peer->hs_tx != NULL) {
                if (!peer->handshake_poll_failed) {
                    uint32_t expired_attempt = 0U;
                    dmp_hs_status hs_poll_st = dmp_hs_poll(peer->hs, &expired_attempt);
                    if (hs_poll_st == DMP_HS_EXPIRED) {
                        char session[QUAL_SESSION_BYTES * 2U + 1U];
                        char peer_mac[18];
                        format_session(session);
                        format_mac(peer->mac, peer_mac);
                        printf("{\"event\":\"handshake_failed\",\"session\":\"%s\",\"peer_mac\":\"%s\","
                               "\"peer_handle\":%u,\"attempt_index\":%" PRIu32 ",\"reason\":\"attempt-expired\"}\n",
                               session, peer_mac, (unsigned)peer->handle.slot, expired_attempt);
                    } else if (hs_poll_st != DMP_HS_OK) {
                        char session[QUAL_SESSION_BYTES * 2U + 1U];
                        char peer_mac[18];
                        format_session(session);
                        format_mac(peer->mac, peer_mac);
                        peer->handshake_poll_failed = true;
                        peer->handshake_done = false;
                        dmp_status revoke_st = dmp_endpoint_revoke_peer(&g_endpoint, peer->handle, now);
                        printf("{\"event\":\"error\",\"session\":\"%s\",\"status\":\"fail_closed\","
                               "\"reason\":\"handshake-poll-unexpected\",\"peer_mac\":\"%s\","
                               "\"peer_handle\":%u,\"status_code\":%d,\"revoke_status\":%d}\n",
                               session, peer_mac, (unsigned)peer->handle.slot, (int)hs_poll_st, (int)revoke_st);
                    }
                }
                dmp_hs_tx_expire(peer->hs_tx, now);
            }
        }

        /* Poll endpoint and drive timeouts */
        (void)dmp_endpoint_poll(&g_endpoint, now);

    }
}
