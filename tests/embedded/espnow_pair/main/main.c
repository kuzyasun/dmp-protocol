/* ESP-NOW peer smoke for the real DMP Core structural codec.
 * This test image deliberately has no SEC-1 keys and makes no authentication
 * or endpoint-acceptance claim. */
#include "dmp/core.h"

#include "esp_err.h"
#include "esp_event.h"
#include "esp_idf_version.h"
#include "esp_log.h"
#include "esp_now.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAIR_CHANNEL 1U
#define PAIR_CORE_MTU_BYTES 256U
#define PAIR_STREAM_R_ENCODED_MTU_BYTES 263U
#if CONFIG_IDF_TARGET_ESP32C3
#define PAIR_MAX_PEERS 1U
#else
#define PAIR_MAX_PEERS 3U
#endif
#define PAIR_EVENT_QUEUE_LENGTH 8U
#define PAIR_COMMAND_QUEUE_LENGTH 4U
#define PAIR_COMMAND_BYTES 96U
#define PAIR_MAX_PAYLOAD_BYTES 240U
#define PAIR_SESSION_BYTES 8U
#define PAIR_FRAME_TIMEOUT_US 3000000LL

_Static_assert(ESP_NOW_MAX_DATA_LEN == 250,
               "this smoke is explicitly bounded to ESP-NOW v1 payloads");
_Static_assert(ESP_NOW_MAX_TOTAL_PEER_NUM >= PAIR_MAX_PEERS,
               "ESP-NOW peer table must fit this smoke's bounded peer count");

typedef enum {
    EVENT_RX = 1,
    EVENT_TX_DONE = 2,
    EVENT_RX_OVERSIZE = 3
} event_kind;

typedef struct {
    event_kind kind;
    uint8_t mac[6];
    esp_now_send_status_t send_status;
    size_t length;
    uint8_t bytes[ESP_NOW_MAX_DATA_LEN];
} wifi_event;

typedef struct {
    char line[PAIR_COMMAND_BYTES];
} command_message;

typedef enum {
    TX_NONE = 0,
    TX_PROBE = 1,
    TX_ECHO = 2
} tx_kind;

typedef struct {
    uint8_t own_mac[6];
    uint8_t peer_macs[PAIR_MAX_PEERS][6];
    uint8_t tx_peer_mac[6];
    uint8_t run_peer_mac[6];
    uint8_t session_token[PAIR_SESSION_BYTES];
    uint8_t peer_count;
    uint8_t session_set;
    uint8_t echo_enabled;
    uint8_t run_active;
    uint8_t tx_live;
    uint8_t probe_tx_done;
    uint8_t echo_received;
    uint8_t echo_pending;
    tx_kind tx_type;
    uint32_t tx_sequence;
    uint32_t next_sequence;
    uint32_t run_target;
    uint32_t run_completed;
    uint32_t run_failed;
    uint32_t run_payload_length;
    uint32_t echo_rx_count;
    uint32_t echo_tx_ok;
    uint32_t echo_tx_failed;
    uint32_t max_core_frame_bytes;
    size_t expected_length;
    size_t echo_pending_length;
    uint32_t echo_pending_sequence;
    int64_t run_deadline_us;
    uint8_t expected[PAIR_CORE_MTU_BYTES];
    uint8_t echo_pending_mac[6];
    uint8_t echo_pending_bytes[ESP_NOW_MAX_DATA_LEN];
    uint8_t tx_buffer[ESP_NOW_MAX_DATA_LEN];
} pair_state;

static const char *TAG = "dmp-espnow-pair";
static QueueHandle_t g_wifi_events;
static QueueHandle_t g_commands;
static pair_state g_state;
static const dmp_core_limits g_core_limits = {
    PAIR_CORE_MTU_BYTES, PAIR_MAX_PAYLOAD_BYTES, 1U
};

static void format_mac(const uint8_t mac[6], char out[18])
{
    (void)snprintf(out, 18U, "%02x:%02x:%02x:%02x:%02x:%02x",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int parse_mac(const char *text, uint8_t mac[6])
{
    unsigned int octets[6];
    char trailing;
    if (sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c", &octets[0], &octets[1],
               &octets[2], &octets[3], &octets[4], &octets[5], &trailing) != 6) {
        return 0;
    }
    for (size_t i = 0U; i < 6U; ++i) {
        if (octets[i] > 0xffU) return 0;
        mac[i] = (uint8_t)octets[i];
    }
    return (mac[0] & 1U) == 0U && memcmp(mac, "\0\0\0\0\0\0", 6U) != 0;
}

static int same_mac(const uint8_t left[6], const uint8_t right[6])
{
    return memcmp(left, right, 6U) == 0;
}

static int find_peer(const uint8_t mac[6])
{
    for (uint8_t index = 0U; index < g_state.peer_count; ++index) {
        if (same_mac(mac, g_state.peer_macs[index])) return (int)index;
    }
    return -1;
}

static void format_session(char out[PAIR_SESSION_BYTES * 2U + 1U])
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0U; i < PAIR_SESSION_BYTES; ++i) {
        out[i * 2U] = hex[g_state.session_token[i] >> 4U];
        out[i * 2U + 1U] = hex[g_state.session_token[i] & 0x0fU];
    }
    out[PAIR_SESSION_BYTES * 2U] = '\0';
}

static int parse_session(const char *text, uint8_t out[PAIR_SESSION_BYTES])
{
    size_t length;
    if (text == NULL || out == NULL) return 0;
    length = strlen(text);
    if (length != PAIR_SESSION_BYTES * 2U) return 0;
    for (size_t i = 0U; i < PAIR_SESSION_BYTES; ++i) {
        char high = text[i * 2U];
        char low = text[i * 2U + 1U];
        unsigned int hi, lo;
        if (high >= '0' && high <= '9') hi = (unsigned int)(high - '0');
        else if (high >= 'a' && high <= 'f') hi = (unsigned int)(high - 'a' + 10);
        else if (high >= 'A' && high <= 'F') hi = (unsigned int)(high - 'A' + 10);
        else return 0;
        if (low >= '0' && low <= '9') lo = (unsigned int)(low - '0');
        else if (low >= 'a' && low <= 'f') lo = (unsigned int)(low - 'a' + 10);
        else if (low >= 'A' && low <= 'F') lo = (unsigned int)(low - 'A' + 10);
        else return 0;
        out[i] = (uint8_t)((hi << 4U) | lo);
    }
    return 1;
}

static void log_ready(void)
{
    char mac[18];
    format_mac(g_state.own_mac, mac);
    printf("{\"event\":\"ready\",\"target\":\"%s\",\"idf\":\"%s\","
           "\"firmware\":\"dmp-espnow-pair/0.1\",\"mac\":\"%s\","
           "\"channel\":%u,\"decoded_core_mtu_bytes\":%u,"
           "\"stream_r_encoded_mtu_bytes\":%u,"
           "\"espnow_v1_payload_mtu_bytes\":%u,\"peer_capacity\":%u,"
           "\"test_mode\":\"unauthenticated-core-echo\"}\n",
           CONFIG_IDF_TARGET, esp_get_idf_version(), mac, PAIR_CHANNEL,
           PAIR_CORE_MTU_BYTES, PAIR_STREAM_R_ENCODED_MTU_BYTES,
           ESP_NOW_MAX_DATA_LEN, PAIR_MAX_PEERS);
}

static int build_telem(uint32_t sequence, size_t payload_length,
                       uint8_t output[PAIR_CORE_MTU_BYTES], size_t *written)
{
    uint8_t payload[PAIR_MAX_PAYLOAD_BYTES];
    dmp_frame_spec frame;
    if (!g_state.session_set || payload_length < PAIR_SESSION_BYTES ||
        payload_length > sizeof payload || written == NULL) {
        return 0;
    }
    memcpy(payload, g_state.session_token, PAIR_SESSION_BYTES);
    for (size_t i = PAIR_SESSION_BYTES; i < payload_length; ++i) {
        payload[i] = (uint8_t)((sequence * 31U + (uint32_t)i * 17U) & 0xffU);
    }
    memset(&frame, 0, sizeof frame);
    frame.fields.type = DMP_TYPE_TELEM;
    frame.fields.options = DMP_OPT_SEQ;
    frame.fields.seq = sequence;
    frame.payload.data = payload;
    frame.payload.size = payload_length;
    return dmp_core_encode(&frame, &g_core_limits,
                           (dmp_buffer){output, PAIR_CORE_MTU_BYTES}, written) == DMP_OK &&
           *written <= ESP_NOW_MAX_DATA_LEN;
}

static int validate_core(const uint8_t *bytes, size_t length, uint32_t *sequence)
{
    dmp_frame_view view;
    dmp_parse_result parsed = dmp_core_parse((dmp_bytes){bytes, length},
                                              &g_core_limits, &view);
    if (parsed.status != DMP_OK || view.fields.type != DMP_TYPE_TELEM ||
        (view.fields.options & DMP_OPT_SEQ) == 0U || sequence == NULL) {
        return 0;
    }
    if (!g_state.session_set || view.payload.size < PAIR_SESSION_BYTES ||
        memcmp(view.payload.data, g_state.session_token, PAIR_SESSION_BYTES) != 0) {
        return 0;
    }
    *sequence = view.fields.seq;
    return 1;
}

static void send_callback(const esp_now_send_info_t *info,
                          esp_now_send_status_t status)
{
    wifi_event event;
    if (g_wifi_events == NULL || info == NULL || info->des_addr == NULL) return;
    memset(&event, 0, sizeof event);
    event.kind = EVENT_TX_DONE;
    memcpy(event.mac, info->des_addr, sizeof event.mac);
    event.send_status = status;
    (void)xQueueSend(g_wifi_events, &event, 0U);
}

static void receive_callback(const esp_now_recv_info_t *info,
                             const uint8_t *data, int data_length)
{
    wifi_event event;
    if (g_wifi_events == NULL || info == NULL || info->src_addr == NULL ||
        data_length < 0 || (data_length > 0 && data == NULL)) {
        return;
    }
    memset(&event, 0, sizeof event);
    memcpy(event.mac, info->src_addr, sizeof event.mac);
    event.length = (size_t)data_length;
    if (event.length > sizeof event.bytes) {
        event.kind = EVENT_RX_OVERSIZE;
    } else {
        event.kind = EVENT_RX;
        if (event.length != 0U) memcpy(event.bytes, data, event.length);
    }
    (void)xQueueSend(g_wifi_events, &event, 0U);
}

static void command_reader(void *unused)
{
    char pending[PAIR_COMMAND_BYTES];
    size_t pending_length = 0U;
    int discarding = 0;
    (void)unused;
    memset(pending, 0, sizeof pending);
    for (;;) {
        command_message command;
        char chunk[PAIR_COMMAND_BYTES];
        if (fgets(chunk, sizeof chunk, stdin) == NULL) {
            clearerr(stdin);
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        for (size_t i = 0U; chunk[i] != '\0'; ++i) {
            const char byte = chunk[i];
            if (discarding) {
                if (byte == '\n') {
                    discarding = 0;
                    pending_length = 0U;
                    (void)snprintf(command.line, sizeof command.line,
                                   "INVALID overlong-command");
                    if (xQueueSend(g_commands, &command, portMAX_DELAY) != pdTRUE) {
                        ESP_LOGE(TAG, "command queue unavailable");
                    }
                }
                continue;
            }
            if (byte == '\n') {
                if (pending_length > 0U && pending[pending_length - 1U] == '\r') {
                    --pending_length;
                }
                pending[pending_length] = '\0';
                memcpy(command.line, pending, pending_length + 1U);
                pending_length = 0U;
                if (xQueueSend(g_commands, &command, portMAX_DELAY) != pdTRUE) {
                    ESP_LOGE(TAG, "command queue unavailable");
                }
                continue;
            }
            if (pending_length + 1U >= sizeof pending) {
                pending_length = 0U;
                discarding = 1;
                continue;
            }
            pending[pending_length++] = byte;
        }
    }
}

static void log_command_error(const char *reason)
{
    printf("{\"event\":\"command_rejected\",\"reason\":\"%s\"}\n", reason);
}

static int submit_datagram(const uint8_t *mac, const uint8_t *bytes,
                           size_t length, tx_kind kind, uint32_t sequence)
{
    char peer[18];
    char session[PAIR_SESSION_BYTES * 2U + 1U];
    esp_err_t result;
    if (g_state.tx_live || bytes == NULL || length == 0U ||
        length > sizeof g_state.tx_buffer || find_peer(mac) < 0) {
        return 0;
    }
    memcpy(g_state.tx_buffer, bytes, length);
    memcpy(g_state.tx_peer_mac, mac, sizeof g_state.tx_peer_mac);
    g_state.tx_type = kind;
    g_state.tx_sequence = sequence;
    g_state.tx_live = 1U;
    format_mac(mac, peer);
    format_session(session);
    result = esp_now_send(mac, g_state.tx_buffer, length);
    if (result != ESP_OK) {
        g_state.tx_live = 0U;
        g_state.tx_type = TX_NONE;
        printf("{\"event\":\"tx_submit_failed\",\"session\":\"%s\",\"seq\":%" PRIu32
               ",\"peer_mac\":\"%s\",\"error\":%d}\n",
               session, sequence, peer, (int)result);
        return 0;
    }
    if (kind == TX_PROBE) {
        printf("{\"event\":\"tx_submit\",\"session\":\"%s\",\"seq\":%" PRIu32
               ",\"peer_mac\":\"%s\",\"core_frame_bytes\":%u,"
               "\"espnow_payload_bytes\":%u}\n",
               session, sequence, peer, (unsigned)length, (unsigned)length);
    }
    return 1;
}

static void finish_run_if_ready(void)
{
    char peer[18];
    char session[PAIR_SESSION_BYTES * 2U + 1U];
    if (!g_state.run_active || !g_state.probe_tx_done || !g_state.echo_received) return;
    ++g_state.run_completed;
    format_mac(g_state.run_peer_mac, peer);
    format_session(session);
    printf("{\"event\":\"round_trip\",\"session\":\"%s\",\"seq\":%" PRIu32
           ",\"peer_mac\":\"%s\",\"tx_done\":true,"
           "\"echo_match\":true,\"core_frame_bytes\":%u}\n",
           session, g_state.tx_sequence, peer, (unsigned)g_state.expected_length);
    g_state.probe_tx_done = 0U;
    g_state.echo_received = 0U;
    if (g_state.run_completed == g_state.run_target) {
        g_state.run_active = 0U;
        printf("{\"event\":\"run_done\",\"session\":\"%s\",\"pass\":true,"
               "\"completed\":%" PRIu32 ",\"payload_bytes\":%u,"
               "\"peer_count\":%u,\"max_core_frame_bytes\":%" PRIu32 "}\n",
               session, g_state.run_completed, (unsigned)g_state.run_payload_length,
               g_state.peer_count, g_state.max_core_frame_bytes);
        return;
    }
}

static int start_probe(uint32_t sequence, size_t payload_length)
{
    size_t length = 0U;
    char peer[18];
    char session[PAIR_SESSION_BYTES * 2U + 1U];
    if (!build_telem(sequence, payload_length, g_state.expected, &length) ||
        length > sizeof g_state.expected || length > ESP_NOW_MAX_DATA_LEN) {
        log_command_error("core-frame-exceeds-packet-limit");
        return 0;
    }
    g_state.expected_length = length;
    if (length > g_state.max_core_frame_bytes) {
        g_state.max_core_frame_bytes = (uint32_t)length;
    }
    g_state.probe_tx_done = 0U;
    g_state.echo_received = 0U;
    memcpy(g_state.run_peer_mac,
           g_state.peer_macs[g_state.run_completed % g_state.peer_count],
           sizeof g_state.run_peer_mac);
    g_state.run_deadline_us = esp_timer_get_time() + PAIR_FRAME_TIMEOUT_US;
    format_mac(g_state.run_peer_mac, peer);
    format_session(session);
    if (!submit_datagram(g_state.run_peer_mac, g_state.expected, length,
                         TX_PROBE, sequence)) {
        ++g_state.run_failed;
        g_state.run_active = 0U;
        printf("{\"event\":\"run_done\",\"session\":\"%s\",\"pass\":false,"
               "\"reason\":\"send-submit-failed\",\"completed\":%" PRIu32
               ",\"peer_mac\":\"%s\"}\n",
               session, g_state.run_completed, peer);
        return 0;
    }
    return 1;
}

static void handle_command(const char *line)
{
    char arg[32];
    char mac_text[24];
    uint8_t mac[6];
    uint8_t session_token[PAIR_SESSION_BYTES];
    char session[PAIR_SESSION_BYTES * 2U + 1U];
    unsigned int count, payload_length;
    char extra;

    if (strcmp(line, "INFO") == 0) {
        log_ready();
    } else if (sscanf(line, "SESSION %31s %c", arg, &extra) == 1) {
        esp_err_t result = ESP_OK;
        if (g_state.tx_live || g_state.run_active ||
            !parse_session(arg, session_token)) {
            log_command_error("invalid-session-or-busy");
            return;
        }
        while (g_state.peer_count > 0U) {
            const uint8_t index = (uint8_t)(g_state.peer_count - 1U);
            result = esp_now_del_peer(g_state.peer_macs[index]);
            if (result != ESP_OK) {
                printf("{\"event\":\"command_rejected\",\"reason\":\"session-peer-remove-failed\",\"error\":%d}\n",
                       (int)result);
                return;
            }
            --g_state.peer_count;
        }
        memcpy(g_state.session_token, session_token, sizeof session_token);
        g_state.session_set = 1U;
        g_state.echo_enabled = 0U;
        g_state.echo_pending = 0U;
        g_state.echo_rx_count = 0U;
        g_state.echo_tx_ok = 0U;
        g_state.echo_tx_failed = 0U;
        g_state.run_completed = 0U;
        g_state.run_failed = 0U;
        format_session(session);
        format_mac(g_state.own_mac, mac_text);
        printf("{\"event\":\"session_set\",\"session\":\"%s\",\"target\":\"%s\",\"mac\":\"%s\"}\n",
               session, CONFIG_IDF_TARGET, mac_text);
    } else if (sscanf(line, "PEER %23s %c", mac_text, &extra) == 1) {
        esp_now_peer_info_t peer;
        esp_err_t result;
        int peer_index;
        if (!g_state.session_set || g_state.tx_live || g_state.run_active ||
            !parse_mac(mac_text, mac) ||
            same_mac(mac, g_state.own_mac)) {
            log_command_error("invalid-session-peer-or-busy");
            return;
        }
        peer_index = find_peer(mac);
        if (peer_index < 0 && g_state.peer_count >= PAIR_MAX_PEERS) {
            log_command_error("peer-capacity-exceeded");
            return;
        }
        memset(&peer, 0, sizeof peer);
        memcpy(peer.peer_addr, mac, sizeof peer.peer_addr);
        peer.channel = PAIR_CHANNEL;
        peer.ifidx = WIFI_IF_STA;
        peer.encrypt = false;
        if (esp_now_is_peer_exist(mac)) {
            result = esp_now_mod_peer(&peer);
        } else {
            result = esp_now_add_peer(&peer);
        }
        if (result != ESP_OK) {
            printf("{\"event\":\"command_rejected\",\"reason\":\"peer-add-failed\","
                   "\"error\":%d}\n", (int)result);
            return;
        }
        if (peer_index < 0) {
            memcpy(g_state.peer_macs[g_state.peer_count], mac, sizeof mac);
            ++g_state.peer_count;
        }
        format_mac(mac, mac_text);
        format_session(session);
        printf("{\"event\":\"peer_added\",\"session\":\"%s\",\"peer_mac\":\"%s\","
               "\"channel\":%u,\"encrypted\":false,\"peer_count\":%u}\n",
               session, mac_text, PAIR_CHANNEL, g_state.peer_count);
    } else if (sscanf(line, "ECHO %31s %c", arg, &extra) == 1 &&
               (strcmp(arg, "ON") == 0 || strcmp(arg, "OFF") == 0)) {
        if (!g_state.session_set || g_state.peer_count == 0U ||
            g_state.tx_live || g_state.run_active) {
            log_command_error("busy");
            return;
        }
        g_state.echo_enabled = (uint8_t)(strcmp(arg, "ON") == 0);
        g_state.echo_rx_count = 0U;
        g_state.echo_tx_ok = 0U;
        g_state.echo_tx_failed = 0U;
        format_session(session);
        printf("{\"event\":\"echo_mode\",\"session\":\"%s\",\"enabled\":%s}\n",
               session, g_state.echo_enabled ? "true" : "false");
    } else if (sscanf(line, "RUN %u %u %c", &count, &payload_length, &extra) == 2) {
        if (!g_state.session_set || g_state.peer_count == 0U || g_state.echo_enabled || g_state.tx_live ||
            g_state.run_active || count == 0U || count > 1000U ||
            payload_length < PAIR_SESSION_BYTES || payload_length > PAIR_MAX_PAYLOAD_BYTES ||
            (count % g_state.peer_count) != 0U) {
            log_command_error("invalid-run-or-busy");
            return;
        }
        g_state.run_target = count;
        g_state.run_completed = 0U;
        g_state.run_failed = 0U;
        g_state.max_core_frame_bytes = 0U;
        g_state.next_sequence = 1U;
        g_state.run_active = 1U;
        g_state.run_payload_length = payload_length;
        format_session(session);
        printf("{\"event\":\"run_started\",\"session\":\"%s\",\"count\":%u,"
               "\"payload_bytes\":%u,\"peer_count\":%u}\n",
               session, count, payload_length, g_state.peer_count);
        (void)start_probe(g_state.next_sequence, payload_length);
    } else if (strcmp(line, "STATS") == 0) {
        format_session(session);
        printf("{\"event\":\"stats\",\"session\":\"%s\",\"echo_rx\":%" PRIu32
               ",\"echo_tx_ok\":%" PRIu32 ",\"echo_tx_failed\":%" PRIu32
               ",\"run_completed\":%" PRIu32 ",\"run_failed\":%" PRIu32 "}\n",
               session, g_state.echo_rx_count, g_state.echo_tx_ok, g_state.echo_tx_failed,
               g_state.run_completed, g_state.run_failed);
    } else if (strcmp(line, "CORE_DUMP_TEST") == 0) {
        printf("{\"event\":\"core_dump_test\",\"action\":\"intentional-abort\"}\n");
        (void)fflush(stdout);
        abort();
    } else {
        log_command_error("unknown-command");
    }
}

static void handle_tx_done(const wifi_event *event)
{
    char peer[18];
    char session[PAIR_SESSION_BYTES * 2U + 1U];
    tx_kind kind;
    uint32_t sequence;
    if (!g_state.tx_live || !same_mac(event->mac, g_state.tx_peer_mac)) {
        format_mac(event->mac, peer);
        printf("{\"event\":\"stale_tx_callback\",\"peer_mac\":\"%s\"}\n", peer);
        return;
    }
    kind = g_state.tx_type;
    sequence = g_state.tx_sequence;
    g_state.tx_live = 0U;
    g_state.tx_type = TX_NONE;
    format_mac(event->mac, peer);
    format_session(session);
    if (kind == TX_PROBE) {
        const int ok = event->send_status == ESP_NOW_SEND_SUCCESS;
        printf("{\"event\":\"tx_done\",\"session\":\"%s\",\"seq\":%" PRIu32
               ",\"peer_mac\":\"%s\",\"status\":\"%s\"}\n",
               session, sequence, peer, ok ? "success" : "failed");
        if (!ok) {
            ++g_state.run_failed;
            g_state.run_active = 0U;
            printf("{\"event\":\"run_done\",\"session\":\"%s\",\"pass\":false,"
                   "\"reason\":\"mac-send-failed\",\"completed\":%" PRIu32 "}\n",
                   session, g_state.run_completed);
            return;
        }
        g_state.probe_tx_done = 1U;
    } else if (kind == TX_ECHO) {
        const int ok = event->send_status == ESP_NOW_SEND_SUCCESS;
        if (ok) ++g_state.echo_tx_ok;
        else ++g_state.echo_tx_failed;
        printf("{\"event\":\"echo_tx_done\",\"session\":\"%s\",\"seq\":%" PRIu32
               ",\"peer_mac\":\"%s\",\"status\":\"%s\"}\n",
               session, sequence, peer, ok ? "success" : "failed");
        if (g_state.echo_pending) {
            const int submitted = submit_datagram(g_state.echo_pending_mac,
                                                  g_state.echo_pending_bytes,
                                                  g_state.echo_pending_length,
                                                  TX_ECHO,
                                                  g_state.echo_pending_sequence);
            g_state.echo_pending = 0U;
            if (!submitted) {
                printf("{\"event\":\"echo_submit_failed\",\"session\":\"%s\",\"seq\":%" PRIu32 "}\n",
                       session, g_state.echo_pending_sequence);
            }
        }
    }
}

static void handle_rx(const wifi_event *event)
{
    char source[18];
    char session[PAIR_SESSION_BYTES * 2U + 1U];
    uint32_t sequence = 0U;
    if (find_peer(event->mac) < 0) {
        format_mac(event->mac, source);
        printf("{\"event\":\"rx_rejected\",\"reason\":\"unexpected-mac\","
               "\"src_mac\":\"%s\"}\n", source);
        return;
    }
    if (!g_state.echo_enabled &&
        (!g_state.run_active || !same_mac(event->mac, g_state.run_peer_mac))) {
        format_mac(event->mac, source);
        printf("{\"event\":\"rx_rejected\",\"reason\":\"unexpected-active-peer\","
               "\"src_mac\":\"%s\"}\n", source);
        return;
    }
    if (!validate_core(event->bytes, event->length, &sequence)) {
        printf("{\"event\":\"rx_rejected\",\"reason\":\"invalid-core-telemetry\","
               "\"core_frame_bytes\":%u}\n", (unsigned)event->length);
        return;
    }
    format_mac(event->mac, source);
    format_session(session);
    printf("{\"event\":\"rx_valid\",\"session\":\"%s\",\"seq\":%" PRIu32
           ",\"src_mac\":\"%s\",\"core_frame_bytes\":%u}\n",
           session, sequence, source, (unsigned)event->length);
    if (g_state.echo_enabled) {
        ++g_state.echo_rx_count;
        if (g_state.tx_live) {
            if (g_state.echo_pending) {
                printf("{\"event\":\"echo_submit_failed\",\"session\":\"%s\",\"seq\":%" PRIu32
                       ",\"reason\":\"pending-slot-busy\"}\n", session, sequence);
                return;
            }
            memcpy(g_state.echo_pending_mac, event->mac, sizeof g_state.echo_pending_mac);
            memcpy(g_state.echo_pending_bytes, event->bytes, event->length);
            g_state.echo_pending_length = event->length;
            g_state.echo_pending_sequence = sequence;
            g_state.echo_pending = 1U;
        } else if (!submit_datagram(event->mac, event->bytes, event->length,
                                    TX_ECHO, sequence)) {
            printf("{\"event\":\"echo_submit_failed\",\"session\":\"%s\",\"seq\":%" PRIu32 "}\n",
                   session, sequence);
        }
        return;
    }
    if (!g_state.run_active || sequence != g_state.next_sequence ||
        event->length != g_state.expected_length ||
        memcmp(event->bytes, g_state.expected, event->length) != 0) {
        ++g_state.run_failed;
        printf("{\"event\":\"echo_mismatch\",\"seq\":%" PRIu32
               ",\"expected_seq\":%" PRIu32 ",\"core_frame_bytes\":%u}\n",
               sequence, g_state.next_sequence, (unsigned)event->length);
        if (g_state.run_active) {
            g_state.run_active = 0U;
            printf("{\"event\":\"run_done\",\"session\":\"%s\",\"pass\":false,"
                   "\"reason\":\"echo-mismatch\",\"completed\":%" PRIu32 "}\n",
                   session, g_state.run_completed);
        }
        return;
    }
    g_state.echo_received = 1U;
}

static void process_wifi_event(const wifi_event *event)
{
    if (event->kind == EVENT_TX_DONE) {
        handle_tx_done(event);
    } else if (event->kind == EVENT_RX_OVERSIZE) {
        printf("{\"event\":\"rx_rejected\",\"reason\":\"oversize-espnow-payload\","
               "\"espnow_payload_bytes\":%u,\"limit_bytes\":%u}\n",
               (unsigned)event->length, ESP_NOW_MAX_DATA_LEN);
    } else if (event->kind == EVENT_RX) {
        handle_rx(event);
    }
}

static void check_run_timeout(void)
{
    if (g_state.run_active && esp_timer_get_time() >= g_state.run_deadline_us) {
        g_state.run_active = 0U;
        ++g_state.run_failed;
        char session[PAIR_SESSION_BYTES * 2U + 1U];
        format_session(session);
        printf("{\"event\":\"run_done\",\"session\":\"%s\",\"pass\":false,"
               "\"reason\":\"round-trip-timeout\",\"completed\":%" PRIu32 "}\n",
               session, g_state.run_completed);
    }
}

static void advance_run(void)
{
    if (!g_state.run_active || g_state.tx_live || !g_state.probe_tx_done ||
        !g_state.echo_received) {
        return;
    }
    finish_run_if_ready();
    if (g_state.run_active) {
        ++g_state.next_sequence;
        (void)start_probe(g_state.next_sequence, (size_t)g_state.run_payload_length);
    }
}

void app_main(void)
{
    wifi_init_config_t wifi_config = WIFI_INIT_CONFIG_DEFAULT();
    command_message command;
    wifi_event event;

    (void)setvbuf(stdout, NULL, _IONBF, 0);
    memset(&g_state, 0, sizeof g_state);
    g_wifi_events = xQueueCreate(PAIR_EVENT_QUEUE_LENGTH, sizeof(wifi_event));
    g_commands = xQueueCreate(PAIR_COMMAND_QUEUE_LENGTH, sizeof(command_message));
    if (g_wifi_events == NULL || g_commands == NULL) {
        ESP_LOGE(TAG, "bounded queue allocation failed");
        return;
    }
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    if (esp_netif_create_default_wifi_sta() == NULL) {
        ESP_LOGE(TAG, "default STA netif creation failed");
        return;
    }
    wifi_config.nvs_enable = false;
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_config));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_channel(PAIR_CHANNEL, WIFI_SECOND_CHAN_NONE));
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, g_state.own_mac));
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_send_cb(send_callback));
    ESP_ERROR_CHECK(esp_now_register_recv_cb(receive_callback));

    log_ready();
    if (xTaskCreate(command_reader, "pair_commands", 3072U, NULL, 4U, NULL) != pdPASS) {
        ESP_LOGE(TAG, "command reader task creation failed");
        return;
    }
    for (;;) {
        if (xQueueReceive(g_wifi_events, &event, pdMS_TO_TICKS(10)) == pdTRUE) {
            /* Drain TX callbacks first so the send fence is released even at timeout. */
            if (event.kind == EVENT_TX_DONE) {
                process_wifi_event(&event);
                check_run_timeout();
            } else {
                /* A late RX must not complete a round trip after its deadline. */
                check_run_timeout();
                process_wifi_event(&event);
            }
            advance_run();
        }
        if (xQueueReceive(g_commands, &command, 0U) == pdTRUE) {
            handle_command(command.line);
        }
        check_run_timeout();
    }
}
