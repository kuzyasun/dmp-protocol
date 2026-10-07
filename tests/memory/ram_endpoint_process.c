/* Process-isolated host lifecycle probe for one measured libdmp endpoint. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "dmp/endpoint.h"
#include "dmp/core.h"
#include "handshake.h"
#include "noise_fixture_probe.h"
#include "provider_port.h"
#include "sha256.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <time.h>
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET socket_t;
#define BAD_SOCKET INVALID_SOCKET
#define CLOSE_SOCKET closesocket
#else
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
typedef int socket_t;
#define BAD_SOCKET (-1)
#define CLOSE_SOCKET close
#endif

enum { FRAME_CAP = 1200, CID_INIT = 7, CID_RESP = 9, IPC_LIMIT = 4096 };
enum { REC_HANDSHAKE = 'H', REC_DATA = 'X', REC_TICK = 'T', REC_DONE = 'D',
       REC_RESTART = 'R', REC_QUIT = 'Q', REC_ERROR = 'E', REC_STALE_DATA = 'S',
       REC_STALE_RESULT = 'V' };

typedef struct allocation_stats {
    size_t live, peak, largest;
} allocation_stats;
typedef struct runtime_profile {
    char id[64];
    size_t namespace_id, node_ids[2], default_service, service_ids[2];
    size_t origin_route, origin_ttl, freshness_required_mask;
    size_t freshness_lease_ms, freshness_grant_delivery_age_ms;
    size_t freshness_tokens_per_association, freshness_tokens_per_principal;
    size_t freshness_grant_requests_per_pair, freshness_token_record_ms;
    size_t freshness_grant_result_ms;
    size_t message_bytes, request_bytes, result_bytes, chunk_bytes, fragments;
    size_t peers, operations_per_service, assemblies_per_peer, tombstones_per_peer;
    size_t sender_slots, result_slots, history_slots, correlation_slots, adapter_slots;
    size_t application_queue_slots, control_slots;
    size_t encoded_mtu, forward_mtu, return_mtu;
    size_t queue_ms, response_timeout_ms, send_horizon_ms, max_bursts;
    size_t receipt_delay_ms, receipt_limit, dedup_ms, rejection_ms, result_cache_ms;
    size_t result_deadline_ms, correlation_ms, tombstone_ms, late_result_ms;
    size_t collect_ms, assembly_ms, burst_span_ms, forward_delay_ms, return_delay_ms;
    size_t feedback_guard_ms, feedback_delay_ms, max_probes, max_status, record_margin_ms;
    size_t hs_mode, hs_cipher, hs_max_pending, hs_max_scratch, hs_episode_attempts, hs_episode_ms;
    size_t hs_episode_traffic, hs_restart_backoff_ms, hs_attempt_ms, hs_cached_responses;
    size_t hs_ingress_packets, hs_ingress_window_ms, hs_later_episodes, hs_provisional_bytes;
    size_t hs_replay_bits, hs_failed_aead, hs_association_ms, hs_global_crypto_ms;
    size_t hs_confirmation_timeout_ms, hs_confirmation_attempts;
    int selective_recovery;
} runtime_profile;
typedef struct peer_status {
    uint32_t requests, results, data_notices, assemblies;
    uint64_t assembled_bytes, association_epoch, prior_epoch;
    uint64_t request_payload_bytes;
    uint32_t request_payload_matches;
    uint32_t request_service_id;
    uint32_t stale_status, stale_requests_before, stale_requests_after;
    uint32_t stale_data_before, stale_data_after;
    uint32_t stale_assemblies_before, stale_assemblies_after;
    uint8_t responder_ephemeral_changed;
} peer_status;
typedef struct side side;
typedef struct endpoint_bundle {
    dmp_endpoint endpoint;
    dmp_admitted_profile admitted;
    dmp_transport transport;
    dmp_identity_slot *identities;
    dmp_reliability_sender_slot *senders;
    uint8_t *sender_payload;
    dmp_reliability_result_slot *results;
    uint8_t *result_payload;
    dmp_reliability_history_slot *history;
    dmp_reliability_correlation_slot *correlations;
    uint8_t *history_metadata;
    uint8_t *correlation_metadata;
    dmp_reliability_adapter_slot *adapters;
    uint8_t *frames;
    uint8_t *receive_payload;
    dmp_reassembly_slot *assemblies;
    dmp_reassembly_tombstone *tombstones;
    dmp_endpoint_freshness_slot *freshness_slots;
    uint8_t *assembly_payload;
    uint8_t *assembly_metadata;
    uint8_t *fragment_message;
    uint8_t *fragment_frame;
    uint8_t *telemetry_payload;
    uint8_t *telemetry_next;
    uint8_t *telemetry_frame;
    uint8_t *stream_tx;
    uint8_t *stream_rx;
    size_t bundle_requested, payload_requested;
    size_t message_bytes;
} endpoint_bundle;
typedef struct entropy_script {
    const uint8_t *parts[2];
    size_t sizes[2], count, index;
    uint8_t owned[3][64];
} entropy_script;
typedef struct hs_context { uint64_t now; int runtime_entropy_enabled; entropy_script entropy; } hs_context;
typedef struct app_state {
    int have_request, requests, results, data_notices;
    int assemblies;
    size_t assembled_bytes;
    size_t request_payload_bytes, result_payload_bytes;
    uint32_t request_service_id, result_service_id, result_wire_status;
    int request_payload_matches, result_payload_matches;
    uint8_t freshness_token[16];
    size_t freshness_grant_payload_bytes;
    int freshness_grants, freshness_grant_valid;
    dmp_reliability_handle request;
} app_state;
typedef struct phase_sample {
    const char *name;
    const char *status;
    size_t caller_owned_requested;
    size_t endpoint_bundle_object_requested;
    size_t caller_payload_buffers_requested;
    size_t provider_object_requested, handshake_object_requested;
    size_t provider_current, provider_peak, provider_largest;
    size_t tx_submissions, injected_losses, request_notices, result_notices;
    size_t local_request_submissions, requested_payload_high_water;
    size_t payload_fragment_bytes, payload_fragment_frames, assembled_message_count, assembled_message_bytes;
    size_t peer_request_notices;
    size_t reliable_request_payload_bytes, reliable_request_fragment_count, reliable_request_frame_count;
    size_t reliable_result_payload_bytes;
    size_t peer_request_payload_bytes;
    size_t origin_route_frames, origin_route_frames_valid;
    size_t origin_route_rx_frames, origin_route_rx_frames_valid;
    size_t freshness_grant_request_frames, freshness_grant_result_payload_bytes;
    int freshness_grant_verified, freshness_token_bound_to_request;
    uint32_t dropped_request_seq, retry_request_seq;
    uint32_t dropped_request_type, retry_request_type;
    uint32_t dropped_request_fragment, retry_request_fragment;
    uint64_t dropped_request_pn, retry_request_pn;
    uint32_t reliable_result_wire_status;
    int peer_request_payload_matches, reliable_result_payload_matches;
    int retry_frame_distinct, reliable_request_retry_observed;
} phase_sample;
typedef struct reconnect_evidence {
    uint64_t prior_epoch, current_epoch, prior_peer_epoch, current_peer_epoch;
    uint32_t stale_status, requests_before, requests_after;
    uint32_t data_before, data_after;
    uint32_t assemblies_before, assemblies_after;
    uint8_t attempt_id_changed, initiator_ephemeral_changed, responder_ephemeral_changed;
    uint8_t old_data_frame_seen_by_original_peer;
} reconnect_evidence;
typedef struct logical_frame_key {
    uint8_t type;
    uint32_t seq, fragment_index;
    uint64_t pn;
    uint8_t route_present;
    dmp_route_fields route;
} logical_frame_key;
struct side {
    socket_t socket;
    endpoint_bundle *bundle;
    dmp_provider *provider;
    dmp_hs *handshake;
    uint32_t attempt;
    uint64_t now;
    uint8_t initiator;
    uint8_t handshake_stage;
    uint8_t drop_first;
    uint8_t dropped;
    uint8_t retry_distinct;
    uint8_t retry_observed;
    uint8_t dropped_request_key_valid;
    uint8_t dropped_request_type;
    uint8_t retry_request_type;
    uint32_t dropped_request_seq, dropped_request_fragment;
    uint64_t dropped_request_pn, retry_request_pn;
    uint8_t responder_ephemeral_changed;
    uint8_t capture_protected_data, protected_data_captured;
    uint32_t generation;
    size_t submissions;
    size_t origin_route_frames, origin_route_frames_valid;
    size_t origin_route_rx_frames, origin_route_rx_frames_valid;
    size_t freshness_grant_request_frames;
    uint8_t capture_freshness_request_frames;
    int freshness_token_bound_to_request;
    uint64_t retry_after;
    uint64_t association_epoch, prior_epoch;
    size_t local_requests;
    peer_status peer;
    size_t first_drop_size;
    uint8_t first_drop[FRAME_CAP];
    size_t protected_data_frame_size;
    uint8_t protected_data_frame[FRAME_CAP];
    app_state app;
    allocation_stats allocations;
    hs_context hsctx;
};

static uint32_t rng_state = 0x19c0ffeeU;
static runtime_profile active_profile;
static FILE *report_stream;
static const noise_fixture_probe_fixture_t *fixture_find(void)
{
    size_t i;
    for (i = 0U; i < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++i)
        if (strcmp(noise_fixture_probe_fixtures[i].name, "nnpsk0") == 0)
            return &noise_fixture_probe_fixtures[i];
    return NULL;
}
static int read_file_bytes(const char *path, uint8_t *data, size_t capacity, size_t *length)
{
    FILE *file = fopen(path, "rb");
    size_t count;
    if (file == NULL) return 0;
    count = fread(data, 1U, capacity, file);
    if (ferror(file) || !feof(file)) { fclose(file); return 0; }
    fclose(file);
    *length = count;
    return 1;
}
static const char *pinned_digest(const char *basename)
{
    if (strcmp(basename, "test-direct-minimal-128.json") == 0)
        return "3bbcce998d664fa74970f503a39b28474de9291d453373810d641b2b662fb6e4";
    if (strcmp(basename, "test-direct-minimal-256.json") == 0)
        return "4dc75347343c209c1ed12ab67e60eba83ff974beaa9f351c121da87e7b18b946";
    if (strcmp(basename, "direct-nnpsk0.json") == 0)
        return "29f7895ab3f8dadfbe7331f1981fa35dcad2bec59139464e29bddc4e841e5285";
    if (strcmp(basename, "radio-nnpsk0.json") == 0)
        return "9767b5daff88424e64887dd78a335c4de0f9b93900d4512c1cec9c4d041b53a9";
    return NULL;
}
static int validate_manifest_digest(const char *path, uint8_t digest[32], char digest_hex[65])
{
    uint8_t manifest[65536], digest_file[8192];
    size_t manifest_size, digest_size, directory_size;
    const char *base = strrchr(path, '/');
    const char *backslash = strrchr(path, '\\');
    const char *expected;
    char digests_path[4096], key[96];
    char computed[65];
    char *entry, *colon, *quote;
    if (backslash != NULL && (base == NULL || backslash > base)) base = backslash;
    base = base == NULL ? path : base + 1;
    expected = pinned_digest(base);
    if (expected == NULL || !read_file_bytes(path, manifest, sizeof manifest, &manifest_size)) return 0;
    harness_sha256_hex(manifest, manifest_size, computed);
    if (strcmp(computed, expected) != 0 || strlen(expected) != 64U) return 0;
    harness_sha256(manifest, manifest_size, digest);
    memcpy(digest_hex, expected, 65U);
    directory_size = (size_t)(base - path);
    if (directory_size + sizeof "digests.json" > sizeof digests_path) return 0;
    memcpy(digests_path, path, directory_size);
    memcpy(digests_path + directory_size, "digests.json", sizeof "digests.json");
    if (!read_file_bytes(digests_path, digest_file, sizeof digest_file - 1U, &digest_size)) return 0;
    digest_file[digest_size] = '\0';
    if (snprintf(key, sizeof key, "\"%s\"", base) >= (int)sizeof key) return 0;
    entry = strstr((char *)digest_file, key);
    if (entry == NULL || (colon = strchr(entry, ':')) == NULL || (quote = strchr(colon, '"')) == NULL) return 0;
    ++quote;
    return strncmp(quote, expected, 64U) == 0 && quote[64] == '"';
}
static int startup_ready(void *ctx) { (void)ctx; return 0; }
static int provider_entropy(void *ctx, void *out, size_t size)
{
    uint8_t *p = (uint8_t *)out; size_t i; (void)ctx;
    for (i = 0U; i < size; ++i) { rng_state ^= rng_state << 13; rng_state ^= rng_state >> 17; rng_state ^= rng_state << 5; p[i] = (uint8_t)rng_state; }
    return 0;
}
static void *tracked_alloc(void *ctx, size_t size)
{
    allocation_stats *a = (allocation_stats *)ctx; void *p = malloc(size);
    if (p != NULL) { a->live += size; if (a->live > a->peak) a->peak = a->live; if (size > a->largest) a->largest = size; }
    return p;
}
static void tracked_free(void *ctx, void *p, size_t size)
{
    allocation_stats *a = (allocation_stats *)ctx;
    if (a != NULL && a->live >= size) a->live -= size;
    free(p);
}
static int hs_entropy(void *ctx, uint8_t *out, size_t size)
{
    hs_context *hs = (hs_context *)ctx;
    entropy_script *s = &hs->entropy;
    if (s->index < s->count && s->sizes[s->index] == size) {
        memcpy(out, s->parts[s->index], size);
        ++s->index;
        return 0;
    }
    if (hs->runtime_entropy_enabled) return provider_entropy(NULL, out, size);
    memset(out, 0, size);
    return 1;
}
static uint64_t hs_now(void *ctx) { return ((hs_context *)ctx)->now; }
static int commit_pin(void *ctx, const dmp_hs_pin_record *record) { (void)ctx; (void)record; return 0; }
static int payload_matches(size_t size, const uint8_t *payload, uint8_t xor_value,
                           size_t expected_size)
{
    size_t i;
    if (size != expected_size || (size != 0U && payload == NULL)) return 0;
    for (i = 0U; i < size; ++i) {
        if (payload[i] != (uint8_t)(i ^ xor_value)) return 0;
    }
    return 1;
}
static void on_notice(void *ctx, const dmp_endpoint_notice *notice)
{
    side *s = (side *)ctx;
    if (notice->event == DMP_ENDPOINT_REQUEST) {
        s->app.have_request = 1;
        s->app.request = notice->request;
        s->app.request_payload_bytes = notice->payload.size;
        s->app.request_service_id = notice->service_id;
        s->app.request_payload_matches = notice->service_id == active_profile.service_ids[1] &&
            payload_matches(notice->payload.size,
            notice->payload.data, 0x5aU, active_profile.request_bytes);
        ++s->app.requests;
    }
    if (notice->event == DMP_ENDPOINT_RESULT) {
        if (notice->service_id == 0U) {
            uint32_t lifetime = 0U;
            s->app.freshness_grant_payload_bytes = notice->payload.size;
            if (notice->wire_status == 0U && notice->payload.size == 21U &&
                notice->payload.data != NULL && notice->payload.data[0] == 0x11U) {
                lifetime = (uint32_t)notice->payload.data[17] |
                    ((uint32_t)notice->payload.data[18] << 8U) |
                    ((uint32_t)notice->payload.data[19] << 16U) |
                    ((uint32_t)notice->payload.data[20] << 24U);
                if (lifetime == active_profile.freshness_lease_ms) {
                    memcpy(s->app.freshness_token, notice->payload.data + 1U,
                           sizeof s->app.freshness_token);
                    s->app.freshness_grant_valid = 1;
                }
            }
            ++s->app.freshness_grants;
        } else {
            s->app.result_payload_bytes = notice->payload.size;
            s->app.result_service_id = notice->service_id;
            s->app.result_wire_status = notice->wire_status;
            s->app.result_payload_matches = notice->service_id == active_profile.service_ids[1] &&
                notice->wire_status == 0U &&
                payload_matches(notice->payload.size, notice->payload.data, 0xa5U,
                                active_profile.result_bytes);
            ++s->app.results;
        }
    }
    if (notice->event == DMP_ENDPOINT_DATA) ++s->app.data_notices;
    if (notice->event == DMP_ENDPOINT_ASSEMBLED) { ++s->app.assemblies; s->app.assembled_bytes = notice->payload.size; }
}
static int send_record(socket_t fd, uint8_t kind, const void *data, size_t size);

static int frame_key_from_stream(const uint8_t *data, size_t size, uint64_t now,
                                 logical_frame_key *key)
{
    uint8_t storage[FRAME_CAP];
    dmp_stream_decoder decoder;
    dmp_stream_result decoded;
    dmp_stream_config stream_config;
    dmp_core_limits limits;
    dmp_frame_view view;
    size_t bound;
    if (data == NULL || key == NULL || size == 0U || size > FRAME_CAP ||
        dmp_stream_encoded_bound(DMP_STREAM_R, active_profile.encoded_mtu, &bound) != DMP_OK ||
        bound > sizeof storage) return 0;
    stream_config.mode = DMP_STREAM_R;
    stream_config.max_core_bytes = active_profile.encoded_mtu;
    stream_config.partial_timeout_ms = active_profile.response_timeout_ms;
    if (dmp_stream_init(&decoder, stream_config, (dmp_buffer){storage, bound}, now) != DMP_OK) return 0;
    decoded = dmp_stream_feed(&decoder, (dmp_bytes){data, size}, now);
    if (decoded.status != DMP_OK || decoded.event != DMP_STREAM_FRAME || decoded.consumed != size) return 0;
    limits.max_frame_bytes = active_profile.encoded_mtu;
    limits.max_message_bytes = (uint32_t)active_profile.message_bytes;
    limits.max_fragments = (uint32_t)active_profile.fragments;
    memset(&view, 0, sizeof view);
    if (dmp_core_parse(decoded.frame, &limits, &view).status != DMP_OK ||
        (view.fields.options & DMP_OPT_SECURITY) == 0U ||
        (view.fields.options & DMP_OPT_SEQ) == 0U) return 0;
    key->type = view.fields.type;
    key->seq = view.fields.seq;
    key->fragment_index = (view.fields.options & DMP_OPT_FRAG) != 0U
        ? view.fields.fragment.index : UINT32_MAX;
    key->pn = view.fields.security.pn;
    key->route_present = (view.fields.options & DMP_OPT_ROUTE) != 0U;
    key->route = view.fields.route;
    return 1;
}
static int route_matches_side(const side *s, const logical_frame_key *key, int outgoing)
{
    int local_index, peer_index;
    if (active_profile.origin_route == 0U) return key->route_present == 0U;
    local_index = s->initiator ? 0 : 1;
    peer_index = 1 - local_index;
    if (!outgoing) {
        int swap = local_index;
        local_index = peer_index;
        peer_index = swap;
    }
    return key->route_present && key->route.mode == 1U &&
        key->route.ttl == active_profile.origin_ttl &&
        key->route.source == active_profile.node_ids[local_index] &&
        key->route.destination == active_profile.node_ids[peer_index];
}

/* Local provider port queues owned copies; one client submission is deliberately
 * completed as transmitted and discarded to exercise libdmp's actual retry timer. */
static dmp_status tx_submit(void *ctx, const dmp_tx_submission *submission)
{
    side *s = (side *)ctx;
    logical_frame_key key;
    if (s == NULL || submission == NULL || submission->frame.data == NULL || submission->frame.size > FRAME_CAP || submission->complete == NULL) return DMP_INVALID_ARGUMENT;
    ++s->submissions;
    if (!frame_key_from_stream(submission->frame.data, submission->frame.size, s->now, &key))
        return DMP_MALFORMED;
    if (active_profile.origin_route != 0U) {
        ++s->origin_route_frames;
        if (route_matches_side(s, &key, 1)) {
            ++s->origin_route_frames_valid;
        } else {
            return DMP_MALFORMED;
        }
    } else if (!route_matches_side(s, &key, 1)) {
        return DMP_MALFORMED;
    }
    if (s->capture_freshness_request_frames && key.type == DMP_TYPE_REQ)
        ++s->freshness_grant_request_frames;
    if (s->drop_first && !s->dropped) {
        if (key.type != DMP_TYPE_REQ) return DMP_MALFORMED;
        s->dropped = 1U;
        s->dropped_request_key_valid = 1U;
        s->dropped_request_type = key.type;
        s->dropped_request_seq = key.seq;
        s->dropped_request_fragment = key.fragment_index;
        s->dropped_request_pn = key.pn;
        s->retry_after = s->now + active_profile.response_timeout_ms;
        s->first_drop_size = submission->frame.size;
        memcpy(s->first_drop, submission->frame.data, submission->frame.size);
        submission->complete(submission->owner, submission->token, DMP_TX_TRANSMITTED, s->now);
        return DMP_OK;
    }
    if (s->drop_first && s->dropped && !s->retry_observed && s->now >= s->retry_after) {
        if (s->dropped_request_key_valid && key.type == s->dropped_request_type &&
            key.seq == s->dropped_request_seq && key.fragment_index == s->dropped_request_fragment) {
            s->retry_observed = 1U;
            s->retry_request_type = key.type;
            s->retry_request_pn = key.pn;
            s->retry_distinct = key.pn != s->dropped_request_pn &&
                (submission->frame.size != s->first_drop_size ||
                 memcmp(submission->frame.data, s->first_drop, submission->frame.size) != 0);
        }
    }
    if (s->capture_protected_data && key.type == DMP_TYPE_DATA && !s->protected_data_captured) {
        s->protected_data_captured = 1U;
        s->protected_data_frame_size = submission->frame.size;
        memcpy(s->protected_data_frame, submission->frame.data, submission->frame.size);
    }
    if (!send_record(s->socket, REC_DATA, submission->frame.data, submission->frame.size)) return DMP_BUSY;
    submission->complete(submission->owner, submission->token, DMP_TX_TRANSMITTED, s->now);
    return DMP_OK;
}
static dmp_status tx_cancel(void *ctx, dmp_tx_token token) { (void)ctx; (void)token; return DMP_OK; }
static void fill_budget(dmp_hs_budget *b)
{
    memset(b, 0, sizeof *b);
    /* Pinned minimal manifests: direct count/byte/deadline limits are copied
     * exactly. The private handshake API counts work units, while the manifest
     * expresses CPU budgets in milliseconds; keep that internal ceiling
     * permissive instead of treating milliseconds as work units. */
    b->max_pending = (uint32_t)active_profile.hs_max_pending;
    b->max_scratch = (uint32_t)active_profile.hs_max_scratch;
    b->episode_attempts = (uint32_t)active_profile.hs_episode_attempts;
    b->episode_deadline_ms = active_profile.hs_episode_ms; b->episode_work = 100000U;
    b->episode_traffic = (uint32_t)active_profile.hs_episode_traffic;
    b->restart_backoff_ms = (uint32_t)active_profile.hs_restart_backoff_ms;
    b->attempt_deadline_ms = (uint32_t)active_profile.hs_attempt_ms;
    b->cached_responses = (uint32_t)active_profile.hs_cached_responses;
    b->global_work = 100000U; b->ingress_work = (uint32_t)active_profile.hs_ingress_packets;
    b->later_episodes = (uint32_t)active_profile.hs_later_episodes;
    b->admit_burst = (uint32_t)active_profile.hs_ingress_packets;
    b->admit_window_ms = (uint32_t)active_profile.hs_ingress_window_ms;
    b->provisional_bytes = (uint32_t)active_profile.hs_provisional_bytes;
    b->replay_window = (uint32_t)active_profile.hs_replay_bits;
    b->failed_aead_limit = (uint32_t)active_profile.hs_failed_aead;
    b->association_lifetime_ms = (uint32_t)active_profile.hs_association_ms;
    b->confirmation_timeout_ms = (uint32_t)active_profile.hs_confirmation_timeout_ms;
    b->confirmation_attempts = (uint32_t)active_profile.hs_confirmation_attempts;
}
static void fill_config(dmp_config *c, size_t message, const uint8_t profile_digest[32])
{
    memset(c, 0, sizeof *c); memcpy(c->sha256, profile_digest, sizeof c->sha256);
    c->namespace_id = (uint32_t)active_profile.namespace_id;
    c->node_id[0] = (uint32_t)active_profile.node_ids[0]; c->node_id[1] = (uint32_t)active_profile.node_ids[1];
    c->default_service = (uint32_t)active_profile.default_service;
    c->service_id[0] = (uint32_t)active_profile.service_ids[0]; c->service_id[1] = (uint32_t)active_profile.service_ids[1];
    c->origin_route = (uint8_t)active_profile.origin_route;
    c->origin_ttl = (uint8_t)active_profile.origin_ttl;
    c->freshness_required_mask = (uint8_t)active_profile.freshness_required_mask;
    c->freshness_lease_ms = (uint32_t)active_profile.freshness_lease_ms;
    c->freshness_grant_delivery_age_ms = (uint32_t)active_profile.freshness_grant_delivery_age_ms;
    c->freshness_tokens_per_association = (uint32_t)active_profile.freshness_tokens_per_association;
    c->freshness_tokens_per_principal = (uint32_t)active_profile.freshness_tokens_per_principal;
    c->freshness_grant_requests_per_pair = (uint32_t)active_profile.freshness_grant_requests_per_pair;
    c->freshness_token_record_ms = (uint32_t)active_profile.freshness_token_record_ms;
    c->freshness_grant_result_ms = (uint32_t)active_profile.freshness_grant_result_ms;
    c->recovery[0] = c->recovery[1] = active_profile.selective_recovery
        ? DMP_PROFILE_RECOVERY_SELECTIVE32 : DMP_PROFILE_RECOVERY_RETRY_ALL;
    c->peers = (uint32_t)active_profile.peers;
    c->operations_per_service = (uint32_t)active_profile.operations_per_service;
    c->assemblies_per_peer = (uint32_t)active_profile.assemblies_per_peer;
    c->assembly_tombstones_per_peer = (uint32_t)active_profile.tombstones_per_peer;
    c->sender_slots = (uint32_t)active_profile.sender_slots;
    c->assembly_slots = (uint32_t)(active_profile.peers * active_profile.assemblies_per_peer);
    c->assembly_tombstone_slots = (uint32_t)(active_profile.peers * active_profile.tombstones_per_peer);
    c->result_slots = (uint32_t)active_profile.result_slots;
    c->history_slots = (uint32_t)active_profile.history_slots;
    c->correlation_slots = (uint32_t)active_profile.correlation_slots;
    c->adapter_slots = (uint32_t)active_profile.adapter_slots;
    c->application_queue_slots = (uint32_t)active_profile.application_queue_slots;
    c->control_slots = (uint32_t)active_profile.control_slots;
    c->message_bytes = (uint32_t)message; c->fragments = (uint32_t)active_profile.fragments;
    c->chunk_bytes = (uint32_t)active_profile.chunk_bytes;
    c->encoded_mtu = (uint32_t)active_profile.encoded_mtu;
    c->forward_mtu = (uint32_t)active_profile.forward_mtu;
    c->return_mtu = (uint32_t)active_profile.return_mtu;
    c->queue_ms = (uint32_t)active_profile.queue_ms;
    c->response_timeout_ms = (uint32_t)active_profile.response_timeout_ms;
    c->send_horizon_ms = (uint32_t)active_profile.send_horizon_ms;
    c->max_bursts = (uint32_t)active_profile.max_bursts;
    c->receipt_delay_ms = (uint32_t)active_profile.receipt_delay_ms;
    c->receipt_limit = (uint32_t)active_profile.receipt_limit;
    c->dedup_ms = (uint32_t)active_profile.dedup_ms;
    c->rejection_ms = (uint32_t)active_profile.rejection_ms;
    c->result_cache_ms = (uint32_t)active_profile.result_cache_ms;
    c->result_deadline_ms = (uint32_t)active_profile.result_deadline_ms;
    c->correlation_ms = (uint32_t)active_profile.correlation_ms;
    c->tombstone_ms = (uint32_t)active_profile.tombstone_ms;
    c->late_result_ms = (uint32_t)active_profile.late_result_ms;
    c->collect_ms = (uint32_t)active_profile.collect_ms;
    c->assembly_ms = (uint32_t)active_profile.assembly_ms;
    c->burst_span_ms = (uint32_t)active_profile.burst_span_ms;
    c->forward_delay_ms = (uint32_t)active_profile.forward_delay_ms;
    c->return_delay_ms = (uint32_t)active_profile.return_delay_ms;
    c->feedback_guard_ms = (uint32_t)active_profile.feedback_guard_ms;
    c->feedback_delay_ms = (uint32_t)active_profile.feedback_delay_ms;
    c->max_probes = (uint32_t)active_profile.max_probes;
    c->max_status = (uint32_t)active_profile.max_status;
    c->record_margin_ms = (uint32_t)active_profile.record_margin_ms;
    c->tx_borrow = true; c->synchronous_completion = true;
}
static void fill_hs_config(dmp_hs_config *c, side *s, const noise_fixture_probe_fixture_t *f,
                           const uint8_t profile_digest[32])
{
    memset(c, 0, sizeof *c); fill_budget(&c->budget);
    c->namespace_id = (uint32_t)active_profile.namespace_id;
    c->local_id = (uint32_t)active_profile.node_ids[s->initiator ? 0 : 1];
    c->peer_id = (uint32_t)active_profile.node_ids[s->initiator ? 1 : 0];
    memcpy(c->profile_hash, profile_digest, sizeof c->profile_hash);
    c->mode = (uint32_t)active_profile.hs_mode; c->cipher = (uint32_t)active_profile.hs_cipher;
    c->key_hint = 5U; c->permissions = 2U;
    c->next_rx_cid = (s->initiator ? CID_INIT : CID_RESP) + 2U * (s->generation - 1U);
    memcpy(c->psk, f->psk.data, 32U); c->has_psk = 1;
}
static int json_number(char *text, const char *key, size_t *value)
{
    char pattern[96], *p, *end;
    if (snprintf(pattern, sizeof pattern, "\"%s\"", key) >= (int)sizeof pattern) return 0;
    p = strstr(text, pattern);
    if (p == NULL || (p = strchr(p, ':')) == NULL) return 0;
    *value = (size_t)strtoul(p + 1, &end, 10);
    return end != p + 1;
}
static int json_string(char *text, const char *key, char *value, size_t capacity)
{
    char pattern[96], *p, *end;
    size_t length;
    if (snprintf(pattern, sizeof pattern, "\"%s\"", key) >= (int)sizeof pattern) return 0;
    p = strstr(text, pattern);
    if (p == NULL || (p = strchr(p, ':')) == NULL || (p = strchr(p, '\"')) == NULL) return 0;
    ++p; end = strchr(p, '\"');
    if (end == NULL || (length = (size_t)(end - p)) == 0U || length >= capacity) return 0;
    memcpy(value, p, length); value[length] = '\0';
    return 1;
}
static int json_two_numbers(char *text, const char *key, size_t values[2])
{
    char pattern[96], *p, *end;
    size_t i;
    if (snprintf(pattern, sizeof pattern, "\"%s\"", key) >= (int)sizeof pattern) return 0;
    p = strstr(text, pattern);
    if (p == NULL || (p = strchr(p, '[')) == NULL) return 0;
    for (i = 0U; i < 2U; ++i) {
        values[i] = (size_t)strtoul(p + 1, &end, 10);
        if (end == p + 1) return 0;
        p = strchr(end, i == 0U ? ',' : ']');
        if (p == NULL) return 0;
    }
    return 1;
}
static int resource_count(char *text, const char *component, size_t *count)
{
    char pattern[96], *p;
    if (snprintf(pattern, sizeof pattern, "\"component\": \"%s\"", component) >= (int)sizeof pattern) return 0;
    p = strstr(text, pattern);
    return p != NULL && json_number(p, "count", count);
}
static int manifest_parameters(const char *path, size_t *request)
{
    char buf[65536]; size_t n; char *profile, *identity, *services, *service, *binding, *limits, *timing, *resources, *security, *freshness;
    FILE *f = fopen(path, "rb");
    if (f == NULL) return 0;
    memset(&active_profile, 0, sizeof active_profile);
    n = fread(buf, 1U, sizeof buf - 1U, f); fclose(f); buf[n] = '\0';
    profile = strstr(buf, "\"profile\""); services = strstr(buf, "\"services\""); service = strstr(buf, "\"id\": 2");
    identity = strstr(buf, "\"identity\""); security = strstr(buf, "\"security\"");
    binding = strstr(buf, "\"binding\""); limits = strstr(buf, "\"limits\"");
    timing = strstr(buf, "\"timing\""); resources = strstr(buf, "\"resources\"");
    freshness = strstr(buf, "\"freshness\"");
    if (profile == NULL || identity == NULL || services == NULL || security == NULL || service == NULL || binding == NULL ||
        limits == NULL || timing == NULL || resources == NULL) return 0;
    {
        char *id = strstr(profile, "\"id\""); char *quote;
        if (id == NULL || (id = strchr(id, ':')) == NULL || (quote = strchr(id, '\"')) == NULL) return 0;
        ++quote; { char *end = strchr(quote, '\"'); size_t len = end == NULL ? 0U : (size_t)(end - quote);
          if (len == 0U || len >= sizeof active_profile.id) return 0;
          memcpy(active_profile.id, quote, len); active_profile.id[len] = '\0'; }
    }
#define JNUM(dst, source, key) do { if (!json_number((source), (key), &(dst))) return 0; } while (0)
    JNUM(active_profile.namespace_id, identity, "namespace");
    JNUM(active_profile.default_service, identity, "default_service");
    if (!json_two_numbers(identity, "nodes", active_profile.node_ids)) return 0;
    JNUM(active_profile.service_ids[0], services, "id");
    JNUM(active_profile.service_ids[1], service, "id");
    JNUM(active_profile.message_bytes, limits, "message_bytes");
    JNUM(active_profile.fragments, limits, "fragments");
    JNUM(active_profile.chunk_bytes, limits, "chunk_bytes");
    JNUM(active_profile.peers, limits, "peers");
    JNUM(active_profile.operations_per_service, limits, "operations_per_service");
    JNUM(active_profile.assemblies_per_peer, limits, "assemblies_per_peer");
    JNUM(active_profile.tombstones_per_peer, limits, "assembly_tombstones_per_peer");
    JNUM(active_profile.sender_slots, limits, "sender_slots");
    JNUM(active_profile.application_queue_slots, limits, "application_queue_slots");
    JNUM(active_profile.control_slots, limits, "control_slots");
    JNUM(active_profile.adapter_slots, limits, "adapter_slots");
    JNUM(active_profile.request_bytes, service, "request_bytes");
    JNUM(active_profile.result_bytes, service, "result_bytes");
    JNUM(active_profile.encoded_mtu, binding, "encoded_mtu");
    JNUM(active_profile.forward_mtu, binding, "forward_mtu");
    JNUM(active_profile.return_mtu, binding, "return_mtu");
    JNUM(active_profile.queue_ms, timing, "queue_ms");
    JNUM(active_profile.response_timeout_ms, timing, "response_timeout_ms");
    JNUM(active_profile.send_horizon_ms, timing, "send_horizon_ms");
    JNUM(active_profile.max_bursts, timing, "max_bursts");
    JNUM(active_profile.receipt_delay_ms, timing, "receipt_delay_ms");
    JNUM(active_profile.receipt_limit, timing, "receipt_limit");
    JNUM(active_profile.dedup_ms, timing, "dedup_ms");
    JNUM(active_profile.rejection_ms, timing, "rejection_ms");
    JNUM(active_profile.result_cache_ms, timing, "result_cache_ms");
    JNUM(active_profile.result_deadline_ms, timing, "result_deadline_ms");
    JNUM(active_profile.correlation_ms, timing, "correlation_ms");
    JNUM(active_profile.tombstone_ms, timing, "tombstone_ms");
    JNUM(active_profile.late_result_ms, timing, "late_result_ms");
    JNUM(active_profile.collect_ms, timing, "collect_ms");
    JNUM(active_profile.assembly_ms, timing, "assembly_ms");
    JNUM(active_profile.burst_span_ms, timing, "burst_span_ms");
    JNUM(active_profile.forward_delay_ms, timing, "forward_delay_ms");
    JNUM(active_profile.return_delay_ms, timing, "return_delay_ms");
    JNUM(active_profile.feedback_guard_ms, timing, "feedback_guard_ms");
    JNUM(active_profile.feedback_delay_ms, timing, "feedback_delay_ms");
    JNUM(active_profile.max_probes, timing, "max_probes");
    JNUM(active_profile.max_status, timing, "max_status");
    JNUM(active_profile.record_margin_ms, timing, "record_margin_ms");
    JNUM(active_profile.hs_max_pending, security, "pending_per_pair");
    JNUM(active_profile.hs_max_scratch, security, "crypto_slots");
    JNUM(active_profile.hs_cipher, security, "cipher");
    JNUM(active_profile.hs_episode_attempts, security, "episode_attempts");
    JNUM(active_profile.hs_episode_ms, security, "episode_ms");
    JNUM(active_profile.hs_episode_traffic, security, "episode_tx_bytes");
    JNUM(active_profile.hs_restart_backoff_ms, security, "restart_backoff_ms");
    JNUM(active_profile.hs_attempt_ms, security, "attempt_ms");
    JNUM(active_profile.hs_cached_responses, security, "duplicate_responses_per_attempt");
    JNUM(active_profile.hs_ingress_packets, security, "ingress_packets_per_window");
    JNUM(active_profile.hs_ingress_window_ms, security, "ingress_window_ms");
    JNUM(active_profile.hs_later_episodes, security, "later_episodes_per_window");
    JNUM(active_profile.hs_provisional_bytes, security, "preauth_bytes");
    JNUM(active_profile.hs_replay_bits, security, "replay_window_bits");
    JNUM(active_profile.hs_failed_aead, security, "failed_aead_limit");
    JNUM(active_profile.hs_association_ms, security, "association_ms");
    JNUM(active_profile.hs_global_crypto_ms, security, "global_crypto_ms_per_window");
    JNUM(active_profile.hs_confirmation_timeout_ms, security, "confirmation_timeout_ms");
    JNUM(active_profile.hs_confirmation_attempts, security, "confirmation_attempts");
    if (freshness != NULL && strstr(service, "\"freshness\": true") != NULL) {
        active_profile.freshness_required_mask = 2U;
        JNUM(active_profile.freshness_lease_ms, freshness, "lease_ms");
        JNUM(active_profile.freshness_grant_delivery_age_ms, freshness, "grant_delivery_age_ms");
        JNUM(active_profile.freshness_tokens_per_association, freshness, "tokens_per_association");
        JNUM(active_profile.freshness_tokens_per_principal, freshness, "tokens_per_principal");
        JNUM(active_profile.freshness_grant_requests_per_pair, freshness, "grant_requests_per_pair");
        JNUM(active_profile.freshness_token_record_ms, freshness, "token_record_ms");
        JNUM(active_profile.freshness_grant_result_ms, freshness, "grant_result_ms");
    }
#undef JNUM
    if (!resource_count(resources, "result", &active_profile.result_slots) ||
        !resource_count(resources, "history", &active_profile.history_slots) ||
        !resource_count(resources, "correlation", &active_profile.correlation_slots)) return 0;
    active_profile.selective_recovery = strstr(service, "\"recovery\": \"selective-32\"") != NULL;
    *request = active_profile.request_bytes;
    {
        char binding_kind[32], context[32], mode[32];
        if (!json_string(binding, "kind", binding_kind, sizeof binding_kind) ||
            !json_string(binding, "context", context, sizeof context) ||
            !json_string(security, "mode", mode, sizeof mode)) return 0;
        if (strcmp(mode, "NNpsk0") != 0) return 0;
        if (strcmp(binding_kind, "stream-r") == 0 && strcmp(context, "association") == 0 &&
            strstr(buf, "\"relays\": []") != NULL) {
            active_profile.origin_route = 0U;
        } else if (strcmp(binding_kind, "packet") == 0 &&
                   strcmp(context, "origin-explicit") == 0 &&
                   strcmp(active_profile.id, "RADIO-1") == 0) {
            active_profile.origin_route = 1U;
            if (!json_number(binding, "ttl", &active_profile.origin_ttl)) return 0;
            if (active_profile.origin_ttl > 4U || active_profile.freshness_required_mask != 2U) return 0;
        } else {
            return 0;
        }
        active_profile.hs_mode = 1U; /* NNpsk0 is SEC-1 mode value 1. */
    }
    return active_profile.namespace_id != 0U && active_profile.node_ids[0] != active_profile.node_ids[1] &&
        active_profile.service_ids[0] == active_profile.default_service &&
        active_profile.service_ids[1] == 2U && active_profile.peers == 1U && active_profile.message_bytes <= 1024U &&
        active_profile.request_bytes == active_profile.message_bytes && active_profile.result_bytes == active_profile.message_bytes &&
        active_profile.chunk_bytes != 0U && active_profile.fragments != 0U &&
        active_profile.sender_slots != 0U && active_profile.adapter_slots != 0U &&
        active_profile.hs_mode == 1U && active_profile.hs_cipher == 1U &&
        active_profile.hs_max_pending == 1U && active_profile.hs_max_scratch == 1U &&
        active_profile.hs_episode_attempts != 0U && active_profile.hs_episode_ms != 0U &&
        active_profile.hs_episode_traffic != 0U && active_profile.hs_cached_responses != 0U &&
        active_profile.hs_ingress_packets != 0U && active_profile.hs_ingress_window_ms != 0U &&
        active_profile.hs_replay_bits != 0U && active_profile.hs_failed_aead != 0U &&
        active_profile.hs_association_ms != 0U && active_profile.hs_confirmation_timeout_ms != 0U &&
        active_profile.hs_confirmation_attempts != 0U &&
        (active_profile.freshness_required_mask == 0U ||
         (active_profile.freshness_lease_ms != 0U &&
          active_profile.freshness_tokens_per_association != 0U &&
          active_profile.freshness_tokens_per_principal != 0U &&
          active_profile.freshness_grant_requests_per_pair != 0U &&
          active_profile.freshness_token_record_ms != 0U &&
          active_profile.freshness_grant_result_ms != 0U));
}
static int socket_send_all(socket_t fd, const uint8_t *p, size_t n)
{
    while (n != 0U) {
        int sent = send(fd, (const char *)p, (int)(n > 0x7fffffffU ? 0x7fffffffU : n), 0);
        if (sent <= 0) return 0;
        p += (size_t)sent; n -= (size_t)sent;
    }
    return 1;
}
static int socket_recv_all(socket_t fd, uint8_t *p, size_t n)
{
    while (n != 0U) {
        int got = recv(fd, (char *)p, (int)(n > 0x7fffffffU ? 0x7fffffffU : n), 0);
        if (got <= 0) return 0;
        p += (size_t)got; n -= (size_t)got;
    }
    return 1;
}
static int send_record(socket_t fd, uint8_t kind, const void *data, size_t size)
{
    uint8_t header[5]; uint32_t n = (uint32_t)size;
    if (size > IPC_LIMIT) return 0;
    header[0] = kind; header[1] = (uint8_t)(n >> 24); header[2] = (uint8_t)(n >> 16); header[3] = (uint8_t)(n >> 8); header[4] = (uint8_t)n;
    return socket_send_all(fd, header, sizeof header) && (size == 0U || socket_send_all(fd, (const uint8_t *)data, size));
}
static int recv_record(socket_t fd, uint8_t *kind, uint8_t *data, size_t cap, size_t *size)
{
    uint8_t h[5]; uint32_t n;
    if (!socket_recv_all(fd, h, sizeof h)) return 0;
    n = ((uint32_t)h[1] << 24) | ((uint32_t)h[2] << 16) | ((uint32_t)h[3] << 8) | h[4];
    if (n > cap || n > IPC_LIMIT) return 0;
    if (n != 0U && !socket_recv_all(fd, data, n)) return 0;
    *kind = h[0]; *size = n; return 1;
}
static int config_endpoint(side *s, size_t message, const uint8_t profile_digest[32])
{
    dmp_config c; dmp_endpoint_storage st; dmp_identity_context_config identity; dmp_endpoint_grant grants[6];
    endpoint_bundle *b = (endpoint_bundle *)calloc(1U, sizeof *b);
    size_t assemblies, tombstones, mtu, stream_capacity, stream_rx_capacity;
#define BUNDLE_ALLOC(field, count, type, payload) do { \
    size_t _n = (count), _bytes; \
    if (_n == 0U || _n > SIZE_MAX / sizeof(type)) goto allocation_failed; \
    _bytes = _n * sizeof(type); b->field = calloc(_n, sizeof(type)); \
    if (b->field == NULL) goto allocation_failed; \
    if (payload) b->payload_requested += _bytes; else b->bundle_requested += _bytes; \
} while (0)
    if (b == NULL) return 0;
    b->message_bytes = message;
    assemblies = active_profile.peers * active_profile.assemblies_per_peer;
    tombstones = active_profile.peers * active_profile.tombstones_per_peer;
    mtu = active_profile.encoded_mtu;
    if (dmp_stream_encoded_bound(DMP_STREAM_R, mtu, &stream_rx_capacity) != DMP_OK) goto allocation_failed;
    stream_capacity = stream_rx_capacity + 1U;
    b->bundle_requested = sizeof *b;
    BUNDLE_ALLOC(identities, active_profile.peers, dmp_identity_slot, 0);
    BUNDLE_ALLOC(senders, active_profile.sender_slots, dmp_reliability_sender_slot, 0);
    BUNDLE_ALLOC(sender_payload, active_profile.sender_slots * message, uint8_t, 1);
    BUNDLE_ALLOC(results, active_profile.result_slots, dmp_reliability_result_slot, 0);
    BUNDLE_ALLOC(result_payload, active_profile.result_slots * message, uint8_t, 1);
    BUNDLE_ALLOC(history, active_profile.history_slots, dmp_reliability_history_slot, 0);
    BUNDLE_ALLOC(correlations, active_profile.correlation_slots, dmp_reliability_correlation_slot, 0);
    BUNDLE_ALLOC(history_metadata, active_profile.history_slots * DMP_RELIABILITY_METADATA_BYTES, uint8_t, 0);
    BUNDLE_ALLOC(correlation_metadata, active_profile.correlation_slots * DMP_RELIABILITY_METADATA_BYTES, uint8_t, 0);
    BUNDLE_ALLOC(adapters, active_profile.adapter_slots, dmp_reliability_adapter_slot, 0);
    BUNDLE_ALLOC(frames, active_profile.adapter_slots * mtu, uint8_t, 0);
    BUNDLE_ALLOC(receive_payload, message, uint8_t, 1);
    BUNDLE_ALLOC(assemblies, assemblies, dmp_reassembly_slot, 0);
    BUNDLE_ALLOC(tombstones, tombstones, dmp_reassembly_tombstone, 0);
    if (active_profile.freshness_required_mask != 0U) {
        BUNDLE_ALLOC(freshness_slots, 2U * active_profile.freshness_tokens_per_association,
                     dmp_endpoint_freshness_slot, 0);
    }
    BUNDLE_ALLOC(assembly_payload, assemblies * message, uint8_t, 1);
    BUNDLE_ALLOC(assembly_metadata, assemblies * DMP_REASSEMBLY_METADATA_BYTES, uint8_t, 0);
    BUNDLE_ALLOC(fragment_message, message, uint8_t, 1);
    BUNDLE_ALLOC(fragment_frame, mtu, uint8_t, 0);
    BUNDLE_ALLOC(telemetry_payload, message, uint8_t, 1);
    BUNDLE_ALLOC(telemetry_next, message, uint8_t, 1);
    BUNDLE_ALLOC(telemetry_frame, mtu, uint8_t, 0);
    BUNDLE_ALLOC(stream_tx, stream_capacity, uint8_t, 0);
    BUNDLE_ALLOC(stream_rx, stream_capacity, uint8_t, 0);
    fill_config(&c, message, profile_digest);
    { dmp_status status = dmp_config_admit(&c, &b->admitted);
      if (status != DMP_OK) { fprintf(stderr, "dmp_config_admit status=%d senders=%u results=%u history=%u corr=%u adapters=%u message=%u fragments=%u\n", (int)status, c.sender_slots, c.result_slots, c.history_slots, c.correlation_slots, c.adapter_slots, c.message_bytes, c.fragments); goto allocation_failed; } }
    memset(&identity, 0, sizeof identity);
    identity.local.namespace_id = identity.peer.namespace_id = (uint32_t)active_profile.namespace_id;
    identity.local.origin_id = (uint32_t)active_profile.node_ids[s->initiator ? 0 : 1];
    identity.peer.origin_id = (uint32_t)active_profile.node_ids[s->initiator ? 1 : 0]; identity.security = 1U;
    b->transport.context = s; b->transport.submit = tx_submit; b->transport.cancel = tx_cancel;
    b->transport.caps.max_frame_bytes = (uint32_t)stream_capacity; b->transport.caps.ownership = DMP_TX_BORROW; b->transport.caps.synchronous_completion = true;
    memset(&st, 0, sizeof st); st.profile = &b->admitted; st.identity_slots = b->identities; st.identity_capacity = active_profile.peers; st.context = identity;
    st.transport = &b->transport; st.notice = on_notice; st.notice_user = s;
    st.senders = b->senders; st.sender_capacity = active_profile.sender_slots; st.sender_payload = b->sender_payload; st.sender_payload_capacity = active_profile.sender_slots * message;
    st.results = b->results; st.result_capacity = active_profile.result_slots; st.result_payload = b->result_payload; st.result_payload_capacity = active_profile.result_slots * message;
    st.history = b->history; st.history_capacity = active_profile.history_slots; st.correlations = b->correlations; st.correlation_capacity = active_profile.correlation_slots;
    st.history_metadata = b->history_metadata; st.history_metadata_capacity = active_profile.history_slots * DMP_RELIABILITY_METADATA_BYTES;
    st.correlation_metadata = b->correlation_metadata; st.correlation_metadata_capacity = active_profile.correlation_slots * DMP_RELIABILITY_METADATA_BYTES;
    st.adapters = b->adapters; st.adapter_capacity = active_profile.adapter_slots; st.frames = b->frames; st.frame_capacity = active_profile.adapter_slots * mtu;
    st.receive_payload = b->receive_payload; st.receive_payload_capacity = message;
    st.assemblies = b->assemblies; st.assembly_capacity = assemblies; st.tombstones = b->tombstones; st.tombstone_capacity = tombstones;
    st.freshness_slots = b->freshness_slots;
    st.freshness_capacity = b->freshness_slots != NULL
        ? 2U * active_profile.freshness_tokens_per_association : 0U;
    st.assembly_payload = b->assembly_payload; st.assembly_payload_capacity = assemblies * message;
    st.assembly_metadata = b->assembly_metadata; st.assembly_metadata_capacity = assemblies * DMP_REASSEMBLY_METADATA_BYTES;
    st.fragment_message = b->fragment_message; st.fragment_message_capacity = message;
    st.fragment_frame = b->fragment_frame; st.fragment_frame_capacity = mtu;
    st.telemetry_payload = b->telemetry_payload; st.telemetry_payload_capacity = message;
    st.telemetry_next = b->telemetry_next; st.telemetry_next_capacity = message;
    st.telemetry_frame = b->telemetry_frame; st.telemetry_frame_capacity = mtu;
    st.stream_tx = b->stream_tx; st.stream_tx_capacity = stream_capacity; st.stream_rx = b->stream_rx; st.stream_rx_capacity = stream_rx_capacity;
    { dmp_status status = dmp_endpoint_init(&b->endpoint, &st, s->now);
      if (status != DMP_OK) { fprintf(stderr, "dmp_endpoint_init status=%d\n", (int)status); goto allocation_failed; } }
    memset(grants, 0, sizeof grants);
    grants[0].principal = (uint32_t)active_profile.node_ids[0]; grants[0].service_id = (uint32_t)active_profile.service_ids[0]; grants[0].permit = DMP_ENDPOINT_PERMIT_TELEM | DMP_ENDPOINT_PERMIT_RESULT;
    grants[1].principal = (uint32_t)active_profile.node_ids[1]; grants[1].service_id = (uint32_t)active_profile.service_ids[0]; grants[1].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[2].principal = (uint32_t)active_profile.node_ids[0]; grants[2].service_id = (uint32_t)active_profile.service_ids[1]; grants[2].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    grants[3].principal = (uint32_t)active_profile.node_ids[1]; grants[3].service_id = (uint32_t)active_profile.service_ids[1]; grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    if (active_profile.freshness_required_mask != 0U) {
        grants[4].principal = (uint32_t)active_profile.node_ids[0];
        grants[4].service_id = 0U;
        grants[4].permit = DMP_ENDPOINT_PERMIT_CONTROL;
        grants[5].principal = (uint32_t)active_profile.node_ids[1];
        grants[5].service_id = 0U;
        grants[5].permit = DMP_ENDPOINT_PERMIT_CONTROL;
    }
    { dmp_status status = dmp_endpoint_set_grants(&b->endpoint, grants,
            active_profile.freshness_required_mask != 0U ? 6U : 4U);
      if (status != DMP_OK) { fprintf(stderr, "dmp_endpoint_set_grants status=%d\n", (int)status); goto allocation_failed; } }
    s->bundle = b; return 1;
allocation_failed:
    free(b->identities); free(b->senders); free(b->sender_payload); free(b->results); free(b->result_payload);
    free(b->history); free(b->correlations); free(b->history_metadata); free(b->correlation_metadata);
    free(b->adapters); free(b->frames); free(b->receive_payload); free(b->assemblies); free(b->tombstones);
    free(b->freshness_slots); free(b->assembly_payload); free(b->assembly_metadata); free(b->fragment_message); free(b->fragment_frame);
    free(b->telemetry_payload); free(b->telemetry_next); free(b->telemetry_frame); free(b->stream_tx); free(b->stream_rx); free(b);
#undef BUNDLE_ALLOC
    return 0;
}
static int seed_entropy(uint8_t out[64], size_t *out_size, const uint8_t *seed,
                        size_t seed_size, uint32_t generation, uint8_t domain)
{
    size_t i;
    if (seed_size == 0U || seed_size > 64U) return 0;
    memcpy(out, seed, seed_size);
    if (generation > 1U) {
        for (i = 0U; i < seed_size; ++i) {
            uint8_t delta = (uint8_t)(domain + 0x53U * generation + 0x2dU * (uint32_t)i);
            out[i] ^= delta == 0U ? 0xa5U : delta;
        }
    }
    *out_size = seed_size;
    return 1;
}
static int setup_side(side *s, size_t message, int initiator, uint32_t generation,
                      const noise_fixture_probe_fixture_t *f, const uint8_t profile_digest[32])
{
    dmp_provider_ports pp; dmp_hs_ports hp; dmp_hs_config hc; entropy_script *script;
    memset(s, 0, sizeof *s); s->initiator = initiator != 0; s->generation = generation; s->now = 10000U;
    rng_state = (initiator ? 0x51f15eedU : 0x811c9dc5U) ^ (0x9e3779b9U * generation);
    s->provider = (dmp_provider *)calloc(1U, dmp_provider_size()); s->handshake = (dmp_hs *)calloc(1U, dmp_hs_size());
    if (s->provider == NULL || s->handshake == NULL) return 0;
    memset(&pp, 0, sizeof pp); pp.startup_ready = startup_ready; pp.startup_read = provider_entropy; pp.entropy = provider_entropy;
    pp.allocate = tracked_alloc; pp.release = tracked_free; pp.ctx = &s->allocations;
    pp.scratch_limit = DMP_PROVIDER_SCRATCH_MAX; pp.retained_limit = DMP_PROVIDER_RETAINED_MAX;
    if (dmp_provider_setup(s->provider, &pp) != DMP_PROVIDER_OK || !config_endpoint(s, message, profile_digest)) return 0;
    script = &s->hsctx.entropy;
    if (initiator) {
        if (!seed_entropy(script->owned[0], &script->sizes[0], f->attempt_id.data,
                          f->attempt_id.size, generation, 0x17U) ||
            !seed_entropy(script->owned[1], &script->sizes[1], f->init_ephemeral.data,
                          f->init_ephemeral.size, generation, 0x43U)) return 0;
        script->parts[0] = script->owned[0]; script->parts[1] = script->owned[1]; script->count = 2U;
    } else {
        if (!seed_entropy(script->owned[2], &script->sizes[0], f->resp_ephemeral.data,
                          f->resp_ephemeral.size, generation, 0x79U)) return 0;
        script->parts[0] = script->owned[2]; script->count = 1U;
    }
    s->hsctx.now = s->now;
    fill_hs_config(&hc, s, f, profile_digest); memset(&hp, 0, sizeof hp); hp.now_ms = hs_now; hp.entropy = hs_entropy; hp.commit_pin = commit_pin; hp.ctx = &s->hsctx;
    if (dmp_hs_init(s->handshake, s->provider, &hc, &hp) != DMP_HS_OK) return 0;
    if (initiator && dmp_hs_begin_episode(s->handshake) != DMP_HS_OK) return 0;
    /* The script lifetime is process side lifetime; free at close. */
    s->app.have_request = 0; return 1;
}
static void close_side(side *s)
{
    if (s->handshake != NULL) { dmp_hs_cleanup(s->handshake); free(s->handshake); }
    if (s->provider != NULL) {
        dmp_provider_cleanup(s->provider);
        if (s->allocations.live != 0U || dmp_provider_retained(s->provider) != 0U) {
            fputs("provider cleanup left tracked retained bytes\n", stderr);
            abort();
        }
        free(s->provider);
    }
    if (s->bundle != NULL) {
        endpoint_bundle *b = s->bundle;
        free(b->identities); free(b->senders); free(b->sender_payload); free(b->results); free(b->result_payload);
        free(b->history); free(b->correlations); free(b->history_metadata); free(b->correlation_metadata);
        free(b->adapters); free(b->frames); free(b->receive_payload); free(b->assemblies); free(b->tombstones);
        free(b->freshness_slots); free(b->assembly_payload); free(b->assembly_metadata); free(b->fragment_message); free(b->fragment_frame);
        free(b->telemetry_payload); free(b->telemetry_next); free(b->telemetry_frame); free(b->stream_tx); free(b->stream_rx); free(b);
    }
    memset(s, 0, sizeof *s);
}
static size_t caller_owned_requested(const side *s)
{ return (s->bundle != NULL ? s->bundle->bundle_requested + s->bundle->payload_requested : 0U) + (s->provider != NULL ? dmp_provider_size() : 0U) + (s->handshake != NULL ? dmp_hs_size() : 0U); }
static void capture(phase_sample *p, const side *s)
{
    if (s->provider == NULL || s->allocations.live != dmp_provider_retained(s->provider)) {
        fputs("provider allocator high-water tracker disagrees with provider\n", stderr);
        abort();
    }
    p->caller_owned_requested = caller_owned_requested(s);
    p->endpoint_bundle_object_requested = s->bundle != NULL ? s->bundle->bundle_requested : 0U;
    p->caller_payload_buffers_requested = s->bundle != NULL ? s->bundle->payload_requested : 0U;
    p->provider_object_requested = s->provider != NULL ? dmp_provider_size() : 0U;
    p->handshake_object_requested = s->handshake != NULL ? dmp_hs_size() : 0U;
    p->provider_current = s->allocations.live; p->provider_peak = s->allocations.peak;
    p->provider_largest = s->allocations.largest;
    p->origin_route_frames = s->origin_route_frames + s->origin_route_rx_frames;
    p->origin_route_frames_valid = s->origin_route_frames_valid + s->origin_route_rx_frames_valid;
    p->freshness_grant_request_frames = s->freshness_grant_request_frames;
    p->freshness_grant_result_payload_bytes = s->app.freshness_grant_payload_bytes;
    p->freshness_grant_verified = s->app.freshness_grant_valid && s->app.freshness_grants == 1;
    p->freshness_token_bound_to_request = s->freshness_token_bound_to_request;
    p->tx_submissions = s->submissions; p->injected_losses = s->dropped;
    p->request_notices = (size_t)s->app.requests; p->result_notices = (size_t)s->app.results;
    p->local_request_submissions = s->local_requests;
    p->retry_frame_distinct = s->retry_distinct;
    p->dropped_request_seq = s->dropped_request_seq;
    p->dropped_request_type = s->dropped_request_type;
    p->dropped_request_fragment = s->dropped_request_fragment;
    p->dropped_request_pn = s->dropped_request_pn;
    if (s->retry_observed) {
        p->retry_request_seq = s->dropped_request_seq;
        p->retry_request_type = s->retry_request_type;
        p->retry_request_fragment = s->dropped_request_fragment;
        p->retry_request_pn = s->retry_request_pn;
    }
    p->requested_payload_high_water = p->caller_owned_requested + p->provider_peak;
    p->peer_request_notices = s->peer.requests;
}
static int hs_offer(dmp_hs *hs, const uint8_t *p, size_t n, uint32_t origin, uint32_t dest, uint64_t epoch, uint32_t seq, dmp_hs_status expected)
{
    dmp_hs_ingress in; dmp_hs_completion done; dmp_hs_status st;
    memset(&in, 0, sizeof in); in.payload = p; in.payload_len = n; in.origin_id = origin; in.destination_id = dest; in.namespace_id = (uint32_t)active_profile.namespace_id; in.context_epoch = epoch; in.seq = seq;
    st = dmp_hs_offer(hs, &in, &done); if (st == DMP_HS_AWAITING) st = dmp_hs_accept(hs, &done); return st == expected;
}
static int hs_protected(dmp_hs *hs, const uint8_t *p, size_t n, uint32_t origin, uint32_t dest, uint64_t epoch)
{
    dmp_hs_protected in; memset(&in, 0, sizeof in); in.frame = p; in.frame_len = n; in.origin_id = origin; in.destination_id = dest; in.namespace_id = (uint32_t)active_profile.namespace_id; in.context_epoch = epoch; return dmp_hs_offer_protected(hs, &in) == DMP_HS_OK;
}
static int bind_endpoint(side *s)
{ dmp_status st = dmp_endpoint_bind(&s->bundle->endpoint, s->handshake, s->attempt); if (st != DMP_OK) fprintf(stderr,"endpoint bind failed role=%u attempt=%u status=%d\n", (unsigned)s->initiator, s->attempt, (int)st); return st == DMP_OK; }
static int send_cached(socket_t fd, uint8_t type, const uint8_t *p, size_t n) { return send_record(fd, type, p, n); }
static int parent_handshake(side *s, const noise_fixture_probe_fixture_t *f)
{
    uint8_t buf[IPC_LIMIT], first[IPC_LIMIT]; uint8_t type; size_t n; uint64_t epoch, ei, er; const uint8_t *p; size_t pn;
    if (dmp_hs_schedule(s->handshake, &s->attempt) != DMP_HS_OK) return 0;
    epoch = dmp_hs_boot_epoch(s->handshake, s->attempt); if (epoch == 0U) return 0;
    p = dmp_hs_cached_flight(s->handshake, s->attempt, &pn); if (p == NULL || pn + sizeof epoch > sizeof first) return 0;
    memcpy(first, &epoch, sizeof epoch); memcpy(first + sizeof epoch, p, pn);
    if (!send_cached(s->socket, REC_HANDSHAKE, first, pn + sizeof epoch)) return 0;
    if (!recv_record(s->socket, &type, buf, sizeof buf, &n) || type != REC_HANDSHAKE || !hs_offer(s->handshake, buf, n, (uint32_t)active_profile.node_ids[1], (uint32_t)active_profile.node_ids[0], epoch, 2U, DMP_HS_CANDIDATE)) return 0;
    if (!dmp_hs_epochs(s->handshake, s->attempt, &ei, &er) || dmp_hs_confirm(s->handshake, s->attempt) != DMP_HS_OK) return 0;
    p = dmp_hs_protected_frame(s->handshake, s->attempt, &pn); if (p == NULL || !send_cached(s->socket, REC_HANDSHAKE, p, pn)) return 0;
    if (!recv_record(s->socket, &type, buf, sizeof buf, &n) || type != REC_HANDSHAKE || !hs_protected(s->handshake, buf, n, (uint32_t)active_profile.node_ids[1], (uint32_t)active_profile.node_ids[0], er)) return 0;
    if (!dmp_hs_association_active(s->handshake) || !bind_endpoint(s) || f == NULL) return 0;
    /* Track the traffic epoch used by the initiator endpoint, not the boot
     * envelope hash used to bind handshake flights. */
    s->association_epoch = ei;
    if (s->association_epoch == 0U) return 0;
    s->hsctx.runtime_entropy_enabled = 1;
    return 1;
}
static int peer_handshake_step(side *s, uint8_t *buf, size_t n)
{
    uint64_t epoch, ei, er; const uint8_t *p; size_t pn;
    if (s->handshake_stage == 0U) {
        if (n <= sizeof epoch) return 0;
        memcpy(&epoch, buf, sizeof epoch);
        if (epoch == 0U || !hs_offer(s->handshake, buf + sizeof epoch, n - sizeof epoch, (uint32_t)active_profile.node_ids[0], (uint32_t)active_profile.node_ids[1], epoch, 1U, DMP_HS_CANDIDATE)) return 0;
        p = dmp_hs_cached_flight(s->handshake, 0U, &pn);
        if (p == NULL || !send_cached(s->socket, REC_HANDSHAKE, p, pn)) return 0;
        s->handshake_stage = 1U; return 1;
    }
    if (!dmp_hs_epochs(s->handshake, 0U, &ei, &er) || !hs_protected(s->handshake, buf, n, (uint32_t)active_profile.node_ids[0], (uint32_t)active_profile.node_ids[1], ei)) return 0;
    p = dmp_hs_protected_frame(s->handshake, 0U, &pn);
    if (p == NULL || !send_cached(s->socket, REC_HANDSHAKE, p, pn) || !dmp_hs_association_active(s->handshake)) return 0;
    /* The responder-side traffic epoch is distinct from the boot epoch. */
    s->association_epoch = er;
    if (s->association_epoch == 0U) return 0;
    s->handshake_stage = 2U;
    if (!bind_endpoint(s)) return 0;
    s->hsctx.runtime_entropy_enabled = 1;
    return 1;
}
static void complete_request(side *s)
{
    static uint8_t rsp[1024];
    size_t i;
    if (s->app.have_request) {
        for (i = 0U; i < active_profile.result_bytes; ++i) rsp[i] = (uint8_t)(i ^ 0xa5U);
        dmp_status st = dmp_endpoint_complete(&s->bundle->endpoint, s->app.request, false, 0U,
                                               (dmp_bytes){rsp, active_profile.result_bytes}, s->now);
        if (st != DMP_OK) fprintf(stderr, "peer complete status=%d\n", (int)st);
        s->app.have_request = 0;
    }
}
static int peer_main_loop(side *s, size_t message, const noise_fixture_probe_fixture_t *f,
                          const uint8_t profile_digest[32])
{
    uint8_t type, buf[IPC_LIMIT]; size_t n;
    for (;;) {
        if (!recv_record(s->socket, &type, buf, sizeof buf, &n)) return 0;
        if (type == REC_QUIT) return send_record(s->socket, REC_DONE, NULL, 0U);
        if (type == REC_RESTART) {
            socket_t fd = s->socket;
            uint32_t next_generation;
            uint8_t old_responder_ephemeral[64];
            size_t old_responder_ephemeral_size = s->hsctx.entropy.sizes[0];
            uint64_t old_epoch = s->association_epoch;
            if (n != sizeof next_generation || old_responder_ephemeral_size > sizeof old_responder_ephemeral) return 0;
            memcpy(&next_generation, buf, sizeof next_generation);
            memcpy(old_responder_ephemeral, s->hsctx.entropy.owned[2], old_responder_ephemeral_size);
            close_side(s);
            if (next_generation == 0U || !setup_side(s, message, 0, next_generation, f, profile_digest)) return 0;
            s->socket = fd;
            s->prior_epoch = old_epoch;
            s->responder_ephemeral_changed = old_responder_ephemeral_size == s->hsctx.entropy.sizes[0] &&
                memcmp(old_responder_ephemeral, s->hsctx.entropy.owned[2], old_responder_ephemeral_size) != 0;
            if (!send_record(s->socket, REC_DONE, NULL, 0U)) return 0;
            continue;
        }
        if (type == REC_STALE_DATA) {
            peer_status state;
            dmp_status st;
            if (n == 0U || n > FRAME_CAP) return 0;
            memset(&state, 0, sizeof state);
            state.stale_requests_before = (uint32_t)s->app.requests;
            state.stale_data_before = (uint32_t)s->app.data_notices;
            state.stale_assemblies_before = (uint32_t)s->app.assemblies;
            st = dmp_endpoint_rx(&s->bundle->endpoint, (dmp_bytes){buf, n}, s->now);
            state.stale_status = (uint32_t)st;
            state.stale_requests_after = (uint32_t)s->app.requests;
            state.stale_data_after = (uint32_t)s->app.data_notices;
            state.stale_assemblies_after = (uint32_t)s->app.assemblies;
            state.association_epoch = s->association_epoch;
            state.prior_epoch = s->prior_epoch;
            state.responder_ephemeral_changed = s->responder_ephemeral_changed;
            if (!send_record(s->socket, REC_STALE_RESULT, &state, sizeof state)) return 0;
            continue;
        }
        if (type == REC_HANDSHAKE) {
            if (!peer_handshake_step(s, buf, n)) return 0;
            continue;
        }
        if (type == REC_DATA) {
            dmp_status st = dmp_endpoint_rx(&s->bundle->endpoint, (dmp_bytes){buf, n}, s->now);
            if (st != DMP_OK && st != DMP_INCOMPLETE && st != DMP_DUPLICATE) { (void)send_record(s->socket, REC_ERROR, &st, sizeof st); fprintf(stderr, "peer endpoint rx status=%d\n", (int)st); return 0; }
            complete_request(s); continue;
        }
        if (type == REC_TICK) {
            if (n != sizeof(uint64_t)) return 0;
            memcpy(&s->now, buf, sizeof s->now); complete_request(s);
            s->hsctx.now = s->now;
            { dmp_status st = dmp_endpoint_poll(&s->bundle->endpoint, s->now); if (st != DMP_OK) { fprintf(stderr, "peer endpoint poll status=%d\n", (int)st); return 0; } }
            peer_status state;
            memset(&state, 0, sizeof state);
            state.requests = (uint32_t)s->app.requests; state.results = (uint32_t)s->app.results;
            state.data_notices = (uint32_t)s->app.data_notices;
            state.assemblies = (uint32_t)s->app.assemblies; state.assembled_bytes = (uint64_t)s->app.assembled_bytes;
            state.request_payload_bytes = (uint64_t)s->app.request_payload_bytes;
            state.request_payload_matches = s->app.request_payload_matches != 0;
            state.request_service_id = s->app.request_service_id;
            state.association_epoch = s->association_epoch;
            state.prior_epoch = s->prior_epoch;
            state.responder_ephemeral_changed = s->responder_ephemeral_changed;
            if (!send_record(s->socket, REC_DONE, &state, sizeof state)) return 0;
            continue;
        }
        return 0;
    }
}

static socket_t listen_loopback(uint16_t *port)
{
    socket_t fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); struct sockaddr_in addr; socklen_t n = (socklen_t)sizeof addr;
    if (fd == BAD_SOCKET) return BAD_SOCKET;
    memset(&addr, 0, sizeof addr); addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || listen(fd, 1) != 0 || getsockname(fd, (struct sockaddr *)&addr, &n) != 0) { CLOSE_SOCKET(fd); return BAD_SOCKET; }
    *port = ntohs(addr.sin_port); return fd;
}
static socket_t connect_loopback(uint16_t port)
{
    struct sockaddr_in addr; socket_t fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == BAD_SOCKET) return BAD_SOCKET;
    memset(&addr, 0, sizeof addr); addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0) return fd;
    CLOSE_SOCKET(fd); return BAD_SOCKET;
}
static int start_peer(const char *exe, const char *manifest, uint16_t port
#ifdef _WIN32
                      , PROCESS_INFORMATION *process
#else
                      , pid_t *process
#endif
)
{
#ifdef _WIN32
    STARTUPINFOA startup; char command[2048];
    memset(&startup, 0, sizeof startup); memset(process, 0, sizeof *process); startup.cb = sizeof startup;
    startup.dwFlags = STARTF_USESTDHANDLES; startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE); startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    if (snprintf(command, sizeof command, "\"%s\" --peer %u --manifest \"%s\"", exe, (unsigned)port, manifest) >= (int)sizeof command) return 0;
    if (!CreateProcessA(NULL, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &startup, process)) return 0;
    CloseHandle(process->hThread); return 1;
#else
    pid_t child = fork();
    if (child < 0) return 0;
    if (child == 0) { char port_text[16]; (void)snprintf(port_text, sizeof port_text, "%u", (unsigned)port); execl(exe, exe, "--peer", port_text, "--manifest", manifest, (char *)NULL); _exit(127); }
    *process = child; return 1;
#endif
}
static int connect_peer_process(const char *exe, const char *manifest, socket_t *connection
#ifdef _WIN32
                                 , PROCESS_INFORMATION *process
#else
                                 , pid_t *process
#endif
)
{
    uint16_t port = 0U; socket_t listener = listen_loopback(&port); struct sockaddr_in peer; socklen_t length = (socklen_t)sizeof peer;
    if (listener == BAD_SOCKET || !start_peer(exe, manifest, port, process)) { if (listener != BAD_SOCKET) CLOSE_SOCKET(listener); return 0; }
    *connection = accept(listener, (struct sockaddr *)&peer, &length); CLOSE_SOCKET(listener); return *connection != BAD_SOCKET;
}
static int peer_process_succeeded(
#ifdef _WIN32
    PROCESS_INFORMATION *process
#else
    pid_t process
#endif
)
{
#ifdef _WIN32
    DWORD wait_status = WaitForSingleObject(process->hProcess, 5000U);
    DWORD exit_code = STILL_ACTIVE;
    int success = wait_status == WAIT_OBJECT_0 && GetExitCodeProcess(process->hProcess, &exit_code) && exit_code == 0U;
    if (wait_status != WAIT_OBJECT_0) {
        (void)TerminateProcess(process->hProcess, 1U);
        (void)WaitForSingleObject(process->hProcess, 5000U);
    }
    CloseHandle(process->hProcess);
    process->hProcess = NULL;
    return success;
#else
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(process, &status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited == process && WIFEXITED(status) && WEXITSTATUS(status) == 0;
#endif
}
static int parent_tick(side *s, uint64_t now)
{
    uint8_t type, buf[IPC_LIMIT]; size_t n; logical_frame_key key;
    s->now = now; s->hsctx.now = now;
    if (dmp_endpoint_poll(&s->bundle->endpoint, now) != DMP_OK) { fputs("parent poll failed\n", stderr); return 0; }
    if (!send_record(s->socket, REC_TICK, &now, sizeof now)) { fputs("parent tick send failed\n", stderr); return 0; }
    for (;;) {
        if (!recv_record(s->socket, &type, buf, sizeof buf, &n)) return 0;
        if (type == REC_DONE) {
            if (n != sizeof s->peer) return 0;
            memcpy(&s->peer, buf, sizeof s->peer);
            break;
        }
        if (type != REC_DATA) return 0;
        if (!frame_key_from_stream(buf, n, now, &key)) return 0;
        if (active_profile.origin_route != 0U) {
            ++s->origin_route_rx_frames;
            if (!route_matches_side(s, &key, 0)) return 0;
            ++s->origin_route_rx_frames_valid;
        } else if (!route_matches_side(s, &key, 0)) {
            return 0;
        }
        { dmp_status st = dmp_endpoint_rx(&s->bundle->endpoint, (dmp_bytes){buf, n}, now); if (st != DMP_OK && st != DMP_INCOMPLETE && st != DMP_DUPLICATE) { fprintf(stderr, "measured endpoint rx status=%d\n", (int)st); return 0; } }
    }
    return 1;
}
static int request_freshness_grant(side *s)
{
    uint8_t payload[5] = {0x10U, 0U, 0U, 0U, 0U};
    int before_grants = s->app.freshness_grants;
    unsigned round;
    dmp_reliability_handle handle;
    dmp_status status;
    uint32_t requested = (uint32_t)active_profile.freshness_lease_ms;
    payload[1] = (uint8_t)requested;
    payload[2] = (uint8_t)(requested >> 8U);
    payload[3] = (uint8_t)(requested >> 16U);
    payload[4] = (uint8_t)(requested >> 24U);
    if (active_profile.freshness_required_mask == 0U || requested == 0U) return 0;
    s->freshness_grant_request_frames = 0U;
    s->capture_freshness_request_frames = 1U;
    status = dmp_endpoint_submit_req(&s->bundle->endpoint, 0U,
                                     (dmp_bytes){payload, sizeof payload}, s->now, &handle);
    if (status != DMP_OK) {
        s->capture_freshness_request_frames = 0U;
        fprintf(stderr, "freshness service-0 submit status=%d\n", (int)status);
        return 0;
    }
    status = dmp_endpoint_poll(&s->bundle->endpoint, s->now);
    if (status != DMP_OK) {
        s->capture_freshness_request_frames = 0U;
        fprintf(stderr, "freshness service-0 poll status=%d\n", (int)status);
        return 0;
    }
    for (round = 0U; round < 4U && s->app.freshness_grants == before_grants; ++round) {
        if (!parent_tick(s, s->now)) {
            s->capture_freshness_request_frames = 0U;
            fprintf(stderr, "freshness service-0 exchange failed at round=%u\n", round);
            return 0;
        }
        if (s->app.freshness_grants == before_grants) s->now += active_profile.queue_ms;
    }
    s->capture_freshness_request_frames = 0U;
    if (s->freshness_grant_request_frames == 0U ||
        s->app.freshness_grants != before_grants + 1 || !s->app.freshness_grant_valid) {
        fprintf(stderr, "freshness result missing: frames=%zu grants=%d bytes=%zu valid=%d route_tx=%zu/%zu route_rx=%zu/%zu\n",
                s->freshness_grant_request_frames, s->app.freshness_grants,
                s->app.freshness_grant_payload_bytes, s->app.freshness_grant_valid,
                s->origin_route_frames_valid, s->origin_route_frames,
                s->origin_route_rx_frames_valid, s->origin_route_rx_frames);
        return 0;
    }
    return s->freshness_grant_request_frames != 0U &&
        s->app.freshness_grants == before_grants + 1 && s->app.freshness_grant_valid;
}
static int pump_exchange(side *s)
{
    uint64_t now = s->now; unsigned rounds;
    for (rounds = 0U; rounds < 64U; ++rounds) {
        if (!parent_tick(s, now)) return 0;
        if (s->app.results != 0) {
            if (!parent_tick(s, now)) return 0;
            return s->app.results == 1;
        }
        now += active_profile.queue_ms;
    }
    fprintf(stderr, "pump exhausted: results=%d peer_requests=%u peer_assemblies=%u peer_bytes=%llu submissions=%zu retry=%u\n",
            s->app.results, s->peer.requests, s->peer.assemblies,
            (unsigned long long)s->peer.assembled_bytes, s->submissions, s->retry_observed);
    return 0;
}
static void print_phase(FILE *out, const phase_sample *p, int comma)
{
    fprintf(out, "{\"name\":\"%s\",\"status\":\"%s\",\"scope\":\"selected one-device process; peer excluded\",\"caller_owned_requested_current_bytes\":%zu,\"endpoint_bundle_object_requested_bytes\":%zu,\"caller_payload_buffers_requested_bytes\":%zu,\"provider_object_requested_bytes\":%zu,\"handshake_object_requested_bytes\":%zu,\"provider_retained_current_bytes\":%zu,\"provider_retained_peak_bytes\":%zu,\"host_observed_requested_payload_high_water_bytes\":%zu,\"provider_largest_single_allocation_bytes\":%zu,\"provider_scratch_limit_bytes\":%u,\"provider_largest_scratch_observed_bytes\":null,\"endpoint_tx_submissions\":%zu,\"injected_loss_count\":%zu,\"local_request_submissions\":%zu,\"peer_request_notices\":%zu,\"endpoint_request_notices\":%zu,\"endpoint_result_notices\":%zu,\"retry_frame_differs_from_dropped_frame\":%s,\"reliable_request_payload_bytes\":%zu,\"reliable_request_fragment_count\":%zu,\"reliable_request_frame_count\":%zu,\"reliable_result_payload_bytes\":%zu,\"peer_request_payload_bytes\":%zu,\"origin_route_frames\":%zu,\"origin_route_frames_valid\":%zu,\"freshness_grant_request_frames\":%zu,\"freshness_grant_result_payload_bytes\":%zu,\"freshness_grant_verified\":%s,\"freshness_token_bound_to_request\":%s,\"peer_request_payload_matches\":%s,\"reliable_result_wire_status\":%u,\"reliable_result_payload_matches\":%s,\"dropped_request_type\":%u,\"retry_request_type\":%u,\"dropped_request_seq\":%u,\"retry_request_seq\":%u,\"dropped_request_fragment_index\":%u,\"retry_request_fragment_index\":%u,\"dropped_request_pn\":%llu,\"retry_request_pn\":%llu,\"reliable_request_retry_observed\":%s,\"payload_fragment_bytes\":%zu,\"payload_fragment_frames\":%zu,\"peer_assembled_message_count\":%zu,\"peer_assembled_message_bytes\":%zu}%s",
            p->name, p->status, p->caller_owned_requested, p->endpoint_bundle_object_requested,
            p->caller_payload_buffers_requested, p->provider_object_requested, p->handshake_object_requested,
            p->provider_current, p->provider_peak, p->requested_payload_high_water,
            p->provider_largest, DMP_PROVIDER_SCRATCH_MAX, p->tx_submissions, p->injected_losses,
            p->local_request_submissions, p->peer_request_notices,
            p->request_notices, p->result_notices,
            p->retry_frame_distinct ? "true" : "false",
            p->reliable_request_payload_bytes, p->reliable_request_fragment_count,
            p->reliable_request_frame_count, p->reliable_result_payload_bytes,
            p->peer_request_payload_bytes,
            p->origin_route_frames, p->origin_route_frames_valid,
            p->freshness_grant_request_frames, p->freshness_grant_result_payload_bytes,
            p->freshness_grant_verified ? "true" : "false",
            p->freshness_token_bound_to_request ? "true" : "false",
            p->peer_request_payload_matches ? "true" : "false",
            p->reliable_result_wire_status,
            p->reliable_result_payload_matches ? "true" : "false",
            p->dropped_request_type, p->retry_request_type,
            p->dropped_request_seq, p->retry_request_seq,
            p->dropped_request_fragment, p->retry_request_fragment,
            (unsigned long long)p->dropped_request_pn,
            (unsigned long long)p->retry_request_pn,
            p->reliable_request_retry_observed ? "true" : "false",
            p->payload_fragment_bytes, p->payload_fragment_frames,
            p->assembled_message_count, p->assembled_message_bytes,
            comma ? "," : "");
}
static int write_report(const phase_sample phases[6], size_t message, const char profile_digest[65],
                        const reconnect_evidence *reconnect)
{
    size_t i;
    fputs("{\"schema_version\":1,\"ok\":true,\"device_count\":1,\"peer_process_count\":1,\"peer_process_isolated\":true,\"ipc\":\"loopback TCP records carry real NNpsk0 flights and protected libdmp endpoint frames\",\"evidence_class\":\"host-runtime-one-endpoint-process-isolated-peer\",\"reliable_result_payload_bytes\":", report_stream);
    fprintf(report_stream, "%zu,\"message_bytes\":%zu,\"reliable_request_payload_bytes\":%zu,\"endpoint_profile_id\":\"%s\",\"phases\":[", phases[3].reliable_result_payload_bytes, message, message, active_profile.id);
    for (i = 0U; i < 6U; ++i) print_phase(report_stream, &phases[i], i != 5U);
    fprintf(report_stream, "],\"profile_id\":\"%s\",\"profile_digest_sha256\":\"%s\",\"handshake_budget\":{\"profile_mode\":\"NNpsk0\",\"profile_cipher\":%zu,\"max_pending\":%zu,\"max_scratch\":%zu,\"episode_attempts\":%zu,\"episode_deadline_ms\":%zu,\"host_internal_episode_work_unit_ceiling\":100000,\"episode_traffic_bytes\":%zu,\"restart_backoff_ms\":%zu,\"attempt_deadline_ms\":%zu,\"cached_responses\":%zu,\"host_internal_global_work_unit_ceiling\":100000,\"manifest_global_crypto_ms_per_window\":%zu,\"ingress_packets_per_window\":%zu,\"later_episodes\":%zu,\"admit_burst\":%zu,\"admit_window_ms\":%zu,\"provisional_bytes\":%zu,\"replay_window_bits\":%zu,\"failed_aead_limit\":%zu,\"association_lifetime_ms\":%zu,\"confirmation_timeout_ms\":%zu,\"confirmation_attempts\":%zu},\"reconnect\":{\"semantics\":\"endpoint/provider state reset followed by fresh NNpsk0 handshake over the same loopback IPC connection\",\"same_ipc_connection\":true,\"attempt_id_changed\":%s,\"initiator_ephemeral_changed\":%s,\"responder_ephemeral_changed\":%s,\"prior_initiator_traffic_epoch\":%llu,\"new_initiator_traffic_epoch\":%llu,\"prior_responder_traffic_epoch\":%llu,\"new_responder_traffic_epoch\":%llu,\"prior_frame_source\":\"first actual protected DMP_TYPE_DATA frame from initial association\",\"old_data_frame_seen_by_original_peer\":%s,\"prior_protected_frame_status\":%u,\"prior_protected_frame_status_name\":\"DMP_AUTHENTICATION_FAILURE\",\"prior_frame_rejected_without_dispatch\":%s,\"requests_before\":%u,\"requests_after\":%u,\"data_notices_before\":%u,\"data_notices_after\":%u,\"assemblies_before\":%u,\"assemblies_after\":%u},\"accounting\":{\"provider_allocator_payload_only\":true,\"malloc_metadata_and_alignment\":\"unknown\",\"scratch_limit_is_per_allocation_ceiling\":true,\"scratch_not_added_to_physical_total\":true,\"peer_memory_included\":false,\"host_abi_size_and_target_runtime_separate\":true,\"physical_mcu_peak\":\"not_measured\"},\"host_abi\":{\"endpoint_bytes\":",
            active_profile.id,
            profile_digest,
            active_profile.hs_cipher,
            active_profile.hs_max_pending, active_profile.hs_max_scratch,
            active_profile.hs_episode_attempts, active_profile.hs_episode_ms,
            active_profile.hs_episode_traffic, active_profile.hs_restart_backoff_ms,
            active_profile.hs_attempt_ms, active_profile.hs_cached_responses,
            active_profile.hs_global_crypto_ms,
            active_profile.hs_ingress_packets, active_profile.hs_later_episodes,
            active_profile.hs_ingress_packets, active_profile.hs_ingress_window_ms,
            active_profile.hs_provisional_bytes, active_profile.hs_replay_bits,
            active_profile.hs_failed_aead, active_profile.hs_association_ms,
            active_profile.hs_confirmation_timeout_ms, active_profile.hs_confirmation_attempts,
            reconnect->attempt_id_changed ? "true" : "false",
            reconnect->initiator_ephemeral_changed ? "true" : "false",
            reconnect->responder_ephemeral_changed ? "true" : "false",
            (unsigned long long)reconnect->prior_epoch, (unsigned long long)reconnect->current_epoch,
            (unsigned long long)reconnect->prior_peer_epoch,
            (unsigned long long)reconnect->current_peer_epoch,
            reconnect->old_data_frame_seen_by_original_peer ? "true" : "false",
            reconnect->stale_status,
            reconnect->stale_status == DMP_AUTHENTICATION_FAILURE &&
                reconnect->requests_before == reconnect->requests_after &&
                reconnect->data_before == reconnect->data_after &&
                reconnect->assemblies_before == reconnect->assemblies_after ? "true" : "false",
            reconnect->requests_before, reconnect->requests_after,
            reconnect->data_before, reconnect->data_after,
            reconnect->assemblies_before, reconnect->assemblies_after);
    fprintf(report_stream, "%zu,\"provider_bytes\":%zu,\"handshake_bytes\":%zu},\"unknowns\":[\"provider scratch allocations cannot be distinguished from retained allocations by the current provider port callbacks\",\"host task stack high-water by phase\",\"MCU allocator metadata and alignment\",\"physical MCU retained peak and stack high-water\",\"RTOS and static backend data\"]}\n", sizeof(dmp_endpoint), dmp_provider_size(), dmp_hs_size());
    return ferror(report_stream) == 0;
}
static int parent_run(const char *exe, const char *manifest, size_t message, size_t request_size,
                      size_t chunk_bytes,
                      const noise_fixture_probe_fixture_t *f, const uint8_t profile_digest[32],
                      const char profile_digest_hex[65])
{
    side target; phase_sample phases[6] = {
        {.name="initial",.status="measured"}, {.name="handshake_peak",.status="measured"},
        {.name="active_steady",.status="measured"}, {.name="request_result_retry",.status="measured"},
        {.name="cleanup",.status="measured"}, {.name="reconnect",.status="measured"}};
    socket_t connection = BAD_SOCKET;
#ifdef _WIN32
    PROCESS_INFORMATION process;
#else
    pid_t process;
#endif
    dmp_reliability_handle handle, data_handle; uint8_t request[1024]; size_t i, request_frames;
    static const uint8_t old_data_payload[1] = {0x6dU};
    const dmp_bytes no_token = {NULL, 0U};
    uint8_t old_attempt_id[64], old_init_ephemeral[64], old_frame[FRAME_CAP];
    size_t old_attempt_id_size, old_init_ephemeral_size, old_frame_size;
    uint64_t old_epoch;
    uint32_t next_generation = 2U;
    reconnect_evidence reconnect;
    peer_status stale;
    memset(&reconnect, 0, sizeof reconnect);
    memset(&stale, 0, sizeof stale);
    if (!connect_peer_process(exe, manifest, &connection, &process)) { fputs("RAM process probe: peer launch/connect failed\n", stderr); return 0; }
    if (!setup_side(&target, message, 1, 1U, f, profile_digest)) { fputs("RAM process probe: measured side setup failed\n", stderr); return 0; }
    target.socket = connection; target.drop_first = 0U;
    capture(&phases[0], &target);
    if (!parent_handshake(&target, f)) { fputs("RAM process probe: initial NNpsk0 handshake failed\n", stderr); return 0; }
#ifdef _WIN32
    if (WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0) { DWORD exit_code = 0U; (void)GetExitCodeProcess(process.hProcess, &exit_code); fprintf(stderr,"peer exited immediately after handshake: code=%lu\n",(unsigned long)exit_code); return 0; }
#endif
    capture(&phases[1], &target);
    if (dmp_endpoint_poll(&target.bundle->endpoint, target.now) != DMP_OK) { fputs("RAM process probe: active endpoint poll failed\n", stderr); return 0; }
    capture(&phases[2], &target);
    if (active_profile.freshness_required_mask != 0U && !request_freshness_grant(&target)) {
        fputs("RAM process probe: protected S7 freshness grant transaction failed\n", stderr);
        return 0;
    }
    for (i = 0U; i < request_size; ++i) request[i] = (uint8_t)(i ^ 0x5aU);
    target.submissions = 0U; target.retry_distinct = 0U; target.retry_observed = 0U; target.dropped = 0U;
    target.drop_first = 1U;
    {
        dmp_status submit_status;
        if (active_profile.freshness_required_mask != 0U) {
            submit_status = dmp_endpoint_submit_req_fresh(&target.bundle->endpoint, 2U,
                (dmp_bytes){request,request_size},
                (dmp_bytes){target.app.freshness_token, sizeof target.app.freshness_token},
                target.now, &handle);
            target.freshness_token_bound_to_request = submit_status == DMP_OK;
            memset(target.app.freshness_token, 0, sizeof target.app.freshness_token);
        } else {
            submit_status = dmp_endpoint_submit_req(&target.bundle->endpoint, 2U,
                (dmp_bytes){request,request_size}, target.now, &handle);
        }
        if (submit_status != DMP_OK || dmp_endpoint_poll(&target.bundle->endpoint, target.now) != DMP_OK ||
            !target.dropped) { fputs("RAM process probe: request submit/initial injected loss failed\n", stderr); return 0; }
    }
    target.local_requests = 1U;
    target.now += active_profile.response_timeout_ms; target.hsctx.now = target.now;
    if (!pump_exchange(&target) || !target.retry_observed || !target.retry_distinct ||
        !target.dropped_request_key_valid || target.retry_request_pn == target.dropped_request_pn ||
        target.submissions < 2U || target.app.results != 1 || target.local_requests != 1U ||
        target.peer.requests != 1U || target.peer.request_payload_bytes != request_size ||
        target.peer.request_service_id != active_profile.service_ids[1] ||
        !target.peer.request_payload_matches || target.app.result_payload_bytes != active_profile.result_bytes ||
        target.app.result_service_id != active_profile.service_ids[1] ||
        target.app.result_wire_status != 0U || !target.app.result_payload_matches) {
        fputs("RAM process probe: exact reliable request/result and fresh-PN retry exchange failed\n", stderr);
        return 0;
    }
    request_frames = request_size <= 128U ? 1U : (request_size + chunk_bytes - 1U) / chunk_bytes;
    if (request_size <= 128U) {
        if (target.peer.assemblies != 0U || target.peer.assembled_bytes != 0U || request_frames != 1U) {
            fputs("RAM process probe: small request was not delivered as one unfragmented frame\n", stderr);
            return 0;
        }
    } else if (target.peer.assemblies != 1U || target.peer.assembled_bytes != request_size) {
        fputs("RAM process probe: large request assembly did not match the manifest payload\n", stderr);
        return 0;
    }
    target.drop_first = 0U;
    phases[3].reliable_request_payload_bytes = request_size;
    phases[3].reliable_request_fragment_count = target.peer.assemblies != 0U ? request_frames : 0U;
    phases[3].reliable_request_frame_count = request_frames;
    phases[3].reliable_request_retry_observed = target.retry_observed != 0U;
    phases[3].reliable_result_payload_bytes = target.app.result_payload_bytes;
    phases[3].reliable_result_wire_status = target.app.result_wire_status;
    phases[3].reliable_result_payload_matches = target.app.result_payload_matches;
    phases[3].peer_request_payload_bytes = (size_t)target.peer.request_payload_bytes;
    phases[3].freshness_grant_request_frames = target.freshness_grant_request_frames;
    phases[3].freshness_grant_result_payload_bytes = target.app.freshness_grant_payload_bytes;
    phases[3].freshness_grant_verified = target.app.freshness_grant_valid &&
        target.app.freshness_grants == 1;
    phases[3].freshness_token_bound_to_request = target.freshness_token_bound_to_request;
    phases[3].peer_request_payload_matches = target.peer.request_payload_matches != 0U;
    phases[3].payload_fragment_bytes = target.peer.assemblies != 0U ? request_size : 0U;
    phases[3].payload_fragment_frames = target.peer.assemblies != 0U ? request_frames : 0U;
    phases[3].assembled_message_count = target.peer.assemblies;
    phases[3].assembled_message_bytes = (size_t)target.peer.assembled_bytes;
    capture(&phases[3], &target);
    target.drop_first = 0U;
    if (dmp_endpoint_poll(&target.bundle->endpoint, target.now) != DMP_OK) return 0;
    target.capture_protected_data = 1U; target.protected_data_captured = 0U;
    {
        dmp_bytes data_token = no_token;
        dmp_status data_status;
        if (active_profile.freshness_required_mask != 0U) {
            if (!request_freshness_grant(&target)) {
                fputs("RAM process probe: DATA freshness grant transaction failed\n", stderr);
                return 0;
            }
            data_token.data = target.app.freshness_token;
            data_token.size = sizeof target.app.freshness_token;
        }
        data_status = dmp_endpoint_submit_data(&target.bundle->endpoint, 2U,
            (dmp_bytes){old_data_payload, sizeof old_data_payload}, data_token,
            target.now, &data_handle);
        memset(target.app.freshness_token, 0, sizeof target.app.freshness_token);
        if (data_status != DMP_OK || dmp_endpoint_poll(&target.bundle->endpoint, target.now) != DMP_OK ||
            !target.protected_data_captured ||
            !parent_tick(&target, target.now) || target.peer.data_notices != 1U) {
            fputs("RAM process probe: old-association protected DATA capture failed\n", stderr);
            return 0;
        }
        {
            logical_frame_key captured_key;
            if (!frame_key_from_stream(target.protected_data_frame,
                                       target.protected_data_frame_size,
                                       target.now, &captured_key) ||
                captured_key.type != DMP_TYPE_DATA) {
                fputs("RAM process probe: reconnect evidence did not capture a DMP_TYPE_DATA frame\n",
                      stderr);
                return 0;
            }
        }
    }
    target.capture_protected_data = 0U;
    reconnect.old_data_frame_seen_by_original_peer = target.peer.data_notices == 1U;
    old_epoch = target.association_epoch;
    reconnect.prior_peer_epoch = target.peer.association_epoch;
    old_attempt_id_size = target.hsctx.entropy.sizes[0];
    old_init_ephemeral_size = target.hsctx.entropy.sizes[1];
    old_frame_size = target.protected_data_frame_size;
    if (old_attempt_id_size > sizeof old_attempt_id || old_init_ephemeral_size > sizeof old_init_ephemeral ||
        old_frame_size == 0U || old_frame_size > sizeof old_frame) return 0;
    memcpy(old_attempt_id, target.hsctx.entropy.owned[0], old_attempt_id_size);
    memcpy(old_init_ephemeral, target.hsctx.entropy.owned[1], old_init_ephemeral_size);
    memcpy(old_frame, target.protected_data_frame, old_frame_size);
    if (!send_record(connection, REC_RESTART, &next_generation, sizeof next_generation)) return 0;
    { uint8_t kind, buf[IPC_LIMIT]; size_t n;
      if (!recv_record(connection, &kind, buf, sizeof buf, &n) || kind != REC_DONE || n != 0U) return 0; }
    phases[4].provider_peak = target.allocations.peak;
    phases[4].provider_largest = target.allocations.largest;
    phases[4].requested_payload_high_water = phases[3].requested_payload_high_water;
    close_side(&target);
    phases[4].caller_owned_requested = 0U;
    if (!setup_side(&target, message, 1, next_generation, f, profile_digest)) return 0;
    reconnect.prior_epoch = old_epoch;
    reconnect.attempt_id_changed = old_attempt_id_size == target.hsctx.entropy.sizes[0] &&
        memcmp(old_attempt_id, target.hsctx.entropy.owned[0], old_attempt_id_size) != 0;
    reconnect.initiator_ephemeral_changed = old_init_ephemeral_size == target.hsctx.entropy.sizes[1] &&
        memcmp(old_init_ephemeral, target.hsctx.entropy.owned[1], old_init_ephemeral_size) != 0;
    target.socket = connection;
    if (!parent_handshake(&target, f)) return 0;
    reconnect.current_epoch = target.association_epoch;
    if (!reconnect.attempt_id_changed || !reconnect.initiator_ephemeral_changed ||
        reconnect.current_epoch == 0U || reconnect.current_epoch == reconnect.prior_epoch) {
        fputs("RAM process probe: reconnect did not change initiator entropy and association epoch\n", stderr);
        return 0;
    }
    if (!send_record(connection, REC_STALE_DATA, old_frame, old_frame_size)) return 0;
    { uint8_t kind, buf[IPC_LIMIT]; size_t n;
      if (!recv_record(connection, &kind, buf, sizeof buf, &n) || kind != REC_STALE_RESULT || n != sizeof stale) return 0;
      memcpy(&stale, buf, sizeof stale); }
    reconnect.stale_status = stale.stale_status;
    reconnect.current_peer_epoch = stale.association_epoch;
    reconnect.requests_before = stale.stale_requests_before;
    reconnect.requests_after = stale.stale_requests_after;
    reconnect.data_before = stale.stale_data_before;
    reconnect.data_after = stale.stale_data_after;
    reconnect.assemblies_before = stale.stale_assemblies_before;
    reconnect.assemblies_after = stale.stale_assemblies_after;
    reconnect.responder_ephemeral_changed = stale.responder_ephemeral_changed;
    if (stale.prior_epoch != reconnect.prior_peer_epoch ||
        stale.association_epoch != reconnect.current_peer_epoch ||
        reconnect.current_peer_epoch == 0U ||
        reconnect.current_peer_epoch == reconnect.prior_peer_epoch ||
        !reconnect.responder_ephemeral_changed || reconnect.stale_status != DMP_AUTHENTICATION_FAILURE ||
        reconnect.requests_before != reconnect.requests_after ||
        reconnect.data_before != reconnect.data_after ||
        reconnect.assemblies_before != reconnect.assemblies_after) {
        fputs("RAM process probe: stale protected frame was not rejected cleanly after fresh handshake\n", stderr);
        return 0;
    }
    capture(&phases[5], &target);
    if (!send_record(connection, REC_QUIT, NULL, 0U)) return 0;
    { uint8_t kind, buf[IPC_LIMIT]; size_t n;
      if (!recv_record(connection, &kind, buf, sizeof buf, &n) || kind != REC_DONE || n != 0U) {
          fputs("RAM process probe: peer did not acknowledge clean shutdown\n", stderr);
          return 0;
      } }
    close_side(&target); CLOSE_SOCKET(connection);
#ifdef _WIN32
    if (!peer_process_succeeded(&process)) {
        fputs("RAM process probe: peer did not exit successfully after cleanup\n", stderr);
        return 0;
    }
#else
    if (!peer_process_succeeded(process)) {
        fputs("RAM process probe: peer did not exit successfully after cleanup\n", stderr);
        return 0;
    }
#endif
    return write_report(phases, message, profile_digest_hex, &reconnect);
}
static int peer_connect_port(uint16_t port, socket_t *out)
{
    socket_t fd = BAD_SOCKET; int tries;
    for (tries = 0; tries < 100 && fd == BAD_SOCKET; ++tries) {
        fd = connect_loopback(port);
        if (fd == BAD_SOCKET) {
#ifdef _WIN32
            Sleep(20);
#else
            { const struct timespec delay = {0, 20000000L}; (void)nanosleep(&delay, NULL); }
#endif
        }
    }
    *out = fd; return fd != BAD_SOCKET;
}
int main(int argc, char **argv)
{
    const noise_fixture_probe_fixture_t *f = fixture_find();
    size_t message = 0U, request = 0U, chunk = 0U;
    uint8_t profile_digest[32]; char profile_digest_hex[65];
    int i; const char *manifest = NULL, *report_path = NULL;
    report_stream = stdout;
    if (f == NULL) return 2;
#ifdef _WIN32
    { WSADATA data; if (WSAStartup(MAKEWORD(2,2), &data) != 0) return 2; }
#else
    (void)signal(SIGPIPE, SIG_IGN);
#endif
    if (argc >= 2 && strcmp(argv[1], "--peer") == 0) {
        uint16_t port = (uint16_t)strtoul(argv[2], NULL, 10); side peer;
        for (i = 3; i + 1 < argc; ++i) if (strcmp(argv[i], "--manifest") == 0) manifest = argv[i+1];
        if (manifest == NULL || !validate_manifest_digest(manifest, profile_digest, profile_digest_hex)) { fputs("peer manifest digest failed\n", stderr); return 2; }
        if (!manifest_parameters(manifest, &request)) { fputs("peer manifest parameters failed\n", stderr); return 2; }
        message = active_profile.message_bytes; chunk = active_profile.chunk_bytes;
        if (!setup_side(&peer, message, 0, 1U, f, profile_digest)) { fputs("peer endpoint setup failed\n", stderr); return 2; }
        if (!peer_connect_port(port, &peer.socket)) { fputs("peer IPC connect failed\n", stderr); close_side(&peer); return 2; }
        i = peer_main_loop(&peer, message, f, profile_digest); close_side(&peer); CLOSE_SOCKET(peer.socket);
#ifdef _WIN32
        WSACleanup();
#endif
        return i ? 0 : 1;
    }
    if (argc < 3 || strcmp(argv[1], "--manifest") != 0) {
        fputs("usage: dmp_ram_endpoint_process --manifest <supported-direct-profile.json> [--output report.json]\n", stderr); return 2;
    }
    for (i = 3; i + 1 < argc; ++i) if (strcmp(argv[i], "--output") == 0) report_path = argv[i+1];
    if (!validate_manifest_digest(argv[2], profile_digest, profile_digest_hex) ||
        !manifest_parameters(argv[2], &request) ||
        (message = active_profile.message_bytes) == 0U || (chunk = active_profile.chunk_bytes) == 0U) {
        fputs("RAM process probe: unsupported or invalid manifest\n", stderr); return 2;
    }
    if (report_path != NULL && (report_stream = fopen(report_path, "wb")) == NULL) {
        fprintf(stderr, "RAM process probe: cannot open report output %s\n", report_path); return 2;
    }
    i = parent_run(argv[0], argv[2], message, request, chunk, f, profile_digest, profile_digest_hex);
    if (report_stream != stdout) { if (fclose(report_stream) != 0) i = 0; report_stream = stdout; }
#ifdef _WIN32
    WSACleanup();
#endif
    return i ? 0 : 1;
}
