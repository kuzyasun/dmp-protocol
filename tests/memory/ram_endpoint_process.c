/* Process-isolated host lifecycle probe for one measured libdmp endpoint. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "dmp/endpoint.h"
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

enum { MSG_MAX = 256, MTU = 263, STREAM_CAP = 512, SENDERS = 1, RESULTS = 1,
       HISTORY = 2, CORRELATIONS = 1, ADAPTERS = 3, TOMBSTONES = 16,
       FRAME_CAP = 600, ID_INIT = 10, ID_RESP = 20,
       CID_INIT = 7, CID_RESP = 9, NAMESPACE = 1, IPC_LIMIT = 4096 };
enum { REC_HANDSHAKE = 'H', REC_DATA = 'X', REC_TICK = 'T', REC_DONE = 'D',
       REC_RESTART = 'R', REC_QUIT = 'Q', REC_ERROR = 'E', REC_STALE_DATA = 'S',
       REC_STALE_RESULT = 'V' };

typedef struct allocation_stats {
    size_t live, peak, largest;
} allocation_stats;
typedef struct peer_status {
    uint32_t requests, results, data_notices, assemblies;
    uint64_t assembled_bytes, association_epoch, prior_epoch;
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
    dmp_identity_slot identities[1];
    dmp_reliability_sender_slot senders[SENDERS];
    uint8_t *sender_payload;
    dmp_reliability_result_slot results[RESULTS];
    uint8_t *result_payload;
    dmp_reliability_history_slot history[HISTORY];
    dmp_reliability_correlation_slot correlations[CORRELATIONS];
    uint8_t history_metadata[HISTORY * DMP_RELIABILITY_METADATA_BYTES];
    uint8_t correlation_metadata[CORRELATIONS * DMP_RELIABILITY_METADATA_BYTES];
    dmp_reliability_adapter_slot adapters[ADAPTERS];
    uint8_t frames[ADAPTERS * MTU];
    uint8_t *receive_payload;
    dmp_reassembly_slot assemblies[1];
    dmp_reassembly_tombstone tombstones[TOMBSTONES];
    uint8_t *assembly_payload;
    uint8_t assembly_metadata[DMP_REASSEMBLY_METADATA_BYTES];
    uint8_t *fragment_message;
    uint8_t fragment_frame[MTU];
    uint8_t *telemetry_payload;
    uint8_t *telemetry_next;
    uint8_t telemetry_frame[MTU];
    uint8_t stream_tx[STREAM_CAP];
    uint8_t stream_rx[STREAM_CAP];
    size_t message_bytes;
} endpoint_bundle;
typedef struct entropy_script {
    const uint8_t *parts[2];
    size_t sizes[2], count, index;
    uint8_t owned[3][64];
} entropy_script;
typedef struct hs_context { uint64_t now; entropy_script entropy; } hs_context;
typedef struct app_state {
    int have_request, requests, results, data_notices;
    int assemblies;
    size_t assembled_bytes;
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
    uint8_t responder_ephemeral_changed;
    uint8_t capture_protected_data, protected_data_captured;
    uint32_t generation;
    size_t submissions;
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
        return "316055bb668eb15d75ff9b90912d715d757faf047e8686d88df433d455c82c01";
    if (strcmp(basename, "test-direct-minimal-256.json") == 0)
        return "94f6bccc8bd9b4d52a695de1a1131f426331802c5838f56baffce0566ec13866";
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
    entropy_script *s = &((hs_context *)ctx)->entropy;
    if (s == NULL || s->index >= s->count || s->sizes[s->index] != size) { memset(out, 0, size); return 1; }
    memcpy(out, s->parts[s->index], size); ++s->index; return 0;
}
static uint64_t hs_now(void *ctx) { return ((hs_context *)ctx)->now; }
static int commit_pin(void *ctx, const dmp_hs_pin_record *record) { (void)ctx; (void)record; return 0; }
static void on_notice(void *ctx, const dmp_endpoint_notice *notice)
{
    side *s = (side *)ctx;
    if (notice->event == DMP_ENDPOINT_REQUEST) { s->app.have_request = 1; s->app.request = notice->request; ++s->app.requests; }
    if (notice->event == DMP_ENDPOINT_RESULT) ++s->app.results;
    if (notice->event == DMP_ENDPOINT_DATA) ++s->app.data_notices;
    if (notice->event == DMP_ENDPOINT_ASSEMBLED) { ++s->app.assemblies; s->app.assembled_bytes = notice->payload.size; }
}
static int send_record(socket_t fd, uint8_t kind, const void *data, size_t size);

/* Local provider port queues owned copies; one client submission is deliberately
 * completed as transmitted and discarded to exercise libdmp's actual retry timer. */
static dmp_status tx_submit(void *ctx, const dmp_tx_submission *submission)
{
    side *s = (side *)ctx;
    if (s == NULL || submission == NULL || submission->frame.data == NULL || submission->frame.size > FRAME_CAP || submission->complete == NULL) return DMP_INVALID_ARGUMENT;
    ++s->submissions;
    if (s->drop_first && !s->dropped) { s->dropped = 1U; s->retry_after = s->now + 1280U; s->first_drop_size = submission->frame.size; memcpy(s->first_drop, submission->frame.data, submission->frame.size); submission->complete(submission->owner, submission->token, DMP_TX_TRANSMITTED, s->now); return DMP_OK; }
    if (s->drop_first && s->dropped && !s->retry_observed && s->now >= s->retry_after) {
        s->retry_observed = 1U;
        s->retry_distinct = submission->frame.size != s->first_drop_size ||
                            memcmp(submission->frame.data, s->first_drop, submission->frame.size) != 0;
    }
    if (s->capture_protected_data && !s->protected_data_captured) {
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
    b->max_pending = 1U; b->max_scratch = 1U;
    b->episode_attempts = 2U; b->episode_deadline_ms = 41000U; b->episode_work = 100000U;
    b->episode_traffic = 16384U; b->restart_backoff_ms = 1000U; b->attempt_deadline_ms = 20000U;
    b->cached_responses = 1U; b->global_work = 100000U; b->ingress_work = 100U;
    b->later_episodes = 2U; b->admit_burst = 100U; b->admit_window_ms = 1000U;
    b->provisional_bytes = 120U; b->replay_window = 1024U;
    b->failed_aead_limit = 1000U; b->association_lifetime_ms = 100000000U;
    b->confirmation_timeout_ms = 512U; b->confirmation_attempts = 2U;
}
static void fill_config(dmp_config *c, size_t message, const uint8_t profile_digest[32])
{
    memset(c, 0, sizeof *c); memcpy(c->sha256, profile_digest, sizeof c->sha256);
    c->namespace_id = NAMESPACE; c->node_id[0] = ID_INIT; c->node_id[1] = ID_RESP;
    c->default_service = 1U; c->service_id[0] = 1U; c->service_id[1] = 2U;
    c->recovery[0] = c->recovery[1] = DMP_PROFILE_RECOVERY_RETRY_ALL;
    c->peers = 1U; c->operations_per_service = 1U; c->assemblies_per_peer = 1U;
    c->assembly_tombstones_per_peer = TOMBSTONES; c->sender_slots = SENDERS;
    c->assembly_slots = 1U; c->assembly_tombstone_slots = TOMBSTONES;
    c->result_slots = RESULTS; c->history_slots = HISTORY; c->correlation_slots = CORRELATIONS;
    c->adapter_slots = ADAPTERS; c->application_queue_slots = 1U; c->control_slots = 2U;
    c->message_bytes = (uint32_t)message; c->fragments = (uint32_t)(message / 64U); c->chunk_bytes = 64U;
    c->encoded_mtu = MTU; c->forward_mtu = c->return_mtu = 256U;
    c->queue_ms = 64U; c->response_timeout_ms = 1280U; c->send_horizon_ms = 5632U; c->max_bursts = 3U;
    c->receipt_delay_ms = 110U; c->receipt_limit = 3U; c->dedup_ms = c->rejection_ms = c->result_cache_ms = 6000U;
    c->result_deadline_ms = 12000U; c->correlation_ms = c->tombstone_ms = 12288U;
    c->late_result_ms = 64U; c->collect_ms = 5652U; c->assembly_ms = 5657U;
    c->tx_borrow = true; c->synchronous_completion = true;
}
static void fill_hs_config(dmp_hs_config *c, side *s, const noise_fixture_probe_fixture_t *f,
                           const uint8_t profile_digest[32])
{
    memset(c, 0, sizeof *c); fill_budget(&c->budget);
    c->namespace_id = NAMESPACE; c->local_id = s->initiator ? ID_INIT : ID_RESP;
    c->peer_id = s->initiator ? ID_RESP : ID_INIT; memcpy(c->profile_hash, profile_digest, sizeof c->profile_hash);
    c->mode = 1U; c->cipher = 1U; c->key_hint = 5U; c->permissions = 2U;
    c->next_rx_cid = (s->initiator ? CID_INIT : CID_RESP) + 2U * (s->generation - 1U);
    memcpy(c->psk, f->psk.data, 32U); c->has_psk = 1;
}
static int manifest_message_size(const char *path, size_t *message, size_t *request, size_t *chunk)
{
    FILE *f = fopen(path, "rb"); char buf[65536]; size_t n; char *p, *service, *limits;
    if (f == NULL) return 0;
    n = fread(buf, 1U, sizeof buf - 1U, f); fclose(f); buf[n] = '\0';
    p = strstr(buf, "\"message_bytes\""); if (p == NULL || (p = strchr(p, ':')) == NULL) return 0;
    *message = (size_t)strtoul(p + 1, NULL, 10);
    service = strstr(buf, "\"id\": 2"); if (service == NULL) return 0;
    p = strstr(service, "\"request_bytes\""); if (p == NULL || (p = strchr(p, ':')) == NULL) return 0;
    *request = (size_t)strtoul(p + 1, NULL, 10);
    limits = strstr(buf, "\"limits\""); if (limits == NULL) return 0;
    p = strstr(limits, "\"chunk_bytes\""); if (p == NULL || (p = strchr(p, ':')) == NULL) return 0;
    *chunk = (size_t)strtoul(p + 1, NULL, 10);
    return (*message == 128U || *message == 256U) && *request == *message && *chunk == 64U;
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
    dmp_config c; dmp_endpoint_storage st; dmp_identity_context_config identity; dmp_endpoint_grant grants[4];
    endpoint_bundle *b = (endpoint_bundle *)calloc(1U, sizeof *b);
    if (b == NULL) return 0;
    b->message_bytes = message;
    b->sender_payload = (uint8_t *)calloc(message, 1U);
    b->result_payload = (uint8_t *)calloc(message, 1U);
    b->receive_payload = (uint8_t *)calloc(message, 1U);
    b->assembly_payload = (uint8_t *)calloc(message, 1U);
    b->fragment_message = (uint8_t *)calloc(message, 1U);
    b->telemetry_payload = (uint8_t *)calloc(message, 1U);
    b->telemetry_next = (uint8_t *)calloc(message, 1U);
    if (b->sender_payload == NULL || b->result_payload == NULL || b->receive_payload == NULL ||
        b->assembly_payload == NULL || b->fragment_message == NULL || b->telemetry_payload == NULL ||
        b->telemetry_next == NULL) { free(b->sender_payload); free(b->result_payload); free(b->receive_payload); free(b->assembly_payload); free(b->fragment_message); free(b->telemetry_payload); free(b->telemetry_next); free(b); return 0; }
    fill_config(&c, message, profile_digest);
    if (dmp_config_admit(&c, &b->admitted) != DMP_OK) { free(b->sender_payload); free(b->result_payload); free(b->receive_payload); free(b->assembly_payload); free(b->fragment_message); free(b->telemetry_payload); free(b->telemetry_next); free(b); return 0; }
    memset(&identity, 0, sizeof identity); identity.local.namespace_id = identity.peer.namespace_id = NAMESPACE;
    identity.local.origin_id = s->initiator ? ID_INIT : ID_RESP; identity.peer.origin_id = s->initiator ? ID_RESP : ID_INIT; identity.security = 1U;
    b->transport.context = s; b->transport.submit = tx_submit; b->transport.cancel = tx_cancel;
    b->transport.caps.max_frame_bytes = STREAM_CAP; b->transport.caps.ownership = DMP_TX_BORROW; b->transport.caps.synchronous_completion = true;
    memset(&st, 0, sizeof st); st.profile = &b->admitted; st.identity_slots = b->identities; st.identity_capacity = 1U; st.context = identity;
    st.transport = &b->transport; st.notice = on_notice; st.notice_user = s;
    st.senders = b->senders; st.sender_capacity = SENDERS; st.sender_payload = b->sender_payload; st.sender_payload_capacity = message;
    st.results = b->results; st.result_capacity = RESULTS; st.result_payload = b->result_payload; st.result_payload_capacity = message;
    st.history = b->history; st.history_capacity = HISTORY; st.correlations = b->correlations; st.correlation_capacity = CORRELATIONS;
    st.history_metadata = b->history_metadata; st.history_metadata_capacity = sizeof b->history_metadata;
    st.correlation_metadata = b->correlation_metadata; st.correlation_metadata_capacity = sizeof b->correlation_metadata;
    st.adapters = b->adapters; st.adapter_capacity = ADAPTERS; st.frames = b->frames; st.frame_capacity = sizeof b->frames;
    st.receive_payload = b->receive_payload; st.receive_payload_capacity = message;
    st.assemblies = b->assemblies; st.assembly_capacity = 1U; st.tombstones = b->tombstones; st.tombstone_capacity = TOMBSTONES;
    st.assembly_payload = b->assembly_payload; st.assembly_payload_capacity = message;
    st.assembly_metadata = b->assembly_metadata; st.assembly_metadata_capacity = sizeof b->assembly_metadata;
    st.fragment_message = b->fragment_message; st.fragment_message_capacity = message;
    st.fragment_frame = b->fragment_frame; st.fragment_frame_capacity = sizeof b->fragment_frame;
    st.telemetry_payload = b->telemetry_payload; st.telemetry_payload_capacity = message;
    st.telemetry_next = b->telemetry_next; st.telemetry_next_capacity = message;
    st.telemetry_frame = b->telemetry_frame; st.telemetry_frame_capacity = sizeof b->telemetry_frame;
    st.stream_tx = b->stream_tx; st.stream_tx_capacity = sizeof b->stream_tx; st.stream_rx = b->stream_rx; st.stream_rx_capacity = sizeof b->stream_rx;
    if (dmp_endpoint_init(&b->endpoint, &st, s->now) != DMP_OK) { free(b->sender_payload); free(b->result_payload); free(b->receive_payload); free(b->assembly_payload); free(b->fragment_message); free(b->telemetry_payload); free(b->telemetry_next); free(b); return 0; }
    memset(grants, 0, sizeof grants);
    grants[0].principal = ID_INIT; grants[0].service_id = 1U; grants[0].permit = DMP_ENDPOINT_PERMIT_TELEM | DMP_ENDPOINT_PERMIT_RESULT;
    grants[1].principal = ID_RESP; grants[1].service_id = 1U; grants[1].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[2].principal = ID_INIT; grants[2].service_id = 2U; grants[2].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    grants[3].principal = ID_RESP; grants[3].service_id = 2U; grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    if (dmp_endpoint_set_grants(&b->endpoint, grants, 4U) != DMP_OK) { free(b->sender_payload); free(b->result_payload); free(b->receive_payload); free(b->assembly_payload); free(b->fragment_message); free(b->telemetry_payload); free(b->telemetry_next); free(b); return 0; }
    s->bundle = b; return 1;
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
    if (s->bundle != NULL) { free(s->bundle->sender_payload); free(s->bundle->result_payload); free(s->bundle->receive_payload); free(s->bundle->assembly_payload); free(s->bundle->fragment_message); free(s->bundle->telemetry_payload); free(s->bundle->telemetry_next); free(s->bundle); }
    memset(s, 0, sizeof *s);
}
static size_t caller_owned_requested(const side *s)
{ return (s->bundle != NULL ? sizeof *s->bundle + 7U * s->bundle->message_bytes : 0U) + (s->provider != NULL ? dmp_provider_size() : 0U) + (s->handshake != NULL ? dmp_hs_size() : 0U); }
static void capture(phase_sample *p, const side *s)
{
    if (s->provider == NULL || s->allocations.live != dmp_provider_retained(s->provider)) {
        fputs("provider allocator high-water tracker disagrees with provider\n", stderr);
        abort();
    }
    p->caller_owned_requested = caller_owned_requested(s);
    p->endpoint_bundle_object_requested = s->bundle != NULL ? sizeof *s->bundle : 0U;
    p->caller_payload_buffers_requested = s->bundle != NULL ? 7U * s->bundle->message_bytes : 0U;
    p->provider_object_requested = s->provider != NULL ? dmp_provider_size() : 0U;
    p->handshake_object_requested = s->handshake != NULL ? dmp_hs_size() : 0U;
    p->provider_current = s->allocations.live; p->provider_peak = s->allocations.peak;
    p->provider_largest = s->allocations.largest;
    p->tx_submissions = s->submissions; p->injected_losses = s->dropped;
    p->request_notices = (size_t)s->app.requests; p->result_notices = (size_t)s->app.results;
    p->local_request_submissions = s->local_requests;
    p->retry_frame_distinct = s->retry_distinct;
    p->requested_payload_high_water = p->caller_owned_requested + p->provider_peak;
    p->peer_request_notices = s->peer.requests;
}
static int hs_offer(dmp_hs *hs, const uint8_t *p, size_t n, uint32_t origin, uint32_t dest, uint64_t epoch, uint32_t seq, dmp_hs_status expected)
{
    dmp_hs_ingress in; dmp_hs_completion done; dmp_hs_status st;
    memset(&in, 0, sizeof in); in.payload = p; in.payload_len = n; in.origin_id = origin; in.destination_id = dest; in.namespace_id = NAMESPACE; in.context_epoch = epoch; in.seq = seq;
    st = dmp_hs_offer(hs, &in, &done); if (st == DMP_HS_AWAITING) st = dmp_hs_accept(hs, &done); return st == expected;
}
static int hs_protected(dmp_hs *hs, const uint8_t *p, size_t n, uint32_t origin, uint32_t dest, uint64_t epoch)
{
    dmp_hs_protected in; memset(&in, 0, sizeof in); in.frame = p; in.frame_len = n; in.origin_id = origin; in.destination_id = dest; in.namespace_id = NAMESPACE; in.context_epoch = epoch; return dmp_hs_offer_protected(hs, &in) == DMP_HS_OK;
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
    if (!recv_record(s->socket, &type, buf, sizeof buf, &n) || type != REC_HANDSHAKE || !hs_offer(s->handshake, buf, n, ID_RESP, ID_INIT, epoch, 2U, DMP_HS_CANDIDATE)) return 0;
    if (!dmp_hs_epochs(s->handshake, s->attempt, &ei, &er) || dmp_hs_confirm(s->handshake, s->attempt) != DMP_HS_OK) return 0;
    p = dmp_hs_protected_frame(s->handshake, s->attempt, &pn); if (p == NULL || !send_cached(s->socket, REC_HANDSHAKE, p, pn)) return 0;
    if (!recv_record(s->socket, &type, buf, sizeof buf, &n) || type != REC_HANDSHAKE || !hs_protected(s->handshake, buf, n, ID_RESP, ID_INIT, er)) return 0;
    if (!dmp_hs_association_active(s->handshake) || !bind_endpoint(s) || f == NULL) return 0;
    /* Track the traffic epoch used by the initiator endpoint, not the boot
     * envelope hash used to bind handshake flights. */
    s->association_epoch = ei;
    if (s->association_epoch == 0U) return 0;
    return 1;
}
static int peer_handshake_step(side *s, uint8_t *buf, size_t n)
{
    uint64_t epoch, ei, er; const uint8_t *p; size_t pn;
    if (s->handshake_stage == 0U) {
        if (n <= sizeof epoch) return 0;
        memcpy(&epoch, buf, sizeof epoch);
        if (epoch == 0U || !hs_offer(s->handshake, buf + sizeof epoch, n - sizeof epoch, ID_INIT, ID_RESP, epoch, 1U, DMP_HS_CANDIDATE)) return 0;
        p = dmp_hs_cached_flight(s->handshake, 0U, &pn);
        if (p == NULL || !send_cached(s->socket, REC_HANDSHAKE, p, pn)) return 0;
        s->handshake_stage = 1U; return 1;
    }
    if (!dmp_hs_epochs(s->handshake, 0U, &ei, &er) || !hs_protected(s->handshake, buf, n, ID_INIT, ID_RESP, ei)) return 0;
    p = dmp_hs_protected_frame(s->handshake, 0U, &pn);
    if (p == NULL || !send_cached(s->socket, REC_HANDSHAKE, p, pn) || !dmp_hs_association_active(s->handshake)) return 0;
    /* The responder-side traffic epoch is distinct from the boot epoch. */
    s->association_epoch = er;
    if (s->association_epoch == 0U) return 0;
    s->handshake_stage = 2U; return bind_endpoint(s);
}
static void complete_request(side *s)
{
    static const uint8_t rsp[17] = {1,1,0,0,0,0,0,0,0,2,0,0,0,0x2c,1,0,0};
    if (s->app.have_request) { dmp_status st = dmp_endpoint_complete(&s->bundle->endpoint, s->app.request, false, 0U, (dmp_bytes){rsp, sizeof rsp}, s->now); if (st != DMP_OK) fprintf(stderr, "peer complete status=%d\n", (int)st); s->app.have_request = 0; }
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
static int parent_tick(side *s, uint64_t now)
{
    uint8_t type, buf[IPC_LIMIT]; size_t n;
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
        { dmp_status st = dmp_endpoint_rx(&s->bundle->endpoint, (dmp_bytes){buf, n}, now); if (st != DMP_OK && st != DMP_INCOMPLETE && st != DMP_DUPLICATE) { fprintf(stderr, "measured endpoint rx status=%d\n", (int)st); return 0; } }
    }
    return 1;
}
static int pump_exchange(side *s)
{
    uint64_t now = s->now; unsigned rounds;
    for (rounds = 0U; rounds < 8U; ++rounds) {
        if (!parent_tick(s, now)) return 0;
        if (s->app.results != 0) {
            if (!parent_tick(s, now)) return 0;
            return s->app.results == 1;
        }
    }
    fprintf(stderr, "pump exhausted: results=%d\n", s->app.results);
    return 0;
}
static void print_phase(FILE *out, const phase_sample *p, int comma)
{
    fprintf(out, "{\"name\":\"%s\",\"status\":\"%s\",\"scope\":\"selected one-device process; peer excluded\",\"caller_owned_requested_current_bytes\":%zu,\"endpoint_bundle_object_requested_bytes\":%zu,\"caller_payload_buffers_requested_bytes\":%zu,\"provider_object_requested_bytes\":%zu,\"handshake_object_requested_bytes\":%zu,\"provider_retained_current_bytes\":%zu,\"provider_retained_peak_bytes\":%zu,\"host_observed_requested_payload_high_water_bytes\":%zu,\"provider_largest_single_allocation_bytes\":%zu,\"provider_scratch_limit_bytes\":%u,\"provider_largest_scratch_observed_bytes\":null,\"endpoint_tx_submissions\":%zu,\"injected_loss_count\":%zu,\"local_request_submissions\":%zu,\"peer_request_notices\":%zu,\"endpoint_request_notices\":%zu,\"endpoint_result_notices\":%zu,\"retry_frame_differs_from_dropped_frame\":%s,\"reliable_request_payload_bytes\":%zu,\"reliable_request_fragment_count\":%zu,\"reliable_request_frame_count\":%zu,\"reliable_request_retry_observed\":%s,\"payload_fragment_bytes\":%zu,\"payload_fragment_frames\":%zu,\"peer_assembled_message_count\":%zu,\"peer_assembled_message_bytes\":%zu}%s",
            p->name, p->status, p->caller_owned_requested, p->endpoint_bundle_object_requested,
            p->caller_payload_buffers_requested, p->provider_object_requested, p->handshake_object_requested,
            p->provider_current, p->provider_peak, p->requested_payload_high_water,
            p->provider_largest, DMP_PROVIDER_SCRATCH_MAX, p->tx_submissions, p->injected_losses,
            p->local_request_submissions, p->peer_request_notices,
            p->request_notices, p->result_notices,
            p->retry_frame_distinct ? "true" : "false",
            p->reliable_request_payload_bytes, p->reliable_request_fragment_count,
            p->reliable_request_frame_count,
            p->reliable_request_retry_observed ? "true" : "false",
            p->payload_fragment_bytes, p->payload_fragment_frames,
            p->assembled_message_count, p->assembled_message_bytes,
            comma ? "," : "");
}
static int write_report(const phase_sample phases[6], size_t message, const char profile_digest[65],
                        const reconnect_evidence *reconnect)
{
    size_t i;
    fputs("{\"schema_version\":1,\"ok\":true,\"device_count\":1,\"peer_process_count\":1,\"peer_process_isolated\":true,\"ipc\":\"loopback TCP records carry real NNpsk0 flights and libdmp Stream R endpoint frames\",\"evidence_class\":\"host-runtime-one-endpoint-process-isolated-peer\",\"reliable_result_payload_bytes\":17,\"message_bytes\":", stdout);
    printf("%zu,\"reliable_request_payload_bytes\":%zu,\"phases\":[", message, message);
    for (i = 0U; i < 6U; ++i) print_phase(stdout, &phases[i], i != 5U);
    fprintf(stdout, "],\"profile_id\":\"TEST-DIRECT-MINIMAL-%zu\",\"profile_digest_sha256\":\"%s\",\"handshake_budget\":{\"max_pending\":1,\"max_scratch\":1,\"episode_attempts\":2,\"episode_deadline_ms\":41000,\"episode_work_units\":100000,\"episode_traffic_bytes\":16384,\"restart_backoff_ms\":1000,\"attempt_deadline_ms\":20000,\"cached_responses\":1,\"global_work_units\":100000,\"ingress_packets_per_window\":100,\"later_episodes\":2,\"admit_burst\":100,\"admit_window_ms\":1000,\"provisional_bytes\":120,\"replay_window_bits\":1024,\"failed_aead_limit\":1000,\"association_lifetime_ms\":100000000,\"confirmation_timeout_ms\":512,\"confirmation_attempts\":2},\"reconnect\":{\"semantics\":\"endpoint/provider state reset followed by fresh NNpsk0 handshake over the same loopback IPC connection\",\"same_ipc_connection\":true,\"attempt_id_changed\":%s,\"initiator_ephemeral_changed\":%s,\"responder_ephemeral_changed\":%s,\"prior_initiator_traffic_epoch\":%llu,\"new_initiator_traffic_epoch\":%llu,\"prior_responder_traffic_epoch\":%llu,\"new_responder_traffic_epoch\":%llu,\"prior_frame_source\":\"first actual protected DMP_TYPE_DATA frame from initial association\",\"old_data_frame_seen_by_original_peer\":%s,\"prior_protected_frame_status\":%u,\"prior_protected_frame_status_name\":\"DMP_AUTHENTICATION_FAILURE\",\"prior_frame_rejected_without_dispatch\":%s,\"requests_before\":%u,\"requests_after\":%u,\"data_notices_before\":%u,\"data_notices_after\":%u,\"assemblies_before\":%u,\"assemblies_after\":%u},\"accounting\":{\"provider_allocator_payload_only\":true,\"malloc_metadata_and_alignment\":\"unknown\",\"scratch_limit_is_per_allocation_ceiling\":true,\"scratch_not_added_to_physical_total\":true,\"peer_memory_included\":false,\"host_abi_size_and_target_runtime_separate\":true,\"physical_mcu_peak\":\"not_measured\"},\"host_abi\":{\"endpoint_bytes\":",
            message,
            profile_digest,
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
    printf("%zu,\"provider_bytes\":%zu,\"handshake_bytes\":%zu},\"unknowns\":[\"provider scratch allocations cannot be distinguished from retained allocations by the current provider port callbacks\",\"host task stack high-water by phase\",\"MCU allocator metadata and alignment\",\"physical MCU retained peak and stack high-water\",\"RTOS and static backend data\"]}\n", sizeof(dmp_endpoint), dmp_provider_size(), dmp_hs_size());
    return ferror(stdout) == 0;
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
    dmp_reliability_handle handle, data_handle; uint8_t request[MSG_MAX]; size_t i, request_frames = 1U;
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
    for (i = 0U; i < request_size; ++i) request[i] = (uint8_t)(i ^ 0x5aU);
    target.submissions = 0U; target.retry_distinct = 0U; target.retry_observed = 0U; target.dropped = 0U;
    target.drop_first = 1U;
    if (dmp_endpoint_submit_req(&target.bundle->endpoint, 2U, (dmp_bytes){request,request_size}, target.now, &handle) != DMP_OK ||
        dmp_endpoint_poll(&target.bundle->endpoint, target.now) != DMP_OK || !target.dropped) { fputs("RAM process probe: request submit/initial injected loss failed\n", stderr); return 0; }
    target.local_requests = 1U;
    target.now += 1280U; target.hsctx.now = target.now;
    if (!pump_exchange(&target) || !target.retry_observed || !target.retry_distinct || target.submissions < 2U ||
        target.app.results != 1 || target.local_requests != 1U || target.peer.requests != 1U) { fputs("RAM process probe: real retry/request/result exchange failed\n", stderr); return 0; }
    if (request_size == 128U) {
        if (target.peer.assemblies != 0U || target.peer.assembled_bytes != 0U ||
            request_frames != 1U) {
            fputs("RAM process probe: 128-byte request was not the expected unfragmented frame\n", stderr);
            return 0;
        }
    } else if (request_size == 256U) {
        request_frames = (request_size + chunk_bytes - 1U) / chunk_bytes;
        if (target.peer.assemblies != 1U || target.peer.assembled_bytes != request_size ||
            request_frames != 4U) {
            fputs("RAM process probe: 256-byte request did not assemble as four fragments\n", stderr);
            return 0;
        }
    } else {
        fputs("RAM process probe: unsupported reliable request size\n", stderr);
        return 0;
    }
    target.drop_first = 0U;
    phases[3].reliable_request_payload_bytes = request_size;
    phases[3].reliable_request_fragment_count = target.peer.assemblies != 0U ? request_frames : 0U;
    phases[3].reliable_request_frame_count = request_frames;
    phases[3].reliable_request_retry_observed = target.retry_observed != 0U;
    phases[3].payload_fragment_bytes = target.peer.assemblies != 0U ? request_size : 0U;
    phases[3].payload_fragment_frames = target.peer.assemblies != 0U ? request_frames : 0U;
    phases[3].assembled_message_count = target.peer.assemblies;
    phases[3].assembled_message_bytes = (size_t)target.peer.assembled_bytes;
    capture(&phases[3], &target);
    target.drop_first = 0U;
    if (dmp_endpoint_poll(&target.bundle->endpoint, target.now) != DMP_OK) return 0;
    target.capture_protected_data = 1U; target.protected_data_captured = 0U;
    if (dmp_endpoint_submit_data(&target.bundle->endpoint, 2U,
                                 (dmp_bytes){old_data_payload, sizeof old_data_payload},
                                 no_token, target.now, &data_handle) != DMP_OK ||
        dmp_endpoint_poll(&target.bundle->endpoint, target.now) != DMP_OK ||
        !target.protected_data_captured ||
        !parent_tick(&target, target.now) || target.peer.data_notices != 1U) {
        fputs("RAM process probe: old-association protected DATA capture failed\n", stderr);
        return 0;
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
    { uint8_t kind, buf[IPC_LIMIT]; size_t n; if (!recv_record(connection, &kind, buf, sizeof buf, &n) || kind != REC_DONE) return 0; }
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
    { uint8_t kind, buf[IPC_LIMIT]; size_t n; (void)recv_record(connection, &kind, buf, sizeof buf, &n); }
    close_side(&target); CLOSE_SOCKET(connection);
#ifdef _WIN32
    (void)WaitForSingleObject(process.hProcess, 5000); CloseHandle(process.hProcess);
#else
    (void)waitpid(process, NULL, 0);
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
    int i; const char *manifest = NULL;
    if (f == NULL) return 2;
#ifdef _WIN32
    { WSADATA data; if (WSAStartup(MAKEWORD(2,2), &data) != 0) return 2; }
#else
    (void)signal(SIGPIPE, SIG_IGN);
#endif
    if (argc >= 2 && strcmp(argv[1], "--peer") == 0) {
        uint16_t port = (uint16_t)strtoul(argv[2], NULL, 10); side peer;
        for (i = 3; i + 1 < argc; ++i) if (strcmp(argv[i], "--manifest") == 0) manifest = argv[i+1];
        if (manifest == NULL || !validate_manifest_digest(manifest, profile_digest, profile_digest_hex) ||
            !manifest_message_size(manifest, &message, &request, &chunk) ||
            !setup_side(&peer, message, 0, 1U, f, profile_digest) || !peer_connect_port(port, &peer.socket)) return 2;
        i = peer_main_loop(&peer, message, f, profile_digest); close_side(&peer); CLOSE_SOCKET(peer.socket);
#ifdef _WIN32
        WSACleanup();
#endif
        return i ? 0 : 1;
    }
    if (argc != 3 || strcmp(argv[1], "--manifest") != 0 ||
        !validate_manifest_digest(argv[2], profile_digest, profile_digest_hex) ||
        !manifest_message_size(argv[2], &message, &request, &chunk)) {
        fputs("usage: dmp_ram_endpoint_process --manifest <minimal-128-or-256.json>\n", stderr); return 2;
    }
    i = parent_run(argv[0], argv[2], message, request, chunk, f, profile_digest, profile_digest_hex);
#ifdef _WIN32
    WSACleanup();
#endif
    return i ? 0 : 1;
}
