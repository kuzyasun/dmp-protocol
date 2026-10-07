/*
 * Initial endpoint-memory milestone. This constructs one real libdmp endpoint
 * backed by the real P01B provider in this process. It deliberately does not
 * bind a handshake: endpoint lifecycle phases after initialization remain
 * unmeasured until an independent peer process is available.
 */
#include "dmp/endpoint.h"
#include "provider_port.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { MESSAGE_MAX = 256, CHUNK = 64, MTU = 263, SLOTS = 3, TOMBSTONES = 16,
       STREAM_CAP = 512 };

typedef struct memory_bundle {
    dmp_endpoint endpoint;
    dmp_admitted_profile admitted;
    dmp_transport transport;
    dmp_identity_slot identities[1];
    dmp_reliability_sender_slot senders[1];
    uint8_t sender_payload[MESSAGE_MAX];
    dmp_reliability_result_slot results[1];
    uint8_t result_payload[MESSAGE_MAX];
    dmp_reliability_history_slot history[2];
    dmp_reliability_correlation_slot correlations[1];
    uint8_t history_metadata[2 * DMP_RELIABILITY_METADATA_BYTES];
    uint8_t correlation_metadata[DMP_RELIABILITY_METADATA_BYTES];
    dmp_reliability_adapter_slot adapters[SLOTS];
    uint8_t frames[SLOTS * MTU];
    uint8_t receive_payload[MESSAGE_MAX];
    dmp_reassembly_slot assemblies[1];
    dmp_reassembly_tombstone tombstones[TOMBSTONES];
    uint8_t assembly_payload[MESSAGE_MAX];
    uint8_t assembly_metadata[DMP_REASSEMBLY_METADATA_BYTES];
    uint8_t fragment_message[MESSAGE_MAX];
    uint8_t fragment_frame[MTU];
    uint8_t telemetry_payload[MESSAGE_MAX];
    uint8_t telemetry_next[MESSAGE_MAX];
    uint8_t telemetry_frame[MTU];
    uint8_t stream_tx[STREAM_CAP];
    uint8_t stream_rx[STREAM_CAP];
} memory_bundle;

typedef struct allocation_stats {
    size_t live;
    size_t peak;
    size_t peak_one;
} allocation_stats;

static int ready(void *ctx) { (void)ctx; return 0; }
static int entropy(void *ctx, void *out, size_t n)
{
    static uint32_t state = 0x19c0ffeeU;
    uint8_t *p = (uint8_t *)out;
    size_t i;
    (void)ctx;
    for (i = 0; i < n; ++i) {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        p[i] = (uint8_t)state;
    }
    return 0;
}
static void *allocate(void *ctx, size_t n)
{
    allocation_stats *stats = (allocation_stats *)ctx;
    void *p = malloc(n);
    if (p != NULL && stats != NULL) {
        stats->live += n;
        if (stats->live > stats->peak) stats->peak = stats->live;
        if (n > stats->peak_one) stats->peak_one = n;
    }
    return p;
}
static void release(void *ctx, void *p, size_t n)
{
    allocation_stats *stats = (allocation_stats *)ctx;
    if (stats != NULL && stats->live >= n) stats->live -= n;
    free(p);
}
static dmp_status submit(void *ctx, const dmp_tx_submission *s)
{ (void)ctx; (void)s; return DMP_BUSY; }
static dmp_status cancel(void *ctx, dmp_tx_token token)
{ (void)ctx; (void)token; return DMP_OK; }
static void notice(void *ctx, const dmp_endpoint_notice *n)
{ (void)ctx; (void)n; }

static void fill_config(dmp_config *c, size_t message)
{
    static const uint8_t hash[32] = {
        0x29,0xcb,0x7b,0x91,0xee,0x0c,0x26,0x9b,0xc1,0x4a,0xc4,0x3e,0x3a,0x7c,0x8f,0xd8,
        0xbd,0xcf,0xe1,0x1e,0x9e,0x05,0x2e,0x8b,0xd9,0xe6,0xaf,0x00,0xfb,0x89,0xc3,0xbf};
    memset(c, 0, sizeof *c);
    memcpy(c->sha256, hash, sizeof hash);
    c->namespace_id = 1U; c->node_id[0] = 10U; c->node_id[1] = 20U;
    c->default_service = 1U; c->service_id[0] = 1U; c->service_id[1] = 2U;
    c->recovery[0] = DMP_PROFILE_RECOVERY_RETRY_ALL;
    c->recovery[1] = DMP_PROFILE_RECOVERY_RETRY_ALL;
    c->peers = 1U; c->operations_per_service = 1U; c->assemblies_per_peer = 1U;
    c->assembly_tombstones_per_peer = TOMBSTONES; c->sender_slots = 1U;
    c->assembly_slots = 1U; c->assembly_tombstone_slots = TOMBSTONES;
    c->result_slots = 1U; c->history_slots = 2U; c->correlation_slots = 1U;
    c->adapter_slots = SLOTS; c->application_queue_slots = 1U; c->control_slots = 2U;
    c->message_bytes = (uint32_t)message; c->fragments = (uint32_t)(message / CHUNK);
    c->chunk_bytes = CHUNK; c->encoded_mtu = MTU;
    c->forward_mtu = 256U; c->return_mtu = 256U;
    c->queue_ms = 64U; c->response_timeout_ms = 1280U;
    c->send_horizon_ms = 5632U; c->max_bursts = 3U;
    c->receipt_delay_ms = 110U; c->receipt_limit = 3U;
    c->dedup_ms = 6000U; c->rejection_ms = 6000U; c->result_cache_ms = 6000U;
    c->result_deadline_ms = 12000U; c->correlation_ms = 12288U;
    c->tombstone_ms = 12288U; c->late_result_ms = 64U;
    c->collect_ms = 5652U; c->assembly_ms = 5657U;
    c->tx_borrow = true; c->synchronous_completion = true;
}

static int manifest_message_size(const char *path, size_t *message)
{
    FILE *f = fopen(path, "rb");
    char buf[65536];
    size_t n;
    char *p;
    if (f == NULL) return 0;
    n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f); buf[n] = '\0';
    p = strstr(buf, "\"message_bytes\"");
    if (p == NULL || (p = strchr(p, ':')) == NULL) return 0;
    *message = (size_t)strtoul(p + 1, NULL, 10);
    return *message == 128U || *message == 256U;
}

int main(int argc, char **argv)
{
    memory_bundle *b;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_endpoint_storage s;
    dmp_identity_context_config identity;
    dmp_endpoint_grant grants[4];
    allocation_stats allocations = {0U, 0U, 0U};
    dmp_status status;
    size_t message;
    if (argc != 3 || strcmp(argv[1], "--manifest") != 0 ||
        !manifest_message_size(argv[2], &message)) {
        fputs("usage: dmp_ram_endpoint_initial --manifest <minimal-128-or-256.json>\n", stderr);
        return 2;
    }
    b = (memory_bundle *)calloc(1U, sizeof *b);
    provider = (dmp_provider *)calloc(1U, dmp_provider_size());
    if (b == NULL || provider == NULL) { free(provider); free(b); return 1; }
    memset(&ports, 0, sizeof ports); ports.startup_ready = ready;
    ports.startup_read = entropy; ports.entropy = entropy;
    ports.allocate = allocate; ports.release = release;
    ports.ctx = &allocations;
    ports.scratch_limit = DMP_PROVIDER_SCRATCH_MAX;
    ports.retained_limit = DMP_PROVIDER_RETAINED_MAX;
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) return 1;
    {
        dmp_config config;
        fill_config(&config, message);
        status = dmp_config_admit(&config, &b->admitted);
        if (status != DMP_OK) { fprintf(stderr, "profile admission: %d\n", (int)status); return 1; }
    }
    memset(&identity, 0, sizeof identity);
    identity.local.namespace_id = identity.peer.namespace_id = 1U;
    identity.local.origin_id = 10U; identity.peer.origin_id = 20U; identity.security = 1U;
    b->transport.context = b; b->transport.submit = submit; b->transport.cancel = cancel;
    b->transport.caps.max_frame_bytes = STREAM_CAP;
    b->transport.caps.ownership = DMP_TX_BORROW;
    b->transport.caps.synchronous_completion = true;
    memset(&s, 0, sizeof s); s.profile = &b->admitted;
    s.identity_slots = b->identities; s.identity_capacity = 1U; s.context = identity;
    s.transport = &b->transport; s.notice = notice; s.senders = b->senders; s.sender_capacity = 1U;
    s.sender_payload = b->sender_payload; s.sender_payload_capacity = sizeof b->sender_payload;
    s.results = b->results; s.result_capacity = 1U;
    s.result_payload = b->result_payload; s.result_payload_capacity = sizeof b->result_payload;
    s.history = b->history; s.history_capacity = 2U;
    s.correlations = b->correlations; s.correlation_capacity = 1U;
    s.history_metadata = b->history_metadata; s.history_metadata_capacity = sizeof b->history_metadata;
    s.correlation_metadata = b->correlation_metadata; s.correlation_metadata_capacity = sizeof b->correlation_metadata;
    s.adapters = b->adapters; s.adapter_capacity = SLOTS;
    s.frames = b->frames; s.frame_capacity = sizeof b->frames;
    s.receive_payload = b->receive_payload; s.receive_payload_capacity = sizeof b->receive_payload;
    s.assemblies = b->assemblies; s.assembly_capacity = 1U;
    s.tombstones = b->tombstones; s.tombstone_capacity = TOMBSTONES;
    s.assembly_payload = b->assembly_payload; s.assembly_payload_capacity = sizeof b->assembly_payload;
    s.assembly_metadata = b->assembly_metadata; s.assembly_metadata_capacity = sizeof b->assembly_metadata;
    s.fragment_message = b->fragment_message; s.fragment_message_capacity = sizeof b->fragment_message;
    s.fragment_frame = b->fragment_frame; s.fragment_frame_capacity = sizeof b->fragment_frame;
    s.telemetry_payload = b->telemetry_payload; s.telemetry_payload_capacity = sizeof b->telemetry_payload;
    s.telemetry_next = b->telemetry_next; s.telemetry_next_capacity = sizeof b->telemetry_next;
    s.telemetry_frame = b->telemetry_frame; s.telemetry_frame_capacity = sizeof b->telemetry_frame;
    s.stream_tx = b->stream_tx; s.stream_tx_capacity = sizeof b->stream_tx;
    s.stream_rx = b->stream_rx; s.stream_rx_capacity = sizeof b->stream_rx;
    status = dmp_endpoint_init(&b->endpoint, &s, 10000U);
    if (status != DMP_OK) { fprintf(stderr, "endpoint init: %d\n", (int)status); return 1; }
    memset(grants, 0, sizeof grants);
    grants[0].principal = 10U; grants[0].service_id = 1U;
    grants[0].permit = DMP_ENDPOINT_PERMIT_TELEM | DMP_ENDPOINT_PERMIT_RESULT;
    grants[1].principal = 20U; grants[1].service_id = 1U; grants[1].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[2].principal = 10U; grants[2].service_id = 2U;
    grants[2].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    grants[3].principal = 20U; grants[3].service_id = 2U;
    grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    if (dmp_endpoint_set_grants(&b->endpoint, grants, 4U) != DMP_OK) return 1;
    if (allocations.live != dmp_provider_retained(provider)) {
        fputs("provider allocator accounting mismatch\n", stderr);
        return 1;
    }
    printf("{\"status\":\"measured\",\"phase\":\"initial\",\"message_bytes\":%zu,\"caller_owned_bundle_requested_bytes\":%zu,\"caller_owned_provider_state_requested_bytes\":%zu,\"provider_retained_current_bytes\":%zu,\"provider_retained_peak_bytes\":%zu,\"provider_retained_largest_single_allocation_bytes\":%zu,\"scope\":\"one initialized real libdmp endpoint; no association or peer exchange\",\"remaining_lifecycle_phases\":\"not_measured\"}\n",
           message, sizeof *b, dmp_provider_size(), allocations.live, allocations.peak,
           allocations.peak_one);
    /* Endpoint storage has no destructor; process exit ends this host milestone. */
    dmp_provider_cleanup(provider);
    free(provider); free(b);
    return 0;
}
