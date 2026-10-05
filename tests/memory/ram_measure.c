/* P01B provider-only NNpsk0 fixture probe. Initiator and responder fixture
 * roles run separately; this does not instantiate a libdmp endpoint. */
#include "provider_port.h"

#include "dmp/endpoint.h"
#include "dmp/identity.h"
#include "dmp/reassembly.h"
#include "dmp/reliability.h"
#include "dmp/stream.h"
#include "handshake.h"
#include "noise_fixture_probe.h"

#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { PHASES = 6, MAX_ALLOCATIONS = 128, MAX_MANIFEST_BYTES = 262144 };

typedef struct allocation_record {
    void *pointer;
    size_t size;
} allocation_record;

typedef struct port_context {
    allocation_record allocations[MAX_ALLOCATIONS];
    size_t live;
    size_t peak;
    size_t largest_single;
} port_context;

typedef struct phase_metric {
    const char *name;
    size_t current;
    size_t peak;
    size_t largest_single;
} phase_metric;

typedef struct side_result {
    const char *role;
    phase_metric phases[PHASES];
    size_t provider_initial_fixture_flight_bytes;
    size_t provider_reopen_fixture_flight_bytes;
} side_result;

static const char *const endpoint_phase_names[PHASES] = {
    "initial", "handshake_peak", "active_steady", "request_result_retry", "cleanup", "reconnect"};
static const char *const provider_phase_names[PHASES] = {
    "provider_initial", "provider_handshake_peak", "provider_after_split",
    "provider_sized_encrypt_sequence", "provider_cleanup", "provider_reopen_handshake"};
static uint32_t entropy_state = 0x51f15eedU;

static int json_integer(const char *json, const char *key, size_t *value)
{
    char pattern[64];
    const char *found;
    char *end;
    unsigned long parsed;
    int written = snprintf(pattern, sizeof pattern, "\"%s\"", key);
    if (written < 0 || (size_t)written >= sizeof pattern) {
        return 0;
    }
    found = strstr(json, pattern);
    if (found == NULL) {
        return 0;
    }
    found = strchr(found + (size_t)written, ':');
    if (found == NULL) {
        return 0;
    }
    parsed = strtoul(found + 1, &end, 10);
    if (end == found + 1 || parsed > (unsigned long)SIZE_MAX) {
        return 0;
    }
    *value = (size_t)parsed;
    return 1;
}

static int read_manifest_limits(const char *path, size_t *message_bytes,
                                size_t *chunk_bytes, size_t *encoded_mtu,
                                size_t *sender_slots)
{
    FILE *input = fopen(path, "rb");
    char *contents;
    long length;
    int ok;
    if (input == NULL || fseek(input, 0L, SEEK_END) != 0 ||
        (length = ftell(input)) <= 0 || length > MAX_MANIFEST_BYTES ||
        fseek(input, 0L, SEEK_SET) != 0) {
        if (input != NULL) {
            fclose(input);
        }
        return 0;
    }
    contents = (char *)malloc((size_t)length + 1U);
    if (contents == NULL) {
        fclose(input);
        return 0;
    }
    ok = fread(contents, 1U, (size_t)length, input) == (size_t)length;
    fclose(input);
    contents[length] = '\0';
    ok = ok && json_integer(contents, "message_bytes", message_bytes) &&
         json_integer(contents, "chunk_bytes", chunk_bytes) &&
         json_integer(contents, "encoded_mtu", encoded_mtu) &&
         json_integer(contents, "sender_slots", sender_slots) &&
         *message_bytes > 0U && *message_bytes <= 1024U &&
         *chunk_bytes > 0U && *chunk_bytes < *message_bytes &&
         *encoded_mtu > 0U && *encoded_mtu <= 66000U &&
         *sender_slots > 0U && *sender_slots <= 64U &&
         (*message_bytes + *chunk_bytes - 1U) / *chunk_bytes <= 32U;
    free(contents);
    return ok;
}

static int startup_ready(void *context)
{
    (void)context;
    return 0;
}

static int random_bytes(void *context, void *output, size_t size)
{
    uint8_t *bytes = (uint8_t *)output;
    size_t i;
    (void)context;
    for (i = 0U; i < size; ++i) {
        entropy_state ^= entropy_state << 13;
        entropy_state ^= entropy_state >> 17;
        entropy_state ^= entropy_state << 5;
        bytes[i] = (uint8_t)entropy_state;
    }
    return 0;
}

static void *tracked_allocate(void *context, size_t size)
{
    port_context *port = (port_context *)context;
    size_t i;
    void *pointer;
    if (port == NULL || size == 0U || size > SIZE_MAX - port->live) {
        return NULL;
    }
    for (i = 0U; i < MAX_ALLOCATIONS; ++i) {
        if (port->allocations[i].pointer == NULL) {
            break;
        }
    }
    if (i == MAX_ALLOCATIONS) {
        return NULL;
    }
    pointer = malloc(size);
    if (pointer == NULL) {
        return NULL;
    }
    port->allocations[i].pointer = pointer;
    port->allocations[i].size = size;
    port->live += size;
    if (port->live > port->peak) {
        port->peak = port->live;
    }
    if (size > port->largest_single) {
        port->largest_single = size;
    }
    return pointer;
}

static void tracked_release(void *context, void *pointer, size_t size)
{
    port_context *port = (port_context *)context;
    size_t i;
    if (port == NULL || pointer == NULL) {
        return;
    }
    for (i = 0U; i < MAX_ALLOCATIONS; ++i) {
        if (port->allocations[i].pointer == pointer) {
            if (port->allocations[i].size == size && port->live >= size) {
                port->live -= size;
                free(pointer);
                port->allocations[i].pointer = NULL;
                port->allocations[i].size = 0U;
            }
            return;
        }
    }
}

static void capture(phase_metric *metric, const port_context *port)
{
    metric->current = port->live;
    metric->peak = port->peak;
    metric->largest_single = port->largest_single;
}

static void fill_keys(const noise_fixture_probe_fixture_t *fixture, int role,
                      dmp_provider_handshake_keys *keys)
{
    const noise_fixture_probe_bytes_t *ephemeral =
        role == DMP_PROVIDER_ROLE_INITIATOR ? &fixture->init_ephemeral : &fixture->resp_ephemeral;
    const noise_fixture_probe_bytes_t *static_key =
        role == DMP_PROVIDER_ROLE_INITIATOR ? &fixture->init_static : &fixture->resp_static;
    memset(keys, 0, sizeof(*keys));
    keys->local_ephemeral = ephemeral->data;
    keys->local_ephemeral_len = ephemeral->size;
    keys->local_static = static_key->data;
    keys->local_static_len = static_key->size;
    keys->psk = fixture->psk.data;
    keys->psk_len = fixture->psk.size;
    keys->prologue = fixture->prologue.data;
    keys->prologue_len = fixture->prologue.size;
}

static int provider_open(port_context *port, dmp_provider **provider)
{
    dmp_provider_ports ports;
    memset(&ports, 0, sizeof ports);
    ports.startup_ready = startup_ready;
    ports.startup_read = random_bytes;
    ports.entropy = random_bytes;
    ports.allocate = tracked_allocate;
    ports.release = tracked_release;
    ports.ctx = port;
    ports.scratch_limit = DMP_PROVIDER_SCRATCH_MAX;
    ports.retained_limit = DMP_PROVIDER_RETAINED_MAX;
    *provider = (dmp_provider *)calloc(1U, dmp_provider_size());
    if (*provider == NULL || dmp_provider_setup(*provider, &ports) != DMP_PROVIDER_OK) {
        free(*provider);
        *provider = NULL;
        return 0;
    }
    return 1;
}

static int run_connection(const noise_fixture_probe_fixture_t *fixture, int role,
                          port_context *port, phase_metric *initial,
                          phase_metric *handshake, phase_metric *active,
                          phase_metric *exchange, phase_metric *cleanup,
                          size_t *first_flight, size_t message_bytes,
                          size_t chunk_bytes, size_t sender_slots, int do_exchange)
{
    dmp_provider *provider = NULL;
    dmp_provider_handshake hs;
    dmp_provider_handshake_keys keys;
    dmp_provider_cipher send_cipher;
    dmp_provider_cipher receive_cipher;
    uint8_t message[2048];
    uint8_t payload[2048];
    uint8_t aad[] = {0x50U, 0x31U, 0x39U};
    uint8_t logical[1024];
    uint8_t hash[32];
    size_t message_len = 0U;
    size_t payload_len = 0U;
    size_t index;
    int hs_open = 0;
    int send_open = 0;
    int receive_open = 0;
    int success = 0;

    memset(&hs, 0, sizeof hs);
    memset(&send_cipher, 0, sizeof send_cipher);
    memset(&receive_cipher, 0, sizeof receive_cipher);
    memset(message, 0, sizeof message);
    memset(payload, 0, sizeof payload);
    memset(logical, 0xA5, sizeof logical);
    entropy_state = role == DMP_PROVIDER_ROLE_INITIATOR ? 0x51f15eedU : 0x811c9dc5U;
    memset(port, 0, sizeof *port);
    if (!provider_open(port, &provider)) {
        return 0;
    }
    capture(initial, port);
    fill_keys(fixture, role, &keys);
    if (dmp_provider_handshake_open(provider, &hs, fixture->protocol_name, role, &keys) !=
        DMP_PROVIDER_OK) {
        goto done;
    }
    hs_open = 1;

    for (index = 0U; index < fixture->flight_count; ++index) {
        const noise_fixture_probe_flight_t *flight = &fixture->flights[index];
        int local_sends = role == DMP_PROVIDER_ROLE_INITIATOR ? (index % 2U) == 0U
                                                              : (index % 2U) != 0U;
        if (local_sends) {
            if (dmp_provider_handshake_write(provider, &hs, flight->plaintext.data,
                                             flight->plaintext.size, message, sizeof message,
                                             &message_len) != DMP_PROVIDER_OK ||
                message_len != flight->message.size ||
                memcmp(message, flight->message.data, message_len) != 0) {
                goto done;
            }
            if (*first_flight == 0U) {
                *first_flight = message_len;
            }
        } else {
            if (dmp_provider_handshake_read(provider, &hs, flight->message.data,
                                            flight->message.size, payload, sizeof payload,
                                            &payload_len) != DMP_PROVIDER_OK ||
                payload_len != flight->plaintext.size ||
                memcmp(payload, flight->plaintext.data, payload_len) != 0) {
                goto done;
            }
        }
    }
    if (dmp_provider_handshake_hash(provider, &hs, hash) != DMP_PROVIDER_OK ||
        memcmp(hash, fixture->handshake_hash.data, sizeof hash) != 0 ||
        dmp_provider_handshake_split(provider, &hs, &send_cipher, &receive_cipher) !=
            DMP_PROVIDER_OK) {
        goto done;
    }
    send_open = 1;
    receive_open = 1;
    capture(handshake, port);
    capture(active, port);

    if (do_exchange) {
        size_t fragments = (message_bytes + chunk_bytes - 1U) / chunk_bytes;
        uint64_t packet_number = 7U;
        for (size_t operation = 0U; operation < sender_slots; ++operation) {
            size_t remaining = message_bytes;
            for (size_t fragment = 0U; fragment < fragments; ++fragment) {
                size_t body_bytes = remaining < chunk_bytes ? remaining : chunk_bytes;
                size_t cipher_len = 0U;
                memset(logical, (int)(0xA5U + (uint8_t)operation), sizeof logical);
                if (dmp_provider_cipher_encrypt(provider, &send_cipher, packet_number++,
                                                aad, sizeof aad, logical, body_bytes,
                                                sizeof logical, &cipher_len) != DMP_PROVIDER_OK ||
                    cipher_len != body_bytes + 16U) {
                    goto done;
                }
                remaining -= body_bytes;
            }
            /* One dropped slice is retransmitted under a fresh packet number. */
            memset(logical, (int)(0xA5U + (uint8_t)operation), sizeof logical);
            {
                size_t retry_bytes = message_bytes < chunk_bytes ? message_bytes : chunk_bytes;
                size_t cipher_len = 0U;
                if (dmp_provider_cipher_encrypt(provider, &send_cipher, packet_number++,
                                                aad, sizeof aad, logical, retry_bytes,
                                                sizeof logical, &cipher_len) != DMP_PROVIDER_OK ||
                    cipher_len != retry_bytes + 16U) {
                    goto done;
                }
            }
        }
        capture(exchange, port);
    } else {
        capture(exchange, port);
    }
    success = 1;

done:
    if (receive_open && dmp_provider_cipher_close(provider, &receive_cipher) != DMP_PROVIDER_OK) {
        success = 0;
    }
    if (send_open && dmp_provider_cipher_close(provider, &send_cipher) != DMP_PROVIDER_OK) {
        success = 0;
    }
    if (hs_open && dmp_provider_handshake_close(provider, &hs) != DMP_PROVIDER_OK) {
        success = 0;
    }
    if (provider != NULL) {
        dmp_provider_cleanup(provider);
        if (port->live != 0U) {
            success = 0;
        }
    }
    capture(cleanup, port);
    free(provider);
    return success;
}

static int run_side(const noise_fixture_probe_fixture_t *fixture, int role,
                    size_t message_bytes, size_t chunk_bytes, size_t sender_slots,
                    side_result *result)
{
    port_context port;
    phase_metric reconnect_initial;
    phase_metric reconnect_handshake;
    phase_metric reconnect_active;
    phase_metric reconnect_exchange;
    phase_metric reconnect_cleanup;
    result->role = role == DMP_PROVIDER_ROLE_INITIATOR ? "initiator" : "responder";
    result->provider_initial_fixture_flight_bytes = 0U;
    result->provider_reopen_fixture_flight_bytes = 0U;
    for (size_t i = 0U; i < PHASES; ++i) {
        result->phases[i].name = provider_phase_names[i];
        memset(&result->phases[i].current, 0, sizeof(size_t) * 3U);
    }
    if (!run_connection(fixture, role, &port, &result->phases[0],
                        &result->phases[1], &result->phases[2],
                        &result->phases[3], &result->phases[4],
                        &result->provider_initial_fixture_flight_bytes, message_bytes, chunk_bytes,
                        sender_slots, 1)) {
        return 0;
    }
    if (!run_connection(fixture, role, &port, &reconnect_initial,
                        &reconnect_handshake, &reconnect_active,
                        &reconnect_exchange, &reconnect_cleanup,
                        &result->provider_reopen_fixture_flight_bytes, message_bytes, chunk_bytes,
                        sender_slots, 0)) {
        return 0;
    }
    result->phases[5] = reconnect_handshake;
    result->phases[5].name = provider_phase_names[5];
    return 1;
}

static void print_metric(FILE *output, const phase_metric *metric, int comma)
{
    fprintf(output, "{\"name\":\"%s\",\"status\":\"measured\","
                    "\"scope\":\"P01B provider only; no libdmp endpoint\","
                    "\"provider_retained_current_bytes\":%zu,"
                    "\"provider_retained_peak_bytes\":%zu,"
                    "\"provider_largest_single_allocation_bytes\":%zu,"
                    "\"provider_largest_scratch_bytes\":null}%s",
            metric->name, metric->current, metric->peak, metric->largest_single,
            comma ? "," : "");
}

static void print_endpoint_phase_unmeasured(FILE *output, const char *name, int comma)
{
    fprintf(output,
            "{\"name\":\"%s\",\"status\":\"not_measured\","
            "\"scope\":\"libdmp endpoint lifecycle\","
            "\"provider_retained_current_bytes\":null,"
            "\"provider_retained_peak_bytes\":null,"
            "\"provider_largest_single_allocation_bytes\":null,"
            "\"provider_largest_scratch_bytes\":null}%s",
            name, comma ? "," : "");
}

static void print_side(FILE *output, const side_result *side, int comma)
{
    fprintf(output, "{\"role\":\"%s\",\"provider_initial_fixture_flight_bytes\":%zu,"
                    "\"provider_reopen_fixture_flight_bytes\":%zu,\"provider_phases\":[",
            side->role, side->provider_initial_fixture_flight_bytes,
            side->provider_reopen_fixture_flight_bytes);
    for (size_t i = 0U; i < PHASES; ++i) {
        print_metric(output, &side->phases[i], i + 1U != PHASES);
    }
    fprintf(output, "]}%s", comma ? "," : "");
}

static void aggregate(const side_result sides[2], phase_metric output[PHASES])
{
    for (size_t phase_index = 0U; phase_index < PHASES; ++phase_index) {
        output[phase_index].name = provider_phase_names[phase_index];
        output[phase_index].current = 0U;
        output[phase_index].peak = 0U;
        output[phase_index].largest_single = 0U;
        for (size_t side_index = 0U; side_index < 2U; ++side_index) {
            const phase_metric *metric = &sides[side_index].phases[phase_index];
            if (metric->current > output[phase_index].current) {
                output[phase_index].current = metric->current;
            }
            if (metric->peak > output[phase_index].peak) {
                output[phase_index].peak = metric->peak;
            }
            if (metric->largest_single > output[phase_index].largest_single) {
                output[phase_index].largest_single = metric->largest_single;
            }
        }
    }
}

static int write_report(FILE *output, const noise_fixture_probe_fixture_t *fixture,
                        const side_result sides[2], size_t message_bytes,
                        size_t chunk_bytes, size_t encoded_mtu, size_t sender_slots)
{
    phase_metric aggregate_phases[PHASES];
    size_t stream_bound = 0U;
    if (dmp_stream_encoded_bound(DMP_STREAM_R, encoded_mtu, &stream_bound) != DMP_OK) {
        return 0;
    }
    aggregate(sides, aggregate_phases);
    fputs("{\n  \"schema_version\":1,\n  \"ok\":true,\n"
          "  \"device_count\":1,\n"
          "  \"evidence_class\":\"host-runtime-p01b-provider-fixture-only\",\n"
          "  \"phases\":[", output);
    for (size_t i = 0U; i < PHASES; ++i) {
        print_endpoint_phase_unmeasured(output, endpoint_phase_names[i], i + 1U != PHASES);
    }
    fputs("],\n  \"side_measurements\":[", output);
    print_side(output, &sides[0], 1);
    print_side(output, &sides[1], 0);
    fprintf(output,
            "],\n  \"workload\":{\"library\":\"P01B provider\","
            "\"protocol\":\"%s\",\"fixture\":\"%s\","
            "\"provider_fixture_flights\":%zu,\"provider_sized_plaintext_bytes\":%zu,"
            "\"provider_encrypt_sequence_count\":%zu,"
            "\"provider_plaintext_chunk_bytes\":%zu,\"provider_encrypt_calls_per_sequence\":%zu,"
            "\"provider_cipher_workload\":\"bounded P01B encrypt calls sized from manifest limits; no DMP framing or endpoint reliability behavior\","
            "\"endpoint_runtime_status\":\"not_measured\","
            "\"endpoint_runtime_reason\":\"probe does not instantiate dmp_hs or dmp_endpoint; fixture peer flights are direct Noise messages\","
            "\"reconnect_overlap_status\":\"not_measured\","
            "\"reconnect_overlap_reason\":\"runs cleanup before a separate provider construction; no simultaneous draining and new association\","
            "\"provider_role_aggregation\":\"maximum of independent initiator/responder runs, never a sum\","
            "\"scratch_limit_is_largest_single_allocation\":true,"
            "\"scratch_is_not_an_additive_arena\":true},\n"
            "  \"objects\":[{\"name\":\"P01B Noise live allocator high-water\","
            "\"charge\":\"provider_retained\",\"check_bytes\":%zu,"
            "\"physical_bytes\":%zu,\"classification\":\"observed\",\"overlap\":false,"
            "\"note\":\"Maximum requested live Noise allocator payload for one role; malloc metadata and alignment are excluded.\"}],\n"
            "  \"host_abi\":["
            "{\"name\":\"dmp_endpoint\",\"sizeof_bytes\":%zu,\"classification\":\"host_abi_only\"},"
            "{\"name\":\"dmp_hs\",\"sizeof_bytes\":%zu,\"classification\":\"host_abi_only\"},"
            "{\"name\":\"dmp_provider\",\"sizeof_bytes\":%zu,\"classification\":\"host_abi_only\"},"
            "{\"name\":\"provider handshake handle\",\"sizeof_bytes\":%zu,\"classification\":\"host_abi_only\"}],\n"
            "  \"host_layout_sizes\":{"
            "\"dmp_endpoint\":%zu,\"dmp_hs\":%zu,\"dmp_provider\":%zu,"
            "\"identity_slot\":%zu,\"sender_slot\":%zu,\"result_slot\":%zu,"
            "\"history_slot\":%zu,\"correlation_slot\":%zu,\"adapter_slot\":%zu,"
            "\"reassembly_slot\":%zu,\"tombstone\":%zu,\"freshness_slot\":%zu,"
            "\"stream_decoder\":%zu,\"reliability_metadata_bytes\":%u,"
            "\"reassembly_metadata_bytes\":%u,\"stream_encoded_bound\":%zu,"
            "\"encoded_mtu\":%zu},\n"
            "  \"compile_only_abi_separate\":true,\n"
            "  \"target_only_unknowns\":[\"endpoint caller-owned buffer layout on this target\","
            "\"MCU allocator metadata and alignment overhead\","
            "\"MCU retained current/peak for completed endpoint request/result with loss retry\","
            "\"target largest single allocation under the production allocator\","
            "\"task stack high-water by phase\",\"static backend data and RTOS objects\"]\n}\n",
            fixture->protocol_name, fixture->name, fixture->flight_count,
            message_bytes, sender_slots, chunk_bytes, (message_bytes + chunk_bytes - 1U) / chunk_bytes,
        aggregate_phases[1].peak > aggregate_phases[5].peak ?
            aggregate_phases[1].peak : aggregate_phases[5].peak,
        aggregate_phases[1].peak > aggregate_phases[5].peak ?
            aggregate_phases[1].peak : aggregate_phases[5].peak,
            sizeof(dmp_endpoint), dmp_hs_size(), dmp_provider_size(),
            sizeof(dmp_provider_handshake), sizeof(dmp_endpoint), dmp_hs_size(),
            dmp_provider_size(), sizeof(dmp_identity_slot),
            sizeof(dmp_reliability_sender_slot), sizeof(dmp_reliability_result_slot),
            sizeof(dmp_reliability_history_slot), sizeof(dmp_reliability_correlation_slot),
            sizeof(dmp_reliability_adapter_slot), sizeof(dmp_reassembly_slot),
            sizeof(dmp_reassembly_tombstone), sizeof(dmp_endpoint_freshness_slot),
            sizeof(dmp_stream_decoder), DMP_RELIABILITY_METADATA_BYTES,
            DMP_REASSEMBLY_METADATA_BYTES, stream_bound, encoded_mtu);
    return ferror(output) == 0;
}

static const noise_fixture_probe_fixture_t *find_fixture(void)
{
    for (size_t i = 0U; i < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++i) {
        if (strcmp(noise_fixture_probe_fixtures[i].name, "nnpsk0") == 0) {
            return &noise_fixture_probe_fixtures[i];
        }
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture();
    side_result sides[2];
    FILE *output = stdout;
    const char *manifest = NULL;
    size_t message_bytes = 0U;
    size_t chunk_bytes = 0U;
    size_t encoded_mtu = 0U;
    size_t sender_slots = 0U;
    if (fixture == NULL || argc < 2) {
        fputs("usage: dmp_ram_measure --manifest FILE --output FILE\n", stderr);
        return 2;
    }
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--manifest") == 0) {
            manifest = argv[i + 1];
        }
        if (strcmp(argv[i], "--output") == 0) {
            output = fopen(argv[i + 1], "wb");
            if (output == NULL) {
                fputs("RAM measurement failed: cannot open output file\n", stderr);
                return 1;
            }
        }
    }
    if (manifest == NULL || !read_manifest_limits(manifest, &message_bytes, &chunk_bytes,
                                                   &encoded_mtu, &sender_slots) ||
        !run_side(fixture, DMP_PROVIDER_ROLE_INITIATOR, message_bytes, chunk_bytes,
                  sender_slots, &sides[0]) ||
        !run_side(fixture, DMP_PROVIDER_ROLE_RESPONDER, message_bytes, chunk_bytes,
                  sender_slots, &sides[1]) ||
        !write_report(output, fixture, sides, message_bytes, chunk_bytes, encoded_mtu,
                      sender_slots)) {
        fputs("P01B provider measurement failed: NNpsk0 fixture handshake did not complete\n", stderr);
        if (output != stdout) {
            fclose(output);
        }
        return 1;
    }
    if (output != stdout && fclose(output) != 0) {
        return 1;
    }
    printf("separate one-provider P01B NNpsk0 runs: initiator_peak=%zu responder_peak=%zu; libdmp endpoint lifecycle not measured\n",
           sides[0].phases[1].peak, sides[1].phases[1].peak);
    return 0;
}
