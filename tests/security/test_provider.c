/* Host tests for the libdmp provider adapter. Fixture keys are public test
 * material. Startup and entropy bytes come from this process, not from a
 * physical or MCU entropy source. */
#include "provider_port.h"
#include "noise_fixture_probe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CASE_BUFFER 512U

typedef struct port_ctx {
    int fail_ready;
    int fail_read;
    int fail_entropy;
    int fail_alloc;
    unsigned fail_alloc_at;
    int nonzero_release;
    unsigned alloc_calls;
    unsigned release_calls;
} port_ctx;

static int g_failures;

static void expect_case(const char *name, int passed)
{
    if (passed) {
        printf("ok %s\n", name);
        return;
    }
    fprintf(stderr, "FAIL %s\n", name);
    g_failures++;
}

static int all_zero(const void *data, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t index;

    for (index = 0U; index < size; ++index) {
        if (bytes[index] != 0U) {
            return 0;
        }
    }
    return 1;
}

static int all_value(const void *data, size_t size, uint8_t value)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t index;

    for (index = 0U; index < size; ++index) {
        if (bytes[index] != value) {
            return 0;
        }
    }
    return 1;
}

static int bytes_match(const char *what, const uint8_t *actual, size_t actual_size,
                       const uint8_t *expected, size_t expected_size)
{
    size_t index;

    if (actual_size != expected_size) {
        fprintf(stderr, "%s length %zu, expected %zu\n", what, actual_size, expected_size);
        return 0;
    }
    if (expected_size == 0U) {
        return 1;
    }
    if (actual == NULL || expected == NULL) {
        fprintf(stderr, "%s is missing a buffer\n", what);
        return 0;
    }
    for (index = 0U; index < expected_size; ++index) {
        if (actual[index] != expected[index]) {
            fprintf(stderr, "%s differs at byte %zu\n", what, index);
            return 0;
        }
    }
    return 1;
}

static int startup_ready(void *ctx)
{
    port_ctx *port = (port_ctx *)ctx;

    return port->fail_ready ? 1 : 0;
}

static int startup_read(void *ctx, void *bytes, size_t size)
{
    port_ctx *port = (port_ctx *)ctx;
    uint8_t *out = (uint8_t *)bytes;
    size_t index;

    if (port->fail_read) {
        for (index = 0U; index < size / 2U; ++index) {
            out[index] = 0xA5U;
        }
        return 1;
    }
    for (index = 0U; index < size; ++index) {
        out[index] = (uint8_t)(0x3DU + (uint8_t)index);
    }
    return 0;
}

static int entropy_fill(void *ctx, void *bytes, size_t size)
{
    port_ctx *port = (port_ctx *)ctx;
    uint8_t *out = (uint8_t *)bytes;
    size_t index;

    if (port->fail_entropy) {
        for (index = 0U; index < size; ++index) {
            out[index] = 0xA5U;
        }
        return 1;
    }
    for (index = 0U; index < size; ++index) {
        out[index] = (uint8_t)(0x71U + (uint8_t)index);
    }
    return 0;
}

static void *port_allocate(void *ctx, size_t size)
{
    port_ctx *port = (port_ctx *)ctx;

    port->alloc_calls++;
    if (port->fail_alloc || port->alloc_calls == port->fail_alloc_at || size == 0U) {
        return NULL;
    }
    return calloc(1, size);
}

static void port_release(void *ctx, void *ptr, size_t size)
{
    port_ctx *port = (port_ctx *)ctx;
    uint8_t *bytes = (uint8_t *)ptr;
    size_t index;

    port->release_calls++;
    if (bytes == NULL) {
        port->nonzero_release = 1;
        return;
    }
    for (index = 0U; index < size; ++index) {
        if (bytes[index] != 0U) {
            port->nonzero_release = 1;
            break;
        }
    }
    free(ptr);
}

static void set_ports(dmp_provider_ports *ports, port_ctx *ctx, size_t scratch,
                      size_t retained)
{
    memset(ports, 0, sizeof(*ports));
    ports->startup_ready = startup_ready;
    ports->startup_read = startup_read;
    ports->entropy = entropy_fill;
    ports->allocate = port_allocate;
    ports->release = port_release;
    ports->ctx = ctx;
    ports->scratch_limit = scratch;
    ports->retained_limit = retained;
}

static const noise_fixture_probe_fixture_t *find_fixture(const char *name)
{
    size_t index;

    for (index = 0U; index < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++index) {
        if (strcmp(noise_fixture_probe_fixtures[index].name, name) == 0) {
            return &noise_fixture_probe_fixtures[index];
        }
    }
    return NULL;
}

static const noise_fixture_probe_packet_t *find_packet(
    const noise_fixture_probe_fixture_t *fixture, uint8_t direction, uint64_t pn)
{
    size_t index;

    for (index = 0U; index < fixture->transport_packet_count; ++index) {
        const noise_fixture_probe_packet_t *packet = &fixture->transport_packets[index];

        if (packet->direction == direction && packet->pn == pn) {
            return packet;
        }
    }
    return NULL;
}

static void fill_keys(const noise_fixture_probe_fixture_t *fixture, int role,
                      const uint8_t *psk, dmp_provider_handshake_keys *keys)
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
    if (psk != NULL) {
        keys->psk = psk;
        keys->psk_len = 32U;
    } else if (fixture->psk.size != 0U) {
        keys->psk = fixture->psk.data;
        keys->psk_len = fixture->psk.size;
    }
    keys->prologue = fixture->prologue.data;
    keys->prologue_len = fixture->prologue.size;
}

static int load_encrypted(const noise_fixture_probe_packet_t *packet, uint8_t *out,
                          size_t cap, size_t *length)
{
    if (packet->tag.size > cap || packet->ciphertext.size > cap - packet->tag.size) {
        return 0;
    }
    if (packet->ciphertext.size != 0U) {
        memcpy(out, packet->ciphertext.data, packet->ciphertext.size);
    }
    memcpy(out + packet->ciphertext.size, packet->tag.data, packet->tag.size);
    *length = packet->ciphertext.size + packet->tag.size;
    return 1;
}

static int release_clean(const port_ctx *port, const char *what)
{
    if (!port->nonzero_release) {
        return 1;
    }
    fprintf(stderr, "%s: a released block still held secret bytes\n", what);
    return 0;
}

static int test_init(void)
{
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_handshake handshake;
    dmp_provider_handshake_keys keys;
    dmp_provider_status status;
    int passed = 0;

    memset(&port, 0, sizeof(port));
    memset(&handshake, 0, sizeof(handshake));
    memset(&keys, 0, sizeof(keys));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    port.fail_ready = 1;
    status = dmp_provider_setup(provider, &ports);
    if (status != DMP_PROVIDER_SETUP_FAILED ||
        dmp_provider_handshake_open(provider, &handshake, "Noise_NNpsk0_25519_ChaChaPoly_SHA256",
                                    DMP_PROVIDER_ROLE_INITIATOR, &keys) != DMP_PROVIDER_INVALID) {
        fprintf(stderr, "init ready failure did not stay closed\n");
        goto done;
    }
    port.fail_ready = 0;
    port.fail_read = 1;
    status = dmp_provider_setup(provider, &ports);
    if (status != DMP_PROVIDER_SETUP_FAILED) {
        fprintf(stderr, "init read failure status %d\n", (int)status);
        goto done;
    }
    port.fail_read = 0;
    status = dmp_provider_setup(provider, &ports);
    if (status != DMP_PROVIDER_OK) {
        fprintf(stderr, "init retry status %d\n", (int)status);
        goto done;
    }
    dmp_provider_cleanup(provider);
    passed = all_zero(provider, dmp_provider_size()) && release_clean(&port, "init");

done:
    free(provider);
    return passed;
}

static int test_entropy(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_handshake handshake;
    dmp_provider_handshake_keys keys;
    uint8_t message[CASE_BUFFER];
    size_t message_len = 99U;
    dmp_provider_status status;
    int passed = 0;

    if (fixture == NULL) {
        fprintf(stderr, "missing nnpsk0 fixture\n");
        return 0;
    }
    memset(&port, 0, sizeof(port));
    memset(&handshake, 0, sizeof(handshake));
    memset(message, 0x11, sizeof(message));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) {
        goto done;
    }
    fill_keys(fixture, DMP_PROVIDER_ROLE_INITIATOR, NULL, &keys);
    keys.local_ephemeral = NULL;
    keys.local_ephemeral_len = 0U;
    port.fail_entropy = 1;
    if (dmp_provider_handshake_open(provider, &handshake, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_INITIATOR, &keys) != DMP_PROVIDER_OK) {
        fprintf(stderr, "entropy case could not open a handshake\n");
        goto done;
    }
    status = dmp_provider_handshake_write(provider, &handshake, NULL, 0U, message,
                                          sizeof(message), &message_len);
    if (status != DMP_PROVIDER_ENTROPY_FAILED || message_len != 0U ||
        !all_zero(message, sizeof(message))) {
        fprintf(stderr, "entropy failure status %d length %zu\n", (int)status, message_len);
        goto done;
    }
    message_len = 99U;
    memset(message, 0x22, sizeof(message));
    status = dmp_provider_handshake_write(provider, &handshake, NULL, 0U, message,
                                          sizeof(message), &message_len);
    if (status == DMP_PROVIDER_OK || message_len != 0U) {
        fprintf(stderr, "failed handshake resumed\n");
        goto done;
    }
    if (dmp_provider_handshake_close(provider, &handshake) != DMP_PROVIDER_OK) {
        goto done;
    }
    port.fail_entropy = 0;
    fill_keys(fixture, DMP_PROVIDER_ROLE_INITIATOR, NULL, &keys);
    if (dmp_provider_handshake_open(provider, &handshake, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_INITIATOR, &keys) != DMP_PROVIDER_OK) {
        fprintf(stderr, "fresh handshake after entropy failure was rejected\n");
        goto done;
    }
    memset(message, 0, sizeof(message));
    status = dmp_provider_handshake_write(provider, &handshake, NULL, 0U, message,
                                          sizeof(message), &message_len);
    if (status != DMP_PROVIDER_OK || message_len == 0U) {
        fprintf(stderr, "fresh handshake produced no flight\n");
        goto done;
    }
    passed = dmp_provider_handshake_close(provider, &handshake) == DMP_PROVIDER_OK &&
             all_zero(&handshake, sizeof(handshake)) && release_clean(&port, "entropy");
    dmp_provider_cleanup(provider);
    passed = passed && all_zero(provider, dmp_provider_size());

done:
    if (!passed) {
        dmp_provider_cleanup(provider);
    }
    free(provider);
    return passed;
}

static int test_oom(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_handshake handshake;
    dmp_provider_handshake_keys keys;
    int passed = 0;

    if (fixture == NULL) {
        return 0;
    }
    memset(&port, 0, sizeof(port));
    memset(&handshake, 0, sizeof(handshake));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, 1U, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) {
        fprintf(stderr, "oom setup failed\n");
        goto done;
    }
    fill_keys(fixture, DMP_PROVIDER_ROLE_INITIATOR, NULL, &keys);
    if (dmp_provider_handshake_open(provider, &handshake, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_INITIATOR, &keys) != DMP_PROVIDER_NO_MEMORY ||
        port.alloc_calls != 0U || dmp_provider_block_count(provider) != 0U) {
        fprintf(stderr, "scratch limit did not fail closed (allocs %u blocks %zu)\n",
                port.alloc_calls, dmp_provider_block_count(provider));
        goto done;
    }
    dmp_provider_cleanup(provider);
    memset(&port, 0, sizeof(port));
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) {
        goto done;
    }
    port.fail_alloc = 1;
    port.alloc_calls = 0U;
    if (dmp_provider_handshake_open(provider, &handshake, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_INITIATOR, &keys) != DMP_PROVIDER_NO_MEMORY ||
        port.alloc_calls == 0U || dmp_provider_block_count(provider) != 0U) {
        fprintf(stderr, "storage failure did not fail closed\n");
        goto done;
    }
    passed = release_clean(&port, "oom") && all_zero(&handshake, sizeof(handshake));
    dmp_provider_cleanup(provider);
    passed = passed && all_zero(provider, dmp_provider_size());

done:
    if (!passed) {
        dmp_provider_cleanup(provider);
    }
    free(provider);
    return passed;
}

static int sweep_handshake_open_allocations(
    dmp_provider *provider, port_ctx *port,
    const noise_fixture_probe_fixture_t *fixture, int role,
    dmp_provider_handshake *handshake,
    unsigned *failed_ordinals, unsigned *success_boundary)
{
    enum { MAX_FAIL_ORDINAL = 64U };
    dmp_provider_handshake_keys keys;
    unsigned ordinal;

    *failed_ordinals = 0U;
    *success_boundary = 0U;
    memset(handshake, 0, sizeof(*handshake));
    fill_keys(fixture, role, NULL, &keys);

    for (ordinal = 1U; ordinal <= MAX_FAIL_ORDINAL; ++ordinal) {
        unsigned calls_before = port->alloc_calls;
        unsigned calls_used;
        dmp_provider_status status;

        memset(handshake, 0xA5, sizeof(*handshake));
        port->fail_alloc_at = calls_before + ordinal;
        status = dmp_provider_handshake_open(provider, handshake, fixture->protocol_name,
                                             role, &keys);
        port->fail_alloc_at = 0U;
        calls_used = port->alloc_calls - calls_before;

        if (status == DMP_PROVIDER_NO_MEMORY && calls_used == ordinal) {
            if (!all_zero(handshake, sizeof(*handshake)) ||
                dmp_provider_block_count(provider) != 0U ||
                dmp_provider_retained(provider) != 0U || !release_clean(port, "open OOM")) {
                fprintf(stderr,
                        "%s role=%d ordinal %u leaked state: blocks=%zu retained=%zu zero=%d\n",
                        fixture->name, role, ordinal, dmp_provider_block_count(provider),
                        dmp_provider_retained(provider), all_zero(handshake, sizeof(*handshake)));
                return 0;
            }
            ++*failed_ordinals;

            /* A failed constructor must leave the same provider usable. */
            memset(handshake, 0xA5, sizeof(*handshake));
            status = dmp_provider_handshake_open(provider, handshake,
                                                 fixture->protocol_name, role, &keys);
            if (status != DMP_PROVIDER_OK ||
                dmp_provider_handshake_close(provider, handshake) != DMP_PROVIDER_OK ||
                !all_zero(handshake, sizeof(*handshake)) ||
                dmp_provider_block_count(provider) != 0U ||
                dmp_provider_retained(provider) != 0U ||
                !release_clean(port, "open OOM recovery")) {
                fprintf(stderr, "%s role=%d provider recovery failed at ordinal %u\n",
                        fixture->name, role, ordinal);
                return 0;
            }
            continue;
        }

        /* The first ordinal beyond all constructor allocations must succeed. */
        if (status == DMP_PROVIDER_OK && calls_used < ordinal &&
            dmp_provider_handshake_close(provider, handshake) == DMP_PROVIDER_OK &&
            all_zero(handshake, sizeof(*handshake)) &&
            dmp_provider_block_count(provider) == 0U &&
            dmp_provider_retained(provider) == 0U &&
            release_clean(port, "open allocation sweep boundary")) {
            *success_boundary = ordinal;
            return *failed_ordinals != 0U;
        }

        fprintf(stderr,
                "%s role=%d ordinal %u unexpected status=%d calls=%u blocks=%zu retained=%zu\n",
                fixture->name, role, ordinal, (int)status, calls_used,
                dmp_provider_block_count(provider), dmp_provider_retained(provider));
        port->fail_alloc_at = 0U;
        return 0;
    }

    fprintf(stderr, "%s role=%d allocation sweep exceeded %u ordinals\n",
            fixture->name, role, MAX_FAIL_ORDINAL);
    return 0;
}

static int test_handshake_open_allocation_sweep(void)
{
    const noise_fixture_probe_fixture_t *fixtures[] = {
        find_fixture("nnpsk0"), find_fixture("xx")
    };
    const int roles[] = {DMP_PROVIDER_ROLE_INITIATOR, DMP_PROVIDER_ROLE_RESPONDER};
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_handshake handshake;
    size_t fixture_index;
    size_t role_index;
    int passed = 0;

    if (fixtures[0] == NULL || fixtures[1] == NULL)
        return 0;
    memset(&port, 0, sizeof(port));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL)
        return 0;
    memset(&handshake, 0, sizeof(handshake));
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK)
        goto done;

    for (fixture_index = 0U; fixture_index < sizeof(fixtures) / sizeof(fixtures[0]);
         ++fixture_index) {
        for (role_index = 0U; role_index < sizeof(roles) / sizeof(roles[0]); ++role_index) {
            unsigned failed_ordinals;
            unsigned success_boundary;
            if (!sweep_handshake_open_allocations(provider, &port, fixtures[fixture_index],
                                                  roles[role_index], &handshake, &failed_ordinals,
                                                  &success_boundary))
                goto done;
            printf("%s role=%s handshake-open sweep: %u failing ordinals; boundary %u\n",
                   fixtures[fixture_index]->name,
                   roles[role_index] == DMP_PROVIDER_ROLE_INITIATOR
                       ? "initiator" : "responder",
                   failed_ordinals, success_boundary);
        }
    }
    passed = 1;

done:
    dmp_provider_cleanup(provider);
    passed = passed && all_zero(provider, dmp_provider_size()) &&
             all_zero(&handshake, sizeof(handshake)) &&
             release_clean(&port, "open sweep cleanup");
    free(provider);
    return passed;
}

static int test_dh_shared_allocation_failure(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    uint8_t shared[32];
    uint8_t public_key[32];
    unsigned releases_before;
    unsigned ordinal;
    dmp_provider_status status;
    int passed = 0;

    if (fixture == NULL) {
        return 0;
    }
    memset(&port, 0, sizeof(port));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) {
        goto done;
    }

    /* Public-key construction has one owned Noise state; failure must wipe
     * the caller output without disturbing provider accounting. */
    memset(public_key, 0xA5, sizeof(public_key));
    releases_before = port.release_calls;
    port.fail_alloc_at = port.alloc_calls + 1U;
    status = dmp_provider_dh_public(provider, fixture->init_ephemeral.data, public_key);
    port.fail_alloc_at = 0U;
    if (status != DMP_PROVIDER_NO_MEMORY || !all_zero(public_key, sizeof(public_key)) ||
        dmp_provider_block_count(provider) != 0U || dmp_provider_retained(provider) != 0U ||
        port.release_calls != releases_before) {
        fprintf(stderr, "DH public allocation failure status=%d releases=%u/%u output_zero=%d\n",
                (int)status, port.release_calls, releases_before,
                all_zero(public_key, sizeof(public_key)));
        goto done;
    }

    for (ordinal = 1U; ordinal <= 3U; ++ordinal) {
        unsigned calls_before = port.alloc_calls;
        unsigned calls_used;

        memset(shared, 0xA5, sizeof(shared));
        releases_before = port.release_calls;
        port.fail_alloc_at = calls_before + ordinal;
        status = dmp_provider_dh_shared(provider, fixture->init_ephemeral.data,
                                        fixture->resp_ephemeral.data, shared);
        port.fail_alloc_at = 0U;
        calls_used = port.alloc_calls - calls_before;

        if (ordinal <= 2U) {
            unsigned expected_release_delta = ordinal - 1U;
            if (status != DMP_PROVIDER_NO_MEMORY || calls_used != ordinal ||
                !all_zero(shared, sizeof(shared)) ||
                dmp_provider_block_count(provider) != 0U ||
                dmp_provider_retained(provider) != 0U ||
                port.release_calls - releases_before != expected_release_delta ||
                !release_clean(&port, "DH shared OOM ordinal")) {
                fprintf(stderr,
                        "DH shared OOM ordinal %u status=%d calls=%u releases=%u/%u "
                        "blocks=%zu retained=%zu output_zero=%d\n",
                        ordinal, (int)status, calls_used, port.release_calls, releases_before,
                        dmp_provider_block_count(provider), dmp_provider_retained(provider),
                        all_zero(shared, sizeof(shared)));
                goto done;
            }

            /* Each failed allocation leaves the same provider usable. */
            memset(shared, 0, sizeof(shared));
            status = dmp_provider_dh_shared(provider, fixture->init_ephemeral.data,
                                            fixture->resp_ephemeral.data, shared);
            if (status != DMP_PROVIDER_OK || all_zero(shared, sizeof(shared)) ||
                dmp_provider_block_count(provider) != 0U ||
                dmp_provider_retained(provider) != 0U ||
                !release_clean(&port, "DH shared OOM recovery")) {
                fprintf(stderr, "DH shared provider recovery failed after ordinal %u\n",
                        ordinal);
                goto done;
            }
            continue;
        }

        if (status != DMP_PROVIDER_OK || calls_used != 2U || all_zero(shared, sizeof(shared)) ||
            dmp_provider_block_count(provider) != 0U ||
            dmp_provider_retained(provider) != 0U ||
            port.release_calls - releases_before != 2U ||
            !release_clean(&port, "DH shared allocation boundary")) {
            fprintf(stderr,
                    "DH shared boundary ordinal %u status=%d calls=%u releases=%u/%u "
                    "blocks=%zu retained=%zu output_zero=%d\n",
                    ordinal, (int)status, calls_used, port.release_calls, releases_before,
                    dmp_provider_block_count(provider), dmp_provider_retained(provider),
                    all_zero(shared, sizeof(shared)));
            goto done;
        }
    }
    printf("DH shared allocation sweep: 2 failing ordinals; boundary 3\n");
    passed = 1;

done:
    dmp_provider_cleanup(provider);
    passed = passed && all_zero(provider, dmp_provider_size());
    free(provider);
    return passed;
}

static int exchange(dmp_provider *provider, const noise_fixture_probe_fixture_t *fixture,
                    dmp_provider_handshake *initiator, dmp_provider_handshake *responder,
                    int compare)
{
    dmp_provider_handshake_keys init_keys;
    dmp_provider_handshake_keys resp_keys;
    uint8_t message[CASE_BUFFER];
    uint8_t payload[CASE_BUFFER];
    uint8_t init_hash[32];
    uint8_t resp_hash[32];
    size_t index;

    fill_keys(fixture, DMP_PROVIDER_ROLE_INITIATOR, NULL, &init_keys);
    fill_keys(fixture, DMP_PROVIDER_ROLE_RESPONDER, NULL, &resp_keys);
    if (dmp_provider_handshake_open(provider, initiator, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_INITIATOR, &init_keys) != DMP_PROVIDER_OK ||
        dmp_provider_handshake_open(provider, responder, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_RESPONDER, &resp_keys) != DMP_PROVIDER_OK) {
        fprintf(stderr, "%s: handshake open failed\n", fixture->name);
        return 0;
    }
    for (index = 0U; index < fixture->flight_count; ++index) {
        const noise_fixture_probe_flight_t *flight = &fixture->flights[index];
        dmp_provider_handshake *sender = (index % 2U) == 0U ? initiator : responder;
        dmp_provider_handshake *receiver = (index % 2U) == 0U ? responder : initiator;
        size_t message_len = 0U;
        size_t payload_len = 0U;
        dmp_provider_status status;

        memset(message, 0x5A, sizeof(message));
        status = dmp_provider_handshake_write(
            provider, sender, flight->plaintext.data, flight->plaintext.size, message,
            sizeof(message), &message_len);
        if (status != DMP_PROVIDER_OK) {
            fprintf(stderr, "%s: flight %zu write status %d\n", fixture->name, index, (int)status);
            return 0;
        }
        if (compare && !bytes_match("flight", message, message_len, flight->message.data,
                                    flight->message.size)) {
            return 0;
        }
        memset(payload, 0xA5, sizeof(payload));
        status = dmp_provider_handshake_read(provider, receiver, message, message_len, payload,
                                             sizeof(payload), &payload_len);
        if (status != DMP_PROVIDER_OK) {
            fprintf(stderr, "%s: flight %zu read status %d\n", fixture->name, index, (int)status);
            return 0;
        }
        if (compare && !bytes_match("flight plaintext", payload, payload_len,
                                    flight->plaintext.data, flight->plaintext.size)) {
            return 0;
        }
    }
    if (!compare) {
        return 1;
    }
    if (dmp_provider_handshake_hash(provider, initiator, init_hash) != DMP_PROVIDER_OK ||
        dmp_provider_handshake_hash(provider, responder, resp_hash) != DMP_PROVIDER_OK) {
        fprintf(stderr, "%s: handshake hash failed\n", fixture->name);
        return 0;
    }
    return bytes_match("initiator hash", init_hash, sizeof(init_hash),
                       fixture->handshake_hash.data, fixture->handshake_hash.size) &&
           bytes_match("responder hash", resp_hash, sizeof(resp_hash),
                       fixture->handshake_hash.data, fixture->handshake_hash.size);
}

static int test_output_contract(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_handshake handshake;
    dmp_provider_handshake_keys keys;
    dmp_provider_cipher cipher;
    uint8_t output[64];
    size_t output_len;
    dmp_provider_status status;
    int passed = 0;

    if (fixture == NULL || fixture->flight_count == 0U) {
        return 0;
    }
    memset(&port, 0, sizeof(port));
    memset(&handshake, 0, sizeof(handshake));
    memset(&cipher, 0, sizeof(cipher));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) {
        goto done;
    }
    fill_keys(fixture, DMP_PROVIDER_ROLE_INITIATOR, NULL, &keys);
    if (dmp_provider_handshake_open(provider, &handshake, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_INITIATOR, &keys) != DMP_PROVIDER_OK) {
        goto done;
    }

    memset(output, 0xA5, 32U);
    status = dmp_provider_handshake_remote_public(provider, &handshake, output);
    if (status != DMP_PROVIDER_REJECTED || !all_zero(output, 32U)) {
        fprintf(stderr, "remote-public before peer key did not reject and wipe output\n");
        goto done;
    }

    memset(output, 0xD4, 32U);
    status = dmp_provider_handshake_remote_public(provider, NULL, output);
    if (status != DMP_PROVIDER_INVALID || !all_value(output, 32U, 0xD4U)) {
        fprintf(stderr, "remote-public null-handshake validation changed caller output\n");
        goto done;
    }

    memset(output, 0xA5, sizeof(output));
    output_len = 0x1234U;
    status = dmp_provider_handshake_write(provider, &handshake, NULL, 1U, output,
                                          sizeof(output), &output_len);
    if (status != DMP_PROVIDER_INVALID || output_len != 0x1234U ||
        !all_value(output, sizeof(output), 0xA5U)) {
        fprintf(stderr, "handshake-write validation changed caller output\n");
        goto done;
    }
    memset(output, 0xB6, sizeof(output));
    output_len = 0x1357U;
    status = dmp_provider_handshake_read(provider, &handshake, NULL, 1U, output,
                                         sizeof(output), &output_len);
    if (status != DMP_PROVIDER_INVALID || output_len != 0x1357U ||
        !all_value(output, sizeof(output), 0xB6U)) {
        fprintf(stderr, "handshake-read validation changed caller output\n");
        goto done;
    }

    if (dmp_provider_handshake_close(provider, &handshake) != DMP_PROVIDER_OK) {
        goto done;
    }
    memset(output, 0xE5, 32U);
    status = dmp_provider_handshake_remote_public(provider, &handshake, output);
    if (status != DMP_PROVIDER_INVALID || !all_zero(output, 32U)) {
        fprintf(stderr, "remote-public closed-handshake failure did not wipe output\n");
        goto done;
    }
    if (dmp_provider_handshake_open(provider, &handshake, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_INITIATOR, &keys) != DMP_PROVIDER_OK) {
        goto done;
    }
    memset(output, 0xA5, sizeof(output));
    output_len = 0x1234U;
    status = dmp_provider_handshake_write(
        provider, &handshake, fixture->flights[0].plaintext.data,
        fixture->flights[0].plaintext.size, output, 1U, &output_len);
    if (status == DMP_PROVIDER_OK || output_len != 0U || !all_zero(output, 1U) ||
        !all_value(output + 1U, sizeof(output) - 1U, 0xA5U)) {
        fprintf(stderr, "short handshake-write output was not bounded and wiped\n");
        goto done;
    }

    if (dmp_provider_cipher_from_key(provider, &cipher, fixture->i_to_r_key.data,
                                     fixture->i_to_r_key.size) != DMP_PROVIDER_OK) {
        goto done;
    }
    memset(output, 0x5A, sizeof(output));
    output_len = 0x2345U;
    status = dmp_provider_cipher_encrypt(provider, &cipher, UINT64_MAX, NULL, 0U,
                                         output, 3U, sizeof(output), &output_len);
    if (status != DMP_PROVIDER_INVALID || output_len != 0x2345U ||
        !all_value(output, sizeof(output), 0x5AU)) {
        fprintf(stderr, "cipher-encrypt validation changed caller output\n");
        goto done;
    }

    memcpy(output, "abc", 3U);
    memset(output + 3U, 0x5A, sizeof(output) - 3U);
    output_len = 0x3456U;
    status = dmp_provider_cipher_encrypt(provider, &cipher, 0U, NULL, 0U,
                                         output, 3U, 3U, &output_len);
    if (status == DMP_PROVIDER_OK || output_len != 0U || !all_zero(output, 3U) ||
        !all_value(output + 3U, sizeof(output) - 3U, 0x5AU)) {
        fprintf(stderr, "short cipher-encrypt output was not bounded and wiped\n");
        goto done;
    }

    memset(output, 0xC3, sizeof(output));
    output_len = 0x4567U;
    status = dmp_provider_cipher_decrypt(provider, &cipher, 0U, NULL, 0U,
                                         output, 4U, 3U, &output_len);
    if (status != DMP_PROVIDER_INVALID || output_len != 0x4567U ||
        !all_value(output, sizeof(output), 0xC3U)) {
        fprintf(stderr, "cipher-decrypt validation changed caller output\n");
        goto done;
    }

    passed = dmp_provider_cipher_close(provider, &cipher) == DMP_PROVIDER_OK &&
             dmp_provider_handshake_close(provider, &handshake) == DMP_PROVIDER_OK &&
             dmp_provider_block_count(provider) == 0U && dmp_provider_retained(provider) == 0U &&
             release_clean(&port, "output contract");
    dmp_provider_cleanup(provider);
    passed = passed && all_zero(provider, dmp_provider_size());

done:
    if (!passed) {
        dmp_provider_cleanup(provider);
    }
    free(provider);
    return passed;
}

static int test_wrong_psk(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_handshake initiator;
    dmp_provider_handshake responder;
    dmp_provider_handshake_keys init_keys;
    dmp_provider_handshake_keys resp_keys;
    uint8_t bad_psk[32];
    uint8_t message[CASE_BUFFER];
    uint8_t payload[CASE_BUFFER];
    size_t message_len = 0U;
    size_t payload_len = 7U;
    int passed = 0;

    if (fixture == NULL || fixture->psk.size != 32U || fixture->flight_count < 1U) {
        return 0;
    }
    memset(&port, 0, sizeof(port));
    memset(&initiator, 0, sizeof(initiator));
    memset(&responder, 0, sizeof(responder));
    memcpy(bad_psk, fixture->psk.data, sizeof(bad_psk));
    bad_psk[31] ^= 0x01U;
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) {
        goto done;
    }
    fill_keys(fixture, DMP_PROVIDER_ROLE_INITIATOR, NULL, &init_keys);
    fill_keys(fixture, DMP_PROVIDER_ROLE_RESPONDER, bad_psk, &resp_keys);
    if (dmp_provider_handshake_open(provider, &initiator, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_INITIATOR, &init_keys) != DMP_PROVIDER_OK ||
        dmp_provider_handshake_open(provider, &responder, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_RESPONDER, &resp_keys) != DMP_PROVIDER_OK) {
        fprintf(stderr, "wrong-PSK open failed\n");
        goto done;
    }
    if (dmp_provider_handshake_write(provider, &initiator, fixture->flights[0].plaintext.data,
                                     fixture->flights[0].plaintext.size, message, sizeof(message),
                                     &message_len) != DMP_PROVIDER_OK ||
        !bytes_match("wrong-PSK flight", message, message_len, fixture->flights[0].message.data,
                     fixture->flights[0].message.size)) {
        goto done;
    }
    memset(payload, 0xA5, sizeof(payload));
    if (dmp_provider_handshake_read(provider, &responder, message, message_len, payload,
                                    sizeof(payload), &payload_len) != DMP_PROVIDER_REJECTED ||
        payload_len != 0U || !all_zero(payload, sizeof(payload))) {
        fprintf(stderr, "wrong-PSK read published output\n");
        goto done;
    }
    {
        dmp_provider_cipher send;
        dmp_provider_cipher receive;

        memset(&send, 0, sizeof(send));
        memset(&receive, 0, sizeof(receive));
        if (dmp_provider_handshake_split(provider, &responder, &send, &receive) !=
            DMP_PROVIDER_REJECTED) {
            fprintf(stderr, "wrong-PSK split was accepted\n");
            goto done;
        }
    }
    passed = dmp_provider_handshake_close(provider, &initiator) == DMP_PROVIDER_OK &&
             dmp_provider_handshake_close(provider, &responder) == DMP_PROVIDER_OK &&
             all_zero(&initiator, sizeof(initiator)) && all_zero(&responder, sizeof(responder)) &&
             release_clean(&port, "wrong-PSK");
    dmp_provider_cleanup(provider);

done:
    memset(bad_psk, 0, sizeof(bad_psk));
    if (!passed) {
        dmp_provider_cleanup(provider);
    }
    free(provider);
    return passed;
}

static int reject_low_order(dmp_provider *provider, const uint8_t private_key[32],
                            const uint8_t public_key[32], const char *what)
{
    uint8_t shared[32];
    dmp_provider_status status;

    memset(shared, 0xA5, sizeof(shared));
    status = dmp_provider_dh_shared(provider, private_key, public_key, shared);
    if (status == DMP_PROVIDER_REJECTED && all_zero(shared, sizeof(shared))) {
        return 1;
    }
    fprintf(stderr, "%s low-order status %d\n", what, (int)status);
    return 0;
}

static int test_low_order(void)
{
    const noise_fixture_probe_fixture_t *nn = find_fixture("nnpsk0");
    const noise_fixture_probe_fixture_t *xx = find_fixture("xx");
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider = NULL;
    dmp_provider_handshake initiator;
    dmp_provider_handshake responder;
    dmp_provider_handshake extra;
    uint8_t public_key[32];
    uint8_t shared[32];
    uint8_t low[32];
    uint8_t message[CASE_BUFFER];
    uint8_t mutated[CASE_BUFFER];
    uint8_t payload[CASE_BUFFER];
    size_t message_len = 0U;
    size_t payload_len = 1U;
    int passed = 0;

    if (nn == NULL || xx == NULL) {
        return 0;
    }
    memset(&port, 0, sizeof(port));
    memset(&initiator, 0, sizeof(initiator));
    memset(&responder, 0, sizeof(responder));
    memset(&extra, 0, sizeof(extra));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) {
        goto done;
    }
    if (dmp_provider_dh_public(provider, nn->resp_ephemeral.data, public_key) != DMP_PROVIDER_OK ||
        all_zero(public_key, sizeof(public_key)) ||
        dmp_provider_dh_shared(provider, nn->init_ephemeral.data, public_key, shared) !=
            DMP_PROVIDER_OK ||
        all_zero(shared, sizeof(shared))) {
        fprintf(stderr, "valid X25519 shared secret was rejected\n");
        goto done;
    }
    memset(low, 0, sizeof(low));
    if (!reject_low_order(provider, nn->init_ephemeral.data, low, "all-zero") ||
        !reject_low_order(provider, xx->init_static.data, low, "static all-zero")) {
        goto done;
    }
    low[0] = 1U;
    if (!reject_low_order(provider, nn->init_ephemeral.data, low, "u=1") ||
        !reject_low_order(provider, xx->init_static.data, low, "static u=1")) {
        goto done;
    }
    memset(low, 0, sizeof(low));
    low[31] = 0x80U;
    if (!reject_low_order(provider, nn->resp_ephemeral.data, low, "high-bit")) {
        goto done;
    }
    low[0] = 1U;
    if (!reject_low_order(provider, xx->resp_static.data, low, "static combined")) {
        goto done;
    }
    {
        dmp_provider_handshake_keys init_keys;
        dmp_provider_handshake_keys resp_keys;

        fill_keys(nn, DMP_PROVIDER_ROLE_INITIATOR, NULL, &init_keys);
        fill_keys(nn, DMP_PROVIDER_ROLE_RESPONDER, NULL, &resp_keys);
        if (dmp_provider_handshake_open(provider, &initiator, nn->protocol_name,
                                        DMP_PROVIDER_ROLE_INITIATOR, &init_keys) != DMP_PROVIDER_OK ||
            dmp_provider_handshake_open(provider, &responder, nn->protocol_name,
                                        DMP_PROVIDER_ROLE_RESPONDER, &resp_keys) != DMP_PROVIDER_OK) {
            goto done;
        }
    }
    if (dmp_provider_handshake_write(provider, &initiator, nn->flights[0].plaintext.data,
                                     nn->flights[0].plaintext.size, message, sizeof(message),
                                     &message_len) != DMP_PROVIDER_OK ||
        message_len < 32U) {
        fprintf(stderr, "low-order flight was not written\n");
        goto done;
    }
    memcpy(mutated, message, message_len);
    memset(mutated, 0, 32U);
    mutated[0] = 1U;
    {
        dmp_provider_handshake_keys extra_keys;

        fill_keys(nn, DMP_PROVIDER_ROLE_RESPONDER, NULL, &extra_keys);
        if (dmp_provider_handshake_open(provider, &extra, nn->protocol_name,
                                        DMP_PROVIDER_ROLE_RESPONDER, &extra_keys) != DMP_PROVIDER_OK) {
            goto done;
        }
    }
    memset(payload, 0xA5, sizeof(payload));
    if (dmp_provider_handshake_read(provider, &extra, mutated, message_len, payload, sizeof(payload),
                                    &payload_len) != DMP_PROVIDER_REJECTED ||
        payload_len != 0U || !all_zero(payload, sizeof(payload))) {
        fprintf(stderr, "low-order ephemeral read published plaintext\n");
        goto done;
    }
    if (dmp_provider_handshake_read(provider, &responder, message, message_len, payload,
                                    sizeof(payload), &payload_len) != DMP_PROVIDER_OK) {
        fprintf(stderr, "valid flight was rejected after a low-order read\n");
        goto done;
    }
    passed = dmp_provider_handshake_close(provider, &initiator) == DMP_PROVIDER_OK &&
             dmp_provider_handshake_close(provider, &responder) == DMP_PROVIDER_OK &&
             dmp_provider_handshake_close(provider, &extra) == DMP_PROVIDER_OK &&
             release_clean(&port, "low-order");
    dmp_provider_cleanup(provider);

done:
    if (provider != NULL && !passed) {
        dmp_provider_cleanup(provider);
    }
    free(provider);
    return passed;
}

static int encrypt_packet(dmp_provider *provider, dmp_provider_cipher *cipher,
                          const noise_fixture_probe_packet_t *packet, const char *what)
{
    uint8_t buffer[CASE_BUFFER];
    size_t out_len = 0U;

    if (packet == NULL || packet->plaintext.size + packet->tag.size > sizeof(buffer) ||
        packet->aad.size == 0U) {
        fprintf(stderr, "%s: packet is missing or empty AAD\n", what);
        return 0;
    }
    memset(buffer, 0, sizeof(buffer));
    if (packet->plaintext.size != 0U) {
        memcpy(buffer, packet->plaintext.data, packet->plaintext.size);
    }
    if (dmp_provider_cipher_encrypt(provider, cipher, packet->pn, packet->aad.data, packet->aad.size,
                                    buffer, packet->plaintext.size, sizeof(buffer),
                                    &out_len) != DMP_PROVIDER_OK) {
        fprintf(stderr, "%s: encrypt failed\n", what);
        return 0;
    }
    if (out_len != packet->ciphertext.size + packet->tag.size ||
        !bytes_match("ciphertext", buffer, packet->ciphertext.size, packet->ciphertext.data,
                     packet->ciphertext.size) ||
        !bytes_match("tag", buffer + packet->ciphertext.size, packet->tag.size, packet->tag.data,
                     packet->tag.size)) {
        return 0;
    }
    return 1;
}

static int decrypt_packet(dmp_provider *provider, dmp_provider_cipher *cipher,
                          const noise_fixture_probe_packet_t *packet, const uint8_t *aad,
                          size_t aad_len, int corrupt_tag, int expect_ok, const char *what)
{
    uint8_t buffer[CASE_BUFFER];
    size_t cipher_len = 0U;
    size_t out_len = 3U;

    memset(buffer, 0x5A, sizeof(buffer));
    if (!load_encrypted(packet, buffer, sizeof(buffer), &cipher_len)) {
        return 0;
    }
    if (corrupt_tag && cipher_len != 0U) {
        buffer[cipher_len - 1U] ^= 0x01U;
    }
    if (dmp_provider_cipher_decrypt(provider, cipher, packet->pn, aad, aad_len, buffer, cipher_len,
                                    sizeof(buffer), &out_len) !=
        (expect_ok ? DMP_PROVIDER_OK : DMP_PROVIDER_REJECTED)) {
        fprintf(stderr, "%s: unexpected decrypt result\n", what);
        return 0;
    }
    if (!expect_ok) {
        if (out_len != 0U || !all_zero(buffer, sizeof(buffer))) {
            fprintf(stderr, "%s: failed decrypt published output\n", what);
            return 0;
        }
        return 1;
    }
    return bytes_match(what, buffer, out_len, packet->plaintext.data, packet->plaintext.size);
}

static int test_pn_aad(const noise_fixture_probe_fixture_t *fixture)
{
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_cipher send;
    dmp_provider_cipher once;
    dmp_provider_cipher receive;
    const noise_fixture_probe_packet_t *pn0;
    const noise_fixture_probe_packet_t *pn1;
    const noise_fixture_probe_packet_t *pn2;
    const noise_fixture_probe_packet_t *high;
    uint8_t bad_aad[CASE_BUFFER];
    uint8_t custom[64];
    size_t custom_len = 0U;
    int passed = 0;

    pn0 = find_packet(fixture, 0U, 0U);
    pn1 = find_packet(fixture, 0U, 1U);
    pn2 = find_packet(fixture, 0U, 2U);
    high = find_packet(fixture, 0U, 128U);
    if (pn0 == NULL || pn1 == NULL || pn2 == NULL || high == NULL) {
        fprintf(stderr, "%s: missing PN fixtures\n", fixture->name);
        return 0;
    }
    memset(&port, 0, sizeof(port));
    memset(&send, 0, sizeof(send));
    memset(&once, 0, sizeof(once));
    memset(&receive, 0, sizeof(receive));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) {
        goto done;
    }
    if (dmp_provider_cipher_from_key(provider, &send, fixture->i_to_r_key.data,
                                     fixture->i_to_r_key.size) != DMP_PROVIDER_OK) {
        goto done;
    }
    if (!encrypt_packet(provider, &send, pn0, "PN0") ||
        !encrypt_packet(provider, &send, pn1, "PN1") ||
        !encrypt_packet(provider, &send, pn2, "PN2")) {
        goto done;
    }
    if (dmp_provider_cipher_from_key(provider, &once, fixture->i_to_r_key.data,
                                     fixture->i_to_r_key.size) != DMP_PROVIDER_OK ||
        !encrypt_packet(provider, &once, pn2, "fresh PN2")) {
        goto done;
    }
    if (dmp_provider_cipher_from_key(provider, &receive, fixture->i_to_r_key.data,
                                     fixture->i_to_r_key.size) != DMP_PROVIDER_OK ||
        !decrypt_packet(provider, &receive, pn2, pn2->aad.data, pn2->aad.size, 0, 1,
                        "receive PN2") ||
        !decrypt_packet(provider, &receive, pn1, pn1->aad.data, pn1->aad.size, 0, 1,
                        "receive PN1")) {
        goto done;
    }
    if (pn1->aad.size == 0U || pn1->aad.size > sizeof(bad_aad)) {
        goto done;
    }
    memcpy(bad_aad, pn1->aad.data, pn1->aad.size);
    bad_aad[pn1->aad.size - 1U] ^= 0x01U;
    if (!decrypt_packet(provider, &receive, high, high->aad.data, high->aad.size, 1, 0,
                        "invalid high PN") ||
        !decrypt_packet(provider, &receive, pn1, bad_aad, pn1->aad.size, 0, 0, "altered AAD") ||
        !decrypt_packet(provider, &receive, pn0, pn0->aad.data, pn0->aad.size, 0, 1, "lower PN")) {
        goto done;
    }
    if (pn0->header.size != 0U && pn0->aad.size != 0U && pn0->aad.size <= sizeof(bad_aad)) {
        memcpy(bad_aad, pn0->aad.data, pn0->aad.size);
        bad_aad[0] ^= 0x01U;
        if (!decrypt_packet(provider, &receive, pn0, bad_aad, pn0->aad.size, 0, 0,
                            "altered header")) {
            goto done;
        }
    }
    memset(custom, 0, sizeof(custom));
    memcpy(custom, "xyz", 3U);
    if (dmp_provider_cipher_encrypt(provider, &once, 4U, (const uint8_t *)"abc", 3U, custom, 3U,
                                    sizeof(custom), &custom_len) != DMP_PROVIDER_OK) {
        fprintf(stderr, "arbitrary AAD encrypt failed\n");
        goto done;
    }
    if (dmp_provider_cipher_decrypt(provider, &receive, 4U, (const uint8_t *)"abc", 3U, custom,
                                    custom_len, sizeof(custom), &custom_len) != DMP_PROVIDER_OK ||
        custom_len != 3U || memcmp(custom, "xyz", 3U) != 0) {
        fprintf(stderr, "arbitrary AAD decrypt failed\n");
        goto done;
    }
    passed = dmp_provider_cipher_close(provider, &send) == DMP_PROVIDER_OK &&
             dmp_provider_cipher_close(provider, &once) == DMP_PROVIDER_OK &&
             dmp_provider_cipher_close(provider, &receive) == DMP_PROVIDER_OK &&
             all_zero(&send, sizeof(send)) && release_clean(&port, "PN/AAD");
    dmp_provider_cleanup(provider);

done:
    if (!passed) {
        dmp_provider_cleanup(provider);
    }
    free(provider);
    return passed;
}

static int test_suite(const noise_fixture_probe_fixture_t *fixture)
{
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_handshake initiator;
    dmp_provider_handshake responder;
    dmp_provider_cipher init_send;
    dmp_provider_cipher init_recv;
    dmp_provider_cipher resp_send;
    dmp_provider_cipher resp_recv;
    const noise_fixture_probe_packet_t *to_responder;
    const noise_fixture_probe_packet_t *to_initiator;
    dmp_provider_handshake_keys rejected;
    int passed = 0;

    memset(&port, 0, sizeof(port));
    memset(&initiator, 0, sizeof(initiator));
    memset(&responder, 0, sizeof(responder));
    memset(&init_send, 0, sizeof(init_send));
    memset(&init_recv, 0, sizeof(init_recv));
    memset(&resp_send, 0, sizeof(resp_send));
    memset(&resp_recv, 0, sizeof(resp_recv));
    memset(&rejected, 0, sizeof(rejected));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) {
        goto done;
    }
    if (dmp_provider_handshake_open(provider, &initiator,
                                    "Noise_NNpsk0_25519_AESGCM_SHA256",
                                    DMP_PROVIDER_ROLE_INITIATOR, &rejected) !=
        DMP_PROVIDER_UNSUPPORTED) {
        fprintf(stderr, "AESGCM was not rejected\n");
        goto done;
    }
    if (!exchange(provider, fixture, &initiator, &responder, 1)) {
        goto done;
    }
    to_responder = find_packet(fixture, 0U, 0U);
    to_initiator = find_packet(fixture, 1U, 0U);
    if (dmp_provider_handshake_split(provider, &initiator, &init_send, &init_recv) !=
            DMP_PROVIDER_OK ||
        dmp_provider_handshake_split(provider, &responder, &resp_send, &resp_recv) !=
            DMP_PROVIDER_OK ||
        !encrypt_packet(provider, &init_send, to_responder, "split send") ||
        !encrypt_packet(provider, &resp_send, to_initiator, "split reply")) {
        goto done;
    }
    passed = dmp_provider_cipher_close(provider, &init_send) == DMP_PROVIDER_OK &&
             dmp_provider_cipher_close(provider, &init_recv) == DMP_PROVIDER_OK &&
             dmp_provider_cipher_close(provider, &resp_send) == DMP_PROVIDER_OK &&
             dmp_provider_cipher_close(provider, &resp_recv) == DMP_PROVIDER_OK &&
             dmp_provider_handshake_close(provider, &initiator) == DMP_PROVIDER_OK &&
             dmp_provider_handshake_close(provider, &responder) == DMP_PROVIDER_OK &&
             dmp_provider_block_count(provider) == 0U && dmp_provider_retained(provider) == 0U &&
             all_zero(&initiator, sizeof(initiator)) && all_zero(&init_send, sizeof(init_send)) &&
             release_clean(&port, fixture->name);
    dmp_provider_cleanup(provider);
    passed = passed && all_zero(provider, dmp_provider_size());

done:
    if (!passed) {
        dmp_provider_cleanup(provider);
    }
    free(provider);
    return passed;
}

static int test_split_partial_registration_cleanup(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    enum { FILLER_COUNT = 9 };
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_handshake initiator;
    dmp_provider_handshake responder;
    dmp_provider_cipher fillers[FILLER_COUNT];
    dmp_provider_cipher send;
    dmp_provider_cipher receive;
    size_t index;
    size_t blocks_before_split;
    size_t retained_before_split;
    unsigned releases_before_split;
    dmp_provider_status split_status;
    int passed = 0;

    memset(&port, 0, sizeof(port));
    memset(&initiator, 0, sizeof(initiator));
    memset(&responder, 0, sizeof(responder));
    memset(fillers, 0, sizeof(fillers));
    memset(&send, 0xA5, sizeof(send));
    memset(&receive, 0xA5, sizeof(receive));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (fixture == NULL || dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK ||
        !exchange(provider, fixture, &initiator, &responder, 0)) {
        goto done;
    }

    for (index = 0U; index < FILLER_COUNT; ++index) {
        if (dmp_provider_cipher_from_key(provider, &fillers[index], fixture->i_to_r_key.data,
                                         fixture->i_to_r_key.size) != DMP_PROVIDER_OK) {
            fprintf(stderr, "split partial cleanup: filler open %zu failed\n", index);
            goto done;
        }
    }
    blocks_before_split = dmp_provider_block_count(provider);
    retained_before_split = dmp_provider_retained(provider);
    releases_before_split = port.release_calls;
    /* The two exchange states plus nine filler ciphers occupy eleven of twelve
     * child slots. Split can register its send child, then must unwind when
     * registration of the receive child has no slot. */
    split_status = dmp_provider_handshake_split(provider, &initiator, &send, &receive);
    if (split_status != DMP_PROVIDER_NO_MEMORY ||
        !all_zero(&send, sizeof(send)) || !all_zero(&receive, sizeof(receive)) ||
        dmp_provider_block_count(provider) > blocks_before_split ||
        dmp_provider_retained(provider) > retained_before_split ||
        port.release_calls <= releases_before_split) {
        fprintf(stderr,
                "split cleanup status=%d blocks=%zu/%zu retained=%zu/%zu releases=%u/%u send_zero=%d receive_zero=%d\n",
                (int)split_status, dmp_provider_block_count(provider), blocks_before_split,
                dmp_provider_retained(provider), retained_before_split, port.release_calls,
                releases_before_split, all_zero(&send, sizeof(send)),
                all_zero(&receive, sizeof(receive)));
        goto done;
    }

    passed = dmp_provider_handshake_close(provider, &initiator) == DMP_PROVIDER_OK &&
             dmp_provider_handshake_close(provider, &responder) == DMP_PROVIDER_OK;
    for (index = 0U; index < FILLER_COUNT; ++index) {
        if (dmp_provider_cipher_close(provider, &fillers[index]) != DMP_PROVIDER_OK) {
            passed = 0;
        }
    }
    passed = passed && dmp_provider_block_count(provider) == 0U &&
             dmp_provider_retained(provider) == 0U && release_clean(&port, "split partial cleanup");
    dmp_provider_cleanup(provider);
    passed = passed && all_zero(provider, dmp_provider_size());

done:
    if (!passed) {
        dmp_provider_cleanup(provider);
    }
    free(provider);
    return passed;
}

static int test_split_allocation_failure_retry(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_handshake initiator;
    dmp_provider_handshake responder;
    dmp_provider_cipher send;
    dmp_provider_cipher receive;
    size_t blocks_before;
    size_t retained_before;
    unsigned releases_before;
    dmp_provider_status status;
    int passed = 0;

    memset(&port, 0, sizeof(port));
    memset(&initiator, 0, sizeof(initiator));
    memset(&responder, 0, sizeof(responder));
    memset(&send, 0xA5, sizeof(send));
    memset(&receive, 0xA5, sizeof(receive));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (fixture == NULL || dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK ||
        !exchange(provider, fixture, &initiator, &responder, 0)) {
        goto done;
    }

    blocks_before = dmp_provider_block_count(provider);
    retained_before = dmp_provider_retained(provider);
    releases_before = port.release_calls;
    port.fail_alloc_at = port.alloc_calls + 1U;
    status = dmp_provider_handshake_split(provider, &initiator, &send, &receive);
    port.fail_alloc_at = 0U;
    if (status != DMP_PROVIDER_NO_MEMORY || !all_zero(&send, sizeof(send)) ||
        !all_zero(&receive, sizeof(receive)) ||
        dmp_provider_block_count(provider) != blocks_before ||
        dmp_provider_retained(provider) != retained_before ||
        port.release_calls != releases_before || !release_clean(&port, "split allocation failure")) {
        fprintf(stderr,
                "split allocation failure status=%d blocks=%zu/%zu retained=%zu/%zu releases=%u/%u\n",
                (int)status, dmp_provider_block_count(provider), blocks_before,
                dmp_provider_retained(provider), retained_before, port.release_calls,
                releases_before);
        goto done;
    }

    status = dmp_provider_handshake_split(provider, &initiator, &send, &receive);
    if (status != DMP_PROVIDER_OK ||
        dmp_provider_cipher_close(provider, &send) != DMP_PROVIDER_OK ||
        dmp_provider_cipher_close(provider, &receive) != DMP_PROVIDER_OK) {
        fprintf(stderr, "split retry after allocation failure did not recover\n");
        goto done;
    }
    passed = dmp_provider_handshake_close(provider, &initiator) == DMP_PROVIDER_OK &&
             dmp_provider_handshake_close(provider, &responder) == DMP_PROVIDER_OK &&
             dmp_provider_block_count(provider) == 0U &&
             dmp_provider_retained(provider) == 0U && release_clean(&port, "split retry");

done:
    dmp_provider_cleanup(provider);
    passed = passed && all_zero(provider, dmp_provider_size());
    free(provider);
    return passed;
}

static int test_cipher_child_capacity_cleanup(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    const noise_fixture_probe_packet_t *probe_packet;
    enum { CIPHER_CAP = 16 };
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_cipher ciphers[CIPHER_CAP];
    dmp_provider_cipher allocation_failure;
    dmp_provider_handshake handshake;
    dmp_provider_handshake_keys keys;
    size_t count = 0U;
    size_t blocks_before;
    size_t retained_before;
    unsigned releases_before;
    dmp_provider_status status;
    int passed = 0;

    if (fixture == NULL) {
        return 0;
    }
    memset(&port, 0, sizeof(port));
    memset(ciphers, 0, sizeof(ciphers));
    memset(&allocation_failure, 0xA5, sizeof(allocation_failure));
    memset(&handshake, 0xA5, sizeof(handshake));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) {
        goto done;
    }

    blocks_before = dmp_provider_block_count(provider);
    retained_before = dmp_provider_retained(provider);
    releases_before = port.release_calls;
    port.fail_alloc_at = port.alloc_calls + 1U;
    status = dmp_provider_cipher_from_key(provider, &allocation_failure,
                                          fixture->i_to_r_key.data,
                                          fixture->i_to_r_key.size);
    port.fail_alloc_at = 0U;
    if (status != DMP_PROVIDER_NO_MEMORY || !all_zero(&allocation_failure, sizeof(allocation_failure)) ||
        dmp_provider_block_count(provider) != blocks_before ||
        dmp_provider_retained(provider) != retained_before ||
        port.release_calls != releases_before || !release_clean(&port, "cipher allocation failure")) {
        fprintf(stderr,
                "cipher allocation failure status=%d blocks=%zu/%zu retained=%zu/%zu releases=%u/%u zero=%d\n",
                (int)status, dmp_provider_block_count(provider), blocks_before,
                dmp_provider_retained(provider), retained_before, port.release_calls,
                releases_before, all_zero(&allocation_failure, sizeof(allocation_failure)));
        goto done;
    }

    while (count < CIPHER_CAP) {
        blocks_before = dmp_provider_block_count(provider);
        retained_before = dmp_provider_retained(provider);
        releases_before = port.release_calls;
        memset(&ciphers[count], 0xA5, sizeof(ciphers[count]));
        status = dmp_provider_cipher_from_key(provider, &ciphers[count],
                                              fixture->i_to_r_key.data,
                                              fixture->i_to_r_key.size);
        if (status == DMP_PROVIDER_OK) {
            count++;
            continue;
        }
        if (status != DMP_PROVIDER_NO_MEMORY || !all_zero(&ciphers[count], sizeof(ciphers[count])) ||
            dmp_provider_block_count(provider) != blocks_before ||
            dmp_provider_retained(provider) != retained_before ||
            port.release_calls <= releases_before || !release_clean(&port, "cipher child capacity")) {
            fprintf(stderr,
                    "cipher child exhaustion status=%d blocks=%zu/%zu retained=%zu/%zu releases=%u/%u object_zero=%d\n",
                    (int)status, dmp_provider_block_count(provider), blocks_before,
                    dmp_provider_retained(provider), retained_before, port.release_calls,
                    releases_before, all_zero(&ciphers[count], sizeof(ciphers[count])));
            goto done;
        }
        break;
    }
    if (count == 0U || count == CIPHER_CAP || status != DMP_PROVIDER_NO_MEMORY) {
        fprintf(stderr, "cipher child capacity was not reached within %d slots\n", CIPHER_CAP);
        goto done;
    }

    /* A new handshake allocates its Noise state before child registration.
     * Exhaustion must release that temporary state and leave existing ciphers
     * intact. */
    blocks_before = dmp_provider_block_count(provider);
    retained_before = dmp_provider_retained(provider);
    releases_before = port.release_calls;
    fill_keys(fixture, DMP_PROVIDER_ROLE_INITIATOR, NULL, &keys);
    status = dmp_provider_handshake_open(provider, &handshake, fixture->protocol_name,
                                         DMP_PROVIDER_ROLE_INITIATOR, &keys);
    if (status != DMP_PROVIDER_NO_MEMORY || !all_zero(&handshake, sizeof(handshake)) ||
        dmp_provider_block_count(provider) != blocks_before ||
        dmp_provider_retained(provider) != retained_before ||
        port.release_calls <= releases_before || !release_clean(&port, "handshake child capacity")) {
        fprintf(stderr,
                "handshake child exhaustion status=%d blocks=%zu/%zu retained=%zu/%zu releases=%u/%u zero=%d\n",
                (int)status, dmp_provider_block_count(provider), blocks_before,
                dmp_provider_retained(provider), retained_before, port.release_calls,
                releases_before, all_zero(&handshake, sizeof(handshake)));
        goto done;
    }

    probe_packet = find_packet(fixture, 0U, 0U);
    if (probe_packet == NULL ||
        !encrypt_packet(provider, &ciphers[0], probe_packet, "cipher survives child capacity")) {
        fprintf(stderr, "existing cipher did not survive child capacity refusal\n");
        goto done;
    }

    passed = 1;

done:
    for (size_t index = 0U; index < count; ++index) {
        if (dmp_provider_cipher_close(provider, &ciphers[index]) != DMP_PROVIDER_OK) {
            passed = 0;
        }
    }
    dmp_provider_cleanup(provider);
    passed = passed && all_zero(provider, dmp_provider_size()) &&
             release_clean(&port, "cipher child capacity cleanup");
    free(provider);
    return passed;
}

static int test_cleanup(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    port_ctx port;
    dmp_provider_ports ports;
    dmp_provider *provider;
    dmp_provider_handshake handshake;
    dmp_provider_handshake_keys keys;
    dmp_provider_cipher cipher;
    int passed = 0;

    if (fixture == NULL) {
        return 0;
    }
    memset(&port, 0, sizeof(port));
    memset(&handshake, 0, sizeof(handshake));
    memset(&cipher, 0, sizeof(cipher));
    provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (provider == NULL) {
        return 0;
    }
    set_ports(&ports, &port, DMP_PROVIDER_SCRATCH_MAX, DMP_PROVIDER_RETAINED_MAX);
    if (dmp_provider_setup(provider, &ports) != DMP_PROVIDER_OK) {
        goto done;
    }
    fill_keys(fixture, DMP_PROVIDER_ROLE_INITIATOR, NULL, &keys);
    if (dmp_provider_handshake_open(provider, &handshake, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_INITIATOR, &keys) != DMP_PROVIDER_OK ||
        dmp_provider_block_count(provider) == 0U ||
        dmp_provider_cipher_from_key(provider, &cipher, fixture->i_to_r_key.data,
                                     fixture->i_to_r_key.size) != DMP_PROVIDER_OK) {
        goto done;
    }
    dmp_provider_cleanup(provider);
    passed = all_zero(provider, dmp_provider_size()) && all_zero(&handshake, sizeof(handshake)) &&
             all_zero(&cipher, sizeof(cipher)) && release_clean(&port, "cleanup");

done:
    dmp_provider_cleanup(provider);
    free(provider);
    return passed;
}

int main(void)
{
    const noise_fixture_probe_fixture_t *nn = find_fixture("nnpsk0");
    const noise_fixture_probe_fixture_t *xx = find_fixture("xx");

    if (nn == NULL || xx == NULL || NOISE_FIXTURE_PROBE_FIXTURE_COUNT != 2U) {
        fprintf(stderr, "expected the two ChaChaPoly fixtures\n");
        return 1;
    }
    expect_case("init", test_init());
    expect_case("entropy", test_entropy());
    expect_case("oom", test_oom());
    expect_case("handshake-open-allocation-sweep", test_handshake_open_allocation_sweep());
    expect_case("dh-shared-allocation-failure", test_dh_shared_allocation_failure());
    expect_case("output-contract", test_output_contract());
    expect_case("wrong-psk", test_wrong_psk());
    expect_case("low-order", test_low_order());
    expect_case("pn-aad-nnpsk0", test_pn_aad(nn));
    expect_case("pn-aad-xx", test_pn_aad(xx));
    expect_case("suite-nnpsk0", test_suite(nn));
    expect_case("suite-xx", test_suite(xx));
    expect_case("split-allocation-failure-retry", test_split_allocation_failure_retry());
    expect_case("split-partial-registration-cleanup", test_split_partial_registration_cleanup());
    expect_case("cipher-child-capacity-cleanup", test_cipher_child_capacity_cleanup());
    expect_case("cleanup", test_cleanup());
    if (g_failures != 0) {
        fprintf(stderr, "%d provider adapter case(s) failed\n", g_failures);
        return 1;
    }
    puts("provider adapter cases passed");
    return 0;
}
