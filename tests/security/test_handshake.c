/* Host tests for bootstrap plus protected FINISH/READY. Fixture keys are
 * public test material. Enrollment commit does not activate an association.
 */
#include "handshake.h"
#include "replay_window.h"
#include "noise_fixture_probe.h"

#include <noise/protocol.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NN_EPOCH UINT64_C(2004215583997381744)
#define NN_EPOCH_I UINT64_C(6442202121705392167)
#define NN_EPOCH_R UINT64_C(3481561963320986040)
#define XX_EPOCH_I UINT64_C(11971125099004572873)
#define XX_EPOCH_R UINT64_C(9004809941332091401)
#define ALT_EPOCH UINT64_C(1020278737886735521)
#define LOCAL_NS 1u
#define ID_INIT 0x0au
#define ID_RESP 0x14u
#define HINT 5u
#define CID_INIT 7u
#define CID_RESP 9u

static const char NN_FLIGHT1[] =
    "02010101000102030405060708090a0b0c0d0e0f010000000a00000014000000"
    "df42593c1cabfab5251e74de44cb595ef0c211deda7587aeed1e7b26bdb4ff4b"
    "05000000070000008f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1a"
    "d1ba6f3e2138285f2ab95cd894675cb1590e17e4d2a86f8a";
static const char NN_FLIGHT2[] =
    "0202000102030405060708090a0b0c0d0e0f358072d6365880d1aeea329adf91"
    "21383851ed21a28e3b75e965d0d2cd166254965c251814634d625053c10f14b3"
    "e8fa2b93ef39";
static const char XX_FLIGHT1[] =
    "02020101000102030405060708090a0b0c0d0e0f010000000a00000014000000"
    "df42593c1cabfab5251e74de44cb595ef0c211deda7587aeed1e7b26bdb4ff4b"
    "00000000070000008f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1a"
    "d1ba6f3e2138285f";
static const char XX_FLIGHT2[] =
    "0202000102030405060708090a0b0c0d0e0f358072d6365880d1aeea329adf91"
    "21383851ed21a28e3b75e965d0d2cd166254194805c1faf1b0084c97c48513bf"
    "83749ae8e43c86936840a11304825a8853b87ced1742148a90085517645a938e"
    "20d8766eab2a319180a0f56f4b2e034f3d76d0b39a4d";
static const char XX_FLIGHT3[] =
    "0203000102030405060708090a0b0c0d0e0f665441cb3e69fb9a0ce0a22435e2"
    "03ae55d8cf04458b94663c3f76b7c1008148608209ba8e14e3469c0ea4d701e3"
    "49301b100709ffbe3707816bfd6bb9dc0469";

static int g_failures;

typedef struct script {
    const uint8_t *data[8];
    size_t len[8];
    size_t count;
    size_t index;
    int fail;
} script;

typedef struct store {
    int fail;
    int calls;
    int has;
    uint8_t saved[32];
    uint32_t permissions;
    uint32_t peer_id;
} store;

typedef struct box {
    uint64_t *now;
    script *entropy_script;
    store *pin_store;
} box;

typedef struct session {
    uint64_t now;
    script init_script;
    script resp_script;
    store init_store;
    store resp_store;
    box init_box;
    box resp_box;
    dmp_provider *provider;
    dmp_hs *initiator;
    dmp_hs *responder;
} session;

typedef struct port_ctx {
    int nonzero_release;
    int deny_all;
    unsigned alloc_calls;
    unsigned release_calls;
    size_t deny_size;
    size_t last_size;
    size_t watch_size;
    unsigned watch_calls;
} port_ctx;

typedef void (*tune_fn)(dmp_hs_config *initiator, dmp_hs_config *responder);

static void expect_case(const char *name, int passed)
{
    if (passed) {
        printf("ok %s\n", name);
        return;
    }
    fprintf(stderr, "FAIL %s\n", name);
    g_failures++;
}

static int hex_decode(const char *hex, uint8_t *out, size_t cap, size_t *length)
{
    size_t chars = strlen(hex);
    size_t index;

    if ((chars % 2U) != 0U || chars / 2U > cap) {
        return 0;
    }
    for (index = 0U; index < chars; index += 2U) {
        unsigned value;

        if (sscanf(hex + index, "%2x", &value) != 1) {
            return 0;
        }
        out[index / 2U] = (uint8_t)value;
    }
    *length = chars / 2U;
    return 1;
}

static int bytes_match(const char *what, const uint8_t *actual, size_t actual_len,
                       const uint8_t *expected, size_t expected_len)
{
    size_t index;

    if (actual == NULL || actual_len != expected_len) {
        fprintf(stderr, "%s length %zu expected %zu\n", what, actual_len, expected_len);
        return 0;
    }
    for (index = 0U; index < expected_len; ++index) {
        if (actual[index] != expected[index]) {
            fprintf(stderr, "%s differs at %zu\n", what, index);
            return 0;
        }
    }
    return 1;
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

static int startup_ready(void *ctx)
{
    (void)ctx;
    return 0;
}

static int startup_read(void *ctx, void *bytes, size_t size)
{
    uint8_t *out = (uint8_t *)bytes;
    size_t index;

    (void)ctx;
    for (index = 0U; index < size; ++index) {
        out[index] = (uint8_t)(0x3DU + (uint8_t)index);
    }
    return 0;
}

static int provider_entropy(void *ctx, void *bytes, size_t size)
{
    uint8_t *out = (uint8_t *)bytes;
    size_t index;

    (void)ctx;
    for (index = 0U; index < size; ++index) {
        out[index] = (uint8_t)(0x71U + (uint8_t)index);
    }
    return 0;
}

static void *port_allocate(void *ctx, size_t size)
{
    port_ctx *port = (port_ctx *)ctx;

    port->alloc_calls++;
    port->last_size = size;
    if (port->watch_size != 0U && size == port->watch_size) {
        port->watch_calls++;
    }
    if (port->deny_all || (port->deny_size != 0U && size == port->deny_size)) {
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

static uint64_t now_of(void *ctx)
{
    box *env = (box *)ctx;

    return *env->now;
}

static int entropy_of(void *ctx, uint8_t *bytes, size_t size)
{
    box *env = (box *)ctx;
    script *src = env->entropy_script;

    if (src->fail || src->index >= src->count || src->len[src->index] != size) {
        memset(bytes, 0, size);
        return 1;
    }
    memcpy(bytes, src->data[src->index], size);
    src->index++;
    return 0;
}

static int commit_of(void *ctx, const dmp_hs_pin_record *record)
{
    box *env = (box *)ctx;
    store *pin = env->pin_store;

    pin->calls++;
    if (pin->fail) {
        return 1;
    }
    memcpy(pin->saved, record->remote_public, 32U);
    pin->permissions = record->permissions;
    pin->peer_id = record->peer_id;
    pin->has = 1;
    return 0;
}

static void script_add(script *src, const uint8_t *data, size_t len)
{
    src->data[src->count] = data;
    src->len[src->count] = len;
    src->count++;
}

static void fill_budget(dmp_hs_budget *budget)
{
    memset(budget, 0, sizeof(*budget));
    budget->max_pending = 2U;
    budget->max_scratch = 2U;
    budget->episode_attempts = 3U;
    budget->episode_deadline_ms = 100000U;
    budget->episode_work = 1000U;
    budget->episode_traffic = 100000U;
    budget->restart_backoff_ms = 1000U;
    budget->attempt_deadline_ms = 5000U;
    budget->cached_responses = 3U;
    budget->global_work = 1000U;
    budget->ingress_work = 1000U;
    budget->later_episodes = 1U;
    budget->admit_burst = 4U;
    budget->provisional_bytes = 240U;
}

static void fill_config(dmp_hs_config *config, const noise_fixture_probe_fixture_t *fixture,
                        int initiator, const uint8_t *pin, int has_pin, int pairing)
{
    memset(config, 0, sizeof(*config));
    fill_budget(&config->budget);
    config->namespace_id = LOCAL_NS;
    config->local_id = initiator ? ID_INIT : ID_RESP;
    config->peer_id = initiator ? ID_RESP : ID_INIT;
    memcpy(config->profile_hash, fixture->profile_hash.data, 32U);
    config->mode = (uint8_t)(fixture->psk.size == 32U ? 1U : 2U);
    config->cipher = 1U;
    config->key_hint = config->mode == 1U ? HINT : 0U;
    config->permissions = 2U;
    config->pairing_allowed = pairing;
    config->next_rx_cid = initiator ? CID_INIT : CID_RESP;
    config->has_pin = has_pin;
    if (has_pin && pin != NULL) {
        memcpy(config->pinned_remote, pin, 32U);
    }
    if (config->mode == 1U) {
        memcpy(config->psk, fixture->psk.data, 32U);
        config->has_psk = 1;
    } else {
        const noise_fixture_probe_bytes_t *secret =
            initiator ? &fixture->init_static : &fixture->resp_static;

        memcpy(config->local_static, secret->data, 32U);
        config->has_static = 1;
    }
}

static int open_provider(port_ctx *port, dmp_provider **provider)
{
    dmp_provider_ports ports;

    memset(port, 0, sizeof(*port));
    memset(&ports, 0, sizeof(ports));
    ports.startup_ready = startup_ready;
    ports.startup_read = startup_read;
    ports.entropy = provider_entropy;
    ports.allocate = port_allocate;
    ports.release = port_release;
    ports.ctx = port;
    ports.scratch_limit = DMP_PROVIDER_SCRATCH_MAX;
    ports.retained_limit = DMP_PROVIDER_RETAINED_MAX;
    *provider = (dmp_provider *)calloc(1, dmp_provider_size());
    if (*provider == NULL) {
        return 0;
    }
    if (dmp_provider_setup(*provider, &ports) != DMP_PROVIDER_OK) {
        free(*provider);
        *provider = NULL;
        return 0;
    }
    return 1;
}

static void close_session(session *env)
{
    if (env->initiator != NULL) {
        dmp_hs_cleanup(env->initiator);
    }
    if (env->responder != NULL) {
        dmp_hs_cleanup(env->responder);
    }
    if (env->provider != NULL) {
        dmp_provider_cleanup(env->provider);
    }
    free(env->initiator);
    free(env->responder);
    free(env->provider);
    env->initiator = NULL;
    env->responder = NULL;
    env->provider = NULL;
}

static int make_pair(session *env, port_ctx *port, const noise_fixture_probe_fixture_t *fixture,
                     const uint8_t *init_pin, int init_has_pin, const uint8_t *resp_pin,
                     int resp_has_pin, int pairing, tune_fn tune)
{
    dmp_hs_config init_config;
    dmp_hs_config resp_config;
    dmp_hs_ports init_ports;
    dmp_hs_ports resp_ports;

    memset(env, 0, sizeof(*env));
    env->now = 10000U;
    memset(env->init_store.saved, 0xAB, sizeof(env->init_store.saved));
    memset(env->resp_store.saved, 0xAB, sizeof(env->resp_store.saved));
    if (!open_provider(port, &env->provider)) {
        return 0;
    }
    env->initiator = (dmp_hs *)calloc(1, dmp_hs_size());
    env->responder = (dmp_hs *)calloc(1, dmp_hs_size());
    if (env->initiator == NULL || env->responder == NULL) {
        close_session(env);
        return 0;
    }
    fill_config(&init_config, fixture, 1, init_pin, init_has_pin, pairing);
    fill_config(&resp_config, fixture, 0, resp_pin, resp_has_pin, pairing);
    if (tune != NULL) {
        tune(&init_config, &resp_config);
    }
    script_add(&env->init_script, fixture->attempt_id.data, fixture->attempt_id.size);
    script_add(&env->init_script, fixture->init_ephemeral.data, fixture->init_ephemeral.size);
    script_add(&env->resp_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
    env->init_box.now = &env->now;
    env->init_box.entropy_script = &env->init_script;
    env->init_box.pin_store = &env->init_store;
    env->resp_box.now = &env->now;
    env->resp_box.entropy_script = &env->resp_script;
    env->resp_box.pin_store = &env->resp_store;
    memset(&init_ports, 0, sizeof(init_ports));
    memset(&resp_ports, 0, sizeof(resp_ports));
    init_ports.now_ms = now_of;
    init_ports.entropy = entropy_of;
    init_ports.commit_pin = commit_of;
    init_ports.ctx = &env->init_box;
    resp_ports.now_ms = now_of;
    resp_ports.entropy = entropy_of;
    resp_ports.commit_pin = commit_of;
    resp_ports.ctx = &env->resp_box;
    if (dmp_hs_init(env->initiator, env->provider, &init_config, &init_ports) != DMP_HS_OK ||
        dmp_hs_init(env->responder, env->provider, &resp_config, &resp_ports) != DMP_HS_OK ||
        dmp_hs_begin_episode(env->initiator) != DMP_HS_OK) {
        close_session(env);
        return 0;
    }
    return 1;
}

static void set_ingress(dmp_hs_ingress *ingress, const uint8_t *payload, size_t length,
                        uint32_t origin, uint32_t destination, uint32_t seq, uint64_t epoch)
{
    memset(ingress, 0, sizeof(*ingress));
    ingress->payload = payload;
    ingress->payload_len = length;
    ingress->origin_id = origin;
    ingress->destination_id = destination;
    ingress->namespace_id = LOCAL_NS;
    ingress->context_epoch = epoch;
    ingress->seq = seq;
}

static dmp_hs_status accept_offer(dmp_hs *hs, const dmp_hs_ingress *ingress, dmp_hs_completion *kept)
{
    dmp_hs_completion completion;
    dmp_hs_status status = dmp_hs_offer(hs, ingress, &completion);

    if (kept != NULL) {
        *kept = completion;
    }
    if (status == DMP_HS_AWAITING) {
        status = dmp_hs_accept(hs, &completion);
    }
    return status;
}

static int drive_flight(dmp_hs *hs, const uint8_t *payload, size_t length, uint32_t origin,
                        uint32_t destination, uint32_t seq, uint64_t epoch, dmp_hs_status expected)
{
    dmp_hs_ingress ingress;

    set_ingress(&ingress, payload, length, origin, destination, seq, epoch);
    return accept_offer(hs, &ingress, NULL) == expected;
}

static int not_active(const dmp_hs *hs, uint32_t index)
{
    return dmp_hs_send_application(hs, index) == DMP_HS_NOT_ACTIVE && !dmp_hs_association_active(hs);
}

static int test_nn_candidate(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t flight1[120];
    uint8_t flight2[80];
    uint8_t hash[32];
    size_t flight1_len = 0U;
    size_t flight2_len = 0U;
    size_t cached_len = 0U;
    uint32_t index = 0U;
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    const uint8_t *cached;
    int passed = 0;

    if (fixture == NULL || !hex_decode(NN_FLIGHT1, flight1, sizeof(flight1), &flight1_len) ||
        !hex_decode(NN_FLIGHT2, flight2, sizeof(flight2), &flight2_len) ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL)) {
        return 0;
    }
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (!bytes_match("flight 1", cached, cached_len, flight1, flight1_len) ||
        !drive_flight(env.responder, cached, cached_len, ID_INIT, ID_RESP, 1U, NN_EPOCH,
                      DMP_HS_CANDIDATE)) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    if (!bytes_match("flight 2", cached, cached_len, flight2, flight2_len) ||
        !drive_flight(env.initiator, cached, cached_len, ID_RESP, ID_INIT, 2U, NN_EPOCH,
                      DMP_HS_CANDIDATE)) {
        goto done;
    }
    passed = dmp_hs_candidate(env.initiator, index) && dmp_hs_candidate(env.responder, 0U) &&
             !dmp_hs_enrolled(env.initiator, index) && !dmp_hs_enrolled(env.responder, 0U) &&
             not_active(env.initiator, index) && not_active(env.responder, 0U) &&
             env.init_store.calls == 0 && env.resp_store.calls == 0 &&
             dmp_hs_copy_hash(env.initiator, index, hash) &&
             bytes_match("hash", hash, 32U, fixture->handshake_hash.data, 32U) &&
             dmp_hs_epochs(env.initiator, index, &epoch_i, &epoch_r) && epoch_i == NN_EPOCH_I &&
             epoch_r == NN_EPOCH_R && dmp_hs_noise_writes(env.initiator, index) == 1U &&
             dmp_hs_noise_writes(env.responder, 0U) == 1U;

done:
    close_session(&env);
    return passed && !port.nonzero_release;
}

static int test_preread_and_conflict(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t flight1[120];
    uint8_t flight2[80];
    uint8_t changed[120];
    uint8_t foreign[40];
    size_t flight1_len = 0U;
    size_t flight2_len = 0U;
    uint32_t index = 0U;
    uint64_t deadline;
    uint32_t reads;
    uint32_t writes;
    uint32_t work;
    dmp_hs_ingress ingress;
    int passed = 0;

    if (fixture == NULL || !hex_decode(NN_FLIGHT1, flight1, sizeof(flight1), &flight1_len) ||
        !hex_decode(NN_FLIGHT2, flight2, sizeof(flight2), &flight2_len) ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        return 0;
    }
    deadline = dmp_hs_deadline(env.initiator, index);
    writes = dmp_hs_noise_writes(env.initiator, index);
    work = dmp_hs_global_work(env.initiator);
    reads = dmp_hs_total_reads(env.initiator);
    memcpy(changed, flight1, flight1_len);
    changed[64] ^= 0x01U;
    set_ingress(&ingress, changed, flight1_len, ID_INIT, ID_INIT, 1U, NN_EPOCH);
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED ||
        dmp_hs_deadline(env.initiator, index) != deadline ||
        dmp_hs_noise_writes(env.initiator, index) != writes ||
        dmp_hs_retransmits(env.initiator, index) != 0U ||
        dmp_hs_total_reads(env.initiator) != reads || dmp_hs_terminal(env.initiator, index)) {
        fprintf(stderr, "conflicting flight 1 mutated the attempt\n");
        goto done;
    }
    set_ingress(&ingress, flight2, flight2_len - 1U, ID_RESP, ID_INIT, 2U, NN_EPOCH);
    memset(foreign, 0x22, sizeof(foreign));
    foreign[0] = 2U;
    foreign[1] = 2U;
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED ||
        dmp_hs_total_reads(env.initiator) != reads) {
        fprintf(stderr, "short flight was not dropped before Noise\n");
        goto done;
    }
    set_ingress(&ingress, foreign, sizeof(foreign), ID_RESP, ID_INIT, 2U, NN_EPOCH);
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED) {
        goto done;
    }
    set_ingress(&ingress, flight2, flight2_len, ID_RESP, ID_INIT, 2U, NN_EPOCH + 1U);
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED ||
        dmp_hs_total_reads(env.initiator) != reads) {
        fprintf(stderr, "wrong epoch reached Noise\n");
        goto done;
    }
    ingress.context_epoch = NN_EPOCH;
    ingress.route_to_root = 1;
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED) {
        goto done;
    }
    set_ingress(&ingress, flight1, flight1_len, ID_INIT, ID_INIT, 3U, NN_EPOCH);
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED ||
        dmp_hs_terminal(env.initiator, index) || dmp_hs_expect_flight(env.initiator, index) != 2U) {
        fprintf(stderr, "unexpected flight aborted the attempt\n");
        goto done;
    }
    passed = dmp_hs_global_work(env.initiator) >= work &&
             drive_flight(env.initiator, flight2, flight2_len, ID_RESP, ID_INIT, 2U, NN_EPOCH,
                          DMP_HS_CANDIDATE) &&
             not_active(env.initiator, index);

done:
    close_session(&env);
    return passed;
}

static int test_duplicate_and_loss(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t flight1[120];
    uint8_t saved[120];
    size_t flight1_len = 0U;
    size_t cached_len = 0U;
    uint32_t index = 0U;
    const uint8_t *cached;
    dmp_hs_ingress ingress;
    uint64_t deadline;
    int passed = 0;

    if (fixture == NULL || !hex_decode(NN_FLIGHT1, flight1, sizeof(flight1), &flight1_len) ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (!drive_flight(env.responder, cached, cached_len, ID_INIT, ID_RESP, 1U, NN_EPOCH,
                      DMP_HS_CANDIDATE)) {
        goto done;
    }
    deadline = dmp_hs_deadline(env.responder, 0U);
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    memcpy(saved, cached, cached_len);
    set_ingress(&ingress, flight1, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH);
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    if (dmp_hs_offer(env.responder, &ingress, NULL) != DMP_HS_OK ||
        dmp_hs_noise_writes(env.responder, 0U) != 1U || dmp_hs_retransmits(env.responder, 0U) != 1U ||
        dmp_hs_deadline(env.responder, 0U) != deadline ||
        !bytes_match("retransmit", cached, cached_len, saved, cached_len)) {
        fprintf(stderr, "identical duplicate wrote the flight again\n");
        goto done;
    }
    passed = dmp_hs_retransmit(env.initiator, index) == DMP_HS_OK &&
             dmp_hs_noise_writes(env.initiator, index) == 1U &&
             dmp_hs_retransmits(env.initiator, index) == 1U;

done:
    close_session(&env);
    return passed;
}

static int test_zero_cid_and_low_order(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_provider_handshake raw;
    dmp_provider_handshake_keys keys;
    uint8_t flight1[120];
    uint8_t bad1[120];
    uint8_t flight2[80];
    uint8_t zero_body[96];
    uint8_t noise[80];
    uint8_t plain[8];
    size_t flight1_len = 0U;
    size_t flight2_len = 0U;
    size_t noise_len = 0U;
    size_t plain_len = 0U;
    size_t cached_len = 0U;
    uint32_t index = 0U;
    uint32_t reads;
    const uint8_t *cached;
    dmp_hs_ingress ingress;
    int passed = 0;

    if (fixture == NULL || !hex_decode(NN_FLIGHT1, flight1, sizeof(flight1), &flight1_len) ||
        !hex_decode(NN_FLIGHT2, flight2, sizeof(flight2), &flight2_len) ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    memcpy(bad1, cached, cached_len);
    memset(bad1 + 68U, 0, 4U);
    set_ingress(&ingress, bad1, cached_len, ID_INIT, ID_RESP, 1U, NN_EPOCH);
    if (dmp_hs_offer(env.responder, &ingress, NULL) != DMP_HS_DROPPED ||
        dmp_hs_total_reads(env.responder) != 0U || dmp_hs_pending(env.responder) != 0U) {
        fprintf(stderr, "zero initiator CID was not dropped before Noise\n");
        goto done;
    }
    memset(&keys, 0, sizeof(keys));
    memset(&raw, 0, sizeof(raw));
    memset(plain, 0, sizeof(plain));
    keys.local_ephemeral = fixture->resp_ephemeral.data;
    keys.local_ephemeral_len = fixture->resp_ephemeral.size;
    keys.psk = fixture->psk.data;
    keys.psk_len = fixture->psk.size;
    keys.prologue = fixture->prologue.data;
    keys.prologue_len = fixture->prologue.size;
    if (dmp_provider_handshake_open(env.provider, &raw, fixture->protocol_name,
                                    DMP_PROVIDER_ROLE_RESPONDER, &keys) != DMP_PROVIDER_OK ||
        dmp_provider_handshake_read(env.provider, &raw, cached + 72U, cached_len - 72U, plain,
                                    sizeof(plain), &plain_len) != DMP_PROVIDER_OK ||
        dmp_provider_handshake_write(env.provider, &raw, plain, 4U, noise, sizeof(noise),
                                     &noise_len) != DMP_PROVIDER_OK ||
        dmp_provider_handshake_close(env.provider, &raw) != DMP_PROVIDER_OK) {
        fprintf(stderr, "zero-CID flight was not produced\n");
        goto done;
    }
    zero_body[0] = 2U;
    zero_body[1] = 2U;
    memcpy(zero_body + 2U, fixture->attempt_id.data, 16U);
    memcpy(zero_body + 18U, noise, noise_len);
    reads = dmp_hs_total_reads(env.initiator);
    if (!drive_flight(env.initiator, zero_body, 18U + noise_len, ID_RESP, ID_INIT, 2U, NN_EPOCH,
                      DMP_HS_ABORTED) ||
        !dmp_hs_terminal(env.initiator, index) || !dmp_hs_secrets_wiped(env.initiator, index) ||
        dmp_hs_total_reads(env.initiator) != reads + 1U || !not_active(env.initiator, index)) {
        fprintf(stderr, "zero responder CID did not abort the attempt\n");
        goto done;
    }
    set_ingress(&ingress, flight2, flight2_len, ID_RESP, ID_INIT, 2U, NN_EPOCH);
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED ||
        dmp_hs_total_reads(env.initiator) != reads + 1U) {
        fprintf(stderr, "late continuation resumed an aborted attempt\n");
        goto done;
    }
    close_session(&env);
    if (!make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL)) {
        return 0;
    }
    memcpy(bad1, flight1, flight1_len);
    memset(bad1 + 72U, 0, 32U);
    bad1[72] = 1U;
    if (!drive_flight(env.responder, bad1, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH, DMP_HS_ABORTED) ||
        dmp_hs_total_reads(env.responder) != 1U || !dmp_hs_secrets_wiped(env.responder, 0U)) {
        fprintf(stderr, "low-order flight did not abort\n");
        goto done;
    }
    set_ingress(&ingress, flight2, flight2_len, ID_INIT, ID_RESP, 2U, NN_EPOCH);
    passed = dmp_hs_offer(env.responder, &ingress, NULL) == DMP_HS_DROPPED &&
             dmp_hs_total_reads(env.responder) == 1U;

done:
    close_session(&env);
    return passed;
}

static int test_wrong_psk(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_hs_config bad_config;
    dmp_hs_ports bad_ports;
    box bad_box;
    script bad_script;
    store bad_store;
    uint8_t bad_psk[32];
    uint8_t flight[120];
    size_t flight_len = 0U;
    uint32_t index = 0U;
    const uint8_t *cached;
    dmp_hs_ingress ingress;
    dmp_hs_retained retained;
    int passed = 0;

    memset(&bad_script, 0, sizeof(bad_script));
    memset(&bad_store, 0, sizeof(bad_store));
    memset(bad_store.saved, 0xAB, sizeof(bad_store.saved));
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &flight_len);
    memcpy(flight, cached, flight_len);
    dmp_hs_cleanup(env.responder);
    free(env.responder);
    env.responder = (dmp_hs *)calloc(1, dmp_hs_size());
    memcpy(bad_psk, fixture->psk.data, 32U);
    bad_psk[31] ^= 0x01U;
    fill_config(&bad_config, fixture, 0, NULL, 0, 0);
    memcpy(bad_config.psk, bad_psk, 32U);
    script_add(&bad_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
    bad_box.now = &env.now;
    bad_box.entropy_script = &bad_script;
    bad_box.pin_store = &bad_store;
    memset(&bad_ports, 0, sizeof(bad_ports));
    bad_ports.now_ms = now_of;
    bad_ports.entropy = entropy_of;
    bad_ports.commit_pin = commit_of;
    bad_ports.ctx = &bad_box;
    memset(&retained, 0, sizeof(retained));
    retained.namespace_id = LOCAL_NS;
    retained.origin_id = 99U;
    retained.epoch = 99U;
    retained.rx_cid = 99U;
    if (env.responder == NULL ||
        dmp_hs_init(env.responder, env.provider, &bad_config, &bad_ports) != DMP_HS_OK ||
        dmp_hs_retain_association(env.responder, &retained) != DMP_HS_OK ||
        !drive_flight(env.responder, flight, flight_len, ID_INIT, ID_RESP, 1U, NN_EPOCH,
                      DMP_HS_ABORTED)) {
        fprintf(stderr, "wrong PSK did not abort\n");
        goto done;
    }
    set_ingress(&ingress, flight, flight_len, ID_INIT, ID_RESP, 2U, NN_EPOCH);
    passed = dmp_hs_secrets_wiped(env.responder, 0U) && !dmp_hs_enrolled(env.responder, 0U) &&
             bad_store.calls == 0 && bad_store.saved[0] == 0xABU &&
             dmp_hs_retained_alive(env.responder, 0U) &&
             dmp_hs_offer(env.responder, &ingress, NULL) == DMP_HS_DROPPED &&
             dmp_hs_total_reads(env.responder) == 1U && not_active(env.responder, 0U);

done:
    memset(bad_psk, 0, sizeof(bad_psk));
    close_session(&env);
    return passed;
}

static int derive_pins(const noise_fixture_probe_fixture_t *fixture, uint8_t init_pin[32],
                       uint8_t resp_pin[32])
{
    port_ctx port;
    dmp_provider *provider = NULL;
    int ok;

    if (!open_provider(&port, &provider)) {
        return 0;
    }
    ok = dmp_provider_dh_public(provider, fixture->resp_static.data, init_pin) == DMP_PROVIDER_OK &&
         dmp_provider_dh_public(provider, fixture->init_static.data, resp_pin) == DMP_PROVIDER_OK;
    dmp_provider_cleanup(provider);
    free(provider);
    return ok && !port.nonzero_release;
}

static int test_xx_pin_candidate(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("xx");
    session env;
    port_ctx port;
    uint8_t init_pin[32];
    uint8_t resp_pin[32];
    uint8_t flight1[120];
    uint8_t flight2[140];
    uint8_t flight3[100];
    uint8_t hash[32];
    size_t len1 = 0U;
    size_t len2 = 0U;
    size_t len3 = 0U;
    size_t cached_len = 0U;
    uint32_t index = 0U;
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    const uint8_t *cached;
    int passed = 0;

    if (fixture == NULL || !derive_pins(fixture, init_pin, resp_pin) ||
        !hex_decode(XX_FLIGHT1, flight1, sizeof(flight1), &len1) ||
        !hex_decode(XX_FLIGHT2, flight2, sizeof(flight2), &len2) ||
        !hex_decode(XX_FLIGHT3, flight3, sizeof(flight3), &len3) ||
        !make_pair(&env, &port, fixture, init_pin, 1, resp_pin, 1, 0, NULL) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (!bytes_match("xx flight 1", cached, cached_len, flight1, len1) ||
        !drive_flight(env.responder, cached, cached_len, ID_INIT, ID_RESP, 1U, NN_EPOCH, DMP_HS_OK)) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    if (!bytes_match("xx flight 2", cached, cached_len, flight2, len2) ||
        !drive_flight(env.initiator, cached, cached_len, ID_RESP, ID_INIT, 2U, NN_EPOCH,
                      DMP_HS_CANDIDATE)) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (!bytes_match("xx flight 3", cached, cached_len, flight3, len3) ||
        !drive_flight(env.responder, cached, cached_len, ID_INIT, ID_RESP, 3U, NN_EPOCH,
                      DMP_HS_CANDIDATE)) {
        goto done;
    }
    passed = dmp_hs_view_of(env.initiator, index) == DMP_HS_VIEW_CANDIDATE &&
             dmp_hs_view_of(env.responder, 0U) == DMP_HS_VIEW_CANDIDATE &&
             !dmp_hs_enrolled(env.initiator, index) && !dmp_hs_enrolled(env.responder, 0U) &&
             env.init_store.calls == 0 && env.resp_store.calls == 0 &&
             not_active(env.initiator, index) && not_active(env.responder, 0U) &&
             dmp_hs_copy_hash(env.initiator, index, hash) &&
             bytes_match("xx hash", hash, 32U, fixture->handshake_hash.data, 32U) &&
             dmp_hs_epochs(env.initiator, index, &epoch_i, &epoch_r) && epoch_i == XX_EPOCH_I &&
             epoch_r == XX_EPOCH_R;

done:
    close_session(&env);
    return passed;
}

static int test_wrong_pin_and_association(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("xx");
    session env;
    port_ctx port;
    uint8_t init_pin[32];
    uint8_t resp_pin[32];
    uint8_t bad_pin[32];
    size_t cached_len = 0U;
    uint32_t index = 0U;
    const uint8_t *cached;
    dmp_hs_retained retained;
    int passed = 0;

    if (fixture == NULL || !derive_pins(fixture, init_pin, resp_pin)) {
        return 0;
    }
    memcpy(bad_pin, init_pin, 32U);
    bad_pin[0] ^= 0x01U;
    if (!make_pair(&env, &port, fixture, bad_pin, 1, resp_pin, 1, 0, NULL) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        return 0;
    }
    memset(&retained, 0, sizeof(retained));
    retained.namespace_id = LOCAL_NS;
    retained.origin_id = 77U;
    retained.epoch = 77U;
    retained.rx_cid = 77U;
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (dmp_hs_retain_association(env.initiator, &retained) != DMP_HS_OK ||
        !drive_flight(env.responder, cached, cached_len, ID_INIT, ID_RESP, 1U, NN_EPOCH, DMP_HS_OK)) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    if (!drive_flight(env.initiator, cached, cached_len, ID_RESP, ID_INIT, 2U, NN_EPOCH, DMP_HS_ABORTED) ||
        !dmp_hs_terminal(env.initiator, index) || dmp_hs_enrolled(env.initiator, index) ||
        env.init_store.calls != 0 || env.init_store.saved[0] != 0xABU ||
        dmp_hs_expect_flight(env.responder, 0U) != 3U || dmp_hs_terminal(env.responder, 0U) ||
        !dmp_hs_retained_alive(env.initiator, 0U) || !not_active(env.initiator, index)) {
        fprintf(stderr, "wrong pin aborted more than the initiator attempt\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    return passed;
}

static void fill_approval(dmp_hs *hs, uint32_t index, dmp_hs_approval *approval, int accept)
{
    memset(approval, 0, sizeof(*approval));
    approval->generation = dmp_hs_generation(hs, index);
    (void)dmp_hs_copy_attempt_id(hs, index, approval->attempt_id);
    approval->initiator_id = ID_INIT;
    approval->responder_id = ID_RESP;
    (void)dmp_hs_copy_hash(hs, index, approval->hash);
    approval->accept = accept;
}

static int test_oob_commit(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("xx");
    session env;
    port_ctx port;
    uint8_t init_pin[32];
    uint8_t resp_pin[32];
    size_t cached_len = 0U;
    uint32_t index = 0U;
    const uint8_t *cached;
    dmp_hs_approval approval;
    int passed = 0;

    if (fixture == NULL || !derive_pins(fixture, init_pin, resp_pin) ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 1, NULL) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (!drive_flight(env.responder, cached, cached_len, ID_INIT, ID_RESP, 1U, NN_EPOCH, DMP_HS_OK)) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    if (!drive_flight(env.initiator, cached, cached_len, ID_RESP, ID_INIT, 2U, NN_EPOCH,
                      DMP_HS_CANDIDATE)) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (!drive_flight(env.responder, cached, cached_len, ID_INIT, ID_RESP, 3U, NN_EPOCH,
                      DMP_HS_CANDIDATE) ||
        dmp_hs_view_of(env.initiator, index) != DMP_HS_VIEW_AWAITING_VERIFICATION ||
        dmp_hs_view_of(env.responder, 0U) != DMP_HS_VIEW_AWAITING_VERIFICATION) {
        fprintf(stderr, "new XX pair did not wait for out-of-band approval\n");
        goto done;
    }
    fill_approval(env.initiator, index, &approval, 1);
    approval.hash[0] ^= 0x01U;
    if (dmp_hs_approve(env.initiator, index, &approval) != DMP_HS_NO_TRUST ||
        dmp_hs_enrolled(env.initiator, index) || env.init_store.calls != 0) {
        fprintf(stderr, "wrong hash installed trust\n");
        goto done;
    }
    fill_approval(env.initiator, index, &approval, 1);
    approval.attempt_id[0] ^= 0x01U;
    if (dmp_hs_approve(env.initiator, index, &approval) != DMP_HS_NO_TRUST ||
        dmp_hs_view_of(env.initiator, index) != DMP_HS_VIEW_AWAITING_VERIFICATION) {
        fprintf(stderr, "swapped attempt id installed trust\n");
        goto done;
    }
    fill_approval(env.initiator, index, &approval, 1);
    if (dmp_hs_approve(env.initiator, index, &approval) != DMP_HS_COMMITTED ||
        !dmp_hs_enrolled(env.initiator, index) || env.init_store.calls != 1 ||
        env.init_store.permissions != 2U || env.init_store.peer_id != ID_RESP ||
        memcmp(env.init_store.saved, init_pin, 32U) != 0 || !not_active(env.initiator, index) ||
        dmp_hs_enrolled(env.responder, 0U) || env.resp_store.calls != 0) {
        fprintf(stderr, "one commit activated traffic or enrolled the peer\n");
        goto done;
    }
    env.resp_store.fail = 1;
    fill_approval(env.responder, 0U, &approval, 1);
    passed = dmp_hs_approve(env.responder, 0U, &approval) == DMP_HS_ABORTED &&
             !dmp_hs_enrolled(env.responder, 0U) && !env.resp_store.has &&
             env.resp_store.saved[0] == 0xABU && dmp_hs_secrets_wiped(env.responder, 0U) &&
             dmp_hs_enrolled(env.initiator, index) && not_active(env.initiator, index);

done:
    close_session(&env);
    return passed;
}

static void tune_episode(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    (void)responder;
    initiator->budget.episode_attempts = 2U;
    initiator->budget.restart_backoff_ms = 1000U;
    initiator->budget.later_episodes = 1U;
}

static int test_episode_backoff(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t ids[3][16];
    uint8_t ephs[3][32];
    uint8_t seen[4][16];
    uint32_t index = 0U;
    uint32_t global_after_first;
    uint32_t attempt_no;
    int passed = 0;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_episode)) {
        return 0;
    }
    for (attempt_no = 0U; attempt_no < 3U; ++attempt_no) {
        memcpy(ids[attempt_no], fixture->attempt_id.data, 16U);
        ids[attempt_no][15] = (uint8_t)(0x10U + attempt_no);
        memset(ephs[attempt_no], (int)(0x31U + attempt_no), 32U);
        script_add(&env.init_script, ids[attempt_no], 16U);
        script_add(&env.init_script, ephs[attempt_no], 32U);
    }
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK ||
        !dmp_hs_copy_attempt_id(env.initiator, index, seen[0])) {
        goto done;
    }
    global_after_first = dmp_hs_global_work(env.initiator);
    if (dmp_hs_begin_episode(env.initiator) != DMP_HS_OK ||
        dmp_hs_episode_attempts_used(env.initiator) != 1U ||
        dmp_hs_global_work(env.initiator) != global_after_first ||
        dmp_hs_cancel(env.initiator, index) != DMP_HS_OK ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_REFUSED ||
        dmp_hs_episode_attempts_used(env.initiator) != 1U) {
        fprintf(stderr, "backoff or a repeated episode request reset the budget\n");
        goto done;
    }
    /* Scheduled delay is restart_backoff_ms. Jitter is 0, so one millisecond
     * early is still refused and the exact backoff is admitted. */
    {
        uint64_t cancelled_at = env.now;
        env.now = cancelled_at + 999U;
        if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_REFUSED) {
            fprintf(stderr, "restart delay was shorter than restart_backoff_ms\n");
            goto done;
        }
        env.now = cancelled_at + 1000U;
    }
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK ||
        dmp_hs_episode_attempts_used(env.initiator) != 2U ||
        dmp_hs_global_work(env.initiator) <= global_after_first ||
        !dmp_hs_copy_attempt_id(env.initiator, index, seen[1]) ||
        memcmp(seen[0], seen[1], 16U) == 0) {
        fprintf(stderr, "fresh attempt did not keep the episode budget\n");
        goto done;
    }
    global_after_first = dmp_hs_global_work(env.initiator);
    env.now += 1000U;
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_REFUSED ||
        dmp_hs_begin_episode(env.initiator) != DMP_HS_OK ||
        dmp_hs_episode_attempts_used(env.initiator) != 0U || dmp_hs_episode_work(env.initiator) != 0U ||
        dmp_hs_global_work(env.initiator) != global_after_first) {
        fprintf(stderr, "later episode reset global work\n");
        goto done;
    }
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK ||
        dmp_hs_begin_episode(env.initiator) != DMP_HS_OK ||
        dmp_hs_episode_attempts_used(env.initiator) != 1U ||
        dmp_hs_cancel(env.initiator, index) != DMP_HS_OK) {
        goto done;
    }
    env.now += 1000U;
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        goto done;
    }
    passed = dmp_hs_global_work(env.initiator) >= global_after_first &&
             dmp_hs_begin_episode(env.initiator) == DMP_HS_REFUSED &&
             dmp_hs_global_work(env.initiator) >= global_after_first &&
             dmp_hs_episode_attempts_used(env.initiator) == 2U;

done:
    close_session(&env);
    return passed;
}

static void tune_orphan(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    (void)initiator;
    responder->budget.max_pending = 1U;
    responder->budget.attempt_deadline_ms = 1000U;
    responder->budget.admit_burst = 4U;
}

static int test_orphan_replay_and_quota(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t flight1[120];
    uint8_t other[120];
    uint8_t alt_eph[32];
    uint8_t first_reply[80];
    size_t flight1_len = 0U;
    size_t cached_len = 0U;
    size_t reply_len = 0U;
    uint32_t index = 0U;
    uint32_t expired = 0U;
    const uint8_t *cached;
    dmp_hs_ingress ingress;
    dmp_hs_retained retained;
    dmp_hs_completion stale;
    int passed = 0;

    if (fixture == NULL || !hex_decode(NN_FLIGHT1, flight1, sizeof(flight1), &flight1_len) ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_orphan)) {
        return 0;
    }
    memset(alt_eph, 0x22, sizeof(alt_eph));
    script_add(&env.resp_script, alt_eph, sizeof(alt_eph));
    memset(&retained, 0, sizeof(retained));
    retained.namespace_id = LOCAL_NS;
    retained.origin_id = 55U;
    retained.epoch = 55U;
    retained.rx_cid = 55U;
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK ||
        dmp_hs_retain_association(env.responder, &retained) != DMP_HS_OK) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    memcpy(flight1, cached, cached_len);
    flight1_len = cached_len;
    if (!drive_flight(env.responder, flight1, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH,
                      DMP_HS_CANDIDATE)) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &reply_len);
    memcpy(first_reply, cached, reply_len);
    memcpy(other, flight1, flight1_len);
    other[19] = 0x10U;
    set_ingress(&ingress, other, flight1_len, ID_INIT, ID_RESP, 1U, ALT_EPOCH);
    if (dmp_hs_offer(env.responder, &ingress, NULL) != DMP_HS_REFUSED ||
        dmp_hs_pending(env.responder) != 1U || !dmp_hs_candidate(env.responder, 0U) ||
        !dmp_hs_retained_alive(env.responder, 0U)) {
        fprintf(stderr, "orphan capacity evicted the admitted attempt\n");
        goto done;
    }
    if (dmp_hs_cancel(env.initiator, index) != DMP_HS_OK || dmp_hs_terminal(env.responder, 0U)) {
        fprintf(stderr, "initiator cancel cleared the remote attempt\n");
        goto done;
    }
    env.now = 11000U;
    if (dmp_hs_poll(env.responder, &expired) != DMP_HS_EXPIRED || !dmp_hs_secrets_wiped(env.responder, 0U) ||
        dmp_hs_pending(env.responder) != 0U || !dmp_hs_retained_alive(env.responder, 0U)) {
        goto done;
    }
    set_ingress(&ingress, flight1, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH);
    if (dmp_hs_offer(env.responder, &ingress, &stale) != DMP_HS_AWAITING) {
        fprintf(stderr, "replayed flight 1 was not admitted after removal\n");
        goto done;
    }
    stale.generation ^= UINT64_C(1);
    if (dmp_hs_accept(env.responder, &stale) != DMP_HS_STALE) {
        goto done;
    }
    stale.generation ^= UINT64_C(1);
    if (dmp_hs_accept(env.responder, &stale) != DMP_HS_CANDIDATE) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    passed = cached_len == reply_len && memcmp(cached, first_reply, reply_len) != 0 &&
             dmp_hs_retained_alive(env.responder, 0U) && not_active(env.responder, 0U);

done:
    close_session(&env);
    return passed;
}

static void tune_scratch(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    (void)initiator;
    responder->budget.max_scratch = 0U;
}

static int test_scratch_serial_partial_stale(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t flight1[120];
    uint8_t partial_a[8];
    uint8_t partial_b[8];
    uint8_t held[8];
    size_t flight1_len = 0U;
    size_t held_len = 0U;
    size_t cached_len = 0U;
    uint32_t index = 0U;
    const uint8_t *cached;
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    dmp_hs_retained retained;
    int passed = 0;

    if (fixture == NULL || !hex_decode(NN_FLIGHT1, flight1, sizeof(flight1), &flight1_len) ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_scratch) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    memcpy(flight1, cached, cached_len);
    flight1_len = cached_len;
    set_ingress(&ingress, flight1, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH);
    if (dmp_hs_offer(env.responder, &ingress, NULL) != DMP_HS_REFUSED ||
        dmp_hs_total_reads(env.responder) != 0U || dmp_hs_pending(env.responder) != 0U) {
        fprintf(stderr, "scratch exhaustion called Noise\n");
        goto done;
    }
    close_session(&env);
    if (!make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    memcpy(partial_a, cached, sizeof(partial_a));
    memcpy(partial_b, partial_a, sizeof(partial_b));
    partial_b[0] ^= 0x01U;
    memset(&ingress, 0, sizeof(ingress));
    ingress.payload = partial_a;
    ingress.payload_len = sizeof(partial_a);
    ingress.partial = 1;
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED) {
        goto done;
    }
    ingress.payload = partial_b;
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED ||
        !dmp_hs_copy_partial(env.initiator, held, sizeof(held), &held_len) ||
        !bytes_match("partial", held, held_len, partial_a, sizeof(partial_a)) ||
        dmp_hs_total_reads(env.initiator) != 0U || dmp_hs_noise_writes(env.initiator, index) != 1U) {
        fprintf(stderr, "incomplete conflict overwrote retained bytes\n");
        goto done;
    }
    set_ingress(&ingress, cached, cached_len, ID_INIT, ID_RESP, 1U, NN_EPOCH);
    if (dmp_hs_offer(env.responder, &ingress, &completion) != DMP_HS_AWAITING) {
        goto done;
    }
    memset(&retained, 0, sizeof(retained));
    retained.namespace_id = LOCAL_NS;
    retained.origin_id = 42U;
    retained.epoch = 42U;
    retained.rx_cid = 42U;
    if (dmp_hs_offer(env.responder, &ingress, NULL) != DMP_HS_SERIAL ||
        dmp_hs_noise_reads(env.responder, completion.attempt_index) != 1U ||
        dmp_hs_retain_association(env.responder, &retained) != DMP_HS_OK ||
        dmp_hs_cancel(env.responder, completion.attempt_index) != DMP_HS_OK ||
        dmp_hs_accept(env.responder, &completion) != DMP_HS_STALE ||
        !dmp_hs_secrets_wiped(env.responder, completion.attempt_index) ||
        dmp_hs_enrolled(env.responder, completion.attempt_index) ||
        !dmp_hs_retained_alive(env.responder, 0U)) {
        fprintf(stderr, "stale completion or serialization failed\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    return passed;
}

static int test_entropy_cid_collision_and_cipher(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_hs_config config;
    dmp_hs_ports ports;
    box env_box;
    script entropy_script;
    store pin_store;
    uint8_t flight2[120];
    size_t cached_len = 0U;
    uint32_t index = 0U;
    uint32_t global_before;
    const uint8_t *cached;
    dmp_hs_retained retained;
    dmp_hs *rejected = NULL;
    int passed = 0;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    memcpy(flight2, cached, cached_len);
    if (!drive_flight(env.responder, flight2, cached_len, ID_INIT, ID_RESP, 1U, NN_EPOCH, DMP_HS_CANDIDATE)) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    memcpy(flight2, cached, cached_len);
    memset(&retained, 0, sizeof(retained));
    retained.namespace_id = LOCAL_NS;
    retained.origin_id = ID_INIT;
    retained.epoch = NN_EPOCH_I;
    retained.rx_cid = 99U;
    if (dmp_hs_retain_association(env.initiator, &retained) != DMP_HS_OK ||
        !drive_flight(env.initiator, flight2, cached_len, ID_RESP, ID_INIT, 2U, NN_EPOCH, DMP_HS_ABORTED) ||
        !dmp_hs_retained_alive(env.initiator, 0U) || !dmp_hs_candidate(env.responder, 0U) ||
        !dmp_hs_secrets_wiped(env.initiator, index)) {
        fprintf(stderr, "epoch collision did not end only the candidate\n");
        goto done;
    }
    global_before = dmp_hs_global_work(env.initiator);
    env.now += 1000U;
    env.init_script.fail = 1;
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_ABORTED ||
        dmp_hs_cached_flight(env.initiator, index, &cached_len) != NULL ||
        dmp_hs_global_work(env.initiator) < global_before || dmp_hs_pending(env.initiator) != 0U) {
        fprintf(stderr, "entropy failure transmitted or reset work\n");
        goto done;
    }
    rejected = (dmp_hs *)calloc(1, dmp_hs_size());
    memset(&entropy_script, 0, sizeof(entropy_script));
    memset(&pin_store, 0, sizeof(pin_store));
    memset(&config, 0, sizeof(config));
    fill_config(&config, fixture, 1, NULL, 0, 0);
    config.cipher = 2U;
    env_box.now = &env.now;
    env_box.entropy_script = &entropy_script;
    env_box.pin_store = &pin_store;
    memset(&ports, 0, sizeof(ports));
    ports.now_ms = now_of;
    ports.entropy = entropy_of;
    ports.commit_pin = commit_of;
    ports.ctx = &env_box;
    if (rejected == NULL ||
        dmp_hs_init(rejected, env.provider, &config, &ports) != DMP_HS_UNSUPPORTED ||
        !not_active(env.responder, 0U)) {
        goto done;
    }
    free(rejected);
    rejected = NULL;
    close_session(&env);
    if (!make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL)) {
        return 0;
    }
    memset(&retained, 0, sizeof(retained));
    retained.namespace_id = LOCAL_NS;
    retained.origin_id = 3U;
    retained.epoch = 3U;
    retained.rx_cid = CID_INIT;
    passed = dmp_hs_retain_association(env.initiator, &retained) == DMP_HS_OK &&
             dmp_hs_schedule(env.initiator, &index) == DMP_HS_OK &&
             dmp_hs_rx_cid(env.initiator, index) != CID_INIT &&
             dmp_hs_retained_alive(env.initiator, 0U);

done:
    free(rejected);
    close_session(&env);
    return passed;
}

static size_t measure_hash_alloc(port_ctx *port)
{
    NoiseHashState *state = NULL;
    unsigned calls = port->alloc_calls;
    size_t measured;

    if (noise_hashstate_new_by_id(&state, NOISE_HASH_SHA256) != NOISE_ERROR_NONE || state == NULL) {
        return 0U;
    }
    measured = port->last_size;
    (void)noise_hashstate_free(state);
    if (port->alloc_calls != calls + 1U || measured == 0U) {
        return 0U;
    }
    return measured;
}

static int test_epoch_hash_alloc(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t flight1[120];
    uint8_t flight2[80];
    size_t flight1_len = 0U;
    size_t flight2_len = 0U;
    size_t hash_size;
    uint32_t index = 0U;
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    const uint8_t *cached;
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    dmp_hs_status status;
    unsigned hash_allocs = 0U;
    uint32_t attempts_before = 0U;
    uint32_t work_before = 0U;
    int first_release = 0;
    int passed = 0;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL)) {
        return 0;
    }
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        close_session(&env);
        return 0;
    }
    hash_size = measure_hash_alloc(&port);
    cached = dmp_hs_cached_flight(env.initiator, index, &flight1_len);
    if (hash_size == 0U || cached == NULL || flight1_len > sizeof(flight1)) {
        goto done;
    }
    memcpy(flight1, cached, flight1_len);
    if (!drive_flight(env.responder, flight1, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH,
                      DMP_HS_CANDIDATE)) {
        fprintf(stderr, "flight 1 did not reach candidate before the accept fault\n");
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &flight2_len);
    if (cached == NULL || flight2_len > sizeof(flight2)) {
        goto done;
    }
    memcpy(flight2, cached, flight2_len);
    set_ingress(&ingress, flight2, flight2_len, ID_RESP, ID_INIT, 2U, NN_EPOCH);
    if (dmp_hs_offer(env.initiator, &ingress, &completion) != DMP_HS_AWAITING) {
        fprintf(stderr, "flight 2 was not held for accept\n");
        goto done;
    }
    port.watch_size = hash_size;
    port.watch_calls = 0U;
    status = dmp_hs_accept(env.initiator, &completion);
    hash_allocs = port.watch_calls;
    port.watch_size = 0U;
    if (hash_allocs != 0U || status != DMP_HS_CANDIDATE ||
        !dmp_hs_epochs(env.initiator, completion.attempt_index, &epoch_i, &epoch_r) ||
        epoch_i != NN_EPOCH_I || epoch_r != NN_EPOCH_R) {
        fprintf(stderr, "accept allocated a hash state or changed epochs (%d, %u)\n",
                (int)status, hash_allocs);
        goto done;
    }
    first_release = port.nonzero_release;
    close_session(&env);

    if (!make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL)) {
        return 0;
    }
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        close_session(&env);
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &flight1_len);
    if (cached == NULL || flight1_len > sizeof(flight1)) {
        goto done;
    }
    memcpy(flight1, cached, flight1_len);
    set_ingress(&ingress, flight1, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH);
    if (dmp_hs_begin_episode(env.responder) != DMP_HS_OK) {
        fprintf(stderr, "responder episode did not open\n");
        goto done;
    }
    attempts_before = dmp_hs_episode_attempts_used(env.responder);
    work_before = dmp_hs_episode_work(env.responder);
    port.deny_all = 1;
    status = dmp_hs_offer(env.responder, &ingress, NULL);
    port.deny_all = 0;
    if (status == DMP_HS_DROPPED || dmp_hs_total_reads(env.responder) != 0U ||
        dmp_hs_view_of(env.responder, 0U) != DMP_HS_VIEW_REJECTED ||
        dmp_hs_episode_attempts_used(env.responder) != attempts_before ||
        dmp_hs_episode_work(env.responder) != work_before) {
        fprintf(stderr, "null allocator dropped flight 1 or charged the episode (%d)\n", (int)status);
        goto done;
    }
    passed = status == DMP_HS_ABORTED && !first_release;

done:
    close_session(&env);
    return passed && !port.nonzero_release;
}

static void tune_confirm(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    initiator->budget.confirmation_timeout_ms = 1000U;
    initiator->budget.confirmation_attempts = 3U;
    responder->budget.confirmation_timeout_ms = 1000U;
    responder->budget.confirmation_attempts = 3U;
    initiator->budget.failed_aead_limit = 4U;
    responder->budget.failed_aead_limit = 4U;
}

static void tune_window(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    tune_confirm(initiator, responder);
    initiator->budget.replay_window = 64U;
    responder->budget.replay_window = 64U;
}

static void tune_aead_limit(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    tune_confirm(initiator, responder);
    initiator->budget.failed_aead_limit = 2U;
    responder->budget.failed_aead_limit = 2U;
}

static void tune_one_confirm(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    tune_confirm(initiator, responder);
    initiator->budget.confirmation_attempts = 1U;
    responder->budget.confirmation_attempts = 1U;
}

static dmp_hs_status offer_frame(dmp_hs *hs, const uint8_t *frame, size_t length, uint32_t origin,
                                 uint32_t destination, uint64_t epoch)
{
    dmp_hs_protected incoming;

    memset(&incoming, 0, sizeof(incoming));
    incoming.frame = frame;
    incoming.frame_len = length;
    incoming.origin_id = origin;
    incoming.destination_id = destination;
    incoming.namespace_id = LOCAL_NS;
    incoming.context_epoch = epoch;
    return dmp_hs_offer_protected(hs, &incoming);
}

static int drive_nn(session *env, uint32_t *index)
{
    const uint8_t *cached;
    size_t length = 0U;

    if (dmp_hs_schedule(env->initiator, index) != DMP_HS_OK) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->initiator, *index, &length);
    if (!drive_flight(env->responder, cached, length, ID_INIT, ID_RESP, 1U, NN_EPOCH, DMP_HS_CANDIDATE)) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->responder, 0U, &length);
    return drive_flight(env->initiator, cached, length, ID_RESP, ID_INIT, 2U, NN_EPOCH, DMP_HS_CANDIDATE);
}

static const noise_fixture_probe_packet_t *find_packet(const noise_fixture_probe_fixture_t *fixture,
                                                       const char *name)
{
    size_t index;

    if (strcmp(fixture->finish.name, name) == 0) {
        return &fixture->finish;
    }
    if (strcmp(fixture->ready.name, name) == 0) {
        return &fixture->ready;
    }
    for (index = 0U; index < fixture->transport_packet_count; ++index) {
        if (strcmp(fixture->transport_packets[index].name, name) == 0) {
            return &fixture->transport_packets[index];
        }
    }
    return NULL;
}

static int copy_protected(const dmp_hs *hs, uint32_t index, uint8_t *out, size_t cap, size_t *length)
{
    size_t have = 0U;
    const uint8_t *frame = dmp_hs_protected_frame(hs, index, &have);

    if (frame == NULL || have > cap) {
        return 0;
    }
    memcpy(out, frame, have);
    *length = have;
    return 1;
}

static int test_finish_ready(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    const noise_fixture_probe_packet_t *telemetry;
    session env;
    port_ctx port;
    uint8_t finish[64];
    uint8_t ready[64];
    uint8_t bare[1] = {0x04U};
    uint8_t bad[64];
    uint8_t wrong_cipher[64];
    uint8_t app[64];
    uint8_t accepted[8];
    size_t finish_len = 0U;
    size_t ready_len = 0U;
    size_t app_len = 0U;
    size_t accepted_len = 0U;
    uint32_t index = 0U;
    uint32_t writes;
    int passed = 0;

    if (fixture == NULL || (telemetry = find_packet(fixture, "telemetry")) == NULL ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_confirm) || !drive_nn(&env, &index)) {
        return 0;
    }
    if (dmp_hs_emit_application(env.initiator, index, (const uint8_t *)"aa", 2U) != DMP_HS_NOT_ACTIVE ||
        dmp_hs_emit_application(env.responder, 0U, (const uint8_t *)"aa", 2U) != DMP_HS_NOT_ACTIVE ||
        !not_active(env.initiator, index) || !not_active(env.responder, 0U)) {
        fprintf(stderr, "candidate state emitted application traffic\n");
        goto done;
    }
    if (dmp_hs_confirm(env.initiator, index) != DMP_HS_OK || !copy_protected(env.initiator, index, finish, sizeof(finish), &finish_len) ||
        !bytes_match("finish", finish, finish_len, fixture->finish.frame.data, fixture->finish.frame.size) ||
        dmp_hs_send_application(env.initiator, index) != DMP_HS_NOT_ACTIVE) {
        fprintf(stderr, "FINISH was not the published protected frame or it activated early\n");
        goto done;
    }
    memcpy(bad, finish, finish_len);
    bad[finish_len - 1U] ^= 0x01U;
    memcpy(wrong_cipher, finish, finish_len);
    wrong_cipher[4] = 0x02U;
    if (offer_frame(env.responder, bare, sizeof(bare), ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_DROPPED ||
        offer_frame(env.responder, wrong_cipher, finish_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_UNSUPPORTED ||
        offer_frame(env.responder, bad, finish_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_DROPPED ||
        dmp_hs_failed_aead(env.responder, 0U) != 1U || dmp_hs_association_active(env.responder) ||
        dmp_hs_next_pn(env.responder, 0U) != 0U || !dmp_hs_candidate(env.responder, 0U)) {
        fprintf(stderr, "FINISH without a valid AEAD tag was accepted or aborted the attempt\n");
        goto done;
    }
    if (offer_frame(env.responder, finish, finish_len, ID_INIT, ID_RESP, NN_EPOCH_R) != DMP_HS_DROPPED ||
        offer_frame(env.responder, finish, finish_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_OK ||
        !copy_protected(env.responder, 0U, ready, sizeof(ready), &ready_len) ||
        !bytes_match("ready", ready, ready_len, fixture->ready.frame.data, fixture->ready.frame.size) ||
        dmp_hs_send_application(env.responder, 0U) != DMP_HS_OK ||
        dmp_hs_send_application(env.initiator, index) != DMP_HS_NOT_ACTIVE) {
        fprintf(stderr, "responder did not activate only after an authorized FINISH\n");
        goto done;
    }
    if (dmp_hs_emit_application(env.responder, 0U, (const uint8_t *)"hi", 2U) != DMP_HS_OK ||
        !copy_protected(env.responder, 0U, app, sizeof(app), &app_len) ||
        offer_frame(env.initiator, app, app_len, ID_RESP, ID_INIT, NN_EPOCH_R) != DMP_HS_OK ||
        !dmp_hs_copy_accepted(env.initiator, index, accepted, sizeof(accepted), &accepted_len) ||
        accepted_len != 2U || memcmp(accepted, "hi", 2U) != 0 ||
        dmp_hs_send_application(env.initiator, index) != DMP_HS_OK) {
        fprintf(stderr, "responder application did not prove readiness\n");
        goto done;
    }
    if (offer_frame(env.initiator, ready, ready_len, ID_RESP, ID_INIT, NN_EPOCH_R) != DMP_HS_OK ||
        dmp_hs_emit_application(env.initiator, index, (const uint8_t *)"\xaa\xbb", 2U) != DMP_HS_OK ||
        !copy_protected(env.initiator, index, app, sizeof(app), &app_len) ||
        !bytes_match("telemetry", app, app_len, telemetry->frame.data, telemetry->frame.size)) {
        fprintf(stderr, "post-activation traffic did not match the published frame\n");
        goto done;
    }
    writes = dmp_hs_noise_writes(env.initiator, index);
    env.now += 1000U;
    {
        uint8_t extra_id[16];
        uint8_t extra_eph[32];
        uint32_t second = 0U;
        dmp_hs_retained retained;

        memset(extra_id, 0x44, sizeof(extra_id));
        memset(extra_eph, 0x55, sizeof(extra_eph));
        memset(&retained, 0, sizeof(retained));
        retained.namespace_id = LOCAL_NS;
        retained.origin_id = ID_RESP;
        retained.epoch = 42U;
        retained.rx_cid = 90U;
        script_add(&env.init_script, extra_id, sizeof(extra_id));
        script_add(&env.init_script, extra_eph, sizeof(extra_eph));
        if (dmp_hs_retain_association(env.initiator, &retained) != DMP_HS_OK ||
            dmp_hs_schedule(env.initiator, &second) != DMP_HS_OK || second == index ||
            dmp_hs_association_active(env.initiator) == 0 ||
            dmp_hs_send_application(env.initiator, index) != DMP_HS_OK ||
            dmp_hs_send_application(env.initiator, second) != DMP_HS_NOT_ACTIVE ||
            !dmp_hs_retained_alive(env.initiator, 0U) || !dmp_hs_association_active(env.responder)) {
            fprintf(stderr, "a new attempt evicted the active association\n");
            goto done;
        }
    }
    passed = dmp_hs_noise_writes(env.initiator, index) == writes && !dmp_hs_enrolled(env.initiator, index);

done:
    close_session(&env);
    return passed && !port.nonzero_release;
}

static int test_confirmation_loss(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t first[64];
    uint8_t retry[64];
    uint8_t ready[64];
    size_t first_len = 0U;
    size_t retry_len = 0U;
    size_t ready_len = 0U;
    uint32_t index = 0U;
    uint64_t pn_after_retry;
    int passed = 0;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_confirm) ||
        !drive_nn(&env, &index) || dmp_hs_confirm(env.initiator, index) != DMP_HS_OK ||
        !copy_protected(env.initiator, index, first, sizeof(first), &first_len)) {
        return 0;
    }
    if (dmp_hs_retransmit(env.initiator, index) != DMP_HS_REFUSED || dmp_hs_next_pn(env.initiator, index) != 1U) {
        fprintf(stderr, "FINISH was retried before its confirmation timer\n");
        goto done;
    }
    env.now += 1000U;
    if (dmp_hs_retransmit(env.initiator, index) != DMP_HS_OK ||
        !copy_protected(env.initiator, index, retry, sizeof(retry), &retry_len) || retry_len != first_len ||
        memcmp(first, retry, first_len) == 0 || dmp_hs_next_pn(env.initiator, index) != 2U) {
        fprintf(stderr, "lost FINISH was not retried under a fresh PN\n");
        goto done;
    }
    if (offer_frame(env.responder, retry, retry_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_OK ||
        offer_frame(env.responder, first, first_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_OK ||
        dmp_hs_next_pn(env.responder, 0U) != 2U) {
        fprintf(stderr, "reordered FINISH pair was not both accepted inside the window\n");
        goto done;
    }
    pn_after_retry = dmp_hs_next_pn(env.responder, 0U);
    if (!copy_protected(env.responder, 0U, ready, sizeof(ready), &ready_len) ||
        offer_frame(env.responder, retry, retry_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_DROPPED ||
        dmp_hs_next_pn(env.responder, 0U) != pn_after_retry || dmp_hs_failed_aead(env.responder, 0U) != 0U) {
        fprintf(stderr, "replayed FINISH was accepted again\n");
        goto done;
    }
    if (offer_frame(env.initiator, ready, ready_len, ID_RESP, ID_INIT, NN_EPOCH_R) != DMP_HS_OK ||
        !dmp_hs_association_active(env.initiator) || !dmp_hs_association_active(env.responder) ||
        dmp_hs_send_application(env.initiator, index) != DMP_HS_OK) {
        fprintf(stderr, "READY after loss did not activate the initiator\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    return passed && !port.nonzero_release;
}

static int test_replay_window(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t finish[64];
    uint8_t ready[64];
    uint8_t low[64];
    uint8_t high[64];
    uint8_t extra[64];
    uint8_t accepted[4];
    size_t finish_len = 0U;
    size_t ready_len = 0U;
    size_t low_len = 0U;
    size_t high_len = 0U;
    size_t extra_len = 0U;
    size_t accepted_len = 0U;
    uint32_t index = 0U;
    uint32_t guard;
    int passed = 0;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_window) ||
        !drive_nn(&env, &index) || dmp_hs_confirm(env.initiator, index) != DMP_HS_OK ||
        !copy_protected(env.initiator, index, finish, sizeof(finish), &finish_len) ||
        offer_frame(env.responder, finish, finish_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_OK ||
        !copy_protected(env.responder, 0U, ready, sizeof(ready), &ready_len) ||
        offer_frame(env.initiator, ready, ready_len, ID_RESP, ID_INIT, NN_EPOCH_R) != DMP_HS_OK) {
        return 0;
    }
    if (dmp_hs_emit_application(env.initiator, index, (const uint8_t *)"L", 1U) != DMP_HS_OK ||
        !copy_protected(env.initiator, index, low, sizeof(low), &low_len) ||
        dmp_hs_emit_application(env.initiator, index, (const uint8_t *)"H", 1U) != DMP_HS_OK ||
        !copy_protected(env.initiator, index, high, sizeof(high), &high_len)) {
        goto done;
    }
    if (offer_frame(env.responder, high, high_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_OK ||
        offer_frame(env.responder, low, low_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_OK ||
        !dmp_hs_copy_accepted(env.responder, 0U, accepted, sizeof(accepted), &accepted_len) ||
        accepted_len != 1U || accepted[0] != (uint8_t)'L') {
        fprintf(stderr, "PN reorder inside W was rejected\n");
        goto done;
    }
    if (offer_frame(env.responder, high, high_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_DROPPED ||
        dmp_hs_failed_aead(env.responder, 0U) != 0U) {
        fprintf(stderr, "in-window replay was decrypted again\n");
        goto done;
    }
    for (guard = 0U; guard < 80U && dmp_hs_next_pn(env.initiator, index) <= 65U; ++guard) {
        if (dmp_hs_emit_application(env.initiator, index, (const uint8_t *)"x", 1U) != DMP_HS_OK ||
            !copy_protected(env.initiator, index, extra, sizeof(extra), &extra_len) ||
            offer_frame(env.responder, extra, extra_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_OK) {
            fprintf(stderr, "window advance failed at PN %llu\n",
                    (unsigned long long)dmp_hs_next_pn(env.initiator, index));
            goto done;
        }
    }
    if (dmp_hs_next_pn(env.initiator, index) <= 65U ||
        offer_frame(env.responder, low, low_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_DROPPED ||
        dmp_hs_failed_aead(env.responder, 0U) != 0U || !dmp_hs_association_active(env.responder)) {
        fprintf(stderr, "PN behind W was accepted\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    return passed && !port.nonzero_release;
}

static int test_enroll_not_active(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("xx");
    session env;
    port_ctx port;
    uint8_t init_pin[32];
    uint8_t resp_pin[32];
    size_t cached_len = 0U;
    uint32_t index = 0U;
    uint32_t writes;
    const uint8_t *cached;
    dmp_hs_approval approval;
    dmp_hs_retained retained;
    int passed = 0;

    if (fixture == NULL || !derive_pins(fixture, init_pin, resp_pin) ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 1, tune_one_confirm) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (!drive_flight(env.responder, cached, cached_len, ID_INIT, ID_RESP, 1U, NN_EPOCH, DMP_HS_OK)) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    if (!drive_flight(env.initiator, cached, cached_len, ID_RESP, ID_INIT, 2U, NN_EPOCH, DMP_HS_CANDIDATE)) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (!drive_flight(env.responder, cached, cached_len, ID_INIT, ID_RESP, 3U, NN_EPOCH, DMP_HS_CANDIDATE)) {
        goto done;
    }
    if (dmp_hs_confirm(env.initiator, index) != DMP_HS_NO_TRUST || dmp_hs_protected_frame(env.initiator, index, NULL) != NULL ||
        !not_active(env.initiator, index)) {
        fprintf(stderr, "unapproved XX sent FINISH\n");
        goto done;
    }
    fill_approval(env.initiator, index, &approval, 1);
    if (dmp_hs_approve(env.initiator, index, &approval) != DMP_HS_COMMITTED) {
        fprintf(stderr, "initiator enrollment did not commit\n");
        goto done;
    }
    fill_approval(env.responder, 0U, &approval, 1);
    if (dmp_hs_approve(env.responder, 0U, &approval) != DMP_HS_COMMITTED ||
        !dmp_hs_enrolled(env.initiator, index) || !dmp_hs_enrolled(env.responder, 0U) ||
        !not_active(env.initiator, index) || !not_active(env.responder, 0U) ||
        dmp_hs_emit_application(env.initiator, index, (const uint8_t *)"no", 2U) != DMP_HS_NOT_ACTIVE) {
        fprintf(stderr, "enrollment commit activated an association\n");
        goto done;
    }
    writes = dmp_hs_noise_writes(env.initiator, index);
    if (dmp_hs_confirm(env.initiator, index) != DMP_HS_OK || dmp_hs_retransmit(env.initiator, index) != DMP_HS_OK ||
        dmp_hs_retransmits(env.initiator, index) != 1U || dmp_hs_noise_writes(env.initiator, index) != writes ||
        dmp_hs_next_pn(env.initiator, index) != 1U || !not_active(env.initiator, index)) {
        fprintf(stderr, "XX confirmation rewrote flight 3 or activated early\n");
        goto done;
    }
    env.now += 1000U;
    if (dmp_hs_poll(env.initiator, NULL) != DMP_HS_EXPIRED || !dmp_hs_enrolled(env.initiator, index) ||
        dmp_hs_view_of(env.initiator, index) != DMP_HS_VIEW_ENROLLED || dmp_hs_association_active(env.initiator) ||
        !dmp_hs_secrets_wiped(env.initiator, index) || env.init_store.calls != 1 ||
        dmp_hs_send_application(env.initiator, index) != DMP_HS_NOT_ACTIVE ||
        dmp_hs_association_active(env.responder) || !dmp_hs_enrolled(env.responder, 0U)) {
        fprintf(stderr, "confirmation loss cleared the committed pin or left traffic active\n");
        goto done;
    }
    memset(&retained, 0, sizeof(retained));
    retained.namespace_id = LOCAL_NS;
    retained.origin_id = ID_INIT;
    retained.epoch = 42U;
    retained.rx_cid = 90U;
    passed = dmp_hs_retain_association(env.responder, &retained) == DMP_HS_OK &&
             dmp_hs_retained_alive(env.responder, 0U) && dmp_hs_candidate(env.responder, 0U) &&
             !dmp_hs_association_active(env.responder);

done:
    close_session(&env);
    return passed && !port.nonzero_release;
}

static int test_failed_aead_limit(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t finish[64];
    uint8_t bad[64];
    size_t finish_len = 0U;
    uint32_t index = 0U;
    int passed = 0;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_aead_limit) ||
        !drive_nn(&env, &index) || dmp_hs_confirm(env.initiator, index) != DMP_HS_OK ||
        !copy_protected(env.initiator, index, finish, sizeof(finish), &finish_len)) {
        return 0;
    }
    memcpy(bad, finish, finish_len);
    bad[finish_len - 1U] ^= 0x01U;
    if (offer_frame(env.responder, bad, finish_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_DROPPED ||
        dmp_hs_failed_aead(env.responder, 0U) != 1U || !dmp_hs_candidate(env.responder, 0U) ||
        dmp_hs_association_active(env.responder)) {
        fprintf(stderr, "the first bad tag closed or authenticated the association\n");
        goto done;
    }
    if (offer_frame(env.responder, finish, finish_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_OK ||
        dmp_hs_failed_aead(env.responder, 0U) != 1U || !dmp_hs_association_active(env.responder)) {
        fprintf(stderr, "a successful packet reset the failed-AEAD count\n");
        goto done;
    }
    bad[6] = 0x01U;
    if (offer_frame(env.responder, bad, finish_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_DROPPED ||
        dmp_hs_failed_aead(env.responder, 0U) != 2U || dmp_hs_association_active(env.responder) ||
        !dmp_hs_secrets_wiped(env.responder, 0U) ||
        offer_frame(env.responder, finish, finish_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_DROPPED) {
        fprintf(stderr, "the configured failed-AEAD ceiling did not close the association\n");
        goto done;
    }
    passed = dmp_hs_send_application(env.initiator, index) == DMP_HS_NOT_ACTIVE;

done:
    close_session(&env);
    return passed && !port.nonzero_release;
}

static int expect_replay_width(const noise_fixture_probe_fixture_t *fixture, uint32_t width,
                              dmp_hs_status want, uint32_t stored)
{
    session env;
    port_ctx port;
    dmp_hs_config config;
    dmp_hs_ports ports;
    dmp_hs_status status;

    memset(&env, 0, sizeof env);
    env.now = 10000U;
    if (!open_provider(&port, &env.provider)) {
        return 0;
    }
    env.initiator = (dmp_hs *)calloc(1, dmp_hs_size());
    if (env.initiator == NULL) {
        close_session(&env);
        return 0;
    }
    fill_config(&config, fixture, 1, NULL, 0, 0);
    config.budget.replay_window = width;
    env.init_box.now = &env.now;
    env.init_box.entropy_script = &env.init_script;
    env.init_box.pin_store = &env.init_store;
    memset(&ports, 0, sizeof ports);
    ports.now_ms = now_of;
    ports.entropy = entropy_of;
    ports.commit_pin = commit_of;
    ports.ctx = &env.init_box;
    status = dmp_hs_init(env.initiator, env.provider, &config, &ports);
    if (status != want || (want == DMP_HS_OK && dmp_hs_replay_width(env.initiator) != stored)) {
        fprintf(stderr, "replay width %u -> status %d stored %u\n", width, (int)status,
                want == DMP_HS_OK ? dmp_hs_replay_width(env.initiator) : 0U);
        close_session(&env);
        return 0;
    }
    close_session(&env);
    return 1;
}

static int test_replay_ceiling(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");

    printf("P19 sizeof dmp_replay_window=%zu attempt=%zu dmp_hs=%zu\n",
           sizeof(dmp_replay_window), dmp_hs_attempt_size(), dmp_hs_size());
    if (sizeof(dmp_replay_window) != (size_t)DMP_REPLAY_WINDOW_BYTES + 16U) {
        fprintf(stderr, "replay bitmap is not the build ceiling\n");
        return 0;
    }
    if (fixture == NULL || !expect_replay_width(fixture, 0U, DMP_HS_OK, DMP_REPLAY_WINDOW_DEFAULT) ||
        !expect_replay_width(fixture, 64U, DMP_HS_OK, 64U) ||
        !expect_replay_width(fixture, DMP_REPLAY_WINDOW_MAX, DMP_HS_OK, DMP_REPLAY_WINDOW_MAX)) {
        return 0;
    }
    /* 2*ceiling is outside this build. When the ceiling is already 65536 that
     * product is not a SEC-1 width, so the rejection check stops there. */
    if (DMP_REPLAY_WINDOW_MAX < 65536U &&
        !expect_replay_width(fixture, DMP_REPLAY_WINDOW_MAX * 2U, DMP_HS_INVALID, 0U)) {
        return 0;
    }
    /* PN behind W is dropped before AEAD in replay-window (failed_aead stays 0).
     * A bad tag does not set the bit in failed-aead-limit: the same PN is
     * accepted afterwards. */
    return 1;
}

int main(void)
{
    expect_case("nn-candidate", test_nn_candidate());
    expect_case("preread-conflict", test_preread_and_conflict());
    expect_case("duplicate-loss", test_duplicate_and_loss());
    expect_case("zero-cid-low-order", test_zero_cid_and_low_order());
    expect_case("wrong-psk", test_wrong_psk());
    expect_case("xx-pin-candidate", test_xx_pin_candidate());
    expect_case("wrong-pin", test_wrong_pin_and_association());
    expect_case("oob-commit", test_oob_commit());
    expect_case("episode-backoff", test_episode_backoff());
    expect_case("orphan-quota", test_orphan_replay_and_quota());
    expect_case("scratch-serial-stale", test_scratch_serial_partial_stale());
    expect_case("entropy-cid-collision", test_entropy_cid_collision_and_cipher());
    expect_case("epoch-hash-alloc", test_epoch_hash_alloc());
    expect_case("finish-ready", test_finish_ready());
    expect_case("confirmation-loss", test_confirmation_loss());
    expect_case("replay-window", test_replay_window());
    expect_case("replay-ceiling", test_replay_ceiling());
    expect_case("enroll-not-active", test_enroll_not_active());
    expect_case("failed-aead-limit", test_failed_aead_limit());
    if (g_failures != 0) {
        fprintf(stderr, "%d handshake case(s) failed\n", g_failures);
        return 1;
    }
    return 0;
}
