/* Host tests for bootstrap plus protected FINISH/READY. Fixture keys are
 * public test material. Enrollment commit does not activate an association.
 */
#include "handshake.h"
#include "handshake_transport.h"
#include "replay_window.h"
#include "noise_fixture_probe.h"
#include "dmp/integrity.h"
#include "dmp/stream.h"

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

typedef struct hs_tx_probe {
    dmp_tx_submission submission;
    uint8_t bytes[600];
    size_t length;
    unsigned submits;
    dmp_status submit_status;
    dmp_status cancel_status;
    unsigned cancels;
    int complete_synchronously;
    dmp_tx_outcome synchronous_outcome;
    dmp_time_ms synchronous_time;
} hs_tx_probe;

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

static dmp_status hs_tx_probe_submit(void *context,
                                     const dmp_tx_submission *submission)
{
    hs_tx_probe *probe = (hs_tx_probe *)context;
    if (probe == NULL || submission == NULL || submission->frame.data == NULL ||
        submission->frame.size > sizeof(probe->bytes)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (probe->submit_status != DMP_OK) {
        dmp_status status = probe->submit_status;
        probe->submit_status = DMP_OK;
        return status;
    }
    probe->submission = *submission;
    probe->length = submission->frame.size;
    memcpy(probe->bytes, submission->frame.data, submission->frame.size);
    probe->submits++;
    if (probe->complete_synchronously) {
        submission->complete(submission->owner, submission->token,
                             probe->synchronous_outcome, probe->synchronous_time);
    }
    return DMP_OK;
}

static dmp_status hs_tx_probe_cancel(void *context, dmp_tx_token token)
{
    hs_tx_probe *probe = (hs_tx_probe *)context;
    (void)token;
    probe->cancels++;
    return probe->cancel_status;
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

static int make_pair_common(session *env, port_ctx *port, const noise_fixture_probe_fixture_t *fixture,
                            const uint8_t *init_pin, int init_has_pin, const uint8_t *resp_pin,
                            int resp_has_pin, int pairing, tune_fn tune, dmp_hs_admission *admission)
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
    if ((admission == NULL ? dmp_hs_init(env->initiator, env->provider, &init_config, &init_ports)
                           : dmp_hs_init_shared(env->initiator, env->provider, &init_config, &init_ports, admission)) != DMP_HS_OK ||
        (admission == NULL ? dmp_hs_init(env->responder, env->provider, &resp_config, &resp_ports)
                           : dmp_hs_init_shared(env->responder, env->provider, &resp_config, &resp_ports, admission)) != DMP_HS_OK ||
        dmp_hs_begin_episode(env->initiator) != DMP_HS_OK) {
        close_session(env);
        return 0;
    }
    return 1;
}

static int make_pair(session *env, port_ctx *port, const noise_fixture_probe_fixture_t *fixture,
                     const uint8_t *init_pin, int init_has_pin, const uint8_t *resp_pin,
                     int resp_has_pin, int pairing, tune_fn tune)
{
    return make_pair_common(env, port, fixture, init_pin, init_has_pin, resp_pin, resp_has_pin,
                            pairing, tune, NULL);
}

static int init_extra_responder(session *env, const noise_fixture_probe_fixture_t *fixture,
                                dmp_hs_admission *admission, dmp_hs **hs,
                                script *entropy_script, store *pin_store, box *port_box)
{
    dmp_hs_config config;
    dmp_hs_ports ports;
    *hs = (dmp_hs *)calloc(1U, dmp_hs_size());
    if (*hs == NULL) return 0;
    fill_config(&config, fixture, 0, NULL, 0, 0);
    config.next_rx_cid = 55U;
    script_add(entropy_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
    memset(pin_store->saved, 0xAB, sizeof(pin_store->saved));
    port_box->now = &env->now;
    port_box->entropy_script = entropy_script;
    port_box->pin_store = pin_store;
    memset(&ports, 0, sizeof(ports));
    ports.now_ms = now_of;
    ports.entropy = entropy_of;
    ports.commit_pin = commit_of;
    ports.ctx = port_box;
    return dmp_hs_init_shared(*hs, env->provider, &config, &ports, admission) == DMP_HS_OK;
}

static void tune_shared_cid(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    initiator->next_rx_cid = 55U;
    responder->next_rx_cid = 55U;
}

static void tune_four_parallel(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    initiator->budget.max_pending = 4U;
    initiator->budget.max_scratch = 2U;
    initiator->budget.episode_attempts = 4U;
    responder->budget.max_pending = 4U;
    responder->budget.max_scratch = 2U;
}

static int init_extra_responder_with_ephemeral(
    session *env, const noise_fixture_probe_fixture_t *fixture,
    dmp_hs_admission *admission, dmp_hs **hs, script *entropy_script,
    const uint8_t ephemeral[32], store *pin_store, box *port_box)
{
    dmp_hs_config config;
    dmp_hs_ports ports;

    *hs = (dmp_hs *)calloc(1U, dmp_hs_size());
    if (*hs == NULL) return 0;
    fill_config(&config, fixture, 0, NULL, 0, 0);
    config.next_rx_cid = 55U;
    /* An inbound flight already supplies its attempt ID. This responder only
     * requests fresh entropy for its local Noise ephemeral. */
    script_add(entropy_script, ephemeral, 32U);
    memset(pin_store->saved, 0xAB, sizeof(pin_store->saved));
    port_box->now = &env->now;
    port_box->entropy_script = entropy_script;
    port_box->pin_store = pin_store;
    memset(&ports, 0, sizeof(ports));
    ports.now_ms = now_of;
    ports.entropy = entropy_of;
    ports.commit_pin = commit_of;
    ports.ctx = port_box;
    return dmp_hs_init_shared(*hs, env->provider, &config, &ports, admission) == DMP_HS_OK;
}

static int setup_admission(dmp_hs_admission **admission, uint32_t pending, uint32_t scratch,
                           uint32_t global_work, uint32_t ingress_work)
{
    dmp_hs_admission_limits limits;
    *admission = (dmp_hs_admission *)calloc(1U, dmp_hs_admission_size());
    if (*admission == NULL) return 0;
    limits.max_pending = pending;
    limits.max_scratch = scratch;
    limits.global_work = global_work;
    limits.ingress_work = ingress_work;
    if (dmp_hs_admission_init(*admission, &limits) != DMP_HS_OK) {
        free(*admission);
        *admission = NULL;
        return 0;
    }
    return 1;
}

static void destroy_extra_hs(dmp_hs **hs)
{
    if (*hs != NULL) {
        dmp_hs_cleanup(*hs);
        free(*hs);
        *hs = NULL;
    }
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

static int test_duplicate_loss_and_processed_conflict(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t flight1[120];
    uint8_t changed[120];
    uint8_t saved[120];
    size_t flight1_len = 0U;
    size_t cached_len = 0U;
    size_t saved_len = 0U;
    uint32_t index = 0U;
    uint32_t reads;
    uint32_t noise_reads;
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
    if (cached == NULL || cached_len > sizeof(saved)) {
        goto done;
    }
    saved_len = cached_len;
    memcpy(saved, cached, saved_len);
    reads = dmp_hs_total_reads(env.responder);
    noise_reads = dmp_hs_noise_reads(env.responder, 0U);
    memcpy(changed, flight1, flight1_len);
    changed[flight1_len - 1U] ^= 0x01U;
    set_ingress(&ingress, changed, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH);
    env.now += 100U;
    if (dmp_hs_offer(env.responder, &ingress, NULL) != DMP_HS_DROPPED ||
        dmp_hs_total_reads(env.responder) != reads ||
        dmp_hs_noise_reads(env.responder, 0U) != noise_reads ||
        dmp_hs_noise_writes(env.responder, 0U) != 1U ||
        dmp_hs_retransmits(env.responder, 0U) != 0U ||
        dmp_hs_deadline(env.responder, 0U) != deadline ||
        !dmp_hs_candidate(env.responder, 0U) || dmp_hs_terminal(env.responder, 0U)) {
        fprintf(stderr, "conflicting processed duplicate changed the candidate\n");
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    if (cached_len != saved_len ||
        !bytes_match("conflict preserves cached response", cached, cached_len, saved, saved_len)) {
        fprintf(stderr, "conflicting processed duplicate changed the cached response\n");
        goto done;
    }
    set_ingress(&ingress, flight1, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH);
    env.now += 100U;
    if (dmp_hs_offer(env.responder, &ingress, NULL) != DMP_HS_OK ||
        dmp_hs_noise_writes(env.responder, 0U) != 1U || dmp_hs_retransmits(env.responder, 0U) != 1U ||
        dmp_hs_total_reads(env.responder) != reads ||
        dmp_hs_noise_reads(env.responder, 0U) != noise_reads ||
        dmp_hs_deadline(env.responder, 0U) != deadline ||
        !dmp_hs_candidate(env.responder, 0U) || dmp_hs_terminal(env.responder, 0U)) {
        fprintf(stderr, "identical duplicate wrote the flight again\n");
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    if (cached_len != saved_len || !bytes_match("retransmit", cached, cached_len, saved, saved_len)) {
        fprintf(stderr, "identical duplicate changed the cached response\n");
        goto done;
    }
    passed = dmp_hs_retransmit(env.initiator, index) == DMP_HS_OK &&
             dmp_hs_noise_writes(env.initiator, index) == 1U &&
             dmp_hs_retransmits(env.initiator, index) == 1U;

done:
    close_session(&env);
    return passed;
}

static void tune_cached_lifetime(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    initiator->budget.attempt_deadline_ms = 2000U;
    initiator->budget.cached_responses = 2U;
    (void)responder;
}

static int test_cached_flight_lifetime(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env = {0};
    port_ctx port;
    uint8_t saved[120];
    size_t cached_len = 0U;
    size_t saved_len = 0U;
    uint32_t index = 0U;
    uint32_t writes;
    uint64_t deadline;
    const uint8_t *cached;
    const uint8_t *borrowed_cached;
    int passed = 0;

    if (fixture == NULL ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_cached_lifetime) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        close_session(&env);
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (cached == NULL || cached_len == 0U || cached_len > sizeof(saved)) {
        goto done;
    }
    borrowed_cached = cached;
    saved_len = cached_len;
    memcpy(saved, cached, saved_len);
    deadline = dmp_hs_deadline(env.initiator, index);
    writes = dmp_hs_noise_writes(env.initiator, index);

    env.now = deadline - 1500U;
    if (dmp_hs_retransmit(env.initiator, index) != DMP_HS_OK ||
        dmp_hs_deadline(env.initiator, index) != deadline) {
        fprintf(stderr, "first cached-flight retry was refused before its deadline\n");
        goto done;
    }
    env.now = deadline - 1000U;
    if (dmp_hs_retransmit(env.initiator, index) != DMP_HS_OK ||
        dmp_hs_deadline(env.initiator, index) != deadline) {
        fprintf(stderr, "second cached-flight retry was refused before its deadline\n");
        goto done;
    }
    env.now = deadline - 500U;
    if (dmp_hs_retransmits(env.initiator, index) != 2U ||
        dmp_hs_retransmit(env.initiator, index) != DMP_HS_REFUSED ||
        dmp_hs_retransmits(env.initiator, index) != 2U ||
        dmp_hs_noise_writes(env.initiator, index) != writes ||
        dmp_hs_deadline(env.initiator, index) != deadline) {
        fprintf(stderr, "cached-flight retry budget or absolute deadline changed\n");
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (cached != borrowed_cached || cached_len != saved_len ||
        !bytes_match("cached flight remains stable through bounded retransmits", cached,
                     cached_len, saved, saved_len)) {
        goto done;
    }

    env.now = deadline;
    if (dmp_hs_retransmit(env.initiator, index) != DMP_HS_EXPIRED ||
        !dmp_hs_terminal(env.initiator, index) || !dmp_hs_secrets_wiped(env.initiator, index) ||
        dmp_hs_noise_writes(env.initiator, index) != writes ||
        dmp_hs_retransmits(env.initiator, index) != 2U ||
        dmp_hs_cached_flight(env.initiator, index, &cached_len) != NULL || cached_len != 0U) {
        fprintf(stderr, "expired attempt still exposed or retransmitted its cached flight\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    return passed && !port.nonzero_release;
}

static int decode_transport_frame(const hs_tx_probe *probe,
                                  dmp_stream_decoder *decoder, uint8_t *core,
                                  size_t core_capacity, dmp_time_ms now,
                                  dmp_frame_view *view)
{
    dmp_stream_result result;
    dmp_core_limits limits = {512U, DMP_HS_PAYLOAD_MAX, 8U};
    dmp_parse_result parsed;

    if (probe->length == 0U || decoder == NULL) return 0;
    result = dmp_stream_feed(decoder, (dmp_bytes){probe->bytes, probe->length}, now);
    if (result.status != DMP_OK || result.event != DMP_STREAM_FRAME ||
        result.frame.size > core_capacity) {
        return 0;
    }
    memcpy(core, result.frame.data, result.frame.size);
    parsed = dmp_core_parse((dmp_bytes){core, result.frame.size}, &limits, view);
    return parsed.status == DMP_OK;
}

static int decode_transport_packet(const hs_tx_probe *probe, uint8_t *core,
                                   size_t core_capacity, dmp_frame_view *view)
{
    dmp_core_limits limits = {512U, DMP_HS_PAYLOAD_MAX, 8U};
    dmp_parse_result parsed;
    if (probe->length < 2U || probe->length > core_capacity) return 0;
    memcpy(core, probe->bytes, probe->length);
    parsed = dmp_core_parse((dmp_bytes){core, probe->length}, &limits, view);
    return parsed.status == DMP_OK;
}

static int core_crc_matches(const dmp_frame_view *view)
{
    uint32_t crc = 0U;
    size_t n = view->frame.size;
    const uint8_t *bytes = view->frame.data;
    return n >= 4U && dmp_crc32c((dmp_bytes){bytes, n - 4U}, &crc) == DMP_OK &&
           bytes[n - 4U] == (uint8_t)crc && bytes[n - 3U] == (uint8_t)(crc >> 8U) &&
           bytes[n - 2U] == (uint8_t)(crc >> 16U) && bytes[n - 1U] == (uint8_t)(crc >> 24U);
}

static void tune_routed_confirm(dmp_hs_config *initiator, dmp_hs_config *responder);

static dmp_hs_status offer_frame(dmp_hs *hs, const uint8_t *frame, size_t length,
                                 uint32_t origin, uint32_t destination, uint64_t epoch);
static int drive_nn(session *env, uint32_t *index);

static int test_real_handshake_transport_snapshot(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env = {0};
    port_ctx port;
    hs_tx_probe probe = {0};
    dmp_transport transport = {0};
    dmp_transport copy_transport;
    dmp_hs_tx_config config = {512U, 8U, DMP_HS_TX_STREAM_R};
    dmp_hs_tx_lifetime lifetime = {0U};
    dmp_hs_tx_buffer buffers[DMP_HS_TX_SLOT_MAX];
    dmp_hs_tx_buffer exact_buffers[DMP_HS_TX_SLOT_MAX];
    uint8_t frame_buffers[DMP_HS_TX_SLOT_MAX][600];
    uint8_t exact_stream_storage[DMP_HS_TX_SLOT_MAX][512];
    uint8_t exact_packet_storage[DMP_HS_TX_SLOT_MAX][256];
    uint8_t decoder_storage[600];
    uint8_t decoder_storage2[600];
    dmp_stream_decoder decoder;
    dmp_stream_decoder decoder2;
    dmp_stream_config decoder_config = {DMP_STREAM_R, 512U, 1000U};
    dmp_hs_tx *tx = NULL;
    dmp_hs_tx_result result;
    dmp_tx_token token;
    dmp_tx_token old_token;
    dmp_tx_complete_fn old_complete;
    void *old_owner;
    uint8_t saved[DMP_HS_PAYLOAD_MAX];
    uint8_t core[512];
    uint8_t rebuilt[DMP_HS_PAYLOAD_MAX];
    size_t saved_len = 0U;
    size_t exact_stream_bound = 0U;
    uint64_t provisional_epoch;
    uint8_t expected_context[9];
    size_t count = 0U, chunk = 0U, rebuilt_len = 0U;
    const uint8_t *cached;
    uint32_t index = 0U, i;
    uint64_t deadline, generation;
    dmp_frame_view view;
    dmp_extension_view extension;
    size_t cursor;
    dmp_peer_handle peer = {0U, 1U};
    dmp_peer_handle peer2 = {1U, 1U};
    int passed = 0;

    if (fixture == NULL ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_routed_confirm) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        close_session(&env);
        return 0;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &saved_len);
    if (cached == NULL || saved_len == 0U || saved_len > sizeof(saved)) goto done;
    memcpy(saved, cached, saved_len);
    provisional_epoch = dmp_hs_boot_epoch(env.initiator, index);
    expected_context[0] = LOCAL_NS;
    for (i = 0U; i < 8U; ++i) {
        expected_context[i + 1U] = (uint8_t)(provisional_epoch >> (8U * i));
    }
    generation = dmp_hs_generation(env.initiator, index);
    deadline = dmp_hs_deadline(env.initiator, index);
    transport.context = &probe;
    transport.caps.ownership = DMP_TX_BORROW;
    transport.caps.max_frame_bytes = sizeof(probe.bytes);
    transport.submit = hs_tx_probe_submit;
    transport.cancel = hs_tx_probe_cancel;
    for (i = 0U; i < DMP_HS_TX_SLOT_MAX; ++i) {
        buffers[i].data = frame_buffers[i];
        buffers[i].capacity = sizeof(frame_buffers[i]);
    }
    tx = (dmp_hs_tx *)calloc(1U, dmp_hs_tx_size());
    /* Core and encoded MTUs are distinct: a 256-byte Stream R Core frame has
     * a 263-byte encoded bound; packet mode adds no framing bytes. */
    if (dmp_stream_encoded_bound(DMP_STREAM_R, 256U, &exact_stream_bound) != DMP_OK ||
        exact_stream_bound != 263U) goto done;
    for (i = 0U; i < DMP_HS_TX_SLOT_MAX; ++i) {
        exact_buffers[i].data = exact_stream_storage[i];
        exact_buffers[i].capacity = exact_stream_bound;
    }
    {
        dmp_hs_tx_config exact_config = {256U, 8U, DMP_HS_TX_STREAM_R};
        if (tx == NULL || dmp_hs_tx_init(tx, env.initiator, &transport, &exact_config,
                                         &lifetime, exact_buffers) != DMP_HS_TX_ACCEPTED) goto done;
        exact_config.framing = DMP_HS_TX_CORE_PACKET;
        for (i = 0U; i < DMP_HS_TX_SLOT_MAX; ++i) {
            exact_buffers[i].data = exact_packet_storage[i];
            exact_buffers[i].capacity = sizeof(exact_packet_storage[i]);
        }
        if (dmp_hs_tx_init(tx, env.initiator, &transport, &exact_config,
                           &lifetime, exact_buffers) != DMP_HS_TX_ACCEPTED) goto done;
    }
    config.max_core_frame_bytes = 512U;
    config.max_bootstrap_fragments = 8U;
    config.framing = DMP_HS_TX_STREAM_R;
    /* Coordinated open: initialize the receiver before the separate sync
     * delimiter submission. */
    if (dmp_stream_init(&decoder, decoder_config,
                        (dmp_buffer){decoder_storage, sizeof(decoder_storage)}, 0U) != DMP_OK ||
        dmp_hs_tx_init(tx, env.initiator, &transport, &config,
                                    &lifetime, buffers) !=
                          DMP_HS_TX_ACCEPTED) goto done;

    /* BUSY leaves synchronization pending and prevents handshake frames. An
     * uncertain delimiter is retried as its own operation; only definite TX
     * releases the first frame. */
    probe.submit_status = DMP_BUSY;
    if (dmp_hs_tx_sync(tx, peer, &token) != DMP_HS_TX_BUSY ||
        dmp_hs_tx_submit(tx, index, DMP_HS_TX_CACHED_FLIGHT, peer, 0U,
                         (dmp_time_ms)env.now, &token) != DMP_HS_TX_BUSY) goto done;
    if (dmp_hs_tx_sync(tx, peer, &token) != DMP_HS_TX_ACCEPTED ||
        probe.length != 1U || probe.bytes[0] != 0U) goto done;
    {
        dmp_stream_result sync_result = dmp_stream_feed(&decoder,
            (dmp_bytes){probe.bytes, probe.length}, 0U);
        if (sync_result.status != DMP_OK || sync_result.event != DMP_STREAM_NONE ||
            sync_result.consumed != 1U) goto done;
    }
    probe.submission.complete(probe.submission.owner, probe.submission.token,
                              DMP_TX_POSSIBLY_TRANSMITTED, (dmp_time_ms)(env.now + 1U));
    if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED ||
        !result.synchronization || result.outcome != DMP_TX_POSSIBLY_TRANSMITTED ||
        dmp_hs_tx_submit(tx, index, DMP_HS_TX_CACHED_FLIGHT, peer, 0U,
                         (dmp_time_ms)(env.now + 1U), &token) != DMP_HS_TX_BUSY ||
        dmp_hs_tx_sync(tx, peer, &token) != DMP_HS_TX_ACCEPTED ||
        probe.length != 1U || probe.bytes[0] != 0U) goto done;
    {
        dmp_stream_result sync_result = dmp_stream_feed(&decoder,
            (dmp_bytes){probe.bytes, probe.length}, 1U);
        if (sync_result.status != DMP_OK || sync_result.event != DMP_STREAM_NONE ||
            sync_result.consumed != 1U) goto done;
    }
    probe.submission.complete(probe.submission.owner, probe.submission.token,
                              DMP_TX_TRANSMITTED, (dmp_time_ms)(env.now + 2U));
    if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED ||
        !result.synchronization || result.outcome != DMP_TX_TRANSMITTED ||
        dmp_hs_tx_sync(tx, peer, &token) != DMP_HS_TX_NO_OUTPUT) goto done;
    /* Sync state is independent for every routed peer. Resetting one peer
     * requires its own delimiter and leaves the other route synchronized. */
    if (dmp_stream_init(&decoder2, decoder_config,
                        (dmp_buffer){decoder_storage2, sizeof(decoder_storage2)}, 0U) != DMP_OK ||
        dmp_hs_tx_sync(tx, peer2, &token) != DMP_HS_TX_ACCEPTED ||
        probe.length != 1U || probe.bytes[0] != 0U) goto done;
    {
        dmp_stream_result sync_result = dmp_stream_feed(&decoder2,
            (dmp_bytes){probe.bytes, probe.length}, (dmp_time_ms)(env.now + 3U));
        if (sync_result.status != DMP_OK || sync_result.event != DMP_STREAM_NONE ||
            sync_result.consumed != 1U) goto done;
    }
    probe.submission.complete(probe.submission.owner, probe.submission.token,
                              DMP_TX_TRANSMITTED, (dmp_time_ms)(env.now + 3U));
    if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED ||
        !result.synchronization ||
        dmp_hs_tx_binding_reset(tx, peer) != DMP_HS_TX_ACCEPTED ||
        dmp_hs_tx_submit(tx, index, DMP_HS_TX_CACHED_FLIGHT, peer, 0U,
                         (dmp_time_ms)(env.now + 3U), &token) != DMP_HS_TX_BUSY ||
        dmp_hs_tx_sync(tx, peer2, &token) != DMP_HS_TX_NO_OUTPUT ||
        dmp_hs_tx_sync(tx, peer, &token) != DMP_HS_TX_ACCEPTED ||
        probe.length != 1U || probe.bytes[0] != 0U) goto done;
    {
        dmp_stream_result sync_result = dmp_stream_feed(&decoder,
            (dmp_bytes){probe.bytes, probe.length}, (dmp_time_ms)(env.now + 4U));
        if (sync_result.status != DMP_OK || sync_result.event != DMP_STREAM_NONE ||
            sync_result.consumed != 1U) goto done;
    }
    probe.submission.complete(probe.submission.owner, probe.submission.token,
                              DMP_TX_TRANSMITTED, (dmp_time_ms)(env.now + 4U));
    if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED ||
        !result.synchronization ||
        dmp_hs_tx_sync(tx, peer, &token) != DMP_HS_TX_NO_OUTPUT) goto done;

    /* BUSY has no callback and leaves both handshake state and quota reusable. */
    probe.submit_status = DMP_BUSY;
    if (dmp_hs_tx_submit(tx, index, DMP_HS_TX_CACHED_FLIGHT, peer, 0U,
                         (dmp_time_ms)env.now, &token) != DMP_HS_TX_BUSY ||
        dmp_hs_generation(env.initiator, index) != generation) goto done;
    probe.submit_status = DMP_OK;
    if (
        dmp_hs_tx_submit(tx, index, DMP_HS_TX_CACHED_FLIGHT, peer, 0U,
                         (dmp_time_ms)env.now, &token) != DMP_HS_TX_ACCEPTED ||
        probe.submission.frame.data == cached || probe.length <= 1U ||
        probe.bytes[0] == 0U) goto done;
    memset(&view, 0, sizeof(view));
    if (!decode_transport_frame(&probe, &decoder, core, sizeof(core),
                                (dmp_time_ms)(env.now + 5U), &view) ||
        view.fields.type != DMP_TYPE_HELLO || view.fields.seq != 1U ||
        (view.fields.options & (DMP_OPT_INTEGRITY | DMP_OPT_EXT | DMP_OPT_ROUTE)) !=
            (DMP_OPT_INTEGRITY | DMP_OPT_EXT | DMP_OPT_ROUTE) ||
        !core_crc_matches(&view) || view.payload.size != saved_len ||
        memcmp(view.payload.data, saved, saved_len) != 0 ||
        view.fields.route.mode != 1U || view.fields.route.source != ID_INIT ||
        view.fields.route.destination != ID_RESP) goto done;
    cursor = 0U;
    if (dmp_extension_next(view.extensions, &cursor, &extension) != DMP_OK ||
        extension.tag != 0x0BU || extension.value.size != sizeof(expected_context) ||
        memcmp(extension.value.data, expected_context, sizeof(expected_context)) != 0 ||
        dmp_extension_next(view.extensions, &cursor, &extension) != DMP_INCOMPLETE) goto done;
    old_token = token;
    old_complete = probe.submission.complete;
    old_owner = probe.submission.owner;
    probe.submission.complete(old_owner, old_token, DMP_TX_POSSIBLY_TRANSMITTED,
                              (dmp_time_ms)(env.now + 1U));
    if (memcmp(probe.submission.frame.data, probe.bytes, probe.length) != 0 ||
        dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED ||
        !all_zero(probe.submission.frame.data, sizeof(frame_buffers[0])) ||
        result.outcome != DMP_TX_POSSIBLY_TRANSMITTED) goto done;
    if (dmp_hs_tx_submit(tx, index, DMP_HS_TX_CACHED_FLIGHT, peer, 0U,
                         (dmp_time_ms)(env.now + 2U), &token) != DMP_HS_TX_REFUSED ||
        dmp_hs_retransmits(env.initiator, index) != 0U ||
        dmp_hs_retransmit(env.initiator, index) != DMP_HS_OK ||
        dmp_hs_retransmits(env.initiator, index) != 1U) goto done;
    probe.submit_status = DMP_BUSY;
    if (dmp_hs_tx_submit(tx, index, DMP_HS_TX_CACHED_FLIGHT, peer, 0U,
                         (dmp_time_ms)(env.now + 2U), &token) != DMP_HS_TX_BUSY ||
        dmp_hs_retransmits(env.initiator, index) != 0U) goto done;
    probe.submit_status = DMP_OK;
    if (dmp_hs_tx_submit(tx, index, DMP_HS_TX_CACHED_FLIGHT, peer, 0U,
                         (dmp_time_ms)(env.now + 2U), &token) != DMP_HS_TX_ACCEPTED ||
        dmp_hs_retransmits(env.initiator, index) != 1U ||
        probe.bytes[0] == 0U) goto done;
    old_complete(old_owner, old_token, DMP_TX_FAILED_UNSENT,
                 (dmp_time_ms)(env.now + 3U));
    if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_NO_OUTPUT) goto done;
    probe.submission.complete(probe.submission.owner, probe.submission.token,
                              DMP_TX_TRANSMITTED, (dmp_time_ms)(env.now + 4U));
    if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED) goto done;

    /* The binding wire MTU forces fixed-stride DMP bootstrap FRAG slices. */
    config.max_core_frame_bytes = 512U;
    config.max_bootstrap_fragments = 8U;
    copy_transport = transport;
    copy_transport.caps.ownership = DMP_TX_COPY;
    copy_transport.caps.max_frame_bytes = 120U;
    if (dmp_stream_init(&decoder, decoder_config,
                        (dmp_buffer){decoder_storage, sizeof(decoder_storage)}, 0U) != DMP_OK ||
        dmp_hs_tx_init(tx, env.initiator, &copy_transport, &config,
                       &lifetime, buffers) !=
            DMP_HS_TX_ACCEPTED ||
        dmp_hs_tx_sync(tx, peer, &token) != DMP_HS_TX_ACCEPTED ||
        probe.length != 1U || probe.bytes[0] != 0U) goto done;
    {
        dmp_stream_result sync_result = dmp_stream_feed(&decoder,
            (dmp_bytes){probe.bytes, probe.length}, (dmp_time_ms)(env.now + 4U));
        if (sync_result.status != DMP_OK || sync_result.event != DMP_STREAM_NONE ||
            sync_result.consumed != 1U) goto done;
    }
    probe.submission.complete(probe.submission.owner, probe.submission.token,
                              DMP_TX_TRANSMITTED, (dmp_time_ms)(env.now + 4U));
    if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED ||
        !result.synchronization ||
        dmp_hs_tx_fragment_plan(tx, index, DMP_HS_TX_CACHED_FLIGHT, &count, &chunk) !=
            DMP_HS_TX_ACCEPTED || count <= 1U || chunk == 0U || count > 8U ||
        dmp_hs_retransmit(env.initiator, index) != DMP_HS_OK) goto done;
    for (i = 0U; i < count; ++i) {
        dmp_hs_tx_status submit_status;
        int decoded;
        memset(&view, 0, sizeof(view));
        submit_status = dmp_hs_tx_submit(tx, index, DMP_HS_TX_CACHED_FLIGHT, peer, i,
                                         (dmp_time_ms)(env.now + 5U + i), &token);
        decoded = submit_status == DMP_HS_TX_ACCEPTED &&
                  decode_transport_frame(&probe, &decoder, core, sizeof(core),
                                        (dmp_time_ms)(env.now + 5U + i), &view);
        if (submit_status != DMP_HS_TX_ACCEPTED || probe.bytes[0] == 0U || !decoded ||
            probe.length > copy_transport.caps.max_frame_bytes ||
            view.fields.type != DMP_TYPE_HELLO || view.fields.seq != 1U ||
            (view.fields.options & (DMP_OPT_FRAG | DMP_OPT_EXT | DMP_OPT_ROUTE |
                                    DMP_OPT_INTEGRITY)) !=
                (DMP_OPT_FRAG | DMP_OPT_EXT | DMP_OPT_ROUTE | DMP_OPT_INTEGRITY) ||
            !core_crc_matches(&view) || view.fields.route.source != ID_INIT ||
            view.fields.route.destination != ID_RESP ||
            view.fields.fragment.index != i || view.fields.fragment.chunk_size != chunk ||
            view.fields.fragment.total_size != saved_len ||
            view.payload.size > sizeof(rebuilt) - rebuilt_len) goto done;
        memcpy(rebuilt + rebuilt_len, view.payload.data, view.payload.size);
        rebuilt_len += view.payload.size;
        probe.submission.complete(probe.submission.owner, probe.submission.token,
                                  DMP_TX_TRANSMITTED, (dmp_time_ms)(env.now + 6U + i));
        if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED) goto done;
        old_token = token;
        old_complete = probe.submission.complete;
        old_owner = probe.submission.owner;
    }
    if (rebuilt_len != saved_len || memcmp(rebuilt, saved, saved_len) != 0) goto done;

    /* Packet transport carries the Core frame directly, with no Stream R
     * envelope, delimiter or stream synchronization state. */
    {
        dmp_hs_tx_config packet_config = config;
        packet_config.framing = DMP_HS_TX_CORE_PACKET;
        if (dmp_hs_tx_init(tx, env.initiator, &transport, &packet_config,
                           &lifetime, buffers) != DMP_HS_TX_ACCEPTED ||
            dmp_hs_retransmit(env.initiator, index) != DMP_HS_OK ||
            dmp_hs_tx_submit(tx, index, DMP_HS_TX_CACHED_FLIGHT, peer, 0U,
                             (dmp_time_ms)(env.now + 15U), &token) !=
                DMP_HS_TX_ACCEPTED ||
            !decode_transport_packet(&probe, core, sizeof(core), &view) ||
            view.fields.type != DMP_TYPE_HELLO || view.fields.seq != 1U ||
            (view.fields.options & DMP_OPT_INTEGRITY) == 0U ||
            view.payload.size != saved_len ||
            memcmp(view.payload.data, saved, saved_len) != 0) goto done;
        old_token = token;
        old_complete = probe.submission.complete;
        old_owner = probe.submission.owner;
        probe.submission.complete(probe.submission.owner, token,
                                  DMP_TX_TRANSMITTED,
                                  (dmp_time_ms)(env.now + 16U));
        if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED) goto done;
    }

    /* Produce an actual SEC-1 FINISH and prove Stream R preserves its Core bytes. */
    {
        dmp_hs_ingress ingress;
        size_t response_len = 0U;
        const uint8_t *response;
        if (dmp_hs_begin_episode(env.responder) != DMP_HS_OK) goto done;
        set_ingress(&ingress, saved, saved_len, ID_INIT, ID_RESP, 1U,
                    dmp_hs_boot_epoch(env.initiator, index));
        if (accept_offer(env.responder, &ingress, NULL) != DMP_HS_CANDIDATE) goto done;
        response = dmp_hs_cached_flight(env.responder, 0U, &response_len);
        if (response == NULL) goto done;
        set_ingress(&ingress, response, response_len, ID_RESP, ID_INIT, 2U,
                    dmp_hs_boot_epoch(env.responder, 0U));
        if (accept_offer(env.initiator, &ingress, NULL) != DMP_HS_CANDIDATE ||
            dmp_hs_confirm(env.initiator, index) != DMP_HS_OK) goto done;
    }
    config.max_core_frame_bytes = 512U;
    probe.complete_synchronously = 1;
    probe.synchronous_outcome = DMP_TX_TRANSMITTED;
    probe.synchronous_time = (dmp_time_ms)(env.now + 21U);
    if (dmp_stream_init(&decoder, decoder_config,
                        (dmp_buffer){decoder_storage, sizeof(decoder_storage)}, 0U) != DMP_OK ||
        dmp_hs_tx_init(tx, env.initiator, &transport, &config,
                       &lifetime, buffers) !=
            DMP_HS_TX_ACCEPTED ||
        dmp_hs_tx_sync(tx, peer, &token) != DMP_HS_TX_ACCEPTED ||
        probe.length != 1U || probe.bytes[0] != 0U) goto done;
    {
        dmp_stream_result sync_result = dmp_stream_feed(&decoder,
            (dmp_bytes){probe.bytes, probe.length}, (dmp_time_ms)(env.now + 19U));
        if (sync_result.status != DMP_OK || sync_result.event != DMP_STREAM_NONE ||
            sync_result.consumed != 1U ||
            dmp_hs_tx_binding_reset(tx, peer) != DMP_HS_TX_BUSY ||
            dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED ||
            !result.synchronization || result.outcome != DMP_TX_TRANSMITTED) goto done;
    }
    if (dmp_hs_tx_binding_reset(tx, peer) != DMP_HS_TX_ACCEPTED ||
        dmp_hs_tx_submit(tx, index, DMP_HS_TX_PROTECTED_FRAME, peer, 0U,
                         (dmp_time_ms)(env.now + 19U), &token) != DMP_HS_TX_BUSY ||
        dmp_stream_reset(&decoder, (dmp_time_ms)(env.now + 19U)) != DMP_OK ||
        dmp_hs_tx_sync(tx, peer, &token) != DMP_HS_TX_ACCEPTED ||
        probe.length != 1U || probe.bytes[0] != 0U) goto done;
    {
        dmp_stream_result sync_result = dmp_stream_feed(&decoder,
            (dmp_bytes){probe.bytes, probe.length}, (dmp_time_ms)(env.now + 19U));
        if (sync_result.status != DMP_OK || sync_result.event != DMP_STREAM_NONE ||
            sync_result.consumed != 1U ||
            dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED ||
            !result.synchronization || result.outcome != DMP_TX_TRANSMITTED) goto done;
    }
    if (dmp_hs_tx_submit(tx, index, DMP_HS_TX_PROTECTED_FRAME, peer, 0U,
                         (dmp_time_ms)(env.now + 20U), &token) != DMP_HS_TX_ACCEPTED ||
        probe.bytes[0] == 0U || dmp_hs_tx_cancel(tx, old_token) != DMP_HS_TX_STALE) goto done;
    old_complete(old_owner, old_token, DMP_TX_FAILED_UNSENT,
                 (dmp_time_ms)(env.now + 20U));
    if (!decode_transport_frame(&probe, &decoder, core, sizeof(core),
                                (dmp_time_ms)(env.now + 20U), &view) ||
        view.fields.type != DMP_TYPE_HELLO ||
        (view.fields.options & DMP_OPT_SECURITY) == 0U ||
        (view.fields.options & DMP_OPT_INTEGRITY) != 0U) goto done;
    if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED ||
        result.outcome != DMP_TX_TRANSMITTED) goto done;
    probe.complete_synchronously = 0;

    /* Expiry requests cancellation before aborting and keeps reservation/buffer pinned. */
    if (dmp_hs_tx_submit(tx, index, DMP_HS_TX_PROTECTED_FRAME, peer, 0U,
                         (dmp_time_ms)(env.now + 22U), &token) != DMP_HS_TX_ACCEPTED) goto done;
    probe.cancel_status = DMP_BUSY;
    if (dmp_hs_tx_cancel(tx, token) != DMP_HS_TX_TRANSPORT_REJECTED ||
        !dmp_hs_terminal(env.initiator, index)) goto done;
    probe.cancel_status = DMP_OK;
    if (dmp_hs_tx_cancel(tx, token) != DMP_HS_TX_ACCEPTED) goto done;
    dmp_hs_tx_expire(tx, deadline);
    probe.submission.complete(probe.submission.owner, probe.submission.token,
                              DMP_TX_POSSIBLY_TRANSMITTED, deadline);
    if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED || !result.expired ||
        !result.cancellation_requested || result.outcome != DMP_TX_POSSIBLY_TRANSMITTED ||
        probe.cancels != 2U || !dmp_hs_terminal(env.initiator, index)) goto done;
    passed = 1;

done:
    free(tx);
    close_session(&env);
    return passed && !port.nonzero_release;
}

static int test_late_active_transport_completion(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env = {0};
    port_ctx port = {0};
    hs_tx_probe probe = {0};
    dmp_transport transport = {0};
    dmp_hs_tx_config config = {512U, 8U, DMP_HS_TX_CORE_PACKET};
    dmp_hs_tx_lifetime lifetime = {0U};
    dmp_hs_tx_buffer buffers[DMP_HS_TX_SLOT_MAX];
    uint8_t frame_storage[DMP_HS_TX_SLOT_MAX][600];
    dmp_hs_tx *tx = NULL;
    dmp_hs_tx_result result;
    dmp_tx_token token;
    dmp_peer_handle peer = {0U, 1U};
    uint32_t index = 0U;
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    uint64_t generation = 0U;
    uint64_t deadline = 0U;
    size_t frame_len = 0U;
    const uint8_t *frame;
    int passed = 0;
    uint32_t i;
    const char *failed_at = "setup";

    if (fixture == NULL) {
        failed_at = "fixture";
        goto done;
    }
    if (!make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0,
                   tune_routed_confirm)) {
        failed_at = "make pair";
        goto done;
    }
    if (!drive_nn(&env, &index)) {
        failed_at = "drive NN";
        goto done;
    }
    if (!dmp_hs_epochs(env.initiator, index, &epoch_i, &epoch_r)) {
        failed_at = "read epochs";
        goto done;
    }
    if (dmp_hs_confirm(env.initiator, index) != DMP_HS_OK) {
        failed_at = "confirm initiator";
        goto done;
    }
    transport.context = &probe;
    transport.caps.ownership = DMP_TX_BORROW;
    transport.caps.max_frame_bytes = sizeof(probe.bytes);
    transport.submit = hs_tx_probe_submit;
    transport.cancel = hs_tx_probe_cancel;
    for (i = 0U; i < DMP_HS_TX_SLOT_MAX; ++i) {
        buffers[i].data = frame_storage[i];
        buffers[i].capacity = sizeof(frame_storage[i]);
    }
    tx = (dmp_hs_tx *)calloc(1U, dmp_hs_tx_size());
    if (tx == NULL || dmp_hs_tx_init(tx, env.initiator, &transport, &config,
                                    &lifetime, buffers) != DMP_HS_TX_ACCEPTED) {
        goto done;
    }
    deadline = dmp_hs_deadline(env.initiator, index);
    generation = dmp_hs_generation(env.initiator, index);
    failed_at = "submit protected FINISH";
    if (deadline == 0U ||
        dmp_hs_tx_submit(tx, index, DMP_HS_TX_PROTECTED_FRAME, peer, 0U,
                         (dmp_time_ms)env.now, &token) != DMP_HS_TX_ACCEPTED ||
        probe.submits != 1U || probe.submission.complete == NULL) {
        goto done;
    }

    failed_at = "activate from READY";
    frame = dmp_hs_protected_frame(env.initiator, index, &frame_len);
    if (frame == NULL || frame_len == 0U ||
        offer_frame(env.responder, frame, frame_len, ID_INIT, ID_RESP, epoch_i) != DMP_HS_OK) {
        goto done;
    }
    frame = dmp_hs_protected_frame(env.responder, 0U, &frame_len);
    if (frame == NULL || frame_len == 0U ||
        offer_frame(env.initiator, frame, frame_len, ID_RESP, ID_INIT, epoch_r) != DMP_HS_OK ||
        dmp_hs_view_of(env.initiator, index) != DMP_HS_VIEW_ACTIVE ||
        dmp_hs_send_application(env.initiator, index) != DMP_HS_OK) {
        goto done;
    }

    /* The protected FINISH was accepted before READY activated this same
     * attempt. Its callback may arrive at the handshake's latest-start time;
     * that late transport result must not tear down the active association. */
    failed_at = "deadline expiry after READY";
    dmp_hs_tx_expire(tx, (dmp_time_ms)deadline);
    if (probe.cancels != 0U || dmp_hs_tx_take(tx, &result) != DMP_HS_TX_NO_OUTPUT ||
        dmp_hs_view_of(env.initiator, index) != DMP_HS_VIEW_ACTIVE ||
        dmp_hs_generation(env.initiator, index) != generation) {
        goto done;
    }

    failed_at = "late completion";
    probe.submission.complete(probe.submission.owner, token, DMP_TX_TRANSMITTED,
                              (dmp_time_ms)deadline);
    if (dmp_hs_tx_take(tx, &result) != DMP_HS_TX_ACCEPTED || result.expired ||
        result.outcome != DMP_TX_TRANSMITTED || probe.cancels != 0U ||
        dmp_hs_generation(env.initiator, index) != generation ||
        dmp_hs_view_of(env.initiator, index) != DMP_HS_VIEW_ACTIVE ||
        dmp_hs_send_application(env.initiator, index) != DMP_HS_OK ||
        dmp_hs_terminal(env.initiator, index)) {
        goto done;
    }
    passed = 1;

done:
    if (!passed) {
        fprintf(stderr,
                "late-active completion failed at %s: view=%u hs=%d deadline=%llu gen=%llu/%llu\n",
                failed_at, (unsigned)dmp_hs_view_of(env.initiator, index),
                (int)dmp_hs_send_application(env.initiator, index),
                (unsigned long long)deadline,
                (unsigned long long)dmp_hs_generation(env.initiator, index),
                (unsigned long long)generation);
    }
    free(tx);
    close_session(&env);
    return passed && !port.nonzero_release;
}

static void tune_episode(dmp_hs_config *initiator, dmp_hs_config *responder);

static int test_invalid_authenticated_payload_restart(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_provider_handshake raw;
    dmp_provider_handshake_keys keys;
    uint8_t flight1[120];
    uint8_t bad1[120];
    uint8_t flight2[80];
    uint8_t first_flight[120];
    uint8_t zero_body[96];
    uint8_t noise[80];
    uint8_t plain[8];
    uint8_t retry_id[16];
    uint8_t retry_ephemeral[32];
    uint8_t first_id[16];
    size_t flight1_len = 0U;
    size_t flight2_len = 0U;
    size_t noise_len = 0U;
    size_t plain_len = 0U;
    size_t cached_len = 0U;
    uint32_t index = 0U;
    uint32_t reads;
    uint32_t global_work;
    uint32_t episode_work;
    uint64_t generation;
    const uint8_t *cached;
    dmp_hs_ingress ingress;
    int passed = 0;

    if (fixture == NULL || !hex_decode(NN_FLIGHT1, flight1, sizeof(flight1), &flight1_len) ||
        !hex_decode(NN_FLIGHT2, flight2, sizeof(flight2), &flight2_len) ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_episode)) {
        return 0;
    }
    memcpy(retry_id, fixture->attempt_id.data, sizeof(retry_id));
    retry_id[15] ^= 0x80U;
    memset(retry_ephemeral, 0x7BU, sizeof(retry_ephemeral));
    script_add(&env.init_script, retry_id, sizeof(retry_id));
    script_add(&env.init_script, retry_ephemeral, sizeof(retry_ephemeral));
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (cached == NULL || cached_len > sizeof(first_flight) ||
        !dmp_hs_copy_attempt_id(env.initiator, index, first_id)) {
        goto done;
    }
    memcpy(first_flight, cached, cached_len);
    generation = dmp_hs_generation(env.initiator, index);
    global_work = dmp_hs_global_work(env.initiator);
    episode_work = dmp_hs_episode_work(env.initiator);
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
        dmp_hs_generation(env.initiator, index) <= generation ||
        dmp_hs_total_reads(env.initiator) != reads + 1U || !not_active(env.initiator, index) ||
        dmp_hs_episode_attempts_used(env.initiator) != 1U ||
        dmp_hs_episode_work(env.initiator) <= episode_work ||
        dmp_hs_global_work(env.initiator) <= global_work) {
        fprintf(stderr, "zero responder CID did not abort the attempt\n");
        goto done;
    }
    set_ingress(&ingress, flight2, flight2_len, ID_RESP, ID_INIT, 2U, NN_EPOCH);
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED ||
        dmp_hs_total_reads(env.initiator) != reads + 1U) {
        fprintf(stderr, "late continuation resumed an aborted attempt\n");
        goto done;
    }
    global_work = dmp_hs_global_work(env.initiator);
    episode_work = dmp_hs_episode_work(env.initiator);
    env.now += 999U;
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_REFUSED ||
        dmp_hs_episode_attempts_used(env.initiator) != 1U ||
        dmp_hs_episode_work(env.initiator) != episode_work ||
        dmp_hs_global_work(env.initiator) != global_work) {
        fprintf(stderr, "invalid authenticated payload bypassed restart backoff\n");
        goto done;
    }
    env.now++;
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK || index != 0U ||
        dmp_hs_episode_attempts_used(env.initiator) != 2U ||
        dmp_hs_episode_work(env.initiator) <= episode_work ||
        dmp_hs_global_work(env.initiator) <= global_work ||
        !dmp_hs_copy_attempt_id(env.initiator, index, retry_id) ||
        memcmp(first_id, retry_id, sizeof(first_id)) == 0 ||
        dmp_hs_generation(env.initiator, index) <= generation) {
        fprintf(stderr, "fresh attempt reset the experiment budget or reused its generation/ID\n");
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    if (cached == NULL || cached_len != flight1_len || cached_len < 104U ||
        memcmp(cached, first_flight, cached_len) == 0 ||
        memcmp(cached + 72U, first_flight + 72U, 32U) == 0) {
        fprintf(stderr, "fresh attempt reused the previous Noise flight keys\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    return passed;
}

static int test_low_order_dh_abort(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t flight1[120];
    uint8_t bad1[120];
    size_t flight1_len = 0U;
    int passed = 0;

    if (fixture == NULL || !hex_decode(NN_FLIGHT1, flight1, sizeof(flight1), &flight1_len) ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL)) {
        return 0;
    }
    memcpy(bad1, flight1, flight1_len);
    memset(bad1 + 72U, 0, 32U);
    bad1[72] = 1U;
    passed = drive_flight(env.responder, bad1, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH,
                          DMP_HS_ABORTED) &&
             dmp_hs_total_reads(env.responder) == 1U && dmp_hs_secrets_wiped(env.responder, 0U);
    if (!passed) {
        fprintf(stderr, "low-order flight did not abort\n");
    }

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
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        fprintf(stderr, "episode initial schedule refused\n");
        goto done;
    }
    if (!dmp_hs_copy_attempt_id(env.initiator, index, seen[0])) {
        fprintf(stderr, "episode first attempt ID unavailable\n");
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
        fprintf(stderr, "episode later-attempt schedule/begin/cancel failed\n");
        goto done;
    }
    env.now += 1000U;
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        fprintf(stderr, "episode later-attempt restart schedule refused\n");
        goto done;
    }
    passed = dmp_hs_global_work(env.initiator) >= global_after_first &&
             dmp_hs_begin_episode(env.initiator) == DMP_HS_REFUSED &&
             dmp_hs_global_work(env.initiator) >= global_after_first &&
             dmp_hs_episode_attempts_used(env.initiator) == 2U;
    if (!passed) {
        fprintf(stderr, "episode terminal budget mismatch: attempts=%u work=%u baseline=%u\n",
                dmp_hs_episode_attempts_used(env.initiator),
                dmp_hs_global_work(env.initiator), global_after_first);
    }

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

static void tune_pending_rotation(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    initiator->budget.max_pending = 1U;
    responder->budget.max_pending = 1U;
    initiator->budget.confirmation_timeout_ms = 1000U;
    initiator->budget.confirmation_attempts = 3U;
    responder->budget.confirmation_timeout_ms = 1000U;
    responder->budget.confirmation_attempts = 3U;
    initiator->budget.failed_aead_limit = 4U;
    responder->budget.failed_aead_limit = 4U;
}

static dmp_hs_status offer_frame(dmp_hs *hs, const uint8_t *frame, size_t length,
                                 uint32_t origin, uint32_t destination, uint64_t epoch);
static int drive_nn(session *env, uint32_t *index);
static int copy_protected(const dmp_hs *hs, uint32_t index, uint8_t *out,
                          size_t cap, size_t *length);

static int test_active_association_does_not_consume_pending_slot(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t finish[64];
    uint8_t ready[64];
    uint8_t second_attempt_id[16];
    uint8_t second_init_eph[32];
    uint8_t second_resp_eph[32];
    size_t finish_len = 0U;
    size_t ready_len = 0U;
    size_t second_flight1_len = 0U;
    uint32_t active_index = 0U;
    uint32_t replacement_index = 0U;
    uint32_t blocked_index = 0U;
    const uint8_t *cached;
    dmp_hs_ingress ingress;
    dmp_hs_status status;
    int passed = 0;

    if (fixture == NULL ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_pending_rotation)) {
        return 0;
    }
    if (!drive_nn(&env, &active_index)) {
        fprintf(stderr, "initial NN handshake failed\n");
        goto done;
    }
    if (dmp_hs_confirm(env.initiator, active_index) != DMP_HS_OK ||
        !copy_protected(env.initiator, active_index, finish, sizeof(finish), &finish_len)) {
        fprintf(stderr, "initial FINISH creation failed\n");
        goto done;
    }
    if (offer_frame(env.responder, finish, finish_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_OK ||
        !copy_protected(env.responder, 0U, ready, sizeof(ready), &ready_len) ||
        offer_frame(env.initiator, ready, ready_len, ID_RESP, ID_INIT, NN_EPOCH_R) != DMP_HS_OK ||
        !dmp_hs_association_active(env.initiator) || !dmp_hs_association_active(env.responder)) {
        fprintf(stderr, "initial association activation failed\n");
        goto done;
    }

    memset(second_attempt_id, 0xA2, sizeof(second_attempt_id));
    memcpy(second_init_eph, fixture->init_ephemeral.data, sizeof(second_init_eph));
    memcpy(second_resp_eph, fixture->resp_ephemeral.data, sizeof(second_resp_eph));
    second_init_eph[0] ^= 0x01U;
    second_resp_eph[0] ^= 0x02U;
    script_add(&env.init_script, second_attempt_id, sizeof(second_attempt_id));
    script_add(&env.init_script, second_init_eph, sizeof(second_init_eph));
    script_add(&env.resp_script, second_resp_eph, sizeof(second_resp_eph));

    status = dmp_hs_schedule(env.initiator, &replacement_index);
    if (status != DMP_HS_OK || replacement_index == active_index) {
        fprintf(stderr, "replacement schedule status=%d index=%u active=%u pending=%u\n",
                (int)status, replacement_index, active_index, dmp_hs_pending(env.initiator));
        fprintf(stderr, "active association consumed the replacement pending slot\n");
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, replacement_index, &second_flight1_len);
    if (cached == NULL) {
        goto done;
    }
    set_ingress(&ingress, cached, second_flight1_len, ID_INIT, ID_RESP, 1U,
                dmp_hs_boot_epoch(env.initiator, replacement_index));
    status = accept_offer(env.responder, &ingress, NULL);
    if (status != DMP_HS_CANDIDATE || !dmp_hs_association_active(env.responder) ||
        dmp_hs_pending(env.responder) != 1U || !dmp_hs_candidate(env.responder, 1U)) {
        fprintf(stderr, "replacement receive status=%d active=%d pending=%u candidate0=%d candidate1=%d\n",
                (int)status, dmp_hs_association_active(env.responder),
                dmp_hs_pending(env.responder), dmp_hs_candidate(env.responder, 0U),
                dmp_hs_candidate(env.responder, 1U));
        fprintf(stderr, "active association blocked one pending replacement candidate\n");
        goto done;
    }

    if (dmp_hs_schedule(env.initiator, &blocked_index) != DMP_HS_REFUSED ||
        !dmp_hs_association_active(env.initiator) || dmp_hs_pending(env.initiator) != 1U) {
        fprintf(stderr, "max_pending did not bound the active initiator's in-progress replacement\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    return passed && !port.nonzero_release;
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
        fprintf(stderr, "orphan initial schedule or retained-association setup failed\n");
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
    memcpy(flight1, cached, cached_len);
    flight1_len = cached_len;
    if (!drive_flight(env.responder, flight1, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH,
                      DMP_HS_CANDIDATE)) {
        fprintf(stderr, "orphan initial flight was not accepted as candidate\n");
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
        fprintf(stderr, "orphan expiry mismatch: expired=%u pending=%u wiped=%d retained=%d\n",
                expired, dmp_hs_pending(env.responder),
                dmp_hs_secrets_wiped(env.responder, 0U),
                dmp_hs_retained_alive(env.responder, 0U));
        goto done;
    }
    set_ingress(&ingress, flight1, flight1_len, ID_INIT, ID_RESP, 1U, NN_EPOCH);
    if (dmp_hs_offer(env.responder, &ingress, &stale) != DMP_HS_AWAITING) {
        fprintf(stderr, "replayed flight 1 was not admitted after removal\n");
        goto done;
    }
    stale.generation ^= UINT64_C(1);
    if (dmp_hs_accept(env.responder, &stale) != DMP_HS_STALE) {
        fprintf(stderr, "orphan stale completion generation was not rejected\n");
        goto done;
    }
    stale.generation ^= UINT64_C(1);
    if (dmp_hs_accept(env.responder, &stale) != DMP_HS_CANDIDATE) {
        fprintf(stderr, "orphan live completion was not accepted after stale check\n");
        goto done;
    }
    cached = dmp_hs_cached_flight(env.responder, 0U, &cached_len);
    passed = cached_len == reply_len && memcmp(cached, first_reply, reply_len) != 0 &&
             dmp_hs_retained_alive(env.responder, 0U) && not_active(env.responder, 0U);
    if (!passed) {
        fprintf(stderr, "orphan replay result mismatch: cached=%zu prior=%zu retained=%d active=%d\n",
                cached_len, reply_len, dmp_hs_retained_alive(env.responder, 0U),
                !not_active(env.responder, 0U));
    }

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
    uint8_t partial_expected[8];
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
    memcpy(partial_expected, partial_a, sizeof(partial_expected));
    partial_b[0] ^= 0x01U;
    memset(&ingress, 0, sizeof(ingress));
    ingress.payload = partial_a;
    ingress.payload_len = sizeof(partial_a);
    ingress.partial = 1;
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED) {
        goto done;
    }
    memset(partial_a, 0xA5, sizeof(partial_a));
    if (!dmp_hs_copy_partial(env.initiator, held, sizeof(held), &held_len) ||
        !bytes_match("partial input copied before return", held, held_len,
                     partial_expected, sizeof(partial_expected))) {
        fprintf(stderr, "partial input remained borrowed after dmp_hs_offer\n");
        goto done;
    }
    ingress.payload = partial_b;
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_DROPPED ||
        !dmp_hs_copy_partial(env.initiator, held, sizeof(held), &held_len) ||
        !bytes_match("partial", held, held_len, partial_expected, sizeof(partial_expected)) ||
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
    uint8_t saved_flight2[80];
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
    memcpy(saved_flight2, flight2, flight2_len);
    set_ingress(&ingress, flight2, flight2_len, ID_RESP, ID_INIT, 2U, NN_EPOCH);
    if (dmp_hs_offer(env.initiator, &ingress, &completion) != DMP_HS_AWAITING) {
        fprintf(stderr, "flight 2 was not held for accept\n");
        goto done;
    }
    memset(flight2, 0xA5, flight2_len);
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
    {
        uint32_t reads = dmp_hs_total_reads(env.initiator);
        uint32_t noise_reads = dmp_hs_noise_reads(env.initiator, completion.attempt_index);
        uint32_t writes = dmp_hs_noise_writes(env.initiator, completion.attempt_index);
        uint64_t deadline = dmp_hs_deadline(env.initiator, completion.attempt_index);

        set_ingress(&ingress, saved_flight2, flight2_len, ID_RESP, ID_INIT, 2U, NN_EPOCH);
        if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_OK ||
            dmp_hs_total_reads(env.initiator) != reads ||
            dmp_hs_noise_reads(env.initiator, completion.attempt_index) != noise_reads ||
            dmp_hs_noise_writes(env.initiator, completion.attempt_index) != writes ||
            dmp_hs_deadline(env.initiator, completion.attempt_index) != deadline ||
            !dmp_hs_candidate(env.initiator, completion.attempt_index) ||
            dmp_hs_terminal(env.initiator, completion.attempt_index)) {
            fprintf(stderr, "accepted flight-2 duplicate changed the candidate\n");
            goto done;
        }
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

static void tune_short_association_lifetime(dmp_hs_config *initiator,
                                            dmp_hs_config *responder)
{
    tune_confirm(initiator, responder);
    initiator->budget.association_lifetime_ms = 100U;
    responder->budget.association_lifetime_ms = 100U;
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

static void tune_routed_confirm(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    tune_confirm(initiator, responder);
    initiator->confirmation_route_ttl = 2U;
    responder->confirmation_route_ttl = 2U;
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
    dmp_hs_status status;
    dmp_hs_ingress ingress;

    status = dmp_hs_schedule(env->initiator, index);
    if (status != DMP_HS_OK) {
        fprintf(stderr, "drive_nn initiator schedule status=%d pending=%u\n",
                (int)status, dmp_hs_pending(env->initiator));
        return 0;
    }
    cached = dmp_hs_cached_flight(env->initiator, *index, &length);
    set_ingress(&ingress, cached, length, ID_INIT, ID_RESP, 1U, NN_EPOCH);
    status = accept_offer(env->responder, &ingress, NULL);
    if (status != DMP_HS_CANDIDATE) {
        fprintf(stderr, "drive_nn responder flight status=%d expected=%d pending=%u\n",
                (int)status, DMP_HS_CANDIDATE, dmp_hs_pending(env->responder));
        return 0;
    }
    cached = dmp_hs_cached_flight(env->responder, 0U, &length);
    set_ingress(&ingress, cached, length, ID_RESP, ID_INIT, 2U, NN_EPOCH);
    status = accept_offer(env->initiator, &ingress, NULL);
    if (status != DMP_HS_CANDIDATE) {
        fprintf(stderr, "drive_nn initiator flight status=%d expected=%d pending=%u\n",
                (int)status, DMP_HS_CANDIDATE, dmp_hs_pending(env->initiator));
        return 0;
    }
    return 1;
}

static int drive_nn_with_current_epochs(session *env, uint32_t *index)
{
    const uint8_t *cached;
    size_t length = 0U;
    dmp_hs_ingress ingress;

    if (dmp_hs_schedule(env->initiator, index) != DMP_HS_OK) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->initiator, *index, &length);
    set_ingress(&ingress, cached, length, ID_INIT, ID_RESP, 1U,
                dmp_hs_boot_epoch(env->initiator, *index));
    if (accept_offer(env->responder, &ingress, NULL) != DMP_HS_CANDIDATE) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->responder, 0U, &length);
    set_ingress(&ingress, cached, length, ID_RESP, ID_INIT, 2U,
                dmp_hs_boot_epoch(env->responder, 0U));
    return accept_offer(env->initiator, &ingress, NULL) == DMP_HS_CANDIDATE;
}

static int test_active_expiry_releases_reservations(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env = {0};
    port_ctx port;
    uint8_t retry_attempt_id[16];
    uint8_t finish[64];
    uint8_t ready[64];
    size_t finish_len = 0U;
    size_t ready_len = 0U;
    uint32_t index = 0U;
    uint32_t expired_index = UINT32_MAX;
    int passed = 0;

    if (fixture == NULL ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0,
                   tune_short_association_lifetime) ||
        !drive_nn(&env, &index) || dmp_hs_confirm(env.initiator, index) != DMP_HS_OK ||
        !copy_protected(env.initiator, index, finish, sizeof(finish), &finish_len) ||
        offer_frame(env.responder, finish, finish_len, ID_INIT, ID_RESP, NN_EPOCH_I) != DMP_HS_OK ||
        !copy_protected(env.responder, 0U, ready, sizeof(ready), &ready_len) ||
        offer_frame(env.initiator, ready, ready_len, ID_RESP, ID_INIT, NN_EPOCH_R) != DMP_HS_OK ||
        !dmp_hs_association_active(env.initiator) ||
        !dmp_hs_association_active(env.responder)) {
        close_session(&env);
        return 0;
    }

    env.now += 100U;
    if (dmp_hs_poll(env.initiator, &expired_index) != DMP_HS_EXPIRED ||
        expired_index != index || dmp_hs_poll(env.responder, &expired_index) != DMP_HS_EXPIRED ||
        !dmp_hs_terminal(env.initiator, index) ||
        !dmp_hs_terminal(env.responder, 0U) ||
        !dmp_hs_secrets_wiped(env.initiator, index) ||
        !dmp_hs_secrets_wiped(env.responder, 0U)) {
        fprintf(stderr, "active association expiry did not terminate both endpoints\n");
        goto done;
    }
    env.now += 1000U; /* Respect the configured restart backoff after expiry. */

    /* Reuse the same Noise ephemeral inputs so the next association derives
     * the same directional epoch keys. A successful second candidate proves
     * expiry released its CID/key owners before alloc_attempt reused the slot. */
    memset(retry_attempt_id, 0x66, sizeof(retry_attempt_id));
    script_add(&env.init_script, retry_attempt_id, sizeof(retry_attempt_id));
    script_add(&env.init_script, fixture->init_ephemeral.data,
               fixture->init_ephemeral.size);
    script_add(&env.resp_script, fixture->resp_ephemeral.data,
               fixture->resp_ephemeral.size);
    if (!drive_nn_with_current_epochs(&env, &index) || index != 0U ||
        !dmp_hs_candidate(env.initiator, index) ||
        !dmp_hs_candidate(env.responder, 0U)) {
        fprintf(stderr, "expired active CID/epoch reservations blocked a fresh attempt\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    return passed && !port.nonzero_release;
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
    const uint8_t *borrowed_finish;
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
    if (dmp_hs_confirm(env.initiator, index) != DMP_HS_OK ||
        (borrowed_finish = dmp_hs_protected_frame(env.initiator, index, NULL)) == NULL ||
        !copy_protected(env.initiator, index, finish, sizeof(finish), &finish_len) ||
        !bytes_match("finish", finish, finish_len, fixture->finish.frame.data, fixture->finish.frame.size) ||
        borrowed_finish != dmp_hs_protected_frame(env.initiator, index, NULL) ||
        !bytes_match("borrowed FINISH frame", borrowed_finish, finish_len, finish, finish_len) ||
        dmp_hs_send_application(env.initiator, index) != DMP_HS_NOT_ACTIVE ||
        borrowed_finish != dmp_hs_protected_frame(env.initiator, index, NULL) ||
        !bytes_match("borrowed FINISH survives refused send", borrowed_finish, finish_len,
                     finish, finish_len)) {
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

static int routed_confirmation_matches(const uint8_t *frame, size_t frame_len,
                                       uint32_t source, uint32_t destination,
                                       uint64_t epoch)
{
    dmp_core_limits limits = {512U, DMP_HS_APP_PLAIN_MAX, 2U};
    dmp_frame_view view;
    dmp_parse_result parsed;
    dmp_extension_view extension;
    size_t cursor = 0U;
    uint32_t namespace_id;
    uint64_t got_epoch;

    memset(&view, 0, sizeof(view));
    parsed = dmp_core_parse((dmp_bytes){frame, frame_len}, &limits, &view);
    if (parsed.status != DMP_OK ||
        view.fields.options != (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ROUTE | DMP_OPT_SECURITY |
                                         DMP_OPT_EXT) ||
        view.fields.type != DMP_TYPE_HELLO || view.fields.seq != 0U ||
        view.fields.route.mode != 1U || view.fields.route.ttl != 2U ||
        view.fields.route.source != source || view.fields.route.destination != destination ||
        view.fields.security.pn != 0U ||
        dmp_extension_next(view.extensions, &cursor, &extension) != DMP_OK ||
        extension.tag != 0x0BU || extension.value.size != 9U ||
        extension.value.data[0] != LOCAL_NS ||
        dmp_extension_next(view.extensions, &cursor, &(dmp_extension_view){0}) != DMP_INCOMPLETE) {
        return 0;
    }
    namespace_id = extension.value.data[0];
    got_epoch = (uint64_t)extension.value.data[1] |
                ((uint64_t)extension.value.data[2] << 8U) |
                ((uint64_t)extension.value.data[3] << 16U) |
                ((uint64_t)extension.value.data[4] << 24U) |
                ((uint64_t)extension.value.data[5] << 32U) |
                ((uint64_t)extension.value.data[6] << 40U) |
                ((uint64_t)extension.value.data[7] << 48U) |
                ((uint64_t)extension.value.data[8] << 56U);
    return namespace_id == LOCAL_NS && got_epoch == epoch;
}

static int test_routed_finish_ready(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint8_t finish[128];
    uint8_t ready[128];
    size_t finish_len = 0U;
    size_t ready_len = 0U;
    uint32_t index = 0U;
    uint64_t epoch_i;
    uint64_t epoch_r;
    dmp_hs_status wrong_finish_status;
    dmp_hs_status finish_status;
    dmp_hs_status wrong_ready_status;
    dmp_hs_status ready_status;
    int passed = 0;

    if (fixture == NULL ||
        !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_routed_confirm) ||
        !drive_nn(&env, &index) ||
        !dmp_hs_epochs(env.initiator, index, &epoch_i, &epoch_r) ||
        dmp_hs_confirm(env.initiator, index) != DMP_HS_OK ||
        !copy_protected(env.initiator, index, finish, sizeof(finish), &finish_len) ||
        !routed_confirmation_matches(finish, finish_len, ID_INIT, ID_RESP, epoch_i)) {
        fprintf(stderr, "initiator did not encode routed FINISH with its association CONTEXT\n");
        close_session(&env);
        return 0;
    }
    wrong_finish_status = offer_frame(env.responder, finish, finish_len, ID_INIT, ID_RESP, epoch_r);
    finish_status = offer_frame(env.responder, finish, finish_len, ID_INIT, ID_RESP, epoch_i);
    if (wrong_finish_status != DMP_HS_DROPPED || finish_status != DMP_HS_OK ||
        !copy_protected(env.responder, 0U, ready, sizeof(ready), &ready_len) ||
        !routed_confirmation_matches(ready, ready_len, ID_RESP, ID_INIT, epoch_r)) {
        fprintf(stderr, "routed FINISH failed (wrong=%d correct=%d ready_len=%zu)\n",
                (int)wrong_finish_status, (int)finish_status, ready_len);
        fprintf(stderr, "routed FINISH state failed_aead=%u next_pn=%llu candidate=%d\n",
                dmp_hs_failed_aead(env.responder, 0U),
                (unsigned long long)dmp_hs_next_pn(env.responder, 0U),
                dmp_hs_candidate(env.responder, 0U));
        goto done;
    }
    wrong_ready_status = offer_frame(env.initiator, ready, ready_len, ID_RESP, ID_INIT, epoch_i);
    ready_status = offer_frame(env.initiator, ready, ready_len, ID_RESP, ID_INIT, epoch_r);
    if (wrong_ready_status != DMP_HS_DROPPED || ready_status != DMP_HS_OK ||
        !dmp_hs_association_active(env.initiator) || !dmp_hs_association_active(env.responder)) {
        fprintf(stderr, "routed READY failed (wrong=%d correct=%d active_i=%d active_r=%d)\n",
                (int)wrong_ready_status, (int)ready_status,
                dmp_hs_association_active(env.initiator), dmp_hs_association_active(env.responder));
        goto done;
    }
    passed = 1;

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

static int test_cleanup_erases_owner(void)
{
    static const char *const fixture_names[] = {"nnpsk0", "xx"};
    size_t fixture_index;

    for (fixture_index = 0U;
         fixture_index < sizeof(fixture_names) / sizeof(fixture_names[0]); ++fixture_index) {
        const noise_fixture_probe_fixture_t *fixture = find_fixture(fixture_names[fixture_index]);
        session env;
        port_ctx port;
        dmp_hs *owner;
        const uint8_t *cached;
        size_t cached_len = 0U;
        uint32_t index = 0U;
        int pairing = fixture_index == 1U;

        memset(&env, 0, sizeof(env));
        memset(&port, 0, sizeof(port));
        if (fixture == NULL ||
            !make_pair(&env, &port, fixture, NULL, 0, NULL, 0, pairing, NULL) ||
            dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
            close_session(&env);
            return 0;
        }
        cached = dmp_hs_cached_flight(env.initiator, index, &cached_len);
        if (cached == NULL || cached_len == 0U || port.alloc_calls == 0U) {
            close_session(&env);
            return 0;
        }

        owner = env.initiator;
        dmp_hs_cleanup(owner);
        if (!all_zero(owner, dmp_hs_size()) || port.nonzero_release) {
            env.initiator = NULL;
            free(owner);
            close_session(&env);
            return 0;
        }
        env.initiator = NULL;
        free(owner);
        close_session(&env);
        if (port.nonzero_release) {
            return 0;
        }
    }
    return 1;
}

static int test_shared_pending_recovery(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_hs_admission *admission = NULL;
    uint32_t index = 0U;
    int passed = 0;

    if (fixture == NULL || !setup_admission(&admission, 1U, 1U, 100U, 100U) ||
        !make_pair_common(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_shared_cid, admission)) {
        free(admission);
        return 0;
    }
    env.resp_script.count = 0U;
    env.resp_script.index = 0U;
    script_add(&env.resp_script, fixture->attempt_id.data, fixture->attempt_id.size);
    script_add(&env.resp_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
    if (dmp_hs_begin_episode(env.responder) != DMP_HS_OK ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK ||
        dmp_hs_schedule(env.responder, NULL) != DMP_HS_INVALID) {
        /* A null output is rejected before admission and is not a quota probe. */
        goto done;
    }
    if (dmp_hs_schedule(env.responder, &index) != DMP_HS_REFUSED ||
        dmp_hs_cancel(env.initiator, 0U) != DMP_HS_OK ||
        dmp_hs_schedule(env.responder, &index) != DMP_HS_OK ||
        dmp_hs_rx_cid(env.responder, index) != 55U) {
        fprintf(stderr, "shared pending slot did not release exactly on cancellation\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    free(admission);
    return passed && !port.nonzero_release;
}

static int test_shared_work_limit(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_hs_admission *admission = NULL;
    uint32_t index = 0U;
    int passed = 0;

    if (fixture == NULL || !setup_admission(&admission, 4U, 2U, 1U, 100U) ||
        !make_pair_common(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL, admission)) {
        free(admission);
        return 0;
    }
    env.resp_script.count = 0U;
    env.resp_script.index = 0U;
    script_add(&env.resp_script, fixture->attempt_id.data, fixture->attempt_id.size);
    script_add(&env.resp_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
    if (dmp_hs_begin_episode(env.responder) != DMP_HS_OK ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK ||
        dmp_hs_schedule(env.responder, &index) != DMP_HS_ABORTED) {
        fprintf(stderr, "shared global work ceiling was not monotonic across owners\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    free(admission);
    return passed && !port.nonzero_release;
}

static int test_shared_scratch_recovery_and_cids(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_hs_admission *admission = NULL;
    uint8_t attempt_id[16];
    uint8_t responder_attempt_id[16];
    const uint8_t *flight1;
    size_t flight_len = 0U;
    uint32_t first_index = 0U;
    uint32_t second_index = 0U;
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    dmp_hs_completion retry_completion;
    dmp_hs_status status;
    int passed = 0;

    memcpy(attempt_id, fixture == NULL ? (const uint8_t[16]){0} : fixture->attempt_id.data, 16U);
    attempt_id[0] ^= 0x80U;
    memcpy(responder_attempt_id, attempt_id, sizeof(responder_attempt_id));
    responder_attempt_id[0] ^= 0x40U;
    if (fixture == NULL || !setup_admission(&admission, 4U, 1U, 100U, 100U) ||
        !make_pair_common(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_shared_cid, admission)) {
        free(admission);
        return 0;
    }
    script_add(&env.init_script, fixture->init_ephemeral.data, fixture->init_ephemeral.size);
    env.resp_script.count = 0U;
    env.resp_script.index = 0U;
    script_add(&env.resp_script, responder_attempt_id, sizeof(responder_attempt_id));
    script_add(&env.resp_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
    script_add(&env.resp_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
    if (dmp_hs_schedule(env.initiator, &first_index) != DMP_HS_OK) {
        fprintf(stderr, "shared-scratch initial initiator schedule refused\n");
        goto done;
    }
    if (dmp_hs_schedule(env.responder, &second_index) != DMP_HS_REFUSED) {
        /* The responder has not opened an episode yet. */
        fprintf(stderr, "shared-scratch responder schedule was not refused before episode\n");
        goto done;
    }
    if (dmp_hs_begin_episode(env.responder) != DMP_HS_OK ||
        dmp_hs_schedule(env.responder, &second_index) != DMP_HS_OK ||
        dmp_hs_rx_cid(env.initiator, first_index) != 55U ||
        dmp_hs_rx_cid(env.responder, second_index) != 56U) {
        fprintf(stderr, "endpoint-wide CID allocator reused a live receive CID\n");
        goto done;
    }
    flight1 = dmp_hs_cached_flight(env.initiator, first_index, &flight_len);
    set_ingress(&ingress, flight1, flight_len, ID_INIT, ID_RESP, 1U, NN_EPOCH);
    status = dmp_hs_offer(env.responder, &ingress, &completion);
    if (status != DMP_HS_AWAITING) {
        fprintf(stderr, "shared-scratch async ingress returned status=%d\n", (int)status);
        goto done;
    }
    flight1 = dmp_hs_cached_flight(env.responder, second_index, &flight_len);
    set_ingress(&ingress, flight1, flight_len, ID_RESP, ID_INIT, 1U,
                dmp_hs_boot_epoch(env.responder, second_index));
    if (dmp_hs_offer(env.initiator, &ingress, NULL) != DMP_HS_REFUSED ||
        dmp_hs_accept(env.responder, &completion) != DMP_HS_CANDIDATE) {
        fprintf(stderr, "shared scratch was not held through provider completion\n");
        goto done;
    }
    if (dmp_hs_offer(env.initiator, &ingress, &retry_completion) != DMP_HS_AWAITING ||
        dmp_hs_accept(env.initiator, &retry_completion) != DMP_HS_CANDIDATE) {
        fprintf(stderr, "shared scratch capacity did not recover after provider completion\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    free(admission);
    return passed && !port.nonzero_release;
}

static int test_shared_four_parallel_scratch_admission(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_hs_admission *admission = NULL;
    dmp_hs *second = NULL;
    dmp_hs *third = NULL;
    script second_script = {{0}, {0}, 0U, 0U, 0};
    script third_script = {{0}, {0}, 0U, 0U, 0};
    store second_store = {0};
    store third_store = {0};
    box second_box = {0};
    box third_box = {0};
    uint8_t attempt_id_2[16];
    uint8_t attempt_id_3[16];
    uint8_t ephemeral_2[32];
    uint8_t ephemeral_3[32];
    uint8_t responder_ephemeral_2[32];
    uint8_t responder_ephemeral_3[32];
    uint8_t responder_ephemeral_4[32];
    uint8_t flight_1[DMP_HS_PAYLOAD_MAX];
    uint8_t flight_2[DMP_HS_PAYLOAD_MAX];
    uint8_t flight_3[DMP_HS_PAYLOAD_MAX];
    size_t flight_1_len = 0U;
    size_t flight_2_len = 0U;
    size_t flight_3_len = 0U;
    uint32_t init_index_1 = 0U;
    uint32_t init_index_2 = 0U;
    uint32_t init_index_3 = 0U;
    uint32_t pending_total;
    dmp_hs_ingress ingress_1;
    dmp_hs_ingress ingress_2;
    dmp_hs_ingress ingress_3;
    dmp_hs_completion completion_1;
    dmp_hs_completion completion_2;
    dmp_hs_completion completion_3;
    dmp_hs_completion capacity_completion;
    const uint8_t *cached;
    dmp_hs_status status;
    int passed = 0;
    size_t i;

    if (fixture == NULL ||
        !setup_admission(&admission, 4U, 2U, 100U, 100U) ||
        !make_pair_common(&env, &port, fixture, NULL, 0, NULL, 0, 0,
                          tune_four_parallel, admission)) {
        free(admission);
        return 0;
    }
    for (i = 0U; i < sizeof(attempt_id_2); ++i) {
        attempt_id_2[i] = (uint8_t)(fixture->attempt_id.data[i] ^ 0x31U);
        attempt_id_3[i] = (uint8_t)(fixture->attempt_id.data[i] ^ 0x62U);
    }
    for (i = 0U; i < sizeof(ephemeral_2); ++i) {
        ephemeral_2[i] = (uint8_t)(fixture->init_ephemeral.data[i] ^ 0x55U);
        ephemeral_3[i] = (uint8_t)(fixture->init_ephemeral.data[i] ^ 0xAAU);
        responder_ephemeral_2[i] = (uint8_t)(fixture->resp_ephemeral.data[i] ^ 0x3CU);
        responder_ephemeral_3[i] = (uint8_t)(fixture->resp_ephemeral.data[i] ^ 0xC3U);
        responder_ephemeral_4[i] = (uint8_t)(fixture->resp_ephemeral.data[i] ^ 0x69U);
    }
    script_add(&env.init_script, attempt_id_2, sizeof(attempt_id_2));
    script_add(&env.init_script, ephemeral_2, sizeof(ephemeral_2));
    if (dmp_hs_begin_episode(env.responder) != DMP_HS_OK ||
        !init_extra_responder_with_ephemeral(&env, fixture, admission, &second,
                                             &second_script, responder_ephemeral_2,
                                             &second_store, &second_box) ||
        !init_extra_responder_with_ephemeral(&env, fixture, admission, &third,
                                             &third_script, responder_ephemeral_3,
                                             &third_store, &third_box) ||
        dmp_hs_begin_episode(second) != DMP_HS_OK ||
        dmp_hs_begin_episode(third) != DMP_HS_OK) {
        fprintf(stderr, "four-parallel shared responder setup failed\n");
        goto done;
    }
    /* The third responder completes two separate inbound reads below. */
    script_add(&third_script, responder_ephemeral_4,
               sizeof(responder_ephemeral_4));
    if (dmp_hs_schedule(env.initiator, &init_index_1) != DMP_HS_OK ||
        dmp_hs_schedule(env.initiator, &init_index_2) != DMP_HS_OK) {
        fprintf(stderr, "four-parallel could not prepare two real Noise flights\n");
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, init_index_1, &flight_1_len);
    if (cached == NULL || flight_1_len > sizeof(flight_1)) goto done;
    memcpy(flight_1, cached, flight_1_len);
    cached = dmp_hs_cached_flight(env.initiator, init_index_2, &flight_2_len);
    if (cached == NULL || flight_2_len > sizeof(flight_2)) goto done;
    memcpy(flight_2, cached, flight_2_len);
    set_ingress(&ingress_1, flight_1, flight_1_len, ID_INIT, ID_RESP, 1U,
                dmp_hs_boot_epoch(env.initiator, init_index_1));
    set_ingress(&ingress_2, flight_2, flight_2_len, ID_INIT, ID_RESP, 1U,
                dmp_hs_boot_epoch(env.initiator, init_index_2));
    if (dmp_hs_pending(env.initiator) != 2U ||
        dmp_hs_offer(env.responder, &ingress_1, &completion_1) != DMP_HS_AWAITING ||
        dmp_hs_offer(second, &ingress_2, &completion_2) != DMP_HS_AWAITING ||
        dmp_hs_noise_reads(env.responder, completion_1.attempt_index) != 1U ||
        dmp_hs_noise_reads(second, completion_2.attempt_index) != 1U) {
        fprintf(stderr, "four-parallel did not hold two real provider reads awaiting completion\n");
        goto done;
    }

    /* Four pending attempts are independently live: two initiators and two
     * peer responders. A third provider read must be rejected at scratch=2. */
    pending_total = dmp_hs_pending(env.initiator) + dmp_hs_pending(env.responder) +
                    dmp_hs_pending(second) + dmp_hs_pending(third);
    set_ingress(&ingress_3, flight_1, flight_1_len, ID_INIT, ID_RESP, 1U,
                dmp_hs_boot_epoch(env.initiator, init_index_1));
    status = dmp_hs_offer(third, &ingress_3, NULL);
    if (pending_total != 4U || status != DMP_HS_REFUSED ||
        dmp_hs_total_reads(third) != 0U ||
        dmp_hs_pending(env.initiator) != 2U || dmp_hs_pending(env.responder) != 1U ||
        dmp_hs_pending(second) != 1U || dmp_hs_pending(third) != 0U) {
        fprintf(stderr, "four-parallel scratch refusal changed pending attempts or called Noise\n");
        goto done;
    }

    /* Accepting one provider completion releases scratch while the candidate
     * still holds its pending token. Free a different pending token, then
     * prove the third owner reaches Noise before retiring that candidate. */
    if (dmp_hs_accept(env.responder, &completion_1) != DMP_HS_CANDIDATE ||
        dmp_hs_cancel(env.initiator, init_index_1) != DMP_HS_OK ||
        dmp_hs_offer(third, &ingress_1, &capacity_completion) != DMP_HS_AWAITING ||
        dmp_hs_noise_reads(third, capacity_completion.attempt_index) != 1U ||
        dmp_hs_cancel(third, capacity_completion.attempt_index) != DMP_HS_OK ||
        dmp_hs_cancel(env.responder, completion_1.attempt_index) != DMP_HS_OK) {
        fprintf(stderr, "four-parallel completion did not release scratch independently\n");
        goto done;
    }
    /* Cancelling the initiator schedules its configured restart backoff; let
     * that retry window elapse before proving endpoint-wide capacity recovery. */
    env.now += 1000U;
    script_add(&env.init_script, attempt_id_3, sizeof(attempt_id_3));
    script_add(&env.init_script, ephemeral_3, sizeof(ephemeral_3));
    status = dmp_hs_schedule(env.initiator, &init_index_3);
    if (status != DMP_HS_OK) {
        fprintf(stderr,
                "four-parallel pending capacity did not recover status=%d pending=%u attempts=%u entropy=%u/%u\n",
                (int)status, (unsigned)dmp_hs_pending(env.initiator),
                (unsigned)dmp_hs_episode_attempts_used(env.initiator),
                (unsigned)env.init_script.index, (unsigned)env.init_script.count);
        goto done;
    }
    cached = dmp_hs_cached_flight(env.initiator, init_index_3, &flight_3_len);
    if (cached == NULL || flight_3_len > sizeof(flight_3)) goto done;
    memcpy(flight_3, cached, flight_3_len);
    set_ingress(&ingress_3, flight_3, flight_3_len, ID_INIT, ID_RESP, 1U,
                dmp_hs_boot_epoch(env.initiator, init_index_3));
    if (dmp_hs_offer(third, &ingress_3, &completion_3) != DMP_HS_AWAITING ||
        dmp_hs_noise_reads(third, completion_3.attempt_index) != 1U ||
        dmp_hs_accept(second, &completion_2) != DMP_HS_CANDIDATE ||
        dmp_hs_accept(third, &completion_3) != DMP_HS_CANDIDATE) {
        fprintf(stderr, "four-parallel later provider operation did not proceed\n");
        goto done;
    }
    if (dmp_hs_pending(env.initiator) + dmp_hs_pending(env.responder) +
            dmp_hs_pending(second) + dmp_hs_pending(third) != 4U) {
        fprintf(stderr, "four-parallel pending quota was not independently restored\n");
        goto done;
    }
    passed = 1;

done:
    destroy_extra_hs(&second);
    destroy_extra_hs(&third);
    close_session(&env);
    free(admission);
    return passed && !port.nonzero_release;
}

static int test_shared_epoch_refs_and_cleanup(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_hs_admission *admission = NULL;
    dmp_hs *second = NULL;
    dmp_hs *third = NULL;
    script second_script = {{0}, {0}, 0U, 0U, 0};
    script third_script = {{0}, {0}, 0U, 0U, 0};
    store second_store = {0};
    store third_store = {0};
    box second_box = {0};
    box third_box = {0};
    dmp_hs_admission_token cid, key_i, key_r, keep_cid, keep_i, keep_r;
    uint32_t namespace_id = 0U;
    uint32_t local_id = 0U;
    uint32_t peer_id = 0U;
    uint64_t local_epoch = 0U;
    uint64_t peer_epoch = 0U;
    uint32_t index = 0U;
    const uint8_t *flight;
    size_t flight_len = 0U;
    int passed = 0;

    if (fixture == NULL || !setup_admission(&admission, 4U, 2U, 100U, 100U) ||
        !make_pair_common(&env, &port, fixture, NULL, 0, NULL, 0, 0, tune_shared_cid, admission)) {
        free(admission);
        return 0;
    }
    if (dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        fprintf(stderr, "shared-epoch initial schedule refused\n");
        goto done;
    }
    flight = dmp_hs_cached_flight(env.initiator, index, &flight_len);
    if (flight == NULL) {
        fprintf(stderr, "shared-epoch initiator cached flight missing\n");
        goto done;
    }
    if (!drive_flight(env.responder, flight, flight_len, ID_INIT, ID_RESP, 1U,
                      NN_EPOCH, DMP_HS_CANDIDATE)) {
        fprintf(stderr, "shared-epoch responder did not accept candidate\n");
        goto done;
    }
    if (dmp_hs_rx_cid(env.initiator, index) != 55U ||
        dmp_hs_rx_cid(env.responder, 0U) != 56U) {
        fprintf(stderr, "shared-epoch CID mismatch: initiator=%u responder=%u\n",
                dmp_hs_rx_cid(env.initiator, index), dmp_hs_rx_cid(env.responder, 0U));
        goto done;
    }
    {
        dmp_hs_status token_status =
            dmp_hs_association_tokens(env.responder, 0U, &cid, &key_i, &key_r);
        if (token_status != DMP_HS_OK) {
            fprintf(stderr,
                    "shared-epoch association tokens unavailable: status=%d candidate=%d cid=%u identity=%d\n",
                    (int)token_status, dmp_hs_candidate(env.responder, 0U),
                    dmp_hs_rx_cid(env.responder, 0U),
                    dmp_hs_traffic_identity(env.responder, 0U, &namespace_id,
                                            &local_id, &peer_id, &local_epoch,
                                            &peer_epoch));
            goto done;
        }
    }
    if (dmp_hs_admission_retain(admission, cid, &keep_cid) != DMP_HS_OK ||
        dmp_hs_admission_retain(admission, key_i, &keep_i) != DMP_HS_OK ||
        dmp_hs_admission_retain(admission, key_r, &keep_r) != DMP_HS_OK) {
        fprintf(stderr, "shared-epoch external token retain failed\n");
        goto done;
    }
    dmp_hs_cleanup(env.responder);
    free(env.responder);
    env.responder = NULL;
    if (dmp_hs_admission_release(admission, cid) != DMP_HS_STALE ||
        dmp_hs_admission_retain(admission, key_i, &cid) != DMP_HS_STALE ||
        dmp_hs_admission_release(admission, keep_cid) != DMP_HS_OK) {
        fprintf(stderr, "shared-epoch owner cleanup did not stale its original tokens\n");
        goto done;
    }
    if (!init_extra_responder(&env, fixture, admission, &second, &second_script,
                              &second_store, &second_box)) {
        fprintf(stderr, "shared-epoch second responder initialization failed\n");
        goto done;
    }
    {
        dmp_hs_ingress duplicate_ingress;
        dmp_hs_status duplicate_status;
        uint32_t duplicate_namespace = 0U;
        uint32_t duplicate_local = 0U;
        uint32_t duplicate_peer = 0U;
        uint64_t duplicate_local_epoch = 0U;
        uint64_t duplicate_peer_epoch = 0U;
        int duplicate_identity;
        set_ingress(&duplicate_ingress, flight, flight_len, ID_INIT, ID_RESP,
                    1U, NN_EPOCH);
        duplicate_status = accept_offer(second, &duplicate_ingress, NULL);
        duplicate_identity = dmp_hs_traffic_identity(second, 0U,
                                                     &duplicate_namespace,
                                                     &duplicate_local,
                                                     &duplicate_peer,
                                                     &duplicate_local_epoch,
                                                     &duplicate_peer_epoch);
        if (duplicate_status != DMP_HS_ABORTED) {
            fprintf(stderr,
                    "retained epoch fence status=%d old=(%u,%u,%llu,%u,%llu) new=(%d,%u,%u,%llu,%u,%llu)\n",
                    (int)duplicate_status, namespace_id, local_id,
                    (unsigned long long)local_epoch, peer_id,
                    (unsigned long long)peer_epoch, duplicate_identity,
                    duplicate_namespace, duplicate_local,
                    (unsigned long long)duplicate_local_epoch, duplicate_peer,
                    (unsigned long long)duplicate_peer_epoch);
            goto done;
        }
    }
    if (dmp_hs_pending(second) != 0U || dmp_hs_candidate(second, 0U)) {
        fprintf(stderr, "retained directional epoch key did not fence duplicate candidate\n");
        goto done;
    }
    destroy_extra_hs(&second);
    if (dmp_hs_admission_release(admission, keep_i) != DMP_HS_OK ||
        dmp_hs_admission_release(admission, keep_r) != DMP_HS_OK ||
        dmp_hs_admission_release(admission, keep_i) != DMP_HS_STALE ||
        !init_extra_responder(&env, fixture, admission, &third, &third_script,
                              &third_store, &third_box) ||
        !drive_flight(third, flight, flight_len, ID_INIT, ID_RESP, 1U, NN_EPOCH, DMP_HS_CANDIDATE)) {
        fprintf(stderr, "exact shared reservation release or stale-token fence failed\n");
        goto done;
    }
    if (dmp_hs_rx_cid(third, 0U) != 56U ||
        dmp_hs_admission_release(admission, keep_i) != DMP_HS_STALE) {
        fprintf(stderr, "cleanup released another peer owner's live CID\n");
        goto done;
    }
    passed = 1;

done:
    destroy_extra_hs(&second);
    destroy_extra_hs(&third);
    close_session(&env);
    free(admission);
    return passed && !port.nonzero_release;
}

static int test_shared_directional_epoch_collision(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_hs_admission *admission = NULL;
    dmp_hs_retained retained;
    uint32_t index = 0U;
    const uint8_t *flight;
    size_t flight_len = 0U;
    int passed = 0;

    if (fixture == NULL || !setup_admission(&admission, 4U, 2U, 100U, 100U) ||
        !make_pair_common(&env, &port, fixture, NULL, 0, NULL, 0, 0, NULL, admission) ||
        dmp_hs_schedule(env.initiator, &index) != DMP_HS_OK) {
        free(admission);
        return 0;
    }
    memset(&retained, 0, sizeof(retained));
    retained.namespace_id = LOCAL_NS;
    retained.origin_id = ID_RESP;
    retained.epoch = NN_EPOCH_R;
    retained.rx_cid = 99U;
    flight = dmp_hs_cached_flight(env.initiator, index, &flight_len);
    if (dmp_hs_retain_association(env.responder, &retained) != DMP_HS_OK || flight == NULL ||
        !drive_flight(env.responder, flight, flight_len, ID_INIT, ID_RESP, 1U, NN_EPOCH,
                      DMP_HS_ABORTED) || dmp_hs_candidate(env.responder, 0U) ||
        !dmp_hs_terminal(env.responder, 0U) || !dmp_hs_secrets_wiped(env.responder, 0U)) {
        fprintf(stderr, "responder-direction epoch collision did not abort and release candidate keys\n");
        goto done;
    }
    passed = 1;

done:
    close_session(&env);
    free(admission);
    return passed && !port.nonzero_release;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "transport") == 0) {
        int passed = test_real_handshake_transport_snapshot();
        int late_active = test_late_active_transport_completion();
        if (!passed) fprintf(stderr, "real-transport-snapshot failed\n");
        if (!late_active) fprintf(stderr, "late-active-transport-completion failed\n");
        return passed && late_active ? 0 : 1;
    }
    expect_case("nn-candidate", test_nn_candidate());
    expect_case("preread-conflict", test_preread_and_conflict());
    expect_case("duplicate-loss-processed-conflict", test_duplicate_loss_and_processed_conflict());
    expect_case("cached-flight-lifetime", test_cached_flight_lifetime());
    expect_case("real-transport-snapshot", test_real_handshake_transport_snapshot());
    expect_case("late-active-transport-completion",
                test_late_active_transport_completion());
    expect_case("invalid-authenticated-payload-restart", test_invalid_authenticated_payload_restart());
    expect_case("low-order-dh-abort", test_low_order_dh_abort());
    expect_case("wrong-psk", test_wrong_psk());
    expect_case("xx-pin-candidate", test_xx_pin_candidate());
    expect_case("wrong-pin", test_wrong_pin_and_association());
    expect_case("oob-commit", test_oob_commit());
    expect_case("episode-backoff", test_episode_backoff());
    expect_case("active-pending-rotation", test_active_association_does_not_consume_pending_slot());
    expect_case("orphan-quota", test_orphan_replay_and_quota());
    expect_case("scratch-serial-stale", test_scratch_serial_partial_stale());
    expect_case("entropy-cid-collision", test_entropy_cid_collision_and_cipher());
    expect_case("epoch-hash-alloc", test_epoch_hash_alloc());
    expect_case("finish-ready", test_finish_ready());
    expect_case("active-expiry-releases-reservations",
                test_active_expiry_releases_reservations());
    expect_case("routed-finish-ready", test_routed_finish_ready());
    expect_case("confirmation-loss", test_confirmation_loss());
    expect_case("replay-window", test_replay_window());
    expect_case("replay-ceiling", test_replay_ceiling());
    expect_case("enroll-not-active", test_enroll_not_active());
    expect_case("failed-aead-limit", test_failed_aead_limit());
    expect_case("cleanup-erases-owner", test_cleanup_erases_owner());
    expect_case("shared-pending-recovery", test_shared_pending_recovery());
    expect_case("shared-work-limit", test_shared_work_limit());
    expect_case("shared-scratch-recovery-cids", test_shared_scratch_recovery_and_cids());
    expect_case("shared-four-parallel-scratch", test_shared_four_parallel_scratch_admission());
    expect_case("shared-epoch-refs-cleanup", test_shared_epoch_refs_and_cleanup());
    expect_case("shared-directional-epoch-collision", test_shared_directional_epoch_collision());
    if (g_failures != 0) {
        fprintf(stderr, "%d handshake case(s) failed\n", g_failures);
        return 1;
    }
    return 0;
}
