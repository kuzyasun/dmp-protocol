/* Private concurrent provider workload. Public fixture credentials are test-only. */
#include "parallel.h"
#include "noise_test_arena.h"
#include "noise_fixture_probe.h"

#include <noise/protocol.h>
#include <string.h>

#define PAR_HOTPATH_ALLOC (-1000)
#define PAR_KEY_SIZE 32u
#define PAR_MESSAGE_SIZE 512u
#define PAR_PLAINTEXT_SIZE 128u
#define PAR_AEAD_SIZE 64u
#define PAR_PAYLOAD_SIZE 32u
#define PAR_AAD_SIZE 24u

typedef struct {
    NoiseHandshakeState *handshake;
    NoiseCipherState *tx;
    NoiseCipherState *rx;
} parallel_endpoint;

typedef struct {
    uint8_t tx_message[PAR_MESSAGE_SIZE];
    uint8_t rx_message[PAR_MESSAGE_SIZE];
    uint8_t plaintext[PAR_PLAINTEXT_SIZE];
    uint8_t public_key[PAR_KEY_SIZE];
    uint8_t initiator_hash[PAR_KEY_SIZE];
    uint8_t responder_hash[PAR_KEY_SIZE];
    uint8_t aad[PAR_AAD_SIZE];
    uint8_t payload[PAR_PAYLOAD_SIZE];
    uint8_t aead[PAR_AEAD_SIZE];
    uint8_t bad_aead[PAR_AEAD_SIZE];
} parallel_scratch;

typedef struct {
    size_t attempts, allocs, frees, refusals, wipe_errors, rng_calls;
    unsigned completed, fixed_pairs, random_pairs;
    uint64_t max_call_us;
} parallel_counters;

typedef struct {
    parallel_endpoint endpoints[2]; /* initiator, responder */
    union { max_align_t alignment; uint8_t bytes[DMP_PARALLEL_CAPACITY]; } backing;
    dmp_noise_test_arena arena;
    parallel_scratch scratch;
    parallel_counters counters;
} parallel_worker;

/* Each element is mutated only by the permanently bound worker with that id. */
static parallel_worker workers[DMP_PARALLEL_WORKERS];
/* Startup is called serially before either worker is released. */
static int startup_initialized;

static parallel_worker *current_worker(void)
{
    unsigned id = dmp_parallel_worker_id();
    return id < DMP_PARALLEL_WORKERS ? &workers[id] : NULL;
}

void *noise_allocator_allocate(size_t size)
{
    parallel_worker *worker = current_worker();
    void *pointer;

    if (worker == NULL)
        return NULL;
    ++worker->counters.attempts;
    pointer = worker->arena.storage != NULL
        ? dmp_noise_test_arena_allocate(&worker->arena, size) : NULL;
    if (pointer != NULL)
        ++worker->counters.allocs;
    else
        ++worker->counters.refusals;
    return pointer;
}

void noise_allocator_release(void *pointer, size_t size)
{
    parallel_worker *worker = current_worker();

    if (worker == NULL)
        return;
    if (dmp_noise_test_arena_release(&worker->arena, pointer, size) !=
        DMP_NOISE_TEST_ARENA_OK)
        ++worker->counters.wipe_errors;
    else
        ++worker->counters.frees;
}

int dmp_sodium_entropy_ready(void)
{
    return 0;
}

int dmp_sodium_entropy_read(void *bytes, size_t size)
{
    parallel_worker *worker = current_worker();
    int error;

    if (worker != NULL)
        ++worker->counters.rng_calls;
    if (bytes == NULL && size != 0u)
        return 1;
    error = dmp_parallel_entropy(bytes, size);
    if (error != 0 && bytes != NULL)
        noise_clean(bytes, size);
    return error != 0;
}

int noise_rand_bytes_checked(void *bytes, size_t size)
{
    return dmp_sodium_entropy_read(bytes, size)
        ? NOISE_ERROR_SYSTEM : NOISE_ERROR_NONE;
}

static int close_endpoint(parallel_endpoint *endpoint)
{
    int first_error = NOISE_ERROR_NONE;
    int error;

    if (endpoint->handshake != NULL) {
        error = noise_handshakestate_free(endpoint->handshake);
        endpoint->handshake = NULL;
        if (error != NOISE_ERROR_NONE && first_error == NOISE_ERROR_NONE)
            first_error = error;
    }
    if (endpoint->tx != NULL) {
        error = noise_cipherstate_free(endpoint->tx);
        endpoint->tx = NULL;
        if (error != NOISE_ERROR_NONE && first_error == NOISE_ERROR_NONE)
            first_error = error;
    }
    if (endpoint->rx != NULL) {
        error = noise_cipherstate_free(endpoint->rx);
        endpoint->rx = NULL;
        if (error != NOISE_ERROR_NONE && first_error == NOISE_ERROR_NONE)
            first_error = error;
    }
    return first_error;
}

static int create_endpoint(parallel_worker *worker, parallel_endpoint *endpoint,
                           const noise_fixture_probe_fixture_t *fixture,
                           int role, int fixed)
{
    parallel_endpoint candidate = {0};
    noise_fixture_probe_bytes_t private_key;
    noise_fixture_probe_bytes_t ephemeral;
    NoiseDHState *dh = NULL;
    NoiseDHState *local_static;
    int error;

    error = noise_handshakestate_new_by_name(&candidate.handshake,
                                              fixture->protocol_name, role);
    if (error != NOISE_ERROR_NONE)
        goto fail;

    private_key = role == NOISE_ROLE_INITIATOR
        ? fixture->init_static : fixture->resp_static;
    if (private_key.size != 0u) {
        local_static = noise_handshakestate_get_local_keypair_dh(candidate.handshake);
        if (local_static == NULL) {
            error = NOISE_ERROR_INVALID_STATE;
            goto fail;
        }
        error = noise_dhstate_set_keypair_private(local_static, private_key.data,
                                                  private_key.size);
        if (error != NOISE_ERROR_NONE)
            goto fail;
    }
    if ((noise_handshakestate_needs_pre_shared_key(candidate.handshake) != 0) !=
        (fixture->psk.size != 0u)) {
        error = NOISE_ERROR_INVALID_STATE;
        goto fail;
    }
    if (fixture->psk.size != 0u) {
        error = noise_handshakestate_set_pre_shared_key(candidate.handshake,
                                                        fixture->psk.data,
                                                        fixture->psk.size);
        if (error != NOISE_ERROR_NONE)
            goto fail;
    }
    if (fixed) {
        ephemeral = role == NOISE_ROLE_INITIATOR
            ? fixture->init_ephemeral : fixture->resp_ephemeral;
        error = noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519);
        if (error == NOISE_ERROR_NONE)
            error = noise_dhstate_set_keypair_private(dh, ephemeral.data,
                                                       ephemeral.size);
        if (error == NOISE_ERROR_NONE)
            error = noise_dhstate_get_public_key(dh, worker->scratch.public_key,
                                                  sizeof(worker->scratch.public_key));
        if (error == NOISE_ERROR_NONE)
            error = noise_handshakestate_set_local_ephemeral(
                candidate.handshake, ephemeral.data, ephemeral.size,
                worker->scratch.public_key, sizeof(worker->scratch.public_key));
        if (dh != NULL) {
            int free_error = noise_dhstate_free(dh);
            dh = NULL;
            if (error == NOISE_ERROR_NONE)
                error = free_error;
        }
        noise_clean(worker->scratch.public_key, sizeof(worker->scratch.public_key));
        if (error != NOISE_ERROR_NONE)
            goto fail;
    }
    error = noise_handshakestate_set_prologue(candidate.handshake,
                                               fixture->prologue.data,
                                               fixture->prologue.size);
    if (error != NOISE_ERROR_NONE)
        goto fail;
    error = noise_handshakestate_start(candidate.handshake);
    if (error != NOISE_ERROR_NONE)
        goto fail;
    *endpoint = candidate;
    return NOISE_ERROR_NONE;

fail:
    if (dh != NULL)
        (void)noise_dhstate_free(dh);
    (void)close_endpoint(&candidate);
    return error;
}

static void record_call_time(parallel_worker *worker, uint64_t start, uint64_t end)
{
    uint64_t elapsed = end >= start ? end - start : 0u;
    if (elapsed > worker->counters.max_call_us)
        worker->counters.max_call_us = elapsed;
}

static int tracked_write(parallel_worker *worker, NoiseHandshakeState *state,
                         NoiseBuffer *message, NoiseBuffer *payload)
{
    size_t attempts = worker->counters.attempts;
    uint64_t start, end;
    int error;

    dmp_parallel_call_enter();
    start = dmp_parallel_time_us();
    error = noise_handshakestate_write_message(state, message, payload);
    end = dmp_parallel_time_us();
    dmp_parallel_call_leave();
    record_call_time(worker, start, end);
    return worker->counters.attempts == attempts ? error : PAR_HOTPATH_ALLOC;
}

static int tracked_read(parallel_worker *worker, NoiseHandshakeState *state,
                        NoiseBuffer *message, NoiseBuffer *payload)
{
    size_t attempts = worker->counters.attempts;
    uint64_t start, end;
    int error;

    dmp_parallel_call_enter();
    start = dmp_parallel_time_us();
    error = noise_handshakestate_read_message(state, message, payload);
    end = dmp_parallel_time_us();
    dmp_parallel_call_leave();
    record_call_time(worker, start, end);
    return worker->counters.attempts == attempts ? error : PAR_HOTPATH_ALLOC;
}

static int tracked_encrypt(parallel_worker *worker, NoiseCipherState *state,
                           const uint8_t *aad, size_t aad_size, NoiseBuffer *buffer)
{
    size_t attempts = worker->counters.attempts;
    uint64_t start, end;
    int error;

    dmp_parallel_call_enter();
    start = dmp_parallel_time_us();
    error = noise_cipherstate_encrypt_with_ad(state, aad, aad_size, buffer);
    end = dmp_parallel_time_us();
    dmp_parallel_call_leave();
    record_call_time(worker, start, end);
    return worker->counters.attempts == attempts ? error : PAR_HOTPATH_ALLOC;
}

static int tracked_decrypt(parallel_worker *worker, NoiseCipherState *state,
                           uint64_t nonce, const uint8_t *aad, size_t aad_size,
                           NoiseBuffer *buffer)
{
    size_t attempts = worker->counters.attempts;
    uint64_t start, end;
    int error;

    dmp_parallel_call_enter();
    start = dmp_parallel_time_us();
    error = noise_cipherstate_decrypt_with_ad_at_nonce(state, nonce, aad, aad_size,
                                                        buffer);
    end = dmp_parallel_time_us();
    dmp_parallel_call_leave();
    record_call_time(worker, start, end);
    return worker->counters.attempts == attempts ? error : PAR_HOTPATH_ALLOC;
}

static int bytes_equal(const uint8_t *actual, size_t actual_size,
                       noise_fixture_probe_bytes_t expected)
{
    return actual_size == expected.size &&
        (actual_size == 0u || memcmp(actual, expected.data, actual_size) == 0);
}

static int transfer_flight(parallel_worker *worker, parallel_endpoint *sender,
                           parallel_endpoint *receiver,
                           const noise_fixture_probe_flight_t *flight, int fixed)
{
    NoiseBuffer message, payload;
    size_t message_size;
    int error;
    uint8_t empty = 0u;

    noise_buffer_set_output(message, worker->scratch.tx_message,
                            sizeof(worker->scratch.tx_message));
    if (flight->plaintext.size != 0u)
        memcpy(worker->scratch.plaintext, flight->plaintext.data,
               flight->plaintext.size);
    noise_buffer_set_input(payload, flight->plaintext.size == 0u
                           ? &empty : worker->scratch.plaintext,
                           flight->plaintext.size);
    error = tracked_write(worker, sender->handshake, &message, &payload);
    if (error != NOISE_ERROR_NONE)
        return error;
    if (fixed && !bytes_equal(message.data, message.size, flight->message))
        return NOISE_ERROR_INVALID_STATE;
    message_size = message.size;
    if (message_size > sizeof(worker->scratch.rx_message))
        return NOISE_ERROR_INVALID_LENGTH;
    memcpy(worker->scratch.rx_message, worker->scratch.tx_message, message_size);

    noise_buffer_set_input(message, worker->scratch.rx_message, message_size);
    noise_buffer_set_output(payload, worker->scratch.plaintext,
                            sizeof(worker->scratch.plaintext));
    error = tracked_read(worker, receiver->handshake, &message, &payload);
    if (error != NOISE_ERROR_NONE)
        return error;
    if (!bytes_equal(payload.data, payload.size, flight->plaintext))
        return NOISE_ERROR_INVALID_STATE;
    return NOISE_ERROR_NONE;
}

static int traffic_direction(parallel_worker *worker, NoiseCipherState *sender,
                              NoiseCipherState *receiver, unsigned worker_id,
                              unsigned cycle, unsigned direction)
{
    NoiseBuffer buffer;
    size_t i;
    int error;

    for (i = 0u; i < sizeof(worker->scratch.payload); ++i)
        worker->scratch.payload[i] = (uint8_t)(0x39u + i * 7u + worker_id * 29u +
                                                cycle * 11u + direction * 53u);
    for (i = 0u; i < sizeof(worker->scratch.aad); ++i)
        worker->scratch.aad[i] = (uint8_t)(0xa5u + i * 5u + worker_id * 17u +
                                            cycle * 3u + direction * 41u);

    memcpy(worker->scratch.aead, worker->scratch.payload,
           sizeof(worker->scratch.payload));
    noise_buffer_set_inout(buffer, worker->scratch.aead,
                           sizeof(worker->scratch.payload),
                           sizeof(worker->scratch.aead));
    error = noise_cipherstate_set_nonce(sender, 1u);
    if (error == NOISE_ERROR_NONE)
        error = tracked_encrypt(worker, sender, worker->scratch.aad,
                                sizeof(worker->scratch.aad), &buffer);
    if (error != NOISE_ERROR_NONE || buffer.size != sizeof(worker->scratch.payload) + 16u)
        return error != NOISE_ERROR_NONE ? error : NOISE_ERROR_INVALID_STATE;
    memcpy(worker->scratch.bad_aead, worker->scratch.aead, buffer.size);
    worker->scratch.bad_aead[buffer.size - 1u] ^= 0x01u;
    noise_buffer_set_inout(buffer, worker->scratch.bad_aead, buffer.size,
                           sizeof(worker->scratch.bad_aead));
    error = tracked_decrypt(worker, receiver, 1u, worker->scratch.aad,
                            sizeof(worker->scratch.aad), &buffer);
    if (error != NOISE_ERROR_MAC_FAILURE)
        return error != NOISE_ERROR_NONE ? error : NOISE_ERROR_INVALID_STATE;
    noise_buffer_set_inout(buffer, worker->scratch.aead,
                           sizeof(worker->scratch.payload) + 16u,
                           sizeof(worker->scratch.aead));
    error = tracked_decrypt(worker, receiver, 1u, worker->scratch.aad,
                            sizeof(worker->scratch.aad), &buffer);
    if (error != NOISE_ERROR_NONE)
        return error;
    if (!bytes_equal(buffer.data, buffer.size,
                     (noise_fixture_probe_bytes_t){worker->scratch.payload,
                                                    sizeof(worker->scratch.payload)}))
        return NOISE_ERROR_INVALID_STATE;
    return NOISE_ERROR_NONE;
}

static int run_cycle(parallel_worker *worker, unsigned worker_id, unsigned cycle,
                     const noise_fixture_probe_fixture_t *fixture, int fixed,
                     dmp_parallel_result *result)
{
    parallel_endpoint *initiator = &worker->endpoints[0];
    parallel_endpoint *responder = &worker->endpoints[1];
    size_t flight = 0u;
    int error = NOISE_ERROR_NONE;
    int success = 0;

#define REQUIRE(condition) do { if (!(condition)) { result->error_line = __LINE__; goto done; } } while (0)
#define REQUIRE_NOISE(expression) do { error = (expression); if (error != NOISE_ERROR_NONE) { result->error_line = __LINE__; goto done; } } while (0)

    REQUIRE(create_endpoint(worker, initiator, fixture, NOISE_ROLE_INITIATOR, fixed) ==
            NOISE_ERROR_NONE);
    REQUIRE(create_endpoint(worker, responder, fixture, NOISE_ROLE_RESPONDER, fixed) ==
            NOISE_ERROR_NONE);
    while (noise_handshakestate_get_action(initiator->handshake) != NOISE_ACTION_SPLIT ||
           noise_handshakestate_get_action(responder->handshake) != NOISE_ACTION_SPLIT) {
        noise_fixture_probe_flight_t const *expected;
        if (flight >= fixture->flight_count) {
            result->error_line = __LINE__;
            goto done;
        }
        expected = &fixture->flights[flight];
        if (noise_handshakestate_get_action(initiator->handshake) ==
            NOISE_ACTION_WRITE_MESSAGE) {
            REQUIRE_NOISE(transfer_flight(worker, initiator, responder, expected, fixed));
        } else if (noise_handshakestate_get_action(responder->handshake) ==
                   NOISE_ACTION_WRITE_MESSAGE) {
            REQUIRE_NOISE(transfer_flight(worker, responder, initiator, expected, fixed));
        } else {
            result->error_line = __LINE__;
            goto done;
        }
        ++flight;
    }
    REQUIRE(flight == fixture->flight_count);
    REQUIRE_NOISE(noise_handshakestate_get_handshake_hash(
        initiator->handshake, worker->scratch.initiator_hash,
        sizeof(worker->scratch.initiator_hash)));
    REQUIRE_NOISE(noise_handshakestate_get_handshake_hash(
        responder->handshake, worker->scratch.responder_hash,
        sizeof(worker->scratch.responder_hash)));
    REQUIRE(memcmp(worker->scratch.initiator_hash, worker->scratch.responder_hash,
                   sizeof(worker->scratch.initiator_hash)) == 0);
    if (fixed)
        REQUIRE(bytes_equal(worker->scratch.initiator_hash,
                            sizeof(worker->scratch.initiator_hash),
                            fixture->handshake_hash));
    REQUIRE_NOISE(noise_handshakestate_split(initiator->handshake,
                                              &initiator->tx, &initiator->rx));
    REQUIRE_NOISE(noise_handshakestate_split(responder->handshake,
                                              &responder->tx, &responder->rx));
    REQUIRE(noise_handshakestate_get_action(initiator->handshake) == NOISE_ACTION_COMPLETE);
    REQUIRE(noise_handshakestate_get_action(responder->handshake) == NOISE_ACTION_COMPLETE);
    error = noise_handshakestate_free(initiator->handshake);
    initiator->handshake = NULL;
    REQUIRE_NOISE(error);
    error = noise_handshakestate_free(responder->handshake);
    responder->handshake = NULL;
    REQUIRE_NOISE(error);
    REQUIRE_NOISE(traffic_direction(worker, initiator->tx, responder->rx,
                                    worker_id, cycle, 0u));
    REQUIRE_NOISE(traffic_direction(worker, responder->tx, initiator->rx,
                                    worker_id, cycle, 1u));
    success = 1;

done:
    if (close_endpoint(initiator) != NOISE_ERROR_NONE) {
        if (result->error_line == 0u)
            result->error_line = __LINE__;
        success = 0;
    }
    if (close_endpoint(responder) != NOISE_ERROR_NONE) {
        if (result->error_line == 0u)
            result->error_line = __LINE__;
        success = 0;
    }
    noise_clean(&worker->scratch, sizeof(worker->scratch));
    if (worker->arena.live_blocks != 0u || worker->arena.charged_bytes != 0u ||
        worker->counters.allocs != worker->counters.frees) {
        if (result->error_line == 0u)
            result->error_line = __LINE__;
        success = 0;
    }
#undef REQUIRE_NOISE
#undef REQUIRE
    return success;
}

static void snapshot_result(const parallel_worker *worker, dmp_parallel_result *result)
{
    result->completed = worker->counters.completed;
    result->fixed_pairs = worker->counters.fixed_pairs;
    result->random_pairs = worker->counters.random_pairs;
    result->attempts = worker->counters.attempts;
    result->allocs = worker->counters.allocs;
    result->frees = worker->counters.frees;
    result->refusals = worker->counters.refusals;
    result->wipe_errors = worker->counters.wipe_errors;
    result->rng_calls = worker->counters.rng_calls;
    result->live = worker->arena.charged_bytes;
    result->blocks = worker->arena.live_blocks;
    result->peak = worker->arena.peak_charged_bytes;
    result->backing = sizeof(worker->backing.bytes);
    result->scratch = sizeof(worker->scratch);
    result->metadata = sizeof(*worker) - sizeof(worker->backing) - sizeof(worker->scratch);
    result->max_call_us = worker->counters.max_call_us;
}

int dmp_parallel_init(void)
{
    int error;

    if (startup_initialized)
        return NOISE_ERROR_NONE;
    error = noise_init_framework();
    if (error == NOISE_ERROR_NONE)
        startup_initialized = 1;
    return error;
}

int dmp_parallel_run(unsigned worker_id, unsigned cycles, dmp_parallel_result *result)
{
    parallel_worker *worker;
    unsigned cycle;
    int status = 0;

    if (result == NULL)
        return -1;
    memset(result, 0, sizeof(*result));
    if (worker_id >= DMP_PARALLEL_WORKERS ||
        dmp_parallel_worker_id() != worker_id || !startup_initialized || cycles == 0u) {
        result->error_line = __LINE__;
        return -1;
    }
    worker = &workers[worker_id];
    memset(&worker->counters, 0, sizeof(worker->counters));
    if (worker->arena.storage == NULL) {
        if (dmp_noise_test_arena_init(&worker->arena, worker->backing.bytes,
                                      sizeof(worker->backing.bytes),
                                      sizeof(worker->backing.bytes),
                                      DMP_NOISE_TEST_ARENA_MAX_BLOCKS) !=
            DMP_NOISE_TEST_ARENA_OK) {
            result->error_line = __LINE__;
            snapshot_result(worker, result);
            return -1;
        }
    } else if (dmp_noise_test_arena_clear(&worker->arena) != DMP_NOISE_TEST_ARENA_OK) {
        result->error_line = __LINE__;
        snapshot_result(worker, result);
        return -1;
    }
    if (NOISE_FIXTURE_PROBE_FIXTURE_COUNT < 2u) {
        result->error_line = __LINE__;
        snapshot_result(worker, result);
        return -1;
    }

    for (cycle = 0u; cycle < cycles; ++cycle) {
        size_t fixture_index = cycle % 2u;
        int fixed = ((cycle / 2u) % 2u) == 0u;
        const noise_fixture_probe_fixture_t *fixture =
            &noise_fixture_probe_fixtures[fixture_index];

        if (!run_cycle(worker, worker_id, cycle, fixture, fixed, result)) {
            (void)dmp_parallel_yield();
            status = -1;
            break;
        }
        ++worker->counters.completed;
        if (fixed)
            ++worker->counters.fixed_pairs;
        else
            ++worker->counters.random_pairs;
        if (dmp_parallel_yield()) {
            result->error_line = __LINE__;
            status = -1;
            break;
        }
    }
    snapshot_result(worker, result);
    if (status != 0)
        return status;
    if (worker->arena.live_blocks != 0u || worker->arena.charged_bytes != 0u ||
        worker->counters.allocs != worker->counters.frees ||
        worker->counters.wipe_errors != 0u || worker->counters.refusals != 0u) {
        result->error_line = __LINE__;
        return -1;
    }
    return 0;
}
