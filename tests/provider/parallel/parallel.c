/* Private concurrent provider workload. Public fixture credentials are test-only. */
#include "parallel.h"
#include "noise_test_arena.h"
#include "noise_fixture_probe.h"

#include <noise/protocol.h>
#include <string.h>
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
#include <stdatomic.h>
#endif

#define PAR_HOTPATH_ALLOC (-1000)
#define PAR_KEY_SIZE 32u
#define PAR_MESSAGE_SIZE 512u
#define PAR_PLAINTEXT_SIZE 128u
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
#define PAR_AEAD_SIZE 320u
#define PAR_PAYLOAD_SIZE 32u
#define PAR_AAD_SIZE 128u
#else
#define PAR_AEAD_SIZE 64u
#define PAR_PAYLOAD_SIZE 32u
#define PAR_AAD_SIZE 24u
#endif

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
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
    unsigned topology_traffic_checks_completed;
#endif
    uint64_t max_call_us;
} parallel_counters;

#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
typedef struct {
    parallel_endpoint endpoint;
    size_t fixture_index;
    uint8_t first_flight[PAR_MESSAGE_SIZE];
    size_t first_flight_len;
} topology_pending;

typedef struct {
    size_t fixture_index;
    NoiseCipherState *tx;
    NoiseCipherState *rx;
} topology_association;
#endif

typedef struct {
    parallel_endpoint endpoints[2]; /* initiator, responder */
    union { max_align_t alignment; uint8_t bytes[DMP_PARALLEL_CAPACITY]; } backing;
    dmp_noise_test_arena arena;
    parallel_scratch scratch;
    parallel_counters counters;
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
    topology_pending pending[2];
    topology_association associations[2][2]; /* per peer: active, draining */
#endif
} parallel_worker;

/* Each element is mutated only by the permanently bound worker with that id. */
static parallel_worker workers[DMP_PARALLEL_WORKERS];
/* Startup is called serially before either worker is released. */
static int startup_initialized;
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
static _Atomic size_t aggregate_live_bytes;
static _Atomic size_t aggregate_peak_bytes;
static uint8_t application_operation_slots[DMP_PARALLEL_FOUR_APP_SLOTS]
                                          [DMP_PARALLEL_FOUR_APP_SLOT_BYTES];

static void aggregate_add(size_t amount)
{
    size_t current = atomic_fetch_add(&aggregate_live_bytes, amount) + amount;
    size_t peak = atomic_load(&aggregate_peak_bytes);

    while (current > peak &&
           !atomic_compare_exchange_weak(&aggregate_peak_bytes, &peak, current)) {
    }
}

static void aggregate_subtract(size_t amount)
{
    if (amount != 0U)
        (void)atomic_fetch_sub(&aggregate_live_bytes, amount);
}
#endif

static parallel_worker *current_worker(void)
{
    unsigned id = dmp_parallel_worker_id();
    return id < DMP_PARALLEL_WORKERS ? &workers[id] : NULL;
}

void *noise_allocator_allocate(size_t size)
{
    parallel_worker *worker = current_worker();
    void *pointer;
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
    size_t charged_before;
#endif

    if (worker == NULL)
        return NULL;
    ++worker->counters.attempts;
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
    /* First allocation is made while constructing this worker's handshake. */
    if (worker->counters.attempts == 1U)
        dmp_parallel_noise_allocator_rendezvous();
    charged_before = worker->arena.charged_bytes;
#endif
    pointer = worker->arena.storage != NULL
        ? dmp_noise_test_arena_allocate(&worker->arena, size) : NULL;
    if (pointer != NULL) {
        ++worker->counters.allocs;
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
        aggregate_add(worker->arena.charged_bytes - charged_before);
#endif
    } else {
        ++worker->counters.refusals;
    }
    return pointer;
}

void noise_allocator_release(void *pointer, size_t size)
{
    parallel_worker *worker = current_worker();
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
    size_t charged_before;
#endif

    if (worker == NULL)
        return;
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
    charged_before = worker->arena.charged_bytes;
#endif
    if (dmp_noise_test_arena_release(&worker->arena, pointer, size) !=
        DMP_NOISE_TEST_ARENA_OK)
        ++worker->counters.wipe_errors;
    else {
        ++worker->counters.frees;
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
        aggregate_subtract(charged_before - worker->arena.charged_bytes);
#endif
    }
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

#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
static const noise_fixture_probe_packet_t *topology_packet(
    const noise_fixture_probe_fixture_t *fixture, uint8_t direction, uint64_t pn)
{
    size_t index;

    for (index = 0U; index < fixture->transport_packet_count; ++index) {
        const noise_fixture_probe_packet_t *packet = &fixture->transport_packets[index];
        if (packet->direction == direction && packet->pn == pn)
            return packet;
    }
    return NULL;
}

static int topology_write_first(parallel_worker *worker, topology_pending *pending)
{
    const noise_fixture_probe_fixture_t *fixture =
        &noise_fixture_probe_fixtures[pending->fixture_index];
    const noise_fixture_probe_flight_t *flight = &fixture->flights[0];
    NoiseBuffer message, payload;
    uint8_t empty = 0U;
    int error;

    noise_buffer_set_output(message, pending->first_flight,
                            sizeof(pending->first_flight));
    noise_buffer_set_input(payload, flight->plaintext.size == 0U
                           ? &empty : (uint8_t *)flight->plaintext.data,
                           flight->plaintext.size);
    error = tracked_write(worker, pending->endpoint.handshake, &message, &payload);
    if (error != NOISE_ERROR_NONE)
        return error;
    pending->first_flight_len = message.size;
    if (!bytes_equal(pending->first_flight, pending->first_flight_len,
                     flight->message) ||
        noise_handshakestate_get_action(pending->endpoint.handshake) !=
            NOISE_ACTION_READ_MESSAGE)
        return NOISE_ERROR_INVALID_STATE;
    return NOISE_ERROR_NONE;
}

static int topology_create_cipher(NoiseCipherState **state,
                                  noise_fixture_probe_bytes_t key)
{
    int error = noise_cipherstate_new_by_id(state, NOISE_CIPHER_CHACHAPOLY);
    if (error == NOISE_ERROR_NONE)
        error = noise_cipherstate_init_key(*state, key.data, key.size);
    if (error != NOISE_ERROR_NONE && *state != NULL) {
        (void)noise_cipherstate_free(*state);
        *state = NULL;
    }
    return error;
}

static int topology_create_association(topology_association *association,
                                       const noise_fixture_probe_fixture_t *fixture,
                                       size_t fixture_index)
{
    int error;

    association->fixture_index = fixture_index;
    error = topology_create_cipher(&association->tx, fixture->i_to_r_key);
    if (error != NOISE_ERROR_NONE)
        return error;
    error = topology_create_cipher(&association->rx, fixture->i_to_r_key);
    if (error != NOISE_ERROR_NONE) {
        (void)noise_cipherstate_free(association->tx);
        association->tx = NULL;
    }
    return error;
}

static int topology_fixture_traffic(parallel_worker *worker,
                                    topology_association *association)
{
    const noise_fixture_probe_fixture_t *fixture =
        &noise_fixture_probe_fixtures[association->fixture_index];
    const noise_fixture_probe_packet_t *packet = topology_packet(fixture, 0U, 0U);
    size_t encrypted_size;
    NoiseBuffer buffer;
    int error;

    if (packet == NULL || packet->plaintext.size > sizeof(worker->scratch.aead) ||
        packet->ciphertext.size + packet->tag.size > sizeof(worker->scratch.aead) ||
        packet->aad.size > sizeof(worker->scratch.aad))
        return NOISE_ERROR_INVALID_LENGTH;
    memcpy(worker->scratch.aad, packet->aad.data, packet->aad.size);
    if (packet->plaintext.size != 0U)
        memcpy(worker->scratch.aead, packet->plaintext.data, packet->plaintext.size);
    error = noise_cipherstate_set_nonce(association->tx, packet->pn);
    if (error != NOISE_ERROR_NONE)
        return error;
    noise_buffer_set_inout(buffer, worker->scratch.aead, packet->plaintext.size,
                           sizeof(worker->scratch.aead));
    error = tracked_encrypt(worker, association->tx, worker->scratch.aad,
                            packet->aad.size, &buffer);
    if (error != NOISE_ERROR_NONE ||
        buffer.size != packet->ciphertext.size + packet->tag.size ||
        !bytes_equal(worker->scratch.aead, packet->ciphertext.size,
                     packet->ciphertext) ||
        !bytes_equal(worker->scratch.aead + packet->ciphertext.size,
                     packet->tag.size, packet->tag))
        return error != NOISE_ERROR_NONE ? error : NOISE_ERROR_INVALID_STATE;
    encrypted_size = buffer.size;

    memcpy(worker->scratch.bad_aead, worker->scratch.aead, encrypted_size);
    worker->scratch.bad_aead[encrypted_size - 1U] ^= 0x01U;
    noise_buffer_set_inout(buffer, worker->scratch.bad_aead, encrypted_size,
                           sizeof(worker->scratch.bad_aead));
    error = tracked_decrypt(worker, association->rx, packet->pn,
                            worker->scratch.aad, packet->aad.size, &buffer);
    if (error != NOISE_ERROR_MAC_FAILURE)
        return error != NOISE_ERROR_NONE ? error : NOISE_ERROR_INVALID_STATE;

    noise_buffer_set_inout(buffer, worker->scratch.aead, encrypted_size,
                           sizeof(worker->scratch.aead));
    error = tracked_decrypt(worker, association->rx, packet->pn,
                            worker->scratch.aad, packet->aad.size, &buffer);
    if (error != NOISE_ERROR_NONE)
        return error;
    return bytes_equal(worker->scratch.aead, buffer.size, packet->plaintext)
        ? NOISE_ERROR_NONE : NOISE_ERROR_INVALID_STATE;
}

static int topology_application_traffic(parallel_worker *worker,
                                        topology_association *association,
                                        unsigned peer, unsigned worker_id,
                                        unsigned association_kind)
{
    /* These four buffers stand in for operation payloads, not endpoint queues. */
    uint8_t *application = application_operation_slots[peer];
    NoiseBuffer buffer;
    size_t index;
    int error;

    for (index = 0U; index < DMP_PARALLEL_FOUR_APP_SLOT_BYTES; ++index)
        application[index] = (uint8_t)(0x31U + index * 7U + peer * 19U +
                                        worker_id * 13U + association_kind * 41U);
    for (index = 0U; index < sizeof(worker->scratch.aad); ++index)
        worker->scratch.aad[index] = (uint8_t)(0xB3U + index * 3U + peer * 11U +
                                                association_kind * 29U);

    memcpy(worker->scratch.aead, application, DMP_PARALLEL_FOUR_APP_SLOT_BYTES);
    error = noise_cipherstate_set_nonce(association->tx, 1U);
    if (error != NOISE_ERROR_NONE)
        return error;
    noise_buffer_set_inout(buffer, worker->scratch.aead,
                           DMP_PARALLEL_FOUR_APP_SLOT_BYTES,
                           sizeof(worker->scratch.aead));
    error = tracked_encrypt(worker, association->tx, worker->scratch.aad,
                            sizeof(worker->scratch.aad), &buffer);
    if (error != NOISE_ERROR_NONE ||
        buffer.size != DMP_PARALLEL_FOUR_APP_SLOT_BYTES + 16U)
        return error != NOISE_ERROR_NONE ? error : NOISE_ERROR_INVALID_STATE;

    memcpy(worker->scratch.bad_aead, worker->scratch.aead, buffer.size);
    worker->scratch.bad_aead[buffer.size - 1U] ^= 0x01U;
    noise_buffer_set_inout(buffer, worker->scratch.bad_aead, buffer.size,
                           sizeof(worker->scratch.bad_aead));
    error = tracked_decrypt(worker, association->rx, 1U, worker->scratch.aad,
                            sizeof(worker->scratch.aad), &buffer);
    if (error != NOISE_ERROR_MAC_FAILURE)
        return error != NOISE_ERROR_NONE ? error : NOISE_ERROR_INVALID_STATE;

    noise_buffer_set_inout(buffer, worker->scratch.aead,
                           DMP_PARALLEL_FOUR_APP_SLOT_BYTES + 16U,
                           sizeof(worker->scratch.aead));
    error = tracked_decrypt(worker, association->rx, 1U, worker->scratch.aad,
                            sizeof(worker->scratch.aad), &buffer);
    if (error != NOISE_ERROR_NONE)
        return error;
    return buffer.size == DMP_PARALLEL_FOUR_APP_SLOT_BYTES &&
           memcmp(worker->scratch.aead, application,
                  DMP_PARALLEL_FOUR_APP_SLOT_BYTES) == 0
        ? NOISE_ERROR_NONE : NOISE_ERROR_INVALID_STATE;
}

static int topology_close_worker(parallel_worker *worker)
{
    size_t peer, association;
    int error = NOISE_ERROR_NONE;

    for (peer = 0U; peer < 2U; ++peer) {
        int close_error = close_endpoint(&worker->pending[peer].endpoint);
        if (error == NOISE_ERROR_NONE && close_error != NOISE_ERROR_NONE)
            error = close_error;
        for (association = 0U; association < 2U; ++association) {
            topology_association *item = &worker->associations[peer][association];
            if (item->tx != NULL) {
                close_error = noise_cipherstate_free(item->tx);
                item->tx = NULL;
                if (error == NOISE_ERROR_NONE && close_error != NOISE_ERROR_NONE)
                    error = close_error;
            }
            if (item->rx != NULL) {
                close_error = noise_cipherstate_free(item->rx);
                item->rx = NULL;
                if (error == NOISE_ERROR_NONE && close_error != NOISE_ERROR_NONE)
                    error = close_error;
            }
        }
    }
    return error;
}
#endif

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
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
    result->topology_traffic_checks_completed =
        worker->counters.topology_traffic_checks_completed;
#endif
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

#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
static int topology_prepare_worker(parallel_worker *worker, unsigned worker_id,
                                   dmp_parallel_result *result)
{
    size_t peer, association;

    memset(&worker->counters, 0, sizeof(worker->counters));
    memset(worker->pending, 0, sizeof(worker->pending));
    memset(worker->associations, 0, sizeof(worker->associations));
    memset(&worker->scratch, 0, sizeof(worker->scratch));
    if (worker->arena.storage == NULL) {
        if (dmp_noise_test_arena_init(&worker->arena, worker->backing.bytes,
                                      sizeof(worker->backing.bytes),
                                      sizeof(worker->backing.bytes),
                                      DMP_NOISE_TEST_ARENA_MAX_BLOCKS) !=
            DMP_NOISE_TEST_ARENA_OK)
            goto fail;
    } else if (dmp_noise_test_arena_clear(&worker->arena) !=
               DMP_NOISE_TEST_ARENA_OK) {
        goto fail;
    }
    if (NOISE_FIXTURE_PROBE_FIXTURE_COUNT < 2U)
        goto fail;

    for (peer = 0U; peer < 2U; ++peer) {
        topology_pending *pending = &worker->pending[peer];
        const noise_fixture_probe_fixture_t *fixture;
        size_t fixture_index = (worker_id * 2U + peer) % 2U;
        pending->fixture_index = fixture_index;
        fixture = &noise_fixture_probe_fixtures[fixture_index];
        if (create_endpoint(worker, &pending->endpoint, fixture,
                            NOISE_ROLE_INITIATOR, 1) != NOISE_ERROR_NONE ||
            topology_write_first(worker, pending) != NOISE_ERROR_NONE)
            goto fail;
        for (association = 0U; association < 2U; ++association) {
            if (topology_create_association(&worker->associations[peer][association],
                                            fixture, fixture_index) !=
                NOISE_ERROR_NONE)
                goto fail;
        }
    }
    return 0;

fail:
    result->error_line = __LINE__;
    (void)topology_close_worker(worker);
    snapshot_result(worker, result);
    return -1;
}

int dmp_parallel_four_parallel_run(unsigned worker_id,
                                   dmp_parallel_result *result)
{
    parallel_worker *worker;
    size_t peer, association;
    int status = 0;

    if (result == NULL)
        return -1;
    memset(result, 0, sizeof(*result));
    if (worker_id >= DMP_PARALLEL_WORKERS ||
        dmp_parallel_worker_id() != worker_id || !startup_initialized) {
        result->error_line = __LINE__;
        return -1;
    }
    worker = &workers[worker_id];
    if (topology_prepare_worker(worker, worker_id, result) != 0) {
        status = -1;
        goto done;
    }

    /* Keep all pending handshakes and all sixteen cipher states live together. */
    if (dmp_parallel_yield() != 0) {
        result->error_line = __LINE__;
        status = -1;
        goto done;
    }
    result->topology_barrier_reached = 1U;
    result->pending_live = 2U;
    result->associations_live = 4U;
    result->cipher_states_live = 8U;
    result->topology_retained = worker->arena.charged_bytes;
    result->topology_blocks = worker->arena.live_blocks;
    result->topology_peak = worker->arena.peak_charged_bytes;
    for (peer = 0U; peer < 2U; ++peer) {
        for (association = 0U; association < 2U; ++association) {
            topology_association *item = &worker->associations[peer][association];
            int traffic_error = topology_fixture_traffic(worker, item);
            if (traffic_error != NOISE_ERROR_NONE) {
                result->error_line = __LINE__;
                status = -1;
                goto done;
            }
            if (topology_application_traffic(worker, item,
                                             (unsigned)(worker_id * 2U + peer),
                                             worker_id, (unsigned)association) !=
                NOISE_ERROR_NONE) {
                result->error_line = __LINE__;
                status = -1;
                goto done;
            }
            ++worker->counters.topology_traffic_checks_completed;
        }
    }
    for (peer = 0U; peer < 2U; ++peer) {
        if (noise_handshakestate_get_action(worker->pending[peer].endpoint.handshake) !=
            NOISE_ACTION_READ_MESSAGE) {
            result->error_line = __LINE__;
            status = -1;
            goto done;
        }
    }
done:
    if (topology_close_worker(worker) != NOISE_ERROR_NONE) {
        if (result->error_line == 0U)
            result->error_line = __LINE__;
        status = -1;
    }
    snapshot_result(worker, result);
    if (worker->arena.live_blocks != 0U || worker->arena.charged_bytes != 0U ||
        worker->counters.allocs != worker->counters.frees ||
        worker->counters.wipe_errors != 0U || worker->counters.refusals != 0U) {
        if (result->error_line == 0U)
            result->error_line = __LINE__;
        status = -1;
    }
    return status;
}

int dmp_parallel_resource_metrics_reset(void)
{
    if (atomic_load(&aggregate_live_bytes) != 0U)
        return -1;
    atomic_store(&aggregate_peak_bytes, 0U);
    return 0;
}

size_t dmp_parallel_aggregate_live(void)
{
    return atomic_load(&aggregate_live_bytes);
}

size_t dmp_parallel_aggregate_peak(void)
{
    return atomic_load(&aggregate_peak_bytes);
}
#endif
