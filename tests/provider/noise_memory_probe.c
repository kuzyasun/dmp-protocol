/* Host-only allocation and erasure characterization for real Noise provider calls. */
#include <noise/protocol.h>

#include "noise_fixture_probe.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRACK_CAPACITY 512U
#define MESSAGE_CAPACITY 512U
#define PLAINTEXT_CAPACITY 128U
#define KEY_LENGTH 32U
#define TAG_LENGTH 16U
#define HASH_LENGTH 32U
#define PHASE_COUNT 6U

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *pointer, size_t size);
void __real_free(void *pointer);

typedef struct {
    void *pointer;
    size_t size;
    bool live;
} allocation_t;

typedef enum {
    PHASE_SETUP = 0,
    PHASE_START,
    PHASE_WRITE,
    PHASE_READ,
    PHASE_SPLIT,
    PHASE_TRAFFIC
} phase_t;

static allocation_t allocations[TRACK_CAPACITY];
static size_t allocation_count;
static size_t attempts;
static size_t fail_ordinal;
static size_t phase_allocations[PHASE_COUNT];
static size_t phase_requested_bytes[PHASE_COUNT];
static size_t live_requested_bytes;
static size_t peak_live_requested_bytes;
static phase_t current_phase;
static bool tracking;
static bool injection_fired;
static bool tracker_failed;
static bool suppress_expected_error;

static void tracker_error(const char *message)
{
    tracker_failed = true;
    if (!suppress_expected_error)
        fprintf(stderr, "noise memory probe: tracker: %s\n", message);
}

static bool allocation_should_fail(void)
{
    if (!tracking)
        return false;
    ++attempts;
    if (fail_ordinal != 0U && attempts == fail_ordinal) {
        injection_fired = true;
        return true;
    }
    return false;
}

static allocation_t *find_allocation(void *pointer)
{
    size_t index;

    for (index = 0U; index < allocation_count; ++index) {
        if (allocations[index].pointer == pointer)
            return &allocations[index];
    }
    return NULL;
}

static void remember_allocation(void *pointer, size_t size)
{
    allocation_t *entry;

    if (!tracking || pointer == NULL)
        return;
    entry = find_allocation(pointer);
    if (entry != NULL) {
        if (entry->live)
            tracker_error("allocator reused a still-live address");
        entry->size = size;
        entry->live = true;
        if ((size_t)current_phase < PHASE_COUNT) {
            ++phase_allocations[current_phase];
            phase_requested_bytes[current_phase] += size;
        }
        live_requested_bytes += size;
        if (live_requested_bytes > peak_live_requested_bytes)
            peak_live_requested_bytes = live_requested_bytes;
        return;
    }
    if (allocation_count == TRACK_CAPACITY) {
        tracker_error("fixed allocation table is full");
        return;
    }
    allocations[allocation_count].pointer = pointer;
    allocations[allocation_count].size = size;
    allocations[allocation_count].live = true;
    ++allocation_count;
    if ((size_t)current_phase < PHASE_COUNT) {
        ++phase_allocations[current_phase];
        phase_requested_bytes[current_phase] += size;
    }
    live_requested_bytes += size;
    if (live_requested_bytes > peak_live_requested_bytes)
        peak_live_requested_bytes = live_requested_bytes;
}

static bool check_zeroed(const allocation_t *entry)
{
    const uint8_t *bytes = (const uint8_t *)entry->pointer;
    size_t index;

    for (index = 0U; index < entry->size; ++index) {
        if (bytes[index] != 0U) {
            tracker_error("tracked allocation was not fully zeroed before free");
            return false;
        }
    }
    return true;
}

void *__wrap_malloc(size_t size)
{
    void *pointer;

    if (allocation_should_fail())
        return NULL;
    pointer = __real_malloc(size);
    remember_allocation(pointer, size);
    return pointer;
}

void *__wrap_calloc(size_t count, size_t size)
{
    void *pointer;

    if (count != 0U && size > SIZE_MAX / count)
        return NULL;
    if (allocation_should_fail())
        return NULL;
    pointer = __real_calloc(count, size);
    remember_allocation(pointer, count * size);
    return pointer;
}

void *__wrap_realloc(void *pointer, size_t size)
{
    allocation_t *entry;

    if (allocation_should_fail())
        return NULL;
    if (pointer == NULL) {
        void *replacement = __real_malloc(size);
        remember_allocation(replacement, size);
        return replacement;
    }
    if (!tracking)
        return __real_realloc(pointer, size);
    entry = find_allocation(pointer);
    if (entry == NULL || !entry->live) {
        tracker_error("realloc released an untracked or already-freed allocation");
        return NULL;
    }
    (void)size;
    tracker_error("provider realloc encountered; probe does not emulate realloc erasure");
    return NULL;
}

void __wrap_free(void *pointer)
{
    allocation_t *entry;

    if (pointer == NULL) {
        __real_free(pointer);
        return;
    }
    if (tracking) {
        entry = find_allocation(pointer);
        if (entry == NULL || !entry->live) {
            tracker_error("free received an untracked or already-freed pointer while armed");
            return;
        }
        (void)check_zeroed(entry);
        live_requested_bytes -= entry->size;
        entry->live = false;
    }
    __real_free(pointer);
}

static void tracker_reset(void)
{
    size_t index;

    tracking = false;
    for (index = 0U; index < allocation_count; ++index) {
        allocations[index].pointer = NULL;
        allocations[index].size = 0U;
        allocations[index].live = false;
    }
    allocation_count = 0U;
    attempts = 0U;
    fail_ordinal = 0U;
    memset(phase_allocations, 0, sizeof(phase_allocations));
    memset(phase_requested_bytes, 0, sizeof(phase_requested_bytes));
    live_requested_bytes = 0U;
    peak_live_requested_bytes = 0U;
    injection_fired = false;
    tracker_failed = false;
    suppress_expected_error = false;
}

static size_t live_allocations(void)
{
    size_t index;
    size_t live = 0U;

    for (index = 0U; index < allocation_count; ++index) {
        if (allocations[index].live)
            ++live;
    }
    return live;
}

static int tracker_self_check(void)
{
    uint8_t *memory;
    uint8_t *resized;

    tracker_reset();
    tracking = true;
    memory = (uint8_t *)__wrap_malloc(8U);
    if (memory == NULL)
        return 0;
    memset(memory, 0, 8U);
    __wrap_free(memory);

    memory = (uint8_t *)__wrap_calloc(2U, 8U);
    if (memory == NULL)
        return 0;
    fail_ordinal = attempts + 1U;
    if (__wrap_realloc(memory, 24U) != NULL || !injection_fired)
        return 0;
    fail_ordinal = 0U;
    memset(memory, 0, 16U);
    __wrap_free(memory);
    resized = (uint8_t *)__wrap_realloc(NULL, 24U);
    if (resized == NULL)
        return 0;
    memset(resized, 0, 24U);
    __wrap_free(resized);

    fail_ordinal = attempts + 1U;
    if (__wrap_malloc(3U) != NULL || !injection_fired)
        return 0;
    fail_ordinal = 0U;

    memory = (uint8_t *)__wrap_malloc(4U);
    if (memory == NULL)
        return 0;
    memory[0] = 0xA5U;
    suppress_expected_error = true;
    __wrap_free(memory);
    suppress_expected_error = false;
    if (!tracker_failed || live_allocations() != 0U)
        return 0;
    tracking = false;
    tracker_reset();
    return 1;
}

typedef struct {
    NoiseHandshakeState *initiator;
    NoiseHandshakeState *responder;
    NoiseCipherState *i_send;
    NoiseCipherState *i_receive;
    NoiseCipherState *r_send;
    NoiseCipherState *r_receive;
} probe_states_t;

typedef enum { RUN_OK, RUN_OOM, RUN_FAILED } run_result_t;

static int fail(const char *fixture, const char *what)
{
    fprintf(stderr, "%s: %s\n", fixture, what);
    return 0;
}

static int expect_error(const char *fixture, const char *operation, int actual, int expected)
{
    char message[96];

    if (actual == expected)
        return 1;
    if (noise_strerror(actual, message, sizeof(message)) != NOISE_ERROR_NONE)
        (void)snprintf(message, sizeof(message), "error %d", actual);
    fprintf(stderr, "%s: %s returned %s (%d), expected %d\n",
            fixture, operation, message, actual, expected);
    return 0;
}

static int expect_bytes(const char *fixture, const char *what, const uint8_t *actual,
                        size_t actual_size, noise_fixture_probe_bytes_t expected)
{
    if (actual_size != expected.size || (actual_size != 0U && actual == NULL) ||
        (expected.size != 0U && expected.data == NULL))
        return fail(fixture, what);
    if (actual_size != 0U && memcmp(actual, expected.data, actual_size) != 0)
        return fail(fixture, what);
    return 1;
}

static int derive_public_key(noise_fixture_probe_bytes_t private_key, uint8_t public_key[KEY_LENGTH])
{
    NoiseDHState *dh = NULL;
    int error;
    int success = 0;

    error = noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519);
    if (error != NOISE_ERROR_NONE)
        goto cleanup;
    error = noise_dhstate_set_keypair_private(dh, private_key.data, private_key.size);
    if (error != NOISE_ERROR_NONE)
        goto cleanup;
    error = noise_dhstate_get_public_key(dh, public_key, KEY_LENGTH);
    if (error == NOISE_ERROR_NONE)
        success = 1;
cleanup:
    if (dh != NULL && noise_dhstate_free(dh) != NOISE_ERROR_NONE)
        success = 0;
    return success;
}

static int configure_state(const noise_fixture_probe_fixture_t *fixture,
                           NoiseHandshakeState *state,
                           noise_fixture_probe_bytes_t ephemeral,
                           const uint8_t public_key[KEY_LENGTH],
                           noise_fixture_probe_bytes_t static_key)
{
    NoiseDHState *static_dh = noise_handshakestate_get_local_keypair_dh(state);
    int error;

    error = noise_handshakestate_set_local_ephemeral(state, ephemeral.data, ephemeral.size,
                                                     public_key, KEY_LENGTH);
    if (error != NOISE_ERROR_NONE)
        return error;
    if (static_key.size != 0U) {
        if (static_dh == NULL) {
            (void)fail(fixture->name, "static key state is missing");
            return NOISE_ERROR_SYSTEM;
        }
        error = noise_dhstate_set_keypair_private(static_dh, static_key.data, static_key.size);
        if (error != NOISE_ERROR_NONE)
            return error;
    } else if (static_dh != NULL) {
        (void)fail(fixture->name, "unexpected static key state");
        return NOISE_ERROR_SYSTEM;
    }
    if (noise_handshakestate_needs_pre_shared_key(state) != 0) {
        error = noise_handshakestate_set_pre_shared_key(state, fixture->psk.data, fixture->psk.size);
        if (error != NOISE_ERROR_NONE)
            return error;
    }
    error = noise_handshakestate_set_prologue(state, fixture->prologue.data, fixture->prologue.size);
    return error;
}

static int create_handshakes(const noise_fixture_probe_fixture_t *fixture,
                             const uint8_t i_ephemeral_public[KEY_LENGTH],
                             const uint8_t r_ephemeral_public[KEY_LENGTH],
                             probe_states_t *states)
{
    int error;

    error = noise_handshakestate_new_by_name(&states->initiator, fixture->protocol_name,
                                             NOISE_ROLE_INITIATOR);
    if (error != NOISE_ERROR_NONE) {
        if (states->initiator != NULL) {
            fprintf(stderr, "%s: constructor returned %d with non-null initiator output after failure\n",
                    fixture->name, error);
            tracker_failed = true;
            states->initiator = NULL; /* The provider may already have freed this value. */
        }
        return error;
    }
    error = noise_handshakestate_new_by_name(&states->responder, fixture->protocol_name,
                                             NOISE_ROLE_RESPONDER);
    if (error != NOISE_ERROR_NONE) {
        if (states->responder != NULL) {
            fprintf(stderr, "%s: constructor returned %d with non-null responder output after failure\n",
                    fixture->name, error);
            tracker_failed = true;
            states->responder = NULL; /* The provider may already have freed this value. */
        }
        return error;
    }
    error = configure_state(fixture, states->initiator, fixture->init_ephemeral,
                            i_ephemeral_public, fixture->init_static);
    if (error != NOISE_ERROR_NONE)
        return error;
    return configure_state(fixture, states->responder, fixture->resp_ephemeral,
                           r_ephemeral_public, fixture->resp_static);
}

static int transfer_fixture_flight(const noise_fixture_probe_fixture_t *fixture,
                                   NoiseHandshakeState *sender,
                                   NoiseHandshakeState *receiver,
                                   const noise_fixture_probe_flight_t *flight)
{
    uint8_t message[MESSAGE_CAPACITY];
    uint8_t plaintext[PLAINTEXT_CAPACITY];
    uint8_t empty = 0U;
    NoiseBuffer message_buffer;
    NoiseBuffer plaintext_buffer;
    int error;

    noise_buffer_set_output(message_buffer, message, sizeof(message));
    noise_buffer_set_input(plaintext_buffer, flight->plaintext.size == 0U ? &empty :
                           (uint8_t *)flight->plaintext.data, flight->plaintext.size);
    current_phase = PHASE_WRITE;
    error = noise_handshakestate_write_message(sender, &message_buffer, &plaintext_buffer);
    if (error != NOISE_ERROR_NONE)
        return error;
    if (!expect_bytes(fixture->name, "exact Noise flight", message_buffer.data,
                      message_buffer.size, flight->message))
        return NOISE_ERROR_SYSTEM;

    noise_buffer_set_input(message_buffer, message, message_buffer.size);
    noise_buffer_set_output(plaintext_buffer, plaintext, sizeof(plaintext));
    current_phase = PHASE_READ;
    error = noise_handshakestate_read_message(receiver, &message_buffer, &plaintext_buffer);
    if (error != NOISE_ERROR_NONE)
        return error;
    if (!expect_bytes(fixture->name, "decrypted fixture payload", plaintext_buffer.data,
                      plaintext_buffer.size, flight->plaintext))
        return NOISE_ERROR_SYSTEM;
    return NOISE_ERROR_NONE;
}

static int encrypt_fixture_packet(const noise_fixture_probe_fixture_t *fixture,
                                  const noise_fixture_probe_packet_t *packet,
                                  NoiseCipherState *state)
{
    uint8_t bytes[256];
    uint8_t expected[256];
    size_t expected_size = packet->ciphertext.size + packet->tag.size;
    NoiseBuffer buffer;
    int error;

    if (packet->plaintext.size > sizeof(bytes) || expected_size > sizeof(expected))
        return fail(fixture->name, "fixture packet exceeds bounded scratch space");
    memcpy(bytes, packet->plaintext.data, packet->plaintext.size);
    noise_buffer_set_inout(buffer, bytes, packet->plaintext.size, sizeof(bytes));
    error = noise_cipherstate_set_nonce(state, packet->pn);
    if (error == NOISE_ERROR_NONE)
        error = noise_cipherstate_encrypt_with_ad(state, packet->aad.data, packet->aad.size, &buffer);
    if (!expect_error(fixture->name, "encrypt fixture packet", error, NOISE_ERROR_NONE))
        return 0;
    memcpy(expected, packet->ciphertext.data, packet->ciphertext.size);
    memcpy(expected + packet->ciphertext.size, packet->tag.data, packet->tag.size);
    return expect_bytes(fixture->name, packet->name, buffer.data, buffer.size,
                        (noise_fixture_probe_bytes_t){expected, expected_size});
}

static int decrypt_fixture_packet(const noise_fixture_probe_fixture_t *fixture,
                                  const noise_fixture_probe_packet_t *packet,
                                  NoiseCipherState *state)
{
    uint8_t bytes[256];
    size_t size = packet->ciphertext.size + packet->tag.size;
    NoiseBuffer buffer;
    int error;

    if (size > sizeof(bytes))
        return fail(fixture->name, "fixture packet exceeds bounded scratch space");
    memcpy(bytes, packet->ciphertext.data, packet->ciphertext.size);
    memcpy(bytes + packet->ciphertext.size, packet->tag.data, packet->tag.size);
    noise_buffer_set_inout(buffer, bytes, size, sizeof(bytes));
    error = noise_cipherstate_set_nonce(state, packet->pn);
    if (error == NOISE_ERROR_NONE)
        error = noise_cipherstate_decrypt_with_ad(state, packet->aad.data, packet->aad.size, &buffer);
    if (!expect_error(fixture->name, "decrypt fixture packet", error, NOISE_ERROR_NONE))
        return 0;
    return expect_bytes(fixture->name, packet->name, buffer.data, buffer.size, packet->plaintext);
}

static bool is_oom(int error, const char *fixture, const char *operation)
{
    if (!injection_fired)
        return false;
    if (error != NOISE_ERROR_NO_MEMORY) {
        (void)expect_error(fixture, operation, error, NOISE_ERROR_NO_MEMORY);
        return false;
    }
    return true;
}

static void cleanup_states(const char *fixture, probe_states_t *states)
{
    if (states->initiator != NULL) {
        if (!expect_error(fixture, "free initiator handshake",
                          noise_handshakestate_free(states->initiator), NOISE_ERROR_NONE))
            tracker_failed = true;
        states->initiator = NULL;
    }
    if (states->responder != NULL) {
        if (!expect_error(fixture, "free responder handshake",
                          noise_handshakestate_free(states->responder), NOISE_ERROR_NONE))
            tracker_failed = true;
        states->responder = NULL;
    }
    if (states->i_send != NULL) {
        if (!expect_error(fixture, "free initiator send cipher",
                          noise_cipherstate_free(states->i_send), NOISE_ERROR_NONE))
            tracker_failed = true;
        states->i_send = NULL;
    }
    if (states->i_receive != NULL) {
        if (!expect_error(fixture, "free initiator receive cipher",
                          noise_cipherstate_free(states->i_receive), NOISE_ERROR_NONE))
            tracker_failed = true;
        states->i_receive = NULL;
    }
    if (states->r_send != NULL) {
        if (!expect_error(fixture, "free responder send cipher",
                          noise_cipherstate_free(states->r_send), NOISE_ERROR_NONE))
            tracker_failed = true;
        states->r_send = NULL;
    }
    if (states->r_receive != NULL) {
        if (!expect_error(fixture, "free responder receive cipher",
                          noise_cipherstate_free(states->r_receive), NOISE_ERROR_NONE))
            tracker_failed = true;
        states->r_receive = NULL;
    }
}

static run_result_t run_successful_exchange(const noise_fixture_probe_fixture_t *fixture,
                                           size_t fail_at)
{
    probe_states_t states = {0};
    uint8_t i_ephemeral_public[KEY_LENGTH];
    uint8_t r_ephemeral_public[KEY_LENGTH];
    uint8_t hash[HASH_LENGTH];
    uint8_t responder_hash[HASH_LENGTH];
    size_t index;
    int error;
    run_result_t result = RUN_FAILED;

    if (!derive_public_key(fixture->init_ephemeral, i_ephemeral_public) ||
        !derive_public_key(fixture->resp_ephemeral, r_ephemeral_public))
        return RUN_FAILED;
    tracker_reset();
    tracking = true;
    fail_ordinal = fail_at;
    current_phase = PHASE_SETUP;
    error = create_handshakes(fixture, i_ephemeral_public, r_ephemeral_public, &states);
    if (error != NOISE_ERROR_NONE) {
        if (is_oom(error, fixture->name, "setup"))
            result = RUN_OOM;
        goto cleanup;
    }

    current_phase = PHASE_START;
    error = noise_handshakestate_start(states.initiator);
    if (error == NOISE_ERROR_NONE)
        error = noise_handshakestate_start(states.responder);
    if (error != NOISE_ERROR_NONE) {
        if (is_oom(error, fixture->name, "start"))
            result = RUN_OOM;
        goto cleanup;
    }
    for (index = 0U; index < fixture->flight_count; ++index) {
        NoiseHandshakeState *sender = (index % 2U == 0U) ? states.initiator : states.responder;
        NoiseHandshakeState *receiver = (index % 2U == 0U) ? states.responder : states.initiator;

        error = transfer_fixture_flight(fixture, sender, receiver, &fixture->flights[index]);
        if (error != NOISE_ERROR_NONE) {
            if (is_oom(error, fixture->name, "write/read flight"))
                result = RUN_OOM;
            goto cleanup;
        }
    }
    if (noise_handshakestate_get_action(states.initiator) != NOISE_ACTION_SPLIT ||
        noise_handshakestate_get_action(states.responder) != NOISE_ACTION_SPLIT) {
        (void)fail(fixture->name, "handshakes did not reach SPLIT");
        goto cleanup;
    }
    if (!expect_error(fixture->name, "initiator handshake hash",
                      noise_handshakestate_get_handshake_hash(states.initiator, hash, sizeof(hash)),
                      NOISE_ERROR_NONE) ||
        !expect_bytes(fixture->name, "initiator handshake hash", hash, sizeof(hash), fixture->handshake_hash) ||
        !expect_error(fixture->name, "responder handshake hash",
                      noise_handshakestate_get_handshake_hash(states.responder, responder_hash,
                                                              sizeof(responder_hash)),
                      NOISE_ERROR_NONE) ||
        !expect_bytes(fixture->name, "responder handshake hash", responder_hash,
                      sizeof(responder_hash), fixture->handshake_hash))
        goto cleanup;
    current_phase = PHASE_SPLIT;
    error = noise_handshakestate_split(states.initiator, &states.i_send, &states.i_receive);
    if (error != NOISE_ERROR_NONE) {
        if (states.i_send != NULL || states.i_receive != NULL) {
            (void)fail(fixture->name, "failed initiator Split left an output pointer non-null");
            tracker_failed = true;
        }
        if (is_oom(error, fixture->name, "split"))
            result = RUN_OOM;
        goto cleanup;
    }
    error = noise_handshakestate_split(states.responder, &states.r_send, &states.r_receive);
    if (error != NOISE_ERROR_NONE) {
        if (states.r_send != NULL || states.r_receive != NULL) {
            (void)fail(fixture->name, "failed responder Split left an output pointer non-null");
            tracker_failed = true;
        }
        if (is_oom(error, fixture->name, "split"))
            result = RUN_OOM;
        goto cleanup;
    }
    if (!expect_error(fixture->name, "destroy initiator handshake",
                      noise_handshakestate_free(states.initiator), NOISE_ERROR_NONE) ||
        !expect_error(fixture->name, "destroy responder handshake",
                      noise_handshakestate_free(states.responder), NOISE_ERROR_NONE))
        goto cleanup;
    states.initiator = NULL;
    states.responder = NULL;

    current_phase = PHASE_TRAFFIC;
    if (!encrypt_fixture_packet(fixture, &fixture->finish, states.i_send) ||
        !decrypt_fixture_packet(fixture, &fixture->finish, states.r_receive) ||
        !encrypt_fixture_packet(fixture, &fixture->ready, states.r_send) ||
        !decrypt_fixture_packet(fixture, &fixture->ready, states.i_receive))
        goto cleanup;
    result = RUN_OK;

cleanup:
    cleanup_states(fixture->name, &states);
    tracking = false;
    if (live_allocations() != 0U) {
        (void)fail(fixture->name, "tracked allocations remain after cleanup");
        tracker_failed = true;
    }
    if (tracker_failed)
        return RUN_FAILED;
    if (fail_at != 0U && !injection_fired) {
        (void)fail(fixture->name, "requested allocation failure ordinal was not reached");
        return RUN_FAILED;
    }
    return result;
}

static int run_abort_and_postread_cleanup(const noise_fixture_probe_fixture_t *fixture,
                                          bool corrupt_final)
{
    probe_states_t states = {0};
    uint8_t i_ephemeral_public[KEY_LENGTH];
    uint8_t r_ephemeral_public[KEY_LENGTH];
    uint8_t message[MESSAGE_CAPACITY];
    uint8_t plaintext[PLAINTEXT_CAPACITY];
    size_t index;
    size_t target = corrupt_final ? fixture->flight_count - 1U : fixture->flight_count;
    int error;
    int success = 0;

    if (!derive_public_key(fixture->init_ephemeral, i_ephemeral_public) ||
        !derive_public_key(fixture->resp_ephemeral, r_ephemeral_public))
        return 0;
    tracker_reset();
    tracking = true;
    fail_ordinal = 0U;
    current_phase = PHASE_SETUP;
    error = create_handshakes(fixture, i_ephemeral_public, r_ephemeral_public, &states);
    if (error != NOISE_ERROR_NONE)
        goto cleanup;
    current_phase = PHASE_START;
    if (noise_handshakestate_start(states.initiator) != NOISE_ERROR_NONE ||
        noise_handshakestate_start(states.responder) != NOISE_ERROR_NONE)
        goto cleanup;
    for (index = 0U; index < target; ++index) {
        NoiseHandshakeState *sender = (index % 2U == 0U) ? states.initiator : states.responder;
        NoiseHandshakeState *receiver = (index % 2U == 0U) ? states.responder : states.initiator;
        if (transfer_fixture_flight(fixture, sender, receiver, &fixture->flights[index]) != NOISE_ERROR_NONE)
            goto cleanup;
    }
    if (corrupt_final) {
        const noise_fixture_probe_flight_t *flight = &fixture->flights[target];
        NoiseHandshakeState *sender = (target % 2U == 0U) ? states.initiator : states.responder;
        NoiseHandshakeState *receiver = (target % 2U == 0U) ? states.responder : states.initiator;
        NoiseBuffer message_buffer;
        NoiseBuffer plaintext_buffer;
        uint8_t empty = 0U;

        noise_buffer_set_output(message_buffer, message, sizeof(message));
        noise_buffer_set_input(plaintext_buffer, flight->plaintext.size == 0U ? &empty :
                               (uint8_t *)flight->plaintext.data, flight->plaintext.size);
        error = noise_handshakestate_write_message(sender, &message_buffer, &plaintext_buffer);
        if (!expect_error(fixture->name, "write final flight before tag corruption",
                          error, NOISE_ERROR_NONE) || message_buffer.size < TAG_LENGTH)
            goto cleanup;
        message[message_buffer.size - 1U] ^= 1U;
        noise_buffer_set_input(message_buffer, message, message_buffer.size);
        noise_buffer_set_output(plaintext_buffer, plaintext, sizeof(plaintext));
        error = noise_handshakestate_read_message(receiver, &message_buffer, &plaintext_buffer);
        if (!expect_error(fixture->name, "corrupt final authenticated flight",
                          error, NOISE_ERROR_MAC_FAILURE) ||
            noise_handshakestate_get_action(receiver) != NOISE_ACTION_FAILED)
            goto cleanup;
    } else {
        /* The provider accepted the final flight; the owning caller then rejects policy. */
        /* All reads succeeded; model the owning caller rejecting its post-read policy check. */
    }
    success = 1;
cleanup:
    cleanup_states(fixture->name, &states);
    tracking = false;
    if (live_allocations() != 0U || tracker_failed)
        success = 0;
    return success;
}

static int run_mode(const noise_fixture_probe_fixture_t *fixture)
{
    run_result_t result;
    size_t successful_allocations;
    size_t ordinal;

    result = run_successful_exchange(fixture, 0U);
    if (result != RUN_OK)
        return 0;
    successful_allocations = attempts;
    if (phase_allocations[PHASE_SETUP] == 0U ||
        phase_allocations[PHASE_SPLIT] == 0U || peak_live_requested_bytes == 0U)
        return fail(fixture->name, "provider allocator interception was not observed");
    printf("%s: allocation calls/bytes setup=%zu/%zu start=%zu/%zu write=%zu/%zu read=%zu/%zu split=%zu/%zu traffic=%zu/%zu total_calls=%zu peak_live_bytes=%zu\n",
           fixture->name, phase_allocations[PHASE_SETUP], phase_requested_bytes[PHASE_SETUP],
           phase_allocations[PHASE_START], phase_requested_bytes[PHASE_START],
           phase_allocations[PHASE_WRITE], phase_requested_bytes[PHASE_WRITE],
           phase_allocations[PHASE_READ], phase_requested_bytes[PHASE_READ],
           phase_allocations[PHASE_SPLIT], phase_requested_bytes[PHASE_SPLIT],
           phase_allocations[PHASE_TRAFFIC], phase_requested_bytes[PHASE_TRAFFIC],
           successful_allocations, peak_live_requested_bytes);

    for (ordinal = 1U; ordinal <= successful_allocations; ++ordinal) {
        result = run_successful_exchange(fixture, ordinal);
        if (result != RUN_OOM) {
            fprintf(stderr, "%s: OOM sweep ordinal %zu did not fail cleanly (result %d)\n",
                    fixture->name, ordinal, (int)result);
            return 0;
        }
    }
    if (!run_abort_and_postread_cleanup(fixture, true) ||
        !run_abort_and_postread_cleanup(fixture, false))
        return 0;
    result = run_successful_exchange(fixture, 0U);
    if (result != RUN_OK)
        return 0;
    printf("%s: all %zu allocation ordinals returned NO_MEMORY with complete tracked cleanup; fresh fixture success passed\n",
           fixture->name, successful_allocations);
    return 1;
}

int main(void)
{
    size_t index;

    puts("Measurements aggregate one initiator/responder pair (two endpoints), with supplied fixture ephemerals; not a per-endpoint RAM budget.");

    if (!tracker_self_check()) {
        fputs("noise memory probe: tracker self-check failed\n", stderr);
        return 1;
    }
    if (!expect_error("noise memory probe", "noise_init_framework",
                      noise_init_framework(), NOISE_ERROR_NONE))
        return 1;
    for (index = 0U; index < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++index) {
        if (!run_mode(&noise_fixture_probe_fixtures[index]))
            return 1;
    }
    puts("Host allocation sizes are requested heap bytes for tracked blocks only; no allocator overhead, production quota, embedded RAM, endpoint, or generation claim is established.");
    return 0;
}
