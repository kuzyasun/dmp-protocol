/*
 * Host probe for checked entropy failures in real Noise handshakes.
 *
 * The link-time random hook below is deterministic test machinery.  It does
 * not model or establish the quality of a production entropy source.
 */
#include <noise/protocol.h>

#include "noise_fixture_probe.h"
#include "protocol/internal.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PROBE_MESSAGE_CAPACITY 512U
#define PROBE_PLAINTEXT_CAPACITY 128U
#define PROBE_AEAD_CAPACITY 256U
#define PROBE_KEY_LENGTH 32U
#define PROBE_HASH_LENGTH 32U
#define PROBE_FAILURE_BYTE 0xA6U
#define PROBE_RECOVERY_BYTE 0x5CU

typedef struct {
    const noise_fixture_probe_fixture_t *fixture;
    size_t calls;
    size_t requested_sizes[4];
    size_t fixture_key_index;
    size_t fail_on_call;
    size_t partial_bytes;
    int failure_error;
} probe_rng_t;

typedef struct {
    NoiseHandshakeState *initiator;
    NoiseHandshakeState *responder;
} probe_pair_t;

static probe_rng_t probe_rng;

/* This symbol is the checked link-time port selected by the experiment build. */
int noise_rand_bytes_checked(void *bytes, size_t size)
{
    uint8_t *output = (uint8_t *)bytes;
    noise_fixture_probe_bytes_t fixture_key;
    size_t count;

    ++probe_rng.calls;
    if (probe_rng.calls <= sizeof(probe_rng.requested_sizes) /
                              sizeof(probe_rng.requested_sizes[0]))
        probe_rng.requested_sizes[probe_rng.calls - 1U] = size;
    if (output == NULL || size == 0U)
        return NOISE_ERROR_INVALID_PARAM;

    if (probe_rng.fail_on_call != 0U && probe_rng.calls == probe_rng.fail_on_call) {
        count = probe_rng.partial_bytes < size ? probe_rng.partial_bytes : size;
        if (count != 0U)
            memset(output, PROBE_FAILURE_BYTE, count);
        return probe_rng.failure_error;
    }

    if (probe_rng.fixture != NULL && probe_rng.fixture_key_index < 2U) {
        fixture_key = probe_rng.fixture_key_index == 0U
                          ? probe_rng.fixture->init_ephemeral
                          : probe_rng.fixture->resp_ephemeral;
        if (fixture_key.data == NULL || fixture_key.size != size)
            return NOISE_ERROR_INVALID_LENGTH;
        memcpy(output, fixture_key.data, size);
        ++probe_rng.fixture_key_index;
        return NOISE_ERROR_NONE;
    }

    /* A recovered source makes any forbidden retry observable and successful. */
    memset(output, PROBE_RECOVERY_BYTE, size);
    return NOISE_ERROR_NONE;
}

static int fail(const char *fixture, const char *what)
{
    fprintf(stderr, "%s: %s\n", fixture, what);
    return 0;
}

static int expect_noise(const char *fixture, const char *operation,
                        int actual, int expected)
{
    if (actual == expected)
        return 1;
    fprintf(stderr, "%s: %s returned %d, expected %d\n",
            fixture, operation, actual, expected);
    return 0;
}

static int expect_bytes(const char *fixture, const char *operation,
                        const uint8_t *actual, size_t actual_size,
                        const uint8_t *expected, size_t expected_size)
{
    if (actual_size != expected_size) {
        fprintf(stderr, "%s: %s length %zu, expected %zu\n",
                fixture, operation, actual_size, expected_size);
        return 0;
    }
    if (expected_size != 0U && (actual == NULL || expected == NULL))
        return fail(fixture, "nonempty byte comparison has a null pointer");
    if (expected_size != 0U && memcmp(actual, expected, expected_size) != 0)
        return fail(fixture, operation);
    return 1;
}

static int all_zero(const uint8_t *bytes, size_t size)
{
    size_t index;

    for (index = 0U; index < size; ++index) {
        if (bytes[index] != 0U)
            return 0;
    }
    return 1;
}

static void reset_rng(const noise_fixture_probe_fixture_t *fixture)
{
    memset(&probe_rng, 0, sizeof(probe_rng));
    probe_rng.fixture = fixture;
    probe_rng.failure_error = NOISE_ERROR_SYSTEM;
}

static int assert_unseeded_ephemeral(const char *name, NoiseHandshakeState *state)
{
    if (state == NULL || state->dh_local_ephemeral == NULL)
        return fail(name, "handshake has no local ephemeral state");
    if (state->local_ephemeral_supplied != 0U || state->dh_fixed_ephemeral != NULL)
        return fail(name, "test unexpectedly supplied or fixed an ephemeral key");
    if (state->dh_local_ephemeral->key_type != NOISE_KEY_TYPE_NO_KEY)
        return fail(name, "local ephemeral was already a keypair before Noise write");
    return 1;
}

static int assert_ephemeral_cleared(const char *name, NoiseHandshakeState *state)
{
    NoiseDHState *ephemeral;

    if (!assert_unseeded_ephemeral(name, state))
        return 0;
    ephemeral = state->dh_local_ephemeral;
    if (ephemeral->private_key == NULL || ephemeral->public_key == NULL)
        return fail(name, "local ephemeral key storage is missing");
    if (!all_zero(ephemeral->private_key, ephemeral->private_key_len) ||
        !all_zero(ephemeral->public_key, ephemeral->public_key_len))
        return fail(name, "failed entropy left partial ephemeral key material");
    return 1;
}

static int configure_state(const noise_fixture_probe_fixture_t *fixture,
                           NoiseHandshakeState **state_out, int role)
{
    noise_fixture_probe_bytes_t static_key;
    NoiseHandshakeState *state = NULL;
    NoiseDHState *local_static;
    bool has_static;
    bool has_psk;
    int error;
    int success = 0;

    *state_out = NULL;
    if (role == NOISE_ROLE_INITIATOR) {
        static_key = fixture->init_static;
    } else {
        static_key = fixture->resp_static;
    }
    has_static = static_key.size != 0U;
    has_psk = fixture->psk.size != 0U;

    error = noise_handshakestate_new_by_name(&state, fixture->protocol_name, role);
    if (!expect_noise(fixture->name, "new handshake state", error, NOISE_ERROR_NONE))
        goto cleanup;
    if (!assert_unseeded_ephemeral(fixture->name, state))
        goto cleanup;

    local_static = noise_handshakestate_get_local_keypair_dh(state);
    if (has_static) {
        if (local_static == NULL) {
            (void)fail(fixture->name, "XX state has no local static-key object");
            goto cleanup;
        }
        error = noise_dhstate_set_keypair_private(
            local_static, static_key.data, static_key.size);
        if (!expect_noise(fixture->name, "install fixture static key",
                          error, NOISE_ERROR_NONE))
            goto cleanup;
    } else if (local_static != NULL) {
        (void)fail(fixture->name, "NNpsk0 state unexpectedly has a static-key object");
        goto cleanup;
    }

    if ((noise_handshakestate_needs_pre_shared_key(state) != 0) != has_psk) {
        (void)fail(fixture->name, "handshake PSK requirement differs from its fixture");
        goto cleanup;
    }
    if (has_psk) {
        error = noise_handshakestate_set_pre_shared_key(
            state, fixture->psk.data, fixture->psk.size);
        if (!expect_noise(fixture->name, "install fixture PSK",
                          error, NOISE_ERROR_NONE))
            goto cleanup;
    }
    error = noise_handshakestate_set_prologue(
        state, fixture->prologue.data, fixture->prologue.size);
    if (!expect_noise(fixture->name, "install fixture prologue",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_handshakestate_start(state);
    if (!expect_noise(fixture->name, "start handshake", error, NOISE_ERROR_NONE))
        goto cleanup;

    *state_out = state;
    state = NULL;
    success = 1;

cleanup:
    if (state != NULL &&
        !expect_noise(fixture->name, "free incomplete handshake",
                      noise_handshakestate_free(state), NOISE_ERROR_NONE))
        success = 0;
    return success;
}

static int create_pair(const noise_fixture_probe_fixture_t *fixture, probe_pair_t *pair)
{
    pair->initiator = NULL;
    pair->responder = NULL;
    if (!configure_state(fixture, &pair->initiator, NOISE_ROLE_INITIATOR) ||
        !configure_state(fixture, &pair->responder, NOISE_ROLE_RESPONDER))
        return 0;
    if (noise_handshakestate_get_action(pair->initiator) != NOISE_ACTION_WRITE_MESSAGE ||
        noise_handshakestate_get_action(pair->responder) != NOISE_ACTION_READ_MESSAGE)
        return fail(fixture->name, "initial actions differ from the fixture pattern");
    return 1;
}

static int free_pair(const char *name, probe_pair_t *pair)
{
    int success = 1;

    if (pair->initiator != NULL &&
        !expect_noise(name, "free initiator",
                      noise_handshakestate_free(pair->initiator), NOISE_ERROR_NONE))
        success = 0;
    if (pair->responder != NULL &&
        !expect_noise(name, "free responder",
                      noise_handshakestate_free(pair->responder), NOISE_ERROR_NONE))
        success = 0;
    pair->initiator = NULL;
    pair->responder = NULL;
    return success;
}

static int write_message(const char *name, NoiseHandshakeState *state,
                         const noise_fixture_probe_flight_t *flight,
                         uint8_t message[PROBE_MESSAGE_CAPACITY], size_t *message_size)
{
    uint8_t empty_input[1] = {0U};
    uint8_t plaintext[PROBE_PLAINTEXT_CAPACITY];
    NoiseBuffer message_buffer;
    NoiseBuffer plaintext_buffer;
    int error;

    if (flight->plaintext.size > sizeof(plaintext) ||
        flight->message.size > PROBE_MESSAGE_CAPACITY)
        return fail(name, "fixture flight exceeds a probe buffer");
    if (flight->plaintext.size != 0U)
        memcpy(plaintext, flight->plaintext.data, flight->plaintext.size);
    noise_buffer_set_output(message_buffer, message, PROBE_MESSAGE_CAPACITY);
    noise_buffer_set_input(plaintext_buffer,
                           flight->plaintext.size != 0U ? plaintext : empty_input,
                           flight->plaintext.size);
    error = noise_handshakestate_write_message(state, &message_buffer, &plaintext_buffer);
    *message_size = message_buffer.size;
    if (!expect_noise(name, "write handshake message", error, NOISE_ERROR_NONE))
        return 0;
    return expect_bytes(name, "exact Noise flight", message_buffer.data,
                        message_buffer.size, flight->message.data, flight->message.size);
}

static int read_message(const char *name, NoiseHandshakeState *state,
                        const noise_fixture_probe_flight_t *flight,
                        const uint8_t *message, size_t message_size)
{
    uint8_t message_copy[PROBE_MESSAGE_CAPACITY];
    uint8_t plaintext[PROBE_PLAINTEXT_CAPACITY];
    NoiseBuffer message_buffer;
    NoiseBuffer plaintext_buffer;
    int error;

    if (message_size > sizeof(message_copy) ||
        flight->plaintext.size > sizeof(plaintext))
        return fail(name, "received fixture flight exceeds a probe buffer");
    memcpy(message_copy, message, message_size);
    noise_buffer_set_input(message_buffer, message_copy, message_size);
    noise_buffer_set_output(plaintext_buffer, plaintext, sizeof(plaintext));
    error = noise_handshakestate_read_message(state, &message_buffer, &plaintext_buffer);
    if (!expect_noise(name, "read authentic Noise flight", error, NOISE_ERROR_NONE))
        return 0;
    return expect_bytes(name, "authenticated Noise plaintext", plaintext_buffer.data,
                        plaintext_buffer.size, flight->plaintext.data,
                        flight->plaintext.size);
}

static int write_and_read_flight(const noise_fixture_probe_fixture_t *fixture,
                                 probe_pair_t *pair, size_t index)
{
    NoiseHandshakeState *sender = (index % 2U == 0U) ? pair->initiator : pair->responder;
    NoiseHandshakeState *receiver = (index % 2U == 0U) ? pair->responder : pair->initiator;
    uint8_t message[PROBE_MESSAGE_CAPACITY];
    size_t message_size = 0U;

    return write_message(fixture->name, sender, &fixture->flights[index],
                         message, &message_size) &&
           read_message(fixture->name, receiver, &fixture->flights[index],
                        message, message_size);
}

static int assert_hash(const noise_fixture_probe_fixture_t *fixture,
                       NoiseHandshakeState *state, const char *role)
{
    uint8_t hash[PROBE_HASH_LENGTH];
    int error = noise_handshakestate_get_handshake_hash(state, hash, sizeof(hash));

    return expect_noise(fixture->name, role, error, NOISE_ERROR_NONE) &&
           expect_bytes(fixture->name, "exact handshake hash", hash, sizeof(hash),
                        fixture->handshake_hash.data, fixture->handshake_hash.size);
}

static int run_to_split(const noise_fixture_probe_fixture_t *fixture, probe_pair_t *pair)
{
    size_t index;

    for (index = 0U; index < fixture->flight_count; ++index) {
        if (!write_and_read_flight(fixture, pair, index))
            return 0;
    }
    if (noise_handshakestate_get_action(pair->initiator) != NOISE_ACTION_SPLIT ||
        noise_handshakestate_get_action(pair->responder) != NOISE_ACTION_SPLIT)
        return fail(fixture->name, "fixture handshake did not reach SPLIT on both peers");
    return assert_hash(fixture, pair->initiator, "get initiator handshake hash") &&
           assert_hash(fixture, pair->responder, "get responder handshake hash");
}

static int encrypt_fixture_packet(const noise_fixture_probe_fixture_t *fixture,
                                  const noise_fixture_probe_packet_t *packet,
                                  NoiseCipherState *send)
{
    uint8_t encrypted[PROBE_AEAD_CAPACITY];
    uint8_t expected[PROBE_AEAD_CAPACITY];
    size_t expected_size;
    NoiseBuffer buffer;
    int error;

    if (packet->key.size != PROBE_KEY_LENGTH || packet->nonce.size != 12U ||
        packet->plaintext.size + packet->tag.size > sizeof(encrypted) ||
        packet->ciphertext.size + packet->tag.size > sizeof(expected) ||
        packet->ciphertext.size != packet->plaintext.size)
        return fail(fixture->name, "Split packet fixture has inconsistent lengths");
    if (packet->plaintext.size != 0U)
        memcpy(encrypted, packet->plaintext.data, packet->plaintext.size);
    noise_buffer_set_inout(buffer, encrypted, packet->plaintext.size, sizeof(encrypted));
    error = noise_cipherstate_set_nonce(send, packet->pn);
    if (!expect_noise(fixture->name, "set Split send nonce", error, NOISE_ERROR_NONE))
        return 0;
    error = noise_cipherstate_encrypt_with_ad(
        send, packet->aad.data, packet->aad.size, &buffer);
    if (!expect_noise(fixture->name, "encrypt Split fixture packet",
                      error, NOISE_ERROR_NONE))
        return 0;

    memcpy(expected, packet->ciphertext.data, packet->ciphertext.size);
    memcpy(expected + packet->ciphertext.size, packet->tag.data, packet->tag.size);
    expected_size = packet->ciphertext.size + packet->tag.size;
    return expect_bytes(fixture->name, "exact Split ciphertext and tag",
                        buffer.data, buffer.size, expected, expected_size);
}

static int decrypt_fixture_packet(const noise_fixture_probe_fixture_t *fixture,
                                  const noise_fixture_probe_packet_t *packet,
                                  NoiseCipherState *receive)
{
    uint8_t encrypted[PROBE_AEAD_CAPACITY];
    size_t encrypted_size;
    NoiseBuffer buffer;
    int error;

    if (packet->key.size != PROBE_KEY_LENGTH || packet->nonce.size != 12U ||
        packet->ciphertext.size + packet->tag.size > sizeof(encrypted))
        return fail(fixture->name, "Split receive fixture has inconsistent lengths");
    memcpy(encrypted, packet->ciphertext.data, packet->ciphertext.size);
    memcpy(encrypted + packet->ciphertext.size, packet->tag.data, packet->tag.size);
    encrypted_size = packet->ciphertext.size + packet->tag.size;
    noise_buffer_set_inout(buffer, encrypted, encrypted_size, sizeof(encrypted));
    error = noise_cipherstate_set_nonce(receive, packet->pn);
    if (!expect_noise(fixture->name, "set Split receive nonce",
                      error, NOISE_ERROR_NONE))
        return 0;
    error = noise_cipherstate_decrypt_with_ad(
        receive, packet->aad.data, packet->aad.size, &buffer);
    if (!expect_noise(fixture->name, "decrypt Split fixture packet",
                      error, NOISE_ERROR_NONE))
        return 0;
    return expect_bytes(fixture->name, "Split packet plaintext", buffer.data,
                        buffer.size, packet->plaintext.data, packet->plaintext.size);
}

static int check_split_packets(const noise_fixture_probe_fixture_t *fixture,
                               probe_pair_t *pair)
{
    NoiseCipherState *init_send = NULL;
    NoiseCipherState *init_receive = NULL;
    NoiseCipherState *resp_send = NULL;
    NoiseCipherState *resp_receive = NULL;
    int success = 0;

    if (!expect_noise(fixture->name, "split initiator",
                      noise_handshakestate_split(pair->initiator,
                                                 &init_send, &init_receive),
                      NOISE_ERROR_NONE) ||
        !expect_noise(fixture->name, "split responder",
                      noise_handshakestate_split(pair->responder,
                                                 &resp_send, &resp_receive),
                      NOISE_ERROR_NONE))
        goto cleanup;
    if (noise_handshakestate_get_action(pair->initiator) != NOISE_ACTION_COMPLETE ||
        noise_handshakestate_get_action(pair->responder) != NOISE_ACTION_COMPLETE) {
        (void)fail(fixture->name, "successful Split did not complete both handshakes");
        goto cleanup;
    }

    /* Exact FINISH/READY encryption verifies the two fixture Split directions. */
    if (!encrypt_fixture_packet(fixture, &fixture->finish, init_send) ||
        !decrypt_fixture_packet(fixture, &fixture->finish, resp_receive) ||
        !encrypt_fixture_packet(fixture, &fixture->ready, resp_send) ||
        !decrypt_fixture_packet(fixture, &fixture->ready, init_receive))
        goto cleanup;
    success = 1;

cleanup:
    if (init_send != NULL &&
        !expect_noise(fixture->name, "free initiator send cipher",
                      noise_cipherstate_free(init_send), NOISE_ERROR_NONE))
        success = 0;
    if (init_receive != NULL &&
        !expect_noise(fixture->name, "free initiator receive cipher",
                      noise_cipherstate_free(init_receive), NOISE_ERROR_NONE))
        success = 0;
    if (resp_send != NULL &&
        !expect_noise(fixture->name, "free responder send cipher",
                      noise_cipherstate_free(resp_send), NOISE_ERROR_NONE))
        success = 0;
    if (resp_receive != NULL &&
        !expect_noise(fixture->name, "free responder receive cipher",
                      noise_cipherstate_free(resp_receive), NOISE_ERROR_NONE))
        success = 0;
    return success;
}

static int assert_failed_action(const char *name, NoiseHandshakeState *state)
{
    return noise_handshakestate_get_action(state) == NOISE_ACTION_FAILED ||
           fail(name, "entropy failure did not put the handshake in FAILED");
}

static int assert_blocked_after_failure(const noise_fixture_probe_fixture_t *fixture,
                                        NoiseHandshakeState *state,
                                        const noise_fixture_probe_flight_t *delayed_flight)
{
    uint8_t message[PROBE_MESSAGE_CAPACITY];
    uint8_t payload[PROBE_PLAINTEXT_CAPACITY];
    uint8_t input[1] = {0U};
    NoiseBuffer message_buffer;
    NoiseBuffer payload_buffer;
    NoiseCipherState *send = NULL;
    NoiseCipherState *receive = NULL;
    size_t size;
    size_t calls_before = probe_rng.calls;
    int error;
    int success = 1;

    /* The hook would succeed now, so a retry cannot be hidden by the fault. */
    probe_rng.fail_on_call = 0U;
    noise_buffer_set_output(message_buffer, message, sizeof(message));
    noise_buffer_set_input(payload_buffer, input, 0U);
    error = noise_handshakestate_write_message(state, &message_buffer, &payload_buffer);
    size = message_buffer.size;
    if (!expect_noise(fixture->name, "write after entropy failure",
                      error, NOISE_ERROR_INVALID_STATE) || size != 0U)
        success = 0;

    memcpy(message, delayed_flight->message.data, delayed_flight->message.size);
    noise_buffer_set_input(message_buffer, message, delayed_flight->message.size);
    noise_buffer_set_output(payload_buffer, payload, sizeof(payload));
    error = noise_handshakestate_read_message(state, &message_buffer, &payload_buffer);
    if (!expect_noise(fixture->name, "read after entropy failure",
                      error, NOISE_ERROR_INVALID_STATE))
        success = 0;

    error = noise_handshakestate_split(state, &send, &receive);
    if (!expect_noise(fixture->name, "split after entropy failure",
                      error, NOISE_ERROR_INVALID_STATE))
        success = 0;
    if (send != NULL || receive != NULL) {
        (void)fail(fixture->name, "failed handshake unexpectedly returned Split state");
        success = 0;
    }
    if (!assert_failed_action(fixture->name, state))
        success = 0;
    if (probe_rng.calls != calls_before) {
        (void)fail(fixture->name, "blocked failed-state operations called the RNG hook");
        success = 0;
    }
    return success;
}

static int expect_entropy_write_failure(const noise_fixture_probe_fixture_t *fixture,
                                        NoiseHandshakeState *state,
                                        const noise_fixture_probe_flight_t *flight,
                                        const char *operation)
{
    uint8_t message[PROBE_MESSAGE_CAPACITY];
    uint8_t empty[1] = {0U};
    uint8_t plaintext[PROBE_PLAINTEXT_CAPACITY];
    NoiseBuffer message_buffer;
    NoiseBuffer plaintext_buffer;
    int error;

    memset(message, 0xD2, sizeof(message));
    if (flight->plaintext.size > sizeof(plaintext))
        return fail(fixture->name, "failed flight plaintext exceeds probe capacity");
    if (flight->plaintext.size != 0U)
        memcpy(plaintext, flight->plaintext.data, flight->plaintext.size);
    noise_buffer_set_output(message_buffer, message, sizeof(message));
    noise_buffer_set_input(plaintext_buffer,
                           flight->plaintext.size != 0U ? plaintext : empty,
                           flight->plaintext.size);
    error = noise_handshakestate_write_message(state, &message_buffer, &plaintext_buffer);
    if (!expect_noise(fixture->name, operation, error, probe_rng.failure_error))
        return 0;
    if (message_buffer.size != 0U)
        return fail(fixture->name, "failed Noise write published a nonempty message");
    if (!assert_failed_action(fixture->name, state))
        return 0;
    return assert_ephemeral_cleared(fixture->name, state);
}

static int test_initiator_first_write_failure(
    const noise_fixture_probe_fixture_t *fixture)
{
    probe_pair_t pair = {NULL, NULL};
    int success = 0;

    reset_rng(fixture);
    probe_rng.fail_on_call = 1U;
    probe_rng.partial_bytes = 7U;
    if (!create_pair(fixture, &pair))
        goto cleanup;
    if (!expect_entropy_write_failure(fixture, pair.initiator,
                                      &fixture->flights[0],
                                      "first initiator write on partial entropy"))
        goto cleanup;
    if (probe_rng.calls != 1U || probe_rng.requested_sizes[0] != PROBE_KEY_LENGTH ||
        probe_rng.fixture_key_index != 0U) {
        (void)fail(fixture->name, "first-write fault did not stop at one 32-byte RNG call");
        goto cleanup;
    }
    if (!assert_unseeded_ephemeral(fixture->name, pair.responder) ||
        !assert_blocked_after_failure(fixture, pair.initiator, &fixture->flights[1]))
        goto cleanup;
    success = 1;

cleanup:
    if (!free_pair(fixture->name, &pair))
        success = 0;
    return success;
}

static int test_responder_second_write_failure(
    const noise_fixture_probe_fixture_t *fixture)
{
    probe_pair_t pair = {NULL, NULL};
    uint8_t first_message[PROBE_MESSAGE_CAPACITY];
    size_t first_message_size = 0U;
    int success = 0;

    reset_rng(fixture);
    probe_rng.fail_on_call = 2U;
    probe_rng.partial_bytes = 11U;
    if (!create_pair(fixture, &pair))
        goto cleanup;

    if (!write_message(fixture->name, pair.initiator, &fixture->flights[0],
                       first_message, &first_message_size) ||
        !read_message(fixture->name, pair.responder, &fixture->flights[0],
                      first_message, first_message_size))
        goto cleanup;
    if (probe_rng.calls != 1U || probe_rng.requested_sizes[0] != PROBE_KEY_LENGTH ||
        probe_rng.fixture_key_index != 1U ||
        !assert_unseeded_ephemeral(fixture->name, pair.responder)) {
        (void)fail(fixture->name, "authentic first read did not precede responder entropy");
        goto cleanup;
    }
    if (!expect_entropy_write_failure(fixture, pair.responder,
                                      &fixture->flights[1],
                                      "second responder write on partial entropy"))
        goto cleanup;
    if (probe_rng.calls != 2U || probe_rng.requested_sizes[1] != PROBE_KEY_LENGTH ||
        probe_rng.fixture_key_index != 1U) {
        (void)fail(fixture->name, "second-write fault did not stop at the responder RNG call");
        goto cleanup;
    }
    if (!assert_blocked_after_failure(
            fixture, pair.responder,
            &fixture->flights[fixture->flight_count > 2U ? 2U : 0U]))
        goto cleanup;
    success = 1;

cleanup:
    if (!free_pair(fixture->name, &pair))
        success = 0;
    return success;
}

static int test_fresh_fixture_success(
    const noise_fixture_probe_fixture_t *fixture)
{
    probe_pair_t pair = {NULL, NULL};
    int success = 0;

    reset_rng(fixture);
    if (!create_pair(fixture, &pair) || !run_to_split(fixture, &pair))
        goto cleanup;
    if (probe_rng.calls != 2U || probe_rng.requested_sizes[0] != PROBE_KEY_LENGTH ||
        probe_rng.requested_sizes[1] != PROBE_KEY_LENGTH ||
        probe_rng.fixture_key_index != 2U) {
        (void)fail(fixture->name, "fresh handshake did not consume both fixture ephemerals");
        goto cleanup;
    }
    if (!check_split_packets(fixture, &pair))
        goto cleanup;
    success = 1;

cleanup:
    if (!free_pair(fixture->name, &pair))
        success = 0;
    return success;
}

static int test_isolated_attempt_failure(
    const noise_fixture_probe_fixture_t *fixture)
{
    probe_pair_t valid_pair = {NULL, NULL};
    probe_pair_t failed_pair = {NULL, NULL};
    int success = 0;

    reset_rng(fixture);
    if (!create_pair(fixture, &valid_pair) || !run_to_split(fixture, &valid_pair))
        goto cleanup;
    if (probe_rng.calls != 2U || probe_rng.fixture_key_index != 2U) {
        (void)fail(fixture->name, "reference handshake did not reach the isolated-fault point");
        goto cleanup;
    }

    probe_rng.fail_on_call = 3U;
    probe_rng.partial_bytes = 9U;
    if (!create_pair(fixture, &failed_pair) ||
        !expect_entropy_write_failure(fixture, failed_pair.initiator,
                                      &fixture->flights[0],
                                      "separate attempt partial-entropy write"))
        goto cleanup;
    if (probe_rng.calls != 3U || probe_rng.requested_sizes[2] != PROBE_KEY_LENGTH ||
        noise_handshakestate_get_action(valid_pair.initiator) != NOISE_ACTION_SPLIT ||
        noise_handshakestate_get_action(valid_pair.responder) != NOISE_ACTION_SPLIT) {
        (void)fail(fixture->name, "separate attempt fault changed the valid handshake");
        goto cleanup;
    }
    if (!assert_blocked_after_failure(fixture, failed_pair.initiator,
                                      &fixture->flights[1]) ||
        !check_split_packets(fixture, &valid_pair))
        goto cleanup;
    success = 1;

cleanup:
    if (!free_pair(fixture->name, &failed_pair))
        success = 0;
    if (!free_pair(fixture->name, &valid_pair))
        success = 0;
    return success;
}

int main(void)
{
    size_t index;

    if (!expect_noise("Noise RNG handshake probe", "initialize Noise framework",
                      noise_init_framework(), NOISE_ERROR_NONE))
        return 1;

    /* sodium_init may stir its backend RNG; this probe begins after initialization. */
    for (index = 0U; index < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++index) {
        const noise_fixture_probe_fixture_t *fixture = &noise_fixture_probe_fixtures[index];

        if (!test_initiator_first_write_failure(fixture) ||
            !test_responder_second_write_failure(fixture) ||
            !test_fresh_fixture_success(fixture))
            return 1;
        printf("%s: partial entropy aborts both write positions; fresh fixture handshake passes\n",
               fixture->name);
    }

    if (!test_isolated_attempt_failure(&noise_fixture_probe_fixtures[0]))
        return 1;
    puts("Separate attempt entropy failure left an established fixture handshake usable. Test hook does not establish production entropy quality or a DMP restart scheduler.");
    return 0;
}
