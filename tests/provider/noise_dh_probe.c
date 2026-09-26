/* Host probe for strict X25519 rejection through the Noise handshake engine. */
#include <noise/protocol.h>

#include "noise_fixture_probe.h"
#include "protocol/internal.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PROBE_MESSAGE_CAPACITY 512U
#define PROBE_PLAINTEXT_CAPACITY 128U
#define PROBE_KEY_LENGTH 32U

typedef struct {
    NoiseHandshakeState *initiator;
    NoiseHandshakeState *responder;
} probe_pair_t;

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

static int raw_write(NoiseHandshakeState *state,
                     const uint8_t *plaintext, size_t plaintext_size,
                     uint8_t message[PROBE_MESSAGE_CAPACITY], size_t *message_size)
{
    NoiseBuffer message_buffer;
    NoiseBuffer plaintext_buffer;
    uint8_t plaintext_copy[PROBE_PLAINTEXT_CAPACITY] = {0};
    int error;

    if (plaintext_size > PROBE_PLAINTEXT_CAPACITY)
        return NOISE_ERROR_INVALID_LENGTH;
    if (plaintext_size != 0U) {
        if (plaintext == NULL)
            return NOISE_ERROR_INVALID_PARAM;
        memcpy(plaintext_copy, plaintext, plaintext_size);
    }
    noise_buffer_set_output(message_buffer, message, PROBE_MESSAGE_CAPACITY);
    noise_buffer_set_input(plaintext_buffer,
                           plaintext_copy,
                           plaintext_size);
    error = noise_handshakestate_write_message(state, &message_buffer, &plaintext_buffer);
    *message_size = message_buffer.size;
    return error;
}

static int raw_read(NoiseHandshakeState *state,
                    const uint8_t *message, size_t message_size)
{
    uint8_t message_copy[PROBE_MESSAGE_CAPACITY];
    uint8_t plaintext[PROBE_PLAINTEXT_CAPACITY];
    NoiseBuffer message_buffer;
    NoiseBuffer plaintext_buffer;

    if (message_size > sizeof(message_copy))
        return NOISE_ERROR_INVALID_LENGTH;
    memcpy(message_copy, message, message_size);
    noise_buffer_set_input(message_buffer, message_copy, message_size);
    noise_buffer_set_output(plaintext_buffer, plaintext, sizeof(plaintext));
    return noise_handshakestate_read_message(state, &message_buffer, &plaintext_buffer);
}

static int derive_public_key(const char *fixture,
                             noise_fixture_probe_bytes_t private_key,
                             uint8_t public_key[PROBE_KEY_LENGTH])
{
    NoiseDHState *dh = NULL;
    int error;
    int success = 0;

    error = noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519);
    if (!expect_noise(fixture, "new temporary Curve25519 state", error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_dhstate_set_keypair_private(dh, private_key.data, private_key.size);
    if (!expect_noise(fixture, "set temporary Curve25519 private key",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_dhstate_get_public_key(dh, public_key, PROBE_KEY_LENGTH);
    if (!expect_noise(fixture, "derive temporary Curve25519 public key",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    success = 1;

cleanup:
    if (dh != NULL &&
        !expect_noise(fixture, "free temporary Curve25519 state",
                      noise_dhstate_free(dh), NOISE_ERROR_NONE))
        success = 0;
    return success;
}

static int configure_state(const noise_fixture_probe_fixture_t *fixture,
                           NoiseHandshakeState **state_out, int role)
{
    noise_fixture_probe_bytes_t ephemeral;
    noise_fixture_probe_bytes_t static_key;
    uint8_t ephemeral_public[PROBE_KEY_LENGTH];
    NoiseHandshakeState *state = NULL;
    NoiseDHState *local_static;
    const bool has_static = fixture->init_static.size != 0U;
    const bool has_psk = fixture->psk.size != 0U;
    int error;
    int success = 0;

    *state_out = NULL;
    if (role == NOISE_ROLE_INITIATOR) {
        ephemeral = fixture->init_ephemeral;
        static_key = fixture->init_static;
    } else {
        ephemeral = fixture->resp_ephemeral;
        static_key = fixture->resp_static;
    }

    error = noise_handshakestate_new_by_name(&state, fixture->protocol_name, role);
    if (!expect_noise(fixture->name, "new handshake state", error, NOISE_ERROR_NONE))
        goto cleanup;
    if (!derive_public_key(fixture->name, ephemeral, ephemeral_public))
        goto cleanup;
    error = noise_handshakestate_set_local_ephemeral(
        state, ephemeral.data, ephemeral.size, ephemeral_public, sizeof(ephemeral_public));
    if (!expect_noise(fixture->name, "set deterministic local ephemeral",
                      error, NOISE_ERROR_NONE))
        goto cleanup;

    local_static = noise_handshakestate_get_local_keypair_dh(state);
    if (has_static) {
        if (local_static == NULL) {
            (void)fail(fixture->name, "XX state has no local static-key object");
            goto cleanup;
        }
        error = noise_dhstate_set_keypair_private(
            local_static, static_key.data, static_key.size);
        if (!expect_noise(fixture->name, "set deterministic local static key",
                          error, NOISE_ERROR_NONE))
            goto cleanup;
    } else if (local_static != NULL) {
        (void)fail(fixture->name, "NNpsk0 state unexpectedly has a local static key");
        goto cleanup;
    }

    if ((noise_handshakestate_needs_pre_shared_key(state) != 0) != has_psk) {
        (void)fail(fixture->name, "handshake PSK requirement differs from its fixture");
        goto cleanup;
    }
    if (has_psk) {
        error = noise_handshakestate_set_pre_shared_key(
            state, fixture->psk.data, fixture->psk.size);
        if (!expect_noise(fixture->name, "set deterministic PSK",
                          error, NOISE_ERROR_NONE))
            goto cleanup;
    }
    error = noise_handshakestate_set_prologue(
        state, fixture->prologue.data, fixture->prologue.size);
    if (!expect_noise(fixture->name, "set exact fixture prologue",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_handshakestate_start(state);
    if (!expect_noise(fixture->name, "start handshake state", error, NOISE_ERROR_NONE))
        goto cleanup;

    *state_out = state;
    state = NULL;
    success = 1;

cleanup:
    if (state != NULL &&
        !expect_noise(fixture->name, "free incomplete handshake state",
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
        return fail(fixture->name, "initial handshake actions differ from the fixture pattern");
    return 1;
}

static int free_pair(const char *fixture, probe_pair_t *pair)
{
    int success = 1;

    if (pair->initiator != NULL) {
        if (!expect_noise(fixture, "free initiator handshake",
                          noise_handshakestate_free(pair->initiator), NOISE_ERROR_NONE))
            success = 0;
        pair->initiator = NULL;
    }
    if (pair->responder != NULL) {
        if (!expect_noise(fixture, "free responder handshake",
                          noise_handshakestate_free(pair->responder), NOISE_ERROR_NONE))
            success = 0;
        pair->responder = NULL;
    }
    return success;
}

static int write_fixture_flight(const noise_fixture_probe_fixture_t *fixture,
                                NoiseHandshakeState *sender,
                                const noise_fixture_probe_flight_t *flight,
                                uint8_t message[PROBE_MESSAGE_CAPACITY],
                                size_t *message_size)
{
    int error = raw_write(sender, flight->plaintext.data, flight->plaintext.size,
                          message, message_size);
    if (!expect_noise(fixture->name, "write deterministic fixture flight",
                      error, NOISE_ERROR_NONE))
        return 0;
    return expect_bytes(fixture->name, "deterministic flight bytes",
                        message, *message_size,
                        flight->message.data, flight->message.size);
}

static int read_fixture_flight(const noise_fixture_probe_fixture_t *fixture,
                               NoiseHandshakeState *receiver,
                               const noise_fixture_probe_flight_t *flight,
                               const uint8_t *message, size_t message_size)
{
    uint8_t message_copy[PROBE_MESSAGE_CAPACITY];
    uint8_t plaintext[PROBE_PLAINTEXT_CAPACITY];
    NoiseBuffer message_buffer;
    NoiseBuffer plaintext_buffer;
    int error;

    if (message_size > sizeof(message_copy) || flight->plaintext.size > sizeof(plaintext))
        return fail(fixture->name, "fixture flight exceeds a probe buffer");
    memcpy(message_copy, message, message_size);
    noise_buffer_set_input(message_buffer, message_copy, message_size);
    noise_buffer_set_output(plaintext_buffer, plaintext, sizeof(plaintext));
    error = noise_handshakestate_read_message(receiver, &message_buffer, &plaintext_buffer);
    if (!expect_noise(fixture->name, "read deterministic fixture flight",
                      error, NOISE_ERROR_NONE))
        return 0;
    return expect_bytes(fixture->name, "fixture flight plaintext",
                        plaintext_buffer.data, plaintext_buffer.size,
                        flight->plaintext.data, flight->plaintext.size);
}

static int transfer_fixture_flight(const noise_fixture_probe_fixture_t *fixture,
                                   probe_pair_t *pair, size_t index)
{
    NoiseHandshakeState *sender = (index % 2U == 0U) ? pair->initiator : pair->responder;
    NoiseHandshakeState *receiver = (index % 2U == 0U) ? pair->responder : pair->initiator;
    uint8_t message[PROBE_MESSAGE_CAPACITY];
    size_t message_size = 0U;

    return write_fixture_flight(fixture, sender, &fixture->flights[index],
                                message, &message_size) &&
           read_fixture_flight(fixture, receiver, &fixture->flights[index],
                               message, message_size);
}

static int run_valid_fixture_handshake(const noise_fixture_probe_fixture_t *fixture)
{
    probe_pair_t pair;
    uint8_t initiator_hash[PROBE_KEY_LENGTH];
    uint8_t responder_hash[PROBE_KEY_LENGTH];
    NoiseCipherState *i_send = NULL;
    NoiseCipherState *i_receive = NULL;
    NoiseCipherState *r_send = NULL;
    NoiseCipherState *r_receive = NULL;
    size_t index;
    int success = 0;
    int error;

    memset(&pair, 0, sizeof(pair));
    if (!create_pair(fixture, &pair))
        goto cleanup;
    for (index = 0U; index < fixture->flight_count; ++index) {
        if (!transfer_fixture_flight(fixture, &pair, index))
            goto cleanup;
    }
    error = noise_handshakestate_get_handshake_hash(
        pair.initiator, initiator_hash, sizeof(initiator_hash));
    if (!expect_noise(fixture->name, "read initiator handshake hash",
                      error, NOISE_ERROR_NONE) ||
        !expect_bytes(fixture->name, "initiator handshake hash",
                      initiator_hash, sizeof(initiator_hash),
                      fixture->handshake_hash.data, fixture->handshake_hash.size))
        goto cleanup;
    error = noise_handshakestate_get_handshake_hash(
        pair.responder, responder_hash, sizeof(responder_hash));
    if (!expect_noise(fixture->name, "read responder handshake hash",
                      error, NOISE_ERROR_NONE) ||
        !expect_bytes(fixture->name, "responder handshake hash",
                      responder_hash, sizeof(responder_hash),
                      fixture->handshake_hash.data, fixture->handshake_hash.size))
        goto cleanup;

    error = noise_handshakestate_split(pair.initiator, &i_send, &i_receive);
    if (!expect_noise(fixture->name, "split valid initiator handshake",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_handshakestate_split(pair.responder, &r_send, &r_receive);
    if (!expect_noise(fixture->name, "split valid responder handshake",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    success = 1;

cleanup:
    if (i_send != NULL && noise_cipherstate_free(i_send) != NOISE_ERROR_NONE)
        success = 0;
    if (i_receive != NULL && noise_cipherstate_free(i_receive) != NOISE_ERROR_NONE)
        success = 0;
    if (r_send != NULL && noise_cipherstate_free(r_send) != NOISE_ERROR_NONE)
        success = 0;
    if (r_receive != NULL && noise_cipherstate_free(r_receive) != NOISE_ERROR_NONE)
        success = 0;
    if (!free_pair(fixture->name, &pair))
        success = 0;
    return success;
}

static int assert_failed_action(const char *fixture, NoiseHandshakeState *state)
{
    if (noise_handshakestate_get_action(state) != NOISE_ACTION_FAILED)
        return fail(fixture, "handshake did not enter the FAILED action");
    return 1;
}

static int assert_failed_split(const char *fixture, NoiseHandshakeState *state)
{
    NoiseCipherState *send = NULL;
    NoiseCipherState *receive = NULL;
    int error = noise_handshakestate_split(state, &send, &receive);
    int success = expect_noise(fixture, "split FAILED handshake",
                               error, NOISE_ERROR_INVALID_STATE);

    if (send != NULL && noise_cipherstate_free(send) != NOISE_ERROR_NONE)
        success = 0;
    if (receive != NULL && noise_cipherstate_free(receive) != NOISE_ERROR_NONE)
        success = 0;
    return success;
}

static int assert_delayed_flight_rejected(const char *fixture,
                                          NoiseHandshakeState *failed_state,
                                          const noise_fixture_probe_flight_t *delayed)
{
    int error = raw_read(failed_state, delayed->message.data, delayed->message.size);

    return expect_noise(fixture, "read delayed valid flight after failure",
                        error, NOISE_ERROR_INVALID_STATE) &&
           assert_failed_action(fixture, failed_state);
}

static int assert_delayed_write_rejected(const char *fixture,
                                         NoiseHandshakeState *failed_state,
                                         const noise_fixture_probe_flight_t *delayed)
{
    uint8_t message[PROBE_MESSAGE_CAPACITY];
    size_t message_size = 0U;
    int error = raw_write(failed_state, delayed->plaintext.data,
                          delayed->plaintext.size, message, &message_size);

    return expect_noise(fixture, "write delayed valid continuation after failure",
                        error, NOISE_ERROR_INVALID_STATE) &&
           message_size == 0U && assert_failed_action(fixture, failed_state);
}

static int test_direct_low_order_inputs(const noise_fixture_probe_fixture_t *fixture)
{
    static const char *const names[] = {
        "u=0", "u=1", "u=0 with high-bit alias", "u=1 with high-bit alias"
    };
    uint8_t low_order[4][PROBE_KEY_LENGTH] = {{0}};
    uint8_t shared[PROBE_KEY_LENGTH];
    NoiseDHState *private_state = NULL;
    NoiseDHState *public_state = NULL;
    size_t vector_index;
    int error;
    int success = 0;

    low_order[1][0] = 1U;
    low_order[2][PROBE_KEY_LENGTH - 1U] = 0x80U;
    low_order[3][0] = 1U;
    low_order[3][PROBE_KEY_LENGTH - 1U] = 0x80U;
    error = noise_dhstate_new_by_id(&private_state, NOISE_DH_CURVE25519);
    if (!expect_noise(fixture->name, "new direct DH private state",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_dhstate_new_by_id(&public_state, NOISE_DH_CURVE25519);
    if (!expect_noise(fixture->name, "new direct DH public state",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_dhstate_set_keypair_private(
        private_state, fixture->init_ephemeral.data, fixture->init_ephemeral.size);
    if (!expect_noise(fixture->name, "install direct DH private key",
                      error, NOISE_ERROR_NONE))
        goto cleanup;

    for (vector_index = 0U; vector_index < 4U; ++vector_index) {
        error = noise_dhstate_set_public_key(
            public_state, low_order[vector_index], PROBE_KEY_LENGTH);
        if (!expect_noise(fixture->name, names[vector_index], error, NOISE_ERROR_NONE))
            goto cleanup;
        memset(shared, 0xA5, sizeof(shared));
        error = noise_dhstate_calculate(
            private_state, public_state, shared, sizeof(shared));
        if (!expect_noise(fixture->name, names[vector_index],
                          error, NOISE_ERROR_INVALID_PARAM))
            goto cleanup;
        if (!expect_bytes(fixture->name, "failed X25519 output clearing",
                          shared, sizeof(shared), low_order[0], sizeof(shared)))
            goto cleanup;
    }
    success = 1;

cleanup:
    if (public_state != NULL &&
        !expect_noise(fixture->name, "free direct DH public state",
                      noise_dhstate_free(public_state), NOISE_ERROR_NONE))
        success = 0;
    if (private_state != NULL &&
        !expect_noise(fixture->name, "free direct DH private state",
                      noise_dhstate_free(private_state), NOISE_ERROR_NONE))
        success = 0;
    return success;
}

static int test_standard_x25519_decoding(const noise_fixture_probe_fixture_t *fixture)
{
    uint8_t basepoint[PROBE_KEY_LENGTH] = {9U};
    uint8_t high_bit_alias[PROBE_KEY_LENGTH] = {9U};
    uint8_t noncanonical_alias[PROBE_KEY_LENGTH];
    uint8_t expected[PROBE_KEY_LENGTH];
    uint8_t actual[PROBE_KEY_LENGTH];
    NoiseDHState *private_state = NULL;
    NoiseDHState *public_state = NULL;
    int error;
    int success = 0;

    high_bit_alias[PROBE_KEY_LENGTH - 1U] = 0x80U;
    memset(noncanonical_alias, 0xFF, sizeof(noncanonical_alias));
    noncanonical_alias[0] = 0xF6U;
    noncanonical_alias[PROBE_KEY_LENGTH - 1U] = 0x7FU;
    error = noise_dhstate_new_by_id(&private_state, NOISE_DH_CURVE25519);
    if (!expect_noise(fixture->name, "new decoding-test private state",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_dhstate_new_by_id(&public_state, NOISE_DH_CURVE25519);
    if (!expect_noise(fixture->name, "new decoding-test public state",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_dhstate_set_keypair_private(
        private_state, fixture->init_ephemeral.data, fixture->init_ephemeral.size);
    if (!expect_noise(fixture->name, "install decoding-test private key",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_dhstate_set_public_key(public_state, basepoint, sizeof(basepoint));
    if (!expect_noise(fixture->name, "set canonical X25519 point",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_dhstate_calculate(private_state, public_state, expected, sizeof(expected));
    if (!expect_noise(fixture->name, "calculate canonical X25519 point",
                      error, NOISE_ERROR_NONE))
        goto cleanup;

    error = noise_dhstate_set_public_key(
        public_state, high_bit_alias, sizeof(high_bit_alias));
    if (!expect_noise(fixture->name, "set X25519 high-bit alias",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_dhstate_calculate(private_state, public_state, actual, sizeof(actual));
    if (!expect_noise(fixture->name, "calculate X25519 high-bit alias",
                      error, NOISE_ERROR_NONE) ||
        !expect_bytes(fixture->name, "high-bit alias shared value",
                      actual, sizeof(actual), expected, sizeof(expected)))
        goto cleanup;

    error = noise_dhstate_set_public_key(
        public_state, noncanonical_alias, sizeof(noncanonical_alias));
    if (!expect_noise(fixture->name, "set noncanonical X25519 alias",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_dhstate_calculate(private_state, public_state, actual, sizeof(actual));
    if (!expect_noise(fixture->name, "calculate noncanonical X25519 alias",
                      error, NOISE_ERROR_NONE) ||
        !expect_bytes(fixture->name, "noncanonical alias shared value",
                      actual, sizeof(actual), expected, sizeof(expected)))
        goto cleanup;
    success = 1;

cleanup:
    if (public_state != NULL &&
        !expect_noise(fixture->name, "free decoding-test public state",
                      noise_dhstate_free(public_state), NOISE_ERROR_NONE))
        success = 0;
    if (private_state != NULL &&
        !expect_noise(fixture->name, "free decoding-test private state",
                      noise_dhstate_free(private_state), NOISE_ERROR_NONE))
        success = 0;
    return success;
}

static void force_local_ephemeral_public(NoiseHandshakeState *state,
                                         const uint8_t public_key[PROBE_KEY_LENGTH])
{
    /* Test-only attacker construction: keep the private scalar, replace the advertised e. */
    memcpy(state->dh_local_ephemeral->public_key, public_key, PROBE_KEY_LENGTH);
}

static void force_local_static_public(NoiseHandshakeState *state,
                                      const uint8_t public_key[PROBE_KEY_LENGTH])
{
    /* Test-only attacker construction: s is inconsistent with its retained private scalar. */
    memcpy(state->dh_local_static->public_key, public_key, PROBE_KEY_LENGTH);
}

static int assert_actual_dh_rejection(const char *fixture,
                                      const NoiseDHState *private_state,
                                      const NoiseDHState *public_state)
{
    uint8_t shared[PROBE_KEY_LENGTH];
    int error;

    memset(shared, 0xA5, sizeof(shared));
    error = noise_dhstate_calculate(private_state, public_state, shared, sizeof(shared));
    return expect_noise(fixture, "real Noise Curve25519 DH backend rejection",
                        error, NOISE_ERROR_INVALID_PARAM);
}

static int test_nnpsk0_zero_ephemeral_is_early_reject(
    const noise_fixture_probe_fixture_t *fixture)
{
    uint8_t zero[PROBE_KEY_LENGTH] = {0};
    uint8_t message[PROBE_MESSAGE_CAPACITY];
    size_t message_size = 0U;
    probe_pair_t pair;
    int error;
    int success = 0;

    memset(&pair, 0, sizeof(pair));
    if (!create_pair(fixture, &pair))
        goto cleanup;
    force_local_ephemeral_public(pair.initiator, zero);
    error = raw_write(pair.initiator, NULL, 0U, message, &message_size);
    if (!expect_noise(fixture->name, "write literal-zero-e test flight",
                      error, NOISE_ERROR_NONE) ||
        message_size != fixture->flights[0].message.size) {
        (void)fail(fixture->name, "literal-zero-e test flight has an unexpected length");
        goto cleanup;
    }
    error = raw_read(pair.responder, message, message_size);
    if (!expect_noise(fixture->name, "read literal-zero-e flight before DH",
                      error, NOISE_ERROR_INVALID_PUBLIC_KEY) ||
        !assert_failed_action(fixture->name, pair.responder))
        goto cleanup;
    if (!assert_delayed_flight_rejected(
            fixture->name, pair.responder, &fixture->flights[0]) ||
        !assert_delayed_write_rejected(
            fixture->name, pair.responder, &fixture->flights[1]) ||
        !assert_failed_split(fixture->name, pair.responder))
        goto cleanup;
    success = 1;

cleanup:
    if (!free_pair(fixture->name, &pair))
        success = 0;
    return success;
}

static int test_nnpsk0_low_order_ephemeral_reaches_write_dh(
    const noise_fixture_probe_fixture_t *fixture)
{
    uint8_t low_order[PROBE_KEY_LENGTH] = {1U};
    uint8_t message[PROBE_MESSAGE_CAPACITY];
    uint8_t response[PROBE_MESSAGE_CAPACITY];
    size_t message_size = 0U;
    size_t response_size = 0U;
    probe_pair_t pair;
    int error;
    int success = 0;

    memset(&pair, 0, sizeof(pair));
    if (!create_pair(fixture, &pair))
        goto cleanup;
    force_local_ephemeral_public(pair.initiator, low_order);
    error = raw_write(pair.initiator, NULL, 0U, message, &message_size);
    if (!expect_noise(fixture->name, "write authenticated NNpsk0 u=1 flight",
                      error, NOISE_ERROR_NONE))
        goto cleanup;
    error = raw_read(pair.responder, message, message_size);
    if (!expect_noise(fixture->name, "read authenticated NNpsk0 u=1 flight",
                      error, NOISE_ERROR_NONE) ||
        noise_handshakestate_get_action(pair.responder) != NOISE_ACTION_WRITE_MESSAGE)
        goto cleanup;

    if (!assert_actual_dh_rejection(fixture->name,
                                    pair.responder->dh_local_ephemeral,
                                    pair.responder->dh_remote_ephemeral))
        goto cleanup;
    error = raw_write(pair.responder, NULL, 0U, response, &response_size);
    if (!expect_noise(fixture->name, "responder write after NNpsk0 u=1 e",
                      error, NOISE_ERROR_INVALID_PARAM) ||
        response_size != 0U || !assert_failed_action(fixture->name, pair.responder))
        goto cleanup;
    if (!assert_delayed_flight_rejected(
            fixture->name, pair.responder, &fixture->flights[0]) ||
        !assert_delayed_write_rejected(
            fixture->name, pair.responder, &fixture->flights[1]) ||
        !assert_failed_split(fixture->name, pair.responder))
        goto cleanup;
    success = 1;

cleanup:
    if (!free_pair(fixture->name, &pair))
        success = 0;
    return success;
}

static int test_xx_low_order_ephemeral_reaches_read_dh(
    const noise_fixture_probe_fixture_t *fixture)
{
    uint8_t low_order[PROBE_KEY_LENGTH] = {1U};
    uint8_t message[PROBE_MESSAGE_CAPACITY];
    size_t message_size = 0U;
    probe_pair_t pair;
    int error;
    int success = 0;

    memset(&pair, 0, sizeof(pair));
    if (!create_pair(fixture, &pair) || !transfer_fixture_flight(fixture, &pair, 0U))
        goto cleanup;
    error = raw_write(pair.responder, fixture->flights[1].plaintext.data,
                      fixture->flights[1].plaintext.size, message, &message_size);
    if (!expect_noise(fixture->name, "write XX responder flight before e substitution",
                      error, NOISE_ERROR_NONE) || message_size < PROBE_KEY_LENGTH)
        goto cleanup;

    /* e is cleartext; the real initiator must reject u=1 during EE before reading ciphertext. */
    memcpy(message, low_order, PROBE_KEY_LENGTH);
    error = raw_read(pair.initiator, message, message_size);
    if (!expect_noise(fixture->name, "initiator read XX u=1 responder e",
                      error, NOISE_ERROR_INVALID_PARAM) ||
        !assert_failed_action(fixture->name, pair.initiator) ||
        !expect_bytes(fixture->name, "decoded remote XX ephemeral",
                      pair.initiator->dh_remote_ephemeral->public_key, PROBE_KEY_LENGTH,
                      low_order, sizeof(low_order)) ||
        !assert_actual_dh_rejection(fixture->name,
                                    pair.initiator->dh_local_ephemeral,
                                    pair.initiator->dh_remote_ephemeral))
        goto cleanup;
    if (!assert_delayed_flight_rejected(
            fixture->name, pair.initiator, &fixture->flights[1]) ||
        !assert_delayed_write_rejected(
            fixture->name, pair.initiator, &fixture->flights[2]) ||
        !assert_failed_split(fixture->name, pair.initiator))
        goto cleanup;
    success = 1;

cleanup:
    if (!free_pair(fixture->name, &pair))
        success = 0;
    return success;
}

static int assert_decoded_static_and_dh_failure(
    const char *fixture, NoiseHandshakeState *receiver,
    const uint8_t expected_static[PROBE_KEY_LENGTH])
{
    NoiseDHState *remote_static = noise_handshakestate_get_remote_public_key_dh(receiver);
    uint8_t decoded[PROBE_KEY_LENGTH];
    int error;

    if (remote_static == NULL)
        return fail(fixture, "receiver has no decoded remote static-key state");
    error = noise_dhstate_get_public_key(remote_static, decoded, sizeof(decoded));
    if (!expect_noise(fixture, "read authenticated remote static key",
                      error, NOISE_ERROR_NONE) ||
        !expect_bytes(fixture, "authenticated decoded static key",
                      decoded, sizeof(decoded), expected_static, PROBE_KEY_LENGTH))
        return 0;
    return assert_actual_dh_rejection(fixture,
                                      receiver->dh_local_ephemeral, remote_static);
}

static int test_xx_low_order_static(
    const noise_fixture_probe_fixture_t *fixture, int sender_role, size_t flight_index,
    const uint8_t low_order[PROBE_KEY_LENGTH], const char *case_name)
{
    uint8_t message[PROBE_MESSAGE_CAPACITY];
    size_t message_size = 0U;
    NoiseHandshakeState *sender;
    NoiseHandshakeState *receiver;
    probe_pair_t pair;
    size_t prefix_index;
    int error;
    int success = 0;

    memset(&pair, 0, sizeof(pair));
    if (!create_pair(fixture, &pair))
        goto cleanup;
    for (prefix_index = 0U; prefix_index < flight_index; ++prefix_index) {
        if (!transfer_fixture_flight(fixture, &pair, prefix_index))
            goto cleanup;
    }
    sender = (sender_role == NOISE_ROLE_INITIATOR) ? pair.initiator : pair.responder;
    receiver = (sender_role == NOISE_ROLE_INITIATOR) ? pair.responder : pair.initiator;
    if (sender->dh_local_static == NULL) {
        (void)fail(fixture->name, "XX malicious sender has no local static-key state");
        goto cleanup;
    }

    force_local_static_public(sender, low_order);
    error = raw_write(sender, fixture->flights[flight_index].plaintext.data,
                      fixture->flights[flight_index].plaintext.size,
                      message, &message_size);
    if (!expect_noise(case_name,
                      "write authentic XX flight carrying a low-order encrypted s",
                      error, NOISE_ERROR_NONE) ||
        message_size != fixture->flights[flight_index].message.size)
        goto cleanup;

    /* Sender used its real Noise state and valid private scalar. Only the advertised s is low-order. */
    error = raw_read(receiver, message, message_size);
    if (!expect_noise(case_name, "read authenticated XX low-order s flight",
                      error, NOISE_ERROR_INVALID_PARAM) ||
        !assert_failed_action(case_name, receiver) ||
        !assert_decoded_static_and_dh_failure(case_name, receiver, low_order))
        goto cleanup;

    if (flight_index + 1U < fixture->flight_count) {
        if (!assert_delayed_flight_rejected(
                case_name, receiver, &fixture->flights[flight_index]) ||
            !assert_delayed_write_rejected(
                case_name, receiver, &fixture->flights[flight_index + 1U]) ||
            !assert_failed_split(case_name, receiver))
            goto cleanup;
    } else {
        /* A fixed valid retransmission after final-flight failure cannot revive the state. */
        if (!assert_delayed_flight_rejected(
                case_name, receiver, &fixture->flights[flight_index]) ||
            !assert_failed_split(case_name, receiver))
            goto cleanup;
    }
    success = 1;

cleanup:
    if (!free_pair(fixture->name, &pair))
        success = 0;
    return success;
}

int main(void)
{
    uint8_t zero[PROBE_KEY_LENGTH] = {0};
    uint8_t one[PROBE_KEY_LENGTH] = {1U};
    const noise_fixture_probe_fixture_t *nnpsk0 = NULL;
    const noise_fixture_probe_fixture_t *xx = NULL;
    size_t index;

    if (!expect_noise("noise DH probe", "initialize Noise framework",
                      noise_init_framework(), NOISE_ERROR_NONE))
        return 1;
    for (index = 0U; index < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++index) {
        const noise_fixture_probe_fixture_t *fixture = &noise_fixture_probe_fixtures[index];
        if (strcmp(fixture->protocol_name, "Noise_NNpsk0_25519_ChaChaPoly_SHA256") == 0)
            nnpsk0 = fixture;
        else if (strcmp(fixture->protocol_name, "Noise_XX_25519_ChaChaPoly_SHA256") == 0)
            xx = fixture;
    }
    if (nnpsk0 == NULL || xx == NULL) {
        (void)fail("noise DH probe", "required NNpsk0 and XX fixtures are missing");
        return 1;
    }

    if (!test_direct_low_order_inputs(nnpsk0) ||
        !test_standard_x25519_decoding(nnpsk0) ||
        !test_nnpsk0_zero_ephemeral_is_early_reject(nnpsk0) ||
        !test_nnpsk0_low_order_ephemeral_reaches_write_dh(nnpsk0) ||
        !test_xx_low_order_ephemeral_reaches_read_dh(xx) ||
        !test_xx_low_order_static(xx, NOISE_ROLE_RESPONDER, 1U,
                                  zero, "XX responder s=u0 / initiator ES") ||
        !test_xx_low_order_static(xx, NOISE_ROLE_RESPONDER, 1U,
                                  one, "XX responder s=u1 / initiator ES") ||
        !test_xx_low_order_static(xx, NOISE_ROLE_INITIATOR, 2U,
                                  zero, "XX initiator s=u0 / responder SE") ||
        !test_xx_low_order_static(xx, NOISE_ROLE_INITIATOR, 2U,
                                  one, "XX initiator s=u1 / responder SE") ||
        !run_valid_fixture_handshake(nnpsk0) ||
        !run_valid_fixture_handshake(xx))
        return 1;

    puts("X25519 low-order/backend and authenticated XX s-rejection probes passed; valid fixture handshakes still split successfully.");
    puts("These host probes characterize the selected sodium backend only; they are not endpoint, lifecycle, interoperability, resource, or production-provider acceptance evidence.");
    return 0;
}
