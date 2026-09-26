/* Host characterization of the unchanged noise-c sodium backend. */
#include <noise/protocol.h>

#include "noise_fixture_probe.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PROBE_MESSAGE_CAPACITY 512U
#define PROBE_PLAINTEXT_CAPACITY 128U
#define PROBE_AEAD_CAPACITY 256U
#define PROBE_HASH_LENGTH 32U
#define PROBE_KEY_LENGTH 32U
#define PROBE_NONCE_LENGTH 12U
#define PROBE_TAG_LENGTH 16U

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
    char error_text[128];

    if (actual == expected)
        return 1;
    if (noise_strerror(actual, error_text, sizeof(error_text)) != NOISE_ERROR_NONE)
        (void)snprintf(error_text, sizeof(error_text), "unknown Noise error %d", actual);
    fprintf(stderr, "%s: %s returned %s (%d), expected %d\n",
            fixture, operation, error_text, actual, expected);
    return 0;
}

static int expect_bytes(const char *fixture, const char *what,
                        const uint8_t *actual, size_t actual_size,
                        noise_fixture_probe_bytes_t expected)
{
    size_t index;

    if (actual_size != expected.size) {
        fprintf(stderr, "%s: %s length %zu, expected %zu\n",
                fixture, what, actual_size, expected.size);
        return 0;
    }
    if (expected.size != 0U && (actual == NULL || expected.data == NULL))
        return fail(fixture, "nonempty byte comparison has a null pointer");
    if (expected.size != 0U && memcmp(actual, expected.data, expected.size) != 0) {
        for (index = 0U; index < expected.size; ++index) {
            if (actual[index] != expected.data[index])
                break;
        }
        fprintf(stderr, "%s: %s differs at byte %zu (actual 0x%02x, expected 0x%02x)\n",
                fixture, what, index, actual[index], expected.data[index]);
        return 0;
    }
    return 1;
}

static int valid_bytes(noise_fixture_probe_bytes_t bytes, size_t maximum,
                       bool must_be_nonempty)
{
    return bytes.size <= maximum && (!must_be_nonempty || bytes.size != 0U) &&
           (bytes.size == 0U || bytes.data != NULL);
}

static int validate_fixture(const noise_fixture_probe_fixture_t *fixture)
{
    size_t index;

    if (!valid_bytes(fixture->init_ephemeral, PROBE_KEY_LENGTH, true) ||
        fixture->init_ephemeral.size != PROBE_KEY_LENGTH ||
        !valid_bytes(fixture->resp_ephemeral, PROBE_KEY_LENGTH, true) ||
        fixture->resp_ephemeral.size != PROBE_KEY_LENGTH ||
        !valid_bytes(fixture->prologue, PROBE_MESSAGE_CAPACITY, true) ||
        !valid_bytes(fixture->handshake_hash, PROBE_HASH_LENGTH, true) ||
        fixture->handshake_hash.size != PROBE_HASH_LENGTH ||
        !valid_bytes(fixture->i_to_r_key, PROBE_KEY_LENGTH, true) ||
        fixture->i_to_r_key.size != PROBE_KEY_LENGTH ||
        !valid_bytes(fixture->r_to_i_key, PROBE_KEY_LENGTH, true) ||
        fixture->r_to_i_key.size != PROBE_KEY_LENGTH ||
        fixture->flights == NULL || fixture->flight_count < 2U ||
        fixture->flight_count > 3U)
        return fail(fixture->name, "fixture input has an invalid size or pointer");

    if (fixture->name == NULL || fixture->protocol_name == NULL)
        return fail("noise fixture", "fixture name or protocol is missing");

    if (fixture->name[0] == 'n') {
        if (fixture->init_static.size != 0U || fixture->resp_static.size != 0U ||
            fixture->psk.size != PROBE_KEY_LENGTH || fixture->flight_count != 2U)
            return fail(fixture->name, "NNpsk0 fixture fields are inconsistent");
    } else if (fixture->name[0] == 'x') {
        if (fixture->init_static.size != PROBE_KEY_LENGTH ||
            fixture->resp_static.size != PROBE_KEY_LENGTH || fixture->psk.size != 0U ||
            fixture->flight_count != 3U)
            return fail(fixture->name, "XX fixture fields are inconsistent");
    } else {
        return fail(fixture->name, "unsupported fixture family");
    }

    for (index = 0U; index < fixture->flight_count; ++index) {
        if (!valid_bytes(fixture->flights[index].message, PROBE_MESSAGE_CAPACITY, true) ||
            !valid_bytes(fixture->flights[index].plaintext, PROBE_PLAINTEXT_CAPACITY, false))
            return fail(fixture->name, "handshake flight has an invalid size or pointer");
    }
    return 1;
}

static int derive_public_key(const char *fixture, noise_fixture_probe_bytes_t private_key,
                             uint8_t public_key[PROBE_KEY_LENGTH])
{
    NoiseDHState *dh = NULL;
    int result = 0;
    int error;

    error = noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519);
    if (!expect_noise(fixture, "noise_dhstate_new_by_id", error, NOISE_ERROR_NONE))
        goto cleanup;
    if (noise_dhstate_get_private_key_length(dh) != private_key.size ||
        noise_dhstate_get_public_key_length(dh) != PROBE_KEY_LENGTH) {
        (void)fail(fixture, "Curve25519 key lengths differ from the public fixtures");
        goto cleanup;
    }
    error = noise_dhstate_set_keypair_private(dh, private_key.data, private_key.size);
    if (!expect_noise(fixture, "noise_dhstate_set_keypair_private", error, NOISE_ERROR_NONE))
        goto cleanup;
    error = noise_dhstate_get_public_key(dh, public_key, PROBE_KEY_LENGTH);
    if (!expect_noise(fixture, "noise_dhstate_get_public_key", error, NOISE_ERROR_NONE))
        goto cleanup;
    result = 1;

cleanup:
    if (dh != NULL &&
        !expect_noise(fixture, "noise_dhstate_free", noise_dhstate_free(dh), NOISE_ERROR_NONE))
        result = 0;
    return result;
}

static int install_ephemeral(const noise_fixture_probe_fixture_t *fixture,
                             NoiseHandshakeState *state,
                             noise_fixture_probe_bytes_t private_key)
{
    uint8_t public_key[PROBE_KEY_LENGTH];
    int error;

    /* Fixed public fixture ephemerals make Noise messages reproducible; this is not RNG testing. */
    if (!derive_public_key(fixture->name, private_key, public_key))
        return 0;
    error = noise_handshakestate_set_local_ephemeral(
        state, private_key.data, private_key.size, public_key, sizeof(public_key));
    return expect_noise(fixture->name, "noise_handshakestate_set_local_ephemeral",
                        error, NOISE_ERROR_NONE);
}

static int install_static(const noise_fixture_probe_fixture_t *fixture,
                          NoiseHandshakeState *state,
                          noise_fixture_probe_bytes_t private_key,
                          bool should_exist)
{
    NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(state);

    if (!should_exist)
        return dh == NULL || fail(fixture->name, "unexpected local static-key state");
    if (dh == NULL)
        return fail(fixture->name, "required local static-key state is missing");
    if (noise_dhstate_get_private_key_length(dh) != private_key.size ||
        noise_dhstate_get_public_key_length(dh) != PROBE_KEY_LENGTH)
        return fail(fixture->name, "static Curve25519 key lengths differ from the fixture");
    return expect_noise(fixture->name, "noise_dhstate_set_keypair_private(static)",
                        noise_dhstate_set_keypair_private(dh, private_key.data, private_key.size),
                        NOISE_ERROR_NONE);
}

static int configure_handshake(const noise_fixture_probe_fixture_t *fixture,
                               NoiseHandshakeState *state,
                               noise_fixture_probe_bytes_t ephemeral,
                               noise_fixture_probe_bytes_t static_key,
                               bool has_static)
{
    const bool has_psk = fixture->psk.size != 0U;

    if (!install_ephemeral(fixture, state, ephemeral) ||
        !install_static(fixture, state, static_key, has_static))
        return 0;
    if ((noise_handshakestate_needs_pre_shared_key(state) != 0) != has_psk)
        return fail(fixture->name, "provider PSK requirement differs from the fixture pattern");
    if (has_psk &&
        !expect_noise(fixture->name, "noise_handshakestate_set_pre_shared_key",
                      noise_handshakestate_set_pre_shared_key(state, fixture->psk.data,
                                                              fixture->psk.size),
                      NOISE_ERROR_NONE))
        return 0;
    if (!expect_noise(fixture->name, "noise_handshakestate_set_prologue",
                      noise_handshakestate_set_prologue(state, fixture->prologue.data,
                                                        fixture->prologue.size),
                      NOISE_ERROR_NONE))
        return 0;
    return 1;
}

static int create_pair(const noise_fixture_probe_fixture_t *fixture, probe_pair_t *pair)
{
    int error;

    error = noise_handshakestate_new_by_name(&pair->initiator, fixture->protocol_name,
                                             NOISE_ROLE_INITIATOR);
    if (!expect_noise(fixture->name, "new initiator handshake", error, NOISE_ERROR_NONE))
        return 0;
    error = noise_handshakestate_new_by_name(&pair->responder, fixture->protocol_name,
                                             NOISE_ROLE_RESPONDER);
    if (!expect_noise(fixture->name, "new responder handshake", error, NOISE_ERROR_NONE))
        return 0;
    if (!configure_handshake(fixture, pair->initiator, fixture->init_ephemeral,
                             fixture->init_static, fixture->init_static.size != 0U) ||
        !configure_handshake(fixture, pair->responder, fixture->resp_ephemeral,
                             fixture->resp_static, fixture->resp_static.size != 0U))
        return 0;

    if (!expect_noise(fixture->name, "start initiator",
                      noise_handshakestate_start(pair->initiator), NOISE_ERROR_NONE) ||
        !expect_noise(fixture->name, "start responder",
                      noise_handshakestate_start(pair->responder), NOISE_ERROR_NONE))
        return 0;
    if (noise_handshakestate_get_action(pair->initiator) != NOISE_ACTION_WRITE_MESSAGE ||
        noise_handshakestate_get_action(pair->responder) != NOISE_ACTION_READ_MESSAGE)
        return fail(fixture->name, "initial Noise handshake actions are unexpected");
    return 1;
}

static int write_flight(const noise_fixture_probe_fixture_t *fixture,
                        NoiseHandshakeState *sender,
                        const noise_fixture_probe_flight_t *flight,
                        uint8_t message[PROBE_MESSAGE_CAPACITY], size_t *message_size)
{
    uint8_t plaintext[PROBE_PLAINTEXT_CAPACITY];
    uint8_t empty = 0U;
    NoiseBuffer message_buffer;
    NoiseBuffer plaintext_buffer;
    int error;

    if (noise_handshakestate_get_action(sender) != NOISE_ACTION_WRITE_MESSAGE)
        return fail(fixture->name, "Noise sender was not ready to write a flight");
    if (flight->plaintext.size != 0U)
        memcpy(plaintext, flight->plaintext.data, flight->plaintext.size);
    noise_buffer_set_output(message_buffer, message, PROBE_MESSAGE_CAPACITY);
    noise_buffer_set_input(plaintext_buffer,
                           flight->plaintext.size == 0U ? &empty : plaintext,
                           flight->plaintext.size);
    error = noise_handshakestate_write_message(sender, &message_buffer, &plaintext_buffer);
    if (!expect_noise(fixture->name, "noise_handshakestate_write_message",
                      error, NOISE_ERROR_NONE))
        return 0;
    if (!expect_bytes(fixture->name, "written Noise flight", message_buffer.data,
                      message_buffer.size, flight->message))
        return 0;
    *message_size = message_buffer.size;
    return 1;
}

static int read_flight(const noise_fixture_probe_fixture_t *fixture,
                       NoiseHandshakeState *receiver,
                       const noise_fixture_probe_flight_t *flight,
                       const uint8_t *message, size_t message_size)
{
    uint8_t received_message[PROBE_MESSAGE_CAPACITY];
    uint8_t plaintext[PROBE_PLAINTEXT_CAPACITY];
    NoiseBuffer message_buffer;
    NoiseBuffer plaintext_buffer;
    int error;

    if (message_size > sizeof(received_message) || flight->plaintext.size > sizeof(plaintext))
        return fail(fixture->name, "Noise flight exceeds the receive buffer");
    if (noise_handshakestate_get_action(receiver) != NOISE_ACTION_READ_MESSAGE)
        return fail(fixture->name, "Noise receiver was not ready to read a flight");
    memcpy(received_message, message, message_size);
    noise_buffer_set_input(message_buffer, received_message, message_size);
    noise_buffer_set_output(plaintext_buffer, plaintext, sizeof(plaintext));
    error = noise_handshakestate_read_message(receiver, &message_buffer, &plaintext_buffer);
    if (!expect_noise(fixture->name, "noise_handshakestate_read_message",
                      error, NOISE_ERROR_NONE))
        return 0;
    return expect_bytes(fixture->name, "decrypted Noise flight payload",
                        plaintext_buffer.data, plaintext_buffer.size, flight->plaintext);
}

static int transfer_flight(const noise_fixture_probe_fixture_t *fixture,
                           NoiseHandshakeState *sender, NoiseHandshakeState *receiver,
                           const noise_fixture_probe_flight_t *flight)
{
    uint8_t message[PROBE_MESSAGE_CAPACITY];
    size_t message_size = 0U;

    return write_flight(fixture, sender, flight, message, &message_size) &&
           read_flight(fixture, receiver, flight, message, message_size);
}

static int validate_packet_metadata(const noise_fixture_probe_fixture_t *fixture,
                                    const noise_fixture_probe_packet_t *packet,
                                    noise_fixture_probe_bytes_t expected_key)
{
    size_t index;

    if (packet->pn != 0U || packet->key.size != PROBE_KEY_LENGTH ||
        packet->nonce.size != PROBE_NONCE_LENGTH || packet->tag.size != PROBE_TAG_LENGTH ||
        !valid_bytes(packet->aad, PROBE_AEAD_CAPACITY, true) ||
        !valid_bytes(packet->header, PROBE_MESSAGE_CAPACITY, true) ||
        !valid_bytes(packet->plaintext, PROBE_PLAINTEXT_CAPACITY, true) ||
        !valid_bytes(packet->ciphertext, PROBE_AEAD_CAPACITY, false) ||
        !valid_bytes(packet->tag, PROBE_TAG_LENGTH, true) ||
        !valid_bytes(packet->frame, PROBE_MESSAGE_CAPACITY, true))
        return fail(fixture->name, "FINISH/READY packet fields have invalid sizes");
    if (!expect_bytes(fixture->name, "packet directional key", packet->key.data,
                      packet->key.size, expected_key))
        return 0;
    for (index = 0U; index < packet->nonce.size; ++index) {
        if (packet->nonce.data[index] != 0U)
            return fail(fixture->name, "PN 0 fixture nonce is not all zero bytes");
    }
    return 1;
}

static int encrypt_packet(const noise_fixture_probe_fixture_t *fixture,
                          const noise_fixture_probe_packet_t *packet,
                          noise_fixture_probe_bytes_t expected_key,
                          NoiseCipherState *send_state)
{
    uint8_t encrypted[PROBE_AEAD_CAPACITY];
    uint8_t expected[PROBE_AEAD_CAPACITY];
    NoiseBuffer buffer;
    size_t expected_size;
    int error;

    if (!validate_packet_metadata(fixture, packet, expected_key))
        return 0;
    if (packet->plaintext.size + packet->tag.size > sizeof(encrypted) ||
        packet->ciphertext.size + packet->tag.size > sizeof(expected))
        return fail(fixture->name, "FINISH/READY packet exceeds the AEAD scratch buffer");
    if (packet->plaintext.size != 0U)
        memcpy(encrypted, packet->plaintext.data, packet->plaintext.size);
    noise_buffer_set_inout(buffer, encrypted, packet->plaintext.size, sizeof(encrypted));
    error = noise_cipherstate_set_nonce(send_state, 0U);
    if (!expect_noise(fixture->name, "noise_cipherstate_set_nonce(send, PN 0)",
                      error, NOISE_ERROR_NONE))
        return 0;
    error = noise_cipherstate_encrypt_with_ad(send_state, packet->aad.data,
                                              packet->aad.size, &buffer);
    if (!expect_noise(fixture->name, "noise_cipherstate_encrypt_with_ad",
                      error, NOISE_ERROR_NONE))
        return 0;

    expected_size = packet->ciphertext.size + packet->tag.size;
    if (buffer.size != expected_size)
        return fail(fixture->name, "encrypted packet length differs from ciphertext plus tag");
    memcpy(expected, packet->ciphertext.data, packet->ciphertext.size);
    memcpy(expected + packet->ciphertext.size, packet->tag.data, packet->tag.size);
    return expect_bytes(fixture->name, packet->name, buffer.data, buffer.size,
                        (noise_fixture_probe_bytes_t){expected, expected_size});
}

static int decrypt_packet(const noise_fixture_probe_fixture_t *fixture,
                          const noise_fixture_probe_packet_t *packet,
                          noise_fixture_probe_bytes_t expected_key,
                          NoiseCipherState *receive_state)
{
    uint8_t encrypted[PROBE_AEAD_CAPACITY];
    size_t encrypted_size;
    NoiseBuffer buffer;
    int error;

    if (!validate_packet_metadata(fixture, packet, expected_key))
        return 0;
    encrypted_size = packet->ciphertext.size + packet->tag.size;
    if (encrypted_size > sizeof(encrypted))
        return fail(fixture->name, "FINISH/READY ciphertext exceeds the AEAD scratch buffer");
    memcpy(encrypted, packet->ciphertext.data, packet->ciphertext.size);
    memcpy(encrypted + packet->ciphertext.size, packet->tag.data, packet->tag.size);
    noise_buffer_set_inout(buffer, encrypted, encrypted_size, sizeof(encrypted));
    error = noise_cipherstate_set_nonce(receive_state, 0U);
    if (!expect_noise(fixture->name, "noise_cipherstate_set_nonce(receive, PN 0)",
                      error, NOISE_ERROR_NONE))
        return 0;
    error = noise_cipherstate_decrypt_with_ad(receive_state, packet->aad.data,
                                              packet->aad.size, &buffer);
    if (!expect_noise(fixture->name, "noise_cipherstate_decrypt_with_ad",
                      error, NOISE_ERROR_NONE))
        return 0;
    return expect_bytes(fixture->name, packet->name, buffer.data, buffer.size,
                        packet->plaintext);
}

static int run_split_packet_checks(const noise_fixture_probe_fixture_t *fixture,
                                   probe_pair_t *pair)
{
    NoiseCipherState *init_send = NULL;
    NoiseCipherState *init_receive = NULL;
    NoiseCipherState *resp_send = NULL;
    NoiseCipherState *resp_receive = NULL;
    uint8_t init_hash[PROBE_HASH_LENGTH];
    uint8_t resp_hash[PROBE_HASH_LENGTH];
    int success = 0;

    if (!expect_noise(fixture->name, "get initiator handshake hash",
                      noise_handshakestate_get_handshake_hash(pair->initiator,
                                                              init_hash, sizeof(init_hash)),
                      NOISE_ERROR_NONE) ||
        !expect_noise(fixture->name, "get responder handshake hash",
                      noise_handshakestate_get_handshake_hash(pair->responder,
                                                              resp_hash, sizeof(resp_hash)),
                      NOISE_ERROR_NONE) ||
        !expect_bytes(fixture->name, "initiator handshake hash", init_hash,
                      sizeof(init_hash), fixture->handshake_hash) ||
        !expect_bytes(fixture->name, "responder handshake hash", resp_hash,
                      sizeof(resp_hash), fixture->handshake_hash))
        goto cleanup;

    if (!expect_noise(fixture->name, "split initiator",
                      noise_handshakestate_split(pair->initiator, &init_send, &init_receive),
                      NOISE_ERROR_NONE) ||
        !expect_noise(fixture->name, "split responder",
                      noise_handshakestate_split(pair->responder, &resp_send, &resp_receive),
                      NOISE_ERROR_NONE))
        goto cleanup;
    if (noise_handshakestate_get_action(pair->initiator) != NOISE_ACTION_COMPLETE ||
        noise_handshakestate_get_action(pair->responder) != NOISE_ACTION_COMPLETE) {
        (void)fail(fixture->name, "split did not complete both handshakes");
        goto cleanup;
    }

    /* These packet checks exercise Noise Split and AEAD only, not SEC-1 activation state. */
#ifdef DMP_NOISE_FIXTURE_EMBEDDED_RUNNER
    /* The custom-storage experiment keeps transferred traffic owners alive
       while releasing both obsolete handshakes back to the same arena. */
    if (!expect_noise(fixture->name, "destroy split initiator handshake",
                      noise_handshakestate_free(pair->initiator), NOISE_ERROR_NONE))
        goto cleanup;
    pair->initiator = NULL;
    if (!expect_noise(fixture->name, "destroy split responder handshake",
                      noise_handshakestate_free(pair->responder), NOISE_ERROR_NONE))
        goto cleanup;
    pair->responder = NULL;
#endif
    if (!encrypt_packet(fixture, &fixture->finish, fixture->i_to_r_key, init_send) ||
        !decrypt_packet(fixture, &fixture->finish, fixture->i_to_r_key, resp_receive) ||
        !encrypt_packet(fixture, &fixture->ready, fixture->r_to_i_key, resp_send) ||
        !decrypt_packet(fixture, &fixture->ready, fixture->r_to_i_key, init_receive))
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

static int free_pair(const char *fixture, probe_pair_t *pair)
{
    int success = 1;

    if (pair->initiator != NULL &&
        !expect_noise(fixture, "free initiator handshake",
                      noise_handshakestate_free(pair->initiator), NOISE_ERROR_NONE))
        success = 0;
    if (pair->responder != NULL &&
        !expect_noise(fixture, "free responder handshake",
                      noise_handshakestate_free(pair->responder), NOISE_ERROR_NONE))
        success = 0;
    pair->initiator = NULL;
    pair->responder = NULL;
    return success;
}

static int run_fixture(const noise_fixture_probe_fixture_t *fixture)
{
    probe_pair_t pair = {NULL, NULL};
    size_t index;
    int success = 0;

    if (!validate_fixture(fixture) || !create_pair(fixture, &pair))
        goto cleanup;
    for (index = 0U; index < fixture->flight_count; ++index) {
        NoiseHandshakeState *sender = (index % 2U == 0U) ? pair.initiator : pair.responder;
        NoiseHandshakeState *receiver = (index % 2U == 0U) ? pair.responder : pair.initiator;

        if (!transfer_flight(fixture, sender, receiver, &fixture->flights[index]))
            goto cleanup;
    }
    if (noise_handshakestate_get_action(pair.initiator) != NOISE_ACTION_SPLIT ||
        noise_handshakestate_get_action(pair.responder) != NOISE_ACTION_SPLIT) {
        (void)fail(fixture->name, "handshake did not reach SPLIT on both roles");
        goto cleanup;
    }
    if (!run_split_packet_checks(fixture, &pair))
        goto cleanup;
    success = 1;

cleanup:
    if (!free_pair(fixture->name, &pair))
        success = 0;
    return success;
}

static int run_abort_first_probe(const noise_fixture_probe_fixture_t *fixture)
{
    probe_pair_t pair = {NULL, NULL};
    size_t target = fixture->flight_count - 1U;
    size_t index;
    uint8_t message[PROBE_MESSAGE_CAPACITY];
    uint8_t tampered[PROBE_MESSAGE_CAPACITY];
    uint8_t plaintext[PROBE_PLAINTEXT_CAPACITY];
    size_t message_size = 0U;
    NoiseHandshakeState *sender;
    NoiseHandshakeState *receiver;
    NoiseBuffer message_buffer;
    NoiseBuffer plaintext_buffer;
    int error;
    int success = 0;

    if (!validate_fixture(fixture) || !create_pair(fixture, &pair))
        goto cleanup;
    for (index = 0U; index < target; ++index) {
        sender = (index % 2U == 0U) ? pair.initiator : pair.responder;
        receiver = (index % 2U == 0U) ? pair.responder : pair.initiator;
        if (!transfer_flight(fixture, sender, receiver, &fixture->flights[index]))
            goto cleanup;
    }

    sender = (target % 2U == 0U) ? pair.initiator : pair.responder;
    receiver = (target % 2U == 0U) ? pair.responder : pair.initiator;
    if (!write_flight(fixture, sender, &fixture->flights[target], message, &message_size))
        goto cleanup;
    if (message_size < PROBE_TAG_LENGTH) {
        (void)fail(fixture->name, "authenticated target flight has no complete tag");
        goto cleanup;
    }
    memcpy(tampered, message, message_size);
    tampered[message_size - 1U] ^= 0x01U;
    noise_buffer_set_input(message_buffer, tampered, message_size);
    noise_buffer_set_output(plaintext_buffer, plaintext, sizeof(plaintext));
    error = noise_handshakestate_read_message(receiver, &message_buffer, &plaintext_buffer);
    if (!expect_noise(fixture->name, "read tampered authenticated flight",
                      error, NOISE_ERROR_MAC_FAILURE))
        goto cleanup;
    if (noise_handshakestate_get_action(receiver) != NOISE_ACTION_FAILED) {
        (void)fail(fixture->name, "tampered authenticated flight did not set FAILED action");
        goto cleanup;
    }

    memcpy(tampered, fixture->flights[target].message.data, message_size);
    noise_buffer_set_input(message_buffer, tampered, message_size);
    noise_buffer_set_output(plaintext_buffer, plaintext, sizeof(plaintext));
    error = noise_handshakestate_read_message(receiver, &message_buffer, &plaintext_buffer);
    if (!expect_noise(fixture->name, "retry authentic flight after authentication failure",
                      error, NOISE_ERROR_INVALID_STATE))
        goto cleanup;
    if (noise_handshakestate_get_action(receiver) != NOISE_ACTION_FAILED) {
        (void)fail(fixture->name, "authentic retry changed the FAILED action");
        goto cleanup;
    }
    success = 1;

cleanup:
    if (!free_pair(fixture->name, &pair))
        success = 0;
    return success;
}

#ifdef DMP_NOISE_FIXTURE_EMBEDDED_RUNNER
int dmp_noise_fixture_run(void)
#else
int main(void)
#endif
{
    size_t index;
    int failed = 0;

    if (!expect_noise("noise fixture probe", "noise_init_framework",
                      noise_init_framework(), NOISE_ERROR_NONE))
        return 1;
    for (index = 0U; index < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++index) {
        const noise_fixture_probe_fixture_t *fixture = &noise_fixture_probe_fixtures[index];

        if (!run_fixture(fixture) || !run_abort_first_probe(fixture)) {
            failed = 1;
            continue;
        }
        printf("%s: exact Noise flights/hash/Split packets and abort-first read behavior passed\n",
               fixture->name);
    }
    if (failed)
        return 1;
    puts("Public deterministic fixtures characterize fixed-key provider behavior; RNG fault handling, provider adoption, and P01 acceptance remain untested.");
    return 0;
}
