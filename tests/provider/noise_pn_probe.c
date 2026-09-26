/* Host characterization of explicit receive packet numbers with public test fixtures. */
#include <noise/protocol.h>

#include "noise_fixture_probe.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PROBE_BUFFER_CAPACITY 512U
#define PROBE_KEY_LENGTH 32U
#define PROBE_NONCE_LENGTH 12U
#define PROBE_TAG_LENGTH 16U
#define PROBE_TRANSPORT_PACKET_COUNT 16U

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

static noise_fixture_probe_bytes_t key_for_direction(
    const noise_fixture_probe_fixture_t *fixture, uint8_t direction)
{
    return direction == 0U ? fixture->i_to_r_key : fixture->r_to_i_key;
}

static int validate_packet(const noise_fixture_probe_fixture_t *fixture,
                           const noise_fixture_probe_packet_t *packet)
{
    noise_fixture_probe_bytes_t expected_key;
    size_t index;

    if (packet->name == NULL || packet->direction > 1U || packet->pn == UINT64_MAX ||
        !valid_bytes(packet->key, PROBE_KEY_LENGTH, true) ||
        packet->key.size != PROBE_KEY_LENGTH ||
        !valid_bytes(packet->nonce, PROBE_NONCE_LENGTH, true) ||
        packet->nonce.size != PROBE_NONCE_LENGTH ||
        !valid_bytes(packet->aad, PROBE_BUFFER_CAPACITY, true) ||
        !valid_bytes(packet->header, PROBE_BUFFER_CAPACITY, false) ||
        !valid_bytes(packet->plaintext, PROBE_BUFFER_CAPACITY, false) ||
        !valid_bytes(packet->ciphertext, PROBE_BUFFER_CAPACITY, false) ||
        !valid_bytes(packet->tag, PROBE_TAG_LENGTH, true) ||
        packet->tag.size != PROBE_TAG_LENGTH ||
        !valid_bytes(packet->frame, PROBE_BUFFER_CAPACITY, true) ||
        packet->plaintext.size != packet->ciphertext.size)
        return fail(fixture->name, "transport packet has invalid metadata or exceeds 512 bytes");

    expected_key = key_for_direction(fixture, packet->direction);
    if (!expect_bytes(fixture->name, "transport packet directional key",
                      packet->key.data, packet->key.size, expected_key))
        return 0;
    for (index = 0U; index < packet->nonce.size; ++index) {
        uint8_t expected_nonce_byte = 0U;

        if (index >= 4U)
            expected_nonce_byte = (uint8_t)(packet->pn >> ((index - 4U) * 8U));
        if (packet->nonce.data[index] != expected_nonce_byte)
            return fail(fixture->name, "fixture nonce does not encode the packet number");
    }
    return 1;
}

static int validate_fixture(const noise_fixture_probe_fixture_t *fixture)
{
    size_t index;
    size_t other;

    if (fixture->name == NULL || fixture->protocol_name == NULL ||
        !valid_bytes(fixture->i_to_r_key, PROBE_KEY_LENGTH, true) ||
        fixture->i_to_r_key.size != PROBE_KEY_LENGTH ||
        !valid_bytes(fixture->r_to_i_key, PROBE_KEY_LENGTH, true) ||
        fixture->r_to_i_key.size != PROBE_KEY_LENGTH ||
        fixture->transport_packets == NULL ||
        fixture->transport_packet_count != PROBE_TRANSPORT_PACKET_COUNT)
        return fail("noise PN probe", "fixture packet table or directional keys are invalid");

    for (index = 0U; index < fixture->transport_packet_count; ++index) {
        const noise_fixture_probe_packet_t *packet = &fixture->transport_packets[index];

        if (!validate_packet(fixture, packet))
            return 0;
        for (other = index + 1U; other < fixture->transport_packet_count; ++other) {
            const noise_fixture_probe_packet_t *candidate = &fixture->transport_packets[other];

            if (packet->direction == candidate->direction && packet->pn == candidate->pn)
                return fail(fixture->name, "fixture repeats a direction and packet number");
        }
    }
    return 1;
}

static const noise_fixture_probe_packet_t *find_packet(
    const noise_fixture_probe_fixture_t *fixture, uint8_t direction, uint64_t packet_number)
{
    size_t index;

    for (index = 0U; index < fixture->transport_packet_count; ++index) {
        const noise_fixture_probe_packet_t *packet = &fixture->transport_packets[index];

        if (packet->direction == direction && packet->pn == packet_number)
            return packet;
    }
    return NULL;
}

static int new_receive_state(const noise_fixture_probe_fixture_t *fixture,
                             uint8_t direction, NoiseCipherState **state)
{
    noise_fixture_probe_bytes_t key = key_for_direction(fixture, direction);
    int error;

    *state = NULL;
    error = noise_cipherstate_new_by_id(state, NOISE_CIPHER_CHACHAPOLY);
    if (!expect_noise(fixture->name, "noise_cipherstate_new_by_id", error, NOISE_ERROR_NONE))
        return 0;
    if (*state == NULL)
        return fail(fixture->name, "noise_cipherstate_new_by_id returned no cipher state");
    if (noise_cipherstate_get_key_length(*state) != key.size || key.size != PROBE_KEY_LENGTH)
        return fail(fixture->name, "ChaChaPoly key length differs from fixture key length");
    error = noise_cipherstate_init_key(*state, key.data, key.size);
    return expect_noise(fixture->name, "noise_cipherstate_init_key", error, NOISE_ERROR_NONE);
}

static int copy_encrypted_packet(const noise_fixture_probe_fixture_t *fixture,
                                 const noise_fixture_probe_packet_t *packet,
                                 uint8_t encrypted[PROBE_BUFFER_CAPACITY],
                                 size_t *encrypted_size)
{
    if (packet->tag.size > PROBE_BUFFER_CAPACITY ||
        packet->ciphertext.size > PROBE_BUFFER_CAPACITY - packet->tag.size)
        return fail(fixture->name, "ciphertext and tag exceed the 512-byte probe buffer");
    *encrypted_size = packet->ciphertext.size + packet->tag.size;
    if (packet->ciphertext.size != 0U)
        memcpy(encrypted, packet->ciphertext.data, packet->ciphertext.size);
    memcpy(encrypted + packet->ciphertext.size, packet->tag.data, packet->tag.size);
    return 1;
}

static int decrypt_at_nonce(const noise_fixture_probe_fixture_t *fixture,
                            const noise_fixture_probe_packet_t *packet,
                            NoiseCipherState *state, const uint8_t *aad, size_t aad_size,
                            bool expect_success)
{
    uint8_t encrypted[PROBE_BUFFER_CAPACITY];
    size_t encrypted_size;
    NoiseBuffer buffer;
    int error;

    if (!copy_encrypted_packet(fixture, packet, encrypted, &encrypted_size))
        return 0;
    noise_buffer_set_inout(buffer, encrypted, encrypted_size, sizeof(encrypted));
    error = noise_cipherstate_decrypt_with_ad_at_nonce(
        state, packet->pn, aad, aad_size, &buffer);
    if (!expect_noise(fixture->name, "noise_cipherstate_decrypt_with_ad_at_nonce",
                      error, expect_success ? NOISE_ERROR_NONE : NOISE_ERROR_MAC_FAILURE))
        return 0;
    if (!expect_success)
        return 1;
    return expect_bytes(fixture->name, packet->name, buffer.data, buffer.size,
                        packet->plaintext);
}

static int decrypt_implicit_nonce_zero(const noise_fixture_probe_fixture_t *fixture,
                                       const noise_fixture_probe_packet_t *packet,
                                       NoiseCipherState *state)
{
    uint8_t encrypted[PROBE_BUFFER_CAPACITY];
    size_t encrypted_size;
    NoiseBuffer buffer;
    int error;

    if (!copy_encrypted_packet(fixture, packet, encrypted, &encrypted_size))
        return 0;
    noise_buffer_set_inout(buffer, encrypted, encrypted_size, sizeof(encrypted));
    error = noise_cipherstate_decrypt_with_ad(state, packet->aad.data,
                                              packet->aad.size, &buffer);
    if (!expect_noise(fixture->name, "legacy noise_cipherstate_decrypt_with_ad at PN 0",
                      error, NOISE_ERROR_NONE))
        return 0;
    return expect_bytes(fixture->name, packet->name, buffer.data, buffer.size,
                        packet->plaintext);
}

static int free_state(const noise_fixture_probe_fixture_t *fixture,
                      NoiseCipherState *state, int success)
{
    if (state != NULL &&
        !expect_noise(fixture->name, "noise_cipherstate_free",
                      noise_cipherstate_free(state), NOISE_ERROR_NONE))
        success = 0;
    return success;
}

static int run_reverse_direction(const noise_fixture_probe_fixture_t *fixture,
                                 uint8_t direction)
{
    const noise_fixture_probe_packet_t *ordered[PROBE_TRANSPORT_PACKET_COUNT];
    size_t packet_count = 0U;
    size_t index;
    size_t position;
    NoiseCipherState *state = NULL;
    const noise_fixture_probe_packet_t *implicit_packet;
    int success = 0;

    for (index = 0U; index < fixture->transport_packet_count; ++index) {
        const noise_fixture_probe_packet_t *packet = &fixture->transport_packets[index];

        if (packet->direction != direction)
            continue;
        if (packet_count >= PROBE_TRANSPORT_PACKET_COUNT)
            return fail(fixture->name, "direction packet count exceeds the fixed probe table");
        position = packet_count;
        while (position > 0U && ordered[position - 1U]->pn < packet->pn) {
            ordered[position] = ordered[position - 1U];
            --position;
        }
        ordered[position] = packet;
        ++packet_count;
    }
    if (packet_count == 0U)
        return fail(fixture->name, "fixture has no packets for a receive direction");
    if (!new_receive_state(fixture, direction, &state))
        goto cleanup;

    for (index = 0U; index < packet_count; ++index) {
        if (!decrypt_at_nonce(fixture, ordered[index], state,
                              ordered[index]->aad.data, ordered[index]->aad.size, true))
            goto cleanup;
    }

    /* Explicit receives must leave the implicit Noise nonce at its initial PN 0. */
    implicit_packet = direction == 0U ? &fixture->finish : &fixture->ready;
    if (implicit_packet->direction != direction || implicit_packet->pn != 0U ||
        !decrypt_implicit_nonce_zero(fixture, implicit_packet, state))
        goto cleanup;
    success = 1;

cleanup:
    return free_state(fixture, state, success);
}

static int run_high_nonce_failure_then_lower_retry(
    const noise_fixture_probe_fixture_t *fixture)
{
    const noise_fixture_probe_packet_t *high = find_packet(fixture, 0U, 128U);
    const noise_fixture_probe_packet_t *lower = find_packet(fixture, 0U, 1U);
    uint8_t encrypted[PROBE_BUFFER_CAPACITY];
    size_t encrypted_size;
    NoiseBuffer buffer;
    NoiseCipherState *state = NULL;
    int success = 0;
    int error;

    if (high == NULL || lower == NULL)
        return fail(fixture->name, "fixture lacks PN 128 and PN 1 for retry coverage");
    if (!new_receive_state(fixture, 0U, &state))
        goto cleanup;
    if (!copy_encrypted_packet(fixture, high, encrypted, &encrypted_size))
        goto cleanup;
    encrypted[encrypted_size - 1U] ^= 0x01U;
    noise_buffer_set_inout(buffer, encrypted, encrypted_size, sizeof(encrypted));
    error = noise_cipherstate_decrypt_with_ad_at_nonce(
        state, high->pn, high->aad.data, high->aad.size, &buffer);
    if (!expect_noise(fixture->name, "tampered PN 128 explicit receive",
                      error, NOISE_ERROR_MAC_FAILURE))
        goto cleanup;
    if (!decrypt_at_nonce(fixture, lower, state, lower->aad.data, lower->aad.size, true))
        goto cleanup;
    success = 1;

cleanup:
    return free_state(fixture, state, success);
}

static int run_wrong_aad_retry_and_repeated_pn(
    const noise_fixture_probe_fixture_t *fixture)
{
    const noise_fixture_probe_packet_t *packet = find_packet(fixture, 0U, 1U);
    uint8_t wrong_aad[PROBE_BUFFER_CAPACITY];
    NoiseCipherState *state = NULL;
    int success = 0;

    if (packet == NULL || packet->aad.size == 0U || packet->aad.size > sizeof(wrong_aad))
        return fail(fixture->name, "fixture lacks bounded nonempty AAD at PN 1");
    if (!new_receive_state(fixture, 0U, &state))
        goto cleanup;
    memcpy(wrong_aad, packet->aad.data, packet->aad.size);
    wrong_aad[0] ^= 0x01U;
    if (!decrypt_at_nonce(fixture, packet, state, wrong_aad, packet->aad.size, false) ||
        !decrypt_at_nonce(fixture, packet, state, packet->aad.data, packet->aad.size, true) ||
        !decrypt_at_nonce(fixture, packet, state, packet->aad.data, packet->aad.size, true))
        goto cleanup;
    success = 1;

cleanup:
    return free_state(fixture, state, success);
}

static int run_fixture(const noise_fixture_probe_fixture_t *fixture)
{
    if (!validate_fixture(fixture) ||
        !run_reverse_direction(fixture, 0U) ||
        !run_reverse_direction(fixture, 1U) ||
        !run_high_nonce_failure_then_lower_retry(fixture) ||
        !run_wrong_aad_retry_and_repeated_pn(fixture))
        return 0;

    printf("%s: 16 explicit receive fixtures passed in reverse PN order; failed-auth retry, "
           "repeated PN, and implicit PN 0 preservation passed\n", fixture->name);
    return 1;
}

int main(void)
{
    size_t index;
    int failed = 0;

    if (!expect_noise("noise PN probe", "noise_init_framework",
                      noise_init_framework(), NOISE_ERROR_NONE))
        return 1;
    for (index = 0U; index < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++index) {
        if (!run_fixture(&noise_fixture_probe_fixtures[index]))
            failed = 1;
    }
    if (failed)
        return 1;
    puts("Public deterministic keys are test-only. Repeated explicit receives are accepted here; "
         "replay admission belongs to the caller. No RNG, lifecycle, or production claim is tested.");
    return 0;
}
