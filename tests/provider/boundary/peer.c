#include "peer.h"

#include "noise_fixture_probe.h"

#include <string.h>

#define PEER_KEY_SIZE 32U
#define PEER_HASH_SIZE 32U
#define PEER_ATTEMPT_ID_SIZE 16U
#define PEER_PROLOGUE_SIZE 85U
#define PEER_PROLOGUE_DOMAIN_SIZE 14U
#define PEER_PROLOGUE_ATTEMPT_OFFSET 17U
#define PEER_EPHEMERAL_MUTATION_OFFSET 5U

static const char peer_nnpsk0_protocol[] = "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
static const char peer_xx_protocol[] = "Noise_XX_25519_ChaChaPoly_SHA256";
static const char peer_prologue_domain[] = "DMP2-SEC1-BOOT";

static int mode_is_supported(unsigned mode)
{
    return mode == 1U || mode == 2U;
}

static const char *protocol_name_for_mode(unsigned mode)
{
    if (mode == 1U)
        return peer_nnpsk0_protocol;
    if (mode == 2U)
        return peer_xx_protocol;
    return NULL;
}

/* Resolve by the fixture's protocol name so generated fixture order is immaterial. */
static const noise_fixture_probe_fixture_t *fixture_for_mode(unsigned mode)
{
    const char *protocol_name = protocol_name_for_mode(mode);
    const noise_fixture_probe_fixture_t *match = NULL;
    size_t index;

    if (protocol_name == NULL)
        return NULL;
    for (index = 0U; index < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++index) {
        const noise_fixture_probe_fixture_t *fixture = &noise_fixture_probe_fixtures[index];

        if (fixture->protocol_name != NULL &&
            strcmp(fixture->protocol_name, protocol_name) == 0) {
            if (match != NULL)
                return NULL;
            match = fixture;
        }
    }
    return match;
}

static int fixture_valid(unsigned mode, const noise_fixture_probe_fixture_t *fixture)
{
    size_t expected_flights;
    size_t index;

    if (fixture == NULL || fixture->protocol_name == NULL || fixture->prologue.data == NULL ||
        fixture->attempt_id.data == NULL || fixture->init_ephemeral.data == NULL ||
        fixture->resp_ephemeral.data == NULL || fixture->handshake_hash.data == NULL ||
        fixture->init_ephemeral.size != PEER_KEY_SIZE ||
        fixture->resp_ephemeral.size != PEER_KEY_SIZE ||
        fixture->attempt_id.size != PEER_ATTEMPT_ID_SIZE ||
        fixture->handshake_hash.size != PEER_HASH_SIZE ||
        fixture->prologue.size != PEER_PROLOGUE_SIZE || fixture->flights == NULL)
        return 0;

    if (mode == 1U) {
        if (fixture->init_static.size != 0U || fixture->resp_static.size != 0U ||
            fixture->psk.data == NULL || fixture->psk.size != PEER_KEY_SIZE)
            return 0;
        expected_flights = 2U;
    } else if (mode == 2U) {
        if (fixture->init_static.data == NULL || fixture->resp_static.data == NULL ||
            fixture->init_static.size != PEER_KEY_SIZE ||
            fixture->resp_static.size != PEER_KEY_SIZE || fixture->psk.size != 0U)
            return 0;
        expected_flights = 3U;
    } else {
        return 0;
    }
    if (fixture->flight_count != expected_flights ||
        memcmp(fixture->prologue.data, peer_prologue_domain, PEER_PROLOGUE_DOMAIN_SIZE) != 0 ||
        fixture->prologue.data[14] != 2U || fixture->prologue.data[15] != (uint8_t)mode ||
        fixture->prologue.data[16] != 1U ||
        memcmp(fixture->prologue.data + PEER_PROLOGUE_ATTEMPT_OFFSET,
               fixture->attempt_id.data, PEER_ATTEMPT_ID_SIZE) != 0)
        return 0;

    for (index = 0U; index < expected_flights; ++index) {
        if (fixture->flights[index].message.data == NULL ||
            fixture->flights[index].message.size != boundary_flight_size(mode,
                                                                         (unsigned)(index + 1U)))
            return 0;
    }
    return 1;
}

static int derive_public_key(const uint8_t private_key[PEER_KEY_SIZE],
                             uint8_t public_key[PEER_KEY_SIZE])
{
    NoiseDHState *dh = NULL;
    int error;
    int free_error;

    error = noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519);
    if (error != NOISE_ERROR_NONE)
        goto cleanup;
    if (dh == NULL) {
        error = NOISE_ERROR_INVALID_STATE;
        goto cleanup;
    }
    if (noise_dhstate_get_private_key_length(dh) != PEER_KEY_SIZE ||
        noise_dhstate_get_public_key_length(dh) != PEER_KEY_SIZE) {
        error = NOISE_ERROR_INVALID_STATE;
        goto cleanup;
    }
    error = noise_dhstate_set_keypair_private(dh, private_key, PEER_KEY_SIZE);
    if (error != NOISE_ERROR_NONE)
        goto cleanup;
    error = noise_dhstate_get_public_key(dh, public_key, PEER_KEY_SIZE);

cleanup:
    if (dh != NULL) {
        free_error = noise_dhstate_free(dh);
        if (error == NOISE_ERROR_NONE && free_error != NOISE_ERROR_NONE)
            error = free_error;
    }
    if (error != NOISE_ERROR_NONE)
        noise_clean(public_key, PEER_KEY_SIZE);
    return error;
}

int boundary_peer_new(NoiseHandshakeState **state, unsigned mode, int role,
                      unsigned generation, int wrong_psk)
{
    const noise_fixture_probe_fixture_t *fixture;
    noise_fixture_probe_bytes_t local_ephemeral;
    noise_fixture_probe_bytes_t local_static;
    NoiseHandshakeState *candidate = NULL;
    NoiseDHState *static_state;
    uint8_t ephemeral_private[PEER_KEY_SIZE] = {0};
    uint8_t ephemeral_public[PEER_KEY_SIZE] = {0};
    uint8_t psk[PEER_KEY_SIZE] = {0};
    uint8_t prologue[PEER_PROLOGUE_SIZE] = {0};
    int error;

    if (state == NULL)
        return NOISE_ERROR_INVALID_PARAM;
    *state = NULL;
    if (!mode_is_supported(mode) ||
        (role != NOISE_ROLE_INITIATOR && role != NOISE_ROLE_RESPONDER) || generation > 255U ||
        (wrong_psk != 0 && wrong_psk != 1) || (wrong_psk != 0 && mode != 1U))
        return NOISE_ERROR_INVALID_PARAM;

    fixture = fixture_for_mode(mode);
    if (!fixture_valid(mode, fixture))
        return NOISE_ERROR_INVALID_STATE;

    if (role == NOISE_ROLE_INITIATOR) {
        local_ephemeral = fixture->init_ephemeral;
        local_static = fixture->init_static;
    } else {
        local_ephemeral = fixture->resp_ephemeral;
        local_static = fixture->resp_static;
    }

    memcpy(ephemeral_private, local_ephemeral.data, PEER_KEY_SIZE);
    memcpy(prologue, fixture->prologue.data, PEER_PROLOGUE_SIZE);
    if (mode == 1U) {
        memcpy(psk, fixture->psk.data, PEER_KEY_SIZE);
        if (wrong_psk != 0)
            psk[0] ^= 0x01U;
    }
    if (generation != 0U) {
        const uint8_t generation_byte = (uint8_t)generation;

        /* Byte 5 is outside X25519's clamped scalar bytes 0 and 31. */
        ephemeral_private[PEER_EPHEMERAL_MUTATION_OFFSET] ^= generation_byte;
        /* SEC-1 S3.1 prologue = domain || PREFIX[0:3] || PREFIX[4:72]. */
        prologue[PEER_PROLOGUE_ATTEMPT_OFFSET] ^= generation_byte;
    }

    error = noise_handshakestate_new_by_name(&candidate, fixture->protocol_name, role);
    if (error != NOISE_ERROR_NONE)
        goto cleanup;
    if (candidate == NULL) {
        error = NOISE_ERROR_INVALID_STATE;
        goto cleanup;
    }

    error = derive_public_key(ephemeral_private, ephemeral_public);
    if (error != NOISE_ERROR_NONE)
        goto cleanup;
    error = noise_handshakestate_set_local_ephemeral(candidate, ephemeral_private,
                                                      PEER_KEY_SIZE, ephemeral_public,
                                                      PEER_KEY_SIZE);
    if (error != NOISE_ERROR_NONE)
        goto cleanup;

    static_state = noise_handshakestate_get_local_keypair_dh(candidate);
    if (mode == 2U) {
        if (static_state == NULL ||
            noise_dhstate_get_private_key_length(static_state) != PEER_KEY_SIZE ||
            noise_dhstate_get_public_key_length(static_state) != PEER_KEY_SIZE) {
            error = NOISE_ERROR_INVALID_STATE;
            goto cleanup;
        }
        error = noise_dhstate_set_keypair_private(static_state, local_static.data,
                                                  local_static.size);
        if (error != NOISE_ERROR_NONE)
            goto cleanup;
    } else if (static_state != NULL) {
        error = NOISE_ERROR_INVALID_STATE;
        goto cleanup;
    }

    if ((noise_handshakestate_needs_pre_shared_key(candidate) != 0) != (mode == 1U)) {
        error = NOISE_ERROR_INVALID_STATE;
        goto cleanup;
    }
    if (mode == 1U) {
        error = noise_handshakestate_set_pre_shared_key(candidate, psk, PEER_KEY_SIZE);
        if (error != NOISE_ERROR_NONE)
            goto cleanup;
    }
    error = noise_handshakestate_set_prologue(candidate, prologue, PEER_PROLOGUE_SIZE);
    if (error != NOISE_ERROR_NONE)
        goto cleanup;
    error = noise_handshakestate_start(candidate);
    if (error != NOISE_ERROR_NONE)
        goto cleanup;
    if ((role == NOISE_ROLE_INITIATOR &&
         noise_handshakestate_get_action(candidate) != NOISE_ACTION_WRITE_MESSAGE) ||
        (role == NOISE_ROLE_RESPONDER &&
         noise_handshakestate_get_action(candidate) != NOISE_ACTION_READ_MESSAGE)) {
        error = NOISE_ERROR_INVALID_STATE;
        goto cleanup;
    }

    *state = candidate;
    candidate = NULL;
    error = NOISE_ERROR_NONE;

cleanup:
    if (candidate != NULL)
        (void)noise_handshakestate_free(candidate);
    noise_clean(ephemeral_private, sizeof(ephemeral_private));
    noise_clean(ephemeral_public, sizeof(ephemeral_public));
    noise_clean(psk, sizeof(psk));
    noise_clean(prologue, sizeof(prologue));
    return error;
}

int boundary_peer_pin(unsigned mode, int role, uint8_t public_key[32])
{
    const noise_fixture_probe_fixture_t *fixture;
    noise_fixture_probe_bytes_t private_key;
    uint8_t private_copy[PEER_KEY_SIZE] = {0};
    int error;

    if (public_key == NULL)
        return NOISE_ERROR_INVALID_PARAM;
    noise_clean(public_key, PEER_KEY_SIZE);
    if (mode != 2U || (role != NOISE_ROLE_INITIATOR && role != NOISE_ROLE_RESPONDER))
        return NOISE_ERROR_INVALID_PARAM;

    fixture = fixture_for_mode(mode);
    if (!fixture_valid(mode, fixture))
        return NOISE_ERROR_INVALID_STATE;
    private_key = role == NOISE_ROLE_INITIATOR ? fixture->init_static : fixture->resp_static;
    if (private_key.data == NULL || private_key.size != PEER_KEY_SIZE)
        return NOISE_ERROR_INVALID_STATE;
    memcpy(private_copy, private_key.data, PEER_KEY_SIZE);
    error = derive_public_key(private_copy, public_key);
    noise_clean(private_copy, sizeof(private_copy));
    return error;
}

size_t boundary_flight_size(unsigned mode, unsigned flight)
{
    if (mode == 1U) {
        if (flight == 1U)
            return 48U;
        if (flight == 2U)
            return 52U;
        return 0U;
    }
    if (mode == 2U) {
        if (flight == 1U)
            return 32U;
        if (flight == 2U)
            return 100U;
        if (flight == 3U)
            return 64U;
    }
    return 0U;
}

int boundary_fixture_flight(unsigned mode, unsigned flight,
                            const uint8_t *bytes, size_t size)
{
    const noise_fixture_probe_fixture_t *fixture;
    size_t expected_size = boundary_flight_size(mode, flight);

    if (!mode_is_supported(mode) || expected_size == 0U || bytes == NULL)
        return NOISE_ERROR_INVALID_PARAM;
    fixture = fixture_for_mode(mode);
    if (!fixture_valid(mode, fixture))
        return NOISE_ERROR_INVALID_STATE;
    if (size != expected_size || fixture->flights[flight - 1U].message.size != expected_size ||
        memcmp(bytes, fixture->flights[flight - 1U].message.data, expected_size) != 0)
        return NOISE_ERROR_INVALID_STATE;
    return NOISE_ERROR_NONE;
}

int boundary_fixture_hash(unsigned mode, const uint8_t hash[32])
{
    const noise_fixture_probe_fixture_t *fixture;

    if (!mode_is_supported(mode) || hash == NULL)
        return NOISE_ERROR_INVALID_PARAM;
    fixture = fixture_for_mode(mode);
    if (!fixture_valid(mode, fixture))
        return NOISE_ERROR_INVALID_STATE;
    if (memcmp(hash, fixture->handshake_hash.data, PEER_HASH_SIZE) != 0)
        return NOISE_ERROR_INVALID_STATE;
    return NOISE_ERROR_NONE;
}
