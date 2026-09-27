/* MEM-03: one actual local Noise endpoint against prerecorded public fixtures. */
#include "noise_owner_fixture.h"
#include "noise_fixture_probe.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MESSAGE_CAP 512U
#define PLAINTEXT_CAP 128U
#define AEAD_CAP 256U
#define KEY_SIZE 32U
#define HASH_SIZE 32U
#define TAG_SIZE 16U

static const noise_fixture_probe_fixture_t *fixture_at(size_t index)
{
    return index < NOISE_FIXTURE_PROBE_FIXTURE_COUNT ? &noise_fixture_probe_fixtures[index] : NULL;
}

static const char *name(const dmp_noise_owner *owner)
{
    const noise_fixture_probe_fixture_t *f = fixture_at(owner->fixture_index);
    return f != NULL && f->name != NULL ? f->name : "noise owner";
}

static int invalid(const dmp_noise_owner *owner, const char *detail)
{
    fprintf(stderr, "%s: %s\n", name(owner), detail);
    return NOISE_ERROR_INVALID_STATE;
}

static int noise_error(const dmp_noise_owner *owner, const char *operation, int error)
{
    char text[128];
    if (error == NOISE_ERROR_NONE)
        return error;
    if (noise_strerror(error, text, sizeof(text)) != NOISE_ERROR_NONE)
        (void)snprintf(text, sizeof(text), "Noise error %d", error);
    fprintf(stderr, "%s: %s returned %s (%d)\n", name(owner), operation, text, error);
    return error;
}

static int valid(noise_fixture_probe_bytes_t b, size_t cap, int nonempty)
{
    return b.size <= cap && (!nonempty || b.size != 0U) && (b.size == 0U || b.data != NULL);
}

static int equal(const dmp_noise_owner *owner, const char *what, const uint8_t *actual, size_t size,
                 noise_fixture_probe_bytes_t expected)
{
    size_t i;
    if (size != expected.size) {
        fprintf(stderr, "%s: %s length %zu, expected %zu\n", name(owner), what, size,
                expected.size);
        return NOISE_ERROR_INVALID_STATE;
    }
    if (size != 0U && (actual == NULL || expected.data == NULL))
        return invalid(owner, "nonempty fixture comparison has a null pointer");
    for (i = 0U; i < size && actual[i] == expected.data[i]; ++i) {
    }
    if (i != size) {
        fprintf(stderr, "%s: %s differs at byte %zu (actual 0x%02x, expected 0x%02x)\n",
                name(owner), what, i, actual[i], expected.data[i]);
        return NOISE_ERROR_INVALID_STATE;
    }
    return NOISE_ERROR_NONE;
}

static int validate(const dmp_noise_owner *owner, const noise_fixture_probe_fixture_t *f)
{
    size_t i;
    if (f->name == NULL || f->protocol_name == NULL || !valid(f->init_ephemeral, KEY_SIZE, 1) ||
        f->init_ephemeral.size != KEY_SIZE || !valid(f->resp_ephemeral, KEY_SIZE, 1) ||
        f->resp_ephemeral.size != KEY_SIZE || !valid(f->init_static, KEY_SIZE, 0) ||
        !valid(f->resp_static, KEY_SIZE, 0) || !valid(f->psk, KEY_SIZE, 0) ||
        !valid(f->prologue, MESSAGE_CAP, 1) || !valid(f->handshake_hash, HASH_SIZE, 1) ||
        f->handshake_hash.size != HASH_SIZE || !valid(f->i_to_r_key, KEY_SIZE, 1) ||
        f->i_to_r_key.size != KEY_SIZE || !valid(f->r_to_i_key, KEY_SIZE, 1) ||
        f->r_to_i_key.size != KEY_SIZE || f->flights == NULL || f->flight_count < 2U ||
        f->flight_count > 3U)
        return invalid(owner, "fixture input has an invalid size or pointer");
    for (i = 0U; i < f->flight_count; ++i) {
        if (!valid(f->flights[i].message, MESSAGE_CAP, 1) ||
            !valid(f->flights[i].plaintext, PLAINTEXT_CAP, 0))
            return invalid(owner, "handshake flight exceeds a fixture buffer bound");
    }
    return NOISE_ERROR_NONE;
}

static int derive_ephemeral(const dmp_noise_owner *owner, noise_fixture_probe_bytes_t private_key,
                            uint8_t public_key[KEY_SIZE])
{
    NoiseDHState *dh = NULL;
    int error = noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519);
    if (error != NOISE_ERROR_NONE)
        return noise_error(owner, "noise_dhstate_new_by_id", error);
    if (noise_dhstate_get_private_key_length(dh) != private_key.size ||
        noise_dhstate_get_public_key_length(dh) != KEY_SIZE) {
        error = invalid(owner, "Curve25519 key lengths differ from the fixture");
    } else {
        error = noise_dhstate_set_keypair_private(dh, private_key.data, private_key.size);
        if (error == NOISE_ERROR_NONE)
            error = noise_dhstate_get_public_key(dh, public_key, KEY_SIZE);
        if (error != NOISE_ERROR_NONE)
            error = noise_error(owner, "derive fixed ephemeral public key", error);
    }
    {
        int free_error = noise_dhstate_free(dh);
        if (error == NOISE_ERROR_NONE && free_error != NOISE_ERROR_NONE)
            error = noise_error(owner, "noise_dhstate_free", free_error);
    }
    return error;
}

static int configure(dmp_noise_owner *owner, const noise_fixture_probe_fixture_t *f,
                     noise_fixture_probe_bytes_t ephemeral, noise_fixture_probe_bytes_t static_key)
{
    uint8_t public_key[KEY_SIZE];
    NoiseDHState *local_static;
    int has_static = static_key.size != 0U;
    int error;
    if ((f->init_static.size != 0U) != (f->resp_static.size != 0U))
        return invalid(owner, "fixture static-key presence is inconsistent");
    error = derive_ephemeral(owner, ephemeral, public_key);
    if (error != NOISE_ERROR_NONE)
        return error;
    error = noise_handshakestate_set_local_ephemeral(
        owner->handshake, ephemeral.data, ephemeral.size, public_key, sizeof(public_key));
    if (error != NOISE_ERROR_NONE)
        return noise_error(owner, "noise_handshakestate_set_local_ephemeral", error);
    local_static = noise_handshakestate_get_local_keypair_dh(owner->handshake);
    if (has_static) {
        if (local_static == NULL ||
            noise_dhstate_get_private_key_length(local_static) != static_key.size ||
            noise_dhstate_get_public_key_length(local_static) != KEY_SIZE)
            return invalid(owner, "required local static-key state or length is invalid");
        error = noise_dhstate_set_keypair_private(local_static, static_key.data, static_key.size);
        if (error != NOISE_ERROR_NONE)
            return noise_error(owner, "noise_dhstate_set_keypair_private(static)", error);
    } else if (local_static != NULL) {
        return invalid(owner, "unexpected local static-key state");
    }
    if ((noise_handshakestate_needs_pre_shared_key(owner->handshake) != 0) != (f->psk.size != 0U))
        return invalid(owner, "provider PSK requirement differs from fixture pattern");
    if (f->psk.size != 0U) {
        error = noise_handshakestate_set_pre_shared_key(owner->handshake, f->psk.data, f->psk.size);
        if (error != NOISE_ERROR_NONE)
            return noise_error(owner, "noise_handshakestate_set_pre_shared_key", error);
    }
    error = noise_handshakestate_set_prologue(owner->handshake, f->prologue.data, f->prologue.size);
    return error == NOISE_ERROR_NONE
               ? error
               : noise_error(owner, "noise_handshakestate_set_prologue", error);
}

static int packet_valid(const dmp_noise_owner *owner, const noise_fixture_probe_packet_t *p)
{
    if (p->name == NULL || p->pn != 0U || !valid(p->aad, AEAD_CAP, 1) ||
        !valid(p->plaintext, PLAINTEXT_CAP, 1) || !valid(p->ciphertext, AEAD_CAP, 0) ||
        !valid(p->tag, TAG_SIZE, 1) || p->tag.size != TAG_SIZE ||
        p->ciphertext.size > AEAD_CAP - p->tag.size)
        return invalid(owner, "FINISH/READY packet exceeds fixture buffer bounds");
    return NOISE_ERROR_NONE;
}

size_t dmp_owner_fixture_count(void) { return NOISE_FIXTURE_PROBE_FIXTURE_COUNT; }

int dmp_owner_create(dmp_noise_owner *owner, size_t index, int role)
{
    const noise_fixture_probe_fixture_t *f;
    dmp_noise_owner candidate = {0};
    noise_fixture_probe_bytes_t ephemeral, static_key;
    int error;
    if (owner == NULL)
        return NOISE_ERROR_INVALID_PARAM;
    if (owner->handshake != NULL || owner->send != NULL || owner->receive != NULL)
        return NOISE_ERROR_INVALID_STATE;
    f = fixture_at(index);
    if (f == NULL || (role != NOISE_ROLE_INITIATOR && role != NOISE_ROLE_RESPONDER))
        return NOISE_ERROR_INVALID_PARAM;
    candidate.fixture_index = index;
    candidate.role = role;
    error = validate(&candidate, f);
    if (error != NOISE_ERROR_NONE)
        return error;
    error = noise_handshakestate_new_by_name(&candidate.handshake, f->protocol_name, role);
    if (error != NOISE_ERROR_NONE) {
        error = noise_error(&candidate, "noise_handshakestate_new_by_name", error);
        goto fail;
    }
    if (role == NOISE_ROLE_INITIATOR) {
        ephemeral = f->init_ephemeral;
        static_key = f->init_static;
    } else {
        ephemeral = f->resp_ephemeral;
        static_key = f->resp_static;
    }
    error = configure(&candidate, f, ephemeral, static_key);
    if (error != NOISE_ERROR_NONE)
        goto fail;
    error = noise_handshakestate_start(candidate.handshake);
    if (error != NOISE_ERROR_NONE) {
        error = noise_error(&candidate, "noise_handshakestate_start", error);
        goto fail;
    }
    if ((role == NOISE_ROLE_INITIATOR &&
         noise_handshakestate_get_action(candidate.handshake) != NOISE_ACTION_WRITE_MESSAGE) ||
        (role == NOISE_ROLE_RESPONDER &&
         noise_handshakestate_get_action(candidate.handshake) != NOISE_ACTION_READ_MESSAGE)) {
        error = invalid(&candidate, "initial Noise handshake action is unexpected");
        goto fail;
    }
    *owner = candidate;
    return NOISE_ERROR_NONE;
fail:
    if (candidate.handshake != NULL)
        (void)noise_handshakestate_free(candidate.handshake);
    memset(owner, 0, sizeof(*owner));
    return error;
}

int dmp_owner_step(dmp_noise_owner *owner, int corrupt)
{
    const noise_fixture_probe_fixture_t *f;
    const noise_fixture_probe_flight_t *flight;
    uint8_t message[MESSAGE_CAP], plaintext[PLAINTEXT_CAP], input[MESSAGE_CAP];
    uint8_t mutable_plaintext[PLAINTEXT_CAP], empty = 0U;
    NoiseBuffer msg, payload;
    int sends, error;
    if (owner == NULL || (corrupt != 0 && corrupt != 1))
        return NOISE_ERROR_INVALID_PARAM;
    f = fixture_at(owner->fixture_index);
    if (f == NULL || owner->handshake == NULL || owner->next_flight >= f->flight_count)
        return NOISE_ERROR_INVALID_STATE;
    flight = &f->flights[owner->next_flight];
    sends = ((owner->next_flight & 1U) == 0U) == (owner->role == NOISE_ROLE_INITIATOR);
    if (sends) {
        if (corrupt)
            return invalid(owner,
                           "corruption is supported only for incoming authenticated flights");
        if (noise_handshakestate_get_action(owner->handshake) != NOISE_ACTION_WRITE_MESSAGE)
            return invalid(owner, "local Noise endpoint is not ready to write this flight");
        if (flight->plaintext.size != 0U)
            memcpy(mutable_plaintext, flight->plaintext.data, flight->plaintext.size);
        noise_buffer_set_output(msg, message, sizeof(message));
        noise_buffer_set_input(payload, flight->plaintext.size == 0U ? &empty : mutable_plaintext,
                               flight->plaintext.size);
        error = noise_handshakestate_write_message(owner->handshake, &msg, &payload);
        if (error != NOISE_ERROR_NONE)
            return noise_error(owner, "noise_handshakestate_write_message", error);
        ++owner->writes;
        error = equal(owner, "written Noise flight", msg.data, msg.size, flight->message);
    } else {
        if (corrupt) {
            int is_xx = strcmp(f->protocol_name, "Noise_XX_25519_ChaChaPoly_SHA256") == 0;
            int is_nnpsk0 = strcmp(f->protocol_name, "Noise_NNpsk0_25519_ChaChaPoly_SHA256") == 0;
            int authenticated = is_xx ? owner->next_flight > 0U
                                      : (is_nnpsk0 && owner->next_flight + 1U == f->flight_count);
            if (!authenticated)
                return invalid(owner,
                               "corruption is supported only for incoming authenticated flights");
        }
        if (noise_handshakestate_get_action(owner->handshake) != NOISE_ACTION_READ_MESSAGE)
            return invalid(owner, "local Noise endpoint is not ready to read this flight");
        if (flight->message.size > sizeof(input) || flight->plaintext.size > sizeof(plaintext))
            return invalid(owner, "incoming Noise flight exceeds its fixed buffer");
        memcpy(input, flight->message.data, flight->message.size);
        if (corrupt) {
            if (flight->message.size <= TAG_SIZE)
                return invalid(owner, "authenticated incoming flight has no complete tag");
            input[flight->message.size - 1U] ^= 1U;
        }
        noise_buffer_set_input(msg, input, flight->message.size);
        noise_buffer_set_output(payload, plaintext, sizeof(plaintext));
        error = noise_handshakestate_read_message(owner->handshake, &msg, &payload);
        if (corrupt)
            return error == NOISE_ERROR_MAC_FAILURE
                       ? error
                       : (error == NOISE_ERROR_NONE
                              ? invalid(owner,
                                        "tampered authenticated flight unexpectedly succeeded")
                              : noise_error(owner, "noise_handshakestate_read_message", error));
        if (error != NOISE_ERROR_NONE)
            return noise_error(owner, "noise_handshakestate_read_message", error);
        error = equal(owner, "decrypted Noise flight plaintext", payload.data, payload.size,
                      flight->plaintext);
    }
    if (error != NOISE_ERROR_NONE)
        return error;
    ++owner->next_flight;
    return NOISE_ERROR_NONE;
}

int dmp_owner_complete(dmp_noise_owner *owner)
{
    const noise_fixture_probe_fixture_t *f;
    uint8_t hash[HASH_SIZE];
    int error;
    if (owner == NULL)
        return NOISE_ERROR_INVALID_PARAM;
    f = fixture_at(owner->fixture_index);
    if (f == NULL || owner->handshake == NULL || owner->send != NULL || owner->receive != NULL)
        return NOISE_ERROR_INVALID_STATE;
    while (owner->next_flight < f->flight_count) {
        error = dmp_owner_step(owner, 0);
        if (error != NOISE_ERROR_NONE)
            return error;
    }
    if (noise_handshakestate_get_action(owner->handshake) != NOISE_ACTION_SPLIT)
        return invalid(owner, "handshake did not reach SPLIT");
    error = noise_handshakestate_get_handshake_hash(owner->handshake, hash, sizeof(hash));
    if (error != NOISE_ERROR_NONE)
        return noise_error(owner, "noise_handshakestate_get_handshake_hash", error);
    error = equal(owner, "Noise handshake hash", hash, sizeof(hash), f->handshake_hash);
    if (error != NOISE_ERROR_NONE)
        return error;
    error = noise_handshakestate_split(owner->handshake, &owner->send, &owner->receive);
    if (error != NOISE_ERROR_NONE)
        return noise_error(owner, "noise_handshakestate_split", error);
    if (noise_handshakestate_get_action(owner->handshake) != NOISE_ACTION_COMPLETE)
        return invalid(owner, "Noise Split did not complete");
    error = noise_handshakestate_free(owner->handshake);
    if (error != NOISE_ERROR_NONE)
        return noise_error(owner, "noise_handshakestate_free after Split", error);
    owner->handshake = NULL;
    return NOISE_ERROR_NONE;
}

int dmp_owner_send_once(dmp_noise_owner *owner)
{
    const noise_fixture_probe_fixture_t *f;
    const noise_fixture_probe_packet_t *p;
    uint8_t encrypted[AEAD_CAP], expected[AEAD_CAP];
    NoiseBuffer buffer;
    size_t expected_size;
    int error;
    if (owner == NULL)
        return NOISE_ERROR_INVALID_PARAM;
    if (owner->send == NULL || owner->handshake != NULL || owner->sent)
        return NOISE_ERROR_INVALID_STATE;
    f = fixture_at(owner->fixture_index);
    if (f == NULL)
        return NOISE_ERROR_INVALID_STATE;
    p = owner->role == NOISE_ROLE_INITIATOR ? &f->finish : &f->ready;
    error = packet_valid(owner, p);
    if (error != NOISE_ERROR_NONE)
        return error;
    if (noise_cipherstate_get_key_length(owner->send) != KEY_SIZE ||
        p->ciphertext.size + p->tag.size > sizeof(encrypted))
        return invalid(owner, "send key or encrypted fixture length is invalid");
    owner->sent = 1;
    if (p->plaintext.size != 0U)
        memcpy(encrypted, p->plaintext.data, p->plaintext.size);
    noise_buffer_set_inout(buffer, encrypted, p->plaintext.size, sizeof(encrypted));
    error = noise_cipherstate_set_nonce(owner->send, p->pn);
    if (error != NOISE_ERROR_NONE)
        return noise_error(owner, "noise_cipherstate_set_nonce(send)", error);
    error = noise_cipherstate_encrypt_with_ad(owner->send, p->aad.data, p->aad.size, &buffer);
    if (error != NOISE_ERROR_NONE)
        return noise_error(owner, "noise_cipherstate_encrypt_with_ad", error);
    ++owner->writes;
    expected_size = p->ciphertext.size + p->tag.size;
    if (p->ciphertext.size != 0U)
        memcpy(expected, p->ciphertext.data, p->ciphertext.size);
    memcpy(expected + p->ciphertext.size, p->tag.data, p->tag.size);
    return equal(owner, "encrypted FINISH/READY bytes", buffer.data, buffer.size,
                 (noise_fixture_probe_bytes_t){expected, expected_size});
}

int dmp_owner_receive(dmp_noise_owner *owner, int corrupt)
{
    const noise_fixture_probe_fixture_t *f;
    const noise_fixture_probe_packet_t *p;
    uint8_t encrypted[AEAD_CAP];
    NoiseBuffer buffer;
    size_t size;
    int error;
    if (owner == NULL || (corrupt != 0 && corrupt != 1))
        return NOISE_ERROR_INVALID_PARAM;
    if (owner->receive == NULL || owner->handshake != NULL)
        return NOISE_ERROR_INVALID_STATE;
    f = fixture_at(owner->fixture_index);
    if (f == NULL)
        return NOISE_ERROR_INVALID_STATE;
    p = owner->role == NOISE_ROLE_INITIATOR ? &f->ready : &f->finish;
    error = packet_valid(owner, p);
    if (error != NOISE_ERROR_NONE)
        return error;
    size = p->ciphertext.size + p->tag.size;
    if (size > sizeof(encrypted) || noise_cipherstate_get_key_length(owner->receive) != KEY_SIZE)
        return invalid(owner, "receive key or encrypted fixture length is invalid");
    if (p->ciphertext.size != 0U)
        memcpy(encrypted, p->ciphertext.data, p->ciphertext.size);
    memcpy(encrypted + p->ciphertext.size, p->tag.data, p->tag.size);
    if (corrupt)
        encrypted[size - 1U] ^= 1U;
    noise_buffer_set_inout(buffer, encrypted, size, sizeof(encrypted));
    error = noise_cipherstate_decrypt_with_ad_at_nonce(owner->receive, p->pn, p->aad.data,
                                                       p->aad.size, &buffer);
    if (corrupt)
        return error == NOISE_ERROR_MAC_FAILURE
                   ? error
                   : (error == NOISE_ERROR_NONE
                          ? invalid(owner, "tampered packet authenticated")
                          : noise_error(owner, "noise_cipherstate_decrypt_with_ad_at_nonce",
                                        error));
    if (error != NOISE_ERROR_NONE)
        return noise_error(owner, "noise_cipherstate_decrypt_with_ad_at_nonce", error);
    return equal(owner, "decrypted FINISH/READY plaintext", buffer.data, buffer.size, p->plaintext);
}

int dmp_owner_close(dmp_noise_owner *owner)
{
    int first = NOISE_ERROR_NONE, error;
    if (owner == NULL)
        return NOISE_ERROR_INVALID_PARAM;
    if (owner->handshake != NULL) {
        error = noise_handshakestate_free(owner->handshake);
        if (error != NOISE_ERROR_NONE)
            first = noise_error(owner, "noise_handshakestate_free", error);
        owner->handshake = NULL;
    }
    if (owner->send != NULL) {
        error = noise_cipherstate_free(owner->send);
        if (error != NOISE_ERROR_NONE && first == NOISE_ERROR_NONE)
            first = noise_error(owner, "noise_cipherstate_free(send)", error);
        owner->send = NULL;
    }
    if (owner->receive != NULL) {
        error = noise_cipherstate_free(owner->receive);
        if (error != NOISE_ERROR_NONE && first == NOISE_ERROR_NONE)
            first = noise_error(owner, "noise_cipherstate_free(receive)", error);
        owner->receive = NULL;
    }
    memset(owner, 0, sizeof(*owner));
    return first;
}
