#include "provider_port.h"

#include "dmp_sodium_entropy.h"

#include <noise/protocol.h>

#include <string.h>

#define DMP_PROVIDER_MAGIC 0xD301B001u
#define DMP_PROVIDER_HANDSHAKE_MAGIC 0xD301B011u
#define DMP_PROVIDER_CIPHER_MAGIC 0xD301B021u
#define DMP_PROVIDER_BLOCK_SLOTS 64u
#define DMP_PROVIDER_CHILD_SLOTS 8u
#define DMP_PROVIDER_KEY_LEN 32u
#define DMP_PROVIDER_HASH_LEN 32u
#define DMP_PROVIDER_MAC_LEN 16u
#define DMP_PROVIDER_SUITE_NNPSK0 "Noise_NNpsk0_25519_ChaChaPoly_SHA256"
#define DMP_PROVIDER_SUITE_XX "Noise_XX_25519_ChaChaPoly_SHA256"

typedef struct dmp_provider_block {
    void *ptr;
    size_t size;
} dmp_provider_block;

typedef struct dmp_provider_child {
    void *object;
    size_t size;
} dmp_provider_child;

struct dmp_provider {
    uint32_t magic;
    int ready;
    int in_setup;
    int entropy_failed;
    int init_failed;
    dmp_provider_ports ports;
    size_t retained;
    size_t block_count;
    size_t child_count;
    dmp_provider_block blocks[DMP_PROVIDER_BLOCK_SLOTS];
    dmp_provider_child children[DMP_PROVIDER_CHILD_SLOTS];
};

typedef struct dmp_provider_handshake_body {
    uint32_t magic;
    uint32_t secret_len;
    NoiseHandshakeState *state;
    uint8_t secret[DMP_PROVIDER_KEY_LEN];
} dmp_provider_handshake_body;

typedef struct dmp_provider_cipher_body {
    uint32_t magic;
    uint32_t reserved;
    NoiseCipherState *state;
} dmp_provider_cipher_body;

static dmp_provider *g_active;

_Static_assert(sizeof(dmp_provider_handshake_body) <= sizeof(dmp_provider_handshake),
               "handshake object is smaller than its private body");
_Static_assert(sizeof(dmp_provider_cipher_body) <= sizeof(dmp_provider_cipher),
               "cipher object is smaller than its private body");

static void wipe(void *data, size_t size)
{
    if (data != NULL && size != 0U) {
        noise_clean(data, size);
    }
}

static int provider_live(const dmp_provider *provider)
{
    return provider != NULL && provider->magic == DMP_PROVIDER_MAGIC &&
           provider->ready && g_active == provider;
}

static dmp_provider_handshake_body *handshake_body(dmp_provider_handshake *handshake)
{
    return (dmp_provider_handshake_body *)handshake;
}

static const dmp_provider_handshake_body *handshake_body_const(
    const dmp_provider_handshake *handshake)
{
    return (const dmp_provider_handshake_body *)handshake;
}

static dmp_provider_cipher_body *cipher_body(dmp_provider_cipher *cipher)
{
    return (dmp_provider_cipher_body *)cipher;
}

static int supported_suite(const char *protocol_name)
{
    return protocol_name != NULL &&
           (strcmp(protocol_name, DMP_PROVIDER_SUITE_NNPSK0) == 0 ||
            strcmp(protocol_name, DMP_PROVIDER_SUITE_XX) == 0);
}

static int register_child(dmp_provider *provider, void *object, size_t size)
{
    if (provider->child_count >= DMP_PROVIDER_CHILD_SLOTS) {
        return 0;
    }
    provider->children[provider->child_count].object = object;
    provider->children[provider->child_count].size = size;
    provider->child_count++;
    return 1;
}

static void unregister_child(dmp_provider *provider, void *object)
{
    size_t index;

    for (index = 0U; index < provider->child_count; ++index) {
        if (provider->children[index].object == object) {
            provider->children[index] = provider->children[provider->child_count - 1U];
            provider->child_count--;
            return;
        }
    }
}

static dmp_provider_status map_noise(dmp_provider *provider, int error)
{
    if (provider->entropy_failed) {
        provider->entropy_failed = 0;
        return DMP_PROVIDER_ENTROPY_FAILED;
    }
    if (error == NOISE_ERROR_NONE) {
        return DMP_PROVIDER_OK;
    }
    if (error == NOISE_ERROR_NO_MEMORY) {
        return DMP_PROVIDER_NO_MEMORY;
    }
    if (error == NOISE_ERROR_INVALID_PARAM || error == NOISE_ERROR_INVALID_LENGTH ||
        error == NOISE_ERROR_INVALID_STATE) {
        return DMP_PROVIDER_INVALID;
    }
    return DMP_PROVIDER_REJECTED;
}

static void wipe_output(uint8_t *buffer, size_t capacity, size_t *length)
{
    if (length != NULL) {
        *length = 0U;
    }
    wipe(buffer, capacity);
}

static int remember_block(dmp_provider *provider, void *ptr, size_t size)
{
    if (provider->block_count >= DMP_PROVIDER_BLOCK_SLOTS) {
        return 0;
    }
    provider->blocks[provider->block_count].ptr = ptr;
    provider->blocks[provider->block_count].size = size;
    provider->block_count++;
    provider->retained += size;
    return 1;
}

static void forget_block(dmp_provider *provider, void *ptr)
{
    size_t index;

    for (index = 0U; index < provider->block_count; ++index) {
        if (provider->blocks[index].ptr == ptr) {
            size_t size = provider->blocks[index].size;

            if (provider->retained >= size) {
                provider->retained -= size;
            } else {
                provider->retained = 0U;
            }
            provider->blocks[index] = provider->blocks[provider->block_count - 1U];
            provider->block_count--;
            return;
        }
    }
}

int noise_rand_bytes_checked(void *bytes, size_t size)
{
    dmp_provider *provider = g_active;
    int result;

    if (bytes == NULL) {
        return NOISE_ERROR_INVALID_PARAM;
    }
    if (size == 0U) {
        return NOISE_ERROR_NONE;
    }
    if (provider == NULL || provider->ports.entropy == NULL ||
        (!provider->ready && !provider->in_setup)) {
        wipe(bytes, size);
        return NOISE_ERROR_INVALID_STATE;
    }
    result = provider->ports.entropy(provider->ports.ctx, bytes, size);
    if (result != 0) {
        provider->entropy_failed = 1;
        wipe(bytes, size);
        return NOISE_ERROR_SYSTEM;
    }
    return NOISE_ERROR_NONE;
}

void *noise_allocator_allocate(size_t size)
{
    dmp_provider *provider = g_active;
    void *ptr;

    if (provider == NULL || provider->ports.allocate == NULL || size == 0U ||
        (!provider->ready && !provider->in_setup)) {
        return NULL;
    }
    if (size > provider->ports.scratch_limit ||
        provider->block_count >= DMP_PROVIDER_BLOCK_SLOTS ||
        size > provider->ports.retained_limit - provider->retained) {
        return NULL;
    }
    ptr = provider->ports.allocate(provider->ports.ctx, size);
    if (ptr == NULL) {
        return NULL;
    }
    if (!remember_block(provider, ptr, size)) {
        provider->ports.release(provider->ports.ctx, ptr, size);
        return NULL;
    }
    return ptr;
}

void noise_allocator_release(void *ptr, size_t size)
{
    dmp_provider *provider = g_active;
    size_t tracked = size;
    size_t index;
    int found = 0;

    (void)size;
    if (provider == NULL || ptr == NULL || provider->ports.release == NULL) {
        return;
    }
    for (index = 0U; index < provider->block_count; ++index) {
        if (provider->blocks[index].ptr == ptr) {
            tracked = provider->blocks[index].size;
            found = 1;
            break;
        }
    }
    if (!found) {
        return;
    }
    forget_block(provider, ptr);
    provider->ports.release(provider->ports.ctx, ptr, tracked);
}

int dmp_sodium_entropy_ready(void)
{
    dmp_provider *provider = g_active;

    if (provider == NULL || provider->ports.startup_ready == NULL) {
        return 1;
    }
    if (provider->ports.startup_ready(provider->ports.ctx) != 0) {
        provider->init_failed = 1;
        return 1;
    }
    return 0;
}

int dmp_sodium_entropy_read(void *bytes, size_t size)
{
    dmp_provider *provider = g_active;
    int result;

    if (provider == NULL || provider->ports.startup_read == NULL ||
        (bytes == NULL && size != 0U)) {
        return 1;
    }
    if (size == 0U) {
        return 0;
    }
    result = provider->ports.startup_read(provider->ports.ctx, bytes, size);
    if (result != 0) {
        provider->init_failed = 1;
        wipe(bytes, size);
        return 1;
    }
    return 0;
}

size_t dmp_provider_size(void)
{
    return sizeof(dmp_provider);
}

size_t dmp_provider_block_count(const dmp_provider *provider)
{
    if (!provider_live(provider)) {
        return 0U;
    }
    return provider->block_count;
}

size_t dmp_provider_retained(const dmp_provider *provider)
{
    if (!provider_live(provider)) {
        return 0U;
    }
    return provider->retained;
}

static int ports_usable(const dmp_provider_ports *ports)
{
    if (ports == NULL || ports->startup_ready == NULL || ports->startup_read == NULL ||
        ports->entropy == NULL || ports->allocate == NULL || ports->release == NULL) {
        return 0;
    }
    if (ports->scratch_limit == 0U || ports->scratch_limit > DMP_PROVIDER_SCRATCH_MAX ||
        ports->retained_limit == 0U || ports->retained_limit > DMP_PROVIDER_RETAINED_MAX ||
        ports->scratch_limit > ports->retained_limit) {
        return 0;
    }
    return 1;
}

dmp_provider_status dmp_provider_setup(dmp_provider *provider, const dmp_provider_ports *ports)
{
    int error;

    if (provider == NULL || !ports_usable(ports) || g_active != NULL) {
        return DMP_PROVIDER_INVALID;
    }
    memset(provider, 0, sizeof(*provider));
    provider->ports = *ports;
    provider->in_setup = 1;
    g_active = provider;
    error = noise_init_framework();
    if (error != NOISE_ERROR_NONE || provider->init_failed) {
        g_active = NULL;
        wipe(provider, sizeof(*provider));
        return DMP_PROVIDER_SETUP_FAILED;
    }
    provider->in_setup = 0;
    provider->ready = 1;
    provider->magic = DMP_PROVIDER_MAGIC;
    return DMP_PROVIDER_OK;
}

void dmp_provider_cleanup(dmp_provider *provider)
{
    dmp_provider_child saved[DMP_PROVIDER_CHILD_SLOTS];
    size_t child_count;
    size_t index;

    if (provider == NULL || provider->magic != DMP_PROVIDER_MAGIC) {
        return;
    }
    child_count = provider->child_count;
    memcpy(saved, provider->children, sizeof(saved));
    while (provider->block_count > 0U) {
        size_t last = provider->block_count - 1U;
        void *ptr = provider->blocks[last].ptr;
        size_t size = provider->blocks[last].size;

        noise_free(ptr, size);
    }
    if (g_active == provider) {
        g_active = NULL;
    }
    for (index = 0U; index < child_count; ++index) {
        wipe(saved[index].object, saved[index].size);
    }
    wipe(provider, sizeof(*provider));
}

static dmp_provider_status fail_handshake(dmp_provider *provider,
                                          dmp_provider_handshake *handshake,
                                          NoiseHandshakeState *state,
                                          dmp_provider_status status)
{
    if (state != NULL) {
        (void)noise_handshakestate_free(state);
    }
    wipe(handshake, sizeof(*handshake));
    provider->entropy_failed = 0;
    return status;
}

static int map_role(int role, int *noise_role)
{
    if (role == DMP_PROVIDER_ROLE_INITIATOR) {
        *noise_role = NOISE_ROLE_INITIATOR;
        return 1;
    }
    if (role == DMP_PROVIDER_ROLE_RESPONDER) {
        *noise_role = NOISE_ROLE_RESPONDER;
        return 1;
    }
    return 0;
}

static dmp_provider_status install_ephemeral(NoiseHandshakeState *state,
                                            const uint8_t *private_key)
{
    NoiseDHState *dh = NULL;
    uint8_t public_key[DMP_PROVIDER_KEY_LEN];
    int error;
    dmp_provider_status status = DMP_PROVIDER_REJECTED;

    error = noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519);
    if (error != NOISE_ERROR_NONE || dh == NULL) {
        status = error == NOISE_ERROR_NO_MEMORY ? DMP_PROVIDER_NO_MEMORY : DMP_PROVIDER_REJECTED;
        goto done;
    }
    error = noise_dhstate_set_keypair_private(dh, private_key, DMP_PROVIDER_KEY_LEN);
    if (error != NOISE_ERROR_NONE) {
        goto done;
    }
    error = noise_dhstate_get_public_key(dh, public_key, sizeof(public_key));
    if (error != NOISE_ERROR_NONE) {
        goto done;
    }
    error = noise_handshakestate_set_local_ephemeral(
        state, private_key, DMP_PROVIDER_KEY_LEN, public_key, sizeof(public_key));
    if (error == NOISE_ERROR_NONE) {
        status = DMP_PROVIDER_OK;
    } else if (error == NOISE_ERROR_NO_MEMORY) {
        status = DMP_PROVIDER_NO_MEMORY;
    }

done:
    wipe(public_key, sizeof(public_key));
    if (dh != NULL) {
        (void)noise_dhstate_free(dh);
    }
    return status;
}

dmp_provider_status dmp_provider_handshake_open(
    dmp_provider *provider, dmp_provider_handshake *handshake,
    const char *protocol_name, int role, const dmp_provider_handshake_keys *keys)
{
    dmp_provider_handshake_body *body;
    NoiseHandshakeState *state = NULL;
    NoiseDHState *static_dh;
    int noise_role = 0;
    int error;
    int needs_psk;
    int needs_static;
    uint8_t empty = 0U;
    const void *prologue;
    dmp_provider_status status;

    if (!provider_live(provider) || handshake == NULL || keys == NULL || !map_role(role, &noise_role)) {
        return DMP_PROVIDER_INVALID;
    }
    if (protocol_name == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    if (!supported_suite(protocol_name)) {
        return DMP_PROVIDER_UNSUPPORTED;
    }
    provider->entropy_failed = 0;
    wipe(handshake, sizeof(*handshake));
    error = noise_handshakestate_new_by_name(&state, protocol_name, noise_role);
    if (error != NOISE_ERROR_NONE || state == NULL) {
        return fail_handshake(provider, handshake, state, map_noise(provider, error));
    }
    if (keys->local_ephemeral_len != 0U) {
        if (keys->local_ephemeral == NULL || keys->local_ephemeral_len != DMP_PROVIDER_KEY_LEN) {
            return fail_handshake(provider, handshake, state, DMP_PROVIDER_INVALID);
        }
        status = install_ephemeral(state, keys->local_ephemeral);
        if (status != DMP_PROVIDER_OK) {
            return fail_handshake(provider, handshake, state, status);
        }
    }
    needs_static = noise_handshakestate_needs_local_keypair(state) != 0;
    if (needs_static != (keys->local_static_len != 0U)) {
        return fail_handshake(provider, handshake, state, DMP_PROVIDER_INVALID);
    }
    if (needs_static) {
        if (keys->local_static == NULL || keys->local_static_len != DMP_PROVIDER_KEY_LEN) {
            return fail_handshake(provider, handshake, state, DMP_PROVIDER_INVALID);
        }
        static_dh = noise_handshakestate_get_local_keypair_dh(state);
        if (static_dh == NULL) {
            return fail_handshake(provider, handshake, state, DMP_PROVIDER_INVALID);
        }
        error = noise_dhstate_set_keypair_private(static_dh, keys->local_static,
                                                  DMP_PROVIDER_KEY_LEN);
        if (error != NOISE_ERROR_NONE) {
            return fail_handshake(provider, handshake, state, map_noise(provider, error));
        }
    }
    needs_psk = noise_handshakestate_needs_pre_shared_key(state) != 0;
    if (needs_psk != (keys->psk_len != 0U)) {
        return fail_handshake(provider, handshake, state, DMP_PROVIDER_INVALID);
    }
    if (needs_psk) {
        if (keys->psk == NULL || keys->psk_len != DMP_PROVIDER_KEY_LEN) {
            return fail_handshake(provider, handshake, state, DMP_PROVIDER_INVALID);
        }
        error = noise_handshakestate_set_pre_shared_key(state, keys->psk, DMP_PROVIDER_KEY_LEN);
        if (error != NOISE_ERROR_NONE) {
            return fail_handshake(provider, handshake, state, map_noise(provider, error));
        }
    }
    if (keys->prologue_len != 0U && keys->prologue == NULL) {
        return fail_handshake(provider, handshake, state, DMP_PROVIDER_INVALID);
    }
    prologue = keys->prologue_len == 0U ? (const void *)&empty : (const void *)keys->prologue;
    error = noise_handshakestate_set_prologue(state, prologue, keys->prologue_len);
    if (error != NOISE_ERROR_NONE) {
        return fail_handshake(provider, handshake, state, map_noise(provider, error));
    }
    error = noise_handshakestate_start(state);
    if (error != NOISE_ERROR_NONE) {
        return fail_handshake(provider, handshake, state, map_noise(provider, error));
    }
    if (!register_child(provider, handshake, sizeof(*handshake))) {
        return fail_handshake(provider, handshake, state, DMP_PROVIDER_NO_MEMORY);
    }
    body = handshake_body(handshake);
    body->magic = DMP_PROVIDER_HANDSHAKE_MAGIC;
    body->state = state;
    if (needs_psk) {
        memcpy(body->secret, keys->psk, DMP_PROVIDER_KEY_LEN);
        body->secret_len = DMP_PROVIDER_KEY_LEN;
    }
    return DMP_PROVIDER_OK;
}

dmp_provider_status dmp_provider_handshake_write(
    dmp_provider *provider, dmp_provider_handshake *handshake,
    const uint8_t *payload, size_t payload_len, uint8_t *message,
    size_t message_cap, size_t *message_len)
{
    dmp_provider_handshake_body *body;
    NoiseBuffer message_buffer;
    NoiseBuffer payload_buffer;
    uint8_t empty = 0U;
    const uint8_t *payload_bytes;
    int error;

    if (!provider_live(provider) || handshake == NULL || message == NULL ||
        message_len == NULL || message_cap == 0U ||
        (payload == NULL && payload_len != 0U)) {
        return DMP_PROVIDER_INVALID;
    }
    body = handshake_body(handshake);
    if (body->magic != DMP_PROVIDER_HANDSHAKE_MAGIC || body->state == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    provider->entropy_failed = 0;
    *message_len = 0U;
    payload_bytes = payload_len == 0U ? &empty : payload;
    noise_buffer_set_output(message_buffer, message, message_cap);
    noise_buffer_set_input(payload_buffer, (uint8_t *)payload_bytes, payload_len);
    error = noise_handshakestate_write_message(body->state, &message_buffer, &payload_buffer);
    if (error != NOISE_ERROR_NONE) {
        wipe_output(message, message_cap, message_len);
        return map_noise(provider, error);
    }
    *message_len = message_buffer.size;
    return DMP_PROVIDER_OK;
}

dmp_provider_status dmp_provider_handshake_read(
    dmp_provider *provider, dmp_provider_handshake *handshake,
    const uint8_t *message, size_t message_len, uint8_t *payload,
    size_t payload_cap, size_t *payload_len)
{
    dmp_provider_handshake_body *body;
    NoiseBuffer message_buffer;
    NoiseBuffer payload_buffer;
    uint8_t message_copy[512];
    int error;

    if (!provider_live(provider) || handshake == NULL || payload == NULL ||
        payload_len == NULL || (message == NULL && message_len != 0U) ||
        message_len > sizeof(message_copy) || payload_cap == 0U) {
        return DMP_PROVIDER_INVALID;
    }
    body = handshake_body(handshake);
    if (body->magic != DMP_PROVIDER_HANDSHAKE_MAGIC || body->state == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    provider->entropy_failed = 0;
    *payload_len = 0U;
    if (message_len != 0U) {
        memcpy(message_copy, message, message_len);
    }
    noise_buffer_set_input(message_buffer, message_copy, message_len);
    noise_buffer_set_output(payload_buffer, payload, payload_cap);
    error = noise_handshakestate_read_message(body->state, &message_buffer, &payload_buffer);
    wipe(message_copy, sizeof(message_copy));
    if (error != NOISE_ERROR_NONE) {
        wipe_output(payload, payload_cap, payload_len);
        return map_noise(provider, error);
    }
    *payload_len = payload_buffer.size;
    return DMP_PROVIDER_OK;
}

dmp_provider_status dmp_provider_handshake_hash(
    dmp_provider *provider, const dmp_provider_handshake *handshake, uint8_t hash[32])
{
    const dmp_provider_handshake_body *body;
    int error;

    if (!provider_live(provider) || handshake == NULL || hash == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    body = handshake_body_const(handshake);
    if (body->magic != DMP_PROVIDER_HANDSHAKE_MAGIC || body->state == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    error = noise_handshakestate_get_handshake_hash(body->state, hash, DMP_PROVIDER_HASH_LEN);
    if (error != NOISE_ERROR_NONE) {
        wipe(hash, DMP_PROVIDER_HASH_LEN);
        return map_noise((dmp_provider *)provider, error);
    }
    return DMP_PROVIDER_OK;
}

dmp_provider_status dmp_provider_handshake_remote_public(
    dmp_provider *provider, const dmp_provider_handshake *handshake,
    uint8_t public_key[32])
{
    const dmp_provider_handshake_body *body;
    NoiseDHState *remote;
    int error;

    if (!provider_live(provider) || handshake == NULL || public_key == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    body = handshake_body_const(handshake);
    if (body->magic != DMP_PROVIDER_HANDSHAKE_MAGIC || body->state == NULL) {
        wipe(public_key, DMP_PROVIDER_KEY_LEN);
        return DMP_PROVIDER_INVALID;
    }
    if (noise_handshakestate_has_remote_public_key(body->state) == 0) {
        wipe(public_key, DMP_PROVIDER_KEY_LEN);
        return DMP_PROVIDER_REJECTED;
    }
    remote = noise_handshakestate_get_remote_public_key_dh(body->state);
    if (remote == NULL) {
        wipe(public_key, DMP_PROVIDER_KEY_LEN);
        return DMP_PROVIDER_REJECTED;
    }
    error = noise_dhstate_get_public_key(remote, public_key, DMP_PROVIDER_KEY_LEN);
    if (error != NOISE_ERROR_NONE) {
        wipe(public_key, DMP_PROVIDER_KEY_LEN);
        return map_noise(provider, error);
    }
    return DMP_PROVIDER_OK;
}

dmp_provider_status dmp_provider_handshake_split(
    dmp_provider *provider, dmp_provider_handshake *handshake,
    dmp_provider_cipher *send, dmp_provider_cipher *receive)
{
    dmp_provider_handshake_body *body;
    dmp_provider_cipher_body *send_body;
    dmp_provider_cipher_body *receive_body;
    NoiseCipherState *send_state = NULL;
    NoiseCipherState *receive_state = NULL;
    int error;

    if (!provider_live(provider) || handshake == NULL || send == NULL || receive == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    body = handshake_body(handshake);
    if (body->magic != DMP_PROVIDER_HANDSHAKE_MAGIC || body->state == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    wipe(send, sizeof(*send));
    wipe(receive, sizeof(*receive));
    if (noise_handshakestate_get_action(body->state) != NOISE_ACTION_SPLIT) {
        return DMP_PROVIDER_REJECTED;
    }
    error = noise_handshakestate_split(body->state, &send_state, &receive_state);
    if (error != NOISE_ERROR_NONE || send_state == NULL || receive_state == NULL) {
        if (send_state != NULL) {
            (void)noise_cipherstate_free(send_state);
        }
        if (receive_state != NULL) {
            (void)noise_cipherstate_free(receive_state);
        }
        return map_noise(provider, error == NOISE_ERROR_NONE ? NOISE_ERROR_INVALID_STATE : error);
    }
    if (!register_child(provider, send, sizeof(*send)) ||
        !register_child(provider, receive, sizeof(*receive))) {
        (void)noise_cipherstate_free(send_state);
        (void)noise_cipherstate_free(receive_state);
        unregister_child(provider, send);
        unregister_child(provider, receive);
        wipe(send, sizeof(*send));
        wipe(receive, sizeof(*receive));
        return DMP_PROVIDER_NO_MEMORY;
    }
    send_body = cipher_body(send);
    receive_body = cipher_body(receive);
    send_body->magic = DMP_PROVIDER_CIPHER_MAGIC;
    send_body->state = send_state;
    receive_body->magic = DMP_PROVIDER_CIPHER_MAGIC;
    receive_body->state = receive_state;
    return DMP_PROVIDER_OK;
}

dmp_provider_status dmp_provider_handshake_close(dmp_provider *provider,
                                                dmp_provider_handshake *handshake)
{
    dmp_provider_handshake_body *body;

    if (!provider_live(provider) || handshake == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    body = handshake_body(handshake);
    if (body->magic != DMP_PROVIDER_HANDSHAKE_MAGIC) {
        return DMP_PROVIDER_INVALID;
    }
    if (body->state != NULL) {
        (void)noise_handshakestate_free(body->state);
    }
    unregister_child(provider, handshake);
    wipe(handshake, sizeof(*handshake));
    return DMP_PROVIDER_OK;
}

dmp_provider_status dmp_provider_cipher_from_key(
    dmp_provider *provider, dmp_provider_cipher *cipher, const uint8_t *key,
    size_t key_len)
{
    dmp_provider_cipher_body *body;
    NoiseCipherState *state = NULL;
    int error;

    if (!provider_live(provider) || cipher == NULL || key == NULL ||
        key_len != DMP_PROVIDER_KEY_LEN) {
        return DMP_PROVIDER_INVALID;
    }
    wipe(cipher, sizeof(*cipher));
    error = noise_cipherstate_new_by_id(&state, NOISE_CIPHER_CHACHAPOLY);
    if (error != NOISE_ERROR_NONE || state == NULL) {
        if (state != NULL) {
            (void)noise_cipherstate_free(state);
        }
        return state == NULL && error == NOISE_ERROR_NONE ? DMP_PROVIDER_NO_MEMORY
                                                         : map_noise(provider, error);
    }
    if (noise_cipherstate_get_mac_length(state) != DMP_PROVIDER_MAC_LEN ||
        noise_cipherstate_get_key_length(state) != DMP_PROVIDER_KEY_LEN) {
        (void)noise_cipherstate_free(state);
        return DMP_PROVIDER_UNSUPPORTED;
    }
    error = noise_cipherstate_init_key(state, key, key_len);
    if (error != NOISE_ERROR_NONE) {
        (void)noise_cipherstate_free(state);
        return map_noise(provider, error);
    }
    if (!register_child(provider, cipher, sizeof(*cipher))) {
        (void)noise_cipherstate_free(state);
        return DMP_PROVIDER_NO_MEMORY;
    }
    body = cipher_body(cipher);
    body->magic = DMP_PROVIDER_CIPHER_MAGIC;
    body->state = state;
    return DMP_PROVIDER_OK;
}

dmp_provider_status dmp_provider_cipher_encrypt(
    dmp_provider *provider, dmp_provider_cipher *cipher, uint64_t packet_number,
    const uint8_t *aad, size_t aad_len, uint8_t *buffer, size_t plaintext_len,
    size_t buffer_cap, size_t *out_len)
{
    dmp_provider_cipher_body *body;
    NoiseBuffer noise_buffer;
    int error;

    if (!provider_live(provider) || cipher == NULL || buffer == NULL || out_len == NULL ||
        (aad == NULL && aad_len != 0U) || packet_number == UINT64_MAX) {
        return DMP_PROVIDER_INVALID;
    }
    body = cipher_body(cipher);
    if (body->magic != DMP_PROVIDER_CIPHER_MAGIC || body->state == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    *out_len = 0U;
    error = noise_cipherstate_set_nonce(body->state, packet_number);
    if (error != NOISE_ERROR_NONE) {
        wipe_output(buffer, buffer_cap, out_len);
        return map_noise(provider, error);
    }
    noise_buffer_set_inout(noise_buffer, buffer, plaintext_len, buffer_cap);
    error = noise_cipherstate_encrypt_with_ad(body->state, aad, aad_len, &noise_buffer);
    if (error != NOISE_ERROR_NONE) {
        wipe_output(buffer, buffer_cap, out_len);
        return map_noise(provider, error);
    }
    *out_len = noise_buffer.size;
    return DMP_PROVIDER_OK;
}

dmp_provider_status dmp_provider_cipher_decrypt(
    dmp_provider *provider, dmp_provider_cipher *cipher, uint64_t packet_number,
    const uint8_t *aad, size_t aad_len, uint8_t *buffer, size_t cipher_len,
    size_t buffer_cap, size_t *out_len)
{
    dmp_provider_cipher_body *body;
    NoiseBuffer noise_buffer;
    int error;

    if (!provider_live(provider) || cipher == NULL || buffer == NULL || out_len == NULL ||
        (aad == NULL && aad_len != 0U) || packet_number == UINT64_MAX ||
        cipher_len > buffer_cap) {
        return DMP_PROVIDER_INVALID;
    }
    body = cipher_body(cipher);
    if (body->magic != DMP_PROVIDER_CIPHER_MAGIC || body->state == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    *out_len = 0U;
    noise_buffer_set_inout(noise_buffer, buffer, cipher_len, buffer_cap);
    /* Explicit packet number. The saved monotonic counter is restored and a
     * failed tag does not commit a receive. */
    error = noise_cipherstate_decrypt_with_ad_at_nonce(
        body->state, packet_number, aad, aad_len, &noise_buffer);
    if (error != NOISE_ERROR_NONE) {
        wipe_output(buffer, buffer_cap, out_len);
        return map_noise(provider, error);
    }
    *out_len = noise_buffer.size;
    return DMP_PROVIDER_OK;
}

dmp_provider_status dmp_provider_cipher_close(dmp_provider *provider,
                                             dmp_provider_cipher *cipher)
{
    dmp_provider_cipher_body *body;

    if (!provider_live(provider) || cipher == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    body = cipher_body(cipher);
    if (body->magic != DMP_PROVIDER_CIPHER_MAGIC) {
        return DMP_PROVIDER_INVALID;
    }
    if (body->state != NULL) {
        (void)noise_cipherstate_free(body->state);
    }
    unregister_child(provider, cipher);
    wipe(cipher, sizeof(*cipher));
    return DMP_PROVIDER_OK;
}

dmp_provider_status dmp_provider_dh_public(dmp_provider *provider,
                                          const uint8_t private_key[32],
                                          uint8_t public_key[32])
{
    NoiseDHState *dh = NULL;
    int error;
    dmp_provider_status status;

    if (!provider_live(provider) || private_key == NULL || public_key == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    wipe(public_key, DMP_PROVIDER_KEY_LEN);
    error = noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519);
    if (error != NOISE_ERROR_NONE || dh == NULL) {
        status = dh == NULL && error == NOISE_ERROR_NONE ? DMP_PROVIDER_NO_MEMORY
                                                        : map_noise(provider, error);
        goto done;
    }
    error = noise_dhstate_set_keypair_private(dh, private_key, DMP_PROVIDER_KEY_LEN);
    if (error != NOISE_ERROR_NONE) {
        status = map_noise(provider, error);
        goto done;
    }
    error = noise_dhstate_get_public_key(dh, public_key, DMP_PROVIDER_KEY_LEN);
    status = map_noise(provider, error);
    if (status != DMP_PROVIDER_OK) {
        wipe(public_key, DMP_PROVIDER_KEY_LEN);
    }

done:
    if (dh != NULL) {
        (void)noise_dhstate_free(dh);
    }
    return status;
}

dmp_provider_status dmp_provider_dh_shared(dmp_provider *provider,
                                          const uint8_t private_key[32],
                                          const uint8_t public_key[32],
                                          uint8_t shared[32])
{
    NoiseDHState *local = NULL;
    NoiseDHState *remote = NULL;
    int error;
    dmp_provider_status status = DMP_PROVIDER_REJECTED;

    if (!provider_live(provider) || private_key == NULL || public_key == NULL || shared == NULL) {
        return DMP_PROVIDER_INVALID;
    }
    wipe(shared, DMP_PROVIDER_KEY_LEN);
    error = noise_dhstate_new_by_id(&local, NOISE_DH_CURVE25519);
    if (error != NOISE_ERROR_NONE || local == NULL) {
        status = local == NULL && error == NOISE_ERROR_NONE ? DMP_PROVIDER_NO_MEMORY
                                                           : map_noise(provider, error);
        goto done;
    }
    error = noise_dhstate_new_by_id(&remote, NOISE_DH_CURVE25519);
    if (error != NOISE_ERROR_NONE || remote == NULL) {
        status = remote == NULL && error == NOISE_ERROR_NONE ? DMP_PROVIDER_NO_MEMORY
                                                            : map_noise(provider, error);
        goto done;
    }
    error = noise_dhstate_set_keypair_private(local, private_key, DMP_PROVIDER_KEY_LEN);
    if (error != NOISE_ERROR_NONE) {
        status = map_noise(provider, error);
        goto done;
    }
    error = noise_dhstate_set_public_key(remote, public_key, DMP_PROVIDER_KEY_LEN);
    if (error != NOISE_ERROR_NONE) {
        status = map_noise(provider, error);
        goto done;
    }
    error = noise_dhstate_calculate(local, remote, shared, DMP_PROVIDER_KEY_LEN);
    /* libsodium reports an all-zero X25519 result as a parameter failure.
     * The arguments were already checked, so this is key rejection. */
    if (error == NOISE_ERROR_NONE) {
        status = DMP_PROVIDER_OK;
    } else if (error == NOISE_ERROR_NO_MEMORY) {
        status = DMP_PROVIDER_NO_MEMORY;
        wipe(shared, DMP_PROVIDER_KEY_LEN);
    } else {
        status = DMP_PROVIDER_REJECTED;
        wipe(shared, DMP_PROVIDER_KEY_LEN);
    }

done:
    if (local != NULL) {
        (void)noise_dhstate_free(local);
    }
    if (remote != NULL) {
        (void)noise_dhstate_free(remote);
    }
    return status;
}
