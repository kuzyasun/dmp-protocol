/* MEM-02: fixed caller storage, real Noise allocation paths, public test keys. */
#include <noise/protocol.h>
#include "noise_test_arena.h"
#include "noise_fixture_probe.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CAPACITY 8192U
static union { max_align_t alignment; unsigned char bytes[CAPACITY]; } backing;
static dmp_noise_test_arena arena;
static size_t allocations, refusals, releases;
static int port_error;
int dmp_noise_fixture_run(void);

void *noise_allocator_allocate(size_t size)
{
    void *p = dmp_noise_test_arena_allocate(&arena, size);
    if (p) {
        ++allocations;
        if ((uintptr_t)p % _Alignof(max_align_t))
            port_error = 1;
    } else {
        ++refusals;
    }
    return p;
}

void noise_allocator_release(void *p, size_t size)
{
    /* Arena validates all requested bytes before marking the allocation free. */
    if (dmp_noise_test_arena_release(&arena, p, size) != DMP_NOISE_TEST_ARENA_OK)
        port_error = 1;
    else
        ++releases;
}

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "allocator probe line %d: %s\n", __LINE__, #condition); return 0; \
} } while (0)

static int reset(size_t bytes, size_t blocks)
{
    CHECK(arena.live_blocks == 0U && arena.charged_bytes == 0U && !port_error);
    CHECK(dmp_noise_test_arena_init(&arena, backing.bytes, sizeof(backing.bytes),
                                   bytes, blocks) == DMP_NOISE_TEST_ARENA_OK);
    /* The port returns dirty memory: Noise must initialize its objects itself. */
    memset(backing.bytes, 0xA5, sizeof(backing.bytes));
    allocations = refusals = releases = 0U;
    return 1;
}

static int empty(void)
{
    CHECK(!port_error && arena.live_blocks == 0U && arena.charged_bytes == 0U);
    CHECK(allocations == releases);
    return 1;
}

static int quota_cases(const char *name, int role)
{
    NoiseHandshakeState *state = NULL;
    size_t blocks, charge, limit;
    static const unsigned char prologue[37] = {0x5AU};
    int result;

    CHECK(reset(CAPACITY, DMP_NOISE_TEST_ARENA_MAX_BLOCKS));
    CHECK(noise_handshakestate_new_by_name(&state, name, role) == NOISE_ERROR_NONE);
    blocks = arena.live_blocks;
    charge = arena.charged_bytes;
    CHECK(blocks > 0U && charge > 0U);
    CHECK(noise_handshakestate_free(state) == NOISE_ERROR_NONE);
    state = NULL;
    CHECK(empty());

    for (limit = 0U; limit < blocks; ++limit) {
        CHECK(reset(CAPACITY, limit));
        result = noise_handshakestate_new_by_name(&state, name, role);
        CHECK(result == NOISE_ERROR_NO_MEMORY && state == NULL && refusals > 0U);
        CHECK(empty());
    }
    CHECK(reset(charge - 1U, DMP_NOISE_TEST_ARENA_MAX_BLOCKS));
    CHECK(noise_handshakestate_new_by_name(&state, name, role) == NOISE_ERROR_NO_MEMORY);
    CHECK(state == NULL && refusals > 0U && empty());

    CHECK(reset(charge, blocks));
    CHECK(noise_handshakestate_new_by_name(&state, name, role) == NOISE_ERROR_NONE);
    /* Both exact limits are already occupied: prologue must not bypass port. */
    CHECK(noise_handshakestate_set_prologue(state, prologue, sizeof(prologue)) == NOISE_ERROR_NO_MEMORY);
    CHECK(refusals == 1U && arena.charged_bytes == charge && arena.live_blocks == blocks);
    CHECK(noise_handshakestate_free(state) == NOISE_ERROR_NONE && empty());
    printf("%s role=%d: constructor blocks=%zu charged=%zu; block sweep, byte boundary and prologue refusal passed\n",
           name, role, blocks, charge);
    return 1;
}

static int preserved_traffic(void)
{
    const noise_fixture_probe_packet_t *packet = &noise_fixture_probe_fixtures[0].finish;
    NoiseCipherState *guard = NULL;
    NoiseHandshakeState *refused = NULL;
    size_t charge;
    unsigned char bytes[128];
    NoiseBuffer buffer;

    CHECK(reset(CAPACITY, DMP_NOISE_TEST_ARENA_MAX_BLOCKS));
    CHECK(noise_cipherstate_new_by_id(&guard, NOISE_CIPHER_CHACHAPOLY) == NOISE_ERROR_NONE);
    charge = arena.charged_bytes;
    CHECK(noise_cipherstate_free(guard) == NOISE_ERROR_NONE && empty());
    CHECK(reset(charge, 1U));
    CHECK(noise_cipherstate_new_by_id(&guard, NOISE_CIPHER_CHACHAPOLY) == NOISE_ERROR_NONE);
    CHECK(noise_cipherstate_init_key(guard, packet->key.data, packet->key.size) == NOISE_ERROR_NONE);
    CHECK(noise_handshakestate_new_by_name(&refused, noise_fixture_probe_fixtures[0].protocol_name,
                                          NOISE_ROLE_INITIATOR) == NOISE_ERROR_NO_MEMORY);
    CHECK(refused == NULL && arena.live_blocks == 1U && arena.charged_bytes == charge);
    CHECK(dmp_noise_test_arena_init(&arena, backing.bytes, CAPACITY, CAPACITY,
                                   DMP_NOISE_TEST_ARENA_MAX_BLOCKS) == DMP_NOISE_TEST_ARENA_BUSY);
    CHECK(packet->plaintext.size + packet->tag.size <= sizeof(bytes));
    memcpy(bytes, packet->plaintext.data, packet->plaintext.size);
    noise_buffer_set_inout(buffer, bytes, packet->plaintext.size, sizeof(bytes));
    CHECK(noise_cipherstate_set_nonce(guard, packet->pn) == NOISE_ERROR_NONE);
    CHECK(noise_cipherstate_encrypt_with_ad(guard, packet->aad.data, packet->aad.size, &buffer) == NOISE_ERROR_NONE);
    CHECK(buffer.size == packet->ciphertext.size + packet->tag.size);
    CHECK(memcmp(bytes, packet->ciphertext.data, packet->ciphertext.size) == 0);
    CHECK(memcmp(bytes + packet->ciphertext.size, packet->tag.data, packet->tag.size) == 0);
    CHECK(noise_cipherstate_free(guard) == NOISE_ERROR_NONE && empty());
    puts("Existing traffic context preserved across quota refusal and rejected live reset");
    return 1;
}

static int run(void)
{
    size_t i;
    CHECK(noise_init_framework() == NOISE_ERROR_NONE);
    CHECK(reset(CAPACITY, DMP_NOISE_TEST_ARENA_MAX_BLOCKS));
    CHECK(noise_alloc_memory(0U) == NULL && allocations == 0U);
    for (i = 0; i < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++i) {
        CHECK(quota_cases(noise_fixture_probe_fixtures[i].protocol_name, NOISE_ROLE_INITIATOR));
        CHECK(quota_cases(noise_fixture_probe_fixtures[i].protocol_name, NOISE_ROLE_RESPONDER));
    }
    CHECK(preserved_traffic());
    CHECK(reset(CAPACITY, DMP_NOISE_TEST_ARENA_MAX_BLOCKS));
    CHECK(dmp_noise_fixture_run() == 0 && empty() && refusals == 0U);
    printf("Both fixtures/abort-first checks via arena: allocations=%zu peak_charged=%zu storage=%zu metadata=%zu alignment=%zu\n",
           allocations, arena.peak_charged_bytes, sizeof(backing), sizeof(arena), _Alignof(max_align_t));
    puts("Test-only serialized fixed storage; excludes stack, backend globals, DMP buffers and MCU runtime acceptance");
    return 1;
}

int main(void) { return run() ? 0 : 1; }
