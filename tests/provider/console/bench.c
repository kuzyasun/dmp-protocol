/* Private provider laboratory driver. Public fixture credentials, never production. */
#include "bench.h"
#include "noise_test_arena.h"
#include "noise_fixture_probe.h"
#include <noise/protocol.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define SLOTS 8u
#define CAPACITY 32768u
#define ARG_ERROR (-1)
#define PROTOCOL_ERROR (-2)
#define CAP_ERROR (-3)
typedef struct {
    NoiseHandshakeState *hs;
    NoiseCipherState *tx, *rx;
    uint64_t next_pn;
} bench_owner;
static bench_owner owners[SLOTS];
static union { max_align_t alignment; unsigned char data[CAPACITY]; } backing;
static dmp_noise_test_arena arena;
static struct { uint8_t input[512], aad[128], output[512]; } scratch;
static char hex_output[1025];
static uint64_t attempts, allocs, frees, refusals, alloc_fail, rng_calls, rng_fail;
static unsigned wipe_errors;
static uint32_t last_id;
static int initialized;
static char boot_id[17];
#ifndef DMP_BENCH_BUILD_ID
#error "Bench binaries require a source identity"
#endif

void *noise_allocator_allocate(size_t size)
{
    void *result;
    ++attempts;
    if (alloc_fail && --alloc_fail == 0) result = NULL;
    else result = dmp_noise_test_arena_allocate(&arena, size);
    if (result) ++allocs;
    else ++refusals;
    return result;
}

void noise_allocator_release(void *pointer, size_t size)
{
    if (dmp_noise_test_arena_release(&arena, pointer, size) != DMP_NOISE_TEST_ARENA_OK)
        ++wipe_errors;
    else ++frees;
}

int dmp_sodium_entropy_ready(void) { return 0; }
int dmp_sodium_entropy_read(void *bytes, size_t size)
{
    int error;
    ++rng_calls;
    error = rng_fail && --rng_fail == 0 ? 1 : dmp_bench_entropy(bytes, size);
    if (error) noise_clean(bytes, size);
    return error;
}
int noise_rand_bytes_checked(void *bytes, size_t size)
{
    return dmp_sodium_entropy_read(bytes, size) ? NOISE_ERROR_SYSTEM : NOISE_ERROR_NONE;
}

static int number(const char *s, uint64_t maximum, uint64_t *value)
{
    uint64_t n = 0;
    if (!s || !*s) return 0;
    for (; *s; ++s) {
        unsigned digit = (unsigned char)*s - (unsigned)'0';
        if (digit > 9 || n > maximum / 10 ||
            (n == maximum / 10 && digit > maximum % 10)) return 0;
        n = n * 10 + digit;
    }
    *value = n;
    return 1;
}

static int nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int unhex(const char *s, uint8_t *out, size_t capacity, size_t *size)
{
    size_t i, length;
    if (strcmp(s, "-") == 0) { *size = 0; return 1; }
    length = strlen(s);
    if (!length || length % 2 || length / 2 > capacity) return 0;
    for (i = 0; i < length; i += 2) {
        int a = nibble(s[i]), b = nibble(s[i + 1]);
        if (a < 0 || b < 0) return 0;
        out[i / 2] = (uint8_t)((a << 4) | b);
    }
    *size = length / 2;
    return 1;
}
static void hex(const uint8_t *bytes, size_t size)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < size; ++i) {
        hex_output[2 * i] = digits[bytes[i] >> 4];
        hex_output[2 * i + 1] = digits[bytes[i] & 15];
    }
    hex_output[2 * size] = 0;
}

static int close_owner(bench_owner *owner)
{
    int error = 0, e;
    if (owner->hs) { e = noise_handshakestate_free(owner->hs); if (e) error = e; }
    if (owner->tx) { e = noise_cipherstate_free(owner->tx); if (e) error = e; }
    if (owner->rx) { e = noise_cipherstate_free(owner->rx); if (e) error = e; }
    noise_clean(owner, sizeof(*owner));
    return error;
}

static int create_owner(bench_owner *owner, size_t index, int role, int fixed)
{
    const noise_fixture_probe_fixture_t *f = &noise_fixture_probe_fixtures[index];
    bench_owner candidate = {0};
    noise_fixture_probe_bytes_t private_key = role == NOISE_ROLE_INITIATOR ?
        f->init_static : f->resp_static;
    int error;
    if (!initialized || owner->hs || owner->tx || owner->rx)
        return NOISE_ERROR_INVALID_STATE;
    error = noise_handshakestate_new_by_name(&candidate.hs, f->protocol_name, role);
    if (error) goto fail;
    if (private_key.size) {
        error = noise_dhstate_set_keypair_private(
            noise_handshakestate_get_local_keypair_dh(candidate.hs),
            private_key.data, private_key.size);
        if (error) goto fail;
    }
    if (f->psk.size) {
        error = noise_handshakestate_set_pre_shared_key(candidate.hs, f->psk.data, f->psk.size);
        if (error) goto fail;
    }
    if (fixed) {
        NoiseDHState *dh = NULL;
        uint8_t public_key[32];
        private_key = role == NOISE_ROLE_INITIATOR ? f->init_ephemeral : f->resp_ephemeral;
        error = noise_dhstate_new_by_id(&dh, NOISE_DH_CURVE25519);
        if (!error) error = noise_dhstate_set_keypair_private(dh, private_key.data, private_key.size);
        if (!error) error = noise_dhstate_get_public_key(dh, public_key, sizeof(public_key));
        if (!error) error = noise_handshakestate_set_local_ephemeral(candidate.hs,
            private_key.data, private_key.size, public_key, sizeof(public_key));
        if (dh) (void)noise_dhstate_free(dh);
        noise_clean(public_key, sizeof(public_key));
        if (error) goto fail;
    }
    error = noise_handshakestate_set_prologue(candidate.hs, f->prologue.data, f->prologue.size);
    if (!error) error = noise_handshakestate_start(candidate.hs);
    if (error) goto fail;
    *owner = candidate;
    return 0;
fail:
    (void)close_owner(&candidate);
    return error;
}

int dmp_bench_init(void)
{
    uint8_t nonce[8];
    size_t i;
    static const char digits[] = "0123456789abcdef";
    /* Public session identifier only; not provider key material or an RNG test. */
    if (dmp_bench_entropy(nonce, sizeof(nonce))) return NOISE_ERROR_SYSTEM;
    for (i = 0; i < sizeof(nonce); ++i) {
        boot_id[i * 2] = digits[nonce[i] >> 4];
        boot_id[i * 2 + 1] = digits[nonce[i] & 15];
    }
    noise_clean(nonce, sizeof(nonce));
    return dmp_noise_test_arena_init(&arena, backing.data, sizeof(backing),
        CAPACITY, DMP_NOISE_TEST_ARENA_MAX_BLOCKS) == DMP_NOISE_TEST_ARENA_OK ? 0 : CAP_ERROR;
}

static int dispatch_operation(char **args, size_t count, size_t *output_size)
{
    const char *op = args[0];
    uint64_t value;
    bench_owner *owner;
    size_t input_size, aad_size;
    int error;
    NoiseBuffer buffer, payload;
    if (!strcmp(op, "HELLO") || !strcmp(op, "STATS")) return count == 1 ? 0 : ARG_ERROR;
    if (!strcmp(op, "INIT")) {
        if (count != 1) return ARG_ERROR;
        error = noise_init_framework();
        if (!error) initialized = 1;
        return error;
    }
    if (!strcmp(op, "RESET")) {
        size_t i;
        if (count != 2 || !number(args[1], CAPACITY, &value)) return ARG_ERROR;
        for (i = 0; i < SLOTS; ++i)
            if (owners[i].hs || owners[i].tx || owners[i].rx) return NOISE_ERROR_INVALID_STATE;
        if (wipe_errors || arena.live_blocks || allocs != frees) return NOISE_ERROR_INVALID_STATE;
        if (dmp_noise_test_arena_init(&arena, backing.data, sizeof(backing), (size_t)value,
                DMP_NOISE_TEST_ARENA_MAX_BLOCKS) != DMP_NOISE_TEST_ARENA_OK) return CAP_ERROR;
        attempts = allocs = frees = refusals = alloc_fail = rng_fail = rng_calls = 0;
        return 0;
    }
    if (!strcmp(op, "ALLOCFAIL") || !strcmp(op, "RNGFAIL")) {
        if (count != 2 || !number(args[1], 1000000, &value)) return ARG_ERROR;
        if (!strcmp(op, "ALLOCFAIL")) alloc_fail = value;
        else rng_fail = value;
        return 0;
    }
    if (count < 2 || !number(args[1], SLOTS - 1, &value)) return ARG_ERROR;
    owner = &owners[value];
    if (!strcmp(op, "NEW")) {
        size_t index;
        int role, fixed;
        if (count != 5) return ARG_ERROR;
        if (!strcmp(args[2], "nn")) index = 0;
        else if (!strcmp(args[2], "xx")) index = 1;
        else return ARG_ERROR;
        if (!strcmp(args[3], "i")) role = NOISE_ROLE_INITIATOR;
        else if (!strcmp(args[3], "r")) role = NOISE_ROLE_RESPONDER;
        else return ARG_ERROR;
        if (!strcmp(args[4], "fixed")) fixed = 1;
        else if (!strcmp(args[4], "random")) fixed = 0;
        else return ARG_ERROR;
        error = create_owner(owner, index, role, fixed);
    } else if (!strcmp(op, "CLOSE")) {
        error = count == 2 ? close_owner(owner) : ARG_ERROR;
    } else if (!strcmp(op, "WRITE")) {
        if (count != 3 || !unhex(args[2], scratch.input, 256, &input_size)) return ARG_ERROR;
        if (!owner->hs) return NOISE_ERROR_INVALID_STATE;
        noise_buffer_set_output(buffer, scratch.output, sizeof(scratch.output));
        noise_buffer_set_input(payload, scratch.input, input_size);
        error = noise_handshakestate_write_message(owner->hs, &buffer, &payload);
        if (!error) *output_size = buffer.size;
    } else if (!strcmp(op, "READ")) {
        if (count != 3 || !unhex(args[2], scratch.input, sizeof(scratch.input), &input_size))
            return ARG_ERROR;
        if (!owner->hs) return NOISE_ERROR_INVALID_STATE;
        noise_buffer_set_input(buffer, scratch.input, input_size);
        noise_buffer_set_output(payload, scratch.output, 256);
        error = noise_handshakestate_read_message(owner->hs, &buffer, &payload);
        if (!error) *output_size = payload.size;
    } else if (!strcmp(op, "SPLIT")) {
        if (count != 2) return ARG_ERROR;
        if (!owner->hs || owner->tx || owner->rx) return NOISE_ERROR_INVALID_STATE;
        /* Noise exposes a hash during the handshake too; require actual SPLIT. */
        if (noise_handshakestate_get_action(owner->hs) != NOISE_ACTION_SPLIT)
            return NOISE_ERROR_INVALID_STATE;
        error = noise_handshakestate_get_handshake_hash(owner->hs, scratch.output, 32);
        if (!error) error = noise_handshakestate_split(owner->hs, &owner->tx, &owner->rx);
        if (!error) {
            error = noise_handshakestate_free(owner->hs);
            owner->hs = NULL;
            *output_size = 32;
        }
    } else if (!strcmp(op, "SEAL") || !strcmp(op, "OPEN")) {
        int sending = !strcmp(op, "SEAL");
        if (count != 5 || !number(args[2], UINT64_MAX - 1, &value) ||
            !unhex(args[3], scratch.aad, sizeof(scratch.aad), &aad_size) ||
            !unhex(args[4], scratch.output, sending ? 256 : 272, &input_size)) return ARG_ERROR;
        if (owner->hs || !owner->tx || !owner->rx) return NOISE_ERROR_INVALID_STATE;
        noise_buffer_set_inout(buffer, scratch.output, input_size, sizeof(scratch.output));
        if (sending) {
            if (value < owner->next_pn) return NOISE_ERROR_INVALID_NONCE;
            /* Burn the admitted record PN even if the provider operation fails. */
            owner->next_pn = value + 1;
            error = noise_cipherstate_set_nonce(owner->tx, value);
            if (!error) error = noise_cipherstate_encrypt_with_ad(owner->tx,
                scratch.aad, aad_size, &buffer);
        } else {
            error = noise_cipherstate_decrypt_with_ad_at_nonce(owner->rx, value,
                scratch.aad, aad_size, &buffer);
        }
        if (!error) *output_size = buffer.size;
    } else return ARG_ERROR;
    return error;
}

static int dispatch(char **args, size_t count, size_t *output_size, int *action)
{
    int error = dispatch_operation(args, count, output_size);
    uint64_t slot;
    const char *op = args[0];
    if (count >= 2 && number(args[1], SLOTS - 1, &slot) &&
        (!strcmp(op, "NEW") || !strcmp(op, "CLOSE") || !strcmp(op, "WRITE") ||
         !strcmp(op, "READ") || !strcmp(op, "SPLIT") || !strcmp(op, "SEAL") ||
         !strcmp(op, "OPEN"))) {
        bench_owner *owner = &owners[slot];
        *action = owner->hs ? noise_handshakestate_get_action(owner->hs) :
            (owner->tx && owner->rx ? NOISE_ACTION_COMPLETE : NOISE_ACTION_NONE);
    }
    return error;
}

void dmp_bench_command(char *line, char response[DMP_BENCH_REPLY])
{
    char *args[10];
    size_t count = 0, output_size = 0;
    uint64_t id = 0, version, start = dmp_bench_time_us(), elapsed;
    int error = PROTOCOL_ERROR, action = 0, written;
    dmp_bench_metrics m = {0};
    noise_clean(&scratch, sizeof(scratch));
    hex_output[0] = 0;
    if (line) {
        char *p = line;
        while (*p && count < sizeof(args) / sizeof(args[0])) {
            while (*p == ' ' || *p == '\t') ++p;
            if (!*p) break;
            args[count++] = p;
            while (*p && *p != ' ' && *p != '\t') ++p;
            if (*p) *p++ = 0;
        }
        if (*p) count = 0; /* Refuse overflow, never execute a token prefix. */
        if (count >= 4 && !strcmp(args[0], "DMPBENCH") &&
            number(args[1], UINT32_MAX, &version) && version == 1 &&
            number(args[2], UINT32_MAX, &id)) {
            if (id == 0 && count == 4 && !strcmp(args[3], "HELLO")) {
                error = 0; /* Read-only reconnect; do not reset IDs or owners. */
            } else if (id && id > last_id) {
                last_id = (uint32_t)id;
                error = dispatch(args + 3, count - 3, &output_size, &action);
            }
        }
    }
    elapsed = dmp_bench_time_us() - start;
    if (wipe_errors && !error) error = NOISE_ERROR_SYSTEM;
    if (!error && output_size <= sizeof(scratch.output)) hex(scratch.output, output_size);
    else { output_size = 0; if (!error) error = CAP_ERROR; }
    noise_clean(&scratch, sizeof(scratch));
    dmp_bench_platform_metrics(&m);
    written = snprintf(response, DMP_BENCH_REPLY,
        "DMPBENCH {\"v\":1,\"id\":%" PRIu64 ",\"last_id\":%" PRIu32 ",\"rc\":%d,\"us\":%" PRIu64
        ",\"action\":%d,\"data\":\"%s\",\"target\":\"%s\",\"idf\":\"%s\","
        "\"boot\":\"%s\",\"build\":\"%s\",\"stats\":{"
        "\"arena_live\":%zu,\"arena_peak\":%zu,\"blocks\":%zu,\"quota\":%zu,"
        "\"backing\":%zu,\"metadata\":%zu,\"owners\":%zu,\"scratch\":%zu,"
        "\"attempts\":%" PRIu64 ",\"allocs\":%" PRIu64 ",\"frees\":%" PRIu64
        ",\"refusals\":%" PRIu64 ",\"wipe_errors\":%u,\"rng_calls\":%" PRIu64
        ",\"heap_free\":%zu,\"heap_min\":%zu,\"heap_largest\":%zu,\"stack_free_min\":%zu}}",
        id, last_id, error, elapsed, action, hex_output, m.target, m.idf, boot_id, DMP_BENCH_BUILD_ID,
        arena.charged_bytes, arena.peak_charged_bytes, arena.live_blocks, arena.byte_quota,
        sizeof(backing), sizeof(arena), sizeof(owners), sizeof(scratch) + sizeof(hex_output),
        attempts, allocs, frees, refusals, wipe_errors, rng_calls,
        m.heap_free, m.heap_min, m.heap_largest, m.stack_free_min);
    noise_clean(hex_output, sizeof(hex_output));
    if (written < 0 || (size_t)written >= DMP_BENCH_REPLY)
        (void)snprintf(response, DMP_BENCH_REPLY,
            "DMPBENCH {\"v\":1,\"id\":%" PRIu64 ",\"rc\":-3}", id);
}
