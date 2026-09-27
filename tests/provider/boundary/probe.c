/* BOUNDARY-01: synchronous private provider owner, NOT a DMP endpoint/parser. */
#include "peer.h"
#include "noise_test_arena.h"
#include <stdio.h>
#include <string.h>

#define CAP 128U
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "boundary line %d: %s\n", __LINE__, #x); return 0; } } while (0)
static union { max_align_t align; uint8_t bytes[16384]; } storage;
static dmp_noise_test_arena arena;
static unsigned allocations, releases, port_error, cases;
void *noise_allocator_allocate(size_t size)
{
    void *p = dmp_noise_test_arena_allocate(&arena, size);
    if (p) ++allocations;
    return p;
}
void noise_allocator_release(void *p, size_t size)
{
    if (dmp_noise_test_arena_release(&arena, p, size) != DMP_NOISE_TEST_ARENA_OK)
        ++port_error;
    else ++releases;
}

/* Work units count real provider calls; traffic counts admitted input bytes.
 * Fixed finite values are laboratory parameters, not production policy. */
typedef struct { unsigned ingress, crypto, bytes, ingress_limit, crypto_limit, byte_limit; } global_budget;
typedef struct {
    global_budget *global;
    unsigned attempts, crypto, bytes, attempt_limit, crypto_limit, byte_limit;
    unsigned now, deadline, restart_at, next_generation;
} episode;
typedef struct {
    NoiseHandshakeState *state;
    episode *episode;
    unsigned mode, generation, expected, deadline, terminal;
    int role;
    uint8_t pin[32];
    uint8_t accepted[3][CAP], outgoing[3][CAP], scratch[CAP], plaintext[CAP];
    size_t accepted_size[3], outgoing_size[3];
    unsigned reads, writes, accepted_reads;
    int last_noise_error;
} owner;
enum outcome { ACCEPT, DROP, DUPLICATE, CONFLICT, ABORT, REFUSED };

static void episode_open(episode *e, global_budget *g, unsigned now)
{
    /* Explicit local request only. Global budgets are deliberately untouched. */
    memset(e, 0, sizeof(*e));
    e->global = g; e->now = now; e->deadline = now + 1000;
    e->attempt_limit = 3; e->crypto_limit = 64; e->byte_limit = 4096;
}
static int reserve_crypto(episode *e)
{
    if (e->crypto >= e->crypto_limit || e->global->crypto >= e->global->crypto_limit)
        return 0;
    ++e->crypto; ++e->global->crypto;
    return 1;
}
static void abort_owner(owner *o)
{
    /* Invalidate before freeing. No automatic retry, response or counter refund. */
    o->terminal = 1;
    o->generation = 0;
    o->episode->restart_at = o->episode->now + 10;
    if (o->state && noise_handshakestate_free(o->state) != NOISE_ERROR_NONE) ++port_error;
    o->state = NULL;
    noise_clean(o->scratch, sizeof(o->scratch));
    noise_clean(o->plaintext, sizeof(o->plaintext));
    noise_clean(o->accepted, sizeof(o->accepted));
    noise_clean(o->outgoing, sizeof(o->outgoing));
    memset(o->accepted_size, 0, sizeof(o->accepted_size));
    memset(o->outgoing_size, 0, sizeof(o->outgoing_size));
}
static int start(owner *o, episode *e, unsigned mode, int role, int wrong_psk, int wrong_pin)
{
    unsigned generation;
    if (o->state || e->now >= e->deadline || e->now < e->restart_at ||
        e->attempts >= e->attempt_limit || e->next_generation == 255 ||
        !reserve_crypto(e)) return REFUSED;
    generation = ++e->next_generation;
    ++e->attempts;
    memset(o, 0, sizeof(*o));
    o->episode = e; o->mode = mode; o->role = role;
    o->generation = generation; o->expected = 1;
    o->deadline = e->now + 100 < e->deadline ? e->now + 100 : e->deadline;
    if (mode == 2) {
        if (boundary_peer_pin(mode, role == NOISE_ROLE_INITIATOR ? NOISE_ROLE_RESPONDER : NOISE_ROLE_INITIATOR,
                              o->pin) != NOISE_ERROR_NONE) { abort_owner(o); return ABORT; }
        if (wrong_pin) o->pin[0] ^= 1;
    }
    o->last_noise_error = boundary_peer_new(&o->state, mode, role, generation, wrong_psk);
    if (o->last_noise_error != NOISE_ERROR_NONE) { abort_owner(o); return ABORT; }
    return ACCEPT;
}
static int sends(const owner *o, unsigned flight)
{
    return ((flight & 1U) != 0) == (o->role == NOISE_ROLE_INITIATOR);
}
static int write_owner(owner *o, unsigned flight, uint8_t *out, size_t *size)
{
    static const uint8_t cid[4] = {9, 0, 0, 0};
    NoiseBuffer message, payload;
    if (o->terminal || !o->state || flight < 1 || flight > 3 || !sends(o, flight)) return DROP;
    if (o->episode->now >= o->deadline) { abort_owner(o); return ABORT; }
    if (o->outgoing_size[flight-1]) {
        *size = o->outgoing_size[flight-1];
        memcpy(out, o->outgoing[flight-1], *size);
        return DUPLICATE;
    }
    if (flight != o->expected || !reserve_crypto(o->episode)) return REFUSED;
    noise_buffer_set_output(message, o->outgoing[flight-1], CAP);
    noise_buffer_set_input(payload, cid, flight == 2 ? 4 : 0);
    ++o->writes;
    o->last_noise_error = noise_handshakestate_write_message(o->state, &message, &payload);
    if (o->last_noise_error || message.size != boundary_flight_size(o->mode, flight)) {
        abort_owner(o); return ABORT;
    }
    o->outgoing_size[flight-1] = message.size;
    *size = message.size; memcpy(out, message.data, *size);
    ++o->expected;
    return ACCEPT;
}
static int receive_owner(owner *o, unsigned generation, unsigned flight,
                         const uint8_t *input, size_t size)
{
    NoiseBuffer message, payload;
    uint8_t public_key[32];
    global_budget *g = o->episode->global;
    int pin_ok = 1;
    if (g->ingress >= g->ingress_limit) return REFUSED;
    ++g->ingress;
    /* Borrowed input is immutable. Complete wire/outer validation is a later gate. */
    if (o->terminal || !o->state || generation != o->generation || flight < 1 || flight > 3 ||
        sends(o, flight) || size != boundary_flight_size(o->mode, flight) || size > CAP) return DROP;
    if (o->episode->now >= o->deadline) { abort_owner(o); return ABORT; }
    if (o->accepted_size[flight-1]) {
        return memcmp(input, o->accepted[flight-1], size) == 0 ? DUPLICATE : CONFLICT;
    }
    if (flight != o->expected) return DROP;
    if (size > o->episode->byte_limit - o->episode->bytes || size > g->byte_limit - g->bytes ||
        !reserve_crypto(o->episode)) return REFUSED;
    o->episode->bytes += (unsigned)size; g->bytes += (unsigned)size;
    memcpy(o->scratch, input, size);
    noise_buffer_set_input(message, o->scratch, size);
    noise_buffer_set_output(payload, o->plaintext, sizeof(o->plaintext));
    ++o->reads;
    o->last_noise_error = noise_handshakestate_read_message(o->state, &message, &payload);
    if (!o->last_noise_error && o->mode == 2 && flight > 1) {
        NoiseDHState *remote = noise_handshakestate_get_remote_public_key_dh(o->state);
        pin_ok = remote && noise_dhstate_get_public_key(remote, public_key, sizeof(public_key)) == NOISE_ERROR_NONE
                 && noise_is_equal(public_key, o->pin, sizeof(public_key));
    }
    noise_clean(public_key, sizeof(public_key));
    if (o->last_noise_error || !pin_ok ||
        (flight == 2 ? (payload.size != 4 || noise_is_zero(payload.data, payload.size)) : payload.size != 0)) {
        abort_owner(o); return ABORT;
    }
    /* Acceptance is the first persistent mutation after all mandatory checks. */
    memcpy(o->accepted[flight-1], input, size); o->accepted_size[flight-1] = size;
    ++o->expected; ++o->accepted_reads;
    noise_clean(o->scratch, sizeof(o->scratch));
    noise_clean(o->plaintext, sizeof(o->plaintext));
    return ACCEPT;
}

static int empty(void)
{
    CHECK(!port_error && !arena.live_blocks && !arena.charged_bytes && allocations == releases);
    return 1;
}
static int reset_arena(void)
{
    CHECK(empty());
    CHECK(dmp_noise_test_arena_init(&arena, storage.bytes, sizeof(storage.bytes),
          sizeof(storage.bytes), DMP_NOISE_TEST_ARENA_MAX_BLOCKS) == DMP_NOISE_TEST_ARENA_OK);
    memset(storage.bytes, 0xa5, sizeof(storage.bytes));
    return 1;
}
static global_budget fresh_budget(void)
{
    global_budget g = {0, 0, 0, 128, 128, 8192};
    return g;
}
static int peer_write(NoiseHandshakeState *peer, unsigned flight, int zero_cid,
                      uint8_t bytes[CAP], size_t *size)
{
    uint8_t cid[4] = {9, 0, 0, 0};
    NoiseBuffer message, payload;
    if (zero_cid) cid[0] = 0;
    noise_buffer_set_output(message, bytes, CAP);
    noise_buffer_set_input(payload, cid, flight == 2 ? sizeof(cid) : 0);
    CHECK(noise_handshakestate_write_message(peer, &message, &payload) == NOISE_ERROR_NONE);
    *size = message.size;
    return 1;
}
static int peer_read(NoiseHandshakeState *peer, const uint8_t *bytes, size_t size)
{
    uint8_t mutable[CAP], plain[CAP];
    NoiseBuffer message, payload;
    int result;
    memcpy(mutable, bytes, size);
    noise_buffer_set_input(message, mutable, size);
    noise_buffer_set_output(payload, plain, sizeof(plain));
    result = noise_handshakestate_read_message(peer, &message, &payload);
    noise_clean(mutable, sizeof(mutable)); noise_clean(plain, sizeof(plain));
    CHECK(result == NOISE_ERROR_NONE);
    return 1;
}
/* A real peer creates authenticated faults; expected outcomes are never fed to
 * receive_owner. fault: 1 wrong PSK, 2 wrong pin, 3 authenticated zero CID. */
static int exchange(owner *o, NoiseHandshakeState *peer, unsigned fault,
                    uint8_t first[CAP], size_t *first_size)
{
    uint8_t bytes[CAP], saved[CAP], duplicate[CAP], hashes[2][32];
    size_t size = 0, duplicate_size;
    unsigned flight, count = o->mode == 1 ? 2 : 3;
    for (flight = 1; flight <= count; ++flight) {
        if (sends(o, flight)) {
            unsigned writes;
            CHECK(write_owner(o, flight, bytes, &size) == ACCEPT);
            writes = o->writes;
            CHECK(write_owner(o, flight, duplicate, &duplicate_size) == DUPLICATE);
            CHECK(writes == o->writes && size == duplicate_size && !memcmp(bytes, duplicate, size));
            CHECK(peer_read(peer, bytes, size));
        } else {
            unsigned reads = o->reads, accepted = o->accepted_reads, writes = o->writes;
            size_t allocated = allocations;
            CHECK(peer_write(peer, flight, fault == 3 && flight == 2, bytes, &size));
            memcpy(saved, bytes, size);
            if (flight == 1) { *first_size = size; memcpy(first, bytes, size); }
            if ((fault == 1) || (fault == 2 && flight > 1) || (fault == 3 && flight == 2)) {
                unsigned old_generation = o->generation, crypto;
                CHECK(receive_owner(o, old_generation, flight, bytes, size) == ABORT);
                CHECK(o->terminal && !o->state && !o->generation);
                CHECK(o->reads == reads + 1 && o->accepted_reads == accepted && o->writes == writes);
                CHECK(fault == 1 ? o->last_noise_error == NOISE_ERROR_MAC_FAILURE : o->last_noise_error == NOISE_ERROR_NONE);
                CHECK(noise_is_zero(o->scratch, sizeof(o->scratch)) && noise_is_zero(o->plaintext, sizeof(o->plaintext)));
                CHECK(noise_is_zero(o->outgoing, sizeof(o->outgoing)) && noise_is_zero(o->accepted, sizeof(o->accepted)));
                crypto = o->episode->crypto;
                CHECK(receive_owner(o, old_generation, flight, saved, size) == DROP);
                CHECK(o->episode->crypto == crypto && o->reads == reads + 1);
                CHECK(!memcmp(bytes, saved, size));
                return 1;
            }
            CHECK(receive_owner(o, o->generation, flight, bytes, size) == ACCEPT);
            CHECK(allocations == allocated && !memcmp(bytes, saved, size));
        }
        if (flight == 1) { *first_size = size; memcpy(first, bytes, size); }
    }
    CHECK(!fault && noise_handshakestate_get_action(o->state) == NOISE_ACTION_SPLIT);
    CHECK(noise_handshakestate_get_handshake_hash(o->state, hashes[0], 32) == NOISE_ERROR_NONE);
    CHECK(noise_handshakestate_get_handshake_hash(peer, hashes[1], 32) == NOISE_ERROR_NONE);
    CHECK(!memcmp(hashes[0], hashes[1], 32));
    return 1;
}
static int fixture_baseline(unsigned mode)
{
    NoiseHandshakeState *i = NULL, *r = NULL;
    uint8_t bytes[CAP], hash[32]; size_t size; unsigned flight;
    CHECK(reset_arena());
    CHECK(boundary_peer_new(&i, mode, NOISE_ROLE_INITIATOR, 0, 0) == NOISE_ERROR_NONE);
    CHECK(boundary_peer_new(&r, mode, NOISE_ROLE_RESPONDER, 0, 0) == NOISE_ERROR_NONE);
    for (flight = 1; flight <= (mode == 1 ? 2U : 3U); ++flight) {
        CHECK(peer_write(flight == 2 ? r : i, flight, 0, bytes, &size));
        CHECK(boundary_fixture_flight(mode, flight, bytes, size) == NOISE_ERROR_NONE);
        CHECK(peer_read(flight == 2 ? i : r, bytes, size));
    }
    CHECK(noise_handshakestate_get_handshake_hash(i, hash, 32) == NOISE_ERROR_NONE);
    CHECK(boundary_fixture_hash(mode, hash) == NOISE_ERROR_NONE);
    CHECK(noise_handshakestate_free(i) == NOISE_ERROR_NONE && noise_handshakestate_free(r) == NOISE_ERROR_NONE);
    CHECK(empty()); ++cases;
    return 1;
}
static int fault_restart(unsigned mode, int role, unsigned fault)
{
    global_budget g = fresh_budget(); episode e; owner o = {0};
    NoiseHandshakeState *peer = NULL;
    uint8_t first[CAP], fresh[CAP], stale[CAP] = {0}; size_t first_size = 0, fresh_size = 0;
    unsigned old_generation, old_crypto, old_bytes, old_global, old_deadline, alloc;
    CHECK(reset_arena()); episode_open(&e, &g, 0);
    CHECK(start(&o, &e, mode, role, fault == 1, fault == 2) == ACCEPT);
    old_generation = o.generation; old_deadline = e.deadline;
    CHECK(boundary_peer_new(&peer, mode, role == NOISE_ROLE_INITIATOR ? NOISE_ROLE_RESPONDER : NOISE_ROLE_INITIATOR,
                            o.generation, 0) == NOISE_ERROR_NONE);
    CHECK(exchange(&o, peer, fault, first, &first_size));
    CHECK(noise_handshakestate_free(peer) == NOISE_ERROR_NONE); peer = NULL;
    CHECK(empty() && e.attempts == 1 && e.deadline == old_deadline);
    old_crypto = e.crypto; old_bytes = e.bytes; old_global = g.crypto; alloc = allocations;
    CHECK(start(&o, &e, mode, role, 0, 0) == REFUSED);
    e.now = 9; CHECK(start(&o, &e, mode, role, 0, 0) == REFUSED);
    CHECK(e.attempts == 1 && e.crypto == old_crypto && g.crypto == old_global && allocations == alloc);
    e.now = 10; CHECK(start(&o, &e, mode, role, 0, 0) == ACCEPT);
    CHECK(o.generation != old_generation && e.attempts == 2 && e.crypto == old_crypto + 1 &&
          e.bytes == old_bytes && g.crypto == old_global + 1 && e.deadline == old_deadline);
    CHECK(receive_owner(&o, old_generation, role == NOISE_ROLE_INITIATOR ? 2 : 1,
                        stale, boundary_flight_size(mode, role == NOISE_ROLE_INITIATOR ? 2 : 1)) == DROP);
    CHECK(o.reads == 0 && !o.terminal);
    CHECK(boundary_peer_new(&peer, mode, role == NOISE_ROLE_INITIATOR ? NOISE_ROLE_RESPONDER : NOISE_ROLE_INITIATOR,
                            o.generation, 0) == NOISE_ERROR_NONE);
    CHECK(exchange(&o, peer, 0, fresh, &fresh_size));
    CHECK(first_size == fresh_size && memcmp(first, fresh, first_size));
    abort_owner(&o); CHECK(noise_handshakestate_free(peer) == NOISE_ERROR_NONE);
    CHECK(empty()); ++cases;
    printf("fault mode=%u role=%d kind=%u: abort, stale generation, bounded fresh success\n", mode, role, fault);
    return 1;
}

static int admission(unsigned mode)
{
    global_budget g = fresh_budget(); episode e; owner o = {0};
    NoiseHandshakeState *peer = NULL;
    uint8_t bytes[CAP], changed[CAP], out[CAP], hash[32]; size_t size, out_size;
    unsigned crypto, deadline, alloc, global_ingress;
    CHECK(reset_arena()); episode_open(&e, &g, 0);
    CHECK(start(&o, &e, mode, NOISE_ROLE_RESPONDER, 0, 0) == ACCEPT);
    CHECK(boundary_peer_new(&peer, mode, NOISE_ROLE_INITIATOR, o.generation, 0) == NOISE_ERROR_NONE);
    CHECK(peer_write(peer, 1, 0, bytes, &size));
    crypto = e.crypto; deadline = o.deadline; alloc = allocations;
    CHECK(receive_owner(&o, o.generation, 1, bytes, size - 1) == DROP);
    CHECK(receive_owner(&o, o.generation + 1, 1, bytes, size) == DROP);
    CHECK(receive_owner(&o, o.generation, 3, bytes, size) == DROP);
    CHECK(o.reads == 0 && !o.terminal && e.crypto == crypto && allocations == alloc && o.deadline == deadline);
    e.crypto_limit = e.crypto;
    CHECK(receive_owner(&o, o.generation, 1, bytes, size) == REFUSED && !o.terminal && !o.reads);
    e.crypto_limit = 64;
    CHECK(receive_owner(&o, o.generation, 1, bytes, size) == ACCEPT);
    CHECK(write_owner(&o, 2, out, &out_size) == ACCEPT);
    crypto = e.crypto; global_ingress = g.ingress;
    CHECK(receive_owner(&o, o.generation, 1, bytes, size) == DUPLICATE);
    memcpy(changed, bytes, size); changed[size-1] ^= 1;
    CHECK(receive_owner(&o, o.generation, 1, changed, size) == CONFLICT);
    CHECK(o.reads == 1 && o.writes == 1 && e.crypto == crypto && g.ingress == global_ingress + 2 &&
          allocations == alloc && o.deadline == deadline && !o.terminal);
    CHECK(peer_read(peer, out, out_size));
    if (mode == 2) {
        CHECK(peer_write(peer, 3, 0, bytes, &size));
        CHECK(receive_owner(&o, o.generation, 3, bytes, size) == ACCEPT);
    }
    CHECK(noise_handshakestate_get_handshake_hash(o.state, hash, 32) == NOISE_ERROR_NONE);
    CHECK(noise_handshakestate_get_action(o.state) == NOISE_ACTION_SPLIT);
    CHECK(noise_handshakestate_get_handshake_hash(peer, changed, 32) == NOISE_ERROR_NONE);
    CHECK(!memcmp(hash, changed, 32));
    abort_owner(&o); CHECK(noise_handshakestate_free(peer) == NOISE_ERROR_NONE);
    CHECK(empty()); ++cases;
    return 1;
}
static int budget_edges(void)
{
    global_budget g = fresh_budget(); episode e; owner o = {0}; unsigned i, spent, alloc;
    CHECK(reset_arena()); episode_open(&e, &g, 0);
    for (i = 0; i < 3; ++i) {
        e.now = i * 10;
        CHECK(start(&o, &e, 1, NOISE_ROLE_RESPONDER, 0, 0) == ACCEPT);
        abort_owner(&o); CHECK(empty());
    }
    alloc = allocations; spent = g.crypto; e.now = 30;
    CHECK(start(&o, &e, 1, NOISE_ROLE_RESPONDER, 0, 0) == REFUSED && allocations == alloc && g.crypto == spent);
    episode_open(&e, &g, 30);
    CHECK(g.crypto == spent && !e.attempts);
    g.crypto_limit = spent;
    CHECK(start(&o, &e, 1, NOISE_ROLE_RESPONDER, 0, 0) == REFUSED && allocations == alloc);
    g.crypto_limit = 128; e.now = e.deadline;
    CHECK(start(&o, &e, 1, NOISE_ROLE_RESPONDER, 0, 0) == REFUSED && allocations == alloc);
    CHECK(empty()); ++cases;
    return 1;
}
int main(void)
{
    if (noise_init_framework() != NOISE_ERROR_NONE) return 1;
    if (!fixture_baseline(1) || !fixture_baseline(2) ||
        !fault_restart(1, NOISE_ROLE_RESPONDER, 1) ||
        !fault_restart(2, NOISE_ROLE_INITIATOR, 2) || !fault_restart(2, NOISE_ROLE_RESPONDER, 2) ||
        !fault_restart(1, NOISE_ROLE_INITIATOR, 3) || !fault_restart(2, NOISE_ROLE_INITIATOR, 3) ||
        !admission(1) || !admission(2) || !budget_edges()) return 1;
    printf("{\"success\":true,\"cases\":%u,\"allocations\":%u,\"releases\":%u,\"wipe_errors\":%u}\n",
           cases, allocations, releases, port_error);
    return 0;
}
