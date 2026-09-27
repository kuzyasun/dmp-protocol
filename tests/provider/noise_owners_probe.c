/* MEM-03: one endpoint's test-only owners, serialized on one fixed arena. */
#include "noise_owner_fixture.h"
#include "noise_test_arena.h"
#include "noise_owner_cases.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CAPACITY 32768U
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "MEM-03 line %d: %s\n", __LINE__, #x); return 0; } } while (0)
static union { max_align_t align; unsigned char bytes[CAPACITY]; } backing;
static dmp_noise_test_arena arena;
static size_t attempts, allocations, releases, refusals, fail_at;
static int port_error;

void *noise_allocator_allocate(size_t size)
{
    void *p;
    ++attempts;
    p = attempts == fail_at ? NULL : dmp_noise_test_arena_allocate(&arena, size);
    if (p) {
        ++allocations;
        if ((uintptr_t)p % _Alignof(max_align_t)) port_error = 1;
    } else {
        ++refusals;
    }
    return p;
}

void noise_allocator_release(void *p, size_t size)
{
    if (dmp_noise_test_arena_release(&arena, p, size) != DMP_NOISE_TEST_ARENA_OK)
        port_error = 1;
    else
        ++releases;
}

static int empty(void)
{
    CHECK(!port_error && arena.live_blocks == 0U && arena.charged_bytes == 0U);
    CHECK(allocations == releases);
    return 1;
}

static int reset(size_t retained)
{
    CHECK(empty() && retained > sizeof(arena) && retained <= CAPACITY);
    /* Logical provider-only slice includes allocator metadata. Physical test
       backing remains CAPACITY bytes, not this logical per-case quota. */
    CHECK(dmp_noise_test_arena_init(&arena, backing.bytes, sizeof(backing),
          retained - sizeof(arena), DMP_NOISE_TEST_ARENA_MAX_BLOCKS) == DMP_NOISE_TEST_ARENA_OK);
    memset(backing.bytes, 0xA5, sizeof(backing.bytes));
    attempts = allocations = releases = refusals = fail_at = 0U;
    return 1;
}

static int drive(dmp_noise_owner *owner)
{
    while (noise_handshakestate_get_action(owner->handshake) != NOISE_ACTION_SPLIT) {
        size_t before = attempts;
        int result = dmp_owner_step(owner, 0);
        if (result != NOISE_ERROR_NONE) return result;
        if (attempts != before) return NOISE_ERROR_INVALID_STATE;
    }
    return NOISE_ERROR_NONE;
}

static int establish(dmp_noise_owner *owner, size_t fixture, int role)
{
    int error = dmp_owner_create(owner, fixture, role);
    if (!error) error = drive(owner);
    if (!error) error = dmp_owner_complete(owner);
    return error;
}

static int traffic(dmp_noise_owner *owners, size_t count)
{
    size_t i, before = attempts;
    for (i = 0; i < count; ++i) {
        CHECK(dmp_owner_receive(&owners[i], 1) == NOISE_ERROR_MAC_FAILURE);
        CHECK(dmp_owner_receive(&owners[i], 0) == NOISE_ERROR_NONE);
    }
    CHECK(attempts == before && !port_error);
    return 1;
}

static size_t fixture_for(unsigned mode, size_t i)
{
    return mode < 4U ? mode / 2U : i % 2U;
}

static int role_for(unsigned mode, size_t i)
{
    return ((mode < 4U ? mode : mode + (unsigned)i) % 2U) ?
        NOISE_ROLE_RESPONDER : NOISE_ROLE_INITIATOR;
}

static int sensitivity(const owner_case *row, const owner_budget *budget, unsigned mode)
{
    dmp_noise_owner guards[8] = {{0}}, pending[4] = {{0}};
    size_t g = 0, p = 0, i, peak, live_at_refusal = 0;
    int refused = 0;
    CHECK(reset(budget->retained));
    for (i = 0; i < row->active + row->draining; ++i) {
        size_t bytes = arena.charged_bytes, blocks = arena.live_blocks;
        int error = establish(&guards[g], fixture_for(mode, i), role_for(mode, i));
        if (error != NOISE_ERROR_NONE) {
            CHECK(error == NOISE_ERROR_NO_MEMORY);
            CHECK(dmp_owner_close(&guards[g]) == NOISE_ERROR_NONE);
            CHECK(arena.charged_bytes == bytes && arena.live_blocks == blocks);
            refused = 1;
            break;
        }
        ++g;
    }
    if (!refused) for (i = 0; i < row->pending; ++i) {
        size_t bytes = arena.charged_bytes, blocks = arena.live_blocks;
        int error = dmp_owner_create(&pending[p], fixture_for(mode, i), role_for(mode, i));
        if (error != NOISE_ERROR_NONE) {
            CHECK(error == NOISE_ERROR_NO_MEMORY && pending[p].handshake == NULL);
            CHECK(arena.charged_bytes == bytes && arena.live_blocks == blocks);
            refused = 1;
            live_at_refusal = p;
            break;
        }
        ++p;
        CHECK(traffic(guards, g));
    }
    CHECK(traffic(guards, g));
    CHECK(dmp_noise_test_arena_clear(&arena) == DMP_NOISE_TEST_ARENA_BUSY);
    /* Cancel a middle pending attempt; reuse its hole with all neighbors live. */
    if (p) {
        size_t middle = p / 2U;
        CHECK(dmp_owner_close(&pending[middle]) == NOISE_ERROR_NONE);
        CHECK(dmp_owner_create(&pending[middle], fixture_for(mode, middle),
                              role_for(mode, middle)) == NOISE_ERROR_NONE);
    }
    for (i = 0; i < p; ++i) {
        CHECK(drive(&pending[i]) == NOISE_ERROR_NONE);
        CHECK(dmp_owner_complete(&pending[i]) == NOISE_ERROR_NONE);
        CHECK(dmp_owner_send_once(&pending[i]) == NOISE_ERROR_NONE);
        CHECK(traffic(pending + i, 1) && traffic(guards, g));
        CHECK(dmp_owner_close(&pending[i]) == NOISE_ERROR_NONE);
    }
    for (i = g; i > 0U; --i) {
        /* Check the preserved send direction after interference, using its
           first and only fixture PN. Receives were checked throughout. */
        CHECK(dmp_owner_send_once(&guards[i - 1U]) == NOISE_ERROR_NONE);
        CHECK(dmp_owner_close(&guards[i - 1U]) == NOISE_ERROR_NONE);
    }
    CHECK(empty());
    peak = arena.peak_charged_bytes;
    printf("MEM03_RESULT {\"row\":\"%s\",\"budget\":\"%s\",\"mode\":%u,"
           "\"retained_slice\":%zu,\"metadata\":%zu,\"peak_charged\":%zu,"
           "\"guards\":%zu,\"pending_admitted\":%zu,\"refused\":%d,\"pending_at_refusal\":%zu}\n",
           row->name, budget->name, mode, budget->retained, sizeof(arena), peak, g, p, refused, live_at_refusal);
    return 1;
}

static int failure_sweeps(void)
{
    dmp_noise_owner guards[2] = {{0}}, neighbor = {0}, candidate = {0};
    unsigned mode;
    size_t i, ordinal, allocation_count, before, bytes, blocks;
    CHECK(reset(CAPACITY));
    for (i = 0; i < COUNT(guards); ++i)
        CHECK(establish(&guards[i], i, role_for(4, i)) == NOISE_ERROR_NONE);
    CHECK(dmp_owner_create(&neighbor, 1, NOISE_ROLE_RESPONDER) == NOISE_ERROR_NONE);
    for (mode = 0; mode < 4U; ++mode) {
        before = attempts;
        CHECK(establish(&candidate, fixture_for(mode, 0), role_for(mode, 0)) == NOISE_ERROR_NONE);
        CHECK(dmp_owner_send_once(&candidate) == NOISE_ERROR_NONE);
        allocation_count = attempts - before;
        CHECK(dmp_owner_close(&candidate) == NOISE_ERROR_NONE);
        CHECK(allocation_count > 1U);
        bytes = arena.charged_bytes;
        blocks = arena.live_blocks;
        for (ordinal = 1U; ordinal <= allocation_count; ++ordinal) {
            fail_at = attempts + ordinal;
            CHECK(establish(&candidate, fixture_for(mode, 0), role_for(mode, 0)) == NOISE_ERROR_NO_MEMORY);
            fail_at = 0U;
            CHECK(dmp_owner_close(&candidate) == NOISE_ERROR_NONE);
            CHECK(arena.charged_bytes == bytes && arena.live_blocks == blocks);
            CHECK(traffic(guards, COUNT(guards)));
        }
        printf("MEM03_OOM mode=%u ordinals=%zu (includes Split), neighboring owners preserved\n",
               mode, allocation_count);
    }
    CHECK(drive(&neighbor) == NOISE_ERROR_NONE && dmp_owner_complete(&neighbor) == NOISE_ERROR_NONE);
    CHECK(dmp_owner_send_once(&neighbor) == NOISE_ERROR_NONE && traffic(&neighbor, 1));
    CHECK(dmp_owner_close(&neighbor) == NOISE_ERROR_NONE);
    /* Corrupt admitted XX flight 2, destroy only that attempt, explicitly retry. */
    CHECK(dmp_owner_create(&candidate, 1, NOISE_ROLE_INITIATOR) == NOISE_ERROR_NONE);
    CHECK(dmp_owner_step(&candidate, 0) == NOISE_ERROR_NONE);
    CHECK(dmp_owner_step(&candidate, 1) == NOISE_ERROR_MAC_FAILURE);
    CHECK(dmp_owner_step(&candidate, 0) == NOISE_ERROR_INVALID_STATE);
    CHECK(dmp_owner_close(&candidate) == NOISE_ERROR_NONE && traffic(guards, COUNT(guards)));
    CHECK(establish(&candidate, 1, NOISE_ROLE_INITIATOR) == NOISE_ERROR_NONE);
    CHECK(dmp_owner_send_once(&candidate) == NOISE_ERROR_NONE);
    CHECK(dmp_owner_close(&candidate) == NOISE_ERROR_NONE);
    for (i = 0; i < COUNT(guards); ++i) {
        CHECK(dmp_owner_send_once(&guards[i]) == NOISE_ERROR_NONE);
        CHECK(dmp_owner_close(&guards[i]) == NOISE_ERROR_NONE);
    }
    CHECK(empty());
    return 1;
}

static int repeated_lifetimes(void)
{
    dmp_noise_owner guards[2] = {{0}}, pending[4] = {{0}};
    size_t i, cycle, bytes, blocks, first_peak = 0;
    CHECK(reset(16384));
    for (i = 0; i < COUNT(guards); ++i)
        CHECK(establish(&guards[i], i, role_for(4, i)) == NOISE_ERROR_NONE);
    bytes = arena.charged_bytes;
    blocks = arena.live_blocks;
    for (cycle = 0; cycle < 32U; ++cycle) {
        for (i = 0; i < COUNT(pending); ++i)
            CHECK(dmp_owner_create(&pending[i], i % 2U, role_for(4, i)) == NOISE_ERROR_NONE);
        CHECK(dmp_owner_close(&pending[1]) == NOISE_ERROR_NONE);
        CHECK(dmp_owner_create(&pending[1], 1, NOISE_ROLE_RESPONDER) == NOISE_ERROR_NONE);
        for (i = 0; i < COUNT(pending); ++i) {
            CHECK(drive(&pending[i]) == NOISE_ERROR_NONE && dmp_owner_complete(&pending[i]) == NOISE_ERROR_NONE);
            CHECK(dmp_owner_send_once(&pending[i]) == NOISE_ERROR_NONE && traffic(&pending[i], 1));
            CHECK(dmp_owner_close(&pending[i]) == NOISE_ERROR_NONE);
        }
        CHECK(traffic(guards, COUNT(guards)));
        CHECK(arena.charged_bytes == bytes && arena.live_blocks == blocks && !port_error);
        if (!cycle) first_peak = arena.peak_charged_bytes;
        CHECK(arena.peak_charged_bytes == first_peak);
    }
    for (i = 0; i < COUNT(guards); ++i) {
        CHECK(dmp_owner_send_once(&guards[i]) == NOISE_ERROR_NONE);
        CHECK(dmp_owner_close(&guards[i]) == NOISE_ERROR_NONE);
    }
    CHECK(empty());
    printf("MEM03_REUSE cycles=32 peak_charged=%zu no residual growth; cleanup wipes checked\n", first_peak);
    return 1;
}

static int run(void)
{
    size_t i, j;
    unsigned mode;
    CHECK(noise_init_framework() == NOISE_ERROR_NONE && dmp_owner_fixture_count() == 2U);
    for (i = 0; i < COUNT(owner_cases); ++i) {
        if (owner_cases[i].slots != 1U) {
            printf("MEM03_DEFERRED row=%s crypto_slots=%zu: simultaneous calls not exercised\n",
                   owner_cases[i].name, owner_cases[i].slots);
            continue;
        }
        for (j = 0; j < COUNT(owner_budgets); ++j)
            for (mode = 0; mode < 6U; ++mode)
                CHECK(sensitivity(&owner_cases[i], &owner_budgets[j], mode));
    }
    CHECK(failure_sweeps() && repeated_lifetimes());
    printf("MEM03_SCOPE host serialized provider only; fixed driver backing=%zu metadata=%zu; "
           "owner records/scratch/stacks/backend/DMP/binding buffers excluded from slice; no MCU runtime\n",
           sizeof(backing), sizeof(arena));
    return 1;
}

int main(void) { return run() ? 0 : 1; }
