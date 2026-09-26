#include "noise_test_arena.h"

#include <stdalign.h>
#include <stdint.h>
#include <string.h>

#define DMP_NOISE_TEST_ARENA_COOKIE 0x4e415231u

static int arena_is_valid(const dmp_noise_test_arena *arena)
{
    return arena != NULL && arena->state_cookie == DMP_NOISE_TEST_ARENA_COOKIE &&
           arena->storage != NULL && arena->capacity != 0u &&
           arena->byte_quota <= arena->capacity &&
           arena->block_quota <= DMP_NOISE_TEST_ARENA_MAX_BLOCKS;
}

static size_t live_block_count(const dmp_noise_test_arena *arena)
{
    size_t count = 0u;
    size_t i;

    for (i = 0u; i < DMP_NOISE_TEST_ARENA_MAX_BLOCKS; ++i) {
        if (arena->slots[i].live != 0u) {
            ++count;
        }
    }
    return count;
}

static int live_charged_bytes(const dmp_noise_test_arena *arena,
                              size_t *total)
{
    size_t sum = 0u;
    size_t i;

    for (i = 0u; i < DMP_NOISE_TEST_ARENA_MAX_BLOCKS; ++i) {
        if (arena->slots[i].live != 0u) {
            if (arena->slots[i].charged > SIZE_MAX - sum) {
                return 0;
            }
            sum += arena->slots[i].charged;
        }
    }
    *total = sum;
    return 1;
}

static int round_charge(size_t requested, size_t *charged)
{
    const size_t alignment = _Alignof(max_align_t);
    const size_t remainder = requested % alignment;
    const size_t padding = remainder == 0u ? 0u : alignment - remainder;

    if (requested == 0u || requested > SIZE_MAX - padding) {
        return 0;
    }
    *charged = requested + padding;
    return 1;
}

static size_t first_free_slot(const dmp_noise_test_arena *arena)
{
    size_t i;

    for (i = 0u; i < arena->block_quota; ++i) {
        if (arena->slots[i].live == 0u) {
            return i;
        }
    }
    return DMP_NOISE_TEST_ARENA_MAX_BLOCKS;
}

static int find_first_fit(const dmp_noise_test_arena *arena,
                          size_t charged,
                          size_t *result)
{
    size_t candidate = 0u;
    size_t attempt;

    for (attempt = 0u; attempt <= arena->block_quota; ++attempt) {
        size_t i;
        size_t next_candidate = candidate;
        int collision = 0;

        if (candidate > arena->capacity ||
            charged > arena->capacity - candidate) {
            return 0;
        }

        for (i = 0u; i < DMP_NOISE_TEST_ARENA_MAX_BLOCKS; ++i) {
            const dmp_noise_test_arena_slot *slot = &arena->slots[i];
            size_t slot_end;
            size_t candidate_end;

            if (slot->live == 0u) {
                continue;
            }
            /* Live records are created only after checked capacity bounds. */
            slot_end = slot->offset + slot->charged;
            candidate_end = candidate + charged;
            if (candidate < slot_end && slot->offset < candidate_end) {
                if (!collision || slot_end < next_candidate) {
                    next_candidate = slot_end;
                }
                collision = 1;
            }
        }

        if (!collision) {
            *result = candidate;
            return 1;
        }
        if (next_candidate <= candidate) {
            return 0;
        }
        candidate = next_candidate;
    }
    return 0;
}

dmp_noise_test_arena_status dmp_noise_test_arena_init(
    dmp_noise_test_arena *arena,
    void *storage,
    size_t capacity,
    size_t byte_quota,
    size_t block_quota)
{
    size_t i;

    if (arena == NULL || storage == NULL || capacity == 0u ||
        byte_quota > capacity ||
        block_quota > DMP_NOISE_TEST_ARENA_MAX_BLOCKS ||
        (uintptr_t)storage % (uintptr_t)_Alignof(max_align_t) != 0u) {
        return DMP_NOISE_TEST_ARENA_INVALID_ARGUMENT;
    }

    if (arena->state_cookie == DMP_NOISE_TEST_ARENA_COOKIE) {
        if (!arena_is_valid(arena)) {
            return DMP_NOISE_TEST_ARENA_INVALID_STATE;
        }
        if (live_block_count(arena) != 0u) {
            return DMP_NOISE_TEST_ARENA_BUSY;
        }
    } else if (arena->state_cookie != 0u) {
        return DMP_NOISE_TEST_ARENA_INVALID_STATE;
    }

    for (i = 0u; i < DMP_NOISE_TEST_ARENA_MAX_BLOCKS; ++i) {
        arena->slots[i].offset = 0u;
        arena->slots[i].requested = 0u;
        arena->slots[i].charged = 0u;
        arena->slots[i].live = 0u;
    }
    arena->storage = (unsigned char *)storage;
    arena->capacity = capacity;
    arena->byte_quota = byte_quota;
    arena->block_quota = block_quota;
    arena->live_blocks = 0u;
    arena->charged_bytes = 0u;
    arena->peak_charged_bytes = 0u;
    arena->state_cookie = DMP_NOISE_TEST_ARENA_COOKIE;
    return DMP_NOISE_TEST_ARENA_OK;
}

dmp_noise_test_arena_status dmp_noise_test_arena_clear(
    dmp_noise_test_arena *arena)
{
    size_t i;

    if (!arena_is_valid(arena)) {
        return DMP_NOISE_TEST_ARENA_INVALID_STATE;
    }
    if (live_block_count(arena) != 0u) {
        return DMP_NOISE_TEST_ARENA_BUSY;
    }
    for (i = 0u; i < DMP_NOISE_TEST_ARENA_MAX_BLOCKS; ++i) {
        arena->slots[i].offset = 0u;
        arena->slots[i].requested = 0u;
        arena->slots[i].charged = 0u;
        arena->slots[i].live = 0u;
    }
    arena->live_blocks = 0u;
    arena->charged_bytes = 0u;
    arena->peak_charged_bytes = 0u;
    return DMP_NOISE_TEST_ARENA_OK;
}

void *dmp_noise_test_arena_allocate(dmp_noise_test_arena *arena,
                                    size_t requested)
{
    size_t charged;
    size_t used_bytes;
    size_t offset;
    size_t slot_index;

    if (!arena_is_valid(arena) ||
        !round_charge(requested, &charged) ||
        !live_charged_bytes(arena, &used_bytes) ||
        used_bytes > arena->byte_quota ||
        charged > arena->byte_quota - used_bytes ||
        live_block_count(arena) >= arena->block_quota) {
        return NULL;
    }
    slot_index = first_free_slot(arena);
    if (slot_index == DMP_NOISE_TEST_ARENA_MAX_BLOCKS ||
        !find_first_fit(arena, charged, &offset)) {
        return NULL;
    }

    arena->slots[slot_index].offset = offset;
    arena->slots[slot_index].requested = requested;
    arena->slots[slot_index].charged = charged;
    arena->slots[slot_index].live = 1u;
    arena->live_blocks += 1u;
    arena->charged_bytes = used_bytes + charged;
    if (arena->charged_bytes > arena->peak_charged_bytes) {
        arena->peak_charged_bytes = arena->charged_bytes;
    }
    return arena->storage + offset;
}

dmp_noise_test_arena_status dmp_noise_test_arena_release(
    dmp_noise_test_arena *arena,
    void *pointer,
    size_t original_requested_size)
{
    size_t i;
    dmp_noise_test_arena_slot *matched = NULL;

    if (!arena_is_valid(arena) || pointer == NULL) {
        return DMP_NOISE_TEST_ARENA_INVALID_ARGUMENT;
    }

    /* Equality is defined for unrelated object pointers; no ordering is used. */
    for (i = 0u; i < DMP_NOISE_TEST_ARENA_MAX_BLOCKS; ++i) {
        if (arena->slots[i].live != 0u &&
            pointer == (void *)(arena->storage + arena->slots[i].offset)) {
            matched = &arena->slots[i];
            break;
        }
    }
    if (matched == NULL) {
        return DMP_NOISE_TEST_ARENA_NOT_OWNED;
    }
    if (original_requested_size != matched->requested) {
        return DMP_NOISE_TEST_ARENA_SIZE_MISMATCH;
    }

    for (i = 0u; i < matched->requested; ++i) {
        if (arena->storage[matched->offset + i] != 0u) {
            return DMP_NOISE_TEST_ARENA_DIRTY;
        }
    }

    if (matched->charged > matched->requested) {
        memset(arena->storage + matched->offset + matched->requested,
               0,
               matched->charged - matched->requested);
    }
    matched->offset = 0u;
    matched->requested = 0u;
    arena->charged_bytes -= matched->charged;
    arena->live_blocks -= 1u;
    matched->charged = 0u;
    matched->live = 0u;
    return DMP_NOISE_TEST_ARENA_OK;
}
