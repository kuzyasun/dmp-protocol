#ifndef DMP_NOISE_TEST_ARENA_H
#define DMP_NOISE_TEST_ARENA_H

/* Test-only bounded allocator for serialized Noise provider experiments. */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DMP_NOISE_TEST_ARENA_MAX_BLOCKS 64u

typedef enum dmp_noise_test_arena_status {
    DMP_NOISE_TEST_ARENA_OK = 0,
    DMP_NOISE_TEST_ARENA_INVALID_ARGUMENT,
    DMP_NOISE_TEST_ARENA_INVALID_STATE,
    DMP_NOISE_TEST_ARENA_BUSY,
    DMP_NOISE_TEST_ARENA_NOT_OWNED,
    DMP_NOISE_TEST_ARENA_SIZE_MISMATCH,
    DMP_NOISE_TEST_ARENA_DIRTY
} dmp_noise_test_arena_status;

typedef struct dmp_noise_test_arena_slot {
    size_t offset;
    size_t requested;
    size_t charged;
    unsigned int live;
} dmp_noise_test_arena_slot;

typedef struct dmp_noise_test_arena {
    dmp_noise_test_arena_slot slots[DMP_NOISE_TEST_ARENA_MAX_BLOCKS];
    unsigned char *storage;
    size_t capacity;
    size_t byte_quota;
    size_t block_quota;
    size_t live_blocks;
    size_t charged_bytes;
    size_t peak_charged_bytes;
    unsigned int state_cookie;
} dmp_noise_test_arena;

/*
 * The arena object must be zero-initialized before its first init call, e.g.
 * `dmp_noise_test_arena arena = {0};`. Storage must be max_align_t-aligned,
 * writable for `capacity` bytes, and outlive the arena. Init never clears it.
 * Zero byte/block quotas are valid and refuse every allocation. Reconfiguration
 * via init and clear both refuse to discard live allocations. Current and peak
 * charged-byte counts include max_align_t padding.
 */
dmp_noise_test_arena_status dmp_noise_test_arena_init(
    dmp_noise_test_arena *arena,
    void *storage,
    size_t capacity,
    size_t byte_quota,
    size_t block_quota);

/* Clear metadata only when empty; storage bytes are not changed. */
dmp_noise_test_arena_status dmp_noise_test_arena_clear(
    dmp_noise_test_arena *arena);

/* Returns uninitialized raw storage; callers initialize objects themselves. */
void *dmp_noise_test_arena_allocate(dmp_noise_test_arena *arena,
                                    size_t requested);

/* Caller must wipe all requested bytes first; padding is cleared on success. */
dmp_noise_test_arena_status dmp_noise_test_arena_release(
    dmp_noise_test_arena *arena,
    void *pointer,
    size_t original_requested_size);

#ifdef __cplusplus
}
#endif

#endif
