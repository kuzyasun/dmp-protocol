#include "noise_test_arena.h"

#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(expression)                                                       \
    do {                                                                        \
        if (!(expression)) {                                                    \
            (void)fprintf(stderr, "check failed at line %d: %s\n", __LINE__,  \
                          #expression);                                         \
            return 1;                                                           \
        }                                                                       \
    } while (0)

static int all_bytes_equal(const unsigned char *bytes,
                           size_t count,
                           unsigned char expected)
{
    size_t i;

    for (i = 0u; i < count; ++i) {
        if (bytes[i] != expected) {
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    _Alignas(max_align_t) unsigned char storage[512];
    dmp_noise_test_arena arena = {0};
    const size_t alignment = _Alignof(max_align_t);
    const size_t short_request = alignment > 1u ? alignment - 1u : 1u;
    unsigned char *first;
    unsigned char *second;
    unsigned char *third;
    unsigned char *fourth;
    unsigned char *reused;
    unsigned char foreign = 0u;
    size_t i;

    memset(storage, 0xa5, sizeof storage);
    CHECK(dmp_noise_test_arena_init(&arena, storage + 1u, sizeof storage - 1u,
                                    sizeof storage - 1u, 1u) ==
          DMP_NOISE_TEST_ARENA_INVALID_ARGUMENT);
    CHECK(dmp_noise_test_arena_init(&arena, storage, 0u, 1u, 1u) ==
          DMP_NOISE_TEST_ARENA_INVALID_ARGUMENT);
    CHECK(dmp_noise_test_arena_init(&arena, storage, sizeof storage, 0u, 1u) ==
          DMP_NOISE_TEST_ARENA_OK);
    CHECK(dmp_noise_test_arena_allocate(&arena, 1u) == NULL);
    CHECK(dmp_noise_test_arena_init(&arena, storage, sizeof storage, 1u, 0u) ==
          DMP_NOISE_TEST_ARENA_OK);
    CHECK(dmp_noise_test_arena_allocate(&arena, 1u) == NULL);
    CHECK(dmp_noise_test_arena_init(&arena, storage, sizeof storage,
                                    sizeof storage + 1u, 1u) ==
          DMP_NOISE_TEST_ARENA_INVALID_ARGUMENT);
    CHECK(dmp_noise_test_arena_init(&arena, storage, sizeof storage,
                                    sizeof storage,
                                    DMP_NOISE_TEST_ARENA_MAX_BLOCKS + 1u) ==
          DMP_NOISE_TEST_ARENA_INVALID_ARGUMENT);

    /* Overflow rejection has no effect; quota charges padded bytes. */
    CHECK(dmp_noise_test_arena_init(&arena, storage, sizeof storage,
                                    2u * alignment, 2u) ==
          DMP_NOISE_TEST_ARENA_OK);
    CHECK(dmp_noise_test_arena_allocate(&arena, SIZE_MAX) == NULL);
    first = (unsigned char *)dmp_noise_test_arena_allocate(&arena, 1u);
    second = (unsigned char *)dmp_noise_test_arena_allocate(&arena,
                                                            short_request);
    CHECK(first != NULL && second != NULL);
    CHECK((uintptr_t)first % (uintptr_t)alignment == 0u);
    CHECK((uintptr_t)second % (uintptr_t)alignment == 0u);
    CHECK(first[0] == 0xa5u && second[0] == 0xa5u);
    CHECK(arena.live_blocks == 2u && arena.charged_bytes == 2u * alignment &&
          arena.peak_charged_bytes == 2u * alignment);
    CHECK(dmp_noise_test_arena_allocate(&arena, 1u) == NULL);
    CHECK(dmp_noise_test_arena_init(&arena, storage, sizeof storage,
                                    3u * alignment, 3u) ==
          DMP_NOISE_TEST_ARENA_BUSY);
    CHECK(dmp_noise_test_arena_clear(&arena) == DMP_NOISE_TEST_ARENA_BUSY);
    memset(first, 0, 1u);
    memset(second, 0, short_request);
    CHECK(dmp_noise_test_arena_release(&arena, first, 1u) ==
          DMP_NOISE_TEST_ARENA_OK);
    CHECK(dmp_noise_test_arena_release(&arena, second, short_request) ==
          DMP_NOISE_TEST_ARENA_OK);

    /* The independent block quota rejects one more allocation. */
    CHECK(dmp_noise_test_arena_init(&arena, storage, sizeof storage,
                                    3u * alignment, 2u) ==
          DMP_NOISE_TEST_ARENA_OK);
    first = (unsigned char *)dmp_noise_test_arena_allocate(&arena, alignment);
    second = (unsigned char *)dmp_noise_test_arena_allocate(&arena, alignment);
    CHECK(first != NULL && second != NULL);
    CHECK(dmp_noise_test_arena_allocate(&arena, 1u) == NULL);
    memset(first, 0, alignment);
    memset(second, 0, alignment);
    CHECK(dmp_noise_test_arena_release(&arena, first, alignment) ==
          DMP_NOISE_TEST_ARENA_OK);
    CHECK(dmp_noise_test_arena_release(&arena, second, alignment) ==
          DMP_NOISE_TEST_ARENA_OK);

    /* Two separated free spans cannot satisfy a larger contiguous request. */
    memset(storage, 0xa5, sizeof storage);
    CHECK(dmp_noise_test_arena_init(&arena, storage, 4u * alignment,
                                    4u * alignment, 4u) ==
          DMP_NOISE_TEST_ARENA_OK);
    first = (unsigned char *)dmp_noise_test_arena_allocate(&arena, alignment);
    second = (unsigned char *)dmp_noise_test_arena_allocate(&arena, alignment);
    third = (unsigned char *)dmp_noise_test_arena_allocate(&arena, alignment);
    fourth = (unsigned char *)dmp_noise_test_arena_allocate(&arena, alignment);
    CHECK(first != NULL && second != NULL && third != NULL && fourth != NULL);
    memset(first, 0x11, alignment);
    memset(second, 0, alignment);
    memset(third, 0x33, alignment);
    memset(fourth, 0, alignment);
    CHECK(dmp_noise_test_arena_release(&arena, second, alignment) ==
          DMP_NOISE_TEST_ARENA_OK);
    CHECK(dmp_noise_test_arena_release(&arena, fourth, alignment) ==
          DMP_NOISE_TEST_ARENA_OK);
    CHECK(dmp_noise_test_arena_allocate(&arena, 2u * alignment) == NULL);
    CHECK(all_bytes_equal(first, alignment, 0x11u));
    CHECK(all_bytes_equal(third, alignment, 0x33u));
    CHECK(dmp_noise_test_arena_release(&arena, first, alignment) ==
          DMP_NOISE_TEST_ARENA_DIRTY);
    CHECK(dmp_noise_test_arena_release(
              &arena, first, alignment == 1u ? 2u : alignment - 1u) ==
          DMP_NOISE_TEST_ARENA_SIZE_MISMATCH);
    CHECK(dmp_noise_test_arena_release(&arena, &foreign, 1u) ==
          DMP_NOISE_TEST_ARENA_NOT_OWNED);
    CHECK(dmp_noise_test_arena_init(&arena, storage, 4u * alignment,
                                    4u * alignment, 4u) ==
          DMP_NOISE_TEST_ARENA_BUSY);
    memset(first, 0, alignment);
    CHECK(dmp_noise_test_arena_release(&arena, first, alignment) ==
          DMP_NOISE_TEST_ARENA_OK);
    CHECK(dmp_noise_test_arena_release(&arena, first, alignment) ==
          DMP_NOISE_TEST_ARENA_NOT_OWNED);
    reused = (unsigned char *)dmp_noise_test_arena_allocate(&arena,
                                                            2u * alignment);
    CHECK(reused == first);
    CHECK(all_bytes_equal(third, alignment, 0x33u));
    memset(reused, 0, 2u * alignment);
    memset(third, 0, alignment);
    CHECK(dmp_noise_test_arena_release(&arena, reused, 2u * alignment) ==
          DMP_NOISE_TEST_ARENA_OK);
    CHECK(dmp_noise_test_arena_release(&arena, third, alignment) ==
          DMP_NOISE_TEST_ARENA_OK);
    CHECK(arena.live_blocks == 0u && arena.charged_bytes == 0u &&
          arena.peak_charged_bytes == 4u * alignment);

    CHECK(dmp_noise_test_arena_clear(&arena) == DMP_NOISE_TEST_ARENA_OK);
    CHECK(dmp_noise_test_arena_allocate(&arena, 1u) != NULL);
    /* Clear cannot silently reset a live block; release it after wiping. */
    for (i = 0u; i < DMP_NOISE_TEST_ARENA_MAX_BLOCKS; ++i) {
        if (arena.slots[i].live != 0u) {
            unsigned char *live = arena.storage + arena.slots[i].offset;
            const size_t requested = arena.slots[i].requested;
            memset(live, 0, requested);
            CHECK(dmp_noise_test_arena_release(&arena, live, requested) ==
                  DMP_NOISE_TEST_ARENA_OK);
            break;
        }
    }
    CHECK(dmp_noise_test_arena_clear(&arena) == DMP_NOISE_TEST_ARENA_OK);
    CHECK(dmp_noise_test_arena_init(&arena, storage, sizeof storage,
                                    alignment, 1u) ==
          DMP_NOISE_TEST_ARENA_OK);
    first = (unsigned char *)dmp_noise_test_arena_allocate(&arena, 1u);
    CHECK(first == storage);
    CHECK(first[0] == 0u);
    memset(first, 0, 1u);
    CHECK(dmp_noise_test_arena_release(&arena, first, 1u) ==
          DMP_NOISE_TEST_ARENA_OK);

    (void)puts("noise test arena probe passed");
    return 0;
}
