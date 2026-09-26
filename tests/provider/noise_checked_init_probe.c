/* Host-only probe for checked entropy failures during real sodium startup. */
#include <noise/protocol.h>

#include <sodium.h>

#include "dmp_sodium_entropy.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(DMP_TEST_WINDOWS_ENTROPY)
#include <windows.h>
#endif

typedef enum entropy_mode {
  ENTROPY_HEALTHY = 0,
  ENTROPY_FAIL_READY,
  ENTROPY_FAIL_READ
} entropy_mode_t;

static entropy_mode_t entropy_mode;
static unsigned int ready_calls;
static unsigned int read_calls;
static uint8_t *last_read_buffer;
static size_t last_read_size;
#if defined(DMP_TEST_WINDOWS_ENTROPY)
static unsigned int system_rng_calls;
BOOLEAN NTAPI SystemFunction036(PVOID buffer, ULONG size);
BOOLEAN NTAPI __real_SystemFunction036(PVOID buffer, ULONG size);

BOOLEAN NTAPI __wrap_SystemFunction036(PVOID buffer, ULONG size) {
  ++system_rng_calls;
  if (entropy_mode == ENTROPY_FAIL_READ) {
    fputs("DMP_TEST_SYSTEM_RNG_FAILURE\n", stderr);
    return FALSE;
  }
  return __real_SystemFunction036(buffer, size);
}
#endif

static int fail(const char *case_name, const char *message) {
  fprintf(stderr, "%s: %s\n", case_name, message);
  return 0;
}

static int expect_int(const char *case_name, const char *operation, int actual,
                      int expected) {
  if (actual == expected)
    return 1;
  fprintf(stderr, "%s: %s returned %d; expected %d\n", case_name,
          operation, actual, expected);
  return 0;
}

static int expect_counts(const char *case_name, unsigned int expected_ready,
                         unsigned int expected_read) {
  if (ready_calls == expected_ready && read_calls == expected_read)
    return 1;
  fprintf(stderr,
          "%s: entropy port counts were ready=%u read=%u; expected %u/%u\n",
          case_name, ready_calls, read_calls, expected_ready, expected_read);
  return 0;
}

static int buffer_is_zero(const uint8_t *buffer, size_t size) {
  size_t index;
  for (index = 0U; index < size; ++index) {
    if (buffer[index] != 0U)
      return 0;
  }
  return 1;
}

/* Actual backend startup calls these checked hooks; no sodium_init mock. */
int dmp_sodium_entropy_ready(void) {
  ++ready_calls;
  return entropy_mode == ENTROPY_FAIL_READY ? 1 : 0;
}

int dmp_sodium_entropy_read(void *bytes, size_t size) {
  uint8_t *output = (uint8_t *)bytes;
  size_t index;

  ++read_calls;
  last_read_buffer = output;
  last_read_size = size;
  if (entropy_mode == ENTROPY_FAIL_READ) {
    const size_t partial_size = size == 0U ? 0U : (size + 1U) / 2U;
    for (index = 0U; index < partial_size; ++index)
      output[index] = 0xA5U;
#if defined(DMP_TEST_WINDOWS_ENTROPY)
    /* The wrapper fails the real Windows OS RNG call; retain partial test bytes. */
    return SystemFunction036(output, (ULONG)size) ? 0 : 1;
#else
    return 1;
#endif
  }
#if defined(DMP_TEST_WINDOWS_ENTROPY)
  return SystemFunction036(output, (ULONG)size) ? 0 : 1;
#else
  for (index = 0U; index < size; ++index)
    output[index] = (uint8_t)(0x3DU + (uint8_t)(index * 19U));
  return 0;
#endif
}

/* Required by the fork's checked custom Noise random port; startup may not use it. */
int noise_rand_bytes_checked(void *bytes, size_t size) {
  uint8_t *output = (uint8_t *)bytes;
  size_t index;
  for (index = 0U; index < size; ++index)
    output[index] = (uint8_t)(0x71U + (uint8_t)(index * 23U));
  return NOISE_ERROR_NONE;
}

static int verify_sha256(const char *case_name) {
  static const uint8_t expected[crypto_hash_sha256_BYTES] = {
      0xBAU, 0x78U, 0x16U, 0xBFU, 0x8FU, 0x01U, 0xCFU, 0xEAU,
      0x41U, 0x41U, 0x40U, 0xDEU, 0x5DU, 0xAEU, 0x22U, 0x23U,
      0xB0U, 0x03U, 0x61U, 0xA3U, 0x96U, 0x17U, 0x7AU, 0x9CU,
      0xB4U, 0x10U, 0xFFU, 0x61U, 0xF2U, 0x00U, 0x15U, 0xADU};
  uint8_t actual[crypto_hash_sha256_BYTES];

  if (crypto_hash_sha256(actual, (const unsigned char *)"abc", 3U) != 0)
    return fail(case_name, "real SHA-256 operation failed after init");
  if (memcmp(actual, expected, sizeof(expected)) != 0)
    return fail(case_name, "SHA-256 abc digest did not match the known value");
  return 1;
}

static int run_healthy(void) {
  const char *case_name = "healthy";

  entropy_mode = ENTROPY_HEALTHY;
  if (!expect_int(case_name, "noise_init_framework", noise_init_framework(),
                  NOISE_ERROR_NONE) ||
      !expect_counts(case_name, 1U, 1U))
    return 0;
  if (last_read_buffer == NULL || last_read_size == 0U)
    return fail(case_name, "backend did not request nonempty canary bytes");

  if (!expect_int(case_name, "subsequent sodium_init", sodium_init(), 1) ||
      !expect_counts(case_name, 1U, 1U) || !verify_sha256(case_name))
    return 0;
#if defined(DMP_TEST_WINDOWS_ENTROPY)
  if (system_rng_calls != 1U)
    return fail(case_name, "expected exactly one successful Windows OS RNG call");
#endif

  puts("PASS: checked startup healthy path, already-initialized result, and real SHA-256.");
  puts("Scope: host entropy-port fault tests only; no physical entropy or hardware claim.");
  return 1;
}

static int run_failure(entropy_mode_t failure_mode, const char *case_name) {
  unsigned int attempt;
  const unsigned int expected_final_reads =
      failure_mode == ENTROPY_FAIL_READ ? 3U : 1U;

  entropy_mode = failure_mode;
  for (attempt = 1U; attempt <= 2U; ++attempt) {
    if (!expect_int(case_name, "noise_init_framework failure",
                    noise_init_framework(), NOISE_ERROR_SYSTEM))
      return 0;
    if (failure_mode == ENTROPY_FAIL_READY) {
      if (!expect_counts(case_name, attempt, 0U))
        return 0;
      if (read_calls != 0U)
        return fail(case_name, "read hook ran after readiness failure");
    } else {
      if (!expect_counts(case_name, attempt, attempt))
        return 0;
      if (last_read_buffer == NULL || last_read_size == 0U)
        return fail(case_name, "read failure did not expose its canary buffer");
      if (!buffer_is_zero(last_read_buffer, last_read_size))
        return fail(case_name,
                    "backend left the partially written canary buffer uncleared");
    }
  }

  entropy_mode = ENTROPY_HEALTHY;
  if (!expect_int(case_name, "fresh sodium_init retry", sodium_init(), 0))
    return 0;
  if (!expect_counts(case_name, 3U, expected_final_reads))
    return 0;
  if (!expect_int(case_name, "subsequent sodium_init", sodium_init(), 1) ||
      !expect_counts(case_name, 3U, expected_final_reads) ||
      !verify_sha256(case_name))
    return 0;
#if defined(DMP_TEST_WINDOWS_ENTROPY)
  if (failure_mode == ENTROPY_FAIL_READ && system_rng_calls != 3U)
    return fail(case_name, "expected two failed and one successful Windows OS RNG call");
  if (failure_mode == ENTROPY_FAIL_READY && system_rng_calls != 1U)
    return fail(case_name, "readiness failure unexpectedly skipped the recovery OS RNG call");
#endif

  printf("PASS: %s propagated twice, cleared failed startup state, and retried successfully.\n",
         case_name);
  puts("Scope: host entropy-port fault tests only; no physical entropy or hardware claim.");
  return 1;
}

int main(int argc, char **argv) {
  if (argc == 1)
    return run_healthy() ? 0 : 1;
  if (argc != 2) {
    fprintf(stderr, "usage: %s healthy|ready-failure|read-failure\n", argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "healthy") == 0)
    return run_healthy() ? 0 : 1;
  if (strcmp(argv[1], "ready-failure") == 0)
    return run_failure(ENTROPY_FAIL_READY, "ready-failure") ? 0 : 1;
  if (strcmp(argv[1], "read-failure") == 0)
    return run_failure(ENTROPY_FAIL_READ, "read-failure") ? 0 : 1;
  fprintf(stderr, "unknown case: %s\n", argv[1]);
  return 2;
}
