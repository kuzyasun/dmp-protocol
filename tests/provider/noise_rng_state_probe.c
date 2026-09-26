/* Host probe for fallible entropy propagation through DH and RandState. */
#include <noise/protocol.h>

#include "protocol/internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROBE_SMALL_BUFFER_SIZE 96U
#define PROBE_RESEED_THRESHOLD 1600000U
#define PROBE_LARGE_REQUEST_SIZE (PROBE_RESEED_THRESHOLD + 1U)

static size_t entropy_calls;
static size_t entropy_fail_call;
static size_t entropy_partial_size;
static int entropy_error;
static const uint8_t *observed_output;
static size_t observed_output_size;
static int output_nonzero_at_failure;

static int fail(const char *test, const char *message) {
  fprintf(stderr, "%s: %s\n", test, message);
  return 0;
}

static int expect_error(const char *test, const char *operation, int actual,
                        int expected) {
  if (actual == expected)
    return 1;
  fprintf(stderr, "%s: %s returned %d; expected %d\n", test, operation, actual,
          expected);
  return 0;
}

static int bytes_are(const uint8_t *bytes, size_t size, uint8_t value) {
  size_t index;
  for (index = 0U; index < size; ++index) {
    if (bytes[index] != value)
      return 0;
  }
  return 1;
}

static int any_nonzero(const uint8_t *bytes, size_t size) {
  size_t index;
  for (index = 0U; index < size; ++index) {
    if (bytes[index] != 0U)
      return 1;
  }
  return 0;
}

static int expect_zero(const char *test, const char *operation,
                       const uint8_t *bytes, size_t size) {
  if (bytes_are(bytes, size, 0U))
    return 1;
  return fail(test, operation);
}

static void reset_entropy(void) {
  entropy_calls = 0U;
  entropy_fail_call = 0U;
  entropy_partial_size = 0U;
  entropy_error = NOISE_ERROR_SYSTEM;
  observed_output = NULL;
  observed_output_size = 0U;
  output_nonzero_at_failure = 0;
}

static void fail_entropy_on(size_t call, size_t partial_size, int error) {
  entropy_fail_call = call;
  entropy_partial_size = partial_size;
  entropy_error = error;
}

/* Link-time test port selected by the fallible custom-random build. */
int noise_rand_bytes_checked(void *bytes, size_t size) {
  uint8_t *output = (uint8_t *)bytes;
  size_t fill_size = size;
  size_t index;
  int fail_this_call;

  ++entropy_calls;
  fail_this_call =
      entropy_fail_call != 0U && entropy_calls == entropy_fail_call;
  if (fail_this_call) {
    if (observed_output != NULL)
      output_nonzero_at_failure =
          any_nonzero(observed_output, observed_output_size);
    if (fill_size > entropy_partial_size)
      fill_size = entropy_partial_size;
  }
  for (index = 0U; index < fill_size; ++index) {
    output[index] = (uint8_t)(0x31U + (uint8_t)(entropy_calls * 17U) +
                              (uint8_t)(index * 29U));
  }
  return fail_this_call ? entropy_error : NOISE_ERROR_NONE;
}

static int test_dh_entropy_failure(const char *test, int dependent,
                                   int start_with_keypair, int failure_code) {
  NoiseDHState *state = NULL;
  int actual;
  int success = 0;

  actual = noise_dhstate_new_by_id(&state, NOISE_DH_CURVE25519);
  if (!expect_error(test, "create Curve25519 state", actual, NOISE_ERROR_NONE))
    goto cleanup;
  if (start_with_keypair) {
    reset_entropy();
    actual = noise_dhstate_generate_keypair(state);
    if (!expect_error(test, "install initial keypair", actual,
                      NOISE_ERROR_NONE) ||
        !noise_dhstate_has_keypair(state)) {
      (void)fail(test, "initial keypair was not installed");
      goto cleanup;
    }
  }

  reset_entropy();
  fail_entropy_on(1U, 9U, failure_code);
  actual = dependent ? noise_dhstate_generate_dependent_keypair(state, NULL)
                     : noise_dhstate_generate_keypair(state);
  if (!expect_error(test, "generate with partial entropy failure", actual,
                    failure_code) ||
      entropy_calls != 1U || state->key_type != NOISE_KEY_TYPE_NO_KEY ||
      noise_dhstate_has_keypair(state) || noise_dhstate_has_public_key(state) ||
      !bytes_are(state->private_key, state->private_key_len, 0U) ||
      !bytes_are(state->public_key, state->public_key_len, 0U)) {
    (void)fail(test,
               "failed generation did not clear and invalidate both keys");
    goto cleanup;
  }

  reset_entropy();
  actual = dependent ? noise_dhstate_generate_dependent_keypair(state, NULL)
                     : noise_dhstate_generate_keypair(state);
  if (!expect_error(test, "recover with a later successful generation", actual,
                    NOISE_ERROR_NONE) ||
      !noise_dhstate_has_keypair(state) ||
      state->key_type != NOISE_KEY_TYPE_KEYPAIR ||
      !any_nonzero(state->private_key, state->private_key_len) ||
      !any_nonzero(state->public_key, state->public_key_len)) {
    (void)fail(test, "successful retry did not install a fresh keypair");
    goto cleanup;
  }
  success = 1;

cleanup:
  if (state != NULL &&
      !expect_error(test, "free Curve25519 state", noise_dhstate_free(state),
                    NOISE_ERROR_NONE))
    success = 0;
  return success;
}

static int test_dh_failures(void) {
  return test_dh_entropy_failure("DH fresh generate_keypair", 0, 0,
                                 NOISE_ERROR_SYSTEM) &&
         test_dh_entropy_failure("DH existing generate_keypair", 0, 1,
                                 NOISE_ERROR_SYSTEM) &&
         test_dh_entropy_failure("DH fresh generate_dependent_keypair", 1, 0,
                                 NOISE_ERROR_SYSTEM) &&
         test_dh_entropy_failure("DH existing generate_dependent_keypair", 1, 1,
                                 NOISE_ERROR_NO_MEMORY);
}

static int test_randstate_new_failure(void) {
  NoiseRandState *state = (NoiseRandState *)(uintptr_t)1U;
  int actual;

  reset_entropy();
  fail_entropy_on(1U, 7U, NOISE_ERROR_SYSTEM);
  actual = noise_randstate_new(&state);
  if (!expect_error("RandState new failure", "create with partial entropy",
                    actual, NOISE_ERROR_SYSTEM) ||
      state != NULL || entropy_calls != 1U)
    return fail("RandState new failure",
                "failed creation must return a null state");
  return 1;
}

static int test_randstate_reseed_invalidation(void) {
  NoiseRandState *state = NULL;
  uint8_t output[PROBE_SMALL_BUFFER_SIZE];
  size_t calls_after_failure;
  int actual;
  int success = 0;

  reset_entropy();
  actual = noise_randstate_new(&state);
  if (!expect_error("RandState reseed failure", "create state", actual,
                    NOISE_ERROR_NONE))
    goto cleanup;

  reset_entropy();
  fail_entropy_on(1U, 5U, NOISE_ERROR_SYSTEM);
  actual = noise_randstate_reseed(state);
  if (!expect_error("RandState reseed failure", "reseed with partial entropy",
                    actual, NOISE_ERROR_SYSTEM) ||
      entropy_calls != 1U)
    goto cleanup;
  calls_after_failure = entropy_calls;

  memset(output, 0xA5, sizeof(output));
  actual = noise_randstate_generate(state, output, sizeof(output));
  if (!expect_error("RandState reseed failure", "generate before recovery",
                    actual, NOISE_ERROR_INVALID_STATE) ||
      entropy_calls != calls_after_failure ||
      !expect_zero("RandState reseed failure",
                   "invalid-state output was not cleared", output,
                   sizeof(output)))
    goto cleanup;

  actual = noise_randstate_reseed(state);
  if (!expect_error("RandState reseed failure", "explicit recovery reseed",
                    actual, NOISE_ERROR_NONE))
    goto cleanup;
  memset(output, 0xA5, sizeof(output));
  actual = noise_randstate_generate(state, output, sizeof(output));
  if (!expect_error("RandState reseed failure", "generate after recovery",
                    actual, NOISE_ERROR_NONE) ||
      !any_nonzero(output, sizeof(output)))
    goto cleanup;
  success = 1;

cleanup:
  if (state != NULL &&
      !expect_error("RandState reseed failure", "free state",
                    noise_randstate_free(state), NOISE_ERROR_NONE))
    success = 0;
  return success;
}

static int test_randstate_error_propagation(void) {
  NoiseRandState *state = NULL;
  uint8_t simple_output[PROBE_SMALL_BUFFER_SIZE];
  int actual;
  int success = 0;

  reset_entropy();
  actual = noise_randstate_new(&state);
  if (!expect_error("RandState error propagation", "create state", actual,
                    NOISE_ERROR_NONE))
    goto cleanup;
  reset_entropy();
  fail_entropy_on(1U, 3U, NOISE_ERROR_NO_MEMORY);
  actual = noise_randstate_reseed(state);
  if (!expect_error("RandState error propagation", "propagate reseed sentinel",
                    actual, NOISE_ERROR_NO_MEMORY))
    goto cleanup;

  reset_entropy();
  fail_entropy_on(1U, 11U, NOISE_ERROR_SYSTEM);
  memset(simple_output, 0xA5, sizeof(simple_output));
  actual =
      noise_randstate_generate_simple(simple_output, sizeof(simple_output));
  if (!expect_error("RandState error propagation", "simple generation failure",
                    actual, NOISE_ERROR_SYSTEM) ||
      !expect_zero("RandState error propagation",
                   "simple output was not cleared", simple_output,
                   sizeof(simple_output)))
    goto cleanup;

  reset_entropy();
  memset(simple_output, 0, sizeof(simple_output));
  actual =
      noise_randstate_generate_simple(simple_output, sizeof(simple_output));
  if (!expect_error("RandState error propagation",
                    "simple deterministic success", actual, NOISE_ERROR_NONE) ||
      !any_nonzero(simple_output, sizeof(simple_output)))
    goto cleanup;
  success = 1;

cleanup:
  if (state != NULL &&
      !expect_error("RandState error propagation", "free state",
                    noise_randstate_free(state), NOISE_ERROR_NONE))
    success = 0;
  return success;
}

static int test_padding_behavior(void) {
  NoiseRandState *state = NULL;
  uint8_t payload[24];
  uint8_t original[8];
  size_t calls_before;
  int actual;
  int success = 0;

  reset_entropy();
  actual = noise_randstate_new(&state);
  if (!expect_error("RandState padding", "create state", actual,
                    NOISE_ERROR_NONE))
    goto cleanup;

  memset(payload, 0xA5, sizeof(payload));
  memcpy(payload, "payload!", sizeof(original));
  memcpy(original, payload, sizeof(original));
  actual = noise_randstate_pad(state, payload, sizeof(original), 16U,
                               NOISE_PADDING_ZERO);
  if (!expect_error("RandState padding", "zero pad", actual,
                    NOISE_ERROR_NONE) ||
      memcmp(payload, original, sizeof(original)) != 0 ||
      !bytes_are(payload + sizeof(original), 8U, 0U) ||
      !bytes_are(payload + 16U, sizeof(payload) - 16U, 0xA5U)) {
    (void)fail("RandState padding",
               "zero padding changed payload or crossed its boundary");
    goto cleanup;
  }

  calls_before = entropy_calls;
  memset(payload, 0x5A, sizeof(payload));
  memcpy(payload, original, sizeof(original));
  actual = noise_randstate_pad(state, payload, sizeof(original),
                               sizeof(original), NOISE_PADDING_RANDOM);
  if (!expect_error("RandState padding", "equal-length random pad no-op",
                    actual, NOISE_ERROR_NONE) ||
      entropy_calls != calls_before ||
      !bytes_are(payload + sizeof(original), sizeof(payload) - sizeof(original),
                 0x5AU)) {
    (void)fail("RandState padding",
               "equal-length padding consumed entropy or changed bytes");
    goto cleanup;
  }
  actual = noise_randstate_pad(state, payload, sizeof(original), 4U,
                               NOISE_PADDING_ZERO);
  if (!expect_error("RandState padding", "shorter-length zero pad no-op",
                    actual, NOISE_ERROR_NONE) ||
      entropy_calls != calls_before ||
      !bytes_are(payload + sizeof(original), sizeof(payload) - sizeof(original),
                 0x5AU)) {
    (void)fail("RandState padding",
               "shorter padding changed the payload buffer");
    goto cleanup;
  }

  fail_entropy_on(entropy_calls + 1U, 4U, NOISE_ERROR_SYSTEM);
  actual = noise_randstate_reseed(state);
  if (!expect_error("RandState padding", "invalidate state on reseed failure",
                    actual, NOISE_ERROR_SYSTEM))
    goto cleanup;
  calls_before = entropy_calls;
  actual = noise_randstate_pad(state, payload, sizeof(original), 16U,
                               NOISE_PADDING_RANDOM);
  if (!expect_error("RandState padding", "propagate invalid generator state",
                    actual, NOISE_ERROR_INVALID_STATE) ||
      entropy_calls != calls_before ||
      memcmp(payload, original, sizeof(original)) != 0 ||
      !expect_zero("RandState padding", "failed random padding was not cleared",
                   payload + sizeof(original), 8U) ||
      !bytes_are(payload + 16U, sizeof(payload) - 16U, 0x5AU)) {
    (void)fail("RandState padding",
               "random-pad failure changed input or missed output cleanup");
    goto cleanup;
  }

  actual = noise_randstate_reseed(state);
  if (!expect_error("RandState padding", "recover state after failed padding",
                    actual, NOISE_ERROR_NONE))
    goto cleanup;
  memset(payload, 0x3C, sizeof(payload));
  memcpy(payload, original, sizeof(original));
  actual = noise_randstate_pad(state, payload, sizeof(original), 16U,
                               NOISE_PADDING_RANDOM);
  if (!expect_error("RandState padding", "random pad success", actual,
                    NOISE_ERROR_NONE) ||
      memcmp(payload, original, sizeof(original)) != 0 ||
      !any_nonzero(payload + sizeof(original), 8U) ||
      !bytes_are(payload + 16U, sizeof(payload) - 16U, 0x3CU)) {
    (void)fail("RandState padding",
               "random padding changed source bytes or crossed its boundary");
    goto cleanup;
  }
  success = 1;

cleanup:
  if (state != NULL &&
      !expect_error("RandState padding", "free state",
                    noise_randstate_free(state), NOISE_ERROR_NONE))
    success = 0;
  return success;
}

static int test_invalid_parameter_behavior(void) {
  NoiseRandState *state = NULL;
  uint8_t buffer[16];
  size_t calls_before;
  int actual;

  actual = noise_randstate_new(NULL);
  if (!expect_error("RandState invalid parameters", "new null out pointer",
                    actual, NOISE_ERROR_INVALID_PARAM))
    return 0;
  actual = noise_randstate_reseed(NULL);
  if (!expect_error("RandState invalid parameters", "reseed null state", actual,
                    NOISE_ERROR_INVALID_PARAM))
    return 0;
  actual = noise_randstate_free(NULL);
  if (!expect_error("RandState invalid parameters", "free null state", actual,
                    NOISE_ERROR_INVALID_PARAM))
    return 0;
  reset_entropy();
  actual = noise_randstate_new(&state);
  if (!expect_error("RandState invalid parameters", "create state", actual,
                    NOISE_ERROR_NONE))
    return 0;
  calls_before = entropy_calls;
  actual = noise_randstate_generate(state, NULL, sizeof(buffer));
  if (!expect_error("RandState invalid parameters", "generate null output",
                    actual, NOISE_ERROR_INVALID_PARAM) ||
      entropy_calls != calls_before) {
    (void)noise_randstate_free(state);
    return 0;
  }
  actual = noise_randstate_pad(state, NULL, 4U, sizeof(buffer),
                               NOISE_PADDING_RANDOM);
  if (!expect_error("RandState invalid parameters", "pad null payload", actual,
                    NOISE_ERROR_INVALID_PARAM)) {
    (void)noise_randstate_free(state);
    return 0;
  }
  if (!expect_error("RandState invalid parameters", "free state",
                    noise_randstate_free(state), NOISE_ERROR_NONE))
    return 0;

  memset(buffer, 0xA5, sizeof(buffer));
  actual = noise_randstate_generate(NULL, buffer, sizeof(buffer));
  if (!expect_error("RandState invalid parameters", "generate null state",
                    actual, NOISE_ERROR_INVALID_PARAM) ||
      !expect_zero("RandState invalid parameters",
                   "null-state output was not cleared", buffer, sizeof(buffer)))
    return 0;
  memset(buffer, 0xA5, sizeof(buffer));
  actual = noise_randstate_pad(NULL, buffer, 4U, sizeof(buffer),
                               NOISE_PADDING_RANDOM);
  if (!expect_error("RandState invalid parameters", "pad null state", actual,
                    NOISE_ERROR_INVALID_PARAM) ||
      !expect_zero("RandState invalid parameters",
                   "null-state padding was not cleared", buffer + 4U,
                   sizeof(buffer) - 4U))
    return 0;
  actual = noise_randstate_generate_simple(NULL, sizeof(buffer));
  if (!expect_error("RandState invalid parameters", "simple null output",
                    actual, NOISE_ERROR_INVALID_PARAM))
    return 0;
  return 1;
}

static int test_large_request_reseed_failures(void) {
  NoiseRandState *state = NULL;
  uint8_t *output = (uint8_t *)malloc(PROBE_LARGE_REQUEST_SIZE + 1U);
  int actual;
  int success = 0;

  if (output == NULL)
    return fail("RandState large request",
                "could not allocate bounded 1.6 MB host buffer");

  reset_entropy();
  actual = noise_randstate_new(&state);
  if (!expect_error("RandState pre-request reseed", "create state", actual,
                    NOISE_ERROR_NONE))
    goto cleanup;
  memset(output, 0xA5, PROBE_LARGE_REQUEST_SIZE);
  observed_output = output;
  observed_output_size = PROBE_LARGE_REQUEST_SIZE;
  fail_entropy_on(2U, 13U, NOISE_ERROR_SYSTEM);
  actual = noise_randstate_generate(state, output, PROBE_LARGE_REQUEST_SIZE);
  if (!expect_error("RandState pre-request reseed", "generate across threshold",
                    actual, NOISE_ERROR_SYSTEM) ||
      entropy_calls != 2U || output_nonzero_at_failure ||
      !expect_zero("RandState pre-request reseed",
                   "failed output was not cleared", output,
                   PROBE_LARGE_REQUEST_SIZE))
    goto cleanup;
  if (!expect_error("RandState pre-request reseed", "free state",
                    noise_randstate_free(state), NOISE_ERROR_NONE))
    goto cleanup;
  state = NULL;

  reset_entropy();
  actual = noise_randstate_new(&state);
  if (!expect_error("RandState mid-request reseed", "create state", actual,
                    NOISE_ERROR_NONE))
    goto cleanup;
  memset(output, 0xA5, PROBE_LARGE_REQUEST_SIZE);
  observed_output = output;
  observed_output_size = PROBE_LARGE_REQUEST_SIZE;
  fail_entropy_on(3U, 13U, NOISE_ERROR_SYSTEM);
  actual = noise_randstate_generate(state, output, PROBE_LARGE_REQUEST_SIZE);
  if (!expect_error("RandState mid-request reseed", "generate across threshold",
                    actual, NOISE_ERROR_SYSTEM) ||
      entropy_calls != 3U || !output_nonzero_at_failure ||
      !expect_zero("RandState mid-request reseed",
                   "whole failed output was not cleared", output,
                   PROBE_LARGE_REQUEST_SIZE))
    goto cleanup;

  {
    size_t calls_after_failure = entropy_calls;
    memset(output, 0xA5, PROBE_SMALL_BUFFER_SIZE);
    actual = noise_randstate_generate(state, output, PROBE_SMALL_BUFFER_SIZE);
    if (!expect_error("RandState mid-request reseed",
                      "generate after invalidation", actual,
                      NOISE_ERROR_INVALID_STATE) ||
        entropy_calls != calls_after_failure ||
        !expect_zero("RandState mid-request reseed",
                     "invalid-state output was not cleared", output,
                     PROBE_SMALL_BUFFER_SIZE))
      goto cleanup;
  }

  if (!expect_error("RandState mid-request reseed", "free invalidated state",
                    noise_randstate_free(state), NOISE_ERROR_NONE))
    goto cleanup;
  state = NULL;

  reset_entropy();
  actual = noise_randstate_new(&state);
  if (!expect_error("RandState pad reseed failure", "create state", actual,
                    NOISE_ERROR_NONE))
    goto cleanup;
  memset(output, 0xA5, PROBE_LARGE_REQUEST_SIZE + 1U);
  output[0] = 0x77U;
  observed_output = output + 1U;
  observed_output_size = PROBE_LARGE_REQUEST_SIZE;
  fail_entropy_on(2U, 13U, NOISE_ERROR_SYSTEM);
  actual = noise_randstate_pad(state, output, 1U, PROBE_LARGE_REQUEST_SIZE + 1U,
                               NOISE_PADDING_RANDOM);
  if (!expect_error("RandState pad reseed failure", "pad across threshold",
                    actual, NOISE_ERROR_SYSTEM) ||
      entropy_calls != 2U || output_nonzero_at_failure || output[0] != 0x77U ||
      !expect_zero("RandState pad reseed failure",
                   "padding output was not cleared", output + 1U,
                   PROBE_LARGE_REQUEST_SIZE))
    goto cleanup;
  success = 1;

cleanup:
  if (state != NULL &&
      !expect_error("RandState large request", "free state",
                    noise_randstate_free(state), NOISE_ERROR_NONE))
    success = 0;
  free(output);
  return success;
}

int main(void) {
  int actual = noise_init_framework();
  if (!expect_error("Noise RNG state probe", "initialize framework", actual,
                    NOISE_ERROR_NONE))
    return 1;

  if (!test_dh_failures() || !test_randstate_new_failure() ||
      !test_randstate_reseed_invalidation() ||
      !test_randstate_error_propagation() || !test_padding_behavior() ||
      !test_invalid_parameter_behavior() ||
      !test_large_request_reseed_failures())
    return 1;

  puts("Fallible entropy propagation, DH cleanup, RandState invalidation, and "
       "output clearing probes passed.");
  puts("The host probe checks API behavior; direct full-erasure verification "
       "remains a source-review gate, not an entropy-quality claim.");
  return 0;
}
