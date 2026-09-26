/* Host probe for Noise framework initialization result propagation. */
#include <noise/defines.h>
#include <noise/protocol.h>

#include <stdio.h>
#include <string.h>

#if NOISE_USE_PTHREAD
#include <pthread.h>
#endif

#define PROBE_THREAD_COUNT 8U
#define PROBE_SERIAL_CALL_COUNT 3U

static int sodium_stub_result;
static unsigned int sodium_stub_calls;

/* sodium_init is renamed to this symbol for both util.c and this probe. */
int noise_test_sodium_init(void) {
  ++sodium_stub_calls;
  return sodium_stub_result;
}

static int expected_wrapper_result(void) {
  return sodium_stub_result < 0 ? NOISE_ERROR_SYSTEM : NOISE_ERROR_NONE;
}

static int parse_result(int argc, char **argv, const char **label) {
  *label = "success";
  sodium_stub_result = 0;
  if (argc == 1)
    return 1;
  if (argc != 2)
    return 0;
  if (strcmp(argv[1], "success") == 0) {
    *label = "success";
    return 1;
  }
  if (strcmp(argv[1], "already") == 0) {
    *label = "already initialized";
    sodium_stub_result = 1;
    return 1;
  }
  if (strcmp(argv[1], "failure") == 0) {
    *label = "failure";
    sodium_stub_result = -1;
    return 1;
  }
  return 0;
}

static int check_result(const char *case_name, int actual, int expected) {
  if (actual == expected)
    return 1;
  fprintf(stderr, "%s: noise_init_framework() returned %d; expected %d\n",
          case_name, actual, expected);
  return 0;
}

#if NOISE_USE_PTHREAD
typedef struct probe_thread_result {
  int result;
} probe_thread_result_t;

static void *call_framework_init(void *argument) {
  probe_thread_result_t *thread_result = (probe_thread_result_t *)argument;
  thread_result->result = noise_init_framework();
  return NULL;
}
#endif

int main(int argc, char **argv) {
  const char *case_label;
  unsigned int index;
  int expected;

  if (!parse_result(argc, argv, &case_label)) {
    fprintf(stderr, "usage: %s [success|already|failure]\n", argv[0]);
    return 2;
  }
  expected = expected_wrapper_result();

#if NOISE_USE_PTHREAD
  {
    pthread_t threads[PROBE_THREAD_COUNT];
    probe_thread_result_t results[PROBE_THREAD_COUNT];

    for (index = 0U; index < PROBE_THREAD_COUNT; ++index) {
      results[index].result = NOISE_ERROR_INVALID_STATE;
      if (pthread_create(&threads[index], NULL, call_framework_init,
                         &results[index]) != 0) {
        fprintf(stderr, "pthread_create failed at worker %u\n", index);
        return 1;
      }
    }
    for (index = 0U; index < PROBE_THREAD_COUNT; ++index) {
      if (pthread_join(threads[index], NULL) != 0) {
        fprintf(stderr, "pthread_join failed at worker %u\n", index);
        return 1;
      }
      if (!check_result("concurrent call", results[index].result, expected))
        return 1;
    }

    /* pthread_once retains this outcome, including an initialization failure. */
    for (index = 0U; index < 2U; ++index) {
      if (!check_result("repeated call", noise_init_framework(), expected))
        return 1;
    }
    if (sodium_stub_calls != 1U) {
      fprintf(stderr, "pthread variant invoked sodium stub %u times; expected 1\n",
              sodium_stub_calls);
      return 1;
    }
  }
#else
  for (index = 0U; index < PROBE_SERIAL_CALL_COUNT; ++index) {
    if (!check_result("serialized call", noise_init_framework(), expected))
      return 1;
    if (sodium_stub_calls != index + 1U) {
      fprintf(stderr,
              "serialized call %u invoked sodium stub %u times; expected %u\n",
              index + 1U, sodium_stub_calls, index + 1U);
      return 1;
    }
  }
#endif

  printf("PASS: injected %s result; wrapper result %d; real backend initialization not exercised.\n",
         case_label, expected);
  return 0;
}
