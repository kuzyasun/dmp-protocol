/* Windows-only diagnostic: actual backend startup with injected OS RNG failure. */
#include <noise/protocol.h>
#include <windows.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int inject_failure;
static unsigned int rng_calls;

BOOLEAN NTAPI __real_SystemFunction036(PVOID buffer, ULONG size);
BOOLEAN NTAPI __wrap_SystemFunction036(PVOID buffer, ULONG size)
{
    ++rng_calls;
    if (inject_failure) {
        fputs("OS_RNG_FAILURE_INJECTED\n", stderr);
        fflush(stderr);
        return FALSE;
    }
    return __real_SystemFunction036(buffer, size);
}

static void observed_abort(int signal_number)
{
    /* Avoid interactive crash reporting; distinguish the actual SIGABRT path. */
    _Exit(signal_number == SIGABRT ? 86 : 87);
}

int main(int argc, char **argv)
{
    int result;
    if (argc != 2 || (strcmp(argv[1], "healthy") != 0 &&
                      strcmp(argv[1], "failure") != 0))
        return 2;
    inject_failure = strcmp(argv[1], "failure") == 0;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (signal(SIGABRT, observed_abort) == SIG_ERR)
        return 3;
    result = noise_init_framework();
    printf("INIT_RETURNED result=%d rng_calls=%u\n", result, rng_calls);
    /* Reaching here on the failing path means the recorded blocker changed. */
    return result == NOISE_ERROR_NONE && rng_calls != 0U ? 0 : 4;
}
