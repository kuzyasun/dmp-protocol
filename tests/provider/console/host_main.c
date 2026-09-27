/* Two separate processes model separate MCU storage/initialization domains. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include "bench.h"
#include <stdio.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#endif

uint64_t dmp_bench_time_us(void)
{
#ifdef _WIN32
    LARGE_INTEGER counter, frequency;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    return (uint64_t)(counter.QuadPart / frequency.QuadPart) * 1000000u +
        (uint64_t)(counter.QuadPart % frequency.QuadPart) * 1000000u / frequency.QuadPart;
#else
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000u + (uint64_t)now.tv_nsec / 1000u;
#endif
}
int dmp_bench_entropy(void *bytes, size_t size)
{
#ifdef _WIN32
    return BCryptGenRandom(NULL, bytes, (ULONG)size, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0;
#else
    FILE *source = fopen("/dev/urandom", "rb");
    int ok;
    if (!source) return 1;
    ok = fread(bytes, 1, size, source) == size;
    fclose(source);
    return !ok;
#endif
}
void dmp_bench_platform_metrics(dmp_bench_metrics *m)
{
    *m = (dmp_bench_metrics){0};
    m->target = "host";
    m->idf = "none";
}
int main(void)
{
    static char line[DMP_BENCH_LINE], response[DMP_BENCH_REPLY];
    size_t used = 0;
    int c, discarded = 0;
    if (dmp_bench_init()) return 1;
    while ((c = getchar()) != EOF) {
        if (c == '\n') {
            if (used && line[used - 1] == '\r') --used;
            line[used] = 0;
            dmp_bench_command(discarded ? NULL : line, response);
            puts(response);
            fflush(stdout);
            used = 0;
            discarded = 0;
        } else if (!discarded) {
            if (used == sizeof(line) - 1 || c == 0 ||
                (c < 32 && c != '\r' && c != '\t') || c > 126) discarded = 1;
            else line[used++] = (char)c;
        }
    }
    return 0;
}
