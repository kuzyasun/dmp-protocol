#ifndef DMP_BENCH_H
#define DMP_BENCH_H
#include <stddef.h>
#include <stdint.h>

#define DMP_BENCH_LINE 3072u
#define DMP_BENCH_REPLY 2048u
typedef struct {
    size_t heap_free, heap_min, heap_largest, stack_free_min;
    const char *target, *idf;
} dmp_bench_metrics;
/* Platform hooks: serialized, no reentry into the provider. */
uint64_t dmp_bench_time_us(void);
int dmp_bench_entropy(void *bytes, size_t size);
void dmp_bench_platform_metrics(dmp_bench_metrics *metrics);
int dmp_bench_init(void);
/* Mutable bounded NUL-terminated line, or NULL for discarded malformed input.
 * Always writes one response without trailing newline. Caller owns serial IO. */
void dmp_bench_command(char *line, char response[DMP_BENCH_REPLY]);
#endif
