#ifndef DMP_PARALLEL_H
#define DMP_PARALLEL_H
#include <stddef.h>
#include <stdint.h>
#define DMP_PARALLEL_WORKERS 2u
#define DMP_PARALLEL_CAPACITY 8192u
typedef struct {
    unsigned completed, error_line, fixed_pairs, random_pairs;
    size_t attempts, allocs, frees, refusals, wipe_errors, live, blocks, peak;
    size_t rng_calls, backing, metadata, scratch;
    uint64_t max_call_us;
} dmp_parallel_result;
/* Platform binds each worker permanently; no ownership migration during run. */
unsigned dmp_parallel_worker_id(void); /* >= WORKERS outside workers */
int dmp_parallel_entropy(void *bytes, size_t size); /* serialized hardware port */
uint64_t dmp_parallel_time_us(void);
void dmp_parallel_call_enter(void);
void dmp_parallel_call_leave(void);
/* Finite platform scheduling checkpoint; nonzero aborts the worker. */
int dmp_parallel_yield(void);
/* Backend init runs once, serially, before tasks. Fresh run only after join. */
int dmp_parallel_init(void);
int dmp_parallel_run(unsigned worker, unsigned cycles, dmp_parallel_result *result);
#endif
