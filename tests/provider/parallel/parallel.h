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
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
    unsigned topology_barrier_reached;
    unsigned pending_live, associations_live, cipher_states_live;
    unsigned topology_traffic_checks_completed;
    size_t topology_retained, topology_blocks, topology_peak;
#endif
} dmp_parallel_result;
/* Platform binds each worker permanently; no ownership migration during run. */
unsigned dmp_parallel_worker_id(void); /* >= WORKERS outside workers */
int dmp_parallel_entropy(void *bytes, size_t size); /* serialized hardware port */
uint64_t dmp_parallel_time_us(void);
void dmp_parallel_call_enter(void);
void dmp_parallel_call_leave(void);
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
void dmp_parallel_noise_allocator_rendezvous(void);
unsigned dmp_parallel_noise_allocator_overlap(void);
#endif
/* Finite platform scheduling checkpoint; nonzero aborts the worker. */
int dmp_parallel_yield(void);
/* Backend init runs once, serially, before tasks. Fresh run only after join. */
int dmp_parallel_init(void);
int dmp_parallel_run(unsigned worker, unsigned cycles, dmp_parallel_result *result);
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
int dmp_parallel_four_parallel_run(unsigned worker, dmp_parallel_result *result);
int dmp_parallel_resource_metrics_reset(void);
size_t dmp_parallel_aggregate_live(void);
size_t dmp_parallel_aggregate_peak(void);
#define DMP_PARALLEL_FOUR_PEERS 4u
#define DMP_PARALLEL_FOUR_PENDING 4u
#define DMP_PARALLEL_FOUR_ASSOCIATIONS 8u
#define DMP_PARALLEL_FOUR_ACTIVE_ASSOCIATIONS 4u
#define DMP_PARALLEL_FOUR_DRAINING_ASSOCIATIONS 4u
#define DMP_PARALLEL_FOUR_CIPHER_STATES 16u
#define DMP_PARALLEL_FOUR_APP_SLOTS 4u
#define DMP_PARALLEL_FOUR_APP_SLOT_BYTES 32u
#endif
#endif
