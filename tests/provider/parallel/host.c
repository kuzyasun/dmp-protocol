#define _POSIX_C_SOURCE 200809L
#include "parallel.h"
#include "report.h"
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
static _Thread_local unsigned worker_id = DMP_PARALLEL_WORKERS;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
static unsigned arrived, wrapper_running, wrapper_peak, count, cycles;
static int released, four_parallel, barrier_failed;
static unsigned call_waiters, call_generation, yield_waiters, yield_generation;
static unsigned allocator_waiters, allocator_generation, allocator_overlap;
static dmp_parallel_result results[2];
static int errors[2];
unsigned dmp_parallel_worker_id(void) { return worker_id; }
uint64_t dmp_parallel_time_us(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000000u + (uint64_t)now.tv_nsec / 1000u;
}
int dmp_parallel_entropy(void *bytes, size_t size)
{
    FILE *source = fopen("/dev/urandom", "rb");
    int error;
    if (!source) return 1;
    error = fread(bytes, 1, size, source) != size;
    fclose(source);
    return error;
}
void dmp_parallel_call_enter(void)
{
    pthread_mutex_lock(&mutex);
    if (four_parallel && !barrier_failed) {
        unsigned generation = call_generation;
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 5;
        if (++call_waiters == count) {
            call_waiters = 0;
            ++call_generation;
            pthread_cond_broadcast(&ready);
        } else {
            while (generation == call_generation && !barrier_failed) {
                int error = pthread_cond_timedwait(&ready, &mutex, &deadline);
                if (error != 0) {
                    barrier_failed = 1;
                    pthread_cond_broadcast(&ready);
                    break;
                }
            }
        }
    }
    /* Count only after the rendezvous, immediately before the real Noise API. */
    ++wrapper_running;
    if (wrapper_running > wrapper_peak) wrapper_peak = wrapper_running;
    pthread_mutex_unlock(&mutex);
}
void dmp_parallel_call_leave(void)
{
    pthread_mutex_lock(&mutex);
    --wrapper_running;
    pthread_mutex_unlock(&mutex);
}
#ifdef DMP_PARALLEL_FOUR_TOPOLOGY
void dmp_parallel_noise_allocator_rendezvous(void)
{
    if (!four_parallel)
        return;
    pthread_mutex_lock(&mutex);
    if (!barrier_failed) {
        unsigned generation = allocator_generation;
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 5;
        ++allocator_waiters;
        if (allocator_waiters > allocator_overlap)
            allocator_overlap = allocator_waiters;
        if (allocator_waiters == count) {
            allocator_waiters = 0;
            ++allocator_generation;
            pthread_cond_broadcast(&ready);
        } else {
            while (generation == allocator_generation && !barrier_failed) {
                int error = pthread_cond_timedwait(&ready, &mutex, &deadline);
                if (error != 0) {
                    barrier_failed = 1;
                    allocator_waiters = 0;
                    ++allocator_generation;
                    pthread_cond_broadcast(&ready);
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&mutex);
}

unsigned dmp_parallel_noise_allocator_overlap(void)
{
    unsigned overlap;
    pthread_mutex_lock(&mutex);
    overlap = allocator_overlap;
    pthread_mutex_unlock(&mutex);
    return overlap;
}
#endif
int dmp_parallel_yield(void)
{
    if (!four_parallel)
        return sched_yield();
    pthread_mutex_lock(&mutex);
    if (!barrier_failed) {
        unsigned generation = yield_generation;
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += 5;
        if (++yield_waiters == count) {
            yield_waiters = 0;
            ++yield_generation;
            pthread_cond_broadcast(&ready);
        } else {
            while (generation == yield_generation && !barrier_failed) {
                int error = pthread_cond_timedwait(&ready, &mutex, &deadline);
                if (error != 0) {
                    barrier_failed = 1;
                    pthread_cond_broadcast(&ready);
                    break;
                }
            }
        }
    }
    int failed = barrier_failed;
    pthread_mutex_unlock(&mutex);
    return failed ? -1 : 0;
}
static void *worker(void *argument)
{
    worker_id = *(unsigned *)argument;
    pthread_mutex_lock(&mutex);
    ++arrived;
    pthread_cond_broadcast(&ready);
    while (!released) pthread_cond_wait(&ready, &mutex);
    pthread_mutex_unlock(&mutex);
    errors[worker_id] = four_parallel
        ? dmp_parallel_four_parallel_run(worker_id, &results[worker_id])
        : dmp_parallel_run(worker_id, cycles, &results[worker_id]);
    return NULL;
}
int main(int argc, char **argv)
{
    pthread_t threads[2];
    unsigned ids[2] = {0, 1}, i;
    int failed = 0;
    if (argc == 2 && strcmp(argv[1], "four_parallel") == 0) {
        four_parallel = 1;
        count = 2;
        cycles = 0;
    } else {
        if (argc != 3) return 2;
        count = (unsigned)strtoul(argv[1], NULL, 10);
        cycles = (unsigned)strtoul(argv[2], NULL, 10);
        if (count < 1 || count > 2 || cycles < 4 || cycles > 256 || cycles % 4) return 2;
    }
    if (four_parallel && dmp_parallel_resource_metrics_reset()) return 3;
    if (dmp_parallel_init()) return 3;
    for (i = 0; i < count; ++i)
        if (pthread_create(&threads[i], NULL, worker, &ids[i])) return 4;
    pthread_mutex_lock(&mutex);
    while (arrived < count) pthread_cond_wait(&ready, &mutex);
    released = 1;
    pthread_cond_broadcast(&ready);
    pthread_mutex_unlock(&mutex);
    for (i = 0; i < count; ++i) {
        if (pthread_join(threads[i], NULL)) return 5;
        if (errors[i] || (four_parallel
            ? results[i].error_line != 0 || !results[i].topology_barrier_reached ||
              results[i].completed != 0U ||
              results[i].topology_traffic_checks_completed !=
                  DMP_PARALLEL_FOUR_ASSOCIATIONS / DMP_PARALLEL_WORKERS ||
              results[i].pending_live != 2U ||
              results[i].associations_live != 4U || results[i].cipher_states_live != 8U ||
              results[i].allocs == 0U || results[i].attempts != results[i].allocs ||
              results[i].allocs != results[i].frees ||
              results[i].live != 0U || results[i].blocks != 0U ||
              results[i].wipe_errors != 0U || results[i].refusals != 0U ||
              results[i].topology_retained == 0U || results[i].topology_blocks == 0U ||
              results[i].topology_peak < results[i].topology_retained ||
              results[i].topology_peak > results[i].backing
            : !dmp_parallel_result_ok(&results[i], cycles))) failed = 1;
    }
    if (wrapper_running != 0U || barrier_failed ||
        (four_parallel ? dmp_parallel_noise_allocator_overlap() != count
                       : wrapper_peak != count)) failed = 1;
    if (four_parallel && (dmp_parallel_aggregate_live() != 0U ||
        dmp_parallel_aggregate_peak() == 0U ||
        dmp_parallel_aggregate_peak() > DMP_PARALLEL_WORKERS * DMP_PARALLEL_CAPACITY ||
        results[0].topology_retained + results[1].topology_retained !=
            dmp_parallel_aggregate_peak())) failed = 1;
    printf("{\"success\":%s,\"case\":\"%s\",\"workers\":%u,\"cycles\":%u,"
           "\"max_tracked_noise_wrapper_inflight\":%u,\"results\":[",
           failed ? "false" : "true", four_parallel ? "four_parallel" : "parallel",
           count, cycles, wrapper_peak);
    for (i = 0; i < count; ++i) {
        if (i) putchar(',');
        dmp_parallel_print_result(&results[i]);
    }
    if (four_parallel) {
        printf("],\"topology\":{\"peers\":%u,\"pending\":%u,\"associations\":%u,"
               "\"active_association_slots\":%u,\"draining_association_slots\":%u,"
               "\"cipher_states\":%u,\"crypto_slots\":%u,"
               "\"application_slots\":%u,\"application_slot_storage_bytes\":%u,"
               "\"application_slots_are_test_driver_buffers\":true,"
               "\"application_slots_counted_in_arena\":false,"
               "\"manifest_row_complete\":false,"
               "\"peer_ids_and_service_registry_modeled\":false,"
               "\"association_lifecycle_and_return_windows_modeled\":false,"
               "\"mtu_and_max_message_bounds_modeled\":false,\"workers\":[",
               DMP_PARALLEL_FOUR_PEERS, DMP_PARALLEL_FOUR_PENDING,
               DMP_PARALLEL_FOUR_ASSOCIATIONS,
               DMP_PARALLEL_FOUR_ACTIVE_ASSOCIATIONS,
               DMP_PARALLEL_FOUR_DRAINING_ASSOCIATIONS,
               DMP_PARALLEL_FOUR_CIPHER_STATES,
               DMP_PARALLEL_WORKERS, DMP_PARALLEL_FOUR_APP_SLOTS,
               DMP_PARALLEL_FOUR_APP_SLOTS * DMP_PARALLEL_FOUR_APP_SLOT_BYTES);
        for (i = 0; i < count; ++i) {
            if (i) putchar(',');
            if (results[i].topology_barrier_reached) {
                printf("{\"topology_barrier_reached\":true,\"pending_at_barrier\":%u,"
                       "\"associations_at_barrier\":%u,\"cipher_states_at_barrier\":%u,"
                       "\"retained_at_barrier\":%zu,\"blocks_at_barrier\":%zu,\"arena_peak\":%zu,"
                       "\"attempts\":%zu,\"allocs\":%zu,\"frees\":%zu}",
                       results[i].pending_live, results[i].associations_live,
                       results[i].cipher_states_live, results[i].topology_retained,
                       results[i].topology_blocks, results[i].topology_peak,
                       results[i].attempts, results[i].allocs, results[i].frees);
            } else {
                printf("{\"topology_barrier_reached\":false,\"pending_at_barrier\":null,"
                       "\"associations_at_barrier\":null,\"cipher_states_at_barrier\":null,"
                       "\"retained_at_barrier\":null,\"blocks_at_barrier\":null,\"arena_peak\":%zu,"
                       "\"attempts\":%zu,\"allocs\":%zu,\"frees\":%zu}",
                       results[i].topology_peak, results[i].attempts,
                       results[i].allocs, results[i].frees);
            }
        }
        printf("],\"noise_allocator_callback_overlap\":%u,\"aggregate_retained_at_barrier\":",
               dmp_parallel_noise_allocator_overlap());
        if (results[0].topology_barrier_reached && results[1].topology_barrier_reached)
            printf("%zu", results[0].topology_retained + results[1].topology_retained);
        else
            printf("null");
        printf(",\"aggregate_peak\":%zu,\"aggregate_live_after\":%zu}}\n",
               dmp_parallel_aggregate_peak(), dmp_parallel_aggregate_live());
    } else {
        puts("]}");
    }
    return failed;
}
