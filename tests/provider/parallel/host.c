#define _POSIX_C_SOURCE 200809L
#include "parallel.h"
#include "report.h"
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <time.h>
static _Thread_local unsigned worker_id = DMP_PARALLEL_WORKERS;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
static unsigned arrived, running, peak, count, cycles;
static int released;
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
    ++running;
    if (running > peak) peak = running;
    pthread_mutex_unlock(&mutex);
}
void dmp_parallel_call_leave(void)
{
    pthread_mutex_lock(&mutex);
    --running;
    pthread_mutex_unlock(&mutex);
}
int dmp_parallel_yield(void) { return sched_yield(); }
static void *worker(void *argument)
{
    worker_id = *(unsigned *)argument;
    pthread_mutex_lock(&mutex);
    ++arrived;
    pthread_cond_broadcast(&ready);
    while (!released) pthread_cond_wait(&ready, &mutex);
    pthread_mutex_unlock(&mutex);
    errors[worker_id] = dmp_parallel_run(worker_id, cycles, &results[worker_id]);
    return NULL;
}
int main(int argc, char **argv)
{
    pthread_t threads[2];
    unsigned ids[2] = {0, 1}, i;
    int failed = 0;
    if (argc != 3) return 2;
    count = (unsigned)strtoul(argv[1], NULL, 10);
    cycles = (unsigned)strtoul(argv[2], NULL, 10);
    if (count < 1 || count > 2 || cycles < 4 || cycles > 256 || cycles % 4) return 2;
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
        if (errors[i] || !dmp_parallel_result_ok(&results[i], cycles)) failed = 1;
    }
    if (peak != count || running) failed = 1;
    printf("{\"success\":%s,\"workers\":%u,\"cycles\":%u,\"max_inflight\":%u,\"results\":[",
           failed ? "false" : "true", count, cycles, peak);
    for (i = 0; i < count; ++i) {
        if (i) putchar(',');
        dmp_parallel_print_result(&results[i]);
    }
    puts("]}");
    return failed;
}
