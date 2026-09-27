#ifndef DMP_PARALLEL_REPORT_H
#define DMP_PARALLEL_REPORT_H
#include "parallel.h"
#include <inttypes.h>
#include <stdio.h>
static int dmp_parallel_result_ok(const dmp_parallel_result *r, unsigned cycles)
{
    return r->error_line == 0 && r->completed == cycles &&
        r->fixed_pairs == cycles / 2 && r->random_pairs == cycles / 2 &&
        r->rng_calls == cycles && r->live == 0 && r->blocks == 0 &&
        r->wipe_errors == 0 && r->refusals == 0 && r->allocs > 0 &&
        r->attempts == r->allocs && r->allocs == r->frees &&
        r->peak > 0 && r->peak <= r->backing;
}
static void dmp_parallel_print_result(const dmp_parallel_result *r)
{
    printf("{\"completed\":%u,\"error_line\":%u,\"fixed_pairs\":%u,\"random_pairs\":%u,"
           "\"attempts\":%zu,\"allocs\":%zu,\"frees\":%zu,\"refusals\":%zu,"
           "\"wipe_errors\":%zu,\"live\":%zu,\"blocks\":%zu,\"peak\":%zu,"
           "\"rng_calls\":%zu,\"backing\":%zu,\"metadata\":%zu,\"scratch\":%zu,"
           "\"max_call_us\":%" PRIu64 "}",
           r->completed, r->error_line, r->fixed_pairs, r->random_pairs,
           r->attempts, r->allocs, r->frees, r->refusals, r->wipe_errors,
           r->live, r->blocks, r->peak, r->rng_calls, r->backing, r->metadata,
           r->scratch, r->max_call_us);
}
#endif
