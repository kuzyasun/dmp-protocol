#ifndef DMP_HARNESS_SCENARIO_H
#define DMP_HARNESS_SCENARIO_H

#include "harness.h"

typedef struct harness_plan {
    harness_action *actions;
    size_t nactions;
    harness_fault *faults;
    size_t nfaults;
    uint8_t *payload;
    size_t payload_len;
    int stress;
    uint64_t until_ms;
    uint64_t loss_threshold;
    uint32_t seed;
    char seed_text[9];
    char sha256[65];
} harness_plan;

/* 0 ok, 2 invalid, 3 budget. Does not echo input. */
int scenario_parse(const uint8_t *bytes, size_t length, harness_plan *plan);
void scenario_plan_free(harness_plan *plan);

#endif
