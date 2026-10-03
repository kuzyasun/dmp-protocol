#ifndef DMP_HARNESS_H
#define DMP_HARNESS_H

#include "dmp/transport.h"

#include <stddef.h>
#include <stdint.h>

#define HARNESS_MAX_ACTIONS 8192U
#define HARNESS_MAX_FAULTS 8192U
#define HARNESS_MAX_EVENTS 65536U
#define HARNESS_MAX_TRACE_RECORDS 65536U
#define HARNESS_MAX_TRACE_BYTES 16777216U
#define HARNESS_TRACE_RESERVE_BYTES 1024U
#define HARNESS_MAX_VIRTUAL_MS 86400000ULL
#define HARNESS_SCENARIO_MAX_BYTES 1048576U

typedef struct harness_binding {
    uint32_t encoded_mtu;
    uint32_t frame_tx_ms;
    uint32_t delay_ms[2];
    uint32_t period_ms;
    uint32_t width_ms;
    uint32_t queue_ms;
    uint32_t adapter_slots;
    int borrow;
    int synchronous_completion;
    uint64_t until_ms;
    uint32_t seed;
    uint64_t loss_threshold;
    int stress;
    char sha256[65];
    char seed_text[9];
} harness_binding;

typedef struct harness_action {
    uint64_t at_ms;
    int cancel;
    uint32_t order;
    uint8_t link;
    uint32_t id;
    const uint8_t *data;
    size_t data_len;
    uint64_t not_after_ms;
    uint32_t reply_to;
    uint8_t return_slot;
} harness_action;

typedef struct harness_fault {
    uint8_t link;
    uint32_t ordinal;
    int drop;
    uint8_t duplicates;
    uint32_t delivery_delay_ms;
    uint32_t completion_delay_ms;
    int used;
} harness_fault;

typedef struct harness_result {
    int exit_code;
    char outcome[32];
    size_t trace_len;
    uint32_t accepted;
    uint32_t rejected;
    uint32_t delivered;
    uint32_t terminal;
    uint32_t pending_local;
    uint32_t pending_delivery;
    uint32_t events;
} harness_result;

/* Runs the transport self-test. trace_cap must be at least HARNESS_MAX_TRACE_BYTES.
 * faults are updated with used marks. Returns 0 when a terminal record was stored. */
int harness_execute(const harness_binding *binding, harness_action *actions, size_t nactions,
                    harness_fault *faults, size_t nfaults, char *trace, size_t trace_cap,
                    harness_result *result);

int harness_trace_budget_self_check(void);
uint32_t harness_xorshift32(uint32_t state);

typedef struct harness_adapter harness_adapter;

harness_adapter *harness_adapter_create(const harness_binding *binding);
void harness_adapter_destroy(harness_adapter *adapter);
dmp_transport *harness_adapter_transport(harness_adapter *adapter);
void harness_adapter_set_now(harness_adapter *adapter, uint64_t now);
void harness_adapter_arm(harness_adapter *adapter, uint8_t link, uint32_t id, int is_return,
                         uint32_t reply_to, uint8_t return_slot, uint32_t completion_delay_ms,
                         uint32_t delivery_delay_ms, int drop, uint8_t duplicates);
int harness_adapter_in_submit(const harness_adapter *adapter);
const uint8_t *harness_adapter_borrowed(const harness_adapter *adapter, uint32_t id);
int harness_adapter_stored_byte(const harness_adapter *adapter, uint32_t id, uint8_t *byte);
void harness_adapter_run(harness_adapter *adapter);
uint32_t harness_adapter_pending_local(const harness_adapter *adapter);
uint32_t harness_adapter_pending_delivery(const harness_adapter *adapter);

#endif
