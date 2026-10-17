#ifndef QUAL_TX_COMPLETION_H
#define QUAL_TX_COMPLETION_H

#include <stdbool.h>
#include <stdint.h>

typedef struct dmp_qual_tx_completion_event {
    uint8_t mac[6];
    int status;
} dmp_qual_tx_completion_event;

/* Caller serializes post/take with a platform lock. A single live TX permits
 * one pending terminal callback, independently of RX event queue pressure. */
typedef struct dmp_qual_tx_completion_slot {
    bool pending;
    dmp_qual_tx_completion_event event;
} dmp_qual_tx_completion_slot;

bool dmp_qual_tx_completion_post(dmp_qual_tx_completion_slot *slot,
                                 const dmp_qual_tx_completion_event *event);
bool dmp_qual_tx_completion_take(dmp_qual_tx_completion_slot *slot,
                                 dmp_qual_tx_completion_event *event);

#endif
