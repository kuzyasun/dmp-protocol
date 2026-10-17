#include "qual_tx_completion.h"

#include <stddef.h>
#include <string.h>

bool dmp_qual_tx_completion_post(dmp_qual_tx_completion_slot *slot,
                                 const dmp_qual_tx_completion_event *event)
{
    if (slot == NULL || event == NULL || slot->pending) return false;
    slot->event = *event;
    slot->pending = true;
    return true;
}

bool dmp_qual_tx_completion_take(dmp_qual_tx_completion_slot *slot,
                                 dmp_qual_tx_completion_event *event)
{
    if (slot == NULL || event == NULL || !slot->pending) return false;
    *event = slot->event;
    memset(&slot->event, 0, sizeof slot->event);
    slot->pending = false;
    return true;
}
