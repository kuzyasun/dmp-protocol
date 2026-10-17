#ifndef QUAL_TRANSPORT_OUTCOME_H
#define QUAL_TRANSPORT_OUTCOME_H

#include <stdbool.h>

#include "dmp/transport.h"

dmp_tx_outcome dmp_qual_espnow_tx_outcome(bool mac_acknowledged);

#endif
