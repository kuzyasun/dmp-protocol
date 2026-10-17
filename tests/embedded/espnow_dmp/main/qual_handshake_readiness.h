#ifndef QUAL_HANDSHAKE_READINESS_H
#define QUAL_HANDSHAKE_READINESS_H

#include <stdbool.h>

bool dmp_qual_application_tx_allowed(bool association_active,
                                     bool confirmation_transport_ready);

#endif
