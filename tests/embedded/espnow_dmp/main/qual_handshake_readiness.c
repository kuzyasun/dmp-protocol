#include "qual_handshake_readiness.h"

bool dmp_qual_application_tx_allowed(bool association_active,
                                     bool confirmation_transport_ready)
{
    return association_active && confirmation_transport_ready;
}
