#include "qual_handshake_readiness.h"

#include <assert.h>

int main(void)
{
    assert(!dmp_qual_application_tx_allowed(false, false));
    assert(!dmp_qual_application_tx_allowed(false, true));
    assert(!dmp_qual_application_tx_allowed(true, false));
    assert(dmp_qual_application_tx_allowed(true, true));
    return 0;
}
