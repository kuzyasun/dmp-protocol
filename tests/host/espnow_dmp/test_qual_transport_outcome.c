#include "qual_transport_outcome.h"

#include <stdio.h>

int main(void)
{
    if (dmp_qual_espnow_tx_outcome(true) != DMP_TX_TRANSMITTED) {
        fputs("MAC acknowledgement must map to transmitted\n", stderr);
        return 1;
    }
    if (dmp_qual_espnow_tx_outcome(false) != DMP_TX_POSSIBLY_TRANSMITTED) {
        fputs("missing MAC acknowledgement must remain possibly transmitted\n", stderr);
        return 1;
    }
    return 0;
}
