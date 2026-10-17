#include "qual_transport_outcome.h"

dmp_tx_outcome dmp_qual_espnow_tx_outcome(bool mac_acknowledged)
{
    return mac_acknowledged ? DMP_TX_TRANSMITTED : DMP_TX_POSSIBLY_TRANSMITTED;
}
