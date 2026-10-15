/* Compile/link references for the pre-hardware ESP32 qualification gate. */
#include "dmp/endpoint.h"
#include "handshake_transport.h"
#include "sample1_endpoint.h"

typedef dmp_status (*endpoint_init_fn)(dmp_endpoint *endpoint,
                                       const dmp_endpoint_storage *storage,
                                       dmp_time_ms now);
typedef dmp_status (*endpoint_add_peer_fn)(
    dmp_endpoint *endpoint, const dmp_identity_context_config *context,
    dmp_time_ms now, dmp_peer_handle *out);
typedef dmp_status (*endpoint_bind_peer_fn)(dmp_endpoint *endpoint,
                                           dmp_peer_handle peer,
                                           struct dmp_hs *handshake,
                                           uint32_t attempt_index);
typedef dmp_status (*endpoint_revoke_peer_fn)(dmp_endpoint *endpoint,
                                              dmp_peer_handle peer,
                                              dmp_time_ms now);
typedef dmp_status (*endpoint_fence_status_fn)(dmp_endpoint *endpoint,
                                               dmp_peer_handle peer);
typedef dmp_hs_tx_status (*handshake_transport_init_fn)(
    dmp_hs_tx *state, dmp_hs *handshake, dmp_transport *transport,
    const dmp_hs_tx_config *config, dmp_hs_tx_lifetime *lifetime,
    const dmp_hs_tx_buffer buffers[DMP_HS_TX_SLOT_MAX]);
typedef dmp_hs_tx_status (*handshake_transport_cancel_fn)(dmp_hs_tx *state,
                                                         dmp_tx_token token);
typedef void (*handshake_transport_expire_fn)(dmp_hs_tx *state,
                                              dmp_time_ms now_ms);
typedef dmp_hs_tx_status (*handshake_transport_take_fn)(
    dmp_hs_tx *state, dmp_hs_tx_result *result);
typedef dmp_sample1_owner_result (*sample1_endpoint_init_fn)(
    dmp_sample1_endpoint *sample, dmp_endpoint *endpoint,
    dmp_sample1_principal principal, const dmp_sample1_endpoint_hooks *hooks);
typedef dmp_sample1_owner_result (*sample1_endpoint_flush_fn)(
    dmp_sample1_endpoint *sample, dmp_time_ms now);

/* Volatile references retain these production objects in both target images.
 * Calling this probe performs no endpoint, transport, or NVS operation. */
static endpoint_init_fn volatile g_endpoint_init_ref;
static endpoint_add_peer_fn volatile g_endpoint_add_peer_ref;
static endpoint_bind_peer_fn volatile g_endpoint_bind_peer_ref;
static endpoint_revoke_peer_fn volatile g_endpoint_revoke_peer_ref;
static endpoint_fence_status_fn volatile g_endpoint_fence_status_ref;
static handshake_transport_init_fn volatile g_handshake_transport_init_ref;
static handshake_transport_cancel_fn volatile g_handshake_transport_cancel_ref;
static handshake_transport_expire_fn volatile g_handshake_transport_expire_ref;
static handshake_transport_take_fn volatile g_handshake_transport_take_ref;
static sample1_endpoint_init_fn volatile g_sample1_endpoint_init_ref;
static sample1_endpoint_flush_fn volatile g_sample1_endpoint_flush_ref;

void dmp_pre_hardware_link_probe(void)
{
    g_endpoint_init_ref = dmp_endpoint_init;
    g_endpoint_add_peer_ref = dmp_endpoint_add_peer;
    g_endpoint_bind_peer_ref = dmp_endpoint_bind_peer;
    g_endpoint_revoke_peer_ref = dmp_endpoint_revoke_peer;
    g_endpoint_fence_status_ref = dmp_endpoint_peer_fence_status;
    g_handshake_transport_init_ref = dmp_hs_tx_init;
    g_handshake_transport_cancel_ref = dmp_hs_tx_cancel;
    g_handshake_transport_expire_ref = dmp_hs_tx_expire;
    g_handshake_transport_take_ref = dmp_hs_tx_take;
    g_sample1_endpoint_init_ref = dmp_sample1_endpoint_init;
    g_sample1_endpoint_flush_ref = dmp_sample1_endpoint_flush;
}
