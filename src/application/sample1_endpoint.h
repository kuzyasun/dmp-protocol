#ifndef DMP_APPLICATION_SAMPLE1_ENDPOINT_H
#define DMP_APPLICATION_SAMPLE1_ENDPOINT_H

#include "dmp/endpoint.h"
#include "sample1_epoch_owner.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *user;
    bool (*try_enter)(void *user);
    void (*leave)(void *user);
    dmp_sample1_port_result (*reserve_next)(void *user,
                                            dmp_sample1_principal principal,
                                            bool *has_previous,
                                            uint64_t *previous_epoch,
                                            uint64_t *reserved_epoch);
    dmp_sample1_port_result (*publish_telem)(void *user,
                                             dmp_sample1_principal principal,
                                             uint64_t sample_epoch,
                                             uint32_t sample_index,
                                             const uint8_t payload[DMP_SAMPLE1_TELEM_BYTES]);
} dmp_sample1_endpoint_hooks;

typedef struct {
    dmp_peer_handle peer;
    dmp_identity_handle active_association;
    dmp_identity_handle draining_association;
    uint64_t active_epoch;
    uint64_t draining_epoch;
    uint8_t live;
} dmp_sample1_peer_epoch;

typedef struct {
    dmp_reliability_handle request_handle;
    dmp_identity_handle association;
    dmp_message_key request;
    uint64_t sample_epoch;
    uint32_t wire_status;
    uint8_t payload[DMP_SAMPLE1_READ_BYTES];
    uint8_t payload_len;
    uint8_t live;
} dmp_sample1_queued_result;

enum {
    DMP_SAMPLE1_ENDPOINT_RESULT_SLOTS = 4U
};

typedef struct {
    dmp_sample1_epoch_owner owner;
    dmp_sample1_endpoint_hooks hooks;
    dmp_endpoint *endpoint;
    dmp_sample1_peer_epoch peers[DMP_PROFILE_MAX_PEERS];
    dmp_sample1_queued_result results[DMP_SAMPLE1_ENDPOINT_RESULT_SLOTS];
    uint8_t initialized;
} dmp_sample1_endpoint;

/* Compose the reusable SAMPLE-1 epoch owner with a real libdmp endpoint.
 * Durable reservation, locking and best-effort publication remain injected
 * application ports. Endpoint fencing, epoch activation, association checks,
 * and correlated READ responses use production endpoint APIs. */
dmp_sample1_owner_result dmp_sample1_endpoint_init(
    dmp_sample1_endpoint *sample, dmp_endpoint *endpoint,
    dmp_sample1_principal principal, const dmp_sample1_endpoint_hooks *hooks);

dmp_sample1_owner_result dmp_sample1_endpoint_begin_epoch(dmp_sample1_endpoint *sample,
                                                          dmp_time_ms now);
dmp_sample1_owner_result dmp_sample1_endpoint_activate_peer(
    dmp_sample1_endpoint *sample, dmp_peer_handle peer);
/* Call after endpoint RX returns. READ notices queue a copied response while
 * running inside the endpoint callback; flush submits those results later. */
dmp_sample1_owner_result dmp_sample1_endpoint_handle_notice(
    dmp_sample1_endpoint *sample, const dmp_endpoint_notice *notice, dmp_time_ms now);
dmp_sample1_owner_result dmp_sample1_endpoint_flush(dmp_sample1_endpoint *sample,
                                                    dmp_time_ms now);
dmp_sample1_owner_result dmp_sample1_endpoint_publish(
    dmp_sample1_endpoint *sample, uint32_t value, dmp_time_ms now);

#ifdef __cplusplus
}
#endif

#endif
