#ifndef DMP_MESH_H
#define DMP_MESH_H

#include "dmp/identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Static-unicast transparent relay. Caller-owned tables; forward does not
 * allocate, decrypt, or rewrite the application payload. The only core-frame
 * mutation on success is the remaining-forwards nibble, plus a recomputed
 * CRC32C trailer when INTEGRITY is present. SECURITY tags are copied.
 * Jitter is not sampled: admission requires the admitted profile's jitter_ms
 * to be zero. This is not an endpoint and holds no traffic keys. */

typedef enum { DMP_MESH_FORWARD = 0, DMP_MESH_RETURN = 1 } dmp_mesh_direction;

/* Manifest value reject-ge-2pow24. The other declared policy is not selected
 * by the RADIO-1 relays and is rejected at init. */
typedef enum { DMP_MESH_PN_REJECT_GE_2POW24 = 1 } dmp_mesh_pn_filter;

typedef struct {
    uint32_t destination;
    uint32_t next_hop;
} dmp_mesh_route;

typedef struct {
    dmp_message_origin origin;
    uint32_t seq;
    uint8_t unfragmented;
    uint32_t fragment_index;
    dmp_time_ms admitted_at;
    dmp_time_ms expires_at;
    dmp_time_ms last_completion;
    uint32_t forwards;
    uint8_t occupied;
} dmp_mesh_cache_slot;

typedef struct {
    uint32_t origin_id;
    uint32_t used_ms;
    uint8_t occupied;
} dmp_mesh_airtime;

typedef struct {
    const dmp_admitted_profile *profile;
    uint32_t self_node;
    dmp_mesh_pn_filter pn_filter;
    uint32_t cooldown_ms;
    uint32_t expiry_ms;
    uint32_t max_forwards_per_key;
    uint32_t frame_tx_ms;
    uint32_t per_origin_airtime_ms;
    uint32_t global_airtime_ms;
    uint32_t return_period_ms;
    uint32_t return_width_ms;
    const dmp_mesh_route *routes;
    size_t route_count;
    dmp_mesh_cache_slot *cache;
    size_t cache_count;
    dmp_mesh_airtime *airtime;
    size_t airtime_count;
    uint32_t global_used_ms;
} dmp_mesh_relay;

typedef struct {
    dmp_mesh_direction direction;
    dmp_time_ms now;
    /* Absolute completion of this forward. Cooldown starts here, at last
     * forward completion, and is not moved by a duplicate refused in cooldown. */
    dmp_time_ms tx_complete_at;
    /* Origin transmission start that opened the return window. Ignored on
     * DMP_MESH_FORWARD. */
    dmp_time_ms source_start_ms;
    uint8_t return_slot;
    dmp_bytes frame;
    dmp_core_limits limits;
} dmp_mesh_forward_in;

typedef struct {
    uint32_t next_hop;
    dmp_time_ms transmit_at;
    size_t written;
} dmp_mesh_forward_out;

/* Zeros cache, airtime and global_used_ms after the borrowed tables check
 * out. Failure leaves those tables unchanged. */
dmp_status dmp_mesh_relay_init(dmp_mesh_relay *relay);

/* On failure the output bytes and *out are unchanged, and no cache, airtime,
 * replay or endpoint state is written. */
dmp_status dmp_mesh_relay_forward(dmp_mesh_relay *relay, const dmp_mesh_forward_in *in,
                                  dmp_buffer output, dmp_mesh_forward_out *out);

#ifdef __cplusplus
}
#endif
#endif
