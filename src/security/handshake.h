/* Private P13 bootstrap, enrollment, and candidate-key owner.
 * Not a public libdmp header: do not install it and do not include it
 * from include/dmp/. Noise objects stay inside the P01B provider adapter.
 *
 * This module calls dmp_provider_* for handshake open/read/write/split/hash
 * and for the remote static public key. It does not open a second Noise
 * stack, choose a cipher, or export a test-only scheduler.
 *
 * Protected FINISH/READY uses the P01B cipher with S5 AAD and an explicit PN.
 * The S6 window rejects a replay or a PN that has fallen at least W behind
 * the highest authenticated PN. W is the configured power of two in
 * [64, 65536]; zero selects the specified default 1024. Candidate keys and a
 * committed pin do not activate an association. Application send is refused
 * until the S4 confirmation transition.
 *
 * S3.1 allows any jitter. This build uses zero until a deployment defines a
 * distribution. Attempt, time, and load limits stay. There is no random source.
 * ACL, freshness leases, rotation, and endpoint S10 cases are outside this
 * owner.
 *
 * The caller serializes each attempt. After AEAD the window is rechecked
 * and marked in that same call; this module does not take a lock. The last
 * sealed frame and the last accepted plaintext are attempt-owned and are
 * replaced by the next seal or accept. Protected receive uses those buffers
 * and does not allocate.
 * SEC-1 requires a nonzero locally unique receive CID and does not define
 * the allocator; this module uses a caller-configured counter that skips
 * 0 and values already retained. A work unit is one charged ingress or
 * Noise event from the S3.1 table, not a CPU-cycle measurement.
 */
#ifndef DMP_HANDSHAKE_H
#define DMP_HANDSHAKE_H

#include "provider_port.h"

#include "dmp/core.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DMP_HS_ATTEMPT_MAX 4u
#define DMP_HS_ASSOCIATION_MAX 4u
#define DMP_HS_PAYLOAD_MAX 120u
/* P14 application record plaintext bound. Endpoint slices use this same limit. */
#define DMP_HS_APP_PLAIN_MAX 32u

typedef enum dmp_hs_status {
    DMP_HS_OK = 0,
    DMP_HS_DROPPED = 1,
    DMP_HS_ABORTED = 2,
    DMP_HS_AWAITING = 3,
    DMP_HS_REFUSED = 4,
    DMP_HS_UNSUPPORTED = 5,
    DMP_HS_STALE = 6,
    DMP_HS_NOT_ACTIVE = 7,
    DMP_HS_NO_TRUST = 8,
    DMP_HS_CANDIDATE = 9,
    DMP_HS_COMMITTED = 10,
    DMP_HS_INVALID = 11,
    DMP_HS_EXPIRED = 12,
    DMP_HS_SERIAL = 13
} dmp_hs_status;

typedef enum dmp_hs_view {
    DMP_HS_VIEW_IDLE = 0,
    DMP_HS_VIEW_PAIRING_ALLOWED = 1,
    DMP_HS_VIEW_CANDIDATE = 2,
    DMP_HS_VIEW_AWAITING_VERIFICATION = 3,
    DMP_HS_VIEW_ENROLLED = 4,
    DMP_HS_VIEW_EXPIRED = 5,
    DMP_HS_VIEW_REJECTED = 6,
    DMP_HS_VIEW_ACTIVE = 7
} dmp_hs_view;

typedef struct dmp_hs_budget {
    uint32_t max_pending;
    uint32_t max_scratch;
    uint32_t episode_attempts;
    uint64_t episode_deadline_ms;
    uint32_t episode_work;
    uint32_t episode_traffic;
    uint32_t restart_backoff_ms;
    uint32_t attempt_deadline_ms;
    uint32_t cached_responses;
    uint32_t global_work;
    uint32_t ingress_work;
    uint32_t later_episodes;
    uint32_t admit_burst;
    uint32_t admit_window_ms;
    uint32_t provisional_bytes;
    /* Zero selects the specified default 1024. Otherwise a power of two in [64, 65536]. */
    uint32_t replay_window;
    /* Zero selects the specified hard ceiling 65536. A larger value is rejected. */
    uint32_t failed_aead_limit;
    /* Zero selects the specified 24-hour lifetime. A shorter value is a local policy. */
    uint32_t association_lifetime_ms;
    /* No numeric default. Confirmation is refused until both are positive. */
    uint32_t confirmation_timeout_ms;
    uint32_t confirmation_attempts;
} dmp_hs_budget;

typedef struct dmp_hs_config {
    uint32_t namespace_id;
    uint32_t local_id;
    uint32_t peer_id;
    uint8_t profile_hash[32];
    uint8_t mode;
    uint8_t cipher;
    uint32_t key_hint;
    uint8_t psk[32];
    int has_psk;
    uint8_t local_static[32];
    int has_static;
    uint8_t pinned_remote[32];
    int has_pin;
    uint32_t permissions;
    int pairing_allowed;
    uint32_t next_rx_cid;
    dmp_hs_budget budget;
} dmp_hs_config;

typedef struct dmp_hs_pin_record {
    uint32_t namespace_id;
    uint32_t local_id;
    uint32_t peer_id;
    uint8_t profile_hash[32];
    uint8_t remote_public[32];
    uint8_t handshake_hash[32];
    uint32_t permissions;
    uint8_t mode;
    uint8_t cipher;
} dmp_hs_pin_record;

typedef struct dmp_hs_ports {
    uint64_t (*now_ms)(void *ctx);
    /* Nonzero means the bytes must not be used. No fallback key is substituted. */
    int (*entropy)(void *ctx, uint8_t *bytes, size_t size);
    /* Nonzero means the pin was not stored. Does not activate an association. */
    int (*commit_pin)(void *ctx, const dmp_hs_pin_record *record);
    void *ctx;
} dmp_hs_ports;

typedef struct dmp_hs_ingress {
    const uint8_t *payload;
    size_t payload_len;
    uint32_t origin_id;
    uint32_t destination_id;
    uint32_t namespace_id;
    uint64_t context_epoch;
    uint32_t seq;
    int route_to_root;
    int route_broadcast;
    int partial;
} dmp_hs_ingress;

typedef struct dmp_hs_completion {
    uint32_t attempt_index;
    uint64_t generation;
} dmp_hs_completion;

typedef struct dmp_hs_approval {
    uint64_t generation;
    uint8_t attempt_id[16];
    uint32_t initiator_id;
    uint32_t responder_id;
    uint8_t hash[32];
    int accept;
} dmp_hs_approval;

typedef struct dmp_hs_retained {
    uint32_t namespace_id;
    uint32_t origin_id;
    uint64_t epoch;
    uint32_t rx_cid;
    int draining;
} dmp_hs_retained;

/* Full protected core frame. Direct identity is resolved from these fields. */
typedef struct dmp_hs_protected {
    const uint8_t *frame;
    size_t frame_len;
    uint32_t origin_id;
    uint32_t destination_id;
    uint32_t namespace_id;
    uint64_t context_epoch;
} dmp_hs_protected;

typedef struct dmp_hs dmp_hs;

size_t dmp_hs_size(void);
dmp_hs_status dmp_hs_init(dmp_hs *hs, dmp_provider *provider,
                          const dmp_hs_config *config, const dmp_hs_ports *ports);
void dmp_hs_cleanup(dmp_hs *hs);

dmp_hs_status dmp_hs_begin_episode(dmp_hs *hs);
dmp_hs_status dmp_hs_schedule(dmp_hs *hs, uint32_t *attempt_index);
dmp_hs_status dmp_hs_offer(dmp_hs *hs, const dmp_hs_ingress *ingress,
                           dmp_hs_completion *completion);
dmp_hs_status dmp_hs_accept(dmp_hs *hs, const dmp_hs_completion *completion);
dmp_hs_status dmp_hs_cancel(dmp_hs *hs, uint32_t attempt_index);
dmp_hs_status dmp_hs_poll(dmp_hs *hs, uint32_t *attempt_index);
dmp_hs_status dmp_hs_retransmit(dmp_hs *hs, uint32_t attempt_index);
dmp_hs_status dmp_hs_approve(dmp_hs *hs, uint32_t attempt_index,
                             const dmp_hs_approval *approval);
dmp_hs_status dmp_hs_send_application(const dmp_hs *hs, uint32_t attempt_index);
dmp_hs_status dmp_hs_confirm(dmp_hs *hs, uint32_t attempt_index);
dmp_hs_status dmp_hs_offer_protected(dmp_hs *hs, const dmp_hs_protected *frame);
dmp_hs_status dmp_hs_emit_application(dmp_hs *hs, uint32_t attempt_index, const uint8_t *plain,
                                      size_t plain_len);
/* Same P14 cipher, AAD, PN and replay window as FINISH/READY. Caller owns
 * the output. Does not allocate and does not hash an epoch. Inactive
 * associations are refused. Plaintext above the P14 record bound is refused. */
dmp_hs_status dmp_hs_seal_logical(dmp_hs *hs, uint32_t attempt_index, const dmp_frame_spec *logical,
                                  uint8_t *out, size_t cap, size_t *written);
/* Decrypt one record for the named attempt. A bad tag does not mark the PN.
 * Cross-attempt and inactive frames are not accepted. Does not allocate. */
dmp_hs_status dmp_hs_open_logical(dmp_hs *hs, uint32_t attempt_index, const dmp_hs_protected *incoming,
                                  uint8_t *plain, size_t plain_cap, size_t *plain_len,
                                  dmp_frame_view *view);
int dmp_hs_traffic_identity(const dmp_hs *hs, uint32_t attempt_index, uint32_t *namespace_id,
                            uint32_t *local_id, uint32_t *peer_id, uint64_t *local_epoch,
                            uint64_t *peer_epoch);
dmp_hs_status dmp_hs_retain_association(dmp_hs *hs, const dmp_hs_retained *retained);

int dmp_hs_association_active(const dmp_hs *hs);
dmp_hs_view dmp_hs_view_of(const dmp_hs *hs, uint32_t attempt_index);
uint64_t dmp_hs_generation(const dmp_hs *hs, uint32_t attempt_index);
uint64_t dmp_hs_deadline(const dmp_hs *hs, uint32_t attempt_index);
uint32_t dmp_hs_noise_writes(const dmp_hs *hs, uint32_t attempt_index);
uint32_t dmp_hs_noise_reads(const dmp_hs *hs, uint32_t attempt_index);
uint32_t dmp_hs_total_reads(const dmp_hs *hs);
uint32_t dmp_hs_global_work(const dmp_hs *hs);
uint32_t dmp_hs_episode_attempts_used(const dmp_hs *hs);
uint32_t dmp_hs_episode_work(const dmp_hs *hs);
uint32_t dmp_hs_rx_cid(const dmp_hs *hs, uint32_t attempt_index);
uint32_t dmp_hs_retransmits(const dmp_hs *hs, uint32_t attempt_index);
int dmp_hs_enrolled(const dmp_hs *hs, uint32_t attempt_index);
int dmp_hs_candidate(const dmp_hs *hs, uint32_t attempt_index);
int dmp_hs_terminal(const dmp_hs *hs, uint32_t attempt_index);
int dmp_hs_secrets_wiped(const dmp_hs *hs, uint32_t attempt_index);
int dmp_hs_retained_alive(const dmp_hs *hs, uint32_t index);
const uint8_t *dmp_hs_cached_flight(const dmp_hs *hs, uint32_t attempt_index,
                                    size_t *length);
const uint8_t *dmp_hs_protected_frame(const dmp_hs *hs, uint32_t attempt_index, size_t *length);
int dmp_hs_copy_accepted(const dmp_hs *hs, uint32_t attempt_index, uint8_t *out, size_t cap,
                         size_t *length);
uint32_t dmp_hs_failed_aead(const dmp_hs *hs, uint32_t attempt_index);
uint64_t dmp_hs_next_pn(const dmp_hs *hs, uint32_t attempt_index);
int dmp_hs_copy_attempt_id(const dmp_hs *hs, uint32_t attempt_index, uint8_t id[16]);
int dmp_hs_copy_hash(const dmp_hs *hs, uint32_t attempt_index, uint8_t hash[32]);
int dmp_hs_epochs(const dmp_hs *hs, uint32_t attempt_index, uint64_t *initiator_epoch,
                  uint64_t *responder_epoch);
uint64_t dmp_hs_boot_epoch(const dmp_hs *hs, uint32_t attempt_index);
uint8_t dmp_hs_expect_flight(const dmp_hs *hs, uint32_t attempt_index);
int dmp_hs_copy_partial(const dmp_hs *hs, uint8_t *out, size_t cap, size_t *length);
uint32_t dmp_hs_pending(const dmp_hs *hs);

#ifdef __cplusplus
}
#endif

#endif
