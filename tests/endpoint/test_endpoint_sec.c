/* Host loopback only. This is not physical-transport evidence.
 *
 * Two libdmp endpoints exchange after the real P14 association activates.
 * Protection is dmp_hs_seal_logical / dmp_hs_open_logical on the existing
 * provider cipher. Reliability and reassembly are the existing engines.
 *
 * Deferred, not implemented here: S10 case 6 relay-state (P19) and S10 case 11
 * multi-binding forwarding (P23). Freshness case 10 stays omitted: the admitted
 * services set freshness false and lease_ms 0. S10 case 8 is host context
 * destruction only; it is not a physical reboot and it does not add NVS.
 * Host loopback is not physical-transport evidence.
 * S3.1 still does not define a jitter distribution; restart jitter stays 0.
 */
#include "dmp/core.h"
#include "dmp/endpoint.h"
#include "dmp/integrity.h"
#include "dmp/stream.h"

#include "handshake.h"
#include "noise_fixture_probe.h"
#include "sample1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

#define CHECK(condition)                                                     \
    do {                                                                     \
        if (!(condition)) {                                                  \
            (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__,     \
                          __LINE__, #condition);                             \
            return 1;                                                        \
        }                                                                    \
    } while (0)

enum {
    SENDERS = 4,
    RESULTS = 6,
    HISTORY = 12,
    CORRELATIONS = 6,
    ADAPTERS = 5,
    MESSAGE = 1024,
    MTU = 263,
    ASSEMBLIES = 1,
    TOMBSTONES = 16,
    STREAM_CAP = 512,
    QUEUE = 24,
    FRAME_CAP = 512,
    LOCAL_NS = 1,
    ID_INIT = 0x0a,
    ID_RESP = 0x14,
    CID_INIT = 7,
    CID_RESP = 9,
    KEY_HINT = 5,
    FRAG_BYTES = 300,
    FRAG_CHUNK = 16
};

enum {
  P23_PROFILE_NONE = 0,
  P23_PROFILE_STREAM_R = 1,
  P23_PROFILE_RADIO_SELECTIVE = 2,
  P23_PROFILE_RADIO_RETRY_ALL = 3,
  P23_PROFILE_MIXED = 4,
  P23_PROFILE_STREAM_R_SAMPLE20 = 5,
  P23_PROFILE_DIRECT_XX = 6,
  P23_PROFILE_RADIO_XX = 7,
  P23_PROFILE_RADIO_RETRY_ALL_XX = 8,
  P23_PROFILE_DIRECT_NN = 9
};

typedef struct node node;

typedef struct {
  int used;
  uint8_t frame[FRAME_CAP];
  size_t len;
} held;

typedef struct {
  dmp_tx_complete_fn complete;
  void *owner;
  dmp_tx_token token;
} pending_completion;

typedef struct {
  node *self;
  held q[QUEUE];
  int n;
  pending_completion pending[QUEUE];
  int pending_count;
  int synchronous_completion;
  int submits;
  int drop_remaining;
  int reject_remaining;
  uint8_t saved[FRAME_CAP];
  size_t saved_len;
  uint8_t last[FRAME_CAP];
  size_t last_len;
  dmp_time_ms now;
} wire;

typedef struct {
    int producer;
    int have_pending;
    dmp_reliability_handle pending;
    int accepts;
    int results;
    int telems;
    int assembled;
    int unknowns;
    uint8_t req[MESSAGE];
    size_t req_n;
    size_t request_service;
    uint8_t result[MESSAGE];
    size_t result_n;
    uint8_t body[MESSAGE];
    size_t body_n;
} app;

struct node {
    dmp_endpoint endpoint;
    dmp_transport transport;
    wire wire;
    app app;
    dmp_identity_slot ids[2];
    dmp_reliability_sender_slot senders[SENDERS];
    uint8_t sender_payload[SENDERS * MESSAGE];
    dmp_reliability_result_slot results[RESULTS];
    uint8_t result_payload[RESULTS * MESSAGE];
    dmp_reliability_history_slot history[HISTORY];
    dmp_reliability_correlation_slot correlations[CORRELATIONS];
    uint8_t history_metadata[HISTORY * DMP_RELIABILITY_METADATA_BYTES];
    uint8_t correlation_metadata[CORRELATIONS * DMP_RELIABILITY_METADATA_BYTES];
    dmp_reliability_adapter_slot adapters[ADAPTERS];
    uint8_t frames[ADAPTERS * MTU];
    uint8_t receive_payload[MESSAGE];
    dmp_reassembly_slot assemblies[ASSEMBLIES];
    dmp_reassembly_tombstone tombstones[TOMBSTONES];
    dmp_endpoint_freshness_slot freshness[8];
    uint8_t assembly_payload[ASSEMBLIES * MESSAGE];
    uint8_t assembly_metadata[ASSEMBLIES * DMP_REASSEMBLY_METADATA_BYTES];
    uint8_t fragment_message[MESSAGE];
    uint8_t fragment_frame[MTU];
    uint8_t telemetry_payload[MESSAGE];
    uint8_t telemetry_next[MESSAGE];
    uint8_t telemetry_frame[MTU];
    uint8_t stream_tx[STREAM_CAP];
    uint8_t stream_rx[STREAM_CAP];
};

typedef struct script {
    const uint8_t *data[16];
    size_t len[16];
    size_t count;
    size_t index;
    int fail;
} script;

typedef struct store {
    int fail;
    int calls;
    int has;
    uint8_t saved[32];
} store;

typedef struct box {
    uint64_t *now;
    script *entropy_script;
    store *pin_store;
} box;

typedef struct session {
    uint64_t now;
    script init_script;
    script resp_script;
    store init_store;
    store resp_store;
    box init_box;
    box resp_box;
    dmp_provider *provider;
    dmp_hs *initiator;
    dmp_hs *responder;
    uint8_t alt_attempt[16];
    uint8_t rot_id[16];
    uint8_t rot_init_eph[32];
    uint8_t rot_resp_eph[32];
} session;

typedef struct port_ctx {
    unsigned alloc_calls;
    size_t live;
    size_t peak;
    size_t peak_one;
} port_ctx;

typedef void (*tune_fn)(dmp_hs_config *initiator, dmp_hs_config *responder);

static node left;
static node right;
static const uint8_t *g_profile_hash_override;
static const uint8_t *g_psk_override;
static int g_p23_copy_async_binding;
static uint8_t g_p23_profile_id;
static int p23_defer_tx_completions;
static uint8_t g_p23_confirmation_route_ttl;
static uint8_t p23_profile_hash[32];
static uint8_t p23_expected_remote_pin[32];
static uint8_t g_p23_security_mode;
static const uint8_t *p23_static_override;
static uint32_t p23_pin_commits;
static dmp_config p23_effective_config;
static dmp_hs_budget p23_effective_budget;

static const uint8_t DIRECT_SHA[DMP_PROFILE_SHA256_BYTES] = {
    0x29, 0xcb, 0x7b, 0x91, 0xee, 0x0c, 0x26, 0x9b, 0xc1, 0x4a, 0xc4, 0x3e, 0x3a, 0x7c, 0x8f, 0xd8,
    0xbd, 0xcf, 0xe1, 0x1e, 0x9e, 0x05, 0x2e, 0x8b, 0xd9, 0xe6, 0xaf, 0x00, 0xfb, 0x89, 0xc3, 0xbf};

static const uint8_t READ_RSP[SAMPLE1_READ_BYTES] = {
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2c, 0x01, 0x00,
    0x00};

static dmp_bytes span(const void *data, size_t size)
{
    dmp_bytes bytes;
    bytes.data = (const uint8_t *)data;
    bytes.size = size;
    return bytes;
}

static void on_notice(void *user, const dmp_endpoint_notice *notice) {
  node *self = user;
  if (self == NULL || notice == NULL) {
    return;
  }
  if (notice->event == DMP_ENDPOINT_REQUEST) {
    self->app.accepts++;
    self->app.request_service = notice->service_id;
    self->app.req_n = notice->payload.size <= sizeof self->app.req
                          ? notice->payload.size
                          : 0U;
    if (self->app.req_n != 0U && notice->payload.data != NULL) {
      memcpy(self->app.req, notice->payload.data, self->app.req_n);
    }
    self->app.pending = notice->request;
    self->app.have_pending = 1;
    return;
  }
  if (notice->event == DMP_ENDPOINT_RESULT) {
    self->app.results++;
    self->app.result_n = notice->payload.size <= sizeof self->app.result
                             ? notice->payload.size
                             : 0U;
    if (self->app.result_n != 0U && notice->payload.data != NULL) {
      memcpy(self->app.result, notice->payload.data, self->app.result_n);
    }
    return;
  }
  if (notice->event == DMP_ENDPOINT_TELEMETRY) {
    self->app.telems++;
    return;
  }
  if (notice->event == DMP_ENDPOINT_ASSEMBLED) {
    self->app.assembled++;
    self->app.body_n = notice->payload.size <= sizeof self->app.body
                           ? notice->payload.size
                           : 0U;
    if (self->app.body_n != 0U && notice->payload.data != NULL) {
      memcpy(self->app.body, notice->payload.data, self->app.body_n);
    }
    return;
  }
  if (notice->event == DMP_ENDPOINT_UNKNOWN) {
    self->app.unknowns++;
  }
}

static dmp_status wire_submit(void *context,
                              const dmp_tx_submission *submission) {
  wire *link = context;
  if (link == NULL || submission == NULL || submission->frame.data == NULL ||
      submission->complete == NULL || submission->frame.size > FRAME_CAP) {
    return DMP_INVALID_ARGUMENT;
  }
  if (link->reject_remaining > 0) {
    link->reject_remaining--;
    return DMP_BUSY;
  }
  if (!link->synchronous_completion && link->pending_count >= QUEUE) {
    return DMP_BUSY;
  }
  link->submits++;
  memcpy(link->last, submission->frame.data, submission->frame.size);
  link->last_len = submission->frame.size;
  if (link->drop_remaining > 0) {
    link->drop_remaining--;
    if (link->saved_len == 0U) {
      memcpy(link->saved, submission->frame.data, submission->frame.size);
      link->saved_len = submission->frame.size;
    }
    if (link->synchronous_completion) {
      submission->complete(submission->owner, submission->token,
                           DMP_TX_TRANSMITTED, link->now);
    } else {
      pending_completion *pending = &link->pending[link->pending_count++];
      pending->complete = submission->complete;
      pending->owner = submission->owner;
      pending->token = submission->token;
    }
    return DMP_OK;
  }
  if (link->n >= QUEUE) {
    return DMP_BUSY;
  }
  memcpy(link->q[link->n].frame, submission->frame.data,
         submission->frame.size);
  link->q[link->n].len = submission->frame.size;
  link->q[link->n].used = 1;
  link->n++;
  if (link->synchronous_completion) {
    submission->complete(submission->owner, submission->token,
                         DMP_TX_TRANSMITTED, link->now);
  } else {
    pending_completion *pending = &link->pending[link->pending_count++];
    pending->complete = submission->complete;
    pending->owner = submission->owner;
    pending->token = submission->token;
  }
  return DMP_OK;
}

static dmp_status wire_cancel(void *context, dmp_tx_token token) {
  (void)context;
  (void)token;
  return DMP_OK;
}

static int g_fill_selective;

static void p23_apply_profile_config(dmp_config *config) {
  if (config == NULL || g_p23_profile_id == P23_PROFILE_NONE ||
      g_p23_profile_id == P23_PROFILE_DIRECT_NN ||
      g_p23_profile_id == P23_PROFILE_DIRECT_XX ||
      g_p23_profile_id == P23_PROFILE_STREAM_R ||
      g_p23_profile_id == P23_PROFILE_STREAM_R_SAMPLE20) {
    return;
  }
  config->recovery[0] =
      (g_p23_profile_id == P23_PROFILE_RADIO_SELECTIVE ||
       g_p23_profile_id == P23_PROFILE_MIXED ||
       g_p23_profile_id == P23_PROFILE_RADIO_XX)
                            ? DMP_PROFILE_RECOVERY_SELECTIVE32
                            : DMP_PROFILE_RECOVERY_RETRY_ALL;
  config->recovery[1] = config->recovery[0];
  config->freshness_required_mask = 2U;
  config->freshness_lease_ms = 12000U;
  config->freshness_grant_delivery_age_ms = 100U;
  config->freshness_tokens_per_association = 4U;
  config->freshness_tokens_per_principal = 8U;
  config->freshness_grant_requests_per_pair = 2U;
  config->freshness_token_record_ms = 12000U;
  config->freshness_grant_result_ms = 11000U;
  config->assembly_tombstones_per_peer = 16U;
  config->sender_slots = 4U;
  config->assembly_tombstone_slots = 16U;
  config->result_slots = 6U;
  config->history_slots = 12U;
  config->correlation_slots = 6U;
  config->adapter_slots = 5U;
  config->application_queue_slots = 2U;
  config->control_slots = 4U;
  config->fragments = 32U;
  config->chunk_bytes = 32U;
  config->encoded_mtu = 256U;
  config->forward_mtu = 256U;
  config->return_mtu = 256U;
  config->response_timeout_ms = 2304U;
  config->send_horizon_ms = 10752U;
  config->receipt_delay_ms = 110U;
  config->receipt_limit = 3U;
  config->dedup_ms = 11000U;
  config->rejection_ms = 11000U;
  config->result_cache_ms = 11000U;
  config->result_deadline_ms = 22000U;
  config->correlation_ms = 23040U;
  config->tombstone_ms = 23040U;
  config->late_result_ms = 64U;
  config->collect_ms = 10772U;
  config->assembly_ms = 10777U;
  config->burst_span_ms = 2048U;
  config->forward_delay_ms = 20U;
  config->return_delay_ms = 20U;
  config->feedback_guard_ms = 4U;
  config->feedback_delay_ms = 110U;
  config->max_probes =
      (g_p23_profile_id == P23_PROFILE_RADIO_SELECTIVE ||
       g_p23_profile_id == P23_PROFILE_MIXED ||
       g_p23_profile_id == P23_PROFILE_RADIO_XX)
          ? 2U
          : 0U;
  config->max_status =
      (g_p23_profile_id == P23_PROFILE_RADIO_SELECTIVE ||
       g_p23_profile_id == P23_PROFILE_MIXED ||
       g_p23_profile_id == P23_PROFILE_RADIO_XX)
          ? 3U
          : 0U;
  config->record_margin_ms = 5U;
  config->tx_borrow = true;
  config->synchronous_completion = !p23_defer_tx_completions;
  config->origin_route = 1U;
  config->origin_ttl = 2U;
  p23_effective_config = *config;
}

static void p23_apply_direct_profile_config(dmp_config *config) {
  if (config == NULL || g_p23_profile_id == P23_PROFILE_NONE ||
      g_p23_profile_id == P23_PROFILE_RADIO_SELECTIVE ||
      g_p23_profile_id == P23_PROFILE_RADIO_RETRY_ALL ||
      g_p23_profile_id == P23_PROFILE_MIXED ||
      g_p23_profile_id == P23_PROFILE_RADIO_XX ||
      g_p23_profile_id == P23_PROFILE_RADIO_RETRY_ALL_XX) {
    return;
  }
  config->recovery[0] = DMP_PROFILE_RECOVERY_RETRY_ALL;
  config->recovery[1] = DMP_PROFILE_RECOVERY_RETRY_ALL;
  config->freshness_required_mask = 0U;
  config->peers = 1U;
  config->operations_per_service = 1U;
  config->assemblies_per_peer = 1U;
  config->assembly_tombstones_per_peer = 16U;
  config->sender_slots = 4U;
  config->assembly_slots = 1U;
  config->assembly_tombstone_slots = 16U;
  config->result_slots = 4U;
  config->history_slots = 8U;
  config->correlation_slots = 4U;
  config->adapter_slots = 3U;
  config->application_queue_slots = 2U;
  config->control_slots = 2U;
  config->message_bytes = 1024U;
  config->fragments = 16U;
  config->chunk_bytes = 64U;
  config->encoded_mtu = 263U;
  config->forward_mtu = 256U;
  config->return_mtu = 256U;
  config->queue_ms = 64U;
  config->response_timeout_ms = 1280U;
  config->send_horizon_ms = 5632U;
  config->max_bursts = 3U;
  config->receipt_delay_ms = 110U;
  config->receipt_limit = 3U;
  config->dedup_ms = 6000U;
  config->rejection_ms = 6000U;
  config->result_cache_ms = 6000U;
  config->result_deadline_ms = 12000U;
  config->correlation_ms = 12288U;
  config->tombstone_ms = 12288U;
  config->late_result_ms = 64U;
  config->collect_ms = 5652U;
  config->assembly_ms = 5657U;
  config->burst_span_ms = 1024U;
  config->forward_delay_ms = 20U;
  config->return_delay_ms = 20U;
  config->feedback_guard_ms = 4U;
  config->feedback_delay_ms = 110U;
  config->max_probes = 0U;
  config->max_status = 0U;
  config->record_margin_ms = 5U;
  config->origin_route = 0U;
  config->origin_ttl = 0U;
  p23_effective_config = *config;
}

static void fill_direct(dmp_config *config, uint32_t chunk,
                        uint32_t fragments) {
  memset(config, 0, sizeof *config);
  memcpy(config->sha256,
         g_profile_hash_override != NULL ? g_profile_hash_override : DIRECT_SHA,
         sizeof DIRECT_SHA);
  config->namespace_id = LOCAL_NS;
  config->node_id[0] = ID_INIT;
  config->node_id[1] = ID_RESP;
  config->default_service = 1U;
  config->service_id[0] = 1U;
  config->service_id[1] = 2U;
  config->recovery[0] = DMP_PROFILE_RECOVERY_RETRY_ALL;
  config->recovery[1] = DMP_PROFILE_RECOVERY_RETRY_ALL;
  config->peers = 1U;
  config->operations_per_service = 1U;
  config->assemblies_per_peer = 1U;
  config->assembly_tombstones_per_peer = TOMBSTONES;
  config->sender_slots = SENDERS;
  config->assembly_slots = ASSEMBLIES;
  config->assembly_tombstone_slots = TOMBSTONES;
  config->result_slots = RESULTS;
  config->history_slots = HISTORY;
  config->correlation_slots = CORRELATIONS;
  config->adapter_slots = ADAPTERS;
  config->application_queue_slots = 2U;
  config->control_slots = 2U;
  config->message_bytes = MESSAGE;
  config->fragments = fragments;
  config->chunk_bytes = chunk;
  config->encoded_mtu = MTU;
  config->forward_mtu = 256U;
  config->return_mtu = 256U;
  config->queue_ms = 64U;
  config->response_timeout_ms = 1280U;
  config->jitter_ms = 0U;
  config->send_horizon_ms = 5632U;
  config->max_bursts = 3U;
  config->receipt_delay_ms = 110U;
  config->receipt_limit = 3U;
  config->dedup_ms = 6000U;
  config->rejection_ms = 6000U;
  config->result_cache_ms = 6000U;
  config->result_deadline_ms = 12000U;
  config->correlation_ms = 12288U;
  config->tombstone_ms = 12288U;
  config->late_result_ms = 64U;
  config->collect_ms = 5652U;
  config->assembly_ms = 5657U;
  config->tx_borrow = !g_p23_copy_async_binding;
  config->synchronous_completion = !g_p23_copy_async_binding;
  if (g_p23_copy_async_binding) {
    config->burst_span_ms = 1024U;
    config->forward_delay_ms = 20U;
    config->return_delay_ms = 20U;
    config->feedback_guard_ms = 4U;
    config->feedback_delay_ms = 110U;
    config->record_margin_ms = 5U;
  }
  if (g_fill_selective) {
    config->recovery[0] = DMP_PROFILE_RECOVERY_SELECTIVE32;
    config->recovery[1] = DMP_PROFILE_RECOVERY_SELECTIVE32;
    config->burst_span_ms = 1U;
    config->forward_delay_ms = 1U;
    config->return_delay_ms = 1U;
    config->feedback_guard_ms = 1U;
    config->feedback_delay_ms = 1U;
    config->max_probes = 1U;
    config->max_status = 1U;
    config->record_margin_ms = 1U;
  }
}

static int install_manifest_grants(node *self) {
  dmp_endpoint_grant grants[6];
  size_t count = 4U;

  memset(grants, 0, sizeof grants);
  grants[0].principal = ID_INIT;
  grants[0].service_id = 1U;
  grants[0].permit = DMP_ENDPOINT_PERMIT_TELEM | DMP_ENDPOINT_PERMIT_RESULT;
  grants[1].principal = ID_RESP;
  grants[1].service_id = 1U;
  grants[1].permit = DMP_ENDPOINT_PERMIT_REQ;
  grants[2].principal = ID_INIT;
  grants[2].service_id = 2U;
  grants[2].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
  grants[3].principal = ID_RESP;
  grants[3].service_id = 2U;
  grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
  if (g_p23_profile_id == P23_PROFILE_RADIO_SELECTIVE ||
      g_p23_profile_id == P23_PROFILE_RADIO_RETRY_ALL ||
      g_p23_profile_id == P23_PROFILE_MIXED ||
      g_p23_profile_id == P23_PROFILE_RADIO_XX ||
      g_p23_profile_id == P23_PROFILE_RADIO_RETRY_ALL_XX) {
    grants[4].principal = ID_INIT;
    grants[4].service_id = 0U;
    grants[4].permit = DMP_ENDPOINT_PERMIT_CONTROL;
    grants[5].principal = ID_RESP;
    grants[5].service_id = 0U;
    grants[5].permit = DMP_ENDPOINT_PERMIT_CONTROL;
    count = 6U;
  }
  return dmp_endpoint_set_grants(&self->endpoint, grants, count) == DMP_OK ? 0 : 1;
}

static int boot_node_slots(node *self, int producer, uint32_t chunk,
                           uint32_t fragments, dmp_time_ms now, size_t slots) {
  dmp_config input;
  dmp_admitted_profile admitted;
  dmp_endpoint_storage storage;
  dmp_identity_context_config identity;
  memset(self, 0, sizeof *self);
  fill_direct(&input, chunk, fragments);
  p23_apply_profile_config(&input);
  p23_apply_direct_profile_config(&input);
  CHECK(dmp_config_admit(&input, &admitted) == DMP_OK);
  if (g_p23_profile_id != P23_PROFILE_NONE) {
    p23_effective_config = admitted;
  }
  memset(&identity, 0, sizeof identity);
  identity.local.namespace_id = LOCAL_NS;
  identity.peer.namespace_id = LOCAL_NS;
  if (producer) {
    identity.local.origin_id = ID_INIT;
    identity.peer.origin_id = ID_RESP;
  } else {
    identity.local.origin_id = ID_RESP;
    identity.peer.origin_id = ID_INIT;
  }
  identity.security = 1U;
  self->app.producer = producer;
  self->wire.self = self;
  self->wire.now = now;
  self->transport.context = &self->wire;
  self->transport.submit = wire_submit;
  self->transport.cancel = wire_cancel;
  self->transport.caps.max_frame_bytes = FRAME_CAP;
  self->wire.synchronous_completion = admitted.synchronous_completion;
  self->transport.caps.ownership =
      admitted.tx_borrow ? DMP_TX_BORROW : DMP_TX_COPY;
  self->transport.caps.synchronous_completion = admitted.synchronous_completion;
  memset(&storage, 0, sizeof storage);
  storage.profile = &admitted;
  storage.identity_slots = self->ids;
  storage.identity_capacity = slots;
  storage.context = identity;
  storage.transport = &self->transport;
  storage.notice = on_notice;
  storage.notice_user = self;
  storage.senders = self->senders;
  storage.sender_capacity = SENDERS;
  storage.sender_payload = self->sender_payload;
  storage.sender_payload_capacity = sizeof self->sender_payload;
  storage.results = self->results;
  storage.result_capacity = RESULTS;
  storage.result_payload = self->result_payload;
  storage.result_payload_capacity = sizeof self->result_payload;
  storage.history = self->history;
  storage.history_capacity = HISTORY;
  storage.correlations = self->correlations;
  storage.correlation_capacity = CORRELATIONS;
  storage.history_metadata = self->history_metadata;
  storage.history_metadata_capacity = sizeof self->history_metadata;
  storage.correlation_metadata = self->correlation_metadata;
  storage.correlation_metadata_capacity = sizeof self->correlation_metadata;
  storage.adapters = self->adapters;
  storage.adapter_capacity = ADAPTERS;
  storage.frames = self->frames;
  storage.frame_capacity = sizeof self->frames;
  storage.receive_payload = self->receive_payload;
  storage.receive_payload_capacity = sizeof self->receive_payload;
  storage.assemblies = self->assemblies;
  storage.assembly_capacity = ASSEMBLIES;
  storage.tombstones = self->tombstones;
  storage.tombstone_capacity = TOMBSTONES;
  storage.freshness_slots = self->freshness;
  storage.freshness_capacity = sizeof self->freshness / sizeof self->freshness[0];
  storage.assembly_payload = self->assembly_payload;
  storage.assembly_payload_capacity = sizeof self->assembly_payload;
  storage.assembly_metadata = self->assembly_metadata;
  storage.assembly_metadata_capacity = sizeof self->assembly_metadata;
  storage.fragment_message = self->fragment_message;
  storage.fragment_message_capacity = sizeof self->fragment_message;
  storage.fragment_frame = self->fragment_frame;
  storage.fragment_frame_capacity = sizeof self->fragment_frame;
  storage.telemetry_payload = self->telemetry_payload;
  storage.telemetry_payload_capacity = sizeof self->telemetry_payload;
  storage.telemetry_next = self->telemetry_next;
  storage.telemetry_next_capacity = sizeof self->telemetry_next;
  storage.telemetry_frame = self->telemetry_frame;
  storage.telemetry_frame_capacity = sizeof self->telemetry_frame;
  storage.stream_tx = self->stream_tx;
  storage.stream_tx_capacity = sizeof self->stream_tx;
  storage.stream_rx = self->stream_rx;
  storage.stream_rx_capacity = sizeof self->stream_rx;
  CHECK(dmp_endpoint_init(&self->endpoint, &storage, now) == DMP_OK);
  return install_manifest_grants(self);
}

static int boot_node(node *self, int producer, uint32_t chunk, uint32_t fragments, dmp_time_ms now)
{
    return boot_node_slots(self, producer, chunk, fragments, now, 1U);
}

static int boot_selective(node *self, int producer, uint32_t chunk, uint32_t fragments, dmp_time_ms now)
{
    int rc;

    g_fill_selective = 1;
    rc = boot_node(self, producer, chunk, fragments, now);
    g_fill_selective = 0;
    return rc;
}

static int unwrap_core(const uint8_t *framed, size_t n, uint8_t *core, size_t cap, size_t *core_n,
                       dmp_time_ms now);

static int stream_fragment(const uint8_t *framed, size_t n, dmp_time_ms now, uint32_t *index,
                           uint64_t *pn)
{
    uint8_t core[MTU];
    size_t core_n = 0U;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_parse_result parsed;

    if (!unwrap_core(framed, n, core, sizeof core, &core_n, now)) {
        return 0;
    }
    memset(&view, 0, sizeof view);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    parsed = dmp_core_parse(span(core, core_n), &limits, &view);
    if (parsed.status != DMP_OK || (view.fields.options & DMP_OPT_FRAG) == 0U) {
        return 0;
    }
    if (index != NULL) {
        *index = view.fields.fragment.index;
    }
    if (pn != NULL) {
        *pn = view.fields.security.pn;
    }
    return 1;
}

static int service(node *self, dmp_time_ms now)
{
    uint8_t payload[SAMPLE1_READ_BYTES];
    size_t n;
    if (!self->app.producer || !self->app.have_pending) {
        return 0;
    }
    if (self->app.req_n != 1U || self->app.req[0] != SAMPLE1_READ) {
        return 1;
    }
    n = sample1_read_rsp(payload, 1U, 2U, 300U);
    CHECK(dmp_endpoint_complete(&self->endpoint, self->app.pending, false, 0U, span(payload, n),
                                now) == DMP_OK);
    self->app.have_pending = 0;
    return 0;
}

static int deliver_one(node *from, node *to, int index, dmp_time_ms now, dmp_status *status_out)
{
    dmp_bytes bytes;
    dmp_status status;
    if (index < 0 || index >= from->wire.n) {
        return 1;
    }
    bytes = span(from->wire.q[index].frame, from->wire.q[index].len);
    status = dmp_endpoint_rx(&to->endpoint, bytes, now);
    if (status_out != NULL) {
        *status_out = status;
    }
    return 0;
}

static int deliver_all(node *from, node *to, dmp_time_ms now)
{
    int i;
    int n = from->wire.n;
    for (i = 0; i < n; i++) {
        dmp_status status = DMP_OK;
        CHECK(deliver_one(from, to, i, now, &status) == 0);
        CHECK(status == DMP_OK || status == DMP_INCOMPLETE || status == DMP_DUPLICATE);
    }
    from->wire.n = 0;
    return 0;
}

static int pump(dmp_time_ms now, int rounds)
{
    int i;
    left.wire.now = now;
    right.wire.now = now;
    for (i = 0; i < rounds; i++) {
        CHECK(service(&left, now) == 0);
        CHECK(service(&right, now) == 0);
        CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
        CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
        CHECK(deliver_all(&left, &right, now) == 0);
        CHECK(deliver_all(&right, &left, now) == 0);
    }
    CHECK(service(&left, now) == 0);
    CHECK(service(&right, now) == 0);
    return 0;
}

static const noise_fixture_probe_fixture_t *find_fixture(const char *name)
{
    size_t index;
    for (index = 0U; index < NOISE_FIXTURE_PROBE_FIXTURE_COUNT; ++index) {
        if (strcmp(noise_fixture_probe_fixtures[index].name, name) == 0) {
            return &noise_fixture_probe_fixtures[index];
        }
    }
    return NULL;
}

static int startup_ready(void *ctx)
{
    (void)ctx;
    return 0;
}

static int startup_read(void *ctx, void *bytes, size_t size)
{
    uint8_t *out = (uint8_t *)bytes;
    size_t index;
    (void)ctx;
    for (index = 0U; index < size; ++index) {
        out[index] = (uint8_t)(0x3DU + (uint8_t)index);
    }
    return 0;
}

static int provider_entropy(void *ctx, void *bytes, size_t size)
{
    uint8_t *out = (uint8_t *)bytes;
    size_t index;
    (void)ctx;
    for (index = 0U; index < size; ++index) {
        out[index] = (uint8_t)(0x71U + (uint8_t)index);
    }
    return 0;
}

static void *port_allocate(void *ctx, size_t size)
{
    port_ctx *port = (port_ctx *)ctx;
    void *ptr;
    port->alloc_calls++;
    ptr = calloc(1, size);
    if (ptr == NULL) {
        return NULL;
    }
    port->live += size;
    if (port->live > port->peak) {
        port->peak = port->live;
    }
    if (size > port->peak_one) {
        port->peak_one = size;
    }
    return ptr;
}

static void port_release(void *ctx, void *ptr, size_t size)
{
    port_ctx *port = (port_ctx *)ctx;
    if (port->live >= size) {
        port->live -= size;
    } else {
        port->live = 0U;
    }
    free(ptr);
}

static void note_provider(const char *label, const port_ctx *port, const dmp_provider *provider)
{
    (void)fprintf(stderr,
                  "provider-measure %s peak_retained=%zu peak_single=%zu live=%zu "
                  "provider_retained=%zu blocks=%zu\n",
                  label, port->peak, port->peak_one, port->live, dmp_provider_retained(provider),
                  dmp_provider_block_count(provider));
}

static uint64_t now_of(void *ctx)
{
    box *env = (box *)ctx;
    return *env->now;
}

static int entropy_of(void *ctx, uint8_t *bytes, size_t size)
{
    box *env = (box *)ctx;
    script *src = env->entropy_script;
    size_t selected = src->index;
    if (src->fail) {
        memset(bytes, 0, size);
        return 1;
    }
    if (g_p23_profile_id == P23_PROFILE_NONE) {
        if (selected >= src->count || src->len[selected] != size) {
            memset(bytes, 0, size);
            return 1;
        }
        memcpy(bytes, src->data[selected], size);
        src->index++;
        return 0;
    }
    while (selected < src->count && src->len[selected] != size) {
        selected++;
    }
    if (selected >= src->count) {
        memset(bytes, 0, size);
        return 1;
    }
    memcpy(bytes, src->data[selected], size);
    if (selected + 1U < src->count) {
        memmove(&src->data[selected], &src->data[selected + 1U],
                (src->count - selected - 1U) * sizeof src->data[0]);
        memmove(&src->len[selected], &src->len[selected + 1U],
                (src->count - selected - 1U) * sizeof src->len[0]);
    }
    src->count--;
    return 0;
}

static int commit_of(void *ctx, const dmp_hs_pin_record *record)
{
    box *env = (box *)ctx;
    if (g_p23_profile_id != P23_PROFILE_NONE &&
        (record == NULL || record->mode != 2U ||
         memcmp(record->remote_public, p23_expected_remote_pin, 32U) != 0 ||
         memcmp(record->profile_hash, p23_profile_hash, 32U) != 0)) {
        return 1;
    }
    env->pin_store->calls++;
    p23_pin_commits++;
    return 0;
}

static void script_add(script *src, const uint8_t *data, size_t len)
{
    src->data[src->count] = data;
    src->len[src->count] = len;
    src->count++;
}

static void fill_budget(dmp_hs_budget *budget)
{
    memset(budget, 0, sizeof *budget);
    budget->max_pending = 2U;
    budget->max_scratch = 2U;
    budget->episode_attempts = 3U;
    budget->episode_deadline_ms = 100000U;
    budget->episode_work = 1000U;
    budget->episode_traffic = 100000U;
    budget->restart_backoff_ms = 1000U;
    budget->attempt_deadline_ms = 60000U;
    budget->cached_responses = 3U;
    budget->global_work = 1000U;
    budget->ingress_work = 1000U;
    budget->later_episodes = 1U;
    budget->admit_burst = 4U;
    budget->provisional_bytes = 240U;
    budget->confirmation_timeout_ms = 1000U;
    budget->confirmation_attempts = 3U;
}

static void fill_hs(dmp_hs_config *config, const noise_fixture_probe_fixture_t *fixture, int initiator)
{
    memset(config, 0, sizeof *config);
    fill_budget(&config->budget);
    config->namespace_id = LOCAL_NS;
    config->local_id = initiator ? ID_INIT : ID_RESP;
    config->peer_id = initiator ? ID_RESP : ID_INIT;
    memcpy(config->profile_hash,
           g_profile_hash_override != NULL ? g_profile_hash_override : fixture->profile_hash.data,
           32U);
    config->mode = 1U;
    config->cipher = 1U;
    config->key_hint = KEY_HINT;
    config->permissions = 2U;
    config->next_rx_cid = initiator ? CID_INIT : CID_RESP;
    config->confirmation_route_ttl = g_p23_confirmation_route_ttl;
    if (fixture->psk.data != NULL) {
        memcpy(config->psk,
               g_psk_override != NULL ? g_psk_override : fixture->psk.data,
               32U);
        config->has_psk = 1;
    }
}

static void p23_apply_hs_profile(dmp_hs_config *config)
{
    if (config == NULL || g_p23_profile_id == P23_PROFILE_NONE) {
        return;
    }
    config->budget.max_pending = 1U;
    config->budget.max_scratch = 1U;
    config->budget.episode_attempts = 2U;
    config->budget.episode_deadline_ms = 41000U;
    config->budget.episode_work = 2000U;
    config->budget.episode_traffic = 16384U;
    config->budget.restart_backoff_ms = 1000U;
    config->budget.attempt_deadline_ms = 20000U;
    config->budget.cached_responses = 1U;
    config->budget.global_work = 100000U;
    config->budget.ingress_work = 100U;
    config->budget.later_episodes = 2U;
    config->budget.admit_burst = 16U;
    config->budget.admit_window_ms = 1000U;
    config->budget.provisional_bytes = 120U;
    config->budget.replay_window = 1024U;
    config->budget.failed_aead_limit = 1000U;
    config->budget.association_lifetime_ms = 100000000U;
    config->budget.confirmation_timeout_ms = 512U;
    config->budget.confirmation_attempts = 2U;
    config->mode = g_p23_security_mode;
    if (g_p23_security_mode == 2U) {
        static const uint8_t local_static[32] = {0U};
        memset(config->psk, 0, sizeof config->psk);
        config->has_psk = 0;
        memcpy(config->local_static,
               p23_static_override != NULL ? p23_static_override : local_static,
               sizeof local_static);
        config->has_static = 1;
        config->key_hint = 0U;
        config->pairing_allowed = 1;
    }
    p23_effective_budget = config->budget;
}

static void close_session(session *env)
{
    if (env->initiator != NULL) {
        dmp_hs_cleanup(env->initiator);
    }
    if (env->responder != NULL) {
        dmp_hs_cleanup(env->responder);
    }
    if (env->provider != NULL) {
        dmp_provider_cleanup(env->provider);
    }
    free(env->initiator);
    free(env->responder);
    free(env->provider);
    env->initiator = NULL;
    env->responder = NULL;
    env->provider = NULL;
}

static int make_pair(session *env, port_ctx *port, const noise_fixture_probe_fixture_t *fixture,
                     tune_fn tune, dmp_provider *existing, int alt_entropy)
{
    dmp_hs_config init_config;
    dmp_hs_config resp_config;
    dmp_hs_ports init_ports;
    dmp_hs_ports resp_ports;
    dmp_provider_ports ports;
    dmp_provider *provider;
    memset(env, 0, sizeof *env);
    env->now = 10000U;
    memset(port, 0, sizeof *port);
    provider = existing;
    if (existing == NULL) {
        memset(&ports, 0, sizeof ports);
        ports.startup_ready = startup_ready;
        ports.startup_read = startup_read;
        ports.entropy = provider_entropy;
        ports.allocate = port_allocate;
        ports.release = port_release;
        ports.ctx = port;
        ports.scratch_limit = DMP_PROVIDER_SCRATCH_MAX;
        ports.retained_limit = DMP_PROVIDER_RETAINED_MAX;
        env->provider = (dmp_provider *)calloc(1, dmp_provider_size());
        if (env->provider == NULL || dmp_provider_setup(env->provider, &ports) != DMP_PROVIDER_OK) {
            close_session(env);
            return 0;
        }
        provider = env->provider;
    }
    env->initiator = (dmp_hs *)calloc(1, dmp_hs_size());
    env->responder = (dmp_hs *)calloc(1, dmp_hs_size());
    if (env->initiator == NULL || env->responder == NULL) {
        close_session(env);
        return 0;
    }
    fill_hs(&init_config, fixture, 1);
    fill_hs(&resp_config, fixture, 0);
    p23_apply_hs_profile(&init_config);
    p23_apply_hs_profile(&resp_config);
    if (tune != NULL) {
        tune(&init_config, &resp_config);
    }
    if (alt_entropy) {
        memset(env->alt_attempt, 0x42, sizeof env->alt_attempt);
        script_add(&env->init_script, env->alt_attempt, sizeof env->alt_attempt);
        script_add(&env->init_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
        script_add(&env->resp_script, fixture->init_ephemeral.data, fixture->init_ephemeral.size);
    } else {
        script_add(&env->init_script, fixture->attempt_id.data, fixture->attempt_id.size);
        script_add(&env->init_script, fixture->init_ephemeral.data, fixture->init_ephemeral.size);
        script_add(&env->resp_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
    }
    env->init_box.now = &env->now;
    env->init_box.entropy_script = &env->init_script;
    env->init_box.pin_store = &env->init_store;
    env->resp_box.now = &env->now;
    env->resp_box.entropy_script = &env->resp_script;
    env->resp_box.pin_store = &env->resp_store;
    memset(&init_ports, 0, sizeof init_ports);
    memset(&resp_ports, 0, sizeof resp_ports);
    init_ports.now_ms = now_of;
    init_ports.entropy = entropy_of;
    init_ports.commit_pin = commit_of;
    init_ports.ctx = &env->init_box;
    resp_ports.now_ms = now_of;
    resp_ports.entropy = entropy_of;
    resp_ports.commit_pin = commit_of;
    resp_ports.ctx = &env->resp_box;
    if (dmp_hs_init(env->initiator, provider, &init_config, &init_ports) != DMP_HS_OK ||
        dmp_hs_init(env->responder, provider, &resp_config, &resp_ports) != DMP_HS_OK ||
        dmp_hs_begin_episode(env->initiator) != DMP_HS_OK) {
        close_session(env);
        return 0;
    }
    return 1;
}

static int drive_flight(dmp_hs *hs, const uint8_t *payload, size_t length, uint32_t origin,
                        uint32_t destination, uint32_t seq, uint64_t epoch, dmp_hs_status expected)
{
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    dmp_hs_status status;
    memset(&ingress, 0, sizeof ingress);
    ingress.payload = payload;
    ingress.payload_len = length;
    ingress.origin_id = origin;
    ingress.destination_id = destination;
    ingress.namespace_id = LOCAL_NS;
    ingress.context_epoch = epoch;
    ingress.seq = seq;
    status = dmp_hs_offer(hs, &ingress, &completion);
    if (status == DMP_HS_AWAITING) {
        status = dmp_hs_accept(hs, &completion);
    }
    return status == expected;
}

static int drive_nn(session *env, uint32_t *index)
{
    const uint8_t *cached;
    size_t length = 0U;
    uint64_t boot;
    if (dmp_hs_schedule(env->initiator, index) != DMP_HS_OK) {
        return 0;
    }
    boot = dmp_hs_boot_epoch(env->initiator, *index);
    if (boot == 0U) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->initiator, *index, &length);
    if (!drive_flight(env->responder, cached, length, ID_INIT, ID_RESP, 1U, boot, DMP_HS_CANDIDATE)) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->responder, 0U, &length);
    return drive_flight(env->initiator, cached, length, ID_RESP, ID_INIT, 2U, boot, DMP_HS_CANDIDATE);
}

static int offer_protected(dmp_hs *hs, const uint8_t *frame, size_t length, uint32_t origin,
                           uint32_t destination, uint64_t epoch)
{
    dmp_hs_protected incoming;
    memset(&incoming, 0, sizeof incoming);
    incoming.frame = frame;
    incoming.frame_len = length;
    incoming.origin_id = origin;
    incoming.destination_id = destination;
    incoming.namespace_id = LOCAL_NS;
    incoming.context_epoch = epoch;
    return dmp_hs_offer_protected(hs, &incoming) == DMP_HS_OK;
}

static int activate(session *env, uint32_t index)
{
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    const uint8_t *frame;
    size_t length = 0U;
    if (!dmp_hs_epochs(env->initiator, index, &epoch_i, &epoch_r)) {
        return 0;
    }
    if (dmp_hs_confirm(env->initiator, index) != DMP_HS_OK) {
        return 0;
    }
    frame = dmp_hs_protected_frame(env->initiator, index, &length);
    if (frame == NULL || !offer_protected(env->responder, frame, length, ID_INIT, ID_RESP, epoch_i)) {
        return 0;
    }
    frame = dmp_hs_protected_frame(env->responder, 0U, &length);
    if (frame == NULL || !offer_protected(env->initiator, frame, length, ID_RESP, ID_INIT, epoch_r)) {
        return 0;
    }
    return dmp_hs_association_active(env->initiator) && dmp_hs_association_active(env->responder);
}

static int bind_pair(session *env, uint32_t index)
{
    CHECK(dmp_endpoint_bind(&left.endpoint, env->initiator, index) == DMP_OK);
    CHECK(dmp_endpoint_bind(&right.endpoint, env->responder, 0U) == DMP_OK);
    return 0;
}

static int unwrap_core(const uint8_t *framed, size_t n, uint8_t *core, size_t cap, size_t *core_n,
                       dmp_time_ms now)
{
    dmp_stream_decoder decoder;
    dmp_stream_config config;
    dmp_buffer storage;
    uint8_t scratch[STREAM_CAP];
    dmp_bytes input;
    memset(&decoder, 0, sizeof decoder);
    memset(&config, 0, sizeof config);
    config.mode = DMP_STREAM_R;
    config.max_core_bytes = MTU;
    config.partial_timeout_ms = 1U;
    storage.data = scratch;
    storage.capacity = sizeof scratch;
    if (dmp_stream_init(&decoder, config, storage, now) != DMP_OK) {
        return 0;
    }
    input = span(framed, n);
    while (input.size != 0U) {
        dmp_stream_result fed = dmp_stream_feed(&decoder, input, now);
        if (fed.status != DMP_OK || fed.consumed == 0U || fed.consumed > input.size) {
            return 0;
        }
        input.data += fed.consumed;
        input.size -= fed.consumed;
        if (fed.event == DMP_STREAM_FRAME) {
            if (fed.frame.size > cap) {
                return 0;
            }
            if (fed.frame.size != 0U) {
                memcpy(core, fed.frame.data, fed.frame.size);
            }
            *core_n = fed.frame.size;
            return 1;
        }
    }
    return 0;
}

static int wrap_core(const uint8_t *core, size_t n, uint8_t *out, size_t cap, size_t *out_n)
{
    dmp_buffer encoded;
    size_t written = 0U;
    if (cap < 2U) {
        return 0;
    }
    encoded.data = out + 1U;
    encoded.capacity = cap - 1U;
    if (dmp_stream_encode(DMP_STREAM_R, span(core, n), encoded, &written) != DMP_OK) {
        return 0;
    }
    out[0] = 0U;
    *out_n = written + 1U;
    return 1;
}

static int test_activation(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t req[1];
    uint8_t plain[32];
    uint8_t wrapped[128];
    dmp_frame_spec spec;
    dmp_core_limits limits;
    dmp_buffer out;
    size_t written = 0U;
    size_t wrapped_n = 0U;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    dmp_status status;
    int failed = 1;
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index)) {
        return 1;
    }
    if (boot_node(&left, 1, 64U, 16U, now) != 0 || boot_node(&right, 0, 64U, 16U, now) != 0 ||
        bind_pair(&env, index) != 0) {
        close_session(&env);
        return 1;
    }
    CHECK(dmp_hs_association_active(env.initiator) == 0);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    status = dmp_endpoint_poll(&right.endpoint, now);
    /* A live attempt that is not active yet keeps the admitted REQ.
     * Poll stays DMP_OK because reliability treats that wait as DMP_BUSY. */
    CHECK(status == DMP_OK);
    CHECK(right.wire.n == 0);
    CHECK(left.app.accepts == 0);
    CHECK(activate(&env, index) == 1);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(right.app.result_n == sizeof READ_RSP);
    CHECK(memcmp(right.app.result, READ_RSP, sizeof READ_RSP) == 0);
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ);
    spec.fields.seq = 1U;
    spec.payload = span(req, 1U);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 16U;
    out.data = plain;
    out.capacity = sizeof plain;
    CHECK(dmp_core_encode(&spec, &limits, out, &written) == DMP_OK);
    CHECK(wrap_core(plain, written, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(left.app.accepts == 1);
    failed = 0;
    close_session(&env);
    return failed;
}

static int test_alter(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t req[1];
    uint8_t core[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t core_n = 0U;
    size_t wrapped_n = 0U;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    dmp_status status = DMP_OK;
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(service(&left, now) == 0);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 1);
    CHECK(unwrap_core(left.wire.q[0].frame, left.wire.q[0].len, core, sizeof core, &core_n, now) == 1);
    CHECK(core_n > 1U);
    core[core_n - 1U] ^= 0x01U;
    CHECK(wrap_core(core, core_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.results == 0);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(right.app.results == 1);
    CHECK(right.app.result_n == sizeof READ_RSP);
    CHECK(memcmp(right.app.result, READ_RSP, sizeof READ_RSP) == 0);
    close_session(&env);
    return 0;
}

static int test_loss(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t req[1];
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    /* The existing reliability engine retries the request. The dropped frame is
     * not replayed: the later submit is a newly sealed record. */
    right.wire.drop_remaining = 1;
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 4) == 0);
    CHECK(left.app.accepts == 0);
    CHECK(right.app.results == 0);
    CHECK(right.wire.saved_len > 0U);
    CHECK(pump(now + 1280U, 8) == 0);
    CHECK(right.wire.submits >= 2);
    CHECK(right.wire.last_len > 0U);
    CHECK(right.wire.saved_len != right.wire.last_len ||
          memcmp(right.wire.saved, right.wire.last, right.wire.saved_len) != 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(memcmp(right.app.result, READ_RSP, sizeof READ_RSP) == 0);
    close_session(&env);
    return 0;
}

static void tune_alt(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    initiator->next_rx_cid = 100U;
    responder->next_rx_cid = 200U;
}

static int test_isolate(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    session other;
    port_ctx port;
    port_ctx other_port;
    uint32_t index = 0U;
    uint32_t other_index = 0U;
    uint8_t req[1];
    uint8_t stolen[FRAME_CAP];
    size_t stolen_len = 0U;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    dmp_status status = DMP_OK;
    memset(&env, 0, sizeof env);
    memset(&other, 0, sizeof other);
    if (fixture == NULL || !make_pair(&other, &other_port, fixture, tune_alt, NULL, 1) ||
        !drive_nn(&other, &other_index) || !activate(&other, other_index)) {
        close_session(&other);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(dmp_endpoint_bind(&left.endpoint, other.initiator, other_index) == DMP_OK);
    CHECK(dmp_endpoint_bind(&right.endpoint, other.responder, 0U) == DMP_OK);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n == 1);
    CHECK(right.wire.q[0].len <= sizeof stolen);
    memcpy(stolen, right.wire.q[0].frame, right.wire.q[0].len);
    stolen_len = right.wire.q[0].len;
    close_session(&other);
    if (!make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    status = dmp_endpoint_rx(&left.endpoint, span(stolen, stolen_len), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(left.app.accepts == 0);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    close_session(&env);
    return 0;
}

static int test_reassembly(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    session other;
    port_ctx port;
    port_ctx other_port;
    uint32_t index = 0U;
    uint32_t other_index = 0U;
    uint8_t body[FRAG_BYTES];
    uint8_t stolen[FRAME_CAP];
    size_t stolen_len = 0U;
    uint8_t conflict_bytes[FRAG_CHUNK];
    uint8_t ext[3];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    uint8_t core[MTU];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    size_t core_n = 0U;
    dmp_frame_spec spec;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_parse_result parsed;
    dmp_time_ms now = 20000U;
    dmp_status status = DMP_OK;
    int i;
    size_t n;
    memset(&env, 0, sizeof env);
    memset(&other, 0, sizeof other);
    if (fixture == NULL || !make_pair(&other, &other_port, fixture, tune_alt, NULL, 1) ||
        !drive_nn(&other, &other_index) || !activate(&other, other_index)) {
        close_session(&other);
        return 1;
    }
    CHECK(boot_node(&left, 1, FRAG_CHUNK, 32U, now) == 0);
    CHECK(dmp_endpoint_bind(&left.endpoint, other.initiator, other_index) == DMP_OK);
    for (n = 0U; n < sizeof body; n++) {
        body[n] = (uint8_t)(0x40U + (uint8_t)(n & 0x0fU));
    }
    left.wire.now = now;
    CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(body, sizeof body), now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n >= 1);
    CHECK(left.wire.q[0].len <= sizeof stolen);
    memcpy(stolen, left.wire.q[0].frame, left.wire.q[0].len);
    stolen_len = left.wire.q[0].len;
    close_session(&other);
    if (!make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, FRAG_CHUNK, 32U, now) == 0);
    CHECK(boot_node(&right, 0, FRAG_CHUNK, 32U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    for (n = 0U; n < sizeof body; n++) {
        body[n] = (uint8_t)(0x40U + (uint8_t)(n & 0x0fU));
    }
    memset(conflict_bytes, 0xff, sizeof conflict_bytes);
    left.wire.now = now;
    CHECK(dmp_endpoint_submit_fragmented(&left.endpoint, 2U, span(body, sizeof body), now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n >= 2);
    status = dmp_endpoint_rx(&right.endpoint, span(stolen, stolen_len), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.assembled == 0);
    CHECK(deliver_one(&left, &right, 0, now, &status) == 0);
    CHECK(status == DMP_INCOMPLETE);
    CHECK(unwrap_core(left.wire.q[0].frame, left.wire.q[0].len, core, sizeof core, &core_n, now) == 1);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    parsed = dmp_core_parse(span(core, core_n), &limits, &view);
    CHECK(parsed.status == DMP_OK);
    ext[0] = 17U;
    ext[1] = 1U;
    ext[2] = 2U;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_DATA;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_FRAG | DMP_OPT_EXT);
    spec.fields.seq = view.fields.seq;
    spec.fields.fragment.index = 0U;
    spec.fields.fragment.chunk_size = FRAG_CHUNK;
    spec.fields.fragment.total_size = FRAG_BYTES;
    spec.extensions = span(ext, sizeof ext);
    spec.payload = span(conflict_bytes, sizeof conflict_bytes);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_MALFORMED);
    CHECK(right.app.assembled == 0);
    for (i = left.wire.n - 1; i >= 1; i--) {
        CHECK(deliver_one(&left, &right, i, now, &status) == 0);
        CHECK(status == DMP_OK || status == DMP_INCOMPLETE || status == DMP_DUPLICATE);
    }
    CHECK(right.app.assembled == 1);
    CHECK(right.app.body_n == sizeof body);
    CHECK(memcmp(right.app.body, body, sizeof body) == 0);
    close_session(&env);
    return 0;
}

static int test_ttl(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t payload[2] = {0x11, 0x22};
    uint8_t ext[16];
    uint8_t sealed[MTU];
    uint8_t ttl_only[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t ext_n = 0U;
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    size_t at;
    unsigned b;
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    dmp_frame_spec spec;
    dmp_time_ms now = 20000U;
    dmp_status status;
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_hs_epochs(env.initiator, index, &epoch_i, &epoch_r) == 1);
    (void)epoch_r;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_TELEM;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ROUTE);
    spec.fields.seq = 1U;
    spec.fields.route.mode = 1U;
    spec.fields.route.ttl = 4U;
    spec.fields.route.source = ID_INIT;
    spec.fields.route.destination = ID_RESP;
    spec.payload = span(payload, sizeof payload);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_CONTEXT_REQUIRED);
    CHECK(right.app.telems == 0);
    ext[ext_n++] = 11U;
    ext[ext_n++] = 9U;
    ext[ext_n++] = 1U;
    for (b = 0U; b < 8U; b++) {
        ext[ext_n++] = (uint8_t)(epoch_i >> (8U * b));
    }
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ROUTE | DMP_OPT_EXT);
    spec.fields.seq = 2U;
    spec.extensions = span(ext, ext_n);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(sealed_n > 4U);
    memcpy(ttl_only, sealed, sealed_n);
    at = 3U;
    while (at < sealed_n && (ttl_only[at] & 0x80U) != 0U) {
        at++;
    }
    at++;
    CHECK(at + 2U < sealed_n);
    ttl_only[at + 2U] ^= 0x01U;
    CHECK(wrap_core(ttl_only, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.telems == 0);
    ttl_only[at + 2U] ^= 0x01U;
    ttl_only[at] = (uint8_t)((9U << 4) | (ttl_only[at] & 0x0fU));
    CHECK(wrap_core(ttl_only, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.telems == 1);
    close_session(&env);
    return 0;
}

static int offer_indexed(dmp_hs *hs, const uint8_t *payload, size_t length, uint32_t origin,
                         uint32_t destination, uint32_t seq, uint64_t epoch, dmp_hs_status expected,
                         uint32_t *index_out)
{
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    dmp_hs_status status;

    memset(&ingress, 0, sizeof ingress);
    memset(&completion, 0, sizeof completion);
    ingress.payload = payload;
    ingress.payload_len = length;
    ingress.origin_id = origin;
    ingress.destination_id = destination;
    ingress.namespace_id = LOCAL_NS;
    ingress.context_epoch = epoch;
    ingress.seq = seq;
    status = dmp_hs_offer(hs, &ingress, &completion);
    if (status == DMP_HS_AWAITING) {
        if (index_out != NULL) {
            *index_out = completion.attempt_index;
        }
        status = dmp_hs_accept(hs, &completion);
    }
    return status == expected;
}

static int drive_rotation(session *env, const noise_fixture_probe_fixture_t *fixture,
                          uint32_t *init_index, uint32_t *resp_index, uint8_t salt)
{
    const uint8_t *cached;
    size_t length = 0U;
    uint64_t boot;

    memcpy(env->rot_id, fixture->attempt_id.data, 16U);
    env->rot_id[0] ^= salt;
    memcpy(env->rot_init_eph, fixture->init_ephemeral.data, 32U);
    memcpy(env->rot_resp_eph, fixture->resp_ephemeral.data, 32U);
    /* A new attempt id is not a new ephemeral. Flip an unclamped scalar byte. */
    env->rot_init_eph[8] ^= salt;
    env->rot_resp_eph[8] ^= salt;
    script_add(&env->init_script, env->rot_id, sizeof env->rot_id);
    script_add(&env->init_script, env->rot_init_eph, sizeof env->rot_init_eph);
    script_add(&env->resp_script, env->rot_resp_eph, sizeof env->rot_resp_eph);
    if (dmp_hs_schedule(env->initiator, init_index) != DMP_HS_OK) {
        return 0;
    }
    boot = dmp_hs_boot_epoch(env->initiator, *init_index);
    cached = dmp_hs_cached_flight(env->initiator, *init_index, &length);
    if (cached == NULL ||
        !offer_indexed(env->responder, cached, length, ID_INIT, ID_RESP, 1U, boot, DMP_HS_CANDIDATE,
                       resp_index)) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->responder, *resp_index, &length);
    return cached != NULL &&
           offer_indexed(env->initiator, cached, length, ID_RESP, ID_INIT, 2U, boot, DMP_HS_CANDIDATE,
                         NULL);
}

static int activate_at(session *env, uint32_t init_index, uint32_t resp_index)
{
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    const uint8_t *frame;
    size_t length = 0U;

    if (!dmp_hs_epochs(env->initiator, init_index, &epoch_i, &epoch_r)) {
        return 0;
    }
    if (dmp_hs_confirm(env->initiator, init_index) != DMP_HS_OK) {
        return 0;
    }
    frame = dmp_hs_protected_frame(env->initiator, init_index, &length);
    if (frame == NULL || !offer_protected(env->responder, frame, length, ID_INIT, ID_RESP, epoch_i)) {
        return 0;
    }
    frame = dmp_hs_protected_frame(env->responder, resp_index, &length);
    if (frame == NULL || !offer_protected(env->initiator, frame, length, ID_RESP, ID_INIT, epoch_r)) {
        return 0;
    }
    return dmp_hs_send_application(env->initiator, init_index) == DMP_HS_OK &&
           dmp_hs_send_application(env->responder, resp_index) == DMP_HS_OK;
}

static int stream_protection(const uint8_t *framed, size_t n, dmp_time_ms now, uint32_t *cid,
                             uint64_t *pn, uint8_t *type_out)
{
    uint8_t core[MTU];
    size_t core_n = 0U;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_parse_result parsed;

    if (!unwrap_core(framed, n, core, sizeof core, &core_n, now)) {
        return 0;
    }
    memset(&view, 0, sizeof view);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    parsed = dmp_core_parse(span(core, core_n), &limits, &view);
    if (parsed.status != DMP_OK || (view.fields.options & DMP_OPT_SECURITY) == 0U) {
        return 0;
    }
    if (cid != NULL) {
        *cid = view.fields.security.receive_cid;
    }
    if (pn != NULL) {
        *pn = view.fields.security.pn;
    }
    if (type_out != NULL) {
        *type_out = view.fields.type;
    }
    return 1;
}

static int protected_err_status(const uint8_t *framed, size_t n, dmp_time_ms now, uint32_t *status_out)
{
    uint8_t core[MTU];
    size_t core_n = 0U;
    size_t cursor = 0U;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_parse_result parsed;
    int found = 0;
    uint32_t wire = 0U;

    if (!unwrap_core(framed, n, core, sizeof core, &core_n, now) || status_out == NULL) {
        return 0;
    }
    memset(&view, 0, sizeof view);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    parsed = dmp_core_parse(span(core, core_n), &limits, &view);
    if (parsed.status != DMP_OK) {
        return 0;
    }
    while (cursor < view.extensions.size) {
        dmp_extension_view ext;
        size_t at = 0U;
        uint32_t value = 0U;
        dmp_status step = dmp_extension_next(view.extensions, &cursor, &ext);
        if (step == DMP_INCOMPLETE) {
            break;
        }
        if (step != DMP_OK) {
            return 0;
        }
        if ((ext.tag >> 2) != 5U) {
            continue;
        }
        if (found != 0 || (ext.tag & 3U) != 1U || ext.value.size == 0U || ext.value.data == NULL) {
            return 0;
        }
        while (at < ext.value.size) {
            uint8_t byte = ext.value.data[at++];
            value = (value << 7) | (uint32_t)(byte & 0x7fU);
            if ((byte & 0x80U) == 0U) {
                break;
            }
        }
        wire = value;
        found = 1;
    }
    if (found == 0) {
        return 0;
    }
    *status_out = wire;
    return 1;
}

static int test_acl(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_endpoint_grant control_only[1];
    dmp_frame_spec spec;
    uint32_t index = 0U;
    uint32_t cid = 0U;
    uint8_t req[1];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    uint8_t type = 0U;
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    dmp_status status;
    int accepts_before;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    sample1_read_req(req);
    /* Node 10 may produce and answer. It may not issue READ. */
    CHECK(dmp_endpoint_submit_req(&left.endpoint, 1U, span(req, 1U), now, &handle) ==
          DMP_UNSUPPORTED);
    CHECK(left.wire.n == 0);
    CHECK(right.app.accepts == 0);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);

    memset(control_only, 0, sizeof control_only);
    control_only[0].principal = ID_INIT;
    control_only[0].service_id = 0U;
    control_only[0].permit = DMP_ENDPOINT_PERMIT_CONTROL;
    CHECK(dmp_endpoint_set_grants(&right.endpoint, control_only, 1U) == DMP_OK);
    accepts_before = right.app.accepts;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ);
    spec.fields.seq = 40U;
    spec.payload = span(req, 1U);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == accepts_before);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n >= 1);
    CHECK(stream_protection(right.wire.q[right.wire.n - 1].frame, right.wire.q[right.wire.n - 1].len, now,
                            &cid, NULL, &type) == 1);
    CHECK(type == (uint8_t)DMP_TYPE_ERR);
    {
        uint32_t wire_status = 0U;
        CHECK(protected_err_status(right.wire.q[right.wire.n - 1].frame,
                                   right.wire.q[right.wire.n - 1].len, now, &wire_status) == 1);
        CHECK(wire_status == 6U);
    }
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == accepts_before);
    close_session(&env);
    return 0;
}

static int test_rotation(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint32_t next_init = 0U;
    uint32_t next_resp = 0U;
    uint32_t old_cid = 0U;
    uint32_t new_cid = 0U;
    uint8_t req[1];
    uint8_t saved[FRAME_CAP];
    size_t saved_len = 0U;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    int accepts;

    /* One identity slot cannot overlap. The live association stays. */
    memset(&env, 0, sizeof env);
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_rotate(&left.endpoint, index, now) == DMP_BUSY);
    if (!drive_rotation(&env, fixture, &next_init, &next_resp, 0x5aU) ||
        !activate_at(&env, next_init, next_resp)) {
        close_session(&env);
        return 1;
    }
    CHECK(dmp_endpoint_rotate(&left.endpoint, next_init, now) == DMP_QUOTA_EXHAUSTED);
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_QUOTA_EXHAUSTED);
    CHECK(left.endpoint.drain_live == 0U);
    CHECK(right.endpoint.drain_live == 0U);
    CHECK(dmp_hs_send_application(env.initiator, index) == DMP_HS_OK);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 6) == 0);
    CHECK(left.app.accepts == 1);
    close_session(&env);

    /* Overlap: new messages wait for activation, then stay off the old association. */
    memset(&env, 0, sizeof env);
    if (!make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node_slots(&left, 1, 64U, 16U, now, 2U) == 0);
    CHECK(boot_node_slots(&right, 0, 64U, 16U, now, 2U) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_set_drain_ms(&left.endpoint, 30000U) == DMP_OK);
    CHECK(dmp_endpoint_set_drain_ms(&right.endpoint, 30000U) == DMP_OK);
    sample1_read_req(req);
    right.wire.drop_remaining = 1;
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.saved_len > 0U);
    memcpy(saved, right.wire.saved, right.wire.saved_len);
    saved_len = right.wire.saved_len;
    CHECK(stream_protection(saved, saved_len, now, &old_cid, NULL, NULL) == 1);
    if (!drive_rotation(&env, fixture, &next_init, &next_resp, 0x5aU)) {
        close_session(&env);
        return 1;
    }
    /* FINISH is sealed and READY is not delivered, so the new attempt is not active. */
    CHECK(dmp_hs_confirm(env.initiator, next_init) == DMP_HS_OK);
    CHECK(dmp_endpoint_rotate(&left.endpoint, next_init, now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(dmp_hs_send_application(env.initiator, index) == DMP_HS_OK);
    {
        uint64_t epoch_i = 0U;
        uint64_t epoch_r = 0U;
        const uint8_t *frame;
        size_t length = 0U;
        CHECK(dmp_hs_epochs(env.initiator, next_init, &epoch_i, &epoch_r) == 1);
        frame = dmp_hs_protected_frame(env.initiator, next_init, &length);
        CHECK(frame != NULL);
        CHECK(offer_protected(env.responder, frame, length, ID_INIT, ID_RESP, epoch_i) == 1);
        frame = dmp_hs_protected_frame(env.responder, next_resp, &length);
        CHECK(frame != NULL);
        CHECK(offer_protected(env.initiator, frame, length, ID_RESP, ID_INIT, epoch_r) == 1);
    }
    CHECK(dmp_hs_send_application(env.initiator, next_init) == DMP_HS_OK);
    CHECK(dmp_endpoint_rotate(&left.endpoint, next_init, now) == DMP_OK);
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_OK);
    CHECK(right.app.unknowns == 0);
    CHECK(pump(now + 1280U, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    accepts = left.app.accepts;
    {
        dmp_time_ms later = now + 1280U;
        dmp_status replay = dmp_endpoint_rx(&left.endpoint, span(saved, saved_len), later);
        CHECK(replay == DMP_OK || replay == DMP_DUPLICATE);
        CHECK(left.app.accepts == accepts);
        right.wire.n = 0;
        CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), later, &handle) == DMP_OK);
        right.wire.now = later;
        CHECK(dmp_endpoint_poll(&right.endpoint, later) == DMP_OK);
        CHECK(right.wire.n >= 1);
        CHECK(stream_protection(right.wire.q[0].frame, right.wire.q[0].len, later, &new_cid, NULL,
                                NULL) == 1);
        CHECK(new_cid != old_cid);
        CHECK(pump(later, 6) == 0);
        CHECK(left.app.accepts == accepts + 1);
    }

    now = 20000U + 30000U;
    left.wire.now = now;
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(dmp_hs_send_application(env.initiator, index) != DMP_HS_OK);
    accepts = left.app.accepts;
    CHECK(dmp_endpoint_rx(&left.endpoint, span(saved, saved_len), now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(left.app.accepts == accepts);

    /* A request that cannot finish inside the drain bound is unknown, not moved. */
    close_session(&env);
    memset(&env, 0, sizeof env);
    now = 20000U;
    if (!make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node_slots(&left, 1, 64U, 16U, now, 2U) == 0);
    CHECK(boot_node_slots(&right, 0, 64U, 16U, now, 2U) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_set_drain_ms(&right.endpoint, 1000U) == DMP_OK);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(stream_protection(right.wire.q[0].frame, right.wire.q[0].len, now, &old_cid, NULL, NULL) == 1);
    if (!drive_rotation(&env, fixture, &next_init, &next_resp, 0x5aU) || !activate_at(&env, next_init, next_resp)) {
        close_session(&env);
        return 1;
    }
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_OK);
    CHECK(right.app.unknowns == 1);
    CHECK(left.app.accepts == 0);
    right.wire.n = 0;
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n >= 1);
    CHECK(stream_protection(right.wire.q[0].frame, right.wire.q[0].len, now, &new_cid, NULL, NULL) == 1);
    CHECK(new_cid != old_cid);

    /* A short unauthenticated buffer is not a revoke command. */
    CHECK(dmp_endpoint_rx(&right.endpoint, span(req, 1U), now) == DMP_OK);
    CHECK(dmp_hs_send_application(env.responder, next_resp) == DMP_HS_OK);
    CHECK(dmp_endpoint_revoke(&right.endpoint, now) == DMP_OK);
    CHECK(right.app.unknowns >= 1);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) ==
          DMP_AUTHENTICATION_FAILURE);
    CHECK(dmp_hs_send_application(env.responder, next_resp) != DMP_HS_OK);
    close_session(&env);
    return 0;
}

static int test_result_permit(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_endpoint_grant grants[2];
    uint32_t index = 0U;
    uint8_t req[1];
    uint8_t payload[SAMPLE1_READ_BYTES];
    size_t n;
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    dmp_status status = DMP_OK;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    memset(grants, 0, sizeof grants);
    grants[0].principal = ID_INIT;
    grants[0].service_id = 1U;
    grants[0].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[1].principal = ID_RESP;
    grants[1].service_id = 1U;
    grants[1].permit = DMP_ENDPOINT_PERMIT_REQ;
    CHECK(dmp_endpoint_set_grants(&left.endpoint, grants, 2U) == DMP_OK);
    CHECK(dmp_endpoint_set_grants(&right.endpoint, grants, 2U) == DMP_OK);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_one(&right, &left, 0, now, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(left.app.accepts == 1);
    CHECK(left.wire.n == 0);
    n = sample1_read_rsp(payload, 1U, 2U, 300U);
    CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, false, 0U, span(payload, n), now) ==
          DMP_UNSUPPORTED);
    CHECK(left.wire.n == 0);
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 0);
    close_session(&env);
    return 0;
}

static int test_frag_deny(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_endpoint_grant control_only[1];
    dmp_frame_spec spec;
    uint32_t index = 0U;
    uint32_t cid = 0U;
    uint8_t body[16];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    uint8_t type = 0U;
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    dmp_time_ms now = 20000U;
    dmp_status status;
    int accepts_before;
    size_t i;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    memset(control_only, 0, sizeof control_only);
    control_only[0].principal = ID_INIT;
    control_only[0].service_id = 0U;
    control_only[0].permit = DMP_ENDPOINT_PERMIT_CONTROL;
    CHECK(dmp_endpoint_set_grants(&right.endpoint, control_only, 1U) == DMP_OK);
    accepts_before = right.app.accepts;
    for (i = 0U; i < sizeof body; i++) {
        body[i] = (uint8_t)(0x30U + (uint8_t)i);
    }
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_FRAG);
    spec.fields.seq = 41U;
    spec.fields.fragment.index = 0U;
    spec.fields.fragment.chunk_size = 16U;
    spec.fields.fragment.total_size = 32U;
    spec.payload = span(body, sizeof body);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    right.wire.n = 0;
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == accepts_before);
    CHECK(right.app.assembled == 0);
    CHECK(right.assemblies[0].live == 0U);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n >= 1);
    CHECK(stream_protection(right.wire.q[right.wire.n - 1].frame, right.wire.q[right.wire.n - 1].len, now,
                            &cid, NULL, &type) == 1);
    CHECK(type == (uint8_t)DMP_TYPE_ERR);
    {
        uint32_t wire_status = 0U;
        CHECK(protected_err_status(right.wire.q[right.wire.n - 1].frame,
                                   right.wire.q[right.wire.n - 1].len, now, &wire_status) == 1);
        CHECK(wire_status == 6U);
    }
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.accepts == accepts_before);
    CHECK(right.assemblies[0].live == 0U);
    close_session(&env);
    return 0;
}

static void tune_pending(dmp_hs_config *initiator, dmp_hs_config *responder)
{
    initiator->budget.max_pending = 3U;
    initiator->budget.episode_attempts = 4U;
    responder->budget.max_pending = 3U;
    responder->budget.episode_attempts = 4U;
}

static int test_drain_retain(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_frame_spec spec;
    dmp_identity_slot *draining;
    uint32_t index = 0U;
    uint32_t next_init = 0U;
    uint32_t next_resp = 0U;
    uint32_t later_init = 0U;
    uint32_t later_resp = 0U;
    uint8_t body[16];
    uint8_t ext[3];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    size_t i;
    dmp_time_ms now = 20000U;
    dmp_time_ms accept_at;
    dmp_time_ms drain_at;
    dmp_time_ms assembly_at;
    dmp_status status = DMP_OK;

    memset(&env, 0, sizeof env);
    if (fixture == NULL || !make_pair(&env, &port, fixture, tune_pending, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node_slots(&right, 0, 64U, 16U, now, 2U) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_set_drain_ms(&right.endpoint, 1000U) == DMP_OK);
    CHECK(right.endpoint.profile.assembly_ms > 1000U);
    if (!drive_rotation(&env, fixture, &next_init, &next_resp, 0x5aU) ||
        !activate_at(&env, next_init, next_resp)) {
        close_session(&env);
        return 1;
    }
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_OK);
    CHECK(right.endpoint.drain_live == 1U);
    CHECK(right.endpoint.drain_attempt == index);
    drain_at = right.endpoint.drain_not_after;
    accept_at = drain_at - 100U;
    assembly_at = accept_at + right.endpoint.profile.assembly_ms;
    CHECK(accept_at < drain_at);
    CHECK(drain_at < assembly_at);
    for (i = 0U; i < sizeof body; i++) {
        body[i] = 0x21U;
    }
    ext[0] = 17U;
    ext[1] = 1U;
    ext[2] = 2U;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_DATA;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_FRAG | DMP_OPT_EXT);
    spec.fields.seq = 8U;
    spec.fields.fragment.index = 0U;
    spec.fields.fragment.chunk_size = 16U;
    spec.fields.fragment.total_size = 32U;
    spec.extensions = span(ext, sizeof ext);
    spec.payload = span(body, sizeof body);
    env.now = accept_at;
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), accept_at);
    CHECK(status == DMP_INCOMPLETE);
    CHECK(right.app.assembled == 0);
    CHECK(right.app.accepts == 0);
    note_provider("drain-overlap", &port, env.provider);
    CHECK(dmp_endpoint_poll(&right.endpoint, drain_at) == DMP_OK);
    draining = &right.endpoint.identity.slots[right.endpoint.drain_context.slot];
    CHECK(right.endpoint.drain_live == 1U);
    CHECK(draining->state == DMP_IDENTITY_SLOT_DRAINING);
    CHECK(draining->retained != 0U);
    CHECK(dmp_endpoint_poll(&right.endpoint, assembly_at) == DMP_OK);
    CHECK(right.endpoint.drain_live == 0U);
    CHECK(draining->state == DMP_IDENTITY_SLOT_UNUSED);
    if (!drive_rotation(&env, fixture, &later_init, &later_resp, 0xa5U) ||
        !activate_at(&env, later_init, later_resp)) {
        close_session(&env);
        return 1;
    }
    env.now = assembly_at;
    CHECK(dmp_endpoint_rotate(&right.endpoint, later_resp, assembly_at) == DMP_OK);
    CHECK(right.endpoint.drain_live == 1U);
    close_session(&env);
    return 0;
}

static int drive_nn_save(session *env, uint32_t *index, uint8_t *saved, size_t cap, size_t *saved_n)
{
    const uint8_t *cached;
    size_t length = 0U;
    uint64_t boot;

    if (dmp_hs_schedule(env->initiator, index) != DMP_HS_OK) {
        return 0;
    }
    boot = dmp_hs_boot_epoch(env->initiator, *index);
    if (boot == 0U) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->initiator, *index, &length);
    if (cached == NULL || length == 0U || length > cap) {
        return 0;
    }
    memcpy(saved, cached, length);
    *saved_n = length;
    if (!drive_flight(env->responder, saved, length, ID_INIT, ID_RESP, 1U, boot, DMP_HS_CANDIDATE)) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->responder, 0U, &length);
    return cached != NULL &&
           drive_flight(env->initiator, cached, length, ID_RESP, ID_INIT, 2U, boot, DMP_HS_CANDIDATE);
}

static int reopen_hs(session *env, const noise_fixture_probe_fixture_t *fixture, uint32_t init_cid,
                     uint32_t resp_cid)
{
    dmp_hs_config init_config;
    dmp_hs_config resp_config;
    dmp_hs_ports init_ports;
    dmp_hs_ports resp_ports;

    dmp_hs_cleanup(env->initiator);
    dmp_hs_cleanup(env->responder);
    fill_hs(&init_config, fixture, 1);
    fill_hs(&resp_config, fixture, 0);
    init_config.next_rx_cid = init_cid;
    resp_config.next_rx_cid = resp_cid;
    memset(&init_ports, 0, sizeof init_ports);
    memset(&resp_ports, 0, sizeof resp_ports);
    init_ports.now_ms = now_of;
    init_ports.entropy = entropy_of;
    init_ports.commit_pin = commit_of;
    init_ports.ctx = &env->init_box;
    resp_ports.now_ms = now_of;
    resp_ports.entropy = entropy_of;
    resp_ports.commit_pin = commit_of;
    resp_ports.ctx = &env->resp_box;
    if (dmp_hs_init(env->initiator, env->provider, &init_config, &init_ports) != DMP_HS_OK ||
        dmp_hs_init(env->responder, env->provider, &resp_config, &resp_ports) != DMP_HS_OK ||
        dmp_hs_begin_episode(env->initiator) != DMP_HS_OK) {
        return 0;
    }
    return 1;
}

static int test_context(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    dmp_frame_spec spec;
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    uint32_t index = 0U;
    uint32_t fresh = 0U;
    uint32_t old_cid = 0U;
    uint32_t init_cid = 0U;
    uint64_t old_epoch_i = 0U;
    uint64_t old_epoch_r = 0U;
    uint64_t new_epoch_i = 0U;
    uint64_t new_epoch_r = 0U;
    uint64_t boot = 0U;
    uint8_t bootstrap[512];
    uint8_t replay_eph[32];
    uint8_t payload[2] = {0x41, 0x42};
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    uint8_t fresh_wrapped[FRAME_CAP];
    size_t boot_n = 0U;
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    size_t fresh_n = 0U;
    dmp_time_ms now = 20000U;
    dmp_status status;

    memset(&env, 0, sizeof env);
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn_save(&env, &index, bootstrap, sizeof bootstrap, &boot_n) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_hs_epochs(env.initiator, index, &old_epoch_i, &old_epoch_r) == 1);
    old_cid = dmp_hs_rx_cid(env.responder, 0U);
    init_cid = dmp_hs_rx_cid(env.initiator, index);
    boot = dmp_hs_boot_epoch(env.initiator, index);
    CHECK(old_cid != 0U);
    CHECK(boot != 0U);
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_TELEM;
    spec.fields.options = (uint8_t)DMP_OPT_SEQ;
    spec.fields.seq = 4U;
    spec.payload = span(payload, sizeof payload);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.telems == 1);
    note_provider("active-pair", &port, env.provider);
    CHECK(dmp_hs_cancel(env.initiator, index) == DMP_HS_OK);
    CHECK(dmp_hs_cancel(env.responder, 0U) == DMP_HS_OK);
    CHECK(dmp_hs_secrets_wiped(env.initiator, index) == 1);
    CHECK(dmp_hs_secrets_wiped(env.responder, 0U) == 1);
    CHECK(dmp_hs_send_application(env.initiator, index) != DMP_HS_OK);
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.telems == 1);
    if (!reopen_hs(&env, fixture, init_cid, old_cid)) {
        close_session(&env);
        return 1;
    }
    memcpy(replay_eph, fixture->resp_ephemeral.data, sizeof replay_eph);
    replay_eph[8] ^= 0x3cU;
    script_add(&env.resp_script, replay_eph, sizeof replay_eph);
    memset(&ingress, 0, sizeof ingress);
    memset(&completion, 0, sizeof completion);
    ingress.payload = bootstrap;
    ingress.payload_len = boot_n;
    ingress.origin_id = ID_INIT;
    ingress.destination_id = ID_RESP;
    ingress.namespace_id = LOCAL_NS;
    ingress.context_epoch = boot;
    ingress.seq = 1U;
    {
        dmp_hs_status offered = dmp_hs_offer(env.responder, &ingress, &completion);
        if (offered == DMP_HS_AWAITING) {
            offered = dmp_hs_accept(env.responder, &completion);
        }
        (void)offered;
    }
    CHECK(dmp_hs_send_application(env.initiator, index) != DMP_HS_OK);
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.telems == 1);
    memcpy(env.rot_id, fixture->attempt_id.data, 16U);
    env.rot_id[0] ^= 0x11U;
    memcpy(env.rot_init_eph, fixture->init_ephemeral.data, 32U);
    memcpy(env.rot_resp_eph, fixture->resp_ephemeral.data, 32U);
    env.rot_init_eph[8] ^= 0x11U;
    env.rot_resp_eph[8] ^= 0x11U;
    script_add(&env.init_script, env.rot_id, sizeof env.rot_id);
    script_add(&env.init_script, env.rot_init_eph, sizeof env.rot_init_eph);
    script_add(&env.resp_script, env.rot_resp_eph, sizeof env.rot_resp_eph);
    if (!reopen_hs(&env, fixture, init_cid, old_cid) || !drive_nn(&env, &fresh) || !activate(&env, fresh)) {
        close_session(&env);
        return 1;
    }
    CHECK(dmp_hs_rx_cid(env.responder, 0U) == old_cid);
    CHECK(dmp_hs_epochs(env.initiator, fresh, &new_epoch_i, &new_epoch_r) == 1);
    CHECK(new_epoch_i != old_epoch_i);
    CHECK(new_epoch_r != old_epoch_r);
    CHECK(dmp_endpoint_bind(&left.endpoint, env.initiator, fresh) == DMP_OK);
    CHECK(dmp_endpoint_bind(&right.endpoint, env.responder, 0U) == DMP_OK);
    spec.fields.seq = 5U;
    CHECK(dmp_hs_seal_logical(env.initiator, fresh, &spec, sealed, sizeof sealed, &sealed_n) == DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, fresh_wrapped, sizeof fresh_wrapped, &fresh_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(fresh_wrapped, fresh_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.telems == 2);
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.telems == 2);
    close_session(&env);
    return 0;
}

static int test_selective_repair(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t body[256];
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    uint32_t frag_index = 0U;
    uint64_t tail_pn = 0U;
    uint64_t repair_pn = 0U;
    int tail = -1;
    int i;
    int repair;
    dmp_status status = DMP_OK;
    size_t n;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_selective(&left, 1, 32U, 16U, now) == 0);
    CHECK(boot_selective(&right, 0, 32U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    for (n = 0U; n < sizeof body; n++) {
        body[n] = (uint8_t)(0x40U + (uint8_t)n);
    }
    right.wire.now = now;
    left.wire.now = now;
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(body, sizeof body), now, &handle) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n == 8);
    for (i = 0; i < right.wire.n; i++) {
        CHECK(stream_fragment(right.wire.q[i].frame, right.wire.q[i].len, now, &frag_index, &tail_pn) ==
              1);
        if (frag_index == 7U) {
          tail = i;
        } else {
          CHECK(deliver_one(&right, &left, i, now, &status) == 0);
          CHECK(status == DMP_INCOMPLETE);
        }
    }
    CHECK(tail >= 0);
    CHECK(status == DMP_INCOMPLETE);
    CHECK(left.app.assembled == 0);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 0);
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 3U) == DMP_OK);
    CHECK(left.wire.n == 1);
    CHECK(deliver_one(&left, &right, 0, now + 3U, &status) == 0);
    CHECK(status == DMP_OK);
    repair = right.wire.n;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 3U) == DMP_OK);
    CHECK(right.wire.n == repair + 1);
    CHECK(stream_fragment(right.wire.q[repair].frame, right.wire.q[repair].len,
                          now + 3U, &frag_index, &repair_pn) == 1);
    CHECK(frag_index == 7U);
    CHECK(repair_pn != tail_pn);
    CHECK(right.wire.q[repair].len != right.wire.q[tail].len ||
          memcmp(right.wire.q[repair].frame, right.wire.q[tail].frame,
                 right.wire.q[tail].len) != 0);
    CHECK(deliver_one(&right, &left, repair, now + 3U, &status) == 0);
    CHECK(status == DMP_OK);
    CHECK(left.app.assembled == 1);
    CHECK(left.app.body_n == sizeof body);
    CHECK(memcmp(left.app.body, body, sizeof body) == 0);
    CHECK(deliver_one(&right, &left, repair, now + 3U, &status) == 0);
    CHECK(left.app.assembled == 1);
    close_session(&env);
    return 0;
}

/* P23's versioned process seam joins this real C endpoint and its real SEC-1
 * state machine to the independent Python peer. The process protocol carries
 * only bounded opaque binding bytes; it does not implement DMP behavior. */
enum {
  P23_PROTOCOL_VERSION = 1,
  P23_OP_INIT = 1,
  P23_OP_RECEIVE = 2,
  P23_OP_SUBMIT_REQ = 3,
  P23_OP_SUBMIT_DATA = 4,
  P23_OP_COMPLETE = 5,
  P23_OP_POLL = 6,
  P23_OP_COMPLETE_SAMPLE = 7,
  P23_OP_SUBMIT_TELEM = 8,
  P23_OP_SUBMIT_FRESH_REQ = 9,
  P23_OP_SUBMIT_FRESH_DATA = 10,
  P23_OP_COMPLETE_TX = 11,
  P23_OP_REJECT_NEXT_TX = 12,
  P23_MAX_INPUT = 65536,
  P23_MAX_RESPONSE = 32768,
  P23_CONTEXT_TAG = 0x0b,
  P23_ORIGIN_TAG = 0x0f
};

typedef struct p23_batch {
  uint8_t bytes[QUEUE][FRAME_CAP];
  size_t lengths[QUEUE];
  size_t count;
} p23_batch;

static session p23_env;
static port_ctx p23_port;
static int p23_initialized;
static int p23_bound;
static int p23_sample_producer;
static dmp_status p23_endpoint_status;
static dmp_status p23_rx_status;
static uint8_t p23_test_grant_entropy[7][16];
static uint8_t p23_rotation_attempt[16];
static uint8_t p23_rotation_ephemeral[32];
static uint32_t p23_active_attempt;
static uint32_t p23_candidate_attempt;
static int p23_candidate_live;
static int p23_rotation_used;

static uint32_t p23_read_u32(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
         ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

static uint64_t p23_read_u64(const uint8_t *bytes) {
  uint64_t value = 0U;
  size_t index;
  for (index = 0U; index < 8U; index++) {
    value |= (uint64_t)bytes[index] << (8U * index);
  }
  return value;
}

static void p23_write_u16(uint8_t *bytes, uint16_t value) {
  bytes[0] = (uint8_t)value;
  bytes[1] = (uint8_t)(value >> 8U);
}

static void p23_write_u32(uint8_t *bytes, uint32_t value) {
  bytes[0] = (uint8_t)value;
  bytes[1] = (uint8_t)(value >> 8U);
  bytes[2] = (uint8_t)(value >> 16U);
  bytes[3] = (uint8_t)(value >> 24U);
}

static void p23_write_u64(uint8_t *bytes, uint64_t value) {
  size_t index;
  for (index = 0U; index < 8U; index++) {
    bytes[index] = (uint8_t)(value >> (8U * index));
  }
}

static int p23_add_frame(p23_batch *batch, const uint8_t *bytes,
                         size_t length) {
  if (batch == NULL || bytes == NULL || length == 0U || length > FRAME_CAP ||
      batch->count >= QUEUE) {
    return 0;
  }
  memcpy(batch->bytes[batch->count], bytes, length);
  batch->lengths[batch->count] = length;
  batch->count++;
  return 1;
}

static int p23_drain_wire(p23_batch *batch) {
  size_t index;
  if (right.wire.n < 0 || right.wire.n > QUEUE) {
    return 0;
  }
  for (index = 0U; index < (size_t)right.wire.n; index++) {
    if (!p23_add_frame(batch, right.wire.q[index].frame,
                       right.wire.q[index].len)) {
      return 0;
    }
  }
  right.wire.n = 0;
  return 1;
}

static int p23_settle_wire(p23_batch *batch) {
  size_t settled = 0U;
  if (!p23_drain_wire(batch)) {
    return 0;
  }
  while (right.wire.pending_count > 0) {
    pending_completion pending = right.wire.pending[0];
    right.wire.pending_count--;
    if (right.wire.pending_count > 0) {
      memmove(right.wire.pending, right.wire.pending + 1,
              (size_t)right.wire.pending_count * sizeof right.wire.pending[0]);
    }
    if (pending.complete == NULL || ++settled > QUEUE ||
        batch->count > QUEUE - (size_t)right.wire.n) {
      return 0;
    }
    /* The adapter-owned copy is now also in the immutable process batch. */
    pending.complete(pending.owner, pending.token, DMP_TX_TRANSMITTED,
                     right.wire.now);
    if (!p23_drain_wire(batch)) {
      return 0;
    }
  }
  return 1;
}

static int p23_uleb(dmp_bytes input, uint32_t *value, size_t *used) {
  uint32_t result = 0U;
  size_t index;
  if (value == NULL || used == NULL || input.data == NULL || input.size == 0U) {
    return 0;
  }
  for (index = 0U; index < input.size && index < 5U; index++) {
    uint8_t byte = input.data[index];
    uint32_t part = (uint32_t)(byte & 0x7fU);
    if (index == 4U && part > 0x0fU) {
      return 0;
    }
    result |= part << (7U * (uint32_t)index);
    if ((byte & 0x80U) == 0U) {
      if (index != 0U && part == 0U) {
        return 0;
      }
      *value = result;
      *used = index + 1U;
      return 1;
    }
  }
  return 0;
}

static int p23_find_extension(const dmp_frame_view *frame, uint32_t id,
                              dmp_bytes *value) {
  size_t cursor = 0U;
  dmp_extension_view extension;
  dmp_status status;
  if (frame == NULL || value == NULL) {
    return 0;
  }
  for (;;) {
    status = dmp_extension_next(frame->extensions, &cursor, &extension);
    if (status == DMP_INCOMPLETE) {
      return 0;
    }
    if (status != DMP_OK) {
      return 0;
    }
    if ((extension.tag >> 2U) == id) {
      *value = extension.value;
      return 1;
    }
  }
}

static int p23_context(const dmp_frame_view *frame, uint32_t *namespace_id,
                       uint64_t *epoch) {
  dmp_bytes value;
  size_t used = 0U;
  size_t index;
  uint32_t parsed_namespace = 0U;
  uint64_t parsed_epoch = 0U;
  if (!p23_find_extension(frame, 2U, &value) ||
      !p23_uleb(value, &parsed_namespace, &used) || value.size != used + 8U) {
    return 0;
  }
  for (index = 0U; index < 8U; index++) {
    parsed_epoch |= (uint64_t)value.data[used + index] << (8U * index);
  }
  *namespace_id = parsed_namespace;
  *epoch = parsed_epoch;
  return 1;
}

static int p23_origin(const dmp_frame_view *frame, uint32_t *origin) {
  dmp_bytes value;
  size_t used = 0U;
  if (frame->fields.route.mode != 0U) {
    *origin = frame->fields.route.source;
    return 1;
  }
  if (!p23_find_extension(frame, 3U, &value)) {
    *origin = ID_INIT;
    return 1;
  }
  return p23_uleb(value, origin, &used) && used == value.size;
}

static int p23_crc_valid(const dmp_frame_view *frame) {
  uint32_t actual = 0U;
  uint32_t received;
  if ((frame->fields.options & DMP_OPT_INTEGRITY) == 0U) {
    return frame->trailer.size == 0U ||
           (frame->fields.options & DMP_OPT_SECURITY) != 0U;
  }
  if (frame->trailer.size != 4U || frame->frame.size < frame->trailer.size ||
      dmp_crc32c(
          span(frame->frame.data, frame->frame.size - frame->trailer.size),
          &actual) != DMP_OK) {
    return 0;
  }
  received = (uint32_t)frame->trailer.data[0] |
             ((uint32_t)frame->trailer.data[1] << 8U) |
             ((uint32_t)frame->trailer.data[2] << 16U) |
             ((uint32_t)frame->trailer.data[3] << 24U);
  return received == actual;
}

static int p23_routed_profile(void);

static int p23_set_time(uint64_t now) {
  dmp_hs_status hs_status;
  if ((uint64_t)p23_env.now > now) {
    return 0;
  }
  p23_env.now = now;
  right.wire.now = now;
  if (p23_initialized) {
    hs_status = dmp_hs_poll(p23_env.responder, NULL);
    if (hs_status != DMP_HS_OK && hs_status != DMP_HS_EXPIRED) return 0;
  }
  return 1;
}

static int p23_complete_tx(uint64_t now, uint32_t count, p23_batch *batch) {
  uint32_t completed;
  if (batch == NULL || !p23_defer_tx_completions || !p23_set_time(now) ||
      count > (uint32_t)right.wire.pending_count || !p23_drain_wire(batch)) {
    return 0;
  }
  for (completed = 0U; completed < count; completed++) {
    pending_completion pending;
    if (right.wire.pending_count <= 0) {
      return 0;
    }
    pending = right.wire.pending[0];
    right.wire.pending_count--;
    if (right.wire.pending_count > 0) {
      memmove(right.wire.pending, right.wire.pending + 1,
              (size_t)right.wire.pending_count * sizeof right.wire.pending[0]);
    }
    if (pending.complete == NULL) {
      return 0;
    }
    pending.complete(pending.owner, pending.token, DMP_TX_TRANSMITTED,
                     right.wire.now);
    if (!p23_drain_wire(batch)) {
      return 0;
    }
  }
  return 1;
}

static int p23_encode_bootstrap(const uint8_t *payload, size_t payload_size,
                                uint8_t sequence, uint64_t epoch,
                                uint32_t origin, uint8_t *wire_bytes,
                                size_t wire_capacity, size_t *wire_size) {
  uint8_t extensions[14];
  uint8_t trailer[4] = {0U, 0U, 0U, 0U};
  uint8_t core[MTU];
  dmp_frame_spec spec;
  dmp_core_limits limits;
  dmp_buffer output;
  size_t extension_size = 14U;
  size_t core_size = 0U;
  uint32_t crc = 0U;
  size_t written = 0U;

  extensions[0] = P23_CONTEXT_TAG;
  extensions[1] = 9U;
  extensions[2] = LOCAL_NS;
  p23_write_u64(&extensions[3], epoch);
  if (p23_routed_profile()) {
    extension_size = 11U;
  } else {
    extensions[11] = P23_ORIGIN_TAG;
    extensions[12] = 1U;
    extensions[13] = (uint8_t)origin;
  }

  memset(&spec, 0, sizeof spec);
  spec.fields.type = DMP_TYPE_HELLO;
  spec.fields.options = DMP_OPT_SEQ | DMP_OPT_INTEGRITY | DMP_OPT_EXT;
  if (g_p23_profile_id == P23_PROFILE_RADIO_SELECTIVE ||
      g_p23_profile_id == P23_PROFILE_RADIO_RETRY_ALL ||
      g_p23_profile_id == P23_PROFILE_MIXED ||
      g_p23_profile_id == P23_PROFILE_RADIO_XX ||
      g_p23_profile_id == P23_PROFILE_RADIO_RETRY_ALL_XX) {
    spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_ROUTE);
    spec.fields.route.mode = 1U;
    spec.fields.route.ttl = 2U;
    spec.fields.route.source = origin;
    spec.fields.route.destination = origin == ID_INIT ? ID_RESP : ID_INIT;
  }
  spec.fields.seq = sequence;
  spec.fields.integrity = 1U;
  spec.extensions = span(extensions, extension_size);
  spec.payload = span(payload, payload_size);
  spec.trailer = span(trailer, sizeof trailer);
  limits.max_frame_bytes = MTU;
  limits.max_message_bytes = MESSAGE;
  limits.max_fragments = 32U;
  output.data = core;
  output.capacity = sizeof core;
  if (dmp_core_encode(&spec, &limits, output, &core_size) != DMP_OK ||
      core_size < 4U ||
      dmp_crc32c(span(core, core_size - 4U), &crc) != DMP_OK) {
    return 0;
  }
  p23_write_u32(core + core_size - 4U, crc);
  if (!wrap_core(core, core_size, wire_bytes, wire_capacity, &written)) {
    return 0;
  }
  *wire_size = written;
  return 1;
}

static const uint8_t *p23_expected_profile_hash(uint8_t profile_id) {
  static const uint8_t radio_selective[32] = {
      0x97, 0x67, 0xb5, 0xda, 0xff, 0x88, 0x42, 0x4e, 0x64, 0x88, 0x7d,
      0xd7, 0x8a, 0x33, 0x5c, 0x4d, 0xe0, 0xf9, 0xb9, 0x39, 0x00, 0xd4,
      0x51, 0x2c, 0x1c, 0xec, 0x9c, 0x4d, 0x04, 0x1b, 0x53, 0xa9};
  static const uint8_t radio_retry_all[32] = {
      0xbc, 0x8b, 0xba, 0x7c, 0x92, 0x9c, 0x6d, 0x0f, 0xe9, 0xad, 0x39,
      0xdb, 0xe6, 0x6a, 0x66, 0x99, 0xd3, 0x42, 0x30, 0x4a, 0xe8, 0x48,
      0x5d, 0xdf, 0x5c, 0xac, 0x9e, 0x32, 0x60, 0x5b, 0x55, 0xf1};
  static const uint8_t stream_r[32] = {
      0xae, 0x40, 0x9b, 0xc0, 0xd4, 0x6c, 0xda, 0x31, 0x9f, 0x9e, 0x98,
      0x61, 0xdc, 0xc3, 0xfb, 0xc6, 0x92, 0x2d, 0x2e, 0xe6, 0xd3, 0x51,
      0x55, 0xae, 0x61, 0xc3, 0x29, 0xb7, 0x9d, 0xc4, 0x97, 0xcc};
  static const uint8_t mixed[32] = {
      0x64, 0x36, 0x3a, 0xd7, 0xc1, 0xf7, 0x50, 0x40, 0x9b, 0xad, 0x1b,
      0x03, 0x95, 0x09, 0xcf, 0xec, 0x40, 0x37, 0xa9, 0x81, 0xfa, 0x76,
      0x0b, 0xbb, 0x4d, 0xce, 0x57, 0xbb, 0x50, 0xe5, 0x54, 0x6d};
  static const uint8_t stream_r_sample20[32] = {
      0x51, 0x4d, 0xb4, 0xae, 0x41, 0xfd, 0x8b, 0x2b, 0x1f, 0x4b, 0x4b,
      0x73, 0x61, 0xcf, 0xb6, 0x3e, 0x4b, 0x04, 0xea, 0x09, 0x5f, 0x33,
      0x94, 0x8f, 0x0e, 0x17, 0xe5, 0xa1, 0x9b, 0xad, 0x9e, 0x2f};
  static const uint8_t direct_nnpsk0[32] = {
      0x29, 0xf7, 0x89, 0x5a, 0xb3, 0xf8, 0xda, 0xdf, 0xbe, 0x73, 0x31,
      0xf1, 0x98, 0x1f, 0xa3, 0x5d, 0xca, 0xd2, 0xbe, 0xc5, 0x91, 0x39,
      0x46, 0x4e, 0x29, 0xbd, 0xdc, 0x4e, 0x84, 0x1e, 0x52, 0x85};
  static const uint8_t direct_xx[32] = {
      0x07, 0x5e, 0x8e, 0xd2, 0x5f, 0x60, 0x11, 0xc7, 0xdc, 0x20, 0xc8,
      0x47, 0x89, 0xeb, 0x61, 0xdf, 0xf4, 0x78, 0x4a, 0xf8, 0x64, 0x13,
      0x41, 0x5d, 0xdb, 0xd4, 0xae, 0xde, 0x07, 0xbc, 0xfc, 0xe3};
  static const uint8_t radio_xx[32] = {
      0x8d, 0xdf, 0x22, 0x6f, 0x20, 0x5a, 0xc3, 0xe5, 0x47, 0xb5, 0x78,
      0x58, 0xd6, 0xcd, 0x68, 0xaa, 0x96, 0x0f, 0xab, 0x03, 0xf6, 0x46,
      0x2b, 0x9f, 0x27, 0xcc, 0xa8, 0x1c, 0x08, 0x22, 0xfe, 0x60};
  static const uint8_t retry_all_xx[32] = {
      0x4a, 0xec, 0xe0, 0x28, 0x3e, 0x15, 0x77, 0x43, 0x46, 0xdd, 0x2d,
      0x0d, 0x73, 0xd4, 0x5e, 0x8c, 0x49, 0x6a, 0x4e, 0x91, 0xae, 0xc2,
      0xac, 0x26, 0x93, 0xa2, 0x53, 0xe9, 0x77, 0xc7, 0x67, 0xc9};
  if (profile_id == P23_PROFILE_RADIO_SELECTIVE) {
    return radio_selective;
  }
  if (profile_id == P23_PROFILE_RADIO_RETRY_ALL) {
    return radio_retry_all;
  }
  if (profile_id == P23_PROFILE_STREAM_R) {
    return stream_r;
  }
  if (profile_id == P23_PROFILE_MIXED) {
    return mixed;
  }
  if (profile_id == P23_PROFILE_STREAM_R_SAMPLE20) {
    return stream_r_sample20;
  }
  if (profile_id == P23_PROFILE_DIRECT_XX) {
    return direct_xx;
  }
  if (profile_id == P23_PROFILE_RADIO_XX) {
    return radio_xx;
  }
  if (profile_id == P23_PROFILE_RADIO_RETRY_ALL_XX) {
    return retry_all_xx;
  }
  if (profile_id == P23_PROFILE_DIRECT_NN) {
    return direct_nnpsk0;
  }
  return NULL;
}

static uint8_t p23_profile_id_for_hash(const uint8_t *profile_hash) {
  uint8_t profile_id;
  if (profile_hash == NULL) {
    return P23_PROFILE_NONE;
  }
  for (profile_id = P23_PROFILE_STREAM_R;
       profile_id <= P23_PROFILE_DIRECT_NN; profile_id++) {
    const uint8_t *expected = p23_expected_profile_hash(profile_id);
    if (expected != NULL &&
        memcmp(profile_hash, expected, sizeof p23_profile_hash) == 0) {
      return profile_id;
    }
  }
  return P23_PROFILE_NONE;
}

static int p23_routed_profile(void) {
  return g_p23_profile_id == P23_PROFILE_RADIO_SELECTIVE ||
         g_p23_profile_id == P23_PROFILE_RADIO_RETRY_ALL ||
         g_p23_profile_id == P23_PROFILE_MIXED ||
         g_p23_profile_id == P23_PROFILE_RADIO_XX ||
         g_p23_profile_id == P23_PROFILE_RADIO_RETRY_ALL_XX;
}

static int p23_stream_profile(void) {
  return g_p23_profile_id == P23_PROFILE_STREAM_R ||
         g_p23_profile_id == P23_PROFILE_STREAM_R_SAMPLE20 ||
         g_p23_profile_id == P23_PROFILE_DIRECT_NN ||
         g_p23_profile_id == P23_PROFILE_DIRECT_XX;
}

static int p23_validate_routed_frame(const dmp_frame_view *frame,
                                     uint32_t source, uint32_t destination,
                                     uint8_t expected_ttl) {
  uint32_t namespace_id = 0U;
  uint64_t context_epoch = 0U;
  if (frame == NULL || !p23_routed_profile() ||
      (frame->fields.options & DMP_OPT_ROUTE) == 0U ||
      frame->fields.route.mode != 1U ||
      frame->fields.route.ttl != expected_ttl ||
      frame->fields.route.source != source ||
      frame->fields.route.destination != destination ||
      !p23_context(frame, &namespace_id, &context_epoch) ||
      namespace_id != LOCAL_NS || context_epoch == 0U) {
    return 0;
  }
  return 1;
}

static int p23_init(const uint8_t *profile_hash, const uint8_t *credential,
                    const uint8_t *expected_pin, uint8_t requested_mode,
                    uint8_t defer_tx_completions, p23_batch *batch) {
  const noise_fixture_probe_fixture_t *fixture;
  dmp_endpoint_grant grants[4];
  uint8_t profile_id = p23_profile_id_for_hash(profile_hash);
  int ok;
  uint8_t profile_mode = (profile_id == P23_PROFILE_DIRECT_XX ||
                          profile_id == P23_PROFILE_RADIO_XX ||
                          profile_id == P23_PROFILE_RADIO_RETRY_ALL_XX)
                             ? 2U
                             : 1U;
  if (profile_id == P23_PROFILE_NONE || credential == NULL ||
      expected_pin == NULL || batch == NULL || requested_mode != profile_mode ||
      defer_tx_completions > 1U || p23_initialized) {
    return 0;
  }
  p23_defer_tx_completions = defer_tx_completions != 0U;
  fixture = find_fixture(profile_mode == 2U ? "xx" : "nnpsk0");
  g_p23_profile_id = profile_id;
  g_p23_security_mode = profile_mode;
  g_p23_confirmation_route_ttl = p23_routed_profile() ? 2U : 0U;
  memcpy(p23_profile_hash, profile_hash, sizeof p23_profile_hash);
  memcpy(p23_expected_remote_pin, expected_pin, sizeof p23_expected_remote_pin);
  p23_pin_commits = 0U;
  g_profile_hash_override = p23_profile_hash;
  g_psk_override = profile_mode == 1U ? credential : NULL;
  p23_static_override = profile_mode == 2U ? credential : NULL;
  ok =
      fixture != NULL && make_pair(&p23_env, &p23_port, fixture, NULL, NULL, 0);
  if (ok) {
    size_t entropy_index;
    for (entropy_index = 0U;
         entropy_index < sizeof p23_test_grant_entropy / sizeof p23_test_grant_entropy[0];
         entropy_index++) {
      size_t byte_index;
      for (byte_index = 0U; byte_index < sizeof p23_test_grant_entropy[0]; byte_index++) {
        p23_test_grant_entropy[entropy_index][byte_index] =
            (uint8_t)(0x40U + entropy_index * sizeof p23_test_grant_entropy[0] + byte_index);
      }
      script_add(&p23_env.resp_script, p23_test_grant_entropy[entropy_index],
                 sizeof p23_test_grant_entropy[entropy_index]);
    }
    for (entropy_index = 0U; entropy_index < sizeof p23_rotation_attempt;
         entropy_index++) {
      p23_rotation_attempt[entropy_index] = (uint8_t)(0xa0U + entropy_index);
    }
    for (entropy_index = 0U; entropy_index < sizeof p23_rotation_ephemeral;
         entropy_index++) {
      p23_rotation_ephemeral[entropy_index] = (uint8_t)(0x60U + entropy_index);
    }
    script_add(&p23_env.resp_script, p23_rotation_attempt,
               sizeof p23_rotation_attempt);
    script_add(&p23_env.resp_script, p23_rotation_ephemeral,
               sizeof p23_rotation_ephemeral);
  }
  if (ok) {
    g_p23_copy_async_binding = p23_stream_profile();
    ok = boot_node_slots(&right, 0,
                         p23_stream_profile() ? 64U : 32U,
                         p23_stream_profile() ? 16U : 32U,
                         p23_env.now, 2U) == 0;
    g_p23_copy_async_binding = 0;
  }
  g_profile_hash_override = NULL;
  g_psk_override = NULL;
  p23_static_override = NULL;
  if (!ok) {
    close_session(&p23_env);
    return 0;
  }
  p23_initialized = 1;
  p23_bound = 0;
  p23_active_attempt = 0U;
  p23_candidate_attempt = 0U;
  p23_candidate_live = 0;
  p23_rotation_used = 0;
  p23_sample_producer = profile_id == P23_PROFILE_STREAM_R_SAMPLE20;
  if (p23_sample_producer) {
    memset(grants, 0, sizeof grants);
    grants[0].principal = ID_RESP;
    grants[0].service_id = 1U;
    grants[0].permit = DMP_ENDPOINT_PERMIT_TELEM | DMP_ENDPOINT_PERMIT_RESULT;
    grants[1].principal = ID_INIT;
    grants[1].service_id = 1U;
    grants[1].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[2].principal = ID_INIT;
    grants[2].service_id = 2U;
    grants[2].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    grants[3].principal = ID_RESP;
    grants[3].service_id = 2U;
    grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    if (dmp_endpoint_set_grants(&right.endpoint, grants, 4U) != DMP_OK) {
      close_session(&p23_env);
      p23_initialized = 0;
      return 0;
    }
  }
  p23_endpoint_status = DMP_OK;
  {
    const uint8_t sync = 0U;
    return p23_add_frame(batch, &sync, sizeof sync);
  }
}

static int p23_handshake_frame(const dmp_frame_view *frame, p23_batch *batch) {
  uint32_t origin = 0U;
  uint32_t namespace_id = 0U;
  uint64_t context_epoch = 0U;
  uint32_t attempt_index;
  uint8_t expected_flight = 0U;
  uint8_t wire_bytes[FRAME_CAP];
  size_t wire_size = 0U;
  dmp_hs_status offered;
  int completed_read = 0;

  if (frame->fields.type != DMP_TYPE_HELLO || !p23_origin(frame, &origin) ||
      origin != ID_INIT) {
    return 0;
  }
  if (p23_routed_profile() &&
      !p23_validate_routed_frame(frame, ID_INIT, ID_RESP, 0U)) {
    return 0;
  }
  if ((frame->fields.options & DMP_OPT_SECURITY) == 0U) {
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    const uint8_t *cached;
    size_t cached_size = 0U;
    if (p23_bound &&
        (g_p23_security_mode != 1U || p23_rotation_used != 0)) {
      return 0;
    }
    attempt_index = p23_candidate_live ? p23_candidate_attempt
                                       : p23_active_attempt;
    /* A post-activation Flight 1 starts a distinct candidate attempt; the
     * active attempt's next-flight counter belongs to its own transcript. */
    expected_flight = p23_candidate_live
                          ? dmp_hs_expect_flight(p23_env.responder,
                                                 attempt_index)
                          : (p23_bound
                                 ? 1U
                                 : dmp_hs_expect_flight(p23_env.responder,
                                                        attempt_index));
    if (expected_flight == 0U) {
      expected_flight = 1U;
    }
    if (frame->fields.seq != expected_flight ||
        !p23_context(frame, &namespace_id, &context_epoch) ||
        namespace_id != LOCAL_NS || !p23_crc_valid(frame)) {
      return 0;
    }
    memset(&ingress, 0, sizeof ingress);
    ingress.payload = frame->payload.data;
    ingress.payload_len = frame->payload.size;
    ingress.origin_id = ID_INIT;
    ingress.destination_id = ID_RESP;
    ingress.namespace_id = namespace_id;
    ingress.context_epoch = context_epoch;
    ingress.seq = frame->fields.seq;
    memset(&completion, 0, sizeof completion);
    offered = dmp_hs_offer(p23_env.responder, &ingress, &completion);
    if (offered == DMP_HS_AWAITING) {
      completed_read = 1;
      attempt_index = completion.attempt_index;
      offered = dmp_hs_accept(p23_env.responder, &completion);
      if (offered == DMP_HS_CANDIDATE) {
        p23_candidate_attempt = attempt_index;
        p23_candidate_live = 1;
      }
    }
    if (g_p23_security_mode == 2U && completed_read &&
        offered == DMP_HS_CANDIDATE &&
        dmp_hs_view_of(p23_env.responder, completion.attempt_index) ==
            DMP_HS_VIEW_AWAITING_VERIFICATION) {
      dmp_hs_approval approval;
      memset(&approval, 0, sizeof approval);
      approval.generation = completion.generation;
      approval.initiator_id = ID_INIT;
      approval.responder_id = ID_RESP;
      approval.accept = 1;
      if (!dmp_hs_copy_attempt_id(p23_env.responder,
                                  completion.attempt_index,
                                  approval.attempt_id) ||
          !dmp_hs_copy_hash(p23_env.responder, completion.attempt_index,
                            approval.hash) ||
          dmp_hs_approve(p23_env.responder, completion.attempt_index,
                         &approval) != DMP_HS_COMMITTED) {
        return 0;
      }
      /* The expected XX peer pin was supplied through the test-only OOB
       * approval input and is checked by commit_of before persistence.
       * Flight 3 is Noise's final cleartext flight; wait for protected FINISH. */
      return 1;
    }
    if (offered != DMP_HS_CANDIDATE) {
      if (!(g_p23_security_mode == 2U && completed_read &&
            offered == DMP_HS_OK &&
            dmp_hs_expect_flight(p23_env.responder, attempt_index) == 3U)) {
        return 0;
      }
    }
    cached = dmp_hs_cached_flight(p23_env.responder, attempt_index,
                                  &cached_size);
    if (cached == NULL || cached_size == 0U ||
        !p23_encode_bootstrap(cached, cached_size, 2U, context_epoch, ID_RESP,
                              wire_bytes, sizeof wire_bytes, &wire_size)) {
      return 0;
    }
    return p23_add_frame(batch, wire_bytes, wire_size);
  }

  {
    uint64_t initiator_epoch = 0U;
    uint64_t responder_epoch = 0U;
    const uint8_t *ready;
    size_t ready_size = 0U;
    dmp_hs_protected incoming;
    if (!p23_candidate_live && !p23_bound) {
      return 0;
    }
    attempt_index = p23_candidate_live ? p23_candidate_attempt
                                       : p23_active_attempt;
    if (!dmp_hs_epochs(p23_env.responder, attempt_index, &initiator_epoch,
                       &responder_epoch)) {
      (void)fprintf(stderr, "P23 protected handshake has no epochs\n");
      return 0;
    }
    memset(&incoming, 0, sizeof incoming);
    incoming.frame = frame->frame.data;
    incoming.frame_len = frame->frame.size;
    incoming.origin_id = ID_INIT;
    incoming.destination_id = ID_RESP;
    incoming.namespace_id = LOCAL_NS;
    incoming.context_epoch = initiator_epoch;
    offered = dmp_hs_offer_protected(p23_env.responder, &incoming);
    if (offered != DMP_HS_OK ||
        dmp_hs_view_of(p23_env.responder, attempt_index) !=
            DMP_HS_VIEW_ACTIVE) {
      return 0;
    }
    if (!p23_bound) {
      if (dmp_endpoint_bind(&right.endpoint, p23_env.responder,
                            attempt_index) != DMP_OK) {
        return 0;
      }
    } else if (attempt_index == p23_active_attempt) {
      /* A fresh-PN duplicate FINISH on the active attempt retransmits READY;
       * it is not an association replacement. */
    } else {
      if (g_p23_security_mode != 1U || p23_rotation_used != 0 ||
          dmp_endpoint_rotate(&right.endpoint, attempt_index,
                              right.wire.now) != DMP_OK) {
        return 0;
      }
      p23_rotation_used = 1;
    }
    p23_active_attempt = attempt_index;
    p23_candidate_live = 0;
    p23_bound = 1;
    ready = dmp_hs_protected_frame(p23_env.responder, attempt_index,
                                   &ready_size);
    if (ready == NULL || ready_size == 0U ||
        !wrap_core(ready, ready_size, wire_bytes, sizeof wire_bytes,
                   &wire_size)) {
      return 0;
    }
    return p23_add_frame(batch, wire_bytes, wire_size);
  }
}

static int p23_receive(const uint8_t *input, size_t input_size, uint64_t now,
                       p23_batch *batch) {
  uint8_t framed[FRAME_CAP + 1U];
  uint8_t core[MTU];
  size_t core_size = 0U;
  dmp_frame_view frame;
  dmp_core_limits limits;
  dmp_parse_result parsed;
  if (!p23_initialized || input == NULL || input_size == 0U ||
      input_size > FRAME_CAP) {
    return 0;
  }
  if (!p23_set_time(now)) {
    return 0;
  }
  if (input_size == 1U && input[0] == 0U) {
    p23_endpoint_status =
        dmp_endpoint_rx(&right.endpoint, span(input, input_size), now);
    p23_rx_status = p23_endpoint_status;
    return p23_endpoint_status == DMP_OK ||
           p23_endpoint_status == DMP_INCOMPLETE;
  }
  framed[0] = 0U;
  memcpy(framed + 1U, input, input_size);
  if (!unwrap_core(framed, input_size + 1U, core, sizeof core, &core_size,
                   now)) {
    return 0;
  }
  limits.max_frame_bytes = MTU;
  limits.max_message_bytes = MESSAGE;
  limits.max_fragments = 32U;
  memset(&frame, 0, sizeof frame);
  parsed = dmp_core_parse(span(core, core_size), &limits, &frame);
  if (parsed.status != DMP_OK) {
    return 0;
  }
  if (p23_routed_profile() &&
      !p23_validate_routed_frame(&frame, ID_INIT, ID_RESP, 0U)) {
    return 0;
  }
  if (frame.fields.type == DMP_TYPE_HELLO) {
    if (!p23_crc_valid(&frame) &&
        (frame.fields.options & DMP_OPT_SECURITY) == 0U) {
      return 0;
    }
    return p23_handshake_frame(&frame, batch);
  }
  if (!p23_bound) {
    return 0;
  }
  p23_rx_status =
      dmp_endpoint_rx(&right.endpoint, span(input, input_size), now);
  p23_endpoint_status = p23_rx_status;
  if (p23_rx_status != DMP_OK && p23_rx_status != DMP_INCOMPLETE &&
      p23_rx_status != DMP_DUPLICATE) {
    return 0;
  }
  p23_endpoint_status = dmp_endpoint_poll(&right.endpoint, now);
  return p23_endpoint_status == DMP_OK && p23_drain_wire(batch);
}

static int p23_submit_req(uint32_t service_id, const uint8_t *payload,
                          size_t payload_size, uint64_t now) {
  dmp_reliability_handle handle;
  dmp_status status;
  if (!p23_set_time(now)) return 0;
  status = dmp_endpoint_submit_req(&right.endpoint, service_id,
                                   span(payload, payload_size), now, &handle);
  if (status != DMP_OK) {
    p23_endpoint_status = status;
    return 0;
  }
  p23_endpoint_status = dmp_endpoint_poll(&right.endpoint, now);
  return p23_endpoint_status == DMP_OK;
}

static int p23_submit_fresh_req(uint32_t service_id, const uint8_t *payload,
                                size_t payload_size, const uint8_t *token,
                                uint64_t now) {
  dmp_reliability_handle handle;
  dmp_status status;
  if (!p23_set_time(now)) return 0;
  status = dmp_endpoint_submit_req_fresh(
      &right.endpoint, service_id, span(payload, payload_size),
      span(token, 16U), now, &handle);
  if (status != DMP_OK) {
    p23_endpoint_status = status;
    return 0;
  }
  p23_endpoint_status = dmp_endpoint_poll(&right.endpoint, now);
  return p23_endpoint_status == DMP_OK;
}

static int p23_submit_data(uint32_t service_id, const uint8_t *payload,
                           size_t payload_size, const uint8_t *token,
                           size_t token_size, uint64_t now) {
  dmp_reliability_handle handle;
  dmp_status status;
  if ((token_size != 0U && token_size != 16U) ||
      (token_size != 0U && token == NULL)) {
    p23_endpoint_status = DMP_INVALID_ARGUMENT;
    return 0;
  }
  if (!p23_set_time(now)) return 0;
  status = dmp_endpoint_submit_data(&right.endpoint, service_id,
                                    span(payload, payload_size),
                                    span(token, token_size), now, &handle);
  if (status != DMP_OK) {
    p23_endpoint_status = status;
    return 0;
  }
  p23_endpoint_status = dmp_endpoint_poll(&right.endpoint, now);
  return p23_endpoint_status == DMP_OK;
}

static int p23_complete(uint64_t now) {
  dmp_status status;
  if (right.app.have_pending == 0 || right.app.req_n == 0U) {
    p23_endpoint_status = DMP_INVALID_ARGUMENT;
    return 0;
  }
  if (!p23_set_time(now)) return 0;
  status = dmp_endpoint_complete(&right.endpoint, right.app.pending, false, 0U,
                                 span(right.app.req, right.app.req_n), now);
  if (status != DMP_OK) {
    p23_endpoint_status = status;
    return 0;
  }
  right.app.have_pending = 0;
  p23_endpoint_status = dmp_endpoint_poll(&right.endpoint, now);
  return p23_endpoint_status == DMP_OK;
}

static int p23_complete_sample(uint64_t now, const uint8_t *payload,
                               size_t payload_size) {
  dmp_status status;
  if (!p23_sample_producer || right.app.have_pending == 0 ||
      right.app.request_service != 1U || right.app.req_n != 1U ||
      right.app.req[0] != SAMPLE1_READ || payload == NULL ||
      payload_size != SAMPLE1_READ_BYTES) {
    p23_endpoint_status = DMP_INVALID_ARGUMENT;
    return 0;
  }
  if (!p23_set_time(now)) return 0;
  status = dmp_endpoint_complete(&right.endpoint, right.app.pending, false, 0U,
                                 span(payload, payload_size), now);
  if (status != DMP_OK) {
    p23_endpoint_status = status;
    return 0;
  }
  right.app.have_pending = 0;
  p23_endpoint_status = dmp_endpoint_poll(&right.endpoint, now);
  return p23_endpoint_status == DMP_OK;
}

static int p23_submit_telem(uint32_t service_id, const uint8_t *payload,
                            size_t payload_size, uint64_t now) {
  dmp_status status;
  if (!p23_sample_producer || service_id != 1U || payload == NULL ||
      payload_size != 16U) {
    p23_endpoint_status = DMP_INVALID_ARGUMENT;
    return 0;
  }
  if (!p23_set_time(now)) return 0;
  status = dmp_endpoint_submit_telem(&right.endpoint, service_id,
                                     span(payload, payload_size), now);
  if (status != DMP_OK) {
    p23_endpoint_status = status;
    return 0;
  }
  p23_endpoint_status = dmp_endpoint_poll(&right.endpoint, now);
  return p23_endpoint_status == DMP_OK;
}

static int p23_poll(uint64_t now) {
  if (!p23_set_time(now)) return 0;
  p23_endpoint_status = dmp_endpoint_poll(&right.endpoint, now);
  return p23_endpoint_status == DMP_OK;
}

static int p23_reject_next_tx(uint64_t now, uint32_t count) {
  if (!p23_set_time(now) || count > (uint32_t)QUEUE) {
    return 0;
  }
  right.wire.reject_remaining = (int)count;
  return 1;
}

static int p23_append(uint8_t *output, size_t capacity, size_t *length,
                      const void *bytes, size_t count) {
  if (output == NULL || length == NULL || (bytes == NULL && count != 0U) ||
      *length > capacity || count > capacity - *length) {
    return 0;
  }
  if (count != 0U) {
    memcpy(output + *length, bytes, count);
  }
  *length += count;
  return 1;
}

static int p23_emit_response(uint8_t operation_status, p23_batch *batch,
                             uint8_t *response, size_t capacity,
                             size_t *response_size) {
  size_t length = 0U;
  size_t index;
  uint8_t scalar[8];
  uint8_t *body;
  size_t body_capacity;
  uint32_t payload_size;
  uint32_t effective[26];
  size_t effective_index;
  if (response == NULL || response_size == NULL || capacity < 6U ||
      (p23_defer_tx_completions ? !p23_drain_wire(batch)
                                : !p23_settle_wire(batch))) {
    return 0;
  }
  body = response + 6U;
  body_capacity = capacity - 6U;
  if (!p23_append(body, body_capacity, &length, &p23_endpoint_status, 1U)) {
    return 0;
  }
  if (!p23_append(body, body_capacity, &length, &p23_rx_status, 1U)) {
    return 0;
  }
  scalar[0] = (uint8_t)(p23_initialized &&
                        dmp_hs_association_active(p23_env.responder));
  scalar[1] = (uint8_t)p23_bound;
  scalar[2] = (uint8_t)(right.app.have_pending != 0);
  scalar[3] = right.endpoint.frag_live;
  if (!p23_append(body, body_capacity, &length, scalar, 4U)) {
    return 0;
  }
  p23_write_u32(scalar, (uint32_t)right.app.accepts);
  p23_write_u32(scalar + 4U, (uint32_t)right.app.results);
  if (!p23_append(body, body_capacity, &length, scalar, 8U)) {
    return 0;
  }
  p23_write_u32(scalar, (uint32_t)right.app.assembled);
  p23_write_u32(scalar + 4U, (uint32_t)right.app.telems);
  if (!p23_append(body, body_capacity, &length, scalar, 8U)) {
    return 0;
  }
  p23_write_u32(scalar, (uint32_t)right.app.request_service);
  if (!p23_append(body, body_capacity, &length, scalar, 4U)) {
    return 0;
  }
  payload_size = (uint32_t)right.app.req_n;
  p23_write_u32(scalar, payload_size);
  if (!p23_append(body, body_capacity, &length, scalar, 4U) ||
      !p23_append(body, body_capacity, &length, right.app.req, payload_size)) {
    return 0;
  }
  payload_size = (uint32_t)right.app.result_n;
  p23_write_u32(scalar, payload_size);
  if (!p23_append(body, body_capacity, &length, scalar, 4U) ||
      !p23_append(body, body_capacity, &length, right.app.result,
                  payload_size)) {
    return 0;
  }
  payload_size = (uint32_t)right.app.body_n;
  p23_write_u32(scalar, payload_size);
  if (!p23_append(body, body_capacity, &length, scalar, 4U) ||
      !p23_append(body, body_capacity, &length, right.app.body, payload_size)) {
    return 0;
  }
  p23_write_u16(scalar, (uint16_t)batch->count);
  if (!p23_append(body, body_capacity, &length, scalar, 2U)) {
    return 0;
  }
  for (index = 0U; index < batch->count; index++) {
    p23_write_u32(scalar, (uint32_t)batch->lengths[index]);
    if (!p23_append(body, body_capacity, &length, scalar, 4U) ||
        !p23_append(body, body_capacity, &length, batch->bytes[index],
                    batch->lengths[index])) {
      return 0;
    }
  }
  effective[0] = p23_effective_config.peers;
  effective[1] = p23_effective_config.operations_per_service;
  effective[2] = p23_effective_config.assemblies_per_peer;
  effective[3] = p23_effective_config.assembly_tombstones_per_peer;
  effective[4] = p23_effective_config.sender_slots;
  effective[5] = p23_effective_config.result_slots;
  effective[6] = p23_effective_config.history_slots;
  effective[7] = p23_effective_config.correlation_slots;
  effective[8] = p23_effective_config.adapter_slots;
  effective[9] = p23_effective_config.application_queue_slots;
  effective[10] = p23_effective_config.control_slots;
  effective[11] = p23_effective_config.message_bytes;
  effective[12] = p23_effective_config.fragments;
  effective[13] = p23_effective_config.chunk_bytes;
  effective[14] = p23_effective_config.encoded_mtu;
  effective[15] = p23_effective_config.forward_mtu;
  effective[16] = p23_effective_config.return_mtu;
  effective[17] = p23_effective_config.freshness_required_mask;
  effective[18] = (uint32_t)p23_effective_config.recovery[0];
  effective[19] = (uint32_t)p23_effective_config.recovery[1];
  effective[20] = p23_effective_config.max_probes;
  effective[21] = p23_effective_config.max_status;
  effective[22] = p23_effective_config.response_timeout_ms;
  effective[23] = p23_effective_config.send_horizon_ms;
  effective[24] = p23_effective_config.burst_span_ms;
  effective[25] = p23_pin_commits;
  if (!p23_append(body, body_capacity, &length, p23_profile_hash, 32U)) {
    return 0;
  }
  for (effective_index = 0U; effective_index < 26U; effective_index++) {
    p23_write_u32(scalar, effective[effective_index]);
    if (!p23_append(body, body_capacity, &length, scalar, 4U)) {
      return 0;
    }
  }
  effective[0] = p23_effective_budget.max_pending;
  effective[1] = p23_effective_budget.max_scratch;
  effective[2] = p23_effective_budget.episode_attempts;
  effective[3] = (uint32_t)p23_effective_budget.episode_deadline_ms;
  effective[4] = p23_effective_budget.attempt_deadline_ms;
  effective[5] = p23_effective_budget.confirmation_timeout_ms;
  effective[6] = p23_effective_budget.confirmation_attempts;
  effective[7] = p23_effective_budget.failed_aead_limit;
  effective[8] = p23_effective_budget.replay_window;
  effective[9] = p23_effective_budget.association_lifetime_ms;
  for (effective_index = 0U; effective_index < 10U; effective_index++) {
    p23_write_u32(scalar, effective[effective_index]);
    if (!p23_append(body, body_capacity, &length, scalar, 4U)) {
      return 0;
    }
  }
  response[0] = P23_PROTOCOL_VERSION;
  response[1] = operation_status;
  p23_write_u32(response + 2U, (uint32_t)length);
  *response_size = length + 6U;
  return 1;
}

static int p23_dispatch(uint8_t operation, const uint8_t *input,
                        size_t input_size, p23_batch *batch) {
  uint64_t now;
  uint32_t service_id;
  uint32_t payload_size;
  int ok = 0;
  memset(batch, 0, sizeof *batch);
  p23_endpoint_status = DMP_OK;
  p23_rx_status = DMP_OK;
  if (operation == P23_OP_INIT) {
    return (input_size == 97U || input_size == 98U) &&
           input[96] >= 1U && input[96] <= 2U &&
           (input_size == 97U || input[97] <= 1U) &&
           p23_init(input, input + 32U, input + 64U, input[96],
                    input_size == 98U ? input[97] : 0U, batch);
  }
  if (!p23_initialized || input == NULL || input_size < 8U) {
    return 0;
  }
  now = p23_read_u64(input);
  if (operation == P23_OP_RECEIVE) {
    if (input_size < 12U) {
      return 0;
    }
    payload_size = p23_read_u32(input + 8U);
    return payload_size == input_size - 12U &&
           p23_receive(input + 12U, payload_size, now, batch);
  }
  if (operation == P23_OP_COMPLETE) {
    return input_size == 8U && p23_complete(now);
  }
  if (operation == P23_OP_COMPLETE_SAMPLE) {
    if (input_size < 12U) {
      return 0;
    }
    payload_size = p23_read_u32(input + 8U);
    return payload_size == input_size - 12U &&
           p23_complete_sample(now, input + 12U, payload_size) &&
           p23_drain_wire(batch);
  }
  if (operation == P23_OP_SUBMIT_TELEM) {
    if (input_size < 16U) {
      return 0;
    }
    service_id = p23_read_u32(input + 8U);
    payload_size = p23_read_u32(input + 12U);
    return payload_size == input_size - 16U &&
           p23_submit_telem(service_id, input + 16U, payload_size, now) &&
           p23_drain_wire(batch);
  }
  if (operation == P23_OP_SUBMIT_FRESH_REQ) {
    if (input_size < 32U) {
      return 0;
    }
    service_id = p23_read_u32(input + 8U);
    payload_size = p23_read_u32(input + 12U);
    return payload_size == input_size - 32U &&
           p23_submit_fresh_req(service_id, input + 32U, payload_size,
                                input + 16U, now) &&
           p23_drain_wire(batch);
  }
  if (operation == P23_OP_SUBMIT_FRESH_DATA) {
    if (input_size < 32U) {
      return 0;
    }
    service_id = p23_read_u32(input + 8U);
    payload_size = p23_read_u32(input + 12U);
    return payload_size == input_size - 32U &&
           p23_submit_data(service_id, input + 32U, payload_size, input + 16U,
                           16U, now) &&
           p23_drain_wire(batch);
  }
  if (operation == P23_OP_POLL) {
    return input_size == 8U && p23_poll(now);
  }
  if (operation == P23_OP_COMPLETE_TX) {
    return input_size == 12U &&
           p23_complete_tx(now, p23_read_u32(input + 8U), batch);
  }
  if (operation == P23_OP_REJECT_NEXT_TX) {
    return input_size == 12U &&
           p23_reject_next_tx(now, p23_read_u32(input + 8U));
  }
  if ((operation != P23_OP_SUBMIT_REQ && operation != P23_OP_SUBMIT_DATA) ||
      input_size < 16U) {
    return 0;
  }
  service_id = p23_read_u32(input + 8U);
  payload_size = p23_read_u32(input + 12U);
  if (payload_size != input_size - 16U) {
    return 0;
  }
  if (operation == P23_OP_SUBMIT_REQ) {
    ok = p23_submit_req(service_id, input + 16U, payload_size, now);
  } else {
    ok = p23_submit_data(service_id, input + 16U, payload_size, NULL, 0U, now);
  }
  if (ok) {
    ok = p23_drain_wire(batch);
  }
  return ok;
}

static int p23_read_exact(uint8_t *bytes, size_t length) {
  size_t total = 0U;
  while (total < length) {
    size_t got = fread(bytes + total, 1U, length - total, stdin);
    if (got == 0U) {
      return 0;
    }
    total += got;
  }
  return 1;
}

static int p23_driver_main(void) {
  uint8_t header[6];
  uint8_t input[P23_MAX_INPUT];
  uint8_t response[P23_MAX_RESPONSE];
#if defined(_WIN32)
  if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
      _setmode(_fileno(stdout), _O_BINARY) == -1) {
    return 5;
  }
#endif
  while (p23_read_exact(header, sizeof header)) {
    uint32_t input_size = p23_read_u32(header + 2U);
    size_t response_size = 0U;
    p23_batch batch;
    uint8_t status;
    if (header[0] != P23_PROTOCOL_VERSION || input_size > sizeof input) {
      return 2;
    }
    if (!p23_read_exact(input, input_size)) {
      return 2;
    }
    status = p23_dispatch(header[1], input, input_size, &batch) ? 0U : 1U;
    if (!p23_emit_response(status, &batch, response, sizeof response,
                           &response_size) ||
        fwrite(response, 1U, response_size, stdout) != response_size ||
        fflush(stdout) != 0) {
      return 3;
    }
  }
  if (p23_initialized) {
    close_session(&p23_env);
    p23_initialized = 0;
  }
  return ferror(stdin) ? 4 : 0;
}

int main(int argc, char **argv) {
  const char *name = argc > 1 ? argv[1] : "all";
  int failed = 0;
  if (strcmp(name, "p23-driver") == 0) {
    return p23_driver_main();
  }
  if (strcmp(name, "activation") == 0 || strcmp(name, "all") == 0) {
    failed |= test_activation();
  }
  if (strcmp(name, "alter") == 0 || strcmp(name, "all") == 0) {
    failed |= test_alter();
  }
  if (strcmp(name, "loss") == 0 || strcmp(name, "all") == 0) {
    failed |= test_loss();
  }
  if (strcmp(name, "isolate") == 0 || strcmp(name, "all") == 0) {
    failed |= test_isolate();
  }
  if (strcmp(name, "reassembly") == 0 || strcmp(name, "all") == 0) {
    failed |= test_reassembly();
  }
  if (strcmp(name, "ttl") == 0 || strcmp(name, "all") == 0) {
    failed |= test_ttl();
  }
  if (strcmp(name, "acl") == 0 || strcmp(name, "all") == 0) {
    failed |= test_acl();
  }
  if (strcmp(name, "rotation") == 0 || strcmp(name, "all") == 0) {
    failed |= test_rotation();
  }
  if (strcmp(name, "result") == 0 || strcmp(name, "all") == 0) {
    failed |= test_result_permit();
  }
  if (strcmp(name, "fragdeny") == 0 || strcmp(name, "all") == 0) {
    failed |= test_frag_deny();
  }
  if (strcmp(name, "drain") == 0 || strcmp(name, "all") == 0) {
    failed |= test_drain_retain();
  }
  if (strcmp(name, "context") == 0 || strcmp(name, "all") == 0) {
    failed |= test_context();
  }
  if (strcmp(name, "repair") == 0 || strcmp(name, "all") == 0) {
    failed |= test_selective_repair();
  }
  if (strcmp(name, "activation") != 0 && strcmp(name, "alter") != 0 &&
      strcmp(name, "loss") != 0 && strcmp(name, "isolate") != 0 &&
      strcmp(name, "reassembly") != 0 && strcmp(name, "ttl") != 0 &&
      strcmp(name, "acl") != 0 && strcmp(name, "rotation") != 0 &&
      strcmp(name, "result") != 0 && strcmp(name, "fragdeny") != 0 &&
      strcmp(name, "drain") != 0 && strcmp(name, "context") != 0 &&
      strcmp(name, "repair") != 0 && strcmp(name, "all") != 0) {
    (void)fprintf(stderr, "unknown test %s\n", name);
    return 2;
  }
  return failed == 0 ? 0 : 1;
}
