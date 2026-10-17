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
#include "sample1_endpoint.h"

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
    MAX_MESSAGE = 4096,
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
    FRAG_CHUNK = 16,
    ASSEMBLY_STORAGE_SLOTS = 2
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
typedef struct sample_tracker sample_tracker;

typedef struct {
  int used;
  uint8_t frame[FRAME_CAP];
  size_t len;
} held;

typedef struct {
  dmp_tx_complete_fn complete;
  void *owner;
  dmp_tx_token token;
  dmp_tx_outcome outcome;
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
  dmp_tx_outcome completion_outcome;
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
    uint8_t peer_pending_live[DMP_PROFILE_MAX_PEERS];
    dmp_reliability_handle peer_pending[DMP_PROFILE_MAX_PEERS];
    int accepts;
    int results;
    uint32_t last_status;
    dmp_reliability_handle result_request;
    unsigned sample_update_attempts;
    int sample_update_status;
    int drop_result_receipt;
    int telems;
    dmp_identity_handle last_notice_association;
    int assembled;
    int unknowns;
    int local_unsent;
    int data_unknowns;
    int data_local_unsent;
    dmp_sample1_owner_result sample_owner_result;
    uint32_t data_unknown_service;
    dmp_peer_handle last_unknown_peer;
    dmp_peer_handle last_peer;
    uint8_t req[MAX_MESSAGE];
    size_t req_n;
    size_t request_service;
    uint8_t result[MAX_MESSAGE];
    size_t result_n;
    uint8_t telem[MAX_MESSAGE];
    size_t telem_n;
    uint8_t body[MAX_MESSAGE];
    size_t body_n;
    dmp_message_key sample1_expected_request;
    uint8_t sample1_expected_request_opcode;
    uint8_t sample1_expected_request_live;
} app;

struct sample_tracker {
    int synchronized;
    int discarded;
    int rollbacks;
    int violations;
    uint64_t epoch;
    uint32_t index;
    uint32_t value;
};

struct node {
    dmp_endpoint endpoint;
    dmp_endpoint_peer_state peer_states[DMP_PROFILE_MAX_PEERS];
    dmp_transport transport;
    wire wire;
    app app;
    sample_tracker *sample_state;
    dmp_sample1_endpoint *sample_endpoint;
    dmp_reliability_handle sample_designated;
    dmp_identity_slot ids[8];
    dmp_reliability_sender_slot senders[SENDERS];
    uint8_t sender_payload[SENDERS * MAX_MESSAGE];
    dmp_reliability_result_slot results[RESULTS];
    uint8_t result_payload[RESULTS * MAX_MESSAGE];
    dmp_reliability_history_slot history[HISTORY];
    dmp_reliability_correlation_slot correlations[CORRELATIONS];
    uint8_t history_metadata[HISTORY * DMP_RELIABILITY_METADATA_BYTES];
    uint8_t correlation_metadata[CORRELATIONS * DMP_RELIABILITY_METADATA_BYTES];
    dmp_reliability_adapter_slot adapters[ADAPTERS];
    uint8_t frames[ADAPTERS * FRAME_CAP];
    uint8_t receive_payload[MAX_MESSAGE];
    dmp_reassembly_slot assemblies[ASSEMBLY_STORAGE_SLOTS * DMP_PROFILE_MAX_PEERS];
    dmp_reassembly_tombstone tombstones[TOMBSTONES * DMP_PROFILE_MAX_PEERS];
    dmp_endpoint_freshness_slot freshness[8];
    uint8_t assembly_payload[ASSEMBLY_STORAGE_SLOTS * DMP_PROFILE_MAX_PEERS * MAX_MESSAGE];
    uint8_t assembly_metadata[ASSEMBLY_STORAGE_SLOTS * DMP_PROFILE_MAX_PEERS * DMP_REASSEMBLY_METADATA_BYTES];
    uint8_t fragment_message[MAX_MESSAGE * DMP_PROFILE_MAX_PEERS];
    uint8_t fragment_frame[MTU];
    uint8_t telemetry_payload[MAX_MESSAGE * DMP_PROFILE_MAX_PEERS];
    uint8_t telemetry_next[MAX_MESSAGE * DMP_PROFILE_MAX_PEERS];
    uint8_t telemetry_frame[MTU];
    uint8_t stream_tx[STREAM_CAP];
    uint8_t stream_rx[STREAM_CAP * DMP_PROFILE_MAX_PEERS];
};

static int sample_accept_read_result(sample_tracker *state, const app *result,
                                     dmp_reliability_handle designated);

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
    uint32_t responder_index;
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

typedef struct {
    uint64_t durable_epoch;
    uint64_t published_epoch;
    uint32_t published_index;
    uint32_t published_value;
    uint8_t locked;
} sample1_store;

typedef void (*tune_fn)(dmp_hs_config *initiator, dmp_hs_config *responder);

static node left;
static node right;
static const uint8_t *g_profile_hash_override;
static const uint8_t *g_psk_override;
static int g_p23_copy_async_binding;
static int g_endpoint_test_async_borrow;
static uint8_t g_p23_profile_id;
static int p23_uses_packet_endpoint(void)
{
  return g_p23_profile_id == P23_PROFILE_RADIO_SELECTIVE ||
         g_p23_profile_id == P23_PROFILE_RADIO_RETRY_ALL ||
         g_p23_profile_id == P23_PROFILE_MIXED ||
         g_p23_profile_id == P23_PROFILE_RADIO_XX ||
         g_p23_profile_id == P23_PROFILE_RADIO_RETRY_ALL_XX;
}

static int p23_defer_tx_completions;
static uint8_t g_p23_confirmation_route_ttl;
static uint8_t p23_profile_hash[32];
static uint8_t p23_expected_remote_pin[32];
static uint8_t g_p23_security_mode;
static const uint8_t *p23_static_override;
static uint32_t p23_pin_commits;
static dmp_config p23_effective_config;
static dmp_hs_budget p23_effective_budget;
static int g_validate_sample1_requests;
static int g_validate_sample1_results;
static uint32_t g_endpoint_test_assembly_quota_override;
static uint32_t g_sample1_validator_calls;
static uint32_t g_sample1_forced_status;
static uint32_t g_endpoint_test_message_bytes;
static uint32_t g_endpoint_test_encoded_mtu;
static uint32_t g_endpoint_test_sender_id;
static uint32_t g_endpoint_test_peer_count;
static uint32_t g_endpoint_test_scratch_slots;
static uint32_t g_endpoint_test_operations_per_service;
static uint32_t g_endpoint_test_queue_ms;
static uint32_t g_endpoint_test_result_slots;
static uint32_t g_endpoint_test_handshake_pending;
static uint32_t g_endpoint_test_next_rx_cid;
static struct dmp_hs_admission *g_endpoint_test_admission;
static void *g_endpoint_test_admission_storage;
static int g_endpoint_test_responder_admission_only;
static int g_endpoint_test_initiator_admission_only;
static int g_endpoint_test_unique_entropy;
static uint8_t g_endpoint_test_alt_attempt[16];
static uint8_t g_endpoint_test_alt_init_ephemeral[32];
static uint8_t g_endpoint_test_alt_resp_ephemeral[32];

static const uint8_t DIRECT_SHA[DMP_PROFILE_SHA256_BYTES] = {
    0x29, 0xcb, 0x7b, 0x91, 0xee, 0x0c, 0x26, 0x9b, 0xc1, 0x4a, 0xc4, 0x3e, 0x3a, 0x7c, 0x8f, 0xd8,
    0xbd, 0xcf, 0xe1, 0x1e, 0x9e, 0x05, 0x2e, 0x8b, 0xd9, 0xe6, 0xaf, 0x00, 0xfb, 0x89, 0xc3, 0xbf};

static const uint8_t READ_RSP[SAMPLE1_READ_BYTES] = {
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2c, 0x01, 0x00,
    0x00};

static uint32_t validate_sample1_request(void *user, const dmp_frame_view *frame,
                                         uint32_t service_id, dmp_bytes payload)
{
    (void)user;
    g_sample1_validator_calls++;
    if (service_id != 1U) {
        return 0U;
    }
    if (g_sample1_forced_status != 0U) {
        return g_sample1_forced_status;
    }
    if ((frame->fields.options & DMP_OPT_PAYLOAD_DESC) != 0U) {
        return 2U;
    }
    if (payload.size != 1U || payload.data == NULL ||
        (payload.data[0] != SAMPLE1_READ && payload.data[0] != SAMPLE1_STATUS)) {
        return 7U;
    }
    return 0U;
}

static int message_key_equal(dmp_message_key left, dmp_message_key right)
{
    return left.origin.namespace_id == right.origin.namespace_id &&
           left.origin.origin_id == right.origin.origin_id &&
           left.origin.epoch == right.origin.epoch && left.seq == right.seq;
}

static void expect_sample1_result(node *self, dmp_message_key request,
                                  uint8_t request_opcode)
{
    if (self == NULL) {
        return;
    }
    self->app.sample1_expected_request = request;
    self->app.sample1_expected_request_opcode = request_opcode;
    self->app.sample1_expected_request_live = 1U;
}

static int validate_sample1_result(void *user, const dmp_frame_view *frame,
                                   uint32_t service_id, dmp_bytes payload)
{
    node *self = user;
    dmp_message_key reply_to;
    dmp_identity_handle context;
    uint64_t epoch;
    uint32_t index;
    if (frame == NULL || frame->fields.type != DMP_TYPE_RSP || service_id != 1U ||
        payload.data == NULL || self == NULL ||
        self->app.sample1_expected_request_live == 0U ||
        self->app.sample1_expected_request_opcode == 0U ||
        self->endpoint.active_peer_slot >= self->endpoint.profile.peers) {
        return 0;
    }
    context = self->endpoint.peers[self->endpoint.active_peer_slot].context;
    if (dmp_identity_reply_to(frame, &self->endpoint.identity, context, self->wire.now,
                              &reply_to) != DMP_OK ||
        !message_key_equal(reply_to, self->app.sample1_expected_request)) {
        return 0;
    }
    if (payload.data[0] != self->app.sample1_expected_request_opcode) {
        return 0;
    }
    if (self->app.sample1_expected_request_opcode == SAMPLE1_STATUS &&
        payload.size == SAMPLE1_STATUS_BYTES && payload.data[0] == SAMPLE1_STATUS) {
        return payload.data[1] <= 1U;
    }
    if (self->app.sample1_expected_request_opcode != SAMPLE1_READ ||
        payload.size != SAMPLE1_READ_BYTES || payload.data[0] != SAMPLE1_READ) {
        return 0;
    }
    epoch = sample1_load_u64(payload.data + 1U);
    index = sample1_load_u32(payload.data + 9U);
    return epoch != 0U && index != 0U;
}

static dmp_bytes span(const void *data, size_t size)
{
    dmp_bytes bytes;
    bytes.data = (const uint8_t *)data;
    bytes.size = size;
    return bytes;
}

static bool sample1_store_try_enter(void *user)
{
    sample1_store *store = user;
    if (store == NULL || store->locked != 0U) {
        return false;
    }
    store->locked = 1U;
    return true;
}

static void sample1_store_leave(void *user)
{
    sample1_store *store = user;
    if (store != NULL) {
        store->locked = 0U;
    }
}

static dmp_sample1_port_result sample1_store_reserve(
    void *user, dmp_sample1_principal principal, bool *has_previous,
    uint64_t *previous_epoch, uint64_t *reserved_epoch)
{
    sample1_store *store = user;
    (void)principal;
    if (store == NULL || store->locked == 0U || has_previous == NULL ||
        previous_epoch == NULL || reserved_epoch == NULL ||
        store->durable_epoch == UINT64_MAX) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    *has_previous = store->durable_epoch != 0U;
    *previous_epoch = store->durable_epoch;
    *reserved_epoch = store->durable_epoch + 1U;
    store->durable_epoch = *reserved_epoch;
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static dmp_sample1_port_result sample1_store_publish(
    void *user, dmp_sample1_principal principal, uint64_t sample_epoch,
    uint32_t sample_index, const uint8_t payload[DMP_SAMPLE1_TELEM_BYTES])
{
    sample1_store *store = user;
    (void)principal;
    if (store == NULL || store->locked == 0U || payload == NULL ||
        sample_epoch != store->durable_epoch || sample_index == 0U) {
        return DMP_SAMPLE1_PORT_FAILED;
    }
    store->published_epoch = sample_epoch;
    store->published_index = sample_index;
    store->published_value = (uint32_t)payload[12] |
                             ((uint32_t)payload[13] << 8U) |
                             ((uint32_t)payload[14] << 16U) |
                             ((uint32_t)payload[15] << 24U);
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static void on_notice(void *user, const dmp_endpoint_notice *notice) {
  node *self = user;
  if (self == NULL || notice == NULL) {
    return;
  }
  self->app.last_notice_association = notice->association;
  if (notice->event == DMP_ENDPOINT_REQUEST) {
    self->app.accepts++;
    self->app.last_peer = notice->peer;
    if (notice->peer.slot < DMP_PROFILE_MAX_PEERS) {
      self->app.peer_pending_live[notice->peer.slot] = 1U;
      self->app.peer_pending[notice->peer.slot] = notice->request;
    }
    self->app.request_service = notice->service_id;
    self->app.req_n = notice->payload.size <= sizeof self->app.req
                          ? notice->payload.size
                          : 0U;
    if (self->app.req_n != 0U && notice->payload.data != NULL) {
      memcpy(self->app.req, notice->payload.data, self->app.req_n);
    }
    self->app.pending = notice->request;
    self->app.have_pending = 1;
    if (self->sample_endpoint != NULL) {
      self->app.sample_owner_result = dmp_sample1_endpoint_handle_notice(
          self->sample_endpoint, notice, self->wire.now);
    }
    return;
  }
  if (notice->event == DMP_ENDPOINT_RESULT) {
    self->app.results++;
    self->app.last_status = notice->wire_status;
    self->app.result_request = notice->request;
    self->app.result_n = notice->payload.size <= sizeof self->app.result
                             ? notice->payload.size
                             : 0U;
    if (self->app.result_n != 0U && notice->payload.data != NULL) {
      memcpy(self->app.result, notice->payload.data, self->app.result_n);
    }
    if (self->sample_state != NULL) {
      self->app.sample_update_attempts++;
      self->app.sample_update_status =
          sample_accept_read_result(self->sample_state, &self->app,
                                    self->sample_designated);
    }
    if (self->app.drop_result_receipt) {
      self->app.drop_result_receipt = 0;
      self->wire.drop_remaining = 1;
    }
    return;
  }
  if (notice->event == DMP_ENDPOINT_TELEMETRY) {
    self->app.telems++;
    self->app.last_peer = notice->peer;
    self->app.telem_n = notice->payload.size <= sizeof self->app.telem
                            ? notice->payload.size
                            : 0U;
    if (self->app.telem_n != 0U && notice->payload.data != NULL) {
      memcpy(self->app.telem, notice->payload.data, self->app.telem_n);
    }
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
    self->app.last_unknown_peer = notice->peer;
    return;
  }
  if (notice->event == DMP_ENDPOINT_LOCAL_UNSENT) {
    self->app.local_unsent++;
    return;
  }
  if (notice->event == DMP_ENDPOINT_DATA_UNKNOWN) {
    self->app.data_unknowns++;
    self->app.data_unknown_service = notice->service_id;
    return;
  }
  if (notice->event == DMP_ENDPOINT_DATA_LOCAL_UNSENT) {
    self->app.data_local_unsent++;
  }
}

static int same_handle(dmp_reliability_handle left, dmp_reliability_handle right)
{
    return left.slot == right.slot && left.generation == right.generation;
}

static int sample_observe_telem(sample_tracker *state, dmp_bytes payload)
{
    uint64_t epoch;
    uint32_t index;
    uint32_t value;

    if (state == NULL || payload.data == NULL || payload.size != SAMPLE1_TELEM_BYTES) {
        return 1;
    }
    epoch = sample1_load_u64(payload.data);
    index = sample1_load_u32(payload.data + 8U);
    value = sample1_load_u32(payload.data + 12U);
    if (epoch == 0U || index == 0U) {
        state->violations++;
        return 0;
    }
    if (!state->synchronized) {
        state->discarded++;
        return 0;
    }
    if (epoch != state->epoch) {
        state->violations++;
    } else if (index > state->index) {
        state->index = index;
        state->value = value;
    } else if (index < state->index) {
        state->rollbacks++;
    } else if (value != state->value) {
        state->violations++;
    }
    return 0;
}

static int sample_accept_read_result(sample_tracker *state, const app *result,
                                     dmp_reliability_handle designated)
{
    uint64_t epoch;
    uint32_t index;
    uint32_t value;

    if (state == NULL || result == NULL || result->last_status != 0U ||
        result->result_n != SAMPLE1_READ_BYTES || result->result[0] != SAMPLE1_READ ||
        !same_handle(result->result_request, designated)) {
        return 1;
    }
    epoch = sample1_load_u64(result->result + 1U);
    index = sample1_load_u32(result->result + 9U);
    value = sample1_load_u32(result->result + 13U);
    if (epoch == 0U || index == 0U) {
        state->violations++;
        return 0;
    }
    if (!state->synchronized) {
        if (state->epoch == epoch && state->index != 0U) {
            if (index > state->index) {
                state->index = index;
                state->value = value;
            } else if (index == state->index && value != state->value) {
                state->violations++;
            }
        } else {
            state->epoch = epoch;
            state->index = index;
            state->value = value;
        }
        state->synchronized = 1;
    } else if (epoch != state->epoch) {
        state->violations++;
    } else if (index > state->index) {
        state->index = index;
        state->value = value;
    } else if (index < state->index) {
        state->rollbacks++;
    } else if (value != state->value) {
        state->violations++;
    }
    return 0;
}

static dmp_status sample_rotate_association(node *self, uint32_t attempt_index,
                                            dmp_time_ms now)
{
    dmp_status status;

    if (self == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    status = dmp_endpoint_rotate(&self->endpoint, attempt_index, now);
    if (status == DMP_OK && self->sample_state != NULL) {
        /* The application owner serializes association replacement with
         * SAMPLE-1 state. Keep the last sample as cache, but require a new
         * designated READ before presenting it as synchronized/live. */
        self->sample_state->synchronized = 0;
        self->sample_designated.slot = UINT32_MAX;
        self->sample_designated.generation = UINT32_MAX;
    }
    return status;
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
                           link->completion_outcome, link->now);
    } else {
      pending_completion *pending = &link->pending[link->pending_count++];
      pending->complete = submission->complete;
      pending->owner = submission->owner;
      pending->token = submission->token;
      pending->outcome = link->completion_outcome;
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
                         link->completion_outcome, link->now);
  } else {
    pending_completion *pending = &link->pending[link->pending_count++];
    pending->complete = submission->complete;
    pending->owner = submission->owner;
    pending->token = submission->token;
    pending->outcome = link->completion_outcome;
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
  config->frame_tx_ms = 1U;
  config->forward_mtu = 256U;
  config->return_mtu = 256U;
  config->forward_delay_ms = 20U;
  config->return_delay_ms = 20U;
  config->record_margin_ms = 5U;
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
  config->peers = g_endpoint_test_peer_count != 0U
                       ? g_endpoint_test_peer_count
                       : 1U;
  config->operations_per_service = g_endpoint_test_operations_per_service != 0U
                                       ? g_endpoint_test_operations_per_service
                                       : 1U;
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
  config->queue_ms = g_endpoint_test_queue_ms != 0U
                         ? g_endpoint_test_queue_ms
                         : 64U;
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
  config->peers = g_endpoint_test_peer_count != 0U
                       ? g_endpoint_test_peer_count
                       : 1U;
  config->operations_per_service = g_endpoint_test_operations_per_service != 0U
                                       ? g_endpoint_test_operations_per_service
                                       : 1U;
  config->assemblies_per_peer = 1U;
  config->assembly_tombstones_per_peer = TOMBSTONES;
  config->sender_slots = SENDERS;
  config->assembly_slots = ASSEMBLIES * config->peers;
  config->assembly_tombstone_slots = TOMBSTONES * config->peers;
  config->result_slots = g_endpoint_test_result_slots != 0U
                             ? g_endpoint_test_result_slots
                             : RESULTS;
  config->history_slots = HISTORY;
  config->correlation_slots = CORRELATIONS;
  config->adapter_slots = ADAPTERS;
  config->application_queue_slots = 2U;
  config->control_slots = 2U;
  config->message_bytes = g_endpoint_test_message_bytes != 0U
                              ? g_endpoint_test_message_bytes
                              : MESSAGE;
  config->fragments = fragments;
  config->chunk_bytes = chunk;
  config->encoded_mtu = g_endpoint_test_encoded_mtu != 0U
                            ? g_endpoint_test_encoded_mtu
                            : MTU;
  config->frame_tx_ms = 1U;
  config->forward_mtu = 256U;
  config->return_mtu = 256U;
  config->forward_delay_ms = 20U;
  config->return_delay_ms = 20U;
  config->record_margin_ms = 5U;
  config->queue_ms = g_endpoint_test_queue_ms != 0U
                         ? g_endpoint_test_queue_ms
                         : 64U;
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
  config->synchronous_completion =
      !g_p23_copy_async_binding && !g_endpoint_test_async_borrow;
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
  if (g_endpoint_test_assembly_quota_override != 0U) {
    input.assemblies_per_peer = g_endpoint_test_assembly_quota_override;
    input.assembly_slots = g_endpoint_test_assembly_quota_override * input.peers;
  }
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
  storage.framing_mode = p23_uses_packet_endpoint()
                             ? DMP_ENDPOINT_FRAMING_PACKET
                             : DMP_ENDPOINT_FRAMING_STREAM_R;
  storage.peer_states = self->peer_states;
  storage.peer_state_capacity = sizeof self->peer_states / sizeof self->peer_states[0];
  storage.identity_slots = self->ids;
  storage.identity_capacity = slots;
  storage.context = identity;
  storage.transport = &self->transport;
  storage.notice = on_notice;
  storage.notice_user = self;
  storage.validate_request_user = self;
  if (g_validate_sample1_requests) {
    storage.validate_request = validate_sample1_request;
  }
  if (g_validate_sample1_results) {
    storage.validate_result = validate_sample1_result;
  }
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
  storage.assembly_capacity = ASSEMBLY_STORAGE_SLOTS * DMP_PROFILE_MAX_PEERS;
  storage.tombstones = self->tombstones;
  storage.tombstone_capacity = TOMBSTONES * DMP_PROFILE_MAX_PEERS;
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
  if (admitted.peers > 1U) {
    dmp_hs_admission_limits hs_limits;
    CHECK(g_endpoint_test_admission_storage != NULL);
    memset(&hs_limits, 0, sizeof hs_limits);
    hs_limits.max_pending = g_endpoint_test_handshake_pending != 0U
                                ? g_endpoint_test_handshake_pending
                                : 4U;
        hs_limits.max_scratch = g_endpoint_test_scratch_slots != 0U
                                    ? g_endpoint_test_scratch_slots
                                    : 2U;
    hs_limits.global_work = 100000U;
    hs_limits.ingress_work = 10000U;
    storage.handshake_admission =
        (struct dmp_hs_admission *)g_endpoint_test_admission_storage;
    storage.handshake_admission_capacity = dmp_hs_admission_size();
    storage.handshake_max_pending = hs_limits.max_pending;
    storage.handshake_max_scratch = hs_limits.max_scratch;
    storage.handshake_global_work = hs_limits.global_work;
    storage.handshake_ingress_work = hs_limits.ingress_work;
  }
  {
    dmp_status init_status = dmp_endpoint_init(&self->endpoint, &storage, now);
    if (init_status != DMP_OK) {
      (void)fprintf(stderr, "endpoint init returned %s (%d) for peers=%u\n",
                    dmp_status_name(init_status), (int)init_status,
                    (unsigned)admitted.peers);
    }
    CHECK(init_status == DMP_OK);
  }
  if (admitted.peers > 1U) {
    g_endpoint_test_admission = dmp_endpoint_handshake_admission(&self->endpoint);
    CHECK(g_endpoint_test_admission != NULL);
  }
  return admitted.peers > 1U ? 0 : install_manifest_grants(self);
}

static int boot_node(node *self, int producer, uint32_t chunk, uint32_t fragments, dmp_time_ms now)
{
    return boot_node_slots(self, producer, chunk, fragments, now, 2U);
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
    uint8_t synced[FRAME_CAP + 1U];
    size_t core_n = 0U;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_parse_result parsed;

    if (!unwrap_core(framed, n, core, sizeof core, &core_n, now)) {
        if (n >= FRAME_CAP) {
            return 0;
        }
        synced[0] = 0U;
        memcpy(synced + 1U, framed, n);
        if (!unwrap_core(synced, n + 1U, core, sizeof core, &core_n, now)) {
            return 0;
        }
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
    if (to->endpoint.profile.peers == 1U) {
        status = dmp_endpoint_rx(&to->endpoint, bytes, now);
    } else if (to->endpoint.active_peer_slot < to->endpoint.peer_count) {
        dmp_peer_handle peer =
            to->endpoint.peers[to->endpoint.active_peer_slot].handle;
        status = dmp_endpoint_rx_from(&to->endpoint, peer, bytes, now);
    } else {
        status = DMP_INVALID_ARGUMENT;
    }
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
        if (status != DMP_OK && status != DMP_INCOMPLETE && status != DMP_DUPLICATE) {
            (void)fprintf(stderr, "endpoint RX returned %d for frame %d of %d\n", (int)status,
                          i + 1, n);
        }
        CHECK(status == DMP_OK || status == DMP_INCOMPLETE || status == DMP_DUPLICATE);
    }
    from->wire.n = 0;
    return 0;
}

static int complete_pending_completions(wire *link, dmp_time_ms now)
{
    pending_completion pending[QUEUE];
    size_t count = link->pending_count;
    size_t i;
    CHECK(count <= QUEUE);
    memcpy(pending, link->pending, count * sizeof pending[0]);
    link->pending_count = 0U;
    for (i = 0U; i < count; i++) {
        CHECK(pending[i].complete != NULL);
        pending[i].complete(pending[i].owner, pending[i].token,
                            pending[i].outcome, now);
    }
    return 0;
}

static int sync_stream_node(node *self, dmp_time_ms now)
{
    self->wire.now = now;
    CHECK(dmp_endpoint_poll(&self->endpoint, now) == DMP_OK);
    CHECK(self->wire.n == 1 && self->wire.q[0].len == 1U && self->wire.q[0].frame[0] == 0U);
    CHECK(complete_pending_completions(&self->wire, now) == 0);
    self->wire.n = 0;
    self->wire.submits = 0;
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
        CHECK(complete_pending_completions(&left.wire, now) == 0);
        CHECK(complete_pending_completions(&right.wire, now) == 0);
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

static void tune_test_sender_identity(dmp_hs_config *initiator,
                                      dmp_hs_config *responder)
{
    if (initiator == NULL || responder == NULL || g_endpoint_test_sender_id == 0U) {
        return;
    }
    initiator->local_id = g_endpoint_test_sender_id;
    initiator->peer_id = ID_RESP;
    responder->local_id = ID_RESP;
    responder->peer_id = g_endpoint_test_sender_id;
}

static void tune_control_reserve_sender_cid(dmp_hs_config *initiator,
                                            dmp_hs_config *responder)
{
    (void)responder;
    if (initiator != NULL && g_endpoint_test_next_rx_cid != 0U) {
        initiator->next_rx_cid = g_endpoint_test_next_rx_cid;
    }
}

static void tune_test_local_initiator_identity(dmp_hs_config *initiator,
                                              dmp_hs_config *responder)
{
    if (initiator == NULL || responder == NULL || g_endpoint_test_sender_id == 0U) {
        return;
    }
    initiator->local_id = ID_RESP;
    initiator->peer_id = g_endpoint_test_sender_id;
    responder->local_id = g_endpoint_test_sender_id;
    responder->peer_id = ID_RESP;
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
    if (existing == NULL) {
        memset(port, 0, sizeof *port);
    }
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
            (void)fprintf(stderr, "make_pair provider setup failed\n");
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
        if (g_endpoint_test_unique_entropy) {
            script_add(&env->init_script, g_endpoint_test_alt_attempt,
                       sizeof g_endpoint_test_alt_attempt);
            script_add(&env->init_script, g_endpoint_test_alt_init_ephemeral,
                       sizeof g_endpoint_test_alt_init_ephemeral);
            script_add(&env->resp_script, g_endpoint_test_alt_resp_ephemeral,
                       sizeof g_endpoint_test_alt_resp_ephemeral);
        } else {
            memset(env->alt_attempt, 0x42, sizeof env->alt_attempt);
            script_add(&env->init_script, env->alt_attempt, sizeof env->alt_attempt);
            script_add(&env->init_script, fixture->resp_ephemeral.data, fixture->resp_ephemeral.size);
            script_add(&env->resp_script, fixture->init_ephemeral.data, fixture->init_ephemeral.size);
        }
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
    if ((g_endpoint_test_admission != NULL &&
         (g_endpoint_test_responder_admission_only == 0 ||
          g_endpoint_test_initiator_admission_only != 0)
             ? dmp_hs_init_shared(env->initiator, provider, &init_config,
                                  &init_ports, g_endpoint_test_admission)
             : dmp_hs_init(env->initiator, provider, &init_config, &init_ports)) !=
            DMP_HS_OK ||
        (g_endpoint_test_admission != NULL &&
         g_endpoint_test_initiator_admission_only == 0
             ? dmp_hs_init_shared(env->responder, provider, &resp_config,
                                  &resp_ports, g_endpoint_test_admission)
             : dmp_hs_init(env->responder, provider, &resp_config, &resp_ports)) !=
            DMP_HS_OK ||
        dmp_hs_begin_episode(env->initiator) != DMP_HS_OK) {
        (void)fprintf(stderr, "make_pair handshake init failed\n");
        close_session(env);
        return 0;
    }
    return 1;
}

/* Re-create only a simulated remote initiator while retaining the responder
 * object bound to the endpoint. The test shares one provider across its local
 * endpoint and four in-process remote peers, so the remote initiator's old
 * cipher objects must be released before exercising the endpoint's declared
 * four-active/four-draining provider envelope. */
static int renew_multi_peer_initiator(session *env, dmp_provider *provider,
                                     const noise_fixture_probe_fixture_t *fixture,
                                     uint32_t peer_id)
{
    dmp_hs_config config;
    dmp_hs_ports ports;

    if (env == NULL || provider == NULL || fixture == NULL || env->initiator == NULL) {
        return 0;
    }
    fill_hs(&config, fixture, 1);
    p23_apply_hs_profile(&config);
    config.local_id = peer_id;
    config.peer_id = ID_RESP;
    memset(&ports, 0, sizeof ports);
    ports.now_ms = now_of;
    ports.entropy = entropy_of;
    ports.commit_pin = commit_of;
    ports.ctx = &env->init_box;
    return dmp_hs_init(env->initiator, provider, &config, &ports) == DMP_HS_OK &&
           dmp_hs_begin_episode(env->initiator) == DMP_HS_OK;
}

static int drive_flight(dmp_hs *hs, const uint8_t *payload, size_t length, uint32_t origin,
                        uint32_t destination, uint32_t seq, uint64_t epoch, dmp_hs_status expected)
{
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    dmp_hs_status status;
    dmp_hs_status offered;
    memset(&ingress, 0, sizeof ingress);
    ingress.payload = payload;
    ingress.payload_len = length;
    ingress.origin_id = origin;
    ingress.destination_id = destination;
    ingress.namespace_id = LOCAL_NS;
    ingress.context_epoch = epoch;
    ingress.seq = seq;
    status = dmp_hs_offer(hs, &ingress, &completion);
    offered = status;
    if (status == DMP_HS_AWAITING) {
        status = dmp_hs_accept(hs, &completion);
    }
    if (status != expected) {
        (void)fprintf(stderr,
                      "flight offer=%d final=%d expected=%d (seq=%u origin=%u destination=%u)\n",
                      (int)offered, (int)status, (int)expected, seq, origin, destination);
    }
    return status == expected;
}

static int find_cached_flight(const dmp_hs *hs, const uint8_t attempt_id[16],
                             uint8_t flight, uint32_t *index_out)
{
    uint32_t index;
    for (index = 0U; index < DMP_HS_ATTEMPT_MAX; index++) {
        size_t length = 0U;
        const uint8_t *cached = dmp_hs_cached_flight(hs, index, &length);
        if (cached != NULL && length >= 18U && cached[0] == 2U && cached[1] == flight &&
            memcmp(cached + 2U, attempt_id, 16U) == 0) {
            *index_out = index;
            return 1;
        }
    }
    return 0;
}

static int drive_nn_for_ids(session *env, uint32_t *index,
                            uint32_t initiator_id, uint32_t responder_id)
{
    const uint8_t *cached;
    uint8_t scheduled_id[16];
    size_t length = 0U;
    uint64_t boot;
    if (dmp_hs_schedule(env->initiator, index) != DMP_HS_OK ||
        !dmp_hs_copy_attempt_id(env->initiator, *index, scheduled_id)) {
        return 0;
    }
    boot = dmp_hs_boot_epoch(env->initiator, *index);
    if (boot == 0U) {
        return 0;
    }
    cached = dmp_hs_cached_flight(env->initiator, *index, &length);
    if (!drive_flight(env->responder, cached, length, initiator_id,
                      responder_id, 1U, boot, DMP_HS_CANDIDATE)) {
        (void)fprintf(stderr, "drive_nn flight 1 failed (%u -> %u)\n",
                      initiator_id, responder_id);
        return 0;
    }
    if (!find_cached_flight(env->responder, scheduled_id, 2U,
                            &env->responder_index)) {
        (void)fprintf(stderr, "responder flight 2 not found for scheduled attempt\n");
        return 0;
    }
    cached = dmp_hs_cached_flight(env->responder, env->responder_index, &length);
    if (!drive_flight(env->initiator, cached, length, responder_id,
                      initiator_id, 2U, boot, DMP_HS_CANDIDATE)) {
        (void)fprintf(stderr, "drive_nn flight 2 failed (%u -> %u)\n",
                      responder_id, initiator_id);
        return 0;
    }
    return 1;
}

static int drive_nn(session *env, uint32_t *index)
{
    return drive_nn_for_ids(env, index, ID_INIT, ID_RESP);
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

static int activate_for_ids(session *env, uint32_t index,
                            uint32_t initiator_id, uint32_t responder_id)
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
    if (frame == NULL || !offer_protected(env->responder, frame, length,
                                          initiator_id, responder_id, epoch_i)) {
        return 0;
    }
    frame = dmp_hs_protected_frame(env->responder, env->responder_index, &length);
    if (frame == NULL || !offer_protected(env->initiator, frame, length,
                                          responder_id, initiator_id, epoch_r)) {
        return 0;
    }
    return dmp_hs_association_active(env->initiator) && dmp_hs_association_active(env->responder);
}

static int activate(session *env, uint32_t index)
{
    return activate_for_ids(env, index, ID_INIT, ID_RESP);
}

static int sync_stream_pair(dmp_time_ms now)
{
    left.wire.now = now;
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(complete_pending_completions(&left.wire, now) == 0);
    CHECK(complete_pending_completions(&right.wire, now) == 0);
    CHECK(left.wire.n == 0 && right.wire.n == 0);
    return 0;
}

static int bind_pair(session *env, uint32_t index)
{
    dmp_time_ms now = left.wire.now;
    CHECK(sync_stream_pair(now) == 0);
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
    uint8_t prefixed[FRAME_CAP + 1U];
    dmp_bytes input;
    dmp_stream_result fed;
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
        fed = dmp_stream_feed(&decoder, input, now);
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
    if (n + 1U > sizeof prefixed) return 0;
    prefixed[0] = 0U;
    memcpy(prefixed + 1U, framed, n);
    memset(&decoder, 0, sizeof decoder);
    if (dmp_stream_init(&decoder, config, storage, now) != DMP_OK) return 0;
    input = span(prefixed, n + 1U);
    while (input.size != 0U) {
        fed = dmp_stream_feed(&decoder, input, now);
        if (fed.status != DMP_OK || fed.consumed == 0U || fed.consumed > input.size) {
            return 0;
        }
        input.data += fed.consumed;
        input.size -= fed.consumed;
        if (fed.event == DMP_STREAM_FRAME) {
            if (fed.frame.size > cap) return 0;
            if (fed.frame.size != 0U) memcpy(core, fed.frame.data, fed.frame.size);
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

static int wire_opens_type(wire *from, dmp_hs *receiver, uint32_t attempt,
                           uint8_t wanted_type, uint8_t *payload,
                           size_t payload_capacity, size_t *payload_size,
                           dmp_time_ms now)
{
    uint8_t core[FRAME_CAP];
    uint8_t plain[FRAME_CAP];
    uint8_t synced[FRAME_CAP + 1U];
    uint64_t local_epoch = 0U;
    uint64_t remote_epoch = 0U;
    size_t core_size;
    size_t plain_size;
    int i;
    if (from == NULL || receiver == NULL || payload_size == NULL ||
        !dmp_hs_epochs(receiver, attempt, &local_epoch, &remote_epoch) ||
        local_epoch == 0U || remote_epoch == 0U) {
        return 0;
    }
    for (i = 0; i < from->n; i++) {
        dmp_hs_protected incoming;
        dmp_frame_view view;
        dmp_hs_status open_status;
        if (!unwrap_core(from->q[i].frame, from->q[i].len, core, sizeof core,
                         &core_size, now)) {
            if (from->q[i].len >= FRAME_CAP) {
                continue;
            }
            /* Stream R may emit the sync delimiter as its own transport send. */
            synced[0] = 0U;
            memcpy(synced + 1U, from->q[i].frame, from->q[i].len);
            if (!unwrap_core(synced, from->q[i].len + 1U, core, sizeof core,
                             &core_size, now)) {
                continue;
            }
        }
        memset(&incoming, 0, sizeof incoming);
        incoming.frame = core;
        incoming.frame_len = core_size;
        incoming.origin_id = ID_RESP;
        incoming.destination_id = ID_INIT;
        incoming.namespace_id = LOCAL_NS;
        incoming.context_epoch = remote_epoch;
        open_status = dmp_hs_open_logical(receiver, attempt, &incoming, plain,
                                          sizeof plain, &plain_size, &view);
        if (open_status != DMP_HS_OK) {
            if (wanted_type == DMP_TYPE_TELEM) {
                (void)fprintf(stderr,
                              "wire telemetry frame %d failed authenticated open: status=%d len=%zu core=%zu epochs=%llu/%llu\n",
                              i, (int)open_status, from->q[i].len, core_size,
                              (unsigned long long)local_epoch,
                              (unsigned long long)remote_epoch);
            }
            continue;
        }
        if (view.fields.type != wanted_type) {
            if (wanted_type == DMP_TYPE_TELEM) {
                (void)fprintf(stderr,
                              "wire telemetry frame %d opened with unexpected type=%u\n",
                              i, (unsigned)view.fields.type);
            }
            continue;
        }
        if (view.payload.size > payload_capacity ||
            (view.payload.size != 0U && (payload == NULL || view.payload.data == NULL))) {
            return 0;
        }
        if (view.payload.size != 0U) {
            memcpy(payload, view.payload.data, view.payload.size);
        }
        *payload_size = view.payload.size;
        return 1;
    }
    return 0;
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

static int test_transport_reject_retry(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t req[1];
    dmp_reliability_handle handle;
    pending_completion pending;
    dmp_time_ms now = 20000U;
    int submits_before;

    if (fixture == NULL) {
        return 1;
    }
    if (!make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    /* Exercise the delayed-copy completion path rather than the direct
     * profile's default synchronous callback. */
    g_p23_copy_async_binding = 1;
    if (boot_node(&left, 1, 64U, 16U, now) != 0 ||
        boot_node(&right, 0, 64U, 16U, now) != 0 || bind_pair(&env, index) != 0) {
        g_p23_copy_async_binding = 0;
        close_session(&env);
        return 1;
    }
    g_p23_copy_async_binding = 0;

    sample1_read_req(req);
    submits_before = right.wire.submits;
    /* reliability_poll may make several bounded passes in one call. Keep the
     * fake transport rejecting through that poll, then explicitly allow the
     * queued operation to retry on the next poll. */
    right.wire.reject_remaining = (int)(right.endpoint.reliability.storage.sender_capacity +
                                        right.endpoint.reliability.storage.adapter_capacity + 16U);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, sizeof req), now, &handle) ==
          DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.submits == submits_before);
    CHECK(right.wire.n == 0 && right.wire.pending_count == 0);
    CHECK(right.wire.reject_remaining > 0);
    CHECK(right.endpoint.wire_busy == 0U);
    CHECK(right.endpoint.reliability.storage.senders[handle.slot].live != 0U);
    CHECK(right.endpoint.reliability.storage.senders[handle.slot].possibly_sent == 0U);

    /* The same queued request is accepted on a later poll. The fake transport
     * has copied the frame, but its completion leaves delivery uncertain. */
    right.wire.reject_remaining = 0;
    right.wire.completion_outcome = DMP_TX_POSSIBLY_TRANSMITTED;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 1U) == DMP_OK);
    CHECK(right.wire.submits == submits_before + 1);
    CHECK(right.wire.n == 1 && right.wire.pending_count == 1);
    pending = right.wire.pending[0];
    right.wire.pending_count = 0;
    CHECK(pending.complete != NULL);
    pending.complete(pending.owner, pending.token, pending.outcome, now + 1U);
    CHECK(right.endpoint.wire_busy == 0U);
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 1U) == DMP_OK);
    CHECK(right.endpoint.reliability.storage.senders[handle.slot].possibly_sent == 1U);

    /* Revocation must report uncertainty, not claim a local unsent request. */
    CHECK(dmp_endpoint_revoke(&right.endpoint, now + 2U) == DMP_OK);
    CHECK(right.app.unknowns == 1);
    CHECK(right.app.local_unsent == 0);
    close_session(&env);

    /* A possibly-transmitted Stream R sync delimiter may have been lost.
     * Keep sync pending until a later delimiter is definitely delivered so
     * queued application frames cannot be sent into an unsynchronized stream. */
    now += 100U;
    if (!make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    g_p23_copy_async_binding = 1;
    if (boot_node(&left, 1, 64U, 16U, now) != 0 ||
        boot_node(&right, 0, 64U, 16U, now) != 0) {
        g_p23_copy_async_binding = 0;
        close_session(&env);
        return 1;
    }
    g_p23_copy_async_binding = 0;
    CHECK(dmp_endpoint_bind(&left.endpoint, env.initiator, index) == DMP_OK);
    CHECK(dmp_endpoint_bind(&right.endpoint, env.responder, 0U) == DMP_OK);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, sizeof req), now, &handle) ==
          DMP_OK);
    right.wire.drop_remaining = 1;
    right.wire.completion_outcome = DMP_TX_POSSIBLY_TRANSMITTED;
    right.wire.now = now;
    CHECK(right.endpoint.peers[0].sync_pending != 0U);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n == 0 && right.wire.pending_count == 1U);
    CHECK(complete_pending_completions(&right.wire, now) == 0);
    CHECK(right.endpoint.peers[0].sync_pending != 0U &&
          right.endpoint.peers[0].sync_tx == 0U);

    right.wire.completion_outcome = DMP_TX_TRANSMITTED;
    right.wire.now = now + 1U;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 1U) == DMP_OK);
    CHECK(right.wire.n == 1 && right.wire.q[0].len == 1U &&
          right.wire.q[0].frame[0] == 0U && right.wire.pending_count == 1U);
    CHECK(complete_pending_completions(&right.wire, now + 1U) == 0);
    CHECK(right.endpoint.peers[0].sync_pending == 0U);
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 2U) == DMP_OK);
    CHECK(right.wire.n == 2 && right.wire.q[1].len > 1U);
    CHECK(deliver_all(&right, &left, now + 2U) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(complete_pending_completions(&right.wire, now + 2U) == 0);
    close_session(&env);
    return 0;
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
    sample_tracker state = {0};
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
    CHECK(sample_accept_read_result(&state, &right.app, handle) == 0);
    CHECK(state.synchronized == 1 && state.epoch == 1U && state.index == 2U &&
          state.value == 300U && state.violations == 0);
    close_session(&env);
    return 0;
}

static int test_result_loss(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    sample_tracker state = {0};
    uint32_t index = 0U;
    uint8_t req[1];
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    /* Drop the first protected RSP after the producer accepts the READ. */
    left.wire.drop_remaining = 1;
    CHECK(pump(now, 3) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(left.wire.drop_remaining == 0);
    CHECK(right.app.results == 0);
    CHECK(state.synchronized == 0);
    CHECK(pump(now + 1280U, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(right.app.result_n == sizeof READ_RSP);
    CHECK(memcmp(right.app.result, READ_RSP, sizeof READ_RSP) == 0);
    CHECK(right.app.unknowns == 0);
    CHECK(sample_accept_read_result(&state, &right.app, handle) == 0);
    CHECK(state.synchronized == 1 && state.epoch == 1U && state.index == 2U &&
          state.value == 300U && state.violations == 0);
    close_session(&env);
    return 0;
}

static int test_control_reserve_under_hello_flood(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    session flood_peer;
    port_ctx port;
    port_ctx flood_port;
    uint32_t index = 0U;
    dmp_time_ms now = 20000U;
    uint8_t req[1];
    uint8_t s2_req[4] = {0x11, 0x22, 0x33, 0x44};
    dmp_reliability_handle h1, h2, h3, h_busy, h_left;
    dmp_status status;
    dmp_hs_status hs_status;
    uint32_t initial_pending;
    uint32_t flood_pending;
    uint8_t hello_core[64];
    size_t hello_core_n = 0U;
    dmp_frame_spec spec;
    dmp_core_limits limits;
    dmp_buffer out;
    uint32_t crc = 0U;
    uint8_t wrapped[128];
    size_t wrapped_n = 0U;
    uint8_t flood_attempt_ids[3][16];
    uint8_t flood_ephemerals[3][32];
    uint8_t flood_responder_ephemerals[2][32];
    uint8_t flood_payloads[3][DMP_HS_PAYLOAD_MAX];
    size_t flood_lengths[3] = {0U, 0U, 0U};
    dmp_hs_ingress ingress;
    dmp_hs_completion completion;
    const uint8_t *cached;
    size_t cached_len;
    uint64_t boot_epoch;
    uint32_t flood_index;
    uint32_t flood_count = 0U;
    uint32_t attempt_number;
    size_t i;
    int initial_right_submits;
    uint8_t trailer[4] = {0};

    g_endpoint_test_operations_per_service = 4U;
    g_endpoint_test_queue_ms = 1000U;
    memset(&flood_peer, 0, sizeof flood_peer);
    memset(&flood_port, 0, sizeof flood_port);
    memset(&env, 0, sizeof env);
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        g_endpoint_test_operations_per_service = 0U;
        g_endpoint_test_queue_ms = 0U;
        return 1;
    }
    CHECK(boot_node_slots(&left, 1, 64U, 16U, now, 2U) == 0);
    CHECK(boot_node_slots(&right, 0, 64U, 16U, now, 2U) == 0);
    CHECK(bind_pair(&env, index) == 0);

    /* Phase 1: Saturate application and retry queues on the responder ('right'). */
    sample1_read_req(req);
    right.wire.drop_remaining = 1;
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &h1) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);

    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &h2) == DMP_OK);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 2U, span(s2_req, sizeof s2_req), now, &h3) == DMP_OK);

    /* Application queue on 'right' is now full (queued_application == 2 == application_queue_slots). */
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &h_busy) == DMP_BUSY);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 2U, span(s2_req, sizeof s2_req), now, &h_busy) == DMP_BUSY);

    /* Phase 2: Inbound request from 'left' admitted on 'right', establishing an ACK obligation. */
    left.wire.now = now;
    CHECK(dmp_endpoint_submit_req(&left.endpoint, 2U, span(s2_req, sizeof s2_req), now, &h_left) == DMP_OK);
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 1);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(right.app.accepts == 1);

    /* App queue remains saturated on 'right'. */
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &h_busy) == DMP_BUSY);

    /* Phase 3: Flood with unauthenticated HELLO frames and bootstrap attempts. */
    initial_pending = dmp_hs_pending(env.responder);
    CHECK(initial_pending == 0U);

    /* 3A: Wire-level unauthenticated HELLO frames. */
    memset(&spec, 0, sizeof spec);
    spec.fields.type = DMP_TYPE_HELLO;
    spec.fields.options = DMP_OPT_SEQ | DMP_OPT_INTEGRITY;
    spec.fields.seq = 1U;
    spec.fields.integrity = 1U;
    spec.trailer = span(trailer, sizeof trailer);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    out.data = hello_core;
    out.capacity = sizeof hello_core;
    CHECK(dmp_core_encode(&spec, &limits, out, &hello_core_n) == DMP_OK);
    crc = 0U;
    CHECK(dmp_crc32c(span(hello_core, hello_core_n - 4U), &crc) == DMP_OK);
    hello_core[hello_core_n - 4U] = (uint8_t)crc;
    hello_core[hello_core_n - 3U] = (uint8_t)(crc >> 8);
    hello_core[hello_core_n - 2U] = (uint8_t)(crc >> 16);
    hello_core[hello_core_n - 1U] = (uint8_t)(crc >> 24);
    CHECK(wrap_core(hello_core, hello_core_n, wrapped, sizeof wrapped, &wrapped_n) == 1);

    for (i = 0U; i < 20U; i++) {
        status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
        CHECK(status == DMP_AUTHENTICATION_FAILURE);
    }

    /* 3B: Offer real, distinct Noise flight-1 payloads to the live SEC-1
     * responder. Hold the first two completions so they consume the fixture's
     * exact max_pending=2 admission bound; a third valid offer must be refused. */
    env.now = now;
    for (attempt_number = 0U; attempt_number < 2U; attempt_number++) {
        uint8_t salt = (uint8_t)(0x51U + attempt_number);

        memcpy(flood_attempt_ids[attempt_number], fixture->attempt_id.data, 16U);
        flood_attempt_ids[attempt_number][0] ^= salt;
        memcpy(flood_ephemerals[attempt_number], fixture->init_ephemeral.data,
               32U);
        /* Match the established rotation fixture convention: change an
         * unclamped scalar byte as well as the attempt identifier. */
        flood_ephemerals[attempt_number][8] ^= salt;
        memcpy(flood_responder_ephemerals[attempt_number],
               fixture->resp_ephemeral.data, 32U);
        flood_responder_ephemerals[attempt_number][8] ^= salt;
        script_add(&env.init_script, flood_attempt_ids[attempt_number], 16U);
        script_add(&env.init_script, flood_ephemerals[attempt_number], 32U);
        script_add(&env.resp_script,
                   flood_responder_ephemerals[attempt_number], 32U);

        CHECK(dmp_hs_schedule(env.initiator, &flood_index) == DMP_HS_OK);
        cached = dmp_hs_cached_flight(env.initiator, flood_index, &cached_len);
        CHECK(cached != NULL && cached_len <= sizeof flood_payloads[0]);
        memcpy(flood_payloads[flood_count], cached, cached_len);
        flood_lengths[flood_count] = cached_len;
        boot_epoch = dmp_hs_boot_epoch(env.initiator, flood_index);
        CHECK(boot_epoch != 0U);

        memset(&ingress, 0, sizeof ingress);
        memset(&completion, 0, sizeof completion);
        ingress.payload = flood_payloads[flood_count];
        ingress.payload_len = flood_lengths[flood_count];
        ingress.origin_id = ID_INIT;
        ingress.destination_id = ID_RESP;
        ingress.namespace_id = LOCAL_NS;
        ingress.seq = 1U;
        ingress.context_epoch = boot_epoch;
        hs_status = dmp_hs_offer(env.responder, &ingress, &completion);
        if (hs_status != DMP_HS_AWAITING) {
            (void)fprintf(stderr,
                          "bootstrap offer %u returned %d (pending=%u, bytes=%zu)\n",
                          flood_count, (int)hs_status,
                          dmp_hs_pending(env.responder), flood_lengths[flood_count]);
        }
        CHECK(hs_status == DMP_HS_AWAITING);
        CHECK(completion.generation != 0U);
        flood_count++;
        CHECK(dmp_hs_pending(env.responder) == flood_count);
    }

    /* Use the same process-wide Noise provider for an additional attacker
     * instance; the fixture's allocator/entropy hooks are serialized. */
    g_endpoint_test_next_rx_cid = CID_INIT + 0x100U;
    CHECK(make_pair(&flood_peer, &flood_port, fixture,
                    tune_control_reserve_sender_cid, env.provider, 0));
    g_endpoint_test_next_rx_cid = 0U;
    flood_peer.now = now;
    memcpy(flood_attempt_ids[2], fixture->attempt_id.data, 16U);
    flood_attempt_ids[2][0] ^= 0x53U;
    memcpy(flood_ephemerals[2], fixture->init_ephemeral.data, 32U);
    flood_ephemerals[2][8] ^= 0x53U;
    flood_peer.init_script.data[0] = flood_attempt_ids[2];
    flood_peer.init_script.len[0] = 16U;
    flood_peer.init_script.data[1] = flood_ephemerals[2];
    flood_peer.init_script.len[1] = 32U;
    CHECK(dmp_hs_schedule(flood_peer.initiator, &flood_index) == DMP_HS_OK);
    cached = dmp_hs_cached_flight(flood_peer.initiator, flood_index, &cached_len);
    CHECK(cached != NULL && cached_len <= sizeof flood_payloads[0]);
    memcpy(flood_payloads[2], cached, cached_len);
    flood_lengths[2] = cached_len;
    boot_epoch = dmp_hs_boot_epoch(flood_peer.initiator, flood_index);
    CHECK(boot_epoch != 0U);
    memset(&ingress, 0, sizeof ingress);
    memset(&completion, 0, sizeof completion);
    ingress.payload = flood_payloads[2];
    ingress.payload_len = flood_lengths[2];
    ingress.origin_id = ID_INIT;
    ingress.destination_id = ID_RESP;
    ingress.namespace_id = LOCAL_NS;
    ingress.seq = 1U;
    ingress.context_epoch = boot_epoch;
    hs_status = dmp_hs_offer(env.responder, &ingress, &completion);
    CHECK(hs_status == DMP_HS_REFUSED);
    flood_count++;
    CHECK(flood_count == 3U);
    close_session(&flood_peer);

    /* Assert the exact configured handshake bound and preserve the established
     * association while unauthenticated bootstrap work is present. */
    flood_pending = dmp_hs_pending(env.responder);
    CHECK(flood_pending == 2U);
    CHECK(dmp_hs_association_active(env.responder) == 1);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &h_busy) == DMP_BUSY);

    /* Phase 4: Advance time past receipt_delay_ms and verify ACK transmission. */
    now += 120U;
    right.wire.now = now;
    left.wire.now = now;
    CHECK(right.endpoint.profile.queue_ms == 1000U);
    CHECK(right.endpoint.reliability.storage.senders[h2.slot].live);
    CHECK(right.endpoint.reliability.storage.senders[h2.slot].phase ==
          DMP_REL_PHASE_QUEUED);
    CHECK(right.endpoint.reliability.storage.senders[h2.slot].queue_deadline > now);
    CHECK(right.endpoint.reliability.storage.senders[h3.slot].live);
    CHECK(right.endpoint.reliability.storage.senders[h3.slot].phase ==
          DMP_REL_PHASE_QUEUED);
    CHECK(right.endpoint.reliability.storage.senders[h3.slot].queue_deadline > now);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now,
                                  &h_busy) == DMP_BUSY);
    initial_right_submits = right.wire.submits;

    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.submits > initial_right_submits);
    CHECK(right.wire.n > 0);

    /* Deliver the ACK to left and verify receipt. */
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.endpoint.reliability.storage.senders[h_left.slot].receipt_seen == true);
    CHECK(left.endpoint.reliability.storage.senders[h_left.slot].phase == DMP_REL_PHASE_AWAIT_RESULT);

    close_session(&env);
    g_endpoint_test_operations_per_service = 0U;
    g_endpoint_test_queue_ms = 0U;
    return 0;
}

static int test_receipt_loss(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    sample_tracker state = {0};
    uint32_t index = 0U;
    uint8_t req[1];
    dmp_reliability_handle handle;
    dmp_time_ms now = 20000U;
    int right_submits;
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    sample1_read_req(req);
    right.app.drop_result_receipt = 1;
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) == DMP_OK);
    CHECK(pump(now, 8) == 0);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(right.wire.drop_remaining == 0);
    CHECK(sample_accept_read_result(&state, &right.app, handle) == 0);
    CHECK(state.synchronized == 1 && state.epoch == 1U && state.index == 2U &&
          state.value == 300U && state.violations == 0);
    right_submits = right.wire.submits;

    /* The first protected receipt was dropped during result delivery. The
     * producer retries its cached protected RSP; the duplicate is re-acked
     * without another application result callback. */
    CHECK(pump(now + 1280U, 8) == 0);
    CHECK(right.wire.submits == right_submits + 1);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
    CHECK(state.synchronized == 1 && state.epoch == 1U && state.index == 2U &&
          state.value == 300U && state.violations == 0);
    CHECK(pump(now + 1390U, 4) == 0);
    CHECK(right.wire.submits == right_submits + 1);
    CHECK(left.app.accepts == 1);
    CHECK(right.app.results == 1);
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
    CHECK(sync_stream_pair(now) == 0);
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
    int expected_fragments = (FRAG_BYTES + FRAG_CHUNK - 1) / FRAG_CHUNK;
    size_t n;
    memset(&env, 0, sizeof env);
    memset(&other, 0, sizeof other);
    if (fixture == NULL || !make_pair(&other, &other_port, fixture, tune_alt, NULL, 1) ||
        !drive_nn(&other, &other_index) || !activate(&other, other_index)) {
        close_session(&other);
        return 1;
    }
    CHECK(boot_node(&left, 1, FRAG_CHUNK, 32U, now) == 0);
    CHECK(sync_stream_node(&left, now) == 0);
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
    for (i = 0; i < 24 && left.wire.n < expected_fragments; i++) {
        CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    }
    CHECK(left.wire.n >= expected_fragments);
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

    /* A fresh authenticated PN with the accepted identity cannot replace the
     * completed body, and it does not dispatch a second assembled message. */
    spec.payload = span(conflict_bytes, sizeof conflict_bytes);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_DUPLICATE);
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
    ttl_only[at] = (uint8_t)(ttl_only[at] & 0x0fU);
    CHECK(wrap_core(ttl_only, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
    CHECK(status == DMP_OK);
    CHECK(right.app.telems == 1);
    close_session(&env);
    return 0;
}

typedef struct protected_header_offsets {
    size_t sequence;
    size_t destination;
    size_t descriptor_codec;
    size_t receive_cid;
    size_t packet_number;
    size_t context_epoch;
    size_t service_id;
    size_t payload;
    size_t tag;
} protected_header_offsets;

static int skip_test_uleb(const uint8_t *frame, size_t frame_size, size_t *cursor)
{
    size_t index;

    if (frame == NULL || cursor == NULL) {
        return 0;
    }
    for (index = 0U; index < 10U && *cursor < frame_size; ++index) {
        uint8_t byte = frame[(*cursor)++];
        if ((byte & 0x80U) == 0U) {
            return 1;
        }
    }
    return 0;
}

static int protected_frame_offsets(const uint8_t *frame, size_t frame_size,
                                   const dmp_frame_view *view,
                                   protected_header_offsets *offsets)
{
    size_t cursor = 2U;
    uint8_t options;

    if (frame == NULL || view == NULL || offsets == NULL || frame_size < 3U ||
        view->header.size > frame_size) {
        return 0;
    }
    memset(offsets, 0xff, sizeof(*offsets));
    options = frame[cursor++];
    if ((options & DMP_OPT_SEQ) != 0U) {
        offsets->sequence = cursor;
        if (!skip_test_uleb(frame, view->header.size, &cursor)) {
            return 0;
        }
    }
    if ((options & DMP_OPT_ROUTE) != 0U) {
        ++cursor; /* Route control byte; TTL is the only mutable AAD field. */
        if (!skip_test_uleb(frame, view->header.size, &cursor)) {
            return 0;
        }
        offsets->destination = cursor;
        if (!skip_test_uleb(frame, view->header.size, &cursor)) {
            return 0;
        }
    }
    if ((options & DMP_OPT_FRAG) != 0U) {
        for (size_t field = 0U; field < 3U; ++field) {
            if (!skip_test_uleb(frame, view->header.size, &cursor)) {
                return 0;
            }
        }
    }
    if ((options & DMP_OPT_PAYLOAD_DESC) != 0U) {
        uint8_t flags;
        if (cursor >= view->header.size) {
            return 0;
        }
        flags = frame[cursor++];
        offsets->descriptor_codec = cursor;
        if (!skip_test_uleb(frame, view->header.size, &cursor) ||
            ((flags & 1U) != 0U && !skip_test_uleb(frame, view->header.size, &cursor)) ||
            ((flags & 2U) != 0U && !skip_test_uleb(frame, view->header.size, &cursor))) {
            return 0;
        }
    }
    if ((options & DMP_OPT_INTEGRITY) != 0U) {
        ++cursor;
    }
    if ((options & DMP_OPT_SECURITY) != 0U) {
        ++cursor; /* Cipher. */
        offsets->receive_cid = cursor;
        if (!skip_test_uleb(frame, view->header.size, &cursor)) {
            return 0;
        }
        offsets->packet_number = cursor;
        if (!skip_test_uleb(frame, view->header.size, &cursor)) {
            return 0;
        }
    }
    if (cursor > view->header.size) {
        return 0;
    }
    {
        size_t extension_cursor = 0U;
        while (extension_cursor < view->extensions.size) {
            dmp_extension_view extension;
            size_t value_offset;
            dmp_status status = dmp_extension_next(view->extensions, &extension_cursor,
                                                    &extension);
            if (status != DMP_OK) {
                return 0;
            }
            value_offset = (size_t)(extension.value.data - frame);
            if ((extension.tag >> 2U) == 2U) {
                offsets->context_epoch = value_offset + 1U; /* Namespace is one byte. */
            } else if ((extension.tag >> 2U) == 4U) {
                offsets->service_id = value_offset;
            }
        }
    }
    offsets->payload = view->header.size;
    if (view->trailer.size != 16U || frame_size < view->trailer.size) {
        return 0;
    }
    offsets->tag = frame_size - view->trailer.size;
    return offsets->sequence != SIZE_MAX && offsets->destination != SIZE_MAX &&
           offsets->descriptor_codec != SIZE_MAX && offsets->receive_cid != SIZE_MAX &&
           offsets->packet_number != SIZE_MAX && offsets->context_epoch != SIZE_MAX &&
           offsets->service_id != SIZE_MAX && offsets->payload < offsets->tag;
}

static int protected_header_mutation_case(unsigned mutation, dmp_time_ms now)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t payload[2] = {0x11U, 0x22U};
    uint8_t extensions[14];
    uint8_t sealed[MTU];
    uint8_t mutated[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t extensions_size = 0U;
    size_t sealed_size = 0U;
    size_t wrapped_size = 0U;
    uint64_t epoch_i = 0U;
    uint64_t epoch_r = 0U;
    dmp_frame_spec spec;
    dmp_frame_view view;
    dmp_core_limits limits = { MTU, MESSAGE, 32U };
    dmp_endpoint_grant grants[5] = {
        { ID_INIT, 1U, DMP_ENDPOINT_PERMIT_TELEM | DMP_ENDPOINT_PERMIT_RESULT },
        { ID_RESP, 1U, DMP_ENDPOINT_PERMIT_REQ },
        { ID_INIT, 2U, DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT },
        { ID_RESP, 2U, DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT },
        { ID_INIT, 2U, DMP_ENDPOINT_PERMIT_TELEM },
    };
    dmp_status status;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_set_peer_grants(&right.endpoint, (dmp_peer_handle){ 0U, 1U },
                                       grants, sizeof grants / sizeof grants[0]) == DMP_OK);
    CHECK(dmp_hs_epochs(env.initiator, index, &epoch_i, &epoch_r) == 1);
    (void)epoch_r;

    extensions[extensions_size++] = 11U;
    extensions[extensions_size++] = 9U;
    extensions[extensions_size++] = 1U;
    for (size_t byte = 0U; byte < 8U; ++byte) {
        extensions[extensions_size++] = (uint8_t)(epoch_i >> (8U * byte));
    }
    extensions[extensions_size++] = 17U;
    extensions[extensions_size++] = 1U;
    extensions[extensions_size++] = 2U;

    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_TELEM;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ROUTE | DMP_OPT_EXT |
                                    DMP_OPT_PAYLOAD_DESC);
    spec.fields.route.mode = 1U;
    spec.fields.route.ttl = 4U;
    spec.fields.route.source = ID_INIT;
    spec.fields.route.destination = ID_RESP;
    spec.fields.descriptor.flags = 1U;
    spec.fields.descriptor.codec = 1U;
    spec.fields.descriptor.schema = 1U;
    spec.extensions = span(extensions, extensions_size);
    spec.payload = span(payload, sizeof payload);

    protected_header_offsets offsets;
    spec.fields.seq = 1U;
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed,
                              &sealed_size) == DMP_HS_OK);
    CHECK(dmp_core_parse(span(sealed, sealed_size), &limits, &view).status == DMP_OK);
    CHECK(protected_frame_offsets(sealed, sealed_size, &view, &offsets) == 1);
    memcpy(mutated, sealed, sealed_size);
    switch (mutation) {
    case 0U:
        mutated[offsets.destination] ^= 1U;
        break;
    case 1U:
        mutated[offsets.sequence] ^= 1U;
        break;
    case 2U:
        mutated[offsets.descriptor_codec] ^= 1U;
        break;
    case 3U:
        mutated[offsets.service_id] ^= 1U;
        break;
    case 4U:
        mutated[offsets.context_epoch + 7U] ^= 1U;
        break;
    case 5U:
        mutated[offsets.receive_cid] ^= 1U;
        break;
    case 6U:
        mutated[offsets.packet_number] += 1U;
        break;
    case 7U:
        mutated[offsets.payload] ^= 1U;
        break;
    default:
        mutated[offsets.tag] ^= 1U;
        break;
    }
    CHECK(dmp_core_parse(span(mutated, sealed_size), &limits, &view).status == DMP_OK);
    CHECK(wrap_core(mutated, sealed_size, wrapped, sizeof wrapped, &wrapped_size) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_size), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.telems == 0);

    CHECK(wrap_core(sealed, sealed_size, wrapped, sizeof wrapped, &wrapped_size) == 1);
    status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_size), now);
    if (status != DMP_OK) {
        (void)fprintf(stderr, "mutation %u left replay state at status %d\n",
                      mutation, (int)status);
        close_session(&env);
        return 1;
    }
    CHECK(right.app.telems == 1);
    close_session(&env);
    return 0;
}

static int test_protected_header_mutations(void)
{
    const dmp_time_ms now = 20000U;

    for (unsigned mutation = 0U; mutation < 9U; ++mutation) {
        if (protected_header_mutation_case(mutation, now) != 0) {
            return 1;
        }
    }
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
    uint8_t synced[FRAME_CAP + 1U];
    size_t core_n = 0U;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_parse_result parsed;

    if (!unwrap_core(framed, n, core, sizeof core, &core_n, now)) {
        if (n >= FRAME_CAP) {
            return 0;
        }
        synced[0] = 0U;
        memcpy(synced + 1U, framed, n);
        if (!unwrap_core(synced, n + 1U, core, sizeof core, &core_n, now)) {
            return 0;
        }
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
    uint8_t synced[FRAME_CAP + 1U];
    size_t core_n = 0U;
    size_t cursor = 0U;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_parse_result parsed;
    int found = 0;
    uint32_t wire = 0U;

    if (status_out == NULL) {
        return 0;
    }
    if (!unwrap_core(framed, n, core, sizeof core, &core_n, now)) {
        if (n >= FRAME_CAP) {
            return 0;
        }
        synced[0] = 0U;
        memcpy(synced + 1U, framed, n);
        if (!unwrap_core(synced, n + 1U, core, sizeof core, &core_n, now)) {
            return 0;
        }
    }
    memset(&view, 0, sizeof view);
    limits.max_frame_bytes = MTU;
    limits.max_message_bytes = MESSAGE;
    limits.max_fragments = 32U;
    parsed = dmp_core_parse(span(core, core_n), &limits, &view);
    if (parsed.status != DMP_OK) {
        return 0;
    }
    if (view.fields.type != DMP_TYPE_ERR ||
        (view.fields.options & DMP_OPT_SECURITY) == 0U) {
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
    if ((wire >= 64U) != ((view.fields.options & DMP_OPT_ACK_REQ) != 0U)) {
        return 0;
    }
    *status_out = wire;
    return 1;
}

static int protected_frame_type_seq(const uint8_t *framed, size_t n, dmp_time_ms now,
                                    uint8_t *type_out, uint32_t *seq_out)
{
    uint8_t core[MTU];
    uint8_t synced[FRAME_CAP + 1U];
    size_t core_n = 0U;
    dmp_core_limits limits = {MTU, MESSAGE, 32U};
    dmp_frame_view view;
    dmp_parse_result parsed;

    if (!unwrap_core(framed, n, core, sizeof core, &core_n, now)) {
        if (n >= FRAME_CAP) {
            return 0;
        }
        synced[0] = 0U;
        memcpy(synced + 1U, framed, n);
        if (!unwrap_core(synced, n + 1U, core, sizeof core, &core_n, now)) {
            return 0;
        }
    }
    memset(&view, 0, sizeof view);
    parsed = dmp_core_parse(span(core, core_n), &limits, &view);
    if (parsed.status != DMP_OK || parsed.offset != core_n ||
        (view.fields.options & DMP_OPT_SECURITY) == 0U) {
        return 0;
    }
    if (type_out != NULL) {
        *type_out = view.fields.type;
    }
    if (seq_out != NULL) {
        *seq_out = view.fields.seq;
    }
    return 1;
}

static size_t encode_test_uleb32(uint32_t value, uint8_t *out)
{
    size_t size = 0U;
    do {
        uint8_t byte = (uint8_t)(value & 0x7FU);
        value >>= 7;
        if (value != 0U) {
            byte |= 0x80U;
        }
        out[size++] = byte;
    } while (value != 0U);
    return size;
}

static int seal_sample_result(session *env, uint32_t attempt, uint32_t own_seq,
                              uint32_t reply_seq, uint32_t service, dmp_bytes payload,
                              uint8_t wrapped[FRAME_CAP], size_t *wrapped_n)
{
    dmp_frame_spec spec;
    uint8_t extensions[16];
    uint8_t value[5];
    uint8_t sealed[MTU];
    size_t value_n;
    size_t ext_n = 0U;
    size_t sealed_n = 0U;

    if (env == NULL || wrapped_n == NULL || (payload.size != 0U && payload.data == NULL)) {
        return 0;
    }
    value_n = encode_test_uleb32(reply_seq, value);
    extensions[ext_n++] = 0x05U; /* REPLY_TO, compact SEC-1 form. */
    extensions[ext_n++] = (uint8_t)value_n;
    memcpy(extensions + ext_n, value, value_n);
    ext_n += value_n;
    if (service != 1U) {
        value_n = encode_test_uleb32(service, value);
        extensions[ext_n++] = 0x11U; /* Explicit nondefault SERVICE. */
        extensions[ext_n++] = (uint8_t)value_n;
        memcpy(extensions + ext_n, value, value_n);
        ext_n += value_n;
    }
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_RSP;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_EXT);
    spec.fields.seq = own_seq;
    spec.extensions = span(extensions, ext_n);
    spec.payload = payload;
    if (dmp_hs_seal_logical(env->initiator, attempt, &spec, sealed, sizeof sealed, &sealed_n) !=
            DMP_HS_OK ||
        !wrap_core(sealed, sealed_n, wrapped, FRAME_CAP, wrapped_n)) {
        return 0;
    }
    return 1;
}

static int seal_sample_result_fragment(session *env, uint32_t attempt, uint32_t own_seq,
                                       uint32_t reply_seq, uint32_t fragment_index,
                                       uint32_t chunk_size, uint32_t total_size, dmp_bytes payload,
                                       uint8_t wrapped[FRAME_CAP], size_t *wrapped_n)
{
    dmp_frame_spec spec;
    uint8_t extensions[8];
    uint8_t value[5];
    uint8_t sealed[MTU];
    size_t value_n;
    size_t ext_n = 0U;
    size_t sealed_n = 0U;

    if (env == NULL || wrapped_n == NULL || (payload.size != 0U && payload.data == NULL)) {
        return 0;
    }
    value_n = encode_test_uleb32(reply_seq, value);
    extensions[ext_n++] = 0x05U; /* REPLY_TO, compact SEC-1 form. */
    extensions[ext_n++] = (uint8_t)value_n;
    memcpy(extensions + ext_n, value, value_n);
    ext_n += value_n;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_RSP;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_FRAG | DMP_OPT_EXT);
    spec.fields.seq = own_seq;
    spec.fields.fragment.index = fragment_index;
    spec.fields.fragment.chunk_size = chunk_size;
    spec.fields.fragment.total_size = total_size;
    spec.extensions = span(extensions, ext_n);
    spec.payload = payload;
    if (dmp_hs_seal_logical(env->initiator, attempt, &spec, sealed, sizeof sealed, &sealed_n) !=
            DMP_HS_OK ||
        !wrap_core(sealed, sealed_n, wrapped, FRAME_CAP, wrapped_n)) {
        return 0;
    }
    return 1;
}

static int expect_request_rejection(session *env, uint32_t seq, uint8_t options,
                                    dmp_bytes payload, int with_descriptor,
                                    uint32_t expected_status, dmp_time_ms now)
{
    dmp_frame_spec spec;
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    int queued = left.wire.n;
    uint32_t wire_status = 0U;

    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | options);
    spec.fields.seq = seq;
    spec.payload = payload;
    if (with_descriptor) {
        spec.fields.descriptor.flags = 3U;
        spec.fields.descriptor.codec = 0U;
        spec.fields.descriptor.schema = 42U;
        spec.fields.descriptor.schema_version = 1U;
    }
    if (dmp_hs_seal_logical(env->responder, 0U, &spec, sealed, sizeof sealed, &sealed_n) !=
            DMP_HS_OK ||
        !wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) ||
        dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), now) != DMP_OK) {
        return 0;
    }
    left.wire.now = now;
    if (dmp_endpoint_poll(&left.endpoint, now) != DMP_OK || left.wire.n != queued + 1 ||
        !protected_err_status(left.wire.q[queued].frame, left.wire.q[queued].len, now,
                              &wire_status)) {
        return 0;
    }
    return wire_status == expected_status;
}

static int test_protected_sample_no_sample(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t read = SAMPLE1_READ;
    uint8_t core[MTU];
    size_t core_n = 0U;
    dmp_core_limits limits = {MTU, MESSAGE, 32U};
    dmp_frame_view view;
    dmp_parse_result parsed;
    dmp_reliability_handle first;
    dmp_reliability_handle second;
    uint32_t status = 0U;
    dmp_time_ms now = 20000U;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);

    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(&read, sizeof read), now, &first) ==
          DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1 && left.app.have_pending);

    CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, true, 64U,
                                span(NULL, 0U), now) == DMP_OK);
    left.app.have_pending = 0;
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 1);
    CHECK(unwrap_core(left.wire.q[0].frame, left.wire.q[0].len, core, sizeof core,
                      &core_n, now));
    memset(&view, 0, sizeof view);
    parsed = dmp_core_parse(span(core, core_n), &limits, &view);
    CHECK(parsed.status == DMP_OK && parsed.offset == core_n);
    CHECK(view.fields.type == DMP_TYPE_ERR);
    CHECK((view.fields.options & DMP_OPT_SECURITY) != 0U);
    CHECK(view.payload.size == 0U);
    CHECK(protected_err_status(left.wire.q[0].frame, left.wire.q[0].len, now, &status));
    CHECK(status == 64U);

    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(right.app.results == 1);
    CHECK(right.app.last_status == 64U);
    CHECK(right.app.result_n == 0U);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);

    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(&read, sizeof read), now + 1U,
                                  &second) == DMP_OK);
    CHECK(first.slot != second.slot || first.generation != second.generation);
    CHECK(pump(now + 1U, 4) == 0);
    CHECK(left.app.accepts == 2);
    CHECK(right.app.results == 2);
    CHECK(right.app.last_status == 0U);
    CHECK(right.app.result_n == sizeof READ_RSP);
    CHECK(memcmp(right.app.result, READ_RSP, sizeof READ_RSP) == 0);
    close_session(&env);
    return 0;
}

static int test_protected_sample_initialization(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    sample_tracker state = {0};
    uint32_t index = 0U;
    uint32_t next_init = 0U;
    uint32_t next_resp = 0U;
    uint8_t read[SAMPLE1_READ_BYTES];
    uint8_t response[SAMPLE1_READ_BYTES];
    uint8_t telem[SAMPLE1_TELEM_BYTES];
    dmp_reliability_handle first;
    dmp_reliability_handle second;
    dmp_time_ms now = 20000U;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node_slots(&left, 1, 64U, 16U, now, 2U) == 0);
    CHECK(boot_node_slots(&right, 0, 64U, 16U, now, 2U) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_set_drain_ms(&left.endpoint, 30000U) == DMP_OK);
    CHECK(dmp_endpoint_set_drain_ms(&right.endpoint, 30000U) == DMP_OK);
    right.sample_state = &state;

    CHECK(sample1_telem(telem, 9U, 1U, 100U) == sizeof telem);
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now) == DMP_OK);
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(right.app.telems == 1);
    CHECK(sample_observe_telem(&state, span(telem, sizeof telem)) == 0);
    CHECK(state.synchronized == 0 && state.discarded == 1);

    CHECK(sample1_read_req(read) == 1U);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(read, 1U), now, &first) == DMP_OK);
    right.sample_designated = first;
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1 && left.app.have_pending);
    CHECK(sample1_read_rsp(response, 9U, 2U, 200U) == sizeof response);
    CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, false, 0U,
                                span(response, sizeof response), now) == DMP_OK);
    left.app.have_pending = 0;
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(right.app.results == 1);
    CHECK(right.app.sample_update_attempts == 1U && right.app.sample_update_status == 0);
    CHECK(state.synchronized == 1 && state.epoch == 9U && state.index == 2U &&
          state.value == 200U);
    CHECK(state.discarded == 1 && state.violations == 0);

    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);

    CHECK(sample1_telem(telem, 9U, 3U, 300U) == sizeof telem);
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now + 1U) ==
          DMP_OK);
    left.wire.now = now + 1U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 1U) == DMP_OK);
    CHECK(deliver_all(&left, &right, now + 1U) == 0);
    CHECK(sample_observe_telem(&state, span(telem, sizeof telem)) == 0);
    CHECK(state.index == 3U && state.value == 300U);

    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(read, 1U), now + 2U, &second) ==
          DMP_OK);
    right.sample_designated = second;
    right.wire.now = now + 2U;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 2U) == DMP_OK);
    CHECK(deliver_all(&right, &left, now + 2U) == 0);
    CHECK(left.app.accepts == 2 && left.app.have_pending);

    CHECK(sample1_telem(telem, 9U, 4U, 400U) == sizeof telem);
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now + 2U) ==
          DMP_OK);
    left.wire.now = now + 2U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 2U) == DMP_OK);
    CHECK(deliver_all(&left, &right, now + 2U) == 0);
    CHECK(sample_observe_telem(&state, span(telem, sizeof telem)) == 0);
    CHECK(state.index == 4U && state.value == 400U);

    CHECK(sample1_read_rsp(response, 9U, 3U, 350U) == sizeof response);
    CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, false, 0U,
                                span(response, sizeof response), now + 2U) == DMP_OK);
    left.app.have_pending = 0;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 2U) == DMP_OK);
    CHECK(deliver_all(&left, &right, now + 2U) == 0);
    CHECK(right.app.results == 2);
    CHECK(right.app.sample_update_attempts == 2U && right.app.sample_update_status == 0);
    CHECK(state.index == 4U && state.value == 400U && state.rollbacks == 1 &&
          state.violations == 0);

    right.wire.now = now + 2U;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 2U) == DMP_OK);
    CHECK(deliver_all(&right, &left, now + 2U) == 0);
    left.wire.now = now + 2U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 2U) == DMP_OK);

    /* A result callback commits SAMPLE-1 state before the serialized owner
     * can replace its association in the next operation. */
    env.now = now + 3U;
    CHECK(drive_rotation(&env, fixture, &next_init, &next_resp, 0x61U));
    CHECK(activate_at(&env, next_init, next_resp));
    CHECK(sample_rotate_association(&left, next_init, now + 3U) == DMP_OK);
    CHECK(sample_rotate_association(&right, next_resp, now + 3U) == DMP_OK);
    CHECK(right.app.sample_update_attempts == 2U && right.app.sample_update_status == 0);
    CHECK(state.synchronized == 0 && state.epoch == 9U && state.index == 4U &&
          state.value == 400U && state.rollbacks == 1 && state.violations == 0);
    CHECK(right.sample_designated.slot == UINT32_MAX &&
          right.sample_designated.generation == UINT32_MAX);

    /* The replacement is live, but the cached sample is not presented until
     * a new designated READ synchronizes the consumer again. */
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(read, 1U), now + 4U,
                                  &first) == DMP_OK);
    right.sample_designated = first;
    right.wire.now = now + 4U;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 4U) == DMP_OK);
    CHECK(deliver_all(&right, &left, now + 4U) == 0);
    CHECK(left.app.accepts == 3 && left.app.have_pending);
    CHECK(sample1_read_rsp(response, 9U, 4U, 400U) == sizeof response);
    CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, false, 0U,
                                span(response, sizeof response), now + 4U) == DMP_OK);
    left.app.have_pending = 0;
    left.wire.now = now + 4U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 4U) == DMP_OK);
    CHECK(deliver_all(&left, &right, now + 4U) == 0);
    CHECK(right.app.results == 3U && right.app.sample_update_attempts == 3U &&
          right.app.sample_update_status == 0);
    CHECK(state.synchronized == 1 && state.epoch == 9U && state.index == 4U &&
          state.value == 400U && state.rollbacks == 1 && state.violations == 0);
    right.wire.now = now + 4U;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 4U) == DMP_OK);
    CHECK(deliver_all(&right, &left, now + 4U) == 0);
    left.wire.now = now + 4U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 4U) == DMP_OK);
    close_session(&env);
    return 0;
}

static int test_protected_service2_immediate(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t request_payload[64];
    uint8_t response_payload[64];
    uint8_t invalid_service_payload = 0x5aU;
    uint8_t extensions[] = {0x11U, 0x01U, 0x03U};
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    uint8_t core[MTU];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    size_t core_n = 0U;
    size_t i;
    uint32_t round;
    dmp_time_ms now = 20000U;
    dmp_time_ms at = now;
    dmp_core_limits limits = {MTU, MESSAGE, 32U};
    dmp_frame_view view;
    dmp_parse_result parsed;
    dmp_frame_spec spec;
    dmp_reliability_handle request;

    memset(&env, 0, sizeof(env));
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    for (i = 0U; i < sizeof(request_payload); ++i) {
        request_payload[i] = (uint8_t)(0x40U + (uint8_t)(i & 0x3fU));
        response_payload[i] = (uint8_t)(0x80U + (uint8_t)(i & 0x3fU));
    }

    /* DIRECT-1's enabled OPAQUE service exercises an immediate reliable RSP
     * over the protected endpoint. Large request/result slicing is covered
     * separately by the P23 workload. */
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 2U,
                                  span(request_payload, sizeof(request_payload)), now,
                                  &request) == DMP_OK);
    for (round = 0U; round < 32U && left.app.accepts == 0; ++round) {
        at = now + round;
        right.wire.now = at;
        CHECK(dmp_endpoint_poll(&right.endpoint, at) == DMP_OK);
        CHECK(right.wire.n != 0);
        CHECK(deliver_all(&right, &left, at) == 0);
    }
    CHECK(left.app.accepts == 1 && left.app.request_service == 2U &&
          left.app.req_n == sizeof(request_payload));
    CHECK(memcmp(left.app.req, request_payload, sizeof(request_payload)) == 0);
    CHECK(left.wire.n == 0);
    CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, false, 0U,
                                span(response_payload, sizeof(response_payload)), now + round) ==
          DMP_OK);
    left.app.have_pending = 0;
    for (round = 0U; round < 32U && right.app.results == 0; ++round) {
        at = now + 20U + round;
        left.wire.now = at;
        CHECK(dmp_endpoint_poll(&left.endpoint, at) == DMP_OK);
        CHECK(left.wire.n != 0);
        for (i = 0U; i < (size_t)left.wire.n; ++i) {
            memset(&view, 0, sizeof(view));
            CHECK(unwrap_core(left.wire.q[i].frame, left.wire.q[i].len, core, sizeof(core),
                              &core_n, at));
            parsed = dmp_core_parse(span(core, core_n), &limits, &view);
            CHECK(parsed.status == DMP_OK && parsed.offset == core_n);
            CHECK(view.fields.type == DMP_TYPE_RSP);
            CHECK((view.fields.options & (DMP_OPT_SECURITY | DMP_OPT_ACK_REQ)) ==
                  (DMP_OPT_SECURITY | DMP_OPT_ACK_REQ));
        }
        CHECK(deliver_all(&left, &right, at) == 0);
    }
    CHECK(right.app.results == 1 && same_handle(right.app.result_request, request));
    CHECK(right.app.last_status == 0U && right.app.result_n == sizeof(response_payload));
    CHECK(memcmp(right.app.result, response_payload, sizeof(response_payload)) == 0);
    at += 1U;
    right.wire.now = at;
    CHECK(dmp_endpoint_poll(&right.endpoint, at) == DMP_OK);
    CHECK(right.wire.n != 0);
    for (i = 0U; i < (size_t)right.wire.n; ++i) {
        uint8_t type = 0U;
        CHECK(protected_frame_type_seq(right.wire.q[i].frame, right.wire.q[i].len, at,
                                       &type, NULL));
        CHECK(type == DMP_TYPE_ACK);
    }
    CHECK(deliver_all(&right, &left, now) == 0);
    at += 1U;
    left.wire.now = at;
    CHECK(dmp_endpoint_poll(&left.endpoint, at) == DMP_OK);

    /* A valid protected REQ for a service outside DIRECT-1 must be rejected
     * before the endpoint emits an application request callback. */
    memset(&spec, 0, sizeof(spec));
    spec.fields.type = DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_EXT);
    spec.fields.seq = 700U;
    spec.extensions = span(extensions, sizeof(extensions));
    spec.payload = span(&invalid_service_payload, sizeof(invalid_service_payload));
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof(sealed), &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof(wrapped), &wrapped_n));
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), at + 1U) == DMP_UNSUPPORTED);
    CHECK(right.app.accepts == 0 && right.wire.n == 0);

    close_session(&env);
    return 0;
}

static int test_protected_single_peer_service_and_bounds(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t payload[MAX_MESSAGE + 1U];
    uint8_t sealed[FRAME_CAP];
    uint8_t wrapped[FRAME_CAP];
    uint8_t small = 0x5aU;
    dmp_frame_spec spec;
    dmp_reliability_handle request;
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    size_t exact_frame_payload;
    size_t i;
    dmp_time_ms now = 20000U;

    memset(&env, 0, sizeof(env));
    memset(payload, 0x6d, sizeof(payload));
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    g_endpoint_test_message_bytes = MAX_MESSAGE;
    /* Decoded-Core MTU is 256 B; encoded_mtu is a separate 270 B buffer cap.
     * Stream R's exact encoded bound for a 256 B Core frame is 263 B. */
    g_endpoint_test_encoded_mtu = 270U;
    if (boot_node(&left, 1, 128U, 32U, now) != 0 ||
        boot_node(&right, 0, 128U, 32U, now) != 0) {
        g_endpoint_test_message_bytes = 0U;
        g_endpoint_test_encoded_mtu = 0U;
        close_session(&env);
        return 1;
    }
    g_endpoint_test_message_bytes = 0U;
    g_endpoint_test_encoded_mtu = 0U;
    if (bind_pair(&env, index) != 0) {
        close_session(&env);
        return 1;
    }

    CHECK(left.endpoint.profile.peers == 1U && right.endpoint.profile.peers == 1U);
    CHECK(left.endpoint.profile.forward_mtu == 256U &&
          right.endpoint.profile.forward_mtu == 256U);
    CHECK(left.endpoint.profile.encoded_mtu == 270U &&
          right.endpoint.profile.encoded_mtu == 270U);
    CHECK(left.endpoint.profile.message_bytes == MAX_MESSAGE &&
          right.endpoint.profile.message_bytes == MAX_MESSAGE);

    /* Service 1 (default) is admitted here; service 2 (explicit) is exercised
     * below by the exact-maximum request. */
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(&small, 1U), now,
                                  &request) == DMP_OK);
    /* Seal a protected default-service telemetry frame whose decoded core is
     * exactly forward_mtu. The next byte exceeds the Core bound and is rejected. */
    memset(&spec, 0, sizeof(spec));
    spec.fields.type = (uint8_t)DMP_TYPE_TELEM;
    spec.fields.options = DMP_OPT_SEQ;
    spec.fields.seq = 700U;
    spec.payload = span(payload, 0U);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof(sealed),
                              &sealed_n) == DMP_HS_OK);
    CHECK(sealed_n < right.endpoint.profile.forward_mtu);
    exact_frame_payload = right.endpoint.profile.forward_mtu - sealed_n;
    spec.payload = span(payload, exact_frame_payload);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof(sealed),
                              &sealed_n) == DMP_HS_OK);
    CHECK(sealed_n == right.endpoint.profile.forward_mtu);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof(wrapped), &wrapped_n));
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_OK);
    CHECK(right.app.telems == 1);

    spec.fields.seq++;
    spec.payload = span(payload, exact_frame_payload + 1U);
    CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof(sealed),
                              &sealed_n) == DMP_HS_OK);
    CHECK(sealed_n == right.endpoint.profile.forward_mtu + 1U);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof(wrapped), &wrapped_n));
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now + 1U) ==
          DMP_MALFORMED);
    CHECK(right.app.telems == 1);

    for (i = 0U; i < MAX_MESSAGE; ++i) {
        payload[i] = (uint8_t)(i * 17U + 3U);
    }
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 2U,
                                  span(payload, MAX_MESSAGE), now + 2U,
                                  &request) == DMP_OK);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 2U,
                                  span(payload, MAX_MESSAGE + 1U), now + 2U,
                                  &request) == DMP_LIMIT_EXHAUSTED);

    close_session(&env);
    return 0;
}

static int test_protected_sample_result_other_peer(void);

static int test_protected_different_sender_not_dispatched(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session target;
    session other;
    port_ctx port;
    uint32_t target_index = 0U;
    uint32_t other_index = 0U;
    uint32_t namespace_id = 0U;
    uint32_t local_id = 0U;
    uint32_t peer_id = 0U;
    uint64_t local_epoch = 0U;
    uint64_t peer_epoch = 0U;
    uint8_t payload = 0x6dU;
    uint8_t sealed[FRAME_CAP];
    uint8_t wrapped[FRAME_CAP];
    size_t sealed_size = 0U;
    size_t wrapped_size = 0U;
    dmp_frame_spec spec;
    dmp_peer_handle target_peer = {0U, 1U};
    dmp_time_ms now = 20000U;
    dmp_status status;

    memset(&target, 0, sizeof target);
    memset(&other, 0, sizeof other);
    g_endpoint_test_sender_id = 0U;
    if (fixture == NULL ||
        !make_pair(&target, &port, fixture, tune_test_sender_identity,
                   NULL, 0) ||
        !drive_nn_for_ids(&target, &target_index, ID_INIT, ID_RESP) ||
        !activate_for_ids(&target, target_index, ID_INIT, ID_RESP)) {
        close_session(&target);
        return 1;
    }
    if (boot_node(&left, 1, 64U, 16U, now) != 0 ||
        boot_node(&right, 0, 64U, 16U, now) != 0 ||
        bind_pair(&target, target_index) != 0) {
        close_session(&target);
        return 1;
    }

    /* This is a separately authenticated NNpsk0 peer with a distinct node ID
     * and distinct ephemeral material, sharing the real provider instance. */
    g_endpoint_test_sender_id = 0x22U;
    if (!make_pair(&other, &port, fixture, tune_test_sender_identity,
                   target.provider, 1) ||
        !drive_nn_for_ids(&other, &other_index, 0x22U, ID_RESP) ||
        !activate_for_ids(&other, other_index, 0x22U, ID_RESP)) {
        g_endpoint_test_sender_id = 0U;
        close_session(&other);
        close_session(&target);
        return 1;
    }
    g_endpoint_test_sender_id = 0U;
    CHECK(dmp_hs_traffic_identity(other.initiator, other_index, &namespace_id,
                                  &local_id, &peer_id, &local_epoch,
                                  &peer_epoch));
    CHECK(namespace_id == LOCAL_NS && local_id == 0x22U && peer_id == ID_RESP &&
          local_epoch != 0U && peer_epoch != 0U);

    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_TELEM;
    spec.fields.options = DMP_OPT_SEQ;
    spec.fields.seq = 1U;
    spec.payload = span(&payload, sizeof payload);
    CHECK(dmp_hs_seal_logical(other.initiator, other_index, &spec, sealed,
                              sizeof sealed, &sealed_size) == DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_size, wrapped, sizeof wrapped,
                    &wrapped_size));

    status = dmp_endpoint_rx_from(&right.endpoint, target_peer,
                                  span(wrapped, wrapped_size), now);
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    CHECK(right.app.telems == 0 && right.app.accepts == 0 &&
          right.wire.n == 0);

    /* The rejected sender must not disrupt the intended authenticated peer. */
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_TELEM;
    spec.fields.options = DMP_OPT_SEQ;
    spec.fields.seq = 1U;
    spec.payload = span(&payload, sizeof payload);
    CHECK(dmp_hs_seal_logical(target.initiator, target_index, &spec, sealed,
                              sizeof sealed, &sealed_size) == DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_size, wrapped, sizeof wrapped,
                    &wrapped_size));
    status = dmp_endpoint_rx_from(&right.endpoint, target_peer,
                                  span(wrapped, wrapped_size), now + 1U);
    CHECK(status == DMP_OK);
    CHECK(right.app.telems == 1 && right.app.accepts == 0);

    close_session(&other);
    close_session(&target);
    return test_protected_sample_result_other_peer();
}

static int test_protected_sample_result_other_peer(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session peers[2];
    port_ctx peer_ports[2];
    uint64_t admission_storage[2048];
    dmp_peer_handle handles[2] = {{0U, 1U}, {0U, 0U}};
    dmp_identity_context_config context;
    dmp_identity_handle associations[2];
    dmp_endpoint_grant grants[4];
    sample_tracker state = {1, 0, 0, 0, 7U, 4U, 400U};
    dmp_reliability_handle designated;
    dmp_message_key designated_key;
    uint32_t indices[2] = {0U, 0U};
    uint8_t read = SAMPLE1_READ;
    uint8_t response[SAMPLE1_READ_BYTES];
    uint8_t wrapped[FRAME_CAP];
    size_t wrapped_n = 0U;
    size_t i;
    dmp_time_ms now = 20000U;
    dmp_status status;
    uint32_t pump_round;
    int frame_i;

    memset(peers, 0, sizeof peers);
    memset(peer_ports, 0, sizeof peer_ports);
    memset(admission_storage, 0, sizeof admission_storage);
    g_endpoint_test_peer_count = 2U;
    g_endpoint_test_scratch_slots = 2U;
    g_endpoint_test_result_slots = 4U;
    g_endpoint_test_responder_admission_only = 1;
    g_endpoint_test_admission = NULL;
    g_endpoint_test_admission_storage = admission_storage;
    if (fixture == NULL || dmp_hs_admission_size() > sizeof admission_storage ||
        boot_node_slots(&right, 0, 64U, 16U, now, 8U) != 0) {
        goto fail;
    }
    g_endpoint_test_peer_count = 0U;
    g_endpoint_test_admission_storage = NULL;
    if (boot_node_slots(&left, 1, 64U, 16U, now, 2U) != 0) {
        goto fail;
    }
    if (!make_pair(&peers[0], &peer_ports[0], fixture, NULL, NULL, 0) ||
        !drive_nn(&peers[0], &indices[0]) || !activate(&peers[0], indices[0]) ||
        dmp_endpoint_bind_peer(&right.endpoint, handles[0], peers[0].responder,
                               0U) != DMP_OK ||
        dmp_endpoint_bind(&left.endpoint, peers[0].initiator, indices[0]) != DMP_OK) {
        goto fail;
    }

    memset(grants, 0, sizeof grants);
    grants[0].principal = ID_INIT;
    grants[0].service_id = 1U;
    grants[0].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_TELEM |
                       DMP_ENDPOINT_PERMIT_RESULT;
    grants[1].principal = ID_RESP;
    grants[1].service_id = 1U;
    grants[1].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    grants[2].principal = ID_INIT;
    grants[2].service_id = 2U;
    grants[2].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[3].principal = ID_RESP;
    grants[3].service_id = 2U;
    grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    if (dmp_endpoint_set_peer_grants(&right.endpoint, handles[0], grants, 4U) !=
        DMP_OK) {
        goto fail;
    }

    memset(&context, 0, sizeof context);
    context.local.namespace_id = LOCAL_NS;
    context.local.origin_id = ID_RESP;
    context.peer.namespace_id = LOCAL_NS;
    context.peer.origin_id = 0x22U;
    context.security = 1U;
    if (dmp_endpoint_add_peer(&right.endpoint, &context, now, &handles[1]) !=
        DMP_OK) {
        goto fail;
    }
    grants[0].principal = 0x22U;
    grants[2].principal = 0x22U;
    if (dmp_endpoint_set_peer_grants(&right.endpoint, handles[1], grants, 4U) !=
        DMP_OK) {
        goto fail;
    }
    for (i = 0U; i < sizeof g_endpoint_test_alt_attempt; ++i) {
        g_endpoint_test_alt_attempt[i] = (uint8_t)(0x30U + i);
    }
    for (i = 0U; i < sizeof g_endpoint_test_alt_init_ephemeral; ++i) {
        g_endpoint_test_alt_init_ephemeral[i] =
            (uint8_t)(fixture->init_ephemeral.data[i] ^ (uint8_t)(0x22U + i));
        g_endpoint_test_alt_resp_ephemeral[i] =
            (uint8_t)(fixture->resp_ephemeral.data[i] ^ (uint8_t)(0x25U + 3U * i));
    }
    g_endpoint_test_unique_entropy = 1;
    g_endpoint_test_sender_id = 0x22U;
    if (!make_pair(&peers[1], &peer_ports[1], fixture,
                   tune_test_sender_identity, peers[0].provider, 1) ||
        !drive_nn_for_ids(&peers[1], &indices[1], 0x22U, ID_RESP) ||
        !activate_for_ids(&peers[1], indices[1], 0x22U, ID_RESP)) {
        goto fail;
    }
    g_endpoint_test_unique_entropy = 0;
    g_endpoint_test_sender_id = 0U;
    peers[1].provider = NULL;
    if (dmp_endpoint_bind_peer(&right.endpoint, handles[1], peers[1].responder,
                               0U) != DMP_OK ||
        dmp_endpoint_set_peer_grants(&right.endpoint, handles[1], grants, 4U) !=
            DMP_OK) {
        goto fail;
    }
    CHECK(right.endpoint.peer_count == 2U &&
          dmp_hs_association_active(peers[0].responder) != 0 &&
          dmp_hs_association_active(peers[1].responder) != 0);
    CHECK(dmp_endpoint_peer_association(&right.endpoint, handles[0],
                                        &associations[0]) == DMP_OK);
    CHECK(dmp_endpoint_peer_association(&right.endpoint, handles[1],
                                        &associations[1]) == DMP_OK);
    CHECK(associations[0].slot != associations[1].slot ||
          associations[0].generation != associations[1].generation);
    g_endpoint_test_peer_count = 0U;
    g_endpoint_test_scratch_slots = 0U;
    g_endpoint_test_result_slots = 0U;
    g_endpoint_test_admission_storage = NULL;
    g_endpoint_test_admission = NULL;

    right.sample_state = &state;
    CHECK(sample1_read_req(&read) == 1U);
    status = dmp_endpoint_submit_req_to(&right.endpoint, handles[0], 1U,
                                        span(&read, sizeof read), now,
                                        &designated);
    CHECK(status == DMP_OK);
    right.sample_designated = designated;
    CHECK(designated.slot < right.endpoint.mem.sender_capacity);
    CHECK(right.senders[designated.slot].live != 0U);
    designated_key = right.senders[designated.slot].own;
    right.wire.now = now;
    for (i = 0U; i < 8U; ++i) {
        CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    }
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1 && left.app.have_pending != 0);
    right.wire.n = 0;

    CHECK(sample1_read_rsp(response, 7U, 5U, 500U) == sizeof response);
    CHECK(seal_sample_result(&peers[1], indices[1], 500U, designated_key.seq,
                             1U, span(response, sizeof response), wrapped,
                             &wrapped_n));
    status = dmp_endpoint_rx_from(&right.endpoint, handles[1],
                                  span(wrapped, wrapped_n), now + 1U);
    CHECK(status == DMP_OK);
    CHECK(right.app.results == 0 && right.app.sample_update_attempts == 0U &&
          right.app.telems == 0);
    CHECK(right.senders[designated.slot].live != 0U &&
          same_handle(right.sample_designated, designated));
    CHECK(state.synchronized == 1 && state.epoch == 7U && state.index == 4U &&
          state.value == 400U && state.discarded == 0 && state.rollbacks == 0 &&
          state.violations == 0);

    /* The designated producer remains usable after the other authenticated
     * peer's correlated-looking response was rejected. */
    CHECK(sample1_read_rsp(response, 7U, 5U, 500U) == sizeof response);
    CHECK(left.app.have_pending != 0);
    CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, false, 0U,
                                span(response, sizeof response), now + 2U) == DMP_OK);
    left.app.have_pending = 0;
    /* The left endpoint has not transmitted its initial per-peer Stream R
     * delimiter yet. Pump the real endpoint/transport while routing every
     * left-to-right frame explicitly to the designated producer peer. */
    for (pump_round = 0U; pump_round < 4U; ++pump_round) {
        left.wire.now = now + 2U;
        right.wire.now = now + 2U;
        CHECK(service(&left, now + 2U) == 0);
        CHECK(service(&right, now + 2U) == 0);
        CHECK(dmp_endpoint_poll(&left.endpoint, now + 2U) == DMP_OK);
        CHECK(dmp_endpoint_poll(&right.endpoint, now + 2U) == DMP_OK);
        for (frame_i = 0; frame_i < left.wire.n; ++frame_i) {
            status = dmp_endpoint_rx_from(&right.endpoint, handles[0],
                                          span(left.wire.q[frame_i].frame,
                                               left.wire.q[frame_i].len),
                                          now + 2U);
            CHECK(status == DMP_OK || status == DMP_INCOMPLETE ||
                  status == DMP_DUPLICATE);
        }
        left.wire.n = 0;
        CHECK(deliver_all(&right, &left, now + 2U) == 0);
        CHECK(complete_pending_completions(&left.wire, now + 2U) == 0);
        CHECK(complete_pending_completions(&right.wire, now + 2U) == 0);
    }
    CHECK(right.app.results == 1 && right.app.sample_update_attempts == 1U &&
          right.app.telems == 0);
    CHECK(right.senders[designated.slot].live == 0U &&
          state.synchronized == 1 && state.epoch == 7U && state.index == 5U &&
          state.value == 500U && state.discarded == 0 && state.rollbacks == 0 &&
          state.violations == 0);

    close_session(&peers[1]);
    close_session(&peers[0]);
    g_endpoint_test_responder_admission_only = 0;
    return 0;

fail:
    g_endpoint_test_unique_entropy = 0;
    g_endpoint_test_sender_id = 0U;
    g_endpoint_test_peer_count = 0U;
    g_endpoint_test_scratch_slots = 0U;
    g_endpoint_test_result_slots = 0U;
    g_endpoint_test_responder_admission_only = 0;
    g_endpoint_test_admission_storage = NULL;
    g_endpoint_test_admission = NULL;
    memset(&left, 0, sizeof left);
    memset(&right, 0, sizeof right);
    close_session(&peers[1]);
    close_session(&peers[0]);
    return 1;
}

static int test_protected_sample1_epoch_endpoint(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session initial;
    session replacement;
    port_ctx initial_port;
    port_ctx replacement_port;
    dmp_sample1_endpoint sample;
    dmp_sample1_endpoint_hooks hooks;
    sample1_store store;
    dmp_sample1_principal principal = {LOCAL_NS, ID_RESP};
    uint64_t admission_storage[2048];
    dmp_peer_handle first_peer = {0U, 1U};
    dmp_peer_handle next_peer;
    dmp_endpoint_grant left_grants[4];
    dmp_identity_context_config context;
    dmp_endpoint_grant grants[4];
    dmp_reliability_handle request;
    dmp_reliability_handle shared_service_request;
    dmp_reliability_handle stale_request = {0};
    dmp_message_key stale_request_key = {0};
    dmp_frame_spec spec;
    dmp_identity_handle association;
    dmp_identity_handle stale_association;
    dmp_status status;
    uint32_t initial_index = 0U;
    uint32_t replacement_index = 0U;
    uint32_t rotation_init = 0U;
    uint32_t rotation_resp = 0U;
    uint32_t observed_cid = 0U;
    uint32_t old_cid = 0U;
    uint32_t new_cid = 0U;
    uint8_t opened[FRAME_CAP];
    size_t opened_size = 0U;
    uint8_t read = DMP_SAMPLE1_READ_OPCODE;
    uint8_t service2_request_payload[] = {0xA1U, 0xB2U, 0xC3U};
    uint8_t service2_result_payload[] = {0xD4U, 0xE5U};
    uint8_t service2_frame_type = 0U;
    uint8_t stream_sync = 0U;
    uint8_t sealed[FRAME_CAP];
    uint8_t framed[FRAME_CAP];
    size_t sealed_size = 0U;
    size_t framed_size = 0U;
    dmp_time_ms now = 20000U;
    dmp_time_ms replacement_now;

    memset(admission_storage, 0, sizeof admission_storage);
    g_endpoint_test_peer_count = 2U;
    g_endpoint_test_async_borrow = 1;
    g_endpoint_test_admission_storage = admission_storage;
    g_endpoint_test_responder_admission_only = 1;
    CHECK(boot_node_slots(&right, 0, 64U, 16U, now, 4U) == 0);
    g_endpoint_test_async_borrow = 0;
    g_endpoint_test_peer_count = 0U;
    g_endpoint_test_admission_storage = NULL;
    if (fixture == NULL || !make_pair(&initial, &initial_port, fixture,
                                      NULL, NULL, 0) ||
        !drive_nn(&initial, &initial_index) || !activate(&initial, initial_index)) {
        close_session(&initial);
        g_endpoint_test_admission = NULL;
        return 1;
    }
    CHECK(boot_node_slots(&left, 1, 64U, 16U, now, 2U) == 0);
    CHECK(dmp_endpoint_bind(&left.endpoint, initial.initiator,
                            initial_index) == DMP_OK);
    CHECK(dmp_endpoint_bind_peer(&right.endpoint, first_peer,
                                 initial.responder, 0U) == DMP_OK);
    memset(left_grants, 0, sizeof left_grants);
    left_grants[0].principal = ID_INIT;
    left_grants[0].service_id = 1U;
    left_grants[0].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    left_grants[1].principal = ID_RESP;
    left_grants[1].service_id = 1U;
    left_grants[1].permit = DMP_ENDPOINT_PERMIT_TELEM | DMP_ENDPOINT_PERMIT_RESULT;
    left_grants[2].principal = ID_INIT;
    left_grants[2].service_id = 2U;
    left_grants[2].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    left_grants[3].principal = ID_RESP;
    left_grants[3].service_id = 2U;
    left_grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    CHECK(dmp_endpoint_set_grants(&left.endpoint, left_grants, 4U) == DMP_OK);
    memset(&store, 0, sizeof store);
    memset(&hooks, 0, sizeof hooks);
    hooks.user = &store;
    hooks.try_enter = sample1_store_try_enter;
    hooks.leave = sample1_store_leave;
    hooks.reserve_next = sample1_store_reserve;
    hooks.publish_telem = sample1_store_publish;
    CHECK(dmp_sample1_endpoint_init(&sample, &right.endpoint, principal,
                                    &hooks) == DMP_SAMPLE1_OWNER_OK);
    right.app.producer = 0;
    right.sample_endpoint = &sample;
    memset(grants, 0, sizeof grants);
    grants[0].principal = ID_INIT;
    grants[0].service_id = 1U;
    grants[0].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[1].principal = ID_RESP;
    grants[1].service_id = 1U;
    grants[1].permit = DMP_ENDPOINT_PERMIT_RESULT | DMP_ENDPOINT_PERMIT_TELEM;
    grants[2].principal = ID_INIT;
    grants[2].service_id = 2U;
    grants[2].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    grants[3].principal = ID_RESP;
    grants[3].service_id = 2U;
    grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    CHECK(dmp_endpoint_set_peer_grants(&right.endpoint, first_peer, grants,
                                       4U) == DMP_OK);

    /* Reserve the first durable epoch, bind its authenticated association,
     * publish telemetry, and answer a real protected READ through the adapter. */
    CHECK(dmp_sample1_endpoint_begin_epoch(&sample, now) == DMP_SAMPLE1_OWNER_OK);
    CHECK(store.durable_epoch == 1U && sample.owner.epoch == 1U);
    CHECK(dmp_sample1_endpoint_activate_peer(&sample, first_peer) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_endpoint_publish(&sample, UINT32_C(0x11223344), now) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(store.published_epoch == 1U && store.published_index == 1U &&
          store.published_value == UINT32_C(0x11223344));
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    /* Complete the delimiter before submitting the first borrowed application frame. */
    CHECK(complete_pending_completions(&right.wire, now) == 0);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(complete_pending_completions(&right.wire, now) == 0);
    CHECK(left.app.telems == 1);
    CHECK(left.app.telem_n == DMP_SAMPLE1_TELEM_BYTES &&
          sample1_load_u64(left.app.telem) == 1U &&
          sample1_load_u32(left.app.telem + 8U) == 1U &&
          sample1_load_u32(left.app.telem + 12U) == UINT32_C(0x11223344));
    CHECK(pump(now, 4) == 0);

    status = dmp_endpoint_submit_req(&left.endpoint, 1U, span(&read, 1U),
                                     now + 1U, &request);
    CHECK(status == DMP_OK);
    left.wire.now = now + 1U;
    right.wire.now = now + 1U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 1U) == DMP_OK);
    CHECK(deliver_all(&left, &right, now + 1U) == 0);
    CHECK(right.app.sample_owner_result == DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_endpoint_flush(&sample, now + 1U) == DMP_SAMPLE1_OWNER_OK);
    right.app.have_pending = 0;
    right.app.peer_pending_live[first_peer.slot] = 0U;
    CHECK(pump(now + 1U, 8) == 0);
    CHECK(left.app.results == 1 && left.app.last_status == 0U);
    {
        uint8_t expected[DMP_SAMPLE1_READ_BYTES];
        CHECK(sample1_read_rsp(expected, 1U, 1U, UINT32_C(0x11223344)) ==
              sizeof expected);
        CHECK(left.app.result_n == sizeof expected &&
              memcmp(left.app.result, expected, sizeof expected) == 0);
    }
    CHECK(pump(now + 2U, 4) == 0);

    /* A same-epoch READ arriving over the old, still-live draining SA remains
     * valid during its bounded retry window and must not stop the producer. */
    CHECK(dmp_endpoint_set_drain_ms(&left.endpoint, 30000U) == DMP_OK);
    CHECK(dmp_endpoint_set_peer_drain_ms(&right.endpoint, first_peer, 30000U) == DMP_OK);
    status = dmp_endpoint_submit_req(&left.endpoint, 1U, span(&read, 1U),
                                     now + 2U, &request);
    CHECK(status == DMP_OK);
    left.wire.now = now + 2U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 2U) == DMP_OK);
    CHECK(left.wire.n == 1);
    old_cid = dmp_hs_rx_cid(initial.responder, initial_index);
    if (!stream_protection(left.wire.q[0].frame, left.wire.q[0].len,
                           now + 2U, &observed_cid, NULL, NULL)) {
        (void)fprintf(stderr, "queued delayed READ is not a protected Core frame (len=%zu)\n",
                      left.wire.q[0].len);
    } else if (observed_cid != old_cid) {
        (void)fprintf(stderr, "queued delayed READ CID %u differs from old CID %u\n",
                      observed_cid, old_cid);
    }
    CHECK(drive_rotation(&initial, fixture, &rotation_init, &rotation_resp, 0xA6U));
    CHECK(activate_at(&initial, rotation_init, rotation_resp));
    new_cid = dmp_hs_rx_cid(initial.responder, rotation_resp);
    if (new_cid == old_cid) {
        (void)fprintf(stderr, "same-epoch rotation reused receive CID %u\n", old_cid);
    }
    CHECK(new_cid != old_cid);
    CHECK(dmp_endpoint_rotate(&left.endpoint, rotation_init, now + 3U) == DMP_OK);
    status = dmp_endpoint_rotate_peer(&right.endpoint, first_peer, rotation_resp,
                                      now + 3U);
    if (status != DMP_OK) {
        (void)fprintf(stderr, "same-epoch SAMPLE-1 rotation returned %s (%d), attempt=%u\n",
                      dmp_status_name(status), (int)status, rotation_resp);
    }
    CHECK(status == DMP_OK);
    CHECK(dmp_sample1_endpoint_activate_peer(&sample, first_peer) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_endpoint_peer_association(&right.endpoint, first_peer,
                                        &stale_association) == DMP_OK);
    CHECK(right.endpoint.peers[first_peer.slot].drain_live != 0U);
    CHECK(sample.peers[first_peer.slot].draining_epoch == sample.owner.epoch);
    if (right.endpoint.peers[first_peer.slot].drain_attempt != initial_index ||
        dmp_hs_rx_cid(right.endpoint.peers[first_peer.slot].association,
                      right.endpoint.peers[first_peer.slot].drain_attempt) != old_cid) {
        (void)fprintf(stderr,
                      "drain table mismatch: peer=%u active=%u drain=%u old=%u active_cid=%u drain_cid=%u frame_cid=%u\n",
                      first_peer.slot,
                      right.endpoint.peers[first_peer.slot].association_attempt,
                      right.endpoint.peers[first_peer.slot].drain_attempt,
                      initial_index,
                      dmp_hs_rx_cid(right.endpoint.peers[first_peer.slot].association,
                                    right.endpoint.peers[first_peer.slot].association_attempt),
                      dmp_hs_rx_cid(right.endpoint.peers[first_peer.slot].association,
                                    right.endpoint.peers[first_peer.slot].drain_attempt),
                      observed_cid);
    }
    CHECK(right.endpoint.peers[first_peer.slot].drain_attempt == initial_index);
    status = dmp_endpoint_validate_association(
        &right.endpoint, right.endpoint.peers[first_peer.slot].drain_context,
        LOCAL_NS, ID_RESP);
    CHECK(status == DMP_OK);
    right.wire.now = now + 3U;
    CHECK(left.wire.n == 1);
    status = dmp_endpoint_rx_from(
        &right.endpoint, first_peer,
        span(left.wire.q[0].frame, left.wire.q[0].len), now + 3U);
    if (status != DMP_OK && status != DMP_INCOMPLETE && status != DMP_DUPLICATE) {
        (void)fprintf(stderr, "draining SAMPLE-1 READ RX returned %s (%d)\n",
                      dmp_status_name(status), (int)status);
    }
    CHECK(status == DMP_OK || status == DMP_INCOMPLETE || status == DMP_DUPLICATE);
    left.wire.n = 0;
    CHECK(right.app.sample_owner_result == DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_endpoint_flush(&sample, now + 3U) == DMP_SAMPLE1_OWNER_OK);
    right.app.have_pending = 0;
    right.app.peer_pending_live[first_peer.slot] = 0U;
    CHECK(pump(now + 3U, 8) == 0);
    CHECK(left.app.results == 2 && left.app.last_status == 0U);

    /* A reliable service-2 request shares this SEC-1 association. The remote
     * accepts it but leaves the result pending while the producer prepares a
     * new SAMPLE-1 epoch. The epoch fence must report the request as unknown
     * and retire it with the old association instead of replaying it later. */
    {
        dmp_reliability_sender_slot *sender;
        CHECK(dmp_endpoint_submit_req_to(&right.endpoint, first_peer, 2U,
                                         span(service2_request_payload,
                                              sizeof service2_request_payload),
                                         now + 4U, &shared_service_request) == DMP_OK);
        right.wire.now = now + 4U;
        left.wire.now = now + 4U;
        CHECK(dmp_endpoint_poll(&right.endpoint, now + 4U) == DMP_OK);
        CHECK(deliver_all(&right, &left, now + 4U) == 0);
        CHECK(left.app.accepts == 1 && left.app.request_service == 2U &&
              left.app.req_n == sizeof service2_request_payload &&
              memcmp(left.app.req, service2_request_payload,
                     sizeof service2_request_payload) == 0);
        CHECK(dmp_endpoint_poll(&left.endpoint, now + 4U) == DMP_OK);
        CHECK(deliver_all(&left, &right, now + 4U) == 0);
        CHECK(complete_pending_completions(&right.wire, now + 4U) == 0);
        CHECK(dmp_endpoint_poll(&right.endpoint, now + 4U) == DMP_OK);
        CHECK(shared_service_request.slot < right.endpoint.mem.sender_capacity);
        sender = &right.endpoint.mem.senders[shared_service_request.slot];
        if (sender->live == 0U || sender->generation != shared_service_request.generation ||
            sender->kind != DMP_REL_SENDER_REQUEST || sender->service_id != 2U ||
            (sender->phase != DMP_REL_PHASE_AWAIT_RECEIPT &&
             sender->phase != DMP_REL_PHASE_AWAIT_RESULT) || !sender->possibly_sent) {
            (void)fprintf(stderr,
                          "service-2 request not in flight: live=%u generation=%llu/%llu kind=%u service=%u phase=%u possibly_sent=%u\n",
                          (unsigned)sender->live,
                          (unsigned long long)sender->generation,
                          (unsigned long long)shared_service_request.generation,
                          (unsigned)sender->kind, (unsigned)sender->service_id,
                          (unsigned)sender->phase, (unsigned)sender->possibly_sent);
        }
        CHECK(sender->live != 0U &&
              sender->generation == shared_service_request.generation &&
              sender->kind == DMP_REL_SENDER_REQUEST && sender->service_id == 2U &&
              (sender->phase == DMP_REL_PHASE_AWAIT_RECEIPT ||
               sender->phase == DMP_REL_PHASE_AWAIT_RESULT) && sender->possibly_sent);
        CHECK(right.app.unknowns == 0);
    }

    /* A borrowed epoch-1 frame must settle before epoch 2 can activate. */
    CHECK(dmp_sample1_endpoint_publish(&sample, UINT32_C(0xAABBCCDD), now + 4U) ==
          DMP_SAMPLE1_OWNER_OK);
    right.wire.completion_outcome = DMP_TX_POSSIBLY_TRANSMITTED;
    right.wire.now = now + 4U;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 4U) == DMP_OK);
    CHECK(right.wire.pending_count == 1U);
    CHECK(dmp_endpoint_peer_fence_status(&right.endpoint, first_peer) ==
          DMP_INVALID_ARGUMENT);
    {
        dmp_sample1_owner_result rollover =
            dmp_sample1_endpoint_begin_epoch(&sample, now + 5U);
        CHECK(rollover == DMP_SAMPLE1_OWNER_BUSY);
    }
    CHECK(dmp_endpoint_peer_fence_status(&right.endpoint, first_peer) == DMP_BUSY);
    CHECK(right.app.unknowns == 1 &&
          right.app.last_unknown_peer.slot == first_peer.slot &&
          right.app.last_unknown_peer.generation == first_peer.generation);
    CHECK(shared_service_request.slot < right.endpoint.mem.sender_capacity &&
          right.endpoint.mem.senders[shared_service_request.slot].live == 0U);
    /* The remote application can finish work it accepted before the fence.
     * Keep that old-SA result queued until a replacement SA is active so the
     * receiver proves it cannot satisfy the canceled request through the new
     * peer association. */
    CHECK(left.app.have_pending != 0);
    CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, false, 0U,
                               span(service2_result_payload,
                                    sizeof service2_result_payload),
                               now + 6U) == DMP_OK);
    left.wire.now = now + 6U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 6U) == DMP_OK);
    CHECK(left.wire.n == 1);
    if (!stream_protection(left.wire.q[0].frame, left.wire.q[0].len,
                           now + 6U, &observed_cid, NULL, NULL)) {
        CHECK(left.wire.q[0].len == 1U && left.wire.q[0].frame[0] == 0U);
        CHECK(complete_pending_completions(&left.wire, now + 6U) == 0);
        left.wire.n = 0;
        CHECK(dmp_endpoint_poll(&left.endpoint, now + 6U) == DMP_OK);
        CHECK(left.wire.n == 1);
    }
    CHECK(stream_protection(left.wire.q[0].frame, left.wire.q[0].len,
                            now + 6U, &observed_cid, NULL,
                            &service2_frame_type));
    CHECK(observed_cid == new_cid);
    CHECK(service2_frame_type == DMP_TYPE_RSP);
    CHECK(complete_pending_completions(&left.wire, now + 6U) == 0);
    CHECK(store.durable_epoch == 2U && sample.owner.epoch == 1U &&
          !sample.owner.active && !sample.owner.stopped);
    CHECK(right.wire.pending_count == 1U);
    CHECK(complete_pending_completions(&right.wire, now + 6U) == 0);
    CHECK(dmp_endpoint_peer_fence_status(&right.endpoint, first_peer) == DMP_OK);
    CHECK(dmp_sample1_endpoint_begin_epoch(&sample, now + 7U) == DMP_SAMPLE1_OWNER_OK);
    CHECK(store.durable_epoch == 2U && sample.owner.epoch == 2U && sample.owner.active);
    {
        dmp_status old_peer_status =
            dmp_endpoint_peer_association(&right.endpoint, first_peer, &association);
        CHECK(old_peer_status == DMP_AUTHENTICATION_FAILURE ||
              old_peer_status == DMP_STALE_HANDLE);
    }
    CHECK(dmp_sample1_endpoint_activate_peer(&sample, first_peer) ==
          DMP_SAMPLE1_OWNER_NOT_READY);
    {
        dmp_time_ms peer_reuse_delay =
            right.endpoint.profile.result_cache_ms + right.endpoint.profile.send_horizon_ms;
        dmp_time_ms late_result_delay = right.endpoint.profile.correlation_ms +
                                        right.endpoint.profile.late_result_ms;
        if (peer_reuse_delay < late_result_delay) {
            peer_reuse_delay = late_result_delay;
        }
        /* The new service-2 UNKNOWN also pins the identity through late-result expiry. */
        replacement_now = now + 7U + peer_reuse_delay + 10U;
    }
    CHECK(service(&right, replacement_now) == 0);
    CHECK(dmp_endpoint_poll(&right.endpoint, replacement_now) == DMP_OK);

    memset(&context, 0, sizeof context);
    context.local.namespace_id = LOCAL_NS;
    context.local.origin_id = ID_RESP;
    context.peer.namespace_id = LOCAL_NS;
    context.peer.origin_id = ID_INIT;
    context.security = 1U;
    status = dmp_endpoint_add_peer(&right.endpoint, &context, replacement_now + 1U,
                                   &next_peer);
    if (status != DMP_OK) {
        (void)fprintf(stderr, "epoch rollover peer reuse returned %s (%d)\n",
                      dmp_status_name(status), (int)status);
    }
    CHECK(status == DMP_OK);
    CHECK(next_peer.slot == first_peer.slot &&
          next_peer.generation != first_peer.generation);
    CHECK(make_pair(&replacement, &replacement_port, fixture, NULL,
                    initial.provider, 0));
    CHECK(drive_nn(&replacement, &replacement_index));
    CHECK(activate(&replacement, replacement_index));
    CHECK(dmp_endpoint_bind_peer(&right.endpoint, next_peer,
                                 replacement.responder, 0U) == DMP_OK);
    CHECK(dmp_endpoint_set_peer_grants(&right.endpoint, next_peer, grants,
                                       2U) == DMP_OK);
    CHECK(dmp_sample1_endpoint_activate_peer(&sample, next_peer) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_hs_rx_cid(replacement.responder, replacement_index) != observed_cid);
    CHECK(dmp_endpoint_rx_from(&right.endpoint, next_peer,
                               span(&stream_sync, sizeof stream_sync),
                               replacement_now + 2U) == DMP_OK);
    status = dmp_endpoint_rx_from(
        &right.endpoint, next_peer,
        span(left.wire.q[0].frame, left.wire.q[0].len), replacement_now + 2U);
    if (status != DMP_AUTHENTICATION_FAILURE) {
        (void)fprintf(stderr, "late old-SA service-2 RSP RX returned %s (%d)\n",
                      dmp_status_name(status), (int)status);
    }
    CHECK(status == DMP_AUTHENTICATION_FAILURE);
    left.wire.n = 0;
    CHECK(right.app.results == 0 &&
          right.endpoint.mem.senders[shared_service_request.slot].live == 0U);
    stale_request.generation = 1U;
    stale_request.peer = next_peer;
    CHECK(dmp_sample1_epoch_owner_accept_read(&sample.owner, stale_association,
                                              stale_request, stale_request_key,
                                              replacement_now + 2U) ==
          DMP_SAMPLE1_OWNER_NOT_READY);
    CHECK(sample.owner.active && !sample.owner.stopped && sample.owner.epoch == 2U &&
          store.locked == 0U);
    /* The uncertain outcome above belongs to the old borrowed epoch-1
     * telemetry. Settle the replacement peer's delimiter definitively. */
    right.wire.completion_outcome = DMP_TX_TRANSMITTED;
    CHECK(dmp_sample1_endpoint_publish(&sample, UINT32_C(0x55667788), replacement_now + 3U) ==
          DMP_SAMPLE1_OWNER_OK);
    CHECK(store.published_epoch == 2U && store.published_index == 1U &&
          store.published_value == UINT32_C(0x55667788));
    right.wire.n = 0;
    right.wire.now = replacement_now + 3U;
    CHECK(dmp_endpoint_poll(&right.endpoint, replacement_now + 3U) == DMP_OK);
    CHECK(right.wire.pending_count == 1);
    CHECK(complete_pending_completions(&right.wire, replacement_now + 3U) == 0);
    CHECK(dmp_endpoint_poll(&right.endpoint, replacement_now + 3U) == DMP_OK);
    CHECK(wire_opens_type(&right.wire, replacement.initiator,
                          replacement_index, DMP_TYPE_TELEM, opened,
                          sizeof opened, &opened_size, replacement_now + 3U));
    CHECK(opened_size == DMP_SAMPLE1_TELEM_BYTES &&
          sample1_load_u64(opened) == 2U && sample1_load_u32(opened + 8U) == 1U &&
          sample1_load_u32(opened + 12U) == UINT32_C(0x55667788));
    CHECK(right.wire.pending_count == 1);
    CHECK(complete_pending_completions(&right.wire, replacement_now + 3U) == 0);
    right.wire.n = 0;

    memset(&spec, 0, sizeof spec);
    spec.fields.type = DMP_TYPE_REQ;
    spec.fields.options = DMP_OPT_SEQ | DMP_OPT_ACK_REQ;
    spec.fields.seq = 1U;
    spec.payload = span(&read, 1U);
    CHECK(dmp_hs_seal_logical(replacement.initiator, replacement_index,
                              &spec, sealed, sizeof sealed, &sealed_size) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_size, framed, sizeof framed, &framed_size));
    right.wire.now = replacement_now + 4U;
    status = dmp_endpoint_rx_from(&right.endpoint, next_peer,
                                  span(framed, framed_size), replacement_now + 4U);
    CHECK(status == DMP_OK);
    CHECK(right.app.sample_owner_result == DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_sample1_endpoint_flush(&sample, replacement_now + 4U) == DMP_SAMPLE1_OWNER_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, replacement_now + 4U) == DMP_OK);
    CHECK(wire_opens_type(&right.wire, replacement.initiator,
                          replacement_index, DMP_TYPE_RSP, opened,
                          sizeof opened, &opened_size, replacement_now + 4U));
    CHECK(opened_size == DMP_SAMPLE1_READ_BYTES && opened[0] == DMP_SAMPLE1_READ_OPCODE &&
          sample1_load_u64(opened + 1U) == 2U &&
          sample1_load_u32(opened + 9U) == 1U &&
          sample1_load_u32(opened + 13U) == UINT32_C(0x55667788));
    CHECK(store.locked == 0U);
    close_session(&replacement);
    close_session(&initial);
    g_endpoint_test_admission = NULL;
    return 0;
}

static int test_endpoint_shared_admission_four_pending(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session peers[5];
    port_ctx peer_ports[5];
    uint64_t admission_storage[2048];
    dmp_peer_handle handles[4];
    dmp_identity_context_config context;
    dmp_hs_completion held_completions[2];
    dmp_hs_completion refused_completion;
    dmp_hs_completion fifth_completion;
    const uint8_t *inbound_m1[2] = {NULL, NULL};
    size_t inbound_m1_len[2] = {0U, 0U};
    uint64_t inbound_boot_epoch[2] = {0U, 0U};
    const uint8_t *local_m2[2] = {NULL, NULL};
    size_t local_m2_len[2] = {0U, 0U};
    uint32_t peer_ids[4] = {ID_INIT, 0x41U, 0x42U, 0x43U};
    uint32_t initiator_indices[4] = {0U};
    uint32_t responder_indices[2] = {0U};
    uint32_t fifth_index = 0U;
    uint32_t i;
    size_t flight_len = 0U;
    const uint8_t *flight;
    dmp_hs_ingress ingress;
    dmp_hs_status hs_status;
    dmp_time_ms now = 19000U;

    memset(peers, 0, sizeof peers);
    memset(peer_ports, 0, sizeof peer_ports);
    memset(admission_storage, 0, sizeof admission_storage);
    memset(handles, 0, sizeof handles);
    memset(held_completions, 0, sizeof held_completions);
    memset(&refused_completion, 0, sizeof refused_completion);
    memset(&fifth_completion, 0, sizeof fifth_completion);
    memset(&right, 0, sizeof right);
    g_endpoint_test_peer_count = 4U;
    g_endpoint_test_scratch_slots = 2U;
    g_endpoint_test_result_slots = 4U;
    g_endpoint_test_handshake_pending = DMP_MULTI_PEER_PENDING_ATTEMPTS;
    g_endpoint_test_message_bytes = DMP_MULTI_PEER_MESSAGE_BYTES;
    g_endpoint_test_responder_admission_only = 1;
    g_endpoint_test_initiator_admission_only = 0;
    g_endpoint_test_admission = NULL;
    g_endpoint_test_admission_storage = admission_storage;
    if (fixture == NULL || dmp_hs_admission_size() > sizeof admission_storage ||
        boot_node_slots(&right, 0, DMP_MULTI_PEER_CHUNK_BYTES,
                        DMP_MULTI_PEER_FRAGMENTS, now, 8U) != 0 ||
        dmp_endpoint_handshake_admission(&right.endpoint) !=
            g_endpoint_test_admission) {
        (void)fprintf(stderr, "shared SEC-1 admission setup failed\n");
        goto fail;
    }

    /* Peer IDs follow the profile total: handle zero is the configured
     * default peer, while the other three are explicit endpoint peers. */
    handles[0].slot = 0U;
    handles[0].generation = 1U;
    for (i = 1U; i < 4U; i++) {
        memset(&context, 0, sizeof context);
        context.local.namespace_id = LOCAL_NS;
        context.local.origin_id = ID_RESP;
        context.peer.namespace_id = LOCAL_NS;
        context.peer.origin_id = peer_ids[i];
        context.security = 1U;
        if (dmp_endpoint_add_peer(&right.endpoint, &context, now,
                                  &handles[i]) != DMP_OK) {
            (void)fprintf(stderr, "endpoint peer slot %u setup failed\n",
                          (unsigned)i);
            goto fail;
        }
    }
    if (right.endpoint.profile.peers != 4U || right.endpoint.peer_count != 4U) {
        (void)fprintf(stderr, "four-peer endpoint geometry mismatch\n");
        goto fail;
    }

    /* Counts are endpoint totals across roles. Prepare two inbound responder
     * flights and two local initiator schedules before holding any reads: a
     * local schedule also needs a scratch slot while it builds flight one. */
    for (i = 0U; i < 2U; i++) {
        size_t entropy_index;
        uint32_t peer_id = peer_ids[i];
        for (entropy_index = 0U;
             entropy_index < sizeof g_endpoint_test_alt_attempt;
             entropy_index++) {
            g_endpoint_test_alt_attempt[entropy_index] =
                (uint8_t)(0x60U + i * 17U + entropy_index);
        }
        for (entropy_index = 0U;
             entropy_index < sizeof g_endpoint_test_alt_init_ephemeral;
             entropy_index++) {
            g_endpoint_test_alt_init_ephemeral[entropy_index] =
                (uint8_t)(fixture->init_ephemeral.data[entropy_index] ^
                          (uint8_t)(peer_id + entropy_index));
            g_endpoint_test_alt_resp_ephemeral[entropy_index] =
                (uint8_t)(fixture->resp_ephemeral.data[entropy_index] ^
                          (uint8_t)(peer_id + 3U * entropy_index));
        }
        g_endpoint_test_unique_entropy = 1;
        g_endpoint_test_sender_id = peer_id;
        if (!make_pair(&peers[i], &peer_ports[i], fixture,
                       tune_test_sender_identity,
                       i == 0U ? NULL : peers[0].provider, 1) ||
            !dmp_hs_uses_admission(peers[i].responder,
                                   g_endpoint_test_admission) ||
            dmp_hs_uses_admission(peers[i].initiator,
                                  g_endpoint_test_admission) ||
            dmp_hs_schedule(peers[i].initiator,
                            &initiator_indices[i]) != DMP_HS_OK) {
            (void)fprintf(stderr, "inbound SEC-1 attempt setup failed for peer %u\n",
                          (unsigned)i);
            goto fail;
        }
        flight = dmp_hs_cached_flight(peers[i].initiator,
                                      initiator_indices[i], &flight_len);
        if (flight == NULL || flight_len == 0U) {
            (void)fprintf(stderr, "inbound first flight missing for peer %u\n",
                          (unsigned)i);
            goto fail;
        }
        inbound_m1[i] = flight;
        inbound_m1_len[i] = flight_len;
        inbound_boot_epoch[i] = dmp_hs_boot_epoch(
            peers[i].initiator, initiator_indices[i]);
    }

    g_endpoint_test_initiator_admission_only = 1;
    g_endpoint_test_responder_admission_only = 0;
    for (i = 2U; i < 4U; i++) {
        size_t entropy_index;
        uint32_t owner_index = i - 2U;
        uint32_t peer_id = peer_ids[i];
        uint8_t attempt_id[16];
        for (entropy_index = 0U;
             entropy_index < sizeof g_endpoint_test_alt_attempt;
             entropy_index++) {
            g_endpoint_test_alt_attempt[entropy_index] =
                (uint8_t)(0x80U + i * 13U + entropy_index);
        }
        for (entropy_index = 0U;
             entropy_index < sizeof g_endpoint_test_alt_init_ephemeral;
             entropy_index++) {
            g_endpoint_test_alt_init_ephemeral[entropy_index] =
                (uint8_t)(fixture->init_ephemeral.data[entropy_index] ^
                          (uint8_t)(peer_id + entropy_index));
            g_endpoint_test_alt_resp_ephemeral[entropy_index] =
                (uint8_t)(fixture->resp_ephemeral.data[entropy_index] ^
                          (uint8_t)(peer_id + 3U * entropy_index));
        }
        g_endpoint_test_unique_entropy = 1;
        g_endpoint_test_sender_id = peer_id;
        if (!make_pair(&peers[i], &peer_ports[i], fixture,
                       tune_test_local_initiator_identity,
                       peers[0].provider, 1) ||
            !dmp_hs_uses_admission(peers[i].initiator,
                                   g_endpoint_test_admission) ||
            dmp_hs_uses_admission(peers[i].responder,
                                  g_endpoint_test_admission) ||
            dmp_hs_schedule(peers[i].initiator,
                            &initiator_indices[i]) != DMP_HS_OK ||
            !dmp_hs_copy_attempt_id(peers[i].initiator,
                                    initiator_indices[i], attempt_id)) {
            (void)fprintf(stderr, "local SEC-1 attempt setup failed for peer %u\n",
                          (unsigned)i);
            goto fail;
        }
        flight = dmp_hs_cached_flight(peers[i].initiator,
                                      initiator_indices[i], &flight_len);
        if (flight == NULL || flight_len == 0U ||
            !drive_flight(peers[i].responder, flight, flight_len,
                          ID_RESP, peer_id, 1U,
                          dmp_hs_boot_epoch(peers[i].initiator,
                                            initiator_indices[i]),
                          DMP_HS_CANDIDATE) ||
            !find_cached_flight(peers[i].responder, attempt_id, 2U,
                                &peers[i].responder_index)) {
            (void)fprintf(stderr, "local SEC-1 reply setup failed for peer %u\n",
                          (unsigned)i);
            goto fail;
        }
        local_m2[owner_index] = dmp_hs_cached_flight(
            peers[i].responder, peers[i].responder_index,
            &local_m2_len[owner_index]);
        if (local_m2[owner_index] == NULL || local_m2_len[owner_index] == 0U ||
            dmp_hs_pending(peers[i].initiator) != 1U) {
            (void)fprintf(stderr, "local SEC-1 pending attempt missing for peer %u\n",
                          (unsigned)i);
            goto fail;
        }
    }

    /* These local schedules have consumed and released their scratch leases.
     * Now two real inbound Noise reads retain both endpoint scratch leases. */
    for (i = 0U; i < 2U; i++) {
        memset(&ingress, 0, sizeof ingress);
        ingress.payload = inbound_m1[i];
        ingress.payload_len = inbound_m1_len[i];
        ingress.origin_id = peer_ids[i];
        ingress.destination_id = ID_RESP;
        ingress.namespace_id = LOCAL_NS;
        ingress.context_epoch = inbound_boot_epoch[i];
        ingress.seq = 1U;
        hs_status = dmp_hs_offer(peers[i].responder, &ingress,
                                 &held_completions[i]);
        if (hs_status != DMP_HS_AWAITING ||
            dmp_hs_pending(peers[i].responder) != 1U) {
            (void)fprintf(stderr,
                          "inbound async read %u status=%d pending=%u\n",
                          (unsigned)i, (int)hs_status,
                          (unsigned)dmp_hs_pending(peers[i].responder));
            goto fail;
        }
        responder_indices[i] = held_completions[i].attempt_index;
    }
    g_endpoint_test_unique_entropy = 0;
    g_endpoint_test_sender_id = 0U;

    if (dmp_hs_pending(peers[0].responder) != 1U ||
        dmp_hs_pending(peers[1].responder) != 1U ||
        dmp_hs_pending(peers[2].initiator) != 1U ||
        dmp_hs_pending(peers[3].initiator) != 1U) {
        (void)fprintf(stderr, "endpoint aggregate did not retain four pending attempts\n");
        goto fail;
    }

    /* With both provider reads still awaiting acceptance, a real M2 read on
     * one scheduled local attempt must be refused for lack of scratch, without
     * dropping any of the four pending reservations. */
    memset(&ingress, 0, sizeof ingress);
    ingress.payload = local_m2[0];
    ingress.payload_len = local_m2_len[0];
    ingress.origin_id = peer_ids[2];
    ingress.destination_id = ID_RESP;
    ingress.namespace_id = LOCAL_NS;
    ingress.context_epoch = dmp_hs_boot_epoch(peers[2].initiator,
                                               initiator_indices[2]);
    ingress.seq = 2U;
    hs_status = dmp_hs_offer(peers[2].initiator, &ingress,
                             &refused_completion);
    if (hs_status != DMP_HS_REFUSED ||
        dmp_hs_pending(peers[0].responder) != 1U ||
        dmp_hs_pending(peers[1].responder) != 1U ||
        dmp_hs_pending(peers[2].initiator) != 1U ||
        dmp_hs_pending(peers[3].initiator) != 1U) {
        (void)fprintf(stderr,
                      "full scratch refusal status=%d changed a pending attempt\n",
                      (int)hs_status);
        goto fail;
    }

    /* Completion releases one scratch slot but leaves its candidate pending.
     * The same real M2 read can now await acceptance in that recovered slot. */
    if (dmp_hs_accept(peers[0].responder, &held_completions[0]) !=
            DMP_HS_CANDIDATE ||
        dmp_hs_pending(peers[0].responder) != 1U ||
        dmp_hs_pending(peers[1].responder) != 1U ||
        dmp_hs_pending(peers[2].initiator) != 1U ||
        dmp_hs_pending(peers[3].initiator) != 1U ||
        dmp_endpoint_bind_peer(&right.endpoint, handles[0],
                               peers[0].responder,
                               responder_indices[0]) != DMP_OK) {
        (void)fprintf(stderr, "scratch recovery completion/bind failed\n");
        goto fail;
    }
    hs_status = dmp_hs_offer(peers[2].initiator, &ingress,
                             &held_completions[0]);
    if (hs_status != DMP_HS_AWAITING ||
        dmp_hs_pending(peers[0].responder) != 1U ||
        dmp_hs_pending(peers[1].responder) != 1U ||
        dmp_hs_pending(peers[2].initiator) != 1U ||
        dmp_hs_pending(peers[3].initiator) != 1U) {
        (void)fprintf(stderr,
                      "recovered scratch slot was not usable; status=%d\n",
                      (int)hs_status);
        goto fail;
    }

    if (dmp_hs_accept(peers[1].responder, &held_completions[1]) !=
            DMP_HS_CANDIDATE ||
        dmp_endpoint_bind_peer(&right.endpoint, handles[1],
                               peers[1].responder,
                               responder_indices[1]) != DMP_OK ||
        dmp_hs_accept(peers[2].initiator, &held_completions[0]) !=
            DMP_HS_CANDIDATE ||
        dmp_endpoint_bind_peer(&right.endpoint, handles[2],
                               peers[2].initiator,
                               initiator_indices[2]) != DMP_OK) {
        (void)fprintf(stderr, "completed candidate peer binding failed\n");
        goto fail;
    }
    ingress.payload = local_m2[1];
    ingress.payload_len = local_m2_len[1];
    ingress.origin_id = peer_ids[3];
    ingress.context_epoch = dmp_hs_boot_epoch(peers[3].initiator,
                                               initiator_indices[3]);
    hs_status = dmp_hs_offer(peers[3].initiator, &ingress,
                             &held_completions[0]);
    if (hs_status != DMP_HS_AWAITING ||
        dmp_hs_accept(peers[3].initiator, &held_completions[0]) !=
            DMP_HS_CANDIDATE ||
        dmp_endpoint_bind_peer(&right.endpoint, handles[3],
                               peers[3].initiator,
                               initiator_indices[3]) != DMP_OK) {
        (void)fprintf(stderr, "fourth candidate peer binding failed\n");
        goto fail;
    }
    for (i = 0U; i < 4U; i++) {
        dmp_hs *owner = i < 2U ? peers[i].responder : peers[i].initiator;
        uint32_t owner_attempt = i < 2U ? responder_indices[i]
                                        : initiator_indices[i];
        if (dmp_hs_pending(owner) != 1U ||
            right.endpoint.peers[handles[i].slot].association_bound == 0U ||
            right.endpoint.peers[handles[i].slot].association != owner ||
            right.endpoint.peers[handles[i].slot].association_attempt !=
                owner_attempt) {
            (void)fprintf(stderr, "peer %u lost its bound pending attempt\n",
                          (unsigned)i);
            goto fail;
        }
    }

    /* A fifth distinct NNpsk0 peer's first flight must hit the shared
     * endpoint limit while the four earlier attempts are still pending. */
    {
        uint32_t peer_id = 0x50U;
        size_t entropy_index;
        for (entropy_index = 0U;
             entropy_index < sizeof g_endpoint_test_alt_attempt;
             entropy_index++) {
            g_endpoint_test_alt_attempt[entropy_index] =
                (uint8_t)(0xa0U + entropy_index);
        }
        for (entropy_index = 0U;
             entropy_index < sizeof g_endpoint_test_alt_init_ephemeral;
             entropy_index++) {
            g_endpoint_test_alt_init_ephemeral[entropy_index] =
                (uint8_t)(fixture->init_ephemeral.data[entropy_index] ^
                          (uint8_t)(peer_id + entropy_index));
            g_endpoint_test_alt_resp_ephemeral[entropy_index] =
                (uint8_t)(fixture->resp_ephemeral.data[entropy_index] ^
                          (uint8_t)(peer_id + 3U * entropy_index));
        }
        g_endpoint_test_unique_entropy = 1;
        g_endpoint_test_sender_id = peer_id;
        g_endpoint_test_initiator_admission_only = 0;
        g_endpoint_test_responder_admission_only = 1;
        if (!make_pair(&peers[4], &peer_ports[4], fixture,
                       tune_test_sender_identity, peers[0].provider, 1) ||
            !dmp_hs_uses_admission(peers[4].responder,
                                   g_endpoint_test_admission) ||
            dmp_hs_schedule(peers[4].initiator, &fifth_index) !=
                DMP_HS_OK ||
            (flight = dmp_hs_cached_flight(peers[4].initiator,
                                           fifth_index, &flight_len)) ==
                NULL ||
            flight_len == 0U) {
            (void)fprintf(stderr, "fifth SEC-1 attempt setup failed\n");
            goto fail;
        }
        memset(&ingress, 0, sizeof ingress);
        ingress.payload = flight;
        ingress.payload_len = flight_len;
        ingress.origin_id = peer_id;
        ingress.destination_id = ID_RESP;
        ingress.namespace_id = LOCAL_NS;
        ingress.context_epoch =
            dmp_hs_boot_epoch(peers[4].initiator, fifth_index);
        ingress.seq = 1U;
        hs_status = dmp_hs_offer(peers[4].responder, &ingress,
                                 &fifth_completion);
        if (hs_status != DMP_HS_REFUSED ||
            dmp_hs_pending(peers[4].responder) != 0U) {
            (void)fprintf(stderr,
                          "fifth SEC-1 attempt status=%d pending=%u (expected refusal)\n",
                          (int)hs_status,
                          (unsigned)dmp_hs_pending(peers[4].responder));
            goto fail;
        }
    }
    for (i = 0U; i < 4U; i++) {
        dmp_hs *owner = i < 2U ? peers[i].responder : peers[i].initiator;
        if (dmp_hs_pending(owner) != 1U) {
            (void)fprintf(stderr,
                          "fifth SEC-1 attempt disturbed pending peer %u\n",
                          (unsigned)i);
            goto fail;
        }
    }

    for (i = 5U; i > 0U; i--) {
        close_session(&peers[i - 1U]);
    }
    g_endpoint_test_unique_entropy = 0;
    g_endpoint_test_sender_id = 0U;
    g_endpoint_test_peer_count = 0U;
    g_endpoint_test_scratch_slots = 0U;
    g_endpoint_test_result_slots = 0U;
    g_endpoint_test_handshake_pending = 0U;
    g_endpoint_test_message_bytes = 0U;
    g_endpoint_test_responder_admission_only = 0;
    g_endpoint_test_initiator_admission_only = 0;
    g_endpoint_test_admission = NULL;
    g_endpoint_test_admission_storage = NULL;
    memset(&right, 0, sizeof right);
    return 0;

fail:
    g_endpoint_test_unique_entropy = 0;
    g_endpoint_test_sender_id = 0U;
    for (i = 5U; i > 0U; i--) {
        close_session(&peers[i - 1U]);
    }
    g_endpoint_test_peer_count = 0U;
    g_endpoint_test_scratch_slots = 0U;
    g_endpoint_test_result_slots = 0U;
    g_endpoint_test_handshake_pending = 0U;
    g_endpoint_test_message_bytes = 0U;
    g_endpoint_test_responder_admission_only = 0;
    g_endpoint_test_initiator_admission_only = 0;
    g_endpoint_test_admission = NULL;
    g_endpoint_test_admission_storage = NULL;
    memset(&right, 0, sizeof right);
    return 1;
}

static int test_protected_multi_peer_routing_profile(uint32_t scratch_slots)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session peers[5];
    port_ctx peer_ports[5];
    dmp_peer_handle handles[4];
    dmp_identity_context_config context;
    dmp_endpoint_grant grants[4];
    uint64_t admission_storage[2048];
    dmp_identity_handle active_assoc;
    dmp_identity_handle active_assocs[4];
    dmp_identity_handle drain_assocs[4];
    uint32_t peer_ids[4] = {ID_INIT, 0x23U, 0x22U, 0x24U};
    uint32_t indices[5] = {0U};
    uint32_t replacement_index = 0U;
    uint32_t rotated_indices[4] = {0U};
    uint32_t i;
    uint8_t sealed[FRAME_CAP];
    uint8_t wrapped[FRAME_CAP];
    uint8_t combined[FRAME_CAP * 2U];
    uint8_t core[FRAME_CAP];
    uint8_t plain[FRAME_CAP];
    uint8_t drain_telem_frame[FRAME_CAP];
    uint8_t payload;
    uint8_t drain_telem_payload = 0xD3U;
    uint8_t response;
    size_t sealed_size;
    size_t wrapped_size;
    size_t combined_size;
    size_t core_size;
    size_t plain_size;
    size_t drain_telem_len = 0U;
    size_t frame_index;
    uint64_t local_epoch;
    uint64_t remote_epoch;
    dmp_frame_spec spec;
    dmp_frame_view view;
    dmp_hs_protected incoming;
    dmp_peer_handle replacement;
    dmp_peer_handle stale;
    dmp_time_ms now = 20000U;
    dmp_time_ms rotate_at;
    dmp_time_ms endpoint_now = now;
    dmp_time_ms lifecycle_at;
    dmp_status status;
    uint8_t rotation_attempt[16] = {
        0x91U, 0x42U, 0x27U, 0x18U, 0x55U, 0x36U, 0x73U, 0x04U,
        0xa5U, 0x66U, 0x83U, 0x14U, 0xc5U, 0x86U, 0xa3U, 0x34U};

    memset(peers, 0, sizeof peers);
    memset(peer_ports, 0, sizeof peer_ports);
    memset(handles, 0, sizeof handles);
    g_endpoint_test_peer_count = DMP_MULTI_PEER_COUNT;
    g_endpoint_test_scratch_slots = scratch_slots;
    g_endpoint_test_result_slots = DMP_MULTI_PEER_APPLICATION_OPERATIONS;
    g_endpoint_test_handshake_pending = DMP_MULTI_PEER_PENDING_ATTEMPTS;
    g_endpoint_test_message_bytes = DMP_MULTI_PEER_MESSAGE_BYTES;
    g_endpoint_test_responder_admission_only = 1;
    g_endpoint_test_admission = NULL;
    g_endpoint_test_admission_storage = admission_storage;
    memset(admission_storage, 0, sizeof admission_storage);
    if (fixture == NULL ||
        dmp_hs_admission_size() > sizeof admission_storage ||
        boot_node_slots(&right, 0, DMP_MULTI_PEER_CHUNK_BYTES,
                        DMP_MULTI_PEER_FRAGMENTS, now, 8U) != 0) {
        (void)fprintf(stderr, "multi-peer endpoint setup failed\n");
        g_endpoint_test_peer_count = 0U;
        g_endpoint_test_handshake_pending = 0U;
        g_endpoint_test_message_bytes = 0U;
        g_endpoint_test_admission = NULL;
        g_endpoint_test_admission_storage = NULL;
        return 1;
    }
    CHECK(right.endpoint.profile.peers == DMP_MULTI_PEER_COUNT);
    CHECK(right.endpoint.profile.operations_per_service ==
          DMP_MULTI_PEER_OPERATIONS_PER_SERVICE);
    CHECK(right.endpoint.profile.message_bytes == DMP_MULTI_PEER_MESSAGE_BYTES);
    CHECK(right.endpoint.profile.chunk_bytes == DMP_MULTI_PEER_CHUNK_BYTES);
    CHECK(right.endpoint.profile.fragments == DMP_MULTI_PEER_FRAGMENTS);
    CHECK(right.endpoint.profile.sender_slots == DMP_MULTI_PEER_SENDER_SLOTS);
    CHECK(scratch_slots == DMP_MULTI_PEER_SERIAL_CRYPTO_SLOTS ||
          scratch_slots == DMP_MULTI_PEER_PARALLEL_CRYPTO_SLOTS);
    CHECK(dmp_endpoint_handshake_admission(&right.endpoint) ==
          g_endpoint_test_admission);
    if (!make_pair(&peers[0], &peer_ports[0], fixture, NULL, NULL, 0) ||
        !drive_nn(&peers[0], &indices[0]) ||
        !activate(&peers[0], indices[0])) {
        (void)fprintf(stderr, "multi-peer setup failed for peer 0\n");
        close_session(&peers[0]);
        goto fail;
    }
    handles[0].slot = 0U;
    handles[0].generation = 1U;
    if (dmp_endpoint_bind_peer(&right.endpoint, handles[0],
                               peers[0].responder, 0U) != DMP_OK) {
        close_session(&peers[0]);
        goto fail;
    }
    CHECK(right.endpoint.peers[handles[0].slot].association_reservation_live != 0U);
    CHECK(dmp_endpoint_peer_association(&right.endpoint, handles[0],
                                        &active_assoc) == DMP_OK);
    CHECK(dmp_endpoint_validate_association(&right.endpoint, active_assoc,
                                            LOCAL_NS, ID_RESP) == DMP_OK);
    grants[0].principal = peer_ids[0];
    grants[0].service_id = 1U;
    grants[0].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_TELEM;
    grants[1].principal = ID_RESP;
    grants[1].service_id = 1U;
    grants[1].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    grants[2].principal = peer_ids[0];
    grants[2].service_id = 2U;
    grants[2].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[3].principal = ID_RESP;
    grants[3].service_id = 2U;
    grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    if (dmp_endpoint_set_peer_grants(&right.endpoint, handles[0], grants,
                                     4U) != DMP_OK) {
        goto fail;
    }
    CHECK(dmp_hs_uses_admission(peers[0].responder,
                                g_endpoint_test_admission));
    CHECK(!dmp_hs_uses_admission(peers[0].initiator,
                                 g_endpoint_test_admission));

    for (i = 1U; i < 4U; i++) {
        size_t entropy_index;
        memset(&context, 0, sizeof context);
        context.local.namespace_id = LOCAL_NS;
        context.local.origin_id = ID_RESP;
        context.peer.namespace_id = LOCAL_NS;
        context.peer.origin_id = peer_ids[i];
        context.security = 1U;
        if (dmp_endpoint_add_peer(&right.endpoint, &context, now,
                                  &handles[i]) != DMP_OK) {
            goto fail;
        }
        grants[0].principal = peer_ids[i];
        grants[0].service_id = 1U;
        grants[0].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_TELEM;
        grants[1].principal = ID_RESP;
        grants[1].service_id = 1U;
        grants[1].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
        grants[2].principal = peer_ids[i];
        grants[2].service_id = 2U;
        grants[2].permit = DMP_ENDPOINT_PERMIT_REQ;
        grants[3].principal = ID_RESP;
        grants[3].service_id = 2U;
        grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
        if (dmp_endpoint_set_peer_grants(&right.endpoint, handles[i], grants,
                                         4U) != DMP_OK) {
            goto fail;
        }
        for (entropy_index = 0U;
             entropy_index < sizeof g_endpoint_test_alt_attempt;
             entropy_index++) {
            g_endpoint_test_alt_attempt[entropy_index] =
                (uint8_t)(0x30U + peer_ids[i] + entropy_index);
        }
        for (entropy_index = 0U;
             entropy_index < sizeof g_endpoint_test_alt_init_ephemeral;
             entropy_index++) {
            g_endpoint_test_alt_init_ephemeral[entropy_index] =
                (uint8_t)(fixture->init_ephemeral.data[entropy_index] ^
                          (uint8_t)(peer_ids[i] + entropy_index));
            g_endpoint_test_alt_resp_ephemeral[entropy_index] =
                (uint8_t)(fixture->resp_ephemeral.data[entropy_index] ^
                          (uint8_t)(peer_ids[i] + 3U * entropy_index));
        }
        g_endpoint_test_unique_entropy = 1;
        g_endpoint_test_sender_id = peer_ids[i];
        if (!make_pair(&peers[i], &peer_ports[i], fixture,
                       tune_test_sender_identity, peers[0].provider, 1)) {
            (void)fprintf(stderr, "multi-peer make_pair failed for peer %u\n", i);
            g_endpoint_test_unique_entropy = 0;
            g_endpoint_test_sender_id = 0U;
            goto fail;
        }
        peers[i].provider = NULL;
        if (!drive_nn_for_ids(&peers[i], &indices[i], peer_ids[i], ID_RESP)) {
            (void)fprintf(stderr, "multi-peer drive_nn failed for peer %u\n", i);
            g_endpoint_test_unique_entropy = 0;
            g_endpoint_test_sender_id = 0U;
            goto fail;
        }
        if (!activate_for_ids(&peers[i], indices[i], peer_ids[i], ID_RESP)) {
            (void)fprintf(stderr, "multi-peer activate failed for peer %u\n", i);
            g_endpoint_test_unique_entropy = 0;
            g_endpoint_test_sender_id = 0U;
            goto fail;
        }
        g_endpoint_test_unique_entropy = 0;
        g_endpoint_test_sender_id = 0U;
        if (dmp_endpoint_bind_peer(&right.endpoint, handles[i],
                                   peers[i].responder, 0U) != DMP_OK) {
            goto fail;
        }
        CHECK(dmp_hs_uses_admission(peers[i].responder,
                                    g_endpoint_test_admission));
        CHECK(!dmp_hs_uses_admission(peers[i].initiator,
                                     g_endpoint_test_admission));
    }

    for (i = 0U; i < 4U; i++) {
        payload = (uint8_t)(0x40U + i);
        memset(&spec, 0, sizeof spec);
        spec.fields.type = DMP_TYPE_REQ;
        spec.fields.options = DMP_OPT_SEQ | DMP_OPT_ACK_REQ;
        spec.fields.seq = 1U;
        spec.payload = span(&payload, sizeof payload);
        CHECK(dmp_hs_seal_logical(peers[i].initiator, indices[i], &spec,
                                  sealed, sizeof sealed, &sealed_size) ==
              DMP_HS_OK);
        CHECK(wrap_core(sealed, sealed_size, wrapped, sizeof wrapped,
                        &wrapped_size));
        status = dmp_endpoint_rx_from(&right.endpoint, handles[i],
                                      span(wrapped, wrapped_size), now + i);
        if (status != DMP_OK) {
            (void)fprintf(stderr,
                          "multi-peer request RX for slot %u returned %s (%d); accepts=%d\n",
                          (unsigned)i, dmp_status_name(status), (int)status,
                          right.app.accepts);
        }
        CHECK(status == DMP_OK);
        CHECK(right.app.accepts == (int)i + 1 &&
              right.app.last_peer.slot == handles[i].slot &&
              right.app.last_peer.generation == handles[i].generation &&
              right.app.peer_pending_live[handles[i].slot] != 0U);
    }

    /* Four per-peer requests occupy the endpoint's shared result pool. A
     * second service on peer 0 would fit its per-service quota, but the fifth
     * outstanding operation must be refused at the endpoint-wide bound. */
    {
        uint8_t request = 0x85U;
        uint8_t service_two_extensions[3] = {17U, 1U, 2U};
        int accepts_before = right.app.accepts;
        memset(&spec, 0, sizeof spec);
        spec.fields.type = DMP_TYPE_REQ;
        spec.fields.options = DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_EXT;
        spec.fields.seq = 2U;
        spec.extensions = span(service_two_extensions,
                               sizeof service_two_extensions);
        spec.payload = span(&request, sizeof request);
        CHECK(dmp_hs_seal_logical(peers[0].initiator, indices[0], &spec,
                                  sealed, sizeof sealed, &sealed_size) ==
              DMP_HS_OK);
        CHECK(wrap_core(sealed, sealed_size, wrapped, sizeof wrapped,
                        &wrapped_size));
        status = dmp_endpoint_rx_from(&right.endpoint, handles[0],
                                      span(wrapped, wrapped_size), now + 10U);
        if (status != DMP_QUOTA_EXHAUSTED) {
            (void)fprintf(stderr, "shared result-slot pressure returned %s (%d)\n",
                          dmp_status_name(status), (int)status);
        }
        CHECK(status == DMP_QUOTA_EXHAUSTED);
        CHECK(right.app.accepts == accepts_before);
    }

    for (i = 0U; i < 4U; i++) {
        int response_opened = 0;
        int decoded_frames = 0;
        uint8_t last_type = 0U;
        uint32_t response_seq = 0U;
        payload = (uint8_t)(0x40U + i);
        response = (uint8_t)~payload;
        CHECK(right.app.peer_pending_live[handles[i].slot] != 0U);
        CHECK(dmp_endpoint_complete(&right.endpoint,
                                    right.app.peer_pending[handles[i].slot],
                                    false, 0U, span(&response, sizeof response),
                                    now + 20U + i) == DMP_OK);
        right.app.peer_pending_live[handles[i].slot] = 0U;
        {
            uint32_t poll_index;
            for (poll_index = 0U; poll_index < right.endpoint.profile.peers * 4U;
                 poll_index++) {
                CHECK(dmp_endpoint_poll(&right.endpoint, now + 20U + i) == DMP_OK);
            }
        }
        CHECK(right.wire.n > 0);
        CHECK(dmp_hs_epochs(peers[i].initiator, indices[i], &local_epoch,
                            &remote_epoch));
        CHECK(local_epoch != 0U && remote_epoch != 0U);
        response_opened = 0;
        for (frame_index = 0U; frame_index < (size_t)right.wire.n;
             frame_index++) {
            if (!unwrap_core(right.wire.q[frame_index].frame,
                             right.wire.q[frame_index].len, core,
                             sizeof core, &core_size, now + 20U + i)) {
                if (right.wire.q[frame_index].len >= FRAME_CAP) {
                    continue;
                }
                combined[0] = 0U;
                memcpy(combined + 1U, right.wire.q[frame_index].frame,
                       right.wire.q[frame_index].len);
                if (!unwrap_core(combined,
                                 right.wire.q[frame_index].len + 1U, core,
                                 sizeof core, &core_size, now + 20U + i)) {
                    continue;
                }
            }
            decoded_frames++;
            memset(&incoming, 0, sizeof incoming);
            incoming.frame = core;
            incoming.frame_len = core_size;
            incoming.origin_id = ID_RESP;
            incoming.destination_id = peer_ids[i];
            incoming.namespace_id = LOCAL_NS;
            incoming.context_epoch = remote_epoch;
            CHECK(dmp_hs_open_logical(peers[i].initiator, indices[i],
                                      &incoming, plain, sizeof plain,
                                      &plain_size, &view) == DMP_HS_OK);
            last_type = view.fields.type;
            if (view.fields.type == DMP_TYPE_RSP) {
                CHECK(view.payload.size == sizeof response &&
                      view.payload.data[0] == response);
                response_seq = view.fields.seq;
                response_opened = 1;
                break;
            }
        }
        if (response_opened == 0) {
            (void)fprintf(stderr,
                          "multi-peer response absent for slot %u: frames=%d decoded=%d last_type=%u submits=%d\n",
                          (unsigned)i, right.wire.n, decoded_frames,
                          (unsigned)last_type, right.wire.submits);
            for (frame_index = 0U; frame_index < (size_t)right.wire.n; frame_index++) {
                (void)fprintf(stderr, "  frame[%zu] len=%zu first=%02x\n", frame_index,
                              right.wire.q[frame_index].len,
                              right.wire.q[frame_index].len != 0U
                                  ? right.wire.q[frame_index].frame[0]
                                  : 0U);
            }
        }
        CHECK(response_opened != 0);
        {
            uint8_t ack_extensions[8];
            uint8_t ack_sealed[FRAME_CAP];
            uint8_t ack_wrapped[FRAME_CAP];
            size_t ack_extension_size;
            size_t ack_sealed_size = 0U;
            size_t ack_wrapped_size = 0U;
            dmp_bytes empty = {NULL, 0U};
            ack_extensions[0] = 0x05U; /* Compact SEC-1 REPLY_TO. */
            ack_extension_size = encode_test_uleb32(response_seq,
                                                     ack_extensions + 2U);
            ack_extensions[1] = (uint8_t)ack_extension_size;
            ack_extension_size += 2U;
            memset(&spec, 0, sizeof spec);
            spec.fields.type = DMP_TYPE_ACK;
            spec.fields.options = DMP_OPT_SEQ | DMP_OPT_EXT;
            spec.fields.seq = 100U + i;
            spec.extensions = span(ack_extensions, ack_extension_size);
            spec.payload = empty;
            CHECK(dmp_hs_seal_logical(peers[i].initiator, indices[i], &spec,
                                      ack_sealed, sizeof ack_sealed,
                                      &ack_sealed_size) == DMP_HS_OK);
            CHECK(wrap_core(ack_sealed, ack_sealed_size, ack_wrapped,
                            sizeof ack_wrapped, &ack_wrapped_size));
            status = dmp_endpoint_rx_from(&right.endpoint, handles[i],
                                          span(ack_wrapped, ack_wrapped_size),
                                          now + 40U + i);
            if (status != DMP_OK) {
                (void)fprintf(stderr,
                              "multi-peer response ACK for slot %u returned %s (%d)\n",
                              (unsigned)i, dmp_status_name(status),
                              (int)status);
            }
            CHECK(status == DMP_OK);
            CHECK(service(&right, now + 40U + i) == 0);
        }
        right.wire.n = 0;
    }

    {
        size_t sender_index;
        size_t result_index;
        unsigned live_senders = 0U;
        unsigned live_results = 0U;
        unsigned acked_results = 0U;
        for (sender_index = 0U;
             sender_index < right.endpoint.mem.sender_capacity;
             sender_index++) {
            live_senders += right.endpoint.mem.senders[sender_index].live != 0U;
        }
        for (result_index = 0U;
             result_index < right.endpoint.mem.result_capacity;
             result_index++) {
            live_results += right.endpoint.mem.results[result_index].live != 0U;
            acked_results += right.endpoint.mem.results[result_index].acknowledged != 0U;
        }
        CHECK(live_senders == 0U);
        CHECK(live_results == 4U && acked_results == 4U);
    }

    /* An output selected for peer 2 advances the scheduler to peer 3, even
     * after the initial peer scan has completed. */
    {
        uint8_t telem = 0xC3U;
        grants[0].principal = peer_ids[2];
        grants[0].service_id = 1U;
        grants[0].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_TELEM;
        grants[1].principal = ID_RESP;
        grants[1].service_id = 1U;
        grants[1].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT |
                           DMP_ENDPOINT_PERMIT_TELEM;
        grants[2].principal = peer_ids[2];
        grants[2].service_id = 2U;
        grants[2].permit = DMP_ENDPOINT_PERMIT_REQ;
        grants[3].principal = ID_RESP;
        grants[3].service_id = 2U;
        grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
        CHECK(dmp_endpoint_set_peer_grants(&right.endpoint, handles[2], grants,
                                           4U) == DMP_OK);
        right.wire.n = 0;
        right.endpoint.poll_peer_cursor = 0U;
        CHECK(dmp_endpoint_submit_telem_to(&right.endpoint, handles[2], 1U,
                                           span(&telem, sizeof telem), now + 50U) ==
              DMP_OK);
        CHECK(dmp_endpoint_poll(&right.endpoint, now + 50U) == DMP_OK);
        CHECK(right.wire.n == 1);
        CHECK(right.endpoint.poll_peer_cursor == 3U);
        right.wire.n = 0;
    }

    /* Expire peer 1's retained request, then ensure peer 0's following
     * receive batch keeps the route and decoder bound to peer 0. */
    {
        dmp_reliability_handle pending;
        uint8_t request = 0xA1U;
        uint8_t telem = 0xB2U;
        dmp_time_ms submit_at = endpoint_now +
                                right.endpoint.profile.result_cache_ms + 10U;
        dmp_time_ms expire_at = 0U;
        int unknowns_before = right.app.unknowns;
        int accepts_before = right.app.accepts;
        int telems_before = right.app.telems;
        dmp_identity_handle expected_context;

        /* Acknowledged results remain in the shared cache until their original
         * result-cache deadline. Age them out before exercising a new peer's
         * independent pending request and timeout. */
        CHECK(dmp_endpoint_poll(&right.endpoint, submit_at - 1U) == DMP_OK);
        CHECK(dmp_endpoint_peer_association(&right.endpoint, handles[1],
                                            &expected_context) == DMP_OK);
        status = dmp_endpoint_submit_req_to(&right.endpoint, handles[1], 2U,
                                            span(&request, 1U), submit_at,
                                            &pending);
        if (status != DMP_OK) {
            (void)fprintf(stderr,
                          "multi-peer outbound REQ on slot 1 returned %s (%d)\n",
                          dmp_status_name(status), (int)status);
        }
        CHECK(status == DMP_OK);
        CHECK(pending.slot < right.endpoint.mem.sender_capacity);
        CHECK(right.endpoint.mem.senders[pending.slot].live != 0U &&
              right.endpoint.mem.senders[pending.slot].generation ==
                  pending.generation);
        expire_at = right.endpoint.mem.senders[pending.slot].result_deadline + 1U;
        CHECK(dmp_endpoint_poll(&right.endpoint, submit_at) == DMP_OK);
        CHECK(service(&right, submit_at) == 0);
        right.wire.n = 0;

        memset(&spec, 0, sizeof spec);
        spec.fields.type = DMP_TYPE_REQ;
        spec.fields.options = DMP_OPT_SEQ | DMP_OPT_ACK_REQ;
        spec.fields.seq = 2U;
        spec.payload = span(&request, 1U);
        CHECK(dmp_hs_seal_logical(peers[0].initiator, indices[0], &spec,
                                  sealed, sizeof sealed, &sealed_size) == DMP_HS_OK);
        CHECK(wrap_core(sealed, sealed_size, wrapped, sizeof wrapped,
                        &wrapped_size));
        memcpy(combined, wrapped, wrapped_size);
        combined_size = wrapped_size;

        memset(&spec, 0, sizeof spec);
        spec.fields.type = DMP_TYPE_TELEM;
        spec.fields.options = DMP_OPT_SEQ;
        spec.fields.seq = 3U;
        spec.payload = span(&telem, 1U);
        CHECK(dmp_hs_seal_logical(peers[0].initiator, indices[0], &spec,
                                  sealed, sizeof sealed, &sealed_size) == DMP_HS_OK);
        CHECK(wrap_core(sealed, sealed_size, wrapped, sizeof wrapped,
                        &wrapped_size));
        CHECK(combined_size + wrapped_size <= sizeof combined);
        memcpy(combined + combined_size, wrapped, wrapped_size);
        combined_size += wrapped_size;

        CHECK(dmp_endpoint_poll(&right.endpoint, expire_at) == DMP_OK);
        if (right.app.unknowns != unknowns_before + 1) {
            (void)fprintf(stderr,
                          "peer expiry notification count=%d before=%d local_unsent=%d last_peer=%u/%llu pending=%u result_deadline=%llu now=%llu wire_pending=%d\n",
                          right.app.unknowns, unknowns_before,
                          right.app.local_unsent,
                          (unsigned)right.app.last_unknown_peer.slot,
                          (unsigned long long)right.app.last_unknown_peer.generation,
                          (unsigned)right.endpoint.mem.senders[pending.slot].live,
                          (unsigned long long)right.endpoint.mem.senders[pending.slot].result_deadline,
                          (unsigned long long)expire_at,
                          right.wire.pending_count);
        }
        CHECK(right.app.unknowns == unknowns_before + 1 &&
              right.app.last_unknown_peer.slot == handles[1].slot &&
              right.app.last_unknown_peer.generation == handles[1].generation &&
              right.app.last_notice_association.slot == expected_context.slot &&
              right.app.last_notice_association.generation == expected_context.generation);
        unknowns_before = right.app.unknowns;
        status = dmp_endpoint_rx_from(&right.endpoint, handles[0],
                                      span(combined, combined_size), expire_at);
        if (status != DMP_OK) {
            (void)fprintf(stderr,
                          "multi-peer combined expiry RX returned %s (%d)\n",
                          dmp_status_name(status), (int)status);
        }
        CHECK(status == DMP_OK);
        CHECK(right.app.unknowns == unknowns_before);
        CHECK(right.app.accepts == accepts_before + 1 &&
              right.app.last_peer.slot == handles[0].slot &&
              right.app.last_peer.generation == handles[0].generation);
        CHECK(right.app.telems == telems_before + 1 &&
              right.app.last_peer.slot == handles[0].slot &&
              right.app.last_peer.generation == handles[0].generation &&
              right.endpoint.active_peer_slot == handles[0].slot);
        endpoint_now = expire_at;
    }

    /* Reliable work and endpoint telemetry share one peer round-robin and
     * one accepted-TX budget, including synchronous transport completions. */
    {
        uint8_t request_payload = 0xA5U;
        uint8_t telem_payload = 0x5AU;
        dmp_reliability_handle scheduled_request;
        uint8_t observed_types[2] = {0U, 0U};
        dmp_time_ms at = endpoint_now + 5U;
        int wire_before;

        grants[1].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT |
                           DMP_ENDPOINT_PERMIT_TELEM;
        CHECK(dmp_endpoint_set_peer_grants(&right.endpoint, handles[0], grants, 4U) == DMP_OK);
        for (i = 0U; i < 4U; i++) {
            if (right.endpoint.peers[i].sync_pending != 0U) {
                right.wire.now = at;
                wire_before = right.wire.n;
                CHECK(dmp_endpoint_poll(&right.endpoint, at++) == DMP_OK);
                CHECK(right.wire.n <= wire_before + 1);
                right.wire.n = 0;
            }
        }
        right.wire.n = 0;
        CHECK(dmp_endpoint_submit_req_to(&right.endpoint, handles[0], 2U,
                                         span(&request_payload, 1U), at,
                                         &scheduled_request) == DMP_OK);
        CHECK(dmp_endpoint_submit_telem_to(&right.endpoint, handles[0], 1U,
                                           span(&telem_payload, 1U), at) == DMP_OK);
        for (i = 0U; i < 2U; i++) {
            wire_before = right.wire.n;
            right.wire.now = at + i;
            CHECK(dmp_endpoint_poll(&right.endpoint, at + i) == DMP_OK);
            CHECK(right.wire.n == wire_before + 1);
            CHECK(protected_frame_type_seq(right.wire.q[wire_before].frame,
                                           right.wire.q[wire_before].len, at + i,
                                           &observed_types[i], NULL));
        }
        CHECK((observed_types[0] == DMP_TYPE_REQ && observed_types[1] == DMP_TYPE_TELEM) ||
              (observed_types[0] == DMP_TYPE_TELEM && observed_types[1] == DMP_TYPE_REQ));
        /* This is an outbound sender handle. Abandon is for app-held inbound
         * requests after their association has closed. */
        CHECK(dmp_reliability_cancel(&right.endpoint.reliability,
                                     scheduled_request, at + 2U) == DMP_OK);
        grants[1].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
        CHECK(dmp_endpoint_set_peer_grants(&right.endpoint, handles[0], grants, 4U) == DMP_OK);
        right.wire.n = 0;
        endpoint_now = at + 2U;
    }

    /* Rotate all four associations while retaining all four old contexts.
     * The shared endpoint must support four active plus four draining routes. */
    rotate_at = endpoint_now + 10U;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = DMP_TYPE_TELEM;
    spec.fields.options = DMP_OPT_SEQ;
    spec.fields.seq = 77U;
    spec.payload = span(&drain_telem_payload, sizeof drain_telem_payload);
    CHECK(dmp_hs_seal_logical(peers[0].initiator, indices[0], &spec, sealed,
                              sizeof sealed, &sealed_size) == DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_size, wrapped, sizeof wrapped, &wrapped_size));
    CHECK(wrapped_size <= sizeof drain_telem_frame);
    memcpy(drain_telem_frame, wrapped, wrapped_size);
    drain_telem_len = wrapped_size;
    for (i = 0U; i < 4U; i++) {
        /* All original client-side ciphers have finished their traffic checks;
         * the endpoint-side responder contexts stay active and retain the old
         * association while each remote initiator is renewed below. */
        dmp_hs_cleanup(peers[i].initiator);
    }
    for (i = 0U; i < 4U; i++) {
        size_t entropy_index;
        CHECK(dmp_endpoint_set_peer_drain_ms(&right.endpoint, handles[i],
                                             1000U) == DMP_OK);
        CHECK(dmp_endpoint_peer_association(&right.endpoint, handles[i],
                                            &active_assocs[i]) == DMP_OK);
        if (i == 0U) {
            memcpy(peers[i].rot_id, rotation_attempt,
                   sizeof peers[i].rot_id);
        } else {
            for (entropy_index = 0U; entropy_index < sizeof peers[i].rot_id;
                 entropy_index++) {
                peers[i].rot_id[entropy_index] =
                    (uint8_t)(0x91U + 17U * i + entropy_index);
            }
        }
        for (entropy_index = 0U; entropy_index < sizeof peers[i].rot_init_eph;
             entropy_index++) {
            peers[i].rot_init_eph[entropy_index] =
                (uint8_t)(fixture->init_ephemeral.data[entropy_index] ^
                          (uint8_t)(0x21U + i + entropy_index));
            peers[i].rot_resp_eph[entropy_index] =
                (uint8_t)(fixture->resp_ephemeral.data[entropy_index] ^
                          (uint8_t)(0x43U + 3U * i + entropy_index));
        }
        script_add(&peers[i].init_script, peers[i].rot_id,
                   sizeof peers[i].rot_id);
        script_add(&peers[i].init_script, peers[i].rot_init_eph,
                   sizeof peers[i].rot_init_eph);
        script_add(&peers[i].resp_script, peers[i].rot_resp_eph,
                   sizeof peers[i].rot_resp_eph);
        peers[i].now = rotate_at + i;
        if (!renew_multi_peer_initiator(&peers[i], peers[0].provider,
                                        fixture, peer_ids[i])) {
            (void)fprintf(stderr, "multi-peer initiator renewal failed for peer %u\n",
                          (unsigned)i);
            goto fail;
        }
        if (!drive_nn_for_ids(&peers[i], &rotated_indices[i],
                              peer_ids[i], ID_RESP)) {
            (void)fprintf(stderr, "multi-peer rotation handshake failed for peer %u\n",
                          (unsigned)i);
            goto fail;
        }
        CHECK(activate_for_ids(&peers[i], rotated_indices[i],
                               peer_ids[i], ID_RESP));
        CHECK(dmp_endpoint_rotate_peer(&right.endpoint, handles[i],
                                       peers[i].responder_index, rotate_at + i) ==
              DMP_OK);
        CHECK(right.endpoint.peers[handles[i].slot].association_bound != 0U &&
              right.endpoint.peers[handles[i].slot].drain_live != 0U &&
              right.endpoint.peers[handles[i].slot].association_reservation_live != 0U &&
              right.endpoint.peers[handles[i].slot].drain_reservation_live != 0U);
        CHECK(dmp_endpoint_peer_association(&right.endpoint, handles[i],
                                            &active_assoc) == DMP_OK);
        CHECK(dmp_endpoint_validate_association(&right.endpoint, active_assoc,
                                                LOCAL_NS, ID_RESP) == DMP_OK);
        CHECK(dmp_endpoint_validate_association(&right.endpoint,
                                                active_assocs[i], LOCAL_NS,
                                                ID_RESP) == DMP_OK);
        drain_assocs[i] = active_assocs[i];
        dmp_hs_cleanup(peers[i].initiator);
    }
    for (i = 0U; i < 4U; i++) {
        CHECK(right.endpoint.peers[handles[i].slot].drain_live != 0U);
    }
    CHECK(dmp_endpoint_rx_from(&right.endpoint, handles[0],
                               span(drain_telem_frame, drain_telem_len),
                               rotate_at + 5U) == DMP_OK);
    CHECK(right.app.last_notice_association.slot == drain_assocs[0].slot &&
          right.app.last_notice_association.generation == drain_assocs[0].generation);
    status = dmp_endpoint_poll(&right.endpoint, rotate_at + 1005U);
    /* The peer-0 request still retains its old identity context while the
     * other three expired drains can be retired immediately. */
    CHECK(status == DMP_OK || status == DMP_DEADLINE_EXPIRED);
    CHECK(right.endpoint.peers[handles[0].slot].drain_live != 0U);
    CHECK(dmp_endpoint_validate_association(&right.endpoint, drain_assocs[0],
                                            LOCAL_NS, ID_RESP) ==
          DMP_AUTHENTICATION_FAILURE);
    for (i = 1U; i < 4U; i++) {
        CHECK(right.endpoint.peers[handles[i].slot].drain_live == 0U);
        CHECK(right.endpoint.peers[handles[i].slot].drain_reservation_live == 0U);
        CHECK(dmp_endpoint_validate_association(&right.endpoint,
                                                drain_assocs[i], LOCAL_NS,
                                                ID_RESP) ==
              DMP_AUTHENTICATION_FAILURE);
    }

    lifecycle_at = rotate_at + right.endpoint.profile.correlation_ms + 32U;
    status = dmp_endpoint_poll(&right.endpoint, lifecycle_at);
    CHECK(status == DMP_OK || status == DMP_DEADLINE_EXPIRED);
    for (i = 0U; i < 4U; i++) {
        CHECK(right.endpoint.peers[handles[i].slot].drain_live == 0U);
        CHECK(right.endpoint.peers[handles[i].slot].drain_reservation_live == 0U);
        CHECK(dmp_endpoint_validate_association(&right.endpoint,
                                                drain_assocs[i], LOCAL_NS,
                                                ID_RESP) ==
              DMP_AUTHENTICATION_FAILURE);
    }

    stale = handles[0];
    CHECK(dmp_endpoint_revoke_peer(&right.endpoint, stale, lifecycle_at + 1U) ==
          DMP_OK);
    memset(&context, 0, sizeof context);
    context.local.namespace_id = LOCAL_NS;
    context.local.origin_id = ID_RESP;
    context.peer.namespace_id = LOCAL_NS;
    context.peer.origin_id = peer_ids[1];
    context.security = 1U;
    {
        dmp_peer_handle duplicate = {UINT32_MAX, UINT64_MAX};
        CHECK(dmp_endpoint_add_peer(&right.endpoint, &context, lifecycle_at + 2U,
                                    &duplicate) == DMP_DUPLICATE);
        CHECK(duplicate.slot == UINT32_MAX && duplicate.generation == UINT64_MAX);
    }
    context.peer.origin_id = 0x30U;
    context.security = 1U;
    CHECK(dmp_endpoint_add_peer(&right.endpoint, &context, lifecycle_at + 3U,
                                &replacement) == DMP_OK);
    CHECK(replacement.slot == stale.slot &&
          replacement.generation != stale.generation &&
          right.endpoint.peers[replacement.slot].association_reservation_live == 0U &&
          right.endpoint.peers[replacement.slot].drain_reservation_live == 0U);
    grants[0].principal = 0x30U;
    grants[0].service_id = 1U;
    grants[0].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_TELEM;
    grants[1].principal = ID_RESP;
    grants[1].service_id = 1U;
    grants[1].permit = DMP_ENDPOINT_PERMIT_RESULT;
    grants[2].principal = 0x30U;
    grants[2].service_id = 2U;
    grants[2].permit = DMP_ENDPOINT_PERMIT_REQ;
    grants[3].principal = ID_RESP;
    grants[3].service_id = 2U;
    grants[3].permit = DMP_ENDPOINT_PERMIT_REQ | DMP_ENDPOINT_PERMIT_RESULT;
    CHECK(dmp_endpoint_set_peer_grants(&right.endpoint, replacement, grants,
                                       4U) == DMP_OK);
    {
        size_t entropy_index;
        for (entropy_index = 0U;
             entropy_index < sizeof g_endpoint_test_alt_attempt;
             entropy_index++) {
            g_endpoint_test_alt_attempt[entropy_index] =
                (uint8_t)(0x70U + entropy_index);
        }
        for (entropy_index = 0U;
             entropy_index < sizeof g_endpoint_test_alt_init_ephemeral;
             entropy_index++) {
            g_endpoint_test_alt_init_ephemeral[entropy_index] =
                (uint8_t)(fixture->init_ephemeral.data[entropy_index] ^
                          (uint8_t)(0x30U + entropy_index));
            g_endpoint_test_alt_resp_ephemeral[entropy_index] =
                (uint8_t)(fixture->resp_ephemeral.data[entropy_index] ^
                          (uint8_t)(0x50U + entropy_index));
        }
    }
    g_endpoint_test_unique_entropy = 1;
    g_endpoint_test_sender_id = 0x30U;
    CHECK(make_pair(&peers[4], &peer_ports[4], fixture,
                    tune_test_sender_identity, peers[0].provider, 1));
    peers[4].provider = NULL;
    g_endpoint_test_unique_entropy = 0;
    g_endpoint_test_sender_id = 0U;
    CHECK(drive_nn_for_ids(&peers[4], &replacement_index, 0x30U, ID_RESP));
    CHECK(activate_for_ids(&peers[4], replacement_index, 0x30U, ID_RESP));
    CHECK(dmp_endpoint_bind_peer(&right.endpoint, replacement, peers[4].responder,
                                 0U) == DMP_OK);

    {
        int telems_before_replacement = right.app.telems;
        memset(&spec, 0, sizeof spec);
        spec.fields.type = DMP_TYPE_TELEM;
        spec.fields.options = DMP_OPT_SEQ;
        spec.fields.seq = 1U;
        payload = 0x7cU;
        spec.payload = span(&payload, sizeof payload);
        CHECK(dmp_hs_seal_logical(peers[4].initiator, replacement_index, &spec,
                                  sealed, sizeof sealed, &sealed_size) == DMP_HS_OK);
        CHECK(wrap_core(sealed, sealed_size, wrapped, sizeof wrapped,
                        &wrapped_size));
        CHECK(dmp_endpoint_rx_from(&right.endpoint, stale,
                                   span(wrapped, wrapped_size), lifecycle_at + 4U) ==
              DMP_STALE_HANDLE);
        CHECK(right.app.telems == telems_before_replacement);
        CHECK(dmp_endpoint_rx_from(&right.endpoint, replacement,
                                   span(wrapped, wrapped_size), lifecycle_at + 4U) ==
              DMP_OK);
        CHECK(right.app.telems == telems_before_replacement + 1 &&
              right.app.last_peer.slot == replacement.slot &&
              right.app.last_peer.generation == replacement.generation);
    }

    /* The four-peer endpoint also receives a complete maximum-size service-2
     * message through the newly active replacement association. The serial
     * and parallel profile runs both cover all 32 protected slices. */
    {
        uint8_t chunk[DMP_MULTI_PEER_CHUNK_BYTES];
        uint8_t service_two_extensions[3] = {17U, 1U, 2U};
        uint32_t fragment_index;
        uint32_t accepts_before = (uint32_t)right.app.accepts;
        dmp_time_ms fragment_at = lifecycle_at + 5U;

        for (fragment_index = 0U;
             fragment_index < DMP_MULTI_PEER_FRAGMENTS;
             fragment_index++) {
            uint32_t offset;
            for (offset = 0U; offset < DMP_MULTI_PEER_CHUNK_BYTES; offset++) {
                chunk[offset] = (uint8_t)(0x31U +
                    ((fragment_index * DMP_MULTI_PEER_CHUNK_BYTES + offset) % 197U));
            }
            memset(&spec, 0, sizeof spec);
            spec.fields.type = DMP_TYPE_REQ;
            spec.fields.options = DMP_OPT_SEQ | DMP_OPT_ACK_REQ |
                                  DMP_OPT_FRAG | DMP_OPT_EXT;
            spec.fields.seq = 7U;
            spec.fields.fragment.index = fragment_index;
            spec.fields.fragment.chunk_size = DMP_MULTI_PEER_CHUNK_BYTES;
            spec.fields.fragment.total_size = DMP_MULTI_PEER_MESSAGE_BYTES;
            spec.extensions = span(service_two_extensions,
                                   sizeof service_two_extensions);
            spec.payload = span(chunk, sizeof chunk);
            CHECK(dmp_hs_seal_logical(peers[4].initiator, replacement_index,
                                      &spec, sealed, sizeof sealed,
                                      &sealed_size) == DMP_HS_OK);
            CHECK(wrap_core(sealed, sealed_size, wrapped, sizeof wrapped,
                            &wrapped_size));
            status = dmp_endpoint_rx_from(
                &right.endpoint, replacement, span(wrapped, wrapped_size),
                fragment_at + fragment_index);
            if (status != (fragment_index + 1U == DMP_MULTI_PEER_FRAGMENTS
                               ? DMP_OK
                               : DMP_INCOMPLETE)) {
                (void)fprintf(stderr,
                              "four-peer 4096-byte fragment %u returned %s (%d)\n",
                              (unsigned)fragment_index,
                              dmp_status_name(status), (int)status);
            }
            CHECK(status == (fragment_index + 1U == DMP_MULTI_PEER_FRAGMENTS
                                 ? DMP_OK
                                 : DMP_INCOMPLETE));
            right.wire.n = 0;
        }
        CHECK((uint32_t)right.app.accepts == accepts_before + 1U &&
              right.app.request_service == 2U &&
              right.app.req_n == DMP_MULTI_PEER_MESSAGE_BYTES &&
              right.app.last_peer.slot == replacement.slot &&
              right.app.last_peer.generation == replacement.generation &&
              right.app.peer_pending_live[replacement.slot] != 0U);
        for (fragment_index = 0U;
             fragment_index < DMP_MULTI_PEER_MESSAGE_BYTES;
             fragment_index++) {
            CHECK(right.app.req[fragment_index] ==
                  (uint8_t)(0x31U + (fragment_index % 197U)));
        }
    }

    for (i = 5U; i > 0U; i--) {
        close_session(&peers[i - 1U]);
    }
    g_endpoint_test_peer_count = 0U;
    g_endpoint_test_scratch_slots = 0U;
    g_endpoint_test_result_slots = 0U;
    g_endpoint_test_handshake_pending = 0U;
    g_endpoint_test_message_bytes = 0U;
    g_endpoint_test_responder_admission_only = 0;
    g_endpoint_test_admission = NULL;
    g_endpoint_test_admission_storage = NULL;
    return 0;

fail:
    g_endpoint_test_sender_id = 0U;
    g_endpoint_test_unique_entropy = 0;
    for (i = 5U; i > 0U; i--) {
        close_session(&peers[i - 1U]);
    }
    g_endpoint_test_peer_count = 0U;
    g_endpoint_test_scratch_slots = 0U;
    g_endpoint_test_result_slots = 0U;
    g_endpoint_test_handshake_pending = 0U;
    g_endpoint_test_message_bytes = 0U;
    g_endpoint_test_responder_admission_only = 0;
    g_endpoint_test_admission = NULL;
    g_endpoint_test_admission_storage = NULL;
    return 1;
}

static int test_protected_multi_peer_routing(void)
{
    if (test_endpoint_shared_admission_four_pending() != 0) {
        return 1;
    }
    /* Keep the lifecycle/routing exercise on both manifest sensitivities:
     * four_parallel owns two crypto slots; four_serial owns one. */
    if (test_protected_multi_peer_routing_profile(
            DMP_MULTI_PEER_PARALLEL_CRYPTO_SLOTS) != 0) {
        return 1;
    }
    return test_protected_multi_peer_routing_profile(
        DMP_MULTI_PEER_SERIAL_CRYPTO_SLOTS);
}

static int test_protected_sample_late_assoc(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    sample_tracker state = {0};
    uint32_t index = 0U;
    uint32_t next_init = 0U;
    uint32_t next_resp = 0U;
    uint32_t old_cid = 0U;
    uint32_t new_cid = 0U;
    uint32_t ack_cid = 0U;
    uint32_t request_cid = 0U;
    uint8_t req[SAMPLE1_READ_BYTES];
    uint8_t response[SAMPLE1_READ_BYTES];
    uint8_t wrapped[FRAME_CAP];
    dmp_reliability_handle handle;
    dmp_reliability_handle current_handle;
    dmp_reliability_handle old_pending;
    dmp_message_key current_request_key;
    dmp_time_ms now = 20000U;
    size_t wrapped_n = 0U;
    size_t result_slot = RESULTS;
    size_t i;

    memset(&env, 0, sizeof(env));
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node_slots(&left, 1, 64U, 16U, now, 2U) == 0);
    CHECK(boot_node_slots(&right, 0, 64U, 16U, now, 2U) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_set_drain_ms(&left.endpoint, 30000U) == DMP_OK);
    CHECK(dmp_endpoint_set_drain_ms(&right.endpoint, 30000U) == DMP_OK);

    state.synchronized = 1;
    state.epoch = 41U;
    state.index = 7U;
    state.value = 700U;
    CHECK(sample1_read_req(req) == 1U);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now, &handle) ==
          DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(right.wire.n == 1);
    CHECK(stream_protection(right.wire.q[0].frame, right.wire.q[0].len, now, &old_cid, NULL,
                            NULL) == 1);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1 && left.app.have_pending);
    old_pending = left.app.pending;
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(right.wire.n == 0);

    CHECK(drive_rotation(&env, fixture, &next_init, &next_resp, 0x5aU));
    CHECK(activate_at(&env, next_init, next_resp));
    CHECK(dmp_endpoint_rotate(&left.endpoint, next_init, now + 1U) == DMP_OK);
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now + 1U) == DMP_OK);
    CHECK(left.endpoint.peers[0].drain_live != 0U &&
          right.endpoint.peers[0].drain_live != 0U);
    new_cid = dmp_hs_rx_cid(env.initiator, next_init);
    CHECK(new_cid != 0U && new_cid != old_cid);

    /* Association replacement returns the consumer to unsynchronized while
     * retaining the prior same-epoch cache for rollback protection. The old
     * request designation is invalidated before a new READ is issued. */
    state.synchronized = 0;
    current_handle.slot = UINT32_MAX;
    current_handle.generation = UINT32_MAX;
    /* SAMPLE-1 applies correlated results synchronously in the serialized
     * endpoint notice callback, so a later replacement cannot interleave. */
    right.sample_state = &state;
    right.sample_designated = current_handle;

    /* A higher-index old-SA result can be correlated and ACKed, but it no
     * longer owns the selected association's initialization generation. */
    CHECK(sample1_read_rsp(response, 41U, 8U, 800U) == sizeof(response));
    CHECK(dmp_endpoint_complete(&left.endpoint, old_pending, false, 0U,
                                span(response, sizeof(response)), now + 2U) == DMP_OK);
    left.app.have_pending = 0;
    left.wire.now = now + 2U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 2U) == DMP_OK);
    CHECK(left.wire.n == 1);
    CHECK(deliver_all(&left, &right, now + 2U) == 0);
    CHECK(right.app.results == 1 && same_handle(right.app.result_request, handle));
    CHECK(right.app.sample_update_attempts == 1U && right.app.sample_update_status != 0);
    CHECK(state.synchronized == 0 && state.epoch == 41U && state.index == 7U &&
          state.value == 700U && state.violations == 0 && state.rollbacks == 0);

    right.wire.now = now + 2U;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 2U) == DMP_OK);
    CHECK(right.wire.n == 1);
    CHECK(stream_protection(right.wire.q[0].frame, right.wire.q[0].len, now + 2U, &ack_cid,
                            NULL, NULL) == 1);
    CHECK(ack_cid == old_cid && ack_cid != new_cid);
    CHECK(deliver_all(&right, &left, now + 2U) == 0);
    for (i = 0U; i < RESULTS; ++i) {
        if (left.results[i].live != 0U) {
            result_slot = i;
            break;
        }
    }
    CHECK(result_slot < RESULTS && left.results[result_slot].acknowledged != 0U);

    /* A new READ on the selected association returns a same-epoch snapshot
     * older than the retained cache; it syncs without rollback. */
    CHECK(sample1_read_req(req) == 1U);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now + 3U,
                                  &current_handle) == DMP_OK);
    right.sample_designated = current_handle;
    right.wire.now = now + 3U;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 3U) == DMP_OK);
    CHECK(right.wire.n == 1);
    CHECK(stream_protection(right.wire.q[0].frame, right.wire.q[0].len, now + 3U,
                            &request_cid, NULL, NULL) == 1);
    CHECK(request_cid == new_cid && request_cid != old_cid);
    CHECK(deliver_all(&right, &left, now + 3U) == 0);
    CHECK(left.app.accepts == 2 && left.app.have_pending);

    /* A reply that names the new READ but is protected by the old draining
     * association resolves to the old local epoch and must not complete it. */
    current_request_key = right.senders[current_handle.slot].own;
    CHECK(sample1_read_rsp(response, 41U, 5U, 500U) == sizeof(response));
    CHECK(seal_sample_result(&env, index, left.results[result_slot].result.seq + 1U,
                             current_request_key.seq, 1U, span(response, sizeof(response)),
                             wrapped, &wrapped_n));
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now + 4U) == DMP_OK);
    CHECK(right.app.results == 1 && right.senders[current_handle.slot].live != 0U &&
          right.app.sample_update_attempts == 1U && right.wire.n == 0);
    CHECK(state.synchronized == 0 && state.epoch == 41U && state.index == 7U &&
          state.value == 700U && state.violations == 0 && state.rollbacks == 0);

    /* The actual response protected by the selected association can complete
     * the same request and restore synchronization without rolling back cache. */
    CHECK(sample1_read_rsp(response, 41U, 6U, 600U) == sizeof(response));
    CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, false, 0U,
                                span(response, sizeof(response)), now + 5U) == DMP_OK);
    left.app.have_pending = 0;
    left.wire.now = now + 5U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 5U) == DMP_OK);
    CHECK(deliver_all(&left, &right, now + 5U) == 0);
    CHECK(right.app.results == 2 && same_handle(right.app.result_request, current_handle));
    CHECK(right.app.sample_update_attempts == 2U && right.app.sample_update_status == 0);
    CHECK(state.synchronized == 1 && state.epoch == 41U && state.index == 7U &&
          state.value == 700U && state.violations == 0 && state.rollbacks == 0);
    CHECK(left.app.accepts == 2);
    close_session(&env);
    return 0;
}

static int test_protected_sample_superseded(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    sample_tracker state = {0};
    uint32_t index = 0U;
    uint8_t read = SAMPLE1_READ;
    uint8_t old_response[SAMPLE1_READ_BYTES];
    uint8_t current_response[SAMPLE1_READ_BYTES];
    dmp_reliability_handle superseded;
    dmp_reliability_handle retired_designation;
    dmp_reliability_handle designated;
    dmp_reliability_handle current_pending;
    dmp_time_ms now = 20000U;

    memset(&env, 0, sizeof(env));
    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);

    /* The app invalidates this full-handle designation while the protected
     * READ remains in flight, before a replacement READ can be submitted. */
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(&read, sizeof(read)), now,
                                  &superseded) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1 && left.app.have_pending);
    current_pending = left.app.pending;
    retired_designation = superseded;
    retired_designation.generation++;
    CHECK(!same_handle(superseded, retired_designation));

    CHECK(sample1_read_rsp(old_response, 41U, 8U, 800U) == sizeof(old_response));
    CHECK(dmp_endpoint_complete(&left.endpoint, current_pending, false, 0U,
                                span(old_response, sizeof(old_response)), now + 2U) == DMP_OK);
    left.wire.now = now + 2U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 2U) == DMP_OK);
    CHECK(deliver_all(&left, &right, now + 2U) == 0);
    CHECK(right.app.results == 1 && same_handle(right.app.result_request, superseded));
    CHECK(sample_accept_read_result(&state, &right.app, retired_designation) != 0);
    CHECK(state.synchronized == 0 && state.epoch == 0U && state.index == 0U &&
          state.value == 0U && state.violations == 0);

    right.wire.now = now + 2U;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 2U) == DMP_OK);
    CHECK(deliver_all(&right, &left, now + 2U) == 0);
    left.wire.now = now + 2U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 2U) == DMP_OK);

    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(&read, sizeof(read)), now + 3U,
                                  &designated) == DMP_OK);
    right.wire.now = now + 3U;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 3U) == DMP_OK);
    CHECK(deliver_all(&right, &left, now + 3U) == 0);
    CHECK(left.app.accepts == 2 && left.app.have_pending);
    current_pending = left.app.pending;
    CHECK(!same_handle(superseded, designated));

    CHECK(sample1_read_rsp(current_response, 42U, 1U, 900U) == sizeof(current_response));
    CHECK(dmp_endpoint_complete(&left.endpoint, current_pending, false, 0U,
                                span(current_response, sizeof(current_response)), now + 3U) ==
          DMP_OK);
    left.app.have_pending = 0;
    left.wire.now = now + 3U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 3U) == DMP_OK);
    CHECK(deliver_all(&left, &right, now + 3U) == 0);
    CHECK(right.app.results == 2 && same_handle(right.app.result_request, designated));
    CHECK(sample_accept_read_result(&state, &right.app, designated) == 0);
    CHECK(state.synchronized == 1 && state.epoch == 42U && state.index == 1U &&
          state.value == 900U && state.violations == 0);

    right.wire.now = now + 3U;
    CHECK(dmp_endpoint_poll(&right.endpoint, now + 3U) == DMP_OK);
    CHECK(deliver_all(&right, &left, now + 3U) == 0);
    left.wire.now = now + 3U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 3U) == DMP_OK);
    close_session(&env);
    return 0;
}

static int exercise_protected_sample_init_retry(int require_retry_success)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    sample_tracker state = {0};
    uint32_t index = 0U;
    uint8_t read = SAMPLE1_READ;
    uint8_t response[SAMPLE1_READ_BYTES];
    dmp_reliability_handle first;
    dmp_reliability_handle second;
    dmp_reliability_handle first_producer_request;
    dmp_reliability_handle second_producer_request;
    dmp_message_key first_key;
    dmp_message_key second_key;
    dmp_status late_status;
    dmp_time_ms now = 20000U;
    dmp_time_ms first_deadline = now + SAMPLE_RESULT_DEADLINE_MS;
    dmp_time_ms retry_at;
    dmp_time_ms init_deadline = now + SAMPLE_INIT_DEADLINE_MS;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(SAMPLE_INIT_ATTEMPTS > 0U && SAMPLE_INIT_RETRY_MS > 0U);
    CHECK(SAMPLE_INIT_DEADLINE_MS > 0U);
    CHECK(SAMPLE_INIT_DEADLINE_MS >=
          SAMPLE_INIT_ATTEMPTS * SAMPLE_RESULT_DEADLINE_MS +
              (SAMPLE_INIT_ATTEMPTS - 1U) * SAMPLE_INIT_RETRY_MS);
    if (require_retry_success) {
        CHECK(SAMPLE_INIT_ATTEMPTS == 2U);
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    right.sample_state = &state;

    /* Each newly bound Stream R endpoint emits its sync delimiter before
     * application frames. Complete that exchange before asserting READ delivery. */
    left.wire.now = now;
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(deliver_all(&right, &left, now) == 0);

    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(&read, sizeof read), now,
                                  &first) == DMP_OK);
    right.sample_designated = first;
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1 && left.app.have_pending &&
          left.app.request_service == 1U && left.app.req_n == sizeof read &&
          left.app.req[0] == SAMPLE1_READ);
    first_producer_request = left.app.pending;
    first_key = right.senders[first.slot].own;

    right.wire.now = first_deadline;
    CHECK(dmp_endpoint_poll(&right.endpoint, first_deadline) == DMP_OK);
    CHECK(right.app.unknowns == 1 && right.app.results == 0);
    CHECK(sample1_read_rsp(response, 9U, 1U, 100U) == sizeof response);
    late_status = dmp_endpoint_complete(&left.endpoint, first_producer_request, false, 0U,
                                        span(response, sizeof response), first_deadline);
    CHECK(late_status == DMP_OK);
    /* Producer completion may queue the response at the deadline. The
     * consumer's expired correlation must still reject it on delivery. */
    left.app.have_pending = 0;
    left.wire.now = first_deadline;
    CHECK(dmp_endpoint_poll(&left.endpoint, first_deadline) == DMP_OK);
    CHECK(deliver_all(&left, &right, first_deadline) == 0);
    CHECK(state.synchronized == 0 && right.app.results == 0);

    if (SAMPLE_INIT_ATTEMPTS == 1U) {
        CHECK(!require_retry_success);
        CHECK(first_deadline == init_deadline);
        close_session(&env);
        return 0;
    }

    CHECK(SAMPLE_INIT_ATTEMPTS == 2U);
    retry_at = first_deadline + SAMPLE_INIT_RETRY_MS;
    CHECK(retry_at < init_deadline);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(&read, sizeof read), retry_at,
                                  &second) == DMP_OK);
    right.sample_designated = second;
    CHECK(!same_handle(first, second));
    second_key = right.senders[second.slot].own;
    CHECK(first_key.origin.namespace_id == second_key.origin.namespace_id &&
          first_key.origin.origin_id == second_key.origin.origin_id &&
          first_key.origin.epoch == second_key.origin.epoch &&
          first_key.seq != second_key.seq);
    right.wire.now = retry_at;
    CHECK(dmp_endpoint_poll(&right.endpoint, retry_at) == DMP_OK);
    CHECK(deliver_all(&right, &left, retry_at) == 0);
    CHECK(left.app.accepts == 2 && left.app.have_pending &&
          left.app.request_service == 1U && left.app.req_n == sizeof read &&
          left.app.req[0] == SAMPLE1_READ);
    second_producer_request = left.app.pending;
    CHECK(!same_handle(first_producer_request, second_producer_request));

    CHECK(sample1_read_rsp(response, 9U, 2U, 200U) == sizeof response);
    CHECK(dmp_endpoint_complete(&left.endpoint, second_producer_request, false, 0U,
                                span(response, sizeof response), retry_at) == DMP_OK);
    left.wire.now = retry_at;
    CHECK(dmp_endpoint_poll(&left.endpoint, retry_at) == DMP_OK);
    CHECK(deliver_all(&left, &right, retry_at) == 0);
    CHECK(left.app.accepts == 2 && right.app.results == 1 &&
          same_handle(right.app.result_request, second) &&
          right.app.sample_update_attempts == 1U &&
          right.app.sample_update_status == 0);
    CHECK(state.synchronized == 1 && state.epoch == 9U && state.index == 2U &&
          state.value == 200U && state.violations == 0);
    CHECK(retry_at < init_deadline && SAMPLE_INIT_ATTEMPTS == 2U);

    /* The original first result identity remains stale after the second READ
     * has become the current designated initialization attempt. */
    late_status = dmp_endpoint_complete(&left.endpoint, first_producer_request, false, 0U,
                                        span(response, sizeof response), retry_at + 1U);
    if (late_status != DMP_STALE_HANDLE) {
        (void)fprintf(stderr, "superseded SAMPLE-1 completion returned %d\n",
                      (int)late_status);
    }
    CHECK(late_status == DMP_STALE_HANDLE);
    close_session(&env);
    return 0;
}

static int test_protected_sample_init_timeout(void)
{
    return exercise_protected_sample_init_retry(0);
}

static int test_protected_sample_init_retry_two_attempts(void)
{
    return exercise_protected_sample_init_retry(1);
}

static int test_protected_sample_invalid_result(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    sample_tracker state = {0};
    uint32_t index = 0U;
    uint8_t read = SAMPLE1_READ;
    uint8_t valid[SAMPLE1_READ_BYTES];
    uint8_t malformed[SAMPLE1_STATUS_BYTES] = {SAMPLE1_STATUS, 2U};
    uint8_t wrapped[FRAME_CAP];
    size_t wrapped_n = 0U;
    dmp_reliability_handle request;
    dmp_message_key request_key;
    dmp_time_ms now = 20000U;
    uint32_t own_seq = 300U;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    g_validate_sample1_results = 1;
    if (boot_node(&left, 1, 64U, 16U, now) != 0 ||
        boot_node(&right, 0, 64U, 16U, now) != 0) {
        g_validate_sample1_results = 0;
        close_session(&env);
        return 1;
    }
    g_validate_sample1_results = 0;
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(&read, sizeof read), now, &request) ==
          DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1 && left.app.have_pending);
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&left, &right, now) == 0);
    request_key = right.senders[request.slot].own;
    expect_sample1_result(&right, request_key, SAMPLE1_READ);
    CHECK(sample1_read_rsp(valid, 9U, 2U, 200U) == sizeof valid);
    {
        uint8_t wrong_opcode[SAMPLE1_STATUS_BYTES];
        CHECK(sample1_status_rsp(wrong_opcode, 1U) == sizeof wrong_opcode);
        CHECK(seal_sample_result(&env, index, own_seq++, request_key.seq, 1U,
                                 span(wrong_opcode, sizeof wrong_opcode), wrapped, &wrapped_n));
        CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_OK);
        CHECK(right.app.results == 0 && right.senders[request.slot].live == 1U &&
              right.wire.n == 0);
    }

    /* The authenticated peer cannot complete this READ under another service. */
    CHECK(seal_sample_result(&env, index, own_seq++, request_key.seq, 2U,
                             span(valid, sizeof valid), wrapped, &wrapped_n));
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_OK);
    CHECK(right.app.results == 0 && right.senders[request.slot].live == 1U);

    /* A protected, correlated RSP with an invalid SAMPLE-1 result schema is
     * dropped before reliability acceptance, so the same READ remains live. */
    CHECK(seal_sample_result(&env, index, own_seq++, request_key.seq, 1U,
                             span(malformed, sizeof malformed), wrapped, &wrapped_n));
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_OK);
    CHECK(right.app.results == 0 && right.senders[request.slot].live == 1U &&
          right.wire.n == 0);
    CHECK(state.synchronized == 0 && state.violations == 0);

    /* A later valid result for the same request is accepted and can sync. */
    CHECK(seal_sample_result(&env, index, own_seq++, request_key.seq, 1U,
                             span(valid, sizeof valid), wrapped, &wrapped_n));
    right.wire.now = now + 1U;
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now + 1U) == DMP_OK);
    CHECK(right.app.results == 1 && right.app.last_status == 0U &&
          same_handle(right.app.result_request, request));
    CHECK(sample_accept_read_result(&state, &right.app, request) == 0);
    CHECK(state.synchronized == 1 && state.epoch == 9U && state.index == 2U &&
          state.value == 200U && state.violations == 0);

    close_session(&env);
    return 0;
}

static int test_protected_sample_invalid_status_result(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t request_payload[1];
    uint8_t invalid_status[SAMPLE1_STATUS_BYTES] = {SAMPLE1_STATUS, 2U};
    uint8_t valid_status[SAMPLE1_STATUS_BYTES];
    uint8_t wrapped[FRAME_CAP];
    size_t wrapped_n = 0U;
    dmp_reliability_handle request;
    dmp_message_key request_key;
    dmp_time_ms now = 20000U;
    uint32_t own_seq = 300U;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    g_validate_sample1_results = 1;
    if (boot_node(&left, 1, 64U, 16U, now) != 0 ||
        boot_node(&right, 0, 64U, 16U, now) != 0) {
        g_validate_sample1_results = 0;
        close_session(&env);
        return 1;
    }
    g_validate_sample1_results = 0;
    CHECK(bind_pair(&env, index) == 0);
    CHECK(sample1_status_req(request_payload) == sizeof request_payload);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U,
                                  span(request_payload, sizeof request_payload), now,
                                  &request) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1 && left.app.req_n == sizeof request_payload &&
          left.app.req[0] == SAMPLE1_STATUS);
    request_key = right.senders[request.slot].own;
    expect_sample1_result(&right, request_key, SAMPLE1_STATUS);

    /* A canonical READ response cannot complete a correlated STATUS. */
    {
        uint8_t wrong_opcode[SAMPLE1_READ_BYTES];
        CHECK(sample1_read_rsp(wrong_opcode, 9U, 2U, 200U) == sizeof wrong_opcode);
        CHECK(seal_sample_result(&env, index, own_seq++, request_key.seq, 1U,
                                 span(wrong_opcode, sizeof wrong_opcode), wrapped, &wrapped_n));
        CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_OK);
        CHECK(right.app.results == 0 && right.senders[request.slot].live == 1U &&
              right.wire.n == 0);
    }

    /* A correlated STATUS response with READY=2 is rejected before the
     * reliability sender completes; a valid response can still complete it. */
    CHECK(seal_sample_result(&env, index, own_seq++, request_key.seq, 1U,
                             span(invalid_status, sizeof invalid_status), wrapped, &wrapped_n));
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now) == DMP_OK);
    CHECK(right.app.results == 0 && right.senders[request.slot].live == 1U &&
          right.wire.n == 0);

    CHECK(sample1_status_rsp(valid_status, 1U) == sizeof valid_status);
    CHECK(seal_sample_result(&env, index, own_seq++, request_key.seq, 1U,
                             span(valid_status, sizeof valid_status), wrapped, &wrapped_n));
    right.wire.now = now + 1U;
    CHECK(dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now + 1U) == DMP_OK);
    CHECK(right.app.results == 1 && right.app.last_status == 0U &&
          same_handle(right.app.result_request, request) &&
          right.app.result_n == sizeof valid_status &&
          memcmp(right.app.result, valid_status, sizeof valid_status) == 0);
    close_session(&env);
    return 0;
}

static int test_protected_sample_invalid_telem(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    sample_tracker state = {0};
    uint32_t index = 0U;
    uint8_t telem[SAMPLE1_TELEM_BYTES + 1U] = {0};
    dmp_time_ms now = 20000U;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);

    /* The endpoint transports opaque bytes; the application rejects both
     * short and schema-invalid SAMPLE-1 TELEM payloads before state changes. */
    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, 15U), now) == DMP_OK);
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(right.app.telems == 1);
    CHECK(sample_observe_telem(&state, span(telem, 15U)) != 0);
    CHECK(state.synchronized == 0 && state.violations == 0);

    CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U, span(telem, sizeof telem), now + 1U) ==
          DMP_OK);
    left.wire.now = now + 1U;
    CHECK(dmp_endpoint_poll(&left.endpoint, now + 1U) == DMP_OK);
    CHECK(deliver_all(&left, &right, now + 1U) == 0);
    CHECK(right.app.telems == 2);
    CHECK(sample_observe_telem(&state, span(telem, sizeof telem)) != 0);
    CHECK(state.synchronized == 0 && state.violations == 0);

    close_session(&env);
    return 0;
}

static int run_protected_sample_fragmented_result(int valid_result)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t read = SAMPLE1_READ;
    uint8_t result[SAMPLE1_READ_BYTES];
    uint8_t wrapped[FRAME_CAP];
    size_t wrapped_n = 0U;
    dmp_reliability_handle request;
    dmp_message_key request_key;
    dmp_time_ms now = 20000U;
    dmp_time_ms valid_result_at = now + 2U;
    uint32_t fragment;
    dmp_status status;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    g_validate_sample1_results = 1;
    if (boot_node(&left, 1, 64U, 16U, now) != 0 ||
        boot_node(&right, 0, 64U, 16U, now) != 0) {
        g_validate_sample1_results = 0;
        close_session(&env);
        return 1;
    }
    g_validate_sample1_results = 0;
    CHECK(bind_pair(&env, index) == 0);

    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(&read, 1U), now, &request) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1 && left.app.have_pending);
    request_key = right.senders[request.slot].own;
    expect_sample1_result(&right, request_key, SAMPLE1_READ);

    if (valid_result == 0) {
        uint8_t wrong_opcode[SAMPLE1_STATUS_BYTES];
        CHECK(sample1_status_rsp(wrong_opcode, 1U) == sizeof wrong_opcode);
        for (fragment = 0U; fragment < 2U; ++fragment) {
            CHECK(seal_sample_result_fragment(&env, index, 300U, request_key.seq,
                                              fragment, 1U, sizeof wrong_opcode,
                                              span(wrong_opcode + fragment, 1U), wrapped,
                                              &wrapped_n));
            right.wire.now = now + fragment;
            status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n),
                                     now + fragment);
            CHECK(status == (fragment == 0U ? DMP_INCOMPLETE : DMP_OK));
        }
        CHECK(right.app.results == 0 && right.senders[request.slot].live != 0U &&
              right.wire.n == 0);
        CHECK(right.endpoint.profile.assemblies_per_peer == 1U);
        CHECK(right.endpoint.reassembly.storage.assemblies[0].live == 0U);
        CHECK(right.endpoint.reassembly.storage.tombstones[0].state ==
              DMP_REASSEMBLY_TOMBSTONE_REJECTED);

        /* A fresh-PN replay cannot recreate the rejected assembly, and it does
         * not prevent the next valid fragmented result from using the single
         * DIRECT-1 assembly slot. */
        for (fragment = 0U; fragment < 2U; ++fragment) {
            size_t offset = (size_t)fragment;
            CHECK(seal_sample_result_fragment(&env, index, 300U, request_key.seq,
                                              fragment, 1U, sizeof wrong_opcode,
                                              span(wrong_opcode + offset, 1U), wrapped,
                                              &wrapped_n));
            right.wire.now = now + 2U + fragment;
            status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n),
                                     now + 2U + fragment);
            CHECK(status == DMP_DUPLICATE);
            CHECK(right.endpoint.reassembly.storage.assemblies[0].live == 0U);
        }
        CHECK(right.app.results == 0 && right.senders[request.slot].live != 0U &&
              right.wire.n == 0);
        valid_result_at = now + 4U;
    }

    CHECK(sample1_read_rsp(result, 9U, 2U, 200U) == sizeof result);
    for (fragment = 0U; fragment < 2U; ++fragment) {
        size_t offset = (size_t)fragment * 16U;
        size_t slice_n = sizeof result - offset;
        if (slice_n > 16U) {
            slice_n = 16U;
        }
        CHECK(seal_sample_result_fragment(&env, index, 301U, request_key.seq, fragment, 16U,
                                         sizeof result, span(result + offset, slice_n), wrapped,
                                         &wrapped_n));
        right.wire.now = valid_result_at + fragment;
        status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n),
                                 valid_result_at + fragment);
        if (status != (fragment == 0U ? DMP_INCOMPLETE : DMP_OK)) {
            (void)fprintf(stderr,
                          "follow-up SAMPLE-1 fragment %u returned %s (%d)\n",
                          (unsigned)fragment, dmp_status_name(status), (int)status);
            return 1;
        }
    }
    CHECK(right.app.results == 1 && right.app.last_status == 0U &&
          same_handle(right.app.result_request, request));
    CHECK(right.app.result_n == sizeof result &&
          memcmp(right.app.result, result, sizeof result) == 0);
    close_session(&env);
    return 0;
}

static int test_protected_sample_fragmented_result(void)
{
    return run_protected_sample_fragmented_result(1);
}

static int test_protected_sample_invalid_fragmented_result(void)
{
    return run_protected_sample_fragmented_result(0);
}

static int test_protected_err_status_contract(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t read = SAMPLE1_READ;
    uint8_t request_type = 0U;
    uint32_t request_seq = 0U;
    uint8_t extensions[12];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    size_t ext_n;
    dmp_frame_spec spec;
    dmp_reliability_handle request;
    dmp_bytes empty = span(NULL, 0U);
    uint32_t wire_status = 0U;
    uint8_t response_type = 0U;
    uint32_t own_seq = 200U;
    uint32_t status;
    dmp_status receive_status;
    dmp_time_ms now = 20000U;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    CHECK(boot_node(&left, 1, 64U, 16U, now) == 0);
    CHECK(boot_node(&right, 0, 64U, 16U, now) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(&read, sizeof read), now, &request) ==
          DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(protected_frame_type_seq(right.wire.last, right.wire.last_len, now, &request_type,
                                   &request_seq));
    CHECK(request_type == DMP_TYPE_REQ && request_seq < 128U);
    CHECK(deliver_all(&right, &left, now) == 0);
    CHECK(left.app.accepts == 1 && left.app.have_pending);

    /* Core parsing rejects ACK_REQ on STATUS 1-7 before a protected record can
     * be constructed; the codec regression covers that rule. The authenticated
     * endpoint must also reject every reserved STATUS 8-63 for local delivery. */
    for (status = 8U; status <= 63U; ++status) {
        memset(&spec, 0, sizeof spec);
        ext_n = 0U;
        extensions[ext_n++] = 0x05U;
        extensions[ext_n++] = 1U;
        ext_n += encode_test_uleb32(request_seq, extensions + ext_n);
        extensions[ext_n++] = 0x15U;
        extensions[ext_n++] = 1U;
        extensions[ext_n++] = (uint8_t)status;
        spec.fields.type = (uint8_t)DMP_TYPE_ERR;
        spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_EXT);
        spec.fields.seq = own_seq++;
        spec.extensions = span(extensions, ext_n);
        spec.payload = empty;
        CHECK(dmp_hs_seal_logical(env.initiator, index, &spec, sealed, sizeof sealed, &sealed_n) ==
              DMP_HS_OK);
        CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n));
        receive_status = dmp_endpoint_rx(&right.endpoint, span(wrapped, wrapped_n), now);
        if (receive_status != DMP_UNSUPPORTED) {
            (void)fprintf(stderr, "reserved STATUS=%lu returned %d\n", (unsigned long)status,
                          (int)receive_status);
        }
        CHECK(receive_status == DMP_UNSUPPORTED);
        CHECK(right.app.results == 0);
    }

    /* A valid terminal application ERR=64 remains reliable and completes the
     * same request after the invalid responses were rejected. */
    CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, true, 64U, empty, now) ==
          DMP_OK);
    left.app.have_pending = 0;
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == 1);
    CHECK(protected_frame_type_seq(left.wire.q[0].frame, left.wire.q[0].len, now,
                                   &response_type, NULL));
    CHECK(response_type == DMP_TYPE_ERR);
    CHECK(protected_err_status(left.wire.q[0].frame, left.wire.q[0].len, now, &wire_status));
    CHECK(wire_status == 64U);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(right.app.results == 1 && right.app.last_status == 64U && right.app.result_n == 0U);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    close_session(&env);
    return 0;
}

static void issue_test_freshness(node *receiver, uint32_t attempt, dmp_time_ms now,
                                 const uint8_t token[16])
{
    dmp_endpoint_freshness_slot *freshness = &receiver->freshness[0];
    const dmp_identity_slot *identity =
        &receiver->endpoint.identity.slots[
            receiver->endpoint.peers[0].context.slot];
    memset(freshness, 0, sizeof *freshness);
    freshness->peer = receiver->endpoint.peers[0].handle;
    memcpy(freshness->token, token, sizeof freshness->token);
    freshness->expires_at = now + 12000U;
    freshness->record_until = now + 18000U;
    freshness->peer_epoch = identity->peer.epoch;
    freshness->principal = identity->peer.origin_id;
    freshness->attempt = attempt;
    freshness->result_slot = UINT32_MAX;
    freshness->granted_lifetime_ms = 12000U;
    freshness->state = DMP_ENDPOINT_FRESHNESS_ISSUED;
}

static int test_sample_invalid_request(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t invalid_length[2] = {SAMPLE1_READ, 0U};
    uint8_t invalid_status[2] = {SAMPLE1_STATUS, 2U};
    uint8_t invalid_opcode = 3U;
    uint8_t read = SAMPLE1_READ;
    dmp_time_ms now = 20000U;
    uint32_t validator_calls;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    g_sample1_validator_calls = 0U;
    g_sample1_forced_status = 0U;
    g_validate_sample1_requests = 1;
    if (boot_node(&left, 1, 64U, 16U, now) != 0 ||
        boot_node(&right, 0, 64U, 16U, now) != 0) {
        g_validate_sample1_requests = 0;
        close_session(&env);
        return 1;
    }
    g_validate_sample1_requests = 0;
    if (bind_pair(&env, index) != 0) {
        close_session(&env);
        return 1;
    }

    /* At a two-byte profile limit this is malformed SAMPLE-1, STATUS=7.
     * At a one-byte limit the size decision takes precedence, STATUS=3. */
    left.endpoint.profile.message_bytes = 2U;
    CHECK(expect_request_rejection(&env, 100U, DMP_OPT_ACK_REQ,
                                   span(invalid_length, sizeof invalid_length), 0, 7U, now));
    validator_calls = g_sample1_validator_calls;
    CHECK(expect_request_rejection(&env, 100U, DMP_OPT_ACK_REQ,
                                   span(invalid_length, sizeof invalid_length), 0, 7U, now));
    CHECK(g_sample1_validator_calls == validator_calls);
    left.endpoint.profile.message_bytes = 1U;
    CHECK(expect_request_rejection(&env, 101U, DMP_OPT_ACK_REQ,
                                   span(invalid_length, sizeof invalid_length), 0, 3U, now));
    CHECK(expect_request_rejection(&env, 101U, DMP_OPT_ACK_REQ,
                                   span(invalid_length, sizeof invalid_length), 0, 3U, now));
    left.endpoint.profile.message_bytes = 2U;
    CHECK(expect_request_rejection(&env, 102U, DMP_OPT_ACK_REQ,
                                   span(&invalid_opcode, sizeof invalid_opcode), 0, 7U, now));
    CHECK(expect_request_rejection(&env, 103U, DMP_OPT_ACK_REQ, span(NULL, 0U), 0, 7U, now));
    CHECK(expect_request_rejection(&env, 104U, DMP_OPT_ACK_REQ,
                                   span(invalid_status, sizeof invalid_status), 0, 7U, now));
    CHECK(expect_request_rejection(&env, 105U,
                                   (uint8_t)(DMP_OPT_ACK_REQ | DMP_OPT_PAYLOAD_DESC),
                                   span(&read, sizeof read), 1, 2U, now));
    CHECK(expect_request_rejection(&env, 106U, 0U, span(&read, sizeof read), 0, 7U, now));
    /* A retransmitted no-ACK request with a fresh PN replays the retained
     * rejection and still cannot reach the application. */
    CHECK(expect_request_rejection(&env, 106U, 0U, span(&read, sizeof read), 0, 7U, now));
    CHECK(expect_request_rejection(&env, 107U, DMP_OPT_ACK_REQ,
                                   span(&invalid_opcode, sizeof invalid_opcode), 0, 7U, now));
    CHECK(expect_request_rejection(&env, 107U, DMP_OPT_ACK_REQ,
                                   span(&invalid_opcode, sizeof invalid_opcode), 0, 7U,
                                   now + 6001U));
    CHECK(left.app.accepts == 0);
    close_session(&env);
    return 0;
}

static int test_validator_duplicate_skipped(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t read = SAMPLE1_READ;
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    dmp_frame_spec spec;
    dmp_time_ms now = 20000U;
    uint32_t validator_calls;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    g_sample1_validator_calls = 0U;
    g_sample1_forced_status = 0U;
    g_validate_sample1_requests = 1;
    if (boot_node(&left, 1, 64U, 16U, now) != 0 ||
        boot_node(&right, 0, 64U, 16U, now) != 0) {
        g_validate_sample1_requests = 0;
        close_session(&env);
        return 1;
    }
    g_validate_sample1_requests = 0;
    if (bind_pair(&env, index) != 0) {
        close_session(&env);
        return 1;
    }

    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ);
    spec.fields.seq = 108U;
    spec.payload = span(&read, sizeof read);
    CHECK(dmp_hs_seal_logical(env.responder, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    CHECK(dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), now) == DMP_OK);
    CHECK(left.app.accepts == 1);
    validator_calls = g_sample1_validator_calls;

    /* Retained identity wins before application policy; this fresh-PN retry
     * must not invoke a now-different validator policy. */
    g_sample1_forced_status = 7U;
    CHECK(dmp_hs_seal_logical(env.responder, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    CHECK(dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), now) == DMP_OK);
    CHECK(g_sample1_validator_calls == validator_calls);
    CHECK(left.app.accepts == 1);
    g_sample1_forced_status = 0U;
    close_session(&env);
    return 0;
}

static int test_retained_rejection_reassembly(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t invalid_opcode = 3U;
    uint8_t fragmented_body[32];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    int queued;
    uint32_t validator_calls;
    uint32_t wire_status = 0U;
    dmp_frame_spec spec;
    dmp_time_ms now = 20000U;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    g_sample1_validator_calls = 0U;
    g_sample1_forced_status = 0U;
    g_validate_sample1_requests = 1;
    if (boot_node(&left, 1, 64U, 16U, now) != 0 ||
        boot_node(&right, 0, 64U, 16U, now) != 0) {
        g_validate_sample1_requests = 0;
        close_session(&env);
        return 1;
    }
    g_validate_sample1_requests = 0;
    if (bind_pair(&env, index) != 0) {
        close_session(&env);
        return 1;
    }

    CHECK(expect_request_rejection(&env, 122U, DMP_OPT_ACK_REQ,
                                   span(&invalid_opcode, sizeof invalid_opcode), 0, 7U, now));
    validator_calls = g_sample1_validator_calls;
    CHECK(left.app.accepts == 0);
    queued = left.wire.n;

    memset(fragmented_body, 0x44, sizeof fragmented_body);
    fragmented_body[0] = invalid_opcode;
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_FRAG);
    spec.fields.seq = 122U;
    spec.fields.fragment.chunk_size = 16U;
    spec.fields.fragment.total_size = sizeof fragmented_body;
    spec.payload = span(fragmented_body, 16U);
    CHECK(dmp_hs_seal_logical(env.responder, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    CHECK(dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), now) == DMP_INCOMPLETE);

    spec.fields.fragment.index = 1U;
    spec.payload = span(fragmented_body + 16U, 16U);
    CHECK(dmp_hs_seal_logical(env.responder, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    CHECK(dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), now) == DMP_OK);
    CHECK(g_sample1_validator_calls == validator_calls);
    CHECK(left.app.accepts == 0);
    CHECK(left.app.assembled == 0);
    CHECK(left.endpoint.reassembly.storage.assemblies[0].live == 0U);
    CHECK(left.endpoint.reassembly.storage.tombstones[0].state ==
          DMP_REASSEMBLY_TOMBSTONE_REJECTED);

    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(left.wire.n == queued + 1);
    CHECK(protected_err_status(left.wire.q[queued].frame, left.wire.q[queued].len, now,
                               &wire_status));
    CHECK(wire_status == 7U);
    close_session(&env);
    return 0;
}

static int test_freshness_terminal_rejection(void)
{
    const noise_fixture_probe_fixture_t *fixture = find_fixture("nnpsk0");
    session env;
    port_ctx port;
    uint32_t index = 0U;
    uint8_t token[16];
    uint8_t extension[18];
    uint8_t invalid_opcode = 3U;
    uint8_t read = SAMPLE1_READ;
    uint8_t fragmented_body[32];
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    dmp_frame_spec spec;
    dmp_time_ms now = 20000U;
    dmp_time_ms after_rejection;
    dmp_status status;
    size_t i;

    if (fixture == NULL || !make_pair(&env, &port, fixture, NULL, NULL, 0) ||
        !drive_nn(&env, &index) || !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    g_sample1_validator_calls = 0U;
    g_sample1_forced_status = 0U;
    g_validate_sample1_requests = 1;
    if (boot_node(&left, 1, 16U, 16U, now) != 0 ||
        boot_node(&right, 0, 16U, 16U, now) != 0) {
        g_validate_sample1_requests = 0;
        close_session(&env);
        return 1;
    }
    g_validate_sample1_requests = 0;
    if (bind_pair(&env, index) != 0) {
        close_session(&env);
        return 1;
    }

    left.endpoint.profile.freshness_required_mask = 1U;
    left.endpoint.profile.freshness_tokens_per_association = 1U;
    left.endpoint.profile.freshness_lease_ms = 12000U;
    left.endpoint.profile.freshness_token_record_ms = 18000U;
    memset(token, 0x31, sizeof token);
    issue_test_freshness(&left, index, now, token);
    extension[0] = 25U;
    extension[1] = 16U;
    memcpy(extension + 2U, token, sizeof token);

    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_EXT);
    spec.fields.seq = 120U;
    spec.extensions = span(extension, sizeof extension);
    spec.payload = span(&invalid_opcode, sizeof invalid_opcode);
    CHECK(dmp_hs_seal_logical(env.responder, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    CHECK(dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), now) == DMP_OK);
    CHECK(left.freshness[0].state == DMP_ENDPOINT_FRESHNESS_CONSUMED);
    CHECK(left.app.accepts == 0);

    /* Once the rejection identity expires, the spent token cannot authorize a
     * different payload under the same SEQ. */
    after_rejection = now + 6001U;
    left.wire.now = after_rejection;
    CHECK(dmp_endpoint_poll(&left.endpoint, after_rejection) == DMP_OK);
    spec.payload = span(&read, sizeof read);
    CHECK(dmp_hs_seal_logical(env.responder, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), after_rejection);
    CHECK(status == DMP_OK);
    CHECK(left.app.accepts == 0);
    CHECK(left.freshness[0].state == DMP_ENDPOINT_FRESHNESS_CONSUMED);

    memset(token, 0x52, sizeof token);
    issue_test_freshness(&left, index, after_rejection, token);
    memcpy(extension + 2U, token, sizeof token);
    for (i = 0U; i < sizeof fragmented_body; i++) {
        fragmented_body[i] = (uint8_t)(0x40U + (uint8_t)i);
    }
    memset(&spec, 0, sizeof spec);
    spec.fields.type = (uint8_t)DMP_TYPE_REQ;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_FRAG | DMP_OPT_EXT);
    spec.fields.seq = 121U;
    spec.fields.fragment.chunk_size = 16U;
    spec.fields.fragment.total_size = sizeof fragmented_body;
    spec.extensions = span(extension, sizeof extension);
    spec.payload = span(fragmented_body, 16U);
    CHECK(dmp_hs_seal_logical(env.responder, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    status = dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), after_rejection);
    CHECK(status == DMP_INCOMPLETE);
    spec.fields.fragment.index = 1U;
    spec.payload = span(fragmented_body + 16U, 16U);
    CHECK(dmp_hs_seal_logical(env.responder, index, &spec, sealed, sizeof sealed, &sealed_n) ==
          DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    CHECK(dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), after_rejection) == DMP_OK);
    CHECK(left.freshness[0].state == DMP_ENDPOINT_FRESHNESS_CONSUMED);
    CHECK(left.app.accepts == 0);
    CHECK(left.app.assembled == 0);
    close_session(&env);
    return 0;
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
    uint8_t response[SAMPLE1_READ_BYTES];
    uint8_t other_request = 0x55U;
    uint8_t service_two_extensions[3] = {17U, 1U, 2U};
    uint8_t sealed[MTU];
    uint8_t wrapped[FRAME_CAP];
    size_t sealed_n = 0U;
    size_t wrapped_n = 0U;
    dmp_frame_spec old_work;
    uint8_t saved[FRAME_CAP];
    size_t saved_len = 0U;
    dmp_reliability_handle handle;
    dmp_reliability_handle sample_handle;
    sample_tracker sample_state = {0};
    dmp_identity_context_config occupied_identity;
    dmp_identity_handle occupied_context;
    dmp_time_ms now = 20000U;
    int accepts;

    /* The configured two-slot arena is full, so rotation cannot overlap. */
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
    memset(&occupied_identity, 0, sizeof occupied_identity);
    occupied_identity.local.namespace_id = LOCAL_NS;
    occupied_identity.local.origin_id = ID_INIT;
    occupied_identity.local.epoch = 101U;
    occupied_identity.peer.namespace_id = LOCAL_NS;
    occupied_identity.peer.origin_id = ID_RESP;
    occupied_identity.peer.epoch = 102U;
    occupied_identity.security = 1U;
    CHECK(dmp_identity_context_open(&left.endpoint.identity, &occupied_identity,
                                    &occupied_context) == DMP_OK);
    occupied_identity.local.origin_id = ID_RESP;
    occupied_identity.local.epoch = 102U;
    occupied_identity.peer.origin_id = ID_INIT;
    occupied_identity.peer.epoch = 101U;
    CHECK(dmp_identity_context_open(&right.endpoint.identity, &occupied_identity,
                                    &occupied_context) == DMP_OK);
    CHECK(dmp_endpoint_rotate(&left.endpoint, index, now) == DMP_BUSY);
    if (!drive_rotation(&env, fixture, &next_init, &next_resp, 0x5aU) ||
        !activate_at(&env, next_init, next_resp)) {
        close_session(&env);
        return 1;
    }
    CHECK(dmp_endpoint_rotate(&left.endpoint, next_init, now) == DMP_QUOTA_EXHAUSTED);
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_QUOTA_EXHAUSTED);
    CHECK(left.endpoint.peers[0].drain_live == 0U);
    CHECK(right.endpoint.peers[0].drain_live == 0U);
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
    /* Complete the Stream R preamble before dropping the application frame. */
    left.wire.now = now;
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(deliver_all(&right, &left, now) == 0);
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
    /* Rotation commits locally. Until the other endpoint switches, its new
     * work under the old active key is still authenticated receive traffic on
     * our bounded draining association; the wire has no drain marker. */
    memset(&old_work, 0, sizeof old_work);
    old_work.fields.type = DMP_TYPE_REQ;
    old_work.fields.options = DMP_OPT_SEQ | DMP_OPT_ACK_REQ | DMP_OPT_EXT;
    old_work.fields.seq = 700U;
    old_work.extensions = span(service_two_extensions, sizeof service_two_extensions);
    old_work.payload = span(&other_request, 1U);
    CHECK(dmp_hs_seal_logical(env.responder, index, &old_work, sealed, sizeof sealed,
                              &sealed_n) == DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    CHECK(stream_protection(wrapped, wrapped_n, now, &new_cid, NULL, NULL) == 1);
    CHECK(new_cid == old_cid);
    CHECK(dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), now) == DMP_OK);
    CHECK(left.app.accepts == 1 && left.app.request_service == 2U);
    CHECK(left.app.last_notice_association.slot ==
          left.endpoint.peers[0].drain_context.slot);
    CHECK(left.app.last_notice_association.generation ==
          left.endpoint.peers[0].drain_context.generation);
    /* This request is deliberately independent of the already-dropped READ;
     * release the fixture callback without manufacturing a sender record on
     * the remote side. */
    left.app.have_pending = 0;
    CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_OK);
    CHECK(right.app.unknowns == 0);
    CHECK(pump(now + 1280U, 8) == 0);
    CHECK(left.app.accepts == 2);
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

    /* Keep a fresh, valid old-SA packet with a PN the receiver has never seen.
     * Deliver it only after drain expiry so replay rejection cannot masquerade
     * as the association-lifetime fence. */
    old_work.fields.seq = 701U;
    CHECK(dmp_hs_seal_logical(env.responder, index, &old_work, sealed, sizeof sealed,
                              &sealed_n) == DMP_HS_OK);
    CHECK(wrap_core(sealed, sealed_n, wrapped, sizeof wrapped, &wrapped_n) == 1);
    CHECK(stream_protection(wrapped, wrapped_n, now, &new_cid, NULL, NULL) == 1);
    CHECK(new_cid == old_cid);
    now = 20000U + 30000U;
    left.wire.now = now;
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(dmp_hs_send_application(env.initiator, index) != DMP_HS_OK);
    accepts = left.app.accepts;
    CHECK(dmp_endpoint_rx(&left.endpoint, span(wrapped, wrapped_n), now) ==
          DMP_AUTHENTICATION_FAILURE);
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
    /* Consume each Stream R endpoint's one-byte synchronization preamble. */
    left.wire.now = now;
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(deliver_all(&right, &left, now) == 0);
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

    /* A SAMPLE-1 epoch change closes the old shared association. A pending
     * READ is settled as unknown, and unrelated service-2 DATA is not retried
     * on the newly active association. The next READ initializes the new
     * sample epoch after pre-sync telemetry is discarded. */
    memset(&env, 0, sizeof env);
    now = 50000U;
    if (!make_pair(&env, &port, fixture, NULL, NULL, 0) || !drive_nn(&env, &index) ||
        !activate(&env, index)) {
        close_session(&env);
        return 1;
    }
    env.now = now;
    CHECK(boot_node_slots(&left, 1, 64U, 16U, now, 2U) == 0);
    CHECK(boot_node_slots(&right, 0, 64U, 16U, now, 2U) == 0);
    CHECK(bind_pair(&env, index) == 0);
    CHECK(dmp_endpoint_set_drain_ms(&left.endpoint, 0U) == DMP_OK);
    CHECK(dmp_endpoint_set_drain_ms(&right.endpoint, 0U) == DMP_OK);
    left.wire.now = now;
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(deliver_all(&right, &left, now) == 0);
    sample_state.synchronized = 1;
    sample_state.epoch = 41U;
    sample_state.index = 7U;
    sample_state.value = 700U;
    sample1_read_req(req);
    CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now,
                                  &sample_handle) == DMP_OK);
    right.wire.now = now;
    CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&right, &left, now) == 0);
    left.wire.now = now;
    CHECK(dmp_endpoint_poll(&left.endpoint, now) == DMP_OK);
    CHECK(deliver_all(&left, &right, now) == 0);
    CHECK(left.app.accepts == 1 && left.app.have_pending == 1);
    CHECK(right.app.results == 0);
    CHECK(dmp_endpoint_abandon_request(&left.endpoint, left.app.pending, now) == DMP_BUSY);
    /* The reference application discards the prior generation at transition. */
    sample_state.synchronized = 0;
    {
        const uint8_t data[] = {0xA1U, 0xB2U, 0xC3U};
        int old_submits;
        right.wire.drop_remaining = 1;
        CHECK(dmp_endpoint_submit_data(&right.endpoint, 2U, span(data, sizeof data), span(NULL, 0U),
                                       now, &handle) == DMP_OK);
        right.wire.now = now;
        CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
        CHECK(right.wire.saved_len > 0U);
        CHECK(stream_protection(right.wire.saved, right.wire.saved_len, now, &old_cid, NULL, NULL) ==
              1);
        CHECK(right.app.data_unknowns == 0);
        old_submits = right.wire.submits;
        if (!drive_rotation(&env, fixture, &next_init, &next_resp, 0x5aU) ||
            !activate_at(&env, next_init, next_resp)) {
            close_session(&env);
            return 1;
        }
        CHECK(dmp_endpoint_rotate(&left.endpoint, next_init, now) == DMP_OK);
        CHECK(dmp_endpoint_rotate(&right.endpoint, next_resp, now) == DMP_OK);
        right.wire.now = now;
        CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
        /* The cancelled READ correlation keeps the old identity reserved until
         * its late-result rejection window expires, although the drain deadline
         * is already closed to traffic. */
        CHECK(right.endpoint.peers[0].drain_live != 0U);
        CHECK(right.endpoint.peers[0].drain_reservation_live != 0U);
        CHECK(right.app.unknowns == 1);
        CHECK(right.app.data_unknowns == 1);
        CHECK(right.app.data_unknown_service == 2U);
        CHECK(right.app.results == 0 && sample_state.synchronized == 0);
        {
            dmp_status stale_result = dmp_endpoint_complete(
                &left.endpoint, left.app.pending, false, 0U,
                span(READ_RSP, sizeof READ_RSP), now);
            CHECK(stale_result == DMP_STALE_HANDLE ||
                  stale_result == DMP_DEADLINE_EXPIRED);
        }
        CHECK(dmp_endpoint_abandon_request(&left.endpoint, left.app.pending, now) == DMP_OK);
        left.app.have_pending = 0;
        right.wire.n = 0;
        CHECK(dmp_endpoint_poll(&right.endpoint, now + 100U) == DMP_OK);
        CHECK(right.wire.submits == old_submits);
        CHECK(right.wire.n == 0);
        CHECK(dmp_endpoint_submit_data(&right.endpoint, 2U, span(data, sizeof data), span(NULL, 0U),
                                       now + 100U, &handle) == DMP_OK);
        right.wire.now = now + 100U;
        CHECK(dmp_endpoint_poll(&right.endpoint, now + 100U) == DMP_OK);
        CHECK(right.wire.n == 1);
        CHECK(stream_protection(right.wire.q[0].frame, right.wire.q[0].len, now + 100U,
                                &new_cid, NULL, NULL) == 1);
        CHECK(new_cid != old_cid);

        /* Use the full SAMPLE-1 frame; req above is only the one-byte READ. */
        {
            uint8_t telem[SAMPLE1_TELEM_BYTES];
            CHECK(sample1_telem(telem, 42U, 1U, 900U) == sizeof telem);
            CHECK(dmp_endpoint_submit_telem(&left.endpoint, 1U,
                                            span(telem, sizeof telem), now + 100U) == DMP_OK);
            left.wire.now = now + 100U;
            CHECK(dmp_endpoint_poll(&left.endpoint, now + 100U) == DMP_OK);
            CHECK(deliver_all(&left, &right, now + 100U) == 0);
            right.wire.now = now + 100U;
            CHECK(dmp_endpoint_poll(&right.endpoint, now + 100U) == DMP_OK);
            CHECK(deliver_all(&right, &left, now + 100U) == 0);
            CHECK(right.app.telems == 1);
            CHECK(sample_observe_telem(&sample_state, span(telem, sizeof telem)) == 0);
            CHECK(sample_state.synchronized == 0 && sample_state.discarded == 1);
        }
        CHECK(sample1_read_req(req) == 1U);
        CHECK(dmp_endpoint_submit_req(&right.endpoint, 1U, span(req, 1U), now + 200U,
                                      &sample_handle) == DMP_OK);
        right.wire.now = now + 200U;
        CHECK(dmp_endpoint_poll(&right.endpoint, now + 200U) == DMP_OK);
        CHECK(deliver_all(&right, &left, now + 200U) == 0);
        CHECK(left.app.accepts == 2 && left.app.have_pending == 1);
        CHECK(sample1_read_rsp(response, 42U, 1U, 900U) == sizeof response);
        CHECK(dmp_endpoint_complete(&left.endpoint, left.app.pending, false, 0U,
                                    span(response, sizeof response), now + 200U) == DMP_OK);
        left.app.have_pending = 0;
        left.wire.now = now + 200U;
        CHECK(dmp_endpoint_poll(&left.endpoint, now + 200U) == DMP_OK);
        CHECK(deliver_all(&left, &right, now + 200U) == 0);
        CHECK(right.app.results == 1);
        CHECK(sample_accept_read_result(&sample_state, &right.app, sample_handle) == 0);
        CHECK(sample_state.synchronized == 1 && sample_state.epoch == 42U &&
              sample_state.index == 1U && sample_state.value == 900U &&
              sample_state.violations == 0);
        {
            dmp_time_ms lifecycle_at =
                now + right.endpoint.profile.correlation_ms + 32U;
            dmp_status lifecycle = dmp_endpoint_poll(&right.endpoint, lifecycle_at);
            CHECK(lifecycle == DMP_OK || lifecycle == DMP_DEADLINE_EXPIRED);
            lifecycle = dmp_endpoint_poll(&left.endpoint, lifecycle_at);
            CHECK(lifecycle == DMP_OK || lifecycle == DMP_DEADLINE_EXPIRED);
            CHECK(right.endpoint.peers[0].drain_live == 0U);
            CHECK(right.endpoint.peers[0].drain_reservation_live == 0U);
            CHECK(left.endpoint.peers[0].drain_live == 0U);
        }
    }
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
    dmp_frame_view reassembly_frame;
    dmp_reassembly_input reassembly_input;
    dmp_reassembly_handle rejected_handle;
    dmp_reassembly_handle accepted_handle;
    dmp_identity_handle rejected_context;
    dmp_identity_slot *draining;
    uint32_t index = 0U;
    uint32_t next_init = 0U;
    uint32_t next_resp = 0U;
    uint32_t later_init = 0U;
    uint32_t later_resp = 0U;
    uint8_t body[16];
    uint8_t rejected_body[32];
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
    dmp_time_ms later_drain_at;
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
    CHECK(right.endpoint.peers[0].drain_live == 1U);
    CHECK(right.endpoint.peers[0].drain_attempt == index);
    drain_at = right.endpoint.peers[0].drain_not_after;
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
    draining = &right.endpoint.identity.slots[
        right.endpoint.peers[0].drain_context.slot];
    CHECK(right.endpoint.peers[0].drain_live == 1U);
    CHECK(draining->state == DMP_IDENTITY_SLOT_DRAINING);
    CHECK(draining->retained != 0U);
    CHECK(dmp_endpoint_poll(&right.endpoint, assembly_at) == DMP_OK);
    CHECK(right.endpoint.peers[0].drain_live == 0U);
    CHECK(draining->state == DMP_IDENTITY_SLOT_UNUSED);
    if (!drive_rotation(&env, fixture, &later_init, &later_resp, 0xa5U) ||
        !activate_at(&env, later_init, later_resp)) {
        close_session(&env);
        return 1;
    }
    env.now = assembly_at;
    CHECK(dmp_endpoint_rotate(&right.endpoint, later_resp, assembly_at) == DMP_OK);
    CHECK(right.endpoint.peers[0].drain_live == 1U);
    rejected_context = right.endpoint.peers[0].drain_context;
    later_drain_at = right.endpoint.peers[0].drain_not_after;

    /* Keep a terminally rejected message on the old association without
     * retaining its assembly. Retirement at the drain boundary must clear its
     * tombstone before the active association admits a fresh assembly. */
    memset(rejected_body, 0x6BU, sizeof rejected_body);
    memset(&reassembly_frame, 0, sizeof reassembly_frame);
    reassembly_frame.fields.type = (uint8_t)DMP_TYPE_REQ;
    reassembly_frame.fields.options =
        (uint8_t)(DMP_OPT_SEQ | DMP_OPT_FRAG | DMP_OPT_SECURITY);
    reassembly_frame.fields.seq = 450U;
    reassembly_frame.fields.fragment.chunk_size = 16U;
    reassembly_frame.fields.fragment.total_size = sizeof rejected_body;
    reassembly_input.frame = &reassembly_frame;
    reassembly_input.context = rejected_context;
    reassembly_input.service_id = 1U;
    reassembly_input.plaintext = span(rejected_body, 16U);
    reassembly_input.immutable_metadata = span(NULL, 0U);
    CHECK(dmp_reassembly_on_fragment(&right.endpoint.reassembly, &reassembly_input,
                                     assembly_at, &rejected_handle) == DMP_INCOMPLETE);
    reassembly_frame.fields.fragment.index = 1U;
    reassembly_input.plaintext = span(rejected_body + 16U, 16U);
    CHECK(dmp_reassembly_on_fragment(&right.endpoint.reassembly, &reassembly_input,
                                     assembly_at + 1U, &rejected_handle) == DMP_OK);
    CHECK(dmp_reassembly_reject(&right.endpoint.reassembly, rejected_handle) == DMP_OK);
    CHECK(right.endpoint.reassembly.storage.tombstones[0].state ==
          DMP_REASSEMBLY_TOMBSTONE_REJECTED);
    status = dmp_endpoint_poll(&right.endpoint, later_drain_at);
    CHECK(status == DMP_OK || status == DMP_DEADLINE_EXPIRED);
    CHECK(right.endpoint.peers[0].drain_live == 0U);
    CHECK(right.endpoint.identity.slots[rejected_context.slot].state == DMP_IDENTITY_SLOT_UNUSED);
    CHECK(right.endpoint.reassembly.storage.tombstones[0].state ==
          DMP_REASSEMBLY_TOMBSTONE_UNUSED);

    reassembly_frame.fields.seq = 451U;
    reassembly_frame.fields.fragment.index = 0U;
    reassembly_input.context = right.endpoint.peers[0].context;
    reassembly_input.plaintext = span(rejected_body, 16U);
    CHECK(dmp_reassembly_on_fragment(&right.endpoint.reassembly, &reassembly_input,
                                     later_drain_at + 1U, &accepted_handle) == DMP_INCOMPLETE);
    reassembly_frame.fields.fragment.index = 1U;
    reassembly_input.plaintext = span(rejected_body + 16U, 16U);
    CHECK(dmp_reassembly_on_fragment(&right.endpoint.reassembly, &reassembly_input,
                                     later_drain_at + 2U, &accepted_handle) == DMP_OK);
    CHECK(dmp_reassembly_release(&right.endpoint.reassembly, accepted_handle) == DMP_OK);
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
    for (i = 0; i < 24 && right.wire.n < 8; i++) {
        CHECK(dmp_endpoint_poll(&right.endpoint, now) == DMP_OK);
    }
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

/* Production poll accepts one TX at a time for cross-peer fairness. The P23
 * process adapter represents one synchronous application action, so keep
 * polling at the same simulated time until that action has no more immediately
 * accepted TX frames to collect. Deferred completions still stop after one
 * poll and follow the explicit completion operation. */
static int p23_poll_sync_tx(uint64_t now) {
  size_t polls;
  for (polls = 0U; polls <= QUEUE; polls++) {
    uint64_t accepted_before = right.endpoint.accepted_tx_generation;
    p23_endpoint_status = dmp_endpoint_poll(&right.endpoint, now);
    if (p23_endpoint_status != DMP_OK) {
      return 0;
    }
    if (!right.endpoint.profile.synchronous_completion ||
        right.endpoint.accepted_tx_generation == accepted_before) {
      return 1;
    }
  }
  return 0;
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
    pending.complete(pending.owner, pending.token, pending.outcome,
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
    pending.complete(pending.owner, pending.token, pending.outcome,
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
      0xa3, 0x88, 0x7c, 0x44, 0xb0, 0x6b, 0x4d, 0x2f, 0x90, 0x5f, 0x89,
      0xfa, 0xe4, 0xb2, 0x8b, 0x99, 0xc0, 0xf0, 0x0d, 0x93, 0xd7, 0x7c,
      0x50, 0xb1, 0xf7, 0x52, 0xce, 0x77, 0xbd, 0xe4, 0x92, 0x2f};
  static const uint8_t radio_retry_all[32] = {
      0xb3, 0x3d, 0x39, 0xbf, 0xfc, 0xb7, 0xc2, 0x75, 0x0f, 0xbf, 0x86,
      0x0e, 0x4e, 0x04, 0x0c, 0xd5, 0xb4, 0xe2, 0x91, 0x01, 0xa6, 0xd6,
      0xc0, 0xca, 0x60, 0x4f, 0xae, 0xf9, 0x71, 0x9c, 0xcf, 0x3f};
  static const uint8_t stream_r[32] = {
      0x8d, 0xe5, 0x61, 0x92, 0xf7, 0x5e, 0x76, 0x77, 0x08, 0x1d, 0x70,
      0x4d, 0x56, 0x8d, 0xdb, 0x64, 0xb1, 0x29, 0x2c, 0x6d, 0xed, 0x72,
      0x44, 0x96, 0x75, 0xeb, 0xce, 0xef, 0xd5, 0x3d, 0x9a, 0x1a};
  static const uint8_t mixed[32] = {
      0x2b, 0xc3, 0xc2, 0xee, 0x1c, 0x9e, 0x8f, 0x3a, 0xa8, 0x7a, 0xf4,
      0xaf, 0xd2, 0xf0, 0xca, 0xb9, 0x96, 0x09, 0x9f, 0xc6, 0x9d, 0xa1,
      0xf0, 0x93, 0x8c, 0x23, 0xe0, 0x50, 0xc8, 0xc6, 0x8f, 0xaf};
  static const uint8_t stream_r_sample20[32] = {
      0xb8, 0x41, 0x32, 0xa0, 0x86, 0x32, 0x3d, 0x43, 0x24, 0x92, 0x96,
      0x77, 0x55, 0x24, 0x4b, 0x59, 0xa9, 0xa5, 0x34, 0x05, 0x88, 0x0d,
      0x85, 0xf3, 0x54, 0xc2, 0x53, 0x53, 0x75, 0x7c, 0x6a, 0xa6};
  static const uint8_t direct_nnpsk0[32] = {
      0x40, 0xab, 0xed, 0xfb, 0xb1, 0x79, 0x9e, 0xa6, 0xcb, 0x71, 0x1f,
      0x73, 0x91, 0x01, 0xd4, 0x0b, 0xae, 0x64, 0x54, 0xea, 0xc7, 0x19,
      0x85, 0x8c, 0x79, 0xb0, 0x66, 0xf2, 0x67, 0x0a, 0xd0, 0xc1};
  static const uint8_t direct_xx[32] = {
      0x28, 0x9e, 0xd4, 0x44, 0xa4, 0x58, 0xbb, 0xa2, 0x80, 0x1f, 0xbc,
      0xeb, 0x68, 0x34, 0x6c, 0xfa, 0xe2, 0x3d, 0xe7, 0x9b, 0xea, 0xab,
      0x2d, 0x34, 0x02, 0xa7, 0x55, 0x39, 0xe1, 0x1b, 0x23, 0xf9};
  static const uint8_t radio_xx[32] = {
      0xb2, 0x7b, 0x06, 0xee, 0x7a, 0xd0, 0xa0, 0xd5, 0x1e, 0x79, 0xcf,
      0x89, 0x4a, 0x37, 0x3b, 0xf2, 0xb7, 0x4d, 0x9f, 0x9b, 0x36, 0x74,
      0xb2, 0x4b, 0x92, 0x56, 0x41, 0x8b, 0x91, 0x41, 0x64, 0x1a};
  static const uint8_t retry_all_xx[32] = {
      0x36, 0x93, 0x14, 0xbd, 0x7d, 0xaf, 0x84, 0x0b, 0x22, 0xd3, 0x4e,
      0x10, 0xc4, 0x32, 0xfe, 0x08, 0x57, 0x5e, 0xcd, 0x9e, 0x1c, 0x56,
      0x2c, 0xfd, 0x73, 0x0a, 0x34, 0x2b, 0xc5, 0xe1, 0x28, 0x6a};
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
  if (p23_uses_packet_endpoint()) {
    const uint8_t sync = 0U;
    return p23_add_frame(batch, &sync, sizeof sync);
  }
  p23_endpoint_status = dmp_endpoint_poll(&right.endpoint, p23_env.now);
  return p23_endpoint_status == DMP_OK && p23_drain_wire(batch);
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
    if (p23_uses_packet_endpoint()) {
      p23_endpoint_status = DMP_OK;
      p23_rx_status = DMP_OK;
      return 1;
    }
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
  p23_rx_status = p23_uses_packet_endpoint()
                      ? dmp_endpoint_rx_packet(&right.endpoint,
                                               span(core, core_size), now)
                      : dmp_endpoint_rx(&right.endpoint,
                                        span(input, input_size), now);
  p23_endpoint_status = p23_rx_status;
  if (p23_rx_status != DMP_OK && p23_rx_status != DMP_INCOMPLETE &&
      p23_rx_status != DMP_DUPLICATE) {
    return 0;
  }
  return p23_poll_sync_tx(now) && p23_drain_wire(batch);
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
  return p23_poll_sync_tx(now);
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
  return p23_poll_sync_tx(now);
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
  return p23_poll_sync_tx(now);
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
  return p23_poll_sync_tx(now);
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
  return p23_poll_sync_tx(now);
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
  return p23_poll_sync_tx(now);
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
  scalar[3] = p23_initialized != 0 && right.endpoint.peers != NULL
                  ? right.endpoint.peers[0].frag_live
                  : 0U;
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

static int profile_hash_nibble(char value, uint8_t *out)
{
  if (value >= '0' && value <= '9') {
    *out = (uint8_t)(value - '0');
    return 1;
  }
  if (value >= 'a' && value <= 'f') {
    *out = (uint8_t)(value - 'a' + 10);
    return 1;
  }
  if (value >= 'A' && value <= 'F') {
    *out = (uint8_t)(value - 'A' + 10);
    return 1;
  }
  return 0;
}

static int profile_hash_decode(const char *encoded, uint8_t out[32])
{
  size_t index;
  if (encoded == NULL || strlen(encoded) != 64U) {
    return 0;
  }
  for (index = 0U; index < 32U; ++index) {
    uint8_t high;
    uint8_t low;
    if (!profile_hash_nibble(encoded[index * 2U], &high) ||
        !profile_hash_nibble(encoded[index * 2U + 1U], &low)) {
      return 0;
    }
    out[index] = (uint8_t)((high << 4U) | low);
  }
  return 1;
}

int main(int argc, char **argv) {
  const char *name = argc > 1 ? argv[1] : "all";
  int failed = 0;
#ifdef DMP_MULTI_PEER_HASH
  static uint8_t multi_peer_hash[32];
  if (!profile_hash_decode(DMP_MULTI_PEER_HASH, multi_peer_hash)) {
    return 2;
  }
#endif
#ifdef DMP_SAMPLE_RETRY_HASH
  static uint8_t retry_hash[32];
  if (!profile_hash_decode(DMP_SAMPLE_RETRY_HASH, retry_hash)) {
    return 2;
  }
  g_profile_hash_override = retry_hash;
#endif
  if (strcmp(name, "p23-driver") == 0) {
    return p23_driver_main();
  }
  if (strcmp(name, "activation") == 0 || strcmp(name, "all") == 0) {
    failed |= test_activation();
  }
  if (strcmp(name, "transport_reject_retry") == 0 || strcmp(name, "all") == 0) {
    failed |= test_transport_reject_retry();
  }
  if (strcmp(name, "alter") == 0 || strcmp(name, "all") == 0) {
    failed |= test_alter();
  }
  if (strcmp(name, "loss") == 0 || strcmp(name, "all") == 0) {
    failed |= test_loss();
  }
  if (strcmp(name, "result_loss") == 0 || strcmp(name, "all") == 0) {
    failed |= test_result_loss();
  }
  if (strcmp(name, "receipt_loss") == 0 || strcmp(name, "all") == 0) {
    failed |= test_receipt_loss();
  }
  if (strcmp(name, "control_reserve") == 0) {
    failed |= test_control_reserve_under_hello_flood();
  }
  if (strcmp(name, "sample_invalid_request") == 0 || strcmp(name, "all") == 0) {
    failed |= test_sample_invalid_request();
  }
  if (strcmp(name, "sample_no_sample") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_sample_no_sample();
  }
  if (strcmp(name, "sample_initialization") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_sample_initialization();
  }
  if (strcmp(name, "service2_immediate") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_service2_immediate();
  }
  if (strcmp(name, "single_peer_bounds") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_single_peer_service_and_bounds();
  }
  if (strcmp(name, "different_sender") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_different_sender_not_dispatched();
  }
  if (strcmp(name, "sample_late_assoc") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_sample_late_assoc();
  }
  if (strcmp(name, "sample_superseded") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_sample_superseded();
  }
  if (strcmp(name, "sample_init_timeout") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_sample_init_timeout();
  }
  if (strcmp(name, "sample_init_retry_two_attempts") == 0) {
    failed |= test_protected_sample_init_retry_two_attempts();
  }
  if (strcmp(name, "sample_invalid_result") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_sample_invalid_result();
  }
  if (strcmp(name, "sample_invalid_status_result") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_sample_invalid_status_result();
  }
  if (strcmp(name, "sample_invalid_telem") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_sample_invalid_telem();
  }
  if (strcmp(name, "sample_fragmented_result") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_sample_fragmented_result();
  }
  if (strcmp(name, "sample_invalid_fragmented_result") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_sample_invalid_fragmented_result();
  }
  if (strcmp(name, "err_status_contract") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_err_status_contract();
  }
  if (strcmp(name, "validator_duplicate_skipped") == 0 || strcmp(name, "all") == 0) {
    failed |= test_validator_duplicate_skipped();
  }
  if (strcmp(name, "retained_rejection_reassembly") == 0 || strcmp(name, "all") == 0) {
    failed |= test_retained_rejection_reassembly();
  }
  if (strcmp(name, "freshness_terminal_rejection") == 0 || strcmp(name, "all") == 0) {
    failed |= test_freshness_terminal_rejection();
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
  if (strcmp(name, "aad_mutations") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_header_mutations();
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
  if (strcmp(name, "multi_peer_routing") == 0 || strcmp(name, "all") == 0) {
#ifdef DMP_MULTI_PEER_HASH
    const uint8_t *previous_profile_hash = g_profile_hash_override;
    g_profile_hash_override = multi_peer_hash;
    failed |= test_protected_multi_peer_routing();
    g_profile_hash_override = previous_profile_hash;
#else
    failed |= test_protected_multi_peer_routing();
#endif
  }
  if (strcmp(name, "sample1_epoch_endpoint") == 0 || strcmp(name, "all") == 0) {
    failed |= test_protected_sample1_epoch_endpoint();
  }
  if (strcmp(name, "activation") != 0 && strcmp(name, "transport_reject_retry") != 0 &&
      strcmp(name, "alter") != 0 &&
      strcmp(name, "loss") != 0 && strcmp(name, "isolate") != 0 &&
      strcmp(name, "result_loss") != 0 && strcmp(name, "receipt_loss") != 0 &&
      strcmp(name, "control_reserve") != 0 &&
      strcmp(name, "sample_invalid_request") != 0 &&
      strcmp(name, "sample_no_sample") != 0 &&
      strcmp(name, "sample_initialization") != 0 &&
      strcmp(name, "service2_immediate") != 0 &&
      strcmp(name, "single_peer_bounds") != 0 &&
      strcmp(name, "different_sender") != 0 &&
      strcmp(name, "sample_late_assoc") != 0 &&
      strcmp(name, "sample_superseded") != 0 &&
      strcmp(name, "sample_init_timeout") != 0 &&
      strcmp(name, "sample_init_retry_two_attempts") != 0 &&
      strcmp(name, "sample_invalid_result") != 0 &&
      strcmp(name, "sample_invalid_status_result") != 0 &&
      strcmp(name, "sample_invalid_telem") != 0 &&
      strcmp(name, "sample_fragmented_result") != 0 &&
      strcmp(name, "sample_invalid_fragmented_result") != 0 &&
      strcmp(name, "err_status_contract") != 0 &&
      strcmp(name, "validator_duplicate_skipped") != 0 &&
      strcmp(name, "retained_rejection_reassembly") != 0 &&
      strcmp(name, "freshness_terminal_rejection") != 0 &&
      strcmp(name, "reassembly") != 0 && strcmp(name, "ttl") != 0 &&
      strcmp(name, "aad_mutations") != 0 &&
      strcmp(name, "acl") != 0 && strcmp(name, "rotation") != 0 &&
      strcmp(name, "result") != 0 && strcmp(name, "fragdeny") != 0 &&
      strcmp(name, "drain") != 0 && strcmp(name, "context") != 0 &&
      strcmp(name, "repair") != 0 &&
      strcmp(name, "multi_peer_routing") != 0 &&
      strcmp(name, "sample1_epoch_endpoint") != 0 && strcmp(name, "all") != 0) {
    (void)fprintf(stderr, "unknown test %s\n", name);
    return 2;
  }
  return failed == 0 ? 0 : 1;
}
