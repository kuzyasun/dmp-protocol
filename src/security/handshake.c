#include "handshake.h"
#include "replay_window.h"

#include "dmp/core.h"

#include <noise/protocol.h>

#include <string.h>

#define DMP_HS_MAGIC 0xD3131301u
#define DMP_HS_PROLOGUE_LEN 85u
#define DMP_HS_PREFIX_LEN 72u
#define DMP_HS_CONT_LEN 18u
#define DMP_HS_PROTECTED_MAX 96u
#define DMP_HS_AAD_MAX (14u + 32u + DMP_MAX_HEADER_BYTES)
#define DMP_HS_PN_LIMIT (UINT64_C(1) << 24)
#define DMP_HS_PLAIN_LIMIT (UINT64_C(1) << 30)
#define DMP_HS_LIFETIME_DEFAULT_MS UINT64_C(86400000)
#define DMP_HS_AEAD_CEILING 65536u

struct hs_attempt {
    int used;
    int terminal;
    int awaiting;
    int initiator;
    int handshake_open;
    int send_open;
    int recv_open;
    int scratch_held;
    int candidate;
    int enrolled;
    int remote_public_valid;
    int hash_valid;
    uint64_t generation;
    uint64_t deadline_ms;
    uint64_t boot_epoch;
    uint64_t epoch_i;
    uint64_t epoch_r;
    uint32_t initiator_id;
    uint32_t responder_id;
    uint32_t namespace_id;
    uint32_t key_hint;
    uint32_t local_rx_cid;
    uint32_t remote_rx_cid;
    uint32_t noise_writes;
    uint32_t noise_reads;
    uint32_t retransmits;
    uint8_t mode;
    uint8_t cipher;
    uint8_t expect_flight;
    uint8_t read_flight;
    dmp_hs_view view;
    uint8_t attempt_id[16];
    uint8_t profile_hash[32];
    uint8_t prologue[DMP_HS_PROLOGUE_LEN];
    uint8_t prefix[DMP_HS_PREFIX_LEN];
    uint8_t ephemeral[32];
    uint8_t psk[32];
    uint8_t remote_public[32];
    uint8_t handshake_hash[32];
    uint8_t seen[3][DMP_HS_PAYLOAD_MAX];
    uint16_t seen_len[3];
    uint8_t seen_ok[3];
    uint8_t pending[DMP_HS_PAYLOAD_MAX];
    uint16_t pending_len;
    uint8_t cached[DMP_HS_PAYLOAD_MAX];
    uint16_t cached_len;
    uint8_t cached_flight;
    int active;
    int waiting_ready;
    int ready_sent;
    uint64_t split_ms;
    uint64_t confirm_deadline;
    uint64_t next_pn;
    uint64_t send_plain;
    uint64_t recv_plain;
    uint32_t next_seq;
    uint32_t confirm_sends;
    uint32_t failed_aead;
    uint32_t send_frames;
    dmp_replay_window replay;
    uint8_t protected_frame[DMP_HS_PROTECTED_MAX];
    uint16_t protected_len;
    uint8_t accepted[DMP_HS_APP_PLAIN_MAX];
    uint16_t accepted_len;
    dmp_provider_handshake handshake;
    dmp_provider_cipher send_cipher;
    dmp_provider_cipher recv_cipher;
};

struct dmp_hs {
    uint32_t magic;
    dmp_provider *provider;
    NoiseHashState *epoch_hash;
    dmp_hs_config config;
    dmp_hs_ports ports;
    uint64_t generation_clock;
    uint64_t episode_start_ms;
    uint64_t next_attempt_ms;
    uint64_t admit_window_start;
    uint32_t episode_attempts_used;
    uint32_t episode_work;
    uint32_t episode_traffic;
    uint32_t global_work;
    uint32_t ingress_work;
    uint32_t later_remaining;
    uint32_t episodes_started;
    uint32_t admits_in_window;
    uint32_t scratch_held;
    uint32_t total_reads;
    uint32_t next_cid;
    uint32_t replay_width;
    uint32_t failed_limit;
    uint64_t lifetime_ms;
    int episode_open;
    struct hs_attempt attempts[DMP_HS_ATTEMPT_MAX];
    dmp_hs_retained retained[DMP_HS_ASSOCIATION_MAX];
    int retained_used[DMP_HS_ASSOCIATION_MAX];
    uint8_t partial[DMP_HS_PAYLOAD_MAX];
    uint16_t partial_len;
    int partial_used;
};

static void wipe(void *data, size_t size)
{
    volatile uint8_t *bytes = (volatile uint8_t *)data;
    size_t index;

    if (data == NULL || size == 0U) {
        return;
    }
    for (index = 0U; index < size; ++index) {
        bytes[index] = 0U;
    }
}

static int live(const dmp_hs *hs)
{
    return hs != NULL && hs->magic == DMP_HS_MAGIC && hs->provider != NULL;
}

static uint32_t load_le32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void store_le32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static uint64_t load_le64(const uint8_t *bytes)
{
    uint64_t value = 0U;
    size_t index;

    for (index = 0U; index < 8U; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8U);
    }
    return value;
}

static uint64_t now_ms(const dmp_hs *hs)
{
    return hs->ports.now_ms(hs->ports.ctx);
}

/* Noise's public SHA-256 API allocates inside noise_hashstate_new_by_id.
 * One HashState is created in dmp_hs_init and reused here, so offer and
 * accept do not allocate for the epoch label. */
static int sha256(NoiseHashState *state, const uint8_t *data, size_t length, uint8_t out[32])
{
    int error;

    if (state == NULL || data == NULL) {
        return 0;
    }
    error = noise_hashstate_hash_one(state, data, length, out, 32U);
    (void)noise_hashstate_reset(state);
    return error == NOISE_ERROR_NONE;
}

static int boot_epoch_of(NoiseHashState *state, const uint8_t attempt_id[16], uint64_t *epoch)
{
    uint8_t input[36];
    uint8_t hash[32];
    int ok;

    memcpy(input, "DMP2-SEC1-BOOT-EPOCH", 20U);
    memcpy(input + 20U, attempt_id, 16U);
    ok = sha256(state, input, sizeof(input), hash);
    if (ok) {
        *epoch = load_le64(hash);
    }
    wipe(input, sizeof(input));
    wipe(hash, sizeof(hash));
    return ok;
}

static int traffic_epoch_of(NoiseHashState *state, const uint8_t handshake_hash[32],
                            uint8_t direction, uint64_t *epoch)
{
    uint8_t input[48];
    uint8_t hash[32];
    int ok;

    memcpy(input, "DMP2-SEC1-EPOCH", 15U);
    memcpy(input + 15U, handshake_hash, 32U);
    input[47] = direction;
    ok = sha256(state, input, sizeof(input), hash);
    if (ok) {
        *epoch = load_le64(hash);
    }
    wipe(input, sizeof(input));
    wipe(hash, sizeof(hash));
    return ok;
}

static size_t noise_length(uint8_t mode, uint8_t flight)
{
    if (mode == 1U && flight == 1U) {
        return 48U;
    }
    if (mode == 1U && flight == 2U) {
        return 52U;
    }
    if (mode == 2U && flight == 1U) {
        return 32U;
    }
    if (mode == 2U && flight == 2U) {
        return 100U;
    }
    if (mode == 2U && flight == 3U) {
        return 64U;
    }
    return 0U;
}

static size_t payload_length(uint8_t mode, uint8_t flight)
{
    size_t noise = noise_length(mode, flight);

    if (noise == 0U) {
        return 0U;
    }
    return flight == 1U ? DMP_HS_PREFIX_LEN + noise : DMP_HS_CONT_LEN + noise;
}

static const char *suite_name(uint8_t mode)
{
    if (mode == 1U) {
        return "Noise_NNpsk0_25519_ChaChaPoly_SHA256";
    }
    if (mode == 2U) {
        return "Noise_XX_25519_ChaChaPoly_SHA256";
    }
    return NULL;
}

static uint32_t pending_count(const dmp_hs *hs)
{
    uint32_t count = 0U;
    uint32_t index;

    for (index = 0U; index < DMP_HS_ATTEMPT_MAX; ++index) {
        if (hs->attempts[index].used && !hs->attempts[index].terminal) {
            count++;
        }
    }
    return count;
}

static int cid_in_use(const dmp_hs *hs, uint32_t cid)
{
    uint32_t index;

    if (cid == 0U) {
        return 1;
    }
    for (index = 0U; index < DMP_HS_ATTEMPT_MAX; ++index) {
        const struct hs_attempt *attempt = &hs->attempts[index];

        if (attempt->used && !attempt->terminal && attempt->local_rx_cid == cid) {
            return 1;
        }
    }
    for (index = 0U; index < DMP_HS_ASSOCIATION_MAX; ++index) {
        if (hs->retained_used[index] && hs->retained[index].rx_cid == cid) {
            return 1;
        }
    }
    return 0;
}

static int take_cid(dmp_hs *hs, uint32_t *cid)
{
    uint32_t candidate = hs->next_cid == 0U ? 1U : hs->next_cid;
    uint32_t guard;

    for (guard = 0U; guard < 64U; ++guard) {
        if (!cid_in_use(hs, candidate)) {
            *cid = candidate;
            hs->next_cid = candidate + 1U;
            if (hs->next_cid == 0U) {
                hs->next_cid = 1U;
            }
            return 1;
        }
        candidate++;
        if (candidate == 0U) {
            candidate = 1U;
        }
    }
    return 0;
}

static int work_room(const dmp_hs *hs)
{
    const dmp_hs_budget *budget = &hs->config.budget;

    if (hs->global_work >= budget->global_work || hs->ingress_work >= budget->ingress_work) {
        return 0;
    }
    if (hs->episode_open && hs->episode_work >= budget->episode_work) {
        return 0;
    }
    return 1;
}

static int charge(dmp_hs *hs)
{
    if (!work_room(hs)) {
        return 0;
    }
    hs->global_work++;
    hs->ingress_work++;
    if (hs->episode_open) {
        hs->episode_work++;
    }
    return 1;
}

static int traffic_room(const dmp_hs *hs, size_t bytes)
{
    const dmp_hs_budget *budget = &hs->config.budget;

    if (!hs->episode_open) {
        return 1;
    }
    if (hs->episode_traffic >= budget->episode_traffic) {
        return 0;
    }
    return bytes <= (size_t)(budget->episode_traffic - hs->episode_traffic);
}

static void add_traffic(dmp_hs *hs, size_t bytes)
{
    if (!hs->episode_open || bytes > UINT32_MAX) {
        return;
    }
    if (hs->episode_traffic > UINT32_MAX - (uint32_t)bytes) {
        hs->episode_traffic = UINT32_MAX;
        return;
    }
    hs->episode_traffic += (uint32_t)bytes;
}

static void release_scratch(dmp_hs *hs, struct hs_attempt *attempt)
{
    if (attempt->scratch_held) {
        if (hs->scratch_held > 0U) {
            hs->scratch_held--;
        }
        attempt->scratch_held = 0;
    }
}

static int reserve_scratch(dmp_hs *hs, struct hs_attempt *attempt)
{
    if (attempt->scratch_held) {
        return 1;
    }
    if (hs->scratch_held >= hs->config.budget.max_scratch) {
        return 0;
    }
    hs->scratch_held++;
    attempt->scratch_held = 1;
    return 1;
}

static void close_crypto(dmp_hs *hs, struct hs_attempt *attempt)
{
    if (attempt->handshake_open) {
        (void)dmp_provider_handshake_close(hs->provider, &attempt->handshake);
        attempt->handshake_open = 0;
    }
    if (attempt->send_open) {
        (void)dmp_provider_cipher_close(hs->provider, &attempt->send_cipher);
        attempt->send_open = 0;
    }
    if (attempt->recv_open) {
        (void)dmp_provider_cipher_close(hs->provider, &attempt->recv_cipher);
        attempt->recv_open = 0;
    }
    wipe(attempt->ephemeral, sizeof(attempt->ephemeral));
    wipe(attempt->psk, sizeof(attempt->psk));
    wipe(attempt->prologue, sizeof(attempt->prologue));
    wipe(attempt->pending, sizeof(attempt->pending));
    attempt->pending_len = 0U;
}

/* S3.1 allows any jitter. This build uses zero until a deployment defines a distribution. */
static void schedule_restart(dmp_hs *hs)
{
    uint64_t now = now_ms(hs);
    const uint32_t jitter_ms = 0U;
    uint32_t backoff = hs->config.budget.restart_backoff_ms;
    uint64_t delay = (uint64_t)backoff + (uint64_t)jitter_ms;

    hs->next_attempt_ms = delay > UINT64_MAX - now ? UINT64_MAX : now + delay;
}

static void abort_attempt(dmp_hs *hs, struct hs_attempt *attempt, dmp_hs_view view)
{
    if (!attempt->used || attempt->terminal) {
        return;
    }
    attempt->terminal = 1;
    attempt->awaiting = 0;
    attempt->candidate = 0;
    attempt->enrolled = 0;
    attempt->active = 0;
    attempt->waiting_ready = 0;
    attempt->ready_sent = 0;
    attempt->protected_len = 0U;
    attempt->accepted_len = 0U;
    wipe(attempt->protected_frame, sizeof(attempt->protected_frame));
    wipe(attempt->accepted, sizeof(attempt->accepted));
    dmp_replay_window_clear(&attempt->replay);
    attempt->view = view;
    attempt->generation = ++hs->generation_clock;
    attempt->expect_flight = 0U;
    attempt->cached_len = 0U;
    attempt->cached_flight = 0U;
    release_scratch(hs, attempt);
    close_crypto(hs, attempt);
    wipe(attempt->remote_public, sizeof(attempt->remote_public));
    wipe(attempt->handshake_hash, sizeof(attempt->handshake_hash));
    attempt->remote_public_valid = 0;
    attempt->hash_valid = 0;
    if (attempt->initiator) {
        schedule_restart(hs);
    }
}

static int episode_finished(const dmp_hs *hs, uint64_t now)
{
    uint64_t end;

    if (!hs->episode_open) {
        return 1;
    }
    if (hs->config.budget.episode_deadline_ms > UINT64_MAX - hs->episode_start_ms) {
        end = UINT64_MAX;
    } else {
        end = hs->episode_start_ms + hs->config.budget.episode_deadline_ms;
    }
    if (now >= end) {
        return 1;
    }
    return hs->episode_attempts_used >= hs->config.budget.episode_attempts;
}

static struct hs_attempt *alloc_attempt(dmp_hs *hs)
{
    uint32_t index;

    if (pending_count(hs) >= hs->config.budget.max_pending) {
        return NULL;
    }
    for (index = 0U; index < DMP_HS_ATTEMPT_MAX; ++index) {
        struct hs_attempt *attempt = &hs->attempts[index];

        if (!attempt->used || attempt->terminal) {
            close_crypto(hs, attempt);
            memset(attempt, 0, sizeof(*attempt));
            attempt->used = 1;
            attempt->generation = ++hs->generation_clock;
            return attempt;
        }
    }
    return NULL;
}

static uint32_t attempt_index(const dmp_hs *hs, const struct hs_attempt *attempt)
{
    return (uint32_t)(attempt - hs->attempts);
}

static struct hs_attempt *find_attempt(dmp_hs *hs, const uint8_t attempt_id[16])
{
    uint32_t index;

    for (index = 0U; index < DMP_HS_ATTEMPT_MAX; ++index) {
        struct hs_attempt *attempt = &hs->attempts[index];

        if (attempt->used && !attempt->terminal &&
            memcmp(attempt->attempt_id, attempt_id, 16U) == 0) {
            return attempt;
        }
    }
    return NULL;
}

static void build_prologue(uint8_t prologue[DMP_HS_PROLOGUE_LEN], const uint8_t prefix[DMP_HS_PREFIX_LEN])
{
    memcpy(prologue, "DMP2-SEC1-BOOT", 14U);
    memcpy(prologue + 14U, prefix, 3U);
    memcpy(prologue + 17U, prefix + 4U, 68U);
}

static void build_prefix(struct hs_attempt *attempt)
{
    memset(attempt->prefix, 0, sizeof(attempt->prefix));
    attempt->prefix[0] = 2U;
    attempt->prefix[1] = attempt->mode;
    attempt->prefix[2] = attempt->cipher;
    attempt->prefix[3] = 1U;
    memcpy(attempt->prefix + 4U, attempt->attempt_id, 16U);
    store_le32(attempt->prefix + 20U, attempt->namespace_id);
    store_le32(attempt->prefix + 24U, attempt->initiator_id);
    store_le32(attempt->prefix + 28U, attempt->responder_id);
    memcpy(attempt->prefix + 32U, attempt->profile_hash, 32U);
    store_le32(attempt->prefix + 64U, attempt->key_hint);
    store_le32(attempt->prefix + 68U, attempt->local_rx_cid);
    build_prologue(attempt->prologue, attempt->prefix);
}

static int open_handshake(dmp_hs *hs, struct hs_attempt *attempt)
{
    dmp_provider_handshake_keys keys;
    const char *name = suite_name(attempt->mode);
    int role = attempt->initiator ? DMP_PROVIDER_ROLE_INITIATOR : DMP_PROVIDER_ROLE_RESPONDER;
    dmp_provider_status status;

    if (name == NULL) {
        return 0;
    }
    memset(&keys, 0, sizeof(keys));
    keys.local_ephemeral = attempt->ephemeral;
    keys.local_ephemeral_len = 32U;
    keys.prologue = attempt->prologue;
    keys.prologue_len = DMP_HS_PROLOGUE_LEN;
    if (attempt->mode == 1U) {
        keys.psk = attempt->psk;
        keys.psk_len = 32U;
    } else {
        keys.local_static = hs->config.local_static;
        keys.local_static_len = 32U;
    }
    status = dmp_provider_handshake_open(hs->provider, &attempt->handshake, name, role, &keys);
    if (status != DMP_PROVIDER_OK) {
        return 0;
    }
    attempt->handshake_open = 1;
    return 1;
}

static int remember_seen(struct hs_attempt *attempt, uint8_t flight, const uint8_t *bytes,
                         size_t length)
{
    if (flight < 1U || flight > 3U || length > DMP_HS_PAYLOAD_MAX) {
        return 0;
    }
    memcpy(attempt->seen[flight - 1U], bytes, length);
    if (length < DMP_HS_PAYLOAD_MAX) {
        memset(attempt->seen[flight - 1U] + length, 0, DMP_HS_PAYLOAD_MAX - length);
    }
    attempt->seen_len[flight - 1U] = (uint16_t)length;
    attempt->seen_ok[flight - 1U] = 1U;
    return 1;
}

static int write_flight(dmp_hs *hs, struct hs_attempt *attempt, uint8_t flight)
{
    uint8_t noise[100];
    uint8_t body[4];
    size_t noise_len = 0U;
    size_t prefix_len = flight == 1U ? DMP_HS_PREFIX_LEN : DMP_HS_CONT_LEN;
    size_t total;
    size_t expect = noise_length(attempt->mode, flight);
    const uint8_t *plain = NULL;
    size_t plain_len = 0U;
    dmp_provider_status status;

    if (expect == 0U || !charge(hs) || !traffic_room(hs, prefix_len + expect)) {
        return 0;
    }
    if (flight == 2U) {
        store_le32(body, attempt->local_rx_cid);
        plain = body;
        plain_len = 4U;
    }
    status = dmp_provider_handshake_write(hs->provider, &attempt->handshake, plain, plain_len,
                                          noise, sizeof(noise), &noise_len);
    wipe(body, sizeof(body));
    if (status != DMP_PROVIDER_OK || noise_len != expect || prefix_len + noise_len > DMP_HS_PAYLOAD_MAX) {
        wipe(noise, sizeof(noise));
        return 0;
    }
    total = prefix_len + noise_len;
    if (flight == 1U) {
        memcpy(attempt->cached, attempt->prefix, DMP_HS_PREFIX_LEN);
    } else {
        attempt->cached[0] = 2U;
        attempt->cached[1] = flight;
        memcpy(attempt->cached + 2U, attempt->attempt_id, 16U);
    }
    memcpy(attempt->cached + prefix_len, noise, noise_len);
    wipe(noise, sizeof(noise));
    attempt->cached_len = (uint16_t)total;
    attempt->cached_flight = flight;
    attempt->noise_writes++;
    add_traffic(hs, total);
    if (flight == 1U) {
        (void)remember_seen(attempt, 1U, attempt->cached, total);
    }
    return 1;
}

static int epoch_collision(const dmp_hs *hs, uint32_t origin, uint64_t epoch)
{
    uint32_t index;

    for (index = 0U; index < DMP_HS_ASSOCIATION_MAX; ++index) {
        if (hs->retained_used[index] && hs->retained[index].namespace_id == hs->config.namespace_id &&
            hs->retained[index].origin_id == origin && hs->retained[index].epoch == epoch) {
            return 1;
        }
    }
    return 0;
}

static dmp_hs_status finish_candidate(dmp_hs *hs, struct hs_attempt *attempt)
{
    uint8_t hash[32];
    dmp_provider_status status;

    memset(hash, 0, sizeof(hash));
    status = dmp_provider_handshake_hash(hs->provider, &attempt->handshake, hash);
    if (status != DMP_PROVIDER_OK ||
        !traffic_epoch_of(hs->epoch_hash, hash, 0U, &attempt->epoch_i) ||
        !traffic_epoch_of(hs->epoch_hash, hash, 1U, &attempt->epoch_r)) {
        wipe(hash, sizeof(hash));
        abort_attempt(hs, attempt, DMP_HS_VIEW_REJECTED);
        return DMP_HS_ABORTED;
    }
    memcpy(attempt->handshake_hash, hash, 32U);
    attempt->hash_valid = 1;
    wipe(hash, sizeof(hash));
    if (epoch_collision(hs, attempt->initiator_id, attempt->epoch_i) ||
        epoch_collision(hs, attempt->responder_id, attempt->epoch_r)) {
        abort_attempt(hs, attempt, DMP_HS_VIEW_REJECTED);
        return DMP_HS_ABORTED;
    }
    status = dmp_provider_handshake_split(hs->provider, &attempt->handshake, &attempt->send_cipher,
                                          &attempt->recv_cipher);
    if (status != DMP_PROVIDER_OK) {
        abort_attempt(hs, attempt, DMP_HS_VIEW_REJECTED);
        return DMP_HS_ABORTED;
    }
    attempt->send_open = 1;
    attempt->recv_open = 1;
    attempt->split_ms = now_ms(hs);
    attempt->next_pn = 0U;
    attempt->next_seq = 0U;
    dmp_replay_window_init(&attempt->replay, hs->replay_width);
    (void)dmp_provider_handshake_close(hs->provider, &attempt->handshake);
    attempt->handshake_open = 0;
    wipe(attempt->ephemeral, sizeof(attempt->ephemeral));
    wipe(attempt->psk, sizeof(attempt->psk));
    wipe(attempt->prologue, sizeof(attempt->prologue));
    attempt->expect_flight = 0U;
    attempt->candidate = 1;
    if (attempt->mode == 2U && !hs->config.has_pin && hs->config.pairing_allowed) {
        attempt->view = DMP_HS_VIEW_AWAITING_VERIFICATION;
    } else {
        attempt->view = DMP_HS_VIEW_CANDIDATE;
    }
    return DMP_HS_CANDIDATE;
}

static int decrypted_payload_ok(struct hs_attempt *attempt, uint8_t flight, const uint8_t *payload,
                                size_t payload_len)
{
    uint32_t cid;

    if (flight == 2U) {
        if (payload_len != 4U) {
            return 0;
        }
        cid = load_le32(payload);
        if (cid == 0U) {
            return 0;
        }
        attempt->remote_rx_cid = cid;
        return 1;
    }
    return payload_len == 0U;
}

static int peer_key_ok(dmp_hs *hs, struct hs_attempt *attempt)
{
    uint8_t remote[32];
    dmp_provider_status status;

    if (attempt->mode != 2U) {
        return 1;
    }
    memset(remote, 0, sizeof(remote));
    status = dmp_provider_handshake_remote_public(hs->provider, &attempt->handshake, remote);
    if (status == DMP_PROVIDER_REJECTED) {
        wipe(remote, sizeof(remote));
        return 1;
    }
    if (status != DMP_PROVIDER_OK) {
        wipe(remote, sizeof(remote));
        return 0;
    }
    memcpy(attempt->remote_public, remote, 32U);
    attempt->remote_public_valid = 1;
    wipe(remote, sizeof(remote));
    if (hs->config.has_pin) {
        return memcmp(attempt->remote_public, hs->config.pinned_remote, 32U) == 0;
    }
    return hs->config.pairing_allowed != 0;
}

static uint32_t flight_sender(const struct hs_attempt *attempt, uint8_t flight)
{
    return flight == 2U ? attempt->responder_id : attempt->initiator_id;
}

static int outer_matches(const dmp_hs *hs, const struct hs_attempt *attempt, uint8_t flight,
                         const dmp_hs_ingress *ingress)
{
    return ingress->origin_id == flight_sender(attempt, flight) &&
           ingress->destination_id == hs->config.local_id &&
           ingress->namespace_id == attempt->namespace_id &&
           ingress->context_epoch == attempt->boot_epoch && ingress->seq == flight &&
           !ingress->route_to_root && !ingress->route_broadcast;
}

static int retransmit_cached(dmp_hs *hs, struct hs_attempt *attempt)
{
    if (attempt->cached_len == 0U || now_ms(hs) >= attempt->deadline_ms) {
        return 0;
    }
    if (attempt->retransmits >= hs->config.budget.cached_responses) {
        return 0;
    }
    attempt->retransmits++;
    return 1;
}

static int fill_entropy(dmp_hs *hs, uint8_t *bytes, size_t size)
{
    if (hs->ports.entropy == NULL || hs->ports.entropy(hs->ports.ctx, bytes, size) != 0) {
        wipe(bytes, size);
        return 0;
    }
    return 1;
}

static void copy_identity(dmp_hs *hs, struct hs_attempt *attempt, int initiator)
{
    attempt->initiator = initiator;
    attempt->mode = hs->config.mode;
    attempt->cipher = hs->config.cipher;
    attempt->namespace_id = hs->config.namespace_id;
    attempt->initiator_id = initiator ? hs->config.local_id : hs->config.peer_id;
    attempt->responder_id = initiator ? hs->config.peer_id : hs->config.local_id;
    attempt->key_hint = hs->config.mode == 2U ? 0U : hs->config.key_hint;
    memcpy(attempt->profile_hash, hs->config.profile_hash, 32U);
    if (hs->config.mode == 1U && hs->config.has_psk) {
        memcpy(attempt->psk, hs->config.psk, 32U);
    }
    {
        uint64_t now = now_ms(hs);
        uint32_t life = hs->config.budget.attempt_deadline_ms;

        attempt->deadline_ms = life > UINT64_MAX - now ? UINT64_MAX : now + life;
    }
    if (hs->config.pairing_allowed) {
        attempt->view = DMP_HS_VIEW_PAIRING_ALLOWED;
    }
}

static int read_noise(dmp_hs *hs, struct hs_attempt *attempt, const uint8_t *message, size_t message_len,
                      uint8_t *payload, size_t payload_cap, size_t *payload_len)
{
    dmp_provider_status status;

    attempt->noise_reads++;
    hs->total_reads++;
    status = dmp_provider_handshake_read(hs->provider, &attempt->handshake, message, message_len, payload,
                                        payload_cap, payload_len);
    return status == DMP_PROVIDER_OK;
}

static dmp_hs_status fail_read(dmp_hs *hs, struct hs_attempt *attempt)
{
    abort_attempt(hs, attempt, DMP_HS_VIEW_REJECTED);
    return DMP_HS_ABORTED;
}

static dmp_hs_status hold_for_accept(struct hs_attempt *attempt, const dmp_hs_ingress *ingress,
                                     uint8_t flight, dmp_hs_completion *completion, dmp_hs *hs)
{
    if (completion == NULL || ingress->payload_len > DMP_HS_PAYLOAD_MAX) {
        return fail_read(hs, attempt);
    }
    memcpy(attempt->pending, ingress->payload, ingress->payload_len);
    attempt->pending_len = (uint16_t)ingress->payload_len;
    attempt->read_flight = flight;
    attempt->awaiting = 1;
    completion->attempt_index = attempt_index(hs, attempt);
    completion->generation = attempt->generation;
    return DMP_HS_AWAITING;
}

static dmp_hs_status read_expected(dmp_hs *hs, struct hs_attempt *attempt, uint8_t flight,
                                   const dmp_hs_ingress *ingress, dmp_hs_completion *completion)
{
    uint8_t payload[16];
    size_t payload_len = 0U;
    size_t prefix_len = flight == 1U ? DMP_HS_PREFIX_LEN : DMP_HS_CONT_LEN;
    size_t expect = payload_length(attempt->mode, flight);

    memset(payload, 0, sizeof(payload));
    if (!outer_matches(hs, attempt, flight, ingress) || ingress->payload_len != expect) {
        if (!charge(hs)) {
            return DMP_HS_REFUSED;
        }
        return DMP_HS_DROPPED;
    }
    if (!traffic_room(hs, ingress->payload_len) || !charge(hs) || !reserve_scratch(hs, attempt)) {
        return DMP_HS_REFUSED;
    }
    if (ingress->payload_len < prefix_len ||
        !read_noise(hs, attempt, ingress->payload + prefix_len, ingress->payload_len - prefix_len, payload,
                    sizeof(payload), &payload_len) ||
        !decrypted_payload_ok(attempt, flight, payload, payload_len) || !peer_key_ok(hs, attempt)) {
        wipe(payload, sizeof(payload));
        return fail_read(hs, attempt);
    }
    wipe(payload, sizeof(payload));
    add_traffic(hs, ingress->payload_len);
    return hold_for_accept(attempt, ingress, flight, completion, hs);
}

static int admit_burst(dmp_hs *hs)
{
    uint64_t now = now_ms(hs);
    uint32_t window = hs->config.budget.admit_window_ms;
    uint32_t burst = hs->config.budget.admit_burst;

    if (burst == 0U) {
        return 0;
    }
    if (window == 0U) {
        if (hs->admits_in_window >= burst) {
            return 0;
        }
        hs->admits_in_window++;
        return 1;
    }
    if (hs->admit_window_start == 0U || now - hs->admit_window_start >= window) {
        hs->admit_window_start = now;
        hs->admits_in_window = 0U;
    }
    if (hs->admits_in_window >= burst) {
        return 0;
    }
    hs->admits_in_window++;
    return 1;
}

static dmp_hs_status admit_flight1(dmp_hs *hs, const dmp_hs_ingress *ingress, dmp_hs_completion *completion)
{
    struct hs_attempt *attempt;
    uint8_t mode;
    uint8_t cipher;
    uint32_t initiator_id;
    uint32_t responder_id;
    uint32_t namespace_id;
    uint32_t key_hint;
    uint32_t remote_cid;
    uint64_t epoch = 0U;
    size_t expect;

    if (ingress->payload_len < DMP_HS_PREFIX_LEN) {
        (void)charge(hs);
        return DMP_HS_DROPPED;
    }
    mode = ingress->payload[1];
    cipher = ingress->payload[2];
    initiator_id = load_le32(ingress->payload + 24U);
    responder_id = load_le32(ingress->payload + 28U);
    namespace_id = load_le32(ingress->payload + 20U);
    key_hint = load_le32(ingress->payload + 64U);
    remote_cid = load_le32(ingress->payload + 68U);
    if (mode != hs->config.mode || cipher != 1U || cipher != hs->config.cipher ||
        initiator_id == responder_id || responder_id != hs->config.local_id ||
        initiator_id != hs->config.peer_id || namespace_id != hs->config.namespace_id ||
        memcmp(ingress->payload + 32U, hs->config.profile_hash, 32U) != 0) {
        (void)charge(hs);
        return mode != hs->config.mode || cipher != 1U ? DMP_HS_UNSUPPORTED : DMP_HS_DROPPED;
    }
    if ((mode == 2U && key_hint != 0U) || (mode == 1U && key_hint != hs->config.key_hint) || remote_cid == 0U) {
        (void)charge(hs);
        return DMP_HS_DROPPED;
    }
    if (mode == 2U && !hs->config.has_pin && !hs->config.pairing_allowed) {
        (void)charge(hs);
        return DMP_HS_DROPPED;
    }
    expect = payload_length(mode, 1U);
    if (ingress->payload_len != expect) {
        (void)charge(hs);
        return DMP_HS_DROPPED;
    }
    if (!boot_epoch_of(hs->epoch_hash, ingress->payload + 4U, &epoch) ||
        ingress->context_epoch != epoch ||
        ingress->origin_id != initiator_id || ingress->destination_id != hs->config.local_id ||
        ingress->seq != 1U) {
        (void)charge(hs);
        return DMP_HS_DROPPED;
    }
    if (pending_count(hs) >= hs->config.budget.max_pending ||
        hs->scratch_held >= hs->config.budget.max_scratch || !traffic_room(hs, expect) ||
        !work_room(hs)) {
        return DMP_HS_REFUSED;
    }
    if (!admit_burst(hs)) {
        return DMP_HS_REFUSED;
    }
    attempt = alloc_attempt(hs);
    if (attempt == NULL) {
        return DMP_HS_REFUSED;
    }
    copy_identity(hs, attempt, 0);
    memcpy(attempt->attempt_id, ingress->payload + 4U, 16U);
    memcpy(attempt->prefix, ingress->payload, DMP_HS_PREFIX_LEN);
    attempt->boot_epoch = epoch;
    attempt->remote_rx_cid = remote_cid;
    build_prologue(attempt->prologue, attempt->prefix);
    if (!fill_entropy(hs, attempt->ephemeral, 32U) || !open_handshake(hs, attempt)) {
        return fail_read(hs, attempt);
    }
    {
        dmp_hs_status status = read_expected(hs, attempt, 1U, ingress, completion);

        if (status != DMP_HS_AWAITING && attempt->used && !attempt->terminal) {
            release_scratch(hs, attempt);
            close_crypto(hs, attempt);
            memset(attempt, 0, sizeof(*attempt));
        }
        return status;
    }
}

static int extract_flight(const dmp_hs_ingress *ingress, uint8_t *flight, uint8_t attempt_id[16])
{
    if (ingress->payload == NULL) {
        return 0;
    }
    if (ingress->seq == 1U) {
        if (ingress->payload_len < 20U || ingress->payload[0] != 2U || ingress->payload[3] != 1U) {
            return 0;
        }
        *flight = 1U;
        memcpy(attempt_id, ingress->payload + 4U, 16U);
        return 1;
    }
    if (ingress->seq == 2U || ingress->seq == 3U) {
        if (ingress->payload_len < DMP_HS_CONT_LEN || ingress->payload[0] != 2U ||
            ingress->payload[1] != ingress->seq) {
            return 0;
        }
        *flight = (uint8_t)ingress->seq;
        memcpy(attempt_id, ingress->payload + 2U, 16U);
        return 1;
    }
    return 0;
}

static dmp_hs_status hold_partial(dmp_hs *hs, const dmp_hs_ingress *ingress)
{
    uint32_t index;
    uint8_t flight;
    size_t overlap;

    if (ingress->payload == NULL || ingress->payload_len > DMP_HS_PAYLOAD_MAX ||
        ingress->payload_len > hs->config.budget.provisional_bytes) {
        return DMP_HS_DROPPED;
    }
    for (index = 0U; index < DMP_HS_ATTEMPT_MAX; ++index) {
        struct hs_attempt *attempt = &hs->attempts[index];

        if (!attempt->used) {
            continue;
        }
        for (flight = 0U; flight < 3U; ++flight) {
            overlap = attempt->seen_len[flight] < ingress->payload_len ? attempt->seen_len[flight]
                                                                       : ingress->payload_len;
            if (attempt->seen_ok[flight] && overlap > 0U &&
                memcmp(attempt->seen[flight], ingress->payload, overlap) != 0) {
                (void)charge(hs);
                return DMP_HS_DROPPED;
            }
        }
    }
    if (hs->partial_used) {
        overlap = hs->partial_len < ingress->payload_len ? hs->partial_len : ingress->payload_len;
        if (overlap > 0U && memcmp(hs->partial, ingress->payload, overlap) != 0) {
            (void)charge(hs);
            return DMP_HS_DROPPED;
        }
        if (ingress->payload_len <= hs->partial_len) {
            return DMP_HS_DROPPED;
        }
    }
    memcpy(hs->partial, ingress->payload, ingress->payload_len);
    if (ingress->payload_len < DMP_HS_PAYLOAD_MAX) {
        memset(hs->partial + ingress->payload_len, 0, DMP_HS_PAYLOAD_MAX - ingress->payload_len);
    }
    hs->partial_len = (uint16_t)ingress->payload_len;
    hs->partial_used = 1;
    return DMP_HS_DROPPED;
}

static const struct hs_attempt *attempt_at(const dmp_hs *hs, uint32_t index)
{
    if (!live(hs) || index >= DMP_HS_ATTEMPT_MAX || !hs->attempts[index].used) {
        return NULL;
    }
    return &hs->attempts[index];
}

size_t dmp_hs_size(void)
{
    return sizeof(dmp_hs);
}

dmp_hs_status dmp_hs_init(dmp_hs *hs, dmp_provider *provider, const dmp_hs_config *config,
                          const dmp_hs_ports *ports)
{
    if (hs == NULL || provider == NULL || config == NULL || ports == NULL || ports->now_ms == NULL ||
        ports->entropy == NULL) {
        return DMP_HS_INVALID;
    }
    if (config->cipher == 2U) {
        return DMP_HS_UNSUPPORTED;
    }
    if ((config->mode != 1U && config->mode != 2U) || config->cipher != 1U ||
        config->local_id == config->peer_id || config->budget.max_pending > DMP_HS_ATTEMPT_MAX ||
        config->budget.max_scratch > DMP_HS_ATTEMPT_MAX) {
        return DMP_HS_INVALID;
    }
    if (config->mode == 1U && !config->has_psk) {
        return DMP_HS_INVALID;
    }
    if (config->mode == 2U && (!config->has_static || config->key_hint != 0U)) {
        return DMP_HS_INVALID;
    }
    if (config->budget.replay_window != 0U &&
        (config->budget.replay_window < DMP_REPLAY_WINDOW_MIN ||
         config->budget.replay_window > DMP_REPLAY_WINDOW_MAX ||
         (config->budget.replay_window & (config->budget.replay_window - 1U)) != 0U)) {
        return DMP_HS_INVALID;
    }
    if (config->budget.failed_aead_limit > DMP_HS_AEAD_CEILING) {
        return DMP_HS_INVALID;
    }
    memset(hs, 0, sizeof(*hs));
    hs->provider = provider;
    hs->config = *config;
    hs->ports = *ports;
    hs->later_remaining = config->budget.later_episodes;
    hs->next_cid = config->next_rx_cid == 0U ? 1U : config->next_rx_cid;
    hs->replay_width = config->budget.replay_window == 0U ? DMP_REPLAY_WINDOW_DEFAULT
                                                          : config->budget.replay_window;
    hs->failed_limit = config->budget.failed_aead_limit == 0U ? DMP_HS_AEAD_CEILING
                                                              : config->budget.failed_aead_limit;
    hs->lifetime_ms = config->budget.association_lifetime_ms == 0U
                          ? DMP_HS_LIFETIME_DEFAULT_MS
                          : config->budget.association_lifetime_ms;
    if (noise_hashstate_new_by_id(&hs->epoch_hash, NOISE_HASH_SHA256) != NOISE_ERROR_NONE ||
        hs->epoch_hash == NULL) {
        wipe(hs, sizeof(*hs));
        return DMP_HS_REFUSED;
    }
    hs->magic = DMP_HS_MAGIC;
    return DMP_HS_OK;
}

void dmp_hs_cleanup(dmp_hs *hs)
{
    uint32_t index;

    if (!live(hs)) {
        return;
    }
    for (index = 0U; index < DMP_HS_ATTEMPT_MAX; ++index) {
        close_crypto(hs, &hs->attempts[index]);
    }
    if (hs->epoch_hash != NULL) {
        (void)noise_hashstate_free(hs->epoch_hash);
        hs->epoch_hash = NULL;
    }
    wipe(hs, sizeof(*hs));
}

dmp_hs_status dmp_hs_begin_episode(dmp_hs *hs)
{
    uint64_t now;

    if (!live(hs)) {
        return DMP_HS_INVALID;
    }
    now = now_ms(hs);
    if (hs->episode_open && !episode_finished(hs, now)) {
        return DMP_HS_OK;
    }
    if (hs->episodes_started > 0U) {
        if (hs->later_remaining == 0U) {
            return DMP_HS_REFUSED;
        }
        hs->later_remaining--;
    }
    hs->episode_open = 1;
    hs->episode_start_ms = now;
    hs->episode_attempts_used = 0U;
    hs->episode_work = 0U;
    hs->episode_traffic = 0U;
    hs->next_attempt_ms = 0U;
    hs->episodes_started++;
    return DMP_HS_OK;
}

dmp_hs_status dmp_hs_schedule(dmp_hs *hs, uint32_t *attempt_index_out)
{
    struct hs_attempt *attempt;
    uint64_t now;
    size_t flight_bytes;

    if (!live(hs) || attempt_index_out == NULL || hs->config.local_id == hs->config.peer_id) {
        return DMP_HS_INVALID;
    }
    now = now_ms(hs);
    flight_bytes = payload_length(hs->config.mode, 1U);
    if (!hs->episode_open || episode_finished(hs, now) ||
        (hs->next_attempt_ms != 0U && now < hs->next_attempt_ms) ||
        hs->episode_attempts_used >= hs->config.budget.episode_attempts ||
        pending_count(hs) >= hs->config.budget.max_pending ||
        hs->global_work >= hs->config.budget.global_work || !traffic_room(hs, flight_bytes)) {
        return DMP_HS_REFUSED;
    }
    attempt = alloc_attempt(hs);
    if (attempt == NULL || !take_cid(hs, &attempt->local_rx_cid)) {
        if (attempt != NULL) {
            attempt->used = 0;
        }
        return DMP_HS_REFUSED;
    }
    hs->episode_attempts_used++;
    copy_identity(hs, attempt, 1);
    if (!fill_entropy(hs, attempt->attempt_id, 16U) || !fill_entropy(hs, attempt->ephemeral, 32U) ||
        !boot_epoch_of(hs->epoch_hash, attempt->attempt_id, &attempt->boot_epoch)) {
        abort_attempt(hs, attempt, DMP_HS_VIEW_REJECTED);
        return DMP_HS_ABORTED;
    }
    build_prefix(attempt);
    if (!open_handshake(hs, attempt) || !write_flight(hs, attempt, 1U)) {
        abort_attempt(hs, attempt, DMP_HS_VIEW_REJECTED);
        return DMP_HS_ABORTED;
    }
    attempt->expect_flight = 2U;
    *attempt_index_out = attempt_index(hs, attempt);
    return DMP_HS_OK;
}

dmp_hs_status dmp_hs_offer(dmp_hs *hs, const dmp_hs_ingress *ingress, dmp_hs_completion *completion)
{
    uint8_t flight = 0U;
    uint8_t attempt_id[16];
    struct hs_attempt *attempt;

    if (!live(hs) || ingress == NULL) {
        return DMP_HS_INVALID;
    }
    if (completion != NULL) {
        memset(completion, 0, sizeof(*completion));
    }
    if (ingress->partial || (ingress->payload != NULL && ingress->payload_len < 2U && ingress->seq == 0U)) {
        return hold_partial(hs, ingress);
    }
    if (ingress->route_to_root || ingress->route_broadcast || ingress->destination_id != hs->config.local_id ||
        ingress->namespace_id != hs->config.namespace_id) {
        (void)charge(hs);
        return DMP_HS_DROPPED;
    }
    if (!extract_flight(ingress, &flight, attempt_id)) {
        (void)charge(hs);
        return DMP_HS_DROPPED;
    }
    attempt = find_attempt(hs, attempt_id);
    if (attempt != NULL && attempt->awaiting) {
        return DMP_HS_SERIAL;
    }
    if (attempt != NULL && now_ms(hs) >= attempt->deadline_ms) {
        abort_attempt(hs, attempt, DMP_HS_VIEW_EXPIRED);
        return DMP_HS_EXPIRED;
    }
    if (attempt != NULL && flight >= 1U && flight <= 3U && attempt->seen_ok[flight - 1U]) {
        int same = ingress->payload_len == attempt->seen_len[flight - 1U] &&
                   memcmp(ingress->payload, attempt->seen[flight - 1U], ingress->payload_len) == 0 &&
                   outer_matches(hs, attempt, flight, ingress);

        if (!same) {
            (void)charge(hs);
            return DMP_HS_DROPPED;
        }
        if (attempt->cached_flight == (uint8_t)(flight + 1U)) {
            if (!retransmit_cached(hs, attempt)) {
                return DMP_HS_REFUSED;
            }
        }
        return DMP_HS_OK;
    }
    if (attempt == NULL) {
        if (flight != 1U) {
            (void)charge(hs);
            return DMP_HS_DROPPED;
        }
        return admit_flight1(hs, ingress, completion);
    }
    if (flight != attempt->expect_flight || attempt->expect_flight == 0U) {
        (void)charge(hs);
        return DMP_HS_DROPPED;
    }
    return read_expected(hs, attempt, flight, ingress, completion);
}

dmp_hs_status dmp_hs_accept(dmp_hs *hs, const dmp_hs_completion *completion)
{
    struct hs_attempt *attempt;
    dmp_hs_status status;

    if (!live(hs) || completion == NULL || completion->attempt_index >= DMP_HS_ATTEMPT_MAX) {
        return DMP_HS_INVALID;
    }
    attempt = &hs->attempts[completion->attempt_index];
    if (!attempt->used || !attempt->awaiting || attempt->generation != completion->generation) {
        return DMP_HS_STALE;
    }
    if (now_ms(hs) >= attempt->deadline_ms) {
        abort_attempt(hs, attempt, DMP_HS_VIEW_EXPIRED);
        return DMP_HS_EXPIRED;
    }
    if (!remember_seen(attempt, attempt->read_flight, attempt->pending, attempt->pending_len)) {
        return fail_read(hs, attempt);
    }
    attempt->awaiting = 0;
    release_scratch(hs, attempt);
    if (!attempt->initiator && attempt->read_flight == 1U) {
        if (!take_cid(hs, &attempt->local_rx_cid) || !write_flight(hs, attempt, 2U)) {
            return fail_read(hs, attempt);
        }
        if (attempt->mode == 1U) {
            return finish_candidate(hs, attempt);
        }
        attempt->expect_flight = 3U;
        return DMP_HS_OK;
    }
    if (attempt->initiator && attempt->mode == 2U && attempt->read_flight == 2U) {
        if (!write_flight(hs, attempt, 3U)) {
            return fail_read(hs, attempt);
        }
        return finish_candidate(hs, attempt);
    }
    if ((attempt->initiator && attempt->mode == 1U && attempt->read_flight == 2U) ||
        (!attempt->initiator && attempt->mode == 2U && attempt->read_flight == 3U)) {
        return finish_candidate(hs, attempt);
    }
    status = DMP_HS_ABORTED;
    abort_attempt(hs, attempt, DMP_HS_VIEW_REJECTED);
    return status;
}

dmp_hs_status dmp_hs_cancel(dmp_hs *hs, uint32_t index)
{
    struct hs_attempt *attempt;

    if (!live(hs) || index >= DMP_HS_ATTEMPT_MAX) {
        return DMP_HS_INVALID;
    }
    attempt = &hs->attempts[index];
    if (!attempt->used) {
        return DMP_HS_INVALID;
    }
    if (attempt->terminal) {
        return DMP_HS_STALE;
    }
    abort_attempt(hs, attempt, DMP_HS_VIEW_REJECTED);
    return DMP_HS_OK;
}

static int lifetime_over(const dmp_hs *hs, const struct hs_attempt *attempt)
{
    if (attempt->split_ms == 0U || hs->lifetime_ms > UINT64_MAX - attempt->split_ms) {
        return 0;
    }
    return now_ms(hs) >= attempt->split_ms + hs->lifetime_ms;
}

static uint64_t add_ms(uint64_t now, uint32_t delta)
{
    if ((uint64_t)delta > UINT64_MAX - now) {
        return UINT64_MAX;
    }
    return now + (uint64_t)delta;
}

/* Ends traffic keys and replay state. A pin committed before this call stays committed. */
static void end_traffic(dmp_hs *hs, struct hs_attempt *attempt)
{
    int enrolled = attempt->enrolled;

    if (!attempt->used || attempt->terminal) {
        return;
    }
    attempt->terminal = 1;
    attempt->awaiting = 0;
    attempt->candidate = 0;
    attempt->active = 0;
    attempt->waiting_ready = 0;
    attempt->ready_sent = 0;
    attempt->expect_flight = 0U;
    attempt->cached_len = 0U;
    attempt->cached_flight = 0U;
    attempt->protected_len = 0U;
    attempt->accepted_len = 0U;
    attempt->generation = ++hs->generation_clock;
    attempt->view = enrolled ? DMP_HS_VIEW_ENROLLED : DMP_HS_VIEW_EXPIRED;
    attempt->enrolled = enrolled;
    release_scratch(hs, attempt);
    close_crypto(hs, attempt);
    dmp_replay_window_clear(&attempt->replay);
    wipe(attempt->protected_frame, sizeof(attempt->protected_frame));
    wipe(attempt->accepted, sizeof(attempt->accepted));
    wipe(attempt->handshake_hash, sizeof(attempt->handshake_hash));
    attempt->hash_valid = 0;
    if (!enrolled) {
        wipe(attempt->remote_public, sizeof(attempt->remote_public));
        attempt->remote_public_valid = 0;
    }
    if (attempt->initiator) {
        schedule_restart(hs);
    }
}

static void expire_attempt(dmp_hs *hs, struct hs_attempt *attempt)
{
    if (attempt->split_ms != 0U || attempt->enrolled || attempt->active || attempt->waiting_ready) {
        end_traffic(hs, attempt);
        return;
    }
    abort_attempt(hs, attempt, DMP_HS_VIEW_EXPIRED);
}

static size_t uleb_size(uint64_t value)
{
    size_t size = 1U;

    while (value >= 0x80U) {
        value >>= 7U;
        size++;
    }
    return size;
}

static int traffic_authorized(const dmp_hs *hs, const struct hs_attempt *attempt)
{
    if (attempt->terminal || !attempt->recv_open || !attempt->send_open || !attempt->hash_valid) {
        return 0;
    }
    if (attempt->view == DMP_HS_VIEW_AWAITING_VERIFICATION) {
        return 0;
    }
    if (attempt->mode == 2U && !hs->config.has_pin && !attempt->enrolled) {
        return 0;
    }
    return attempt->candidate || attempt->enrolled || attempt->active;
}

static void become_active(struct hs_attempt *attempt)
{
    attempt->active = 1;
    attempt->waiting_ready = 0;
    attempt->candidate = 0;
    attempt->view = DMP_HS_VIEW_ACTIVE;
}

static int context_matches(const dmp_hs *hs, const struct hs_attempt *attempt,
                           const dmp_hs_protected *incoming)
{
    uint64_t epoch;

    if (incoming->destination_id != hs->config.local_id ||
        incoming->namespace_id != attempt->namespace_id || incoming->origin_id == hs->config.local_id) {
        return 0;
    }
    if (incoming->origin_id == attempt->initiator_id) {
        epoch = attempt->epoch_i;
    } else if (incoming->origin_id == attempt->responder_id) {
        epoch = attempt->epoch_r;
    } else {
        return 0;
    }
    return incoming->context_epoch == epoch;
}

static int canonical_header(const dmp_frame_view *view, uint8_t *out, size_t cap, size_t *length)
{
    size_t offset = 3U;

    if (view->header.data == NULL || view->header.size < 2U || view->header.size > cap) {
        return 0;
    }
    memcpy(out, view->header.data, view->header.size);
    *length = view->header.size;
    if ((view->fields.options & DMP_OPT_ROUTE) == 0U) {
        return 1;
    }
    if ((view->fields.options & DMP_OPT_SEQ) != 0U) {
        offset += uleb_size(view->fields.seq);
    }
    if (offset >= view->header.size) {
        return 0;
    }
    out[offset] = (uint8_t)(out[offset] & 0x0FU);
    return 1;
}

static int build_aad(const uint8_t hash[32], const uint8_t *header, size_t header_len, uint8_t *aad,
                     size_t cap, size_t *aad_len)
{
    if (header_len > cap - 46U) {
        return 0;
    }
    memcpy(aad, "DMP2-SEC1-DATA", 14U);
    memcpy(aad + 14U, hash, 32U);
    memcpy(aad + 46U, header, header_len);
    *aad_len = 46U + header_len;
    return 1;
}

static const dmp_core_limits *protected_limits(void)
{
    static const dmp_core_limits limits = {512U, DMP_HS_APP_PLAIN_MAX, 2U};

    return &limits;
}

static int seal_record(dmp_hs *hs, struct hs_attempt *attempt, uint8_t type, uint32_t seq,
                       const uint8_t *plain, size_t plain_len)
{
    uint8_t header[DMP_MAX_HEADER_BYTES];
    uint8_t body[DMP_HS_APP_PLAIN_MAX + 16U];
    uint8_t frame[DMP_HS_PROTECTED_MAX];
    uint8_t aad[DMP_HS_AAD_MAX];
    dmp_frame_spec spec;
    dmp_buffer output;
    size_t header_len = 0U;
    size_t aad_len = 0U;
    size_t sealed = 0U;
    size_t total;
    uint64_t pn;
    dmp_provider_status status;

    if (!attempt->send_open || attempt->remote_rx_cid == 0U || plain_len > DMP_HS_APP_PLAIN_MAX ||
        (plain_len != 0U && plain == NULL) || lifetime_over(hs, attempt)) {
        return 0;
    }
    if (attempt->next_pn >= DMP_HS_PN_LIMIT || attempt->send_plain > DMP_HS_PLAIN_LIMIT - plain_len) {
        return 0;
    }
    pn = attempt->next_pn;
    memset(&spec, 0, sizeof(spec));
    spec.fields.type = type;
    spec.fields.options = (uint8_t)(DMP_OPT_SEQ | DMP_OPT_SECURITY);
    spec.fields.seq = seq;
    spec.fields.security.cipher = attempt->cipher;
    spec.fields.security.receive_cid = attempt->remote_rx_cid;
    spec.fields.security.pn = pn;
    spec.payload.data = plain;
    spec.payload.size = plain_len;
    spec.trailer.size = 16U;
    output.data = header;
    output.capacity = sizeof(header);
    if (dmp_core_encode_header(&spec, protected_limits(), output, &header_len) != DMP_OK ||
        !build_aad(attempt->handshake_hash, header, header_len, aad, sizeof(aad), &aad_len) ||
        header_len + plain_len + 16U > sizeof(frame)) {
        wipe(aad, sizeof(aad));
        return 0;
    }
    if (plain_len != 0U) {
        memcpy(body, plain, plain_len);
    }
    status = dmp_provider_cipher_encrypt(hs->provider, &attempt->send_cipher, pn, aad, aad_len, body,
                                         plain_len, sizeof(body), &sealed);
    wipe(aad, sizeof(aad));
    if (status != DMP_PROVIDER_OK || sealed != plain_len + 16U) {
        wipe(body, sizeof(body));
        return 0;
    }
    total = header_len + sealed;
    memcpy(frame, header, header_len);
    memcpy(frame + header_len, body, sealed);
    wipe(body, sizeof(body));
    memcpy(attempt->protected_frame, frame, total);
    if (total < sizeof(attempt->protected_frame)) {
        memset(attempt->protected_frame + total, 0, sizeof(attempt->protected_frame) - total);
    }
    wipe(frame, sizeof(frame));
    attempt->protected_len = (uint16_t)total;
    attempt->next_pn = pn + 1U;
    attempt->send_frames++;
    attempt->send_plain += plain_len;
    return 1;
}

static dmp_hs_status retry_confirmation(dmp_hs *hs, struct hs_attempt *attempt)
{
    uint8_t opcode = 0x04U;
    uint64_t now = now_ms(hs);
    int flight3 = attempt->initiator && attempt->mode == 2U && attempt->cached_flight == 3U &&
                  attempt->cached_len != 0U;

    if (attempt->terminal || !attempt->waiting_ready) {
        return DMP_HS_REFUSED;
    }
    if (now >= attempt->deadline_ms || lifetime_over(hs, attempt)) {
        end_traffic(hs, attempt);
        return DMP_HS_EXPIRED;
    }
    if (flight3) {
        (void)retransmit_cached(hs, attempt);
    }
    if (now < attempt->confirm_deadline) {
        return flight3 ? DMP_HS_OK : DMP_HS_REFUSED;
    }
    if (attempt->confirm_sends >= hs->config.budget.confirmation_attempts) {
        end_traffic(hs, attempt);
        return DMP_HS_EXPIRED;
    }
    if (!seal_record(hs, attempt, DMP_TYPE_HELLO, 0U, &opcode, 1U)) {
        return DMP_HS_REFUSED;
    }
    attempt->confirm_sends++;
    attempt->confirm_deadline = add_ms(now, hs->config.budget.confirmation_timeout_ms);
    return DMP_HS_OK;
}

static struct hs_attempt *find_by_cid(dmp_hs *hs, uint32_t cid)
{
    uint32_t index;

    if (cid == 0U) {
        return NULL;
    }
    for (index = 0U; index < DMP_HS_ATTEMPT_MAX; ++index) {
        struct hs_attempt *attempt = &hs->attempts[index];

        if (attempt->used && !attempt->terminal && attempt->local_rx_cid == cid) {
            return attempt;
        }
    }
    return NULL;
}

static int confirmation_hello(const dmp_frame_view *view, const uint8_t *plain, size_t plain_len,
                              uint8_t opcode)
{
    return view->fields.type == DMP_TYPE_HELLO &&
           view->fields.options == (uint8_t)(DMP_OPT_SEQ | DMP_OPT_SECURITY) && view->fields.seq == 0U &&
           view->extensions.size == 0U && plain_len == 1U && plain[0] == opcode;
}

static void remember_plain(struct hs_attempt *attempt, const uint8_t *plain, size_t plain_len)
{
    if (plain_len > sizeof(attempt->accepted)) {
        plain_len = sizeof(attempt->accepted);
    }
    if (plain_len != 0U) {
        memcpy(attempt->accepted, plain, plain_len);
    }
    if (plain_len < sizeof(attempt->accepted)) {
        memset(attempt->accepted + plain_len, 0, sizeof(attempt->accepted) - plain_len);
    }
    attempt->accepted_len = (uint16_t)plain_len;
}

dmp_hs_status dmp_hs_poll(dmp_hs *hs, uint32_t *index_out)
{
    uint32_t index;
    int expired = 0;
    uint64_t now;

    if (!live(hs)) {
        return DMP_HS_INVALID;
    }
    now = now_ms(hs);
    for (index = 0U; index < DMP_HS_ATTEMPT_MAX; ++index) {
        struct hs_attempt *attempt = &hs->attempts[index];

        if (!attempt->used || attempt->terminal) {
            continue;
        }
        if (lifetime_over(hs, attempt) ||
            (attempt->waiting_ready && now >= attempt->confirm_deadline &&
             attempt->confirm_sends >= hs->config.budget.confirmation_attempts) ||
            now >= attempt->deadline_ms) {
            expire_attempt(hs, attempt);
            if (!expired && index_out != NULL) {
                *index_out = index;
            }
            expired = 1;
        }
    }
    return expired ? DMP_HS_EXPIRED : DMP_HS_OK;
}

dmp_hs_status dmp_hs_retransmit(dmp_hs *hs, uint32_t index)
{
    struct hs_attempt *attempt;

    if (!live(hs) || index >= DMP_HS_ATTEMPT_MAX) {
        return DMP_HS_INVALID;
    }
    attempt = &hs->attempts[index];
    if (!attempt->used || attempt->terminal) {
        return DMP_HS_REFUSED;
    }
    if (attempt->waiting_ready) {
        return retry_confirmation(hs, attempt);
    }
    if (attempt->cached_len == 0U) {
        return DMP_HS_REFUSED;
    }
    if (now_ms(hs) >= attempt->deadline_ms || lifetime_over(hs, attempt)) {
        expire_attempt(hs, attempt);
        return DMP_HS_EXPIRED;
    }
    if (!retransmit_cached(hs, attempt)) {
        return DMP_HS_REFUSED;
    }
    return DMP_HS_OK;
}

dmp_hs_status dmp_hs_approve(dmp_hs *hs, uint32_t index, const dmp_hs_approval *approval)
{
    struct hs_attempt *attempt;
    dmp_hs_pin_record record;

    if (!live(hs) || approval == NULL || index >= DMP_HS_ATTEMPT_MAX) {
        return DMP_HS_INVALID;
    }
    attempt = &hs->attempts[index];
    if (!attempt->used) {
        return DMP_HS_INVALID;
    }
    if (attempt->terminal || attempt->generation != approval->generation) {
        return DMP_HS_STALE;
    }
    if (now_ms(hs) >= attempt->deadline_ms) {
        abort_attempt(hs, attempt, DMP_HS_VIEW_EXPIRED);
        return DMP_HS_EXPIRED;
    }
    if (attempt->view != DMP_HS_VIEW_AWAITING_VERIFICATION || !attempt->hash_valid ||
        !attempt->remote_public_valid) {
        return DMP_HS_NO_TRUST;
    }
    if (memcmp(approval->attempt_id, attempt->attempt_id, 16U) != 0 ||
        approval->initiator_id != attempt->initiator_id ||
        approval->responder_id != attempt->responder_id ||
        memcmp(approval->hash, attempt->handshake_hash, 32U) != 0) {
        return DMP_HS_NO_TRUST;
    }
    if (!approval->accept) {
        abort_attempt(hs, attempt, DMP_HS_VIEW_REJECTED);
        return DMP_HS_ABORTED;
    }
    memset(&record, 0, sizeof(record));
    record.namespace_id = attempt->namespace_id;
    record.local_id = hs->config.local_id;
    record.peer_id = attempt->initiator ? attempt->responder_id : attempt->initiator_id;
    memcpy(record.profile_hash, attempt->profile_hash, 32U);
    memcpy(record.remote_public, attempt->remote_public, 32U);
    memcpy(record.handshake_hash, attempt->handshake_hash, 32U);
    record.permissions = hs->config.permissions;
    record.mode = attempt->mode;
    record.cipher = attempt->cipher;
    if (hs->ports.commit_pin == NULL || hs->ports.commit_pin(hs->ports.ctx, &record) != 0) {
        wipe(&record, sizeof(record));
        abort_attempt(hs, attempt, DMP_HS_VIEW_REJECTED);
        return DMP_HS_ABORTED;
    }
    wipe(&record, sizeof(record));
    attempt->enrolled = 1;
    attempt->view = DMP_HS_VIEW_ENROLLED;
    return DMP_HS_COMMITTED;
}

dmp_hs_status dmp_hs_send_application(const dmp_hs *hs, uint32_t attempt_index_in)
{
    const struct hs_attempt *attempt = attempt_at(hs, attempt_index_in);

    if (!live(hs)) {
        return DMP_HS_INVALID;
    }
    if (attempt == NULL) {
        return DMP_HS_INVALID;
    }
    if (attempt->active && !attempt->terminal) {
        return DMP_HS_OK;
    }
    return DMP_HS_NOT_ACTIVE;
}

dmp_hs_status dmp_hs_confirm(dmp_hs *hs, uint32_t index)
{
    struct hs_attempt *attempt;
    uint8_t opcode = 0x04U;
    uint64_t now;

    if (!live(hs) || index >= DMP_HS_ATTEMPT_MAX) {
        return DMP_HS_INVALID;
    }
    attempt = &hs->attempts[index];
    if (!attempt->used) {
        return DMP_HS_INVALID;
    }
    if (attempt->terminal) {
        return DMP_HS_STALE;
    }
    now = now_ms(hs);
    if (now >= attempt->deadline_ms || lifetime_over(hs, attempt)) {
        expire_attempt(hs, attempt);
        return DMP_HS_EXPIRED;
    }
    if (!attempt->initiator || attempt->remote_rx_cid == 0U) {
        return DMP_HS_REFUSED;
    }
    if (attempt->active) {
        return DMP_HS_OK;
    }
    if (!traffic_authorized(hs, attempt)) {
        return DMP_HS_NO_TRUST;
    }
    if (hs->config.budget.confirmation_timeout_ms == 0U || hs->config.budget.confirmation_attempts == 0U) {
        return DMP_HS_INVALID;
    }
    if (attempt->waiting_ready) {
        return retry_confirmation(hs, attempt);
    }
    if (!seal_record(hs, attempt, DMP_TYPE_HELLO, 0U, &opcode, 1U)) {
        return DMP_HS_REFUSED;
    }
    attempt->waiting_ready = 1;
    attempt->confirm_sends = 1U;
    attempt->confirm_deadline = add_ms(now, hs->config.budget.confirmation_timeout_ms);
    if (attempt->next_seq == 0U) {
        attempt->next_seq = 1U;
    }
    return DMP_HS_OK;
}

dmp_hs_status dmp_hs_offer_protected(dmp_hs *hs, const dmp_hs_protected *incoming)
{
    struct hs_attempt *attempt;
    dmp_frame_view view;
    dmp_parse_result parsed;
    uint8_t canon[DMP_MAX_HEADER_BYTES];
    uint8_t aad[DMP_HS_AAD_MAX];
    uint8_t body[DMP_HS_APP_PLAIN_MAX + 16U];
    size_t canon_len = 0U;
    size_t aad_len = 0U;
    size_t plain_len = 0U;
    dmp_provider_status status;
    uint8_t opcode = 0x05U;

    if (!live(hs) || incoming == NULL || incoming->frame == NULL || incoming->frame_len == 0U) {
        return DMP_HS_INVALID;
    }
    memset(&view, 0, sizeof(view));
    parsed = dmp_core_parse((dmp_bytes){incoming->frame, incoming->frame_len}, protected_limits(), &view);
    if (parsed.status != DMP_OK || (view.fields.options & DMP_OPT_SECURITY) == 0U) {
        return DMP_HS_DROPPED;
    }
    attempt = find_by_cid(hs, view.fields.security.receive_cid);
    if (attempt == NULL || !attempt->recv_open || !context_matches(hs, attempt, incoming)) {
        return DMP_HS_DROPPED;
    }
    if (view.fields.security.cipher == 2U) {
        return DMP_HS_UNSUPPORTED;
    }
    if (view.fields.security.cipher != attempt->cipher || view.trailer.size != 16U) {
        return DMP_HS_DROPPED;
    }
    if (lifetime_over(hs, attempt) || attempt->recv_plain > DMP_HS_PLAIN_LIMIT - view.payload.size) {
        end_traffic(hs, attempt);
        return DMP_HS_EXPIRED;
    }
    if (view.fields.security.pn >= DMP_HS_PN_LIMIT ||
        !dmp_replay_window_admit(&attempt->replay, view.fields.security.pn)) {
        return DMP_HS_DROPPED;
    }
    if (!traffic_authorized(hs, attempt)) {
        return DMP_HS_DROPPED;
    }
    if (attempt->failed_aead >= hs->failed_limit) {
        end_traffic(hs, attempt);
        return DMP_HS_DROPPED;
    }
    if (view.payload.size + view.trailer.size > sizeof(body) ||
        !canonical_header(&view, canon, sizeof(canon), &canon_len) ||
        !build_aad(attempt->handshake_hash, canon, canon_len, aad, sizeof(aad), &aad_len)) {
        wipe(canon, sizeof(canon));
        return DMP_HS_DROPPED;
    }
    if (view.payload.size != 0U) {
        memcpy(body, view.payload.data, view.payload.size);
    }
    memcpy(body + view.payload.size, view.trailer.data, view.trailer.size);
    status = dmp_provider_cipher_decrypt(hs->provider, &attempt->recv_cipher, view.fields.security.pn, aad,
                                         aad_len, body, view.payload.size + view.trailer.size, sizeof(body),
                                         &plain_len);
    wipe(aad, sizeof(aad));
    wipe(canon, sizeof(canon));
    if (status != DMP_PROVIDER_OK || plain_len != view.payload.size) {
        wipe(body, sizeof(body));
        attempt->failed_aead++;
        if (attempt->failed_aead >= hs->failed_limit) {
            end_traffic(hs, attempt);
        }
        return DMP_HS_DROPPED;
    }
    if (!dmp_replay_window_commit(&attempt->replay, view.fields.security.pn)) {
        wipe(body, sizeof(body));
        return DMP_HS_DROPPED;
    }
    attempt->recv_plain += plain_len;
    if (!attempt->initiator && confirmation_hello(&view, body, plain_len, 0x04U)) {
        if (!seal_record(hs, attempt, DMP_TYPE_HELLO, 0U, &opcode, 1U)) {
            wipe(body, sizeof(body));
            return DMP_HS_REFUSED;
        }
        attempt->ready_sent = 1;
        if (attempt->next_seq == 0U) {
            attempt->next_seq = 1U;
        }
        become_active(attempt);
        wipe(body, sizeof(body));
        return DMP_HS_OK;
    }
    if (attempt->initiator && confirmation_hello(&view, body, plain_len, 0x05U)) {
        become_active(attempt);
        wipe(body, sizeof(body));
        return DMP_HS_OK;
    }
    if (view.fields.type == DMP_TYPE_HELLO || (!attempt->initiator && !attempt->ready_sent) ||
        (attempt->initiator && !attempt->waiting_ready && !attempt->active)) {
        wipe(body, sizeof(body));
        return DMP_HS_DROPPED;
    }
    remember_plain(attempt, body, plain_len);
    if (attempt->initiator && attempt->waiting_ready) {
        become_active(attempt);
    }
    wipe(body, sizeof(body));
    if (!attempt->active) {
        return DMP_HS_DROPPED;
    }
    return DMP_HS_OK;
}

dmp_hs_status dmp_hs_emit_application(dmp_hs *hs, uint32_t index, const uint8_t *plain, size_t plain_len)
{
    struct hs_attempt *attempt;

    if (!live(hs) || index >= DMP_HS_ATTEMPT_MAX) {
        return DMP_HS_INVALID;
    }
    attempt = &hs->attempts[index];
    if (!attempt->used) {
        return DMP_HS_INVALID;
    }
    if (!attempt->active || attempt->terminal) {
        return DMP_HS_NOT_ACTIVE;
    }
    if (plain_len > DMP_HS_APP_PLAIN_MAX || (plain_len != 0U && plain == NULL) ||
        attempt->next_seq == UINT32_MAX) {
        return DMP_HS_INVALID;
    }
    if (lifetime_over(hs, attempt)) {
        end_traffic(hs, attempt);
        return DMP_HS_EXPIRED;
    }
    if (!seal_record(hs, attempt, DMP_TYPE_TELEM, attempt->next_seq, plain, plain_len)) {
        return DMP_HS_REFUSED;
    }
    attempt->next_seq++;
    return DMP_HS_OK;
}

dmp_hs_status dmp_hs_seal_logical(dmp_hs *hs, uint32_t index, const dmp_frame_spec *logical,
                                  uint8_t *out, size_t cap, size_t *written)
{
    struct hs_attempt *attempt;
    dmp_frame_spec spec;
    dmp_frame_view view;
    dmp_core_limits limits;
    dmp_buffer output;
    uint8_t header[DMP_MAX_HEADER_BYTES];
    uint8_t canon[DMP_MAX_HEADER_BYTES];
    uint8_t body[DMP_HS_APP_PLAIN_MAX + 16U];
    uint8_t aad[DMP_HS_AAD_MAX];
    size_t header_len = 0U;
    size_t canon_len = 0U;
    size_t aad_len = 0U;
    size_t sealed = 0U;
    uint64_t pn;
    dmp_provider_status status;

    if (written != NULL) {
        *written = 0U;
    }
    if (!live(hs) || logical == NULL || out == NULL || written == NULL || index >= DMP_HS_ATTEMPT_MAX) {
        return DMP_HS_INVALID;
    }
    attempt = &hs->attempts[index];
    if (!attempt->used) {
        return DMP_HS_INVALID;
    }
    if (!attempt->active || attempt->terminal) {
        return DMP_HS_NOT_ACTIVE;
    }
    if (attempt->cipher != 1U) {
        return DMP_HS_UNSUPPORTED;
    }
    if (logical->payload.size > DMP_HS_APP_PLAIN_MAX ||
        (logical->payload.size != 0U && logical->payload.data == NULL) ||
        (logical->fields.options & DMP_OPT_SEQ) == 0U ||
        (logical->fields.options & DMP_OPT_INTEGRITY) != 0U) {
        return DMP_HS_INVALID;
    }
    if (!attempt->send_open || attempt->remote_rx_cid == 0U) {
        return DMP_HS_REFUSED;
    }
    if (lifetime_over(hs, attempt)) {
        end_traffic(hs, attempt);
        return DMP_HS_EXPIRED;
    }
    if (attempt->next_pn >= DMP_HS_PN_LIMIT ||
        attempt->send_plain > DMP_HS_PLAIN_LIMIT - logical->payload.size) {
        return DMP_HS_REFUSED;
    }
    pn = attempt->next_pn;
    spec = *logical;
    spec.fields.options = (uint8_t)(spec.fields.options | DMP_OPT_SECURITY);
    spec.fields.security.cipher = attempt->cipher;
    spec.fields.security.receive_cid = attempt->remote_rx_cid;
    spec.fields.security.pn = pn;
    spec.trailer.data = NULL;
    spec.trailer.size = 16U;
    limits.max_frame_bytes = cap;
    /* The slice stays within the P14 plaintext bound. total_size may name a
     * larger reassembled message. */
    limits.max_message_bytes = 65535U;
    limits.max_fragments = 32U;
    output.data = header;
    output.capacity = sizeof(header);
    if (dmp_core_encode_header(&spec, &limits, output, &header_len) != DMP_OK ||
        header_len + logical->payload.size + 16U > cap) {
        wipe(header, sizeof(header));
        return DMP_HS_REFUSED;
    }
    memset(&view, 0, sizeof(view));
    view.header.data = header;
    view.header.size = header_len;
    view.fields.options = spec.fields.options;
    view.fields.seq = spec.fields.seq;
    if (!canonical_header(&view, canon, sizeof(canon), &canon_len) ||
        !build_aad(attempt->handshake_hash, canon, canon_len, aad, sizeof(aad), &aad_len)) {
        wipe(header, sizeof(header));
        wipe(canon, sizeof(canon));
        wipe(aad, sizeof(aad));
        return DMP_HS_REFUSED;
    }
    if (logical->payload.size != 0U) {
        memcpy(body, logical->payload.data, logical->payload.size);
    }
    status = dmp_provider_cipher_encrypt(hs->provider, &attempt->send_cipher, pn, aad, aad_len, body,
                                         logical->payload.size, sizeof(body), &sealed);
    wipe(aad, sizeof(aad));
    wipe(canon, sizeof(canon));
    if (status != DMP_PROVIDER_OK || sealed != logical->payload.size + 16U) {
        wipe(header, sizeof(header));
        wipe(body, sizeof(body));
        return DMP_HS_REFUSED;
    }
    memcpy(out, header, header_len);
    memcpy(out + header_len, body, sealed);
    wipe(header, sizeof(header));
    wipe(body, sizeof(body));
    *written = header_len + sealed;
    attempt->next_pn = pn + 1U;
    attempt->send_frames++;
    attempt->send_plain += logical->payload.size;
    return DMP_HS_OK;
}

dmp_hs_status dmp_hs_open_logical(dmp_hs *hs, uint32_t index, const dmp_hs_protected *incoming,
                                  uint8_t *plain, size_t plain_cap, size_t *plain_len,
                                  dmp_frame_view *view_out)
{
    struct hs_attempt *attempt;
    dmp_frame_view view;
    dmp_parse_result parsed;
    dmp_core_limits limits;
    uint8_t canon[DMP_MAX_HEADER_BYTES];
    uint8_t aad[DMP_HS_AAD_MAX];
    uint8_t body[DMP_HS_APP_PLAIN_MAX + 16U];
    size_t canon_len = 0U;
    size_t aad_len = 0U;
    size_t opened = 0U;
    dmp_provider_status status;

    if (plain_len != NULL) {
        *plain_len = 0U;
    }
    if (!live(hs) || incoming == NULL || incoming->frame == NULL || incoming->frame_len == 0U ||
        plain == NULL || plain_len == NULL || view_out == NULL || index >= DMP_HS_ATTEMPT_MAX) {
        return DMP_HS_INVALID;
    }
    attempt = &hs->attempts[index];
    if (!attempt->used) {
        return DMP_HS_INVALID;
    }
    limits.max_frame_bytes = 512U;
    limits.max_message_bytes = 65535U;
    limits.max_fragments = 32U;
    memset(&view, 0, sizeof(view));
    parsed = dmp_core_parse((dmp_bytes){incoming->frame, incoming->frame_len}, &limits, &view);
    if (parsed.status != DMP_OK || (view.fields.options & DMP_OPT_SECURITY) == 0U) {
        return DMP_HS_DROPPED;
    }
    if (attempt->terminal || !attempt->recv_open || attempt->local_rx_cid != view.fields.security.receive_cid ||
        !context_matches(hs, attempt, incoming)) {
        return DMP_HS_DROPPED;
    }
    if (view.fields.security.cipher == 2U) {
        return DMP_HS_UNSUPPORTED;
    }
    if (view.fields.security.cipher != attempt->cipher || view.trailer.size != 16U) {
        return DMP_HS_DROPPED;
    }
    if (!attempt->active || view.fields.type == DMP_TYPE_HELLO) {
        return attempt->active ? DMP_HS_DROPPED : DMP_HS_NOT_ACTIVE;
    }
    if (lifetime_over(hs, attempt) || attempt->recv_plain > DMP_HS_PLAIN_LIMIT - view.payload.size) {
        end_traffic(hs, attempt);
        return DMP_HS_EXPIRED;
    }
    if (view.fields.security.pn >= DMP_HS_PN_LIMIT ||
        !dmp_replay_window_admit(&attempt->replay, view.fields.security.pn)) {
        return DMP_HS_DROPPED;
    }
    if (!traffic_authorized(hs, attempt)) {
        return DMP_HS_DROPPED;
    }
    if (attempt->failed_aead >= hs->failed_limit) {
        end_traffic(hs, attempt);
        return DMP_HS_DROPPED;
    }
    if (view.payload.size > DMP_HS_APP_PLAIN_MAX || view.payload.size > plain_cap ||
        view.payload.size + view.trailer.size > sizeof(body) ||
        !canonical_header(&view, canon, sizeof(canon), &canon_len) ||
        !build_aad(attempt->handshake_hash, canon, canon_len, aad, sizeof(aad), &aad_len)) {
        wipe(canon, sizeof(canon));
        wipe(aad, sizeof(aad));
        return DMP_HS_DROPPED;
    }
    if (view.payload.size != 0U) {
        memcpy(body, view.payload.data, view.payload.size);
    }
    memcpy(body + view.payload.size, view.trailer.data, view.trailer.size);
    status = dmp_provider_cipher_decrypt(hs->provider, &attempt->recv_cipher, view.fields.security.pn, aad,
                                         aad_len, body, view.payload.size + view.trailer.size, sizeof(body),
                                         &opened);
    wipe(aad, sizeof(aad));
    wipe(canon, sizeof(canon));
    if (status != DMP_PROVIDER_OK || opened != view.payload.size) {
        wipe(body, sizeof(body));
        attempt->failed_aead++;
        if (attempt->failed_aead >= hs->failed_limit) {
            end_traffic(hs, attempt);
        }
        return DMP_HS_DROPPED;
    }
    if (!dmp_replay_window_commit(&attempt->replay, view.fields.security.pn)) {
        wipe(body, sizeof(body));
        return DMP_HS_DROPPED;
    }
    attempt->recv_plain += opened;
    if (opened != 0U) {
        memcpy(plain, body, opened);
    }
    wipe(body, sizeof(body));
    view.payload.data = plain;
    view.payload.size = opened;
    *plain_len = opened;
    *view_out = view;
    return DMP_HS_OK;
}

int dmp_hs_traffic_identity(const dmp_hs *hs, uint32_t index, uint32_t *namespace_id,
                            uint32_t *local_id, uint32_t *peer_id, uint64_t *local_epoch,
                            uint64_t *peer_epoch)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    if (attempt == NULL || !attempt->hash_valid || namespace_id == NULL || local_id == NULL ||
        peer_id == NULL || local_epoch == NULL || peer_epoch == NULL) {
        return 0;
    }
    *namespace_id = attempt->namespace_id;
    *local_id = hs->config.local_id;
    if (attempt->initiator) {
        *peer_id = attempt->responder_id;
        *local_epoch = attempt->epoch_i;
        *peer_epoch = attempt->epoch_r;
    } else {
        *peer_id = attempt->initiator_id;
        *local_epoch = attempt->epoch_r;
        *peer_epoch = attempt->epoch_i;
    }
    return 1;
}

dmp_hs_status dmp_hs_retain_association(dmp_hs *hs, const dmp_hs_retained *retained)
{
    uint32_t index;

    if (!live(hs) || retained == NULL || retained->rx_cid == 0U) {
        return DMP_HS_INVALID;
    }
    for (index = 0U; index < DMP_HS_ASSOCIATION_MAX; ++index) {
        if (!hs->retained_used[index]) {
            hs->retained[index] = *retained;
            hs->retained_used[index] = 1;
            return DMP_HS_OK;
        }
    }
    return DMP_HS_REFUSED;
}

int dmp_hs_association_active(const dmp_hs *hs)
{
    uint32_t index;

    if (!live(hs)) {
        return 0;
    }
    for (index = 0U; index < DMP_HS_ATTEMPT_MAX; ++index) {
        const struct hs_attempt *attempt = &hs->attempts[index];

        if (attempt->used && attempt->active && !attempt->terminal) {
            return 1;
        }
    }
    return 0;
}

dmp_hs_view dmp_hs_view_of(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    if (attempt == NULL) {
        return live(hs) && hs->config.pairing_allowed ? DMP_HS_VIEW_PAIRING_ALLOWED : DMP_HS_VIEW_IDLE;
    }
    return attempt->view;
}

uint64_t dmp_hs_generation(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt == NULL ? 0U : attempt->generation;
}

uint64_t dmp_hs_deadline(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt == NULL ? 0U : attempt->deadline_ms;
}

uint32_t dmp_hs_noise_writes(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt == NULL ? 0U : attempt->noise_writes;
}

uint32_t dmp_hs_noise_reads(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt == NULL ? 0U : attempt->noise_reads;
}

uint32_t dmp_hs_total_reads(const dmp_hs *hs)
{
    return live(hs) ? hs->total_reads : 0U;
}

uint32_t dmp_hs_global_work(const dmp_hs *hs)
{
    return live(hs) ? hs->global_work : 0U;
}

uint32_t dmp_hs_episode_attempts_used(const dmp_hs *hs)
{
    return live(hs) ? hs->episode_attempts_used : 0U;
}

uint32_t dmp_hs_episode_work(const dmp_hs *hs)
{
    return live(hs) ? hs->episode_work : 0U;
}

uint32_t dmp_hs_rx_cid(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt == NULL ? 0U : attempt->local_rx_cid;
}

uint32_t dmp_hs_retransmits(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt == NULL ? 0U : attempt->retransmits;
}

int dmp_hs_enrolled(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt != NULL && attempt->enrolled;
}

int dmp_hs_candidate(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt != NULL && attempt->candidate && !attempt->terminal;
}

int dmp_hs_terminal(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt != NULL && attempt->terminal;
}

int dmp_hs_secrets_wiped(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);
    uint8_t zeros[32];

    if (attempt == NULL || !attempt->terminal || attempt->handshake_open || attempt->send_open ||
        attempt->recv_open) {
        return 0;
    }
    memset(zeros, 0, sizeof(zeros));
    return memcmp(attempt->ephemeral, zeros, 32U) == 0 && memcmp(attempt->psk, zeros, 32U) == 0;
}

int dmp_hs_retained_alive(const dmp_hs *hs, uint32_t index)
{
    if (!live(hs) || index >= DMP_HS_ASSOCIATION_MAX) {
        return 0;
    }
    return hs->retained_used[index];
}

const uint8_t *dmp_hs_cached_flight(const dmp_hs *hs, uint32_t index, size_t *length)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    if (attempt == NULL || attempt->cached_len == 0U) {
        if (length != NULL) {
            *length = 0U;
        }
        return NULL;
    }
    if (length != NULL) {
        *length = attempt->cached_len;
    }
    return attempt->cached;
}

const uint8_t *dmp_hs_protected_frame(const dmp_hs *hs, uint32_t index, size_t *length)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    if (attempt == NULL || attempt->protected_len == 0U) {
        if (length != NULL) {
            *length = 0U;
        }
        return NULL;
    }
    if (length != NULL) {
        *length = attempt->protected_len;
    }
    return attempt->protected_frame;
}

int dmp_hs_copy_accepted(const dmp_hs *hs, uint32_t index, uint8_t *out, size_t cap, size_t *length)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    if (attempt == NULL || out == NULL || attempt->accepted_len > cap) {
        return 0;
    }
    if (attempt->accepted_len != 0U) {
        memcpy(out, attempt->accepted, attempt->accepted_len);
    }
    if (length != NULL) {
        *length = attempt->accepted_len;
    }
    return 1;
}

uint32_t dmp_hs_failed_aead(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt == NULL ? 0U : attempt->failed_aead;
}

uint64_t dmp_hs_next_pn(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt == NULL ? 0U : attempt->next_pn;
}

int dmp_hs_copy_attempt_id(const dmp_hs *hs, uint32_t index, uint8_t id[16])
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    if (attempt == NULL || id == NULL) {
        return 0;
    }
    memcpy(id, attempt->attempt_id, 16U);
    return 1;
}

int dmp_hs_copy_hash(const dmp_hs *hs, uint32_t index, uint8_t hash[32])
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    if (attempt == NULL || hash == NULL || !attempt->hash_valid) {
        return 0;
    }
    memcpy(hash, attempt->handshake_hash, 32U);
    return 1;
}

int dmp_hs_epochs(const dmp_hs *hs, uint32_t index, uint64_t *initiator_epoch, uint64_t *responder_epoch)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    if (attempt == NULL || !attempt->hash_valid || initiator_epoch == NULL || responder_epoch == NULL) {
        return 0;
    }
    *initiator_epoch = attempt->epoch_i;
    *responder_epoch = attempt->epoch_r;
    return 1;
}

uint64_t dmp_hs_boot_epoch(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt == NULL ? 0U : attempt->boot_epoch;
}

uint8_t dmp_hs_expect_flight(const dmp_hs *hs, uint32_t index)
{
    const struct hs_attempt *attempt = attempt_at(hs, index);

    return attempt == NULL ? 0U : attempt->expect_flight;
}

int dmp_hs_copy_partial(const dmp_hs *hs, uint8_t *out, size_t capacity, size_t *length)
{
    if (!live(hs) || !hs->partial_used || out == NULL || length == NULL || capacity < hs->partial_len) {
        return 0;
    }
    memcpy(out, hs->partial, hs->partial_len);
    *length = hs->partial_len;
    return 1;
}

uint32_t dmp_hs_pending(const dmp_hs *hs)
{
    return live(hs) ? pending_count(hs) : 0U;
}
