#include "sample1_epoch_store.h"

#include <stdio.h>
#include <string.h>

#include "dmp/integrity.h"

#define CHECK(expr)                                                                            \
    do {                                                                                       \
        if (!(expr)) {                                                                         \
            (void)fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #expr);    \
            return 1;                                                                          \
        }                                                                                      \
    } while (0)

/* --- Mock Monotonic Anchor State --- */

typedef struct {
    bool has_floor;
    uint64_t floor;
    bool is_pending;
    uint64_t pending_epoch;
    dmp_sample1_principal principal;

    /* Injected error controls */
    bool get_status_error;
    bool begin_error;
    bool complete_error;

    /* Call counters */
    unsigned get_calls;
    unsigned begin_calls;
    unsigned complete_calls;
} mock_anchor_state;

static char g_events[64];
static size_t g_event_count = 0;

static void clear_events(void)
{
    g_event_count = 0;
    g_events[0] = '\0';
}

static void record_event(char c)
{
    if (g_event_count + 1 < sizeof(g_events)) {
        g_events[g_event_count++] = c;
        g_events[g_event_count] = '\0';
    }
}

static void mock_anchor_latch_pending(mock_anchor_state *anchor,
                                      dmp_sample1_principal principal)
{
    if (anchor == NULL) {
        return;
    }
    if (!anchor->is_pending) {
        anchor->is_pending = true;
        if (anchor->has_floor) {
            anchor->pending_epoch = (anchor->floor == UINT64_MAX) ? UINT64_MAX : anchor->floor + 1U;
        } else {
            anchor->pending_epoch = 1U;
        }
    }
    anchor->principal = principal;
}

static bool mock_anchor_get_status(void *user,
                                   dmp_sample1_principal principal,
                                   dmp_sample1_anchor_status *status)
{
    mock_anchor_state *anchor = (mock_anchor_state *)user;
    (void)principal;
    if (anchor == NULL || status == NULL) {
        return false;
    }
    anchor->get_calls++;
    if (anchor->get_status_error) {
        mock_anchor_latch_pending(anchor, principal);
        return false;
    }
    status->has_floor = anchor->has_floor;
    status->floor = anchor->floor;
    status->is_pending = anchor->is_pending;
    status->pending_epoch = anchor->pending_epoch;
    return true;
}

static bool mock_anchor_begin(void *user,
                              dmp_sample1_principal principal,
                              bool has_expected_floor,
                              uint64_t expected_floor,
                              bool is_recovery,
                              uint64_t expected_pending,
                              uint64_t candidate_epoch)
{
    mock_anchor_state *anchor = (mock_anchor_state *)user;
    if (anchor == NULL) {
        return false;
    }
    record_event('B');
    anchor->begin_calls++;
    if (anchor->begin_error) {
        goto failed;
    }
    if (!is_recovery) {
        if (anchor->is_pending) {
            goto failed;
        }
        if (has_expected_floor != anchor->has_floor) {
            goto failed;
        }
        if (has_expected_floor && anchor->floor != expected_floor) {
            goto failed;
        }
        if (candidate_epoch <= (has_expected_floor ? expected_floor : 0U)) {
            goto failed;
        }
    } else {
        if (!anchor->is_pending) {
            goto failed;
        }
        if (anchor->pending_epoch != expected_pending) {
            goto failed;
        }
        if (candidate_epoch <= expected_pending) {
            goto failed;
        }
    }
    anchor->is_pending = true;
    anchor->pending_epoch = candidate_epoch;
    anchor->principal = principal;
    return true;

failed:
    mock_anchor_latch_pending(anchor, principal);
    return false;
}

/* complete_reservation failure MUST leave the durable pending reservation intact */
static bool mock_anchor_complete(void *user,
                                 dmp_sample1_principal principal,
                                 uint64_t committed_epoch)
{
    mock_anchor_state *anchor = (mock_anchor_state *)user;
    (void)principal;
    if (anchor == NULL) {
        return false;
    }
    record_event('K');
    anchor->complete_calls++;
    if (anchor->complete_error) {
        /* On failure, leave the durable pending reservation intact */
        return false;
    }
    if (!anchor->is_pending || anchor->pending_epoch != committed_epoch) {
        return false;
    }
    anchor->has_floor = true;
    anchor->floor = committed_epoch;
    anchor->is_pending = false;
    anchor->pending_epoch = 0U;
    return true;
}

static const dmp_sample1_epoch_anchor_ops g_mock_anchor_ops = {
    .get_status = mock_anchor_get_status,
    .begin_reservation = mock_anchor_begin,
    .complete_reservation = mock_anchor_complete,
};

/* --- Mock NVS State --- */

typedef struct {
    bool has_blob;
    uint8_t blob[64];
    size_t blob_len;
    char key[32];

    /* Injected failure controls */
    esp_err_t get_error;
    esp_err_t set_error;
    esp_err_t commit_error;

    /* Call counters */
    unsigned get_calls;
    unsigned set_calls;
    unsigned commit_calls;
} mock_nvs_state;

static mock_nvs_state *g_mock_nvs = NULL;

static esp_err_t mock_get_blob(nvs_handle_t handle, const char *key, void *out_value, size_t *length)
{
    mock_nvs_state *nvs = g_mock_nvs;
    (void)handle;
    (void)key;
    if (nvs == NULL || length == NULL) {
        return -1;
    }
    nvs->get_calls++;
    if (nvs->get_error != ESP_OK) {
        return nvs->get_error;
    }
    if (!nvs->has_blob) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (out_value == NULL) {
        *length = nvs->blob_len;
        return ESP_OK;
    }
    if (*length < nvs->blob_len) {
        *length = nvs->blob_len;
        return -1;
    }
    (void)memcpy(out_value, nvs->blob, nvs->blob_len);
    *length = nvs->blob_len;
    return ESP_OK;
}

static esp_err_t mock_set_blob(nvs_handle_t handle, const char *key, const void *value, size_t length)
{
    mock_nvs_state *nvs = g_mock_nvs;
    (void)handle;
    if (nvs == NULL || key == NULL || value == NULL || length > sizeof(nvs->blob)) {
        return -1;
    }
    record_event('S');
    nvs->set_calls++;
    if (nvs->set_error != ESP_OK) {
        return nvs->set_error;
    }
    (void)memcpy(nvs->blob, value, length);
    nvs->blob_len = length;
    nvs->has_blob = true;
    (void)strncpy(nvs->key, key, sizeof(nvs->key) - 1U);
    nvs->key[sizeof(nvs->key) - 1U] = '\0';
    return ESP_OK;
}

static esp_err_t mock_commit(nvs_handle_t handle)
{
    mock_nvs_state *nvs = g_mock_nvs;
    (void)handle;
    if (nvs == NULL) {
        return -1;
    }
    record_event('C');
    nvs->commit_calls++;
    if (nvs->commit_error != ESP_OK) {
        return nvs->commit_error;
    }
    return ESP_OK;
}

static const dmp_sample1_nvs_ops g_mock_ops = {
    .get_blob = mock_get_blob,
    .set_blob = mock_set_blob,
    .commit = mock_commit,
};

static bool cb_allow_first_provisioning(void *user, dmp_sample1_principal principal)
{
    (void)user;
    (void)principal;
    return true;
}

static bool cb_deny_first_provisioning(void *user, dmp_sample1_principal principal)
{
    (void)user;
    (void)principal;
    return false;
}

static bool cb_allow_reprovision_after_failure(void *user,
                                              dmp_sample1_principal principal,
                                              bool has_committed_epoch,
                                              uint64_t committed_epoch,
                                              uint64_t pending_epoch)
{
    (void)user;
    (void)principal;
    (void)has_committed_epoch;
    (void)committed_epoch;
    (void)pending_epoch;
    return true;
}

static bool cb_deny_reprovision_after_failure(void *user,
                                             dmp_sample1_principal principal,
                                             bool has_committed_epoch,
                                             uint64_t committed_epoch,
                                             uint64_t pending_epoch)
{
    (void)user;
    (void)principal;
    (void)has_committed_epoch;
    (void)committed_epoch;
    (void)pending_epoch;
    return false;
}

typedef struct {
    unsigned calls;
    bool return_value;
} counted_provision_cb_state;

static bool cb_counted_provisioning(void *user, dmp_sample1_principal principal)
{
    counted_provision_cb_state *st = (counted_provision_cb_state *)user;
    (void)principal;
    if (st != NULL) {
        st->calls++;
        return st->return_value;
    }
    return false;
}

/* Helper to build a valid format-v1 record into a buffer */
static void build_raw_record_v1(uint8_t out[DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES],
                                uint64_t epoch,
                                uint32_t version,
                                uint32_t namespace_id,
                                uint32_t origin_id)
{
    uint32_t crc = 0U;
    for (size_t i = 0U; i < 8U; i++) {
        out[i] = (uint8_t)((epoch >> (i * 8U)) & 0xFFU);
    }
    out[8] = (uint8_t)(version & 0xFFU);
    out[9] = (uint8_t)((version >> 8) & 0xFFU);
    out[10] = (uint8_t)((version >> 16) & 0xFFU);
    out[11] = (uint8_t)((version >> 24) & 0xFFU);

    out[12] = (uint8_t)(namespace_id & 0xFFU);
    out[13] = (uint8_t)((namespace_id >> 8) & 0xFFU);
    out[14] = (uint8_t)((namespace_id >> 16) & 0xFFU);
    out[15] = (uint8_t)((namespace_id >> 24) & 0xFFU);

    out[16] = (uint8_t)(origin_id & 0xFFU);
    out[17] = (uint8_t)((origin_id >> 8) & 0xFFU);
    out[18] = (uint8_t)((origin_id >> 16) & 0xFFU);
    out[19] = (uint8_t)((origin_id >> 24) & 0xFFU);

    (void)dmp_crc32c((dmp_bytes){ out, 20U }, &crc);
    out[20] = (uint8_t)(crc & 0xFFU);
    out[21] = (uint8_t)((crc >> 8) & 0xFFU);
    out[22] = (uint8_t)((crc >> 16) & 0xFFU);
    out[23] = (uint8_t)((crc >> 24) & 0xFFU);
}

/* --- Tests --- */

static int test_first_provisioning_denied(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));

    /* Case A: Callback explicitly returns false */
    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_deny_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_REJECTED);
    CHECK(has_prev == true);
    CHECK(prev == 0xAAU);
    CHECK(reserved == 0xBBU);
    CHECK(!nvs.has_blob);
    CHECK(!anchor.has_floor);
    CHECK(!anchor.is_pending);
    CHECK(nvs.set_calls == 0U);
    CHECK(nvs.commit_calls == 0U);

    /* Case B: Callback is NULL (missing callback fails closed) */
    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        NULL, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_REJECTED);
    CHECK(has_prev == true);
    CHECK(prev == 0xAAU);
    CHECK(reserved == 0xBBU);
    CHECK(!nvs.has_blob);
    CHECK(!anchor.has_floor);

    return 0;
}

static int test_first_provisioning_allowed(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
    CHECK(has_prev == false);
    CHECK(prev == 0U);
    CHECK(reserved == 1U);
    CHECK(anchor.has_floor == true);
    CHECK(anchor.floor == 1U);
    CHECK(anchor.is_pending == false);
    CHECK(nvs.has_blob);
    CHECK(nvs.blob_len == DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES);
    CHECK(nvs.set_calls == 1U);
    CHECK(nvs.commit_calls == 1U);
    CHECK(anchor.begin_calls == 1U);
    CHECK(anchor.complete_calls == 1U);
    CHECK(strcmp(nvs.key, "s1_epoch") == 0);

    return 0;
}

static int test_sequential_increments_and_reopen(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = false;
    uint64_t prev = 0U;
    uint64_t reserved = 0U;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));

    /* First provisioning */
    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
    CHECK(!has_prev && prev == 0U && reserved == 1U);
    CHECK(anchor.floor == 1U && !anchor.is_pending);

    /* Second reservation: increments from 1 to 2 */
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
    CHECK(has_prev == true && prev == 1U && reserved == 2U);
    CHECK(anchor.floor == 2U && !anchor.is_pending);

    /* Third reservation: increments from 2 to 3 */
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
    CHECK(has_prev == true && prev == 2U && reserved == 3U);
    CHECK(anchor.floor == 3U && !anchor.is_pending);

    /* Reopen: construct brand new store instance on same NVS and anchor backing. */
    {
        dmp_sample1_nvs_epoch_store reopened_store;
        g_mock_nvs = &nvs;
        dmp_sample1_nvs_epoch_store_init(
            &reopened_store, 1U, "s1_epoch",
            NULL, NULL,
            NULL, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        res = dmp_sample1_nvs_reserve_next(&reopened_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true && prev == 3U && reserved == 4U);
        CHECK(anchor.floor == 4U && !anchor.is_pending);

        res = dmp_sample1_nvs_reserve_next(&reopened_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true && prev == 4U && reserved == 5U);
        CHECK(anchor.floor == 5U && !anchor.is_pending);
    }

    return 0;
}

static int test_nvs_get_blob_failure_leaves_pending_state(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));

    /* Start from anchor/NVS epoch 5 */
    build_raw_record_v1(nvs.blob, 5U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION,
                        principal.namespace_id, principal.origin_id);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 5U;
    anchor.is_pending = false;

    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    /* Inject get_blob failure: candidate 6 becomes pending BEFORE read */
    nvs.get_error = -1;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_UNKNOWN);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(anchor.is_pending == true);
    CHECK(anchor.pending_epoch == 6U);
    nvs.get_error = ESP_OK;

    /* Reopen without reprovision authorization: verifies FAILED */
    {
        dmp_sample1_nvs_epoch_store fresh_store;
        dmp_sample1_nvs_epoch_store_init(
            &fresh_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        has_prev = true; prev = 0xAAU; reserved = 0xBBU;
        res = dmp_sample1_nvs_reserve_next(&fresh_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
        CHECK(anchor.is_pending == true);
        CHECK(anchor.pending_epoch == 6U);
    }

    /* Reopen with authorization: verifies ACCEPTED at an epoch greater than 6 */
    {
        dmp_sample1_nvs_epoch_store recovery_store;
        dmp_sample1_nvs_epoch_store_init(
            &recovery_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_allow_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        has_prev = false; prev = 0U; reserved = 0U;
        res = dmp_sample1_nvs_reserve_next(&recovery_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true);
        CHECK(prev == 5U);
        CHECK(reserved == 7U);
        CHECK(reserved > 6U);
        CHECK(anchor.is_pending == false);
        CHECK(anchor.floor == 7U);
    }

    return 0;
}

static int test_fresh_anchor_nvs_failure_leaves_pending_state(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    g_mock_nvs = &nvs;

    /* Part 1: Operational read failure with fresh anchor */
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    nvs.get_error = -1;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_UNKNOWN);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(!anchor.has_floor);
    CHECK(anchor.is_pending == true);
    CHECK(anchor.pending_epoch == 1U);
    nvs.get_error = ESP_OK;

    /* Reopen with no reprovision callback: fails closed while pending epoch 1 remains */
    {
        dmp_sample1_nvs_epoch_store fresh_store;
        dmp_sample1_nvs_epoch_store_init(
            &fresh_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        has_prev = true; prev = 0xAAU; reserved = 0xBBU;
        res = dmp_sample1_nvs_reserve_next(&fresh_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
        CHECK(anchor.is_pending == true);
        CHECK(anchor.pending_epoch == 1U);
    }

    /* Explicit recovery authorization advances past pending epoch 1 and completes epoch 2 */
    {
        dmp_sample1_nvs_epoch_store recovery_store;
        dmp_sample1_nvs_epoch_store_init(
            &recovery_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_allow_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        has_prev = true; prev = 0xAAU; reserved = 0xBBU;
        res = dmp_sample1_nvs_reserve_next(&recovery_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == false);
        CHECK(prev == 0U);
        CHECK(reserved == 2U);
        CHECK(anchor.has_floor == true);
        CHECK(anchor.floor == 2U);
        CHECK(anchor.is_pending == false);
    }

    /* Part 2: Unexpected fresh-state NVS outcome with INVALID_LENGTH latches pending epoch 1 */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    nvs.get_error = ESP_ERR_NVS_INVALID_LENGTH;
    has_prev = true; prev = 0xAAU; reserved = 0xBBU;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(!anchor.has_floor);
    CHECK(anchor.is_pending == true);
    CHECK(anchor.pending_epoch == 1U);
    nvs.get_error = ESP_OK;

    /* Reopen without reprovision callback fails closed */
    {
        dmp_sample1_nvs_epoch_store fresh_store;
        dmp_sample1_nvs_epoch_store_init(
            &fresh_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        res = dmp_sample1_nvs_reserve_next(&fresh_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(anchor.is_pending == true && anchor.pending_epoch == 1U);
    }

    /* Reopen with recovery authorization advances past 1 to 2 */
    {
        dmp_sample1_nvs_epoch_store recovery_store;
        dmp_sample1_nvs_epoch_store_init(
            &recovery_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_allow_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        res = dmp_sample1_nvs_reserve_next(&recovery_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == false && prev == 0U && reserved == 2U);
        CHECK(anchor.has_floor == true && anchor.floor == 2U && !anchor.is_pending);
    }

    /* Part 3: Verify NOT_FOUND + denied callback does NOT mutate anchor (remains clean) */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_deny_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    has_prev = true; prev = 0xAAU; reserved = 0xBBU;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_REJECTED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(!anchor.has_floor);
    CHECK(!anchor.is_pending);

    /* Part 4: An unexpected existing NVS record also latches pending epoch 1. */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    build_raw_record_v1(nvs.blob, 7U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION,
                        principal.namespace_id, principal.origin_id);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    has_prev = true; prev = 0xAAU; reserved = 0xBBU;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(!anchor.has_floor);
    CHECK(anchor.is_pending == true && anchor.pending_epoch == 1U);
    CHECK(nvs.set_calls == 0U && nvs.commit_calls == 0U);

    return 0;
}

static int test_stale_nvs_rollback_rejected(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));

    /* Case A: Valid stale NVS blob has epoch 5, but trusted anchor floor is newer (epoch 10).
     * Candidate 11 is marked pending before NVS read; NVS mismatch fails closed and leaves pending. */
    build_raw_record_v1(nvs.blob, 5U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION,
                        principal.namespace_id, principal.origin_id);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;

    anchor.has_floor = true;
    anchor.floor = 10U;
    anchor.is_pending = false;

    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(anchor.floor == 10U && anchor.is_pending == true && anchor.pending_epoch == 11U);
    CHECK(nvs.set_calls == 0U);

    /* Case B: NVS record epoch 10, but anchor floor is older (epoch 5). Mismatch fails closed. */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    build_raw_record_v1(nvs.blob, 10U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION,
                        principal.namespace_id, principal.origin_id);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 5U;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(anchor.is_pending == true && anchor.pending_epoch == 6U);

    /* Case C: NVS record exists, but anchor has no floor. Fails closed (fresh anchor)
     * and latches candidate epoch 1 as pending so reopen fails closed until authorized reprovision. */
    (void)memset(&anchor, 0, sizeof(anchor));
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(!anchor.has_floor && anchor.is_pending == true && anchor.pending_epoch == 1U);

    /* Case D: NVS blob is missing, but anchor has a committed floor 3.
     * Candidate 4 becomes pending; NVS missing fails closed and leaves pending 4. */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    anchor.has_floor = true;
    anchor.floor = 3U;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(anchor.floor == 3U && anchor.is_pending == true && anchor.pending_epoch == 4U);
    CHECK(!nvs.has_blob);

    return 0;
}

static int test_missing_and_incomplete_anchor_ops(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    g_mock_nvs = &nvs;

    /* Case A: anchor_ops is NULL */
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, NULL, NULL);
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);

    /* Case B: get_status is NULL */
    {
        dmp_sample1_epoch_anchor_ops partial_anchor = {
            .get_status = NULL,
            .begin_reservation = mock_anchor_begin,
            .complete_reservation = mock_anchor_complete,
        };
        dmp_sample1_nvs_epoch_store_init(
            &store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &partial_anchor, &anchor);
        res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    }

    /* Case C: begin_reservation is NULL */
    {
        dmp_sample1_epoch_anchor_ops partial_anchor = {
            .get_status = mock_anchor_get_status,
            .begin_reservation = NULL,
            .complete_reservation = mock_anchor_complete,
        };
        dmp_sample1_nvs_epoch_store_init(
            &store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &partial_anchor, &anchor);
        res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    }

    /* Case D: complete_reservation is NULL */
    {
        dmp_sample1_epoch_anchor_ops partial_anchor = {
            .get_status = mock_anchor_get_status,
            .begin_reservation = mock_anchor_begin,
            .complete_reservation = NULL,
        };
        dmp_sample1_nvs_epoch_store_init(
            &store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &partial_anchor, &anchor);
        res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    }

    /* Case E: A failed status read leaves a durable stop for reopen. */
    build_raw_record_v1(nvs.blob, 5U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION, 1U, 10U);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 5U;
    anchor.is_pending = false;
    anchor.pending_epoch = 0U;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);
    anchor.get_status_error = true;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(anchor.is_pending == true && anchor.pending_epoch == 6U);
    anchor.get_status_error = false;

    {
        dmp_sample1_nvs_epoch_store fresh_store;
        dmp_sample1_nvs_epoch_store_init(
            &fresh_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);
        res = dmp_sample1_nvs_reserve_next(&fresh_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(anchor.is_pending == true && anchor.pending_epoch == 6U);
    }

    {
        dmp_sample1_nvs_epoch_store recovery_store;
        dmp_sample1_nvs_epoch_store_init(
            &recovery_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_allow_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);
        res = dmp_sample1_nvs_reserve_next(&recovery_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true && prev == 5U && reserved == 7U);
        CHECK(anchor.floor == 7U && anchor.is_pending == false);
    }

    /* Case F: A failed begin_reservation also remains fail-closed across reopen. */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    build_raw_record_v1(nvs.blob, 5U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION, 1U, 10U);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 5U;
    has_prev = true;
    prev = 0xAAU;
    reserved = 0xBBU;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);
    anchor.begin_error = true;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(anchor.is_pending == true && anchor.pending_epoch == 6U);
    anchor.begin_error = false;

    {
        dmp_sample1_nvs_epoch_store fresh_store;
        dmp_sample1_nvs_epoch_store_init(
            &fresh_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);
        res = dmp_sample1_nvs_reserve_next(&fresh_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(anchor.is_pending == true && anchor.pending_epoch == 6U);
    }

    {
        dmp_sample1_nvs_epoch_store recovery_store;
        dmp_sample1_nvs_epoch_store_init(
            &recovery_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_allow_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);
        res = dmp_sample1_nvs_reserve_next(&recovery_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true && prev == 5U && reserved == 7U);
        CHECK(anchor.floor == 7U && anchor.is_pending == false);
    }

    return 0;
}

static int test_partial_nvs_ops_rejected(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    counted_provision_cb_state prov_cb_state = { .calls = 0, .return_value = true };
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    g_mock_nvs = &nvs;

    /* Case A: get_blob is NULL. Must be rejected before any provisioning callback! */
    {
        dmp_sample1_nvs_ops partial_ops = {
            .get_blob = NULL,
            .set_blob = mock_set_blob,
            .commit = mock_commit,
        };
        dmp_sample1_nvs_epoch_store_init(
            &store, 1U, "s1_epoch",
            cb_counted_provisioning, &prov_cb_state,
            NULL, NULL,
            &partial_ops, &g_mock_anchor_ops, &anchor);
        res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
        CHECK(prov_cb_state.calls == 0U);
        CHECK(anchor.begin_calls == 0U);
        CHECK(nvs.set_calls == 0U);
    }

    /* Case B: set_blob is NULL */
    {
        dmp_sample1_nvs_ops partial_ops = {
            .get_blob = mock_get_blob,
            .set_blob = NULL,
            .commit = mock_commit,
        };
        dmp_sample1_nvs_epoch_store_init(
            &store, 1U, "s1_epoch",
            cb_counted_provisioning, &prov_cb_state,
            NULL, NULL,
            &partial_ops, &g_mock_anchor_ops, &anchor);
        res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
        CHECK(prov_cb_state.calls == 0U);
    }

    /* Case C: commit is NULL */
    {
        dmp_sample1_nvs_ops partial_ops = {
            .get_blob = mock_get_blob,
            .set_blob = mock_set_blob,
            .commit = NULL,
        };
        dmp_sample1_nvs_epoch_store_init(
            &store, 1U, "s1_epoch",
            cb_counted_provisioning, &prov_cb_state,
            NULL, NULL,
            &partial_ops, &g_mock_anchor_ops, &anchor);
        res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
        CHECK(prov_cb_state.calls == 0U);
    }

    return 0;
}

static int test_failed_commit_and_reopen_fail_stop_and_recovery(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));

    /* Scenario 1: Existing record epoch 5, anchor floor 5.
     * Candidate 6 begins reservation (pending 6). set_blob writes 6. Commit fails!
     * Store must return UNKNOWN, outputs unchanged, anchor remains pending 6. */
    build_raw_record_v1(nvs.blob, 5U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION,
                        principal.namespace_id, principal.origin_id);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 5U;
    anchor.is_pending = false;

    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    nvs.commit_error = -1;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_UNKNOWN);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(anchor.is_pending == true);
    CHECK(anchor.pending_epoch == 6U);
    nvs.commit_error = ESP_OK;

    /* Reopen without reprovision authorization: MUST FAIL CLOSED across restart */
    {
        dmp_sample1_nvs_epoch_store fresh_store;
        dmp_sample1_nvs_epoch_store_init(
            &fresh_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        has_prev = true; prev = 0xAAU; reserved = 0xBBU;
        res = dmp_sample1_nvs_reserve_next(&fresh_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
        CHECK(anchor.is_pending == true);
        CHECK(anchor.pending_epoch == 6U);
    }

    /* Reopen with explicit denial: MUST FAIL CLOSED */
    {
        dmp_sample1_nvs_epoch_store fresh_store;
        dmp_sample1_nvs_epoch_store_init(
            &fresh_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_deny_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        has_prev = true; prev = 0xAAU; reserved = 0xBBU;
        res = dmp_sample1_nvs_reserve_next(&fresh_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
        CHECK(anchor.is_pending == true);
    }

    /* Reopen WITH explicit reprovision authorization:
     * Resumes at a strictly greater epoch (skips pending 6, reserves 7). Never reuses 6! */
    {
        dmp_sample1_nvs_epoch_store recovery_store;
        dmp_sample1_nvs_epoch_store_init(
            &recovery_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_allow_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        has_prev = false; prev = 0U; reserved = 0U;
        res = dmp_sample1_nvs_reserve_next(&recovery_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true);
        CHECK(prev == 5U);
        CHECK(reserved == 7U);
        CHECK(reserved > 6U);
        CHECK(anchor.is_pending == false);
        CHECK(anchor.floor == 7U);

        /* Subsequent reservations proceed normally from 7 to 8 */
        res = dmp_sample1_nvs_reserve_next(&recovery_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true && prev == 7U && reserved == 8U);
        CHECK(anchor.floor == 8U && !anchor.is_pending);
    }

    /* Scenario 2: First provisioning failed commit.
     * Fresh NVS, fresh anchor. Candidate is 1. Anchor marked pending 1.
     * set_blob writes 1 into NVS. Commit fails. */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    nvs.commit_error = -1;
    has_prev = true; prev = 0xAAU; reserved = 0xBBU;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_UNKNOWN);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(anchor.is_pending == true && anchor.pending_epoch == 1U);
    nvs.commit_error = ESP_OK;

    /* Reopen fresh store without reprovision authorization: must fail closed */
    {
        dmp_sample1_nvs_epoch_store fresh_store;
        dmp_sample1_nvs_epoch_store_init(
            &fresh_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        has_prev = true; prev = 0xAAU; reserved = 0xBBU;
        res = dmp_sample1_nvs_reserve_next(&fresh_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    }

    /* Reopen with reprovision authorization: resumes at epoch 2 (never reissues 1!) */
    {
        dmp_sample1_nvs_epoch_store recovery_store;
        dmp_sample1_nvs_epoch_store_init(
            &recovery_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_allow_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        has_prev = true; prev = 0xAAU; reserved = 0xBBU;
        res = dmp_sample1_nvs_reserve_next(&recovery_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == false);
        CHECK(prev == 0U);
        CHECK(reserved == 2U);
        CHECK(reserved > 1U);
        CHECK(anchor.is_pending == false && anchor.floor == 2U);
    }

    /* Scenario 3: Anchor completion failure.
     * Record 10, anchor committed 10. set_blob and commit succeed, but
     * complete_reservation fails. Anchor must remain pending. */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    build_raw_record_v1(nvs.blob, 10U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION,
                        principal.namespace_id, principal.origin_id);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 10U;

    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    anchor.complete_error = true;
    has_prev = true; prev = 0xAAU; reserved = 0xBBU;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_UNKNOWN);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(anchor.is_pending == true && anchor.pending_epoch == 11U);
    anchor.complete_error = false;

    /* Reopen without reprovision auth fails closed */
    {
        dmp_sample1_nvs_epoch_store fresh_store;
        dmp_sample1_nvs_epoch_store_init(
            &fresh_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        res = dmp_sample1_nvs_reserve_next(&fresh_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    }

    /* Reopen with reprovision auth succeeds at 12 (> 11) */
    {
        dmp_sample1_nvs_epoch_store recovery_store;
        dmp_sample1_nvs_epoch_store_init(
            &recovery_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_allow_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        res = dmp_sample1_nvs_reserve_next(&recovery_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true && prev == 10U && reserved == 12U);
        CHECK(anchor.floor == 12U && !anchor.is_pending);
    }

    return 0;
}

static int test_commit_ordering(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    /* Case A: Standard reservation sequence from epoch 5 to 6 */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    build_raw_record_v1(nvs.blob, 5U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION, 1U, 10U);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 5U;
    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    clear_events();
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
    CHECK(strcmp(g_events, "BSCK") == 0); /* Begin -> Set -> Commit -> Complete */

    /* Case B: Commit failure stops before anchor completion */
    nvs.commit_error = -1;
    has_prev = true; prev = 0xAAU; reserved = 0xBBU;
    clear_events();
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_UNKNOWN);
    CHECK(strcmp(g_events, "BSC") == 0); /* 'K' must not be called when commit fails */
    nvs.commit_error = ESP_OK;

    /* Case C: Set failure stops before commit and complete */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    build_raw_record_v1(nvs.blob, 5U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION, 1U, 10U);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 5U;
    nvs.set_error = -1;
    has_prev = true; prev = 0xAAU; reserved = 0xBBU;
    clear_events();
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_UNKNOWN);
    CHECK(strcmp(g_events, "BS") == 0); /* Neither commit nor complete called */
    nvs.set_error = ESP_OK;

    /* Case D: Begin reservation failure stops before any NVS write */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    build_raw_record_v1(nvs.blob, 5U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION, 1U, 10U);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 5U;
    anchor.begin_error = true;
    has_prev = true; prev = 0xAAU; reserved = 0xBBU;
    clear_events();
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(strcmp(g_events, "B") == 0); /* No NVS operations attempted */
    anchor.begin_error = false;

    /* Case E: Recovery reservation ordering */
    clear_events();
    {
        dmp_sample1_nvs_epoch_store rec_store;
        dmp_sample1_nvs_epoch_store_init(
            &rec_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_allow_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        res = dmp_sample1_nvs_reserve_next(&rec_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(strcmp(g_events, "BSCK") == 0);
    }

    return 0;
}

static int test_valid_zero_principals(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    dmp_sample1_principal test_principals[] = {
        { 0U, 0U },
        { 0U, 42U },
        { 42U, 0U },
    };

    for (size_t i = 0U; i < sizeof(test_principals) / sizeof(test_principals[0]); i++) {
        dmp_sample1_principal principal = test_principals[i];
        (void)memset(&nvs, 0, sizeof(nvs));
        (void)memset(&anchor, 0, sizeof(anchor));
        g_mock_nvs = &nvs;

        dmp_sample1_nvs_epoch_store_init(
            &store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        /* First provisioning */
        res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(!has_prev && prev == 0U && reserved == 1U);
        CHECK(anchor.floor == 1U && !anchor.is_pending);

        /* Second reservation: increments to 2 */
        res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true && prev == 1U && reserved == 2U);
        CHECK(anchor.floor == 2U && !anchor.is_pending);
    }

    return 0;
}

static int test_foreign_principal_mismatch(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal provisioned_principal = { 1U, 10U };
    dmp_sample1_principal foreign_origin = { 1U, 20U };
    dmp_sample1_principal foreign_namespace = { 2U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));

    /* Pre-populate NVS and anchor with record for principal { 1, 10 }, epoch = 42 */
    build_raw_record_v1(nvs.blob, 42U, DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION,
                        provisioned_principal.namespace_id, provisioned_principal.origin_id);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 42U;

    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    /* Case A: Origin mismatch */
    res = dmp_sample1_nvs_reserve_next(&store, foreign_origin, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);

    /* Case B: Namespace mismatch */
    (void)memset(&anchor, 0, sizeof(anchor));
    anchor.has_floor = true;
    anchor.floor = 42U;
    res = dmp_sample1_nvs_reserve_next(&store, foreign_namespace, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);

    return 0;
}

static int test_malformed_version_and_checksum_records(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    anchor.has_floor = true;
    anchor.floor = 10U;

    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    /* Case A: Truncated blob (23 bytes) */
    build_raw_record_v1(nvs.blob, 10U, 1U, 1U, 10U);
    nvs.blob_len = 23U;
    nvs.has_blob = true;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);

    /* Case B: Oversized blob (25 bytes) */
    (void)memset(&anchor, 0, sizeof(anchor));
    anchor.has_floor = true;
    anchor.floor = 10U;
    nvs.blob_len = 25U;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);

    /* Case C: Version mismatch (version 2 with valid CRC for version 2) */
    (void)memset(&anchor, 0, sizeof(anchor));
    anchor.has_floor = true;
    anchor.floor = 10U;
    build_raw_record_v1(nvs.blob, 10U, 2U, 1U, 10U);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);

    /* Case D: Checksum error (flip 1 bit in epoch) */
    (void)memset(&anchor, 0, sizeof(anchor));
    anchor.has_floor = true;
    anchor.floor = 10U;
    build_raw_record_v1(nvs.blob, 10U, 1U, 1U, 10U);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.blob[0] ^= 0x01U; /* Corrupt */
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);

    /* Case E: Zero epoch (stored epoch must be nonzero) */
    (void)memset(&anchor, 0, sizeof(anchor));
    anchor.has_floor = true;
    anchor.floor = 0U;
    build_raw_record_v1(nvs.blob, 0U, 1U, 1U, 10U);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);

    return 0;
}

static int test_read_write_failures_with_unchanged_outputs(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));

    /* Pre-populate valid record with epoch 5 */
    build_raw_record_v1(nvs.blob, 5U, 1U, 1U, 10U);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 5U;

    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    /* Case A: Read failure */
    nvs.get_error = -1;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_UNKNOWN);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(nvs.set_calls == 0U);
    CHECK(anchor.is_pending == true && anchor.pending_epoch == 6U);
    nvs.get_error = ESP_OK;

    /* Reopen without reprovision authorization: the pending epoch is a durable stop. */
    {
        dmp_sample1_nvs_epoch_store fresh_store;
        dmp_sample1_nvs_epoch_store_init(
            &fresh_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            NULL, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        res = dmp_sample1_nvs_reserve_next(&fresh_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
        CHECK(anchor.is_pending == true && anchor.pending_epoch == 6U);
    }

    /* Explicit recovery skips the possibly exposed epoch 6 and reserves epoch 7. */
    {
        dmp_sample1_nvs_epoch_store recovery_store;
        dmp_sample1_nvs_epoch_store_init(
            &recovery_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_allow_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        res = dmp_sample1_nvs_reserve_next(&recovery_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true && prev == 5U && reserved == 7U);
        CHECK(anchor.has_floor == true && anchor.floor == 7U);
        CHECK(anchor.is_pending == false);
    }

    /* Case B: Write failure */
    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    build_raw_record_v1(nvs.blob, 5U, 1U, 1U, 10U);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = 5U;
    has_prev = true;
    prev = 0xAAU;
    reserved = 0xBBU;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    nvs.set_error = -1;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_UNKNOWN);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(nvs.commit_calls == 0U);
    CHECK(anchor.is_pending == true && anchor.pending_epoch == 6U);
    nvs.set_error = ESP_OK;

    return 0;
}

static int test_uint64_max_exhaustion(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_principal principal = { 1U, 10U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));

    /* Pre-populate NVS and anchor with UINT64_MAX epoch */
    build_raw_record_v1(nvs.blob, UINT64_MAX, 1U, 1U, 10U);
    nvs.blob_len = DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES;
    nvs.has_blob = true;
    anchor.has_floor = true;
    anchor.floor = UINT64_MAX;

    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_FAILED);
    CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    CHECK(nvs.set_calls == 0U);
    CHECK(nvs.commit_calls == 0U);

    /* Case B: Pending epoch is UINT64_MAX during recovery */
    (void)memset(&anchor, 0, sizeof(anchor));
    anchor.has_floor = true;
    anchor.floor = UINT64_MAX - 1U;
    anchor.is_pending = true;
    anchor.pending_epoch = UINT64_MAX;

    {
        dmp_sample1_nvs_epoch_store rec_store;
        dmp_sample1_nvs_epoch_store_init(
            &rec_store, 1U, "s1_epoch",
            cb_allow_first_provisioning, NULL,
            cb_allow_reprovision_after_failure, NULL,
            &g_mock_ops, &g_mock_anchor_ops, &anchor);

        res = dmp_sample1_nvs_reserve_next(&rec_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);
    }

    return 0;
}

/* Dummy callbacks for testing composition with epoch owner */
static bool dummy_try_enter(void *user)
{
    (void)user;
    return true;
}

static void dummy_leave(void *user)
{
    (void)user;
}

static dmp_sample1_port_result dummy_fence_epoch(void *user, dmp_sample1_principal p, uint64_t old_epoch)
{
    (void)user;
    (void)p;
    (void)old_epoch;
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static dmp_sample1_port_result dummy_activate_epoch(void *user, dmp_sample1_principal p, uint64_t new_epoch)
{
    (void)user;
    (void)p;
    (void)new_epoch;
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static dmp_sample1_port_result dummy_activate_association(void *user, dmp_sample1_principal p, dmp_identity_handle h, uint64_t e)
{
    (void)user;
    (void)p;
    (void)h;
    (void)e;
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static dmp_sample1_port_result dummy_queue_read_result(void *user, dmp_sample1_principal p, dmp_identity_handle a, dmp_reliability_handle rh, dmp_message_key rk, uint32_t s, const uint8_t *pl, size_t l)
{
    (void)user;
    (void)p;
    (void)a;
    (void)rh;
    (void)rk;
    (void)s;
    (void)pl;
    (void)l;
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static dmp_sample1_port_result dummy_publish_telem(void *user, dmp_sample1_principal p, uint64_t e, uint32_t i, const uint8_t pl[DMP_SAMPLE1_TELEM_BYTES])
{
    (void)user;
    (void)p;
    (void)e;
    (void)i;
    (void)pl;
    return DMP_SAMPLE1_PORT_ACCEPTED;
}

static int test_epoch_owner_composition(void)
{
    mock_nvs_state nvs;
    mock_anchor_state anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_epoch_owner owner;
    dmp_sample1_epoch_owner_ports ports;
    dmp_sample1_principal principal = { 1U, 10U };
    dmp_sample1_owner_result o_res;

    (void)memset(&nvs, 0, sizeof(nvs));
    (void)memset(&anchor, 0, sizeof(anchor));
    g_mock_nvs = &nvs;
    dmp_sample1_nvs_epoch_store_init(
        &store, 1U, "s1_epoch",
        cb_allow_first_provisioning, NULL,
        NULL, NULL,
        &g_mock_ops, &g_mock_anchor_ops, &anchor);

    (void)memset(&ports, 0, sizeof(ports));
    ports.user = &store;
    ports.try_enter = dummy_try_enter;
    ports.leave = dummy_leave;
    ports.reserve_next = dmp_sample1_nvs_reserve_next;
    ports.fence_epoch = dummy_fence_epoch;
    ports.activate_epoch = dummy_activate_epoch;
    ports.activate_association = dummy_activate_association;
    ports.queue_read_result = dummy_queue_read_result;
    ports.publish_telem = dummy_publish_telem;

    o_res = dmp_sample1_epoch_owner_init(&owner, principal, &ports);
    CHECK(o_res == DMP_SAMPLE1_OWNER_OK);

    /* Begin first epoch */
    o_res = dmp_sample1_epoch_owner_begin_epoch(&owner, 100U);
    CHECK(o_res == DMP_SAMPLE1_OWNER_OK);
    CHECK(owner.epoch == 1U);
    CHECK(owner.active == true);

    /* Begin second epoch (transition / rollover) */
    o_res = dmp_sample1_epoch_owner_begin_epoch(&owner, 200U);
    CHECK(o_res == DMP_SAMPLE1_OWNER_OK);
    CHECK(owner.epoch == 2U);
    CHECK(owner.active == true);

    return 0;
}

int main(void)
{
    CHECK(test_first_provisioning_denied() == 0);
    CHECK(test_first_provisioning_allowed() == 0);
    CHECK(test_sequential_increments_and_reopen() == 0);
    CHECK(test_nvs_get_blob_failure_leaves_pending_state() == 0);
    CHECK(test_fresh_anchor_nvs_failure_leaves_pending_state() == 0);
    CHECK(test_stale_nvs_rollback_rejected() == 0);
    CHECK(test_missing_and_incomplete_anchor_ops() == 0);
    CHECK(test_partial_nvs_ops_rejected() == 0);
    CHECK(test_failed_commit_and_reopen_fail_stop_and_recovery() == 0);
    CHECK(test_commit_ordering() == 0);
    CHECK(test_valid_zero_principals() == 0);
    CHECK(test_foreign_principal_mismatch() == 0);
    CHECK(test_malformed_version_and_checksum_records() == 0);
    CHECK(test_read_write_failures_with_unchanged_outputs() == 0);
    CHECK(test_uint64_max_exhaustion() == 0);
    CHECK(test_epoch_owner_composition() == 0);

    (void)printf("all sample1_epoch_store tests passed.\n");
    return 0;
}
