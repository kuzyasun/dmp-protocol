#include "sample1_epoch_anchor_nvs.h"

#include <stdio.h>
#include <string.h>

#include "dmp/integrity.h"

#define CHECK(expr)                                                                            \
    do {                                                                                       \
        if (!(expr)) {                                                                         \
            (void)fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return 1;                                                                          \
        }                                                                                      \
    } while (0)

enum {
    MOCK_MAX_ENTRIES = 8U,
    MOCK_MAX_BLOB_SIZE = 64U,
    TEST_ANCHOR_BYTES = 44U,
    TEST_CRC_OFFSET = 40U,
    TEST_VERSION_OFFSET = 4U,
    TEST_FLAGS_OFFSET = 8U,
    TEST_FLOOR_OFFSET = 20U,
    TEST_PENDING_OFFSET = 28U,
    TEST_FLAG_HAS_FLOOR = 1U,
    TEST_FLAG_PENDING = 2U
};

typedef enum {
    MOCK_COMMIT_FAIL_BEFORE_PERSIST = 0,
    MOCK_COMMIT_FAIL_AFTER_PERSIST = 1
} mock_commit_failure_mode;

typedef struct {
    char key[32];
    bool in_use;
    bool has_durable;
    uint8_t durable[MOCK_MAX_BLOB_SIZE];
    size_t durable_len;
    bool has_staged;
    uint8_t staged[MOCK_MAX_BLOB_SIZE];
    size_t staged_len;
} mock_nvs_entry;

typedef struct {
    /* Direct fields for existing standalone anchor tests (corresponds to default "s1_anchor" key) */
    bool has_durable;
    uint8_t durable[MOCK_MAX_BLOB_SIZE];
    size_t durable_len;
    bool has_staged;
    uint8_t staged[MOCK_MAX_BLOB_SIZE];
    size_t staged_len;

    mock_nvs_entry entries[MOCK_MAX_ENTRIES];

    esp_err_t get_error;
    esp_err_t set_error;
    esp_err_t commit_error;
    uint32_t fail_on_commit_index;
    mock_commit_failure_mode commit_failure_mode;
    uint32_t get_calls;
    uint32_t set_calls;
    uint32_t commit_calls;
} mock_nvs_state;

static mock_nvs_state *g_mock;

static mock_nvs_entry *mock_find_entry(mock_nvs_state *mock, const char *key, bool create)
{
    size_t i;
    if (mock == NULL || key == NULL) {
        return NULL;
    }
    for (i = 0U; i < MOCK_MAX_ENTRIES; ++i) {
        if (mock->entries[i].in_use && strcmp(mock->entries[i].key, key) == 0) {
            return &mock->entries[i];
        }
    }
    if (!create) {
        return NULL;
    }
    for (i = 0U; i < MOCK_MAX_ENTRIES; ++i) {
        if (!mock->entries[i].in_use) {
            mock->entries[i].in_use = true;
            (void)strncpy(mock->entries[i].key, key, sizeof(mock->entries[i].key) - 1U);
            mock->entries[i].key[sizeof(mock->entries[i].key) - 1U] = '\0';
            return &mock->entries[i];
        }
    }
    return NULL;
}

static esp_err_t mock_get_blob(nvs_handle_t handle, const char *key, void *out, size_t *length)
{
    mock_nvs_state *mock = g_mock;
    const char *k = (key != NULL) ? key : "s1_anchor";
    (void)handle;
    if (mock == NULL || length == NULL) {
        return -1;
    }
    mock->get_calls++;
    if (mock->get_error != ESP_OK) {
        return mock->get_error;
    }
    if (strcmp(k, "s1_anchor") == 0) {
        if (!mock->has_durable) {
            return ESP_ERR_NVS_NOT_FOUND;
        }
        if (out == NULL) {
            *length = mock->durable_len;
            return ESP_OK;
        }
        if (*length < mock->durable_len) {
            *length = mock->durable_len;
            return ESP_ERR_NVS_INVALID_LENGTH;
        }
        (void)memcpy(out, mock->durable, mock->durable_len);
        *length = mock->durable_len;
        return ESP_OK;
    } else {
        mock_nvs_entry *entry = mock_find_entry(mock, k, false);
        if (entry == NULL || !entry->has_durable) {
            return ESP_ERR_NVS_NOT_FOUND;
        }
        if (out == NULL) {
            *length = entry->durable_len;
            return ESP_OK;
        }
        if (*length < entry->durable_len) {
            *length = entry->durable_len;
            return ESP_ERR_NVS_INVALID_LENGTH;
        }
        (void)memcpy(out, entry->durable, entry->durable_len);
        *length = entry->durable_len;
        return ESP_OK;
    }
}

static esp_err_t mock_set_blob(nvs_handle_t handle, const char *key,
                               const void *value, size_t length)
{
    mock_nvs_state *mock = g_mock;
    const char *k = (key != NULL) ? key : "s1_anchor";
    (void)handle;
    if (mock == NULL || value == NULL) {
        return -1;
    }
    mock->set_calls++;
    if (mock->set_error != ESP_OK) {
        return mock->set_error;
    }
    if (strcmp(k, "s1_anchor") == 0) {
        if (length > sizeof(mock->staged)) {
            return -1;
        }
        (void)memcpy(mock->staged, value, length);
        mock->staged_len = length;
        mock->has_staged = true;
        return ESP_OK;
    } else {
        mock_nvs_entry *entry = mock_find_entry(mock, k, true);
        if (entry == NULL || length > sizeof(entry->staged)) {
            return -1;
        }
        (void)memcpy(entry->staged, value, length);
        entry->staged_len = length;
        entry->has_staged = true;
        return ESP_OK;
    }
}

static void mock_apply_staged_to_durable(mock_nvs_state *mock)
{
    size_t i;
    if (mock->has_staged) {
        (void)memcpy(mock->durable, mock->staged, mock->staged_len);
        mock->durable_len = mock->staged_len;
        mock->has_durable = true;
        mock->has_staged = false;
    }
    for (i = 0U; i < MOCK_MAX_ENTRIES; ++i) {
        if (mock->entries[i].in_use && mock->entries[i].has_staged) {
            (void)memcpy(mock->entries[i].durable, mock->entries[i].staged,
                         mock->entries[i].staged_len);
            mock->entries[i].durable_len = mock->entries[i].staged_len;
            mock->entries[i].has_durable = true;
            mock->entries[i].has_staged = false;
        }
    }
}

static esp_err_t mock_commit(nvs_handle_t handle)
{
    mock_nvs_state *mock = g_mock;
    (void)handle;
    if (mock == NULL) {
        return -1;
    }
    mock->commit_calls++;

    if (mock->fail_on_commit_index > 0U &&
        mock->commit_calls == mock->fail_on_commit_index) {
        esp_err_t err = (mock->commit_error != ESP_OK) ? mock->commit_error : -1;
        if (mock->commit_failure_mode == MOCK_COMMIT_FAIL_AFTER_PERSIST) {
            /* Persist staged data to durable storage before returning error */
            mock_apply_staged_to_durable(mock);
        }
        return err;
    }

    if (mock->commit_error != ESP_OK && mock->fail_on_commit_index == 0U) {
        return mock->commit_error;
    }

    mock_apply_staged_to_durable(mock);
    return ESP_OK;
}

static const dmp_sample1_nvs_ops g_mock_ops = {
    .get_blob = mock_get_blob,
    .set_blob = mock_set_blob,
    .commit = mock_commit
};

static void mock_reboot(mock_nvs_state *mock)
{
    size_t i;
    if (mock == NULL) {
        return;
    }
    mock->has_staged = false;
    mock->staged_len = 0U;
    mock->get_error = ESP_OK;
    mock->set_error = ESP_OK;
    mock->commit_error = ESP_OK;
    mock->fail_on_commit_index = 0U;
    mock->commit_failure_mode = MOCK_COMMIT_FAIL_BEFORE_PERSIST;
    mock->get_calls = 0U;
    mock->set_calls = 0U;
    mock->commit_calls = 0U;
    for (i = 0U; i < MOCK_MAX_ENTRIES; ++i) {
        mock->entries[i].has_staged = false;
        mock->entries[i].staged_len = 0U;
    }
}

static void encode_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value & 0xFFU);
    out[1] = (uint8_t)((value >> 8U) & 0xFFU);
    out[2] = (uint8_t)((value >> 16U) & 0xFFU);
    out[3] = (uint8_t)((value >> 24U) & 0xFFU);
}

static uint32_t decode_u32_le(const uint8_t *in)
{
    return ((uint32_t)in[0]) |
           (((uint32_t)in[1]) << 8U) |
           (((uint32_t)in[2]) << 16U) |
           (((uint32_t)in[3]) << 24U);
}

static void encode_u64_le(uint8_t *out, uint64_t value)
{
    size_t i;
    for (i = 0U; i < 8U; ++i) {
        out[i] = (uint8_t)((value >> (i * 8U)) & 0xFFU);
    }
}

static uint64_t decode_u64_le(const uint8_t *in)
{
    uint64_t value = 0U;
    size_t i;
    for (i = 0U; i < 8U; ++i) {
        value |= ((uint64_t)in[i]) << (i * 8U);
    }
    return value;
}

static void refresh_crc(mock_nvs_state *mock)
{
    uint32_t crc = 0U;
    (void)dmp_crc32c((dmp_bytes){ mock->durable, TEST_CRC_OFFSET }, &crc);
    encode_u32_le(&mock->durable[TEST_CRC_OFFSET], crc);
}

static bool validate_durable_epoch_record(mock_nvs_state *mock,
                                         const char *key,
                                         dmp_sample1_principal expected_principal,
                                         uint64_t expected_epoch)
{
    mock_nvs_entry *entry;
    uint32_t computed_crc = 0U;
    uint32_t stored_crc;
    uint32_t version;
    uint32_t ns;
    uint32_t origin;
    uint64_t epoch;

    if (mock == NULL || key == NULL) {
        return false;
    }
    entry = mock_find_entry(mock, key, false);
    if (entry == NULL || !entry->has_durable ||
        entry->durable_len != DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES) {
        return false;
    }
    if (dmp_crc32c((dmp_bytes){ entry->durable, 20U }, &computed_crc) != DMP_OK) {
        return false;
    }
    stored_crc = decode_u32_le(&entry->durable[20]);
    if (computed_crc != stored_crc) {
        return false;
    }
    epoch = decode_u64_le(&entry->durable[0]);
    version = decode_u32_le(&entry->durable[8]);
    ns = decode_u32_le(&entry->durable[12]);
    origin = decode_u32_le(&entry->durable[16]);

    return (version == DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION &&
            ns == expected_principal.namespace_id &&
            origin == expected_principal.origin_id &&
            epoch == expected_epoch);
}

static dmp_sample1_nvs_epoch_anchor make_anchor(mock_nvs_state *mock)
{
    dmp_sample1_nvs_epoch_anchor anchor;
    g_mock = mock;
    dmp_sample1_nvs_epoch_anchor_init(&anchor, 1U, NULL, &g_mock_ops);
    return anchor;
}

static bool cb_allow_first_provisioning(void *user, dmp_sample1_principal principal)
{
    (void)user;
    (void)principal;
    return true;
}

typedef struct {
    unsigned calls;
    bool allow;
    dmp_sample1_principal last_principal;
    bool last_has_committed;
    uint64_t last_committed_epoch;
    uint64_t last_pending_epoch;
} reprovision_tracker;

static bool cb_reprovision_tracker(void *user,
                                   dmp_sample1_principal principal,
                                   bool has_committed_epoch,
                                   uint64_t committed_epoch,
                                   uint64_t pending_epoch)
{
    reprovision_tracker *t = (reprovision_tracker *)user;
    if (t != NULL) {
        t->calls++;
        t->last_principal = principal;
        t->last_has_committed = has_committed_epoch;
        t->last_committed_epoch = committed_epoch;
        t->last_pending_epoch = pending_epoch;
        return t->allow;
    }
    return false;
}

static int test_normal_progression_and_reopen(void)
{
    mock_nvs_state mock;
    dmp_sample1_nvs_epoch_anchor anchor;
    dmp_sample1_nvs_epoch_anchor reopened;
    dmp_sample1_anchor_status status;
    const dmp_sample1_principal principal = { 7U, 19U };

    (void)memset(&mock, 0, sizeof(mock));
    anchor = make_anchor(&mock);
    (void)memset(&status, 0xA5, sizeof(status));
    CHECK(dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    CHECK(!status.has_floor && status.floor == 0U);
    CHECK(!status.is_pending && status.pending_epoch == 0U);

    CHECK(dmp_sample1_nvs_anchor_ops.begin_reservation(
        &anchor, principal, false, 0U, false, 0U, 1U));
    CHECK(dmp_sample1_nvs_anchor_ops.complete_reservation(&anchor, principal, 1U));
    CHECK(dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    CHECK(status.has_floor && status.floor == 1U && !status.is_pending);

    CHECK(dmp_sample1_nvs_anchor_ops.begin_reservation(
        &anchor, principal, true, 1U, false, 0U, 2U));
    CHECK(dmp_sample1_nvs_anchor_ops.complete_reservation(&anchor, principal, 2U));

    reopened = make_anchor(&mock);
    CHECK(dmp_sample1_nvs_anchor_ops.get_status(&reopened, principal, &status));
    CHECK(status.has_floor && status.floor == 2U);
    CHECK(!status.is_pending && status.pending_epoch == 0U);
    return 0;
}

static int test_recovery_skips_pending_candidate(void)
{
    mock_nvs_state mock;
    dmp_sample1_nvs_epoch_anchor anchor;
    dmp_sample1_nvs_epoch_anchor reopened;
    dmp_sample1_anchor_status status;
    const dmp_sample1_principal principal = { 3U, 5U };

    (void)memset(&mock, 0, sizeof(mock));
    anchor = make_anchor(&mock);
    CHECK(dmp_sample1_nvs_anchor_ops.begin_reservation(
        &anchor, principal, false, 0U, false, 0U, 1U));

    reopened = make_anchor(&mock);
    CHECK(dmp_sample1_nvs_anchor_ops.get_status(&reopened, principal, &status));
    CHECK(status.is_pending && status.pending_epoch == 1U);
    CHECK(!dmp_sample1_nvs_anchor_ops.begin_reservation(
        &reopened, principal, false, 0U, false, 0U, 1U));
    CHECK(dmp_sample1_nvs_anchor_ops.begin_reservation(
        &reopened, principal, false, 0U, true, 1U, 2U));
    CHECK(dmp_sample1_nvs_anchor_ops.complete_reservation(&reopened, principal, 2U));
    CHECK(dmp_sample1_nvs_anchor_ops.get_status(&reopened, principal, &status));
    CHECK(status.has_floor && status.floor == 2U && !status.is_pending);
    return 0;
}

static int test_transition_validation_and_unchanged_status(void)
{
    mock_nvs_state mock;
    dmp_sample1_nvs_epoch_anchor anchor;
    dmp_sample1_anchor_status status;
    dmp_sample1_anchor_status original;
    const dmp_sample1_principal principal = { 7U, 19U };
    const dmp_sample1_principal foreign = { 7U, 20U };

    (void)memset(&mock, 0, sizeof(mock));
    anchor = make_anchor(&mock);
    CHECK(dmp_sample1_nvs_anchor_ops.begin_reservation(
        &anchor, principal, false, 0U, false, 0U, 1U));
    (void)memset(&status, 0x5A, sizeof(status));
    original = status;
    CHECK(!dmp_sample1_nvs_anchor_ops.get_status(&anchor, foreign, &status));
    CHECK(memcmp(&status, &original, sizeof(status)) == 0);

    mock.durable[0] ^= 0x01U;
    (void)memset(&status, 0x5A, sizeof(status));
    original = status;
    CHECK(!dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    CHECK(memcmp(&status, &original, sizeof(status)) == 0);
    mock.durable[0] ^= 0x01U;

    encode_u32_le(&mock.durable[TEST_VERSION_OFFSET], 2U);
    refresh_crc(&mock);
    CHECK(!dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    encode_u32_le(&mock.durable[TEST_VERSION_OFFSET], 1U);
    refresh_crc(&mock);

    encode_u32_le(&mock.durable[TEST_FLAGS_OFFSET], 4U);
    refresh_crc(&mock);
    CHECK(!dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    encode_u32_le(&mock.durable[TEST_FLAGS_OFFSET], TEST_FLAG_PENDING);
    refresh_crc(&mock);

    mock.durable_len = TEST_ANCHOR_BYTES - 1U;
    CHECK(!dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    mock.durable_len = TEST_ANCHOR_BYTES;

    CHECK(dmp_sample1_nvs_anchor_ops.complete_reservation(&anchor, principal, 1U));
    CHECK(dmp_sample1_nvs_anchor_ops.begin_reservation(
        &anchor, principal, true, 1U, false, 0U, 2U));
    encode_u32_le(&mock.durable[TEST_FLAGS_OFFSET], TEST_FLAG_HAS_FLOOR | TEST_FLAG_PENDING);
    encode_u64_le(&mock.durable[TEST_FLOOR_OFFSET], 1U);
    encode_u64_le(&mock.durable[TEST_PENDING_OFFSET], 1U);
    refresh_crc(&mock);
    CHECK(!dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    return 0;
}

static int test_nvs_failures_are_fail_closed(void)
{
    mock_nvs_state mock;
    dmp_sample1_nvs_epoch_anchor anchor;
    dmp_sample1_anchor_status status;
    dmp_sample1_anchor_status original;
    const dmp_sample1_principal principal = { 2U, 4U };

    (void)memset(&mock, 0, sizeof(mock));
    anchor = make_anchor(&mock);
    (void)memset(&status, 0xA5, sizeof(status));
    original = status;
    mock.get_error = -1;
    CHECK(!dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    CHECK(memcmp(&status, &original, sizeof(status)) == 0);
    mock.get_error = ESP_OK;

    mock.set_error = -1;
    CHECK(!dmp_sample1_nvs_anchor_ops.begin_reservation(
        &anchor, principal, false, 0U, false, 0U, 1U));
    CHECK(!mock.has_durable);
    mock.set_error = ESP_OK;

    mock.commit_error = -1;
    CHECK(!dmp_sample1_nvs_anchor_ops.begin_reservation(
        &anchor, principal, false, 0U, false, 0U, 1U));
    CHECK(!mock.has_durable);
    mock.commit_error = ESP_OK;
    CHECK(dmp_sample1_nvs_anchor_ops.begin_reservation(
        &anchor, principal, false, 0U, false, 0U, 1U));

    mock.set_error = -1;
    CHECK(!dmp_sample1_nvs_anchor_ops.complete_reservation(&anchor, principal, 1U));
    mock.set_error = ESP_OK;
    mock.commit_error = -1;
    CHECK(!dmp_sample1_nvs_anchor_ops.complete_reservation(&anchor, principal, 1U));
    mock.commit_error = ESP_OK;
    CHECK(dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    CHECK(status.is_pending && status.pending_epoch == 1U);
    CHECK(!dmp_sample1_nvs_anchor_ops.complete_reservation(&anchor, principal, 2U));
    CHECK(dmp_sample1_nvs_anchor_ops.complete_reservation(&anchor, principal, 1U));
    return 0;
}

static int test_composition_reservation_and_reopen(void)
{
    mock_nvs_state mock;
    dmp_sample1_nvs_epoch_anchor anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_nvs_epoch_anchor reopened_anchor;
    dmp_sample1_nvs_epoch_store reopened_store;
    dmp_sample1_anchor_status status;
    const dmp_sample1_principal principal = { 11U, 22U };
    bool has_prev = true;
    uint64_t prev = 0xAAU;
    uint64_t reserved = 0xBBU;
    dmp_sample1_port_result res;

    (void)memset(&mock, 0, sizeof(mock));
    g_mock = &mock;

    dmp_sample1_nvs_epoch_anchor_init(&anchor, 1U, "s1_anchor", &g_mock_ops);
    dmp_sample1_nvs_epoch_store_init(&store, 1U, "s1_epoch",
                                     cb_allow_first_provisioning, NULL,
                                     NULL, NULL,
                                     &g_mock_ops,
                                     &dmp_sample1_nvs_anchor_ops, &anchor);

    /* First reservation on clean unprovisioned store + anchor */
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
    CHECK(has_prev == false);
    CHECK(prev == 0U);
    CHECK(reserved == 1U);

    CHECK(dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    CHECK(status.has_floor == true && status.floor == 1U && !status.is_pending);
    CHECK(validate_durable_epoch_record(&mock, "s1_epoch", principal, 1U));

    /* Subsequent reservation: increments to 2 */
    has_prev = false; prev = 0U; reserved = 0U;
    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
    CHECK(has_prev == true);
    CHECK(prev == 1U);
    CHECK(reserved == 2U);

    CHECK(dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    CHECK(status.has_floor == true && status.floor == 2U && !status.is_pending);
    CHECK(validate_durable_epoch_record(&mock, "s1_epoch", principal, 2U));

    /* Reopen with fresh instances over the same persistent mock */
    mock_reboot(&mock);
    dmp_sample1_nvs_epoch_anchor_init(&reopened_anchor, 1U, "s1_anchor", &g_mock_ops);
    dmp_sample1_nvs_epoch_store_init(&reopened_store, 1U, "s1_epoch",
                                     NULL, NULL,
                                     NULL, NULL,
                                     &g_mock_ops,
                                     &dmp_sample1_nvs_anchor_ops, &reopened_anchor);

    has_prev = false; prev = 0U; reserved = 0U;
    res = dmp_sample1_nvs_reserve_next(&reopened_store, principal, &has_prev, &prev, &reserved);
    CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
    CHECK(has_prev == true);
    CHECK(prev == 2U);
    CHECK(reserved == 3U);

    CHECK(dmp_sample1_nvs_anchor_ops.get_status(&reopened_anchor, principal, &status));
    CHECK(status.has_floor == true && status.floor == 3U && !status.is_pending);
    CHECK(validate_durable_epoch_record(&mock, "s1_epoch", principal, 3U));

    return 0;
}

/* --- Shared scenario runner for commit failure persistence phases --- */

typedef enum {
    /* Before #1: anchor stayed clean floor 1; unauthenticated reopen advances to epoch 2 */
    REOPEN_CLEAN_ADVANCES_TO_EPOCH_2,

    /* Before #2/#3 and After #1/#2: anchor is pending 2;
     * unauthenticated reopen fails closed; authorized recovery skips to epoch 3 with previous 1 */
    REOPEN_PENDING_REQUIRES_RECOVERY_TO_EPOCH_3,

    /* After #3: completed anchor persisted at floor 2; unauthenticated reopen advances to epoch 3 with previous 2 */
    REOPEN_DURABLE_ADVANCES_TO_EPOCH_3
} expected_reopen_outcome;

static int run_commit_failure_scenario(dmp_sample1_principal principal,
                                       uint32_t commit_phase,
                                       mock_commit_failure_mode failure_mode,
                                       uint64_t expected_durable_epoch,
                                       expected_reopen_outcome expected_outcome)
{
    mock_nvs_state mock;
    dmp_sample1_nvs_epoch_anchor anchor;
    dmp_sample1_nvs_epoch_store store;
    dmp_sample1_nvs_epoch_anchor reopened_anchor;
    dmp_sample1_nvs_epoch_store reopened_store;
    dmp_sample1_anchor_status status;
    bool has_prev;
    uint64_t prev;
    uint64_t reserved;
    dmp_sample1_port_result res;
    dmp_sample1_port_result expected_failure =
        (commit_phase == 1U) ? DMP_SAMPLE1_PORT_FAILED : DMP_SAMPLE1_PORT_UNKNOWN;

    (void)memset(&mock, 0, sizeof(mock));
    g_mock = &mock;

    dmp_sample1_nvs_epoch_anchor_init(&anchor, 1U, "s1_anchor", &g_mock_ops);
    dmp_sample1_nvs_epoch_store_init(&store, 1U, "s1_epoch",
                                     cb_allow_first_provisioning, NULL,
                                     NULL, NULL,
                                     &g_mock_ops,
                                     &dmp_sample1_nvs_anchor_ops, &anchor);

    /* First reservation establishes floor 1 */
    has_prev = true; prev = 0xAAU; reserved = 0xBBU;
    CHECK(dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved) ==
          DMP_SAMPLE1_PORT_ACCEPTED);
    CHECK(has_prev == false && prev == 0U && reserved == 1U);

    /* Inject commit failure at commit_phase with the specified persistence mode */
    mock.commit_calls = 0U;
    mock.fail_on_commit_index = commit_phase;
    mock.commit_failure_mode = failure_mode;
    has_prev = true;
    prev = 0xAAU;
    reserved = 0xBBU;

    res = dmp_sample1_nvs_reserve_next(&store, principal, &has_prev, &prev, &reserved);
    CHECK(res == expected_failure);
    /* Public outputs must remain unchanged on failure */
    CHECK(has_prev == true);
    CHECK(prev == 0xAAU);
    CHECK(reserved == 0xBBU);

    /* Durable anchor checks before reboot */
    CHECK(dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    if (expected_outcome == REOPEN_CLEAN_ADVANCES_TO_EPOCH_2) {
        CHECK(status.has_floor == true && status.floor == 1U && !status.is_pending);
    } else if (expected_outcome == REOPEN_PENDING_REQUIRES_RECOVERY_TO_EPOCH_3) {
        CHECK(status.has_floor == true && status.floor == 1U);
        CHECK(status.is_pending == true && status.pending_epoch == 2U);
    } else { /* REOPEN_DURABLE_ADVANCES_TO_EPOCH_3 */
        CHECK(status.has_floor == true && status.floor == 2U && !status.is_pending);
    }

    /* Durable epoch blob checks before reboot: assert exact record length, format, and epoch */
    CHECK(validate_durable_epoch_record(&mock, "s1_epoch", principal, expected_durable_epoch));

    /* Simulate reboot / restart: unpersisted staged data discarded */
    mock_reboot(&mock);
    dmp_sample1_nvs_epoch_anchor_init(&reopened_anchor, 1U, "s1_anchor", &g_mock_ops);

    if (expected_outcome == REOPEN_CLEAN_ADVANCES_TO_EPOCH_2) {
        /* Unauthenticated reopen cleanly reserves next epoch 2 */
        dmp_sample1_nvs_epoch_store_init(&reopened_store, 1U, "s1_epoch",
                                         NULL, NULL,
                                         NULL, NULL,
                                         &g_mock_ops,
                                         &dmp_sample1_nvs_anchor_ops, &reopened_anchor);
        has_prev = false; prev = 0U; reserved = 0U;
        res = dmp_sample1_nvs_reserve_next(&reopened_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true && prev == 1U && reserved == 2U);
        CHECK(dmp_sample1_nvs_anchor_ops.get_status(&reopened_anchor, principal, &status));
        CHECK(status.has_floor == true && status.floor == 2U && !status.is_pending);
        CHECK(validate_durable_epoch_record(&mock, "s1_epoch", principal, 2U));
    } else if (expected_outcome == REOPEN_DURABLE_ADVANCES_TO_EPOCH_3) {
        /* Completed anchor floor 2 is durable; unauthenticated reopen reserves 3 with previous 2 */
        dmp_sample1_nvs_epoch_store_init(&reopened_store, 1U, "s1_epoch",
                                         NULL, NULL,
                                         NULL, NULL,
                                         &g_mock_ops,
                                         &dmp_sample1_nvs_anchor_ops, &reopened_anchor);
        has_prev = false; prev = 0U; reserved = 0U;
        res = dmp_sample1_nvs_reserve_next(&reopened_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_prev == true && prev == 2U && reserved == 3U);
        CHECK(dmp_sample1_nvs_anchor_ops.get_status(&reopened_anchor, principal, &status));
        CHECK(status.has_floor == true && status.floor == 3U && !status.is_pending);
        CHECK(validate_durable_epoch_record(&mock, "s1_epoch", principal, 3U));
    } else {
        /* Pending epoch 2 is durable:
         * 1) Unauthenticated reopen MUST fail closed and keep outputs unchanged */
        reprovision_tracker tracker;
        dmp_sample1_nvs_epoch_store_init(&reopened_store, 1U, "s1_epoch",
                                         NULL, NULL,
                                         NULL, NULL,
                                         &g_mock_ops,
                                         &dmp_sample1_nvs_anchor_ops, &reopened_anchor);
        has_prev = true; prev = 0xAAU; reserved = 0xBBU;
        res = dmp_sample1_nvs_reserve_next(&reopened_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_FAILED);
        CHECK(has_prev == true && prev == 0xAAU && reserved == 0xBBU);

        /* 2) Explicit authorized recovery skips pending epoch 2 and reserves 3 */
        (void)memset(&tracker, 0, sizeof(tracker));
        tracker.allow = true;
        dmp_sample1_nvs_epoch_store_init(&reopened_store, 1U, "s1_epoch",
                                         NULL, NULL,
                                         cb_reprovision_tracker, &tracker,
                                         &g_mock_ops,
                                         &dmp_sample1_nvs_anchor_ops, &reopened_anchor);
        has_prev = false; prev = 0U; reserved = 0U;
        res = dmp_sample1_nvs_reserve_next(&reopened_store, principal, &has_prev, &prev, &reserved);
        CHECK(res == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(tracker.calls == 1U);
        CHECK(tracker.last_has_committed == true);
        CHECK(tracker.last_committed_epoch == 1U);
        CHECK(tracker.last_pending_epoch == 2U);
        CHECK(has_prev == true && prev == 1U && reserved == 3U);
        CHECK(dmp_sample1_nvs_anchor_ops.get_status(&reopened_anchor, principal, &status));
        CHECK(status.has_floor == true && status.floor == 3U && !status.is_pending);
        CHECK(validate_durable_epoch_record(&mock, "s1_epoch", principal, 3U));
    }

    return 0;
}

static int test_composition_commit_failure_scenarios(void)
{
    static const struct {
        dmp_sample1_principal principal;
        uint32_t commit_phase;
        mock_commit_failure_mode failure_mode;
        uint64_t expected_durable_epoch;
        expected_reopen_outcome outcome;
    } scenarios[] = {
        /* Phase #1: Pending anchor commit */
        { { 15U, 30U }, 1U, MOCK_COMMIT_FAIL_BEFORE_PERSIST, 1U, REOPEN_CLEAN_ADVANCES_TO_EPOCH_2 },
        { { 21U, 42U }, 1U, MOCK_COMMIT_FAIL_AFTER_PERSIST,  1U, REOPEN_PENDING_REQUIRES_RECOVERY_TO_EPOCH_3 },

        /* Phase #2: Epoch record commit */
        { { 17U, 34U }, 2U, MOCK_COMMIT_FAIL_BEFORE_PERSIST, 1U, REOPEN_PENDING_REQUIRES_RECOVERY_TO_EPOCH_3 },
        { { 23U, 46U }, 2U, MOCK_COMMIT_FAIL_AFTER_PERSIST,  2U, REOPEN_PENDING_REQUIRES_RECOVERY_TO_EPOCH_3 },

        /* Phase #3: Completed anchor commit */
        { { 19U, 38U }, 3U, MOCK_COMMIT_FAIL_BEFORE_PERSIST, 2U, REOPEN_PENDING_REQUIRES_RECOVERY_TO_EPOCH_3 },
        { { 25U, 50U }, 3U, MOCK_COMMIT_FAIL_AFTER_PERSIST,  2U, REOPEN_DURABLE_ADVANCES_TO_EPOCH_3 }
    };
    size_t i;
    for (i = 0U; i < sizeof(scenarios) / sizeof(scenarios[0]); ++i) {
        CHECK(run_commit_failure_scenario(scenarios[i].principal,
                                          scenarios[i].commit_phase,
                                          scenarios[i].failure_mode,
                                          scenarios[i].expected_durable_epoch,
                                          scenarios[i].outcome) == 0);
    }
    return 0;
}

int main(void)
{
    CHECK(test_normal_progression_and_reopen() == 0);
    CHECK(test_recovery_skips_pending_candidate() == 0);
    CHECK(test_transition_validation_and_unchanged_status() == 0);
    CHECK(test_nvs_failures_are_fail_closed() == 0);
    CHECK(test_composition_reservation_and_reopen() == 0);
    CHECK(test_composition_commit_failure_scenarios() == 0);
    (void)printf("all sample1_epoch_anchor_nvs tests passed.\n");
    return 0;
}
