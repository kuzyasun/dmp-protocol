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
    TEST_ANCHOR_BYTES = 44U,
    TEST_BLOB_BYTES = 64U,
    TEST_KEY_ANCHOR = 0U,
    TEST_KEY_EPOCH = 1U,
    TEST_KEY_COUNT = 2U,
    TEST_CRC_OFFSET = 40U,
    TEST_VERSION_OFFSET = 4U,
    TEST_FLAGS_OFFSET = 8U,
    TEST_FLOOR_OFFSET = 20U,
    TEST_PENDING_OFFSET = 28U,
    TEST_FLAG_HAS_FLOOR = 1U,
    TEST_FLAG_PENDING = 2U
};

typedef struct {
    bool has_durable[TEST_KEY_COUNT];
    uint8_t durable[TEST_KEY_COUNT][TEST_BLOB_BYTES];
    size_t durable_len[TEST_KEY_COUNT];
    bool has_staged[TEST_KEY_COUNT];
    uint8_t staged[TEST_KEY_COUNT][TEST_BLOB_BYTES];
    size_t staged_len[TEST_KEY_COUNT];
    esp_err_t get_error;
    esp_err_t set_error;
    esp_err_t commit_error;
    uint32_t fail_commit_call;
    uint32_t get_calls;
    uint32_t set_calls;
    uint32_t commit_calls;
} mock_nvs_state;

static mock_nvs_state *g_mock;

static int mock_key_index(const char *key)
{
    if (key == NULL) {
        return -1;
    }
    if (strcmp(key, "s1_anchor") == 0) {
        return TEST_KEY_ANCHOR;
    }
    if (strcmp(key, "s1_epoch") == 0) {
        return TEST_KEY_EPOCH;
    }
    return -1;
}

static esp_err_t mock_get_blob(nvs_handle_t handle, const char *key, void *out, size_t *length)
{
    mock_nvs_state *mock = g_mock;
    int index = mock_key_index(key);
    (void)handle;
    if (mock == NULL || length == NULL || index < 0) {
        return -1;
    }
    mock->get_calls++;
    if (mock->get_error != ESP_OK) {
        return mock->get_error;
    }
    if (!mock->has_durable[index]) {
        return ESP_ERR_NVS_NOT_FOUND;
    }
    if (out == NULL || *length < mock->durable_len[index]) {
        *length = mock->durable_len[index];
        return ESP_ERR_NVS_INVALID_LENGTH;
    }
    (void)memcpy(out, mock->durable[index], mock->durable_len[index]);
    *length = mock->durable_len[index];
    return ESP_OK;
}

static esp_err_t mock_set_blob(nvs_handle_t handle, const char *key,
                               const void *value, size_t length)
{
    mock_nvs_state *mock = g_mock;
    int index = mock_key_index(key);
    (void)handle;
    if (mock == NULL || value == NULL || index < 0 || length > TEST_BLOB_BYTES) {
        return -1;
    }
    mock->set_calls++;
    if (mock->set_error != ESP_OK) {
        return mock->set_error;
    }
    (void)memcpy(mock->staged[index], value, length);
    mock->staged_len[index] = length;
    mock->has_staged[index] = true;
    return ESP_OK;
}

static esp_err_t mock_commit(nvs_handle_t handle)
{
    mock_nvs_state *mock = g_mock;
    (void)handle;
    if (mock == NULL) {
        return -1;
    }
    mock->commit_calls++;
    if (mock->commit_error != ESP_OK) {
        return mock->commit_error;
    }
    if (mock->fail_commit_call != 0U && mock->commit_calls == mock->fail_commit_call) {
        return -1;
    }
    for (size_t i = 0U; i < TEST_KEY_COUNT; ++i) {
        if (mock->has_staged[i]) {
            (void)memcpy(mock->durable[i], mock->staged[i], mock->staged_len[i]);
            mock->durable_len[i] = mock->staged_len[i];
            mock->has_durable[i] = true;
            mock->has_staged[i] = false;
        }
    }
    return ESP_OK;
}

static const dmp_sample1_nvs_ops g_mock_ops = {
    .get_blob = mock_get_blob,
    .set_blob = mock_set_blob,
    .commit = mock_commit
};

static void encode_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value & 0xFFU);
    out[1] = (uint8_t)((value >> 8U) & 0xFFU);
    out[2] = (uint8_t)((value >> 16U) & 0xFFU);
    out[3] = (uint8_t)((value >> 24U) & 0xFFU);
}

static void encode_u64_le(uint8_t *out, uint64_t value)
{
    size_t i;
    for (i = 0U; i < 8U; ++i) {
        out[i] = (uint8_t)((value >> (i * 8U)) & 0xFFU);
    }
}

static void refresh_crc(mock_nvs_state *mock)
{
    uint32_t crc = 0U;
    (void)dmp_crc32c((dmp_bytes){ mock->durable[TEST_KEY_ANCHOR], TEST_CRC_OFFSET }, &crc);
    encode_u32_le(&mock->durable[TEST_KEY_ANCHOR][TEST_CRC_OFFSET], crc);
}

static dmp_sample1_nvs_epoch_anchor make_anchor(mock_nvs_state *mock)
{
    dmp_sample1_nvs_epoch_anchor anchor;
    g_mock = mock;
    dmp_sample1_nvs_epoch_anchor_init(&anchor, 1U, NULL, &g_mock_ops);
    return anchor;
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

    mock.durable[TEST_KEY_ANCHOR][0] ^= 0x01U;
    (void)memset(&status, 0x5A, sizeof(status));
    original = status;
    CHECK(!dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    CHECK(memcmp(&status, &original, sizeof(status)) == 0);
    mock.durable[TEST_KEY_ANCHOR][0] ^= 0x01U;

    encode_u32_le(&mock.durable[TEST_KEY_ANCHOR][TEST_VERSION_OFFSET], 2U);
    refresh_crc(&mock);
    CHECK(!dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    encode_u32_le(&mock.durable[TEST_KEY_ANCHOR][TEST_VERSION_OFFSET], 1U);
    refresh_crc(&mock);

    encode_u32_le(&mock.durable[TEST_KEY_ANCHOR][TEST_FLAGS_OFFSET], 4U);
    refresh_crc(&mock);
    CHECK(!dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    encode_u32_le(&mock.durable[TEST_KEY_ANCHOR][TEST_FLAGS_OFFSET], TEST_FLAG_PENDING);
    refresh_crc(&mock);

    mock.durable_len[TEST_KEY_ANCHOR] = TEST_ANCHOR_BYTES - 1U;
    CHECK(!dmp_sample1_nvs_anchor_ops.get_status(&anchor, principal, &status));
    mock.durable_len[TEST_KEY_ANCHOR] = TEST_ANCHOR_BYTES;

    CHECK(dmp_sample1_nvs_anchor_ops.complete_reservation(&anchor, principal, 1U));
    CHECK(dmp_sample1_nvs_anchor_ops.begin_reservation(
        &anchor, principal, true, 1U, false, 0U, 2U));
    encode_u32_le(&mock.durable[TEST_KEY_ANCHOR][TEST_FLAGS_OFFSET],
                  TEST_FLAG_HAS_FLOOR | TEST_FLAG_PENDING);
    encode_u64_le(&mock.durable[TEST_KEY_ANCHOR][TEST_FLOOR_OFFSET], 1U);
    encode_u64_le(&mock.durable[TEST_KEY_ANCHOR][TEST_PENDING_OFFSET], 1U);
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
    CHECK(!mock.has_durable[TEST_KEY_ANCHOR]);
    mock.set_error = ESP_OK;

    mock.commit_error = -1;
    CHECK(!dmp_sample1_nvs_anchor_ops.begin_reservation(
        &anchor, principal, false, 0U, false, 0U, 1U));
    CHECK(!mock.has_durable[TEST_KEY_ANCHOR]);
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

static bool allow_first_provisioning(void *user, dmp_sample1_principal principal)
{
    (void)user;
    (void)principal;
    return true;
}

static bool allow_reprovision_after_failure(void *user,
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

static void init_composed_store(dmp_sample1_nvs_epoch_store *store,
                                dmp_sample1_nvs_epoch_anchor *anchor)
{
    dmp_sample1_nvs_epoch_store_init(store,
                                     1U,
                                     "s1_epoch",
                                     allow_first_provisioning,
                                     NULL,
                                     allow_reprovision_after_failure,
                                     NULL,
                                     &g_mock_ops,
                                     &dmp_sample1_nvs_anchor_ops,
                                     anchor);
}

static int test_store_anchor_composition_and_commit_failures(void)
{
    const dmp_sample1_principal principal = { 31U, 47U };
    mock_nvs_state mock;
    dmp_sample1_nvs_epoch_anchor anchor;
    dmp_sample1_nvs_epoch_store store;
    bool has_previous = false;
    uint64_t previous = 0U;
    uint64_t reserved = 0U;

    (void)memset(&mock, 0, sizeof(mock));
    anchor = make_anchor(&mock);
    init_composed_store(&store, &anchor);
    CHECK(dmp_sample1_nvs_reserve_next(&store, principal, &has_previous, &previous, &reserved) ==
          DMP_SAMPLE1_PORT_ACCEPTED);
    CHECK(!has_previous && previous == 0U && reserved == 1U);
    CHECK(dmp_sample1_nvs_reserve_next(&store, principal, &has_previous, &previous, &reserved) ==
          DMP_SAMPLE1_PORT_ACCEPTED);
    CHECK(has_previous && previous == 1U && reserved == 2U);

    {
        dmp_sample1_nvs_epoch_anchor reopened_anchor = make_anchor(&mock);
        dmp_sample1_nvs_epoch_store reopened_store;
        init_composed_store(&reopened_store, &reopened_anchor);
        CHECK(dmp_sample1_nvs_reserve_next(&reopened_store,
                                            principal,
                                            &has_previous,
                                            &previous,
                                            &reserved) == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_previous && previous == 2U && reserved == 3U);
    }

    for (uint32_t failed_phase = 1U; failed_phase <= 3U; ++failed_phase) {
        dmp_sample1_anchor_status status;
        dmp_sample1_nvs_epoch_anchor reopened_anchor;
        dmp_sample1_nvs_epoch_store reopened_store;
        dmp_sample1_port_result result;

        (void)memset(&mock, 0, sizeof(mock));
        anchor = make_anchor(&mock);
        init_composed_store(&store, &anchor);
        has_previous = false;
        previous = 0U;
        reserved = 0U;
        CHECK(dmp_sample1_nvs_reserve_next(&store,
                                            principal,
                                            &has_previous,
                                            &previous,
                                            &reserved) == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(reserved == 1U);

        has_previous = true;
        previous = UINT64_C(0xA5A5A5A5A5A5A5A5);
        reserved = UINT64_C(0x5A5A5A5A5A5A5A5A);
        mock.fail_commit_call = mock.commit_calls + failed_phase;
        result = dmp_sample1_nvs_reserve_next(&store,
                                              principal,
                                              &has_previous,
                                              &previous,
                                              &reserved);
        CHECK(result == ((failed_phase == 1U) ? DMP_SAMPLE1_PORT_FAILED
                                               : DMP_SAMPLE1_PORT_UNKNOWN));
        CHECK(has_previous);
        CHECK(previous == UINT64_C(0xA5A5A5A5A5A5A5A5));
        CHECK(reserved == UINT64_C(0x5A5A5A5A5A5A5A5A));

        mock.fail_commit_call = 0U;
        reopened_anchor = make_anchor(&mock);
        init_composed_store(&reopened_store, &reopened_anchor);
        CHECK(dmp_sample1_nvs_reserve_next(&reopened_store,
                                            principal,
                                            &has_previous,
                                            &previous,
                                            &reserved) == DMP_SAMPLE1_PORT_ACCEPTED);
        CHECK(has_previous && previous == 1U);
        CHECK(reserved == ((failed_phase == 1U) ? 2U : 3U));
        CHECK(dmp_sample1_nvs_anchor_ops.get_status(&reopened_anchor, principal, &status));
        CHECK(status.has_floor && status.floor == reserved && !status.is_pending);
    }

    return 0;
}

int main(void)
{
    CHECK(test_normal_progression_and_reopen() == 0);
    CHECK(test_recovery_skips_pending_candidate() == 0);
    CHECK(test_transition_validation_and_unchanged_status() == 0);
    CHECK(test_nvs_failures_are_fail_closed() == 0);
    CHECK(test_store_anchor_composition_and_commit_failures() == 0);
    (void)printf("all sample1_epoch_anchor_nvs tests passed.\n");
    return 0;
}
