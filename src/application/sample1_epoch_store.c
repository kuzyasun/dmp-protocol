#include "sample1_epoch_store.h"

#include <string.h>

#include "dmp/integrity.h"

/* Static assertion ensuring zero struct padding in the format-v1 record */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(dmp_sample1_epoch_record_v1) == DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES,
               "dmp_sample1_epoch_record_v1 must have zero padding and exactly 24 bytes");
#endif

static void encode_u32_le(uint8_t *p, uint32_t val)
{
    p[0] = (uint8_t)(val & 0xFFU);
    p[1] = (uint8_t)((val >> 8) & 0xFFU);
    p[2] = (uint8_t)((val >> 16) & 0xFFU);
    p[3] = (uint8_t)((val >> 24) & 0xFFU);
}

static uint32_t decode_u32_le(const uint8_t *p)
{
    return ((uint32_t)p[0]) |
           (((uint32_t)p[1]) << 8) |
           (((uint32_t)p[2]) << 16) |
           (((uint32_t)p[3]) << 24);
}

static void encode_u64_le(uint8_t *p, uint64_t val)
{
    for (size_t i = 0U; i < 8U; i++) {
        p[i] = (uint8_t)((val >> (i * 8U)) & 0xFFU);
    }
}

static uint64_t decode_u64_le(const uint8_t *p)
{
    uint64_t val = 0U;
    for (size_t i = 0U; i < 8U; i++) {
        val |= ((uint64_t)p[i]) << (i * 8U);
    }
    return val;
}

static void serialize_record_v1(uint8_t out[DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES],
                                uint64_t epoch,
                                uint32_t namespace_id,
                                uint32_t origin_id)
{
    uint32_t crc = 0U;
    encode_u64_le(&out[0], epoch);
    encode_u32_le(&out[8], DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION);
    encode_u32_le(&out[12], namespace_id);
    encode_u32_le(&out[16], origin_id);
    (void)dmp_crc32c((dmp_bytes){ out, 20U }, &crc);
    encode_u32_le(&out[20], crc);
}

static bool deserialize_and_validate_v1(const uint8_t in[DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES],
                                        dmp_sample1_principal expected_principal,
                                        uint64_t *out_epoch)
{
    uint32_t computed_crc = 0U;
    uint32_t stored_crc;
    uint32_t version;
    uint32_t ns;
    uint32_t orig;
    uint64_t epoch;

    if (dmp_crc32c((dmp_bytes){ in, 20U }, &computed_crc) != DMP_OK) {
        return false;
    }
    stored_crc = decode_u32_le(&in[20]);
    if (computed_crc != stored_crc) {
        return false;
    }

    epoch = decode_u64_le(&in[0]);
    version = decode_u32_le(&in[8]);
    ns = decode_u32_le(&in[12]);
    orig = decode_u32_le(&in[16]);

    if (version != DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION) {
        return false;
    }
    if (ns != expected_principal.namespace_id || orig != expected_principal.origin_id) {
        return false;
    }
    if (epoch == 0U) {
        return false;
    }

    *out_epoch = epoch;
    return true;
}

static esp_err_t do_get_blob(const dmp_sample1_nvs_epoch_store *store,
                             const char *key,
                             void *out_value,
                             size_t *length)
{
    if (store->ops != NULL) {
        return store->ops->get_blob(store->nvs_handle, key, out_value, length);
    }
#if defined(ESP_PLATFORM)
    return nvs_get_blob(store->nvs_handle, key, out_value, length);
#else
    return -1;
#endif
}

static esp_err_t do_set_blob(const dmp_sample1_nvs_epoch_store *store,
                             const char *key,
                             const void *value,
                             size_t length)
{
    if (store->ops != NULL) {
        return store->ops->set_blob(store->nvs_handle, key, value, length);
    }
#if defined(ESP_PLATFORM)
    return nvs_set_blob(store->nvs_handle, key, value, length);
#else
    (void)key;
    (void)value;
    (void)length;
    return -1;
#endif
}

static esp_err_t do_commit(const dmp_sample1_nvs_epoch_store *store)
{
    if (store->ops != NULL) {
        return store->ops->commit(store->nvs_handle);
    }
#if defined(ESP_PLATFORM)
    return nvs_commit(store->nvs_handle);
#else
    return -1;
#endif
}

void dmp_sample1_nvs_epoch_store_init(
    dmp_sample1_nvs_epoch_store *store,
    nvs_handle_t nvs_handle,
    const char *key,
    dmp_sample1_first_provision_cb allow_first_provisioning,
    void *provision_user,
    dmp_sample1_reprovision_cb allow_reprovision_after_failure,
    void *reprovision_user,
    const dmp_sample1_nvs_ops *ops,
    const dmp_sample1_epoch_anchor_ops *anchor_ops,
    void *anchor_user)
{
    if (store == NULL) {
        return;
    }
    store->nvs_handle = nvs_handle;
    store->key = (key != NULL) ? key : "s1_epoch";
    store->allow_first_provisioning = allow_first_provisioning;
    store->provision_user = provision_user;
    store->allow_reprovision_after_failure = allow_reprovision_after_failure;
    store->reprovision_user = reprovision_user;
    store->ops = ops;
    store->anchor_ops = anchor_ops;
    store->anchor_user = anchor_user;
}

dmp_sample1_port_result dmp_sample1_nvs_reserve_next(
    void *user,
    dmp_sample1_principal principal,
    bool *has_previous,
    uint64_t *previous_epoch,
    uint64_t *reserved_epoch)
{
    dmp_sample1_nvs_epoch_store *store = (dmp_sample1_nvs_epoch_store *)user;
    const char *key;
    uint8_t read_buf[64];
    size_t length = sizeof(read_buf);
    esp_err_t err;
    bool is_first = false;
    uint64_t prev_epoch = 0U;
    uint64_t next_epoch = 0U;
    uint8_t write_buf[DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES];
    dmp_sample1_anchor_status anchor_status;

    /* Validate output parameter pointers */
    if (store == NULL || has_previous == NULL || previous_epoch == NULL || reserved_epoch == NULL) {
        return DMP_SAMPLE1_PORT_FAILED;
    }

    /* Epoch-anchor operations are required to gate every reservation. */
    if (store->anchor_ops == NULL ||
        store->anchor_ops->get_status == NULL ||
        store->anchor_ops->begin_reservation == NULL ||
        store->anchor_ops->complete_reservation == NULL) {
        return DMP_SAMPLE1_PORT_FAILED;
    }

    /* Reject partial NVS ops table before any provisioning callback or write */
    if (store->ops != NULL) {
        if (store->ops->get_blob == NULL ||
            store->ops->set_blob == NULL ||
            store->ops->commit == NULL) {
            return DMP_SAMPLE1_PORT_FAILED;
        }
    }
#if !defined(ESP_PLATFORM)
    else {
        return DMP_SAMPLE1_PORT_FAILED;
    }
#endif

    /* Read durable status from anchor */
    (void)memset(&anchor_status, 0, sizeof(anchor_status));
    if (!store->anchor_ops->get_status(store->anchor_user, principal, &anchor_status)) {
        return DMP_SAMPLE1_PORT_FAILED;
    }

    key = (store->key != NULL) ? store->key : "s1_epoch";

    if (anchor_status.is_pending) {
        /* A previous reservation was interrupted or failed before completion.
         * Fails closed across restarts unless explicitly authorized by reprovision callback. */
        if (store->allow_reprovision_after_failure == NULL ||
            !store->allow_reprovision_after_failure(store->reprovision_user,
                                                    principal,
                                                    anchor_status.has_floor,
                                                    anchor_status.floor,
                                                    anchor_status.pending_epoch)) {
            return DMP_SAMPLE1_PORT_FAILED;
        }

        if (anchor_status.pending_epoch == UINT64_MAX) {
            return DMP_SAMPLE1_PORT_FAILED;
        }

        /* Skip the possibly exposed pending epoch and reserve a strictly greater epoch */
        next_epoch = anchor_status.pending_epoch + 1U;
        if (anchor_status.has_floor) {
            is_first = false;
            prev_epoch = anchor_status.floor;
        } else {
            is_first = true;
            prev_epoch = 0U;
        }

        /* Begin recovery reservation in anchor */
        if (!store->anchor_ops->begin_reservation(store->anchor_user,
                                                  principal,
                                                  anchor_status.has_floor,
                                                  anchor_status.floor,
                                                  true,
                                                  anchor_status.pending_epoch,
                                                  next_epoch)) {
            return DMP_SAMPLE1_PORT_FAILED;
        }
    } else if (anchor_status.has_floor) {
        /* Clean anchor with an existing committed floor N.
         * Durably mark candidate N+1 as pending in the anchor BEFORE attempting to read NVS.
         * Any subsequent NVS read error, missing/corrupt record, or mismatch
         * leaves the pending marker intact, requiring explicit reprovision authorization on reopen. */
        if (anchor_status.floor == UINT64_MAX) {
            return DMP_SAMPLE1_PORT_FAILED;
        }

        next_epoch = anchor_status.floor + 1U;
        prev_epoch = anchor_status.floor;
        is_first = false;

        if (!store->anchor_ops->begin_reservation(store->anchor_user,
                                                  principal,
                                                  true,
                                                  anchor_status.floor,
                                                  false,
                                                  0U,
                                                  next_epoch)) {
            return DMP_SAMPLE1_PORT_FAILED;
        }

        /* Now inspect NVS blob */
        err = do_get_blob(store, key, read_buf, &length);
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            /* Record missing while anchor has floor: fail closed (pending marker remains) */
            return DMP_SAMPLE1_PORT_FAILED;
        } else if (err == ESP_ERR_NVS_INVALID_LENGTH) {
            /* Record length invalid: fail closed (pending marker remains) */
            return DMP_SAMPLE1_PORT_FAILED;
        } else if (err != ESP_OK) {
            /* Read error from NVS (e.g. flash I/O failure): fail unknown (pending marker remains) */
            return DMP_SAMPLE1_PORT_UNKNOWN;
        }

        /* Record exists: validate size, CRC, version, principal, and non-zero epoch */
        if (length != DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES) {
            return DMP_SAMPLE1_PORT_FAILED;
        }
        {
            uint64_t nvs_epoch = 0U;
            if (!deserialize_and_validate_v1(read_buf, principal, &nvs_epoch)) {
                return DMP_SAMPLE1_PORT_FAILED;
            }
            /* Anchor committed floor must exactly match the NVS record epoch */
            if (anchor_status.floor != nvs_epoch) {
                return DMP_SAMPLE1_PORT_FAILED;
            }
        }
    } else {
        /* Clean anchor without floor (fresh unprovisioned anchor).
         * Preserve first provisioning semantics: inspect NVS first. */
        err = do_get_blob(store, key, read_buf, &length);
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            /* Missing record: authorized first provisioning required */
            if (store->allow_first_provisioning == NULL ||
                !store->allow_first_provisioning(store->provision_user, principal)) {
                return DMP_SAMPLE1_PORT_REJECTED;
            }
            is_first = true;
            prev_epoch = 0U;
            next_epoch = 1U;

            /* Atomically mark candidate epoch 1 as pending before writing NVS */
            if (!store->anchor_ops->begin_reservation(store->anchor_user,
                                                      principal,
                                                      false,
                                                      0U,
                                                      false,
                                                      0U,
                                                      next_epoch)) {
                return DMP_SAMPLE1_PORT_FAILED;
            }
        } else {
            /* Unexpected fresh-state NVS outcome (operational read error, invalid length,
             * or unexpected existing NVS record while anchor has no floor).
             * Latch candidate epoch 1 as pending so the store fails closed on reopen
             * until explicitly authorized reprovisioning prevents reuse of epoch 1. */
            (void)store->anchor_ops->begin_reservation(store->anchor_user,
                                                       principal,
                                                       false,
                                                       0U,
                                                       false,
                                                       0U,
                                                       1U);
            if (err == ESP_ERR_NVS_INVALID_LENGTH || err == ESP_OK) {
                return DMP_SAMPLE1_PORT_FAILED;
            }
            return DMP_SAMPLE1_PORT_UNKNOWN;
        }
    }

    serialize_record_v1(write_buf, next_epoch, principal.namespace_id, principal.origin_id);

    err = do_set_blob(store, key, write_buf, sizeof(write_buf));
    if (err != ESP_OK) {
        return DMP_SAMPLE1_PORT_UNKNOWN;
    }

    err = do_commit(store);
    if (err != ESP_OK) {
        return DMP_SAMPLE1_PORT_UNKNOWN;
    }

    /* Complete reservation and clear pending state only after set_blob AND commit succeed */
    if (!store->anchor_ops->complete_reservation(store->anchor_user, principal, next_epoch)) {
        return DMP_SAMPLE1_PORT_UNKNOWN;
    }

    /* Update output parameters only after durable anchor completion succeeds */
    *has_previous = !is_first;
    *previous_epoch = prev_epoch;
    *reserved_epoch = next_epoch;
    return DMP_SAMPLE1_PORT_ACCEPTED;
}
