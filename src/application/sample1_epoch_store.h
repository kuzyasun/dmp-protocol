#ifndef DMP_APPLICATION_SAMPLE1_EPOCH_STORE_H
#define DMP_APPLICATION_SAMPLE1_EPOCH_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sample1_epoch_owner.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(ESP_PLATFORM)
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include "nvs.h"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#else
/* Native test / host platform definitions matching ESP-IDF NVS */
typedef uint32_t nvs_handle_t;
typedef int32_t esp_err_t;

#ifndef ESP_OK
#define ESP_OK 0
#endif

#ifndef ESP_ERR_NVS_BASE
#define ESP_ERR_NVS_BASE 0x1100
#endif

#ifndef ESP_ERR_NVS_NOT_FOUND
#define ESP_ERR_NVS_NOT_FOUND (ESP_ERR_NVS_BASE + 0x02)
#endif

#ifndef ESP_ERR_NVS_INVALID_LENGTH
#define ESP_ERR_NVS_INVALID_LENGTH (ESP_ERR_NVS_BASE + 0x0d)
#endif
#endif

enum {
    DMP_SAMPLE1_EPOCH_RECORD_V1_VERSION = 1U,
    DMP_SAMPLE1_EPOCH_RECORD_V1_BYTES = 24U
};

/* Format-v1 record layout (24 bytes, zero padding):
 * Offset  0..7:  uint64_t epoch (little-endian)
 * Offset  8..11: uint32_t version (little-endian, must be 1U)
 * Offset 12..15: uint32_t namespace_id (little-endian)
 * Offset 16..19: uint32_t origin_id (little-endian)
 * Offset 20..23: uint32_t crc32c (little-endian CRC32C over bytes 0..19)
 */
typedef struct {
    uint64_t epoch;
    uint32_t version;
    uint32_t namespace_id;
    uint32_t origin_id;
    uint32_t crc32c;
} dmp_sample1_epoch_record_v1;

/* Callback to explicitly authorize first provisioning when NVS key and anchor are absent.
 * Missing/corrupt/foreign-principal records fail closed unless authorized here. */
typedef bool (*dmp_sample1_first_provision_cb)(void *user,
                                               dmp_sample1_principal principal);

/* Callback to explicitly authorize reprovisioning/recovery after storage failure.
 * When the anchor has a durable pending-reservation state from an interrupted or
 * failed reservation, reopen fails closed by default. Only when authorized here
 * may the store skip the possibly exposed pending epoch and reserve a strictly
 * greater epoch. The pending epoch is never reused. */
typedef bool (*dmp_sample1_reprovision_cb)(void *user,
                                           dmp_sample1_principal principal,
                                           bool has_committed_epoch,
                                           uint64_t committed_epoch,
                                           uint64_t pending_epoch);

/* Durable status of the trusted monotonic anchor port. */
typedef struct {
    bool has_floor;         /* True if a committed monotonic floor exists */
    uint64_t floor;         /* Committed monotonic floor value */
    bool is_pending;        /* True if an uncommitted reservation is pending */
    uint64_t pending_epoch; /* Candidate epoch currently marked pending */
} dmp_sample1_anchor_status;

/* Injected trusted monotonic epoch-anchor operations table.
 * Used to detect rollback, guarantee freshness independently of NVS CRC,
 * and maintain fail-stop durability across restarts. */
typedef struct {
    /* Read durable status for principal.
     * On success, return true and populate *status.
     * On any operational failure, return false only after durably preserving an
     * existing pending reservation or latching a pending/fault state that a later
     * successful get_status reports as pending. This must also hold when the
     * status read itself fails; otherwise a later reopen could silently continue. */
    bool (*get_status)(void *user,
                       dmp_sample1_principal principal,
                       dmp_sample1_anchor_status *status);

    /* Atomically transition anchor to pending candidate_epoch in durable storage.
     * If is_recovery is false:
     *   - Anchor must not be pending (is_pending == false).
     *   - has_expected_floor must match anchor's has_floor.
     *   - If has_expected_floor is true, anchor's floor must equal expected_floor.
     * If is_recovery is true:
     *   - Anchor must be pending (is_pending == true).
     *   - Anchor's pending_epoch must equal expected_pending.
     *   - candidate_epoch must be strictly greater than expected_pending.
     * Return true when candidate_epoch is durably marked pending. On mismatch or
     * operational failure, return false only after preserving an existing pending
     * reservation or durably latching a pending/fault state for later reopens. */
    bool (*begin_reservation)(void *user,
                              dmp_sample1_principal principal,
                              bool has_expected_floor,
                              uint64_t expected_floor,
                              bool is_recovery,
                              uint64_t expected_pending,
                              uint64_t candidate_epoch);

    /* Atomically clear pending flag and advance committed floor to committed_epoch.
     * Called only after NVS set_blob AND commit succeed.
     * Returning true means durable state is complete and protected independently
     * from NVS rollback.
     * Returning false MUST leave the same durable pending reservation intact
     * (or otherwise durably faulted) so subsequent reopens fail closed and require
     * explicit reprovision authorization; it must never revert to the prior
     * committed floor as clean. */
    bool (*complete_reservation)(void *user,
                                 dmp_sample1_principal principal,
                                 uint64_t committed_epoch);
} dmp_sample1_epoch_anchor_ops;

/* Optional injected NVS operations table (for host testing / dependency injection).
 * If ops is provided, all function pointers (get_blob, set_blob, commit) must be non-NULL.
 * On ESP_PLATFORM, if ops is NULL, the store calls standard nvs_get_blob, nvs_set_blob, nvs_commit. */
typedef struct {
    esp_err_t (*get_blob)(nvs_handle_t handle, const char *key, void *out_value, size_t *length);
    esp_err_t (*set_blob)(nvs_handle_t handle, const char *key, const void *value, size_t length);
    esp_err_t (*commit)(nvs_handle_t handle);
} dmp_sample1_nvs_ops;

typedef struct {
    nvs_handle_t nvs_handle;
    const char *key;
    dmp_sample1_first_provision_cb allow_first_provisioning;
    void *provision_user;
    dmp_sample1_reprovision_cb allow_reprovision_after_failure;
    void *reprovision_user;
    const dmp_sample1_nvs_ops *ops;
    const dmp_sample1_epoch_anchor_ops *anchor_ops;
    void *anchor_user;
} dmp_sample1_nvs_epoch_store;

/* Initialize an NVS epoch store adapter.
 * If key is NULL, defaults to "s1_epoch".
 * anchor_ops must be non-NULL and have get_status, begin_reservation, complete_reservation.
 * If ops is NULL, uses real/linked nvs_get_blob, nvs_set_blob, nvs_commit (ESP_PLATFORM only). */
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
    void *anchor_user);

/* Compatible with sample1_endpoint_hooks.reserve_next and
 * dmp_sample1_epoch_owner_ports.reserve_next.
 * Atomically reserves and durably commits the next never-reused epoch. */
dmp_sample1_port_result dmp_sample1_nvs_reserve_next(
    void *user,
    dmp_sample1_principal principal,
    bool *has_previous,
    uint64_t *previous_epoch,
    uint64_t *reserved_epoch);

#ifdef __cplusplus
}
#endif

#endif
