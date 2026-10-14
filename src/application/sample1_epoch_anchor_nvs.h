#ifndef DMP_APPLICATION_SAMPLE1_EPOCH_ANCHOR_NVS_H
#define DMP_APPLICATION_SAMPLE1_EPOCH_ANCHOR_NVS_H

#include "sample1_epoch_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NVS-backed implementation of dmp_sample1_epoch_anchor_ops.
 * The anchor is an integrity-checked record in ordinary NVS. This detects
 * damaged or inconsistent records and supports normal restart recovery, but
 * cannot detect restoring a complete older flash/NVS image. A rollback-resistant
 * adapter must keep its monotonic high-water mark outside restorable flash,
 * bind it to the producer principal, preserve pending reservations across reset,
 * and fail closed on loss or exhaustion. A qualified secure-element counter is
 * one possible implementation; no eFuse implementation is provided. */
typedef struct {
    nvs_handle_t nvs_handle;
    const char *key;
    const dmp_sample1_nvs_ops *ops;
} dmp_sample1_nvs_epoch_anchor;

/* Initialize an NVS anchor. A NULL key selects "s1_anchor". If ops is NULL,
 * ESP_PLATFORM builds call nvs_get_blob/nvs_set_blob/nvs_commit directly;
 * host builds must provide all three operations for deterministic tests. */
void dmp_sample1_nvs_epoch_anchor_init(dmp_sample1_nvs_epoch_anchor *anchor,
                                       nvs_handle_t nvs_handle,
                                       const char *key,
                                       const dmp_sample1_nvs_ops *ops);

/* Pass this operations table and the initialized anchor to the SAMPLE-1 epoch
 * store. Calls must be serialized by the application epoch owner's gate. */
extern const dmp_sample1_epoch_anchor_ops dmp_sample1_nvs_anchor_ops;

#ifdef __cplusplus
}
#endif

#endif
