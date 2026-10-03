#ifndef DMP_HARNESS_MANIFEST_H
#define DMP_HARNESS_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

/* Executable manifest-v2 boundary. Codes and paths match the published contract. */

#define MANIFEST_MAX_BYTES 262144U

typedef struct manifest_view {
    int borrow;
    int synchronous_completion;
    uint32_t encoded_mtu;
    uint32_t frame_tx_ms;
    uint32_t forward_delay_ms;
    uint32_t return_delay_ms;
    uint32_t period_ms;
    uint32_t width_ms;
    uint32_t queue_ms;
    uint32_t adapter_slots;
    char sha256[65];
} manifest_view;

typedef struct manifest_failure {
    char code[32];
    char path[192];
} manifest_failure;

/* 0 valid, 1 contract failure, -1 unreadable schema or internal limit. */
int manifest_validate(const uint8_t *bytes, size_t length, const char *expected_sha256,
                      const char *schema_path, manifest_view *view,
                      manifest_failure *failure);

#endif
