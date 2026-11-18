#ifndef DMP_PRIVATE_EXTENSION_VALUES_H
#define DMP_PRIVATE_EXTENSION_VALUES_H

#include "dmp/base.h"

typedef struct {
    uint32_t namespace_id, origin_id;
    uint64_t epoch;
    uint32_t seq;
} dmp_reply_to_value;

/* Decode one complete, backed TLV value. The caller owns tag and role checks.
 * A NULL result is validation-only. An optional error offset is relative to
 * the value and is changed only on failure. Results are published on success. */
bool dmp_decode_extension_u32(dmp_bytes value, uint32_t *out, size_t *error);
bool dmp_decode_extension_context(dmp_bytes value, uint32_t *namespace_id,
                                  uint64_t *epoch, size_t *error);
bool dmp_decode_extension_reply_to(dmp_bytes value, bool compact,
                                   dmp_reply_to_value *out, size_t *error);

#endif
