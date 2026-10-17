#ifndef DMP_QUAL_HANDSHAKE_FRAME_H
#define DMP_QUAL_HANDSHAKE_FRAME_H

#include "dmp/core.h"

typedef enum dmp_qual_handshake_frame_kind {
    DMP_QUAL_FRAME_OTHER = 0,
    DMP_QUAL_FRAME_BOOTSTRAP,
    DMP_QUAL_FRAME_PROTECTED_HELLO
} dmp_qual_handshake_frame_kind;

typedef struct dmp_qual_bootstrap_context {
    uint32_t namespace_id;
    uint32_t origin_id;
    uint64_t provisional_epoch;
} dmp_qual_bootstrap_context;

dmp_qual_handshake_frame_kind dmp_qual_classify_handshake_frame(
    const dmp_frame_view *view);
dmp_status dmp_qual_parse_bootstrap_context(const dmp_frame_view *view,
                                             dmp_qual_bootstrap_context *context);

#endif
