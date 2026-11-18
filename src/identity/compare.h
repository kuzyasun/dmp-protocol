#ifndef DMP_PRIVATE_IDENTITY_COMPARE_H
#define DMP_PRIVATE_IDENTITY_COMPARE_H

#include "dmp/identity.h"

static inline bool dmp_peer_handle_equal(dmp_peer_handle a, dmp_peer_handle b)
{
    return a.slot == b.slot && a.generation == b.generation;
}

static inline bool dmp_identity_handle_equal(dmp_identity_handle a, dmp_identity_handle b)
{
    return a.slot == b.slot && a.generation == b.generation;
}

static inline bool dmp_message_origin_equal(dmp_message_origin a, dmp_message_origin b)
{
    return a.namespace_id == b.namespace_id && a.origin_id == b.origin_id && a.epoch == b.epoch;
}

static inline bool dmp_message_key_equal(dmp_message_key a, dmp_message_key b)
{
    return a.seq == b.seq && dmp_message_origin_equal(a.origin, b.origin);
}

#endif
