#ifndef DMP_FUZZ_LIMITS_H
#define DMP_FUZZ_LIMITS_H

/* Fixed admission bounds for the structural/framing fuzz callbacks.
 * These are harness quotas, not a profile, an MTU, or an acceptance claim.
 * Stream R storage matches dmp_stream_encoded_bound: COBS(max_core + 4)
 * plus the delimiter, which is (max_core + 4) + (max_core + 4) / 254 + 2. */

#define DMP_FUZZ_MAX_INPUT 256u
#define DMP_FUZZ_MAX_EXTENSIONS 128u
#define DMP_FUZZ_MAX_FEED_STEPS 256u

#define DMP_FUZZ_CORE_MAX_MESSAGE 128u
#define DMP_FUZZ_CORE_MAX_FRAGMENTS 8u

#define DMP_FUZZ_STREAM_MAX_CORE 128u
#define DMP_FUZZ_STREAM_TIMEOUT_MS 10u
#define DMP_FUZZ_STREAM_INIT_NOW 0u
#define DMP_FUZZ_STREAM_FEED_NOW 1u
#define DMP_FUZZ_STREAM_STORAGE                         \
    (DMP_FUZZ_STREAM_MAX_CORE + 4u +                    \
     (DMP_FUZZ_STREAM_MAX_CORE + 4u) / 254u + 2u)

_Static_assert(DMP_FUZZ_MAX_INPUT >= 2u, "parser needs a two-byte header floor");
_Static_assert(DMP_FUZZ_MAX_FEED_STEPS == DMP_FUZZ_MAX_INPUT,
               "one feed pull per admitted input byte");
_Static_assert(DMP_FUZZ_CORE_MAX_FRAGMENTS >= 2u,
               "dmp_core_parse rejects max_fragments below 2");
_Static_assert(DMP_FUZZ_CORE_MAX_MESSAGE > 0u, "message budget must be positive");
_Static_assert(DMP_FUZZ_CORE_MAX_MESSAGE <= DMP_FUZZ_MAX_INPUT,
               "message budget fits the admitted frame");
_Static_assert(DMP_FUZZ_STREAM_MAX_CORE >= 2u, "stream init rejects a smaller core");
_Static_assert(DMP_FUZZ_STREAM_TIMEOUT_MS > 0u, "stream init rejects a zero timeout");
_Static_assert(DMP_FUZZ_STREAM_FEED_NOW > DMP_FUZZ_STREAM_INIT_NOW,
               "feed time stays monotonic");
_Static_assert(DMP_FUZZ_STREAM_FEED_NOW + DMP_FUZZ_STREAM_TIMEOUT_MS >
                   DMP_FUZZ_STREAM_FEED_NOW,
               "poll time stays monotonic");
_Static_assert(DMP_FUZZ_STREAM_STORAGE >= DMP_FUZZ_STREAM_MAX_CORE,
               "L decoder storage is max_core bytes");

#endif
