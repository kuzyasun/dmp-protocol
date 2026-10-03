#ifndef DMP_FUZZ_STREAM_H
#define DMP_FUZZ_STREAM_H

#include <stddef.h>
#include <stdint.h>

/* Framing-only decode of one admitted byte string. The same bytes are applied
 * to a fresh Stream L session and a fresh Stream R session. Returns 0.
 * A frame event is framing integrity only, never core or endpoint acceptance. */
int dmp_fuzz_stream(const uint8_t *data, size_t size);

/* Harness sink incremented only when the callback reaches libdmp. */
uint32_t dmp_fuzz_stream_observations(void);

#endif
