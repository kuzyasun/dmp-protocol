#ifndef DMP_PRIVATE_COBS_H
#define DMP_PRIVATE_COBS_H

#include "dmp/base.h"

/* Private helpers shared with tests through the archive implementation. */
dmp_status dmp_cobs_encoded_bound(size_t input_size, size_t *out);
dmp_status dmp_cobs_encode(dmp_bytes input, dmp_buffer output, size_t *written);
dmp_status dmp_cobs_encode_parts(dmp_bytes first, dmp_bytes second,
                                 dmp_buffer output, size_t *written);
dmp_status dmp_cobs_decode_canonical(uint8_t *candidate, size_t candidate_size,
                                     size_t capacity, size_t *decoded_size);

#endif
