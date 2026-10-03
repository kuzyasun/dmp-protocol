#ifndef DMP_HARNESS_SHA256_H
#define DMP_HARNESS_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* Compact SHA-256 of the exact input bytes. out receives 32 raw bytes. */
void harness_sha256(const uint8_t *data, size_t length, uint8_t out[32]);

/* Lowercase hex, 64 characters, no terminator written beyond out[64]. */
void harness_sha256_hex(const uint8_t *data, size_t length, char out[65]);

#endif
