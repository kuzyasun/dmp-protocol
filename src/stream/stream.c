#include "dmp/stream.h"

#include "cobs.h"
#include "dmp/integrity.h"

#include <stdint.h>
#include <string.h>

enum {
    PHASE_L_MAGIC = 1,
    PHASE_L_LENGTH = 2,
    PHASE_L_BODY = 3,
    PHASE_R_SYNC = 4,
    PHASE_R_READY = 5,
    PHASE_R_DISCARD = 6
};

static bool ranges_overlap(const void *left, size_t left_size,
                           const void *right, size_t right_size)
{
    uintptr_t a, b;

    if (left_size == 0U || right_size == 0U || left == NULL || right == NULL) {
        return false;
    }
    a = (uintptr_t)left;
    b = (uintptr_t)right;
    if (left_size > UINTPTR_MAX - a || right_size > UINTPTR_MAX - b) {
        return true;
    }
    return a < b + right_size && b < a + left_size;
}

static bool valid_bytes(dmp_bytes bytes)
{
    return bytes.data != NULL || bytes.size == 0U;
}

static bool valid_buffer(dmp_buffer buffer)
{
    return buffer.data != NULL || buffer.capacity == 0U;
}

static bool decoder_initialized(const dmp_stream_decoder *decoder)
{
    if (decoder == NULL || !valid_buffer(decoder->storage) ||
        decoder->config.partial_timeout_ms == 0U ||
        decoder->config.max_core_bytes < 2U) {
        return false;
    }
    if (decoder->config.mode == DMP_STREAM_L) {
        return decoder->phase == PHASE_L_MAGIC ||
               decoder->phase == PHASE_L_LENGTH ||
               decoder->phase == PHASE_L_BODY;
    }
    if (decoder->config.mode == DMP_STREAM_R) {
        return decoder->phase == PHASE_R_SYNC ||
               decoder->phase == PHASE_R_READY ||
               decoder->phase == PHASE_R_DISCARD;
    }
    return false;
}

dmp_status dmp_stream_encoded_bound(dmp_stream_mode mode, size_t core_size,
                                    size_t *out)
{
    size_t wire_size, bound;
    dmp_status status;

    if (out == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    if (mode == DMP_STREAM_R) {
        if (core_size > SIZE_MAX - 4U) {
            return DMP_LIMIT_EXHAUSTED;
        }
        wire_size = core_size + 4U;
        status = dmp_cobs_encoded_bound(wire_size, &bound);
        if (status != DMP_OK) {
            return status;
        }
        if (bound == SIZE_MAX) {
            return DMP_LIMIT_EXHAUSTED;
        }
        *out = bound + 1U; /* delimiter */
        return DMP_OK;
    }
    if (mode != DMP_STREAM_L) {
        return DMP_INVALID_ARGUMENT;
    }
    /* DMP magic plus the largest ULEB32 length plus the core frame. */
    if (core_size > SIZE_MAX - 8U) {
        return DMP_LIMIT_EXHAUSTED;
    }
    *out = core_size + 8U;
    return DMP_OK;
}

static size_t uleb32_size(uint32_t value)
{
    size_t size = 1U;
    while (value >= 0x80U) {
        value >>= 7U;
        ++size;
    }
    return size;
}

dmp_status dmp_stream_encode(dmp_stream_mode mode, dmp_bytes core,
                             dmp_buffer output, size_t *written)
{
    size_t required, length_size, index, cobs_size;
    uint32_t crc;
    uint8_t trailer[4];
    dmp_status status;

    if (written != NULL &&
        !ranges_overlap(written, sizeof *written, core.data, core.size) &&
        !ranges_overlap(written, sizeof *written, output.data, output.capacity)) {
        *written = 0U;
    }
    if (written == NULL || !valid_bytes(core) || !valid_buffer(output)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (ranges_overlap(written, sizeof *written, core.data, core.size) ||
        ranges_overlap(written, sizeof *written, output.data, output.capacity) ||
        ranges_overlap(core.data, core.size, output.data, output.capacity)) {
        return DMP_INVALID_ARGUMENT;
    }
    *written = 0U;
    if (core.size < 2U) {
        return DMP_INVALID_ARGUMENT;
    }

    if (mode == DMP_STREAM_L) {
        if (core.size > UINT32_MAX) {
            return DMP_LIMIT_EXHAUSTED;
        }
        length_size = uleb32_size((uint32_t)core.size);
        if (core.size > SIZE_MAX - 3U - length_size) {
            return DMP_LIMIT_EXHAUSTED;
        }
        required = 3U + length_size + core.size;
        if (required > output.capacity) {
            return DMP_QUOTA_EXHAUSTED;
        }
        output.data[0] = 0x44U;
        output.data[1] = 0x4DU;
        output.data[2] = 0x50U;
        index = 3U;
        {
            uint32_t remaining = (uint32_t)core.size;
            while (remaining >= 0x80U) {
                output.data[index++] = (uint8_t)(remaining | 0x80U);
                remaining >>= 7U;
            }
            output.data[index++] = (uint8_t)remaining;
        }
        memcpy(output.data + index, core.data, core.size);
        *written = required;
        return DMP_OK;
    }
    if (mode != DMP_STREAM_R) {
        return DMP_INVALID_ARGUMENT;
    }
    if (core.size > SIZE_MAX - 4U) {
        return DMP_LIMIT_EXHAUSTED;
    }
    status = dmp_stream_encoded_bound(mode, core.size, &required);
    if (status != DMP_OK) {
        return status;
    }
    if (required > output.capacity) {
        return DMP_QUOTA_EXHAUSTED;
    }
    status = dmp_crc32c(core, &crc);
    if (status != DMP_OK) {
        return status;
    }
    trailer[0] = (uint8_t)crc;
    trailer[1] = (uint8_t)(crc >> 8U);
    trailer[2] = (uint8_t)(crc >> 16U);
    trailer[3] = (uint8_t)(crc >> 24U);
    status = dmp_cobs_encode_parts(core, (dmp_bytes){ trailer, sizeof trailer },
                                   (dmp_buffer){ output.data, required - 1U },
                                   &cobs_size);
    if (status != DMP_OK) {
        return status;
    }
    output.data[cobs_size] = 0U;
    *written = cobs_size + 1U;
    return DMP_OK;
}

dmp_status dmp_stream_init(dmp_stream_decoder *decoder,
                           dmp_stream_config config, dmp_buffer storage,
                           dmp_time_ms now)
{
    dmp_stream_decoder fresh;
    size_t needed;
    dmp_status status;

    if (decoder == NULL || !valid_buffer(storage) ||
        config.partial_timeout_ms == 0U || config.max_core_bytes < 2U ||
        (config.mode != DMP_STREAM_L && config.mode != DMP_STREAM_R)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (ranges_overlap(decoder, sizeof *decoder, storage.data, storage.capacity)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (config.mode == DMP_STREAM_L) {
        needed = config.max_core_bytes;
    } else {
        status = dmp_stream_encoded_bound(config.mode, config.max_core_bytes,
                                          &needed);
        if (status != DMP_OK) {
            return status;
        }
    }
    if (storage.capacity < needed) {
        return DMP_QUOTA_EXHAUSTED;
    }

    memset(&fresh, 0, sizeof fresh);
    fresh.config = config;
    fresh.storage = storage;
    fresh.last_now = now;
    fresh.phase = config.mode == DMP_STREAM_L ? PHASE_L_MAGIC : PHASE_R_SYNC;
    fresh.expected = config.mode == DMP_STREAM_R ? needed - 1U : 0U;
    *decoder = fresh;
    return DMP_OK;
}

dmp_status dmp_stream_reset(dmp_stream_decoder *decoder, dmp_time_ms now)
{
    dmp_stream_decoder reset;

    if (decoder == NULL || !decoder_initialized(decoder)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (now < decoder->last_now) {
        return DMP_INVALID_ARGUMENT;
    }
    reset = *decoder;
    reset.used = 0U;
    reset.expected = 0U;
    reset.deadline = 0U;
    reset.last_now = now;
    reset.length_value = 0U;
    reset.length_bytes = 0U;
    reset.timer_armed = false;
    reset.failed = false;
    reset.phase = reset.config.mode == DMP_STREAM_L ? PHASE_L_MAGIC : PHASE_R_SYNC;
    if (reset.config.mode == DMP_STREAM_R) {
        size_t bound;
        if (dmp_stream_encoded_bound(DMP_STREAM_R,
                                     reset.config.max_core_bytes,
                                     &bound) != DMP_OK) {
            return DMP_LIMIT_EXHAUSTED;
        }
        reset.expected = bound - 1U;
    }
    *decoder = reset;
    return DMP_OK;
}

static dmp_stream_result result(dmp_status status, dmp_stream_event event,
                                size_t consumed, const uint8_t *frame,
                                size_t frame_size)
{
    dmp_stream_result value;
    value.status = status;
    value.event = event;
    value.consumed = consumed;
    value.frame.data = frame;
    value.frame.size = frame_size;
    return value;
}

static void clear_l_partial(dmp_stream_decoder *decoder)
{
    decoder->phase = PHASE_L_MAGIC;
    decoder->used = 0U;
    decoder->expected = 0U;
    decoder->length_value = 0U;
    decoder->length_bytes = 0U;
    decoder->timer_armed = false;
}

static dmp_stream_result l_fail(dmp_stream_decoder *decoder,
                                dmp_status status, size_t consumed)
{
    decoder->failed = true;
    return result(status, DMP_STREAM_SESSION_FAILED, consumed, NULL, 0U);
}

static dmp_stream_result feed_l(dmp_stream_decoder *decoder, dmp_bytes input,
                                dmp_time_ms now)
{
    static const uint8_t magic[3] = { 0x44U, 0x4DU, 0x50U };
    size_t index;

    if (decoder->failed) {
        return result(DMP_MALFORMED, DMP_STREAM_NONE, 0U, NULL, 0U);
    }
    if (decoder->timer_armed && now > decoder->deadline) {
        return l_fail(decoder, DMP_DEADLINE_EXPIRED, 0U);
    }
    for (index = 0U; index < input.size; ++index) {
        uint8_t byte = input.data[index];
        if (decoder->phase == PHASE_L_MAGIC) {
            if (decoder->used == 0U) {
                dmp_status status;
                if (byte != magic[0]) {
                    return l_fail(decoder, DMP_MALFORMED, index + 1U);
                }
                status = dmp_deadline_after(now,
                                           decoder->config.partial_timeout_ms,
                                           &decoder->deadline);
                if (status != DMP_OK) {
                    decoder->failed = true;
                    decoder->timer_armed = false;
                    return result(status, DMP_STREAM_SESSION_FAILED,
                                  index + 1U, NULL, 0U);
                }
                decoder->timer_armed = true;
            } else if (byte != magic[decoder->used]) {
                return l_fail(decoder, DMP_MALFORMED, index + 1U);
            }
            ++decoder->used;
            if (decoder->used == sizeof magic) {
                decoder->phase = PHASE_L_LENGTH;
                decoder->used = 0U;
            }
        } else if (decoder->phase == PHASE_L_LENGTH) {
            uint8_t payload = (uint8_t)(byte & 0x7FU);
            unsigned shift = (unsigned)decoder->length_bytes * 7U;
            if (decoder->length_bytes >= 5U ||
                (decoder->length_bytes == 4U && payload > 0x0FU)) {
                return l_fail(decoder, DMP_MALFORMED, index + 1U);
            }
            decoder->length_value |= (uint32_t)payload << shift;
            ++decoder->length_bytes;
            if ((byte & 0x80U) == 0U) {
                if ((decoder->length_bytes > 1U && payload == 0U) ||
                    decoder->length_value < 2U ||
                    (uint64_t)decoder->length_value >
                        (uint64_t)decoder->config.max_core_bytes) {
                    return l_fail(decoder, DMP_MALFORMED, index + 1U);
                }
                decoder->expected = decoder->length_value;
                decoder->used = 0U;
                decoder->phase = PHASE_L_BODY;
            } else if (decoder->length_bytes == 5U) {
                return l_fail(decoder, DMP_MALFORMED, index + 1U);
            }
        } else {
            decoder->storage.data[decoder->used++] = byte;
            if (decoder->used == decoder->expected) {
                size_t frame_size = decoder->used;
                const uint8_t *frame = decoder->storage.data;
                clear_l_partial(decoder);
                return result(DMP_OK, DMP_STREAM_FRAME, index + 1U,
                              frame, frame_size);
            }
        }
    }
    decoder->last_now = now;
    return result(DMP_OK, DMP_STREAM_NONE, input.size, NULL, 0U);
}

static dmp_stream_result feed_r(dmp_stream_decoder *decoder, dmp_bytes input,
                                dmp_time_ms now)
{
    size_t index;

    if (decoder->failed) {
        return result(DMP_MALFORMED, DMP_STREAM_NONE, 0U, NULL, 0U);
    }
    if (decoder->timer_armed && now > decoder->deadline) {
        decoder->phase = PHASE_R_DISCARD;
        decoder->used = 0U;
        decoder->timer_armed = false;
        decoder->last_now = now;
        return result(DMP_DEADLINE_EXPIRED, DMP_STREAM_DISCARDED,
                      0U, NULL, 0U);
    }

    for (index = 0U; index < input.size; ++index) {
        uint8_t byte = input.data[index];
        if (decoder->phase == PHASE_R_SYNC || decoder->phase == PHASE_R_DISCARD) {
            if (byte == 0U) {
                decoder->phase = PHASE_R_READY;
                decoder->used = 0U;
                decoder->timer_armed = false;
            }
            continue;
        }
        if (byte == 0U) {
            if (decoder->used == 0U) {
                continue;
            }
            {
                size_t decoded_size = 0U;
                uint32_t expected_crc, actual_crc;
                dmp_status status = dmp_cobs_decode_canonical(
                    decoder->storage.data, decoder->used,
                    decoder->config.max_core_bytes + 4U, &decoded_size);
                decoder->used = 0U;
                decoder->timer_armed = false;
                decoder->last_now = now;
                if (status != DMP_OK || decoded_size < 6U ||
                    decoded_size > decoder->config.max_core_bytes + 4U) {
                    return result(DMP_MALFORMED,
                                  DMP_STREAM_DISCARDED, index + 1U, NULL, 0U);
                }
                expected_crc = (uint32_t)decoder->storage.data[decoded_size - 4U] |
                               ((uint32_t)decoder->storage.data[decoded_size - 3U] << 8U) |
                               ((uint32_t)decoder->storage.data[decoded_size - 2U] << 16U) |
                               ((uint32_t)decoder->storage.data[decoded_size - 1U] << 24U);
                {
                    dmp_bytes bytes = { decoder->storage.data, decoded_size - 4U };
                    status = dmp_crc32c(bytes, &actual_crc);
                }
                if (status != DMP_OK || actual_crc != expected_crc) {
                    return result(DMP_INTEGRITY_FAILURE, DMP_STREAM_DISCARDED,
                                  index + 1U, NULL, 0U);
                }
                return result(DMP_OK, DMP_STREAM_FRAME, index + 1U,
                              decoder->storage.data, decoded_size - 4U);
            }
        }
        if (decoder->used == decoder->expected) {
            decoder->phase = PHASE_R_DISCARD;
            decoder->used = 0U;
            decoder->timer_armed = false;
            decoder->last_now = now;
            return result(DMP_MALFORMED, DMP_STREAM_DISCARDED,
                          index + 1U, NULL, 0U);
        }
        if (!decoder->timer_armed) {
            dmp_status status = dmp_deadline_after(
                now, decoder->config.partial_timeout_ms, &decoder->deadline);
            if (status != DMP_OK) {
                decoder->failed = true;
                decoder->phase = PHASE_R_DISCARD;
                decoder->used = 0U;
                decoder->last_now = now;
                return result(status, DMP_STREAM_SESSION_FAILED,
                              index + 1U, NULL, 0U);
            }
            decoder->timer_armed = true;
        }
        decoder->storage.data[decoder->used++] = byte;
    }
    decoder->last_now = now;
    return result(DMP_OK, DMP_STREAM_NONE, input.size, NULL, 0U);
}

dmp_stream_result dmp_stream_feed(dmp_stream_decoder *decoder,
                                  dmp_bytes input, dmp_time_ms now)
{
    if (!decoder_initialized(decoder) || !valid_bytes(input) ||
        ranges_overlap(decoder, sizeof *decoder, input.data, input.size) ||
        ranges_overlap(decoder->storage.data, decoder->storage.capacity,
                       input.data, input.size) || now < decoder->last_now) {
        return result(DMP_INVALID_ARGUMENT, DMP_STREAM_NONE, 0U, NULL, 0U);
    }
    decoder->last_now = now;
    if (decoder->failed) {
        return result(DMP_MALFORMED, DMP_STREAM_NONE, 0U, NULL, 0U);
    }
    return decoder->config.mode == DMP_STREAM_L
               ? feed_l(decoder, input, now)
               : feed_r(decoder, input, now);
}

dmp_stream_result dmp_stream_poll(dmp_stream_decoder *decoder, dmp_time_ms now)
{
    if (!decoder_initialized(decoder) || now < decoder->last_now) {
        return result(DMP_INVALID_ARGUMENT, DMP_STREAM_NONE, 0U, NULL, 0U);
    }
    decoder->last_now = now;
    if (decoder->failed) {
        return result(DMP_MALFORMED, DMP_STREAM_NONE, 0U, NULL, 0U);
    }
    if (!decoder->timer_armed || !dmp_deadline_reached(now, decoder->deadline)) {
        return result(DMP_OK, DMP_STREAM_NONE, 0U, NULL, 0U);
    }
    if (decoder->config.mode == DMP_STREAM_L) {
        decoder->failed = true;
        return result(DMP_DEADLINE_EXPIRED, DMP_STREAM_SESSION_FAILED,
                      0U, NULL, 0U);
    }
    decoder->phase = PHASE_R_DISCARD;
    decoder->used = 0U;
    decoder->timer_armed = false;
    return result(DMP_DEADLINE_EXPIRED, DMP_STREAM_DISCARDED,
                  0U, NULL, 0U);
}
