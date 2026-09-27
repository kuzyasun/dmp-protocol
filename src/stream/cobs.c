#include "cobs.h"

#include <stdint.h>

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

dmp_status dmp_cobs_encoded_bound(size_t input_size, size_t *out)
{
    size_t extra;

    if (out == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    extra = input_size / 254U;
    if (input_size > SIZE_MAX - extra - 1U) {
        return DMP_LIMIT_EXHAUSTED;
    }
    *out = input_size + extra + 1U;
    return DMP_OK;
}

dmp_status dmp_cobs_encode_parts(dmp_bytes first, dmp_bytes second,
                                 dmp_buffer output, size_t *written)
{
    size_t input_size, bound, read_index, code_index, write_index;
    uint8_t code = 1U;
    dmp_status status;

    if (written != NULL &&
        !ranges_overlap(written, sizeof *written, first.data, first.size) &&
        !ranges_overlap(written, sizeof *written, second.data, second.size) &&
        !ranges_overlap(written, sizeof *written, output.data, output.capacity)) {
        *written = 0U;
    }
    if (written == NULL ||
        (output.data == NULL && output.capacity != 0U) ||
        (first.data == NULL && first.size != 0U) ||
        (second.data == NULL && second.size != 0U)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (ranges_overlap(first.data, first.size, output.data, output.capacity) ||
        ranges_overlap(second.data, second.size, output.data, output.capacity) ||
        ranges_overlap(written, sizeof *written, first.data, first.size) ||
        ranges_overlap(written, sizeof *written, second.data, second.size) ||
        ranges_overlap(written, sizeof *written, output.data, output.capacity)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (first.size > SIZE_MAX - second.size) {
        return DMP_LIMIT_EXHAUSTED;
    }
    input_size = first.size + second.size;
    status = dmp_cobs_encoded_bound(input_size, &bound);
    if (status != DMP_OK) {
        return status;
    }
    if (bound > output.capacity) {
        return DMP_QUOTA_EXHAUSTED;
    }

    write_index = 1U;
    code_index = 0U;
    for (read_index = 0U; read_index < input_size; ++read_index) {
        uint8_t value = read_index < first.size
                            ? first.data[read_index]
                            : second.data[read_index - first.size];
        if (value == 0U) {
            output.data[code_index] = code;
            code = 1U;
            code_index = write_index++;
        } else {
            output.data[write_index++] = value;
            ++code;
            if (code == 0xFFU) {
                output.data[code_index] = code;
                code = 1U;
                code_index = write_index++;
            }
        }
    }
    output.data[code_index] = code;
    *written = write_index;
    return DMP_OK;
}

dmp_status dmp_cobs_encode(dmp_bytes input, dmp_buffer output, size_t *written)
{
    if (written != NULL &&
        !ranges_overlap(written, sizeof *written, input.data, input.size) &&
        !ranges_overlap(written, sizeof *written, output.data, output.capacity)) {
        *written = 0U;
    }
    return dmp_cobs_encode_parts(input, (dmp_bytes){ NULL, 0U }, output, written);
}

/* The rules below accept precisely the canonical block layout produced by the
 * encoder above, including its mandatory empty block after a full final run. */
dmp_status dmp_cobs_decode_canonical(uint8_t *candidate, size_t candidate_size,
                                     size_t capacity, size_t *decoded_size)
{
    size_t read_index = 0U, write_index = 0U;

    if (decoded_size == NULL || (candidate == NULL && candidate_size != 0U)) {
        return DMP_INVALID_ARGUMENT;
    }
    if (candidate_size == 0U) {
        return DMP_MALFORMED;
    }

    while (read_index < candidate_size) {
        uint8_t code = candidate[read_index++];
        size_t count = (size_t)code - 1U;
        size_t next;
        size_t i;

        if (code == 0U || count > candidate_size - read_index) {
            return DMP_MALFORMED;
        }
        next = read_index + count;
        if (code == 0xFFU && next == candidate_size) {
            return DMP_MALFORMED; /* Missing canonical trailing 01 block. */
        }
        if (write_index > capacity || count > capacity - write_index) {
            return DMP_LIMIT_EXHAUSTED;
        }
        for (i = 0U; i < count; ++i) {
            uint8_t value = candidate[read_index + i];
            if (value == 0U) {
                return DMP_MALFORMED;
            }
            candidate[write_index++] = value;
        }
        read_index = next;
        if (code < 0xFFU && read_index < candidate_size) {
            if (write_index >= capacity) {
                return DMP_LIMIT_EXHAUSTED;
            }
            candidate[write_index++] = 0U;
        }
    }

    *decoded_size = write_index;
    return DMP_OK;
}
