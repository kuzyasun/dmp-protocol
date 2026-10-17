#include "qual_handshake_frame.h"

#include "dmp/integrity.h"

#include <string.h>

#define QUAL_HS_CONTEXT_TAG UINT32_C(0x0B)
#define QUAL_HS_ORIGIN_TAG UINT32_C(0x0F)
#define QUAL_BOOTSTRAP_OPTIONS (DMP_OPT_SEQ | DMP_OPT_EXT | DMP_OPT_INTEGRITY)

static int decode_uleb32(dmp_bytes bytes, size_t *consumed, uint32_t *value)
{
    uint64_t decoded = 0U;

    if (bytes.data == NULL || consumed == NULL || value == NULL || bytes.size == 0U) {
        return 0;
    }
    for (size_t index = 0U; index < bytes.size && index < 5U; ++index) {
        uint8_t byte = bytes.data[index];
        if (index == 4U && (byte & 0xF0U) != 0U) {
            return 0;
        }
        decoded |= (uint64_t)(byte & 0x7FU) << (index * 7U);
        if ((byte & 0x80U) == 0U) {
            if (index != 0U && (byte & 0x7FU) == 0U) {
                return 0;
            }
            *consumed = index + 1U;
            *value = (uint32_t)decoded;
            return 1;
        }
    }
    return 0;
}

static uint64_t load_le64(const uint8_t *bytes)
{
    uint64_t value = 0U;

    for (size_t index = 0U; index < 8U; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8U);
    }
    return value;
}

static int bootstrap_crc_matches(const dmp_frame_view *view)
{
    uint32_t actual = 0U;
    uint32_t expected;

    if (view->frame.data == NULL || view->frame.size < 4U || view->trailer.size != 4U ||
        view->trailer.data != view->frame.data + view->frame.size - 4U ||
        dmp_crc32c((dmp_bytes){ view->frame.data, view->frame.size - 4U }, &actual) != DMP_OK) {
        return 0;
    }
    expected = (uint32_t)view->trailer.data[0] |
               ((uint32_t)view->trailer.data[1] << 8U) |
               ((uint32_t)view->trailer.data[2] << 16U) |
               ((uint32_t)view->trailer.data[3] << 24U);
    return actual == expected;
}

dmp_qual_handshake_frame_kind dmp_qual_classify_handshake_frame(
    const dmp_frame_view *view)
{
    if (view == NULL || view->fields.type != DMP_TYPE_HELLO) {
        return DMP_QUAL_FRAME_OTHER;
    }
    return (view->fields.options & DMP_OPT_SECURITY) != 0U
               ? DMP_QUAL_FRAME_PROTECTED_HELLO
               : DMP_QUAL_FRAME_BOOTSTRAP;
}

dmp_status dmp_qual_parse_bootstrap_context(const dmp_frame_view *view,
                                             dmp_qual_bootstrap_context *context)
{
    dmp_qual_bootstrap_context parsed = {0};
    dmp_extension_view extension;
    size_t cursor = 0U;
    size_t value_bytes = 0U;
    uint32_t seen = 0U;
    uint8_t options;

    if (view == NULL || context == NULL) {
        return DMP_INVALID_ARGUMENT;
    }
    memset(context, 0, sizeof(*context));
    options = view->fields.options;
    if (dmp_qual_classify_handshake_frame(view) != DMP_QUAL_FRAME_BOOTSTRAP ||
        view->fields.seq == 0U ||
        (options & (uint8_t)~QUAL_BOOTSTRAP_OPTIONS) != 0U ||
        (options & QUAL_BOOTSTRAP_OPTIONS) != QUAL_BOOTSTRAP_OPTIONS ||
        (options & DMP_OPT_ROUTE) != 0U) {
        return DMP_MALFORMED;
    }
    if (!bootstrap_crc_matches(view)) {
        return DMP_INTEGRITY_FAILURE;
    }

    for (;;) {
        dmp_status status = dmp_extension_next(view->extensions, &cursor, &extension);
        if (status == DMP_INCOMPLETE) {
            break;
        }
        if (status != DMP_OK) {
            return status;
        }
        if (extension.tag == QUAL_HS_CONTEXT_TAG) {
            size_t namespace_bytes = 0U;
            if ((seen & 1U) != 0U ||
                !decode_uleb32(extension.value, &namespace_bytes, &parsed.namespace_id) ||
                extension.value.size - namespace_bytes != 8U) {
                return DMP_MALFORMED;
            }
            parsed.provisional_epoch = load_le64(extension.value.data + namespace_bytes);
            seen |= 1U;
        } else if (extension.tag == QUAL_HS_ORIGIN_TAG) {
            if ((seen & 2U) != 0U ||
                !decode_uleb32(extension.value, &value_bytes, &parsed.origin_id) ||
                value_bytes != extension.value.size) {
                return DMP_MALFORMED;
            }
            seen |= 2U;
        } else {
            return DMP_UNSUPPORTED;
        }
    }
    if (seen != 3U) {
        return DMP_CONTEXT_REQUIRED;
    }
    *context = parsed;
    return DMP_OK;
}
