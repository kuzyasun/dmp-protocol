#include "qual_handshake_frame.h"

#include "dmp/integrity.h"

#include <stdio.h>
#include <string.h>

static int encode_frame(uint8_t *bytes, size_t capacity, size_t *written,
                        const dmp_frame_spec *spec)
{
    const dmp_core_limits limits = { 256U, 256U, 1U };
    dmp_status status = dmp_core_encode(spec, &limits,
                                        (dmp_buffer){ bytes, capacity }, written);
    if (status != DMP_OK) {
        return 0;
    }
    if ((spec->fields.options & DMP_OPT_INTEGRITY) != 0U) {
        uint32_t crc = 0U;
        if (*written < 4U || dmp_crc32c((dmp_bytes){ bytes, *written - 4U }, &crc) != DMP_OK) {
            return 0;
        }
        bytes[*written - 4U] = (uint8_t)crc;
        bytes[*written - 3U] = (uint8_t)(crc >> 8U);
        bytes[*written - 2U] = (uint8_t)(crc >> 16U);
        bytes[*written - 1U] = (uint8_t)(crc >> 24U);
    }
    return 1;
}

static int parse_frame(uint8_t *bytes, size_t length, dmp_frame_view *view)
{
    const dmp_core_limits limits = { 256U, 256U, 1U };
    dmp_parse_result parsed = dmp_core_parse((dmp_bytes){ bytes, length }, &limits, view);
    return parsed.status == DMP_OK;
}

static int test_bootstrap_routes_and_preserves_wire_context(void)
{
    uint8_t bytes[128] = {0};
    uint8_t extensions[] = {
        0x0BU, 9U, 1U, 0x88U, 0x77U, 0x66U, 0x55U, 0x44U, 0x33U, 0x22U, 0x11U,
        0x0FU, 1U, 20U
    };
    uint8_t payload[20] = {0};
    uint8_t trailer[4] = {0};
    dmp_frame_spec spec;
    dmp_frame_view view;
    dmp_qual_bootstrap_context context;
    size_t written = 0U;

    memset(&spec, 0, sizeof(spec));
    spec.fields.type = DMP_TYPE_HELLO;
    spec.fields.options = DMP_OPT_SEQ | DMP_OPT_EXT | DMP_OPT_INTEGRITY;
    spec.fields.seq = 1U;
    spec.fields.integrity = 1U;
    spec.extensions = (dmp_bytes){ extensions, sizeof extensions };
    spec.payload = (dmp_bytes){ payload, sizeof payload };
    spec.trailer = (dmp_bytes){ trailer, sizeof trailer };
    if (!encode_frame(bytes, sizeof bytes, &written, &spec) ||
        !parse_frame(bytes, written, &view) ||
        dmp_qual_classify_handshake_frame(&view) != DMP_QUAL_FRAME_BOOTSTRAP ||
        dmp_qual_parse_bootstrap_context(&view, &context) != DMP_OK ||
        context.namespace_id != 1U || context.origin_id != 20U ||
        context.provisional_epoch != UINT64_C(0x1122334455667788)) {
        return 0;
    }

    /* A changed CONTEXT with a valid CRC must reach SEC-1 unchanged for its
     * attempt-ID comparison instead of being replaced by local constants. */
    extensions[2] = 2U;
    extensions[3] ^= 1U;
    if (!encode_frame(bytes, sizeof bytes, &written, &spec) ||
        !parse_frame(bytes, written, &view) ||
        dmp_qual_parse_bootstrap_context(&view, &context) != DMP_OK ||
        context.namespace_id != 2U ||
        context.provisional_epoch != UINT64_C(0x1122334455667789)) {
        return 0;
    }

    bytes[written - 1U] ^= 1U;
    if (!parse_frame(bytes, written, &view) ||
        dmp_qual_parse_bootstrap_context(&view, &context) != DMP_INTEGRITY_FAILURE) {
        return 0;
    }
    return 1;
}

static int test_protected_hello_routes_to_sec1(void)
{
    uint8_t bytes[64] = {0};
    uint8_t payload[1] = {0xA5U};
    uint8_t trailer[16] = {0};
    dmp_frame_spec spec;
    dmp_frame_view view;
    dmp_qual_bootstrap_context context;
    size_t written = 0U;

    memset(&spec, 0, sizeof(spec));
    spec.fields.type = DMP_TYPE_HELLO;
    spec.fields.options = DMP_OPT_SEQ | DMP_OPT_SECURITY;
    spec.fields.seq = 0U;
    spec.fields.security.cipher = 1U;
    spec.fields.security.receive_cid = 7U;
    spec.fields.security.pn = 0U;
    spec.payload = (dmp_bytes){ payload, sizeof payload };
    spec.trailer = (dmp_bytes){ trailer, sizeof trailer };
    if (!encode_frame(bytes, sizeof bytes, &written, &spec) ||
        !parse_frame(bytes, written, &view) ||
        dmp_qual_classify_handshake_frame(&view) != DMP_QUAL_FRAME_PROTECTED_HELLO ||
        dmp_qual_parse_bootstrap_context(&view, &context) != DMP_MALFORMED) {
        return 0;
    }
    return 1;
}

static int test_namespace_uleb32_boundaries(void)
{
    static const struct {
        uint32_t value;
        uint8_t encoded[5];
        size_t encoded_size;
    } valid_cases[] = {
        { UINT32_C(0x7FFFFFFF), { 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x07U }, 5U },
        { UINT32_C(0x80000000), { 0x80U, 0x80U, 0x80U, 0x80U, 0x08U }, 5U },
        { UINT32_MAX, { 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0x0FU }, 5U },
    };
    uint8_t bytes[128] = {0};
    uint8_t extensions[18] = {0};
    uint8_t payload[1] = {0};
    uint8_t trailer[4] = {0};
    dmp_frame_spec spec;
    dmp_frame_view view;
    dmp_qual_bootstrap_context context;
    size_t written = 0U;

    memset(&spec, 0, sizeof(spec));
    spec.fields.type = DMP_TYPE_HELLO;
    spec.fields.options = DMP_OPT_SEQ | DMP_OPT_EXT | DMP_OPT_INTEGRITY;
    spec.fields.seq = 1U;
    spec.fields.integrity = 1U;
    spec.extensions = (dmp_bytes){ extensions, sizeof extensions };
    spec.payload = (dmp_bytes){ payload, sizeof payload };
    spec.trailer = (dmp_bytes){ trailer, sizeof trailer };

    for (size_t index = 0U; index < sizeof valid_cases / sizeof valid_cases[0]; ++index) {
        size_t ext_size = 0U;
        dmp_status parse_status;
        extensions[ext_size++] = 0x0BU;
        extensions[ext_size++] = (uint8_t)(valid_cases[index].encoded_size + 8U);
        memcpy(extensions + ext_size, valid_cases[index].encoded,
               valid_cases[index].encoded_size);
        ext_size += valid_cases[index].encoded_size;
        memset(extensions + ext_size, 0x11, 8U);
        ext_size += 8U;
        extensions[ext_size++] = 0x0FU;
        extensions[ext_size++] = 1U;
        extensions[ext_size++] = 1U;
        spec.extensions = (dmp_bytes){ extensions, ext_size };

        if (!encode_frame(bytes, sizeof bytes, &written, &spec) ||
            !parse_frame(bytes, written, &view)) {
            fprintf(stderr, "failed to encode/parse valid namespace case %zu\n", index);
            return 0;
        }
        parse_status = dmp_qual_parse_bootstrap_context(&view, &context);
        if (parse_status != DMP_OK || context.namespace_id != valid_cases[index].value) {
            fprintf(stderr, "valid namespace case %zu returned status %d and value %u\n",
                    index, (int)parse_status, (unsigned)context.namespace_id);
            return 0;
        }
    }

    /* The high nibble of byte five is reserved for overflow detection. */
    {
        uint32_t crc = 0U;
        size_t overflow_byte = (size_t)(view.extensions.data - bytes) + 6U;
        bytes[overflow_byte] = 0x10U;
        if (dmp_crc32c((dmp_bytes){ bytes, written - 4U }, &crc) != DMP_OK) {
            fputs("failed to recalculate overflow fixture CRC\n", stderr);
            return 0;
        }
        bytes[written - 4U] = (uint8_t)crc;
        bytes[written - 3U] = (uint8_t)(crc >> 8U);
        bytes[written - 2U] = (uint8_t)(crc >> 16U);
        bytes[written - 1U] = (uint8_t)(crc >> 24U);
        /* Keep the already parsed view so this malformed value reaches the
         * qualification parser directly; the generic core parser rejects it
         * earlier while validating the known CONTEXT extension. */
        if (dmp_qual_parse_bootstrap_context(&view, &context) != DMP_MALFORMED) {
            fputs("qualification parser accepted an overflowing namespace\n", stderr);
            return 0;
        }
    }
    return 1;
}

int main(void)
{
    if (!test_bootstrap_routes_and_preserves_wire_context()) {
        fputs("bootstrap context/CRC qualification failed\n", stderr);
        return 1;
    }
    if (!test_protected_hello_routes_to_sec1()) {
        fputs("protected HELLO dispatch qualification failed\n", stderr);
        return 1;
    }
    if (!test_namespace_uleb32_boundaries()) {
        fputs("bootstrap namespace ULEB32 boundary qualification failed\n", stderr);
        return 1;
    }
    return 0;
}
