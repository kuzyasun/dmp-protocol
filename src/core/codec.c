#include "dmp/core.h"

#include "byte_span.h"
#include "extension_values.h"
#include "little_endian.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

typedef struct { uint64_t value; size_t next; } varint;

static int add_size(size_t a, size_t b, size_t *out)
{
    if (b > SIZE_MAX - a) return 0;
    *out = a + b;
    return 1;
}
static size_t uleb_size(uint64_t value)
{
    size_t n = 1U;
    while (value >= 128U) { value >>= 7; ++n; }
    return n;
}
static size_t put_uleb(uint8_t *out, uint64_t value)
{
    size_t n = 0U;
    do {
        uint8_t byte = (uint8_t)(value & 0x7fU);
        value >>= 7;
        if (value != 0U) byte |= 0x80U;
        out[n++] = byte;
    } while (value != 0U);
    return n;
}
static int get_uleb(dmp_bytes in, size_t *at, unsigned bits, varint *out,
                    size_t *bad)
{
    uint64_t value = 0U;
    size_t start = *at, i;
    unsigned max = bits == 32U ? 5U : 10U;
    for (i = 0U; i < max; ++i) {
        uint8_t b;
        unsigned shift = (unsigned)(7U * i);
        uint8_t chunk;
        if (*at >= in.size) { *bad = in.size; return 0; }
        b = in.data[(*at)++]; chunk = (uint8_t)(b & 0x7fU);
        if ((bits == 32U && i == 4U && chunk > 0x0fU) ||
            (bits == 64U && i == 9U && chunk > 0x01U)) {
            *bad = *at - 1U; return 0;
        }
        value |= ((uint64_t)chunk) << shift;
        if ((b & 0x80U) == 0U) {
            if (*at - start != uleb_size(value)) { *bad = start; return 0; }
            out->value = value; out->next = *at; return 1;
        }
        if (i + 1U == max) { *bad = *at - 1U; return 0; }
    }
    *bad = *at; return 0;
}
static int read_u32(dmp_bytes in, size_t *at, uint32_t *v, size_t *bad)
{
    varint x;
    if (!get_uleb(in, at, 32U, &x, bad)) return 0;
    *v = (uint32_t)x.value; return 1;
}

bool dmp_decode_extension_u32(dmp_bytes value, uint32_t *out, size_t *error)
{
    size_t at = 0U, ignored;
    uint32_t decoded;
    size_t *bad = error != NULL ? error : &ignored;

    if (!read_u32(value, &at, &decoded, bad)) return false;
    if (at != value.size) { *bad = at; return false; }
    if (out != NULL) *out = decoded;
    return true;
}

bool dmp_decode_extension_context(dmp_bytes value, uint32_t *namespace_id,
                                  uint64_t *epoch, size_t *error)
{
    size_t at = 0U, ignored;
    uint32_t decoded_ns;
    size_t *bad = error != NULL ? error : &ignored;

    if (!read_u32(value, &at, &decoded_ns, bad)) return false;
    if (value.size - at != 8U) {
        *bad = value.size - at < 8U ? value.size : at + 8U;
        return false;
    }
    if (namespace_id != NULL) *namespace_id = decoded_ns;
    if (epoch != NULL) *epoch = dmp_load_le64(value.data + at);
    return true;
}

bool dmp_decode_extension_reply_to(dmp_bytes value, bool compact,
                                   dmp_reply_to_value *out, size_t *error)
{
    size_t at = 0U, ignored;
    size_t *bad = error != NULL ? error : &ignored;
    dmp_reply_to_value decoded = {0};

    if (!compact) {
        if (!read_u32(value, &at, &decoded.namespace_id, bad) ||
            !read_u32(value, &at, &decoded.origin_id, bad)) return false;
        if (value.size - at < 8U) { *bad = value.size; return false; }
        if (out != NULL) decoded.epoch = dmp_load_le64(value.data + at);
        at += 8U;
    }
    if (!read_u32(value, &at, &decoded.seq, bad)) return false;
    if (at != value.size) { *bad = at; return false; }
    if (out != NULL) *out = decoded;
    return true;
}

typedef enum {
    EXTENSION_OK,
    EXTENSION_BAD_HEADER,
    EXTENSION_TRUNCATED_VALUE,
} extension_read_result;

/* A decoded tag is available on value truncation so strict validation can
 * report out-of-order tags first. Only success advances the cursor. */
static extension_read_result read_extension(dmp_bytes extensions, size_t *cursor,
                                             dmp_extension_view *out, size_t *error)
{
    size_t at = *cursor, ignored;
    uint32_t len;
    size_t *bad = error != NULL ? error : &ignored;

    if (!read_u32(extensions, &at, &out->tag, bad) ||
        !read_u32(extensions, &at, &len, bad)) return EXTENSION_BAD_HEADER;
    if (len > extensions.size - at) {
        *bad = extensions.size;
        return EXTENSION_TRUNCATED_VALUE;
    }
    out->value = (dmp_bytes){extensions.data + at, len};
    *cursor = at + len;
    return EXTENSION_OK;
}

static dmp_parse_result parse_error(dmp_frame_view *out, dmp_status status,
                                    size_t at)
{
    memset(out, 0, sizeof *out);
    { dmp_parse_result r = { status, at }; return r; }
}

static int known_extension(uint32_t id) { return id >= 1U && id <= 6U; }
static dmp_status validate_extensions(dmp_bytes ext, uint8_t options,
                                      uint8_t type, size_t *bad, uint32_t *status)
{
    size_t at = 0U;
    uint32_t prev = 0U;
    bool have_reply = false, have_status = false;
    while (at < ext.size) {
        size_t start = at, value_at;
        dmp_extension_view view;
        extension_read_result result = read_extension(ext, &at, &view, bad);
        uint32_t id;
        uint8_t flags;
        if (result == EXTENSION_BAD_HEADER) return DMP_MALFORMED;
        id = view.tag >> 2;
        if (start != 0U && id <= prev) { *bad = start; return DMP_MALFORMED; }
        if (result != EXTENSION_OK) return DMP_MALFORMED;
        prev = id;
        flags = (uint8_t)(view.tag & 3U);
        value_at = at - view.value.size;
        if (known_extension(id)) {
            uint8_t expected = (id == 1U || id == 4U || id == 5U || id == 6U) ? 1U : 3U;
            if (flags != expected) { *bad = start; return DMP_MALFORMED; }
            if (id == 1U) {
                if (!dmp_decode_extension_reply_to(view.value, (options & DMP_OPT_SECURITY) != 0U,
                                                  NULL, bad)) {
                    *bad += value_at; return DMP_MALFORMED;
                }
                have_reply = true;
            } else if (id == 2U) {
                if (!dmp_decode_extension_context(view.value, NULL, NULL, bad)) {
                    *bad += value_at; return DMP_MALFORMED;
                }
            } else if (id == 3U || id == 4U || id == 5U) {
                if (!dmp_decode_extension_u32(view.value, id == 5U ? status : NULL, bad)) {
                    *bad += value_at; return DMP_MALFORMED;
                }
                if (id == 3U && (options & DMP_OPT_ROUTE) != 0U) { *bad = start; return DMP_MALFORMED; }
                if (id == 5U) have_status = true;
            } else if (id == 6U) {
                if (view.value.size != 16U || (options & DMP_OPT_SECURITY) == 0U) { *bad = value_at; return DMP_MALFORMED; }
            }
        }
        if (type == DMP_TYPE_FRAG_STATUS && (id == 5U || id == 6U)) { *bad = start; return DMP_MALFORMED; }
    }
    if (((options & DMP_OPT_EXT) != 0U) != (ext.size != 0U)) { *bad = 2U; return DMP_MALFORMED; }
    if ((type == DMP_TYPE_ACK || type == DMP_TYPE_RSP || type == DMP_TYPE_ERR || type == DMP_TYPE_FRAG_STATUS) && !have_reply) {
        *bad = ext.size == 0U ? 2U : 0U; return DMP_MALFORMED;
    }
    if (type == DMP_TYPE_ERR && !have_status) { *bad = ext.size == 0U ? 2U : 0U; return DMP_MALFORMED; }
    if (type == DMP_TYPE_ACK && have_status) { *bad = 2U; return DMP_MALFORMED; }
    return DMP_OK;
}

dmp_parse_result dmp_core_parse(dmp_bytes input, const dmp_core_limits *limits,
                                dmp_frame_view *out)
{
    dmp_frame_view v;
    size_t at = 0U, bad = 0U, trailer_len = 0U, payload_at;
    dmp_bytes head;
    uint8_t vt, hdr, opt = 0U;
    uint32_t ext_status = 0U;
    dmp_status st;
    if (out == NULL) { dmp_parse_result r = { DMP_INVALID_ARGUMENT, 0U }; return r; }
    memset(out, 0, sizeof *out);
    if (!dmp_bytes_valid(input) || limits == NULL || limits->max_frame_bytes < 2U ||
        limits->max_message_bytes == 0U || limits->max_fragments == 0U) return parse_error(out, DMP_INVALID_ARGUMENT, 0U);
    if (input.size > limits->max_frame_bytes) return parse_error(out, DMP_LIMIT_EXHAUSTED, limits->max_frame_bytes);
    if (input.size < 2U) return parse_error(out, DMP_MALFORMED, input.size);
    vt = input.data[0]; hdr = input.data[1];
    if ((vt >> 5) != DMP_WIRE_VERSION) return parse_error(out, DMP_UNSUPPORTED, 0U);
    if (hdr < 2U || hdr > input.size) return parse_error(out, DMP_MALFORMED, hdr > input.size ? input.size : 1U);
    head.data = input.data; head.size = hdr;
    memset(&v, 0, sizeof v); v.fields.type = vt & 0x1fU;
    v.fields.options = 0U; at = 2U;
    if (hdr > 2U) {
        opt = input.data[at++]; v.fields.options = opt;
        if (opt == 0U) return parse_error(out, DMP_MALFORMED, 2U);
    }
    if ((opt & DMP_OPT_SEQ) != 0U && !read_u32(head, &at, &v.fields.seq, &bad)) return parse_error(out, DMP_MALFORMED, bad);
    if ((opt & DMP_OPT_ROUTE) != 0U) {
        uint8_t ctl;
        if (at >= hdr) return parse_error(out, DMP_MALFORMED, hdr);
        ctl = input.data[at++]; v.fields.route.ttl = ctl >> 4; v.fields.route.mode = ctl & 0x0fU;
        if (v.fields.route.mode > 2U) return parse_error(out, DMP_UNSUPPORTED, at - 1U);
        if (!read_u32(head, &at, &v.fields.route.source, &bad)) return parse_error(out, DMP_MALFORMED, bad);
        if (v.fields.route.mode == 1U && !read_u32(head, &at, &v.fields.route.destination, &bad)) return parse_error(out, DMP_MALFORMED, bad);
    }
    if ((opt & DMP_OPT_FRAG) != 0U) {
        if (!read_u32(head, &at, &v.fields.fragment.index, &bad) ||
            !read_u32(head, &at, &v.fields.fragment.chunk_size, &bad) ||
            !read_u32(head, &at, &v.fields.fragment.total_size, &bad)) return parse_error(out, DMP_MALFORMED, bad);
    }
    if ((opt & DMP_OPT_PAYLOAD_DESC) != 0U) {
        uint8_t flags;
        if (at >= hdr) return parse_error(out, DMP_MALFORMED, hdr);
        flags = input.data[at++]; v.fields.descriptor.flags = flags;
        if ((flags & 0xfcU) != 0U || ((flags & 2U) != 0U && (flags & 1U) == 0U)) return parse_error(out, DMP_MALFORMED, at - 1U);
        if (!read_u32(head, &at, &v.fields.descriptor.codec, &bad)) return parse_error(out, DMP_MALFORMED, bad);
        if ((flags & 1U) != 0U && !read_u32(head, &at, &v.fields.descriptor.schema, &bad)) return parse_error(out, DMP_MALFORMED, bad);
        if ((flags & 2U) != 0U && !read_u32(head, &at, &v.fields.descriptor.schema_version, &bad)) return parse_error(out, DMP_MALFORMED, bad);
    }
    if ((opt & DMP_OPT_INTEGRITY) != 0U) {
        if (at >= hdr) return parse_error(out, DMP_MALFORMED, hdr);
        v.fields.integrity = input.data[at++];
        if (v.fields.integrity != 1U) return parse_error(out, DMP_UNSUPPORTED, at - 1U);
        trailer_len = 4U;
    }
    if ((opt & DMP_OPT_SECURITY) != 0U) {
        varint x;
        if ((opt & DMP_OPT_INTEGRITY) != 0U) return parse_error(out, DMP_MALFORMED, at);
        if (at >= hdr) return parse_error(out, DMP_MALFORMED, hdr);
        v.fields.security.cipher = input.data[at++];
        if (v.fields.security.cipher != 1U && v.fields.security.cipher != 2U) return parse_error(out, DMP_UNSUPPORTED, at - 1U);
        if (!read_u32(head, &at, &v.fields.security.receive_cid, &bad) || !get_uleb(head, &at, 64U, &x, &bad)) return parse_error(out, DMP_MALFORMED, bad);
        v.fields.security.pn = x.value; trailer_len = 16U;
    }
    if (at > hdr) return parse_error(out, DMP_MALFORMED, hdr);
    if ((opt & DMP_OPT_EXT) != 0U) {
        v.extensions.data = input.data + at; v.extensions.size = hdr - at;
        if (v.extensions.size == 0U) return parse_error(out, DMP_MALFORMED, at);
        st = validate_extensions(v.extensions, opt, v.fields.type, &bad, &ext_status);
        if (st != DMP_OK) return parse_error(out, st, at + bad);
        at = hdr;
    } else if (at != hdr) return parse_error(out, DMP_MALFORMED, at);
    else {
        st = validate_extensions((dmp_bytes){NULL, 0U}, opt, v.fields.type, &bad, &ext_status);
        if (st != DMP_OK) return parse_error(out, st, bad);
    }
    if (v.fields.type == DMP_TYPE_ACK && ((opt & (DMP_OPT_ACK_REQ|DMP_OPT_FRAG|DMP_OPT_PAYLOAD_DESC)) != 0U)) return parse_error(out, DMP_MALFORMED, 2U);
    if (v.fields.type == DMP_TYPE_FRAG_STATUS && ((opt & (DMP_OPT_ACK_REQ|DMP_OPT_FRAG|DMP_OPT_PAYLOAD_DESC)) != 0U || (opt & (DMP_OPT_SECURITY | DMP_OPT_INTEGRITY)) == 0U)) return parse_error(out, DMP_MALFORMED, 2U);
    if (((v.fields.type == DMP_TYPE_REQ || v.fields.type == DMP_TYPE_RSP || v.fields.type == DMP_TYPE_ERR || v.fields.type == DMP_TYPE_ACK || v.fields.type == DMP_TYPE_FRAG_STATUS) || (opt & (DMP_OPT_ACK_REQ | DMP_OPT_SECURITY)) != 0U) && (opt & DMP_OPT_SEQ) == 0U) return parse_error(out, DMP_MALFORMED, 2U);
    if (v.fields.type == DMP_TYPE_ERR && ext_status <= 7U && (opt & DMP_OPT_ACK_REQ) != 0U) return parse_error(out, DMP_MALFORMED, 2U);
    if ((opt & DMP_OPT_FRAG) != 0U) {
        uint32_t count, expected;
        uint64_t offset;
        if ((opt & DMP_OPT_SEQ) == 0U || v.fields.fragment.chunk_size == 0U || v.fields.fragment.chunk_size >= v.fields.fragment.total_size) return parse_error(out, DMP_MALFORMED, 2U);
        if (v.fields.fragment.total_size > limits->max_message_bytes) return parse_error(out, DMP_LIMIT_EXHAUSTED, 2U);
        count = 1U + (v.fields.fragment.total_size - 1U) / v.fields.fragment.chunk_size;
        if (count < 2U || v.fields.fragment.index >= count) return parse_error(out, DMP_MALFORMED, 2U);
        if (count > limits->max_fragments) return parse_error(out, DMP_LIMIT_EXHAUSTED, 2U);
        offset = (uint64_t)v.fields.fragment.index * v.fields.fragment.chunk_size;
        expected = v.fields.fragment.total_size - (uint32_t)offset;
        if (expected > v.fields.fragment.chunk_size) expected = v.fields.fragment.chunk_size;
        payload_at = hdr;
        if (trailer_len > input.size - hdr || input.size - hdr - trailer_len != expected) return parse_error(out, DMP_MALFORMED, input.size);
    } else payload_at = hdr;
    if (trailer_len > input.size - hdr) return parse_error(out, DMP_MALFORMED, input.size);
    if (input.size - hdr - trailer_len > limits->max_message_bytes) return parse_error(out, DMP_LIMIT_EXHAUSTED, hdr);
    if ((opt & DMP_OPT_SECURITY) != 0U && input.size - hdr - trailer_len > 65519U) return parse_error(out, DMP_LIMIT_EXHAUSTED, hdr);
    if ((opt & DMP_OPT_ACK_REQ) != 0U && (opt & DMP_OPT_ROUTE) != 0U && v.fields.route.mode == 2U) return parse_error(out, DMP_MALFORMED, 2U);
    if (v.fields.type == DMP_TYPE_ACK && input.size - hdr - trailer_len != 0U) return parse_error(out, DMP_MALFORMED, hdr);
    if (v.fields.type == DMP_TYPE_FRAG_STATUS && input.size - hdr - trailer_len != 4U) return parse_error(out, DMP_MALFORMED, hdr);
    if ((opt & DMP_OPT_ROUTE) != 0U && (opt & DMP_OPT_SEQ) == 0U) return parse_error(out, DMP_MALFORMED, 2U);
    v.frame = input; v.header.data = input.data; v.header.size = hdr;
    v.payload.data = input.data + payload_at; v.payload.size = input.size - hdr - trailer_len;
    v.trailer.data = trailer_len == 0U ? (input.data + input.size) : input.data + input.size - trailer_len;
    v.trailer.size = trailer_len;
    *out = v;
    { dmp_parse_result r = { DMP_OK, input.size }; return r; }
}

dmp_status dmp_core_check_role(const dmp_frame_view *frame,
                               const dmp_role_policy *policy)
{
    size_t at = 0U;
    uint32_t previous = 0U;
    uint32_t unsupported_flag;
    if (frame == NULL || policy == NULL || !dmp_bytes_valid(frame->extensions) ||
        !dmp_bytes_valid(frame->payload) || !dmp_bytes_valid(frame->trailer)) return DMP_INVALID_ARGUMENT;
    if (policy->role != DMP_ROLE_ENDPOINT && policy->role != DMP_ROLE_FORWARDER) return DMP_INVALID_ARGUMENT;
    if (policy->role == DMP_ROLE_ENDPOINT) {
        if (frame->fields.type >= 9U) return DMP_UNSUPPORTED;
        if (frame->fields.type == DMP_TYPE_HELLO) return DMP_UNSUPPORTED;
        if (frame->fields.type == DMP_TYPE_FRAG_STATUS && !policy->selective32) return DMP_UNSUPPORTED;
        if ((frame->fields.options & DMP_OPT_SECURITY) != 0U && frame->fields.security.pn >= UINT64_C(16777216)) return DMP_LIMIT_EXHAUSTED;
        while (at < frame->extensions.size) {
            size_t start = at;
            dmp_extension_view view;
            uint32_t value;
            if (read_extension(frame->extensions, &at, &view, NULL) != EXTENSION_OK ||
                (start != 0U && (view.tag >> 2) <= previous)) return DMP_MALFORMED;
            previous = view.tag >> 2;
            if (previous == 4U || previous == 5U) {
                if (!dmp_decode_extension_u32(view.value, &value, NULL)) return DMP_MALFORMED;
                if (previous == 4U && value == policy->default_service) return DMP_MALFORMED;
                if (previous == 5U && value >= 8U && value <= 63U) return DMP_UNSUPPORTED;
            }
        }
    }
    /* Endpoint SERVICE/STATUS checks take precedence over unknown flags. */
    unsupported_flag = policy->role == DMP_ROLE_ENDPOINT ? 1U : 2U;
    at = 0U;
    previous = 0U;
    while (at < frame->extensions.size) {
        size_t start = at;
        dmp_extension_view view;
        if (read_extension(frame->extensions, &at, &view, NULL) != EXTENSION_OK ||
            (start != 0U && (view.tag >> 2) <= previous)) return DMP_MALFORMED;
        previous = view.tag >> 2;
        if (!known_extension(previous) && (view.tag & unsupported_flag) != 0U) return DMP_UNSUPPORTED;
    }
    return DMP_OK;
}

/* Shared wire validation used by both encoders. */
static dmp_status encode_preflight(const dmp_frame_spec *f, const dmp_core_limits *lim,
                                   size_t *header_size, size_t *total_size)
{
    uint8_t opts = f->fields.options;
    size_t h = f->fields.options == 0U ? 2U : 3U, t = 0U, n;
    uint32_t ext_status = 0U;
    size_t bad = 0U;
    dmp_status st;
    if (!dmp_bytes_valid(f->extensions) ||
        lim->max_frame_bytes < 2U || lim->max_message_bytes == 0U || lim->max_fragments == 0U) return DMP_INVALID_ARGUMENT;
    if (f->fields.type > 31U) return DMP_INVALID_ARGUMENT;
    if (((opts & DMP_OPT_EXT) != 0U) != (f->extensions.size != 0U)) return DMP_MALFORMED;
    if ((opts & DMP_OPT_SEQ) != 0U && !add_size(h, uleb_size(f->fields.seq), &h)) return DMP_LIMIT_EXHAUSTED;
    if ((opts & DMP_OPT_ROUTE) != 0U) {
        if (f->fields.route.ttl > 15U) return DMP_INVALID_ARGUMENT;
        if (f->fields.route.mode > 2U) return DMP_UNSUPPORTED;
        if (!add_size(h, 1U + uleb_size(f->fields.route.source), &h)) return DMP_LIMIT_EXHAUSTED;
        if (f->fields.route.mode == 1U && !add_size(h, uleb_size(f->fields.route.destination), &h)) return DMP_LIMIT_EXHAUSTED;
    }
    if ((opts & DMP_OPT_FRAG) != 0U) {
        uint32_t c = f->fields.fragment.chunk_size, total = f->fields.fragment.total_size;
        uint32_t count;
        uint64_t offset;
        if (c == 0U || c >= total) return DMP_MALFORMED;
        if (total > lim->max_message_bytes) return DMP_LIMIT_EXHAUSTED;
        count = 1U + (total - 1U) / c;
        if (count < 2U || f->fields.fragment.index >= count) return DMP_MALFORMED;
        if (count > lim->max_fragments) return DMP_LIMIT_EXHAUSTED;
        offset = (uint64_t)f->fields.fragment.index * c;
        n = total - (size_t)offset; if (n > c) n = c;
        if (f->payload.size != n) return DMP_MALFORMED;
        if (!add_size(h, uleb_size(f->fields.fragment.index) + uleb_size(c) + uleb_size(total), &h)) return DMP_LIMIT_EXHAUSTED;
    }
    if ((opts & DMP_OPT_PAYLOAD_DESC) != 0U) {
        uint8_t d = f->fields.descriptor.flags;
        if ((d & 0xfcU) != 0U || ((d & 2U) && !(d & 1U))) return DMP_MALFORMED;
        n = 1U + uleb_size(f->fields.descriptor.codec);
        if (d & 1U) n += uleb_size(f->fields.descriptor.schema);
        if (d & 2U) n += uleb_size(f->fields.descriptor.schema_version);
        if (!add_size(h, n, &h)) return DMP_LIMIT_EXHAUSTED;
    }
    if ((opts & DMP_OPT_INTEGRITY) != 0U) {
        if (f->fields.integrity != 1U || (opts & DMP_OPT_SECURITY)) return DMP_UNSUPPORTED;
        ++h; t = 4U;
    }
    if ((opts & DMP_OPT_SECURITY) != 0U) {
        if (f->fields.security.cipher != 1U && f->fields.security.cipher != 2U) return DMP_UNSUPPORTED;
        if (!add_size(h, 1U + uleb_size(f->fields.security.receive_cid) + uleb_size(f->fields.security.pn), &h)) return DMP_LIMIT_EXHAUSTED;
        t = 16U;
    }
    st = validate_extensions(f->extensions, opts, f->fields.type, &bad, &ext_status);
    if (st != DMP_OK) return st;
    if ((opts & DMP_OPT_EXT) != 0U) {
        if (!add_size(h, f->extensions.size, &h)) return DMP_LIMIT_EXHAUSTED;
    }
    if (((f->fields.type == DMP_TYPE_REQ || f->fields.type == DMP_TYPE_RSP || f->fields.type == DMP_TYPE_ERR || f->fields.type == DMP_TYPE_ACK || f->fields.type == DMP_TYPE_FRAG_STATUS) || (opts & (DMP_OPT_ACK_REQ | DMP_OPT_SECURITY | DMP_OPT_FRAG | DMP_OPT_ROUTE)) != 0U) && (opts & DMP_OPT_SEQ) == 0U) return DMP_MALFORMED;
    if ((opts & DMP_OPT_ACK_REQ) != 0U && (opts & DMP_OPT_ROUTE) != 0U && f->fields.route.mode == 2U) return DMP_MALFORMED;
    if (f->fields.type == DMP_TYPE_ACK && (f->payload.size != 0U || (opts & (DMP_OPT_ACK_REQ|DMP_OPT_FRAG|DMP_OPT_PAYLOAD_DESC)) != 0U)) return DMP_MALFORMED;
    if (f->fields.type == DMP_TYPE_FRAG_STATUS && (f->payload.size != 4U || (opts & (DMP_OPT_ACK_REQ|DMP_OPT_FRAG|DMP_OPT_PAYLOAD_DESC)) != 0U || (opts & (DMP_OPT_SECURITY | DMP_OPT_INTEGRITY)) == 0U)) return DMP_MALFORMED;
    if (f->fields.type == DMP_TYPE_ERR && ext_status <= 7U && (opts & DMP_OPT_ACK_REQ) != 0U) return DMP_MALFORMED;
    if (h > DMP_MAX_HEADER_BYTES || !add_size(h, f->payload.size, total_size) || !add_size(*total_size, t, total_size) || *total_size > lim->max_frame_bytes || f->payload.size > lim->max_message_bytes || ((opts & DMP_OPT_SECURITY) != 0U && f->payload.size > 65519U)) return DMP_LIMIT_EXHAUSTED;
    *header_size = h; return DMP_OK;
}

static void emit_header(const dmp_frame_spec *f, uint8_t *out, size_t h)
{
    size_t at = 0U; uint8_t opt = f->fields.options;
    out[at++] = (uint8_t)((DMP_WIRE_VERSION << 5) | f->fields.type); out[at++] = (uint8_t)h;
    if (opt != 0U) out[at++] = opt;
    if (opt & DMP_OPT_SEQ) at += put_uleb(out + at, f->fields.seq);
    if (opt & DMP_OPT_ROUTE) {
        out[at++] = (uint8_t)((f->fields.route.ttl << 4) | f->fields.route.mode);
        at += put_uleb(out + at, f->fields.route.source);
        if (f->fields.route.mode == 1U) at += put_uleb(out + at, f->fields.route.destination);
    }
    if (opt & DMP_OPT_FRAG) {
        at += put_uleb(out + at, f->fields.fragment.index); at += put_uleb(out + at, f->fields.fragment.chunk_size); at += put_uleb(out + at, f->fields.fragment.total_size);
    }
    if (opt & DMP_OPT_PAYLOAD_DESC) {
        out[at++] = f->fields.descriptor.flags; at += put_uleb(out + at, f->fields.descriptor.codec);
        if (f->fields.descriptor.flags & 1U) at += put_uleb(out + at, f->fields.descriptor.schema);
        if (f->fields.descriptor.flags & 2U) at += put_uleb(out + at, f->fields.descriptor.schema_version);
    }
    if (opt & DMP_OPT_INTEGRITY) out[at++] = f->fields.integrity;
    if (opt & DMP_OPT_SECURITY) {
        out[at++] = f->fields.security.cipher; at += put_uleb(out + at, f->fields.security.receive_cid); at += put_uleb(out + at, f->fields.security.pn);
    }
    if (f->extensions.size != 0U) { memcpy(out + at, f->extensions.data, f->extensions.size); at += f->extensions.size; }
    (void)at; (void)h;
}

static dmp_status encode_common(const dmp_frame_spec *f, const dmp_core_limits *lim,
                                dmp_buffer out, size_t *written, int header_only)
{
    size_t h = 0U, total = 0U, required;
    dmp_status st;
    if (written == NULL) return DMP_INVALID_ARGUMENT;
    if (f != NULL && (dmp_ranges_overlap(written, sizeof *written, f, sizeof *f) ||
        dmp_ranges_overlap(written, sizeof *written, f->extensions.data, f->extensions.size) ||
        dmp_ranges_overlap(written, sizeof *written, f->payload.data, f->payload.size) ||
        dmp_ranges_overlap(written, sizeof *written, f->trailer.data, f->trailer.size))) return DMP_INVALID_ARGUMENT;
    if ((lim != NULL && dmp_ranges_overlap(written, sizeof *written, lim, sizeof *lim)) ||
        (out.data != NULL && dmp_ranges_overlap(written, sizeof *written, out.data, out.capacity))) return DMP_INVALID_ARGUMENT;
    *written = 0U;
    if (f == NULL || lim == NULL || !dmp_bytes_valid(f->extensions) ||
        (!header_only && (!dmp_bytes_valid(f->payload) || !dmp_bytes_valid(f->trailer))) ||
        (out.data == NULL && out.capacity != 0U)) return DMP_INVALID_ARGUMENT;
    st = encode_preflight(f, lim, &h, &total);
    if (st != DMP_OK) return st;
    required = header_only ? h : total;
    if (out.capacity < required || (required != 0U && out.data == NULL)) return DMP_LIMIT_EXHAUSTED;
    if ((!header_only && f->payload.size != 0U && f->payload.data == NULL) ||
        f->trailer.size != ((f->fields.options & DMP_OPT_SECURITY) ? 16U : (f->fields.options & DMP_OPT_INTEGRITY) ? 4U : 0U) ||
        (!header_only && f->trailer.size != 0U && f->trailer.data == NULL)) return DMP_INVALID_ARGUMENT;
    if (dmp_ranges_overlap(written, sizeof *written, out.data, out.capacity) ||
        dmp_ranges_overlap(written, sizeof *written, f, sizeof *f) ||
        dmp_ranges_overlap(written, sizeof *written, f->extensions.data, f->extensions.size) ||
        dmp_ranges_overlap(written, sizeof *written, f->payload.data, f->payload.size) ||
        dmp_ranges_overlap(written, sizeof *written, f->trailer.data, f->trailer.size)) return DMP_INVALID_ARGUMENT;
    if (dmp_ranges_overlap(out.data, required, f, sizeof *f) ||
        dmp_ranges_overlap(out.data, required, lim, sizeof *lim) ||
        dmp_ranges_overlap(out.data, required, f->extensions.data, f->extensions.size) ||
        dmp_ranges_overlap(out.data, required, f->payload.data, f->payload.size) ||
        dmp_ranges_overlap(out.data, required, f->trailer.data, f->trailer.size)) return DMP_INVALID_ARGUMENT;
    emit_header(f, out.data, h);
    if (!header_only) {
        if (f->payload.size != 0U) memcpy(out.data + h, f->payload.data, f->payload.size);
        if (f->trailer.size != 0U) memcpy(out.data + h + f->payload.size, f->trailer.data, f->trailer.size);
    }
    *written = required; return DMP_OK;
}
dmp_status dmp_core_encode_header(const dmp_frame_spec *f, const dmp_core_limits *lim,
                                  dmp_buffer out, size_t *written)
{ return encode_common(f, lim, out, written, 1); }
dmp_status dmp_core_encode(const dmp_frame_spec *f, const dmp_core_limits *lim,
                           dmp_buffer out, size_t *written)
{ return encode_common(f, lim, out, written, 0); }

dmp_status dmp_extension_next(dmp_bytes extensions, size_t *cursor,
                              dmp_extension_view *out)
{
    dmp_extension_view v;
    if (!dmp_bytes_valid(extensions) || cursor == NULL || out == NULL || *cursor > extensions.size) return DMP_INVALID_ARGUMENT;
    if (*cursor == extensions.size) return DMP_INCOMPLETE;
    if (read_extension(extensions, cursor, &v, NULL) != EXTENSION_OK) return DMP_MALFORMED;
    *out = v;
    return DMP_OK;
}
