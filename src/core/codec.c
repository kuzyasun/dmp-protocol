#include "dmp/core.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

typedef struct { uint64_t value; size_t next; } varint;

static int valid_bytes(dmp_bytes b) { return b.data != NULL || b.size == 0U; }
static int add_size(size_t a, size_t b, size_t *out)
{
    if (b > SIZE_MAX - a) return 0;
    *out = a + b;
    return 1;
}
static int overlap(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t ap, bp;
    if (an == 0U || bn == 0U || a == NULL || b == NULL) return 0;
    ap = (uintptr_t)a; bp = (uintptr_t)b;
    if (ap > UINTPTR_MAX - an || bp > UINTPTR_MAX - bn) return 1;
    return ap < bp + bn && bp < ap + an;
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
static dmp_parse_result parse_error(dmp_frame_view *out, dmp_status status,
                                    size_t at)
{
    memset(out, 0, sizeof *out);
    { dmp_parse_result r = { status, at }; return r; }
}

static int known_extension(uint32_t id) { return id >= 1U && id <= 6U; }
static dmp_status validate_extensions(dmp_bytes ext, uint8_t options,
                                      uint8_t type, size_t *bad,
                                      uint32_t *reply_seq, int *has_reply,
                                      uint32_t *service, int *has_service,
                                      uint32_t *status, int *has_status)
{
    size_t at = 0U;
    uint32_t prev = 0U;
    int have_prev = 0;
    while (at < ext.size) {
        size_t start = at, value_at, end;
        uint32_t tag, len, id;
        uint8_t flags;
        dmp_bytes value;
        if (!read_u32(ext, &at, &tag, bad)) return DMP_MALFORMED;
        if (!read_u32(ext, &at, &len, bad)) return DMP_MALFORMED;
        id = tag >> 2; flags = (uint8_t)(tag & 3U); value_at = at;
        if (have_prev && id <= prev) { *bad = start; return DMP_MALFORMED; }
        prev = id; have_prev = 1;
        if ((size_t)len > ext.size - at) { *bad = ext.size; return DMP_MALFORMED; }
        end = at + (size_t)len;
        value.data = len == 0U ? (ext.data == NULL ? NULL : ext.data + at) : ext.data + at;
        value.size = len;
        if (known_extension(id)) {
            uint8_t expected = (id == 1U || id == 4U || id == 5U || id == 6U) ? 1U : 3U;
            if (flags != expected) { *bad = start; return DMP_MALFORMED; }
            if (id == 1U) {
                size_t p = 0U; uint32_t ns, origin, seq;
                if ((options & DMP_OPT_SECURITY) != 0U) {
                    if (!read_u32(value, &p, &seq, bad)) { *bad += value_at; return DMP_MALFORMED; }
                    if (p != value.size) { *bad = value_at + p; return DMP_MALFORMED; }
                    *reply_seq = seq;
                } else {
                    if (!read_u32(value, &p, &ns, bad) || !read_u32(value, &p, &origin, bad)) { *bad += value_at; return DMP_MALFORMED; }
                    if (value.size - p < 8U) { *bad = end; return DMP_MALFORMED; }
                    p += 8U;
                    if (!read_u32(value, &p, &seq, bad)) { *bad += value_at; return DMP_MALFORMED; }
                    if (p != value.size) { *bad = value_at + p; return DMP_MALFORMED; }
                    (void)ns; (void)origin; *reply_seq = seq;
                }
                *has_reply = 1;
            } else if (id == 2U) {
                size_t p = 0U; uint32_t ns;
                if (!read_u32(value, &p, &ns, bad)) { *bad += value_at; return DMP_MALFORMED; }
                if (value.size - p != 8U) { *bad = value.size - p < 8U ? end : value_at + p + 8U; return DMP_MALFORMED; }
            } else if (id == 3U || id == 4U || id == 5U) {
                size_t p = 0U; uint32_t n;
                if (!read_u32(value, &p, &n, bad)) { *bad += value_at; return DMP_MALFORMED; }
                if (p != value.size) { *bad = value_at + p; return DMP_MALFORMED; }
                if (id == 3U && (options & DMP_OPT_ROUTE) != 0U) { *bad = start; return DMP_MALFORMED; }
                if (id == 4U) { *service = n; *has_service = 1; }
                if (id == 5U) { *status = n; *has_status = 1; }
            } else if (id == 6U) {
                if (len != 16U || (options & DMP_OPT_SECURITY) == 0U) { *bad = value_at; return DMP_MALFORMED; }
            }
        }
        if (type == DMP_TYPE_FRAG_STATUS && (id == 5U || id == 6U)) { *bad = start; return DMP_MALFORMED; }
        at = end;
    }
    if (((options & DMP_OPT_EXT) != 0U) != (ext.size != 0U)) { *bad = 2U; return DMP_MALFORMED; }
    if ((type == DMP_TYPE_ACK || type == DMP_TYPE_RSP || type == DMP_TYPE_ERR || type == DMP_TYPE_FRAG_STATUS) && !*has_reply) {
        *bad = ext.size == 0U ? 2U : 0U; return DMP_MALFORMED;
    }
    if (type == DMP_TYPE_ERR && !*has_status) { *bad = ext.size == 0U ? 2U : 0U; return DMP_MALFORMED; }
    if (type == DMP_TYPE_ACK && *has_status) { *bad = 2U; return DMP_MALFORMED; }
    (void)reply_seq;
    return DMP_OK;
}

dmp_parse_result dmp_core_parse(dmp_bytes input, const dmp_core_limits *limits,
                                dmp_frame_view *out)
{
    dmp_frame_view v;
    size_t at = 0U, bad = 0U, trailer_len = 0U, payload_at;
    dmp_bytes head;
    uint8_t vt, hdr, opt = 0U;
    uint32_t ext_reply = 0U, service = 0U, ext_status = 0U;
    int has_reply = 0, has_service = 0, has_status = 0;
    dmp_status st;
    if (out == NULL) { dmp_parse_result r = { DMP_INVALID_ARGUMENT, 0U }; return r; }
    memset(out, 0, sizeof *out);
    if (!valid_bytes(input) || limits == NULL || limits->max_frame_bytes < 2U ||
        limits->max_message_bytes == 0U || limits->max_fragments < 2U) return parse_error(out, DMP_INVALID_ARGUMENT, 0U);
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
        st = validate_extensions(v.extensions, opt, v.fields.type, &bad, &ext_reply, &has_reply, &service, &has_service, &ext_status, &has_status);
        if (st != DMP_OK) return parse_error(out, st, at + bad);
        at = hdr;
    } else if (at != hdr) return parse_error(out, DMP_MALFORMED, at);
    else {
        st = validate_extensions((dmp_bytes){NULL, 0U}, opt, v.fields.type, &bad, &ext_reply, &has_reply, &service, &has_service, &ext_status, &has_status);
        if (st != DMP_OK) return parse_error(out, st, bad);
    }
    if (v.fields.type == DMP_TYPE_ACK && ((opt & (DMP_OPT_ACK_REQ|DMP_OPT_FRAG|DMP_OPT_PAYLOAD_DESC)) != 0U)) return parse_error(out, DMP_MALFORMED, 2U);
    if (v.fields.type == DMP_TYPE_FRAG_STATUS && ((opt & (DMP_OPT_ACK_REQ|DMP_OPT_FRAG|DMP_OPT_PAYLOAD_DESC)) != 0U || (opt & DMP_OPT_SECURITY) == 0U)) return parse_error(out, DMP_MALFORMED, 2U);
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
    if (frame == NULL || policy == NULL || !valid_bytes(frame->extensions) || !valid_bytes(frame->payload) || !valid_bytes(frame->trailer)) return DMP_INVALID_ARGUMENT;
    if (policy->role != DMP_ROLE_ENDPOINT && policy->role != DMP_ROLE_FORWARDER) return DMP_INVALID_ARGUMENT;
    if (policy->role == DMP_ROLE_ENDPOINT) {
        if (frame->fields.type >= 9U) return DMP_UNSUPPORTED;
        if (frame->fields.type == DMP_TYPE_HELLO) return DMP_UNSUPPORTED;
        if (frame->fields.type == DMP_TYPE_FRAG_STATUS && !policy->selective32) return DMP_UNSUPPORTED;
        if ((frame->fields.options & DMP_OPT_SECURITY) != 0U && frame->fields.security.pn >= UINT64_C(16777216)) return DMP_LIMIT_EXHAUSTED;
        {
            while (at < frame->extensions.size) {
                uint32_t tag, len; size_t p = at;
                if (!read_u32(frame->extensions, &p, &tag, &at) || !read_u32(frame->extensions, &p, &len, &at)) return DMP_MALFORMED;
                if ((at != 0U && (tag >> 2) <= previous) || len > frame->extensions.size - p) return DMP_MALFORMED;
                previous = tag >> 2;
                if (previous == 4U) {
                    size_t q = p; uint32_t service;
                    if (!read_u32(frame->extensions, &q, &service, &at) || q != p + len) return DMP_MALFORMED;
                    if (service == policy->default_service) return DMP_MALFORMED;
                }
                if (previous == 5U) {
                    size_t q = p; uint32_t status;
                    if (!read_u32(frame->extensions, &q, &status, &at) || q != p + len) return DMP_MALFORMED;
                    if (status >= 8U && status <= 63U) return DMP_UNSUPPORTED;
                }
                at = p + len;
            }
        }
    }
    if (policy->role == DMP_ROLE_FORWARDER) {
        at = 0U; previous = 0U;
        while (at < frame->extensions.size) {
            uint32_t tag, len; size_t p = at, bad = at;
            if (!read_u32(frame->extensions, &p, &tag, &bad) || !read_u32(frame->extensions, &p, &len, &bad) || len > frame->extensions.size - p) return DMP_MALFORMED;
            if (at != 0U && (tag >> 2) <= previous) return DMP_MALFORMED;
            previous = tag >> 2;
            if (!known_extension(previous) && (tag & 2U) != 0U) return DMP_UNSUPPORTED;
            at = p + len;
        }
    } else {
        at = 0U; previous = 0U;
        while (at < frame->extensions.size) {
            uint32_t tag, len; size_t p = at, bad = at;
            if (!read_u32(frame->extensions, &p, &tag, &bad) || !read_u32(frame->extensions, &p, &len, &bad) || len > frame->extensions.size - p) return DMP_MALFORMED;
            if (at != 0U && (tag >> 2) <= previous) return DMP_MALFORMED;
            previous = tag >> 2;
            if (!known_extension(previous) && (tag & 1U) != 0U) return DMP_UNSUPPORTED;
            at = p + len;
        }
    }
    return DMP_OK;
}

/* Shared wire validation used by both encoders. */
static dmp_status encode_preflight(const dmp_frame_spec *f, const dmp_core_limits *lim,
                                   size_t *header_size, size_t *total_size)
{
    uint8_t opts = f->fields.options;
    size_t h = f->fields.options == 0U ? 2U : 3U, t = 0U, n;
    uint32_t dummy[4] = {0U,0U,0U,0U}; int flags[3] = {0,0,0}; size_t bad = 0U;
    dmp_status st;
    if (!valid_bytes(f->extensions) ||
        lim->max_frame_bytes < 2U || lim->max_message_bytes == 0U || lim->max_fragments < 2U) return DMP_INVALID_ARGUMENT;
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
    st = validate_extensions(f->extensions, opts, f->fields.type, &bad, &dummy[0], &flags[0], &dummy[1], &flags[1], &dummy[2], &flags[2]);
    if (st != DMP_OK) return st;
    if ((opts & DMP_OPT_EXT) != 0U) {
        if (!add_size(h, f->extensions.size, &h)) return DMP_LIMIT_EXHAUSTED;
    }
    if (((f->fields.type == DMP_TYPE_REQ || f->fields.type == DMP_TYPE_RSP || f->fields.type == DMP_TYPE_ERR || f->fields.type == DMP_TYPE_ACK || f->fields.type == DMP_TYPE_FRAG_STATUS) || (opts & (DMP_OPT_ACK_REQ | DMP_OPT_SECURITY | DMP_OPT_FRAG | DMP_OPT_ROUTE)) != 0U) && (opts & DMP_OPT_SEQ) == 0U) return DMP_MALFORMED;
    if ((opts & DMP_OPT_ACK_REQ) != 0U && (opts & DMP_OPT_ROUTE) != 0U && f->fields.route.mode == 2U) return DMP_MALFORMED;
    if (f->fields.type == DMP_TYPE_ACK && (f->payload.size != 0U || (opts & (DMP_OPT_ACK_REQ|DMP_OPT_FRAG|DMP_OPT_PAYLOAD_DESC)) != 0U)) return DMP_MALFORMED;
    if (f->fields.type == DMP_TYPE_FRAG_STATUS && (f->payload.size != 4U || (opts & (DMP_OPT_ACK_REQ|DMP_OPT_FRAG|DMP_OPT_PAYLOAD_DESC)) != 0U || (opts & DMP_OPT_SECURITY) == 0U)) return DMP_MALFORMED;
    if (f->fields.type == DMP_TYPE_ERR && flags[2] && dummy[2] <= 7U && (opts & DMP_OPT_ACK_REQ) != 0U) return DMP_MALFORMED;
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
    if (f != NULL && (overlap(written, sizeof *written, f, sizeof *f) ||
        overlap(written, sizeof *written, f->extensions.data, f->extensions.size) ||
        overlap(written, sizeof *written, f->payload.data, f->payload.size) ||
        overlap(written, sizeof *written, f->trailer.data, f->trailer.size))) return DMP_INVALID_ARGUMENT;
    if ((lim != NULL && overlap(written, sizeof *written, lim, sizeof *lim)) ||
        (out.data != NULL && overlap(written, sizeof *written, out.data, out.capacity))) return DMP_INVALID_ARGUMENT;
    *written = 0U;
    if (f == NULL || lim == NULL || !valid_bytes(f->extensions) ||
        (!header_only && (!valid_bytes(f->payload) || !valid_bytes(f->trailer))) ||
        (out.data == NULL && out.capacity != 0U)) return DMP_INVALID_ARGUMENT;
    st = encode_preflight(f, lim, &h, &total);
    if (st != DMP_OK) return st;
    required = header_only ? h : total;
    if (out.capacity < required || (required != 0U && out.data == NULL)) return DMP_LIMIT_EXHAUSTED;
    if ((!header_only && f->payload.size != 0U && f->payload.data == NULL) ||
        f->trailer.size != ((f->fields.options & DMP_OPT_SECURITY) ? 16U : (f->fields.options & DMP_OPT_INTEGRITY) ? 4U : 0U) ||
        (!header_only && f->trailer.size != 0U && f->trailer.data == NULL)) return DMP_INVALID_ARGUMENT;
    if (overlap(written, sizeof *written, out.data, out.capacity) || overlap(written, sizeof *written, f, sizeof *f) ||
        overlap(written, sizeof *written, f->extensions.data, f->extensions.size) ||
        overlap(written, sizeof *written, f->payload.data, f->payload.size) || overlap(written, sizeof *written, f->trailer.data, f->trailer.size)) return DMP_INVALID_ARGUMENT;
    if (overlap(out.data, required, f, sizeof *f) || overlap(out.data, required, lim, sizeof *lim) ||
        overlap(out.data, required, f->extensions.data, f->extensions.size) ||
        overlap(out.data, required, f->payload.data, f->payload.size) ||
        overlap(out.data, required, f->trailer.data, f->trailer.size)) return DMP_INVALID_ARGUMENT;
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
    size_t at, bad = 0U; uint32_t tag, len;
    dmp_extension_view v;
    if (!valid_bytes(extensions) || cursor == NULL || out == NULL || *cursor > extensions.size) return DMP_INVALID_ARGUMENT;
    if (*cursor == extensions.size) return DMP_INCOMPLETE;
    at = *cursor;
    if (!read_u32(extensions, &at, &tag, &bad) || !read_u32(extensions, &at, &len, &bad) || len > extensions.size - at) return DMP_MALFORMED;
    v.tag = tag; v.value.data = len == 0U && extensions.data == NULL ? NULL : extensions.data + at; v.value.size = len;
    *cursor = at + len; *out = v; return DMP_OK;
}
