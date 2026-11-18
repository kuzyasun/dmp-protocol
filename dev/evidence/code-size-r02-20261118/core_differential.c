#include "dmp/core.h"

#include <stdio.h>
#include <string.h>

dmp_parse_result r01_parse(dmp_bytes, const dmp_core_limits *, dmp_frame_view *);
dmp_status r01_role(const dmp_frame_view *, const dmp_role_policy *);
dmp_status r01_next(dmp_bytes, size_t *, dmp_extension_view *);
dmp_status r01_encode(const dmp_frame_spec *, const dmp_core_limits *, dmp_buffer, size_t *);
dmp_status r01_encode_header(const dmp_frame_spec *, const dmp_core_limits *, dmp_buffer, size_t *);

#define CHECK(test) do { \
    if (!(test)) { \
        fprintf(stderr, "trial %u, line %d: %s\n", trial, __LINE__, #test); \
        return 1; \
    } \
} while (0)

static uint32_t state = UINT32_C(0x791ab251);

static uint32_t next_word(void)
{
    state ^= state << 13U;
    state ^= state >> 17U;
    state ^= state << 5U;
    return state;
}

static bool same_span(dmp_bytes a, dmp_bytes b)
{
    return a.data == b.data && a.size == b.size;
}

static size_t make_extensions(uint8_t *bytes, size_t capacity, bool structured)
{
    static const uint8_t tags[] = {1U, 5U, 11U, 15U, 17U, 21U, 25U, 28U, 29U, 30U, 32U};
    size_t total = next_word() % (capacity + 1U);
    size_t at = 0U;

    if (structured) {
        while (total - at >= 2U) {
            size_t left = total - at - 2U;
            size_t len = next_word() % (left + 1U);
            size_t i;
            bytes[at++] = tags[next_word() % sizeof tags];
            bytes[at++] = (uint8_t)len;
            for (i = 0; i < len; ++i) bytes[at++] = (uint8_t)(next_word() & 0x8fU);
        }
        return at;
    }
    while (at < total) bytes[at++] = (uint8_t)next_word();
    return at;
}

int main(void)
{
    const dmp_core_limits limits = {96U, 96U, 32U};
    unsigned trial;

    for (trial = 0U; trial < 100000U; ++trial) {
        unsigned protected_frame = trial & 1U;
        size_t prefix = protected_frame ? 7U : 3U;
        uint8_t raw[96] = {0};
        size_t length = make_extensions(raw + prefix, 48U, (trial & 2U) != 0U);
        dmp_bytes ext = {raw + prefix, length};
        size_t ca = next_word() % (length + 2U), cb = ca;
        dmp_extension_view ea = {0x1234U, {raw, 1U}}, eb = ea;
        dmp_frame_view va = {0}, vb = {0};
        dmp_frame_view synthetic = {.fields = {.type = (uint8_t)(next_word() % 9U)}, .extensions = ext};
        dmp_role_policy endpoint = {DMP_ROLE_ENDPOINT, next_word() % 4U, (trial & 4U) != 0U};
        dmp_role_policy forwarder = {DMP_ROLE_FORWARDER, 1U, false};
        dmp_parse_result pa, pb;
        dmp_frame_spec spec = {0};
        uint8_t oa[96], ob[96];
        size_t na = 19U, nb = 19U;

        CHECK(r01_next(ext, &ca, &ea) == dmp_extension_next(ext, &cb, &eb));
        CHECK(ca == cb && ea.tag == eb.tag && same_span(ea.value, eb.value));
        CHECK(r01_role(&synthetic, &endpoint) == dmp_core_check_role(&synthetic, &endpoint));
        CHECK(r01_role(&synthetic, &forwarder) == dmp_core_check_role(&synthetic, &forwarder));

        raw[0] = (uint8_t)(0x40U | synthetic.fields.type);
        raw[1] = (uint8_t)(prefix + length);
        raw[2] = protected_frame ? 0xc1U : 0x80U;
        raw[3] = protected_frame ? 1U : raw[3];
        raw[4] = protected_frame ? 1U : raw[4];
        raw[5] = protected_frame ? 1U : raw[5];
        raw[6] = protected_frame ? 1U : raw[6];
        dmp_bytes input = {raw, prefix + length + 1U + 16U * protected_frame};
        pa = r01_parse(input, &limits, &va);
        pb = dmp_core_parse(input, &limits, &vb);
        CHECK(pa.status == pb.status && pa.offset == pb.offset);
        CHECK(same_span(va.frame, vb.frame) && same_span(va.extensions, vb.extensions));
        CHECK(same_span(va.payload, vb.payload) && same_span(va.trailer, vb.trailer));
        CHECK(va.fields.type == vb.fields.type && va.fields.options == vb.fields.options);

        spec.fields = synthetic.fields;
        spec.fields.options = raw[2];
        spec.fields.seq = 1U;
        spec.fields.security = (dmp_security_fields){1U, 1U, 1U};
        spec.extensions = ext;
        spec.payload = (dmp_bytes){raw + prefix + length, 1U};
        spec.trailer = (dmp_bytes){raw + prefix + length + 1U, 16U * protected_frame};
        memset(oa, 0xa5, sizeof oa);
        memset(ob, 0xa5, sizeof ob);
        CHECK(r01_encode(&spec, &limits, (dmp_buffer){oa, sizeof oa}, &na) ==
              dmp_core_encode(&spec, &limits, (dmp_buffer){ob, sizeof ob}, &nb));
        CHECK(na == nb && memcmp(oa, ob, sizeof oa) == 0);
        CHECK(r01_encode_header(&spec, &limits, (dmp_buffer){oa, sizeof oa}, &na) ==
              dmp_core_encode_header(&spec, &limits, (dmp_buffer){ob, sizeof ob}, &nb));
        CHECK(na == nb && memcmp(oa, ob, sizeof oa) == 0);
    }
    printf("Matched %u seeded Core trials\n", trial);
    return 0;
}
