#include "dmp/core.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { (void)fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #x); return 1; } } while (0)

static const dmp_core_limits limits = { 4096U, 1024U, 32U };
static int parse_ok(const uint8_t *p, size_t n, dmp_frame_view *v)
{
    dmp_parse_result r = dmp_core_parse((dmp_bytes){p, n}, &limits, v);
    return r.status == DMP_OK && r.offset == n;
}
static int test_independent_golden_vectors(void)
{
    static const uint8_t minimal[] = {0x45,0x02,0xaa,0xbb};
    static const uint8_t request[] = {0x40,0x04,0x03,0x2a,0xaa};
    static const uint8_t ack[] = {0x46,0x11,0x81,0x08,0x05,0x0b,0x01,0x0a,0x07,0,0,0,0,0,0,0,0x2a};
    static const uint8_t routed[] = {0x45,0x11,0x85,0x51,0x30,0x1b,0x0b,0x09,0x01,0x07,0,0,0,0,0,0,0xaa};
    static const uint8_t frag[] = {0x47,0x07,0x09,0x09,0x01,0x02,0x03,0xcc};
    static const uint8_t desc[] = {0x47,0x07,0x20,0x03,0x00,0x2a,0x01,0xde,0xad};
    static const uint8_t unknown[] = {0x47,0x08,0x80,0x81,0x02,0x02,0xde,0xad};
    dmp_frame_view v; dmp_role_policy role;
    CHECK(parse_ok(minimal, sizeof minimal, &v));
    CHECK(v.fields.type == DMP_TYPE_TELEM && v.header.size == 2U && v.payload.size == 2U && v.payload.data[0] == 0xaa);
    CHECK(parse_ok(request, sizeof request, &v));
    CHECK(v.fields.type == DMP_TYPE_REQ && v.fields.seq == 42U && v.payload.data[0] == 0xaa);
    CHECK(parse_ok(ack, sizeof ack, &v));
    CHECK(v.fields.type == DMP_TYPE_ACK && v.fields.seq == 8U && v.payload.size == 0U);
    CHECK(parse_ok(routed, sizeof routed, &v));
    CHECK(v.fields.route.ttl == 3U && v.fields.route.source == 27U && v.extensions.size == 11U);
    CHECK(parse_ok(frag, sizeof frag, &v));
    CHECK(v.fields.fragment.index == 1U && v.payload.size == 1U && v.payload.data[0] == 0xcc);
    CHECK(parse_ok(desc, sizeof desc, &v));
    CHECK(v.fields.descriptor.codec == 0U && v.fields.descriptor.schema == 42U && v.fields.descriptor.schema_version == 1U);
    CHECK(parse_ok(unknown, sizeof unknown, &v));
    role = (dmp_role_policy){DMP_ROLE_ENDPOINT, 1U, false};
    CHECK(dmp_core_check_role(&v, &role) == DMP_UNSUPPORTED);
    role.role = DMP_ROLE_FORWARDER;
    CHECK(dmp_core_check_role(&v, &role) == DMP_OK);
    return 0;
}
static int test_uleb_boundaries(void)
{
    /* Canonical UINT32_MAX and UINT64_MAX are independent literal fixtures. */
    static const uint8_t u32max[] = {0x47,0x08,0x01,0xff,0xff,0xff,0xff,0x0f,0xaa};
    static const uint8_t u32overflow[] = {0x47,0x08,0x01,0x80,0x80,0x80,0x80,0x10,0xaa};
    static const uint8_t u32overlong[] = {0x47,0x05,0x01,0x80,0x00,0xaa};
    static const uint8_t u64max[] = {0x47,0x10,0x41,0x01,0x01,0x01,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x01,0xaa,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    static const uint8_t u64overflow[] = {0x47,0x10,0x41,0x01,0x01,0x01,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x02,0xaa,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    static const uint8_t u64overlong[] = {0x47,0x08,0x41,0x01,0x01,0x01,0x80,0x00,0xaa,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    static const uint8_t u32truncated[] = {0x47,0x05,0x01,0x80,0x80};
    static const uint8_t pn_endpoint_limit[] = {0x47,0x0a,0x41,0x01,0x01,0x01,0x80,0x80,0x80,0x08,0xaa,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    dmp_frame_view v;
    CHECK(parse_ok(u32max, sizeof u32max, &v) && v.fields.seq == UINT32_MAX);
    CHECK(!parse_ok(u32overflow, sizeof u32overflow, &v));
    CHECK(!parse_ok(u32overlong, sizeof u32overlong, &v));
    CHECK(!parse_ok(u32truncated, sizeof u32truncated, &v));
    CHECK(parse_ok(u64max, sizeof u64max, &v) && v.fields.security.pn == UINT64_MAX);
    CHECK(!parse_ok(u64overflow, sizeof u64overflow, &v));
    CHECK(!parse_ok(u64overlong, sizeof u64overlong, &v));
    CHECK(parse_ok(pn_endpoint_limit,sizeof pn_endpoint_limit,&v));
    {
        dmp_role_policy p={DMP_ROLE_ENDPOINT,1U,false};
        CHECK(dmp_core_check_role(&v,&p)==DMP_LIMIT_EXHAUSTED);
        p.role=DMP_ROLE_FORWARDER; CHECK(dmp_core_check_role(&v,&p)==DMP_OK);
    }
    return 0;
}
static int test_malformed_and_limits(void)
{
    static const uint8_t short_hdr[] = {0x45,0x01};
    static const uint8_t long_hdr[] = {0x45,0x04,0x01};
    static const uint8_t no_options[] = {0x45,0x03,0x00};
    static const uint8_t unexplained[] = {0x45,0x05,0x01,0x01,0xaa};
    static const uint8_t unknown_integrity[] = {0x45,0x04,0x10,0x02};
    static const uint8_t frag_bad_len[] = {0x47,0x07,0x09,0x09,0x01,0x02,0x03,0xcc,0xdd};
    dmp_frame_view v; dmp_parse_result r;
    memset(&v, 0xa5, sizeof v);
    r = dmp_core_parse((dmp_bytes){short_hdr,sizeof short_hdr}, &limits, &v);
    CHECK(r.status == DMP_MALFORMED && r.offset == 1U);
    CHECK(v.frame.data == NULL && v.frame.size == 0U && v.fields.type == 0U);
    r = dmp_core_parse((dmp_bytes){long_hdr,sizeof long_hdr}, &limits, &v);
    CHECK(r.status == DMP_MALFORMED && r.offset == sizeof long_hdr);
    CHECK(dmp_core_parse((dmp_bytes){no_options,sizeof no_options}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){unexplained,sizeof unexplained}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){unknown_integrity,sizeof unknown_integrity}, &limits, &v).status == DMP_UNSUPPORTED);
    CHECK(dmp_core_parse((dmp_bytes){frag_bad_len,sizeof frag_bad_len}, &limits, &v).status == DMP_MALFORMED);
    return 0;
}
static int test_roles_and_safe_unknown(void)
{
    static const uint8_t unknown_safe[] = {0x47,0x06,0x80,0x80,0x02,0x00,0xaa};
    static const uint8_t unknown_unsafe[] = {0x47,0x06,0x80,0x82,0x02,0x00,0xaa};
    dmp_frame_view v; dmp_role_policy role = {DMP_ROLE_ENDPOINT, 1U, false};
    CHECK(parse_ok(unknown_safe, sizeof unknown_safe, &v));
    CHECK(dmp_core_check_role(&v, &role) == DMP_OK);
    role.role = DMP_ROLE_FORWARDER;
    CHECK(dmp_core_check_role(&v, &role) == DMP_OK);
    CHECK(parse_ok(unknown_unsafe, sizeof unknown_unsafe, &v));
    CHECK(dmp_core_check_role(&v, &role) == DMP_UNSUPPORTED);
    return 0;
}
static int test_encoder_preflight_and_header_placeholders(void)
{
    static const uint8_t expected[] = {0x45,0x02,0xaa,0xbb};
    uint8_t output[8], before[8]; size_t written = 123U;
    dmp_frame_spec f; dmp_core_limits lim = limits;
    memset(&f, 0, sizeof f); memset(output, 0x5a, sizeof output);
    f.fields.type = DMP_TYPE_TELEM; f.payload = (dmp_bytes){expected + 2,2U};
    CHECK(dmp_core_encode(&f, &lim, (dmp_buffer){output,sizeof output}, &written) == DMP_OK);
    CHECK(written == sizeof expected && memcmp(output, expected, sizeof expected) == 0);
    f.payload.data = NULL;
    memset(output, 0x5a, sizeof output); memcpy(before, output, sizeof output); written = 99U;
    CHECK(dmp_core_encode_header(&f, &lim, (dmp_buffer){output,sizeof output}, &written) == DMP_OK);
    CHECK(written == 2U && output[0] == 0x45 && output[1] == 2U && output[2] == before[2]);
    memcpy(before, output, sizeof output);
    written = 99U; CHECK(dmp_core_encode(&f, &lim, (dmp_buffer){output,sizeof output}, &written) == DMP_INVALID_ARGUMENT);
    CHECK(written == 0U && memcmp(output, before, sizeof output) == 0);
    lim.max_frame_bytes = 3U; written = 99U;
    CHECK(dmp_core_encode(&((dmp_frame_spec){.fields={.type=DMP_TYPE_TELEM},.payload={expected+2,2U}}), &lim, (dmp_buffer){output,sizeof output}, &written) == DMP_LIMIT_EXHAUSTED);
    CHECK(written == 0U && memcmp(output, before, sizeof output) == 0);
    return 0;
}
static int test_extension_iterator(void)
{
    static const uint8_t ext[] = {0x80,0x02,0x00}; /* Raw tag 256, unknown safe ID 64. */
    dmp_extension_view v = {77U,{(const uint8_t *)"x",1U}}; size_t cursor = 0U;
    CHECK(dmp_extension_next((dmp_bytes){ext,sizeof ext}, &cursor, &v) == DMP_OK);
    CHECK(v.tag == 256U && v.value.size == 0U && cursor == sizeof ext);
    CHECK(dmp_extension_next((dmp_bytes){ext,sizeof ext}, &cursor, &v) == DMP_INCOMPLETE);
    CHECK(cursor == sizeof ext && v.tag == 256U);
    return 0;
}
static int test_extension_structure_and_roles(void)
{
    static const uint8_t unknown_safe[] = {0x47,0x06,0x80,0x80,0x02,0x00,0xaa};
    static const uint8_t known_empty_reply[] = {0x45,0x06,0x80,0x05,0x00,0xaa};
    static const uint8_t duplicate[] = {0x47,0x09,0x80,0x80,0x02,0x00,0x80,0x02,0x00,0xaa};
    static const uint8_t unordered[] = {0x47,0x09,0x80,0x85,0x02,0x00,0x80,0x02,0x00,0xaa};
    static const uint8_t crossing[] = {0x47,0x06,0x80,0x80,0x02,0x02,0xaa};
    static const uint8_t raw_tags[4][7] = {
        {0x47,0x06,0x80,0x80,0x02,0x00,0xaa}, {0x47,0x06,0x80,0x81,0x02,0x00,0xaa},
        {0x47,0x06,0x80,0x82,0x02,0x00,0xaa}, {0x47,0x06,0x80,0x83,0x02,0x00,0xaa}
    };
    dmp_frame_view v; dmp_role_policy role = {DMP_ROLE_ENDPOINT,1U,false}; unsigned i;
    CHECK(parse_ok(unknown_safe, sizeof unknown_safe, &v));
    CHECK(dmp_core_check_role(&v, &role) == DMP_OK);
    CHECK(dmp_core_parse((dmp_bytes){known_empty_reply,sizeof known_empty_reply}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){duplicate,sizeof duplicate}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){unordered,sizeof unordered}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){crossing,sizeof crossing}, &limits, &v).status == DMP_MALFORMED);
    for (i = 0U; i < 4U; ++i) {
        dmp_status endpoint, relay;
        CHECK(parse_ok(raw_tags[i], sizeof raw_tags[i], &v));
        role.role = DMP_ROLE_ENDPOINT; endpoint = dmp_core_check_role(&v, &role);
        role.role = DMP_ROLE_FORWARDER; relay = dmp_core_check_role(&v, &role);
        CHECK(endpoint == ((i & 1U) ? DMP_UNSUPPORTED : DMP_OK));
        CHECK(relay == ((i & 2U) ? DMP_UNSUPPORTED : DMP_OK));
    }
    return 0;
}
static int test_descriptors_security_and_fragment_geometry(void)
{
    static const uint8_t bad_flags[] = {0x47,0x05,0x20,0x04,0x00};
    static const uint8_t bad_schema[] = {0x47,0x05,0x20,0x02,0x00};
    static const uint8_t bad_cipher[] = {0x47,0x07,0x41,0x01,0x03,0x01,0x01};
    static const uint8_t both_trailers[] = {0x47,0x05,0x51,0x01,0x01};
    static const uint8_t frag_zero[] = {0x47,0x07,0x09,0x01,0x00,0x00,0x03,0xaa};
    static const uint8_t frag_equal[] = {0x47,0x07,0x09,0x01,0x00,0x03,0x03,0xaa,0xbb,0xcc};
    static const uint8_t frag_index[] = {0x47,0x07,0x09,0x01,0x02,0x02,0x03,0xaa};
    static const uint8_t frag_tail_wrong[] = {0x47,0x07,0x09,0x01,0x01,0x02,0x03,0xaa,0xbb};
    static const uint8_t frag_limit[] = {0x47,0x07,0x09,0x01,0x00,0x01,0x03,0xaa};
    dmp_frame_view v;
    CHECK(dmp_core_parse((dmp_bytes){bad_flags,sizeof bad_flags}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){bad_schema,sizeof bad_schema}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){bad_cipher,sizeof bad_cipher}, &limits, &v).status == DMP_UNSUPPORTED);
    CHECK(dmp_core_parse((dmp_bytes){both_trailers,sizeof both_trailers}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){frag_zero,sizeof frag_zero}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){frag_equal,sizeof frag_equal}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){frag_index,sizeof frag_index}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){frag_tail_wrong,sizeof frag_tail_wrong}, &limits, &v).status == DMP_MALFORMED);
    {
        dmp_core_limits small=limits; small.max_fragments=2U;
        CHECK(dmp_core_parse((dmp_bytes){frag_limit,sizeof frag_limit},&small,&v).status==DMP_LIMIT_EXHAUSTED);
        small=limits; small.max_message_bytes=2U;
        CHECK(dmp_core_parse((dmp_bytes){frag_limit,sizeof frag_limit},&small,&v).status==DMP_LIMIT_EXHAUSTED);
    }
    return 0;
}
static int test_type_rules_and_endpoint_canonical_service(void)
{
    static const uint8_t no_seq_ackreq[] = {0x45,0x03,0x02};
    static const uint8_t no_seq_sec[] = {0x47,0x06,0x40,0x01,0x01,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    static const uint8_t service_default[] = {0x47,0x06,0x80,0x11,0x01,0x01,0xaa};
    static const uint8_t service_nondefault[] = {0x47,0x06,0x80,0x11,0x01,0x02,0xaa};
    static const uint8_t service_control[] = {0x47,0x06,0x80,0x11,0x01,0x00,0xaa};
    static const uint8_t unknown_endpoint_type[] = {0x4f,0x02,0xaa};
    static const uint8_t ackreq_broadcast[] = {0x45,0x06,0x07,0x01,0x02,0x01};
    dmp_frame_view v; dmp_role_policy role = {DMP_ROLE_ENDPOINT,1U,false};
    CHECK(dmp_core_parse((dmp_bytes){no_seq_ackreq,sizeof no_seq_ackreq}, &limits, &v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){no_seq_sec,sizeof no_seq_sec}, &limits, &v).status == DMP_MALFORMED);
    CHECK(parse_ok(service_default, sizeof service_default, &v));
    CHECK(dmp_core_check_role(&v, &role) == DMP_MALFORMED);
    CHECK(parse_ok(service_nondefault, sizeof service_nondefault, &v));
    CHECK(dmp_core_check_role(&v, &role) == DMP_OK);
    CHECK(parse_ok(service_control, sizeof service_control, &v));
    CHECK(dmp_core_check_role(&v, &role) == DMP_OK);
    CHECK(parse_ok(unknown_endpoint_type, sizeof unknown_endpoint_type, &v));
    CHECK(dmp_core_check_role(&v, &role) == DMP_UNSUPPORTED);
    role.role=DMP_ROLE_FORWARDER; CHECK(dmp_core_check_role(&v,&role)==DMP_OK);
    CHECK(dmp_core_parse((dmp_bytes){ackreq_broadcast,sizeof ackreq_broadcast},&limits,&v).status==DMP_MALFORMED);
    return 0;
}
static int test_reply_status_and_control_shapes(void)
{
    static const uint8_t full_reply_ack[] = {0x46,0x11,0x81,0x08,0x05,0x0b,0x01,0x0a,0x07,0,0,0,0,0,0,0,0x2a};
    static const uint8_t compact_reply_ack[] = {0x46,0x0a,0xc1,0x01,0x01,0x01,0x01,0x05,0x01,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    static const uint8_t compact_plain_reply[] = {0x46,0x07,0x81,0x01,0x05,0x01,0x01};
    static const uint8_t full_secure_reply[] = {0x46,0x14,0xc1,0x01,0x01,0x01,0x01,0x05,0x0b,0x01,0x0a,0x07,0,0,0,0,0,0,0,0x2a,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    static const uint8_t err_status1_ackreq[] = {0x42,0x14,0x83,0x01,0x05,0x0b,0x01,0x01,0,0,0,0,0,0,0,0,0x01,0x15,0x01,0x01,0xaa};
    static const uint8_t err_status8[] = {0x42,0x14,0x81,0x01,0x05,0x0b,0x01,0x01,0,0,0,0,0,0,0,0,0x01,0x15,0x01,0x08};
    static const uint8_t err_status64[] = {0x42,0x14,0x81,0x01,0x05,0x0b,0x01,0x01,0,0,0,0,0,0,0,0,0x01,0x15,0x01,0x40};
    static const uint8_t frag_status[] = {0x48,0x0a,0xc1,0x01,0x01,0x01,0x01,0x05,0x01,0x01,0x44,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    static const uint8_t ack_status[] = {0x46,0x07,0x81,0x01,0x15,0x01,0x01};
    static const uint8_t frag_status_ext[] = {0x48,0x0d,0xc1,0x01,0x01,0x01,0x01,0x05,0x01,0x01,0x15,0x01,0x01,0x44,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    dmp_frame_view v; dmp_role_policy role = {DMP_ROLE_ENDPOINT,1U,false};
    CHECK(parse_ok(full_reply_ack,sizeof full_reply_ack,&v));
    CHECK(parse_ok(compact_reply_ack,sizeof compact_reply_ack,&v));
    CHECK(dmp_core_parse((dmp_bytes){compact_plain_reply,sizeof compact_plain_reply},&limits,&v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){full_secure_reply,sizeof full_secure_reply},&limits,&v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){err_status1_ackreq,sizeof err_status1_ackreq},&limits,&v).status == DMP_MALFORMED);
    CHECK(parse_ok(err_status8,sizeof err_status8,&v));
    CHECK(dmp_core_check_role(&v,&role) == DMP_UNSUPPORTED);
    CHECK(parse_ok(err_status64,sizeof err_status64,&v));
    CHECK(parse_ok(frag_status,sizeof frag_status,&v));
    CHECK(dmp_core_check_role(&v,&role) == DMP_UNSUPPORTED);
    role.selective32 = true; CHECK(dmp_core_check_role(&v,&role) == DMP_OK);
    CHECK(dmp_core_parse((dmp_bytes){ack_status,sizeof ack_status},&limits,&v).status == DMP_MALFORMED);
    CHECK(dmp_core_parse((dmp_bytes){frag_status_ext,sizeof frag_status_ext},&limits,&v).status == DMP_MALFORMED);
    return 0;
}
static int test_encoder_failure_sentinels(void)
{
    uint8_t out[64], before[64]; size_t written; dmp_frame_spec f; dmp_status st;
    memset(&f,0,sizeof f); memset(out,0xa5,sizeof out); memcpy(before,out,sizeof out);
    f.fields.type = DMP_TYPE_TELEM; f.fields.options = DMP_OPT_ACK_REQ;
    written = 77U; st = dmp_core_encode(&f,&limits,(dmp_buffer){out,sizeof out},&written);
    CHECK(st == DMP_MALFORMED && written == 0U && memcmp(out,before,sizeof out)==0);
    memset(&f,0,sizeof f); f.fields.type=DMP_TYPE_DATA; f.fields.options=DMP_OPT_EXT;
    f.extensions=(dmp_bytes){(const uint8_t[]){0x05,0x00},2U};
    written=77U; st=dmp_core_encode(&f,&limits,(dmp_buffer){out,sizeof out},&written);
    CHECK(st == DMP_MALFORMED && written == 0U && memcmp(out,before,sizeof out)==0);
    memset(&f,0,sizeof f); f.fields.type=DMP_TYPE_ACK; f.fields.options=DMP_OPT_SEQ|DMP_OPT_EXT; f.fields.seq=1U;
    f.extensions=(dmp_bytes){(const uint8_t[]){0x05,0x00},2U};
    written=77U; st=dmp_core_encode(&f,&limits,(dmp_buffer){out,sizeof out},&written);
    CHECK(st == DMP_MALFORMED && written == 0U && memcmp(out,before,sizeof out)==0);
    return 0;
}

static int rejects_both_encoders(const dmp_frame_spec *frame, dmp_status expected)
{
    uint8_t out[64], before[64];
    size_t written;
    memset(out, 0xa5, sizeof out);
    memcpy(before, out, sizeof out);
    written = 99U;
    CHECK(dmp_core_encode_header(frame, &limits, (dmp_buffer){out,sizeof out}, &written) == expected);
    CHECK(written == 0U && memcmp(out, before, sizeof out) == 0);
    written = 99U;
    CHECK(dmp_core_encode(frame, &limits, (dmp_buffer){out,sizeof out}, &written) == expected);
    CHECK(written == 0U && memcmp(out, before, sizeof out) == 0);
    return 0;
}

static int test_encoder_required_identity_and_ttl(void)
{
    const uint8_t payload = 0xaa;
    dmp_frame_spec f;
    memset(&f, 0, sizeof f);
    f.fields.type = DMP_TYPE_DATA;
    f.fields.options = DMP_OPT_FRAG;
    f.fields.fragment = (dmp_fragment_fields){0U, 1U, 2U};
    f.payload = (dmp_bytes){&payload, 1U};
    CHECK(rejects_both_encoders(&f, DMP_MALFORMED) == 0);

    memset(&f, 0, sizeof f);
    f.fields.type = DMP_TYPE_TELEM;
    f.fields.options = DMP_OPT_ROUTE;
    f.fields.route.source = 1U;
    CHECK(rejects_both_encoders(&f, DMP_MALFORMED) == 0);
    f.fields.options |= DMP_OPT_SEQ | DMP_OPT_ACK_REQ;
    f.fields.route.mode = 2U;
    CHECK(rejects_both_encoders(&f, DMP_MALFORMED) == 0);
    f.fields.route.mode = 0U;
    f.fields.route.ttl = 16U;
    CHECK(rejects_both_encoders(&f, DMP_INVALID_ARGUMENT) == 0);
    return 0;
}
static int test_nested_error_offsets_and_zero_default(void)
{
    static const uint8_t nonminimal[] = {0x47,7,0x80,0x11,2,0x80,0,0xaa};
    static const uint8_t overflow[30] = {0x46,14,0xc1,1,1,1,1,5,5,0xff,0xff,0xff,0xff,0x10};
    static const uint8_t header_truncated[] = {0x47,4,1,0x80,0xaa};
    static const uint8_t value_truncated[] = {0x47,6,0x80,0x11,1,0x80,0xaa};
    static const uint8_t value_trailing[] = {0x47,7,0x80,0x11,2,1,0,0xaa};
    static const uint8_t context_short[] = {0x47,7,0x80,0x0b,2,1,0,0xaa};
    static const uint8_t default_zero[] = {0x47,6,0x80,0x11,1,0};
    static const uint8_t reserved_status[] = {0x47,6,0x80,0x15,1,8};
    const dmp_bytes bad[] = {
        {nonminimal,sizeof nonminimal}, {overflow,sizeof overflow},
        {header_truncated,sizeof header_truncated}, {value_truncated,sizeof value_truncated},
        {value_trailing,sizeof value_trailing}, {context_short,sizeof context_short}
    };
    const size_t offsets[] = {5U,13U,4U,6U,6U,7U};
    dmp_frame_view v, zero;
    dmp_role_policy role = {DMP_ROLE_ENDPOINT,0U,false};
    size_t i;
    memset(&zero,0,sizeof zero);
    for (i=0U; i<sizeof bad/sizeof bad[0]; ++i) {
        dmp_parse_result r;
        memset(&v,0xa5,sizeof v);
        r=dmp_core_parse(bad[i],&limits,&v);
        CHECK(r.status==DMP_MALFORMED && r.offset==offsets[i]);
        CHECK(memcmp(&v,&zero,sizeof v)==0);
    }
    CHECK(parse_ok(default_zero,sizeof default_zero,&v));
    CHECK(dmp_core_check_role(&v,&role)==DMP_MALFORMED);
    CHECK(parse_ok(reserved_status,sizeof reserved_status,&v));
    CHECK(dmp_core_check_role(&v,&role)==DMP_UNSUPPORTED);
    role.role=DMP_ROLE_FORWARDER;
    CHECK(dmp_core_check_role(&v,&role)==DMP_OK);
    return 0;
}

static int test_header_and_capacity_boundaries(void)
{
    uint8_t ext[253], out[256], before[256];
    dmp_frame_spec f;
    dmp_frame_view v;
    size_t written;
    memset(ext,0,sizeof ext);
    /* Unknown safe ID=7, canonical 249-byte length: total header=255. */
    ext[0]=28; ext[1]=0xf9; ext[2]=1;
    memset(&f,0,sizeof f);
    f.fields.type=DMP_TYPE_DATA; f.fields.options=DMP_OPT_EXT;
    f.extensions=(dmp_bytes){ext,252U};
    CHECK(dmp_core_encode(&f,&limits,(dmp_buffer){out,255U},&written)==DMP_OK);
    CHECK(written==255U && parse_ok(out,written,&v) && v.header.size==255U);
    memset(out,0xa5,sizeof out); memcpy(before,out,sizeof out);
    CHECK(dmp_core_encode(&f,&limits,(dmp_buffer){out,254U},&written)==DMP_LIMIT_EXHAUSTED);
    CHECK(written==0U && memcmp(out,before,sizeof out)==0);
    ext[1]=0xfa; f.extensions.size=253U;
    CHECK(rejects_both_encoders(&f,DMP_LIMIT_EXHAUSTED)==0);
    memset(&f,0,sizeof f);
    f.fields.type=DMP_TYPE_DATA; f.fields.options=DMP_OPT_SEQ|DMP_OPT_SECURITY;
    f.fields.security.cipher=1; f.trailer=(dmp_bytes){NULL,15U};
    CHECK(dmp_core_encode_header(&f,&limits,(dmp_buffer){out,sizeof out},&written)==DMP_INVALID_ARGUMENT);
    CHECK(written==0U && memcmp(out,before,sizeof out)==0);
    return 0;
}

int main(void)
{
    CHECK(test_independent_golden_vectors() == 0);
    CHECK(test_uleb_boundaries() == 0);
    CHECK(test_malformed_and_limits() == 0);
    CHECK(test_roles_and_safe_unknown() == 0);
    CHECK(test_encoder_preflight_and_header_placeholders() == 0);
    CHECK(test_extension_iterator() == 0);
    CHECK(test_extension_structure_and_roles() == 0);
    CHECK(test_descriptors_security_and_fragment_geometry() == 0);
    CHECK(test_type_rules_and_endpoint_canonical_service() == 0);
    CHECK(test_reply_status_and_control_shapes() == 0);
    CHECK(test_encoder_failure_sentinels() == 0);
    CHECK(test_encoder_required_identity_and_ttl() == 0);
    CHECK(test_nested_error_offsets_and_zero_default() == 0);
    CHECK(test_header_and_capacity_boundaries() == 0);
    return 0;
}
