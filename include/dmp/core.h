#ifndef DMP_CORE_H
#define DMP_CORE_H

#include "dmp/base.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Structural codec implemented in src/core/codec.c; no endpoint state. */
enum { DMP_WIRE_VERSION = 2, DMP_MAX_HEADER_BYTES = 255 };
typedef enum {
    DMP_TYPE_REQ = 0, DMP_TYPE_RSP = 1, DMP_TYPE_ERR = 2,
    DMP_TYPE_HELLO = 3, DMP_TYPE_EVENT = 4, DMP_TYPE_TELEM = 5,
    DMP_TYPE_ACK = 6, DMP_TYPE_DATA = 7, DMP_TYPE_FRAG_STATUS = 8
} dmp_type;
enum {
    DMP_OPT_SEQ = 0x01, DMP_OPT_ACK_REQ = 0x02, DMP_OPT_ROUTE = 0x04,
    DMP_OPT_FRAG = 0x08, DMP_OPT_INTEGRITY = 0x10,
    DMP_OPT_PAYLOAD_DESC = 0x20, DMP_OPT_SECURITY = 0x40, DMP_OPT_EXT = 0x80
};

typedef struct {
    uint8_t mode, ttl;
    uint32_t source, destination;
} dmp_route_fields;
typedef struct { uint32_t index, chunk_size, total_size; } dmp_fragment_fields;
typedef struct {
    uint8_t flags;
    uint32_t codec, schema, schema_version;
} dmp_payload_descriptor;
typedef struct { uint8_t cipher; uint32_t receive_cid; uint64_t pn; } dmp_security_fields;
typedef struct {
    uint8_t type, options;
    uint32_t seq;
    dmp_route_fields route;
    dmp_fragment_fields fragment;
    dmp_payload_descriptor descriptor;
    uint8_t integrity;
    dmp_security_fields security;
} dmp_header_fields;

typedef struct {
    size_t max_frame_bytes;
    uint32_t max_message_bytes, max_fragments;
} dmp_core_limits;

/* All spans borrow the same input frame. Payload is still ciphertext when
 * SECURITY is present. No trusted identity, decrypted plaintext or acceptance
 * flag exists in this view. Absent optional scalar fields are zero. */
typedef struct {
    dmp_header_fields fields;
    dmp_bytes frame, header, extensions, payload, trailer;
} dmp_frame_view;

/* One role per call: local rejection must not veto an otherwise permitted relay.
 * Recognition of a cipher/TYPE does not enable endpoint crypto/recovery modules. */
typedef enum { DMP_ROLE_ENDPOINT = 0, DMP_ROLE_FORWARDER = 1 } dmp_role;
typedef struct {
    dmp_role role;
    uint32_t default_service;
    bool selective32;
} dmp_role_policy;

typedef struct {
    dmp_header_fields fields;
    dmp_bytes extensions; /* Complete canonical ordered TLVs; never native structs. */
    dmp_bytes payload, trailer;
} dmp_frame_spec;
/* tag is the complete EXT_TAG, including the low C/U bits, not extension ID. */
typedef struct { uint32_t tag; dmp_bytes value; } dmp_extension_view;

/* Structural checks only, including geometry and known descriptor/value shapes.
 * No CRC/AEAD verification or state changes. Error: output zeroed, offset names
 * first rejected byte, or the enclosing header/TLV-value boundary when a field
 * is truncated there. Packet truncation uses input.size; OK does likewise. */
dmp_parse_result dmp_core_parse(dmp_bytes input, const dmp_core_limits *limits,
                                dmp_frame_view *out);
/* frame must be an unmodified successful parse view with backing still alive.
 * OK is only structural role compatibility, never endpoint/module acceptance. */
dmp_status dmp_core_check_role(const dmp_frame_view *frame,
                               const dmp_role_policy *policy);

/* Encode supplied payload/trailer as bytes; do not compute CRC or AEAD. Header
 * encoding permits the later caller to form AAD before encrypting: payload and
 * trailer sizes are checked but their bytes are not read; only for header-only
 * encoding, their data pointers may be NULL length-only placeholders. Both perform
 * complete preflight: on failure *written=0 and destination bytes unchanged.
 * Inputs and destination must not overlap; all backed views stay valid for call.
 * Required pointers must be non-NULL; a NULL written is INVALID_ARGUMENT. */
dmp_status dmp_core_encode_header(const dmp_frame_spec *frame,
                                  const dmp_core_limits *limits,
                                  dmp_buffer output, size_t *written);
dmp_status dmp_core_encode(const dmp_frame_spec *frame,
                           const dmp_core_limits *limits,
                           dmp_buffer output, size_t *written);

/* Iterator cursor starts at 0. OK advances one TLV; INCOMPLETE at exact end
 * means no more entries. No other failure advances cursor or publishes output.
 * Input must be the validated extensions span from dmp_core_parse. */
dmp_status dmp_extension_next(dmp_bytes extensions, size_t *cursor,
                              dmp_extension_view *out);

#ifdef __cplusplus
}
#endif
#endif
