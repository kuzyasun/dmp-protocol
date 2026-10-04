"""Public SELECTIVE-32 FRAG_STATUS fixtures. Not a protocol implementation.

Expected header, AAD and ciphertext come from the revision-10 / SEC-1 revision-5
rules and Python ``cryptography`` ChaCha20-Poly1305. This script does not import
libdmp, ``src/reliability`` or ``dmp_core_encode``.

The traffic key and handshake hash are copied from the already published
NNpsk0 ChaChaPoly vector in ``docs/DMP_v2_Security_Test_Vectors.json``. That
file is not rewritten. Cipher 2 and XX are outside this file's supported suite.

Regenerate, then check with a separate implementation:
  python dev/dmp_generate_recovery_vectors.py
  node dev/dmp_verify_recovery_vectors.cjs
"""

import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ROOT = Path(__file__).resolve().parents[1]
SECURITY = ROOT / "docs" / "DMP_v2_Security_Test_Vectors.json"
OUTPUT = ROOT / "docs" / "DMP_v2_Recovery_Test_Vectors.json"
PROTOCOL = "Noise_NNpsk0_25519_ChaChaPoly_SHA256"
PINNED_HASH = "a786c7e69cf80b08aafd8d20bcc5efc4fa30968643fa49ae1ad8452cf99844cf"
AAD_LABEL = b"DMP2-SEC1-DATA"
ILLUSTRATIVE = "480ac109010107050105"


def uleb(value):
    if value < 0:
        raise ValueError("negative integer")
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def ext(extension_id, value, unsafe=False):
    tag = (extension_id << 2) | (2 if unsafe else 0) | 1
    return uleb(tag) + uleb(len(value)) + value


def mask_accept(mask, count):
    if not isinstance(count, int) or count < 2 or count > 32:
        return False
    if not isinstance(mask, int) or mask <= 0 or mask > 0xFFFFFFFF:
        return False
    if count < 32 and (mask >> count) != 0:
        return False
    every = 0xFFFFFFFF if count == 32 else (1 << count) - 1
    return mask != every


def canonical(header, route_offset):
    out = bytearray(header)
    if route_offset is not None:
        out[route_offset] &= 0x0F
    return bytes(out)


def build_header(case, epoch):
    reply = case["reply"]
    extensions = b""
    if reply == "compact":
        extensions += ext(1, uleb(case["reply_seq"]))
    elif reply == "full":
        body = uleb(case["full_namespace"]) + uleb(case["full_origin"])
        body += int(case["full_epoch"]).to_bytes(8, "little") + uleb(case["reply_seq"])
        extensions += ext(1, body)
    elif reply == "nonminimal":
        extensions += ext(1, b"\x80\x00")
    elif reply != "absent":
        raise ValueError(reply)
    if case.get("context"):
        body = uleb(case["context"]["namespace"]) + int(epoch).to_bytes(8, "little")
        extensions += ext(2, body, unsafe=True)
    if case.get("service") is not None:
        extensions += ext(4, uleb(case["service"]))
    if case.get("status") is not None:
        extensions += ext(5, uleb(case["status"]))
    if case.get("freshness"):
        extensions += ext(6, bytes(16))
    opts = 1
    if case.get("ack_req"):
        opts |= 2
    route = case.get("route")
    frag = case.get("frag")
    if route:
        opts |= 4
    if frag:
        opts |= 8
    if case.get("integrity"):
        opts |= 0x10
    if case.get("payload_desc"):
        opts |= 0x20
    if case.get("security", True):
        opts |= 0x40
    if extensions:
        opts |= 0x80
    fields = bytes([opts]) + uleb(case["seq"])
    route_offset = None
    if route:
        route_offset = 2 + len(fields)
        ttl, source, destination = route
        fields += bytes([(ttl << 4) | 1]) + uleb(source) + uleb(destination)
    if frag:
        fields += uleb(frag[0]) + uleb(frag[1]) + uleb(frag[2])
    if case.get("payload_desc"):
        fields += bytes([0]) + uleb(0)
    if case.get("integrity"):
        fields += bytes([1])
    if case.get("security", True):
        fields += bytes([case["cipher"]]) + uleb(case["cid"]) + uleb(case["pn"])
    fields += extensions
    if len(fields) + 2 > 255:
        raise ValueError("header too large")
    return bytes([0x48, len(fields) + 2]) + fields, route_offset


def plaintext_of(case):
    if "plaintext" in case:
        return bytes.fromhex(case["plaintext"])
    return case["mask"].to_bytes(4, "little")


def seal(key, handshake, case, epoch):
    header, route_offset = build_header(case, epoch)
    plain = plaintext_of(case)
    if not case.get("seal", True):
        tag = b"" if case.get("omit_tag") else bytes(16)
        frame = header + plain + tag
        return {"header": header.hex(), "route_control_offset": route_offset,
                "plaintext": plain.hex(), "ciphertext": plain.hex() if tag else "",
                "tag": tag.hex(), "frame": frame.hex(), "nonce": None, "aad": None,
                "aead_valid": False}
    canon = canonical(header, route_offset)
    aad = AAD_LABEL + handshake + canon
    nonce = bytes(4) + case["pn"].to_bytes(8, "little")
    boxed = ChaCha20Poly1305(key).encrypt(nonce, plain, aad)
    body, tag = boxed[:-16], boxed[-16:]
    opened = ChaCha20Poly1305(key).decrypt(nonce, boxed, aad)
    if opened != plain:
        raise AssertionError(case["name"])
    return {"header": header.hex(), "route_control_offset": route_offset,
            "plaintext": plain.hex(), "ciphertext": body.hex(), "tag": tag.hex(),
            "frame": (header + boxed).hex(), "nonce": nonce.hex(), "aad": aad.hex(),
            "aead_valid": True}


def load_suite():
    data = json.loads(SECURITY.read_text(encoding="utf-8"))
    vector = next(item for item in data["vectors"] if item["protocol_name"] == PROTOCOL)
    if vector["handshake_hash"] != PINNED_HASH or vector["cipher"] != 1 or vector["mode"] != 1:
        raise SystemExit("Published NNpsk0 ChaChaPoly vector no longer matches the P18 pin")
    ready = next(packet for packet in vector["packets"] if packet["name"] == "ready")
    if ready["header"] != "43074100010700" or ready["direction"] != 1:
        raise SystemExit("Published READY header is not the pinned initiator receive CID")
    routed = next(packet for packet in vector["packets"] if packet["name"] == "routed_request")
    if not routed["header"].startswith("4018c702310a14"):
        raise SystemExit("Published routed request is not source 10, destination 20")
    return vector


def cases(vector):
    epoch = vector["origin_epochs"][1]
    initiator_epoch = vector["origin_epochs"][0]
    common = {"cid": 7, "cipher": 1, "reply": "compact", "reply_seq": 5, "security": True}
    rows = [
        {**common, "name": "two_of_eight", "seq": 9, "pn": 16, "n": 8, "mask": 0x44,
         "library_parse": "ok", "library_role": "ok"},
        {**common, "name": "n2_index0", "seq": 10, "pn": 17, "n": 2, "mask": 0x01,
         "library_parse": "ok", "library_role": "ok"},
        {**common, "name": "n32_index31", "seq": 11, "pn": 18, "n": 32, "mask": 0x80000000,
         "library_parse": "ok", "library_role": "ok"},
        {**common, "name": "explicit_service", "seq": 12, "pn": 19, "n": 2, "mask": 0x01,
         "service": 2, "library_parse": "ok", "library_role": "ok"},
        {**common, "name": "routed_return", "seq": 13, "pn": 20, "n": 8, "mask": 0x44,
         "route": (3, 20, 10), "context": {"namespace": 1},
         "library_parse": "ok", "library_role": "ok"},
        {**common, "name": "pn_two_byte", "seq": 14, "pn": 128, "n": 8, "mask": 0x44,
         "library_parse": "ok", "library_role": "ok"},
        {**common, "name": "mask_zero", "seq": 15, "pn": 21, "n": 8, "mask": 0,
         "plaintext": "00000000", "library_parse": "ok", "library_role": "ok"},
        {**common, "name": "mask_all_n2", "seq": 16, "pn": 22, "n": 2, "mask": 0x03,
         "library_parse": "ok", "library_role": "ok"},
        {**common, "name": "mask_out_of_range_n2", "seq": 17, "pn": 23, "n": 2, "mask": 0x04,
         "library_parse": "ok", "library_role": "ok"},
        {**common, "name": "mask_all_n32", "seq": 18, "pn": 24, "n": 32, "mask": 0xFFFFFFFF,
         "library_parse": "ok", "library_role": "ok"},
        {**common, "name": "payload_short", "seq": 19, "pn": 25, "n": 8, "mask": 0x44,
         "plaintext": "440000", "library_parse": "malformed", "library_role": "skip"},
        {**common, "name": "payload_long", "seq": 20, "pn": 26, "n": 8, "mask": 0x44,
         "plaintext": "44000000ff", "library_parse": "malformed", "library_role": "skip"},
        {**common, "name": "explicit_default_service", "seq": 21, "pn": 27, "n": 2, "mask": 0x01,
         "service": 1, "library_parse": "ok", "library_role": "malformed"},
        {**common, "name": "pn_at_limit", "seq": 22, "pn": 1 << 24, "n": 8, "mask": 0x44,
         "library_parse": "ok", "library_role": "limit"},
        {**common, "name": "missing_reply", "seq": 23, "pn": 28, "n": 8, "mask": 0x44,
         "reply": "absent", "library_parse": "malformed", "library_role": "skip"},
        {**common, "name": "full_reply", "seq": 24, "pn": 29, "n": 8, "mask": 0x44,
         "reply": "full", "full_namespace": 1, "full_origin": 10, "full_epoch": initiator_epoch,
         "library_parse": "malformed", "library_role": "skip"},
        {**common, "name": "nonminimal_reply", "seq": 25, "pn": 30, "n": 8, "mask": 0x44,
         "reply": "nonminimal", "library_parse": "malformed", "library_role": "skip"},
        {**common, "name": "ack_req", "seq": 26, "pn": 31, "n": 8, "mask": 0x44, "ack_req": True,
         "library_parse": "malformed", "library_role": "skip"},
        {**common, "name": "frag", "seq": 27, "pn": 32, "n": 8, "mask": 0x44, "frag": (0, 4, 8),
         "library_parse": "malformed", "library_role": "skip"},
        {**common, "name": "payload_desc", "seq": 28, "pn": 33, "n": 8, "mask": 0x44,
         "payload_desc": True, "library_parse": "malformed", "library_role": "skip"},
        {**common, "name": "status_extension", "seq": 29, "pn": 34, "n": 8, "mask": 0x44,
         "status": 1, "library_parse": "malformed", "library_role": "skip"},
        {**common, "name": "freshness_extension", "seq": 30, "pn": 35, "n": 8, "mask": 0x44,
         "freshness": True, "library_parse": "malformed", "library_role": "skip"},
        {**common, "name": "integrity_with_security", "seq": 31, "pn": 36, "n": 8, "mask": 0x44,
         "integrity": True, "seal": False, "library_parse": "malformed", "library_role": "skip"},
        {**common, "name": "cipher_3", "seq": 32, "pn": 37, "n": 8, "mask": 0x44, "cipher": 3,
         "seal": False, "library_parse": "unsupported", "library_role": "skip"},
        {**common, "name": "cipher_2_outside_suite", "seq": 33, "pn": 38, "n": 8, "mask": 0x44,
         "cipher": 2, "seal": False, "library_parse": "ok", "library_role": "ok"},
        {"name": "illustrative_header_only", "seq": 9, "pn": 7, "cid": 1, "cipher": 1,
         "reply": "compact", "reply_seq": 5, "n": 8, "mask": 0x44, "security": True,
         "seal": False, "omit_tag": True, "library_parse": "malformed", "library_role": "skip"},
    ]
    seen = set()
    for row in rows:
        if row.get("seal", True):
            if row["pn"] in seen:
                raise AssertionError("PN reused")
            seen.add(row["pn"])
    return rows, epoch


def decision_inputs(row):
    return {
        "name": row["name"],
        "seq": row["seq"],
        "pn": row["pn"],
        "cid": row["cid"],
        "cipher": row["cipher"],
        "reply": row["reply"],
        "reply_seq": row.get("reply_seq"),
        "n": row.get("n"),
        "mask": row.get("mask"),
        "service": row.get("service"),
        "ack_req": bool(row.get("ack_req")),
        "frag": list(row["frag"]) if row.get("frag") else None,
        "payload_desc": bool(row.get("payload_desc")),
        "integrity": bool(row.get("integrity")),
        "status": row.get("status"),
        "freshness": bool(row.get("freshness")),
        "security": bool(row.get("security", True)),
        "sealed": bool(row.get("seal", True)),
        "omit_tag": bool(row.get("omit_tag")),
    }


def main():
    vector = load_suite()
    key = bytes.fromhex(vector["r_to_i_key"])
    handshake = bytes.fromhex(vector["handshake_hash"])
    if len(key) != 32 or len(handshake) != 32:
        raise SystemExit("Pinned suite key or handshake hash has the wrong length")
    rows, epoch = cases(vector)
    illustrative, _ = build_header(
        {"seq": 9, "pn": 7, "cid": 1, "cipher": 1, "reply": "compact", "reply_seq": 5,
         "security": True}, epoch)
    if illustrative.hex() != ILLUSTRATIVE:
        raise SystemExit("R6 illustrative header bytes were not reproduced")
    emitted = []
    for row in rows:
        sealed = seal(key, handshake, row, epoch)
        if row["name"] == "illustrative_header_only" and sealed["header"] != ILLUSTRATIVE:
            raise SystemExit("Illustrative case drifted from R6")
        if row["name"] == "two_of_eight" and len(bytes.fromhex(sealed["frame"])) != 30:
            raise SystemExit("One-byte protected status is not the annex's 30-byte size")
        plain = bytes.fromhex(sealed["plaintext"])
        if row.get("plaintext") is None and plain != row["mask"].to_bytes(4, "little"):
            raise SystemExit(row["name"])
        emitted.append({
            **decision_inputs(row),
            "library_parse": row["library_parse"],
            "library_role": row["library_role"],
            "route": list(row["route"]) if row.get("route") else None,
            "context_epoch": epoch if row.get("context") else None,
            "full_namespace": row.get("full_namespace"),
            "full_origin": row.get("full_origin"),
            "full_epoch": row.get("full_epoch"),
            **sealed,
            "route_control_offset": sealed["route_control_offset"],
        })
    by_name = {item["name"]: item for item in emitted}
    mutations = []
    for name, base_name, selector, mask, valid in (
        ("ttl_only", "routed_return", "route", 0x10, True),
        ("destination", "routed_return", "destination", 0x01, False),
        ("sequence", "two_of_eight", "seq", 0x01, False),
        ("reply_to", "two_of_eight", "reply", 0x01, False),
        ("receive_cid", "two_of_eight", "cid", 0x01, False),
        ("packet_number", "two_of_eight", "pn", 0x01, False),
        ("ciphertext", "two_of_eight", "ciphertext", 0x01, False),
        ("tag", "two_of_eight", "tag", 0x01, False),
    ):
        base = by_name[base_name]
        frame = bytearray.fromhex(base["frame"])
        header = bytes.fromhex(base["header"])
        if selector == "route":
            offset = base["route_control_offset"]
        elif selector == "destination":
            offset = base["route_control_offset"] + 2
        elif selector == "seq":
            offset = 3
        elif selector == "reply":
            offset = len(header) - 1
        elif selector == "cid":
            offset = 5
        elif selector == "pn":
            offset = 6
        elif selector == "ciphertext":
            offset = len(header)
        elif selector == "tag":
            offset = len(frame) - 1
        else:
            raise SystemExit(selector)
        if selector == "reply" and base_name == "two_of_eight":
            offset = len(header) - 1
        frame[offset] ^= mask
        canon = bytearray(frame[:frame[1]])
        if base["route_control_offset"] is not None:
            canon[base["route_control_offset"]] &= 0x0F
        aad = AAD_LABEL + handshake + bytes(canon)
        nonce = bytes.fromhex(base["nonce"])
        ok = True
        try:
            ChaCha20Poly1305(key).decrypt(nonce, bytes(frame[frame[1]:]), aad)
        except Exception:
            ok = False
        if ok != valid:
            raise SystemExit(f"Mutation {name} AEAD {ok} != {valid}")
        mutations.append({
            "name": name, "base": base_name, "offset": offset, "xor": mask,
            "aead_valid": valid, "frame": frame.hex(),
            "library_parse": "ok", "library_role": "ok",
        })
    document = {
        "specification": "DMP v2 revision 10 / SEC-1 revision 5 / SELECTIVE-32 revision 1",
        "warning": "PUBLIC TEST KEYS ONLY. These fixtures are not a live association, an endpoint, or physical transport.",
        "provenance": {
            "generator": "dev/dmp_generate_recovery_vectors.py",
            "generator_crypto": "Python cryptography ChaCha20Poly1305",
            "verifier": "dev/dmp_verify_recovery_vectors.cjs",
            "verifier_crypto": "node:crypto chacha20-poly1305",
            "key_source": "docs/DMP_v2_Security_Test_Vectors.json NNpsk0 ChaChaPoly r_to_i_key and handshake_hash",
            "pinned_handshake_hash": PINNED_HASH,
            "not_produced_by": "src/reliability and dmp_core_encode",
            "canonical_security_file": "not modified",
        },
        "supported_suite": {
            "mode": 1,
            "cipher": 1,
            "protocol_name": PROTOCOL,
            "direction": 1,
            "receive_cid": 7,
            "default_service": 1,
            "explicit_service": 2,
            "excluded": "Cipher 2 AES-GCM and Noise_XX are optional or separate SEC-1 corpus entries. This file does not generate or accept them.",
        },
        "association": {
            "handshake_hash": vector["handshake_hash"],
            "key": vector["r_to_i_key"],
            "initiator_origin": 10,
            "responder_origin": 20,
            "namespace": 1,
            "responder_epoch": epoch,
            "initiator_epoch": vector["origin_epochs"][0],
        },
        "illustrative_header": {
            "source": "SELECTIVE-32 R6",
            "header": ILLUSTRATIVE,
            "plaintext": "44000000",
            "complete_frame": False,
        },
        "cases": emitted,
        "mutations": mutations,
    }
    OUTPUT.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii")
    print(f"wrote {OUTPUT} cases={len(emitted)} mutations={len(mutations)}")


if __name__ == "__main__":
    main()
