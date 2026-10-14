"""Generate test-only C arrays for the published protected TYPE-8 vectors."""

import json
from pathlib import Path
import sys


def bytes_array(name, value):
    raw = bytes.fromhex(value)
    items = ", ".join(f"0x{byte:02x}U" for byte in raw)
    return [f"static const uint8_t {name}[] = {{{items}}};"]


def read_uleb(data, offset):
    value = 0
    shift = 0
    start = offset
    while offset < len(data) and shift < 35:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            if offset - start > 1 and byte == 0:
                raise SystemExit("non-canonical packet number in mutation frame")
            return value
        shift += 7
    raise SystemExit("invalid packet number in mutation frame")


def main():
    recovery_path, security_path, output_path = map(Path, sys.argv[1:])
    recovery = json.loads(recovery_path.read_text(encoding="utf-8"))
    security = json.loads(security_path.read_text(encoding="utf-8"))
    suite = next(
        item
        for item in security["vectors"]
        if item["protocol_name"] == recovery["supported_suite"]["protocol_name"]
    )
    if recovery["association"]["key"] != suite["r_to_i_key"]:
        raise SystemExit("recovery vector key does not match the public SEC-1 vector")
    if recovery["association"]["handshake_hash"] != suite["handshake_hash"]:
        raise SystemExit("recovery handshake hash does not match the public SEC-1 vector")

    rows = []
    declarations = bytes_array("frag_status_aead_key", recovery["association"]["key"])
    for case in recovery["cases"]:
        if case.get("aead_valid") is not True or case.get("cipher") != 1:
            continue
        name = f"case_{case['name']}"
        declarations += bytes_array(f"{name}_frame", case["frame"])
        declarations += bytes_array(f"{name}_aad", case["aad"])
        declarations += bytes_array(f"{name}_plain", case["plaintext"])
        rows.append(
            f'    {{"{case["name"]}", {name}_frame, sizeof {name}_frame, '
            f'{name}_aad, sizeof {name}_aad, {name}_plain, sizeof {name}_plain, '
            f'UINT64_C({case["pn"]}), 1}},'
        )

    case_by_name = {case["name"]: case for case in recovery["cases"]}
    label = b"DMP2-SEC1-DATA"
    handshake = bytes.fromhex(recovery["association"]["handshake_hash"])
    for mutation in recovery["mutations"]:
        base = case_by_name[mutation["base"]]
        frame = bytes.fromhex(mutation["frame"])
        header_len = frame[1]
        canonical_header = bytearray(frame[:header_len])
        packet_number = base["pn"]
        if mutation["name"] == "packet_number":
            packet_number = read_uleb(frame, mutation["offset"])
            if packet_number == base["pn"]:
                raise SystemExit("packet_number mutation did not change packet number")
        route_offset = base.get("route_control_offset")
        if route_offset is not None:
            canonical_header[route_offset] &= 0x0F
        aad = label + handshake + canonical_header
        plain = bytes.fromhex(base["plaintext"])
        name = f"mutation_{mutation['name']}"
        declarations += bytes_array(f"{name}_frame", mutation["frame"])
        declarations += bytes_array(f"{name}_aad", aad.hex())
        declarations += bytes_array(f"{name}_plain", plain.hex())
        rows.append(
            f'    {{"{mutation["name"]}", {name}_frame, sizeof {name}_frame, '
            f'{name}_aad, sizeof {name}_aad, {name}_plain, sizeof {name}_plain, '
            f'UINT64_C({packet_number}), {1 if mutation["aead_valid"] else 0}}},'
        )

    text = [
        "/* Generated from the public recovery and SEC-1 vector JSON files. */",
        "typedef struct {",
        "    const char *name;",
        "    const uint8_t *frame; size_t frame_len;",
        "    const uint8_t *aad; size_t aad_len;",
        "    const uint8_t *plain; size_t plain_len;",
        "    uint64_t pn; int expect_open;",
        "} frag_status_aead_case;",
        *declarations,
        "static const frag_status_aead_case frag_status_aead_cases[] = {",
        *rows,
        "};",
        "",
    ]
    output_path.write_text("\n".join(text), encoding="ascii")


if __name__ == "__main__":
    main()
