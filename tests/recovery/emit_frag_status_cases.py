"""Copy published FRAG_STATUS frames into a test-only C header.

No codec, AEAD or recovery state machine is implemented here. The JSON fixture
is the byte source. Structural acceptance is not authentication.
"""
import json
from pathlib import Path
import sys


EXPECT = {"ok": 0, "malformed": 1, "unsupported": 2}
ROLE = {"ok": 0, "malformed": 1, "limit": 2, "skip": 3}


def rows(document):
    for case in document["cases"]:
        yield case["name"], case["frame"], case["library_parse"], case["library_role"], True
    for mutation in document["mutations"]:
        yield mutation["name"], mutation["frame"], mutation["library_parse"], mutation["library_role"], False


def main():
    source, output = map(Path, sys.argv[1:])
    document = json.loads(source.read_text(encoding="utf-8"))
    lines = [
        "/* Generated from docs/DMP_v2_Recovery_Test_Vectors.json. Tests only. */",
        "typedef struct { const char *name; const uint8_t *data; size_t size;",
        "    int parse_expect, role_expect, check_fields; uint32_t seq; uint64_t pn;",
        "    uint8_t cipher; } frag_case;",
    ]
    entries = []
    names = set()
    for name, frame_hex, parse, role, check in rows(document):
        if name in names:
            raise SystemExit(f"duplicate fixture name {name}")
        names.add(name)
        frame = bytes.fromhex(frame_hex)
        if parse == "ok":
            header = frame[1]
            if header < 2 or header + 16 > len(frame) or len(frame) - header - 16 != 4:
                raise SystemExit(f"{name} is not a 4-byte protected frame")
        octets = ",".join(f"0x{value:02x}" for value in frame)
        lines.append(f"static const uint8_t frag_{name}[] = {{{octets}}};")
        case = next((item for item in document["cases"] if item["name"] == name), None)
        seq = case["seq"] if case and check else 0
        pn = case["pn"] if case and check else 0
        cipher = case["cipher"] if case and check else 0
        entries.append(
            f'    {{"{name}", frag_{name}, sizeof frag_{name}, {EXPECT[parse]}, {ROLE[role]}, '
            f'{1 if check else 0}, UINT32_C({seq}), UINT64_C({pn}), {cipher}U}},'
        )
    lines += ["static const frag_case frag_cases[] = {", *entries, "};", ""]
    output.write_text("\n".join(lines) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
