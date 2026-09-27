"""Copy public packet bytes/expected metadata into a test-only C header.

No codec, crypto, state machine or private key material is generated here.
The published fixture is the independent expected-byte source.
"""
import json
from pathlib import Path
import sys


def main():
    source, output = map(Path, sys.argv[1:])
    vectors = json.loads(source.read_text(encoding="utf-8"))["vectors"]
    lines = ["/* Generated from published public packet fixtures; tests only. */",
             "typedef struct { const uint8_t *data; size_t size, header_size, payload_size;",
             "    uint32_t seq; uint64_t pn; uint8_t cipher; } public_packet;"]
    rows = []
    for vector in vectors:
        for packet in vector["packets"]:
            frame = bytes.fromhex(packet["frame"])
            header = bytes.fromhex(packet["header"])
            ciphertext = bytes.fromhex(packet["ciphertext"])
            tag = bytes.fromhex(packet["tag"])
            if frame != header + ciphertext + tag or len(tag) != 16:
                raise ValueError("published packet field mismatch")
            index = len(rows)
            octets = ",".join(f"0x{value:02x}" for value in frame)
            lines.append(f"static const uint8_t packet_{index}[] = {{{octets}}};")
            rows.append(f"    {{packet_{index}, sizeof packet_{index}, {len(header)}U, "
                        f"{len(ciphertext)}U, UINT32_C({packet['seq']}), "
                        f"UINT64_C({packet['pn']}), {vector['cipher']}U}},")
    lines += ["static const public_packet packets[] = {", *rows, "};", ""]
    output.write_text("\n".join(lines), encoding="ascii")


if __name__ == "__main__":
    main()
