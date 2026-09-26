#!/usr/bin/env python3
"""Generate a C header for the public Noise provider fixture probe."""

import argparse
import json
from pathlib import Path
import re
import sys


EXPECTED_PROTOCOLS = {
    "Noise_NNpsk0_25519_ChaChaPoly_SHA256": ("nnpsk0", 1, 2),
    "Noise_XX_25519_ChaChaPoly_SHA256": ("xx", 2, 3),
}


def decode_hex(value, label, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) % 2 != 0:
        raise ValueError("{} must be an even-length hexadecimal string".format(label))
    if not re.fullmatch(r"[0-9a-fA-F]*", value):
        raise ValueError("{} contains non-hexadecimal characters".format(label))
    return bytes.fromhex(value)


def c_string(value):
    return json.dumps(value, ensure_ascii=True)


class HeaderBuilder:
    def __init__(self):
        self.lines = []

    def add_array(self, name, value):
        if value is None:
            return "{NULL, 0U}"
        if not value:
            return "{NULL, 0U}"
        self.lines.append("static const uint8_t {}[] = {{".format(name))
        for offset in range(0, len(value), 12):
            row = value[offset : offset + 12]
            self.lines.append("    " + ", ".join("0x{:02x}U".format(byte) for byte in row) + ",")
        self.lines.append("};")
        return "{{{}, sizeof({})}}".format(name, name)


def required_bytes(obj, key, label, nullable=False):
    if key not in obj:
        raise ValueError("missing {}".format(label))
    return decode_hex(obj[key], label, nullable=nullable)


def validate_packet(vector, name, direction, directional_key, plaintext):
    matches = [packet for packet in vector.get("packets", []) if packet.get("name") == name]
    if len(matches) != 1:
        raise ValueError("{} must have exactly one {} packet".format(vector["protocol_name"], name))
    packet = matches[0]
    if packet.get("direction") != direction or packet.get("pn") != 0:
        raise ValueError("{} must be direction {} at PN 0".format(name, direction))
    if required_bytes(packet, "key", name + ".key") != directional_key:
        raise ValueError("{} key does not match its directional split-key fixture".format(name))
    if required_bytes(packet, "plaintext", name + ".plaintext") != plaintext:
        raise ValueError("{} has an unexpected plaintext".format(name))
    for field in ("nonce", "aad", "header", "ciphertext", "tag", "frame"):
        required_bytes(packet, field, name + "." + field)
    if len(decode_hex(packet["tag"], name + ".tag")) != 16:
        raise ValueError("{} tag must be 16 bytes".format(name))
    return packet


def validate_transport_packets(vector, i_to_r_key, r_to_i_key):
    packets = vector.get("packets")
    if not isinstance(packets, list) or len(packets) != 16:
        raise ValueError("{} must contain all 16 transport packets".format(vector["protocol_name"]))

    directional_keys = {0: i_to_r_key, 1: r_to_i_key}
    seen_names = set()
    seen_packet_numbers = set()
    decoded_packets = []
    for packet in packets:
        if not isinstance(packet, dict):
            raise ValueError("{} has a malformed transport packet".format(vector["protocol_name"]))
        name = packet.get("name")
        direction = packet.get("direction")
        packet_number = packet.get("pn")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_]+", name):
            raise ValueError("{} has an invalid transport packet name".format(vector["protocol_name"]))
        if name in seen_names:
            raise ValueError("{} has duplicate packet name {}".format(vector["protocol_name"], name))
        if type(direction) is not int or direction not in directional_keys:
            raise ValueError("{} packet {} has an invalid direction".format(vector["protocol_name"], name))
        if type(packet_number) is not int or packet_number < 0 or packet_number >= (1 << 64) - 1:
            raise ValueError("{} packet {} has an invalid packet number".format(vector["protocol_name"], name))
        if (direction, packet_number) in seen_packet_numbers:
            raise ValueError("{} has duplicate direction/packet-number metadata".format(vector["protocol_name"]))

        decoded = {}
        for field in ("key", "nonce", "aad", "header", "plaintext", "ciphertext", "tag", "frame"):
            decoded[field] = required_bytes(packet, field, name + "." + field)
        if decoded["key"] != directional_keys[direction]:
            raise ValueError("{} packet {} key does not match its direction".format(vector["protocol_name"], name))
        if len(decoded["nonce"]) != 12 or decoded["nonce"] != b"\x00" * 4 + packet_number.to_bytes(8, "little"):
            raise ValueError("{} packet {} nonce does not encode its packet number".format(vector["protocol_name"], name))
        if len(decoded["tag"]) != 16 or len(decoded["ciphertext"]) != len(decoded["plaintext"]):
            raise ValueError("{} packet {} has invalid ChaChaPoly lengths".format(vector["protocol_name"], name))

        seen_names.add(name)
        seen_packet_numbers.add((direction, packet_number))
        decoded_packets.append(packet)

    if not {"finish", "ready"}.issubset(seen_names):
        raise ValueError("{} transport packets must include FINISH and READY".format(vector["protocol_name"]))
    return decoded_packets


def validate_vector(vector, protocol_name, short_name, mode, flight_count):
    if vector.get("protocol_name") != protocol_name:
        raise ValueError("unexpected protocol name")
    if vector.get("mode") != mode or vector.get("cipher") != 1:
        raise ValueError("{} must be mode {} with ChaChaPoly".format(protocol_name, mode))
    inputs = vector.get("test_only_inputs")
    if not isinstance(inputs, dict):
        raise ValueError("{} has no test_only_inputs object".format(protocol_name))

    decoded_inputs = {}
    for field in (
        "init_ephemeral",
        "resp_ephemeral",
        "init_static",
        "resp_static",
        "psk",
        "attempt_id",
        "manifest_bytes",
        "profile_hash",
    ):
        decoded_inputs[field] = required_bytes(
            inputs,
            field,
            protocol_name + ".test_only_inputs." + field,
            nullable=field in ("init_static", "resp_static", "psk"),
        )

    for field in ("init_ephemeral", "resp_ephemeral"):
        if len(decoded_inputs[field]) != 32:
            raise ValueError("{} must be 32 bytes".format(field))
    if mode == 1:
        if decoded_inputs["init_static"] is not None or decoded_inputs["resp_static"] is not None:
            raise ValueError("NNpsk0 must not contain static keypairs")
        if len(decoded_inputs["psk"] or b"") != 32:
            raise ValueError("NNpsk0 PSK must be 32 bytes")
    else:
        if len(decoded_inputs["init_static"] or b"") != 32 or len(decoded_inputs["resp_static"] or b"") != 32:
            raise ValueError("XX static keypairs must be 32 bytes")
        if decoded_inputs["psk"] is not None:
            raise ValueError("XX must not contain a PSK")
    if len(decoded_inputs["attempt_id"]) != 16 or len(decoded_inputs["profile_hash"]) != 32:
        raise ValueError("{} has an invalid attempt_id or profile_hash length".format(protocol_name))

    prologue = required_bytes(vector, "prologue", protocol_name + ".prologue")
    expected_hash = required_bytes(vector, "handshake_hash", protocol_name + ".handshake_hash")
    i_to_r_key = required_bytes(vector, "i_to_r_key", protocol_name + ".i_to_r_key")
    r_to_i_key = required_bytes(vector, "r_to_i_key", protocol_name + ".r_to_i_key")
    if len(expected_hash) != 32 or len(i_to_r_key) != 32 or len(r_to_i_key) != 32:
        raise ValueError("{} has an invalid hash or key length".format(protocol_name))

    flights = vector.get("flights")
    if not isinstance(flights, list) or len(flights) != flight_count:
        raise ValueError("{} must contain {} flights".format(protocol_name, flight_count))
    decoded_flights = []
    for index, flight in enumerate(flights, start=1):
        if flight.get("flight") != index:
            raise ValueError("{} flight numbers must be sequential from 1".format(protocol_name))
        decoded_flights.append(
            {
                "message": required_bytes(flight, "noise_message", "flight {} message".format(index)),
                "plaintext": required_bytes(flight, "noise_plaintext", "flight {} plaintext".format(index)),
            }
        )

    finish = validate_packet(vector, "finish", 0, i_to_r_key, b"\x04")
    ready = validate_packet(vector, "ready", 1, r_to_i_key, b"\x05")
    transport_packets = validate_transport_packets(vector, i_to_r_key, r_to_i_key)
    return {
        "name": short_name,
        "protocol_name": protocol_name,
        "inputs": decoded_inputs,
        "prologue": prologue,
        "handshake_hash": expected_hash,
        "i_to_r_key": i_to_r_key,
        "r_to_i_key": r_to_i_key,
        "flights": decoded_flights,
        "finish": finish,
        "ready": ready,
        "transport_packets": transport_packets,
    }


def bytes_ref(builder, name, value):
    return builder.add_array(name, value)


def emit_packet(builder, fixture_name, field_name, packet):
    fields = []
    for key in ("key", "nonce", "aad", "header", "plaintext", "ciphertext", "tag", "frame"):
        value = decode_hex(packet[key], fixture_name + "." + field_name + "." + key)
        fields.append(".{} = {}".format(key, bytes_ref(builder, "noise_fixture_{}_{}_{}".format(fixture_name, field_name, key), value)))
    fields.extend(
        [
            ".name = {}".format(c_string(packet.get("name", field_name))),
            ".direction = {}U".format(packet["direction"]),
            ".pn = UINT64_C({})".format(packet["pn"]),
        ]
    )
    return "{\n        " + ",\n        ".join(fields) + "\n    }"


def emit_fixture(builder, fixture):
    name = fixture["name"]
    inputs = fixture["inputs"]
    fields = []
    for field in (
        "init_ephemeral",
        "resp_ephemeral",
        "init_static",
        "resp_static",
        "psk",
        "attempt_id",
        "manifest_bytes",
        "profile_hash",
    ):
        fields.append(".{} = {}".format(field, bytes_ref(builder, "noise_fixture_{}_{}".format(name, field), inputs[field])))
    for field in ("prologue", "handshake_hash", "i_to_r_key", "r_to_i_key"):
        fields.append(".{} = {}".format(field, bytes_ref(builder, "noise_fixture_{}_{}".format(name, field), fixture[field])))

    flight_rows = []
    for index, flight in enumerate(fixture["flights"], start=1):
        message = bytes_ref(builder, "noise_fixture_{}_flight{}_message".format(name, index), flight["message"])
        plaintext = bytes_ref(builder, "noise_fixture_{}_flight{}_plaintext".format(name, index), flight["plaintext"])
        flight_rows.append("{{.message = {}, .plaintext = {}}}".format(message, plaintext))
    builder.lines.append("static const noise_fixture_probe_flight_t noise_fixture_{}_flights[] = {{".format(name))
    builder.lines.extend("    {},".format(row) for row in flight_rows)
    builder.lines.append("};")
    fields.append(".flights = noise_fixture_{}_flights".format(name))
    fields.append(".flight_count = sizeof(noise_fixture_{}_flights) / sizeof(noise_fixture_{}_flights[0])".format(name, name))
    fields.append(".finish = {}".format(emit_packet(builder, name, "finish", fixture["finish"])))
    fields.append(".ready = {}".format(emit_packet(builder, name, "ready", fixture["ready"])))
    packet_rows = [
        emit_packet(builder, name, "transport_" + packet["name"], packet)
        for packet in fixture["transport_packets"]
    ]
    builder.lines.append("static const noise_fixture_probe_packet_t noise_fixture_{}_transport_packets[] = {{".format(name))
    builder.lines.extend("    {},".format(row) for row in packet_rows)
    builder.lines.append("};")
    fields.append(".transport_packets = noise_fixture_{}_transport_packets".format(name))
    fields.append(".transport_packet_count = sizeof(noise_fixture_{}_transport_packets) / sizeof(noise_fixture_{}_transport_packets[0])".format(name, name))
    fields.append(".name = {}".format(c_string(name)))
    fields.append(".protocol_name = {}".format(c_string(fixture["protocol_name"])))
    return "    {\n        " + ",\n        ".join(fields) + "\n    }"


def generate_header(source_path, source, vectors):
    builder = HeaderBuilder()
    fixture_rows = [emit_fixture(builder, fixture) for fixture in vectors]
    lines = [
        "/* Generated from {}. Public test-only credentials; never use in production. */".format(source_path.as_posix()),
        "#ifndef NOISE_FIXTURE_PROBE_H",
        "#define NOISE_FIXTURE_PROBE_H",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "typedef struct { const uint8_t *data; size_t size; } noise_fixture_probe_bytes_t;",
        "typedef struct { noise_fixture_probe_bytes_t message; noise_fixture_probe_bytes_t plaintext; } noise_fixture_probe_flight_t;",
        "typedef struct {",
        "    const char *name;",
        "    uint8_t direction;",
        "    uint64_t pn;",
        "    noise_fixture_probe_bytes_t key;",
        "    noise_fixture_probe_bytes_t nonce;",
        "    noise_fixture_probe_bytes_t aad;",
        "    noise_fixture_probe_bytes_t header;",
        "    noise_fixture_probe_bytes_t plaintext;",
        "    noise_fixture_probe_bytes_t ciphertext;",
        "    noise_fixture_probe_bytes_t tag;",
        "    noise_fixture_probe_bytes_t frame;",
        "} noise_fixture_probe_packet_t;",
        "typedef struct {",
        "    const char *name;",
        "    const char *protocol_name;",
        "    noise_fixture_probe_bytes_t init_ephemeral;",
        "    noise_fixture_probe_bytes_t resp_ephemeral;",
        "    noise_fixture_probe_bytes_t init_static;",
        "    noise_fixture_probe_bytes_t resp_static;",
        "    noise_fixture_probe_bytes_t psk;",
        "    noise_fixture_probe_bytes_t attempt_id;",
        "    noise_fixture_probe_bytes_t manifest_bytes;",
        "    noise_fixture_probe_bytes_t profile_hash;",
        "    noise_fixture_probe_bytes_t prologue;",
        "    noise_fixture_probe_bytes_t handshake_hash;",
        "    noise_fixture_probe_bytes_t i_to_r_key;",
        "    noise_fixture_probe_bytes_t r_to_i_key;",
        "    const noise_fixture_probe_flight_t *flights;",
        "    size_t flight_count;",
        "    noise_fixture_probe_packet_t finish;",
        "    noise_fixture_probe_packet_t ready;",
        "    const noise_fixture_probe_packet_t *transport_packets;",
        "    size_t transport_packet_count;",
        "} noise_fixture_probe_fixture_t;",
        "",
        "#define NOISE_FIXTURE_PROBE_BYTES(name) {name, sizeof(name)}",
        "",
    ]
    lines.extend(builder.lines)
    lines.append("static const noise_fixture_probe_fixture_t noise_fixture_probe_fixtures[] = {")
    lines.extend(row + "," for row in fixture_rows)
    lines.extend(
        [
            "};",
            "#define NOISE_FIXTURE_PROBE_FIXTURE_COUNT (sizeof(noise_fixture_probe_fixtures) / sizeof(noise_fixture_probe_fixtures[0]))",
            "",
            "#endif",
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="normative public security vector JSON")
    parser.add_argument("--output", required=True, type=Path, help="generated header path under the build directory")
    args = parser.parse_args()

    try:
        source_path = args.input
        source = json.loads(source_path.read_text(encoding="utf-8"))
        if "revision 10" not in source.get("specification", "") or "SEC-1 revision 5" not in source.get("specification", ""):
            raise ValueError("input is not the expected DMP revision 10 / SEC-1 revision 5 fixture set")
        matches = source.get("vectors")
        if not isinstance(matches, list):
            raise ValueError("input has no vectors array")
        fixtures = []
        for protocol_name, details in EXPECTED_PROTOCOLS.items():
            selected = [vector for vector in matches if vector.get("protocol_name") == protocol_name]
            if len(selected) != 1:
                raise ValueError("expected exactly one fixture for {}".format(protocol_name))
            fixtures.append(validate_vector(selected[0], protocol_name, *details))

        output_path = args.output
        if output_path.resolve() == source_path.resolve():
            raise ValueError("output must not overwrite the normative JSON input")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(generate_header(source_path, source, fixtures), encoding="utf-8", newline="\n")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print("noise fixture header generation failed: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
