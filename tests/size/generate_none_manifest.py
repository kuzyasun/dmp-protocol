"""Produce the typed endpoint inputs for the exact NONE size workloads."""

import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "identity"))
from parity_drive import typed_fields, validator  # noqa: E402


def main():
    manifest, output = map(Path, sys.argv[1:])
    raw = manifest.read_bytes()
    digests = json.loads(manifest.with_name("digests.json").read_bytes())["manifests"]
    validator.validate_bytes(raw, digests[manifest.name])
    document = json.loads(raw)
    fields = typed_fields(raw, document)
    kind = document["binding"]["kind"]
    expected = {
        "direct-none.json": ("DIRECT-1", "stream-r", "retry-all"),
        "radio-none.json": ("RADIO-1", "packet", "selective-32"),
    }
    profile, binding, recovery = expected[manifest.name]
    radio_fragments = 8
    opaque = document["services"][1]
    radio_payload_supported = (fields["fragments"] >= radio_fragments and
                               radio_fragments * fields["chunk_bytes"] <= opaque["request_bytes"] and
                               any(entry["node"] == 10 and "data" in entry["actions"]
                                   for entry in opaque["acl"]))
    if (document["profile"]["id"] != profile or kind != binding or
            fields["peers"] != 1 or fields["assembly_slots"] != 1 or
            not fields["tx_borrow"] or not fields["synchronous_completion"] or
            (fields["namespace_id"], fields["node_id0"], fields["node_id1"]) != (1, 10, 20) or
            (fields["service_id0"], fields["service_id1"]) != (1, 2) or
            (profile == "DIRECT-1" and document["identity"]["sample_producer"] != 10) or
            (profile == "RADIO-1" and not radio_payload_supported) or
            any(service["security"] != "NONE" or service["freshness"] or
                service["recovery"] != recovery for service in document["services"])):
        raise ValueError(f"{manifest.name} no longer matches the exact workload")
    digest = fields.pop("sha256")
    identity = {key: fields.pop(key) for key in
                ("node_id0", "node_id1", "service_id0", "service_id1", "recovery0", "recovery1")}
    fields["frame_tx_ms"] = document["binding"]["frame_tx_ms"]
    capacities = ("peers", "sender_slots", "result_slots", "history_slots",
                  "correlation_slots", "adapter_slots", "assembly_slots",
                  "assembly_tombstone_slots", "message_bytes", "encoded_mtu", "chunk_bytes")
    lines = ['/* Generated from validated manifest bytes. */',
             f'#define DMP_NONE_MANIFEST_SHA256 "{digest}"',
             f'#define DMP_NONE_SECOND_BURST_MS {document["timing"]["burst_starts_ms"][1]}U']
    if profile == "RADIO-1":
        lines.append(f"#define DMP_NONE_PROBE_FRAGMENTS {radio_fragments}U")
    lines.extend(f"#define DMP_NONE_{key.upper()} {fields[key]}U" for key in capacities)
    lines.extend(["", "static const dmp_config dmp_none_manifest = {",
                  "    .sha256 = {" + ", ".join(f"0x{byte:02x}U" for byte in bytes.fromhex(digest)) + "},",
                  "    .security_mode = DMP_PROFILE_SECURITY_NONE,"])
    for field in ("node_id", "service_id", "recovery"):
        lines.append(f"    .{field} = {{{identity[field + '0']}U, {identity[field + '1']}U}},")
    lines.extend(f"    .{key} = {value}U," for key, value in fields.items())
    lines.append("};")
    content = "\n".join(lines) + "\n"
    if not output.is_file() or output.read_text(encoding="ascii") != content:
        output.write_text(content, encoding="ascii", newline="\n")


if __name__ == "__main__":
    main()
