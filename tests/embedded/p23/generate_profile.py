"""Bind the sized P23 responder to one pinned manifest at build time."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "identity"))
from parity_drive import typed_fields, validator  # noqa: E402


def generate(manifest: Path) -> str:
    raw = manifest.read_bytes()
    digest = json.loads(manifest.with_name("digests.json").read_bytes())["manifests"][manifest.name]
    validator.validate_bytes(raw, digest)
    document = json.loads(raw)
    fields = typed_fields(raw, document)
    binding = document["binding"]
    security = document["security"]
    profile_id, expected_binding, expected_noise = {
        "direct-nnpsk0.json": ("P23_PROFILE_DIRECT_NN", "stream-r", "NNpsk0"),
        "radio-xx.json": ("P23_PROFILE_RADIO_XX", "packet", "XX"),
    }[manifest.name]
    if (binding["kind"] != expected_binding or security["noise_mode"] != expected_noise
            or security["mode"] != "SEC-1" or fields["peers"] != 1 or not fields["tx_borrow"]
            or not fields["synchronous_completion"]
            or document["identity"]["sample_producer"] != 10
            or fields["origin_ttl"] != (2 if expected_binding == "packet" else 0)
            or tuple(fields[k] for k in ("namespace_id", "node_id0", "node_id1", "service_id0", "service_id1"))
            != (1, 10, 20, 1, 2)):
        raise ValueError(f"{manifest.name} is incompatible with the P23 responder fixture")

    fields["frame_tx_ms"] = binding["frame_tx_ms"]
    fields["freshness_required_mask"] = sum(
        1 << index for index, service in enumerate(document["services"]) if service["freshness"]
    )
    for key in ("lease_ms", "grant_delivery_age_ms", "tokens_per_association", "tokens_per_principal",
                "grant_requests_per_pair", "token_record_ms", "grant_result_ms"):
        fields[f"freshness_{key}"] = document["freshness"][key]

    budget = {
        "max_pending": "pending_per_pair", "max_scratch": "crypto_slots",
        "episode_attempts": "episode_attempts", "episode_deadline_ms": "episode_ms",
        "episode_work": "episode_crypto_ms", "episode_traffic": "episode_tx_bytes",
        "restart_backoff_ms": "restart_backoff_ms", "attempt_deadline_ms": "attempt_ms",
        "cached_responses": "duplicate_responses_per_attempt", "global_work": "global_crypto_ms_per_window",
        "ingress_work": "ingress_packets_per_window", "later_episodes": "later_episodes_per_window",
        "admit_burst": "responses_per_window", "admit_window_ms": "response_window_ms",
        "provisional_bytes": "preauth_bytes", "replay_window": "replay_window_bits",
        "failed_aead_limit": "failed_aead_limit", "association_lifetime_ms": "association_ms",
        "confirmation_timeout_ms": "confirmation_timeout_ms", "confirmation_attempts": "confirmation_attempts",
    }
    capacities = ("peers", "message_bytes", "sender_slots", "result_slots", "history_slots",
                  "correlation_slots", "adapter_slots", "assembly_slots", "assembly_tombstone_slots",
                  "encoded_mtu")
    lines = ["/* Generated from the pinned deployment manifest. */",
             f"#define P23_TARGET_PROFILE {profile_id}",
             f"#define P23_TARGET_NOISE_MODE {1 if expected_noise == 'NNpsk0' else 2}U",
             f"#define P23_TARGET_CIPHER {security['cipher']}U",
             f"#define P23_TARGET_STREAM_BYTES {fields['encoded_mtu'] if expected_binding == 'stream-r' else 1}U",
             f"#define P23_TARGET_CORE_MTU {max(fields['forward_mtu'], fields['return_mtu'])}U",
             f"#define P23_TARGET_FRESHNESS_SLOTS {2 * fields['peers'] * fields['freshness_tokens_per_association']}U"]
    lines.extend(f"#define P23_TARGET_{key.upper()} {fields[key]}U" for key in capacities)
    lines.extend(["", "static const dmp_config p23_target_config = {",
                  "    .sha256 = {" + ", ".join(f"0x{b:02x}U" for b in bytes.fromhex(fields.pop("sha256"))) + "},",
                  "    .security_mode = DMP_PROFILE_SECURITY_SEC1,"])
    for key in ("node_id", "service_id", "recovery"):
        lines.append(f"    .{key} = {{{fields.pop(key + '0')}U, {fields.pop(key + '1')}U}},")
    lines.extend(f"    .{key} = {value}U," for key, value in fields.items())
    lines.extend(["};", "", "static const dmp_hs_budget p23_target_budget = {"])
    lines.extend(f"    .{key} = {security[field]}U," for key, field in budget.items())
    lines.extend(["};", "", "static const dmp_endpoint_grant p23_target_grants[] = {"])
    permits = {"produce": "TELEM", "result": "RESULT", "read": "REQ", "status": "REQ", "data": "REQ"}
    for service in document["services"]:
        for grant in service["acl"]:
            mask = " | ".join(f"DMP_ENDPOINT_PERMIT_{key}" for key in sorted({permits[a] for a in grant["actions"]}))
            lines.append(f"    {{ .principal = {grant['node']}U, .service_id = {service['id']}U, .permit = {mask} }},")
    for node in document["freshness"]["grant_nodes"]:
        lines.append(f"    {{ .principal = {node}U, .service_id = 0U, .permit = DMP_ENDPOINT_PERMIT_CONTROL }},")
    lines.append("};")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    source, header = map(Path, sys.argv[1:])
    header.write_text(generate(source), encoding="ascii", newline="\n")
