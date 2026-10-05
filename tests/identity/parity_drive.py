"""Compare typed admission with the host JSON and PROFILE_HASH oracle.

Python reads each deployment's original bytes, including a trailing newline.
hashlib.sha256 of those bytes is the digest copied into dmp_config. The C
driver does not parse JSON. Invalid manifests stay in tests/profiles.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import validate_profile as validator  # noqa: E402

FIXTURES = ROOT / "tests" / "profiles" / "fixtures"
CORPUS = ROOT / "tests" / "profiles" / "invalid.json"
DEPLOYMENTS = (
    "direct-nnpsk0.json",
    "direct-xx.json",
    "radio-nnpsk0.json",
    "radio-xx.json",
    "test-radio-retry-all-nnpsk0.json",
    "test-radio-retry-all-xx.json",
)
RECOVERY = {"retry-all": 0, "selective-32": 1}
FIELDS = (
    "sha256",
    "namespace_id",
    "node_id0",
    "node_id1",
    "default_service",
    "service_id0",
    "service_id1",
    "recovery0",
    "recovery1",
    "peers",
    "operations_per_service",
    "assemblies_per_peer",
    "assembly_tombstones_per_peer",
    "sender_slots",
    "assembly_slots",
    "assembly_tombstone_slots",
    "result_slots",
    "history_slots",
    "correlation_slots",
    "adapter_slots",
    "application_queue_slots",
    "control_slots",
    "message_bytes",
    "fragments",
    "chunk_bytes",
    "encoded_mtu",
    "forward_mtu",
    "return_mtu",
    "queue_ms",
    "response_timeout_ms",
    "jitter_ms",
    "send_horizon_ms",
    "max_bursts",
    "receipt_delay_ms",
    "receipt_limit",
    "dedup_ms",
    "rejection_ms",
    "result_cache_ms",
    "result_deadline_ms",
    "correlation_ms",
    "tombstone_ms",
    "late_result_ms",
    "collect_ms",
    "assembly_ms",
    "burst_span_ms",
    "forward_delay_ms",
    "return_delay_ms",
    "feedback_guard_ms",
    "feedback_delay_ms",
    "max_probes",
    "max_status",
    "record_margin_ms",
    "tx_borrow",
    "synchronous_completion",
    "origin_route",
    "origin_ttl",
)


def charge_count(document, component):
    for resource in document["resources"]:
        if resource["role"] == "relay":
            continue
        for charge in resource["charges"]:
            if charge["component"] == component:
                return int(charge["count"])
        break
    raise AssertionError(f"missing endpoint charge {component}")


def typed_fields(raw, document):
    identity = document["identity"]
    limits = document["limits"]
    binding = document["binding"]
    timing = document["timing"]
    services = document["services"]
    if len(identity["nodes"]) != 2 or len(services) != 2:
        raise AssertionError("deployment is not the fixed node/service pair")
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "sha256": digest,
        "namespace_id": int(identity["namespace"]),
        "node_id0": int(identity["nodes"][0]),
        "node_id1": int(identity["nodes"][1]),
        "default_service": int(identity["default_service"]),
        "service_id0": int(services[0]["id"]),
        "service_id1": int(services[1]["id"]),
        "recovery0": RECOVERY[services[0]["recovery"]],
        "recovery1": RECOVERY[services[1]["recovery"]],
        "peers": int(limits["peers"]),
        "operations_per_service": int(limits["operations_per_service"]),
        "assemblies_per_peer": int(limits["assemblies_per_peer"]),
        "assembly_tombstones_per_peer": int(limits["assembly_tombstones_per_peer"]),
        "sender_slots": charge_count(document, "sender"),
        "assembly_slots": charge_count(document, "assembly"),
        "assembly_tombstone_slots": charge_count(document, "assembly_tombstone"),
        "result_slots": charge_count(document, "result"),
        "history_slots": charge_count(document, "history"),
        "correlation_slots": charge_count(document, "correlation"),
        "adapter_slots": charge_count(document, "adapter"),
        "application_queue_slots": int(limits["application_queue_slots"]),
        "control_slots": int(limits["control_slots"]),
        "message_bytes": int(limits["message_bytes"]),
        "fragments": int(limits["fragments"]),
        "chunk_bytes": int(limits["chunk_bytes"]),
        "encoded_mtu": int(binding["encoded_mtu"]),
        "forward_mtu": int(binding["forward_mtu"]),
        "return_mtu": int(binding["return_mtu"]),
        "queue_ms": int(timing["queue_ms"]),
        "response_timeout_ms": int(timing["response_timeout_ms"]),
        "jitter_ms": int(timing["jitter_ms"]),
        "send_horizon_ms": int(timing["send_horizon_ms"]),
        "max_bursts": int(timing["max_bursts"]),
        "receipt_delay_ms": int(timing["receipt_delay_ms"]),
        "receipt_limit": int(timing["receipt_limit"]),
        "dedup_ms": int(timing["dedup_ms"]),
        "rejection_ms": int(timing["rejection_ms"]),
        "result_cache_ms": int(timing["result_cache_ms"]),
        "result_deadline_ms": int(timing["result_deadline_ms"]),
        "correlation_ms": int(timing["correlation_ms"]),
        "tombstone_ms": int(timing["tombstone_ms"]),
        "late_result_ms": int(timing["late_result_ms"]),
        "collect_ms": int(timing["collect_ms"]),
        "assembly_ms": int(timing["assembly_ms"]),
        "burst_span_ms": int(timing["burst_span_ms"]),
        "forward_delay_ms": int(timing["forward_delay_ms"]),
        "return_delay_ms": int(timing["return_delay_ms"]),
        "feedback_guard_ms": int(timing["feedback_guard_ms"]),
        "feedback_delay_ms": int(timing["feedback_delay_ms"]),
        "max_probes": int(timing["max_probes"]),
        "max_status": int(timing["max_status"]),
        "record_margin_ms": int(timing["record_margin_ms"]),
        "tx_borrow": 1 if binding["tx_ownership"] == "borrow" else 0,
        "synchronous_completion": 1 if binding["synchronous_completion"] else 0,
        "origin_route": validator.origin_route_of(document),
        "origin_ttl": validator.origin_ttl_of(document),
    }


def run_admit(executable, fields):
    payload = "".join(f"{name} {fields[name]}\n" for name in FIELDS)
    completed = subprocess.run(
        [executable, "--config"],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    parsed = {}
    for line in completed.stdout.splitlines():
        key, value = line.split(" ", 1)
        parsed[key] = value
    return parsed


def expect_deployment(executable, name):
    path = ROOT / "profiles" / "deployments" / name
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    python_result = validator.validate_bytes(raw)
    if python_result["sha256"] != digest:
        raise AssertionError(f"{name}: validator digest is not hashlib of the file bytes")
    document = json.loads(raw.decode("utf-8"))
    fields = typed_fields(raw, document)
    if fields["sha256"] != digest:
        raise AssertionError(f"{name}: typed digest was not the original-byte hash")
    admitted = run_admit(executable, fields)
    if admitted.get("status") != "ok":
        raise AssertionError(f"{name}: C admission returned {admitted.get('status')}")
    for key in FIELDS:
        if admitted.get(key) != str(fields[key]):
            raise AssertionError(
                f"{name}: admitted {key}={admitted.get(key)} expected {fields[key]}")


def main(argv):
    if len(argv) != 2:
        raise SystemExit("usage: parity_drive.py <dmp_test_profile_admit>")
    executable = argv[1]
    if not CORPUS.is_file():
        raise SystemExit(f"missing invalid corpus {CORPUS}")
    fixtures = sorted(FIXTURES.glob("*.json"))
    if len(fixtures) != 3:
        raise SystemExit(f"expected 3 fixtures, found {len(fixtures)}")
    for name in DEPLOYMENTS:
        expect_deployment(executable, name)
    print(f"parity ok: {len(DEPLOYMENTS)} deployments; "
          f"invalid corpus and {len(fixtures)} fixtures remain host-side")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
