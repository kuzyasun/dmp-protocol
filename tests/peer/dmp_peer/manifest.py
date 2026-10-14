"""Strict parser for the published DMP test-manifest contract."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ManifestError(ValueError):
    def __init__(self, code: str, path: str, message: str):
        self.code, self.path, self.message = code, path, message
        super().__init__(f"{code} at {path}: {message}")


@dataclass(frozen=True)
class Manifest:
    values: dict[str, Any]
    sha256: str


_FROZEN = {
    "direct-nnpsk0-async.json": "5cb5603473be180c4b70502c7a93dfc0c725703ea3ed0e7481fa71f16798d390",
    "direct-nnpsk0.json": "40abedfbb1799ea6cb711f739101d40bae6454eac719858c79b066f2670ad0c1",
    "direct-xx.json": "289ed444a458bba2801fbceb68346cfae23de79beaab2d3402a75539e11b23f9",
    "radio-nnpsk0-n2.json": "6753a738f003e9dc9f7dafdf24735ee907a3904576718d18709b751c88476873",
    "radio-nnpsk0.json": "a3887c44b06b4d2f905f89fae4b28b99c0f00d93d77c50b1f752ce77bde4922f",
    "radio-xx.json": "b27b06ee7ad0a0d51e79cf894a373bf2b74d9f9b3674b24b9256418b9141641a",
    "test-direct-minimal-128.json": "d987dbae6d7490d98d45aaca7d7af13c600d4c3557b3453c3598e5ffec9c0fa1",
    "test-direct-minimal-256.json": "9cc6d8ae95c5f241166c9af9edc70d12e61fdb4404c10479bb68de32d0d344ea",
    "test-direct-sample-retry-2-nnpsk0.json": "478af0bc4912d0fc46ed76c249ec5f30f8f64bc89ed7411e9b9231bbf487db5c",
    "test-radio-retry-all-nnpsk0.json": "b33d39bffcb7c2750fbf860e4e040cd5b4e29101a6d6c0ca604faef9719ccf3f",
    "test-radio-retry-all-xx.json": "369314bd7daf840b22d34e10c432fe08575ecd9e1c562cfd730a342bc5e1286a",
    "test-peer-tcp-stream-r-nnpsk0.json": "8de56192f75e7677081d704d568ddb64b1292c6ded72449675ebceefd53d9a1a",
    "test-peer-tcp-stream-r-sample20-nnpsk0.json": "b84132a086323d432492967755244b59a9a53405880d85f354c25353757c6aa6",
    "test-mixed-tcp-stream-r-sim-packet-nnpsk0.json": "2bc3c2ee1c9e8f3aa87af4afd2f0cab996099fc69da1f0938c23e050c8c68faf",
    "test-direct-multi-peer-nnpsk0.json": "001eb42d8f440e0ceaf1711e764ceacfc3c1dd034cfb2d7f320be7d877f7454f",
}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError("json", "$", f"duplicate object member {key!r}")
        result[key] = value
    return result


def _parse_integer(token: str) -> int:
    digits = token[1:] if token.startswith("-") else token
    if len(digits) > 20:
        raise ManifestError("json", "$", "integer has more than 20 digits")
    return int(token)


def _reject_number(_token: str):
    raise ManifestError("json", "$", "fractional and exponent numbers are forbidden")


def _reject_constant(_token: str):
    raise ManifestError("json", "$", "non-finite numbers are forbidden")


def _check_text(value: Any, path: str = "$") -> None:
    if isinstance(value, str):
        index = 0
        while index < len(value):
            codepoint = ord(value[index])
            if 0xD800 <= codepoint <= 0xDBFF:
                if index + 1 >= len(value) or not 0xDC00 <= ord(value[index + 1]) <= 0xDFFF:
                    raise ManifestError("json", path, "unpaired Unicode surrogate")
                index += 2
                continue
            if 0xDC00 <= codepoint <= 0xDFFF:
                raise ManifestError("json", path, "unpaired Unicode surrogate")
            index += 1
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_text(item, f"{path}[{index}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_text(key, path)
            _check_text(item, f"{path}.{key}")


def _depth(value: Any, level: int = 0) -> int:
    if not isinstance(value, (dict, list)):
        return level
    if level >= 24:
        raise ManifestError("json", "$", "more than 24 nested containers")
    values = value.values() if isinstance(value, dict) else value
    return max((_depth(item, level + 1) for item in values), default=level + 1)


def _schema_check(value: Any, schema: dict, path: str = "$") -> None:
    expected = schema.get("type")
    types = {
        "object": lambda x: isinstance(x, dict),
        "array": lambda x: isinstance(x, list),
        "string": lambda x: isinstance(x, str),
        "integer": lambda x: isinstance(x, int) and not isinstance(x, bool),
        "boolean": lambda x: isinstance(x, bool),
    }
    if expected and not types[expected](value):
        raise ManifestError("schema", path, f"expected {expected}")
    if "enum" in schema and not any(type(value) is type(candidate) and value == candidate
                                    for candidate in schema["enum"]):
        raise ManifestError("schema", path, "value is outside the allowed enum")
    if expected == "integer":
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            raise ManifestError("schema", path, "integer is outside the allowed range")
    if expected == "string":
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", len(value)):
            raise ManifestError("schema", path, "string length is outside the allowed range")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            raise ManifestError("schema", path, "string does not match required pattern")
    if expected == "array":
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", len(value)):
            raise ManifestError("schema", path, "array size is outside the allowed range")
        for index, item in enumerate(value):
            _schema_check(item, schema["items"], f"{path}[{index}]")
    if expected == "object":
        for key in schema.get("required", ()):
            if key not in value:
                raise ManifestError("schema", path, f"missing required member {key}")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key not in properties:
                if schema.get("additionalProperties") is False:
                    raise ManifestError("schema", f"{path}.{key}", "unknown member")
                continue
            _schema_check(item, properties[key], f"{path}.{key}")


_SCHEMA_PATH = Path(__file__).with_name("manifest-v1.schema.json")
_SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def parse_manifest(raw: bytes, expected_sha256: str | None = None) -> Manifest:
    if not isinstance(raw, bytes):
        raise TypeError("manifest input must be original bytes")
    if len(raw) > 262144:
        raise ManifestError("encoding", "$", "manifest exceeds 262144 bytes")
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ManifestError("encoding", "$", "UTF-8 BOM is forbidden")
    try:
        source = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ManifestError("encoding", "$", "manifest is not valid UTF-8") from exc
    try:
        value = json.loads(source, object_pairs_hook=_pairs, parse_int=_parse_integer,
                           parse_float=_reject_number, parse_constant=_reject_constant)
    except ManifestError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ManifestError("json", "$", "invalid JSON document") from exc
    if not isinstance(value, dict):
        raise ManifestError("schema", "$", "top-level value must be an object")
    _depth(value)
    _check_text(value)
    _schema_check(value, _SCHEMA)
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ManifestError("digest", "$", "SHA-256 of original bytes does not match")
    _check_contract_feasibility(value)
    return Manifest(value, digest)


def _check_contract_feasibility(value: dict[str, Any]) -> None:
    def require(condition: bool, code: str, path: str, message: str) -> None:
        if not condition:
            raise ManifestError(code, path, message)

    def width(value: int) -> int:
        return max(1, (value.bit_length() + 6) // 7)

    profile = value["profile"]
    profile_id = profile["id"]
    tcp_profile = profile_id in {"PEER-TCP-STREAM-R", "MIXED-TCP-STREAM-R-SIM-PACKET"}
    multi_peer_profile = profile_id == "TEST-DIRECT-MULTIPEER"
    require(("tcp_binding" in value) == tcp_profile, "profile", "$.tcp_binding",
            "TCP binding settings must appear only on TCP Stream R profiles")
    require(("mixed_path" in value) == (profile_id == "MIXED-TCP-STREAM-R-SIM-PACKET"),
            "profile", "$.mixed_path", "mixed path settings must appear only on the mixed profile")
    require(("multi_peer" in value) == multi_peer_profile, "profile", "$.multi_peer",
            "multi-peer settings must appear only on the shared-endpoint profile")
    identity = value["identity"]
    expected_node_count = 5 if multi_peer_profile else 2
    require(len(identity["nodes"]) == expected_node_count
            and len(set(identity["nodes"])) == expected_node_count,
            "identity", "$.identity.nodes",
            "selected profile requires an exact endpoint count with distinct IDs")
    message_ceiling = 4096 if multi_peer_profile else 1024
    require(value["limits"]["message_bytes"] <= message_ceiling,
            "geometry", "$.limits.message_bytes", "selected profile exceeds its logical message ceiling")
    require(identity["sample_producer"] in identity["nodes"], "identity",
            "$.identity.sample_producer", "SAMPLE producer must be an endpoint")
    require(identity["default_service"] == 1, "service", "$.identity.default_service",
            "service 1 is the application default")
    require(identity["epoch_source"] == "sec1-association"
            and identity["restart"] == "fresh-handshake"
            and identity["sample_epoch"] == "persistent-never-reused-u64",
            "identity", "$.identity", "unsupported identity lifecycle")

    profile_key = (profile["owner"], profile["id"], profile["revision"])
    direct_profiles = {
        ("DMP-reference", "DIRECT-1", 4),
        ("DMP-test", "TEST-DIRECT-ASYNC", 1),
        ("DMP-test", "TEST-DIRECT-MINIMAL-128", 1),
        ("DMP-test", "TEST-DIRECT-MINIMAL-256", 1),
        ("DMP-test", "TEST-DIRECT-SAMPLE-RETRY-2", 1),
    }
    radio_profiles = {
        ("DMP-reference", "RADIO-1", 4),
        ("DMP-test", "TEST-RADIO-N2", 1),
        ("DMP-test", "TEST-RADIO-RETRY-ALL", 1),
    }
    tcp_direct = ("DMP-test", "PEER-TCP-STREAM-R", 1)
    tcp_mixed = ("DMP-test", "MIXED-TCP-STREAM-R-SIM-PACKET", 1)
    multi_peer = ("DMP-test", "TEST-DIRECT-MULTIPEER", 1)
    allowed_profiles = direct_profiles | radio_profiles | {tcp_direct, tcp_mixed, multi_peer}
    require(profile_key in allowed_profiles, "profile", "$.profile",
            "profile family, owner, or revision is not admitted by this contract")
    direct = profile_key in direct_profiles
    binding, limits, security = value["binding"], value["limits"], value["security"]
    timing, freshness, services = value["timing"], value["freshness"], value["services"]
    if multi_peer_profile and profile_key == multi_peer:
        direct = True
        require((binding["id"], binding["kind"], binding["topology"], binding["context"],
                 binding["ttl"], value["relays"]) ==
                ("DMP-test/SIM-STREAM-R", "stream-r", "shared-endpoint-multi-peer",
                 "association", 0, []),
                "profile", "$.binding", "multi-peer profile binding/topology/context is inconsistent")
        expected_recovery = "retry-all"
    elif tcp_profile and profile_key == tcp_direct:
        direct = True
        require((binding["id"], binding["kind"], binding["topology"], binding["context"],
                 binding["ttl"], value["relays"]) ==
                ("DMP-test/TCP-STREAM-R", "stream-r", "point-to-point", "association", 0, []),
                "profile", "$.binding", "peer TCP profile binding/topology/context is inconsistent")
        expected_recovery = "retry-all"
    elif tcp_profile and profile_key == tcp_mixed:
        require((binding["id"], binding["kind"], binding["topology"], binding["context"]) ==
                ("DMP-test/SIM-PACKET", "packet", "static-unicast", "origin-explicit"),
                "profile", "$.binding", "mixed profile packet binding is inconsistent")
        expected_recovery = "selective-32"
        relay_ids = [relay["node"] for relay in value["relays"]]
        require(len(relay_ids) == 2 and len(set(relay_ids)) == 2
                and not set(relay_ids).intersection(identity["nodes"]),
                "identity", "$.relays", "mixed profile requires two distinct non-endpoint relays")
        require(binding["ttl"] >= len(relay_ids), "profile", "$.binding.ttl",
                "mixed profile TTL must cover its relay path")
    elif direct:
        require((binding["id"], binding["kind"], binding["topology"], binding["context"],
                 binding["ttl"], value["relays"]) ==
                ("DMP-test/SIM-STREAM-R", "stream-r", "point-to-point", "association", 0, []),
                "profile", "$.binding", "DIRECT profile binding/topology/context is inconsistent")
        expected_recovery = "retry-all"
    else:
        require((binding["id"], binding["kind"], binding["topology"], binding["context"]) ==
                ("DMP-test/SIM-PACKET", "packet", "static-unicast", "origin-explicit"),
                "profile", "$.binding", "RADIO profile binding/topology/context is inconsistent")
        expected_recovery = ("retry-all" if profile["id"] == "TEST-RADIO-RETRY-ALL"
                             else "selective-32")
        relay_ids = [relay["node"] for relay in value["relays"]]
        require(len(relay_ids) <= 4 and len(set(relay_ids)) == len(relay_ids)
                and not set(relay_ids).intersection(identity["nodes"]),
                "identity", "$.relays", "relay IDs must be unique and distinct from endpoints")
        require(binding["ttl"] >= len(relay_ids),
                "profile", "$.binding.ttl", "RADIO TTL must cover its relay path")

    if multi_peer_profile:
        _check_multi_peer_profile(value, require)

    services = value["services"]
    require([service["id"] for service in services] == [1, 2], "service", "$.services",
            "the manifest requires services 1 and 2 in order")
    sample_service, opaque_service = services
    require(all(service["reply_service"] == service["id"]
                and service["security"] == "SEC-1"
                and service["payload_desc"] == "omitted"
                and service["recovery"] == expected_recovery
                for service in services),
            "service", "$.services", "service addressing, security, codec, or recovery is noncanonical")
    require((sample_service["schema"], sample_service["service_encoding"],
             sample_service["freshness"], sample_service["request_bytes"],
             sample_service["result_bytes"]) ==
            ("DMP-reference/SAMPLE-1/2", "omitted", False, 1, 17),
            "service", "$.services[0]", "service 1 must retain the SAMPLE-1 contract")
    require((opaque_service["schema"], opaque_service["service_encoding"],
             opaque_service["idempotent"]) ==
            ("DMP-test/OPAQUE-1/1", "explicit", True),
            "service", "$.services[1]", "service 2 must use the idempotent opaque test service")
    for service in services:
        acl_nodes = [entry["node"] for entry in service["acl"]]
        require(len(acl_nodes) == len(identity["nodes"])
                and len(set(acl_nodes)) == len(acl_nodes)
                and set(acl_nodes) == set(identity["nodes"]),
                "service", "$.services.acl", "ACL must cover every endpoint exactly once")
    sample_acl = {entry["node"]: entry["actions"] for entry in sample_service["acl"]}
    producer = identity["sample_producer"]
    consumers = set(identity["nodes"]) - {producer}
    expected_sample_acl = ({producer: ["produce", "result"]}
                           | {node: ["read", "status"] for node in consumers})
    require(sample_acl == expected_sample_acl,
            "service", "$.services[0].acl", "SAMPLE-1 producer/consumer ACL is inconsistent")
    opaque_acl = {entry["node"]: entry["actions"] for entry in opaque_service["acl"]}
    require(opaque_acl == {node: ["data", "result"] for node in identity["nodes"]},
            "service", "$.services[1].acl", "opaque test service requires its fixed two-node ACL")
    require(value["sample"]["telemetry_bytes"] == 16
            and value["sample"]["read_request_bytes"] == 1
            and value["sample"]["read_result_bytes"] == 17
            and value["sample"]["status_request_bytes"] == 1
            and value["sample"]["status_result_bytes"] == 2
            and sample_service["result_bytes"] == value["sample"]["read_result_bytes"],
            "service", "$.sample", "SAMPLE-1 asserted lengths do not match its fixed schema")
    require(0 < opaque_service["request_bytes"] <= limits["message_bytes"]
            and 0 < opaque_service["result_bytes"] <= limits["message_bytes"],
            "geometry", "$.services[1]", "service-2 request/result exceed admitted message capacity")
    require(opaque_service["freshness"] == (freshness["lease_ms"] > 0),
            "security", "$.services[1].freshness", "service freshness and grant configuration disagree")

    allowed_security = {"NNpsk0": "provisioned-pairwise-psk",
                        "XX": "authenticated-oob-xx"}
    require(security["mode"] in allowed_security
            and security["credential"] == allowed_security[security["mode"]]
            and security["cipher"] == 1,
            "security", "$.security", "mode, credential, and mandatory cipher do not match")
    require(all(service["security"] == "SEC-1" for service in services),
            "security", "$.services", "both application services require SEC-1")
    require(security["crypto_slots"] <= security["pending_per_pair"]
            * (limits["peers"] if multi_peer_profile else 1)
            and security["pending_per_pair"] >= 1
            and security["active_per_pair"] >= 1,
            "security", "$.security", "crypto/pending/active admission limits are infeasible")
    require((security["replay_window_bits"] & (security["replay_window_bits"] - 1)) == 0
            and 64 <= security["replay_window_bits"] <= 1024,
            "security", "$.security.replay_window_bits", "replay window must be a power of two from 64 to 1024")
    require(security["preauth_slots"] >= 1
            and security["preauth_bytes"] >= 120 * security["preauth_slots"],
            "security", "$.security", "bootstrap admission must reserve one complete 120-byte flight")
    require(security["association_ms"] > 0 and security["drain_ms"] < security["association_ms"],
            "security", "$.security.drain_ms", "drain must fit within the original association lifetime")

    message_bytes, chunk_bytes = limits["message_bytes"], limits["chunk_bytes"]
    require(0 < chunk_bytes < message_bytes, "geometry", "$.limits.chunk_bytes",
            "application chunk must be positive and smaller than the message bound")
    fragments = (message_bytes + chunk_bytes - 1) // chunk_bytes
    family_cap = 32 if multi_peer_profile else (16 if direct else 32)
    require(2 <= fragments <= limits["fragments"] <= family_cap,
            "geometry", "$.limits.fragments", "message geometry exceeds its profile or manifest fragment cap")
    bootstrap_chunk = limits["bootstrap_chunk_bytes"]
    require(0 < bootstrap_chunk < 120, "geometry", "$.limits.bootstrap_chunk_bytes",
            "bootstrap chunk must be positive and smaller than the 120-byte flight")
    bootstrap_fragments = (120 + bootstrap_chunk - 1) // bootstrap_chunk
    require(2 <= bootstrap_fragments <= limits["bootstrap_fragments"],
            "geometry", "$.limits.bootstrap_fragments", "bootstrap flight exceeds its independent fragment quota")

    nodes = identity["nodes"]
    ids = nodes + [relay["node"] for relay in value["relays"]]
    source_width = max(width(node) for node in ids)
    destination_width = max(width(node) for node in ids)
    namespace_width = width(identity["namespace"])
    service_width = width(2)
    routed_context = 0 if direct else (1 + source_width + destination_width) + (2 + namespace_width + 8)
    base_protected = 2 + 1 + 5 + 1 + 5 + 4
    # Reserve the contract's simultaneous application metadata envelope.
    app_extensions = (2 + 5) + (2 + 5) + (2 + service_width)
    if freshness["lease_ms"] > 0:
        app_extensions += 2 + 16
    frag_header = width(fragments - 1) + width(chunk_bytes) + width(message_bytes)
    app_header = base_protected + routed_context + app_extensions + frag_header
    max_application_frame = app_header + chunk_bytes + 16
    require(app_header <= 255, "mtu", "$.binding", "worst application HDR_LEN exceeds 255")
    require(max_application_frame <= min(binding["forward_mtu"], binding["return_mtu"]),
            "mtu", "$.binding", "worst protected application frame exceeds a path MTU")
    sample_frame = base_protected + routed_context + 17 + 16
    security_control_frame = base_protected + routed_context + (2 + width(0)) + 21 + 16
    reply_header = base_protected + routed_context + (2 + 5) + (2 + service_width)
    protected_status_frame = reply_header + 4 + 16
    ack_frame = reply_header + 16
    finish_ready_frame = base_protected + routed_context + 1
    require(max(sample_frame, security_control_frame, protected_status_frame, ack_frame,
                finish_ready_frame)
            <= min(binding["forward_mtu"], binding["return_mtu"]),
            "mtu", "$.binding", "SAMPLE, control, ACK, FINISH/READY, or protected status frame exceeds a path MTU")
    bootstrap_route = (1 + source_width + destination_width) if not direct else (2 + source_width)
    bootstrap_context = 2 + namespace_width + 8
    bootstrap_frag_header = (width(bootstrap_fragments - 1) + width(bootstrap_chunk)
                             + width(120))
    bootstrap_frame = (2 + 1 + 1 + bootstrap_context + bootstrap_route
                       + bootstrap_frag_header + 1 + bootstrap_chunk + 4)
    require(bootstrap_frame <= min(binding["forward_mtu"], binding["return_mtu"]),
            "mtu", "$.binding", "bootstrap fragment exceeds a path MTU")
    core_cap = max(binding["forward_mtu"], binding["return_mtu"])
    if binding["kind"] == "stream-r":
        envelope_n = core_cap + 4
        encoded_cap = envelope_n + envelope_n // 254 + 2
    else:
        encoded_cap = core_cap
    require(binding["encoded_mtu"] >= encoded_cap, "mtu", "$.binding.encoded_mtu",
            "encoded MTU does not hold the complete declared core-frame bound")

    # Pair scheduling and history lifetimes.
    longest = max(timing["forward_delay_ms"], timing["return_delay_ms"])
    traversal = binding["frame_tx_ms"] + longest
    require(binding["return_slot_width_ms"] >= 2 * traversal, "schedule",
            "$.binding.return_slot_width_ms", "return window cannot fit two reverse traversals")
    require(binding["return_slot_period_ms"] - binding["return_slot_width_ms"] >= traversal,
            "schedule", "$.binding.return_slot_period_ms", "source slot cannot fit a complete traversal")
    period, width_ms = binding["return_slot_period_ms"], binding["return_slot_width_ms"]
    require(binding["return_slot_period_ms"] + width_ms
            <= min(timing["feedback_delay_ms"], timing["receipt_delay_ms"]),
            "schedule", "$.binding.return_slot_period_ms", "reserved pair slots exceed feedback/receipt opportunity")
    require(timing["queue_ms"] >= period, "schedule", "$.timing.queue_ms",
            "queue bound must cover one source-slot alignment period")
    fwd, ret = timing["forward_delay_ms"], timing["return_delay_ms"]
    burst, horizon, margin, queue = (timing["burst_span_ms"], timing["send_horizon_ms"],
                                     timing["record_margin_ms"], timing["queue_ms"])
    if expected_recovery == "selective-32":
        response_min = max(2 * fwd + burst + timing["feedback_guard_ms"]
                           + timing["feedback_delay_ms"] + ret,
                           2 * ret + burst + timing["feedback_guard_ms"]
                           + timing["feedback_delay_ms"] + fwd,
                           fwd + timing["receipt_delay_ms"] + ret)
    else:
        response_min = fwd + timing["receipt_delay_ms"] + ret
    require(timing["response_timeout_ms"] >= response_min, "timing",
            "$.timing.response_timeout_ms", "response timeout is shorter than the admitted path envelope")
    require(burst >= max(fragments, bootstrap_fragments) * period, "schedule",
            "$.timing.burst_span_ms", "burst does not reserve all application/bootstrap fragment slots")
    starts = timing["burst_starts_ms"]
    require(len(starts) == timing["max_bursts"] and starts and starts[0] == 0,
            "schedule", "$.timing.burst_starts_ms", "source starts must begin at zero and match max_bursts")
    require(all(start % period == 0 for start in starts), "schedule",
            "$.timing.burst_starts_ms", "source starts must align to return-slot period boundaries")
    minimum_gap = burst + timing["response_timeout_ms"] + timing["jitter_ms"]
    require(all(later - earlier >= minimum_gap for earlier, later in zip(starts, starts[1:]))
            and starts[-1] + burst <= horizon,
            "schedule", "$.timing.burst_starts_ms", "source bursts overlap or exceed send_horizon")
    require(timing["max_probes"] <= timing["max_bursts"] - 1,
            "schedule", "$.timing.max_probes", "probes cannot exceed noninitial burst opportunities")
    if expected_recovery == "retry-all":
        require(timing["max_probes"] == 0 and timing["max_status"] == 0,
                "profile", "$.timing", "retry-all profiles do not configure selective probes/status")
    else:
        require(timing["max_status"] >= timing["max_bursts"],
                "schedule", "$.timing.max_status", "selective status quota must cover each burst opportunity")
    require(timing["receipt_limit"] >= timing["max_bursts"],
            "schedule", "$.timing.receipt_limit", "receipt quota must cover each admitted burst")
    require(timing["collect_ms"] >= horizon + longest
            and timing["assembly_ms"] >= max(horizon + longest, timing["collect_ms"]) + margin
            and timing["inactivity_ms"] == 0,
            "timing", "$.timing.assembly_ms", "collection/assembly lifetime or inactivity rule is infeasible")
    history_min = horizon + queue + fwd + ret + margin
    require(min(timing["dedup_ms"], timing["rejection_ms"], timing["tombstone_ms"])
            >= history_min and limits["assembly_tombstones_per_peer"] >= limits["assemblies_per_peer"],
            "timing", "$.timing", "identity history/tombstone lifetime or capacity is too small")
    max_processing = max(service["processing_ms"] for service in services)
    result_deadline_min = (queue + horizon + longest + max_processing
                           + queue + horizon + longest + timing["receipt_delay_ms"])
    require(timing["result_deadline_ms"] >= result_deadline_min
            and timing["result_cache_ms"] >= horizon + queue + fwd + ret + margin
            and timing["correlation_ms"] >= timing["result_deadline_ms"]
            + timing["late_result_ms"] + margin
            and timing["tombstone_ms"] >= timing["correlation_ms"],
            "timing", "$.timing", "request/result retention lifetimes are infeasible")
    require(security["association_ms"] >= timing["correlation_ms"] + queue,
            "security", "$.security.association_ms", "association lifetime does not cover correlation and queueing")
    sample = value["sample"]
    sample_duration = (sample["init_attempts"] * timing["result_deadline_ms"]
                       + max(0, sample["init_attempts"] - 1) * sample["init_retry_ms"])
    require(sample["init_deadline_ms"] >= sample_duration, "timing", "$.sample.init_deadline_ms",
            "SAMPLE initialization deadline cannot cover all request attempts")

    freshness_enabled = freshness["lease_ms"] > 0
    require((freshness["lease_ms"] <= 60000
             and freshness["grant_delivery_age_ms"] + queue + horizon + longest
             <= freshness["lease_ms"])
            if freshness_enabled else
            freshness["grant_delivery_age_ms"] == 0
            and freshness["grant_nodes"] == []
            and all(freshness[key] == 0 for key in (
                "tokens_per_association", "tokens_per_principal", "grant_requests_per_pair",
                "token_record_ms", "grant_result_ms")),
            "security", "$.freshness", "freshness lease is infeasible or disabled values are nonzero")
    if freshness_enabled:
        require(len(freshness["grant_nodes"]) == len(nodes)
                and set(freshness["grant_nodes"]) == set(nodes),
                "security", "$.freshness.grant_nodes",
                "freshness grants must include both endpoint IDs exactly once")
        require(0 < freshness["grant_requests_per_pair"]
                <= freshness["tokens_per_association"] <= freshness["tokens_per_principal"],
                "security", "$.freshness", "grant request/token quotas are inconsistent")
        require(freshness["token_record_ms"] >= freshness["lease_ms"]
                and freshness["grant_result_ms"] >= history_min,
                "timing", "$.freshness", "freshness token/result retention is too short")

    # Establishment has separate bounded retries, crypto work, ingress, and wire budgets.
    boot_slots = bootstrap_fragments * period
    flight_count = 2 if security["mode"] == "NNpsk0" else 3
    extra_xx = security["confirmation_attempts"] if security["mode"] == "XX" else 0
    flight_slot_count = (flight_count * security["flight_attempts"]
                         + security["duplicate_responses_per_attempt"])
    confirm_floor = 2 * (period + longest) + timing["receipt_delay_ms"]
    if security["mode"] == "XX":
        confirm_floor += boot_slots + longest
    require(security["flight_retry_ms"] >=
            2 * (boot_slots + longest) + security["crypto_per_attempt_ms"]
            + security["pairing_timeout_ms"]
            and security["flight_retry_ms"] % period == 0,
            "security", "$.security.flight_retry_ms", "bootstrap flight retry interval is infeasible")
    require(security["confirmation_timeout_ms"] >= confirm_floor
            and security["confirmation_timeout_ms"] % period == 0,
            "security", "$.security.confirmation_timeout_ms", "confirmation interval is infeasible")
    attempt_duration = (flight_slot_count * security["flight_retry_ms"]
                        + security["confirmation_attempts"] * security["confirmation_timeout_ms"]
                        + security["pairing_timeout_ms"] + security["crypto_per_attempt_ms"])
    require(security["attempt_ms"] >= attempt_duration, "security", "$.security.attempt_ms",
            "attempt deadline cannot cover reserved flights, confirmation, pairing, and crypto")
    frame_slots = ((flight_slot_count + extra_xx) * bootstrap_fragments
                   + 2 * security["confirmation_attempts"])
    required_attempt_bytes = frame_slots * binding["encoded_mtu"]
    response_count = flight_slot_count + extra_xx
    require(security["attempt_tx_bytes"] >= required_attempt_bytes
            and security["episode_tx_bytes"] >= security["attempt_tx_bytes"] * security["episode_attempts"],
            "security", "$.security.attempt_tx_bytes", "attempt/episode wire budget is too small")
    require(security["episode_crypto_ms"] >=
            security["crypto_per_attempt_ms"] * security["episode_attempts"]
            and security["episode_ms"] >=
            security["attempt_ms"] * security["episode_attempts"]
            + security["restart_backoff_ms"] * max(0, security["episode_attempts"] - 1)
            and security["global_crypto_ms_per_window"] >=
            security["episode_crypto_ms"] * security["later_episodes_per_window"],
            "security", "$.security", "episode or global establishment budget is too small")
    require(security["response_window_ms"] <= security["attempt_ms"]
            and security["responses_per_window"] >= response_count
            and security["response_bytes_per_window"] >=
            frame_slots * binding["encoded_mtu"]
            and security["ingress_packets_per_window"] >= frame_slots,
            "security", "$.security.response_window_ms", "response/ingress window cannot admit the attempt schedule")

    # Encoded airtime budget covers both directions, application controls, and bootstrap.
    transfer_frames = (2 * timing["max_bursts"]
                       * (fragments + timing["max_status"] + timing["receipt_limit"])
                       + frame_slots * security["episode_attempts"])
    require(transfer_frames * binding["frame_tx_ms"] <= timing["max_transfer_airtime_ms"],
            "schedule", "$.timing.max_transfer_airtime_ms", "transfer airtime cannot cover admitted traffic")

    # Transparent relay reservations include adjacency, cooldown, duplicate, expiry, and cache bounds.
    relay_path = value["relays"]
    if relay_path:
        establishment_duration = attempt_duration
        establishment_frames = frame_slots
        pair_service_concurrency = 2 * len(services)
        required_cache = (pair_service_concurrency * (fragments + bootstrap_fragments)
                          + timing["max_status"] + timing["receipt_limit"]
                          + establishment_frames * security["episode_attempts"])
        for direction in ("forward", "return"):
            ordered = relay_path if direction == "forward" else list(reversed(relay_path))
            require(all(relay[f"{direction}_arrival_min_ms"]
                        <= relay[f"{direction}_arrival_max_ms"] for relay in ordered),
                    "relay", "$.relays", f"{direction} arrival minimum exceeds maximum")
            for previous, following in zip(ordered, ordered[1:]):
                hop_end = (previous[f"{direction}_arrival_max_ms"]
                           + previous["duplicate_tail_ms"]
                           + (1 + previous["lower_duplicates"]) * previous["frame_tx_ms"])
                require(following[f"{direction}_arrival_min_ms"] >= hop_end,
                        "relay", "$.relays", f"{direction} hop interval overlaps prior relay forwarding")
            for relay in ordered:
                minimum = relay[f"{direction}_arrival_min_ms"]
                maximum = relay[f"{direction}_arrival_max_ms"]
                copy_tail = (relay["duplicate_tail_ms"]
                             + (1 + relay["lower_duplicates"]) * relay["frame_tx_ms"])
                cooldown = relay["cooldown_ms"]
                require(maximum + copy_tail <= timing[f"{direction}_delay_ms"],
                        "relay", "$.relays", f"{direction} relay forwarding exceeds endpoint delivery bound")
                require(all(later - earlier + minimum >=
                            burst + maximum + copy_tail + cooldown
                            for earlier, later in zip(starts, starts[1:])),
                        "relay", "$.relays", f"{direction} relay cooldown conflicts with source reservations")
                require(relay["max_forwards_per_key"] >=
                        timing["max_bursts"] * (1 + relay["lower_duplicates"]),
                        "relay", "$.relays.max_forwards_per_key",
                        "relay key limit cannot cover admitted bursts and lower duplicates")
                app_expiry = (horizon + maximum + copy_tail + margin)
                establishment_expiry = (establishment_duration + maximum + copy_tail + margin)
                require(relay["expiry_ms"] >= max(app_expiry, establishment_expiry),
                        "relay", "$.relays.expiry_ms", "relay expiry is shorter than the admitted transfer envelope")
                relay_traffic_ms = (transfer_frames * pair_service_concurrency
                                    * (1 + relay["lower_duplicates"]) * relay["frame_tx_ms"])
                require(relay["per_origin_airtime_ms"] >= relay_traffic_ms
                        and relay["global_airtime_ms"] >= relay_traffic_ms,
                        "relay", "$.relays", "relay airtime reservation is too small")
                retry_spacing = (boot_slots + maximum + copy_tail + cooldown)
                confirm_spacing = (period + maximum + copy_tail + cooldown)
                if security["mode"] == "XX":
                    confirm_spacing = retry_spacing
                require(security["flight_retry_ms"] >= retry_spacing
                        and security["confirmation_timeout_ms"] >= confirm_spacing,
                        "relay", "$.relays", "relay cooldown conflicts with bootstrap/confirmation retries")
        require(all(relay["max_forwards_per_key"] >=
                    max(timing["max_bursts"] * (1 + relay["lower_duplicates"]),
                        security["flight_attempts"]
                        + security["duplicate_responses_per_attempt"] + extra_xx,
                        security["confirmation_attempts"]) for relay in relay_path),
                "relay", "$.relays.max_forwards_per_key",
                "relay per-key cap cannot cover application and establishment identities")

    if tcp_profile:
        _check_tcp_topology(value, require)
    # Resource templates must be unique, finite, internally summed, and sized for their pools.
    resources = value["resources"]
    roles = [resource["role"] for resource in resources]
    require(roles.count("endpoint") == 1 and roles.count("relay") == (1 if relay_path else 0),
            "resources", "$.resources", "require exactly one endpoint template and one relay template iff routed")
    components = {
        "provider_retained", "provider_scratch", "association", "bootstrap", "sender",
        "assembly", "assembly_tombstone", "result", "history", "correlation", "control",
        "application_queue", "adapter", "stacks", "relay_cache", "freshness_tokens",
    }
    if multi_peer_profile:
        components |= {"endpoint_metadata", "peer_state", "identity_context",
                       "stream_decoder", "admission_owner"}
    for resource in resources:
        role = resource["role"]
        require(resource["flash_reserved_bytes"] <= resource["flash_limit_bytes"],
                "resources", "$.resources.flash_reserved_bytes", "flash reservation exceeds role limit")
        region_limits = {region["id"]: region["limit_bytes"] for region in resource["regions"]}
        require(len(region_limits) == len(resource["regions"]), "resources", "$.resources.regions",
                "RAM region identifiers must be unique")
        sums = {name: 0 for name in region_limits}
        by_component = {}
        for charge in resource["charges"]:
            component = charge["component"]
            require(component not in by_component, "resources", "$.resources.charges",
                    f"duplicate component charge {component}")
            require(charge["region"] in region_limits, "resources", "$.resources.charges",
                    "charge references an undeclared region")
            by_component[component] = charge
            sums[charge["region"]] += charge["count"] * charge["bytes_each"]
        require(set(by_component) == components, "resources", "$.resources.charges",
                "every resource component must appear exactly once")
        require(all(charge["count"] >= 1 and charge["bytes_each"] >= 1
                    for charge in by_component.values()),
                "resources", "$.resources.charges",
                "every component requires a nonzero design reserve")
        require(all(sums[region] <= limit for region, limit in region_limits.items()),
                "resources", "$.resources.charges", "component total exceeds a RAM region limit")
        charge = by_component
        if role == "endpoint":
            # The contract's simultaneous sender/result/history minima are enforced here.
            service_concurrency = (value["multi_peer"]["shared_endpoint"]["application_operations"]
                                   if multi_peer_profile else
                                   limits["peers"] * limits["operations_per_service"]
                                   * len(services))
            operation_slots = max(service_concurrency, limits["sender_slots"])
            grant_count = freshness["grant_requests_per_pair"] * limits["peers"]
            provider_slots = (security["pending_per_pair"] + security["active_per_pair"]
                              + security["draining_per_pair"]) * limits["peers"]
            require(charge["provider_retained"]["count"] >= provider_slots
                    and charge["provider_scratch"]["count"] >= security["crypto_slots"]
                    and charge["association"]["count"] >= provider_slots
                    and charge["bootstrap"]["count"] >= security["preauth_slots"],
                    "resources", "$.resources", "endpoint crypto/association/bootstrap reserves are too small")
            require(charge["sender"]["count"] >= operation_slots
                    and charge["result"]["count"] >= operation_slots + grant_count
                    and charge["correlation"]["count"] >= operation_slots + grant_count
                    and charge["history"]["count"] >= 2 * (operation_slots + grant_count),
                    "resources", "$.resources", "endpoint sender/result/correlation/history slots are insufficient")
            require(charge["assembly"]["count"] >= limits["peers"] * limits["assemblies_per_peer"]
                    and charge["assembly_tombstone"]["count"] >= limits["peers"]
                    * limits["assembly_tombstones_per_peer"]
                    and charge["control"]["count"] >= timing["feedback_buffers"] + grant_count + 1
                    and charge["application_queue"]["count"] >= limits["application_queue_slots"]
                    and charge["adapter"]["count"] >= limits["adapter_slots"]
                    and charge["freshness_tokens"]["count"] >= max(
                        1, limits["peers"] * freshness["tokens_per_principal"]),
                    "resources", "$.resources", "endpoint assembly, control, queue, adapter, or token pool is insufficient")
            if multi_peer_profile:
                require(charge["endpoint_metadata"]["count"] == 1
                        and charge["peer_state"]["count"] >= limits["peers"]
                        and charge["identity_context"]["count"] >= provider_slots
                        and charge["stream_decoder"]["count"] >= limits["peers"]
                        and charge["admission_owner"]["count"] == 1,
                        "resources", "$.resources.charges",
                        "multi-peer metadata, per-peer state/decoder, identity, or admission reserves are too small")
                metadata_minima = {
                    "endpoint_metadata": 4096,
                    "peer_state": 2048,
                    "identity_context": 64,
                    "stream_decoder": 512,
                    "admission_owner": 8192,
                }
                require(all(charge[name]["bytes_each"] >= minimum
                            for name, minimum in metadata_minima.items()),
                        "resources", "$.resources.charges",
                        "multi-peer metadata/state/decoder/admission buffers are undersized")
            require(charge["sender"]["bytes_each"] >= message_bytes
                    and charge["assembly"]["bytes_each"] >= message_bytes
                    and charge["result"]["bytes_each"] >= max(
                        message_bytes, opaque_service["result_bytes"], 21 if grant_count else 0)
                    and charge["application_queue"]["bytes_each"] >= message_bytes,
                    "resources", "$.resources", "endpoint message buffers are smaller than admitted payloads")
            require(charge["bootstrap"]["bytes_each"] >= 120
                    and charge["control"]["bytes_each"] >= binding["encoded_mtu"]
                    and charge["adapter"]["bytes_each"] >= binding["encoded_mtu"]
                    and (not freshness_enabled or charge["freshness_tokens"]["bytes_each"] >= 16),
                    "resources", "$.resources", "endpoint bootstrap/control/adapter/token buffers are too small")
        else:
            require(charge["control"]["bytes_each"] >= binding["encoded_mtu"]
                    and charge["adapter"]["bytes_each"] >= binding["encoded_mtu"]
                    and charge["relay_cache"]["count"] >= required_cache,
                    "resources", "$.resources", "relay frame/cache reserves are too small")
            require(all(charge[name]["count"] >= 1 and charge[name]["bytes_each"] >= 1
                        for name in components - {"control", "adapter", "relay_cache"}),
                    "resources", "$.resources", "relay role requires minimal endpoint-only design reserves")


def _check_tcp_topology(value: dict[str, Any], require) -> None:
    """Validate TCP placement and the mixed transparent bridge independently."""
    profile = value["profile"]["id"]
    nodes = value["identity"]["nodes"]
    relays = [entry["node"] for entry in value["relays"]]
    binding = value["binding"]
    timing = value["timing"]
    tcp = value["tcp_binding"]

    require((tcp["forward_mtu"], tcp["return_mtu"], tcp["encoded_mtu"]) == (256, 256, 263),
            "tcp-binding", "$.tcp_binding", "TCP Stream R capacity must be 256 core / 263 encoded bytes")
    require(tcp["bind_address"] == "127.0.0.1" and tcp["port_assignment"] == "ephemeral",
            "tcp-binding", "$.tcp_binding", "TCP listener must use loopback and an ephemeral port")
    expected_timeout = (binding["frame_tx_ms"]
                        + max(timing["forward_delay_ms"], timing["return_delay_ms"])
                        + timing["record_margin_ms"])
    require(tcp["partial_candidate_timeout_ms"] == expected_timeout,
            "tcp-binding", "$.tcp_binding.partial_candidate_timeout_ms",
            "candidate timeout must equal frame transmit + longest path delay + record margin")

    if profile == "PEER-TCP-STREAM-R":
        require(tcp["placement"] == "peer-pair"
                and tcp["connector_node"] in nodes and tcp["listener_node"] in nodes
                and tcp["connector_node"] != tcp["listener_node"],
                "tcp-binding", "$.tcp_binding", "direct TCP roles must be opposite endpoint nodes")
        require(binding["tx_ownership"] == "copy"
                and binding["synchronous_completion"] is False,
                "tcp-binding", "$.binding", "direct TCP requires copy ownership and asynchronous completion")
        require((binding["forward_mtu"], binding["return_mtu"], binding["encoded_mtu"])
                == (tcp["forward_mtu"], tcp["return_mtu"], tcp["encoded_mtu"]),
                "tcp-binding", "$.binding", "direct binding capacities must match TCP Stream R")
        require("mixed_path" not in value, "profile", "$.mixed_path",
                "direct peer profile must not carry mixed-path metadata")
    else:
        mixed = value.get("mixed_path")
        require(mixed is not None, "mixed-path", "$.mixed_path",
                "mixed profile requires its forwarding topology")
        if mixed is None:
            return
        endpoints = set(nodes)
        require(tcp["placement"] == "endpoint-to-relay"
                and mixed["stream_endpoint"] in endpoints
                and mixed["packet_endpoint"] in endpoints
                and mixed["stream_endpoint"] != mixed["packet_endpoint"],
                "tcp-binding", "$.tcp_binding", "mixed TCP connector and packet endpoint must be distinct endpoints")
        require(mixed["bridge_node"] in relays and bool(relays)
                and mixed["bridge_node"] == relays[0]
                and tcp["connector_node"] == mixed["stream_endpoint"]
                and tcp["listener_node"] == mixed["bridge_node"],
                "tcp-binding", "$.tcp_binding", "TCP must connect the stream endpoint to the first relay bridge")
        require(mixed["forward_relays"] == relays
                and mixed["return_relays"] == list(reversed(relays)),
                "mixed-path", "$.mixed_path", "mixed relay order must match the route and reverse exactly")
        require(mixed["context_policy"] == "origin-supplied-require-exact"
                and binding["context"] == "origin-explicit",
                "mixed-path", "$.mixed_path.context_policy",
                "both path directions require exact origin-supplied CONTEXT")
        require(mixed["recovery"] == "selective-32"
                and all(service["recovery"] == "selective-32" for service in value["services"]),
                "mixed-path", "$.mixed_path.recovery", "mixed path requires selective-32 for both services")
        require((binding["forward_mtu"], binding["return_mtu"])
                == (tcp["forward_mtu"], tcp["return_mtu"]),
                "tcp-binding", "$.binding", "mixed path core MTU must fit both TCP directions")

    tcp_role = "endpoint" if profile == "PEER-TCP-STREAM-R" else "relay"
    for resource in value["resources"]:
        if resource["role"] != tcp_role:
            continue
        adapter = next((charge for charge in resource["charges"]
                        if charge["component"] == "adapter"), None)
        require(adapter is not None and adapter["bytes_each"] >= tcp["encoded_mtu"],
                "resources", "$.resources",
                f"{tcp_role} adapter slot must hold a complete TCP envelope")


def _check_multi_peer_profile(value: dict[str, Any], require) -> None:
    """Validate the four-peer shared-endpoint profile independently of its schema."""
    identity = value["identity"]
    binding = value["binding"]
    limits = value["limits"]
    security = value["security"]
    multi = value["multi_peer"]
    peers = multi["peer_nodes"]
    endpoint = multi["endpoint_node"]
    peer_count = 4

    require(len(peers) == peer_count and len(set(peers)) == peer_count
            and endpoint not in peers,
            "identity", "$.multi_peer.peer_nodes", "four peer IDs must be unique and distinct from the endpoint")
    require(len(identity["nodes"]) == peer_count + 1
            and len(set(identity["nodes"])) == peer_count + 1
            and set(identity["nodes"]) == {endpoint, *peers}
            and identity["sample_producer"] == endpoint,
            "identity", "$.identity.nodes", "identity nodes must be exactly the endpoint and four distinct peers")
    require(multi["peer_isolation"] == "peer-handle-and-bound-association-generation"
            and multi["response_routing"] == "reply-via-origin-peer-handle"
            and multi["transport_lifetime"] == "pinned-until-each-peers-terminal-callbacks-settle",
            "profile", "$.multi_peer", "multi-peer isolation, routing, or transport lifetime is noncanonical")
    require(multi["per_peer"] == {
                "pending_attempts": security["pending_per_pair"],
                "active_associations": security["active_per_pair"],
                "draining_associations": security["draining_per_pair"],
            }
            and all(value == 1 for value in multi["per_peer"].values()),
            "security", "$.multi_peer.per_peer", "per-peer quotas must match the one-slot security ceilings")
    shared = multi["shared_endpoint"]
    expected_shared = {
        "pending_attempts": security["pending_per_pair"] * peer_count,
        "active_associations": security["active_per_pair"] * peer_count,
        "draining_associations": security["draining_per_pair"] * peer_count,
        "sender_slots": limits["sender_slots"],
        "services": len(value["services"]),
        "application_operations": peer_count,
    }
    require(limits["peers"] == peer_count
            and shared == expected_shared
            and expected_shared == {
                "pending_attempts": 4,
                "active_associations": 4,
                "draining_associations": 4,
                "sender_slots": 4,
                "services": 2,
                "application_operations": 4,
            },
            "quota", "$.multi_peer.shared_endpoint", "shared endpoint quotas must be the derived four-peer totals")
    require(limits["peers"] == peer_count
            and limits["message_bytes"] == 4096
            and limits["chunk_bytes"] == 128
            and limits["fragments"] == 32
            and binding["forward_mtu"] == binding["return_mtu"] == 256
            and binding["encoded_mtu"] == 263
            and binding["return_slot_period_ms"] == 1000
            and binding["return_slot_width_ms"] == 250
            and security["crypto_slots"] == 2,
            "profile", "$.limits", "multi-peer message geometry, Stream R capacity, schedule, or crypto slots changed")

    serial = {
        "name": "four_serial", "peers": 4, "services": 2,
        "active_associations": 4, "draining_associations": 4,
        "pending_attempts": 4, "crypto_slots": 1,
        "application_operations": 4, "mtu_bytes": 256,
        "max_message_bytes": 4096, "return_period_ms": 1000,
        "return_window_ms": 250,
    }
    parallel = {**serial, "name": "four_parallel", "crypto_slots": 2}
    require(multi["sensitivity_rows"] == [serial, parallel],
            "quota", "$.multi_peer.sensitivity_rows",
            "sensitivity rows must exactly match the four_serial and four_parallel contracts")

def load_manifest(name: str, root: str | Path | None = None) -> Manifest:
    if name not in _FROZEN:
        raise ManifestError("profile", "$", "manifest is not in the frozen P20 input set")
    base = Path(root) if root is not None else _SCHEMA_PATH.parents[3] / "profiles" / "deployments"
    try:
        raw = (base / name).read_bytes()
    except OSError as exc:
        raise ManifestError("encoding", "$", f"cannot read manifest {name}") from exc
    return parse_manifest(raw, _FROZEN[name])


def identify_frozen_manifest(raw: bytes) -> Manifest:
    digest = hashlib.sha256(raw).hexdigest()
    for name, expected in _FROZEN.items():
        if digest == expected:
            return parse_manifest(raw, expected)
    raise ManifestError("digest", "$", "bytes do not match a frozen P20 manifest")
