#!/usr/bin/env python3
"""Offline DMP test-manifest gate. See docs/DMP_Test_Manifest_Contract.md.

No endpoint or protocol state machine lives here. Runtime startup must enforce
the same published contract using the shared corpus, not trust this tool's exit.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 262144
MAX_DEPTH = 24
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "profiles/schema/manifest-v2.schema.json"


class ProfileError(ValueError):
    def __init__(self, code, path, message):
        super().__init__(message)
        self.code, self.path, self.message = code, path, message


def require(condition, code, path, message):
    if not condition:
        raise ProfileError(code, path, message)


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "json", "$", "duplicate member: " + key)
        result[key] = value
    return result


def _integer(value):
    require(len(value.lstrip("-")) <= 20, "json", "$", "integer exceeds 20 digits")
    return int(value)


def _noninteger(_value):
    raise ProfileError("json", "$", "only JSON integer numbers are allowed")


def _check_text(text):
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            require(depth <= MAX_DEPTH, "json", "$", "nesting exceeds 24 containers")
        elif char in "]}":
            depth -= 1


def _check_surrogates(value):
    if isinstance(value, str):
        require(not any(0xD800 <= ord(c) <= 0xDFFF for c in value),
                "encoding", "$", "unpaired Unicode surrogate")
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_surrogates(key)
            _check_surrogates(item)
    elif isinstance(value, list):
        for item in value:
            _check_surrogates(item)


def _schema(value, spec, path="$"):
    """Evaluate exactly the keyword subset used by our checked-in schema.

    Unknown schema keywords are a developer error, never silently ignored. The
    exported schema is standard JSON Schema, independently consumable by peers.
    """
    supported = {"$schema", "$id", "type", "enum", "minimum", "maximum",
                 "minLength", "maxLength", "pattern", "additionalProperties",
                 "required", "properties", "minItems", "maxItems", "items"}
    if set(spec) - supported:
        raise RuntimeError("unsupported schema keyword")
    if "enum" in spec:
        require(any(type(value) is type(candidate) and value == candidate
                    for candidate in spec["enum"]), "schema", path, "not a permitted value")
    kind = spec.get("type")
    if kind:
        types = {"object": dict, "array": list, "integer": int, "string": str, "boolean": bool}
        require(type(value) is types[kind], "schema", path, "expected " + kind)
    if kind == "object":
        require(spec.get("additionalProperties") is False, "schema", path, "schema is not closed")
        missing = set(spec["required"]) - set(value)
        unknown = set(value) - set(spec["properties"])
        require(not missing, "schema", path, "missing fields: " + ",".join(sorted(missing)))
        require(not unknown, "schema", path, "unknown fields: " + ",".join(sorted(unknown)))
        for key, item in value.items():
            _schema(item, spec["properties"][key], path + "." + key)
    elif kind == "array":
        require(spec["minItems"] <= len(value) <= spec["maxItems"], "schema", path, "array size outside bounds")
        for index, item in enumerate(value):
            _schema(item, spec["items"], f"{path}[{index}]")
    elif kind == "integer":
        require(spec["minimum"] <= value <= spec["maximum"], "schema", path, "integer outside bounds")
    elif kind == "string":
        require(spec["minLength"] <= len(value) <= spec["maxLength"], "schema", path, "string length outside bounds")
        require(re.fullmatch(spec["pattern"], value) is not None, "schema", path, "invalid identifier")


def width(value):
    return max(1, (value.bit_length() + 6) // 7)


def _identity_and_services(m):
    p, b, ident, services = m["profile"], m["binding"], m["identity"], m["services"]
    direct = p["id"] == "DIRECT-1"
    selective = p["id"] == "RADIO-1"
    test = p["id"] == "TEST-RADIO-RETRY-ALL"
    require(p["owner"] == ("DMP-test" if test else "DMP-reference") and
            p["revision"] == (1 if test else 4), "profile", "$.profile", "family owner/revision mismatch")
    expected = (("DMP-test/SIM-STREAM-R", "stream-r", "point-to-point", "association") if direct else
                ("DMP-test/SIM-PACKET", "packet", "static-unicast", "origin-explicit"))
    require(tuple(b[k] for k in ("id", "kind", "topology", "context")) == expected,
            "profile", "$.binding", "binding is incompatible with selected family")
    require((not direct or (not m["relays"] and b["ttl"] == 0)) and b["ttl"] >= len(m["relays"]),
            "profile", "$.binding.ttl", "route/TTL does not cover the selected path")
    nodes = ident["nodes"]
    all_nodes = nodes + [relay["node"] for relay in m["relays"]]
    require(len(set(all_nodes)) == len(all_nodes) and ident["sample_producer"] in nodes,
            "identity", "$.identity", "node identities must be unique and producer must be an endpoint")
    require({s["id"] for s in services} == {1, 2}, "service", "$.services", "require services 1 and 2 exactly once")
    for index, service in enumerate(services):
        path = f"$.services[{index}]"
        sid = service["id"]
        require(service["reply_service"] == sid and service["service_encoding"] ==
                ("omitted" if sid == ident["default_service"] else "explicit"),
                "service", path, "noncanonical default or asymmetric reply service")
        require(service["recovery"] == ("selective-32" if selective else "retry-all"),
                "profile", path + ".recovery", "recovery cannot change within the selected profile")
        require(service["schema"] == ("DMP-reference/SAMPLE-1/2" if sid == 1 else "DMP-test/OPAQUE-1/1"),
                "service", path, "service/schema mismatch")
        require({a["node"] for a in service["acl"]} == set(nodes), "service", path + ".acl", "ACL must cover both nodes once")
        for acl in service["acl"]:
            expected_actions = ({"produce", "result"} if acl["node"] == ident["sample_producer"] else {"read", "status"}) if sid == 1 else {"data", "result"}
            require(set(acl["actions"]) == expected_actions and len(acl["actions"]) == len(expected_actions),
                    "service", path + ".acl", "unsupported or duplicate ACL action")
        require(max(service["request_bytes"], service["result_bytes"]) <= m["limits"]["message_bytes"],
                "service", path, "service payload exceeds logical message capacity")
        if sid == 1:
            require(service["request_bytes"] == 1 and service["result_bytes"] == 17 and not service["freshness"],
                    "service", path, "SAMPLE-1 contract cannot be changed")
    return direct, selective


def _security(m):
    s, t = m["security"], m["timing"]
    require(s["credential"] == ("provisioned-pairwise-psk" if s["mode"] == "NNpsk0" else "authenticated-oob-xx"),
            "security", "$.security.credential", "credential/mode mismatch")
    require(s["crypto_slots"] <= s["pending_per_pair"] <= s["preauth_slots"],
            "security", "$.security", "crypto/pending/preauth admission mismatch")
    require(s["preauth_bytes"] >= 120 * s["preauth_slots"], "security", "$.security.preauth_bytes", "whole bootstrap flights must be reserved")
    require(s["drain_ms"] < s["association_ms"] and (s["draining_per_pair"] > 0 or s["drain_ms"] == 0),
            "security", "$.security.drain_ms", "draining exceeds association policy")
    require(s["association_ms"] >= t["correlation_ms"] + t["queue_ms"],
            "security", "$.security.association_ms", "association cannot cover admitted exchange")
    require(s["pairing_timeout_ms"] <= s["attempt_ms"] and s["crypto_per_attempt_ms"] <= s["attempt_ms"],
            "security", "$.security.attempt_ms", "attempt does not cover pairing/crypto budget")
    attempts = s["episode_attempts"]
    require(s["episode_ms"] >= attempts * s["attempt_ms"] + (attempts - 1) * s["restart_backoff_ms"],
            "security", "$.security.episode_ms", "episode does not cover attempts and backoff")
    require(s["episode_crypto_ms"] >= attempts * s["crypto_per_attempt_ms"] and
            s["episode_crypto_ms"] <= s["episode_ms"] * s["crypto_slots"],
            "security", "$.security.episode_crypto_ms", "episode crypto budget contradicts admitted work")
    require(s["episode_tx_bytes"] >= attempts * s["attempt_tx_bytes"],
            "security", "$.security.episode_tx_bytes", "episode traffic budget too small")
    require(s["later_window_ms"] >= s["episode_ms"] and
            s["global_crypto_ms_per_window"] >= s["later_episodes_per_window"] * s["episode_crypto_ms"] and
            s["global_crypto_ms_per_window"] <= s["later_window_ms"] * s["crypto_slots"],
            "security", "$.security", "later-episode global work window inconsistent")


def _frames(m, direct):
    l, b, ident = m["limits"], m["binding"], m["identity"]
    size, chunk = l["message_bytes"], l["chunk_bytes"]
    require(chunk < size, "geometry", "$.limits.chunk_bytes", "fragment chunk must be smaller than logical maximum")
    count = (size + chunk - 1) // chunk
    boot_chunk = l["bootstrap_chunk_bytes"]
    boot_count = (120 + boot_chunk - 1) // boot_chunk
    require(count <= l["fragments"] <= (16 if direct else 32), "geometry", "$.limits.fragments", "fragment geometry exceeds family capacity")
    require(boot_count <= l["bootstrap_fragments"], "geometry", "$.limits.bootstrap_fragments", "bootstrap requires its own sufficient fragment quota")
    node_width = max(width(n) for n in ident["nodes"])
    context = 2 + width(ident["namespace"]) + 8
    route = 1 + sum(width(n) for n in ident["nodes"])
    base = 18 + (0 if direct else route + context)
    app_frames, app_headers, status_frames = [], [], []
    frag = width(count - 1) + width(chunk) + width(size)
    for service in m["services"]:
        service_ext = 0 if service["id"] == ident["default_service"] else 2 + width(service["id"])
        header = base + 7 + 7 + service_ext + (18 if service["freshness"] else 0) + frag
        app_headers.append(header)
        app_frames.append(header + chunk + 16)
        status_frames.append(base + 7 + service_ext + 4 + 16)
    # Service 0 grant/result requires REPLY_TO + explicit SERVICE_ID + 21 bytes.
    control = base + 7 + 3 + 21 + 16
    sample = base + 7 + 7 + 17 + 16
    # VT, HDR_LEN, OPTIONS, SEQ=FLIGHT, INTEGRITY_DESC=CRC32C.
    boot_header = 5 + context + (2 + node_width if direct else route)
    boot_header += width(boot_count - 1) + width(boot_chunk) + width(120)
    boot_frame = boot_header + boot_chunk + 4
    frame = max(*app_frames, *status_frames, control, sample, boot_frame)
    require(max(*app_headers, boot_header, base + 10) <= 255 and frame <= min(b["forward_mtu"], b["return_mtu"]),
            "mtu", "$.binding", "worst PN/header/index/application/bootstrap/control frame exceeds path MTU")
    core = max(b["forward_mtu"], b["return_mtu"])
    encoded = core + 4 + (core + 4) // 254 + 2 if direct else core
    require(encoded <= b["encoded_mtu"], "mtu", "$.binding.encoded_mtu", "binding encoding exceeds frame capacity")
    return {"fragment_count": count, "bootstrap_fragment_count": boot_count,
            "app_frame_bytes": max(app_frames), "status_frame_bytes": max(status_frames),
            "bootstrap_frame_bytes": boot_frame, "encoded_frame_bytes": encoded}


def _timing(m, selective, derived):
    t, b, s = m["timing"], m["binding"], m["security"]
    f, r, span, margin = (t[k] for k in ("forward_delay_ms", "return_delay_ms", "burst_span_ms", "record_margin_ms"))
    horizon, queue, delay = t["send_horizon_ms"], t["queue_ms"], max(f, r)
    floor = f + t["receipt_delay_ms"] + r
    if selective:
        floor = max(floor, 2*f + span + t["feedback_guard_ms"] + t["feedback_delay_ms"] + r,
                    2*r + span + t["feedback_guard_ms"] + t["feedback_delay_ms"] + f)
    require(t["response_timeout_ms"] >= floor, "timing", "$.timing.response_timeout_ms", "timeout is earlier than admitted feedback/receipt")
    bursts, starts = t["max_bursts"], t["burst_starts_ms"]
    require(len(starts) == bursts and starts[0] == 0, "schedule", "$.timing.burst_starts_ms", "one reservation per burst, beginning at zero")
    require(all(right >= left + span + t["response_timeout_ms"] + t["jitter_ms"] for left, right in zip(starts, starts[1:])),
            "schedule", "$.timing.burst_starts_ms", "source burst reservations overlap admitted wait/jitter")
    require(starts[-1] + span <= horizon, "schedule", "$.timing.send_horizon_ms", "final burst exceeds absolute horizon")
    require(t["max_probes"] <= bursts - 1 and
            ((t["max_probes"] >= 1 and t["max_status"] >= bursts) if selective else (t["max_probes"] == t["max_status"] == 0)),
            "schedule", "$.timing", "probe/status caps incompatible with recovery envelope")
    period, window = b["return_slot_period_ms"], b["return_slot_width_ms"]
    traversal = b["frame_tx_ms"] + delay
    require(window >= 2*traversal and period - window >= traversal and
            b["return_slot_period_ms"] + b["return_slot_width_ms"] <= min(t["receipt_delay_ms"], t["feedback_delay_ms"]),
            "schedule", "$.binding", "superframe must fit one complete data path and two reverse control paths")
    require(span >= max(derived["fragment_count"], derived["bootstrap_fragment_count"]) * period and
            all(start % period == 0 for start in starts) and queue >= period,
            "schedule", "$.timing", "serialized path reservations do not fit burst/queue/phase bounds")
    require(t["receipt_limit"] >= bursts and m["limits"]["control_slots"] >= t["feedback_buffers"] + 1,
            "schedule", "$.timing", "control reservation cannot cover receipts independently")
    # Reserve application and maximum bootstrap schedules together; no airtime
    # inference from payload bytes or optimistic selective masks.
    frames = bursts * (derived["fragment_count"] + derived["bootstrap_fragment_count"]) + t["max_status"] + t["receipt_limit"]
    require(t["max_transfer_airtime_ms"] >= frames * b["frame_tx_ms"],
            "schedule", "$.timing.max_transfer_airtime_ms", "transfer airtime reserve is insufficient")
    require(t["collect_ms"] >= horizon + delay and t["assembly_ms"] >= max(horizon + delay, t["collect_ms"]) + margin,
            "timing", "$.timing.assembly_ms", "absolute assembly lifetime cannot cover collection and margin")
    history = horizon + queue + f + r + margin
    for key in ("dedup_ms", "rejection_ms", "result_cache_ms", "tombstone_ms"):
        require(t[key] >= history, "timing", "$.timing." + key, "history expires inside the admitted retry/delay envelope")
    result = 2*(queue + horizon + delay) + max(x["processing_ms"] for x in m["services"]) + t["receipt_delay_ms"]
    require(t["result_deadline_ms"] >= result and t["correlation_ms"] >= t["result_deadline_ms"] + t["late_result_ms"] + margin and
            t["tombstone_ms"] >= t["correlation_ms"], "timing", "$.timing", "result/correlation/terminal tombstone lifetime insufficient")
    sample = m["sample"]
    require(sample["init_deadline_ms"] >= sample["init_attempts"]*t["result_deadline_ms"] + (sample["init_attempts"]-1)*sample["init_retry_ms"],
            "timing", "$.sample.init_deadline_ms", "sample initialization deadline cannot cover configured attempts")
    fresh = m["freshness"]
    need = fresh["grant_delivery_age_ms"] + queue + horizon + delay
    if any(x["freshness"] for x in m["services"]):
        require(0 < fresh["lease_ms"] and need <= fresh["lease_ms"], "timing", "$.freshness", "freshness expires before final new-command admission")
        require(set(fresh["grant_nodes"]) == set(m["identity"]["nodes"]) and len(fresh["grant_nodes"]) == 2 and
                0 < fresh["grant_requests_per_pair"] <= fresh["tokens_per_association"] <= fresh["tokens_per_principal"] and
                fresh["token_record_ms"] >= fresh["lease_ms"] and fresh["grant_result_ms"] >= history,
                "security", "$.freshness", "grant authorization, token admission or control-result retention missing")
    else:
        require(all(value == 0 for key, value in fresh.items() if key not in ("grant_nodes", "grant_acl")) and not fresh["grant_nodes"],
                "timing", "$.freshness", "unused freshness must be explicitly disabled")
    derived.update(response_floor_ms=floor, freshness_required_ms=need, transfer_frame_reserve=frames)


def _establishment(m, derived):
    s, b, t = m["security"], m["binding"], m["timing"]
    period, delay = b["return_slot_period_ms"], max(t["forward_delay_ms"], t["return_delay_ms"])
    flight_span = derived["bootstrap_fragment_count"] * period
    retry_floor = 2*(flight_span + delay) + s["crypto_per_attempt_ms"] + s["pairing_timeout_ms"]
    require(s["flight_retry_ms"] >= retry_floor and s["flight_retry_ms"] % period == 0,
            "security", "$.security.flight_retry_ms", "cached-flight retry cannot cover serialized peer flight/verification")
    # XX must keep retransmitting cached flight 3 while waiting for READY.
    # Reserve one complete flight-3 copy even in the initial confirmation slot.
    xx_confirmation_flights = s["confirmation_attempts"] if s["mode"] == "XX" else 0
    confirmation_floor = 2*(period + delay) + t["receipt_delay_ms"]
    if xx_confirmation_flights:
        confirmation_floor += flight_span + delay
    require(s["confirmation_timeout_ms"] >= confirmation_floor and s["confirmation_timeout_ms"] % period == 0,
            "security", "$.security.confirmation_timeout_ms", "confirmation retry cannot cover FINISH/READY path")
    flights = 2 if s["mode"] == "NNpsk0" else 3
    responses = flights*s["flight_attempts"] + s["duplicate_responses_per_attempt"] + xx_confirmation_flights + 2*s["confirmation_attempts"]
    frames = (flights*s["flight_attempts"] + s["duplicate_responses_per_attempt"] + xx_confirmation_flights) * derived["bootstrap_fragment_count"] + 2*s["confirmation_attempts"]
    traffic = frames*derived["encoded_frame_bytes"]
    # All allowed duplicate responses consume their own serialized full-flight
    # reservation. Budgets include both origins, deliberately conservative.
    duration = (flights*s["flight_attempts"] + s["duplicate_responses_per_attempt"]) * s["flight_retry_ms"]
    duration += s["confirmation_attempts"]*s["confirmation_timeout_ms"] + s["pairing_timeout_ms"] + s["crypto_per_attempt_ms"]
    require(s["attempt_ms"] >= duration and s["attempt_tx_bytes"] >= traffic,
            "security", "$.security", "attempt deadline/wire traffic cannot cover bootstrap and confirmation schedule")
    require(s["response_window_ms"] <= s["attempt_ms"] and s["responses_per_window"] >= responses and
            s["response_bytes_per_window"] >= traffic,
            "security", "$.security", "duplicate-response rate/byte window cannot admit selected schedule")
    require(s["ingress_packets_per_window"] >= frames,
            "security", "$.security.ingress_packets_per_window", "ingress budget cannot admit a complete selected attempt")
    require(s["encryption_limit"] >= derived["transfer_frame_reserve"] + 2*s["confirmation_attempts"] and
            s["plaintext_limit"] >= derived["transfer_frame_reserve"]*m["limits"]["message_bytes"],
            "security", "$.security", "association encryption/plaintext limits cannot admit the transfer envelope")
    derived.update(establishment_frame_reserve=frames, establishment_wire_bytes=traffic,
                   establishment_ms=duration, bootstrap_flight_span_ms=flight_span)


def _relays(m, derived):
    t, relays = m["timing"], m["relays"]
    starts, span = t["burst_starts_ms"], t["burst_span_ms"]
    for direction, ordered in (("forward", relays), ("return", list(reversed(relays)))):
        preceding_end = 0
        for relay in ordered:
            path = f"$.relays[node={relay['node']}]"
            low, high = relay[direction + "_arrival_min_ms"], relay[direction + "_arrival_max_ms"]
            require(preceding_end <= low <= high, "relay", path, "inconsistent per-hop arrival intervals")
            copies = 1 + relay["lower_duplicates"]
            # Wait through the entire arrival/duplicate interval, then reserve
            # serial transmission of every admitted copy, not just one frame.
            preceding_end = high + relay["duplicate_tail_ms"] + copies*relay["frame_tx_ms"]
            require(preceding_end <= t[direction + "_delay_ms"], "relay", path, "relay schedule exceeds endpoint delivery bound")
            require(all(nxt + low >= prev + span + high + relay["duplicate_tail_ms"] + copies*relay["frame_tx_ms"] + relay["cooldown_ms"]
                        for prev, nxt in zip(starts, starts[1:])),
                    "relay", path, "arrival/duplicate tail can consume the next cooldown opportunity")
            boot_opportunities = m["security"]["flight_attempts"] + m["security"]["duplicate_responses_per_attempt"]
            confirmation_span = m["binding"]["return_slot_period_ms"]
            if m["security"]["mode"] == "XX":
                boot_opportunities += m["security"]["confirmation_attempts"]
                confirmation_span = derived["bootstrap_flight_span_ms"]
            require(relay["max_forwards_per_key"] >= max(t["max_bursts"], boot_opportunities, m["security"]["confirmation_attempts"]) * copies,
                    "relay", path, "duplicate forwarding can exhaust per-key count")
            require(relay["expiry_ms"] >= starts[-1] + span + high - low + relay["duplicate_tail_ms"] + copies*relay["frame_tx_ms"] + t["record_margin_ms"],
                    "relay", path, "relay record expires before the final reserved opportunity")
            require(m["security"]["flight_retry_ms"] + low >= derived["bootstrap_flight_span_ms"] + high + relay["duplicate_tail_ms"] + copies*relay["frame_tx_ms"] + relay["cooldown_ms"] and
                    m["security"]["confirmation_timeout_ms"] + low >= confirmation_span + high + relay["duplicate_tail_ms"] + copies*relay["frame_tx_ms"] + relay["cooldown_ms"] and
                    relay["expiry_ms"] >= derived["establishment_ms"] + high - low + relay["duplicate_tail_ms"] + copies*relay["frame_tx_ms"] + t["record_margin_ms"],
                    "relay", path, "bootstrap duplicate/retry schedule exceeds relay cooldown or expiry")
            airtime = (2 * len(m["services"]) * derived["transfer_frame_reserve"] + derived["establishment_frame_reserve"]*m["security"]["episode_attempts"])*copies*relay["frame_tx_ms"]
            require(relay["per_origin_airtime_ms"] >= airtime and relay["global_airtime_ms"] >= 2*airtime,
                    "relay", path, "relay airtime does not cover both origins and admitted service concurrency")


def _resources(m, derived):
    s, l = m["security"], m["limits"]
    roles = {r["role"] for r in m["resources"]}
    expected = {"endpoint", "relay"} if m["relays"] else {"endpoint"}
    require(roles == expected and len(roles) == len(m["resources"]), "resources", "$.resources", "resource roles missing or duplicated")
    associations = s["pending_per_pair"] + s["active_per_pair"] + s["draining_per_pair"]
    operations = 2 * len(m["services"])
    fresh = m["freshness"]
    grants = fresh["grant_requests_per_pair"]
    require(l["assembly_tombstones_per_peer"] >= l["assemblies_per_peer"],
            "resources", "$.limits.assembly_tombstones_per_peer",
            "each active assembly must reserve its future expiry tombstone")
    minimum_counts = {"provider_retained": associations, "provider_scratch": s["crypto_slots"],
                      "association": associations, "bootstrap": s["preauth_slots"],
                      "sender": operations, "assembly": l["assemblies_per_peer"],
                      "assembly_tombstone": l["peers"] * l["assembly_tombstones_per_peer"],
                      "result": operations + grants, "history": 2*(operations + grants), "correlation": operations + grants,
                      "control": l["control_slots"], "application_queue": l["application_queue_slots"],
                      "adapter": l["adapter_slots"], "stacks": 1, "relay_cache": 1,
                      "freshness_tokens": max(1, fresh["tokens_per_principal"])}
    minimum_bytes = {key: l["message_bytes"] for key in ("sender", "assembly", "result", "application_queue")}
    minimum_bytes["assembly"] += 512
    minimum_bytes["assembly_tombstone"] = 48
    minimum_bytes.update(bootstrap=120, control=derived["encoded_frame_bytes"], adapter=derived["encoded_frame_bytes"])
    minimum_bytes["result"] = max(l["message_bytes"], 21 if grants else 1)
    minimum_bytes["freshness_tokens"] = 16 if grants else 1
    require(l["control_slots"] >= m["timing"]["feedback_buffers"] + grants + 1,
            "resources", "$.limits.control_slots", "grant requests cannot consume receipt/feedback reservation")
    totals = {}
    for resource in m["resources"]:
        path = "$.resources[" + resource["role"] + "]"
        require(resource["flash_reserved_bytes"] <= resource["flash_limit_bytes"], "resources", path, "linked flash reservation exceeds limit")
        regions = {r["id"]: r["limit_bytes"] for r in resource["regions"]}
        require(len(regions) == len(resource["regions"]), "resources", path, "duplicate memory region")
        charges = {c["component"]: c for c in resource["charges"]}
        require(set(charges) == set(minimum_counts) and len(charges) == len(resource["charges"]),
                "resources", path, "each required component must be charged exactly once")
        used = dict.fromkeys(regions, 0)
        for key, charge in charges.items():
            require(charge["region"] in regions, "resources", path, "unknown charged memory region")
            # A relay-only role does not instantiate endpoint state, but keeps
            # explicit nonzero module reservations for its eventual layout.
            count = minimum_counts[key] if resource["role"] == "endpoint" else 1
            size = minimum_bytes.get(key, 1) if resource["role"] == "endpoint" else 1
            if resource["role"] == "relay" and key == "relay_cache":
                count = operations * (derived["fragment_count"] + derived["bootstrap_fragment_count"]) + m["timing"]["max_status"] + m["timing"]["receipt_limit"]
                count += derived["establishment_frame_reserve"]*s["episode_attempts"]
            if key in ("control", "adapter"):
                size = minimum_bytes[key]
            require(charge["count"] >= count and charge["bytes_each"] >= size,
                    "resources", path + "." + key, "component pool cannot cover admitted concurrency or whole buffers")
            used[charge["region"]] += charge["count"] * charge["bytes_each"]
        require(all(used[k] <= regions[k] for k in regions), "resources", path, "aggregate simultaneous RAM charges exceed a region limit")
        totals[resource["role"]] = used
    derived["ram_reserved_bytes"] = totals


def validate_bytes(raw, expected_sha256=None):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BYTES, "encoding", "$", "input must be 1..262144 bytes")
    require(not raw.startswith(b"\xef\xbb\xbf"), "encoding", "$", "UTF-8 BOM is forbidden")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ProfileError("encoding", "$", "invalid UTF-8") from error
    _check_text(text)
    try:
        m = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                       parse_float=_noninteger, parse_constant=_noninteger)
    except (json.JSONDecodeError, RecursionError) as error:
        raise ProfileError("json", "$", "invalid JSON") from error
    _check_surrogates(m)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    _schema(m, schema)
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None:
        require(isinstance(expected_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None and
                digest == expected_sha256, "digest", "$", "exact manifest SHA256 mismatch")
    direct, selective = _identity_and_services(m)
    _security(m)
    derived = _frames(m, direct)
    _timing(m, selective, derived)
    _establishment(m, derived)
    _relays(m, derived)
    _resources(m, derived)
    return {"valid": True, "sha256": digest, "derived": derived}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--expect-sha256")
    args = parser.parse_args(argv)
    try:
        with args.manifest.open("rb") as handle:
            raw = handle.read(MAX_BYTES + 1)
        result = validate_bytes(raw, args.expect_sha256)
    except ProfileError as error:
        print(json.dumps({"valid": False, "code": error.code, "path": error.path, "message": error.message}))
        return 1
    except OSError as error:
        print(json.dumps({"valid": False, "code": "io", "path": "$", "message": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
