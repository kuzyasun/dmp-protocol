#!/usr/bin/env python3
"""Merge P01B provider evidence with a manifest-bound endpoint lifecycle run."""

import argparse
import copy
import hashlib
import json
import sys

import ram_layout
import ram_report


def load(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    return raw, json.loads(raw.decode("utf-8"))


def require(condition, message):
    if not condition:
        raise ram_report.Invalid(message)


def number(value, name):
    return ram_report.nonnegative(value, name)


def bounded_number(value, name, maximum):
    result = number(value, name)
    require(result <= maximum, f"{name} exceeds {maximum}")
    return result


def service_two(manifest):
    services = manifest.get("services")
    if not isinstance(services, list):
        raise ram_report.Invalid("manifest services must be an array")
    matches = [item for item in services if isinstance(item, dict) and item.get("id") == 2]
    if len(matches) != 1:
        raise ram_report.Invalid("manifest must declare exactly one service 2 workload")
    return matches[0]


def validate_endpoint_runtime(manifest, manifest_hash, endpoint):
    if not isinstance(endpoint, dict) or endpoint.get("ok") is not True:
        raise ram_report.Invalid("endpoint lifecycle report did not complete")
    require(endpoint.get("schema_version") == 1 and not isinstance(endpoint.get("schema_version"), bool),
            "endpoint lifecycle schema_version must be 1")
    require(endpoint.get("device_count") == 1 and endpoint.get("peer_process_count") == 1 and
            endpoint.get("peer_process_isolated") is True,
            "endpoint lifecycle must measure one device with an isolated peer process")
    require(endpoint.get("evidence_class") == "host-runtime-one-endpoint-process-isolated-peer",
            "endpoint lifecycle evidence class is not the expected one-device host run")
    profile_id = manifest.get("profile", {}).get("id")
    require(endpoint.get("profile_id") == profile_id and endpoint.get("endpoint_profile_id") == profile_id,
            "endpoint lifecycle profile ID differs from manifest")
    require(endpoint.get("profile_digest_sha256") == manifest_hash,
            "endpoint lifecycle digest differs from exact manifest bytes")
    phases = endpoint.get("phases")
    if not isinstance(phases, list):
        raise ram_report.Invalid("endpoint lifecycle phases must be an array")
    by_name = {}
    for phase in phases:
        if not isinstance(phase, dict) or not isinstance(phase.get("name"), str):
            raise ram_report.Invalid("endpoint lifecycle phase needs a name")
        if phase["name"] in by_name:
            raise ram_report.Invalid("endpoint lifecycle phase names must be unique")
        by_name[phase["name"]] = phase
    require(set(by_name) == ram_report.REQUIRED_PHASES,
            "endpoint lifecycle must report every required phase exactly once")
    for name, phase in by_name.items():
        require(phase.get("status") == "measured", f"endpoint lifecycle phase {name} is not measured")
        current = number(phase.get("caller_owned_requested_current_bytes"), f"{name} caller-owned current")
        provider_current = number(phase.get("provider_retained_current_bytes"), f"{name} provider current")
        provider_peak = number(phase.get("provider_retained_peak_bytes"), f"{name} provider peak")
        largest = number(phase.get("provider_largest_single_allocation_bytes"), f"{name} provider largest")
        high_water = number(phase.get("host_observed_requested_payload_high_water_bytes"), f"{name} host high-water")
        require(provider_current <= provider_peak, f"{name} provider current exceeds its peak")
        require(largest <= provider_peak, f"{name} provider largest allocation exceeds its peak")
        require(high_water >= current + provider_current, f"{name} host high-water is below current requested bytes")
        if name != "cleanup":
            require(high_water >= current + provider_peak,
                    f"{name} host high-water omits provider lifetime peak")
    service = service_two(manifest)
    binding = manifest.get("binding")
    require(isinstance(binding, dict), "manifest binding must be an object")
    request_bytes = number(service.get("request_bytes"), "service 2 request_bytes")
    result_bytes = number(service.get("result_bytes"), "service 2 result_bytes")
    limits = manifest.get("limits")
    if not isinstance(limits, dict):
        raise ram_report.Invalid("manifest limits must be an object")
    chunk_bytes = number(limits.get("chunk_bytes"), "chunk_bytes")
    require(chunk_bytes > 0, "chunk_bytes must be nonzero")
    encoded_mtu = number(manifest.get("binding", {}).get("encoded_mtu"), "encoded_mtu")
    unfragmented_fits = request_bytes + 48 <= encoded_mtu
    max_fragments = number(limits.get("fragments"), "fragments")
    expected_frames = (1 if unfragmented_fits
                       else (request_bytes + chunk_bytes - 1) // chunk_bytes)
    require(request_bytes == number(limits.get("message_bytes"), "message_bytes") and
            (unfragmented_fits or expected_frames == max_fragments),
            "service 2 request geometry differs from manifest limits")
    retry = by_name["request_result_retry"]
    if binding.get("context") == "origin-explicit":
        route_frames = number(retry.get("origin_route_frames"), "origin route frame count")
        valid_route_frames = number(retry.get("origin_route_frames_valid"), "valid origin route frame count")
        require(route_frames > 0 and valid_route_frames == route_frames,
                "endpoint lifecycle did not verify every emitted and received origin route")
    if service.get("freshness") is True:
        require(retry.get("freshness_grant_verified") is True and
                retry.get("freshness_grant_request_frames") == 1 and
                retry.get("freshness_grant_result_payload_bytes") == 21 and
                retry.get("freshness_token_bound_to_request") is True,
                "endpoint lifecycle did not complete and bind the manifest S7 freshness grant")
    require(retry.get("reliable_request_payload_bytes") == request_bytes and
            retry.get("peer_request_payload_bytes") == request_bytes and
            retry.get("peer_request_payload_matches") is True,
            "endpoint peer did not verify the exact manifest-sized request payload")
    require(retry.get("reliable_result_payload_bytes") == result_bytes and
            retry.get("reliable_result_payload_matches") is True and
            retry.get("reliable_result_wire_status") == 0,
            "endpoint did not verify the exact successful manifest-sized result payload")
    require(retry.get("injected_loss_count") == 1 and retry.get("local_request_submissions") == 1 and
            retry.get("peer_request_notices") == 1 and retry.get("endpoint_result_notices") == 1,
            "endpoint lifecycle did not complete exactly one request with one injected loss")
    require(retry.get("reliable_request_retry_observed") is True and
            retry.get("retry_frame_differs_from_dropped_frame") is True,
            "endpoint lifecycle did not observe a distinct protected retry")
    dropped_type = bounded_number(retry.get("dropped_request_type"), "dropped request type", 0xFFFFFFFF)
    retry_type = bounded_number(retry.get("retry_request_type"), "retry request type", 0xFFFFFFFF)
    dropped_seq = bounded_number(retry.get("dropped_request_seq"), "dropped request SEQ", 0xFFFFFFFF)
    retry_seq = bounded_number(retry.get("retry_request_seq"), "retry request SEQ", 0xFFFFFFFF)
    dropped_fragment = bounded_number(retry.get("dropped_request_fragment_index"),
                                      "dropped request fragment index", 0xFFFFFFFF)
    retry_fragment = bounded_number(retry.get("retry_request_fragment_index"),
                                    "retry request fragment index", 0xFFFFFFFF)
    dropped_pn = bounded_number(retry.get("dropped_request_pn"), "dropped request PN", 0xFFFFFF)
    retry_pn = bounded_number(retry.get("retry_request_pn"), "retry request PN", 0xFFFFFF)
    fragment_valid = (dropped_fragment == 0xFFFFFFFF if expected_frames == 1
                      else dropped_fragment < expected_frames)
    require(dropped_type == retry_type == 0 and dropped_seq == retry_seq and
            dropped_fragment == retry_fragment and fragment_valid and dropped_pn != retry_pn,
            "retry does not match the lost logical REQ fragment with a fresh PN")
    request_frame_count = number(retry.get("reliable_request_frame_count"), "request frame count")
    require(request_frame_count == expected_frames, "request frame count differs from manifest geometry")
    if expected_frames == 1:
        require(retry.get("reliable_request_fragment_count") == 0 and
                retry.get("peer_assembled_message_count") == 0 and
                retry.get("peer_assembled_message_bytes") == 0,
                "small request should remain one unfragmented frame")
    else:
        require(retry.get("reliable_request_fragment_count") == expected_frames and
                retry.get("peer_assembled_message_count") == 1 and
                retry.get("peer_assembled_message_bytes") == request_bytes,
                "fragmented request frame/assembly evidence differs from its manifest geometry")
    reconnect = endpoint.get("reconnect")
    if not isinstance(reconnect, dict):
        raise ram_report.Invalid("endpoint lifecycle reconnect evidence must be an object")
    prior_initiator_epoch = bounded_number(reconnect.get("prior_initiator_traffic_epoch"),
                                           "prior initiator traffic epoch", 0xFFFFFFFFFFFFFFFF)
    new_initiator_epoch = bounded_number(reconnect.get("new_initiator_traffic_epoch"),
                                         "new initiator traffic epoch", 0xFFFFFFFFFFFFFFFF)
    prior_responder_epoch = bounded_number(reconnect.get("prior_responder_traffic_epoch"),
                                           "prior responder traffic epoch", 0xFFFFFFFFFFFFFFFF)
    new_responder_epoch = bounded_number(reconnect.get("new_responder_traffic_epoch"),
                                         "new responder traffic epoch", 0xFFFFFFFFFFFFFFFF)
    require(prior_initiator_epoch != 0 and new_initiator_epoch != 0 and
            prior_responder_epoch != 0 and new_responder_epoch != 0 and
            reconnect.get("same_ipc_connection") is True and
            reconnect.get("attempt_id_changed") is True and
            reconnect.get("initiator_ephemeral_changed") is True and
            reconnect.get("responder_ephemeral_changed") is True and
            prior_initiator_epoch != new_initiator_epoch and
            prior_responder_epoch != new_responder_epoch,
            "reconnect did not use fresh entropy and distinct traffic epochs")
    require(reconnect.get("old_data_frame_seen_by_original_peer") is True and
            reconnect.get("prior_protected_frame_status_name") == "DMP_AUTHENTICATION_FAILURE" and
            reconnect.get("prior_frame_rejected_without_dispatch") is True,
            "prior-association protected DATA was not rejected without dispatch")
    accounting = endpoint.get("accounting")
    require(isinstance(accounting, dict) and accounting.get("peer_memory_included") is False and
            accounting.get("physical_mcu_peak") == "not_measured",
            "endpoint lifecycle accounting must exclude peer and MCU runtime claims")
    runtime_peak = max(number(phase["provider_retained_peak_bytes"], "provider peak")
                       for phase in phases)
    endpoint_peak = max(number(phase["host_observed_requested_payload_high_water_bytes"], "host high-water")
                        for phase in phases)
    return by_name, runtime_peak, endpoint_peak


def merge(manifest_raw, manifest, provider, endpoint):
    ram_report.validate_measurement(provider)
    manifest_hash = hashlib.sha256(manifest_raw).hexdigest()
    phases, runtime_peak, endpoint_peak = validate_endpoint_runtime(manifest, manifest_hash, endpoint)
    merged = copy.deepcopy(provider)
    merged["phases"] = [copy.deepcopy(phases[name]) for name in (
        "initial", "handshake_peak", "active_steady", "request_result_retry", "cleanup", "reconnect")]
    provider_peak = max(runtime_peak, ram_layout.checked_side_measurements(provider))
    workload = merged.get("workload")
    if not isinstance(workload, dict):
        raise ram_report.Invalid("P01B workload must be an object")
    workload["endpoint_runtime_status"] = "measured"
    workload["endpoint_runtime_reason"] = "one manifest-bound protected endpoint ran against a real isolated libdmp peer process"
    workload["reconnect_overlap_status"] = "budgeted_not_measured"
    workload["reconnect_overlap_reason"] = (
        "the harness closes endpoint/provider state before a fresh handshake; simultaneous rotation is reserved by "
        "pending+active+draining provider charges and is not claimed as runtime-measured"
    )
    workload["one_device_provider_retained_peak_bytes"] = provider_peak
    workload["one_device_host_requested_payload_high_water_bytes"] = endpoint_peak
    workload["endpoint_runtime_manifest_digest_sha256"] = manifest_hash
    workload["endpoint_runtime_profile_id"] = manifest["profile"]["id"]
    objects = merged.get("objects")
    if not isinstance(objects, list):
        raise ram_report.Invalid("P01B objects must be an array")
    provider_objects = [item for item in objects if isinstance(item, dict) and item.get("charge") == "provider_retained"]
    if len(provider_objects) != 1:
        raise ram_report.Invalid("P01B report must contain exactly one provider_retained object")
    provider_objects[0]["physical_bytes"] = provider_peak
    provider_objects[0]["check_bytes"] = provider_peak
    provider_objects[0]["note"] = (
        "Maximum requested live Noise allocator payload across P01B and the manifest-bound one-device endpoint run; "
        "peer memory, scratch classification, allocator metadata and alignment are excluded."
    )
    unknowns = endpoint.get("unknowns")
    if not isinstance(unknowns, list) or any(not isinstance(item, str) for item in unknowns):
        raise ram_report.Invalid("endpoint runtime unknowns must be an array of strings")
    merged["host_runtime_unknowns"] = list(dict.fromkeys(unknowns))
    merged["host_runtime_accounting"] = copy.deepcopy(endpoint["accounting"])
    merged["host_runtime"] = {
        "evidence_class": endpoint["evidence_class"],
        "profile_id": endpoint["profile_id"],
        "manifest_sha256": manifest_hash,
        "one_device_provider_retained_peak_bytes": provider_peak,
        "one_device_host_requested_payload_high_water_bytes": endpoint_peak,
        "peer_process_isolated": True,
        "peer_memory_included": False,
        "reconnect_overlap_status": "budgeted_not_measured",
        "physical_mcu_peak": "not_measured",
    }
    return merged


def main():
    parser = argparse.ArgumentParser(description="Join P01B provider and manifest-bound endpoint lifecycle evidence")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--provider-measurement", required=True)
    parser.add_argument("--endpoint-measurement", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        manifest_raw, manifest = load(args.manifest)
        _, provider = load(args.provider_measurement)
        _, endpoint = load(args.endpoint_measurement)
        report = merge(manifest_raw, manifest, provider, endpoint)
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        print(f"{manifest['profile']['id']}: endpoint_peak={report['host_runtime']['one_device_host_requested_payload_high_water_bytes']} "
              f"provider_peak={report['host_runtime']['one_device_provider_retained_peak_bytes']} "
              f"reconnect_overlap=budgeted_not_measured")
        return 0
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(f"invalid RAM merge input: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
