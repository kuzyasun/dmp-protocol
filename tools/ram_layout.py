#!/usr/bin/env python3
"""Reconcile one endpoint's caller-owned RAM layout without mixing evidence.

Host sizeof-derived buffers, Cortex-M compile-only layout, observed host Noise
allocator blocks, reserved queue/stack budgets, and unknown target peaks are
reported separately. The provider scratch limit is a maximum single allocation,
not a second arena; control slots share the adapter frame pool.
"""

import argparse
import hashlib
import json
import sys

import ram_report


CAP = 131072
SCRATCH_LIMIT = 16384


def load(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    return json.loads(raw.decode("utf-8"))


def count_bytes(charge):
    return {item["component"]: (item["count"], item["bytes_each"])
            for item in charge["charges"] if item.get("region") == "RAM"}


def checked_side_measurements(measurement):
    ram_report.validate_measurement(measurement)
    sides = measurement.get("side_measurements")
    if not isinstance(sides, list) or len(sides) != 2:
        raise ram_report.Invalid("measurement must contain separate initiator and responder runs")
    by_role = {item.get("role"): item for item in sides if isinstance(item, dict)}
    if set(by_role) != {"initiator", "responder"}:
        raise ram_report.Invalid("side measurements must contain initiator and responder exactly once")
    peaks = []
    for role, side in by_role.items():
        phases = side.get("provider_phases")
        if not isinstance(phases, list) or {p.get("name") for p in phases if isinstance(p, dict)} != ram_report.PROVIDER_PHASES:
            raise ram_report.Invalid(f"{role} side must report every P01B provider phase")
        if any(p.get("status") != "measured" for p in phases):
            raise ram_report.Invalid(f"{role} side contains an unmeasured P01B provider phase")
        for phase in phases:
            for key in ("provider_retained_current_bytes", "provider_retained_peak_bytes",
                        "provider_largest_single_allocation_bytes"):
                ram_report.nonnegative(phase.get(key), f"{role} {phase.get('name')} {key}")
            if phase["provider_retained_current_bytes"] > phase["provider_retained_peak_bytes"]:
                raise ram_report.Invalid(f"{role} side has current retained bytes above its peak")
        peak = max(p["provider_retained_peak_bytes"] for p in phases)
        peaks.append(peak)
    return max(peaks)


def abi_maps(mcu):
    objects = {item["name"]: item["sizeof"] for item in mcu.get("objects", [])}
    # Keep the public C probe's record names intact in its artifact while
    # translating to the conceptual names used by the shared host layout.
    objects["dmp_endpoint"] = objects.get("endpoint")
    objects["tombstone"] = objects.get("reassembly_tombstone")
    private = {item["symbol"]: item.get("sizeof") for item in mcu.get("private_sizes", [])}
    if mcu.get("runtime_executed") is not False or mcu.get("abi_class") != "mcu_compile_only":
        raise ram_report.Invalid("MCU ABI input is not explicitly classified compile-only")
    objects["dmp_hs"] = private.get("dmp_hs_size")
    objects["dmp_provider"] = private.get("dmp_provider_size")
    required = {
        "dmp_endpoint", "identity_slot", "sender_slot", "result_slot",
        "history_slot", "correlation_slot", "adapter_slot", "reassembly_slot",
        "tombstone", "freshness_slot", "stream_decoder", "dmp_hs", "dmp_provider",
    }
    missing = sorted(name for name in required if not isinstance(objects.get(name), int))
    if missing:
        raise ram_report.Invalid("MCU layout misses required records: " + ", ".join(missing))
    return objects


def operation_count(manifest):
    profile_id = manifest["profile"]["id"]
    return 1 if profile_id in {"TEST-DIRECT-MINIMAL-128", "TEST-DIRECT-MINIMAL-256"} else 2 * len(manifest["services"])


def components(manifest, sizes, observed_provider_peak):
    limits = manifest["limits"]
    security = manifest["security"]
    freshness = manifest["freshness"]
    services = manifest["services"]
    associations = (security["pending_per_pair"] + security["active_per_pair"] +
                    security["draining_per_pair"])
    operations = operation_count(manifest)
    grants = freshness["grant_requests_per_pair"] if any(s["freshness"] for s in services) else 0
    result_count = operations + grants
    history_count = 2 * result_count
    message = limits["message_bytes"]
    encoded = manifest["binding"]["encoded_mtu"]
    stream_bound = (encoded + 4) + (encoded + 4) // 254 + 2
    work_buffers = 4 * message + 2 * encoded + stream_bound + (stream_bound + 1)
    queue_reserved = limits["application_queue_slots"] * message
    association_group = (sizes["dmp_endpoint"] + sizes["dmp_hs"] + sizes["dmp_provider"] +
                         associations * sizes["identity_slot"])
    freshness_count = freshness["tokens_per_principal"] if any(s["freshness"] for s in services) else 0
    return {
        "counts": {
            "provider_retained": associations,
            "provider_scratch": 1,
        "association": 1,
            "bootstrap": 0,
            "sender": operations,
            "assembly": limits["assemblies_per_peer"],
            "assembly_tombstone": limits["peers"] * limits["assembly_tombstones_per_peer"],
            "result": result_count,
            "history": history_count,
            "correlation": result_count,
            "control": limits["control_slots"],
            "application_queue": 1,
            "adapter": limits["adapter_slots"],
            "stacks": 1,
            "relay_cache": 0,
            "freshness_tokens": freshness_count,
        },
        "bytes_each": {
            "provider_retained": observed_provider_peak,
            "provider_scratch": SCRATCH_LIMIT,
            "association": association_group,
            "bootstrap": 0,
            "sender": sizes["sender_slot"] + message,
            "assembly": sizes["reassembly_slot"] + message + sizes["reassembly_metadata_bytes"],
            "assembly_tombstone": sizes["tombstone"],
            "result": sizes["result_slot"] + message,
            "history": sizes["history_slot"] + sizes["reliability_metadata_bytes"],
            "correlation": sizes["correlation_slot"] + sizes["reliability_metadata_bytes"],
            "control": 0,
            "application_queue": work_buffers + queue_reserved,
            "adapter": sizes["adapter_slot"] + encoded,
            "stacks": 12288,
            "relay_cache": 0,
            "freshness_tokens": sizes["freshness_slot"] if freshness_count else 0,
        },
        "details": {
            "operation_limit_global": operations,
            "provider_association_slots_reserved": associations,
            "provider_one_association_peak_observed_host": observed_provider_peak,
            "provider_scratch_observed_largest_single": None,
            "provider_scratch_limit_per_allocation": SCRATCH_LIMIT,
            "endpoint_work_buffers_host_layout_bytes": work_buffers,
            "application_queue_reserved_bytes": queue_reserved,
            "control_quota_overlaps_adapter_frame_pool": True,
            "attempts_are_embedded_in_handshake_manager": True,
            "relay_cache_endpoint_bytes": 0,
            "freshness_slots": freshness_count,
            "max_logical_message_bytes": message,
            "chunk_bytes": limits["chunk_bytes"],
            "fragment_count_at_maximum": (message + limits["chunk_bytes"] - 1) // limits["chunk_bytes"],
        "association_rotation_policy": {
            "pending_per_pair": security["pending_per_pair"],
            "active_per_pair": security["active_per_pair"],
            "draining_per_pair": security["draining_per_pair"],
            "drain_ms": security["drain_ms"],
            "full_capacity": security["full_capacity"],
            "peer_restart": security["peer_restart"],
            "reconnect": manifest["identity"]["restart"],
        },
        },
    }


def calculate(manifest, measurement, mcu, manifest_hash):
    ram_report.validate_measurement(measurement)
    if not isinstance(mcu, dict):
        raise ram_report.Invalid("MCU ABI input must be an object")
    resource = ram_report.endpoint_resource(manifest)
    charges = count_bytes(resource)
    workload = measurement.get("workload")
    if not isinstance(workload, dict):
        raise ram_report.Invalid("measurement workload must be an object")
    limits = manifest["limits"]
    if (workload.get("provider_sized_plaintext_bytes") != limits["message_bytes"] or
            workload.get("provider_encrypt_sequence_count") != limits["sender_slots"] or
            workload.get("provider_plaintext_chunk_bytes") != limits["chunk_bytes"] or
            workload.get("provider_encrypt_calls_per_sequence") != limits["fragments"]):
        raise ram_report.Invalid("P01B provider cipher workload differs from the declared manifest-sized inputs")
    host_sizes = measurement.get("host_layout_sizes")
    if not isinstance(host_sizes, dict):
        raise ram_report.Invalid("measurement is missing host_layout_sizes")
    required_host = {
        "dmp_endpoint", "dmp_hs", "dmp_provider", "identity_slot", "sender_slot",
        "result_slot", "history_slot", "correlation_slot", "adapter_slot",
        "reassembly_slot", "tombstone", "freshness_slot", "stream_decoder",
        "reliability_metadata_bytes", "reassembly_metadata_bytes", "stream_encoded_bound", "encoded_mtu",
    }
    if any(isinstance(host_sizes.get(name), bool) or not isinstance(host_sizes.get(name), int)
           for name in required_host):
        raise ram_report.Invalid("host layout sizes are incomplete")
    if host_sizes["encoded_mtu"] != manifest["binding"]["encoded_mtu"]:
        raise ram_report.Invalid("provider probe encoded MTU differs from manifest binding")
    provider_probe_peak = checked_side_measurements(measurement)
    endpoint_runtime_peak = workload.get("one_device_provider_retained_peak_bytes", 0)
    if isinstance(endpoint_runtime_peak, bool) or not isinstance(endpoint_runtime_peak, int) or endpoint_runtime_peak < 0:
        raise ram_report.Invalid("one-device endpoint provider peak must be a nonnegative integer")
    host_peak = max(provider_probe_peak, endpoint_runtime_peak)
    layout = components(manifest, host_sizes, host_peak)
    layout["details"]["provider_one_association_peak_p01b_probe"] = provider_probe_peak
    layout["details"]["provider_one_association_peak_endpoint_runtime"] = endpoint_runtime_peak
    mcu_sizes = abi_maps(mcu)
    mcu_sizes.update({
        "reliability_metadata_bytes": host_sizes["reliability_metadata_bytes"],
        "reassembly_metadata_bytes": host_sizes["reassembly_metadata_bytes"],
    })
    mcu_projection = components(manifest, mcu_sizes, 0)

    object_rows = []
    def add(name, count, each, classification, note):
        object_rows.append({"name": name, "count": count, "bytes_each": each,
                            "bytes": count * each, "classification": classification,
                            "note": note})

    for name in ("association", "sender", "assembly", "assembly_tombstone", "result",
                 "history", "correlation", "adapter"):
        add(name, layout["counts"][name], layout["bytes_each"][name], "host_abi_calculated",
            "Exact GCC host sizeof values plus caller-owned capacity from this manifest.")
    if layout["counts"]["freshness_tokens"]:
        add("freshness_tokens", layout["counts"]["freshness_tokens"],
            layout["bytes_each"]["freshness_tokens"], "host_abi_calculated",
            "Freshness grant records measured with the host ABI.")
    add("endpoint_work_buffers", 1, layout["details"]["endpoint_work_buffers_host_layout_bytes"],
        "host_abi_calculated", "Receive, fragment, telemetry, and Stream R arrays; no control-slot copy.")
    add("application_queue", 1, layout["details"]["application_queue_reserved_bytes"], "reserved",
        "Application-owned payload queue reserve, distinct from libdmp sender storage.")
    add("provider_retained_single_association", 1, host_peak, "observed",
        "One-role P01B NNpsk0 requested live allocator high-water; host allocator metadata excluded.")
    add("provider_retained_rotation_reserve", max(layout["counts"]["provider_retained"] - 1, 0),
        host_peak, "estimate", "Projects one measured active association peak per simultaneous Noise state.")
    stack_charge = charges.get("stacks", (0, 0))[0] * charges.get("stacks", (0, 0))[1]
    add("task_stacks", 1, stack_charge, "reserved", "Manifest reservation only; stack high-water is unmeasured.")

    expected_charges = {name: (layout["counts"][name], layout["bytes_each"][name])
                        for name in layout["counts"]}
    charge_gaps = []
    charge_headroom = []
    for name, expected in expected_charges.items():
        actual = charges.get(name)
        if actual is None or actual[0] < expected[0] or actual[1] < expected[1]:
            charge_gaps.append({"component": name, "expected_count_bytes_each": expected,
                                "manifest_count_bytes_each": actual})
        elif actual != expected:
            charge_headroom.append({"component": name, "minimum_count_bytes_each": expected,
                                    "manifest_count_bytes_each": actual,
                                    "surplus_bytes": actual[0] * actual[1] - expected[0] * expected[1]})

    host_static = sum(row["bytes"] for row in object_rows
                      if row["classification"] == "host_abi_calculated")
    provider_reserved = layout["counts"]["provider_retained"] * host_peak
    host_budget = host_static + layout["details"]["application_queue_reserved_bytes"] + provider_reserved + stack_charge
    mcu_static = sum(mcu_projection["counts"][name] * mcu_projection["bytes_each"][name]
                     for name in ("association", "sender", "assembly", "assembly_tombstone",
                                  "result", "history", "correlation", "adapter"))
    mcu_static += mcu_projection["details"]["endpoint_work_buffers_host_layout_bytes"]
    mcu_static += (mcu_projection["counts"]["freshness_tokens"] *
                   mcu_projection["bytes_each"]["freshness_tokens"])
    manifest_additive = sum(item["charged"] for item in ram_report.charge_table(resource).values())
    projection_gap = host_budget - manifest_additive
    totals = {
        "host_static_arrays_calculated_bytes": host_static,
        "host_one_association_provider_peak_observed_bytes": host_peak,
        "host_provider_rotation_reserve_estimate_bytes": provider_reserved,
        "application_queue_reserved_bytes": layout["details"]["application_queue_reserved_bytes"],
        "stack_reserved_bytes_unverified": stack_charge,
        "host_budget_projection_bytes": host_budget,
        "manifest_additive_charged_bytes": manifest_additive,
        "host_projection_minus_manifest_charge_bytes": projection_gap,
        "manifest_charge_headroom_bytes": max(-projection_gap, 0),
        "manifest_undercoverage_bytes": max(projection_gap, 0),
        "mcu_static_layout_compile_only_bytes": mcu_static,
        "mcu_provider_dynamic_bytes": None,
        "mcu_stack_peak_bytes": None,
        "ram_region_limit_bytes": CAP,
        "host_budget_projection_within_region": host_budget <= CAP,
        "mcu_layout_is_not_physical_peak": True,
        "scratch_limit_additive_bytes": 0,
        "control_pool_additive_bytes": 0,
        "reconnect_overlap_status": workload.get("reconnect_overlap_status"),
    }
    issues = [
        f"required endpoint lifecycle phase {phase['name']} is not measured"
        for phase in measurement["phases"] if phase["status"] != "measured"
    ]
    if workload.get("endpoint_runtime_status") != "measured":
        issues.append("endpoint lifecycle runtime is not measured; layout is a charge projection only")
    else:
        if workload.get("endpoint_runtime_profile_id") != manifest.get("profile", {}).get("id"):
            issues.append("endpoint lifecycle profile ID does not match the manifest")
        if workload.get("endpoint_runtime_manifest_digest_sha256") != manifest_hash:
            issues.append("endpoint lifecycle manifest digest does not match the exact manifest SHA-256")
    overlap_status = workload.get("reconnect_overlap_status")
    if overlap_status == "budgeted_not_measured":
        provider_charge = charges.get("provider_retained", (0, 0))
        if (provider_charge[0] < layout["counts"]["provider_retained"] or
                provider_charge[1] < host_peak):
            issues.append("reconnect overlap is not measured and provider rotation charges do not cover the manifest association slots")
    elif overlap_status != "measured":
        issues.append("reconnect overlap runtime is not measured; draining/new association concurrency is unknown")
    if host_budget > CAP:
        issues.append(f"host budget projection {host_budget} exceeds {CAP}")
    if charge_gaps:
        issues.append(f"{len(charge_gaps)} manifest RAM charge rows under-cover the reconciled host layout")
    if projection_gap > 0:
        issues.append(f"host projection and additive manifest charges differ by {projection_gap} bytes")
    if manifest_additive > CAP:
        issues.append(f"manifest additive RAM charges {manifest_additive} exceed {CAP}")
    return {"ok": not issues, "profile_id": manifest["profile"]["id"],
            "manifest_hash": manifest_hash, "objects": object_rows,
            "expected_charges": expected_charges, "charge_gaps": charge_gaps,
            "charge_headroom": charge_headroom,
            "details": layout["details"], "mcu_layout_projection": {
                "classification": "Cortex-M compile-only sizeof/alignof; no allocator, stack, or runtime claim",
                "static_bytes": mcu_static,
            }, "totals": totals, "issues": issues}


def main():
    parser = argparse.ArgumentParser(description="Reconcile one endpoint host and MCU RAM layouts")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--measurement", required=True)
    parser.add_argument("--mcu-abi", required=True)
    parser.add_argument("--output", required=True)
    checks = parser.add_mutually_exclusive_group()
    checks.add_argument("--check", action="store_true",
                        help="require lifecycle evidence and all profile-layout checks")
    checks.add_argument("--check-budget-only", action="store_true",
                        help="check profile layout while preserving unmeasured lifecycle status")
    args = parser.parse_args()
    try:
        with open(args.manifest, "rb") as handle:
            manifest_raw = handle.read()
        manifest = json.loads(manifest_raw.decode("utf-8"))
        measurement = load(args.measurement)
        mcu = load(args.mcu_abi)
        report = calculate(manifest, measurement, mcu, hashlib.sha256(manifest_raw).hexdigest())
        lifecycle_prefixes = ("required endpoint lifecycle phase ",
                              "endpoint lifecycle runtime is not measured",
                              "reconnect overlap runtime is not measured")
        check_issues = ([issue for issue in report["issues"]
                         if not issue.startswith(lifecycle_prefixes)]
                        if args.check_budget_only else report["issues"])
        report["ok"] = not check_issues
        report["check_scope"] = "profile-budget-only" if args.check_budget_only else "lifecycle-and-profile-budget"
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        print(f"{report['profile_id']}: host_static={report['totals']['host_static_arrays_calculated_bytes']} "
              f"host_budget={report['totals']['host_budget_projection_bytes']} "
              f"mcu_static_layout={report['totals']['mcu_static_layout_compile_only_bytes']} "
              f"limit={CAP}")
        for gap in report["charge_gaps"]:
            print(f"RAM CHARGE UNDERCOVERAGE {gap['component']}: minimum {gap['expected_count_bytes_each']} "
                  f"manifest {gap['manifest_count_bytes_each']}", file=sys.stderr)
        for surplus in report["charge_headroom"]:
            print(f"RAM CHARGE HEADROOM {surplus['component']}: minimum {surplus['minimum_count_bytes_each']} "
                  f"manifest {surplus['manifest_count_bytes_each']} surplus={surplus['surplus_bytes']} bytes")
        for issue in report["issues"]:
            if args.check_budget_only and issue.startswith(lifecycle_prefixes):
                print(f"UNMEASURED: {issue}", file=sys.stderr)
            else:
                print(f"ERROR: {issue}", file=sys.stderr)
        return 1 if (args.check and report["issues"]) or (args.check_budget_only and check_issues) else 0
    except (OSError, json.JSONDecodeError, ram_report.Invalid, KeyError, TypeError, ValueError) as error:
        print(f"invalid RAM layout input: {error}", file=sys.stderr)
        return 1 if args.check or args.check_budget_only else 2


if __name__ == "__main__":
    sys.exit(main())
