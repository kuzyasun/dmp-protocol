#!/usr/bin/env python3
"""Validate and report one-device RAM evidence against manifest charges.

Reserved charges, observed allocations, stack estimates, and unknown target
items are kept separate. --check is a budget/coverage gate, not MCU runtime
qualification.
"""

import argparse
import hashlib
import json
import sys


OWNER_REGION_CAP = 131072
NON_ADDITIVE_CHARGES = {"provider_scratch", "control"}
REQUIRED_PHASES = {
    "initial",
    "handshake_peak",
    "active_steady",
    "request_result_retry",
    "cleanup",
    "reconnect",
}
PROVIDER_PHASES = {
    "provider_initial",
    "provider_handshake_peak",
    "provider_after_split",
    "provider_sized_encrypt_sequence",
    "provider_cleanup",
    "provider_reopen_handshake",
}


class Invalid(ValueError):
    pass


def load(path):
    with open(path, "rb") as handle:
        raw = handle.read()
    return raw, json.loads(raw.decode("utf-8"))


def nonnegative(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise Invalid(f"{name} must be a nonnegative integer")
    return value


def endpoint_resource(manifest):
    if not isinstance(manifest, dict):
        raise Invalid("manifest root must be an object")
    resources = manifest.get("resources")
    if not isinstance(resources, list):
        raise Invalid("manifest resources must be an array")
    matches = [item for item in resources if isinstance(item, dict) and item.get("role") == "endpoint"]
    if len(matches) != 1:
        raise Invalid("manifest must have exactly one endpoint resource")
    return matches[0]


def charge_table(resource):
    rows = {}
    charges = resource.get("charges")
    if not isinstance(charges, list) or not charges:
        raise Invalid("endpoint charges must be a nonempty array")
    for item in charges:
        if not isinstance(item, dict):
            raise Invalid("each endpoint charge must be an object")
        if item.get("region") != "RAM":
            continue
        name = item.get("component")
        if not isinstance(name, str) or not name or name in rows:
            raise Invalid("RAM charge component names must be unique nonempty strings")
        count = nonnegative(item.get("count"), f"charge {name} count")
        each = nonnegative(item.get("bytes_each"), f"charge {name} bytes_each")
        if (count == 0) != (each == 0) and name not in NON_ADDITIVE_CHARGES:
            raise Invalid(f"RAM charge {name} must set count and bytes_each to zero together")
        additive = name not in NON_ADDITIVE_CHARGES
        rows[name] = {"count": count, "bytes_each": each,
                      "configured_bytes": count * each,
                      "additive": additive,
                      "charged": count * each if additive else 0}
    if not rows:
        raise Invalid("endpoint resource has no RAM charges")
    return rows


def region_limit(resource):
    regions = resource.get("regions")
    if not isinstance(regions, list):
        raise Invalid("endpoint regions must be an array")
    matches = [item for item in regions if isinstance(item, dict) and item.get("id") == "RAM"]
    if len(matches) != 1:
        raise Invalid("endpoint must have exactly one RAM region")
    return nonnegative(matches[0].get("limit_bytes"), "RAM limit_bytes")


def validate_measurement(data):
    if (not isinstance(data, dict) or isinstance(data.get("schema_version"), bool) or
            data.get("schema_version") != 1):
        raise Invalid("measurement schema_version must be 1")
    if data.get("ok") is not True:
        raise Invalid(data.get("error", "measurement did not complete"))
    if isinstance(data.get("device_count"), bool) or data.get("device_count") != 1:
        raise Invalid("measurement must describe exactly one device")
    phases = data.get("phases")
    if not isinstance(phases, list):
        raise Invalid("phases must be an array")
    names = []
    for phase in phases:
        if not isinstance(phase, dict) or not isinstance(phase.get("name"), str):
            raise Invalid("each phase needs a name")
        names.append(phase["name"])
        status = phase.get("status")
        if status not in {"measured", "not_measured"}:
            raise Invalid(f"phase {phase['name']} needs measured/not_measured status")
        for key in ("provider_retained_current_bytes", "provider_retained_peak_bytes",
                    "provider_largest_single_allocation_bytes", "provider_largest_scratch_bytes"):
            if phase.get(key) is None and (status == "not_measured" or key == "provider_largest_scratch_bytes"):
                continue
            nonnegative(phase.get(key), f"phase {phase['name']} {key}")
        if status == "measured" and any(phase.get(key) is None for key in (
                "provider_retained_current_bytes", "provider_retained_peak_bytes",
                "provider_largest_single_allocation_bytes")):
            raise Invalid(f"measured phase {phase['name']} has missing retained counters")
        if (phase.get("provider_retained_current_bytes") is not None and
                phase.get("provider_retained_peak_bytes") is not None and
                phase["provider_retained_current_bytes"] > phase["provider_retained_peak_bytes"]):
            raise Invalid(f"phase {phase['name']} retained current exceeds peak")
    missing = REQUIRED_PHASES - set(names)
    if missing:
        raise Invalid("missing phases: " + ", ".join(sorted(missing)))
    if len(names) != len(set(names)):
        raise Invalid("phase names must be unique")
    objects = data.get("objects")
    if not isinstance(objects, list) or not objects:
        raise Invalid("objects must be a nonempty array")
    object_names, overlap_groups = set(), {}
    for obj in objects:
        if not isinstance(obj, dict):
            raise Invalid("each object must be an object")
        name = obj.get("name")
        if not isinstance(name, str) or not name or name in object_names:
            raise Invalid("object names must be unique nonempty strings")
        object_names.add(name)
        for key in ("physical_bytes", "check_bytes"):
            nonnegative(obj.get(key), f"object {name} {key}")
        if obj.get("classification") not in {"observed", "reserved", "estimate", "unknown"}:
            raise Invalid(f"object {name} has invalid classification")
        if not isinstance(obj.get("overlap", False), bool):
            raise Invalid(f"object {name} overlap must be a boolean")
        if obj["classification"] == "unknown" and obj["physical_bytes"] != 0:
            raise Invalid(f"unknown object {name} cannot claim measured physical bytes")
        if obj.get("overlap"):
            group = obj.get("overlap_group")
            if not isinstance(group, str) or not group:
                raise Invalid(f"overlapping object {name} needs overlap_group")
            shared = nonnegative(obj.get("overlap_bytes"), f"object {name} overlap_bytes")
            if shared > obj["physical_bytes"]:
                raise Invalid(f"object {name} overlap_bytes exceeds its physical size")
            overlap_groups.setdefault(group, []).append((name, shared, obj["physical_bytes"]))
        elif obj.get("overlap_group") is not None:
            raise Invalid(f"object {name} declares overlap_group without overlap=true")
        elif "overlap_bytes" in obj:
            raise Invalid(f"object {name} declares overlap_bytes without overlap=true")
        charge = obj.get("charge")
        if charge is not None and (not isinstance(charge, str) or not charge):
            raise Invalid(f"object {name} charge must be a nonempty string or null")
    for group, members in overlap_groups.items():
        if len(members) < 2:
            raise Invalid(f"overlap group {group} must declare at least two objects")
        shared_sizes = {shared for _, shared, _ in members}
        if len(shared_sizes) != 1:
            raise Invalid(f"overlap group {group} has inconsistent shared byte declarations")
    unknowns = data.get("target_only_unknowns")
    if (not isinstance(unknowns, list) or
            any(not isinstance(item, str) or not item.strip() for item in unknowns)):
        raise Invalid("target_only_unknowns must be an array of nonempty strings")
    return objects


def evaluate(manifest, measurement):
    resource = endpoint_resource(manifest)
    limit = region_limit(resource)
    charges = charge_table(resource)
    objects = validate_measurement(measurement)
    required = {name: 0 for name in charges}
    by_charge = {name: [] for name in charges}
    issues = []
    workload = measurement.get("workload")
    if not isinstance(workload, dict):
        raise Invalid("measurement workload must be an object")
    if workload.get("endpoint_runtime_status") != "measured":
        reason = workload.get("endpoint_runtime_reason")
        suffix = f": {reason}" if isinstance(reason, str) and reason else ""
        issues.append("one-device endpoint lifecycle is not measured" + suffix)
    if workload.get("reconnect_overlap_status") != "measured":
        reason = workload.get("reconnect_overlap_reason")
        suffix = f": {reason}" if isinstance(reason, str) and reason else ""
        issues.append("reconnect overlap is not measured" + suffix)
    for phase in measurement["phases"]:
        if phase["status"] != "measured":
            issues.append(f"required phase {phase['name']} is explicitly not measured")
    observed = reserved = estimated = 0
    for obj in objects:
        cls = obj["classification"]
        if cls == "observed":
            observed += obj["physical_bytes"]
        elif cls == "reserved":
            reserved += obj["physical_bytes"]
        elif cls == "estimate":
            estimated += obj["physical_bytes"]
        name = obj.get("charge")
        if obj["check_bytes"] > 0 and not name:
            issues.append(f"uncharged object {obj['name']} requires {obj['check_bytes']} bytes")
        elif obj["physical_bytes"] > 0 and not name:
            issues.append(f"uncharged object {obj['name']} has {obj['physical_bytes']} physical bytes")
        if name:
            if name not in charges:
                issues.append(f"object {obj['name']} refers to undeclared charge {name}")
            else:
                required[name] += obj["check_bytes"]
                by_charge[name].append(obj["name"])
    rows = []
    for name, charge in charges.items():
        gap = required[name] - charge["charged"]
        if gap > 0:
            issues.append(f"charge {name} undercovers objects by {gap} bytes")
        rows.append({"charge": name, "objects": by_charge[name], "required_bytes": required[name],
                     "charged_bytes": charge["charged"], "gap_bytes": gap})
    physical = observed + reserved
    overlap_groups = {}
    for obj in objects:
        if obj.get("overlap"):
            overlap_groups.setdefault(obj["overlap_group"], []).append(obj)
    for members in overlap_groups.values():
        if any(obj["classification"] not in {"observed", "reserved"} for obj in members):
            issues.append("overlap groups may contain only observed/reserved objects")
        elif members:
            physical -= members[0]["overlap_bytes"] * (len(members) - 1)
    charged = sum(item["charged"] for item in charges.values())
    if physical > charged:
        issues.append(f"physical total {physical} exceeds charged total {charged}")
    if physical > OWNER_REGION_CAP:
        issues.append(f"physical total {physical} exceeds fixed cap {OWNER_REGION_CAP}")
    if charged > OWNER_REGION_CAP:
        issues.append(f"charged total {charged} exceeds fixed cap {OWNER_REGION_CAP}")
    if limit != OWNER_REGION_CAP:
        issues.append(f"manifest RAM limit {limit} is not fixed cap {OWNER_REGION_CAP}")
    if physical > limit:
        issues.append(f"physical total {physical} exceeds manifest RAM limit {limit}")
    if charged > limit:
        issues.append(f"charged total {charged} exceeds manifest RAM limit {limit}")
    totals = {"observed_bytes": observed, "reserved_bytes": reserved,
              "estimated_bytes": estimated, "physical_bytes": physical,
              "charged_bytes": charged, "region_limit_bytes": limit,
              "unknown_count": len(measurement["target_only_unknowns"]),
              "scratch_limit_is_per_allocation": True,
              "scratch_included_in_physical": False,
              "scratch_limit_max_bytes_non_additive": charges.get("provider_scratch", {}).get("configured_bytes", 0),
              "control_slots_share_adapter_pool": True}
    return rows, totals, issues


def main():
    parser = argparse.ArgumentParser(description="Validate one-device RAM evidence and charges")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--measurement", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        raw, manifest = load(args.manifest)
        _, measurement = load(args.measurement)
        rows, totals, issues = evaluate(manifest, measurement)
        report = {"ok": not issues, "profile_hash": hashlib.sha256(raw).hexdigest(),
                  "manifest_bytes": len(raw), "rows": rows, "totals": totals,
                  "issues": issues, "phases": measurement["phases"],
                  "workload": measurement.get("workload", {}),
                  "target_only_unknowns": measurement["target_only_unknowns"],
                  "host_abi": measurement.get("host_abi", []),
                  "compile_only_abi_separate": measurement.get("compile_only_abi_separate", True)}
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        print(f"PROFILE_HASH {report['profile_hash']}")
        print(f"{'charge':<28} {'required':>10} {'reserved':>10} {'gap':>8}")
        for row in rows:
            print(f"{row['charge']:<28} {row['required_bytes']:>10} {row['charged_bytes']:>10} {row['gap_bytes']:>8}")
        print("totals: observed={observed_bytes} reserved={reserved_bytes} estimated={estimated_bytes} "
              "physical={physical_bytes} charged={charged_bytes} unknown={unknown_count}".format(**totals))
        for issue in issues:
            print(f"ERROR: {issue}", file=sys.stderr)
        return 1 if args.check and issues else 0
    except (OSError, json.JSONDecodeError, Invalid, TypeError) as error:
        print(f"invalid RAM report input: {error}", file=sys.stderr)
        try:
            with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
                json.dump({"ok": False, "error": str(error)}, handle, indent=2)
                handle.write("\n")
        except OSError as output_error:
            print(f"could not write error report: {output_error}", file=sys.stderr)
        return 1 if args.check else 2


if __name__ == "__main__":
    sys.exit(main())
