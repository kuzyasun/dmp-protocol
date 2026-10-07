import copy
import contextlib
import hashlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "profiles" / "deployments" / "direct-nnpsk0.json"
RADIO_MANIFEST = ROOT / "profiles" / "deployments" / "radio-nnpsk0.json"
MANIFEST_BYTES = MANIFEST.read_bytes()
BASE_MANIFEST = json.loads(MANIFEST_BYTES)
MANIFEST_SHA256 = hashlib.sha256(MANIFEST_BYTES).hexdigest()


def manifest_bytes_for_test(manifest):
    if manifest == BASE_MANIFEST:
        return MANIFEST_BYTES
    return json.dumps(manifest).encode("utf-8")


def manifest_sha256_for_test(manifest):
    return hashlib.sha256(manifest_bytes_for_test(manifest)).hexdigest()


sys.path.insert(0, str(ROOT / "tools"))
import ram_report
import ram_layout
import ram_merge
with MANIFEST.open(encoding="utf-8") as stream:
    RESOURCE = next(item for item in json.load(stream)["resources"] if item["role"] == "endpoint")
CHARGES = {row["component"]: row["count"] * row["bytes_each"]
           for row in RESOURCE["charges"] if row["region"] == "RAM"}


def good_measurement():
    return {
        "schema_version": 1,
        "ok": True,
        "device_count": 1,
        "phases": [
            {"name": name, "status": "measured" if name == "initial" else "not_measured",
             "provider_retained_current_bytes": 0 if name == "initial" else None,
             "provider_retained_peak_bytes": 0 if name == "initial" else None,
             "provider_largest_single_allocation_bytes": 0 if name == "initial" else None,
             "provider_largest_scratch_bytes": 0 if name == "initial" else None}
            for name in ("initial", "handshake_peak", "active_steady",
                         "request_result_retry", "cleanup", "reconnect")
        ],
        "objects": [{"name": "provider area", "charge": "provider_retained",
                     "check_bytes": 1, "physical_bytes": 1,
                     "classification": "observed", "overlap": False}],
        "target_only_unknowns": ["target stack high-water"],
        "workload": {
            "endpoint_runtime_status": "measured",
            "endpoint_runtime_profile_id": BASE_MANIFEST["profile"]["id"],
            "endpoint_runtime_manifest_digest_sha256": MANIFEST_SHA256,
            "reconnect_overlap_status": "measured",
        },
    }


def layout_inputs(unmeasured_phases):
    with MANIFEST.open(encoding="utf-8") as stream:
        manifest = json.load(stream)
    limits = manifest["limits"]
    phases = []
    for name in sorted(ram_report.REQUIRED_PHASES):
        status = "not_measured" if name in unmeasured_phases else "measured"
        phases.append({
            "name": name,
            "status": status,
            "provider_retained_current_bytes": None if status == "not_measured" else 0,
            "provider_retained_peak_bytes": None if status == "not_measured" else 0,
            "provider_largest_single_allocation_bytes": None if status == "not_measured" else 0,
            "provider_largest_scratch_bytes": None,
        })
    measurement = {
        "schema_version": 1,
        "ok": True,
        "device_count": 1,
        "phases": phases,
        "side_measurements": [
            {"role": role, "provider_phases": [
                {"name": name, "status": "measured",
                 "provider_retained_current_bytes": 0 if name in {
                     "provider_initial", "provider_cleanup"} else 1325,
                 "provider_retained_peak_bytes": 0 if name == "provider_initial" else 1325,
                 "provider_largest_single_allocation_bytes": 0 if name == "provider_initial" else 256}
                for name in sorted(ram_report.PROVIDER_PHASES)
            ]}
            for role in ("initiator", "responder")
        ],
        "workload": {
            "provider_sized_plaintext_bytes": limits["message_bytes"],
            "provider_encrypt_sequence_count": limits["sender_slots"],
            "provider_plaintext_chunk_bytes": limits["chunk_bytes"],
            "provider_encrypt_calls_per_sequence": limits["fragments"],
            "endpoint_runtime_status": "measured",
            "endpoint_runtime_profile_id": manifest["profile"]["id"],
            "endpoint_runtime_manifest_digest_sha256": manifest_sha256_for_test(manifest),
            "reconnect_overlap_status": "measured",
        },
        "objects": [{"name": "provider payload", "charge": "provider_retained",
                     "check_bytes": 0, "physical_bytes": 0,
                     "classification": "observed", "overlap": False}],
        "target_only_unknowns": [],
        "host_layout_sizes": {
            name: 1 for name in (
                "dmp_endpoint", "dmp_hs", "dmp_provider", "identity_slot", "sender_slot",
                "result_slot", "history_slot", "correlation_slot", "adapter_slot",
                "reassembly_slot", "tombstone", "freshness_slot", "stream_decoder",
                "reliability_metadata_bytes", "reassembly_metadata_bytes", "stream_encoded_bound",
            )
        },
    }
    measurement["host_layout_sizes"]["encoded_mtu"] = manifest["binding"]["encoded_mtu"]
    mcu_objects = {
        name: 1 for name in (
            "endpoint", "identity_slot", "sender_slot", "result_slot", "history_slot",
            "correlation_slot", "adapter_slot", "reassembly_slot", "reassembly_tombstone",
            "freshness_slot", "stream_decoder",
        )
    }
    mcu = {
        "runtime_executed": False,
        "abi_class": "mcu_compile_only",
        "objects": [{"name": name, "sizeof": size} for name, size in mcu_objects.items()],
        "private_sizes": [
            {"symbol": "dmp_hs_size", "sizeof": 1},
            {"symbol": "dmp_provider_size", "sizeof": 1},
        ],
    }
    return manifest, measurement, mcu


def endpoint_runtime_measurement(manifest, manifest_hash):
    service = next(item for item in manifest["services"] if item["id"] == 2)
    request_bytes = service["request_bytes"]
    result_bytes = service["result_bytes"]
    small = request_bytes + 48 <= manifest["binding"]["encoded_mtu"]
    frame_count = (1 if small else
                   (request_bytes + manifest["limits"]["chunk_bytes"] - 1) // manifest["limits"]["chunk_bytes"])
    retry = {
        "name": "request_result_retry", "status": "measured",
        "caller_owned_requested_current_bytes": 5000,
        "provider_retained_current_bytes": 408, "provider_retained_peak_bytes": 1477,
        "provider_largest_single_allocation_bytes": 256,
        "host_observed_requested_payload_high_water_bytes": 6477,
        "reliable_request_payload_bytes": request_bytes,
        "peer_request_payload_bytes": request_bytes, "peer_request_payload_matches": True,
        "reliable_result_payload_bytes": result_bytes, "reliable_result_payload_matches": True,
        "reliable_result_wire_status": 0,
        "injected_loss_count": 1, "local_request_submissions": 1,
        "peer_request_notices": 1, "endpoint_result_notices": 1,
        "reliable_request_retry_observed": True, "retry_frame_differs_from_dropped_frame": True,
        "dropped_request_type": 0, "retry_request_type": 0,
        "dropped_request_seq": 9, "retry_request_seq": 9,
        "dropped_request_fragment_index": 0 if not small else 4294967295,
        "retry_request_fragment_index": 0 if not small else 4294967295,
        "dropped_request_pn": 1, "retry_request_pn": 2,
        "reliable_request_frame_count": frame_count,
        "reliable_request_fragment_count": 0 if small else frame_count,
        "peer_assembled_message_count": 0 if small else 1,
        "peer_assembled_message_bytes": 0 if small else request_bytes,
    }
    if manifest["binding"].get("context") == "origin-explicit":
        retry["origin_route_frames"] = 8
        retry["origin_route_frames_valid"] = 8
    if service.get("freshness") is True:
        retry["freshness_grant_request_frames"] = 1
        retry["freshness_grant_result_payload_bytes"] = 21
        retry["freshness_grant_verified"] = True
        retry["freshness_token_bound_to_request"] = True
    phases = []
    for name in sorted(ram_report.REQUIRED_PHASES):
        phase = dict(retry) if name == "request_result_retry" else {
            "caller_owned_requested_current_bytes": 5000,
            "provider_retained_current_bytes": 152,
            "provider_retained_peak_bytes": 1477,
            "provider_largest_single_allocation_bytes": 256,
            "host_observed_requested_payload_high_water_bytes": 6477,
        }
        phase.update({"name": name, "status": "measured"})
        if name == "cleanup":
            phase["caller_owned_requested_current_bytes"] = 0
            phase["provider_retained_current_bytes"] = 0
        phases.append(phase)
    return {
        "schema_version": 1, "ok": True, "device_count": 1,
        "peer_process_count": 1, "peer_process_isolated": True,
        "evidence_class": "host-runtime-one-endpoint-process-isolated-peer",
        "profile_id": manifest["profile"]["id"],
        "endpoint_profile_id": manifest["profile"]["id"],
        "profile_digest_sha256": manifest_hash,
        "phases": phases,
        "reconnect": {
            "same_ipc_connection": True, "attempt_id_changed": True,
            "initiator_ephemeral_changed": True, "responder_ephemeral_changed": True,
            "prior_initiator_traffic_epoch": 1, "new_initiator_traffic_epoch": 2,
            "prior_responder_traffic_epoch": 3, "new_responder_traffic_epoch": 4,
            "old_data_frame_seen_by_original_peer": True,
            "prior_protected_frame_status_name": "DMP_AUTHENTICATION_FAILURE",
            "prior_frame_rejected_without_dispatch": True,
        },
        "accounting": {"peer_memory_included": False, "physical_mcu_peak": "not_measured"},
        "unknowns": ["host stack high-water is not measured"],
    }


class RamReportTests(unittest.TestCase):
    def evaluate(self, measurement, manifest=None):
        if manifest is None:
            manifest = BASE_MANIFEST
        return ram_report.evaluate(manifest, measurement, manifest_sha256_for_test(manifest))

    def test_valid_one_device_report_keeps_unknown_phases_explicit(self):
        data = good_measurement()
        for phase in data["phases"]:
            phase["status"] = "measured"
            phase["provider_retained_current_bytes"] = 0
            phase["provider_retained_peak_bytes"] = 0
            phase["provider_largest_single_allocation_bytes"] = 0
            phase["provider_largest_scratch_bytes"] = 0
        _, totals, issues = self.evaluate(data)
        self.assertFalse(issues, issues)
        self.assertEqual(totals["unknown_count"], 1)
        self.assertTrue(totals["scratch_limit_is_per_allocation"])
        self.assertTrue(totals["control_slots_share_adapter_pool"])

    def test_measured_lifecycle_must_match_manifest_digest_and_profile(self):
        raw = RADIO_MANIFEST.read_bytes()
        radio = json.loads(raw)
        radio_hash = hashlib.sha256(raw).hexdigest()
        data = good_measurement()
        for phase in data["phases"]:
            phase.update({"status": "measured", "provider_retained_current_bytes": 0,
                          "provider_retained_peak_bytes": 0,
                          "provider_largest_single_allocation_bytes": 0,
                          "provider_largest_scratch_bytes": 0})
        data["workload"]["endpoint_runtime_profile_id"] = radio["profile"]["id"]
        _, _, issues = ram_report.evaluate(radio, data, radio_hash)
        self.assertTrue(any("manifest digest does not match" in issue for issue in issues), issues)

        data["workload"]["endpoint_runtime_manifest_digest_sha256"] = radio_hash
        data["workload"]["endpoint_runtime_profile_id"] = "not-the-radio-profile"
        _, _, issues = ram_report.evaluate(radio, data, radio_hash)
        self.assertTrue(any("profile ID does not match" in issue for issue in issues), issues)

    def test_scratch_limit_and_control_quota_are_not_additive_arenas(self):
        charges = ram_report.charge_table(RESOURCE)
        self.assertEqual(0, charges["provider_scratch"]["charged"])
        self.assertEqual(16384, charges["provider_scratch"]["configured_bytes"])
        self.assertEqual(0, charges["control"]["charged"])

    def test_unmeasured_phase_is_explicit_and_fails_gate(self):
        _, _, issues = self.evaluate(good_measurement())
        self.assertTrue(any("explicitly not measured" in issue for issue in issues))

    def test_provider_only_probe_fails_endpoint_and_reconnect_gates(self):
        data = good_measurement()
        data["workload"].update({
            "endpoint_runtime_status": "not_measured",
            "endpoint_runtime_reason": "probe never instantiates dmp_endpoint",
            "reconnect_overlap_status": "not_measured",
            "reconnect_overlap_reason": "no overlapping association owners",
        })
        _, _, issues = self.evaluate(data)
        self.assertTrue(any("one-device endpoint lifecycle is not measured" in issue for issue in issues))
        self.assertTrue(any("reconnect overlap runtime is not measured" in issue for issue in issues))

    def test_budgeted_reconnect_overlap_requires_all_manifest_association_slots(self):
        data = good_measurement()
        for phase in data["phases"]:
            phase["status"] = "measured"
            phase["provider_retained_current_bytes"] = 0
            phase["provider_retained_peak_bytes"] = 1477
            phase["provider_largest_single_allocation_bytes"] = 256
        data["workload"].update({
            "endpoint_runtime_status": "measured",
            "reconnect_overlap_status": "budgeted_not_measured",
        })
        _, _, issues = self.evaluate(data)
        self.assertFalse(any("reconnect overlap" in issue for issue in issues), issues)
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        endpoint = next(item for item in manifest["resources"] if item["role"] == "endpoint")
        provider = next(row for row in endpoint["charges"] if row["component"] == "provider_retained")
        provider["count"] = 2
        _, _, issues = self.evaluate(data, manifest)
        self.assertTrue(any("provider rotation charges do not cover" in issue for issue in issues), issues)

        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        endpoint = next(item for item in manifest["resources"] if item["role"] == "endpoint")
        association = next(row for row in endpoint["charges"] if row["component"] == "association")
        association["count"] = 2
        _, _, issues = self.evaluate(data, manifest)
        self.assertTrue(any("association charges do not cover" in issue for issue in issues), issues)

    def test_layout_association_charge_covers_each_lifecycle_slot(self):
        manifest, measurement, mcu = layout_inputs(set())
        sizes = measurement["host_layout_sizes"]
        slots = sum(manifest["security"][key] for key in (
            "pending_per_pair", "active_per_pair", "draining_per_pair"))
        layout = ram_layout.components(manifest, sizes, 1325)
        shared = sizes["dmp_endpoint"] + sizes["dmp_hs"] + sizes["dmp_provider"]
        required = shared + slots * sizes["identity_slot"]
        self.assertEqual(slots, layout["counts"]["association"])
        self.assertGreaterEqual(layout["counts"]["association"] *
                                layout["bytes_each"]["association"], required)
        self.assertLess(layout["counts"]["association"] *
                        layout["bytes_each"]["association"] - required, slots)

    def test_budget_only_cli_preserves_unmeasured_lifecycle_but_checks_budget(self):
        data = good_measurement()
        for phase in data["phases"]:
            phase["status"] = "measured"
            phase["provider_retained_current_bytes"] = 0
            phase["provider_retained_peak_bytes"] = 0
            phase["provider_largest_single_allocation_bytes"] = 0
        data["workload"].update({
            "endpoint_runtime_status": "not_measured",
            "endpoint_runtime_reason": "provider-only source",
            "reconnect_overlap_status": "not_measured",
        })
        source_files = {
            "manifest.json": MANIFEST.read_bytes(),
            "measurement.json": json.dumps(data).encode("utf-8"),
        }

        class CaptureOutput(io.StringIO):
            def close(self):
                self.flush()

        output = CaptureOutput()

        def open_virtual(path, mode="r", *args, **kwargs):
            if mode == "rb":
                return io.BytesIO(source_files[str(path)])
            if mode == "w":
                return output
            raise AssertionError(f"unexpected open: {path}")

        argv = ["ram_report.py", "--manifest", "manifest.json", "--measurement", "measurement.json",
                "--output", "report.json", "--check-budget-only"]

        def run_cli():
            with (mock.patch.object(sys, "argv", argv), mock.patch("builtins.open", open_virtual),
                  contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
                return_code = ram_report.main()
            return return_code, json.loads(output.getvalue())

        return_code, report = run_cli()
        self.assertEqual(0, return_code)
        self.assertTrue(report["ok"])
        self.assertEqual("profile-budget-only", report["check_scope"])
        self.assertTrue(any("one-device endpoint lifecycle is not measured" in issue
                            for issue in report["issues"]))

        manifest = json.loads(source_files["manifest.json"])
        endpoint_resource = next(item for item in manifest["resources"] if item["role"] == "endpoint")
        next(row for row in endpoint_resource["charges"] if row["component"] == "provider_retained")["count"] = 2
        data = good_measurement()
        for phase in data["phases"]:
            phase.update({"status": "measured", "provider_retained_current_bytes": 0,
                          "provider_retained_peak_bytes": 1477,
                          "provider_largest_single_allocation_bytes": 256})
        data["workload"].update({
            "endpoint_runtime_status": "measured",
            "reconnect_overlap_status": "budgeted_not_measured",
        })
        source_files["manifest.json"] = json.dumps(manifest).encode("utf-8")
        source_files["measurement.json"] = json.dumps(data).encode("utf-8")
        output = CaptureOutput()
        return_code, report = run_cli()
        self.assertEqual(1, return_code)
        self.assertFalse(report["ok"])
        self.assertTrue(any("provider rotation charges do not cover" in issue
                            for issue in report["issues"]))

    def test_report_check_rejects_lifecycle_from_old_manifest_bytes(self):
        manifest = json.loads(MANIFEST_BYTES)
        endpoint = next(item for item in manifest["resources"] if item["role"] == "endpoint")
        association = next(row for row in endpoint["charges"] if row["component"] == "association")
        association["bytes_each"] += 1
        source_files = {
            "manifest.json": json.dumps(manifest).encode("utf-8"),
        }
        data = good_measurement()
        for phase in data["phases"]:
            phase.update({"status": "measured", "provider_retained_current_bytes": 0,
                          "provider_retained_peak_bytes": 0,
                          "provider_largest_single_allocation_bytes": 0,
                          "provider_largest_scratch_bytes": 0})
        source_files["measurement.json"] = json.dumps(data).encode("utf-8")

        class CaptureOutput(io.StringIO):
            def close(self):
                self.flush()

        output = CaptureOutput()

        def open_virtual(path, mode="r", *args, **kwargs):
            if mode == "rb":
                return io.BytesIO(source_files[str(path)])
            if mode == "w":
                return output
            raise AssertionError(f"unexpected open: {path} {mode}")

        argv = ["ram_report.py", "--manifest", "manifest.json", "--measurement", "measurement.json",
                "--output", "report.json", "--check"]
        with (mock.patch.object(sys, "argv", argv), mock.patch("builtins.open", open_virtual),
              contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
            return_code = ram_report.main()
        report = json.loads(output.getvalue())
        self.assertEqual(1, return_code)
        self.assertFalse(report["ok"])
        self.assertTrue(any("manifest digest does not match" in issue for issue in report["issues"]))

    def test_endpoint_merge_is_bound_and_checks_exact_exchange(self):
        manifest_raw = MANIFEST.read_bytes()
        manifest = json.loads(manifest_raw)
        manifest_hash = __import__("hashlib").sha256(manifest_raw).hexdigest()
        _, provider, _ = layout_inputs(set())
        endpoint = endpoint_runtime_measurement(manifest, manifest_hash)
        merged = ram_merge.merge(manifest_raw, manifest, provider, endpoint)
        self.assertEqual("measured", merged["workload"]["endpoint_runtime_status"])
        self.assertEqual("budgeted_not_measured", merged["workload"]["reconnect_overlap_status"])
        self.assertEqual(1477, merged["workload"]["one_device_provider_retained_peak_bytes"])
        self.assertEqual(1477, merged["objects"][0]["check_bytes"])
        layout = ram_layout.calculate(manifest, merged, layout_inputs(set())[2], manifest_hash)
        self.assertEqual(1477, layout["totals"]["host_one_association_provider_peak_observed_bytes"])

    def test_radio_endpoint_merge_requires_routed_freshness_lifecycle(self):
        manifest_raw = RADIO_MANIFEST.read_bytes()
        manifest = json.loads(manifest_raw)
        digest = __import__("hashlib").sha256(manifest_raw).hexdigest()
        _, provider, _ = layout_inputs(set())
        endpoint = endpoint_runtime_measurement(manifest, digest)
        merged = ram_merge.merge(manifest_raw, manifest, provider, endpoint)
        self.assertEqual("RADIO-1", merged["workload"]["endpoint_runtime_profile_id"])

        endpoint = endpoint_runtime_measurement(manifest, digest)
        retry = next(p for p in endpoint["phases"] if p["name"] == "request_result_retry")
        retry["origin_route_frames_valid"] -= 1
        with self.assertRaisesRegex(ram_report.Invalid, "verify every emitted and received origin route"):
            ram_merge.validate_endpoint_runtime(manifest, digest, endpoint)

        endpoint = endpoint_runtime_measurement(manifest, digest)
        retry = next(p for p in endpoint["phases"] if p["name"] == "request_result_retry")
        retry["freshness_token_bound_to_request"] = False
        with self.assertRaisesRegex(ram_report.Invalid, "complete and bind the manifest S7 freshness grant"):
            ram_merge.validate_endpoint_runtime(manifest, digest, endpoint)

    def test_endpoint_merge_uses_max_of_p01b_roles_and_phases(self):
        manifest_raw = MANIFEST.read_bytes()
        manifest = json.loads(manifest_raw)
        manifest_hash = __import__("hashlib").sha256(manifest_raw).hexdigest()
        _, provider, _ = layout_inputs(set())
        for phase in provider["side_measurements"][1]["provider_phases"]:
            phase["provider_retained_current_bytes"] = 0 if phase["name"] in {
                "provider_initial", "provider_cleanup"} else 900
            phase["provider_retained_peak_bytes"] = 0 if phase["name"] == "provider_initial" else 900
        endpoint = endpoint_runtime_measurement(manifest, manifest_hash)
        for phase in endpoint["phases"]:
            phase["caller_owned_requested_current_bytes"] = 5000
            phase["provider_retained_current_bytes"] = 0
            phase["provider_retained_peak_bytes"] = 1000
            phase["host_observed_requested_payload_high_water_bytes"] = 6500
        merged = ram_merge.merge(manifest_raw, manifest, provider, endpoint)
        self.assertEqual(1325, merged["workload"]["one_device_provider_retained_peak_bytes"])

    def test_endpoint_merge_requires_complete_retry_identity_and_reconnect_epochs(self):
        manifest_raw = MANIFEST.read_bytes()
        manifest = json.loads(manifest_raw)
        manifest_hash = __import__("hashlib").sha256(manifest_raw).hexdigest()
        _, provider, _ = layout_inputs(set())
        endpoint = endpoint_runtime_measurement(manifest, manifest_hash)
        retry = next(p for p in endpoint["phases"] if p["name"] == "request_result_retry")
        del retry["dropped_request_seq"]
        with self.assertRaisesRegex(ram_report.Invalid, "dropped request SEQ"):
            ram_merge.merge(manifest_raw, manifest, provider, endpoint)
        endpoint = endpoint_runtime_measurement(manifest, manifest_hash)
        retry = next(p for p in endpoint["phases"] if p["name"] == "request_result_retry")
        del retry["retry_request_fragment_index"]
        with self.assertRaisesRegex(ram_report.Invalid, "retry request fragment index"):
            ram_merge.merge(manifest_raw, manifest, provider, endpoint)
        endpoint = endpoint_runtime_measurement(manifest, manifest_hash)
        del endpoint["reconnect"]["prior_initiator_traffic_epoch"]
        with self.assertRaisesRegex(ram_report.Invalid, "prior initiator traffic epoch"):
            ram_merge.merge(manifest_raw, manifest, provider, endpoint)

    def test_endpoint_merge_rejects_digest_retry_or_short_result_mismatch(self):
        manifest_raw = MANIFEST.read_bytes()
        manifest = json.loads(manifest_raw)
        manifest_hash = __import__("hashlib").sha256(manifest_raw).hexdigest()
        _, provider, _ = layout_inputs(set())
        endpoint = endpoint_runtime_measurement(manifest, manifest_hash)
        endpoint["profile_digest_sha256"] = "0" * 64
        with self.assertRaisesRegex(ram_report.Invalid, "digest differs"):
            ram_merge.merge(manifest_raw, manifest, provider, endpoint)
        endpoint = endpoint_runtime_measurement(manifest, manifest_hash)
        retry = next(p for p in endpoint["phases"] if p["name"] == "request_result_retry")
        retry["retry_request_pn"] = retry["dropped_request_pn"]
        with self.assertRaisesRegex(ram_report.Invalid, "fresh PN"):
            ram_merge.merge(manifest_raw, manifest, provider, endpoint)
        endpoint = endpoint_runtime_measurement(manifest, manifest_hash)
        retry = next(p for p in endpoint["phases"] if p["name"] == "request_result_retry")
        retry["reliable_result_payload_matches"] = False
        with self.assertRaisesRegex(ram_report.Invalid, "result payload"):
            ram_merge.merge(manifest_raw, manifest, provider, endpoint)

    def test_missing_workload_is_invalid(self):
        data = good_measurement()
        del data["workload"]
        with self.assertRaisesRegex(ram_report.Invalid, "workload must be an object"):
            self.evaluate(data)

    def test_provider_phase_names_are_separate_from_endpoint_lifecycle(self):
        self.assertFalse(ram_report.PROVIDER_PHASES & ram_report.REQUIRED_PHASES)
        data = good_measurement()
        for phase in data["phases"]:
            phase["status"] = "measured"
            phase["provider_retained_current_bytes"] = 0
            phase["provider_retained_peak_bytes"] = 0
            phase["provider_largest_single_allocation_bytes"] = 0
        provider_phases = [
            {"name": name, "status": "measured",
             "provider_retained_current_bytes": 0,
             "provider_retained_peak_bytes": peak,
             "provider_largest_single_allocation_bytes": peak}
            for name, peak in zip(sorted(ram_report.PROVIDER_PHASES), range(1, 7))
        ]
        data["side_measurements"] = [
            {"role": role, "provider_phases": copy.deepcopy(provider_phases)}
            for role in ("initiator", "responder")
        ]
        self.assertEqual(6, ram_layout.checked_side_measurements(data))
        data["side_measurements"][0]["provider_phases"][0]["name"] = "request_result_retry"
        with self.assertRaisesRegex(ram_report.Invalid, "P01B provider phase"):
            ram_layout.checked_side_measurements(data)

    def test_layout_calculate_rejects_unmeasured_endpoint_phases_despite_workload_flags(self):
        cases = [
            set(ram_report.REQUIRED_PHASES),
            {"request_result_retry"},
        ]
        for unmeasured in cases:
            with self.subTest(unmeasured=unmeasured):
                manifest, measurement, mcu = layout_inputs(unmeasured)
                report = ram_layout.calculate(manifest, measurement, mcu,
                                              manifest_sha256_for_test(manifest))
                self.assertFalse(report["ok"])
                for phase_name in unmeasured:
                    self.assertIn(
                        f"required endpoint lifecycle phase {phase_name} is not measured",
                        report["issues"],
                    )

    def test_layout_calculate_rejects_stale_endpoint_manifest_digest_and_profile(self):
        manifest, measurement, mcu = layout_inputs(set())
        current_hash = manifest_sha256_for_test(manifest)
        measurement["workload"]["endpoint_runtime_manifest_digest_sha256"] = "old-digest"
        report = ram_layout.calculate(manifest, measurement, mcu, current_hash)
        self.assertFalse(report["ok"])
        self.assertTrue(any("manifest digest does not match" in issue for issue in report["issues"]))

        measurement["workload"]["endpoint_runtime_manifest_digest_sha256"] = current_hash
        measurement["workload"]["endpoint_runtime_profile_id"] = "stale-profile"
        report = ram_layout.calculate(manifest, measurement, mcu, current_hash)
        self.assertFalse(report["ok"])
        self.assertTrue(any("profile ID does not match" in issue for issue in report["issues"]))

    def test_layout_accepts_and_reports_conservative_manifest_charge_headroom(self):
        manifest, measurement, mcu = layout_inputs(set())
        baseline_hash = manifest_sha256_for_test(manifest)
        baseline = ram_layout.calculate(manifest, measurement, mcu, baseline_hash)
        resource = next(item for item in manifest["resources"] if item["role"] == "endpoint")
        for row in resource["charges"]:
            expected = baseline["expected_charges"].get(row["component"])
            if expected is not None:
                row["count"], row["bytes_each"] = expected
        provider = next(row for row in resource["charges"] if row["component"] == "provider_retained")
        provider["bytes_each"] += 152
        manifest_hash = manifest_sha256_for_test(manifest)
        measurement["workload"]["endpoint_runtime_manifest_digest_sha256"] = manifest_hash
        report = ram_layout.calculate(manifest, measurement, mcu, manifest_hash)
        self.assertTrue(report["ok"], report["issues"])
        self.assertFalse(report["charge_gaps"])
        headroom = next(row for row in report["charge_headroom"]
                        if row["component"] == "provider_retained")
        self.assertEqual(456, headroom["surplus_bytes"])
        self.assertEqual(456, report["totals"]["manifest_charge_headroom_bytes"])

    def test_layout_cli_check_rejects_unmeasured_endpoint_phases_despite_workload_flags(self):
        cases = [
            set(ram_report.REQUIRED_PHASES),
            {"handshake_peak"},
        ]
        for unmeasured in cases:
            with self.subTest(unmeasured=unmeasured):
                manifest, measurement, mcu = layout_inputs(unmeasured)
                manifest_raw = json.dumps(manifest).encode("utf-8")
                measurement["workload"]["endpoint_runtime_manifest_digest_sha256"] = hashlib.sha256(
                    manifest_raw).hexdigest()
                source_files = {
                    "manifest.json": manifest_raw,
                    "measurement.json": json.dumps(measurement).encode("utf-8"),
                    "mcu-abi.json": json.dumps(mcu).encode("utf-8"),
                }
                class CaptureOutput(io.StringIO):
                    def close(self):
                        self.flush()

                output = CaptureOutput()

                def open_virtual(path, mode="r", *args, **kwargs):
                    if mode == "rb":
                        return io.BytesIO(source_files[str(path)])
                    if mode == "w":
                        return output
                    raise AssertionError(f"unexpected open: {path} {mode}")

                argv = [
                    "ram_layout.py", "--manifest", "manifest.json",
                    "--measurement", "measurement.json", "--mcu-abi", "mcu-abi.json",
                    "--output", "layout-report.json", "--check",
                ]
                with (mock.patch.object(sys, "argv", argv),
                      mock.patch("builtins.open", open_virtual),
                      contextlib.redirect_stdout(io.StringIO()),
                      contextlib.redirect_stderr(io.StringIO())):
                    return_code = ram_layout.main()
                self.assertEqual(1, return_code)
                report = json.loads(output.getvalue())
                self.assertFalse(report["ok"])
                for phase_name in unmeasured:
                    self.assertIn(
                        f"required endpoint lifecycle phase {phase_name} is not measured",
                        report["issues"],
                    )

    def test_layout_cli_check_rejects_lifecycle_from_old_manifest_bytes(self):
        manifest, measurement, mcu = layout_inputs(set())
        endpoint = next(item for item in manifest["resources"] if item["role"] == "endpoint")
        association = next(row for row in endpoint["charges"] if row["component"] == "association")
        association["bytes_each"] += 1
        manifest_raw = json.dumps(manifest).encode("utf-8")
        source_files = {
            "manifest.json": manifest_raw,
            "measurement.json": json.dumps(measurement).encode("utf-8"),
            "mcu-abi.json": json.dumps(mcu).encode("utf-8"),
        }

        class CaptureOutput(io.StringIO):
            def close(self):
                self.flush()

        output = CaptureOutput()

        def open_virtual(path, mode="r", *args, **kwargs):
            if mode == "rb":
                return io.BytesIO(source_files[str(path)])
            if mode == "w":
                return output
            raise AssertionError(f"unexpected open: {path} {mode}")

        argv = ["ram_layout.py", "--manifest", "manifest.json", "--measurement", "measurement.json",
                "--mcu-abi", "mcu-abi.json", "--output", "layout-report.json", "--check"]
        with (mock.patch.object(sys, "argv", argv), mock.patch("builtins.open", open_virtual),
              contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO())):
            return_code = ram_layout.main()
        report = json.loads(output.getvalue())
        self.assertEqual(1, return_code)
        self.assertFalse(report["ok"])
        self.assertTrue(any("manifest digest does not match" in issue for issue in report["issues"]))

    def test_rejects_boolean_schema_device_count_and_overlap(self):
        data = good_measurement()
        data["schema_version"] = True
        with self.assertRaisesRegex(ram_report.Invalid, "schema_version"):
            self.evaluate(data)
        data = good_measurement()
        data["device_count"] = True
        with self.assertRaisesRegex(ram_report.Invalid, "exactly one device"):
            self.evaluate(data)
        data = good_measurement()
        data["objects"][0]["overlap"] = "false"
        with self.assertRaisesRegex(ram_report.Invalid, "overlap must be a boolean"):
            self.evaluate(data)

    def test_rejects_uncharged_object(self):
        data = good_measurement()
        data["objects"][0]["charge"] = None
        _, _, issues = self.evaluate(data)
        self.assertTrue(any("uncharged object" in issue for issue in issues))

    def test_rejects_charge_undercoverage(self):
        data = good_measurement()
        data["objects"][0]["check_bytes"] = CHARGES["provider_retained"] + 1
        _, _, issues = self.evaluate(data)
        self.assertTrue(any("undercovers" in issue for issue in issues))

    def test_rejects_physical_and_charged_over_fixed_limit(self):
        data = good_measurement()
        data["objects"][0]["physical_bytes"] = 131073
        _, _, issues = self.evaluate(data)
        self.assertTrue(any("physical total" in issue for issue in issues))
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        endpoint = next(item for item in manifest["resources"] if item["role"] == "endpoint")
        endpoint["charges"][0]["bytes_each"] = 131073
        _, _, issues = self.evaluate(good_measurement(), manifest)
        self.assertTrue(any("charged total" in issue for issue in issues))

    def test_rejects_missing_phase_and_invalid_data(self):
        data = good_measurement()
        data["phases"].pop()
        with self.assertRaisesRegex(ram_report.Invalid, "missing phases"):
            self.evaluate(data)
        data = good_measurement()
        data["objects"][0]["physical_bytes"] = -1
        with self.assertRaisesRegex(ram_report.Invalid, "nonnegative integer"):
            self.evaluate(data)

    def test_rejects_undeclared_overlap_and_duplicate_object(self):
        data = good_measurement()
        data["objects"][0]["overlap"] = True
        with self.assertRaisesRegex(ram_report.Invalid, "overlap_group"):
            self.evaluate(data)
        data = good_measurement()
        data["objects"].append(copy.deepcopy(data["objects"][0]))
        with self.assertRaisesRegex(ram_report.Invalid, "unique"):
            self.evaluate(data)


if __name__ == "__main__":
    unittest.main()
