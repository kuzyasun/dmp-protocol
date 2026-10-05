import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "profiles" / "deployments" / "direct-nnpsk0.json"
sys.path.insert(0, str(ROOT / "tools"))
import ram_report
import ram_layout
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
            "reconnect_overlap_status": "measured",
        },
    }


class RamReportTests(unittest.TestCase):
    def evaluate(self, measurement, manifest=None):
        if manifest is None:
            with MANIFEST.open(encoding="utf-8") as stream:
                manifest = json.load(stream)
        return ram_report.evaluate(manifest, measurement)

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
        self.assertTrue(any("reconnect overlap is not measured" in issue for issue in issues))

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
