from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import bench  # noqa: E402


class TestP24Benchmark(unittest.TestCase):
    def test_checked_in_profile_pairs_are_equivalent(self) -> None:
        for mode in ("nnpsk0", "xx"):
            with self.subTest(mode=mode):
                radio, retry_all = bench.load_profile_pair(mode)
                comparison = bench.validate_profile_pair(
                    radio["values"], retry_all["values"]
                )
                fields = {item["field"] for item in comparison["allowed_differences"]}
                self.assertIn("profile/id", fields)
                self.assertIn("services/1/recovery", fields)
                self.assertIn("timing/max_probes", fields)
                self.assertIn("timing/max_status", fields)
                self.assertNotEqual(radio["digest"], retry_all["digest"])

    def test_profile_pair_rejects_common_workload_drift(self) -> None:
        radio, retry_all = bench.load_profile_pair("nnpsk0")
        retry_values = json.loads(json.dumps(retry_all["values"]))
        retry_values["binding"]["forward_mtu"] += 1
        with self.assertRaisesRegex(ValueError, "outside the P03 comparison allowlist"):
            bench.validate_profile_pair(radio["values"], retry_values)

    def test_metrics_count_endpoint_and_relay_transmissions(self) -> None:
        profile = bench.load_profile_pair("nnpsk0")[0]["values"]
        metrics = bench._P24Metrics(profile)
        parsed = SimpleNamespace(message_type=7, sequence=11, fragment=SimpleNamespace(index=2))
        metrics.endpoint_tx(10, b"frame", parsed)
        metrics.relay_tx(30, b"frame", parsed)
        metrics.dropped(10, 2)
        report = metrics.report()["cold_setup"]
        self.assertEqual(report["frame_attempts"], 2)
        self.assertEqual(report["core_frame_bytes"], 10)
        self.assertEqual(report["modeled_airtime_ms"], 2)
        self.assertEqual(report["nodes"]["10"]["fragment_indices"], {"2": 1})
        self.assertEqual(report["nodes"]["30"]["role"], "relay")
        self.assertEqual(report["dropped_fragments"][0]["fragment_index"], 2)

    @unittest.skipUnless(
        os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
        "P23 C endpoint executable is not configured",
    )
    def test_cli_runs_paired_real_endpoint_smoke(self) -> None:
        endpoint = Path(os.environ["DMP_P23_ENDPOINT_SEC_EXE"])
        self.assertTrue(endpoint.is_file())
        output = ROOT / "build" / "host" / "p24-smoke-report.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "bench.py"),
                "--modes", "nnpsk0",
                "--sizes", "64",
                "--iterations", "1",
                "--seed", "9216",
                "--output", str(output),
            ],
            cwd=ROOT,
            env=os.environ.copy(),
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["schema"], "DMP-P24-BENCH/1")
        self.assertEqual(report["failure_count"], 0)
        self.assertEqual(len(report["samples"]), 2)
        selective, retry = report["samples"]
        self.assertTrue(selective["passed"] and retry["passed"])
        self.assertEqual(selective["payload_sha256"], retry["payload_sha256"])
        self.assertEqual(selective["workload_sha256"], retry["workload_sha256"])
        self.assertEqual(selective["repair_fragment_indices"], [0])
        self.assertEqual(retry["repair_fragment_indices"], [0, 1])
        self.assertEqual(selective["fresh_associations"], 1)
        self.assertIn("cold_setup", selective["phase_virtual_ms"])
        self.assertIn("warm_exchange", selective["phase_measurements"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
