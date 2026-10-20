"""Read-only drift checks and explicit regeneration for frozen profile hashes."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "generate_profile_digests.py"


class ProfileDigestGeneratorTests(unittest.TestCase):
    def setUp(self):
        build = ROOT / "build"
        build.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="dmp-digest-check-", dir=build)
        self.root = Path(self.temp.name)
        self.deployments = self.root / "profiles" / "deployments"
        self.deployments.mkdir(parents=True)
        (self.deployments / "alpha.json").write_bytes(b'{"id":"alpha"}\n')
        (self.deployments / "resource-inputs.json").write_text("{}\n", encoding="utf-8")
        self.index = self.deployments / "digests.json"
        self.valid = {
            "contract": "test",
            "manifests": {
                "alpha.json": hashlib.sha256((self.deployments / "alpha.json").read_bytes()).hexdigest()
            },
        }
        self.write_index(self.valid)

    def tearDown(self):
        self.temp.cleanup()

    def write_index(self, value):
        self.index.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def invoke(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_current_index_check_passes_without_writing(self):
        before = self.index.read_bytes()
        result = self.invoke("--check")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(before, self.index.read_bytes())

    def test_stale_index_check_fails_without_repairing_it(self):
        stale = json.loads(json.dumps(self.valid))
        stale["manifests"]["alpha.json"] = "0" * 64
        self.write_index(stale)
        before = self.index.read_bytes()
        result = self.invoke("--check")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("stale digest entries: alpha.json", result.stderr)
        self.assertEqual(before, self.index.read_bytes())

    def test_missing_and_extra_entries_are_rejected_without_writing(self):
        for manifests, expected_message in (
            ({}, "missing digest entries: alpha.json"),
            ({**self.valid["manifests"], "ghost.json": "f" * 64},
             "extra digest entries: ghost.json"),
        ):
            with self.subTest(expected_message=expected_message):
                self.write_index({"contract": "test", "manifests": manifests})
                before = self.index.read_bytes()
                result = self.invoke("--check")
                self.assertNotEqual(0, result.returncode)
                self.assertIn(expected_message, result.stderr)
                self.assertEqual(before, self.index.read_bytes())

    def test_explicit_regeneration_repairs_stale_index(self):
        stale = {"contract": "test", "manifests": {"alpha.json": "0" * 64}}
        self.write_index(stale)
        result = self.invoke()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(self.valid, json.loads(self.index.read_text(encoding="utf-8")))

    def test_unknown_argument_is_rejected_without_writing(self):
        before = self.index.read_bytes()
        result = self.invoke("--check", "--overwrite-quietly")
        self.assertEqual(2, result.returncode)
        self.assertIn("unrecognized arguments", result.stderr)
        self.assertEqual(before, self.index.read_bytes())


if __name__ == "__main__":
    unittest.main()
