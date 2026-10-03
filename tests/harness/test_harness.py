"""Subprocess checks for the P07 C harness. Python only drives the executable."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
EXE = Path(sys.argv[1])
CORPUS = json.loads((ROOT / "tests" / "profiles" / "invalid.json").read_text(encoding="utf-8"))
FIXTURES = ROOT / "tests" / "profiles" / "fixtures"
DEPLOYMENTS = ROOT / "profiles" / "deployments"


def scenario(sha, actions=None, faults=None, **overrides):
    body = {
        "interface_version": 1,
        "mode": "transport-selftest",
        "manifest_sha256": sha,
        "seed": "00000001",
        "until_ms": 1000,
        "stress": False,
        "loss_threshold": 0,
        "actions": actions or [],
        "faults": faults or [],
    }
    body.update(overrides)
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def run(args, payload=b"", manifest=None):
    command = [str(EXE), *args]
    if manifest is not None:
        command.extend(["--manifest", str(manifest)])
    return subprocess.run(command, input=payload, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)


def mutate(document, operations):
    value = json.loads(json.dumps(document))
    for operation in operations:
        path = operation["path"].strip("/").split("/")
        parent = value
        for part in path[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        key = path[-1]
        if operation["op"] == "remove":
            if isinstance(parent, list):
                parent.pop(int(key))
            else:
                del parent[key]
        elif operation["op"] == "add":
            parent[key] = operation["value"]
        elif isinstance(parent, list):
            parent[int(key)] = operation["value"]
        else:
            parent[key] = operation["value"]
    return value


def raw_case(case):
    if "hex" in case:
        return bytes.fromhex(case["hex"])
    if "ascii" in case:
        return case["ascii"].encode("ascii")
    if "repeat_prefix_hex" in case:
        prefix = bytes.fromhex(case["repeat_prefix_hex"]) * case["repeat"]
        suffix = bytes.fromhex(case["repeat_suffix_hex"]) * case["repeat"]
        return prefix + case.get("middle_ascii", "").encode("ascii") + suffix
    if "repeat_hex" in case:
        return bytes.fromhex(case["repeat_hex"]) * case["repeat"]
    raise AssertionError("unknown corpus encoding")


class HarnessSubprocessTests(unittest.TestCase):
    def test_interface_version_and_cli_rejection(self):
        version = run(["--interface-version"])
        self.assertEqual(version.returncode, 0)
        self.assertEqual(version.stdout, b"1\n")
        self.assertEqual(version.stderr, b"")
        repeated = run(["--interface-version", "--interface-version"])
        self.assertEqual(repeated.returncode, 2)
        self.assertIn(b"E_CLI", repeated.stderr)
        unknown = run(["--debug"])
        self.assertEqual(unknown.returncode, 2)
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        broken = subprocess.Popen(
            [str(EXE), "--interface-version"],
            stdin=subprocess.DEVNULL, stdout=write_fd, stderr=subprocess.PIPE)
        os.close(write_fd)
        _ignored, err = broken.communicate(timeout=30)
        self.assertEqual(broken.returncode, 4, err)

    def test_repeatable_trace_hides_payload(self):
        manifest = DEPLOYMENTS / "direct-nnpsk0.json"
        raw = manifest.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        payload = scenario(digest, [{
            "at_ms": 0, "op": "submit", "link": 0, "id": 1, "data_hex": "0badf00d",
            "not_after_ms": 1000, "reply_to": 0, "return_slot": 0
        }])
        first = run([], payload, manifest)
        second = run([], payload, manifest)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        text = first.stdout.decode("utf-8")
        self.assertNotIn("0badf00d", text)
        self.assertNotIn("0badf00d", first.stderr.decode("utf-8", "replace"))
        lines = text.splitlines()
        self.assertTrue(lines[-1].startswith('{"seq":'))
        end = json.loads(lines[-1])
        self.assertEqual(end["event"], "run_end")
        self.assertEqual(end["outcome"], "completed")
        self.assertEqual(end["exit_code"], 0)
        self.assertEqual(end["accepted"], 1)
        self.assertEqual(end["delivered"], 1)

    def test_malformed_scenario_is_only_a_terminal_record(self):
        manifest = DEPLOYMENTS / "direct-nnpsk0.json"
        cases = [
            b"\xef\xbb\xbf{}",
            b'{"interface_version":1.5}',
            b'{"a":1,"a":2}',
            b'{"interface_version":1} trailing',
            ('{"interface_version":1,"mode":"transport-selftest","manifest_sha256":"' + ("0" * 64) +
             '","seed":"00000001","until_ms":1,"stress":false,"loss_threshold":0,"actions":[],"faults":[],"extra":1}').encode(),
        ]
        for payload in cases:
            with self.subTest(payload=payload[:24]):
                result = run([], payload, manifest)
                self.assertEqual(result.returncode, 2)
                lines = result.stdout.splitlines()
                self.assertEqual(len(lines), 1)
                end = json.loads(lines[0])
                self.assertEqual(end["seq"], 0)
                self.assertEqual(end["outcome"], "invalid_input")
                self.assertFalse(end["stress"])

    def test_manifest_corpus_codes_match(self):
        for case in CORPUS["mutation_cases"]:
            with self.subTest(case=case["name"]):
                source = json.loads((FIXTURES / case["fixture"]).read_text(encoding="utf-8"))
                raw = json.dumps(mutate(source, case["mutations"]), separators=(",", ":")).encode()
                self.assert_manifest_code(raw, case["expected_code"], case["expected_path"])
        for case in CORPUS["raw_cases"]:
            with self.subTest(case=case["name"]):
                self.assert_manifest_code(raw_case(case), case["expected_code"], case["expected_path"])

    def assert_manifest_code(self, raw, code, path):
        digest = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "manifest.json"
            manifest.write_bytes(raw)
            result = run([], scenario(digest), manifest)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(f"code={code}".encode(), result.stderr)
        self.assertIn(f"path={path}".encode(), result.stderr)
        end = json.loads(result.stdout.splitlines()[-1])
        self.assertEqual(end["outcome"], "invalid_input")

    def test_digest_mismatch_and_valid_deployments(self):
        for name in ("direct-nnpsk0.json", "direct-xx.json", "radio-nnpsk0.json",
                     "radio-xx.json", "test-radio-retry-all-nnpsk0.json",
                     "test-radio-retry-all-xx.json"):
            with self.subTest(deployment=name):
                raw = (DEPLOYMENTS / name).read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                good = run([], scenario(digest), DEPLOYMENTS / name)
                self.assertEqual(good.returncode, 0, good.stderr)
                bad = run([], scenario("0" * 64), DEPLOYMENTS / name)
                self.assertEqual(bad.returncode, 2)
                self.assertIn(b"code=digest", bad.stderr)

    def test_pair_schedule_and_same_time_tie(self):
        manifest = DEPLOYMENTS / "direct-nnpsk0.json"
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        actions = [
            {"at_ms": 0, "op": "submit", "link": 0, "id": 1, "data_hex": "aa",
             "not_after_ms": 1000, "reply_to": 0, "return_slot": 0},
            {"at_ms": 0, "op": "submit", "link": 1, "id": 2, "data_hex": "bb",
             "not_after_ms": 1000, "reply_to": 0, "return_slot": 0},
            {"at_ms": 22, "op": "submit", "link": 1, "id": 3, "data_hex": "cc",
             "not_after_ms": 1000, "reply_to": 1, "return_slot": 1},
        ]
        result = run([], scenario(digest, actions), manifest)
        self.assertEqual(result.returncode, 0, result.stderr)
        text = result.stdout.decode()
        self.assertIn('"id":1,"link":0,"bytes":1,"status":"ok","slot":1,"generation":"0000000000000001"', text)
        self.assertLess(text.index('"id":1,'), text.index('"id":2,'))
        end = json.loads(text.splitlines()[-1])
        self.assertEqual(end["accepted"], 3)

    def offline_failure(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_bytes(raw)
            proc = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "validate_profile.py"), str(path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        body = json.loads(proc.stdout.decode("utf-8"))
        self.assertFalse(body["valid"])
        return body["code"], body["path"]

    def test_embedded_nul_matches_offline_profile_boundary(self):
        raw = (DEPLOYMENTS / "direct-nnpsk0.json").read_bytes()
        cases = {
            "enum": raw.replace(b'"id": "DIRECT-1"', b'"id": "DIRECT-1\\u0000"', 1),
            "key": raw.replace(b'"id": "DIRECT-1"', b'"id\\u0000": "DIRECT-1"', 1),
            "identifier": raw.replace(b'"id": "RAM"', b'"id": "\\u0000"', 1),
        }
        for name, mutated in cases.items():
            with self.subTest(case=name):
                self.assertNotEqual(mutated, raw)
                code, path = self.offline_failure(mutated)
                self.assertEqual(code, "schema")
                self.assert_manifest_code(mutated, code, path)

    def test_embedded_nul_rejects_scenario_fields(self):
        manifest = DEPLOYMENTS / "direct-nnpsk0.json"
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        base = scenario(digest, [{
            "at_ms": 0, "op": "submit", "link": 0, "id": 1, "data_hex": "aa",
            "not_after_ms": 1000, "reply_to": 0, "return_slot": 0
        }])
        mutations = [
            (b'"mode":"transport-selftest"', b'"mode":"transport-selftest\\u0000"'),
            (b'"op":"submit"', b'"op":"submit\\u0000"'),
            (b'"id":1', b'"id\\u0000":1'),
            (b'"data_hex":"aa"', b'"data_hex":"aa\\u0000"'),
        ]
        for old, new in mutations:
            with self.subTest(old=old):
                payload = base.replace(old, new, 1)
                self.assertNotEqual(payload, base)
                result = run([], payload, manifest)
                self.assertEqual(result.returncode, 2, result.stderr)
                end = json.loads(result.stdout.splitlines()[-1])
                self.assertEqual(end["outcome"], "invalid_input")
                self.assertEqual(end["exit_code"], 2)

    def test_cancel_uses_schedule_order_not_array_position(self):
        manifest = DEPLOYMENTS / "direct-nnpsk0.json"
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        submit = {
            "at_ms": 0, "op": "submit", "link": 0, "id": 1, "data_hex": "aa",
            "not_after_ms": 1000, "reply_to": 0, "return_slot": 0
        }
        accepted = run([], scenario(digest, [
            {"at_ms": 10, "op": "cancel", "id": 1},
            submit,
        ]), manifest)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        end = json.loads(accepted.stdout.splitlines()[-1])
        self.assertEqual(end["outcome"], "completed")
        self.assertEqual(end["exit_code"], 0)
        self.assertIn(b'"event":"submit"', accepted.stdout)

        tied = run([], scenario(digest, [
            {"at_ms": 0, "op": "cancel", "id": 1},
            submit,
        ]), manifest)
        self.assertEqual(tied.returncode, 2)
        later_submit = dict(submit)
        later_submit["at_ms"] = 10
        earlier = run([], scenario(digest, [
            {"at_ms": 0, "op": "cancel", "id": 1},
            later_submit,
        ]), manifest)
        self.assertEqual(earlier.returncode, 2)

    def test_early_io_failures_are_process_failures(self):
        manifest = DEPLOYMENTS / "direct-nnpsk0.json"
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        broken = subprocess.Popen(
            [str(EXE), "--manifest", str(manifest)],
            stdin=subprocess.PIPE, stdout=write_fd, stderr=subprocess.PIPE)
        os.close(write_fd)
        _ignored, err = broken.communicate(b"{", timeout=30)
        self.assertEqual(broken.returncode, 4, err)

        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        unread = subprocess.Popen(
            [str(EXE), "--manifest", str(manifest)],
            stdin=write_fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(write_fd)
        out, err = unread.communicate(timeout=30)
        self.assertEqual(unread.returncode, 4, err)
        self.assertNotIn(b"invalid_input", out)
        self.assertNotIn(b'"outcome":"completed"', out)
        self.assertTrue(out.strip())
        end = json.loads(out.splitlines()[-1])
        self.assertEqual(end["outcome"], "internal_error")
        self.assertEqual(end["exit_code"], 4)

        empty = run([], b"", manifest)
        self.assertEqual(empty.returncode, 2)
        end = json.loads(empty.stdout.splitlines()[-1])
        self.assertEqual(end["outcome"], "invalid_input")
        self.assertEqual(end["exit_code"], 2)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
