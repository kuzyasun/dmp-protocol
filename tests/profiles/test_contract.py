"""Contract tests for the P02 offline manifest validator."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests" / "profiles"
FIXTURES = TESTS / "fixtures"
sys.path.insert(0, str(ROOT / "tools"))
import validate_profile as validator  # noqa: E402


def _read_fixture(name):
    return (FIXTURES / name).read_bytes()


def _mutate(document, operations):
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


def _raw_case(case):
    if "hex" in case:
        return bytes.fromhex(case["hex"])
    if "ascii" in case:
        return case["ascii"].encode("ascii")
    if "repeat_prefix_hex" in case:
        prefix = bytes.fromhex(case["repeat_prefix_hex"]) * case["repeat"]
        suffix = bytes.fromhex(case["repeat_suffix_hex"]) * case["repeat"]
        return prefix + case.get("middle_ascii", "").encode("ascii") + suffix
    if "repeat_hex" in case:
        repeated = bytes.fromhex(case["repeat_hex"]) * case["repeat"]
        return (repeated + case.get("middle_ascii", "").encode("ascii") +
                bytes.fromhex(case.get("suffix_hex", "")))
    raise AssertionError("unknown raw corpus encoding")


class ManifestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads((TESTS / "invalid.json").read_text(encoding="utf-8"))

    def test_three_frozen_fixtures_have_independent_expected_bounds(self):
        expected = json.loads((TESTS / "expected.json").read_text(encoding="utf-8"))
        for filename, bounds in expected["fixtures"].items():
            with self.subTest(fixture=filename):
                raw = _read_fixture(filename)
                result = validator.validate_bytes(raw)
                self.assertTrue(result["valid"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), result["sha256"])
                self.assertEqual(result["sha256"], bounds["sha256"])
                self.assertEqual(bounds["derived"], result["derived"])

    def test_fixture_source_and_schema_are_reproducible(self):
        fixture_module = importlib.util.spec_from_file_location(
            "profile_fixture_generator", TESTS / "make_fixtures.py")
        generator = importlib.util.module_from_spec(fixture_module)
        fixture_module.loader.exec_module(generator)
        for kind, filename in (("direct", "direct.json"), ("radio", "radio.json"),
                               ("test-radio-retry-all", "test-radio-retry-all.json")):
            with self.subTest(fixture=filename):
                actual = json.loads(_read_fixture(filename))
                self.assertEqual(generator.manifest(kind), actual)

        schema_module = importlib.util.spec_from_file_location(
            "profile_schema_generator", ROOT / "profiles" / "schema" / "build_schema.py")
        schema_generator = importlib.util.module_from_spec(schema_module)
        schema_module.loader.exec_module(schema_generator)
        generated = json.dumps(schema_generator.SCHEMA, indent=2) + "\n"
        self.assertEqual(generated, (ROOT / "profiles/schema/manifest-v2.schema.json").read_text(encoding="utf-8"))

    def test_mutation_corpus_rejects_contract_violations_at_declared_location(self):
        self.assertGreaterEqual(len(self.corpus["mutation_cases"]), 31)
        for case in self.corpus["mutation_cases"]:
            with self.subTest(case=case["name"]):
                source = json.loads(_read_fixture(case["fixture"]))
                raw = json.dumps(_mutate(source, case["mutations"]), separators=(",", ":")).encode()
                with self.assertRaises(validator.ProfileError) as raised:
                    validator.validate_bytes(raw)
                self.assertEqual(case["expected_code"], raised.exception.code)
                self.assertEqual(case["expected_path"], raised.exception.path)

    def test_raw_input_corpus(self):
        self.assertGreaterEqual(len(self.corpus["raw_cases"]), 15)
        for case in self.corpus["raw_cases"]:
            with self.subTest(case=case["name"]):
                with self.assertRaises(validator.ProfileError) as raised:
                    validator.validate_bytes(_raw_case(case))
                self.assertEqual(case["expected_code"], raised.exception.code)
                self.assertEqual(case["expected_path"], raised.exception.path)

    def test_frame_timing_freshness_and_pool_boundaries(self):
        radio = validator.validate_bytes(_read_fixture("radio.json"))["derived"]
        direct = validator.validate_bytes(_read_fixture("direct.json"))["derived"]
        self.assertEqual(102, radio["app_frame_bytes"])
        self.assertEqual(86, direct["bootstrap_frame_bytes"])
        self.assertEqual(263, direct["encoded_frame_bytes"])
        self.assertEqual(430, radio["response_floor_ms"])
        self.assertEqual(1144, radio["freshness_required_ms"])
        self.assertEqual(5689, radio["ram_reserved_bytes"]["endpoint"]["RAM"])
        self.assertEqual(2317, radio["ram_reserved_bytes"]["relay"]["RAM"])

    def test_grant_result_pool_has_independent_21_byte_floor(self):
        radio = json.loads(_read_fixture("radio.json"))
        small_message = _mutate(radio, [
            {"op": "set", "path": "/limits/message_bytes", "value": 17},
            {"op": "set", "path": "/services/1/request_bytes", "value": 17},
            {"op": "set", "path": "/services/1/result_bytes", "value": 17},
            {"op": "set", "path": "/resources/0/charges/7/bytes_each", "value": 20},
        ])
        with self.assertRaises(validator.ProfileError) as raised:
            validator.validate_bytes(json.dumps(small_message, separators=(",", ":")).encode())
        self.assertEqual("resources", raised.exception.code)
        self.assertEqual("$.resources[endpoint].result", raised.exception.path)

        small_message["resources"][0]["charges"][7]["bytes_each"] = 21
        self.assertTrue(validator.validate_bytes(
            json.dumps(small_message, separators=(",", ":")).encode())["valid"])

    def test_assembly_expiry_tombstones_are_reserved_and_funded(self):
        direct = json.loads(_read_fixture("direct.json"))
        under_reserved = _mutate(direct, [
            {"op": "set", "path": "/limits/assembly_tombstones_per_peer", "value": 0},
        ])
        with self.assertRaises(validator.ProfileError) as raised:
            validator.validate_bytes(json.dumps(under_reserved, separators=(",", ":")).encode())
        self.assertEqual("schema", raised.exception.code)

        underfunded = _mutate(direct, [
            {"op": "set", "path": "/resources/0/charges/6/count", "value": 15},
        ])
        with self.assertRaises(validator.ProfileError) as raised:
            validator.validate_bytes(json.dumps(underfunded, separators=(",", ":")).encode())
        self.assertEqual("resources", raised.exception.code)
        self.assertEqual("$.resources[endpoint].assembly_tombstone", raised.exception.path)

    def test_exact_bootstrap_frame_boundary_and_reverse_selective_timing_term(self):
        direct = json.loads(_read_fixture("direct.json"))
        boundary = _mutate(direct, [
            {"op": "set", "path": "/limits/bootstrap_chunk_bytes", "value": 119},
            {"op": "set", "path": "/binding/forward_mtu", "value": 145},
            {"op": "set", "path": "/binding/return_mtu", "value": 145},
            {"op": "set", "path": "/binding/encoded_mtu", "value": 151},
        ])
        result = validator.validate_bytes(json.dumps(boundary, separators=(",", ":")).encode())
        self.assertEqual(145, result["derived"]["bootstrap_frame_bytes"])
        self.assertEqual(151, result["derived"]["encoded_frame_bytes"])

        radio = json.loads(_read_fixture("radio.json"))
        # F=19/R=20 makes the reverse selective term 429 ms; the forward term is 428 ms.
        skewed = _mutate(radio, [
            {"op": "set", "path": "/timing/forward_delay_ms", "value": 19},
            {"op": "set", "path": "/timing/response_timeout_ms", "value": 428},
        ])
        with self.assertRaises(validator.ProfileError) as raised:
            validator.validate_bytes(json.dumps(skewed, separators=(",", ":")).encode())
        self.assertEqual("timing", raised.exception.code)
        self.assertEqual("$.timing.response_timeout_ms", raised.exception.path)
        skewed["timing"]["response_timeout_ms"] = 429
        self.assertEqual(429, validator.validate_bytes(
            json.dumps(skewed, separators=(",", ":")).encode())["derived"]["response_floor_ms"])

    def test_digest_covers_exact_whitespace_and_expected_hash_format(self):
        original = _read_fixture("direct.json")
        whitespace_variant = b" " + original
        original_hash = hashlib.sha256(original).hexdigest()
        variant_hash = hashlib.sha256(whitespace_variant).hexdigest()
        self.assertNotEqual(original_hash, variant_hash)
        self.assertEqual(variant_hash, validator.validate_bytes(whitespace_variant, variant_hash)["sha256"])
        for wrong in (original_hash, "A" * 64, "0" * 63, None):
            if wrong is None:
                continue
            with self.subTest(expected=wrong):
                with self.assertRaises(validator.ProfileError) as raised:
                    validator.validate_bytes(whitespace_variant, wrong)
                self.assertEqual("digest", raised.exception.code)
                self.assertEqual("$", raised.exception.path)

    def test_xx_confirmation_reserves_cached_flight_three_and_its_budget(self):
        direct = json.loads(_read_fixture("direct.json"))
        xx = _mutate(direct, [
            {"op": "set", "path": "/security/mode", "value": "XX"},
            {"op": "set", "path": "/security/credential", "value": "authenticated-oob-xx"},
            {"op": "set", "path": "/security/confirmation_timeout_ms", "value": 448},
        ])
        result = validator.validate_bytes(json.dumps(xx, separators=(",", ":")).encode())
        self.assertEqual(22, result["derived"]["establishment_frame_reserve"])
        self.assertEqual(5786, result["derived"]["establishment_wire_bytes"])
        self.assertEqual(15388, result["derived"]["establishment_ms"])

        underfunded = _mutate(xx, [
            {"op": "set", "path": "/security/attempt_tx_bytes", "value": 5785},
        ])
        with self.assertRaises(validator.ProfileError) as raised:
            validator.validate_bytes(json.dumps(underfunded, separators=(",", ":")).encode())
        self.assertEqual("security", raised.exception.code)
        self.assertEqual("$.security", raised.exception.path)

    def test_cli_reports_valid_digest_and_rejects_bad_expected_digest(self):
        path = FIXTURES / "direct.json"
        command = [sys.executable, str(ROOT / "tools" / "validate_profile.py"), str(path)]
        good = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(0, good.returncode, good.stderr)
        payload = json.loads(good.stdout)
        self.assertTrue(payload["valid"])
        bad = subprocess.run(command + ["--expect-sha256", "0" * 64],
                             capture_output=True, text=True, check=False)
        self.assertEqual(1, bad.returncode)
        error = json.loads(bad.stdout)
        self.assertEqual({"valid": False, "code": "digest", "path": "$"},
                         {key: error[key] for key in ("valid", "code", "path")})
        missing = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "validate_profile.py"),
             str(TESTS / "no-such-manifest.json")],
            capture_output=True, text=True, check=False)
        self.assertEqual(1, missing.returncode)
        io_error = json.loads(missing.stdout)
        self.assertEqual({"valid": False, "code": "io", "path": "$"},
                         {key: io_error[key] for key in ("valid", "code", "path")})


if __name__ == "__main__":
    unittest.main()
