"""Contract-3 host binding validation and mixed-profile boundaries."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENTS = ROOT / "profiles" / "deployments"
SCHEMA_DIR = ROOT / "profiles" / "schema"
sys.path.insert(0, str(ROOT / "tools"))
import validate_profile as validator  # noqa: E402


DIRECT = "test-peer-tcp-stream-r-nnpsk0.json"
MIXED = "test-mixed-tcp-stream-r-sim-packet-nnpsk0.json"


class Contract3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.digests = json.loads((DEPLOYMENTS / "digests.json").read_text(encoding="utf-8"))["manifests"]
        cls.raw = {name: (DEPLOYMENTS / name).read_bytes() for name in (DIRECT, MIXED)}
        cls.values = {name: json.loads(raw) for name, raw in cls.raw.items()}

    @staticmethod
    def encoded(value):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def assert_rejected(self, value, code, path=None):
        with self.assertRaises(validator.ProfileError) as raised:
            validator.validate_bytes(self.encoded(value))
        self.assertEqual(code, raised.exception.code)
        if path is not None:
            self.assertEqual(path, raised.exception.path)

    def test_frozen_v3_manifests_match_exact_digests_and_independent_bounds(self):
        expected = {
            DIRECT: ("PEER-TCP-STREAM-R", 16, 263, 60488),
            MIXED: ("MIXED-TCP-STREAM-R-SIM-PACKET", 32, 256, 67180),
        }
        for name, (profile_id, fragments, encoded, endpoint_ram) in expected.items():
            with self.subTest(manifest=name):
                raw = self.raw[name]
                digest = self.digests[name]
                self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
                result = validator.validate_bytes(raw, digest)
                self.assertTrue(result["valid"])
                self.assertEqual(profile_id, self.values[name]["profile"]["id"])
                self.assertEqual(fragments, result["derived"]["fragment_count"])
                if name == DIRECT:
                    self.assertEqual(encoded, result["derived"]["encoded_frame_bytes"])
                    self.assertEqual(endpoint_ram, result["derived"]["ram_reserved_bytes"]["endpoint"]["RAM"])
                else:
                    self.assertEqual(encoded, self.values[name]["binding"]["encoded_mtu"])
                    self.assertEqual(263, self.values[name]["tcp_binding"]["encoded_mtu"])
                    self.assertEqual(endpoint_ram, result["derived"]["ram_reserved_bytes"]["endpoint"]["RAM"])
                    self.assertEqual(29441, result["derived"]["ram_reserved_bytes"]["relay"]["RAM"])

    def test_v3_schema_is_generated_and_v2_schema_bytes_are_stable(self):
        module_spec = importlib.util.spec_from_file_location(
            "profile_schema_generator", SCHEMA_DIR / "build_schema.py")
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        self.assertEqual(json.dumps(module.SCHEMA, indent=2) + "\n",
                         (SCHEMA_DIR / "manifest-v2.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(json.dumps(module.SCHEMA_V3, indent=2) + "\n",
                         (SCHEMA_DIR / "manifest-v3.schema.json").read_text(encoding="utf-8"))

    def test_tcp_roles_caps_and_absolute_timeout_fail_closed(self):
        direct = self.values[DIRECT]
        wrong_placement = copy.deepcopy(direct)
        wrong_placement["tcp_binding"]["placement"] = "endpoint-to-relay"
        self.assert_rejected(wrong_placement, "profile", "$.tcp_binding")

        duplicate_role = copy.deepcopy(direct)
        duplicate_role["tcp_binding"]["listener_node"] = direct["identity"]["nodes"][0]
        self.assert_rejected(duplicate_role, "profile", "$.tcp_binding")

        short_timeout = copy.deepcopy(direct)
        short_timeout["tcp_binding"]["partial_candidate_timeout_ms"] -= 1
        self.assert_rejected(short_timeout, "timing", "$.tcp_binding.partial_candidate_timeout_ms")

        short_encoded_cap = copy.deepcopy(direct)
        short_encoded_cap["tcp_binding"]["encoded_mtu"] = 262
        self.assert_rejected(short_encoded_cap, "mtu", "$.tcp_binding.encoded_mtu")

    def test_mixed_topology_and_capacity_fail_closed(self):
        mixed = self.values[MIXED]
        missing = copy.deepcopy(mixed)
        del missing["mixed_path"]
        self.assert_rejected(missing, "profile", "$.mixed_path")

        wrong_listener = copy.deepcopy(mixed)
        wrong_listener["tcp_binding"]["listener_node"] = mixed["identity"]["nodes"][1]
        self.assert_rejected(wrong_listener, "route", "$.mixed_path")

        wrong_return_route = copy.deepcopy(mixed)
        wrong_return_route["mixed_path"]["return_relays"] = [30, 40]
        self.assert_rejected(wrong_return_route, "route", "$.mixed_path")

        wrong_context_policy = copy.deepcopy(mixed)
        wrong_context_policy["mixed_path"]["context_policy"] = "bridge-adds-context"
        self.assert_rejected(wrong_context_policy, "schema", "$.mixed_path.context_policy")

        short_packet_egress = copy.deepcopy(mixed)
        short_packet_egress["binding"]["return_mtu"] = 255
        self.assert_rejected(short_packet_egress, "mtu")

        underfunded_control = copy.deepcopy(mixed)
        endpoint = next(r for r in underfunded_control["resources"] if r["role"] == "endpoint")
        next(c for c in endpoint["charges"] if c["component"] == "control")["bytes_each"] = 262
        self.assert_rejected(underfunded_control, "resources", "$.resources[endpoint].control")

    def test_unknown_profiles_fields_and_digest_mismatch_are_rejected(self):
        direct = copy.deepcopy(self.values[DIRECT])
        direct["profile"]["id"] = "DIRECT-1"
        self.assert_rejected(direct, "schema", "$.profile.id")

        extra = copy.deepcopy(self.values[MIXED])
        extra["mixed_path"]["silent_fallback"] = True
        self.assert_rejected(extra, "schema", "$.mixed_path")

        raw = self.raw[DIRECT] + b" "
        with self.assertRaises(validator.ProfileError) as raised:
            validator.validate_bytes(raw, self.digests[DIRECT])
        self.assertEqual("digest", raised.exception.code)
        self.assertEqual("$", raised.exception.path)

    def test_non_string_contract_marker_uses_structured_schema_error(self):
        for marker in ([], {}):
            with self.subTest(marker=marker):
                malformed = {"contract": marker}
                self.assert_rejected(malformed, "schema", "$.contract")


if __name__ == "__main__":
    unittest.main()
