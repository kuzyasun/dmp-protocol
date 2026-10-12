import copy
import json
import unittest
from pathlib import Path

from dmp_peer.manifest import ManifestError, identify_frozen_manifest, load_manifest, parse_manifest


DEPLOYMENTS = Path(__file__).parents[3] / "profiles" / "deployments"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class ManifestV3Tests(unittest.TestCase):
    def read(self, name):
        return json.loads((DEPLOYMENTS / name).read_bytes())

    def rejected(self, value, pattern=None):
        if pattern is None:
            with self.assertRaises(ManifestError):
                parse_manifest(encoded(value))
        else:
            with self.assertRaisesRegex(ManifestError, pattern):
                parse_manifest(encoded(value))

    def test_frozen_direct_and_mixed_profiles_parse_and_match_exact_hashes(self):
        cases = {
            "test-peer-tcp-stream-r-nnpsk0.json": "PEER-TCP-STREAM-R",
            "test-mixed-tcp-stream-r-sim-packet-nnpsk0.json": "MIXED-TCP-STREAM-R-SIM-PACKET",
        }
        for name, profile_id in cases.items():
            with self.subTest(name=name):
                manifest = load_manifest(name)
                raw = (DEPLOYMENTS / name).read_bytes()
                self.assertEqual(manifest.values["contract"], "DMP-test-manifest/3")
                self.assertEqual(manifest.values["profile"]["id"], profile_id)
                identified = identify_frozen_manifest(raw)
                self.assertEqual(identified, manifest)
                self.assertEqual(identified.values["profile"]["id"], profile_id)

    def test_direct_tcp_roles_capacity_and_timeout_fail_closed(self):
        original = self.read("test-peer-tcp-stream-r-nnpsk0.json")
        for path, mutate in (
            ("tcp_binding", lambda tcp, value: tcp.update(connector_node=tcp["listener_node"])),
            ("tcp_binding", lambda tcp, value: tcp.update(listener_node=999)),
            ("tcp_binding", lambda tcp, value: tcp.update(encoded_mtu=262)),
            ("tcp_binding", lambda tcp, value: tcp.update(partial_candidate_timeout_ms=25)),
            ("resources", lambda tcp, value: next(
                c for r in value["resources"] if r["role"] == "endpoint"
                for c in r["charges"] if c["component"] == "adapter"
            ).update(bytes_each=262)),
        ):
            with self.subTest(path=path, mutation=mutate):
                value = copy.deepcopy(original)
                mutate(value["tcp_binding"] if path == "tcp_binding" else None, value)
                self.rejected(value)

        for mutate in (
            lambda binding: binding.update(tx_ownership="borrow"),
            lambda binding: binding.update(synchronous_completion=True),
        ):
            with self.subTest(mutation=mutate):
                value = copy.deepcopy(original)
                mutate(value["binding"])
                self.rejected(value)

    def test_mixed_profile_topology_context_recovery_and_capacity_fail_closed(self):
        original = self.read("test-mixed-tcp-stream-r-sim-packet-nnpsk0.json")
        mutations = (
            lambda value: value["tcp_binding"].update(listener_node=40),
            lambda value: value["tcp_binding"].update(connector_node=20),
            lambda value: value["tcp_binding"].update(placement="peer-pair"),
            lambda value: value["tcp_binding"].update(forward_mtu=255),
            lambda value: value["tcp_binding"].update(partial_candidate_timeout_ms=27),
            lambda value: next(
                c for r in value["resources"] if r["role"] == "relay"
                for c in r["charges"] if c["component"] == "adapter"
            ).update(bytes_each=262),
            lambda value: value["binding"].update(ttl=1),
            lambda value: value["mixed_path"].update(forward_relays=[40, 30]),
            lambda value: value["mixed_path"].update(return_relays=[30, 40]),
            lambda value: value["mixed_path"].update(context_policy="association"),
            lambda value: value["binding"].update(context="association"),
            lambda value: value["mixed_path"].update(recovery="retry-all"),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = copy.deepcopy(original)
                mutate(value)
                self.rejected(value)

        value = copy.deepcopy(original)
        del value["mixed_path"]
        self.rejected(value)

    def test_unknown_profile_extra_members_and_expected_digest_are_rejected(self):
        value = self.read("test-peer-tcp-stream-r-nnpsk0.json")
        value["profile"]["id"] = "UNSUPPORTED-TCP-PROFILE"
        self.rejected(value)

        value = self.read("test-mixed-tcp-stream-r-sim-packet-nnpsk0.json")
        value["mixed_path"]["unexpected"] = True
        self.rejected(value)

        raw = (DEPLOYMENTS / "test-peer-tcp-stream-r-nnpsk0.json").read_bytes()
        with self.assertRaisesRegex(ManifestError, "SHA-256"):
            parse_manifest(raw, "0" * 64)

    def test_contract2_frozen_bytes_and_contract_marker_are_unchanged(self):
        legacy = load_manifest("direct-nnpsk0.json")
        raw = (DEPLOYMENTS / "direct-nnpsk0.json").read_bytes()
        self.assertEqual(legacy.sha256,
                         "29f7895ab3f8dadfbe7331f1981fa35dcad2bec59139464e29bddc4e841e5285")
        self.assertEqual(identify_frozen_manifest(raw), legacy)

        v3 = self.read("test-peer-tcp-stream-r-nnpsk0.json")
        v3["contract"] = "DMP-test-manifest/2"
        self.rejected(v3)


if __name__ == "__main__":
    unittest.main()
