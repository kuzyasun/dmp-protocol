import json
import unittest
from pathlib import Path

from dmp_peer.manifest import ManifestError, identify_frozen_manifest, load_manifest, parse_manifest
from dmp_peer.testing import PeerEndpoint


class ManifestTests(unittest.TestCase):
    def test_all_frozen_profiles_match_original_byte_digests(self):
        expected = {
            "direct-nnpsk0-async.json": ("TEST-DIRECT-ASYNC", "stream-r", "retry-all"),
            "direct-nnpsk0.json": ("DIRECT-1", "stream-r", "retry-all"),
            "direct-xx.json": ("DIRECT-1", "stream-r", "retry-all"),
            "radio-nnpsk0-n2.json": ("TEST-RADIO-N2", "packet", "selective-32"),
            "radio-nnpsk0.json": ("RADIO-1", "packet", "selective-32"),
            "radio-xx.json": ("RADIO-1", "packet", "selective-32"),
            "test-direct-minimal-128.json": ("TEST-DIRECT-MINIMAL-128", "stream-r", "retry-all"),
            "test-direct-minimal-256.json": ("TEST-DIRECT-MINIMAL-256", "stream-r", "retry-all"),
            "test-direct-sample-retry-2-nnpsk0.json": (
                "TEST-DIRECT-SAMPLE-RETRY-2", "stream-r", "retry-all"
            ),
            "test-radio-retry-all-nnpsk0.json": ("TEST-RADIO-RETRY-ALL", "packet", "retry-all"),
            "test-radio-retry-all-xx.json": ("TEST-RADIO-RETRY-ALL", "packet", "retry-all"),
        }
        for name, interpretation in expected.items():
            with self.subTest(name=name):
                manifest = load_manifest(name)
                self.assertEqual(len(manifest.sha256), 64)
                self.assertEqual(
                    (manifest.values["profile"]["id"], manifest.values["binding"]["kind"],
                     manifest.values["services"][0]["recovery"]),
                    interpretation,
                )
                self.assertEqual(identify_frozen_manifest(
                    (Path(__file__).parents[3] / "profiles" / "deployments" / name).read_bytes()
                ), manifest)

    def test_sample_retry_profile_has_two_distinct_initialization_attempts(self):
        manifest = load_manifest("test-direct-sample-retry-2-nnpsk0.json")
        sample = manifest.values["sample"]
        timing = manifest.values["timing"]
        self.assertEqual(2, sample["init_attempts"])
        self.assertEqual(5, sample["init_retry_ms"])
        self.assertGreaterEqual(
            sample["init_deadline_ms"],
            sample["init_attempts"] * timing["result_deadline_ms"]
            + (sample["init_attempts"] - 1) * sample["init_retry_ms"],
        )

    def test_multi_peer_manifest_uses_single_format(self):
        path = (Path(__file__).parents[3] / "profiles" / "deployments"
                / "test-direct-multi-peer-nnpsk0.json")
        manifest = load_manifest("test-direct-multi-peer-nnpsk0.json")
        self.assertEqual(manifest.values["contract"], "DMP-test-manifest/1.0")
        multi = manifest.values["multi_peer"]
        self.assertEqual(multi["endpoint_node"], 20)
        self.assertEqual(multi["peer_nodes"], [10, 35, 34, 36])
        self.assertEqual([row["name"] for row in multi["sensitivity_rows"]],
                         ["four_serial", "four_parallel"])

    def test_multi_peer_rejects_duplicate_or_overlapping_peer_identities(self):
        path = (Path(__file__).parents[3] / "profiles" / "deployments"
                / "test-direct-multi-peer-nnpsk0.json")
        original = json.loads(path.read_bytes())

        value = json.loads(json.dumps(original))
        value["multi_peer"]["peer_nodes"][1] = value["multi_peer"]["peer_nodes"][0]
        with self.assertRaisesRegex(ManifestError, "peer IDs must be unique"):
            parse_manifest(json.dumps(value).encode())

        value = json.loads(json.dumps(original))
        value["multi_peer"]["peer_nodes"][0] = value["multi_peer"]["endpoint_node"]
        with self.assertRaisesRegex(ManifestError, "peer IDs must be unique"):
            parse_manifest(json.dumps(value).encode())

        value = json.loads(json.dumps(original))
        value["identity"]["nodes"][4] = value["identity"]["nodes"][3]
        with self.assertRaisesRegex(ManifestError, "exact endpoint count"):
            parse_manifest(json.dumps(value).encode())

        value = json.loads(json.dumps(original))
        value["multi_peer"]["endpoint_node"] = 21
        with self.assertRaisesRegex(ManifestError, "identity nodes must be exactly"):
            parse_manifest(json.dumps(value).encode())

    def test_multi_peer_rejects_inconsistent_per_peer_and_shared_quotas(self):
        path = (Path(__file__).parents[3] / "profiles" / "deployments"
                / "test-direct-multi-peer-nnpsk0.json")
        original = json.loads(path.read_bytes())

        value = json.loads(json.dumps(original))
        value["security"]["active_per_pair"] = 2
        with self.assertRaisesRegex(ManifestError, "per-peer quotas must match"):
            parse_manifest(json.dumps(value).encode())

        value = json.loads(json.dumps(original))
        value["limits"]["peers"] = 3
        with self.assertRaisesRegex(ManifestError, "shared endpoint quotas"):
            parse_manifest(json.dumps(value).encode())

        value = json.loads(json.dumps(original))
        value["multi_peer"]["shared_endpoint"]["sender_slots"] = 3
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(value).encode())

    def test_multi_peer_rejects_undersized_peer_metadata_buffers(self):
        path = (Path(__file__).parents[3] / "profiles" / "deployments"
                / "test-direct-multi-peer-nnpsk0.json")
        original = json.loads(path.read_bytes())
        minima = {
            "endpoint_metadata": 4096,
            "peer_state": 2048,
            "identity_context": 64,
            "stream_decoder": 512,
            "admission_owner": 8192,
        }
        for component, minimum in minima.items():
            with self.subTest(component=component):
                value = json.loads(json.dumps(original))
                endpoint = next(resource for resource in value["resources"]
                                if resource["role"] == "endpoint")
                charge = next(item for item in endpoint["charges"]
                              if item["component"] == component)
                charge["bytes_each"] = minimum - 1
                with self.assertRaisesRegex(ManifestError,
                                            "metadata/state/decoder/admission buffers"):
                    parse_manifest(json.dumps(value).encode())

    def test_multi_peer_rejects_altered_sensitivity_row_values(self):
        path = (Path(__file__).parents[3] / "profiles" / "deployments"
                / "test-direct-multi-peer-nnpsk0.json")
        value = json.loads(path.read_bytes())
        value["multi_peer"]["sensitivity_rows"][0]["crypto_slots"] = 2
        with self.assertRaisesRegex(ManifestError, "sensitivity rows must exactly match"):
            parse_manifest(json.dumps(value).encode())

    def test_duplicate_escape_equivalent_key_is_rejected(self):
        raw = b'{"contract":"a","\\u0063ontract":"b"}'
        with self.assertRaisesRegex(ManifestError, "duplicate"):
            parse_manifest(raw)

    def test_unknown_fields_and_bad_json_values_are_rejected(self):
        valid = (Path(__file__).parents[3] / "profiles" / "deployments" / "direct-nnpsk0.json").read_bytes()
        value = json.loads(valid)
        value["surprise"] = 1
        with self.assertRaisesRegex(ManifestError, "unknown"):
            parse_manifest(json.dumps(value).encode())
        value.pop("surprise")
        value["services"][0]["surprise"] = True
        with self.assertRaisesRegex(ManifestError, "unknown"):
            parse_manifest(json.dumps(value).encode())
        nested_duplicate = b'{"outer":{"name":"a","\\u006eame":"b"}}'
        with self.assertRaisesRegex(ManifestError, "duplicate"):
            parse_manifest(nested_duplicate)
        for raw in (b"\xef\xbb\xbf{}", b"{} {}", b'{"x":1.0}', b'{"x":1e2}',
                    b'{"x":NaN}', b'{"x":"\\ud800"}'):
            with self.subTest(raw=raw), self.assertRaises(ManifestError):
                parse_manifest(raw)

    def test_schema_ranges_digest_and_contract_feasibility(self):
        raw = (Path(__file__).parents[3] / "profiles" / "deployments" / "direct-nnpsk0.json").read_bytes()
        with self.assertRaisesRegex(ManifestError, "SHA-256"):
            parse_manifest(raw, "0" * 64)
        value = json.loads(raw)
        value["binding"]["forward_mtu"] = -1
        with self.assertRaises(ManifestError):
            parse_manifest(json.dumps(value).encode())
        value = json.loads(raw)
        value["timing"]["assembly_ms"] = 1
        with self.assertRaisesRegex(ManifestError, "assembly lifetime"):
            parse_manifest(json.dumps(value).encode())

    def test_schema_type_checks_precede_enum_checks(self):
        raw = (Path(__file__).parents[3] / "profiles" / "deployments" / "direct-nnpsk0.json").read_bytes()
        value = json.loads(raw)
        value["limits"]["peers"] = True
        with self.assertRaisesRegex(ManifestError, "expected integer"):
            parse_manifest(json.dumps(value).encode())

        value = json.loads(raw)
        value["services"][1]["idempotent"] = 1
        with self.assertRaisesRegex(ManifestError, "enum"):
            parse_manifest(json.dumps(value).encode())

    def test_profile_recovery_and_fragment_geometry_are_feasible(self):
        raw = (Path(__file__).parents[3] / "profiles" / "deployments" / "direct-nnpsk0.json").read_bytes()
        value = json.loads(raw)
        value["services"][0]["recovery"] = "selective-32"
        with self.assertRaisesRegex(ManifestError, "service"):
            parse_manifest(json.dumps(value).encode())

        value = json.loads(raw)
        value["limits"]["fragments"] = 2
        with self.assertRaisesRegex(ManifestError, "geometry"):
            parse_manifest(json.dumps(value).encode())

    def test_mtu_schedule_relay_and_resource_feasibility(self):
        deployments = Path(__file__).parents[3] / "profiles" / "deployments"
        direct = json.loads((deployments / "direct-nnpsk0.json").read_bytes())
        direct["security"]["association_ms"] = 1
        with self.assertRaisesRegex(ManifestError, "security"):
            parse_manifest(json.dumps(direct).encode())

        direct = json.loads((deployments / "direct-nnpsk0.json").read_bytes())
        direct["binding"]["forward_mtu"] = 32
        with self.assertRaisesRegex(ManifestError, "mtu"):
            parse_manifest(json.dumps(direct).encode())

        direct = json.loads((deployments / "direct-nnpsk0.json").read_bytes())
        direct["timing"]["max_transfer_airtime_ms"] = 1
        with self.assertRaisesRegex(ManifestError, "schedule"):
            parse_manifest(json.dumps(direct).encode())

        radio = json.loads((deployments / "radio-nnpsk0.json").read_bytes())
        radio["relays"][0]["max_forwards_per_key"] = 1
        with self.assertRaisesRegex(ManifestError, "relay"):
            parse_manifest(json.dumps(radio).encode())

        direct = json.loads((deployments / "direct-nnpsk0.json").read_bytes())
        endpoint = next(resource for resource in direct["resources"]
                        if resource["role"] == "endpoint")
        endpoint["flash_reserved_bytes"] = endpoint["flash_limit_bytes"] + 1
        with self.assertRaisesRegex(ManifestError, "resources"):
            parse_manifest(json.dumps(direct).encode())

    def test_burst_starts_must_align_to_the_slot_period(self):
        path = Path(__file__).parents[3] / "profiles" / "deployments" / "direct-nnpsk0.json"
        value = json.loads(path.read_bytes())
        value["timing"]["max_bursts"] = 2
        value["timing"]["burst_starts_ms"] = [0, 2305]
        with self.assertRaisesRegex(ManifestError, "align to return-slot"):
            parse_manifest(json.dumps(value).encode())

    def test_relay_arrival_intervals_must_be_ordered(self):
        path = Path(__file__).parents[3] / "profiles" / "deployments" / "radio-nnpsk0.json"
        value = json.loads(path.read_bytes())
        value["relays"][0]["forward_arrival_min_ms"] = 3
        value["relays"][0]["forward_arrival_max_ms"] = 2
        with self.assertRaisesRegex(ManifestError, "arrival minimum exceeds maximum"):
            parse_manifest(json.dumps(value).encode())

    def test_establishment_ingress_caps_cover_all_frames(self):
        path = Path(__file__).parents[3] / "profiles" / "deployments" / "direct-nnpsk0.json"
        original = json.loads(path.read_bytes())

        value = json.loads(json.dumps(original))
        value["security"]["ingress_packets_per_window"] = 5
        with self.assertRaisesRegex(ManifestError, "response/ingress window"):
            parse_manifest(json.dumps(value).encode())

        value = json.loads(json.dumps(original))
        value["security"]["response_bytes_per_window"] = 1315
        with self.assertRaisesRegex(ManifestError, "response/ingress window"):
            parse_manifest(json.dumps(value).encode())

    def test_result_slots_reserve_max_message_and_grant_control_payload(self):
        deployments = Path(__file__).parents[3] / "profiles" / "deployments"
        direct = json.loads((deployments / "direct-nnpsk0.json").read_bytes())
        direct["services"][1]["result_bytes"] = 17
        endpoint = next(resource for resource in direct["resources"]
                        if resource["role"] == "endpoint")
        result_charge = next(charge for charge in endpoint["charges"]
                             if charge["component"] == "result")
        result_charge["bytes_each"] = 17
        with self.assertRaisesRegex(ManifestError, "endpoint message buffers"):
            parse_manifest(json.dumps(direct).encode())

        radio = json.loads((deployments / "radio-nnpsk0.json").read_bytes())
        radio["limits"]["message_bytes"] = 17
        radio["limits"]["chunk_bytes"] = 8
        radio["services"][1]["request_bytes"] = 17
        radio["services"][1]["result_bytes"] = 17
        endpoint = next(resource for resource in radio["resources"]
                        if resource["role"] == "endpoint")
        result_charge = next(charge for charge in endpoint["charges"]
                             if charge["component"] == "result")
        result_charge["bytes_each"] = 20
        with self.assertRaisesRegex(ManifestError, "endpoint message buffers"):
            parse_manifest(json.dumps(radio).encode())

    def test_freshness_grant_nodes_accept_either_endpoint_order(self):
        path = Path(__file__).parents[3] / "profiles" / "deployments" / "radio-nnpsk0.json"
        value = json.loads(path.read_bytes())
        value["freshness"]["grant_nodes"] = list(reversed(value["identity"]["nodes"]))
        parse_manifest(json.dumps(value).encode())

        value["freshness"]["grant_nodes"] = [value["identity"]["nodes"][0]] * 2
        with self.assertRaisesRegex(ManifestError, "both endpoint IDs exactly once"):
            parse_manifest(json.dumps(value).encode())

    def test_association_resource_covers_pending_active_and_draining(self):
        path = Path(__file__).parents[3] / "profiles" / "deployments" / "direct-nnpsk0.json"
        value = json.loads(path.read_bytes())
        endpoint = next(resource for resource in value["resources"]
                        if resource["role"] == "endpoint")
        association = next(charge for charge in endpoint["charges"]
                           if charge["component"] == "association")
        provider_slots = sum(value["security"][key] for key in (
            "pending_per_pair", "active_per_pair", "draining_per_pair"))
        association["count"] = provider_slots - 1
        with self.assertRaisesRegex(ManifestError, "crypto/association/bootstrap"):
            parse_manifest(json.dumps(value).encode())

    def test_draining_limit_is_independent_of_active_limit(self):
        path = Path(__file__).parents[3] / "profiles" / "deployments" / "direct-xx.json"
        value = json.loads(path.read_bytes())
        value["security"]["draining_per_pair"] = 2
        endpoint = next(resource for resource in value["resources"]
                        if resource["role"] == "endpoint")
        provider_slots = sum(value["security"][key] for key in (
            "pending_per_pair", "active_per_pair", "draining_per_pair"))
        for component in ("provider_retained", "association"):
            charge = next(item for item in endpoint["charges"]
                          if item["component"] == component)
            charge["count"] = provider_slots
        parse_manifest(json.dumps(value).encode())

    def test_radio_profile_can_use_zero_ttl_without_relays(self):
        path = Path(__file__).parents[3] / "profiles" / "deployments" / "radio-nnpsk0.json"
        value = json.loads(path.read_bytes())
        value["relays"] = []
        value["binding"]["ttl"] = 0
        value["resources"] = [resource for resource in value["resources"]
                               if resource["role"] != "relay"]
        parse_manifest(json.dumps(value).encode())

    def test_peer_api_skeleton_binds_only_a_frozen_manifest(self):
        raw = (Path(__file__).parents[3] / "profiles" / "deployments" / "direct-nnpsk0.json").read_bytes()
        endpoint = PeerEndpoint(
            raw, {"psk": b"\x01" * 32}, lambda size: bytes(size), {}
        )
        self.assertEqual(endpoint.manifest.sha256, identify_frozen_manifest(raw).sha256)
        with self.assertRaises(ManifestError):
            PeerEndpoint(raw + b" ", {}, lambda size: bytes(size), {})


if __name__ == "__main__":
    unittest.main()
