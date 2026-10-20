"""P03 deployment freeze checks against the manifest contract."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENTS = ROOT / "profiles" / "deployments"
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "peer"))
import validate_profile as validator  # noqa: E402
from dmp_peer.manifest import parse_manifest  # noqa: E402


class DeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.digests = json.loads((DEPLOYMENTS / "digests.json").read_text(encoding="utf-8"))["manifests"]
        cls.expected = json.loads((Path(__file__).with_name("deployment_expected.json")).read_text(encoding="utf-8"))
        cls.manifests = {}
        cls.raw = {}
        for name in cls.digests:
            raw = (DEPLOYMENTS / name).read_bytes()
            cls.raw[name] = raw
            cls.manifests[name] = json.loads(raw)

    @staticmethod
    def encode(document):
        return json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def assert_rejected(self, document, code, path=None):
        with self.assertRaises(validator.ProfileError) as raised:
            validator.validate_bytes(self.encode(document))
        self.assertEqual(code, raised.exception.code)
        if path is not None:
            self.assertEqual(path, raised.exception.path)

    def test_manifest_inventory_digests_and_independent_derived_bounds(self):
        inventory = {path.name for path in DEPLOYMENTS.glob("*.json")
                     if path.name not in {"digests.json", "resource-inputs.json"}}
        self.assertEqual(set(self.digests), inventory)
        self.assertEqual(set(self.digests), set(self.expected))
        for name, expected_digest in self.digests.items():
            with self.subTest(manifest=name):
                raw = self.raw[name]
                self.assertEqual(expected_digest, hashlib.sha256(raw).hexdigest())
                result = validator.validate_bytes(raw, expected_digest)
                self.assertTrue(result["valid"])
                self.assertEqual(expected_digest, result["sha256"])
                self.assertEqual(self.expected[name], result["derived"])

    def test_profile_identities_and_security_modes_are_explicit(self):
        identities = {
            "direct-nnpsk0.json": ("DMP-reference", "DIRECT-1", 5, "NNpsk0"),
            "direct-none.json": ("DMP-reference", "DIRECT-1", 5, "NONE"),
            "test-direct-none-five-peers.json": ("DMP-reference", "DIRECT-1", 5, "NONE"),
            "direct-xx.json": ("DMP-reference", "DIRECT-1", 5, "XX"),
            "radio-nnpsk0.json": ("DMP-reference", "RADIO-1", 5, "NNpsk0"),
            "radio-none.json": ("DMP-reference", "RADIO-1", 5, "NONE"),
            "radio-xx.json": ("DMP-reference", "RADIO-1", 5, "XX"),
            "test-radio-retry-all-nnpsk0.json": ("DMP-test", "TEST-RADIO-RETRY-ALL", 1, "NNpsk0"),
            "test-radio-retry-all-xx.json": ("DMP-test", "TEST-RADIO-RETRY-ALL", 1, "XX"),
            "direct-nnpsk0-async.json": ("DMP-test", "TEST-DIRECT-ASYNC", 1, "NNpsk0"),
            "radio-nnpsk0-n2.json": ("DMP-test", "TEST-RADIO-N2", 1, "NNpsk0"),
            "test-direct-minimal-128.json": ("DMP-test", "TEST-DIRECT-MINIMAL-128", 1, "NNpsk0"),
            "test-direct-minimal-256.json": ("DMP-test", "TEST-DIRECT-MINIMAL-256", 1, "NNpsk0"),
            "test-direct-sample-retry-2-nnpsk0.json": (
                "DMP-test", "TEST-DIRECT-SAMPLE-RETRY-2", 1, "NNpsk0"
            ),
            "test-direct-multi-peer-nnpsk0.json": (
                "DMP-test", "TEST-DIRECT-MULTIPEER", 1, "NNpsk0"
            ),
            "test-peer-tcp-stream-r-sample20-nnpsk0.json": (
                "DMP-test", "PEER-TCP-STREAM-R", 1, "NNpsk0"
            ),
        }
        for name, expected in identities.items():
            with self.subTest(manifest=name):
                manifest = self.manifests[name]
                profile = manifest["profile"]
                self.assertEqual(expected[:3], (profile["owner"], profile["id"], profile["revision"]))
                if expected[3] == "NONE":
                    self.assertEqual({"mode": "NONE"}, manifest["security"])
                else:
                    self.assertEqual("SEC-1", manifest["security"]["mode"])
                    self.assertEqual(expected[3], manifest["security"]["noise_mode"])

    def test_sample_and_maximum_message_fragment_boundaries_stay_frozen(self):
        for name, manifest in self.manifests.items():
            with self.subTest(manifest=name):
                services = {service["id"]: service for service in manifest["services"]}
                sample = services[1]
                self.assertEqual(("DMP-reference/SAMPLE-1/3", 1, 17, False),
                                 (sample["schema"], sample["request_bytes"], sample["result_bytes"], sample["freshness"]))
                self.assertEqual(16, manifest["sample"]["telemetry_bytes"])
                self.assertEqual((1, 17), (manifest["sample"]["read_request_bytes"], manifest["sample"]["read_result_bytes"]))
                maximum = manifest["limits"]["message_bytes"]
                self.assertEqual((maximum, maximum), (services[2]["request_bytes"], services[2]["result_bytes"]))
                self.assertEqual(4, manifest["limits"]["sender_slots"])
                expected_fragments = (maximum + manifest["limits"]["chunk_bytes"] - 1) // manifest["limits"]["chunk_bytes"]
                self.assertEqual(expected_fragments, manifest["limits"]["fragments"])
                peers = manifest["limits"].get("peers", 1)
                self.assertEqual(16, manifest["limits"]["assembly_tombstones_per_peer"])
                endpoint = next(resource for resource in manifest["resources"]
                                if resource["role"] == "endpoint")
                tombstones = next(charge for charge in endpoint["charges"]
                                  if charge["component"] == "assembly_tombstone")
                self.assertEqual((16 * peers, 48),
                                 (tombstones["count"], tombstones["bytes_each"]))

    def test_sample_retry_profile_is_separate_and_timing_bounded(self):
        retry = self.manifests["test-direct-sample-retry-2-nnpsk0.json"]
        direct = self.manifests["direct-nnpsk0.json"]
        self.assertEqual((1, 12000), (direct["sample"]["init_attempts"],
                                     direct["sample"]["init_deadline_ms"]))
        self.assertEqual(2, retry["sample"]["init_attempts"])
        minimum = (2 * retry["timing"]["result_deadline_ms"]
                   + retry["sample"]["init_retry_ms"])
        self.assertEqual(24005, minimum)
        self.assertEqual(retry["sample"]["init_retry_ms"],
                         retry["sample"]["init_deadline_ms"] - minimum)
        self.assertGreaterEqual(retry["sample"]["init_deadline_ms"], minimum)
        self.assertEqual(direct["resources"], retry["resources"])
        self.assertEqual({"/profile/owner", "/profile/id", "/profile/revision",
                          "/sample/init_attempts", "/sample/init_deadline_ms"},
                         self.differing_paths(direct, retry))
        for name, digest in {
                "direct-nnpsk0.json": self.digests["direct-nnpsk0.json"],
                "direct-xx.json": self.digests["direct-xx.json"],
        }.items():
            with self.subTest(manifest=name):
                self.assertEqual(digest, hashlib.sha256(self.raw[name]).hexdigest())

        too_short = copy.deepcopy(retry)
        too_short["sample"]["init_deadline_ms"] = minimum - 1
        self.assert_rejected(too_short, "timing", "$.sample.init_deadline_ms")

    def test_none_peer_capacity_is_caller_quota_and_ram_bounded(self):
        manifest = self.manifests["test-direct-none-five-peers.json"]
        self.assertEqual(6, len(manifest["identity"]["nodes"]))
        self.assertEqual(5, manifest["limits"]["peers"])
        endpoint = next(resource for resource in manifest["resources"] if resource["role"] == "endpoint")
        self.assertEqual(98304, endpoint["regions"][0]["limit_bytes"])
        excess_peer_quota = copy.deepcopy(manifest)
        excess_peer_quota["limits"]["peers"] = 4
        self.assert_rejected(excess_peer_quota, "resources", "$.limits.peers")
        undersized_ram = copy.deepcopy(manifest)
        undersized_ram["resources"][0]["regions"][0]["limit_bytes"] = 70000
        self.assert_rejected(undersized_ram, "resources", "$.resources[endpoint]")

    def test_multi_peer_profile_matches_both_sensitivity_rows(self):
        manifest = copy.deepcopy(self.manifests["test-direct-multi-peer-nnpsk0.json"])
        self.assertEqual("DMP-test-manifest/1.1", manifest["contract"])
        self.assertEqual("shared-endpoint-multi-peer", manifest["binding"]["topology"])
        self.assertEqual((256, 263), (manifest["binding"]["forward_mtu"],
                                      manifest["binding"]["encoded_mtu"]))
        self.assertEqual((4, 4096, 128, 32), (
            manifest["limits"]["peers"], manifest["limits"]["message_bytes"],
            manifest["limits"]["chunk_bytes"], manifest["limits"]["fragments"],
        ))
        self.assertEqual((1000, 250), (
            manifest["binding"]["return_slot_period_ms"],
            manifest["binding"]["return_slot_width_ms"],
        ))
        self.assertEqual({20, 10, 35, 34, 36}, set(manifest["identity"]["nodes"]))
        self.assertEqual([10, 35, 34, 36], manifest["multi_peer"]["peer_nodes"])
        self.assertEqual({
            "pending_attempts": 4, "active_associations": 4,
            "draining_associations": 4, "sender_slots": 4, "services": 2,
            "application_operations": 4,
        }, manifest["multi_peer"]["shared_endpoint"])
        self.assertEqual([
            {"name": "four_serial", "peers": 4, "services": 2,
             "active_associations": 4, "draining_associations": 4,
             "pending_attempts": 4, "crypto_slots": 1,
             "application_operations": 4, "mtu_bytes": 256,
             "max_message_bytes": 4096, "return_period_ms": 1000,
             "return_window_ms": 250},
            {"name": "four_parallel", "peers": 4, "services": 2,
             "active_associations": 4, "draining_associations": 4,
             "pending_attempts": 4, "crypto_slots": 2,
             "application_operations": 4, "mtu_bytes": 256,
             "max_message_bytes": 4096, "return_period_ms": 1000,
             "return_window_ms": 250},
        ], manifest["multi_peer"]["sensitivity_rows"])
        validated = validator.validate_bytes(self.encode(manifest))
        self.assertTrue(validated["valid"])
        endpoint = next(resource for resource in manifest["resources"]
                        if resource["role"] == "endpoint")
        ram_limit = next(region["limit_bytes"] for region in endpoint["regions"]
                         if region["id"] == "RAM")
        ram_reserved = sum(charge["count"] * charge["bytes_each"]
                           for charge in endpoint["charges"]
                           if charge["region"] == "RAM")
        self.assertEqual(ram_reserved, validated["derived"]["ram_reserved_bytes"]
                         ["endpoint"]["RAM"])
        self.assertLessEqual(ram_reserved, ram_limit)

        underfunded = copy.deepcopy(manifest)
        endpoint = next(resource for resource in underfunded["resources"]
                        if resource["role"] == "endpoint")
        ram = next(region for region in endpoint["regions"]
                   if region["id"] == "RAM")
        ram["limit_bytes"] = ram_reserved - 1
        self.assert_rejected(underfunded, "resources", "$.resources[endpoint]")

        duplicate = copy.deepcopy(manifest)
        duplicate["multi_peer"]["peer_nodes"][1] = duplicate["multi_peer"]["peer_nodes"][0]
        self.assert_rejected(duplicate, "identity", "$.multi_peer")

        overlapping = copy.deepcopy(manifest)
        overlapping["multi_peer"]["peer_nodes"][0] = overlapping["multi_peer"]["endpoint_node"]
        self.assert_rejected(overlapping, "identity", "$.multi_peer")

        per_peer_mismatch = copy.deepcopy(manifest)
        per_peer_mismatch["multi_peer"]["per_peer"]["active_associations"] = 2
        self.assert_rejected(per_peer_mismatch, "schema")

        shared_mismatch = copy.deepcopy(manifest)
        shared_mismatch["multi_peer"]["shared_endpoint"]["pending_attempts"] = 3
        self.assert_rejected(shared_mismatch, "schema")

        altered_row = copy.deepcopy(manifest)
        altered_row["multi_peer"]["sensitivity_rows"][0]["crypto_slots"] = 2
        self.assert_rejected(altered_row, "resources", "$.multi_peer.sensitivity_rows")

    def test_per_peer_resources_scale_with_admitted_peer_count(self):
        multi_peer = copy.deepcopy(self.manifests["direct-nnpsk0.json"])
        multi_peer["limits"]["peers"] = 2
        endpoint = next(resource for resource in multi_peer["resources"]
                        if resource["role"] == "endpoint")
        expected_counts = {
            "provider_retained": 6,
            "provider_scratch": 2,
            "association": 6,
            "bootstrap": 2,
            "assembly": 2,
            "assembly_tombstone": 32,
        }
        charges = {item["component"]: item for item in endpoint["charges"]}
        for component, count in expected_counts.items():
            charges[component]["count"] = count
        self.assertTrue(validator.validate_bytes(self.encode(multi_peer))["valid"])

        for component, count in expected_counts.items():
            with self.subTest(component=component):
                underfunded = copy.deepcopy(multi_peer)
                endpoint = next(resource for resource in underfunded["resources"]
                                if resource["role"] == "endpoint")
                charge = next(item for item in endpoint["charges"]
                              if item["component"] == component)
                charge["count"] = count - 1
                self.assert_rejected(underfunded, "resources",
                                     f"$.resources[endpoint].{component}")

    def test_async_and_n2_are_separate_exact_profiles(self):
        direct = self.manifests["direct-nnpsk0.json"]
        async_direct = self.manifests["direct-nnpsk0-async.json"]
        direct_differences = self.differing_paths(direct, async_direct)
        self.assertEqual({"/profile/owner", "/profile/id", "/profile/revision",
                          "/binding/synchronous_completion"}, direct_differences)
        self.assertFalse(async_direct["binding"]["synchronous_completion"])
        self.assertNotEqual(self.digests["direct-nnpsk0.json"],
                            self.digests["direct-nnpsk0-async.json"])

        radio = self.manifests["radio-nnpsk0.json"]
        n2 = self.manifests["radio-nnpsk0-n2.json"]
        n2_differences = self.differing_paths(radio, n2)
        self.assertEqual({"/profile/owner", "/profile/id", "/profile/revision",
                          "/binding/forward_mtu", "/binding/return_mtu",
                          "/binding/encoded_mtu", "/binding/synchronous_completion",
                          "/resources/0/charges/10/bytes_each",
                          "/resources/0/charges/11/bytes_each",
                          "/resources/0/charges/12/bytes_each"},
                         n2_differences)
        self.assertEqual((119, 119, 119), (n2["binding"]["forward_mtu"],
                                           n2["binding"]["return_mtu"],
                                           n2["binding"]["encoded_mtu"]))
        self.assertFalse(n2["binding"]["synchronous_completion"])
        self.assertEqual("selective-32", n2["services"][1]["recovery"])
        self.assertTrue(n2["services"][1]["freshness"])
        self.assertNotEqual(self.digests["radio-nnpsk0.json"],
                            self.digests["radio-nnpsk0-n2.json"])

    @staticmethod
    def differing_paths(left, right, prefix=""):
        if isinstance(left, dict) and isinstance(right, dict):
            paths = set()
            for key in left.keys() | right.keys():
                child = f"{prefix}/{key}"
                if key not in left or key not in right:
                    paths.add(child)
                else:
                    paths.update(DeploymentTests.differing_paths(left[key], right[key], child))
            return paths
        if isinstance(left, list) and isinstance(right, list):
            paths = set()
            if len(left) != len(right):
                paths.add(prefix + "/length")
            for index, (a, b) in enumerate(zip(left, right)):
                paths.update(DeploymentTests.differing_paths(a, b, f"{prefix}/{index}"))
            return paths
        return set() if left == right else {prefix}

    def test_radio_retry_all_changes_only_the_named_contract_fields(self):
        for mode in ("nnpsk0", "xx"):
            with self.subTest(mode=mode):
                radio_name = f"radio-{mode}.json"
                retry_name = f"test-radio-retry-all-{mode}.json"
                radio = self.manifests[radio_name]
                retry = self.manifests[retry_name]
                differences = self.differing_paths(radio, retry)
                allowed = {
                    "/profile/owner", "/profile/id", "/profile/revision",
                    "/services/0/recovery", "/services/1/recovery",
                    "/timing/max_probes", "/timing/max_status",
                }
                self.assertEqual(allowed, differences)
                self.assertNotEqual(self.digests[radio_name], self.digests[retry_name])

    def test_retry_all_cannot_be_relabelled_as_radio_1(self):
        radio = copy.deepcopy(self.manifests["radio-nnpsk0.json"])
        for service in radio["services"]:
            service["recovery"] = "retry-all"
        self.assert_rejected(radio, "profile", "$.services[0].recovery")

    def test_memory_per_buffer_and_aggregate_limits_reject_underfunding(self):
        radio = self.manifests["radio-nnpsk0.json"]
        small_buffer = copy.deepcopy(radio)
        endpoint = next(resource for resource in small_buffer["resources"] if resource["role"] == "endpoint")
        sender = next(charge for charge in endpoint["charges"] if charge["component"] == "sender")
        sender["bytes_each"] = 1023
        self.assert_rejected(small_buffer, "resources", "$.resources[endpoint].sender")

        small_assembly = copy.deepcopy(radio)
        endpoint = next(resource for resource in small_assembly["resources"] if resource["role"] == "endpoint")
        assembly = next(charge for charge in endpoint["charges"] if charge["component"] == "assembly")
        assembly["bytes_each"] = small_assembly["limits"]["message_bytes"] - 1
        self.assert_rejected(small_assembly, "resources", "$.resources[endpoint].assembly")

        small_region = copy.deepcopy(radio)
        endpoint = next(resource for resource in small_region["resources"] if resource["role"] == "endpoint")
        ram = next(region for region in endpoint["regions"] if region["id"] == "RAM")
        total = validator.validate_bytes(self.raw["radio-nnpsk0.json"])["derived"]["ram_reserved_bytes"]["endpoint"]["RAM"]
        ram["limit_bytes"] = total - 1
        self.assert_rejected(small_region, "resources", "$.resources[endpoint]")

    def test_every_component_keeps_a_nonzero_reserve_when_disabled(self):
        security_components = {"provider_retained", "provider_scratch", "association",
                               "bootstrap", "freshness_tokens"}
        for name, manifest in self.manifests.items():
            for resource in manifest["resources"]:
                for charge in resource["charges"]:
                    with self.subTest(manifest=name, role=resource["role"], component=charge["component"]):
                        if manifest["security"]["mode"] == "NONE" and charge["component"] in security_components:
                            self.assertEqual((0, 0), (charge["count"], charge["bytes_each"]))
                        else:
                            self.assertGreaterEqual(charge["count"], 1)
                            self.assertGreaterEqual(charge["bytes_each"], 1)

        minimal = self.manifests["test-direct-minimal-128.json"]
        for component in ("relay_cache", "freshness_tokens"):
            for field in ("count", "bytes_each"):
                with self.subTest(component=component, field=field):
                    underfunded = copy.deepcopy(minimal)
                    endpoint = next(resource for resource in underfunded["resources"]
                                    if resource["role"] == "endpoint")
                    charge = next(item for item in endpoint["charges"]
                                  if item["component"] == component)
                    charge[field] = 0
                    self.assert_rejected(underfunded, "resources", f"$.resources[endpoint].{component}")

    def test_association_charge_covers_pending_active_and_draining_slots(self):
        for name, manifest in self.manifests.items():
            if manifest["security"]["mode"] == "NONE":
                continue
            required = sum(manifest["security"][key] for key in (
                "pending_per_pair", "active_per_pair", "draining_per_pair"))
            endpoint = next(resource for resource in manifest["resources"]
                            if resource["role"] == "endpoint")
            charge = next(item for item in endpoint["charges"]
                          if item["component"] == "association")
            with self.subTest(manifest=name):
                self.assertGreaterEqual(charge["count"], required)

        direct = copy.deepcopy(self.manifests["direct-nnpsk0.json"])
        endpoint = next(resource for resource in direct["resources"]
                        if resource["role"] == "endpoint")
        association = next(item for item in endpoint["charges"]
                           if item["component"] == "association")
        association["count"] = sum(direct["security"][key] for key in (
            "pending_per_pair", "active_per_pair", "draining_per_pair")) - 1
        self.assert_rejected(direct, "resources", "$.resources[endpoint].association")

    def test_fragment_count_and_direct_chunk_boundaries(self):
        radio = copy.deepcopy(self.manifests["radio-nnpsk0.json"])
        radio["limits"]["message_bytes"] = 1023
        radio["limits"]["chunk_bytes"] = 31
        service = next(service for service in radio["services"] if service["id"] == 2)
        service["request_bytes"] = service["result_bytes"] = 1023
        self.assertEqual(33, (radio["limits"]["message_bytes"] + radio["limits"]["chunk_bytes"] - 1) // radio["limits"]["chunk_bytes"])
        self.assert_rejected(radio, "geometry", "$.limits.fragments")

        direct = copy.deepcopy(self.manifests["direct-nnpsk0.json"])
        direct["limits"]["chunk_bytes"] = 63
        self.assert_rejected(direct, "geometry", "$.limits.fragments")

    def test_return_mtu_must_fit_the_largest_admitted_frame(self):
        radio = copy.deepcopy(self.manifests["radio-nnpsk0.json"])
        radio["binding"]["return_mtu"] = 118
        self.assert_rejected(radio, "mtu")

    def test_none_full_reply_frame_mtu_exact_fit_and_underflow(self):
        direct = copy.deepcopy(self.manifests["direct-none.json"])
        # Worst admitted service-2 RSP: CONTEXT, ORIGIN_ID, full REPLY_TO,
        # explicit SERVICE_ID, FRAG, 64-byte payload and CRC32C = 115 bytes.
        direct["binding"].update(forward_mtu=115, return_mtu=115, encoded_mtu=121)
        result = validator.validate_bytes(self.encode(direct))
        self.assertTrue(result["valid"])
        self.assertEqual(115, result["derived"]["app_frame_bytes"])
        direct["binding"].update(forward_mtu=114, return_mtu=114, encoded_mtu=120)
        self.assert_rejected(direct, "mtu", "$.binding")
        direct["binding"].update(forward_mtu=107, return_mtu=107, encoded_mtu=114)
        self.assert_rejected(direct, "mtu", "$.binding")

    def test_radio_none_route_mtu_counts_only_pair_ids_and_matches_peer(self):
        radio = copy.deepcopy(self.manifests["radio-none.json"])
        nodes = [10, 20, 50, 60, 70, 80]
        radio["identity"]["nodes"] = nodes
        radio["limits"]["peers"] = len(nodes) - 1
        for service in radio["services"]:
            service["acl"] = [
                {"node": node, "actions":
                 ((["produce", "result"] if node == 10 else ["read", "status"])
                  if service["id"] == 1 else ["data", "result"])}
                for node in nodes
            ]
        for resource in radio["resources"]:
            for region in resource["regions"]:
                region["limit_bytes"] = 16 * 1024 * 1024
            for charge in resource["charges"]:
                if resource["role"] == "relay" and charge["component"] == "relay_cache":
                    charge["count"] = 1000
                elif resource["role"] == "endpoint":
                    if charge["component"] in {"sender", "result", "correlation"}:
                        charge["count"] = 20
                    elif charge["component"] == "history":
                        charge["count"] = 40
                    elif charge["component"] == "assembly":
                        charge["count"] = 5
                    elif charge["component"] == "assembly_tombstone":
                        charge["count"] = 80
        radio["binding"].update(forward_mtu=83, return_mtu=83, encoded_mtu=83)
        raw = self.encode(radio)
        primary = validator.validate_bytes(raw)
        peer = parse_manifest(raw)
        self.assertEqual(83, primary["derived"]["app_frame_bytes"])
        self.assertEqual(nodes, peer.values["identity"]["nodes"])

        radio["binding"].update(forward_mtu=82, return_mtu=82, encoded_mtu=82)
        raw = self.encode(radio)
        with self.assertRaises(validator.ProfileError) as error:
            validator.validate_bytes(raw)
        self.assertEqual("mtu", error.exception.code)
        from dmp_peer.manifest import ManifestError
        with self.assertRaises(ManifestError):
            parse_manifest(raw)

        # Wider IDs change pairwise ROUTE width, but inventory size still does
        # not add unrelated IDs to each on-wire frame.
        wider_nodes = [10, 20, 300, 10000, 70000, 900000]
        radio["identity"]["nodes"] = wider_nodes
        for service in radio["services"]:
            service["acl"] = [
                {"node": node, "actions":
                 ((["produce", "result"] if node == 10 else ["read", "status"])
                  if service["id"] == 1 else ["data", "result"])}
                for node in wider_nodes
            ]
        radio["binding"].update(forward_mtu=90, return_mtu=90, encoded_mtu=90)
        raw = self.encode(radio)
        primary = validator.validate_bytes(raw)
        peer = parse_manifest(raw)
        self.assertEqual(wider_nodes, peer.values["identity"]["nodes"])

    def test_radio_freshness_lease_exact_boundary_includes_token_record(self):
        radio = copy.deepcopy(self.manifests["radio-nnpsk0.json"])
        radio["freshness"]["lease_ms"] = 10935
        radio["freshness"]["token_record_ms"] = 10935
        self.assert_rejected(radio, "timing", "$.freshness")
        radio["freshness"]["lease_ms"] = 10936
        radio["freshness"]["token_record_ms"] = 10936
        self.assertTrue(validator.validate_bytes(self.encode(radio))["valid"])

    def test_selective_response_floor_exact_boundary_keeps_schedule_valid(self):
        radio = copy.deepcopy(self.manifests["radio-nnpsk0.json"])
        radio["timing"]["response_timeout_ms"] = 2221
        self.assert_rejected(radio, "timing", "$.timing.response_timeout_ms")
        radio["timing"]["response_timeout_ms"] = 2222
        self.assertTrue(validator.validate_bytes(self.encode(radio))["valid"])

    def test_missing_required_field_and_changed_manifest_bytes_are_caught(self):
        broken = copy.deepcopy(self.manifests["direct-nnpsk0.json"])
        del broken["profile"]["revision"]
        self.assert_rejected(broken, "schema", "$.profile")

        name = "radio-xx.json"
        changed = self.raw[name] + b" "
        with self.assertRaises(validator.ProfileError) as raised:
            validator.validate_bytes(changed, self.digests[name])
        self.assertEqual("digest", raised.exception.code)
        self.assertEqual("$", raised.exception.path)

    def test_resource_input_hashes_match_source_bytes(self):
        document = json.loads((DEPLOYMENTS / "resource-inputs.json").read_text(encoding="utf-8"))
        self.assertEqual(
            "Source text with CRLF replaced by LF; no other normalization. This is not PROFILE_HASH.",
            document["hash_bytes"],
        )
        for relative, expected_digest in document["files"].items():
            with self.subTest(source=relative):
                source = (ROOT / relative).read_bytes().replace(b"\r\n", b"\n")
                self.assertEqual(expected_digest, hashlib.sha256(source).hexdigest())

    def test_excluded_features_are_explicit_configuration_rejections(self):
        changes = (
            ("security", "cipher", 2),
            ("security", "noise_mode", "group"),
            ("binding", "topology", "dynamic-unicast"),
            ("binding", "id", "DMP-test/UART-STREAM-R"),
        )
        for section, key, value in changes:
            with self.subTest(section=section, key=key, value=value):
                manifest = copy.deepcopy(self.manifests["radio-nnpsk0.json"])
                manifest[section][key] = value
                self.assert_rejected(manifest, "schema", f"$.{section}.{key}")


if __name__ == "__main__":
    unittest.main()
