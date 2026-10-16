"""Host tests for exact manifest geometry, MTU separation, and SHA-256 digests."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

EMBEDDED_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_dmp"
PROFILES_DIR = Path(__file__).resolve().parents[3] / "profiles" / "deployments"
sys.path.insert(0, str(EMBEDDED_DIR))

from serial_dmp_common import (
    MULTI_PEER_PROFILE_HASH,
    RETRY_2_PROFILE_HASH,
    validate_ready_event,
)


class TestProfileGeometry(unittest.TestCase):
    def test_manifest_digests_match_constants(self):
        retry2_path = PROFILES_DIR / "test-direct-sample-retry-2-nnpsk0.json"
        multipeer_path = PROFILES_DIR / "test-direct-multi-peer-nnpsk0.json"
        digests_path = PROFILES_DIR / "digests.json"

        self.assertTrue(retry2_path.is_file(), f"Missing {retry2_path}")
        self.assertTrue(multipeer_path.is_file(), f"Missing {multipeer_path}")
        self.assertTrue(digests_path.is_file(), f"Missing {digests_path}")

        # Compute file SHA-256
        retry2_hash = hashlib.sha256(retry2_path.read_bytes()).hexdigest()
        multipeer_hash = hashlib.sha256(multipeer_path.read_bytes()).hexdigest()

        self.assertEqual(retry2_hash, RETRY_2_PROFILE_HASH)
        self.assertEqual(multipeer_hash, MULTI_PEER_PROFILE_HASH)

        digests_data = json.loads(digests_path.read_text(encoding="utf-8"))
        self.assertEqual(digests_data["manifests"]["test-direct-sample-retry-2-nnpsk0.json"], RETRY_2_PROFILE_HASH)
        self.assertEqual(digests_data["manifests"]["test-direct-multi-peer-nnpsk0.json"], MULTI_PEER_PROFILE_HASH)

    def test_retry_2_manifest_geometry(self):
        retry2_path = PROFILES_DIR / "test-direct-sample-retry-2-nnpsk0.json"
        data = json.loads(retry2_path.read_text(encoding="utf-8"))

        binding = data["binding"]
        self.assertEqual(binding["forward_mtu"], 256)
        self.assertEqual(binding["return_mtu"], 256)
        self.assertEqual(binding["encoded_mtu"], 263)

        limits = data["limits"]
        self.assertEqual(limits["peers"], 1)
        self.assertEqual(limits["message_bytes"], 1024)
        self.assertEqual(limits["chunk_bytes"], 64)
        self.assertEqual(limits["fragments"], 16)

        services = {s["id"]: s for s in data["services"]}
        self.assertIn(1, services)
        self.assertEqual(services[1]["request_bytes"], 1)
        self.assertEqual(services[1]["result_bytes"], 17)

    def test_multi_peer_manifest_geometry(self):
        multipeer_path = PROFILES_DIR / "test-direct-multi-peer-nnpsk0.json"
        data = json.loads(multipeer_path.read_text(encoding="utf-8"))

        binding = data["binding"]
        self.assertEqual(binding["forward_mtu"], 256)
        self.assertEqual(binding["return_mtu"], 256)
        self.assertEqual(binding["encoded_mtu"], 263)

        limits = data["limits"]
        self.assertEqual(limits["peers"], 4)
        self.assertEqual(limits["message_bytes"], 4096)
        self.assertEqual(limits["chunk_bytes"], 128)
        self.assertEqual(limits["fragments"], 32)

        services = {s["id"]: s for s in data["services"]}
        self.assertIn(2, services)
        self.assertEqual(services[2]["request_bytes"], 4096)
        self.assertEqual(services[2]["result_bytes"], 4096)

    def test_distinct_mtu_reporting(self):
        event = {
            "event": "ready",
            "target": "esp32s3",
            "idf": "ESP-IDF v6.1",
            "firmware": "dmp-espnow-dmp/0.1",
            "mac": "28:37:2f:75:5d:64",
            "channel": 1,
            "decoded_core_mtu_bytes": 256,
            "stream_r_encoded_mtu_bytes": 263,
            "espnow_v1_payload_mtu_bytes": 250,
            "espnow_v2_payload_mtu_bytes": 1470,
            "espnow_version": 2,
            "peer_capacity": 4,
            "test_mode": "authenticated-dmp-endpoint",
        }
        res = validate_ready_event(event, "esp32s3")
        self.assertEqual(res["decoded_core_mtu_bytes"], 256)
        self.assertEqual(res["stream_r_encoded_mtu_bytes"], 263)
        self.assertEqual(res["espnow_v1_payload_mtu_bytes"], 250)
        self.assertEqual(res["espnow_v2_payload_mtu_bytes"], 1470)
        self.assertEqual(res["espnow_version"], 2)


if __name__ == "__main__":
    unittest.main()
