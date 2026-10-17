"""Host tests for exact manifest geometry, MTU separation, and SHA-256 digests."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

EMBEDDED_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_dmp"
PROFILES_DIR = Path(__file__).resolve().parents[3] / "profiles" / "deployments"
FIRMWARE_MAIN = EMBEDDED_DIR / "main" / "main.c"
DMP_COMPONENT_CMAKE = Path(__file__).resolve().parents[2] / "embedded" / "components" / "dmp" / "CMakeLists.txt"
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

    def test_embedded_profile_timing_matches_manifests(self):
        source = FIRMWARE_MAIN.read_text(encoding="utf-8")
        fields = (
            "frame_tx_ms",
            "queue_ms",
            "forward_delay_ms",
            "return_delay_ms",
            "receipt_delay_ms",
            "burst_span_ms",
            "feedback_guard_ms",
            "feedback_delay_ms",
            "response_timeout_ms",
            "send_horizon_ms",
            "max_bursts",
            "max_probes",
            "max_status",
            "jitter_ms",
            "record_margin_ms",
            "collect_ms",
            "assembly_ms",
            "dedup_ms",
            "rejection_ms",
            "result_cache_ms",
            "result_deadline_ms",
            "correlation_ms",
            "tombstone_ms",
            "late_result_ms",
            "receipt_limit",
        )
        retry2_path = PROFILES_DIR / "test-direct-sample-retry-2-nnpsk0.json"
        multi_path = PROFILES_DIR / "test-direct-multi-peer-nnpsk0.json"
        timing_start = source.index(
            "    /* Keep runtime scheduling bounds",
            source.index("static bool init_dmp_stack"),
        )
        retry_start = source.index(
            '    if (strcmp(profile_name, "retry-2") == 0) {\n'
            "        g_profile_config.queue_ms",
            timing_start,
        )
        multi_start = source.index(
            "    } else {\n        g_profile_config.queue_ms = 1000U;",
            retry_start,
        )
        timing_end = source.index(
            "\n    }\n\n    g_profile_config.recovery[0]",
            multi_start,
        )
        common_source = source[timing_start:retry_start]
        timing_sources = {
            "retry-2": source[retry_start:multi_start],
            "multi-peer": source[multi_start:timing_end],
        }

        for profile_name, manifest_path in (
            ("retry-2", retry2_path),
            ("multi-peer", multi_path),
        ):
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            expected = {
                "frame_tx_ms": manifest["binding"]["frame_tx_ms"],
                **{field: manifest["timing"][field] for field in fields if field != "frame_tx_ms"},
            }
            self.assertEqual(set(expected), set(fields))
            for field, value in expected.items():
                assignment = rf"g_profile_config\.{field}\s*=\s*{value}U;"
                with self.subTest(profile=profile_name, field=field):
                    self.assertRegex(common_source + timing_sources[profile_name], assignment)

    def test_embedded_handshake_buffers_cover_encoded_mtu(self):
        source = FIRMWARE_MAIN.read_text(encoding="utf-8")
        match = re.search(
            r"#define QUAL_STREAM_R_ENCODED_MTU_BYTES\s+(\d+)U",
            source,
        )
        self.assertIsNotNone(match)
        encoded_mtu = int(match.group(1))
        for manifest_name in (
            "test-direct-sample-retry-2-nnpsk0.json",
            "test-direct-multi-peer-nnpsk0.json",
        ):
            manifest = json.loads((PROFILES_DIR / manifest_name).read_text(encoding="utf-8"))
            self.assertEqual(encoded_mtu, manifest["binding"]["encoded_mtu"])
        self.assertRegex(
            source,
            r"uint8_t\s+hs_buffer_bytes\s*\[DMP_HS_TX_SLOT_MAX\]"
            r"\[QUAL_STREAM_R_ENCODED_MTU_BYTES\];",
        )

    def test_initial_embedded_peer_uses_endpoint_seeded_slot(self):
        source = FIRMWARE_MAIN.read_text(encoding="utf-8")
        register_start = source.index("        /* Register in DMP endpoint */")
        register_end = source.index("        /* Setup handshake structures for peer */", register_start)
        register_block = source[register_start:register_end]
        endpoint_source = (Path(__file__).resolve().parents[3] / "src" / "endpoint" / "endpoint.c").read_text(
            encoding="utf-8"
        )

        self.assertIn("if (peer_idx == 0U)", register_block)
        self.assertIn("out_handle = g_endpoint.peers[0].handle", register_block)
        self.assertIn("dmp_endpoint_add_peer(&g_endpoint", register_block)
        self.assertIn("endpoint->peers[0].live = 1U", endpoint_source)
        self.assertIn("endpoint->peer_count = 1U", endpoint_source)
        self.assertIn("endpoint->profile.peers <= 1U", endpoint_source)

    def test_qualification_build_exposes_handshake_schedule_failure_stage(self):
        component_cmake = DMP_COMPONENT_CMAKE.read_text(encoding="utf-8")
        project_cmake = (EMBEDDED_DIR / "CMakeLists.txt").read_text(encoding="utf-8")
        firmware = FIRMWARE_MAIN.read_text(encoding="utf-8")
        handshake = (Path(__file__).resolve().parents[3] / "src" / "security" / "handshake.c").read_text(
            encoding="utf-8"
        )

        self.assertIn("if(DMP_ESP_NOW_QUAL_DIAGNOSTICS)", component_cmake)
        self.assertIn("DMP_HANDSHAKE_QUAL_DIAGNOSTICS=1", component_cmake)
        self.assertIn("set(DMP_ESP_NOW_QUAL_DIAGNOSTICS ON CACHE BOOL", project_cmake)
        self.assertIn("dmp_handshake_qual_diagnostic", firmware)
        self.assertIn('"provider-write"', handshake)
        self.assertIn('"boot-epoch-hash"', handshake)
        self.assertIn("hs_cfg.budget.episode_work = 1000U", firmware)

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
            "boot_id": "a" * 16,
            "reset_reason": "power_on",
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
