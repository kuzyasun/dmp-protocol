"""Host tests for peer identity mapping, MAC validation, and capacity bounds."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

EMBEDDED_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_dmp"
sys.path.insert(0, str(EMBEDDED_DIR))

from serial_dmp_common import MAC_PATTERN, DmpTestError, validate_ready_event


class TestPeerMapping(unittest.TestCase):
    def test_mac_pattern_valid_cases(self):
        self.assertTrue(MAC_PATTERN.match("28:37:2f:75:5d:64"))
        self.assertTrue(MAC_PATTERN.match("20:6E:F1:B0:F0:2C"))
        self.assertTrue(MAC_PATTERN.match("00:11:22:33:44:55"))

    def test_mac_pattern_invalid_cases(self):
        self.assertFalse(MAC_PATTERN.match("28:37:2f:75:5d"))  # too short
        self.assertFalse(MAC_PATTERN.match("28:37:2f:75:5d:64:11"))  # too long
        self.assertFalse(MAC_PATTERN.match("28-37-2f-75-5d-64"))  # hyphens
        self.assertFalse(MAC_PATTERN.match("28:37:2f:75:5d:zz"))  # non-hex
        self.assertFalse(MAC_PATTERN.match(""))

    def test_ready_event_rejects_invalid_mac(self):
        event = {
            "event": "ready",
            "target": "esp32s3",
            "idf": "ESP-IDF v6.1",
            "firmware": "dmp-espnow-dmp/0.1",
            "boot_id": "a" * 16,
            "reset_reason": "power_on",
            "mac": "not-a-mac",
            "channel": 1,
            "decoded_core_mtu_bytes": 256,
            "stream_r_encoded_mtu_bytes": 263,
            "espnow_v1_payload_mtu_bytes": 250,
            "espnow_v2_payload_mtu_bytes": 1470,
            "espnow_version": 2,
            "peer_capacity": 4,
            "test_mode": "authenticated-dmp-endpoint",
        }
        with self.assertRaisesRegex(DmpTestError, "Invalid station MAC"):
            validate_ready_event(event, "esp32s3")

    def test_ready_event_rejects_wrong_target(self):
        event = {
            "event": "ready",
            "target": "esp32c3",
            "idf": "ESP-IDF v6.1",
            "firmware": "dmp-espnow-dmp/0.1",
            "boot_id": "b" * 16,
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
        with self.assertRaisesRegex(DmpTestError, "Target mismatch"):
            validate_ready_event(event, "esp32s3")

    def test_ready_event_rejects_missing_mtu_reporting(self):
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
            # missing espnow_v2_payload_mtu_bytes
            "espnow_version": 2,
            "peer_capacity": 4,
            "test_mode": "authenticated-dmp-endpoint",
        }
        with self.assertRaisesRegex(DmpTestError, "ESP-NOW v2 payload MTU"):
            validate_ready_event(event, "esp32s3")


if __name__ == "__main__":
    unittest.main()
