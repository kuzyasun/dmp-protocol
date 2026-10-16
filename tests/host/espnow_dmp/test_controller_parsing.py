"""Host tests for JSON event parsing, framing, and boot noise resilience."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

EMBEDDED_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_dmp"
sys.path.insert(0, str(EMBEDDED_DIR))

from serial_dmp_common import parse_json_event


class TestControllerParsing(unittest.TestCase):
    def test_parse_clean_json_event(self):
        line = b'{"event":"ready","target":"esp32s3","mac":"28:37:2f:75:5d:64"}\r\n'
        parsed = parse_json_event(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.get("event"), "ready")
        self.assertEqual(parsed.get("target"), "esp32s3")
        self.assertEqual(parsed.get("mac"), "28:37:2f:75:5d:64")

    def test_parse_json_with_leading_boot_noise(self):
        line = (
            b"I (143) esp_image: segment 4: paddr=000bb37c vaddr=40382fd4 size"
            b'{"event":"ready","target":"esp32c3","mac":"20:6e:f1:b0:f0:2c"}\r\n'
        )
        parsed = parse_json_event(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.get("event"), "ready")
        self.assertEqual(parsed.get("target"), "esp32c3")

    def test_ignore_plain_boot_noise_without_json(self):
        line = b"I (234) wifi: mode : sta (28:37:2f:75:5d:64)\r\n"
        self.assertIsNone(parse_json_event(line))

    def test_ignore_malformed_or_truncated_json(self):
        line = b'{"event":"transfer_started","session":"0123456789abcdef",\r\n'
        self.assertIsNone(parse_json_event(line))

    def test_ignore_json_without_event_field(self):
        line = b'{"status":"ok","value":42}\r\n'
        self.assertIsNone(parse_json_event(line))

    def test_ignore_empty_or_whitespace_lines(self):
        self.assertIsNone(parse_json_event(b""))
        self.assertIsNone(parse_json_event(b"   \r\n"))
        self.assertIsNone(parse_json_event(b"\n"))

    def test_resilience_to_non_utf8_binary_garbage(self):
        line = b"\xaa\xff\x00\xfe\x12{\"event\":\"stats\",\"tx_frames\":10}\r\n"
        parsed = parse_json_event(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.get("event"), "stats")
        self.assertEqual(parsed.get("tx_frames"), 10)


if __name__ == "__main__":
    unittest.main()
