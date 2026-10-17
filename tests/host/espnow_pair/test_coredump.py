import unittest
import sys
from pathlib import Path

HARDWARE_RUNNER_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_pair"
sys.path.insert(0, str(HARDWARE_RUNNER_DIR))

import struct

from serial_coredump import (
    DEFAULT_READ_BAUD,
    CoreDumpTestError,
    build_argument_parser,
    extract_core_elf,
    validate_capture_events,
)


class CoreDumpCaptureTests(unittest.TestCase):
    def test_default_read_baud_uses_reliable_capture_rate(self):
        args = build_argument_parser().parse_args(["--port", "COM1", "--target", "esp32c3"])
        self.assertEqual(DEFAULT_READ_BAUD, 115200)
        self.assertEqual(args.read_baud, DEFAULT_READ_BAUD)

    def test_read_baud_can_be_overridden(self):
        args = build_argument_parser().parse_args(
            ["--port", "COM1", "--target", "esp32c3", "--read-baud", "460800"]
        )
        self.assertEqual(args.read_baud, 460800)

    def test_extracts_length_prefixed_elf(self):
        core = b"\x7fELFtest-core"
        partition = struct.pack("<I", len(core)) + b"\x04\x01\x05\x00\x04\x00\x00\x00" + core
        self.assertEqual(extract_core_elf(partition), core)

    def test_rejects_invalid_partition_length(self):
        with self.assertRaisesRegex(CoreDumpTestError, "outside the captured partition"):
            extract_core_elf(struct.pack("<I", 64) + bytes(20))

    def test_rejects_non_elf_payload(self):
        partition = struct.pack("<I", 4) + bytes(8) + b"data"
        with self.assertRaisesRegex(CoreDumpTestError, "does not contain an ELF"):
            extract_core_elf(partition)

    def test_accepts_abort_followed_by_target_reboot(self):
        events = [
            {"event": "ready", "target": "esp32s3"},
            {"event": "core_dump_test", "action": "intentional-abort"},
            {"event": "ready", "target": "esp32s3"},
        ]
        result = validate_capture_events(events, "esp32s3")
        self.assertTrue(result["post_abort_ready"])

    def test_rejects_missing_intentional_abort(self):
        events = [{"event": "ready", "target": "esp32c3"}]
        with self.assertRaisesRegex(CoreDumpTestError, "did not acknowledge"):
            validate_capture_events(events, "esp32c3")

    def test_rejects_missing_post_abort_reboot(self):
        events = [
            {"event": "ready", "target": "esp32c3"},
            {"event": "core_dump_test", "action": "intentional-abort"},
        ]
        with self.assertRaisesRegex(CoreDumpTestError, "did not reboot"):
            validate_capture_events(events, "esp32c3")


if __name__ == "__main__":
    unittest.main()
