"""Host tests for SAMPLE-1 NVS epoch storage validation and fail-closed handling."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

EMBEDDED_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_dmp"
sys.path.insert(0, str(EMBEDDED_DIR))

from serial_dmp_common import (
    DmpTestError,
    MULTI_PEER_EPOCH_NVS_KEY,
    validate_nvs_check,
)

SESSION = "0123456789abcdef"


class TestNvsCheck(unittest.TestCase):
    def test_nvs_first_boot_success(self):
        event = {
            "event": "nvs_epoch_check",
            "session": SESSION,
            "status": "ok",
            "namespace": "dmp_test_nvs",
            "key": "s1_epoch_test",
            "has_previous": False,
            "previous_epoch": 0,
            "reserved_epoch": 1,
        }
        validated = validate_nvs_check(event, SESSION)
        self.assertEqual(validated["status"], "ok")
        self.assertEqual(validated["reserved_epoch"], 1)

    def test_nvs_subsequent_boot_success(self):
        event = {
            "event": "nvs_epoch_check",
            "session": SESSION,
            "status": "ok",
            "namespace": "dmp_test_nvs",
            "key": "s1_epoch_test",
            "has_previous": True,
            "previous_epoch": 5,
            "reserved_epoch": 6,
        }
        validated = validate_nvs_check(event, SESSION)
        self.assertEqual(validated["status"], "ok")
        self.assertEqual(validated["reserved_epoch"], 6)

    def test_multi_peer_profile_uses_principal_specific_epoch_key(self):
        event = {
            "event": "nvs_epoch_check",
            "session": SESSION,
            "status": "ok",
            "namespace": "dmp_test_nvs",
            "key": MULTI_PEER_EPOCH_NVS_KEY,
            "has_previous": False,
            "previous_epoch": 0,
            "reserved_epoch": 1,
        }
        validated = validate_nvs_check(
            event, SESSION, expected_key=MULTI_PEER_EPOCH_NVS_KEY
        )
        self.assertEqual(validated["key"], MULTI_PEER_EPOCH_NVS_KEY)

    def test_multi_peer_profile_rejects_pair_epoch_key(self):
        event = {
            "event": "nvs_epoch_check",
            "session": SESSION,
            "status": "ok",
            "namespace": "dmp_test_nvs",
            "key": "s1_epoch_test",
            "has_previous": False,
            "previous_epoch": 0,
            "reserved_epoch": 1,
        }
        with self.assertRaisesRegex(DmpTestError, "Unexpected NVS key"):
            validate_nvs_check(
                event, SESSION, expected_key=MULTI_PEER_EPOCH_NVS_KEY
            )

    def test_nvs_rejects_monotonic_violation(self):
        event = {
            "event": "nvs_epoch_check",
            "session": SESSION,
            "status": "ok",
            "namespace": "dmp_test_nvs",
            "key": "s1_epoch_test",
            "has_previous": True,
            "previous_epoch": 10,
            "reserved_epoch": 10,
        }
        with self.assertRaisesRegex(DmpTestError, "Monotonic violation"):
            validate_nvs_check(event, SESSION)

    def test_nvs_rejects_fail_open(self):
        event = {
            "event": "nvs_epoch_check",
            "session": SESSION,
            "status": "fail_open",
            "error": 4354,
        }
        with self.assertRaisesRegex(DmpTestError, "failed to open storage"):
            validate_nvs_check(event, SESSION)

    def test_nvs_rejects_fail_reserve(self):
        event = {
            "event": "nvs_epoch_check",
            "session": SESSION,
            "status": "fail_reserve",
            "port_error": 2,
        }
        with self.assertRaisesRegex(DmpTestError, "failed to reserve epoch"):
            validate_nvs_check(event, SESSION)

    def test_nvs_rejects_fail_monotonic_status(self):
        event = {
            "event": "nvs_epoch_check",
            "session": SESSION,
            "status": "fail_monotonic",
            "previous_epoch": 5,
            "reserved_epoch": 4,
        }
        with self.assertRaisesRegex(DmpTestError, "violated monotonicity"):
            validate_nvs_check(event, SESSION)

    def test_nvs_rejects_wrong_namespace(self):
        event = {
            "event": "nvs_epoch_check",
            "session": SESSION,
            "status": "ok",
            "namespace": "wrong_ns",
            "key": "s1_epoch_test",
            "has_previous": False,
            "previous_epoch": 0,
            "reserved_epoch": 1,
        }
        with self.assertRaisesRegex(DmpTestError, "Unexpected NVS namespace"):
            validate_nvs_check(event, SESSION)

    def test_nvs_rejects_wrong_session(self):
        event = {
            "event": "nvs_epoch_check",
            "session": "fedcba9876543210",
            "status": "ok",
            "namespace": "dmp_test_nvs",
            "key": "s1_epoch_test",
            "has_previous": False,
            "previous_epoch": 0,
            "reserved_epoch": 1,
        }
        with self.assertRaisesRegex(DmpTestError, "session mismatch"):
            validate_nvs_check(event, SESSION)


if __name__ == "__main__":
    unittest.main()
