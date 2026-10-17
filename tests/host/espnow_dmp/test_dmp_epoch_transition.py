"""Host-only validation tests for the physical SAMPLE-1 epoch transition runner."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

EMBEDDED_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_dmp"
sys.path.insert(0, str(EMBEDDED_DIR))

from serial_dmp_common import DmpTestError
from serial_dmp_epoch_transition import (
    load_live_pair_context,
    load_retry2_initialization_deadline,
    stale_read_violation,
    validate_busy_rotation_event,
    validate_epoch_rotation_event,
    validate_persisted_epoch,
)

SESSION = "0123456789abcdef"
NVS_CHECK = {
    "event": "nvs_epoch_check",
    "session": SESSION,
    "status": "ok",
    "namespace": "dmp_test_nvs",
    "key": "s1_epoch_test",
    "has_previous": True,
    "previous_epoch": 56,
    "reserved_epoch": 57,
}


def rotation_event(**overrides):
    event = {
        "event": "sample1_epoch_transition",
        "session": SESSION,
        "status": "ok",
        "owner_status": 0,
        "previous_epoch": 57,
        "reserved_epoch": 58,
        "new_epoch": 58,
        "sample_value": 0x55667788,
        "peer_records_before": 1,
        "peer_records_after": 0,
        "owner_active": True,
        "sample_published": True,
    }
    event.update(overrides)
    return event


class TestDmpEpochTransition(unittest.TestCase):
    def test_manifest_deadline_is_loaded_as_two_attempt_retry_window(self):
        timing = load_retry2_initialization_deadline()
        self.assertEqual("TEST-DIRECT-SAMPLE-RETRY-2", timing["profile_id"])
        self.assertEqual(2, timing["attempts"])
        self.assertEqual(12000, timing["result_deadline_ms"])
        self.assertEqual(5, timing["retry_delay_ms"])
        self.assertEqual(24010, timing["init_deadline_ms"])

    def test_valid_rotation_records_next_reserved_epoch_and_peer_fence(self):
        result = validate_epoch_rotation_event(57, rotation_event(), 0x55667788)
        self.assertEqual(
            {"previous_epoch": 57, "reserved_epoch": 58, "sample_value": 0x55667788},
            result,
        )

    def test_rotation_with_missing_reservation_is_rejected(self):
        with self.assertRaisesRegex(DmpTestError, "reserve and activate exactly"):
            validate_epoch_rotation_event(
                57,
                rotation_event(reserved_epoch=0, new_epoch=0),
                0x55667788,
            )

    def test_rotation_with_old_peer_record_still_live_is_rejected(self):
        with self.assertRaisesRegex(DmpTestError, "close the single previous-epoch peer"):
            validate_epoch_rotation_event(
                57,
                rotation_event(peer_records_after=1),
                0x55667788,
            )

    def test_rotation_with_wrong_published_value_is_rejected(self):
        with self.assertRaisesRegex(DmpTestError, "requested SAMPLE-1 value"):
            validate_epoch_rotation_event(
                57,
                rotation_event(sample_value=1),
                0x55667788,
            )

    def test_busy_before_reservation_keeps_old_owner_active(self):
        event = {
            **rotation_event(),
            "status": "busy",
            "reserved_epoch": 0,
            "new_epoch": 0,
            "owner_active": True,
            "sample_published": False,
        }
        self.assertEqual(validate_busy_rotation_event(57, event, 0x55667788), 0)

    def test_busy_after_reservation_keeps_the_same_inactive_transition(self):
        event = {
            **rotation_event(),
            "status": "busy",
            "new_epoch": 0,
            "owner_active": False,
            "sample_published": False,
        }
        self.assertEqual(validate_busy_rotation_event(57, event, 0x55667788), 58)

    def test_busy_transition_that_changes_reserved_epoch_is_rejected(self):
        event = {
            **rotation_event(),
            "status": "busy",
            "reserved_epoch": 59,
            "new_epoch": 0,
            "owner_active": False,
            "sample_published": False,
        }
        with self.assertRaisesRegex(DmpTestError, "changed the active or reserved epoch"):
            validate_busy_rotation_event(57, event, 0x55667788)

    def test_live_pair_context_requires_current_owner_reservation_without_nvs_check(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pair_dir = Path(tmpdir)
            (pair_dir / "evidence.json").write_text(json.dumps({
                "result": "PASS",
                "test_mode": "authenticated-dmp-endpoint",
                "peer_count": 1,
                "s3_node_id": 10,
                "c3_node_id": 20,
                "nvs_check_performed": False,
                "session": SESSION,
                "s3_boot_id": "a" * 16,
                "c3_boot_id": "b" * 16,
                "sample1_owner_epoch": 58,
            }), encoding="utf-8")
            (pair_dir / "events_s3.jsonl").write_text(json.dumps({
                "host_unix_time_ns": 1792268149760891800,
                "side": "s3",
                "port": "COM37",
                "event": {
                    "event": "sample1_epoch_reserved",
                    "session": SESSION,
                    "epoch": 58,
                },
            }) + "\n", encoding="utf-8")

            pair, active_epoch = load_live_pair_context(pair_dir)

        self.assertEqual(active_epoch, 58)
        self.assertEqual(pair["sample1_owner_epoch"], active_epoch)

    def test_live_pair_context_rejects_nvs_check_that_consumed_owner_epoch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pair_dir = Path(tmpdir)
            (pair_dir / "evidence.json").write_text(json.dumps({
                "result": "PASS",
                "test_mode": "authenticated-dmp-endpoint",
                "peer_count": 1,
                "s3_node_id": 10,
                "c3_node_id": 20,
                "nvs_check_performed": False,
                "session": SESSION,
                "s3_boot_id": "a" * 16,
                "c3_boot_id": "b" * 16,
                "sample1_owner_epoch": 58,
            }), encoding="utf-8")
            (pair_dir / "events_s3.jsonl").write_text("\n".join(
                json.dumps({"side": "s3", "event": event}) for event in (
                    {"event": "sample1_epoch_reserved", "session": SESSION, "epoch": 58},
                    {"event": "nvs_epoch_check", "session": SESSION},
                )
            ) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(DmpTestError, "extra NVS epoch"):
                load_live_pair_context(pair_dir)

    def test_stale_sample_read_acceptance_on_producer_is_detected(self):
        violation = stale_read_violation(
            [{"event": "rx_request", "session": SESSION, "service_id": 1}],
            [],
            SESSION,
        )
        self.assertIn("S3 accepted", violation)

    def test_stale_sample_read_result_on_reader_is_detected(self):
        violation = stale_read_violation(
            [],
            [{"event": "rx_result", "session": SESSION, "service_id": 1, "wire_status": 0}],
            SESSION,
        )
        self.assertIn("C3 received", violation)

    def test_unrelated_or_non_sample_events_do_not_count_as_stale_read_acceptance(self):
        self.assertIsNone(stale_read_violation(
            [{"event": "rx_request", "session": SESSION, "service_id": 2}],
            [{"event": "rx_result", "session": "ffffffffffffffff", "service_id": 1}],
            SESSION,
        ))

    def test_post_restart_owner_and_nvs_check_advance_after_rotation(self):
        result = validate_persisted_epoch(
            {"previous_epoch": 56, "reserved_epoch": 58, "sample_value": 0x55667788},
            {**NVS_CHECK, "previous_epoch": 59, "reserved_epoch": 60},
            SESSION,
        )
        self.assertEqual(
            {
                "rotated_epoch": 58,
                "post_reboot_owner_epoch": 59,
                "post_reboot_check_reserved_epoch": 60,
            },
            result,
        )

    def test_post_restart_missing_nvs_persistence_is_rejected(self):
        with self.assertRaisesRegex(DmpTestError, "did not reserve from the epoch committed"):
            validate_persisted_epoch(
                {"previous_epoch": 56, "reserved_epoch": 58, "sample_value": 0x55667788},
                {**NVS_CHECK, "previous_epoch": 58, "reserved_epoch": 59},
                SESSION,
            )


if __name__ == "__main__":
    unittest.main()
