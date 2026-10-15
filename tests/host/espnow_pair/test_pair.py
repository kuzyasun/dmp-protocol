import sys
import unittest
from pathlib import Path

HARDWARE_RUNNER_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_pair"
sys.path.insert(0, str(HARDWARE_RUNNER_DIR))

from serial_pair import PairTestError, parse_json_event, validate_pair_events, validate_ready_events


S3_MAC = "28:37:2f:75:5d:64"
C3_MAC = "20:6e:f1:b0:f0:2c"
SESSION = "0123456789abcdef"
OLD_SESSION = "fedcba9876543210"


def ready(target, mac):
    return {
        "event": "ready",
        "target": target,
        "idf": "ESP-IDF v6.1",
        "firmware": "dmp-espnow-pair/0.1",
        "mac": mac,
        "channel": 1,
        "decoded_core_mtu_bytes": 256,
        "stream_r_encoded_mtu_bytes": 263,
        "espnow_v1_payload_mtu_bytes": 250,
        "peer_capacity": 3 if target == "esp32s3" else 1,
        "test_mode": "unauthenticated-core-echo",
    }


def passing_events(count=2, session=SESSION):
    events = [
        ("s3", ready("esp32s3", S3_MAC)),
        ("c3", ready("esp32c3", C3_MAC)),
        ("s3", {"event": "session_set", "session": session, "target": "esp32s3", "mac": S3_MAC}),
        ("c3", {"event": "session_set", "session": session, "target": "esp32c3", "mac": C3_MAC}),
        ("s3", {"event": "peer_added", "session": session, "peer_mac": C3_MAC, "peer_count": 1}),
        ("c3", {"event": "peer_added", "session": session, "peer_mac": S3_MAC, "peer_count": 1}),
        ("c3", {"event": "echo_mode", "session": session, "enabled": True}),
        ("s3", {"event": "run_started", "session": session, "count": count,
                "payload_bytes": 64, "peer_count": 1}),
    ]
    for seq in range(1, count + 1):
        events.extend([
            ("s3", {"event": "tx_done", "session": session, "seq": seq, "status": "success"}),
            ("c3", {"event": "rx_valid", "session": session, "seq": seq, "src_mac": S3_MAC, "core_frame_bytes": 74}),
            ("c3", {"event": "echo_tx_done", "session": session, "seq": seq, "peer_mac": S3_MAC, "status": "success"}),
            ("s3", {"event": "round_trip", "session": session, "seq": seq, "peer_mac": C3_MAC,
                    "tx_done": True, "echo_match": True, "core_frame_bytes": 74}),
        ])
    events.append(("s3", {"event": "run_done", "session": session, "pass": True, "completed": count,
                          "payload_bytes": 64, "peer_count": 1, "max_core_frame_bytes": 74}))
    events.append(("c3", {"event": "stats", "session": session, "echo_rx": count, "echo_tx_ok": count,
                          "echo_tx_failed": 0}))
    return events


class SerialPairTests(unittest.TestCase):
    def test_parses_firmware_json_but_ignores_boot_text(self):
        self.assertIsNone(parse_json_event(b"I (12) wifi: start\r\n"))
        self.assertEqual(parse_json_event(b'{"event":"ready","target":"esp32s3"}\r\n'),
                         {"event": "ready", "target": "esp32s3"})

    def test_parses_json_event_after_unterminated_boot_text(self):
        line = (b'I (143) esp_image: segment 4: paddr=000bb37c vaddr=40382fd4 size'
                b'{"event":"ready","target":"esp32c3"}\r\n')
        self.assertEqual(parse_json_event(line), {"event": "ready", "target": "esp32c3"})
        self.assertIsNone(parse_json_event(b"boot noise {incomplete json\r\n"))

    def test_validates_complete_s3_c3_pair_trace(self):
        result = validate_pair_events(passing_events(), 2, 64, SESSION)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["s3_mac"], S3_MAC)
        self.assertEqual(result["c3_mac"], C3_MAC)
        self.assertEqual(result["round_trips"], 2)

    def test_rejects_duplicate_or_missing_sequence(self):
        events = passing_events()
        events = [(side, {**event, "seq": 1} if side == "s3" and event.get("event") == "round_trip" and event.get("seq") == 2 else event)
                  for side, event in events]
        with self.assertRaisesRegex(PairTestError, "sequence set/order"):
            validate_pair_events(events, 2, 64, SESSION)

    def test_rejects_incorrect_test_mode_label(self):
        events = passing_events()
        events = [(side, {**event, "test_mode": "sec1"} if side == "c3" and event.get("event") == "ready" else event)
                  for side, event in events]
        with self.assertRaisesRegex(PairTestError, "test mode"):
            validate_pair_events(events, 2, 64, SESSION)

    def test_rejects_wrong_peer_mac_even_when_core_frames_parse(self):
        events = passing_events()
        events = [(side, {**event, "src_mac": "88:56:a6:63:c2:78"}
                   if side == "c3" and event.get("event") == "rx_valid" and event.get("seq") == 1
                   else event) for side, event in events]
        with self.assertRaisesRegex(PairTestError, "unexpected MAC"):
            validate_pair_events(events, 2, 64, SESSION)

    def test_rejects_failed_mac_completion(self):
        events = passing_events()
        events = [(side, {**event, "status": "failed"}
                   if side == "s3" and event.get("event") == "tx_done" and event.get("seq") == 1
                   else event) for side, event in events]
        with self.assertRaisesRegex(PairTestError, "failed ESP-NOW"):
            validate_pair_events(events, 2, 64, SESSION)

    def test_rejects_core_frame_over_espnow_packet_bound(self):
        events = passing_events()
        events = [(side, {**event, "core_frame_bytes": 251}
                   if side == "c3" and event.get("event") == "rx_valid" and event.get("seq") == 1
                   else event) for side, event in events]
        with self.assertRaisesRegex(PairTestError, "packet bound"):
            validate_pair_events(events, 2, 64, SESSION)

    def test_rejects_mismatched_c3_echo_counters(self):
        events = passing_events()
        events = [(side, {**event, "echo_tx_ok": 1}
                   if side == "c3" and event.get("event") == "stats" else event)
                  for side, event in events]
        with self.assertRaisesRegex(PairTestError, "echo counters"):
            validate_pair_events(events, 2, 64, SESSION)

    def test_old_passing_trace_cannot_mask_current_failed_run(self):
        events = passing_events(session=OLD_SESSION)
        events.extend([
            ("s3", {"event": "session_set", "session": SESSION,
                     "target": "esp32s3", "mac": S3_MAC}),
            ("c3", {"event": "session_set", "session": SESSION,
                     "target": "esp32c3", "mac": C3_MAC}),
            ("s3", {"event": "peer_added", "session": SESSION, "peer_mac": C3_MAC}),
            ("c3", {"event": "peer_added", "session": SESSION, "peer_mac": S3_MAC}),
            ("c3", {"event": "echo_mode", "session": SESSION, "enabled": True}),
            ("s3", {"event": "run_started", "session": SESSION,
                     "count": 2, "payload_bytes": 64, "peer_count": 1}),
            ("s3", {"event": "run_done", "session": SESSION,
                     "pass": False, "completed": 0, "peer_count": 1,
                     "reason": "round-trip-timeout"}),
        ])
        with self.assertRaisesRegex(PairTestError, "complete passing run"):
            validate_pair_events(events, 2, 64, SESSION)

    def test_ready_requires_distinct_targets_and_exact_mtu_labels(self):
        valid = [("s3", ready("esp32s3", S3_MAC)), ("c3", ready("esp32c3", C3_MAC))]
        self.assertEqual(set(validate_ready_events(valid)), {"s3", "c3"})
        invalid = [(side, {**event, "stream_r_encoded_mtu_bytes": 256}
                    if side == "s3" else event) for side, event in valid]
        with self.assertRaisesRegex(PairTestError, "MTU report"):
            validate_ready_events(invalid)
        invalid_capacity = [(side, {**event, "peer_capacity": 4}
                             if side == "s3" else event) for side, event in valid]
        with self.assertRaisesRegex(PairTestError, "peer capacity"):
            validate_ready_events(invalid_capacity)


if __name__ == "__main__":
    unittest.main()
