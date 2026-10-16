"""Host tests for authenticated S3/C3 pair qualification event validation."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

EMBEDDED_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_dmp"
sys.path.insert(0, str(EMBEDDED_DIR))

from serial_dmp_common import (
    PAIR_CONTROLLER_NODE_ID,
    PAIR_PEER_NODE_ID,
    DmpTestError,
    RETRY_2_PROFILE_HASH,
)
from serial_dmp_pair import run_dmp_pair, validate_dmp_pair_events

S3_MAC = "28:37:2f:75:5d:64"
C3_MAC = "20:6e:f1:b0:f0:2c"
SESSION = "0123456789abcdef"


def make_ready(target: str, mac: str, espnow_version: int = 2) -> dict:
    return {
        "event": "ready",
        "target": target,
        "idf": "ESP-IDF v6.1",
        "firmware": "dmp-espnow-dmp/0.1",
        "mac": mac,
        "channel": 1,
        "decoded_core_mtu_bytes": 256,
        "stream_r_encoded_mtu_bytes": 263,
        "espnow_v1_payload_mtu_bytes": 250,
        "espnow_v2_payload_mtu_bytes": 1470,
        "espnow_version": espnow_version,
        "peer_capacity": 4,
        "test_mode": "authenticated-dmp-endpoint",
    }


def make_passing_pair_events(
    transfer_bytes: int = 4096,
    session: str = SESSION,
    count: int = 1,
    bidirectional: bool = False,
) -> list[tuple[str, dict]]:
    fragments = (transfer_bytes + 127) // 128
    events = [
        ("s3", make_ready("esp32s3", S3_MAC)),
        ("c3", make_ready("esp32c3", C3_MAC)),
        ("s3", {"event": "session_set", "session": session, "target": "esp32s3", "mac": S3_MAC}),
        ("c3", {"event": "session_set", "session": session, "target": "esp32c3", "mac": C3_MAC}),
        ("s3", {"event": "role_set", "session": session, "role": "controller", "profile": "retry-2", "profile_hash": RETRY_2_PROFILE_HASH, "node_id": PAIR_CONTROLLER_NODE_ID, "handshake_scratch_slots": 1}),
        ("c3", {"event": "role_set", "session": session, "role": "peer", "profile": "retry-2", "profile_hash": RETRY_2_PROFILE_HASH, "node_id": PAIR_PEER_NODE_ID, "handshake_scratch_slots": 1}),
        ("s3", {"event": "peer_added", "session": session, "peer_mac": C3_MAC, "node_id": PAIR_PEER_NODE_ID, "peer_handle": 0, "peer_count": 1}),
        ("c3", {"event": "peer_added", "session": session, "peer_mac": S3_MAC, "node_id": PAIR_CONTROLLER_NODE_ID, "peer_handle": 0, "peer_count": 1}),
        ("s3", {
            "event": "nvs_epoch_check",
            "session": session,
            "status": "ok",
            "namespace": "dmp_test_nvs",
            "key": "s1_epoch_test",
            "has_previous": True,
            "previous_epoch": 1,
            "reserved_epoch": 2,
        }),
        ("s3", {"event": "handshake_started", "session": session, "peer_mac": C3_MAC, "peer_handle": 0}),
        ("s3", {"event": "tx_done", "session": session, "peer_mac": C3_MAC, "peer_handle": 0, "frame_bytes": 100, "status": "success"}),
        ("c3", {"event": "tx_done", "session": session, "peer_mac": S3_MAC, "peer_handle": 0, "frame_bytes": 100, "status": "success"}),
        ("s3", {"event": "handshake_done", "session": session, "peer_mac": C3_MAC, "peer_handle": 0, "status": "success"}),
        ("c3", {"event": "handshake_done", "session": session, "peer_mac": S3_MAC, "peer_handle": 0, "status": "success"}),
        ("c3", {"event": "sample_read_submitted", "session": session, "peer_handle": 0, "status": 0}),
        ("c3", {"event": "rx_result", "session": session, "peer_handle": 0, "service_id": 1, "wire_status": 0, "bytes": 17}),
        ("s3", {"event": "v2_frame_emitted", "session": session, "peer_handle": 0, "decoded_bytes": 256, "encoded_bytes": 258, "authenticated": False}),
        ("c3", {"event": "v2_frame_received", "session": session, "peer_handle": 0, "decoded_bytes": 256, "encoded_bytes": 258, "authenticated": False, "classification": "raw-v2-capability-probe"}),
    ]
    for _ in range(count):
        # Forward: S3 -> C3
        events.append(("s3", {"event": "transfer_started", "session": session, "peer_handle": 0, "peer_mac": C3_MAC, "bytes": transfer_bytes, "chunk_bytes": 128, "fragments": fragments}))
        for _ in range(fragments):
            events.append(("s3", {"event": "tx_done", "session": session, "peer_mac": C3_MAC, "peer_handle": 0, "frame_bytes": 168, "status": "success"}))
        events.append(("c3", {
            "event": "rx_assembled",
            "session": session,
            "peer_handle": 0,
            "service_id": 2,
            "bytes": transfer_bytes,
            "fragments": fragments,
            "payload_match": True,
            "max_frame_bytes": 168,
        }))
        if bidirectional:
            # Reverse: C3 -> S3
            events.append(("c3", {"event": "transfer_started", "session": session, "peer_handle": 0, "peer_mac": S3_MAC, "bytes": transfer_bytes, "chunk_bytes": 128, "fragments": fragments}))
            for _ in range(fragments):
                events.append(("c3", {"event": "tx_done", "session": session, "peer_mac": S3_MAC, "peer_handle": 0, "frame_bytes": 168, "status": "success"}))
            events.append(("s3", {
                "event": "rx_assembled",
                "session": session,
                "peer_handle": 0,
                "service_id": 2,
                "bytes": transfer_bytes,
                "fragments": fragments,
                "payload_match": True,
                "max_frame_bytes": 168,
            }))
    return events


class TestDmpPair(unittest.TestCase):
    def test_serial_runner_cli_help(self):
        result = subprocess.run(
            [sys.executable, str(EMBEDDED_DIR / "serial_dmp_pair.py"), "--help"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--s3-port", result.stdout)
        self.assertIn("--c3-port", result.stdout)

    def test_passing_pair_events(self):
        events = make_passing_pair_events(4096)
        res = validate_dmp_pair_events(events, 4096, SESSION)
        self.assertEqual(res["result"], "PASS")
        self.assertEqual(res["transfer_bytes"], 4096)
        self.assertEqual(res["chunk_bytes"], 128)
        self.assertEqual(res["fragments"], 32)
        self.assertEqual(res["decoded_core_mtu_bytes"], 256)
        self.assertEqual(res["stream_r_encoded_mtu_bytes"], 263)
        self.assertEqual(res["espnow_v1_payload_mtu_bytes"], 250)
        self.assertEqual(res["espnow_v2_payload_mtu_bytes"], 1470)

    def test_passing_bidirectional_pair_events(self):
        events = make_passing_pair_events(4096, count=2, bidirectional=True)
        res = validate_dmp_pair_events(events, 4096, SESSION, count=2, bidirectional=True)
        self.assertEqual(res["result"], "PASS")
        self.assertEqual(res["transfer_bytes"], 4096)

    def test_rejects_bidirectional_missing_reverse(self):
        events = make_passing_pair_events(4096, count=1, bidirectional=False)
        with self.assertRaisesRegex(DmpTestError, "C3 transfer_started count mismatch"):
            validate_dmp_pair_events(events, 4096, SESSION, count=1, bidirectional=True)

    def test_rejects_missing_s3_ready(self):
        events = [e for e in make_passing_pair_events() if not (e[0] == "s3" and e[1].get("event") == "ready")]
        with self.assertRaisesRegex(DmpTestError, "S3 did not report ready"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_missing_c3_ready(self):
        events = [e for e in make_passing_pair_events() if not (e[0] == "c3" and e[1].get("event") == "ready")]
        with self.assertRaisesRegex(DmpTestError, "C3 did not report ready"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_espnow_version_below_2(self):
        events = make_passing_pair_events()
        events = [(side, make_ready("esp32s3", S3_MAC, espnow_version=1) if ev.get("event") == "ready" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "invalid or non-v2 espnow_version"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_c3_espnow_version_below_2(self):
        events = make_passing_pair_events()
        events = [(side, make_ready("esp32c3", C3_MAC, espnow_version=1) if ev.get("event") == "ready" and side == "c3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "invalid or non-v2 espnow_version"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_same_mac_address(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "mac": S3_MAC} if ev.get("event") == "ready" and side == "c3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "identical MAC"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_controller_role_on_c3(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "role": "controller"} if ev.get("event") == "role_set" and side == "c3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "C3 did not confirm role 'peer'"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_missing_s3_node_id(self):
        events = make_passing_pair_events()
        events = [(side, {k: v for k, v in ev.items() if k != "node_id"} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "S3 node_id missing from role_set"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_wrong_s3_node_id(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "node_id": 99} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "S3 node_id mismatch"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_wrong_handshake_scratch_slot_count(self):
        events = make_passing_pair_events()
        events = [
            (
                side,
                {**event, "handshake_scratch_slots": 2}
                if side == "s3" and event.get("event") == "role_set"
                else event,
            )
            for side, event in events
        ]
        with self.assertRaisesRegex(DmpTestError, "S3 retry-2 profile must report one handshake scratch slot"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_missing_c3_node_id(self):
        events = make_passing_pair_events()
        events = [(side, {k: v for k, v in ev.items() if k != "node_id"} if ev.get("event") == "role_set" and side == "c3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "C3 node_id missing from role_set"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_wrong_c3_node_id(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "node_id": 99} if ev.get("event") == "role_set" and side == "c3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "C3 node_id mismatch"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_wrong_profile_name(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "profile": "wrong-profile"} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "did not use profile 'retry-2'"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_wrong_profile_hash(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "profile_hash": "00" * 32} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "profile hash mismatch"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_missing_nvs_check(self):
        events = [e for e in make_passing_pair_events() if e[1].get("event") != "nvs_epoch_check"]
        with self.assertRaisesRegex(DmpTestError, "S3 producer did not report NVS epoch check"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_failed_handshake(self):
        events = make_passing_pair_events()
        events = [
            (side, {**event, "status": "failed"} if event.get("event") == "handshake_done" and side == "s3" else event)
            for side, event in events
        ]
        with self.assertRaisesRegex(DmpTestError, "S3 did not complete handshake with status success"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_expired_handshake(self):
        events = make_passing_pair_events()
        events.append(("s3", {
            "event": "handshake_failed",
            "session": SESSION,
            "peer_mac": C3_MAC,
            "peer_handle": 0,
            "attempt_index": 0,
            "reason": "attempt-expired",
        }))
        with self.assertRaisesRegex(DmpTestError, "S3 handshake failed: attempt-expired"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_fail_closed_handshake_poll_error(self):
        events = make_passing_pair_events()
        events.append(("s3", {
            "event": "error",
            "session": SESSION,
            "status": "fail_closed",
            "reason": "handshake-poll-unexpected",
            "peer_mac": C3_MAC,
            "peer_handle": 0,
            "status_code": -1,
            "revoke_status": 0,
        }))
        with self.assertRaisesRegex(DmpTestError, "S3 handshake failed: handshake-poll-unexpected"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_missing_sample_read_result(self):
        events = [e for e in make_passing_pair_events() if e[1].get("event") != "rx_result"]
        with self.assertRaisesRegex(DmpTestError, "SAMPLE-1 result"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_sample_read_wrong_bytes(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "bytes": 8} if ev.get("event") == "rx_result" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "SAMPLE-1 READ result bytes mismatch: expected 17"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_sample_read_failed_wire_status(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "wire_status": 1} if ev.get("event") == "rx_result" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "successful SAMPLE-1 result"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_service2_corrupted_payload(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "payload_match": False} if ev.get("event") == "rx_assembled" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "does not match expected deterministic pattern"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_extra_service2_assembly(self):
        events = make_passing_pair_events()
        assembled = next(ev for side, ev in events if side == "c3" and ev.get("event") == "rx_assembled")
        events.append(("c3", dict(assembled)))
        with self.assertRaisesRegex(DmpTestError, "C3 rx_assembled count mismatch: got 2, expected 1"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_transfer_count_underflow(self):
        events = make_passing_pair_events(4096, count=1)
        with self.assertRaisesRegex(DmpTestError, "S3 transfer_started count mismatch"):
            validate_dmp_pair_events(events, 4096, SESSION, count=2)

    def test_rejects_transfer_count_overflow(self):
        events = make_passing_pair_events(4096, count=2)
        with self.assertRaisesRegex(DmpTestError, "S3 transfer_started count mismatch"):
            validate_dmp_pair_events(events, 4096, SESSION, count=1)

    def test_rejects_missing_v2_frame_emitted(self):
        events = [e for e in make_passing_pair_events() if e[1].get("event") != "v2_frame_emitted"]
        with self.assertRaisesRegex(DmpTestError, "No native v2 frame emission recorded"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_missing_v2_frame_received(self):
        events = [e for e in make_passing_pair_events() if e[1].get("event") != "v2_frame_received"]
        with self.assertRaisesRegex(DmpTestError, "No native v2 frame reception recorded"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_probe_frame_over_263b(self):
        events = make_passing_pair_events(4096)
        events = [(side, {**ev, "encoded_bytes": 264} if ev.get("event") == "v2_frame_emitted" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "encoded bytes not in \\(250, 263\\]"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_probe_frame_at_or_below_250b(self):
        events = make_passing_pair_events(4096)
        events = [(side, {**ev, "encoded_bytes": 250} if ev.get("event") == "v2_frame_emitted" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "encoded bytes not in \\(250, 263\\]"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_probe_frame_authenticated(self):
        events = make_passing_pair_events(4096)
        events = [(side, {**ev, "authenticated": True} if ev.get("event") == "v2_frame_emitted" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "v2 frame emitted must report authenticated=false"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_probe_frame_received_authenticated(self):
        events = make_passing_pair_events(4096)
        events = [(side, {**ev, "authenticated": True} if ev.get("event") == "v2_frame_received" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "v2 frame received must report authenticated=false"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_probe_frame_wrong_classification(self):
        events = make_passing_pair_events(4096)
        events = [(side, {**ev, "classification": "non-probe"} if ev.get("event") == "v2_frame_received" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "classification mismatch"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_probe_frame_wrong_decoded_bytes(self):
        events = make_passing_pair_events(4096)
        events = [(side, {**ev, "decoded_bytes": 200} if ev.get("event") == "v2_frame_emitted" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "v2 frame emitted decoded bytes mismatch: expected 256"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_payload_bytes_mismatch(self):
        events = make_passing_pair_events(2048)
        with self.assertRaisesRegex(DmpTestError, "transfer_started for 4096 bytes"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_oversize_frame_over_stream_r_mtu(self):
        events = make_passing_pair_events(4096)
        events.append(("s3", {"event": "tx_done", "session": SESSION, "frame_bytes": 264, "status": "success"}))
        with self.assertRaisesRegex(DmpTestError, "exceeds Stream R MTU cap of 263 bytes"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_rejects_no_v2_frames_observed(self):
        events = [e for e in make_passing_pair_events(4096) if e[1].get("event") not in ("v2_frame_emitted", "v2_frame_received")]
        events.append(("s3", {"event": "v2_frame_emitted", "session": SESSION, "peer_handle": 0, "decoded_bytes": 256, "encoded_bytes": 250}))
        events.append(("c3", {"event": "v2_frame_received", "session": SESSION, "peer_handle": 0, "decoded_bytes": 256, "encoded_bytes": 250}))
        with self.assertRaisesRegex(DmpTestError, "encoded bytes not in \\(250, 263\\]"):
            validate_dmp_pair_events(events, 4096, SESSION)

    def test_run_dmp_pair_rejects_duplicate_ports(self):
        with self.assertRaisesRegex(DmpTestError, "cannot use duplicate serial port"):
            run_dmp_pair(s3_port="COM1", c3_port="COM1")


if __name__ == "__main__":
    unittest.main()
