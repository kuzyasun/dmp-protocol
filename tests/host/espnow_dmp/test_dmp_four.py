"""Host tests for multi-peer ESP-NOW qualification event validation."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

EMBEDDED_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_dmp"
sys.path.insert(0, str(EMBEDDED_DIR))

from serial_dmp_common import (
    FOUR_CONTROLLER_NODE_ID,
    FOUR_PEER_NODE_IDS,
    DmpTestError,
    MULTI_PEER_PROFILE_HASH,
)
from serial_dmp_four import run_dmp_four, run_dmp_three_peer_serial, validate_dmp_four_events

S3_MAC = "28:37:2f:75:5d:64"
PEER_MACS = [
    "20:6e:f1:b0:f0:2c",
    "20:6e:f1:b0:f0:2d",
    "20:6e:f1:b0:f0:2e",
    "20:6e:f1:b0:f0:2f",
]
SESSION = "0123456789abcdef"


PEER_NODE_IDS = [10, 35, 34, 36]


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


def append_passing_sample1_reads(
    events: list[tuple[str, dict]], peer_count: int, session: str = SESSION
) -> None:
    for peer_idx in range(peer_count):
        side = f"c3_{peer_idx}"
        events.extend([
            (side, {
                "event": "sample_read_submitted",
                "session": session,
                "peer_handle": 0,
                "status": 0,
            }),
            ("s3", {
                "event": "rx_request",
                "session": session,
                "peer_handle": peer_idx,
                "service_id": 1,
                "bytes": 1,
            }),
            (side, {
                "event": "rx_result",
                "session": session,
                "peer_handle": 0,
                "service_id": 1,
                "wire_status": 0,
                "bytes": 17,
            }),
            ("s3", {
                "event": "tx_done",
                "session": session,
                "peer_handle": peer_idx,
                "frame_bytes": 63,
                "status": "success",
                "transport_outcome": "transmitted",
            }),
        ])


def make_passing_four_events(
    mode: str = "four_serial",
    bytes_per_peer: int = 4096,
    count_per_peer: int = 1,
) -> list[tuple[str, dict]]:
    fragments = (bytes_per_peer + 127) // 128
    events = [
        ("s3", make_ready("esp32s3", S3_MAC)),
        ("s3", {"event": "session_set", "session": SESSION, "target": "esp32s3", "mac": S3_MAC}),
        ("s3", {"event": "role_set", "session": SESSION, "role": "controller", "profile": "multi-peer", "profile_hash": MULTI_PEER_PROFILE_HASH, "node_id": 20, "handshake_scratch_slots": 1 if mode == "four_serial" else 2}),
    ]
    for i, mac in enumerate(PEER_MACS):
        side = f"c3_{i}"
        node_id = PEER_NODE_IDS[i]
        events.extend([
            (side, make_ready("esp32c3", mac)),
            (side, {"event": "session_set", "session": SESSION, "target": "esp32c3", "mac": mac}),
            (side, {"event": "role_set", "session": SESSION, "role": "peer", "profile": "multi-peer", "profile_hash": MULTI_PEER_PROFILE_HASH, "node_id": node_id, "handshake_scratch_slots": 1}),
            (side, {"event": "peer_added", "session": SESSION, "peer_mac": S3_MAC, "node_id": 20, "peer_handle": 0, "peer_count": 1}),
            (side, {"event": "handshake_stream_sync_done", "session": SESSION, "peer_mac": S3_MAC, "peer_handle": 0, "status": "success"}),
            ("s3", {"event": "peer_added", "session": SESSION, "peer_mac": mac, "node_id": node_id, "peer_handle": i, "peer_count": i + 1}),
            ("s3", {"event": "handshake_stream_sync_done", "session": SESSION, "peer_mac": mac, "peer_handle": i, "status": "success"}),
            ("s3", {"event": "handshake_started", "session": SESSION, "peer_mac": mac, "peer_handle": i}),
            ("s3", {"event": "handshake_done", "session": SESSION, "peer_mac": mac, "peer_handle": i, "status": "success"}),
            (side, {"event": "handshake_ready_submit", "session": SESSION, "peer_mac": S3_MAC, "peer_handle": 0, "accepted": True, "status": 0, "status_name": "accepted"}),
            (side, {"event": "handshake_done", "session": SESSION, "peer_mac": S3_MAC, "peer_handle": 0, "status": "success"}),
        ])

    events.append(("s3", {
        "event": "nvs_epoch_check",
        "session": SESSION,
        "status": "ok",
        "namespace": "dmp_test_nvs",
        "key": "s1_epoch_mp",
        "has_previous": True,
        "previous_epoch": 1,
        "reserved_epoch": 2,
    }))
    append_passing_sample1_reads(events, len(PEER_MACS))

    for _ in range(count_per_peer):
        for i in range(4):
            side = f"c3_{i}"
            events.append(("s3", {
                "event": "transfer_started",
                "session": SESSION,
                "peer_handle": i,
                "peer_mac": PEER_MACS[i],
                "bytes": bytes_per_peer,
                "chunk_bytes": 128,
                "fragments": fragments,
            }))
            for _ in range(fragments):
                events.append(("s3", {"event": "tx_done", "session": SESSION, "peer_mac": PEER_MACS[i], "peer_handle": i, "frame_bytes": 168, "status": "success"}))
            events.append((side, {
                "event": "rx_assembled",
                "session": SESSION,
                "peer_handle": 0,
                "service_id": 2,
                "bytes": bytes_per_peer,
                "fragments": fragments,
                "payload_match": True,
                "max_frame_bytes": 168,
            }))

    return events


def make_passing_three_peer_events(
    mode: str = "three_peer_serial",
    bytes_per_peer: int = 4096,
    count_per_peer: int = 1,
    peer_node_ids: list[int] | None = None,
    peer_macs: list[str] | None = None,
) -> list[tuple[str, dict]]:
    macs = peer_macs or PEER_MACS[:3]
    node_ids = peer_node_ids or PEER_NODE_IDS[:3]
    fragments = (bytes_per_peer + 127) // 128
    events = [
        ("s3", make_ready("esp32s3", S3_MAC)),
        ("s3", {"event": "session_set", "session": SESSION, "target": "esp32s3", "mac": S3_MAC}),
        ("s3", {
            "event": "role_set",
            "session": SESSION,
            "role": "controller",
            "profile": "multi-peer",
            "profile_hash": MULTI_PEER_PROFILE_HASH,
            "node_id": 20,
            "handshake_scratch_slots": 1,
        }),
    ]
    for i, mac in enumerate(macs):
        side = f"c3_{i}"
        node_id = node_ids[i]
        events.extend([
            (side, make_ready("esp32c3", mac)),
            (side, {"event": "session_set", "session": SESSION, "target": "esp32c3", "mac": mac}),
            (side, {
                "event": "role_set",
                "session": SESSION,
                "role": "peer",
                "profile": "multi-peer",
                "profile_hash": MULTI_PEER_PROFILE_HASH,
                "node_id": node_id,
                "handshake_scratch_slots": 1,
            }),
            (side, {
                "event": "peer_added",
                "session": SESSION,
                "peer_mac": S3_MAC,
                "node_id": 20,
                "peer_handle": 0,
                "peer_count": 1,
            }),
            (side, {
                "event": "handshake_stream_sync_done",
                "session": SESSION,
                "peer_mac": S3_MAC,
                "peer_handle": 0,
                "status": "success",
            }),
            (
                "s3",
                {
                    "event": "peer_added",
                    "session": SESSION,
                    "peer_mac": mac,
                    "node_id": node_id,
                    "peer_handle": i,
                    "peer_count": i + 1,
                },
            ),
            (
                "s3",
                {
                    "event": "handshake_stream_sync_done",
                    "session": SESSION,
                    "peer_mac": mac,
                    "peer_handle": i,
                    "status": "success",
                },
            ),
            (
                "s3",
                {
                    "event": "handshake_started",
                    "session": SESSION,
                    "peer_mac": mac,
                    "peer_handle": i,
                },
            ),
            (
                "s3",
                {
                    "event": "handshake_done",
                    "session": SESSION,
                    "peer_mac": mac,
                    "peer_handle": i,
                    "status": "success",
                },
            ),
            (
                side,
                {
                    "event": "handshake_ready_submit",
                    "session": SESSION,
                    "peer_mac": S3_MAC,
                    "peer_handle": 0,
                    "accepted": True,
                    "status": 0,
                    "status_name": "accepted",
                },
            ),
            (
                side,
                {
                    "event": "handshake_done",
                    "session": SESSION,
                    "peer_mac": S3_MAC,
                    "peer_handle": 0,
                    "status": "success",
                },
            ),
        ])

    events.append(("s3", {
        "event": "nvs_epoch_check",
        "session": SESSION,
        "status": "ok",
        "namespace": "dmp_test_nvs",
        "key": "s1_epoch_mp",
        "has_previous": True,
        "previous_epoch": 1,
        "reserved_epoch": 2,
    }))
    append_passing_sample1_reads(events, len(macs))

    for _ in range(count_per_peer):
        for i in range(len(macs)):
            side = f"c3_{i}"
            events.append(("s3", {
                "event": "transfer_started",
                "session": SESSION,
                "peer_handle": i,
                "peer_mac": macs[i],
                "bytes": bytes_per_peer,
                "chunk_bytes": 128,
                "fragments": fragments,
            }))
            for _ in range(fragments):
                events.append((
                    "s3",
                    {
                        "event": "tx_done",
                        "session": SESSION,
                        "peer_mac": macs[i],
                        "peer_handle": i,
                        "frame_bytes": 168,
                        "status": "success",
                    },
                ))
            events.append((
                side,
                {
                    "event": "rx_assembled",
                    "session": SESSION,
                    "peer_handle": 0,
                    "service_id": 2,
                    "bytes": bytes_per_peer,
                    "fragments": fragments,
                    "payload_match": True,
                    "max_frame_bytes": 168,
                },
            ))

    return events


class TestDmpFour(unittest.TestCase):
    def test_serial_runner_cli_help(self):
        result = subprocess.run(
            [sys.executable, str(EMBEDDED_DIR / "serial_dmp_four.py"), "--help"],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--s3-port", result.stdout)
        self.assertIn("--c3-ports", result.stdout)
        self.assertIn("three_peer_serial", result.stdout)

    def test_passing_four_serial(self):
        events = make_passing_four_events("four_serial", 4096)
        res = validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)
        self.assertEqual(res["result"], "PASS")
        self.assertEqual(res["mode"], "four_serial")
        self.assertEqual(res["total_boards"], 5)
        self.assertEqual(res["peer_count"], 4)
        self.assertEqual(res["controller_node_id"], 20)
        self.assertEqual(res["peer_node_ids"], [10, 35, 34, 36])
        self.assertEqual(res["bytes_per_peer"], 4096)
        self.assertEqual(res["fragments_per_peer"], 32)
        self.assertEqual(len(res["peer_macs"]), 4)

    def test_passing_four_parallel(self):
        events = make_passing_four_events("four_parallel", 4096)
        res = validate_dmp_four_events(events, "four_parallel", 4, 4096, SESSION)
        self.assertEqual(res["result"], "PASS")
        self.assertEqual(res["mode"], "four_parallel")
        self.assertEqual(res["total_boards"], 5)
        self.assertEqual(res["peer_count"], 4)

    def test_passing_four_serial_multi_count(self):
        events = make_passing_four_events("four_serial", 4096, count_per_peer=2)
        res = validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION, count_per_peer=2)
        self.assertEqual(res["result"], "PASS")
        self.assertEqual(res["count_per_peer"], 2)
        self.assertEqual(res["controller_handshake_scratch_slots"], 1)

    def test_passing_four_parallel_multi_count(self):
        events = make_passing_four_events("four_parallel", 4096, count_per_peer=2)
        res = validate_dmp_four_events(events, "four_parallel", 4, 4096, SESSION, count_per_peer=2)
        self.assertEqual(res["result"], "PASS")
        self.assertEqual(res["count_per_peer"], 2)
        self.assertEqual(res["controller_handshake_scratch_slots"], 2)

    def test_rejects_missing_peer_handshake_stream_sync(self):
        events = [
            event for event in make_passing_four_events("four_serial", 4096)
            if not (event[0] == "c3_2" and event[1].get("event") == "handshake_stream_sync_done")
        ]
        with self.assertRaisesRegex(DmpTestError, "Peer c3_2 did not synchronize its handshake Stream R binding"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_invalid_mode(self):
        events = make_passing_four_events("four_serial", 4096)
        with self.assertRaisesRegex(DmpTestError, "Invalid mode"):
            validate_dmp_four_events(events, "invalid_mode", 4, 4096, SESSION)

    def test_rejects_wrong_controller_profile(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {**ev, "profile": "wrong-profile"} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "did not use profile 'multi-peer'"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_wrong_controller_profile_hash(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {**ev, "profile_hash": "badhash" * 8} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "profile hash mismatch"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_wrong_peer_profile(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {**ev, "profile": "retry-2"} if ev.get("event") == "role_set" and side == "c3_1" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "did not use profile 'multi-peer'"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_wrong_peer_profile_hash(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {**ev, "profile_hash": "00" * 32} if ev.get("event") == "role_set" and side == "c3_2" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "profile hash mismatch"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_missing_controller_node_id(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {k: v for k, v in ev.items() if k != "node_id"} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "S3 controller node_id missing from role_set"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_wrong_controller_node_id(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {**ev, "node_id": 99} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "S3 controller node_id mismatch"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_missing_peer_node_id(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {k: v for k, v in ev.items() if k != "node_id"} if ev.get("event") == "role_set" and side == "c3_0" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "Peer c3_0 node_id missing from role_set"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_wrong_peer_node_id(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {**ev, "node_id": 99} if ev.get("event") == "role_set" and side == "c3_0" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "not in allowed multi-peer set"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_duplicate_peer_node_id(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {**ev, "node_id": 10} if ev.get("event") == "role_set" and side == "c3_1" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "Duplicate peer node_id detected"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_partial_peer_count_1_to_3(self):
        events = make_passing_four_events("four_serial", 4096)
        for count in (1, 2, 3):
            with self.assertRaisesRegex(DmpTestError, "Four-peer qualification requires exactly 4 peers"):
                validate_dmp_four_events(events, "four_serial", count, 4096, SESSION)

    def test_rejects_fewer_than_4_peer_streams(self):
        events = [e for e in make_passing_four_events("four_serial", 4096) if not e[0].startswith("c3_3")]
        with self.assertRaisesRegex(DmpTestError, "Expected exactly 4 peer streams"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_missing_peer_handshake(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [e for e in events if not (e[0] == "c3_2" and e[1].get("event") == "handshake_done")]
        with self.assertRaisesRegex(DmpTestError, "Peer c3_2 did not complete handshake"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_missing_peer_ready_transport_acceptance(self):
        events = [
            e for e in make_passing_four_events("four_serial", 4096)
            if not (e[0] == "c3_2" and e[1].get("event") == "handshake_ready_submit")
        ]
        with self.assertRaisesRegex(DmpTestError, "Peer c3_2 did not accept protected READY transport submission"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_failed_peer_ready_transport_submission(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [
            (side, {**event, "accepted": False, "status": 4}
             if side == "c3_2" and event.get("event") == "handshake_ready_submit" else event)
            for side, event in events
        ]
        with self.assertRaisesRegex(DmpTestError, "Peer c3_2 did not accept protected READY transport submission"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_expired_handshake(self):
        events = make_passing_four_events("four_serial", 4096)
        events.append(("s3", {
            "event": "handshake_failed",
            "session": SESSION,
            "peer_mac": PEER_MACS[2],
            "peer_handle": 2,
            "attempt_index": 0,
            "reason": "attempt-expired",
        }))
        with self.assertRaisesRegex(DmpTestError, "s3 handshake failed for peer handle 2: attempt-expired"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_fail_closed_handshake_poll_error(self):
        events = make_passing_four_events("four_serial", 4096)
        events.append(("s3", {
            "event": "error",
            "session": SESSION,
            "status": "fail_closed",
            "reason": "handshake-poll-unexpected",
            "peer_mac": PEER_MACS[1],
            "peer_handle": 1,
            "status_code": -1,
            "revoke_status": 0,
        }))
        with self.assertRaisesRegex(DmpTestError, "s3 handshake failed for peer handle 1: handshake-poll-unexpected"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_run_started_alone(self):
        # Has setup and run_started, but NO transfer_started or rx_assembled
        events = [e for e in make_passing_four_events("four_serial", 4096) if e[1].get("event") not in ("transfer_started", "rx_assembled")]
        events.append(("s3", {
            "event": "run_started",
            "session": SESSION,
            "mode": "four_serial",
            "count_per_peer": 1,
            "bytes": 4096,
            "peer_count": 4,
        }))
        with self.assertRaisesRegex(DmpTestError, "S3 transfer_started count mismatch"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_cross_peer_assembly_handle(self):
        events = make_passing_four_events("four_serial", 4096)
        # c3_0 receives rx_assembled claiming peer_handle 1 instead of 0
        events = [(side, {**ev, "peer_handle": 1} if ev.get("event") == "rx_assembled" and side == "c3_0" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "unexpected peer_handle"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_cross_peer_transfer_mac(self):
        events = make_passing_four_events("four_serial", 4096)
        # S3 transfer_started for handle 0 has MAC of peer 1
        events = [(side, {**ev, "peer_mac": PEER_MACS[1]} if ev.get("event") == "transfer_started" and ev.get("peer_handle") == 0 else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "Cross-peer transfer detected on S3"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_exact_transfer_count_underflow(self):
        events = make_passing_four_events("four_serial", 4096)
        with self.assertRaisesRegex(DmpTestError, "count mismatch"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION, count_per_peer=2)

    def test_rejects_exact_transfer_count_overflow(self):
        events = make_passing_four_events("four_serial", 4096, count_per_peer=2)
        with self.assertRaisesRegex(DmpTestError, "count mismatch"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION, count_per_peer=1)

    def test_rejects_missing_assembly_on_peer(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [e for e in events if not (e[0] == "c3_3" and e[1].get("event") == "rx_assembled")]
        with self.assertRaisesRegex(DmpTestError, "Peer c3_3 assembled 0 transfers, expected 1"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_corrupted_payload_on_peer(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {**ev, "payload_match": False} if ev.get("event") == "rx_assembled" and side == "c3_0" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "payload mismatch"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_extra_assembly_on_peer(self):
        events = make_passing_four_events("four_serial", 4096)
        assembled = next(ev for side, ev in events if side == "c3_2" and ev.get("event") == "rx_assembled")
        events.append(("c3_2", dict(assembled)))
        with self.assertRaisesRegex(DmpTestError, "Peer c3_2 assembled 2 transfers, expected 1"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_controller_scratch_slot_mismatch_for_mode(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [
            (
                side,
                {**event, "handshake_scratch_slots": 2}
                if side == "s3" and event.get("event") == "role_set"
                else event,
            )
            for side, event in events
        ]
        with self.assertRaisesRegex(DmpTestError, "four_serial handshake scratch slots mismatch"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_oversize_frame_over_stream_r_mtu(self):
        events = make_passing_four_events("four_serial", 4096)
        events.append(("s3", {"event": "tx_done", "session": SESSION, "frame_bytes": 265, "status": "success"}))
        with self.assertRaisesRegex(DmpTestError, "exceeds Stream R MTU limit 263"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_duplicate_peer_mac(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {**ev, "mac": PEER_MACS[0]} if ev.get("event") == "ready" and side == "c3_1" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "Duplicate or controller-matching MAC"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_peer_espnow_version_below_2(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {**ev, "espnow_version": 1} if ev.get("event") == "ready" and side == "c3_2" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "invalid or non-v2 espnow_version"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_rejects_controller_espnow_version_below_2(self):
        events = make_passing_four_events("four_serial", 4096)
        events = [(side, {**ev, "espnow_version": 1} if ev.get("event") == "ready" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "invalid or non-v2 espnow_version"):
            validate_dmp_four_events(events, "four_serial", 4, 4096, SESSION)

    def test_run_dmp_four_rejects_duplicate_ports(self):
        with self.assertRaisesRegex(DmpTestError, "detected duplicates"):
            run_dmp_four(s3_port="COM1", c3_ports=["COM1", "COM2", "COM3", "COM4"])

    def test_run_dmp_four_rejects_invalid_port_count(self):
        with self.assertRaisesRegex(DmpTestError, "requires exactly 4 C3 ports"):
            run_dmp_four(s3_port="COM1", c3_ports=["COM2", "COM3", "COM4"])


class TestDmpThreePeer(unittest.TestCase):
    def test_passing_three_peer_serial(self):
        events = make_passing_three_peer_events(bytes_per_peer=1024, count_per_peer=2)
        result = validate_dmp_four_events(
            events, "three_peer_serial", 3, 1024, SESSION, count_per_peer=2
        )
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["mode"], "three_peer_serial")
        self.assertEqual(result["peer_count"], 3)
        self.assertEqual(result["total_boards"], 4)
        self.assertEqual(result["sample1_read_peer_count"], 3)
        self.assertEqual(result["decoded_core_mtu_bytes"], 256)
        self.assertEqual(result["stream_r_encoded_mtu_bytes"], 263)

    def test_rejects_missing_sample1_result(self):
        events = [
            item for item in make_passing_three_peer_events()
            if not (item[0] == "c3_1" and item[1].get("event") == "rx_result")
        ]
        with self.assertRaisesRegex(DmpTestError, "Peer c3_1 did not receive exactly one SAMPLE-1 result"):
            validate_dmp_four_events(events, "three_peer_serial", 3, 4096, SESSION)

    def test_rejects_cross_peer_sample1_request(self):
        events = [
            (
                side,
                {**event, "peer_handle": 0}
                if side == "s3"
                and event.get("event") == "rx_request"
                and event.get("service_id") == 1
                and event.get("peer_handle") == 1
                else event,
            )
            for side, event in make_passing_three_peer_events()
        ]
        with self.assertRaisesRegex(DmpTestError, "SAMPLE-1 READ requests were not mapped one-to-one"):
            validate_dmp_four_events(events, "three_peer_serial", 3, 4096, SESSION)

    def test_rejects_failed_sample1_response_transport(self):
        events = [
            (
                side,
                {**event, "transport_outcome": "possibly-transmitted"}
                if side == "s3"
                and event.get("event") == "tx_done"
                and event.get("peer_handle") == 2
                and event.get("frame_bytes") == 63
                else event,
            )
            for side, event in make_passing_three_peer_events()
        ]
        with self.assertRaisesRegex(DmpTestError, "S3 SAMPLE-1 response TX failed for peer handle 2"):
            validate_dmp_four_events(events, "three_peer_serial", 3, 4096, SESSION)

    def test_rejects_nvs_epoch_check_on_non_producer_peer(self):
        events = make_passing_three_peer_events()
        events.append(("c3_0", {
            "event": "nvs_epoch_check",
            "session": SESSION,
            "status": "ok",
            "namespace": "dmp_test_nvs",
            "key": "s1_epoch_mp",
            "has_previous": True,
            "previous_epoch": 1,
            "reserved_epoch": 2,
        }))
        with self.assertRaisesRegex(DmpTestError, "reserved exactly once by the S3 producer"):
            validate_dmp_four_events(events, "three_peer_serial", 3, 4096, SESSION)

    def test_rejects_missing_third_peer_stream(self):
        events = [
            item for item in make_passing_three_peer_events()
            if item[0] != "c3_2"
        ]
        with self.assertRaisesRegex(DmpTestError, "Expected exactly 3 peer streams, found 2"):
            validate_dmp_four_events(events, "three_peer_serial", 3, 4096, SESSION)

    def test_rejects_extra_peer_registration(self):
        events = make_passing_three_peer_events()
        events.append(("s3", {
            "event": "peer_added",
            "session": SESSION,
            "peer_mac": PEER_MACS[3],
            "node_id": PEER_NODE_IDS[3],
            "peer_handle": 3,
            "peer_count": 4,
        }))
        with self.assertRaisesRegex(DmpTestError, "S3 registered 4 peers, expected exactly 3"):
            validate_dmp_four_events(events, "three_peer_serial", 3, 4096, SESSION)

    def test_rejects_cross_peer_transfer_mapping(self):
        events = make_passing_three_peer_events()
        events = [
            (
                side,
                {**event, "peer_mac": PEER_MACS[0]}
                if side == "s3"
                and event.get("event") == "transfer_started"
                and event.get("peer_handle") == 1
                else event,
            )
            for side, event in events
        ]
        with self.assertRaisesRegex(DmpTestError, "Cross-peer transfer detected on S3 for handle 1"):
            validate_dmp_four_events(events, "three_peer_serial", 3, 4096, SESSION)

    def test_four_peer_modes_still_reject_three_peers(self):
        events = make_passing_three_peer_events()
        with self.assertRaisesRegex(DmpTestError, "Four-peer qualification requires exactly 4 peers"):
            validate_dmp_four_events(events, "four_serial", 3, 4096, SESSION)


if __name__ == "__main__":
    unittest.main()
