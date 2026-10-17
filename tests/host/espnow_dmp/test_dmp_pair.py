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
    validate_entropy_diagnostic_event,
    validate_ready_event,
    validate_resources_event,
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
        "boot_id": "a" * 16 if target == "esp32s3" else "b" * 16,
        "reset_reason": "power_on",
        "channel": 1,
        "decoded_core_mtu_bytes": 256,
        "stream_r_encoded_mtu_bytes": 263,
        "espnow_v1_payload_mtu_bytes": 250,
        "espnow_v2_payload_mtu_bytes": 1470,
        "espnow_version": espnow_version,
        "peer_capacity": 4,
        "test_mode": "authenticated-dmp-endpoint",
    }


def make_resources(session: str, target: str) -> dict:
    return {
        "event": "resources", "session": session, "target": target, "status": "ok",
        "entropy_ready": True,
        "heap_internal_free_bytes": 100000,
        "heap_internal_min_free_bytes": 90000,
        "heap_internal_largest_block_bytes": 80000,
        "heap_internal_used_since_ready_bytes": 1000,
        "heap_spiram_free_bytes": 0,
        "heap_spiram_min_free_bytes": 0,
        "heap_spiram_largest_block_bytes": 0,
        "qualification_static_bytes": 40000,
        "qualification_dynamic_object_bytes": 3000,
        "provider_live_requested_bytes": 1000,
        "provider_peak_requested_bytes": 12000,
        "provider_largest_allocation_bytes": 8192,
        "provider_retained_bytes": 1000,
        "provider_scratch_limit_bytes": 16384,
        "provider_retained_limit_bytes": 131072,
        "main_stack_min_free_bytes": 1500,
        "main_stack_configured_bytes": 7168,
        "command_stack_min_free_bytes": 1400,
        "command_stack_configured_bytes": 4096,
        "wifi_rx_callback_stack_sampled": True,
        "wifi_rx_callback_stack_min_free_bytes": 1200,
        "wifi_tx_callback_stack_sampled": True,
        "wifi_tx_callback_stack_min_free_bytes": 1100,
        "decoded_core_mtu_bytes": 256,
        "stream_r_encoded_mtu_bytes": 263,
        "espnow_v1_payload_mtu_bytes": 250,
        "espnow_v2_payload_mtu_bytes": 1470,
    }


def make_entropy_diagnostic(session: str) -> dict:
    return {
        "event": "entropy_diagnostic", "session": session, "status": "ok",
        "entropy_ready": True, "source": "esp_fill_random_wifi_active",
        "sample_bytes": 4096, "unique_byte_values": 256,
        "minimum_bucket_count": 5, "maximum_bucket_count": 31,
        "chi_square_x1000": 25413000, "elapsed_us": 1500,
        "quality_certified": False,
        "interpretation": "statistical diagnostic only",
    }


def make_passing_pair_events(
    transfer_bytes: int = 1024,
    session: str = SESSION,
    count: int = 1,
    bidirectional: bool = False,
) -> list[tuple[str, dict]]:
    fragments = (transfer_bytes + 63) // 64
    events = [
        ("s3", make_ready("esp32s3", S3_MAC)),
        ("c3", make_ready("esp32c3", C3_MAC)),
        ("s3", {"event": "session_set", "session": session, "target": "esp32s3", "mac": S3_MAC}),
        ("c3", {"event": "session_set", "session": session, "target": "esp32c3", "mac": C3_MAC}),
        ("s3", {"event": "role_set", "session": session, "role": "controller", "profile": "retry-2", "profile_hash": RETRY_2_PROFILE_HASH, "node_id": PAIR_CONTROLLER_NODE_ID, "handshake_scratch_slots": 1}),
        ("c3", {"event": "role_set", "session": session, "role": "peer", "profile": "retry-2", "profile_hash": RETRY_2_PROFILE_HASH, "node_id": PAIR_PEER_NODE_ID, "handshake_scratch_slots": 1}),
        ("s3", {"event": "peer_added", "session": session, "peer_mac": C3_MAC, "node_id": PAIR_PEER_NODE_ID, "peer_handle": 0, "peer_count": 1}),
        ("c3", {"event": "peer_added", "session": session, "peer_mac": S3_MAC, "node_id": PAIR_CONTROLLER_NODE_ID, "peer_handle": 0, "peer_count": 1}),
        ("s3", {"event": "handshake_stream_sync_done", "session": session, "peer_mac": C3_MAC, "peer_handle": 0, "status": "success"}),
        ("c3", {"event": "handshake_stream_sync_done", "session": session, "peer_mac": S3_MAC, "peer_handle": 0, "status": "success"}),
        ("s3", {
            "event": "nvs_epoch_check",
            "session": session,
            "status": "ok",
            "namespace": "dmp_test_nvs",
            "key": "s1_epoch_test",
            "has_previous": True,
            "previous_epoch": 1,
            "reserved_epoch": 2,
            "elapsed_us": 120,
        }),
        ("s3", {"event": "sample1_epoch_reserved", "session": session, "epoch": 1, "elapsed_us": 180}),
        ("s3", {"event": "handshake_started", "session": session, "peer_mac": C3_MAC, "peer_handle": 0}),
        ("s3", {"event": "tx_done", "session": session, "peer_mac": C3_MAC, "peer_handle": 0, "frame_bytes": 100, "status": "success"}),
        ("c3", {"event": "tx_done", "session": session, "peer_mac": S3_MAC, "peer_handle": 0, "frame_bytes": 100, "status": "success"}),
        ("s3", {"event": "handshake_done", "session": session, "peer_mac": C3_MAC, "peer_handle": 0, "status": "success", "elapsed_us": 50000}),
        ("c3", {"event": "handshake_ready_submit", "session": session, "peer_mac": S3_MAC, "peer_handle": 0, "accepted": True, "status": 0, "status_name": "accepted"}),
        ("c3", {"event": "handshake_done", "session": session, "peer_mac": S3_MAC, "peer_handle": 0, "status": "success", "elapsed_us": 51000}),
        ("c3", {"event": "sample_read_submitted", "session": session, "peer_handle": 0, "status": 0}),
        ("c3", {"event": "rx_result", "session": session, "peer_handle": 0, "service_id": 1, "wire_status": 0, "bytes": 17}),
        ("c3", {"event": "sample1_read_result", "session": session, "peer_handle": 0, "epoch": 1, "sample_index": 1, "sample_value": 0x11223344}),
        ("s3", {"event": "v2_frame_emitted", "session": session, "peer_handle": 0, "decoded_bytes": 256, "encoded_bytes": 258, "authenticated": False}),
        ("c3", {"event": "v2_frame_received", "session": session, "peer_handle": 0, "decoded_bytes": 256, "encoded_bytes": 258, "authenticated": False, "classification": "raw-v2-capability-probe"}),
        ("s3", {"event": "v2_frame_tx_done", "session": session, "peer_handle": 0, "encoded_bytes": 258, "status": "success", "authenticated": False}),
    ]
    events.extend((side, make_resources(session, target))
                  for side, target in (("s3", "esp32s3"), ("c3", "esp32c3")))
    events.extend((side, make_entropy_diagnostic(session)) for side in ("s3", "c3"))
    for _ in range(count):
        # Forward: S3 -> C3
        events.append(("s3", {"event": "transfer_started", "session": session, "peer_handle": 0, "peer_mac": C3_MAC, "bytes": transfer_bytes, "chunk_bytes": 64, "fragments": fragments}))
        for _ in range(fragments):
            events.append(("s3", {"event": "tx_done", "session": session, "peer_mac": C3_MAC, "peer_handle": 0, "frame_bytes": 168, "status": "success"}))
        events.append(("c3", {
            "event": "rx_assembled",
            "session": session,
            "peer_handle": 0,
            "service_id": 2,
            "bytes": transfer_bytes,
            "fragments": fragments,
            "chunk_bytes": 64,
            "payload_match": True,
            "max_frame_bytes": 168,
        }))
        if bidirectional:
            # Reverse: C3 -> S3
            events.append(("c3", {"event": "transfer_started", "session": session, "peer_handle": 0, "peer_mac": S3_MAC, "bytes": transfer_bytes, "chunk_bytes": 64, "fragments": fragments}))
            for _ in range(fragments):
                events.append(("c3", {"event": "tx_done", "session": session, "peer_mac": S3_MAC, "peer_handle": 0, "frame_bytes": 168, "status": "success"}))
            events.append(("s3", {
                "event": "rx_assembled",
                "session": session,
                "peer_handle": 0,
                "service_id": 2,
                "bytes": transfer_bytes,
                "fragments": fragments,
                "chunk_bytes": 64,
                "payload_match": True,
                "max_frame_bytes": 168,
            }))
    return events


class TestDmpPair(unittest.TestCase):
    def test_ready_event_requires_a_boot_identity(self):
        event = make_ready("esp32s3", S3_MAC)
        self.assertEqual(validate_ready_event(event, "esp32s3")["boot_id"], "a" * 16)
        with self.assertRaisesRegex(DmpTestError, "boot identity"):
            validate_ready_event({**event, "boot_id": "not-a-boot-id"}, "esp32s3")

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
        events = make_passing_pair_events(1024)
        res = validate_dmp_pair_events(events, 1024, SESSION)
        self.assertEqual(res["result"], "PASS")
        self.assertTrue(res["nvs_check_performed"])
        self.assertEqual(res["sample1_owner_epoch"], 1)
        self.assertEqual(res["transfer_bytes"], 1024)
        self.assertEqual(res["chunk_bytes"], 64)
        self.assertEqual(res["fragments"], 16)
        self.assertEqual(res["decoded_core_mtu_bytes"], 256)
        self.assertEqual(res["stream_r_encoded_mtu_bytes"], 263)
        self.assertEqual(res["espnow_v1_payload_mtu_bytes"], 250)
        self.assertEqual(res["espnow_v2_payload_mtu_bytes"], 1470)
        self.assertEqual(res["target_handshake_elapsed_us"], {"s3": 50000, "c3": 51000})
        self.assertEqual(res["target_resources"]["s3"]["decoded_core_mtu_bytes"], 256)
        self.assertFalse(res["target_entropy_diagnostics"]["c3"]["quality_certified"])
        self.assertEqual(res["sample1_read_result"], {
            "epoch": 1, "sample_index": 1, "sample_value": 0x11223344
        })

    def test_epoch_transition_pair_skips_nvs_check_and_preserves_owner_epoch(self):
        events = [
            (side, event)
            for side, event in make_passing_pair_events(1024)
            if event.get("event") != "nvs_epoch_check"
        ]
        result = validate_dmp_pair_events(
            events, 1024, SESSION, require_nvs_check=False
        )
        self.assertFalse(result["nvs_check_performed"])
        self.assertEqual(result["sample1_owner_epoch"], 1)

    def test_epoch_transition_pair_rejects_unexpected_nvs_reservation(self):
        with self.assertRaisesRegex(DmpTestError, "unexpectedly ran NVS_CHECK"):
            validate_dmp_pair_events(
                make_passing_pair_events(1024),
                1024,
                SESSION,
                require_nvs_check=False,
            )

    def test_rejects_sample1_read_from_stale_epoch(self):
        events = [
            (side, {**event, "epoch": 0}
             if event.get("event") == "sample1_read_result" else event)
            for side, event in make_passing_pair_events()
        ]
        with self.assertRaisesRegex(DmpTestError, "did not return the current owner epoch"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_missing_decoded_sample1_read_payload(self):
        events = [
            item for item in make_passing_pair_events()
            if item[1].get("event") != "sample1_read_result"
        ]
        with self.assertRaisesRegex(DmpTestError, "Expected one decoded SAMPLE-1 READ result"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_missing_integrated_resource_measurement(self):
        events = [
            item for item in make_passing_pair_events()
            if not (item[0] == "c3" and item[1].get("event") == "resources")
        ]
        with self.assertRaisesRegex(DmpTestError, "C3 did not report integrated target resources"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_entropy_sample_as_certified_quality(self):
        events = [
            (side, {**event, "quality_certified": True}
             if event.get("event") == "entropy_diagnostic" and side == "s3" else event)
            for side, event in make_passing_pair_events()
        ]
        with self.assertRaisesRegex(DmpTestError, "sample size or its diagnostic-only qualification"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_resources_validator_rejects_encoded_mtu_confusion(self):
        resource = next(
            event for side, event in make_passing_pair_events()
            if side == "s3" and event.get("event") == "resources"
        )
        with self.assertRaisesRegex(DmpTestError, "stream_r_encoded_mtu_bytes mismatch"):
            validate_resources_event(
                {**resource, "stream_r_encoded_mtu_bytes": 256}, "esp32s3", SESSION
            )

    def test_entropy_validator_requires_readiness(self):
        diagnostic = next(
            event for side, event in make_passing_pair_events()
            if side == "s3" and event.get("event") == "entropy_diagnostic"
        )
        with self.assertRaisesRegex(DmpTestError, "wrong session or is not ready"):
            validate_entropy_diagnostic_event(
                {**diagnostic, "entropy_ready": False}, SESSION
            )

    def test_passing_bidirectional_pair_events(self):
        events = make_passing_pair_events(1024, count=2, bidirectional=True)
        res = validate_dmp_pair_events(events, 1024, SESSION, count=2, bidirectional=True)
        self.assertEqual(res["result"], "PASS")
        self.assertEqual(res["transfer_bytes"], 1024)

    def test_rejects_wrong_retry2_fragment_geometry(self):
        events = [
            (side, {**event, "chunk_bytes": 128}
             if event.get("event") == "transfer_started" else event)
            for side, event in make_passing_pair_events()
        ]
        with self.assertRaisesRegex(DmpTestError, "S3 transfer geometry does not match the retry-2 profile"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_pair_transfer_above_retry2_profile_limit(self):
        with self.assertRaisesRegex(DmpTestError, "retry-2 pair profile supports Service-2 payloads"):
            validate_dmp_pair_events(make_passing_pair_events(), 1025, SESSION)

    def test_runner_rejects_transfer_above_retry2_limit_before_opening_ports(self):
        opened_ports = []

        def serial_factory(port, **kwargs):
            opened_ports.append(port)
            raise AssertionError("serial factory must not run for an out-of-profile transfer")

        with self.assertRaisesRegex(DmpTestError, "retry-2 pair profile supports Service-2 payloads"):
            run_dmp_pair(
                s3_port="COM37",
                c3_port="COM40",
                transfer_bytes=1025,
                serial_factory=serial_factory,
            )
        self.assertEqual(opened_ports, [])

    def test_rejects_missing_v2_probe_tx_completion(self):
        events = [e for e in make_passing_pair_events() if e[1].get("event") != "v2_frame_tx_done"]
        with self.assertRaisesRegex(DmpTestError, "did not complete its transport send"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_failed_v2_probe_tx_completion(self):
        events = [
            (side, {**event, "status": "failed"}
             if event.get("event") == "v2_frame_tx_done" else event)
            for side, event in make_passing_pair_events()
        ]
        with self.assertRaisesRegex(DmpTestError, "did not complete its transport send"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_bidirectional_missing_reverse(self):
        events = make_passing_pair_events(1024, count=1, bidirectional=False)
        with self.assertRaisesRegex(DmpTestError, "C3 transfer_started count mismatch"):
            validate_dmp_pair_events(events, 1024, SESSION, count=1, bidirectional=True)

    def test_rejects_missing_s3_ready(self):
        events = [e for e in make_passing_pair_events() if not (e[0] == "s3" and e[1].get("event") == "ready")]
        with self.assertRaisesRegex(DmpTestError, "S3 did not report ready"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_missing_c3_ready(self):
        events = [e for e in make_passing_pair_events() if not (e[0] == "c3" and e[1].get("event") == "ready")]
        with self.assertRaisesRegex(DmpTestError, "C3 did not report ready"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_missing_handshake_stream_sync(self):
        events = [
            event for event in make_passing_pair_events()
            if not (event[0] == "c3" and event[1].get("event") == "handshake_stream_sync_done")
        ]
        with self.assertRaisesRegex(DmpTestError, "C3 did not synchronize the handshake Stream R binding"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_espnow_version_below_2(self):
        events = make_passing_pair_events()
        events = [(side, make_ready("esp32s3", S3_MAC, espnow_version=1) if ev.get("event") == "ready" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "invalid or non-v2 espnow_version"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_c3_espnow_version_below_2(self):
        events = make_passing_pair_events()
        events = [(side, make_ready("esp32c3", C3_MAC, espnow_version=1) if ev.get("event") == "ready" and side == "c3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "invalid or non-v2 espnow_version"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_same_mac_address(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "mac": S3_MAC} if ev.get("event") == "ready" and side == "c3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "identical MAC"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_controller_role_on_c3(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "role": "controller"} if ev.get("event") == "role_set" and side == "c3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "C3 did not confirm role 'peer'"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_missing_s3_node_id(self):
        events = make_passing_pair_events()
        events = [(side, {k: v for k, v in ev.items() if k != "node_id"} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "S3 node_id missing from role_set"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_wrong_s3_node_id(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "node_id": 99} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "S3 node_id mismatch"):
            validate_dmp_pair_events(events, 1024, SESSION)

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
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_missing_c3_node_id(self):
        events = make_passing_pair_events()
        events = [(side, {k: v for k, v in ev.items() if k != "node_id"} if ev.get("event") == "role_set" and side == "c3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "C3 node_id missing from role_set"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_wrong_c3_node_id(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "node_id": 99} if ev.get("event") == "role_set" and side == "c3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "C3 node_id mismatch"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_wrong_profile_name(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "profile": "wrong-profile"} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "did not use profile 'retry-2'"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_wrong_profile_hash(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "profile_hash": "00" * 32} if ev.get("event") == "role_set" and side == "s3" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "profile hash mismatch"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_missing_nvs_check(self):
        events = [e for e in make_passing_pair_events() if e[1].get("event") != "nvs_epoch_check"]
        with self.assertRaisesRegex(DmpTestError, "S3 producer did not report NVS epoch check"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_failed_handshake(self):
        events = make_passing_pair_events()
        events = [
            (side, {**event, "status": "failed"} if event.get("event") == "handshake_done" and side == "s3" else event)
            for side, event in events
        ]
        with self.assertRaisesRegex(DmpTestError, "S3 did not complete handshake with status success"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_missing_ready_transport_acceptance(self):
        events = [e for e in make_passing_pair_events() if e[1].get("event") != "handshake_ready_submit"]
        with self.assertRaisesRegex(DmpTestError, "C3 did not accept protected READY transport submission"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_failed_ready_transport_submission(self):
        events = make_passing_pair_events()
        events = [
            (side, {**event, "accepted": False, "status": 4}
             if event.get("event") == "handshake_ready_submit" else event)
            for side, event in events
        ]
        with self.assertRaisesRegex(DmpTestError, "C3 did not accept protected READY transport submission"):
            validate_dmp_pair_events(events, 1024, SESSION)

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
            validate_dmp_pair_events(events, 1024, SESSION)

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
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_missing_sample_read_result(self):
        events = [e for e in make_passing_pair_events() if e[1].get("event") != "rx_result"]
        with self.assertRaisesRegex(DmpTestError, "SAMPLE-1 result"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_sample_read_submission_failure(self):
        events = make_passing_pair_events()
        events = [
            (side, {**event, "status": 3}
             if event.get("event") == "sample_read_submitted" else event)
            for side, event in events
        ]
        with self.assertRaisesRegex(
            DmpTestError, "SAMPLE-1 READ submission failed with DMP status 3"
        ):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_sample_read_wrong_bytes(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "bytes": 8} if ev.get("event") == "rx_result" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "SAMPLE-1 READ result bytes mismatch: expected 17"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_sample_read_failed_wire_status(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "wire_status": 1} if ev.get("event") == "rx_result" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "successful SAMPLE-1 result"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_service2_corrupted_payload(self):
        events = make_passing_pair_events()
        events = [(side, {**ev, "payload_match": False} if ev.get("event") == "rx_assembled" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "does not match expected deterministic pattern"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_extra_service2_assembly(self):
        events = make_passing_pair_events()
        assembled = next(ev for side, ev in events if side == "c3" and ev.get("event") == "rx_assembled")
        events.append(("c3", dict(assembled)))
        with self.assertRaisesRegex(DmpTestError, "C3 rx_assembled count mismatch: got 2, expected 1"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_transfer_count_underflow(self):
        events = make_passing_pair_events(1024, count=1)
        with self.assertRaisesRegex(DmpTestError, "S3 transfer_started count mismatch"):
            validate_dmp_pair_events(events, 1024, SESSION, count=2)

    def test_rejects_transfer_count_overflow(self):
        events = make_passing_pair_events(1024, count=2)
        with self.assertRaisesRegex(DmpTestError, "S3 transfer_started count mismatch"):
            validate_dmp_pair_events(events, 1024, SESSION, count=1)

    def test_rejects_missing_v2_frame_emitted(self):
        events = [e for e in make_passing_pair_events() if e[1].get("event") != "v2_frame_emitted"]
        with self.assertRaisesRegex(DmpTestError, "No native v2 frame emission recorded"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_missing_v2_frame_received(self):
        events = [e for e in make_passing_pair_events() if e[1].get("event") != "v2_frame_received"]
        with self.assertRaisesRegex(DmpTestError, "No native v2 frame reception recorded"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_probe_frame_over_263b(self):
        events = make_passing_pair_events(1024)
        events = [(side, {**ev, "encoded_bytes": 264} if ev.get("event") == "v2_frame_emitted" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "encoded bytes not in \\(250, 263\\]"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_probe_frame_at_or_below_250b(self):
        events = make_passing_pair_events(1024)
        events = [(side, {**ev, "encoded_bytes": 250} if ev.get("event") == "v2_frame_emitted" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "encoded bytes not in \\(250, 263\\]"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_probe_frame_authenticated(self):
        events = make_passing_pair_events(1024)
        events = [(side, {**ev, "authenticated": True} if ev.get("event") == "v2_frame_emitted" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "v2 frame emitted must report authenticated=false"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_probe_frame_received_authenticated(self):
        events = make_passing_pair_events(1024)
        events = [(side, {**ev, "authenticated": True} if ev.get("event") == "v2_frame_received" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "v2 frame received must report authenticated=false"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_probe_frame_wrong_classification(self):
        events = make_passing_pair_events(1024)
        events = [(side, {**ev, "classification": "non-probe"} if ev.get("event") == "v2_frame_received" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "classification mismatch"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_probe_frame_wrong_decoded_bytes(self):
        events = make_passing_pair_events(1024)
        events = [(side, {**ev, "decoded_bytes": 200} if ev.get("event") == "v2_frame_emitted" else ev) for side, ev in events]
        with self.assertRaisesRegex(DmpTestError, "v2 frame emitted decoded bytes mismatch: expected 256"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_payload_bytes_mismatch(self):
        events = make_passing_pair_events(2048)
        with self.assertRaisesRegex(DmpTestError, "transfer_started for 1024 bytes"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_oversize_frame_over_stream_r_mtu(self):
        events = make_passing_pair_events(1024)
        events.append(("s3", {"event": "tx_done", "session": SESSION, "frame_bytes": 264, "status": "success"}))
        with self.assertRaisesRegex(DmpTestError, "exceeds Stream R MTU cap of 263 bytes"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_rejects_no_v2_frames_observed(self):
        events = [e for e in make_passing_pair_events(1024) if e[1].get("event") not in ("v2_frame_emitted", "v2_frame_received")]
        events.append(("s3", {"event": "v2_frame_emitted", "session": SESSION, "peer_handle": 0, "decoded_bytes": 256, "encoded_bytes": 250}))
        events.append(("c3", {"event": "v2_frame_received", "session": SESSION, "peer_handle": 0, "decoded_bytes": 256, "encoded_bytes": 250}))
        with self.assertRaisesRegex(DmpTestError, "encoded bytes not in \\(250, 263\\]"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_run_dmp_pair_rejects_duplicate_ports(self):
        with self.assertRaisesRegex(DmpTestError, "cannot use duplicate serial port"):
            run_dmp_pair(s3_port="COM1", c3_port="COM1")


if __name__ == "__main__":
    unittest.main()
