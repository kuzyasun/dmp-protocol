"""Host test suite exercising in-memory serial stub without opening COM ports."""

from __future__ import annotations

import json
import queue
import sys
import threading
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Callable

EMBEDDED_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_dmp"
sys.path.insert(0, str(EMBEDDED_DIR))

from serial_dmp_common import (
    DmpTestError,
    FOUR_CONTROLLER_NODE_ID,
    FOUR_PEER_NODE_IDS,
    HostCommandLog,
    MULTI_PEER_PROFILE_HASH,
    PAIR_CONTROLLER_NODE_ID,
    PAIR_PEER_NODE_ID,
    RETRY_2_PROFILE_HASH,
    SerialDeviceSession,
    create_evidence_dir,
    wait_for_handshake_pair,
)
from serial_dmp_pair import run_dmp_pair, validate_dmp_pair_events
from serial_dmp_four import run_dmp_four, run_dmp_three_peer_serial, validate_dmp_four_events

S3_MAC = "28:37:2f:75:5d:64"
C3_MAC = "20:6e:f1:b0:f0:2c"
PEER_MACS = [
    "20:6e:f1:b0:f0:2c",
    "20:6e:f1:b0:f0:2d",
    "20:6e:f1:b0:f0:2e",
    "20:6e:f1:b0:f0:2f",
]
SESSION = "0123456789abcdef"


class EspNowDmpStub:
    """In-memory serial stub simulating DMP endpoint over ESP-NOW."""

    def __init__(
        self,
        target: str,
        mac: str,
        fail_handshake: bool = False,
        fail_nvs: bool = False,
        fail_role: bool = False,
        corrupt_payload: bool = False,
        espnow_version: int = 2,
        profile: str = "retry-2",
        fail_schedule: bool = False,
        fail_peer: bool = False,
        sample_read_status: int = 0,
        defer_sample_response_tx_done: bool = False,
        fail_v2_frame: bool = False,
        defer_v2_tx_done: bool = False,
    ):
        self.target = target
        self.mac = mac
        self.fail_handshake = fail_handshake
        self.fail_poll_error = False
        self.fail_nvs = fail_nvs
        self.fail_role = fail_role
        self.corrupt_payload = corrupt_payload
        self.espnow_version = espnow_version
        self.profile = profile
        self.fail_schedule = fail_schedule
        self.fail_peer = fail_peer
        self.sample_read_status = sample_read_status
        self.defer_sample_response_tx_done = defer_sample_response_tx_done
        self.fail_v2_frame = fail_v2_frame
        self.defer_v2_tx_done = defer_v2_tx_done
        self.session: str | None = None
        self.role: str | None = None
        self.node_id: int | None = None
        self.stack_initialized = False
        self.peers: list[tuple[str, int]] = []
        self.hs_sync_handles: set[int] = set()
        self.sample_response_tx_pending = False
        self.v2_frame_started_while_sample_response_tx_pending = False
        self.v2_tx_pending = False
        self.transfer_started_while_v2_tx_pending = False
        self.nvs_epoch = 1
        self.port: MockSerialPort | None = None

    def bind_port(self, port: MockSerialPort) -> None:
        self.port = port

    def _emit(self, side: str, event: dict[str, Any], event_queue: queue.Queue | None = None) -> None:
        if event_queue is not None:
            event_queue.put((side, event))
        if self.port is not None:
            self.port.emit_event(event)

    def handle_command(
        self,
        side: str,
        command: str,
        event_queue: queue.Queue | None = None,
        network: SimulatedEspNowNetwork | None = None,
    ) -> None:
        parts = command.strip().split()
        if not parts:
            return
        cmd = parts[0]

        if cmd in ("RUN_PAIR", "RUN_FOUR_SERIAL", "RUN_FOUR_PARALLEL"):
            self._emit(side, {
                "event": "command_rejected",
                "session": self.session,
                "reason": "runner-owned-scheduling",
            }, event_queue)
            return

        if cmd == "INFO":
            self._emit(side, {
                "event": "ready",
                "target": self.target,
                "idf": "ESP-IDF v6.1",
                "firmware": "dmp-espnow-dmp/0.1",
                "mac": self.mac,
                "channel": 1,
                "decoded_core_mtu_bytes": 256,
                "stream_r_encoded_mtu_bytes": 263,
                "espnow_v1_payload_mtu_bytes": 250,
                "espnow_v2_payload_mtu_bytes": 1470,
                "espnow_version": self.espnow_version,
                "peer_capacity": 4,
                "test_mode": "authenticated-dmp-endpoint",
            }, event_queue)
        elif cmd == "SESSION" and len(parts) >= 2:
            self.session = parts[1]
            self._emit(side, {
                "event": "session_set",
                "session": self.session,
                "target": self.target,
                "mac": self.mac,
            }, event_queue)
        elif cmd == "PROFILE" and len(parts) >= 2:
            if self.stack_initialized:
                self._emit(side, {
                    "event": "command_rejected",
                    "reason": "profile-already-initialized-in-session",
                }, event_queue)
                return
            if parts[1] not in ("retry-2", "multi-peer"):
                self._emit(side, {
                    "event": "command_rejected",
                    "reason": "unknown-profile",
                }, event_queue)
                return
            self.profile = parts[1]
            self._emit(side, {
                "event": "profile_set",
                "session": self.session,
                "profile": self.profile,
            }, event_queue)
        elif cmd == "ROLE" and len(parts) >= 2:
            if self.stack_initialized:
                self._emit(side, {
                    "event": "command_rejected",
                    "reason": "already-initialized",
                }, event_queue)
                return
            if self.fail_role:
                self._emit(side, {
                    "event": "role_failed",
                    "session": self.session,
                    "role": parts[1],
                    "reason": "stack-init-failed",
                }, event_queue)
                return
            self.role = parts[1]
            if len(parts) >= 3:
                self.profile = parts[2]
            prof = self.profile or "retry-2"
            prof_hash = RETRY_2_PROFILE_HASH if prof == "retry-2" else MULTI_PEER_PROFILE_HASH
            if len(parts) != 5:
                self._emit(side, {
                    "event": "command_rejected",
                    "reason": "role-usage",
                    "expected": "ROLE <controller|peer> <profile> <local_node_id> <handshake_scratch_slots>",
                }, event_queue)
                return
            try:
                node_id = int(parts[3])
                scratch_slots = int(parts[4])
            except ValueError:
                self._emit(side, {"event": "command_rejected", "reason": "invalid-role-argument"}, event_queue)
                return
            if scratch_slots not in (1, 2) or (prof == "retry-2" and scratch_slots != 1):
                self._emit(side, {"event": "command_rejected", "reason": "invalid-handshake-scratch-slots"}, event_queue)
                return
            self.node_id = node_id
            self.stack_initialized = True
            self.hs_sync_handles.clear()
            self._emit(side, {
                "event": "role_set",
                "session": self.session,
                "role": self.role,
                "profile": prof,
                "profile_hash": prof_hash,
                "node_id": node_id,
                "handshake_scratch_slots": scratch_slots,
            }, event_queue)
        elif cmd == "PEER" and len(parts) >= 2:
            if self.fail_peer:
                self._emit(side, {
                    "event": "command_rejected",
                    "session": self.session,
                    "reason": "endpoint-add-peer-failed",
                    "status": 1,
                }, event_queue)
                return
            peer_mac = parts[1]
            node_id = int(parts[2]) if len(parts) >= 3 else (20 + len(self.peers))
            peer_h = len(self.peers)
            self.peers.append((peer_mac, node_id))
            self._emit(side, {
                "event": "peer_added",
                "session": self.session,
                "peer_mac": peer_mac,
                "node_id": node_id,
                "peer_handle": peer_h,
                "peer_count": len(self.peers),
            }, event_queue)
        elif cmd == "NVS_CHECK":
            if self.fail_nvs:
                self._emit(side, {
                    "event": "nvs_epoch_check",
                    "session": self.session,
                    "status": "fail_monotonic",
                    "previous_epoch": 5,
                    "reserved_epoch": 4,
                }, event_queue)
            else:
                self.nvs_epoch += 1
                self._emit(side, {
                    "event": "nvs_epoch_check",
                    "session": self.session,
                    "status": "ok",
                    "namespace": "dmp_test_nvs",
                    "key": "s1_epoch_mp" if self.profile == "multi-peer" else "s1_epoch_test",
                    "has_previous": True,
                    "previous_epoch": self.nvs_epoch - 1,
                    "reserved_epoch": self.nvs_epoch,
                }, event_queue)
        elif cmd == "HS_SYNC" and len(parts) >= 2:
            h = int(parts[1])
            if h >= len(self.peers):
                self._emit(side, {
                    "event": "handshake_stream_sync_failed",
                    "session": self.session,
                    "peer_handle": h,
                    "status": "invalid-peer",
                }, event_queue)
                return
            self.hs_sync_handles.add(h)
            self._emit(side, {
                "event": "handshake_stream_sync_done",
                "session": self.session,
                "peer_mac": self.peers[h][0],
                "peer_handle": h,
                "status": "success",
            }, event_queue)
        elif cmd == "HANDSHAKE" and len(parts) >= 2:
            h = int(parts[1])
            peer_mac = self.peers[h][0] if h < len(self.peers) else "00:00:00:00:00:00"
            if h not in self.hs_sync_handles:
                self._emit(side, {
                    "event": "handshake_failed",
                    "session": self.session,
                    "peer_mac": peer_mac,
                    "peer_handle": h,
                    "reason": "stream-sync-not-complete",
                }, event_queue)
                return
            if self.fail_schedule:
                self._emit(side, {
                    "event": "handshake_schedule_diagnostic",
                    "session": self.session,
                    "peer_mac": peer_mac,
                    "peer_handle": h,
                    "stage": "first-flight-write",
                    "status": 2,
                }, event_queue)
                return
            self._emit(side, {
                "event": "handshake_started",
                "session": self.session,
                "peer_mac": peer_mac,
                "peer_handle": h,
            }, event_queue)
            self._emit(side, {
                "event": "tx_done",
                "session": self.session,
                "peer_mac": peer_mac,
                "peer_handle": h,
                "frame_bytes": 100,
                "status": "success",
            }, event_queue)
            if self.fail_poll_error:
                self._emit(side, {
                    "event": "error",
                    "session": self.session,
                    "status": "fail_closed",
                    "reason": "handshake-poll-unexpected",
                    "peer_mac": peer_mac,
                    "peer_handle": h,
                    "status_code": -1,
                    "revoke_status": 0,
                }, event_queue)
            elif self.fail_handshake:
                self._emit(side, {
                    "event": "handshake_failed",
                    "session": self.session,
                    "peer_mac": peer_mac,
                    "peer_handle": h,
                    "attempt_index": 0,
                    "reason": "attempt-expired",
                }, event_queue)
            else:
                self._emit(side, {
                    "event": "handshake_done",
                    "session": self.session,
                    "peer_mac": peer_mac,
                    "peer_handle": h,
                    "status": "success",
                }, event_queue)
            if network and not self.fail_handshake and not self.fail_poll_error:
                peer_port = network.ports_by_mac.get(peer_mac.lower())
                if peer_port is not None:
                    peer_port.emit_event({
                        "event": "handshake_ready_submit",
                        "session": self.session,
                        "peer_mac": self.mac,
                        "peer_handle": 0,
                        "accepted": True,
                        "status": 0,
                        "status_name": "accepted",
                    })
                    peer_port.emit_event({
                        "event": "handshake_done",
                        "session": self.session,
                        "peer_mac": self.mac,
                        "peer_handle": 0,
                        "status": "success",
                    })
        elif cmd == "SAMPLE_READ" and len(parts) >= 2:
            h = int(parts[1])
            self._emit(side, {
                "event": "sample_read_submitted",
                "session": self.session,
                "peer_handle": h,
                "status": self.sample_read_status,
            }, event_queue)
            if self.sample_read_status == 0:
                peer_port = None
                controller_handle = None
                if network and h < len(self.peers):
                    peer_mac = self.peers[h][0]
                    peer_port = network.ports_by_mac.get(peer_mac.lower())
                if peer_port is not None:
                    controller_handle = next(
                        (
                            idx for idx, (mac, _) in enumerate(peer_port.stub.peers)
                            if mac.lower() == self.mac.lower()
                        ),
                        None,
                    )
                if peer_port is not None and controller_handle is not None:
                    peer_port.stub.sample_response_tx_pending = True
                    peer_port.emit_event({
                        "event": "rx_request",
                        "session": self.session,
                        "peer_handle": controller_handle,
                        "service_id": 1,
                        "bytes": 1,
                    })
                self._emit(side, {
                    "event": "rx_result",
                    "session": self.session,
                    "peer_handle": h,
                    "service_id": 1,
                    "wire_status": 0,
                    "bytes": 17,
                }, event_queue)
                if peer_port is not None and controller_handle is not None:
                    def complete_sample_response_tx() -> None:
                        peer_port.stub.sample_response_tx_pending = False
                        peer_port.emit_event({
                            "event": "tx_done",
                            "session": self.session,
                            "peer_mac": self.mac,
                            "peer_handle": controller_handle,
                            "frame_bytes": 63,
                            "status": "success",
                            "transport_outcome": "transmitted",
                        })

                    if peer_port.stub.defer_sample_response_tx_done:
                        timer = threading.Timer(0.5, complete_sample_response_tx)
                        timer.daemon = True
                        timer.start()
                    else:
                        complete_sample_response_tx()
        elif cmd == "V2_FRAME" and len(parts) >= 2:
            h = int(parts[1])
            if self.sample_response_tx_pending:
                self.v2_frame_started_while_sample_response_tx_pending = True
                self._emit(side, {
                    "event": "v2_frame_failed",
                    "session": self.session,
                    "peer_handle": h,
                    "reason": "transport-busy",
                }, event_queue)
                return
            if self.fail_v2_frame:
                self._emit(side, {
                    "event": "v2_frame_failed",
                    "session": self.session,
                    "peer_handle": h,
                    "reason": "transport-rejected",
                }, event_queue)
                return
            peer_mac = self.peers[h][0] if h < len(self.peers) else "00:00:00:00:00:00"
            self._emit(side, {
                "event": "v2_frame_emitted",
                "session": self.session,
                "peer_handle": h,
                "decoded_bytes": 256,
                "encoded_bytes": 258,
                "authenticated": False,
            }, event_queue)
            self.v2_tx_pending = True
            if network:
                peer_port = network.ports_by_mac.get(peer_mac.lower())
                if peer_port is not None:
                    peer_port.emit_event({
                        "event": "v2_frame_received",
                        "session": self.session,
                        "peer_handle": 0,
                        "decoded_bytes": 256,
                        "encoded_bytes": 258,
                        "authenticated": False,
                        "classification": "raw-v2-capability-probe",
                    })
            def complete_v2_tx() -> None:
                self.v2_tx_pending = False
                self._emit(side, {
                    "event": "v2_frame_tx_done",
                    "session": self.session,
                    "peer_mac": peer_mac,
                    "peer_handle": h,
                    "encoded_bytes": 258,
                    "status": "success",
                    "authenticated": False,
                }, event_queue)

            if self.defer_v2_tx_done:
                timer = threading.Timer(0.5, complete_v2_tx)
                timer.daemon = True
                timer.start()
            else:
                complete_v2_tx()
        elif cmd == "TRANSFER" and len(parts) >= 3:
            h = int(parts[1])
            b = int(parts[2])
            chunk_bytes = 64 if self.profile == "retry-2" else 128
            frags = (b + chunk_bytes - 1) // chunk_bytes
            if self.v2_tx_pending:
                self.transfer_started_while_v2_tx_pending = True
            peer_mac = self.peers[h][0] if h < len(self.peers) else "00:00:00:00:00:00"
            self._emit(side, {
                "event": "transfer_started",
                "session": self.session,
                "peer_handle": h,
                "peer_mac": peer_mac,
                "bytes": b,
                "chunk_bytes": chunk_bytes,
                "fragments": frags,
            }, event_queue)
            for _ in range(frags):
                self._emit(side, {
                    "event": "tx_done",
                    "session": self.session,
                    "peer_mac": peer_mac,
                    "peer_handle": h,
                    "frame_bytes": chunk_bytes + 40,
                    "status": "success",
                }, event_queue)
            if network:
                peer_port = network.ports_by_mac.get(peer_mac.lower())
                if peer_port is not None:
                    peer_port.emit_event({
                        "event": "rx_assembled",
                        "session": self.session,
                        "peer_handle": 0,
                        "service_id": 2,
                        "bytes": b,
                        "fragments": frags,
                        "chunk_bytes": chunk_bytes,
                        "payload_match": not self.corrupt_payload,
                        "max_frame_bytes": chunk_bytes + 40,
                    })


class MockSerialPort:
    """Mock serial port feeding commands into EspNowDmpStub and returning json lines."""

    def __init__(self, stub: EspNowDmpStub, side: str, network: SimulatedEspNowNetwork | None = None):
        self.stub = stub
        self.side = side
        self.network = network
        self._rx_queue: queue.Queue[bytes] = queue.Queue()
        self.closed = False
        stub.bind_port(self)

    def write(self, data: bytes) -> int:
        lines = data.decode("utf-8", errors="replace").splitlines()
        for line in lines:
            line_str = line.strip()
            if line_str:
                self.stub.handle_command(self.side, line_str, network=self.network)
        return len(data)

    def readline(self) -> bytes:
        try:
            return self._rx_queue.get(timeout=0.05)
        except queue.Empty:
            return b""

    def emit_event(self, event: dict[str, Any]) -> None:
        self._rx_queue.put((json.dumps(event) + "\n").encode("utf-8"))

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class SimulatedEspNowNetwork:
    """Interconnects simulated stub endpoints by MAC address."""

    def __init__(self) -> None:
        self.ports: dict[str, MockSerialPort] = {}
        self.stubs_by_mac: dict[str, EspNowDmpStub] = {}
        self.ports_by_mac: dict[str, MockSerialPort] = {}

    def register(self, port_name: str, side: str, stub: EspNowDmpStub) -> MockSerialPort:
        port = MockSerialPort(stub, side, self)
        self.ports[port_name.strip().lower()] = port
        self.stubs_by_mac[stub.mac.lower()] = stub
        self.ports_by_mac[stub.mac.lower()] = port
        return port

    def get_port(self, port_name: str) -> MockSerialPort:
        p = self.ports.get(port_name.strip().lower())
        if p is None:
            raise RuntimeError(f"Unknown mock serial port {port_name!r}")
        return p

    def make_factory(self) -> Callable[..., Any]:
        def factory(port: str, baudrate: int = 115200, timeout: float = 1.0) -> Any:
            return self.get_port(port)
        return factory


class TestRunnerStub(unittest.TestCase):
    def test_wait_ignores_rejection_from_stale_serial_session(self):
        stub = EspNowDmpStub("esp32s3", S3_MAC)
        port = MockSerialPort(stub, "s3")
        with tempfile.TemporaryDirectory() as tmpdir:
            device = SerialDeviceSession(
                "s3", "COM37", port, Path(tmpdir), expected_session="current-session"
            )
            try:
                port.emit_event({
                    "event": "command_rejected",
                    "session": "previous-session",
                    "reason": "stale-rejection",
                })
                port.emit_event({
                    "event": "session_set",
                    "session": "current-session",
                })
                event = device.wait_for_event(
                    lambda item: item.get("event") == "session_set"
                    and item.get("session") == "current-session",
                    timeout=1.0,
                    desc="current session",
                )
                self.assertEqual(event["session"], "current-session")
            finally:
                device.close()


    class EventSource:
        def __init__(self, events: list[dict[str, Any]]):
            self.events = events

        def get_events(self) -> list[dict[str, Any]]:
            return list(self.events)

    def test_waits_through_ready_busy_until_transport_accepts(self):
        initiator = self.EventSource([
            {"event": "handshake_done", "session": SESSION, "peer_handle": 0, "status": "success"}
        ])
        responder = self.EventSource([
            {
                "event": "handshake_ready_submit",
                "session": SESSION,
                "peer_handle": 0,
                "accepted": False,
                "status": 1,
                "status_name": "busy",
            },
            {
                "event": "handshake_ready_submit",
                "session": SESSION,
                "peer_handle": 0,
                "accepted": True,
                "status": 0,
                "status_name": "accepted",
            },
            {"event": "handshake_done", "session": SESSION, "peer_handle": 0, "status": "success"},
        ])

        result = wait_for_handshake_pair(
            initiator, responder, SESSION, 0.1, "pair handshake", 0, 0
        )

        self.assertEqual(result[0]["event"], "handshake_done")
        self.assertEqual(result[1]["event"], "handshake_done")

    def test_rejects_permanent_ready_submit_failure_immediately(self):
        initiator = self.EventSource([])
        responder = self.EventSource([
            {
                "event": "handshake_ready_submit",
                "session": SESSION,
                "peer_handle": 0,
                "accepted": False,
                "status": 6,
                "status_name": "transport-rejected",
            }
        ])

        with self.assertRaisesRegex(DmpTestError, "transport-rejected"):
            wait_for_handshake_pair(
                initiator, responder, SESSION, 30.0, "pair handshake", 0, 0
            )

    def test_rejects_activation_without_accepted_ready(self):
        initiator = self.EventSource([
            {"event": "handshake_done", "session": SESSION, "peer_handle": 0, "status": "success"}
        ])
        responder = self.EventSource([
            {"event": "handshake_done", "session": SESSION, "peer_handle": 0, "status": "success"}
        ])

        with self.assertRaisesRegex(DmpTestError, "without an accepted READY"):
            wait_for_handshake_pair(
                initiator, responder, SESSION, 30.0, "pair handshake", 0, 0
            )

    def test_wait_ignores_unscoped_rejection_before_current_session(self):
        stub = EspNowDmpStub("esp32s3", S3_MAC)
        port = MockSerialPort(stub, "s3")
        with tempfile.TemporaryDirectory() as tmpdir:
            device = SerialDeviceSession(
                "s3", "COM37", port, Path(tmpdir), expected_session="current-session"
            )
            try:
                port.emit_event({
                    "event": "command_rejected",
                    "reason": "stale-unscoped-rejection",
                })
                port.emit_event({
                    "event": "session_set",
                    "session": "current-session",
                })
                event = device.wait_for_event(
                    lambda item: item.get("event") == "session_set"
                    and item.get("session") == "current-session",
                    timeout=1.0,
                    desc="current session",
                )
                self.assertEqual(event["session"], "current-session")
            finally:
                device.close()

    def test_wait_fails_on_unscoped_rejection_after_current_session(self):
        stub = EspNowDmpStub("esp32s3", S3_MAC)
        port = MockSerialPort(stub, "s3")
        with tempfile.TemporaryDirectory() as tmpdir:
            device = SerialDeviceSession(
                "s3", "COM37", port, Path(tmpdir), expected_session="current-session"
            )
            try:
                port.emit_event({
                    "event": "session_set",
                    "session": "current-session",
                })
                device.wait_for_event(
                    lambda item: item.get("event") == "session_set"
                    and item.get("session") == "current-session",
                    timeout=1.0,
                    desc="current session",
                )
                port.emit_event({
                    "event": "command_rejected",
                    "reason": "current-unscoped-rejection",
                })
                with self.assertRaisesRegex(DmpTestError, "current-unscoped-rejection"):
                    device.wait_for_event(
                        lambda item: item.get("event") == "never-arrives",
                        timeout=1.0,
                        desc="pending event",
                    )
            finally:
                device.close()

    def test_simulated_pair_run_success(self):
        s3 = EspNowDmpStub("esp32s3", S3_MAC)
        c3 = EspNowDmpStub("esp32c3", C3_MAC)
        q: queue.Queue = queue.Queue()

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd_log = HostCommandLog(Path(tmpdir) / "commands.log")

            # Setup info
            s3.handle_command("s3", "INFO", q)
            c3.handle_command("c3", "INFO", q)

            # Session
            s3.handle_command("s3", f"SESSION {SESSION}", q)
            c3.handle_command("c3", f"SESSION {SESSION}", q)

            # Roles with explicit node_ids
            s3.handle_command("s3", f"ROLE controller retry-2 {PAIR_CONTROLLER_NODE_ID} 1", q)
            c3.handle_command("c3", f"ROLE peer retry-2 {PAIR_PEER_NODE_ID} 1", q)

            # Peers
            s3.handle_command("s3", f"PEER {C3_MAC} 20", q)
            c3.handle_command("c3", f"PEER {S3_MAC} 10", q)
            s3.handle_command("s3", "HS_SYNC 0", q)
            c3.handle_command("c3", "HS_SYNC 0", q)

            # NVS check on S3 producer
            s3.handle_command("s3", "NVS_CHECK", q)

            # Handshake
            s3.handle_command("s3", "HANDSHAKE 0", q)
            q.put(("c3", {
                "event": "handshake_ready_submit",
                "session": SESSION,
                "peer_mac": S3_MAC,
                "peer_handle": 0,
                "accepted": True,
                "status": 0,
                "status_name": "accepted",
            }))
            q.put(("c3", {
                "event": "handshake_done",
                "session": SESSION,
                "peer_mac": S3_MAC,
                "peer_handle": 0,
                "status": "success",
            }))

            # Sample Read on C3 reader
            c3.handle_command("c3", "SAMPLE_READ 0", q)

            # Native v2 frame
            s3.handle_command("s3", "V2_FRAME 0", q)
            q.put(("c3", {
                "event": "v2_frame_received",
                "session": SESSION,
                "peer_handle": 0,
                "decoded_bytes": 256,
                "encoded_bytes": 258,
                "authenticated": False,
                "classification": "raw-v2-capability-probe",
            }))

            # Transfer at the retry-2 profile's 1024-byte limit.
            s3.handle_command("s3", "TRANSFER 0 1024", q)
            q.put(("c3", {
                "event": "rx_assembled",
                "session": SESSION,
                "peer_handle": 0,
                "service_id": 2,
                "bytes": 1024,
                "fragments": 16,
                "chunk_bytes": 64,
                "payload_match": True,
                "max_frame_bytes": 104,
            }))

            cmd_log.close()

            events = []
            while not q.empty():
                events.append(q.get())

            res = validate_dmp_pair_events(events, 1024, SESSION)
            self.assertEqual(res["result"], "PASS")
            self.assertEqual(res["transfer_bytes"], 1024)
            self.assertEqual(res["fragments"], 16)
            self.assertEqual(res["decoded_core_mtu_bytes"], 256)
            self.assertEqual(res["stream_r_encoded_mtu_bytes"], 263)

    def test_simulated_pair_run_fails_closed_on_role_failure(self):
        s3 = EspNowDmpStub("esp32s3", S3_MAC, fail_role=True)
        c3 = EspNowDmpStub("esp32c3", C3_MAC)
        q: queue.Queue = queue.Queue()

        s3.handle_command("s3", "INFO", q)
        c3.handle_command("c3", "INFO", q)
        s3.handle_command("s3", f"SESSION {SESSION}", q)
        c3.handle_command("c3", f"SESSION {SESSION}", q)
        s3.handle_command("s3", f"ROLE controller retry-2 {PAIR_CONTROLLER_NODE_ID} 1", q)
        c3.handle_command("c3", f"ROLE peer retry-2 {PAIR_PEER_NODE_ID} 1", q)

        events = []
        while not q.empty():
            events.append(q.get())

        with self.assertRaisesRegex(DmpTestError, "S3 did not confirm role 'controller'"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_simulated_pair_run_fails_closed_on_espnow_v1(self):
        s3 = EspNowDmpStub("esp32s3", S3_MAC, espnow_version=1)
        c3 = EspNowDmpStub("esp32c3", C3_MAC)
        q: queue.Queue = queue.Queue()

        s3.handle_command("s3", "INFO", q)
        c3.handle_command("c3", "INFO", q)

        events = []
        while not q.empty():
            events.append(q.get())

        with self.assertRaisesRegex(DmpTestError, "invalid or non-v2 espnow_version"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_simulated_pair_run_rejects_profile_change_after_init(self):
        s3 = EspNowDmpStub("esp32s3", S3_MAC)
        q: queue.Queue = queue.Queue()

        s3.handle_command("s3", f"SESSION {SESSION}", q)
        s3.handle_command("s3", f"ROLE controller retry-2 {PAIR_CONTROLLER_NODE_ID} 1", q)
        s3.handle_command("s3", "PROFILE multi-peer", q)

        events = []
        while not q.empty():
            events.append(q.get())

        rejected = [e[1] for e in events if e[1].get("event") == "command_rejected"]
        self.assertTrue(len(rejected) > 0)
        self.assertEqual(rejected[0].get("reason"), "profile-already-initialized-in-session")

    def test_simulated_pair_run_fails_closed_on_handshake_error(self):
        s3 = EspNowDmpStub("esp32s3", S3_MAC, fail_handshake=True)
        c3 = EspNowDmpStub("esp32c3", C3_MAC)
        q: queue.Queue = queue.Queue()

        s3.handle_command("s3", "INFO", q)
        c3.handle_command("c3", "INFO", q)
        s3.handle_command("s3", f"SESSION {SESSION}", q)
        c3.handle_command("c3", f"SESSION {SESSION}", q)
        s3.handle_command("s3", f"ROLE controller retry-2 {PAIR_CONTROLLER_NODE_ID} 1", q)
        c3.handle_command("c3", f"ROLE peer retry-2 {PAIR_PEER_NODE_ID} 1", q)
        s3.handle_command("s3", f"PEER {C3_MAC} 20", q)
        c3.handle_command("c3", f"PEER {S3_MAC} 10", q)
        s3.handle_command("s3", "HS_SYNC 0", q)
        c3.handle_command("c3", "HS_SYNC 0", q)
        s3.handle_command("s3", "NVS_CHECK", q)
        s3.handle_command("s3", "HANDSHAKE 0", q)

        events = []
        while not q.empty():
            events.append(q.get())

        with self.assertRaisesRegex(DmpTestError, "S3 handshake failed: attempt-expired"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_serial_runner_rejects_firmware_owned_run_command(self):
        for command in ("RUN_PAIR 2 4096", "RUN_FOUR_SERIAL 2 4096", "RUN_FOUR_PARALLEL 2 4096"):
            with self.subTest(command=command):
                s3 = EspNowDmpStub("esp32s3", S3_MAC)
                q: queue.Queue = queue.Queue()
                s3.handle_command("s3", f"SESSION {SESSION}", q)
                s3.handle_command("s3", command, q)
                events = []
                while not q.empty():
                    events.append(q.get())
                rejected = [event for _, event in events if event.get("event") == "command_rejected"]
                self.assertEqual(len(rejected), 1)
                self.assertEqual(rejected[0].get("reason"), "runner-owned-scheduling")

    def test_pair_runner_fails_immediately_on_handshake_expiry(self):
        net = SimulatedEspNowNetwork()
        net.register("COM37", "s3", EspNowDmpStub("esp32s3", S3_MAC, fail_handshake=True))
        net.register("COM36", "c3", EspNowDmpStub("esp32c3", C3_MAC))
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(DmpTestError, "pair handshake failed on initiator: attempt-expired"):
                run_dmp_pair(
                    s3_port="COM37",
                    c3_port="COM36",
                    evidence_dir=tmpdir,
                    timeout=1.0,
                    serial_factory=net.make_factory(),
                )

    def test_pair_runner_surfaces_handshake_schedule_failure_before_timeout(self):
        net = SimulatedEspNowNetwork()
        net.register(
            "COM37",
            "s3",
            EspNowDmpStub("esp32s3", S3_MAC, fail_schedule=True),
        )
        net.register("COM36", "c3", EspNowDmpStub("esp32c3", C3_MAC))
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(
                DmpTestError,
                "handshake_started on S3 failed before start: first-flight-write status=2",
            ):
                run_dmp_pair(
                    s3_port="COM37",
                    c3_port="COM36",
                    evidence_dir=tmpdir,
                    timeout=1.0,
                    serial_factory=net.make_factory(),
                )

    def test_four_runner_surfaces_handshake_schedule_failure_before_timeout(self):
        net = SimulatedEspNowNetwork()
        net.register(
            "COM37",
            "s3",
            EspNowDmpStub("esp32s3", S3_MAC, profile="multi-peer", fail_schedule=True),
        )
        c3_ports = ["COM31", "COM32", "COM33", "COM34"]
        for i, port in enumerate(c3_ports):
            net.register(
                port,
                f"c3_{i}",
                EspNowDmpStub("esp32c3", PEER_MACS[i], profile="multi-peer"),
            )
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(
                DmpTestError,
                "handshake_started on S3 for peer 0 failed before start: first-flight-write status=2",
            ):
                run_dmp_four(
                    s3_port="COM37",
                    c3_ports=c3_ports,
                    mode="four_serial",
                    bytes_per_peer=4096,
                    evidence_dir=tmpdir,
                    count_per_peer=1,
                    timeout=1.0,
                    serial_factory=net.make_factory(),
                )

    def test_pair_runner_fails_immediately_on_handshake_poll_error(self):
        net = SimulatedEspNowNetwork()
        s3 = EspNowDmpStub("esp32s3", S3_MAC)
        s3.fail_poll_error = True
        net.register("COM37", "s3", s3)
        net.register("COM36", "c3", EspNowDmpStub("esp32c3", C3_MAC))
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(DmpTestError, "pair handshake failed on initiator: handshake-poll-unexpected"):
                run_dmp_pair(
                    s3_port="COM37",
                    c3_port="COM36",
                    evidence_dir=tmpdir,
                    timeout=1.0,
                    serial_factory=net.make_factory(),
                )

    def test_four_runner_fails_immediately_on_handshake_expiry(self):
        net = SimulatedEspNowNetwork()
        net.register("COM37", "s3", EspNowDmpStub("esp32s3", S3_MAC, profile="multi-peer", fail_handshake=True))
        c3_ports = ["COM31", "COM32", "COM33", "COM34"]
        for i, port in enumerate(c3_ports):
            net.register(port, f"c3_{i}", EspNowDmpStub("esp32c3", PEER_MACS[i], profile="multi-peer"))
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(DmpTestError, "handshake with c3_0 failed on initiator: attempt-expired"):
                run_dmp_four(
                    s3_port="COM37",
                    c3_ports=c3_ports,
                    mode="four_serial",
                    bytes_per_peer=4096,
                    evidence_dir=tmpdir,
                    timeout=1.0,
                    serial_factory=net.make_factory(),
                )

    def test_simulated_pair_run_fails_closed_on_nvs_monotonic_violation(self):
        s3 = EspNowDmpStub("esp32s3", S3_MAC, fail_nvs=True)
        c3 = EspNowDmpStub("esp32c3", C3_MAC)
        q: queue.Queue = queue.Queue()

        s3.handle_command("s3", "INFO", q)
        c3.handle_command("c3", "INFO", q)
        s3.handle_command("s3", f"SESSION {SESSION}", q)
        c3.handle_command("c3", f"SESSION {SESSION}", q)
        s3.handle_command("s3", f"ROLE controller retry-2 {PAIR_CONTROLLER_NODE_ID} 1", q)
        c3.handle_command("c3", f"ROLE peer retry-2 {PAIR_PEER_NODE_ID} 1", q)
        s3.handle_command("s3", f"PEER {C3_MAC} 20", q)
        c3.handle_command("c3", f"PEER {S3_MAC} 10", q)
        s3.handle_command("s3", "HS_SYNC 0", q)
        c3.handle_command("c3", "HS_SYNC 0", q)
        s3.handle_command("s3", "NVS_CHECK", q)

        events = []
        while not q.empty():
            events.append(q.get())

        with self.assertRaisesRegex(DmpTestError, "violated monotonicity"):
            validate_dmp_pair_events(events, 1024, SESSION)

    def test_run_dmp_pair_orchestration(self):
        net = SimulatedEspNowNetwork()
        s3_stub = EspNowDmpStub("esp32s3", S3_MAC)
        c3_stub = EspNowDmpStub("esp32c3", C3_MAC)
        net.register("COM37", "s3", s3_stub)
        net.register("COM36", "c3", c3_stub)

        with tempfile.TemporaryDirectory() as tmpdir:
            res = run_dmp_pair(
                s3_port="COM37",
                c3_port="COM36",
                count=2,
                transfer_bytes=1024,
                evidence_dir=tmpdir,
                timeout=5.0,
                serial_factory=net.make_factory(),
            )
            self.assertEqual(res["result"], "PASS")
            self.assertEqual(res["peer_count"], 1)
            self.assertEqual(res["transfer_bytes"], 1024)
            self.assertEqual(res["fragments"], 16)
            self.assertTrue(Path(res["evidence_dir"]).is_dir())
            evidence_json = Path(res["evidence_dir"]) / "evidence.json"
            self.assertTrue(evidence_json.is_file())
            commands_log = Path(res["evidence_dir"]) / "commands.log"
            self.assertTrue(commands_log.is_file())
            content = commands_log.read_text(encoding="utf-8")
            self.assertNotIn("4a5b6c7d", content.lower())  # Verify no PSK logged
            commands = [json.loads(line) for line in content.splitlines()]
            s3_commands = [
                entry["command"] for entry in commands
                if entry.get("port") == "COM37" and entry.get("status") == "sent"
            ]
            handshake_command = s3_commands.index("HANDSHAKE 0")
            self.assertEqual(s3_commands[handshake_command - 1], "INFO")
            self.assertIn("HS_SYNC 0", s3_commands[:handshake_command])

    def test_pair_runner_waits_for_v2_probe_tx_completion_before_transfer(self):
        net = SimulatedEspNowNetwork()
        s3_stub = EspNowDmpStub("esp32s3", S3_MAC, defer_v2_tx_done=True)
        c3_stub = EspNowDmpStub("esp32c3", C3_MAC)
        net.register("COM37", "s3", s3_stub)
        net.register("COM40", "c3", c3_stub)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_dmp_pair(
                s3_port="COM37",
                c3_port="COM40",
                count=1,
                transfer_bytes=64,
                evidence_dir=tmpdir,
                timeout=2.0,
                serial_factory=net.make_factory(),
            )

        self.assertEqual(result["result"], "PASS")
        self.assertFalse(s3_stub.transfer_started_while_v2_tx_pending)

    def test_pair_runner_waits_for_sample_response_tx_before_v2_probe(self):
        net = SimulatedEspNowNetwork()
        s3_stub = EspNowDmpStub("esp32s3", S3_MAC, defer_sample_response_tx_done=True)
        c3_stub = EspNowDmpStub("esp32c3", C3_MAC)
        net.register("COM37", "s3", s3_stub)
        net.register("COM40", "c3", c3_stub)

        started = time.monotonic()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_dmp_pair(
                s3_port="COM37",
                c3_port="COM40",
                count=1,
                transfer_bytes=64,
                evidence_dir=tmpdir,
                timeout=2.0,
                serial_factory=net.make_factory(),
            )

        self.assertGreaterEqual(time.monotonic() - started, 0.45)
        self.assertEqual(result["result"], "PASS")
        self.assertFalse(s3_stub.v2_frame_started_while_sample_response_tx_pending)

    def test_pair_runner_surfaces_v2_probe_submission_failure_before_timeout(self):
        net = SimulatedEspNowNetwork()
        s3_stub = EspNowDmpStub("esp32s3", S3_MAC, fail_v2_frame=True)
        c3_stub = EspNowDmpStub("esp32c3", C3_MAC)
        net.register("COM37", "s3", s3_stub)
        net.register("COM40", "c3", c3_stub)

        with tempfile.TemporaryDirectory() as tmpdir:
            started = time.monotonic()
            with self.assertRaisesRegex(
                DmpTestError, "V2_FRAME probe submission failed: transport-rejected"
            ):
                run_dmp_pair(
                    s3_port="COM37",
                    c3_port="COM40",
                    count=1,
                    transfer_bytes=64,
                    evidence_dir=tmpdir,
                    timeout=2.0,
                    serial_factory=net.make_factory(),
                )
            self.assertLess(time.monotonic() - started, 1.0)

    def test_pair_runner_surfaces_peer_registration_rejection_before_timeout(self):
        net = SimulatedEspNowNetwork()
        s3_stub = EspNowDmpStub("esp32s3", S3_MAC, fail_peer=True)
        c3_stub = EspNowDmpStub("esp32c3", C3_MAC)
        net.register("COM37", "s3", s3_stub)
        net.register("COM40", "c3", c3_stub)

        with tempfile.TemporaryDirectory() as tmpdir:
            started = time.monotonic()
            with self.assertRaisesRegex(DmpTestError, "endpoint-add-peer-failed"):
                run_dmp_pair(
                    s3_port="COM37",
                    c3_port="COM40",
                    count=1,
                    transfer_bytes=64,
                    evidence_dir=tmpdir,
                    timeout=2.0,
                    serial_factory=net.make_factory(),
                )
            self.assertLess(time.monotonic() - started, 1.0)

    def test_pair_runner_surfaces_sample_read_submission_failure_before_result_timeout(self):
        net = SimulatedEspNowNetwork()
        s3_stub = EspNowDmpStub("esp32s3", S3_MAC)
        c3_stub = EspNowDmpStub("esp32c3", C3_MAC, sample_read_status=3)
        net.register("COM37", "s3", s3_stub)
        net.register("COM40", "c3", c3_stub)

        with tempfile.TemporaryDirectory() as tmpdir:
            started = time.monotonic()
            with self.assertRaisesRegex(
                DmpTestError, "SAMPLE-1 READ submission failed with DMP status 3"
            ):
                run_dmp_pair(
                    s3_port="COM37",
                    c3_port="COM40",
                    count=1,
                    transfer_bytes=64,
                    evidence_dir=tmpdir,
                    timeout=2.0,
                    serial_factory=net.make_factory(),
                )
            self.assertLess(time.monotonic() - started, 1.0)

    def test_run_dmp_four_serial_orchestration(self):
        net = SimulatedEspNowNetwork()
        s3_stub = EspNowDmpStub("esp32s3", S3_MAC, profile="multi-peer")
        net.register("COM37", "s3", s3_stub)

        c3_ports = ["COM31", "COM32", "COM33", "COM34"]
        for i, p in enumerate(c3_ports):
            c3_stub = EspNowDmpStub("esp32c3", PEER_MACS[i], profile="multi-peer")
            net.register(p, f"c3_{i}", c3_stub)

        with tempfile.TemporaryDirectory() as tmpdir:
            res = run_dmp_four(
                s3_port="COM37",
                c3_ports=c3_ports,
                mode="four_serial",
                count_per_peer=2,
                bytes_per_peer=4096,
                evidence_dir=tmpdir,
                timeout=5.0,
                serial_factory=net.make_factory(),
            )
            self.assertEqual(res["result"], "PASS")
            self.assertEqual(res["mode"], "four_serial")
            self.assertEqual(res["peer_count"], 4)
            self.assertEqual(res["count_per_peer"], 2)
            self.assertEqual(res["total_boards"], 5)
            self.assertTrue(Path(res["evidence_dir"]).is_dir())

    def test_run_dmp_three_peer_serial_orchestration(self):
        net = SimulatedEspNowNetwork()
        s3_stub = EspNowDmpStub("esp32s3", S3_MAC, profile="multi-peer")
        net.register("COM37", "s3", s3_stub)

        c3_ports = ["COM36", "COM38", "COM40"]
        for i, port in enumerate(c3_ports):
            c3_stub = EspNowDmpStub("esp32c3", PEER_MACS[i], profile="multi-peer")
            net.register(port, f"c3_{i}", c3_stub)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_dmp_three_peer_serial(
                s3_port="COM37",
                c3_ports=c3_ports,
                count_per_peer=1,
                bytes_per_peer=256,
                evidence_dir=tmpdir,
                timeout=5.0,
                serial_factory=net.make_factory(),
            )
            self.assertTrue(Path(result["evidence_dir"]).is_dir())
            command_log = Path(result["evidence_dir"]) / "commands.log"
            commands = [
                json.loads(line)
                for line in command_log.read_text(encoding="utf-8").splitlines()
            ]
            read_ports = {
                entry["port"] for entry in commands
                if entry.get("command") == "SAMPLE_READ 0" and entry.get("status") == "sent"
            }

        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["mode"], "three_peer_serial")
        self.assertEqual(result["peer_count"], 3)
        self.assertEqual(result["total_boards"], 4)
        self.assertEqual(result["sample1_read_peer_count"], 3)
        self.assertEqual(result["peer_node_ids"], list(FOUR_PEER_NODE_IDS[:3]))
        self.assertEqual(result["decoded_core_mtu_bytes"], 256)
        self.assertEqual(result["stream_r_encoded_mtu_bytes"], 263)
        self.assertEqual(len(s3_stub.peers), 3)
        self.assertEqual(read_ports, set(c3_ports))

    def test_three_peer_runner_waits_for_each_sample_response_tx(self):
        net = SimulatedEspNowNetwork()
        s3_stub = EspNowDmpStub(
            "esp32s3", S3_MAC, profile="multi-peer", defer_sample_response_tx_done=True
        )
        net.register("COM37", "s3", s3_stub)
        c3_ports = ["COM36", "COM38", "COM40"]
        for i, port in enumerate(c3_ports):
            net.register(
                port,
                f"c3_{i}",
                EspNowDmpStub("esp32c3", PEER_MACS[i], profile="multi-peer"),
            )

        started = time.monotonic()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = run_dmp_three_peer_serial(
                s3_port="COM37",
                c3_ports=c3_ports,
                count_per_peer=1,
                bytes_per_peer=64,
                evidence_dir=tmpdir,
                timeout=3.0,
                serial_factory=net.make_factory(),
            )

        self.assertGreaterEqual(time.monotonic() - started, 1.4)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["sample1_read_peer_count"], 3)

    def test_run_dmp_four_parallel_orchestration(self):
        net = SimulatedEspNowNetwork()
        s3_stub = EspNowDmpStub("esp32s3", S3_MAC, profile="multi-peer")
        net.register("COM37", "s3", s3_stub)

        c3_ports = ["COM31", "COM32", "COM33", "COM34"]
        for i, p in enumerate(c3_ports):
            c3_stub = EspNowDmpStub("esp32c3", PEER_MACS[i], profile="multi-peer")
            net.register(p, f"c3_{i}", c3_stub)

        with tempfile.TemporaryDirectory() as tmpdir:
            res = run_dmp_four(
                s3_port="COM37",
                c3_ports=c3_ports,
                mode="four_parallel",
                count_per_peer=1,
                bytes_per_peer=2048,
                evidence_dir=tmpdir,
                timeout=5.0,
                serial_factory=net.make_factory(),
            )
            self.assertEqual(res["result"], "PASS")
            self.assertEqual(res["mode"], "four_parallel")
            self.assertEqual(res["peer_count"], 4)
            self.assertEqual(res["bytes_per_peer"], 2048)
            self.assertEqual(res["fragments_per_peer"], 16)

    def test_run_dmp_four_parallel_multi_count(self):
        net = SimulatedEspNowNetwork()
        s3_stub = EspNowDmpStub("esp32s3", S3_MAC, profile="multi-peer")
        net.register("COM37", "s3", s3_stub)

        c3_ports = ["COM31", "COM32", "COM33", "COM34"]
        for i, p in enumerate(c3_ports):
            c3_stub = EspNowDmpStub("esp32c3", PEER_MACS[i], profile="multi-peer")
            net.register(p, f"c3_{i}", c3_stub)

        with tempfile.TemporaryDirectory() as tmpdir:
            res = run_dmp_four(
                s3_port="COM37",
                c3_ports=c3_ports,
                mode="four_parallel",
                count_per_peer=2,
                bytes_per_peer=2048,
                evidence_dir=tmpdir,
                timeout=5.0,
                serial_factory=net.make_factory(),
            )
            self.assertEqual(res["result"], "PASS")
            self.assertEqual(res["mode"], "four_parallel")
            self.assertEqual(res["peer_count"], 4)
            self.assertEqual(res["count_per_peer"], 2)
            self.assertEqual(res["bytes_per_peer"], 2048)
            self.assertEqual(res["fragments_per_peer"], 16)

    def test_run_dmp_pair_fails_on_duplicate_ports(self):
        with self.assertRaisesRegex(DmpTestError, "duplicate serial port"):
            run_dmp_pair(s3_port="COM1", c3_port="COM1")

    def test_run_dmp_four_fails_on_duplicate_ports(self):
        with self.assertRaisesRegex(DmpTestError, "detected duplicates"):
            run_dmp_four(s3_port="COM1", c3_ports=["COM1", "COM2", "COM3", "COM4"])

    def test_run_dmp_pair_timeout_fails_closed(self):
        net = SimulatedEspNowNetwork()
        # Create non-responding stub
        s3_stub = EspNowDmpStub("esp32s3", S3_MAC)
        c3_stub = EspNowDmpStub("esp32c3", C3_MAC)
        # S3 writes commands, but stub does not emit ready for C3
        c3_stub.handle_command = lambda *args, **kwargs: None  # Silent C3
        net.register("COM37", "s3", s3_stub)
        net.register("COM36", "c3", c3_stub)

        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(DmpTestError, "Timeout .* waiting for ready on C3"):
                run_dmp_pair(
                    s3_port="COM37",
                    c3_port="COM36",
                    evidence_dir=tmpdir,
                    timeout=0.3,
                    serial_factory=net.make_factory(),
                )

    def test_evidence_dir_unique_non_colliding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            dir1 = create_evidence_dir(tmpdir, prefix="test")
            dir2 = create_evidence_dir(tmpdir, prefix="test")
            self.assertNotEqual(dir1, dir2)
            self.assertTrue(dir1.is_dir())
            self.assertTrue(dir2.is_dir())


if __name__ == "__main__":
    unittest.main()
