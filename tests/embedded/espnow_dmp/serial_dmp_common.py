#!/usr/bin/env python3
"""Common utilities and protocol validation for ESP-NOW DMP qualification.

Shared between the host test suite and the hardware qualification runners.
Handles JSON event parsing, device specification, command logging, and
validation of firmware readiness, MTU constraints, and NVS epoch reservation.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable


MAC_PATTERN = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z", re.IGNORECASE)
SESSION_PATTERN = re.compile(r"^[0-9a-f]{16}\Z")


RETRY_2_PROFILE_HASH = "478af0bc4912d0fc46ed76c249ec5f30f8f64bc89ed7411e9b9231bbf487db5c"
MULTI_PEER_PROFILE_HASH = "001eb42d8f440e0ceaf1711e764ceacfc3c1dd034cfb2d7f320be7d877f7454f"
RETRY_2_EPOCH_NVS_KEY = "s1_epoch_test"
MULTI_PEER_EPOCH_NVS_KEY = "s1_epoch_mp"

PAIR_CONTROLLER_NODE_ID = 10
PAIR_PEER_NODE_ID = 20
FOUR_CONTROLLER_NODE_ID = 20
FOUR_PEER_NODE_IDS = (10, 35, 34, 36)

CORE_MTU_BYTES = 256
STREAM_R_ENCODED_MTU_BYTES = 263
ESPNOW_V1_PAYLOAD_MTU_BYTES = 250
ESPNOW_V2_PAYLOAD_MTU_BYTES = 1470


class DmpTestError(RuntimeError):
    """Firmware qualification failed or produced invalid/inconclusive evidence."""


@dataclass(frozen=True)
class DeviceSpec:
    side: str
    port: str
    target: str
    image: Path


def parse_json_event(line: bytes) -> dict[str, Any] | None:
    """Return a parsed JSON firmware event, tolerating boot text and partial lines."""
    try:
        decoded = line.decode("utf-8", errors="replace").strip()
    except Exception:
        return None
    start = decoded.find("{")
    if start < 0:
        return None
    try:
        value = json.loads(decoded[start:])
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("event"), str):
        return None
    return value


def validate_ready_event(event: dict[str, Any], expected_target: str) -> dict[str, Any]:
    """Validate a firmware 'ready' event against target and protocol MTU invariants."""
    if event.get("event") != "ready":
        raise DmpTestError(f"Expected 'ready' event, got {event.get('event')!r}")
    target = event.get("target")
    if target != expected_target:
        raise DmpTestError(f"Target mismatch: got {target!r}, expected {expected_target!r}")
    if event.get("firmware") != "dmp-espnow-dmp/0.1":
        raise DmpTestError(f"Firmware mismatch: {event.get('firmware')!r}")
    if event.get("idf") != "ESP-IDF v6.1":
        raise DmpTestError(f"IDF version mismatch: {event.get('idf')!r}")
    if event.get("test_mode") != "authenticated-dmp-endpoint":
        raise DmpTestError(f"Test mode mismatch: {event.get('test_mode')!r}")

    # Protocol MTU bounds
    if event.get("decoded_core_mtu_bytes") != 256:
        raise DmpTestError("Firmware did not report decoded Core MTU 256")
    if event.get("stream_r_encoded_mtu_bytes") != 263:
        raise DmpTestError("Firmware did not report Stream R encoded MTU 263")
    if event.get("espnow_v1_payload_mtu_bytes") != 250:
        raise DmpTestError("Firmware did not report ESP-NOW v1 payload MTU 250")
    if event.get("espnow_v2_payload_mtu_bytes") != 1470:
        raise DmpTestError("Firmware did not report ESP-NOW v2 payload MTU 1470")

    version = event.get("espnow_version")
    if not isinstance(version, int) or version < 2:
        raise DmpTestError(f"Firmware reported invalid or non-v2 espnow_version: {version}")

    if event.get("channel") != 1:
        raise DmpTestError(f"WiFi channel is {event.get('channel')}, expected 1")
    if event.get("peer_capacity") != 4:
        raise DmpTestError(f"Peer capacity is {event.get('peer_capacity')}, expected 4")

    mac = event.get("mac")
    if not isinstance(mac, str) or not MAC_PATTERN.match(mac):
        raise DmpTestError(f"Invalid station MAC address: {mac!r}")

    return event


def validate_nvs_check(
    event: dict[str, Any],
    session: str,
    expected_key: str = RETRY_2_EPOCH_NVS_KEY,
) -> dict[str, Any]:
    """Validate SAMPLE-1 NVS epoch reservation, ensuring monotonic progression and fail-closed handling."""
    if event.get("event") != "nvs_epoch_check":
        raise DmpTestError(f"Expected 'nvs_epoch_check' event, got {event.get('event')!r}")
    if event.get("session") != session:
        raise DmpTestError(f"NVS check session mismatch: got {event.get('session')!r}, expected {session!r}")

    status = event.get("status")
    if status == "fail_open":
        raise DmpTestError(f"NVS check failed to open storage: error={event.get('error')}")
    if status == "fail_reserve":
        raise DmpTestError(f"NVS check failed to reserve epoch: port_error={event.get('port_error')}")
    if status == "fail_monotonic":
        raise DmpTestError(
            f"NVS check violated monotonicity: prev={event.get('previous_epoch')} "
            f"reserved={event.get('reserved_epoch')}"
        )
    if status != "ok":
        raise DmpTestError(f"NVS check reported unknown status: {status!r}")

    if event.get("namespace") != "dmp_test_nvs":
        raise DmpTestError(f"Unexpected NVS namespace: {event.get('namespace')!r}")
    if event.get("key") != expected_key:
        raise DmpTestError(f"Unexpected NVS key: {event.get('key')!r}")

    has_prev = event.get("has_previous")
    prev_epoch = event.get("previous_epoch")
    reserved_epoch = event.get("reserved_epoch")

    if not isinstance(reserved_epoch, int) or reserved_epoch == 0:
        raise DmpTestError("NVS reserved epoch must be a non-zero integer")
    if has_prev is True and prev_epoch is not None and reserved_epoch <= prev_epoch:
        raise DmpTestError(f"Monotonic violation: reserved {reserved_epoch} <= prev {prev_epoch}")

    return event


class HostCommandLog:
    """Thread-safe command logger for host-side serial interaction."""

    def __init__(self, path: Path):
        self._stream = path.open("w", encoding="utf-8")
        self._lock = threading.Lock()

    def record(self, port: str, command: str, status: str, **fields: Any) -> None:
        record = {
            "host_unix_time_ns": time.time_ns(),
            "event": "host_command",
            "port": port,
            "command": command,
            "command_bytes_base64": base64.b64encode(command.encode("ascii") + b"\n").decode("ascii"),
            "status": status,
            **fields,
        }
        with self._lock:
            self._stream.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._stream.flush()

    def close(self) -> None:
        with self._lock:
            self._stream.close()


def create_evidence_dir(base_dir: Path | str | None = None, prefix: str = "run") -> Path:
    """Create a unique non-overwriting evidence directory."""
    base = Path(base_dir) if base_dir is not None else Path("dev/evidence/espnow_dmp")
    base.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    for _ in range(100):
        token = secrets.token_hex(4)
        target = base / f"{prefix}_{timestamp}_{token}"
        try:
            target.mkdir(parents=True, exist_ok=False)
            return target
        except FileExistsError:
            continue
    token = secrets.token_hex(8)
    target = base / f"{prefix}_{timestamp}_{time.time_ns()}_{token}"
    target.mkdir(parents=True, exist_ok=False)
    return target


def default_serial_factory(port: str, baudrate: int = 115200, timeout: float = 1.0) -> Any:
    """Open a hardware serial port lazily without importing pyserial at module load."""
    try:
        import serial
    except ImportError as exc:
        raise DmpTestError(
            "pyserial is required for hardware qualification runs. "
            "Install pyserial or inject a mock serial factory for host testing."
        ) from exc
    return serial.Serial(port, baudrate=baudrate, timeout=timeout)


class SerialDeviceSession:
    """Thread-safe serial device manager capturing raw bytes and JSON events."""

    def __init__(
        self,
        side: str,
        port_name: str,
        port_obj: Any,
        evidence_dir: Path,
        cmd_log: HostCommandLog | None = None,
        expected_session: str | None = None,
    ):
        self.side = side
        self.port_name = port_name
        self.port_obj = port_obj
        self.evidence_dir = evidence_dir
        self.cmd_log = cmd_log
        self.expected_session = expected_session

        self.raw_path = evidence_dir / f"raw_serial_{side}.bin"
        self.jsonl_path = evidence_dir / f"events_{side}.jsonl"

        self._raw_file = self.raw_path.open("wb")
        self._jsonl_file = self.jsonl_path.open("w", encoding="utf-8")

        self._events: list[dict[str, Any]] = []
        self._expected_session_event_index: int | None = None
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._stopped = False
        self._reader_error: Exception | None = None

        self._reader_thread = threading.Thread(
            target=self._reader_loop,
            name=f"SerialReader-{side}",
            daemon=True,
        )
        self._reader_thread.start()

    def _reader_loop(self) -> None:
        while not self._stopped:
            try:
                line = self.port_obj.readline()
            except Exception as exc:
                if not self._stopped:
                    self._reader_error = exc
                break
            if not line:
                continue

            raw_bytes = line if isinstance(line, bytes) else str(line).encode("utf-8")
            with self._lock:
                self._raw_file.write(raw_bytes)
                self._raw_file.flush()

                parsed = parse_json_event(raw_bytes)
                if parsed is not None:
                    now_ns = time.time_ns()
                    entry = {
                        "host_unix_time_ns": now_ns,
                        "side": self.side,
                        "port": self.port_name,
                        "event": parsed,
                    }
                    self._jsonl_file.write(json.dumps(entry, separators=(",", ":")) + "\n")
                    self._jsonl_file.flush()
                    event_index = len(self._events)
                    self._events.append(parsed)
                    if (
                        self.expected_session is not None
                        and self._expected_session_event_index is None
                        and parsed.get("event") == "session_set"
                        and parsed.get("session") == self.expected_session
                    ):
                        self._expected_session_event_index = event_index
                    self._cond.notify_all()

    def send_command(self, cmd: str) -> None:
        cmd_clean = cmd.strip()
        line_bytes = cmd_clean.encode("ascii") + b"\n"
        if self.cmd_log:
            self.cmd_log.record(self.port_name, cmd_clean, "sending")
        try:
            self.port_obj.write(line_bytes)
            if hasattr(self.port_obj, "flush"):
                self.port_obj.flush()
        except Exception as exc:
            if self.cmd_log:
                self.cmd_log.record(self.port_name, cmd_clean, "failed", error=str(exc))
            raise
        if self.cmd_log:
            self.cmd_log.record(self.port_name, cmd_clean, "sent")

    @property
    def event_count(self) -> int:
        with self._lock:
            return len(self._events)

    def wait_for_event(
        self,
        predicate: Callable[[dict[str, Any]], bool],
        timeout: float = 10.0,
        desc: str = "event",
        start_index: int = 0,
    ) -> dict[str, Any]:
        deadline = time.time() + timeout
        with self._cond:
            for event_index in range(start_index, len(self._events)):
                ev = self._events[event_index]
                if predicate(ev):
                    return ev
                self._raise_if_firmware_rejected(ev, desc, event_index)
            while True:
                if self._reader_error is not None:
                    raise DmpTestError(f"Serial reader error on {self.side}: {self._reader_error}")
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise DmpTestError(f"Timeout ({timeout:.1f}s) waiting for {desc} on {self.side}")
                self._cond.wait(timeout=min(remaining, 0.1))
                for event_index in range(start_index, len(self._events)):
                    ev = self._events[event_index]
                    if predicate(ev):
                        return ev
                    self._raise_if_firmware_rejected(ev, desc, event_index)

    def _raise_if_firmware_rejected(
        self, event: dict[str, Any], desc: str, event_index: int
    ) -> None:
        event_name = event.get("event")
        event_session = event.get("session")
        if self.expected_session is not None:
            if event_session is not None and event_session != self.expected_session:
                return
            if event_session is None and (
                self._expected_session_event_index is None
                or event_index < self._expected_session_event_index
            ):
                return
        if event_name in ("command_rejected", "role_failed", "handshake_stream_sync_failed") or (
            event_name == "error" and event.get("status") == "fail_closed"
        ):
            reason = event.get("reason", event_name)
            raise DmpTestError(
                f"Firmware rejected command while waiting for {desc} on {self.side}: {reason}"
            )

    def get_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def close(self) -> None:
        self._stopped = True
        try:
            self.port_obj.close()
        except Exception:
            pass
        if self._reader_thread.is_alive():
            self._reader_thread.join(timeout=1.0)
        with self._lock:
            try:
                self._raw_file.close()
            except Exception:
                pass
            try:
                self._jsonl_file.close()
            except Exception:
                pass


def wait_for_handshake_result(
    device: SerialDeviceSession,
    session: str,
    timeout: float,
    desc: str,
    peer_handle: int | None = None,
) -> dict[str, Any]:
    """Return only a successful handshake result; surface firmware failures immediately."""

    def is_result(event: dict[str, Any]) -> bool:
        if event.get("session") != session:
            return False
        event_name = event.get("event")
        if event_name not in ("handshake_done", "handshake_failed") and not (
            event_name == "error" and event.get("status") == "fail_closed"
        ):
            return False
        event_peer = event.get("peer_handle")
        return peer_handle is None or event_peer is None or event_peer == peer_handle

    event = device.wait_for_event(is_result, timeout=timeout, desc=desc)
    if event.get("event") in ("handshake_failed", "error"):
        reason = event.get("reason", "unspecified")
        raise DmpTestError(f"{desc} failed: {reason}")
    if event.get("status") != "success":
        raise DmpTestError(f"{desc} completed with status {event.get('status')!r}")
    return event


def wait_for_handshake_pair(
    initiator: SerialDeviceSession,
    responder: SerialDeviceSession,
    session: str,
    timeout: float,
    desc: str,
    initiator_peer_handle: int,
    responder_peer_handle: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Wait for endpoint activation and an accepted READY submit together.

    The responder activates on authenticated FINISH, while application TX is
    allowed only after READY is accepted by its transport. BUSY can be retried
    by duplicate FINISH; permanent submit failures are surfaced immediately.
    """
    deadline = time.monotonic() + timeout
    done: dict[str, dict[str, Any]] = {}
    ready_accepted = False
    last_ready_busy: Any = None

    def matches_peer(event: dict[str, Any], peer_handle: int) -> bool:
        event_peer = event.get("peer_handle")
        return event_peer is None or event_peer == peer_handle

    while True:
        for device, label, peer_handle in (
            (initiator, "initiator", initiator_peer_handle),
            (responder, "responder", responder_peer_handle),
        ):
            for event in device.get_events():
                if event.get("session") != session or not matches_peer(event, peer_handle):
                    continue
                event_name = event.get("event")
                if event_name == "handshake_failed" or (
                    event_name == "error" and event.get("status") == "fail_closed"
                ):
                    raise DmpTestError(
                        f"{desc} failed on {label}: {event.get('reason', event_name)}"
                    )
                if event_name == "handshake_done":
                    if event.get("status") != "success":
                        raise DmpTestError(
                            f"{desc} completed on {label} with status {event.get('status')!r}"
                        )
                    done[label] = event
                if label == "responder" and event_name == "handshake_ready_submit":
                    if event.get("accepted") is True:
                        ready_accepted = True
                    elif event.get("status_name") == "busy":
                        last_ready_busy = event.get("status")
                    elif not ready_accepted:
                        raise DmpTestError(
                            f"{desc} responder rejected protected READY transport submission: "
                            f"status={event.get('status_name', event.get('status'))!r}"
                        )

        if len(done) == 2 and ready_accepted:
            return done["initiator"], done["responder"]
        if len(done) == 2 and not ready_accepted:
            raise DmpTestError(
                f"{desc} endpoints became active without an accepted READY transport submission"
            )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if not ready_accepted:
                suffix = (
                    f"; last READY submit status={last_ready_busy!r}"
                    if last_ready_busy is not None
                    else ""
                )
                raise DmpTestError(
                    f"Timeout waiting for responder to accept protected READY submission for {desc}{suffix}"
                )
            missing = " and ".join(label for label in ("initiator", "responder") if label not in done)
            raise DmpTestError(f"Timeout waiting for {desc} activation on {missing}")
        time.sleep(min(0.05, remaining))


def wait_for_handshake_start(
    device: SerialDeviceSession,
    session: str,
    timeout: float,
    desc: str,
    peer_handle: int | None = None,
) -> dict[str, Any]:
    """Return handshake_started or surface a synchronous scheduling failure."""

    def is_start_or_failure(event: dict[str, Any]) -> bool:
        if event.get("session") != session:
            return False
        event_name = event.get("event")
        if event_name not in (
            "handshake_started",
            "handshake_failed",
            "handshake_schedule_diagnostic",
        ) and not (event_name == "error" and event.get("status") == "fail_closed"):
            return False
        event_peer = event.get("peer_handle")
        return peer_handle is None or event_peer is None or event_peer == peer_handle

    event = device.wait_for_event(is_start_or_failure, timeout=timeout, desc=desc)
    if event.get("event") != "handshake_started":
        reason = event.get("reason") or event.get("stage") or event.get("event", "unspecified")
        status = event.get("status")
        suffix = "" if status is None else f" status={status}"
        raise DmpTestError(f"{desc} failed before start: {reason}{suffix}")
    return event
