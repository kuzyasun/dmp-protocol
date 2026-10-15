#!/usr/bin/env python3
"""Capture and run a bounded ESP-NOW DMP core-frame echo on S3/C3 boards.

This is a transport smoke test. It does not perform SEC-1 authentication or
claim DMP endpoint acceptance. Raw bytes from both Serial/JTAG ports are kept
alongside a timestamped line index and a machine-checked result.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import queue
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable


DEFAULT_S3_PORT = "COM37"
DEFAULT_C3_PORT = "COM36"
DEFAULT_S3_BIN = Path("build/espnow-pair-esp32s3/dmp_espnow_pair.bin")
DEFAULT_C3_BIN = Path("build/espnow-pair-esp32c3/dmp_espnow_pair.bin")
DEFAULT_EVIDENCE_ROOT = Path("dev/evidence/espnow-pair")
MAX_COUNT = 1000
MAX_PAYLOAD_BYTES = 240
MAC_PATTERN = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z", re.IGNORECASE)


class PairTestError(RuntimeError):
    """The serial run failed or did not produce conclusive evidence."""


@dataclass(frozen=True)
class DeviceSpec:
    side: str
    port: str
    target: str
    image: Path


def parse_json_event(line: bytes) -> dict[str, Any] | None:
    """Return a firmware event from a line, tolerating unterminated boot text."""
    try:
        decoded = line.decode("utf-8").strip()
    except (UnicodeDecodeError, json.JSONDecodeError):
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


def validate_pair_events(
    tagged_events: Iterable[tuple[str, dict[str, Any]]], count: int,
    payload_bytes: int,
    session: str,
) -> dict[str, Any]:
    """Validate S3 initiator and C3 echo evidence without treating MAC ACK as DMP ACK."""
    if not re.fullmatch(r"[0-9a-f]{16}", session):
        raise PairTestError("the run session token is not a 64-bit lowercase hex value")
    by_side: dict[str, list[dict[str, Any]]] = {"s3": [], "c3": []}
    for side, event in tagged_events:
        if side in by_side and (event.get("event") == "ready" or event.get("session") == session):
            by_side[side].append(event)

    def first_ready(side: str, target: str) -> dict[str, Any]:
        matches = [e for e in by_side[side] if e.get("event") == "ready"]
        if not matches:
            raise PairTestError(f"{side.upper()} did not report ready")
        ready = matches[-1]
        if ready.get("target") != target:
            raise PairTestError(
                f"{side.upper()} reports {ready.get('target')!r}, expected {target}"
            )
        if ready.get("test_mode") != "unauthenticated-core-echo":
            raise PairTestError(f"{side.upper()} firmware test mode is unexpected")
        if ready.get("decoded_core_mtu_bytes") != 256:
            raise PairTestError(f"{side.upper()} did not report the 256-byte core MTU")
        if ready.get("stream_r_encoded_mtu_bytes") != 263:
            raise PairTestError(f"{side.upper()} did not report the 263-byte Stream R MTU")
        if ready.get("espnow_v1_payload_mtu_bytes") != 250:
            raise PairTestError(f"{side.upper()} did not report the ESP-NOW v1 limit")
        expected_capacity = 3 if side == "s3" else 1
        if ready.get("peer_capacity") != expected_capacity:
            raise PairTestError(f"{side.upper()} peer capacity is not {expected_capacity}")
        if ready.get("channel") != 1:
            raise PairTestError(f"{side.upper()} is not on the agreed test channel 1")
        mac = ready.get("mac")
        if not isinstance(mac, str) or not MAC_PATTERN.fullmatch(mac):
            raise PairTestError(f"{side.upper()} reported an invalid station MAC")
        return ready

    s3 = first_ready("s3", "esp32s3")
    c3 = first_ready("c3", "esp32c3")
    s3_mac, c3_mac = s3["mac"].lower(), c3["mac"].lower()
    if s3_mac == c3_mac:
        raise PairTestError("the two devices reported the same station MAC")

    for side in ("s3", "c3"):
        sessions = [e for e in by_side[side] if e.get("event") == "session_set"]
        if len(sessions) != 1 or sessions[0].get("session") != session:
            raise PairTestError(f"{side.upper()} did not confirm the current test session")

    def has_event(side: str, name: str, predicate: Callable[[dict[str, Any]], bool]) -> bool:
        return any(e.get("event") == name and predicate(e) for e in by_side[side])

    if not has_event("s3", "peer_added", lambda e: str(e.get("peer_mac", "")).lower() == c3_mac):
        raise PairTestError("S3 did not confirm C3 as its unicast peer")
    if not has_event("c3", "peer_added", lambda e: str(e.get("peer_mac", "")).lower() == s3_mac):
        raise PairTestError("C3 did not confirm S3 as its unicast peer")
    if not has_event("c3", "echo_mode", lambda e: e.get("enabled") is True):
        raise PairTestError("C3 did not confirm echo mode")

    started = [e for e in by_side["s3"] if e.get("event") == "run_started"]
    if (len(started) != 1 or started[0].get("count") != count or
            started[0].get("payload_bytes") != payload_bytes or
            started[0].get("peer_count") != 1):
        raise PairTestError("S3 did not report exactly one current run with the requested parameters")
    done = [e for e in by_side["s3"] if e.get("event") == "run_done"]
    if (len(done) != 1 or done[0].get("pass") is not True or
            done[0].get("completed") != count or done[0].get("peer_count") != 1):
        raise PairTestError("S3 did not report a complete passing run")

    rx = [e for e in by_side["c3"] if e.get("event") == "rx_valid"]
    echo_done = [e for e in by_side["c3"] if e.get("event") == "echo_tx_done"]
    tx_done = [e for e in by_side["s3"] if e.get("event") == "tx_done"]
    round_trips = [e for e in by_side["s3"] if e.get("event") == "round_trip"]
    expected_sequences = list(range(1, count + 1))
    for label, records in (("C3 received", rx), ("C3 echoed", echo_done),
                           ("S3 send callback", tx_done), ("S3 completed", round_trips)):
        sequences = [e.get("seq") for e in records]
        if len(records) != count or sequences != expected_sequences:
            raise PairTestError(f"{label} sequence set/order was {sequences!r}")
    if any(e.get("status") != "success" for e in echo_done[:count] + tx_done[:count]):
        raise PairTestError("C3 reported a failed ESP-NOW echo transmission")
    if any(str(e.get("src_mac", "")).lower() != s3_mac for e in rx):
        raise PairTestError("C3 received a valid core frame from an unexpected MAC")
    if any(str(e.get("peer_mac", "")).lower() != c3_mac for e in round_trips):
        raise PairTestError("S3 completed a round trip with an unexpected MAC")
    if any(e.get("tx_done") is not True or e.get("echo_match") is not True for e in round_trips):
        raise PairTestError("S3 round-trip evidence is missing send completion or byte equality")
    frame_sizes = [e.get("core_frame_bytes") for e in rx + round_trips]
    if any(not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 250
           for size in frame_sizes):
        raise PairTestError("a core frame exceeded the ESP-NOW v1 packet bound")

    stats = [e for e in by_side["c3"] if e.get("event") == "stats"]
    if (len(stats) != 1 or stats[0].get("echo_rx") != count or
            stats[0].get("echo_tx_ok") != count or stats[0].get("echo_tx_failed") != 0):
        raise PairTestError("C3 echo counters do not match the completed pair run")
    if done[0].get("payload_bytes") != payload_bytes:
        raise PairTestError("S3 completed a run with a different payload size")
    reported_max = done[0].get("max_core_frame_bytes")
    if not isinstance(reported_max, int) or isinstance(reported_max, bool) or reported_max != max(frame_sizes):
        raise PairTestError("S3 maximum core-frame size does not match the received trace")
    return {
        "result": "PASS",
        "test_mode": "unauthenticated-core-echo",
        "session": session,
        "s3_mac": s3_mac,
        "c3_mac": c3_mac,
        "peer_count": 1,
        "channel": s3.get("channel"),
        "count": count,
        "payload_bytes": done[0].get("payload_bytes"),
        "round_trips": len(expected_sequences),
        "max_observed_core_frame_bytes": done[0].get("max_core_frame_bytes"),
        "decoded_core_mtu_bytes": 256,
        "stream_r_encoded_mtu_bytes": 263,
        "espnow_v1_payload_mtu_bytes": 250,
        "security_claim": "none; SEC-1 was not run by this smoke test",
    }


class HostCommandLog:
    def __init__(self, path: Path):
        self._stream = path.open("x", encoding="utf-8")
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
        self._stream.close()


class SerialCapture:
    """Read raw serial bytes continuously and expose firmware JSON events."""

    def __init__(self, spec: DeviceSpec, output: Path, event_queue: queue.Queue,
                 command_log: HostCommandLog):
        try:
            import serial  # type: ignore[import-not-found]
        except ImportError as exc:
            raise PairTestError("serial capture requires pyserial") from exc
        self.spec = spec
        self.event_queue = event_queue
        self.command_log = command_log
        self.stop_event = threading.Event()
        self._serial = serial.Serial(port=None, baudrate=115200, timeout=0.1, write_timeout=1.0)
        self._serial.port = spec.port
        self._serial.dtr = False
        self._serial.rts = False
        self._serial.open()
        self._raw = (output / f"{spec.side}-{spec.port}.raw.bin").open("xb")
        self._timeline = (output / f"{spec.side}-{spec.port}.timeline.jsonl").open("x", encoding="utf-8")
        self._thread = threading.Thread(target=self._reader, name=f"serial-{spec.side}", daemon=True)
        self._thread.start()

    def write_line(self, command: str) -> None:
        payload = command.encode("ascii") + b"\n"
        self.command_log.record(self.spec.port, command, "attempted")
        try:
            written = self._serial.write(payload)
        except Exception as exc:
            self.command_log.record(self.spec.port, command, "failed", error=str(exc))
            raise PairTestError(f"serial command write failed on {self.spec.port}") from exc
        self.command_log.record(self.spec.port, command,
                                "written" if written == len(payload) else "short-write",
                                bytes_written=written, bytes_requested=len(payload))
        if written != len(payload):
            raise PairTestError(f"short command write to {self.spec.port}: {command}")

    def _reader(self) -> None:
        line = bytearray()
        try:
            while not self.stop_event.is_set():
                chunk = self._serial.read(512)
                if not chunk:
                    continue
                self._raw.write(chunk)
                self._raw.flush()
                line.extend(chunk)
                while b"\n" in line:
                    index = line.index(b"\n")
                    record = bytes(line[:index + 1])
                    del line[:index + 1]
                    self._record_line(record)
                if len(line) > 65536:
                    # Preserve the unmodified stream in .raw.bin and bound only
                    # the secondary line decoder.
                    self._record_line(bytes(line[:65536]) + b"\n[LINE TRUNCATED]\n")
                    line.clear()
        except Exception as exc:  # forwarded to the controller, never ignored
            self.event_queue.put((self.spec.side, {"event": "serial_error", "error": str(exc)}))

    def _record_line(self, raw_line: bytes) -> None:
        stamp = time.time_ns()
        decoded = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
        event = parse_json_event(raw_line)
        index = {
            "host_unix_time_ns": stamp,
            "port": self.spec.port,
            "line_utf8": decoded,
            "line_base64": base64.b64encode(raw_line).decode("ascii"),
            "firmware_event": event,
        }
        self._timeline.write(json.dumps(index, separators=(",", ":")) + "\n")
        self._timeline.flush()
        print(f"[{self.spec.port}] {decoded}", flush=True)
        if event is not None:
            self.event_queue.put((self.spec.side, event))

    def close(self) -> None:
        self.stop_event.set()
        self._serial.close()
        self._thread.join(timeout=1.0)
        self._raw.close()
        self._timeline.close()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def collect_port_inventory(specs: dict[str, DeviceSpec]) -> dict[str, dict[str, Any]]:
    """Collect read-only USB metadata for the physical run evidence."""
    try:
        from serial.tools import list_ports  # type: ignore[import-not-found]
        inventory = {item.device.upper(): {
            "description": item.description,
            "hwid": item.hwid,
            "serial_number": item.serial_number,
            "location": item.location,
        } for item in list_ports.comports()}
        return {
            side: inventory.get(spec.port.upper(), {"description": "not reported by pyserial"})
            for side, spec in specs.items()
        }
    except ImportError:
        return {side: {"description": "pyserial list_ports unavailable"} for side in specs}


def wait_until_events(
    devices: dict[str, SerialCapture], collected: list[tuple[str, dict[str, Any]]],
    predicate: Callable[[list[tuple[str, dict[str, Any]]]], bool], timeout: float, description: str,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate(collected):
            return
        try:
            tagged = devices["s3"].event_queue.get(timeout=min(0.05, max(0.0, deadline - time.monotonic())))
        except queue.Empty:
            continue
        collected.append(tagged)
        if tagged[1].get("event") == "serial_error":
            raise PairTestError(f"{tagged[0].upper()} serial read failed: {tagged[1].get('error')}")
    raise PairTestError(f"timed out waiting for {description}")


def create_output_dir(root: Path, requested: Path | None) -> Path:
    if requested is not None:
        path = requested
        path.mkdir(parents=True, exist_ok=False)
        return path
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    path = root / f"pair-{stamp}-{time.time_ns() % 1_000_000_000:09d}Z"
    path.mkdir(exist_ok=False)
    return path


def run(args: argparse.Namespace) -> int:
    if not 1 <= args.count <= MAX_COUNT:
        raise PairTestError(f"count must be between 1 and {MAX_COUNT}")
    if not 8 <= args.payload_bytes <= MAX_PAYLOAD_BYTES:
        raise PairTestError(f"payload-bytes must be between 8 and {MAX_PAYLOAD_BYTES}")
    specs = {
        "s3": DeviceSpec("s3", args.s3_port, "esp32s3", args.s3_bin),
        "c3": DeviceSpec("c3", args.c3_port, "esp32c3", args.c3_bin),
    }
    if specs["s3"].port == specs["c3"].port:
        raise PairTestError("S3 and C3 ports must differ")
    for spec in specs.values():
        if not spec.image.is_file():
            raise PairTestError(f"firmware image is missing: {spec.image}")

    output = create_output_dir(args.evidence_root, args.output_dir)
    event_queue: queue.Queue = queue.Queue()
    devices: dict[str, SerialCapture] = {}
    command_log: HostCommandLog | None = None
    events: list[tuple[str, dict[str, Any]]] = []
    metadata: dict[str, Any] = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "ports": {side: spec.port for side, spec in specs.items()},
        "images": {side: {"path": str(spec.image), "sha256": sha256_file(spec.image)} for side, spec in specs.items()},
        "count": args.count,
        "payload_bytes": args.payload_bytes,
        "session": secrets.token_hex(8),
        "channel": 1,
        "dtr": False,
        "rts": False,
        "mode": "unauthenticated-core-echo",
        "evidence_boundary": "ESP-NOW delivery and DMP core structural parsing only; no SEC-1 or endpoint acceptance",
    }
    metadata["port_inventory"] = collect_port_inventory(specs)
    (output / "run.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    try:
        command_log = HostCommandLog(output / "commands.jsonl")
        devices["s3"] = SerialCapture(specs["s3"], output, event_queue, command_log)
        devices["c3"] = SerialCapture(specs["c3"], output, event_queue, command_log)
        for device in devices.values():
            device.write_line("INFO")
        wait_until_events(
            devices, events,
            lambda es: all(any(side == wanted and e.get("event") == "ready" for side, e in es)
                           for wanted in ("s3", "c3")),
            args.boot_timeout, "S3 and C3 firmware ready records",
        )
        ready = validate_ready_events(events)
        s3_mac, c3_mac = ready["s3"]["mac"], ready["c3"]["mac"]
        session = metadata["session"]
        devices["s3"].write_line(f"SESSION {session}")
        devices["c3"].write_line(f"SESSION {session}")
        wait_until_events(
            devices, events,
            lambda es: all(any(side == wanted and e.get("event") == "session_set" and
                               e.get("session") == session for side, e in es)
                           for wanted in ("s3", "c3")),
            args.command_timeout, "S3 and C3 session confirmation",
        )
        for side, target in (("s3", "esp32s3"), ("c3", "esp32c3")):
            confirmed = [event for event_side, event in events
                         if event_side == side and event.get("event") == "session_set" and
                         event.get("session") == session]
            if len(confirmed) != 1 or confirmed[0].get("target") != target or \
                    str(confirmed[0].get("mac", "")).lower() != ready[side]["mac"].lower():
                raise PairTestError(f"{side.upper()} session confirmation does not match its fresh target and MAC")

        devices["s3"].write_line(f"PEER {c3_mac}")
        devices["c3"].write_line(f"PEER {s3_mac}")
        devices["c3"].write_line("ECHO ON")
        wait_until_events(
            devices, events,
            lambda es: (
                any(s == "s3" and e.get("event") == "peer_added" and e.get("session") == session and str(e.get("peer_mac", "")).lower() == c3_mac.lower() for s, e in es)
                and any(s == "c3" and e.get("event") == "peer_added" and e.get("session") == session and str(e.get("peer_mac", "")).lower() == s3_mac.lower() for s, e in es)
                and any(s == "c3" and e.get("event") == "echo_mode" and e.get("session") == session and e.get("enabled") is True for s, e in es)
            ), args.command_timeout, "peer configuration and C3 echo mode",
        )
        devices["s3"].write_line(f"RUN {args.count} {args.payload_bytes}")
        wait_until_events(
            devices, events,
            lambda es: any(side == "s3" and e.get("event") == "run_done" and
                           e.get("session") == session for side, e in es),
            args.run_timeout, "S3 run completion",
        )
        if any(side == "s3" and e.get("event") == "run_done" and
               e.get("session") == session and e.get("pass") is False for side, e in events):
            raise PairTestError("S3 reported failure for the current session")
        wait_until_events(
            devices, events,
            lambda es: sum(side == "c3" and e.get("event") == "echo_tx_done" and
                           e.get("session") == session for side, e in es) >= args.count,
            args.command_timeout, "all C3 echo send callbacks",
        )
        devices["c3"].write_line("STATS")
        wait_until_events(
            devices, events,
            lambda es: any(side == "c3" and e.get("event") == "stats" and
                           e.get("session") == session for side, e in es),
            args.command_timeout, "C3 echo counters",
        )

        result = validate_pair_events(events, args.count, args.payload_bytes, session)
        metadata["ended_at_utc"] = datetime.now(timezone.utc).isoformat()
        metadata["result"] = result
        metadata["firmware_ready"] = {side: {k: v for k, v in event.items() if k != "event"}
                                      for side, event in ready.items()}
        (output / "run.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        print(f"PASS: {args.count} bidirectional ESP-NOW core-frame echoes; evidence: {output}")
        return 0
    except Exception as exc:
        metadata["ended_at_utc"] = datetime.now(timezone.utc).isoformat()
        metadata["result"] = {"result": "FAIL", "error": str(exc)}
        (output / "run.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        raise
    finally:
        for device in devices.values():
            device.close()
        if command_log is not None:
            command_log.close()


def validate_ready_events(events: Iterable[tuple[str, dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    ready: dict[str, dict[str, Any]] = {}
    for side, event in events:
        if side in ("s3", "c3") and event.get("event") == "ready":
            ready[side] = event
    for side, target in (("s3", "esp32s3"), ("c3", "esp32c3")):
        event = ready.get(side)
        if event is None:
            raise PairTestError(f"{side.upper()} ready record is missing")
        if event.get("target") != target:
            raise PairTestError(f"{side.upper()} target mismatch: {event.get('target')!r}")
        if event.get("test_mode") != "unauthenticated-core-echo":
            raise PairTestError(f"{side.upper()} is not the approved pair-smoke firmware")
        if event.get("decoded_core_mtu_bytes") != 256 or event.get("stream_r_encoded_mtu_bytes") != 263:
            raise PairTestError(f"{side.upper()} MTU report does not match DMP DIRECT-1 reference values")
        if event.get("espnow_v1_payload_mtu_bytes") != 250:
            raise PairTestError(f"{side.upper()} ESP-NOW v1 payload limit is not 250 bytes")
        expected_capacity = 3 if side == "s3" else 1
        if event.get("peer_capacity") != expected_capacity:
            raise PairTestError(f"{side.upper()} peer capacity is not {expected_capacity}")
        if event.get("channel") != 1:
            raise PairTestError(f"{side.upper()} is not on channel 1")
        if not isinstance(event.get("mac"), str) or not MAC_PATTERN.fullmatch(event["mac"]):
            raise PairTestError(f"{side.upper()} MAC address is missing or invalid")
    return ready


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--s3-port", default=DEFAULT_S3_PORT)
    parser.add_argument("--c3-port", default=DEFAULT_C3_PORT)
    parser.add_argument("--s3-bin", type=Path, default=DEFAULT_S3_BIN)
    parser.add_argument("--c3-bin", type=Path, default=DEFAULT_C3_BIN)
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--output-dir", type=Path, help="new, empty output directory; must not already exist")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--payload-bytes", type=int, default=64,
                        help="DMP payload size (8..240 bytes; first 8 bytes carry the run token)")
    parser.add_argument("--boot-timeout", type=float, default=20.0)
    parser.add_argument("--command-timeout", type=float, default=5.0)
    parser.add_argument("--run-timeout", type=float, default=45.0)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run(args)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
