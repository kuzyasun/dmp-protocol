#!/usr/bin/env python3
"""Trigger and capture the test image's flash coredump on one ESP32 board.

This is a physical-board utility and is intentionally not registered in CTest.
It records raw UART bytes, the intentional abort/reboot events, and a read-only
copy of the configured coredump partition for later offline decoding.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from serial_pair import parse_json_event


DEFAULT_EVIDENCE_ROOT = Path("dev/evidence/espnow-pair")
COREDUMP_OFFSET = 0x300000
COREDUMP_SIZE = 0x100000


class CoreDumpTestError(RuntimeError):
    """The board did not produce a complete, inspectable coredump capture."""


def extract_core_elf(partition: bytes) -> bytes:
    """Extract the length-prefixed ELF from an ESP-IDF flash partition image."""
    if len(partition) < 16:
        raise CoreDumpTestError("coredump partition image is shorter than its header")
    core_size = struct.unpack_from("<I", partition, 0)[0]
    core_start = 12
    core_end = core_start + core_size
    if core_size == 0 or core_end > len(partition):
        raise CoreDumpTestError("coredump header length is outside the captured partition")
    core = partition[core_start:core_end]
    if core[:4] != b"\x7fELF":
        raise CoreDumpTestError("coredump payload does not contain an ELF image")
    return core


def validate_capture_events(events: Iterable[dict[str, Any]], target: str) -> dict[str, Any]:
    """Require the requested test image, intentional abort, and a post-crash boot."""
    observed = list(events)
    ready_indices = [
        index for index, event in enumerate(observed)
        if event.get("event") == "ready" and event.get("target") == target
    ]
    if not ready_indices:
        raise CoreDumpTestError(f"board did not report ready for {target}")
    crash_indices = [
        index for index, event in enumerate(observed)
        if event.get("event") == "core_dump_test"
        and event.get("action") == "intentional-abort"
    ]
    if not crash_indices:
        raise CoreDumpTestError("board did not acknowledge the intentional abort command")
    crash_index = crash_indices[-1]
    if not any(index > crash_index for index in ready_indices):
        raise CoreDumpTestError("board did not reboot into the test image after the abort")
    return {
        "target": target,
        "initial_ready": True,
        "intentional_abort_seen": True,
        "post_abort_ready": True,
    }


def _write_json_line(file, value: dict[str, Any]) -> None:
    file.write(json.dumps(value, sort_keys=True) + "\n")
    file.flush()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="USB Serial/JTAG COM port")
    parser.add_argument("--target", required=True, choices=("esp32s3", "esp32c3"))
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--event-timeout", type=float, default=35.0)
    parser.add_argument("--read-baud", type=int, default=460800)
    args = parser.parse_args()

    try:
        import serial
    except ImportError as error:  # pragma: no cover - depends on host setup
        print(f"pyserial is required: {error}", file=sys.stderr)
        return 2

    started = datetime.now(timezone.utc)
    stamp = started.strftime("%Y%m%dT%H%M%S") + f"-{started.microsecond:06d}Z"
    output_dir = args.evidence_root / f"core-dump-{args.target}-{args.port}-{stamp}"
    output_dir.mkdir(parents=True, exist_ok=False)
    raw_path = output_dir / "serial.raw.bin"
    timeline_path = output_dir / "serial.timeline.jsonl"
    commands_path = output_dir / "commands.jsonl"
    dump_path = output_dir / "coredump-partition.bin"
    core_elf_path = output_dir / "core.elf"
    events: list[dict[str, Any]] = []
    error_text: str | None = None
    ready_after_abort = False
    crash_event_seen = False

    def read_line(port, raw_file, timeline_file) -> dict[str, Any] | None:
        data = port.readline()
        if not data:
            return None
        raw_file.write(data)
        raw_file.flush()
        event = parse_json_event(data)
        entry: dict[str, Any] = {
            "host_unix_time_ns": time.time_ns(),
            "port": args.port,
            "raw_base64": base64.b64encode(data).decode("ascii"),
        }
        if event is not None:
            entry["firmware_event"] = event
            events.append(event)
            print(json.dumps(event, sort_keys=True))
        else:
            entry["line_utf8"] = data.decode("utf-8", errors="replace")
        _write_json_line(timeline_file, entry)
        return event

    def send_command(port, command_file, command: bytes) -> None:
        written = port.write(command)
        port.flush()
        _write_json_line(command_file, {
            "host_unix_time_ns": time.time_ns(),
            "port": args.port,
            "bytes_base64": base64.b64encode(command).decode("ascii"),
            "written": written,
        })
        if written != len(command):
            raise CoreDumpTestError("serial command was only partially written")

    try:
        # Keep both modem-control lines inactive; opening the console must not reset it.
        port = serial.Serial(port=None, baudrate=115200, timeout=0.2,
                             write_timeout=2.0, dsrdtr=False, rtscts=False)
        port.dtr = False
        port.rts = False
        port.port = args.port
        port.open()
        with port, raw_path.open("wb") as raw_file, \
                timeline_path.open("w", encoding="utf-8", newline="\n") as timeline_file, \
                commands_path.open("w", encoding="utf-8", newline="\n") as command_file:
            send_command(port, command_file, b"INFO\n")
            deadline = time.monotonic() + args.event_timeout
            initial_ready = False
            while time.monotonic() < deadline:
                event = read_line(port, raw_file, timeline_file)
                if event and event.get("event") == "ready":
                    if event.get("target") != args.target:
                        raise CoreDumpTestError(
                            f"port reports {event.get('target')!r}, expected {args.target}"
                        )
                    initial_ready = True
                    break
            if not initial_ready:
                raise CoreDumpTestError("no fresh INFO/ready event from the board")

            send_command(port, command_file, b"CORE_DUMP_TEST\n")
            deadline = time.monotonic() + args.event_timeout
            while time.monotonic() < deadline:
                event = read_line(port, raw_file, timeline_file)
                if not event:
                    continue
                if (event.get("event") == "core_dump_test" and
                        event.get("action") == "intentional-abort"):
                    crash_event_seen = True
                elif crash_event_seen and event.get("event") == "ready":
                    if event.get("target") != args.target:
                        raise CoreDumpTestError(
                            f"post-abort boot reports unexpected target {event.get('target')!r}"
                        )
                    ready_after_abort = True
                    break
            if not crash_event_seen:
                raise CoreDumpTestError("board did not acknowledge CORE_DUMP_TEST")
            if not ready_after_abort:
                raise CoreDumpTestError("board did not reboot after intentional abort")

        esptool = shutil.which("esptool")
        if esptool:
            command = [esptool]
        else:
            command = [sys.executable, "-m", "esptool"]
        command.extend([
            "--chip", args.target, "--port", args.port, "--baud", str(args.read_baud),
            "read-flash", hex(COREDUMP_OFFSET), hex(COREDUMP_SIZE), str(dump_path),
        ])
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        (output_dir / "esptool-read-flash.log").write_text(
            result.stdout + result.stderr, encoding="utf-8"
        )
        if result.returncode != 0:
            raise CoreDumpTestError(f"esptool read-flash failed with exit {result.returncode}")
        dump = dump_path.read_bytes()
        non_erased = sum(byte != 0xFF for byte in dump)
        if len(dump) != COREDUMP_SIZE:
            raise CoreDumpTestError(f"coredump read returned {len(dump)} bytes")
        if non_erased == 0:
            raise CoreDumpTestError("coredump partition is still entirely erased")
        core_elf = extract_core_elf(dump)
        core_elf_path.write_bytes(core_elf)
        validate_capture_events(events, args.target)
        result_data = {
            "started_at_utc": started.isoformat(),
            "ended_at_utc": datetime.now(timezone.utc).isoformat(),
            "port": args.port,
            "target": args.target,
            "result": "PASS",
            "events": {
                "intentional_abort_seen": crash_event_seen,
                "post_abort_ready": ready_after_abort,
            },
            "coredump_partition": {
                "offset": COREDUMP_OFFSET,
                "size_bytes": len(dump),
                "non_erased_bytes": non_erased,
                "sha256": hashlib.sha256(dump).hexdigest(),
                "core_elf_size_bytes": len(core_elf),
                "core_elf_sha256": hashlib.sha256(core_elf).hexdigest(),
                "decode_status": "extracted-not-decoded",
            },
            "evidence_boundary": (
                "intentional panic, reboot, and non-erased coredump partition only; "
                "the dump still requires offline ESP-IDF decoding"
            ),
        }
    except Exception as error:  # preserve partial evidence on every failure
        error_text = f"{type(error).__name__}: {error}"
        result_data = {
            "started_at_utc": started.isoformat(),
            "ended_at_utc": datetime.now(timezone.utc).isoformat(),
            "port": args.port,
            "target": args.target,
            "result": "FAIL",
            "error": error_text,
            "events": {
                "intentional_abort_seen": crash_event_seen,
                "post_abort_ready": ready_after_abort,
            },
        }
    (output_dir / "run.json").write_text(
        json.dumps(result_data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"{result_data['result']}: evidence: {output_dir}")
    if error_text:
        print(error_text, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
