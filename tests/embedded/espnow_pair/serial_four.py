#!/usr/bin/env python3
"""Capture one S3 endpoint owner and three C3 ESP-NOW echo peers.

This is an unauthenticated radio and Core-codec smoke test. It keeps three
unicast peers configured on one S3 radio context, then sends one packet at a
time in a deterministic round-robin order. It does not run SEC-1, the
production dmp_endpoint, SAMPLE-1, or the four_parallel workload.
"""

from __future__ import annotations

import argparse
import json
import queue
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from serial_pair import (
    DEFAULT_EVIDENCE_ROOT,
    DEFAULT_S3_BIN,
    DeviceSpec,
    HostCommandLog,
    MAX_PAYLOAD_BYTES,
    MAC_PATTERN,
    PairTestError,
    SerialCapture,
    collect_port_inventory,
    sha256_file,
    wait_until_events,
)


DEFAULT_S3_PORT = "COM37"
DEFAULT_C3_PORTS = ("COM36", "COM38", "COM40")
DEFAULT_C3_BIN = Path("build/espnow-pair-esp32c3/dmp_espnow_pair.bin")
MAX_COUNT_PER_PEER = 333
SIDES = ("s3", "c3_1", "c3_2", "c3_3")


def validate_ready_events(
    tagged_events: Iterable[tuple[str, dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    ready: dict[str, dict[str, Any]] = {}
    for side, event in tagged_events:
        if side in SIDES and event.get("event") == "ready":
            ready[side] = event
    for side, target, capacity in (
        ("s3", "esp32s3", 3),
        ("c3_1", "esp32c3", 1),
        ("c3_2", "esp32c3", 1),
        ("c3_3", "esp32c3", 1),
    ):
        event = ready.get(side)
        if event is None:
            raise PairTestError(f"{side.upper()} ready record is missing")
        if event.get("target") != target:
            raise PairTestError(f"{side.upper()} target mismatch: {event.get('target')!r}")
        if event.get("test_mode") != "unauthenticated-core-echo":
            raise PairTestError(f"{side.upper()} is not running the radio smoke image")
        if event.get("decoded_core_mtu_bytes") != 256:
            raise PairTestError(f"{side.upper()} did not report the 256-byte decoded Core MTU")
        if event.get("stream_r_encoded_mtu_bytes") != 263:
            raise PairTestError(f"{side.upper()} did not report the 263-byte encoded Stream R MTU")
        if event.get("espnow_v1_payload_mtu_bytes") != 250:
            raise PairTestError(f"{side.upper()} did not report the ESP-NOW v1 payload limit")
        if event.get("peer_capacity") != capacity:
            raise PairTestError(f"{side.upper()} peer capacity is not {capacity}")
        if event.get("channel") != 1:
            raise PairTestError(f"{side.upper()} is not on test channel 1")
        mac = event.get("mac")
        if not isinstance(mac, str) or not MAC_PATTERN.fullmatch(mac):
            raise PairTestError(f"{side.upper()} reported an invalid station MAC")
    macs = [ready[side]["mac"].lower() for side in SIDES]
    if len(set(macs)) != len(macs):
        raise PairTestError("the four boards reported duplicate station MAC addresses")
    return ready


def validate_four_peer_events(
    tagged_events: Iterable[tuple[str, dict[str, Any]]],
    count_per_peer: int,
    payload_bytes: int,
    session: str,
) -> dict[str, Any]:
    if not 1 <= count_per_peer <= MAX_COUNT_PER_PEER:
        raise PairTestError(f"count-per-peer must be between 1 and {MAX_COUNT_PER_PEER}")
    if not 8 <= payload_bytes <= MAX_PAYLOAD_BYTES:
        raise PairTestError(f"payload-bytes must be between 8 and {MAX_PAYLOAD_BYTES}")
    if not isinstance(session, str) or len(session) != 16 or any(c not in "0123456789abcdef" for c in session):
        raise PairTestError("the run session token is not a 64-bit lowercase hex value")

    events = list(tagged_events)
    ready = validate_ready_events(events)
    mac_by_side = {side: ready[side]["mac"].lower() for side in SIDES}
    c3_sides = SIDES[1:]
    total = count_per_peer * len(c3_sides)
    by_side = {
        side: [event for event_side, event in events
               if event_side == side and
               (event.get("event") == "ready" or event.get("session") == session)]
        for side in SIDES
    }

    for side in SIDES:
        sessions = [event for event in by_side[side] if event.get("event") == "session_set"]
        if (len(sessions) != 1 or sessions[0].get("session") != session or
                sessions[0].get("target") != ready[side]["target"] or
                str(sessions[0].get("mac", "")).lower() != mac_by_side[side]):
            raise PairTestError(f"{side.upper()} did not confirm the current target and session")

    s3_peers = [event for event in by_side["s3"] if event.get("event") == "peer_added"]
    expected_peer_macs = [mac_by_side[side] for side in c3_sides]
    if ([str(event.get("peer_mac", "")).lower() for event in s3_peers] != expected_peer_macs or
            [event.get("peer_count") for event in s3_peers] != [1, 2, 3]):
        raise PairTestError("S3 did not admit exactly the three C3 peers in configured order")

    for side in c3_sides:
        peers = [event for event in by_side[side] if event.get("event") == "peer_added"]
        echo_modes = [event for event in by_side[side] if event.get("event") == "echo_mode"]
        if (len(peers) != 1 or str(peers[0].get("peer_mac", "")).lower() != mac_by_side["s3"] or
                peers[0].get("peer_count") != 1):
            raise PairTestError(f"{side.upper()} did not configure S3 as its only peer")
        if len(echo_modes) != 1 or echo_modes[0].get("enabled") is not True:
            raise PairTestError(f"{side.upper()} did not confirm echo mode")

    started = [event for event in by_side["s3"] if event.get("event") == "run_started"]
    done = [event for event in by_side["s3"] if event.get("event") == "run_done"]
    if (len(started) != 1 or started[0].get("count") != total or
            started[0].get("payload_bytes") != payload_bytes or
            started[0].get("peer_count") != len(c3_sides)):
        raise PairTestError("S3 did not report the requested three-peer run")
    if (len(done) != 1 or done[0].get("pass") is not True or
            done[0].get("completed") != total or
            done[0].get("peer_count") != len(c3_sides) or
            done[0].get("payload_bytes") != payload_bytes):
        raise PairTestError("S3 did not report a complete passing three-peer run")

    expected_sequences = list(range(1, total + 1))
    tx_done = [event for event in by_side["s3"] if event.get("event") == "tx_done"]
    round_trips = [event for event in by_side["s3"] if event.get("event") == "round_trip"]
    for label, records in (("S3 send callback", tx_done), ("S3 round trip", round_trips)):
        sequences = [event.get("seq") for event in records]
        if sequences != expected_sequences:
            raise PairTestError(f"{label} sequence set/order was {sequences!r}")
    if any(event.get("status") != "success" for event in tx_done):
        raise PairTestError("S3 reported a failed ESP-NOW send callback")
    if any(event.get("tx_done") is not True or event.get("echo_match") is not True
           for event in round_trips):
        raise PairTestError("S3 round-trip evidence lacks a successful callback or byte match")
    expected_round_trip_macs = [mac_by_side[c3_sides[index % len(c3_sides)]]
                                for index in range(total)]
    if [str(event.get("peer_mac", "")).lower() for event in round_trips] != expected_round_trip_macs:
        raise PairTestError("S3 round trips did not follow the configured round-robin peer order")
    if [str(event.get("peer_mac", "")).lower() for event in tx_done] != expected_round_trip_macs:
        raise PairTestError("S3 send callbacks did not match the round-robin peer order")

    all_frame_sizes: list[int] = []
    for peer_index, side in enumerate(c3_sides):
        expected_peer_sequences = list(range(peer_index + 1, total + 1, len(c3_sides)))
        receives = [event for event in by_side[side] if event.get("event") == "rx_valid"]
        echo_done = [event for event in by_side[side] if event.get("event") == "echo_tx_done"]
        if [event.get("seq") for event in receives] != expected_peer_sequences:
            raise PairTestError(f"{side.upper()} receive sequence set/order is incomplete")
        if [event.get("seq") for event in echo_done] != expected_peer_sequences:
            raise PairTestError(f"{side.upper()} echo callback sequence set/order is incomplete")
        if any(event.get("status") != "success" for event in echo_done):
            raise PairTestError(f"{side.upper()} reported a failed echo send callback")
        if any(str(event.get("src_mac", "")).lower() != mac_by_side["s3"]
               for event in receives):
            raise PairTestError(f"{side.upper()} received a frame from an unexpected MAC")
        stats = [event for event in by_side[side] if event.get("event") == "stats"]
        if (len(stats) != 1 or stats[0].get("echo_rx") != count_per_peer or
                stats[0].get("echo_tx_ok") != count_per_peer or
                stats[0].get("echo_tx_failed") != 0):
            raise PairTestError(f"{side.upper()} counters do not match its assigned round trips")
        all_frame_sizes.extend(event.get("core_frame_bytes") for event in receives)

    all_frame_sizes.extend(event.get("core_frame_bytes") for event in round_trips)
    if any(not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 250
           for size in all_frame_sizes):
        raise PairTestError("a Core frame exceeded the ESP-NOW v1 packet bound")
    if (not isinstance(done[0].get("max_core_frame_bytes"), int) or
            isinstance(done[0].get("max_core_frame_bytes"), bool) or
            done[0]["max_core_frame_bytes"] != max(all_frame_sizes)):
        raise PairTestError("S3 maximum Core-frame size does not match the captured peer trace")

    return {
        "result": "PASS",
        "test_mode": "unauthenticated-core-echo",
        "endpoint_claim": "none; this is one test-radio owner with three unicast peers, not dmp_endpoint",
        "four_parallel_claim": "none; ESP-NOW sends are serialized one callback at a time",
        "session": session,
        "s3_mac": mac_by_side["s3"],
        "c3_macs": {side: mac_by_side[side] for side in c3_sides},
        "channel": ready["s3"]["channel"],
        "peer_count": len(c3_sides),
        "count_per_peer": count_per_peer,
        "round_trips": total,
        "payload_bytes": payload_bytes,
        "max_observed_core_frame_bytes": done[0]["max_core_frame_bytes"],
        "decoded_core_mtu_bytes": 256,
        "stream_r_encoded_mtu_bytes": 263,
        "espnow_v1_payload_mtu_bytes": 250,
        "security_claim": "none; SEC-1 was not run by this smoke test",
    }


def create_output_dir(root: Path, requested: Path | None) -> Path:
    if requested is not None:
        requested.mkdir(parents=True, exist_ok=False)
        return requested
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    output = root / f"four-peer-{stamp}-{time.time_ns() % 1_000_000_000:09d}Z"
    output.mkdir(exist_ok=False)
    return output


def c3_images_for_ports(
    c3_ports: list[str], default_image: Path, overrides: list[str] | None,
) -> dict[str, Path]:
    """Resolve image paths per C3 serial port while keeping one default image."""
    allowed_ports = {port.upper() for port in c3_ports}
    port_names = {port.upper(): port for port in c3_ports}
    images: dict[str, Path] = {}
    for value in overrides or []:
        port, separator, image_path = value.partition("=")
        key = port.strip().upper()
        if not separator or not key or not image_path.strip():
            raise PairTestError("each --c3-bin-for-port value must be PORT=PATH")
        if key not in allowed_ports:
            raise PairTestError(
                f"--c3-bin-for-port references an unconfigured C3 port: {port.strip()}"
            )
        if key in images:
            raise PairTestError(f"--c3-bin-for-port is repeated for {port_names[key]}")
        images[key] = Path(image_path.strip())
    return {port.upper(): images.get(port.upper(), default_image) for port in c3_ports}


def run(args: argparse.Namespace) -> int:
    c3_ports = [port.strip() for port in args.c3_ports.split(",") if port.strip()]
    if len(c3_ports) != 3:
        raise PairTestError("exactly three comma-separated C3 ports are required")
    if len({args.s3_port.upper(), *(port.upper() for port in c3_ports)}) != 4:
        raise PairTestError("all four serial ports must be distinct")
    if not 1 <= args.count_per_peer <= MAX_COUNT_PER_PEER:
        raise PairTestError(f"count-per-peer must be between 1 and {MAX_COUNT_PER_PEER}")
    if not 8 <= args.payload_bytes <= MAX_PAYLOAD_BYTES:
        raise PairTestError(f"payload-bytes must be between 8 and {MAX_PAYLOAD_BYTES}")

    c3_images = c3_images_for_ports(c3_ports, args.c3_bin, args.c3_bin_for_port)
    specs = {"s3": DeviceSpec("s3", args.s3_port, "esp32s3", args.s3_bin)}
    for index, port in enumerate(c3_ports, start=1):
        side = f"c3_{index}"
        specs[side] = DeviceSpec(side, port, "esp32c3", c3_images[port.upper()])
    for spec in specs.values():
        if not spec.image.is_file():
            raise PairTestError(f"firmware image is missing: {spec.image}")

    total_count = args.count_per_peer * 3
    output = create_output_dir(args.evidence_root, args.output_dir)
    event_queue: queue.Queue = queue.Queue()
    devices: dict[str, SerialCapture] = {}
    command_log: HostCommandLog | None = None
    events: list[tuple[str, dict[str, Any]]] = []
    metadata: dict[str, Any] = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "ports": {side: spec.port for side, spec in specs.items()},
        "images": {side: {"path": str(spec.image), "sha256": sha256_file(spec.image)}
                   for side, spec in specs.items()},
        "count_per_peer": args.count_per_peer,
        "total_round_trips": total_count,
        "payload_bytes": args.payload_bytes,
        "session": secrets.token_hex(8),
        "channel": 1,
        "dtr": False,
        "rts": False,
        "mode": "unauthenticated-core-echo",
        "peer_count": 3,
        "evidence_boundary": "one S3 radio test context with three unicast C3 peers; no SEC-1, dmp_endpoint, SAMPLE-1, or four_parallel claim",
    }
    metadata["port_inventory"] = collect_port_inventory(specs)
    (output / "run.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    try:
        command_log = HostCommandLog(output / "commands.jsonl")
        for side, spec in specs.items():
            devices[side] = SerialCapture(spec, output, event_queue, command_log)
        for device in devices.values():
            device.write_line("INFO")
        wait_until_events(
            devices, events,
            lambda collected: all(any(side == wanted and event.get("event") == "ready"
                                      for side, event in collected) for wanted in SIDES),
            args.boot_timeout, "one S3 and three C3 ready records",
        )
        ready = validate_ready_events(events)
        session = metadata["session"]
        for device in devices.values():
            device.write_line(f"SESSION {session}")
        wait_until_events(
            devices, events,
            lambda collected: all(sum(side == wanted and event.get("event") == "session_set" and
                                      event.get("session") == session
                                      for side, event in collected) >= 1 for wanted in SIDES),
            args.command_timeout, "four session confirmations",
        )
        for side in SIDES:
            session_events = [event for event_side, event in events
                              if event_side == side and event.get("event") == "session_set" and
                              event.get("session") == session]
            if (len(session_events) != 1 or
                    session_events[0].get("target") != ready[side]["target"] or
                    str(session_events[0].get("mac", "")).lower() != ready[side]["mac"].lower()):
                raise PairTestError(f"{side.upper()} session confirmation does not match fresh INFO")

        s3_mac = ready["s3"]["mac"].lower()
        for side in SIDES[1:]:
            devices["s3"].write_line(f"PEER {ready[side]['mac']}")
            devices[side].write_line(f"PEER {ready['s3']['mac']}")
            devices[side].write_line("ECHO ON")
        wait_until_events(
            devices, events,
            lambda collected: (
                len([event for event_side, event in collected
                     if event_side == "s3" and event.get("event") == "peer_added" and
                     event.get("session") == session]) == 3 and
                all(any(event_side == side and event.get("event") == "peer_added" and
                        event.get("session") == session and
                        str(event.get("peer_mac", "")).lower() == s3_mac
                        for event_side, event in collected) and
                    any(event_side == side and event.get("event") == "echo_mode" and
                        event.get("session") == session and event.get("enabled") is True
                        for event_side, event in collected) for side in SIDES[1:])
            ), args.command_timeout, "three S3 peers and three C3 echo peers",
        )

        devices["s3"].write_line(f"RUN {total_count} {args.payload_bytes}")
        wait_until_events(
            devices, events,
            lambda collected: any(side == "s3" and event.get("event") == "run_done" and
                                  event.get("session") == session
                                  for side, event in collected),
            args.run_timeout, "S3 three-peer run completion",
        )
        failures = [event for side, event in events
                    if side == "s3" and event.get("event") == "run_done" and
                    event.get("session") == session and event.get("pass") is False]
        if failures:
            reason = failures[0].get("reason", "unspecified")
            raise PairTestError(
                f"S3 reported failure for the current three-peer session: {reason}"
            )
        for side in SIDES[1:]:
            expected_echoes = args.count_per_peer
            wait_until_events(
                devices, events,
                lambda collected, wanted=side, expected=expected_echoes: sum(
                    event_side == wanted and event.get("event") == "echo_tx_done" and
                    event.get("session") == session
                    for event_side, event in collected) >= expected,
                args.command_timeout, f"{side.upper()} echo send callbacks",
            )
            devices[side].write_line("STATS")
        wait_until_events(
            devices, events,
            lambda collected: all(any(event_side == side and event.get("event") == "stats" and
                                     event.get("session") == session
                                     for event_side, event in collected) for side in SIDES[1:]),
            args.command_timeout, "three C3 echo counter records",
        )

        result = validate_four_peer_events(
            events, args.count_per_peer, args.payload_bytes, session,
        )
        metadata["ended_at_utc"] = datetime.now(timezone.utc).isoformat()
        metadata["result"] = result
        metadata["firmware_ready"] = {
            side: {key: value for key, value in event.items() if key != "event"}
            for side, event in ready.items()
        }
        (output / "run.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        print(f"PASS: {total_count} serialized ESP-NOW echoes across three C3 peers; evidence: {output}")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--s3-port", default=DEFAULT_S3_PORT)
    parser.add_argument("--c3-ports", default=",".join(DEFAULT_C3_PORTS),
                        help="exactly three comma-separated C3 serial ports")
    parser.add_argument("--s3-bin", type=Path, default=DEFAULT_S3_BIN)
    parser.add_argument("--c3-bin", type=Path, default=DEFAULT_C3_BIN)
    parser.add_argument("--c3-bin-for-port", action="append", metavar="PORT=PATH",
                        help="override the C3 image for a serial port; may be repeated")
    parser.add_argument("--evidence-root", type=Path, default=DEFAULT_EVIDENCE_ROOT)
    parser.add_argument("--output-dir", type=Path,
                        help="new, empty output directory; must not already exist")
    parser.add_argument("--count-per-peer", type=int, default=10)
    parser.add_argument("--payload-bytes", type=int, default=64,
                        help="DMP payload size (8..240 bytes; first 8 bytes carry the run token)")
    parser.add_argument("--boot-timeout", type=float, default=20.0)
    parser.add_argument("--command-timeout", type=float, default=5.0)
    parser.add_argument("--run-timeout", type=float, default=120.0)
    return parser


def main() -> int:
    try:
        return run(build_parser().parse_args())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
