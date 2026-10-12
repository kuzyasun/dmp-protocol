"""Redacted command-line decoder for bounded core and Stream R inputs."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, TextIO

from .frame import FrameError, decode_uleb, parse_frame
from .process_bridge import BridgeInputError, _bytes, _depth, _object
from .stream_r import StreamRDecoder


MAX_LINES = 4_096
MAX_LINE_BYTES = 100_000
IDENTITY_FIELDS = {"namespace", "origin", "destination", "epoch", "sequence", "fragment_index"}


def _load_input(line: str, maximum: int) -> tuple[bytes, int]:
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise BridgeInputError("decoder input line exceeds byte limit")
    try:
        value = json.loads(line, object_pairs_hook=_object)
    except BridgeInputError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
        raise BridgeInputError("invalid decoder JSON line") from exc
    _depth(value)
    if not isinstance(value, dict) or set(value) != {"bytes_b64", "at_ms"}:
        raise BridgeInputError("decoder input does not match the closed schema")
    at_ms = value["at_ms"]
    if isinstance(at_ms, bool) or not isinstance(at_ms, int) or not 0 <= at_ms <= 0xFFFFFFFFFFFFFFFF:
        raise BridgeInputError("decoder time must be u64")
    return _bytes(value["bytes_b64"], maximum), at_ms


def _identity(frame) -> dict[str, int]:
    identity: dict[str, int] = {}
    if frame.sequence is not None:
        identity["sequence"] = frame.sequence
    if frame.route is not None:
        identity["origin"] = frame.route.source_id
        if frame.route.destination_id is not None:
            identity["destination"] = frame.route.destination_id
    if frame.fragment is not None:
        identity["fragment_index"] = frame.fragment.index
    context = next((ext for ext in frame.extensions if ext.extension_id == 2), None)
    if context is not None:
        namespace, at = decode_uleb(context.value, 0)
        if at + 8 == len(context.value):
            identity["namespace"] = namespace
            identity["epoch"] = int.from_bytes(context.value[at:at + 8], "little")
    return {key: value for key, value in identity.items() if key in IDENTITY_FIELDS}


def _summary(core: bytes, at_ms: int, include_identity: bool) -> dict[str, Any]:
    frame = parse_frame(core, max_frame=256)
    event: dict[str, Any] = {
        "event": "frame", "at_ms": at_ms, "size": len(core),
        "message_type": frame.message_type, "protected": frame.security is not None,
        "fragmented": frame.fragment is not None, "route_present": frame.route is not None,
    }
    if include_identity:
        identity = _identity(frame)
        if identity:
            event["identity"] = identity
    return event


def run_decoder(stdin: TextIO, stdout: TextIO, stderr: TextIO, *, mode: str,
                include_identity: bool = False) -> int:
    if mode not in {"core", "stream"}:
        raise ValueError("mode must be core or stream")
    decoder = (StreamRDecoder(max_encoded=263, max_core=256,
                              candidate_timeout_ms=26, await_sync=True)
               if mode == "stream" else None)
    lines = 0
    emitted = 0
    while True:
        line = stdin.readline(MAX_LINE_BYTES + 2)
        if line == "":
            return 0
        lines += 1
        if lines > MAX_LINES:
            stderr.write("E_LIMIT\n")
            return 2
        try:
            raw, at_ms = _load_input(line, 256 if mode == "core" else 65_536)
            if mode == "core":
                try:
                    records = [_summary(raw, at_ms, include_identity)]
                except (FrameError, ValueError):
                    records = [{"event": "discarded", "at_ms": at_ms, "reason": "malformed"}]
            else:
                assert decoder is not None
                stream_events = decoder.feed(raw, at_ms=at_ms)
                records = []
                for item in stream_events:
                    if item.kind == "frame":
                        try:
                            records.append(_summary(item.frame, at_ms, include_identity))
                        except (FrameError, ValueError):
                            records.append({"event": "discarded", "at_ms": at_ms,
                                            "reason": "malformed"})
                    elif item.kind == "discarded":
                        reason = item.reason if item.reason in {"candidate-timeout", "candidate-bound"} else "malformed"
                        records.append({"event": "discarded", "at_ms": at_ms, "reason": reason})
            emitted += len(records)
            if emitted > MAX_LINES:
                stderr.write("E_LIMIT\n")
                return 2
            for record in records:
                output = json.dumps(record, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
                stdout.write(output + "\n")
            stdout.flush()
        except (BridgeInputError, ValueError, TypeError, KeyError, RecursionError):
            stderr.write("E_INPUT\n")
            return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--mode", required=True, choices=("core", "stream"))
    parser.add_argument("--include-identity", action="store_true")
    args = parser.parse_args(argv)
    return run_decoder(sys.stdin, sys.stdout, sys.stderr, mode=args.mode,
                       include_identity=args.include_identity)


if __name__ == "__main__":
    raise SystemExit(main())
