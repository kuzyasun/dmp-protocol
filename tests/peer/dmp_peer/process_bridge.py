"""Bounded JSON-lines adapter for the existing DMP-PEER-TEST/1 API."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any, TextIO

from .endpoint import PeerEndpoint
from .events import (
    Advance, ApplicationEvent, ApplicationRequest, Cancel, Disconnect, Open,
    PublishSample, Receive, Restart, TxAdmit, TxSubmit, TxTerminal,
)


MAX_INPUT_LINE = 1_048_576
MAX_INPUT_BYTES = 65_536
MAX_OUTPUT_BYTES = 1_048_576
MAX_OUTPUT_LINE = 2_097_152
MAX_REQUESTS = 10_000
MAX_EVENTS = 4_096


class BridgeInputError(ValueError):
    """Input is outside the closed, bounded process interface."""


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BridgeInputError("duplicate JSON member")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise BridgeInputError("non-finite JSON number")


def _depth(value: Any, level: int = 0) -> None:
    if not isinstance(value, (dict, list)):
        return
    if level >= 16:
        raise BridgeInputError("JSON nesting limit exceeded")
    items = value.values() if isinstance(value, dict) else value
    for item in items:
        _depth(item, level + 1)


def _exact(value: Any, required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BridgeInputError("event must be an object")
    keys = set(value)
    if keys - required - optional or required - keys:
        raise BridgeInputError("event members do not match the closed schema")
    return value


def _bytes(value: Any, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise BridgeInputError("byte field exceeds its input bound")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BridgeInputError("byte field is not canonical base64") from exc
    if len(decoded) > maximum:
        raise BridgeInputError("byte field exceeds its input bound")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise BridgeInputError("byte field is not canonical base64")
    return decoded


def _input_event(value: Any):
    if not isinstance(value, dict) or not isinstance(value.get("op"), str):
        raise BridgeInputError("input event requires an op")
    op = value["op"]
    if op == "open":
        item = _exact(value, {"op", "link", "deadline_capability", "at_ms"})
        return Open(item["link"], item["deadline_capability"], item["at_ms"])
    if op == "receive":
        item = _exact(value, {"op", "link", "bytes_b64", "at_ms"})
        return Receive(item["link"], _bytes(item["bytes_b64"], MAX_INPUT_BYTES), item["at_ms"])
    if op == "advance":
        item = _exact(value, {"op", "now_ms"})
        return Advance(item["now_ms"])
    if op == "tx_admit":
        item = _exact(value, {"op", "handle", "generation", "accepted", "reason", "at_ms"})
        return TxAdmit(item["handle"], item["generation"], item["accepted"], item["reason"], item["at_ms"])
    if op == "tx_terminal":
        item = _exact(value, {"op", "handle", "generation", "outcome", "at_ms"})
        return TxTerminal(item["handle"], item["generation"], item["outcome"], item["at_ms"])
    if op == "disconnect":
        item = _exact(value, {"op", "link", "at_ms"})
        return Disconnect(item["link"], item["at_ms"])
    if op == "restart":
        item = _exact(value, {"op", "at_ms", "entropy_b64"})
        return Restart(item["at_ms"], _bytes(item["entropy_b64"], 256))
    if op == "application_request":
        item = _exact(value, {"op", "service_id", "payload_b64", "at_ms"},
                      {"exchange_id", "ack_req", "not_after_ms"})
        payload = _bytes(item["payload_b64"], MAX_INPUT_BYTES)
        return ApplicationRequest(
            service_id=item["service_id"], payload=payload, at_ms=item["at_ms"],
            exchange_id=item.get("exchange_id", 0), ack_req=item.get("ack_req", True),
            not_after_ms=item.get("not_after_ms"),
        )
    if op == "publish_sample":
        item = _exact(value, {"op", "value", "at_ms"})
        return PublishSample(item["value"], item["at_ms"])
    raise BridgeInputError("unsupported input op")


def _event_record(event: Any) -> dict[str, Any]:
    if isinstance(event, TxSubmit):
        return {"type": "tx_submit", "handle": event.handle, "generation": event.generation,
                "bytes_b64": base64.b64encode(event.bytes).decode("ascii"),
                "not_after_ms": event.not_after_ms, "at_ms": event.at_ms}
    if isinstance(event, TxTerminal):
        return {"type": "tx_terminal", "handle": event.handle, "generation": event.generation,
                "outcome": event.outcome, "at_ms": event.at_ms}
    if isinstance(event, Cancel):
        return {"type": "cancel", "handle": event.handle, "generation": event.generation,
                "at_ms": event.at_ms}
    if isinstance(event, ApplicationEvent):
        return {"type": "application_event", "kind": event.kind,
                "service_id": event.service_id, "exchange_id": event.exchange_id,
                "status": event.status, "payload_b64": base64.b64encode(event.payload).decode("ascii"),
                "at_ms": event.at_ms}
    raise RuntimeError("endpoint emitted an unregistered event type")


def _parse_line(line: str) -> dict[str, Any]:
    if len(line.encode("utf-8")) > MAX_INPUT_LINE:
        raise BridgeInputError("input line exceeds byte limit")
    try:
        value = json.loads(line, object_pairs_hook=_object, parse_constant=_reject_constant)
    except BridgeInputError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
        raise BridgeInputError("invalid JSON line") from exc
    _depth(value)
    if not isinstance(value, dict) or set(value) != {"interface", "input"}:
        raise BridgeInputError("request does not match the closed process schema")
    if value["interface"] != "DMP-PEER-TEST/1":
        raise BridgeInputError("unsupported interface version")
    return value


def run_bridge(stdin: TextIO, stdout: TextIO, stderr: TextIO, endpoint: PeerEndpoint) -> int:
    """Process bounded one-event requests; API bytes go only to stdout."""
    requests = 0
    while True:
        line = stdin.readline(MAX_INPUT_LINE + 2)
        if line == "":
            break
        requests += 1
        if requests > MAX_REQUESTS:
            stderr.write("E_LIMIT\n")
            return 2
        try:
            request = _parse_line(line)
            input_event = _input_event(request["input"])
            events = endpoint.handle(input_event)
            if len(events) > MAX_EVENTS:
                raise BridgeInputError("event count exceeds output bound")
            records = [_event_record(event) for event in events]
            raw_output_bytes = sum(
                len(getattr(event, "bytes", b"")) + len(getattr(event, "payload", b""))
                for event in events
            )
            if raw_output_bytes > MAX_OUTPUT_BYTES or len(records) > MAX_EVENTS:
                raise BridgeInputError("event bytes exceed output bound")
            response = json.dumps(
                {"interface": "DMP-PEER-TEST/1", "events": records},
                ensure_ascii=True, separators=(",", ":"), allow_nan=False,
            )
            if len(response.encode("utf-8")) > MAX_OUTPUT_LINE:
                raise BridgeInputError("output line exceeds byte limit")
        except (BridgeInputError, ValueError, TypeError, KeyError, RecursionError):
            stderr.write("E_INPUT\n")
            return 2
        stdout.write(response + "\n")
        stdout.flush()
    if endpoint.active_submissions:
        stderr.write("E_TERMINAL\n")
        return 2
    return 0


def _secret_hex(name: str, size: int) -> bytes | None:
    text = os.environ.get(name)
    if text is None:
        return None
    try:
        value = bytes.fromhex(text)
    except ValueError as exc:
        raise BridgeInputError("invalid credential environment value") from exc
    if len(value) != size:
        raise BridgeInputError("credential environment value has wrong size")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--node-id", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        raw = Path(args.manifest).read_bytes()
        credentials: dict[str, Any] = {"node_id": args.node_id}
        psk = _secret_hex("DMP_PEER_TEST_PSK_HEX", 32)
        static_private = _secret_hex("DMP_PEER_TEST_STATIC_PRIVATE_HEX", 32)
        peer_pin = _secret_hex("DMP_PEER_TEST_PEER_PIN_HEX", 32)
        if psk is not None:
            credentials["psk"] = psk
        if static_private is not None:
            credentials["static_private_key"] = static_private
        if peer_pin is not None:
            credentials["peer_static_public_key"] = peer_pin
        hint = os.environ.get("DMP_PEER_TEST_KEY_HINT")
        if hint is not None:
            credentials["key_hint"] = int(hint, 0)
        endpoint = PeerEndpoint(
            manifest_bytes=raw, test_credentials=credentials,
            entropy_source=secrets.token_bytes, test_services={},
        )
    except (OSError, ValueError, TypeError, KeyError, BridgeInputError):
        sys.stderr.write("E_CONFIG\n")
        return 2
    return run_bridge(sys.stdin, sys.stdout, sys.stderr, endpoint)


if __name__ == "__main__":
    raise SystemExit(main())
