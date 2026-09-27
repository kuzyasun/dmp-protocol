#!/usr/bin/env python3
"""Bounded two-peer controller for the private DMPBENCH v1 provider probe.

This is a laboratory host tool. It drives the provider command interface; it
does not implement Noise or the DMP wire protocol.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import queue
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, Sequence


PREFIX = b"DMPBENCH "
VERSION = 1
REQUEST_MAX = 3071
RESPONSE_MAX = 16384
MAX_CYCLES = 1000
DEFAULT_CYCLES = 8
DEFAULT_TIMEOUT = 3.0
MAX_TIMEOUT = 60.0
MAX_RECENT_LOGS = 64
MAC_FAILURE = 17668
ERROR_NO_MEMORY = 17665
ERROR_SYSTEM = 17670
ERROR_INVALID_STATE = 17676
ERROR_INVALID_NONCE = 17677
ACTION_WRITE = 16641
ACTION_READ = 16642
ACTION_SPLIT = 16644
ACTION_COMPLETE = 16645
ACTION_FAILED = 16643
REQUIRED_STATS = {
    "arena_live", "arena_peak", "blocks", "quota", "backing", "metadata",
    "owners", "scratch", "allocs", "frees", "attempts", "refusals",
    "wipe_errors", "rng_calls", "heap_free", "heap_min", "heap_largest",
    "stack_free_min",
}
STABLE_LAYOUT_STATS = {"quota", "backing", "metadata", "owners", "scratch"}
_REBOOT = re.compile(rb"(?:rst:\s*0x|Rebooting\s+\.\.\.|ESP-ROM:|Restarting\s+system)", re.I)
_BOOT_ID = re.compile(r"[0-9a-f]{16}\Z")
_BUILD_ID = re.compile(r"[0-9a-f]{64}\Z")


class BenchError(RuntimeError):
    """A failed or indeterminate bench operation; the command is never retried."""


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


class LineTransport(Protocol):
    def readline(self, timeout: float, limit: int = RESPONSE_MAX) -> bytes: ...
    def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...


class SubprocessTransport:
    """A bounded line view over a host provider executable's stdout/stdin."""

    def __init__(self, executable: str):
        self.process = subprocess.Popen(
            [executable], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, bufsize=0,
        )
        assert self.process.stdout is not None
        self._chunks: queue.Queue[bytes | None] = queue.Queue(maxsize=16)
        self._buffer = bytearray()
        self._discarding = False
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        assert self.process.stdout is not None
        try:
            while True:
                chunk = os.read(self.process.stdout.fileno(), 256)
                if not chunk:
                    self._chunks.put(None)
                    return
                self._chunks.put(chunk)
        except (OSError, ValueError):
            try:
                self._chunks.put_nowait(None)
            except queue.Full:
                pass

    def write(self, data: bytes) -> None:
        if self.process.poll() is not None or self.process.stdin is None:
            raise BenchError(f"host provider exited (status {self.process.poll()})")
        try:
            self.process.stdin.write(data)
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise BenchError("host provider stdin closed") from exc

    def readline(self, timeout: float, limit: int = RESPONSE_MAX) -> bytes:
        deadline = time.monotonic() + timeout
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self._buffer[: newline + 1])
                del self._buffer[: newline + 1]
                if self._discarding:
                    self._discarding = False
                    raise BenchError("provider emitted an overlong line")
                if len(line) > limit:
                    raise BenchError("provider emitted an overlong line")
                return line
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("provider response deadline expired")
            try:
                chunk = self._chunks.get(timeout=remaining)
            except queue.Empty as exc:
                raise TimeoutError("provider response deadline expired") from exc
            if chunk is None:
                raise BenchError("host provider stdout closed")
            if self._discarding:
                newline = chunk.find(b"\n")
                if newline >= 0:
                    tail = chunk[newline + 1:]
                    self._buffer.extend(tail)
                    self._discarding = False
                    raise BenchError("provider emitted an overlong line")
                continue
            self._buffer.extend(chunk)
            if len(self._buffer) > limit and b"\n" not in self._buffer:
                self._buffer.clear()
                self._discarding = True

    def close(self) -> None:
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1.0)
        self.process.stdout.close() if self.process.stdout is not None else None


class SerialTransport:
    def __init__(self, port: str, baud: int = 115200):
        try:
            import serial  # type: ignore[import-not-found]
        except ImportError as exc:
            raise BenchError("UART mode requires optional pyserial") from exc
        self._serial = serial.Serial(port=None, baudrate=baud, timeout=0.05,
                                     write_timeout=1.0)
        self._serial.port = port
        self._serial.dtr = False
        self._serial.rts = False
        self._serial.open()

    def write(self, data: bytes) -> None:
        try:
            written = self._serial.write(data)
        except Exception as exc:
            raise BenchError("UART write failed") from exc
        if written != len(data):
            raise BenchError("short UART write")

    def readline(self, timeout: float, limit: int = RESPONSE_MAX) -> bytes:
        deadline = time.monotonic() + timeout
        line = bytearray()
        oversized = False
        while time.monotonic() < deadline:
            chunk = self._serial.read(1)
            if not chunk:
                continue
            if not oversized:
                line += chunk
                if len(line) > limit:
                    line.clear()
                    oversized = True
            if chunk == b"\n":
                if oversized:
                    raise BenchError("provider emitted an overlong line")
                return bytes(line)
        raise TimeoutError("UART response deadline expired")

    def close(self) -> None:
        self._serial.close()


@dataclass
class Peer:
    name: str
    transport: LineTransport
    evidence: Any
    timeout: float = DEFAULT_TIMEOUT
    sequence: int = 0
    logs: list[str] = field(default_factory=list)
    closed: bool = False
    boot_id: str | None = None
    build_id: str | None = None

    def __post_init__(self) -> None:
        if not math.isfinite(self.timeout) or not 0 < self.timeout <= MAX_TIMEOUT:
            raise BenchError(f"timeout must be finite and in 0..{MAX_TIMEOUT:g} seconds")

    def command(self, op: str, *args: object,
                expected_rc: int | tuple[int, ...] = 0) -> dict[str, Any]:
        if self.closed:
            raise BenchError(f"{self.name}: transport is closed")
        if type(expected_rc) is int:
            expected_codes = (expected_rc,)
        elif isinstance(expected_rc, tuple) and expected_rc and all(type(code) is int for code in expected_rc):
            expected_codes = expected_rc
        else:
            raise BenchError("expected_rc must name one or more exact integer result codes")
        tokens = [op, *(str(arg) for arg in args)]
        if any(not token or any(ord(char) < 0x21 or ord(char) > 0x7E for char in token)
               for token in tokens):
            raise BenchError("command tokens must be nonempty printable ASCII without whitespace")
        if len(tokens) + 3 > 10:
            raise BenchError("command exceeds provider token capacity")
        seq = self.sequence + 1
        if seq > 0xFFFFFFFF:
            raise BenchError(f"{self.name}: DMPBENCH command id space exhausted")
        fields = ["DMPBENCH", "1", str(seq), *tokens]
        request = (" ".join(fields) + "\n").encode("ascii")
        if len(request) - 1 > REQUEST_MAX:
            raise BenchError(f"{self.name}: request exceeds {REQUEST_MAX} bytes")
        self.sequence = seq
        self._record({"event": "command", "peer": self.name, "id": seq,
                      "op": op, "args": [str(arg) for arg in args]})
        return self._exchange(request, op, seq, expected_codes)

    def synchronize(self) -> dict[str, Any]:
        """Read the provider's current command ID without consuming one."""
        if self.closed:
            raise BenchError(f"{self.name}: transport is closed")
        request = b"DMPBENCH 1 0 HELLO\n"
        self._record({"event": "synchronize", "peer": self.name, "id": 0,
                      "op": "HELLO", "raw_request": request.decode("ascii").rstrip("\n")})
        response = self._exchange(request, "HELLO", 0, (0,))
        last_id = response["last_id"]
        if type(last_id) is not int or not 0 <= last_id <= 0xFFFFFFFF:
            raise BenchError(f"{self.name}: synchronization returned invalid last_id")
        if last_id < response["id"]:
            raise BenchError(f"{self.name}: synchronization last_id precedes response id")
        self.sequence = last_id
        self._record({"event": "synchronized", "peer": self.name,
                      "id": 0, "last_id": last_id})
        return response

    def _exchange(self, request: bytes, op: str, seq: int,
                  expected_codes: tuple[int, ...]) -> dict[str, Any]:
        try:
            self.transport.write(request)
            deadline = time.monotonic() + self.timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("provider response deadline expired")
                raw = self.transport.readline(remaining, RESPONSE_MAX)
                if _REBOOT.search(raw):
                    raise BenchError(f"{self.name}: device reboot detected: {raw[:200]!r}")
                if not raw.startswith(PREFIX):
                    log_line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    self.logs.append(log_line)
                    if len(self.logs) > MAX_RECENT_LOGS:
                        del self.logs[:len(self.logs) - MAX_RECENT_LOGS]
                    self._record({"event": "log", "peer": self.name,
                                  "id": seq, "raw": log_line})
                    continue
                try:
                    response = self._parse_response(raw, seq)
                except BenchError as exc:
                    self._record({"event": "malformed_response", "peer": self.name,
                                  "id": seq, "raw": raw.decode("ascii", "replace").rstrip("\r\n"),
                                  "raw_hex": raw.hex(), "error": str(exc)})
                    raise
                self._record({"event": "response", "peer": self.name,
                              "id": seq, "raw": raw.decode("ascii", "replace").rstrip("\r\n"),
                              "response": response})
                if response["rc"] not in expected_codes:
                    raise BenchError(f"{self.name}: {op} returned rc={response['rc']}, expected one of {expected_codes}")
                return response
        except TimeoutError as exc:
            self._record({"event": "timeout", "peer": self.name, "id": seq,
                          "op": op, "outcome": "unknown; not retried"})
            raise BenchError(f"{self.name}: {op} id={seq} timed out; outcome unknown, not retried") from exc
        except BenchError as exc:
            self._record({"event": "failure", "peer": self.name, "id": seq,
                          "op": op, "error": str(exc)})
            raise

    def _parse_response(self, raw: bytes, expected_id: int) -> dict[str, Any]:
        try:
            value = json.loads(raw[len(PREFIX):].decode("ascii").strip(),
                               object_pairs_hook=_unique_json_object,
                               parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, ValueError) as exc:
            raise BenchError(f"{self.name}: malformed DMPBENCH JSON") from exc
        if not isinstance(value, dict):
            raise BenchError(f"{self.name}: response JSON is not an object")
        required = {"v", "id", "rc", "us", "action", "data", "target", "idf",
                    "boot", "build", "last_id", "stats"}
        if not required.issubset(value):
            raise BenchError(f"{self.name}: response missing fields {sorted(required - value.keys())}")
        if type(value["v"]) is not int or value["v"] != VERSION:
            raise BenchError(f"{self.name}: unsupported response version {value['v']!r}")
        if type(value["id"]) is not int or value["id"] != expected_id:
            raise BenchError(f"{self.name}: response id {value['id']!r}, expected {expected_id}")
        if (type(value["last_id"]) is not int
                or not 0 <= value["last_id"] <= 0xFFFFFFFF
                or value["last_id"] < value["id"]):
            raise BenchError(f"{self.name}: last_id must be uint32 and at least the response id")
        if type(value["rc"]) is not int or type(value["action"]) is not int or value["action"] < 0:
            raise BenchError(f"{self.name}: rc/action must be integers")
        if (type(value["us"]) is not int or not 0 <= value["us"] <= 0xFFFFFFFFFFFFFFFF
                or not isinstance(value["target"], str) or not value["target"]
                or not isinstance(value["idf"], str) or not value["idf"]):
            raise BenchError(f"{self.name}: us/target/idf have invalid values")
        if not isinstance(value["boot"], str) or not _BOOT_ID.fullmatch(value["boot"]):
            raise BenchError(f"{self.name}: boot must be a 16-character lowercase hex identifier")
        if not isinstance(value["build"], str) or not _BUILD_ID.fullmatch(value["build"]):
            raise BenchError(f"{self.name}: build must be a 64-character lowercase hex fingerprint")
        if not isinstance(value["data"], str) or not re.fullmatch(r"(?:[0-9a-f]{2})*", value["data"]):
            raise BenchError(f"{self.name}: data must be lowercase even-length hex")
        if value["rc"] != 0 and value["data"]:
            raise BenchError(f"{self.name}: error response data must be empty")
        if not isinstance(value["stats"], dict) or not REQUIRED_STATS.issubset(value["stats"]):
            raise BenchError(f"{self.name}: stats missing required counters")
        if any(type(value["stats"][key]) is not int or value["stats"][key] < 0
               for key in REQUIRED_STATS):
            raise BenchError(f"{self.name}: stats counters must be nonnegative integers")
        if self.boot_id is not None and value["boot"] != self.boot_id:
            raise BenchError(f"{self.name}: boot identifier changed; device reset detected")
        if self.build_id is not None and value["build"] != self.build_id:
            raise BenchError(f"{self.name}: build fingerprint changed during the run")
        self.boot_id = value["boot"]
        self.build_id = value["build"]
        return value

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.transport.close()
            finally:
                self._record({"event": "transport_closed", "peer": self.name})

    def _record(self, value: dict[str, Any]) -> None:
        value["time_unix_ms"] = int(time.time() * 1000)
        self.evidence.write(json.dumps(value, sort_keys=True) + "\n")
        self.evidence.flush()


def _fixture_vectors() -> dict[str, dict[str, Any]]:
    fixture_path = Path(__file__).resolve().parents[3] / "docs" / "DMP_v2_Security_Test_Vectors.json"
    try:
        document = json.loads(fixture_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchError(f"cannot read public test vectors at {fixture_path}") from exc
    result: dict[str, dict[str, Any]] = {}
    for vector in document["vectors"]:
        if vector["cipher"] == 1:
            result["nn" if vector["mode"] == 1 else "xx"] = vector
    if set(result) != {"nn", "xx"}:
        raise BenchError("public vectors do not contain both ChaChaPoly NN and XX cases")
    return result


def _hex(data: str) -> bytes:
    return bytes.fromhex(data)


def _expect_data(response: dict[str, Any], expected_hex: str, what: str) -> None:
    if response["data"] != expected_hex.lower():
        raise BenchError(f"{what}: expected {expected_hex}, got {response['data']}")


def _response_data(response: dict[str, Any]) -> bytes:
    return _hex(response["data"])


def _expect_action(response: dict[str, Any], expected: int, what: str) -> None:
    if response["action"] != expected:
        raise BenchError(f"{what}: expected post-operation action {expected}, got {response['action']}")


def _stats(peer: Peer) -> dict[str, Any]:
    return peer.command("STATS")["stats"]


def _assert_clean_stats(peer: Peer, stats: dict[str, int]) -> None:
    if stats["arena_live"] != 0 or stats["blocks"] != 0:
        raise BenchError(f"{peer.name}: arena still has live bytes or blocks after CLOSE")
    if stats["allocs"] != stats["frees"]:
        raise BenchError(f"{peer.name}: allocation/free counts differ after CLOSE")
    if stats["wipe_errors"] != 0:
        raise BenchError(f"{peer.name}: provider reported wipe errors")


def _assert_layout(peer: Peer, stats: dict[str, int], baseline: dict[str, int]) -> None:
    # `owners` reports sizeof the static owner table in bytes, not live owners.
    if stats["owners"] <= 0:
        raise BenchError(f"{peer.name}: owner-table storage size is invalid")
    for key in STABLE_LAYOUT_STATS:
        if stats[key] != baseline[key]:
            raise BenchError(f"{peer.name}: {key} storage/configuration baseline changed")


def _close_slot(peer: Peer, slot: int) -> None:
    peer.command("CLOSE", slot)


def _handshake(peers: tuple[Peer, Peer], mode: str, fixed: bool,
               orientation: int) -> tuple[Peer, Peer, bytes, dict[str, Any]]:
    initiator, responder = peers if orientation % 2 == 0 else peers[::-1]
    mode_num = {"nn": "nn", "xx": "xx"}[mode]
    flavor = "fixed" if fixed else "random"
    created_i = initiator.command("NEW", 0, mode_num, "i", flavor)
    created_r = responder.command("NEW", 0, mode_num, "r", flavor)
    _expect_action(created_i, ACTION_WRITE, f"{initiator.name} NEW initiator")
    _expect_action(created_r, ACTION_READ, f"{responder.name} NEW responder")
    vector = _fixture_vectors()[mode] if fixed else None
    flights = vector["flights"] if vector else None
    flight_idx = 0
    message_count = len(flights) if vector else (2 if mode == "nn" else 3)
    for flight_idx in range(message_count):
        # WRITE carries the handshake payload argument. The provider returns its
        # serialized Noise flight; no host crypto or flight rewriting occurs.
        writer, reader = (initiator, responder) if flight_idx % 2 == 0 else (responder, initiator)
        payload = flights[flight_idx]["noise_plaintext"] if vector else ("09000000" if flight_idx == 1 else "")
        out = writer.command("WRITE", 0, payload or "-")
        write_action = ACTION_SPLIT if flight_idx + 1 == message_count else ACTION_READ
        _expect_action(out, write_action, f"{writer.name} WRITE flight {flight_idx + 1}")
        flight = _response_data(out)
        if vector:
            if flight_idx >= len(flights) or flight.hex() != flights[flight_idx]["noise_message"]:
                raise BenchError(f"{mode.upper()} flight {flight_idx + 1} differs from public vector")
        received = reader.command("READ", 0, flight.hex())
        read_action = ACTION_SPLIT if flight_idx + 1 == message_count else ACTION_WRITE
        _expect_action(received, read_action, f"{reader.name} READ flight {flight_idx + 1}")
        expected_plaintext = payload.lower()
        if received["data"] != expected_plaintext:
            raise BenchError(f"{mode.upper()} flight {flight_idx + 1} plaintext differs from sent payload")
        if vector and received["data"] != flights[flight_idx]["noise_plaintext"]:
            raise BenchError(f"{mode.upper()} flight {flight_idx + 1} plaintext differs from vector")
    split_i = initiator.command("SPLIT", 0)
    split_r = responder.command("SPLIT", 0)
    _expect_action(split_i, ACTION_COMPLETE, f"{initiator.name} SPLIT")
    _expect_action(split_r, ACTION_COMPLETE, f"{responder.name} SPLIT")
    if len(split_i["data"]) != 64 or split_i["data"] != split_r["data"]:
        raise BenchError("peer handshake hashes differ or are not 32 bytes")
    if vector and split_i["data"] != vector["handshake_hash"]:
        raise BenchError(f"{mode.upper()} handshake hash differs from public vector")
    return initiator, responder, bytes.fromhex(split_i["data"]), vector or {}


def _seal(sender: Peer, pn: int, aad: str, plaintext: str) -> bytes:
    response = sender.command("SEAL", 0, pn, aad or "-", plaintext or "-")
    _expect_action(response, ACTION_COMPLETE, f"{sender.name} SEAL")
    return _response_data(response)


def _open(receiver: Peer, pn: int, aad: str, ciphertext: bytes,
          expected_rc: int = 0) -> str:
    response = receiver.command("OPEN", 0, pn, aad or "-", ciphertext.hex() or "-",
                                expected_rc=expected_rc)
    _expect_action(response, ACTION_COMPLETE, f"{receiver.name} OPEN")
    return response["data"]


def _security_exchange(peers: tuple[Peer, Peer], initiator: Peer, responder: Peer, fixed: bool,
                       vector: dict[str, Any], mode: str) -> None:
    if fixed and vector:
        packets = {packet["name"]: packet for packet in vector["packets"]}
        for name in ("finish", "ready"):
            packet = packets[name]
            sender, receiver = (initiator, responder) if packet["direction"] == 0 else (responder, initiator)
            ciphertext = _seal(sender, packet["pn"], packet["aad"], packet["plaintext"])
            _expect_data({"data": ciphertext.hex()}, packet["ciphertext"] + packet["tag"],
                         f"{mode.upper()} {name} ciphertext")
            if _open(receiver, packet["pn"], packet["aad"], ciphertext) != packet["plaintext"]:
                raise BenchError(f"{mode.upper()} {name} plaintext mismatch")

    # Exercise a two-packet receive reordering in each direction. These are
    # actual bytes captured from the peer provider and passed unchanged.
    for sender, receiver in ((initiator, responder), (responder, initiator)):
        p1 = _seal(sender, 1, "a1", "010203")
        p2 = _seal(sender, 2, "a2", "a0b0c0")
        if _open(receiver, 2, "a2", p2) != "a0b0c0":
            raise BenchError("PN 2 reordered packet plaintext mismatch")
        if _open(receiver, 1, "a1", p1) != "010203":
            raise BenchError("PN 1 after PN 2 plaintext mismatch")

        tag_aad = b"tag-aad".hex()
        packet = _seal(sender, 3, tag_aad, "cafe")
        corrupt = packet[:-1] + bytes([packet[-1] ^ 1])
        _open(receiver, 3, tag_aad, corrupt, expected_rc=MAC_FAILURE)
        if _open(receiver, 3, tag_aad, packet) != "cafe":
            raise BenchError("authentic packet failed after bad-tag rejection")

        right_aad = b"right-aad".hex()
        wrong_aad = b"wrong-aad".hex()
        aad_packet = _seal(sender, 4, right_aad, "beef")
        _open(receiver, 4, wrong_aad, aad_packet, expected_rc=MAC_FAILURE)
        if _open(receiver, 4, right_aad, aad_packet) != "beef":
            raise BenchError("authentic packet failed after wrong-AAD rejection")
        rejected = sender.command("SEAL", 0, 4, right_aad, "beef",
                                  expected_rc=ERROR_INVALID_NONCE)
        _expect_action(rejected, ACTION_COMPLETE, f"{sender.name} reused TX PN")


def _fault_cases(peers: tuple[Peer, Peer], mode: str) -> None:
    peer = peers[0]
    # NEW allocates the owner and handshake state. The one-shot allocation fault
    # must therefore surface as the exact Noise out-of-memory error here.
    peer.command("ALLOCFAIL", 1)
    failed_new = peer.command("NEW", 7, mode, "i", "random", expected_rc=ERROR_NO_MEMORY)
    if failed_new["data"]:
        raise BenchError("failed NEW returned data")
    _close_slot(peer, 7)
    _assert_clean_stats(peer, _stats(peer))

    # Random NEW/start does not request entropy. RNGFAIL is consumed by the
    # first WRITE, which must latch the Noise state as failed.
    peer.command("RNGFAIL", 1)
    peer.command("NEW", 7, mode, "i", "random")
    before_write = _stats(peer)
    failed_write = peer.command("WRITE", 7, "-", expected_rc=ERROR_SYSTEM)
    _expect_action(failed_write, ACTION_FAILED, f"{peer.name} RNG-failed WRITE")
    if failed_write["data"]:
        raise BenchError("failed WRITE returned data")
    for counter in ("attempts", "allocs", "frees", "refusals"):
        if failed_write["stats"][counter] != before_write[counter]:
            raise BenchError(f"WRITE changed allocation counter {counter}")
    peer.command("WRITE", 7, "-", expected_rc=ERROR_INVALID_STATE)
    _close_slot(peer, 7)

    # Retry only from a fresh owner after explicit cleanup. A successful WRITE
    # also proves this operation does not allocate.
    peer.command("NEW", 7, mode, "i", "random")
    before_write = _stats(peer)
    retried_write = peer.command("WRITE", 7, "-")
    _expect_action(retried_write, ACTION_READ, f"{peer.name} fresh WRITE retry")
    for counter in ("attempts", "allocs", "frees", "refusals"):
        if retried_write["stats"][counter] != before_write[counter]:
            raise BenchError(f"WRITE changed allocation counter {counter}")
    _close_slot(peer, 7)
    _assert_clean_stats(peer, _stats(peer))


def run_bench(peers: tuple[Peer, Peer], *, cycles: int, mode: str,
              output_path: str) -> dict[str, Any]:
    if not 1 <= cycles <= MAX_CYCLES:
        raise BenchError(f"cycles must be 1..{MAX_CYCLES}")
    if mode not in {"fixed", "random", "both"}:
        raise BenchError("mode must be fixed, random or both")
    summaries: list[dict[str, Any]] = []
    selected = [name for name in ("nn", "xx")]
    hellos = [peer.synchronize() for peer in peers]
    for peer, hello in zip(peers, hellos):
        if hello["v"] != VERSION:
            raise BenchError("provider synchronization HELLO mismatch")
        peer._record({"event": "run_metadata", "peer": peer.name,
                      "target": hello["target"], "idf": hello["idf"],
                      "boot": hello["boot"], "build": hello["build"],
                      "cycles": cycles, "mode": mode, "timeout_s": peer.timeout,
                      "command_protocol": "DMPBENCH 1"})
        peer.command("INIT")
    layout_baselines = [_stats(peer) for peer in peers]
    for peer, baseline in zip(peers, layout_baselines):
        _assert_clean_stats(peer, baseline)
        _assert_layout(peer, baseline, baseline)
    fixed = mode in ("fixed", "both")
    random_run = mode in ("random", "both")
    for cycle in range(cycles):
        for pattern in selected:
            for use_fixed in ([True] if fixed else []) + ([False] if random_run else []):
                # Every pattern/flavor pair covers both physical role
                # orientations, even when cycles=1.
                for orientation in (0, 1):
                    before = [_stats(peer) for peer in peers]
                    for index, stats in enumerate(before):
                        _assert_clean_stats(peers[index], stats)
                        _assert_layout(peers[index], stats, layout_baselines[index])
                    initiator, responder, _, vector = _handshake(peers, pattern, use_fixed, orientation)
                    _security_exchange(peers, initiator, responder, use_fixed, vector, pattern)
                    after = [_stats(peer) for peer in peers]
                    for peer in peers:
                        _close_slot(peer, 0)
                    closed = [_stats(peer) for peer in peers]
                    for index, stats in enumerate(closed):
                        _assert_clean_stats(peers[index], stats)
                        _assert_layout(peers[index], stats, layout_baselines[index])
                        if (stats["arena_live"] != before[index]["arena_live"]
                                or stats["blocks"] != before[index]["blocks"]):
                            raise BenchError(f"{peers[index].name}: live arena baseline changed after CLOSE")
                    summaries.append({"cycle": cycle, "mode": pattern,
                                      "kind": "fixed" if use_fixed else "random",
                                      "orientation": orientation, "before": before,
                                      "active": after, "closed": closed})
    if random_run:
        _fault_cases(peers, "nn")
        stable = [_stats(peer) for peer in peers]
        for index, stats in enumerate(stable):
            _assert_clean_stats(peers[index], stats)
            _assert_layout(peers[index], stats, layout_baselines[index])
    result = {"schema": "dmpbench-summary-v1", "success": True,
              "cycles": cycles, "mode": mode, "output": output_path,
              "scenarios": summaries}
    for peer in peers:
        peer._record({"event": "summary", **result})
    return result


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--host-exe", help="provider executable; start two independent processes")
    source.add_argument("--ports", nargs=2, metavar=("PORT_A", "PORT_B"),
                        help="two UART ports, opened at 115200 baud")
    parser.add_argument("--output", required=True, help="JSONL evidence path")
    parser.add_argument("--cycles", type=int, default=DEFAULT_CYCLES)
    parser.add_argument("--mode", choices=("fixed", "random", "both"), default="both")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if not 1 <= args.cycles <= MAX_CYCLES:
        print(f"error: --cycles must be 1..{MAX_CYCLES}", file=sys.stderr)
        return 2
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= MAX_TIMEOUT:
        print(f"error: --timeout must be finite and in 0..{MAX_TIMEOUT:g} seconds", file=sys.stderr)
        return 2
    evidence = None
    peers: list[Peer] = []
    transports: list[LineTransport] = []
    try:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        evidence = path.open("x", encoding="utf-8", newline="\n")
        if args.host_exe:
            for _ in range(2):
                transports.append(SubprocessTransport(args.host_exe))
        else:
            for port in args.ports:
                transports.append(SerialTransport(port, 115200))
        peers = [Peer(f"peer-{index + 1}", transport, evidence, args.timeout)
                 for index, transport in enumerate(transports)]
        for index, peer in enumerate(peers):
            peer._record({"event": "transport_metadata", "peer": peer.name,
                          "transport": "host-process" if args.host_exe else "uart",
                          "endpoint": args.host_exe if args.host_exe else args.ports[index],
                          "baud": None if args.host_exe else 115200,
                          "dtr": False if args.ports else None,
                          "rts": False if args.ports else None,
                          "cycles": args.cycles, "mode": args.mode,
                          "timeout_s": args.timeout})
        summary = run_bench((peers[0], peers[1]), cycles=args.cycles,
                            mode=args.mode, output_path=str(path))
        print(json.dumps(summary, sort_keys=True))
        return 0
    except Exception as exc:
        if evidence is not None:
            evidence.write(json.dumps({"event": "run_failed", "error": str(exc),
                                       "time_unix_ms": int(time.time() * 1000)}, sort_keys=True) + "\n")
            evidence.flush()
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        for peer in peers:
            try:
                peer.close()
            except Exception:
                pass
        for transport in transports[len(peers):]:
            try:
                transport.close()
            except Exception:
                pass
        if evidence is not None:
            evidence.close()


if __name__ == "__main__":
    raise SystemExit(main())
