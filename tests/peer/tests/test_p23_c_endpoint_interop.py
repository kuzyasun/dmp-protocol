"""P23 direct interoperability: the C endpoint talks to the P21 Python peer."""

from __future__ import annotations

import hashlib
import json
import os
from collections import deque
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from typing import Any

sys.path.insert(0, str(Path(__file__).parents[1]))

from dmp_peer.events import (  # noqa: E402
    Advance,
    ApplicationEvent,
    ApplicationRequest,
    Open,
    PublishSample,
    Receive,
    TxAdmit,
    TxSubmit,
    TxTerminal,
)
from dmp_peer.sample1 import Sample  # noqa: E402
from dmp_peer.stream_r import StreamRDecoder, encode_stream_r  # noqa: E402
from dmp_peer.testing import PeerEndpoint  # noqa: E402


_ROOT = Path(__file__).parents[3]
_MANIFEST_NAME = "test-peer-tcp-stream-r-nnpsk0.json"
_SAMPLE20_MANIFEST_NAME = "test-peer-tcp-stream-r-sample20-nnpsk0.json"
_INTERFACE_VERSION = 1
_OP_INIT = 1
_OP_RECEIVE = 2
_OP_SUBMIT_REQ = 3
_OP_SUBMIT_DATA = 4
_OP_COMPLETE = 5
_OP_POLL = 6
_OP_COMPLETE_SAMPLE = 7
_OP_SUBMIT_TELEM = 8
_OP_SUBMIT_FRESH_REQ = 9
_OP_SUBMIT_FRESH_DATA = 10
_OP_COMPLETE_TX = 11
_OP_REJECT_NEXT_TX = 12
_MAX_PROCESS_RECORD = 65536
_MAX_FRAMES = 24
_MAX_FRAME_BYTES = 512
_EFFECTIVE_CONFIG_FIELDS = (
    "peers", "operations_per_service", "assemblies_per_peer",
    "assembly_tombstones_per_peer", "sender_slots", "result_slots",
    "history_slots", "correlation_slots", "adapter_slots",
    "application_queue_slots", "control_slots", "message_bytes",
    "fragments", "chunk_bytes", "encoded_mtu", "forward_mtu",
    "return_mtu", "freshness_required_mask", "recovery_service_1",
    "recovery_service_2", "max_probes", "max_status", "response_timeout_ms",
    "send_horizon_ms", "burst_span_ms", "pin_commits",
)
_EFFECTIVE_BUDGET_FIELDS = (
    "max_pending", "max_scratch", "episode_attempts", "episode_deadline_ms",
    "attempt_deadline_ms", "confirmation_timeout_ms", "confirmation_attempts",
    "failed_aead_limit", "replay_window", "association_lifetime_ms",
)


def _read_exact(stream, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.read(size - len(chunks))
        if not chunk:
            raise EOFError("C endpoint test process closed its output")
        chunks.extend(chunk)
    return bytes(chunks)


class _CProcess:
    def __init__(
        self,
        executable: str,
        profile_hash: bytes,
        credential: bytes,
        *,
        mode: int = 1,
        expected_remote_pin: bytes = bytes(32),
        async_tx_completion: bool = False,
    ):
        self.process = subprocess.Popen(
            [executable, "p23-driver"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        if len(profile_hash) != 32 or len(credential) != 32 or len(expected_remote_pin) != 32:
            raise ValueError("P23 credentials and profile digest must be 32 bytes")
        self.initial = self.call(
            _OP_INIT,
            profile_hash + credential + expected_remote_pin
            + bytes((mode, int(async_tx_completion))),
        )
        if self.initial.status != 0:
            self.close()
            raise AssertionError("C endpoint initialization failed")
        self.last_state = self.initial
        self.async_tx_completion = async_tx_completion

    def call(self, operation: int, payload: bytes = b"") -> _CState:
        if len(payload) > _MAX_PROCESS_RECORD:
            raise ValueError("C endpoint test input exceeds process bound")
        self.process.stdin.write(struct.pack("<BBI", _INTERFACE_VERSION, operation, len(payload)))
        self.process.stdin.write(payload)
        self.process.stdin.flush()
        try:
            header = _read_exact(self.process.stdout, 6)
        except EOFError as exc:
            try:
                code = self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                code = None
            diagnostic = ""
            if code is not None:
                diagnostic = self.process.stderr.read().decode("utf-8", "replace")
            raise EOFError(f"{exc}; process status={code}; stderr={diagnostic}") from exc
        version, status, response_len = struct.unpack("<BBI", header)
        if version != _INTERFACE_VERSION or response_len > 32768:
            raise AssertionError("C endpoint returned an invalid process record")
        body = _read_exact(self.process.stdout, response_len)
        state = _decode_state(body)
        state.status = status
        self.last_state = state
        return state

    def receive(self, wire: bytes, now_ms: int) -> _CState:
        return self.call(_OP_RECEIVE, struct.pack("<QI", now_ms, len(wire)) + wire)

    def submit_req(self, service_id: int, payload: bytes, now_ms: int) -> _CState:
        return self.call(_OP_SUBMIT_REQ, struct.pack("<QII", now_ms, service_id, len(payload)) + payload)

    def submit_req_fresh(
        self, service_id: int, payload: bytes, token: bytes, now_ms: int
    ) -> _CState:
        if len(token) != 16:
            raise ValueError("S7 freshness tokens must be exactly 16 bytes")
        return self.call(
            _OP_SUBMIT_FRESH_REQ,
            struct.pack("<QII", now_ms, service_id, len(payload)) + token + payload,
        )

    def submit_data(self, service_id: int, payload: bytes, now_ms: int) -> _CState:
        return self.call(_OP_SUBMIT_DATA, struct.pack("<QII", now_ms, service_id, len(payload)) + payload)

    def submit_data_fresh(
        self, service_id: int, payload: bytes, token: bytes, now_ms: int
    ) -> _CState:
        if len(token) != 16:
            raise ValueError("S7 freshness tokens must be exactly 16 bytes")
        return self.call(
            _OP_SUBMIT_FRESH_DATA,
            struct.pack("<QII", now_ms, service_id, len(payload)) + token + payload,
        )

    def complete(self, now_ms: int) -> _CState:
        return self.call(_OP_COMPLETE, struct.pack("<Q", now_ms))

    def complete_sample(self, payload: bytes, now_ms: int) -> _CState:
        return self.call(
            _OP_COMPLETE_SAMPLE,
            struct.pack("<QI", now_ms, len(payload)) + payload,
        )

    def submit_telem(self, service_id: int, payload: bytes, now_ms: int) -> _CState:
        return self.call(
            _OP_SUBMIT_TELEM,
            struct.pack("<QII", now_ms, service_id, len(payload)) + payload,
        )

    def poll(self, now_ms: int) -> _CState:
        return self.call(_OP_POLL, struct.pack("<Q", now_ms))

    def complete_tx(self, count: int, now_ms: int) -> _CState:
        if not self.async_tx_completion:
            raise ValueError("manual TX completion requires async_tx_completion=True")
        if count < 0 or count > 0xFFFFFFFF:
            raise ValueError("TX completion count is outside the process bound")
        return self.call(_OP_COMPLETE_TX, struct.pack("<QI", now_ms, count))

    def reject_next_tx(self, count: int, now_ms: int) -> _CState:
        if count < 0 or count > 0xFFFFFFFF:
            raise ValueError("TX rejection count is outside the process bound")
        return self.call(_OP_REJECT_NEXT_TX, struct.pack("<QI", now_ms, count))

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.stdin.close()
            code = self.process.wait(timeout=10)
            diagnostic = self.process.stderr.read().decode("utf-8", "replace")
            self.process.stdout.close()
            self.process.stderr.close()
            if code != 0:
                raise AssertionError(f"C endpoint process failed ({code}): {diagnostic}")


class _CState:
    def __init__(self) -> None:
        self.status = 0
        self.endpoint_status = 0
        self.rx_status = 0
        self.handshake_active = False
        self.bound = False
        self.pending = False
        self.fragment_live = False
        self.accepts = 0
        self.results = 0
        self.assembled = 0
        self.telemetry = 0
        self.request_service = 0
        self.request = b""
        self.result = b""
        self.body = b""
        self.frames: list[bytes] = []
        self.profile_hash = b""
        self.effective_config: dict[str, int] = {}
        self.effective_budget: dict[str, int] = {}


def _decode_state(raw: bytes) -> _CState:
    state = _CState()
    cursor = 0

    def take(size: int) -> bytes:
        nonlocal cursor
        if size < 0 or cursor + size > len(raw):
            raise AssertionError("truncated C endpoint state record")
        value = raw[cursor : cursor + size]
        cursor += size
        return value

    def u32() -> int:
        return struct.unpack("<I", take(4))[0]

    state.endpoint_status = take(1)[0]
    state.rx_status = take(1)[0]
    flags = take(4)
    state.handshake_active = bool(flags[0])
    state.bound = bool(flags[1])
    state.pending = bool(flags[2])
    state.fragment_live = bool(flags[3])
    state.accepts = u32()
    state.results = u32()
    state.assembled = u32()
    state.telemetry = u32()
    state.request_service = u32()
    state.request = take(u32())
    state.result = take(u32())
    state.body = take(u32())
    frame_count = struct.unpack("<H", take(2))[0]
    if frame_count > _MAX_FRAMES:
        raise AssertionError("C endpoint exceeded its output frame bound")
    for _ in range(frame_count):
        frame = take(u32())
        if not frame or len(frame) > _MAX_FRAME_BYTES:
            raise AssertionError("C endpoint emitted an invalid frame size")
        state.frames.append(frame)
    state.profile_hash = take(32)
    state.effective_config = dict(
        zip(_EFFECTIVE_CONFIG_FIELDS, (u32() for _ in _EFFECTIVE_CONFIG_FIELDS))
    )
    state.effective_budget = dict(
        zip(_EFFECTIVE_BUDGET_FIELDS, (u32() for _ in _EFFECTIVE_BUDGET_FIELDS))
    )
    if cursor != len(raw):
        raise AssertionError("C endpoint returned trailing state bytes")
    return state


def _assert_effective_profile(test: unittest.TestCase, state: _CState, manifest_bytes: bytes) -> None:
    manifest = json.loads(manifest_bytes)
    limits = manifest["limits"]
    binding = manifest["binding"]
    timing = manifest["timing"]
    security = manifest["security"]
    endpoint_charges = next(
        item["charges"] for item in manifest["resources"] if item["role"] == "endpoint"
    )
    resource_counts = {
        charge["component"]: charge["count"] for charge in endpoint_charges
    }
    recovery = {"retry-all": 0, "selective-32": 1}
    expected_config = {
        "peers": limits["peers"],
        "operations_per_service": limits["operations_per_service"],
        "assemblies_per_peer": limits["assemblies_per_peer"],
        "assembly_tombstones_per_peer": limits["assembly_tombstones_per_peer"],
        "sender_slots": limits["sender_slots"],
        "result_slots": resource_counts["result"],
        "history_slots": resource_counts["history"],
        "correlation_slots": resource_counts["correlation"],
        "adapter_slots": limits["adapter_slots"],
        "application_queue_slots": limits["application_queue_slots"],
        "control_slots": limits["control_slots"],
        "message_bytes": limits["message_bytes"],
        "fragments": limits["fragments"],
        "chunk_bytes": limits["chunk_bytes"],
        "encoded_mtu": binding["encoded_mtu"],
        "forward_mtu": binding["forward_mtu"],
        "return_mtu": binding["return_mtu"],
        "freshness_required_mask": sum(
            1 << index for index, service in enumerate(manifest["services"])
            if service["freshness"]
        ),
        "recovery_service_1": recovery[manifest["services"][0]["recovery"]],
        "recovery_service_2": recovery[manifest["services"][1]["recovery"]],
        "max_probes": timing["max_probes"],
        "max_status": timing["max_status"],
        "response_timeout_ms": timing["response_timeout_ms"],
        "send_horizon_ms": timing["send_horizon_ms"],
        "burst_span_ms": timing["burst_span_ms"],
    }
    expected_budget = {
        "max_pending": security["pending_per_pair"],
        "max_scratch": security["crypto_slots"],
        "episode_attempts": security["episode_attempts"],
        "episode_deadline_ms": security["episode_ms"],
        "attempt_deadline_ms": security["attempt_ms"],
        "confirmation_timeout_ms": security["confirmation_timeout_ms"],
        "confirmation_attempts": security["confirmation_attempts"],
        "failed_aead_limit": security["failed_aead_limit"],
        "replay_window": security["replay_window_bits"],
        "association_lifetime_ms": security["association_ms"],
    }
    test.assertEqual(state.profile_hash, hashlib.sha256(manifest_bytes).digest())
    test.assertEqual(
        {key: state.effective_config[key] for key in expected_config}, expected_config
    )
    test.assertEqual(state.effective_budget, expected_budget)


class _Clock:
    def __init__(self, initial: int = 10000):
        self.now_ms = initial

    def next(self) -> int:
        self.now_ms += 1
        return self.now_ms

    def advance(self, delta_ms: int) -> int:
        self.now_ms += delta_ms
        return self.now_ms


def _settle(
    peer: PeerEndpoint,
    events: tuple[Any, ...] | list[Any],
    clock: _Clock,
) -> tuple[list[bytes], list[Any]]:
    wires: list[bytes] = []
    observed: list[Any] = list(events)
    for event in events:
        if isinstance(event, TxSubmit):
            wires.append(event.bytes)
    while peer.active_submissions:
        for handle, submission in list(peer.active_submissions.items()):
            if not submission.get("admitted"):
                admitted = peer.handle(
                    TxAdmit(
                        handle=handle,
                        generation=submission["generation"],
                        accepted=True,
                        reason=None,
                        at_ms=clock.next(),
                    )
                )
                observed.extend(admitted)
                wires.extend(item.bytes for item in admitted if isinstance(item, TxSubmit))
            if handle in peer.active_submissions:
                terminal = peer.handle(
                    TxTerminal(
                        handle=handle,
                        generation=submission["generation"],
                        outcome="transmitted",
                        at_ms=clock.next(),
                    )
                )
                observed.extend(terminal)
                wires.extend(item.bytes for item in terminal if isinstance(item, TxSubmit))
    return wires, observed


def _pump(
    c_endpoint: _CProcess,
    peer: PeerEndpoint,
    initial_c_frames: list[bytes],
    clock: _Clock,
    initial_peer_frames: list[bytes] | None = None,
) -> list[Any]:
    pending = deque(("c", frame) for frame in initial_c_frames)
    pending.extend(("peer", frame) for frame in (initial_peer_frames or []))
    observed: list[Any] = []
    for step in range(4096):
        if not pending:
            return observed
        side, wire = pending.popleft()
        if side == "c":
            events = peer.handle(Receive(link=0, bytes=wire, at_ms=clock.next()))
            peer_frames, peer_events = _settle(peer, events, clock)
            observed.extend(peer_events)
            pending.extend(("peer", frame) for frame in peer_frames)
        else:
            state = c_endpoint.receive(wire, clock.next())
            if state.status != 0:
                raise AssertionError(
                    f"C endpoint rejected a valid peer frame (status={state.endpoint_status}, "
                    f"rx_status={state.rx_status}, "
                    f"step={step}, frame_bytes={len(wire)}, accepts={state.accepts}, "
                    f"pending={state.pending}, request_bytes={len(state.request)})"
                )
            pending.extend(("c", frame) for frame in state.frames)
    raise AssertionError("endpoint exchange exceeded the bounded frame pump")


def _submit_c_data_until_peer_accepts(
    c_endpoint: _CProcess,
    peer: PeerEndpoint,
    initial: _CState,
    clock: _Clock,
    service_id: int,
    payload: bytes,
) -> list[Any]:
    observed: list[Any] = []
    frames = initial.frames
    deadline = clock.now_ms + 20_000
    while clock.now_ms < deadline:
        observed.extend(_pump(c_endpoint, peer, frames, clock))
        if any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == service_id
            and event.payload == payload
            for event in observed
        ):
            return observed
        state = c_endpoint.poll(clock.advance(64))
        if state.status != 0:
            raise AssertionError(
                f"C endpoint DATA poll failed (endpoint={state.endpoint_status}, "
                f"rx={state.rx_status}, service={service_id})"
            )
        frames = state.frames
    raise AssertionError(
        f"C DATA transfer was not accepted by the peer (service={service_id}, "
        f"bytes={len(payload)}, events={observed!r})"
    )


def _activate_pair(c_endpoint: _CProcess, peer: PeerEndpoint, clock: _Clock) -> None:
    peer_open = peer.handle(
        Open(link=0, deadline_capability="strict_latest_start", at_ms=clock.next())
    )
    peer_frames, _ = _settle(peer, peer_open, clock)
    if peer_frames != [b"\x00"] or c_endpoint.initial.frames != [b"\x00"]:
        raise AssertionError("Stream R endpoints did not exchange the empty sync delimiter")
    if c_endpoint.receive(peer_frames[0], clock.next()).status != 0:
        raise AssertionError("C endpoint rejected the peer's Stream R sync delimiter")
    if peer.handle(Receive(link=0, bytes=c_endpoint.initial.frames[0], at_ms=clock.next())) != ():
        raise AssertionError("Python peer emitted an unexpected response to the C sync delimiter")

    first_flight_events = peer.initiate_handshake(at_ms=clock.next())
    first_flight, _ = _settle(peer, first_flight_events, clock)
    if len(first_flight) != 1:
        raise AssertionError("Python peer did not emit one initial SEC-1 flight")
    c_response = c_endpoint.receive(first_flight[0], clock.next())
    if c_response.status != 0 or len(c_response.frames) != 1:
        raise AssertionError(f"C endpoint handshake stage/status={c_response.endpoint_status}")
    _pump(c_endpoint, peer, c_response.frames, clock)
    if not c_endpoint.last_state.handshake_active or not c_endpoint.last_state.bound:
        raise AssertionError("C endpoint did not bind the active SEC-1 association")
    if peer.association is None or peer.association.status != "active":
        raise AssertionError("Python peer did not activate the SEC-1 association")


@unittest.skipUnless(
    os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
    "C P23 endpoint executable is not configured",
)
class TestP23CPrimaryInterop(unittest.TestCase):
    def setUp(self) -> None:
        manifest_path = _ROOT / "profiles" / "deployments" / _MANIFEST_NAME
        digest_index = json.loads((_ROOT / "profiles" / "deployments" / "digests.json").read_text())
        self.manifest_bytes = manifest_path.read_bytes()
        self.profile_hash = hashlib.sha256(self.manifest_bytes).digest()
        self.assertEqual(self.profile_hash.hex(), digest_index["manifests"][_MANIFEST_NAME])
        self.executable = os.environ["DMP_P23_ENDPOINT_SEC_EXE"]

    def open_pair(
        self,
        psk: bytes,
        entropy_seed: int,
        *,
        manifest_name: str = _MANIFEST_NAME,
    ) -> tuple[_CProcess, PeerEndpoint, _Clock]:
        clock = _Clock()
        manifest_path = _ROOT / "profiles" / "deployments" / manifest_name
        manifest_bytes = manifest_path.read_bytes()
        profile_hash = hashlib.sha256(manifest_bytes).digest()
        digest_index = json.loads((_ROOT / "profiles" / "deployments" / "digests.json").read_text())
        self.assertEqual(profile_hash.hex(), digest_index["manifests"][manifest_name])
        manifest = json.loads(manifest_bytes)
        if manifest["security"]["mode"] == "XX":
            from cryptography.hazmat.primitives.asymmetric import x25519

            peer_static = b"\x20" * 32  # P20/P21C public test identity for node 10.
            c_static = b"\x10" * 32  # P20/P21C public test identity for node 20.
            c_public = x25519.X25519PrivateKey.from_private_bytes(c_static).public_key().public_bytes_raw()
            peer_public = x25519.X25519PrivateKey.from_private_bytes(peer_static).public_key().public_bytes_raw()
            c_endpoint = _CProcess(
                self.executable, profile_hash, c_static, mode=2, expected_remote_pin=peer_public
            )
            credentials = {
                "node_id": 10,
                "static_private_key": peer_static,
                "peer_static_public_key": c_public,
            }
        else:
            c_endpoint = _CProcess(self.executable, profile_hash, psk)
            credentials = {"node_id": 10, "psk": psk, "key_hint": 5}
        self.addCleanup(c_endpoint.close)
        _assert_effective_profile(self, c_endpoint.initial, manifest_bytes)
        self.assertEqual(c_endpoint.initial.effective_config["pin_commits"], 0)
        peer = PeerEndpoint(
            manifest_bytes=manifest_bytes,
            test_credentials=credentials,
            entropy_source=lambda n: bytes((entropy_seed + index) & 0xFF for index in range(n)),
            test_services={},
        )
        _activate_pair(c_endpoint, peer, clock)
        self.assertEqual(
            c_endpoint.last_state.effective_config["pin_commits"],
            1 if manifest["security"]["mode"] == "XX" else 0,
        )
        return c_endpoint, peer, clock

    def open_xx_through_noise_confirmation(
        self, *, wrong_remote_pin: bool = False
    ) -> tuple[_CProcess, PeerEndpoint, _Clock, list[bytes]]:
        manifest_name = "direct-xx.json"
        manifest_path = _ROOT / "profiles" / "deployments" / manifest_name
        manifest_bytes = manifest_path.read_bytes()
        profile_hash = hashlib.sha256(manifest_bytes).digest()
        digest_index = json.loads(
            (_ROOT / "profiles" / "deployments" / "digests.json").read_text()
        )
        self.assertEqual(profile_hash.hex(), digest_index["manifests"][manifest_name])

        from cryptography.hazmat.primitives.asymmetric import x25519

        c_static = b"\x10" * 32
        peer_static = b"\x20" * 32
        wrong_static = b"\x30" * 32

        def public_key(private_key: bytes) -> bytes:
            return x25519.X25519PrivateKey.from_private_bytes(
                private_key
            ).public_key().public_bytes_raw()

        expected_pin = public_key(wrong_static if wrong_remote_pin else peer_static)
        c_endpoint = _CProcess(
            self.executable,
            profile_hash,
            c_static,
            mode=2,
            expected_remote_pin=expected_pin,
        )
        self.addCleanup(c_endpoint.close)
        _assert_effective_profile(self, c_endpoint.initial, manifest_bytes)
        peer = PeerEndpoint(
            manifest_bytes=manifest_bytes,
            test_credentials={
                "node_id": 10,
                "static_private_key": peer_static,
                "peer_static_public_key": public_key(c_static),
            },
            entropy_source=lambda size: bytes((0xA7 + index) & 0xFF for index in range(size)),
            test_services={},
        )
        clock = _Clock()
        peer_sync, _ = _settle(
            peer,
            peer.handle(
                Open(
                    link=0,
                    deadline_capability="strict_latest_start",
                    at_ms=clock.next(),
                )
            ),
            clock,
        )
        self.assertEqual(peer_sync, [b"\x00"])
        self.assertEqual(c_endpoint.receive(peer_sync[0], clock.next()).status, 0)
        self.assertEqual(
            peer.handle(
                Receive(link=0, bytes=c_endpoint.initial.frames[0], at_ms=clock.next())
            ),
            (),
        )
        first_flight, _ = _settle(
            peer, peer.initiate_handshake(at_ms=clock.next()), clock
        )
        self.assertEqual(len(first_flight), 1)
        c_response = c_endpoint.receive(first_flight[0], clock.next())
        self.assertEqual(c_response.status, 0)
        self.assertEqual(len(c_response.frames), 1)
        peer_confirmation, _ = _settle(
            peer,
            peer.handle(
                Receive(link=0, bytes=c_response.frames[0], at_ms=clock.next())
            ),
            clock,
        )
        self.assertEqual(len(peer_confirmation), 2)
        return c_endpoint, peer, clock, peer_confirmation

    def test_c_endpoint_produces_sample1_accepted_by_python_peer(self) -> None:
        c_endpoint, peer, clock = self.open_pair(
            b"\x04" * 32,
            0x91,
            manifest_name=_SAMPLE20_MANIFEST_NAME,
        )
        self.assertEqual(peer.sample_producer_node, 20)
        self.assertEqual(peer.local_node_id, 10)
        self.assertIsNotNone(peer.sample_consumer)

        # Synchronize the independent consumer on a real, correlated READ result
        # over this fresh association before testing live producer telemetry.
        read_events = peer.handle(
            ApplicationRequest(
                service_id=1,
                payload=b"\x01",
                at_ms=clock.next(),
                exchange_id=0x2304,
            )
        )
        read_frames, _ = _settle(peer, read_events, clock)
        _pump(c_endpoint, peer, [], clock, initial_peer_frames=read_frames)
        self.assertTrue(c_endpoint.last_state.pending)
        snapshot = Sample(epoch=0x1122334455667788, index=1, value=2468)
        completed = c_endpoint.complete_sample(snapshot.encode_read_result(), clock.next())
        self.assertEqual(completed.status, 0)
        read_events = _pump(c_endpoint, peer, completed.frames, clock)
        self.assertTrue(
            any(
                isinstance(event, ApplicationEvent)
                and event.kind == "request_result"
                and event.service_id == 1
                and event.exchange_id == 0x2304
                and event.status == 0
                and event.payload == snapshot.encode_read_result()
                for event in read_events
            )
        )
        self.assertEqual(peer.sample_consumer.cached_sample, snapshot)
        self.assertTrue(peer.sample_consumer.is_live)

        produced = Sample(epoch=snapshot.epoch, index=2, value=12345)
        state = c_endpoint.submit_telem(1, produced.encode_telemetry(), clock.next())
        self.assertEqual(state.status, 0)
        _pump(c_endpoint, peer, state.frames, clock)
        self.assertEqual(peer.sample_consumer.cached_sample, produced)
        self.assertTrue(peer.sample_consumer.is_live)
        opaque_data = bytes((index * 19 + 7) & 0xFF for index in range(1024))
        data_state = c_endpoint.submit_data(2, opaque_data, clock.next())
        self.assertEqual(data_state.status, 0)
        data_events = _submit_c_data_until_peer_accepts(
            c_endpoint, peer, data_state, clock, 2, opaque_data
        )
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == 2
            and event.payload == opaque_data
            for event in data_events
        ))

    def test_sample_and_large_request_result_from_c_to_peer(self) -> None:
        for profile, seed in (("direct-nnpsk0.json", 0x31), ("direct-xx.json", 0x41)):
            with self.subTest(profile=profile):
                c_endpoint, peer, clock = self.open_pair(
                    b"\x01" * 32, seed, manifest_name=profile
                )

                published = peer.handle(PublishSample(value=12345, at_ms=clock.next()))
                sample_wires, _ = _settle(peer, published, clock)
                _pump(c_endpoint, peer, [], clock, initial_peer_frames=sample_wires)
                self.assertGreaterEqual(c_endpoint.last_state.telemetry, 1)

                request = c_endpoint.submit_req(1, b"\x01", clock.next())
                self.assertEqual(request.status, 0)
                _pump(c_endpoint, peer, request.frames, clock)
                self.assertEqual(c_endpoint.last_state.results, 1)
                sample = Sample.decode_read_result(c_endpoint.last_state.result)
                self.assertEqual(sample.value, 12345)

                c_request = bytes((index * 11 + 5) & 0xFF for index in range(1024))
                state = c_endpoint.submit_req(2, c_request, clock.next())
                self.assertEqual(state.status, 0)
                peer_events: list[Any] = []
                for _ in range(64):
                    peer_events.extend(_pump(c_endpoint, peer, state.frames, clock))
                    if c_endpoint.last_state.results >= 2:
                        break
                    state = c_endpoint.poll(clock.advance(21))
                    self.assertEqual(state.status, 0)
                self.assertEqual(
                    c_endpoint.last_state.results,
                    2,
                    f"large C REQ did not complete: endpoint_status={c_endpoint.last_state.endpoint_status}, "
                    f"result_bytes={len(c_endpoint.last_state.result)}, peer_events={peer_events!r}",
                )
                self.assertEqual(c_endpoint.last_state.result, bytes((index % 256) ^ 0xA5 for index in range(1024)))
                self.assertTrue(
                    any(
                        isinstance(event, ApplicationEvent)
                        and event.kind == "request_accepted"
                        and event.service_id == 2
                        and event.payload == c_request
                        for event in peer_events
                    )
                )

    def test_fragmented_data_in_both_directions(self) -> None:
        for profile, seed in (("direct-nnpsk0.json", 0x71), ("direct-xx.json", 0x91)):
            with self.subTest(profile=profile):
                c_endpoint, peer, clock = self.open_pair(
                    b"\x03" * 32, seed, manifest_name=profile
                )

                c_data = bytes((index * 17 + 9) & 0xFF for index in range(1024))
                state = c_endpoint.submit_data(2, c_data, clock.next())
                self.assertEqual(state.status, 0)
                peer_events = _submit_c_data_until_peer_accepts(
                    c_endpoint, peer, state, clock, 2, c_data
                )
                self.assertTrue(
                    any(
                        isinstance(event, ApplicationEvent)
                        and event.kind == "request_accepted"
                        and event.service_id == 2
                        and event.payload == c_data
                        for event in peer_events
                    )
                )

                peer_data = bytes((index * 29 + 3) & 0xFF for index in range(1024))
                outgoing: list[Any] = []
                peer._queue_data_transfer(2, peer_data, ack_req=True, out=outgoing)
                peer_data_wires, _ = _settle(peer, outgoing, clock)
                _pump(c_endpoint, peer, [], clock, initial_peer_frames=peer_data_wires)
                self.assertEqual(c_endpoint.last_state.assembled, 1)
                self.assertEqual(c_endpoint.last_state.body, peer_data)

    def test_p03_direct_nnpsk0_and_xx_large_request_result(self) -> None:
        request_payload = bytes((index % 256) ^ 0x5A for index in range(1024))
        expected_result = bytes((index % 256) ^ 0xA5 for index in range(1024))
        for profile, seed in (("direct-nnpsk0.json", 0x61), ("direct-xx.json", 0x81)):
            with self.subTest(profile=profile):
                c_endpoint, peer, clock = self.open_pair(
                    b"\x5a" * 32, seed, manifest_name=profile
                )
                request = c_endpoint.submit_req(2, request_payload, clock.next())
                self.assertEqual(request.status, 0)
                peer_events: list[Any] = []
                for _ in range(64):
                    peer_events.extend(_pump(c_endpoint, peer, request.frames, clock))
                    if c_endpoint.last_state.results:
                        break
                    request = c_endpoint.poll(clock.advance(21))
                    self.assertEqual(request.status, 0)
                self.assertTrue(any(
                    isinstance(event, ApplicationEvent)
                    and event.kind == "request_accepted"
                    and event.service_id == 2
                    and event.payload == request_payload
                    for event in peer_events
                ))
                self.assertEqual(c_endpoint.last_state.results, 1)
                self.assertEqual(c_endpoint.last_state.result, expected_result)

    def test_xx_rejects_wrong_remote_pin_without_activation_or_application_traffic(self) -> None:
        c_endpoint, peer, clock, peer_confirmation = self.open_xx_through_noise_confirmation(
            wrong_remote_pin=True
        )
        self.assertFalse(c_endpoint.last_state.handshake_active)
        self.assertFalse(c_endpoint.last_state.bound)
        for frame in peer_confirmation:
            rejected = c_endpoint.receive(frame, clock.next())
            self.assertNotEqual(rejected.status, 0)
            self.assertFalse(rejected.frames)
        self.assertFalse(c_endpoint.last_state.handshake_active)
        self.assertFalse(c_endpoint.last_state.bound)
        self.assertEqual(c_endpoint.last_state.effective_config["pin_commits"], 0)
        self.assertIsNone(peer.association)
        attempted = c_endpoint.submit_req(1, b"\x01", clock.next())
        self.assertNotEqual(attempted.status, 0)
        self.assertFalse(attempted.frames)

    def test_xx_blocks_application_request_before_protected_confirmation(self) -> None:
        c_endpoint, peer, clock, peer_confirmation = self.open_xx_through_noise_confirmation()
        first = c_endpoint.receive(peer_confirmation[0], clock.next())
        self.assertEqual(first.status, 0)
        self.assertFalse(first.handshake_active)
        self.assertFalse(first.bound)
        self.assertFalse(first.frames)

        attempted = c_endpoint.submit_req(1, b"\x01", clock.next())
        self.assertNotEqual(attempted.status, 0)
        self.assertFalse(attempted.frames)
        self.assertFalse(attempted.handshake_active)
        self.assertIsNone(peer.association)

        confirmed = c_endpoint.receive(peer_confirmation[1], clock.next())
        self.assertEqual(confirmed.status, 0)
        self.assertTrue(confirmed.handshake_active)
        self.assertTrue(confirmed.bound)
        self.assertEqual(len(confirmed.frames), 1)
        _pump(c_endpoint, peer, confirmed.frames, clock)
        self.assertEqual(peer.association.status, "active")

    def test_manifest_failed_aead_limit_and_monotonic_association_expiry(self) -> None:
        c_endpoint, peer, clock = self.open_pair(
            b"\x17" * 32, 0x29, manifest_name="direct-nnpsk0.json"
        )
        sent = peer.handle(PublishSample(value=9876, at_ms=clock.next()))
        valid_wires, _ = _settle(peer, sent, clock)
        self.assertEqual(len(valid_wires), 1)
        decoder = StreamRDecoder(
            max_encoded=263, max_core=256, candidate_timeout_ms=26, await_sync=False
        )
        decoded = [event.frame for event in decoder.feed(valid_wires[0], at_ms=clock.next()) if event.kind == "frame"]
        self.assertEqual(len(decoded), 1)
        assert decoded[0] is not None
        tampered_core = bytearray(decoded[0])
        self.assertGreater(len(tampered_core), 17)
        tampered_core[-17] ^= 0x01
        tampered_wire = encode_stream_r(bytes(tampered_core), max_core=256, max_encoded=263)
        for _ in range(1000):
            result = c_endpoint.receive(tampered_wire, clock.next())
            self.assertNotEqual(result.status, 0)
            self.assertFalse(result.frames)
        self.assertFalse(c_endpoint.last_state.handshake_active)
        self.assertEqual(c_endpoint.last_state.telemetry, 0)
        rejected = c_endpoint.receive(valid_wires[0], clock.next())
        self.assertNotEqual(rejected.status, 0)
        self.assertEqual(c_endpoint.last_state.telemetry, 0)

        # A new exact-profile association verifies expiry on the same virtual
        # clock used by handshake, endpoint, wire callbacks and poll.
        c_endpoint, peer, clock = self.open_pair(
            b"\x18" * 32, 0x39, manifest_name="direct-nnpsk0.json"
        )
        expires_at = clock.now_ms + 100_000_000
        expired = c_endpoint.poll(expires_at)
        self.assertEqual(expired.status, 0)
        self.assertFalse(expired.handshake_active)
        clock.now_ms = expires_at
        attempted = c_endpoint.submit_req(1, b"\x01", clock.next())
        self.assertNotEqual(attempted.status, 0)
        self.assertFalse(attempted.frames)

    def test_large_request_result_from_peer_to_c(self) -> None:
        for profile, seed in (("direct-nnpsk0.json", 0x51), ("direct-xx.json", 0xA1)):
            with self.subTest(profile=profile):
                reverse_c, reverse_peer, reverse_clock = self.open_pair(
                    b"\x02" * 32, seed, manifest_name=profile
                )
                peer_request = bytes((index * 7 + 13) & 0xFF for index in range(1024))
                request_events = reverse_peer.handle(
                    ApplicationRequest(
                        service_id=2,
                        payload=peer_request,
                        at_ms=reverse_clock.next(),
                        exchange_id=0x2301,
                    )
                )
                peer_request_wires, _ = _settle(reverse_peer, request_events, reverse_clock)
                _pump(reverse_c, reverse_peer, [], reverse_clock, initial_peer_frames=peer_request_wires)
                for _ in range(64):
                    if reverse_c.last_state.pending:
                        break
                    advanced = reverse_peer.handle(Advance(now_ms=reverse_clock.advance(21)))
                    more_wires, _ = _settle(reverse_peer, advanced, reverse_clock)
                    _pump(reverse_c, reverse_peer, [], reverse_clock, initial_peer_frames=more_wires)
                self.assertTrue(reverse_c.last_state.pending)
                self.assertEqual(reverse_c.last_state.request_service, 2)
                self.assertEqual(reverse_c.last_state.request, peer_request)
                completed = reverse_c.complete(reverse_clock.next())
                self.assertEqual(completed.status, 0)
                reverse_events: list[Any] = []
                for _ in range(64):
                    reverse_events.extend(_pump(reverse_c, reverse_peer, completed.frames, reverse_clock))
                    if any(
                        isinstance(event, ApplicationEvent)
                        and event.kind == "request_result"
                        and event.exchange_id == 0x2301
                        for event in reverse_events
                    ):
                        break
                    completed = reverse_c.poll(reverse_clock.advance(21))
                    self.assertEqual(completed.status, 0)
                self.assertTrue(
                    any(
                        isinstance(event, ApplicationEvent)
                        and event.kind == "request_result"
                        and event.service_id == 2
                        and event.exchange_id == 0x2301
                        and event.payload == peer_request
                        for event in reverse_events
                    )
                )


if __name__ == "__main__":
    unittest.main()
