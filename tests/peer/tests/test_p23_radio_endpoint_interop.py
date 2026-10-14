"""P23 RADIO-1 interoperability through the real P21 transparent relays."""

from __future__ import annotations

import hashlib
import json
import os
from collections import deque
from pathlib import Path
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
)
from dmp_peer.frame import FrameError, crc32c, encode_uleb, parse_frame  # noqa: E402
from dmp_peer.relay import RelayDecision, TransparentRelay  # noqa: E402
from dmp_peer.stream_r import StreamRDecoder, encode_stream_r  # noqa: E402
from dmp_peer.testing import PeerEndpoint  # noqa: E402
from test_p23_c_endpoint_interop import (  # noqa: E402
    _CProcess,
    _Clock,
    _assert_effective_profile,
    _settle,
)


_ROOT = Path(__file__).parents[3]
_RADIO = "radio-nnpsk0.json"
_RETRY_ALL = "test-radio-retry-all-nnpsk0.json"
_RADIO_XX = "radio-xx.json"
_RETRY_ALL_XX = "test-radio-retry-all-xx.json"
_MANIFESTS = (_RADIO, _RETRY_ALL, _RADIO_XX, _RETRY_ALL_XX)
_MAX_CORE = 256
_MAX_ENCODED = 263
_PSK = b"\x29" * 32  # deterministic, test-only, never logged


def _ttl_offset(wire: bytes) -> int:
    return 3 + len(encode_uleb(parse_frame(wire, max_frame=_MAX_CORE).sequence))


def _assert_ttl_only(test: unittest.TestCase, original: bytes, forwarded: bytes) -> None:
    before = parse_frame(original, max_frame=_MAX_CORE)
    after = parse_frame(forwarded, max_frame=_MAX_CORE)
    test.assertIsNotNone(before.route)
    test.assertIsNotNone(after.route)
    assert before.route is not None and after.route is not None
    test.assertEqual(after.route.ttl, before.route.ttl - 1)
    expected = bytearray(original)
    offset = _ttl_offset(original)
    expected[offset] = ((before.route.ttl - 1) << 4) | (expected[offset] & 0x0F)
    if before.integrity is not None:
        expected[-4:] = crc32c(bytes(expected[:-4])).to_bytes(4, "little")
    test.assertEqual(forwarded, bytes(expected))


def _decode_c_stream_frame(encoded: bytes) -> bytes:
    # The C endpoint emits Core frames directly for RADIO-1's packet binding;
    # DIRECT-1's Stream R endpoint still emits an encoded frame.
    try:
        parse_frame(encoded, max_frame=_MAX_CORE)
    except FrameError:
        pass
    else:
        return encoded
    decoder = StreamRDecoder(
        max_encoded=_MAX_ENCODED,
        max_core=_MAX_CORE,
        candidate_timeout_ms=26,
        await_sync=True,
    )
    events = decoder.feed(encoded, at_ms=1)
    frames = [event.frame for event in events if event.kind == "frame"]
    if len(frames) != 1 or frames[0] is None:
        raise AssertionError(f"C process did not emit one complete Stream R frame: {events!r}")
    return frames[0]


def _frame_summary(frames: list[bytes]) -> list[tuple[int, int, int | None]]:
    summary = []
    for wire in frames:
        frame = parse_frame(wire, max_frame=_MAX_CORE)
        summary.append((
            frame.message_type,
            frame.sequence,
            frame.fragment.index if frame.fragment is not None else None,
        ))
    return summary


@unittest.skipUnless(
    os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
    "C P23 endpoint executable is not configured",
)
class TestP23RadioEndpointInterop(unittest.TestCase):
    def setUp(self) -> None:
        self.executable = os.environ["DMP_P23_ENDPOINT_SEC_EXE"]
        self.digest_index = json.loads(
            (_ROOT / "profiles" / "deployments" / "digests.json").read_text()
        )["manifests"]

    def _open_pair(
        self, manifest_name: str, entropy_seed: int, *, async_tx_completion: bool = False
    ):
        manifest_bytes = (_ROOT / "profiles" / "deployments" / manifest_name).read_bytes()
        digest = hashlib.sha256(manifest_bytes).digest()
        self.assertEqual(digest.hex(), self.digest_index[manifest_name])
        manifest = json.loads(manifest_bytes)
        if manifest["security"]["mode"] == "XX":
            from cryptography.hazmat.primitives.asymmetric import x25519

            peer_static = b"\x20" * 32
            c_static = b"\x10" * 32
            c_public = x25519.X25519PrivateKey.from_private_bytes(c_static).public_key().public_bytes_raw()
            peer_public = x25519.X25519PrivateKey.from_private_bytes(peer_static).public_key().public_bytes_raw()
            c_endpoint = _CProcess(
                self.executable,
                digest,
                c_static,
                mode=2,
                expected_remote_pin=peer_public,
                async_tx_completion=async_tx_completion,
            )
            credentials = {
                "node_id": 10,
                "static_private_key": peer_static,
                "peer_static_public_key": c_public,
            }
        else:
            c_endpoint = _CProcess(
                self.executable, digest, _PSK,
                async_tx_completion=async_tx_completion,
            )
            credentials = {"node_id": 10, "psk": _PSK, "key_hint": 5}
        self.addCleanup(c_endpoint.close)
        _assert_effective_profile(self, c_endpoint.initial, manifest_bytes)
        self.assertEqual(c_endpoint.initial.effective_config["pin_commits"], 0)
        peer = PeerEndpoint(
            manifest_bytes=manifest_bytes,
            test_credentials=credentials,
            entropy_source=lambda size: bytes((entropy_seed + i) & 0xFF for i in range(size)),
            test_services={},
        )
        self.assertEqual(peer.manifest.sha256, digest.hex())
        self.assertEqual(peer.local_node_id, 10)
        self.assertEqual(peer.remote_node_id, 20)
        relays = {node: TransparentRelay(manifest_bytes, node) for node in (30, 40)}
        self.assertEqual({relay.cache_slots for relay in relays.values()}, {192})
        self.assertEqual(c_endpoint.initial.frames, [b"\x00"])
        return c_endpoint, peer, relays, _Clock()

    def _route(
        self, relays, frame: bytes, *, source: int, clock: _Clock, metrics=None
    ) -> bytes:
        path = (30, 40) if source == 10 else (40, 30)
        current = frame
        for node in path:
            at_ms = clock.next()
            relay = relays[node]
            decision: RelayDecision = relay.receive(current, at_ms)
            self.assertTrue(decision.forwarded, (node, decision.reason))
            assert decision.frame is not None
            _assert_ttl_only(self, current, decision.frame)
            relay.complete(decision.token, at_ms + 1, transmitted=True)
            if metrics is not None:
                metrics.relay_tx(node, decision.frame, parse_frame(decision.frame, max_frame=_MAX_CORE))
            current = decision.frame
            clock.now_ms = max(clock.now_ms, at_ms + 1)
            self.assertLessEqual(len(relay._entries), relay.cache_slots)
            self.assertTrue(all(value >= 0 for value in relay._pending_airtime.values()))
            self.assertGreaterEqual(relay._pending_global, 0)
        self.assertEqual(parse_frame(current, max_frame=_MAX_CORE).route.ttl, 0)
        return current

    def _peer_send(self, peer: PeerEndpoint, events, clock: _Clock) -> list[bytes]:
        frames, _ = _settle(peer, list(events), clock)
        return frames

    def _dispatch(
        self,
        c_endpoint: _CProcess,
        peer: PeerEndpoint,
        relays,
        source: int,
        frames: list[bytes],
        clock: _Clock,
        *,
        drop: set[tuple[int, int]] | None = None,
        drop_c_types: set[int] | None = None,
        dropped_c: list[bytes] | None = None,
        observed: list[Any] | None = None,
        metrics=None,
    ) -> tuple[list[bytes], list[int]]:
        """Route serialized endpoint frames; return generated peer frames and C frames."""
        pending = deque((source, frame) for frame in frames)
        peer_out: list[bytes] = []
        c_out: list[int] = []
        while pending:
            side, frame = pending.popleft()
            if side == 20:
                try:
                    parse_frame(frame, max_frame=_MAX_CORE)
                except FrameError:
                    frame = _decode_c_stream_frame(frame)
            parsed = parse_frame(frame, max_frame=_MAX_CORE)
            if metrics is not None:
                metrics.endpoint_tx(side, frame, parsed)
            if drop is not None and side == 10 and parsed.fragment is not None:
                marker = (parsed.sequence, parsed.fragment.index)
                if marker in drop:
                    drop.remove(marker)
                    if metrics is not None:
                        metrics.dropped(side, parsed.fragment.index)
                    continue
            forwarded = self._route(
                relays, frame, source=side, clock=clock, metrics=metrics
            )
            at_ms = clock.next()
            if side == 10:
                state = c_endpoint.receive(
                    encode_stream_r(forwarded, max_core=_MAX_CORE, max_encoded=_MAX_ENCODED),
                    at_ms,
                )
                self.assertEqual(
                    state.status,
                    0,
                    (state.endpoint_status, state.rx_status, parsed.message_type,
                     parsed.fragment.index if parsed.fragment else None),
                )
                c_frames = [
                    _decode_c_stream_frame(wire)
                    for wire in state.frames
                    if wire != b"\x00"
                ]
                if drop_c_types is not None:
                    kept = []
                    for c_frame in c_frames:
                        if parse_frame(c_frame, max_frame=_MAX_CORE).message_type in drop_c_types:
                            drop_c_types.remove(
                                parse_frame(c_frame, max_frame=_MAX_CORE).message_type
                            )
                            if dropped_c is not None:
                                dropped_c.append(c_frame)
                        else:
                            kept.append(c_frame)
                    c_frames = kept
                c_out.extend(
                    parse_frame(wire, max_frame=_MAX_CORE).fragment.index
                    for wire in c_frames
                    if parse_frame(wire, max_frame=_MAX_CORE).fragment is not None
                )
                pending.extend((20, wire) for wire in c_frames)
            else:
                events = peer.handle(Receive(link=0, bytes=forwarded, at_ms=at_ms))
                if observed is not None:
                    observed.extend(event for event in events if isinstance(event, ApplicationEvent))
                peer_frames = self._peer_send(peer, events, clock)
                peer_out.extend(peer_frames)
                pending.extend((10, wire) for wire in peer_frames)
        return peer_out, c_out

    def _start_peer_data_transfer(self, entropy_seed: int, payload: bytes):
        """Start a protected Python-to-C service-2 DATA transfer on RADIO-1."""
        c_endpoint, peer, relays, clock = self._open_pair(_RADIO, entropy_seed)
        self._activate(c_endpoint, peer, relays, clock)
        self._grant_freshness(c_endpoint, peer, relays, clock)
        outgoing: list[Any] = []
        sequence = peer._queue_data_transfer(2, payload, ack_req=True, out=outgoing)
        frames = self._peer_send(peer, outgoing, clock)
        parsed = [parse_frame(frame, max_frame=_MAX_CORE) for frame in frames]
        self.assertEqual(len(parsed), 8)
        self.assertEqual([frame.fragment.index for frame in parsed], list(range(8)))
        self.assertTrue(all(frame.security is not None and frame.route is not None for frame in parsed))
        self.assertTrue(all(6 in {ext.extension_id for ext in frame.extensions} for frame in parsed))
        self.assertTrue(all(frame.sequence == sequence for frame in parsed))
        return c_endpoint, peer, relays, clock, sequence, frames

    def _advance_data_recovery(
        self, c_endpoint, peer, relays, clock, *, drop_c_types=None, dropped_c=None,
        drop_peer=None, observed=None, deadline_ms=12_000,
    ):
        """Advance both real endpoints and route their protected recovery frames."""
        repairs: list[int] = []
        statuses: list[bytes] = []
        terminal_deadline = clock.now_ms + deadline_ms
        initial_accepts = c_endpoint.last_state.accepts
        while clock.now_ms < terminal_deadline and c_endpoint.last_state.accepts == initial_accepts:
            now = clock.advance(64)
            peer_frames = self._peer_send(peer, peer.handle(Advance(now_ms=now)), clock)
            if peer_frames:
                repairs.extend(
                    parse_frame(frame, max_frame=_MAX_CORE).fragment.index
                    for frame in peer_frames
                    if parse_frame(frame, max_frame=_MAX_CORE).fragment is not None
                    and parse_frame(frame, max_frame=_MAX_CORE).message_type == 7
                )
                self._dispatch(
                    c_endpoint, peer, relays, 10, peer_frames, clock,
                    drop=drop_peer,
                    observed=observed,
                )
            state = c_endpoint.poll(clock.next())
            self.assertEqual(state.status, 0, (state.endpoint_status, state.rx_status))
            c_frames = [
                _decode_c_stream_frame(wire) for wire in state.frames if wire != b"\x00"
            ]
            statuses.extend(
                frame for frame in c_frames
                if parse_frame(frame, max_frame=_MAX_CORE).message_type == 8
            )
            routed_c_frames = []
            for wire, c_frame in zip(
                (wire for wire in state.frames if wire != b"\x00"), c_frames
            ):
                message_type = parse_frame(c_frame, max_frame=_MAX_CORE).message_type
                if drop_c_types is not None and message_type in drop_c_types:
                    drop_c_types.remove(message_type)
                    if dropped_c is not None:
                        dropped_c.append(c_frame)
                else:
                    routed_c_frames.append(wire)
            if routed_c_frames:
                peer_out, _ = self._dispatch(
                    c_endpoint, peer, relays, 20, routed_c_frames, clock,
                    drop=drop_peer,
                    observed=observed,
                )
                repairs.extend(
                    parse_frame(frame, max_frame=_MAX_CORE).fragment.index
                    for frame in peer_out
                    if parse_frame(frame, max_frame=_MAX_CORE).fragment is not None
                    and parse_frame(frame, max_frame=_MAX_CORE).message_type == 7
                )
        return repairs, statuses

    def _deliver_c_data_until_peer_accepts(
        self, c_endpoint, peer, relays, clock, initial_frames, observed, payload
    ) -> None:
        frames = initial_frames
        deadline = clock.now_ms + 20_000
        while clock.now_ms < deadline:
            if frames:
                self._dispatch(
                    c_endpoint, peer, relays, 20, frames, clock, observed=observed
                )
            if any(
                isinstance(event, ApplicationEvent)
                and event.kind == "request_accepted"
                and event.service_id == 2
                and event.payload == payload
                for event in observed
            ):
                return
            state = c_endpoint.poll(clock.advance(64))
            self.assertEqual(state.status, 0, (state.endpoint_status, state.rx_status))
            frames = state.frames
        self.fail(f"routed C DATA was not accepted: observed={observed!r}")

    def _activate(self, c_endpoint, peer, relays, clock, *, metrics=None) -> None:
        peer.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=clock.next()))
        # The Python node uses packet binding, while this C process seam keeps
        # a Stream R adapter around its endpoint. Seed that adapter's receive
        # decoder once before packet frames are wrapped for the C process.
        sync = c_endpoint.receive(b"\x00", clock.next())
        self.assertEqual(sync.status, 0)
        first = self._peer_send(peer, peer.initiate_handshake(at_ms=clock.next()), clock)
        self.assertEqual(len(first), 1)
        self.assertIsNotNone(parse_frame(first[0], max_frame=_MAX_CORE).route)
        self._dispatch(c_endpoint, peer, relays, 10, first, clock, metrics=metrics)
        self.assertTrue(c_endpoint.last_state.handshake_active)
        self.assertTrue(c_endpoint.last_state.bound)
        self.assertIsNotNone(peer.association)
        self.assertEqual(peer.association.status, "active")
        self.assertEqual(
            c_endpoint.last_state.effective_config["pin_commits"],
            1 if peer.sec_mode_str == "XX" else 0,
        )

    def _exercise_sample_and_fragmented_data(self, c_endpoint, peer, relays, clock) -> None:
        sample_events = peer.handle(PublishSample(value=4321, at_ms=clock.next()))
        sample_frames = self._peer_send(peer, sample_events, clock)
        self.assertEqual(len(sample_frames), 1)
        routed_events: list[Any] = []
        self._dispatch(c_endpoint, peer, relays, 10, sample_frames, clock, observed=routed_events)
        self.assertGreaterEqual(c_endpoint.last_state.telemetry, 1)

        read = c_endpoint.submit_req(1, b"\x01", clock.next())
        self.assertEqual(read.status, 0)
        self._dispatch(c_endpoint, peer, relays, 20, read.frames, clock, observed=routed_events)
        self.assertGreaterEqual(c_endpoint.last_state.results, 1)
        self.assertEqual(len(c_endpoint.last_state.result), 17)
        self.assertEqual(c_endpoint.last_state.result[-4:], (4321).to_bytes(4, "little"))

        initial_results = c_endpoint.last_state.results
        grant = c_endpoint.submit_req(
            0,
            b"\x10" + (12_000).to_bytes(4, "little"),
            clock.next(),
        )
        self.assertEqual(grant.status, 0)
        self.assertEqual(len(grant.frames), 1)
        grant_events: list[Any] = []
        self._dispatch(
            c_endpoint, peer, relays, 20, grant.frames, clock, observed=grant_events
        )
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == 0
            for event in grant_events
        ))
        self.assertEqual(c_endpoint.last_state.result[:1], b"\x11")
        self.assertEqual(len(c_endpoint.last_state.result), 21)
        self.assertEqual(c_endpoint.last_state.results, initial_results + 1)
        data_token = c_endpoint.last_state.result[1:17]
        self.assertGreater(int.from_bytes(c_endpoint.last_state.result[17:21], "little"), 0)

        c_data = bytes((index * 19 + 3) & 0xFF for index in range(1024))
        data = c_endpoint.submit_data_fresh(2, c_data, data_token, clock.next())
        self.assertEqual(data.status, 0)
        self._deliver_c_data_until_peer_accepts(
            c_endpoint, peer, relays, clock, data.frames, routed_events, c_data
        )

        # Each direction needs its own S7 grant. The C-to-peer grant above
        # cannot authorize DATA sent by the independent peer.
        self._grant_freshness(c_endpoint, peer, relays, clock)

        peer_data = bytes((index * 23 + 11) & 0xFF for index in range(1024))
        outgoing: list[Any] = []
        peer._queue_data_transfer(2, peer_data, ack_req=True, out=outgoing)
        peer_frames = self._peer_send(peer, outgoing, clock)
        self.assertEqual(len(peer_frames), 32)
        self.assertTrue(all(
            6 in {extension.extension_id for extension in parse_frame(frame).extensions}
            for frame in peer_frames
        ), "peer-to-C DATA fragments must carry the issued S7 freshness token")
        self._dispatch(c_endpoint, peer, relays, 10, peer_frames, clock)
        self.assertEqual(c_endpoint.last_state.assembled, 1)
        self.assertEqual(c_endpoint.last_state.body, peer_data)

    def _grant_freshness(self, c_endpoint, peer, relays, clock, *, metrics=None) -> None:
        request = self._peer_send(
            peer,
            peer.handle(ApplicationRequest(
                service_id=0,
                payload=b"\x10" + (12_000).to_bytes(4, "little"),
                ack_req=True,
                at_ms=clock.next(),
            )),
            clock,
        )
        self.assertEqual(len(request), 1)
        self.assertEqual(parse_frame(request[0]).message_type, 0)
        self.assertIsNotNone(parse_frame(request[0]).security)
        self.assertIsNotNone(parse_frame(request[0]).route)
        observed: list[Any] = []
        self._dispatch(
            c_endpoint, peer, relays, 10, request, clock, observed=observed,
            metrics=metrics,
        )
        if metrics is not None:
            metrics.observe_application(observed)
        self.assertIsNotNone(peer.active_freshness_token)
        self.assertTrue(c_endpoint.last_state.bound)

    def _issue_freshness(self, c_endpoint, peer, relays, clock, lifetime_ms: int):
        """Issue a real service-0 grant and retain its C-side expiry instant."""
        request = self._peer_send(
            peer,
            peer.handle(ApplicationRequest(
                service_id=0,
                payload=b"\x10" + lifetime_ms.to_bytes(4, "little"),
                ack_req=True,
                at_ms=clock.next(),
            )),
            clock,
        )
        self.assertEqual(len(request), 1)
        forwarded = self._route(relays, request[0], source=10, clock=clock)
        issued_at_ms = clock.next()
        state = c_endpoint.receive(
            encode_stream_r(forwarded, max_core=_MAX_CORE, max_encoded=_MAX_ENCODED),
            issued_at_ms,
        )
        self.assertEqual(state.status, 0, (state.endpoint_status, state.rx_status))
        c_frames = [
            _decode_c_stream_frame(wire)
            for wire in state.frames
            if wire != b"\x00"
        ]
        observed: list[Any] = []
        self._dispatch(c_endpoint, peer, relays, 20, c_frames, clock, observed=observed)
        grant_events = [
            event for event in observed
            if isinstance(event, ApplicationEvent)
            and event.kind == "request_result"
            and event.service_id == 0
            and event.status == 0
        ]
        self.assertEqual(len(grant_events), 1, repr(observed))
        grant = grant_events[0].payload
        self.assertEqual(len(grant), 21)
        self.assertEqual(grant[0], 0x11)
        token = grant[1:17]
        granted_ms = int.from_bytes(grant[17:21], "little")
        self.assertEqual(granted_ms, lifetime_ms)
        self.assertEqual(peer.active_freshness_token, token)
        return token, issued_at_ms + granted_ms

    def _send_peer_data_frame_to_c(self, c_endpoint, peer, relays, clock, frame):
        forwarded = self._route(relays, frame, source=10, clock=clock)
        state = c_endpoint.receive(
            encode_stream_r(forwarded, max_core=_MAX_CORE, max_encoded=_MAX_ENCODED),
            clock.next(),
        )
        self.assertEqual(state.status, 0, (state.endpoint_status, state.rx_status))
        c_frames = [
            _decode_c_stream_frame(wire)
            for wire in state.frames
            if wire != b"\x00"
        ]
        observed: list[Any] = []
        if c_frames:
            self._dispatch(
                c_endpoint, peer, relays, 20, c_frames, clock, observed=observed
            )
        return c_endpoint.last_state, observed

    def _assert_no_data_dispatch(self, c_endpoint, peer, before, observed):
        self.assertEqual(c_endpoint.last_state.accepts, before.accepts)
        self.assertEqual(c_endpoint.last_state.assembled, before.assembled)
        self.assertEqual(c_endpoint.last_state.request, before.request)
        self.assertEqual(c_endpoint.last_state.body, before.body)
        self.assertEqual(c_endpoint.last_state.request_service, before.request_service)
        self.assertFalse(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == 2
            for event in observed
        ), f"rejected DATA was dispatched: {observed!r}")
        self.assertTrue(c_endpoint.last_state.bound)
        self.assertTrue(peer.association is not None and peer.association.status == "active")

    def _exercise_radio_freshness_rejections(self, manifest_name: str, entropy_seed: int):
        # One association has a two-request grant budget. Missing-token DATA
        # uses no grant; the wrong and expired token cases use one each.
        c_endpoint, peer, relays, clock = self._open_pair(manifest_name, entropy_seed)
        self._activate(c_endpoint, peer, relays, clock)
        payload = b"rejected-single-fragment"
        before = c_endpoint.last_state
        missing = peer._build_data_frames(2, 0x2A01, payload)[0]
        self.assertNotIn(6, {ext.extension_id for ext in parse_frame(missing).extensions})
        state, observed = self._send_peer_data_frame_to_c(
            c_endpoint, peer, relays, clock, missing
        )
        self._assert_no_data_dispatch(c_endpoint, peer, before, observed)

        wrong_token, _ = self._issue_freshness(
            c_endpoint, peer, relays, clock, lifetime_ms=1000
        )
        before = c_endpoint.last_state
        wrong = bytes((wrong_token[0] ^ 0x80,)) + wrong_token[1:]
        wrong_frame = peer._build_data_frames(
            2, 0x2A02, payload, freshness_token=wrong
        )[0]
        parsed_wrong = parse_frame(wrong_frame)
        self.assertEqual(parsed_wrong.extensions[-1].extension_id, 6)
        self.assertEqual(parsed_wrong.extensions[-1].value, wrong)
        self.assertIsNotNone(parsed_wrong.security)
        state, observed = self._send_peer_data_frame_to_c(
            c_endpoint, peer, relays, clock, wrong_frame
        )
        self._assert_no_data_dispatch(c_endpoint, peer, before, observed)

        token, expiry_ms = self._issue_freshness(
            c_endpoint, peer, relays, clock, lifetime_ms=1000
        )
        if clock.now_ms < expiry_ms:
            clock.advance(expiry_ms - clock.now_ms)
        before = c_endpoint.last_state
        expired_frame = peer._build_data_frames(
            2, 0x2A03, payload, freshness_token=token
        )[0]
        state, observed = self._send_peer_data_frame_to_c(
            c_endpoint, peer, relays, clock, expired_frame
        )
        self._assert_no_data_dispatch(c_endpoint, peer, before, observed)
        c_endpoint.close()

        # A fresh association isolates the final-fragment expiry case and its
        # one-grant budget. Fragment zero is admitted before the real lease
        # deadline; fragment one reaches C after that deadline.
        c_endpoint, peer, relays, clock = self._open_pair(
            manifest_name, entropy_seed ^ 0x40
        )
        self._activate(c_endpoint, peer, relays, clock)
        token, expiry_ms = self._issue_freshness(
            c_endpoint, peer, relays, clock, lifetime_ms=200
        )
        initial = c_endpoint.last_state
        fragmented = peer._build_data_frames(
            2, 0x2A04, bytes(range(33)), freshness_token=token
        )
        self.assertEqual(len(fragmented), 2)
        first_fragment, final_fragment = (
            parse_frame(frame, max_frame=_MAX_CORE) for frame in fragmented
        )
        self.assertEqual(first_fragment.fragment.index, 0)
        self.assertEqual(final_fragment.fragment.index, 1)
        self.assertEqual(first_fragment.sequence, final_fragment.sequence)
        self.assertEqual(
            [frame.extensions[-1].value for frame in (first_fragment, final_fragment)],
            [token, token],
        )
        first_state, first_observed = self._send_peer_data_frame_to_c(
            c_endpoint, peer, relays, clock, fragmented[0]
        )
        self.assertEqual(first_state.rx_status, 7)  # DMP_INCOMPLETE: one fragment retained.
        self.assertEqual(first_state.accepts, initial.accepts)
        self.assertEqual(first_state.assembled, initial.assembled)
        self.assertFalse(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in first_observed
        ))
        self.assertLess(clock.now_ms, expiry_ms)
        clock.advance(expiry_ms - clock.now_ms)
        before_final = c_endpoint.last_state
        final_state, final_observed = self._send_peer_data_frame_to_c(
            c_endpoint, peer, relays, clock, fragmented[1]
        )
        self.assertEqual(final_state.rx_status, 0)
        self._assert_no_data_dispatch(c_endpoint, peer, before_final, final_observed)

        # The rejected final fragment leaves no accepted logical request; the
        # already-open assembly expires under its manifest deadline.
        timeout_ms = int(peer.manifest.values["timing"]["collect_ms"])
        expired_assembly = c_endpoint.poll(clock.advance(timeout_ms + 1))
        self.assertEqual(expired_assembly.status, 0)
        self.assertFalse(expired_assembly.fragment_live)
        self.assertEqual(expired_assembly.accepts, initial.accepts)
        self.assertEqual(expired_assembly.assembled, initial.assembled)
        self.assertEqual(expired_assembly.request, initial.request)
        self.assertEqual(expired_assembly.body, initial.body)
        self.assertEqual(expired_assembly.request_service, initial.request_service)
        self.assertTrue(expired_assembly.bound)
        self.assertTrue(peer.association is not None and peer.association.status == "active")
        c_endpoint.close()

    def _exercise_c_freshness_requester(self, c_endpoint, peer, relays, clock) -> None:
        initial_results = c_endpoint.last_state.results
        grant = c_endpoint.submit_req(
            0,
            b"\x10" + (12_000).to_bytes(4, "little"),
            clock.next(),
        )
        self.assertEqual(grant.status, 0)
        self.assertEqual(len(grant.frames), 1)
        grant_events: list[Any] = []
        peer_frames, c_fragments = self._dispatch(
            c_endpoint, peer, relays, 20, grant.frames, clock, observed=grant_events
        )
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == 0
            for event in grant_events
        ))
        self.assertEqual(
            c_endpoint.last_state.result[:1], b"\x11",
            (c_endpoint.last_state.results, len(c_endpoint.last_state.result),
             [(parse_frame(frame).message_type, parse_frame(frame).sequence,
               len(parse_frame(frame).payload)) for frame in peer_frames],
             c_fragments, [event.kind for event in grant_events]),
        )
        self.assertEqual(len(c_endpoint.last_state.result), 21)
        self.assertEqual(c_endpoint.last_state.results, initial_results + 1)
        token = c_endpoint.last_state.result[1:17]
        granted_ms = int.from_bytes(c_endpoint.last_state.result[17:21], "little")
        self.assertGreater(granted_ms, 0)

        request_payload = bytes((index * 13 + 11) & 0xFF for index in range(1024))
        request = c_endpoint.submit_req_fresh(2, request_payload, token, clock.next())
        self.assertEqual(request.status, 0)
        self.assertGreater(len(request.frames), 1)
        request_parts = [
            parse_frame(_decode_c_stream_frame(wire), max_frame=_MAX_CORE)
            for wire in request.frames
        ]
        self.assertTrue(all(part.fragment is not None for part in request_parts))
        self.assertTrue(all(
            6 in {extension.extension_id for extension in part.extensions}
            for part in request_parts
        ), "service-2 request fragments must carry the issued S7 freshness token")
        request_events: list[Any] = []
        self._dispatch(
            c_endpoint, peer, relays, 20, request.frames, clock, observed=request_events
        )
        deadline = clock.now_ms + 11_000
        while clock.now_ms < deadline and c_endpoint.last_state.results < 2:
            now = clock.advance(64)
            peer_frames = self._peer_send(peer, peer.handle(Advance(now_ms=now)), clock)
            if peer_frames:
                self._dispatch(
                    c_endpoint, peer, relays, 10, peer_frames, clock,
                    observed=request_events,
                )
            c_state = c_endpoint.poll(clock.next())
            self.assertEqual(c_state.status, 0)
            c_frames = [
                _decode_c_stream_frame(wire)
                for wire in c_state.frames
                if wire != b"\x00"
            ]
            if c_frames:
                self._dispatch(
                    c_endpoint, peer, relays, 20, c_frames, clock,
                    observed=request_events,
                )
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == 2
            and event.payload == request_payload
            for event in request_events
        ), f"peer did not accept the fragmented fresh request: {request_events!r}")
        expected_result = bytes((index % 256) ^ 0xA5 for index in range(1024))
        self.assertEqual(
            c_endpoint.last_state.results, initial_results + 2,
            f"fresh request result did not complete: {len(c_endpoint.last_state.result)} bytes",
        )
        self.assertEqual(c_endpoint.last_state.result, expected_result)

    def _run_fragmented_request(self, manifest_name: str, entropy_seed: int) -> None:
        c_endpoint, peer, relays, clock = self._open_pair(manifest_name, entropy_seed)
        self._activate(c_endpoint, peer, relays, clock)
        self._exercise_sample_and_fragmented_data(c_endpoint, peer, relays, clock)

        # Keep each endpoint pair within its two-grant manifest budget: the
        # bidirectional DATA checks above each use one grant. Exercise the
        # C-requested fragmented request on a fresh association.
        c_endpoint.close()
        c_endpoint, peer, relays, clock = self._open_pair(
            manifest_name, entropy_seed ^ 0x10
        )
        self._activate(c_endpoint, peer, relays, clock)
        self._exercise_c_freshness_requester(c_endpoint, peer, relays, clock)

        # The manifest admits one retained assembly per peer so replay
        # decisions remain immutable for the association lifetime. The
        # opposite-direction relay case therefore uses a separate fresh
        # association instead of exceeding that admitted quota.
        c_endpoint.close()
        c_endpoint, peer, relays, clock = self._open_pair(
            manifest_name, entropy_seed ^ 0x20
        )
        self._activate(c_endpoint, peer, relays, clock)
        self._grant_freshness(c_endpoint, peer, relays, clock)
        initial_accepts = c_endpoint.last_state.accepts
        payload = bytes((index * 31 + 7) & 0xFF for index in range(1024))
        events = peer.handle(ApplicationRequest(
            service_id=2, payload=payload, ack_req=True, at_ms=clock.next(), exchange_id=0x2301
        ))
        first = self._peer_send(peer, events, clock)
        self.assertEqual(len(first), 32)
        original = [parse_frame(frame, max_frame=_MAX_CORE) for frame in first]
        self.assertTrue(all(frame.security is not None and frame.route is not None for frame in original))
        self.assertTrue(all(
            6 in {extension.extension_id for extension in frame.extensions}
            for frame in original
        ), "service-2 fragments must carry the issued S7 freshness token")
        request_seq = original[0].sequence
        self.assertTrue(all(frame.sequence == request_seq for frame in original))
        missing = 7
        self.assertIsNotNone(original[missing].security)
        original_missing_pn = original[missing].security.packet_number
        self._dispatch(
            c_endpoint, peer, relays, 10, first, clock,
            drop={(request_seq, missing)},
        )
        self.assertEqual(c_endpoint.last_state.accepts, initial_accepts)

        resent_indices: list[int] = []
        resent_packet_numbers: list[int] = []
        recovery_trace: list[str] = []
        deadline = clock.now_ms + 11_000
        while clock.now_ms < deadline and c_endpoint.last_state.accepts == initial_accepts:
            now = clock.advance(64)
            generated: list[bytes] = []
            generated.extend(self._peer_send(peer, peer.handle(Advance(now_ms=now)), clock))
            c_state = c_endpoint.poll(clock.next())
            self.assertEqual(c_state.status, 0)
            c_frames = [
                _decode_c_stream_frame(wire)
                for wire in c_state.frames
                if wire != b"\x00"
            ]
            if generated or c_frames:
                recovery_trace.append(
                    f"t={now}, peer_tx={_frame_summary(generated)}, "
                    f"c_tx={_frame_summary(c_frames)}"
                )
            if generated:
                resent_indices.extend(
                    parse_frame(wire, max_frame=_MAX_CORE).fragment.index
                    for wire in generated
                    if parse_frame(wire, max_frame=_MAX_CORE).fragment is not None
                )
                resent_packet_numbers.extend(
                    parse_frame(wire, max_frame=_MAX_CORE).security.packet_number
                    for wire in generated
                    if parse_frame(wire, max_frame=_MAX_CORE).fragment is not None
                    and parse_frame(wire, max_frame=_MAX_CORE).security is not None
                )
                self._dispatch(c_endpoint, peer, relays, 10, generated, clock)
            if c_frames:
                # Routing the actual C endpoint's feedback/replies may make the
                # Python endpoint emit its repair, which _dispatch delivers.
                peer_replies, _ = self._dispatch(
                    c_endpoint, peer, relays, 20, c_frames, clock
                )
                if peer_replies:
                    recovery_trace.append(
                        f"t={now}, peer_rx_reply={_frame_summary(peer_replies)}"
                    )
                resent_indices.extend(
                    parse_frame(wire, max_frame=_MAX_CORE).fragment.index
                    for wire in peer_replies
                    if parse_frame(wire, max_frame=_MAX_CORE).fragment is not None
                )
                resent_packet_numbers.extend(
                    parse_frame(wire, max_frame=_MAX_CORE).security.packet_number
                    for wire in peer_replies
                    if parse_frame(wire, max_frame=_MAX_CORE).fragment is not None
                    and parse_frame(wire, max_frame=_MAX_CORE).security is not None
                )

        self.assertEqual(
            c_endpoint.last_state.accepts, initial_accepts + 1,
            f"fragmented peer REQ was not accepted: endpoint_status="
            f"{c_endpoint.last_state.endpoint_status}, rx_status={c_endpoint.last_state.rx_status}, "
            f"fragment_live={c_endpoint.last_state.fragment_live}, "
            f"request_bytes={len(c_endpoint.last_state.request)}, "
            f"resent_indices={resent_indices}, now={clock.now_ms}, deadline={deadline}, "
            f"trace={recovery_trace[-8:]}",
        )
        self.assertEqual(c_endpoint.last_state.request_service, 2)
        self.assertEqual(c_endpoint.last_state.request, payload)

        if manifest_name in {_RADIO, _RADIO_XX}:
            self.assertEqual(resent_indices, [missing], "SELECTIVE-32 must repair only the lost index")
            self.assertEqual(len(resent_packet_numbers), 1)
            self.assertGreater(resent_packet_numbers[0], original_missing_pn)
        else:
            self.assertEqual(sorted(resent_indices), list(range(32)), "retry-all must retry the full fragment set")
            self.assertEqual(len(resent_packet_numbers), 32)
            self.assertTrue(all(pn > 0 for pn in resent_packet_numbers))

        terminal_events: list[Any] = []
        completed = c_endpoint.complete(clock.next())
        self.assertEqual(completed.status, 0)
        result_frames = [
            _decode_c_stream_frame(wire)
            for wire in completed.frames
            if wire != b"\x00"
        ]
        peer_feedback, repaired_indices = self._dispatch(
            c_endpoint, peer, relays, 20, result_frames, clock, observed=terminal_events
        )
        result_deadline = clock.now_ms + 11_000
        while clock.now_ms < result_deadline and not any(
            event.kind == "request_result" and event.exchange_id == 0x2301
            for event in terminal_events
        ):
            now = clock.advance(64)
            peer_frames = self._peer_send(
                peer, peer.handle(Advance(now_ms=now)), clock
            )
            if peer_frames:
                _, c_fragments = self._dispatch(
                    c_endpoint, peer, relays, 10, peer_frames, clock
                )
                repaired_indices.extend(c_fragments)
            c_state = c_endpoint.poll(clock.next())
            self.assertEqual(c_state.status, 0)
            c_frames = [
                _decode_c_stream_frame(wire)
                for wire in c_state.frames
                if wire != b"\x00"
            ]
            if c_frames:
                peer_frames, c_fragments = self._dispatch(
                    c_endpoint, peer, relays, 20, c_frames, clock,
                    observed=terminal_events,
                )
                peer_feedback.extend(peer_frames)
                repaired_indices.extend(c_fragments)
        self.assertTrue(any(
            event.kind == "request_result"
            and event.exchange_id == 0x2301
            and event.service_id == 2
            and event.status == 0
            and event.payload == payload
            for event in terminal_events
        ), f"terminal result did not complete: events={terminal_events!r}, "
           f"C_frames={_frame_summary(result_frames)}, "
           f"C_state=(status={c_endpoint.last_state.status}, "
           f"endpoint={c_endpoint.last_state.endpoint_status}, "
           f"rx={c_endpoint.last_state.rx_status}, "
           f"accepts={c_endpoint.last_state.accepts}), "
           f"peer_feedback={_frame_summary(peer_feedback)}, "
           f"repaired_indices={repaired_indices}, "
           f"result_geometry={[(parse_frame(frame).fragment.chunk_size, parse_frame(frame).fragment.total_length, len(parse_frame(frame).payload)) for frame in result_frames if parse_frame(frame).fragment is not None]}")
        self.assertEqual(c_endpoint.last_state.results, 0)
        self.assertEqual(peer.manifest.sha256, hashlib.sha256(
            (_ROOT / "profiles" / "deployments" / manifest_name).read_bytes()
        ).hexdigest())
        self.assertEqual(peer._selective_enabled(2), manifest_name in {_RADIO, _RADIO_XX})
        for relay in relays.values():
            self.assertLessEqual(len(relay._entries), relay.cache_slots)
            self.assertEqual(relay._pending_global, 0)
            self.assertTrue(all(value == 0 for value in relay._pending_airtime.values()))
        # This process was initialized once with one exact manifest digest and
        # the peer exercised one fresh association for that same profile.
        self.assertEqual(len(c_endpoint.process.args), 2)
        self.assertIsNotNone(peer.association)
        self.assertEqual(peer.association.status, "active")

    def test_selective_32_repairs_one_lost_fragment_over_radio_relays(self) -> None:
        self._run_fragmented_request(_RADIO, 0x31)

    def test_retry_all_retries_the_full_set_over_radio_relays(self) -> None:
        self._run_fragmented_request(_RETRY_ALL, 0x51)

    def test_radio_freshness_rejections_do_not_dispatch_data(self) -> None:
        self._exercise_radio_freshness_rejections(_RADIO, 0x81)
        self._exercise_radio_freshness_rejections(_RETRY_ALL, 0x91)
        self._exercise_radio_freshness_rejections(_RADIO_XX, 0xA1)
        self._exercise_radio_freshness_rejections(_RETRY_ALL_XX, 0xB1)

    def test_selective_32_repairs_over_radio_xx(self) -> None:
        self._run_fragmented_request(_RADIO_XX, 0x61)

    def test_retry_all_xx_uses_distinct_manifest_and_fresh_associations(self) -> None:
        self._run_fragmented_request(_RETRY_ALL_XX, 0x71)

    def _assert_peer_data_accepted(self, c_endpoint, payload, before_accepts):
        self.assertEqual(c_endpoint.last_state.accepts, before_accepts)
        self.assertEqual(
            c_endpoint.last_state.assembled, 1,
            (c_endpoint.last_state.endpoint_status, c_endpoint.last_state.rx_status,
             c_endpoint.last_state.fragment_live, len(c_endpoint.last_state.body)),
        )
        self.assertEqual(c_endpoint.last_state.body, payload)

    def test_r6_two_of_eight_mask_repairs_only_missing_indices_c_to_python(self) -> None:
        payload = bytes((index % 256) ^ 0x5A for index in range(256))
        c_endpoint, peer, relays, clock, sequence, frames = self._start_peer_data_transfer(
            0xC1, payload
        )
        transfer = peer.outgoing_data[(peer.association.h, sequence)]
        selective = transfer.selective_state
        before = c_endpoint.last_state.accepts
        self._dispatch(
            c_endpoint, peer, relays, 10, frames, clock,
            drop={(sequence, 2), (sequence, 6)},
        )
        self.assertEqual(c_endpoint.last_state.accepts, before)
        repairs, statuses = self._advance_data_recovery(
            c_endpoint, peer, relays, clock
        )
        self._assert_peer_data_accepted(c_endpoint, payload, before)
        self.assertEqual(repairs, [2, 6])
        self.assertEqual(len(statuses), 1)
        self.assertEqual(selective.status_count, 1)
        self.assertEqual(selective.terminal, True)
        self.assertNotIn((peer.association.h, sequence), peer.outgoing_data)

    def _exercise_r6_initial_loss(self, seed, missing, expected_repairs) -> None:
        payload = bytes((index * 17 + 9) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock, sequence, frames = (
            self._start_peer_data_transfer(seed, payload)
        )
        before = c_endpoint.last_state.accepts
        self._dispatch(
            c_endpoint, peer, relays, 10, frames, clock,
            drop={(sequence, index) for index in missing},
        )
        self.assertEqual(c_endpoint.last_state.accepts, before)
        repairs, statuses = self._advance_data_recovery(
            c_endpoint, peer, relays, clock
        )
        self._assert_peer_data_accepted(c_endpoint, payload, before)
        self.assertEqual(repairs, expected_repairs)
        self.assertTrue(statuses)

    def test_r6_final_fragment_loss_probes_and_repairs_final_index(self) -> None:
        self._exercise_r6_initial_loss(0xC2, {7}, [7])

    def test_r6_all_initial_fragments_lost_probes_then_repairs_rest(self) -> None:
        self._exercise_r6_initial_loss(
            0xC3, set(range(8)), [7, 0, 1, 2, 3, 4, 5, 6]
        )

    def _exercise_r6_feedback_loss(self, seed, *, drop_repair) -> None:
        payload = bytes((index * 7 + 3) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock, sequence, frames = (
            self._start_peer_data_transfer(seed, payload)
        )
        transfer = peer.outgoing_data[(peer.association.h, sequence)]
        selective = transfer.selective_state
        before = c_endpoint.last_state.accepts
        dropped_statuses: list[bytes] = []
        dropped_types = set() if drop_repair else {8}
        drop_peer = {(sequence, 2)} if drop_repair else None
        self._dispatch(
            c_endpoint, peer, relays, 10, frames, clock,
            drop={(sequence, 2), (sequence, 6)},
        )
        # In the status-loss case the first C-generated protected FRAG_STATUS
        # is deliberately discarded at the relay boundary.
        repairs, statuses = self._advance_data_recovery(
            c_endpoint, peer, relays, clock,
            drop_c_types=dropped_types,
            dropped_c=dropped_statuses,
            drop_peer=drop_peer,
        )
        if drop_repair:
            self.assertEqual(dropped_statuses, [])
        else:
            self.assertEqual(len(dropped_statuses), 1)
        self._assert_peer_data_accepted(c_endpoint, payload, before)
        self.assertTrue(statuses)
        if drop_repair:
            # The first selective repair was lost; a later snapshot still
            # requests and delivers the missing indices.
            self.assertEqual(repairs, [2, 6, 2])
            self.assertEqual(selective.status_count, 2)
        else:
            # The sender probes the final index after the lost snapshot, then
            # repairs exactly the two reported gaps.
            self.assertEqual(repairs, [7, 2, 6])
            self.assertEqual(selective.status_count, 1)

    def test_r6_status_loss_probes_then_emits_new_protected_status(self) -> None:
        self._exercise_r6_feedback_loss(0xC4, drop_repair=False)

    def test_r6_repair_slice_loss_is_requested_again(self) -> None:
        self._exercise_r6_feedback_loss(0xC5, drop_repair=True)

    def test_r6_lost_final_ack_is_repeated_without_second_acceptance(self) -> None:
        payload = bytes((index * 29 + 1) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock, sequence, frames = self._start_peer_data_transfer(
            0xC6, payload
        )
        before = c_endpoint.last_state.accepts
        dropped_ack: list[bytes] = []
        self._dispatch(
            c_endpoint, peer, relays, 10, frames, clock,
            drop_c_types={6}, dropped_c=dropped_ack,
        )
        self.assertEqual(len(dropped_ack), 1)
        self.assertEqual(c_endpoint.last_state.accepts, before)
        self.assertEqual(c_endpoint.last_state.assembled, 1)
        self.assertEqual(c_endpoint.last_state.body, payload)
        self.assertIn((peer.association.h, sequence), peer.outgoing_data)

        transfer = peer.outgoing_data[(peer.association.h, sequence)]
        probe_at = max(transfer.selective_state.started_at_ms + 4352, peer.now_ms + 1)
        if probe_at > clock.now_ms:
            clock.advance(probe_at - clock.now_ms)
        probe = self._peer_send(peer, peer.handle(Advance(now_ms=probe_at)), clock)
        probe_indices = [
            parse_frame(frame, max_frame=_MAX_CORE).fragment.index
            for frame in probe
            if parse_frame(frame, max_frame=_MAX_CORE).fragment is not None
        ]
        self.assertEqual(probe_indices, [7])
        self._dispatch(c_endpoint, peer, relays, 10, probe, clock)
        self.assertEqual(c_endpoint.last_state.accepts, before)
        self.assertEqual(c_endpoint.last_state.assembled, 1)
        self.assertNotIn((peer.association.h, sequence), peer.outgoing_data)

    def test_r6_incomplete_assembly_tombstone_rejects_late_protected_slice(self) -> None:
        payload = bytes(range(256))
        c_endpoint, peer, relays, clock, sequence, frames = self._start_peer_data_transfer(
            0xC7, payload
        )
        self._dispatch(
            c_endpoint, peer, relays, 10, frames[:1], clock
        )
        self.assertEqual(c_endpoint.last_state.accepts, 0)
        self.assertEqual(c_endpoint.last_state.rx_status, 7)
        assembly_ms = int(peer.manifest.values["timing"]["assembly_ms"])
        expired = c_endpoint.poll(clock.advance(assembly_ms + 1))
        self.assertEqual(expired.status, 0)
        self.assertEqual(expired.accepts, 0)
        late = c_endpoint.receive(
            encode_stream_r(
                self._route(relays, frames[1], source=10, clock=clock),
                max_core=_MAX_CORE,
                max_encoded=_MAX_ENCODED,
            ),
            clock.next(),
        )
        self.assertEqual(late.accepts, 0)
        self.assertNotEqual(late.status, 0)
        self.assertEqual(late.assembled, 0)
        self.assertEqual(late.body, b"")

    def test_r6_receiver_restart_does_not_resume_old_association(self) -> None:
        payload = bytes((index * 5) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock, _, frames = self._start_peer_data_transfer(
            0xC8, payload
        )
        self._dispatch(c_endpoint, peer, relays, 10, frames[:1], clock)
        self.assertEqual(c_endpoint.last_state.rx_status, 7)
        old_association_frame = self._route(
            relays, frames[1], source=10, clock=clock
        )
        old_digest = bytes.fromhex(peer.manifest.sha256)
        c_endpoint.close()
        restarted = _CProcess(self.executable, old_digest, _PSK)
        self.addCleanup(restarted.close)
        _assert_effective_profile(
            self, restarted.initial,
            (_ROOT / "profiles" / "deployments" / _RADIO).read_bytes(),
        )
        self.assertEqual(restarted.receive(b"\x00", clock.next()).status, 0)
        state = restarted.receive(
            encode_stream_r(
                old_association_frame,
                max_core=_MAX_CORE,
                max_encoded=_MAX_ENCODED,
            ),
            clock.next(),
        )
        self.assertNotEqual(state.status, 0)
        self.assertEqual(state.accepts, 0)
        self.assertFalse(state.bound)
        self.assertEqual(state.body, b"")

    def test_r6_status_after_acceptance_cannot_reopen_c_sender(self) -> None:
        c_endpoint, peer, relays, clock = self._open_pair(_RADIO, 0xC9)
        self._activate(c_endpoint, peer, relays, clock)
        grant = c_endpoint.submit_req(
            0, b"\x10" + (12_000).to_bytes(4, "little"), clock.next()
        )
        self.assertEqual(grant.status, 0)
        grant_events: list[Any] = []
        self._dispatch(
            c_endpoint, peer, relays, 20, grant.frames, clock,
            observed=grant_events,
        )
        token = c_endpoint.last_state.result[1:17]
        self.assertEqual(len(token), 16)

        payload = bytes((index * 11 + 4) & 0xFF for index in range(256))
        initial_results = c_endpoint.last_state.results
        c_request = c_endpoint.submit_req_fresh(2, payload, token, clock.next())
        self.assertEqual(c_request.status, 0)
        initial = [
            _decode_c_stream_frame(wire) for wire in c_request.frames if wire != b"\x00"
        ]
        self.assertEqual(len(initial), 8)
        sequence = parse_frame(initial[0], max_frame=_MAX_CORE).sequence
        observed: list[Any] = []
        self._dispatch(c_endpoint, peer, relays, 20, c_request.frames, clock, observed=observed)
        accepted = [
            event for event in observed
            if isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == 2
            and event.payload == payload
        ]
        self.assertEqual(len(accepted), 1)
        self.assertEqual(c_endpoint.last_state.results, initial_results + 1)
        self.assertEqual(
            c_endpoint.last_state.result,
            bytes((index % 256) ^ 0xA5 for index in range(256)),
        )
        completed_key = next(
            key for key in peer.reassembly.completed if key[3] == sequence
        )

        # An authenticated late FRAG_STATUS is still a protocol frame, but a
        # terminal C sender has no live transfer for it to reopen.
        late_status = peer._build_fragment_status(completed_key, 2, 1)
        self.assertIsNotNone(late_status)
        peer_out, c_fragments = self._dispatch(
            c_endpoint, peer, relays, 10, [late_status], clock
        )
        self.assertEqual(peer_out, [])
        self.assertEqual(c_fragments, [])
        self.assertEqual(c_endpoint.last_state.results, initial_results + 1)

    def test_r6_stale_status_with_fresh_pn_does_not_replace_newer_mask(self) -> None:
        payload = bytes((index * 13 + 7) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock = self._open_pair(
            _RADIO, 0xCA, async_tx_completion=True
        )
        self._activate(c_endpoint, peer, relays, clock)
        grant = c_endpoint.submit_req(
            0, b"\x10" + (12_000).to_bytes(4, "little"), clock.next()
        )
        self.assertEqual(grant.status, 0)
        grant_events: list[Any] = []
        self._dispatch(
            c_endpoint, peer, relays, 20, grant.frames, clock,
            observed=grant_events,
        )
        token = c_endpoint.last_state.result[1:17]
        self.assertEqual(len(token), 16)
        completed_grant = c_endpoint.complete_tx(1, clock.next())
        self.assertEqual(completed_grant.status, 0, completed_grant.endpoint_status)

        request = c_endpoint.submit_req_fresh(2, payload, token, clock.next())
        self.assertEqual(request.status, 0)
        initial_wire = [wire for wire in request.frames if wire != b"\x00"]
        initial = [_decode_c_stream_frame(wire) for wire in initial_wire]
        self.assertTrue(initial)
        sequence = parse_frame(initial[0], max_frame=_MAX_CORE).sequence
        initial_by_index = {
            parse_frame(frame, max_frame=_MAX_CORE).fragment.index: frame
            for frame in initial
        }
        self.assertTrue(all(
            parse_frame(frame, max_frame=_MAX_CORE).sequence == sequence
            for frame in initial
        ))

        # Complete just enough C link submissions to let the sender schedule
        # the rest of its original burst. Leave the final batch uncompleted so
        # both authenticated status frames arrive while burst_inflight is set.
        initial_frames = list(initial_wire)
        last_batch = initial_wire
        while set(initial_by_index) != set(range(8)):
            completed = c_endpoint.complete_tx(len(last_batch), clock.next())
            self.assertEqual(completed.status, 0, completed.endpoint_status)
            polled = c_endpoint.poll(clock.next())
            self.assertEqual(polled.status, 0, (polled.endpoint_status, polled.rx_status))
            last_batch = [wire for wire in polled.frames if wire != b"\x00"]
            self.assertTrue(last_batch, "C sender did not continue its initial fragment burst")
            for wire in last_batch:
                frame = _decode_c_stream_frame(wire)
                parsed = parse_frame(frame, max_frame=_MAX_CORE)
                self.assertEqual(parsed.sequence, sequence)
                self.assertIsNotNone(parsed.fragment)
                assert parsed.fragment is not None
                self.assertNotIn(parsed.fragment.index, initial_by_index)
                initial_by_index[parsed.fragment.index] = frame
            initial_frames.extend(last_batch)

        self.assertEqual(sorted(initial_by_index), list(range(8)))
        self.assertEqual(len(initial_frames), 8)
        delivered_initial = [
            wire for wire in initial_frames
            if parse_frame(_decode_c_stream_frame(wire), max_frame=_MAX_CORE)
            .fragment.index not in (2, 6)
        ]

        observed: list[Any] = []
        self._dispatch(
            c_endpoint,
            peer,
            relays,
            20,
            delivered_initial,
            clock,
            observed=observed,
        )
        self.assertFalse(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.payload == payload
            for event in observed
        ))
        active_key = next(
            key for key in peer.reassembly.active if key[3] == sequence
        )

        newer = peer._build_fragment_status(active_key, 2, (1 << 2) | (1 << 6))
        self.assertIsNotNone(newer)
        assert newer is not None
        newer_fields = parse_frame(newer, max_frame=_MAX_CORE)
        self.assertIsNotNone(newer_fields.security)
        assert newer_fields.security is not None

        # Reuse an older logical SEQ only after the newer frame consumed its
        # PN. The peer seals a second real protected frame, so its PN is fresh
        # even though its status SEQ is stale.
        next_peer_sequence = peer.next_seq
        peer.next_seq = newer_fields.sequence - 1
        stale = peer._build_fragment_status(active_key, 2, 1 << 0)
        self.assertIsNotNone(stale)
        assert stale is not None
        peer.next_seq = next_peer_sequence
        stale_fields = parse_frame(stale, max_frame=_MAX_CORE)
        self.assertIsNotNone(stale_fields.security)
        assert stale_fields.security is not None
        self.assertLess(stale_fields.sequence, newer_fields.sequence)
        self.assertGreater(
            stale_fields.security.packet_number, newer_fields.security.packet_number
        )

        _, newer_c_fragments = self._dispatch(
            c_endpoint, peer, relays, 10, [newer], clock
        )
        _, stale_c_fragments = self._dispatch(
            c_endpoint, peer, relays, 10, [stale], clock
        )
        self.assertEqual(newer_c_fragments, [])
        self.assertEqual(stale_c_fragments, [])

        # The final original-burst TX completions promote only the accepted
        # newer mask. A subsequent poll must repair fragments 2 and 6, never 0.
        completed = c_endpoint.complete_tx(len(last_batch), clock.next())
        self.assertEqual(completed.status, 0, completed.endpoint_status)
        repairs = c_endpoint.poll(clock.next())
        self.assertEqual(repairs.status, 0, (repairs.endpoint_status, repairs.rx_status))
        repair_wire = [wire for wire in repairs.frames if wire != b"\x00"]
        all_repair_wire = list(repair_wire)
        repair_frames = [_decode_c_stream_frame(wire) for wire in repair_wire]
        repair_indices = [
            parse_frame(frame, max_frame=_MAX_CORE).fragment.index
            for frame in repair_frames
        ]
        while len(repair_indices) < 2:
            completed = c_endpoint.complete_tx(len(repair_wire), clock.next())
            self.assertEqual(completed.status, 0, completed.endpoint_status)
            next_repairs = c_endpoint.poll(clock.next())
            self.assertEqual(
                next_repairs.status,
                0,
                (next_repairs.endpoint_status, next_repairs.rx_status),
            )
            repair_wire = [wire for wire in next_repairs.frames if wire != b"\x00"]
            self.assertTrue(repair_wire, "C sender did not continue its selective repair mask")
            all_repair_wire.extend(repair_wire)
            repair_frames = [_decode_c_stream_frame(wire) for wire in repair_wire]
            repair_indices.extend(
                parse_frame(frame, max_frame=_MAX_CORE).fragment.index
                for frame in repair_frames
            )
        self.assertEqual(
            repair_indices,
            [2, 6],
        )
        repair_events: list[Any] = []
        self._dispatch(
            c_endpoint,
            peer,
            relays,
            20,
            all_repair_wire,
            clock,
            observed=repair_events,
        )
        accepted = [
            event for event in repair_events
            if isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == 2
            and event.payload == payload
        ]
        self.assertEqual(len(accepted), 1)


if __name__ == "__main__":
    unittest.main()
