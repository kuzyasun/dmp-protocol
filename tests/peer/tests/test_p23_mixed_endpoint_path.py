"""P23 mixed-path interoperability with the real C endpoint and P21 peer."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parents[1]))

from dmp_peer.events import (  # noqa: E402
    ApplicationEvent,
    Open,
    PublishSample,
    Receive,
)
from dmp_peer.frame import (  # noqa: E402
    FrameError,
    crc32c,
    encode_frame,
    encode_uleb,
    parse_frame,
)
from dmp_peer.mixed_path import MixedPathRouter  # noqa: E402
from dmp_peer.sample1 import Sample  # noqa: E402
from dmp_peer.stream_r import StreamRDecoder, encode_stream_r  # noqa: E402
from dmp_peer.testing import PeerEndpoint  # noqa: E402
from test_p22_mixed_path_router import route_ttl_offset  # noqa: E402
from test_p23_c_endpoint_interop import _CProcess, _Clock, _settle  # noqa: E402


_ROOT = Path(__file__).parents[3]
_MANIFEST_NAME = "test-mixed-tcp-stream-r-sim-packet-nnpsk0.json"
_MANIFEST_DIGEST = "2bc3c2ee1c9e8f3aa87af4afd2f0cab996099fc69da1f0938c23e050c8c68faf"
_MAX_CORE = 256
_MAX_ENCODED = 263
_SYNC = b"\x00"


def _advance_until(router: MixedPathRouter, events, kind: str):
    collected = list(events)
    while not any(event.kind == kind for event in collected):
        rejected = [event for event in collected if event.kind == "rejected"]
        if rejected:
            raise AssertionError(rejected)
        if not router._pending:
            raise AssertionError(collected)
        due = min(item.completion_ms for item in router._pending)
        collected.extend(router.advance(max(router._last_ms, due)))
    matches = [event for event in collected if event.kind == kind]
    if len(matches) != 1 or matches[0].frame is None:
        raise AssertionError(collected)
    return matches[0]


def _check_ttl_only_change(original: bytes, forwarded: bytes) -> None:
    parsed_original = parse_frame(original, max_frame=_MAX_CORE)
    parsed_forwarded = parse_frame(forwarded, max_frame=_MAX_CORE)
    if parsed_original.route is None or parsed_forwarded.route is None:
        raise AssertionError("mixed endpoint frame is missing ROUTE")
    if parsed_original.route.ttl != 2 or parsed_forwarded.route.ttl != 0:
        raise AssertionError(
            f"mixed path TTL was not decremented across two relays: "
            f"{parsed_original.route.ttl}->{parsed_forwarded.route.ttl}"
        )
    expected = bytearray(original)
    expected[route_ttl_offset(original)] -= 0x20
    # Bootstrap frames carry CRC32C. A relay must refresh that checksum after
    # changing ROUTE TTL; protected SEC-1 frames have an opaque tag and do not.
    if parsed_original.integrity is not None:
        expected[-4:] = crc32c(bytes(expected[:-4])).to_bytes(4, "little")
    if bytes(expected) != forwarded:
        allowed = "ROUTE TTL and its dependent CRC32C" if parsed_original.integrity is not None else "ROUTE TTL"
        raise AssertionError(f"mixed relays changed core bytes other than {allowed}")


def _mutate_context(core: bytes, *, remove: bool) -> bytes:
    frame = parse_frame(core, max_frame=_MAX_CORE)
    context_index = next(
        (index for index, extension in enumerate(frame.extensions)
         if extension.extension_id == 2),
        None,
    )
    if context_index is None:
        raise AssertionError("actual endpoint frame has no CONTEXT to mutate")
    extensions = list(frame.extensions)
    context = extensions[context_index]
    if remove:
        del extensions[context_index]
    else:
        namespace, offset = _decode_uleb(context.value)
        del namespace
        wrong_value = encode_uleb(2) + context.value[offset:]
        extensions[context_index] = replace(context, value=wrong_value)
    return encode_frame(replace(frame, extensions=tuple(extensions)), max_frame=_MAX_CORE)


def _decode_uleb(data: bytes) -> tuple[int, int]:
    value = 0
    for index, octet in enumerate(data):
        value |= (octet & 0x7F) << (7 * index)
        if octet & 0x80 == 0:
            return value, index + 1
    raise AssertionError("truncated CONTEXT namespace")


def _finish_transit(router: MixedPathRouter, events, *, expected_kind: str):
    collected = list(events)
    while True:
        result = next(
            (event for event in collected
             if event.kind in {"rejected", "packet_frame", "tcp_stream"}),
            None,
        )
        if result is not None:
            if result.kind != expected_kind:
                raise AssertionError(collected)
            return result
        if not router._pending:
            raise AssertionError(collected)
        due = min(item.completion_ms for item in router._pending)
        collected.extend(router.advance(max(router._last_ms, due)))


@unittest.skipUnless(
    os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
    "C P23 endpoint executable is not configured",
)
class TestP23MixedEndpointPath(unittest.TestCase):
    def setUp(self) -> None:
        manifest_path = (
            _ROOT / "profiles" / "deployments" / _MANIFEST_NAME
        )
        self.manifest_bytes = manifest_path.read_bytes()
        self.profile_hash = hashlib.sha256(self.manifest_bytes).digest()
        digest_index = json.loads(
            (_ROOT / "profiles" / "deployments" / "digests.json").read_text()
        )
        self.assertEqual(self.profile_hash.hex(), _MANIFEST_DIGEST)
        self.assertEqual(
            self.profile_hash.hex(), digest_index["manifests"][_MANIFEST_NAME]
        )
        self.executable = os.environ["DMP_P23_ENDPOINT_SEC_EXE"]

    def _mixed_outcome(self, core: bytes, *, source: str, expected_kind: str):
        router = MixedPathRouter(self.manifest_bytes)
        if source == "python":
            sync = router.start_tcp(lambda: None)
            wire = encode_stream_r(
                core, max_core=_MAX_CORE, max_encoded=_MAX_ENCODED
            )
            events = router.feed_tcp(sync + wire, at_ms=0)
        else:
            events = router.feed_packet(core, at_ms=0)
        return _finish_transit(router, events, expected_kind=expected_kind)

    def _check_endpoint_frame_negatives(
        self, *, python_frame: bytes, c_frame: bytes, c_endpoint: _CProcess,
        peer: PeerEndpoint,
    ) -> None:
        cases = (
            ("python", python_frame, "packet_frame", "forward_mtu"),
            ("c", c_frame, "tcp_stream", "tcp_return_mtu"),
        )
        c_snapshot = (
            c_endpoint.last_state.accepts,
            c_endpoint.last_state.results,
            c_endpoint.last_state.telemetry,
        )
        peer_status = peer.association.status if peer.association is not None else None
        for source, actual, accepted_kind, egress_limit in cases:
            self.assertIsNotNone(parse_frame(actual).security)
            self.assertIsNotNone(parse_frame(actual).route)
            self.assertLessEqual(len(actual), _MAX_CORE)

            # Use the actual SEC-1 endpoint frame at its exact egress limit,
            # then one byte below it. The router must accept the boundary and
            # reject the over-limit copy before it can reach the other endpoint.
            boundary_router = MixedPathRouter(self.manifest_bytes)
            setattr(boundary_router.relays[30], egress_limit, len(actual))
            if source == "python":
                sync = boundary_router.start_tcp(lambda: None)
                wire = encode_stream_r(
                    actual, max_core=_MAX_CORE, max_encoded=_MAX_ENCODED
                )
                boundary_events = boundary_router.feed_tcp(sync + wire, at_ms=0)
            else:
                boundary_events = boundary_router.feed_packet(actual, at_ms=0)
            boundary = _finish_transit(
                boundary_router, boundary_events, expected_kind=accepted_kind
            )
            delivered_core = boundary.frame
            if source == "c":
                decoded = [
                    event.frame for event in StreamRDecoder(
                        max_encoded=_MAX_ENCODED,
                        max_core=_MAX_CORE,
                        candidate_timeout_ms=26,
                        await_sync=True,
                    ).feed(_SYNC + boundary.frame, at_ms=boundary.at_ms)
                    if event.kind == "frame"
                ]
                self.assertEqual(len(decoded), 1)
                delivered_core = decoded[0]
            self.assertEqual(len(delivered_core), len(actual))
            _check_ttl_only_change(actual, delivered_core)

            reject_router = MixedPathRouter(self.manifest_bytes)
            setattr(reject_router.relays[30], egress_limit, len(actual) - 1)
            if source == "python":
                sync = reject_router.start_tcp(lambda: None)
                wire = encode_stream_r(
                    actual, max_core=_MAX_CORE, max_encoded=_MAX_ENCODED
                )
                reject_events = reject_router.feed_tcp(sync + wire, at_ms=0)
            else:
                reject_events = reject_router.feed_packet(actual, at_ms=0)
            rejected = _finish_transit(
                reject_router, reject_events, expected_kind="rejected"
            )
            self.assertIn("mtu", rejected.reason or "")

            for remove, expected_reason in (
                (True, "routed SEC-1 frame requires explicit CONTEXT"),
                (False, "context-mismatch"),
            ):
                invalid = _mutate_context(actual, remove=remove)
                rejected_context = self._mixed_outcome(
                    invalid, source=source, expected_kind="rejected"
                )
                self.assertIn(expected_reason, rejected_context.reason or "")

            # Rejected router inputs produced no endpoint-facing event, so the
            # C acceptance counters and Python association state stay unchanged.
            self.assertEqual(
                (
                    c_endpoint.last_state.accepts,
                    c_endpoint.last_state.results,
                    c_endpoint.last_state.telemetry,
                ),
                c_snapshot,
            )
            self.assertEqual(
                peer.association.status if peer.association is not None else None,
                peer_status,
            )

    def test_sec1_sample_exchange_crosses_mixed_path_in_both_directions(self) -> None:
        psk = b"\x23" * 32
        clock = _Clock()
        router = MixedPathRouter(self.manifest_bytes)
        bridge_sync = router.start_tcp(lambda: None)
        self.assertEqual(bridge_sync, _SYNC)

        # The existing C seam is a real node-20 endpoint whose process boundary
        # carries Stream R. The mixed packet edge therefore uses only the
        # Stream R framing adapter around its serialized core frames.
        c_endpoint = _CProcess(self.executable, self.profile_hash, psk)
        self.addCleanup(c_endpoint.close)
        self.assertEqual(c_endpoint.initial.frames, [_SYNC])
        self.assertEqual(c_endpoint.receive(bridge_sync, clock.next()).status, 0)

        peer = PeerEndpoint(
            manifest_bytes=self.manifest_bytes,
            test_credentials={"node_id": 10, "psk": psk, "key_hint": 5},
            entropy_source=lambda size: bytes((0x39 + index) & 0xFF for index in range(size)),
            test_services={},
        )
        peer.handle(
            Open(link=0, deadline_capability="strict_latest_start", at_ms=clock.next())
        )

        c_decoder = StreamRDecoder(
            max_encoded=_MAX_ENCODED,
            max_core=_MAX_CORE,
            candidate_timeout_ms=26,
            await_sync=True,
        )
        peer_return_decoder = StreamRDecoder(
            max_encoded=_MAX_ENCODED,
            max_core=_MAX_CORE,
            candidate_timeout_ms=26,
            await_sync=True,
        )
        peer_tcp_sync_pending = True
        peer_return_sync_pending = True

        def transport_time() -> int:
            clock.now_ms = max(clock.now_ms, router._last_ms)
            return clock.next()

        def peer_to_c(core: bytes) -> tuple[object, bytes]:
            nonlocal peer_tcp_sync_pending
            original = bytes(core)
            prefix = _SYNC if peer_tcp_sync_pending else b""
            peer_tcp_sync_pending = False
            incoming = encode_stream_r(
                original, max_core=_MAX_CORE, max_encoded=_MAX_ENCODED
            )
            event = _advance_until(
                router,
                router.feed_tcp(prefix + incoming, at_ms=transport_time()),
                "packet_frame",
            )
            _check_ttl_only_change(original, event.frame)
            c_wire = encode_stream_r(
                event.frame, max_core=_MAX_CORE, max_encoded=_MAX_ENCODED
            )
            return event, c_wire

        def c_to_peer(stream_wire: bytes) -> tuple[object, bytes]:
            nonlocal peer_return_sync_pending
            try:
                parse_frame(stream_wire, max_frame=_MAX_CORE)
            except FrameError:
                parsed_frames = [
                    item.frame
                    for item in c_decoder.feed(stream_wire, at_ms=transport_time())
                    if item.kind == "frame"
                ]
                if len(parsed_frames) != 1 or parsed_frames[0] is None:
                    raise AssertionError(
                        "C process did not emit one packet Core or Stream R frame"
                    )
                original = parsed_frames[0]
            else:
                original = stream_wire
            event = _advance_until(
                router,
                router.feed_packet(original, at_ms=transport_time()),
                "tcp_stream",
            )
            prefix = bridge_sync if peer_return_sync_pending else b""
            peer_return_sync_pending = False
            decoded = [
                item.frame
                for item in peer_return_decoder.feed(
                    prefix + event.frame, at_ms=event.at_ms
                )
                if item.kind == "frame"
            ]
            if len(decoded) != 1:
                raise AssertionError("mixed return path did not decode one Stream R frame")
            _check_ttl_only_change(original, decoded[0])
            return event, decoded[0]

        # Node 10 (Python) initiates the real SEC-1 handshake; every serialized
        # endpoint frame traverses the P22 router between the two endpoints.
        peer_events = peer.initiate_handshake(at_ms=clock.next())
        peer_frames, _ = _settle(peer, peer_events, clock)
        pending = [("peer", frame) for frame in peer_frames]
        for _ in range(24):
            if not pending:
                break
            side, wire = pending.pop(0)
            if side == "peer":
                event, c_wire = peer_to_c(wire)
                c_state = c_endpoint.receive(c_wire, event.at_ms + 1)
                clock.now_ms = max(clock.now_ms, event.at_ms + 1)
                self.assertEqual(c_state.status, 0)
                pending.extend(("c", frame) for frame in c_state.frames)
            else:
                event, peer_core = c_to_peer(wire)
                received = peer.handle(
                    Receive(link=0, bytes=peer_core, at_ms=event.at_ms + 1)
                )
                clock.now_ms = max(clock.now_ms, event.at_ms + 1)
                outgoing, _ = _settle(peer, received, clock)
                pending.extend(("peer", frame) for frame in outgoing)
            if c_endpoint.last_state.handshake_active and peer.association is not None:
                if peer.association.status == "active":
                    break
        self.assertTrue(c_endpoint.last_state.handshake_active)
        self.assertTrue(c_endpoint.last_state.bound)
        self.assertIsNotNone(peer.association)
        self.assertEqual(peer.association.status, "active")

        # Produce one genuine SEC-1 frame from each endpoint, then exercise
        # both mixed-path directions at the egress MTU boundary and with bad
        # CONTEXT metadata. These rejected inputs never reach either endpoint.
        published = peer.handle(PublishSample(value=12345, at_ms=clock.next()))
        sample_frames, _ = _settle(peer, published, clock)
        self.assertEqual(len(sample_frames), 1)
        c_request_state = c_endpoint.submit_req(1, b"\x01", clock.next())
        self.assertEqual(c_request_state.status, 0)
        self.assertEqual(len(c_request_state.frames), 1)
        c_request_wires = list(c_request_state.frames)
        try:
            parse_frame(c_request_wires[0], max_frame=_MAX_CORE)
        except FrameError:
            c_core_frames = [
                item.frame
                for item in c_decoder.feed(c_request_wires[0], at_ms=clock.next())
                if item.kind == "frame"
            ]
        else:
            c_core_frames = [c_request_wires[0]]
        self.assertEqual(len(c_core_frames), 1)
        self._check_endpoint_frame_negatives(
            python_frame=sample_frames[0],
            c_frame=c_core_frames[0],
            c_endpoint=c_endpoint,
            peer=peer,
        )

        # Python node 10 is the SAMPLE-1 producer. Its protected telemetry goes
        # over TCP/Stream R, across both relays, and reaches the actual C reader.
        self.assertIsNotNone(parse_frame(sample_frames[0]).security)
        sample_event, sample_wire = peer_to_c(sample_frames[0])
        c_state = c_endpoint.receive(sample_wire, sample_event.at_ms + 1)
        clock.now_ms = max(clock.now_ms, sample_event.at_ms + 1)
        self.assertEqual(c_state.status, 0)
        self.assertGreaterEqual(c_state.telemetry, 1)

        # The C node-20 reader sends a protected SAMPLE-1 read request through
        # the packet side. The Python producer returns the protected sample over
        # the reverse Stream R side; both core objects are checked byte-for-byte
        # apart from the two relay TTL decrements.
        # Deliver the same pending request that was used for the boundary
        # checks. A second service-1 request would correctly exceed the profile's
        # one-operation-per-service limit while this correlation is pending.
        peer_responses = []
        for frame in c_request_wires:
            event, peer_core = c_to_peer(frame)
            self.assertIsNotNone(parse_frame(peer_core).security)
            received = peer.handle(
                Receive(link=0, bytes=peer_core, at_ms=event.at_ms + 1)
            )
            clock.now_ms = max(clock.now_ms, event.at_ms + 1)
            outgoing, _ = _settle(peer, received, clock)
            peer_responses.extend(outgoing)

        routed_peer_response = False
        for frame in peer_responses:
            self.assertIsNotNone(parse_frame(frame).security)
            event, c_wire = peer_to_c(frame)
            c_state = c_endpoint.receive(c_wire, event.at_ms + 1)
            clock.now_ms = max(clock.now_ms, event.at_ms + 1)
            self.assertEqual(c_state.status, 0)
            routed_peer_response = True
            if c_state.results >= 1:
                break
        self.assertTrue(routed_peer_response)
        self.assertEqual(c_endpoint.last_state.results, 1)
        sample = Sample.decode_read_result(c_endpoint.last_state.result)
        self.assertEqual(sample.value, 12345)


if __name__ == "__main__":
    unittest.main()
