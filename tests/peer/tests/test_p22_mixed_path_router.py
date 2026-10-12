"""Stream R/packet composition behavior for the independent peer simulator."""

from __future__ import annotations

import unittest
from pathlib import Path

from dmp_peer.events import ApplicationRequest, Open, Receive, TxAdmit, TxSubmit, TxTerminal
from dmp_peer.frame import parse_frame
from dmp_peer.mixed_path import MixedPathRouter
from dmp_peer.stream_r import StreamRDecoder, encode_stream_r
from dmp_peer.testing import PeerEndpoint


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = (ROOT / "profiles" / "deployments"
            / "test-mixed-tcp-stream-r-sim-packet-nnpsk0.json").read_bytes()


def uleb(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def extension(ext_id: int, value: bytes, *, critical: int = 1, unsafe: int = 0) -> bytes:
    return uleb((ext_id << 2) | (unsafe << 1) | critical) + uleb(len(value)) + value


def protected_frame(*, source: int, destination: int, seq: int = 17, pn: int = 1,
                    ttl: int = 2, namespace: int = 1, message_type: int = 7,
                    service_id: int = 2, payload_size: int = 32) -> bytes:
    route = bytes(((ttl << 4) | 1,)) + uleb(source) + uleb(destination)
    security = b"\x01" + uleb(9) + uleb(pn)
    context = uleb(namespace) + (0x0102030405060708).to_bytes(8, "little")
    extensions = b""
    if message_type in (6, 8):
        extensions += extension(1, uleb(17))
    extensions += extension(2, context, critical=1, unsafe=1)
    if service_id != 1:
        extensions += extension(4, uleb(service_id))
    extensions += extension(64, b"xyz", critical=0)
    header = bytes((0x40 | message_type, 0, 0xC5)) + uleb(seq) + route + security + extensions
    header = header[:1] + bytes((len(header),)) + header[2:]
    if message_type == 6:
        payload = b""
    elif message_type == 8:
        payload = b"\x01\x00\x00\x00"
    else:
        payload = bytes((pn & 0xFF,)) * payload_size
    return header + payload + bytes((0xA0 + pn % 16,)) * 16


def route_ttl_offset(frame: bytes) -> int:
    pos = 3
    while frame[pos] & 0x80:
        pos += 1
    return pos + 1


class MixedPathRouterTests(unittest.TestCase):
    @staticmethod
    def send_tcp(router: MixedPathRouter, frame: bytes, *, at_ms: int,
                 not_after_ms: int | None = None):
        wire = encode_stream_r(frame, max_core=256, max_encoded=263)
        if not router._tcp_ready:
            sync = router.start_tcp(lambda: None)
            wire = sync + wire
        return router.feed_tcp(wire, at_ms=at_ms, not_after_ms=not_after_ms)

    @staticmethod
    def advance_pending(router: MixedPathRouter, events=()):
        collected = list(events)
        while router._pending:
            due = min(item.completion_ms for item in router._pending)
            collected.extend(router.advance(max(router._last_ms, due)))
        return tuple(collected)

    @staticmethod
    def advance_until(router: MixedPathRouter, events, kind: str):
        collected = list(events)
        while not any(event.kind == kind for event in collected):
            if not router._pending:
                raise AssertionError(collected)
            due = min(item.completion_ms for item in router._pending)
            collected.extend(router.advance(max(router._last_ms, due)))
        return tuple(collected)

    @staticmethod
    def scheduled_start(event, relay_arrival_ms: int = 8) -> int:
        return event.at_ms - relay_arrival_ms

    def test_tcp_stream_splits_and_packet_return_coalesces_at_frozen_bridge(self):
        router = MixedPathRouter(MANIFEST)
        ready: list[str] = []
        sync = router.start_tcp(lambda: ready.append("ready"))
        self.assertEqual(ready, ["ready"])
        self.assertEqual(sync, b"\x00")

        forward = protected_frame(source=10, destination=20, seq=101)
        encoded = encode_stream_r(forward, max_core=256, max_encoded=263)
        split = len(encoded) // 2
        self.assertEqual(router.feed_tcp(sync + encoded[:split], at_ms=0), ())
        event = router.feed_tcp(encoded[split:], at_ms=1)
        event = self.advance_pending(router, event)
        self.assertEqual(len(event), 1)
        self.assertEqual((event[0].kind, event[0].interface), ("packet_frame", "packet"))
        forwarded = bytearray(forward)
        forwarded[route_ttl_offset(forward)] -= 0x20
        self.assertEqual(event[0].frame, bytes(forwarded))

        reverse = protected_frame(source=20, destination=10, seq=202)
        tcp_event = router.feed_packet(reverse, at_ms=100)
        tcp_event = self.advance_pending(router, tcp_event)
        self.assertEqual(len(tcp_event), 1)
        self.assertEqual((tcp_event[0].kind, tcp_event[0].interface), ("tcp_stream", "tcp"))
        decoder = StreamRDecoder(
            max_encoded=263, max_core=256, candidate_timeout_ms=26, await_sync=True
        )
        frames = decoder.feed(b"\x00" + tcp_event[0].frame, at_ms=tcp_event[0].at_ms)
        returned = next(item.frame for item in frames if item.kind == "frame")
        returned_expected = bytearray(reverse)
        returned_expected[route_ttl_offset(reverse)] -= 0x20
        self.assertEqual(returned, bytes(returned_expected))

    def test_stream_candidate_timeout_discards_partial_and_resynchronizes(self):
        router = MixedPathRouter(MANIFEST)
        router.start_tcp(lambda: None)
        frame = protected_frame(source=10, destination=20, seq=303)
        wire = encode_stream_r(frame, max_core=256, max_encoded=263)
        first = router.feed_tcp(b"\x00" + wire[:3], at_ms=0)
        self.assertEqual(first, ())
        expired = router.feed_tcp(wire[3:] + b"\x00", at_ms=27)
        self.assertTrue(any(event.kind == "discarded" for event in expired))
        self.assertFalse(any(event.kind == "packet_frame" for event in expired))

    def test_pair_gate_serializes_both_directions_services_and_bootstrap(self):
        router = MixedPathRouter(MANIFEST)
        first_events = self.send_tcp(router, protected_frame(
            source=10, destination=20, seq=401, message_type=7, service_id=1,
        ), at_ms=0)
        second_events = router.feed_packet(protected_frame(
            source=20, destination=10, seq=402, message_type=7, service_id=2,
        ), at_ms=0)
        third_events = self.send_tcp(router, protected_frame(
            source=10, destination=20, seq=403, message_type=3, service_id=1,
        ), at_ms=64)
        all_events = self.advance_pending(
            router, (*first_events, *second_events, *third_events)
        )
        first, second, third = all_events

        self.assertEqual(self.scheduled_start(first), 0)
        self.assertEqual(self.scheduled_start(second), 64)
        self.assertEqual(self.scheduled_start(third), 128)
        self.assertEqual([first.kind, second.kind, third.kind],
                         ["packet_frame", "tcp_stream", "packet_frame"])

    def test_oversized_packet_ingress_is_rejected_before_reservation_or_retention(self):
        router = MixedPathRouter(MANIFEST)
        oversized = protected_frame(
            source=20, destination=10, seq=404, payload_size=100_000,
        )
        self.assertGreater(len(oversized), 256)

        events = router.feed_packet(oversized, at_ms=0)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "rejected")
        self.assertIn("core MTU", events[0].reason)
        self.assertEqual(router._pending, [])
        self.assertEqual(router._data_slots, set())
        self.assertEqual(router._control_slots, {})
        self.assertEqual(router._next_ordinal, 0)

    def test_each_data_reservation_has_two_reverse_ack_feedback_opportunities(self):
        router = MixedPathRouter(MANIFEST)
        data = self.send_tcp(router, protected_frame(
            source=10, destination=20, seq=410, message_type=7,
        ), at_ms=0)
        data = self.advance_pending(router, data)[0]
        self.assertEqual(self.scheduled_start(data), 0)

        ack_events = router.feed_packet(protected_frame(
            source=20, destination=10, seq=411, message_type=6,
        ), at_ms=22)
        ack = self.advance_pending(router, ack_events)[0]
        feedback_events = router.feed_packet(protected_frame(
            source=20, destination=10, seq=412, message_type=8,
        ), at_ms=43)
        feedback = self.advance_pending(router, feedback_events)[0]
        self.assertEqual(self.scheduled_start(ack), 22)
        self.assertEqual(self.scheduled_start(feedback), 43)

        exhausted_events = router.feed_packet(protected_frame(
            source=20, destination=10, seq=413, message_type=6,
        ), at_ms=51, not_after_ms=52)
        exhausted = exhausted_events[0]
        self.assertEqual(exhausted.kind, "rejected")
        self.assertIn("deadline", exhausted.reason)

        stale_events = router.feed_packet(protected_frame(
            source=20, destination=10, seq=417, message_type=6,
        ), at_ms=70)
        stale = stale_events[0]
        self.assertEqual(stale.kind, "rejected")
        self.assertIn("no reverse-control reservation", stale.reason)

        reverse_router = MixedPathRouter(MANIFEST)
        reverse_data_events = reverse_router.feed_packet(protected_frame(
            source=20, destination=10, seq=414, message_type=3,
        ), at_ms=64)
        reverse_data = self.advance_pending(reverse_router, reverse_data_events)[0]
        self.assertEqual(self.scheduled_start(reverse_data), 64)
        reverse_ack_events = self.send_tcp(reverse_router, protected_frame(
            source=10, destination=20, seq=415, message_type=6,
        ), at_ms=86)
        reverse_ack = self.advance_pending(reverse_router, reverse_ack_events)[0]
        reverse_feedback_events = self.send_tcp(reverse_router, protected_frame(
            source=10, destination=20, seq=416, message_type=8,
        ), at_ms=107)
        reverse_feedback = self.advance_pending(reverse_router, reverse_feedback_events)[0]
        self.assertEqual(self.scheduled_start(reverse_ack), 86)
        self.assertEqual(self.scheduled_start(reverse_feedback), 107)

    def test_latest_start_deadline_and_one_period_queue_refuse_without_a_slot(self):
        deadline_router = MixedPathRouter(MANIFEST)
        first_events = self.send_tcp(deadline_router, protected_frame(
            source=10, destination=20, seq=420,
        ), at_ms=0)
        expired_events = self.send_tcp(deadline_router, protected_frame(
            source=10, destination=20, seq=421,
        ), at_ms=0, not_after_ms=64)
        self.assertEqual(len(first_events), 0)
        expired = expired_events[0]
        self.assertEqual(expired.kind, "rejected")
        self.assertIn("deadline", expired.reason)

        full_router = MixedPathRouter(MANIFEST)
        first_events = self.send_tcp(full_router, protected_frame(
            source=10, destination=20, seq=430,
        ), at_ms=0)
        queued_events = full_router.feed_packet(protected_frame(
            source=20, destination=10, seq=431,
        ), at_ms=0)
        refused_events = self.send_tcp(full_router, protected_frame(
            source=10, destination=20, seq=432,
        ), at_ms=0)
        queued_events = self.advance_pending(
            full_router, (*first_events, *queued_events)
        )
        self.assertEqual(len(queued_events), 2)
        first, queued = queued_events
        self.assertEqual(self.scheduled_start(first), 0)
        self.assertEqual(self.scheduled_start(queued), 64)
        refused = refused_events[0]
        self.assertEqual(refused.kind, "rejected")
        self.assertIn("queue is full", refused.reason)

    def test_future_source_reservation_cannot_open_control_before_traversal(self):
        router = MixedPathRouter(MANIFEST)
        self.send_tcp(router, protected_frame(
            source=10, destination=20, seq=440,
        ), at_ms=0)
        router.feed_packet(protected_frame(
            source=20, destination=10, seq=441,
        ), at_ms=0)

        # The t=0 source reservation has completed, so both reverse slots work.
        first_control = router.feed_packet(protected_frame(
            source=20, destination=10, seq=442, message_type=6,
        ), at_ms=22)
        first_control = next(
            event for event in self.advance_until(router, first_control, "tcp_stream")
            if event.kind == "tcp_stream"
        )
        self.assertEqual(self.scheduled_start(first_control), 22)
        second_control = router.feed_packet(protected_frame(
            source=20, destination=10, seq=443, message_type=8,
        ), at_ms=43)
        second_control = next(
            event for event in self.advance_until(router, second_control, "tcp_stream")
            if event.kind == "tcp_stream"
        )
        self.assertEqual(self.scheduled_start(second_control), 43)

        # A second source frame is reserved for t=64. Its traversal ends at 85;
        # a control arriving at 70 cannot consume its t=86 opportunity early.
        early = self.send_tcp(router, protected_frame(
            source=10, destination=20, seq=444, message_type=6,
        ), at_ms=70)[0]
        self.assertEqual(early.kind, "rejected")
        self.assertIn("source traversal has not completed", early.reason)

        router.advance(72)
        admitted_events = self.send_tcp(router, protected_frame(
            source=10, destination=20, seq=445, message_type=6,
        ), at_ms=85)
        admitted = self.advance_pending(router, admitted_events)[0]
        self.assertEqual(admitted.kind, "packet_frame")
        self.assertEqual(self.scheduled_start(admitted), 86)

    def test_sec1_freshness_exchange_crosses_the_mixed_path_both_directions(self):
        router = MixedPathRouter(MANIFEST)
        bridge_sync = router.start_tcp(lambda: None)
        client_sync_pending = True
        return_decoder = StreamRDecoder(
            max_encoded=263, max_core=256, candidate_timeout_ms=26, await_sync=True
        )
        return_sync_pending = True

        def make_endpoint(node_id: int, entropy_offset: int) -> PeerEndpoint:
            return PeerEndpoint(
                manifest_bytes=MANIFEST,
                test_credentials={"node_id": node_id, "psk": b"\x01" * 32},
                entropy_source=lambda size: bytes((index + entropy_offset) % 256
                                                  for index in range(size)),
                test_services={},
            )

        stream_endpoint = make_endpoint(10, 1)
        packet_endpoint = make_endpoint(20, 2)
        stream_endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        packet_endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        last_delivery_ms = -1

        def settle(endpoint: PeerEndpoint, events, at_ms: int) -> list[bytes]:
            wires = [event.bytes for event in events or () if isinstance(event, TxSubmit)]
            while endpoint.active_submissions:
                for handle, submission in list(endpoint.active_submissions.items()):
                    if not submission["admitted"]:
                        endpoint.handle(TxAdmit(
                            handle, submission["generation"], True, None, at_ms
                        ))
                    terminal = endpoint.handle(TxTerminal(
                        handle, submission["generation"], "transmitted", at_ms + 1
                    ))
                    wires.extend(item.bytes for item in terminal if isinstance(item, TxSubmit))
                    at_ms += 2
            return wires

        def from_stream(core: bytes, at_ms: int) -> bytes:
            nonlocal client_sync_pending, last_delivery_ms
            prefix = b"\x00" if client_sync_pending else b""
            client_sync_pending = False
            events = router.feed_tcp(
                prefix + encode_stream_r(core, max_core=256, max_encoded=263), at_ms=at_ms
            )
            events = list(events)
            while not any(event.kind == "packet_frame" for event in events):
                if not router._pending:
                    raise AssertionError([event.kind + ":" + (event.reason or "") for event in events])
                due = min(item.completion_ms for item in router._pending)
                events.extend(router.advance(max(router._last_ms, due)))
            frames = [event for event in events if event.kind == "packet_frame"]
            if len(frames) != 1:
                raise AssertionError([event.kind + ":" + (event.reason or "") for event in events])
            last_delivery_ms = frames[0].at_ms
            return frames[0].frame

        def from_packet(core: bytes, at_ms: int) -> tuple[bytes, int]:
            nonlocal return_sync_pending, last_delivery_ms
            events = list(router.feed_packet(core, at_ms=at_ms))
            while not any(event.kind == "tcp_stream" for event in events):
                if not router._pending:
                    raise AssertionError(events)
                due = min(item.completion_ms for item in router._pending)
                events.extend(router.advance(max(router._last_ms, due)))
            matching = [event for event in events if event.kind == "tcp_stream"]
            if len(matching) != 1 or matching[0].frame is None:
                raise AssertionError(events)
            event = matching[0]
            last_delivery_ms = event.at_ms
            prefix = bridge_sync if return_sync_pending else b""
            return_sync_pending = False
            decoded = return_decoder.feed(prefix + event.frame, at_ms=event.at_ms)
            frames = [item.frame for item in decoded if item.kind == "frame"]
            if len(frames) != 1:
                raise AssertionError(decoded)
            return frames[0], event.at_ms

        first = settle(stream_endpoint, stream_endpoint.initiate_handshake(at_ms=100), 101)
        self.assertEqual(len(first), 1)
        self.assertIsNotNone(parse_frame(first[0]).route)
        self.assertTrue(any(ext.extension_id == 2 for ext in parse_frame(first[0]).extensions))

        second = settle(
            packet_endpoint,
            packet_endpoint.handle(Receive(
                link=0, bytes=from_stream(first[0], 110), at_ms=last_delivery_ms + 1
            )),
            last_delivery_ms + 2,
        )
        self.assertEqual(len(second), 1)
        third_core, third_at = from_packet(second[0], 200)
        third = settle(
            stream_endpoint,
            stream_endpoint.handle(Receive(link=0, bytes=third_core, at_ms=third_at + 1)),
            third_at + 2,
        )
        self.assertEqual(len(third), 1)
        fourth = settle(
            packet_endpoint,
            packet_endpoint.handle(Receive(
                link=0, bytes=from_stream(third[0], 300), at_ms=last_delivery_ms + 1
            )),
            last_delivery_ms + 2,
        )
        self.assertEqual(len(fourth), 1)
        ready_core, ready_at = from_packet(fourth[0], 400)
        stream_endpoint.handle(Receive(link=0, bytes=ready_core, at_ms=ready_at + 1))
        self.assertEqual(stream_endpoint.association.status, "active")
        self.assertEqual(packet_endpoint.association.status, "active")

        request_wires = settle(
            stream_endpoint,
            stream_endpoint.handle(ApplicationRequest(
                service_id=0,
                payload=b"\x10" + (12_000).to_bytes(4, "little"),
                ack_req=True,
                at_ms=500,
            )),
            501,
        )
        self.assertEqual(len(request_wires), 1)
        self.assertIsNotNone(parse_frame(request_wires[0]).security)
        grant_events = packet_endpoint.handle(Receive(
            link=0, bytes=from_stream(request_wires[0], 510), at_ms=last_delivery_ms + 1
        ))
        grants = settle(packet_endpoint, grant_events, last_delivery_ms + 2)
        self.assertGreaterEqual(len(grants), 1)
        self.assertTrue(all(parse_frame(wire).security is not None for wire in grants))

        for index, grant in enumerate(grants):
            packet_at = max(600 + index * 64, router._last_ms + 1)
            returned, received_at = from_packet(grant, packet_at)
            self.assertIsNotNone(parse_frame(returned).security)
            received = stream_endpoint.handle(Receive(
                link=0, bytes=returned, at_ms=received_at + 1
            ))
            receipts = settle(stream_endpoint, received, received_at + 2)
            source_start = received_at - 8
            for receipt_index, receipt in enumerate(receipts):
                control_at = max(source_start + 21, router._last_ms + 1)
                packet = from_stream(receipt, control_at)
                self.assertIsNotNone(parse_frame(receipt).security)
                packet_endpoint.handle(Receive(
                    link=0, bytes=packet, at_ms=last_delivery_ms + 1
                ))
        self.assertIsNotNone(stream_endpoint.active_freshness_token)


if __name__ == "__main__":
    unittest.main()
