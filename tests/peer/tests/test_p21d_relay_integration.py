"""S10.06 protected endpoint recovery through the RADIO-1 relay path."""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

from dmp_peer.events import Advance, ApplicationEvent, ApplicationRequest, Open, PublishSample, Receive, TxAdmit, TxSubmit, TxTerminal
from dmp_peer.frame import encode_uleb, parse_frame
from dmp_peer.relay import RelayDecision, TransparentRelay
from dmp_peer.testing import PeerEndpoint


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = (ROOT / "profiles" / "deployments" / "radio-nnpsk0.json").read_bytes()


def extract_and_settle(
    endpoint: PeerEndpoint,
    events: tuple[Any, ...] | list[Any] | None = None,
    *,
    at_ms: int,
) -> list[bytes]:
    wires = [event.bytes for event in events or () if isinstance(event, TxSubmit)]
    while endpoint.active_submissions:
        for handle, submission in list(endpoint.active_submissions.items()):
            if not submission.get("admitted"):
                endpoint.handle(TxAdmit(
                    handle=handle,
                    generation=submission["generation"],
                    accepted=True,
                    reason=None,
                    at_ms=at_ms,
                ))
            terminal = endpoint.handle(TxTerminal(
                handle=handle,
                generation=submission["generation"],
                outcome="transmitted",
                at_ms=at_ms,
            ))
            wires.extend(event.bytes for event in terminal if isinstance(event, TxSubmit))
    return wires


def ttl_offset(frame: bytes) -> int:
    parsed = parse_frame(frame)
    return 3 + len(encode_uleb(parsed.sequence))


def expected_ttl_forward(frame: bytes) -> bytes:
    parsed = parse_frame(frame)
    result = bytearray(frame)
    offset = ttl_offset(frame)
    result[offset] = ((parsed.route.ttl - 1) << 4) | (result[offset] & 0x0F)
    return bytes(result)


class P21DRelayRecoveryIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        # Forward path 20->10 is relay 40 then 30; return path is 30 then 40.
        self.relays = {node: TransparentRelay(MANIFEST, node) for node in (30, 40)}
        self.initiator, self.responder = self._pair_and_handshake()

    def _pair_and_handshake(self) -> tuple[PeerEndpoint, PeerEndpoint]:
        initiator = PeerEndpoint(
            manifest_bytes=MANIFEST,
            test_credentials={"node_id": 20, "psk": b"\x01" * 32},
            entropy_source=lambda size: bytes((i + 2) % 256 for i in range(size)),
            test_services={},
        )
        responder = PeerEndpoint(
            manifest_bytes=MANIFEST,
            test_credentials={"node_id": 10, "psk": b"\x01" * 32},
            entropy_source=lambda size: bytes((i + 1) % 256 for i in range(size)),
            test_services={},
        )
        for endpoint in (initiator, responder):
            endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))

        flight1 = extract_and_settle(initiator, initiator.initiate_handshake(at_ms=100), at_ms=101)
        self.assertEqual(len(flight1), 1)
        flight2 = extract_and_settle(
            responder, responder.handle(Receive(link=0, bytes=flight1[0], at_ms=110)), at_ms=111
        )
        self.assertEqual(len(flight2), 1)
        finish = extract_and_settle(
            initiator, initiator.handle(Receive(link=0, bytes=flight2[0], at_ms=120)), at_ms=121
        )
        self.assertEqual(len(finish), 1)
        ready = extract_and_settle(
            responder, responder.handle(Receive(link=0, bytes=finish[0], at_ms=130)), at_ms=131
        )
        self.assertEqual(len(ready), 1)
        initiator.handle(Receive(link=0, bytes=ready[0], at_ms=140))
        self.assertEqual(initiator.association.status, "active")
        self.assertEqual(responder.association.status, "active")
        return initiator, responder

    def _grant_service2_freshness(self) -> None:
        request = extract_and_settle(
            self.initiator,
            self.initiator.handle(ApplicationRequest(
                service_id=0,
                payload=b"\x10" + (12_000).to_bytes(4, "little"),
                ack_req=True,
                at_ms=200,
            )),
            at_ms=201,
        )
        self.assertEqual(len(request), 1)
        grant = extract_and_settle(
            self.responder,
            self.responder.handle(Receive(link=0, bytes=request[0], at_ms=210)),
            at_ms=211,
        )
        self.assertGreaterEqual(len(grant), 1)
        receipts: list[bytes] = []
        for offset, wire in enumerate(grant):
            events = self.initiator.handle(Receive(link=0, bytes=wire, at_ms=220 + offset))
            receipts.extend(extract_and_settle(self.initiator, events, at_ms=221 + offset))
        for offset, wire in enumerate(receipts):
            self.responder.handle(Receive(link=0, bytes=wire, at_ms=222 + offset))
        self.assertIsNotNone(self.initiator.active_freshness_token)

    def _traverse(self, frame: bytes, *, source: int, at_ms: int) -> tuple[bytes, int]:
        path = (40, 30) if source == 20 else (30, 40)
        current = frame
        now = at_ms
        for node in path:
            relay = self.relays[node]
            decision: RelayDecision = relay.receive(current, now)
            self.assertTrue(decision.forwarded, (node, decision.reason))
            self.assertEqual(decision.frame, expected_ttl_forward(current))
            relay.complete(decision.token, now + 1, transmitted=True)
            current = decision.frame
            now += 2
        return current, now

    def test_selective_fragment_repair_crosses_relays_with_fresh_pn(self) -> None:
        """S10.06: endpoint reassembly and fresh-PN repair traverse bounded relay state."""
        self._grant_service2_freshness()
        payload = bytes((index % 256) ^ 0x5A for index in range(1024))
        initial = extract_and_settle(
            self.initiator,
            self.initiator.handle(ApplicationRequest(
                service_id=2, payload=payload, ack_req=True, at_ms=230
            )),
            at_ms=231,
        )
        self.assertEqual(len(initial), 32)
        initial_frames = [parse_frame(wire) for wire in initial]
        self.assertTrue(all(frame.security is not None and frame.route is not None for frame in initial_frames))
        sequence = initial_frames[0].sequence
        self.assertTrue(all(frame.sequence == sequence for frame in initial_frames))

        missing_index = 2
        first_arrival_ms = 300
        for index, wire in enumerate(initial):
            forwarded, arrived = self._traverse(wire, source=20, at_ms=first_arrival_ms + index * 10)
            self.assertEqual(parse_frame(forwarded).route.ttl, 0)
            if index != missing_index:
                events = self.responder.handle(Receive(link=0, bytes=forwarded, at_ms=arrived + 1))
                self.assertFalse(any(
                    isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
                    for event in events
                ))

        key = (1, 20, self.initiator.association.local_epoch, sequence)
        session = self.responder.reassembly.active[key]
        self.assertEqual(session.received_indices, set(range(32)) - {missing_index})
        self.assertNotIn(key, self.responder.delivery.accepted_messages)

        status_due = session.selective_feedback_due_ms
        self.assertIsNotNone(status_due)
        status = extract_and_settle(
            self.responder,
            self.responder.handle(Advance(now_ms=status_due)),
            at_ms=status_due + 1,
        )
        self.assertEqual(len(status), 1)
        self.assertEqual(parse_frame(status[0]).message_type, 8)
        status_at_endpoint, arrived = self._traverse(status[0], source=10, at_ms=status_due + 2)
        self.assertEqual(parse_frame(status_at_endpoint).route.ttl, 0)
        feedback = self.initiator.handle(Receive(link=0, bytes=status_at_endpoint, at_ms=arrived + 1))
        self.assertFalse(any(isinstance(event, ApplicationEvent) for event in feedback))

        transfer = next(iter(self.initiator.delivery.active_outgoing.values()))
        self.assertEqual(transfer.selective_state.pending_mask, 1 << missing_index)
        repair_at = transfer.selective_state.started_at_ms + 4352
        repairs = extract_and_settle(
            self.initiator,
            self.initiator.handle(Advance(now_ms=repair_at)),
            at_ms=repair_at + 1,
        )
        self.assertEqual(len(repairs), 1)
        repaired_frame = parse_frame(repairs[0])
        self.assertEqual(repaired_frame.fragment.index, missing_index)
        self.assertGreater(
            repaired_frame.security.packet_number,
            initial_frames[missing_index].security.packet_number,
        )

        forwarded_repair, arrived = self._traverse(repairs[0], source=20, at_ms=repair_at + 2)
        self.assertEqual(parse_frame(forwarded_repair).route.ttl, 0)
        repaired_events = self.responder.handle(
            Receive(link=0, bytes=forwarded_repair, at_ms=arrived + 1)
        )
        accepted = [
            event for event in repaired_events
            if isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
        ]
        self.assertEqual(len(accepted), 1)
        self.assertEqual(accepted[0].payload, payload)
        self.assertIn(key, self.responder.delivery.accepted_messages)

    def test_fragmented_result_and_result_ack_cross_return_relays(self) -> None:
        self._grant_service2_freshness()
        payload = bytes((index % 256) ^ 0x5A for index in range(1024))
        request = extract_and_settle(
            self.initiator,
            self.initiator.handle(ApplicationRequest(
                service_id=2, payload=payload, ack_req=True, at_ms=230
            )),
            at_ms=231,
        )
        self.assertEqual(len(request), 32)

        responder_wires: list[bytes] = []
        for index, wire in enumerate(request):
            arrived, arrival_time = self._traverse(wire, source=20, at_ms=300 + index * 20)
            received = self.responder.handle(Receive(
                link=0, bytes=arrived, at_ms=arrival_time + 1
            ))
            responder_wires.extend(extract_and_settle(
                self.responder, received, at_ms=arrival_time + 2
            ))

        response_types = [parse_frame(wire).message_type for wire in responder_wires]
        # A complete reliable result is a permitted immediate receipt, so this
        # path returns the result burst without a separate request ACK.
        self.assertEqual(response_types, [1] * 32)
        self.assertTrue(all(
            parse_frame(wire).route is not None
            and {ext.extension_id for ext in parse_frame(wire).extensions} >= {1, 2, 4}
            for wire in responder_wires
        ))

        request_result_events: list[ApplicationEvent] = []
        result_ack_wires: list[bytes] = []
        for index, wire in enumerate(responder_wires):
            arrived, arrival_time = self._traverse(wire, source=10, at_ms=1200 + index * 20)
            received = self.initiator.handle(Receive(
                link=0, bytes=arrived, at_ms=arrival_time + 1
            ))
            request_result_events.extend(
                event for event in received
                if isinstance(event, ApplicationEvent) and event.kind == "request_result"
            )
            result_ack_wires.extend(extract_and_settle(
                self.initiator, received, at_ms=arrival_time + 2
            ))

        expected_result = bytes((index % 256) ^ 0xA5 for index in range(1024))
        self.assertEqual(len(request_result_events), 1)
        self.assertEqual(request_result_events[0].payload, expected_result)
        self.assertEqual(len(result_ack_wires), 1)
        result_ack = parse_frame(result_ack_wires[0])
        self.assertEqual(result_ack.message_type, 6)
        self.assertIsNotNone(result_ack.route)
        self.assertEqual({ext.extension_id for ext in result_ack.extensions}, {1, 2, 4})

        ack_at_endpoint, arrived = self._traverse(
            result_ack_wires[0], source=20, at_ms=2200
        )
        self.responder.handle(Receive(link=0, bytes=ack_at_endpoint, at_ms=arrived + 1))
        retained = next(iter(self.responder.delivery.retained_results.values()))
        self.assertTrue(retained.acknowledged)

    def test_telem_keeps_its_explicit_route_through_both_relays(self) -> None:
        sample_events = self.responder.handle(PublishSample(value=4321, at_ms=200))
        telemetry = extract_and_settle(self.responder, sample_events, at_ms=201)
        self.assertEqual(len(telemetry), 1)
        parsed = parse_frame(telemetry[0])
        self.assertEqual(parsed.message_type, 5)
        self.assertIsNotNone(parsed.route)
        self.assertEqual({ext.extension_id for ext in parsed.extensions}, {2})

        arrived_frame, arrived_at = self._traverse(
            telemetry[0], source=10, at_ms=300
        )
        self.assertEqual(parse_frame(arrived_frame).route.ttl, 0)
        self.initiator.handle(Receive(
            link=0, bytes=arrived_frame, at_ms=arrived_at + 1
        ))


if __name__ == "__main__":
    unittest.main()
