"""P21D recovery matrix cases for the frozen authenticated XX radio profiles."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import x25519

from dmp_peer.events import Advance, ApplicationEvent, ApplicationRequest, Open, Receive, TxAdmit, TxSubmit, TxTerminal
from dmp_peer.frame import decode_uleb, parse_frame
from dmp_peer.testing import PeerEndpoint


ROOT = Path(__file__).resolve().parents[3]


def manifest_bytes(name: str) -> bytes:
    return (ROOT / "profiles" / "deployments" / name).read_bytes()


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


def send_receive(
    endpoint: PeerEndpoint,
    wires: list[bytes],
    *,
    start_ms: int,
) -> tuple[list[Any], list[bytes]]:
    received_events: list[Any] = []
    response_wires: list[bytes] = []
    for offset, wire in enumerate(wires):
        received = endpoint.handle(Receive(link=0, bytes=wire, at_ms=start_ms + offset))
        received_events.extend(received)
        response_wires.extend(extract_and_settle(
            endpoint, received, at_ms=start_ms + offset + 1
        ))
    return received_events, response_wires


class P21DXXRadioMatrixTests(unittest.TestCase):
    def pair(self, profile: str) -> tuple[PeerEndpoint, PeerEndpoint]:
        manifest = manifest_bytes(profile)
        initiator_private = b"\x10" * 32
        responder_private = b"\x20" * 32
        initiator_public = x25519.X25519PrivateKey.from_private_bytes(
            initiator_private
        ).public_key().public_bytes_raw()
        responder_public = x25519.X25519PrivateKey.from_private_bytes(
            responder_private
        ).public_key().public_bytes_raw()

        initiator = PeerEndpoint(
            manifest_bytes=manifest,
            test_credentials={
                "node_id": 20,
                "static_private_key": initiator_private,
                "peer_static_public_key": responder_public,
            },
            entropy_source=lambda size: bytes((i + 2) % 256 for i in range(size)),
            test_services={},
        )
        responder = PeerEndpoint(
            manifest_bytes=manifest,
            test_credentials={
                "node_id": 10,
                "static_private_key": responder_private,
                "peer_static_public_key": initiator_public,
            },
            entropy_source=lambda size: bytes((i + 1) % 256 for i in range(size)),
            test_services={},
        )

        initiator_open = extract_and_settle(
            initiator,
            initiator.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10)),
            at_ms=11,
        )
        responder_open = extract_and_settle(
            responder,
            responder.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10)),
            at_ms=11,
        )
        for wire in initiator_open:
            responder.handle(Receive(link=0, bytes=wire, at_ms=12))
        for wire in responder_open:
            initiator.handle(Receive(link=0, bytes=wire, at_ms=12))

        flight1 = extract_and_settle(
            initiator, initiator.initiate_handshake(at_ms=100), at_ms=101
        )
        self.assertEqual(len(flight1), 1)
        flight2 = extract_and_settle(
            responder,
            responder.handle(Receive(link=0, bytes=flight1[0], at_ms=110)),
            at_ms=111,
        )
        self.assertEqual(len(flight2), 1)
        flight3_and_finish = extract_and_settle(
            initiator,
            initiator.handle(Receive(link=0, bytes=flight2[0], at_ms=120)),
            at_ms=121,
        )
        self.assertEqual(len(flight3_and_finish), 2)
        for wire in flight3_and_finish:
            response = responder.handle(Receive(link=0, bytes=wire, at_ms=130))
            for ready in extract_and_settle(responder, response, at_ms=131):
                initiator.handle(Receive(link=0, bytes=ready, at_ms=140))

        self.assertEqual(initiator.manifest.values["security"]["mode"], "XX")
        self.assertEqual(responder.manifest.values["security"]["mode"], "XX")
        self.assertEqual(initiator.association.status, "active")
        self.assertEqual(responder.association.status, "active")
        return initiator, responder

    def grant_service2_freshness(
        self, initiator: PeerEndpoint, responder: PeerEndpoint
    ) -> None:
        request = extract_and_settle(
            initiator,
            initiator.handle(ApplicationRequest(
                service_id=0,
                payload=b"\x10" + (12_000).to_bytes(4, "little"),
                ack_req=True,
                at_ms=200,
            )),
            at_ms=201,
        )
        self.assertEqual(len(request), 1)
        grant = extract_and_settle(
            responder,
            responder.handle(Receive(link=0, bytes=request[0], at_ms=210)),
            at_ms=211,
        )
        self.assertGreaterEqual(len(grant), 1)
        receipts: list[bytes] = []
        for offset, wire in enumerate(grant):
            response = initiator.handle(Receive(link=0, bytes=wire, at_ms=220 + offset))
            receipts.extend(extract_and_settle(
                initiator, response, at_ms=221 + offset
            ))
        for offset, wire in enumerate(receipts):
            responder.handle(Receive(link=0, bytes=wire, at_ms=230 + offset))
        self.assertIsNotNone(initiator.active_freshness_token)

    def test_radio_xx_repairs_only_missing_protected_selective_fragments(self) -> None:
        profile = manifest_bytes("radio-xx.json")
        self.assertEqual(
            hashlib.sha256(profile).hexdigest(),
            "b27b06ee7ad0a0d51e79cf894a373bf2b74d9f9b3674b24b9256418b9141641a",
        )
        initiator, responder = self.pair("radio-xx.json")
        self.grant_service2_freshness(initiator, responder)

        payload = bytes((index % 256) ^ 0x5A for index in range(1024))
        initial = extract_and_settle(
            initiator,
            initiator.handle(ApplicationRequest(
                service_id=2, payload=payload, ack_req=True, at_ms=230
            )),
            at_ms=231,
        )
        self.assertEqual(len(initial), 32)
        self.assertTrue(all(parse_frame(wire).security is not None for wire in initial))
        self.assertTrue(all(parse_frame(wire).security.cipher == 1 for wire in initial))
        sequence = parse_frame(initial[0]).sequence
        selective_exchange = next(
            exchange for exchange in initiator.delivery.active_outgoing.values()
            if exchange.seq == sequence
        )
        self.assertIsNotNone(selective_exchange.selective_state)

        missing = {2, 6}
        partial_events, _ = send_receive(
            responder,
            [wire for wire in initial if parse_frame(wire).fragment.index not in missing],
            start_ms=300,
        )
        self.assertFalse(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in partial_events
        ))
        assembly_key = (1, initiator.local_node_id, initiator.association.local_epoch, sequence)
        assembly = responder.reassembly.active[assembly_key]
        self.assertEqual(assembly.received_indices, set(range(32)) - missing)
        self.assertIsNotNone(
            assembly.selective_feedback_due_ms,
            msg=(
                f"XX selective feedback was not scheduled; message_types="
                f"{sorted({parse_frame(wire).message_type for wire in initial})}, "
                f"received={sorted(assembly.received_indices)}, events={partial_events!r}"
            ),
        )

        feedback_at = assembly.selective_feedback_due_ms
        status_events = responder.handle(Advance(now_ms=feedback_at))
        status_wires = extract_and_settle(responder, status_events, at_ms=feedback_at + 1)
        self.assertEqual(len(status_wires), 1)
        status = parse_frame(status_wires[0])
        self.assertEqual(status.message_type, 8)
        self.assertIsNotNone(status.security)
        self.assertEqual(status.security.cipher, 1)

        initiator.handle(Receive(link=0, bytes=status_wires[0], at_ms=feedback_at + 2))
        sender_state = selective_exchange.selective_state
        repair_at = sender_state.started_at_ms + 4352
        repairs = extract_and_settle(
            initiator, initiator.handle(Advance(now_ms=repair_at)), at_ms=repair_at + 1
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in repairs], [2, 6])
        self.assertTrue(all(parse_frame(wire).security is not None for wire in repairs))
        self.assertTrue(all(parse_frame(wire).security.cipher == 1 for wire in repairs))
        self.assertTrue(all(parse_frame(wire).sequence == sequence for wire in repairs))
        repaired_events, _ = send_receive(responder, repairs, start_ms=repair_at + 10)
        self.assertTrue(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in repaired_events
        ))

    def test_radio_xx_repairs_large_request_and_result_with_stable_identity(self) -> None:
        initiator, responder = self.pair("radio-xx.json")
        self.grant_service2_freshness(initiator, responder)
        payload = bytes((index % 256) ^ 0x5A for index in range(1024))
        request_wires = extract_and_settle(
            initiator,
            initiator.handle(ApplicationRequest(
                service_id=2, payload=payload, ack_req=True, at_ms=230
            )),
            at_ms=231,
        )
        self.assertEqual(len(request_wires), 32)
        request_frames = [parse_frame(wire) for wire in request_wires]
        request_seq = request_frames[0].sequence
        self.assertTrue(all(frame.sequence == request_seq for frame in request_frames))
        self.assertTrue(all(frame.security is not None and frame.security.cipher == 1
                            for frame in request_frames))
        request_exchange = next(
            exchange for exchange in initiator.delivery.active_outgoing.values()
            if exchange.seq == request_seq
        )
        self.assertIsNotNone(request_exchange.selective_state)

        missing_request = {2, 6}
        partial_request_events, _ = send_receive(
            responder,
            [wire for wire in request_wires
             if parse_frame(wire).fragment.index not in missing_request],
            start_ms=300,
        )
        self.assertFalse(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in partial_request_events
        ))
        request_key = (
            1, initiator.local_node_id, initiator.association.local_epoch, request_seq
        )
        request_assembly = responder.reassembly.active[request_key]
        self.assertEqual(
            request_assembly.received_indices, set(range(32)) - missing_request
        )
        request_feedback_at = request_assembly.selective_feedback_due_ms
        self.assertIsNotNone(request_feedback_at)
        request_status_events = responder.handle(Advance(now_ms=request_feedback_at))
        request_status_wires = extract_and_settle(
            responder, request_status_events, at_ms=request_feedback_at + 1
        )
        self.assertEqual(len(request_status_wires), 1)
        request_status = parse_frame(request_status_wires[0])
        self.assertEqual(request_status.message_type, 8)
        self.assertTrue(request_status.security is not None
                        and request_status.security.cipher == 1)

        initiator.handle(Receive(
            link=0, bytes=request_status_wires[0], at_ms=request_feedback_at + 2
        ))
        request_state = request_exchange.selective_state
        request_repair_at = request_state.started_at_ms + 4352
        request_repairs = extract_and_settle(
            initiator,
            initiator.handle(Advance(now_ms=request_repair_at)),
            at_ms=request_repair_at + 1,
        )
        request_repair_frames = [parse_frame(wire) for wire in request_repairs]
        self.assertEqual([frame.fragment.index for frame in request_repair_frames], [2, 6])
        self.assertTrue(all(frame.sequence == request_seq for frame in request_repair_frames))
        self.assertTrue(all(frame.security is not None and frame.security.cipher == 1
                            for frame in request_repair_frames))
        request_initial_pns = [frame.security.packet_number for frame in request_frames]
        request_repair_pns = [frame.security.packet_number for frame in request_repair_frames]
        self.assertTrue(all(pn > max(request_initial_pns) for pn in request_repair_pns))
        self.assertEqual(len(set(request_repair_pns)), len(request_repair_pns))

        request_result_events, request_return = send_receive(
            responder, request_repairs, start_ms=request_repair_at + 10
        )
        self.assertTrue(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in request_result_events
        ))
        result_wires = [
            wire for wire in request_return if parse_frame(wire).message_type == 1
        ]
        self.assertEqual(len(result_wires), 32)
        result_frames = [parse_frame(wire) for wire in result_wires]
        result_seq = result_frames[0].sequence
        self.assertTrue(all(frame.sequence == result_seq for frame in result_frames))
        self.assertTrue(all(frame.security is not None and frame.security.cipher == 1
                            for frame in result_frames))

        missing_result = {1, 4}
        partial_result_events, _ = send_receive(
            initiator,
            [wire for wire in result_wires
             if parse_frame(wire).fragment.index not in missing_result],
            start_ms=request_repair_at + 30,
        )
        self.assertFalse(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_result"
            for event in partial_result_events
        ))
        retained = next(
            item for item in responder.delivery.retained_results.values()
            if item.service_id == 2 and item.req_seq == request_seq
        )
        self.assertEqual(retained.result_seq, result_seq)
        result_key = (
            1, responder.local_node_id, responder.association.local_epoch, result_seq
        )
        result_assembly = initiator.reassembly.active[result_key]
        self.assertEqual(
            result_assembly.received_indices, set(range(32)) - missing_result
        )
        result_feedback_at = result_assembly.selective_feedback_due_ms
        self.assertIsNotNone(result_feedback_at)
        result_status_events = initiator.handle(Advance(now_ms=result_feedback_at))
        result_status_wires = extract_and_settle(
            initiator, result_status_events, at_ms=result_feedback_at + 1
        )
        self.assertEqual(len(result_status_wires), 1)
        result_status = parse_frame(result_status_wires[0])
        self.assertEqual(result_status.message_type, 8)
        self.assertTrue(result_status.security is not None
                        and result_status.security.cipher == 1)

        responder.handle(Receive(
            link=0, bytes=result_status_wires[0], at_ms=result_feedback_at + 2
        ))
        result_state = retained.selective_state
        result_repair_at = result_state.started_at_ms + 4352
        result_repairs = extract_and_settle(
            responder,
            responder.handle(Advance(now_ms=result_repair_at)),
            at_ms=result_repair_at + 1,
        )
        result_repair_frames = [parse_frame(wire) for wire in result_repairs]
        self.assertEqual(
            [(frame.message_type, frame.fragment.index if frame.fragment else None)
             for frame in result_repair_frames],
            [(1, 1), (1, 4)],
        )
        self.assertTrue(all(frame.sequence == result_seq for frame in result_repair_frames))
        self.assertTrue(all(frame.message_type == 1 for frame in result_repair_frames))
        self.assertTrue(all(frame.security is not None and frame.security.cipher == 1
                            for frame in result_repair_frames))
        result_initial_pns = [frame.security.packet_number for frame in result_frames]
        result_repair_pns = [frame.security.packet_number for frame in result_repair_frames]
        self.assertTrue(all(pn > max(result_initial_pns) for pn in result_repair_pns))
        self.assertEqual(len(set(result_repair_pns)), len(result_repair_pns))

        final_events, result_acks = send_receive(
            initiator, result_repairs, start_ms=result_repair_at + 10
        )
        expected_result = bytes((index % 256) ^ 0xA5 for index in range(1024))
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_result"
            and event.payload == expected_result
            for event in final_events
        ))
        result_ack = next(
            wire for wire in result_acks if parse_frame(wire).message_type == 6
        )
        self.assertTrue(parse_frame(result_ack).security is not None)
        responder.handle(Receive(
            link=0, bytes=result_ack, at_ms=result_repair_at + 30
        ))
        self.assertTrue(retained.acknowledged)
        self.assertTrue(result_state.terminal)

    def test_retry_all_xx_retransmits_the_full_protected_set_on_a_fresh_association(self) -> None:
        profile = manifest_bytes("test-radio-retry-all-xx.json")
        self.assertEqual(
            hashlib.sha256(profile).hexdigest(),
            "369314bd7daf840b22d34e10c432fe08575ecd9e1c562cfd730a342bc5e1286a",
        )
        initiator, responder = self.pair("test-radio-retry-all-xx.json")
        self.grant_service2_freshness(initiator, responder)
        payload = bytes((index % 256) ^ 0x5A for index in range(1024))
        initial = extract_and_settle(
            initiator,
            initiator.handle(ApplicationRequest(
                service_id=2, payload=payload, ack_req=True, at_ms=230
            )),
            at_ms=231,
        )
        self.assertEqual(len(initial), 32)
        self.assertEqual(initiator.manifest.values["profile"]["id"], "TEST-RADIO-RETRY-ALL")
        self.assertEqual(initiator.manifest.values["services"][1]["recovery"], "retry-all")
        self.assertTrue(all(parse_frame(wire).security is not None for wire in initial))
        self.assertTrue(all(parse_frame(wire).security.cipher == 1 for wire in initial))
        self.assertEqual([parse_frame(wire).fragment.index for wire in initial], list(range(32)))

        missing = {2, 6}
        partial_events, _ = send_receive(
            responder,
            [wire for wire in initial if parse_frame(wire).fragment.index not in missing],
            start_ms=300,
        )
        self.assertFalse(any(isinstance(event, ApplicationEvent) for event in partial_events))
        self.assertEqual(responder.handle(Advance(now_ms=2372)), ())
        exchange = next(iter(initiator.delivery.active_outgoing.values()))
        retry_at = exchange.next_retry_ms
        retry = extract_and_settle(
            initiator,
            initiator.handle(Advance(now_ms=retry_at)),
            at_ms=retry_at + 1,
        )
        self.assertEqual(len(retry), 32)
        self.assertEqual([parse_frame(wire).fragment.index for wire in retry], list(range(32)))
        self.assertTrue(all(parse_frame(wire).sequence == exchange.seq for wire in retry))
        self.assertTrue(all(parse_frame(wire).message_type != 8 for wire in retry))
        self.assertTrue(all(parse_frame(wire).security is not None for wire in retry))
        self.assertTrue(all(parse_frame(wire).security.cipher == 1 for wire in retry))
        initial_pns = [parse_frame(wire).security.packet_number for wire in initial]
        retry_pns = [parse_frame(wire).security.packet_number for wire in retry]
        self.assertTrue(all(pn > max(initial_pns) for pn in retry_pns))
        self.assertEqual(len(set(retry_pns)), len(retry_pns))

        request_events, result_wires = send_receive(
            responder, retry, start_ms=retry_at + 10
        )
        accepted = [
            event for event in request_events
            if isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
        ]
        self.assertEqual(len(accepted), 1)
        expected_result = bytes((index % 256) ^ 0xA5 for index in range(1024))
        result_wires = [wire for wire in result_wires if parse_frame(wire).message_type == 1]
        self.assertEqual(len(result_wires), 32 * 3)
        self.assertTrue(all(parse_frame(wire).security is not None for wire in result_wires))
        result_events, receipt_wires = send_receive(
            initiator, result_wires, start_ms=retry_at + 100
        )
        results = [
            event for event in result_events
            if isinstance(event, ApplicationEvent) and event.kind == "request_result"
        ]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].payload, expected_result)
        result_acks = [wire for wire in receipt_wires if parse_frame(wire).message_type == 6]
        self.assertGreaterEqual(len(result_acks), 1)
        self.assertTrue(all(
            parse_frame(wire).security is not None
            and parse_frame(wire).security.cipher == 1
            for wire in result_acks
        ))
        result_seq = parse_frame(result_wires[0]).sequence
        for wire in result_acks:
            ack_frame = parse_frame(wire)
            reply_to = next(ext for ext in ack_frame.extensions if ext.extension_id == 1)
            service = next(ext for ext in ack_frame.extensions if ext.extension_id == 4)
            self.assertEqual(decode_uleb(reply_to.value)[0], result_seq)
            self.assertEqual(decode_uleb(service.value)[0], 2)
        for offset, wire in enumerate(result_acks):
            responder.handle(Receive(
                link=0, bytes=wire, at_ms=retry_at + 200 + offset
            ))
        retained = next(
            item for item in responder.delivery.retained_results.values()
            if item.service_id == 2
        )
        self.assertTrue(retained.acknowledged)
        self.assertNotIn(exchange.exchange_id, initiator.delivery.active_outgoing)

    def test_retry_all_xx_expires_partial_request_and_rejects_late_retry_fragments(self) -> None:
        initiator, responder = self.pair("test-radio-retry-all-xx.json")
        self.grant_service2_freshness(initiator, responder)
        payload = bytes((index % 256) ^ 0x5A for index in range(1024))
        initial = extract_and_settle(
            initiator,
            initiator.handle(ApplicationRequest(
                service_id=2, payload=payload, ack_req=True, at_ms=230
            )),
            at_ms=231,
        )
        self.assertEqual(len(initial), 32)
        exchange = next(iter(initiator.delivery.active_outgoing.values()))
        request_seq = exchange.seq
        responder.handle(Receive(link=0, bytes=initial[0], at_ms=300))
        request_key = (
            1, initiator.local_node_id, responder.association.peer_epoch, request_seq
        )
        self.assertIn(request_key, responder.reassembly.active)

        retry_sets: list[list[bytes]] = []
        while exchange.exchange_id in initiator.delivery.active_outgoing:
            retry_at = exchange.next_retry_ms
            self.assertIsNotNone(retry_at)
            retry_batch = extract_and_settle(
                initiator,
                initiator.handle(Advance(now_ms=retry_at)),
                at_ms=retry_at + 1,
            )
            if retry_batch:
                retry_sets.append(retry_batch)
            # The bounded retry profile must eventually fail the active request.
            if not retry_batch and exchange.exchange_id not in initiator.delivery.active_outgoing:
                break
        self.assertEqual(len(retry_sets), initiator.manifest.values["timing"]["max_bursts"] - 1)
        self.assertNotIn(exchange.exchange_id, initiator.delivery.active_outgoing)

        assembly_deadline = 300 + responder.manifest.values["timing"]["assembly_ms"]
        responder.handle(Advance(now_ms=assembly_deadline))
        self.assertNotIn(request_key, responder.reassembly.active)
        self.assertIn(request_key, responder.reassembly.tombstones)
        late_events, _ = send_receive(
            responder, retry_sets[-1], start_ms=assembly_deadline + 1
        )
        self.assertFalse(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in late_events
        ))
        self.assertNotIn(request_key, responder.reassembly.active)
        self.assertNotIn(request_key, responder.delivery.accepted_messages)


if __name__ == "__main__":
    unittest.main()
