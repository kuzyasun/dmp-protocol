"""P21D protected SELECTIVE-32 endpoint and retry-all integration cases."""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from typing import Any

import dmp_peer.manifest as manifest_module
from dmp_peer.events import Advance, ApplicationEvent, ApplicationRequest, Open, Receive, TxAdmit, TxSubmit, TxTerminal
from dmp_peer.frame import parse_frame
from dmp_peer.security import MAX_PN, SecurityError
from dmp_peer.testing import PeerEndpoint


ROOT = Path(__file__).resolve().parents[3]


def manifest_bytes(name: str) -> bytes:
    return (ROOT / "profiles" / "deployments" / name).read_bytes()


def extract_and_settle(
    ep: PeerEndpoint,
    events: tuple[Any, ...] | list[Any] | None = None,
    *,
    at_ms: int,
) -> list[bytes]:
    wires = [event.bytes for event in events or () if isinstance(event, TxSubmit)]
    while ep.active_submissions:
        for handle, submission in list(ep.active_submissions.items()):
            if not submission.get("admitted"):
                ep.handle(TxAdmit(
                    handle=handle,
                    generation=submission["generation"],
                    accepted=True,
                    reason=None,
                    at_ms=at_ms,
                ))
            terminal = ep.handle(TxTerminal(
                handle=handle,
                generation=submission["generation"],
                outcome="transmitted",
                at_ms=at_ms,
            ))
            wires.extend(event.bytes for event in terminal if isinstance(event, TxSubmit))
    return wires


def send_receive(
    receiver: PeerEndpoint,
    wires: list[bytes],
    *,
    start_ms: int,
) -> tuple[list[Any], list[bytes]]:
    events: list[Any] = []
    responses: list[bytes] = []
    for offset, wire in enumerate(wires):
        received = receiver.handle(Receive(link=0, bytes=wire, at_ms=start_ms + offset))
        events.extend(received)
        responses.extend(extract_and_settle(receiver, received, at_ms=start_ms + offset + 1))
    return events, responses


class P21DSelectiveIntegrationTests(unittest.TestCase):
    def pair(
        self,
        profile: str = "radio-nnpsk0.json",
        *,
        manifest_override: bytes | None = None,
        unique_entropy: bool = False,
    ) -> tuple[PeerEndpoint, PeerEndpoint]:
        manifest = manifest_override or manifest_bytes(profile)
        if unique_entropy:

            def entropy_source(seed: int) -> Any:
                counter = 0

                def draw(size: int) -> bytes:
                    nonlocal counter
                    value = bytes(
                        (seed + counter * 17 + index) % 256
                        for index in range(size)
                    )
                    counter += 1
                    return value

                return draw

            initiator_entropy = entropy_source(1)
            responder_entropy = entropy_source(2)
        else:
            initiator_entropy = lambda size: bytes((i + 2) % 256 for i in range(size))
            responder_entropy = lambda size: bytes((i + 1) % 256 for i in range(size))

        def construct_pair() -> tuple[PeerEndpoint, PeerEndpoint]:
            return (
                PeerEndpoint(
                    manifest_bytes=manifest,
                    test_credentials={"node_id": 20, "psk": b"\x01" * 32},
                    entropy_source=initiator_entropy,
                    test_services={},
                ),
                PeerEndpoint(
                    manifest_bytes=manifest,
                    test_credentials={"node_id": 10, "psk": b"\x01" * 32},
                    entropy_source=responder_entropy,
                    test_services={},
                ),
            )

        if manifest_override is None:
            endpoints = construct_pair()
        else:
            digest = hashlib.sha256(manifest).hexdigest()
            test_profile_name = f"test-p21d-{digest}"
            previous_digest = manifest_module._FROZEN.get(test_profile_name)
            manifest_module._FROZEN[test_profile_name] = digest
            try:
                endpoints = construct_pair()
                self.assertEqual(endpoints[0].manifest.sha256, digest)
                self.assertEqual(endpoints[1].manifest.sha256, digest)
            finally:
                if previous_digest is None:
                    del manifest_module._FROZEN[test_profile_name]
                else:
                    manifest_module._FROZEN[test_profile_name] = previous_digest
        initiator, responder = endpoints
        init_open = initiator.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        resp_open = responder.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        init_sync = extract_and_settle(initiator, init_open, at_ms=11)
        resp_sync = extract_and_settle(responder, resp_open, at_ms=11)
        for wire in init_sync:
            responder.handle(Receive(link=0, bytes=wire, at_ms=12))
        for wire in resp_sync:
            initiator.handle(Receive(link=0, bytes=wire, at_ms=12))

        flight1 = extract_and_settle(initiator, initiator.initiate_handshake(at_ms=100), at_ms=101)
        self.assertEqual(len(flight1), 1)
        flight2_events = responder.handle(Receive(link=0, bytes=flight1[0], at_ms=110))
        flight2 = extract_and_settle(responder, flight2_events, at_ms=111)
        self.assertEqual(len(flight2), 1)
        finish_events = initiator.handle(Receive(link=0, bytes=flight2[0], at_ms=120))
        finish = extract_and_settle(initiator, finish_events, at_ms=121)
        self.assertEqual(len(finish), 1)
        ready_events = responder.handle(Receive(link=0, bytes=finish[0], at_ms=130))
        ready = extract_and_settle(responder, ready_events, at_ms=131)
        self.assertEqual(len(ready), 1)
        initiator.handle(Receive(link=0, bytes=ready[0], at_ms=140))
        self.assertEqual(initiator.association.status, "active")
        self.assertEqual(responder.association.status, "active")
        return initiator, responder

    def grant_service2_freshness(
        self,
        initiator: PeerEndpoint,
        responder: PeerEndpoint,
        *,
        base_ms: int = 150,
    ) -> None:
        request_events = initiator.handle(ApplicationRequest(
            service_id=0,
            payload=b"\x10" + (12_000).to_bytes(4, "little"),
            ack_req=True,
            at_ms=base_ms,
        ))
        request = extract_and_settle(
            initiator,
            request_events,
            at_ms=base_ms + 1,
        )
        self.assertEqual(
            len(request),
            1,
            (request_events, initiator.delivery.active_outgoing, initiator.delivery.queue),
        )
        grant_events = responder.handle(Receive(link=0, bytes=request[0], at_ms=base_ms + 10))
        grant = extract_and_settle(responder, grant_events, at_ms=base_ms + 11)
        self.assertGreaterEqual(len(grant), 1)
        result_receipts: list[bytes] = []
        for offset, wire in enumerate(grant):
            received = initiator.handle(Receive(link=0, bytes=wire, at_ms=base_ms + 20 + offset))
            result_receipts.extend(extract_and_settle(
                initiator, received, at_ms=base_ms + 21 + offset
            ))
        for offset, wire in enumerate(result_receipts):
            receipt_events = responder.handle(Receive(
                link=0, bytes=wire, at_ms=base_ms + 22 + offset
            ))
            extract_and_settle(responder, receipt_events, at_ms=base_ms + 23 + offset)
        self.assertIsNotNone(initiator.active_freshness_token)

    def test_selective_association_stops_before_sequence_wrap(self) -> None:
        initiator, _ = self.pair()
        initiator.next_seq = 0xFFFFFFFF
        self.assertEqual(initiator._alloc_seq(), 0xFFFFFFFF)
        self.assertEqual(initiator.next_seq, 0x1_0000_0000)
        with self.assertRaisesRegex(SecurityError, "SEQ space is exhausted"):
            initiator._alloc_seq()
        self.assertEqual(initiator.association.status, "closed")

    def test_selective_protected_frames_fit_at_maximum_packet_number(self) -> None:
        initiator, responder = self.pair()
        self.grant_service2_freshness(initiator, responder)
        initiator.association.next_send_pn = MAX_PN - 1
        outgoing: list[Any] = []
        sequence = initiator._queue_data_transfer(
            2, bytes(range(64)), ack_req=True, out=outgoing
        )
        initial = extract_and_settle(initiator, outgoing, at_ms=201)
        self.assertEqual(
            [parse_frame(wire).security.packet_number for wire in initial],
            [MAX_PN - 1, MAX_PN],
        )
        self.assertTrue(all(len(wire) <= initiator.forward_mtu for wire in initial))

        responder.association.next_send_pn = MAX_PN
        reference = (1, initiator.local_node_id, initiator.local_epoch, sequence)
        status = responder._build_fragment_status(reference, 2, 0x01)
        self.assertIsNotNone(status)
        self.assertEqual(parse_frame(status).security.packet_number, MAX_PN)
        self.assertLessEqual(len(status), initiator.manifest.values["binding"]["return_mtu"])
        state = initiator.outgoing_data[(initiator.association.h, sequence)].selective_state
        events = initiator.handle(Receive(link=0, bytes=status, at_ms=202))
        self.assertFalse(any(isinstance(event, ApplicationEvent) for event in events))
        self.assertEqual(state.pending_mask, 0x01)

    def test_radio_request_and_large_result_repair_only_missing_fragments(self) -> None:
        initiator, responder = self.pair()
        self.grant_service2_freshness(initiator, responder)
        payload = bytes((index % 256) ^ 0x5A for index in range(1024))
        request_wires = extract_and_settle(
            initiator,
            initiator.handle(ApplicationRequest(service_id=2, payload=payload, ack_req=True, at_ms=230)),
            at_ms=231,
        )
        self.assertEqual(len(request_wires), 32)
        original_seq = parse_frame(request_wires[0]).sequence
        self.assertTrue(all(parse_frame(wire).sequence == original_seq for wire in request_wires))

        partial_request = [wire for wire in request_wires if parse_frame(wire).fragment.index not in (2, 6)]
        request_events, _ = send_receive(responder, partial_request, start_ms=300)
        self.assertFalse(any(isinstance(event, ApplicationEvent) for event in request_events))
        request_key = (1, 20, initiator.association.local_epoch, original_seq)
        self.assertEqual(len(responder.reassembly.active[request_key].received_indices), 30)
        self.assertEqual(responder.reassembly.active[request_key].received_indices,
                         set(range(32)) - {2, 6})
        self.assertNotIn(request_key, responder.reassembly.completed)
        self.assertNotIn(request_key, responder.delivery.accepted_messages)
        self.assertNotIn(request_key, responder.delivery.retained_results)
        status_events = responder.handle(Advance(now_ms=2372))
        request_status = extract_and_settle(responder, status_events, at_ms=2373)
        self.assertEqual(len(request_status), 1)
        status_frame = parse_frame(request_status[0])
        self.assertEqual(status_frame.message_type, 8)
        self.assertEqual(status_frame.security.cipher, 1)
        self.assertLessEqual(
            len(request_status[0]), initiator.manifest.values["binding"]["return_mtu"]
        )

        sender_state = next(iter(initiator.delivery.active_outgoing.values())).selective_state
        self.assertEqual(sender_state.frames_remaining, 0)
        feedback = initiator.handle(Receive(link=0, bytes=request_status[0], at_ms=2374))
        self.assertFalse(any(isinstance(event, ApplicationEvent) for event in feedback))
        self.assertEqual(sender_state.pending_mask, 0x44)
        repair_at = sender_state.started_at_ms + 4352
        request_repairs = extract_and_settle(
            initiator,
            initiator.handle(Advance(now_ms=repair_at)),
            at_ms=repair_at + 1,
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in request_repairs], [2, 6])
        initial_pns = [parse_frame(wire).security.packet_number for wire in request_wires]
        repair_pns = [parse_frame(wire).security.packet_number for wire in request_repairs]
        self.assertTrue(all(pn > max(initial_pns) for pn in repair_pns))
        freshness = next(ext.value for ext in parse_frame(request_wires[0]).extensions if ext.extension_id == 6)
        grant = responder.freshness_manager.grants[freshness]
        initial_meta = responder._immutable_message_metadata(
            parse_frame(request_wires[0]), (32, 1024)
        )
        repair_meta = responder._immutable_message_metadata(
            parse_frame(request_repairs[0]), (32, 1024)
        )
        expected_digest = hashlib.sha256(repr((initial_meta, None)).encode("utf-8")).digest()
        self.assertEqual(grant.bound_message_digest, expected_digest)
        self.assertEqual(repair_meta, initial_meta)
        self.assertFalse(grant.consumed)

        _, request_return = send_receive(
            responder, request_repairs, start_ms=repair_at + 10
        )
        result_wires = [wire for wire in request_return if parse_frame(wire).message_type == 1]
        self.assertEqual(len(result_wires), 32)
        result_seq = parse_frame(result_wires[0]).sequence

        partial_result = [wire for wire in result_wires if parse_frame(wire).fragment.index not in (1, 4)]
        result_events, _ = send_receive(initiator, partial_result, start_ms=repair_at + 30)
        self.assertFalse(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_result"
            for event in result_events
        ))
        result_feedback_at = repair_at + 30 + 2072
        status_events = initiator.handle(Advance(now_ms=result_feedback_at))
        result_status = extract_and_settle(initiator, status_events, at_ms=result_feedback_at + 1)
        self.assertEqual(len(result_status), 1)
        self.assertEqual(parse_frame(result_status[0]).message_type, 8)
        retained = next(
            item for item in responder.delivery.retained_results.values()
            if item.service_id == 2 and item.req_seq == original_seq
        )
        self.assertEqual(retained.result_seq, result_seq)
        result_state = retained.selective_state
        responder.handle(Receive(link=0, bytes=result_status[0], at_ms=result_feedback_at + 2))
        self.assertEqual(result_state.pending_mask, 0x12)
        result_repair_at = result_state.started_at_ms + 4352
        result_repairs = extract_and_settle(
            responder,
            responder.handle(Advance(now_ms=result_repair_at)),
            at_ms=result_repair_at + 1,
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in result_repairs], [1, 4])
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
        result_ack = next(wire for wire in result_acks if parse_frame(wire).message_type == 6)
        responder.handle(Receive(link=0, bytes=result_ack, at_ms=result_repair_at + 30))
        self.assertTrue(retained.acknowledged)
        self.assertTrue(result_state.terminal)

    def test_r6_two_of_eight_repairs_only_indices_two_and_six(self) -> None:
        initiator, responder = self.pair()
        self.grant_service2_freshness(initiator, responder)
        payload = bytes((index % 256) ^ 0x5A for index in range(256))
        request_wires = extract_and_settle(
            initiator,
            initiator.handle(ApplicationRequest(
                service_id=2, payload=payload, ack_req=True, at_ms=230
            )),
            at_ms=231,
        )
        self.assertEqual(len(request_wires), 8)
        frames = [parse_frame(wire) for wire in request_wires]
        original_seq = frames[0].sequence
        self.assertTrue(all(frame.fragment.total_length == 256 for frame in frames))
        self.assertTrue(all(frame.fragment.chunk_size == 32 for frame in frames))
        self.assertEqual([frame.fragment.index for frame in frames], list(range(8)))

        partial = [wire for wire in request_wires
                   if parse_frame(wire).fragment.index not in (2, 6)]
        receive_events, _ = send_receive(responder, partial, start_ms=300)
        self.assertFalse(any(isinstance(event, ApplicationEvent) for event in receive_events))
        status = extract_and_settle(
            responder, responder.handle(Advance(now_ms=2372)), at_ms=2373
        )
        self.assertEqual(len(status), 1)
        status_frame = parse_frame(status[0])
        self.assertEqual(status_frame.message_type, 8)
        self.assertEqual(status_frame.security.cipher, 1)
        self.assertLessEqual(
            len(status[0]), initiator.manifest.values["binding"]["return_mtu"]
        )

        sender = next(iter(initiator.delivery.active_outgoing.values()))
        state = sender.selective_state
        feedback_events = initiator.handle(Receive(link=0, bytes=status[0], at_ms=2374))
        self.assertFalse(any(isinstance(event, ApplicationEvent) for event in feedback_events))
        self.assertEqual(state.pending_mask, 0x00000044)
        repair_at = state.started_at_ms + 4352
        repairs = extract_and_settle(
            initiator, initiator.handle(Advance(now_ms=repair_at)), at_ms=repair_at + 1
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in repairs], [2, 6])
        initial_pns = [frame.security.packet_number for frame in frames]
        self.assertTrue(all(parse_frame(wire).security.packet_number > max(initial_pns)
                            for wire in repairs))

        send_receive(responder, repairs, start_ms=repair_at + 10)
        request_key = (1, initiator.local_node_id, initiator.association.local_epoch,
                       original_seq)
        self.assertIn(request_key, responder.delivery.accepted_messages)
        retained = responder.delivery.retained_results[request_key]
        self.assertEqual(retained.result_payload,
                         bytes((index % 256) ^ 0xA5 for index in range(256)))

    def test_fragmented_data_repairs_and_ack_clears_transfer(self) -> None:
        initiator, responder = self.pair()
        self.grant_service2_freshness(initiator, responder)
        payload = bytes((index * 7) % 256 for index in range(160))
        outgoing: list[Any] = []
        sequence = initiator._queue_data_transfer(2, payload, ack_req=True, out=outgoing)
        data_wires = extract_and_settle(initiator, outgoing, at_ms=201)
        self.assertEqual(len(data_wires), 5)
        transfer = initiator.outgoing_data[(initiator.association.h, sequence)]
        self.assertEqual(transfer.selective_state.frames_remaining, 0)

        partial = [wire for wire in data_wires if parse_frame(wire).fragment.index not in (1, 4)]
        receive_events, _ = send_receive(responder, partial, start_ms=300)
        self.assertFalse(any(isinstance(event, ApplicationEvent) for event in receive_events))
        status = extract_and_settle(
            responder,
            responder.handle(Advance(now_ms=2372)),
            at_ms=2373,
        )
        self.assertEqual(len(status), 1)
        self.assertEqual(parse_frame(status[0]).message_type, 8)
        initiator.handle(Receive(link=0, bytes=status[0], at_ms=2374))
        self.assertEqual(transfer.selective_state.pending_mask, 0x12)
        repair_at = transfer.selective_state.started_at_ms + 4352
        repairs = extract_and_settle(
            initiator,
            initiator.handle(Advance(now_ms=repair_at)),
            at_ms=repair_at + 1,
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in repairs], [1, 4])
        data_events, ack_wires = send_receive(responder, repairs, start_ms=repair_at + 10)
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.payload == payload
            for event in data_events
        ))
        ack = next(wire for wire in ack_wires if parse_frame(wire).message_type == 6)
        initiator.handle(Receive(link=0, bytes=ack, at_ms=repair_at + 20))
        self.assertNotIn((initiator.association.h, sequence), initiator.outgoing_data)

    def test_old_association_frag_status_repairs_data_during_rotation_drain(self) -> None:
        initiator, responder = self.pair(unique_entropy=True)
        for endpoint in (initiator, responder):
            endpoint.manifest.values["security"]["episode_attempts"] = 2
        self.grant_service2_freshness(initiator, responder)
        payload = bytes((index * 19) & 0xFF for index in range(160))
        outgoing: list[Any] = []
        sequence = initiator._queue_data_transfer(
            2, payload, ack_req=True, out=outgoing
        )
        data_wires = extract_and_settle(initiator, outgoing, at_ms=201)
        self.assertEqual(len(data_wires), 5)
        partial = [wire for wire in data_wires
                   if parse_frame(wire).fragment.index not in (1, 4)]
        receive_events, _ = send_receive(responder, partial, start_ms=300)
        self.assertFalse(any(isinstance(event, ApplicationEvent)
                             for event in receive_events))
        request_key = (
            1, initiator.local_node_id, initiator.association.local_epoch, sequence
        )
        self.assertIn(request_key, responder.reassembly.active)

        old_init = initiator.association
        old_resp = responder.association
        flight1 = extract_and_settle(
            initiator,
            initiator.initiate_handshake(
                at_ms=1_500, attempt_id=b"radio-data-rot01"
            ),
            at_ms=1_501,
        )
        flight2_events = responder.handle(Receive(
            link=0, bytes=flight1[0], at_ms=1_510
        ))
        flight2 = extract_and_settle(responder, flight2_events, at_ms=1_511)
        finish_events = initiator.handle(Receive(
            link=0, bytes=flight2[0], at_ms=1_520
        ))
        finish = extract_and_settle(initiator, finish_events, at_ms=1_521)
        ready_events = responder.handle(Receive(
            link=0, bytes=finish[0], at_ms=1_530
        ))
        ready = extract_and_settle(responder, ready_events, at_ms=1_531)
        self.assertEqual(len(ready), 1)
        initiator.handle(Receive(link=0, bytes=ready[0], at_ms=1_540))
        self.assertEqual(old_init.status, "draining")
        self.assertEqual(old_resp.status, "draining")

        with responder._use_association(old_resp, allow_draining=True):
            feedback = responder._build_fragment_status(
                request_key, 2, (1 << 1) | (1 << 4)
            )
        self.assertIsNotNone(feedback)
        state = initiator.outgoing_data[(old_init.h, sequence)].selective_state
        initiator.handle(Receive(link=0, bytes=feedback, at_ms=1_550))
        self.assertEqual(state.pending_mask, (1 << 1) | (1 << 4))
        self.assertFalse(state.terminal)

    def _radio_rotation_collision(self) -> tuple[PeerEndpoint, PeerEndpoint, Any, Any, int, list[bytes]]:
        initiator, responder = self.pair(unique_entropy=True)
        for endpoint in (initiator, responder):
            endpoint.manifest.values["security"]["episode_attempts"] = 2
        self.grant_service2_freshness(initiator, responder)

        payload = bytes((index * 23) & 0xFF for index in range(160))
        old_events: list[Any] = []
        old_sequence = initiator._queue_data_transfer(
            2, payload, ack_req=True, out=old_events
        )
        old_frames = extract_and_settle(initiator, old_events, at_ms=201)
        old_association = initiator.association
        old_transfer = initiator.outgoing_data[(old_association.h, old_sequence)]

        flight1 = extract_and_settle(
            initiator,
            initiator.initiate_handshake(at_ms=1_500, attempt_id=b"collision-rot001"),
            at_ms=1_501,
        )
        flight2_events = responder.handle(Receive(link=0, bytes=flight1[0], at_ms=1_510))
        flight2 = extract_and_settle(responder, flight2_events, at_ms=1_511)
        finish_events = initiator.handle(Receive(link=0, bytes=flight2[0], at_ms=1_520))
        finish = extract_and_settle(initiator, finish_events, at_ms=1_521)
        ready_events = responder.handle(Receive(link=0, bytes=finish[0], at_ms=1_530))
        ready = extract_and_settle(responder, ready_events, at_ms=1_531)
        self.assertEqual(len(ready), 1)
        initiator.handle(Receive(link=0, bytes=ready[0], at_ms=1_540))
        self.assertEqual(old_association.status, "draining")

        self.grant_service2_freshness(
            initiator, responder, base_ms=1_550
        )
        new_events: list[Any] = []
        new_sequence = initiator._queue_data_transfer(
            2, payload, ack_req=True, out=new_events
        )
        new_frames = extract_and_settle(initiator, new_events, at_ms=1_601)
        self.assertEqual(old_sequence, 3)
        self.assertEqual(new_sequence, old_sequence)
        new_transfer = initiator.outgoing_data[(initiator.association.h, new_sequence)]
        self.assertEqual(len(initiator.outgoing_data), 2)
        return initiator, responder, old_transfer, new_transfer, old_sequence, old_frames

    def test_rotation_same_seq_keeps_transfers_and_old_status_ack_scope(self) -> None:
        initiator, responder, old_transfer, new_transfer, sequence, old_frames = (
            self._radio_rotation_collision()
        )
        old_association = initiator._association_by_hash(old_transfer.association_h)
        old_receiver_association = responder._association_by_hash(old_transfer.association_h)
        self.assertIsNotNone(old_association)
        self.assertIsNotNone(old_receiver_association)

        request_key = (
            initiator.namespace,
            initiator.local_node_id,
            old_association.local_epoch,
            sequence,
        )
        with responder._use_association(old_receiver_association, allow_draining=True):
            feedback = responder._build_fragment_status(request_key, 2, 1 << 1)
        self.assertIsNotNone(feedback)
        initiator.handle(Receive(link=0, bytes=feedback, at_ms=1_610))
        self.assertEqual(old_transfer.selective_state.pending_mask, 1 << 1)
        self.assertIsNone(new_transfer.selective_state.pending_mask)

        _, acknowledgements = send_receive(responder, old_frames, start_ms=1_620)
        ack = next(wire for wire in acknowledgements if parse_frame(wire).message_type == 6)
        initiator.handle(Receive(link=0, bytes=ack, at_ms=1_640))
        self.assertNotIn((old_transfer.association_h, sequence), initiator.outgoing_data)
        self.assertIn((new_transfer.association_h, sequence), initiator.outgoing_data)
        self.assertFalse(new_transfer.selective_state.terminal)

    def test_old_same_seq_transfer_timeout_does_not_remove_new_transfer(self) -> None:
        initiator, _, old_transfer, new_transfer, sequence, _ = (
            self._radio_rotation_collision()
        )
        initiator.handle(Advance(now_ms=old_transfer.selective_state.horizon_at_ms))
        self.assertNotIn((old_transfer.association_h, sequence), initiator.outgoing_data)
        self.assertIn((new_transfer.association_h, sequence), initiator.outgoing_data)
        self.assertFalse(new_transfer.selective_state.terminal)

    def test_total_initial_loss_probes_final_slice_then_repairs_the_rest(self) -> None:
        initiator, responder = self.pair()
        self.grant_service2_freshness(initiator, responder)
        initiator.handle(Advance(now_ms=200))
        payload = bytes(range(64))
        outgoing: list[Any] = []
        sequence = initiator._queue_data_transfer(2, payload, ack_req=True, out=outgoing)
        initial = extract_and_settle(initiator, outgoing, at_ms=201)
        state = initiator.outgoing_data[(initiator.association.h, sequence)].selective_state
        self.assertEqual(len(initial), 2)

        probe_at = state.started_at_ms + 4352
        probes = extract_and_settle(
            initiator,
            initiator.handle(Advance(now_ms=probe_at)),
            at_ms=probe_at + 1,
        )
        self.assertEqual(len(probes), 1)
        self.assertEqual(parse_frame(probes[0]).fragment.index, 1)
        self.assertGreater(
            parse_frame(probes[0]).security.packet_number,
            parse_frame(initial[1]).security.packet_number,
        )
        key = (1, 20, initiator.association.local_epoch, sequence)
        probe_events, _ = send_receive(responder, probes, start_ms=probe_at + 10)
        self.assertFalse(any(isinstance(event, ApplicationEvent) for event in probe_events))
        self.assertEqual(responder.reassembly.active[key].received_indices, {1})

        status_at = probe_at + 10 + 2072
        status = extract_and_settle(
            responder,
            responder.handle(Advance(now_ms=status_at)),
            at_ms=status_at + 1,
        )
        self.assertEqual(len(status), 1)
        initiator.handle(Receive(link=0, bytes=status[0], at_ms=status_at + 2))
        self.assertEqual(state.pending_mask, 0x01)

        repair_at = state.started_at_ms + 8704
        repairs = extract_and_settle(
            initiator,
            initiator.handle(Advance(now_ms=repair_at)),
            at_ms=repair_at + 1,
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in repairs], [0])
        accepted, acknowledgements = send_receive(responder, repairs, start_ms=repair_at + 10)
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.payload == payload
            for event in accepted
        ))
        ack = next(wire for wire in acknowledgements if parse_frame(wire).message_type == 6)
        initiator.handle(Receive(link=0, bytes=ack, at_ms=repair_at + 20))
        self.assertNotIn((initiator.association.h, sequence), initiator.outgoing_data)

    def test_terminal_data_ack_wins_over_a_later_status(self) -> None:
        initiator, responder = self.pair()
        self.grant_service2_freshness(initiator, responder)
        initiator.handle(Advance(now_ms=200))
        payload = bytes(range(64))
        outgoing: list[Any] = []
        sequence = initiator._queue_data_transfer(2, payload, ack_req=True, out=outgoing)
        initial = extract_and_settle(initiator, outgoing, at_ms=201)
        first_slice = [wire for wire in initial if parse_frame(wire).fragment.index == 0]
        second_slice = next(wire for wire in initial if parse_frame(wire).fragment.index == 1)
        send_receive(responder, first_slice, start_ms=300)

        # Build an authenticated status, but let the remaining original slice and
        # its terminal ACK complete first. A newer stale status must not reopen it.
        initial_status = extract_and_settle(
            responder,
            responder.handle(Advance(now_ms=2372)),
            at_ms=2373,
        )
        self.assertEqual(len(initial_status), 1)
        accepted, acknowledgements = send_receive(responder, [second_slice], start_ms=2400)
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.payload == payload
            for event in accepted
        ))
        ack = next(wire for wire in acknowledgements if parse_frame(wire).message_type == 6)
        initiator.handle(Receive(link=0, bytes=ack, at_ms=2410))
        self.assertNotIn((initiator.association.h, sequence), initiator.outgoing_data)

        key = (1, 20, initiator.association.local_epoch, sequence)
        later_status = responder._build_fragment_status(key, 2, 0x01)
        self.assertIsNotNone(later_status)
        stale_events = initiator.handle(Receive(link=0, bytes=later_status, at_ms=2411))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in stale_events))
        self.assertFalse(any(isinstance(event, ApplicationEvent) for event in stale_events))
        self.assertNotIn((initiator.association.h, sequence), initiator.outgoing_data)

    def test_lost_status_is_recovered_by_final_slice_probe(self) -> None:
        initiator, responder = self.pair()
        self.grant_service2_freshness(initiator, responder)
        initiator.handle(Advance(now_ms=200))
        payload = bytes(range(64))
        outgoing: list[Any] = []
        sequence = initiator._queue_data_transfer(2, payload, ack_req=True, out=outgoing)
        initial = extract_and_settle(initiator, outgoing, at_ms=201)
        state = initiator.outgoing_data[(initiator.association.h, sequence)].selective_state
        last_slice = next(wire for wire in initial if parse_frame(wire).fragment.index == 1)
        send_receive(responder, [last_slice], start_ms=300)

        lost_status = extract_and_settle(
            responder,
            responder.handle(Advance(now_ms=2372)),
            at_ms=2373,
        )
        self.assertEqual(len(lost_status), 1)
        self.assertEqual(parse_frame(lost_status[0]).message_type, 8)
        self.assertEqual(state.status_count, 0)

        probe_at = state.started_at_ms + 4352
        probes = extract_and_settle(
            initiator,
            initiator.handle(Advance(now_ms=probe_at)),
            at_ms=probe_at + 1,
        )
        self.assertEqual(len(probes), 1)
        self.assertEqual(parse_frame(probes[0]).fragment.index, 1)
        send_receive(responder, probes, start_ms=probe_at + 10)

        new_status_at = probe_at + 10 + 2072
        new_status = extract_and_settle(
            responder,
            responder.handle(Advance(now_ms=new_status_at)),
            at_ms=new_status_at + 1,
        )
        self.assertEqual(len(new_status), 1)
        initiator.handle(Receive(link=0, bytes=new_status[0], at_ms=new_status_at + 2))
        self.assertEqual(state.pending_mask, 0x01)
        repair_at = state.started_at_ms + 8704
        repairs = extract_and_settle(
            initiator,
            initiator.handle(Advance(now_ms=repair_at)),
            at_ms=repair_at + 1,
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in repairs], [0])
        accepted, acknowledgements = send_receive(responder, repairs, start_ms=repair_at + 10)
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.payload == payload
            for event in accepted
        ))
        ack = next(wire for wire in acknowledgements if parse_frame(wire).message_type == 6)
        initiator.handle(Receive(link=0, bytes=ack, at_ms=repair_at + 20))
        self.assertNotIn((initiator.association.h, sequence), initiator.outgoing_data)

    def test_lost_repair_is_reported_again_then_stops_at_burst_budget(self) -> None:
        initiator, responder = self.pair()
        self.grant_service2_freshness(initiator, responder)
        initiator.handle(Advance(now_ms=200))
        payload = bytes(range(96))
        outgoing: list[Any] = []
        sequence = initiator._queue_data_transfer(2, payload, ack_req=True, out=outgoing)
        initial = extract_and_settle(initiator, outgoing, at_ms=201)
        state = initiator.outgoing_data[(initiator.association.h, sequence)].selective_state
        self.assertEqual([parse_frame(wire).fragment.index for wire in initial], [0, 1, 2])

        _, _ = send_receive(
            responder,
            [wire for wire in initial if parse_frame(wire).fragment.index != 1],
            start_ms=300,
        )
        first_status = extract_and_settle(
            responder, responder.handle(Advance(now_ms=2372)), at_ms=2373
        )
        self.assertEqual(len(first_status), 1)
        initiator.handle(Receive(link=0, bytes=first_status[0], at_ms=2374))
        self.assertEqual(state.pending_mask, 0x02)

        repair_at = state.started_at_ms + 4352
        dropped_repair = extract_and_settle(
            initiator,
            initiator.handle(Advance(now_ms=repair_at)),
            at_ms=repair_at + 1,
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in dropped_repair], [1])
        self.assertEqual(responder.reassembly.active[(1, 20, initiator.association.local_epoch, sequence)].received_indices, {0, 2})

        probe_at = state.started_at_ms + 8704
        probe = extract_and_settle(
            initiator,
            initiator.handle(Advance(now_ms=probe_at)),
            at_ms=probe_at + 1,
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in probe], [2])
        send_receive(responder, probe, start_ms=probe_at + 10)
        next_status_at = probe_at + 10 + 2072
        next_status = extract_and_settle(
            responder,
            responder.handle(Advance(now_ms=next_status_at)),
            at_ms=next_status_at + 1,
        )
        self.assertEqual(len(next_status), 1)
        initiator_events = initiator.handle(Receive(
            link=0, bytes=next_status[0], at_ms=next_status_at + 2
        ))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in initiator_events))
        self.assertEqual(state.status_count, 1)
        expired_events = initiator.handle(Advance(now_ms=next_status_at + 2))
        self.assertTrue(state.terminal)
        self.assertIsNone(state.pending_mask)
        self.assertNotIn((initiator.association.h, sequence), initiator.outgoing_data)
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "diagnostic"
            and event.payload == b"unknown"
            for event in expired_events
        ))

    def test_lost_final_data_ack_uses_fresh_probe_without_reaccepting(self) -> None:
        initiator, responder = self.pair()
        self.grant_service2_freshness(initiator, responder)
        initiator.handle(Advance(now_ms=200))
        payload = bytes(range(64))
        outgoing: list[Any] = []
        sequence = initiator._queue_data_transfer(2, payload, ack_req=True, out=outgoing)
        initial = extract_and_settle(initiator, outgoing, at_ms=201)
        state = initiator.outgoing_data[(initiator.association.h, sequence)].selective_state

        accepted, lost_ack = send_receive(responder, initial, start_ms=300)
        self.assertEqual(sum(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in accepted
        ), 1)
        self.assertEqual(len(lost_ack), 1)
        self.assertEqual(parse_frame(lost_ack[0]).message_type, 6)
        self.assertIn((initiator.association.h, sequence), initiator.outgoing_data)

        probe_at = state.started_at_ms + 4352
        probe = extract_and_settle(
            initiator,
            initiator.handle(Advance(now_ms=probe_at)),
            at_ms=probe_at + 1,
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in probe], [1])
        self.assertGreater(
            parse_frame(probe[0]).security.packet_number,
            max(parse_frame(wire).security.packet_number for wire in initial),
        )
        duplicate_events, retry_acks = send_receive(
            responder, probe, start_ms=probe_at + 10
        )
        self.assertFalse(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in duplicate_events
        ))
        self.assertEqual(len(retry_acks), 1)
        initiator.handle(Receive(link=0, bytes=retry_acks[0], at_ms=probe_at + 20))
        self.assertNotIn((initiator.association.h, sequence), initiator.outgoing_data)

    def test_duplicate_req_receipts_for_selective_result_obey_receipt_limit(self) -> None:
        initiator, responder = self.pair()
        self.grant_service2_freshness(initiator, responder)
        payload = bytes((index % 256) ^ 0x5A for index in range(64))
        initial_request = extract_and_settle(
            initiator,
            initiator.handle(ApplicationRequest(
                service_id=2, payload=payload, ack_req=True, at_ms=230
            )),
            at_ms=231,
        )
        request_seq = parse_frame(initial_request[0]).sequence
        _, initial_result = send_receive(responder, initial_request, start_ms=300)
        result_frames = [wire for wire in initial_result
                         if parse_frame(wire).message_type == 1]
        self.assertEqual(len(result_frames), 2)
        retained = next(item for item in responder.delivery.retained_results.values()
                        if item.req_seq == request_seq)
        self.assertIsNotNone(retained.selective_state)
        accepted = responder.delivery.accepted_messages[
            (1, initiator.local_node_id, initiator.association.local_epoch, request_seq)
        ]
        sender = next(item for item in initiator.delivery.active_outgoing.values()
                      if item.seq == request_seq)

        replayed_receipts: list[bytes] = []
        for index in range(5):
            final_probe = initiator._build_req_frames(
                service_id=2,
                seq=request_seq,
                payload=payload,
                ack_req=True,
                freshness_token=sender.freshness_token,
                selected_indices=(1,),
            )
            _, replies = send_receive(
                responder, final_probe, start_ms=500 + index * 10
            )
            replayed_receipts.extend(
                wire for wire in replies if parse_frame(wire).message_type == 6
            )
            self.assertFalse(any(parse_frame(wire).message_type == 1 for wire in replies))

        self.assertEqual(len(replayed_receipts), 2)
        self.assertEqual(accepted.replay_bursts, 2)
        self.assertFalse(retained.selective_state.terminal)

    def test_selective_transfer_expires_at_its_absolute_horizon(self) -> None:
        initiator, responder = self.pair()
        self.grant_service2_freshness(initiator, responder)
        initiator.handle(Advance(now_ms=200))
        outgoing: list[Any] = []
        sequence = initiator._queue_data_transfer(2, bytes(range(64)), ack_req=True, out=outgoing)
        initial = extract_and_settle(initiator, outgoing, at_ms=201)
        self.assertEqual(len(initial), 2)
        state = initiator.outgoing_data[(initiator.association.h, sequence)].selective_state

        events = initiator.handle(Advance(now_ms=state.horizon_at_ms))

        self.assertNotIn((initiator.association.h, sequence), initiator.outgoing_data)
        self.assertTrue(state.terminal)
        self.assertFalse(any(isinstance(event, TxSubmit) for event in events))
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "diagnostic"
            and event.payload == b"unknown"
            for event in events
        ))

    def test_retry_all_uses_its_frozen_manifest_and_retries_the_full_set(self) -> None:
        profile = manifest_bytes("test-radio-retry-all-nnpsk0.json")
        self.assertEqual(
            hashlib.sha256(profile).hexdigest(),
            "bc8bba7c929c6d0fe9ad39dbe66a6699d342304ae8485ddf5cac9e32605b55f1",
        )
        initiator, responder = self.pair("test-radio-retry-all-nnpsk0.json")
        self.grant_service2_freshness(initiator, responder)
        payload = bytes((index % 256) ^ 0x5A for index in range(1024))
        initial = extract_and_settle(
            initiator,
            initiator.handle(ApplicationRequest(service_id=2, payload=payload, ack_req=True, at_ms=230)),
            at_ms=231,
        )
        self.assertEqual(len(initial), 32)
        self.assertEqual(initiator.manifest.values["profile"]["id"], "TEST-RADIO-RETRY-ALL")
        self.assertEqual(initiator.manifest.values["services"][1]["recovery"], "retry-all")
        partial_events, _ = send_receive(
            responder,
            [wire for wire in initial if parse_frame(wire).fragment.index not in (2, 6)],
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

        for _ in range(2):
            exchange = next(iter(initiator.delivery.active_outgoing.values()))
            retry_at = exchange.next_retry_ms
            advance_events = initiator.handle(Advance(now_ms=retry_at))
            retry = extract_and_settle(
                initiator,
                advance_events,
                at_ms=retry_at + 1,
            )
            if exchange.exchange_id not in initiator.delivery.active_outgoing:
                self.assertEqual(retry, [])
                self.assertTrue(any(
                    isinstance(event, ApplicationEvent)
                    and event.kind == "diagnostic"
                    and event.payload == b"unknown"
                    for event in advance_events
                ))
                break
            self.assertEqual(len(retry), 32)
            self.assertEqual([parse_frame(wire).fragment.index for wire in retry], list(range(32)))
            self.assertTrue(all(parse_frame(wire).sequence == exchange.seq for wire in retry))
        else:
            self.fail("retry-all transfer did not expire after its configured full bursts")

        # The delayed original fragment cannot reopen an expired retry-all identity.
        late_key = (1, 20, initiator.association.local_epoch, exchange.seq)
        late_at = responder.reassembly.active[late_key].expires_at_ms
        responder.handle(Advance(now_ms=late_at))
        late = responder.handle(Receive(link=0, bytes=initial[2], at_ms=late_at + 1))
        self.assertFalse(any(isinstance(event, ApplicationEvent) for event in late))
        self.assertNotIn(late_key, responder.reassembly.active)
        self.assertIn(late_key, responder.reassembly.tombstones)


if __name__ == "__main__":
    unittest.main()
