"""Focused SELECTIVE-32 integration cases for asynchronous and invalid feedback."""

from __future__ import annotations

import unittest
from typing import Any

from dmp_peer.events import Advance, ApplicationEvent, ApplicationRequest, Cancel, Open, Receive, TxAdmit, TxSubmit, TxTerminal
from dmp_peer.frame import CoreFrame, Extension, encode_uleb, parse_frame
from dmp_peer.testing import PeerEndpoint

import test_p21d_selective as helpers


def alternate_pair(psk: bytes) -> tuple[PeerEndpoint, PeerEndpoint]:
    manifest = helpers.manifest_bytes("radio-nnpsk0.json")
    initiator = PeerEndpoint(
        manifest_bytes=manifest,
        test_credentials={"node_id": 20, "psk": psk},
        entropy_source=lambda size: bytes((i + 2) % 256 for i in range(size)),
        test_services={},
    )
    responder = PeerEndpoint(
        manifest_bytes=manifest,
        test_credentials={"node_id": 10, "psk": psk},
        entropy_source=lambda size: bytes((i + 1) % 256 for i in range(size)),
        test_services={},
    )
    init_open = helpers.extract_and_settle(
        initiator,
        initiator.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10)),
        at_ms=11,
    )
    resp_open = helpers.extract_and_settle(
        responder,
        responder.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10)),
        at_ms=11,
    )
    for wire in init_open:
        responder.handle(Receive(link=0, bytes=wire, at_ms=12))
    for wire in resp_open:
        initiator.handle(Receive(link=0, bytes=wire, at_ms=12))

    flight1 = helpers.extract_and_settle(
        initiator, initiator.initiate_handshake(at_ms=100), at_ms=101
    )
    flight2 = helpers.extract_and_settle(
        responder,
        responder.handle(Receive(link=0, bytes=flight1[0], at_ms=110)),
        at_ms=111,
    )
    finish = helpers.extract_and_settle(
        initiator,
        initiator.handle(Receive(link=0, bytes=flight2[0], at_ms=120)),
        at_ms=121,
    )
    ready = helpers.extract_and_settle(
        responder,
        responder.handle(Receive(link=0, bytes=finish[0], at_ms=130)),
        at_ms=131,
    )
    initiator.handle(Receive(link=0, bytes=ready[0], at_ms=140))
    return initiator, responder


class P21DSelectiveEdgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.initiator, self.responder = helpers.P21DSelectiveIntegrationTests().pair()

    def test_valid_status_waits_for_outstanding_initial_burst_completion(self) -> None:
        self.initiator.handle(Advance(now_ms=200))
        payload = bytes(range(64))
        initial_events: list[Any] = []
        sequence = self.initiator._queue_data_transfer(
            2, payload, ack_req=True, out=initial_events
        )
        initial_wires = [event.bytes for event in initial_events if isinstance(event, TxSubmit)]
        self.assertEqual(len(initial_wires), 2)
        state = self.initiator.outgoing_data[sequence].selective_state
        self.assertEqual(state.active_kind, "initial")
        self.assertEqual(state.frames_remaining, 2)

        target_key = (1, self.initiator.local_node_id, self.initiator.local_epoch, sequence)
        status = self.responder._build_fragment_status(target_key, 2, 0x01)
        self.assertIsNotNone(status)
        feedback_events = self.initiator.handle(Receive(link=0, bytes=status, at_ms=210))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in feedback_events))
        self.assertEqual(state.pending_mask, 0x01)
        self.assertEqual(state.status_count, 1)
        self.assertEqual(state.active_kind, "initial")

        # Complete every original submission while retaining the accepted
        # feedback mask. No repair is submitted until the burst has completed.
        self.assertEqual(len(self.initiator.active_submissions), 2)
        settled_outputs: list[Any] = []
        for index, (handle, submission) in enumerate(
            list(self.initiator.active_submissions.items())
        ):
            self.initiator.handle(TxAdmit(
                handle=handle,
                generation=submission["generation"],
                accepted=True,
                reason=None,
                at_ms=220 + index * 2,
            ))
            settled_outputs.extend(self.initiator.handle(TxTerminal(
                handle=handle,
                generation=submission["generation"],
                outcome="transmitted",
                at_ms=221 + index * 2,
            )))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in settled_outputs))
        self.assertIsNone(state.active_kind)
        self.assertEqual(state.pending_mask, 0x01)

        repair_at = state.started_at_ms + 4352
        repairs = helpers.extract_and_settle(
            self.initiator,
            self.initiator.handle(Advance(now_ms=repair_at)),
            at_ms=repair_at + 1,
        )
        self.assertEqual([parse_frame(wire).fragment.index for wire in repairs], [0])

    def test_rejected_selective_data_admission_retires_queued_and_active_siblings(self) -> None:
        self.initiator.handle(Advance(now_ms=200))
        outgoing: list[Any] = []
        sequence = self.initiator._queue_data_transfer(
            2, bytes(range(256)), ack_req=True, out=outgoing
        )
        submissions = [event for event in outgoing if isinstance(event, TxSubmit)]
        self.assertEqual(len(submissions), self.initiator.adapter_slots)
        self.assertGreater(len(self.initiator.tx_queue), 0)
        state = self.initiator.outgoing_data[sequence].selective_state

        first = submissions[0]
        rejected = self.initiator.handle(TxAdmit(
            handle=first.handle,
            generation=first.generation,
            accepted=False,
            reason="busy",
            at_ms=202,
        ))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in rejected))
        self.assertFalse(any(isinstance(event, Cancel) for event in rejected))
        self.assertTrue(state.terminal)
        self.assertNotIn(sequence, self.initiator.outgoing_data)
        self.assertFalse(any(item.get("recovery_seq") == sequence
                             for item in self.initiator.tx_queue))
        self.assertTrue(self.initiator.active_submissions)
        self.assertTrue(all(item.get("cancel_requested")
                            for item in self.initiator.active_submissions.values()))

        remaining_handle, remaining = next(iter(self.initiator.active_submissions.items()))
        cancellation = self.initiator.handle(TxAdmit(
            handle=remaining_handle,
            generation=remaining["generation"],
            accepted=True,
            reason=None,
            at_ms=203,
        ))
        self.assertTrue(any(isinstance(event, Cancel) for event in cancellation))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in cancellation))

    def test_failed_selective_data_completion_retires_queued_and_active_siblings(self) -> None:
        self.initiator.handle(Advance(now_ms=200))
        outgoing: list[Any] = []
        sequence = self.initiator._queue_data_transfer(
            2, bytes(range(256)), ack_req=True, out=outgoing
        )
        submissions = [event for event in outgoing if isinstance(event, TxSubmit)]
        self.assertEqual(len(submissions), self.initiator.adapter_slots)
        self.assertGreater(len(self.initiator.tx_queue), 0)
        state = self.initiator.outgoing_data[sequence].selective_state

        first = submissions[0]
        self.initiator.handle(TxAdmit(
            handle=first.handle,
            generation=first.generation,
            accepted=True,
            reason=None,
            at_ms=202,
        ))
        failed = self.initiator.handle(TxTerminal(
            handle=first.handle,
            generation=first.generation,
            outcome="failed_unsent",
            at_ms=203,
        ))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in failed))
        self.assertTrue(state.terminal)
        self.assertNotIn(sequence, self.initiator.outgoing_data)
        self.assertFalse(any(item.get("recovery_seq") == sequence
                             for item in self.initiator.tx_queue))
        self.assertTrue(self.initiator.active_submissions)
        self.assertTrue(all(item.get("cancel_requested")
                            for item in self.initiator.active_submissions.values()))

        remaining_handle, remaining = next(iter(self.initiator.active_submissions.items()))
        cancellation = self.initiator.handle(TxAdmit(
            handle=remaining_handle,
            generation=remaining["generation"],
            accepted=True,
            reason=None,
            at_ms=204,
        ))
        self.assertTrue(any(isinstance(event, Cancel) for event in cancellation))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in cancellation))

    def test_wrong_service_and_reference_leave_recovery_state_unchanged(self) -> None:
        self.initiator.handle(Advance(now_ms=200))
        outgoing: list[Any] = []
        sequence = self.initiator._queue_data_transfer(
            2, bytes(range(64)), ack_req=True, out=outgoing
        )
        initial = helpers.extract_and_settle(self.initiator, outgoing, at_ms=201)
        state = self.initiator.outgoing_data[sequence].selective_state
        target_key = (1, self.initiator.local_node_id, self.initiator.local_epoch, sequence)

        wrong_service = self.responder._build_fragment_status(target_key, 1, 0x01)
        wrong_reference = self.responder._build_fragment_status(
            (target_key[0], target_key[1], target_key[2], sequence + 1), 2, 0x01
        )
        self.assertIsNotNone(wrong_service)
        self.assertIsNotNone(wrong_reference)
        self.assertTrue(initial)

        for wire in (wrong_service, wrong_reference):
            before = vars(state).copy()
            events = self.initiator.handle(Receive(
                link=0, bytes=wire, at_ms=self.initiator.now_ms + 1
            ))
            self.assertFalse(any(isinstance(event, TxSubmit) for event in events))
            self.assertEqual(vars(state), before)

    def test_status_from_a_different_association_leaves_recovery_state_unchanged(self) -> None:
        self.initiator.handle(Advance(now_ms=200))
        outgoing: list[Any] = []
        sequence = self.initiator._queue_data_transfer(
            2, bytes(range(64)), ack_req=True, out=outgoing
        )
        helpers.extract_and_settle(self.initiator, outgoing, at_ms=201)
        state = self.initiator.outgoing_data[sequence].selective_state

        _, unrelated_responder = alternate_pair(b"\x02" * 32)
        target_key = (1, self.initiator.local_node_id, self.initiator.local_epoch, sequence)
        unrelated_status = unrelated_responder._build_fragment_status(target_key, 2, 0x01)
        self.assertIsNotNone(unrelated_status)
        before = vars(state).copy()
        events = self.initiator.handle(Receive(
            link=0, bytes=unrelated_status, at_ms=202
        ))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in events))
        self.assertEqual(vars(state), before)

    def test_recovery_eligibility_excludes_telem_and_protocol_err_but_allows_event(self) -> None:
        payload = bytes(index % 256 for index in range(96))

        def protected_fragment(
            sender: PeerEndpoint, message_type: int, service_id: int,
            *, status: int | None = None,
        ) -> tuple[int, bytes]:
            sequence = sender._alloc_seq()
            base = sender._build_data_frames(service_id, sequence, payload, ack_req=True)
            parsed = parse_frame(base[0])
            extensions = list(parsed.extensions)
            if status is not None:
                extensions.extend((
                    Extension(1, True, False, encode_uleb(1)),
                    Extension(5, True, False, encode_uleb(status)),
                ))
            frame = CoreFrame(
                message_type=message_type,
                options=parsed.options,
                sequence=sequence,
                route=parsed.route,
                fragment=parsed.fragment,
                extensions=tuple(sorted(extensions, key=lambda ext: ext.extension_id)),
            )
            return sequence, sender._encrypt_and_encode(frame, payload[:32])

        event_seq, event_wire = protected_fragment(self.initiator, 4, 2)
        self.assertTrue(self.responder._selective_frame_eligible(
            parse_frame(event_wire), 2
        ))
        self.assertGreater(event_seq, 0)

        for message_type, service_id, status, at_ms in (
            (5, 1, None, 302), (2, 2, 1, 304),
        ):
            sequence, wire = protected_fragment(
                self.responder, message_type, service_id, status=status
            )
            received = self.initiator.handle(Receive(link=0, bytes=wire, at_ms=at_ms))
            key = (1, self.responder.local_node_id,
                   self.responder.association.local_epoch, sequence)
            if message_type == 5:
                self.assertIn(key, self.initiator.reassembly.active)
                self.assertIsNone(
                    self.initiator.reassembly.active[key].selective_feedback_due_ms
                )
            else:
                self.assertFalse(self.initiator._selective_frame_eligible(
                    parse_frame(wire), service_id
                ))
                self.assertNotIn(key, self.initiator.reassembly.active)
            self.assertFalse(any(isinstance(item, TxSubmit) for item in received))

    def test_feedback_buffer_bounds_second_status_while_first_is_outstanding(self) -> None:
        self.initiator.handle(Advance(now_ms=200))
        outgoing: list[Any] = []
        sequence = self.initiator._queue_data_transfer(
            2, bytes(index % 251 for index in range(96)), ack_req=True, out=outgoing
        )
        initial = helpers.extract_and_settle(self.initiator, outgoing, at_ms=201)
        state = self.initiator.outgoing_data[sequence].selective_state
        first_slice = next(wire for wire in initial if parse_frame(wire).fragment.index == 0)
        self.responder.handle(Receive(link=0, bytes=first_slice, at_ms=300))

        first_status_events = self.responder.handle(Advance(now_ms=2372))
        first_status = [event for event in first_status_events if isinstance(event, TxSubmit)]
        self.assertEqual(len(first_status), 1)
        self.assertTrue(self.responder.active_submissions[first_status[0].handle]["is_frag_status"])

        # With no returned status, the sender's final-fragment probe creates a
        # second receiver feedback opportunity while the first status still owns
        # the single configured feedback buffer.
        probe_at = state.started_at_ms + 4352
        probes = helpers.extract_and_settle(
            self.initiator,
            self.initiator.handle(Advance(now_ms=probe_at)),
            at_ms=probe_at + 1,
        )
        self.assertEqual(len(probes), 1)
        self.assertEqual(parse_frame(probes[0]).fragment.index, 2)
        for offset, probe in enumerate(probes):
            self.responder.handle(Receive(
                link=0, bytes=probe, at_ms=probe_at + 10 + offset
            ))

        session_key = (1, self.initiator.local_node_id,
                       self.initiator.association.local_epoch, sequence)
        session = self.responder.reassembly.active[session_key]
        self.assertEqual(session.received_indices, {0, 2})
        self.assertEqual(session.selective_status_count, 1)
        second_due = session.selective_feedback_due_ms
        self.assertIsNotNone(second_due)
        second_events = self.responder.handle(Advance(now_ms=second_due))
        self.assertFalse(any(
            isinstance(event, TxSubmit)
            and self.responder.active_submissions.get(event.handle, {}).get("is_frag_status")
            for event in second_events
        ))
        self.assertEqual(session.selective_status_count, 1)
        self.assertFalse(any(item.get("is_frag_status") for item in self.responder.tx_queue))

    def test_unavailable_adapter_slot_defers_status_within_feedback_delay(self) -> None:
        self.initiator.handle(Advance(now_ms=200))
        outgoing: list[Any] = []
        sequence = self.initiator._queue_data_transfer(
            2, bytes(index % 251 for index in range(96)), ack_req=True, out=outgoing
        )
        initial = helpers.extract_and_settle(self.initiator, outgoing, at_ms=201)
        first_slice = next(wire for wire in initial if parse_frame(wire).fragment.index == 0)
        self.responder.handle(Receive(link=0, bytes=first_slice, at_ms=300))

        occupied: list[tuple[int, int]] = []
        for offset in range(self.responder.adapter_slots):
            filler_events: list[Any] = []
            self.responder._enqueue_tx(
                b"busy-slot-" + bytes((offset,)),
                not_after_ms=None,
                service_id=0,
                out=filler_events,
            )
            submission = next(event for event in filler_events if isinstance(event, TxSubmit))
            occupied.append((submission.handle, submission.generation))
        self.assertEqual(len(self.responder.active_submissions), self.responder.adapter_slots)

        unavailable_events = self.responder.handle(Advance(now_ms=2372))
        session_key = (1, self.initiator.local_node_id,
                       self.initiator.association.local_epoch, sequence)
        session = self.responder.reassembly.active[session_key]
        self.assertFalse(any(isinstance(event, TxSubmit) for event in unavailable_events))
        self.assertEqual(session.selective_status_count, 0)
        self.assertEqual(session.selective_feedback_due_ms, 2372)
        self.assertFalse(any(item.get("is_frag_status") for item in self.responder.tx_queue))

        # Free one slot before feedback_delay expires. The original opportunity
        # remains pending and is submitted without requiring another slice.
        handle, generation = occupied[0]
        self.responder.handle(TxAdmit(
            handle=handle, generation=generation, accepted=True, reason=None, at_ms=2373
        ))
        self.responder.handle(TxTerminal(
            handle=handle, generation=generation, outcome="transmitted", at_ms=2374
        ))
        deferred_events = self.responder.handle(Advance(now_ms=2375))
        deferred_status = [event for event in deferred_events if isinstance(event, TxSubmit)]
        self.assertEqual(len(deferred_status), 1)
        self.assertTrue(self.responder.active_submissions[deferred_status[0].handle]["is_frag_status"])
        self.assertEqual(session.selective_status_count, 1)
        self.assertIsNone(session.selective_feedback_due_ms)

    def test_status_obligation_expires_after_feedback_delay(self) -> None:
        self.initiator.handle(Advance(now_ms=200))
        outgoing: list[Any] = []
        sequence = self.initiator._queue_data_transfer(
            2, bytes(index % 251 for index in range(96)), ack_req=True, out=outgoing
        )
        initial = helpers.extract_and_settle(self.initiator, outgoing, at_ms=201)
        first_slice = next(wire for wire in initial if parse_frame(wire).fragment.index == 0)
        self.responder.handle(Receive(link=0, bytes=first_slice, at_ms=300))
        occupied: list[tuple[int, int]] = []
        for offset in range(self.responder.adapter_slots):
            filler_events: list[Any] = []
            self.responder._enqueue_tx(
                b"busy-slot-" + bytes((offset,)),
                not_after_ms=None,
                service_id=0,
                out=filler_events,
            )
            submission = next(event for event in filler_events if isinstance(event, TxSubmit))
            occupied.append((submission.handle, submission.generation))
        self.responder.handle(Advance(now_ms=2372))
        session_key = (1, self.initiator.local_node_id,
                       self.initiator.association.local_epoch, sequence)
        session = self.responder.reassembly.active[session_key]
        self.assertEqual(session.selective_feedback_due_ms, 2372)

        handle, generation = occupied[0]
        self.responder.handle(TxAdmit(
            handle=handle, generation=generation, accepted=True, reason=None, at_ms=2483
        ))
        self.responder.handle(TxTerminal(
            handle=handle, generation=generation, outcome="transmitted", at_ms=2484
        ))
        expired_events = self.responder.handle(Advance(now_ms=2485))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in expired_events))
        self.assertIsNone(session.selective_feedback_due_ms)
        self.assertEqual(session.selective_status_count, 0)

        second_slice = next(wire for wire in initial if parse_frame(wire).fragment.index == 1)
        self.responder.handle(Receive(link=0, bytes=second_slice, at_ms=2486))
        self.assertEqual(session.received_indices, {0, 1})
        self.assertEqual(session.selective_feedback_due_ms, 2486 + 2072)

    def test_status_extension_registry_rules_allow_unknown_safe_and_reject_required_unknown(self) -> None:
        self.initiator.handle(Advance(now_ms=200))
        outgoing: list[Any] = []
        sequence = self.initiator._queue_data_transfer(
            2, bytes(range(64)), ack_req=True, out=outgoing
        )
        helpers.extract_and_settle(self.initiator, outgoing, at_ms=201)
        state = self.initiator.outgoing_data[sequence].selective_state
        target_key = (1, self.initiator.local_node_id, self.initiator.local_epoch, sequence)

        route, context = self.responder._routed_fields()
        def extra_status(*, critical: bool, value: bytes) -> bytes:
            extensions = (
            Extension(1, True, False, encode_uleb(sequence)),
            context,
            Extension(4, True, False, encode_uleb(2)),
                Extension(7, critical, False, value),
            )
            frame = CoreFrame(
                message_type=8,
                options=1 | 0x80 | 4,
                sequence=self.responder._alloc_seq(),
                route=route,
                extensions=extensions,
            )
            return self.responder._encrypt_and_encode(frame, b"\x01\x00\x00\x00")

        for invalid in (extra_status(critical=True, value=b""),
                        extra_status(critical=True, value=b"opaque")):
            before = vars(state).copy()
            events = self.initiator.handle(Receive(link=0, bytes=invalid, at_ms=202))
            self.assertFalse(any(isinstance(event, TxSubmit) for event in events))
            self.assertEqual(vars(state), before)

        for status in (extra_status(critical=False, value=b""),
                       extra_status(critical=False, value=b"opaque")):
            self.initiator.handle(Receive(link=0, bytes=status, at_ms=203))
        self.assertEqual(state.status_count, 2)
        self.assertEqual(state.pending_mask, 0x01)

    def test_expired_assembly_tombstone_pressure_refuses_new_identity(self) -> None:
        payload = bytes(range(64))
        now_ms = 300
        admitted_keys = []
        for index in range(self.responder.reassembly.tombstones_per_peer):
            sequence = 1000 + index
            frames = self.initiator._build_data_frames(
                2, sequence, payload, ack_req=True
            )
            first = next(wire for wire in frames if parse_frame(wire).fragment.index == 0)
            events = self.responder.handle(Receive(
                link=0, bytes=first, at_ms=now_ms
            ))
            self.assertFalse(any(
                isinstance(event, ApplicationEvent) for event in events
            ))
            key = (1, self.initiator.local_node_id,
                   self.initiator.local_epoch, sequence)
            session = self.responder.reassembly.active[key]
            admitted_keys.append(key)
            expire_at = session.expires_at_ms
            expiry_events = self.responder.handle(Advance(now_ms=expire_at))
            helpers.extract_and_settle(
                self.responder, expiry_events, at_ms=expire_at + 1
            )
            self.assertNotIn(key, self.responder.reassembly.active)
            self.assertIn(key, self.responder.reassembly.tombstones)
            self.assertIsNone(self.responder.reassembly.tombstones[key])
            now_ms = expire_at + 2

        self.assertEqual(len(self.responder.reassembly.tombstones),
                         self.responder.reassembly.tombstones_per_peer)
        sequence = 1000 + self.responder.reassembly.tombstones_per_peer
        frames = self.initiator._build_data_frames(2, sequence, payload, ack_req=True)
        first = next(wire for wire in frames if parse_frame(wire).fragment.index == 0)
        refused = self.responder.handle(Receive(
            link=0, bytes=first, at_ms=now_ms
        ))
        refused_key = (1, self.initiator.local_node_id,
                       self.initiator.local_epoch, sequence)
        self.assertNotIn(refused_key, self.responder.reassembly.active)
        self.assertEqual(len(self.responder.reassembly.tombstones),
                         self.responder.reassembly.tombstones_per_peer)
        self.assertFalse(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in refused
        ))

    def test_acl_refuses_fragmented_data_before_reassembly(self) -> None:
        frames = self.initiator._build_data_frames(
            1, 2000, bytes(range(64)), ack_req=True
        )
        for index, frame in enumerate(frames):
            events = self.responder.handle(Receive(
                link=0, bytes=frame, at_ms=300 + index
            ))
            self.assertFalse(any(isinstance(event, TxSubmit) for event in events))
        self.assertEqual(self.responder.reassembly.active, {})
        self.assertEqual(self.responder.delivery.accepted_messages, {})

    def test_missing_freshness_token_does_not_start_selective_request(self) -> None:
        events = self.initiator.handle(ApplicationRequest(
            service_id=2, payload=bytes(range(64)), ack_req=True, at_ms=200
        ))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in events))
        self.assertFalse(self.initiator.delivery.active_outgoing)
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "protocol_rejection"
            and event.payload == b"freshness_token_required"
            for event in events
        ))


if __name__ == "__main__":
    unittest.main()
