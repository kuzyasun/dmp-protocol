"""Cross-endpoint RADIO-1 R7 recovery checks over deterministic relays.

These tests compose the existing RADIO-1 harness rather than inheriting its
TestCase, so its existing tests are not discovered a second time.

Covered here: exact RADIO-1 profile binding, bidirectional protected TYPE-8
exchange, independent mask interpretation, replay idempotency, protected
invalid mask/reference/service feedback, deterministic loss recovery, fixed
recovery horizons, expiry/tombstone behavior, relay bounds, and freshness.
"""

from __future__ import annotations

import unittest

import test_p23_radio_endpoint_interop as radio
from dmp_peer.events import Advance, ApplicationRequest, TxAdmit, TxSubmit, TxTerminal
from dmp_peer.frame import CoreFrame, Extension, FrameError, encode_frame


@unittest.skipUnless(
    radio.os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
    "C P23 endpoint executable is not configured",
)
class TestP23R7CrossEndpointInterop(unittest.TestCase):
    def setUp(self) -> None:
        # Composition intentionally reuses real C/Python endpoint and relay
        # helpers without inheriting the helper TestCase's test methods.
        self.harness = radio.TestP23RadioEndpointInterop("runTest")
        self.harness.setUp()
        self.addCleanup(self.harness.doCleanups)

    def _start_c_request(self, seed: int, payload: bytes):
        c_endpoint, peer, relays, clock = self.harness._open_pair(radio._RADIO, seed)
        self.harness._activate(c_endpoint, peer, relays, clock)
        grant = c_endpoint.submit_req(
            0, b"\x10" + (12_000).to_bytes(4, "little"), clock.next()
        )
        self.assertEqual(grant.status, 0)
        self.harness._dispatch(c_endpoint, peer, relays, 20, grant.frames, clock)
        token = c_endpoint.last_state.result[1:17]
        self.assertEqual(len(token), 16)
        request_payload = payload
        request = c_endpoint.submit_req_fresh(2, request_payload, token, clock.next())
        self.assertEqual(request.status, 0)
        frames = [radio._decode_c_stream_frame(wire) for wire in request.frames]
        parsed = [radio.parse_frame(wire, max_frame=radio._MAX_CORE) for wire in frames]
        self.assertEqual(len(parsed), 8)
        self.assertTrue(all(frame.fragment is not None for frame in parsed))
        self.assertTrue(all(frame.security is not None for frame in parsed))
        self.assertTrue(all(frame.sequence == parsed[0].sequence for frame in parsed))
        return c_endpoint, peer, relays, clock, request, request_payload, parsed[0].sequence, parsed

    def test_c_protected_status_has_exact_missing_mask_and_replay_is_idempotent(self) -> None:
        payload = bytes((index * 13 + 7) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock, sequence, frames = (
            self.harness._start_peer_data_transfer(0xD1, payload)
        )
        initial_accepts = c_endpoint.last_state.accepts
        self.harness._dispatch(
            c_endpoint,
            peer,
            relays,
            10,
            frames,
            clock,
            drop={(sequence, 2), (sequence, 6)},
        )
        self.assertEqual(c_endpoint.last_state.accepts, initial_accepts)

        # Poll the C receiver at the real manifest schedule until it emits
        # authenticated TYPE 8 feedback. Do not inspect/decode its ciphertext
        # structurally: the independent Python endpoint consumes it below and
        # exposes the independently interpreted missing mask.
        status_wires: list[bytes] = []
        collect_ms = int(peer.manifest.values["timing"]["collect_ms"])
        feedback_delay_ms = int(peer.manifest.values["timing"]["feedback_delay_ms"])
        deadline = clock.now_ms + collect_ms + feedback_delay_ms + 2_000
        while clock.now_ms <= deadline and not status_wires:
            state = c_endpoint.poll(clock.advance(16))
            self.assertEqual(state.status, 0)
            decoded = [
                radio._decode_c_stream_frame(wire)
                for wire in state.frames
                if wire != b"\x00"
            ]
            status_wires = [
                wire for wire in decoded
                if radio.parse_frame(wire, max_frame=radio._MAX_CORE).message_type == 8
            ]
        self.assertEqual(len(status_wires), 1)
        status = radio.parse_frame(status_wires[0], max_frame=radio._MAX_CORE)
        self.assertIsNotNone(status.security)
        self.assertIsNotNone(status.route)
        self.assertEqual(status.message_type, 8)
        self.assertEqual(status.options & 1, 1)  # sequence field is present
        references = [ext for ext in status.extensions if ext.extension_id == 1]
        self.assertEqual(len(references), 1)
        self.assertEqual(references[0].value, radio.encode_uleb(sequence))

        transfer = peer.outgoing_data[(peer.association.h, sequence)]
        before_statuses = transfer.selective_state.status_count
        peer_out, _ = self.harness._dispatch(
            c_endpoint, peer, relays, 20, status_wires, clock
        )
        self.assertEqual(peer_out, [])  # feedback is held until the initial burst settles
        selective = transfer.selective_state
        self.assertEqual(selective.status_count, before_statuses + 1)
        self.assertEqual(selective.pending_mask, (1 << 2) | (1 << 6))

        # Replay the identical protected status through the same two relay
        # hops. SEC-1 replay handling must not count it twice or create a
        # second repair burst.
        # Keep each duplicate within the relay's admitted per-key forwarding
        # count while spacing it beyond cooldown so the endpoint replay gate,
        # rather than relay suppression, is what rejects the duplicate.
        for _ in range(8):
            clock.advance(relays[30].cooldown_ms + 1)
            duplicate_out, _ = self.harness._dispatch(
                c_endpoint, peer, relays, 20, status_wires, clock
            )
            self.assertEqual(duplicate_out, [])
        for relay in relays.values():
            self.assertTrue(all(
                entry.forwards <= relay.max_forwards_per_key
                for entry in relay._entries.values()
            ))
        self.assertEqual(selective.status_count, before_statuses + 1)
        self.assertEqual(selective.pending_mask, (1 << 2) | (1 << 6))

        repairs: list[int] = []
        repair_at = selective.started_at_ms + 4_352
        for now in range(repair_at, repair_at + 128, 16):
            clock.now_ms = max(clock.now_ms, now)
            generated = self.harness._peer_send(
                peer, peer.handle(radio.Advance(now_ms=now)), clock
            )
            if generated:
                repairs.extend(
                    radio.parse_frame(wire, max_frame=radio._MAX_CORE).fragment.index
                    for wire in generated
                    if radio.parse_frame(wire, max_frame=radio._MAX_CORE).fragment is not None
                )
                self.harness._dispatch(c_endpoint, peer, relays, 10, generated, clock)
                break
        self.assertEqual(repairs, [2, 6])
        self.assertEqual(c_endpoint.last_state.accepts, initial_accepts)
        self.assertEqual(c_endpoint.last_state.assembled, 1)
        self.assertEqual(c_endpoint.last_state.body, payload)

    def test_c_status_retries_after_transport_reports_no_adapter_slot(self) -> None:
        payload = bytes((index * 5 + 1) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock, sequence, frames = (
            self.harness._start_peer_data_transfer(0xE1, payload)
        )
        missing_initial = {(sequence, index) for index in range(1, 8)}
        self.harness._dispatch(
            c_endpoint,
            peer,
            relays,
            10,
            frames,
            clock,
            drop=missing_initial,
        )
        self.assertFalse(missing_initial)

        # Reject the first due protected feedback frame at the actual C
        # transport callback boundary, then require the next poll to retry it.
        reject = c_endpoint.reject_next_tx(1, clock.next())
        self.assertEqual(reject.status, 0, reject.endpoint_status)
        timing = peer.manifest.values["timing"]
        collection_wait = (
            int(timing["burst_span_ms"])
            + int(timing["forward_delay_ms"])
            + int(timing["feedback_guard_ms"])
        )
        first_due = c_endpoint.poll(clock.advance(collection_wait))
        self.assertEqual(first_due.status, 0, first_due.endpoint_status)
        self.assertFalse(first_due.frames)

        retried = c_endpoint.poll(clock.next())
        self.assertEqual(retried.status, 0, retried.endpoint_status)
        status_frames = [
            radio._decode_c_stream_frame(wire)
            for wire in retried.frames
            if wire != b"\x00"
        ]
        self.assertEqual(len(status_frames), 1)
        status = radio.parse_frame(status_frames[0], max_frame=radio._MAX_CORE)
        self.assertEqual(status.message_type, 8)
        self.assertIsNotNone(status.security)
        self.assertIsNotNone(status.route)

        forwarded = self.harness._route(
            relays, status_frames[0], source=20, clock=clock
        )
        peer.handle(radio.Receive(link=0, bytes=forwarded, at_ms=clock.next()))
        transfer = peer.outgoing_data[(peer.association.h, sequence)]
        self.assertEqual(transfer.selective_state.status_count, 1)
        self.assertEqual(transfer.selective_state.pending_mask, 0xFE)

    def test_delayed_status_during_live_burst_is_coalesced_without_feedback_storm(self) -> None:
        c_endpoint, peer, relays, clock = self.harness._open_pair(radio._RADIO, 0xDD)
        self.harness._activate(c_endpoint, peer, relays, clock)
        self.harness._grant_freshness(c_endpoint, peer, relays, clock)
        payload = bytes(range(64))
        outgoing: list[object] = []
        sequence = peer._queue_data_transfer(2, payload, ack_req=True, out=outgoing)
        initial = [event for event in outgoing if isinstance(event, TxSubmit)]
        self.assertEqual(len(initial), 2)
        transfer = peer.outgoing_data[(peer.association.h, sequence)]
        selective = transfer.selective_state
        self.assertEqual(selective.active_kind, "initial")
        self.assertEqual(selective.frames_remaining, 2)

        # One of the actual sender submissions arrives through the relays;
        # the second remains pending in the Python adapter while the real C
        # endpoint schedules delayed TYPE 8 feedback.
        self.harness._dispatch(
            c_endpoint, peer, relays, 10, [initial[0].bytes], clock
        )
        status_wires: list[bytes] = []
        deadline = clock.now_ms + int(peer.manifest.values["timing"]["assembly_ms"])
        while clock.now_ms < deadline and not status_wires:
            state = c_endpoint.poll(clock.advance(16))
            self.assertEqual(state.status, 0)
            for wire in state.frames:
                if wire == b"\x00":
                    continue
                decoded = radio._decode_c_stream_frame(wire)
                if radio.parse_frame(decoded, max_frame=radio._MAX_CORE).message_type == 8:
                    status_wires.append(wire)
        self.assertEqual(len(status_wires), 1)

        def deliver_status_without_settling_peer(wire: bytes) -> list[object]:
            decoded = radio._decode_c_stream_frame(wire)
            routed = self.harness._route(relays, decoded, source=20, clock=clock)
            return peer.handle(radio.Receive(
                link=0, bytes=routed, at_ms=clock.next()
            ))

        first_feedback_events = deliver_status_without_settling_peer(status_wires[0])
        self.assertFalse(any(isinstance(event, TxSubmit) for event in first_feedback_events))
        self.assertEqual(selective.active_kind, "initial")
        self.assertEqual(selective.frames_remaining, 2)
        self.assertEqual(selective.pending_mask, 0x02)
        self.assertEqual(selective.status_count, 1)

        # Relay admitted replay duplicates are spaced beyond its cooldown.
        # The SEC-1 replay window and SELECTIVE-32 status counter suppress
        # duplicate work even while the initial burst remains unsettled.
        for _ in range(8):
            clock.advance(relays[30].cooldown_ms + 1)
            repeated = deliver_status_without_settling_peer(status_wires[0])
            self.assertFalse(any(isinstance(event, TxSubmit) for event in repeated))
            self.assertEqual(selective.status_count, 1)
            self.assertEqual(selective.pending_mask, 0x02)
            self.assertEqual(selective.frames_remaining, 2)

        for handle, submission in list(peer.active_submissions.items()):
            peer.handle(TxAdmit(
                handle=handle,
                generation=submission["generation"],
                accepted=True,
                reason=None,
                at_ms=clock.next(),
            ))
            peer.handle(TxTerminal(
                handle=handle,
                generation=submission["generation"],
                outcome="transmitted",
                at_ms=clock.next(),
            ))
        self.assertIsNone(selective.active_kind)
        repair_at = selective.started_at_ms + 4_352
        clock.now_ms = max(clock.now_ms, repair_at)
        repairs = self.harness._peer_send(
            peer, peer.handle(Advance(now_ms=repair_at)), clock
        )
        self.assertEqual([
            radio.parse_frame(wire, max_frame=radio._MAX_CORE).fragment.index
            for wire in repairs
        ], [1])
        self.harness._dispatch(c_endpoint, peer, relays, 10, repairs, clock)
        self.assertEqual(c_endpoint.last_state.accepts, 0)
        self.assertEqual(c_endpoint.last_state.assembled, 1)
        self.assertEqual(c_endpoint.last_state.body, payload)

    def test_python_protected_status_repairs_c_originated_request_over_relays(self) -> None:
        """Exercise C as the sender and Python as the recovery receiver."""
        payload = bytes((index * 17 + 3) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock, request, payload, sequence, parsed = (
            self._start_c_request(0xD2, payload)
        )
        self.assertTrue(all(
            6 in {extension.extension_id for extension in frame.extensions}
            for frame in parsed
        ))
        # Drop two actual protected C fragments at the simulated relay path.
        self.harness._dispatch(
            c_endpoint,
            peer,
            relays,
            20,
            [wire for index, wire in enumerate(request.frames) if index not in {1, 5}],
            clock,
        )
        accepted: list[radio.Any] = []
        feedback: list[bytes] = []
        repairs: list[int] = []
        deadline = clock.now_ms + 10_000
        while clock.now_ms < deadline and not any(
            event.kind == "request_accepted" and event.service_id == 2
            and event.payload == payload for event in accepted
        ):
            now = clock.advance(64)
            generated = self.harness._peer_send(
                peer, peer.handle(radio.Advance(now_ms=now)), clock
            )
            feedback.extend(
                wire for wire in generated
                if radio.parse_frame(wire, max_frame=radio._MAX_CORE).message_type == 8
            )
            if generated:
                observed: list[radio.Any] = []
                peer_out, c_fragments = self.harness._dispatch(
                    c_endpoint, peer, relays, 10, generated, clock, observed=observed
                )
                accepted.extend(observed)
                repairs.extend(c_fragments)
        self.assertTrue(feedback, "Python receiver did not emit protected TYPE 8")
        self.assertTrue(all(
            radio.parse_frame(wire, max_frame=radio._MAX_CORE).security is not None
            and radio.parse_frame(wire, max_frame=radio._MAX_CORE).route is not None
            for wire in feedback
        ))
        accepted_requests = [
            event for event in accepted
            if event.kind == "request_accepted" and event.service_id == 2
            and event.payload == payload
        ]
        self.assertEqual(len(accepted_requests), 1)
        self.assertEqual(sorted(repairs), [1, 5])

    def test_freshness_failures_do_not_enter_c_reassembly_over_radio_relays(self) -> None:
        # Reuse the real C endpoint, independent peer, and two deterministic
        # relays; its assertions distinguish missing, mismatched, and expired
        # S7 authorization and verify no service-2 application dispatch.
        self.harness._exercise_radio_freshness_rejections(radio._RADIO, 0xD4)

    def test_seeded_radio_endpoint_pair_repeats_protected_wire_bytes(self) -> None:
        payload = bytes((index * 31 + 9) & 0xFF for index in range(256))

        def exchange(seed: int) -> list[bytes]:
            c_endpoint, peer, relays, clock = self.harness._open_pair(radio._RADIO, seed)
            self.harness._activate(c_endpoint, peer, relays, clock)
            self.harness._grant_freshness(c_endpoint, peer, relays, clock)
            outgoing = []
            peer._queue_data_transfer(2, payload, ack_req=True, out=outgoing)
            frames = self.harness._peer_send(peer, outgoing, clock)
            self.assertEqual(len(frames), 8)
            self.assertTrue(all(
                radio.parse_frame(frame, max_frame=radio._MAX_CORE).security is not None
                for frame in frames
            ))
            return frames

        self.assertEqual(exchange(0xD5), exchange(0xD5))

    def test_final_slice_and_total_initial_loss_recover_over_relays(self) -> None:
        payload = bytes((index * 7 + 1) & 0xFF for index in range(256))
        for label, seed, missing, expected in (
            ("final", 0xD6, {7}, [7]),
            ("all", 0xD7, set(range(8)), [7, 0, 1, 2, 3, 4, 5, 6]),
        ):
            with self.subTest(loss=label):
                c_endpoint, peer, relays, clock, sequence, frames = (
                    self.harness._start_peer_data_transfer(seed, payload)
                )
                self.harness._dispatch(
                    c_endpoint, peer, relays, 10, frames, clock,
                    drop={(sequence, index) for index in missing},
                )
                repairs, statuses = self.harness._advance_data_recovery(
                    c_endpoint, peer, relays, clock
                )
                self.assertEqual(repairs, expected)
                self.assertTrue(statuses)
                self.assertEqual(c_endpoint.last_state.accepts, 0)
                self.assertEqual(c_endpoint.last_state.assembled, 1)
                self.assertEqual(c_endpoint.last_state.body, payload)

    def test_all_loss_feedback_cannot_extend_the_absolute_send_horizon(self) -> None:
        payload = bytes((index * 5 + 3) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock, sequence, frames = (
            self.harness._start_peer_data_transfer(0xD8, payload)
        )
        transfer = peer.outgoing_data[(peer.association.h, sequence)]
        selective = transfer.selective_state
        horizon = selective.horizon_at_ms
        self.harness._dispatch(
            c_endpoint, peer, relays, 10, frames, clock,
            drop={(sequence, index) for index in range(8)},
        )
        self.assertEqual(c_endpoint.last_state.accepts, 0)

        # Total loss causes the protocol's bounded final-slice probe. The C
        # endpoint sees that real protected fragment, emits TYPE 8, and the
        # independent sender interprets the exact seven-bit missing mask.
        probe_at = selective.started_at_ms + 4_352
        clock.now_ms = max(clock.now_ms, probe_at)
        probe = self.harness._peer_send(
            peer, peer.handle(radio.Advance(now_ms=probe_at)), clock
        )
        self.assertEqual([
            radio.parse_frame(wire, max_frame=radio._MAX_CORE).fragment.index
            for wire in probe
        ], [7])
        self.harness._dispatch(c_endpoint, peer, relays, 10, probe, clock)
        self.assertEqual(c_endpoint.last_state.accepts, 0)

        status_wires: list[bytes] = []
        assembly_ms = int(peer.manifest.values["timing"]["assembly_ms"])
        assembly_deadline = clock.now_ms + assembly_ms
        while clock.now_ms < min(horizon, assembly_deadline) and not status_wires:
            state = c_endpoint.poll(clock.advance(16))
            self.assertEqual(state.status, 0)
            status_wires = [
                radio._decode_c_stream_frame(wire)
                for wire in state.frames if wire != b"\x00"
                if radio.parse_frame(
                    radio._decode_c_stream_frame(wire), max_frame=radio._MAX_CORE
                ).message_type == 8
            ]
        self.assertEqual(len(status_wires), 1)
        self.harness._dispatch(c_endpoint, peer, relays, 20, status_wires, clock)
        self.assertEqual(selective.pending_mask, 0x7F)
        self.assertEqual(selective.horizon_at_ms, horizon)

        clock.now_ms = max(clock.now_ms, horizon)
        late_repairs = self.harness._peer_send(
            peer, peer.handle(radio.Advance(now_ms=horizon)), clock
        )
        self.assertEqual(late_repairs, [])
        self.assertTrue(selective.terminal)
        self.assertIsNone(selective.pending_mask)
        self.assertEqual(selective.horizon_at_ms, horizon)

    def test_c_assembly_expiry_tombstones_late_slice_over_relays(self) -> None:
        payload = bytes(range(256))
        c_endpoint, peer, relays, clock, _, frames = (
            self.harness._start_peer_data_transfer(0xD9, payload)
        )
        routed_first = self.harness._route(relays, frames[0], source=10, clock=clock)
        first = c_endpoint.receive(
            radio.encode_stream_r(
                routed_first, max_core=radio._MAX_CORE, max_encoded=radio._MAX_ENCODED,
            ),
            clock.next(),
        )
        self.assertEqual(first.accepts, 0)
        self.assertEqual(first.rx_status, 7)

        assembly_ms = int(peer.manifest.values["timing"]["assembly_ms"])
        expired = c_endpoint.poll(clock.advance(assembly_ms + 1))
        self.assertEqual(expired.status, 0)
        self.assertFalse(expired.fragment_live)
        self.assertEqual(expired.accepts, 0)

        late = self.harness._route(relays, frames[1], source=10, clock=clock)
        rejected = c_endpoint.receive(
            radio.encode_stream_r(
                late, max_core=radio._MAX_CORE, max_encoded=radio._MAX_ENCODED
            ),
            clock.next(),
        )
        self.assertNotEqual(rejected.status, 0)
        self.assertEqual(rejected.accepts, 0)
        self.assertEqual(rejected.assembled, 0)
        self.assertEqual(rejected.body, b"")

    def test_c_tombstone_reservation_pressure_rejects_new_assembly(self) -> None:
        self.skipTest(
            "the exact RADIO-1 manifest admits one active assembly per peer "
            "(assembly_ms=10777) and retains tombstones for 23040 ms; sequential "
            "expiry can create at most ceil(23040/10777)=3 tombstones, below the "
            "limit of 16. Python has no authorized service-1 DATA path to create "
            "overlapping C assemblies. C and Python local quota cases cover the "
            "16/17 boundary; a faithful cross-endpoint pressure state is unreachable."
        )

    def test_relay_cooldown_and_forward_limit_use_real_endpoint_frame(self) -> None:
        payload = bytes((index * 3 + 11) & 0xFF for index in range(256))
        _, _, relays, clock, _, frames = self.harness._start_peer_data_transfer(
            0xDA, payload
        )
        relay = relays[30]
        wire = frames[0]

        keys_before = set(relay._entries)
        first_at = clock.next()
        first = relay.receive(wire, first_at)
        self.assertTrue(first.forwarded, first.reason)
        self.assertIsNotNone(first.frame)
        radio._assert_ttl_only(self.harness, wire, first.frame)
        relay.complete(first.token, first_at + 1, transmitted=True)
        new_keys = set(relay._entries) - keys_before
        self.assertEqual(len(new_keys), 1)

        cooldown_reject = relay.receive(wire, first_at + 2)
        self.assertFalse(cooldown_reject.forwarded)
        self.assertEqual(cooldown_reject.reason, "cooldown")

        complete_at = first_at + 1
        for _ in range(relay.max_forwards_per_key - 1):
            next_at = complete_at + relay.cooldown_ms
            decision = relay.receive(wire, next_at)
            self.assertTrue(decision.forwarded, decision.reason)
            self.assertIsNotNone(decision.frame)
            radio._assert_ttl_only(self.harness, wire, decision.frame)
            relay.complete(decision.token, next_at + 1, transmitted=True)
            complete_at = next_at + 1

        limit_reject = relay.receive(wire, complete_at + relay.cooldown_ms)
        self.assertFalse(limit_reject.forwarded)
        self.assertEqual(limit_reject.reason, "forward-limit")

    def test_status_from_another_association_cannot_repair_c_transfer(self) -> None:
        payload = bytes((index * 19 + 7) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock, request, _, sequence, _ = (
            self._start_c_request(0xDB, payload)
        )
        self.harness._dispatch(
            c_endpoint, peer, relays, 20,
            [wire for index, wire in enumerate(request.frames) if index not in {2, 6}],
            clock,
        )

        # A separate real Python endpoint establishes a different SEC-1
        # association under the same RADIO-1 manifest and builds a protected
        # status for the same wire SEQ. Its ciphertext must not affect C's
        # active sender state.
        unrelated_c, unrelated_peer, unrelated_relays, unrelated_clock = (
            self.harness._open_pair(radio._RADIO, 0xDC)
        )
        self.harness._activate(
            unrelated_c, unrelated_peer, unrelated_relays, unrelated_clock
        )
        foreign = unrelated_peer._build_fragment_status(
            (1, 20, unrelated_peer.association.peer_epoch, sequence), 2, 1 << 2
        )
        self.assertIsNotNone(foreign)
        routed = self.harness._route(relays, foreign, source=10, clock=clock)
        before = c_endpoint.last_state
        state = c_endpoint.receive(
            radio.encode_stream_r(
                routed, max_core=radio._MAX_CORE, max_encoded=radio._MAX_ENCODED
            ),
            clock.next(),
        )
        output = [
            radio._decode_c_stream_frame(wire)
            for wire in state.frames if wire != b"\x00"
        ]
        self.assertFalse(any(
            radio.parse_frame(frame, max_frame=radio._MAX_CORE).message_type == 7
            and radio.parse_frame(frame, max_frame=radio._MAX_CORE).fragment is not None
            for frame in output
        ))
        self.assertEqual(state.accepts, before.accepts)
        self.assertEqual(state.results, before.results)
        self.assertTrue(state.bound)

    def test_fresh_packet_number_with_older_max_boundary_status_seq_keeps_newer_mask(self) -> None:
        payload = bytes((index * 29 + 1) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock = self.harness._open_pair(
            radio._RADIO, 0xDE, async_tx_completion=True
        )
        self.harness._activate(c_endpoint, peer, relays, clock)
        grant = c_endpoint.submit_req(
            0, b"\x10" + (12_000).to_bytes(4, "little"), clock.next()
        )
        self.assertEqual(grant.status, 0)
        self.harness._dispatch(c_endpoint, peer, relays, 20, grant.frames, clock)
        token = c_endpoint.last_state.result[1:17]
        self.assertEqual(len(token), 16)
        self.assertEqual(c_endpoint.complete_tx(1, clock.next()).status, 0)

        request = c_endpoint.submit_req_fresh(2, payload, token, clock.next())
        self.assertEqual(request.status, 0)
        first_batch = [wire for wire in request.frames if wire != b"\x00"]
        initial_by_index = {
            radio.parse_frame(radio._decode_c_stream_frame(wire), max_frame=radio._MAX_CORE)
            .fragment.index: wire
            for wire in first_batch
        }
        all_initial = list(first_batch)
        last_batch = first_batch
        while set(initial_by_index) != set(range(8)):
            completed = c_endpoint.complete_tx(len(last_batch), clock.next())
            self.assertEqual(completed.status, 0, completed.endpoint_status)
            polled = c_endpoint.poll(clock.next())
            self.assertEqual(polled.status, 0, polled.endpoint_status)
            last_batch = [wire for wire in polled.frames if wire != b"\x00"]
            self.assertTrue(last_batch)
            for wire in last_batch:
                parsed = radio.parse_frame(
                    radio._decode_c_stream_frame(wire), max_frame=radio._MAX_CORE
                )
                self.assertIsNotNone(parsed.fragment)
                assert parsed.fragment is not None
                initial_by_index[parsed.fragment.index] = wire
            all_initial.extend(last_batch)
        delivered = [wire for index, wire in initial_by_index.items() if index != 2]
        self.harness._dispatch(c_endpoint, peer, relays, 20, delivered, clock)
        sequence = next(iter(initial_by_index.values()))
        sequence = radio.parse_frame(
            radio._decode_c_stream_frame(sequence), max_frame=radio._MAX_CORE
        ).sequence
        active_key = next(key for key in peer.reassembly.active if key[3] == sequence)
        route, context = peer._routed_fields()

        def status_with_sequence(feedback_seq: int, mask: int) -> bytes:
            extensions = [Extension(1, True, False, radio.encode_uleb(sequence))]
            if context is not None:
                extensions.append(context)
            if 2 != peer.default_service:
                extensions.append(Extension(4, True, False, radio.encode_uleb(2)))
            frame = CoreFrame(
                message_type=8,
                options=1 | 0x80 | (4 if route is not None else 0),
                sequence=feedback_seq,
                route=route,
                extensions=tuple(extensions),
                payload=b"",
            )
            return peer._encrypt_and_encode(
                frame, plaintext=mask.to_bytes(4, "little")
            )

        # The cryptographic packet numbers advance normally while the logical
        # feedback SEQ moves backward at the u32 boundary. The older snapshot
        # must not supersede the first mask.
        newer = status_with_sequence(0xFFFFFFFF, 1 << 2)
        older = status_with_sequence(0xFFFFFFFE, 1 << 5)
        self.assertLess(
            radio.parse_frame(newer, max_frame=radio._MAX_CORE).security.packet_number,
            radio.parse_frame(older, max_frame=radio._MAX_CORE).security.packet_number,
        )
        for wire in (newer, older):
            routed = self.harness._route(relays, wire, source=10, clock=clock)
            received = c_endpoint.receive(
                radio.encode_stream_r(
                    routed, max_core=radio._MAX_CORE, max_encoded=radio._MAX_ENCODED
                ),
                clock.next(),
            )
            self.assertEqual(received.status, 0)

        completed = c_endpoint.complete_tx(len(last_batch), clock.next())
        self.assertEqual(completed.status, 0, completed.endpoint_status)
        generated = [wire for wire in completed.frames if wire != b"\x00"]
        polled = c_endpoint.poll(clock.next())
        self.assertEqual(polled.status, 0, polled.endpoint_status)
        generated.extend(wire for wire in polled.frames if wire != b"\x00")
        repair_frames = [radio._decode_c_stream_frame(wire) for wire in generated]
        repair_indices = [
            radio.parse_frame(frame, max_frame=radio._MAX_CORE).fragment.index
            for frame in repair_frames
            if radio.parse_frame(frame, max_frame=radio._MAX_CORE).fragment is not None
        ]
        self.assertEqual(repair_indices, [2])
        accepted: list[radio.Any] = []
        self.harness._dispatch(
            c_endpoint, peer, relays, 20, generated, clock, observed=accepted
        )
        self.assertEqual(
            len([event for event in accepted if event.kind == "request_accepted" and event.payload == payload]),
            1,
        )
        self.assertEqual(c_endpoint.last_state.results, 2)  # grant plus REQ result
        self.assertEqual(
            c_endpoint.last_state.result,
            bytes((index % 256) ^ 0xA5 for index in range(len(payload))),
        )

    def test_result_status_repair_and_terminal_ack_are_idempotent(self) -> None:
        c_endpoint, peer, relays, clock = self.harness._open_pair(
            radio._RADIO, 0xDF
        )
        self.harness._activate(c_endpoint, peer, relays, clock)
        self.harness._grant_freshness(c_endpoint, peer, relays, clock)
        payload = bytes((index * 7 + 3) & 0xFF for index in range(256))
        exchange_id = 0x23DF
        initial_events = peer.handle(ApplicationRequest(
            service_id=2, payload=payload, ack_req=True,
            at_ms=clock.next(), exchange_id=exchange_id,
        ))
        request_wires = self.harness._peer_send(peer, initial_events, clock)
        request_frames = [
            radio.parse_frame(wire, max_frame=radio._MAX_CORE) for wire in request_wires
        ]
        self.assertEqual(len(request_frames), 8)
        request_seq = request_frames[0].sequence
        before_accepts = c_endpoint.last_state.accepts
        observed: list[radio.Any] = []
        _, result_fragment_indices = self.harness._dispatch(
            c_endpoint, peer, relays, 10, request_wires, clock,
            observed=observed,
        )
        self.assertEqual(c_endpoint.last_state.accepts, before_accepts + 1)
        self.assertEqual(result_fragment_indices, [])
        completed_request = c_endpoint.complete(clock.next())
        self.assertEqual(completed_request.status, 0, completed_request.endpoint_status)
        result_wires = [
            radio._decode_c_stream_frame(wire)
            for wire in completed_request.frames if wire != b"\x00"
        ]
        result_frames = [
            radio.parse_frame(wire, max_frame=radio._MAX_CORE)
            for wire in result_wires
        ]
        self.assertEqual(len(result_frames), 8)
        self.assertTrue(
            all(frame.message_type == 1 for frame in result_frames),
            [frame.message_type for frame in result_frames],
        )
        self.assertEqual(
            {frame.fragment.index for frame in result_frames if frame.fragment},
            set(range(8)),
        )
        self.harness._dispatch(
            c_endpoint, peer, relays, 20,
            [wire for frame, wire in zip(result_frames, result_wires)
             if frame.fragment is not None and frame.fragment.index != 0],
            clock,
        )
        result_fragment_indices = list(range(1, 8))

        # The peer has seven of eight RSP fragments. Its protected status
        # schedules one repair for the missing result slice.
        status_wires: list[bytes] = []
        status_deadline = clock.now_ms + int(
            peer.manifest.values["timing"]["assembly_ms"]
        )
        while clock.now_ms < status_deadline and not status_wires:
            generated = self.harness._peer_send(
                peer, peer.handle(radio.Advance(now_ms=clock.advance(16))), clock
            )
            status_wires = [
                wire for wire in generated
                if radio.parse_frame(wire, max_frame=radio._MAX_CORE).message_type == 8
            ]
        self.assertEqual(len(status_wires), 1)
        status = radio.parse_frame(status_wires[0], max_frame=radio._MAX_CORE)
        self.assertEqual(status.message_type, 8)
        routed_status = self.harness._route(
            relays, status_wires[0], source=10, clock=clock
        )
        status_state = c_endpoint.receive(
            radio.encode_stream_r(
                routed_status, max_core=radio._MAX_CORE,
                max_encoded=radio._MAX_ENCODED,
            ),
            clock.next(),
        )
        self.assertEqual(status_state.status, 0, status_state.endpoint_status)
        held_c_frames = [
            radio._decode_c_stream_frame(wire)
            for wire in status_state.frames if wire != b"\x00"
        ]

        exchange = peer.delivery.active_outgoing[exchange_id]
        self.assertIsNotNone(exchange.selective_state)
        duplicate_reqs = peer._build_req_frames(
            service_id=2,
            seq=request_seq,
            payload=payload,
            ack_req=True,
            freshness_token=exchange.freshness_token,
            selected_indices=(0,),
        )
        duplicate_frames = [
            radio.parse_frame(wire, max_frame=radio._MAX_CORE)
            for wire in duplicate_reqs
        ]
        self.assertEqual(len(duplicate_frames), 1)
        self.assertEqual(duplicate_frames[0].message_type, 0)
        self.assertEqual(duplicate_frames[0].sequence, request_seq)
        self.assertGreater(
            duplicate_frames[0].security.packet_number,
            max(frame.security.packet_number for frame in request_frames),
        )
        duplicate_replies: list[bytes] = []
        for wire in duplicate_reqs:
            forwarded = self.harness._route(relays, wire, source=10, clock=clock)
            received = c_endpoint.receive(
                radio.encode_stream_r(
                    forwarded, max_core=radio._MAX_CORE,
                    max_encoded=radio._MAX_ENCODED,
                ),
                clock.next(),
            )
            self.assertEqual(received.status, 0, received.endpoint_status)
            duplicate_replies.extend(
                radio._decode_c_stream_frame(frame)
                for frame in received.frames if frame != b"\x00"
            )
        held_c_frames.extend(duplicate_replies)
        self.assertTrue(held_c_frames)
        self.assertEqual(c_endpoint.last_state.accepts, before_accepts + 1)

        # Release the real status repair. The peer completes one terminal
        # result and sends its protected receipt ACK back to C.
        repair_wires = held_c_frames
        result_repairs = [
            radio.parse_frame(wire, max_frame=radio._MAX_CORE)
            for wire in repair_wires
        ]
        result_repairs = [
            frame for frame in result_repairs
            if frame.message_type == 1 and frame.fragment is not None
        ]
        self.assertEqual([frame.fragment.index for frame in result_repairs], [0])
        result_events: list[radio.Any] = []
        peer_ack_frames, _ = self.harness._dispatch(
            c_endpoint, peer, relays, 20, repair_wires, clock,
            observed=result_events,
        )
        results = [
            event for event in result_events
            if event.kind == "request_result" and event.exchange_id == exchange_id
        ]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].payload, payload)
        self.assertTrue(any(
            radio.parse_frame(wire, max_frame=radio._MAX_CORE).message_type == 6
            for wire in peer_ack_frames
        ))
        self.assertNotIn(exchange_id, peer.delivery.active_outgoing)

    def test_authenticated_invalid_feedback_values_do_not_repair_or_dispatch(self) -> None:
        payload = bytes((index * 23 + 5) & 0xFF for index in range(256))
        c_endpoint, peer, relays, clock, request, _, sequence, _ = (
            self._start_c_request(0xD3, payload)
        )
        # Establish a live Python reassembly while the C endpoint retains the
        # corresponding sender state. The omissions are deterministic losses
        # before the two real relays.
        self.harness._dispatch(
            c_endpoint, peer, relays, 20,
            [wire for index, wire in enumerate(request.frames) if index not in {1, 5}],
            clock,
        )
        initial_accepts = c_endpoint.last_state.accepts
        initial_results = c_endpoint.last_state.results
        route, context = peer._routed_fields()

        def protected_status(label: str, *, target: int | None, mask: int,
                             service: int = 2) -> bytes:
            extensions = []
            if target is not None:
                extensions.append(Extension(1, True, False, radio.encode_uleb(target)))
            if context is not None:
                extensions.append(context)
            if service != 2:
                extensions.append(Extension(4, True, False, radio.encode_uleb(service)))
            extensions.sort(key=lambda item: item.extension_id)
            frame = CoreFrame(
                message_type=8,
                options=1 | 0x80 | (4 if route is not None else 0),
                sequence=peer._alloc_seq(),
                route=route,
                extensions=tuple(extensions),
                payload=b"",
            )
            wire = peer._encrypt_and_encode(frame, plaintext=mask.to_bytes(4, "little"))
            self.assertTrue(wire, label)
            return wire

        # These are authenticated by the independent Python endpoint: empty,
        # all-fragments, and out-of-range masks; missing/mismatched reference;
        # and an ineligible service binding. They must not schedule C repairs.
        # The public peer encoder refuses to create a protected TYPE 8
        # without REPLY_TO or with extensions out of order. Record those
        # syntax gates locally; only structurally valid authenticated frames
        # can be routed into the C endpoint below.
        no_reference = CoreFrame(
            message_type=8,
            options=1 | 0x80 | (4 if route is not None else 0),
            sequence=peer._alloc_seq(), route=route,
            extensions=(context,) if context is not None else (), payload=b"",
        )
        with self.assertRaisesRegex(radio.FrameError, "requires REPLY_TO"):
            encode_frame(no_reference, max_frame=radio._MAX_CORE)
        if context is not None:
            reversed_extensions = CoreFrame(
                message_type=8,
                options=1 | 0x80 | (4 if route is not None else 0),
                sequence=peer._alloc_seq(), route=route,
                extensions=(context, Extension(1, True, False, radio.encode_uleb(sequence))),
                payload=b"",
            )
            with self.assertRaisesRegex(radio.FrameError, "unique and increasing"):
                encode_frame(reversed_extensions, max_frame=radio._MAX_CORE)

        malformed = (
            ("zero mask", protected_status("zero", target=sequence, mask=0)),
            ("all mask", protected_status("all", target=sequence, mask=0xFF)),
            ("high mask bit", protected_status("high", target=sequence, mask=0x100)),
            ("wrong reference", protected_status("wrong", target=sequence + 1, mask=0x02)),
            ("wrong service", protected_status("service", target=sequence, mask=0x02, service=1)),
        )
        for label, wire in malformed:
            with self.subTest(case=label):
                routed = self.harness._route(relays, wire, source=10, clock=clock)
                state = c_endpoint.receive(
                    radio.encode_stream_r(
                        routed, max_core=radio._MAX_CORE,
                        max_encoded=radio._MAX_ENCODED,
                    ),
                    clock.next(),
                )
                frames = [
                    radio._decode_c_stream_frame(item)
                    for item in state.frames if item != b"\x00"
                ]
                self.assertFalse(any(
                    radio.parse_frame(frame, max_frame=radio._MAX_CORE).message_type == 1
                    and radio.parse_frame(frame, max_frame=radio._MAX_CORE).fragment is not None
                    for frame in frames
                ), (label, state.endpoint_status, state.rx_status))
                self.assertEqual(state.accepts, initial_accepts)
                self.assertTrue(state.bound)

        # The real receiver still emits a valid protected status; it repairs
        # exactly indices 1 and 5 and dispatches the request once.
        accepted: list[radio.Any] = []
        repairs: list[int] = []
        deadline = clock.now_ms + 10_000
        while clock.now_ms < deadline and c_endpoint.last_state.accepts == initial_accepts:
            now = clock.advance(64)
            generated = self.harness._peer_send(
                peer, peer.handle(radio.Advance(now_ms=now)), clock
            )
            if generated:
                observed: list[radio.Any] = []
                peer_out, c_fragments = self.harness._dispatch(
                    c_endpoint, peer, relays, 10, generated, clock, observed=observed
                )
                accepted.extend(observed)
                repairs.extend(c_fragments)
        self.assertEqual(c_endpoint.last_state.accepts, initial_accepts)
        self.assertEqual(c_endpoint.last_state.results, initial_results + 1)
        self.assertEqual(
            c_endpoint.last_state.result,
            bytes((index % 256) ^ 0xA5 for index in range(len(payload))),
        )
        self.assertEqual(sorted(repairs), [1, 5])


if __name__ == "__main__":
    unittest.main()
