"""P23 C-primary confirmation loss/retry interoperability for SEC-1 S10.02."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))

import test_p23_c_endpoint_interop as interop  # noqa: E402
from dmp_peer.events import Advance  # noqa: E402
from dmp_peer.frame import parse_frame  # noqa: E402


def _wire_frame(wire: bytes, clock: interop._Clock):
    decoder = interop.StreamRDecoder(
        max_encoded=263, max_core=256, candidate_timeout_ms=26, await_sync=False
    )
    frames = [
        event.frame
        for event in decoder.feed(wire, at_ms=clock.next())
        if event.kind == "frame"
    ]
    if len(frames) != 1 or frames[0] is None:
        raise AssertionError("expected exactly one complete SEC-1 Stream R frame")
    return parse_frame(frames[0], max_frame=256)


def _protected_confirmation_wires(
    wires: list[bytes], clock: interop._Clock
) -> list[tuple[bytes, object]]:
    confirmations = []
    for wire in wires:
        frame = _wire_frame(wire, clock)
        if frame.message_type == 3 and frame.security is not None:
            confirmations.append((wire, frame))
    if not confirmations:
        raise AssertionError("peer retry did not include a protected SEC-1 confirmation")
    return confirmations


@unittest.skipUnless(
    os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
    "C P23 endpoint executable is not configured",
)
class TestP23S10ConfirmationInterop(unittest.TestCase):
    def test_xx_finish_and_ready_loss_recover_with_bounded_fresh_pn_retries(self) -> None:
        def open_candidate():
            harness = interop.TestP23CPrimaryInterop()
            harness.setUp()
            c_endpoint, peer, clock, peer_flight = (
                harness.open_xx_through_noise_confirmation()
            )
            self.addCleanup(c_endpoint.close)
            return c_endpoint, peer, clock, peer_flight

        # The first peer output is the final Noise flight. Receiving it must
        # leave the C responder's association pending until protected FINISH.
        c_endpoint, peer, clock, initial_peer_flight = open_candidate()
        flight3 = _wire_frame(initial_peer_flight[0], clock)
        initial_finish = _wire_frame(initial_peer_flight[1], clock)
        self.assertIsNone(flight3.security)
        self.assertIsNotNone(initial_finish.security)
        self.assertEqual(initial_finish.message_type, 3)
        before_finish = c_endpoint.receive(initial_peer_flight[0], clock.next())
        self.assertEqual(before_finish.status, 0)
        self.assertFalse(before_finish.handshake_active)
        self.assertFalse(before_finish.bound)
        self.assertFalse(before_finish.frames)

        # Drop the first protected FINISH. The initiator must remain pending,
        # then retry within its configured finite confirmation-attempt budget.
        self.assertIsNone(peer.association)
        self.assertEqual(peer.confirmation_attempts_used, 1)
        retry_deadline = peer.next_confirmation_retry_ms
        self.assertIsNotNone(retry_deadline)
        clock.advance(max(0, retry_deadline - clock.now_ms))
        retried_wires, _ = interop._settle(
            peer,
            peer.handle(Advance(now_ms=retry_deadline)),
            clock,
        )
        self.assertEqual(peer.confirmation_attempts_used, 2)
        retry_finish_candidates = _protected_confirmation_wires(retried_wires, clock)
        retry_finish_wire, retry_finish = retry_finish_candidates[-1]
        assert initial_finish.security is not None
        assert retry_finish.security is not None
        self.assertEqual(retry_finish.sequence, initial_finish.sequence)
        self.assertGreater(
            retry_finish.security.packet_number,
            initial_finish.security.packet_number,
            "FINISH retransmission must use a fresh packet number",
        )
        self.assertIsNone(peer.association)

        # Deliver the retried FINISH to the real C responder. It activates
        # only now and its valid READY activates the Python initiator.
        c_after_finish = c_endpoint.receive(retry_finish_wire, clock.next())
        self.assertEqual(c_after_finish.status, 0)
        self.assertTrue(c_after_finish.handshake_active)
        self.assertTrue(c_after_finish.bound)
        first_ready_wires = [
            wire
            for wire in c_after_finish.frames
            if (frame := _wire_frame(wire, clock)).message_type == 3
            and frame.security is not None
        ]
        self.assertEqual(len(first_ready_wires), 1)
        first_ready = _wire_frame(first_ready_wires[0], clock)
        self.assertIsNone(peer.association)
        peer.handle(
            interop.Receive(link=0, bytes=first_ready_wires[0], at_ms=clock.next())
        )
        self.assertIsNotNone(peer.association)
        self.assertEqual(peer.association.status, "active")
        self.assertEqual(peer.confirmation_attempts_used, 2)
        self.assertLessEqual(peer.confirmation_attempts_used, peer.confirmation_attempts)

        # Exercise READY loss in a separate attempt because the production
        # profile allows two total confirmation transmissions: initial plus
        # one retry. Lose the initial READY, then require duplicate FINISH to
        # elicit a fresh-PN READY with the same logical identity.
        c_endpoint, peer, clock, peer_flight = open_candidate()
        self.assertEqual(c_endpoint.receive(peer_flight[0], clock.next()).status, 0)
        self.assertFalse(c_endpoint.last_state.handshake_active)
        self.assertFalse(c_endpoint.last_state.bound)
        first_finish = _wire_frame(peer_flight[1], clock)
        self.assertIsNotNone(first_finish.security)
        c_result = c_endpoint.receive(peer_flight[1], clock.next())
        self.assertEqual(c_result.status, 0)
        self.assertTrue(c_result.handshake_active)
        self.assertTrue(c_result.bound)
        ready_wires = [
            wire
            for wire in c_result.frames
            if (frame := _wire_frame(wire, clock)).message_type == 3
            and frame.security is not None
        ]
        self.assertEqual(len(ready_wires), 1)
        first_ready = _wire_frame(ready_wires[0], clock)
        self.assertIsNone(peer.association)  # the first READY is deliberately lost

        retry_deadline = peer.next_confirmation_retry_ms
        self.assertIsNotNone(retry_deadline)
        clock.advance(max(0, retry_deadline - clock.now_ms))
        duplicate_wires, _ = interop._settle(
            peer,
            peer.handle(Advance(now_ms=retry_deadline)),
            clock,
        )
        self.assertEqual(peer.confirmation_attempts_used, 2)
        duplicate_finish_wire, duplicate_finish = _protected_confirmation_wires(
            duplicate_wires, clock
        )[-1]
        self.assertGreater(
            duplicate_finish.security.packet_number,
            first_finish.security.packet_number,
        )
        duplicate_result = c_endpoint.receive(duplicate_finish_wire, clock.next())
        self.assertEqual(duplicate_result.status, 0)
        self.assertTrue(duplicate_result.handshake_active)
        self.assertTrue(duplicate_result.bound)
        retry_ready_wires = [
            wire
            for wire in duplicate_result.frames
            if (frame := _wire_frame(wire, clock)).message_type == 3
            and frame.security is not None
        ]
        self.assertEqual(len(retry_ready_wires), 1)
        retry_ready = _wire_frame(retry_ready_wires[0], clock)
        self.assertEqual(retry_ready.sequence, first_ready.sequence)
        assert retry_ready.security is not None and first_ready.security is not None
        self.assertGreater(
            retry_ready.security.packet_number,
            first_ready.security.packet_number,
            "READY retransmission must retain logical identity and use a fresh PN",
        )
        self.assertIsNone(peer.association)

        # The valid protected READY is the initiator's activation gate.
        peer.handle(
            interop.Receive(link=0, bytes=retry_ready_wires[0], at_ms=clock.next())
        )
        self.assertIsNotNone(peer.association)
        self.assertEqual(peer.association.status, "active")
        self.assertTrue(c_endpoint.last_state.handshake_active)
        self.assertTrue(c_endpoint.last_state.bound)
        self.assertEqual(peer.confirmation_attempts_used, 2)
        self.assertLessEqual(peer.confirmation_attempts_used, peer.confirmation_attempts)

        # The first READY was delayed rather than destroyed and arrives after
        # the higher-PN retry. It must not regress the activated association.
        delayed_ready_events = peer.handle(
            interop.Receive(link=0, bytes=ready_wires[0], at_ms=clock.next())
        )
        self.assertFalse(
            any(isinstance(event, interop.TxSubmit) for event in delayed_ready_events)
        )
        self.assertEqual(peer.association.status, "active")
