"""P23 S7 freshness-token coverage for protected DATA transfers."""

from __future__ import annotations

import unittest
from typing import Any

from dmp_peer.events import ApplicationEvent, Receive
from dmp_peer.frame import parse_frame
from dmp_peer.security import SecurityError
from dmp_peer.stream_r import StreamRDecoder

import test_p21d_selective as helpers


class TestP23FreshData(unittest.TestCase):
    def _pair_and_grant(self):
        fixture = helpers.P21DSelectiveIntegrationTests(methodName="runTest")
        sender, receiver = fixture.pair()
        fixture.grant_service2_freshness(sender, receiver)
        token = sender.active_freshness_token
        self.assertIsNotNone(token)
        return fixture, sender, receiver, token

    def _receive_data(
        self,
        receiver,
        wires: list[bytes],
        *,
        start_ms: int,
    ) -> tuple[list[Any], list[bytes]]:
        events: list[Any] = []
        replies: list[bytes] = []
        for offset, wire in enumerate(wires):
            at_ms = start_ms + offset
            received = receiver.handle(Receive(link=0, bytes=wire, at_ms=at_ms))
            events.extend(received)
            replies.extend(
                helpers.extract_and_settle(receiver, received, at_ms=at_ms + 1)
            )
        return events, replies

    def _forged_data(
        self, sender, payload: bytes, token: bytes | None
    ) -> tuple[int, list[bytes]]:
        seq = sender._alloc_seq()
        frames = sender._build_data_frames(
            2, seq, payload, ack_req=True, freshness_token=token
        )
        return seq, frames

    def _assert_not_dispatched(self, receiver, events: list[Any]) -> None:
        self.assertFalse(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in events
        ))
        self.assertEqual(receiver.reassembly.active, {})
        self.assertFalse(any(
            record.message_type == 7
            for record in receiver.delivery.accepted_messages.values()
        ))

    def test_freshness_token_is_bound_to_one_fragmented_data_message(self) -> None:
        _, sender, receiver, token = self._pair_and_grant()
        payload = bytes((index * 13 + 5) & 0xFF for index in range(65))
        outgoing: list[Any] = []
        seq = sender._queue_data_transfer(2, payload, ack_req=True, out=outgoing)
        self.assertIsNone(sender.active_freshness_token)
        wires = helpers.extract_and_settle(sender, outgoing, at_ms=230)
        self.assertEqual(len(wires), 3)
        parsed = [parse_frame(wire) for wire in wires]
        self.assertTrue(all(frame.sequence == seq for frame in parsed))
        self.assertTrue(all(frame.fragment is not None for frame in parsed))
        self.assertEqual(
            [next(ext.value for ext in frame.extensions if ext.extension_id == 6)
             for frame in parsed],
            [token, token, token],
        )

        events, _ = self._receive_data(receiver, wires, start_ms=300)
        accepted = [
            event for event in events
            if isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
        ]
        self.assertEqual(len(accepted), 1)
        self.assertEqual((accepted[0].service_id, accepted[0].payload), (2, payload))

        grant = receiver.freshness_manager.grants[token]
        self.assertEqual(grant.bound_identity, (1, sender.local_node_id, sender.local_epoch, seq))
        self.assertEqual(grant.bound_service_id, 2)
        self.assertTrue(grant.consumed)

    def test_sender_requires_a_well_formed_grant_for_fresh_data(self) -> None:
        _, sender, _, _ = self._pair_and_grant()
        outgoing: list[Any] = []
        sender.active_freshness_token = None
        with self.assertRaisesRegex(SecurityError, "freshness token required"):
            sender._queue_data_transfer(2, b"opaque", ack_req=True, out=outgoing)
        self.assertEqual(outgoing, [])

        sender.active_freshness_token = b"short"
        with self.assertRaisesRegex(SecurityError, "exactly 16 bytes"):
            sender._queue_data_transfer(2, b"opaque", ack_req=True, out=outgoing)
        self.assertEqual(outgoing, [])

    def test_missing_wrong_and_expired_data_tokens_are_rejected(self) -> None:
        cases = (
            ("missing", None, 300),
            ("wrong", b"\xff" * 16, 300),
            ("expired", "grant", None),
        )
        for label, token_choice, receive_at in cases:
            with self.subTest(token=label):
                _, sender, receiver, token = self._pair_and_grant()
                supplied = token if token_choice == "grant" else token_choice
                if receive_at is None:
                    grant = receiver.freshness_manager.grants[token]
                    receive_at = grant.issued_at_ms + grant.granted_lifetime_ms
                _, frames = self._forged_data(
                    sender, b"rejected-fresh-data", supplied
                )
                events, replies = self._receive_data(
                    receiver, frames, start_ms=receive_at
                )
                self._assert_not_dispatched(receiver, events)
                self.assertTrue(replies, "rejected DATA must produce a terminal protocol response")
                self.assertFalse(any(
                    isinstance(event, ApplicationEvent)
                    and event.kind == "request_accepted"
                    for event in events
                ))

    def test_data_without_manifest_freshness_keeps_tokenless_behavior(self) -> None:
        fixture = helpers.P21DSelectiveIntegrationTests(methodName="runTest")
        sender, receiver = fixture.pair("test-peer-tcp-stream-r-sample20-nnpsk0.json")
        # The SAMPLE20 profile has no freshness requirement for service 2.
        payload = b"plain opaque data"
        outgoing: list[Any] = []
        sender._queue_data_transfer(2, payload, ack_req=True, out=outgoing)
        wires = helpers.extract_and_settle(sender, outgoing, at_ms=200)
        decoder = StreamRDecoder(
            max_encoded=sender.encoded_mtu,
            max_core=sender.forward_mtu,
            candidate_timeout_ms=26,
        )
        frames = [
            event.frame
            for index, wire in enumerate(wires)
            for event in decoder.feed(wire, at_ms=201 + index)
            if event.kind == "frame" and event.frame is not None
        ]
        self.assertTrue(all(
            all(ext.extension_id != 6 for ext in frame.extensions)
            for frame in frames
        ))
        events, _ = self._receive_data(receiver, wires, start_ms=200)
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == 2
            and event.payload == payload
            for event in events
        ))


if __name__ == "__main__":
    unittest.main()
