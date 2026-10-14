"""P23 peer-local SEC-1 §S10(10) freshness-grant lifecycle coverage."""

from __future__ import annotations

import unittest
from pathlib import Path
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).parents[1]))

from dmp_peer.events import Advance, ApplicationEvent, ApplicationRequest, Receive
from dmp_peer.frame import parse_frame

import test_p21d_selective as helpers


class TestP23FreshnessLifecycle(unittest.TestCase):
    def _pair(self):
        fixture = helpers.P21DSelectiveIntegrationTests(methodName="runTest")
        initiator, responder = fixture.pair()
        return fixture, initiator, responder

    def _send_grant_request(
        self,
        fixture,
        initiator,
        responder,
        *,
        lifetime_ms: int,
        at_ms: int = 150,
        deliver_result: bool,
    ) -> dict[str, Any]:
        payload = b"\x10" + lifetime_ms.to_bytes(4, "little")
        outgoing = initiator.handle(ApplicationRequest(
            service_id=0, payload=payload, ack_req=True, at_ms=at_ms
        ))
        request_frames = helpers.extract_and_settle(
            initiator, outgoing, at_ms=at_ms + 1
        )
        self.assertEqual(len(request_frames), 1)
        request_frame = parse_frame(request_frames[0])
        request_key = (
            1,
            initiator.local_node_id,
            initiator.local_epoch,
            request_frame.sequence,
        )
        received = responder.handle(Receive(
            link=0, bytes=request_frames[0], at_ms=at_ms + 10
        ))
        responses = helpers.extract_and_settle(
            responder, received, at_ms=at_ms + 11
        )
        response_frames = [parse_frame(wire) for wire in responses]
        receipt_wires = [
            wire for wire, frame in zip(responses, response_frames)
            if frame.message_type == 6
        ]
        result_wires = [
            wire for wire, frame in zip(responses, response_frames)
            if frame.message_type == 1
        ]
        self.assertEqual(len(result_wires), 1)
        result = responder.delivery.retained_results[request_key]
        record = responder.delivery.accepted_messages[request_key]
        token = result.result_payload[1:17]
        grant = responder.freshness_manager.grants[token]
        self.assertEqual(result.result_payload[0], 0x11)
        self.assertEqual(
            int.from_bytes(result.result_payload[17:21], "little"), lifetime_ms
        )

        for offset, wire in enumerate(receipt_wires):
            receipt_events = initiator.handle(Receive(
                link=0, bytes=wire, at_ms=at_ms + 20 + offset
            ))
            helpers.extract_and_settle(
                initiator, receipt_events, at_ms=at_ms + 21 + offset
            )

        result_events: list[Any] = []
        result_ack_wires: list[bytes] = []
        if deliver_result:
            result_events.extend(initiator.handle(Receive(
                link=0, bytes=result_wires[0], at_ms=at_ms + 22
            )))
            result_ack_wires.extend(helpers.extract_and_settle(
                initiator, result_events, at_ms=at_ms + 23
            ))
            for offset, wire in enumerate(result_ack_wires):
                ack_events = responder.handle(Receive(
                    link=0, bytes=wire, at_ms=at_ms + 24 + offset
                ))
                helpers.extract_and_settle(
                    responder, ack_events, at_ms=at_ms + 25 + offset
                )

        return {
            "payload": payload,
            "request_key": request_key,
            "request_seq": request_frame.sequence,
            "request_wire": request_frames[0],
            "result_wire": result_wires[0],
            "result_events": result_events,
            "result": result,
            "record": record,
            "grant": grant,
            "token": token,
            "issued_at_ms": grant.issued_at_ms,
            "granted_ms": grant.granted_lifetime_ms,
            "responses": responses,
        }

    def _duplicate_grant_request(self, initiator, responder, grant, at_ms: int):
        duplicate = initiator._build_req_frames(
            0,
            grant["request_seq"],
            grant["payload"],
            ack_req=True,
        )[0]
        parsed = parse_frame(duplicate)
        original = parse_frame(grant["request_wire"])
        self.assertEqual(parsed.sequence, original.sequence)
        self.assertGreater(parsed.security.packet_number, original.security.packet_number)
        events = responder.handle(Receive(link=0, bytes=duplicate, at_ms=at_ms))
        wires = helpers.extract_and_settle(responder, events, at_ms=at_ms + 1)
        return duplicate, events, wires

    def test_grant_duplicate_after_result_release_returns_only_receipt_ack(self) -> None:
        fixture, initiator, responder = self._pair()
        grant = self._send_grant_request(
            fixture,
            initiator,
            responder,
            lifetime_ms=1000,
            deliver_result=True,
        )
        result = grant["result"]
        self.assertTrue(result.acknowledged)
        self.assertIn(grant["request_key"], responder.delivery.accepted_messages)
        initial_token_count = len(responder.freshness_manager.grants)
        initial_grant = responder.freshness_manager.grants[grant["token"]]

        _, _, duplicate_responses = self._duplicate_grant_request(
            initiator, responder, grant, at_ms=300
        )
        response_types = [
            parse_frame(wire).message_type for wire in duplicate_responses
        ]
        self.assertEqual(response_types, [6])
        self.assertEqual(len(responder.freshness_manager.grants), initial_token_count)
        self.assertIs(
            responder.freshness_manager.grants[grant["token"]], initial_grant
        )
        self.assertTrue(result.acknowledged)
        self.assertEqual(result.result_payload[1:17], grant["token"])

    def test_expired_grant_result_replay_keeps_original_token_and_budget(self) -> None:
        fixture, initiator, responder = self._pair()
        grant = self._send_grant_request(
            fixture,
            initiator,
            responder,
            lifetime_ms=50,
            deliver_result=False,
        )
        result = grant["result"]
        token_record = grant["grant"]
        result_seq = result.result_seq
        result_created = result.created_at_ms
        result_expires = result.expires_at_ms
        original_attempts = result.attempts_left
        original_request_count = responder.freshness_manager.requests_by_pair[
            (responder.association.h, initiator.local_node_id)
        ]
        initial_pn = parse_frame(grant["result_wire"]).security.packet_number

        expired_at = grant["issued_at_ms"] + grant["granted_ms"]
        self.assertGreaterEqual(expired_at, token_record.issued_at_ms + 50)
        _, _, duplicate_responses = self._duplicate_grant_request(
            initiator, responder, grant, at_ms=expired_at
        )
        self.assertEqual(len(duplicate_responses), 1)
        duplicate_result = parse_frame(duplicate_responses[0])
        self.assertEqual(duplicate_result.message_type, 1)
        self.assertEqual(duplicate_result.sequence, result_seq)
        self.assertGreater(duplicate_result.security.packet_number, initial_pn)
        self.assertEqual(result.result_payload[1:17], grant["token"])
        self.assertEqual(result.result_payload[17:21], (50).to_bytes(4, "little"))
        self.assertEqual(result.attempts_left, original_attempts - 1)
        self.assertEqual((result.created_at_ms, result.expires_at_ms),
                         (result_created, result_expires))
        self.assertEqual(token_record.issued_at_ms, grant["issued_at_ms"])
        self.assertEqual(
            responder.freshness_manager.requests_by_pair[
                (responder.association.h, initiator.local_node_id)
            ],
            original_request_count,
        )

        first_retry_at = result.next_retry_ms
        retry_events = responder.handle(Advance(now_ms=first_retry_at))
        retry_wires = helpers.extract_and_settle(
            responder, retry_events, at_ms=first_retry_at + 1
        )
        retry_wires = [wire for wire in retry_wires if parse_frame(wire).message_type == 1]
        self.assertEqual(len(retry_wires), 1)
        retry = parse_frame(retry_wires[0])
        self.assertEqual((retry.message_type, retry.sequence), (1, result_seq))
        self.assertEqual(result.attempts_left, 0)
        self.assertEqual((result.created_at_ms, result.expires_at_ms),
                         (result_created, result_expires))

        exhausted_events = responder.handle(
            Advance(now_ms=result.next_retry_ms)
        )
        self.assertEqual(
            helpers.extract_and_settle(
                responder, exhausted_events, at_ms=result.next_retry_ms + 1
            ),
            [],
        )
        self.assertEqual(result.expires_at_ms, result_expires)

    def test_final_fragment_expiry_rejects_without_partial_dispatch(self) -> None:
        fixture, initiator, responder = self._pair()
        grant = self._send_grant_request(
            fixture,
            initiator,
            responder,
            lifetime_ms=1000,
            deliver_result=True,
        )
        token = grant["token"]
        sequence = initiator._alloc_seq()
        payload = bytes((index * 11 + 3) & 0xFF for index in range(65))
        frames = initiator._build_req_frames(
            2, sequence, payload, ack_req=True, freshness_token=token
        )
        self.assertEqual(len(frames), 3)
        self.assertTrue(all(
            next(ext.value for ext in parse_frame(wire).extensions
                 if ext.extension_id == 6) == token
            for wire in frames
        ))
        request_key = (1, initiator.local_node_id, initiator.local_epoch, sequence)
        expiry = grant["issued_at_ms"] + grant["granted_ms"]
        receive_times = (expiry - 100, expiry - 50, expiry)
        events: list[Any] = []
        for index, (wire, at_ms) in enumerate(zip(frames, receive_times)):
            received = responder.handle(Receive(link=0, bytes=wire, at_ms=at_ms))
            events.extend(received)
            helpers.extract_and_settle(responder, received, at_ms=at_ms + 1)
            if index < 2:
                self.assertIn(request_key, responder.reassembly.active)
                self.assertEqual(
                    responder.reassembly.active[request_key].received_indices,
                    set(range(index + 1)),
                )

        self.assertFalse(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == 2
            for event in events
        ))
        self.assertNotIn(request_key, responder.delivery.accepted_messages)
        self.assertNotIn(request_key, responder.reassembly.completed)
        self.assertIn(request_key, responder.delivery.rejections)
        freshness = responder.freshness_manager.grants[token]
        self.assertTrue(freshness.consumed)
        self.assertEqual(freshness.bound_identity, request_key)
        self.assertEqual(freshness.bound_service_id, 2)

    def test_token_binding_rejects_other_principal_identity_and_service(self) -> None:
        fixture, initiator, responder = self._pair()
        grant = self._send_grant_request(
            fixture,
            initiator,
            responder,
            lifetime_ms=1000,
            deliver_result=True,
        )
        manager = responder.freshness_manager
        association_h = responder.association.h
        token = grant["token"]
        identity = (
            1, initiator.local_node_id, initiator.local_epoch, 0x3456
        )
        digest = b"D" * 32
        self.assertTrue(manager.validate_command_token(
            token,
            association_h,
            initiator.local_node_id,
            identity,
            grant["issued_at_ms"] + 1,
            service_id=2,
            message_digest=digest,
        ))
        self.assertFalse(manager.validate_command_token(
            token,
            association_h,
            initiator.local_node_id + 1,
            identity,
            grant["issued_at_ms"] + 2,
            service_id=2,
            message_digest=digest,
        ))
        self.assertFalse(manager.validate_command_token(
            token,
            association_h,
            initiator.local_node_id,
            (1, initiator.local_node_id, initiator.local_epoch, 0x3457),
            grant["issued_at_ms"] + 2,
            service_id=2,
            message_digest=digest,
        ))
        self.assertFalse(manager.validate_command_token(
            token,
            association_h,
            initiator.local_node_id,
            identity,
            grant["issued_at_ms"] + 2,
            service_id=1,
            message_digest=digest,
        ))

    def test_grant_from_another_association_is_not_accepted(self) -> None:
        fixture_a, initiator_a, responder_a = self._pair()
        grant = self._send_grant_request(
            fixture_a,
            initiator_a,
            responder_a,
            lifetime_ms=1000,
            deliver_result=True,
        )
        fixture_b, initiator_b, responder_b = self._pair()
        sequence = initiator_b._alloc_seq()
        frame = initiator_b._build_req_frames(
            2,
            sequence,
            b"cross-association command",
            ack_req=True,
            freshness_token=grant["token"],
        )[0]
        key = (
            1,
            initiator_b.local_node_id,
            initiator_b.local_epoch,
            sequence,
        )
        events = responder_b.handle(Receive(link=0, bytes=frame, at_ms=300))
        helpers.extract_and_settle(responder_b, events, at_ms=301)
        self.assertFalse(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == 2
            for event in events
        ))
        self.assertNotIn(key, responder_b.delivery.accepted_messages)
        self.assertNotIn(grant["token"], responder_b.freshness_manager.grants)


if __name__ == "__main__":
    unittest.main()
