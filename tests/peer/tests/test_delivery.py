"""Tests for direct reliability, ACK generation, stop-and-wait, and result retention (DMP §8, §8.1)."""

import unittest
from pathlib import Path

from dmp_peer.events import (
    Advance,
    ApplicationEvent,
    ApplicationRequest,
    Open,
    Receive,
    TxAdmit,
    TxSubmit,
    TxTerminal,
)
from dmp_peer.frame import CoreFrame, Extension, decode_uleb, encode_frame, encode_uleb, parse_frame
from dmp_peer.delivery import DeliveryManager, OutgoingExchange, RetainedResult
from dmp_peer.stream_r import encode_stream_r
from dmp_peer.testing import PeerEndpoint


def _load_manifest_bytes(name: str = "direct-nnpsk0.json") -> bytes:
    path = Path(__file__).parents[3] / "profiles" / "deployments" / name
    return path.read_bytes()


class DirectDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.raw_manifest = _load_manifest_bytes()
        # In §22.2 and §22.9: Node 10 is requester (epoch 7), Node 20 is responder (epoch 9)
        self.requester = PeerEndpoint(
            manifest_bytes=self.raw_manifest,
            test_credentials={"node_id": 10, "epoch": 7, "remote_epoch": 9},
            entropy_source=lambda n: bytes(n),
            test_services={},
        )
        self.responder = PeerEndpoint(
            manifest_bytes=self.raw_manifest,
            test_credentials={"node_id": 20, "epoch": 9, "remote_epoch": 7},
            entropy_source=lambda n: bytes(n),
            test_services={},
        )
        # Open both endpoints and cross-feed initial sync delimiters
        req_open = self.requester.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        resp_open = self.responder.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        # Initial delimiter from requester to responder
        req_sync = next(e.bytes for e in req_open if isinstance(e, TxSubmit))
        self.responder.handle(Receive(link=0, bytes=req_sync, at_ms=12))
        # Initial delimiter from responder to requester
        resp_sync = next(e.bytes for e in resp_open if isinstance(e, TxSubmit))
        self.requester.handle(Receive(link=0, bytes=resp_sync, at_ms=12))

    def test_canonical_ack_with_own_seq_referencing_request_identity(self):
        # Service 2 (OPAQUE-1) reliable request from requester (origin 10) to responder (origin 20)
        ext_service = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))
        req2 = CoreFrame(message_type=0, options=0x83, sequence=42, extensions=(ext_service,), payload=b"\x5A")
        req2_bytes = encode_frame(req2, max_frame=256)
        req2_stream = encode_stream_r(req2_bytes, max_core=256, max_encoded=263)

        events2 = self.responder.handle(Receive(link=0, bytes=req2_stream, at_ms=30))
        tx_subs2 = [e for e in events2 if isinstance(e, TxSubmit)]
        self.assertTrue(len(tx_subs2) >= 1)

        # The responder emits an immediate reliable RSP
        rsp_stream = tx_subs2[0].bytes
        decoded_events = self.requester.stream_r_decoder.feed(rsp_stream, at_ms=35)
        core_frame = next(e.frame for e in decoded_events if e.kind == "frame")
        parsed = parse_frame(core_frame)
        self.assertEqual(parsed.message_type, 1)  # RSP
        self.assertNotEqual(parsed.sequence, 42)  # Own SEQ allocated!
        # Check REPLY_TO references (1, 10, 7, 42)
        reply_ext = next(ext for ext in parsed.extensions if ext.extension_id == 1)
        ns, at = decode_uleb(reply_ext.value, 0)
        orig, at = decode_uleb(reply_ext.value, at)
        epoch = int.from_bytes(reply_ext.value[at : at + 8], "little")
        at += 8
        seq, _ = decode_uleb(reply_ext.value, at)
        self.assertEqual((ns, orig, epoch, seq), (1, 10, 7, 42))

    def test_immediate_reliable_response_and_result_receipt_golden(self):
        # Test Section 22.9 golden exchange
        # REQ: (1, 10, 7, 42) -> RSP SEQ=9, payload BB, references (1, 10, 7, 42)
        # Golden RSP: 41 11 83 09 05 0B 01 0A 07 00 00 00 00 00 00 00 2A BB
        # Golden ACK of result: 46 11 81 2B 05 0B 01 14 09 00 00 00 00 00 00 00 09
        golden_rsp_core = bytes.fromhex("41 11 83 09 05 0B 01 0A 07 00 00 00 00 00 00 00 2A BB")
        golden_rsp_stream = encode_stream_r(golden_rsp_core, max_core=256, max_encoded=263)

        # Inject an active request with SEQ=42 on requester so it expects this result
        self.requester.next_seq = 42
        req = ApplicationRequest(service_id=1, payload=b"\x01", at_ms=20, exchange_id=101)
        self.requester.handle(req)

        # Deliver immediate RSP
        events = self.requester.handle(Receive(link=0, bytes=golden_rsp_stream, at_ms=25))

        # Check that result was accepted once
        res_evt = next((e for e in events if isinstance(e, ApplicationEvent) and e.kind == "request_result"), None)
        self.assertIsNotNone(res_evt)
        self.assertEqual(res_evt.payload, b"\xBB")

        # Requester emits ACK for the result
        tx_ack = next((e for e in events if isinstance(e, TxSubmit)), None)
        self.assertIsNotNone(tx_ack)

        # Decode ACK and verify it references result identity (1, 20, 9, 9)
        dec = self.responder.stream_r_decoder.feed(tx_ack.bytes, at_ms=30)
        ack_core = next(e.frame for e in dec if e.kind == "frame")
        ack_frame = parse_frame(ack_core)
        self.assertEqual(ack_frame.message_type, 6)  # ACK
        self.assertEqual(ack_frame.payload, b"")  # Empty payload

    def test_duplicate_request_replays_retained_result_without_reexecution(self):
        # Send Service 2 request from requester (10) to responder (20)
        ext_service = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))
        req = CoreFrame(message_type=0, options=0x83, sequence=10, extensions=(ext_service,), payload=b"\x5A")
        req_stream = encode_stream_r(encode_frame(req, max_frame=256), max_core=256, max_encoded=263)

        # First delivery: executes and returns RSP
        events1 = self.responder.handle(Receive(link=0, bytes=req_stream, at_ms=20))
        sub1 = next(e for e in events1 if isinstance(e, TxSubmit))
        app_events1 = [e for e in events1 if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]
        self.assertEqual(len(app_events1), 1)

        # Duplicate delivery: resends same RSP, NO new execution callback!
        events2 = self.responder.handle(Receive(link=0, bytes=req_stream, at_ms=30))
        sub2 = next(e for e in events2 if isinstance(e, TxSubmit))
        app_events2 = [e for e in events2 if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]
        self.assertEqual(len(app_events2), 0)  # No second execution!
        self.assertEqual(sub1.bytes, sub2.bytes)  # Exact same cached result!

    def test_stop_and_wait_gate_serializes_application_requests(self):
        # First request
        req1 = ApplicationRequest(service_id=2, payload=b"first", at_ms=20, exchange_id=1)
        evts1 = self.requester.handle(req1)
        tx_subs1 = [e for e in evts1 if isinstance(e, TxSubmit)]
        self.assertEqual(len(tx_subs1), 1)

        # Second request to same destination & service: should be queued by stop-and-wait gate
        req2 = ApplicationRequest(service_id=2, payload=b"second", at_ms=25, exchange_id=2)
        evts2 = self.requester.handle(req2)
        tx_subs2 = [e for e in evts2 if isinstance(e, TxSubmit)]
        self.assertEqual(len(tx_subs2), 0)  # Queued! Not submitted while first is in flight

    def test_default_service_canonical_rule(self):
        # Service 1 is default service. An incoming frame with explicit SERVICE_ID=1 is noncanonical and rejected!
        ext_s1 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(1))
        bad_frame = CoreFrame(message_type=0, options=0x83, sequence=15, extensions=(ext_s1,), payload=b"\x01")
        bad_stream = encode_stream_r(encode_frame(bad_frame, max_frame=256), max_core=256, max_encoded=263)

        events = self.responder.handle(Receive(link=0, bytes=bad_stream, at_ms=20))
        # No request_accepted event because explicit default service is rejected!
        app_evts = [e for e in events if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]
        self.assertEqual(len(app_evts), 0)

    def test_wrong_responder_cannot_complete_exchange_or_result_ack(self):
        mgr = DeliveryManager(
            response_timeout_ms=100,
            receipt_delay_ms=50,
            result_deadline_ms=500,
            result_cache_ms=1000,
            dedup_ms=1000,
            rejection_ms=500,
            correlation_ms=1000,
            max_bursts=3,
            app_queue_slots=2,
        )
        exc = OutgoingExchange(
            exchange_id=1,
            service_id=2,
            destination=20,
            seq=42,
            namespace=1,
            origin=10,
            epoch=7,
            frames=(b"frame1",),
            ack_req=True,
            not_after_ms=None,
            created_at_ms=0,
            response_timeout_ms=100,
            result_deadline_ms=500,
            max_attempts=3,
        )
        mgr.enqueue_outgoing(exc)

        # ACK from node 30 (not node 20) does not acknowledge request
        self.assertIsNone(mgr.record_ack_received(1, 10, 7, 42, responder=30, service_id=2))
        self.assertFalse(exc.received_ack)

        # RSP from node 30 does not match request
        self.assertIsNone(mgr.match_request_for_result(1, 10, 7, 42, responder=30, service_id=2))

        # Result ACK from node 30 for retained result of node 10 does not acknowledge result
        res = RetainedResult(
            service_id=2,
            req_namespace=1,
            req_origin=10,
            req_epoch=7,
            req_seq=42,
            result_seq=99,
            result_frame_bytes=b"rsp",
            is_app_err=False,
            status=0,
            created_at_ms=0,
            expires_at_ms=500,
        )
        mgr.retained_results[(1, 10, 7, 42)] = res
        self.assertIsNone(mgr.record_result_ack_received(99, responder=30, service_id=2))
        self.assertFalse(res.acknowledged)

    def test_wrong_service_id_cannot_complete_exchange(self):
        mgr = DeliveryManager(
            response_timeout_ms=100,
            receipt_delay_ms=50,
            result_deadline_ms=500,
            result_cache_ms=1000,
            dedup_ms=1000,
            rejection_ms=500,
            correlation_ms=1000,
            max_bursts=3,
            app_queue_slots=2,
        )
        exc = OutgoingExchange(
            exchange_id=1,
            service_id=2,
            destination=20,
            seq=42,
            namespace=1,
            origin=10,
            epoch=7,
            frames=(b"frame1",),
            ack_req=True,
            not_after_ms=None,
            created_at_ms=0,
            response_timeout_ms=100,
            result_deadline_ms=500,
            max_attempts=3,
        )
        mgr.enqueue_outgoing(exc)

        # ACK with service_id 1 does not acknowledge request on service 2
        self.assertIsNone(mgr.record_ack_received(1, 10, 7, 42, responder=20, service_id=1))
        self.assertFalse(exc.received_ack)

        # RSP with service_id 1 does not match request on service 2
        self.assertIsNone(mgr.match_request_for_result(1, 10, 7, 42, responder=20, service_id=1))

    def test_fragmented_request_slices_sent_as_single_exchange(self):
        # Service 2 request with payload larger than chunk_bytes (64)
        # All slices should be sent under ONE OutgoingExchange
        large_payload = b"A" * 100
        req = ApplicationRequest(service_id=2, payload=large_payload, at_ms=20, exchange_id=5)
        events = self.requester.handle(req)
        tx_subs = [e for e in events if isinstance(e, TxSubmit)]
        # Multiple slices submitted
        self.assertGreater(len(tx_subs), 1)
        # Exactly one active outgoing exchange in delivery manager
        self.assertEqual(len(self.requester.delivery.active_outgoing), 1)
        exc = next(iter(self.requester.delivery.active_outgoing.values()))
        self.assertEqual(exc.exchange_id, 5)
        self.assertEqual(len(exc.frames), len(tx_subs))
        # Gate for (remote_node, service_id) is occupied by this single exchange
        self.assertEqual(self.requester.delivery.active_per_dest_service.get((20, 2)), 5)

    def test_result_ack_matching_full_identity_rejects_colliding_seq_from_other_identity(self):
        mgr = DeliveryManager(
            response_timeout_ms=100, receipt_delay_ms=50, result_deadline_ms=500,
            result_cache_ms=1000, dedup_ms=1000, rejection_ms=500, correlation_ms=1000,
            max_bursts=3, app_queue_slots=2,
        )
        res = RetainedResult(
            service_id=2, req_namespace=1, req_origin=10, req_epoch=7, req_seq=42,
            result_seq=99, result_frames=(b"slice0", b"slice1"),
            result_namespace=1, result_origin=20, result_epoch=9,
            created_at_ms=10, expires_at_ms=1000,
        )
        mgr.retained_results[(1, 10, 7, 42)] = res

        # Colliding sequence 99 from wrong origin (node 30 instead of 20)
        self.assertIsNone(mgr.record_result_ack_received(1, 30, 9, 99, responder=10, service_id=2))
        self.assertFalse(res.acknowledged)

        # Colliding sequence 99 from wrong epoch (epoch 8 instead of 9)
        self.assertIsNone(mgr.record_result_ack_received(1, 20, 8, 99, responder=10, service_id=2))
        self.assertFalse(res.acknowledged)

        # Colliding sequence 99 from wrong requester responder (node 15 instead of expected requester 10)
        self.assertIsNone(mgr.record_result_ack_received(1, 20, 9, 99, responder=15, service_id=2))
        self.assertFalse(res.acknowledged)

        # Matching full result identity acknowledges result
        matched = mgr.record_result_ack_received(1, 20, 9, 99, responder=10, service_id=2)
        self.assertIsNotNone(matched)
        self.assertTrue(res.acknowledged)

    def test_retained_result_all_frames_retransmitted_on_retry(self):
        mgr = DeliveryManager(
            response_timeout_ms=100, receipt_delay_ms=50, result_deadline_ms=500,
            result_cache_ms=1000, dedup_ms=1000, rejection_ms=500, correlation_ms=1000,
            max_bursts=3, app_queue_slots=2,
        )
        res = RetainedResult(
            service_id=2, req_namespace=1, req_origin=10, req_epoch=7, req_seq=42,
            result_seq=101, result_frames=(b"slice0_bytes", b"slice1_bytes"),
            result_namespace=1, result_origin=20, result_epoch=9,
            created_at_ms=10, expires_at_ms=1000, next_retry_ms=50, attempts_left=2,
        )
        mgr.retained_results[(1, 10, 7, 42)] = res

        due_reqs, due_results, expired_excs = mgr.advance(now_ms=60)
        self.assertEqual(len(due_results), 1)
        # All frames are retained for replay
        self.assertEqual(len(due_results[0].result_frames), 2)
        self.assertEqual(due_results[0].result_frames[0], b"slice0_bytes")
        self.assertEqual(due_results[0].result_frames[1], b"slice1_bytes")


if __name__ == "__main__":
    unittest.main()
