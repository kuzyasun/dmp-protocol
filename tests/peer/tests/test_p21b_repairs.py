"""Regression coverage for the P21B independent review repairs."""

import unittest
from pathlib import Path

from dmp_peer.delivery import DeliveryManager, OutgoingExchange, RetainedResult
from dmp_peer.events import (
    Advance,
    ApplicationEvent,
    ApplicationRequest,
    Cancel,
    Disconnect,
    Open,
    PublishSample,
    Receive,
    Restart,
    TxAdmit,
    TxSubmit,
    TxTerminal,
)
from dmp_peer.frame import CoreFrame, Extension, Fragment, decode_uleb, encode_frame, encode_uleb, parse_frame
from dmp_peer.reassembly import ReassemblyError, ReassemblyManager
from dmp_peer.sample1 import Sample, SampleConsumer
from dmp_peer.stream_r import encode_stream_r
from dmp_peer.testing import PeerEndpoint


def manifest(name="direct-nnpsk0.json"):
    return (Path(__file__).parents[3] / "profiles" / "deployments" / name).read_bytes()


def endpoint(node=10):
    ep = PeerEndpoint(manifest(), {"node_id": node}, lambda n: b"e" * n, {})
    ep.handle(Open(0, "strict_latest_start", 1))
    ep.handle(Receive(0, b"\x00", 2))
    return ep


def service2_frame(kind, seq, payload, *, ack=True, fragment=None, reply=None):
    exts = [Extension(4, True, False, encode_uleb(2))]
    if reply is not None:
        ns, origin, epoch, ref_seq = reply
        exts = [Extension(1, True, False, encode_uleb(ns) + encode_uleb(origin) + epoch.to_bytes(8, "little") + encode_uleb(ref_seq)), *exts]
    options = 0x83 if ack else 0x81
    if fragment is not None:
        options |= 0x08
    return encode_frame(CoreFrame(kind, options, seq, fragment=fragment, extensions=tuple(sorted(exts, key=lambda e:e.extension_id)), payload=payload))


def settle_all(ep, at_ms):
    for handle, sub in list(ep.active_submissions.items()):
        if not sub["admitted"]:
            ep.handle(TxAdmit(handle, sub["generation"], True, None, at_ms))
            at_ms += 1
        ep.handle(TxTerminal(handle, sub["generation"], "transmitted", at_ms))
        at_ms += 1


class P21BRepairTests(unittest.TestCase):
    def test_fragmented_terminal_result_replays_ack_after_ack_loss(self):
        receiver = endpoint(10)
        request_events = receiver.handle(ApplicationRequest(2, b"q", 10, exchange_id=8))
        exc = receiver.delivery.active_outgoing[8]
        frames, _ = endpoint(20)._build_rsp_frames((1, 10, exc.epoch, exc.seq), 2, b"x" * 100)
        first_events = []
        for i, raw in enumerate(frames):
            first_events.extend(receiver.handle(Receive(0, encode_stream_r(raw), 20 + i)))
        self.assertEqual(sum(type(e).__name__ == "ApplicationEvent" and e.kind == "request_result" for e in first_events), 1)
        self.assertTrue(any(isinstance(e, TxSubmit) for e in first_events))
        settle_all(receiver, 25)
        replay = receiver.handle(Receive(0, encode_stream_r(frames[0]), 30))
        self.assertEqual(sum(type(e).__name__ == "ApplicationEvent" and e.kind == "request_result" for e in replay), 0)
        self.assertTrue(any(isinstance(e, TxSubmit) for e in replay))

    def test_deadline_cancels_admitted_borrow_and_keeps_it_until_terminal(self):
        ep = endpoint()
        tx = next(e for e in ep.handle(ApplicationRequest(2, b"x", 10, exchange_id=3, not_after_ms=20)) if isinstance(e, TxSubmit))
        ep.handle(TxAdmit(tx.handle, tx.generation, True, None, 11))
        out = ep.handle(Advance(20))
        self.assertTrue(any(type(e).__name__ == "Cancel" for e in out))
        self.assertNotIn(3, ep.delivery.active_outgoing)
        self.assertIn(tx.handle, ep.active_submissions)
        ep.handle(TxTerminal(tx.handle, tx.generation, "cancelled_unsent", 21))
        self.assertNotIn(tx.handle, ep.active_submissions)

    def test_reassembly_identity_includes_immutable_metadata(self):
        mgr = ReassemblyManager(100, 10, 2, 4, 10, 20)
        base = dict(namespace=1, origin=2, epoch=3, seq=4, chunk_size=2, total_length=4,
                    message_type=7, ack_req=False, service_id=2, at_ms=1)
        mgr.process_fragment(**base, fragment_index=0, slice_payload=b"ab", immutable_metadata=("route-A",))
        with self.assertRaises(ReassemblyError):
            mgr.process_fragment(**base, fragment_index=1, slice_payload=b"cd", immutable_metadata=("route-B",))

    def test_disconnect_retires_protocol_state_and_advance_does_not_send(self):
        ep = endpoint()
        tx = next(e for e in ep.handle(ApplicationRequest(2, b"x", 10)) if isinstance(e, TxSubmit))
        ep.handle(TxAdmit(tx.handle, tx.generation, True, None, 11))
        ep.handle(Disconnect(0, 12))
        self.assertFalse(ep.is_open)
        self.assertFalse(ep.delivery.active_outgoing)
        self.assertFalse(ep.reassembly.active)
        self.assertTrue(ep.active_submissions)  # borrowed bytes remain until terminal
        self.assertFalse(any(isinstance(e, TxSubmit) for e in ep.handle(Advance(1000))))

    def test_manifest_quotas_bound_adapter_sender_result_history_and_correlation_state(self):
        ep = endpoint()
        evts = ep.handle(ApplicationRequest(2, b"x" * 1024, 10, exchange_id=90))
        self.assertLessEqual(len(ep.active_submissions), ep.adapter_slots)
        self.assertLessEqual(len(ep.tx_queue), ep.max_queued_frames)
        self.assertLessEqual(len(ep.delivery.active_outgoing) + len(ep.delivery.queue), ep.delivery.sender_slots)
        self.assertLessEqual(len(ep.delivery.retained_results), ep.delivery.result_slots)
        self.assertLessEqual(len(ep.delivery.accepted_messages) + len(ep.delivery.rejections), ep.delivery.history_slots)
        self.assertLessEqual(len(ep.delivery.caller_tombstones), ep.delivery.correlation_slots)
        self.assertTrue(any(isinstance(e, TxSubmit) for e in evts))

    def test_terminal_result_uses_same_stop_and_wait_gate_as_local_request(self):
        responder = endpoint(20)
        req = service2_frame(0, 20, b"q")
        result_events = responder.handle(Receive(0, encode_stream_r(req), 10))
        result_tx = next(e for e in result_events if isinstance(e, TxSubmit))
        queued = responder.handle(ApplicationRequest(2, b"local", 20, exchange_id=91))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in queued))
        result_core = next(e.frame for e in responder.stream_r_decoder.feed(result_tx.bytes, at_ms=21) if e.kind == "frame")
        result_frame = parse_frame(result_core)
        ack = responder._build_ack_frame((1, 20, responder.local_epoch, result_frame.sequence), 2)
        promoted = responder.handle(Receive(0, encode_stream_r(ack), 22))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in promoted))
        self.assertIn(91, responder.delivery.active_outgoing)

    def test_duplicate_changed_payload_precedes_size_and_ack_rejection(self):
        responder = endpoint(20)
        original = service2_frame(0, 25, b"q")
        responder.handle(Receive(0, encode_stream_r(original), 10))
        changed = service2_frame(0, 25, b"x" * 1024, ack=False)
        events = responder.handle(Receive(0, encode_stream_r(changed), 11))
        self.assertFalse(any(type(e).__name__ == "ApplicationEvent" and e.kind in ("request_accepted", "protocol_rejection") for e in events))
        self.assertEqual(responder.delivery.accepted_messages[(1, 10, 7, 25)].payload, b"q")

    def test_late_result_ack_requires_original_peer_service_and_payload_context(self):
        requester = endpoint(10)
        requester.handle(ApplicationRequest(2, b"q", 10, exchange_id=92))
        exc = requester.delivery.active_outgoing[92]
        requester.delivery.complete_exchange(exc)
        wrong_peer = CoreFrame(1, 0x83, 70, extensions=(
            Extension(1, True, False, encode_uleb(1) + encode_uleb(10) + exc.epoch.to_bytes(8, "little") + encode_uleb(exc.seq)),
            Extension(3, True, True, encode_uleb(30)),
        ), payload=b"ok")
        self.assertFalse(any(isinstance(e, TxSubmit) for e in requester.handle(Receive(0, encode_stream_r(encode_frame(wrong_peer)), 11))))
        wrong_service = CoreFrame(1, 0x83, 71, extensions=(
            Extension(1, True, False, encode_uleb(1) + encode_uleb(10) + exc.epoch.to_bytes(8, "little") + encode_uleb(exc.seq)),
            Extension(4, True, False, encode_uleb(1)),
        ), payload=b"ok")
        self.assertFalse(any(isinstance(e, TxSubmit) for e in requester.handle(Receive(0, encode_stream_r(encode_frame(wrong_service)), 12))))
        valid = service2_frame(1, 72, b"ok", reply=(1, 10, exc.epoch, exc.seq))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in requester.handle(Receive(0, encode_stream_r(valid), 13))))

    def test_invalid_restart_and_unadmitted_terminal_do_not_advance_clock(self):
        ep = endpoint()
        with self.assertRaises(ValueError):
            ep.handle(Restart(50, b"short"))
        self.assertEqual(ep.now_ms, 2)
        tx = next(e for e in ep.handle(ApplicationRequest(2, b"x", 3)) if isinstance(e, TxSubmit))
        self.assertEqual(ep.handle(TxTerminal(tx.handle, tx.generation, "transmitted", 50)), ())
        self.assertEqual(ep.now_ms, 3)

    def test_sample_deadline_invalidates_read_and_index_exhaustion_closes_association(self):
        consumer = SampleConsumer(max_attempts=2, init_deadline_ms=10)
        consumer.start_initialization(1, 0)
        consumer.designate_read(5, 1)
        self.assertTrue(consumer.advance(10))
        self.assertIsNone(consumer.designated_request_seq)
        self.assertFalse(consumer.handle_read_result(5, Sample(1, 1, 1).encode_read_result(), now_ms=11))

        producer = endpoint(10)
        producer.sample_producer._sample_index = 0xFFFFFFFF
        out = producer.handle(PublishSample(5, 3))
        self.assertFalse(producer.is_open)
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out))
        self.assertEqual(producer.sample_epoch_store.current_epoch(), 2)

    def test_incomplete_identity_remains_retired_while_context_is_live(self):
        mgr = ReassemblyManager(100, 10, 1, 2, 5, 10)
        args = dict(namespace=1, origin=2, epoch=3, seq=4, chunk_size=2, total_length=4,
                    message_type=7, ack_req=False, service_id=2)
        mgr.process_fragment(**args, fragment_index=0, slice_payload=b"ab", at_ms=0)
        mgr.advance(5)
        mgr.advance(100000)
        with self.assertRaises(ReassemblyError):
            mgr.process_fragment(**args, fragment_index=1, slice_payload=b"cd", at_ms=100001)

    def test_result_retry_bursts_stop_at_manifest_max(self):
        mgr = DeliveryManager(response_timeout_ms=1, receipt_delay_ms=1, result_deadline_ms=10,
                              result_cache_ms=10, dedup_ms=10, rejection_ms=10, correlation_ms=10,
                              max_bursts=2, app_queue_slots=1)
        result = RetainedResult(2, 1, 2, 3, 4, 5, result_frames=(b"one",), expires_at_ms=10, next_retry_ms=1, attempts_left=1)
        key = (1, 2, 3, 4)
        mgr.retained_results[key] = result
        self.assertEqual(len(mgr.advance(1)[1]), 1)
        self.assertEqual(len(mgr.advance(2)[1]), 0)
        self.assertEqual(result.bursts_sent, 2)

    def test_fragmented_result_replay_ack_requires_endpoint_acceptance(self):
        # An unsolicited complete RSP and a malformed SAMPLE READ RSP both leave
        # the reassembly record completed, but neither earns a result receipt ACK.
        unsolicited = endpoint(10)
        frames, _ = endpoint(20)._build_rsp_frames((1, 10, 777, 40), 2, b"x" * 100)
        for i, raw in enumerate(frames):
            out = unsolicited.handle(Receive(0, encode_stream_r(raw), 10 + i))
        replay = unsolicited.handle(Receive(0, encode_stream_r(frames[0]), 20))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in replay))

        sample = endpoint(20)
        req = next(e for e in sample.handle(ApplicationRequest(1, b"\x01", 10, exchange_id=501)) if isinstance(e, TxSubmit))
        exc = sample.delivery.active_outgoing[501]
        malformed, _ = endpoint(10)._build_rsp_frames((1, 20, exc.epoch, exc.seq), 1, b"bad" * 30)
        for i, raw in enumerate(malformed):
            sample.handle(Receive(0, encode_stream_r(raw), 20 + i))
        replay = sample.handle(Receive(0, encode_stream_r(malformed[0]), 40))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in replay))

    def test_data_history_quota_prevents_ack_and_acceptance(self):
        ep = endpoint(20)
        for i in range(ep.delivery.history_slots):
            key = (1, 10, 7, 100 + i)
            ep.delivery.accepted_messages[key] = __import__("dmp_peer.delivery", fromlist=["AcceptedRecord"]).AcceptedRecord(
                7, 2, 1, b"a", 0, 1000, b"old"
            )
        frame = service2_frame(7, 999, b"new")
        out = ep.handle(Receive(0, encode_stream_r(frame), 10))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out))
        self.assertNotIn((1, 10, 7, 999), ep.delivery.accepted_messages)
        self.assertEqual(len(ep.delivery.accepted_messages), ep.delivery.history_slots)

    def test_repeated_negative_tx_admit_preserves_accepted_borrow(self):
        ep = endpoint()
        tx = next(e for e in ep.handle(ApplicationRequest(2, b"x", 10, exchange_id=502)) if isinstance(e, TxSubmit))
        ep.handle(TxAdmit(tx.handle, tx.generation, True, None, 11))
        self.assertEqual(ep.handle(TxAdmit(tx.handle, tx.generation, False, "busy", 12)), ())
        self.assertIn(tx.handle, ep.active_submissions)
        self.assertTrue(ep.active_submissions[tx.handle]["admitted"])
        ep.handle(TxTerminal(tx.handle, tx.generation, "transmitted", 13))
        self.assertNotIn(tx.handle, ep.active_submissions)

    def test_unsent_fragment_terminal_cancels_sibling_and_reports_unknown(self):
        ep = endpoint()
        submits = [e for e in ep.handle(ApplicationRequest(2, b"x" * 900, 10, exchange_id=503)) if isinstance(e, TxSubmit)]
        self.assertGreaterEqual(len(submits), 2)
        for tx in submits[:2]:
            ep.handle(TxAdmit(tx.handle, tx.generation, True, None, 11))
        out = ep.handle(TxTerminal(submits[0].handle, submits[0].generation, "failed_unsent", 12))
        self.assertTrue(any(type(e).__name__ == "Cancel" and e.handle == submits[1].handle for e in out))
        self.assertTrue(any(type(e).__name__ == "ApplicationEvent" and e.payload == b"unknown" for e in out))
        self.assertIn(submits[1].handle, ep.active_submissions)
        self.assertFalse(any(item.get("exchange_id") == 503 for item in ep.tx_queue))
        ep.handle(TxTerminal(submits[1].handle, submits[1].generation, "cancelled_unsent", 13))
        self.assertNotIn(submits[1].handle, ep.active_submissions)

    def test_disconnect_reports_transmitted_exchange_unknown_on_sample_epoch_rollover(self):
        ep = endpoint(10)
        tx = next(e for e in ep.handle(ApplicationRequest(2, b"x", 10, exchange_id=504)) if isinstance(e, TxSubmit))
        ep.handle(TxAdmit(tx.handle, tx.generation, True, None, 11))
        ep.handle(TxTerminal(tx.handle, tx.generation, "transmitted", 12))
        ep.sample_producer._sample_index = 0xFFFFFFFF
        out = ep.handle(PublishSample(5, 13))
        self.assertFalse(ep.is_open)
        self.assertTrue(any(type(e).__name__ == "ApplicationEvent" and e.exchange_id == 504 and e.payload == b"unknown" for e in out))

    def test_retained_rejection_is_checked_before_changed_size_or_ack_policy(self):
        ep = endpoint(20)
        first = encode_frame(CoreFrame(0, 0x81, 505, payload=b"\xff"))
        ep.handle(Receive(0, encode_stream_r(first), 10))
        key = (1, 10, 7, 505)
        rej = ep.delivery.rejections[key]
        original = (rej.status, rej.expires_at_ms, rej.replay_bursts)
        changed = encode_frame(CoreFrame(0, 0x81, 505, payload=b"\x01\x02"))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in ep.handle(Receive(0, encode_stream_r(changed), 11))) )
        self.assertEqual((rej.status, rej.expires_at_ms, rej.replay_bursts), original)
        exact = ep.handle(Receive(0, encode_stream_r(first), 12))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in exact))
        self.assertEqual(rej.status, 7)
        self.assertEqual(rej.expires_at_ms, original[1])
        self.assertEqual(rej.replay_bursts, original[2] + 1)

    def test_result_deadline_expires_before_pending_handle_gate_after_ack(self):
        ep = endpoint()
        tx = next(e for e in ep.handle(ApplicationRequest(2, b"x", 10, exchange_id=506)) if isinstance(e, TxSubmit))
        ep.handle(TxAdmit(tx.handle, tx.generation, True, None, 11))
        exc = ep.delivery.active_outgoing[506]
        exc.received_ack = True
        exc.state = "awaiting_result"
        out = ep.handle(Advance(exc.created_at_ms + exc.result_deadline_ms))
        self.assertNotIn(506, ep.delivery.active_outgoing)
        self.assertIn(tx.handle, ep.active_submissions)
        self.assertTrue(any(type(e).__name__ == "Cancel" and e.handle == tx.handle for e in out))
        self.assertTrue(any(type(e).__name__ == "ApplicationEvent" and e.payload == b"unknown" for e in out))

    def test_unfragmented_duplicate_metadata_changes_do_not_replay_req_or_data_ack(self):
        ep = endpoint(20)
        req = service2_frame(0, 507, b"same", ack=True)
        self.assertTrue(any(isinstance(e, TxSubmit) for e in ep.handle(Receive(0, encode_stream_r(req), 10))))
        changed_req = service2_frame(0, 507, b"same", ack=False)
        self.assertFalse(any(isinstance(e, TxSubmit) for e in ep.handle(Receive(0, encode_stream_r(changed_req), 11))))

        data = service2_frame(7, 508, b"same", ack=True)
        self.assertTrue(any(isinstance(e, TxSubmit) for e in ep.handle(Receive(0, encode_stream_r(data), 12))))
        changed_data = service2_frame(7, 508, b"same", ack=False)
        self.assertFalse(any(isinstance(e, TxSubmit) for e in ep.handle(Receive(0, encode_stream_r(changed_data), 13))))

    def test_tx_drain_expiry_retires_siblings_cancels_admitted_and_reports_unknown_if_transmitted(self):
        ep = endpoint()
        settle_all(ep, 5)
        # Request with 200 bytes generates 4 fragments in direct profile (MTU 256, chunk_bytes 64)
        submits = [e for e in ep.handle(ApplicationRequest(2, b"x" * 200, 10, exchange_id=701, not_after_ms=30)) if isinstance(e, TxSubmit)]
        self.assertEqual(len(submits), ep.adapter_slots)  # 3 admitted to adapter boundary
        self.assertEqual(len(ep.tx_queue), 1)  # 4th fragment queued in tx_queue
        for tx in submits:
            ep.handle(TxAdmit(tx.handle, tx.generation, True, None, 10))
        # Handle 0 terminal transmitted at at_ms=30 (which reaches not_after_ms=30)
        out = ep.handle(TxTerminal(submits[0].handle, submits[0].generation, "transmitted", 30))
        # 4th fragment expired while draining tx_queue:
        # 1. Reports unknown because fragment 0 was transmitted
        self.assertTrue(any(type(e).__name__ == "ApplicationEvent" and e.exchange_id == 701 and e.payload == b"unknown" for e in out))
        # 2. Cancels still-admitted sibling handles (1 and 2)
        self.assertTrue(any(type(e).__name__ == "Cancel" and e.handle == submits[1].handle for e in out))
        self.assertTrue(any(type(e).__name__ == "Cancel" and e.handle == submits[2].handle for e in out))
        # 3. Queued siblings removed from tx_queue
        self.assertFalse(any(item.get("exchange_id") == 701 for item in ep.tx_queue))
        # 4. Admitted handles remain in active_submissions until terminal callbacks
        self.assertIn(submits[1].handle, ep.active_submissions)
        self.assertIn(submits[2].handle, ep.active_submissions)
        # Settle admitted siblings
        ep.handle(TxTerminal(submits[1].handle, submits[1].generation, "cancelled_unsent", 31))
        ep.handle(TxTerminal(submits[2].handle, submits[2].generation, "cancelled_unsent", 31))
        self.assertNotIn(submits[1].handle, ep.active_submissions)
        self.assertNotIn(submits[2].handle, ep.active_submissions)

    def test_terminal_result_clears_queued_retries_and_cancels_admitted_attempts(self):
        ep = endpoint(10)
        settle_all(ep, 5)
        out = ep.handle(ApplicationRequest(2, b"x" * 200, 10, exchange_id=702))
        submits = [e for e in out if isinstance(e, TxSubmit)]
        self.assertEqual(len(submits), ep.adapter_slots)
        self.assertTrue(any(item.get("exchange_id") == 702 for item in ep.tx_queue))
        for tx in submits:
            ep.handle(TxAdmit(tx.handle, tx.generation, True, None, 11))

        # Terminal RSP arrives from responder
        exc = ep.delivery.active_outgoing[702]
        exts = [
            Extension(4, True, False, encode_uleb(2)),
            Extension(1, True, False, encode_uleb(1) + encode_uleb(10) + exc.epoch.to_bytes(8, "little") + encode_uleb(exc.seq)),
        ]
        rsp = encode_frame(CoreFrame(1, 0x83, 999, extensions=tuple(sorted(exts, key=lambda e: e.extension_id)), payload=b"pong"))
        rsp_events = ep.handle(Receive(0, encode_stream_r(rsp), 12))
        self.assertTrue(any(type(e).__name__ == "ApplicationEvent" and e.kind == "request_result" and e.exchange_id == 702 for e in rsp_events))
        # Admitted attempts are canceled
        cancels = [e for e in rsp_events if isinstance(e, Cancel)]
        self.assertEqual(len(cancels), 3)
        # Queued attempt frames for 702 are removed from tx_queue
        self.assertFalse(any(item.get("exchange_id") == 702 for item in ep.tx_queue))
        # Borrows remain in active_submissions until terminal
        self.assertTrue(all(c.handle in ep.active_submissions for c in cancels))
        # Settle first cancelled handle -> drains result ACK (not 702)
        t1 = ep.handle(TxTerminal(cancels[0].handle, cancels[0].generation, "cancelled_unsent", 13))
        self.assertFalse(any(isinstance(e, TxSubmit) and ep.active_submissions.get(e.handle, {}).get("exchange_id") == 702 for e in t1))
        # Settle remaining cancelled handles -> no completed 702 frames drained
        t2 = ep.handle(TxTerminal(cancels[1].handle, cancels[1].generation, "cancelled_unsent", 14))
        t3 = ep.handle(TxTerminal(cancels[2].handle, cancels[2].generation, "cancelled_unsent", 15))
        self.assertEqual(len(t2), 0)
        self.assertEqual(len(t3), 0)
        self.assertFalse(any(c.handle in ep.active_submissions for c in cancels))

    def test_fragmented_rejected_req_duplicate_replays_retained_rejection(self):
        responder = endpoint(20)
        exts_s99 = (Extension(4, True, False, encode_uleb(99)),)
        f0 = CoreFrame(0, 0x8b, 100, fragment=Fragment(0, 100, 200), extensions=exts_s99, payload=b"A" * 100)
        f1 = CoreFrame(0, 0x8b, 100, fragment=Fragment(1, 100, 200), extensions=exts_s99, payload=b"B" * 100)
        responder.handle(Receive(0, encode_stream_r(encode_frame(f0)), 10))
        rej_out = responder.handle(Receive(0, encode_stream_r(encode_frame(f1)), 11))
        # First completion emitted rejection ERR
        self.assertTrue(any(isinstance(e, TxSubmit) for e in rej_out))
        key = (1, 10, 7, 100)
        self.assertIn(key, responder.delivery.rejections)
        rej = responder.delivery.rejections[key]
        self.assertEqual(rej.status, 2)
        initial_bursts = rej.replay_bursts

        # Metadata-matching duplicate fragment 0 replays retained rejection without renewing expiry
        dup_out = responder.handle(Receive(0, encode_stream_r(encode_frame(f0)), 12))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in dup_out))
        self.assertEqual(rej.replay_bursts, initial_bursts + 1)

        # Conflicting slice payload is dropped without replay
        f0_conflict = CoreFrame(0, 0x8b, 100, fragment=Fragment(0, 100, 200), extensions=exts_s99, payload=b"Z" * 100)
        conflict_out = responder.handle(Receive(0, encode_stream_r(encode_frame(f0_conflict)), 13))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in conflict_out))

        # Conflicting metadata (different service) is dropped without replay
        exts_s98 = (Extension(4, True, False, encode_uleb(98)),)
        f0_diff = CoreFrame(0, 0x8b, 100, fragment=Fragment(0, 100, 200), extensions=exts_s98, payload=b"A" * 100)
        diff_out = responder.handle(Receive(0, encode_stream_r(encode_frame(f0_diff)), 14))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in diff_out))

        # Exhaust replay budget
        while rej.replay_bursts < responder.delivery.max_bursts - 1:
            responder.handle(Receive(0, encode_stream_r(encode_frame(f0)), 15))
        exhausted_out = responder.handle(Receive(0, encode_stream_r(encode_frame(f0)), 16))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in exhausted_out))

    def test_publish_sample_backpressure_replaces_unsent_and_bounds_queue(self):
        producer = endpoint(10)
        settle_all(producer, 5)
        # Fill all adapter slots using a 4-fragment request
        out = producer.handle(ApplicationRequest(2, b"x" * 200, 10, exchange_id=801))
        for tx in [e for e in out if isinstance(e, TxSubmit)]:
            producer.handle(TxAdmit(tx.handle, tx.generation, True, None, 11))
        self.assertEqual(len(producer.active_submissions), producer.adapter_slots)
        initial_tx_queue_len = len(producer.tx_queue)  # 1 fragment from request 801

        # Publish initial sample under backpressure -> queued in tx_queue
        producer.handle(PublishSample(100, 12))
        self.assertEqual(len(producer.tx_queue), initial_tx_queue_len + 1)
        self.assertTrue(any(item.get("is_sample_telemetry") for item in producer.tx_queue))

        # Publish 50 more samples: replaces unsent sample in-place, bounded queue, no exception
        for v in range(101, 151):
            producer.handle(PublishSample(v, 13))
        self.assertEqual(len(producer.tx_queue), initial_tx_queue_len + 1)
        self.assertEqual(producer.sample_coalesced_count, 50)
        self.assertEqual(producer.counters["coalesced_samples"], 50)

        # Admitted requests in active_submissions remain untouched
        self.assertEqual(len(producer.active_submissions), producer.adapter_slots)
        self.assertFalse(any(sub.get("cancel_requested") for sub in producer.active_submissions.values()))

        # Terminate first request slice -> drains 4th fragment of request
        h0 = list(producer.active_submissions.keys())[0]
        drain1 = producer.handle(TxTerminal(h0, producer.active_submissions[h0]["generation"], "transmitted", 14))
        for e in drain1:
            if isinstance(e, TxSubmit):
                producer.handle(TxAdmit(e.handle, e.generation, True, None, 14))

        # Terminate next request slice -> drains newest sample (150)
        h1 = list(producer.active_submissions.keys())[0]
        drain2 = producer.handle(TxTerminal(h1, producer.active_submissions[h1]["generation"], "transmitted", 15))
        tx_sample = next(e for e in drain2 if isinstance(e, TxSubmit))
        stream_core = next(e.frame for e in producer.stream_r_decoder.feed(tx_sample.bytes, at_ms=16) if e.kind == "frame")
        sample_frame = parse_frame(stream_core)
        decoded_sample = Sample.decode_telemetry(sample_frame.payload)
        self.assertEqual(decoded_sample.value, 150)

    def test_fragmented_unfragmented_data_switch_rejected_both_directions(self):
        # Direction 1: Fragmented DATA accepted -> same-identity unfragmented DATA rejected without ACK
        responder = endpoint(20)
        settle_all(responder, 5)
        f0 = service2_frame(7, 500, b"abcde", ack=True, fragment=Fragment(0, 5, 10))
        f1 = service2_frame(7, 500, b"fghij", ack=True, fragment=Fragment(1, 5, 10))
        responder.handle(Receive(0, encode_stream_r(f0), 10))
        out1 = responder.handle(Receive(0, encode_stream_r(f1), 11))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in out1))  # Acceptance ACK emitted
        self.assertTrue(any(type(e).__name__ == "ApplicationEvent" and e.kind == "request_accepted" for e in out1))
        key = (1, 10, 7, 500)
        self.assertIn(key, responder.delivery.accepted_messages)
        rec = responder.delivery.accepted_messages[key]
        self.assertTrue(rec.immutable_metadata[0])  # is_fragmented
        self.assertEqual(rec.immutable_metadata[1], (5, 10))  # geometry
        settle_all(responder, 12)

        # Same-identity unfragmented DATA with same payload is dropped without ACK replay or dispatch
        unfrag = service2_frame(7, 500, b"abcdefghij", ack=True)
        out_unfrag = responder.handle(Receive(0, encode_stream_r(unfrag), 15))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out_unfrag))
        self.assertFalse(any(type(e).__name__ == "ApplicationEvent" for e in out_unfrag))

        # Direction 2: Unfragmented DATA accepted -> same-identity fragmented DATA rejected without assembly or ACK
        unfrag_2 = service2_frame(7, 501, b"1234567890", ack=True)
        out2 = responder.handle(Receive(0, encode_stream_r(unfrag_2), 20))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in out2))
        key2 = (1, 10, 7, 501)
        self.assertIn(key2, responder.delivery.accepted_messages)
        rec2 = responder.delivery.accepted_messages[key2]
        self.assertFalse(rec2.immutable_metadata[0])  # is_fragmented False
        self.assertIsNone(rec2.immutable_metadata[1])  # geometry None
        settle_all(responder, 21)

        # Fragment arrives for unfragmented identity: dropped before starting assembly
        frag2_0 = service2_frame(7, 501, b"12345", ack=True, fragment=Fragment(0, 5, 10))
        out_frag = responder.handle(Receive(0, encode_stream_r(frag2_0), 25))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out_frag))
        self.assertNotIn(key2, responder.reassembly.active)  # No unnecessary assembly created!
        frag2_1 = service2_frame(7, 501, b"67890", ack=True, fragment=Fragment(1, 5, 10))
        out_frag1 = responder.handle(Receive(0, encode_stream_r(frag2_1), 26))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out_frag1))
        self.assertNotIn(key2, responder.reassembly.active)

    def test_fragmented_unfragmented_req_switch_rejected_both_directions(self):
        # Direction 1: Fragmented REQ accepted -> same-identity unfragmented REQ rejected without result replay
        responder = endpoint(20)
        settle_all(responder, 5)
        # Service 2 REQ with payload 100 bytes: chunk=64, total=100
        req_f0 = service2_frame(0, 600, b"x" * 64, ack=True, fragment=Fragment(0, 64, 100))
        req_f1 = service2_frame(0, 600, b"x" * 36, ack=True, fragment=Fragment(1, 64, 100))
        responder.handle(Receive(0, encode_stream_r(req_f0), 10))
        out1 = responder.handle(Receive(0, encode_stream_r(req_f1), 11))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in out1))  # Result emitted
        key = (1, 10, 7, 600)
        self.assertIn(key, responder.delivery.accepted_messages)
        self.assertTrue(responder.delivery.accepted_messages[key].immutable_metadata[0])
        settle_all(responder, 12)

        # Same-identity unfragmented REQ is rejected without result replay or dispatch
        unfrag_req = service2_frame(0, 600, b"x" * 100, ack=True)
        out_unfrag = responder.handle(Receive(0, encode_stream_r(unfrag_req), 15))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out_unfrag))
        self.assertFalse(any(type(e).__name__ == "ApplicationEvent" for e in out_unfrag))

        # Direction 2: Unfragmented REQ accepted -> same-identity fragmented REQ rejected without assembly or result replay
        responder2 = endpoint(20)
        settle_all(responder2, 5)
        unfrag_req2 = service2_frame(0, 601, b"hello", ack=True)
        out2 = responder2.handle(Receive(0, encode_stream_r(unfrag_req2), 20))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in out2))
        key2 = (1, 10, 7, 601)
        self.assertIn(key2, responder2.delivery.accepted_messages)
        self.assertFalse(responder2.delivery.accepted_messages[key2].immutable_metadata[0])
        settle_all(responder2, 21)

        # Fragment arrives for unfragmented identity: dropped before starting assembly
        frag2_0 = service2_frame(0, 601, b"he", ack=True, fragment=Fragment(0, 2, 5))
        out_frag = responder2.handle(Receive(0, encode_stream_r(frag2_0), 25))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out_frag))
        self.assertNotIn(key2, responder2.reassembly.active)

    def test_retained_rejection_fragmented_unfragmented_switch_rejected_both_directions(self):
        # Direction 1: Fragmented REQ rejected -> same-identity unfragmented REQ rejected without ERR replay
        responder = endpoint(20)
        settle_all(responder, 5)
        exts_s99 = (Extension(4, True, False, encode_uleb(99)),)
        f0 = CoreFrame(0, 0x8b, 700, fragment=Fragment(0, 50, 100), extensions=exts_s99, payload=b"A" * 50)
        f1 = CoreFrame(0, 0x8b, 700, fragment=Fragment(1, 50, 100), extensions=exts_s99, payload=b"B" * 50)
        responder.handle(Receive(0, encode_stream_r(encode_frame(f0)), 10))
        out1 = responder.handle(Receive(0, encode_stream_r(encode_frame(f1)), 11))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in out1))  # Rejection ERR emitted
        key = (1, 10, 7, 700)
        self.assertIn(key, responder.delivery.rejections)
        rej = responder.delivery.rejections[key]
        self.assertTrue(rej.immutable_metadata[0])  # is_fragmented True
        self.assertEqual(rej.immutable_metadata[1], (50, 100))
        settle_all(responder, 12)

        # Same-identity unfragmented REQ for service 99: dropped without ERR replay
        unfrag_f = CoreFrame(0, 0x83, 700, extensions=exts_s99, payload=b"A" * 50 + b"B" * 50)
        out_unfrag = responder.handle(Receive(0, encode_stream_r(encode_frame(unfrag_f)), 15))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out_unfrag))

        # Fragment with conflicting geometry (chunk=25): dropped without ERR replay
        f_bad_geom = CoreFrame(0, 0x8b, 700, fragment=Fragment(0, 25, 100), extensions=exts_s99, payload=b"A" * 25)
        out_bad_geom = responder.handle(Receive(0, encode_stream_r(encode_frame(f_bad_geom)), 16))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out_bad_geom))

        # Direction 2: Unfragmented REQ rejected -> same-identity fragmented REQ rejected without assembly or ERR replay
        unfrag_701 = CoreFrame(0, 0x83, 701, extensions=exts_s99, payload=b"unsupported")
        out2 = responder.handle(Receive(0, encode_stream_r(encode_frame(unfrag_701)), 20))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in out2))
        key2 = (1, 10, 7, 701)
        self.assertIn(key2, responder.delivery.rejections)
        rej2 = responder.delivery.rejections[key2]
        self.assertFalse(rej2.immutable_metadata[0])  # is_fragmented False
        self.assertIsNone(rej2.immutable_metadata[1])
        settle_all(responder, 21)

        # Fragment arrives for unfragmented rejected identity: dropped before starting assembly
        frag_701 = CoreFrame(0, 0x8b, 701, fragment=Fragment(0, 5, 11), extensions=exts_s99, payload=b"unsup")
        out_frag = responder.handle(Receive(0, encode_stream_r(encode_frame(frag_701)), 25))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out_frag))
        self.assertNotIn(key2, responder.reassembly.active)

    def test_sample_coalescing_and_full_queue_drop_local_reporting(self):
        producer = endpoint(10)
        settle_all(producer, 5)
        # Fill adapter slots using 4-fragment request
        out = producer.handle(ApplicationRequest(2, b"x" * 200, 10, exchange_id=850))
        for tx in [e for e in out if isinstance(e, TxSubmit)]:
            producer.handle(TxAdmit(tx.handle, tx.generation, True, None, 11))
        self.assertEqual(len(producer.active_submissions), producer.adapter_slots)

        # Initial sample under backpressure queued
        producer.handle(PublishSample(1, 12))
        self.assertTrue(any(item.get("is_sample_telemetry") for item in producer.tx_queue))
        self.assertEqual(producer.sample_coalesced_count, 0)
        self.assertEqual(producer.sample_dropped_count, 0)

        # Subsequent sample while previous unsent sample is queued: coalesced locally
        coal_out = producer.handle(PublishSample(2, 13))
        self.assertEqual(producer.sample_coalesced_count, 1)
        self.assertEqual(producer.counters["coalesced_samples"], 1)
        self.assertTrue(any(
            isinstance(e, ApplicationEvent)
            and e.kind == "diagnostic"
            and e.service_id == 1
            and e.payload == b"sample_coalesced"
            for e in coal_out
        ))

        # Fill tx_queue up to max_queued_frames with non-sample items to test full-queue drop
        producer.tx_queue.clear()
        producer.max_queued_frames = 2
        producer.tx_queue.append({"wire_bytes": b"non_sample_1", "not_after_ms": None, "service_id": 2, "exchange_id": None})
        producer.tx_queue.append({"wire_bytes": b"non_sample_2", "not_after_ms": None, "service_id": 2, "exchange_id": None})
        self.assertEqual(len(producer.tx_queue), producer.max_queued_frames)

        # Publish sample when queue is full without unsent sample: drops locally with diagnostic
        drop_out = producer.handle(PublishSample(3, 14))
        self.assertEqual(len(producer.tx_queue), producer.max_queued_frames)  # bounded queue use
        self.assertEqual(producer.sample_dropped_count, 1)
        self.assertEqual(producer.counters["dropped_samples"], 1)
        self.assertTrue(any(
            isinstance(e, ApplicationEvent)
            and e.kind == "diagnostic"
            and e.service_id == 1
            and e.payload == b"sample_dropped"
            for e in drop_out
        ))
    def test_unfragmented_frame_cannot_reopen_expired_assembly_tombstone(self):
        receiver = endpoint(20)
        settle_all(receiver, 5)
        key = (1, 10, 7, 500)

        # 1. Receiver node 20 accepts first DATA fragment identity (1, 10, 7, 500) at t=10
        frag0 = service2_frame(7, 500, b"abcde", ack=True, fragment=Fragment(0, 5, 10))
        receiver.handle(Receive(0, encode_stream_r(frag0), 10))
        self.assertIn(key, receiver.reassembly.active)
        self.assertNotIn(key, receiver.reassembly.tombstones)
        self.assertNotIn(key, receiver.delivery.accepted_messages)

        # 2. Advance to 10 + assembly_ms so it expires into a tombstone
        expiry_ms = 10 + receiver.reassembly.assembly_ms
        receiver.handle(Advance(expiry_ms))
        self.assertNotIn(key, receiver.reassembly.active)
        self.assertIn(key, receiver.reassembly.tombstones)
        self.assertNotIn(key, receiver.delivery.accepted_messages)

        # 3. Deliver same identity as unfragmented DATA with same service, ACK_REQ, payload abcdefghij
        unfrag = service2_frame(7, 500, b"abcdefghij", ack=True)
        out_unfrag = receiver.handle(Receive(0, encode_stream_r(unfrag), expiry_ms + 1))

        # Rejected without ACK, acceptance callback, or application effect
        self.assertEqual(out_unfrag, ())
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out_unfrag))
        self.assertFalse(any(isinstance(e, ApplicationEvent) for e in out_unfrag))
        self.assertNotIn(key, receiver.delivery.accepted_messages)
        self.assertNotIn(key, receiver.reassembly.active)
        self.assertIn(key, receiver.reassembly.tombstones)

        # 4. Prove unrelated identities are NOT blocked
        unfrag_other = service2_frame(7, 501, b"unrelated", ack=True)
        out_other = receiver.handle(Receive(0, encode_stream_r(unfrag_other), expiry_ms + 2))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in out_other))
        self.assertTrue(any(isinstance(e, ApplicationEvent) and e.kind == "request_accepted" for e in out_other))
        self.assertIn((1, 10, 7, 501), receiver.delivery.accepted_messages)

        # 5. REQ identity: fragmented REQ expires into tombstone; unfragmented REQ cannot reopen
        key_req = (1, 10, 7, 600)
        req_frag0 = service2_frame(0, 600, b"r" * 64, ack=True, fragment=Fragment(0, 64, 100))
        receiver.handle(Receive(0, encode_stream_r(req_frag0), expiry_ms + 10))
        self.assertIn(key_req, receiver.reassembly.active)
        req_exp_ms = expiry_ms + 10 + receiver.reassembly.assembly_ms
        receiver.handle(Advance(req_exp_ms))
        self.assertNotIn(key_req, receiver.reassembly.active)
        self.assertIn(key_req, receiver.reassembly.tombstones)

        unfrag_req = service2_frame(0, 600, b"r" * 100, ack=True)
        out_req = receiver.handle(Receive(0, encode_stream_r(unfrag_req), req_exp_ms + 1))
        self.assertEqual(out_req, ())
        self.assertNotIn(key_req, receiver.delivery.accepted_messages)
        self.assertNotIn(key_req, receiver.delivery.retained_results)

        # 6. Tombstone clears on restart/context retirement
        receiver.handle(Restart(req_exp_ms + 5, b"restart_entropy_12345"))
        self.assertNotIn(key, receiver.reassembly.tombstones)
        self.assertNotIn(key_req, receiver.reassembly.tombstones)


if __name__ == "__main__":
    unittest.main()
