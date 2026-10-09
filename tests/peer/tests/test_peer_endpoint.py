"""Tests for DMP-PEER-TEST/1 event API, buffer ownership, deadlines, and lifecycle."""

import unittest
from pathlib import Path

from dmp_peer.events import (
    Advance,
    ApplicationEvent,
    ApplicationRequest,
    Cancel,
    Disconnect,
    EventValidationError,
    Open,
    PublishSample,
    Receive,
    Restart,
    TxAdmit,
    TxSubmit,
    TxTerminal,
)
from dmp_peer.frame import CoreFrame, Extension, Fragment, Security, decode_uleb, encode_frame, encode_uleb, parse_frame
from dmp_peer.stream_r import encode_stream_r
from dmp_peer.testing import PeerEndpoint


def _load_manifest_bytes(name: str = "direct-nnpsk0.json") -> bytes:
    path = Path(__file__).parents[3] / "profiles" / "deployments" / name
    return path.read_bytes()


class PeerEndpointApiTests(unittest.TestCase):
    def setUp(self):
        self.raw_manifest = _load_manifest_bytes()
        self.endpoint = PeerEndpoint(
            manifest_bytes=self.raw_manifest,
            test_credentials={"node_id": 10, "epoch": 7},
            entropy_source=lambda n: bytes(n),
            test_services={},
            test_only_disable_sec1=True,
        )

    def _settle_active(self, at_ms):
        for handle, sub in list(self.endpoint.active_submissions.items()):
            if not sub["admitted"]:
                self.endpoint.handle(TxAdmit(handle, sub["generation"], True, None, at_ms))
                at_ms += 1
            self.endpoint.handle(TxTerminal(handle, sub["generation"], "transmitted", at_ms))
            at_ms += 1

    def test_event_validation_and_range_checks(self):
        # Type and range checking: bool not accepted for integers
        with self.assertRaises(EventValidationError):
            Open(link=True, deadline_capability="strict_latest_start", at_ms=10)

        with self.assertRaises(EventValidationError):
            Open(link=256, deadline_capability="strict_latest_start", at_ms=10)

        with self.assertRaises(EventValidationError):
            Open(link=0, deadline_capability="invalid_capability", at_ms=10)

        with self.assertRaises(EventValidationError):
            TxAdmit(handle=1, generation=1, accepted=True, reason="busy", at_ms=10)

        with self.assertRaises(EventValidationError):
            TxTerminal(handle=1, generation=1, outcome="invalid_outcome", at_ms=10)

        with self.assertRaises(EventValidationError):
            ApplicationEvent(kind="invalid_kind", service_id=1, exchange_id=1, status=0, payload=b"", at_ms=10)

    def test_backwards_time_fails_closed(self):
        self.endpoint.handle(Advance(now_ms=100))
        self.assertEqual(self.endpoint.now_ms, 100)
        with self.assertRaisesRegex(ValueError, "time cannot move backwards"):
            self.endpoint.handle(Advance(now_ms=90))
        # State unchanged
        self.assertEqual(self.endpoint.now_ms, 100)

    def test_open_emits_initial_stream_r_sync_delimiter(self):
        # Direct profile uses Stream R and requires strict_latest_start
        events = self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.assertTrue(self.endpoint.is_open)
        self.assertEqual(len(events), 1)
        sub = events[0]
        self.assertIsInstance(sub, TxSubmit)
        self.assertEqual(sub.bytes, b"\x00")
        self.assertEqual(sub.generation, 1)
        self.assertIsNone(sub.not_after_ms)

    def test_open_with_incapable_binding_fails(self):
        with self.assertRaisesRegex(ValueError, "strict_latest_start"):
            self.endpoint.handle(Open(link=0, deadline_capability="submission_only", at_ms=10))

    def test_borrowed_tx_buffer_and_stale_completion(self):
        # Open endpoint -> initial delimiter emitted
        events = self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        sub = events[0]
        self.assertIsInstance(sub, TxSubmit)
        handle = sub.handle
        gen = sub.generation

        # Controller admits submission
        self.endpoint.handle(TxAdmit(handle=handle, generation=gen, accepted=True, reason=None, at_ms=10))
        self.assertIn(handle, self.endpoint.active_submissions)
        self.assertTrue(self.endpoint.active_submissions[handle]["admitted"])

        # Stale completion with wrong generation has no effect
        self.endpoint.handle(TxTerminal(handle=handle, generation=gen + 1, outcome="transmitted", at_ms=20))
        self.assertIn(handle, self.endpoint.active_submissions)

        # Valid completion frees slot
        self.endpoint.handle(TxTerminal(handle=handle, generation=gen, outcome="transmitted", at_ms=30))
        self.assertNotIn(handle, self.endpoint.active_submissions)

    def test_deadline_strict_latest_start_local_expiry(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        sub = self.endpoint.handle(Advance(now_ms=15))

        # Request with not_after_ms = 50
        req = ApplicationRequest(service_id=2, payload=b"test", at_ms=20, not_after_ms=50)
        events = self.endpoint.handle(req)
        tx_sub = next(e for e in events if isinstance(e, TxSubmit))
        self.assertEqual(tx_sub.not_after_ms, 50)

        # Advance past cutoff to 60 -> local expiry before transmission
        term_events = self.endpoint.handle(Advance(now_ms=60))
        rej = next((e for e in term_events if isinstance(e, ApplicationEvent) and e.kind == "protocol_rejection"), None)
        self.assertIsNotNone(rej)

    def test_disconnect_and_restart_advance_generation(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        initial_gen = self.endpoint.generation
        self.endpoint.handle(Disconnect(link=0, at_ms=50))
        self.assertFalse(self.endpoint.is_open)
        self.assertEqual(self.endpoint.generation, initial_gen + 1)
        self.assertEqual(len(self.endpoint.active_submissions), 0)

        self.endpoint.handle(Restart(at_ms=100, entropy=b"\x00" * 32))
        self.assertEqual(self.endpoint.generation, initial_gen + 2)

    def test_cancel_input_event_rejected(self):
        # Cancel is a peer output event per P20, not a controller input
        with self.assertRaises(EventValidationError):
            self.endpoint.handle(Cancel(handle=1, generation=1, at_ms=10))
        self.assertEqual(self.endpoint.now_ms, 0)

    def test_disconnect_preserves_admitted_submissions_until_tx_terminal(self):
        events = self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        sub = events[0]
        gen = sub.generation
        handle = sub.handle

        # Controller admits submission
        self.endpoint.handle(TxAdmit(handle=handle, generation=gen, accepted=True, reason=None, at_ms=10))
        self.assertIn(handle, self.endpoint.active_submissions)

        # Disconnect preserves admitted submissions; generation advances
        self.endpoint.handle(Disconnect(link=0, at_ms=50))
        self.assertFalse(self.endpoint.is_open)
        self.assertIn(handle, self.endpoint.active_submissions)
        self.assertEqual(self.endpoint.generation, gen + 1)

        # Controller settles borrow with TxTerminal
        self.endpoint.handle(TxTerminal(handle=handle, generation=gen, outcome="cancelled_unsent", at_ms=60))
        self.assertNotIn(handle, self.endpoint.active_submissions)

    def test_protected_frame_rejected_without_mutation(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.endpoint.handle(Receive(link=0, bytes=b"\x00", at_ms=12))
        # Protected frame with SEC-1 Security header (must be rejected in P21B; no plaintext interpretation)
        prot_frame = CoreFrame(
            message_type=0,
            options=0x83,
            sequence=1,
            security=Security(cipher=1, receive_cid=5, packet_number=10),
            trailer=b"\x00" * 16,
            payload=b"encrypted_secret",
        )
        prot_bytes = encode_frame(prot_frame, max_frame=256)
        prot_stream = encode_stream_r(prot_bytes, max_core=256, max_encoded=263)

        events = self.endpoint.handle(Receive(link=0, bytes=prot_stream, at_ms=20))
        # No application events or output frames emitted from rejected protected frame
        self.assertEqual(len(events), 0)

    def test_unsupported_service_explicitly_rejected_status_2(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.endpoint.handle(Receive(link=0, bytes=b"\x00", at_ms=12))
        # Deliver a request with service_id=99 (unsupported)
        ext_s99 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(99))
        req = CoreFrame(message_type=0, options=0x83, sequence=10, extensions=(ext_s99,), payload=b"\x01")
        req_stream = encode_stream_r(encode_frame(req, max_frame=256), max_core=256, max_encoded=263)

        events = self.endpoint.handle(Receive(link=0, bytes=req_stream, at_ms=20))
        tx_subs = [e for e in events if isinstance(e, TxSubmit)]
        self.assertTrue(len(tx_subs) >= 1)
        # Verify ERR frame with STATUS=2
        dec = self.endpoint.stream_r_decoder.feed(tx_subs[0].bytes, at_ms=25)
        core = next(e.frame for e in dec if e.kind == "frame")
        err_frame = parse_frame(core)
        self.assertEqual(err_frame.message_type, 2)  # ERR
        status_ext = next(ext for ext in err_frame.extensions if ext.extension_id == 5)
        status, _ = decode_uleb(status_ext.value)
        self.assertEqual(status, 2)  # STATUS=2: Unsupported service

    def test_expiry_after_possible_transmission_reports_unknown_outcome(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        req = ApplicationRequest(service_id=2, payload=b"probe", at_ms=20, not_after_ms=50, exchange_id=10)
        events = self.endpoint.handle(req)
        tx_sub = next(e for e in events if isinstance(e, TxSubmit))
        handle = tx_sub.handle
        gen = tx_sub.generation

        # Controller admits submission
        self.endpoint.handle(TxAdmit(handle=handle, generation=gen, accepted=True, reason=None, at_ms=20))
        # Submission transmitted over wire
        self.endpoint.handle(TxTerminal(handle=handle, generation=gen, outcome="transmitted", at_ms=25))

        # Advance past deadline without remote response
        term_events = self.endpoint.handle(Advance(now_ms=60))
        diag = next((e for e in term_events if isinstance(e, ApplicationEvent) and e.kind == "diagnostic"), None)
        self.assertIsNotNone(diag)
        self.assertEqual(diag.payload, b"unknown")
        # No protocol_rejection status=4 because transmission already happened
        rej = next((e for e in term_events if isinstance(e, ApplicationEvent) and e.kind == "protocol_rejection"), None)
    def test_data_duplicate_never_redispatches_or_reruns_service_effects(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.endpoint.handle(Receive(link=0, bytes=b"\x00", at_ms=12))

        # Reliable DATA (message_type=7, ACK_REQ=1)
        ext_s2 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))
        data_frame = CoreFrame(message_type=7, options=0x83, sequence=10, extensions=(ext_s2,), payload=b"payload_bytes")
        stream_bytes = encode_stream_r(encode_frame(data_frame, max_frame=256), max_core=256, max_encoded=263)

        # 1. First delivery accepts DATA, emits request_accepted and transmits ACK
        evts1 = self.endpoint.handle(Receive(link=0, bytes=stream_bytes, at_ms=20))
        accepted_evts1 = [e for e in evts1 if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]
        self.assertEqual(len(accepted_evts1), 1)
        tx_subs1 = [e for e in evts1 if isinstance(e, TxSubmit)]
        self.assertEqual(len(tx_subs1), 1)

        # 2. Duplicate delivery must NOT re-dispatch request_accepted, must replay ACK
        evts2 = self.endpoint.handle(Receive(link=0, bytes=stream_bytes, at_ms=30))
        accepted_evts2 = [e for e in evts2 if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]
        self.assertEqual(len(accepted_evts2), 0)  # Never re-dispatches service effects!
        tx_subs2 = [e for e in evts2 if isinstance(e, TxSubmit)]
        self.assertEqual(len(tx_subs2), 1)  # Replays cached ACK
        self.assertEqual(tx_subs1[0].bytes, tx_subs2[0].bytes)

    def test_queue_full_and_expired_local_submission_produce_bounded_local_outcome(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))

        # 1. Already-expired local submission (not_after_ms=15 < at_ms=20)
        exp_req = ApplicationRequest(service_id=2, payload=b"late", at_ms=20, not_after_ms=15)
        exp_evts = self.endpoint.handle(exp_req)
        exp_rej = next((e for e in exp_evts if isinstance(e, ApplicationEvent) and e.kind == "protocol_rejection"), None)
        self.assertIsNotNone(exp_rej)
        self.assertEqual(exp_rej.status, 4)
        self.assertEqual(exp_rej.payload, b"expired")

        # 2. Fill queue capacity: direct-nnpsk0 has application_queue_slots = 2
        # First request occupies stop-and-wait gate
        self.endpoint.handle(ApplicationRequest(service_id=2, payload=b"slot0", at_ms=20))
        # Slots 1 and 2 queued
        self.endpoint.handle(ApplicationRequest(service_id=2, payload=b"slot1", at_ms=20))
        self.endpoint.handle(ApplicationRequest(service_id=2, payload=b"slot2", at_ms=20))
        # Slot 3 exceeds queue capacity: produces explicit queue_full protocol_rejection
        qf_evts = self.endpoint.handle(ApplicationRequest(service_id=2, payload=b"slot3", at_ms=20))
        qf_rej = next((e for e in qf_evts if isinstance(e, ApplicationEvent) and e.kind == "protocol_rejection"), None)
        self.assertIsNotNone(qf_rej)
        self.assertEqual(qf_rej.status, 4)
        self.assertEqual(qf_rej.payload, b"queue_full")

    def test_repeat_advance_never_re_emits_expiry_or_cancel(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        # Request with not_after_ms=30
        self.endpoint.handle(ApplicationRequest(service_id=2, payload=b"msg", at_ms=20, not_after_ms=30, exchange_id=88))

        # Advance past deadline at 35: expires exactly once
        adv1 = self.endpoint.handle(Advance(now_ms=35))
        rejs1 = [e for e in adv1 if isinstance(e, ApplicationEvent) and e.kind == "protocol_rejection"]
        self.assertEqual(len(rejs1), 1)

        # Later Advance calls MUST NOT repeat rejection or Cancel
        adv2 = self.endpoint.handle(Advance(now_ms=40))
        rejs2 = [e for e in adv2 if isinstance(e, ApplicationEvent) and e.kind == "protocol_rejection"]
        self.assertEqual(len(rejs2), 0)
        cancels2 = [e for e in adv2 if isinstance(e, Cancel)]
        self.assertEqual(len(cancels2), 0)

    def test_restart_fails_closed_on_missing_or_reused_entropy_and_rotates_epoch(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        initial_epoch = self.endpoint.local_epoch

        # Missing / short entropy fails closed
        with self.assertRaises(EventValidationError):
            self.endpoint.handle(Restart(at_ms=20, entropy=b""))
        with self.assertRaises(EventValidationError):
            self.endpoint.handle(Restart(at_ms=20, entropy=b"1234567"))

        # Valid restart rotates logical epoch
        self.endpoint.handle(Restart(at_ms=30, entropy=b"\x01\x02\x03\x04\x05\x06\x07\x08"))
        self.assertNotEqual(self.endpoint.local_epoch, initial_epoch)

        # Reused entropy fails closed
        with self.assertRaises(EventValidationError):
            self.endpoint.handle(Restart(at_ms=40, entropy=b"\x01\x02\x03\x04\x05\x06\x07\x08"))

    def test_restart_reports_unresolved_remote_outcomes_and_settles_borrows(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        # Request submitted and transmitted
        evts = self.endpoint.handle(ApplicationRequest(service_id=2, payload=b"unresolved", at_ms=20, exchange_id=77))
        sub = next(e for e in evts if isinstance(e, TxSubmit))
        self.endpoint.handle(TxAdmit(handle=sub.handle, generation=sub.generation, accepted=True, reason=None, at_ms=20))
        self.endpoint.handle(TxTerminal(handle=sub.handle, generation=sub.generation, outcome="possibly_transmitted", at_ms=25))

        # Restart with unresolved transmitted request in flight: reports diagnostic unknown
        rst_evts = self.endpoint.handle(Restart(at_ms=30, entropy=b"\xAA" * 16))
        diag = next((e for e in rst_evts if isinstance(e, ApplicationEvent) and e.kind == "diagnostic"), None)
        self.assertIsNotNone(diag)
        self.assertEqual(diag.payload, b"unknown")

    def test_fragmented_transfer_duplicate_slices_replay_cached_receipt_without_reopening(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.endpoint.handle(Receive(link=0, bytes=b"\x00", at_ms=12))

        # Two fragments of reliable DATA (service 2, total 20 bytes, chunk 10)
        ext_s2 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))
        f0 = CoreFrame(
            message_type=7, options=0x8B, sequence=50,
            fragment=Fragment(index=0, chunk_size=10, total_length=20),
            extensions=(ext_s2,), payload=b"0123456789",
        )
        f1 = CoreFrame(
            message_type=7, options=0x8B, sequence=50,
            fragment=Fragment(index=1, chunk_size=10, total_length=20),
            extensions=(ext_s2,), payload=b"ABCDEFGHIJ",
        )
        s0 = encode_stream_r(encode_frame(f0, max_frame=256), max_core=256, max_encoded=263)
        s1 = encode_stream_r(encode_frame(f1, max_frame=256), max_core=256, max_encoded=263)

        # Slice 0 in progress
        evts0 = self.endpoint.handle(Receive(link=0, bytes=s0, at_ms=20))
        self.assertEqual([e for e in evts0 if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"], [])

        # Slice 1 completes transfer
        evts1 = self.endpoint.handle(Receive(link=0, bytes=s1, at_ms=25))
        accepted1 = [e for e in evts1 if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]
        self.assertEqual(len(accepted1), 1)
        self.assertEqual(accepted1[0].payload, b"0123456789ABCDEFGHIJ")

        # Duplicate slice 0 arrives: must NOT reopen assembly, must replay cached ACK, must NOT re-emit request_accepted
        evts_dup = self.endpoint.handle(Receive(link=0, bytes=s0, at_ms=30))
        accepted_dup = [e for e in evts_dup if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]
        self.assertEqual(len(accepted_dup), 0)
        tx_subs_dup = [e for e in evts_dup if isinstance(e, TxSubmit)]
        self.assertEqual(len(tx_subs_dup), 1)  # Replays ACK!
        # Assembly manager did not reopen an active session
        self.assertNotIn((1, 20, 9, 50), self.endpoint.reassembly.active)

    def test_fragmented_result_retained_and_replayed_in_full(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.endpoint.handle(Receive(link=0, bytes=b"\x00", at_ms=12))

        # Request 100 bytes on service 2 (chunk_bytes=64 -> 2 RSP fragments)
        ext_s2 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))
        req = CoreFrame(message_type=0, options=0x83, sequence=25, extensions=(ext_s2,), payload=b"\x5A" * 100)
        req_stream = encode_stream_r(encode_frame(req, max_frame=256), max_core=256, max_encoded=263)

        # First request: generates 2 RSP frames
        evts1 = self.endpoint.handle(Receive(link=0, bytes=req_stream, at_ms=20))
        tx1 = [e for e in evts1 if isinstance(e, TxSubmit)]
        self.assertEqual(len(tx1), 2)  # Fragment 0 and Fragment 1!
        self._settle_active(21)

        # Duplicate request arrives: replays ALL frames of retained result (not only fragment 0)
        evts_dup = self.endpoint.handle(Receive(link=0, bytes=req_stream, at_ms=30))
        tx_dup = [e for e in evts_dup if isinstance(e, TxSubmit)]
        self.assertEqual(len(tx_dup), 2)  # Replays both fragments!
        self.assertEqual(tx1[0].bytes, tx_dup[0].bytes)
        self.assertEqual(tx1[1].bytes, tx_dup[1].bytes)

    def test_req_acceptance_preserved_after_result_release_and_conflicting_metadata_rejected(self):
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.endpoint.handle(Receive(link=0, bytes=b"\x00", at_ms=12))

        ext_s2 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))
        req = CoreFrame(message_type=0, options=0x83, sequence=33, extensions=(ext_s2,), payload=b"\x5A")
        req_stream = encode_stream_r(encode_frame(req, max_frame=256), max_core=256, max_encoded=263)

        # Initial execution
        self.endpoint.handle(Receive(link=0, bytes=req_stream, at_ms=20))
        sender_key = (1, 20, 9, 33)
        self.assertIn(sender_key, self.endpoint.delivery.accepted_messages)
        self.assertIn(sender_key, self.endpoint.delivery.retained_results)
        initial_exp = self.endpoint.delivery.accepted_messages[sender_key].expires_at_ms
        self._settle_active(21)

        # Duplicate traffic does not renew absolute retention
        self.endpoint.handle(Receive(link=0, bytes=req_stream, at_ms=50))
        self._settle_active(51)
        self.assertEqual(self.endpoint.delivery.accepted_messages[sender_key].expires_at_ms, initial_exp)

        # Release/purge retained result (simulate result cache expiry or release)
        del self.endpoint.delivery.retained_results[sender_key]
        self.endpoint.delivery.release_result_gate(sender_key)
        self.assertNotIn(sender_key, self.endpoint.delivery.retained_results)
        # But acceptance metadata is preserved in accepted_messages!
        self.assertIn(sender_key, self.endpoint.delivery.accepted_messages)
        self._settle_active(21)

        # Duplicate request arriving after result release does NOT re-run service effects
        evts_post_release = self.endpoint.handle(Receive(link=0, bytes=req_stream, at_ms=60))
        self.assertEqual([e for e in evts_post_release if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"], [])

        # Conflicting identity metadata (same SEQ 33 arrives with conflicting message_type=7 DATA) cannot become new acceptance
        conflict_data = CoreFrame(message_type=7, options=0x83, sequence=33, extensions=(ext_s2,), payload=b"\x5A")
        conflict_stream = encode_stream_r(encode_frame(conflict_data, max_frame=256), max_core=256, max_encoded=263)
        evts_conflict = self.endpoint.handle(Receive(link=0, bytes=conflict_stream, at_ms=70))
        self.assertEqual([e for e in evts_conflict if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"], [])

    def test_retained_result_expiry_replays_cached_receipt_ack_not_result_slice(self):
        """Accepted REQ duplicate gets complete result before cache expiry; after expiry gets only cached receipt ACK."""
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.endpoint.handle(Receive(link=0, bytes=b"\x00", at_ms=12))

        ext_s2 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))
        req = CoreFrame(message_type=0, options=0x83, sequence=51, extensions=(ext_s2,), payload=b"\x42")
        req_stream = encode_stream_r(encode_frame(req, max_frame=256), max_core=256, max_encoded=263)

        # 1. Initial request execution
        evts1 = self.endpoint.handle(Receive(link=0, bytes=req_stream, at_ms=20))
        sender_key = (1, 20, 9, 51)
        self.assertIn(sender_key, self.endpoint.delivery.accepted_messages)
        self.assertIn(sender_key, self.endpoint.delivery.retained_results)

        # Check RetainedResult next_retry_ms is initialized to now_ms + response_timeout_ms (never 0)
        res = self.endpoint.delivery.retained_results[sender_key]
        expected_retry = 20 + self.endpoint.delivery.response_timeout_ms
        self.assertEqual(res.next_retry_ms, expected_retry)

        # Check that AcceptedRecord.ack_frame_bytes is a distinct receipt ACK (type 6), not the RSP
        rec = self.endpoint.delivery.accepted_messages[sender_key]
        cached_ack_frame = parse_frame(rec.ack_frame_bytes)
        self.assertEqual(cached_ack_frame.message_type, 6)  # ACK, NOT RSP (1)!

        # 2. Duplicate while retained_results is active replays the complete result (RSP)
        evts_dup1 = self.endpoint.handle(Receive(link=0, bytes=req_stream, at_ms=30))
        tx_dup1 = next(e for e in evts_dup1 if isinstance(e, TxSubmit))
        core_dup1 = next(e.frame for e in self.endpoint.stream_r_decoder.feed(tx_dup1.bytes, at_ms=32) if e.kind == "frame")
        frame_dup1 = parse_frame(core_dup1)
        self.assertEqual(frame_dup1.message_type, 1)  # Replays RSP!
        self._settle_active(33)

        # 3. Simulate retained result expiry (purged from retained_results, but retained in accepted_messages)
        del self.endpoint.delivery.retained_results[sender_key]
        self.endpoint.delivery.release_result_gate(sender_key)
        self.assertNotIn(sender_key, self.endpoint.delivery.retained_results)
        self.assertIn(sender_key, self.endpoint.delivery.accepted_messages)

        # 4. Duplicate arriving AFTER retained result expiry replays ONLY the cached receipt ACK (type 6)
        evts_dup2 = self.endpoint.handle(Receive(link=0, bytes=req_stream, at_ms=40))
        tx_dup2 = next(e for e in evts_dup2 if isinstance(e, TxSubmit))
        core_dup2 = next(e.frame for e in self.endpoint.stream_r_decoder.feed(tx_dup2.bytes, at_ms=42) if e.kind == "frame")
        frame_dup2 = parse_frame(core_dup2)
        self.assertEqual(frame_dup2.message_type, 6)  # Replays cached receipt ACK, NOT RSP!
        # And verify no new request_accepted event
        self.assertEqual([e for e in evts_dup2 if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"], [])

    def test_tx_admit_non_expired_rejection_reaches_bounded_outcome(self):
        """Every TxAdmit rejection reaches a defined bounded outcome or retry; never leaves exchange permanently waiting."""
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.endpoint.handle(Receive(link=0, bytes=b"\x00", at_ms=12))

        # Enqueue outgoing request
        req = ApplicationRequest(service_id=2, payload=b"payload_data", at_ms=20, exchange_id=201)
        sub_evts = self.endpoint.handle(req)
        tx_sub = next(e for e in sub_evts if isinstance(e, TxSubmit))
        handle = tx_sub.handle
        gen = tx_sub.generation

        self.assertIn(201, self.endpoint.delivery.active_outgoing)
        self.assertIn((20, 2), self.endpoint.delivery.active_per_dest_service)

        # Adapter rejects with non-expired reason "mtu_exceeded"
        admit_evts = self.endpoint.handle(TxAdmit(handle=handle, generation=gen, accepted=False, reason="mtu_exceeded", at_ms=25))

        # 1. Exchange transitions to "failed" and is removed from active outgoing
        self.assertNotIn(201, self.endpoint.delivery.active_outgoing)
        # 2. Gate is released (not permanently blocked)
        self.assertNotIn((20, 2), self.endpoint.delivery.active_per_dest_service)
        # 3. Diagnostic event emitted with reason bytes
        diag = next((e for e in admit_evts if isinstance(e, ApplicationEvent) and e.kind == "diagnostic"), None)
        self.assertIsNotNone(diag)
        self.assertEqual(diag.payload, b"mtu_exceeded")
        self.assertEqual(diag.exchange_id, 201)

    def test_terminal_status_and_ack_req_validation(self):
        """Reject invalid terminal status/ACK_REQ combinations before exchange completion."""
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.endpoint.handle(Receive(link=0, bytes=b"\x00", at_ms=12))

        # Start an active exchange (service 2)
        req = ApplicationRequest(service_id=2, payload=b"test_payload", at_ms=20, exchange_id=301)
        sub_evts = self.endpoint.handle(req)
        tx_sub = next(e for e in sub_evts if isinstance(e, TxSubmit))
        self.endpoint.handle(TxAdmit(handle=tx_sub.handle, generation=tx_sub.generation, accepted=True, reason=None, at_ms=22))
        self.endpoint.handle(TxTerminal(handle=tx_sub.handle, generation=tx_sub.generation, outcome="transmitted", at_ms=23))

        exc = self.endpoint.delivery.active_outgoing[301]
        req_seq = exc.seq

        # Helper to build reply_to extension targeting the active request
        reply_to_bytes = bytearray()
        reply_to_bytes.extend(encode_uleb(1))  # ns
        reply_to_bytes.extend(encode_uleb(10))  # orig
        reply_to_bytes.extend((7).to_bytes(8, "little"))  # epoch
        reply_to_bytes.extend(encode_uleb(req_seq))  # seq
        ext_reply = Extension(extension_id=1, critical=True, unsafe=False, value=bytes(reply_to_bytes))
        ext_s2 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))

        # 1. Terminal RSP (status 0) WITHOUT ACK_REQ (options=0x81, missing bit 2) -> dropped, cannot complete
        rsp_no_ack_req = CoreFrame(message_type=1, options=0x81, sequence=91, extensions=(ext_reply, ext_s2), payload=b"data")
        evts1 = self.endpoint.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(rsp_no_ack_req)), at_ms=30))
        self.assertNotIn("request_result", [getattr(e, "kind", None) for e in evts1])
        self.assertIn(301, self.endpoint.delivery.active_outgoing)  # Exchange still active!

        # 2. Terminal ERR with invalid status range 8..63 (e.g., status 15) with ACK_REQ -> dropped, cannot complete
        ext_status15 = Extension(extension_id=5, critical=True, unsafe=False, value=encode_uleb(15))
        err_invalid_status = CoreFrame(message_type=2, options=0x83, sequence=92, extensions=(ext_reply, ext_s2, ext_status15), payload=b"")
        evts2 = self.endpoint.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(err_invalid_status)), at_ms=35))
        self.assertNotIn("request_result", [getattr(e, "kind", None) for e in evts2])
        self.assertIn(301, self.endpoint.delivery.active_outgoing)  # Exchange still active!

        # 3. Protocol rejection ERR (status 4) WITH ACK_REQ (must NOT have ACK_REQ) -> dropped, cannot complete
        ext_status4 = Extension(extension_id=5, critical=True, unsafe=False, value=encode_uleb(4))
        err_rej_with_ack_req = CoreFrame(message_type=2, options=0x83, sequence=93, extensions=(ext_reply, ext_s2, ext_status4), payload=b"")
        evts3 = self.endpoint.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(err_rej_with_ack_req)), at_ms=40))
        self.assertNotIn("protocol_rejection", [getattr(e, "kind", None) for e in evts3])
        self.assertIn(301, self.endpoint.delivery.active_outgoing)  # Exchange still active!

        # 4. Valid terminal RSP (status 0) WITH ACK_REQ (options=0x83) -> completes exchange successfully!
        rsp_valid = CoreFrame(message_type=1, options=0x83, sequence=94, extensions=(ext_reply, ext_s2), payload=b"ok_data")
        evts4 = self.endpoint.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(rsp_valid)), at_ms=45))
        self.assertIn("request_result", [getattr(e, "kind", None) for e in evts4])
        self.assertNotIn(301, self.endpoint.delivery.active_outgoing)  # Exchange completed!

    def test_service_without_enabled_handler_rejected_status_2(self):
        """Service registered in manifest or test_services without enabled handler is rejected before acceptance."""
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.endpoint.handle(Receive(link=0, bytes=b"\x00", at_ms=12))

        # Endpoint manifest has services 1 and 2. Send request with service_id 99 (unsupported)
        ext_s99 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(99))
        req_unsupported = CoreFrame(message_type=0, options=0x83, sequence=61, extensions=(ext_s99,), payload=b"\x01")
        evts = self.endpoint.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(req_unsupported)), at_ms=20))

        # Must NOT be accepted
        self.assertEqual([e for e in evts if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"], [])
        # Must be rejected with STATUS 2 ERR
        sender_key = (1, 20, 9, 61)
        self.assertIn(sender_key, self.endpoint.delivery.rejections)
        self.assertEqual(self.endpoint.delivery.rejections[sender_key].status, 2)

    def test_duplicate_req_and_data_conflicting_payload_dropped(self):
        """Duplicate DATA/REQ with conflicting payload bytes cannot reexecute and is dropped without replay."""
        self.endpoint.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        self.endpoint.handle(Receive(link=0, bytes=b"\x00", at_ms=12))

        ext_s2 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))

        # 1. Accepted REQ with payload A
        req_a = CoreFrame(message_type=0, options=0x83, sequence=71, extensions=(ext_s2,), payload=b"PAYLOAD_A")
        evts_req_a = self.endpoint.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(req_a)), at_ms=20))
        self.assertEqual(len([e for e in evts_req_a if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]), 1)

        # Duplicate REQ with conflicting payload B under same identity (sequence 71)
        req_b = CoreFrame(message_type=0, options=0x83, sequence=71, extensions=(ext_s2,), payload=b"PAYLOAD_B_CONFLICT")
        evts_req_b = self.endpoint.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(req_b)), at_ms=25))
        # Dropped: no re-execution, no duplicate result transmission
        self.assertEqual(len([e for e in evts_req_b if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]), 0)
        self.assertEqual(len([e for e in evts_req_b if isinstance(e, TxSubmit)]), 0)

        # 2. Accepted DATA with payload X
        data_x = CoreFrame(message_type=7, options=0x83, sequence=72, extensions=(ext_s2,), payload=b"DATA_X")
        evts_data_x = self.endpoint.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(data_x)), at_ms=30))
        self.assertEqual(len([e for e in evts_data_x if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]), 1)
        # Emitted ACK for initial DATA
        self.assertEqual(len([e for e in evts_data_x if isinstance(e, TxSubmit)]), 1)

        # Duplicate DATA with conflicting payload Y under same identity (sequence 72)
        data_y = CoreFrame(message_type=7, options=0x83, sequence=72, extensions=(ext_s2,), payload=b"DATA_Y_CONFLICT")
        evts_data_y = self.endpoint.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(data_y)), at_ms=35))
        # Dropped: no re-dispatch, no cached ACK transmission
        self.assertEqual(len([e for e in evts_data_y if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]), 0)
        self.assertEqual(len([e for e in evts_data_y if isinstance(e, TxSubmit)]), 0)


if __name__ == "__main__":
    unittest.main()
