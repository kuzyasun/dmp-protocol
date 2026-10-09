"""Tests for SAMPLE-1 reference application (docs/DMP_v2_Reference_Application.md A1-A4)."""

import struct
import unittest
from pathlib import Path

from dmp_peer.events import (
    Advance,
    ApplicationEvent,
    ApplicationRequest,
    Open,
    PublishSample,
    Receive,
    TxAdmit,
    TxSubmit,
    TxTerminal,
)
from dmp_peer.frame import CoreFrame, Extension, decode_uleb, encode_frame, encode_uleb, parse_frame
from dmp_peer.sample1 import Sample, SampleConsumer, SampleEpochError, SampleEpochStore, SampleProducer
from dmp_peer.stream_r import encode_stream_r
from dmp_peer.testing import PeerEndpoint


def _load_manifest_bytes(name: str = "direct-nnpsk0.json") -> bytes:
    path = Path(__file__).parents[3] / "profiles" / "deployments" / name
    return path.read_bytes()


class Sample1UnitTests(unittest.TestCase):
    def test_sample_schemas_and_canonical_byte_vectors_a3(self):
        # A3 canonical payload vectors
        # TELEM epoch=1, index=2, value=300:
        # 01 00 00 00 00 00 00 00 02 00 00 00 2C 01 00 00
        golden_telem = bytes.fromhex("01 00 00 00 00 00 00 00 02 00 00 00 2C 01 00 00")
        sample = Sample.decode_telemetry(golden_telem)
        self.assertEqual((sample.epoch, sample.index, sample.value), (1, 2, 300))
        self.assertEqual(sample.encode_telemetry(), golden_telem)

        # READ result for the same sample:
        # 01 01 00 00 00 00 00 00 00 02 00 00 00 2C 01 00 00
        golden_read_rsp = bytes.fromhex("01 01 00 00 00 00 00 00 00 02 00 00 00 2C 01 00 00")
        sample_from_rsp = Sample.decode_read_result(golden_read_rsp)
        self.assertEqual((sample_from_rsp.epoch, sample_from_rsp.index, sample_from_rsp.value), (1, 2, 300))
        self.assertEqual(sample_from_rsp.encode_read_result(), golden_read_rsp)

    def test_producer_epoch_persistence_and_failure(self):
        store = SampleEpochStore(initial_epoch=5)
        producer = SampleProducer(epoch_store=store)

        s1 = producer.publish(100)
        self.assertEqual((s1.epoch, s1.index, s1.value), (5, 1, 100))

        s2 = producer.publish(200)
        self.assertEqual((s2.epoch, s2.index, s2.value), (5, 2, 200))

        # Restart advances epoch atomically
        producer.restart()
        s3 = producer.publish(300)
        self.assertEqual((s3.epoch, s3.index, s3.value), (6, 1, 300))

        # Persistence failure stops publication
        store.set_failed(True)
        with self.assertRaises(SampleEpochError):
            producer.publish(400)

    def test_consumer_initialization_state_machine_a2(self):
        consumer = SampleConsumer()
        self.assertEqual(consumer.state, "unsynchronized")
        self.assertFalse(consumer.is_live)

        # Step 1: Discard telemetry while unsynchronized
        telem_payload = Sample(epoch=1, index=5, value=50).encode_telemetry()
        self.assertIsNone(consumer.handle_telemetry(telem_payload))
        self.assertFalse(consumer.is_live)

        # Step 2: Start init and designate request SEQ=42
        consumer.start_initialization(association_id=1)
        consumer.designate_read(request_seq=42)

        # Non-matching request seq cannot initialize
        rsp_unmatched = Sample(epoch=1, index=5, value=50).encode_read_result()
        res = consumer.handle_read_result(request_seq=99, payload=rsp_unmatched)
        self.assertFalse(res)
        self.assertFalse(consumer.is_live)

        # Matching designated READ RSP initializes!
        rsp_matched = Sample(epoch=1, index=5, value=50).encode_read_result()
        res = consumer.handle_read_result(request_seq=42, payload=rsp_matched)
        self.assertTrue(res)
        self.assertTrue(consumer.is_live)
        self.assertEqual(consumer.state, "synchronized")
        self.assertEqual(consumer.cached_sample.value, 50)

        # Step 3: Now live samples with higher index are accepted
        telem_newer = Sample(epoch=1, index=6, value=60).encode_telemetry()
        updated = consumer.handle_telemetry(telem_newer)
        self.assertIsNotNone(updated)
        self.assertEqual(updated.value, 60)

        # Stale index (index 6 or index 4) is ignored
        telem_stale = Sample(epoch=1, index=4, value=40).encode_telemetry()
        self.assertIsNone(consumer.handle_telemetry(telem_stale))
        self.assertEqual(consumer.cached_sample.value, 60)

        # Older READ result snapshot cannot roll back live sample
        consumer.handle_read_result(request_seq=42, payload=rsp_matched)
        self.assertEqual(consumer.cached_sample.value, 60)

    def test_consumer_rejects_stale_association_and_generation_results(self):
        consumer = SampleConsumer()
        gen = consumer.start_initialization(association_id=1)
        consumer.designate_read(request_seq=10)

        rsp_payload = Sample(epoch=1, index=1, value=123).encode_read_result()

        # Result from wrong association
        res_wrong_assoc = consumer.handle_read_result(
            request_seq=10, payload=rsp_payload, association_id=2, generation=gen
        )
        self.assertFalse(res_wrong_assoc)
        self.assertEqual(consumer.state, "unsynchronized")

        # Result from stale generation
        res_stale_gen = consumer.handle_read_result(
            request_seq=10, payload=rsp_payload, association_id=1, generation=gen - 1
        )
        self.assertFalse(res_stale_gen)
        self.assertEqual(consumer.state, "unsynchronized")

        # Valid correlated result synchronizes
        res_valid = consumer.handle_read_result(
            request_seq=10, payload=rsp_payload, association_id=1, generation=gen
        )
        self.assertTrue(res_valid)
        self.assertEqual(consumer.state, "synchronized")
        self.assertEqual(consumer.cached_sample.value, 123)

        # Once synchronized, subsequent/superseded result cannot mutate live cache
        rsp_other = Sample(epoch=1, index=2, value=456).encode_read_result()
        res_late = consumer.handle_read_result(
            request_seq=10, payload=rsp_other, association_id=1, generation=gen
        )
        self.assertFalse(res_late)
        self.assertEqual(consumer.cached_sample.value, 123)

    def test_consumer_max_attempts_exhaustion(self):
        consumer = SampleConsumer(max_attempts=2)
        consumer.start_initialization(association_id=1)

        # Attempt 1
        self.assertTrue(consumer.designate_read(request_seq=1))
        self.assertEqual(consumer.init_attempts, 1)

        # Attempt 2
        self.assertTrue(consumer.designate_read(request_seq=2))
        self.assertEqual(consumer.init_attempts, 2)

        # Attempt 3: exceeds max_attempts (2) -> fails
        self.assertFalse(consumer.designate_read(request_seq=3))
        self.assertIsNone(consumer.designated_request_seq)

    def test_producer_injected_persistence_backend(self):
        persisted = []

        def mock_persist(epoch):
            persisted.append(epoch)
            return True

        store = SampleEpochStore(initial_epoch=1, persist_fn=mock_persist)
        producer = SampleProducer(epoch_store=store)

        producer.restart()
        self.assertEqual(persisted, [2])
        self.assertEqual(store.current_epoch(), 2)

        # Backend failure stops store and producer
        def failing_persist(epoch):
            return False

        failing_store = SampleEpochStore(initial_epoch=5, persist_fn=failing_persist)
        failing_producer = SampleProducer(epoch_store=failing_store)

        with self.assertRaises(SampleEpochError):
            failing_producer.restart()
        self.assertTrue(failing_store.failed)

        with self.assertRaises(SampleEpochError):
            failing_producer.publish(999)

    def test_consumer_manifest_budget_and_deadline_orchestration(self):
        """SampleConsumer enforces manifest init_attempts budget and init_deadline_ms."""
        # direct-nnpsk0 has init_attempts=1, init_retry_ms=5, init_deadline_ms=12000
        consumer = SampleConsumer(max_attempts=1, init_retry_ms=5, init_deadline_ms=12000)
        gen = consumer.start_initialization(association_id=1, at_ms=100)
        self.assertEqual(consumer.state, "unsynchronized")
        self.assertFalse(consumer.is_live)

        # First attempt within budget succeeds
        self.assertTrue(consumer.designate_read(request_seq=1, at_ms=105))
        self.assertEqual(consumer.designated_request_seq, 1)
        self.assertEqual(consumer.init_attempts, 1)

        # NO_SAMPLE (terminal ERR=64) arrives
        consumer.handle_no_sample(request_seq=1, association_id=1, generation=gen)
        self.assertIsNone(consumer.designated_request_seq)
        self.assertEqual(consumer.state, "unsynchronized")

        # Retry attempt 2 exceeds max_attempts (1) -> rejected by attempt budget
        self.assertFalse(consumer.designate_read(request_seq=2, at_ms=115))
        self.assertIsNone(consumer.designated_request_seq)

        # Late result arriving for request 2 cannot synchronize
        rsp_payload = Sample(epoch=1, index=1, value=999).encode_read_result()
        res = consumer.handle_read_result(request_seq=2, payload=rsp_payload, association_id=1, generation=gen)
        self.assertFalse(res)
        self.assertEqual(consumer.state, "unsynchronized")
        self.assertFalse(consumer.is_live)
        self.assertIsNone(consumer.cached_sample)

        # Deadline test: new association with budget=3 but past deadline 12,000 ms
        consumer2 = SampleConsumer(max_attempts=3, init_retry_ms=5, init_deadline_ms=12000)
        consumer2.start_initialization(association_id=2, at_ms=0)
        self.assertFalse(consumer2.designate_read(request_seq=10, at_ms=12500))  # Past deadline
        self.assertIsNone(consumer2.designated_request_seq)


class Sample1EndpointIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.raw_manifest = _load_manifest_bytes()
        # Node 10 is producer, Node 20 is consumer
        self.producer = PeerEndpoint(
            manifest_bytes=self.raw_manifest,
            test_credentials={"node_id": 10, "epoch": 7, "remote_epoch": 9, "sample_epoch": 1},
            entropy_source=lambda n: bytes(n),
            test_services={},
            test_only_disable_sec1=True,
        )
        self.consumer = PeerEndpoint(
            manifest_bytes=self.raw_manifest,
            test_credentials={"node_id": 20, "epoch": 9, "remote_epoch": 7},
            entropy_source=lambda n: bytes(n),
            test_services={},
            test_only_disable_sec1=True,
        )
        # Open both
        p_open = self.producer.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        c_open = self.consumer.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        p_sync = next(e.bytes for e in p_open if isinstance(e, TxSubmit))
        c_sync = next(e.bytes for e in c_open if isinstance(e, TxSubmit))
        self.consumer.handle(Receive(link=0, bytes=p_sync, at_ms=12))
        self.producer.handle(Receive(link=0, bytes=c_sync, at_ms=12))

    def test_no_sample_returns_terminal_app_err_64(self):
        # Producer has no sample yet -> READ request (01) returns ERR STATUS=64
        req_frame = CoreFrame(message_type=0, options=0x03, sequence=10, payload=b"\x01")
        req_stream = encode_stream_r(encode_frame(req_frame, max_frame=256), max_core=256, max_encoded=263)

        events = self.producer.handle(Receive(link=0, bytes=req_stream, at_ms=20))
        tx_sub = next(e for e in events if isinstance(e, TxSubmit))

        # Decode response on consumer
        dec = self.consumer.stream_r_decoder.feed(tx_sub.bytes, at_ms=25)
        core = next(e.frame for e in dec if e.kind == "frame")
        frame = parse_frame(core)
        self.assertEqual(frame.message_type, 2)  # ERR
        self.assertEqual(frame.options & 2, 2)  # Reliable terminal result has ACK_REQ=1
        status_ext = next(ext for ext in frame.extensions if ext.extension_id == 5)
        status, _ = decode_uleb(status_ext.value)
        self.assertEqual(status, 64)  # NO_SAMPLE STATUS=64!
        self.assertEqual(frame.payload, b"")  # Empty payload!

    def test_read_and_status_after_sample_published(self):
        # Publish sample value=500
        self.producer.handle(PublishSample(value=500, at_ms=20))
        settle_at = 21
        for handle, sub in list(self.producer.active_submissions.items()):
            self.producer.handle(TxAdmit(handle, sub["generation"], True, None, settle_at))
            settle_at += 1
            self.producer.handle(TxTerminal(handle, sub["generation"], "transmitted", settle_at))
            settle_at += 1

        # READ request (01)
        req_read = CoreFrame(message_type=0, options=0x03, sequence=11, payload=b"\x01")
        req_stream = encode_stream_r(encode_frame(req_read, max_frame=256), max_core=256, max_encoded=263)
        events = self.producer.handle(Receive(link=0, bytes=req_stream, at_ms=30))
        tx_sub = next(e for e in events if isinstance(e, TxSubmit))

        dec = self.consumer.stream_r_decoder.feed(tx_sub.bytes, at_ms=35)
        core = next(e.frame for e in dec if e.kind == "frame")
        frame = parse_frame(core)
        self.assertEqual(frame.message_type, 1)  # RSP
        sample = Sample.decode_read_result(frame.payload)
        self.assertEqual(sample.value, 500)
        for handle, sub in list(self.producer.active_submissions.items()):
            if not sub["admitted"]:
                self.producer.handle(TxAdmit(handle, sub["generation"], True, None, 36))
            self.producer.handle(TxTerminal(handle, sub["generation"], "transmitted", 37))

        # Release the shared request/result stop-and-wait gate before STATUS.
        ack = self.consumer._build_ack_frame(
            (1, self.producer.local_node_id, self.producer.local_epoch, frame.sequence), 1
        )
        self.producer.handle(Receive(link=0, bytes=encode_stream_r(ack), at_ms=38))

        # STATUS request (02)
        req_status = CoreFrame(message_type=0, options=0x03, sequence=12, payload=b"\x02")
        req_status_stream = encode_stream_r(encode_frame(req_status, max_frame=256), max_core=256, max_encoded=263)
        events_status = self.producer.handle(Receive(link=0, bytes=req_status_stream, at_ms=40))
        tx_sub_st = next(e for e in events_status if isinstance(e, TxSubmit))
        dec_st = self.consumer.stream_r_decoder.feed(tx_sub_st.bytes, at_ms=45)
        core_st = next(e.frame for e in dec_st if e.kind == "frame")
        frame_st = parse_frame(core_st)
        self.assertEqual(frame_st.message_type, 1)  # RSP
        self.assertEqual(frame_st.payload, b"\x02\x01")  # opcode=2, ready=1

    def test_size_vs_shape_validation_order_a1(self):
        # A1: Configured message size check precedes application payload validation
        # In direct-nnpsk0 manifest, service 1 request_bytes is 1
        # Payload b"\x01\x00" (2 bytes): exceeds 1 byte -> STATUS=3 (not STATUS=7)!
        bad_req = CoreFrame(message_type=0, options=0x03, sequence=15, payload=b"\x01\x00")
        bad_stream = encode_stream_r(encode_frame(bad_req, max_frame=256), max_core=256, max_encoded=263)

        events = self.producer.handle(Receive(link=0, bytes=bad_stream, at_ms=50))
        tx_sub = next(e for e in events if isinstance(e, TxSubmit))
        dec = self.consumer.stream_r_decoder.feed(tx_sub.bytes, at_ms=55)
        core = next(e.frame for e in dec if e.kind == "frame")
        frame = parse_frame(core)
        self.assertEqual(frame.message_type, 2)  # ERR
        status_ext = next(ext for ext in frame.extensions if ext.extension_id == 5)
        status, _ = decode_uleb(status_ext.value)
        self.assertEqual(status, 3)  # STATUS=3: size check precedes opcode/shape!

    def test_sample1_response_validation_invalid_shapes_leave_exchange_eligible_for_retry(self):
        # Consumer issues READ request (01)
        req = ApplicationRequest(service_id=1, payload=b"\x01", at_ms=20, exchange_id=50)
        self.consumer.handle(req)
        self.assertIn(50, self.consumer.delivery.active_outgoing)
        exc = self.consumer.delivery.active_outgoing[50]
        req_seq = exc.seq

        # 1. Deliver malformed READ result: len != 17 (e.g. 5 bytes)
        reply_to = bytearray()
        reply_to.extend(encode_uleb(1))
        reply_to.extend(encode_uleb(20))
        reply_to.extend((9).to_bytes(8, "little"))
        reply_to.extend(encode_uleb(req_seq))
        exts = [Extension(extension_id=1, critical=True, unsafe=False, value=bytes(reply_to))]
        bad_len_rsp = CoreFrame(message_type=1, options=0x83, sequence=99, extensions=tuple(exts), payload=b"\x01\x02\x03\x04\x05")
        bad_stream = encode_stream_r(encode_frame(bad_len_rsp, max_frame=256), max_core=256, max_encoded=263)

        evts = self.consumer.handle(Receive(link=0, bytes=bad_stream, at_ms=30))
        # Must NOT emit request_result!
        self.assertEqual([e for e in evts if isinstance(e, ApplicationEvent) and e.kind == "request_result"], [])
        # Exchange remains active and eligible for retry/timeout
        self.assertIn(50, self.consumer.delivery.active_outgoing)
        # Consumer cache remains unmutated
        self.assertIsNone(self.consumer.sample_consumer.cached_sample)
        self.assertEqual(self.consumer.sample_consumer.state, "unsynchronized")

        # 2. Deliver wrong opcode result for READ request: opcode=2 (STATUS result) instead of opcode=1
        bad_opcode_rsp = CoreFrame(message_type=1, options=0x83, sequence=100, extensions=tuple(exts), payload=b"\x02\x01")
        bad_op_stream = encode_stream_r(encode_frame(bad_opcode_rsp, max_frame=256), max_core=256, max_encoded=263)
        evts_op = self.consumer.handle(Receive(link=0, bytes=bad_op_stream, at_ms=35))
        self.assertEqual([e for e in evts_op if isinstance(e, ApplicationEvent) and e.kind == "request_result"], [])
        self.assertIn(50, self.consumer.delivery.active_outgoing)
        self.assertIsNone(self.consumer.sample_consumer.cached_sample)

    def test_sample1_status_response_invalid_ready_byte_rejected(self):
        # Consumer issues STATUS request (02)
        req = ApplicationRequest(service_id=1, payload=b"\x02", at_ms=20, exchange_id=60)
        self.consumer.handle(req)
        self.assertIn(60, self.consumer.delivery.active_outgoing)
        exc = self.consumer.delivery.active_outgoing[60]
        req_seq = exc.seq

        # Deliver STATUS result with ready=2 (must be strictly 0 or 1 per A1)
        reply_to = bytearray()
        reply_to.extend(encode_uleb(1))
        reply_to.extend(encode_uleb(20))
        reply_to.extend((9).to_bytes(8, "little"))
        reply_to.extend(encode_uleb(req_seq))
        exts = [Extension(extension_id=1, critical=True, unsafe=False, value=bytes(reply_to))]
        bad_ready_rsp = CoreFrame(message_type=1, options=0x83, sequence=101, extensions=tuple(exts), payload=b"\x02\x02")
        bad_ready_stream = encode_stream_r(encode_frame(bad_ready_rsp, max_frame=256), max_core=256, max_encoded=263)

        evts = self.consumer.handle(Receive(link=0, bytes=bad_ready_stream, at_ms=30))
        self.assertEqual([e for e in evts if isinstance(e, ApplicationEvent) and e.kind == "request_result"], [])
        self.assertIn(60, self.consumer.delivery.active_outgoing)


if __name__ == "__main__":
    unittest.main()
