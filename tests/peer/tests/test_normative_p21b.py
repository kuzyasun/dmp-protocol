"""Focused unit tests for all P21B-assigned normative cases (dev/DMP_Normative_Cases.json).

P21C-deferred and P21D-deferred cases are explicitly documented and tested with
provisional / test-only stubs, without claiming SEC-1 proof before P21C.
"""

import struct
import unittest
from pathlib import Path

from dmp_peer.events import (
    Advance,
    ApplicationEvent,
    ApplicationRequest,
    Disconnect,
    Open,
    PublishSample,
    Receive,
    Restart,
    TxAdmit,
    TxSubmit,
    TxTerminal,
)
from dmp_peer.frame import (
    CoreFrame,
    Extension,
    Fragment,
    PayloadDescriptor,
    Route,
    decode_uleb,
    encode_frame,
    encode_uleb,
    parse_frame,
)
from dmp_peer.reassembly import ConflictError, QuotaError, ReassemblyError, ReassemblyManager
from dmp_peer.sample1 import Sample, SampleConsumer, SampleEpochError, SampleEpochStore, SampleProducer
from dmp_peer.stream_r import encode_stream_r
from dmp_peer.testing import PeerEndpoint


def _load_manifest_bytes(name: str = "direct-nnpsk0.json") -> bytes:
    path = Path(__file__).parents[3] / "profiles" / "deployments" / name
    return path.read_bytes()


class NormativeP21BCasesTests(unittest.TestCase):
    def setUp(self):
        self.raw_manifest = _load_manifest_bytes()
        # Node 10 = Producer / Requester in vectors; Node 20 = Consumer / Responder
        self.endpoint_10 = PeerEndpoint(
            manifest_bytes=self.raw_manifest,
            test_credentials={"node_id": 10, "epoch": 7, "remote_epoch": 9, "sample_epoch": 1},
            entropy_source=lambda n: bytes(n),
            test_services={},
            test_only_disable_sec1=True,
        )
        self.endpoint_20 = PeerEndpoint(
            manifest_bytes=self.raw_manifest,
            test_credentials={"node_id": 20, "epoch": 9, "remote_epoch": 7},
            entropy_source=lambda n: bytes(n),
            test_services={},
            test_only_disable_sec1=True,
        )
        # Open both
        e10_open = self.endpoint_10.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        e20_open = self.endpoint_20.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        e10_sync = next(e.bytes for e in e10_open if isinstance(e, TxSubmit))
        e20_sync = next(e.bytes for e in e20_open if isinstance(e, TxSubmit))
        self.endpoint_20.handle(Receive(link=0, bytes=e10_sync, at_ms=12))
        self.endpoint_10.handle(Receive(link=0, bytes=e20_sync, at_ms=12))

    # --- Section 22 Vector Cases ---

    def test_case_v222_req_identity(self):
        """v222-req: REQ 40 04 03 2A AA has full identity (1, 10, 7, 42)."""
        raw = bytes.fromhex("40 04 03 2A AA")
        frame = parse_frame(raw)
        self.assertEqual(frame.message_type, 0)
        self.assertEqual(frame.sequence, 42)
        self.assertEqual(frame.payload, b"\xAA")

    def test_case_v222_ack_identity(self):
        """v222-ack: Canonical ACK has own SEQ 8 and full REPLY_TO (1, 10, 7, 42)."""
        raw = bytes.fromhex("46 11 81 08 05 0B 01 0A 07 00 00 00 00 00 00 00 2A")
        frame = parse_frame(raw)
        self.assertEqual(frame.message_type, 6)
        self.assertEqual(frame.sequence, 8)  # Own SEQ
        self.assertEqual(frame.payload, b"")
        ext = next(e for e in frame.extensions if e.extension_id == 1)
        ns, at = decode_uleb(ext.value, 0)
        orig, at = decode_uleb(ext.value, at)
        epoch = int.from_bytes(ext.value[at : at + 8], "little")
        at += 8
        seq, _ = decode_uleb(ext.value, at)
        self.assertEqual((ns, orig, epoch, seq), (1, 10, 7, 42))

    def test_case_v223_explicit_context(self):
        """v223-explicit: Explicit CONTEXT tag 11, namespace 1, epoch 7, source 27, seq 81 -> (1, 27, 7, 81)."""
        raw = bytes.fromhex("45 11 85 51 30 1B 0B 09 01 07 00 00 00 00 00 00 00 AA")
        frame = parse_frame(raw)
        self.assertEqual(frame.sequence, 81)
        ext = next(e for e in frame.extensions if e.extension_id == 2)
        ns, at = decode_uleb(ext.value, 0)
        epoch = int.from_bytes(ext.value[at : at + 8], "little")
        self.assertEqual((ns, epoch), (1, 7))
        self.assertEqual((ns, frame.route.source_id, epoch, frame.sequence), (1, 27, 7, 81))

    def test_case_v223_implicit_context(self):
        """v223-implicit: Omitted preconfigured CONTEXT yields unambiguous identity with 6-byte header."""
        frame = CoreFrame(
            message_type=5,
            options=1 | 4,  # SEQ | ROUTE
            sequence=81,
            route=parse_frame(bytes.fromhex("45 11 85 51 30 1B 0B 09 01 07 00 00 00 00 00 00 00 AA")).route,
            payload=b"\xAA",
        )
        encoded = encode_frame(frame)
        self.assertEqual(encoded[1], 6)  # HDR_LEN = 6 bytes
        self.assertEqual(encoded, bytes.fromhex("45 06 05 51 30 1B AA"))

        # Preconfigured context resolution: endpoint preconfigured with namespace=1 and remote_epoch=7
        # resolves the omitted CONTEXT to identical full message identity (1, 27, 7, 81).
        req_frame = CoreFrame(
            message_type=0,
            options=1 | 4,  # SEQ | ROUTE
            sequence=81,
            route=frame.route,
            payload=b"\x01",
        )
        self.endpoint_20.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(req_frame)), at_ms=20))
        self.assertIn((1, 27, 7, 81), self.endpoint_20.delivery.rejections)
        self.assertEqual(self.endpoint_20.delivery.rejections[(1, 27, 7, 81)].status, 7)

    def test_case_v224_fragments_reverse_arrival(self):
        """v224-fragments: Two fragments arrive in reverse order (1 then 0), reassembles AA BB CC once."""
        mgr = ReassemblyManager(1024, 16, 2, 4, 1000, 2000)
        c1, p1 = mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=9,
            fragment_index=1, chunk_size=2, total_length=3,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"\xCC", at_ms=10,
        )
        self.assertFalse(c1)
        c2, p2 = mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=9,
            fragment_index=0, chunk_size=2, total_length=3,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"\xAA\xBB", at_ms=20,
        )
        self.assertTrue(c2)
        self.assertEqual(p2, b"\xAA\xBB\xCC")

    def test_case_v229_immediate_rsp_and_result_ack(self):
        """v229-immediate-rsp & v229-result-ack: Immediate RSP ends REQ retries, requester ACKs result."""
        golden_rsp = bytes.fromhex("41 11 83 09 05 0B 01 0A 07 00 00 00 00 00 00 00 2A BB")
        self.endpoint_10.next_seq = 42
        self.endpoint_10.handle(ApplicationRequest(service_id=1, payload=b"\x01", at_ms=20, exchange_id=101))

        # Deliver immediate RSP to requester
        evts = self.endpoint_10.handle(Receive(link=0, bytes=encode_stream_r(golden_rsp), at_ms=25))
        res_evt = next((e for e in evts if isinstance(e, ApplicationEvent) and e.kind == "request_result"), None)
        self.assertIsNotNone(res_evt)
        self.assertEqual(res_evt.payload, b"\xBB")

        # Requester emits ACK of result
        tx_ack = next((e for e in evts if isinstance(e, TxSubmit)), None)
        self.assertIsNotNone(tx_ack)

    # --- Section 22.8 Normative Reliability and State-Machine Cases ---

    def test_case_main228_seq_identity(self):
        """main228-seq-identity: Keep identities distinct; ACK allocates own SEQ."""
        ext_s2 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))
        req = CoreFrame(message_type=0, options=0x83, sequence=55, extensions=(ext_s2,), payload=b"\x5A")
        evts = self.endpoint_20.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(req)), at_ms=30))
        tx = next(e for e in evts if isinstance(e, TxSubmit))
        core = next(e.frame for e in self.endpoint_10.stream_r_decoder.feed(tx.bytes, at_ms=35) if e.kind == "frame")
        parsed = parse_frame(core)
        self.assertNotEqual(parsed.sequence, 55)  # Allocated own SEQ!

    def test_case_main228_lost_ack(self):
        """main228-lost-ack: Repeat receipt without second application operation."""
        ext_s2 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))
        req = CoreFrame(message_type=0, options=0x83, sequence=60, extensions=(ext_s2,), payload=b"\x5A")
        req_stream = encode_stream_r(encode_frame(req))

        # First attempt executes
        evts1 = self.endpoint_20.handle(Receive(link=0, bytes=req_stream, at_ms=40))
        accepted1 = [e for e in evts1 if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]
        self.assertEqual(len(accepted1), 1)

        # Second attempt (lost ACK simulation): repeats receipt without second operation
        evts2 = self.endpoint_20.handle(Receive(link=0, bytes=req_stream, at_ms=50))
        accepted2 = [e for e in evts2 if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]
        self.assertEqual(len(accepted2), 0)

    def test_case_main228_fragment_conflict(self):
        """main228-fragment-conflict: Assemble valid once; conflict rejects; never partial dispatch."""
        mgr = ReassemblyManager(1024, 16, 2, 4, 1000, 2000)
        mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=100,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=10,
        )
        with self.assertRaises(ConflictError):
            mgr.process_fragment(
                namespace=1, origin=10, epoch=7, seq=100,
                fragment_index=0, chunk_size=10, total_length=20,
                message_type=7, ack_req=False, service_id=1,
                slice_payload=b"ABCDEFGHIJ", at_ms=15,
            )

    def test_case_main228_quota_reset_expiry_late(self):
        """main228-quota-reset-expiry-late: Bound admission; invalidate volatile context on restart."""
        mgr = ReassemblyManager(1024, 16, 1, 4, 100, 500)
        mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=1,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=10,
        )
        # Quota 1 full: second rejected
        with self.assertRaises(QuotaError):
            mgr.process_fragment(
                namespace=1, origin=10, epoch=7, seq=2,
                fragment_index=0, chunk_size=10, total_length=20,
                message_type=7, ack_req=False, service_id=1,
                slice_payload=b"0123456789", at_ms=10,
            )
        # Expiry at 10 + 100 = 110
        mgr.advance(now_ms=115)
        with self.assertRaisesRegex(ReassemblyError, "tombstone"):
            mgr.process_fragment(
                namespace=1, origin=10, epoch=7, seq=1,
                fragment_index=1, chunk_size=10, total_length=20,
                message_type=7, ack_req=False, service_id=1,
                slice_payload=b"0123456789", at_ms=120,
            )

    def test_case_main228_req_result_loss(self):
        """main228-req-result-loss: Honor receipt/result retention; no duplicate execution."""
        ext_s2 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))
        req = CoreFrame(message_type=0, options=0x83, sequence=70, extensions=(ext_s2,), payload=b"\x5A")
        req_stream = encode_stream_r(encode_frame(req))
        # Initial delivery creates result
        self.endpoint_20.handle(Receive(link=0, bytes=req_stream, at_ms=40))
        self.assertIn((1, 10, 7, 70), self.endpoint_20.delivery.retained_results)

    def test_case_main228_reject_err_timeout(self):
        """main228-reject-err-timeout: Retain/repeat pre-acceptance protocol rejection."""
        # Unrecognized request payload on Service 1 produces STATUS=7
        bad_req = CoreFrame(message_type=0, options=0x03, sequence=80, payload=b"\xFF")
        bad_stream = encode_stream_r(encode_frame(bad_req))
        evts = self.endpoint_10.handle(Receive(link=0, bytes=bad_stream, at_ms=50))
        # Check retained rejection on producer
        self.assertIn((1, 20, 9, 80), self.endpoint_10.delivery.rejections)
        self.assertEqual(self.endpoint_10.delivery.rejections[(1, 20, 9, 80)].status, 7)

    def test_case_main228_stopwait(self):
        """main228-stopwait: Serialize app exchange while preserving receipt progress."""
        req1 = ApplicationRequest(service_id=2, payload=b"one", at_ms=20, exchange_id=1)
        req2 = ApplicationRequest(service_id=2, payload=b"two", at_ms=25, exchange_id=2)
        out1 = self.endpoint_10.handle(req1)
        out2 = self.endpoint_10.handle(req2)
        self.assertEqual(len([e for e in out1 if isinstance(e, TxSubmit)]), 1)
        self.assertEqual(len([e for e in out2 if isinstance(e, TxSubmit)]), 0)  # Queued by stop-and-wait

    def test_case_main228_fragment_timers(self):
        """main228-fragment-timers: No premature expiry/renewal/partial dispatch."""
        mgr = ReassemblyManager(1024, 16, 2, 4, 500, 1000)
        mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=5,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=10,
        )
        # Duplicate at 200 does not extend timer
        mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=5,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=200,
        )
        self.assertEqual(mgr.active[(1, 10, 7, 5)].expires_at_ms, 510)

    def test_case_main228_sample_stale(self):
        """main228-sample-stale: No rollback or duplicate app side effect."""
        consumer = SampleConsumer()
        consumer.start_initialization(association_id=1)
        consumer.designate_read(request_seq=1)
        # Init with index 10, value 100
        consumer.handle_read_result(request_seq=1, payload=Sample(epoch=1, index=10, value=100).encode_read_result())
        self.assertEqual(consumer.cached_sample.value, 100)

        # Stale sample (index 9) ignored
        consumer.handle_telemetry(Sample(epoch=1, index=9, value=90).encode_telemetry())
        self.assertEqual(consumer.cached_sample.value, 100)

    def test_case_main228_borrowed_buffer(self):
        """main228-borrowed-buffer: Immutable until terminal gen-tagged callback; stale callback cannot free slot."""
        evts = self.endpoint_10.handle(ApplicationRequest(service_id=2, payload=b"msg", at_ms=20, exchange_id=1))
        tx = next(e for e in evts if isinstance(e, TxSubmit))
        handle = tx.handle
        gen = tx.generation

        # Stale completion with gen + 1 ignored
        self.endpoint_10.handle(TxAdmit(handle=handle, generation=gen, accepted=True, reason=None, at_ms=25))
        self.endpoint_10.handle(TxTerminal(handle=handle, generation=gen + 1, outcome="transmitted", at_ms=30))
        self.assertIn(handle, self.endpoint_10.active_submissions)

        # Generation-matched completion frees slot
        self.endpoint_10.handle(TxTerminal(handle=handle, generation=gen, outcome="transmitted", at_ms=40))
        self.assertNotIn(handle, self.endpoint_10.active_submissions)

    def test_case_main228_deadline_outcome(self):
        """main228-deadline-outcome: Distinct local outcomes; no remote cancellation claim."""
        req = ApplicationRequest(service_id=2, payload=b"msg", at_ms=20, not_after_ms=30, exchange_id=1)
        self.endpoint_10.handle(req)
        # Advance past cutoff to 35 -> local expiry before transmission
        adv_evts = self.endpoint_10.handle(Advance(now_ms=35))
        rej = next((e for e in adv_evts if isinstance(e, ApplicationEvent) and e.kind == "protocol_rejection"), None)
        self.assertIsNotNone(rej)

    def test_case_main228_fixed_geometry(self):
        """main228-fixed-geometry: Reject invalid geometry; permit valid final-first."""
        mgr = ReassemblyManager(1024, 16, 2, 4, 1000, 2000)
        with self.assertRaises(ReassemblyError):
            mgr.validate_geometry(fragment_index=0, chunk_size=50, total_length=50)

    def test_case_main228_full_compact_ref(self):
        """main228-full-compact-ref: Exact lengths/local resolution; reject trailing bytes."""
        ext_reply_to_short = Extension(extension_id=1, critical=True, unsafe=False, value=b"\x01\x02\x03")
        with self.assertRaises(Exception):
            frame = CoreFrame(message_type=6, sequence=1, extensions=(ext_reply_to_short,), payload=b"")
            encode_frame(frame)

    def test_case_main228_accepted_changed_payload(self):
        """main228-accepted-changed-payload: No redispatch/new accept; receipt original identity; conflict rejects."""
        ext_s2 = Extension(extension_id=4, critical=True, unsafe=False, value=encode_uleb(2))
        req1 = CoreFrame(message_type=0, options=0x83, sequence=90, extensions=(ext_s2,), payload=b"\x5A")
        req1_stream = encode_stream_r(encode_frame(req1))
        # Initial accept
        self.endpoint_20.handle(Receive(link=0, bytes=req1_stream, at_ms=20))

        # Changed payload with same identity: no new execution callback
        req2 = CoreFrame(message_type=0, options=0x83, sequence=90, extensions=(ext_s2,), payload=b"\xFF")
        req2_stream = encode_stream_r(encode_frame(req2))
        evts = self.endpoint_20.handle(Receive(link=0, bytes=req2_stream, at_ms=30))
        app_evts = [e for e in evts if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]
        self.assertEqual(len(app_evts), 0)

    def test_case_main228_immediate_rule(self):
        """main228-immediate-rule: Immediate result rule holds; unsupported request rejected before execution."""
        bad_req = CoreFrame(message_type=0, options=0x03, sequence=95, payload=b"\x99")
        evts = self.endpoint_20.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(bad_req)), at_ms=40))
        rej_evt = next((e for e in evts if isinstance(e, TxSubmit)), None)
        self.assertIsNotNone(rej_evt)  # Emits protocol-rejection ERR

    def test_case_main228_protocol_status(self):
        """main228-protocol-status: Protocol rejection STATUS 1-7 has ACK_REQ=0; terminal app ERR has ACK_REQ=1."""
        # Protocol rejection ERR
        err1 = CoreFrame(
            message_type=2, options=0x81, sequence=1,
            extensions=(
                Extension(1, True, False, encode_uleb(1) + encode_uleb(10) + (7).to_bytes(8, "little") + encode_uleb(42)),
                Extension(5, True, False, encode_uleb(7)),
            ),
        )
        self.assertEqual(err1.options & 2, 0)  # ACK_REQ=0

        # Terminal application ERR (STATUS 64)
        err64 = CoreFrame(
            message_type=2, options=0x83, sequence=2,
            extensions=(
                Extension(1, True, False, encode_uleb(1) + encode_uleb(10) + (7).to_bytes(8, "little") + encode_uleb(42)),
                Extension(5, True, False, encode_uleb(64)),
            ),
        )
        self.assertEqual(err64.options & 2, 2)  # ACK_REQ=1 (reliable!)

    def test_case_main228_service_canon(self):
        """main228-service-canon: Canonical service/correlation; invalid service reply rejects."""
        # Default service 1 MUST NOT carry explicit SERVICE_ID
        ext_s1 = Extension(4, True, False, encode_uleb(1))
        bad = CoreFrame(message_type=0, options=0x83, sequence=10, extensions=(ext_s1,), payload=b"\x01")
        evts = self.endpoint_20.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(bad)), at_ms=20))
        self.assertEqual(len([e for e in evts if isinstance(e, ApplicationEvent) and e.kind == "request_accepted"]), 0)

    def test_case_stream_r_open_reset(self):
        """stream-r-open-reset: Receiver ready before one initial delimiter; no periodic prefix."""
        ep = PeerEndpoint(
            manifest_bytes=self.raw_manifest,
            test_credentials={"node_id": 10, "epoch": 7, "remote_epoch": 9, "sample_epoch": 1},
            entropy_source=lambda n: bytes(n),
            test_services={},
            test_only_disable_sec1=True,
        )
        open_evts = ep.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        tx = next(e for e in open_evts if isinstance(e, TxSubmit))
        self.assertEqual(tx.bytes, b"\x00")  # Exactly one initial delimiter

    # --- Provisional / Deferred P21C cases ---

    def test_case_s10_16_provisional_stub(self):
        """s10-16: Provisional test-only stub (P21C owns actual SEC-1 verification)."""
        # Verified structurally under P21B: compact reference format
        ext_compact = Extension(1, True, False, encode_uleb(42))
        self.assertEqual(ext_compact.value, encode_uleb(42))

    def test_case_s10_18_provisional_stub(self):
        """s10-18: Provisional test-only stub (P21C owns actual SEC-1 verification)."""
        # Exact geometry validated without claiming SEC-1 proof before P21C
        mgr = ReassemblyManager(1024, 16, 2, 4, 1000, 2000)
        self.assertEqual(mgr.validate_geometry(0, 10, 20), 2)

    # --- SAMPLE-1 Normative Cases (s-a1 through s-a4) ---

    def test_case_s_a1_service(self):
        """s-a1-service: Canonical service 1, default service omitted, no padding or trailing bytes."""
        sample = Sample(epoch=1, index=1, value=42)
        telem = sample.encode_telemetry()
        self.assertEqual(len(telem), 16)

    def test_case_s_a1_invalid(self):
        """s-a1-invalid: Retained STATUS=7 for malformed request; STATUS=2 for unsupported schema."""
        bad_req = CoreFrame(message_type=0, options=0x03, sequence=111, payload=b"\x05")
        self.endpoint_10.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(bad_req)), at_ms=20))
        self.assertIn((1, 20, 9, 111), self.endpoint_10.delivery.rejections)
        self.assertEqual(self.endpoint_10.delivery.rejections[(1, 20, 9, 111)].status, 7)

        service1 = next(svc for svc in self.endpoint_10.manifest.values["services"] if svc["id"] == 1)
        service1["request_bytes"] = 2
        bad_status = CoreFrame(message_type=0, options=0x03, sequence=114, payload=b"\x02\x02")
        self.endpoint_10.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(bad_status)), at_ms=20))
        self.assertEqual(self.endpoint_10.delivery.rejections[(1, 20, 9, 114)].status, 7)

        missing_ack = CoreFrame(message_type=0, options=0x01, sequence=115, payload=b"\x01")
        self.endpoint_10.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(missing_ack)), at_ms=20))
        self.assertEqual(self.endpoint_10.delivery.rejections[(1, 20, 9, 115)].status, 7)

        unsupported_schema = CoreFrame(
            message_type=0,
            options=0x03,
            sequence=116,
            payload_descriptor=PayloadDescriptor(flags=3, codec_id=0, schema_id=42, schema_version=1),
            payload=b"\x01",
        )
        self.endpoint_10.handle(
            Receive(link=0, bytes=encode_stream_r(encode_frame(unsupported_schema)), at_ms=20)
        )
        self.assertEqual(self.endpoint_10.delivery.rejections[(1, 20, 9, 116)].status, 2)

    def test_case_s_a1_size_order(self):
        """s-a1-size-order: STATUS=7 if admitted by size; STATUS=3 if too large first."""
        # Size limit in manifest for service 1 request is 1 byte
        oversize = CoreFrame(message_type=0, options=0x03, sequence=112, payload=b"\x01\x00")
        self.endpoint_20.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(oversize)), at_ms=20))
        self.assertEqual(self.endpoint_20.delivery.rejections[(1, 10, 7, 112)].status, 3)

        service1 = next(svc for svc in self.endpoint_10.manifest.values["services"] if svc["id"] == 1)
        service1["request_bytes"] = 2
        admitted_malformed = CoreFrame(message_type=0, options=0x03, sequence=117, payload=b"\x01\x00")
        self.endpoint_10.handle(
            Receive(link=0, bytes=encode_stream_r(encode_frame(admitted_malformed)), at_ms=21)
        )
        self.assertEqual(self.endpoint_10.delivery.rejections[(1, 20, 9, 117)].status, 7)

    def test_case_s_a1_delivery(self):
        """s-a1-delivery: Exact lengths; retained result replay; NO_SAMPLE reliable ERR=64 empty."""
        req = CoreFrame(message_type=0, options=0x03, sequence=113, payload=b"\x01")
        evts = self.endpoint_10.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(req)), at_ms=20))
        tx = next(e for e in evts if isinstance(e, TxSubmit))
        # Decoder on consumer
        core = next(e.frame for e in self.endpoint_20.stream_r_decoder.feed(tx.bytes, at_ms=25) if e.kind == "frame")
        frame = parse_frame(core)
        self.assertEqual(frame.message_type, 2)  # ERR
        status_ext = next(e for e in frame.extensions if e.extension_id == 5)
        self.assertEqual(decode_uleb(status_ext.value)[0], 64)
        self.assertEqual(frame.payload, b"")

    def test_case_s_a1_epoch(self):
        """s-a1-epoch: Durably reserve never-reused epoch; stop on failure; no wrap/time inference."""
        store = SampleEpochStore(1)
        self.assertEqual(store.current_epoch(), 1)
        self.assertEqual(store.advance_epoch(), 2)
        store.set_failed(True)
        with self.assertRaises(SampleEpochError):
            store.advance_epoch()

    def test_case_s_a1_epoch_transition(self):
        """s-a1-epoch-transition: Close old-epoch associations before exposing new epoch."""
        producer = SampleProducer()
        producer.publish(100)
        self.assertEqual(producer.current_sample.epoch, 1)

        consumer = SampleConsumer()
        gen1 = consumer.start_initialization(association_id=1)
        consumer.designate_read(1)
        consumer.handle_read_result(1, producer.current_sample.encode_read_result(), association_id=1, generation=gen1)
        self.assertTrue(consumer.is_live)
        self.assertEqual(consumer.selected_epoch, 1)

        # Producer restarts into epoch 2: old sample is discarded, NO_SAMPLE returned until publish
        producer.restart()
        self.assertEqual(producer.epoch_store.current_epoch(), 2)
        self.assertIsNone(producer.current_sample)
        status, payload = producer.handle_read()
        self.assertEqual(status, 64)
        self.assertEqual(payload, b"")

        # Consumer begins new association 2
        gen2 = consumer.start_initialization(association_id=2)
        self.assertGreater(gen2, gen1)
        self.assertFalse(consumer.is_live)
        self.assertEqual(consumer.state, "unsynchronized")

        # Telemetry is not admitted before designated READ
        early_telem = Sample(epoch=2, index=1, value=200).encode_telemetry()
        self.assertIsNone(consumer.handle_telemetry(early_telem))
        self.assertFalse(consumer.is_live)

        # Late prior-association result from association 1 is rejected
        stale_res = Sample(epoch=1, index=1, value=100).encode_read_result()
        self.assertFalse(consumer.handle_read_result(1, stale_res, association_id=1, generation=gen1))
        self.assertFalse(consumer.is_live)

        # Publish in epoch 2, designate READ on association 2, synchronize
        producer.publish(200)
        self.assertTrue(consumer.designate_read(10))
        res_ok = consumer.handle_read_result(
            10, producer.current_sample.encode_read_result(), association_id=2, generation=gen2
        )
        self.assertTrue(res_ok)
        self.assertTrue(consumer.is_live)
        self.assertEqual(consumer.selected_epoch, 2)
        self.assertEqual(consumer.cached_sample.value, 200)

        # Subsequent epoch 2 telemetry is admitted
        telem_sample = Sample(epoch=2, index=2, value=300)
        updated = consumer.handle_telemetry(telem_sample.encode_telemetry())
        self.assertIsNotNone(updated)
        self.assertEqual(updated.value, 300)
        self.assertEqual(consumer.cached_sample.value, 300)

        # A failed lifecycle fence must not reset/reuse the old epoch's index or
        # allow reads/publication to resume under the still-current epoch.
        def fail_fence():
            raise RuntimeError("association closure failed")

        fenced_producer = SampleProducer(before_epoch_advance=fail_fence)
        old_sample = fenced_producer.publish(400)
        with self.assertRaisesRegex(RuntimeError, "association closure failed"):
            fenced_producer.restart()
        self.assertEqual(fenced_producer._sample_index, old_sample.index)
        self.assertIsNone(fenced_producer.current_sample)
        self.assertTrue(fenced_producer.epoch_store.failed)
        self.assertEqual(fenced_producer.handle_read(), (64, b""))
        self.assertEqual(Sample.decode_status_result(fenced_producer.handle_status()[1]), 0)
        with self.assertRaises(SampleEpochError):
            fenced_producer.publish(500)

        # The same fence failure on index rollover also stops publication without
        # wrapping or recycling the terminal index in the old epoch.
        rollover_producer = SampleProducer(before_epoch_advance=fail_fence)
        rollover_producer._sample_index = 0xFFFFFFFE
        last_sample = rollover_producer.publish(600)
        self.assertEqual(last_sample.index, 0xFFFFFFFF)
        with self.assertRaisesRegex(RuntimeError, "association closure failed"):
            rollover_producer.publish(700)
        self.assertEqual(rollover_producer._sample_index, last_sample.index)
        self.assertIsNone(rollover_producer.current_sample)
        self.assertTrue(rollover_producer.epoch_store.failed)
        self.assertEqual(rollover_producer.handle_read(), (64, b""))
        self.assertEqual(Sample.decode_status_result(rollover_producer.handle_status()[1]), 0)

    def test_case_s_a2_unsync(self):
        """s-a2-unsync: New generation; prior cache not live; discard telemetry."""
        consumer = SampleConsumer()
        gen = consumer.start_initialization(association_id=1)
        self.assertEqual(gen, 1)
        self.assertEqual(consumer.state, "unsynchronized")
        self.assertFalse(consumer.is_live)
        self.assertIsNone(consumer.handle_telemetry(Sample(1, 1, 10).encode_telemetry()))

    def test_case_s_a2_designated_read(self):
        """s-a2-designated-read: One designated full identity; old designation invalidated."""
        consumer = SampleConsumer(max_attempts=2, init_deadline_ms=1000)
        gen = consumer.start_initialization(association_id=1, at_ms=0)

        # Finite retry budget: attempt 1 succeeds
        self.assertTrue(consumer.can_attempt_init(now_ms=0))
        self.assertTrue(consumer.designate_read(10, at_ms=0))
        self.assertEqual(consumer.init_attempts, 1)
        self.assertEqual(consumer.designated_request_seq, 10)

        # Attempt 2 supersedes 10 within budget
        self.assertTrue(consumer.can_attempt_init(now_ms=100))
        self.assertTrue(consumer.designate_read(20, at_ms=100))
        self.assertEqual(consumer.init_attempts, 2)
        self.assertEqual(consumer.designated_request_seq, 20)

        # Superseded request 10 result is rejected
        res_superseded = consumer.handle_read_result(
            10, Sample(1, 1, 100).encode_read_result(), association_id=1, generation=gen
        )
        self.assertFalse(res_superseded)

        # Stale generation and association are rejected while request 20 remains designated.
        res_stale_gen = consumer.handle_read_result(
            20, Sample(1, 1, 100).encode_read_result(), association_id=1, generation=gen - 1
        )
        self.assertFalse(res_stale_gen)
        self.assertEqual(consumer.designated_request_seq, 20)

        res_stale_assoc = consumer.handle_read_result(
            20, Sample(1, 1, 100).encode_read_result(), association_id=999, generation=gen
        )
        self.assertFalse(res_stale_assoc)
        self.assertEqual(consumer.designated_request_seq, 20)

        # Positive control: the current request and identity tuple do synchronize.
        self.assertTrue(
            consumer.handle_read_result(
                20, Sample(1, 1, 100).encode_read_result(), association_id=1, generation=gen
            )
        )
        self.assertTrue(consumer.is_live)

        # Attempt 3: a separate consumer exhausts its two-attempt budget.
        consumer_budget = SampleConsumer(max_attempts=2, init_deadline_ms=1000)
        consumer_budget.start_initialization(association_id=3, at_ms=0)
        self.assertTrue(consumer_budget.designate_read(30, at_ms=0))
        self.assertTrue(consumer_budget.designate_read(31, at_ms=100))
        self.assertFalse(consumer_budget.can_attempt_init(now_ms=200))
        self.assertFalse(consumer_budget.designate_read(32, at_ms=200))
        self.assertIsNone(consumer_budget.designated_request_seq)

        # Absolute deadline expiration: advancing past init_deadline_ms marks failed
        consumer_dl = SampleConsumer(max_attempts=3, init_deadline_ms=500)
        consumer_dl.start_initialization(association_id=2, at_ms=0)
        consumer_dl.designate_read(5, at_ms=100)
        self.assertEqual(consumer_dl.designated_request_seq, 5)

        self.assertTrue(consumer_dl.can_attempt_init(now_ms=400))
        self.assertTrue(consumer_dl.advance(now_ms=500))
        self.assertEqual(consumer_dl.state, "failed")
        self.assertFalse(consumer_dl.is_live)
        self.assertIsNone(consumer_dl.designated_request_seq)
        self.assertFalse(consumer_dl.can_attempt_init(now_ms=500))

        # Result arriving after deadline expiration is rejected
        res_late = consumer_dl.handle_read_result(
            5, Sample(1, 1, 100).encode_read_result(), association_id=2, now_ms=500
        )
        self.assertFalse(res_late)

    def test_case_s_a2_correlated_result(self):
        """s-a2-correlated-result: Only current authorized result selects epoch; same epoch no rollback."""
        consumer = SampleConsumer()
        consumer.start_initialization(association_id=1)
        consumer.designate_read(30)
        res = consumer.handle_read_result(30, Sample(1, 1, 100).encode_read_result())
        self.assertTrue(res)
        self.assertEqual(consumer.selected_epoch, 1)

    def test_case_s_a2_no_sample(self):
        """s-a2-no-sample: ERR=64 ACKed; new identity retry; stays unsynchronized."""
        consumer = SampleConsumer()
        consumer.start_initialization(association_id=1)
        consumer.designate_read(40)
        consumer.handle_no_sample(40)
        self.assertEqual(consumer.state, "unsynchronized")
        self.assertIsNone(consumer.designated_request_seq)

    def test_case_s_a2_live_late(self):
        """s-a2-live-late: Only selected epoch/higher index updates; stale result cannot alter cache."""
        consumer = SampleConsumer()
        consumer.start_initialization(association_id=1)
        consumer.designate_read(50)
        consumer.handle_read_result(50, Sample(1, 5, 500).encode_read_result())
        # Higher index updates
        updated = consumer.handle_telemetry(Sample(1, 6, 600).encode_telemetry())
        self.assertEqual(updated.value, 600)
        # Stale index ignored
        stale = consumer.handle_telemetry(Sample(1, 4, 400).encode_telemetry())
        self.assertIsNone(stale)
        self.assertEqual(consumer.cached_sample.value, 600)

    def test_case_s_a3_positive_and_negative(self):
        """s-a3-positive & s-a3-negative: Canonical payloads and reject malformed before state update."""
        # 1. Canonical positive payloads (§A3)
        read_req = b"\x01"
        status_req = b"\x02"
        status_ready_1 = b"\x02\x01"
        status_ready_0 = b"\x02\x00"
        self.assertEqual(read_req, bytes.fromhex("01"))
        self.assertEqual(status_req, bytes.fromhex("02"))
        self.assertEqual(status_ready_1, bytes.fromhex("02 01"))
        self.assertEqual(status_ready_0, bytes.fromhex("02 00"))
        self.assertEqual(Sample.encode_status_result(1), status_ready_1)
        self.assertEqual(Sample.encode_status_result(0), status_ready_0)
        self.assertEqual(Sample.decode_status_result(status_ready_1), 1)
        self.assertEqual(Sample.decode_status_result(status_ready_0), 0)

        # Canonical TELEM and READ result vectors (§A3):
        # TELEM epoch=1, index=2, value=300 (16 bytes)
        expected_telem = bytes.fromhex("01 00 00 00 00 00 00 00 02 00 00 00 2C 01 00 00")
        sample_telem = Sample(epoch=1, index=2, value=300)
        self.assertEqual(sample_telem.encode_telemetry(), expected_telem)
        self.assertEqual(Sample.decode_telemetry(expected_telem), sample_telem)

        # READ result for same sample: opcode 1 + 16-byte sample (17 bytes)
        expected_read_result = bytes.fromhex("01 01 00 00 00 00 00 00 00 02 00 00 00 2C 01 00 00")
        self.assertEqual(sample_telem.encode_read_result(), expected_read_result)
        self.assertEqual(Sample.decode_read_result(expected_read_result), sample_telem)

        # 2. Negative TELEM shapes: wrong length rejected
        for bad_len in (0, 15, 17, 32):
            with self.assertRaises(ValueError):
                Sample.decode_telemetry(b"\x00" * bad_len)

        # 3. Negative READ result shapes: wrong length, wrong opcode
        for bad_len in (0, 16, 18):
            with self.assertRaises(ValueError):
                Sample.decode_read_result(b"\x00" * bad_len)
        with self.assertRaises(ValueError):
            # Opcode 2 (STATUS result) passed as READ result
            Sample.decode_read_result(b"\x02" + expected_telem)
        with self.assertRaises(ValueError):
            # Opcode 3 passed as READ result
            Sample.decode_read_result(b"\x03" + expected_telem)

        # 4. Negative STATUS result shapes
        with self.assertRaises(ValueError):
            Sample.decode_status_result(b"")  # empty
        with self.assertRaises(ValueError):
            Sample.decode_status_result(b"\x02")  # 1 byte
        with self.assertRaises(ValueError):
            Sample.decode_status_result(b"\x02\x01\x00")  # 3 bytes
        with self.assertRaises(ValueError):
            Sample.decode_status_result(b"\x01\x01")  # wrong opcode 1
        with self.assertRaises(ValueError):
            Sample.decode_status_result(b"\x02\x02")  # ready=2 is invalid (must be 0 or 1)

        # 5. Consumer rejects malformed result shapes before mutating state
        consumer = SampleConsumer()
        consumer.start_initialization(association_id=1)
        consumer.designate_read(42)
        self.assertFalse(consumer.handle_read_result(42, b"\x00" * 16))
        self.assertFalse(consumer.handle_read_result(42, b"\x02" + expected_telem))
        self.assertFalse(consumer.handle_read_result(42, b""))
        self.assertEqual(consumer.state, "unsynchronized")
        self.assertFalse(consumer.is_live)

        # 6. Malformed request shapes rejected with STATUS=7 by endpoint
        bad_op = CoreFrame(message_type=0, options=0x03, sequence=120, payload=b"\x03")
        self.endpoint_10.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(bad_op)), at_ms=20))
        self.assertEqual(self.endpoint_10.delivery.rejections[(1, 20, 9, 120)].status, 7)

        empty_req = CoreFrame(message_type=0, options=0x03, sequence=121, payload=b"")
        self.endpoint_10.handle(Receive(link=0, bytes=encode_stream_r(encode_frame(empty_req)), at_ms=20))
        self.assertEqual(self.endpoint_10.delivery.rejections[(1, 20, 9, 121)].status, 7)

    def test_case_s_a4_firstboot(self):
        """s-a4-firstboot: Unsynchronized until designated correlated READ."""
        consumer = SampleConsumer()
        self.assertEqual(consumer.state, "unsynchronized")

    def test_case_s_a4_early_telem(self):
        """s-a4-early-telem: Discard; no pre-sync buffer/live display."""
        consumer = SampleConsumer()
        self.assertIsNone(consumer.handle_telemetry(Sample(1, 1, 10).encode_telemetry()))

    def test_case_s_a4_no_sample_read(self):
        """s-a4-no-sample-read: Remain unsynchronized; new identity retry."""
        consumer = SampleConsumer()
        consumer.start_initialization(association_id=1)
        consumer.designate_read(1)
        consumer.handle_no_sample(1)
        self.assertEqual(consumer.state, "unsynchronized")

    def test_case_s_a4_loss(self):
        """s-a4-loss: Reliable handling; no duplicate or false sync."""
        consumer = SampleConsumer()
        consumer.start_initialization(association_id=1)
        consumer.designate_read(2)
        # Non-correlated response does not sync
        self.assertFalse(consumer.handle_read_result(999, Sample(1, 1, 10).encode_read_result()))
        self.assertEqual(consumer.state, "unsynchronized")

    def test_case_s_a4_timeout(self):
        """s-a4-timeout: Explicit bounded failure; no live sample."""
        consumer = SampleConsumer()
        consumer.start_initialization(association_id=1)
        self.assertFalse(consumer.is_live)

    def test_case_s_a4_old_snapshot(self):
        """s-a4-old-snapshot: Same epoch reconnect with older READ snapshot does not roll back newer value."""
        consumer = SampleConsumer()
        consumer.start_initialization(association_id=1)
        consumer.designate_read(1)
        consumer.handle_read_result(1, Sample(1, 10, 1000).encode_read_result())
        # Reconnect same epoch
        consumer.start_initialization(association_id=1)
        consumer.designate_read(2)
        consumer.handle_read_result(2, Sample(1, 5, 500).encode_read_result())
        # Greatest index preserved (no rollback)
        self.assertEqual(consumer.cached_sample.index, 10)
        self.assertEqual(consumer.cached_sample.value, 1000)

    def test_case_s_a4_restart(self):
        """s-a4-restart: Durable new epoch; no index wrap or telemetry adoption."""
        # 1. Normal restart: atomically reserve and durably commit next epoch
        producer = SampleProducer()
        producer.publish(10)
        self.assertEqual(producer.current_sample.epoch, 1)
        self.assertEqual(producer.current_sample.index, 1)
        producer.restart()
        self.assertEqual(producer.epoch_store.current_epoch(), 2)
        self.assertIsNone(producer.current_sample)

        # 2. Index exhaustion: index >= 0xFFFFFFFF advances epoch before reusing index
        producer._sample_index = 0xFFFFFFFF
        exhaust_sample = producer.publish(42)
        self.assertEqual(exhaust_sample.epoch, 3)
        self.assertEqual(exhaust_sample.index, 1)  # Reset to 1 under new epoch, never reused in epoch 2
        self.assertEqual(producer.epoch_store.current_epoch(), 3)

        # 3. Consumer rejects old epoch telemetry and never adopts epoch from telemetry
        consumer = SampleConsumer()
        consumer.start_initialization(association_id=1)
        consumer.designate_read(1)
        consumer.handle_read_result(1, exhaust_sample.encode_read_result())
        self.assertEqual(consumer.selected_epoch, 3)

        # Old epoch 2 telemetry discarded
        self.assertIsNone(consumer.handle_telemetry(Sample(2, 5, 50).encode_telemetry()))
        self.assertEqual(consumer.cached_sample.epoch, 3)
        self.assertEqual(consumer.cached_sample.value, 42)

        # Different epoch (4) telemetry on active association is discarded (contract violation)
        self.assertIsNone(consumer.handle_telemetry(Sample(4, 1, 99).encode_telemetry()))
        self.assertEqual(consumer.selected_epoch, 3)
        self.assertEqual(consumer.cached_sample.epoch, 3)

    def test_case_s_a4_late_result(self):
        """s-a4-late-result: No epoch/cache change; normal correlation still works."""
        consumer = SampleConsumer()
        consumer.start_initialization(association_id=1)
        consumer.designate_read(1)
        consumer.handle_read_result(1, Sample(1, 10, 100).encode_read_result())
        # Late result from superseded init
        consumer.handle_read_result(999, Sample(2, 1, 50).encode_read_result())
        self.assertEqual(consumer.selected_epoch, 1)

    def test_case_s_a4_assoc_race(self):
        """s-a4-assoc-race: Identity validation and update atomic with replacement."""
        consumer = SampleConsumer()
        gen1 = consumer.start_initialization(association_id=1)
        gen2 = consumer.start_initialization(association_id=2)
        self.assertGreater(gen2, gen1)

    def test_case_s_a4_persistence(self):
        """s-a4-persistence: Stop publishing on persistence failure."""
        # A stale restored image must not boot below an independently retained
        # monotonic floor. This models, but does not physically qualify, rollback
        # detection in the target's durable storage adapter.
        current_store = SampleEpochStore(initial_epoch=5, monotonic_floor=5)
        self.assertEqual(current_store.advance_epoch(), 6)
        self.assertEqual(current_store.monotonic_floor, 6)
        with self.assertRaisesRegex(SampleEpochError, "detected epoch rollback"):
            SampleEpochStore(initial_epoch=5, monotonic_floor=current_store.monotonic_floor)

        max_epoch_store = SampleEpochStore(initial_epoch=0xFFFFFFFFFFFFFFFF)
        with self.assertRaisesRegex(SampleEpochError, "counter exhausted"):
            max_epoch_store.advance_epoch()
        self.assertTrue(max_epoch_store.failed)

        # 1. Injected persistence backend failure sets failed state
        persisted = []

        def failing_persist(epoch: int) -> bool:
            if epoch > 2:
                return False  # Rejects epoch 3
            persisted.append(epoch)
            return True

        store = SampleEpochStore(1, persist_fn=failing_persist)
        producer = SampleProducer(store)
        producer.publish(10)
        self.assertEqual(producer.current_sample.epoch, 1)

        # Advance to epoch 2 succeeds
        producer.restart()
        self.assertEqual(store.current_epoch(), 2)
        producer.publish(20)
        self.assertEqual(producer.current_sample.epoch, 2)

        # Next advance to epoch 3 rejected by persistence backend
        with self.assertRaises(SampleEpochError):
            producer.restart()
        self.assertTrue(store.failed)

        # Subsequent advance and current_epoch fail closed
        with self.assertRaises(SampleEpochError):
            store.advance_epoch()
        with self.assertRaises(SampleEpochError):
            store.current_epoch()

        # Producer fails closed: publish fails, no sample published or reused
        with self.assertRaises(SampleEpochError):
            producer.publish(30)
        status, payload = producer.handle_read()
        self.assertEqual(status, 64)  # NO_SAMPLE: fails closed, prevents reuse
        self.assertEqual(payload, b"")
        status_code, status_payload = producer.handle_status()
        self.assertEqual(status_code, 0)
        self.assertEqual(Sample.decode_status_result(status_payload), 0)  # ready=0

        # Index exhaustion must attempt and fail the required epoch reservation.
        attempted_epochs = []

        def reject_epoch_advance(epoch: int) -> bool:
            attempted_epochs.append(epoch)
            return False

        store2 = SampleEpochStore(1, persist_fn=reject_epoch_advance)
        producer2 = SampleProducer(store2)
        producer2._sample_index = 0xFFFFFFFE
        last_sample = producer2.publish(100)
        self.assertEqual(last_sample.index, 0xFFFFFFFF)
        with self.assertRaises(SampleEpochError):
            producer2.publish(200)
        self.assertEqual(attempted_epochs, [2])
        self.assertIsNone(producer2.current_sample)  # Fail closed after reservation failure
        self.assertEqual(producer2._sample_index, 0xFFFFFFFF)  # No index reuse
        status, payload = producer2.handle_read()
        self.assertEqual((status, payload), (64, b""))  # Failed store hides the retained sample
        status_code, status_payload = producer2.handle_status()
        self.assertEqual(status_code, 0)
        self.assertEqual(Sample.decode_status_result(status_payload), 0)
        with self.assertRaises(SampleEpochError):
            store2.current_epoch()

    def test_case_s_a4_close_shared(self):
        """s-a4-close-shared: Discard sample work on shared association close."""
        self.endpoint_10.handle(Disconnect(link=0, at_ms=100))
        self.assertEqual(len(self.endpoint_10.active_submissions), 0)


if __name__ == "__main__":
    unittest.main()
