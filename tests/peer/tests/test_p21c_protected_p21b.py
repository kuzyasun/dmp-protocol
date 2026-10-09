"""Focused protected-P21B regression suite for P21C.

Verifies P21B delivery, reassembly, deduplication, retry, correlation,
deadlines, and buffer ownership over real SEC-1 protected wire frames between
two live PeerEndpoint instances (NNpsk0 and XX modes) without test-only SEC-1
bypasses or synthetic association stubs.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

from dmp_peer.events import (
    Advance,
    ApplicationEvent,
    ApplicationRequest,
    Cancel,
    Disconnect,
    Open,
    PublishSample,
    Receive,
    TxAdmit,
    TxSubmit,
    TxTerminal,
)
from dmp_peer.frame import (
    CoreFrame,
    Extension,
    Fragment,
    decode_uleb,
    encode_frame,
    encode_uleb,
    parse_frame,
)
from dmp_peer.sample1 import Sample
from dmp_peer.security import (
    CIPHER_CHACHAPOLY,
    MODE_NNPSK0,
    MODE_XX,
)
from dmp_peer.stream_r import cobs_decode, encode_stream_r
from dmp_peer.testing import PeerEndpoint


def decode_stream_r(wire: bytes) -> bytes:
    cand = wire.rstrip(b"\x00")
    raw = cobs_decode(cand)
    return raw[:-4]


def _load_manifest_bytes(name: str = "direct-nnpsk0.json") -> bytes:
    path = Path(__file__).parents[3] / "profiles" / "deployments" / name
    return path.read_bytes()


def _extract_and_settle(
    ep: PeerEndpoint,
    events: tuple[Any, ...] | list[Any] | None = None,
    at_ms: int = 1000,
    out_events: list[Any] | None = None,
) -> list[bytes]:
    """Collect submitted wire bytes and settle active adapter borrows with TxAdmit/TxTerminal."""
    wires: list[bytes] = []
    if events is not None:
        for e in events:
            if isinstance(e, TxSubmit):
                wires.append(e.bytes)
            elif out_events is not None:
                out_events.append(e)
    while ep.active_submissions:
        for handle, sub in list(ep.active_submissions.items()):
            if not sub.get("admitted"):
                adm_evts = ep.handle(
                    TxAdmit(handle=handle, generation=sub["generation"], accepted=True, reason=None, at_ms=at_ms)
                )
                if out_events is not None:
                    out_events.extend(adm_evts)
            term_evts = ep.handle(
                TxTerminal(handle=handle, generation=sub["generation"], outcome="transmitted", at_ms=at_ms)
            )
            for te in term_evts:
                if isinstance(te, TxSubmit):
                    wires.append(te.bytes)
                elif out_events is not None:
                    out_events.append(te)
    return wires


class TestP21CProtectedP21B(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_manifest_nnpsk0 = _load_manifest_bytes("direct-nnpsk0.json")
        self.raw_manifest_xx = _load_manifest_bytes("direct-xx.json")

    def _setup_pair_nnpsk0(
        self,
        psk: bytes = b"\x01" * 32,
    ) -> tuple[PeerEndpoint, PeerEndpoint]:
        # Node 10 = Responder / Producer; Node 20 = Initiator / Consumer
        ep_resp = PeerEndpoint(
            manifest_bytes=self.raw_manifest_nnpsk0,
            test_credentials={"node_id": 10, "psk": psk},
            entropy_source=lambda n: bytes((i + 1) % 256 for i in range(n)),
            test_services={},
        )
        ep_init = PeerEndpoint(
            manifest_bytes=self.raw_manifest_nnpsk0,
            test_credentials={"node_id": 20, "psk": psk},
            entropy_source=lambda n: bytes((i + 2) % 256 for i in range(n)),
            test_services={},
        )
        e_resp_open = ep_resp.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        e_init_open = ep_init.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        resp_sync = _extract_and_settle(ep_resp, e_resp_open, at_ms=11)
        init_sync = _extract_and_settle(ep_init, e_init_open, at_ms=11)
        if resp_sync:
            ep_init.handle(Receive(link=0, bytes=resp_sync[0], at_ms=12))
        if init_sync:
            ep_resp.handle(Receive(link=0, bytes=init_sync[0], at_ms=12))
        return ep_init, ep_resp

    def _setup_pair_xx(
        self,
        init_priv: bytes = b"\x10" * 32,
        resp_priv: bytes = b"\x20" * 32,
    ) -> tuple[PeerEndpoint, PeerEndpoint]:
        from cryptography.hazmat.primitives.asymmetric import x25519

        init_pub = x25519.X25519PrivateKey.from_private_bytes(init_priv).public_key().public_bytes_raw()
        resp_pub = x25519.X25519PrivateKey.from_private_bytes(resp_priv).public_key().public_bytes_raw()

        resp_credentials = {
            "node_id": 10,
            "static_private_key": resp_priv,
            "peer_static_public_key": init_pub,
        }
        init_credentials = {
            "node_id": 20,
            "static_private_key": init_priv,
            "peer_static_public_key": resp_pub,
        }

        ep_resp = PeerEndpoint(
            manifest_bytes=self.raw_manifest_xx,
            test_credentials=resp_credentials,
            entropy_source=lambda n: bytes((i + 1) % 256 for i in range(n)),
            test_services={},
        )
        ep_init = PeerEndpoint(
            manifest_bytes=self.raw_manifest_xx,
            test_credentials=init_credentials,
            entropy_source=lambda n: bytes((i + 2) % 256 for i in range(n)),
            test_services={},
        )
        e_resp_open = ep_resp.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        e_init_open = ep_init.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        resp_sync = _extract_and_settle(ep_resp, e_resp_open, at_ms=11)
        init_sync = _extract_and_settle(ep_init, e_init_open, at_ms=11)
        if resp_sync:
            ep_init.handle(Receive(link=0, bytes=resp_sync[0], at_ms=12))
        if init_sync:
            ep_resp.handle(Receive(link=0, bytes=init_sync[0], at_ms=12))
        return ep_init, ep_resp

    def _perform_nnpsk0_handshake(
        self, ep_init: PeerEndpoint, ep_resp: PeerEndpoint, at_ms: int = 100
    ) -> None:
        evts = ep_init.initiate_handshake(at_ms=at_ms)
        f1_wires = _extract_and_settle(ep_init, evts, at_ms=at_ms + 1)
        self.assertEqual(len(f1_wires), 1)

        f2_evts = ep_resp.handle(Receive(link=0, bytes=f1_wires[0], at_ms=at_ms + 10))
        f2_wires = _extract_and_settle(ep_resp, f2_evts, at_ms=at_ms + 11)
        self.assertEqual(len(f2_wires), 1)

        fin_evts = ep_init.handle(Receive(link=0, bytes=f2_wires[0], at_ms=at_ms + 20))
        fin_wires = _extract_and_settle(ep_init, fin_evts, at_ms=at_ms + 21)
        self.assertEqual(len(fin_wires), 1)

        ready_evts = ep_resp.handle(Receive(link=0, bytes=fin_wires[0], at_ms=at_ms + 30))
        ready_wires = _extract_and_settle(ep_resp, ready_evts, at_ms=at_ms + 31)
        self.assertEqual(len(ready_wires), 1)
        self.assertIsNotNone(ep_resp.association)
        self.assertEqual(ep_resp.association.status, "active")

        ep_init.handle(Receive(link=0, bytes=ready_wires[0], at_ms=at_ms + 40))
        self.assertIsNotNone(ep_init.association)
        self.assertEqual(ep_init.association.status, "active")

    def _perform_xx_handshake(
        self, ep_init: PeerEndpoint, ep_resp: PeerEndpoint, at_ms: int = 100
    ) -> None:
        evts = ep_init.initiate_handshake(at_ms=at_ms)
        f1_wires = _extract_and_settle(ep_init, evts, at_ms=at_ms + 1)
        self.assertEqual(len(f1_wires), 1)

        f2_evts = ep_resp.handle(Receive(link=0, bytes=f1_wires[0], at_ms=at_ms + 10))
        f2_wires = _extract_and_settle(ep_resp, f2_evts, at_ms=at_ms + 11)
        self.assertEqual(len(f2_wires), 1)

        f3_evts = ep_init.handle(Receive(link=0, bytes=f2_wires[0], at_ms=at_ms + 20))
        f3_wires = _extract_and_settle(ep_init, f3_evts, at_ms=at_ms + 21)
        self.assertEqual(len(f3_wires), 2)  # Flight 3 and FINISH

        for w in f3_wires:
            resp_evts = ep_resp.handle(Receive(link=0, bytes=w, at_ms=at_ms + 30))
            for rw in _extract_and_settle(ep_resp, resp_evts, at_ms=at_ms + 31):
                ep_init.handle(Receive(link=0, bytes=rw, at_ms=at_ms + 40))

        self.assertIsNotNone(ep_resp.association)
        self.assertEqual(ep_resp.association.status, "active")
        self.assertIsNotNone(ep_init.association)
        self.assertEqual(ep_init.association.status, "active")

    # =========================================================================
    # P21B Obligation 1: Lost request retry & duplicate suppression
    # =========================================================================

    def test_p21b_lost_request_retry_with_fresh_pn_and_successful_delivery(self) -> None:
        """P21B retry obligation: unacknowledged request is retransmitted with fresh PN and delivered."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        ep_resp.handle(PublishSample(value=4321, at_ms=200))
        _extract_and_settle(ep_resp, at_ms=201)

        # Initiator sends READ request at t=210
        req_evts = ep_init.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=210))
        req_wires_1 = _extract_and_settle(ep_init, req_evts, at_ms=211)
        self.assertEqual(len(req_wires_1), 1)

        f1 = parse_frame(decode_stream_r(req_wires_1[0]))
        self.assertIsNotNone(f1.security)
        self.assertEqual(f1.security.packet_number, 1)

        # Drop first wire frame (simulated network loss)
        # Advance time on initiator past response timeout (1280 ms)
        adv_evts = ep_init.handle(Advance(now_ms=211 + 1280))
        retry_wires = _extract_and_settle(ep_init, adv_evts, at_ms=211 + 1281)
        self.assertEqual(len(retry_wires), 1)

        # Verify retry frame keeps same logical request seq but uses fresh PN
        f_retry = parse_frame(decode_stream_r(retry_wires[0]))
        self.assertEqual(f_retry.sequence, f1.sequence)
        self.assertIsNotNone(f_retry.security)
        self.assertGreater(f_retry.security.packet_number, f1.security.packet_number)

        # Deliver retried frame to responder
        rsp_evts = ep_resp.handle(Receive(link=0, bytes=retry_wires[0], at_ms=1600))
        rsp_wires = _extract_and_settle(ep_resp, rsp_evts, at_ms=1601)
        self.assertGreaterEqual(len(rsp_wires), 1)

        # Deliver response to initiator
        term_evts: list[Any] = []
        for rw in rsp_wires:
            term_evts.extend(ep_init.handle(Receive(link=0, bytes=rw, at_ms=1610)))
        _extract_and_settle(ep_init, at_ms=1611)

        result_event = next(
            (e for e in term_evts if isinstance(e, ApplicationEvent) and e.kind == "request_result"), None
        )
        self.assertIsNotNone(result_event)
        self.assertEqual(result_event.service_id, 1)
        self.assertEqual(result_event.status, 0)
        sample = Sample.decode_read_result(result_event.payload)
        self.assertEqual(sample.value, 4321)

    def test_p21b_retry_crosses_packet_number_uleb_width_boundary(self) -> None:
        """A protected retry keeps its logical SEQ while PN grows from 127 to 128."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)
        ep_init.association.next_send_pn = 127

        payload = b"P" * 64
        first_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(ApplicationRequest(service_id=2, payload=payload, ack_req=True, at_ms=210)),
            at_ms=211,
        )
        self.assertEqual(len(first_wires), 1)
        first_core = decode_stream_r(first_wires[0])
        first = parse_frame(first_core)
        self.assertEqual(first.security.packet_number, 127)
        self.assertEqual(len(encode_uleb(first.security.packet_number)), 1)
        self.assertLessEqual(len(first_core), ep_init.forward_mtu)

        retry_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(Advance(now_ms=211 + 1280)),
            at_ms=211 + 1281,
        )
        self.assertEqual(len(retry_wires), 1)
        retry_core = decode_stream_r(retry_wires[0])
        retry = parse_frame(retry_core)
        self.assertEqual(retry.sequence, first.sequence)
        self.assertEqual(retry.security.packet_number, 128)
        self.assertEqual(len(encode_uleb(retry.security.packet_number)), 2)
        self.assertEqual(len(retry_core), len(first_core) + 1)
        self.assertLessEqual(len(retry_core), ep_init.forward_mtu)

        received = ep_resp.handle(Receive(link=0, bytes=retry_wires[0], at_ms=1600))
        self.assertTrue(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in received
        ))

    def test_p21b_duplicate_request_suppression_prevents_duplicate_application_dispatch(self) -> None:
        """P21B duplicate suppression: duplicate request does not cause duplicate application dispatch."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        ep_resp.handle(PublishSample(value=9876, at_ms=200))
        _extract_and_settle(ep_resp, at_ms=201)

        # Instrument responder application dispatch
        dispatch_count = 0
        orig_read = ep_resp.sample_producer.handle_read

        def tracking_read() -> tuple[int, bytes]:
            nonlocal dispatch_count
            dispatch_count += 1
            return orig_read()

        ep_resp.sample_producer.handle_read = tracking_read

        # Initiator sends request
        req_evts = ep_init.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=210))
        req_wires = _extract_and_settle(ep_init, req_evts, at_ms=211)
        self.assertEqual(len(req_wires), 1)

        # First delivery to responder: application executes once
        rsp_evts = ep_resp.handle(Receive(link=0, bytes=req_wires[0], at_ms=220))
        rsp_wires = _extract_and_settle(ep_resp, rsp_evts, at_ms=221)
        self.assertEqual(dispatch_count, 1)
        self.assertGreaterEqual(len(rsp_wires), 1)

        # Simulate response loss: initiator times out and retransmits request with fresh PN
        adv_evts = ep_init.handle(Advance(now_ms=211 + 1280))
        retry_wires = _extract_and_settle(ep_init, adv_evts, at_ms=211 + 1281)
        self.assertEqual(len(retry_wires), 1)

        f_dup = parse_frame(decode_stream_r(retry_wires[0]))
        f_orig = parse_frame(decode_stream_r(req_wires[0]))
        self.assertEqual(f_dup.sequence, f_orig.sequence)
        self.assertGreater(f_dup.security.packet_number, f_orig.security.packet_number)

        # Deliver duplicate request to responder
        dup_rsp_evts = ep_resp.handle(Receive(link=0, bytes=retry_wires[0], at_ms=1600))
        dup_rsp_wires = _extract_and_settle(ep_resp, dup_rsp_evts, at_ms=1601)

        # CONTRACT OBLIGATION: application MUST NOT be dispatched a second time!
        self.assertEqual(dispatch_count, 1)

        # Retained result replayed with fresh PN
        self.assertGreaterEqual(len(dup_rsp_wires), 1)
        f_replayed = parse_frame(decode_stream_r(dup_rsp_wires[-1]))
        f_orig_rsp = parse_frame(decode_stream_r(rsp_wires[-1]))
        self.assertEqual(f_replayed.sequence, f_orig_rsp.sequence)
        self.assertGreater(f_replayed.security.packet_number, f_orig_rsp.security.packet_number)

        request_key = (
            ep_resp.namespace,
            ep_init.local_node_id,
            ep_resp.association.peer_epoch,
            f_orig.sequence,
        )
        retained = ep_resp.delivery.retained_results[request_key]
        self.assertEqual((retained.bursts_sent, retained.attempts_left), (2, 1))

        # Duplicate-triggered protected replays consume the same manifest budget
        # as timed retries; a third result burst would exceed max_bursts=3.
        duplicate2_raw = ep_init._build_req_frames(
            service_id=1,
            seq=f_orig.sequence,
            payload=b"\x01",
            ack_req=True,
        )[0]
        duplicate2_frame = parse_frame(duplicate2_raw)
        self.assertGreater(duplicate2_frame.security.packet_number, f_dup.security.packet_number)
        duplicate2 = encode_stream_r(duplicate2_raw)
        duplicate2_events = ep_resp.handle(Receive(link=0, bytes=duplicate2, at_ms=1620))
        duplicate2_results = _extract_and_settle(ep_resp, duplicate2_events, at_ms=1621)
        self.assertGreaterEqual(len(duplicate2_results), 1)
        self.assertEqual((retained.bursts_sent, retained.attempts_left), (3, 0))

        duplicate3_raw = ep_init._build_req_frames(
            service_id=1,
            seq=f_orig.sequence,
            payload=b"\x01",
            ack_req=True,
        )[0]
        duplicate3_frame = parse_frame(duplicate3_raw)
        self.assertGreater(duplicate3_frame.security.packet_number, duplicate2_frame.security.packet_number)
        duplicate3 = encode_stream_r(duplicate3_raw)
        duplicate3_events = ep_resp.handle(Receive(link=0, bytes=duplicate3, at_ms=1640))
        duplicate3_results = _extract_and_settle(ep_resp, duplicate3_events, at_ms=1641)
        self.assertEqual(duplicate3_results, [])
        self.assertEqual((retained.bursts_sent, retained.attempts_left), (3, 0))

        # Initiator receives replayed result
        term_evts: list[Any] = []
        for rw in dup_rsp_wires:
            term_evts.extend(ep_init.handle(Receive(link=0, bytes=rw, at_ms=1610)))
        _extract_and_settle(ep_init, at_ms=1611)

        results = [e for e in term_evts if isinstance(e, ApplicationEvent) and e.kind == "request_result"]
        self.assertEqual(len(results), 1)
        self.assertEqual(Sample.decode_read_result(results[0].payload).value, 9876)

    # =========================================================================
    # P21B Obligation 2: Receipt/result delivery, ACK correlation & result release
    # =========================================================================

    def test_p21b_result_ack_loss_retransmits_result_and_prevents_premature_release(self) -> None:
        """P21B correlation/ACK obligation: retained result retransmits on lost ACK; result gate held until ACK."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        ep_resp.handle(PublishSample(value=5555, at_ms=200))
        _extract_and_settle(ep_resp, at_ms=201)

        # Send request and deliver to responder
        req_wires = _extract_and_settle(
            ep_init, ep_init.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=210)), at_ms=211
        )
        rsp_wires = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=req_wires[0], at_ms=220)), at_ms=221
        )

        # Responder has retained result with gate held
        self.assertEqual(len(ep_resp.delivery.retained_results), 1)
        res_key = next(iter(ep_resp.delivery.retained_results.keys()))
        retained_res = ep_resp.delivery.retained_results[res_key]
        self.assertFalse(retained_res.acknowledged)
        gate_key = (ep_init.local_node_id, 1)
        self.assertIn(gate_key, ep_resp.delivery.result_gates)

        # Deliver response to initiator -> generates result ACK
        init_evts: list[Any] = []
        for rw in rsp_wires:
            init_evts.extend(ep_init.handle(Receive(link=0, bytes=rw, at_ms=230)))
        ack_wires = _extract_and_settle(ep_init, init_evts, at_ms=231)
        self.assertGreaterEqual(len(ack_wires), 1)

        # Verify correlation in result ACK: under SEC-1, REPLY_TO encodes tgt_seq
        f_ack = parse_frame(decode_stream_r(ack_wires[0]))
        self.assertEqual(f_ack.message_type, 6)  # ACK
        self.assertIsNotNone(f_ack.security)
        ext_reply = next(e for e in f_ack.extensions if e.extension_id == 1)
        ack_target_seq, _ = decode_uleb(ext_reply.value, 0)
        self.assertEqual(ack_target_seq, retained_res.result_seq)

        # PREMATURE RESULT RELEASE CHECK:
        # Before result ACK is delivered, result gate is STILL held and acknowledged is False
        self.assertFalse(retained_res.acknowledged)
        self.assertIn(gate_key, ep_resp.delivery.result_gates)

        # Simulate loss of result ACK: advance time on responder past response timeout
        adv_evts = ep_resp.handle(Advance(now_ms=220 + 1280))
        retransmitted_rsp_wires = _extract_and_settle(ep_resp, adv_evts, at_ms=220 + 1281)
        self.assertGreaterEqual(len(retransmitted_rsp_wires), 1)

        # Initiator receives retransmitted result: does NOT emit duplicate request_result
        dup_evts: list[Any] = []
        for rw in retransmitted_rsp_wires:
            dup_evts.extend(ep_init.handle(Receive(link=0, bytes=rw, at_ms=1600)))
        re_ack_wires = _extract_and_settle(ep_init, dup_evts, at_ms=1601)
        self.assertFalse(any(isinstance(e, ApplicationEvent) and e.kind == "request_result" for e in dup_evts))
        self.assertGreaterEqual(len(re_ack_wires), 1)

        # Deliver retransmitted result ACK to responder
        ep_resp.handle(Receive(link=0, bytes=re_ack_wires[0], at_ms=1610))
        _extract_and_settle(ep_resp, at_ms=1611)

        # NOW retained result is acknowledged and result gate is released!
        self.assertTrue(retained_res.acknowledged)
        self.assertNotIn(gate_key, ep_resp.delivery.result_gates)

    def test_p21b_mismatched_correlation_does_not_release_result_gate(self) -> None:
        """P21B stable correlation: ACK with mismatched responder/service does not acknowledge or release result."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        ep_resp.handle(PublishSample(value=1111, at_ms=200))
        _extract_and_settle(ep_resp, at_ms=201)

        req_wires = _extract_and_settle(
            ep_init, ep_init.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=210)), at_ms=211
        )
        _extract_and_settle(ep_resp, ep_resp.handle(Receive(link=0, bytes=req_wires[0], at_ms=220)), at_ms=221)

        gate_key = (ep_init.local_node_id, 1)
        self.assertIn(gate_key, ep_resp.delivery.result_gates)
        res_key = next(iter(ep_resp.delivery.retained_results.keys()))
        retained_res = ep_resp.delivery.retained_results[res_key]

        # Attempting to acknowledge with mismatched service_id or wrong origin fails
        res = ep_resp.delivery.record_result_ack_received(
            retained_res.result_namespace,
            retained_res.result_origin,
            retained_res.result_epoch,
            retained_res.result_seq,
            service_id=99,  # Mismatched service
        )
        self.assertIsNone(res)
        self.assertFalse(retained_res.acknowledged)
        self.assertIn(gate_key, ep_resp.delivery.result_gates)

    # =========================================================================
    # P21B Obligation 3: Deadline expiry & TX borrow cancellation
    # =========================================================================

    def test_p21b_send_deadline_cancels_admitted_borrow_and_releases_gate(self) -> None:
        """P21B deadline obligation: send deadline cancels admitted borrow, preserves buffer until terminal, releases gate."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Initiator requests with not_after_ms = 300
        req_evts = ep_init.handle(
            ApplicationRequest(service_id=2, payload=b"deadline-payload", ack_req=True, not_after_ms=300, at_ms=200)
        )
        tx_submit = next(e for e in req_evts if isinstance(e, TxSubmit))
        handle = tx_submit.handle
        gen = tx_submit.generation

        # Adapter admits the buffer
        ep_init.handle(TxAdmit(handle=handle, generation=gen, accepted=True, reason=None, at_ms=210))
        self.assertTrue(ep_init.active_submissions[handle]["admitted"])
        gate_key = (ep_resp.local_node_id, 2)
        self.assertIn(gate_key, ep_init.delivery.active_per_dest_service)

        # Advance past send deadline without transmitting
        adv_evts = ep_init.handle(Advance(now_ms=300))

        # CONTRACT VERIFICATION:
        # 1. Endpoint emits Cancel for the admitted borrow
        cancels = [e for e in adv_evts if isinstance(e, Cancel)]
        self.assertEqual(len(cancels), 1)
        self.assertEqual(cancels[0].handle, handle)
        self.assertEqual(cancels[0].generation, gen)

        # 2. Exchange is removed from active outgoing
        self.assertFalse(ep_init.delivery.active_outgoing)

        # 3. Stop-and-wait gate is released
        self.assertNotIn(gate_key, ep_init.delivery.active_per_dest_service)

        # 4. Buffer ownership: buffer remains in active_submissions until TxTerminal!
        self.assertIn(handle, ep_init.active_submissions)

        # Adapter completes cancellation
        ep_init.handle(TxTerminal(handle=handle, generation=gen, outcome="cancelled_unsent", at_ms=305))
        self.assertNotIn(handle, ep_init.active_submissions)

        # 5. Subsequent request can now be admitted immediately through the released gate
        req2_evts = ep_init.handle(
            ApplicationRequest(service_id=2, payload=b"subsequent-request", ack_req=True, at_ms=310)
        )
        req2_wires = _extract_and_settle(ep_init, req2_evts, at_ms=311)
        self.assertEqual(len(req2_wires), 1)

        # Deliver subsequent request to responder and complete exchange
        rsp2_wires = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=req2_wires[0], at_ms=320)), at_ms=321
        )
        term2_evts: list[Any] = []
        for rw in rsp2_wires:
            term2_evts.extend(ep_init.handle(Receive(link=0, bytes=rw, at_ms=330)))
        _extract_and_settle(ep_init, at_ms=331)

        res2 = next((e for e in term2_evts if isinstance(e, ApplicationEvent) and e.kind == "request_result"), None)
        self.assertIsNotNone(res2)
        self.assertEqual(res2.status, 0)

    # =========================================================================
    # P21B Obligation 4: Protected fragmented request reassembly
    # =========================================================================

    def test_p21b_protected_fragmented_request_reassembly_and_replay(self) -> None:
        """P21B fragmentation obligation: multi-fragment protected request is reassembled and replayed."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # 150 bytes payload -> chunk_bytes is 64 -> 3 fragments (64, 64, 22)
        payload = bytes((i * 11 + 5) % 256 for i in range(150))
        req_evts = ep_init.handle(ApplicationRequest(service_id=2, payload=payload, ack_req=True, at_ms=200))
        frag_wires = _extract_and_settle(ep_init, req_evts, at_ms=201)
        self.assertEqual(len(frag_wires), 3)

        # Verify all wire frames have SEC-1 protection and Fragment metadata
        seen_pns = set()
        for idx, fw in enumerate(frag_wires):
            f = parse_frame(decode_stream_r(fw))
            self.assertIsNotNone(f.security)
            self.assertEqual(f.security.cipher, CIPHER_CHACHAPOLY)
            seen_pns.add(f.security.packet_number)
            self.assertIsNotNone(f.fragment)
            self.assertEqual(f.fragment.chunk_size, 64)
            self.assertEqual(f.fragment.total_length, 150)
            self.assertEqual(f.fragment.index, idx)
        self.assertEqual(len(seen_pns), 3)

        # Deliver fragments OUT OF ORDER to responder: index 1, then index 0, then index 2
        r1 = ep_resp.handle(Receive(link=0, bytes=frag_wires[1], at_ms=210))
        self.assertEqual(len(_extract_and_settle(ep_resp, r1, at_ms=211)), 0)

        r0 = ep_resp.handle(Receive(link=0, bytes=frag_wires[0], at_ms=220))
        self.assertEqual(len(_extract_and_settle(ep_resp, r0, at_ms=221)), 0)

        r2 = ep_resp.handle(Receive(link=0, bytes=frag_wires[2], at_ms=230))
        rsp_wires = _extract_and_settle(ep_resp, r2, at_ms=231)
        self.assertGreaterEqual(len(rsp_wires), 1)

        # Deliver response to initiator
        term_evts: list[Any] = []
        for rw in rsp_wires:
            term_evts.extend(ep_init.handle(Receive(link=0, bytes=rw, at_ms=240)))
        _extract_and_settle(ep_init, at_ms=241)

        result_event = next(
            (e for e in term_evts if isinstance(e, ApplicationEvent) and e.kind == "request_result"), None
        )
        self.assertIsNotNone(result_event)
        self.assertEqual(result_event.status, 0)
        expected_opaque = bytes((i % 256) ^ 0xA5 for i in range(150))
        self.assertEqual(result_event.payload, expected_opaque)

    # =========================================================================
    # P21B Obligation 5: Delayed TX ownership and stop-and-wait queue admission
    # =========================================================================

    def test_p21b_stop_and_wait_queue_admission_and_drain_after_result(self) -> None:
        """P21B queue admission: second request for same service is queued while gate busy, pops on completion."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Request 1 admitted immediately
        req1_evts = ep_init.handle(
            ApplicationRequest(service_id=2, payload=b"request-1", ack_req=True, at_ms=200)
        )
        req1_tx = [e for e in req1_evts if isinstance(e, TxSubmit)]
        self.assertEqual(len(req1_tx), 1)
        self.assertIn((ep_resp.local_node_id, 2), ep_init.delivery.active_per_dest_service)

        # Request 2 for SAME service submitted while gate busy -> queued in app queue
        req2_evts = ep_init.handle(
            ApplicationRequest(service_id=2, payload=b"request-2", ack_req=True, at_ms=205)
        )
        req2_tx = [e for e in req2_evts if isinstance(e, TxSubmit)]
        self.assertEqual(len(req2_tx), 0)
        self.assertEqual(len(ep_init.delivery.queue), 1)

        # Delayed adapter admission for request 1
        ep_init.handle(Advance(now_ms=210))
        self.assertFalse(ep_init.active_submissions[req1_tx[0].handle]["admitted"])

        # Adapter admits and transmits request 1
        ep_init.handle(TxAdmit(handle=req1_tx[0].handle, generation=req1_tx[0].generation, accepted=True, reason=None, at_ms=215))
        ep_init.handle(TxTerminal(handle=req1_tx[0].handle, generation=req1_tx[0].generation, outcome="transmitted", at_ms=220))

        # Deliver request 1 to responder and complete
        rsp1_wires = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=req1_tx[0].bytes, at_ms=225)), at_ms=226
        )

        # When initiator receives result 1, exchange 1 completes, gate releases, and request 2 is popped and submitted!
        pop_evts: list[Any] = []
        for rw in rsp1_wires:
            pop_evts.extend(ep_init.handle(Receive(link=0, bytes=rw, at_ms=230)))
        req2_wires = _extract_and_settle(ep_init, pop_evts, at_ms=231)

        # Request 2 was popped and submitted; result ACK 1 was also submitted
        self.assertEqual(len(ep_init.delivery.queue), 0)
        self.assertEqual(len(req2_wires), 2)
        ack1_wire = next(w for w in req2_wires if parse_frame(decode_stream_r(w)).message_type == 6)
        req2_wire = next(w for w in req2_wires if parse_frame(decode_stream_r(w)).message_type == 0)

        # Deliver result ACK 1 to responder (acknowledging result 1)
        ep_resp.handle(Receive(link=0, bytes=ack1_wire, at_ms=235))
        _extract_and_settle(ep_resp, at_ms=236)

        # Deliver request 2 to responder and complete
        rsp2_wires = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=req2_wire, at_ms=240)), at_ms=241
        )
        res2_evts: list[Any] = []
        for rw in rsp2_wires:
            res2_evts.extend(ep_init.handle(Receive(link=0, bytes=rw, at_ms=250)))
        _extract_and_settle(ep_init, at_ms=251)

        res2 = next((e for e in res2_evts if isinstance(e, ApplicationEvent) and e.kind == "request_result"), None)
        self.assertIsNotNone(res2)
        self.assertEqual(res2.status, 0)
        self.assertEqual(res2.payload, bytes((i % 256) ^ 0xA5 for i in range(len(b"request-2"))))

    # =========================================================================
    # Multi-mode verification: XX Mode 2 protected exchange
    # =========================================================================

    def test_p21b_xx_mode_protected_exchange_and_fragmented_reassembly(self) -> None:
        """P21B multi-mode verification: authenticated XX Mode 2 exchanges real protected wire frames."""
        ep_init, ep_resp = self._setup_pair_xx()
        self._perform_xx_handshake(ep_init, ep_resp)

        self.assertEqual(ep_init.association.status, "active")
        self.assertEqual(ep_resp.association.status, "active")

        # Fragmented request under XX Mode 2
        payload = bytes((i * 13 + 7) % 256 for i in range(140))
        req_evts = ep_init.handle(ApplicationRequest(service_id=2, payload=payload, ack_req=True, at_ms=200))
        frag_wires = _extract_and_settle(ep_init, req_evts, at_ms=201)
        self.assertEqual(len(frag_wires), 3)

        # All fragments protected under XX
        for fw in frag_wires:
            f = parse_frame(decode_stream_r(fw))
            self.assertIsNotNone(f.security)
            self.assertEqual(f.security.cipher, CIPHER_CHACHAPOLY)

        # Deliver to responder
        for fw in frag_wires:
            rsp_evts = ep_resp.handle(Receive(link=0, bytes=fw, at_ms=210))
            for rw in _extract_and_settle(ep_resp, rsp_evts, at_ms=211):
                res_evts = ep_init.handle(Receive(link=0, bytes=rw, at_ms=220))
                _extract_and_settle(ep_init, res_evts, at_ms=221)

        # Verify association remains active and healthy
        self.assertEqual(ep_init.association.status, "active")
        self.assertEqual(ep_resp.association.status, "active")
