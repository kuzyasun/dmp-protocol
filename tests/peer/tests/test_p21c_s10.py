"""Normative integration tests for P21C and SEC-1 §S10 failure scenarios.

Tests exercise live peer-to-peer interactions between two independent
PeerEndpoint instances through DMP-PEER-TEST/1 without synthetic context stubs.
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
    Security as SecDesc,
    crc32c,
    decode_uleb,
    encode_frame,
    encode_uleb,
    parse_frame,
)
from dmp_peer.sample1 import Sample
from dmp_peer.security import (
    BOOT_VERSION,
    CIPHER_CHACHAPOLY,
    MODE_NNPSK0,
    MODE_XX,
    PAYLOAD_FINISH,
    PAYLOAD_READY,
    SecurityError,
    compute_bootstrap_epoch,
    compute_prologue,
)
from dmp_peer.stream_r import cobs_decode, cobs_encode, encode_stream_r
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
) -> list[bytes]:
    """Collect submitted wire bytes and settle all active borrows with TxAdmit/TxTerminal.

    Drains queued frames recursively until all adapter slots are released.
    """
    wires: list[bytes] = []
    if events is not None:
        for e in events:
            if isinstance(e, TxSubmit):
                wires.append(e.bytes)
    while ep.active_submissions:
        for handle, sub in list(ep.active_submissions.items()):
            if not sub.get("admitted"):
                ep.handle(TxAdmit(handle=handle, generation=sub["generation"], accepted=True, reason=None, at_ms=at_ms))
            term_evts = ep.handle(
                TxTerminal(handle=handle, generation=sub["generation"], outcome="transmitted", at_ms=at_ms)
            )
            for te in term_evts:
                if isinstance(te, TxSubmit):
                    wires.append(te.bytes)
    return wires


class TestP21CS10SecurityLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        self.raw_manifest_nnpsk0 = _load_manifest_bytes("direct-nnpsk0.json")
        self.raw_manifest_xx = _load_manifest_bytes("direct-xx.json")

    def _setup_pair_nnpsk0(
        self,
        psk: bytes = b"\x01" * 32,
        manifest_bytes: bytes | None = None,
    ) -> tuple[PeerEndpoint, PeerEndpoint]:
        # Node 10 = Responder / Producer; Node 20 = Initiator / Consumer
        manifest_bytes = manifest_bytes or self.raw_manifest_nnpsk0
        ep_resp = PeerEndpoint(
            manifest_bytes=manifest_bytes,
            test_credentials={"node_id": 10, "psk": psk},
            entropy_source=lambda n: bytes((i + 1) % 256 for i in range(n)),
            test_services={},
        )
        ep_init = PeerEndpoint(
            manifest_bytes=manifest_bytes,
            test_credentials={"node_id": 20, "psk": psk},
            entropy_source=lambda n: bytes((i + 2) % 256 for i in range(n)),
            test_services={},
        )
        # Open links and exchange initial sync delimiters for Stream R
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
        approve_oob: bool = True,
        resp_peer_pin: bytes | None = None,
    ) -> tuple[PeerEndpoint, PeerEndpoint]:
        from cryptography.hazmat.primitives.asymmetric import x25519

        init_pub = x25519.X25519PrivateKey.from_private_bytes(init_priv).public_key().public_bytes_raw()
        resp_pub = x25519.X25519PrivateKey.from_private_bytes(resp_priv).public_key().public_bytes_raw()

        resp_credentials = {"node_id": 10, "static_private_key": resp_priv}
        init_credentials = {"node_id": 20, "static_private_key": init_priv}
        if approve_oob:
            resp_credentials["peer_static_public_key"] = init_pub if resp_peer_pin is None else resp_peer_pin
            init_credentials["peer_static_public_key"] = resp_pub

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
        # Step 1: Initiator builds Flight 1
        evts = ep_init.initiate_handshake(at_ms=at_ms)
        f1_wires = _extract_and_settle(ep_init, evts, at_ms=at_ms + 1)
        self.assertEqual(len(f1_wires), 1)

        # Step 2: Responder receives Flight 1 -> sends Flight 2
        f2_evts = ep_resp.handle(Receive(link=0, bytes=f1_wires[0], at_ms=at_ms + 10))
        f2_wires = _extract_and_settle(ep_resp, f2_evts, at_ms=at_ms + 11)
        self.assertEqual(len(f2_wires), 1)

        # Step 3: Initiator receives Flight 2 -> sends protected FINISH
        fin_evts = ep_init.handle(Receive(link=0, bytes=f2_wires[0], at_ms=at_ms + 20))
        fin_wires = _extract_and_settle(ep_init, fin_evts, at_ms=at_ms + 21)
        self.assertEqual(len(fin_wires), 1)

        # Step 4: Responder receives protected FINISH -> activates and sends protected READY
        ready_evts = ep_resp.handle(Receive(link=0, bytes=fin_wires[0], at_ms=at_ms + 30))
        ready_wires = _extract_and_settle(ep_resp, ready_evts, at_ms=at_ms + 31)
        self.assertEqual(len(ready_wires), 1)
        self.assertIsNotNone(ep_resp.association)
        self.assertEqual(ep_resp.association.status, "active")

        # Step 5: Initiator receives protected READY -> activates
        ep_init.handle(Receive(link=0, bytes=ready_wires[0], at_ms=at_ms + 40))
        self.assertIsNotNone(ep_init.association)
        self.assertEqual(ep_init.association.status, "active")

    def _perform_xx_handshake(
        self, ep_init: PeerEndpoint, ep_resp: PeerEndpoint, at_ms: int = 100
    ) -> None:
        # Step 1: Initiator builds Flight 1
        evts = ep_init.initiate_handshake(at_ms=at_ms)
        f1_wires = _extract_and_settle(ep_init, evts, at_ms=at_ms + 1)
        self.assertEqual(len(f1_wires), 1)

        # Step 2: Responder receives Flight 1 -> sends Flight 2
        f2_evts = ep_resp.handle(Receive(link=0, bytes=f1_wires[0], at_ms=at_ms + 10))
        f2_wires = _extract_and_settle(ep_resp, f2_evts, at_ms=at_ms + 11)
        self.assertEqual(len(f2_wires), 1)

        # Step 3: Initiator receives Flight 2 -> sends Flight 3 and protected FINISH
        f3_evts = ep_init.handle(Receive(link=0, bytes=f2_wires[0], at_ms=at_ms + 20))
        f3_wires = _extract_and_settle(ep_init, f3_evts, at_ms=at_ms + 21)
        self.assertEqual(len(f3_wires), 2)  # Flight 3 and FINISH

        # Step 4: Responder receives Flight 3 and FINISH -> activates and sends READY
        for w in f3_wires:
            resp_evts = ep_resp.handle(Receive(link=0, bytes=w, at_ms=at_ms + 30))
            for rw in _extract_and_settle(ep_resp, resp_evts, at_ms=at_ms + 31):
                ep_init.handle(Receive(link=0, bytes=rw, at_ms=at_ms + 40))

        self.assertIsNotNone(ep_resp.association)
        self.assertEqual(ep_resp.association.status, "active")
        self.assertIsNotNone(ep_init.association)
        self.assertEqual(ep_init.association.status, "active")

    # =========================================================================
    # Normative Test Cases
    # =========================================================================

    def test_handshake_nnpsk0_live_activation_and_sample1_exchange(self) -> None:
        """S10.01/S10.02: Verify full NNpsk0 handshake and subsequent protected SAMPLE-1 exchange."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Publish sample on responder (Node 10)
        ep_resp.handle(PublishSample(value=12345, at_ms=200))
        _extract_and_settle(ep_resp, at_ms=201)

        # Initiator sends READ request (Service 1, opcode 1)
        req_evts = ep_init.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=210))
        req_wires = _extract_and_settle(ep_init, req_evts, at_ms=211)
        self.assertEqual(len(req_wires), 1)

        # Verify request wire has SEC-1 protection
        f_req = parse_frame(decode_stream_r(req_wires[0]))
        self.assertIsNotNone(f_req.security)
        self.assertEqual(f_req.security.cipher, CIPHER_CHACHAPOLY)
        self.assertEqual(f_req.security.packet_number, 1)

        # Responder receives protected REQ -> generates protected receipt ACK and protected RSP
        rsp_evts = ep_resp.handle(Receive(link=0, bytes=req_wires[0], at_ms=220))
        rsp_wires = _extract_and_settle(ep_resp, rsp_evts, at_ms=221)
        self.assertGreaterEqual(len(rsp_wires), 1)

        # Initiator receives RSP -> emits request_result and generates protected result ACK
        term_evts = []
        for rw in rsp_wires:
            res = ep_init.handle(Receive(link=0, bytes=rw, at_ms=230))
            term_evts.extend(res)
        _extract_and_settle(ep_init, at_ms=231)

        result_event = next(
            (e for e in term_evts if isinstance(e, ApplicationEvent) and e.kind == "request_result"), None
        )
        self.assertIsNotNone(result_event)
        self.assertEqual(result_event.service_id, 1)
        self.assertEqual(result_event.status, 0)
        sample = Sample.decode_read_result(result_event.payload)
        self.assertEqual(sample.value, 12345)

    def test_handshake_xx_live_activation(self) -> None:
        """S10.01/S10.14: Verify full XX Mode 2 mutual handshake with committed pin."""
        ep_init, ep_resp = self._setup_pair_xx()
        self._perform_xx_handshake(ep_init, ep_resp)

        self.assertEqual(ep_init.association.status, "active")
        self.assertEqual(ep_resp.association.status, "active")

    def test_s10_01_handshake_failures_abort_and_block_traffic(self) -> None:
        """S10.01: Invalid PSK, mismatched pin, unknown profile digest fail closed without activating."""
        # Case 1: Wrong PSK
        ep_init, ep_resp = self._setup_pair_nnpsk0(psk=b"\x01" * 32)
        ep_resp.psk = b"\x99" * 32  # Mismatched PSK
        ep_resp.bootstrap_mgr.psk = b"\x99" * 32

        evts = ep_init.initiate_handshake(at_ms=100)
        f1 = _extract_and_settle(ep_init, evts, at_ms=101)[0]

        # Responder fails decrypting Flight 1 -> no Flight 2
        f2_evts = ep_resp.handle(Receive(link=0, bytes=f1, at_ms=110))
        self.assertEqual(len(_extract_and_settle(ep_resp, f2_evts, at_ms=111)), 0)
        self.assertIsNone(ep_resp.association)

        # Case 2: Mismatched static public key in Mode 2
        from cryptography.hazmat.primitives.asymmetric import x25519

        ep_init_xx, ep_resp_xx = self._setup_pair_xx(resp_peer_pin=b"\x33" * 32)

        f1_xx = _extract_and_settle(ep_init_xx, ep_init_xx.initiate_handshake(at_ms=100), at_ms=101)[0]
        f2_xx = _extract_and_settle(ep_resp_xx, ep_resp_xx.handle(Receive(link=0, bytes=f1_xx, at_ms=110)), at_ms=111)[0]
        f3_wires = _extract_and_settle(
            ep_init_xx, ep_init_xx.handle(Receive(link=0, bytes=f2_xx, at_ms=120)), at_ms=121
        )
        # When responder receives flight 3 with unexpected static key, authorization fails
        resp_out = ep_resp_xx.handle(Receive(link=0, bytes=f3_wires[0], at_ms=130))
        self.assertEqual(len(_extract_and_settle(ep_resp_xx, resp_out, at_ms=131)), 0)
        self.assertIsNone(ep_resp_xx.association)

    def test_s10_02_confirmation_timeout_and_fresh_pn_retry(self) -> None:
        """S10.02: Lost FINISH is retransmitted with fresh PN upon confirmation timeout."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        evts = ep_init.initiate_handshake(at_ms=100)
        f1 = _extract_and_settle(ep_init, evts, at_ms=101)[0]
        f2 = _extract_and_settle(ep_resp, ep_resp.handle(Receive(link=0, bytes=f1, at_ms=110)), at_ms=111)[0]
        fin_evts = ep_init.handle(Receive(link=0, bytes=f2, at_ms=120))
        fin_1_wires = _extract_and_settle(ep_init, fin_evts, at_ms=121)
        fin_1 = fin_1_wires[0]

        # Parse FINISH 1 PN
        frame1 = parse_frame(decode_stream_r(fin_1))
        self.assertEqual(frame1.security.packet_number, 0)

        # Advance time past confirmation_timeout_ms (512 ms in direct-nnpsk0)
        adv_evts = ep_init.handle(Advance(now_ms=120 + 600))
        fin_2_wires = _extract_and_settle(ep_init, adv_evts, at_ms=721)
        self.assertEqual(len(fin_2_wires), 1)

        # Re-sent FINISH has fresh PN!
        frame2 = parse_frame(decode_stream_r(fin_2_wires[0]))
        self.assertEqual(frame2.security.packet_number, 1)

        # Responder accepts retransmitted FINISH and activates
        ready_wires = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=fin_2_wires[0], at_ms=750)), at_ms=751
        )
        self.assertEqual(len(ready_wires), 1)
        self.assertEqual(ep_resp.association.status, "active")

    def test_flight1_retry_reuses_cached_bytes_with_manifest_attempt_limit(self) -> None:
        """Bootstrap F1 retry reuses cached bytes and stops at the manifest attempt cap."""
        ep_init, _ = self._setup_pair_nnpsk0()
        first_wire = _extract_and_settle(
            ep_init, ep_init.initiate_handshake(at_ms=100), at_ms=101
        )[0]
        security_cfg = ep_init.manifest.values["security"]
        retry_at = 100 + security_cfg["flight_retry_ms"]

        before_retry = ep_init.handle(Advance(now_ms=retry_at - 1))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in before_retry))

        retry_wires = _extract_and_settle(
            ep_init, ep_init.handle(Advance(now_ms=retry_at)), at_ms=retry_at + 1
        )
        self.assertEqual(retry_wires, [first_wire])

        after_budget = ep_init.handle(
            Advance(now_ms=retry_at + security_cfg["flight_retry_ms"])
        )
        self.assertFalse(any(isinstance(event, TxSubmit) for event in after_budget))

    def test_confirmation_timeout_retires_candidate_and_allows_bounded_retry(self) -> None:
        """A timed-out confirmation erases candidate state and allows a later bounded attempt."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        f1 = _extract_and_settle(
            ep_init, ep_init.initiate_handshake(at_ms=100), at_ms=101
        )[0]
        f2 = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=f1, at_ms=110)), at_ms=111
        )[0]
        fin_evts = ep_init.handle(Receive(link=0, bytes=f2, at_ms=120))
        _extract_and_settle(ep_init, fin_evts, at_ms=121)  # Deliberately lose FINISH/READY.

        first_retry = ep_init.next_confirmation_retry_ms
        self.assertIsNotNone(first_retry)
        ep_init.handle(Advance(now_ms=first_retry))
        second_retry = ep_init.next_confirmation_retry_ms
        self.assertIsNotNone(second_retry)
        ep_init.handle(Advance(now_ms=second_retry))

        self.assertIsNone(ep_init.pending_association)
        self.assertIsNone(ep_init.bootstrap_mgr.current_attempt_id)
        self.assertIsNone(ep_init._bootstrap_attempt_id)

        new_attempt_at = ep_init._bootstrap_last_attempt_end_ms + ep_init.manifest.values["security"]["restart_backoff_ms"]
        ep_init.handle(Advance(now_ms=new_attempt_at))
        entropy_counter = 0

        def fresh_entropy(n: int) -> bytes:
            nonlocal entropy_counter
            entropy_counter += 1
            return bytes([entropy_counter]) * n

        ep_init.entropy_source = fresh_entropy
        ep_init.bootstrap_mgr.entropy_source = fresh_entropy
        new_f1 = ep_init.initiate_handshake(at_ms=new_attempt_at, attempt_id=b"\x77" * 16)
        self.assertTrue(any(isinstance(event, TxSubmit) for event in new_f1))
        self.assertNotEqual(ep_init.bootstrap_mgr.current_attempt_id, b"\x02" * 16)

    def test_absolute_attempt_expiry_cancels_later_confirmation_timer(self) -> None:
        """Absolute bootstrap expiry clears candidate keys before confirmation work can run."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        f1 = _extract_and_settle(
            ep_init, ep_init.initiate_handshake(at_ms=100), at_ms=101
        )[0]
        f2 = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=f1, at_ms=110)), at_ms=111
        )[0]
        _extract_and_settle(
            ep_init, ep_init.handle(Receive(link=0, bytes=f2, at_ms=120)), at_ms=121
        )  # Candidate now waits for READY.

        expired_at = ep_init._bootstrap_attempt_start_ms + ep_init.manifest.values["security"]["attempt_ms"]
        events = ep_init.handle(Advance(now_ms=expired_at))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in events))
        self.assertIsNone(ep_init.pending_association)
        self.assertIsNone(ep_init.next_confirmation_retry_ms)
        self.assertIsNone(ep_init.cached_finish_wire)
        self.assertIsNone(ep_init.bootstrap_mgr.current_attempt_id)

    def test_s10_03_plaintext_downgrade_and_service_acl_rejection(self) -> None:
        """S10.03: Plaintext downgrade is rejected; unauthorized service request returns STATUS 6."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Case 1: Plaintext frame injected into active association -> silently dropped
        raw_plaintext = encode_stream_r(encode_frame(CoreFrame(message_type=0, options=3, sequence=99, payload=b"\x01")))
        out = ep_resp.handle(Receive(link=0, bytes=raw_plaintext, at_ms=300))
        self.assertEqual(len(out), 0)  # No processing, no response

        # Case 2: Node 10 sends REQ to Node 20 on Service 1 (Node 10 has produce/result only, not read)
        bad_req_evts = ep_resp.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=310))
        bad_req_wires = _extract_and_settle(ep_resp, bad_req_evts, at_ms=311)
        self.assertEqual(len(bad_req_wires), 1)

        # Node 20 evaluates ACL: Node 10 is not authorized for read on Service 1 -> emits STATUS 6 ERR
        acl_err_evts = ep_init.handle(Receive(link=0, bytes=bad_req_wires[0], at_ms=320))
        err_wires = _extract_and_settle(ep_init, acl_err_evts, at_ms=321)
        self.assertEqual(len(err_wires), 1)
        err_frame = parse_frame(decode_stream_r(err_wires[0]))
        self.assertIsNotNone(err_frame.security)  # Protected error!

    def test_sec1_fails_closed_without_credentials_or_before_activation(self) -> None:
        with self.assertRaises(SecurityError):
            PeerEndpoint(
                self.raw_manifest_nnpsk0,
                {"node_id": 10},
                lambda n: b"\x01" * n,
                {},
            )

        from cryptography.hazmat.primitives.asymmetric import x25519

        ep_unapproved = PeerEndpoint(
            self.raw_manifest_xx,
            {"node_id": 10, "static_private_key": b"\x20" * 32},
            lambda n: b"\x01" * n,
            {},
        )
        ep_unapproved.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=10))
        with self.assertRaises(SecurityError):
            ep_unapproved.initiate_handshake(at_ms=20)

        ep_init, ep_resp = self._setup_pair_nnpsk0()
        plain_req = encode_stream_r(
            encode_frame(CoreFrame(message_type=0, options=3, sequence=88, payload=b"\x01"))
        )
        self.assertEqual(ep_resp.handle(Receive(link=0, bytes=plain_req, at_ms=20)), ())
        self.assertEqual(ep_resp.delivery.accepted_messages, {})

        app_events = ep_init.handle(
            ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=21)
        )
        self.assertFalse(any(isinstance(e, TxSubmit) for e in app_events))
        rejection = next(e for e in app_events if isinstance(e, ApplicationEvent))
        self.assertEqual(rejection.kind, "protocol_rejection")
        self.assertEqual(rejection.payload, b"security_not_active")

    def test_s10_04_exact_duplicate_dropped_and_fresh_pn_retry_deduplicates(self) -> None:
        """S10.04: Exact duplicate dropped by replay window; fresh-PN retry dedups without reexecution."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        ep_resp.handle(PublishSample(value=5555, at_ms=200))
        _extract_and_settle(ep_resp, at_ms=201)

        # Send REQ
        req_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=210)),
            at_ms=211,
        )
        self.assertEqual(len(req_wires), 1)

        # Responder processes REQ -> outputs receipt ACK and RSP
        rsp_wires = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=req_wires[0], at_ms=220)), at_ms=221
        )
        self.assertGreaterEqual(len(rsp_wires), 1)

        # Inject EXACT duplicate of REQ wire (same PN)
        dup_rsp = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=req_wires[0], at_ms=225)), at_ms=226
        )
        # Replay window drops exact duplicate before AEAD commit
        self.assertEqual(len(dup_rsp), 0)

        # Simulate initiator retry after ACK loss: advance time to trigger timeout retry
        retry_evts = ep_init.handle(Advance(now_ms=210 + 2000))
        retry_wires = _extract_and_settle(ep_init, retry_evts, at_ms=2211)
        self.assertEqual(len(retry_wires), 1)

        # Verify retry has FRESH PN
        f_orig = parse_frame(decode_stream_r(req_wires[0]))
        f_retry = parse_frame(decode_stream_r(retry_wires[0]))
        self.assertGreater(f_retry.security.packet_number, f_orig.security.packet_number)

        # Responder receives fresh-PN retry: passes replay window, dedups, replays cached result
        res_wires = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=retry_wires[0], at_ms=2300)), at_ms=2301
        )
        self.assertGreaterEqual(len(res_wires), 1)

    def test_s10_05_invalid_tag_does_not_advance_replay_window(self) -> None:
        """S10.05: Invalid tag with high PN does not advance replay window; valid lower PN accepted."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Corrupt last byte of tag in a valid wire frame
        req_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=210)),
            at_ms=211,
        )
        self.assertEqual(len(req_wires), 1)
        raw = bytearray(decode_stream_r(req_wires[0]))
        raw[-1] ^= 0xFF  # Invalidate tag!
        corrupt_wire = encode_stream_r(bytes(raw))

        # Deliver corrupted frame
        bad_out = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=corrupt_wire, at_ms=220)), at_ms=221
        )
        self.assertEqual(len(bad_out), 0)

        # Replay window on responder must NOT have advanced past PN 0 (from FINISH)
        self.assertEqual(ep_resp.association.replay_window.h, 0)

        # Valid original frame with PN=1 is delivered and accepted
        valid_out = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=req_wires[0], at_ms=230)), at_ms=231
        )
        self.assertGreaterEqual(len(valid_out), 1)
        self.assertEqual(ep_resp.association.replay_window.h, 1)

    def test_s10_06_endpoint_authenticated_reassembly(self) -> None:
        """S10.06-endpoint: Reassembly of authenticated fragments with sequential PNs."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Send large payload on Service 2 (OPAQUE-1, 150 bytes > chunk_bytes 64)
        large_payload = bytes(i % 256 for i in range(150))
        req_evts = ep_init.handle(ApplicationRequest(service_id=2, payload=large_payload, ack_req=True, at_ms=210))
        req_wires = _extract_and_settle(ep_init, req_evts, at_ms=211)
        self.assertEqual(len(req_wires), 3)  # 3 slices: 64, 64, 22 bytes

        # Deliver all 3 slices to responder
        for w in req_wires:
            ep_resp.handle(Receive(link=0, bytes=w, at_ms=220))
        _extract_and_settle(ep_resp, at_ms=221)

        # Verify responder reassembled and accepted message
        self.assertIn((1, 20, ep_init.local_epoch, 1), ep_resp.delivery.accepted_messages)

    def test_s10_07_ttl_mutation_preserves_aead(self) -> None:
        """S10.07: TTL is mutable on a protected routed frame; other header bytes are authenticated."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Direct-1 is point-to-point. For this endpoint-local AAD case, mark
        # the already validated pair as routed so the real Receive path accepts
        # a correctly bound ROUTE header. Relay forwarding remains P21D scope.
        ep_init.manifest.values["binding"]["topology"] = "relay-routed"
        ep_resp.manifest.values["binding"]["topology"] = "relay-routed"

        def make_protected_data() -> bytes:
            assoc = ep_init.association
            route = Route(ttl=5, mode=1, source_id=20, destination_id=10)
            extensions = (
                Extension(2, True, True, encode_uleb(ep_init.namespace) + assoc.local_epoch.to_bytes(8, "little")),
                Extension(4, True, False, encode_uleb(2)),
            )
            frame = CoreFrame(
                message_type=7,
                options=0x85,  # SEQ | ROUTE | EXT
                sequence=ep_init._alloc_seq(),
                route=route,
                extensions=extensions,
                payload=b"",
            )
            return ep_init._encrypt_and_encode(frame, plaintext=b"telemetry_data")

        original_wire = make_protected_data()
        original = parse_frame(original_wire)
        original_header_len = original_wire[1]
        original_pn = original.security.packet_number

        # Test A: Mutate TTL nibble (bits 4..7 in route control octet at offset 4).
        mutated_ttl = bytearray(original_wire)
        mutated_ttl[4] = (mutated_ttl[4] & 0x0F) | (2 << 4)
        before = ep_resp.association.failed_aead_count
        delivered = ep_resp.handle(Receive(link=0, bytes=encode_stream_r(bytes(mutated_ttl)), at_ms=220))
        self.assertEqual(ep_resp.association.failed_aead_count, before)
        self.assertEqual(ep_resp.association.replay_window.h, original_pn)
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.payload == b"telemetry_data"
            for event in delivered
        ))

        # Test B: A fresh frame with a consistent encoded PN fails when a
        # non-TTL authenticated ROUTE field is changed before Receive.
        bad_header = bytearray(make_protected_data())
        bad_header_len = bad_header[1]
        self.assertEqual(bad_header_len, original_header_len)
        bad_header[5] ^= 0x01  # source_id 20 -> 21
        before = ep_resp.association.failed_aead_count
        rejected = ep_resp.handle(Receive(link=0, bytes=encode_stream_r(bytes(bad_header)), at_ms=221))
        self.assertEqual(ep_resp.association.failed_aead_count, before + 1)
        self.assertFalse(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in rejected
        ))

    def test_s10_08_restart_erases_session_state(self) -> None:
        """S10.08: Endpoint restart erases volatile traffic state; fresh handshake required."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Save an encrypted packet
        req_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=210)),
            at_ms=211,
        )
        self.assertEqual(len(req_wires), 1)
        req_wire = req_wires[0]

        # Responder restarts
        ep_resp.handle(Restart(entropy=b"\xFE" * 16, at_ms=300))
        self.assertIsNone(ep_resp.association)

        # Open link again on responder
        open_res = ep_resp.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=310))
        _extract_and_settle(ep_resp, open_res, at_ms=311)

        # Delivering old traffic frame is rejected
        out = _extract_and_settle(ep_resp, ep_resp.handle(Receive(link=0, bytes=req_wire, at_ms=320)), at_ms=321)
        self.assertEqual(len(out), 0)

    def test_result_ack_retries_keep_logical_sequence_and_fresh_packet_number(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)
        request_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(ApplicationRequest(service_id=2, payload=b"stable-ack", ack_req=True, at_ms=210)),
            at_ms=211,
        )
        response_wires = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Receive(link=0, bytes=request_wires[0], at_ms=220)),
            at_ms=221,
        )
        result_wire = next(
            wire for wire in response_wires
            if parse_frame(decode_stream_r(wire)).message_type == 1
        )
        first_ack_events = ep_init.handle(Receive(link=0, bytes=result_wire, at_ms=230))
        first_acks = _extract_and_settle(ep_init, first_ack_events, at_ms=231)
        self.assertEqual(len(first_acks), 1)
        first_ack = parse_frame(decode_stream_r(first_acks[0]))

        # Do not deliver ACK1; the retained result retries with a fresh PN.
        retained = next(iter(ep_resp.delivery.retained_results.values()))
        retry_at = max(retained.next_retry_ms, 240)
        retry_wires = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Advance(now_ms=retry_at)),
            at_ms=retry_at + 1,
        )
        retry_result = next(
            wire for wire in retry_wires
            if parse_frame(decode_stream_r(wire)).message_type == 1
        )
        retry_frame = parse_frame(decode_stream_r(retry_result))
        original_result = parse_frame(decode_stream_r(result_wire))
        self.assertEqual(retry_frame.sequence, original_result.sequence)
        self.assertGreater(retry_frame.security.packet_number, original_result.security.packet_number)

        second_ack_events = ep_init.handle(Receive(
            link=0,
            bytes=retry_result,
            at_ms=retry_at + 2,
        ))
        second_acks = _extract_and_settle(ep_init, second_ack_events, at_ms=retry_at + 3)
        self.assertEqual(len(second_acks), 1)
        second_ack = parse_frame(decode_stream_r(second_acks[0]))
        self.assertEqual(second_ack.sequence, first_ack.sequence)
        self.assertGreater(second_ack.security.packet_number, first_ack.security.packet_number)

    def test_restart_aborts_pre_split_bootstrap_attempt(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        f1 = _extract_and_settle(ep_init, ep_init.initiate_handshake(at_ms=100), at_ms=101)[0]
        f2 = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=f1, at_ms=110)), at_ms=111
        )[0]
        self.assertIsNotNone(ep_init.bootstrap_mgr.current_attempt_id)

        ep_init.handle(Restart(entropy=b"\xD1" * 16, at_ms=120))
        self.assertIsNone(ep_init.bootstrap_mgr.current_attempt_id)
        ep_init.handle(Open(link=0, deadline_capability="strict_latest_start", at_ms=130))
        out = ep_init.handle(Receive(link=0, bytes=f2, at_ms=140))
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out))
        self.assertIsNone(ep_init.pending_association)

    def test_association_expiry_stops_receive_and_send(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)
        ep_resp.association.association_lifetime_ms = 1

        expired_events = ep_resp.handle(Advance(now_ms=142))
        self.assertIsNone(ep_resp.association)
        self.assertFalse(any(isinstance(e, TxSubmit) for e in expired_events))

        plain_req = encode_stream_r(
            encode_frame(CoreFrame(message_type=0, options=3, sequence=89, payload=b"\x01"))
        )
        self.assertEqual(ep_resp.handle(Receive(link=0, bytes=plain_req, at_ms=143)), ())
        out = ep_resp.handle(
            ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=144)
        )
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out))

    def test_authenticated_identity_fields_must_match_association(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        forged_extensions = (
            (
                Extension(3, True, True, encode_uleb(99)),
                Extension(4, True, False, encode_uleb(2)),
            ),
            (
                Extension(
                    2,
                    True,
                    True,
                    encode_uleb(ep_init.namespace)
                    + (ep_init.association.peer_epoch + 1).to_bytes(8, "little"),
                ),
                Extension(4, True, False, encode_uleb(2)),
            ),
        )
        for i, extensions in enumerate(forged_extensions, start=1):
            frame = CoreFrame(
                message_type=0,
                options=0x81,
                sequence=100 + i,
                extensions=tuple(sorted(extensions, key=lambda ext: ext.extension_id)),
                payload=b"\x01",
            )
            protected = ep_init._encrypt_and_encode(frame, plaintext=b"\x01")
            wire = encode_stream_r(protected)
            events = ep_resp.handle(Receive(link=0, bytes=wire, at_ms=200 + i))
            self.assertFalse(any(isinstance(e, TxSubmit) for e in events))
            self.assertNotIn((1, 20, ep_init.local_epoch, 100 + i), ep_resp.delivery.accepted_messages)

    def test_s10_09_failed_aead_limit_closes_association(self) -> None:
        """S10.09: Exceeding failed_aead_limit closes association."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        ep_resp.association.failed_aead_limit = 5
        for i in range(5):
            bad_pn = 1000 + i
            try:
                ep_resp.association.decrypt_frame(
                    core_header=b"\x00" * 4,
                    ciphertext=b"\x00" * 10,
                    tag=b"\x00" * 16,
                    pn=bad_pn,
                    rx_cid=ep_resp.association.local_rx_cid,
                )
            except Exception:
                pass

        self.assertEqual(ep_resp.association.status, "closed")

    def test_s10_10_service_0_freshness_tokens(self) -> None:
        """S10.10: Service 0 issues freshness token; validated and consumed on application request."""
        ep_init, ep_resp = self._setup_pair_nnpsk0(
            manifest_bytes=_load_manifest_bytes("radio-nnpsk0.json")
        )
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Client requests freshness grant on Service 0: 1000 ms lifetime
        req_payload = b"\x10" + (1000).to_bytes(4, "little")
        req_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(ApplicationRequest(service_id=0, payload=req_payload, ack_req=True, at_ms=200)),
            at_ms=201,
        )
        self.assertEqual(len(req_wires), 1)

        # Server grants lease: responds with opcode 0x11
        rsp_wires = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=req_wires[0], at_ms=210)), at_ms=211
        )
        self.assertGreaterEqual(len(rsp_wires), 1)

        # Client processes grant RSP and stores active_freshness_token
        res_evts = []
        for rw in rsp_wires:
            res_evts.extend(ep_init.handle(Receive(link=0, bytes=rw, at_ms=220)))
        _extract_and_settle(ep_init, at_ms=221)
        self.assertIsNotNone(ep_init.active_freshness_token)
        self.assertEqual(len(ep_init.active_freshness_token), 16)

        token = ep_init.active_freshness_token
        # Service 2's frozen radio profile requires a lease; no runtime manifest edits.
        cmd_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(ApplicationRequest(service_id=2, payload=b"fresh-command", ack_req=True, at_ms=230)),
            at_ms=231,
        )
        self.assertEqual(len(cmd_wires), 1)
        cmd_frame = parse_frame(cmd_wires[0])
        self.assertEqual(next(e.value for e in cmd_frame.extensions if e.extension_id == 6), token)
        self.assertIsNone(ep_init.active_freshness_token)

        # A logical retry gets a fresh PN but retains the original lease token.
        exc = next(iter(ep_init.delivery.active_outgoing.values()))
        first_pn = cmd_frame.security.packet_number
        retry_evts = ep_init.handle(Advance(now_ms=exc.next_retry_ms))
        retry_wires = _extract_and_settle(ep_init, retry_evts, at_ms=exc.next_retry_ms + 1)
        retry_frame = parse_frame(retry_wires[0])
        self.assertGreater(retry_frame.security.packet_number, first_pn)
        self.assertEqual(next(e.value for e in retry_frame.extensions if e.extension_id == 6), token)

        # Server accepts command with valid fresh token
        accept_evts = ep_resp.handle(Receive(link=0, bytes=cmd_wires[0], at_ms=240))
        _extract_and_settle(ep_resp, accept_evts, at_ms=241)
        self.assertTrue(any(isinstance(e, ApplicationEvent) and e.kind == "request_accepted" for e in accept_evts))

    def test_freshness_required_service_rejects_without_grant(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0(
            manifest_bytes=_load_manifest_bytes("radio-nnpsk0.json")
        )
        self._perform_nnpsk0_handshake(ep_init, ep_resp)
        out = ep_init.handle(
            ApplicationRequest(service_id=2, payload=b"needs-lease", ack_req=True, at_ms=210)
        )
        self.assertFalse(any(isinstance(e, TxSubmit) for e in out))
        rejection = next(e for e in out if isinstance(e, ApplicationEvent))
        self.assertEqual(rejection.kind, "protocol_rejection")
        self.assertEqual(rejection.payload, b"freshness_token_required")

    def test_s10_12_pn_varint_boundary_and_header_limits(self) -> None:
        """S10.12: PN limits (2^24) enforced and ULEB boundary transitions verified."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        assoc = ep_init.association
        # Set next send PN right at the 2^24 limit
        assoc.next_send_pn = 16_777_216  # 2^24 limit
        with self.assertRaises(SecurityError):
            assoc.alloc_send_pn()

        # Verify ULEB encodings at boundaries
        for val in (0, 127, 128, 16383, 16384, (1 << 24) - 1, (1 << 32) - 1):
            enc = encode_uleb(val)
            dec, length = decode_uleb(enc, 0)
            self.assertEqual(dec, val)
            self.assertEqual(length, len(enc))

        # Exercise the widest permitted PN in an actual protected transfer and
        # include its encoded header overhead in the profile's core MTU.
        assoc.next_send_pn = (1 << 24) - 1
        wires = _extract_and_settle(
            ep_init,
            ep_init.handle(ApplicationRequest(service_id=2, payload=b"pn-boundary", ack_req=True, at_ms=210)),
            at_ms=211,
        )
        self.assertEqual(len(wires), 1)
        core = decode_stream_r(wires[0])
        frame = parse_frame(core)
        self.assertEqual(frame.security.packet_number, (1 << 24) - 1)
        self.assertEqual(len(encode_uleb(frame.security.packet_number)), 4)
        self.assertLessEqual(len(core), ep_init.forward_mtu)
        accepted = ep_resp.handle(Receive(link=0, bytes=wires[0], at_ms=220))
        self.assertTrue(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in accepted
        ))

    def test_s10_13_bounded_bootstrap_work_and_admission(self) -> None:
        """S10.13: Forged/garbage bootstrap frames are dropped without leaking half-open attempts."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()

        def _make_bad_boot(payload: bytes) -> bytes:
            attempt_id = b"\x11" * 16
            b_epoch = compute_bootstrap_epoch(attempt_id)
            ext_context = Extension(2, True, True, encode_uleb(ep_resp.namespace) + b_epoch.to_bytes(8, "little"))
            ext_origin = Extension(3, True, True, encode_uleb(ep_init.local_node_id))
            f = CoreFrame(
                message_type=3,  # HELLO
                options=1 | 0x80,  # SEQ | EXT
                sequence=1,
                extensions=(ext_context, ext_origin),
                payload=payload,
            )
            return encode_stream_r(encode_frame(f, max_frame=ep_resp.forward_mtu))

        # Flood responder with malformed bootstrap frames
        for bad_bytes in (
            b"\x00" * 10,  # too short
            b"\x00\x02\x05\x00\x00\x00\x00",  # invalid stream/frame
            _make_bad_boot(bytes([BOOT_VERSION, 99, 1, 1]) + b"\x00" * 70),  # invalid mode
            _make_bad_boot(bytes([BOOT_VERSION, MODE_NNPSK0, 99, 1]) + b"\x00" * 70),  # invalid cipher
        ):
            out = ep_resp.handle(Receive(link=0, bytes=bad_bytes, at_ms=100))
            self.assertEqual(len(out), 0)
            self.assertIsNone(ep_resp.bootstrap_mgr.current_attempt_id)

        # Admitted valid attempt still succeeds afterwards
        self._perform_nnpsk0_handshake(ep_init, ep_resp, at_ms=200)
        self.assertEqual(ep_resp.association.status, "active")

    def test_s10_13_bootstrap_rate_duplicate_and_attempt_deadlines(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        security_cfg = ep_resp.manifest.values["security"]
        security_cfg["ingress_packets_per_window"] = 2
        security_cfg["ingress_window_ms"] = 1000

        f1_wires = _extract_and_settle(ep_init, ep_init.initiate_handshake(at_ms=100), at_ms=101)
        malformed = encode_stream_r(encode_frame(
            CoreFrame(message_type=3, options=0, sequence=1, payload=b""),
            max_frame=ep_resp.forward_mtu,
        ))
        self.assertEqual(ep_resp.handle(Receive(link=0, bytes=malformed, at_ms=110)), ())

        first_f2 = ep_resp.handle(Receive(link=0, bytes=f1_wires[0], at_ms=111))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in first_f2))
        # The in-window third packet is rejected by ingress admission.
        self.assertEqual(ep_resp.handle(Receive(link=0, bytes=f1_wires[0], at_ms=112)), ())

        # After the ingress window, exactly one cached duplicate response is allowed.
        duplicate_f2 = ep_resp.handle(Receive(link=0, bytes=f1_wires[0], at_ms=1111))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in duplicate_f2))
        self.assertEqual(ep_resp.handle(Receive(link=0, bytes=f1_wires[0], at_ms=1112)), ())

        timed_init, timed_resp = self._setup_pair_nnpsk0()
        timed_resp.manifest.values["security"]["attempt_ms"] = 10
        timed_f1 = _extract_and_settle(timed_init, timed_init.initiate_handshake(at_ms=200), at_ms=201)
        accepted_f1 = timed_resp.handle(Receive(link=0, bytes=timed_f1[0], at_ms=202))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in accepted_f1))
        timed_resp.handle(Receive(link=0, bytes=timed_f1[0], at_ms=212))
        self.assertIsNone(timed_resp.bootstrap_mgr.current_attempt_id)
        self.assertIsNone(timed_resp.pending_association)

    def test_s10_14_enrollment_commit_distinct_from_activation(self) -> None:
        """S10.14: Pin verification commits state before activation; activation requires protected READY."""
        ep_init, ep_resp = self._setup_pair_xx(approve_oob=False)
        from cryptography.hazmat.primitives.asymmetric import x25519

        init_pub = x25519.X25519PrivateKey.from_private_bytes(b"\x10" * 32).public_key().public_bytes_raw()
        resp_pub = x25519.X25519PrivateKey.from_private_bytes(b"\x20" * 32).public_key().public_bytes_raw()
        self.assertEqual(ep_init.bootstrap_mgr.committed_pins, set())
        self.assertEqual(ep_resp.bootstrap_mgr.committed_pins, set())
        with self.assertRaises(SecurityError):
            ep_init.initiate_handshake(at_ms=100)

        # The local approval operation models verification of the displayed key
        # through the separate owner-controlled out-of-band channel.
        ep_init.approve_oob_peer_static_key(resp_pub)
        ep_resp.approve_oob_peer_static_key(init_pub)
        self.assertIn(resp_pub, ep_init.bootstrap_mgr.committed_pins)
        self.assertIn(init_pub, ep_resp.bootstrap_mgr.committed_pins)

        # Step 1: The approved initiator sends Flight 1.
        f1_wires = _extract_and_settle(ep_init, ep_init.initiate_handshake(at_ms=100), at_ms=101)

        # Step 2: Responder sends Flight 2
        f2_wires = _extract_and_settle(
            ep_resp, ep_resp.handle(Receive(link=0, bytes=f1_wires[0], at_ms=110)), at_ms=111
        )

        # Step 3: Initiator verifies the committed peer pin and creates pending association.
        f3_wires = _extract_and_settle(
            ep_init, ep_init.handle(Receive(link=0, bytes=f2_wires[0], at_ms=120)), at_ms=121
        )
        self.assertIsNotNone(ep_init.pending_association)
        self.assertEqual(ep_init.pending_association.status, "candidate")
        self.assertIsNone(ep_init.association)  # Not active yet!

        # Step 4: Responder receives Flight 3 and FINISH -> activates and emits READY
        ready_wires = []
        for w in f3_wires:
            r_evts = ep_resp.handle(Receive(link=0, bytes=w, at_ms=130))
            ready_wires.extend(_extract_and_settle(ep_resp, r_evts, at_ms=131))

        self.assertIsNotNone(ep_resp.association)
        self.assertEqual(ep_resp.association.status, "active")

        # Step 5: Initiator receives READY -> transitions from pending to active
        ep_init.handle(Receive(link=0, bytes=ready_wires[0], at_ms=140))
        self.assertIsNotNone(ep_init.association)
        self.assertEqual(ep_init.association.status, "active")
        self.assertIsNone(ep_init.pending_association)

    def test_s10_15_borrowed_buffer_cancel_releases_without_nonce_reuse(self) -> None:
        """S10.15: Borrowed-buffer cancel releases buffer; subsequent request allocates fresh PN."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Initiator enqueues an application request
        req_evts = ep_init.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=210))
        sub = next(e for e in req_evts if isinstance(e, TxSubmit))
        first_frame = parse_frame(decode_stream_r(sub.bytes))
        first_pn = first_frame.security.packet_number

        # Cancel the submission before transmission completes
        ep_init.handle(TxAdmit(handle=sub.handle, generation=sub.generation, accepted=True, reason=None, at_ms=211))
        ep_init.handle(
            TxTerminal(handle=sub.handle, generation=sub.generation, outcome="cancelled_unsent", at_ms=212)
        )
        self.assertEqual(len(ep_init.active_submissions), 0)

        # Next request must allocate a FRESH PN (no nonce reuse!)
        req_evts_2 = ep_init.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=220))
        sub_2 = next(e for e in req_evts_2 if isinstance(e, TxSubmit))
        second_frame = parse_frame(decode_stream_r(sub_2.bytes))
        second_pn = second_frame.security.packet_number
        self.assertGreater(second_pn, first_pn)
        _extract_and_settle(ep_init, at_ms=221)

    def test_s10_16_compact_reply_to_resolved_via_local_identity(self) -> None:
        """S10.16: Protected REPLY_TO contains only single ULEB32 seq; rejected if extra bytes."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Valid compact REPLY_TO: exactly 1 ULEB32 seq
        compact_val = encode_uleb(42)
        frame_valid = CoreFrame(
            message_type=6,
            options=0x41,
            sequence=1,
            extensions=(Extension(1, True, False, compact_val),),
            security=ep_resp.association.local_rx_cid,
        )
        resolved = ep_resp._extract_reply_to(frame_valid)
        self.assertEqual(resolved, (ep_resp.namespace, ep_resp.local_node_id, ep_resp.local_epoch, 42))

        # Invalid compact REPLY_TO with extra trailing bytes: must reject
        frame_invalid = CoreFrame(
            message_type=6,
            options=0x41,
            sequence=1,
            extensions=(Extension(1, True, False, compact_val + b"\x99"),),
            security=ep_resp.association.local_rx_cid,
        )
        self.assertIsNone(ep_resp._extract_reply_to(frame_invalid))

    def test_s10_17_abort_first_pre_read_drops_vs_abort(self) -> None:
        """S10.17: Pre-read mismatch and wrong-role flights preserve a pending attempt."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        evts = ep_init.initiate_handshake(at_ms=100)
        f1 = _extract_and_settle(ep_init, evts, at_ms=101)[0]

        # Establish real responder-side Noise/candidate state before sending a
        # malformed duplicate. This is the state a cheap pre-read rejection
        # must preserve.
        f2_wires = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Receive(link=0, bytes=f1, at_ms=110)),
            at_ms=111,
        )
        self.assertEqual(len(f2_wires), 1)
        attempt_id = ep_resp.bootstrap_mgr.current_attempt_id
        pending = ep_resp.pending_association
        self.assertIsNotNone(attempt_id)
        self.assertIsNotNone(pending)
        self.assertEqual(pending.status, "candidate")

        # Mutate version in Flight 1 prefix
        raw = bytearray(decode_stream_r(f1))
        payload_idx = raw.find(bytes([BOOT_VERSION, MODE_NNPSK0, CIPHER_CHACHAPOLY, 1]))
        raw[payload_idx] = 99  # Invalid BOOT_VERSION
        bad_f1 = encode_stream_r(bytes(raw))

        out = ep_resp.handle(Receive(link=0, bytes=bad_f1, at_ms=120))
        self.assertEqual(len(out), 0)
        self.assertEqual(ep_resp.bootstrap_mgr.current_attempt_id, attempt_id)
        self.assertIs(ep_resp.pending_association, pending)
        self.assertFalse(ep_resp.bootstrap_mgr.attempt_aborted)

        # A responder that has admitted Flight 1 must also reject a same-attempt
        # Flight 2 before re-entering Noise or damaging the pending candidate.
        b_epoch = compute_bootstrap_epoch(attempt_id)
        wrong_flight = CoreFrame(
            message_type=3,
            options=1 | 0x80,
            sequence=2,
            extensions=(
                Extension(2, True, True, encode_uleb(ep_resp.namespace) + b_epoch.to_bytes(8, "little")),
                Extension(3, True, True, encode_uleb(ep_init.local_node_id)),
            ),
            payload=bytes([BOOT_VERSION, 2]) + attempt_id + b"\x00" * 52,
        )
        crypto_used_before = ep_resp._bootstrap_attempt_crypto_ms
        wrong_role_out = ep_resp.handle(Receive(
            link=0,
            bytes=encode_stream_r(encode_frame(wrong_flight, max_frame=ep_resp.forward_mtu)),
            at_ms=121,
        ))
        self.assertEqual(wrong_role_out, ())
        self.assertEqual(ep_resp._bootstrap_attempt_crypto_ms, crypto_used_before)
        self.assertEqual(ep_resp.bootstrap_mgr.current_attempt_id, attempt_id)
        self.assertIs(ep_resp.pending_association, pending)

    def test_conflicting_duplicate_flight1_is_a_cheap_drop_after_flight3(self) -> None:
        ep_init, ep_resp = self._setup_pair_xx()
        f1_wire = _extract_and_settle(
            ep_init, ep_init.initiate_handshake(at_ms=100), at_ms=101
        )[0]
        f2_wire = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Receive(link=0, bytes=f1_wire, at_ms=110)),
            at_ms=111,
        )[0]
        init_flights = _extract_and_settle(
            ep_init,
            ep_init.handle(Receive(link=0, bytes=f2_wire, at_ms=120)),
            at_ms=121,
        )
        f3_wire = next(
            wire for wire in init_flights if parse_frame(decode_stream_r(wire)).security is None
        )
        finish_wire = next(
            wire for wire in init_flights if parse_frame(decode_stream_r(wire)).security is not None
        )
        self.assertEqual(ep_resp.handle(Receive(link=0, bytes=f3_wire, at_ms=130)), ())
        processed_f3 = ep_resp._processed_flight3_payload
        pending = ep_resp.pending_association
        crypto_used = ep_resp._bootstrap_attempt_crypto_ms
        self.assertIsNotNone(processed_f3)
        self.assertIsNotNone(pending)

        original_f1 = parse_frame(decode_stream_r(f1_wire))
        changed_payload = bytearray(original_f1.payload)
        changed_payload[72] ^= 1  # Preserve the valid prefix and ATTEMPT_ID; conflict in Noise bytes.
        conflict = CoreFrame(
            message_type=original_f1.message_type,
            options=original_f1.options,
            sequence=original_f1.sequence,
            route=original_f1.route,
            extensions=original_f1.extensions,
            payload=bytes(changed_payload),
        )
        conflict_wire = encode_stream_r(encode_frame(conflict, max_frame=ep_resp.forward_mtu))
        self.assertEqual(ep_resp.handle(Receive(link=0, bytes=conflict_wire, at_ms=140)), ())
        self.assertEqual(ep_resp._bootstrap_attempt_crypto_ms, crypto_used)
        self.assertEqual(ep_resp._processed_flight3_payload, processed_f3)
        self.assertIs(ep_resp.pending_association, pending)

        # The exact cached Flight 3 still follows the cheap duplicate path, and
        # the original confirmation can complete the retained attempt.
        self.assertEqual(ep_resp.handle(Receive(link=0, bytes=f3_wire, at_ms=150)), ())
        ready = ep_resp.handle(Receive(link=0, bytes=finish_wire, at_ms=160))
        self.assertTrue(any(isinstance(event, TxSubmit) for event in ready))
        self.assertIsNotNone(ep_resp.association)
        self.assertEqual(ep_resp.association.status, "active")

    def test_candidate_initiator_requires_authorized_application_to_confirm_readiness(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        service2 = next(service for service in ep_init.manifest.values["services"] if service.get("id") == 2)
        service2["request_bytes"] = 4  # Test-only boundary for candidate admission.
        f1_wire = _extract_and_settle(
            ep_init, ep_init.initiate_handshake(at_ms=100), at_ms=101
        )[0]
        f2_wire = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Receive(link=0, bytes=f1_wire, at_ms=110)),
            at_ms=111,
        )[0]
        finish_wire = _extract_and_settle(
            ep_init,
            ep_init.handle(Receive(link=0, bytes=f2_wire, at_ms=120)),
            at_ms=121,
        )[0]
        ready_wires = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Receive(link=0, bytes=finish_wire, at_ms=130)),
            at_ms=131,
        )
        ready_wire = next(
            wire for wire in ready_wires
            if parse_frame(decode_stream_r(wire)).message_type == 3
        )
        self.assertIsNone(ep_init.association)
        self.assertIsNotNone(ep_init.pending_association)

        unknown_req = _extract_and_settle(
            ep_resp,
            ep_resp.handle(ApplicationRequest(service_id=99, payload=b"unknown", ack_req=True, at_ms=140)),
            at_ms=141,
        )[0]
        self.assertEqual(ep_init.handle(Receive(link=0, bytes=unknown_req, at_ms=150)), ())
        self.assertIsNone(ep_init.association)
        self.assertIsNotNone(ep_init.pending_association)
        self.assertEqual(ep_init.pending_association.status, "candidate")

        invalid_candidates = (
            ep_resp._build_req_frames(service_id=2, seq=900, payload=b"no-ack", ack_req=False)[0],
            ep_resp._build_req_frames(service_id=2, seq=901, payload=b"oversize", ack_req=True)[0],
            ep_resp._encrypt_and_encode(
                CoreFrame(message_type=5, options=1, sequence=902, payload=b""),
                plaintext=b"\x00" * 15,
            ),
            ep_resp._encrypt_and_encode(
                CoreFrame(
                    message_type=5,
                    options=0x21,
                    sequence=903,
                    payload_descriptor=PayloadDescriptor(flags=0, codec_id=128),
                ),
                plaintext=Sample(epoch=1, index=1, value=5).encode_telemetry(),
            ),
        )
        for index, wire in enumerate(invalid_candidates, start=1):
            self.assertEqual(
                ep_init.handle(Receive(link=0, bytes=encode_stream_r(wire), at_ms=150 + index)), ()
            )
            self.assertIsNone(ep_init.association)
            self.assertIsNotNone(ep_init.pending_association)
            self.assertEqual(ep_init.pending_association.status, "candidate")

        valid_req = _extract_and_settle(
            ep_resp,
            ep_resp.handle(ApplicationRequest(service_id=2, payload=b"ok", ack_req=True, at_ms=160)),
            at_ms=161,
        )[0]
        accepted = ep_init.handle(Receive(link=0, bytes=valid_req, at_ms=170))
        self.assertTrue(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in accepted
        ))
        self.assertIsNotNone(ep_init.association)
        self.assertEqual(ep_init.association.status, "active")
        self.assertIsNone(ep_init.pending_association)
        # The dropped READY remains valid; its replayed late delivery is harmless.
        ep_init.handle(Receive(link=0, bytes=ready_wire, at_ms=180))

    def test_protected_sample_request_with_unknown_codec_returns_unsupported(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)
        ep_resp.sample_producer.publish(123)

        sequence = 5000
        unsupported_req = ep_init._encrypt_and_encode(
            CoreFrame(
                message_type=0,
                options=0x23,  # SEQ + ACK_REQ + PAYLOAD_DESC
                sequence=sequence,
                payload_descriptor=PayloadDescriptor(flags=0, codec_id=128),
            ),
            plaintext=b"\x01",  # SAMPLE-1 READ
        )
        events = ep_resp.handle(Receive(
            link=0,
            bytes=encode_stream_r(unsupported_req),
            at_ms=200,
        ))

        sender_key = (
            ep_resp.namespace,
            ep_init.local_node_id,
            ep_resp.association.peer_epoch,
            sequence,
        )
        self.assertIn(sender_key, ep_resp.delivery.rejections)
        self.assertEqual(ep_resp.delivery.rejections[sender_key].status, 2)
        self.assertNotIn(sender_key, ep_resp.delivery.retained_results)
        self.assertTrue(any(isinstance(event, TxSubmit) for event in events))

    def test_malformed_protected_sample_telem_is_dropped_without_escaping_receive(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)
        ep_resp.handle(PublishSample(value=321, at_ms=200))
        _extract_and_settle(ep_resp, at_ms=201)

        request_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(ApplicationRequest(service_id=1, payload=b"\x01", ack_req=True, at_ms=210)),
            at_ms=211,
        )
        response_wires = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Receive(link=0, bytes=request_wires[0], at_ms=220)),
            at_ms=221,
        )
        for wire in response_wires:
            ep_init.handle(Receive(link=0, bytes=wire, at_ms=230))
        _extract_and_settle(ep_init, at_ms=231)
        self.assertEqual(ep_init.sample_consumer.state, "synchronized")
        current_sample = ep_init.sample_consumer.cached_sample
        self.assertIsNotNone(current_sample)

        malformed_telem = ep_resp._encrypt_and_encode(
            CoreFrame(message_type=5, options=1, sequence=5000, payload=b""),
            plaintext=b"\xAA" * 15,
        )
        received = ep_init.handle(Receive(
            link=0,
            bytes=encode_stream_r(malformed_telem),
            at_ms=240,
        ))
        self.assertEqual(received, ())
        self.assertIs(ep_init.sample_consumer.cached_sample, current_sample)
        self.assertEqual(ep_init.association.status, "active")

    def test_finish_and_ready_require_the_exact_sec1_control_shape(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        f1_wire = _extract_and_settle(
            ep_init, ep_init.initiate_handshake(at_ms=100), at_ms=101
        )[0]
        f2_wire = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Receive(link=0, bytes=f1_wire, at_ms=110)),
            at_ms=111,
        )[0]
        finish_wire = _extract_and_settle(
            ep_init,
            ep_init.handle(Receive(link=0, bytes=f2_wire, at_ms=120)),
            at_ms=121,
        )[0]
        ready_wires = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Receive(link=0, bytes=finish_wire, at_ms=130)),
            at_ms=131,
        )
        ready_wire = next(
            wire for wire in ready_wires
            if parse_frame(decode_stream_r(wire)).message_type == 3
        )
        self.assertIsNone(ep_init.association)
        candidate = ep_init.pending_association
        self.assertIsNotNone(candidate)

        raw_ready = decode_stream_r(ready_wire)
        missing_seq = bytes((raw_ready[0], raw_ready[1] - 1, raw_ready[2] & ~0x01)) + raw_ready[4:]
        missing_seq_wire = cobs_encode(missing_seq + crc32c(missing_seq).to_bytes(4, "little")) + b"\x00"
        self.assertEqual(
            ep_init.handle(Receive(link=0, bytes=missing_seq_wire, at_ms=139)), ()
        )  # SECURITY requires SEQ; the structural parser drops this before AEAD.
        self.assertIsNone(ep_init.association)
        self.assertIs(ep_init.pending_association, candidate)

        malformed = (
            CoreFrame(message_type=3, options=0x03, sequence=0, payload=b""),  # ACK_REQ forbidden.
            CoreFrame(
                message_type=3,
                options=0x09,
                sequence=0,
                fragment=Fragment(index=0, chunk_size=1, total_length=2),
                payload=b"",
            ),  # FRAG forbidden.
            CoreFrame(
                message_type=3,
                options=0x21,
                sequence=0,
                payload_descriptor=PayloadDescriptor(flags=0, codec_id=1),
                payload=b"",
            ),  # PAYLOAD_DESC forbidden.
            CoreFrame(
                message_type=3,
                options=0x81,
                sequence=0,
                extensions=(Extension(1, True, False, encode_uleb(1)),),  # REPLY_TO forbidden.
                payload=b"",
            ),
            CoreFrame(
                message_type=3,
                options=0x81,
                sequence=0,
                extensions=(Extension(5, True, False, encode_uleb(1)),),  # STATUS forbidden.
                payload=b"",
            ),
            CoreFrame(
                message_type=3,
                options=0x81,
                sequence=0,
                extensions=(Extension(4, True, False, encode_uleb(2)),),  # SERVICE_ID forbidden.
                payload=b"",
            ),
        )
        for index, malformed_frame in enumerate(malformed, start=1):
            bad_ready = ep_resp._encrypt_and_encode(malformed_frame, plaintext=PAYLOAD_READY)
            self.assertEqual(
                ep_init.handle(Receive(
                    link=0,
                    bytes=encode_stream_r(bad_ready),
                    at_ms=140 + index,
                )),
                (),
            )
            self.assertIsNone(ep_init.association)
            self.assertIs(ep_init.pending_association, candidate)
            self.assertEqual(candidate.status, "candidate")

        ep_init.handle(Receive(link=0, bytes=ready_wire, at_ms=150))
        self.assertIs(ep_init.association, candidate)
        self.assertEqual(candidate.status, "active")
        self.assertIsNone(ep_init.pending_association)

    def test_crypto_admission_exhaustion_preserves_the_initiator_noise_state(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        f1 = _extract_and_settle(ep_init, ep_init.initiate_handshake(at_ms=100), at_ms=101)[0]
        f2_wires = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Receive(link=0, bytes=f1, at_ms=110)),
            at_ms=111,
        )
        attempt_id = ep_init.bootstrap_mgr.current_attempt_id
        ep_init._bootstrap_attempt_crypto_ms = ep_init.manifest.values["security"]["crypto_per_attempt_ms"]

        denied = ep_init.handle(Receive(link=0, bytes=f2_wires[0], at_ms=120))
        self.assertEqual(denied, ())
        self.assertEqual(ep_init.bootstrap_mgr.current_attempt_id, attempt_id)
        self.assertIsNotNone(ep_init.bootstrap_mgr.sym_state)
        self.assertIsNone(ep_init.pending_association)

        # Once capacity is available, the same expected flight can be admitted.
        ep_init._bootstrap_attempt_crypto_ms = 0
        ep_init._bootstrap_episode_crypto_ms = 0
        admitted = ep_init.handle(Receive(link=0, bytes=f2_wires[0], at_ms=130))
        self.assertTrue(any(isinstance(event, TxSubmit) for event in admitted))
        self.assertEqual(ep_init.bootstrap_mgr.current_attempt_id, attempt_id)
        self.assertIsNotNone(ep_init.pending_association)

    def test_initiator_entropy_failure_retires_the_endpoint_attempt(self) -> None:
        ep_init, _ = self._setup_pair_nnpsk0()

        def fail_entropy(_size: int) -> bytes:
            raise RuntimeError("entropy unavailable")

        ep_init.entropy_source = fail_entropy
        ep_init.bootstrap_mgr.entropy_source = fail_entropy
        with self.assertRaises(SecurityError):
            ep_init.initiate_handshake(at_ms=100, attempt_id=b"E" * 16)
        self.assertIsNone(ep_init.bootstrap_mgr.current_attempt_id)
        self.assertIsNone(ep_init.bootstrap_mgr.ephemeral_private)
        self.assertIsNone(ep_init.pending_association)
        self.assertIsNone(ep_init._bootstrap_attempt_id)
        self.assertIsNone(ep_init._bootstrap_attempt_start_ms)

    def test_candidate_confirmation_deadline_is_checked_on_receive(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        f1 = _extract_and_settle(ep_init, ep_init.initiate_handshake(at_ms=100), at_ms=101)[0]
        f2_wires = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Receive(link=0, bytes=f1, at_ms=110)),
            at_ms=111,
        )
        finish_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(Receive(link=0, bytes=f2_wires[0], at_ms=120)),
            at_ms=121,
        )
        finish_wire = next(
            wire for wire in finish_wires
            if parse_frame(decode_stream_r(wire)).message_type == 3
        )
        self.assertIsNone(ep_resp.association)
        self.assertIsNotNone(ep_resp.pending_association)
        deadline = (
            ep_resp._bootstrap_attempt_start_ms
            + ep_resp.manifest.values["security"]["attempt_ms"]
        )

        # No Advance event runs first: the protected FINISH itself must enforce
        # the absolute attempt deadline before AEAD or candidate activation.
        late = ep_resp.handle(Receive(link=0, bytes=finish_wire, at_ms=deadline))
        self.assertEqual(late, ())
        self.assertIsNone(ep_resp.association)
        self.assertIsNone(ep_resp.pending_association)
        self.assertIsNone(ep_resp.bootstrap_mgr.current_attempt_id)

    def test_bootstrap_rejects_a_mismatched_provisioned_key_hint_before_noise(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        f1_wire = _extract_and_settle(
            ep_init,
            ep_init.initiate_handshake(at_ms=100),
            at_ms=101,
        )[0]
        f1 = parse_frame(decode_stream_r(f1_wire))
        payload = bytearray(f1.payload)
        payload[64:68] = (2).to_bytes(4, "little")  # Provisioned record expects KEY_HINT=1.
        changed = CoreFrame(
            message_type=f1.message_type,
            options=f1.options,
            sequence=f1.sequence,
            route=f1.route,
            extensions=f1.extensions,
            payload=bytes(payload),
        )
        before_crypto = ep_resp._bootstrap_crypto_window_start_ms
        rejected = ep_resp.handle(Receive(
            link=0,
            bytes=encode_stream_r(encode_frame(changed, max_frame=ep_resp.forward_mtu)),
            at_ms=110,
        ))
        self.assertEqual(rejected, ())
        self.assertIsNone(ep_resp.bootstrap_mgr.current_attempt_id)
        self.assertIsNone(ep_resp._bootstrap_attempt_id)
        self.assertIsNone(ep_resp._bootstrap_crypto_window_start_ms)
        self.assertEqual(ep_resp._bootstrap_crypto_window_start_ms, before_crypto)

    def test_attempt_abort_cancels_borrowed_and_queued_bootstrap_tx(self) -> None:
        # An admitted borrow is canceled on expiry and remains retained until its
        # matching terminal callback.
        ep_init, _ = self._setup_pair_nnpsk0()
        submits = ep_init.initiate_handshake(at_ms=100, attempt_id=b"B" * 16)
        submit = next(event for event in submits if isinstance(event, TxSubmit))
        self.assertEqual(ep_init.handle(TxAdmit(
            handle=submit.handle, generation=submit.generation, accepted=True, reason=None, at_ms=101
        )), ())
        deadline = (
            ep_init._bootstrap_attempt_start_ms
            + ep_init.manifest.values["security"]["attempt_ms"]
        )
        timeout_events = ep_init.handle(Advance(now_ms=deadline))
        self.assertTrue(any(
            isinstance(event, Cancel)
            and event.handle == submit.handle
            and event.generation == submit.generation
            for event in timeout_events
        ))
        self.assertIn(submit.handle, ep_init.active_submissions)
        self.assertTrue(ep_init.active_submissions[submit.handle]["cancel_requested"])
        ep_init.handle(TxTerminal(
            handle=submit.handle,
            generation=submit.generation,
            outcome="cancelled_unsent",
            at_ms=deadline + 1,
        ))
        self.assertNotIn(submit.handle, ep_init.active_submissions)

        late_ep, _ = self._setup_pair_nnpsk0()
        late_submits = late_ep.initiate_handshake(at_ms=100, attempt_id=b"L" * 16)
        late_submit = next(event for event in late_submits if isinstance(event, TxSubmit))
        late_deadline = (
            late_ep._bootstrap_attempt_start_ms
            + late_ep.manifest.values["security"]["attempt_ms"]
        )
        late_ep.handle(Advance(now_ms=late_deadline))
        self.assertTrue(late_ep.active_submissions[late_submit.handle]["cancel_requested"])
        late_admit = late_ep.handle(TxAdmit(
            handle=late_submit.handle,
            generation=late_submit.generation,
            accepted=True,
            reason=None,
            at_ms=late_deadline + 1,
        ))
        self.assertTrue(any(
            isinstance(event, Cancel) and event.handle == late_submit.handle
            for event in late_admit
        ))
        late_ep.handle(TxTerminal(
            handle=late_submit.handle,
            generation=late_submit.generation,
            outcome="cancelled_unsent",
            at_ms=late_deadline + 2,
        ))
        self.assertNotIn(late_submit.handle, late_ep.active_submissions)

        # An unrelated service-0 TX queued behind full adapter slots survives
        # while the aborted bootstrap item is removed.
        queued_ep, _ = self._setup_pair_nnpsk0()
        filler_events: list[Any] = []
        filler_frame = encode_frame(CoreFrame(message_type=5, options=0, payload=b"\x00" * 16))
        for _ in range(queued_ep.adapter_slots):
            queued_ep._enqueue_tx(filler_frame, not_after_ms=None, service_id=0, out=filler_events)
        queued_ep._enqueue_tx(filler_frame, not_after_ms=None, service_id=0, out=filler_events)
        queued_ep.initiate_handshake(at_ms=100, attempt_id=b"Q" * 16)
        self.assertTrue(any(item.get("bootstrap_attempt_id") == b"Q" * 16 for item in queued_ep.tx_queue))
        queue_deadline = (
            queued_ep._bootstrap_attempt_start_ms
            + queued_ep.manifest.values["security"]["attempt_ms"]
        )
        queued_ep.handle(Advance(now_ms=queue_deadline))
        self.assertFalse(any(item.get("bootstrap_attempt_id") is not None for item in queued_ep.tx_queue))
        self.assertEqual(len(queued_ep.tx_queue), 1)
        self.assertEqual(queued_ep.tx_queue[0]["service_id"], 0)

    def test_queued_bootstrap_tx_expires_on_terminal_without_advance(self) -> None:
        ep, _ = self._setup_pair_nnpsk0()
        filler_frame = encode_frame(CoreFrame(message_type=5, options=0, payload=b"filler"))
        filler_events: list[Any] = []
        for _ in range(ep.adapter_slots):
            ep._enqueue_tx(filler_frame, not_after_ms=None, service_id=0, out=filler_events)
        fillers = [event for event in filler_events if isinstance(event, TxSubmit)]
        for event in fillers:
            ep.handle(TxAdmit(
                handle=event.handle,
                generation=event.generation,
                accepted=True,
                reason=None,
                at_ms=101,
            ))

        attempt_id = b"D" * 16
        self.assertEqual(ep.initiate_handshake(at_ms=110, attempt_id=attempt_id), ())
        queued = next(item for item in ep.tx_queue if item.get("bootstrap_attempt_id") == attempt_id)
        deadline = ep._bootstrap_attempt_start_ms + ep.manifest.values["security"]["attempt_ms"]
        self.assertEqual(queued["not_after_ms"], deadline)

        terminal_events = ep.handle(TxTerminal(
            handle=fillers[0].handle,
            generation=fillers[0].generation,
            outcome="transmitted",
            at_ms=deadline,
        ))
        self.assertFalse(any(isinstance(event, TxSubmit) for event in terminal_events))
        self.assertFalse(any(item.get("bootstrap_attempt_id") is not None for item in ep.tx_queue))
        self.assertIsNone(ep.bootstrap_mgr.current_attempt_id)
        self.assertIsNone(ep.pending_association)

    def test_security_rejection_cannot_be_upgraded_under_the_same_identity(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)
        seq = 4242
        rejected_frame = ep_init._build_req_frames(
            service_id=1,
            seq=seq,
            payload=b"\x03",  # Not an authorized SAMPLE-1 request opcode.
            ack_req=True,
        )[0]
        rejection_out = ep_resp.handle(Receive(
            link=0,
            bytes=encode_stream_r(rejected_frame),
            at_ms=210,
        ))
        rejection_key = (1, ep_init.local_node_id, ep_init.local_epoch, seq)
        self.assertIn(rejection_key, ep_resp.delivery.rejections)
        self.assertFalse(any(
            isinstance(event, ApplicationEvent) and event.kind == "request_accepted"
            for event in rejection_out
        ))
        _extract_and_settle(ep_resp, rejection_out, at_ms=211)

        upgraded_frame = ep_init._build_req_frames(
            service_id=1,
            seq=seq,
            payload=b"\x01",  # A permitted READ cannot replace the retained denial.
            ack_req=True,
        )[0]
        upgraded_out = ep_resp.handle(Receive(
            link=0,
            bytes=encode_stream_r(upgraded_frame),
            at_ms=220,
        ))
        self.assertEqual(upgraded_out, ())
        self.assertNotIn(rejection_key, ep_resp.delivery.accepted_messages)
        self.assertNotIn(rejection_key, ep_resp.delivery.retained_results)

    def test_freshness_rejection_cannot_be_upgraded_by_adding_a_token(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0(
            manifest_bytes=_load_manifest_bytes("radio-nnpsk0.json")
        )
        self._perform_nnpsk0_handshake(ep_init, ep_resp)
        grant_request = b"\x10" + (1000).to_bytes(4, "little")
        grant_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(ApplicationRequest(service_id=0, payload=grant_request, ack_req=True, at_ms=200)),
            at_ms=201,
        )
        grant_responses = _extract_and_settle(
            ep_resp,
            ep_resp.handle(Receive(link=0, bytes=grant_wires[0], at_ms=210)),
            at_ms=211,
        )
        for wire in grant_responses:
            grant_events = ep_init.handle(Receive(link=0, bytes=wire, at_ms=220))
            _extract_and_settle(ep_init, grant_events, at_ms=221)
        token = ep_init.active_freshness_token
        self.assertIsNotNone(token)

        seq = 5151
        payload = b"freshness-upgrade"
        missing_token_frame = ep_init._build_req_frames(
            service_id=2, seq=seq, payload=payload, ack_req=True, freshness_token=None
        )[0]
        denied = ep_resp.handle(Receive(link=0, bytes=missing_token_frame, at_ms=230))
        rejection_key = (1, ep_init.local_node_id, ep_init.local_epoch, seq)
        self.assertIn(rejection_key, ep_resp.delivery.rejections)
        _extract_and_settle(ep_resp, denied, at_ms=231)

        with_token_frame = ep_init._build_req_frames(
            service_id=2, seq=seq, payload=payload, ack_req=True, freshness_token=token
        )[0]
        upgraded = ep_resp.handle(Receive(link=0, bytes=with_token_frame, at_ms=240))
        self.assertEqual(upgraded, ())
        self.assertNotIn(rejection_key, ep_resp.delivery.accepted_messages)
        self.assertNotIn(rejection_key, ep_resp.delivery.retained_results)

    def test_authenticated_data_requires_the_data_acl_action(self) -> None:
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)
        frame = CoreFrame(
            message_type=7,
            options=0x01,
            sequence=4243,
            payload=b"unauthorized-data",
        )
        wire = ep_init._encrypt_and_encode(frame, plaintext=b"unauthorized-data")
        out = ep_resp.handle(Receive(link=0, bytes=encode_stream_r(wire), at_ms=210))
        key = (1, ep_init.local_node_id, ep_init.local_epoch, 4243)
        self.assertEqual(out, ())
        self.assertNotIn(key, ep_resp.delivery.accepted_messages)

    def test_s10_18_protected_fixed_stride_reassembly_and_changed_payload_duplicate(self) -> None:
        """S10.18: Protected fixed-stride reassembly rejects altered slice duplicate."""
        ep_init, ep_resp = self._setup_pair_nnpsk0()
        self._perform_nnpsk0_handshake(ep_init, ep_resp)

        # Send 100 bytes on Service 2 (2 slices: 64, 36)
        payload = bytes(range(100))
        req_wires = _extract_and_settle(
            ep_init,
            ep_init.handle(ApplicationRequest(service_id=2, payload=payload, ack_req=True, at_ms=210)),
            at_ms=211,
        )
        self.assertEqual(len(req_wires), 2)

        # Deliver slice 0
        ep_resp.handle(Receive(link=0, bytes=req_wires[0], at_ms=220))
        _extract_and_settle(ep_resp, at_ms=221)

        # Inject duplicate slice 0 with corrupted ciphertext (fails AEAD tag)
        raw_slice0 = bytearray(decode_stream_r(req_wires[0]))
        raw_slice0[-1] ^= 0xFF
        ep_resp.handle(Receive(link=0, bytes=encode_stream_r(bytes(raw_slice0)), at_ms=225))

        # A validly authenticated but changed duplicate slice conflicts with the
        # still-incomplete assembly and cannot replace the original bytes.
        req_seq = parse_frame(decode_stream_r(req_wires[0])).sequence
        changed_frames = ep_init._build_req_frames(
            service_id=2,
            seq=req_seq,
            payload=bytes([payload[0] ^ 0xFF]) + payload[1:],
            ack_req=True,
        )
        changed_first = encode_stream_r(changed_frames[0])
        conflict_events = ep_resp.handle(Receive(link=0, bytes=changed_first, at_ms=227))
        self.assertFalse(any(
            isinstance(e, ApplicationEvent) and e.kind == "request_accepted" for e in conflict_events
        ))

        # Deliver authentic slice 1 -> reassembly completes successfully despite tampered duplicate
        accepted_events = ep_resp.handle(Receive(link=0, bytes=req_wires[1], at_ms=230))
        self.assertTrue(any(
            isinstance(e, ApplicationEvent) and e.kind == "request_accepted" for e in accepted_events
        ))
        _extract_and_settle(ep_resp, accepted_events, at_ms=231)
        self.assertIn((1, 20, ep_init.local_epoch, 1), ep_resp.delivery.accepted_messages)

        # After acceptance, changed plaintext with the same immutable identity
        # receives the original retained result and never re-executes the service.
        changed_after_accept = ep_init._build_req_frames(
            service_id=2,
            seq=req_seq,
            payload=bytes([payload[0] ^ 0xFF]) + payload[1:],
            ack_req=True,
        )
        changed_replay = encode_stream_r(changed_after_accept[0])
        duplicate_events = ep_resp.handle(Receive(link=0, bytes=changed_replay, at_ms=240))
        self.assertFalse(any(
            isinstance(e, ApplicationEvent) and e.kind == "request_accepted" for e in duplicate_events
        ))
        self.assertTrue(any(isinstance(e, TxSubmit) for e in duplicate_events))
        _extract_and_settle(ep_resp, duplicate_events, at_ms=241)


if __name__ == "__main__":
    unittest.main()
