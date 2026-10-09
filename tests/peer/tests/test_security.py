"""Tests for independent SEC-1 cryptographic state machine, vectors, and primitives."""

import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from dmp_peer.frame import CoreFrame, Extension, Security, encode_frame, parse_frame
from dmp_peer.security import (
    BOOT_VERSION,
    MODE_NNPSK0,
    MODE_XX,
    AuthenticationError,
    BootstrapManager,
    CipherState,
    FreshnessManager,
    FreshnessError,
    HandshakeError,
    ReplayError,
    ReplayWindow,
    SecurityAssociation,
    SecurityError,
    SymmetricState,
    compute_bootstrap_epoch,
    compute_canonical_header,
    compute_origin_epoch,
    compute_prologue,
    hkdf_extract_and_expand,
    x25519_dh,
)


def _load_vectors() -> dict:
    path = Path(__file__).parents[3] / "docs" / "DMP_v2_Security_Test_Vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))


class SecurityPrimitivesAndVectorsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors_data = _load_vectors()

    def test_hkdf_basic(self):
        prk, out1 = hkdf_extract_and_expand(b"\x00" * 32, b"input_key", 2)
        self.assertEqual(len(prk), 32)
        self.assertEqual(len(out1), 32)

    def test_x25519_low_order_rejected(self):
        priv = x25519.X25519PrivateKey.generate()
        with self.assertRaises(HandshakeError):
            x25519_dh(priv, b"\x00" * 32)

    def test_canonical_header_ttl_normalization(self):
        # Frame with ROUTE: TTL=3, mode=1 (TO_NODE)
        header = bytes.fromhex("4018c702310a140109020b09012788848bb24c6759110102")
        canonical = compute_canonical_header(header)
        # Byte at offset 4 had 0x31 -> should become 0x01
        self.assertEqual(canonical[4], 0x01)
        self.assertEqual(canonical[:4], header[:4])
        self.assertEqual(canonical[5:], header[5:])

    def test_canonical_header_unrouted(self):
        header = bytes.fromhex("43074100010900")
        canonical = compute_canonical_header(header)
        self.assertEqual(canonical, header)

    def test_vector_0_nnpsk0_chachapoly(self):
        v = self.vectors_data["vectors"][0]
        self.assertEqual(v["protocol_name"], "Noise_NNpsk0_25519_ChaChaPoly_SHA256")

        inputs = v["test_only_inputs"]
        attempt_id = bytes.fromhex(inputs["attempt_id"])
        psk = bytes.fromhex(inputs["psk"])
        init_e = bytes.fromhex(inputs["init_ephemeral"])
        resp_e = bytes.fromhex(inputs["resp_ephemeral"])

        # 1. Bootstrap epoch
        b_epoch = compute_bootstrap_epoch(attempt_id)
        self.assertEqual(str(b_epoch), v["bootstrap_epoch"])

        # 2. Prologue from Flight 1 prefix
        f1_payload = bytes.fromhex(v["flights"][0]["bootstrap_payload"])
        f1_prefix = f1_payload[:72]
        prologue = compute_prologue(f1_prefix)
        self.assertEqual(prologue.hex(), v["prologue"])

        # 3. Simulate initiator building flight 1
        mgr_init = BootstrapManager(
            mode=MODE_NNPSK0,
            manifest_digest=bytes.fromhex(inputs["profile_hash"]),
            namespace=1,
            local_node_id=10,
            remote_node_id=20,
            entropy_source=lambda n: init_e,
            psk=psk,
            key_hint=5,
            local_rx_cid=7,
        )
        _, f1_built = mgr_init.build_flight_1(attempt_id, at_ms=10)
        self.assertEqual(f1_built.hex(), v["flights"][0]["bootstrap_payload"])

        # 4. Simulate responder processing flight 1 and building flight 2
        mgr_resp = BootstrapManager(
            mode=MODE_NNPSK0,
            manifest_digest=bytes.fromhex(inputs["profile_hash"]),
            namespace=1,
            local_node_id=20,
            remote_node_id=10,
            entropy_source=lambda n: resp_e,
            psk=psk,
            key_hint=5,
            local_rx_cid=9,
        )
        _, f2_built = mgr_resp.process_flight_1(f1_built, at_ms=12)
        self.assertEqual(f2_built.hex(), v["flights"][1]["bootstrap_payload"])

        # 5. Initiator processes flight 2
        mgr_init.process_flight_2(f2_built, at_ms=14)

        # 6. Verify handshake completion
        self.assertTrue(mgr_init.handshake_completed)
        self.assertTrue(mgr_resp.handshake_completed)
        self.assertEqual(mgr_init.sym_state.h.hex(), v["handshake_hash"])
        self.assertEqual(mgr_resp.sym_state.h.hex(), v["handshake_hash"])

        # 7. Create associations and verify keys and epochs
        assoc_init = mgr_init.create_association(is_initiator=True, at_ms=14)
        assoc_resp = mgr_resp.create_association(is_initiator=False, at_ms=14)

        self.assertEqual(assoc_init.send_key.hex(), v["i_to_r_key"])
        self.assertEqual(assoc_init.recv_key.hex(), v["r_to_i_key"])
        self.assertEqual(assoc_resp.send_key.hex(), v["r_to_i_key"])
        self.assertEqual(assoc_resp.recv_key.hex(), v["i_to_r_key"])

        self.assertEqual(str(assoc_init.local_epoch), v["origin_epochs"][0])
        self.assertEqual(str(assoc_init.peer_epoch), v["origin_epochs"][1])
        self.assertEqual(str(assoc_resp.local_epoch), v["origin_epochs"][1])
        self.assertEqual(str(assoc_resp.peer_epoch), v["origin_epochs"][0])

        # 8. Verify published packets
        for pkt in v["packets"]:
            direction = pkt["direction"]
            sender = assoc_init if direction == 0 else assoc_resp
            receiver = assoc_resp if direction == 0 else assoc_init

            hdr = bytes.fromhex(pkt["header"])
            pt = bytes.fromhex(pkt["plaintext"])
            sender.next_send_pn = pkt["pn"]
            pn, ct_and_tag = sender.encrypt_frame(hdr, pt)

            self.assertEqual(pn, pkt["pn"])
            self.assertEqual(ct_and_tag[:-16].hex(), pkt["ciphertext"])
            self.assertEqual(ct_and_tag[-16:].hex(), pkt["tag"])

            receiver.replay_window.h = None
            receiver.replay_window.bitmap = 0
            decrypted = receiver.decrypt_frame(
                hdr,
                ct_and_tag[:-16],
                ct_and_tag[-16:],
                pn=pn,
                rx_cid=receiver.local_rx_cid,
            )
            self.assertEqual(decrypted, pt)

        # 9. Verify mutations fail decryption
        for mut in v["mutations"]:
            corrupt = bytes.fromhex(mut["frame"])
            hdr_len = corrupt[1]
            c_hdr = corrupt[:hdr_len]
            c_ct = corrupt[hdr_len:-16]
            c_tag = corrupt[-16:]
            with self.assertRaises(SecurityError):
                assoc_resp.decrypt_frame(c_hdr, c_ct, c_tag, pn=0, rx_cid=assoc_resp.local_rx_cid)

    def test_nnpsk0_flight1_requires_the_provisioned_key_hint(self):
        v = self.vectors_data["vectors"][0]
        inputs = v["test_only_inputs"]
        f1_payload = bytes.fromhex(v["flights"][0]["bootstrap_payload"])
        manager = BootstrapManager(
            mode=MODE_NNPSK0,
            manifest_digest=bytes.fromhex(inputs["profile_hash"]),
            namespace=1,
            local_node_id=20,
            remote_node_id=10,
            entropy_source=lambda n: b"R" * n,
            psk=bytes.fromhex(inputs["psk"]),
            key_hint=6,
            local_rx_cid=9,
        )
        with self.assertRaisesRegex(HandshakeError, "KEY_HINT"):
            manager.process_flight_1(f1_payload, at_ms=12)
        self.assertIsNone(manager.current_attempt_id)

    def test_noise_dh_failure_aborts_the_mutated_attempt(self):
        v = self.vectors_data["vectors"][0]
        inputs = v["test_only_inputs"]
        attempt_id = bytes.fromhex(inputs["attempt_id"])
        psk = bytes.fromhex(inputs["psk"])
        init_e = bytes.fromhex(inputs["init_ephemeral"])
        resp_e = bytes.fromhex(inputs["resp_ephemeral"])
        init = BootstrapManager(
            mode=MODE_NNPSK0,
            manifest_digest=bytes.fromhex(inputs["profile_hash"]),
            namespace=1,
            local_node_id=10,
            remote_node_id=20,
            entropy_source=lambda n: init_e,
            psk=psk,
            key_hint=5,
            local_rx_cid=7,
        )
        resp = BootstrapManager(
            mode=MODE_NNPSK0,
            manifest_digest=bytes.fromhex(inputs["profile_hash"]),
            namespace=1,
            local_node_id=20,
            remote_node_id=10,
            entropy_source=lambda n: resp_e,
            psk=psk,
            key_hint=5,
            local_rx_cid=9,
        )
        _, f1 = init.build_flight_1(attempt_id, at_ms=10)
        _, f2 = resp.process_flight_1(f1, at_ms=12)
        corrupted = bytearray(f2)
        corrupted[18:50] = b"\x00" * 32  # Low-order responder ephemeral after Noise mutation begins.
        with self.assertRaises(HandshakeError):
            init.process_flight_2(bytes(corrupted), at_ms=14)
        self.assertTrue(init.attempt_aborted)
        self.assertIsNone(init.current_attempt_id)
        self.assertIsNone(init.sym_state)
        self.assertIsNone(init.ephemeral_private)

    def test_flight1_entropy_failure_erases_partial_manager_state(self):
        def fail_entropy(_size):
            raise RuntimeError("entropy unavailable")

        manager = BootstrapManager(
            mode=MODE_NNPSK0,
            manifest_digest=b"D" * 32,
            namespace=1,
            local_node_id=10,
            remote_node_id=20,
            entropy_source=fail_entropy,
            psk=b"P" * 32,
            local_rx_cid=1,
        )
        with self.assertRaises(HandshakeError):
            manager.build_flight_1(b"A" * 16, at_ms=10)
        self.assertTrue(manager.attempt_aborted)
        self.assertIsNone(manager.current_attempt_id)
        self.assertIsNone(manager.sym_state)

    def test_vector_2_xx_chachapoly(self):
        v = self.vectors_data["vectors"][2]
        self.assertEqual(v["protocol_name"], "Noise_XX_25519_ChaChaPoly_SHA256")

        inputs = v["test_only_inputs"]
        attempt_id = bytes.fromhex(inputs["attempt_id"])
        init_e = bytes.fromhex(inputs["init_ephemeral"])
        resp_e = bytes.fromhex(inputs["resp_ephemeral"])
        init_s = bytes.fromhex(inputs["init_static"])
        resp_s = bytes.fromhex(inputs["resp_static"])

        # Initiator
        mgr_init = BootstrapManager(
            mode=MODE_XX,
            manifest_digest=bytes.fromhex(inputs["profile_hash"]),
            namespace=1,
            local_node_id=10,
            remote_node_id=20,
            entropy_source=lambda n: init_e,
            static_private_key=init_s,
            peer_static_public_key=x25519.X25519PrivateKey.from_private_bytes(resp_s).public_key().public_bytes_raw(),
            key_hint=0,
            local_rx_cid=7,
        )
        _, f1_built = mgr_init.build_flight_1(attempt_id, at_ms=10)
        self.assertEqual(f1_built.hex(), v["flights"][0]["bootstrap_payload"])

        # Responder
        mgr_resp = BootstrapManager(
            mode=MODE_XX,
            manifest_digest=bytes.fromhex(inputs["profile_hash"]),
            namespace=1,
            local_node_id=20,
            remote_node_id=10,
            entropy_source=lambda n: resp_e,
            static_private_key=resp_s,
            peer_static_public_key=x25519.X25519PrivateKey.from_private_bytes(init_s).public_key().public_bytes_raw(),
            local_rx_cid=9,
        )
        _, f2_built = mgr_resp.process_flight_1(f1_built, at_ms=12)
        self.assertEqual(f2_built.hex(), v["flights"][1]["bootstrap_payload"])

        # Initiator processes flight 2 and builds flight 3
        _, f3_built = mgr_init.process_flight_2(f2_built, at_ms=14)
        self.assertEqual(f3_built.hex(), v["flights"][2]["bootstrap_payload"])

        # Responder processes flight 3
        mgr_resp.process_flight_3(f3_built, at_ms=16)

        self.assertTrue(mgr_init.handshake_completed)
        self.assertTrue(mgr_resp.handshake_completed)
        self.assertEqual(mgr_init.sym_state.h.hex(), v["handshake_hash"])
        self.assertEqual(mgr_resp.sym_state.h.hex(), v["handshake_hash"])

        assoc_init = mgr_init.create_association(is_initiator=True, at_ms=16)
        assoc_resp = mgr_resp.create_association(is_initiator=False, at_ms=16)

        self.assertEqual(assoc_init.send_key.hex(), v["i_to_r_key"])
        self.assertEqual(assoc_init.recv_key.hex(), v["r_to_i_key"])
        self.assertEqual(assoc_resp.send_key.hex(), v["r_to_i_key"])
        self.assertEqual(assoc_resp.recv_key.hex(), v["i_to_r_key"])

        self.assertEqual(str(assoc_init.local_epoch), v["origin_epochs"][0])
        self.assertEqual(str(assoc_init.peer_epoch), v["origin_epochs"][1])


class ReplayWindowAndLifecycleTests(unittest.TestCase):
    def test_replay_window_in_order(self):
        w = ReplayWindow(1024)
        for pn in range(100):
            self.assertTrue(w.check(pn))
            w.commit(pn)
            self.assertFalse(w.check(pn))  # Duplicate rejected

    def test_replay_window_reordering(self):
        w = ReplayWindow(1024)
        w.commit(5)
        self.assertTrue(w.check(4))
        self.assertTrue(w.check(3))
        self.assertTrue(w.check(6))
        w.commit(3)
        self.assertFalse(w.check(3))
        self.assertTrue(w.check(4))

    def test_replay_window_below_window(self):
        w = ReplayWindow(64)
        w.commit(100)
        self.assertFalse(w.check(35))  # 100 - 35 = 65 >= 64 -> rejected!
        self.assertTrue(w.check(37))   # 100 - 37 = 63 < 64 -> accepted!

    def test_replay_window_shift_larger_than_window(self):
        w = ReplayWindow(64)
        w.commit(10)
        w.commit(200)  # shift = 190 >= 64: resets bitmap
        self.assertFalse(w.check(10))
        self.assertTrue(w.check(199))

    def test_replay_window_bounded_bitmap_length(self):
        # 1. Test bounded bitmap length after many sequential commits for W=64 and W=1024,
        # starting from PN=0.
        for w_size in (64, 1024):
            w = ReplayWindow(w_size)
            # PN=0 behavior
            self.assertTrue(w.check(0))
            w.commit(0)
            self.assertEqual(w.h, 0)
            self.assertEqual(w.bitmap, 1)
            self.assertEqual(w.bitmap & 1, 1)
            self.assertLessEqual(w.bitmap.bit_length(), w_size)
            self.assertEqual(w.bitmap >> w_size, 0)
            self.assertFalse(w.check(0))

            # Many sequential commits (exceeding window_size many times over)
            for pn in range(1, 2000):
                self.assertTrue(w.check(pn))
                w.commit(pn)
                self.assertEqual(w.h, pn)
                self.assertEqual(w.bitmap & 1, 1)
                self.assertEqual(w.bitmap >> w_size, 0)
                self.assertLessEqual(w.bitmap.bit_length(), w_size)
                self.assertFalse(w.check(pn))

        # 2. Test bounded bitmap length with out-of-order and reordered arrivals
        w64 = ReplayWindow(64)
        # Advance with bursts and out-of-order fills
        w64.commit(100)
        self.assertEqual(w64.bitmap & 1, 1)
        self.assertEqual(w64.bitmap >> 64, 0)
        self.assertLessEqual(w64.bitmap.bit_length(), 64)

        # In-window arrivals in non-monotonic order
        for pn in (90, 80, 95, 70, 85, 60):
            self.assertTrue(w64.check(pn))
            w64.commit(pn)
            self.assertEqual(w64.bitmap & 1, 1)
            self.assertEqual(w64.bitmap >> 64, 0)
            self.assertLessEqual(w64.bitmap.bit_length(), 64)
            self.assertFalse(w64.check(pn))

        # Reordering test with W=1024
        w1024 = ReplayWindow(1024)
        for base in range(0, 3000, 200):
            w1024.commit(base)
            self.assertEqual(w1024.bitmap & 1, 1)
            self.assertEqual(w1024.bitmap >> 1024, 0)
            self.assertLessEqual(w1024.bitmap.bit_length(), 1024)

            # Insert out-of-order packets within current window
            for offset in (5, 50, 150, 20, 80):
                target = base - offset
                if target >= 0 and w1024.check(target):
                    w1024.commit(target)
                    self.assertEqual(w1024.bitmap & 1, 1)
                    self.assertEqual(w1024.bitmap >> 1024, 0)
                    self.assertLessEqual(w1024.bitmap.bit_length(), 1024)
                    self.assertFalse(w1024.check(target))

        # 3. Test jump >= window_size resets bitmap and maintains invariants
        w64.commit(5000)
        self.assertEqual(w64.h, 5000)
        self.assertEqual(w64.bitmap, 1)
        self.assertEqual(w64.bitmap & 1, 1)
        self.assertEqual(w64.bitmap >> 64, 0)
        self.assertLessEqual(w64.bitmap.bit_length(), 64)

    def test_replay_window_exact_boundary_shifts(self):
        # Test shift == window_size - 1 preserves the oldest bit at offset W-1
        w = ReplayWindow(64)
        w.commit(10)
        # Shift by 63 (64 - 1): new H = 73
        w.commit(73)
        self.assertEqual(w.h, 73)
        self.assertEqual(w.bitmap & 1, 1)
        self.assertEqual(w.bitmap >> 64, 0)
        self.assertLessEqual(w.bitmap.bit_length(), 64)
        # Old PN 10 is at diff = 73 - 10 = 63, which is bit 63
        self.assertEqual((w.bitmap >> 63) & 1, 1)
        self.assertFalse(w.check(10))  # Duplicate
        self.assertTrue(w.check(11))   # Bit 62 is 0 -> accepted
        self.assertFalse(w.check(9))    # diff = 64 >= 64 -> below window

        # Duplicate commit is idempotent and preserves bit 0
        prev_bitmap = w.bitmap
        w.commit(10)
        self.assertEqual(w.bitmap, prev_bitmap)
        self.assertEqual(w.h, 73)
        self.assertEqual(w.bitmap & 1, 1)

        # Below-window commit leaves bitmap and h unchanged
        w.commit(9)
        self.assertEqual(w.bitmap, prev_bitmap)
        self.assertEqual(w.h, 73)
        self.assertEqual(w.bitmap & 1, 1)

        # Test shift == window_size (exact boundary) evicts old bits and sets bitmap = 1
        w2 = ReplayWindow(64)
        w2.commit(10)
        # Shift by 64: new H = 74
        w2.commit(74)
        self.assertEqual(w2.h, 74)
        self.assertEqual(w2.bitmap, 1)
        self.assertEqual(w2.bitmap & 1, 1)
        self.assertEqual(w2.bitmap >> 64, 0)
        self.assertLessEqual(w2.bitmap.bit_length(), 64)
        self.assertFalse(w2.check(10))  # diff = 64 >= 64 -> below window
        self.assertTrue(w2.check(11))   # diff = 63 < 64 -> accepted


    def test_failed_aead_limit_closes_association(self):
        assoc = SecurityAssociation(
            h=b"\x01" * 32,
            send_key=b"\x02" * 32,
            recv_key=b"\x03" * 32,
            local_rx_cid=10,
            peer_rx_cid=20,
            local_epoch=1,
            peer_epoch=2,
            is_initiator=True,
            failed_aead_limit=3,
        )
        self.assertEqual(assoc.status, "candidate")
        for i in range(2):
            with self.assertRaises(AuthenticationError):
                assoc.decrypt_frame(b"\x00" * 4, b"ct", b"\x00" * 16, pn=i, rx_cid=10)
            self.assertNotEqual(assoc.status, "closed")

        # 3rd failure closes association
        with self.assertRaises(AuthenticationError):
            assoc.decrypt_frame(b"\x00" * 4, b"ct", b"\x00" * 16, pn=2, rx_cid=10)
        self.assertEqual(assoc.status, "closed")

        # After closure, encryption/decryption are rejected
        with self.assertRaises(SecurityError):
            assoc.encrypt_frame(b"\x00" * 4, b"pt")

    def test_freshness_manager_grants_and_tokens(self):
        mgr = FreshnessManager(entropy_source=lambda n: b"\x42" * n)
        tok, granted = mgr.issue_grant(
            association_h=b"assoc_1",
            requester_id=10,
            requested_lifetime_ms=5000,
            at_ms=100,
        )
        self.assertEqual(tok, b"\x42" * 16)
        self.assertEqual(granted, 5000)

        # Valid before expiry
        msg_id = (1, 10, 7, 1)
        self.assertTrue(mgr.validate_command_token(tok, b"assoc_1", 10, msg_id, at_ms=2000))
        # Wrong association rejected
        self.assertFalse(mgr.validate_command_token(tok, b"assoc_2", 10, msg_id, at_ms=2000))
        # Wrong requester rejected
        self.assertFalse(mgr.validate_command_token(tok, b"assoc_1", 20, msg_id, at_ms=2000))
        # Expired rejected
        self.assertFalse(mgr.validate_command_token(tok, b"assoc_1", 10, msg_id, at_ms=6000))

        # Consumed token cannot bind to different identity
        mgr.consume_token(tok)
        self.assertFalse(mgr.validate_command_token(tok, b"assoc_1", 10, (1, 10, 7, 2), at_ms=2000))
        # But can re-validate same accepted identity
        self.assertTrue(mgr.validate_command_token(tok, b"assoc_1", 10, msg_id, at_ms=2000))

    def test_freshness_manager_bounds_grants_and_expires_at_exact_deadline(self):
        counter = 0

        def entropy(n):
            nonlocal counter
            counter += 1
            return counter.to_bytes(n, "little")

        mgr = FreshnessManager(entropy_source=entropy)
        token, granted = mgr.issue_grant(
            association_h=b"assoc_1",
            requester_id=10,
            requested_lifetime_ms=50,
            at_ms=100,
            max_policy_ms=40,
            max_tokens_per_association=1,
            max_tokens_per_principal=1,
            max_requests_per_pair=2,
            token_record_ms=80,
        )
        self.assertEqual(granted, 40)
        identity = (1, 10, 7, 5)
        self.assertTrue(mgr.validate_command_token(token, b"assoc_1", 10, identity, at_ms=139))

        # The retained token record continues to occupy quotas after its lease expires.
        self.assertIsNone(mgr.issue_grant(
            association_h=b"assoc_1",
            requester_id=10,
            requested_lifetime_ms=10,
            at_ms=139,
            max_policy_ms=40,
            max_tokens_per_association=1,
            max_tokens_per_principal=1,
            max_requests_per_pair=2,
            token_record_ms=40,
        ))
        self.assertFalse(mgr.validate_command_token(token, b"assoc_1", 10, identity, at_ms=140))
        self.assertIsNone(mgr.issue_grant(
            association_h=b"assoc_1",
            requester_id=11,
            requested_lifetime_ms=10,
            at_ms=140,
            max_policy_ms=40,
            max_tokens_per_association=1,
            max_tokens_per_principal=1,
            max_requests_per_pair=2,
            token_record_ms=80,
        ))
        # Association retirement clears grants and request counters.
        mgr.clear_association(b"assoc_1")
        next_token, next_granted = mgr.issue_grant(
            association_h=b"assoc_1",
            requester_id=10,
            requested_lifetime_ms=10,
            at_ms=180,
            max_policy_ms=40,
            max_tokens_per_association=1,
            max_tokens_per_principal=1,
            max_requests_per_pair=1,
            token_record_ms=40,
        )
        self.assertEqual(next_granted, 10)
        self.assertNotEqual(next_token, token)

    def test_freshness_manager_does_not_replace_existing_token_on_collision(self):
        mgr = FreshnessManager(entropy_source=lambda n: b"\x55" * n)
        token, _ = mgr.issue_grant(
            b"assoc_1", 10, 100, 100, max_policy_ms=100, token_record_ms=100
        )
        identity = (1, 10, 7, 1)
        self.assertTrue(mgr.validate_command_token(token, b"assoc_1", 10, identity, 101))
        with self.assertRaises(FreshnessError):
            mgr.issue_grant(
                b"assoc_1", 10, 100, 102, max_policy_ms=100,
                max_tokens_per_association=4, max_tokens_per_principal=4,
                max_requests_per_pair=4, token_record_ms=100,
            )
        self.assertIs(mgr.grants[token].bound_identity, identity)

    def test_freshness_manager_binds_lease_to_service_and_message(self):
        mgr = FreshnessManager(entropy_source=lambda n: b"\x66" * n)
        token, _ = mgr.issue_grant(b"assoc_1", 10, 500, 10, token_record_ms=500)
        identity = (1, 10, 7, 8)
        digest = b"request-message-digest"
        self.assertTrue(mgr.validate_command_token(
            token, b"assoc_1", 10, identity, at_ms=20, service_id=2, message_digest=digest
        ))
        self.assertFalse(mgr.validate_command_token(
            token, b"assoc_1", 10, identity, at_ms=21, service_id=1, message_digest=digest
        ))
        self.assertFalse(mgr.validate_command_token(
            token, b"assoc_1", 10, identity, at_ms=21, service_id=2, message_digest=b"changed"
        ))


if __name__ == "__main__":
    unittest.main()
