"""Independent Python peer regression for protected FRAG_STATUS test vectors.

Implements tightly scoped byte-level verification of published recovery vectors
(docs/DMP_v2_Recovery_Test_Vectors.json) against the independent Python peer
implementation in dmp_peer, closing the sel-r7-protected-vector gap.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from dmp_peer.frame import parse_frame
from dmp_peer.security import (
    AuthenticationError,
    DATA_AAD_PREFIX,
    ReplayError,
    SecurityAssociation,
    SecurityError,
    compute_canonical_header,
)


def _load_recovery_vectors() -> dict:
    path = Path(__file__).resolve().parents[3] / "docs" / "DMP_v2_Recovery_Test_Vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _load_security_vectors() -> dict:
    path = Path(__file__).resolve().parents[3] / "docs" / "DMP_v2_Security_Test_Vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))


class RecoveryVectorsRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recovery_data = _load_recovery_vectors()
        cls.security_data = _load_security_vectors()
        cls.assoc_data = cls.recovery_data["association"]
        cls.handshake_hash = bytes.fromhex(cls.assoc_data["handshake_hash"])
        cls.key = bytes.fromhex(cls.assoc_data["key"])
        cls.rx_cid = cls.recovery_data["supported_suite"]["receive_cid"]
        cls.initiator_epoch = int(cls.assoc_data["initiator_epoch"])
        cls.responder_epoch = int(cls.assoc_data["responder_epoch"])

    def _make_association(self, *, h: int | None = None, bitmap: int = 0) -> SecurityAssociation:
        assoc = SecurityAssociation(
            h=self.handshake_hash,
            send_key=self.key,
            recv_key=self.key,
            local_rx_cid=self.rx_cid,
            peer_rx_cid=self.rx_cid,
            local_epoch=self.initiator_epoch,
            peer_epoch=self.responder_epoch,
            is_initiator=False,
            status="active",
        )
        assoc.replay_window.h = h
        assoc.replay_window.bitmap = bitmap
        return assoc

    def test_vector_provenance_and_security_vector_link(self):
        """Link recovery traffic key, handshake hash, and epochs to SEC-1 public vectors."""
        sec_nnpsk0 = self.security_data["vectors"][0]
        self.assertEqual(sec_nnpsk0["protocol_name"], "Noise_NNpsk0_25519_ChaChaPoly_SHA256")
        self.assertEqual(self.assoc_data["handshake_hash"], sec_nnpsk0["handshake_hash"])
        self.assertEqual(self.assoc_data["key"], sec_nnpsk0["r_to_i_key"])
        self.assertEqual(self.assoc_data["initiator_epoch"], sec_nnpsk0["origin_epochs"][0])
        self.assertEqual(self.assoc_data["responder_epoch"], sec_nnpsk0["origin_epochs"][1])
        self.assertEqual(self.recovery_data["supported_suite"]["cipher"], 1)
        self.assertEqual(self.recovery_data["supported_suite"]["receive_cid"], 7)
        self.assertEqual(self.recovery_data["supported_suite"]["direction"], 1)

    def test_valid_cipher1_vectors_aad_and_peer_crypto(self):
        """Derive AAD and verify exact peer encrypt/decrypt bytes for all valid cipher-1 cases."""
        aead_cases = [
            case
            for case in self.recovery_data["cases"]
            if case.get("cipher") == 1 and case.get("aead_valid")
        ]
        self.assertEqual(
            len(aead_cases), 22, "Expected exactly 22 published aead_valid cipher-1 cases"
        )

        for case in aead_cases:
            with self.subTest(case=case["name"]):
                raw_hdr = bytes.fromhex(case["header"])
                pt = bytes.fromhex(case["plaintext"])
                ct = bytes.fromhex(case["ciphertext"])
                tag = bytes.fromhex(case["tag"])
                pn = case["pn"]

                # Independently derive AAD from peer canonical-header rule and pinned hash
                canon_hdr = compute_canonical_header(raw_hdr)
                derived_aad = DATA_AAD_PREFIX + self.handshake_hash + canon_hdr
                self.assertEqual(derived_aad.hex(), case["aad"])

                assoc = self._make_association()
                if case["name"] == "pn_at_limit":
                    # pn_at_limit (PN = 16_777_216) must be explicitly rejected by the peer API
                    self.assertEqual(pn, 16_777_216)
                    with self.assertRaisesRegex(SecurityError, "PN exhaustion"):
                        assoc.encrypt_frame(raw_hdr, pt, pn=pn)
                    with self.assertRaisesRegex(SecurityError, "PN out of range"):
                        assoc.decrypt_frame(raw_hdr, ct, tag, pn=pn, rx_cid=self.rx_cid)
                else:
                    # Verify exact peer encryption output
                    enc_pn, ct_and_tag = assoc.encrypt_frame(raw_hdr, pt, pn=pn)
                    self.assertEqual(enc_pn, pn)
                    self.assertEqual(ct_and_tag[:-16], ct)
                    self.assertEqual(ct_and_tag[-16:], tag)
                    self.assertEqual((raw_hdr + ct_and_tag).hex(), case["frame"])

                    # Verify exact peer decryption output
                    dec_pt = assoc.decrypt_frame(raw_hdr, ct, tag, pn=pn, rx_cid=self.rx_cid)
                    self.assertEqual(dec_pt, pt)

                    # Verify duplicate packet is rejected by replay window
                    with self.assertRaises(ReplayError):
                        assoc.decrypt_frame(raw_hdr, ct, tag, pn=pn, rx_cid=self.rx_cid)

    def test_ttl_only_authenticated_mutation(self):
        """Verify ttl_only mutation preserves canonical AAD and decrypts without error."""
        ttl_mut = next(m for m in self.recovery_data["mutations"] if m["name"] == "ttl_only")
        base_case = next(c for c in self.recovery_data["cases"] if c["name"] == ttl_mut["base"])

        frame_bytes = bytes.fromhex(ttl_mut["frame"])
        cf = parse_frame(frame_bytes)
        hdr_len = frame_bytes[1]
        mut_hdr = frame_bytes[:hdr_len]
        base_hdr = bytes.fromhex(base_case["header"])

        # Raw TTL byte differs (XOR 16), but canonical header zeroes TTL nibble
        self.assertEqual(mut_hdr[4] ^ base_hdr[4], ttl_mut["xor"])
        mut_canon = compute_canonical_header(mut_hdr)
        self.assertEqual(mut_canon, compute_canonical_header(base_hdr))
        derived_aad = DATA_AAD_PREFIX + self.handshake_hash + mut_canon
        self.assertEqual(derived_aad.hex(), base_case["aad"])

        # Decrypts via SecurityAssociation and commits PN 20
        assoc = self._make_association()
        decrypted = assoc.decrypt_frame(
            mut_hdr,
            cf.payload,
            cf.trailer,
            pn=cf.security.packet_number,
            rx_cid=cf.security.receive_cid,
        )
        self.assertEqual(decrypted, bytes.fromhex(base_case["plaintext"]))
        self.assertFalse(assoc.replay_window.check(20))

    def test_all_seven_aead_invalid_mutations_rejected_without_replay_advance(self):
        """Reject all seven AEAD-invalid mutations and verify replay window state is not advanced."""
        invalid_muts = [
            mutation
            for mutation in self.recovery_data["mutations"]
            if not mutation.get("aead_valid")
        ]
        self.assertEqual(
            len(invalid_muts), 7, "Expected exactly 7 AEAD-invalid published mutations"
        )

        for mut in invalid_muts:
            with self.subTest(mutation=mut["name"]):
                frame_bytes = bytes.fromhex(mut["frame"])
                cf = parse_frame(frame_bytes)
                hdr = frame_bytes[:frame_bytes[1]]

                # Initial replay window state
                assoc = self._make_association(h=10, bitmap=1)
                initial_h = assoc.replay_window.h
                initial_bitmap = assoc.replay_window.bitmap

                # Decryption must fail
                if mut["name"] == "receive_cid":
                    with self.assertRaisesRegex(SecurityError, "CID mismatch"):
                        assoc.decrypt_frame(
                            hdr,
                            cf.payload,
                            cf.trailer,
                            pn=cf.security.packet_number,
                            rx_cid=cf.security.receive_cid,
                        )
                else:
                    with self.assertRaisesRegex(AuthenticationError, "AEAD decryption failed"):
                        assoc.decrypt_frame(
                            hdr,
                            cf.payload,
                            cf.trailer,
                            pn=cf.security.packet_number,
                            rx_cid=cf.security.receive_cid,
                        )

                # Replay window state must remain unchanged
                self.assertEqual(assoc.replay_window.h, initial_h)
                self.assertEqual(assoc.replay_window.bitmap, initial_bitmap)
                self.assertTrue(assoc.replay_window.check(cf.security.packet_number))


if __name__ == "__main__":
    unittest.main()
