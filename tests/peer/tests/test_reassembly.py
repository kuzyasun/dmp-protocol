"""Tests for fixed-stride reassembly geometry, quotas, conflicts, and expiry (DMP §11)."""

import unittest

from dmp_peer.reassembly import (
    ConflictError,
    QuotaError,
    ReassemblyError,
    ReassemblyManager,
)


class ReassemblyTests(unittest.TestCase):
    def setUp(self):
        self.mgr = ReassemblyManager(
            max_message_bytes=1024,
            max_fragments=16,
            assemblies_per_peer=2,
            tombstones_per_peer=4,
            assembly_ms=1000,
            tombstone_ms=2000,
        )

    def test_geometry_validation_and_rejections(self):
        # chunk_size == 0
        with self.assertRaises(ReassemblyError):
            self.mgr.validate_geometry(fragment_index=0, chunk_size=0, total_length=100)

        # total <= chunk
        with self.assertRaises(ReassemblyError):
            self.mgr.validate_geometry(fragment_index=0, chunk_size=100, total_length=100)
        with self.assertRaises(ReassemblyError):
            self.mgr.validate_geometry(fragment_index=0, chunk_size=100, total_length=50)

        # total > max_message_bytes (1024)
        with self.assertRaises(ReassemblyError):
            self.mgr.validate_geometry(fragment_index=0, chunk_size=100, total_length=2000)

        # fragments count exceeds max_fragments (16)
        with self.assertRaises(ReassemblyError):
            self.mgr.validate_geometry(fragment_index=0, chunk_size=10, total_length=200)

        # index >= count
        # total=100, chunk=40 -> count = 1 + 99//40 = 3 (indices 0, 1, 2)
        count = self.mgr.validate_geometry(fragment_index=2, chunk_size=40, total_length=100)
        self.assertEqual(count, 3)
        with self.assertRaises(ReassemblyError):
            self.mgr.validate_geometry(fragment_index=3, chunk_size=40, total_length=100)

    def test_final_first_and_out_of_order_reassembly_golden_v224(self):
        # Section 22.4 vector: total=3, chunk=2 -> derived count=2
        # Index 0 has offset 0, len 2: b"AA BB"
        # Index 1 has offset 2, len 1: b"CC"
        # Final slice (index 1) arrives first!
        complete1, payload1 = self.mgr.process_fragment(
            namespace=1,
            origin=10,
            epoch=7,
            seq=9,
            fragment_index=1,
            chunk_size=2,
            total_length=3,
            message_type=7,
            ack_req=False,
            service_id=1,
            slice_payload=b"\xCC",
            at_ms=10,
        )
        self.assertFalse(complete1)
        self.assertIsNone(payload1)

        # First slice (index 0) arrives second
        complete2, payload2 = self.mgr.process_fragment(
            namespace=1,
            origin=10,
            epoch=7,
            seq=9,
            fragment_index=0,
            chunk_size=2,
            total_length=3,
            message_type=7,
            ack_req=False,
            service_id=1,
            slice_payload=b"\xAA\xBB",
            at_ms=20,
        )
        self.assertTrue(complete2)
        self.assertEqual(payload2, b"\xAA\xBB\xCC")

    def test_conflicting_slice_bytes_rejected_without_mutation(self):
        # Send index 0
        self.mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=15,
            fragment_index=0, chunk_size=10, total_length=25,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=10,
        )

        # Conflicting slice bytes for already received index 0
        with self.assertRaises(ConflictError):
            self.mgr.process_fragment(
                namespace=1, origin=10, epoch=7, seq=15,
                fragment_index=0, chunk_size=10, total_length=25,
                message_type=7, ack_req=False, service_id=1,
                slice_payload=b"XXXXXXXXXX", at_ms=15,
            )

        # Accepted bytes remain unmutated
        session = self.mgr.active[(1, 10, 7, 15)]
        self.assertEqual(session.buffer[:10], b"0123456789")

    def test_metadata_conflict_across_slices_rejected(self):
        # Send index 0 with chunk_size 10
        self.mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=20,
            fragment_index=0, chunk_size=10, total_length=25,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=10,
        )

        # Conflicting geometry (chunk_size 12) under same identity
        with self.assertRaises(ConflictError):
            self.mgr.process_fragment(
                namespace=1, origin=10, epoch=7, seq=20,
                fragment_index=1, chunk_size=12, total_length=25,
                message_type=7, ack_req=False, service_id=1,
                slice_payload=b"012345678901", at_ms=15,
            )

    def test_active_assemblies_and_tombstone_quotas(self):
        # Limit is 2 concurrent assemblies
        self.mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=1,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=10,
        )
        self.mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=2,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=10,
        )

        # Third assembly exceeds quota
        with self.assertRaises(QuotaError):
            self.mgr.process_fragment(
                namespace=1, origin=10, epoch=7, seq=3,
                fragment_index=0, chunk_size=10, total_length=20,
                message_type=7, ack_req=False, service_id=1,
                slice_payload=b"0123456789", at_ms=10,
            )

    def test_absolute_assembly_expiry_and_tombstone_no_reopen(self):
        # Start assembly at at_ms=100, assembly_ms=1000 -> expires at 1100
        self.mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=30,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=100,
        )

        # Duplicate does not extend timer
        self.mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=30,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=500,
        )
        self.assertEqual(self.mgr.active[(1, 10, 7, 30)].expires_at_ms, 1100)

        # Advance past expiry to 1105
        expired = self.mgr.advance(now_ms=1105)
        self.assertIn((1, 10, 7, 30), expired)
        self.assertNotIn((1, 10, 7, 30), self.mgr.active)
        self.assertIn((1, 10, 7, 30), self.mgr.tombstones)

        # Attempt to send slice for expired message cannot reopen
        with self.assertRaisesRegex(ReassemblyError, "tombstone"):
            self.mgr.process_fragment(
                namespace=1, origin=10, epoch=7, seq=30,
                fragment_index=1, chunk_size=10, total_length=20,
                message_type=7, ack_req=False, service_id=1,
                slice_payload=b"0123456789", at_ms=1110,
            )

    def test_tombstone_capacity_reservation_at_admission(self):
        # Manager with assemblies_per_peer=5, tombstones_per_peer=2
        mgr = ReassemblyManager(
            max_message_bytes=1024,
            max_fragments=16,
            assemblies_per_peer=5,
            tombstones_per_peer=2,
            assembly_ms=1000,
            tombstone_ms=2000,
        )
        # First assembly admitted: active=1, tombstones=0 (1 < 2)
        mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=1,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=10,
        )
        # Second assembly admitted: active=2, tombstones=0 (2 <= 2 reserved)
        mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=2,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=10,
        )
        # Third assembly: len(active) + len(tombstones) == 2 >= tombstones_per_peer -> QuotaError
        with self.assertRaises(QuotaError):
            mgr.process_fragment(
                namespace=1, origin=10, epoch=7, seq=3,
                fragment_index=0, chunk_size=10, total_length=20,
                message_type=7, ack_req=False, service_id=1,
                slice_payload=b"0123456789", at_ms=10,
            )

    def test_completed_assembly_tombstone_blocks_reopening(self):
        # Complete an assembly
        c1, p1 = self.mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=50,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=10,
        )
        self.assertFalse(c1)
        c2, p2 = self.mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=50,
            fragment_index=1, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"ABCDEFGHIJ", at_ms=20,
        )
        self.assertTrue(c2)
        self.assertEqual(p2, b"0123456789ABCDEFGHIJ")

        # Identity is retained in completed records (distinct from incomplete expiry tombstones)
        self.assertIn((1, 10, 7, 50), self.mgr.completed)
        self.assertNotIn((1, 10, 7, 50), self.mgr.tombstones)

        # Metadata-matching duplicate slice triggers already_completed flag without reopening assembly
        res = self.mgr.process_fragment(
            namespace=1, origin=10, epoch=7, seq=50,
            fragment_index=0, chunk_size=10, total_length=20,
            message_type=7, ack_req=False, service_id=1,
            slice_payload=b"0123456789", at_ms=30,
        )
        self.assertFalse(res.complete)
        self.assertIsNone(res.payload)
        self.assertTrue(res.already_completed)
        self.assertNotIn((1, 10, 7, 50), self.mgr.active)

        # Conflicting metadata under completed identity raises ConflictError
        with self.assertRaises(ConflictError):
            self.mgr.process_fragment(
                namespace=1, origin=10, epoch=7, seq=50,
                fragment_index=0, chunk_size=10, total_length=20,
                message_type=7, ack_req=False, service_id=99,
                slice_payload=b"0123456789", at_ms=35,
            )


if __name__ == "__main__":
    unittest.main()
