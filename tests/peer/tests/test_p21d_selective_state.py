"""Focused state-machine tests for independent SELECTIVE-32 recovery."""

from __future__ import annotations

import unittest

from dmp_peer.selective import RecoveryAction, SelectiveTransfer


def transfer(*, fragment_count: int = 4, **overrides: object) -> SelectiveTransfer:
    values: dict[str, object] = {
        "fragment_count": fragment_count,
        "started_at_ms": 100,
        "send_horizon_ms": 1_000,
        "response_timeout_ms": 20,
        "max_bursts": 5,
        "max_probes": 2,
        "max_status": 4,
        "burst_starts_ms": (0, 10, 20, 30, 40),
        "frames_remaining": 1,
    }
    values.update(overrides)
    return SelectiveTransfer(**values)  # type: ignore[arg-type]


class SelectiveTransferTests(unittest.TestCase):
    def test_n2_and_n32_accept_the_highest_valid_missing_bit(self):
        for count in (2, 32):
            with self.subTest(fragment_count=count):
                state = transfer(fragment_count=count)
                self.assertTrue(state.settle_frame(100))
                self.assertFalse(state.accept_status(1, 1 << count, 101))
                mask = 1 << (count - 1)
                self.assertTrue(state.accept_status(2, mask, 101))
                self.assertEqual(
                    state.take_due_action(110), RecoveryAction("repair", (count - 1,))
                )

    def test_rejects_invalid_masks_and_nonadvancing_or_invalid_sequences(self):
        state = transfer(fragment_count=32)
        valid_mask = (1 << 32) - 1
        for sequence, mask in (
            (1, 0),
            (1, -1),
            (1, valid_mask),
            (1, 1 << 32),
            (1, True),
            (1, 1.0),
            (1, "1"),
            (True, 1),
            (-1, 1),
            (1 << 32, 1),
            (1.0, 1),
            ("1", 1),
        ):
            with self.subTest(sequence=sequence, mask=mask):
                self.assertFalse(state.accept_status(sequence, mask, 101))  # type: ignore[arg-type]
        self.assertEqual(state.status_count, 0)
        self.assertEqual(state.greatest_status_seq, -1)
        self.assertIsNone(state.pending_mask)

        self.assertTrue(state.accept_status(7, 1, 102))
        for sequence in (7, 6, 0):
            with self.subTest(nonadvancing_sequence=sequence):
                self.assertFalse(state.accept_status(sequence, 2, 103))
        self.assertEqual(state.status_count, 1)
        self.assertEqual(state.pending_mask, 1)

    def test_newer_status_snapshot_supersedes_instead_of_merging(self):
        state = transfer()
        self.assertTrue(state.settle_frame(100))
        self.assertTrue(state.accept_status(10, 0b0101, 101))
        self.assertTrue(state.accept_status(11, 0b0010, 102))
        self.assertEqual(state.pending_mask, 0b0010)
        self.assertEqual(state.take_due_action(110), RecoveryAction("repair", (1,)))

    def test_repairs_are_ordered_single_flight_and_wait_for_the_next_slot(self):
        state = transfer()
        self.assertTrue(state.settle_frame(100))
        self.assertTrue(state.accept_status(1, 0b0101, 101))
        self.assertIsNone(state.take_due_action(109))
        self.assertEqual(state.take_due_action(110), RecoveryAction("repair", (0, 2)))

        self.assertFalse(state.settle_frame(111))
        self.assertIsNone(state.take_due_action(111))
        self.assertTrue(state.accept_status(2, 0b0010, 112))
        self.assertIsNone(state.take_due_action(112))
        self.assertTrue(state.settle_frame(113))
        self.assertEqual(state.wait_until_ms, 133)
        self.assertIsNone(state.take_due_action(119))
        self.assertEqual(state.take_due_action(120), RecoveryAction("repair", (1,)))

    def test_probe_retransmits_only_the_last_fragment(self):
        state = transfer(fragment_count=32)
        self.assertTrue(state.settle_frame(100))
        self.assertIsNone(state.take_due_action(119))
        self.assertEqual(state.take_due_action(120), RecoveryAction("probe", (31,)))
        self.assertEqual(state.probe_count, 1)
        self.assertEqual(state.burst_count, 2)

    def test_status_burst_probe_budgets_and_horizon_stop_the_transfer(self):
        status_limited = transfer(max_status=1)
        self.assertTrue(status_limited.accept_status(1, 1, 101))
        self.assertFalse(status_limited.accept_status(2, 2, 102))

        burst_limited = transfer(max_bursts=1)
        self.assertTrue(burst_limited.settle_frame(100))
        self.assertTrue(burst_limited.accept_status(1, 1, 101))
        self.assertEqual(
            burst_limited.take_due_action(101), RecoveryAction("stop", reason="burst_budget")
        )
        self.assertTrue(burst_limited.terminal)
        self.assertIsNone(burst_limited.pending_mask)

        probe_limited = transfer(max_probes=0)
        self.assertTrue(probe_limited.settle_frame(100))
        self.assertEqual(
            probe_limited.take_due_action(120),
            RecoveryAction("stop", reason="burst_or_probe_budget"),
        )
        self.assertTrue(probe_limited.terminal)

        horizon_limited = transfer(send_horizon_ms=50)
        self.assertFalse(horizon_limited.accept_status(1, 1, 150))
        self.assertEqual(
            horizon_limited.take_due_action(150), RecoveryAction("stop", reason="send_horizon")
        )
        self.assertTrue(horizon_limited.terminal)
        self.assertFalse(horizon_limited.accept_status(2, 1, 149))
        self.assertIsNone(horizon_limited.take_due_action(149))

    def test_explicit_termination_clears_pending_and_active_recovery(self):
        state = transfer()
        self.assertTrue(state.settle_frame(100))
        self.assertTrue(state.accept_status(1, 1, 101))
        self.assertEqual(state.take_due_action(110), RecoveryAction("repair", (0,)))
        state.terminate()
        self.assertTrue(state.terminal)
        self.assertIsNone(state.pending_mask)
        self.assertIsNone(state.active_kind)
        self.assertEqual(state.frames_remaining, 0)
        self.assertIsNone(state.wait_until_ms)
        self.assertFalse(state.accept_status(2, 2, 111))
        self.assertIsNone(state.take_due_action(111))


if __name__ == "__main__":
    unittest.main()
