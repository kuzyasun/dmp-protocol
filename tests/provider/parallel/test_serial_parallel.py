"""Regression gates remain effective under Python -O; no serial access."""
import copy
import unittest
from serial_parallel import validate


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        result = dict(completed=8, error_line=0, fixed_pairs=4, random_pairs=4,
                      live=0, blocks=0, wipe_errors=0, refusals=0, attempts=50,
                      allocs=50, frees=50, peak=3000, backing=8192, rng_calls=8)
        self.value = dict(success=True, workers=2, cycles=8, max_inflight=2,
                          target="esp32s3", cores=2, dual_core_overlap=10,
                          core_mask=3, heap_before=10000, heap_after=10000,
                          worker_stack_bytes=12288, worker_stack_free=[8000,8000],
                          sync_rounds=[8,8], results=[result, copy.deepcopy(result)])

    def test_valid(self):
        validate(self.value, 2, 8)

    def test_failed_result_is_rejected_with_optimization(self):
        self.value["success"] = False
        with self.assertRaises(RuntimeError):
            validate(self.value, 2, 8)

    def test_unicore_s3_cannot_pass_parallel_gate(self):
        self.value.update(cores=1, core_mask=1, dual_core_overlap=0)
        with self.assertRaises(RuntimeError):
            validate(self.value, 2, 8)


if __name__ == "__main__":
    unittest.main()
