"""No hardware: fail-closed orchestration and planned-reset boundaries."""
import copy
import json
import unittest

from serial_soak import Soak, BUILD, CYCLES, reset_uart
import test_serial_parallel


class FakeSerial:
    def __init__(self):
        fixture = test_serial_parallel.AcceptanceTests()
        fixture.setUp()
        self.reply = fixture.value
        self.boot, self.last_id, self.run_id = 1, 6, 6
        self.writes, self.resets, self.pending = [], [], []
        self.change = lambda value: None

    def write(self, data):
        self.writes.append(data)
        line = data.decode().split()
        value = dict(id=int(line[0]), op=line[1], boot=f"{self.boot:08x}",
                     target="esp32s3", idf="v6.1", build=BUILD, cores=2)
        if line[1] == "HELLO":
            value["last_id"] = self.last_id
        else:
            self.last_id = value["id"]
            self.run_id += 1
            value.update(copy.deepcopy(self.reply), run=self.run_id, cycles=CYCLES,
                         sync_rounds=[CYCLES, CYCLES])
            for result in value["results"]:
                result.update(completed=CYCLES, fixed_pairs=CYCLES//2,
                              random_pairs=CYCLES//2, rng_calls=CYCLES)
        self.change(value)
        self.pending.append(("DMPPAR " + json.dumps(value) + "\n").encode())

    def readline(self, timeout, limit):
        return self.pending.pop(0)

    def reset(self, serial):
        self.resets.append(len(self.writes))
        self.boot += 1
        self.last_id = self.run_id = 0
        self.pending.extend([b"ESP-ROM:esp32s3-20210327\n", b"rst:0x1 (POWERON),boot:0x8 (SPI_FAST_FLASH_BOOT)\n"])


class SoakTests(unittest.TestCase):
    def setUp(self):
        self.serial = FakeSerial()
        self.events = []
        self.soak = Soak(self.serial, "esp32s3", lambda event, **kw: self.events.append((event, kw)),
                         self.serial.reset)

    def test_epochs_reset_only_after_four_accepted_runs_and_final_hello(self):
        self.soak.run()
        self.assertEqual(self.serial.resets, [6, 12])
        self.assertEqual(len([e for e, _ in self.events if e == "accepted"]), 12)
        self.assertEqual(self.events[-1][1]["pairs"], 3072)

    def test_c3_epochs(self):
        self.soak.target = "esp32c3"
        def change(v):
            v.update(target="esp32c3", cores=1)
            if v["op"] == "RUN":
                v.update(core_mask=1, dual_core_overlap=0)
        self.serial.change = change
        self.soak.run()
        self.assertEqual(self.events[-1][0], "complete")

    def test_c3_wrong_core_or_overlap_is_rejected(self):
        for mask, overlap in ((3, 0), (1, 1)):
            with self.subTest(mask=mask, overlap=overlap):
                self.setUp()
                self.soak.target = "esp32c3"
                def change(v):
                    v.update(target="esp32c3", cores=1)
                    if v["op"] == "RUN":
                        v.update(core_mask=mask, dual_core_overlap=overlap)
                self.serial.change = change
                with self.assertRaises(RuntimeError):
                    self.soak.run()
                self.assertEqual(self.serial.resets, [])

    def test_failed_run_never_retried_or_reset(self):
        self.serial.change = lambda v: v.update(success=False) if v["op"] == "RUN" else None
        with self.assertRaises(RuntimeError):
            self.soak.run()
        self.assertEqual(len(self.serial.writes), 2)
        self.assertEqual(self.serial.resets, [])

    def test_timeout_never_retried_or_reset(self):
        def timeout(*args):
            raise TimeoutError("injected")
        self.serial.readline = timeout
        with self.assertRaises(TimeoutError):
            self.soak.run()
        self.assertEqual(len(self.serial.writes), 1)
        self.assertEqual(self.serial.resets, [])

    def test_reset_without_boot_change_stops_before_next_run(self):
        def reset(serial):
            old_boot = serial.boot
            serial.reset(serial)
            serial.boot = old_boot
        self.soak.reset = reset
        with self.assertRaisesRegex(RuntimeError, "fresh boot"):
            self.soak.run()
        self.assertEqual(len(self.serial.writes), 7)

    def test_reset_without_counter_clear_is_rejected(self):
        def reset(serial):
            old_id = serial.last_id
            serial.reset(serial)
            serial.last_id = old_id
        self.soak.reset = reset
        with self.assertRaisesRegex(RuntimeError, "counter did not reset"):
            self.soak.run()

    def test_unexpected_reboot_during_run_is_rejected(self):
        self.serial.change = lambda v: v.update(boot="ffffffff") if v["op"] == "RUN" else None
        with self.assertRaisesRegex(RuntimeError, "Unexpected reboot"):
            self.soak.run()

    def test_heap_loss_after_reset_is_rejected(self):
        def change(v):
            if self.serial.boot > 1 and v["op"] == "RUN":
                v.update(heap_before=9999, heap_after=9999)
        self.serial.change = change
        with self.assertRaisesRegex(RuntimeError, "Heap changed"):
            self.soak.run()

    def test_wrong_image_is_rejected(self):
        self.serial.change = lambda v: v.update(build="0"*64)
        with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
            self.soak.run()

    def test_boot_panic_is_not_ignored(self):
        self.serial.pending.append(b"Guru Meditation Error\n")
        with self.assertRaisesRegex(RuntimeError, "Unexpected serial output"):
            self.soak.run()

    def test_watchdog_and_brownout_reset_diagnostics_are_rejected(self):
        for line in (b"rst:0x8 (TG1WDT_SYS_RST)\n", b"Brownout detector was triggered\n",
                     b"rst:0xc (RTC_SW_CPU_RST)\n"):
            with self.subTest(line=line):
                self.setUp()
                self.serial.pending.append(line)
                with self.assertRaises(RuntimeError):
                    self.soak.run()
                self.assertEqual(len(self.serial.writes), 1)

    def test_duplicate_boot_sequences_are_rejected(self):
        self.serial.pending.extend([b"ESP-ROM:esp32s3\n", b"rst:0x1 (POWERON)\n",
                                    b"ESP-ROM:esp32s3\n", b"rst:0x1 (POWERON)\n"])
        with self.assertRaisesRegex(RuntimeError, "Multiple boot"):
            self.soak.run()

    def test_planned_reset_without_rom_evidence_is_rejected(self):
        def reset(serial):
            serial.reset(serial)
            serial.pending.clear()
        self.soak.reset = reset
        with self.assertRaisesRegex(RuntimeError, "Missing planned-reset"):
            self.soak.run()

    def test_reset_pulse_keeps_boot_pin_inactive(self):
        events = []
        class Port:
            def setDTR(self, value):
                events.append(("dtr", value))
            def setRTS(self, value):
                events.append(("rts", value))
        self.serial._serial = Port()
        reset_uart(self.serial, lambda delay: events.append(("sleep", delay)))
        self.assertEqual(events, [("dtr", False), ("rts", True), ("dtr", False),
                                 ("sleep", 0.1), ("rts", False), ("dtr", False), ("sleep", 1.0)])


if __name__ == "__main__":
    unittest.main()
