"""No hardware: fail-closed orchestration and planned-reset boundaries."""
import copy
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from serial_soak import (
    Soak, BUILD, CYCLES, reset_uart,
    parse_partitions_csv, validate_partition_table, validate_target_partition_config,
    COREDUMP_OFFSET, COREDUMP_SIZE, FLASH_SIZE_4MB, EXPECTED_PARTITIONS, main
)
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

    def test_partition_preflight_fails_before_serial_open(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / "soak.jsonl"
            with patch("serial_soak.validate_target_partition_config",
                       side_effect=RuntimeError("invalid partition config")), \
                 patch("serial_soak.transport.SerialTransport") as serial_open, \
                 patch.object(sys, "argv", ["serial_soak.py", "--port", "COM35",
                                             "--target", "esp32c3", "--output", str(output)]), \
                 redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = main()

            self.assertEqual(result, 1)
            serial_open.assert_not_called()
            events = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(events[-1]["event"], "failed")
            self.assertIn("invalid partition config", events[-1]["error"])

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


class PartitionLayoutTests(unittest.TestCase):
    def setUp(self):
        self.target_dir = Path(__file__).resolve().parent.parent / "targets" / "esp32-parallel"
        self.espnow_dir = Path(__file__).resolve().parent.parent.parent / "embedded" / "espnow_pair"

    def test_provider_target_partition_config_passes_validation(self):
        validate_target_partition_config(self.target_dir)

    def test_provider_target_partition_entries_match_expected_tuples(self):
        csv_path = self.target_dir / "partitions.csv"
        self.assertTrue(csv_path.is_file())
        partitions = parse_partitions_csv(csv_path.read_text(encoding="utf-8"))
        actual = [(p["name"], p["type"], p["subtype"], p["offset"], p["size"]) for p in partitions]
        self.assertEqual(actual, list(EXPECTED_PARTITIONS))

    def test_provider_target_geometry_matches_espnow_pair(self):
        target_csv = (self.target_dir / "partitions.csv").read_text(encoding="utf-8")
        espnow_csv = (self.espnow_dir / "partitions.csv").read_text(encoding="utf-8")
        p_target = [(p["name"], p["offset"], p["size"]) for p in parse_partitions_csv(target_csv)]
        p_espnow = [(p["name"], p["offset"], p["size"]) for p in parse_partitions_csv(espnow_csv)]
        self.assertEqual(p_target, p_espnow)

    def test_validate_partition_table_empty_fails(self):
        with self.assertRaisesRegex(RuntimeError, "Partition table is empty"):
            validate_partition_table("")

    def test_parse_partition_table_rejects_malformed_row(self):
        with self.assertRaisesRegex(RuntimeError, "Malformed partition row at line 1"):
            parse_partitions_csv("coredump, data, coredump, 0x300000\n")

    def test_parse_partition_table_rejects_invalid_offset(self):
        with self.assertRaisesRegex(RuntimeError, "Invalid partition offset/size at line 1"):
            parse_partitions_csv("nvs, data, nvs, nope, 0x6000\n")

    def test_validate_partition_table_rejects_duplicate_name(self):
        table = (
            "nvs, data, nvs, 0x9000, 0x6000\n"
            "nvs, data, nvs, 0xf000, 0x1000\n"
            "factory, app, factory, 0x10000, 0x2F0000\n"
            "coredump, data, coredump, 0x300000, 0x100000\n"
        )
        with self.assertRaisesRegex(RuntimeError, "Duplicate partition name"):
            validate_partition_table(table)

    def test_validate_partition_table_rejects_bootloader_region(self):
        table = (
            "factory, app, factory, 0x8000, 0x1000\n"
            "coredump, data, coredump, 0x300000, 0x100000\n"
        )
        with self.assertRaisesRegex(RuntimeError, "starts before partition table end"):
            validate_partition_table(table)

    def test_validate_partition_table_rejects_missing_expected_partition(self):
        table = (
            "nvs, data, nvs, 0x9000, 0x6000\n"
            "factory, app, factory, 0x10000, 0x2F0000\n"
            "coredump, data, coredump, 0x300000, 0x100000\n"
        )
        with self.assertRaisesRegex(RuntimeError, "does not match the expected"):
            validate_partition_table(table)

    def test_validate_partition_table_missing_coredump_fails(self):
        table = (
            "nvs, data, nvs, 0x9000, 0x6000\n"
            "phy_init, data, phy, 0xf000, 0x1000\n"
            "factory, app, factory, 0x10000, 0x2F0000\n"
        )
        with self.assertRaisesRegex(RuntimeError, "Missing coredump partition"):
            validate_partition_table(table)

    def test_validate_partition_table_invalid_coredump_type_or_subtype(self):
        for bad_type, bad_subtype in (("app", "coredump"), ("data", "nvs")):
            with self.subTest(bad_type=bad_type, bad_subtype=bad_subtype):
                table = (
                    "factory, app, factory, 0x10000, 0x2F0000\n"
                    f"coredump, {bad_type}, {bad_subtype}, 0x300000, 0x100000\n"
                )
                with self.assertRaisesRegex(RuntimeError, "invalid type/subtype"):
                    validate_partition_table(table)

    def test_validate_partition_table_wrong_coredump_offset(self):
        table = (
            "factory, app, factory, 0x10000, 0x2F0000\n"
            "coredump, data, coredump, 0x200000, 0x100000\n"
        )
        with self.assertRaisesRegex(RuntimeError, "offset mismatch"):
            validate_partition_table(table)

    def test_validate_partition_table_wrong_coredump_size(self):
        table = (
            "factory, app, factory, 0x10000, 0x2F0000\n"
            "coredump, data, coredump, 0x300000, 0x80000\n"
        )
        with self.assertRaisesRegex(RuntimeError, "size mismatch"):
            validate_partition_table(table)

    def test_validate_partition_table_overlap(self):
        table = (
            "factory, app, factory, 0x10000, 0x300000\n"
            "coredump, data, coredump, 0x300000, 0x100000\n"
        )
        with self.assertRaisesRegex(RuntimeError, "overlap detected"):
            validate_partition_table(table)

    def test_validate_partition_table_exceeds_4mb(self):
        table = (
            "factory, app, factory, 0x10000, 0x2F0000\n"
            "coredump, data, coredump, 0x300000, 0x100000\n"
            "extra, data, nvs, 0x400000, 0x1000\n"
        )
        with self.assertRaisesRegex(RuntimeError, "extends beyond 4 MiB"):
            validate_partition_table(table)

    def test_validate_target_partition_config_missing_csv(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(RuntimeError, "Missing partitions.csv"):
                validate_target_partition_config(Path(td))

    def test_validate_target_partition_config_missing_sdkconfig(self):
        with tempfile.TemporaryDirectory() as td:
            csv_path = Path(td) / "partitions.csv"
            csv_path.write_text((self.target_dir / "partitions.csv").read_text(encoding="utf-8"))
            with self.assertRaisesRegex(RuntimeError, "Missing sdkconfig.defaults"):
                validate_target_partition_config(Path(td))

    def test_validate_target_partition_config_missing_options(self):
        required_options = [
            "CONFIG_PARTITION_TABLE_CUSTOM=y",
            'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"',
            "CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y",
            "CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y",
        ]
        valid_sdkconfig = (self.target_dir / "sdkconfig.defaults").read_text(encoding="utf-8")
        for opt in required_options:
            with self.subTest(missing_opt=opt):
                with tempfile.TemporaryDirectory() as td:
                    (Path(td) / "partitions.csv").write_text((self.target_dir / "partitions.csv").read_text(encoding="utf-8"))
                    corrupted = valid_sdkconfig.replace(opt, "")
                    (Path(td) / "sdkconfig.defaults").write_text(corrupted)
                    with self.assertRaisesRegex(RuntimeError, re.escape(opt)):
                        validate_target_partition_config(Path(td))


if __name__ == "__main__":
    unittest.main()
