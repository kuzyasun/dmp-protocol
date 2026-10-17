"""Host-only tests for physical SAMPLE-1 reset evidence validation."""

from __future__ import annotations

import json
import queue
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

EMBEDDED_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_dmp"
FIRMWARE_MAIN = EMBEDDED_DIR / "main" / "main.c"
sys.path.insert(0, str(EMBEDDED_DIR))

from serial_dmp_common import DmpTestError, default_serial_factory
from serial_dmp_restart import (
    load_pair_nvs_event,
    request_serial_restart,
    run_persistent_transition,
    validate_boot_identity_transition,
    validate_persistent_epoch_transition,
)


def nvs_event(previous: int, reserved: int, *, key: str = "s1_epoch_test") -> dict:
    return {
        "event": "nvs_epoch_check",
        "session": "0123456789abcdef",
        "status": "ok",
        "namespace": "dmp_test_nvs",
        "key": key,
        "has_previous": True,
        "previous_epoch": previous,
        "reserved_epoch": reserved,
    }


class FakeSerial:
    def __init__(self, events_by_command, **kwargs):
        self.kwargs = kwargs
        self.timeout = kwargs.get("timeout", 0.1)
        self.events_by_command = events_by_command
        self.lines = queue.Queue()
        self.port = None
        self.dtr = True
        self.rts = True
        self.operations = []
        self.opened = False
        self.closed = False

    def open(self):
        self.opened = True
        self.operations.append(("open", self.dtr, self.rts))

    def close(self):
        self.closed = True
        self.operations.append(("close", self.dtr, self.rts))

    def write(self, value):
        command = value.decode("ascii").strip()
        self.operations.append(("write", command))
        for event in self.events_by_command.get(command, []):
            self.lines.put(json.dumps(event).encode("utf-8") + b"\n")
        return len(value)

    def flush(self):
        pass

    def readline(self):
        try:
            return self.lines.get(timeout=self.timeout)
        except queue.Empty:
            return b""


class TestPersistentEpochTransition(unittest.TestCase):
    def test_default_serial_factory_opens_with_modem_lines_inactive(self):
        operations = []

        class FakeOpenedSerial:
            def __init__(self, **kwargs):
                operations.append(("construct", kwargs))
                self.port = None
                self.dtr = True
                self.rts = True

            def open(self):
                operations.append(("open", self.port, self.dtr, self.rts))

        with patch.dict(sys.modules, {"serial": SimpleNamespace(Serial=FakeOpenedSerial)}):
            handle = default_serial_factory("COM37", baudrate=115200, timeout=0.2)

        self.assertEqual(operations[0], (
            "construct", {"port": None, "baudrate": 115200, "timeout": 0.2}
        ))
        self.assertEqual(operations[1], ("open", "COM37", False, False))
        self.assertFalse(handle.dtr)
        self.assertFalse(handle.rts)

    def test_serial_reboot_closes_command_log_when_initial_port_open_fails(self):
        command_logs = []

        class TrackingCommandLog:
            def __init__(self, path):
                self.path = path
                self.closed = False
                command_logs.append(self)

            def close(self):
                self.closed = True

        def unavailable_port(port, **kwargs):
            raise OSError("port unavailable")

        with tempfile.TemporaryDirectory() as temp:
            with patch("serial_dmp_restart.HostCommandLog", TrackingCommandLog):
                with self.assertRaisesRegex(OSError, "port unavailable"):
                    request_serial_restart(
                        "COM37", "s3", "esp32s3", "a" * 16,
                        Path(temp), timeout=0.1, serial_factory=unavailable_port,
                    )

        self.assertEqual(len(command_logs), 1)
        self.assertTrue(command_logs[0].closed)

    def test_serial_reboot_retries_when_reconnected_port_write_fails(self):
        def ready_event(boot_id, reason):
            return {
                "event": "ready",
                "target": "esp32s3",
                "idf": "ESP-IDF v6.1",
                "firmware": "dmp-espnow-dmp/0.1",
                "mac": "20:6e:f1:b0:f0:2c",
                "channel": 1,
                "boot_id": boot_id,
                "reset_reason": reason,
                "decoded_core_mtu_bytes": 256,
                "stream_r_encoded_mtu_bytes": 263,
                "espnow_v1_payload_mtu_bytes": 250,
                "espnow_v2_payload_mtu_bytes": 1470,
                "espnow_version": 2,
                "peer_capacity": 4,
                "entropy_ready": True,
                "test_mode": "authenticated-dmp-endpoint",
            }

        class DisconnectOnWrite(FakeSerial):
            def write(self, value):
                raise OSError("USB serial disconnected during INFO write")

        before = "a" * 16
        after = "b" * 16
        handles = [
            FakeSerial({
                "INFO": [ready_event(before, "power_on")],
                "REBOOT": [{
                    "event": "reboot_requested", "target": "esp32s3", "boot_id": before
                }],
            }),
            DisconnectOnWrite({}),
            FakeSerial({"INFO": [ready_event(after, "software")]}),
        ]
        opened_handles = list(handles)
        opened_ports = []

        def serial_factory(port, **kwargs):
            handle = handles.pop(0)
            opened_ports.append(port)
            handle.port = port
            handle.dtr = False
            handle.rts = False
            handle.open()
            return handle

        with tempfile.TemporaryDirectory() as temp:
            result = request_serial_restart(
                "COM37", "s3", "esp32s3", before, Path(temp),
                timeout=2.0, serial_factory=serial_factory,
            )

        self.assertEqual(opened_ports, ["COM37", "COM37", "COM37"])
        self.assertEqual(result["reconnect_attempts"], 2)
        self.assertEqual(result["boot_id_after"], after)
        self.assertEqual(result["reset_reason_after_command"], "software")
        self.assertTrue(all(handle.closed for handle in opened_handles))

    def test_transition_forwards_serial_factory_to_pair_runner(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            previous_dir = root / "previous"
            previous_dir.mkdir()
            previous_result = {
                "result": "PASS",
                "test_mode": "authenticated-dmp-endpoint",
                "session": "0123456789abcdef",
                "evidence_dir": str(previous_dir),
                "s3_boot_id": "a" * 16,
                "c3_boot_id": "b" * 16,
            }
            (previous_dir / "evidence.json").write_text(
                json.dumps(previous_result), encoding="utf-8"
            )
            (previous_dir / "events_s3.jsonl").write_text(
                json.dumps({"event": nvs_event(1, 2)}) + "\n", encoding="utf-8"
            )

            serial_factory = object()
            observed = {}

            def pair_runner(**kwargs):
                observed.update(kwargs)
                current_dir = Path(kwargs["evidence_dir"]) / "pair_stub"
                current_dir.mkdir()
                current_result = {
                    "result": "PASS",
                    "test_mode": "authenticated-dmp-endpoint",
                    "session": "fedcba9876543210",
                    "evidence_dir": str(current_dir),
                    "s3_boot_id": "c" * 16,
                    "c3_boot_id": "d" * 16,
                    "security_claim": "authenticated DMP pair",
                    "decoded_core_mtu_bytes": 256,
                    "stream_r_encoded_mtu_bytes": 263,
                    "max_observed_frame_bytes": 104,
                }
                (current_dir / "evidence.json").write_text(
                    json.dumps(current_result), encoding="utf-8"
                )
                (current_dir / "events_s3.jsonl").write_text(
                    json.dumps({"event": nvs_event(3, 4, key="s1_epoch_test") | {
                        "session": current_result["session"]
                    }}) + "\n", encoding="utf-8"
                )
                return current_result

            result = run_persistent_transition(
                s3_port="COM37",
                c3_port="COM40",
                previous_run=previous_dir,
                reset_mode="none",
                evidence_dir=root / "evidence",
                pair_runner=pair_runner,
                serial_factory=serial_factory,
            )

        self.assertIs(observed["serial_factory"], serial_factory)
        self.assertEqual(result["result"], "PASS")
        self.assertFalse(result["reset_verified"])
        self.assertEqual(result["epoch_progression"]["current_owner_previous_epoch"], 3)

    def test_serial_reboot_transition_uses_one_open_port_factory_contract(self):
        def ready_event(target, mac, boot_id, reason):
            return {
                "event": "ready",
                "target": target,
                "idf": "ESP-IDF v6.1",
                "firmware": "dmp-espnow-dmp/0.1",
                "mac": mac,
                "channel": 1,
                "boot_id": boot_id,
                "reset_reason": reason,
                "decoded_core_mtu_bytes": 256,
                "stream_r_encoded_mtu_bytes": 263,
                "espnow_v1_payload_mtu_bytes": 250,
                "espnow_v2_payload_mtu_bytes": 1470,
                "espnow_version": 2,
                "peer_capacity": 4,
                "entropy_ready": True,
                "test_mode": "authenticated-dmp-endpoint",
            }

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            previous_dir = root / "previous"
            previous_dir.mkdir()
            previous_result = {
                "result": "PASS",
                "test_mode": "authenticated-dmp-endpoint",
                "session": "0123456789abcdef",
                "evidence_dir": str(previous_dir),
                "s3_boot_id": "a" * 16,
                "c3_boot_id": "b" * 16,
            }
            (previous_dir / "evidence.json").write_text(
                json.dumps(previous_result), encoding="utf-8"
            )
            (previous_dir / "events_s3.jsonl").write_text(
                json.dumps({"event": nvs_event(1, 2)}) + "\n", encoding="utf-8"
            )

            s3_before, s3_after = "c" * 16, "d" * 16
            c3_before, c3_after = "e" * 16, "f" * 16
            handles = [
                FakeSerial({
                    "INFO": [ready_event("esp32s3", "20:6e:f1:b0:f0:2c", s3_before, "power_on")],
                    "REBOOT": [{
                        "event": "reboot_requested", "target": "esp32s3", "boot_id": s3_before
                    }],
                }),
                FakeSerial({
                    "INFO": [ready_event("esp32s3", "20:6e:f1:b0:f0:2c", s3_after, "software")]
                }),
                FakeSerial({
                    "INFO": [ready_event("esp32c3", "94:a9:90:7b:ef:00", c3_before, "power_on")],
                    "REBOOT": [{
                        "event": "reboot_requested", "target": "esp32c3", "boot_id": c3_before
                    }],
                }),
                FakeSerial({
                    "INFO": [ready_event("esp32c3", "94:a9:90:7b:ef:00", c3_after, "software")]
                }),
            ]
            opened_handles = list(handles)
            opened_ports = []

            def serial_factory(port, **kwargs):
                handle = handles.pop(0)
                opened_ports.append(port)
                handle.port = port
                handle.dtr = False
                handle.rts = False
                handle.open()
                return handle

            pair_call = {}

            def pair_runner(**kwargs):
                pair_call.update(kwargs)
                current_dir = Path(kwargs["evidence_dir"]) / "pair_stub"
                current_dir.mkdir()
                current_result = {
                    "result": "PASS",
                    "test_mode": "authenticated-dmp-endpoint",
                    "session": "fedcba9876543210",
                    "evidence_dir": str(current_dir),
                    "s3_boot_id": s3_after,
                    "c3_boot_id": c3_after,
                    "s3_reset_reason": "software",
                    "c3_reset_reason": "software",
                    "security_claim": "authenticated DMP pair",
                    "decoded_core_mtu_bytes": 256,
                    "stream_r_encoded_mtu_bytes": 263,
                    "max_observed_frame_bytes": 104,
                }
                (current_dir / "evidence.json").write_text(
                    json.dumps(current_result), encoding="utf-8"
                )
                current_nvs = nvs_event(3, 4)
                current_nvs["session"] = current_result["session"]
                (current_dir / "events_s3.jsonl").write_text(
                    json.dumps({"event": current_nvs}) + "\n", encoding="utf-8"
                )
                return current_result

            result = run_persistent_transition(
                s3_port="COM37",
                c3_port="COM40",
                previous_run=previous_dir,
                reset_mode="serial-reboot",
                evidence_dir=root / "evidence",
                timeout=2.0,
                pair_runner=pair_runner,
                serial_factory=serial_factory,
            )

        self.assertEqual(opened_ports, ["COM37", "COM37", "COM40", "COM40"])
        self.assertIs(pair_call["serial_factory"], serial_factory)
        self.assertTrue(result["reset_verified"])
        self.assertEqual(result["epoch_progression"]["current_owner_previous_epoch"], 3)
        self.assertEqual(result["current_pair"]["nvs_epoch_check"]["reserved_epoch"], 4)
        self.assertEqual(result["current_pair"]["s3_reset_reason"], "software")
        self.assertEqual(result["current_pair"]["c3_reset_reason"], "software")
        self.assertTrue(all(handle.closed for handle in opened_handles))

    def test_boot_transition_requires_both_targets_to_reboot(self):
        previous = {"s3_boot_id": "a" * 16, "c3_boot_id": "b" * 16}
        current = {"s3_boot_id": "c" * 16, "c3_boot_id": "d" * 16}
        self.assertEqual(
            validate_boot_identity_transition(previous, current),
            {"s3": {"before": "a" * 16, "after": "c" * 16},
             "c3": {"before": "b" * 16, "after": "d" * 16}},
        )
        with self.assertRaisesRegex(DmpTestError, "S3 boot identity did not change"):
            validate_boot_identity_transition(previous, {**current, "s3_boot_id": "a" * 16})

    def test_external_power_mode_requires_operator_attestation(self):
        with self.assertRaisesRegex(DmpTestError, "requires operator confirmation"):
            run_persistent_transition(
                s3_port="COM37",
                c3_port="COM40",
                previous_run="not-read-before-attestation-check",
                reset_mode="external-power",
                evidence_dir="unused",
            )

    def test_external_power_preflight_refuses_same_boot_before_pair_setup(self):
        ready = {
            "event": "ready", "target": "esp32s3", "idf": "ESP-IDF v6.1",
            "firmware": "dmp-espnow-dmp/0.1", "mac": "20:6e:f1:b0:f0:2c",
            "channel": 1, "boot_id": "a" * 16, "reset_reason": "software",
            "decoded_core_mtu_bytes": 256, "stream_r_encoded_mtu_bytes": 263,
            "espnow_v1_payload_mtu_bytes": 250, "espnow_v2_payload_mtu_bytes": 1470,
            "espnow_version": 2, "peer_capacity": 4,
            "test_mode": "authenticated-dmp-endpoint",
        }
        handle = FakeSerial({"INFO": [ready]})
        opened_ports = []

        def serial_factory(port, **kwargs):
            opened_ports.append(port)
            handle.port = port
            handle.open()
            return handle

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            previous_dir = root / "previous"
            previous_dir.mkdir()
            previous = {
                "result": "PASS", "test_mode": "authenticated-dmp-endpoint",
                "session": "0123456789abcdef", "evidence_dir": str(previous_dir),
                "s3_boot_id": "a" * 16, "c3_boot_id": "b" * 16,
            }
            (previous_dir / "evidence.json").write_text(
                json.dumps(previous), encoding="utf-8"
            )
            (previous_dir / "events_s3.jsonl").write_text(
                json.dumps({"event": nvs_event(1, 2)}) + "\n", encoding="utf-8"
            )

            def unexpected_pair_runner(**kwargs):
                self.fail("pair setup must not run before the external-reset preflight passes")

            with self.assertRaisesRegex(DmpTestError, "boot identity did not change"):
                run_persistent_transition(
                    s3_port="COM37", c3_port="COM40", previous_run=previous_dir,
                    reset_mode="external-power", operator_confirms_power_cycle=True,
                    evidence_dir=root / "evidence", pair_runner=unexpected_pair_runner,
                    serial_factory=serial_factory,
                )

        self.assertEqual(opened_ports, ["COM37"])
        self.assertIn(("write", "INFO"), handle.operations)
        self.assertNotIn(("write", "SESSION 0123456789abcdef"), handle.operations)
        self.assertTrue(handle.closed)

    def test_external_power_preflight_accepts_fresh_power_on_boots(self):
        def ready(target, mac, boot_id):
            return {
                "event": "ready", "target": target, "idf": "ESP-IDF v6.1",
                "firmware": "dmp-espnow-dmp/0.1", "mac": mac,
                "channel": 1, "boot_id": boot_id, "reset_reason": "power_on",
                "decoded_core_mtu_bytes": 256, "stream_r_encoded_mtu_bytes": 263,
                "espnow_v1_payload_mtu_bytes": 250, "espnow_v2_payload_mtu_bytes": 1470,
                "espnow_version": 2, "peer_capacity": 4,
                "test_mode": "authenticated-dmp-endpoint",
            }

        handles = [
            FakeSerial({"INFO": [ready("esp32s3", "20:6e:f1:b0:f0:2c", "c" * 16)]}),
            FakeSerial({"INFO": [ready("esp32c3", "94:a9:90:7b:ef:00", "d" * 16)]}),
        ]
        opened_ports = []

        def serial_factory(port, **kwargs):
            handle = handles.pop(0)
            opened_ports.append(port)
            handle.port = port
            handle.open()
            return handle

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            previous_dir = root / "previous"
            previous_dir.mkdir()
            previous = {
                "result": "PASS", "test_mode": "authenticated-dmp-endpoint",
                "session": "0123456789abcdef", "evidence_dir": str(previous_dir),
                "s3_boot_id": "a" * 16, "c3_boot_id": "b" * 16,
            }
            (previous_dir / "evidence.json").write_text(
                json.dumps(previous), encoding="utf-8"
            )
            (previous_dir / "events_s3.jsonl").write_text(
                json.dumps({"event": nvs_event(1, 2)}) + "\n", encoding="utf-8"
            )

            current_dir = root / "evidence" / "pair_stub"

            def pair_runner(**kwargs):
                current_dir.mkdir(parents=True)
                result = {
                    "result": "PASS", "test_mode": "authenticated-dmp-endpoint",
                    "session": "fedcba9876543210", "evidence_dir": str(current_dir),
                    "s3_boot_id": "c" * 16, "c3_boot_id": "d" * 16,
                    "s3_reset_reason": "power_on", "c3_reset_reason": "power_on",
                    "security_claim": "authenticated DMP pair",
                    "decoded_core_mtu_bytes": 256, "stream_r_encoded_mtu_bytes": 263,
                    "max_observed_frame_bytes": 104,
                }
                (current_dir / "evidence.json").write_text(
                    json.dumps(result), encoding="utf-8"
                )
                check = nvs_event(3, 4)
                check["session"] = result["session"]
                (current_dir / "events_s3.jsonl").write_text(
                    json.dumps({"event": check}) + "\n", encoding="utf-8"
                )
                return result

            result = run_persistent_transition(
                s3_port="COM37", c3_port="COM40", previous_run=previous_dir,
                reset_mode="external-power", operator_confirms_power_cycle=True,
                evidence_dir=root / "evidence", pair_runner=pair_runner,
                serial_factory=serial_factory,
            )

        self.assertEqual(opened_ports, ["COM37", "COM40"])
        self.assertTrue(all(handle.closed for handle in handles))
        self.assertEqual([record["reset_reason_after_power_cycle"] for record in result["reset_records"]],
                         ["power_on", "power_on"])
        self.assertTrue(result["operator_power_cycle_attested"])
        self.assertTrue(result["reset_verified"])
        self.assertEqual(result["epoch_progression"]["current_owner_previous_epoch"], 3)

    def test_qualification_firmware_never_erases_nvs_on_startup_failure(self):
        source = FIRMWARE_MAIN.read_text(encoding="utf-8")
        self.assertNotIn("nvs_flash_erase(", source)
        self.assertIn('\\"reason\\":\\"nvs-init\\"', source)
        self.assertIn('\\"erase_attempted\\":false', source)

    def test_reboot_confirmation_is_flushed_before_restart(self):
        source = FIRMWARE_MAIN.read_text(encoding="utf-8")
        start = source.index('if (strcmp(line, "REBOOT") == 0)')
        end = source.index("} else if", start)
        reboot_handler = source[start:end]
        self.assertLess(reboot_handler.index("printf("), reboot_handler.index("fflush(stdout)"))
        self.assertLess(reboot_handler.index("fflush(stdout)"), reboot_handler.index("esp_restart()"))

    def test_epoch_advances_once_for_owner_then_once_for_check(self):
        result = validate_persistent_epoch_transition(nvs_event(36, 37), nvs_event(38, 39))
        self.assertEqual(result["previous_check_reserved_epoch"], 37)
        self.assertEqual(result["current_owner_previous_epoch"], 38)
        self.assertEqual(result["current_check_reserved_epoch"], 39)

    def test_rejects_lost_or_rolled_back_nvs(self):
        with self.assertRaisesRegex(DmpTestError, "did not retain a prior epoch"):
            validate_persistent_epoch_transition(
                nvs_event(36, 37), {**nvs_event(0, 1), "has_previous": False}
            )

    def test_rejects_unexpected_epoch_jump(self):
        with self.assertRaisesRegex(DmpTestError, "owner reservation after reset"):
            validate_persistent_epoch_transition(nvs_event(36, 37), nvs_event(40, 41))

    def test_rejects_nonconsecutive_check_reservation(self):
        with self.assertRaisesRegex(DmpTestError, "did not reserve the next distinct epoch"):
            validate_persistent_epoch_transition(nvs_event(36, 37), nvs_event(38, 40))

    def test_rejects_namespace_or_key_change(self):
        with self.assertRaisesRegex(DmpTestError, "namespace/key changed"):
            validate_persistent_epoch_transition(
                nvs_event(36, 37), nvs_event(38, 39, key="s1_epoch_mp")
            )

    def test_loads_exactly_one_validated_epoch_event(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "evidence.json").write_text(json.dumps({
                "result": "PASS",
                "test_mode": "authenticated-dmp-endpoint",
                "session": "0123456789abcdef",
                "evidence_dir": str(run_dir),
            }), encoding="utf-8")
            (run_dir / "events_s3.jsonl").write_text(
                json.dumps({"event": nvs_event(38, 39)}) + "\n", encoding="utf-8"
            )
            result, event = load_pair_nvs_event(run_dir)
            self.assertEqual(result["session"], "0123456789abcdef")
            self.assertEqual(event["reserved_epoch"], 39)

    def test_rejects_multiple_epoch_events(self):
        with tempfile.TemporaryDirectory() as temp:
            run_dir = Path(temp)
            (run_dir / "evidence.json").write_text(json.dumps({
                "result": "PASS",
                "test_mode": "authenticated-dmp-endpoint",
                "session": "0123456789abcdef",
            }), encoding="utf-8")
            records = [{"event": nvs_event(38, 39)}, {"event": nvs_event(39, 40)}]
            (run_dir / "events_s3.jsonl").write_text(
                "\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(DmpTestError, "exactly one"):
                load_pair_nvs_event(run_dir)

    def test_serial_reboot_requires_requested_and_new_boot_ready(self):
        previous_boot = "a" * 16
        next_boot = "c" * 16
        previous_pair_boot = "b" * 16
        before_handle = FakeSerial({
            "INFO": [{
                "event": "ready", "target": "esp32s3", "idf": "ESP-IDF v6.1",
                "firmware": "dmp-espnow-dmp/0.1", "mac": "28:37:2f:75:5d:64",
                "channel": 1, "boot_id": previous_boot, "reset_reason": "power_on",
                "decoded_core_mtu_bytes": 256,
                "stream_r_encoded_mtu_bytes": 263, "espnow_v1_payload_mtu_bytes": 250,
                "espnow_v2_payload_mtu_bytes": 1470, "espnow_version": 2,
                "peer_capacity": 4, "entropy_ready": True,
                "test_mode": "authenticated-dmp-endpoint",
            }],
            "REBOOT": [{
                "event": "reboot_requested", "target": "esp32s3", "boot_id": previous_boot
            }],
        })
        after_handle = FakeSerial({
            "INFO": [{
                "event": "ready", "target": "esp32s3", "idf": "ESP-IDF v6.1",
                "firmware": "dmp-espnow-dmp/0.1", "mac": "28:37:2f:75:5d:64",
                "channel": 1, "boot_id": next_boot, "reset_reason": "software",
                "decoded_core_mtu_bytes": 256,
                "stream_r_encoded_mtu_bytes": 263, "espnow_v1_payload_mtu_bytes": 250,
                "espnow_v2_payload_mtu_bytes": 1470, "espnow_version": 2,
                "peer_capacity": 4, "entropy_ready": True,
                "test_mode": "authenticated-dmp-endpoint",
            }],
        })
        handles = iter((before_handle, after_handle))
        factory_calls = []

        def factory(port, **kwargs):
            factory_calls.append((port, kwargs))
            handle = next(handles)
            handle.port = port
            handle.dtr = False
            handle.rts = False
            handle.open()
            return handle

        with tempfile.TemporaryDirectory() as temp:
            evidence = request_serial_restart(
                "COM37", "s3", "esp32s3", previous_pair_boot, Path(temp),
                serial_factory=factory,
            )
        self.assertEqual(evidence["pair_boot_id_before"], previous_pair_boot)
        self.assertEqual(evidence["boot_id_before"], previous_boot)
        self.assertEqual(evidence["boot_id_after"], next_boot)
        self.assertTrue(evidence["boot_changed_since_previous_pair"])
        self.assertTrue(evidence["reboot_request_observed"])
        self.assertTrue(evidence["boot_transition_observed"])
        self.assertEqual(evidence["reset_reason_after_command"], "software")
        self.assertEqual(evidence["reconnect_attempts"], 1)
        self.assertEqual([call[0] for call in factory_calls], ["COM37", "COM37"])
        self.assertTrue(evidence["reboot_request_observed"])
        self.assertTrue(evidence["boot_transition_observed"])
        self.assertIn(("write", "REBOOT"), before_handle.operations)
        self.assertTrue(before_handle.opened)
        self.assertTrue(before_handle.closed)
        self.assertTrue(after_handle.opened)
        self.assertTrue(after_handle.closed)
        self.assertFalse(before_handle.dtr)
        self.assertFalse(before_handle.rts)
        self.assertFalse(after_handle.dtr)
        self.assertFalse(after_handle.rts)

    def test_serial_reboot_rejects_nonsoftware_reset_reason(self):
        common_ready = {
            "event": "ready", "target": "esp32s3", "idf": "ESP-IDF v6.1",
            "firmware": "dmp-espnow-dmp/0.1", "mac": "28:37:2f:75:5d:64",
            "channel": 1, "decoded_core_mtu_bytes": 256,
            "stream_r_encoded_mtu_bytes": 263, "espnow_v1_payload_mtu_bytes": 250,
            "espnow_v2_payload_mtu_bytes": 1470, "espnow_version": 2,
            "peer_capacity": 4, "entropy_ready": True,
            "test_mode": "authenticated-dmp-endpoint",
        }
        before = {**common_ready, "boot_id": "a" * 16, "reset_reason": "power_on"}
        after = {**common_ready, "boot_id": "b" * 16, "reset_reason": "panic"}
        handles = [
            FakeSerial({
                "INFO": [before],
                "REBOOT": [{
                    "event": "reboot_requested", "target": "esp32s3", "boot_id": before["boot_id"]
                }],
            }),
            FakeSerial({"INFO": [after]}),
        ]

        def factory(port, **kwargs):
            handle = handles.pop(0)
            handle.port = port
            handle.dtr = False
            handle.rts = False
            handle.open()
            return handle

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(DmpTestError, "expected 'software'"):
                request_serial_restart(
                    "COM37", "s3", "esp32s3", "c" * 16, Path(temp),
                    timeout=1.0, serial_factory=factory,
                )


if __name__ == "__main__":
    unittest.main()
