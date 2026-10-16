"""CI-safe tests for the one-S3/three-C3 ESP-NOW smoke harness."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

HARDWARE_RUNNER_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_pair"
sys.path.insert(0, str(HARDWARE_RUNNER_DIR))

import serial_four
from serial_pair import PairTestError


SIDES = ("s3", "c3_1", "c3_2", "c3_3")
MACS = {
    "s3": "20:6e:f1:b0:f0:2c",
    "c3_1": "28:37:2f:75:5d:64",
    "c3_2": "18:8b:0e:31:be:9c",
    "c3_3": "88:56:a6:63:c2:78",
}
SESSION = "0123456789abcdef"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
FIRMWARE_MAIN = HARDWARE_RUNNER_DIR / "main" / "main.c"


def ready(side: str) -> dict:
    return {
        "event": "ready",
        "target": "esp32s3" if side == "s3" else "esp32c3",
        "idf": "ESP-IDF v6.1",
        "firmware": "dmp-espnow-pair/0.1",
        "mac": MACS[side],
        "channel": 1,
        "decoded_core_mtu_bytes": 256,
        "stream_r_encoded_mtu_bytes": 263,
        "espnow_v1_payload_mtu_bytes": 250,
        "peer_capacity": 3 if side == "s3" else 1,
        "test_mode": "unauthenticated-core-echo",
    }


def passing_events(count_per_peer: int = 2, session: str = SESSION) -> list[tuple[str, dict]]:
    total = count_per_peer * 3
    events = [(side, ready(side)) for side in SIDES]
    for side in SIDES:
        events.append((side, {
            "event": "session_set", "session": session,
            "target": "esp32s3" if side == "s3" else "esp32c3",
            "mac": MACS[side],
        }))
    for index, side in enumerate(SIDES[1:], start=1):
        events.append(("s3", {"event": "peer_added", "session": session,
                               "peer_mac": MACS[side], "peer_count": index}))
        events.extend([
            (side, {"event": "peer_added", "session": session,
                    "peer_mac": MACS["s3"], "peer_count": 1}),
            (side, {"event": "echo_mode", "session": session, "enabled": True}),
        ])
    events.append(("s3", {"event": "run_started", "session": session,
                           "count": total, "payload_bytes": 64, "peer_count": 3}))
    for sequence in range(1, total + 1):
        peer_side = SIDES[1 + ((sequence - 1) % 3)]
        events.extend([
            ("s3", {"event": "tx_done", "session": session, "seq": sequence,
                    "peer_mac": MACS[peer_side], "status": "success"}),
            (peer_side, {"event": "rx_valid", "session": session, "seq": sequence,
                         "src_mac": MACS["s3"], "core_frame_bytes": 68}),
            (peer_side, {"event": "echo_tx_done", "session": session, "seq": sequence,
                         "peer_mac": MACS["s3"], "status": "success"}),
            ("s3", {"event": "round_trip", "session": session, "seq": sequence,
                    "peer_mac": MACS[peer_side], "tx_done": True,
                    "echo_match": True, "core_frame_bytes": 68}),
        ])
    for side in SIDES[1:]:
        events.append((side, {"event": "stats", "session": session,
                              "echo_rx": count_per_peer, "echo_tx_ok": count_per_peer,
                              "echo_tx_failed": 0}))
    events.append(("s3", {"event": "run_done", "session": session, "pass": True,
                           "completed": total, "payload_bytes": 64, "peer_count": 3,
                           "max_core_frame_bytes": 68}))
    return events


class FourPeerValidatorTests(unittest.TestCase):
    def test_accepts_complete_single_owner_three_peer_trace(self):
        result = serial_four.validate_four_peer_events(passing_events(), 2, 64, SESSION)
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["peer_count"], 3)
        self.assertEqual(result["round_trips"], 6)
        self.assertEqual(result["decoded_core_mtu_bytes"], 256)
        self.assertEqual(result["stream_r_encoded_mtu_bytes"], 263)
        self.assertEqual(result["espnow_v1_payload_mtu_bytes"], 250)
        self.assertIn("not dmp_endpoint", result["endpoint_claim"])
        self.assertIn("serialized", result["four_parallel_claim"])

    def test_rejects_peer_that_breaks_round_robin_isolation(self):
        events = passing_events()
        events = [(side, {**event, "peer_mac": MACS["c3_1"]}
                   if side == "s3" and event.get("event") == "round_trip" and
                   event.get("seq") == 2 else event) for side, event in events]
        with self.assertRaisesRegex(PairTestError, "round-robin peer order"):
            serial_four.validate_four_peer_events(events, 2, 64, SESSION)

    def test_rejects_a_missing_c3_echo_even_when_s3_trace_is_complete(self):
        events = [(side, event) for side, event in passing_events()
                  if not (side == "c3_2" and event.get("event") == "echo_tx_done" and
                          event.get("seq") == 2)]
        with self.assertRaisesRegex(PairTestError, "echo callback sequence"):
            serial_four.validate_four_peer_events(events, 2, 64, SESSION)

    def test_rejects_duplicate_physical_mac(self):
        events = [(side, {**event, "mac": MACS["c3_1"]}
                   if side == "c3_2" and event.get("event") == "ready" else event)
                  for side, event in passing_events()]
        with self.assertRaisesRegex(PairTestError, "duplicate station MAC"):
            serial_four.validate_four_peer_events(events, 2, 64, SESSION)

    def test_firmware_checks_deadline_before_rx_and_after_releasing_tx_callback(self):
        source = FIRMWARE_MAIN.read_text(encoding="utf-8")
        app_main = source.split("void app_main(void)", maxsplit=1)[1]
        loop = app_main.split("for (;;) {", maxsplit=1)[1]
        tx_branch = loop.index("if (event.kind == EVENT_TX_DONE)")
        tx_dispatch = loop.index("process_wifi_event(&event);", tx_branch)
        tx_timeout = loop.index("check_run_timeout();", tx_dispatch)
        else_branch = loop.index("} else {", tx_timeout)
        rx_timeout = loop.index("check_run_timeout();", else_branch)
        rx_dispatch = loop.index("process_wifi_event(&event);", rx_timeout)
        advance = loop.index("advance_run();", rx_dispatch)

        self.assertLess(tx_branch, tx_dispatch)
        self.assertLess(tx_dispatch, tx_timeout)
        self.assertLess(tx_timeout, else_branch)
        self.assertLess(rx_timeout, rx_dispatch)
        self.assertLess(rx_dispatch, advance)


class FourPeerEspNowStub:
    """Four in-memory serial endpoints with a deterministic round-robin link."""

    def __init__(self, fail_run: bool = False, failure_reason: str = "stubbed-round-trip-timeout"):
        self.fail_run = fail_run
        self.failure_reason = failure_reason
        self.devices = {}
        self.commands = []
        self.peer_counts = {side: 0 for side in SIDES}
        self.echo_rx = {side: 0 for side in SIDES[1:]}
        self.echo_tx_ok = {side: 0 for side in SIDES[1:]}

    def attach(self, device):
        self.devices[device.spec.side] = device

    def emit(self, side: str, event: dict):
        self.devices[side].event_queue.put((side, event))

    def run(self, session: str, total: int, payload_bytes: int):
        self.emit("s3", {"event": "run_started", "session": session,
                          "count": total, "payload_bytes": payload_bytes,
                          "peer_count": 3})
        if self.fail_run:
            self.emit("s3", {"event": "run_done", "session": session,
                              "pass": False, "completed": 0, "peer_count": 3,
                              "reason": self.failure_reason})
            return
        core_frame_bytes = payload_bytes + 4
        for sequence in range(1, total + 1):
            side = SIDES[1 + ((sequence - 1) % 3)]
            self.emit("s3", {"event": "tx_done", "session": session, "seq": sequence,
                              "peer_mac": MACS[side], "status": "success"})
            self.emit(side, {"event": "rx_valid", "session": session, "seq": sequence,
                             "src_mac": MACS["s3"], "core_frame_bytes": core_frame_bytes})
            self.emit(side, {"event": "echo_tx_done", "session": session, "seq": sequence,
                             "peer_mac": MACS["s3"], "status": "success"})
            self.emit("s3", {"event": "round_trip", "session": session, "seq": sequence,
                              "peer_mac": MACS[side], "tx_done": True,
                              "echo_match": True, "core_frame_bytes": core_frame_bytes})
            self.echo_rx[side] += 1
            self.echo_tx_ok[side] += 1
        for side in SIDES[1:]:
            if self.echo_rx[side] != 0:
                continue
        self.emit("s3", {"event": "run_done", "session": session, "pass": True,
                          "completed": total, "payload_bytes": payload_bytes,
                          "peer_count": 3, "max_core_frame_bytes": core_frame_bytes})


class StubSerialCapture:
    radio: FourPeerEspNowStub

    def __init__(self, spec, _output, event_queue, command_log):
        self.spec = spec
        self.event_queue = event_queue
        self.command_log = command_log
        self.session = None
        self.radio.attach(self)

    def write_line(self, command: str):
        payload = command.encode("ascii") + b"\n"
        self.command_log.record(self.spec.port, command, "attempted")
        self.radio.commands.append((self.spec.side, command))
        self.command_log.record(self.spec.port, command, "written",
                                bytes_written=len(payload), bytes_requested=len(payload))
        if command == "INFO":
            event = ready(self.spec.side)
            event["idf"] = "host-stub"
            self.event_queue.put((self.spec.side, event))
        elif command.startswith("SESSION "):
            self.session = command.split(" ", 1)[1]
            self.event_queue.put((self.spec.side, {
                "event": "session_set", "session": self.session,
                "target": "esp32s3" if self.spec.side == "s3" else "esp32c3",
                "mac": MACS[self.spec.side],
            }))
        elif command.startswith("PEER "):
            self.radio.peer_counts[self.spec.side] += 1
            self.event_queue.put((self.spec.side, {
                "event": "peer_added", "session": self.session,
                "peer_mac": command.split(" ", 1)[1],
                "peer_count": self.radio.peer_counts[self.spec.side],
            }))
        elif command == "ECHO ON":
            self.event_queue.put((self.spec.side, {
                "event": "echo_mode", "session": self.session, "enabled": True,
            }))
        elif command.startswith("RUN "):
            _, total, payload_bytes = command.split(" ")
            self.radio.run(self.session, int(total), int(payload_bytes))
        elif command == "STATS":
            self.event_queue.put((self.spec.side, {
                "event": "stats", "session": self.session,
                "echo_rx": self.radio.echo_rx[self.spec.side],
                "echo_tx_ok": self.radio.echo_tx_ok[self.spec.side],
                "echo_tx_failed": 0,
            }))

    def close(self):
        pass


class FourPeerRunnerStubTests(unittest.TestCase):
    def run_with_stub(self, root: Path, fail_run: bool,
                      failure_reason: str = "stubbed-round-trip-timeout",
                      c3_bin_overrides: dict[str, bytes] | None = None):
        s3_image = root / "s3.bin"
        c3_image = root / "c3.bin"
        s3_image.write_bytes(b"host-stub-s3-image")
        c3_image.write_bytes(b"host-stub-c3-image")
        output = root / "evidence"
        arguments = [
            "--s3-port", "STUB-S3", "--c3-ports", "STUB-C3-1,STUB-C3-2,STUB-C3-3",
            "--s3-bin", str(s3_image), "--c3-bin", str(c3_image),
            "--evidence-root", str(root / "unused-evidence-root"),
            "--output-dir", str(output), "--count-per-peer", "2", "--payload-bytes", "64",
        ]
        for port, contents in (c3_bin_overrides or {}).items():
            image = root / f"{port.lower()}-image.bin"
            image.write_bytes(contents)
            arguments.extend(["--c3-bin-for-port", f"{port}={image}"])
        args = serial_four.build_parser().parse_args(arguments)
        radio = FourPeerEspNowStub(fail_run=fail_run, failure_reason=failure_reason)
        StubSerialCapture.radio = radio
        with patch.object(serial_four, "SerialCapture", StubSerialCapture), \
                patch.object(serial_four, "collect_port_inventory", return_value={}):
            serial_four.run(args)
        return output, radio

    def test_rejects_image_override_for_unconfigured_c3_port(self):
        with self.assertRaisesRegex(PairTestError, "unconfigured C3 port"):
            serial_four.c3_images_for_ports(
                ["COM36", "COM38", "COM35"], Path("common.bin"), ["COM39=other.bin"],
            )

    def test_default_ports_match_current_three_c3_bench(self):
        self.assertEqual(
            serial_four.build_parser().get_default("c3_ports"),
            "COM36,COM38,COM40",
        )

    def test_rejects_duplicate_image_override_for_c3_port(self):
        with self.assertRaisesRegex(PairTestError, "repeated for COM35"):
            serial_four.c3_images_for_ports(
                ["COM36", "COM38", "COM35"], Path("common.bin"),
                ["COM35=first.bin", "com35=second.bin"],
            )

    def test_runner_configures_one_owner_and_three_peers(self):
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT / "dev") as directory:
            output, radio = self.run_with_stub(Path(directory), fail_run=False)
            metadata = json.loads((output / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["result"]["result"], "PASS")
            self.assertEqual(metadata["result"]["peer_count"], 3)
            self.assertEqual(metadata["result"]["round_trips"], 6)
            self.assertEqual([radio.peer_counts[side] for side in SIDES], [3, 1, 1, 1])
            self.assertTrue(any(side == "s3" and command == "RUN 6 64"
                                for side, command in radio.commands))
            self.assertEqual(metadata["dtr"], False)
            self.assertEqual(metadata["rts"], False)

    def test_runner_records_per_port_c3_image_hashes(self):
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT / "dev") as directory:
            output, _ = self.run_with_stub(
                Path(directory), fail_run=False,
                c3_bin_overrides={"STUB-C3-3": b"host-stub-c3-uart-image"},
            )
            metadata = json.loads((output / "run.json").read_text(encoding="utf-8"))
            default_hash = hashlib.sha256(b"host-stub-c3-image").hexdigest()
            override_hash = hashlib.sha256(b"host-stub-c3-uart-image").hexdigest()
            self.assertEqual(metadata["images"]["c3_1"]["sha256"], default_hash)
            self.assertEqual(metadata["images"]["c3_2"]["sha256"], default_hash)
            self.assertEqual(metadata["images"]["c3_3"]["sha256"], override_hash)

    def test_runner_fails_closed_on_current_s3_run_failure(self):
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT / "dev") as directory:
            output = Path(directory) / "evidence"
            try:
                self.run_with_stub(Path(directory), fail_run=True)
            except PairTestError as error:
                self.assertIn("failure for the current three-peer session", str(error))
            else:
                self.fail("current failed multi-peer run was accepted")
            metadata = json.loads((output / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["result"]["result"], "FAIL")

    def test_runner_fails_closed_when_firmware_times_out_before_final_echo(self):
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT / "dev") as directory:
            output = Path(directory) / "evidence"
            try:
                self.run_with_stub(Path(directory), fail_run=True,
                                   failure_reason="round-trip-timeout")
            except PairTestError as error:
                self.assertIn("failure for the current three-peer session", str(error))
            else:
                self.fail("firmware round-trip timeout was accepted as a passing run")
            metadata = json.loads((output / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["result"]["result"], "FAIL")
            self.assertIn("round-trip-timeout", metadata["result"]["error"])


if __name__ == "__main__":
    unittest.main()
