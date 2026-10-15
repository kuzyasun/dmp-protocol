"""CI-safe orchestration test for the hardware pair runner using an ESP-NOW stub."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from unittest.mock import patch

HARDWARE_RUNNER_DIR = Path(__file__).resolve().parents[2] / "embedded" / "espnow_pair"
sys.path.insert(0, str(HARDWARE_RUNNER_DIR))

import serial_pair


S3_MAC = "28:37:2f:75:5d:64"
C3_MAC = "20:6e:f1:b0:f0:2c"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class EspNowSerialStub:
    """Two in-memory serial endpoints with a deterministic ESP-NOW echo link."""

    def __init__(self, fail_run: bool = False,
                 fail_echo_sequence: int | None = None):
        self.fail_run = fail_run
        self.fail_echo_sequence = fail_echo_sequence
        self.devices = {}
        self.commands = []
        self.echo_rx = 0
        self.echo_tx_ok = 0
        self.echo_tx_failed = 0

    def attach(self, device):
        self.devices[device.spec.side] = device

    def emit(self, side: str, event: dict):
        self.devices[side].event_queue.put((side, event))

    def run(self, session: str, count: int, payload_bytes: int):
        self.emit("s3", {"event": "run_started", "session": session,
                          "count": count, "payload_bytes": payload_bytes,
                          "peer_count": 1})
        if self.fail_run:
            self.emit("s3", {"event": "run_done", "session": session,
                              "pass": False, "completed": 0,
                              "peer_count": 1, "reason": "stubbed-round-trip-timeout"})
            return

        core_frame_bytes = payload_bytes + 10
        for sequence in range(1, count + 1):
            echo_tx_ok = sequence != self.fail_echo_sequence
            self.emit("s3", {"event": "tx_done", "session": session,
                              "seq": sequence, "status": "success"})
            self.emit("c3", {"event": "rx_valid", "session": session,
                              "seq": sequence, "src_mac": S3_MAC,
                              "core_frame_bytes": core_frame_bytes})
            self.emit("c3", {"event": "echo_tx_done", "session": session,
                              "seq": sequence, "peer_mac": S3_MAC,
                              "status": "success" if echo_tx_ok else "failed"})
            self.emit("s3", {"event": "round_trip", "session": session,
                              "seq": sequence, "peer_mac": C3_MAC,
                              "tx_done": True, "echo_match": True,
                              "core_frame_bytes": core_frame_bytes})
        self.echo_rx = count
        self.echo_tx_failed = int(self.fail_echo_sequence is not None and
                                  1 <= self.fail_echo_sequence <= count)
        self.echo_tx_ok = count - self.echo_tx_failed
        self.emit("s3", {"event": "run_done", "session": session,
                          "pass": True, "completed": count,
                          "payload_bytes": payload_bytes, "peer_count": 1,
                          "max_core_frame_bytes": core_frame_bytes})


class StubSerialCapture:
    pair: EspNowSerialStub

    def __init__(self, spec, _output, event_queue, command_log):
        self.spec = spec
        self.event_queue = event_queue
        self.command_log = command_log
        self.session = None
        self.pair.attach(self)

    def write_line(self, command: str):
        self.command_log.record(self.spec.port, command, "attempted")
        self.pair.commands.append((self.spec.side, command))
        self.command_log.record(self.spec.port, command, "written",
                                bytes_written=len(command.encode("ascii")) + 1,
                                bytes_requested=len(command.encode("ascii")) + 1)
        if command == "INFO":
            target, mac = ("esp32s3", S3_MAC) if self.spec.side == "s3" else ("esp32c3", C3_MAC)
            self.event_queue.put((self.spec.side, {
                "event": "ready", "target": target, "idf": "host-stub",
                "firmware": "dmp-espnow-pair/0.1", "mac": mac, "channel": 1,
                "decoded_core_mtu_bytes": 256, "stream_r_encoded_mtu_bytes": 263,
                "espnow_v1_payload_mtu_bytes": 250,
                "peer_capacity": 3 if self.spec.side == "s3" else 1,
                "test_mode": "unauthenticated-core-echo",
            }))
        elif command.startswith("SESSION "):
            self.session = command.split(" ", 1)[1]
            target, mac = ("esp32s3", S3_MAC) if self.spec.side == "s3" else ("esp32c3", C3_MAC)
            self.event_queue.put((self.spec.side, {
                "event": "session_set", "session": self.session,
                "target": target, "mac": mac,
            }))
        elif command.startswith("PEER "):
            self.event_queue.put((self.spec.side, {
                "event": "peer_added", "session": self.session,
                "peer_mac": command.split(" ", 1)[1],
                "peer_count": 1,
            }))
        elif command == "ECHO ON":
            self.event_queue.put((self.spec.side, {
                "event": "echo_mode", "session": self.session, "enabled": True,
            }))
        elif command.startswith("RUN "):
            _, count, payload_bytes = command.split(" ")
            self.pair.run(self.session, int(count), int(payload_bytes))
        elif command == "STATS":
            self.event_queue.put((self.spec.side, {
                "event": "stats", "session": self.session,
                "echo_rx": self.pair.echo_rx,
                "echo_tx_ok": self.pair.echo_tx_ok,
                "echo_tx_failed": self.pair.echo_tx_failed,
            }))

    def close(self):
        pass


class RunnerHostStubTests(unittest.TestCase):
    def run_with_stub(self, root: Path, fail_run: bool,
                      fail_echo_sequence: int | None = None):
        s3_image = root / "s3.bin"
        c3_image = root / "c3.bin"
        s3_image.write_bytes(b"host-stub-s3-image")
        c3_image.write_bytes(b"host-stub-c3-image")
        output = root / "evidence"
        args = serial_pair.build_parser().parse_args([
            "--s3-port", "STUB-S3", "--c3-port", "STUB-C3",
            "--s3-bin", str(s3_image), "--c3-bin", str(c3_image),
            "--evidence-root", str(root / "unused-evidence-root"),
            "--output-dir", str(output), "--count", "2", "--payload-bytes", "64",
        ])
        pair = EspNowSerialStub(fail_run=fail_run,
                                fail_echo_sequence=fail_echo_sequence)
        StubSerialCapture.pair = pair
        with patch.object(serial_pair, "SerialCapture", StubSerialCapture), \
                patch.object(serial_pair, "collect_port_inventory", return_value={}):
            serial_pair.run(args)
        return output, pair

    def test_runner_orchestrates_stubbed_pair_and_writes_verdict(self):
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT / "dev") as directory:
            output, pair = self.run_with_stub(Path(directory), fail_run=False)
            metadata = json.loads((output / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["result"]["result"], "PASS")
            self.assertEqual(metadata["result"]["round_trips"], 2)
            self.assertEqual(len(metadata["session"]), 16)
            sessions = [command.split(" ", 1)[1] for _, command in pair.commands
                        if command.startswith("SESSION ")]
            self.assertEqual(sessions, [metadata["session"], metadata["session"]])
            commands = [json.loads(line) for line in
                        (output / "commands.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertTrue(any(record["command"].startswith("RUN ") and
                                record["status"] == "written" for record in commands))

    def test_runner_fails_closed_on_stubbed_current_run_failure(self):
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT / "dev") as directory:
            root = Path(directory)
            s3_image = root / "s3.bin"
            c3_image = root / "c3.bin"
            s3_image.write_bytes(b"stub-s3")
            c3_image.write_bytes(b"stub-c3")
            output = root / "evidence"
            args = serial_pair.build_parser().parse_args([
                "--s3-port", "STUB-S3", "--c3-port", "STUB-C3",
                "--s3-bin", str(s3_image), "--c3-bin", str(c3_image),
                "--evidence-root", str(root / "unused-evidence-root"),
                "--output-dir", str(output), "--count", "1", "--payload-bytes", "64",
            ])
            StubSerialCapture.pair = EspNowSerialStub(fail_run=True)
            with patch.object(serial_pair, "SerialCapture", StubSerialCapture), \
                    patch.object(serial_pair, "collect_port_inventory", return_value={}):
                with self.assertRaisesRegex(serial_pair.PairTestError,
                                            "failure for the current session"):
                    serial_pair.run(args)
            metadata = json.loads((output / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["result"]["result"], "FAIL")

    def test_runner_fails_closed_on_c3_failed_callback_even_if_echo_returns(self):
        with tempfile.TemporaryDirectory(dir=REPOSITORY_ROOT / "dev") as directory:
            root = Path(directory)
            s3_image = root / "s3.bin"
            c3_image = root / "c3.bin"
            s3_image.write_bytes(b"stub-s3")
            c3_image.write_bytes(b"stub-c3")
            output = root / "evidence"
            args = serial_pair.build_parser().parse_args([
                "--s3-port", "STUB-S3", "--c3-port", "STUB-C3",
                "--s3-bin", str(s3_image), "--c3-bin", str(c3_image),
                "--evidence-root", str(root / "unused-evidence-root"),
                "--output-dir", str(output), "--count", "2", "--payload-bytes", "64",
            ])
            pair = EspNowSerialStub(fail_echo_sequence=2)
            StubSerialCapture.pair = pair
            with patch.object(serial_pair, "SerialCapture", StubSerialCapture), \
                    patch.object(serial_pair, "collect_port_inventory", return_value={}):
                with self.assertRaisesRegex(serial_pair.PairTestError,
                                            "failed ESP-NOW echo transmission"):
                    serial_pair.run(args)
            metadata = json.loads((output / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["result"]["result"], "FAIL")
            self.assertEqual(metadata["result"]["error"],
                             "C3 reported a failed ESP-NOW echo transmission")


if __name__ == "__main__":
    unittest.main()
