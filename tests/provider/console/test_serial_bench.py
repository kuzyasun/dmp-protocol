"""Transport and framing tests for serial_bench; no provider state is simulated."""

from __future__ import annotations

import io
import json
import math
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

import serial_bench as bench


_STATS = {key: 0 for key in bench.REQUIRED_STATS}


def response(seq: int, *, version: int = 1, rc: int = 0, data: str = "",
             action: int = 0, us: int = 1, last_id: int | None = None,
             boot: str = "0123456789abcdef", build: str = "ab" * 32,
             stats: dict[str, int] | None = None) -> bytes:
    value = {"v": version, "id": seq, "last_id": seq if last_id is None else last_id,
             "rc": rc, "us": us, "action": action,
             "data": data, "target": "host", "idf": "test", "boot": boot,
             "build": build, "stats": _STATS if stats is None else stats}
    return b"DMPBENCH " + json.dumps(value, separators=(",", ":")).encode() + b"\n"


class FakeTransport:
    def __init__(self, lines: list[bytes]):
        self.lines = list(lines)
        self.writes: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    def readline(self, timeout: float, limit: int = bench.RESPONSE_MAX) -> bytes:
        if not self.lines:
            raise TimeoutError("fake timeout")
        line = self.lines.pop(0)
        if len(line) > limit:
            raise bench.BenchError("provider emitted an overlong line")
        return line

    def close(self) -> None:
        self.closed = True


class SerialBenchTests(unittest.TestCase):
    def peer(self, lines: list[bytes]) -> tuple[bench.Peer, FakeTransport, io.StringIO]:
        transport = FakeTransport(lines)
        evidence = io.StringIO()
        return bench.Peer("fake", transport, evidence), transport, evidence

    def test_skips_and_records_unprefixed_sdk_lines(self) -> None:
        peer, _, evidence = self.peer([b"I (123) boot: ready\r\n", response(1)])
        peer.command("HELLO")
        self.assertEqual(peer.logs, ["I (123) boot: ready"])
        records = [json.loads(row) for row in evidence.getvalue().splitlines()]
        self.assertEqual([row["event"] for row in records], ["command", "log", "response"])

    def test_rejects_malformed_prefixed_json_and_wrong_id(self) -> None:
        cases = ([b"DMPBENCH {bad json}\n"], [response(2)])
        for lines in cases:
            with self.subTest(lines=lines):
                peer, transport, _ = self.peer(list(lines))
                with self.assertRaises(bench.BenchError):
                    peer.command("INIT")
                self.assertEqual(len(transport.writes), 1)

    def test_duplicate_json_fields_are_rejected_and_raw_line_is_saved_first(self) -> None:
        line = response(1).replace(b'"v":1', b'"v":1,"v":1', 1)
        peer, _, evidence = self.peer([line])
        with self.assertRaisesRegex(bench.BenchError, "malformed DMPBENCH JSON"):
            peer.command("HELLO")
        records = [json.loads(row) for row in evidence.getvalue().splitlines()]
        self.assertEqual(records[-2]["event"], "malformed_response")
        self.assertEqual(records[-2]["raw_hex"], line.hex())
        self.assertEqual(records[-1]["event"], "failure")

    def test_rejects_wrong_version_and_invalid_hex(self) -> None:
        bad_hex = response(1, data="ABC")
        for line in (response(1, version=2), bad_hex):
            with self.subTest(line=line):
                peer, _, _ = self.peer([line])
                with self.assertRaises(bench.BenchError):
                    peer.command("HELLO")

    def test_rejects_nonempty_error_data_negative_metrics_and_bad_common_fields(self) -> None:
        negative_stat = dict(_STATS, arena_live=-1)
        cases = (
            response(1, rc=bench.ERROR_NO_MEMORY, data="aa"),
            response(1, us=-1),
            response(1, stats=negative_stat),
            response(1, last_id=-1),
            response(1, last_id=0),
            response(1, boot="not-a-boot-id"),
            response(1, build="not-a-build-id"),
        )
        for line in cases:
            with self.subTest(line=line):
                peer, _, _ = self.peer([line])
                with self.assertRaises(bench.BenchError):
                    peer.command("HELLO")

    def test_boot_and_build_identity_must_remain_stable(self) -> None:
        peer, _, evidence = self.peer([
            response(1),
            response(2, boot="fedcba9876543210"),
        ])
        peer.command("HELLO")
        with self.assertRaisesRegex(bench.BenchError, "boot identifier changed"):
            peer.command("STATS")
        records = [json.loads(row) for row in evidence.getvalue().splitlines()]
        self.assertEqual(records[-2]["event"], "malformed_response")
        self.assertIn("boot identifier changed", records[-2]["error"])

    def test_build_fingerprint_must_remain_stable(self) -> None:
        peer, _, _ = self.peer([
            response(1),
            response(2, build="cd" * 32),
        ])
        peer.command("HELLO")
        with self.assertRaisesRegex(bench.BenchError, "build fingerprint changed"):
            peer.command("STATS")

    def test_sync_uses_read_only_id_zero_and_resumes_after_provider_last_id(self) -> None:
        peer, transport, evidence = self.peer([
            response(0, last_id=41),
            response(42, last_id=42),
        ])
        synced = peer.synchronize()
        self.assertEqual(synced["last_id"], 41)
        self.assertEqual(peer.sequence, 41)
        peer.command("INIT")
        self.assertEqual(transport.writes, [b"DMPBENCH 1 0 HELLO\n", b"DMPBENCH 1 42 INIT\n"])
        records = [json.loads(row) for row in evidence.getvalue().splitlines()]
        self.assertEqual([row["event"] for row in records if row["event"] in {"synchronize", "synchronized"}],
                         ["synchronize", "synchronized"])

    def test_sync_rejects_invalid_last_id_without_advancing_local_sequence(self) -> None:
        for bad_last_id in (-1, 0x100000000, True):
            with self.subTest(last_id=bad_last_id):
                peer, transport, _ = self.peer([response(0, last_id=bad_last_id)])
                with self.assertRaises(bench.BenchError):
                    peer.synchronize()
                self.assertEqual(peer.sequence, 0)
                self.assertEqual(transport.writes, [b"DMPBENCH 1 0 HELLO\n"])

    def test_detects_reset_even_on_sdk_line(self) -> None:
        peer, _, _ = self.peer([b"ESP-ROM:esp32s3-20210327\n"])
        with self.assertRaisesRegex(bench.BenchError, "reboot detected"):
            peer.command("STATS")

    def test_timeout_is_unknown_and_command_is_never_retried(self) -> None:
        peer, transport, evidence = self.peer([])
        with self.assertRaisesRegex(bench.BenchError, "not retried"):
            peer.command("WRITE", 0, "-")
        self.assertEqual(len(transport.writes), 1)
        records = [json.loads(row) for row in evidence.getvalue().splitlines()]
        self.assertEqual(records[-1]["event"], "timeout")
        self.assertEqual(records[-1]["outcome"], "unknown; not retried")
        self.assertEqual(peer.sequence, 1)

    def test_nonzero_result_can_be_checked_as_an_expected_failure(self) -> None:
        peer, _, _ = self.peer([response(1, rc=17668)])
        result = peer.command("OPEN", 0, 1, "-", "00", expected_rc=17668)
        self.assertEqual(result["rc"], 17668)

    def test_expected_failure_must_name_exact_code(self) -> None:
        peer, transport, _ = self.peer([])
        with self.assertRaisesRegex(bench.BenchError, "exact integer"):
            peer.command("OPEN", 0, 1, "-", "00", expected_rc=None)  # type: ignore[arg-type]
        self.assertEqual(transport.writes, [])

    def test_request_tokens_reject_whitespace_controls_and_non_ascii(self) -> None:
        for token in ("space here", "line\nbreak", "tab\there", "nul\x00byte", "snowman-☃"):
            with self.subTest(token=token):
                peer, transport, _ = self.peer([])
                with self.assertRaisesRegex(bench.BenchError, "printable ASCII"):
                    peer.command("WRITE", 0, token)
                self.assertEqual(transport.writes, [])
                self.assertEqual(peer.sequence, 0)

    def test_timeout_must_be_finite_and_bounded(self) -> None:
        for timeout in (0, -1, math.nan, math.inf, bench.MAX_TIMEOUT + 0.01):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(bench.BenchError, "timeout must be finite"):
                    bench.Peer("fake", FakeTransport([]), io.StringIO(), timeout=timeout)

    def test_sdk_log_buffer_is_bounded_while_jsonl_keeps_all_lines(self) -> None:
        lines = [f"I ({index}) sdk: line\n".encode() for index in range(bench.MAX_RECENT_LOGS + 6)]
        lines.append(response(1))
        peer, _, evidence = self.peer(lines)
        peer.command("HELLO")
        self.assertEqual(len(peer.logs), bench.MAX_RECENT_LOGS)
        self.assertIn("line", peer.logs[-1])
        records = [json.loads(row) for row in evidence.getvalue().splitlines()]
        self.assertEqual(sum(row["event"] == "log" for row in records), bench.MAX_RECENT_LOGS + 6)

    def test_failed_response_does_not_get_resent(self) -> None:
        peer, transport, _ = self.peer([response(1, rc=-3)])
        with self.assertRaises(bench.BenchError):
            peer.command("NEW", 0, "nn", "i", "random")
        self.assertEqual(len(transport.writes), 1)
        self.assertIn(b" 1 NEW ", transport.writes[0])

    def test_close_is_idempotent_and_closes_transport(self) -> None:
        peer, transport, _ = self.peer([])
        peer.close()
        peer.close()
        self.assertTrue(transport.closed)
        with self.assertRaises(bench.BenchError):
            peer.command("HELLO")

    def test_command_ids_increase_after_failed_command(self) -> None:
        peer, transport, _ = self.peer([response(1, rc=-2), response(2)])
        with self.assertRaises(bench.BenchError):
            peer.command("INIT")
        peer.command("HELLO")
        self.assertEqual(transport.writes, [b"DMPBENCH 1 1 INIT\n", b"DMPBENCH 1 2 HELLO\n"])

    def test_output_file_creation_never_overwrites_existing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.jsonl"
            output.write_text("keep this\n", encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                result = bench.main(["--host-exe", "unused", "--output", str(output)])
            self.assertEqual(result, 1)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep this\n")


if __name__ == "__main__":
    unittest.main()
