"""Redaction allowlist and bounded input tests for the decoder CLI."""

from __future__ import annotations

import base64
import io
import json
import unittest

from dmp_peer.decoder_cli import IDENTITY_FIELDS, run_decoder
from dmp_peer.frame import CoreFrame, Extension, Route, encode_frame, encode_uleb
from dmp_peer.stream_r import encode_stream_r


def core_frame() -> bytes:
    context = encode_uleb(7) + (0x1122334455667788).to_bytes(8, "little")
    return encode_frame(CoreFrame(
        message_type=7,
        sequence=23,
        route=Route(ttl=2, mode=1, source_id=10, destination_id=20),
        extensions=(Extension(2, True, True, context),),
        payload=b"secret plaintext must not appear in diagnostics",
    ))


def input_line(raw: bytes, at_ms: int) -> str:
    return json.dumps({"bytes_b64": base64.b64encode(raw).decode("ascii"), "at_ms": at_ms}) + "\n"


class DecoderCliTests(unittest.TestCase):
    def test_default_core_output_omits_identity_payload_and_frame_bytes(self):
        raw = core_frame()
        stdout, stderr = io.StringIO(), io.StringIO()
        self.assertEqual(run_decoder(io.StringIO(input_line(raw, 5)), stdout, stderr,
                                     mode="core"), 0)
        self.assertEqual(stderr.getvalue(), "")
        result = json.loads(stdout.getvalue())
        self.assertEqual(set(result), {
            "event", "at_ms", "size", "message_type", "protected", "fragmented", "route_present"
        })
        self.assertNotIn("identity", result)
        self.assertNotIn("secret plaintext", stdout.getvalue())
        self.assertNotIn(base64.b64encode(raw).decode("ascii"), stdout.getvalue())

    def test_identity_opt_in_adds_only_the_identity_allowlist(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        self.assertEqual(run_decoder(io.StringIO(input_line(core_frame(), 6)), stdout, stderr,
                                     mode="core", include_identity=True), 0)
        result = json.loads(stdout.getvalue())
        self.assertTrue(set(result["identity"]).issubset(IDENTITY_FIELDS))
        self.assertEqual(set(result["identity"]), {
            "namespace", "origin", "destination", "epoch", "sequence"
        })
        self.assertEqual(result["identity"]["namespace"], 7)
        self.assertEqual(result["identity"]["origin"], 10)
        self.assertEqual(result["identity"]["destination"], 20)
        self.assertNotIn("secret plaintext", stdout.getvalue())

    def test_stream_mode_handles_chunked_input_and_keeps_the_same_redaction(self):
        wire = encode_stream_r(core_frame(), max_core=256, max_encoded=263)
        midpoint = len(wire) // 2
        requests = input_line(b"\x00" + wire[:midpoint], 0) + input_line(wire[midpoint:], 1)
        stdout, stderr = io.StringIO(), io.StringIO()
        self.assertEqual(run_decoder(io.StringIO(requests), stdout, stderr, mode="stream"), 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["event"], "frame")
        self.assertNotIn("identity", result)
        self.assertNotIn("secret plaintext", stdout.getvalue())

    def test_duplicate_or_unknown_input_members_are_rejected_without_echo(self):
        for line in (
            '{"bytes_b64":"AA==","bytes_b64":"AQ==","at_ms":0}\n',
            input_line(b"x", 0).replace('"at_ms": 0', '"at_ms": 0, "private": "hide"'),
        ):
            with self.subTest(line=line):
                stdout, stderr = io.StringIO(), io.StringIO()
                self.assertEqual(run_decoder(io.StringIO(line), stdout, stderr, mode="core"), 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "E_INPUT\n")
                self.assertNotIn("private", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
