"""Closed-schema and terminal-record tests for the peer process bridge."""

from __future__ import annotations

import io
import json
import unittest
from unittest.mock import ANY
from pathlib import Path

from dmp_peer.endpoint import PeerEndpoint
from dmp_peer.process_bridge import run_bridge


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = (ROOT / "profiles" / "deployments" / "test-peer-tcp-stream-r-nnpsk0.json").read_bytes()


def endpoint() -> PeerEndpoint:
    return PeerEndpoint(
        manifest_bytes=MANIFEST,
        test_credentials={"node_id": 10},
        entropy_source=lambda size: bytes(range(size)),
        test_services={},
        test_only_disable_sec1=True,
    )


def request(value: dict) -> str:
    return json.dumps({"interface": "DMP-PEER-TEST/1", "input": value}) + "\n"


class ProcessBridgeTests(unittest.TestCase):
    def test_api_bytes_stay_on_stdout_and_accepted_submission_settles(self):
        requests = "".join((
            request({"op": "open", "link": 0,
                     "deadline_capability": "strict_latest_start", "at_ms": 1}),
            request({"op": "tx_admit", "handle": 1, "generation": 1,
                     "accepted": True, "reason": None, "at_ms": 1}),
            request({"op": "tx_terminal", "handle": 1, "generation": 1,
                     "outcome": "transmitted", "at_ms": 2}),
        ))
        stdout, stderr = io.StringIO(), io.StringIO()
        result = run_bridge(io.StringIO(requests), stdout, stderr, endpoint())
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0]["events"][0]["type"], "tx_submit")
        self.assertEqual(lines[0]["events"][0]["bytes_b64"], "AA==")
        self.assertEqual(lines[1]["events"], [])
        self.assertEqual(lines[2]["events"], [])

    def test_stale_generation_is_ignored_before_the_matching_terminal(self):
        requests = "".join((
            request({"op": "open", "link": 0,
                     "deadline_capability": "strict_latest_start", "at_ms": 1}),
            request({"op": "tx_admit", "handle": 1, "generation": 1,
                     "accepted": True, "reason": None, "at_ms": 1}),
            request({"op": "tx_terminal", "handle": 1, "generation": 2,
                     "outcome": "transmitted", "at_ms": 2}),
            request({"op": "tx_terminal", "handle": 1, "generation": 1,
                     "outcome": "transmitted", "at_ms": 3}),
        ))
        stdout, stderr = io.StringIO(), io.StringIO()
        self.assertEqual(run_bridge(io.StringIO(requests), stdout, stderr, endpoint()), 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual([json.loads(line)["events"] for line in stdout.getvalue().splitlines()],
                         [[ANY], [], [], []])

    def test_eof_with_an_unsettled_submit_fails_with_fixed_code(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        result = run_bridge(io.StringIO(request({
            "op": "open", "link": 0,
            "deadline_capability": "strict_latest_start", "at_ms": 1,
        })), stdout, stderr, endpoint())
        self.assertEqual(result, 2)
        self.assertEqual(stderr.getvalue(), "E_TERMINAL\n")
        self.assertNotIn("AA==", stderr.getvalue())

    def test_duplicate_and_unknown_json_members_fail_without_echoing_input(self):
        for line in (
            '{"interface":"DMP-PEER-TEST/1","interface":"x","input":{}}\n',
            request({"op": "advance", "now_ms": 1, "secret": "do not echo"}),
        ):
            with self.subTest(line=line):
                stdout, stderr = io.StringIO(), io.StringIO()
                result = run_bridge(io.StringIO(line), stdout, stderr, endpoint())
                self.assertEqual(result, 2)
                self.assertEqual(stderr.getvalue(), "E_INPUT\n")
                self.assertNotIn("do not echo", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
