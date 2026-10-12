"""P23 C-primary interoperability regression for SEC-1 S10.18."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
import hashlib
import json

sys.path.insert(0, str(Path(__file__).parents[1]))
sys.path.insert(0, str(Path(__file__).parent))

from dmp_peer.frame import parse_frame  # noqa: E402
from dmp_peer.stream_r import encode_stream_r  # noqa: E402
from dmp_peer.testing import PeerEndpoint  # noqa: E402
from test_p23_c_endpoint_interop import (  # noqa: E402
    _CProcess,
    _ROOT,
    _Clock,
    _MANIFEST_NAME,
    _activate_pair,
    _assert_effective_profile,
    _pump,
)


def _wire(core_frame: bytes) -> bytes:
    return encode_stream_r(core_frame, max_core=256, max_encoded=263)


@unittest.skipUnless(
    os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
    "C P23 endpoint executable is not configured",
)
class TestP23S10MutationInterop(unittest.TestCase):
    def setUp(self) -> None:
        self.executable = os.environ["DMP_P23_ENDPOINT_SEC_EXE"]

    def open_pair(self, psk: bytes, entropy_seed: int):
        manifest_path = _ROOT / "profiles" / "deployments" / _MANIFEST_NAME
        manifest_bytes = manifest_path.read_bytes()
        profile_hash = hashlib.sha256(manifest_bytes).digest()
        digest_index = json.loads(
            (_ROOT / "profiles" / "deployments" / "digests.json").read_text()
        )
        self.assertEqual(profile_hash.hex(), digest_index["manifests"][_MANIFEST_NAME])
        c_endpoint = _CProcess(self.executable, profile_hash, psk)
        self.addCleanup(c_endpoint.close)
        _assert_effective_profile(self, c_endpoint.initial, manifest_bytes)
        peer = PeerEndpoint(
            manifest_bytes=manifest_bytes,
            test_credentials={"node_id": 10, "psk": psk, "key_hint": 5},
            entropy_source=lambda size: bytes(
                (entropy_seed + index) & 0xFF for index in range(size)
            ),
            test_services={},
        )
        clock = _Clock()
        _activate_pair(c_endpoint, peer, clock)
        self.assertEqual(c_endpoint.last_state.effective_config["pin_commits"], 0)
        return c_endpoint, peer, clock

    def deliver(
        self, c_endpoint, peer: PeerEndpoint, wire: bytes, clock: _Clock, *, allow_reject=False
    ):
        state = c_endpoint.receive(wire, clock.next())
        if allow_reject:
            self.assertIn(state.status, (0, 1), "C endpoint returned an unexpected receive status")
        else:
            self.assertEqual(state.status, 0, "C endpoint rejected a valid authenticated peer frame")
        if state.frames:
            _pump(c_endpoint, peer, state.frames, clock)
        return state

    def test_fresh_pn_changed_payload_duplicate_cannot_replace_data_slice(self) -> None:
        c_endpoint, peer, clock = self.open_pair(b"\x3c" * 32, 0x6D)
        chunk_bytes = c_endpoint.last_state.effective_config["chunk_bytes"]
        original = bytes((index * 19 + 7) & 0xFF for index in range(chunk_bytes + 23))
        changed = bytes((original[0] ^ 0x80,)) + original[1:]
        sequence = peer._alloc_seq()

        original_frames = peer._build_data_frames(
            service_id=2, seq=sequence, payload=original, ack_req=True
        )
        changed_frames = peer._build_data_frames(
            service_id=2, seq=sequence, payload=changed, ack_req=True
        )
        self.assertEqual(len(original_frames), 2)
        self.assertEqual(len(changed_frames), 2)

        original_first = parse_frame(original_frames[0])
        altered_first = parse_frame(changed_frames[0])
        self.assertEqual(original_first.message_type, 7)
        self.assertEqual(original_first.sequence, sequence)
        self.assertEqual(original_first.fragment.index, 0)
        self.assertEqual(original_first.fragment.chunk_size, chunk_bytes)
        self.assertEqual(original_first.fragment.total_length, len(original))
        self.assertEqual(altered_first.message_type, original_first.message_type)
        self.assertEqual(altered_first.options, original_first.options)
        self.assertEqual(altered_first.sequence, original_first.sequence)
        self.assertEqual(altered_first.route, original_first.route)
        self.assertEqual(altered_first.fragment, original_first.fragment)
        self.assertEqual(altered_first.extensions, original_first.extensions)
        self.assertEqual(altered_first.security.receive_cid, original_first.security.receive_cid)
        self.assertGreater(
            altered_first.security.packet_number, original_first.security.packet_number
        )
        self.assertNotEqual(altered_first.payload, original_first.payload)

        partial = self.deliver(c_endpoint, peer, _wire(original_frames[0]), clock)
        self.assertEqual(partial.assembled, 0)
        self.assertEqual(partial.body, b"")

        conflict = self.deliver(
            c_endpoint, peer, _wire(changed_frames[0]), clock, allow_reject=True
        )
        self.assertEqual(conflict.assembled, 0)
        self.assertEqual(conflict.body, b"")

        completed = self.deliver(c_endpoint, peer, _wire(original_frames[1]), clock)
        self.assertEqual(completed.assembled, 1)
        self.assertEqual(completed.body, original)

        # A later fresh-PN retry of the altered immutable identity must not
        # execute a second application delivery or replace retained content.
        replay = self.deliver(
            c_endpoint, peer, _wire(changed_frames[0]), clock, allow_reject=True
        )
        self.assertEqual(replay.assembled, 1)
        self.assertEqual(replay.body, original)


if __name__ == "__main__":
    unittest.main()
