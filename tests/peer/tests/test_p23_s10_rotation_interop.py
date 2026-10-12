"""P23 C/Python interop for S10.09 association rotation isolation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))

from dmp_peer.events import PublishSample, Receive  # noqa: E402
from dmp_peer.stream_r import StreamRDecoder, encode_stream_r  # noqa: E402
from dmp_peer.testing import PeerEndpoint  # noqa: E402

from test_p23_c_endpoint_interop import (  # noqa: E402
    _CProcess,
    _Clock,
    _ROOT,
    _activate_pair,
    _assert_effective_profile,
    _settle,
)


@unittest.skipUnless(
    os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
    "C P23 endpoint executable is not configured",
)
class TestP23S1009RotationInterop(unittest.TestCase):
    def test_old_authenticated_application_frame_does_not_activate_rotation(self) -> None:
        manifest_name = "direct-nnpsk0.json"
        manifest_path = _ROOT / "profiles" / "deployments" / manifest_name
        manifest_bytes = manifest_path.read_bytes()
        digest_index = json.loads(
            (_ROOT / "profiles" / "deployments" / "digests.json").read_text()
        )
        self.assertEqual(
            hashlib.sha256(manifest_bytes).hexdigest(),
            digest_index["manifests"][manifest_name],
        )

        self.executable = os.environ["DMP_P23_ENDPOINT_SEC_EXE"]
        profile_hash = hashlib.sha256(manifest_bytes).digest()
        psk = b"\x17" * 32
        c_endpoint = _CProcess(self.executable, profile_hash, psk)
        self.addCleanup(c_endpoint.close)
        _assert_effective_profile(self, c_endpoint.initial, manifest_bytes)

        entropy_offset = 0

        def peer_entropy(size: int) -> bytes:
            nonlocal entropy_offset
            start = entropy_offset
            entropy_offset += size
            return bytes((0x39 + start + index) & 0xFF for index in range(size))

        peer = PeerEndpoint(
            manifest_bytes=manifest_bytes,
            test_credentials={"node_id": 10, "psk": psk, "key_hint": 5},
            entropy_source=peer_entropy,
            test_services={},
        )
        clock = _Clock()
        _activate_pair(c_endpoint, peer, clock)

        old_association = peer.association
        self.assertIsNotNone(old_association)
        # Allocate a fresh PN on the original association. It is an authentic
        # FINISH control frame, but is retained until the replacement candidate
        # is pending on the C endpoint.
        old_finish_core = peer._build_protected_finish_frame()
        old_finish_wire = encode_stream_r(
            old_finish_core, max_core=256, max_encoded=263
        )
        framing = StreamRDecoder(
            max_encoded=263, max_core=256, candidate_timeout_ms=26, await_sync=False
        )
        decoded_old_finish = [
            event.frame
            for event in framing.feed(old_finish_wire, at_ms=0)
            if event.kind == "frame"
        ]
        self.assertEqual(decoded_old_finish, [old_finish_core])

        # The frozen profile requires its one-second restart backoff between
        # completed bootstrap episodes.
        rotation_events = peer.initiate_handshake(
            at_ms=clock.advance(1001), attempt_id=b"rotation-attempt"
        )
        rotation_flights, _ = _settle(peer, rotation_events, clock)
        self.assertEqual(len(rotation_flights), 1)

        c_flight2 = c_endpoint.receive(rotation_flights[0], clock.next())
        self.assertEqual(c_flight2.status, 0)
        self.assertEqual(len(c_flight2.frames), 1)
        self.assertTrue(c_flight2.handshake_active)
        self.assertTrue(c_flight2.bound)

        # An authenticated FINISH under the old SA must not confirm the new
        # candidate. The driver does not export candidate-live as a snapshot
        # field, so the negative result plus successful later candidate FINISH
        # prove that the candidate remains available.
        old_finish_result = c_endpoint.receive(old_finish_wire, clock.next())
        self.assertNotEqual(old_finish_result.status, 0)
        self.assertFalse(old_finish_result.frames)
        self.assertTrue(old_finish_result.handshake_active)
        self.assertTrue(old_finish_result.bound)

        # Finish the Python-initiated rotation with its distinct candidate SA.
        peer_flight2_events = peer.handle(
            Receive(link=0, bytes=c_flight2.frames[0], at_ms=clock.next())
        )
        candidate_finish_wires, _ = _settle(peer, peer_flight2_events, clock)
        self.assertEqual(len(candidate_finish_wires), 1)
        c_finish = c_endpoint.receive(candidate_finish_wires[0], clock.next())
        self.assertEqual(c_finish.status, 0)
        self.assertTrue(c_finish.handshake_active)
        self.assertTrue(c_finish.bound)
        self.assertEqual(len(c_finish.frames), 1)

        # READY is protected by the replacement SA and activates it at the
        # Python peer. The superseded Python SA enters its bounded drain state.
        ready_events = peer.handle(
            Receive(link=0, bytes=c_finish.frames[0], at_ms=clock.next())
        )
        self.assertEqual(ready_events, ())
        self.assertIsNot(peer.association, old_association)
        self.assertEqual(peer.association.status, "active")
        self.assertEqual(old_association.status, "draining")

        # A newly authenticated application frame proves the C side now uses
        # the rotated SA, not just its prior active binding.
        new_app_events = peer.handle(
            PublishSample(value=0x5678, at_ms=clock.next())
        )
        new_app_wires, _ = _settle(peer, new_app_events, clock)
        self.assertEqual(len(new_app_wires), 1)
        new_frame_result = c_endpoint.receive(new_app_wires[0], clock.next())
        self.assertEqual(new_frame_result.status, 0)
        self.assertTrue(new_frame_result.handshake_active)
        self.assertTrue(new_frame_result.bound)
        self.assertEqual(new_frame_result.telemetry, 1)


if __name__ == "__main__":
    unittest.main()
