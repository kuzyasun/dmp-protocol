"""Bounded hostile bootstrap traffic followed by real C/Python progress."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))

import test_p23_c_endpoint_interop as interop  # noqa: E402
from dmp_peer.events import Open, PublishSample, Receive  # noqa: E402
from dmp_peer.frame import (  # noqa: E402
    Extension,
    decode_uleb,
    encode_frame,
    encode_uleb,
    parse_frame,
)
from dmp_peer.security import compute_bootstrap_epoch  # noqa: E402
from dmp_peer.stream_r import StreamRDecoder, encode_stream_r  # noqa: E402
from dmp_peer.testing import PeerEndpoint  # noqa: E402


_ROOT = Path(__file__).parents[3]
_MANIFEST = "test-peer-tcp-stream-r-nnpsk0.json"
_MAX_CORE = 256
_MAX_ENCODED = 263


def _decode_core(wire: bytes, at_ms: int) -> bytes:
    decoder = StreamRDecoder(
        max_encoded=_MAX_ENCODED,
        max_core=_MAX_CORE,
        candidate_timeout_ms=26,
        await_sync=False,
    )
    frames = [
        event.frame
        for event in decoder.feed(wire, at_ms=at_ms)
        if event.kind == "frame"
    ]
    if len(frames) != 1 or frames[0] is None:
        raise AssertionError("expected one valid bootstrap Stream R frame")
    return frames[0]


@unittest.skipUnless(
    os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
    "C P23 endpoint executable is not configured",
)
class TestP23S10BootstrapBudgetInterop(unittest.TestCase):
    def test_bounded_hostile_flight1_does_not_block_real_association_progress(self) -> None:
        manifest_path = _ROOT / "profiles" / "deployments" / _MANIFEST
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        security = manifest["security"]
        digest_index = json.loads(
            (_ROOT / "profiles" / "deployments" / "digests.json").read_text()
        )
        self.assertEqual(
            hashlib.sha256(manifest_bytes).hexdigest(),
            digest_index["manifests"][_MANIFEST],
        )
        hostile_count = security["episode_attempts"]
        self.assertGreater(hostile_count, 0)
        self.assertEqual(security["preauth_slots"], 1)

        clock = interop._Clock()
        endpoint = interop._CProcess(
            os.environ["DMP_P23_ENDPOINT_SEC_EXE"],
            hashlib.sha256(manifest_bytes).digest(),
            b"\x35" * 32,
        )
        self.addCleanup(endpoint.close)
        interop._assert_effective_profile(self, endpoint.initial, manifest_bytes)
        peer = PeerEndpoint(
            manifest_bytes=manifest_bytes,
            test_credentials={"node_id": 10, "psk": b"\x35" * 32, "key_hint": 5},
            entropy_source=lambda size: bytes((0x71 + index) & 0xFF for index in range(size)),
            test_services={},
        )

        peer_open = peer.handle(
            Open(link=0, deadline_capability="strict_latest_start", at_ms=clock.next())
        )
        sync_frames, _ = interop._settle(peer, peer_open, clock)
        self.assertEqual(sync_frames, [b"\x00"])
        self.assertEqual(endpoint.receive(sync_frames[0], clock.next()).status, 0)
        self.assertEqual(
            peer.handle(Receive(link=0, bytes=endpoint.initial.frames[0], at_ms=clock.next())),
            (),
        )

        flight_events = peer.initiate_handshake(at_ms=clock.next())
        flight_wires, _ = interop._settle(peer, flight_events, clock)
        self.assertEqual(len(flight_wires), 1)
        original_core = _decode_core(flight_wires[0], clock.next())
        original_frame = parse_frame(original_core, max_frame=_MAX_CORE)
        self.assertEqual(original_frame.message_type, 3)
        self.assertGreaterEqual(len(original_frame.payload), 72)

        # Flood exactly the profile's bounded per-episode attempt count with
        # distinct pre-auth candidates carrying a bad PROFILE_HASH. These
        # fail before admission/cryptographic state is allocated.
        for attempt in range(hostile_count):
            payload = bytearray(original_frame.payload)
            attempt_id = attempt.to_bytes(16, "little")
            payload[4:20] = attempt_id
            payload[32:64] = bytes([0xA0 + attempt]) * 32
            context = next(
                ext for ext in original_frame.extensions if ext.extension_id == 2
            )
            namespace, namespace_end = decode_uleb(context.value)
            self.assertEqual(namespace_end + 8, len(context.value))
            bootstrap_epoch = compute_bootstrap_epoch(attempt_id)
            self.assertEqual(
                int.from_bytes(context.value[namespace_end:], "little"),
                compute_bootstrap_epoch(original_frame.payload[4:20]),
            )
            context_value = (
                encode_uleb(namespace)
                + bootstrap_epoch.to_bytes(8, "little")
            )
            extensions = tuple(
                Extension(ext.extension_id, ext.critical, ext.unsafe, context_value)
                if ext.extension_id == 2
                else ext
                for ext in original_frame.extensions
            )
            hostile_core = encode_frame(
                replace(original_frame, payload=bytes(payload), extensions=extensions),
                max_frame=_MAX_CORE,
            )
            hostile_wire = encode_stream_r(
                hostile_core, max_core=_MAX_CORE, max_encoded=_MAX_ENCODED
            )
            rejected = endpoint.receive(hostile_wire, clock.next())
            # Pre-auth profile mismatches are a silent, successful drop at the
            # transport API: no reply and no endpoint association state.
            self.assertFalse(rejected.frames)
            self.assertFalse(rejected.handshake_active)
            self.assertFalse(rejected.bound)

        admitted = endpoint.receive(flight_wires[0], clock.next())
        self.assertEqual(admitted.status, 0)
        self.assertEqual(len(admitted.frames), 1)
        self.assertFalse(admitted.handshake_active)
        interop._pump(endpoint, peer, admitted.frames, clock)
        self.assertTrue(endpoint.last_state.handshake_active)
        self.assertTrue(endpoint.last_state.bound)
        self.assertEqual(peer.association.status, "active")

        before = endpoint.last_state.telemetry
        events = peer.handle(PublishSample(value=3210, at_ms=clock.next()))
        sample_wires, _ = interop._settle(peer, events, clock)
        self.assertEqual(len(sample_wires), 1)
        progressed = endpoint.receive(sample_wires[0], clock.next())
        self.assertEqual(progressed.status, 0)
        self.assertEqual(progressed.telemetry, before + 1)
        self.assertTrue(progressed.handshake_active)
        self.assertTrue(progressed.bound)


if __name__ == "__main__":
    unittest.main()
