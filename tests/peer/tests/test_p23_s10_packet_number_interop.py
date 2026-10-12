"""P23 C-primary interoperability at the SEC-1 S10.12 packet-number edge."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))

from dmp_peer.events import ApplicationRequest  # noqa: E402
from dmp_peer.frame import encode_uleb, parse_frame  # noqa: E402
from dmp_peer.security import SecurityError  # noqa: E402
from dmp_peer.stream_r import StreamRDecoder  # noqa: E402
from dmp_peer.testing import PeerEndpoint  # noqa: E402
from test_p23_c_endpoint_interop import (  # noqa: E402
    _CProcess,
    _Clock,
    _MANIFEST_NAME,
    _ROOT,
    _activate_pair,
    _assert_effective_profile,
    _settle,
)


_MAX_PN = (1 << 24) - 1


@unittest.skipUnless(
    os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
    "C P23 endpoint executable is not configured",
)
class TestP23S10PacketNumberInterop(unittest.TestCase):
    def test_widest_packet_number_is_decoded_and_accepted_by_c_endpoint(self) -> None:
        manifest_path = _ROOT / "profiles" / "deployments" / _MANIFEST_NAME
        manifest_bytes = manifest_path.read_bytes()
        digest = hashlib.sha256(manifest_bytes).digest()
        digest_index = json.loads(
            (_ROOT / "profiles" / "deployments" / "digests.json").read_text()
        )
        self.assertEqual(digest.hex(), digest_index["manifests"][_MANIFEST_NAME])

        psk = b"\x46" * 32
        endpoint = _CProcess(os.environ["DMP_P23_ENDPOINT_SEC_EXE"], digest, psk)
        self.addCleanup(endpoint.close)
        _assert_effective_profile(self, endpoint.initial, manifest_bytes)
        clock = _Clock()
        peer = PeerEndpoint(
            manifest_bytes=manifest_bytes,
            test_credentials={"node_id": 10, "psk": psk, "key_hint": 5},
            entropy_source=lambda size: bytes((0x52 + index) & 0xFF for index in range(size)),
            test_services={},
        )
        _activate_pair(endpoint, peer, clock)
        self.assertEqual(peer.association.status, "active")

        # The protected header encodes this maximum valid 24-bit PN in four
        # ULEB bytes. Deliver the actual authenticated frame to the C endpoint.
        peer.association.next_send_pn = _MAX_PN
        payload = b"s10.12-pn-boundary"
        events = peer.handle(
            ApplicationRequest(
                service_id=2,
                payload=payload,
                at_ms=clock.next(),
                exchange_id=0x2312,
            )
        )
        wires, _ = _settle(peer, events, clock)
        self.assertEqual(len(wires), 1)

        decoder = StreamRDecoder(
            max_encoded=263,
            max_core=256,
            candidate_timeout_ms=26,
            await_sync=False,
        )
        decoded = [
            event.frame
            for event in decoder.feed(wires[0], at_ms=clock.next())
            if event.kind == "frame"
        ]
        self.assertEqual(len(decoded), 1)
        self.assertIsNotNone(decoded[0])
        core = decoded[0]
        frame = parse_frame(core, max_frame=256)
        self.assertEqual(frame.security.packet_number, _MAX_PN)
        self.assertEqual(len(encode_uleb(frame.security.packet_number)), 4)
        self.assertLessEqual(len(core), endpoint.initial.effective_config["forward_mtu"])

        accepted = endpoint.receive(wires[0], clock.next())
        self.assertEqual(accepted.status, 0)
        self.assertEqual(accepted.accepts, 1)
        self.assertEqual(accepted.request_service, 2)
        self.assertEqual(accepted.request, payload)

        # The same sender cannot allocate 2^24; the upper edge is exclusive.
        with self.assertRaises(SecurityError):
            peer.association.alloc_send_pn()


if __name__ == "__main__":
    unittest.main()
