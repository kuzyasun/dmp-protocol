"""P23 S10.15 cross-endpoint admission and delayed-completion scenario.

The process driver exposes no C-side TX-admission/borrow callbacks. This case
therefore holds the independent Python peer's adapter borrow while exercising
the actual C endpoint as the request initiator and response receiver.
"""

from __future__ import annotations

import os
import hashlib
import json
import unittest
from test_p23_c_endpoint_interop import (
    _CProcess,
    _Clock,
    _MANIFEST_NAME,
    _ROOT,
    _activate_pair,
    _assert_effective_profile,
    _pump,
)
from dmp_peer.events import (
    Advance,
    ApplicationEvent,
    Receive,
    TxAdmit,
    TxSubmit,
    TxTerminal,
)
from dmp_peer.testing import PeerEndpoint


@unittest.skipUnless(
    os.environ.get("DMP_P23_ENDPOINT_SEC_EXE"),
    "C P23 endpoint executable is not configured",
)
class TestP23S1015BufferInterop(unittest.TestCase):
    def setUp(self) -> None:
        self.executable = os.environ["DMP_P23_ENDPOINT_SEC_EXE"]

    def open_pair(self):
        manifest_path = _ROOT / "profiles" / "deployments" / _MANIFEST_NAME
        manifest_bytes = manifest_path.read_bytes()
        profile_hash = hashlib.sha256(manifest_bytes).digest()
        digest_index = json.loads(
            (_ROOT / "profiles" / "deployments" / "digests.json").read_text()
        )
        self.assertEqual(profile_hash.hex(), digest_index["manifests"][_MANIFEST_NAME])
        c_endpoint = _CProcess(self.executable, profile_hash, b"\x04" * 32)
        self.addCleanup(c_endpoint.close)
        _assert_effective_profile(self, c_endpoint.initial, manifest_bytes)
        peer = PeerEndpoint(
            manifest_bytes=manifest_bytes,
            test_credentials={"node_id": 10, "psk": b"\x04" * 32, "key_hint": 5},
            entropy_source=lambda size: bytes((0xA1 + index) & 0xFF for index in range(size)),
            test_services={},
        )
        clock = _Clock()
        _activate_pair(c_endpoint, peer, clock)
        return c_endpoint, peer, clock

    def test_delayed_peer_adapter_completion_preserves_c_request_result_frame(self) -> None:
        c_endpoint, peer, clock = self.open_pair()
        request_payload = b"P23-S10.15-REQ"
        expected_result = bytes(index ^ 0xA5 for index in range(len(request_payload)))

        request = c_endpoint.submit_req(2, request_payload, clock.next())
        self.assertEqual(request.status, 0)
        peer_events: list[object] = []
        tx_submits: list[TxSubmit] = []
        for wire in request.frames:
            events = peer.handle(Receive(link=0, bytes=wire, at_ms=clock.next()))
            peer_events.extend(events)
            tx_submits.extend(event for event in events if isinstance(event, TxSubmit))
        self.assertTrue(any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_accepted"
            and event.service_id == 2
            and event.payload == request_payload
            for event in peer_events
        ))
        self.assertTrue(tx_submits, "Python peer did not submit the protected response")

        # Admit each borrowed frame but delay terminal completion. During the
        # delay, advance the independent endpoint and verify its retained borrow
        # still matches the immutable TxSubmit snapshot.
        snapshots = {event.handle: event.bytes for event in tx_submits}
        for event in tx_submits:
            self.assertFalse(peer.handle(TxAdmit(
                handle=event.handle,
                generation=event.generation,
                accepted=True,
                reason=None,
                at_ms=clock.next(),
            )))
        peer.handle(Advance(now_ms=clock.advance(25)))
        for event in tx_submits:
            self.assertEqual(peer.active_submissions[event.handle]["bytes"], snapshots[event.handle])
            self.assertEqual(event.bytes, snapshots[event.handle])

        peer_wires: list[bytes] = []
        pending_submits = list(tx_submits)
        while pending_submits:
            event = pending_submits.pop(0)
            terminal = peer.handle(TxTerminal(
                handle=event.handle,
                generation=event.generation,
                outcome="transmitted",
                at_ms=clock.next(),
            ))
            peer_wires.append(snapshots[event.handle])
            for followup in terminal:
                if isinstance(followup, TxSubmit):
                    snapshots[followup.handle] = followup.bytes
                    pending_submits.append(followup)
                    peer.handle(TxAdmit(
                        handle=followup.handle,
                        generation=followup.generation,
                        accepted=True,
                        reason=None,
                        at_ms=clock.next(),
                    ))

        result_events = _pump(c_endpoint, peer, [], clock, initial_peer_frames=peer_wires)
        self.assertGreaterEqual(c_endpoint.last_state.results, 1)
        self.assertEqual(
            c_endpoint.last_state.result,
            expected_result,
            f"C state status={c_endpoint.last_state.endpoint_status} rx={c_endpoint.last_state.rx_status} "
            f"results={c_endpoint.last_state.results} peer_events={result_events!r}",
        )
        self.assertGreaterEqual(c_endpoint.last_state.results, 1)


if __name__ == "__main__":
    unittest.main()
