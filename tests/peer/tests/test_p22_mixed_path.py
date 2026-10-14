"""Format 1.0 Stream R/TCP to SIM-PACKET relay composition checks."""

from __future__ import annotations

import unittest
from pathlib import Path

from dmp_peer.relay import RelayError, TransparentRelay


ROOT = Path(__file__).resolve().parents[3]
MANIFEST = (ROOT / "profiles" / "deployments"
            / "test-mixed-tcp-stream-r-sim-packet-nnpsk0.json").read_bytes()


def uleb(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def extension(ext_id: int, value: bytes, *, critical: int = 1, unsafe: int = 0) -> bytes:
    return uleb((ext_id << 2) | (unsafe << 1) | critical) + uleb(len(value)) + value


def protected_frame(*, source: int, destination: int, seq: int = 17, pn: int = 1,
                    ttl: int = 2, namespace: int = 1, include_context: bool = True,
                    payload_size: int = 32) -> bytes:
    route = bytes(((ttl << 4) | 1,)) + uleb(source) + uleb(destination)
    fragmented = payload_size == 32
    fragment = uleb(0) + uleb(32) + uleb(64) if fragmented else b""
    security = b"\x01" + uleb(9) + uleb(pn)
    extensions = b""
    if include_context:
        context = uleb(namespace) + (0x0102030405060708).to_bytes(8, "little")
        extensions += extension(2, context, critical=1, unsafe=1)
    extensions += extension(4, uleb(2)) + extension(64, b"xyz", critical=0)
    options = 0xCD if fragmented else 0xC5
    header = bytes((0x47, 0, options)) + uleb(seq) + route + fragment + security + extensions
    header = header[:1] + bytes((len(header),)) + header[2:]
    return header + bytes((pn & 0xFF,)) * payload_size + bytes((0xA0 + pn % 16,)) * 16


def route_ttl_offset(frame: bytes) -> int:
    pos = 3
    while frame[pos] & 0x80:
        pos += 1
    return pos + 1


class MixedPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bridge = TransparentRelay(MANIFEST, relay_node=30)
        self.packet_relay = TransparentRelay(MANIFEST, relay_node=40)

    @staticmethod
    def settle(relay: TransparentRelay, decision, at_ms: int) -> None:
        if not decision.forwarded:
            raise AssertionError(decision.reason)
        relay.complete(decision.token, at_ms, transmitted=True)

    def assert_ttl_only_changed(self, before: bytes, after: bytes) -> None:
        offset = route_ttl_offset(before)
        expected = bytearray(before)
        expected[offset] -= 0x10
        self.assertEqual(after, bytes(expected))

    def test_forward_and_return_use_the_frozen_interface_order(self):
        for source, destination, first_ingress, path, expected_egress, base_time in (
            (10, 20, "tcp", (self.bridge, self.packet_relay), ("packet", "packet"), 0),
            (20, 10, "packet", (self.packet_relay, self.bridge), ("packet", "tcp"), 100),
        ):
            with self.subTest(source=source):
                wire = protected_frame(source=source, destination=destination, seq=source)
                ingress = first_ingress
                for index, (relay, egress) in enumerate(zip(path, expected_egress)):
                    now = base_time + index * 2
                    decision = relay.receive(wire, now, ingress_interface=ingress)
                    self.assertTrue(decision.forwarded, decision.reason)
                    self.assertEqual(decision.egress_interface, egress)
                    self.assert_ttl_only_changed(wire, decision.frame)
                    self.settle(relay, decision, now + 1)
                    wire = decision.frame
                    ingress = "packet"
                self.assertEqual((wire[route_ttl_offset(wire)] >> 4), 0)

    def test_bridge_duplicate_budget_is_shared_across_tcp_and_packet_ingress(self):
        first = protected_frame(source=10, destination=20, seq=44, pn=1)
        admitted = self.bridge.receive(first, 0, airtime_ms=7, ingress_interface="tcp")
        self.assertTrue(admitted.forwarded)
        self.settle(self.bridge, admitted, 1)

        duplicate = protected_frame(source=10, destination=20, seq=44, pn=2)
        blocked_during_cooldown = self.bridge.receive(
            duplicate, 50, ingress_interface="packet"
        )
        self.assertEqual(blocked_during_cooldown.reason, "cooldown")
        blocked_wrong_interface = self.bridge.receive(
            duplicate, 52, ingress_interface="packet"
        )
        self.assertEqual(blocked_wrong_interface.reason, "wrong-ingress")
        self.assertEqual(len(self.bridge._entries), 1)
        entry = next(iter(self.bridge._entries.values()))
        self.assertEqual(entry.forwards, 1)
        self.assertEqual(self.bridge._global_airtime, 7)

    def test_context_namespace_must_match_and_context_may_not_be_added(self):
        for source, destination, relay, ingress in (
            (10, 20, self.bridge, "tcp"),
            (20, 10, self.packet_relay, "packet"),
        ):
            with self.subTest(source=source):
                missing = protected_frame(
                    source=source, destination=destination, seq=60 + source,
                    include_context=False,
                )
                with self.assertRaisesRegex(RelayError, "requires explicit CONTEXT"):
                    relay.receive(missing, 0, ingress_interface=ingress)
                wrong = protected_frame(
                    source=source, destination=destination, seq=70 + source,
                    namespace=2,
                )
                result = relay.receive(wrong, 1, ingress_interface=ingress)
                self.assertEqual(result.reason, "context-mismatch")

    def test_egress_mtu_is_enforced_in_both_directions(self):
        for source, destination, egress_limit, ingress in (
            (10, 20, "forward_mtu", "tcp"),
            (20, 10, "tcp_return_mtu", "packet"),
        ):
            with self.subTest(source=source):
                frame = protected_frame(
                    source=source, destination=destination, seq=80 + source,
                    payload_size=48,
                )
                self.assertLessEqual(len(frame), 256)
                setattr(self.bridge, egress_limit, len(frame) - 1)
                result = self.bridge.receive(frame, 0, ingress_interface=ingress)
                self.assertEqual(result.reason, "mtu-exceeded")
                self.assertFalse(result.forwarded)
                self.assertIsNone(result.frame)


if __name__ == "__main__":
    unittest.main()
