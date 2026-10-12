"""Independent structural fixtures for the provisional P21D relay role."""

from __future__ import annotations

import unittest
from pathlib import Path

from dmp_peer.relay import RelayError, TransparentRelay


ROOT = Path(__file__).resolve().parents[3]
RADIO = (ROOT / "profiles" / "deployments" / "radio-nnpsk0.json").read_bytes()


def uleb(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def extension(ext_id: int, value: bytes, *, critical: int = 1, unsafe: int = 0) -> bytes:
    return uleb((ext_id << 2) | (unsafe << 1) | critical) + uleb(len(value)) + value


def protected_routed_frame(*, seq: int = 77, pn: int = 1, frag_index: int = 0,
                           ttl: int = 4, source: int = 10, destination: int = 20,
                           payload: bytes | None = None, cid: int = 9,
                           epoch: int = 0x0102030405060708,
                           fragmented: bool = True) -> bytes:
    """Build a wire-shaped SEC-1 packet without importing any peer codec."""
    ciphertext = payload if payload is not None else bytes((pn & 0xFF,)) * 32
    route = bytes(((ttl << 4) | 1,)) + uleb(source) + uleb(destination)
    fragment = uleb(frag_index) + uleb(32) + uleb(64) if fragmented else b""
    security = bytes((1,)) + uleb(cid) + uleb(pn)
    context = uleb(1) + epoch.to_bytes(8, "little")
    extensions = (
        extension(2, context, critical=1, unsafe=1)
        + extension(4, uleb(2), critical=1, unsafe=0)
        + extension(64, b"xyz", critical=0, unsafe=0)
    )
    options = 0xCD if fragmented else 0xC5
    header = bytes((0x47, 0, options)) + uleb(seq) + route + fragment + security + extensions
    header = header[:1] + bytes((len(header),)) + header[2:]
    return header + ciphertext + bytes((0xA0 + pn % 16,)) * 16


def ttl_byte(frame: bytes) -> int:
    return frame[ttl_byte_offset(frame)]


class TransparentRelayTests(unittest.TestCase):
    def relay(self) -> TransparentRelay:
        return TransparentRelay(RADIO, relay_node=30)

    def finish(self, relay: TransparentRelay, decision, at_ms: int, transmitted: bool = True) -> None:
        self.assertTrue(decision.forwarded, decision.reason)
        relay.complete(decision.token, at_ms, transmitted=transmitted)

    def test_original_and_fresh_pn_retry_share_logical_fragment_key(self):
        relay = self.relay()
        original = protected_routed_frame(pn=1)
        first = relay.receive(original, 100)
        self.assertTrue(first.forwarded)
        expected = bytearray(original)
        expected[ttl_byte_offset(original)] -= 0x10
        self.assertEqual(first.frame, bytes(expected))
        self.assertEqual(first.frame[ttl_byte_offset(original)] >> 4, 3)
        self.finish(relay, first, 107)

        # Same logical message and fragment, but fresh PN/ciphertext/tag.
        retry = protected_routed_frame(pn=2)
        blocked = relay.receive(retry, 156)
        self.assertFalse(blocked.forwarded)
        self.assertEqual(blocked.reason, "cooldown")
        eligible = relay.receive(retry, 157)
        self.assertTrue(eligible.forwarded)
        self.finish(relay, eligible, 158)

        # A distinct fragment has an independent duplicate key.
        other_fragment = relay.receive(protected_routed_frame(pn=3, frag_index=1), 158)
        self.assertTrue(other_fragment.forwarded)

    def test_cooldown_anchors_only_to_last_forward_completion(self):
        relay = self.relay()
        first = relay.receive(protected_routed_frame(), 0)
        self.assertTrue(first.forwarded)
        self.assertEqual(relay.receive(protected_routed_frame(pn=2), 49).reason, "forward-pending")
        self.finish(relay, first, 100)
        self.assertEqual(relay.receive(protected_routed_frame(pn=2), 149).reason, "cooldown")
        retry = relay.receive(protected_routed_frame(pn=2), 150)
        self.assertTrue(retry.forwarded)

    def test_duplicates_do_not_extend_absolute_expiry(self):
        relay = self.relay()
        first = relay.receive(protected_routed_frame(), 0)
        self.finish(relay, first, 1)
        self.assertEqual(relay.receive(protected_routed_frame(pn=2), 49).reason, "cooldown")
        retry = relay.receive(protected_routed_frame(pn=3), 19_998)
        self.assertTrue(retry.forwarded)
        # The retry did not renew the first admission's 20,000 ms expiry.
        latest = next(iter(relay._entries.values()))
        self.assertEqual(latest.expires_at_ms, 20_000)
        self.finish(relay, retry, 19_999)
        self.assertEqual(relay.receive(protected_routed_frame(pn=4), 20_000).reason, "expired")

    def test_forward_count_per_key_is_bounded(self):
        relay = self.relay()
        for index in range(relay.max_forwards_per_key):
            at_ms = index * relay.cooldown_ms
            decision = relay.receive(protected_routed_frame(pn=index), at_ms)
            self.assertTrue(decision.forwarded, (index, decision.reason))
            relay.complete(decision.token, at_ms, transmitted=True)
        blocked = relay.receive(protected_routed_frame(pn=100), relay.max_forwards_per_key * relay.cooldown_ms)
        self.assertFalse(blocked.forwarded)
        self.assertEqual(blocked.reason, "forward-limit")

    def test_fragmented_and_unfragmented_forms_conflict_for_one_message_identity(self):
        for first_fragmented in (True, False):
            with self.subTest(first_fragmented=first_fragmented):
                relay = self.relay()
                first = relay.receive(
                    protected_routed_frame(seq=333, pn=1, fragmented=first_fragmented),
                    0,
                )
                self.assertTrue(first.forwarded)
                relay.complete(first.token, 1, transmitted=True)
                conflicting = relay.receive(
                    protected_routed_frame(seq=333, pn=2, fragmented=not first_fragmented),
                    relay.cooldown_ms + 1,
                )
                self.assertFalse(conflicting.forwarded)
                self.assertEqual(conflicting.reason, "identity-conflict")

    def test_cache_capacity_is_taken_from_the_frozen_relay_reserve(self):
        relay = self.relay()
        for seq in range(relay.cache_slots):
            decision = relay.receive(protected_routed_frame(seq=seq, pn=seq), seq)
            self.assertTrue(decision.forwarded, (seq, decision.reason))
            relay.complete(decision.token, seq, transmitted=True)
        full = relay.receive(protected_routed_frame(seq=relay.cache_slots, pn=500), relay.cache_slots)
        self.assertFalse(full.forwarded)
        self.assertEqual(full.reason, "cache-full")

    def test_per_origin_and_global_airtime_budgets(self):
        relay = self.relay()
        # A caller reserves actual airtime; the first origin reaches its RADIO-1 cap.
        for index in range(2):
            frame = protected_routed_frame(seq=100 + index, pn=index)
            decision = relay.receive(frame, index, airtime_ms=5_000)
            self.assertTrue(decision.forwarded)
            relay.complete(decision.token, index, transmitted=True)
        origin_limited = relay.receive(protected_routed_frame(seq=105, pn=5), 3)
        self.assertFalse(origin_limited.forwarded)
        self.assertEqual(origin_limited.reason, "origin-airtime-limit")

        # A second relay consumes the remaining origin budget, exhausting global airtime.
        relay = self.relay()
        for source, seq in ((10, 200), (20, 201)):
            frame = protected_routed_frame(seq=seq, pn=seq, source=source,
                                           destination=10 if source == 20 else 20)
            decision = relay.receive(frame, seq, airtime_ms=10_000)
            self.assertTrue(decision.forwarded)
            relay.complete(decision.token, seq, transmitted=True)
        global_limited = relay.receive(protected_routed_frame(seq=202, pn=202), 202)
        self.assertFalse(global_limited.forwarded)
        self.assertEqual(global_limited.reason, "global-airtime-limit")

    def test_ttl_mtu_and_protected_frame_bytes_are_bounded(self):
        relay = self.relay()
        original = protected_routed_frame(pn=17, ttl=1)
        decision = relay.receive(original, 0)
        self.assertTrue(decision.forwarded)
        expected = bytearray(original)
        offset = ttl_byte_offset(original)
        expected[offset] = original[offset] & 0x0F
        self.assertEqual(decision.frame, bytes(expected))
        self.finish(relay, decision, 1)
        with self.assertRaisesRegex(RelayError, "TTL zero"):
            relay.receive(protected_routed_frame(seq=78, pn=18, ttl=0), 2)
        oversized = protected_routed_frame(seq=79, pn=19, payload=b"x" * 240, fragmented=False)
        self.assertEqual(relay.receive(oversized, 2).reason, "mtu-exceeded")

    def test_rejects_malformed_or_unsupported_routing_and_security(self):
        relay = self.relay()
        with self.assertRaises(RelayError):
            relay.receive(b"\x47\x02\x00", 0)
        with self.assertRaises(RelayError):
            relay.receive(bytes((0x47, 0x03, 0x8D)) + b"\x4d", 0)
        non_unicast = protected_routed_frame()
        mutated = bytearray(non_unicast)
        mutated[ttl_byte_offset(non_unicast)] = 0x40
        with self.assertRaises(RelayError):
            relay.receive(bytes(mutated), 0)
        pn_limited = relay.receive(protected_routed_frame(seq=81, pn=(1 << 24)), 0)
        self.assertEqual(pn_limited.reason, "packet-number-limit")

    def test_completion_tokens_and_monotonic_clock_are_guarded(self):
        relay = self.relay()
        decision = relay.receive(protected_routed_frame(), 10)
        with self.assertRaises(RelayError):
            relay.receive(protected_routed_frame(seq=80), 9)
        relay.complete(decision.token, 11, transmitted=False)
        with self.assertRaises(RelayError):
            relay.complete(decision.token, 12, transmitted=True)


def ttl_byte_offset(frame: bytes) -> int:
    pos = 3
    while frame[pos] & 0x80:
        pos += 1
    return pos + 1


if __name__ == "__main__":
    unittest.main()
