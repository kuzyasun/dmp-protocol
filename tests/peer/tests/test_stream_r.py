import unittest

from dmp_peer.frame import CoreFrame, encode_frame
from dmp_peer.stream_r import (
    StreamRDecoder, cobs_decode, cobs_encode, encode_stream_r, initial_sync_delimiter,
)


class StreamRTests(unittest.TestCase):
    def test_published_cobs_vectors(self):
        self.assertEqual(cobs_encode(bytes.fromhex("11 00 22")), bytes.fromhex("02 11 02 22"))
        self.assertEqual(cobs_encode(b"\x11" * 254), b"\xff" + b"\x11" * 254 + b"\x01")
        self.assertEqual(cobs_encode(b"\x11" * 255), b"\xff" + b"\x11" * 254 + b"\x02\x11")
        self.assertEqual(cobs_encode(b"\x11" * 508), b"\xff" + b"\x11" * 254 + b"\xff" + b"\x11" * 254 + b"\x01")

    def test_decoder_handles_sync_chunking_and_coalescing(self):
        a = encode_frame(CoreFrame(5, sequence=1, payload=b"\x00\xaa"))
        b = encode_frame(CoreFrame(5, sequence=2, payload=b"\xbb"))
        stream = b"\x00" + encode_stream_r(a) + encode_stream_r(b)
        decoder = StreamRDecoder(max_encoded=100, max_core=40, candidate_timeout_ms=1000)
        events = decoder.feed(stream[:4], at_ms=0) + decoder.feed(stream[4:], at_ms=1)
        self.assertEqual([e.kind for e in events].count("synchronized"), 1)
        self.assertEqual([e.frame for e in events if e.kind == "frame"], [a, b])

    def test_bad_crc_and_canonical_cobs_rejected_then_resynchronizes(self):
        frame = encode_frame(CoreFrame(5, sequence=1, payload=b"x"))
        bad = bytearray(encode_stream_r(frame))
        bad[-2] ^= 1
        good = encode_stream_r(frame)
        decoder = StreamRDecoder(max_encoded=100, max_core=40, candidate_timeout_ms=1000,
                                 await_sync=False)
        events = decoder.feed(bytes(bad) + good, at_ms=0)
        self.assertEqual([e.kind for e in events].count("discarded"), 1)
        self.assertEqual([e.frame for e in events if e.kind == "frame"], [frame])
        with self.assertRaises(ValueError):
            cobs_decode(b"\xff" + b"\x11" * 254)

    def test_candidate_bound_discards_through_delimiter(self):
        decoder = StreamRDecoder(max_encoded=16, max_core=20, candidate_timeout_ms=1000,
                                 await_sync=False)
        events = decoder.feed(b"x" * 16 + b"\x00" + encode_stream_r(encode_frame(CoreFrame(5, sequence=1))),
                              at_ms=0)
        self.assertEqual(events[0].kind, "discarded")
        self.assertEqual(events[0].reason, "candidate-bound")
        self.assertTrue(any(event.kind == "frame" for event in events))

    def test_encoded_bound_includes_the_delimiter(self):
        at_cap = encode_frame(CoreFrame(5, payload=b"x" * 254))
        over_cap = encode_frame(CoreFrame(5, payload=b"x" * 255))
        encoded_at_cap = encode_stream_r(at_cap, max_core=256, max_encoded=263)
        self.assertEqual(len(encoded_at_cap), 263)
        self.assertEqual(encoded_at_cap[-1], 0)
        with self.assertRaisesRegex(ValueError, "including delimiter"):
            encode_stream_r(over_cap, max_core=257, max_encoded=263)

        decoder = StreamRDecoder(max_encoded=263, max_core=257,
                                 candidate_timeout_ms=1000, await_sync=False)
        events = decoder.feed(encode_stream_r(over_cap, max_core=257) , at_ms=0)
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0].kind, events[0].reason),
                         ("discarded", "candidate-bound"))

    def test_candidate_timeout_is_absolute_and_discards_to_delimiter(self):
        frame = encode_frame(CoreFrame(5, sequence=1, payload=b"ok"))
        wire = encode_stream_r(frame)
        exact = StreamRDecoder(max_encoded=100, max_core=40, candidate_timeout_ms=10,
                               await_sync=False)
        self.assertEqual(exact.feed(wire[:-1], at_ms=0), ())
        events = exact.feed(wire[-1:], at_ms=10)
        self.assertEqual([event.frame for event in events if event.kind == "frame"], [frame])

        late = StreamRDecoder(max_encoded=100, max_core=40, candidate_timeout_ms=10,
                              await_sync=False)
        self.assertEqual(late.feed(b"a", at_ms=0), ())
        self.assertEqual(late.feed(b"b", at_ms=9), ())
        expired = late.advance(10)
        self.assertEqual([(event.kind, event.reason) for event in expired],
                         [("discarded", "candidate-timeout")])
        self.assertEqual(late.feed(b"c", at_ms=11), ())
        recovered = late.feed(b"\x00" + wire, at_ms=12)
        self.assertEqual([event.frame for event in recovered if event.kind == "frame"], [frame])

    def test_late_input_does_not_renew_candidate_deadline(self):
        frame = encode_frame(CoreFrame(5, sequence=2))
        wire = encode_stream_r(frame)
        decoder = StreamRDecoder(max_encoded=100, max_core=40, candidate_timeout_ms=10,
                                 await_sync=False)
        decoder.feed(b"a", at_ms=100)
        events = decoder.feed(b"b", at_ms=111)
        self.assertEqual([(event.kind, event.reason) for event in events],
                         [("discarded", "candidate-timeout")])
        recovered = decoder.feed(b"\x00" + wire, at_ms=112)
        self.assertEqual([event.frame for event in recovered if event.kind == "frame"], [frame])

    def test_candidate_clock_is_monotonic(self):
        decoder = StreamRDecoder(max_encoded=100, max_core=40, candidate_timeout_ms=10,
                                 await_sync=False)
        decoder.feed(b"x", at_ms=10)
        with self.assertRaisesRegex(ValueError, "cannot move backwards"):
            decoder.advance(9)

    def test_encoder_starts_with_frame_envelope_without_initial_open_delimiter(self):
        frame = encode_frame(CoreFrame(5, sequence=1))
        self.assertTrue(encode_stream_r(frame).endswith(b"\x00"))
        self.assertNotEqual(encode_stream_r(frame)[:1], b"\x00")
        self.assertEqual(initial_sync_delimiter(), b"\x00")
        with self.assertRaises(ValueError):
            encode_stream_r(frame, max_core=len(frame) - 1)


if __name__ == "__main__":
    unittest.main()
