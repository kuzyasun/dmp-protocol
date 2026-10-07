import unittest

from dmp_peer.frame import (
    CoreFrame, Extension, Fragment, PayloadDescriptor, Route, Security,
    FrameError, crc32c, decode_uleb, encode_frame, encode_uleb, parse_frame,
)


class FrameTests(unittest.TestCase):
    def test_minimal_packet_and_golden_crc(self):
        self.assertEqual(crc32c(b"123456789"), 0xE3069283)
        raw = bytes.fromhex("45 04 10 01 AA BB A3 D5 0E BD")
        parsed = parse_frame(raw)
        self.assertEqual(parsed.message_type, 5)
        self.assertIsNone(parsed.sequence)
        self.assertEqual(parsed.payload, b"\xaa\xbb")
        self.assertEqual(encode_frame(parsed), raw)

    def test_roundtrip_full_structural_header_and_stream_security_shape(self):
        frame = CoreFrame(
            7, sequence=81, route=Route(3, 1, 27, 44),
            fragment=Fragment(0, 2, 3),
            payload_descriptor=PayloadDescriptor(3, 0, 5, 1),
            security=Security(1, 17, 127),
            extensions=(Extension(2, True, True, b"\x01" + (7).to_bytes(8, "little")),
                        Extension(4, True, False, b"\x02")),
            payload=b"\xaa\xbb",
            trailer=bytes(16),
        )
        wire = encode_frame(frame)
        result = parse_frame(wire)
        self.assertEqual(result, frame.__class__(**{**frame.__dict__, "options": result.options}))

    def test_uleb_boundaries_and_rejections(self):
        for number in (0, 127, 128, 16384, 0xFFFFFFFF):
            encoded = encode_uleb(number)
            self.assertEqual(decode_uleb(encoded), (number, len(encoded)))
        for invalid in (b"\x80\x00", b"\x80", b"\xff\xff\xff\xff\x10", b"\x80\x80\x80\x80\x80"):
            with self.subTest(invalid=invalid), self.assertRaises(FrameError):
                decode_uleb(invalid)

    def test_bad_header_lengths_types_and_options(self):
        for raw in (b"", b"\x00\x02", b"\x45\x01", b"\x45\x03\x00", b"\x45\x03\x00",
                    b"\x49\x02", b"\x40\x02", b"\x45\x03\x08"):
            with self.subTest(raw=raw), self.assertRaises(FrameError):
                parse_frame(raw)

    def test_extension_order_duplicates_flags_and_bounds(self):
        reply_to = b"\x01\x02" + bytes(8) + b"\x03"
        duplicate = (b"\x47\x1e\x81\x01"
                     + b"\x05\x0b" + reply_to
                     + b"\x05\x0b" + reply_to)
        with self.assertRaisesRegex(FrameError, "duplicated or out of order"):
            parse_frame(duplicate)
        one_reply_to = b"\x47\x11\x81\x01\x05\x0b" + reply_to
        self.assertEqual(parse_frame(one_reply_to).extensions[0].extension_id, 1)

        context = b"\x01" + bytes(8)
        out_of_order = (b"\x47\x1c\x81\x01"
                        + b"\x0b\x09" + context
                        + b"\x05\x0b" + reply_to)
        with self.assertRaisesRegex(FrameError, "duplicated or out of order"):
            parse_frame(out_of_order)
        reordered = (b"\x47\x1c\x81\x01"
                     + b"\x05\x0b" + reply_to
                     + b"\x0b\x09" + context)
        self.assertEqual([ext.extension_id for ext in parse_frame(reordered).extensions], [1, 2])

        bad_flags = b"\x47\x11\x81\x01\x04\x0b" + reply_to
        with self.assertRaisesRegex(FrameError, "incorrect flags"):
            parse_frame(bad_flags)
        correct_flags = b"\x47\x11\x81\x01\x05\x0b" + reply_to
        self.assertEqual(parse_frame(correct_flags).extensions[0].extension_id, 1)

        crosses_header = bytes.fromhex("47 06 81 01 1C 7F")
        with self.assertRaisesRegex(FrameError, "crosses HDR_LEN"):
            parse_frame(crosses_header)

    def test_unknown_safe_reserved_extension_is_preserved(self):
        raw = bytes.fromhex("47 06 81 01 1C 00")
        parsed = parse_frame(raw)
        self.assertEqual(parsed.extensions, (Extension(7, False, False, b""),))
        self.assertEqual(encode_frame(parsed), raw)

    def test_fragment_exact_tail_and_length(self):
        frame = CoreFrame(7, sequence=3, fragment=Fragment(1, 2, 3), payload=b"\x22")
        encoded = encode_frame(frame)
        self.assertEqual(parse_frame(encoded), frame.__class__(**{**frame.__dict__, "options": parse_frame(encoded).options}))
        with self.assertRaises(FrameError):
            parse_frame(encoded[:-1])
        malformed = CoreFrame(7, sequence=3, fragment=Fragment(0, 3, 3), payload=b"abc")
        with self.assertRaises(FrameError):
            encode_frame(malformed)

    def test_core_crc_is_verified(self):
        wire = encode_frame(CoreFrame(5, sequence=1, integrity=1, payload=b"\xaa"))
        self.assertEqual(parse_frame(wire).payload, b"\xaa")
        with self.assertRaisesRegex(FrameError, "CRC32C"):
            parse_frame(wire[:-1] + bytes((wire[-1] ^ 1,)))


if __name__ == "__main__":
    unittest.main()
