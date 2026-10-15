import unittest

from dmp_peer.stream_l import StreamLError, decode_frame, encode_frame


class StreamLTests(unittest.TestCase):
    def test_minimal_telemetry_matches_published_wire_bytes(self):
        core = bytes.fromhex("45 02 AA BB")
        encoded = encode_frame(core)

        self.assertEqual(bytes.fromhex("44 4D 50 04 45 02 AA BB"), encoded)
        self.assertEqual(core, decode_frame(encoded))

    def test_invalid_magic_length_and_trailing_bytes_are_rejected(self):
        valid = bytes.fromhex("44 4D 50 04 45 02 AA BB")
        for malformed in (
            bytes.fromhex("45 4D 50 04 45 02 AA BB"),
            bytes.fromhex("44 4D 50 01 45"),
            valid + b"\x00",
            bytes.fromhex("44 4D 50 84 00 45 02 AA BB"),
        ):
            with self.subTest(packet=malformed), self.assertRaises(StreamLError):
                decode_frame(malformed)


if __name__ == "__main__":
    unittest.main()
