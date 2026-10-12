import socket
import unittest

from dmp_peer.frame import CoreFrame, encode_frame
from dmp_peer.stream_r import encode_stream_r
from dmp_peer.tcp_binding import MAX_CORE, MAX_ENVELOPE, TcpStreamBinding


class FakeSocket:
    def __init__(self, sends=(), receives=()):
        self.sends = list(sends)
        self.receives = list(receives)
        self.sent = bytearray()
        self.closed = False
        self.blocking = None

    def setblocking(self, value):
        self.blocking = value

    def send(self, data):
        action = self.sends.pop(0) if self.sends else len(data)
        if isinstance(action, BaseException):
            raise action
        count = min(action, len(data))
        self.sent.extend(data[:count])
        return count

    def recv(self, size):
        if not self.receives:
            raise BlockingIOError()
        action = self.receives.pop(0)
        if isinstance(action, BaseException):
            raise action
        if action is None:
            return b""
        return action[:size]

    def close(self):
        self.closed = True


class TcpStreamBindingTests(unittest.TestCase):
    def setUp(self):
        self.frames = []
        self.terminals = []
        self.events = []

    def binding(self, sock=None, **kwargs):
        binding = TcpStreamBinding(
            sock or FakeSocket(), on_frame=lambda frame, at: self.frames.append((frame, at)),
            on_terminal=lambda *event: self.terminals.append(event),
            candidate_timeout_ms=kwargs.pop("candidate_timeout_ms", 10),
            on_stream_event=lambda *event: self.events.append(event), **kwargs,
        )
        binding.start(lambda: self.events.append(("ready",)), at_ms=0)
        return binding

    def test_listener_uses_loopback_and_ephemeral_port(self):
        listener = TcpStreamBinding.listen()
        try:
            host, port = listener.getsockname()
            self.assertEqual(host, "127.0.0.1")
            self.assertGreater(port, 0)
        finally:
            listener.close()

    def test_receiver_ready_precedes_startup_sync_and_frame(self):
        sock = FakeSocket()
        order = []
        binding = TcpStreamBinding(sock, on_frame=lambda *_: None, on_terminal=lambda *_: None,
                                  candidate_timeout_ms=10)
        binding.start(lambda: order.append("ready"), at_ms=0)
        binding.submit(1, 1, encode_frame(CoreFrame(5)), at_ms=0)
        binding.pump_write(at_ms=0)
        self.assertEqual(order, ["ready"])
        self.assertEqual(bytes(sock.sent), b"\x00" + encode_stream_r(encode_frame(CoreFrame(5))))

    def test_split_and_coalesced_loopback_reads(self):
        listener = TcpStreamBinding.listen()
        client = None
        server = None
        try:
            host, port = listener.getsockname()
            try:
                client = TcpStreamBinding.connect_loopback(port)
            except PermissionError as exc:
                self.skipTest(f"sandbox denies loopback TCP: {exc}")
            server = TcpStreamBinding.accept_loopback(listener)
            rx = TcpStreamBinding(server, on_frame=lambda f, t: self.frames.append((f, t)),
                                  on_terminal=lambda *_: None, candidate_timeout_ms=100)
            tx = TcpStreamBinding(client, on_frame=lambda *_: None, on_terminal=lambda *_: None,
                                  candidate_timeout_ms=100)
            rx.start(lambda: None, at_ms=0)
            tx.start(lambda: None, at_ms=0)
            tx.pump_write(at_ms=0)
            rx.poll_read(at_ms=0)
            a = encode_frame(CoreFrame(5, sequence=1, payload=b"a"))
            b = encode_frame(CoreFrame(5, sequence=2, payload=b"b"))
            # Split one envelope across TCP writes, then coalesce the tail and
            # the next envelope in a single write. The receiver also reads in
            # small chunks to exercise arbitrary TCP segmentation.
            stream = encode_stream_r(a) + encode_stream_r(b)
            client.sendall(stream[:3])
            client.sendall(stream[3:])
            rx.poll_read(at_ms=1, chunk_size=3)
            self.assertEqual([frame for frame, _ in self.frames], [a, b])
        finally:
            listener.close()
            for sock in (client, server):
                if sock:
                    sock.close()

    def test_copy_ownership_ordering_and_bounded_backpressure(self):
        sock = FakeSocket([1, BlockingIOError(), 4096, 4096])
        binding = self.binding(sock, max_slots=1)
        binding.pump_write(at_ms=0)  # Startup delimiter.
        source = bytearray(encode_frame(CoreFrame(5, sequence=1, payload=b"one")))
        expected = encode_stream_r(bytes(source))
        self.assertTrue(binding.submit(4, 1, source, at_ms=1).accepted)
        source[:] = b"x" * len(source)
        self.assertEqual(binding.submit(5, 1, encode_frame(CoreFrame(5)), at_ms=1).reason, "busy")
        binding.pump_write(at_ms=1)
        binding.pump_write(at_ms=1)
        self.assertEqual(sock.sent[-len(expected):], expected)
        self.assertEqual(self.terminals, [(4, 1, "transmitted", 1)])

    def test_deadline_is_strict_at_first_positive_write(self):
        sock = FakeSocket([1, BlockingIOError(), 1])
        binding = self.binding(sock)
        binding.pump_write(at_ms=0)
        binding.submit(1, 1, encode_frame(CoreFrame(5)), not_after_ms=5, at_ms=1)
        self.assertEqual(binding.pump_write(at_ms=5), 0)
        self.assertEqual(self.terminals, [(1, 1, "expired_unsent", 5)])

        sock2 = FakeSocket([1, 1, 4096])
        binding2 = TcpStreamBinding(sock2, on_frame=lambda *_: None,
                                    on_terminal=lambda *event: self.terminals.append(event),
                                    candidate_timeout_ms=10)
        binding2.start(lambda: None, at_ms=0)
        binding2.pump_write(at_ms=0)
        binding2.submit(2, 1, encode_frame(CoreFrame(5)), not_after_ms=5, at_ms=1)
        binding2.pump_write(at_ms=4)
        binding2.pump_write(at_ms=4)
        self.assertEqual(self.terminals[-1], (2, 1, "transmitted", 4))

    def test_write_would_block_does_not_start_and_deadline_is_rechecked(self):
        sock = FakeSocket([1, BlockingIOError(), BlockingIOError(), 8])
        binding = self.binding(sock)
        binding.pump_write(at_ms=0)
        binding.submit(2, 1, encode_frame(CoreFrame(5)), not_after_ms=10, at_ms=1)
        self.assertEqual(binding.pump_write(at_ms=9), 0)
        self.assertEqual(self.terminals, [])
        self.assertEqual(binding.pump_write(at_ms=10), 0)
        self.assertEqual(self.terminals, [(2, 1, "expired_unsent", 10)])

    def test_cancel_before_start_and_after_start(self):
        sock = FakeSocket([1, 1, 4096])
        binding = self.binding(sock)
        binding.pump_write(at_ms=0)
        frame1 = encode_frame(CoreFrame(5, sequence=1))
        self.assertTrue(binding.submit(1, 1, frame1, at_ms=1).accepted)
        self.assertTrue(binding.cancel(1, 1, at_ms=1))
        self.assertEqual(self.terminals, [(1, 1, "cancelled_unsent", 1)])
        self.assertTrue(binding.submit(2, 1, frame1, at_ms=2).accepted)
        binding.pump_write(at_ms=2)  # First byte starts it.
        self.assertTrue(binding.cancel(2, 1, at_ms=3))
        binding.pump_write(at_ms=3)
        self.assertEqual(self.terminals[-1], (2, 1, "transmitted", 3))
        self.assertEqual(len(self.terminals), 2)

    def test_disconnect_before_and_after_start_settles_once(self):
        sock = FakeSocket([1, BlockingIOError(), 2, BrokenPipeError()])
        binding = self.binding(sock)
        binding.pump_write(at_ms=0)
        frame = encode_frame(CoreFrame(5, sequence=1))
        binding.submit(1, 1, frame, at_ms=1)
        binding.submit(2, 1, frame, at_ms=1)
        binding.pump_write(at_ms=1)
        binding.pump_write(at_ms=2)
        binding.pump_write(at_ms=2)
        self.assertEqual(self.terminals, [(1, 1, "possibly_transmitted", 2),
                                          (2, 1, "failed_unsent", 2)])
        binding.disconnect(at_ms=3)
        self.assertEqual(len(self.terminals), 2)

    def test_failure_before_first_frame_write_is_known_unsent(self):
        sock = FakeSocket([1, BrokenPipeError()])
        binding = self.binding(sock)
        binding.pump_write(at_ms=0)
        binding.submit(1, 1, encode_frame(CoreFrame(5)), at_ms=1)
        binding.pump_write(at_ms=1)
        self.assertEqual(self.terminals, [(1, 1, "failed_unsent", 1)])

    def test_cancel_and_disconnect_ignore_stale_generation(self):
        binding = self.binding()
        binding.pump_write(at_ms=0)
        old_generation = binding.generation
        self.assertFalse(binding.cancel(3, old_generation + 1, at_ms=1))
        replacement = FakeSocket()
        self.assertEqual(binding.reconnect(replacement, at_ms=2), old_generation + 1)
        self.assertEqual(binding.submit(3, old_generation, encode_frame(CoreFrame(5)), at_ms=2).reason,
                         "stale_generation")
        binding.start(lambda: None, at_ms=2)
        binding.pump_write(at_ms=2)
        self.assertTrue(binding.submit(3, binding.generation,
                                       encode_frame(CoreFrame(5)), at_ms=2).accepted)
        binding.pump_write(at_ms=2)
        self.assertEqual(self.terminals, [(3, binding.generation, "transmitted", 2)])

    def test_bad_crc_oversize_and_reset_resynchronize(self):
        binding = self.binding()
        frame = encode_frame(CoreFrame(5, sequence=1))
        binding.feed_received(b"\x00", at_ms=1)
        bad = bytearray(encode_stream_r(frame))
        bad[-2] ^= 1
        oversized = b"x" * MAX_ENVELOPE + b"\x00"
        good = encode_stream_r(frame)
        events = binding.feed_received(bytes(bad) + oversized + good, at_ms=2)
        self.assertEqual([f for f, _ in self.frames], [frame])
        self.assertGreaterEqual(sum(e.kind == "discarded" for e in events), 2)

    def test_partial_timeout_requires_delimiter_before_recovery(self):
        binding = self.binding(candidate_timeout_ms=5)
        binding.feed_received(b"\x00abc", at_ms=1)
        events = binding.advance(at_ms=6)
        self.assertEqual([(event.kind, event.reason) for event in events],
                         [("discarded", "candidate-timeout")])
        frame = encode_frame(CoreFrame(5, sequence=7))
        binding.feed_received(b"junk" + b"\x00" + encode_stream_r(frame), at_ms=7)
        self.assertEqual([f for f, _ in self.frames], [frame])

    def test_poll_read_processes_available_delimiter_before_exact_timeout(self):
        frame = encode_frame(CoreFrame(5, sequence=9, payload=b"boundary"))
        wire = encode_stream_r(frame)
        sock = FakeSocket(receives=[b"\x00" + wire[:3]])
        binding = self.binding(sock, candidate_timeout_ms=26)
        self.assertEqual(binding.poll_read(at_ms=0), 4)

        # The complete envelope is already available at the deadline, but the
        # socket returns its final bytes across two recv calls.
        sock.receives.extend((wire[3:-1], wire[-1:]))
        self.assertEqual(binding.poll_read(at_ms=26), len(wire) - 3)
        self.assertEqual([received for received, _ in self.frames], [frame])
        self.assertFalse(any(event[0].reason == "candidate-timeout" for event in self.events
                             if len(event) > 1 and hasattr(event[0], "reason")))

    def test_zero_write_retries_without_starting_or_disconnect(self):
        sock = FakeSocket([1, 0, 4096])
        binding = self.binding(sock)
        binding.pump_write(at_ms=0)  # Startup delimiter.
        frame = encode_frame(CoreFrame(5, sequence=10))
        self.assertTrue(binding.submit(3, 1, frame, not_after_ms=10, at_ms=1).accepted)

        self.assertEqual(binding.pump_write(at_ms=2), 0)
        self.assertFalse(sock.closed)
        self.assertEqual(self.terminals, [])
        self.assertEqual(binding.pump_write(at_ms=3), len(encode_stream_r(frame)))
        self.assertEqual(self.terminals, [(3, 1, "transmitted", 3)])

    def test_zero_write_rechecks_deadline_before_retry(self):
        sock = FakeSocket([1, 0, 4096])
        binding = self.binding(sock)
        binding.pump_write(at_ms=0)
        self.assertTrue(binding.submit(4, 1, encode_frame(CoreFrame(5)),
                                      not_after_ms=5, at_ms=1).accepted)
        self.assertEqual(binding.pump_write(at_ms=2), 0)
        self.assertEqual(binding.pump_write(at_ms=5), 0)
        self.assertEqual(self.terminals, [(4, 1, "expired_unsent", 5)])
        self.assertFalse(sock.closed)

    def test_frame_and_envelope_caps(self):
        at_cap = encode_frame(CoreFrame(5, payload=b"x" * 254))
        self.assertEqual(len(at_cap), MAX_CORE)
        self.assertEqual(len(encode_stream_r(at_cap, max_core=MAX_CORE, max_encoded=MAX_ENVELOPE)),
                         MAX_ENVELOPE)
        binding = self.binding()
        self.assertEqual(binding.submit(1, 1, b"\x00\x02", at_ms=1).reason, "invalid_argument")
        self.assertEqual(binding.submit(2, 1, at_cap + b"x", at_ms=1).reason, "mtu_exceeded")


if __name__ == "__main__":
    unittest.main()
