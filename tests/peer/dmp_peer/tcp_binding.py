"""Bounded loopback TCP binding for canonical Stream R envelopes.

This is a host-test adapter, not a reliable-delivery or production transport.
``TcpStreamBinding`` owns accepted frame copies and reports only local socket
handoff. ``start`` calls the receiver-ready hook before queuing the initial
Stream R synchronization delimiter. Call ``pump_write`` / ``poll_read`` from
the owning event loop; all calls for one binding must be serialized.

The small integration surface is ``start``, ``submit``, ``cancel``,
``pump_write``, ``poll_read``, ``disconnect`` and ``reconnect``. Times are
process-local monotonic milliseconds. A submission's generation must equal
``binding.generation``; terminal callbacks are ``(handle, generation,
outcome, at_ms)`` and never imply remote receipt.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Callable

from .stream_r import StreamEvent, StreamRDecoder, encode_stream_r


MAX_CORE = 256
MAX_ENVELOPE = 263
DEADLINE_CAPABILITY = "strict_latest_start"


@dataclass(frozen=True)
class Admission:
    accepted: bool
    reason: str | None = None


@dataclass
class _Submission:
    handle: int
    generation: int
    wire: bytes
    not_after_ms: int | None
    offset: int = 0

    @property
    def started(self) -> bool:
        return self.offset > 0


class TcpStreamBinding:
    """One bounded, nonblocking TCP stream endpoint."""

    def __init__(self, sock: socket.socket, *, on_frame: Callable[[bytes, int], None],
                 on_terminal: Callable[[int, int, str, int], None],
                 candidate_timeout_ms: int, max_slots: int = 4,
                 on_stream_event: Callable[[StreamEvent, int], None] | None = None,
                 clock_ms: Callable[[], int] | None = None):
        if isinstance(max_slots, bool) or not isinstance(max_slots, int) or max_slots < 1:
            raise ValueError("max_slots must be a positive integer")
        self._validate_callback(on_frame, "on_frame")
        self._validate_callback(on_terminal, "on_terminal")
        if on_stream_event is not None:
            self._validate_callback(on_stream_event, "on_stream_event")
        self._sock = sock
        self._sock.setblocking(False)
        self._on_frame = on_frame
        self._on_terminal = on_terminal
        self._on_stream_event = on_stream_event
        self._clock_ms = clock_ms or (lambda: time.monotonic_ns() // 1_000_000)
        self._candidate_timeout_ms = candidate_timeout_ms
        self._max_slots = max_slots
        self.generation = 1
        self._decoder = self._new_decoder()
        self._started = False
        self._connected = True
        self._sync_pending = bytearray()
        self._queue: list[_Submission] = []
        self._last_ms: int | None = None

    @staticmethod
    def _validate_callback(callback: object, name: str) -> None:
        if not callable(callback):
            raise TypeError(f"{name} must be callable")

    @classmethod
    def listen(cls, *, backlog: int = 1) -> socket.socket:
        """Create an IPv4 listener bound only to loopback and an ephemeral port."""
        if isinstance(backlog, bool) or not isinstance(backlog, int) or backlog < 1:
            raise ValueError("backlog must be a positive integer")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(backlog)
            return listener
        except BaseException:
            listener.close()
            raise

    @classmethod
    def connect_loopback(cls, port: int, *, timeout: float = 2.0) -> socket.socket:
        """Connect to a loopback listener; reject non-loopback port inputs."""
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port must be in 1..65535")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect(("127.0.0.1", port))
            sock.setblocking(False)
            return sock
        except BaseException:
            sock.close()
            raise

    @classmethod
    def accept_loopback(cls, listener: socket.socket) -> socket.socket:
        """Accept one loopback peer and reject/close any non-loopback client."""
        sock, address = listener.accept()
        if address[0] != "127.0.0.1":
            sock.close()
            raise OSError("TCP binding accepts IPv4 loopback peers only")
        sock.setblocking(False)
        return sock

    def _new_decoder(self) -> StreamRDecoder:
        return StreamRDecoder(max_encoded=MAX_ENVELOPE, max_core=MAX_CORE,
                              candidate_timeout_ms=self._candidate_timeout_ms)

    def _time(self, at_ms: int | None) -> int:
        now = self._clock_ms() if at_ms is None else at_ms
        if isinstance(now, bool) or not isinstance(now, int) or not 0 <= now <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("time must be an unsigned 64-bit millisecond value")
        if self._last_ms is not None and now < self._last_ms:
            raise ValueError("binding time cannot move backwards")
        self._last_ms = now
        return now

    def start(self, receiver_ready: Callable[[], None], *, at_ms: int | None = None) -> None:
        """Mark RX ready first, then schedule the one-byte startup delimiter."""
        if not self._connected:
            raise OSError("binding is disconnected")
        if self._started:
            raise RuntimeError("binding already started")
        self._validate_callback(receiver_ready, "receiver_ready")
        now = self._time(at_ms)
        receiver_ready()
        self._started = True
        self._sync_pending = bytearray(b"\x00")
        self._last_ms = now

    def submit(self, handle: int, generation: int, core_frame: bytes, *,
               not_after_ms: int | None = None, at_ms: int | None = None) -> Admission:
        """Copy/admit one core frame; rejection retains caller ownership."""
        now = self._time(at_ms)
        if (isinstance(handle, bool) or not isinstance(handle, int) or not 0 <= handle <= 0xFFFFFFFF
                or isinstance(generation, bool) or not isinstance(generation, int)
                or not 0 <= generation <= 0xFFFFFFFF
                or not isinstance(core_frame, (bytes, bytearray, memoryview))):
            return Admission(False, "invalid_argument")
        if generation != self.generation:
            return Admission(False, "stale_generation")
        if not self._connected or not self._started:
            return Admission(False, "disconnected")
        if any(item.handle == handle and item.generation == generation for item in self._queue):
            return Admission(False, "invalid_argument")
        if not_after_ms is not None and (isinstance(not_after_ms, bool)
                or not isinstance(not_after_ms, int) or not 0 <= not_after_ms <= 0xFFFFFFFFFFFFFFFF):
            return Admission(False, "invalid_argument")
        if not_after_ms is not None and now >= not_after_ms:
            return Admission(False, "expired")
        if len(self._queue) >= self._max_slots:
            return Admission(False, "busy")
        try:
            wire = encode_stream_r(bytes(core_frame), max_core=MAX_CORE, max_encoded=MAX_ENVELOPE)
        except (TypeError, ValueError):
            return Admission(False, "mtu_exceeded" if isinstance(core_frame, (bytes, bytearray, memoryview))
                             and len(core_frame) > MAX_CORE else "invalid_argument")
        self._queue.append(_Submission(handle, generation, bytes(wire), not_after_ms))
        return Admission(True)

    def cancel(self, handle: int, generation: int, *, at_ms: int | None = None) -> bool:
        """Request cancellation; a started frame is completed in stream order."""
        now = self._time(at_ms)
        for index, item in enumerate(self._queue):
            if item.handle != handle or item.generation != generation:
                continue
            if not item.started:
                self._queue.pop(index)
                self._terminal(item, "cancelled_unsent", now)
            return True
        return False

    def pump_write(self, *, at_ms: int | None = None) -> int:
        """Make nonblocking progress; return bytes accepted by the local socket."""
        now = self._time(at_ms)
        if not self._connected or not self._started:
            return 0
        written = 0
        while self._sync_pending:
            try:
                count = self._sock.send(self._sync_pending)
            except (BlockingIOError, InterruptedError):
                return written
            except OSError:
                self.disconnect(at_ms=now)
                return written
            if count == 0:
                return written
            if count < 0 or count > len(self._sync_pending):
                self.disconnect(at_ms=now)
                return written
            del self._sync_pending[:count]
            written += count
        while self._queue and self._connected:
            item = self._queue[0]
            if not item.started and item.not_after_ms is not None and now >= item.not_after_ms:
                self._queue.pop(0)
                self._terminal(item, "expired_unsent", now)
                continue
            try:
                # This is the strict-latest-start boundary: immediately before
                # the first nonblocking write call for this envelope.
                call_time = self._time(at_ms)
                if not item.started and item.not_after_ms is not None and call_time >= item.not_after_ms:
                    self._queue.pop(0)
                    self._terminal(item, "expired_unsent", call_time)
                    continue
                count = self._sock.send(item.wire[item.offset:])
            except (BlockingIOError, InterruptedError):
                return written
            except OSError:
                self.disconnect(at_ms=call_time)
                return written
            if count == 0:
                return written
            if count < 0 or count > len(item.wire) - item.offset:
                self.disconnect(at_ms=call_time)
                return written
            item.offset += count
            written += count
            if item.offset == len(item.wire):
                self._queue.pop(0)
                self._terminal(item, "transmitted", self._time(at_ms))
            else:
                # One successful send per call keeps scheduling bounded and
                # gives the owner a chance to service RX/cancellation.
                return written
        return written

    def feed_received(self, data: bytes, *, at_ms: int | None = None) -> tuple[StreamEvent, ...]:
        """Feed an already-read TCP chunk through the bounded Stream R decoder."""
        now = self._time(at_ms)
        if not self._connected or not self._started:
            return ()
        events = self._decoder.feed(bytes(data), at_ms=now)
        self._deliver(events, now)
        return events

    def poll_read(self, *, at_ms: int | None = None, chunk_size: int = 4096) -> int:
        """Read currently available bytes until would-block and decode incrementally."""
        now = self._time(at_ms)
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        if not self._connected or not self._started:
            return 0
        total = 0
        while True:
            try:
                chunk = self._sock.recv(chunk_size)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                self.disconnect(at_ms=now)
                break
            if not chunk:
                self.disconnect(at_ms=now)
                break
            total += len(chunk)
            # A recv boundary is not a stream boundary. Defer the exact-timeout
            # decision until every byte already available at this poll has had
            # a chance to include the candidate delimiter.
            events = self._decoder.feed(chunk, at_ms=now, expire_at_boundary=False)
            self._deliver(events, now)
        if self._connected:
            events = self._decoder.advance(now)
            self._deliver(events, now)
        return total

    def advance(self, *, at_ms: int | None = None) -> tuple[StreamEvent, ...]:
        """Advance absolute partial-candidate timeout handling."""
        now = self._time(at_ms)
        events = self._decoder.advance(now)
        self._deliver(events, now)
        return events

    def reconnect(self, sock: socket.socket, *, at_ms: int | None = None) -> int:
        """Install a fresh connection and generation after settling old work."""
        now = self._time(at_ms)
        self.disconnect(at_ms=now, close_socket=True)
        if self.generation == 0xFFFFFFFF:
            raise OverflowError("binding generation exhausted")
        self.generation += 1
        self._sock = sock
        self._sock.setblocking(False)
        self._decoder = self._new_decoder()
        self._sync_pending.clear()
        self._started = False
        self._connected = True
        return self.generation

    def disconnect(self, *, at_ms: int | None = None, close_socket: bool = True) -> None:
        """Settle all accepted sends once and drop partial RX/TX state."""
        now = self._time(at_ms)
        if not self._connected:
            return
        self._connected = False
        self._started = False
        self._sync_pending.clear()
        self._decoder = self._new_decoder()
        pending, self._queue = self._queue, []
        for item in pending:
            self._terminal(item, "possibly_transmitted" if item.started else "failed_unsent", now)
        if close_socket:
            try:
                self._sock.close()
            except OSError:
                pass

    def _deliver(self, events: tuple[StreamEvent, ...], at_ms: int) -> None:
        for event in events:
            if event.kind == "frame":
                self._on_frame(bytes(event.frame), at_ms)
            elif self._on_stream_event is not None:
                self._on_stream_event(event, at_ms)

    def _terminal(self, item: _Submission, outcome: str, at_ms: int) -> None:
        self._on_terminal(item.handle, item.generation, outcome, at_ms)
