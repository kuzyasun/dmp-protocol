"""Canonical Stream R framing with bounded incremental candidate handling."""

from __future__ import annotations

from dataclasses import dataclass

from .frame import crc32c, parse_frame


class StreamRError(ValueError):
    pass


def cobs_encode(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("COBS input must be bytes")
    out = bytearray((0,))
    code_at = 0
    code = 1
    for octet in data:
        if octet == 0:
            out[code_at] = code
            code_at = len(out)
            out.append(0)
            code = 1
        else:
            out.append(octet)
            code += 1
            if code == 0xFF:
                out[code_at] = code
                code_at = len(out)
                out.append(0)
                code = 1
    out[code_at] = code
    return bytes(out)


def cobs_decode(candidate: bytes) -> bytes:
    if not candidate or 0 in candidate:
        raise StreamRError("empty or delimiter-containing COBS candidate")
    out = bytearray()
    offset = 0
    while offset < len(candidate):
        code = candidate[offset]
        if code == 0:
            raise StreamRError("zero COBS code")
        offset += 1
        end = offset + code - 1
        if end > len(candidate):
            raise StreamRError("COBS block exceeds candidate")
        out.extend(candidate[offset:end])
        offset = end
        if code < 0xFF and offset < len(candidate):
            out.append(0)
    decoded = bytes(out)
    if cobs_encode(decoded) != candidate:
        raise StreamRError("noncanonical COBS representation")
    return decoded


def encode_stream_r(core_frame: bytes, *, max_core: int = 1_048_576,
                    max_encoded: int | None = None) -> bytes:
    if not isinstance(core_frame, bytes):
        raise TypeError("core frame must be bytes")
    if isinstance(max_core, bool) or not isinstance(max_core, int) or max_core < 2:
        raise ValueError("core-frame bound must be an integer of at least two bytes")
    if (max_encoded is not None
            and (isinstance(max_encoded, bool) or not isinstance(max_encoded, int)
                 or max_encoded < 2)):
        raise ValueError("encoded-envelope bound must be an integer of at least two bytes")
    if len(core_frame) > max_core:
        raise StreamRError("core frame exceeds configured bound")
    parse_frame(core_frame, max_frame=max_core)
    envelope = core_frame + crc32c(core_frame).to_bytes(4, "little")
    encoded = cobs_encode(envelope) + b"\x00"
    if max_encoded is not None and len(encoded) > max_encoded:
        raise StreamRError("encoded envelope including delimiter exceeds configured bound")
    return encoded


def initial_sync_delimiter() -> bytes:
    """Bytes a transmitter emits after its receiver is ready on open or reset."""
    return b"\x00"


@dataclass(frozen=True)
class StreamEvent:
    kind: str
    frame: bytes | None = None
    reason: str | None = None


class StreamRDecoder:
    """Incrementally decode Stream R after a sync delimiter; discard bad candidates."""

    def __init__(self, *, max_encoded: int, max_core: int,
                 candidate_timeout_ms: int, await_sync: bool = True):
        if (isinstance(max_encoded, bool) or not isinstance(max_encoded, int) or max_encoded < 2
                or isinstance(max_core, bool) or not isinstance(max_core, int) or max_core < 2):
            raise ValueError("bounds are too small")
        if (isinstance(candidate_timeout_ms, bool) or not isinstance(candidate_timeout_ms, int)
                or candidate_timeout_ms <= 0):
            raise ValueError("candidate timeout must be a positive integer")
        self.max_encoded = max_encoded
        self.max_core = max_core
        self.candidate_timeout_ms = candidate_timeout_ms
        self._synced = not await_sync
        self._candidate = bytearray()
        self._discarding = False
        self._discard_reason: str | None = None
        self._discard_reported = False
        self._candidate_started_ms: int | None = None
        self._now_ms: int | None = None

    def _set_time(self, now_ms: int) -> None:
        if (isinstance(now_ms, bool) or not isinstance(now_ms, int)
                or not 0 <= now_ms <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("time must be an unsigned 64-bit millisecond value")
        if self._now_ms is not None and now_ms < self._now_ms:
            raise ValueError("Stream R time cannot move backwards")
        self._now_ms = now_ms

    def _expire(self) -> StreamEvent | None:
        if self._candidate_started_ms is None:
            return None
        self._candidate.clear()
        self._candidate_started_ms = None
        self._discarding = True
        self._discard_reason = "candidate-timeout"
        self._discard_reported = True
        return StreamEvent("discarded", reason="candidate-timeout")

    def advance(self, now_ms: int) -> tuple[StreamEvent, ...]:
        self._set_time(now_ms)
        if (self._candidate_started_ms is not None
                and now_ms >= self._candidate_started_ms + self.candidate_timeout_ms):
            event = self._expire()
            return (event,) if event else ()
        return ()

    def feed(self, chunk: bytes, *, at_ms: int) -> tuple[StreamEvent, ...]:
        if not isinstance(chunk, bytes):
            raise TypeError("stream input must be bytes")
        self._set_time(at_ms)
        events: list[StreamEvent] = []
        if (self._candidate_started_ms is not None
                and at_ms > self._candidate_started_ms + self.candidate_timeout_ms):
            event = self._expire()
            if event:
                events.append(event)
        for octet in chunk:
            if octet == 0:
                if not self._synced:
                    self._synced = True
                    self._candidate.clear()
                    self._candidate_started_ms = None
                    self._discarding = False
                    self._discard_reason = None
                    self._discard_reported = False
                    events.append(StreamEvent("synchronized"))
                    continue
                if self._discarding:
                    self._discarding = False
                    self._candidate.clear()
                    self._candidate_started_ms = None
                    if not self._discard_reported:
                        events.append(StreamEvent("discarded", reason=self._discard_reason))
                    self._discard_reason = None
                    self._discard_reported = False
                    continue
                if not self._candidate:
                    events.append(StreamEvent("empty"))
                    continue
                candidate = bytes(self._candidate)
                self._candidate.clear()
                self._candidate_started_ms = None
                try:
                    envelope = cobs_decode(candidate)
                    if len(envelope) < 6:
                        raise StreamRError("envelope is shorter than minimum frame plus CRC")
                    if len(envelope) - 4 > self.max_core:
                        raise StreamRError("core frame exceeds configured bound")
                    core = envelope[:-4]
                    if int.from_bytes(envelope[-4:], "little") != crc32c(core):
                        raise StreamRError("envelope CRC32C mismatch")
                    parse_frame(core, max_frame=self.max_core)
                except (StreamRError, ValueError) as exc:
                    events.append(StreamEvent("discarded", reason=str(exc)))
                else:
                    events.append(StreamEvent("frame", bytes(core)))
                continue
            if not self._synced or self._discarding:
                continue
            if len(self._candidate) + 1 >= self.max_encoded:
                self._candidate.clear()
                self._candidate_started_ms = None
                self._discarding = True
                self._discard_reason = "candidate-bound"
                self._discard_reported = False
            else:
                self._candidate.append(octet)
                if self._candidate_started_ms is None:
                    self._candidate_started_ms = at_ms
        if (self._candidate_started_ms is not None
                and at_ms == self._candidate_started_ms + self.candidate_timeout_ms):
            event = self._expire()
            if event:
                events.append(event)
        return tuple(events)
