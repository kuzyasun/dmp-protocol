"""Independent encoder/decoder for DMP's reliable Stream L envelope."""

from __future__ import annotations

from .frame import FrameError, decode_uleb, encode_uleb, parse_frame


class StreamLError(ValueError):
    """Input is not one bounded, structurally valid Stream L frame."""


_MAGIC = b"\x44\x4d\x50"


def encode_frame(core: bytes, *, max_core: int = 1_048_576) -> bytes:
    if not isinstance(core, bytes):
        raise TypeError("Stream L core frame must be bytes")
    if not 2 <= len(core) <= max_core:
        raise StreamLError("Stream L core frame is outside its configured bound")
    try:
        parse_frame(core, max_frame=max_core)
        length = encode_uleb(len(core), bits=32)
    except FrameError as exc:
        raise StreamLError("Stream L core frame is malformed") from exc
    return _MAGIC + length + core


def decode_frame(packet: bytes, *, max_core: int = 1_048_576) -> bytes:
    if not isinstance(packet, bytes):
        raise TypeError("Stream L input must be bytes")
    if not packet.startswith(_MAGIC):
        raise StreamLError("Stream L magic mismatch")
    try:
        length, body_offset = decode_uleb(packet, len(_MAGIC), bits=32)
    except FrameError as exc:
        raise StreamLError("Stream L length is malformed") from exc
    if not 2 <= length <= max_core or len(packet) != body_offset + length:
        raise StreamLError("Stream L length is outside its bound or not exact")
    core = packet[body_offset:]
    try:
        parse_frame(core, max_frame=max_core)
    except FrameError as exc:
        raise StreamLError("Stream L core frame is malformed") from exc
    return core
