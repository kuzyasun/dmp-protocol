"""Bounded structural DMP v2 core-frame codec."""

from __future__ import annotations

from dataclasses import dataclass


class FrameError(ValueError):
    """Input is not a canonical, structurally valid core frame."""


@dataclass(frozen=True)
class Route:
    ttl: int
    mode: int
    source_id: int
    destination_id: int | None = None


@dataclass(frozen=True)
class Fragment:
    index: int
    chunk_size: int
    total_length: int


@dataclass(frozen=True)
class PayloadDescriptor:
    flags: int
    codec_id: int
    schema_id: int | None = None
    schema_version: int | None = None


@dataclass(frozen=True)
class Security:
    cipher: int
    receive_cid: int
    packet_number: int


@dataclass(frozen=True)
class Extension:
    extension_id: int
    critical: bool
    unsafe: bool
    value: bytes

    @property
    def tag(self) -> int:
        return (self.extension_id << 2) | (int(self.unsafe) << 1) | int(self.critical)


@dataclass(frozen=True)
class CoreFrame:
    message_type: int
    options: int = 0
    sequence: int | None = None
    route: Route | None = None
    fragment: Fragment | None = None
    payload_descriptor: PayloadDescriptor | None = None
    integrity: int | None = None
    security: Security | None = None
    extensions: tuple[Extension, ...] = ()
    payload: bytes = b""
    trailer: bytes = b""


def encode_uleb(value: int, *, bits: int = 32) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise FrameError(f"ULEB{bits} value out of range")
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def decode_uleb(data: bytes, offset: int = 0, *, bits: int = 32, end: int | None = None) -> tuple[int, int]:
    limit = len(data) if end is None else end
    maximum = (bits + 6) // 7
    value = 0
    for index in range(maximum):
        if offset >= limit:
            raise FrameError("truncated ULEB")
        octet = data[offset]
        offset += 1
        part = octet & 0x7F
        shift = 7 * index
        if part >= (1 << (bits - shift)):
            raise FrameError("ULEB overflow")
        value |= part << shift
        if not octet & 0x80:
            if index and part == 0:
                raise FrameError("non-minimal ULEB")
            return value, offset
    raise FrameError("ULEB continuation exceeds width")


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in data:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def _read_extensions(data: bytes, offset: int, end: int, secure: bool) -> tuple[Extension, ...]:
    entries = []
    previous = -1
    while offset < end:
        tag, offset = decode_uleb(data, offset, end=end)
        length, offset = decode_uleb(data, offset, end=end)
        ident, flags = tag >> 2, tag & 3
        if ident <= previous:
            raise FrameError("extensions are duplicated or out of order")
        if length > end - offset:
            raise FrameError("extension crosses HDR_LEN")
        value = data[offset:offset + length]
        offset += length
        previous = ident
        expected_flags = {1: 1, 2: 3, 3: 3, 4: 1, 5: 1, 6: 1}.get(ident)
        if expected_flags is not None and flags != expected_flags:
            raise FrameError("known extension has incorrect flags")
        if ident == 1:
            at = 0
            if not secure:
                _, at = decode_uleb(value, at)
                _, at = decode_uleb(value, at)
                if len(value) - at < 8:
                    raise FrameError("short full REPLY_TO epoch")
                at += 8
            _, at = decode_uleb(value, at)
            if at != len(value):
                raise FrameError("invalid REPLY_TO length")
        elif ident == 2:
            _, at = decode_uleb(value)
            if len(value) - at != 8:
                raise FrameError("invalid CONTEXT length")
        elif ident == 3:
            _, at = decode_uleb(value)
            if at != len(value):
                raise FrameError("invalid ORIGIN_ID length")
        elif ident in (4, 5):
            _, at = decode_uleb(value)
            if at != len(value):
                raise FrameError("invalid integer extension length")
        elif ident == 6 and (not secure or len(value) != 16):
            raise FrameError("FRESHNESS requires SECURITY and exactly 16 bytes")
        entries.append(Extension(ident, bool(flags & 1), bool(flags & 2), bytes(value)))
    return tuple(entries)


def parse_frame(data: bytes, *, max_frame: int = 1_048_576) -> CoreFrame:
    if not isinstance(data, bytes) or len(data) > max_frame or len(data) < 2:
        raise FrameError("frame is too short or exceeds configured bound")
    vt, header_length = data[0], data[1]
    if vt >> 5 != 2:
        raise FrameError("unsupported wire version")
    kind = vt & 0x1F
    if 9 <= kind <= 23:
        raise FrameError("reserved message type")
    if not 2 <= header_length <= min(255, len(data)):
        raise FrameError("invalid HDR_LEN")
    if header_length == 2:
        if (vt & 0x1F) in (0, 1, 2, 6, 8):
            raise FrameError("message type requires SEQ")
        return CoreFrame(kind, payload=data[2:])
    options, offset, end = data[2], 3, header_length
    if options == 0:
        raise FrameError("OPTIONS=0 is noncanonical")
    sequence = route = fragment = descriptor = integrity = security = None
    extensions = ()
    if options & 1:
        sequence, offset = decode_uleb(data, offset, end=end)
    if options & 4:
        if offset >= end:
            raise FrameError("truncated ROUTE_CONTROL")
        control = data[offset]
        offset += 1
        ttl, mode = control >> 4, control & 0x0F
        if mode > 2:
            raise FrameError("reserved route destination mode")
        source, offset = decode_uleb(data, offset, end=end)
        destination = None
        if mode == 1:
            destination, offset = decode_uleb(data, offset, end=end)
        route = Route(ttl, mode, source, destination)
    if options & 8:
        index, offset = decode_uleb(data, offset, end=end)
        chunk, offset = decode_uleb(data, offset, end=end)
        total, offset = decode_uleb(data, offset, end=end)
        if not 0 < chunk < total or index >= (total + chunk - 1) // chunk:
            raise FrameError("invalid fragment geometry")
        fragment = Fragment(index, chunk, total)
    if options & 0x20:
        if offset >= end:
            raise FrameError("truncated payload descriptor")
        flags, offset = data[offset], offset + 1
        if flags & 0xFC or flags & 2 and not flags & 1:
            raise FrameError("invalid payload descriptor flags")
        codec, offset = decode_uleb(data, offset, end=end)
        schema = version = None
        if flags & 1:
            schema, offset = decode_uleb(data, offset, end=end)
        if flags & 2:
            version, offset = decode_uleb(data, offset, end=end)
        descriptor = PayloadDescriptor(flags, codec, schema, version)
    if options & 0x10:
        if offset >= end:
            raise FrameError("truncated integrity descriptor")
        integrity, offset = data[offset], offset + 1
        if integrity != 1:
            raise FrameError("unsupported core integrity descriptor")
    if options & 0x40:
        if offset >= end:
            raise FrameError("truncated security descriptor")
        cipher, offset = data[offset], offset + 1
        cid, offset = decode_uleb(data, offset, end=end)
        pn, offset = decode_uleb(data, offset, bits=64, end=end)
        if cipher not in (1, 2) or integrity is not None or sequence is None:
            raise FrameError("unsupported/inconsistent security descriptor")
        security = Security(cipher, cid, pn)
    if options & 0x80:
        if offset == end:
            raise FrameError("EXT requires at least one extension")
        extensions = _read_extensions(data, offset, end, security is not None)
        offset = end
    if offset != end:
        raise FrameError("unexplained bytes within HDR_LEN")
    trailer_size = 4 if integrity else 16 if security else 0
    if len(data) < header_length + trailer_size:
        raise FrameError("truncated trailer")
    body_end = len(data) - trailer_size
    payload, trailer = data[header_length:body_end], data[body_end:]
    if integrity and int.from_bytes(trailer, "little") != crc32c(data[:body_end]):
        raise FrameError("core CRC32C mismatch")
    if fragment:
        expected = min(fragment.chunk_size, fragment.total_length - fragment.index * fragment.chunk_size)
        if expected <= 0 or len(payload) != expected:
            raise FrameError("fragment payload length does not match geometry")
    ext_ids = {ext.extension_id for ext in extensions}
    if route and 3 in ext_ids:
        raise FrameError("ROUTE and ORIGIN_ID cannot both be present")
    if options & 2 and sequence is None:
        raise FrameError("ACK_REQ requires SEQ")
    if options & 0x0C and sequence is None:
        raise FrameError("ROUTE and FRAG require SEQ")
    if kind in (0, 1, 2, 6, 8) and sequence is None:
        raise FrameError("message type requires SEQ")
    if kind in (1, 2, 6, 8) and 1 not in ext_ids:
        raise FrameError("reply/receipt type requires REPLY_TO")
    if kind == 2 and 5 not in ext_ids:
        raise FrameError("ERR requires STATUS")
    if kind == 6 and (payload or options & (2 | 8 | 0x20) or 5 in ext_ids):
        raise FrameError("invalid ACK structure")
    if kind == 8 and (not security or len(payload) != 4 or options & (2 | 8 | 0x20) or 5 in ext_ids or 6 in ext_ids):
        raise FrameError("invalid FRAG_STATUS structure")
    return CoreFrame(kind, options, sequence, route, fragment, descriptor, integrity,
                     security, extensions, bytes(payload), bytes(trailer))


def encode_frame(frame: CoreFrame, *, max_frame: int = 1_048_576) -> bytes:
    if not isinstance(frame, CoreFrame):
        raise FrameError("expected CoreFrame")
    if isinstance(frame.message_type, bool) or not isinstance(frame.message_type, int) or not 0 <= frame.message_type <= 31:
        raise FrameError("message type is outside VT range")
    if 9 <= frame.message_type <= 23:
        raise FrameError("reserved message type")
    options = (1 if frame.sequence is not None else 0) | (4 if frame.route else 0)
    options |= (8 if frame.fragment else 0) | (0x20 if frame.payload_descriptor else 0)
    options |= (0x10 if frame.integrity is not None else 0) | (0x40 if frame.security else 0)
    options |= (0x80 if frame.extensions else 0) | (frame.options & 2)
    if options == 0:
        header = bytes(((2 << 5) | frame.message_type, 2))
    else:
        out = bytearray((options,))
        if frame.sequence is not None:
            out.extend(encode_uleb(frame.sequence))
        if frame.route:
            if not 0 <= frame.route.ttl <= 15 or frame.route.mode not in (0, 1, 2):
                raise FrameError("invalid route")
            out.append((frame.route.ttl << 4) | frame.route.mode)
            out.extend(encode_uleb(frame.route.source_id))
            if frame.route.mode == 1:
                if frame.route.destination_id is None:
                    raise FrameError("TO_NODE route requires destination")
                out.extend(encode_uleb(frame.route.destination_id))
        if frame.fragment:
            out.extend(encode_uleb(frame.fragment.index))
            out.extend(encode_uleb(frame.fragment.chunk_size))
            out.extend(encode_uleb(frame.fragment.total_length))
        if frame.payload_descriptor:
            desc = frame.payload_descriptor
            out.append(desc.flags)
            out.extend(encode_uleb(desc.codec_id))
            if desc.flags & 1:
                if desc.schema_id is None:
                    raise FrameError("schema flag requires schema id")
                out.extend(encode_uleb(desc.schema_id))
            if desc.flags & 2:
                if desc.schema_version is None:
                    raise FrameError("version flag requires version")
                out.extend(encode_uleb(desc.schema_version))
        if frame.integrity is not None:
            out.append(frame.integrity)
        if frame.security:
            out.append(frame.security.cipher)
            out.extend(encode_uleb(frame.security.receive_cid))
            out.extend(encode_uleb(frame.security.packet_number, bits=64))
        previous = -1
        for ext in frame.extensions:
            if ext.extension_id <= previous:
                raise FrameError("extensions must be unique and increasing")
            previous = ext.extension_id
            out.extend(encode_uleb(ext.tag))
            out.extend(encode_uleb(len(ext.value)))
            out.extend(ext.value)
        if len(out) + 2 > 255:
            raise FrameError("header exceeds HDR_LEN")
        header = bytes(((2 << 5) | frame.message_type, len(out) + 2)) + bytes(out)
    body = header + bytes(frame.payload)
    if frame.integrity is not None:
        if frame.integrity != 1 or frame.security:
            raise FrameError("unsupported/conflicting integrity mode")
        body += crc32c(body).to_bytes(4, "little")
    elif frame.security:
        if len(frame.trailer) != 16:
            raise FrameError("protected frame requires a 16-byte tag")
        body += frame.trailer
    elif frame.trailer:
        raise FrameError("trailer without integrity/security")
    if len(body) > max_frame:
        raise FrameError("frame exceeds configured bound")
    parse_frame(body, max_frame=max_frame)
    return body
