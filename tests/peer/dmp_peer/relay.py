"""Bounded transparent protected-frame relay for the independent peer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .frame import FrameError, crc32c, parse_frame
from .manifest import ManifestError, identify_frozen_manifest


class RelayError(ValueError):
    """Malformed, unsupported, or out-of-order relay input."""


@dataclass(frozen=True)
class RelayDecision:
    forwarded: bool
    reason: str
    token: int | None = None
    frame: bytes | None = None
    egress_interface: str | None = None


@dataclass
class _Entry:
    expires_at_ms: int
    origin: int
    immutable_metadata: tuple[Any, ...]
    forwards: int = 0
    last_completion_ms: int | None = None
    pending_token: int | None = None
    pending_cost: int = 0


@dataclass(frozen=True)
class _Parsed:
    key: tuple[int, int, int, int, int | None]
    origin: int
    ttl_offset: int
    ttl: int
    destination: int
    packet_number: int | None
    immutable_metadata: tuple[Any, ...]
    bootstrap: bool = False
    integrity: bool = False


def _uleb(raw: bytes, pos: int, maximum: int = 0xFFFFFFFF) -> tuple[int, int]:
    start = pos
    value = 0
    shift = 0
    while pos < len(raw) and pos - start < 10:
        octet = raw[pos]
        pos += 1
        value |= (octet & 0x7F) << shift
        if not octet & 0x80:
            if value > maximum or raw[start:pos] != _encode_uleb(value):
                raise RelayError("noncanonical or overflowing ULEB")
            return value, pos
        shift += 7
    raise RelayError("truncated or oversized ULEB")


def _encode_uleb(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _parse_protected_route(raw: bytes) -> _Parsed:
    if not isinstance(raw, bytes) or len(raw) < 2:
        raise RelayError("frame must be immutable bytes with a complete header")
    vt, hdr_len = raw[0], raw[1]
    if vt >> 5 != 2 or hdr_len < 3 or hdr_len > len(raw):
        raise RelayError("unsupported version or invalid header length")
    opts = raw[2]
    if opts == 0 or not opts & 0x01 or not opts & 0x04 or not opts & 0x40:
        raise RelayError("relay requires SEQ, ROUTE, and SEC-1 SECURITY")
    if opts & 0x10 or opts & 0x80 == 0:
        raise RelayError("integrity-only or extension-free routed frames are unsupported")
    pos = 3
    seq, pos = _uleb(raw, pos)
    route_control_offset = pos
    route_control = raw[pos]
    pos += 1
    ttl, mode = route_control >> 4, route_control & 0x0F
    if mode != 1:
        raise RelayError("only TO_NODE routing is supported")
    source, pos = _uleb(raw, pos)
    destination, pos = _uleb(raw, pos)
    if opts & 0x08:
        frag_index, pos = _uleb(raw, pos)
        chunk_size, pos = _uleb(raw, pos)
        total_length, pos = _uleb(raw, pos)
        if chunk_size == 0 or total_length == 0 or frag_index >= (total_length + chunk_size - 1) // chunk_size:
            raise RelayError("invalid fragment geometry")
        fragment_marker: int | None = frag_index
        fragment_metadata: tuple[Any, ...] = (chunk_size, total_length)
    else:
        fragment_marker = None
        fragment_metadata = ()
    if opts & 0x20:
        descriptor_start = pos
        flags = raw[pos]
        codec, pos = _uleb(raw, pos + 1)
        schema = version = None
        if flags & 0x01:
            schema, pos = _uleb(raw, pos)
        if flags & 0x02:
            version, pos = _uleb(raw, pos)
        if flags & ~0x03 or (version is not None and schema is None):
            raise RelayError("invalid payload descriptor")
        payload_descriptor = raw[descriptor_start:pos]
    else:
        payload_descriptor = b""
    if not opts & 0x40:
        raise RelayError("unprotected frame")
    if pos >= hdr_len:
        raise RelayError("truncated security descriptor")
    cipher = raw[pos]
    if cipher not in (1, 2):
        raise RelayError("unsupported SEC-1 cipher")
    rx_cid, pos = _uleb(raw, pos + 1)
    packet_number, pos = _uleb(raw, pos, 0xFFFFFFFFFFFFFFFF)
    security_without_pn = (cipher, rx_cid)
    if pos > hdr_len:
        raise RelayError("security descriptor exceeds header")
    context: tuple[int, int] | None = None
    extension_metadata = []
    previous_id = -1
    seen: set[int] = set()
    while pos < hdr_len:
        tag_start = pos
        tag, pos = _uleb(raw, pos)
        ext_id, unsafe, critical = tag >> 2, (tag >> 1) & 1, tag & 1
        length, pos = _uleb(raw, pos)
        value_end = pos + length
        if value_end > hdr_len or ext_id <= previous_id or ext_id in seen:
            raise RelayError("malformed extension sequence")
        value = raw[pos:value_end]
        if unsafe and ext_id not in {1, 2, 3, 4, 5, 6}:
            raise RelayError("unsafe extension cannot be forwarded")
        if ext_id == 2:
            if (critical, unsafe) != (1, 1) or len(value) < 9:
                raise RelayError("invalid CONTEXT extension")
            namespace, end = _uleb(value, 0)
            if end + 8 != len(value):
                raise RelayError("invalid CONTEXT length")
            context = namespace, int.from_bytes(value[end:end + 8], "little")
        elif ext_id in {1, 3, 4, 5, 6}:
            expected_flags = {1: (1, 0), 3: (1, 1), 4: (1, 0), 5: (1, 0), 6: (1, 0)}[ext_id]
            if (critical, unsafe) != expected_flags:
                raise RelayError("known extension has invalid flags")
            if ext_id == 3:
                raise RelayError("ROUTE and ORIGIN_ID cannot coexist")
            if ext_id == 6 and len(value) != 16:
                raise RelayError("invalid FRESHNESS extension")
            if ext_id == 1:
                ref, end = _uleb(value, 0)
                if end != len(value):
                    raise RelayError("protected REPLY_TO must contain one SEQ")
            if ext_id in {4, 5}:
                decoded, end = _uleb(value, 0)
                if end != len(value):
                    raise RelayError("malformed known extension")
        extension_metadata.append(raw[tag_start:value_end])
        previous_id = ext_id
        seen.add(ext_id)
        pos = value_end
    if context is None or pos != hdr_len:
        raise RelayError("routed SEC-1 frame requires explicit CONTEXT")
    if ttl == 0:
        raise RelayError("TTL zero cannot be forwarded")
    if rx_cid == 0:
        raise RelayError("zero receive CID is unsupported")
    trailer_start = hdr_len
    if len(raw) - trailer_start < 16:
        raise RelayError("protected frame is missing its tag")
    if opts & 0x08:
        fragment_count = (total_length + chunk_size - 1) // chunk_size
        expected_slice = chunk_size if frag_index + 1 < fragment_count else total_length - frag_index * chunk_size
        if len(raw) - hdr_len - 16 != expected_slice:
            raise RelayError("fragment ciphertext length does not match geometry")
    # The secure trailer is opaque. It cannot be authenticated by a relay.
    service = None
    for encoded in extension_metadata:
        tag, tpos = _uleb(encoded, 0)
        length, tpos = _uleb(encoded, tpos)
        if tag >> 2 == 4:
            service, end = _uleb(encoded, tpos)
            if end != len(encoded) or length != end - tpos:
                raise RelayError("malformed SERVICE_ID")
    metadata = (
        vt & 0x1F, opts & ~0x04, seq, source, destination, context,
        fragment_marker, fragment_metadata, payload_descriptor,
        security_without_pn, tuple(extension_metadata),
    )
    key = (*context[:1], source, context[1], seq, fragment_marker)
    return _Parsed(key, source, route_control_offset, ttl, destination, packet_number, metadata)


def _parse_bootstrap_route(raw: bytes, *, preauth_bytes: int) -> _Parsed:
    """Validate the routed SEC-1 bootstrap subset without interpreting its payload."""
    try:
        frame = parse_frame(raw, max_frame=256)
    except (FrameError, TypeError, ValueError) as exc:
        raise RelayError("malformed bootstrap frame") from exc
    if (frame.message_type != 3 or frame.security is not None or frame.sequence not in (1, 2, 3)
            or frame.route is None or frame.route.mode != 1 or frame.route.destination_id is None
            or frame.integrity not in (None, 1)):
        raise RelayError("unsupported bootstrap frame")
    if frame.options & (1 | 4 | 0x80) != (1 | 4 | 0x80) or frame.options & (2 | 0x40):
        raise RelayError("bootstrap requires SEQ, ROUTE, EXT and no ACK_REQ or SECURITY")
    if len(frame.extensions) != 1 or frame.extensions[0].extension_id != 2:
        raise RelayError("bootstrap requires only explicit CONTEXT")
    context_extension = frame.extensions[0]
    namespace, at = _uleb(context_extension.value, 0)
    if at + 8 != len(context_extension.value):
        raise RelayError("invalid bootstrap CONTEXT")
    epoch = int.from_bytes(context_extension.value[at:at + 8], "little")
    fragment = frame.fragment
    if fragment is not None:
        count = (fragment.total_length + fragment.chunk_size - 1) // fragment.chunk_size
        if fragment.total_length > preauth_bytes or count > 2:
            raise RelayError("bootstrap fragment budget exceeded")
        fragment_marker: int | None = fragment.index
        fragment_metadata: tuple[Any, ...] = (fragment.chunk_size, fragment.total_length)
    else:
        if len(frame.payload) > preauth_bytes:
            raise RelayError("bootstrap payload exceeds preauthentication cap")
        fragment_marker = None
        fragment_metadata = ()
    sequence = frame.sequence
    source = frame.route.source_id
    destination = frame.route.destination_id
    route_control_offset = 3 + len(_encode_uleb(sequence))
    metadata = (
        frame.message_type, frame.options & ~0x04, sequence, source, destination,
        (namespace, epoch), fragment_marker, fragment_metadata, frame.payload,
        frame.integrity,
    )
    key = (namespace, source, epoch, sequence, fragment_marker)
    return _Parsed(key, source, route_control_offset, frame.route.ttl, destination,
                   None, metadata, bootstrap=True, integrity=frame.integrity is not None)


class TransparentRelay:
    """Provisional forwarding state; never authenticates endpoint traffic."""

    def __init__(self, manifest_bytes: bytes, relay_node: int):
        if isinstance(relay_node, bool) or not isinstance(relay_node, int) or not 0 <= relay_node <= 0xFFFFFFFF:
            raise RelayError("relay_node must be u32")
        try:
            manifest = identify_frozen_manifest(bytes(manifest_bytes))
        except (ManifestError, TypeError) as exc:
            raise RelayError("relay requires exact frozen manifest bytes") from exc
        values = manifest.values
        profile_id = values.get("profile", {}).get("id")
        if profile_id not in {"RADIO-1", "MIXED-TCP-STREAM-R-SIM-PACKET"}:
            raise RelayError("relay requires a frozen RADIO-1 or mixed TCP/packet profile")
        binding = values["binding"]
        if binding.get("topology") != "static-unicast" or binding.get("context") != "origin-explicit":
            raise RelayError("unsupported routing profile")
        relays = [r for r in values.get("relays", []) if r.get("node") == relay_node]
        if len(relays) != 1:
            raise RelayError("relay node must identify exactly one configured relay")
        config = relays[0]
        if config.get("cooldown_anchor") != "last-forward-completion":
            raise RelayError("unsupported cooldown anchor")
        charge = next(
            (item for role in values.get("resources", []) if role.get("role") == "relay"
             for item in role.get("charges", []) if item.get("component") == "relay_cache"),
            None,
        )
        if charge is None or charge.get("count", 0) <= 0:
            raise RelayError("manifest has no bounded relay cache")
        self.node = relay_node
        self.profile_id = profile_id
        self.namespace = values["identity"]["namespace"]
        self.cooldown_ms = config["cooldown_ms"]
        self.expiry_ms = config["expiry_ms"]
        self.max_forwards_per_key = config["max_forwards_per_key"]
        self.frame_tx_ms = config["frame_tx_ms"]
        self.per_origin_airtime_ms = config["per_origin_airtime_ms"]
        self.global_airtime_ms = config["global_airtime_ms"]
        self.cache_slots = charge["count"]
        self.forward_mtu = binding["forward_mtu"]
        self.return_mtu = binding["return_mtu"]
        self.nodes = tuple(values["identity"]["nodes"])
        self.mixed = values.get("mixed_path")
        self.bridge_node = self.mixed["bridge_node"] if self.mixed is not None else None
        self.stream_endpoint = self.mixed["stream_endpoint"] if self.mixed is not None else None
        self.packet_endpoint = self.mixed["packet_endpoint"] if self.mixed is not None else None
        tcp = values.get("tcp_binding", {})
        self.tcp_forward_mtu = tcp.get("forward_mtu", self.forward_mtu)
        self.tcp_return_mtu = tcp.get("return_mtu", self.return_mtu)
        self.public_pn_filter = config["public_pn_filter"]
        self.preauth_bytes = values.get("security", {}).get("preauth_bytes", 120)
        self._entries: dict[tuple[int, int, int, int, int | None], _Entry] = {}
        self._origin_airtime = {origin: 0 for origin in self.nodes}
        self._global_airtime = 0
        self._pending_airtime = {origin: 0 for origin in self.nodes}
        self._pending_global = 0
        self._last_time = -1
        self._next_token = 1

    def receive(self, frame: bytes, at_ms: int, *, airtime_ms: int | None = None,
                ingress_interface: str = "packet") -> RelayDecision:
        if isinstance(at_ms, bool) or not isinstance(at_ms, int) or not 0 <= at_ms <= 0xFFFFFFFFFFFFFFFF:
            raise RelayError("at_ms must be u64")
        if at_ms < self._last_time:
            raise RelayError("relay time cannot move backwards")
        maximum_core = max(self.forward_mtu, self.return_mtu,
                           self.tcp_forward_mtu, self.tcp_return_mtu)
        if not isinstance(frame, bytes) or len(frame) > maximum_core:
            return RelayDecision(False, "mtu-exceeded")
        try:
            if not isinstance(frame, bytes) or len(frame) < 3:
                raise RelayError("frame must be immutable bytes with a complete header")
            if frame[2] & 0x40:
                parsed = _parse_protected_route(frame)
            else:
                parsed = _parse_bootstrap_route(frame, preauth_bytes=self.preauth_bytes)
        except (IndexError, OverflowError) as exc:
            raise RelayError("truncated or overflowing frame structure") from exc
        self._last_time = at_ms
        if parsed.origin not in self.nodes or parsed.key[0] <= 0 or parsed.destination not in self.nodes:
            return RelayDecision(False, "unsupported-origin")
        if parsed.key[0] != self.namespace:
            return RelayDecision(False, "context-mismatch")
        if parsed.destination == parsed.origin:
            return RelayDecision(False, "unsupported-route")
        if parsed.destination == self.node:
            return RelayDecision(False, "local-destination")
        egress_interface = None
        ingress_valid = True
        if self.mixed is not None:
            if parsed.destination != (self.packet_endpoint if parsed.origin == self.stream_endpoint
                                      else self.stream_endpoint):
                return RelayDecision(False, "unsupported-route")
            expected_ingress = "packet"
            egress_interface = "packet"
            if self.node == self.bridge_node:
                if parsed.origin == self.stream_endpoint:
                    expected_ingress, egress_interface = "tcp", "packet"
                else:
                    expected_ingress, egress_interface = "packet", "tcp"
            ingress_valid = ingress_interface == expected_ingress
        if (self.public_pn_filter == "reject-ge-2pow24" and parsed.packet_number is not None
                and parsed.packet_number >= (1 << 24)):
            return RelayDecision(False, "packet-number-limit")
        cost = self.frame_tx_ms if airtime_ms is None else airtime_ms
        if (isinstance(cost, bool) or not isinstance(cost, int)
                or not self.frame_tx_ms <= cost <= 0xFFFFFFFFFFFFFFFF):
            raise RelayError("airtime reservation must cover frame_tx_ms")
        egress_mtu = self.forward_mtu if parsed.origin == self.nodes[0] else self.return_mtu
        if egress_interface == "tcp":
            egress_mtu = (self.tcp_forward_mtu if parsed.origin == self.nodes[0]
                          else self.tcp_return_mtu)
        if len(frame) > egress_mtu:
            return RelayDecision(False, "mtu-exceeded")
        key = parsed.key
        entry = self._entries.get(key)
        if entry is not None and at_ms >= entry.expires_at_ms and entry.pending_token is None:
            del self._entries[key]
            return RelayDecision(False, "expired")
        if entry is not None and at_ms >= entry.expires_at_ms:
            return RelayDecision(False, "expired")
        self._prune(at_ms)
        base_key = key[:4]
        if any(
            other_key[:4] == base_key
            and other_key[4] != key[4]
            and (other_key[4] is None or key[4] is None)
            for other_key in self._entries
        ):
            return RelayDecision(False, "identity-conflict")
        if entry is not None and parsed.immutable_metadata != entry.immutable_metadata:
            return RelayDecision(False, "identity-conflict")
        if entry is not None and entry.pending_token is not None:
            return RelayDecision(False, "forward-pending")
        if entry is not None and entry.last_completion_ms is not None and at_ms < entry.last_completion_ms + self.cooldown_ms:
            return RelayDecision(False, "cooldown")
        if entry is not None and entry.forwards >= self.max_forwards_per_key:
            return RelayDecision(False, "forward-limit")
        if not ingress_valid:
            return RelayDecision(False, "wrong-ingress")
        expires_at = entry.expires_at_ms if entry is not None else at_ms + self.expiry_ms
        if at_ms + cost >= expires_at:
            return RelayDecision(False, "expired")
        if self._global_airtime + self._pending_global + cost > self.global_airtime_ms:
            return RelayDecision(False, "global-airtime-limit")
        if self._origin_airtime[parsed.origin] + self._pending_airtime[parsed.origin] + cost > self.per_origin_airtime_ms:
            return RelayDecision(False, "origin-airtime-limit")
        if entry is None:
            self._prune(at_ms)
            if len(self._entries) >= self.cache_slots:
                return RelayDecision(False, "cache-full")
            entry = _Entry(at_ms + self.expiry_ms, parsed.origin, parsed.immutable_metadata)
            self._entries[key] = entry
        forwarded = bytearray(frame)
        forwarded[parsed.ttl_offset] = ((parsed.ttl - 1) << 4) | (forwarded[parsed.ttl_offset] & 0x0F)
        if parsed.integrity:
            forwarded[-4:] = crc32c(bytes(forwarded[:-4])).to_bytes(4, "little")
        token = self._next_token
        self._next_token += 1
        entry.pending_token = token
        entry.pending_cost = cost
        self._pending_airtime[entry.origin] += cost
        self._pending_global += cost
        return RelayDecision(True, "forward", token, bytes(forwarded), egress_interface)

    def complete(self, token: int, at_ms: int, *, transmitted: bool) -> None:
        if isinstance(token, bool) or not isinstance(token, int) or token <= 0:
            raise RelayError("token must be a positive integer")
        if (isinstance(at_ms, bool) or not isinstance(at_ms, int)
                or not 0 <= at_ms <= 0xFFFFFFFFFFFFFFFF or at_ms < self._last_time):
            raise RelayError("completion time must be monotonic")
        if not isinstance(transmitted, bool):
            raise RelayError("transmitted must be bool")
        self._last_time = at_ms
        found = next(((key, entry) for key, entry in self._entries.items()
                      if entry.pending_token == token), None)
        if found is None:
            raise RelayError("unknown or already settled forward token")
        key, entry = found
        # Every reservation has frame_tx_ms unless an explicit larger reservation
        # was used; retain the exact amount alongside the pending token.
        pending_cost = entry.pending_cost
        entry.pending_token = None
        entry.pending_cost = 0
        self._pending_airtime[entry.origin] -= pending_cost
        self._pending_global -= pending_cost
        if transmitted:
            entry.forwards += 1
            entry.last_completion_ms = at_ms
            self._origin_airtime[entry.origin] += pending_cost
            self._global_airtime += pending_cost
            if at_ms >= entry.expires_at_ms:
                self._entries.pop(key, None)
        elif at_ms >= entry.expires_at_ms:
            self._entries.pop(key, None)
        if not transmitted and entry.forwards == 0:
            self._entries.pop(key, None)

    def _prune(self, now_ms: int) -> None:
        for key, entry in tuple(self._entries.items()):
            if entry.pending_token is None and now_ms >= entry.expires_at_ms:
                del self._entries[key]
