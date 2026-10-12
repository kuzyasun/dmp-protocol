"""Bounded simulator for the frozen mixed Stream R/TCP to SIM-PACKET path."""

from __future__ import annotations

from dataclasses import dataclass

from .frame import FrameError, parse_frame
from .manifest import ManifestError, identify_frozen_manifest
from .relay import RelayError, TransparentRelay
from .stream_r import StreamRDecoder, encode_stream_r, initial_sync_delimiter


MAX_CORE = 256
MAX_ENCODED = 263
MAX_STREAM_CHUNK = 65_536
MAX_PENDING_TRANSITS = 6


class MixedPathError(ValueError):
    """The frozen mixed path rejected an input or relay transition."""


@dataclass(frozen=True)
class MixedPathEvent:
    kind: str
    interface: str
    at_ms: int
    frame: bytes | None = None
    reason: str | None = None


@dataclass(frozen=True)
class _PendingTransit:
    source: int
    frame: bytes
    route_start_ms: int
    completion_ms: int
    ordinal: int


class MixedPathRouter:
    """Translate framing at the bridge while sharing each relay's bounded state.

    The TCP side carries Stream R envelopes. The packet side carries DMP core
    frames. Returned events expose only the frame for the machine-facing test
    API; callers remain responsible for endpoint events and socket completion.
    """

    def __init__(self, manifest_bytes: bytes):
        try:
            manifest = identify_frozen_manifest(bytes(manifest_bytes))
        except (ManifestError, TypeError) as exc:
            raise MixedPathError("router requires exact frozen manifest bytes") from exc
        values = manifest.values
        if values.get("profile", {}).get("id") != "MIXED-TCP-STREAM-R-SIM-PACKET":
            raise MixedPathError("router requires the frozen mixed TCP/packet profile")
        self.manifest = manifest
        self.path = values["mixed_path"]
        self.tcp = values["tcp_binding"]
        self.binding = values["binding"]
        self.relays = {
            relay["node"]: TransparentRelay(manifest_bytes, relay["node"])
            for relay in values["relays"]
        }
        self._tcp_decoder = StreamRDecoder(
            max_encoded=self.tcp["encoded_mtu"],
            max_core=self.tcp["forward_mtu"],
            candidate_timeout_ms=self.tcp["partial_candidate_timeout_ms"],
            await_sync=True,
        )
        self._tcp_ready = False
        self._last_ms = -1
        self._forward_configs = {relay["node"]: relay for relay in values["relays"]}
        binding = values["binding"]
        self._period_ms = binding["return_slot_period_ms"]
        self._return_width_ms = binding["return_slot_width_ms"]
        self._traversal_ms = binding["frame_tx_ms"] + max(
            values["timing"]["forward_delay_ms"], values["timing"]["return_delay_ms"]
        )
        self._queue_ms = values["timing"]["queue_ms"]
        if (self._return_width_ms < 2 * self._traversal_ms
                or self._period_ms - self._return_width_ms < self._traversal_ms):
            raise MixedPathError("manifest pair schedule cannot reserve its traversals")
        self._control_offsets = (
            self._period_ms - self._return_width_ms,
            self._period_ms - self._return_width_ms + self._traversal_ms,
        )
        self._data_slots: set[int] = set()
        self._data_directions: dict[int, str] = {}
        self._control_slots: dict[int, set[int]] = {}
        self._control_directions: dict[tuple[int, int], str] = {}
        self._pending: list[_PendingTransit] = []
        self._next_ordinal = 0

    def start_tcp(self, receiver_ready) -> bytes:
        """Run readiness before returning the one startup delimiter to send."""
        if not callable(receiver_ready):
            raise TypeError("receiver_ready must be callable")
        if self._tcp_ready:
            raise MixedPathError("TCP side is already started")
        receiver_ready()
        self._tcp_ready = True
        return initial_sync_delimiter()

    def feed_tcp(self, data: bytes, *, at_ms: int,
                 not_after_ms: int | None = None) -> tuple[MixedPathEvent, ...]:
        """Decode arbitrary TCP chunks and forward complete Stream R frames."""
        now = self._time(at_ms)
        if not self._tcp_ready:
            raise MixedPathError("TCP receiver is not ready")
        if not isinstance(data, bytes):
            raise TypeError("TCP input must be bytes")
        if len(data) > MAX_STREAM_CHUNK:
            raise MixedPathError("TCP read chunk exceeds its input bound")
        events = list(self._drain_due(now))
        for stream_event in self._tcp_decoder.feed(data, at_ms=now):
            if stream_event.kind == "frame":
                try:
                    self._schedule_transit(
                        stream_event.frame, source=self.path["stream_endpoint"], at_ms=now,
                        not_after_ms=not_after_ms,
                    )
                except (RelayError, MixedPathError) as exc:
                    events.append(MixedPathEvent("rejected", "tcp", now, reason=str(exc)))
            elif stream_event.kind == "discarded":
                events.append(MixedPathEvent("discarded", "tcp", now, reason=stream_event.reason))
        events.extend(self._drain_due(now))
        return tuple(events)

    def feed_packet(self, core_frame: bytes, *, at_ms: int,
                    not_after_ms: int | None = None) -> tuple[MixedPathEvent, ...]:
        """Queue one packet-endpoint frame and drain only work due by ``at_ms``."""
        now = self._time(at_ms)
        if not isinstance(core_frame, bytes):
            raise TypeError("packet input must be bytes")
        events = list(self._drain_due(now))
        try:
            self._schedule_transit(
                core_frame, source=self.path["packet_endpoint"], at_ms=now,
                not_after_ms=not_after_ms,
            )
        except (RelayError, MixedPathError, ValueError) as exc:
            events.append(MixedPathEvent("rejected", "packet", now, reason=str(exc)))
        events.extend(self._drain_due(now))
        return tuple(events)

    def advance(self, at_ms: int) -> tuple[MixedPathEvent, ...]:
        """Advance simulator time and deterministically emit completed transits."""
        now = self._time(at_ms)
        return self._drain_due(now)

    def _time(self, at_ms: int) -> int:
        if isinstance(at_ms, bool) or not isinstance(at_ms, int) or not 0 <= at_ms <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("time must be an unsigned 64-bit millisecond value")
        if at_ms < self._last_ms:
            raise ValueError("mixed-path time cannot move backwards")
        self._last_ms = at_ms
        current_period = (at_ms // self._period_ms) * self._period_ms
        # Keep only the immediately previous and current/future period state.
        # This bounds scheduler bookkeeping independently of simulator lifetime.
        oldest = current_period - self._period_ms
        self._data_slots = {slot for slot in self._data_slots if slot >= oldest}
        self._data_directions = {
            slot: direction for slot, direction in self._data_directions.items()
            if slot >= oldest
        }
        self._control_slots = {
            start: used for start, used in self._control_slots.items()
            if start >= oldest
        }
        self._control_directions = {
            key: direction for key, direction in self._control_directions.items()
            if key[0] >= oldest
        }
        return at_ms

    def _schedule_transit(self, frame: bytes | None, *, source: int, at_ms: int,
                          not_after_ms: int | None = None) -> None:
        if not isinstance(frame, bytes):
            raise MixedPathError("decoded frame is missing")
        if source == self.path["stream_endpoint"]:
            relay_order = self.path["forward_relays"]
            direction = "forward"
            ingress = "tcp"
        elif source == self.path["packet_endpoint"]:
            relay_order = self.path["return_relays"]
            direction = "return"
            ingress = "packet"
        else:
            raise MixedPathError("source is not a configured endpoint")

        core_cap = min(
            self.tcp["forward_mtu"], self.binding["forward_mtu"]
        ) if source == self.path["stream_endpoint"] else min(
            self.binding["return_mtu"], self.tcp["return_mtu"]
        )
        if len(frame) > core_cap:
            raise MixedPathError("frame exceeds mixed-path core MTU")

        try:
            parsed = parse_frame(frame, max_frame=core_cap)
        except FrameError as exc:
            raise MixedPathError("frame cannot be assigned a reserved slot") from exc
        is_control = parsed.message_type in (6, 8)  # ACK / FRAG_STATUS
        if len(self._pending) >= MAX_PENDING_TRANSITS:
            raise MixedPathError("mixed-path transit queue is full")
        route_start = self._reserve_slot(
            direction, at_ms, is_control=is_control, not_after_ms=not_after_ms
        )
        completion_ms = route_start
        for relay_node in relay_order:
            config = self._forward_configs[relay_node]
            completion_ms = max(
                completion_ms,
                route_start + config[f"{direction}_arrival_min_ms"] + config["frame_tx_ms"],
            )
        self._pending.append(_PendingTransit(
            source=source,
            frame=frame,
            route_start_ms=route_start,
            completion_ms=completion_ms,
            ordinal=self._next_ordinal,
        ))
        self._next_ordinal += 1

    def _drain_due(self, now: int) -> tuple[MixedPathEvent, ...]:
        due = sorted(
            (item for item in self._pending if item.completion_ms <= now),
            key=lambda item: (item.route_start_ms, item.ordinal),
        )
        if not due:
            return ()
        due_ordinals = {item.ordinal for item in due}
        self._pending = [item for item in self._pending if item.ordinal not in due_ordinals]
        events: list[MixedPathEvent] = []
        for item in due:
            try:
                frame, delivered_at = self._run_transit(item)
                if item.source == self.path["stream_endpoint"]:
                    events.append(MixedPathEvent("packet_frame", "packet", delivered_at, frame))
                else:
                    wire = encode_stream_r(
                        frame,
                        max_core=self.tcp["return_mtu"],
                        max_encoded=self.tcp["encoded_mtu"],
                    )
                    events.append(MixedPathEvent("tcp_stream", "tcp", delivered_at, wire))
            except (RelayError, MixedPathError, ValueError) as exc:
                interface = "tcp" if item.source == self.path["stream_endpoint"] else "packet"
                events.append(MixedPathEvent("rejected", interface, now, reason=str(exc)))
        return tuple(events)

    def _run_transit(self, item: _PendingTransit) -> tuple[bytes, int]:
        source = item.source
        if source == self.path["stream_endpoint"]:
            relay_order = self.path["forward_relays"]
            direction = "forward"
            ingress = "tcp"
        else:
            relay_order = self.path["return_relays"]
            direction = "return"
            ingress = "packet"
        current = item.frame
        delivered_at = item.route_start_ms
        for relay_node in relay_order:
            config = self._forward_configs[relay_node]
            arrival = item.route_start_ms + config[f"{direction}_arrival_min_ms"]
            relay = self.relays[relay_node]
            decision = relay.receive(current, arrival, ingress_interface=ingress)
            if not decision.forwarded or decision.frame is None or decision.token is None:
                raise MixedPathError(decision.reason)
            completion = arrival + config["frame_tx_ms"]
            relay.complete(decision.token, completion, transmitted=True)
            current = decision.frame
            ingress = "packet"
            delivered_at = completion
        return current, delivered_at

    def _reserve_slot(self, direction: str, at_ms: int, *, is_control: bool,
                      not_after_ms: int | None) -> int:
        """Reserve one finite pair-wide source or reverse-control opportunity.

        Source traffic (including HELLO/bootstrap and both services) can start
        only on a period boundary. Each period also reserves two reverse control
        starts, one complete traversal apart. The one-period queue bound limits
        how far an input can wait; an optional deadline is strict latest-start.
        """
        if (not_after_ms is not None and
                (isinstance(not_after_ms, bool) or not isinstance(not_after_ms, int)
                 or not 0 <= not_after_ms <= 0xFFFFFFFFFFFFFFFF)):
            raise MixedPathError("invalid latest-start deadline")
        if not_after_ms is not None and at_ms >= not_after_ms:
            raise MixedPathError("latest-start deadline expired")

        if not is_control:
            slot = ((at_ms + self._period_ms - 1) // self._period_ms) * self._period_ms
            while (slot in self._data_slots or any(
                    control_direction != ("return" if direction == "forward" else "forward")
                    for (period, _), control_direction in self._control_directions.items()
                    if period == slot)):
                slot += self._period_ms
            if slot - at_ms > self._queue_ms:
                raise MixedPathError("pair schedule queue is full")
            if not_after_ms is not None and slot >= not_after_ms:
                raise MixedPathError("latest-start deadline leaves no source slot")
            self._data_slots.add(slot)
            self._data_directions[slot] = direction
            return slot

        period_start = (at_ms // self._period_ms) * self._period_ms
        eligible_reservation = False
        source_incomplete = False
        # Consider the current and next superframe only: a later opportunity
        # would exceed the manifest's one-period alignment queue bound.
        for start in (period_start, period_start + self._period_ms):
            if start not in self._data_slots:
                continue
            eligible_reservation = True
            if at_ms < start + self._traversal_ms:
                source_incomplete = True
                continue
            source_direction = self._data_directions[start]
            expected_direction = "return" if source_direction == "forward" else "forward"
            if direction != expected_direction:
                continue
            used = self._control_slots.setdefault(start, set())
            for index, offset in enumerate(self._control_offsets):
                slot = start + offset
                if slot < at_ms or index in used:
                    continue
                if slot - at_ms > self._queue_ms:
                    continue
                if not_after_ms is not None and slot >= not_after_ms:
                    continue
                used.add(index)
                self._control_directions[(start, index)] = direction
                return slot
        if not_after_ms is not None:
            raise MixedPathError("latest-start deadline leaves no reverse-control slot")
        if source_incomplete:
            raise MixedPathError("source traversal has not completed for reverse control")
        if not eligible_reservation:
            raise MixedPathError("no reverse-control reservation in the current superframe")
        raise MixedPathError("reserved reverse-control opportunities are full")
