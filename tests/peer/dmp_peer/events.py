"""Immutable DMP-PEER-TEST/1 event records and validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class EventValidationError(ValueError):
    """Event record is invalid or out of contract."""


def _check_u8(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFF:
        raise EventValidationError(f"{name} must be an unsigned 8-bit integer (0..255)")
    return value


def _check_u32(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise EventValidationError(f"{name} must be an unsigned 32-bit integer (0..2^32-1)")
    return value


def _check_u64(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise EventValidationError(f"{name} must be an unsigned 64-bit integer (0..2^64-1)")
    return value


def _check_opt_u64(value: Any, name: str) -> int | None:
    if value is None:
        return None
    return _check_u64(value, name)


def _check_bytes(value: Any, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise EventValidationError(f"{name} must be bytes-like")
    return bytes(value)


def _check_enum(value: Any, allowed: set[Any], name: str) -> Any:
    if value not in allowed:
        raise EventValidationError(f"{name} must be one of {sorted(repr(x) for x in allowed)}, got {value!r}")
    return value


@dataclass(frozen=True)
class Open:
    link: int
    deadline_capability: str
    at_ms: int

    def __post_init__(self):
        object.__setattr__(self, "link", _check_u8(self.link, "link"))
        object.__setattr__(self, "deadline_capability", _check_enum(
            self.deadline_capability, {"strict_latest_start", "submission_only"}, "deadline_capability"
        ))
        object.__setattr__(self, "at_ms", _check_u64(self.at_ms, "at_ms"))


@dataclass(frozen=True)
class Receive:
    link: int
    bytes: bytes
    at_ms: int

    def __post_init__(self):
        object.__setattr__(self, "link", _check_u8(self.link, "link"))
        object.__setattr__(self, "bytes", _check_bytes(self.bytes, "bytes"))
        object.__setattr__(self, "at_ms", _check_u64(self.at_ms, "at_ms"))


@dataclass(frozen=True)
class Advance:
    now_ms: int

    def __post_init__(self):
        object.__setattr__(self, "now_ms", _check_u64(self.now_ms, "now_ms"))


@dataclass(frozen=True)
class TxSubmit:
    handle: int
    generation: int
    bytes: bytes
    not_after_ms: int | None
    at_ms: int

    def __post_init__(self):
        object.__setattr__(self, "handle", _check_u32(self.handle, "handle"))
        object.__setattr__(self, "generation", _check_u32(self.generation, "generation"))
        object.__setattr__(self, "bytes", _check_bytes(self.bytes, "bytes"))
        object.__setattr__(self, "not_after_ms", _check_opt_u64(self.not_after_ms, "not_after_ms"))
        object.__setattr__(self, "at_ms", _check_u64(self.at_ms, "at_ms"))


@dataclass(frozen=True)
class TxAdmit:
    handle: int
    generation: int
    accepted: bool
    reason: str | None
    at_ms: int

    def __post_init__(self):
        object.__setattr__(self, "handle", _check_u32(self.handle, "handle"))
        object.__setattr__(self, "generation", _check_u32(self.generation, "generation"))
        if not isinstance(self.accepted, bool):
            raise EventValidationError("accepted must be a boolean")
        if self.accepted:
            if self.reason is not None:
                raise EventValidationError("reason must be None when accepted is True")
        else:
            _check_enum(self.reason, {"busy", "expired", "mtu_exceeded", "disconnected", "invalid_argument"}, "reason")
        object.__setattr__(self, "at_ms", _check_u64(self.at_ms, "at_ms"))


@dataclass(frozen=True)
class TxTerminal:
    handle: int
    generation: int
    outcome: str
    at_ms: int

    def __post_init__(self):
        object.__setattr__(self, "handle", _check_u32(self.handle, "handle"))
        object.__setattr__(self, "generation", _check_u32(self.generation, "generation"))
        object.__setattr__(self, "outcome", _check_enum(
            self.outcome,
            {"transmitted", "failed_unsent", "cancelled_unsent", "expired_unsent", "possibly_transmitted"},
            "outcome"
        ))
        object.__setattr__(self, "at_ms", _check_u64(self.at_ms, "at_ms"))


@dataclass(frozen=True)
class Cancel:
    handle: int
    generation: int
    at_ms: int

    def __post_init__(self):
        object.__setattr__(self, "handle", _check_u32(self.handle, "handle"))
        object.__setattr__(self, "generation", _check_u32(self.generation, "generation"))
        object.__setattr__(self, "at_ms", _check_u64(self.at_ms, "at_ms"))


@dataclass(frozen=True)
class Disconnect:
    link: int
    at_ms: int

    def __post_init__(self):
        object.__setattr__(self, "link", _check_u8(self.link, "link"))
        object.__setattr__(self, "at_ms", _check_u64(self.at_ms, "at_ms"))


@dataclass(frozen=True)
class Restart:
    at_ms: int
    entropy: bytes

    def __post_init__(self):
        object.__setattr__(self, "at_ms", _check_u64(self.at_ms, "at_ms"))
        object.__setattr__(self, "entropy", _check_bytes(self.entropy, "entropy"))


@dataclass(frozen=True)
class ApplicationEvent:
    kind: str
    service_id: int
    exchange_id: int
    status: int
    payload: bytes
    at_ms: int

    def __post_init__(self):
        object.__setattr__(self, "kind", _check_enum(
            self.kind,
            {"request_accepted", "request_result", "protocol_rejection", "diagnostic"},
            "kind"
        ))
        object.__setattr__(self, "service_id", _check_u32(self.service_id, "service_id"))
        object.__setattr__(self, "exchange_id", _check_u64(self.exchange_id, "exchange_id"))
        object.__setattr__(self, "status", _check_u32(self.status, "status"))
        object.__setattr__(self, "payload", _check_bytes(self.payload, "payload"))
        object.__setattr__(self, "at_ms", _check_u64(self.at_ms, "at_ms"))


@dataclass(frozen=True)
class ApplicationRequest:
    service_id: int
    payload: bytes
    at_ms: int
    exchange_id: int = 0
    ack_req: bool = True
    not_after_ms: int | None = None

    def __post_init__(self):
        object.__setattr__(self, "service_id", _check_u32(self.service_id, "service_id"))
        object.__setattr__(self, "payload", _check_bytes(self.payload, "payload"))
        object.__setattr__(self, "at_ms", _check_u64(self.at_ms, "at_ms"))
        object.__setattr__(self, "exchange_id", _check_u64(self.exchange_id, "exchange_id"))
        if not isinstance(self.ack_req, bool):
            raise EventValidationError("ack_req must be boolean")
        object.__setattr__(self, "not_after_ms", _check_opt_u64(self.not_after_ms, "not_after_ms"))


@dataclass(frozen=True)
class PublishSample:
    value: int
    at_ms: int

    def __post_init__(self):
        object.__setattr__(self, "value", _check_u32(self.value, "value"))
        object.__setattr__(self, "at_ms", _check_u64(self.at_ms, "at_ms"))
