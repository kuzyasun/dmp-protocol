"""Bounded fixed-stride reassembly engine (DMP spec §11)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


class ReassemblyError(ValueError):
    """Reassembly geometry, conflict, or quota violation."""


class ConflictError(ReassemblyError):
    """Conflicting slice bytes or inconsistent metadata under same identity."""


class QuotaError(ReassemblyError):
    """Active assemblies or tombstone quota exhausted."""


class ReassemblyOutcome(tuple):
    """Result tuple (complete: bool, payload: Optional[bytes]) with already_completed flag."""

    def __new__(cls, complete: bool, payload: Optional[bytes], already_completed: bool = False):
        return super().__new__(cls, (complete, payload))

    @property
    def complete(self) -> bool:
        return self[0]

    @property
    def payload(self) -> Optional[bytes]:
        return self[1]

    @property
    def already_completed(self) -> bool:
        return self._already_completed

    def __init__(self, complete: bool, payload: Optional[bytes], already_completed: bool = False):
        self._already_completed = already_completed


@dataclass
class AssemblySession:
    namespace: int
    origin: int
    epoch: int
    seq: int
    total_length: int
    chunk_size: int
    derived_count: int
    message_type: int
    ack_req: bool
    service_id: int
    immutable_metadata: tuple
    buffer: bytearray
    received_indices: set[int] = field(default_factory=set)
    created_at_ms: int = 0
    expires_at_ms: int = 0

    def is_complete(self) -> bool:
        return len(self.received_indices) == self.derived_count


@dataclass
class CompletedAssemblyRecord:
    namespace: int
    origin: int
    epoch: int
    seq: int
    total_length: int
    chunk_size: int
    derived_count: int
    message_type: int
    ack_req: bool
    service_id: int
    immutable_metadata: tuple
    expires_at_ms: int
    endpoint_accepted: bool = False
    result_ack_replays: int = 0


class ReassemblyManager:
    """Manages active assemblies, quotas, expiry tombstones, and completed transfer records."""

    def __init__(
        self,
        max_message_bytes: int,
        max_fragments: int,
        assemblies_per_peer: int,
        tombstones_per_peer: int,
        assembly_ms: int,
        tombstone_ms: int,
    ):
        self.max_message_bytes = max_message_bytes
        self.max_fragments = max_fragments
        self.assemblies_per_peer = assemblies_per_peer
        self.tombstones_per_peer = tombstones_per_peer
        self.assembly_ms = assembly_ms
        self.tombstone_ms = tombstone_ms

        # Active assemblies keyed by (namespace, origin, epoch, seq)
        self.active: dict[tuple[int, int, int, int], AssemblySession] = {}
        # Tombstones for incomplete expired assemblies keyed by (namespace, origin, epoch, seq) -> expires_at_ms
        self.tombstones: dict[tuple[int, int, int, int], int | None] = {}
        # Completed transfers keyed by (namespace, origin, epoch, seq) -> CompletedAssemblyRecord
        self.completed: dict[tuple[int, int, int, int], CompletedAssemblyRecord] = {}

    def advance(self, now_ms: int) -> list[tuple[int, int, int, int]]:
        """Advance time; expire overdue assemblies and purge old tombstones/completed records."""
        expired_keys = []
        # Check active assemblies for expiry
        for key, session in list(self.active.items()):
            if now_ms >= session.expires_at_ms:
                del self.active[key]
                # Install tombstone for incomplete expired assembly
                self.tombstones[key] = None
                expired_keys.append(key)

        # Check tombstones for purge
        for key, exp in list(self.tombstones.items()):
            if exp is not None and now_ms >= exp:
                del self.tombstones[key]

        # Check completed records for purge
        for key, rec in list(self.completed.items()):
            if now_ms >= rec.expires_at_ms:
                del self.completed[key]
                self.tombstones[key] = None

        return expired_keys

    def retire(self) -> None:
        """Retire live assemblies while reserving their identity tombstones."""
        for key in (*self.active.keys(), *self.completed.keys()):
            self.tombstones[key] = None
        self.active.clear()
        self.completed.clear()

    def validate_geometry(self, fragment_index: int, chunk_size: int, total_length: int) -> int:
        """Validate fixed-stride geometry and return derived fragment count."""
        if not (0 < chunk_size < total_length <= self.max_message_bytes):
            raise ReassemblyError(f"invalid fragment geometry: chunk={chunk_size}, total={total_length}, max={self.max_message_bytes}")
        derived_count = 1 + (total_length - 1) // chunk_size
        if not (2 <= derived_count <= self.max_fragments):
            raise ReassemblyError(f"derived fragment count {derived_count} outside [2, {self.max_fragments}]")
        if fragment_index >= derived_count:
            raise ReassemblyError(f"fragment index {fragment_index} >= count {derived_count}")
        return derived_count

    def process_fragment(
        self,
        *,
        namespace: int,
        origin: int,
        epoch: int,
        seq: int,
        fragment_index: int,
        chunk_size: int,
        total_length: int,
        message_type: int,
        ack_req: bool,
        service_id: int,
        slice_payload: bytes,
        at_ms: int,
        immutable_metadata: tuple = (),
    ) -> ReassemblyOutcome:
        """
        Ingest one fragment.
        Returns ReassemblyOutcome(is_complete, complete_payload_or_None, already_completed).
        Raises ReassemblyError, ConflictError, or QuotaError.
        """
        key = (namespace, origin, epoch, seq)

        # Incomplete expired assembly tombstone: cannot reopen
        if key in self.tombstones:
            raise ReassemblyError(f"message {key} has expired and cannot be reopened (tombstone active)")

        # Check completed assembly dedup record
        if key in self.completed:
            rec = self.completed[key]
            # Validate geometry and slice length
            self.validate_geometry(fragment_index, chunk_size, total_length)
            offset = fragment_index * chunk_size
            expected_len = min(chunk_size, total_length - offset)
            if len(slice_payload) != expected_len:
                raise ReassemblyError(f"slice length {len(slice_payload)} does not match geometry expectation {expected_len}")
            # Validate metadata matching
            if (
                rec.chunk_size != chunk_size
                or rec.total_length != total_length
                or rec.message_type != message_type
                or rec.ack_req != ack_req
                or rec.service_id != service_id
                or rec.immutable_metadata != immutable_metadata
            ):
                raise ConflictError("fragment metadata does not match completed assembly record")
            # Metadata-matching duplicate slice of completed transfer:
            # Does NOT reopen assembly or renew retention deadline
            return ReassemblyOutcome(complete=False, payload=None, already_completed=True)

        derived_count = self.validate_geometry(fragment_index, chunk_size, total_length)

        # Verify slice length
        offset = fragment_index * chunk_size
        expected_len = min(chunk_size, total_length - offset)
        if len(slice_payload) != expected_len:
            raise ReassemblyError(f"slice length {len(slice_payload)} does not match geometry expectation {expected_len}")

        session = self.active.get(key)
        if session is None:
            # Check quotas before admitting first slice
            if len(self.active) >= self.assemblies_per_peer:
                raise QuotaError("active assemblies quota exhausted")
            # Reserve tombstone capacity across active plus tombstoned plus completed transfers:
            # no active-expiry path may exceed the manifest tombstone quota
            if len(self.active) + len(self.tombstones) + len(self.completed) >= self.tombstones_per_peer:
                raise QuotaError("assembly tombstone quota exhausted (reserved across active transfers)")

            session = AssemblySession(
                namespace=namespace,
                origin=origin,
                epoch=epoch,
                seq=seq,
                total_length=total_length,
                chunk_size=chunk_size,
                derived_count=derived_count,
                message_type=message_type,
                ack_req=ack_req,
                service_id=service_id,
                immutable_metadata=immutable_metadata,
                buffer=bytearray(total_length),
                created_at_ms=at_ms,
                expires_at_ms=at_ms + self.assembly_ms,
            )
            self.active[key] = session
        else:
            # Verify consistency across fragments
            if (
                session.chunk_size != chunk_size
                or session.total_length != total_length
                or session.message_type != message_type
                or session.ack_req != ack_req
                or session.service_id != service_id
                or session.immutable_metadata != immutable_metadata
            ):
                raise ConflictError("fragment metadata does not match active assembly session")

        # Check if slice already received
        if fragment_index in session.received_indices:
            # Check for conflict
            existing_slice = bytes(session.buffer[offset : offset + expected_len])
            if existing_slice != slice_payload:
                raise ConflictError(f"conflicting slice bytes for index {fragment_index}")
            # Identical duplicate: ignore, do not refresh timer
            return ReassemblyOutcome(complete=False, payload=None, already_completed=False)

        # New slice: copy into buffer
        session.buffer[offset : offset + expected_len] = slice_payload
        session.received_indices.add(fragment_index)

        if session.is_complete():
            completed_payload = bytes(session.buffer)
            del self.active[key]
            # Retain completed assembly record for deduplication horizon
            self.completed[key] = CompletedAssemblyRecord(
                namespace=namespace,
                origin=origin,
                epoch=epoch,
                seq=seq,
                total_length=total_length,
                chunk_size=chunk_size,
                derived_count=session.derived_count,
                message_type=message_type,
                ack_req=ack_req,
                service_id=service_id,
                immutable_metadata=session.immutable_metadata,
                expires_at_ms=at_ms + self.tombstone_ms,
            )
            return ReassemblyOutcome(complete=True, payload=completed_payload, already_completed=False)

        return ReassemblyOutcome(complete=False, payload=None, already_completed=False)
