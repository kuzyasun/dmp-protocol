"""Reliable request/result exchange, deduplication, and stop-and-wait gate (DMP spec §8, §8.1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class OutgoingExchange:
    exchange_id: int
    service_id: int
    destination: int
    seq: int
    namespace: int
    origin: int
    epoch: int
    frames: tuple[bytes, ...]
    ack_req: bool
    not_after_ms: Optional[int]
    created_at_ms: int
    response_timeout_ms: int
    result_deadline_ms: int
    max_attempts: int
    request_payload: bytes = b""
    freshness_token: bytes | None = None
    attempts_used: int = 1
    next_retry_ms: int = 0
    received_ack: bool = False
    state: str = "awaiting_receipt"  # awaiting_receipt, awaiting_result, completed, expired, failed
    possibly_transmitted: bool = False
    schedule_admitted: bool = False
    pending_schedule_handles: set[int] = field(default_factory=set)
    admitted_schedule_handles: set[int] = field(default_factory=set)
    active_submission_handles: list[int] = field(default_factory=list)
    queued_schedule_frames: int = 0

    @property
    def frame_bytes(self) -> bytes:
        return self.frames[0] if self.frames else b""


@dataclass
class RetainedResult:
    service_id: int
    req_namespace: int
    req_origin: int
    req_epoch: int
    req_seq: int
    result_seq: int
    result_frame_bytes: bytes = b""
    result_frames: tuple[bytes, ...] = field(default_factory=tuple)
    is_app_err: bool = False
    status: int = 0
    created_at_ms: int = 0
    expires_at_ms: int = 0
    result_namespace: int = 1
    result_origin: int = 0
    result_epoch: int = 0
    acknowledged: bool = False
    attempts_left: int = 3
    next_retry_ms: int = 0
    bursts_sent: int = 1
    gate_destination: Optional[int] = None
    immutable_metadata: tuple = ()
    result_payload: bytes | None = None

    def __post_init__(self):
        if not self.result_frames and self.result_frame_bytes:
            self.result_frames = (self.result_frame_bytes,)
        elif self.result_frames and not self.result_frame_bytes:
            self.result_frame_bytes = self.result_frames[0]


@dataclass
class AcceptedRecord:
    message_type: int
    service_id: int
    ack_seq: int
    ack_frame_bytes: bytes
    created_at_ms: int
    expires_at_ms: int
    payload: bytes = b""
    replay_bursts: int = 0
    immutable_metadata: tuple = ()


@dataclass
class RejectionRecord:
    status: int
    service_id: int
    err_frame_bytes: bytes
    created_at_ms: int
    expires_at_ms: int
    replay_bursts: int = 0
    payload: bytes = b""
    immutable_metadata: tuple = ()
    err_seq: int = 0


@dataclass
class CallerTombstone:
    expires_at_ms: int
    responder: int
    service_id: int
    request_payload: bytes
    result_ack_seq: int | None = None


class EnqueueResult:
    """Result of enqueue_outgoing: truthy only when admitted immediately."""

    def __init__(self, status: str):
        self.status = status  # "admitted", "queued", "queue_full"

    def __bool__(self) -> bool:
        return self.status == "admitted"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, bool):
            return bool(self) == other
        if isinstance(other, str):
            return self.status == other
        return False

    def __repr__(self) -> str:
        return f"EnqueueResult({self.status!r})"


class DeliveryManager:
    """Tracks stop-and-wait, retransmissions, result cache, deduplication, and tombstones."""

    def __init__(
        self,
        *,
        response_timeout_ms: int,
        receipt_delay_ms: int,
        result_deadline_ms: int,
        result_cache_ms: int,
        dedup_ms: int,
        rejection_ms: int,
        correlation_ms: int,
        max_bursts: int,
        app_queue_slots: int,
        sender_slots: int | None = None,
        result_slots: int | None = None,
        history_slots: int | None = None,
        correlation_slots: int | None = None,
    ):
        self.response_timeout_ms = response_timeout_ms
        self.receipt_delay_ms = receipt_delay_ms
        self.result_deadline_ms = result_deadline_ms
        self.result_cache_ms = result_cache_ms
        self.dedup_ms = dedup_ms
        self.rejection_ms = rejection_ms
        self.correlation_ms = correlation_ms
        self.max_bursts = max_bursts
        self.app_queue_slots = app_queue_slots
        self.sender_slots = sender_slots
        self.result_slots = result_slots
        self.history_slots = history_slots
        self.correlation_slots = correlation_slots

        # Active outgoing exchanges: exchange_id -> OutgoingExchange
        self.active_outgoing: dict[int, OutgoingExchange] = {}
        # Stop-and-wait active exchange per (destination, service_id)
        self.active_per_dest_service: dict[tuple[int, int], int] = {}
        self.result_gates: dict[tuple[int, int], tuple[int, int, int, int]] = {}
        # Queued outgoing requests: list of OutgoingExchange
        self.queue: list[OutgoingExchange] = []

        # Retained results for responder: (req_namespace, req_origin, req_epoch, req_seq) -> RetainedResult
        self.retained_results: dict[tuple[int, int, int, int], RetainedResult] = {}

        # Accepted messages deduplication cache: (namespace, origin, epoch, seq) -> AcceptedRecord
        self.accepted_messages: dict[tuple[int, int, int, int], AcceptedRecord] = {}

        # Retained pre-acceptance protocol rejections: (namespace, origin, epoch, seq) -> RejectionRecord
        self.rejections: dict[tuple[int, int, int, int], RejectionRecord] = {}

        # Caller correlation tombstones: (namespace, origin, epoch, seq) -> expires_at_ms
        self.caller_tombstones: dict[tuple[int, int, int, int], CallerTombstone] = {}

    def advance(self, now_ms: int) -> tuple[list[OutgoingExchange], list[RetainedResult], list[OutgoingExchange]]:
        """
        Advance timers.
        Returns:
          - due_request_retries: exchanges that need retransmission
          - due_result_retries: retained results that need retransmission
          - expired_exchanges: OutgoingExchange objects that reached their result deadline or send deadline
        """
        due_reqs: list[OutgoingExchange] = []
        due_results: list[RetainedResult] = []
        expired_excs: list[OutgoingExchange] = []

        # Advance active outgoing exchanges
        for exc_id, exc in list(self.active_outgoing.items()):
            # Check send deadline (not_after_ms): do not expire while admitted slices remain in schedule
            if exc.not_after_ms is not None and now_ms >= exc.not_after_ms:
                exc.state = "expired"
                del self.active_outgoing[exc_id]
                self._release_gate(exc)
                expired_excs.append(exc)
                continue

            # Check overall result deadline
            if now_ms >= exc.created_at_ms + exc.result_deadline_ms:
                exc.state = "failed"
                del self.active_outgoing[exc_id]
                self._release_gate(exc)
                expired_excs.append(exc)
                continue

            # Start response/result timing only after the full bounded initial fragment schedule reaches adapter boundary
            if not exc.schedule_admitted or exc.pending_schedule_handles or exc.queued_schedule_frames:
                continue

            # Check response timeout for unacknowledged request
            if not exc.received_ack and exc.state == "awaiting_receipt":
                if now_ms >= exc.next_retry_ms:
                    if exc.attempts_used < exc.max_attempts:
                        exc.attempts_used += 1
                        exc.next_retry_ms = now_ms + exc.response_timeout_ms
                        due_reqs.append(exc)
                    else:
                        # Attempt limit reached without receipt
                        exc.state = "failed"
                        del self.active_outgoing[exc_id]
                        self._release_gate(exc)
                        expired_excs.append(exc)

        # Advance retained results
        for key, res in list(self.retained_results.items()):
            if now_ms >= res.expires_at_ms:
                del self.retained_results[key]
                self.release_result_gate(key)
                continue
            if not res.acknowledged and res.attempts_left > 0 and now_ms >= res.next_retry_ms:
                res.attempts_left -= 1
                res.bursts_sent += 1
                res.next_retry_ms = now_ms + self.response_timeout_ms
                due_results.append(res)

        # Expire accepted messages cache
        for key, rec in list(self.accepted_messages.items()):
            if now_ms >= rec.expires_at_ms:
                del self.accepted_messages[key]

        # Expire rejection records
        for key, rej in list(self.rejections.items()):
            if now_ms >= rej.expires_at_ms:
                del self.rejections[key]

        # Expire caller tombstones
        for key, tombstone in list(self.caller_tombstones.items()):
            if now_ms >= tombstone.expires_at_ms:
                del self.caller_tombstones[key]

        return due_reqs, due_results, expired_excs

    def _release_gate(self, exc: OutgoingExchange) -> None:
        key = (exc.destination, exc.service_id)
        if self.active_per_dest_service.get(key) == exc.exchange_id:
            del self.active_per_dest_service[key]
            # Record in caller tombstones
            tombstone_key = (exc.namespace, exc.origin, exc.epoch, exc.seq)
            self.caller_tombstones[tombstone_key] = CallerTombstone(
                expires_at_ms=exc.created_at_ms + self.correlation_ms,
                responder=exc.destination,
                service_id=exc.service_id,
                request_payload=exc.request_payload,
            )

    def can_admit_outgoing(self, destination: int, service_id: int) -> bool:
        """Check stop-and-wait gate and queue capacity."""
        gate_key = (destination, service_id)
        if gate_key not in self.active_per_dest_service and gate_key not in self.result_gates:
            return True
        return len(self.queue) < self.app_queue_slots

    def enqueue_outgoing(self, exc: OutgoingExchange) -> EnqueueResult:
        """Admit or queue an outgoing exchange, or reject on queue full."""
        gate_key = (exc.destination, exc.service_id)
        if self.correlation_slots is not None and len(self.caller_tombstones) + len(self.active_outgoing) + len(self.queue) >= self.correlation_slots:
            return EnqueueResult("queue_full")
        if gate_key not in self.active_per_dest_service and gate_key not in self.result_gates:
            if self.sender_slots is not None and len(self.active_outgoing) + len(self.queue) >= self.sender_slots:
                return EnqueueResult("queue_full")
            self.active_per_dest_service[gate_key] = exc.exchange_id
            self.active_outgoing[exc.exchange_id] = exc
            return EnqueueResult("admitted")
        if len(self.queue) >= self.app_queue_slots or (self.sender_slots is not None and len(self.active_outgoing) + len(self.queue) >= self.sender_slots):
            return EnqueueResult("queue_full")
        self.queue.append(exc)
        return EnqueueResult("queued")

    def pop_next_admissible(self) -> Optional[OutgoingExchange]:
        """Check queue for next exchange whose gate is now open."""
        for i, exc in enumerate(self.queue):
            gate_key = (exc.destination, exc.service_id)
            if gate_key not in self.active_per_dest_service and gate_key not in self.result_gates:
                self.queue.pop(i)
                self.active_per_dest_service[gate_key] = exc.exchange_id
                self.active_outgoing[exc.exchange_id] = exc
                return exc
        return None

    def reserve_result_gate(self, destination: int, service_id: int, request_key: tuple[int, int, int, int]) -> bool:
        key = (destination, service_id)
        if key in self.result_gates or key in self.active_per_dest_service:
            return False
        self.result_gates[key] = request_key
        return True

    def release_result_gate(self, request_key: tuple[int, int, int, int]) -> None:
        for gate, owner in list(self.result_gates.items()):
            if owner == request_key:
                del self.result_gates[gate]

    def admit_result_replay(self, result: RetainedResult, now_ms: int) -> bool:
        if result.acknowledged or result.attempts_left <= 0 or now_ms >= result.expires_at_ms:
            return False
        result.attempts_left -= 1
        result.bursts_sent += 1
        result.next_retry_ms = now_ms + self.response_timeout_ms
        return True

    def admit_rejection_replay(self, rejection: RejectionRecord) -> bool:
        if rejection.replay_bursts >= self.max_bursts - 1:
            return False
        rejection.replay_bursts += 1
        return True

    def admit_history(self) -> bool:
        return self.history_slots is None or len(self.accepted_messages) + len(self.rejections) < self.history_slots

    def admit_result(self, request_key: tuple[int, int, int, int]) -> bool:
        return request_key in self.retained_results or self.result_slots is None or len(self.retained_results) < self.result_slots

    def record_ack_received(
        self,
        namespace: int,
        origin: int,
        epoch: int,
        seq: int,
        *,
        responder: Optional[int] = None,
        service_id: Optional[int] = None,
    ) -> Optional[OutgoingExchange]:
        """Match incoming ACK REPLY_TO against active outgoing requests with responder/service validation."""
        for exc in self.active_outgoing.values():
            if (exc.namespace, exc.origin, exc.epoch, exc.seq) == (namespace, origin, epoch, seq):
                if responder is not None and exc.destination != responder:
                    return None
                if service_id is not None and exc.service_id != service_id:
                    return None
                exc.received_ack = True
                if exc.state == "awaiting_receipt":
                    exc.state = "awaiting_result"
                return exc
        return None

    def record_result_ack_received(
        self,
        namespace_or_result_seq: int,
        origin: Optional[int] = None,
        epoch: Optional[int] = None,
        seq: Optional[int] = None,
        *,
        responder: Optional[int] = None,
        service_id: Optional[int] = None,
    ) -> Optional[RetainedResult]:
        """Match incoming ACK REPLY_TO against retained results with full result identity, requester and service validation."""
        for res in self.retained_results.values():
            if origin is not None and epoch is not None and seq is not None:
                # Full result identity matching: (result_namespace, result_origin, result_epoch, result_seq)
                if not (
                    res.result_namespace == namespace_or_result_seq
                    and res.result_origin == origin
                    and res.result_epoch == epoch
                    and res.result_seq == seq
                ):
                    continue
            else:
                # Sequence-only fallback
                if res.result_seq != namespace_or_result_seq:
                    continue
            if responder is not None and res.req_origin != responder:
                continue
            if service_id is not None and res.service_id != service_id:
                continue
            res.acknowledged = True
            self.release_result_gate((res.req_namespace, res.req_origin, res.req_epoch, res.req_seq))
            return res
        return None

    def match_request_for_result(
        self,
        namespace: int,
        origin: int,
        epoch: int,
        seq: int,
        *,
        responder: Optional[int] = None,
        service_id: Optional[int] = None,
    ) -> Optional[OutgoingExchange]:
        """Find active outgoing request matching incoming result REPLY_TO with responder/service validation."""
        for exc in self.active_outgoing.values():
            if (exc.namespace, exc.origin, exc.epoch, exc.seq) == (namespace, origin, epoch, seq):
                if responder is not None and exc.destination != responder:
                    return None
                if service_id is not None and exc.service_id != service_id:
                    return None
                return exc
        return None

    def complete_exchange(self, exc: OutgoingExchange) -> None:
        """Mark exchange completed and release stop-and-wait gate."""
        exc.state = "completed"
        if exc.exchange_id in self.active_outgoing:
            del self.active_outgoing[exc.exchange_id]
        self._release_gate(exc)
