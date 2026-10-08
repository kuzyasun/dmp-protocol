"""SAMPLE-1 reference application (docs/DMP_v2_Reference_Application.md A1-A4)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


class SampleEpochError(RuntimeError):
    """Producer epoch store failure or exhaustion."""


class SampleEpochStore:
    """Producer-owned persistent epoch counter with injected persistence modeling."""

    def __init__(self, initial_epoch: int = 1, *, persist_fn=None):
        if initial_epoch <= 0 or initial_epoch > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("initial_epoch must be a positive 64-bit integer")
        self._current_epoch = initial_epoch
        self._failed = False
        self._persist_fn = persist_fn

    @property
    def failed(self) -> bool:
        return self._failed

    def set_failed(self, failed: bool = True) -> None:
        self._failed = failed

    def current_epoch(self) -> int:
        if self._failed:
            raise SampleEpochError("epoch storage is inaccessible or failed")
        return self._current_epoch

    def advance_epoch(self) -> int:
        if self._failed:
            raise SampleEpochError("epoch storage is inaccessible or failed")
        if self._current_epoch >= 0xFFFFFFFFFFFFFFFF:
            raise SampleEpochError("sample epoch counter exhausted")
        next_epoch = self._current_epoch + 1
        if self._persist_fn is not None:
            try:
                ok = self._persist_fn(next_epoch)
                if not ok:
                    self._failed = True
                    raise SampleEpochError("injected persistence backend rejected epoch advance")
            except Exception as e:
                self._failed = True
                if isinstance(e, SampleEpochError):
                    raise
                raise SampleEpochError(f"injected persistence failure: {e}") from e
        self._current_epoch = next_epoch
        return self._current_epoch


@dataclass(frozen=True)
class Sample:
    epoch: int
    index: int
    value: int

    def encode_telemetry(self) -> bytes:
        return struct.pack("<QII", self.epoch, self.index, self.value)

    def encode_read_result(self) -> bytes:
        return struct.pack("<BQII", 1, self.epoch, self.index, self.value)

    @classmethod
    def decode_telemetry(cls, payload: bytes) -> Sample:
        if len(payload) != 16:
            raise ValueError(f"SAMPLE-1 telemetry must be exactly 16 bytes, got {len(payload)}")
        epoch, index, value = struct.unpack("<QII", payload)
        return cls(epoch, index, value)

    @classmethod
    def decode_read_result(cls, payload: bytes) -> Sample:
        if len(payload) != 17:
            raise ValueError(f"SAMPLE-1 READ result must be exactly 17 bytes, got {len(payload)}")
        opcode, epoch, index, value = struct.unpack("<BQII", payload)
        if opcode != 1:
            raise ValueError(f"SAMPLE-1 READ result opcode must be 1, got {opcode}")
        return cls(epoch, index, value)


class SampleProducer:
    """SAMPLE-1 producer state machine."""

    def __init__(self, epoch_store: Optional[SampleEpochStore] = None, initial_value: Optional[int] = None, before_epoch_advance=None):
        self.epoch_store = epoch_store or SampleEpochStore(1)
        self._current_sample: Optional[Sample] = None
        self._sample_index: int = 0
        self._before_epoch_advance = before_epoch_advance
        if initial_value is not None:
            self.publish(initial_value)

    @property
    def current_sample(self) -> Optional[Sample]:
        return self._current_sample

    def publish(self, value: int) -> Sample:
        if self.epoch_store.failed:
            raise SampleEpochError("producer stopped: persistence failure")
        epoch = self.epoch_store.current_epoch()
        if self._sample_index >= 0xFFFFFFFF:
            # Index exhausted: must advance epoch
            if self._before_epoch_advance is not None:
                self._before_epoch_advance()
            epoch = self.epoch_store.advance_epoch()
            self._sample_index = 0
        self._sample_index += 1
        sample = Sample(epoch, self._sample_index, value & 0xFFFFFFFF)
        self._current_sample = sample
        return sample

    def restart(self) -> None:
        """Producer restarts: atomically reserve and durably commit next epoch."""
        self.epoch_store.advance_epoch()
        self._sample_index = 0
        self._current_sample = None

    def handle_read(self) -> tuple[int, bytes]:
        """Handle READ request. Returns (status, result_payload)."""
        if self._current_sample is None:
            # NO_SAMPLE: status 64, empty payload
            return 64, b""
        return 0, self._current_sample.encode_read_result()

    def handle_status(self) -> tuple[int, bytes]:
        """Handle STATUS request. Returns (status, result_payload)."""
        ready = 1 if self._current_sample is not None and not self.epoch_store.failed else 0
        return 0, struct.pack("<BB", 2, ready)


class SampleConsumer:
    """SAMPLE-1 consumer initialization and live-cache state machine (A2)."""

    def __init__(
        self,
        max_attempts: int = 3,
        init_retry_ms: int = 5,
        init_deadline_ms: int = 12000,
    ):
        self.state: str = "unsynchronized"
        self.association_id: Optional[int] = None
        self.init_generation: int = 0
        self.designated_request_seq: Optional[int] = None
        self.selected_epoch: Optional[int] = None
        self.cached_sample: Optional[Sample] = None
        self.is_live: bool = False
        self.init_attempts: int = 0
        self.max_attempts: int = max_attempts
        self.init_retry_ms: int = init_retry_ms
        self.init_deadline_ms: int = init_deadline_ms
        self.init_started_at_ms: int = 0

    def start_initialization(self, association_id: int, at_ms: int = 0) -> int:
        """Enter unsynchronized, advance init generation, bind association."""
        self.state = "unsynchronized"
        self.is_live = False
        self.association_id = association_id
        self.init_generation += 1
        self.designated_request_seq = None
        self.init_attempts = 0
        self.init_started_at_ms = at_ms
        return self.init_generation

    def can_attempt_init(self, now_ms: int = 0) -> bool:
        """Check if initialization attempt is permitted within budget and deadline."""
        if self.state != "unsynchronized":
            return False
        if self.init_attempts >= self.max_attempts:
            return False
        if self.init_deadline_ms > 0 and (now_ms - self.init_started_at_ms) >= self.init_deadline_ms:
            return False
        return True

    def advance(self, now_ms: int) -> bool:
        """Expire initialization at its absolute deadline and invalidate its READ."""
        if (
            self.state == "unsynchronized"
            and self.init_deadline_ms > 0
            and now_ms - self.init_started_at_ms >= self.init_deadline_ms
        ):
            self.state = "failed"
            self.is_live = False
            self.designated_request_seq = None
            return True
        return False

    def designate_read(self, request_seq: int, at_ms: int = 0) -> bool:
        """Designate the request identity for synchronization."""
        if not self.can_attempt_init(at_ms):
            self.designated_request_seq = None
            return False
        self.designated_request_seq = request_seq
        self.init_attempts += 1
        return True

    def handle_read_result(
        self,
        request_seq: int,
        payload: bytes,
        *,
        association_id: Optional[int] = None,
        generation: Optional[int] = None,
        now_ms: Optional[int] = None,
    ) -> bool:
        """Correlate READ RSP with current initialization. Returns True if synchronized."""
        # 1. Check association and generation binding
        if association_id is not None and association_id != self.association_id:
            return False
        if generation is not None and generation != self.init_generation:
            return False

        # 2. If already synchronized, late or superseded results cannot mutate live cache!
        if self.state != "unsynchronized":
            return False

        if now_ms is not None and self.advance(now_ms):
            return False

        # 3. Check designated request
        if self.designated_request_seq is None or request_seq != self.designated_request_seq:
            # Superseded or un-designated request
            return False

        try:
            sample = Sample.decode_read_result(payload)
        except ValueError:
            return False

        if self.selected_epoch is None or sample.epoch != self.selected_epoch:
            # New epoch installed
            self.selected_epoch = sample.epoch
            self.cached_sample = sample
        else:
            # Same epoch: preserve greatest index/value (no rollback)
            if self.cached_sample is None or sample.index >= self.cached_sample.index:
                self.cached_sample = sample

        self.state = "synchronized"
        self.is_live = True
        return True

    def handle_no_sample(
        self,
        request_seq: int,
        *,
        association_id: Optional[int] = None,
        generation: Optional[int] = None,
    ) -> None:
        """NO_SAMPLE terminal ERR=64 arrived."""
        if association_id is not None and association_id != self.association_id:
            return
        if generation is not None and generation != self.init_generation:
            return
        if self.designated_request_seq == request_seq:
            self.designated_request_seq = None

    def handle_telemetry(self, payload: bytes) -> Optional[Sample]:
        """Process incoming TELEM payload. Returns updated sample or None if discarded."""
        if not self.is_live or self.state != "synchronized":
            # Discard while unsynchronized; no pre-sync buffer
            return None

        sample = Sample.decode_telemetry(payload)
        if sample.epoch != self.selected_epoch:
            # Different epoch on active association is contract violation, discard
            return None

        if self.cached_sample is not None and sample.index <= self.cached_sample.index:
            # Stale sample: do not overwrite newer cached state
            return None

        self.cached_sample = sample
        return sample
