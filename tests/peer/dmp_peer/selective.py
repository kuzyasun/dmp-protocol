"""Independent SELECTIVE-32 sender recovery state for one logical transfer."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryAction:
    kind: str
    indices: tuple[int, ...] = ()
    reason: str | None = None


@dataclass
class SelectiveTransfer:
    """Bounded stop-and-wait state for repair and final-fragment probe bursts."""

    fragment_count: int
    started_at_ms: int
    send_horizon_ms: int
    response_timeout_ms: int
    max_bursts: int
    max_probes: int
    max_status: int
    burst_starts_ms: tuple[int, ...]
    burst_count: int = 1
    probe_count: int = 0
    status_count: int = 0
    greatest_status_seq: int = -1
    pending_mask: int | None = None
    active_kind: str | None = "initial"
    frames_remaining: int = 0
    wait_until_ms: int | None = None
    terminal: bool = False

    @property
    def horizon_at_ms(self) -> int:
        return self.started_at_ms + self.send_horizon_ms

    def begin_burst(self, kind: str, frame_count: int) -> None:
        if self.terminal or self.active_kind is not None or frame_count <= 0:
            raise ValueError("recovery burst cannot start in the current state")
        if kind not in ("repair", "probe"):
            raise ValueError("recovery burst kind must be repair or probe")
        self.active_kind = kind
        self.frames_remaining = frame_count
        self.wait_until_ms = None

    def settle_frame(self, now_ms: int) -> bool:
        """Settle one accepted/queued frame; return true when its burst is complete."""
        if self.terminal or self.active_kind is None or self.frames_remaining <= 0:
            return False
        self.frames_remaining -= 1
        if self.frames_remaining == 0:
            self.active_kind = None
            self.wait_until_ms = now_ms + self.response_timeout_ms
            return True
        return False

    def accept_status(self, sequence: int, mask: int, now_ms: int) -> bool:
        """Accept only a newer, structurally valid snapshot for this live transfer."""
        if self.terminal or now_ms >= self.horizon_at_ms:
            return False
        if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= 0xFFFFFFFF:
            return False
        valid_mask = (1 << self.fragment_count) - 1
        if isinstance(mask, bool) or not isinstance(mask, int) or mask <= 0:
            return False
        if mask & ~valid_mask or mask == valid_mask:
            return False
        if sequence <= self.greatest_status_seq or self.status_count >= self.max_status:
            return False
        self.greatest_status_seq = sequence
        self.status_count += 1
        # Newer snapshots supersede older pending snapshots; never merge masks.
        self.pending_mask = mask
        return True

    def take_due_action(self, now_ms: int) -> RecoveryAction | None:
        """Take the next scheduled repair/probe or report that the transfer is spent."""
        if self.terminal:
            return None
        if now_ms >= self.horizon_at_ms:
            self.terminal = True
            self.pending_mask = None
            return RecoveryAction("stop", reason="send_horizon")
        if self.active_kind is not None:
            return None

        next_start = self._next_burst_start()
        if self.pending_mask is not None:
            if next_start is None or self.burst_count >= self.max_bursts:
                self.terminal = True
                self.pending_mask = None
                return RecoveryAction("stop", reason="burst_budget")
            if now_ms < next_start:
                return None
            mask = self.pending_mask
            self.pending_mask = None
            indices = tuple(i for i in range(self.fragment_count) if mask & (1 << i))
            self.burst_count += 1
            self.begin_burst("repair", len(indices))
            return RecoveryAction("repair", indices)

        if self.wait_until_ms is None or now_ms < self.wait_until_ms:
            return None
        if (next_start is None or self.burst_count >= self.max_bursts
                or self.probe_count >= self.max_probes):
            self.terminal = True
            return RecoveryAction("stop", reason="burst_or_probe_budget")
        if now_ms < next_start:
            return None
        self.burst_count += 1
        self.probe_count += 1
        self.begin_burst("probe", 1)
        return RecoveryAction("probe", (self.fragment_count - 1,))

    def terminate(self) -> None:
        self.terminal = True
        self.pending_mask = None
        self.active_kind = None
        self.frames_remaining = 0
        self.wait_until_ms = None

    def _next_burst_start(self) -> int | None:
        if self.burst_count >= len(self.burst_starts_ms):
            return None
        return self.started_at_ms + self.burst_starts_ms[self.burst_count]
