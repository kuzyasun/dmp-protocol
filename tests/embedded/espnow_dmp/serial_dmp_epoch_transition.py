#!/usr/bin/env python3
"""Qualify live SAMPLE-1 epoch rotation and stale-association fencing on S3/C3.

This physical-hardware runner requires a passing pair run that is still live on
both boards. It rotates the controller epoch, submits one READ over the old C3
association, observes the full retry-2 initialization deadline, then reboots
and verifies persistent monotonic advancement on the next controller startup.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Callable

from serial_dmp_common import (
    DmpTestError,
    HostCommandLog,
    SerialDeviceSession,
    create_evidence_dir,
    default_serial_factory,
    validate_nvs_check,
    validate_ready_event,
)
from serial_dmp_restart import _open_serial_without_reset

DEFAULT_S3_PORT = "COM37"
DEFAULT_C3_PORT = "COM40"
DEFAULT_ROTATION_SAMPLE = 0x55667788


def load_live_pair_context(pair_dir: Path | str) -> tuple[dict[str, Any], int]:
    """Load a passing pair that intentionally preserved the current owner epoch."""
    path = Path(pair_dir)
    try:
        pair = json.loads((path / "evidence.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DmpTestError(f"Cannot load pair evidence from {path}: {error}") from error
    if pair.get("result") != "PASS" or pair.get("test_mode") != "authenticated-dmp-endpoint":
        raise DmpTestError("Epoch rotation requires a passing authenticated DMP pair run")
    if pair.get("peer_count") != 1 or pair.get("s3_node_id") != 10 or pair.get("c3_node_id") != 20:
        raise DmpTestError("Epoch rotation requires the one-peer retry-2 S3/C3 pair profile")
    if pair.get("nvs_check_performed") is not False:
        raise DmpTestError(
            "Live pair must use --skip-nvs-check-for-epoch-transition so its owner remains current"
        )
    session = pair.get("session")
    event_path = path / "events_s3.jsonl"
    try:
        records = []
        for line in event_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                raise DmpTestError("S3 event log contains a non-object JSON record")
            payload = record.get("event")
            records.append(payload if isinstance(payload, dict) else record)
    except (OSError, json.JSONDecodeError) as error:
        raise DmpTestError(f"Cannot read S3 epoch events from {event_path}: {error}") from error
    if any(
        record.get("event") == "nvs_epoch_check" and record.get("session") == session
        for record in records if isinstance(record, dict)
    ):
        raise DmpTestError("Live pair unexpectedly consumed an extra NVS epoch with NVS_CHECK")
    owner_events = [
        record for record in records
        if isinstance(record, dict)
        and record.get("event") == "sample1_epoch_reserved"
        and record.get("session") == session
    ]
    if len(owner_events) != 1:
        raise DmpTestError(f"Expected one active owner epoch reservation, got {len(owner_events)}")
    active_epoch = owner_events[0].get("epoch")
    if not isinstance(active_epoch, int) or isinstance(active_epoch, bool) or active_epoch <= 0:
        raise DmpTestError("Live pair is missing its positive active owner epoch")
    if pair.get("sample1_owner_epoch") != active_epoch:
        raise DmpTestError("Pair summary active owner epoch disagrees with its captured S3 event")
    for side in ("s3", "c3"):
        boot_id = pair.get(f"{side}_boot_id")
        if not isinstance(boot_id, str) or len(boot_id) != 16:
            raise DmpTestError(f"Pair evidence is missing a valid {side.upper()} boot identity")
    return pair, active_epoch


def load_retry2_initialization_deadline(repo_root: Path | None = None) -> dict[str, int | str]:
    """Read the live two-attempt retry-2 bounds from its profile manifest."""
    root = repo_root or Path(__file__).resolve().parents[3]
    path = root / "profiles" / "deployments" / "test-direct-sample-retry-2-nnpsk0.json"
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        profile_id = manifest["profile"]["id"]
        sample = manifest["sample"]
        timing = manifest["timing"]
        attempts = sample["init_attempts"]
        result_deadline = timing["result_deadline_ms"]
        retry_delay = sample["init_retry_ms"]
        deadline = sample["init_deadline_ms"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise DmpTestError(f"Cannot read retry-2 initialization bounds from {path}: {error}") from error
    if not isinstance(profile_id, str) or not profile_id.strip():
        raise DmpTestError("Retry-2 manifest profile ID must be a non-empty string")
    values = (attempts, result_deadline, retry_delay, deadline)
    if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in values):
        raise DmpTestError("Retry-2 initialization bounds must be positive integers")
    minimum = attempts * result_deadline + retry_delay
    if attempts != 2 or deadline < minimum:
        raise DmpTestError(
            f"Retry-2 initialization deadline {deadline} ms is below its manifest minimum {minimum} ms"
        )
    return {
        "profile_id": profile_id,
        "attempts": attempts,
        "result_deadline_ms": result_deadline,
        "retry_delay_ms": retry_delay,
        "init_deadline_ms": deadline,
    }


def validate_epoch_rotation_event(
    active_epoch: int, event: dict[str, Any], sample_value: int
) -> dict[str, int]:
    """Validate the owner epoch reservation, fencing and publication event."""
    expected_reserved = active_epoch + 1
    if event.get("event") != "sample1_epoch_transition" or event.get("status") != "ok":
        raise DmpTestError("S3 SAMPLE-1 epoch transition did not complete with status=ok")
    if event.get("previous_epoch") != active_epoch:
        raise DmpTestError("Transition did not start from the current live SAMPLE-1 epoch")
    if event.get("reserved_epoch") != expected_reserved or event.get("new_epoch") != expected_reserved:
        raise DmpTestError("Transition did not reserve and activate exactly the next NVS epoch")
    if event.get("sample_value") != sample_value:
        raise DmpTestError("Transition did not publish the requested SAMPLE-1 value")
    if event.get("peer_records_before") not in (0, 1) or event.get("peer_records_after") != 0:
        raise DmpTestError("Transition did not close the single previous-epoch peer record")
    if event.get("owner_active") is not True or event.get("sample_published") is not True:
        raise DmpTestError("Transition did not leave the new epoch active with a published sample")
    return {
        "previous_epoch": active_epoch,
        "reserved_epoch": expected_reserved,
        "sample_value": sample_value,
    }


def validate_busy_rotation_event(
    active_epoch: int, event: dict[str, Any], sample_value: int
) -> int:
    """Validate a retryable BUSY state without accepting a stopped/uncertain owner."""
    expected_reserved = active_epoch + 1
    reserved = event.get("reserved_epoch")
    if event.get("event") != "sample1_epoch_transition" or event.get("status") != "busy":
        raise DmpTestError("Expected a retryable SAMPLE-1 transition BUSY event")
    if event.get("previous_epoch") != active_epoch or reserved not in (0, expected_reserved):
        raise DmpTestError("BUSY transition changed the active or reserved epoch")
    if event.get("sample_value") != sample_value or event.get("new_epoch") != 0:
        raise DmpTestError("BUSY transition unexpectedly activated or published a new epoch")
    if event.get("owner_active") is not (reserved == 0):
        raise DmpTestError("BUSY transition owner activity does not match reservation progress")
    if event.get("sample_published") is not False:
        raise DmpTestError("BUSY transition reported a new sample publication")
    if event.get("peer_records_before") not in (0, 1) or event.get("peer_records_after") not in (0, 1):
        raise DmpTestError("BUSY transition peer record count exceeds the one-peer profile")
    return reserved


def stale_read_violation(
    s3_events: list[dict[str, Any]], c3_events: list[dict[str, Any]],
    session: str,
) -> str | None:
    """Return a reason if an old-association SAMPLE-1 READ was accepted."""
    for event in s3_events:
        if event.get("session") == session and event.get("event") == "rx_request" and event.get("service_id") == 1:
            return "S3 accepted a SAMPLE-1 request after fencing the old epoch"
    for event in c3_events:
        if event.get("session") == session and event.get("event") in ("rx_result", "sample1_read_result"):
            if event.get("event") == "sample1_read_result" or event.get("service_id") == 1:
                return "C3 received a SAMPLE-1 result over the stale association"
    return None


def validate_persisted_epoch(rotation: dict[str, int], nvs_check: dict[str, Any], session: str) -> dict[str, int]:
    """Require the post-reboot owner to reserve after the rotated epoch."""
    validate_nvs_check(nvs_check, session)
    if nvs_check.get("has_previous") is not True:
        raise DmpTestError("Post-reboot NVS check did not find the persisted epoch")
    expected_previous = rotation["reserved_epoch"] + 1
    if nvs_check.get("previous_epoch") != expected_previous:
        raise DmpTestError(
            "Post-reboot controller owner did not reserve from the epoch committed by rotation"
        )
    if nvs_check.get("reserved_epoch") != expected_previous + 1:
        raise DmpTestError("Post-reboot NVS check did not reserve the following distinct epoch")
    return {
        "rotated_epoch": rotation["reserved_epoch"],
        "post_reboot_owner_epoch": expected_previous,
        "post_reboot_check_reserved_epoch": expected_previous + 1,
    }


def _ready_without_reset(
    device: SerialDeviceSession,
    target: str,
    expected_boot_id: str,
    timeout: float,
) -> dict[str, Any]:
    start = device.event_count
    device.send_command("INFO")
    ready = validate_ready_event(
        device.wait_for_event(
            lambda event: event.get("event") == "ready" and event.get("target") == target,
            timeout=timeout,
            desc=f"INFO ready on {target}",
            start_index=start,
        ),
        target,
    )
    if ready["boot_id"] != expected_boot_id:
        raise DmpTestError(
            f"{target} rebooted since the pair run; refusing to rotate a non-live association"
        )
    return ready


def _reboot_and_observe(
    device: SerialDeviceSession,
    target: str,
    previous_boot_id: str,
    timeout: float,
) -> dict[str, Any]:
    reboot_start = device.event_count
    device.send_command("REBOOT")
    requested = device.wait_for_event(
        lambda event: event.get("event") == "reboot_requested"
        and event.get("target") == target
        and event.get("boot_id") == previous_boot_id,
        timeout=timeout,
        desc=f"REBOOT confirmation on {target}",
        start_index=reboot_start,
    )
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        start = device.event_count
        device.send_command("INFO")
        try:
            ready = validate_ready_event(
                device.wait_for_event(
                    lambda event: event.get("event") == "ready" and event.get("target") == target,
                    timeout=min(1.0, max(0.1, deadline - time.monotonic())),
                    desc=f"post-reboot INFO ready on {target}",
                    start_index=start,
                ),
                target,
            )
            if ready["boot_id"] == previous_boot_id or ready["reset_reason"] != "software":
                raise DmpTestError(f"{target} did not report a new software-reset boot")
            return {
                "target": target,
                "boot_id_before": previous_boot_id,
                "boot_id_after": ready["boot_id"],
                "reset_reason": ready["reset_reason"],
                "reboot_requested_event": requested,
            }
        except DmpTestError as error:
            last_error = error
    raise DmpTestError(f"Could not observe {target} after software reboot: {last_error}")


def run_live_epoch_transition(
    s3_port: str,
    c3_port: str,
    previous_pair_dir: Path | str,
    evidence_dir: Path | str | None = None,
    timeout: float = 15.0,
    sample_value: int = DEFAULT_ROTATION_SAMPLE,
    serial_factory: Callable[..., Any] | None = None,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Rotate a live one-peer session, observe stale READ rejection, and verify NVS restart."""
    if not s3_port or not c3_port or s3_port.strip().lower() == c3_port.strip().lower():
        raise DmpTestError("Distinct explicit S3 and C3 serial ports are required")
    if not isinstance(sample_value, int) or isinstance(sample_value, bool) or not 0 <= sample_value <= 0xFFFFFFFF:
        raise DmpTestError("SAMPLE-1 rotation value must fit uint32")

    pair, active_epoch = load_live_pair_context(previous_pair_dir)
    timing = load_retry2_initialization_deadline(repo_root)
    root = repo_root or Path(__file__).resolve().parents[3]
    observer_window_ms = timing["init_deadline_ms"] + 250
    factory = serial_factory or default_serial_factory
    ev_dir = create_evidence_dir(evidence_dir, prefix="epoch-rotation")
    command_log = HostCommandLog(ev_dir / "commands.log")
    s3: SerialDeviceSession | None = None
    c3: SerialDeviceSession | None = None
    rotation: dict[str, int] | None = None
    try:
        s3 = SerialDeviceSession(
            "s3", s3_port, _open_serial_without_reset(s3_port, factory), ev_dir,
            cmd_log=command_log, expected_session=pair["session"],
        )
        c3 = SerialDeviceSession(
            "c3", c3_port, _open_serial_without_reset(c3_port, factory), ev_dir,
            cmd_log=command_log, expected_session=pair["session"],
        )
        _ready_without_reset(s3, "esp32s3", pair["s3_boot_id"], timeout)
        _ready_without_reset(c3, "esp32c3", pair["c3_boot_id"], timeout)

        transition_attempts: list[dict[str, Any]] = []
        transition_started = time.monotonic()
        transition_deadline = transition_started + timeout
        reserved_epoch: int | None = None
        for attempt in range(50):
            transition_start = s3.event_count
            s3.send_command(f"SAMPLE_ROTATE {sample_value}")
            transition_event = s3.wait_for_event(
                lambda event: event.get("event") == "sample1_epoch_transition"
                and event.get("session") == pair["session"],
                timeout=max(0.1, transition_deadline - time.monotonic()),
                desc="live SAMPLE-1 epoch transition on S3",
                start_index=transition_start,
            )
            transition_attempts.append(transition_event)
            if transition_event.get("status") == "ok":
                rotation = validate_epoch_rotation_event(active_epoch, transition_event, sample_value)
                break
            attempt_reservation = validate_busy_rotation_event(
                active_epoch, transition_event, sample_value
            )
            if attempt_reservation != 0:
                if reserved_epoch not in (None, attempt_reservation):
                    raise DmpTestError("Retryable transition changed its durable epoch reservation")
                reserved_epoch = attempt_reservation
            if attempt == 49 or time.monotonic() >= transition_deadline:
                raise DmpTestError("SAMPLE-1 epoch transition remained BUSY through its retry window")
            time.sleep(min(0.1, max(0.0, transition_deadline - time.monotonic())))
        if rotation is None:
            raise DmpTestError("SAMPLE-1 epoch transition did not produce a successful event")

        s3_stale_start = s3.event_count
        c3_stale_start = c3.event_count
        c3.send_command("SAMPLE_READ 0")
        stale_submit = c3.wait_for_event(
            lambda event: event.get("event") == "sample_read_submitted"
            and event.get("session") == pair["session"],
            timeout=timeout,
            desc="stale-association SAMPLE-1 READ submission on C3",
            start_index=c3_stale_start,
        )
        if stale_submit.get("status") != 0:
            raise DmpTestError(
                f"C3 could not submit stale-association SAMPLE-1 READ: {stale_submit.get('status')!r}"
            )

        observe_until = time.monotonic() + observer_window_ms / 1000.0
        while time.monotonic() < observe_until:
            violation = stale_read_violation(
                s3.get_events()[s3_stale_start:],
                c3.get_events()[c3_stale_start:],
                pair["session"],
            )
            if violation:
                raise DmpTestError(violation)
            time.sleep(min(0.1, max(0.0, observe_until - time.monotonic())))
        stale_observation = {
            "submitted": True,
            "submit_status": stale_submit["status"],
            "init_attempts": timing["attempts"],
            "result_deadline_ms": timing["result_deadline_ms"],
            "retry_delay_ms": timing["retry_delay_ms"],
            "manifest_init_deadline_ms": timing["init_deadline_ms"],
            "observed_ms": observer_window_ms,
            "producer_rx_request_count": 0,
            "reader_rx_result_count": 0,
            "client_timeout_event_available": False,
        }

        # Reboot and reinitialize only S3 to prove the transition's NVS state
        # survived. The C3 remains unconfigured after its reboot, leaving a clean
        # pair-ready state after a final reset below.
        s3_reset = _reboot_and_observe(s3, "esp32s3", pair["s3_boot_id"], timeout)
        c3_reset = _reboot_and_observe(c3, "esp32c3", pair["c3_boot_id"], timeout)
        s3.send_command(f"SESSION {pair['session']}")
        s3.wait_for_event(
            lambda event: event.get("event") == "session_set"
            and event.get("session") == pair["session"],
            timeout=timeout,
            desc="session setup for post-rotation NVS persistence check",
        )
        s3.send_command("ROLE controller retry-2 10 1")
        s3.wait_for_event(
            lambda event: event.get("event") == "role_set"
            and event.get("session") == pair["session"],
            timeout=timeout,
            desc="S3 controller initialization after epoch rotation reboot",
        )
        nvs_start = s3.event_count
        s3.send_command("NVS_CHECK")
        post_nvs = s3.wait_for_event(
            lambda event: event.get("event") == "nvs_epoch_check"
            and event.get("session") == pair["session"],
            timeout=timeout,
            desc="post-rotation NVS persistence check",
            start_index=nvs_start,
        )
        persisted = validate_persisted_epoch(rotation, post_nvs, pair["session"])

        # Leave both boards unconfigured for the next pair runner.
        s3_clean_reset = _reboot_and_observe(
            s3, "esp32s3", s3_reset["boot_id_after"], timeout
        )
        c3_clean_reset = _reboot_and_observe(
            c3, "esp32c3", c3_reset["boot_id_after"], timeout
        )
        result = {
            "result": "PASS",
            "test_mode": "authenticated-dmp-sample1-epoch-transition",
            "previous_pair_evidence": str(Path(previous_pair_dir)),
            "session": pair["session"],
            "ports": {"s3": s3_port, "c3": c3_port},
            "rotation": rotation,
            "transition_attempt_count": len(transition_attempts),
            "transition_attempt_statuses": [event.get("status") for event in transition_attempts],
            "old_association": {
                "peer_records_before": transition_event["peer_records_before"],
                "peer_records_after": transition_event["peer_records_after"],
                "owner_active": transition_event["owner_active"],
                "sample_published": transition_event["sample_published"],
            },
            "stale_read_observation": stale_observation,
            "post_rotation_nvs": {**post_nvs, **persisted},
            "software_reset_after_rotation": {"s3": s3_reset, "c3": c3_reset},
            "cleanup_reset": {"s3": s3_clean_reset, "c3": c3_clean_reset},
            "retry2_profile": {
                "attempts": timing["attempts"],
                "result_deadline_ms": timing["result_deadline_ms"],
                "retry_delay_ms": timing["retry_delay_ms"],
                "init_deadline_ms": timing["init_deadline_ms"],
                "manifest_profile": timing["profile_id"],
                "decoded_core_mtu_bytes": 256,
                "stream_r_encoded_mtu_bytes": 263,
            },
            "evidence_boundary": (
                "One authenticated S3/C3 pair; target-side rotation and peer fencing, stale READ "
                "non-acceptance over the full manifest retry window, and NVS continuity after "
                "software reset. This does not qualify power-loss durability or multi-peer rotation."
            ),
            "evidence_dir": str(ev_dir),
        }
        (ev_dir / "epoch_rotation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result
    except Exception as error:
        failure = {
            "result": "FAIL",
            "error": f"{type(error).__name__}: {error}",
            "previous_pair_evidence": str(Path(previous_pair_dir)),
            "session": pair.get("session"),
            "rotation": rotation,
            "evidence_dir": str(ev_dir),
        }
        (ev_dir / "epoch_rotation_failure.json").write_text(
            json.dumps(failure, indent=2), encoding="utf-8"
        )
        raise
    finally:
        if s3 is not None:
            s3.close()
        if c3 is not None:
            c3.close()
        command_log.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Live SAMPLE-1 epoch rotation hardware runner")
    parser.add_argument("--s3-port", default=DEFAULT_S3_PORT, help="Serial port for ESP32-S3")
    parser.add_argument("--c3-port", default=DEFAULT_C3_PORT, help="Serial port for ESP32-C3")
    parser.add_argument("--previous-pair-dir", required=True, type=Path,
                        help="Passing pair evidence directory; endpoints must still be live")
    parser.add_argument("--sample-value", type=lambda value: int(value, 0),
                        default=DEFAULT_ROTATION_SAMPLE, help="Published uint32 decimal or 0x-prefixed value")
    parser.add_argument("--evidence-dir", type=Path, default=None, help="Evidence base directory")
    parser.add_argument("--timeout", type=float, default=15.0, help="Serial command timeout in seconds")
    args = parser.parse_args()
    print(json.dumps(run_live_epoch_transition(
        s3_port=args.s3_port,
        c3_port=args.c3_port,
        previous_pair_dir=args.previous_pair_dir,
        evidence_dir=args.evidence_dir,
        timeout=args.timeout,
        sample_value=args.sample_value,
    ), indent=2))


if __name__ == "__main__":
    main()
