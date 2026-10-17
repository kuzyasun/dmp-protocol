#!/usr/bin/env python3
"""Run a protected DMP pair after serial software reset or operator power cycle.

This is a physical-hardware runner. Its host tests inject serial and pair-runner
stubs and never open a COM port.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Callable

from serial_dmp_common import (
    BOOT_ID_PATTERN,
    DmpTestError,
    HostCommandLog,
    SerialDeviceSession,
    create_evidence_dir,
    default_serial_factory,
    validate_nvs_check,
    validate_ready_event,
)
from serial_dmp_pair import run_dmp_pair


def load_pair_nvs_event(run_path: Path | str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load and validate the single NVS reserve event from a passing pair run."""
    path = Path(run_path)
    if path.is_file():
        evidence_path = path
        run_dir = path.parent
    else:
        run_dir = path
        evidence_path = run_dir / "evidence.json"
    try:
        result = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DmpTestError(f"Cannot load pair evidence from {evidence_path}: {error}") from error
    if result.get("result") != "PASS" or result.get("test_mode") != "authenticated-dmp-endpoint":
        raise DmpTestError("Previous/current evidence is not a passing authenticated DMP pair run")
    session = result.get("session")
    if not isinstance(session, str) or not session:
        raise DmpTestError("Pair evidence is missing its session identity")

    events_path = run_dir / "events_s3.jsonl"
    try:
        lines = events_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise DmpTestError(f"Cannot load S3 event log from {events_path}: {error}") from error
    nvs_events: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise DmpTestError(f"Invalid JSON in {events_path}:{line_number}: {error}") from error
        event = record.get("event") if isinstance(record, dict) else None
        if isinstance(event, dict) and event.get("event") == "nvs_epoch_check":
            nvs_events.append(event)
    if len(nvs_events) != 1:
        raise DmpTestError(f"Expected exactly one S3 NVS epoch check, got {len(nvs_events)}")
    return result, validate_nvs_check(nvs_events[0], session)


def validate_persistent_epoch_transition(
    previous: dict[str, Any], current: dict[str, Any]
) -> dict[str, int | str]:
    """Verify the owner reservation survived one reset before the next READ.

    A successful ROLE reserves one epoch before publishing. The runner's NVS_CHECK
    reserves the next epoch. Therefore the next boot's owner reservation must be
    exactly one above the previous run's check reservation, and its own check
    must reserve the following value.
    """
    previous_epoch = previous.get("reserved_epoch")
    current_previous_epoch = current.get("previous_epoch")
    current_reserved_epoch = current.get("reserved_epoch")
    if previous.get("status") != "ok" or current.get("status") != "ok":
        raise DmpTestError("Both NVS checks must report status=ok")
    if previous.get("namespace") != current.get("namespace") or previous.get("key") != current.get("key"):
        raise DmpTestError("NVS namespace/key changed across reset")
    if current.get("has_previous") is not True:
        raise DmpTestError("NVS did not retain a prior epoch across reset")
    if not isinstance(previous_epoch, int) or isinstance(previous_epoch, bool) or previous_epoch <= 0:
        raise DmpTestError("Previous NVS reservation is not a positive integer")
    if not isinstance(current_previous_epoch, int) or isinstance(current_previous_epoch, bool):
        raise DmpTestError("Current NVS previous_epoch is not an integer")
    if not isinstance(current_reserved_epoch, int) or isinstance(current_reserved_epoch, bool):
        raise DmpTestError("Current NVS reserved_epoch is not an integer")
    if current_previous_epoch != previous_epoch + 1:
        raise DmpTestError(
            "Epoch did not advance by the owner reservation after reset: "
            f"previous run reserved {previous_epoch}, current previous is {current_previous_epoch}"
        )
    if current_reserved_epoch != current_previous_epoch + 1:
        raise DmpTestError("Current NVS check did not reserve the next distinct epoch")
    return {
        "previous_check_reserved_epoch": previous_epoch,
        "current_owner_previous_epoch": current_previous_epoch,
        "current_check_reserved_epoch": current_reserved_epoch,
        "key": str(current["key"]),
        "namespace": str(current["namespace"]),
    }


def _open_serial_without_reset(port: str, serial_factory: Callable[..., Any] | None = None) -> Any:
    """Use the shared port-factory contract; the default keeps modem lines inactive."""
    factory = serial_factory or default_serial_factory
    return factory(port, baudrate=115200, timeout=0.2)


def observe_external_power_reset(
    port: str,
    side: str,
    expected_target: str,
    previous_boot_id: str,
    evidence_dir: Path,
    timeout: float = 15.0,
    *,
    serial_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Read INFO and require a fresh power-on boot before pair setup mutates state."""
    side_dir = evidence_dir / f"power_preflight_{side}"
    side_dir.mkdir(parents=True, exist_ok=False)
    command_log = HostCommandLog(side_dir / "commands.log")
    device: SerialDeviceSession | None = None
    try:
        handle = _open_serial_without_reset(port, serial_factory)
        device = SerialDeviceSession(side, port, handle, side_dir, cmd_log=command_log)
        info_start = device.event_count
        device.send_command("INFO")
        ready = validate_ready_event(
            device.wait_for_event(
                lambda event: event.get("event") == "ready"
                and event.get("target") == expected_target,
                timeout=timeout,
                desc=f"external-power preflight INFO ready on {side.upper()}",
                start_index=info_start,
            ),
            expected_target,
        )
        if ready["boot_id"] == previous_boot_id:
            raise DmpTestError(
                f"{side.upper()} boot identity did not change after the attested power cycle; "
                "refusing to send SESSION or ROLE to an already initialized endpoint"
            )
        if ready["reset_reason"] != "power_on":
            raise DmpTestError(
                f"{side.upper()} reports reset reason {ready['reset_reason']!r} after the "
                "attested power cycle, expected 'power_on'"
            )
        return {
            "port": port,
            "target": expected_target,
            "boot_id_before": previous_boot_id,
            "boot_id_after": ready["boot_id"],
            "reset_reason_after_power_cycle": ready["reset_reason"],
            "info_observed": True,
            "power_off_duration_operator_attested_ms": 5000,
            "tool_controlled": False,
        }
    finally:
        if device is not None:
            device.close()
        command_log.close()


def _pair_boot_id(pair_result: dict[str, Any], side: str) -> str:
    key = f"{side}_boot_id"
    boot_id = pair_result.get(key)
    if not isinstance(boot_id, str) or not BOOT_ID_PATTERN.fullmatch(boot_id):
        raise DmpTestError(f"Pair evidence is missing a valid {key}")
    return boot_id


def validate_boot_identity_transition(
    previous: dict[str, Any], current: dict[str, Any]
) -> dict[str, dict[str, str]]:
    """Require fresh target boot identities on both sides of a reset run."""
    transition: dict[str, dict[str, str]] = {}
    for side in ("s3", "c3"):
        before = _pair_boot_id(previous, side)
        after = _pair_boot_id(current, side)
        if before == after:
            raise DmpTestError(f"{side.upper()} boot identity did not change across reset")
        transition[side] = {"before": before, "after": after}
    return transition


def request_serial_restart(
    port: str,
    side: str,
    expected_target: str,
    expected_boot_id: str,
    evidence_dir: Path,
    timeout: float = 15.0,
    *,
    serial_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Request esp_restart, then reopen USB Serial/JTAG and require the new identity."""
    side_dir = evidence_dir / f"serial_reset_{side}"
    side_dir.mkdir(parents=True, exist_ok=False)
    command_log = HostCommandLog(side_dir / "commands.log")
    device: SerialDeviceSession | None = None
    try:
        handle = _open_serial_without_reset(port, serial_factory)
        device = SerialDeviceSession(side, port, handle, side_dir, cmd_log=command_log)
        info_start = device.event_count
        device.send_command("INFO")
        prior_ready = validate_ready_event(
            device.wait_for_event(
                lambda event: event.get("event") == "ready"
                and event.get("target") == expected_target,
                timeout=timeout,
                desc=f"pre-reset INFO ready on {side.upper()}",
                start_index=info_start,
            ),
            expected_target,
        )
        reset_start = device.event_count
        device.send_command("REBOOT")
        request_event = device.wait_for_event(
            lambda event: event.get("event") == "reboot_requested"
            and event.get("target") == expected_target
            and event.get("boot_id") == prior_ready["boot_id"],
            timeout=timeout,
            desc=f"serial reboot request on {side.upper()}",
            start_index=reset_start,
        )
    except BaseException:
        command_log.close()
        raise
    finally:
        if device is not None:
            device.close()

    reconnect_deadline = time.monotonic() + timeout
    reconnect_attempts = 0
    last_reconnect_error: str | None = None
    new_ready: dict[str, Any] | None = None
    try:
        while time.monotonic() < reconnect_deadline:
            reconnect_attempts += 1
            try:
                handle = _open_serial_without_reset(port, serial_factory)
            except OSError as error:
                last_reconnect_error = str(error)
                time.sleep(min(0.1, max(0.0, reconnect_deadline - time.monotonic())))
                continue

            attempt_dir = side_dir / f"after_reset_{reconnect_attempts:03d}"
            attempt_dir.mkdir(parents=True, exist_ok=False)
            reconnect_device = SerialDeviceSession(
                side, port, handle, attempt_dir, cmd_log=command_log
            )
            try:
                reconnect_device.send_command("INFO")
                candidate = reconnect_device.wait_for_event(
                    lambda event: event.get("event") == "ready"
                    and event.get("target") == expected_target,
                    timeout=min(1.0, max(0.01, reconnect_deadline - time.monotonic())),
                    desc=f"new boot-ready identity after serial reset on {side.upper()}",
                )
                candidate = validate_ready_event(candidate, expected_target)
                if candidate["boot_id"] == prior_ready["boot_id"]:
                    last_reconnect_error = "target returned its pre-reset boot identity"
                else:
                    new_ready = candidate
            except OSError as error:
                last_reconnect_error = str(error)
            except DmpTestError as error:
                error_text = str(error)
                if error_text.startswith("Timeout (") or error_text.startswith("Serial reader error"):
                    last_reconnect_error = error_text
                else:
                    raise
            finally:
                reconnect_device.close()

            if new_ready is not None:
                break
            time.sleep(min(0.1, max(0.0, reconnect_deadline - time.monotonic())))

        if new_ready is None:
            suffix = f"; last reconnect error: {last_reconnect_error}" if last_reconnect_error else ""
            raise DmpTestError(
                f"Timed out waiting for a new {side.upper()} boot identity after serial reset{suffix}"
            )
        if new_ready["reset_reason"] != "software":
            raise DmpTestError(
                f"{side.upper()} serial REBOOT produced reset reason "
                f"{new_ready['reset_reason']!r}, expected 'software'"
            )
    finally:
        command_log.close()

    return {
        "port": port,
        "reset": "serial REBOOT command followed by esp_restart",
        "target": expected_target,
        "pair_boot_id_before": expected_boot_id,
        "boot_id_before": prior_ready["boot_id"],
        "boot_id_after": new_ready["boot_id"],
        "reset_reason_before_command": prior_ready["reset_reason"],
        "boot_changed_since_previous_pair": prior_ready["boot_id"] != expected_boot_id,
        "reset_reason_after_command": new_ready["reset_reason"],
        "reboot_request_observed": request_event["boot_id"] == prior_ready["boot_id"],
        "boot_transition_observed": new_ready["boot_id"] != prior_ready["boot_id"],
        "reconnect_attempts": reconnect_attempts,
        "evidence_dir": str(side_dir),
    }


def run_persistent_transition(
    *,
    s3_port: str,
    c3_port: str,
    previous_run: Path | str,
    reset_mode: str,
    evidence_dir: Path | str,
    timeout: float = 70.0,
    transfer_bytes: int = 1024,
    operator_confirms_power_cycle: bool = False,
    pair_runner: Callable[..., dict[str, Any]] = run_dmp_pair,
    serial_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    if reset_mode not in ("serial-reboot", "external-power", "none"):
        raise DmpTestError(f"Unsupported reset mode: {reset_mode!r}")
    if reset_mode == "external-power" and not operator_confirms_power_cycle:
        raise DmpTestError("external-power requires operator confirmation of a full power cycle")
    previous_result, previous_nvs = load_pair_nvs_event(previous_run)
    root = create_evidence_dir(evidence_dir, prefix="epoch_transition")
    if reset_mode == "serial-reboot":
        reset_records = [
            request_serial_restart(
                s3_port, "s3", "esp32s3", _pair_boot_id(previous_result, "s3"),
                root, timeout=timeout, serial_factory=serial_factory,
            ),
            request_serial_restart(
                c3_port, "c3", "esp32c3", _pair_boot_id(previous_result, "c3"),
                root, timeout=timeout, serial_factory=serial_factory,
            ),
        ]
    elif reset_mode == "external-power":
        reset_records = [
            observe_external_power_reset(
                s3_port, "s3", "esp32s3", _pair_boot_id(previous_result, "s3"),
                root, timeout=timeout, serial_factory=serial_factory,
            ),
            observe_external_power_reset(
                c3_port, "c3", "esp32c3", _pair_boot_id(previous_result, "c3"),
                root, timeout=timeout, serial_factory=serial_factory,
            ),
        ]
    else:
        reset_records = []

    current_result = pair_runner(
        s3_port=s3_port,
        c3_port=c3_port,
        count=1,
        transfer_bytes=transfer_bytes,
        evidence_dir=root,
        timeout=timeout,
        serial_factory=serial_factory,
    )
    current_result_doc, current_nvs = load_pair_nvs_event(current_result["evidence_dir"])
    progression = validate_persistent_epoch_transition(previous_nvs, current_nvs)
    boot_progression = None
    if reset_mode != "none":
        boot_progression = validate_boot_identity_transition(previous_result, current_result_doc)
    if reset_mode == "serial-reboot":
        for side, record in zip(("s3", "c3"), reset_records, strict=True):
            if not record["reboot_request_observed"] or not record["boot_transition_observed"]:
                raise DmpTestError(f"{side.upper()} serial reset lacks positive boot transition evidence")
            if record["boot_id_after"] != _pair_boot_id(current_result_doc, side):
                raise DmpTestError(
                    f"{side.upper()} pair run boot identity does not match serial reset evidence"
                )
            if current_result_doc.get(f"{side}_reset_reason") != "software":
                raise DmpTestError(
                    f"{side.upper()} pair reported reset reason "
                    f"{current_result_doc.get(f'{side}_reset_reason')!r}, expected 'software'"
                )
    if reset_mode == "external-power":
        for side in ("s3", "c3"):
            if current_result_doc.get(f"{side}_reset_reason") != "power_on":
                raise DmpTestError(
                    f"{side.upper()} did not report a power-on reset after the attested power cycle"
                )
    evidence = {
        "result": "PASS",
        "reset_mode": reset_mode,
        "reset_records": reset_records,
        "previous_pair": {
            "evidence_dir": previous_result.get("evidence_dir"),
            "session": previous_result.get("session"),
            "s3_boot_id": previous_result.get("s3_boot_id"),
            "c3_boot_id": previous_result.get("c3_boot_id"),
            "nvs_epoch_check": previous_nvs,
        },
        "current_pair": {
            "evidence_dir": current_result_doc.get("evidence_dir"),
            "session": current_result_doc.get("session"),
            "s3_boot_id": current_result_doc.get("s3_boot_id"),
            "c3_boot_id": current_result_doc.get("c3_boot_id"),
            "s3_reset_reason": current_result_doc.get("s3_reset_reason"),
            "c3_reset_reason": current_result_doc.get("c3_reset_reason"),
            "nvs_epoch_check": current_nvs,
        },
        "epoch_progression": progression,
        "boot_identity_progression": boot_progression,
        "reset_verified": reset_mode != "none",
        "current_authenticated_claim": current_result.get("security_claim"),
        "decoded_core_mtu_bytes": current_result.get("decoded_core_mtu_bytes"),
        "stream_r_encoded_mtu_bytes": current_result.get("stream_r_encoded_mtu_bytes"),
        "max_observed_frame_bytes": current_result.get("max_observed_frame_bytes"),
        "operator_power_cycle_attested": reset_mode == "external-power" and operator_confirms_power_cycle,
        "physical_power_loss_verified_by_tool": False,
    }
    result_path = root / "epoch_transition.json"
    result_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    evidence["evidence_file"] = str(result_path)
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--s3-port", required=True)
    parser.add_argument("--c3-port", required=True)
    parser.add_argument("--previous-run", required=True, type=Path,
                        help="previous pair evidence directory or evidence.json")
    parser.add_argument("--reset-mode", required=True,
                        choices=("serial-reboot", "external-power", "none"))
    parser.add_argument("--evidence-dir", type=Path, default=Path("dev/evidence/espnow_dmp"))
    parser.add_argument("--timeout", type=float, default=70.0)
    parser.add_argument("--transfer-bytes", type=int, default=1024)
    parser.add_argument("--operator-confirms-power-cycle", action="store_true",
                        help="attest that both boards were unpowered for at least 5 seconds")
    args = parser.parse_args()
    if args.reset_mode == "external-power" and not args.operator_confirms_power_cycle:
        parser.error("external-power requires --operator-confirms-power-cycle")
    result = run_persistent_transition(
        s3_port=args.s3_port,
        c3_port=args.c3_port,
        previous_run=args.previous_run,
        reset_mode=args.reset_mode,
        evidence_dir=args.evidence_dir,
        timeout=args.timeout,
        transfer_bytes=args.transfer_bytes,
        operator_confirms_power_cycle=args.operator_confirms_power_cycle,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
