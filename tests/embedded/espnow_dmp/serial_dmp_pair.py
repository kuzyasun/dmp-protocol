#!/usr/bin/env python3
"""Hardware runner and event validator for authenticated DMP ESP-NOW S3/C3 pair.

Exercises:
1. Controller (S3) and Peer (C3) initialization and MTU / driver verification.
2. Station MAC and mutual unicast peer registration.
3. Monotonic SAMPLE-1 NVS epoch store and reservation check.
4. Real production SEC-1 Noise handshake establishment.
5. Authenticated SAMPLE-1 initialization READ request/response.
6. Authenticated Service-2 transfer up to 4096 bytes with 128-byte DMP fragments.
7. Verification that frames fit within ESP-NOW v1 bounds while explicitly
   reporting decoded Core MTU 256, Stream R MTU 263, ESP-NOW v1 250, and ESP-NOW v2 1470.
"""

from __future__ import annotations

import argparse
import json
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from serial_dmp_common import (
    DmpTestError,
    HostCommandLog,
    PAIR_CONTROLLER_NODE_ID,
    PAIR_PEER_NODE_ID,
    RETRY_2_PROFILE_HASH,
    SESSION_PATTERN,
    SerialDeviceSession,
    create_evidence_dir,
    default_serial_factory,
    validate_nvs_check,
    validate_ready_event,
    wait_for_handshake_result,
)

DEFAULT_S3_PORT = "COM37"
DEFAULT_C3_PORT = "COM36"
DEFAULT_TRANSFER_BYTES = 4096
CHUNK_BYTES = 128


def validate_dmp_pair_events(
    tagged_events: Iterable[tuple[str, dict[str, Any]]],
    bytes_to_transfer: int,
    session: str,
    count: int = 1,
    bidirectional: bool = False,
) -> dict[str, Any]:
    """Validate authenticated pair evidence from S3 controller and C3 peer."""
    if not SESSION_PATTERN.match(session):
        raise DmpTestError(f"Session token must be 16 lowercase hex characters, got {session!r}")

    by_side: dict[str, list[dict[str, Any]]] = {"s3": [], "c3": []}
    for side, event in tagged_events:
        if side in by_side and (event.get("event") == "ready" or event.get("session") == session):
            by_side[side].append(event)

    for side in ("s3", "c3"):
        failures = [
            e for e in by_side[side]
            if e.get("event") == "handshake_failed"
            or (e.get("event") == "error" and e.get("status") == "fail_closed")
        ]
        if failures:
            raise DmpTestError(f"{side.upper()} handshake failed: {failures[-1].get('reason', 'unspecified')}")

    def get_first_ready(side: str, target: str) -> dict[str, Any]:
        matches = [e for e in by_side[side] if e.get("event") == "ready"]
        if not matches:
            raise DmpTestError(f"{side.upper()} did not report ready")
        return validate_ready_event(matches[-1], target)

    s3_ready = get_first_ready("s3", "esp32s3")
    c3_ready = get_first_ready("c3", "esp32c3")

    s3_mac = str(s3_ready["mac"]).lower()
    c3_mac = str(c3_ready["mac"]).lower()
    if s3_mac == c3_mac:
        raise DmpTestError(f"S3 and C3 reported identical MAC address: {s3_mac}")

    # Validate session_set
    for side in ("s3", "c3"):
        sessions = [e for e in by_side[side] if e.get("event") == "session_set"]
        if len(sessions) != 1 or sessions[0].get("session") != session:
            raise DmpTestError(f"{side.upper()} did not confirm session {session}")

    # Validate role_set
    s3_roles = [e for e in by_side["s3"] if e.get("event") == "role_set"]
    if not s3_roles or s3_roles[-1].get("role") != "controller":
        raise DmpTestError("S3 did not confirm role 'controller'")
    if s3_roles[-1].get("profile") != "retry-2":
        raise DmpTestError(f"S3 did not use profile 'retry-2', got {s3_roles[-1].get('profile')!r}")
    if s3_roles[-1].get("profile_hash") != RETRY_2_PROFILE_HASH:
        raise DmpTestError(
            f"S3 profile hash mismatch: got {s3_roles[-1].get('profile_hash')!r}, expected {RETRY_2_PROFILE_HASH}"
        )
    if s3_roles[-1].get("node_id") is None:
        raise DmpTestError("S3 node_id missing from role_set")
    if s3_roles[-1].get("node_id") != PAIR_CONTROLLER_NODE_ID:
        raise DmpTestError(f"S3 node_id mismatch: got {s3_roles[-1].get('node_id')}, expected {PAIR_CONTROLLER_NODE_ID}")
    if s3_roles[-1].get("handshake_scratch_slots") != 1:
        raise DmpTestError("S3 retry-2 profile must report one handshake scratch slot")

    c3_roles = [e for e in by_side["c3"] if e.get("event") == "role_set"]
    if not c3_roles or c3_roles[-1].get("role") != "peer":
        raise DmpTestError("C3 did not confirm role 'peer'")
    if c3_roles[-1].get("profile") != "retry-2":
        raise DmpTestError(f"C3 did not use profile 'retry-2', got {c3_roles[-1].get('profile')!r}")
    if c3_roles[-1].get("profile_hash") != RETRY_2_PROFILE_HASH:
        raise DmpTestError(
            f"C3 profile hash mismatch: got {c3_roles[-1].get('profile_hash')!r}, expected {RETRY_2_PROFILE_HASH}"
        )
    if c3_roles[-1].get("node_id") is None:
        raise DmpTestError("C3 node_id missing from role_set")
    if c3_roles[-1].get("node_id") != PAIR_PEER_NODE_ID:
        raise DmpTestError(f"C3 node_id mismatch: got {c3_roles[-1].get('node_id')}, expected {PAIR_PEER_NODE_ID}")
    if c3_roles[-1].get("handshake_scratch_slots") != 1:
        raise DmpTestError("C3 retry-2 profile must report one handshake scratch slot")

    # Validate peer_added
    s3_peers = [e for e in by_side["s3"] if e.get("event") == "peer_added"]
    if not any(str(e.get("peer_mac", "")).lower() == c3_mac and e.get("node_id") == 20 for e in s3_peers):
        raise DmpTestError("S3 did not add C3 (node 20) as peer")

    c3_peers = [e for e in by_side["c3"] if e.get("event") == "peer_added"]
    if not any(str(e.get("peer_mac", "")).lower() == s3_mac and e.get("node_id") == 10 for e in c3_peers):
        raise DmpTestError("C3 did not add S3 (node 10) as peer")

    # Validate NVS check on S3 producer
    s3_nvs = [e for e in by_side["s3"] if e.get("event") == "nvs_epoch_check"]
    if not s3_nvs:
        raise DmpTestError("S3 producer did not report NVS epoch check")
    for nvs_ev in s3_nvs:
        validate_nvs_check(nvs_ev, session)

    # Validate Handshake
    s3_hs_start = [e for e in by_side["s3"] if e.get("event") == "handshake_started"]
    if not s3_hs_start:
        raise DmpTestError("S3 initiator did not start handshake")

    s3_hs_done = [e for e in by_side["s3"] if e.get("event") == "handshake_done"]
    if not s3_hs_done or s3_hs_done[-1].get("status") != "success":
        raise DmpTestError("S3 did not complete handshake with status success")

    c3_hs_done = [e for e in by_side["c3"] if e.get("event") == "handshake_done"]
    if not c3_hs_done or c3_hs_done[-1].get("status") != "success":
        raise DmpTestError("C3 did not complete handshake with status success")

    # Validate SAMPLE-1 read on C3 reader
    sample_submits = [e for e in by_side["c3"] if e.get("event") == "sample_read_submitted"]
    if not sample_submits or sample_submits[-1].get("status") != 0:
        raise DmpTestError("C3 reader did not successfully submit SAMPLE-1 READ request")

    sample_results = [e for e in by_side["c3"] if e.get("event") == "rx_result" and e.get("service_id") == 1]
    if not sample_results or sample_results[-1].get("wire_status") != 0:
        raise DmpTestError("C3 reader did not receive successful SAMPLE-1 result")
    if sample_results[-1].get("bytes") != 17:
        raise DmpTestError(
            f"SAMPLE-1 READ result bytes mismatch: expected 17 (DMP_SAMPLE1_READ_BYTES), got {sample_results[-1].get('bytes')}"
        )

    # Validate Service-2 transfer
    expected_fragments = (bytes_to_transfer + CHUNK_BYTES - 1) // CHUNK_BYTES
    s3_transfers_started = [e for e in by_side["s3"] if e.get("event") == "transfer_started"]
    if len(s3_transfers_started) != count:
        raise DmpTestError(
            f"S3 transfer_started count mismatch: got {len(s3_transfers_started)}, expected {count}"
        )
    for ev in s3_transfers_started:
        if ev.get("bytes") != bytes_to_transfer:
            raise DmpTestError(f"S3 did not report transfer_started for {bytes_to_transfer} bytes")

    c3_assembled = [
        e for e in by_side["c3"]
        if e.get("event") == "rx_assembled" and e.get("service_id") == 2
    ]
    if len(c3_assembled) != count:
        raise DmpTestError(
            f"C3 rx_assembled count mismatch: got {len(c3_assembled)}, expected {count}"
        )

    for ev in c3_assembled:
        if ev.get("bytes") != bytes_to_transfer:
            raise DmpTestError(f"C3 did not assemble Service-2 transfer of {bytes_to_transfer} bytes")
        if ev.get("fragments") != expected_fragments:
            raise DmpTestError(
                f"Fragment count mismatch on C3: expected {expected_fragments}, got {ev.get('fragments')}"
            )
        if ev.get("payload_match") is not True:
            raise DmpTestError("Assembled Service-2 payload on C3 does not match expected deterministic pattern")

    s3_assembled = [
        e for e in by_side["s3"]
        if e.get("event") == "rx_assembled" and e.get("service_id") == 2
    ]
    if bidirectional:
        c3_transfers_started = [e for e in by_side["c3"] if e.get("event") == "transfer_started"]
        if len(c3_transfers_started) != count:
            raise DmpTestError(
                f"C3 transfer_started count mismatch: got {len(c3_transfers_started)}, expected {count}"
            )
        for ev in c3_transfers_started:
            if ev.get("bytes") != bytes_to_transfer:
                raise DmpTestError(f"C3 did not report transfer_started for {bytes_to_transfer} bytes")
        if len(s3_assembled) != count:
            raise DmpTestError(
                f"S3 rx_assembled count mismatch: got {len(s3_assembled)}, expected {count}"
            )
        for ev in s3_assembled:
            if ev.get("bytes") != bytes_to_transfer:
                raise DmpTestError(f"S3 did not assemble Service-2 transfer of {bytes_to_transfer} bytes")
            if ev.get("fragments") != expected_fragments:
                raise DmpTestError(
                    f"Fragment count mismatch on S3: expected {expected_fragments}, got {ev.get('fragments')}"
                )
            if ev.get("payload_match") is not True:
                raise DmpTestError("Assembled Service-2 payload on S3 does not match expected deterministic pattern")

    # Native v2 frame validation
    v2_emitted = [e for e in by_side["s3"] + by_side["c3"] if e.get("event") == "v2_frame_emitted"]
    if not v2_emitted:
        raise DmpTestError("No native v2 frame emission recorded")
    for ev in v2_emitted:
        if ev.get("decoded_bytes") != 256:
            raise DmpTestError(f"v2 frame emitted decoded bytes mismatch: expected 256, got {ev.get('decoded_bytes')}")
        enc = ev.get("encoded_bytes", 0)
        if not (250 < enc <= 263):
            raise DmpTestError(f"v2 frame emitted encoded bytes not in (250, 263]: got {enc}")
        if ev.get("authenticated") is not False:
            raise DmpTestError("v2 frame emitted must report authenticated=false")

    v2_received = [e for e in by_side["s3"] + by_side["c3"] if e.get("event") == "v2_frame_received"]
    if not v2_received:
        raise DmpTestError("No native v2 frame reception recorded")
    for ev in v2_received:
        if ev.get("decoded_bytes") != 256:
            raise DmpTestError(f"v2 frame received decoded bytes mismatch: expected 256, got {ev.get('decoded_bytes')}")
        enc = ev.get("encoded_bytes", 0)
        if not (250 < enc <= 263):
            raise DmpTestError(f"v2 frame received encoded bytes not in (250, 263]: got {enc}")
        if ev.get("authenticated") is not False:
            raise DmpTestError("v2 frame received must report authenticated=false")
        if ev.get("classification") != "raw-v2-capability-probe":
            raise DmpTestError(
                f"v2 frame received classification mismatch: expected 'raw-v2-capability-probe', got {ev.get('classification')!r}"
            )

    # Frame size validation
    tx_frames = [e for e in by_side["s3"] + by_side["c3"] if e.get("event") == "tx_done"]
    frame_bytes_list = [e.get("frame_bytes") for e in tx_frames if isinstance(e.get("frame_bytes"), int)]
    for ev in v2_emitted:
        if isinstance(ev.get("encoded_bytes"), int):
            frame_bytes_list.append(ev["encoded_bytes"])
    max_frame = max(frame_bytes_list) if frame_bytes_list else 0
    if max_frame > 263:
        raise DmpTestError(f"Observed frame size {max_frame} exceeds Stream R MTU cap of 263 bytes")
    if max_frame <= 250:
        raise DmpTestError(
            f"Observed max frame {max_frame} did not exceed ESP-NOW v1 cap of 250 bytes; "
            "ESP-NOW v2 larger-payload capability was not exercised"
        )

    return {
        "result": "PASS",
        "test_mode": "authenticated-dmp-endpoint",
        "session": session,
        "s3_mac": s3_mac,
        "c3_mac": c3_mac,
        "s3_node_id": 10,
        "c3_node_id": 20,
        "peer_count": 1,
        "handshake_scratch_slots": 1,
        "channel": s3_ready["channel"],
        "transfer_bytes": bytes_to_transfer,
        "chunk_bytes": CHUNK_BYTES,
        "fragments": expected_fragments,
        "max_observed_frame_bytes": max_frame,
        "decoded_core_mtu_bytes": 256,
        "stream_r_encoded_mtu_bytes": 263,
        "espnow_v1_payload_mtu_bytes": 250,
        "espnow_v2_payload_mtu_bytes": 1470,
        "claims": {
            "authenticated_traffic": (
                "authenticated SEC-1 Noise handshake, SAMPLE-1 NVS epoch check, "
                f"protected Service-2 {bytes_to_transfer}B transfer"
            ),
            "unauthenticated_probe": (
                "raw-v2-capability-probe 256B frame exchange without session key authentication"
            ),
        },
        "authenticated_claim": (
            "authenticated SEC-1 Noise handshake, SAMPLE-1 NVS epoch check, "
            f"protected Service-2 {bytes_to_transfer}B transfer"
        ),
        "unauthenticated_claim": (
            "raw-v2-capability-probe 256B frame exchange without session key authentication"
        ),
        "security_claim": (
            "authenticated SEC-1 Noise handshake, SAMPLE-1 NVS epoch check, "
            f"protected Service-2 {bytes_to_transfer}B transfer; "
            "distinct unauthenticated raw-v2-capability-probe"
        ),
    }


def run_dmp_pair(
    s3_port: str,
    c3_port: str,
    count: int = 1,
    transfer_bytes: int = DEFAULT_TRANSFER_BYTES,
    evidence_dir: Path | str | None = None,
    timeout: float = 25.0,
    serial_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Execute authenticated pair qualification between S3 and C3 devices."""
    if not s3_port or not isinstance(s3_port, str) or not s3_port.strip():
        raise DmpTestError("Explicit S3 serial port is required")
    if not c3_port or not isinstance(c3_port, str) or not c3_port.strip():
        raise DmpTestError("Explicit C3 serial port is required")
    if s3_port.strip().lower() == c3_port.strip().lower():
        raise DmpTestError(f"S3 and C3 cannot use duplicate serial port {s3_port!r}")

    factory = serial_factory or default_serial_factory
    session = secrets.token_hex(8)
    ev_dir = create_evidence_dir(evidence_dir, prefix="pair")
    cmd_log = HostCommandLog(ev_dir / "commands.log")

    s3_dev: SerialDeviceSession | None = None
    c3_dev: SerialDeviceSession | None = None
    try:
        s3_raw = factory(s3_port, baudrate=115200, timeout=1.0)
        c3_raw = factory(c3_port, baudrate=115200, timeout=1.0)
        s3_dev = SerialDeviceSession("s3", s3_port, s3_raw, ev_dir, cmd_log)
        c3_dev = SerialDeviceSession("c3", c3_port, c3_raw, ev_dir, cmd_log)

        # 1. INFO: Verify target readiness and extract MAC addresses
        s3_dev.send_command("INFO")
        c3_dev.send_command("INFO")
        s3_ready = s3_dev.wait_for_event(
            lambda e: e.get("event") == "ready" and e.get("target") == "esp32s3",
            timeout=timeout,
            desc="ready on S3",
        )
        c3_ready = c3_dev.wait_for_event(
            lambda e: e.get("event") == "ready" and e.get("target") == "esp32c3",
            timeout=timeout,
            desc="ready on C3",
        )
        s3_mac = str(s3_ready["mac"]).lower()
        c3_mac = str(c3_ready["mac"]).lower()
        if s3_mac == c3_mac:
            raise DmpTestError(f"S3 and C3 reported duplicate MAC: {s3_mac}")

        # 2. SESSION: Establish matching session token
        s3_dev.send_command(f"SESSION {session}")
        c3_dev.send_command(f"SESSION {session}")
        s3_dev.wait_for_event(
            lambda e: e.get("event") == "session_set" and e.get("session") == session,
            timeout=timeout,
            desc="session_set on S3",
        )
        c3_dev.wait_for_event(
            lambda e: e.get("event") == "session_set" and e.get("session") == session,
            timeout=timeout,
            desc="session_set on C3",
        )

        # 3. ROLE: S3 controller (node 10), C3 peer/reader (node 20)
        s3_dev.send_command(f"ROLE controller retry-2 {PAIR_CONTROLLER_NODE_ID} 1")
        s3_dev.wait_for_event(
            lambda e: e.get("event") == "role_set" and e.get("session") == session,
            timeout=timeout,
            desc="role_set on S3",
        )
        c3_dev.send_command(f"ROLE peer retry-2 {PAIR_PEER_NODE_ID} 1")
        c3_dev.wait_for_event(
            lambda e: e.get("event") == "role_set" and e.get("session") == session,
            timeout=timeout,
            desc="role_set on C3",
        )

        # 4. PEER: S3 registers remote node 20; C3 registers remote node 10
        s3_dev.send_command(f"PEER {c3_mac} {PAIR_PEER_NODE_ID}")
        s3_dev.wait_for_event(
            lambda e: e.get("event") == "peer_added" and e.get("session") == session,
            timeout=timeout,
            desc="peer_added on S3",
        )
        c3_dev.send_command(f"PEER {s3_mac} {PAIR_CONTROLLER_NODE_ID}")
        c3_dev.wait_for_event(
            lambda e: e.get("event") == "peer_added" and e.get("session") == session,
            timeout=timeout,
            desc="peer_added on C3",
        )

        # 5. Handshake triggered at S3
        s3_dev.send_command("HANDSHAKE 0")
        s3_dev.wait_for_event(
            lambda e: e.get("event") == "handshake_started" and e.get("session") == session,
            timeout=timeout,
            desc="handshake_started on S3",
        )
        wait_for_handshake_result(
            s3_dev, session, timeout, "handshake completion on S3", peer_handle=0
        )
        wait_for_handshake_result(
            c3_dev, session, timeout, "handshake completion on C3", peer_handle=0
        )

        # 6. Producer NVS check at S3
        s3_dev.send_command("NVS_CHECK")
        s3_dev.wait_for_event(
            lambda e: e.get("event") == "nvs_epoch_check" and e.get("session") == session,
            timeout=timeout,
            desc="nvs_epoch_check on S3",
        )

        # 7. SAMPLE_READ on C3 reader
        c3_dev.send_command("SAMPLE_READ 0")
        c3_dev.wait_for_event(
            lambda e: e.get("event") == "sample_read_submitted" and e.get("session") == session,
            timeout=timeout,
            desc="sample_read_submitted on C3",
        )
        c3_dev.wait_for_event(
            lambda e: (
                e.get("event") == "rx_result"
                and e.get("session") == session
                and e.get("service_id") == 1
            ),
            timeout=timeout,
            desc="rx_result on C3",
        )

        # 8. Unauthenticated V2_FRAME probe separately
        s3_dev.send_command("V2_FRAME 0")
        s3_dev.wait_for_event(
            lambda e: e.get("event") == "v2_frame_emitted" and e.get("session") == session,
            timeout=timeout,
            desc="v2_frame_emitted on S3",
        )
        c3_dev.wait_for_event(
            lambda e: e.get("event") == "v2_frame_received" and e.get("session") == session,
            timeout=timeout,
            desc="v2_frame_received on C3",
        )

        # 9. Authenticated Service-2 bidirectional transfer
        for iter_idx in range(count):
            s3_idx = s3_dev.event_count
            c3_idx = c3_dev.event_count
            # Forward: S3 -> C3
            s3_dev.send_command(f"TRANSFER 0 {transfer_bytes}")
            s3_dev.wait_for_event(
                lambda e: e.get("event") == "transfer_started" and e.get("session") == session,
                timeout=timeout,
                desc=f"transfer_started on S3 (iter {iter_idx})",
                start_index=s3_idx,
            )
            c3_dev.wait_for_event(
                lambda e: (
                    e.get("event") == "rx_assembled"
                    and e.get("session") == session
                    and e.get("service_id") == 2
                ),
                timeout=timeout,
                desc=f"rx_assembled on C3 (iter {iter_idx})",
                start_index=c3_idx,
            )
            s3_idx = s3_dev.event_count
            c3_idx = c3_dev.event_count
            # Reverse: C3 -> S3
            c3_dev.send_command(f"TRANSFER 0 {transfer_bytes}")
            c3_dev.wait_for_event(
                lambda e: e.get("event") == "transfer_started" and e.get("session") == session,
                timeout=timeout,
                desc=f"transfer_started on C3 (iter {iter_idx})",
                start_index=c3_idx,
            )
            s3_dev.wait_for_event(
                lambda e: (
                    e.get("event") == "rx_assembled"
                    and e.get("session") == session
                    and e.get("service_id") == 2
                ),
                timeout=timeout,
                desc=f"rx_assembled on S3 (iter {iter_idx})",
                start_index=s3_idx,
            )

        tagged_events = (
            [("s3", ev) for ev in s3_dev.get_events()]
            + [("c3", ev) for ev in c3_dev.get_events()]
        )
        result = validate_dmp_pair_events(
            tagged_events,
            transfer_bytes,
            session,
            count=count,
            bidirectional=True,
        )
        result["evidence_dir"] = str(ev_dir)

        evidence_file = ev_dir / "evidence.json"
        evidence_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    finally:
        if s3_dev is not None:
            s3_dev.close()
        if c3_dev is not None:
            c3_dev.close()
        cmd_log.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Authenticated DMP ESP-NOW Pair Runner")
    parser.add_argument("--s3-port", required=True, help="Serial port for ESP32-S3")
    parser.add_argument("--c3-port", required=True, help="Serial port for ESP32-C3")
    parser.add_argument("--count", type=int, default=1, help="Bidirectional transfer count")
    parser.add_argument("--transfer-bytes", type=int, default=DEFAULT_TRANSFER_BYTES, help="Payload bytes")
    parser.add_argument("--evidence-dir", type=Path, default=None, help="Evidence directory")
    parser.add_argument("--timeout", type=float, default=25.0, help="Operation timeout in seconds")
    args = parser.parse_args()

    result = run_dmp_pair(
        s3_port=args.s3_port,
        c3_port=args.c3_port,
        count=args.count,
        transfer_bytes=args.transfer_bytes,
        evidence_dir=args.evidence_dir,
        timeout=args.timeout,
    )
    print(json.dumps(result, indent=2))
