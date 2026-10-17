#!/usr/bin/env python3
"""Hardware runner and event validator for multi-peer DMP ESP-NOW qualification.

Supports three qualification patterns:
1. four_serial: S3 controller executes sequential authenticated transfers to 4 peers.
2. four_parallel: S3 controller executes concurrent authenticated transfers to 4 peers.
3. three_peer_serial: S3 controller executes sequential authenticated transfers to 3 peers.

Validates that:
- One S3 controller coordinates authenticated peers (3 or 4 peers depending on mode).
- Each peer performs a real SEC-1 Noise handshake.
- High-volume Service-2 transfers (up to 4096 bytes with 128-byte DMP fragments) assemble
  correctly on all peers.
  - Every observed physical frame stays within the Stream R encoded MTU of 263 bytes.
    This runner does not claim that every frame fits the ESP-NOW v1 250-byte limit.
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
    FOUR_CONTROLLER_NODE_ID,
    FOUR_PEER_NODE_IDS,
    HostCommandLog,
    MULTI_PEER_EPOCH_NVS_KEY,
    MULTI_PEER_PROFILE_HASH,
    SESSION_PATTERN,
    SerialDeviceSession,
    create_evidence_dir,
    default_serial_factory,
    validate_nvs_check,
    validate_ready_event,
    wait_for_handshake_start,
    wait_for_handshake_pair,
)

DEFAULT_BYTES_PER_PEER = 4096
CHUNK_BYTES = 128


def validate_dmp_four_events(
    tagged_events: Iterable[tuple[str, dict[str, Any]]],
    mode: str,
    peer_count: int,
    bytes_per_peer: int,
    session: str,
    count_per_peer: int = 1,
) -> dict[str, Any]:
    """Validate qualification events in four_serial, four_parallel, or three_peer_serial mode."""
    if mode not in ("four_serial", "four_parallel", "three_peer_serial"):
        raise DmpTestError(
            f"Invalid mode {mode!r}; expected 'four_serial', 'four_parallel', or 'three_peer_serial'"
        )
    if mode in ("four_serial", "four_parallel") and peer_count != 4:
        raise DmpTestError(f"Four-peer qualification requires exactly 4 peers; got {peer_count}")
    if mode == "three_peer_serial" and peer_count != 3:
        raise DmpTestError(f"Three-peer qualification requires exactly 3 peers; got {peer_count}")
    if not SESSION_PATTERN.match(session):
        raise DmpTestError(f"Session token must be 16 lowercase hex characters, got {session!r}")

    by_side: dict[str, list[dict[str, Any]]] = {}
    for side, event in tagged_events:
        if event.get("event") == "ready" or event.get("session") == session:
            by_side.setdefault(side, []).append(event)

    for side, events in by_side.items():
        failures = [
            e for e in events
            if e.get("event") == "handshake_failed"
            or (e.get("event") == "error" and e.get("status") == "fail_closed")
        ]
        if failures:
            failure = failures[-1]
            peer_handle = failure.get("peer_handle")
            peer_text = f" for peer handle {peer_handle}" if peer_handle is not None else ""
            raise DmpTestError(
                f"{side} handshake failed{peer_text}: {failure.get('reason', 'unspecified')}"
            )

    if "s3" not in by_side:
        raise DmpTestError("Controller (S3) events missing")

    # Validate controller ready
    s3_readies = [e for e in by_side["s3"] if e.get("event") == "ready"]
    if not s3_readies:
        raise DmpTestError("S3 controller did not report ready")
    s3_ready = validate_ready_event(s3_readies[-1], "esp32s3")
    s3_mac = str(s3_ready["mac"]).lower()

    # Validate peer readies - exactly peer_count peers
    peer_sides = [side for side in sorted(by_side.keys()) if side != "s3"]
    if len(peer_sides) != peer_count:
        if peer_count == 4:
            raise DmpTestError(f"Expected exactly 4 peer streams, found {len(peer_sides)}")
        else:
            raise DmpTestError(f"Expected exactly {peer_count} peer streams, found {len(peer_sides)}")

    peer_macs: list[str] = []
    for side in peer_sides:
        readies = [e for e in by_side[side] if e.get("event") == "ready"]
        if not readies:
            raise DmpTestError(f"Peer {side} did not report ready")
        p_ready = validate_ready_event(readies[-1], "esp32c3")
        mac = str(p_ready["mac"]).lower()
        if mac == s3_mac or mac in peer_macs:
            raise DmpTestError(f"Duplicate or controller-matching MAC: {mac}")
        peer_macs.append(mac)

    # Validate session_set and role_set on all sides
    for side in ["s3"] + peer_sides:
        sessions = [e for e in by_side[side] if e.get("event") == "session_set"]
        if len(sessions) != 1 or sessions[0].get("session") != session:
            raise DmpTestError(f"{side} did not confirm session {session}")

    s3_role = [e for e in by_side["s3"] if e.get("event") == "role_set"]
    if not s3_role or s3_role[-1].get("role") != "controller":
        raise DmpTestError("S3 did not confirm role 'controller'")
    if s3_role[-1].get("profile") != "multi-peer":
        raise DmpTestError(f"S3 did not use profile 'multi-peer', got {s3_role[-1].get('profile')!r}")
    if s3_role[-1].get("profile_hash") != MULTI_PEER_PROFILE_HASH:
        raise DmpTestError(
            f"S3 profile hash mismatch: got {s3_role[-1].get('profile_hash')!r}, expected {MULTI_PEER_PROFILE_HASH}"
        )
    if s3_role[-1].get("node_id") is None:
        raise DmpTestError("S3 controller node_id missing from role_set")
    if s3_role[-1].get("node_id") != FOUR_CONTROLLER_NODE_ID:
        raise DmpTestError(f"S3 controller node_id mismatch: got {s3_role[-1].get('node_id')}, expected {FOUR_CONTROLLER_NODE_ID}")
    expected_scratch_slots = 1 if mode in ("four_serial", "three_peer_serial") else 2
    if s3_role[-1].get("handshake_scratch_slots") != expected_scratch_slots:
        raise DmpTestError(
            f"S3 {mode} handshake scratch slots mismatch: expected {expected_scratch_slots}, "
            f"got {s3_role[-1].get('handshake_scratch_slots')}"
        )

    peer_node_ids: list[int] = []
    for side in peer_sides:
        p_role = [e for e in by_side[side] if e.get("event") == "role_set"]
        if not p_role or p_role[-1].get("role") != "peer":
            raise DmpTestError(f"Peer {side} did not confirm role 'peer'")
        if p_role[-1].get("profile") != "multi-peer":
            raise DmpTestError(f"Peer {side} did not use profile 'multi-peer', got {p_role[-1].get('profile')!r}")
        if p_role[-1].get("profile_hash") != MULTI_PEER_PROFILE_HASH:
            raise DmpTestError(
                f"Peer {side} profile hash mismatch: got {p_role[-1].get('profile_hash')!r}, expected {MULTI_PEER_PROFILE_HASH}"
            )
        n_id = p_role[-1].get("node_id")
        if n_id is None:
            raise DmpTestError(f"Peer {side} node_id missing from role_set")
        if n_id not in FOUR_PEER_NODE_IDS:
            raise DmpTestError(f"Peer {side} node_id {n_id} not in allowed multi-peer set {FOUR_PEER_NODE_IDS}")
        if p_role[-1].get("handshake_scratch_slots") != 1:
            raise DmpTestError(f"Peer {side} must report one handshake scratch slot")
        if n_id in peer_node_ids:
            raise DmpTestError(f"Duplicate peer node_id detected: {n_id}")
        peer_node_ids.append(n_id)

    if len(peer_node_ids) != peer_count:
        if peer_count == 4:
            raise DmpTestError("Four-peer qualification requires exactly 4 distinct peer node IDs")
        else:
            raise DmpTestError(
                f"Three-peer qualification requires exactly 3 distinct peer node IDs, got {len(peer_node_ids)}"
            )

    # Validate peer registrations
    s3_peers_added = [e for e in by_side["s3"] if e.get("event") == "peer_added"]
    if len(s3_peers_added) != peer_count:
        raise DmpTestError(
            f"S3 registered {len(s3_peers_added)} peers, expected exactly {peer_count}"
        )

    # Each handshake adapter owns Stream R synchronization state per peer.
    s3_syncs = {
        e.get("peer_handle") for e in by_side["s3"]
        if e.get("event") == "handshake_stream_sync_done"
        and e.get("session") == session and e.get("status") == "success"
    }
    if not set(range(peer_count)).issubset(s3_syncs):
        if peer_count == 4:
            raise DmpTestError("S3 did not synchronize all four handshake Stream R peer bindings")
        else:
            raise DmpTestError(f"S3 did not synchronize all {peer_count} handshake Stream R peer bindings")
    for side in peer_sides:
        peer_syncs = [
            e for e in by_side[side]
            if e.get("event") == "handshake_stream_sync_done"
            and e.get("session") == session and e.get("status") == "success"
            and e.get("peer_handle") == 0
        ]
        if not peer_syncs:
            raise DmpTestError(f"Peer {side} did not synchronize its handshake Stream R binding")

    # Validate NVS checks
    nvs_events = [e for evs in by_side.values() for e in evs if e.get("event") == "nvs_epoch_check"]
    if not nvs_events:
        if peer_count == 4:
            raise DmpTestError("No NVS epoch check evidence found in 4-peer run")
        else:
            raise DmpTestError(f"No NVS epoch check evidence found in {mode} run")
    for nvs_ev in nvs_events:
        validate_nvs_check(nvs_ev, session, expected_key=MULTI_PEER_EPOCH_NVS_KEY)
    s3_nvs_events = [
        event for event in by_side["s3"] if event.get("event") == "nvs_epoch_check"
    ]
    if len(nvs_events) != 1 or len(s3_nvs_events) != 1:
        raise DmpTestError(
            "Multi-peer SAMPLE-1 epoch must be reserved exactly once by the S3 producer"
        )

    # Validate Handshakes for each peer
    for i in range(peer_count):
        s3_hs_dones = [
            e for e in by_side["s3"]
            if e.get("event") == "handshake_done"
            and e.get("status") == "success"
            and e.get("peer_handle") == i
        ]
        if not s3_hs_dones:
            raise DmpTestError(f"S3 did not complete handshake with peer handle {i}")

    for side in peer_sides:
        p_hs_done = [e for e in by_side[side] if e.get("event") == "handshake_done" and e.get("status") == "success"]
        if not p_hs_done:
            raise DmpTestError(f"Peer {side} did not complete handshake with status success")
        ready_submits = [e for e in by_side[side] if e.get("event") == "handshake_ready_submit"]
        if not any(e.get("accepted") is True for e in ready_submits):
            raise DmpTestError(f"Peer {side} did not accept protected READY transport submission")

    # Exercise one authenticated SAMPLE-1 initialization READ from each peer.
    s3_events = by_side["s3"]
    sample_requests = [
        event for event in s3_events
        if event.get("event") == "rx_request" and event.get("service_id") == 1
    ]
    if len(sample_requests) != peer_count:
        raise DmpTestError(
            f"S3 received {len(sample_requests)} SAMPLE-1 READ requests, expected {peer_count}"
        )
    if {event.get("peer_handle") for event in sample_requests} != set(range(peer_count)):
        raise DmpTestError("SAMPLE-1 READ requests were not mapped one-to-one to peer handles")
    if any(event.get("bytes") != 1 for event in sample_requests):
        raise DmpTestError("SAMPLE-1 READ request body length mismatch")

    first_transfer_index = next(
        (index for index, event in enumerate(s3_events) if event.get("event") == "transfer_started"),
        len(s3_events),
    )
    for peer_idx, side in enumerate(peer_sides):
        submits = [
            event for event in by_side[side]
            if event.get("event") == "sample_read_submitted"
        ]
        if len(submits) != 1 or submits[0].get("peer_handle") != 0:
            raise DmpTestError(f"Peer {side} did not submit exactly one SAMPLE-1 READ to handle 0")
        if submits[0].get("status") != 0:
            raise DmpTestError(f"Peer {side} SAMPLE-1 READ submission failed")

        results = [
            event for event in by_side[side]
            if event.get("event") == "rx_result" and event.get("service_id") == 1
        ]
        if len(results) != 1 or results[0].get("peer_handle") != 0:
            raise DmpTestError(f"Peer {side} did not receive exactly one SAMPLE-1 result")
        if results[0].get("wire_status") != 0 or results[0].get("bytes") != 17:
            raise DmpTestError(f"Peer {side} SAMPLE-1 READ result was unsuccessful or malformed")

        request = next(
            event for event in sample_requests if event.get("peer_handle") == peer_idx
        )
        request_index = s3_events.index(request)
        response_tx = next(
            (
                (index, event)
                for index, event in enumerate(s3_events[request_index + 1 :], request_index + 1)
                if event.get("event") == "tx_done" and event.get("peer_handle") == peer_idx
            ),
            None,
        )
        if response_tx is None or response_tx[0] >= first_transfer_index:
            raise DmpTestError(f"S3 did not complete SAMPLE-1 response TX for peer handle {peer_idx}")
        if response_tx[1].get("status") != "success" or response_tx[1].get("transport_outcome") != "transmitted":
            raise DmpTestError(f"S3 SAMPLE-1 response TX failed for peer handle {peer_idx}")

    # Validate transfers - mapping every transfer_started and assembly to correct peer
    expected_fragments = (bytes_per_peer + CHUNK_BYTES - 1) // CHUNK_BYTES

    # Validate S3 transfer_started events mapped to each peer
    for i in range(peer_count):
        expected_mac = peer_macs[i]
        s3_transfers = [
            e for e in by_side["s3"]
            if e.get("event") == "transfer_started" and e.get("peer_handle") == i
        ]
        if len(s3_transfers) != count_per_peer:
            raise DmpTestError(
                f"S3 transfer_started count mismatch for peer handle {i}: "
                f"expected {count_per_peer}, got {len(s3_transfers)}"
            )
        for ev in s3_transfers:
            if str(ev.get("peer_mac", "")).lower() != expected_mac:
                raise DmpTestError(
                    f"Cross-peer transfer detected on S3 for handle {i}: "
                    f"expected MAC {expected_mac}, got {ev.get('peer_mac')}"
                )
            if ev.get("bytes") != bytes_per_peer:
                raise DmpTestError(
                    f"S3 transfer bytes mismatch for peer {i}: expected {bytes_per_peer}, got {ev.get('bytes')}"
                )
            if ev.get("fragments") != expected_fragments:
                raise DmpTestError(
                    f"S3 fragment count mismatch for peer {i}: expected {expected_fragments}, got {ev.get('fragments')}"
                )
    # Validate rx_assembled on each peer
    for i, side in enumerate(peer_sides):
        assembled = [
            e for e in by_side[side]
            if e.get("event") == "rx_assembled" and e.get("service_id") == 2
        ]
        if len(assembled) != count_per_peer:
            raise DmpTestError(
                f"Peer {side} assembled {len(assembled)} transfers, expected {count_per_peer}"
            )
        for ev in assembled:
            if ev.get("bytes") != bytes_per_peer:
                raise DmpTestError(f"Peer {side} did not assemble {bytes_per_peer} bytes in {mode}")
            if ev.get("fragments") != expected_fragments:
                raise DmpTestError(f"Peer {side} fragment count mismatch")
            if ev.get("payload_match") is not True:
                raise DmpTestError(f"Peer {side} payload mismatch: did not match deterministic pattern")
            if ev.get("peer_handle") != 0:
                raise DmpTestError(f"Peer {side} assembled transfer from unexpected peer_handle {ev.get('peer_handle')}")

    # Frame size check
    all_events = [e for evs in by_side.values() for e in evs]
    tx_frames = [e for e in all_events if e.get("event") == "tx_done"]
    frame_bytes_list = [e.get("frame_bytes") for e in tx_frames if isinstance(e.get("frame_bytes"), int)]
    max_frame = max(frame_bytes_list) if frame_bytes_list else 0
    if max_frame > 263:
        raise DmpTestError(f"Observed frame size {max_frame} exceeds Stream R MTU limit 263")

    total_boards = peer_count + 1
    return {
        "result": "PASS",
        "mode": mode,
        "session": session,
        "total_boards": total_boards,
        "peer_count": peer_count,
        "controller_node_id": FOUR_CONTROLLER_NODE_ID,
        "controller_handshake_scratch_slots": expected_scratch_slots,
        "peer_node_ids": peer_node_ids or list(FOUR_PEER_NODE_IDS[:peer_count]),
        "count_per_peer": count_per_peer,
        "sample1_read_peer_count": peer_count,
        "s3_mac": s3_mac,
        "peer_macs": peer_macs,
        "bytes_per_peer": bytes_per_peer,
        "chunk_bytes": CHUNK_BYTES,
        "fragments_per_peer": expected_fragments,
        "max_observed_frame_bytes": max_frame,
        "decoded_core_mtu_bytes": 256,
        "stream_r_encoded_mtu_bytes": 263,
        "espnow_v1_payload_mtu_bytes": 250,
        "espnow_v2_payload_mtu_bytes": 1470,
        "boards_description": (
            f"{total_boards} physical boards total: 1 ESP32-S3 controller (node {FOUR_CONTROLLER_NODE_ID}) "
            f"and {peer_count} ESP32-C3 peers"
        ),
        "security_claim": (
            f"authenticated SEC-1 Noise handshakes across {peer_count} peers, "
            f"SAMPLE-1 epoch reservation and READ across {peer_count} peers, "
            f"protected Service-2 transfers ({mode})"
        ),
    }


def run_dmp_four(
    s3_port: str,
    c3_ports: dict[int | str, str] | list[str] | tuple[str, ...],
    mode: str = "four_serial",
    count_per_peer: int = 1,
    bytes_per_peer: int = DEFAULT_BYTES_PER_PEER,
    evidence_dir: Path | str | None = None,
    timeout: float = 60.0,
    serial_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Execute authenticated multi-peer qualification between 1 S3 and 3 or 4 C3 devices."""
    if not s3_port or not isinstance(s3_port, str) or not s3_port.strip():
        raise DmpTestError("Explicit S3 serial port is required")

    if mode not in ("four_serial", "four_parallel", "three_peer_serial"):
        raise DmpTestError(
            f"Invalid mode {mode!r}; expected 'four_serial', 'four_parallel', or 'three_peer_serial'"
        )

    expected_peers = 3 if mode == "three_peer_serial" else 4

    if isinstance(c3_ports, dict):
        try:
            c3_map = {int(k): str(v) for k, v in c3_ports.items()}
        except Exception as exc:
            raise DmpTestError(f"Invalid C3 port mapping: {exc}") from exc
        if expected_peers == 4:
            if set(c3_map.keys()) != set(FOUR_PEER_NODE_IDS):
                raise DmpTestError(
                    f"C3 port mapping keys must be {set(FOUR_PEER_NODE_IDS)}, got {set(c3_map.keys())}"
                )
            peer_mapping = [(node_id, c3_map[node_id]) for node_id in FOUR_PEER_NODE_IDS]
        else:
            if len(c3_map) != 3 or not set(c3_map.keys()).issubset(set(FOUR_PEER_NODE_IDS)):
                raise DmpTestError(
                    f"Three-peer qualification requires exactly 3 C3 ports with keys from {set(FOUR_PEER_NODE_IDS)}, got {set(c3_map.keys())}"
                )
            peer_mapping = [
                (node_id, c3_map[node_id])
                for node_id in sorted(c3_map.keys(), key=lambda nid: FOUR_PEER_NODE_IDS.index(nid))
            ]
    elif isinstance(c3_ports, (list, tuple)):
        if expected_peers == 4:
            if len(c3_ports) != 4:
                raise DmpTestError(
                    f"Four-peer qualification requires exactly 4 C3 ports, got {len(c3_ports)}"
                )
            peer_mapping = list(zip(FOUR_PEER_NODE_IDS, [str(p) for p in c3_ports]))
        else:
            if len(c3_ports) != 3:
                raise DmpTestError(
                    f"Three-peer qualification requires exactly 3 C3 ports, got {len(c3_ports)}"
                )
            peer_mapping = list(zip(FOUR_PEER_NODE_IDS[:3], [str(p) for p in c3_ports]))
    else:
        raise DmpTestError(f"c3_ports must be a dict or a {expected_peers}-element sequence")

    all_ports = [s3_port] + [port for _, port in peer_mapping]
    for p in all_ports:
        if not p or not p.strip():
            raise DmpTestError("Explicit serial port required for all devices")
    norm_ports = [p.strip().lower() for p in all_ports]
    expected_total_ports = expected_peers + 1
    if len(set(norm_ports)) != expected_total_ports:
        if expected_peers == 4:
            raise DmpTestError(
                f"S3 and 4 C3 devices must use 5 distinct serial ports; detected duplicates in {all_ports}"
            )
        else:
            raise DmpTestError(
                f"S3 and 3 C3 devices must use 4 distinct serial ports; detected duplicates in {all_ports}"
            )

    factory = serial_factory or default_serial_factory
    session = secrets.token_hex(8)
    dir_prefix = mode if mode == "three_peer_serial" else f"four_{mode}"
    ev_dir = create_evidence_dir(evidence_dir, prefix=dir_prefix)
    cmd_log = HostCommandLog(ev_dir / "commands.log")

    s3_dev: SerialDeviceSession | None = None
    c3_devs: list[SerialDeviceSession] = []
    try:
        s3_raw = factory(s3_port, baudrate=115200, timeout=1.0)
        s3_dev = SerialDeviceSession(
            "s3", s3_port, s3_raw, ev_dir, cmd_log, expected_session=session
        )

        for i, (node_id, port) in enumerate(peer_mapping):
            raw = factory(port, baudrate=115200, timeout=1.0)
            dev = SerialDeviceSession(
                f"c3_{i}", port, raw, ev_dir, cmd_log, expected_session=session
            )
            c3_devs.append(dev)

        # 1. INFO: Verify target readiness and extract MAC addresses
        s3_dev.send_command("INFO")
        for dev in c3_devs:
            dev.send_command("INFO")

        s3_ready = s3_dev.wait_for_event(
            lambda e: e.get("event") == "ready" and e.get("target") == "esp32s3",
            timeout=timeout,
            desc="ready on S3",
        )
        s3_mac = str(s3_ready["mac"]).lower()

        c3_macs: list[str] = []
        for i, dev in enumerate(c3_devs):
            ready = dev.wait_for_event(
                lambda e: e.get("event") == "ready" and e.get("target") == "esp32c3",
                timeout=timeout,
                desc=f"ready on c3_{i}",
            )
            mac = str(ready["mac"]).lower()
            if mac == s3_mac or mac in c3_macs:
                raise DmpTestError(f"Duplicate MAC detected: {mac}")
            c3_macs.append(mac)

        # 2. SESSION: Establish matching session token on all boards
        s3_dev.send_command(f"SESSION {session}")
        for dev in c3_devs:
            dev.send_command(f"SESSION {session}")

        s3_dev.wait_for_event(
            lambda e: e.get("event") == "session_set" and e.get("session") == session,
            timeout=timeout,
            desc="session_set on S3",
        )
        for i, dev in enumerate(c3_devs):
            dev.wait_for_event(
                lambda e: e.get("event") == "session_set" and e.get("session") == session,
                timeout=timeout,
                desc=f"session_set on c3_{i}",
            )

        # 3. ROLE: S3 controller (node 20), C3 peers
        controller_scratch_slots = 1 if mode in ("four_serial", "three_peer_serial") else 2
        s3_dev.send_command(
            f"ROLE controller multi-peer {FOUR_CONTROLLER_NODE_ID} {controller_scratch_slots}"
        )
        s3_dev.wait_for_event(
            lambda e: e.get("event") == "role_set" and e.get("session") == session,
            timeout=timeout,
            desc="role_set on S3",
        )
        for i, (node_id, _) in enumerate(peer_mapping):
            c3_devs[i].send_command(f"ROLE peer multi-peer {node_id} 1")
            c3_devs[i].wait_for_event(
                lambda e: e.get("event") == "role_set" and e.get("session") == session,
                timeout=timeout,
                desc=f"role_set on c3_{i}",
            )

        # 4. PEER: S3 registers peers; each C3 registers S3
        for i, (node_id, _) in enumerate(peer_mapping):
            s3_dev.send_command(f"PEER {c3_macs[i]} {node_id}")
            s3_dev.wait_for_event(
                lambda e: (
                    e.get("event") == "peer_added"
                    and e.get("session") == session
                    and e.get("node_id") == node_id
                ),
                timeout=timeout,
                desc=f"peer_added on S3 for peer {i}",
            )
            c3_devs[i].send_command(f"PEER {s3_mac} {FOUR_CONTROLLER_NODE_ID}")
            c3_devs[i].wait_for_event(
                lambda e: (
                    e.get("event") == "peer_added"
                    and e.get("session") == session
                    and e.get("node_id") == FOUR_CONTROLLER_NODE_ID
                ),
                timeout=timeout,
                desc=f"peer_added on c3_{i}",
            )

        # Synchronize adapters after all peer registrations
        for i in range(expected_peers):
            s3_dev.send_command(f"HS_SYNC {i}")
            s3_dev.wait_for_event(
                lambda e: (
                    e.get("event") == "handshake_stream_sync_done"
                    and e.get("session") == session
                    and e.get("peer_handle") == i
                    and e.get("status") == "success"
                ),
                timeout=timeout,
                desc=f"handshake Stream R sync on S3 for peer {i}",
            )
            c3_devs[i].send_command("HS_SYNC 0")
            c3_devs[i].wait_for_event(
                lambda e: (
                    e.get("event") == "handshake_stream_sync_done"
                    and e.get("session") == session
                    and e.get("peer_handle") == 0
                    and e.get("status") == "success"
                ),
                timeout=timeout,
                desc=f"handshake Stream R sync on c3_{i}",
            )

        # 5. Handshakes for all peers
        for i in range(expected_peers):
            s3_dev.send_command(f"HANDSHAKE {i}")
            wait_for_handshake_start(
                s3_dev,
                session,
                timeout=timeout,
                desc=f"handshake_started on S3 for peer {i}",
                peer_handle=i,
            )
            wait_for_handshake_pair(
                s3_dev,
                c3_devs[i],
                session,
                timeout,
                f"handshake with c3_{i}",
                i,
                0,
            )

        # 6. Producer NVS check at S3
        s3_dev.send_command("NVS_CHECK")
        s3_dev.wait_for_event(
            lambda e: e.get("event") == "nvs_epoch_check" and e.get("session") == session,
            timeout=timeout,
            desc="nvs_epoch_check on S3",
        )

        # 7. SAMPLE_READ on each C3 reader
        for i, dev in enumerate(c3_devs):
            s3_sample_start = s3_dev.event_count
            c3_sample_start = dev.event_count
            dev.send_command("SAMPLE_READ 0")
            sample_submit = dev.wait_for_event(
                lambda e: e.get("event") == "sample_read_submitted" and e.get("session") == session,
                timeout=timeout,
                desc=f"sample_read_submitted on c3_{i}",
                start_index=c3_sample_start,
            )
            if sample_submit.get("status") != 0:
                raise DmpTestError(
                    f"c3_{i} SAMPLE-1 READ submission failed with DMP status {sample_submit.get('status')!r}"
                )
            s3_sample_request = s3_dev.wait_for_event(
                lambda e: (
                    e.get("event") == "rx_request"
                    and e.get("session") == session
                    and e.get("peer_handle") == i
                    and e.get("service_id") == 1
                ),
                timeout=timeout,
                desc=f"SAMPLE-1 READ request on S3 from c3_{i}",
                start_index=s3_sample_start,
            )
            s3_sample_events = s3_dev.get_events()
            request_index = next(
                index for index in range(s3_sample_start, len(s3_sample_events))
                if s3_sample_events[index] is s3_sample_request
            )
            sample_result = dev.wait_for_event(
                lambda e: (
                    e.get("event") == "rx_result"
                    and e.get("session") == session
                    and e.get("service_id") == 1
                ),
                timeout=timeout,
                desc=f"SAMPLE-1 READ result on c3_{i}",
                start_index=c3_sample_start,
            )
            if sample_result.get("wire_status") != 0 or sample_result.get("bytes") != 17:
                raise DmpTestError(f"c3_{i} SAMPLE-1 READ returned an unsuccessful or malformed result")
            s3_sample_tx = s3_dev.wait_for_event(
                lambda e: (
                    e.get("event") == "tx_done"
                    and e.get("session") == session
                    and e.get("peer_handle") == i
                ),
                timeout=timeout,
                desc=f"SAMPLE-1 response TX completion on S3 for c3_{i}",
                start_index=request_index + 1,
            )
            if s3_sample_tx.get("status") != "success" or s3_sample_tx.get("transport_outcome") != "transmitted":
                raise DmpTestError(f"S3 SAMPLE-1 response transport failed for c3_{i}")

        # 8. Transfers using individual TRANSFER commands
        if mode in ("four_serial", "three_peer_serial"):
            for c in range(count_per_peer):
                for i in range(expected_peers):
                    s3_idx = s3_dev.event_count
                    c3_idx = c3_devs[i].event_count
                    s3_dev.send_command(f"TRANSFER {i} {bytes_per_peer}")
                    s3_dev.wait_for_event(
                        lambda e: (
                            e.get("event") == "transfer_started"
                            and e.get("session") == session
                            and e.get("peer_handle") == i
                        ),
                        timeout=timeout,
                        desc=f"transfer_started on S3 for peer {i} (iter {c})",
                        start_index=s3_idx,
                    )
                    c3_devs[i].wait_for_event(
                        lambda e: (
                            e.get("event") == "rx_assembled"
                            and e.get("session") == session
                            and e.get("service_id") == 2
                            and e.get("bytes") == bytes_per_peer
                        ),
                        timeout=timeout,
                        desc=f"rx_assembled on c3_{i} (iter {c})",
                        start_index=c3_idx,
                    )
        else:
            for c in range(count_per_peer):
                c3_start_indices = [dev.event_count for dev in c3_devs]
                # Submit one transfer for all peers as a batch
                for i in range(expected_peers):
                    s3_idx = s3_dev.event_count
                    s3_dev.send_command(f"TRANSFER {i} {bytes_per_peer}")
                    s3_dev.wait_for_event(
                        lambda e: (
                            e.get("event") == "transfer_started"
                            and e.get("session") == session
                            and e.get("peer_handle") == i
                        ),
                        timeout=timeout,
                        desc=f"transfer_started on S3 for peer {i} (iter {c})",
                        start_index=s3_idx,
                    )
                # Wait for all assemblies
                for i in range(expected_peers):
                    c3_devs[i].wait_for_event(
                        lambda e: (
                            e.get("event") == "rx_assembled"
                            and e.get("session") == session
                            and e.get("service_id") == 2
                            and e.get("bytes") == bytes_per_peer
                        ),
                        timeout=timeout,
                        desc=f"rx_assembled on c3_{i} (iter {c})",
                        start_index=c3_start_indices[i],
                    )

        tagged_events = [("s3", ev) for ev in s3_dev.get_events()]
        for i, dev in enumerate(c3_devs):
            tagged_events.extend([(f"c3_{i}", ev) for ev in dev.get_events()])

        result = validate_dmp_four_events(
            tagged_events,
            mode=mode,
            peer_count=expected_peers,
            bytes_per_peer=bytes_per_peer,
            session=session,
            count_per_peer=count_per_peer,
        )
        result["evidence_dir"] = str(ev_dir)

        evidence_file = ev_dir / "evidence.json"
        evidence_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
        return result

    finally:
        if s3_dev is not None:
            s3_dev.close()
        for dev in c3_devs:
            dev.close()
        cmd_log.close()


def run_dmp_three_peer_serial(
    s3_port: str,
    c3_ports: dict[int | str, str] | list[str] | tuple[str, ...],
    count_per_peer: int = 1,
    bytes_per_peer: int = DEFAULT_BYTES_PER_PEER,
    evidence_dir: Path | str | None = None,
    timeout: float = 60.0,
    serial_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Execute authenticated 3-peer qualification between 1 S3 and 3 C3 devices."""
    return run_dmp_four(
        s3_port=s3_port,
        c3_ports=c3_ports,
        mode="three_peer_serial",
        count_per_peer=count_per_peer,
        bytes_per_peer=bytes_per_peer,
        evidence_dir=evidence_dir,
        timeout=timeout,
        serial_factory=serial_factory,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-Peer Authenticated DMP ESP-NOW Qualification Runner")
    parser.add_argument("--s3-port", required=True, help="Serial port for ESP32-S3")
    parser.add_argument(
        "--c3-ports",
        nargs="+",
        required=True,
        metavar="PORT",
        help="Serial ports for the ESP32-C3 peers (3 ports for three_peer_serial, 4 ports for four_serial/four_parallel)",
    )
    parser.add_argument(
        "--mode",
        choices=["four_serial", "four_parallel", "three_peer_serial"],
        default="four_serial",
        help="Qualification mode: four_serial, four_parallel, or three_peer_serial",
    )
    parser.add_argument("--count-per-peer", type=int, default=1, help="Transfers per peer")
    parser.add_argument("--bytes-per-peer", type=int, default=DEFAULT_BYTES_PER_PEER)
    parser.add_argument("--evidence-dir", type=Path, default=None, help="Evidence directory")
    parser.add_argument("--timeout", type=float, default=60.0, help="Operation timeout in seconds")
    args = parser.parse_args()

    if args.mode == "three_peer_serial":
        result = run_dmp_three_peer_serial(
            s3_port=args.s3_port,
            c3_ports=args.c3_ports,
            count_per_peer=args.count_per_peer,
            bytes_per_peer=args.bytes_per_peer,
            evidence_dir=args.evidence_dir,
            timeout=args.timeout,
        )
    else:
        result = run_dmp_four(
            s3_port=args.s3_port,
            c3_ports=args.c3_ports,
            mode=args.mode,
            count_per_peer=args.count_per_peer,
            bytes_per_peer=args.bytes_per_peer,
            evidence_dir=args.evidence_dir,
            timeout=args.timeout,
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
