#!/usr/bin/env python3
"""Bounded multi-owner quota pressure runner for the private DMPBENCH probe."""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import serial_bench as bench


QUOTAS = (2048, 3840, 4096, 8192, 32768)
SLOTS = tuple(range(2, 8))
ERROR_NO_MEMORY = 17665
ERROR_INVALID_STATE = 17676
ACTION_WRITE = 16641
ACTION_READ = 16642
ACTION_SPLIT = 16644
ACTION_COMPLETE = 16645
ALLOC_COUNTERS = ("attempts", "allocs", "frees", "refusals")


@dataclass
class Pair:
    slot: int
    mode: str
    initiator: int
    generation: int = 0
    flights_done: int = 0

    @property
    def flight_count(self) -> int:
        return 2 if self.mode == "nn" else 3

    @property
    def complete_flights(self) -> bool:
        return self.flights_done == self.flight_count


def _stats(peer: bench.Peer) -> dict[str, int]:
    stats = peer.command("STATS")["stats"]
    _assert_quota(peer, stats)
    return stats


def _assert_quota(peer: bench.Peer, stats: dict[str, int],
                  expected: int | None = None) -> None:
    quota = stats["quota"] if expected is None else expected
    if stats["quota"] != quota or not 0 <= stats["arena_live"] <= stats["arena_peak"] <= quota:
        raise bench.BenchError(f"{peer.name}: live/peak arena exceeds the configured quota {quota}")


def _snapshot(peers: tuple[bench.Peer, bench.Peer]) -> list[dict[str, int]]:
    return [_stats(peer) for peer in peers]


def _assert_clean(peer: bench.Peer, stats: dict[str, int]) -> None:
    _assert_quota(peer, stats)
    bench._assert_clean_stats(peer, stats)


def _assert_layout(peer: bench.Peer, stats: dict[str, int], baseline: dict[str, int]) -> None:
    for key in ("backing", "metadata", "owners", "scratch"):
        if stats[key] != baseline[key]:
            raise bench.BenchError(f"{peer.name}: {key} storage baseline changed")


def _assert_position(peer: bench.Peer, actual: dict[str, int],
                     expected: dict[str, int], reason: str) -> None:
    _assert_quota(peer, actual, expected["quota"])
    for key in ("arena_live", "blocks", "quota"):
        if actual[key] != expected[key]:
            raise bench.BenchError(
                f"{peer.name}: {reason} changed {key} from {expected[key]} to {actual[key]}")
    if actual["wipe_errors"] != 0:
        raise bench.BenchError(f"{peer.name}: {reason} reported wipe errors")


def _check_action(response: dict[str, Any], action: int, where: str) -> None:
    if response["action"] != action:
        raise bench.BenchError(
            f"{where}: expected post-operation action {action}, got {response['action']}")


def _message(peers: tuple[bench.Peer, bench.Peer], pair: Pair, quota: int,
             orientation: int, flight: int) -> bytes:
    return (f"pressure|q={quota}|o={orientation}|slot={pair.slot}|"
            f"gen={pair.generation}|mode={pair.mode}|flight={flight}").encode("ascii")


def _start_pair(peers: tuple[bench.Peer, bench.Peer], pair: Pair) -> None:
    for index, peer in enumerate(peers):
        role = "i" if index == pair.initiator else "r"
        response = peer.command("NEW", pair.slot, pair.mode, role, "random")
        expected = ACTION_WRITE if role == "i" else ACTION_READ
        _check_action(response, expected, f"{peer.name} NEW slot {pair.slot} {role}")


def _next_flight(peers: tuple[bench.Peer, bench.Peer], pair: Pair,
                 quota: int, orientation: int) -> None:
    index = pair.flights_done
    if index >= pair.flight_count:
        raise bench.BenchError(f"slot {pair.slot}: no handshake flight remains")
    writer_index = pair.initiator if index % 2 == 0 else 1 - pair.initiator
    reader_index = 1 - writer_index
    writer, reader = peers[writer_index], peers[reader_index]
    payload = _message(peers, pair, quota, orientation, index)
    final_flight = index + 1 == pair.flight_count
    written = writer.command("WRITE", pair.slot, payload.hex() or "-")
    _check_action(written, ACTION_SPLIT if final_flight else ACTION_READ,
                  f"{writer.name} WRITE slot {pair.slot} flight {index + 1}")
    received = reader.command("READ", pair.slot, written["data"] or "-")
    _check_action(received, ACTION_SPLIT if final_flight else ACTION_WRITE,
                  f"{reader.name} READ slot {pair.slot} flight {index + 1}")
    if received["data"] != payload.hex():
        raise bench.BenchError(f"slot {pair.slot} flight {index + 1}: plaintext mismatch")
    pair.flights_done += 1


def _guard_round(peers: tuple[bench.Peer, bench.Peer], guards: tuple[Pair, Pair],
                 quota: int, orientation: int,
                 packet_numbers: dict[tuple[int, int], int]) -> None:
    before = _snapshot(peers)
    for guard in guards:
        for sender_index in (0, 1):
            receiver_index = 1 - sender_index
            sender, receiver = peers[sender_index], peers[receiver_index]
            key = (guard.slot, sender_index)
            pn = packet_numbers[key] + 1
            packet_numbers[key] = pn
            aad = (f"pressure-aad|q={quota}|o={orientation}|slot={guard.slot}|"
                   f"from={sender.name}|pn={pn}").encode("ascii")
            plaintext = (f"guard|q={quota}|o={orientation}|slot={guard.slot}|"
                         f"from={sender.name}|to={receiver.name}|pn={pn}").encode("ascii")
            sealed = sender.command("SEAL", guard.slot, pn, aad.hex(), plaintext.hex())
            _check_action(sealed, ACTION_COMPLETE,
                          f"{sender.name} SEAL guard slot {guard.slot} PN {pn}")
            if any(sealed["stats"][name] != before[sender_index][name]
                   for name in ALLOC_COUNTERS):
                raise bench.BenchError(
                    f"{sender.name}: guard SEAL changed allocator counters")
            opened = receiver.command("OPEN", guard.slot, pn, aad.hex(), sealed["data"])
            _check_action(opened, ACTION_COMPLETE,
                          f"{receiver.name} OPEN guard slot {guard.slot} PN {pn}")
            if opened["data"] != plaintext.hex():
                raise bench.BenchError(
                    f"guard slot {guard.slot} PN {pn}: authenticated plaintext mismatch")
            if any(opened["stats"][name] != before[receiver_index][name]
                   for name in ALLOC_COUNTERS):
                raise bench.BenchError(
                    f"{receiver.name}: guard OPEN changed allocator counters")
    after = _snapshot(peers)
    for index, peer in enumerate(peers):
        for counter in ALLOC_COUNTERS:
            if after[index][counter] != before[index][counter]:
                raise bench.BenchError(
                    f"{peer.name}: guard traffic changed allocator counter {counter}")


def _owner_round(peers: tuple[bench.Peer, bench.Peer], pair: Pair,
                 quota: int, orientation: int) -> None:
    """Check bidirectional authenticated traffic for a freshly split candidate."""
    before = _snapshot(peers)
    for sender_index in (0, 1):
        receiver_index = 1 - sender_index
        sender, receiver = peers[sender_index], peers[receiver_index]
        pn = 1
        aad = (f"candidate-aad|q={quota}|o={orientation}|slot={pair.slot}|"
               f"gen={pair.generation}|mode={pair.mode}|from={sender.name}|pn={pn}").encode("ascii")
        plaintext = (f"candidate|q={quota}|o={orientation}|slot={pair.slot}|"
                     f"gen={pair.generation}|mode={pair.mode}|from={sender.name}|"
                     f"to={receiver.name}|pn={pn}").encode("ascii")
        sealed = sender.command("SEAL", pair.slot, pn, aad.hex(), plaintext.hex())
        _check_action(sealed, ACTION_COMPLETE,
                      f"{sender.name} SEAL candidate slot {pair.slot} PN {pn}")
        if any(sealed["stats"][name] != before[sender_index][name]
               for name in ALLOC_COUNTERS):
            raise bench.BenchError(f"{sender.name}: candidate SEAL changed allocator counters")
        opened = receiver.command("OPEN", pair.slot, pn, aad.hex(), sealed["data"])
        _check_action(opened, ACTION_COMPLETE,
                      f"{receiver.name} OPEN candidate slot {pair.slot} PN {pn}")
        if opened["data"] != plaintext.hex():
            raise bench.BenchError(
                f"candidate slot {pair.slot} generation {pair.generation}: plaintext mismatch")
        if any(opened["stats"][name] != before[receiver_index][name]
               for name in ALLOC_COUNTERS):
            raise bench.BenchError(f"{receiver.name}: candidate OPEN changed allocator counters")
    after = _snapshot(peers)
    for index, peer in enumerate(peers):
        for counter in ALLOC_COUNTERS:
            if after[index][counter] != before[index][counter]:
                raise bench.BenchError(
                    f"{peer.name}: candidate traffic changed allocator counter {counter}")


def _guard_round_count(packet_numbers: dict[tuple[int, int], int]) -> int:
    # A complete round advances every guard/direction PN once.
    return min(packet_numbers.values())


def _close_pair(peers: tuple[bench.Peer, bench.Peer], pair: Pair) -> None:
    for peer in peers:
        peer.command("CLOSE", pair.slot)


def _record_checkpoint(peers: tuple[bench.Peer, bench.Peer], label: str,
                       checkpoints: list[dict[str, Any]]) -> list[dict[str, int]]:
    stats = _snapshot(peers)
    checkpoints.append({"label": label,
                        "peers": {peer.name: current
                                  for peer, current in zip(peers, stats)}})
    for peer, current in zip(peers, stats):
        peer._record({"event": "case_checkpoint", "label": label,
                      "peer": peer.name, "stats": current})
    return stats


def _admit_candidate(peers: tuple[bench.Peer, bench.Peer], pair: Pair,
                     guards: tuple[Pair, Pair], quota: int, orientation: int,
                     packet_numbers: dict[tuple[int, int], int],
                     checkpoints: list[dict[str, Any]]) -> tuple[bool, dict[str, Any] | None]:
    baseline = _snapshot(peers)
    for index, peer in enumerate(peers):
        role = "i" if index == pair.initiator else "r"
        result = peer.command("NEW", pair.slot, pair.mode, role, "random",
                              expected_rc=(0, ERROR_NO_MEMORY))
        if result["rc"] == ERROR_NO_MEMORY:
            _check_action(result, 0, f"{peer.name} failed NEW slot {pair.slot}")
            _assert_position(peer, result["stats"], baseline[index], "failed NEW")
            if result["stats"]["refusals"] != baseline[index]["refusals"] + 1:
                raise bench.BenchError("failed NEW must record exactly one allocator refusal")
            refused = {"stage": "NEW", "peer": peer.name, "slot": pair.slot,
                       "mode": pair.mode, "generation": pair.generation,
                       "rc": ERROR_NO_MEMORY}
            for other in peers:
                other.command("CLOSE", pair.slot)
            after = _record_checkpoint(peers, f"slot-{pair.slot}-new-refusal", checkpoints)
            for other, current, original in zip(peers, after, baseline):
                _assert_position(other, current, original, "candidate refusal cleanup")
            _guard_round(peers, guards, quota, orientation, packet_numbers)
            return False, refused
        expected = ACTION_WRITE if role == "i" else ACTION_READ
        _check_action(result, expected, f"{peer.name} NEW slot {pair.slot} {role}")
    _record_checkpoint(peers, f"slot-{pair.slot}-admitted", checkpoints)
    _guard_round(peers, guards, quota, orientation, packet_numbers)
    return True, None


def _reset_boundary_check(peers: tuple[bench.Peer, bench.Peer], guards: tuple[Pair, Pair],
                          quota: int, orientation: int,
                          packet_numbers: dict[tuple[int, int], int]) -> None:
    for index, peer in enumerate(peers):
        before = _stats(peer)
        denied = peer.command("RESET", 0, expected_rc=ERROR_INVALID_STATE)
        after = denied["stats"]
        if after["quota"] != quota:
            raise bench.BenchError(f"{peer.name}: rejected RESET changed quota")
        _assert_position(peer, after, before, "rejected RESET")
        for key in ("allocs", "frees", "attempts", "refusals"):
            if after[key] != before[key]:
                raise bench.BenchError(f"{peer.name}: rejected RESET changed {key}")
        _guard_round(peers, guards, quota, orientation, packet_numbers)


def _split_pair(peers: tuple[bench.Peer, bench.Peer], pair: Pair,
                guards: tuple[Pair, Pair], quota: int, orientation: int,
                packet_numbers: dict[tuple[int, int], int]) -> tuple[bool, dict[str, Any] | None]:
    before = _snapshot(peers)
    order = ((pair.slot + orientation) % 2, (pair.slot + orientation + 1) % 2)
    outputs: dict[int, str] = {}
    for index in order:
        peer = peers[index]
        response = peer.command("SPLIT", pair.slot,
                                expected_rc=(0, ERROR_NO_MEMORY))
        if response["rc"] == ERROR_NO_MEMORY:
            _check_action(response, ACTION_SPLIT, f"{peer.name} refused SPLIT slot {pair.slot}")
            _assert_position(peer, response["stats"], before[index], "failed SPLIT")
            if response["stats"]["refusals"] != before[index]["refusals"] + 1:
                raise bench.BenchError("failed SPLIT must record exactly one allocator refusal")
            refusal = {"stage": "SPLIT", "peer": peer.name, "slot": pair.slot,
                       "mode": pair.mode, "generation": pair.generation,
                       "rc": ERROR_NO_MEMORY}
            _close_pair(peers, pair)
            _guard_round(peers, guards, quota, orientation, packet_numbers)
            return False, refusal
        _check_action(response, ACTION_COMPLETE, f"{peer.name} SPLIT slot {pair.slot}")
        if len(response["data"]) != 64:
            raise bench.BenchError(f"{peer.name}: SPLIT did not return a 32-byte hash")
        outputs[index] = response["data"]
        _guard_round(peers, guards, quota, orientation, packet_numbers)
    if outputs[0] != outputs[1]:
        raise bench.BenchError(f"slot {pair.slot}: peer handshake hashes differ")
    return True, None


def _allocation_faults(peers: tuple[bench.Peer, bench.Peer],
                       guards: tuple[Pair, Pair], quota: int, orientation: int,
                       packet_numbers: dict[tuple[int, int], int],
                       checkpoints: list[dict[str, Any]]) -> None:
    for failed_index, peer in enumerate(peers):
        before = _snapshot(peers)
        peer.command("ALLOCFAIL", 1)
        failure = peer.command("NEW", 7, "nn", "i", "random",
                               expected_rc=ERROR_NO_MEMORY)
        _check_action(failure, 0, f"{peer.name} injected NEW slot 7")
        _assert_position(peer, failure["stats"], before[failed_index], "injected failed NEW")
        for key, delta in (("attempts", 1), ("refusals", 1), ("allocs", 0), ("frees", 0)):
            if failure["stats"][key] != before[failed_index][key] + delta:
                raise bench.BenchError(f"{peer.name}: first-allocation fault changed {key} unexpectedly")
        peer.command("CLOSE", 7)
        for endpoint in peers:
            endpoint.command("ALLOCFAIL", 0)
        after = _record_checkpoint(peers, f"allocfail-peer-{failed_index + 1}", checkpoints)
        for endpoint, current, original in zip(peers, after, before):
            _assert_position(endpoint, current, original, "injected failure cleanup")
        _guard_round(peers, guards, quota, orientation, packet_numbers)


def _case(peers: tuple[bench.Peer, bench.Peer], quota: int,
          orientation: int) -> dict[str, Any]:
    checkpoints: list[dict[str, Any]] = []
    admitted: list[Pair] = []
    completed: list[dict[str, Any]] = []
    refused: dict[str, Any] | None = None
    split_refusals: list[dict[str, Any]] = []
    cancelled: dict[str, Any] | None = None
    packet_numbers = {(slot, endpoint): 0 for slot in (0, 1) for endpoint in (0, 1)}
    initial_baselines = _snapshot(peers)
    for peer, stats in zip(peers, initial_baselines):
        _assert_clean(peer, stats)
    result: dict[str, Any] = {"quota": quota, "orientation": orientation,
                              "success": False, "admitted": [], "completed": [],
                              "refused": None, "split_refusals": [],
                              "checkpoints": checkpoints,
                              "max_live_candidate_owner_pairs": 0,
                              "guard_survival_checks": 0}
    peers[0]._record({"event": "case_start", "quota": quota,
                      "orientation": orientation})
    try:
        for peer in peers:
            reset = peer.command("RESET", quota)
            if reset["stats"]["quota"] != quota:
                raise bench.BenchError(f"{peer.name}: RESET did not set quota {quota}")
            _assert_clean(peer, reset["stats"])
        layout = _snapshot(peers)
        for peer, stats, initial in zip(peers, layout, initial_baselines):
            _assert_layout(peer, stats, initial)
        baseline = _record_checkpoint(peers, "empty-after-reset", checkpoints)
        guards = (
            Pair(0, "nn", orientation % 2),
            Pair(1, "xx", 1 - (orientation % 2)),
        )
        for guard in guards:
            _start_pair(peers, guard)
            while not guard.complete_flights:
                _next_flight(peers, guard, quota, orientation)
            first = (guard.slot + orientation) % 2
            outputs: dict[int, str] = {}
            for index in (first, 1 - first):
                response = peers[index].command("SPLIT", guard.slot)
                _check_action(response, ACTION_COMPLETE,
                              f"{peers[index].name} guard SPLIT slot {guard.slot}")
                if len(response["data"]) != 64:
                    raise bench.BenchError("guard SPLIT hash is not 32 bytes")
                outputs[index] = response["data"]
            if outputs[0] != outputs[1]:
                raise bench.BenchError(f"guard slot {guard.slot}: handshake hashes differ")
        _guard_round(peers, guards, quota, orientation, packet_numbers)
        guard_baseline = _record_checkpoint(peers, "guards-live", checkpoints)
        _reset_boundary_check(peers, guards, quota, orientation, packet_numbers)

        for slot in SLOTS:
            mode = "nn" if (slot - SLOTS[0]) % 2 == 0 else "xx"
            pair = Pair(slot, mode, (slot + orientation) % 2)
            admitted_ok, denial = _admit_candidate(
                peers, pair, guards, quota, orientation, packet_numbers, checkpoints)
            if not admitted_ok:
                refused = denial
                break
            admitted.append(pair)
        result["max_live_candidate_owner_pairs"] = len(admitted)
        result["admitted"] = [
            {"slot": pair.slot, "mode": pair.mode, "initiator_peer": peers[pair.initiator].name,
             "generation": pair.generation} for pair in admitted]

        for pair in admitted:
            _next_flight(peers, pair, quota, orientation)
            _guard_round(peers, guards, quota, orientation, packet_numbers)
            peers[0]._record({"event": "candidate_progress", "slot": pair.slot,
                              "generation": pair.generation, "stage": "first-flight",
                              "quota": quota, "orientation": orientation,
                              "stats": {peer.name: stats
                                        for peer, stats in zip(peers, _snapshot(peers))}})
        if admitted:
            middle_index = len(admitted) // 2
            old = admitted[middle_index]
            _close_pair(peers, old)
            admitted.pop(middle_index)
            cancelled = {"slot": old.slot, "mode": old.mode,
                         "generation": old.generation}
            _guard_round(peers, guards, quota, orientation, packet_numbers)
            replacement = Pair(old.slot, old.mode, old.initiator, old.generation + 1)
            recreated, denial = _admit_candidate(
                peers, replacement, guards, quota, orientation, packet_numbers, checkpoints)
            if not recreated:
                raise bench.BenchError(
                    f"cancelled slot {old.slot} could not be recreated while peers remained live: {denial}")
            admitted.insert(middle_index, replacement)
            _next_flight(peers, replacement, quota, orientation)
            _guard_round(peers, guards, quota, orientation, packet_numbers)
            peers[0]._record({"event": "candidate_progress", "slot": replacement.slot,
                              "generation": replacement.generation, "stage": "replacement-first-flight",
                              "quota": quota, "orientation": orientation,
                              "stats": {peer.name: stats
                                        for peer, stats in zip(peers, _snapshot(peers))}})
            _record_checkpoint(peers, f"slot-{old.slot}-recreated", checkpoints)

        while any(not pair.complete_flights for pair in admitted):
            for pair in admitted:
                if pair.complete_flights:
                    continue
                _next_flight(peers, pair, quota, orientation)
                _guard_round(peers, guards, quota, orientation, packet_numbers)
                peers[0]._record({"event": "candidate_progress", "slot": pair.slot,
                                  "generation": pair.generation,
                                  "stage": f"flight-{pair.flights_done}",
                                  "quota": quota, "orientation": orientation})

        for pair in admitted:
            split_ok, split_denial = _split_pair(
                peers, pair, guards, quota, orientation, packet_numbers)
            if split_ok:
                _owner_round(peers, pair, quota, orientation)
                _guard_round(peers, guards, quota, orientation, packet_numbers)
                completed.append({"slot": pair.slot, "mode": pair.mode,
                                  "generation": pair.generation})
                peers[0]._record({"event": "candidate_progress", "slot": pair.slot,
                                  "generation": pair.generation,
                                  "stage": "split-traffic", "quota": quota,
                                  "orientation": orientation})
            else:
                assert split_denial is not None
                split_refusals.append(split_denial)
        result["completed"] = completed
        result["refused"] = refused
        result["split_refusals"] = split_refusals
        result["cancelled"] = cancelled
        _record_checkpoint(peers, "post-split", checkpoints)

        # All candidate slots, including successful Split outputs, are released before fault injection.
        for pair in admitted:
            if not any(item["slot"] == pair.slot and item["generation"] == pair.generation
                       for item in split_refusals):
                _close_pair(peers, pair)
        cleaned = _record_checkpoint(peers, "pending-cleanup", checkpoints)
        for peer, stats, expected in zip(peers, cleaned, guard_baseline):
            _assert_position(peer, stats, expected, "pending cleanup")
        _allocation_faults(peers, guards, quota, orientation, packet_numbers, checkpoints)

        for guard in reversed(guards):
            _close_pair(peers, guard)
        final = _record_checkpoint(peers, "final-clean", checkpoints)
        for peer, stats, initial in zip(peers, final, initial_baselines):
            _assert_quota(peer, stats, quota)
            _assert_clean(peer, stats)
            _assert_layout(peer, stats, initial)
        result["baseline_stats"] = {peer.name: stats for peer, stats in zip(peers, baseline)}
        result["guard_baseline_stats"] = {
            peer.name: stats for peer, stats in zip(peers, guard_baseline)}
        result["final_stats"] = {peer.name: stats for peer, stats in zip(peers, final)}
        result["peak_arena_live"] = {peer.name: stats["arena_peak"]
                                      for peer, stats in zip(peers, final)}
        result["guard_survival_checks"] = _guard_round_count(packet_numbers)
        result["guard_survived"] = True
        result["quota_limited"] = bool(refused or split_refusals)
        if len(set(packet_numbers.values())) != 1:
            raise bench.BenchError("guard directional packet counts disagree")
        if quota == 32768 and (len(admitted) != 6 or len(completed) != 6):
            raise bench.BenchError(
                f"full quota must admit and complete six pending pairs; admitted={len(admitted)} "
                f"completed={len(completed)}")
        result["success"] = True
        return result
    except Exception as exc:
        result["success"] = False
        result.update({"admitted": [
            {"slot": pair.slot, "mode": pair.mode, "generation": pair.generation}
            for pair in admitted],
            "completed": completed, "refused": refused,
            "split_refusals": split_refusals, "cancelled": cancelled,
            "guard_survival_checks": _guard_round_count(packet_numbers), "error": str(exc)})
        peers[0]._record({"event": "case_result", **result})
        raise
    finally:
        if result.get("success"):
            peers[0]._record({"event": "case_result", **result})


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--host-exe", help="provider executable; start two independent processes")
    source.add_argument("--ports", nargs=2, metavar=("PORT_A", "PORT_B"),
                        help="two UART ports, opened at 115200 baud")
    parser.add_argument("--output", required=True, help="exclusive JSONL evidence path")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="finite per-response deadline in seconds (default: 10)")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= bench.MAX_TIMEOUT:
        print(f"error: --timeout must be finite and in 0..{bench.MAX_TIMEOUT:g} seconds",
              file=sys.stderr)
        return 2
    evidence = None
    peers: list[bench.Peer] = []
    transports: list[bench.LineTransport] = []
    try:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        evidence = path.open("x", encoding="utf-8", newline="\n")
        if args.host_exe:
            transports.extend(bench.SubprocessTransport(args.host_exe) for _ in range(2))
        else:
            transports.extend(bench.SerialTransport(port, 115200) for port in args.ports)
        peers = [bench.Peer(f"peer-{index + 1}", transport, evidence, args.timeout)
                 for index, transport in enumerate(transports)]
        for index, peer in enumerate(peers):
            peer._record({"event": "transport_metadata", "peer": peer.name,
                          "transport": "host-process" if args.host_exe else "uart",
                          "endpoint": args.host_exe if args.host_exe else args.ports[index],
                          "baud": None if args.host_exe else 115200,
                          "dtr": False if args.ports else None,
                          "rts": False if args.ports else None,
                          "timeout_s": args.timeout, "quotas": list(QUOTAS),
                          "orientations": [0, 1]})
        hellos = [peer.synchronize() for peer in peers]
        for peer, hello in zip(peers, hellos):
            peer._record({"event": "run_metadata", "peer": peer.name,
                          "target": hello["target"], "idf": hello["idf"],
                          "boot": hello["boot"], "build": hello["build"],
                          "timeout_s": args.timeout, "quotas": list(QUOTAS),
                          "orientations": [0, 1],
                          "scenario": "multi-owner-quota-pressure"})
            peer.command("INIT")
        cases = []
        for quota in QUOTAS:
            for orientation in (0, 1):
                cases.append(_case((peers[0], peers[1]), quota, orientation))
        if not any(case["quota_limited"] for case in cases):
            raise bench.BenchError("quota-pressure sweep never reached an actual quota refusal")
        # Every case leaves an empty arena. Restore the default capacity explicitly.
        for peer in peers:
            current = _stats(peer)
            _assert_clean(peer, current)
            restored = peer.command("RESET", 32768)["stats"]
            if restored["quota"] != 32768:
                raise bench.BenchError(f"{peer.name}: could not restore quota 32768")
            _assert_clean(peer, restored)
        summary = {"schema": "dmpbench-pressure-summary-v1", "success": True,
                   "quotas": list(QUOTAS), "orientations": [0, 1],
                   "cases": cases, "output": str(path)}
        for peer in peers:
            peer._record({"event": "summary", **summary})
        print(json.dumps(summary, sort_keys=True))
        return 0
    except Exception as exc:
        if evidence is not None:
            evidence.write(json.dumps({"event": "run_failed", "error": str(exc),
                                       "time_unix_ms": int(time.time() * 1000)},
                                      sort_keys=True) + "\n")
            evidence.flush()
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        # Closing transports is safe after an unknown command outcome; owners remain untouched.
        for peer in peers:
            try:
                peer.close()
            except Exception:
                pass
        for transport in transports[len(peers):]:
            try:
                transport.close()
            except Exception:
                pass
        if evidence is not None:
            evidence.close()


if __name__ == "__main__":
    raise SystemExit(main())
