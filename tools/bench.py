#!/usr/bin/env python3
"""Run equivalent P24 workloads through the real P23 host endpoints."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import tracemalloc
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PEER_TESTS = ROOT / "tests" / "peer" / "tests"
sys.path.insert(0, str(PEER_TESTS))

from test_p23_radio_endpoint_interop import (  # noqa: E402
    TestP23RadioEndpointInterop,
    _MAX_CORE,
    _decode_c_stream_frame,
)
from dmp_peer.events import Advance, ApplicationEvent, ApplicationRequest  # noqa: E402
from dmp_peer.frame import parse_frame  # noqa: E402


PROFILE_PAIRS = {
    "nnpsk0": ("radio-nnpsk0.json", "test-radio-retry-all-nnpsk0.json"),
    "xx": ("radio-xx.json", "test-radio-retry-all-xx.json"),
}
ALLOWED_PROFILE_FIELDS = (
    ("profile", "id"),
    ("profile", "owner"),
    ("profile", "revision"),
)
MESSAGE_NAMES = {
    0: "REQ",
    1: "RSP",
    2: "ERR",
    3: "HELLO",
    4: "EVENT",
    5: "TELEM",
    6: "ACK",
    7: "DATA",
    8: "FRAG_STATUS",
}


def _manifest_path(name: str) -> Path:
    return ROOT / "profiles" / "deployments" / name


def _manifest_digests() -> dict[str, str]:
    data = json.loads((_manifest_path("digests.json")).read_text(encoding="utf-8"))
    return data["manifests"]


def _set_path(value: dict[str, Any], path: tuple[str, ...], replacement: Any) -> None:
    parent: Any = value
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = replacement


def validate_profile_pair(radio: dict[str, Any], retry_all: dict[str, Any]) -> dict[str, Any]:
    """Require identical common workload and binding configuration."""
    radio_normalized = json.loads(json.dumps(radio))
    retry_normalized = json.loads(json.dumps(retry_all))
    permitted: list[dict[str, Any]] = []

    for path in ALLOWED_PROFILE_FIELDS:
        left: Any = radio
        right: Any = retry_all
        for key in path:
            left, right = left[key], right[key]
        if left != right:
            permitted.append({"field": "/".join(path), "radio_1": left, "retry_all": right})
        _set_path(radio_normalized, path, None)
        _set_path(retry_normalized, path, None)

    for index, (left_service, right_service) in enumerate(
        zip(radio["services"], retry_all["services"], strict=True)
    ):
        left, right = left_service["recovery"], right_service["recovery"]
        if left != right:
            permitted.append({
                "field": f"services/{index}/recovery",
                "radio_1": left,
                "retry_all": right,
            })
        radio_normalized["services"][index]["recovery"] = None
        retry_normalized["services"][index]["recovery"] = None

    for field in ("max_probes", "max_status"):
        left, right = radio["timing"][field], retry_all["timing"][field]
        if left != right:
            permitted.append({
                "field": f"timing/{field}", "radio_1": left, "retry_all": right
            })
        radio_normalized["timing"][field] = None
        retry_normalized["timing"][field] = None

    if radio_normalized != retry_normalized:
        raise ValueError("profile pair differs outside the P03 comparison allowlist")
    if radio["security"]["mode"] != retry_all["security"]["mode"]:
        raise ValueError("profile pair security modes differ")
    if radio["services"][1]["recovery"] != "selective-32":
        raise ValueError("RADIO-1 service 2 does not select SELECTIVE-32")
    if retry_all["services"][1]["recovery"] != "retry-all":
        raise ValueError("retry-all profile service 2 does not select retry-all")
    return {"allowed_differences": permitted}


def load_profile_pair(mode: str) -> tuple[dict[str, Any], dict[str, Any]]:
    radio_name, retry_name = PROFILE_PAIRS[mode]
    digests = _manifest_digests()
    manifests = []
    for name in (radio_name, retry_name):
        raw = _manifest_path(name).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digests.get(name) != digest:
            raise ValueError("manifest digest does not match the checked-in digest index")
        manifest = json.loads(raw)
        manifests.append({"name": name, "digest": digest, "values": manifest})
    validate_profile_pair(manifests[0]["values"], manifests[1]["values"])
    return manifests[0], manifests[1]


class _ProcessSampler:
    """Best-effort standard-library process CPU/RSS sampling."""

    def __init__(self) -> None:
        self.cpu_start: float | None = None
        self.cpu_end: float | None = None
        self.cpu_unavailable_reason: str | None = None
        self.rss_peak: int | None = None
        self.rss_current: int | None = None
        self.unavailable_reason: str | None = None
        self._ticks = None
        if sys.platform.startswith("linux"):
            try:
                self._ticks = os.sysconf("SC_CLK_TCK")
            except (OSError, ValueError):
                pass

    def _linux_sample(self, process: subprocess.Popen[Any]) -> tuple[float | None, int | None, int | None]:
        proc_root = Path(f"/proc/{process.pid}")
        try:
            status = (proc_root / "status").read_text(encoding="ascii")
            fields = {}
            for line in status.splitlines():
                if line.startswith(("VmRSS:", "VmHWM:")):
                    key, value, _unit = line.split()
                    fields[key[:-1]] = int(value) * 1024
            stat = (proc_root / "stat").read_text(encoding="ascii")
            tail = stat[stat.rfind(")") + 2 :].split()
            cpu = None
            if self._ticks:
                cpu = (int(tail[11]) + int(tail[12])) / self._ticks
            return cpu, fields.get("VmRSS"), fields.get("VmHWM")
        except (OSError, ValueError, IndexError):
            return None, None, None

    def _windows_sample(self, process: subprocess.Popen[Any]) -> tuple[float | None, int | None, int | None]:
        try:
            import ctypes
            from ctypes import wintypes

            class _FileTime(ctypes.Structure):
                _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

            class _MemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("page_fault_count", wintypes.DWORD),
                    ("peak_working_set_size", ctypes.c_size_t),
                    ("working_set_size", ctypes.c_size_t),
                    ("quota_peak_paged_pool_usage", ctypes.c_size_t),
                    ("quota_paged_pool_usage", ctypes.c_size_t),
                    ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
                    ("quota_non_paged_pool_usage", ctypes.c_size_t),
                    ("pagefile_usage", ctypes.c_size_t),
                    ("peak_pagefile_usage", ctypes.c_size_t),
                ]

            handle = wintypes.HANDLE(process._handle)  # noqa: SLF001
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            creation, exit_time, kernel_time, user_time = (_FileTime() for _ in range(4))
            cpu = None
            if kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel_time),
                ctypes.byref(user_time),
            ):
                ticks = lambda value: (value.high << 32) | value.low
                cpu = (ticks(kernel_time) + ticks(user_time)) / 10_000_000
            counters = _MemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            if psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(counters), counters.cb
            ):
                return cpu, int(counters.working_set_size), int(counters.peak_working_set_size)
            return cpu, None, None
        except (AttributeError, OSError, TypeError, ValueError):
            return None, None, None

    def sample(self, endpoint: Any) -> None:
        process = getattr(endpoint, "process", None)
        if process is None or process.poll() is not None:
            return
        if sys.platform.startswith("linux"):
            cpu, current, peak = self._linux_sample(process)
        elif os.name == "nt":
            cpu, current, peak = self._windows_sample(process)
        else:
            cpu, current, peak = None, None, None
        if cpu is not None:
            self.cpu_start = cpu if self.cpu_start is None else self.cpu_start
            self.cpu_end = cpu
        elif self.cpu_unavailable_reason is None:
            self.cpu_unavailable_reason = "host process CPU sampling is unavailable"
        if current is not None:
            self.rss_current = current
            self.rss_peak = max(self.rss_peak or 0, current, peak or 0)
        elif self.unavailable_reason is None:
            self.unavailable_reason = "host process RSS sampling is unavailable"


class _P24Metrics:
    def __init__(self, manifest: dict[str, Any]):
        self.manifest = manifest
        self.phase = "cold_setup"
        self.phases: dict[str, dict[str, Any]] = {}
        self.endpoint: Any = None
        self.process = _ProcessSampler()
        self.seen_events: set[int] = set()
        self.receive_windows = Counter()
        self.recovery_fragment_indices: list[int] = []
        self.probe_candidates = 0

    def _phase(self) -> dict[str, Any]:
        return self.phases.setdefault(self.phase, {
            "nodes": {},
            "frame_attempts": 0,
            "core_frame_bytes": 0,
            "frame_type_counts": Counter(),
            "dropped_fragments": [],
            "fragments_by_type_and_index": Counter(),
            "application_event_counts": Counter(),
            "receive_windows": 0,
            "recovery_fragment_indices": [],
            "probe_candidates": 0,
            "modeled_airtime_ms": 0,
        })

    def _record(self, node: int, role: str, wire: bytes, parsed: Any) -> None:
        phase = self._phase()
        nodes = phase["nodes"]
        item = nodes.setdefault(str(node), {
            "role": role,
            "frame_attempts": 0,
            "core_frame_bytes": 0,
            "frame_type_counts": Counter(),
            "fragment_indices": Counter(),
        })
        item["frame_attempts"] += 1
        item["core_frame_bytes"] += len(wire)
        item["frame_type_counts"][str(parsed.message_type)] += 1
        phase["frame_attempts"] += 1
        phase["core_frame_bytes"] += len(wire)
        phase["frame_type_counts"][str(parsed.message_type)] += 1
        if parsed.fragment is not None:
            fragment_index = parsed.fragment.index
            item["fragment_indices"][str(fragment_index)] += 1
            phase["fragments_by_type_and_index"][
                f"type_{parsed.message_type}/index_{fragment_index}"
            ] += 1
        self.process.sample(self.endpoint)

    def endpoint_tx(self, node: int, wire: bytes, parsed: Any) -> None:
        self._record(node, "endpoint", wire, parsed)
        phase = self._phase()
        binding_ms = int(self.manifest["binding"]["frame_tx_ms"])
        phase["modeled_airtime_ms"] += binding_ms

    def relay_tx(self, node: int, wire: bytes, parsed: Any) -> None:
        self._record(node, "relay", wire, parsed)
        relay = next(item for item in self.manifest["relays"] if item["node"] == node)
        self._phase()["modeled_airtime_ms"] += int(relay["frame_tx_ms"])

    def dropped(self, node: int, fragment_index: int) -> None:
        self._phase()["dropped_fragments"].append({
            "source_node": node,
            "fragment_index": fragment_index,
        })

    def observe_application(self, events: list[Any]) -> None:
        phase = self._phase()
        for event in events:
            if isinstance(event, ApplicationEvent) and id(event) not in self.seen_events:
                self.seen_events.add(id(event))
                phase["application_event_counts"][event.kind] += 1

    def receive_window(self) -> None:
        self._phase()["receive_windows"] += 1

    def recovery_tx(self, frames: list[bytes], fragment_count: int) -> None:
        parsed = [parse_frame(frame, max_frame=_MAX_CORE) for frame in frames]
        fragments = [frame.fragment.index for frame in parsed if frame.fragment is not None]
        self.recovery_fragment_indices.extend(fragments)
        phase = self._phase()
        phase["recovery_fragment_indices"].extend(fragments)
        if (
            len(fragments) == 1
            and fragments[0] == fragment_count - 1
            and phase["frame_type_counts"].get("8", 0) == 0
        ):
            self.probe_candidates += 1
            phase["probe_candidates"] += 1

    def report(self) -> dict[str, Any]:
        result = {}
        for name, phase in self.phases.items():
            result[name] = {
                "nodes": {
                    node: {
                        **entry,
                        "frame_type_counts": dict(sorted(entry["frame_type_counts"].items())),
                        "fragment_indices": dict(sorted(entry["fragment_indices"].items())),
                    }
                    for node, entry in phase["nodes"].items()
                },
                "frame_attempts": phase["frame_attempts"],
                "core_frame_bytes": phase["core_frame_bytes"],
                "frame_type_counts": dict(sorted(phase["frame_type_counts"].items())),
                "message_type_names": {
                    str(number): name for number, name in MESSAGE_NAMES.items()
                },
                "dropped_fragments": phase["dropped_fragments"],
                "fragments_by_type_and_index": dict(
                    sorted(phase["fragments_by_type_and_index"].items())
                ),
                "frag_status_frames": phase["frame_type_counts"].get("8", 0),
                "application_event_counts": dict(
                    sorted(phase["application_event_counts"].items())
                ),
                "receive_windows": phase["receive_windows"],
                "recovery_fragment_indices": phase["recovery_fragment_indices"],
                "probe_candidates": phase["probe_candidates"],
                "modeled_airtime_ms": phase["modeled_airtime_ms"],
            }
        return result


def _sample_case(
    mode: str,
    profile: dict[str, Any],
    payload: bytes,
    seed: int,
    iteration: int,
    endpoint_path: Path,
) -> dict[str, Any]:
    harness = TestP23RadioEndpointInterop(
        "test_selective_32_repairs_one_lost_fragment_over_radio_relays"
    )
    harness.setUp()
    metrics = _P24Metrics(profile["values"])
    c_endpoint = None
    start_wall = time.perf_counter_ns()
    start_cpu = time.process_time_ns()
    phase_virtual: dict[str, int] = {}
    failure: str | None = None
    tracemalloc.start()
    tracemalloc.reset_peak()
    python_heap_before, _ = tracemalloc.get_traced_memory()
    try:
        c_endpoint, peer, relays, clock = harness._open_pair(
            profile["name"], seed
        )
        metrics.endpoint = c_endpoint
        metrics.process.sample(c_endpoint)

        metrics.phase = "cold_setup"
        phase_start = clock.now_ms
        harness._activate(c_endpoint, peer, relays, clock, metrics=metrics)
        phase_virtual["cold_setup"] = clock.now_ms - phase_start

        metrics.phase = "freshness_grant"
        phase_start = clock.now_ms
        harness._grant_freshness(
            c_endpoint, peer, relays, clock, metrics=metrics
        )
        phase_virtual["freshness_grant"] = clock.now_ms - phase_start

        metrics.phase = "warm_exchange"
        phase_start = clock.now_ms
        exchange_id = 0x2401
        events = peer.handle(ApplicationRequest(
            service_id=2,
            payload=payload,
            ack_req=True,
            at_ms=clock.next(),
            exchange_id=exchange_id,
        ))
        first = harness._peer_send(peer, events, clock)
        original = [parse_frame(frame, max_frame=_MAX_CORE) for frame in first]
        if not original or any(frame.fragment is None for frame in original):
            raise ValueError("workload did not form a fragmented request")
        fragment_count = len(original)
        dropped_index = (fragment_count - 1) // 2
        sequence = original[0].sequence
        if any(frame.sequence != sequence for frame in original):
            raise ValueError("request fragments do not share one sequence")
        observed: list[Any] = []
        initial_accepts = c_endpoint.last_state.accepts
        drop = {(sequence, dropped_index)}
        initial_peer_feedback, _ = harness._dispatch(
            c_endpoint,
            peer,
            relays,
            10,
            first,
            clock,
            drop=drop,
            observed=observed,
            metrics=metrics,
        )
        metrics.recovery_tx(initial_peer_feedback, fragment_count)
        metrics.observe_application(observed)

        recovery_deadline = clock.now_ms + 11_000
        while clock.now_ms < recovery_deadline and c_endpoint.last_state.accepts == initial_accepts:
            now = clock.advance(64)
            generated = harness._peer_send(
                peer, peer.handle(Advance(now_ms=now)), clock
            )
            state = c_endpoint.poll(clock.next())
            metrics.receive_window()
            if state.status != 0:
                raise ValueError("C endpoint failed while polling recovery")
            c_frames = [
                _decode_c_stream_frame(wire)
                for wire in state.frames
                if wire != b"\x00"
            ]
            if generated:
                metrics.recovery_tx(generated, fragment_count)
                peer_feedback, _ = harness._dispatch(
                    c_endpoint, peer, relays, 10, generated, clock,
                    observed=observed, metrics=metrics,
                )
                metrics.recovery_tx(peer_feedback, fragment_count)
                metrics.observe_application(observed)
            if c_frames:
                peer_replies, _ = harness._dispatch(
                    c_endpoint, peer, relays, 20, c_frames, clock,
                    observed=observed, metrics=metrics,
                )
                metrics.recovery_tx(peer_replies, fragment_count)
                metrics.observe_application(observed)

        if c_endpoint.last_state.accepts != initial_accepts + 1:
            raise ValueError("fragmented request was not accepted before deadline")
        if c_endpoint.last_state.request_service != 2 or c_endpoint.last_state.request != payload:
            raise ValueError("C endpoint accepted unexpected request contents")

        policy = profile["values"]["services"][1]["recovery"]
        repairs = metrics.recovery_fragment_indices
        if policy == "selective-32" and repairs != [dropped_index]:
            raise ValueError("SELECTIVE-32 did not repair exactly the dropped fragment")
        if policy == "retry-all" and sorted(repairs) != list(range(fragment_count)):
            raise ValueError("retry-all did not repair the full fragment set")

        completed = c_endpoint.complete(clock.next())
        if completed.status != 0:
            raise ValueError("C endpoint rejected request completion")
        terminal_events: list[Any] = []
        harness._dispatch(
            c_endpoint,
            peer,
            relays,
            20,
            [wire for wire in completed.frames if wire != b"\x00"],
            clock,
            observed=terminal_events,
            metrics=metrics,
        )
        metrics.observe_application(terminal_events)
        result_deadline = clock.now_ms + 11_000
        while clock.now_ms < result_deadline and not any(
            isinstance(event, ApplicationEvent)
            and event.kind == "request_result"
            and event.exchange_id == exchange_id
            for event in terminal_events
        ):
            now = clock.advance(64)
            peer_frames = harness._peer_send(
                peer, peer.handle(Advance(now_ms=now)), clock
            )
            if peer_frames:
                harness._dispatch(
                    c_endpoint, peer, relays, 10, peer_frames, clock,
                    metrics=metrics,
                )
            state = c_endpoint.poll(clock.next())
            metrics.receive_window()
            if state.status != 0:
                raise ValueError("C endpoint failed while polling result delivery")
            c_frames = [
                _decode_c_stream_frame(wire)
                for wire in state.frames
                if wire != b"\x00"
            ]
            if c_frames:
                harness._dispatch(
                    c_endpoint, peer, relays, 20, c_frames, clock,
                    observed=terminal_events, metrics=metrics,
                )
                metrics.observe_application(terminal_events)

        results = [
            event for event in terminal_events
            if isinstance(event, ApplicationEvent)
            and event.kind == "request_result"
            and event.exchange_id == exchange_id
            and event.service_id == 2
            and event.status == 0
        ]
        if len(results) != 1 or results[0].payload != payload:
            raise ValueError("request result did not match the deterministic workload")
        phase_virtual["warm_exchange"] = clock.now_ms - phase_start
        metrics.process.sample(c_endpoint)
    except Exception as exc:
        failure = f"harness_{type(exc).__name__}"
    finally:
        if c_endpoint is not None:
            metrics.process.sample(c_endpoint)
        if hasattr(harness, "doCleanups"):
            harness.doCleanups()
        tracemalloc_current, tracemalloc_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    end_wall = time.perf_counter_ns()
    end_cpu = time.process_time_ns()
    if failure is not None:
        return {
            "mode": mode,
            "policy": profile["values"]["services"][1]["recovery"],
            "manifest": profile["name"],
            "manifest_sha256": profile["digest"],
            "payload_bytes": len(payload),
            "seed": seed,
            "iteration": iteration,
            "passed": False,
            "failure_code": failure,
            "phase_virtual_ms": phase_virtual,
            "host_wall_ms": (end_wall - start_wall) / 1_000_000,
            "host_python_cpu_ms": (end_cpu - start_cpu) / 1_000_000,
        }

    return {
        "mode": mode,
        "policy": profile["values"]["services"][1]["recovery"],
        "manifest": profile["name"],
        "manifest_sha256": profile["digest"],
        "endpoint_executable_sha256": hashlib.sha256(endpoint_path.read_bytes()).hexdigest(),
        "payload_bytes": len(payload),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "workload_sha256": hashlib.sha256(json.dumps({
            "direction": "peer10_to_c20_request_then_c20_to_peer10_result",
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "loss": "drop_one_middle_request_fragment_once",
            "route": [30, 40],
            "service_id": 2,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "seed": seed,
        "iteration": iteration,
        "fragment_count": fragment_count,
        "dropped_fragment_index": dropped_index,
        "repair_fragment_indices": metrics.recovery_fragment_indices,
        "probe_candidates": metrics.probe_candidates,
        "request_accepts": c_endpoint.last_state.accepts - initial_accepts,
        "fresh_associations": 1,
        "passed": True,
        "phase_virtual_ms": phase_virtual,
        "phase_measurements": metrics.report(),
        "host_wall_ms": (end_wall - start_wall) / 1_000_000,
        "host_python_cpu_ms": (end_cpu - start_cpu) / 1_000_000,
        "python_tracemalloc_peak_delta_bytes": max(
            0, tracemalloc_peak - python_heap_before
        ),
        "python_tracemalloc_current_delta_bytes": tracemalloc_current - python_heap_before,
        "c_process_cpu_ms": (
            None if metrics.process.cpu_start is None or metrics.process.cpu_end is None
            else max(0.0, metrics.process.cpu_end - metrics.process.cpu_start) * 1000
        ),
        "c_process_cpu_unavailable_reason": metrics.process.cpu_unavailable_reason,
        "c_process_rss_current_bytes": metrics.process.rss_current,
        "c_process_rss_peak_bytes": metrics.process.rss_peak,
        "c_process_rss_unavailable_reason": metrics.process.unavailable_reason,
    }


def _payload(seed: int, size: int) -> bytes:
    return bytes((index * 31 + seed * 17 + 7) & 0xFF for index in range(size))


def _parse_csv_ints(value: str, option: str) -> list[int]:
    try:
        items = [int(item) for item in value.split(",")]
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{option} must be comma-separated integers") from exc
    if not items or len(items) != len(set(items)):
        raise argparse.ArgumentTypeError(f"{option} must contain unique values")
    return items


def _serialize(value: Any) -> Any:
    if isinstance(value, Counter):
        return dict(value)
    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    return value


def run_benchmark(args: argparse.Namespace) -> tuple[dict[str, Any], bool]:
    endpoint_path = Path(os.environ["DMP_P23_ENDPOINT_SEC_EXE"]).resolve()
    if not endpoint_path.is_file():
        raise ValueError("endpoint executable is unavailable")
    cases: list[dict[str, Any]] = []
    comparisons: dict[str, Any] = {}
    failures = 0
    for mode in args.modes:
        radio, retry_all = load_profile_pair(mode)
        comparison = validate_profile_pair(radio["values"], retry_all["values"])
        comparisons[mode] = {
            "radio_1": {"manifest": radio["name"], "sha256": radio["digest"]},
            "retry_all": {"manifest": retry_all["name"], "sha256": retry_all["digest"]},
            **comparison,
        }
        for size in args.sizes:
            for iteration in range(args.iterations):
                seed = (args.seed + iteration) & 0xFFFFFFFF
                payload = _payload(seed, size)
                for profile in (radio, retry_all):
                    sample = _sample_case(
                        mode, profile, payload, seed, iteration, endpoint_path
                    )
                    cases.append(sample)
                    if not sample["passed"]:
                        failures += 1
    report = {
        "schema": "DMP-P24-BENCH/1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "machine": platform.machine(),
        },
        "configuration": {
            "modes": args.modes,
            "payload_sizes": args.sizes,
            "iterations": args.iterations,
            "base_seed": args.seed,
            "endpoint_executable_sha256": hashlib.sha256(endpoint_path.read_bytes()).hexdigest(),
        },
        "profile_comparisons": comparisons,
        "limitations": [
            "virtual time is simulated endpoint/relay time, not wall latency",
            "configured frame_tx_ms airtime is a binding model, not physical airtime or energy",
            "energy and physical transmit/reception instrumentation are not present",
            "probe_candidates identifies one-frame original-final-fragment retries without prior FRAG_STATUS; it does not replace transport-level probe instrumentation",
            "core-frame bytes exclude the C test seam Stream R wrapper and are not radio wire bytes",
            "host CPU and memory measurements do not establish MCU resource budgets",
            "the benchmark covers the P23 C endpoint and independent Python peer only",
        ],
        "failure_count": failures,
        "samples": cases,
    }
    return _serialize(report), failures == 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", help="P23 C endpoint executable path")
    parser.add_argument("--modes", default="nnpsk0,xx", help="comma-separated: nnpsk0,xx")
    parser.add_argument("--sizes", default="64,256,1024", help="comma-separated payload bytes")
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--seed", type=int, default=0x2400)
    parser.add_argument("--output", type=Path, help="write JSON to this file; default stdout")
    args = parser.parse_args(argv)
    try:
        args.modes = [item.strip().lower() for item in args.modes.split(",")]
        args.sizes = _parse_csv_ints(args.sizes, "--sizes")
        if not args.modes or len(args.modes) != len(set(args.modes)) or any(
            mode not in PROFILE_PAIRS for mode in args.modes
        ):
            raise ValueError("--modes must be unique members of nnpsk0,xx")
        if not 1 <= args.iterations <= 100:
            raise ValueError("--iterations is outside the supported range")
        if any(size < 64 or size > 1024 for size in args.sizes):
            raise ValueError("--sizes must be between 64 and 1024 bytes")
        if not 0 <= args.seed <= 0xFFFFFFFF:
            raise ValueError("--seed is outside the supported range")
        if args.endpoint:
            os.environ["DMP_P23_ENDPOINT_SEC_EXE"] = str(Path(args.endpoint).resolve())
        report, passed = run_benchmark(args)
        output = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            sys.stdout.write(output)
        return 0 if passed else 1
    except Exception:
        sys.stderr.write("E_BENCHMARK\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
