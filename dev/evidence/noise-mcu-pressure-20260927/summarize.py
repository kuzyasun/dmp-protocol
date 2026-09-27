"""Independently audit recorded pressure evidence; no serial or runner imports."""
import collections
import hashlib
import json
import sys
from pathlib import Path


def audit(path):
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    counts = collections.Counter(e["event"] for e in events)
    assert not counts["run_failed"]
    pending, identities, latest, stats_by_peer = {}, {}, {}, collections.defaultdict(list)
    nonces, pairs, refusals = {}, [], []
    previous = None
    for event in events:
        kind = event["event"]
        if kind in ("command", "synchronize"):
            peer = event["peer"]
            assert peer not in pending
            pending[peer] = event
        elif kind == "response":
            peer, response = event["peer"], event["response"]
            command = pending.pop(peer)
            assert response == json.loads(event["raw"].removeprefix("DMPBENCH "))
            assert command["id"] == response["id"]
            identity = tuple(response[k] for k in ("target", "idf", "boot", "build"))
            assert identity == identities.setdefault(peer, identity)
            if response["id"]:
                assert response["id"] == latest[peer] + 1 == response["last_id"]
            latest[peer] = response["last_id"]
            stats = response["stats"]
            assert 0 <= stats["arena_live"] <= stats["arena_peak"] <= stats["quota"]
            assert stats["wipe_errors"] == 0
            assert stats["attempts"] == stats["allocs"] + stats["refusals"]
            assert stats["allocs"] - stats["frees"] == stats["blocks"]
            stats_by_peer[peer].append(stats)
            op, args = command["op"], command.get("args", [])
            if response["rc"]:
                assert (op in ("NEW", "SPLIT") and response["rc"] == 17665) or (op == "RESET" and response["rc"] == 17676)
                refusals.append({"peer": peer, "op": op, "rc": response["rc"], "quota": stats["quota"], "id": response["id"]})
            elif op == "NEW":
                nonces[(peer, args[0])] = 0
            elif op == "SEAL":
                key = (peer, args[0])
                assert int(args[1]) > nonces[key]
                nonces[key] = int(args[1])
            elif op in ("READ", "OPEN"):
                sender, sent_command, sent_response = previous
                assert sender != peer and sent_response["rc"] == 0
                assert sent_command["op"] == {"READ": "WRITE", "OPEN": "SEAL"}[op]
                sent_args = sent_command["args"]
                assert args[0] == sent_args[0]
                assert args[-1] == sent_response["data"]
                assert response["data"] == sent_args[-1]
                if op == "OPEN":
                    assert args[1:3] == sent_args[1:3]
                pairs.append(op)
            previous = (peer, command, response)
    assert not pending
    cases = [e for e in events if e["event"] == "case_result"]
    assert {(c["quota"], c["orientation"]) for c in cases} == {(q, o) for q in (2048, 3840, 4096, 8192, 32768) for o in (0, 1)}
    assert len(cases) == 10 and counts["summary"] == 2
    for case in cases:
        assert case["success"] and case["guard_survived"]
        for stats in case["final_stats"].values():
            assert stats["arena_live"] == stats["blocks"] == stats["wipe_errors"] == 0
            assert stats["allocs"] == stats["frees"]
    for rows in stats_by_peer.values():
        assert rows[-1]["quota"] == 32768 and rows[-1]["arena_live"] == rows[-1]["blocks"] == 0
    return {
        "trace_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "events": dict(counts), "forwarded_pairs": dict(collections.Counter(pairs)),
        "duration_seconds": (events[-1]["time_unix_ms"] - events[0]["time_unix_ms"]) / 1000,
        "identities": identities, "expected_errors": refusals,
        "memory": {peer: {"heap_free_values": sorted({s["heap_free"] for s in rows}),
                          "heap_min": min(s["heap_min"] for s in rows),
                          "heap_largest_min": min(s["heap_largest"] for s in rows),
                          "stack_free_min": min(s["stack_free_min"] for s in rows),
                          "max_arena_peak": max(s["arena_peak"] for s in rows)}
                   for peer, rows in stats_by_peer.items()},
        "cases": [{k: c[k] for k in ("quota", "orientation", "admitted", "completed", "refused", "split_refusals", "peak_arena_live", "guard_survival_checks", "cancelled")} for c in cases],
    }


if __name__ == "__main__":
    print(json.dumps(audit(Path(sys.argv[1])), indent=2, sort_keys=True))
