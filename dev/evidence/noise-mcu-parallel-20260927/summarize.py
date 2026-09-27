"""Offline MCU-04 raw-trace audit; no runner or serial imports."""
import hashlib
import json
from pathlib import Path
import sys


def check(condition):
    if not condition:
        raise RuntimeError("Recorded MCU-04 evidence failed independent checks")


def audit(path):
    events = [json.loads(line) for line in path.read_text().splitlines()]
    check(events[-1]["event"] == "complete" and events[-1]["success"] is True)
    check(not any(e["event"] == "failed" for e in events))
    responses = [json.loads(e["line"][7:]) for e in events
                 if e["event"] == "raw" and e["line"].startswith("DMPPAR {")]
    accepted = [e["response"] for e in events if e["event"] == "accepted"]
    commands = [e["line"] for e in events if e["event"] == "command"]
    check(len(responses) == 7 and len(commands) == 7 and accepted == responses[1:])
    hello = responses[0]
    check(hello["id"] == 0 and hello["op"] == "HELLO")
    identity = {k: hello[k] for k in ("boot", "build", "target", "idf", "cores")}
    check(identity["idf"] == "v6.1")
    check(identity["cores"] == (2 if identity["target"] == "esp32s3" else 1))
    expected = [(1,8),(2,8),(2,32),(2,32),(2,32),(1,8)]
    check([(r["workers"], r["cycles"]) for r in accepted] == expected)
    for i, r in enumerate(accepted, 1):
        check(r["id"] == hello["last_id"] + i and r["op"] == "RUN")
        check(commands[i] == f'{r["id"]} RUN {r["workers"]} {r["cycles"]}')
        check(all(r[k] == v for k,v in identity.items()))
        check(r["success"] is True and r["max_inflight"] == r["workers"])
        check(r["heap_before"] == r["heap_after"] == accepted[0]["heap_before"])
        if r["workers"] == 2 and r["cores"] == 2:
            check(r["core_mask"] == 3 and r["dual_core_overlap"] > 0)
        check(len(r["results"]) == r["workers"])
        for worker, result in enumerate(r["results"]):
            check(r["sync_rounds"][worker] == result["completed"] == r["cycles"])
            check(result["error_line"] == result["refusals"] == result["wipe_errors"] == result["live"] == result["blocks"] == 0)
            check(result["allocs"] == result["frees"] == result["attempts"] > 0)
            check(result["fixed_pairs"] == result["random_pairs"] == r["cycles"] // 2)
            check(result["rng_calls"] == r["cycles"])
            check(0 < result["peak"] <= result["backing"] == 8192)
            check(0 < r["worker_stack_free"][worker] < r["worker_stack_bytes"] == 12288)
    return dict(identity=identity, trace_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                responses=len(responses), cases=len(accepted),
                pairs=sum(x["completed"] for r in accepted for x in r["results"]),
                allocations=sum(x["allocs"] for r in accepted for x in r["results"]),
                peak_per_worker=max(x["peak"] for r in accepted for x in r["results"]),
                max_call_us=max(x["max_call_us"] for r in accepted for x in r["results"]),
                max_stack_used=[max(r["worker_stack_bytes"]-r["worker_stack_free"][i]
                                    for r in accepted if r["workers"]>i) for i in (0,1)],
                heap_free=accepted[0]["heap_before"],
                heap_min=min(r["heap_min"] for r in accepted),
                main_stack_used=8192-min(r["main_stack_free"] for r in accepted),
                duration_seconds=(events[-1]["time_unix_ms"]-events[0]["time_unix_ms"])/1000,
                runs=accepted)


if __name__ == "__main__":
    print(json.dumps({Path(p).name: audit(Path(p)) for p in sys.argv[1:]}, indent=2))
