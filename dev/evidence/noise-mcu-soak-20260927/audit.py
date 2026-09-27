"""Offline audit of completed or failed MCU-05 traces; never accesses hardware."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tests/provider/parallel"))
from serial_soak import BUILD, check, validate


def audit(path):
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    target = rows[0]["target"]
    commands, replies, runs, epochs, bootlogs = [], [], [], [], []
    pending = None
    for row in rows:
        if row["event"] == "command":
            check(pending is None, "Command without previous reply")
            pending = row["line"]
            commands.append(pending)
        elif row["event"] == "raw":
            if row["line"].startswith("DMPPAR {"):
                value = json.loads(row["line"][7:])
                check(pending is not None and value["id"] == int(pending.split()[0]), "Reply mismatch")
                check(value["target"] == target and value["idf"] == "v6.1" and value["build"] == BUILD,
                      "Image mismatch")
                check(value["op"] == pending.split()[1], "Op mismatch")
                replies.append(value)
                pending = None
            else:
                bootlogs.append(row["line"])
        elif row["event"] == "epoch":
            check(row["hello"] == replies[-1], "Epoch/raw mismatch")
            epochs.append(row["hello"])
        elif row["event"] == "accepted":
            value = row["response"]
            check(value == replies[-1], "Accepted/raw mismatch")
            check(row["epoch"] == len(epochs)-1 and value["boot"] == epochs[-1]["boot"], "Boot mismatch")
            validate(value, 2, 128)
            runs.append(value)
    check(len({v["heap_before"] for v in runs}) == 1, "Heap accumulation")
    check(rows[-1]["event"] in ("complete", "failed"), "Unfinished trace")
    if rows[-1]["event"] == "complete":
        check(len(runs) == 12 and len(epochs) == 3 and len(set(v["boot"] for v in epochs)) == 3,
              "Incomplete successful scope")
        check(rows[-1]["pairs"] == 3072 and rows[-1]["planned_resets"] == 2, "Wrong totals")
    results = [r for v in runs for r in v["results"]]
    return dict(target=target, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                outcome=rows[-1]["event"], failure=rows[-1].get("error"),
                commands=len(commands), replies=len(replies), completed_runs=len(runs),
                accepted_epochs=len(epochs), boots=[e["boot"] for e in epochs],
                planned_resets=sum(r["event"] == "planned_reset" for r in rows),
                rom_banners=sum(s.startswith("ESP-ROM:") for s in bootlogs),
                reset_reasons=[s for s in bootlogs if "rst:" in s],
                pairs=sum(r["completed"] for r in results),
                fixed_pairs=sum(r["fixed_pairs"] for r in results),
                random_pairs=sum(r["random_pairs"] for r in results),
                allocs=sum(r["allocs"] for r in results), frees=sum(r["frees"] for r in results),
                heap_free=runs[0]["heap_before"], heap_min=min(v["heap_min"] for v in runs),
                worker_peak=max(r["peak"] for r in results),
                worker_stack_used=max(v["worker_stack_bytes"]-min(v["worker_stack_free"]) for v in runs),
                main_stack_used=max(8192-v["main_stack_free"] for v in runs),
                max_call_us=max(r["max_call_us"] for r in results),
                total_run_us=sum(v["elapsed_us"] for v in runs),
                dual_core_overlap=sum(v["dual_core_overlap"] for v in runs))


if __name__ == "__main__":
    here = Path(__file__).resolve().parent
    result = [audit(here / f"physical-{name}.jsonl") for name in ("s3", "c3")]
    (here / "physical-audit.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
