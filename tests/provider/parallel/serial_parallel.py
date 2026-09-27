"""Bounded MCU-04 driver; records raw replies and never retries a RUN."""
import argparse
import json
from pathlib import Path
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "console"))
import serial_bench as transport


def require(condition):
    if not condition:
        raise RuntimeError("MCU-04 evidence validation failed")


def validate(value, workers, cycles):
    require(value["success"] is True)
    require(value["workers"] == workers and value["cycles"] == cycles)
    require(value["max_inflight"] == workers)
    require(value["cores"] == (2 if value["target"] == "esp32s3" else 1))
    require(value["heap_before"] == value["heap_after"])
    require(value["worker_stack_bytes"] == 12288)
    if workers == 2 and value["cores"] == 2:
        require(value["dual_core_overlap"] > 0 and value["core_mask"] == 3)
    require(len(value["results"]) == workers)
    for index, result in enumerate(value["results"]):
        require(value["sync_rounds"][index] == cycles)
        require(result["completed"] == cycles and result["error_line"] == 0)
        require(result["fixed_pairs"] == result["random_pairs"] == cycles // 2)
        require(result["live"] == result["blocks"] == result["wipe_errors"] == result["refusals"] == 0)
        require(result["attempts"] == result["allocs"] == result["frees"] > 0)
        require(0 < result["peak"] <= result["backing"] == 8192)
        require(result["rng_calls"] == cycles)
        require(0 < value["worker_stack_free"][index] < value["worker_stack_bytes"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True)
    parser.add_argument("--target", choices=("esp32s3", "esp32c3"), required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    serial = None
    with args.output.open("x", encoding="utf-8") as output:
        def record(event, **fields):
            output.write(json.dumps(dict(event=event, time_unix_ms=int(time.time()*1000), **fields)) + "\n")
            output.flush()
        try:
            serial = transport.SerialTransport(args.port, 115200)
            record("metadata", port=args.port, target=args.target, build=args.build, dtr=False, rts=False)
            def command(line, startup=False):
                record("command", line=line)
                serial.write((line + "\n").encode("ascii"))
                deadline = time.monotonic() + 100
                while time.monotonic() < deadline:
                    raw = serial.readline(deadline-time.monotonic(), 4096).decode("ascii").strip()
                    record("raw", line=raw)
                    if not raw.startswith("DMPPAR {"):
                        if startup and not raw.startswith("DMPPAR_"):
                            continue
                        raise RuntimeError("Unexpected serial output: " + raw)
                    value = json.loads(raw[7:], object_pairs_hook=transport._unique_json_object,
                                       parse_constant=transport._reject_json_constant)
                    require(value["id"] == int(line.split()[0]))
                    require(value["target"] == args.target and value["idf"] == "v6.1")
                    require(value["build"] == args.build)
                    return value
                raise TimeoutError("MCU-04 response deadline")
            hello = command("0 HELLO", startup=True)
            require(hello["op"] == "HELLO")
            require(hello["cores"] == (2 if args.target == "esp32s3" else 1))
            initial_heap = None
            identifier = hello["last_id"]
            for workers, cycles in ((1,8), (2,8), (2,32), (2,32), (2,32), (1,8)):
                identifier += 1
                value = command(f"{identifier} RUN {workers} {cycles}")
                require(value["boot"] == hello["boot"] and value["op"] == "RUN")
                validate(value, workers, cycles)
                if initial_heap is None:
                    initial_heap = value["heap_before"]
                require(value["heap_before"] == initial_heap)
                record("accepted", response=value)
            record("complete", success=True)
            print(json.dumps({"success": True, "port": args.port, "cases": 6}))
            return 0
        except Exception as exc:
            record("failed", error=repr(exc))
            print(str(exc), file=sys.stderr)
            return 1
        finally:
            if serial:
                serial.close()


if __name__ == "__main__":
    raise SystemExit(main())
