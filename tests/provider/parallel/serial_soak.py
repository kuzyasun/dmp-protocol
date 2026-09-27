"""MCU-05 bounded soak of unchanged MCU-04 images; never retries a command."""
import argparse
import json
from pathlib import Path
import re
import sys
import time

from serial_parallel import transport, validate

BUILD = "383e6818927e55aa1a4f51dc9119b77bcb10c68892512af16fe001f554ebc64f"
EPOCHS, RUNS, CYCLES = 3, 4, 128


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def reset_uart(serial, sleep=time.sleep):
    """UART-bridge EN pulse, matching esp_pylib.serial_reset hard_reset.

    DTR stays inactive (IO0 high); reapply DTR after RTS for usbser.sys.
    This is a warm reset only, never a bootloader/provisioning operation.
    """
    port = serial._serial
    port.setDTR(False)
    try:
        port.setRTS(True)
        port.setDTR(False)
        sleep(0.1)
    finally:
        port.setRTS(False)
        port.setDTR(False)
    sleep(1.0)


class Soak:
    def __init__(self, serial, target, record, reset=reset_uart):
        self.serial, self.target, self.record, self.reset = serial, target, record, reset

    def command(self, line, startup=False, planned_reset=False):
        self.record("command", line=line)
        self.serial.write((line + "\n").encode("ascii"))
        deadline = time.monotonic() + (10 if startup else 100)
        boot_lines = 0
        banners = reasons = 0
        while time.monotonic() < deadline:
            raw = self.serial.readline(deadline - time.monotonic(), 4096).decode("ascii").strip()
            self.record("raw", line=raw)
            if not raw.startswith("DMPPAR {"):
                boot_lines += 1
                check(startup and boot_lines <= 64 and not raw.startswith("DMPPAR_")
                      and not re.search(r"panic|watchdog|wdt|brownout|abort\(|Guru Meditation", raw, re.I),
                      "Unexpected serial output: " + raw)
                if raw.startswith("ESP-ROM:"):
                    banners += 1
                    check(banners == 1, "Multiple boot banners")
                if "rst:" in raw:
                    reasons += 1
                    check(reasons == 1 and re.search(r"rst:0x1\s*\(POWERON\)", raw),
                          "Unexpected/duplicate reset cause: " + raw)
                continue
            value = json.loads(raw[7:], object_pairs_hook=transport._unique_json_object,
                               parse_constant=transport._reject_json_constant)
            check(value["id"] == int(line.split()[0]), "Reply ID mismatch")
            check(value["target"] == self.target and value["idf"] == "v6.1"
                  and value["build"] == BUILD, "Image identity mismatch")
            check(value["cores"] == (2 if self.target == "esp32s3" else 1), "Core count mismatch")
            check(isinstance(value["boot"], str) and re.fullmatch(r"[0-9a-f]{8}", value["boot"]),
                  "Invalid boot identity")
            if planned_reset:
                check(banners == reasons == 1, "Missing planned-reset ROM evidence")
            return value
        raise TimeoutError("MCU-05 response deadline")

    def run(self):
        heap = None
        boots = set()
        for epoch in range(EPOCHS):
            if epoch:
                # All prior RUNs have passed cleanup checks before any reset.
                self.record("planned_reset", epoch=epoch)
                self.reset(self.serial)
                self.record("reset_released", epoch=epoch)
            hello = self.command("0 HELLO", startup=True, planned_reset=epoch > 0)
            check(hello["op"] == "HELLO", "Expected HELLO")
            check(hello["boot"] not in boots, "Reset did not produce a fresh boot identity")
            check(type(hello["last_id"]) is int and 0 <= hello["last_id"] < 0xfffffff0,
                  "Invalid command counter")
            if epoch:
                check(hello["last_id"] == 0, "Command counter did not reset")
            boots.add(hello["boot"])
            self.record("epoch", epoch=epoch, hello=hello)
            identifier = hello["last_id"]
            previous_run = None
            for block in range(RUNS):
                identifier += 1
                value = self.command(f"{identifier} RUN 2 {CYCLES}")
                check(value["boot"] == hello["boot"] and value["op"] == "RUN", "Unexpected reboot/op")
                validate(value, 2, CYCLES)
                check(value["core_mask"] == (3 if self.target == "esp32s3" else 1), "Wrong worker cores")
                if self.target == "esp32c3":
                    check(value["dual_core_overlap"] == 0, "Impossible dual-core overlap")
                check(type(value["run"]) is int and value["run"] > 0, "Invalid RUN counter")
                if previous_run is not None:
                    check(value["run"] == previous_run + 1, "RUN counter discontinuity")
                elif epoch:
                    check(value["run"] == 1, "RUN counter did not reset")
                previous_run = value["run"]
                if heap is None:
                    heap = value["heap_before"]
                check(value["heap_before"] == heap, "Heap changed across RUNs/boots")
                self.record("accepted", epoch=epoch, block=block, response=value)
            # End each epoch with an identity/counter check; no stale reply can
            # authorize the reset or successful completion.
            final = self.command("0 HELLO")
            check(final["op"] == "HELLO" and final["boot"] == hello["boot"]
                  and final["last_id"] == identifier, "Epoch ended in unexpected state")
        self.record("complete", success=True, epochs=EPOCHS, runs=EPOCHS * RUNS,
                    pairs=EPOCHS * RUNS * 2 * CYCLES, planned_resets=EPOCHS - 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True)
    parser.add_argument("--target", choices=("esp32s3", "esp32c3"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    serial = None
    with args.output.open("x", encoding="utf-8") as output:
        def record(event, **fields):
            output.write(json.dumps(dict(event=event, time_unix_ms=int(time.time()*1000), **fields)) + "\n")
            output.flush()
        try:
            record("metadata", port=args.port, target=args.target, build=BUILD,
                   epochs=EPOCHS, runs_per_epoch=RUNS, workers=2, cycles=CYCLES,
                   reset="UART bridge EN, RTS true 100ms then false; DTR false")
            serial = transport.SerialTransport(args.port, 115200)
            Soak(serial, args.target, record).run()
            print(json.dumps(dict(success=True, target=args.target, pairs=EPOCHS*RUNS*2*CYCLES)))
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
