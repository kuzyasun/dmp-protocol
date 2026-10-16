"""MCU-05 bounded soak of unchanged MCU-04 images; never retries a command."""
import argparse
import csv
import json
from pathlib import Path
import re
import sys
import time

from serial_parallel import transport, validate

BUILD = "b5cb389bbeda7d86c856959e6f547ad71200916d92de8b44add98dd0160007b0"
EPOCHS, RUNS, CYCLES = 3, 4, 128
COREDUMP_OFFSET = 0x300000
COREDUMP_SIZE = 0x100000
FLASH_SIZE_4MB = 0x400000
PARTITION_REGION_ALIGNMENT = 0x1000
PARTITION_TABLE_END = 0x9000
EXPECTED_PARTITIONS = (
    ("nvs", "data", "nvs", 0x9000, 0x6000),
    ("phy_init", "data", "phy", 0xF000, 0x1000),
    ("factory", "app", "factory", 0x10000, 0x2F0000),
    ("coredump", "data", "coredump", 0x300000, 0x100000),
)


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def parse_partitions_csv(text: str) -> list[dict]:
    partitions = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = next(csv.reader([line], skipinitialspace=True))
        except csv.Error as error:
            raise RuntimeError(f"Malformed partition row at line {line_number}: {error}") from error
        parts = [part.strip() for part in parts]
        if len(parts) not in (5, 6) or any(not part for part in parts[:5]):
            raise RuntimeError(f"Malformed partition row at line {line_number}")
        name, ptype, subtype = parts[0], parts[1], parts[2]
        try:
            offset = int(parts[3], 0)
            size = int(parts[4], 0)
        except ValueError as error:
            raise RuntimeError(f"Invalid partition offset/size at line {line_number}") from error
        if size <= 0:
            raise RuntimeError(f"Invalid partition size at line {line_number}: {parts[4]}")
        flags = parts[5] if len(parts) > 5 and parts[5] else None
        partitions.append({
            "name": name,
            "type": ptype,
            "subtype": subtype,
            "offset": offset,
            "size": size,
            "flags": flags,
        })
    return partitions


def validate_partition_table(text: str) -> list[dict]:
    partitions = parse_partitions_csv(text)
    check(bool(partitions), "Partition table is empty")
    names = [partition["name"] for partition in partitions]
    check(len(names) == len(set(names)), "Duplicate partition name")
    coredump = next((p for p in partitions if p["name"] == "coredump"), None)
    check(coredump is not None, "Missing coredump partition")
    check(coredump["type"] == "data" and coredump["subtype"] == "coredump",
          f"Coredump partition has invalid type/subtype: {coredump['type']}/{coredump['subtype']}")
    check(coredump["offset"] == COREDUMP_OFFSET,
          f"Coredump partition offset mismatch: {hex(coredump['offset'])} != {hex(COREDUMP_OFFSET)}")
    check(coredump["size"] == COREDUMP_SIZE,
          f"Coredump partition size mismatch: {hex(coredump['size'])} != {hex(COREDUMP_SIZE)}")

    sorted_parts = sorted(partitions, key=lambda p: p["offset"])
    prev_end = 0
    for p in sorted_parts:
        check(p["offset"] >= PARTITION_TABLE_END,
              f"Partition {p['name']} starts before partition table end: {hex(p['offset'])}")
        check(p["offset"] % PARTITION_REGION_ALIGNMENT == 0 and
              p["size"] % PARTITION_REGION_ALIGNMENT == 0,
              f"Partition {p['name']} is not aligned to {hex(PARTITION_REGION_ALIGNMENT)}")
        check(p["offset"] >= prev_end,
              f"Partition overlap detected at {p['name']} ({hex(p['offset'])} < {hex(prev_end)})")
        end = p["offset"] + p["size"]
        check(end <= FLASH_SIZE_4MB,
              f"Partition {p['name']} extends beyond 4 MiB: {hex(end)} > {hex(FLASH_SIZE_4MB)}")
        prev_end = end
    actual = tuple(
        (p["name"], p["type"], p["subtype"], p["offset"], p["size"])
        for p in sorted_parts
    )
    check(actual == EXPECTED_PARTITIONS,
          "Partition layout does not match the expected 4 MiB provider test table")
    return partitions


def validate_target_partition_config(target_dir: Path) -> None:
    csv_path = target_dir / "partitions.csv"
    check(csv_path.is_file(), f"Missing partitions.csv in {target_dir}")
    validate_partition_table(csv_path.read_text(encoding="utf-8"))

    sdkconfig_path = target_dir / "sdkconfig.defaults"
    check(sdkconfig_path.is_file(), f"Missing sdkconfig.defaults in {target_dir}")
    config_text = sdkconfig_path.read_text(encoding="utf-8")
    check("CONFIG_PARTITION_TABLE_CUSTOM=y" in config_text,
          "CONFIG_PARTITION_TABLE_CUSTOM=y missing in sdkconfig.defaults")
    check('CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"' in config_text,
          'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv" missing in sdkconfig.defaults')
    check("CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y" in config_text,
          "CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y missing in sdkconfig.defaults")
    check("CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y" in config_text,
          "CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y missing in sdkconfig.defaults")


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
            target_dir = Path(__file__).resolve().parent.parent / "targets" / "esp32-parallel"
            validate_target_partition_config(target_dir)
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
