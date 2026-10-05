#!/usr/bin/env python3
"""Compile-only 32-bit sizeof/alignof probe.

Host heap and stack peaks are not MCU peaks. When arm-none-eabi-gcc is
absent the script writes that gap and exits 0. A present compiler that
fails to compile exits 1.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys


MCU_FLAGS = [
    "-std=c11",
    "-mcpu=cortex-m4",
    "-mthumb",
    "-mfloat-abi=soft",
    "-ffreestanding",
    "-fno-builtin",
    "-Os",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
]

REQUIRED_LAYOUT_OBJECTS = {
    "endpoint",
    "endpoint_storage",
    "freshness_slot",
    "sender_slot",
    "result_slot",
    "history_slot",
    "correlation_slot",
    "adapter_slot",
    "reassembly_slot",
    "reassembly_tombstone",
    "identity_slot",
    "stream_decoder",
    "replay_window",
}


def run(cmd, cwd=None):
    completed = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def parse_nm(text):
    sizes = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        size_hex = parts[-3] if len(parts) >= 4 and re.fullmatch(r"[0-9A-Fa-f]+", parts[-3]) else None
        # nm -S: address size type name, or size type name when address is absent
        if len(parts) >= 4 and re.fullmatch(r"[0-9A-Fa-f]+", parts[1]):
            size_hex = parts[1]
            name = parts[-1]
        elif len(parts) >= 3 and re.fullmatch(r"[0-9A-Fa-f]+", parts[0]):
            size_hex = parts[0]
            name = parts[-1]
        else:
            continue
        if name.startswith("ram_mcu_size_") or name.startswith("ram_mcu_align_"):
            sizes[name] = int(size_hex, 16)
    objects = []
    names = sorted(
        name[len("ram_mcu_size_") :]
        for name in sizes
        if name.startswith("ram_mcu_size_")
    )
    for name in names:
        objects.append(
            {
                "name": name,
                "sizeof": sizes.get("ram_mcu_size_" + name),
                "alignof": sizes.get("ram_mcu_align_" + name),
            }
        )
    return objects


def parse_return_immediate(disassembly):
    """Read a Thumb return value loaded into r0."""
    low = None
    high = 0
    saw = False
    for line in disassembly.splitlines():
        movs = re.search(r"\bmovs\s+r0,\s+#(-?\d+)", line)
        if movs:
            return int(movs.group(1))
        movw = re.search(r"\bmovw\s+r0,\s+#(\d+)", line)
        if movw:
            low = int(movw.group(1))
            saw = True
            continue
        mov_imm = re.search(r"\bmov(?:\.w)?\s+r0,\s+#(\d+)", line)
        if mov_imm and "movs" not in line and "movw" not in line and "movt" not in line:
            return int(mov_imm.group(1))
        movt = re.search(r"\bmovt\s+r0,\s+#(\d+)", line)
        if movt and low is not None:
            high = int(movt.group(1))
            return (high << 16) | low
        word = re.search(r"\.word\s+(-?0x[0-9A-Fa-f]+|-?\d+)", line)
        if word and saw is False and "ldr" in disassembly:
            token = word.group(1)
            return int(token, 0)
    if low is not None:
        return low
    return None


def write_report(path, report):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")


def main():
    parser = argparse.ArgumentParser(description="Cortex-M4 compile-only layout sizes")
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--layout", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--cc", default="")
    args = parser.parse_args()

    physical_run_must_measure = [
        "provider heap current and peak on the target allocator, including per-allocation overhead",
        "largest single Noise allocation against scratch_limit",
        "task stack high-water for handshake, poll, submit, rx, cleanup, reconnect, and rotation",
        "caller-owned object placement in the target ABI, including padding",
        "static backend data and any DMA or adapter buffers outside libdmp",
    ]
    base = {
        "abi_class": "mcu_compile_only",
        "layout_classification": "compile_only_sizeof_alignof",
        "target": "cortex-m4",
        "pointer_bits": 32,
        "runtime_executed": False,
        "runtime_peak_measurement": False,
        "host_peaks_are_mcu_peaks": False,
        "physical_run_must_measure": physical_run_must_measure,
    }
    cc = args.cc.strip()
    if not cc or not os.path.isfile(cc):
        found = shutil.which("arm-none-eabi-gcc")
        cc = found or ""
    if not cc:
        base.update(
            {
                "available": False,
                "missing": [
                    "arm-none-eabi-gcc (Cortex-M4 compile). Not on PATH.",
                    "xtensa-esp32s3-elf-gcc / ESP-IDF (ESP32-S3 compile). Not on PATH.",
                ],
                "objects": [],
            }
        )
        write_report(args.output, base)
        print("MCU ABI compilers not found; wrote the gap")
        return 0

    os.makedirs(args.work, exist_ok=True)
    version_rc, version_out, version_err = run([cc, "-dumpfullversion", "-dumpmachine"])
    bin_dir = os.path.dirname(cc)
    nm = os.path.join(bin_dir, "arm-none-eabi-nm")
    objdump = os.path.join(bin_dir, "arm-none-eabi-objdump")
    if os.name == "nt":
        nm += ".exe"
        objdump += ".exe"
    root = args.source_root
    includes = [
        "-I", os.path.join(root, "include"),
        "-I", os.path.join(root, "src", "security"),
        "-I", os.path.join(root, "third_party", "noise-c", "include"),
        "-I", os.path.join(root, "third_party", "noise-c", "src"),
        "-I", os.path.join(root, "tests", "provider", "backend"),
    ]
    layout_obj = os.path.join(args.work, "mcu_layout.o")
    layout_cmd = [cc] + MCU_FLAGS + includes + ["-c", args.layout, "-o", layout_obj]
    layout_rc, layout_out, layout_err = run(layout_cmd)
    objects = []
    nm_out = ""
    if layout_rc == 0:
        nm_rc, nm_out, nm_err = run([nm, "-S", layout_obj])
        if nm_rc != 0:
            layout_rc = nm_rc
            layout_err += nm_err
        else:
            objects = parse_nm(nm_out)
            present = {item["name"] for item in objects}
            missing_layout = sorted(REQUIRED_LAYOUT_OBJECTS - present)
            if missing_layout:
                layout_rc = 1
                layout_err += "missing required layout records: " + ", ".join(missing_layout)
    else:
        nm_err = ""

    private = []
    private_errors = []
    units = [
        ("dmp_hs_size", os.path.join(root, "src", "security", "handshake.c"), "hs.o"),
        ("dmp_hs_attempt_size", os.path.join(root, "src", "security", "handshake.c"), "hs.o"),
        ("dmp_provider_size", os.path.join(root, "src", "security", "provider_adapter.c"), "provider.o"),
    ]
    built = {}
    for symbol, source, obj_name in units:
        obj_path = os.path.join(args.work, obj_name)
        if obj_name not in built:
            cmd = [cc] + MCU_FLAGS + includes + ["-c", source, "-o", obj_path]
            rc, out, err = run(cmd)
            built[obj_name] = (rc, out, err, obj_path, cmd)
        rc, out, err, obj_path, cmd = built[obj_name]
        entry = {
            "symbol": symbol,
            "source": source,
            "command": cmd,
            "compile_exit": rc,
        }
        if rc != 0:
            entry["sizeof"] = None
            entry["stderr"] = err[-4000:]
            private_errors.append(symbol)
        else:
            dump_rc, dump_out, dump_err = run(
                [objdump, "-d", f"--disassemble={symbol}", obj_path]
            )
            entry["disassembly"] = dump_out[-2000:]
            entry["sizeof"] = parse_return_immediate(dump_out) if dump_rc == 0 else None
            if entry["sizeof"] is None:
                entry["objdump_stderr"] = dump_err[-2000:]
                private_errors.append(symbol)
        private.append(entry)

    base.update(
        {
            "available": True,
            "compiler": cc,
            "compiler_id": (version_out or version_err).strip(),
            "flags": MCU_FLAGS,
            "layout_command": layout_cmd,
            "layout_exit": layout_rc,
            "layout_stderr": layout_err[-4000:] if layout_rc != 0 else "",
            "objects": objects,
            "private_sizes": private,
            "missing": [] if layout_rc == 0 else ["public layout object failed required-record validation or failed to compile"],
            "xtensa_esp32s3": "not on PATH; ESP-IDF is not installed locally",
        }
    )
    write_report(args.output, base)
    if layout_rc != 0 or private_errors:
        print(layout_err, file=sys.stderr)
        print("MCU ABI compile incomplete", file=sys.stderr)
        return 1
    print(f"MCU ABI objects {len(objects)} private {len(private)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
