#!/usr/bin/env python3
"""Collect reproducible, bounded link evidence from an existing MCU build."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
HEADER_SUFFIXES = {".h", ".hpp", ".inc"}
ARCHIVES = ("libnoise_c.a", "libsodium.a", "libdmp_mcu_fixture.a")
FORBIDDEN_NOISE_UNDEFINED = {
    "malloc", "calloc", "realloc", "free", "randombytes_buf", "randombytes_stir",
}
REQUIRED_NOISE_UNDEFINED = {
    "noise_allocator_allocate", "noise_allocator_release", "noise_rand_bytes_checked",
}
REQUIRED_ELF = {
    "noise_handshakestate_new_by_name", "noise_cipherstate_encrypt_with_ad",
    "sodium_init", "dmp_sodium_entropy_read", "noise_allocator_allocate",
}


def fail(message):
    raise RuntimeError(message)


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def selected(path, build_dir):
    path = path.resolve()
    try:
        relative = path.relative_to(build_dir.resolve())
        if "checked-sodium" in relative.parts:
            return True
    except ValueError:
        pass
    roots = (ROOT / "third_party" / "noise-c", ROOT / "tests" / "provider",
             ROOT / "build" / "noise-upstream")
    for base in roots:
        try:
            path.relative_to(base.resolve())
            return True
        except ValueError:
            pass
    return False


def run_tool(args, output_path):
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False)
    except OSError as exc:
        fail("cannot run {}: {}".format(args[0], exc))
    stdout = result.stdout.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    stderr = result.stderr.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    if result.returncode:
        fail("{} exited {}: {}".format(args[0], result.returncode, stderr.strip()))
    output_path.write_text(stdout, encoding="utf-8", newline="\n")
    return stdout


def symbols(text):
    return {line.split()[-1] for line in text.splitlines() if line.split()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--nm", required=True, help="nm executable")
    parser.add_argument("--size", required=True, help="size executable")
    parser.add_argument("--output", required=True, type=Path, help="output JSON path")
    parser.add_argument("--elf", type=Path, help="linked ELF to inspect")
    args = parser.parse_args()

    build_dir = args.build_dir.resolve()
    if not build_dir.is_dir():
        fail("build directory does not exist: {}".format(build_dir))
    compile_db = build_dir / "compile_commands.json"
    report_path = args.output.resolve()
    if report_path.is_relative_to(build_dir) or selected(report_path, build_dir):
        fail("output must be outside the build directory and selected source inputs")
    report_path.unlink(missing_ok=True)
    try:
        entries = json.loads(compile_db.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail("cannot read {}: {}".format(compile_db, exc))
    if not isinstance(entries, list):
        fail("compile_commands.json must contain a JSON array")

    selected_entries = []
    selected_sources = set()
    object_paths = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("directory"), str) or not isinstance(entry.get("file"), str):
            fail("malformed compile command entry")
        command = entry.get("command")
        arguments = entry.get("arguments")
        if command is not None and not isinstance(command, str):
            fail("compile command 'command' must be a string")
        if arguments is not None and (not isinstance(arguments, list) or
                                      any(not isinstance(item, str) for item in arguments)):
            fail("compile command 'arguments' must be a list of strings")
        if command is None and arguments is None:
            fail("compile command entry has neither 'command' nor 'arguments'")
        source = Path(entry["file"])
        if not source.is_absolute():
            source = Path(entry["directory"]) / source
        if selected(source, build_dir):
            selected_entries.append(entry)
            selected_sources.add(source.resolve())
            object_output = entry.get("output")
            command_text = command or ""
            if object_output is None:
                match = re.search(r"(?:^|\s)-o\s+(?:\"([^\"]+)\"|(\S+))", command_text)
                object_output = (match.group(1) or match.group(2)) if match else None
                if object_output is None and arguments:
                    try:
                        object_output = arguments[arguments.index("-o") + 1]
                    except (ValueError, IndexError):
                        pass
            if isinstance(object_output, str):
                object_path = Path(object_output)
                if not object_path.is_absolute():
                    object_path = Path(entry["directory"]) / object_path
                object_paths.append(object_path.resolve().with_suffix(".su"))
    if not selected_entries:
        fail("no selected source files found in compile_commands.json")

    source_files = set(selected_sources)
    header_roots = [ROOT / "third_party" / "noise-c" / "include",
                    ROOT / "third_party" / "noise-c" / "src",
                    ROOT / "tests" / "provider" / "backend"]
    backend_root = None
    for source in selected_sources:
        parts = source.parts
        for index, part in enumerate(parts):
            if part.startswith("esphome_libsodium-") and index + 1 < len(parts):
                backend_root = Path(*parts[:index + 1])
                break
        if backend_root:
            break
    if backend_root:
        header_roots.extend((backend_root / "libsodium" / "src" / "libsodium" / "include",
                             backend_root / "port_include"))
    for base in header_roots:
        if base.is_dir():
            source_files.update(p.resolve() for p in base.rglob("*")
                                if p.is_file() and p.suffix in HEADER_SUFFIXES)
    fixture_headers = [p.resolve() for p in build_dir.rglob("noise_fixture_probe.h") if p.is_file()]
    source_files.update(fixture_headers)
    for path in sorted(source_files):
        if not path.is_file():
            fail("selected source input is missing: {}".format(path))

    report_path.parent.mkdir(parents=True, exist_ok=True)
    evidence = {
        "schema": "dmp-mcu-build-evidence-v1",
        "build_dir": str(build_dir),
        "compile_commands": str(compile_db),
        "compile_entries": selected_entries,
        "source_sha256": {str(p): sha256(p) for p in sorted(source_files)},
        "configuration_sha256": {},
        "stack_usage": [],
        "archives": {},
        "elf": None,
        "claims": {
            "archive_sizes": "archive member totals only; not linked image size or runtime RAM",
            "stack_usage": "compiler .su static estimates; not runtime stack high-water",
        },
    }
    for name in ("CMakeCache.txt", "sdkconfig"):
        path = build_dir / name
        if path.is_file():
            evidence["configuration_sha256"][name] = sha256(path)

    for path in sorted(set(object_paths)):
        if path.is_file():
            evidence["stack_usage"].append({"path": str(path), "sha256": sha256(path),
                                             "text": path.read_text(encoding="utf-8", errors="replace")})

    archive_paths = {}
    for name in ARCHIVES:
        matches = sorted(p.resolve() for p in build_dir.rglob(name) if p.is_file())
        if len(matches) != 1:
            fail("expected exactly one {} under {}, found {}".format(name, build_dir, len(matches)))
        archive_paths[name] = matches[0]

    for name, path in archive_paths.items():
        stem = Path(name).stem
        undefined = run_tool([args.nm, "-A", "-u", str(path)], report_path.with_name(report_path.stem + "-" + stem + "-nm-undefined.txt"))
        size_text = run_tool([args.size, "-A", str(path)], report_path.with_name(report_path.stem + "-" + stem + "-size.txt"))
        evidence["archives"][name] = {"path": str(path), "sha256": sha256(path),
                                      "undefined_symbols_log": report_path.stem + "-" + stem + "-nm-undefined.txt",
                                      "size_log": report_path.stem + "-" + stem + "-size.txt",
                                      "size_output": size_text}
        if name == "libnoise_c.a":
            undefined_symbols = symbols(undefined)
            forbidden = sorted(undefined_symbols & FORBIDDEN_NOISE_UNDEFINED)
            required = sorted(REQUIRED_NOISE_UNDEFINED - undefined_symbols)
            if forbidden:
                fail("Noise archive has forbidden undefined symbols: " + ", ".join(forbidden))
            if required:
                fail("Noise archive is missing required undefined hooks: " + ", ".join(required))

    if args.elf:
        elf = args.elf.resolve()
        if not elf.is_file():
            fail("ELF does not exist: {}".format(elf))
        defined_log = report_path.with_name(report_path.stem + "-elf-nm-defined.txt")
        defined_text = run_tool([args.nm, "-S", "--defined-only", str(elf)], defined_log)
        elf_size_log = report_path.with_name(report_path.stem + "-elf-size.txt")
        elf_size = run_tool([args.size, "-A", str(elf)], elf_size_log)
        defined = symbols(defined_text)
        legacy = sorted(defined & {"randombytes_buf", "randombytes_stir", "randombytes_sysrandom_implementation"})
        missing = sorted(REQUIRED_ELF - defined)
        if legacy:
            fail("forbidden legacy RNG symbols survived ELF linking: " + ", ".join(legacy))
        if missing:
            fail("ELF is missing required symbols: " + ", ".join(missing))
        map_path = elf.with_suffix(".map")
        if not map_path.is_file():
            map_matches = sorted(p.resolve() for p in build_dir.rglob(elf.stem + ".map") if p.is_file())
            if len(map_matches) > 1:
                fail("multiple map files match ELF {} under {}".format(elf.name, build_dir))
            map_path = map_matches[0] if map_matches else None
        if map_path is None:
            fail("no map file found for ELF {} beside it or under {}".format(elf, build_dir))
        evidence["elf"] = {"path": str(elf), "sha256": sha256(elf),
                           "nm_defined_log": defined_log.name, "size_log": elf_size_log.name,
                           "size_output": elf_size,
                           "map_path": str(map_path), "map_sha256": sha256(map_path)}

    report_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError) as exc:
        print("collect_mcu_build: error: {}".format(exc), file=sys.stderr)
        sys.exit(2)
