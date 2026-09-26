#!/usr/bin/env python3
"""Compile-only Noise/libsodium state layout and allocator-hook probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


NOISE_ROOT = Path(__file__).resolve().parents[2]
NOISE_SOURCE = Path("third_party/noise-c/src")
SODIUM_BACKENDS = {
    "x25519": NOISE_SOURCE / "backend/sodium/dh-curve25519.c",
    "sha256": NOISE_SOURCE / "backend/sodium/hash-sha256.c",
    "chachapoly": NOISE_SOURCE / "backend/sodium/cipher-chachapoly.c",
}
LAYOUT_TYPES = {
    "NoiseHandshakeState": "NoiseHandshakeState",
    "NoiseSymmetricState": "NoiseSymmetricState",
    "NoiseCurve25519State": "NoiseCurve25519State",
    "NoiseSHA256State": "NoiseSHA256State",
    "NoiseChaChaPolyState": "NoiseChaChaPolyState",
    "max_align_t": "max_align_t",
    "void_pointer": "void *",
    "dmp_noise_test_arena": "dmp_noise_test_arena",
}
ALLOCATOR_SYMBOLS = {"malloc", "calloc", "realloc", "free"}


class ProbeError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def save_process(output: Path, name: str, result: subprocess.CompletedProcess[str]) -> None:
    (output / f"{name}.stdout.txt").write_text(result.stdout, encoding="utf-8")
    (output / f"{name}.stderr.txt").write_text(result.stderr, encoding="utf-8")


def compile_command(
    compiler: str,
    common: list[str],
    extra_flags: list[str],
    source: Path,
    object_path: Path,
) -> list[str]:
    return [compiler, *common, *extra_flags, "-c", os.fspath(source), "-o", os.fspath(object_path)]


def nm_symbols(nm: str, obj: Path, output: Path, label: str) -> tuple[dict[str, int], list[str]]:
    sized = run([nm, "-S", "--radix=d", os.fspath(obj)], output)
    save_process(output, f"{label}-nm-sized", sized)
    if sized.returncode != 0:
        raise ProbeError(f"nm failed for {obj}: {sized.stderr.strip()}")

    layout_sizes: dict[str, int] = {}
    for line in sized.stdout.splitlines():
        columns = line.split()
        if len(columns) >= 4 and columns[-1].startswith("dmp_layout_"):
            try:
                layout_sizes[columns[-1]] = int(columns[-3], 10)
            except ValueError as exc:
                raise ProbeError(f"cannot parse nm symbol size: {line}") from exc

    undefined = run([nm, "-u", os.fspath(obj)], output)
    save_process(output, f"{label}-nm-undefined", undefined)
    if undefined.returncode != 0:
        raise ProbeError(f"nm undefined-symbol query failed for {obj}: {undefined.stderr.strip()}")
    symbols: list[str] = []
    for line in undefined.stdout.splitlines():
        columns = line.split()
        if columns:
            symbols.append(columns[-1])
    return layout_sizes, sorted(set(symbols))


def parse_assembly_layout(assembly: str) -> dict[str, int]:
    """Read compiler-emitted byte counts for the external layout arrays."""
    label_re = re.compile(r"^\s*_?(dmp_layout_(?:size|align)_[A-Za-z0-9_]+):\s*(?:[#;].*)?$")
    extent_re = re.compile(r"^\s*\.(?:space|zero)\s+([0-9]+)(?:\s*(?:[#;].*)?)$")
    values: dict[str, int] = {}
    pending: str | None = None
    for line in assembly.splitlines():
        label = label_re.match(line)
        if label:
            pending = label.group(1)
            continue
        if pending is None:
            continue
        extent = extent_re.match(line)
        if extent:
            values[pending] = int(extent.group(1), 10)
            pending = None
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")) or stripped.startswith("."):
            continue
        pending = None
    return values


def assembly_layout(
    compiler: str,
    common: list[str],
    source: Path,
    output: Path,
    label: str,
) -> tuple[dict[str, int], list[str]]:
    assembly_path = output / f"{label}.s"
    command = [compiler, *common, "-S", os.fspath(source), "-o", os.fspath(assembly_path)]
    result = run(command, output)
    save_process(output, f"{label}-assembly", result)
    if result.returncode != 0:
        raise ProbeError(f"assembly compile failed for {label} ({result.returncode})")
    if not assembly_path.is_file():
        raise ProbeError(f"compiler did not write expected assembly: {assembly_path}")
    text = assembly_path.read_text(encoding="utf-8", errors="replace")
    sizes = parse_assembly_layout(text)
    return sizes, command


def type_probe_source(type_name: str, type_expression: str, includes: str) -> str:
    safe_name = type_name
    return (
        f"{includes}\n"
        f"_Static_assert(_Alignof({type_expression}) <= _Alignof(max_align_t), "
        f'"{safe_name} exceeds max_align_t allocator alignment");\n'
        f"unsigned char dmp_layout_size_{safe_name}[sizeof({type_expression})];\n"
        f"unsigned char dmp_layout_align_{safe_name}[_Alignof({type_expression})];\n"
    )


def write_probe_sources(output: Path, repo: Path) -> dict[str, Path]:
    sources: dict[str, Path] = {}
    core_includes = '#include "protocol/internal.h"\n#include <stddef.h>\n'
    core = type_probe_source("NoiseHandshakeState", "NoiseHandshakeState", core_includes)
    core += type_probe_source("NoiseSymmetricState", "NoiseSymmetricState", core_includes)
    core += type_probe_source("max_align_t", "max_align_t", core_includes)
    core += type_probe_source("void_pointer", "void *", core_includes)
    core += type_probe_source("dmp_noise_test_arena", "dmp_noise_test_arena",
                              '#include "noise_test_arena.h"\n')
    core_path = output / "noise_layout_core.c"
    core_path.write_text(core, encoding="utf-8")
    sources["layout-core"] = core_path

    backend_probe_types = {
        "x25519": "NoiseCurve25519State",
        "sha256": "NoiseSHA256State",
        "chachapoly": "NoiseChaChaPolyState",
    }
    for backend, state_type in backend_probe_types.items():
        include_source = (repo / SODIUM_BACKENDS[backend]).resolve().as_posix()
        text = (
            '#include "protocol/internal.h"\n'
            "#include <stddef.h>\n"
            f'#include "{include_source}"\n'
        )
        text += type_probe_source(state_type, state_type, "")
        path = output / f"noise_layout_{backend}.c"
        path.write_text(text, encoding="utf-8")
        sources[f"layout-{backend}"] = path
    return sources


def parse_layout(symbols: dict[str, int]) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for label in LAYOUT_TYPES:
        size_symbol = f"dmp_layout_size_{label}"
        align_symbol = f"dmp_layout_align_{label}"
        if size_symbol not in symbols or align_symbol not in symbols:
            raise ProbeError(f"nm did not report both layout arrays for {label}")
        result[label] = {"size_bytes": symbols[size_symbol], "alignment_bytes": symbols[align_symbol]}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True, help="C compiler executable")
    parser.add_argument("--nm", required=True, help="matching nm executable")
    parser.add_argument("--target", required=True, choices=("host", "cortex-m4", "esp32s3"))
    parser.add_argument("--backend", required=True, type=Path, help="prepared sodium source root")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--repo", type=Path, default=NOISE_ROOT)
    args = parser.parse_args()

    repo = args.repo.expanduser().resolve()
    output = args.output.expanduser().resolve()
    backend = args.backend.expanduser().resolve()
    noise_include = repo / "third_party/noise-c/include"
    noise_src = repo / NOISE_SOURCE
    sodium_include = backend / "libsodium/src/libsodium/include"
    sodium_port_include = backend / "port_include"
    for required, label in (
        (repo / "third_party/noise-c/src/protocol/internal.h", "Noise internal.h"),
        (noise_include / "noise/protocol.h", "Noise public headers"),
        (sodium_include / "sodium.h", "prepared sodium headers"),
        (sodium_port_include, "prepared sodium port headers"),
    ):
        if not required.exists():
            raise ProbeError(f"{label} not found: {required}")
    output.mkdir(parents=True, exist_ok=True)

    common = [
        "-std=c11",
        "-Wall", "-Wextra", "-Wpedantic",
        "-Os",
        "-ffunction-sections",
        "-fdata-sections",
        "-fstack-usage",
        "-ffreestanding",
        "-fno-strict-aliasing",
        "-DNOISE_USE_LIBSODIUM=1",
        "-DNOISE_USE_CUSTOM_ALLOCATOR=1",
        "-DNOISE_USE_CUSTOM_RAND=1",
        "-DNOISE_USE_SODIUM_RAND=0",
        "-DNOISE_REQUIRE_FALLIBLE_RAND=1",
        "-DNOISE_USE_PTHREAD=0",
        "-DNOISE_REQUIRE_SODIUM_FAST_PATH",
        f"-I{noise_include}",
        f"-I{noise_src}",
        f"-I{sodium_include}",
        f"-I{sodium_port_include}",
        f"-I{repo / 'tests/provider'}",
    ]
    if args.target == "cortex-m4":
        common.extend(["-mcpu=cortex-m4", "-mthumb", "-mfloat-abi=soft"])

    try:
        compiler_version = run([args.compiler, "--version"], repo)
        save_process(output, "compiler-version", compiler_version)
        if compiler_version.returncode != 0:
            raise ProbeError(f"compiler --version failed: {compiler_version.stderr.strip()}")

        sources = write_probe_sources(output, repo)
        compile_sources: dict[str, Path] = dict(sources)
        for name in ("util.c", "handshakestate.c"):
            compile_sources[f"noise-{name.removesuffix('.c')}"] = noise_src / "protocol" / name
        compile_sources["test-arena"] = repo / "tests/provider/noise_test_arena.c"

        source_hashes: dict[str, str] = {}
        for label, source in compile_sources.items():
            if not source.is_file():
                raise ProbeError(f"source file missing for {label}: {source}")
            if source in sources.values():
                source_hashes[os.fspath(source.relative_to(output))] = sha256(source)
            else:
                source_hashes[os.fspath(source.relative_to(repo))] = sha256(source)
        for source in (
            repo / "third_party/noise-c/src/protocol/internal.h",
            repo / "third_party/noise-c/include/noise/defines.h",
            repo / "third_party/noise-c/include/noise/protocol/util.h",
            repo / "tests/provider/noise_test_arena.h",
            repo / "third_party/noise-c/src/backend/sodium/dh-curve25519.c",
            repo / "third_party/noise-c/src/backend/sodium/hash-sha256.c",
            repo / "third_party/noise-c/src/backend/sodium/cipher-chachapoly.c",
            sodium_include / "sodium.h",
            sodium_port_include / "sodium/sodium_esphome.h",
        ):
            if source.is_file():
                source_hashes[os.fspath(source)] = sha256(source)

        all_layout_symbols: dict[str, int] = {}
        object_records: dict[str, Any] = {}
        undefined_by_object: dict[str, list[str]] = {}
        for label, source in compile_sources.items():
            object_path = output / f"{label}.o"
            extra_flags = ["-Werror"] if label in {"layout-core", "test-arena"} else []
            command = compile_command(args.compiler, common, extra_flags, source, object_path)
            result = run(command, repo)
            save_process(output, label, result)
            object_records[label] = {
                "source": os.fspath(source),
                "object": os.fspath(object_path),
                "command": command,
                "return_code": result.returncode,
                "stdout_file": f"{label}.stdout.txt",
                "stderr_file": f"{label}.stderr.txt",
                "warnings": [line.strip() for line in result.stderr.splitlines() if "warning:" in line],
            }
            if result.returncode != 0:
                raise ProbeError(f"compile failed for {label} ({result.returncode}); see {output / (label + '.stderr.txt')}")
            object_layout, undefined = nm_symbols(args.nm, object_path, output, label)
            extraction_method = "nm -S --radix=d"
            if args.target == "host" and label.startswith("layout-"):
                object_layout, assembly_command = assembly_layout(
                    args.compiler, [*common, *extra_flags], source, output, label
                )
                object_records[label]["assembly_command"] = assembly_command
                object_records[label]["assembly_file"] = f"{label}.s"
                object_records[label]["extraction_method"] = "compiler assembly .space/.zero decimal extent"
                extraction_method = "compiler assembly .space/.zero decimal extent"
            else:
                object_records[label]["extraction_method"] = extraction_method
            all_layout_symbols.update(object_layout)
            undefined_by_object[label] = undefined

        layouts = parse_layout(all_layout_symbols)
        if not {"noise_allocator_allocate", "noise_allocator_release"}.issubset(
                undefined_by_object["noise-util"]):
            raise ProbeError("custom allocator hook references missing from util object")
        allocator_undefined = {
            label: [
                symbol
                for symbol in symbols
                if symbol in ALLOCATOR_SYMBOLS or symbol.startswith("noise_allocator_")
            ]
            for label, symbols in undefined_by_object.items()
        }
        legacy_allocator_calls = {
            label: [symbol for symbol in symbols if symbol in ALLOCATOR_SYMBOLS]
            for label, symbols in undefined_by_object.items()
        }
        legacy_allocator_calls = {
            label: symbols for label, symbols in legacy_allocator_calls.items() if symbols
        }
        # Keep only outputs of this run, not stale files from an earlier probe.
        su_files = sorted(Path(record["object"]).with_suffix(".su").name
                          for record in object_records.values()
                          if Path(record["object"]).with_suffix(".su").is_file())
        report = {
            "schema": "dmp-noise-compile-layout/1",
            "scope": "compile-only object layouts and static compiler stack reports; no link, runtime, high-water, or RAM-budget claim",
            "target": args.target,
            "compiler": args.compiler,
            "compiler_version": compiler_version.stdout.strip(),
            "nm": args.nm,
            "repo": os.fspath(repo),
            "backend_root": os.fspath(backend),
            "compile_flags": common,
            "warning_policy": "Wall/Wextra/Wpedantic enabled; Werror applies only to owned layout-core and test-arena translation units; inherited backend warnings are retained in stderr and listed per object",
            "source_sha256": source_hashes,
            "layouts": layouts,
            "undefined_symbols": undefined_by_object,
            "allocator_related_undefined_symbols": allocator_undefined,
            "legacy_allocator_calls_found": legacy_allocator_calls,
            "objects": object_records,
            "stack_usage_files": su_files,
            "stack_usage_scope": "compiler .su static reports, recorded separately from state sizes; not MCU runtime stack high-water",
        }
        report_path = output / "noise-layout.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if legacy_allocator_calls:
            raise ProbeError(
                "legacy malloc/calloc/free references remain in custom-allocator objects; "
                f"see {report_path}"
            )
        print(f"Wrote compile-only layout report: {report_path}")
        return 0
    except (OSError, ProbeError, subprocess.SubprocessError) as exc:
        print(f"measure_noise_layout: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
