#!/usr/bin/env python3
"""Reject allocator references in one libdmp archive or a directory containing it."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


ALLOCATORS = {
    "malloc",
    "calloc",
    "realloc",
    "free",
    "malloc_r",
    "calloc_r",
    "realloc_r",
    "free_r",
    "reallocarray",
    "aligned_alloc",
    "posix_memalign",
    "memalign",
    "valloc",
    "pvPortMalloc",
    "pvPortCalloc",
    "pvPortRealloc",
    "pvPortFree",
    "heap_caps_malloc",
    "heap_caps_calloc",
    "heap_caps_realloc",
    "heap_caps_free",
    "heap_caps_aligned_alloc",
    "heap_caps_aligned_calloc",
    "heap_caps_strdup",
    "sbrk",
}


def locate_archive(path: Path) -> Path:
    if path.is_file():
        return path
    matches = sorted(path.rglob("libdmp.a"))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one libdmp.a under {path}, found {len(matches)}")
    return matches[0]


def undefined_symbols(nm: str, archive: Path) -> set[str]:
    result = subprocess.run(
        [nm, "-u", str(archive)], check=True, capture_output=True, text=True
    )
    symbols: set[str] = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        symbol = fields[-1]
        symbol = re.sub(r"^_+", "", symbol)
        symbol = symbol.split("@", 1)[0]
        symbols.add(symbol)
    return symbols


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path, help="libdmp.a or a build directory containing it")
    parser.add_argument("--nm", required=True, help="matching nm executable")
    args = parser.parse_args()

    try:
        archive = locate_archive(args.archive)
        references = undefined_symbols(args.nm, archive)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"allocator check could not inspect archive: {error}", file=sys.stderr)
        return 2

    found = sorted(ALLOCATORS & references)
    if found:
        print(f"allocator references in {archive}: {', '.join(found)}", file=sys.stderr)
        return 1
    print(f"no allocator references in {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
