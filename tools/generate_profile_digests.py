#!/usr/bin/env python3
"""Check or regenerate the frozen deployment manifest SHA-256 index."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {"digests.json", "resource-inputs.json"}


def manifest_digests(deployments: Path) -> dict[str, str]:
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(deployments.glob("*.json"))
        if path.name not in EXCLUDED
    }


def read_index(index: Path) -> dict:
    value = json.loads(index.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("digest index must be a JSON object")
    return value


def check(index: Path, deployments: Path) -> int:
    try:
        current = read_index(index)
        recorded = current.get("manifests")
        if not isinstance(recorded, dict):
            raise ValueError("digest index must contain a manifests object")
        expected = manifest_digests(deployments)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"digest check failed: {error}", file=sys.stderr)
        return 1

    recorded_names = set(recorded)
    expected_names = set(expected)
    missing = sorted(expected_names - recorded_names)
    extra = sorted(recorded_names - expected_names)
    stale = sorted(name for name in expected_names & recorded_names
                   if recorded[name] != expected[name])
    if missing or extra or stale:
        if missing:
            print(f"missing digest entries: {', '.join(missing)}", file=sys.stderr)
        if extra:
            print(f"extra digest entries: {', '.join(extra)}", file=sys.stderr)
        if stale:
            print(f"stale digest entries: {', '.join(stale)}", file=sys.stderr)
        return 1
    print(f"deployment digest index is current ({len(expected)} manifests)")
    return 0


def regenerate(index: Path, deployments: Path) -> int:
    try:
        current = read_index(index)
        current["manifests"] = manifest_digests(deployments)
        serialized = json.dumps(current, indent=2) + "\n"
        index.write_text(serialized, encoding="utf-8", newline="")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"digest regeneration failed: {error}", file=sys.stderr)
        return 1
    print(f"regenerated deployment digest index ({len(current['manifests'])} manifests)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="verify the index without changing any files")
    parser.add_argument("--root", type=Path, default=ROOT,
                        help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    deployments = args.root / "profiles" / "deployments"
    index = deployments / "digests.json"
    return check(index, deployments) if args.check else regenerate(index, deployments)


if __name__ == "__main__":
    raise SystemExit(main())
