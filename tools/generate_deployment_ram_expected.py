#!/usr/bin/env python3
"""Refresh only frozen RAM charge totals after manifest reservation edits."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENTS = ROOT / "profiles" / "deployments"
EXPECTED = ROOT / "tests" / "profiles" / "deployment_expected.json"


def main() -> int:
    frozen = json.loads(EXPECTED.read_text(encoding="utf-8"))
    for name, row in frozen.items():
        manifest = json.loads((DEPLOYMENTS / name).read_text(encoding="utf-8"))
        totals: dict[str, dict[str, int]] = {}
        for resource in manifest["resources"]:
            role = resource["role"]
            for charge in resource["charges"]:
                region = charge["region"]
                totals.setdefault(role, {}).setdefault(region, 0)
                totals[role][region] += charge["count"] * charge["bytes_each"]
        row["ram_reserved_bytes"] = totals
    EXPECTED.write_text(json.dumps(frozen, indent=2) + "\n", encoding="utf-8", newline="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
