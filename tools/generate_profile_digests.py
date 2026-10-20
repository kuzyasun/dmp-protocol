#!/usr/bin/env python3
"""Regenerate the frozen deployment manifest SHA-256 index."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOYMENTS = ROOT / "profiles" / "deployments"
INDEX = DEPLOYMENTS / "digests.json"


def main() -> int:
    current = json.loads(INDEX.read_text(encoding="utf-8"))
    current["manifests"] = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(DEPLOYMENTS.glob("*.json"))
        if path.name not in {"digests.json", "resource-inputs.json"}
    }
    INDEX.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8", newline="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
