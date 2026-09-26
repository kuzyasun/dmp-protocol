"""Apply the reviewed checked-initialization patch to pinned libsodium sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any


TARGETS = (
    "libsodium/src/libsodium/sodium/core.c",
    "libsodium/src/libsodium/sodium/utils.c",
)
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class PreparationError(RuntimeError):
    """Raised when pinned source or patch validation fails."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _load_inputs(path: Path) -> tuple[dict[str, str], str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        files = value["files"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise PreparationError(f"cannot read inputs file {path}: {exc}") from exc
    if not isinstance(value, dict) or set(value) - {"files", "hash_normalization"}:
        raise PreparationError("inputs file contains unsupported fields")
    if not isinstance(files, dict) or set(files) != set(TARGETS):
        raise PreparationError("inputs.files must name exactly the two pinned sodium files")
    normalization = value.get("hash_normalization", "none")
    if normalization not in ("none", "crlf-to-lf"):
        raise PreparationError(f"unsupported hash normalization: {normalization}")
    for name, digest in files.items():
        if not isinstance(digest, str) or not HASH_RE.fullmatch(digest):
            raise PreparationError(f"invalid SHA-256 for {name}")
    return files, normalization


def _patch_targets(patch_bytes: bytes) -> list[str]:
    try:
        lines = patch_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise PreparationError("patch must be UTF-8") from exc

    pairs: list[tuple[str, str]] = []
    old: str | None = None
    for line in lines:
        if line.startswith("--- "):
            old = line[4:].split("\t", 1)[0]
        elif line.startswith("+++ "):
            new = line[4:].split("\t", 1)[0]
            if old is None:
                raise PreparationError("patch has a new-file header without an old-file header")
            pairs.append((old, new))
            old = None
    if old is not None or not pairs:
        raise PreparationError("patch file headers are incomplete or missing")

    targets: list[str] = []
    for old, new in pairs:
        if not old.startswith("a/") or not new.startswith("b/"):
            raise PreparationError("patch may not add, delete, or rename files")
        old_name, new_name = old[2:], new[2:]
        if old_name != new_name or old_name not in TARGETS:
            raise PreparationError(f"patch changes an unapproved path: {old_name} -> {new_name}")
        if old_name in targets:
            raise PreparationError(f"patch repeats target path: {old_name}")
        targets.append(old_name)
    if set(targets) != set(TARGETS):
        raise PreparationError("patch must modify exactly core.c and utils.c")
    return targets


def _is_git_worktree(path: Path) -> bool:
    result = subprocess.run(
        ["git", "-C", os.fspath(path), "rev-parse", "--show-toplevel"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def _validate_output_paths(output: Path) -> None:
    if output.exists() and not output.is_dir():
        raise PreparationError(f"output path is not a directory: {output}")
    targets = [Path(name) for name in TARGETS] + [Path("preparation.json")]
    for relative in targets:
        current = output
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise PreparationError(f"output path contains a symlink: {current}")
        resolved_target = _resolved(current)
        if resolved_target != output and output not in resolved_target.parents:
            raise PreparationError(f"output path escapes output directory: {current}")
        if current.exists() and not current.is_file():
            raise PreparationError(f"output target is not a regular file: {current}")


def _replace_if_changed(destination: Path, data: bytes) -> None:
    if destination.exists() and destination.read_bytes() == data:
        return
    # Replace the directory entry, never truncate an existing (possibly hard-
    # linked) inode. This preserves any source/external file linked to the leaf.
    descriptor, temporary = tempfile.mkstemp(prefix=".checked-sodium-", dir=destination.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        os.replace(temporary_path, destination)
    finally:
        temporary_path.unlink(missing_ok=True)


def _prepare(source: Path, output: Path, patch_path: Path, inputs_path: Path) -> dict[str, Any]:
    source = _resolved(source)
    output = _resolved(output)
    patch_path = _resolved(patch_path)
    inputs_path = _resolved(inputs_path)
    if not source.is_dir():
        raise PreparationError(f"source is not a directory: {source}")
    if _paths_overlap(source, output):
        raise PreparationError("output must be separate from the source tree")
    _validate_output_paths(output)

    expected_hashes, hash_normalization = _load_inputs(inputs_path)
    originals: dict[str, bytes] = {}
    raw_source_hashes: dict[str, str] = {}
    normalized_source_hashes: dict[str, str] = {}
    for relative in TARGETS:
        file_path = source / Path(relative)
        components = [source]
        for part in Path(relative).parts:
            components.append(components[-1] / part)
        if any(component.is_symlink() for component in components[1:]):
            raise PreparationError(f"pinned source path contains a symlink: {relative}")
        if not file_path.is_file():
            raise PreparationError(f"pinned source is missing or is a symlink: {relative}")
        data = file_path.read_bytes()
        normalized = data.replace(b"\r\n", b"\n") if hash_normalization == "crlf-to-lf" else data
        actual = _sha256(normalized)
        if actual != expected_hashes[relative]:
            raise PreparationError(f"source hash mismatch for {relative}")
        originals[relative] = data
        raw_source_hashes[relative] = _sha256(data)
        normalized_source_hashes[relative] = _sha256(data.replace(b"\r\n", b"\n"))

    try:
        patch_bytes = patch_path.read_bytes()
    except OSError as exc:
        raise PreparationError(f"cannot read patch {patch_path}: {exc}") from exc
    _patch_targets(patch_bytes)

    temp_parent = _resolved(Path(tempfile.gettempdir()))
    if _is_git_worktree(temp_parent):
        raise PreparationError("system temporary directory is inside a Git worktree")
    with tempfile.TemporaryDirectory(prefix="checked-sodium-") as temporary:
        scratch = Path(temporary)
        if _paths_overlap(scratch.resolve(), source) or _is_git_worktree(scratch):
            raise PreparationError("patch scratch directory must be outside every Git worktree")
        normalized_line_endings = False
        for relative, data in originals.items():
            destination = scratch / Path(relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary_data = data.replace(b"\r\n", b"\n")
            normalized_line_endings |= temporary_data != data
            destination.write_bytes(temporary_data)

        patch_hash = _sha256(patch_bytes)
        patch_file = scratch / "checked-init.patch"
        patch_file.write_bytes(patch_bytes)
        for command in (
            ["git", "apply", "--check", "--whitespace=error", os.fspath(patch_file)],
            ["git", "apply", "--whitespace=error", os.fspath(patch_file)],
        ):
            result = subprocess.run(command, cwd=scratch, capture_output=True, text=True, encoding="utf-8")
            if result.returncode:
                detail = (result.stderr or result.stdout).strip()
                raise PreparationError(f"git apply failed ({result.returncode}): {detail}")

        expected_files = {Path(name) for name in TARGETS} | {Path("checked-init.patch")}
        found_files = {item.relative_to(scratch) for item in scratch.rglob("*") if item.is_file()}
        if found_files != expected_files:
            raise PreparationError("patch produced unexpected files or paths")
        outputs = {relative: (scratch / Path(relative)).read_bytes() for relative in TARGETS}
        source_after = {relative: _sha256((source / Path(relative)).read_bytes()) for relative in TARGETS}
        if source_after != raw_source_hashes:
            raise PreparationError("source tree changed during patch preparation")

    output_hashes = {name: _sha256(data) for name, data in outputs.items()}
    report = {
        "format": 1,
        "source": os.fspath(source),
        "source_hashes": raw_source_hashes,
        "normalized_source_hashes": normalized_source_hashes,
        "source_hash_normalization": hash_normalization,
        "temporary_source_line_endings": "CRLF normalized to LF" if normalized_line_endings else "unchanged",
        "patch_sha256": patch_hash,
        "output_hashes": output_hashes,
    }

    # Materialize only after every source and patch check has passed.
    for relative, data in outputs.items():
        destination = output / Path(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        _replace_if_changed(destination, data)
    report_path = output / "preparation.json"
    encoded_report = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _replace_if_changed(report_path, encoded_report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="prepared ESPHome sodium root")
    parser.add_argument("--output", required=True, type=Path, help="distinct generated source directory")
    args = parser.parse_args()
    script_dir = Path(__file__).resolve().parent
    try:
        report = _prepare(args.source, args.output, script_dir / "checked-init.patch", script_dir / "inputs.json")
    except (PreparationError, OSError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
