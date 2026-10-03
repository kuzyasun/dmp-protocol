"""Drive the C profile gate with the shared P02 corpus and compare codes."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import validate_profile as validator  # noqa: E402

FIXTURES = ROOT / "tests" / "profiles" / "fixtures"
CORPUS = ROOT / "tests" / "profiles" / "invalid.json"
DEPLOYMENTS = (
    "direct-nnpsk0.json",
    "direct-xx.json",
    "radio-nnpsk0.json",
    "radio-xx.json",
    "test-radio-retry-all-nnpsk0.json",
    "test-radio-retry-all-xx.json",
)
STATUS = {
    "encoding": "malformed",
    "json": "malformed",
    "digest": "integrity_failure",
}


def _mutate(document, operations):
    value = json.loads(json.dumps(document))
    for operation in operations:
        path = operation["path"].strip("/").split("/")
        parent = value
        for part in path[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        key = path[-1]
        if operation["op"] == "remove":
            if isinstance(parent, list):
                parent.pop(int(key))
            else:
                del parent[key]
        elif operation["op"] == "add":
            parent[key] = operation["value"]
        elif isinstance(parent, list):
            parent[int(key)] = operation["value"]
        else:
            parent[key] = operation["value"]
    return value


def _raw_case(case):
    if "hex" in case:
        return bytes.fromhex(case["hex"])
    if "ascii" in case:
        return case["ascii"].encode("ascii")
    if "repeat_prefix_hex" in case:
        prefix = bytes.fromhex(case["repeat_prefix_hex"]) * case["repeat"]
        suffix = bytes.fromhex(case["repeat_suffix_hex"]) * case["repeat"]
        return prefix + case.get("middle_ascii", "").encode("ascii") + suffix
    if "repeat_hex" in case:
        repeated = bytes.fromhex(case["repeat_hex"]) * case["repeat"]
        return (repeated + case.get("middle_ascii", "").encode("ascii") +
                bytes.fromhex(case.get("suffix_hex", "")))
    raise AssertionError("unknown raw corpus encoding")


def run_gate(executable, raw, expected_hex=None):
    command = [executable, "-"]
    if expected_hex is not None:
        command.append(expected_hex)
    completed = subprocess.run(command, input=raw, capture_output=True, check=False)
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode("utf-8", "replace"))
    line = completed.stdout.decode("utf-8").strip().splitlines()[-1]
    return json.loads(line)


def expect_failure(executable, raw, code, path, label):
    python_error = None
    try:
        validator.validate_bytes(raw)
    except validator.ProfileError as error:
        python_error = error
    if python_error is None:
        raise AssertionError(f"{label}: Python accepted bytes the corpus rejects")
    if python_error.code != code or python_error.path != path:
        raise AssertionError(
            f"{label}: Python {python_error.code} {python_error.path}, corpus {code} {path}")
    result = run_gate(executable, raw)
    expected_status = STATUS.get(code, "unsupported")
    if result["status"] != expected_status or result["code"] != code or result["path"] != path:
        raise AssertionError(
            f"{label}: C {result['status']} {result['code']} {result['path']}, "
            f"expected {expected_status} {code} {path}")


def expect_success(executable, raw, label):
    python_result = validator.validate_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    if python_result["sha256"] != digest:
        raise AssertionError(f"{label}: Python digest mismatch")
    result = run_gate(executable, raw, digest)
    if result["status"] != "ok" or result["sha256"] != digest:
        raise AssertionError(f"{label}: C did not admit the Python-valid profile: {result}")
    wrong = "0" * 64 if digest[0] != "0" else "1" * 64
    rejected = run_gate(executable, raw, wrong)
    if rejected["status"] != "integrity_failure" or rejected["code"] != "digest" or rejected["path"] != "$":
        raise AssertionError(f"{label}: wrong digest returned {rejected}")


def main(argv):
    if len(argv) != 2:
        raise SystemExit("usage: parity_drive.py <dmp_test_profile_admit>")
    executable = argv[1]
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    mutations = corpus["mutation_cases"]
    raw_cases = corpus["raw_cases"]
    if len(mutations) != 42 or len(raw_cases) != 17:
        raise SystemExit(f"unexpected corpus size: {len(mutations)} mutations, {len(raw_cases)} raw")
    fixtures = sorted(FIXTURES.glob("*.json"))
    if len(fixtures) != 3:
        raise SystemExit(f"expected 3 fixtures, found {len(fixtures)}")
    for fixture in fixtures:
        expect_success(executable, fixture.read_bytes(), fixture.name)
    for name in DEPLOYMENTS:
        raw = (ROOT / "profiles" / "deployments" / name).read_bytes()
        expect_success(executable, raw, name)
    for case in mutations:
        source = json.loads((FIXTURES / case["fixture"]).read_text(encoding="utf-8"))
        raw = json.dumps(_mutate(source, case["mutations"]), separators=(",", ":")).encode()
        expect_failure(executable, raw, case["expected_code"], case["expected_path"], case["name"])
    for case in raw_cases:
        expect_failure(executable, _raw_case(case), case["expected_code"], case["expected_path"], case["name"])
    print(f"parity ok: {len(fixtures)} fixtures, {len(DEPLOYMENTS)} deployments, "
          f"{len(mutations)} mutations, {len(raw_cases)} raw")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
