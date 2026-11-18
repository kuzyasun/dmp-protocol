# R03 command recipes

Run each build block separately from the root of a fresh disposable RBO macOS
checkout with the pinned dependency checkout. Use clean R02 commit
`6d490df40afe2f702d8e10ff4b88f8bba166c35c` for the paired baseline. Set
`r03` to the reviewed R03 commit and apply stage preparation below while
still on the same R02 commit for a candidate link or host gate. This keeps
the build's Git base revision consistent with the archived RBO runs. An
empty qualification dirty-file hash list is expected for the clean baseline.
Source snapshot IDs are in the [report](README.md). Individual dirty-file
hashes use raw checkout bytes.

## Prepare a candidate stage

Run on a disposable clean R02 checkout with the R03 commit available in Git.
Set `stage` to `record`, `teardown` (record plus teardown), or `final`.
Use the final stage for the full and sanitizer host gates. The record-only
host gate uses the focused test filter in the sanitizer recipe with the
release provider configuration.

```bash
python3 - "$stage" "$r03" <<'PY'
import hashlib
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

base = "6d490df40afe2f702d8e10ff4b88f8bba166c35c"
stage, final = sys.argv[1:]
assert stage in ("record", "teardown", "final")

def git(*args, **kwargs):
    return subprocess.check_output(["git", *args], **kwargs)

assert git("rev-parse", "HEAD").decode().strip() == base
paths = ["src/security/handshake.c", "tests/endpoint/test_endpoint_sec.c"]
if stage == "final":
    paths.append("src/security/handshake_transport.c")
assert not git("status", "--porcelain", "--", *paths)
sources = {path: git("show", f"{final}:{path}") for path in paths}
handshake, endpoint = paths[:2]
if stage == "record":
    diff = git("diff", "--no-ext-diff", "--no-textconv", "--no-color",
               "--inter-hunk-context=0", "-U3", base, final, "--", handshake)
    header, *hunks = re.split(rb"(?m)(?=^@@ -)", diff)
    # Keep the AAD constants and the record hunks from the pinned R02 base.
    record_hunks = []
    for hunk in hunks:
        old_line = int(re.match(rb"@@ -(\d+)", hunk)[1])
        if old_line == 22 or old_line >= 1982:
            record_hunks.append(hunk)
    with TemporaryDirectory() as directory:
        old = Path(directory, handshake)
        old.parent.mkdir(parents=True)
        old.write_bytes(git("show", f"{base}:{handshake}"))
        subprocess.run(["git", "-c", "core.autocrlf=false", "apply", "-"],
                       input=header + b"".join(record_hunks),
                       cwd=directory, check=True)
        sources[handshake] = old.read_bytes()

expected = {
    handshake: ("a2a19c21e86c6c2ec1aeb4b6b7987d82fec96cff43d6901f047602ab808b154d"
                if stage == "record" else
                "ee3e5a44be5e66525b0df61a3b1131774aecae8a6abe62fa6dfb94e85a8f13f8"),
    endpoint: "87414ed35887b914414c0fe4bbbadb4a3144b113208a3fae3ed8ef18dcc22769",
    "src/security/handshake_transport.c":
        "07d39404d4bc2f3d87a2069bc9bfc33297054e162a26b3e1719e17b26adc29f2",
}
for path, raw in sources.items():
    lf = raw.replace(b"\r\n", b"\n")
    checkout = lf.replace(b"\n", b"\r\n") if path == endpoint else lf
    if hashlib.sha256(checkout).hexdigest() != expected[path]:
        raise SystemExit(f"Unexpected source SHA-256: {path}")
    sources[path] = checkout
for path, raw in sources.items():
    Path(path).write_bytes(raw)
    print(f"{expected[path]}  {path}")
PY
```

The host recipes also restore pinned fixture line endings in the disposable
checkout before running the tests.

## ESP32-S3 qualification link

```bash
set -euo pipefail
eim run "idf.py --version" v6.1
dir=build/r03-final-esp32s3
out=build/r03-final-esp32s3-evidence
project=tests/embedded/espnow_dmp
mkdir -p "$out"
git rev-parse HEAD > "$out/revision.txt"
git -C third_party/noise-c rev-parse HEAD > "$out/noise-revision.txt"
git status --short > "$out/working-status.txt"
{ git diff --name-only --diff-filter=ACMRT 6d490df40afe2f702d8e10ff4b88f8bba166c35c -- src; git ls-files --others --exclude-standard -- src; } | while IFS= read -r path; do shasum -a 256 "$path"; done > "$out/dirty-input-hashes.txt"
args="-C $project -B $dir -DIDF_TARGET=esp32s3"
tool=xtensa-esp32s3-elf
test ! -e "$dir"
eim run "idf.py $args build" v6.1 > "$out/build.txt" 2>&1 || { tail -n 100 "$out/build.txt"; exit 1; }
for report in size size-components size-files; do
  eim run "idf.py $args $report" v6.1 > "$out/$report.txt" 2>&1 || { tail -n 60 "$out/$report.txt"; exit 1; }
done
eim run "$tool-nm -S --size-sort --radix=d $dir/dmp_espnow_dmp.elf" v6.1 > "$out/symbols.txt"
eim run "$tool-gcc --version" v6.1 > "$out/gcc.txt"
ninja -C "$dir" -t commands dmp_espnow_dmp.elf | tail -n 1 > "$out/link-command.txt"
shasum -a 256 "$dir"/sdkconfig "$dir"/dmp_espnow_dmp.{elf,map,bin} "$dir"/esp-idf/esp_system/ld/*.ld "$project/dependencies.lock" | tee "$out/artifact-hashes.txt"
wc -c "$dir"/dmp_espnow_dmp.bin
grep -E 'libdmp\.a|libnoise-c\.a|libesphome__libsodium\.a' "$out/size-components.txt"
grep -E ' (take_frame|dmp_reliability_on_rx|dmp_endpoint_poll|dmp_ranges_overlap)(\.[a-z0-9]+)?$' "$out/symbols.txt" || true
eim run "$tool-objdump -d $dir/dmp_espnow_dmp.elf" v6.1 > "$dir/disassembly.txt"
python3 - "$dir/disassembly.txt" <<'PY' | tee "$out/stack-frames.txt"
import re
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(errors="replace")
names = (
  "seal_record", "seal_prepared_record", "dmp_hs_seal_logical", "dmp_hs_offer_protected",
  "dmp_hs_open_logical", "open_record_body", "build_record_aad", "abort_attempt",
  "end_traffic", "dmp_hs_tx_submit"
)
for name in names:
    head = rf"(?m)^[0-9a-f]+ <({name}(?:[.$][^>]+)?)>:\n"
    match = re.search(head + r"\s*[0-9a-f]+:\s+[0-9a-f]+\s+entry\s+a1,\s*(0x[0-9a-fA-F]+|\d+)\b", text)
    if match:
        print(f"{match[1]} {int(match[2], 16 if match[2].startswith('0x') else 10)} B")
PY
tail -n 27 "$out/size.txt"
```

## ESP32-C3 qualification link

```bash
set -euo pipefail
eim run "idf.py --version" v6.1
dir=build/r03-final-esp32c3
out=build/r03-final-esp32c3-evidence
project=tests/embedded/espnow_dmp
mkdir -p "$out"
git rev-parse HEAD > "$out/revision.txt"
git -C third_party/noise-c rev-parse HEAD > "$out/noise-revision.txt"
git status --short > "$out/working-status.txt"
{ git diff --name-only --diff-filter=ACMRT 6d490df40afe2f702d8e10ff4b88f8bba166c35c -- src; git ls-files --others --exclude-standard -- src; } | while IFS= read -r path; do shasum -a 256 "$path"; done > "$out/dirty-input-hashes.txt"
args="-C $project -B $dir -DIDF_TARGET=esp32c3"
tool=riscv32-esp-elf
test ! -e "$dir"
eim run "idf.py $args build" v6.1 > "$out/build.txt" 2>&1 || { tail -n 100 "$out/build.txt"; exit 1; }
for report in size size-components size-files; do
  eim run "idf.py $args $report" v6.1 > "$out/$report.txt" 2>&1 || { tail -n 60 "$out/$report.txt"; exit 1; }
done
eim run "$tool-nm -S --size-sort --radix=d $dir/dmp_espnow_dmp.elf" v6.1 > "$out/symbols.txt"
eim run "$tool-gcc --version" v6.1 > "$out/gcc.txt"
ninja -C "$dir" -t commands dmp_espnow_dmp.elf | tail -n 1 > "$out/link-command.txt"
shasum -a 256 "$dir"/sdkconfig "$dir"/dmp_espnow_dmp.{elf,map,bin} "$dir"/esp-idf/esp_system/ld/*.ld "$project/dependencies.lock" | tee "$out/artifact-hashes.txt"
wc -c "$dir"/dmp_espnow_dmp.bin
grep -E 'libdmp\.a|libnoise-c\.a|libesphome__libsodium\.a' "$out/size-components.txt"
grep -E ' (take_frame|dmp_reliability_on_rx|dmp_endpoint_poll|dmp_ranges_overlap)(\.[a-z0-9]+)?$' "$out/symbols.txt" || true
tail -n 27 "$out/size.txt"
```

## Host real-provider and peer gate

```bash
set -euo pipefail
# Restore only line endings that match the pinned digest.
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path("profiles/deployments")
entries = {root / name: digest
           for name, digest in json.loads((root / "digests.json").read_bytes())["manifests"].items()}
entries[Path("tests/peer/fixtures/r7-tombstone-pressure.json")] = (
    "0ab102c8b13b99b506539a78a87bf5f0c4f54d9c3e7c04dfd59235a177957ae3"
)
for path, expected in sorted(entries.items()):
    raw = path.read_bytes()
    lf = raw.replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() == expected:
        continue
    for variant in (lf, lf.replace(b"\n", b"\r\n")):
        if hashlib.sha256(variant).hexdigest() == expected:
            path.write_bytes(variant)
            print(f"{path}: restored pinned bytes {expected}")
            break
    else:
        raise SystemExit(f"{path}: neither line-ending representation matches the pinned digest")
PY
prep=build/r03-sodium-prep
dir=build/r03-real-provider
out=build/r03-host-provider-evidence
mkdir -p "$out"
cmake --version
/usr/bin/cc --version
python3 --version
node --version
cmake -S third_party/noise-c -B "$prep" -G Ninja -DNOISE_C_BUILD_TESTS=ON > "$out/prepare.txt" 2>&1 || { tail -n 90 "$out/prepare.txt"; exit 1; }
sodium="$PWD/$prep/_deps/esphome_libsodium-1.10021.11"
for repo in third_party/noise-c "$sodium" "$sodium/libsodium"; do
  git -C "$repo" rev-parse HEAD
  git -C "$repo" status --short
done | tee "$out/provider-revisions.txt"
cmake -S . -B "$dir" -G Ninja -DCMAKE_BUILD_TYPE=Release -DDMP_BUILD_TESTS=ON -DDMP_SODIUM_SOURCE_DIR="$sodium"
cmake --build "$dir" --parallel 6 > "$out/build.txt" 2>&1 || { tail -n 90 "$out/build.txt"; exit 1; }
{ git diff --name-only --diff-filter=ACMRT 6d490df40afe2f702d8e10ff4b88f8bba166c35c -- src tests/endpoint tests/security; git ls-files --others --exclude-standard -- src tests/endpoint tests/security; } | sort -u | while IFS= read -r path; do shasum -a 256 "$path"; done > "$out/dirty-input-hashes.txt"
for archive in libdmp libdmp_none; do
  python3 tools/check_core_allocators.py "$dir/$archive.a" --nm /usr/bin/nm
done | tee "$out/allocators.txt"
ctest --test-dir "$dir" -N > "$out/registered.txt"
ctest --test-dir "$dir" --output-on-failure -E '^memory\.(mcu_abi|.*\.layout)$' | tee "$out/ctest.txt"
test -x "$dir/tests/security/dmp_test_endpoint_sec"
test -x "$dir/dmp_test_sample1_none_stream_r_5"
PYTHONPATH=tests/peer DMP_P23_ENDPOINT_SEC_EXE="$PWD/$dir/tests/security/dmp_test_endpoint_sec" DMP_P23_SAMPLE1_NONE_DRIVER="$PWD/$dir/dmp_test_sample1_none_stream_r_5" python3 -B -m unittest discover -v -s tests/peer/tests -p 'test_*.py' > "$out/peer.txt" 2>&1 || { tail -n 90 "$out/peer.txt"; exit 1; }
tail -n 5 "$out/peer.txt"
```

## Focused ASan and UBSan gate

```bash
set -euo pipefail
# Restore only line endings that match the pinned digest.
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path("profiles/deployments")
entries = {root / name: digest
           for name, digest in json.loads((root / "digests.json").read_bytes())["manifests"].items()}
entries[Path("tests/peer/fixtures/r7-tombstone-pressure.json")] = (
    "0ab102c8b13b99b506539a78a87bf5f0c4f54d9c3e7c04dfd59235a177957ae3"
)
for path, expected in sorted(entries.items()):
    raw = path.read_bytes()
    lf = raw.replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() == expected:
        continue
    for variant in (lf, lf.replace(b"\n", b"\r\n")):
        if hashlib.sha256(variant).hexdigest() == expected:
            path.write_bytes(variant)
            print(f"{path}: restored pinned bytes {expected}")
            break
    else:
        raise SystemExit(f"{path}: neither line-ending representation matches the pinned digest")
PY
prep=build/r03-sanitize-sodium-prep
dir=build/r03-sanitize-real-provider
out=build/r03-sanitize-host-provider-evidence
mkdir -p "$out"
cmake --version
/usr/bin/cc --version
python3 --version
node --version
cmake -S third_party/noise-c -B "$prep" -G Ninja -DNOISE_C_BUILD_TESTS=ON > "$out/prepare.txt" 2>&1 || { tail -n 90 "$out/prepare.txt"; exit 1; }
sodium="$PWD/$prep/_deps/esphome_libsodium-1.10021.11"
for repo in third_party/noise-c "$sodium" "$sodium/libsodium"; do
  git -C "$repo" rev-parse HEAD
  git -C "$repo" status --short
done | tee "$out/provider-revisions.txt"
cmake -S . -B "$dir" -G Ninja -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDMP_BUILD_TESTS=ON -DDMP_FUZZ=ON -DDMP_SODIUM_SOURCE_DIR="$sodium"
cmake --build "$dir" --parallel 6 --target dmp_test_handshake dmp_test_endpoint_sec > "$out/build.txt" 2>&1 || { tail -n 90 "$out/build.txt"; exit 1; }
ctest --test-dir "$dir" --output-on-failure -R '^(security\.handshake(_transport)?|endpoint\.protected_single_peer_bounds|endpoint\.security\.(ttl|aad_mutations))$' | tee "$out/ctest.txt"
```
