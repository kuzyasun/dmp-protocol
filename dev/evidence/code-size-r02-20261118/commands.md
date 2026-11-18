# DMP R02 reproduction commands

Run from the root of a disposable RBO snapshot. The source snapshot must include
both R01 and R02 plus the Tier 0 harness from R00.
The input manifests hash raw checkout bytes. A checkout with different line
endings can preserve the same Git content and produce different raw hashes.

## Qualification links

The S3 invocation is below. For C3, replace the target and build suffix
`esp32s3` with `esp32c3` and the tool prefix `xtensa-esp32s3-elf` with
`riscv32-esp-elf`.

```bash
set -euo pipefail
eim run "idf.py --version" v6.1
dir=build/r02-tlv-esp32s3
out=build/r02-tlv-esp32s3-evidence
project=tests/embedded/espnow_dmp
mkdir -p "$out"
git rev-parse HEAD > "$out/revision.txt"
git -C third_party/noise-c rev-parse HEAD > "$out/noise-revision.txt"
git status --short > "$out/working-status.txt"
{ git diff --name-only --diff-filter=ACMRT 67e1f67c0a11eaac172906cdd186f6cab3864fbf -- src; git ls-files --others --exclude-standard -- src; } | sort -u | while IFS= read -r path; do shasum -a 256 "$path"; done > "$out/dirty-input-hashes.txt"
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
tail -n 27 "$out/size.txt"
```

For the S3 stack sample, mount the archived R01 ELF at
`../r02-baseline/esp32s3-dmp_espnow_dmp.elf` read-only. Continue with the same
`dir` and `out` variables.

```bash
test -f ../r02-baseline/esp32s3-dmp_espnow_dmp.elf
shasum -a 256 ../r02-baseline/esp32s3-dmp_espnow_dmp.elf > "$out/stack-baseline-hash.txt"
eim run "xtensa-esp32s3-elf-objdump -d ../r02-baseline/esp32s3-dmp_espnow_dmp.elf" v6.1 > "$dir/stack-r01.txt"
eim run "xtensa-esp32s3-elf-objdump -d $dir/dmp_espnow_dmp.elf" v6.1 > "$dir/stack-r02.txt"
python3 - "$dir" <<'PY' | tee "$out/stack-frames.txt"
import re
import sys
from pathlib import Path

names = (
    "dmp_core_parse", "dmp_core_check_role", "dmp_extension_next", "validate_extensions",
    "read_extension", "dmp_decode_extension_reply_to", "dmp_decode_extension_context",
    "dmp_identity_source_key", "dmp_identity_reply_to", "read_extensions",
    "dmp_reliability_on_rx", "dmp_reassembly_rx", "take_frame", "dmp_hs_open_logical",
)
for variant in ("r01", "r02"):
    source = (Path(sys.argv[1]) / f"stack-{variant}.txt").read_text(errors="replace")
    print(variant)
    for name in names:
        prefix = rf"(?m)^[0-9a-f]+ <({name}(?:\.[^>]+)?)>:\n"
        match = re.search(prefix + r"\s*[0-9a-f]+:\s+[0-9a-f]+\s+entry\s+a1,\s*(0x[0-9a-fA-F]+|\d+)\b", source)
        if match:
            print(f"  {match[1]} {int(match[2], 16 if match[2].startswith('0x') else 10)} B")
PY
```

## Host tests

This recipe includes the R02 Core and reliability inputs and the R01 Stream
regression. Compare file names with the fixed pre-R00 source commit to capture
the same inputs with either staged changes or a clean R02 commit.

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
prep=build/r02-sodium-prep
dir=build/r02-real-provider
out=build/r02-host-provider-evidence
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
{ git diff --name-only --diff-filter=ACMRT 67e1f67c0a11eaac172906cdd186f6cab3864fbf -- src tests/core tests/reliability tests/stream; git ls-files --others --exclude-standard -- src tests/core tests/reliability tests/stream; } | sort -u | while IFS= read -r path; do shasum -a 256 "$path"; done > "$out/dirty-input-hashes.txt"
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

## Focused ASan/UBSan

```bash
set -euo pipefail
dir=build/r02-sanitize
out=build/r02-sanitize-evidence
mkdir -p "$out"
/usr/bin/clang --version
cmake -S . -B "$dir" -G Ninja -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDMP_BUILD_TESTS=ON -DDMP_FUZZ=ON
cmake --build "$dir" --parallel 6 --target dmp_fuzz_selfcheck dmp_test_codec dmp_test_stream
ctest --test-dir "$dir" --output-on-failure -R '^(fuzz\.selfcheck|core\.codec|stream\.framing)$' | tee "$out/ctest.txt"
```

## Standalone ESP-IDF links

```bash
eim run "idf.py -C tests/embedded/size -B build/r02-tier0-core -DIDF_TARGET=esp32s3 -DDMP_SIZE_PROBE_STREAM_R=OFF build" v6.1
eim run "idf.py -C tests/embedded/size -B build/r02-tier0-core-stream-r -DIDF_TARGET=esp32s3 -DDMP_SIZE_PROBE_STREAM_R=ON build" v6.1
eim run "idf.py -C tests/embedded/espnow_pair -B build/r02-espnow-pair-s3 -DIDF_TARGET=esp32s3 build" v6.1
```

Use the same `-C`, `-B`, and `-D` arguments for `size`, `size-components`,
and `size-files`. Test the built Tier 0 ELFs with
`xtensa-esp32s3-elf-nm -S --size-sort --radix=d` in EIM 6.1. Both variants
should retain Core encode, parse and CRC32C. Only the Stream R variant should
retain Stream encode, init and feed.

## Core differential

Mount the saved R01 codec at `../r02-r01-input/r01-codec.c`. Its SHA-256 is
`8111d1454b9f027a7544aa5106b15e9bf955403e8ae3d553352f946fedb46646`.
Mount the [comparison driver](core_differential.c) at
`../r02-diff-input/core_differential.c`. Use read-only mounts.

```bash
set -euo pipefail
baseline=../r02-r01-input/r01-codec.c
driver=../r02-diff-input/core_differential.c
out=build/r02-core-differential
mkdir -p "$out"
shasum -a 256 "$baseline" "$driver" src/core/codec.c src/core/extension_values.h tests/core/test_codec.c | tee "$out/inputs.txt"
/usr/bin/clang -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -Iinclude -Isrc/core \
  "$baseline" tests/core/test_codec.c -o "$out/test_core_on_r01"
"$out/test_core_on_r01"
echo "Updated Core fixture suite passed on R01"
/usr/bin/clang -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -Iinclude -Isrc/core \
  -Ddmp_core_parse=r01_parse -Ddmp_core_check_role=r01_role -Ddmp_extension_next=r01_next \
  -Ddmp_core_encode=r01_encode -Ddmp_core_encode_header=r01_encode_header \
  -c "$baseline" -o "$out/r01-codec.o"
/usr/bin/clang -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -Iinclude \
  src/core/codec.c "$driver" "$out/r01-codec.o" -o "$out/core_ab"
"$out/core_ab" | tee "$out/result.txt"
```
