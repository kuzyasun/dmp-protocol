# P08 bounded structural and framing fuzz targets

Two libFuzzer executables exercise the existing `libdmp` sources. They check
structure and framing only. `DMP_OK` from these calls is not endpoint,
authentication, security, or runtime acceptance. The remaining P08 gates are
host CI, embedded compile-only builds, map/size, and allocator checks.

## Targets and bounds

| Bound | Value |
| --- | --- |
| Maximum input (`-max_len` and callback cap) | 256 bytes |
| Core `max_frame_bytes` / `max_message_bytes` / `max_fragments` | 256 / 128 / 8 |
| Stream `max_core_bytes` / partial timeout | 128 bytes / 10 ms |
| Stream storage per mode | 134 bytes, the R encoded bound for a 128-byte core |
| Feed pulls per mode / extension walk | 256 / 128 |
| Smoke run count / time per target | 1000 / 5 seconds |

`dmp_fuzz_core` parses one bounded structural frame, walks at most 128
extensions, and applies endpoint and forwarder structural role policies.
`dmp_fuzz_stream` copies the input to fixed stack storage and applies it to
separate fresh Stream L and R decoders, with at most 256 feed pulls and one
poll per decoder. Neither callback allocates, performs I/O, or reads a clock.
Inputs over 256 bytes and null non-empty inputs return before any library call.
`DMP_STREAM_FRAME` is only a framing result.

`dmp_fuzz_seed_corpus` writes a known core frame and Stream L/R encodings
produced by the library's public framing encoder. Keep the resulting corpus
and fuzzer crash artifacts outside the source tree.

## Compiler and sanitizers

Fuzz executables require the Clang GNU-style driver (`clang`, not `clang-cl`),
C11, and compiler-rt. Fuzzer executables use `-fsanitize=fuzzer,address,undefined`;
`libdmp` is compiled with address and undefined-behavior sanitizers only. Do not
combine this build with MemorySanitizer. Windows Clang targets require a
configured CRT/linker environment; the Windows GNU target does not provide
libFuzzer support in the tested toolchain.

## Root build integration

The root build exposes `DMP_FUZZ` (default `OFF`). It instruments `libdmp`, then
adds this directory. The CMake file rejects standalone builds, non-Clang
frontends, or an archive that was not instrumented. Ordinary builds need
neither Clang nor compiler-rt.

Configure and build from the repository root:

```bash
cmake -S . -B build/fuzz -G Ninja \
  -DCMAKE_C_COMPILER=clang \
  -DDMP_BUILD_TESTS=ON \
  -DDMP_FUZZ=ON
cmake --build build/fuzz --parallel
ctest --test-dir build/fuzz --output-on-failure
```

Run both seeded smoke fuzzers from the repository root:

```bash
out="${TMPDIR:-/tmp}/dmp-p08-fuzz"
mkdir -p "$out/core-corpus" "$out/stream-corpus" "$out/artifacts"
build/fuzz/tests/fuzz/dmp_fuzz_seed_corpus \
  "$out/core-corpus/core.bin" "$out/stream-corpus/stream-l.bin" \
  "$out/stream-corpus/stream-r.bin"
build/fuzz/tests/fuzz/dmp_fuzz_core "$out/core-corpus" \
  -max_len=256 -runs=1000 -max_total_time=5 \
  -artifact_prefix="$out/artifacts/core-"
build/fuzz/tests/fuzz/dmp_fuzz_stream "$out/stream-corpus" \
  -max_len=256 -runs=1000 -max_total_time=5 \
  -artifact_prefix="$out/artifacts/stream-"
```

## Self-check without running libFuzzer

`tests/fuzz/selfcheck.c` links both callbacks without `DMP_FUZZ_LIBFUZZER`. It
checks the storage bound, rejects overlong and null/non-empty inputs before the
library is called, and runs one known structural frame plus encoded Stream L
and Stream R bytes through the callbacks. It is registered as `fuzz.selfcheck`
when `DMP_FUZZ` and `DMP_BUILD_TESTS` are both enabled.

`fuzz.selfcheck` is part of the instrumented CTest build above. To run the same
callback checks with GCC without compiler-rt, compile the source with the core
files from the root `libdmp` target:

```bash
gcc -std=c11 -Wall -Wextra -Wpedantic -Werror -I include \
  tests/fuzz/selfcheck.c tests/fuzz/fuzz_core.c tests/fuzz/fuzz_stream.c \
  src/core/base.c src/core/codec.c src/integrity/crc32c.c \
  src/stream/cobs.c src/stream/stream.c -o build/dmp-fuzz-selfcheck
build/dmp-fuzz-selfcheck
```

## Allocation checks

`core.allocator_paths` uses GNU linker wrapping to count `malloc`, `calloc`,
`realloc`, and `free` calls while the host runs core encode/parse and Stream
L/R encode/init/feed/poll. `tools/check_core_allocators.py` separately checks
undefined references in the static `libdmp` archive for common C, RTOS, and
ESP-IDF allocator APIs. These checks cover the implemented core/framing only;
there is no endpoint retry path in P08 to measure, and provider/setup
allocation remains a separate concern.
