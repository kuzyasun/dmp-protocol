# R07 optional build compositions

Baseline `11a40fe` is the reviewed R06 commit. This slice uses the existing
`dmp::dmp_none` and `dmp::sample1_none` targets without changing public
structures, deployment manifests, or the default SEC-1 composition.

Typed admission rejects SEC-1 configurations and required freshness in the
NONE build before assigning the admitted profile. Endpoint initialization
uses the same check. Direct handshake bind and rotation calls reject the
unavailable capability before selecting a peer or changing a route. The rejection
fixture checks that a live NONE endpoint and the profile output retain
their exact bytes. It also checks rejection of caller-provided handshake
admission and a bind attempt for a different peer on a live endpoint.

The previous NONE endpoint left a few SEC-1 calls to compiler elimination.
Their unavailable operations now compile out of the NONE target. Debug
uses the selected configuration's compiler flags. The link probe disables
linker garbage collection on GNU linkers and uses `/OPT:NOREF` on MSVC.
Where CMake provides an `nm`-style reader, CTest verifies required symbols
in the probe and the absence of SEC-1, provider, Noise, and libsodium symbols
in that executable and both NONE archives.
The GCC CI job now runs the focused Debug link, symbol, and admission
tests. Its commands were exercised locally with MinGW GCC. The remote
Linux CI job was not run as part of this work.

## Host verification

MinGW GCC 15.2 Debug used `-O0` for the production NONE endpoint source.
The link command used `--no-gc-sections` and only `libdmp_sample1_none.a`,
`libdmp_none.a`, and the Windows toolchain libraries. All 40 targeted CTests
passed. They include the crypto-free link and symbol checks, fail-closed
admission and bind, NONE SAMPLE-1 including Stream R fixtures, and the routed
RADIO SELECTIVE-32 recovery fixture. The allocator audit passed for both
Debug and Release `libdmp_none.a`.

The Release controls used the same pinned Noise/libsodium toolchain as R06.
Each capture mode passed 200 host CTests. The independent peer suite passed
all 454 cases.
Builds used one worker at a time. [Verification excerpts](verification.txt).

```powershell
$gcc = (Get-Command gcc).Source.Replace('\', '/')
cmake -S . -B build/r07-none-debug -G Ninja "-DCMAKE_C_COMPILER=$gcc" `
    -DCMAKE_BUILD_TYPE=Debug '-DCMAKE_C_FLAGS_DEBUG=-O0 -g' `
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build/r07-none-debug --parallel 1 --target `
    dmp_none_link_probe dmp_test_none_capacity dmp_test_endpoint_none `
    dmp_test_none_multi_peer_traffic dmp_test_sample1_none dmp_test_sample1_none_5 `
    dmp_test_sample1_none_16 dmp_test_sample1_none_stream_r_5 `
    dmp_test_sample1_none_stream_r_16 dmp_test_sample1_none_radio_5 `
    dmp_test_sample1_none_radio_16 dmp_test_radio_none_selective `
    dmp_size_core dmp_size_core_stream_r dmp_size_none_direct dmp_size_none_radio
ctest --test-dir build/r07-none-debug -j 1 --output-on-failure -R '^(endpoint[.]none|size[.])'
```

## Tier 0 host size probes

The existing executable probes run real Core encode and parse plus CRC32C,
with Stream R framing and decode enabled in the second executable. GNU
`size -A` reported the following PE section sizes, including host runtime
overhead. GNU `nm` confirmed the Core and CRC32C entry points in both
executables and the Stream/COBS symbols in the second executable only.

| Host GCC configuration | Executable workload | `.text` (B) | `.rdata` (B) |
| --- | --- | ---: | ---: |
| Debug `-O0` | Core + CRC32C | 18,560 | 2,504 |
| Debug `-O0` | Core + CRC32C + Stream R | 27,808 | 2,984 |
| Release | Core + CRC32C | 18,032 | 2,504 |
| Release | Core + CRC32C + Stream R | 25,456 | 3,016 |

## Exact NONE profiles and Packet-only endpoint builds

The additional `dmp_size_none_direct` and `dmp_size_none_radio` targets
derive typed admission input, SHA-256 and capacity constants from the exact
validated manifest bytes at CMake configuration. They use the same workload
sources as the ESP-IDF size project. DIRECT exercises SAMPLE-1 over Stream R
and explicit context replacement. RADIO exercises CRC32C and selective
repair for routed DATA over Packet with one peer per endpoint. Both use
deterministic loopback transports and the RADIO probe does not forward
through a relay.

The default `DMP_ENABLE_ENDPOINT_STREAM_R=ON` retains both endpoint bindings.
Set OFF for Packet-only. The endpoint rejects Stream R initialization and
direct Stream ingress before mutation. The archive still provides the
standalone Stream codec, and the full library keeps SEC-1 handshake
transport. The narrow host test configuration links the exact RADIO NONE
workload and exercises the independent Core + Stream R probe. Supplying
the pinned `DMP_SODIUM_SOURCE_DIR` also registers the protected RADIO peer
gate. The Packet-only NONE executable's symbol audit checks that the
endpoint, packet RX and CRC are present and that Stream, COBS and SEC-1
symbols are absent.
The Packet-only host gate passed 9 CTests with the pinned provider and 4
size/link CTests without it.
Prepare the pinned provider using the [R04 host recipe](../code-size-r04-20261118/commands.md).

```powershell
$sodium = (Resolve-Path 'build/noise-upstream/_deps/esphome_libsodium-1.10021.11').Path.Replace('\', '/')
cmake -S . -B build/r07-packet -G Ninja "-DCMAKE_C_COMPILER=$gcc" `
    -DCMAKE_BUILD_TYPE=Debug '-DCMAKE_C_FLAGS_DEBUG=-O0 -g' `
    -DDMP_ENABLE_ENDPOINT_STREAM_R=OFF "-DDMP_SODIUM_SOURCE_DIR=$sodium"
cmake --build build/r07-packet --parallel 1
ctest --test-dir build/r07-packet -j 1 --output-on-failure
```

## ESP-IDF 6.1

Run the same recipe for `esp32s3` and `esp32c3`, with separate build
directories for each workload. The minimal project does not declare a
Noise, libsodium or SEC-1 source or component dependency.

| Workload | CMake arguments |
| --- | --- |
| Core + CRC32C | Defaults |
| Core + CRC32C + Stream R | `-DDMP_SIZE_PROBE_STREAM_R=ON` |
| DIRECT-1 NONE | `-DDMP_SIZE_NONE_PROFILE=direct` |
| RADIO-1 NONE | `-DDMP_SIZE_NONE_PROFILE=radio` |
| RADIO-1 NONE, Packet-only | `-DDMP_SIZE_NONE_PROFILE=radio -DDMP_ENABLE_ENDPOINT_STREAM_R=OFF` |

```text
eim run "idf.py -C tests/embedded/size -B build/size-s3-radio -DIDF_TARGET=esp32s3 -DPROJECT_VER=11a40fe-r07-size -DDMP_SIZE_NONE_PROFILE=radio build" v6.1
```

Run `idf.py size` with the same target, cache arguments and directory. Use
the ESP-IDF Python environment for `python -m esp_idf_size --archives
--format csv dmp_size_probe.map` and the target's `nm` for the linked ELF.
Separate build directories share their target's fixed SDK defaults. The
size application reserves an 8 KiB main task stack for the fixture, so the
Stage 0 qualification comparison uses the original qualification project
and its own unchanged SDK configuration.

The qualification reproduction uses the [R05 recipe](../code-size-r05-20261119/commands.md)
with the Stage 0 or final source overlay. Refresh source file timestamps
after copying a snapshot into an existing build tree to prevent stale
objects. Compare Stage 0, final default, and final with capture and
diagnostics disabled plus shared admission. The SDK configuration,
lock, linker script hashes and link command must match within each
target's qualification set. [Stage 0 to R07 report](final-report.md).

## Local portability follow-up

GitHub Actions run `44426225722` on `3710115` and Stage 0 run
`39489742339` hit the existing CI failures. This follow-up fixes the
corresponding build paths and validates them locally. RBO was unreachable.
The local builds ran serially. The GitHub results still describe those
published revisions.

The full unpinned host suite links the NONE-only endpoint and relay fixtures
against the NONE library. The relay fixture also compiles the replay-window
source it uses as a test utility. With the pinned provider available, the
fixtures retain their full-library link. The MSVC warning fixes affect test
configuration and types. The Arm build retains the existing valid transport
outcome range and maps out-of-range values to the same conservative outcome.
The isolated ESP-IDF CI job checks out the Noise submodule recursively, uses
the 6.1 SDK recorded in its lock, and exports the per-file size report.

The three NONE deployment files carry their pinned CRLF bytes in the working
tree. The Git attributes preserve those bytes when committed and exported to
source archives. All 18 deployment SHA-256 values match `digests.json`.
The size generator accepts the pinned DIRECT-1 bytes and rejects an LF copy
with `exact manifest SHA256 mismatch`. The archived R07 generated headers
and measurement record already contain the pinned SHA-256 values.

| Local gate | Result |
| --- | --- |
| Ubuntu 24.04/GCC 13.3.0 Release, no provider | 99/99 CTests, including both Node fixture gates and the allocator-path test |
| Ubuntu GCC Debug `-O0`, focused CI configurations | NONE link/symbol/admission 3/3 and Packet-only size/Stream/symbol 4/4 |
| Windows MSVC 19.44 Release, no provider | 97/97 CTests |
| Ubuntu 24.04/Clang 18.1.3, ASan and UBSan for `libdmp` and fuzz targets | 100/100 CTests. Seeded Core and Stream libFuzzer targets each passed 1,000 runs. |
| Windows GCC 15.2.0, pinned Noise/libsodium | 200/200 CTests, including SEC-1 endpoint, P23, P24 and Cortex-M4 ABI |
| Independent Python peer suite with both native drivers | 454/454 tests, no skips |
| Arm GNU 13.3.1, freestanding Cortex-M4 archive | Build and core allocator-symbol check passed |
| ESP-IDF 6.1 isolated ESP32-S3 project, Xtensa GCC 15.2.0 | Compile/link and allocator-symbol check passed. The dependency lock was unchanged, the app `.bin` was 188,928 B, and all three size reports were generated. |

The six size-probe rebuilds below use the closeout worktree based on `3710115`,
the pinned NONE manifests and the same per-image `sdkconfig` bytes as the
archived R07 runs. The symbol check found no DMP handshake, provider, Noise
or sodium symbols in the six ELFs. The paired Packet-only links also omit
Stream and COBS symbols.

| Workload | S3 DMP Flash (B) | S3 app `.bin` (B) | C3 DMP Flash (B) | C3 app `.bin` (B) |
| --- | ---: | ---: | ---: | ---: |
| DIRECT-1 NONE, Stream R and SAMPLE-1 | 54,438 | 196,752 | 57,885 | 179,232 |
| RADIO-1 NONE, Packet and SELECTIVE-32 | 45,631 | 184,512 | 48,390 | 166,800 |
| RADIO-1 NONE, endpoint Stream R compiled out | 43,580 | 182,448 | 46,396 | 164,800 |

Espressif QEMU 9.2.2 ran all six rebuilt NONE workloads and the four
archived R07 Tier 0 workloads (Core and Core plus Stream R on each target).
The virtual serial logs captured the expected success marker and return from
`app_main()` in all ten runs. The recipe uses `esptool merge-bin` with the
build's `flash_args` and configured Flash size, then boots the resulting
image with the SDK's QEMU machine and initial eFuse data. The workloads use
loopback and the emulated CPU. Physical transport and timing remain open.

The Cortex-M4 Tier 0 comparison links the same `tests/size/codec_probe.c`
against Stage 0 and the current sources. Both builds use Arm GNU 13.3.1,
`-mcpu=cortex-m4 -mthumb -mfloat-abi=soft -Os -ffreestanding`, section GC and
the same minimal linker layout. The synthetic layout places Flash at
`0x08000000` and RAM at `0x20000000` with `main` as the link entry and no
startup files. `nm` confirms the workload's public Core, CRC and optional
Stream entry points are retained. The values describe linked sections and
the raw load image for this comparison.

| Cortex-M4 Tier 0 workload | Stage 0 raw image (B) | Closeout raw image (B) | Delta (B) | Static BSS in both (B) |
| --- | ---: | ---: | ---: | ---: |
| Core + CRC32C | 4,608 | 4,756 | +148 | 0 |
| Core + CRC32C + Stream R | 6,979 | 7,099 | +120 | 263 |

Local logs, image hashes and input hashes are in `build/closeout-idf/`,
`build/closeout-fuzz/`, `build/closeout-linux/`, `build/closeout-msvc/`,
`build/closeout-arm/`, `build/closeout-m4-tier0/` and `build/r06-host-on/`.

The S3/C3 qualification application uses a `0x2f0000`-byte factory
partition. Its Stage 0, R07 default and R07 trimmed app binaries leave
2,187,200 / 2,190,576 / 2,192,032 B free on S3 and
2,148,288 / 2,150,080 / 2,151,488 B free on C3, respectively. These are
partition arithmetic for the measured applications. Deployment Flash, RAM,
stack and latency budget acceptance still needs owner-defined thresholds.

Tier 4 and Tier 5 have exact-profile real-provider host execution via the
independent peer, including DIRECT-1 NNpsk0 and RADIO-1 XX. The shared host
driver and the ESP-NOW qualification link each have their own size results.
The [dedicated P23 targets](../../../tests/embedded/p23/README.md) provide
separate Tier 4 and Tier 5 image sizes and QEMU interoperability on ESP32-S3
and ESP32-C3. Runtime heap/stack high-water, crypto scratch at target
concurrency, on-device latency and physical transport still require hardware
execution.
The proposed freshness and SELECTIVE-32 flags remain outside the supported
builds. Tier 1 still requires an unfragmented manifest and admission contract.
