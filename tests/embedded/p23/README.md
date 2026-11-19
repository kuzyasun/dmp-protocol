# P23 ESP-IDF size and interoperability fixture

Each image runs one C responder (node 20) with the checked Noise/libsodium
provider. The independent P23 Python peer runs node 10 and the two transparent
relays for RADIO-1. The emulator serial channel carries length-delimited P23
test records. Inside the records, DIRECT-1 uses Stream R and RADIO-1 uses raw
Packet frames. Simulated time, public fixture credentials, UART and response
buffers belong to the test harness.

The build validates the raw manifest against `digests.json`. It generates the
C endpoint configuration, grants, supported handshake budgets and arena sizes
from that manifest. The responder admits its selected digest and Noise mode.
DIRECT-1 runs the existing P23 1,024-byte request/result exchange. RADIO-1
runs routed XX, freshness grants and rejections, and selective repair after a
dropped fragment. The runner also checks profile and Noise mode mismatch.

## Build and run

Initialize the pinned `third_party/noise-c` submodule. Activate ESP-IDF 6.1
with its Espressif QEMU Xtensa and RISC-V tools. Run from the repository root.

```text
eim run "idf.py -C tests/embedded/p23 -B build/p23-s3-direct -DIDF_TARGET=esp32s3 -DDMP_P23_PROFILE=direct-nnpsk0 -DPROJECT_VER=p23-size-r07 build" v6.1
eim run "python -B tests/embedded/p23/run_qemu.py build/p23-s3-direct esp32s3 direct-nnpsk0" v6.1
```

Use a separate build directory for each `esp32s3` or `esp32c3` and
`direct-nnpsk0` or `radio-xx` combination. For an A/B pair use a separate
directory and set `-DDMP_ENABLE_TEST_APIS=OFF` for DIRECT-1 capture removal or
`-DDMP_ENABLE_ENDPOINT_STREAM_R=OFF` for RADIO-1 Packet-only. Pass the same
configuration arguments to `size`, `size-components` and `size-files`.
Keep the application `.bin`, ELF, map, `sdkconfig`, dependency lock and run
log for each image. Use `--emulator` to specify the Espressif QEMU executable
if the activated SDK leaves it off `PATH`.

The QEMU runner checks that the merged Flash image contains the measured app
binary byte for byte. It uses loopback for the serial connection and disables
guest networking. These sizes describe the linked responder and test harness.
Physical transport and on-device latency, heap and stack peaks require
hardware measurements.

## Local measurement inputs

The measurements use the worktree based on `3710115`, ESP-IDF 6.1.0,
GNU 15.2.0, Espressif QEMU 9.2.2 and size optimization. The provider
links use Noise `c40f2dca78eee064e521233a5d884853d471028a` and checked
ESPHome libsodium `1.10021.11`. The generated manifests are bound to these
original-byte hashes.

| Profile | SHA-256 |
| --- | --- |
| `direct-nnpsk0.json` | `048e59973fda6088cb15f1bacdc8f68544ab825f1b4ffd120774f9ec8170f3df` |
| `radio-xx.json` | `43358de08b8d00f0ced3a2e9a085acb17a20d3cb407107309caadb178cba2d92` |

`build/p23-size/` contains the exact build flags, source and artifact hashes,
maps, section and archive reports, and QEMU test logs. `measurements.json`
records the application `.bin` size separately from linked archive Flash and
static data RAM. The paired trials use responder-owned handshake admission.

## Linked size and QEMU results

All values are bytes. Archive Flash is the sum of Flash Code and Flash Data
for that archive in the map. Static RAM is the application `.bss` plus `.data`
in its DRAM or DIRAM region. The app `.bin` also includes the SDK and fixture
code. The Python peer and relays run outside it.

| Target | Profile | Composition | App `.bin` | DMP Flash | P23 fixture Flash | Static RAM | QEMU tests |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| ESP32-S3 | Tier 4 DIRECT-1 NNpsk0 | Default | 272,704 | 75,214 | 20,078 | 88,714 | 2/2 |
| ESP32-S3 | Tier 4 DIRECT-1 NNpsk0 | Capture off | 272,560 | 75,065 | 20,078 | 88,714 | 2/2 |
| ESP32-S3 | Tier 5 RADIO-1 XX | Default | 270,144 | 73,091 | 19,681 | 94,474 | 3/3 |
| ESP32-S3 | Tier 5 RADIO-1 XX | Packet-only endpoint | 268,112 | 71,082 | 19,681 | 94,474 | 3/3 |
| ESP32-C3 | Tier 4 DIRECT-1 NNpsk0 | Default | 259,168 | 81,259 | 20,333 | 84,564 | 2/2 |
| ESP32-C3 | Tier 4 DIRECT-1 NNpsk0 | Capture off | 259,056 | 81,147 | 20,333 | 84,564 | 2/2 |
| ESP32-C3 | Tier 5 RADIO-1 XX | Default | 256,672 | 78,844 | 20,301 | 90,340 | 3/3 |
| ESP32-C3 | Tier 5 RADIO-1 XX | Packet-only endpoint | 254,688 | 76,856 | 20,301 | 90,340 | 3/3 |

Noise plus libsodium contribute 38,766 B of linked Flash on S3 (9,596 B and
29,170 B) and 41,700 B on C3 (11,194 B and 30,506 B) across the corresponding
rows. Capture removal saves 144 B on S3 and 112 B on C3 in the Tier 4 `.bin`.
Compiling out endpoint Stream R saves 2,032 B on S3 and 1,984 B on C3 in the
Tier 5 `.bin`. Both Packet-only ELFs omit Stream and COBS symbols.

The `sdkconfig` and dependency lock match byte-for-byte within all four pairs.
The eight images passed 20 QEMU tests. The host entry points passed
53 focused CTests and the full independent Python peer suite passed 454 tests.
After independent review, the runner was updated to bound emulator startup,
response and suite time and to require raw Packet output for RADIO-1. All eight
images passed again. A test process that flooded stderr failed at the startup
deadline and returned a capped diagnostic.
