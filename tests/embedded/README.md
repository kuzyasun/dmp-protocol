# P08 embedded compile-only probes

These projects compile the same portable `src/` library files used by the root
CMake target. They do not connect to DTrack, flash a board, or claim runtime,
transport, or whole-device resource support.

## Cortex-M4 archive

The root project can be configured with
`tests/provider/targets/cortex-m4.cmake` and `DMP_BUILD_TESTS=OFF`. This uses
the P00-selected Cortex-M4 / Thumb-2 EABI5 / little-endian soft-float ABI with
Arm GNU Toolchain 13.3.1 and creates only the `libdmp` static archive. CI keeps
the compiler version, CMake configuration hash, archive section sizes, and
allocator-symbol report.

## ESP32-S3 link and map

`esp32s3/` is an isolated ESP-IDF project pinned in CI to v6.0.2. It builds a
minimal `app_main` against the portable library as an IDF component. The app
exists only to force the public core/framing objects into a linked image and
linker map; CI records the compiler/configuration hashes, IDF size reports,
map, and allocator-symbol report. It is compile/link-only and is never flashed
or run on a board.

## Allocator evidence

The host `core.allocator_paths` test counts calls to common C allocators while
the implemented core parse/encode and Stream L/R encode/init/feed/poll APIs run.
The archive symbol check covers those core/framing objects on host and both
embedded toolchains. Retry/reliability paths do not exist yet; P08 makes no
claim about future endpoint or provider/setup allocations.
