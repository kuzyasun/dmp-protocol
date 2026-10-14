# P08 embedded compile-only probes

These projects compile the same portable `src/` library and SAMPLE-1 application
files used by the root CMake target. ESP-IDF builds them as a compile/link-only
probe; they do not connect to DTrack, flash a board, or claim runtime, transport,
or whole-device resource support.

## Cortex-M4 archive

The root project can be configured with
`tests/provider/targets/cortex-m4.cmake` and `DMP_BUILD_TESTS=OFF`. This uses
the P00-selected Cortex-M4 / Thumb-2 EABI5 / little-endian soft-float ABI with
Arm GNU Toolchain 13.3.1 and creates only the `libdmp` static archive. CI keeps
the compiler version, CMake configuration hash, archive section sizes, and
allocator-symbol report.

## ESP32-S3 and ESP32-C3 link and map

`esp32s3/` and `esp32c3/` are isolated ESP-IDF projects. Each builds the full
portable core, endpoint, SEC-1 adapter/handshake transport, and SAMPLE-1 owner
as an IDF component, then links the small public core/framing probe app. Run
both with the EIM-selected ESP-IDF 6.x toolchain. CI records the compiler and
configuration hashes, IDF size reports, linker map, and allocator-symbol
report. These are compile/link-only checks and never flash or run on a board.

## Allocator evidence

The host `core.allocator_paths` test counts calls to common C allocators while
the implemented core parse/encode and Stream L/R encode/init/feed/poll APIs run.
The archive symbol check covers the selected core/framing objects on host and
the declared cross-compilers. These probes establish compilation of the
current modules only; they do not establish target allocator behavior, runtime
crypto/provider fit, full endpoint peak memory, or physical operation.
