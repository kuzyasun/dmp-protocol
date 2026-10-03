# P08 Hosted CI Results

Date: 2026-10-03. GitHub Actions run
[37118205823](https://github.com/kuzyasun/dmp-protocol/actions/runs/37118205823)
completed successfully for commit
`2bccf6bf7f8fac3e84eeeadfb8f570cdee5b0bb4`.

| Job | Result |
| --- | --- |
| Linux GCC host | 13/13 CTest cases passed; core archive has no allocator references |
| Windows MSVC host | 12/12 CTest cases passed |
| Linux Clang fuzz/sanitizer | 14/14 CTest cases passed; seeded core and stream libFuzzer smoke runs completed 1,000 executions each |
| Cortex-M4 archive | Arm GNU Toolchain 13.3.1 built `libdmp.a`; no allocator references |
| ESP32-S3 | ESP-IDF v6.0.2 / Xtensa GCC 15.2.0 compile and link passed; map, total/component size reports, hashes and allocator report retained |

The ESP32-S3 artifact was downloaded and inspected. Its application map is
3,437,241 bytes and the bootloader map is 576,818 bytes. `idf.py size` reports
153,033 total image bytes; the linked `libdmp.a` component contribution is
7,330 bytes. The allocator report says there are no allocator references in
the linked core archive. Compiler, `CMakeCache.txt`, and generated `sdkconfig`
SHA-256 values and the source revision are in the artifact. The source revision
matches the CI commit. The Cortex-M4 artifact likewise records source revision,
toolchain/configuration hashes, archive section sizes, and a clean allocator
check.

Artifacts: `dmp-esp32s3-idf-6.0.2` and `dmp-cortex-m4-archive` in the linked
workflow run. These are compile/link and host-test results only; they do not
claim MCU execution, whole-device resource-budget acceptance, physical
transport behavior, or target qualification under P01C.
