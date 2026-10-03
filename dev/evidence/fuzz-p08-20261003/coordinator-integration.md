# P08 coordinator integration checkpoint

Date: 2026-10-03. Independent source review is complete. Package remains open
pending the configured hosted CI jobs and embedded map/size evidence.

## Broker and repository baseline

- `broker_status` returned `READY`; DMP discovery revision 11 was fully
  paginated in one page with eight routes. Live route model, effort, role, and
  policy bindings match the saved operator configuration.
- Workspace bindings are `dmp-current-project` (`current`,
  `dmp-source-project`) and `dmp-review-project` (`review_slot`,
  `dmp-source-project`). `dmp-worker-project` is workspace-write and
  `dmp-reviewer` is read-only.
- No DMP session had an active turn. The P08 worker turn remains
  `turn-b38e6c1420c78485ab8fc779`, with the recorded baseline
  `snap-1f59469d30b556c798c9ecdf` and worker final
  `snap-d6edf6137ed89a61951c2a07`.
- The current route `dmp_cursor_reviewer` is now `grok-4.7-high` with no effort
  override. Review will use the already-authorized, IDLE
  `session-0d68e81ab43e2a092cca438c` on `dmp-review-project`, whose immutable
  session route is Cursor `grok-4.7-xhigh` with no effort override.
- Branch/HEAD: `feat/initial-version` /
  `ae7e06e133b92dcec818bd2006875bbf43d39956`. Existing P07 changes and the
  worker's untracked `tests/fuzz/` contribution remain unstaged and preserved.

## Coordinator integration

- Root CMake now has an opt-in `DMP_FUZZ` mode. It instruments the same
  `libdmp` target with ASan/UBSan, enables two GNU-style Clang/libFuzzer
  executables, and registers a bounded self-check. Normal builds remain
  independent of Clang and compiler-rt.
- The seeded corpus generator uses `dmp_stream_encode` to create Stream L/R
  seeds from the existing known core frame. Inputs are generated under ignored
  `build/` paths and are not committed.
- Linux host CI runs the CMake/CTest suite with GCC and the separate
  Clang/ASan/UBSan/libFuzzer job. Windows host CI uses the Visual Studio 2022
  toolchain. The Cortex-M4 job pins Arm GNU Toolchain 13.3.1 and builds the
  actual `libdmp` archive with the P00 Thumb-2 soft-float flags. The isolated
  ESP32-S3 job uses ESP-IDF v6.0.2, links the same sources, and retains a map,
  size reports, compiler/configuration hashes, and allocator-symbol report.
- `core.allocator_paths` wraps common C allocators while exercising the
  implemented core parse/encode and Stream L/R encode/init/feed/poll paths.
  `tools/check_core_allocators.py` separately inspects undefined symbols in
  the host and embedded archives. Retry/reliability code does not exist yet;
  no future retry or provider/setup allocation claim is made.
- The Cortex compiler exposed a GCC 13.3.1 `-Werror=type-limits` warning in
  `dmp_status_name`. Its range check now casts the enum to `unsigned`, which
  also safely rejects negative invalid values on signed-enum targets.

## Checks independently reproduced

- Direct GCC 15.2.0 strict C11 builds and executions passed for the core
  `base`, `headers`, `codec`, `pipeline`, and 64-packet public-vector tests;
  Stream framing; P07 `harness.port`; the allocator-path probe; fuzz
  self-check; and seed generation (4-byte core, 8-byte Stream L, 11-byte
  Stream R seeds).
- The profile Python suite passed 23/23 tests. The Node vector verifier passed
  4 fixtures, 64 packets, 44 mutations, and its rejection checks.
- The Cortex-M4 archive was compiled from all five portable library sources
  with GCC 13.3.1 and strict warnings. `arm-none-eabi-nm` found no allocator
  references. See [archive size sections](cortex-m4-libdmp-size.txt),
  [allocator check](cortex-m4-allocator-check.txt), and
  [toolchain/flags](cortex-m4-build.txt). This is archive-only evidence, not
  an MCU link, runtime, or whole-device memory result.
- YAML parsing found all five expected workflow jobs. `git diff --check`
  passed.

## Validation gaps and environment limits

- The Windows CMake compiler probe did not finish: compiler identification
  succeeded, then the `try_compile` child stalled during ABI detection. The
  same CMake path could not produce a full local CTest run. Equivalent
  toolchain source builds and focused executables were run directly as listed
  above.
- The P07 Python subprocess suite was attempted, but this sandbox denied file
  creation inside Python-created `TemporaryDirectory` folders, first under
  system `%TEMP%` and again after `TEMP`/`TMP` were placed under the ignored
  repository build directory. `harness.port` itself passed. The hosted
  Windows/Linux CTest jobs remain the required check for that subprocess
  suite.
- Local `eim run "idf.py --version"` failed before invoking IDF with
  `Error executing CLI: Failed to setup logging`, so ESP-IDF was not run
  locally. An authorized RBO macOS host-build request returned an internal
  error without a job ID; it was not replayed.
- The current Windows Clang targets `x86_64-pc-windows-msvc`; libFuzzer and
  its CRT/linker path were not available here. Actual ASan/UBSan execution,
  libFuzzer smoke runs, hosted two-OS CTest, ESP32-S3 link/map, and the hosted
  Cortex archive job are configured but unrun. No configured CI job is
  reported as passed.

## Independent review finding and repair

- Review turn `turn-0d69e2a08f701033fd67f4ef` used the authorized read-only
  Cursor reviewer session and the original P08 baseline. It found that the
  fuzz CMake file declared `dmp_fuzz_selfcheck` and `dmp_fuzz_seed_corpus`
  twice, which made the fuzz configuration fail before target generation.
- The duplicate second block has been removed. One self-check, one seed
  generator, and one `fuzz.selfcheck` test remain.
- A local configure retry with Clang 21.1.0, a GNU/Linux target, and static
  try-compile again stalled at CMake's compiler ABI detection and was stopped.
  The fix has source-level target-count checks and was confirmed in the final
  independent review. Hosted fuzz CI is still required before acceptance.
- Final review turn `turn-122bc0d3f9d9a40cd1f094fc` confirmed that the P1 is
  resolved and reported no additional actionable P0-P2 findings. It did not run
  builds; host CI, libFuzzer/sanitizers, ESP32-S3, and hosted Cortex-M4 evidence
  remain pending.
