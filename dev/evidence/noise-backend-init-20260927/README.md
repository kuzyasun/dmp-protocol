# BINIT-01 checked backend startup experiment - 2026-09-27

Status: BINIT-01 serialized host scope accepted after independent final review. P01 remains running.

## Frozen design and acceptance

The owner requested the recommended backend startup continuation. Start from
clean parent 2896cf3 and Noise fork cfb45b9. No normative contract changes.
Patch only startup coordination in pinned libsodium core.c and allocator-canary
setup in utils.c, preserving CPU feature/primitive implementation setup. An
opt-in checked build calls platform readiness and canary-byte ports that report
failure; no void RNG callbacks, global replacement or nonlocal recovery.

On entropy failure return -1 before publishing initialized, clear partial
canary bytes and release the existing lock. An explicit later init call may
retry; there is no automatic loop/fallback. The serialized Noise configuration
is tested; pthread-once still caches its first returned error. Ports own CSPRNG
quality/readiness/boundedness and must not reenter startup while under its lock.
Callers must require init success before using provider objects.

Keep the original backend/regressions and its expected abort reproduction.
Build a separate checked backend from hash-verified generated translations of
the two original source files. The tracked patch/tool/header/license form the
maintained experimental delta; do not edit the fetched backend or generated
outputs manually. Checked Noise uses the RNG-01 custom port for runtime entropy;
legacy libsodium randombytes APIs are outside this selected provider contract.

Root owns patch, security design, CMake, evidence and final acceptance. Workers
own only the patch-preparation helper/tests and separate startup fault probe.
Run source-preparation negative tests, readiness/partial-byte/explicit-retry
checks, real healthy crypto/fixtures and existing PN/DH/RNG regressions on the
new backend. Independent review is mandatory before local commit. No push,
new remote fork, hardware operation, production adoption or DTrack integration.

RBO discovery returned fetch failed; local fallback. Physical cold-boot quality,
full MCU builds/runtime resources, lock-time bounds and other P01 gates remain
open. A test entropy port proves failure handling, not eligible hardware entropy.

## Executed checks

The initial configure failed because the inherited assembly file needed ASM
language enabled in the new target's scope. The corrected configuration built
97 steps without emitted warnings and passed 29 CTest invocations. Coverage was
then expanded to inherited unit/vector suites linked to the checked backend;
the deterministic fixture port now varies its test seed per call to exercise
fresh-state uniqueness. The resulting 30 incremental build steps had no
emitted warnings and the final suite passed **31/31 CTest invocations**.
No primitive or backend-patch change was needed after the runtime checks.

Commands from repository root:

```text
cmake -S . -B build/noise-experiments -G Ninja -DCMAKE_C_COMPILER=C:/develop/mingw/w64devkit/bin/gcc.exe -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=C:/projects/gemslibe/dmp-protocol/build/noise-upstream/_deps/esphome_libsodium-1.10021.11
cmake --build build/noise-experiments
ctest --test-dir build/noise-experiments --output-on-failure
```

See [initial configure failure](configure-initial-failure.log), [configure](configure.log),
[first build](build-first.log), [final incremental build](build.log),
[initial test summary](ctest-summary-first.log), [final test summary](ctest-summary.log)
and [full final test log](ctest-full.log). The two expected-limitations tests
remain separately labeled; their success is not a capability pass. Each
inherited vector configuration runs 52 cases and skips 988. They do not add
backend independence: both configurations use the same primitive sources.

| Requirement | Actual check | Result / boundary |
|---|---|---|
| Reproducible patch inputs | Seven Python cases within dmp_checked_backend_preparation | Tampered source, invalid patch, overlap/symlink rejection and hard-link preservation; idempotence and LF/CRLF equivalence pass; generated outputs carry hashes |
| Readiness failure | Actual checked sodium_init through Noise, two explicit failed calls | SYSTEM returned, one readiness call per attempt, no canary read, no successful-init publication |
| Canary read failure | Partial bytes written before error, two attempts | Entire static canary buffer is zero afterward; no abort or automatic retry |
| Recovery and normal init | Explicit sodium_init after recovery returns 0, next returns 1 | Port call counts unchanged after success; real SHA-256 abc digest matches |
| Windows OS RNG failure | Same probe with checked port calling SystemFunction036 | Two forced FALSE results return locally, then actual OS RNG succeeds; canary cleared between failures |
| No legacy RNG fallback | GNU/Windows wrappers trap randombytes_stir/randombytes_buf | All exercised checked startup/Noise/regression paths avoid both void APIs |
| Real Noise behavior | Five existing DMP probes plus inherited unit/vector suites linked only to checked backend | Exact NNpsk0/XX flights/hash/Split, PN/DH/RNG failures and regression cases pass |
| Baseline unchanged | Original suite including supervised backend abort | Still reproduces original limitation; backend/Noise/normative hashes unchanged |

The helper worker's earlier sandbox runs failed due to temporary-directory
permissions and an early fixture-format issue. A machine-specific test-path
workaround was rejected and removed before acceptance. Final tests use normal
portable temporary directories, and the coordinator's elevated run passed all
initial six cases; the final seven-case run after review also passed without skips. Four identified repository-root scratch directories
were removed after checking exact paths; no source/index reset was performed.
These failures are not recorded as successful checks.

## Source identity and review boundary

[Baseline](baseline.json) records clean heads, original backend digests and seven
normative hashes. Both backend trees still match their original raw-byte digests.
[Preparation report](preparation.json) records the two original raw/normalized
hashes, patch hash and generated translation hashes. Existing licenses remain
in place; the upstream ISC copy accompanies the maintained patch.
[Patch contract](../../../tests/provider/backend/README.md) defines the new
experimental integration and excluded surfaces. No source file under the
fetched backend or Noise submodule changed.

The initial code snapshot predates the test-seed/inherited-suite coverage
extension. A final code snapshot plus final evidence snapshot identify the
reviewed integrated files; logs only have trailing-whitespace normalization.

## Limits and recommended next work

This accepts no production CSPRNG or MCU cold-boot quality. Current runtime
startup coverage is serialized host initialization; lock wait bounds, critical
section failure injection, invalid-page fault injection and concurrent backend
startup are not passed. The inherited critical-section machinery is retained.
Generic libsodium legacy RNG APIs remain outside the selected provider surface.
A caller must require successful initialization before using objects.

The partial canary check proves this buffer's cleanup, not erasure of every
secret copy. MCU builds/runtime resources, storage/allocator failure and other
P01 cases remain pending. Next recommended wave is MEM-01: bounded setup
allocation, OOM and secret cleanup, alongside separately planned platform entropy
readiness/quality evidence. No new remote fork, push, hardware or DTrack action.

## Confirmed review finding and repair

The independent reviewer found that truncating an existing generated-output
hard link could modify its linked original source, despite path/symlink checks.
The coordinator confirmed the code path and replaced in-place writes with a
new temporary file and os.replace for both generated sources and the report.
The new hard-link regression links output core.c and preparation.json to the
two original files, then verifies distinct output inodes and unchanged originals.

[Targeted recheck](preparation-hardlink-recheck.log) passed all seven helper cases.
The [final configure](configure-final.log) succeeded, [build](build-final.log)
reported no work (generated C unchanged), and the final 31/31 suite passed again.
The reviewer verified all 12 final code hashes and 18 evidence hashes, confirmed
the repair and returned scoped PASS with no open actionable findings. See
[review result](review-result.json). Review was read-only source/evidence inspection;
the coordinator ran the builds and tests. Historical reviewed snapshots are
retained; subsequent changes only record acceptance metadata and this result.
No runtime provider code changed for this finding.
