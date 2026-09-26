# MEM-02 bounded allocator port and target layouts - 2026-09-27

Status: host quota tests and selected compile-only layouts accepted after independent read-only review. P01 remains running.

## Frozen design

Start from clean parent b75f1a9 and fork 0a7eddb. Add an opt-in compile-time
allocator port to the controlled Noise fork. Object and prologue allocation
must use the same port, preserve zero-initialized objects, propagate NULL as
NO_MEMORY and erase owned bytes before release. No automatic heap fallback,
runtime allocator registration, new primitive or wire/state-machine change.
The default system allocator remains an explicitly separate regression build.

The application port supplies max_align_t-aligned storage, bounded quotas and
matching release for the original size. Storage/metadata outlive all owners,
including Split traffic contexts. One serialized owner is tested; per-object
allocator domains and concurrent dispatch are not introduced by this seam.

The test arena's declared byte storage is reused for different object types.
GNU/Clang custom-arena targets explicitly use -fno-strict-aliasing; alignment
alone does not establish ISO C effective-type safety for that storage policy.
This compiler choice belongs to the experiment port, not the abstract allocator
hook, and is not a claim about every compiler or a production allocator.

The private experiment uses a caller-backed fixed arena with finite metadata,
aligned first-fit spans, byte and block quotas and reuse while other allocations
live. Test quota exhaustion, fragmentation, rejection without partial mutation,
dirty/invalid frees and object cleanup. Reuse exact Noise fixtures on a separate
custom-allocator target, and inspect allocator symbols for bypasses.

Compile actual provider types/call paths for Windows host, Cortex-M4 and
ESP32-S3 to record concrete size/alignment without copying opaque layouts.
Generated compiler inputs/objects are build artifacts, produced by the tracked
script. Compile-only evidence is not linked-backend or MCU runtime acceptance.

Coordinator owns fork hooks, shared registration, integration, evidence and
acceptance. One worker owns only noise_test_arena.h/.c and its unit probe; a
second owns only measure_noise_layout.py. Independent final review is required.

RBO job job_01M3FY09EM0CBCKG0H14G1X270 failed before execution: repo_fetch could
not fetch local unpublished submodule commit 0a7eddb from origin. No push was
performed to work around this. Local fallback uses the already recorded tools.

## Limits

This is a provider seam plus a test allocator, not the future public DMP API or
production profile acceptance. Include arena metadata/padding in storage claims;
do not substitute requested heap bytes for physical storage. Stack/register
erasure, full backend MCU linking, stack high-water, runtime/entropy, admission
and asynchronous ownership remain open. No push, hardware or DTrack integration.

## Host results

[Final ordinary suite](ctest-final-summary.log): 34/34 CTest invocations.
[Release](ctest-release-summary.log): 2/2 targeted arena unit/integration probes,
not all Release tests. Full logs accompany both summaries. The ordinary suite
retains two expected-limitations diagnostics and both inherited vector suites
(52 vectors run, 988 skipped each); these are not extra capability passes.
The seven preparation tests pass without skips. Release repeats the already
reviewed patterns.c memchr-bound warning; no suppression or warning-free Release
claim. New probe/arena sources compile with C11 and warnings as errors.

Arena unit tests cover zero/exact/over-quota and overflow requests, alignment,
rounding, fragmentation, reuse while a neighbor stays live, dirty/wrong-size/
foreign/double release, and rejection of reset while live. Integration fills
backing bytes with 0xA5 before creation so objects cannot rely on clean storage.
For both roles: NNpsk0 constructor uses 6 blocks / 1136 charged bytes; XX uses
8 / 1488 on this host. Each smaller block quota and one-byte-short constructor
quota returns NO_MEMORY with NULL output and complete cleanup. A full exact
constructor quota refuses subsequent prologue allocation. Existing keyed traffic
survives a refused new handshake and refused live reset, matching fixture bytes.

Both exact fixture exchanges and abort-first checks run through the custom
port. After Split the embedded fixture runner destroys both handshakes before
using the transferred traffic contexts. 76 allocations complete and release,
with peak charged live storage 3424 bytes. The fixed reserve is 8192 bytes plus
2112 bytes of metadata = 10304 bytes, not 3424 physical bytes. It serves the
two-endpoint test driver and is not a production per-endpoint budget. No heap
fallback exists in the custom Noise archive; [symbol check](allocator-symbols.log)
shows the application hooks and the prologue wrapper, with no libc allocator
references. Unmodified baseline allocator builds remain separate regressions.

## Compile-only layouts

The [measurement summary](layout-summary.json) and per-target JSON contain exact
commands, compiler versions, input hashes, layout extraction, undefined symbols
and warnings. Each target compiles seven translation units: actual state-layout
probes, util.c, handshakestate.c and the test arena. Host COFF does not provide
nm symbol sizes, so the tool reads compiler-emitted .space/.zero extents; the
host assembly is retained here. ELF targets use nm symbol sizes. No opaque
structure is copied/redeclared. Static assertions verify selected concrete type
alignment does not exceed max_align_t.

| Type (size / alignment bytes) | Windows x86-64 | Cortex-M4 | ESP32-S3 |
|---|---:|---:|---:|
| Handshake | 240 / 8 | 176 / 4 | 176 / 4 |
| Symmetric | 256 / 8 | 244 / 4 | 244 / 4 |
| X25519 | 168 / 8 | 120 / 4 | 120 / 4 |
| SHA256 | 152 / 8 | 136 / 8 | 136 / 8 |
| ChaChaPoly | 128 / 8 | 112 / 8 | 112 / 8 |
| Arena metadata | 2112 / 8 | 1056 / 4 | 1056 / 4 |
| max_align_t | 32 / 16 | 16 / 8 | 16 / 8 |

These are individual type sizes, not a complete handshake allocation sum.
Compiler .su reports are retained separately; they are not call-chain stack
peaks or physical high-water evidence. The source-generated probes compile the
Noise sodium adapters, not a fully linked libsodium backend for the MCU. They
show no legacy allocator references and do reference both custom allocator
hooks. ESP32-S3 uses the previously recorded SDK toolchain directly for these
isolated translation units; no IDF project, board or firmware was built/flashed.

Initial strict layout builds failed because -Wextra/-Werror exposed inherited
unused parameters in the included backend sources; the failed diagnostics are
retained. The corrected tool applies -Werror to owned core-layout/arena inputs,
retains -Wall/-Wextra/-Wpedantic for inherited inputs and records their warnings
without suppressions. Each target reports six inherited unused-parameter
warnings. These checks do not claim warning-free full provider builds.

## Reproduction

From repository root, using the existing configured ordinary and Release builds:

```text
cmake -S . -B build/noise-experiments
cmake --build build/noise-experiments
ctest --test-dir build/noise-experiments --output-on-failure
cmake -S . -B build/noise-memory-release
cmake --build build/noise-memory-release --target dmp_noise_arena_unit dmp_noise_allocator_probe
ctest --test-dir build/noise-memory-release -R ^dmp_noise_(arena_unit|allocator_probe)$ --output-on-failure
python tests/provider/measure_noise_layout.py --compiler <target-gcc> --nm <matching-nm> --target <host|cortex-m4|esp32s3> --backend build/noise-upstream/_deps/esphome_libsodium-1.10021.11 --output build/noise-layout/<target>
```

PowerShell callers must quote the CTest regex. Full compiler paths/flags are in
the target JSON reports; the host/backend configuration is inherited from
MEM-01 and BINIT-01. [Baseline](baseline.json) records both initial clean heads,
index hashes and seven normative files. Both backend raw tree digests match
the previous wave. No normative file changed.

Independent final review returned scoped PASS without actionable findings. The
reviewer inspected sources and recorded evidence, not fresh test execution, and
verified 14 code hashes, 37 evidence hashes, both initial indexes, seven normative
files and both backend digests. See [review result](review-result.json). Reviewed
fork source is local commit c40f2dc. Historical snapshots remain unchanged; the
parent source pin and acceptance metadata were updated after review.

Next recommended: complete provider/backend archive compilation for Cortex-M4
and an isolated ESP-IDF ESP32-S3 build/link. Cortex-M4 has no selected board or
linker map yet. Then measure retained/scratch/stack and declared concurrency.
Host quota checks alone cannot close P01.
