# MEM-01 provider allocation and cleanup experiment - 2026-09-27

Status: MEM-01 host allocation/owned-heap cleanup scope accepted after independent final review. P01 remains running.

## Scope and frozen brief

Resume clean parent bec767c and Noise fork cfb45b9 after accepted BINIT-01.
Use the separately built checked backend with serialized state ownership and
the existing deterministic fixture-only entropy port. No normative change or
production allocator adoption. RBO discovery returned fetch failed; local
host build/test fallback is used.

The normal host build and a separate Release build will exercise the memory
probe; optimized erasure is checked on that exact host compiler configuration,
without implying all compiler/LTO/target combinations are covered.

Instrument actual selected provider calls with GNU allocator link wrappers.
The tracker uses a fixed table, counts requested allocation bytes and observes
every tracked block immediately before real free. It does not inspect freed
storage or mirror opaque provider structs. Inject failure at each allocation
ordinal observed in a successful NNpsk0/XX setup, exchange and Split sequence;
check error propagation, API output ownership, cleanup and an explicitly fresh
successful attempt. Track allocations separately around setup, start, each
write/read and Split. Compare public fixtures and exercise resulting traffic
contexts after destroying the handshake. Also destroy attempts after a bad
authenticated flight and a simulated successful-read/post-check rejection.

The coordinator owns design, registration, source acceptance, evidence and Git.
One worker owns only tests/provider/noise_memory_probe.c. A second worker reads
the selected source lifecycle without edits. Independent final read-only review
uses a frozen integrated snapshot and actual test logs before acceptance.

## Limits

Requested host heap bytes exclude allocator metadata, fragmentation, stack,
static backend storage and unimplemented DMP/adapter buffers. Failure injection
does not implement a production arena or prove admission caps. This wave does
not claim the manifest's aggregate RAM envelopes, MCU stack/flash/runtime,
simultaneous crypto-slot measurements, complete erasure of stack/register
copies, asynchronous cleanup or endpoint generation/restart policy. These gates
remain open. A provider FAILED action alone is not destruction; the owner must
destroy the attempt and safely release owned buffers.

No push, hardware operation, DTrack integration or production adoption.

## Results and repair

The probe reproduced a dangling constructor output at NNpsk0 allocation 5:
NO_MEMORY returned with a pointer to storage already freed by the provider.
See [pre-fix reproduction](constructor-reproduction.log). The coordinator added
one assignment clearing the output after partial-object destruction in the
shared internal constructor; both public constructors use this path. No layout,
transition, primitive or wire change. The fork change ledger records the repair.
[Source review](source-review.md) also records a prologue allegation that was
checked and rejected.

The first post-fix run passed the NNpsk0 sweep but failed the XX abort test:
the test supplied a NULL input pointer for the empty final payload. The
coordinator supplied a valid empty-buffer pointer, matching the existing probe.
This was a test error; [failed run](ctest-initial-after-fix.log) retained. Later
the coordinator added an actual-provider-interception assertion and an explicit
two-endpoint measurement label. No expectation was weakened.

Final normal build: [32/32 CTest](ctest-final-summary.log),
[full log](ctest-final-full.log). This includes seven preparation cases without
skips. Each inherited vector configuration runs 52 and skips 988; two expected
limitations remain separate from capability passes. Final Release:
[1/1 targeted probe](ctest-release-final-summary.log),
[full log](ctest-release-final-full.log); other Release tests were not run.
Release uses GCC 15.2.0, -O3 -DNDEBUG, no LTO. Initial new-target build: 4 steps;
constructor repair: 25 steps; initial Release: 76 steps; final probe rebuilds:
2 steps each. Ordinary builds and final probe rebuilds emitted no warnings.
The first Release build emitted one existing patterns.c:691 -Wstringop-overread
warning: memchr's maximum token bound exceeds the concrete static base-pattern
array size. The patterns are END-terminated, but this broad bound needs separate
source-boundary assessment; no warning suppression or pattern change is included
in MEM-01, and a warning-free optimized provider build is not claimed.
See [Release build log](build-release.log). Probe: C11 with
-Wall -Wextra -Wpedantic -Werror.

| Aggregate of one initiator/responder pair | NNpsk0 | XX |
|---|---:|---:|
| Setup requests / total requested bytes | 14 / 2394 | 18 / 3066 |
| Start, write, read allocation requests | 0 | 0 |
| Split requests / total requested bytes | 2 / 256 | 2 / 256 |
| FINISH/READY cipher-operation requests after handshake destruction | 0 | 0 |
| Peak live requested heap bytes for the pair | 2650 | 3322 |
| Distinct allocation-failure ordinals exercised | 16 | 20 |

Values match in both host builds. These use supplied fixture ephemerals, not
every RNG/key-generation path or concurrent crypto slot. Public-key derivation
occurs before tracking. The fixed tracker table is not a production allocation
cap. Bytes exclude heap metadata and stack/static storage; never compare this
two-endpoint sum directly to a per-endpoint envelope.

Each injected ordinal must fire, return NO_MEMORY and leave no tracked live
allocation after cleanup. Constructor and failed Split outputs are checked.
Exact flights, payloads, both final hashes and directional FINISH/READY bytes
are verified. A fresh successful exchange follows each mode's sweep. Separate
cases destroy owners after a corrupt authenticated final flight and successful
final reads with simulated owner policy rejection. No endpoint pin/late-work
implementation is claimed.

Every tracked free checks all requested bytes before real free; the test does
not erase them for the provider. Self-checks exercise allocation interception,
failure injection and deliberate dirty-free detection. Unexpected live-block
realloc fails explicitly; no emulated erasure. Static provider/backend allocator
references are intercepted; dynamic CRT internals and startup before tracking
are excluded. [Symbol inventory](allocator-symbols.log) is complementary evidence.

## Reproduction and identity

From the repository root with the prepared pinned backend:

```text
cmake -S . -B build/noise-experiments -G Ninja -DCMAKE_C_COMPILER=C:/develop/mingw/w64devkit/bin/gcc.exe -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=C:/projects/gemslibe/dmp-protocol/build/noise-upstream/_deps/esphome_libsodium-1.10021.11
cmake --build build/noise-experiments
ctest --test-dir build/noise-experiments --output-on-failure
cmake -S . -B build/noise-memory-release -G Ninja -DCMAKE_C_COMPILER=C:/develop/mingw/w64devkit/bin/gcc.exe -DCMAKE_BUILD_TYPE=Release -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=C:/projects/gemslibe/dmp-protocol/build/noise-upstream/_deps/esphome_libsodium-1.10021.11
cmake --build build/noise-memory-release --target dmp_noise_memory_probe
ctest --test-dir build/noise-memory-release -R ^dmp_noise_memory_probe$ --output-on-failure
```

[Baseline](baseline.json) records starting heads, normative hashes and original
index hash. Code/evidence snapshots identify the reviewed dirty source. Logs
retain results with trailing whitespace normalized. No fetched backend or
normative file changed.

Next recommended: MEM-02, a bounded setup-storage/allocator seam and explicit
quota exhaustion, followed by size/alignment and build evidence for both MCU
configurations. Complete stack/secret-copy and platform entropy gates stay open.

## Final review and local source pin

The independent reviewer returned scoped PASS with no actionable findings after
verifying nine code hashes, 23 evidence hashes, seven normative hashes, both
backend tree digests and the initial index. Review inspected code and recorded
logs; the coordinator executed tests. The memchr diagnostic was assessed against
the static END-terminated tables and C11's first-match semantics; it does not
establish an overread for those tables or block this scope. The emitted warning
remains recorded; an entirely warning-free Release build is not claimed.

Reviewed fork files were committed locally as
0a7eddb6c5d2c84e7f78d5b9831a42e103852520. Subsequent changes only update the
parent engine pin, acceptance metadata and [review result](review-result.json).
The reviewed snapshots remain historical evidence, including their old pin and
pre-acceptance README hash. No reviewed implementation changed after acceptance.
