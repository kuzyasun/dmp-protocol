# P05 codec and P06 framing

Status: P05 and P06 accepted for the scoped host library implementation.
[baseline.json](baseline.json) records HEAD, exact index and source hashes.
Ignored build/codec-framing-preserve contains the original index and
staged/unstaged binary patches. No staging, commit, push or board operation.

Two disjoint Luna high workers implemented real library modules and dedicated
tests. Coordinator integrated shared headers/CMake and tests, verified actual
diffs and fixed confirmed findings. Independent Astra xhigh reviewed the fixed
source and evidence without edits; [review and closures](review.md).

## Implemented code and verification

- `src/core/codec.c`: borrowed structural parser, canonical u32/u64 ULEB,
  ordered TLVs, known shapes, quotas/fragment geometry, separate role checks,
  preflighted header/full encoding and extension iterator.
- `src/integrity/crc32c.c`: standard CRC32C; `src/stream/cobs.c`: shared canonical
  COBS implementation; `src/stream/stream.c`: bounded incremental Stream L/R,
  caller-owned scratch, absolute deadlines and explicit reset/resynchronization.
- `core.codec`: independent main examples, malformed/overflow/truncated fields,
  C/U role combinations, descriptor/service/control shapes, header 255/256,
  capacity/error sentinels, diagnostic offsets and encoder regressions.
- `core.public_packets`: 64 published SEC-1 packets, both cipher descriptors,
  exact parse/header/full-encode bytes and Stream R round trips. The generator only
  copies fixture bytes/metadata; it implements no codec or crypto. Flipped tags
  still parse structurally, explicitly demonstrating the authentication boundary.
- `stream.framing`: CRC and canonical COBS 254/255/508/zero-adjacency vectors,
  all splits of the small golden frames, concatenation, length/CRC/COBS failures,
  encoded and decoded oversize recovery, startup/reset/prefix, deadline equality,
  late feed, overflow, monotonic failed-state time and scratch/output canaries.
- `core.pipeline`: exact main core/L/R bytes through real library objects, plus
  corrupted core CRC and valid envelope containing malformed core to preserve
  the separate framing/structure/integrity decisions.

Strict C11/C++ header-consumer Debug and Release builds emitted zero warnings;
CTest passed **10/10 in each configuration**. The tests-off C-only archive builds
without Python/Node/C++ test dependencies. `nm` shows own library references and
`memcpy`, with no allocator, SDK, transport or crypto dependency.

Exact source/configuration/tool/log hashes and command outcomes are in
[checks.json](checks.json). Final logs are
[Debug](ctest-accepted-codec-framing.log),
[Release](ctest-accepted-codec-framing-release.log) and
[archive symbols](library-symbols.log). Intermediate failures are retained:
`regression-before-fix.log` reproduces the missing encoder SEQ check;
`ctest-fixed.log` records a new test's mistaken MALFORMED expectation for an
invalid supplied trailer length, corrected to the API's INVALID_ARGUMENT.

RBO returned no live agents, so the announced fallback ran locally on Windows
with GCC 15.2.0, CMake 3.28.1 and Ninja 1.11.1. The sandbox compiler probe limitation
was handled by ordinary local elevated execution, without forcing compiler checks.
No physical or cross-platform execution is inferred.

## Remaining gates

The 137-case ledger now has **23 passed primary codec/framing scopes and 10
partial primary scopes**. All 33 whole rows stay partial pending their peer,
interop or later primary gates; 104 rows remain not-run. The case-to-function
mapping lives in [the ledger](../../DMP_Normative_Cases.json), not a second table.

No AEAD, replay, endpoint acceptance, identity resolution, retry/reassembly or
relay state machine is implemented by these packages. Structural role OK is
not SEC-1 eligibility: protected-route TO_NODE/CONTEXT, nonzero advertised CID,
HELLO/control service handling, enabled modules and association policy remain
P09/P13/P14/P17 obligations. Cipher descriptor recognition is not provider support.
Manifest-derived framing deadlines still need P07/P08 scheduling integration;
reset recovery within the original retry budget needs P10. No S10 row is passed.
P08 sanitizer/fuzz, two-host and embedded compile gates remain unexecuted.

Recommended next: P07 deterministic clock/event/transport harness and an
independent bounded P01B real-library provider adapter assignment. No MCU run is
needed to accept this codec/framing scope; later integrated qualification must
reuse these same library sources.
