# P07 deterministic transport harness assignment

Status: prepared under owner authorization. First worker turn timed out before
making repository changes; P07 remains ready. No implementation or acceptance
is claimed by this brief.

Repository: `C:/projects/gemslibe/dmp-protocol`.
Baseline: clean `feat/initial-version`, HEAD `ae7e06e133b92dcec818bd2006875bbf43d39956`;
Noise gitlink and clean submodule HEAD `c40f2dca78eee064e521233a5d884853d471028a`.
Original sealed checkout: `snap-cf9ec66130257c9804abbaab`, source digest
`adebce0d99e8e643eae35d9b96155a5f756dce1f95084ad8416e465de299fb96`.
An author's initial snapshot, returned by session spawn after this preparation,
will be the review baseline; the final target will be separately sealed.

## Scope and ownership

Implement P07 after accepted P04. P05/P06 already implement the codec/framing;
do not repeat those packages. One bounded implementation worker uses the
owner-selected complex-task route `dmp_cursor_large`, live `grok-4.7-high` /
`high`, `dmp-worker`, current workspace. Its `prefer/2` native delegation is
advisory; keep this tightly integrated package with one implementation owner.

Exclusive worker write set: new files below `tests/harness/` except its existing
`PROTOCOL.md`; root `CMakeLists.txt` is explicitly transferred only for harness
test/build registration. The coordinator does not edit these files while the
worker is active. Shared headers, library sources, manifests/schema, dependencies,
normative docs and status/evidence remain coordinator-owned. Propose any needed
change outside the write set; do not make it.

Read `AGENTS.md`, `dev/DMP_Core_Interfaces.md`, `include/dmp/base.h`,
`include/dmp/transport.h`, `tests/harness/PROTOCOL.md`, the P07 acceptance row,
`docs/DMP_Test_Manifest_Contract.md`, `profiles/schema/manifest-v1.schema.json`,
`tools/validate_profile.py`, the existing profile corpus and six deployment
manifests. Use existing CMake/test patterns. P07's frozen subprocess v1 is the
acceptance contract; do not silently relax or version it.

## Required outcome

Create a C host harness linked to the real `dmp::dmp` archive, reusable bounded
clock/queue/opaque transport seams and dedicated self-tests. Implement the v1
CLI, bounded strict scenario JSON, executable manifest validation and exact-byte
SHA256 agreement, deterministic event ordering, xorshift32 loss, explicit
drop/reorder/duplicate, pair calendar/forward/return slots, generation-tagged
copy/borrow transport ownership, inline and delayed completion, cancellation,
horizon settlement and redacted canonical JSONL traces. It must contain no
DMP endpoint/parser/reliability/security state-machine substitute and no
wall-clock protocol inputs. Do not add a dependency.

Manifest validation must enforce the existing selected manifest contract and
cross-field rules at the executable boundary, using the existing valid/invalid
corpus for parity. A separately run Python validator alone is not acceptance.
If the current frozen contract has a concrete contradiction, report it before
inventing behavior. Test-tool memory is bounded; do not infer MCU core budgets.

## Acceptance and handoff

Add meaningful C port tests and subprocess corpus tests (Python may only drive
the C executable and check outcomes/traces). Cover repeatability and independent
expected scheduling/loss values; same-time arrivals/completion/action/start ties;
rejection without callbacks or RNG draws; inline callback-before-return;
cancel before/at/after start; stale/reused generations; queue/capacity/deadline
refusal; reverse references and slots; delayed completion and arrival ownership;
horizon cleanup and both pending counters; unused fault ordinals; malformed,
duplicate/unknown-field, float/BOM/UTF8 and CLI cases; all hard budgets and output
failure; manifest corpus/digest parity; absence of confidential bytes in traces.

Register the new checks under a `harness` CTest label and use strict warning
options. Host Debug/Release and tests-off archive checks will be required before
acceptance; P08 sanitizer/fuzz/cross-host/embedded gates remain separate.

RBO initially returned `fetch failed`; after the owner started it, discovery
returned one idle macOS/arm64 worker. Use RBO with `target_os=macos` and bash
for host build/test. The owner explicitly authorized local host builds when
RBO has problems or fuller logs are needed. Record actual execution and failures.
Do not stage, commit, push, publish, install dependencies or operate hardware.
Return changed files, exact commands/results (distinguish unrun), requirement
coverage, limits/open issues and a concrete source diff. Success is execution,
not acceptance. Deadline: one bounded broker turn, up to the broker hard limit.

Reviewer route selected by the owner: `dmp_cursor_reviewer`, exact model
`grok-4.7-xhigh`, effort override null. Complex-task route:
`dmp_cursor_large`, exact model `grok-4.7-high`, effort `high`.
No automatic escalation or provider substitution. The initial
`dmp_cursor_worker` turn `turn-ed50161de3bedec44b3255e9` exceeded its 900000 ms
deadline without a handoff or file changes. Broker result was TIMED_OUT and
usage unknown. After owner-confirmed Cursor recovery, a fresh live READY and
fully paginated discovery passed at configuration revision 8. The implementation
continues on this owner-approved complex-task route with a new session/turn.
See `broker-blocker.md` for the earlier pre-inference failure.
