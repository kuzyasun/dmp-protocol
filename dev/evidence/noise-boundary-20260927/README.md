# BOUNDARY-01 bounded provider receive / abort / restart laboratory

Status: unvalidated draft; not registered in the build. P01 remains running,
P02 pending. The owner challenged further laboratory state-machine duplication
before the first build. Coordinator stopped extending this draft to reassess
the transition to reusable library code; no BOUNDARY-01 check has passed.
Preserve the draft for review, not as accepted protocol implementation. The owner
approved the [implementation transition](../implementation-transition-20260927/README.md):
port useful fault inputs/expectations into tests linked to actual P01B/P13
library code; do not continue this separate owner/scheduler implementation.

Frozen scope: private host driver around actual accepted Noise NNpsk0/XX
ChaChaPoly states, checked backend and bounded allocator. No fork/primitives,
normative, firmware, production endpoint or public API changes. Reuse accepted
fixture expectations and ownership hooks; this driver is not a DMP parser.

Close wrong-PSK cryptographic failure, XX pinned-static rejection, authenticated
zero CID, pre-read length/selector mismatch and processed-flight conflicts.
Read, mandatory payload/pin checks and acceptance form one synchronous owner
boundary; no next-flight write before checks pass. Terminal abort invalidates
the generation, destroys only the private state, wipes owned scratch/cache and
cannot auto-restart. Late continuation uses an old generation and cannot call
Noise or commit, including after a new attempt occupies the owner slot.

Use an explicit laboratory scheduler with finite attempt count, absolute
episode/attempt deadlines, work/traffic ceilings, global charges and fixed
restart backoff. Failure never refunds those counters. Deterministic injected
time; no wall-clock sleeps as protocol time. Explicit fresh attempts change
ATTEMPT_ID/prologue and ephemeral fixture material; deterministic public keys
are test-only, not entropy-quality evidence. Verify original generation-zero
flights and final hash against the independent fixture before fault cases.

Test malformed public length before Noise separately from an authenticated
zero-CID payload of the correct length. Wrong pin is a real comparison to the
provider's remote static key, not an injected success/failure Boolean.
The wire framing/outer context is a bounded supplied selector test seam;
full DMP parsing/reassembly/identity and P13/P14 lifecycle remain pending.

Same-owner threaded duplicates, full cached-TX completion/cancel lifetime,
full secret-copy inventory, aggregate resource sensitivity, non-Espressif
runtime and complete P01 acceptance remain outside this wave. Sequential
duplicate classification may be checked without claiming threaded safety.

Coordinator owns state machine/security decisions, probe, build registration,
status and final acceptance. A bounded worker owns only `boundary/peer.c`,
implementing setup and independent fixture helpers to the frozen `peer.h`.
Independent source/evidence review follows a fixed snapshot. Preserve existing
dirty files and Git index; no commit/push or hardware operations are needed.
