# P12 and P25 completion plan — 2026-10-12

## Goal and boundary

Close the remaining software and host/simulation evidence before the final
hardware qualification. Hardware evidence is deferred to the end by owner
direction; it remains pending and is not inferred from host memory estimates or
provider-only MCU measurements. No production-readiness claim is made before
P01C.

The current workboard still lists P12 as running, while P23 and P24 are accepted
for their enabled host/simulation scopes. P25 depends on P24 and full P01. P01C
will remain the final hardware gate; this plan does not waive its acceptance
criteria.

## Milestones

1. **Reconcile P12 evidence.** Audit all 34 normative rows that include P12 as
   an owner. Map existing primary C tests, secured P15 tests, and P23 C/Python
   interop separately. A P23 `not-applicable` result is not a pass for the
   underlying application or primary endpoint requirement. Do not rerun an
   already accepted scope without a concrete gap.
2. **Close confirmed host gaps.** Based on the current P12 log, specifically
   resolve separate SAMPLE-1 lost-result/lost-receipt cases and the shared-
   association close behavior during a producer epoch transition. Reuse the
   existing rotation, cancellation, and unknown-outcome rules where they meet
   the application contract. Preserve durable epoch reservation and fail-closed
   behavior; do not invent an in-memory substitute for persistence.
3. **Reconcile provider-only prerequisites.** Match the P01 provider rows
   against P13/P15 and current primary tests. Implement or record only the
   remaining host gaps (wrong-PSK, post-read abort/pin/payload checks, cached
   flight ownership, same-owner serialization, secret-copy cleanup, and
   restart-budget behavior). Keep target runtime, hardware entropy quality,
   aggregate target resources, and energy measurements pending for P01C.
4. **Complete P25 host/simulation report.** Summarize accepted package evidence,
   exact manifest identities, reproducible commands, host benchmark outputs,
   the P21 provenance limitation, and all items deferred to P01C. P25 cannot be
   marked fully complete or release-ready until P01C passes.
5. **Final hardware qualification.** After the software report is stable, run
   the owner-approved target/resource scenarios, close the C3 reset evidence
   using an available diagnostic channel without changing eFuses, qualify the
   selected non-Espressif target, and complete the required resource/entropy
   measurements. Then close P01C/P01 and finish the P25 release assessment.

## Progress on 2026-10-12

- Implemented reliable DATA cancellation on association close/revoke with the
  contract's `DATA_LOCAL_UNSENT` / `DATA_UNKNOWN` outcomes. Added protected
  rotation regression plus reliability-unit coverage; the protected rotation
  test has not run because the security-enabled CMake integrity check could not
  read the Noise submodule Git metadata.
- Added separate plaintext SAMPLE-1 result-loss and receipt-loss tests. The
  primary endpoint test source compiled, but the test executable could not link
  in a provider-free configuration; these cases remain unverified.
- A clean tests-off CMake build compiled `libdmp` with GCC 15.2.0, and
  `reliability.direct` passed 1/1 in a separate no-provider build. Strict
  syntax-only compilation passed for the changed endpoint, reliability and
  protected-endpoint C sources.
- P12 remains running. Durable epoch reservation/fail-stop still has no
  production persistence port. P01C and final P25 remain pending until the
  deferred target phase.

## Progress on 2026-10-13

- Added SEC-1 endpoint regressions for a lost protected READ result and a lost
  protected result receipt. They are registered as
  `endpoint.protected_result_loss` and `endpoint.protected_receipt_loss`.
- Strict syntax-only compilation passed for the new cases. They remain
  unexecuted until the pinned-provider CMake revision check can run.

## Progress on 2026-10-13 — host recheck

- Corrected the Noise submodule Git-pointer handling in the security test
  CMake check and built `dmp_test_endpoint_sec`, `dmp_test_endpoint`, and
  `dmp_test_reliability` with the configured host build.
- Focused CTest passed 40/40: all 36 endpoint tests, plus direct reliability,
  reassembly, provider-adapter, and handshake tests. This includes the new
  protected result-loss, receipt-loss, and malformed SAMPLE-1 request cases.
- The complete independent-peer Python suite passed 410 tests; 51 tests were
  skipped by their existing conditions. The P12 normative-case ledger still
  needs row-by-row reconciliation; this suite result does not close untested
  rows by implication. The ledger now records `s-a1-invalid` and
  `s-a1-size-order` against the primary protected endpoint and independent-peer
  tests; the all-requirement audit remains open.
- P12 remains running. Durable producer epoch reservation is exercised with a
  host test persistence port, but the repository has no platform storage
  adapter. A successful host port test does not prove durable storage on a
  target. P01C and final P25 acceptance remain deferred until the final
  hardware phase.

## Progress on 2026-10-13 — retained rejection replay review

- Closed the reviewed edge case where a retained unfragmented invalid REQ,
  retried as complete fragments with the same identity, replayed its ERR and
  also emitted `ASSEMBLED`. Reliability now reports retained rejection state;
  the endpoint replays the ERR and suppresses delivery of that rejected body.
- Added `endpoint.protected_retained_rejection_reassembly`; it checks the
  retained STATUS=7 replay, unchanged validator count, zero application
  accepts, and zero ASSEMBLED events. The security-enabled host build passed,
  and the focused integration CTest suite passed 43/43. Independent read-only
  review found no actionable issue in this fix.
- This closes one P12 host edge case. The 34-row normative mapping and
  platform-backed durable epoch storage remain open. No hardware or MCU claim
  follows from the passing host tests; P01C and final P25 acceptance remain
  deferred to the final hardware phase.

## Progress on 2026-10-13 — P01 host lifecycle regressions

- Added a combined authenticated invalid-payload restart case: generation
  invalidation and secret cleanup, late authentic continuation refusal, exact
  restart backoff, and a fresh attempt with new ID/ephemeral key while episode
  and global counters continue. Kept low-order-DH rejection as a separate case.
- Added a same-identity conflicting processed Flight 1 case. It must be a
  bounded drop that leaves the accepted candidate, deadline, cached response,
  and Noise read/write state intact; a following exact duplicate still replays
  the cached response.
- Host build of `dmp_test_handshake` and `security.handshake` CTest passed.
  Independent review of both regressions found no remaining actionable issue,
  including the fixed-length cache comparisons and deadline checks after time
  advances.
- P01 remains open for requirement mapping, secret-copy inventory, cached-flight
  transport/lifetime cases, aggregate resources, integrated target peaks, and
  P01C/final hardware checks. RAM estimates remain host/measurement evidence,
  not proof of target operation.

## Current evidence to reuse

- P12 plaintext endpoint history: `dev/DMP_Execution_Log.md`, entries dated
  2026-10-04; the recorded scoped endpoint suite passed 17/17, but P12 was not
  accepted and the log explicitly leaves loss variants and shared-association
  behavior to reconcile.
- P15 real SEC-1 endpoint tests and P23 C/Python interop are distinct evidence
  scopes. Keep their exact test IDs and results in the case ledger.
- P23 accepted 53 applicable interoperability rows; its 84 out-of-slice rows
  retain their own whole-row status.
- P24 accepted its one-iteration host/simulation matrix and benchmark tooling.
  Host RSS/CPU and virtual schedule time are diagnostics, not MCU or physical
  measurements.

## Acceptance for the deferred-hardware sequence

- P12 has no unresolved software requirement represented as passed; every
  remaining partial/not-run row has an exact owner, reason, and next gate.
- Host/secured endpoint behavior is mapped to actual tests and recorded output.
- P25 reports host/simulation readiness separately from target readiness.
- P01C/P01 and final P25 remain pending until the final hardware phase passes.
