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

## Progress on 2026-10-13 — P12 row-by-row host reconciliation

- Audited all 34 normative rows with P12 in `primary_gate`. Each now names
  the primary C checks, the corresponding independent P21 peer check, and the
  evidence-log anchor. P23 interop fields remain a separate axis;
  `not-applicable` is not treated as a pass.
- Re-ran the security-enabled focused host CTest filter: 43/43 passed (39
  endpoint cases plus reliability, reassembly, provider adapter and handshake).
  The independent peer suite's prior 410 passed / 51 skipped result remains
  the evidence for the mapped P21 cases.
- Eight rows now have all recorded applicable evidence and are `passed`; 26
  remain `partial` with a concrete `primary_remaining`. The partials include
  missing primary C golden packet assertions for v2.2.4/v2.2.9, incomplete
  status/service-case mapping, protected initialization/stale-result variants,
  manifest-derived initialization timing, and SAMPLE-1 epoch lifecycle gaps.
- The audit found a concrete host-model gap: `publish_sample` stops permanently
  at `UINT32_MAX`; SAMPLE-1 requires reserving a new epoch after index
  exhaustion. It also found no path that couples that transition to closing all
  old-epoch associations. The endpoint's generic protected rotation test covers
  the shared service-2 unknown outcome, but does not exercise a SAMPLE-1 epoch
  transition. This identified the next host item; the following progress entry
  records the host-model correction and its remaining adapter boundary.
- P12 remains running. Epoch persistence is still only a deterministic test port;
  no production storage adapter exists. These host gaps are separate from the
  deferred hardware phase. P01C and final P25 remain pending.

## Progress on 2026-10-13 — SAMPLE-1 index-exhaustion rollover

- Corrected the host SAMPLE-1 producer model: startup after source-state loss
  and `UINT32_MAX` exhaustion both reserve a distinct epoch. The model requires
  old-association closure before publishing the new epoch at index 1. Failed
  reservation or closure stops publication; a reserved epoch is not reused.
- Updated `endpoint.sample_epoch_restart` and added
  `endpoint.sample_epoch_index_exhaustion` for restart/rollover and fail-closed
  closure failure. The focused security-enabled CTest filter passed 44/44.
- The callback remains a test seam: it does not implement platform storage or
  enumerate/close real application associations. P12 remains open until those
  application-level transitions and persistence are backed by production
  adapters; hardware qualification remains deferred to the final phase.

## Progress on 2026-10-13 — primary C golden-vector assertions

- Added primary C coverage for exact §22.4 reverse-order fragment bytes and
  the §22.9 immediate RSP/result ACK bytes with complete full-form REPLY_TO
  extensions. The vectors now pass through the primary C codec/reassembly
  implementations; P23 `not-applicable` and independent P21 evidence remain
  separate.
- The ledger moves from 8/34 to 11/34 rows passed; 23 remain partial with
  explicit primary gaps. `core.codec` and `reassembly.direct` passed 2/2 after
  the additions. A combined focused run is recorded in the execution log.
- This closes two byte-level host gaps only. SAMPLE-1 durable epoch storage,
  endpoint-wide association closure, remaining application/status cases, and
  other primary evidence gaps still keep P12 open. P01C and final P25 target
  qualification remain deferred; host vectors do not establish MCU behavior.

## Progress on 2026-10-13 — protected SAMPLE-1 NO_SAMPLE

- Added a primary SEC-1 endpoint exchange for terminal NO_SAMPLE: the request
  returns protected ERR STATUS=64 with no payload, its receipt is returned, and
  the next READ uses a distinct request handle and receives the result.
- SAMPLE-1 A1 delivery and A4 NO_SAMPLE/new-READ now pass in the ledger. A2
  remains partial for manifest-derived timeout and protected initialization
  exhaustion. The overall P12 ledger is 13 passed / 21 partial of 34.
- The combined focused host CTest filter passed 46/46. This extends the host
  endpoint evidence only; epoch persistence, association transition, other
  software gaps, P01C, and final P25 target qualification remain open.

## Progress on 2026-10-13 — SEC-1 ERR status classes

- Added a protected endpoint regression for all reserved STATUS values 8–63.
  Each authenticated frame is rejected as unsupported without producing a
  result; the same live READ then accepts a reliable terminal application
  ERR=64 and returns its receipt. Existing codec coverage checks the
  protocol-rejection ACK_REQ prohibition.
- The primary/peer protocol-status row is now passed, and the P12 ledger is
  14 passed / 20 partial of 34. The separate rejection/timeout row retains
  explicit gaps for individual protocol status causes and correlation
  exhaustion.
- The dedicated host test passed 1/1. Target, runtime, physical transport,
  hardware, and final P01C/P25 qualification remain deferred.

## Progress on 2026-10-13 — manifest-derived SAMPLE-1 timing

- The endpoint test target now reads SAMPLE-1 attempts, retry interval,
  initialization deadline, and NO_SAMPLE status directly from the active
  direct NNpsk0 manifest during CMake configuration and reconfigures when that
  file changes. The manifest/schema remain unchanged.
- The timeout test now uses the manifest's 12000 ms deadline, verifies that a
  completion after the request's terminal timeout is stale, and confirms no
  sample is accepted. `endpoint.sample_init_budget` passed 1/1.
- Manifest-derived timing gaps are closed for plaintext host initialization.
  Protected primary initialization behavior remains open; no target or
  hardware evidence was produced.

## Progress on 2026-10-13 — rejection statuses and correlation exhaustion

- Primary C now checks every protocol ERR STATUS 1–7 with ACK_REQ and exercises
  correlation-table exhaustion while a separate sender slot and service are
  available. The failed admission leaves the first request and its deadline
  unchanged.
- The §22.8 rejection/timeout row is passed across the available primary and
  peer host evidence. The P12 ledger is 15 passed / 19 partial of 34.
- `core.codec` and `reliability.direct` passed 2/2 after the additions.
  These are host checks; target/runtime, physical transport, and final hardware
  qualification remain deferred.

## Progress on 2026-10-13 — protected SAMPLE-1 initialization and ordering

- Added a protected host endpoint scenario for early telemetry discard,
  current READ-handle correlation, initialization from the READ result, and an
  older same-epoch READ snapshot arriving after newer telemetry. The primary
  first-boot, early-telemetry, and old-snapshot rows now pass.
- The P12 ledger is 18 passed / 16 partial of 34. Protected epoch-switch,
  prior-association, concurrent-update, and manifest-timed initialization
  retry/deadline cases remain open.
- The new SEC-1 endpoint test passed 1/1 and the combined focused host CTest
  filter passed 48/48. It proves software behavior in the host harness only;
  target/runtime and final hardware qualification remain deferred.

## Progress on 2026-10-13 — protected SAMPLE-1 negative shapes

- The protected endpoint now checks wrong-service result correlation, a
  correlated READ RSP with a non-READ STATUS payload, and 15/17-byte TELEM
  payload rejection at the SAMPLE-1 application boundary. Existing SEC-1
  request tests cover malformed READ shapes.
- The A3 negative row remains partial because its primary single-peer profile
  cannot exercise a second authenticated sender/association. The new test
  passed 1/1 and the combined focused CTest filter passed 49/49; this does not
  provide target or hardware evidence.

## 2026-10-13 update — protected initialization deadline

- Added `endpoint.protected_sample_init_timeout`, deriving attempts, retry,
  initialization deadline, and result deadline from the active DIRECT-1
  manifest. The authenticated READ receives no app result; at 12000 ms the
  consumer reports one UNKNOWN and remains unsynchronized, and a late producer
  completion is rejected as stale.
- Promoted `s-a2-no-sample` and `s-a4-timeout`; `s-a2-designated-read` stays
  partial for protected retry scheduling, cancellation, and supersession.
  The ledger now has 20 passed / 14 partial rows out of 34.
- Endpoint SEC-1 target rebuilt successfully (no work pending); the focused
  host CTest filter passed 50/50. MCU resource fit and physical behavior remain
  deferred to final hardware qualification.

## 2026-10-13 update — protected loss and SAMPLE-1 epoch transition

- SEC-1 READ-loss, RSP-loss, and receipt-loss cases now assert SAMPLE-1 state
  changes only once and only after the correlated result arrives.
- Added a local abandon operation for an app-held READ after its association
  closes or expires. The protected epoch-transition case verifies active and
  draining work cannot be abandoned early, a late old result is rejected, the
  unrelated service-2 transfer settles as DATA_UNKNOWN, and a new READ starts
  synchronization on the new epoch after pre-sync telemetry is discarded.
- Promoted `s-a4-close-shared`; the ledger now stands at 21 passed / 13 partial
  out of 34. The focused host CTest filter passed 50/50. Persistent target
  storage and final hardware qualification remain open.

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

## 2026-10-13 — protected stale-sample reconciliation

- Reconciled the remaining protected cases for `main228-sample-stale` against
  the existing SEC-1 endpoint tests: older same-epoch READ result after newer
  telemetry (`test_protected_sample_initialization`), old-association result
  rejection and initialization of the new epoch (`test_rotation`), and the
  three request/result/receipt-loss paths without a duplicate SAMPLE-1 state
  transition (`test_loss`, `test_result_loss`, `test_receipt_loss`).
- The focused command rebuilt the provider, handshake, and protected-endpoint
  targets and passed all seven selected CTests. The ledger now has 22 passed /
  12 partial primary rows among its 34 P12 rows. This is host/SEC-1 evidence;
  durable target storage and physical qualification remain open.
- The most recent full CTest attempt did not finish: the subprocess harness
  initially hit sandbox TEMP access errors, and the process-isolated
  `memory.test-direct-minimal-128.endpoint_lifecycle` case could not connect
  over host loopback and timed out. Re-running `harness.subprocess` with TEMP
  and TMP under `build/host/ctest-tmp` passed 1/1. The full CTest suite is not
  claimed green; this host IPC limitation is separate from physical hardware.
- Continued P01 host reconciliation with `security.handshake::cleanup-erases-owner`:
  after scheduling NNpsk0/PSK and XX/local-static attempts, it asserts each
  complete `dmp_hs` object is zeroed by cleanup and the provider allocator
  releases only zeroed blocks.
  `security.handshake` passed 1/1. The copy/lifecycle map is recorded in
  `dev/evidence/noise-mcu-soak-20260927/p01-reconciliation.md`; target resource
  aggregation, cached-flight transport lifetime, non-Espressif runtime, C3
  reset diagnostics, and final hardware qualification remain open.
- Added a protected late-result test across an association rotation with a
  30-second drain. A result correlated to the old READ arrives under epoch 41
  after the application has selected epoch 42/index 1; its protected receipt
  is routed on the old CID, the old result cache is acknowledged, and the new
  sample cache is unchanged. One targeted CTest passed. This narrows, but does
  not close, the P12 rows for protected superseded-designation results and
  atomic concurrent result/association updates.

## 2026-10-13 update — protected SAMPLE-1 designation supersession

- Added `endpoint.protected_sample_superseded`: a protected READ remains
  correlated by the endpoint after the application invalidates its full-handle
  designation. The stale result is delivered and ACKed but cannot initialize
  the SAMPLE-1 cache; a subsequent designated READ can initialize it.
- The P12 `s-a2-designated-read` row remains partial because the active
  DIRECT-1 manifest allows exactly one initialization attempt, so host
  protected retry scheduling is not exercised. Its protected timeout and
  designation-supersession coverage is now explicit in the ledger.
- Promoted `s-a4-late-result` to passed across primary and peer evidence; P12
  and `s-a2-unsync` to passed across primary and peer evidence; P12 now has
  24 passed / 10 partial primary rows of 34. The latter reuses the protected
  rotation test's prior-cache invalidation, pre-sync telemetry discard, and
  new-epoch READ assertions.
- This is host/SEC-1 evidence. Target memory fit and physical behavior remain
  deferred to the final hardware phase; acceptable host estimates are not
  hardware qualification.
- 2026-10-13 follow-up: added protected service-2 immediate-result and
  unsupported-service rejection coverage, promoting `main228-immediate-rule`.
  The P12 primary ledger is now 25 passed / 9 partial of 34. Hardware testing
  remains the final phase; RAM estimates are planning evidence, not proof of
  physical operation.
- 2026-10-13 follow-up: added a P01 host regression for cached-flight retry
  count, byte stability, unchanged attempt deadline, and expiry invalidation.
  `security.handshake` passed 1/1. Adapter send-fault injection, aggregate
  resources, target runtime, and final physical qualification remain open.

- 2026-10-13: consolidated the accepted host/simulation packages and open
  gates in `DMP_P25_Host_Simulation_Report.md`. P25 remains pending until the
  software gates and final P01C target/hardware qualification are complete.
- 2026-10-13 follow-up: corrected protected same-epoch reconnect evidence and
  added an optional RSP schema validator that runs after authentication and
  reassembly but before reliability acceptance/receipt. Added valid and
  malformed fragmented-result cases, plus unfragmented result and TELEM shape
  regressions. The focused P12 endpoint selection passed 7/7; independent
  review found no remaining source issue. The primary ledger remains 25 passed
  / 9 partial, with the wrong-authenticated-sender variant and production
  persistence/serialization boundaries still open. The validator adds one
  callback pointer to endpoint storage/object; target RAM is not measured.
- 2026-10-13 follow-up: P01's `remote_public` wipe exception and cached
  AWAITING-flight byte-ownership regressions passed focused build/CTest 2/2 and
  independent review. P01 remains open for other provider/adapter and P01C
  target requirements. Hardware checks stay deferred to milestone 5; host
  memory figures do not guarantee hardware operation.
