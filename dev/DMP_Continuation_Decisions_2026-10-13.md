# DMP continuation decisions — 2026-10-13

## Authority and scope

This is an operator decision record and a continuation plan, not a
conformance result. Repository artifacts are in English; the operator discussion
is in Ukrainian. Only entries explicitly marked **accepted** are owner decisions.
The owner accepted D1, D2, D4 and D6 and the D5 target-scope disposition in this
chat; D3 is an acceptance consequence of the approved multi-peer scope. These
decisions unblock implementation by the continuing agent within that scope.
No implementation, manifest revision, staging, commit, or hardware operation was
performed for this analysis.

## Superseding owner decision — one manifest format 1.0 (2026-10-14)

The owner clarified that DMP has no released manifest consumers and is still
developing its first version. Use exactly one manifest format, identified as
`DMP-test-manifest/1.0`. Remove the development-only format 2/3/4 schemas and
dispatch paths. Keep the current binding and multi-peer fields in this one
schema, with profile-specific validation. Do not preserve old manifest bytes,
hashes or parsing behavior for backward compatibility. Recompute exact manifest
digests and rerun the affected profile, peer and host checks.

This supersedes earlier notes in this record and the P22 plan that kept contract
2 unchanged while adding contracts 3 and 4. Profile-family revisions and
protocol component revisions remain contract identifiers required by the DMP
specification; they are not alternate manifest-format compatibility paths.

Inspected baseline: branch `feat/initial-version`, HEAD
`959a54f4fbc7cf00d72b28864c406ac5c9da5319`. The parent worktree was clean with
`git status --short --ignore-submodules=all`. Submodule Git metadata was not
accessible, so submodule cleanliness/revision was not independently verified.
Builds and tests were not rerun; historical results below are recorded evidence.

## Current state verified from the checkout

- The work board accepts P13–P24 for their individual recorded scopes, including
  P21 with its explicit historical provenance limitation and P23 host/simulation
  interoperability. This is not whole-product or target acceptance.
- P12 is running: 28 passed and 6 partial among its 34 normative rows. P01 is
  running; P01C and final P25 acceptance remain open.
- `src/reliability/reliability.c::validate_storage` rejects `peers != 1`.
  `include/dmp/endpoint.h` stores one active and one draining association.
  The limitation is in the actual implementation, not just the test harness.
- The provider experiment's `four_parallel` counts apply to ONE endpoint:
  four peers, four active and four draining associations, four pending attempts,
  two crypto slots, two services and four application operations. Separate
  single-peer endpoints do not meet that accounting contract. `four_serial`
  is also part of the declared sensitivity matrix and must not be forgotten.
- DIRECT-1's current SAMPLE-1 policy permits one initialization READ attempt.
  The validator requires `init_deadline_ms >= attempts * result_deadline_ms +
  (attempts - 1) * init_retry_ms`.
- `src/security/handshake.h` exposes cached-flight/lifecycle operations but no
  `dmp_transport` submission/completion path. Data-endpoint transport tests do
  not establish handshake send ownership and cancellation behavior.
- The C SAMPLE-1 implementation used for acceptance is application test code.
  Production durable epoch storage and the integrated epoch-transition owner
  are absent. SAMPLE-1 belongs outside the payload-agnostic core.
- The complete 137-row ledger currently records 77 passed, 37 partial and 23
  not-run. Some remaining descriptions still call accepted modules unimplemented.
  This is a traceability inconsistency to reconcile, not proof that all those
  implementations are missing. P23 interoperability results are a separate axis.
- README's claim that this is not yet an endpoint library is stale relative to
  the current sources and work board; update the scope summary during closure.

## D1 — Multiple peers in the first completed version

**Accepted by the owner in this chat:** “Кілька peers: до 4 на endpoint”.

The first completed version must support up to four authenticated peers on one
endpoint. Single-peer behavior is an intermediate implementation, not the final
scope. Retain configurable bounded admission, including the one-peer case; do
not require every deployment to allocate four peers unconditionally.

Expand the endpoint/reliability design and integrated resource accounting.
Use one logical endpoint and explicit peer/association ownership; internal
reuse of per-peer engines is possible only with shared admission/accounting and
correct endpoint-wide lifecycle semantics. Four independent devices are not an
equivalent test. Do not claim four peers implies four simultaneous crypto calls:
the declared `four_parallel` row has two crypto slots.

Acceptance must include peer isolation, active/draining replacement, pending
attempt quotas, cross-peer reply rejection, bounded control progress under
pressure, complete message exchange and aggregate storage accounting. Preserve
the declared sensitivity scenarios; overrunning an experimental envelope is an
infeasible combination, not permission to silently enlarge that envelope.

## D2 — Protected SAMPLE-1 initialization retry

**Accepted by the owner:** retain existing DIRECT-1 manifests and add a separately identified
test manifest with two initialization attempts and its own exact-byte hash.
This exercises the existing retry contract without silently changing deployment
policy. Explicitly support the test family in schema/validators/adapters and
record its identity in the case ledger and peer inputs as applicable.

With the current 12,000 ms result deadline and 5 ms retry interval, two attempts
require at least 24,005 ms overall. Validate all dependent timing/resource rules;
the formula is a lower bound, not a substitute for that validation. Prove a new
designated request identity, supersession of the old designation, rejection of
late old results, bounded attempts and the unchanged absolute deadline over real
SEC-1. A retransmission of one reliable READ is not a second initialization READ.

## D3 — Wrong authenticated sender

**Acceptance consequence of accepted D1:** add a multi-peer scenario in which an
authenticated peer other than the configured SAMPLE-1 producer supplies a
well-formed sample or correlated-looking result. It must not synchronize the
consumer, replace its cache, or complete the designated producer READ. Follow
with the intended producer's valid response to prove its state remains usable.

Use actual SEC-1 associations, not a forged payload identity or merely a bad MAC.
Retain the existing old/draining-association negative case as a distinct check.
The exact multi-peer manifest/schema/API design is still to be prepared and
reviewed; the existing two-endpoint manifest contract cannot just be relabeled.

## D4 — Handshake transport integration

**Accepted by the owner:** finish a bounded production integration layer before the final
software gate. It may wrap the existing handshake state machine; do not put
transport-specific behavior into cryptographic primitives or duplicate Noise.
Freeze the minimal ownership/completion contract before implementation.

Exercise pre-accept BUSY/rejection, accepted delayed completion, uncertain send,
cancel/disconnect/expiry, stale completions and buffer reuse. Respect COPY/BORROW,
exactly-once completion and generation fences from `include/dmp/transport.h`.
Cached handshake retransmission must preserve the established bytes and budgets;
it must not rerun Noise write or restart the absolute deadline. Qualify the
composition through real libdmp sources and existing simulated transports now;
physical binding evidence remains a final-stage item.

## D5 — Final target selection and physical qualification

**Already accepted:** hardware qualification stays at the end of the plan.
**Accepted target families:** ESP32-S3 and several ESP32-C3 boards, as stated by
the owner. Exact board/module models, memory configurations and board counts
remain to be recorded before the final hardware phase.

**Accepted deferral:** physical qualification on a non-Espressif MCU moves to a
future stage. Keep that requirement and its existing Cortex-M4 archive/ABI
evidence in the plan as deferred, not passed or deleted. It no longer blocks
first-version P01/P25 acceptance for the explicitly qualified S3/C3 scope.
Do not advertise non-Espressif runtime support. Existing portable-core and
non-Espressif cross-compile checks remain; only physical qualification is deferred.

Record each selected target's linker map, memory regions, entropy, monotonic
clock, storage and transport ports before target implementation/qualification.
Qualify the same library and admitted resource scenarios on S3 and C3; several
C3 boards do not substitute for four peers within one endpoint or prove all C3
board variants. Keep C3 reset diagnostics and all remaining storage, entropy,
resource and lifecycle acceptance criteria. Board details do not block portable
host work. This record authorizes no flashing, provisioning or eFuse changes.
Target limits cannot be inferred from host allocator measurements.

## D6 — SAMPLE-1 epoch owner and persistence

**Accepted by the owner:** include a reusable application-side transition owner in the
software completion scope. Keep it outside libdmp's payload-agnostic core.
Use explicit storage and association lifecycle ports, and test the same owner
with injected storage failures and real endpoint lifecycle actions on the host.

It must reserve/commit a never-reused epoch, close all old-epoch associations,
serialize READ snapshots/publication/activation, and fail closed on storage or
closure uncertainty, including shared-service unknown outcomes. Test callbacks
alone must not stand in for the integrated owner. The selected target's actual
durable storage adapter and crash/restart/rollback qualification remain required
before closing the persistence rows and final P01C/P25 gates.

## Implementation handoff

Continue the accepted software work below without asking again whether to
support four peers, add the two-attempt test profile, integrate handshake
transport, or implement the SAMPLE-1 transition owner. Freeze and review the
concrete interfaces as required by AGENTS.md; a new material choice outside
these decisions still requires owner direction. Keep P12/P01 open until their
checks pass; this record changes scope/authorization, not test outcomes.

## Recommended implementation order

1. Freeze bounded multi-peer contracts, manifest topology and resource accounting
   for D1. Explicitly distinguish decoded core MTU from binding encoded MTU;
   DIRECT-1 uses 256 versus 263 bytes, and experiment `mtu_bytes` needs a stated
   mapping. Resolve material contract choices before dependent implementation.
2. Implement the multi-peer endpoint and its isolation/resource tests, including
   D3 and both declared four-peer sensitivity rows.
3. Implement D4 and D6 as bounded integration packages using the resulting
   association ownership model. Add the D2 manifest and retry scenario.
4. Reconcile all 137 normative rows against concrete primary/peer/interop tests;
   record absent evidence without promoting passes by package status alone.
   Close the provider failure/secret-copy inventory with a finite requirement
   map rather than an open-ended sequence of unrelated wrapper tests.
5. Independently review the fixed security/lifecycle snapshot, run focused checks
   and then the required host gate, update README/P25 evidence and list remaining
   physical gates. Follow the live agent's authorized execution/model routes.
6. Record exact S3/C3 board configurations and qualify D5 targets at the
   scheduled final stage, then assess P01/P25 acceptance for that supported
   scope. Retain non-Espressif physical qualification as future work. No release
   or product adoption is authorized here.

## Evidence sources

- [Work board](DMP_Work_Packages.md)
- [P25 report](DMP_P25_Host_Simulation_Report.md)
- [P12/P25 completion plan](DMP_P12_P25_completion_plan_2026-10-12.md)
- [Normative case ledger](DMP_Normative_Cases.json)
- [P01 reconciliation](evidence/noise-mcu-soak-20260927/p01-reconciliation.md)
- [Experiment manifest](../tests/provider/experiment_manifest.json)
- [SAMPLE-1 contract](../docs/DMP_v2_Reference_Application.md)
- [Manifest contract](../docs/DMP_Test_Manifest_Contract.md)
