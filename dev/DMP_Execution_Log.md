# DMP execution log

**Current status (2026-09-26):** implementation paused by the owner; only review
verification and documentation corrections are authorized. P00 remains partial
and unaccepted. The confirmed target is ESP32-S3 / ESP-IDF 6.x, portable C core.

## 2026-09-25 — P00 initial baseline

Owner: coordinator (`/root`, current user-selected model). Implementation is
authorized through the dependency board, without staging, commits, publishing,
hardware operations, credential provisioning or DTrack adoption.

Initial HEAD: `afd460c24919b58296883c3b60b497149ad4366c`, branch
`feat/initial-version`. There was no standalone implementation. Seventeen files
had staged changes; `AGENTS.md` also had an unstaged workflow change. Preserve
both layers. Exact working-file SHA-256 hashes, index entries, index SHA-256 and
diff hashes are in [initial baseline](evidence/p00/initial-baseline.json).
Local ignored copies of both binary diffs are beside that file. No existing
source or normative document was overwritten.

Read main document revision 8, SEC-1 revision 3 / BOOT_VERSION 2, recovery
revision 1, deployment profiles, README, workflow and both implementation plans.
The JSON records the exact bytes of every existing tracked working file,
including all normative inputs and public fixtures.

Initial local tool discovery: Windows x86-64; CMake 3.28.1, Ninja 1.11.1,
GCC 15.2.0, Clang 21.1.0 (MSVC target), Node 24.11.1, Python 3.12.8.
Discovery is not a successful build. RBO has an idle macOS/arm64 agent; submitted
host capability probe `job_01M3CZ7ZFZJG054SYQSMWATSW5` using bash and an immutable
snapshot. Prefer that host for build verification.

Decisions: portable C11 host experiment scaffold; no production ABI or
target-dependent budgets frozen. `DMP_BUILD_TESTS` explicitly controls the
scaffold and existing fixture check. No provider is silently downloaded or
enabled. Initially the target was missing; the operator subsequently selected
ESP32-S3 / ESP-IDF 6.x with a portable C core before pausing implementation.

P00 checks and acceptance: pending actual scaffold runner results. Target selected;
no CMake build or P01 experiment was run before the owner paused implementation.
P01/provider acceptance and all endpoint/security conformance: not run.

## Completed narrow P22 plan review

`/root/p22_plan_review` (`gpt-6-luna`, xhigh) completed the read-only review of
the latest P22 mixed Stream R/packet clarification and P20/P23/S10 dependencies.
No material contradiction was found. The one wording improvement, MTU/context
failure checks in each direction, is now explicit in both plans. This closes
the interrupted narrow plan review, not P22 implementation.

## 2026-09-26 — Review verification while implementation is paused

The supplied independent review was checked claim by claim; conclusions and
corrections are in [review disposition](DMP_Review_Disposition.md). Normative
wire/crypto fixtures and implementation files were preserved. The corrected
R3 timing bound and other documented clarifications require refreshed source
hashes when work resumes; they do not accept any implementation package.

Existing fixture verification passed on RBO (`job_01M3CZHWR1J3873F5F8QV3QVA0`):
Node v24.18.0, exit 0, 4 fixtures, 64 packets, 44 mutations. This is fixture
evidence only. Calculations/link checks and preservation hashes are recorded
in `dev/evidence/review-20260925/checks.json`. Independent final read-only
review of the documentation corrections found no actionable findings; the
subsequent narrow relay-filter plan clarification also passed its separate
read-only delta review. No outstanding review finding remains for these edits.

The index changed externally across the interruption; its new entries/hash
are preserved in `dev/evidence/review-20260925/resume-baseline.json`. No staging
or reset was performed by the coordinator. No worker owns a write area.
Next implementation action, only after owner authorization: reconcile the
current index/files, validate the partial P00 scaffold, then continue the
provider survey/gate without treating any current fixture result as P01.



## 2026-09-26 — Four approved specification amendments

Scope: specification, plan and public encoding-fixture maintenance only; endpoint implementation remains paused. The baseline and original index SHA-256 are in `dev/evidence/approved-amendments-20260926/baseline.json`. Main revision 9 / SEC-1 revision 4 / SAMPLE-1 revision 2 now record the four owner-approved changes; [review disposition](DMP_Review_Disposition.md) states their costs and the unadopted Noise alternative.

RBO discovery returned `fetch failed`; local fixture checks are the fallback. The existing generator revalidated all four upstream Cacophony patterns under the pinned SHA-256 and regenerated 4 DMP fixtures / 64 packets / 44 mutations. Node fixture verification passed, including 64 wrong-key, 164 structural and 8 fixture-service-policy rejections. These are fixture-helper checks, not provider or endpoint conformance. New required endpoint/resource cases remain pending in the matrix. No MCU build or hardware action ran. Independent final review and exact preservation hashes are recorded in this amendment evidence directory.


Independent read-only final review by `/root/review_timing_claims` found no actionable findings on the frozen amendment snapshot. The reviewer independently matched all snapshot hashes and index hash, reran the fixture verifier and `git diff --check`, and confirmed Noise S3.1 is unchanged. Coordinator checks also confirmed deterministic fixture regeneration, 79 existing relative Markdown links and all 30 packages still pending. The only post-review source edits are this evidence entry and the matrix's fixture-result status. See `dev/evidence/approved-amendments-20260926/checks.json` and `final-evidence.json`; deferred endpoint/MCU checks are not passed.


During final evidence recording, the staged set changed outside coordinator commands (the formerly untracked scaffold/evidence and current amended files became staged). The final index SHA-256 observed is `1348AF06EB0F960AACFF70E985C524DA52F7FA76B1580DD2E53978FA65008213`, versus `E4D96AFA5C058AB7DC937EEE0546DC5F61BE8D2399C7A1ACEB880FC7D383ABA0` at the successful independent review. Preserve this external staging; no reset or restaging was performed. Reviewed normative/helper hashes still match. Final hash evidence distinguishes review-time preservation from this later index change.


## 2026-09-26 — Portable MCU provider source survey

The owner authorized provider research only and clarified that other MCU families must be supported without tying the C core to ESP32. The checkout now starts at externally created commit `03de75750d3aafe0bb0f4cf527916b7041589474`; it was clean at initial inspection. Baseline hashes/index entries are in `dev/evidence/provider-survey-20260926/baseline.json`. No commit or staging was performed by the coordinator.

[Provider survey](DMP_Noise_Provider_Survey.md) records pinned primary-source findings for Noise-C and its maintained MCU fork, noise-protocol/noise-rust-crypto, Snow and Noise*. The coordinator verified critical source claims independently of worker summaries, including C nonce/recovery limitations and Rust cloning/extraction/erasure. A worker's mention of a combined NNpsk0+XX requirement was rejected: these are separate DMP modes. Source inspection does not pass P01 or prove target RAM/flash.

Plan/board now treat ESP32-S3 as the first reference, with a non-Espressif freestanding compile configuration to select at P00 and verify by P08. Vendor/OS/entropy/persistence ports remain outside the core. No normative document, fixture, build configuration, dependency or production source was changed. No build, provider execution, flash or external issue/PR/message ran. Both Noise error strategies remain under discussion; current S3.1 is unchanged. All packages remain pending. Final source/document preservation checks and independent review are recorded in the survey evidence directory.

## 2026-09-26 — Owner-directed abort-first and controlled-core reassessment

The owner's attached brief supersedes the earlier mandatory preserve-state and blanket private-Noise-core prohibition for this research/documentation pass. Implementation/adoption remains paused. The [ADR](DMP_Noise_ADR.md) maps the four separate decisions: failure behavior, storage/API, engine origin and primitive backend. The main draft advances to revision 10, SEC-1 to 5 and reference families to /4; BOOT_VERSION stays 2 because bootstrap layouts do not change. Recovery revision 1 and SAMPLE-1 revision 2 keep their behavior. No wire policy selector or second strategy was added.

The coordinator updated S3.1/S3.2's structural-drop versus admitted-read/post-check-abort boundary, cleanup, episode/restart budgets, delayed/orphan/replayed attempts and S10.17. S4/S5/S8 retain distinct confirmation/transport behavior and provider-neutral PN/AAD. The workflow, plan, board, matrix and provider-test brief now permit reviewed standard Noise core changes with owned provenance/maintenance; no primitive rewrite or production dependency is accepted. The historical source survey is retained behind a superseded-policy heading and a new pinned reassessment.

Read-only specialists researched the engine and primitives. The coordinator checked actual source, including the C monotonic receive nonce, old-vs-modern PSK mixing, production ephemeral setter, generic DH error masking and component licenses. Corrected an overly broad backend summary: reference X25519 defaults to STROBE, not Donna, and the bundled Donna 32-bit source has a BSD-style notice despite the crypto README's MIT summary. No all-zero acceptance exploit or blanket Noise nonconformance is claimed; SEC-1 selects the permitted rejection behavior explicitly. First experiment recommendation: existing ESPHome C engine with a bounded patch queue and separately reviewed sodium software backend. A Rust-to-C translation remains a more expensive reserve route.

The baseline revision-9 Node verifier passed. After updating the exact public manifest, the Python generator passed its hash-checked upstream corpus; the first Node run caught the remaining old manifest literal in the verifier. Updated that literal, then the independent Node check passed: 4 fixtures, 64 packets, 44 mutations, 64 wrong-key rejections, 164 structural and 8 fixture-policy rejections. Replacing only the new manifest literal with the old one in an in-memory generator invocation exactly reproduced all four old fixture objects. New cryptographic bytes follow the changed PROFILE_HASH; packet lengths, algorithms and public key inputs remain unchanged. Details: [vector impact](evidence/noise-abort-first-20260926/vector-impact.json). This is not abort-first endpoint execution.

During work, HEAD advanced externally from `03de75750d3aafe0bb0f4cf527916b7041589474` to `64495d7` and the staged set changed. The coordinator issued no commit/stage/reset commands and preserved that state; baseline index SHA-256 was `a09858c3431fbd271d33e1ea0af59248a26f56ccdfd15a23f1a6e3df2ad9b12a`, later observed `373c690ce00859937d19cccf4aab50df0850c71eaa6364304f8bcd09c4b280d6`. Review uses frozen file hashes and the original content baseline, not unstaged diff alone. Final review/check evidence is recorded in `dev/evidence/noise-abort-first-20260926/`.

No provider builds/executions, MCU resource measurements, firmware integration, installs, fork implementation, hardware actions or external issues/PRs were performed. Existing C/build scaffold files are unchanged; all 30 packages remain pending. The next implementation experiment is specified in the plan, not started. Missing numeric product manifests/target budgets, backend provenance gaps and runtime/independent interoperability evidence are explicit acceptance gaps.


## 2026-09-26 — Authorized commit, fork and initial executable experiments

The owner authorized local commits, adding their Noise-C fork as a submodule,
and starting experiments. Created documentation commit `c9dabbf72746bb20bebe3546bf4ce5aa8b967a3d`
with the reviewed revision-10/SEC-1-revision-5 changes and evidence. Added
`third_party/noise-c` from `https://github.com/kuzyasun/noise-c` at the inspected
ESPHome-derived commit `44722c19f7795dd409b46728712067fac87ffc53`; no engine patch
or fork commit is part of this initial wave. No push was performed.

RBO discovery returned `fetch failed`, so local host checks were used. The
unchanged upstream library built and passed both inherited CTest entries, with
52 executed and 988 explicitly skipped vectors. Root host scaffold passed 2/2.
ESP-IDF v6.0.2 was discovered; the additional Cortex-M4 soft-float compile-only
scaffold check passed with GCC 13.3.1. Neither is MCU provider/resource evidence.
The [baseline record](evidence/noise-baseline-20260926/README.md) contains source
provenance, test logs, exact toolchain scope and remaining gates.

Two bounded workers authored disjoint host-only probes: public API limitations
and independent DMP fixture reproduction. The coordinator owns registration,
source review, runtime checks and acceptance. No production API, normative bytes
or engine primitives changed. P00 preparation is running and P01 remains pending
its prerequisite and full acceptance, including target resources. During work,
the current experiment files were staged externally; HEAD stayed at `c9dabbf`.
The coordinator preserves this staging and reviews the complete content before
creating the authorized experiment commit.

Integrated host CTest passed 6/6, including exact NNpsk0/XX ChaChaPoly fixture
flights/hash/Split AEAD and final-flight FAILED/no-resume checks. The first build
found a new fixture-header generator formatting bug; the corrected generator and
strict C11 build passed. The expected-limitation probe confirmed monotonic receive
PN incompatibility, invalid-high-PN poisoning and literal-zero DH success. Its
success is a reproduced blocker, not SEC-1 conformance. The coordinator corrected
the high-PN test ordering so lower-PN rejection is observed before any successful
high-PN authentication. Independent review is recorded with the final snapshot.

Independent read-only review by `/root/abort_first_final_review` found no material findings. All 24 snapshot hashes, normative hashes and all three engine/backend tree digests matched. It checked source and the recorded 6/6 results without rerunning the suite; limits remain explicit. See [review result](evidence/noise-baseline-20260926/review-result.json). Only this review-result entry and review metadata were added after the reviewed source snapshot.


## 2026-09-26 — P00 acceptance and P01 explicit receive PN

Resumed clean parent `f649853` and clean fork `44722c19f7795dd409b46728712067fac87ffc53`.
The owner authorized the recommended P00 completion and bounded PN implementation.
[P00 acceptance](evidence/noise-pn-20260926/p00-acceptance.md) records finite
experimental RAM/flash/concurrency/path sensitivity inputs, MCU memory-placement
choices, exact available toolchains and runner evidence. These are experiment
inputs, not production budgets or hardware support. P00 is done; P01 is running.

The coordinator designed and implemented a keyed explicit receive nonce/AAD
wrapper in the controlled fork. Two bounded workers separately authored upstream
boundary tests and independent DMP transport-vector tests. Actual source diffs
were reviewed; the coordinator added the missing assertion of implicit nonce
preservation after the parameter/length-error block through worker feedback.
Integrated local CTest passed 7/7 after RBO returned `fetch failed`. No runtime
failure occurred in this patch wave. The changed cipherstate translation unit
also compiled with strict warnings for Cortex-M4 and ESP32-S3; this is neither a
full MCU provider build nor runtime memory evidence. New normative bytes, crypto
primitives, KDF, TX behavior, handshake semantics and DTrack integration are absent.

The [PN-01 evidence](evidence/noise-pn-20260926/README.md) distinguishes capability
checks from the retained expected-legacy-limitations test, and records the open
DH/entropy/storage/cleanup/resource and endpoint gates. Independent review and
final source pins are recorded separately in that evidence directory.

Independent read-only review verified the frozen 26-file snapshot, normative
hashes and unchanged backend digests. Its sole P2 finding was ambiguous resource
scope: envelopes and sensitivity counts now explicitly apply per endpoint,
including coexisting roles. A narrow follow-up verified both corrected documents
and their hashes and closed the finding. No other material findings remain within
the reviewed scope; see the [review result](evidence/noise-pn-20260926/review-result.json).

Committed the reviewed fork source locally as
`355b2923666c23df0d52c096a7459e7bee09b88a` and updated the parent experiment's
exact engine pin. CMake reconfiguration accepted that revision. Tested source
is unchanged; only the documented resource clarification, engine pin and review
metadata followed the frozen snapshot. No push was performed. The recommended
next bounded patch is DH-01 strict all-zero DH-result rejection and full
ephemeral/static negative-path coverage; P01 is not complete.

## 2026-09-26 — P01 strict X25519 DH-result rejection

Resumed clean parent `e3fc79a` and clean fork `355b292`; no staged or unrelated
changes were present. The owner requested continuation of the recommended DH-01
wave. The coordinator confirmed that the inherited DH null-key override masked
backend errors and that the handshake mixed the result even after DH failure.
The bounded patch applies SEC-1's existing strict X25519 policy and guards MixKey;
no normative bytes, primitives, KDF, backend sources or other DH policies changed.

Two bounded workers authored disjoint inherited tests and the host DH probe.
The coordinator inspected the diffs, corrected a missed null-vector expectation
through worker feedback, and fixed two probe compilation errors (bounded mutable
plaintext copy and string-label access). RBO discovery returned `fetch failed`;
local integrated CTest passed 8/8 with no emitted final-build warnings. Both exact
fixture modes and the PN seam still pass; 988 skipped vectors remain skips.

Strict `dhstate.c` object builds passed on ARM and Xtensa. The stronger ARM
`handshakestate.c` compile check hit two inherited unused parameters; the same
failure was reproduced from the pre-patch fork. That check, full MCU provider
builds and runtime resources remain unresolved, without warning suppression.
See [DH-01 evidence](evidence/noise-dh-20260926/README.md) for case mapping,
failed/successful logs, hashes, and the separate code/final review records.
P01 remains running; the next bounded work is fallible entropy and its failure
paths, followed by storage/cleanup/resource acceptance. No push or hardware action.

Independent read-only review by `/root/dh_final_review` found no actionable
defects within this bounded host scope. It verified the six-file code snapshot,
16 final probe/evidence entries, seven normative hashes and both backend tree
digests, and inspected the recorded 8/8 results without rerunning tests. The
coordinator accepted DH-01, retaining all broader P01 limitations. The reviewed
fork source was committed locally as `c707782972b9c9015a8a1ba06724a07572306d50`;
updating the exact parent pin and reconfiguring succeeded. Only the revision pin
and acceptance metadata followed the reviewed source snapshot. See
[review result](evidence/noise-dh-20260926/review-result.json). Next: RNG-01.

## 2026-09-27 — P01 checked entropy port (RNG-01)

Resumed clean parent `a99d7bd` and clean fork `c707782`. The owner requested
continuation of the recommended RNG-01 wave and previously authorized local
fork/parent commits. The coordinator owns the checked link-time entropy port,
configuration guards and error propagation. Two bounded workers authored
separate DH/RandState and handshake probes; the coordinator inspected actual
source and test diffs. No normative contract or primitive/backend source changed.

The custom-port build propagates entropy errors, invalidates/clears failed DH
keys and RandState state, and discards the whole failed output. Tests exercise
partial entropy at real ephemeral generation, first/second Noise writes,
FAILED-state no-resume, fresh exact fixture/hash/Split recovery, and automatic
reseed failure after part of a large host output was already generated.

RBO discovery returned `fetch failed`; the local fallback's first integrated
build had 105 steps and no emitted warnings. CTest passed 10/10, including the
previous PN/DH checks; inherited vectors ran 52 cases and skipped 988. MCU
wrapper checks passed for Cortex-M4 and Xtensa after correcting include paths
and PowerShell argument quoting. These are compile-only checks, not complete
provider builds or resource budgets. The Windows OS adapter passed strict
object compilation only; alternative OS/reference configurations lack runtime
acceptance. Source/backend/normative hashes and exact commands are recorded in
[RNG-01 evidence](evidence/noise-rng-20260927/README.md).

Source inspection found a separate startup blocker: `sodium_init()` calls its
own RNG outside the checked Noise port, and framework/backend init failures are
not fully exposed. Tests run after actual successful host initialization. The
complete entropy/cold-boot gate remains open alongside storage/allocation,
complete erasure, MCU resources and remaining P01 cases. No backend init was
skipped or mocked. Next recommended wave: INIT-01 startup failure propagation.

Independent read-only review by `/root/dh_final_review` found no actionable
findings. It verified 10 fork and 21 final snapshot hashes, seven normative
hashes and both backend tree digests (47/670 regular files), and inspected the
recorded results without rerunning tests. The coordinator accepted RNG-01 only
within the post-initialization host scope. P01 remains running. The unchanged
reviewed fork source was committed locally as `0d86934919dc9220eaa49574bc9b22f0abe972b2`;
updating the exact parent pin and reconfiguring succeeded. Only the revision
pin and acceptance metadata followed the reviewed snapshot. See
[review result](evidence/noise-rng-20260927/review-result.json). No push or hardware action.

## 2026-09-27 — INIT-01 error visibility and confirmed backend startup blocker

Resumed clean parent `3b5338f` and fork `0d86934`. The coordinator fixed the
confirmed Noise wrapper bug: a returned negative sodium_init result now maps
to SYSTEM, and pthread_once retains the actual initializer result rather than
masking failure. Explicit non-pthread initialization remains caller-serialized;
no global per-object admission guard or implicit retry was added.

One bounded worker authored the wrapper return tests; another independently
inspected the actual backend startup path without edits/builds. The coordinator
verified both and added a supervised Windows diagnostic using real sodium_init
with the OS RNG call interposed. Healthy startup succeeds. Forced OS failure
reaches real backend SIGABRT before Noise returns, confirming an unresolved
no-process-exit blocker through allocator-canary randombytes_buf. No fake RNG,
backend initialization bypass or modified primitive is accepted.

RBO discovery returned fetch failed. Local first integrated configure/build/test
passed: 73 build steps without emitted warnings; 17/17 CTest invocations,
including six return-code injection cases and the separately labeled expected
backend-abort limitation. Prior PN/DH/RNG checks pass; inherited vectors ran 52
and skipped 988. util.c compiled strictly for Cortex-M4 and Xtensa in serialized
mode; these two objects do not prove complete MCU runtime/resources.

[INIT-01 evidence](evidence/noise-init-20260927/README.md) records the source
hashes, commands, outputs and [backend boundary](evidence/noise-init-20260927/backend-boundary.md).
Full startup/cold-boot and P01 remain open. Next recommended experiment is a
maintained checked backend startup integration covering both readiness and
allocator-canary entropy, with failure before publishing initialized state.
Independent read-only review by `/root/dh_final_review` found no actionable
finding, verified 3 production and 17 final hashes, 7 normative hashes and both
backend tree digests, and confirmed the stated evidence limits. The coordinator
accepted returned-error handling only. The unchanged fork source was committed
locally as `cfb45b9041d174b3e3106333235c87af47dcb425`; the parent exact pin was
updated and CMake reconfiguration succeeded. Only the pin and acceptance
metadata followed the snapshot. See [review result](evidence/noise-init-20260927/review-result.json).
No backend source, normative bytes, hardware, DTrack integration or remote
repository was changed.

Final documentation scripting hit Windows default encoding/newline issues;
these were corrected with explicit UTF-8 and verified preservation of the
previous log content. No tested code changed. Some task files were staged
during work; their content was checked against the frozen snapshot before
updating the authorized commit, without resetting the index.

## 2026-09-27 — BINIT-01 checked backend startup

Resumed clean parent `2896cf3` and unchanged Noise fork `cfb45b9`. The owner
requested the recommended backend integration experiment. The coordinator
created a maintained two-file patch, checked entropy port, isolated source
preparation and separate backend/Noise targets. Two workers authored disjoint
preparation tooling/tests and startup probes. No fetched backend file, Noise
submodule source or normative contract changed.

Checked startup propagates readiness/canary-read errors before initialized is
published, wipes partial canary bytes and releases the existing startup lock.
No implicit retry or fallback is introduced. An explicit later call can recover.
CPU/primitive setup is retained; selected Noise runtime entropy still uses the
RNG-01 checked custom port. Legacy libsodium RNG APIs remain outside this surface.

RBO discovery returned fetch failed. The initial local configure found an ASM
scope issue, corrected without changing cryptography. A 97-step build and 29
CTest invocations passed. The coordinator added inherited unit/vector suites on
the checked backend and distinct per-call deterministic fixture entropy; the
30-step incremental build and 31/31 suite passed. Each inherited configuration
runs 52 vectors and skips 988. The original backend's expected abort reproduction
remains separate from checked-backend startup acceptance.

Independent review found an output hard-link preservation bug in the preparer.
The coordinator confirmed and fixed it with new-file atomic replacement for
both source outputs and the report, then added a real hard-link regression.
All 7 preparation cases and the final 31/31 CTest invocations passed without
skips in the preparation tests; reconfiguration left generated C unchanged.
Original backend digests and normative hashes still match the clean baseline.
The worker's earlier sandbox/fixture failures and rejected machine-specific
path workaround are recorded as failed pre-acceptance work, not passed evidence.

See [BINIT-01 evidence](evidence/noise-backend-init-20260927/README.md) for the
maintained patch/license, exact source/configuration identities, failed and
successful logs, case mapping and scope limits. The independent reviewer verified
12 final code hashes and 18 evidence hashes and returned scoped PASS with the
hard-link finding resolved; [review result](evidence/noise-backend-init-20260927/review-result.json).
The coordinator accepts the serialized host scope. P01 remains running; physical cold-boot quality, MCU resources,
concurrent/lock bounds and other storage/cleanup gates remain open. Next:
MEM-01 bounded setup allocation, OOM and cleanup. No push/hardware/DTrack action.

## 2026-09-27 — MEM-01 allocation failure and owned-heap cleanup

Resumed clean parent bec767c and fork cfb45b9. RBO discovery returned fetch
failed, so used local host checks. One bounded worker authored the memory probe;
a separate read-only source investigator mapped ownership. The coordinator
registered the checked backend probe and reviewed the actual code.

The investigator's partial-constructor dangling output was confirmed in source
and reproduced at NNpsk0 allocation ordinal 5. The coordinator clears the caller
output after destroying the partial object. A separate prologue double-free
allegation was rejected and retracted: malloc assigns NULL on failure.

The probe originally passed a NULL pointer for XX's empty final payload; the
coordinator corrected that test input, preserved the failed log, and strengthened
allocator-interception self-checks. Final ordinary host checks passed 32/32;
optimized Release memory probe passed 1/1. There are 16 NNpsk0 and 20 XX OOM
ordinals, with zero live tracked allocations after cleanup. Pair aggregate peak
requested heap bytes are 2650 and 3322; these are two-endpoint supplied-ephemeral
fixture measurements, excluding allocator overhead, stack and DMP buffers.

Initial Release compilation emitted one existing patterns.c memchr-bound
warning. It is preserved in evidence and not suppressed; warning-free Release
provider compilation is not claimed. Independent review returned scoped PASS;
nine code hashes and 23 evidence hashes verified, no actionable findings. The
reviewer assessed the existing warning against END-terminated static tables and
first-match semantics; no observed overread or blocker for this scoped result.
Reviewed fork source committed locally as 0a7eddb; parent pin updated afterward.
See [MEM-01 evidence](evidence/noise-memory-20260927/README.md) for source pins,
failure and success logs, scoped claims and remaining gates. P01 remains running.
Next recommended: bounded setup storage/quota and both MCU configuration checks.

## 2026-09-27 — MEM-02 custom allocator and target layouts

Resumed clean parent b75f1a9 and Noise fork 0a7eddb. RBO was reachable, but job
job_01M3FY09EM0CBCKG0H14G1X270 failed in repo_fetch because the fork commit is
local and not present at origin. Used local fallback without pushing.

The coordinator added a fixed allocator port for object/prologue storage and
wipe-before-release. Two bounded workers authored a caller-backed test arena
and actual-type compile-only layout tooling; coordinator owns integration and
acceptance. The custom target uses explicit -fno-strict-aliasing for its static
byte-storage policy. Existing system-allocator targets remain separate.

Ordinary suite passed 34/34; Release arena unit/integration passed 2/2. Tests
cover byte/block quota refusal, fragmentation/reuse, dirty and invalid release,
preserved traffic after refused allocation/reset, and Split traffic after
handshake destruction. Reserved host storage is 8192 bytes plus 2112 metadata;
peak charged live bytes of the pair driver are 3424, not its full physical cost.

All three layout/call-path compilations passed: host, Cortex-M4 and ESP32-S3.
Their selected objects contain custom hooks without libc allocator references.
MCU concrete state alignment fits 8 bytes; arena metadata is 1056 bytes. These
are compile-only ABI measurements, not full backend linking or runtime budgets.
Initial strict compilation failed on inherited unused parameters; diagnostics
remain recorded. The tool now retains six inherited warnings per target while
owned layout/arena units use -Werror. Host extraction uses compiler assembly
extents because COFF nm omits sizes. Stale .su files are excluded explicitly.
Release also retains the previously reviewed pattern-bound warning.

Independent read-only final review returned scoped PASS with no actionable
findings: 14 code hashes, 37 evidence hashes, both initial indexes, seven
normative files and both backend digests verified. Fork source committed locally
as c40f2dc; only its parent pin and acceptance metadata changed after review.
See [MEM-02 evidence](evidence/noise-arena-20260927/README.md) and its review result.
P01 remains running. Next: complete provider/backend archive compilation for
Cortex-M4 and an isolated ESP-IDF ESP32-S3 build/link. A Cortex-M4 board/linker
map is not selected. Runtime, stack high-water and concurrency remain later gates.

## 2026-09-27 — MCU-01 isolated provider build feasibility

Resumed parent ccb3bc4 and clean Noise fork c40f2dc. RBO job
job_01M3FZKED982WEBDVSKSDWX5H9 could not fetch the unpublished fork pin;
local fallback used the recorded toolchains without pushing or installing.
EIM-managed v6.0.2 activation was verified after its CLI invocation returned
without executing the requested command.

Added isolated Cortex-M4 archive and ESP32-S3 IDF projects, sharing the generic
pinned source inventories and checked startup preparation. Explicit protocol
tables retain NNpsk0 and XX; the upstream single-pattern IDF component is not
used. Static archive rescan resolves callbacks into the fixture port. Public
fixture keys/entropy require an explicit test-only opt-in. No fork or normative
source changed. A read-only worker examined portability; another worker owned
only the build-evidence collector. Coordinator owns integration and acceptance.

Cortex built all three selected archives (74 translation units); ESP32-S3 linked
the provider test and an SDK baseline with identical sdkconfig. Both symbol
gates passed. The MCU logs emitted no compiler warnings; inherited backend/SDK
warning policies remain visible. Failed configure/archive-order/group-scope
attempts and final successful logs are retained. Missing test-only opt-in was
rejected as expected. Compiler stack reports are not runtime stack measurements.

ESP map attributes 38856 bytes of flash code/data and 143 static DIRAM bytes to
Noise plus checked sodium. The fixture alone adds 9272 static DIRAM bytes,
including its backing/arena, and substantial vectors/diagnostics. Whole-image
size difference is 72176 bytes; this includes additional SDK/stdio retention.
None of these values is an accepted per-endpoint DMP budget. Cortex has no board
linker map; neither MCU ran the fixture. Entropy quality, runtime, concurrency,
complete resource sensitivity and full P01 remain pending.

Independent final review returned scoped PASS with no actionable findings: all
9 code and 68 evidence snapshots, archive/ELF/map/source and backend-file hashes,
RESCAN link graph and size claims verified. Sources stayed fixed after review;
only acceptance metadata changed. See [MCU-01 evidence](evidence/noise-mcu-20260927/README.md).
No flash, publication or DTrack integration was performed. Next: per-endpoint
quota/ownership sensitivity with multiple live handshake and traffic contexts.

## 2026-09-27 — Reconcile accepted MEM-03 / MCU-02 through MCU-04 scopes

This entry brings this chronological ledger up to date with the work board;
it does not rerun or broaden those accepted experiments. MEM-03 supplied
serialized live-owner/quota/OOM/reuse evidence. MCU-02 added the generic serial
provider console, 33/33 host checks and both EIM IDF6.1 builds. Owner-authorized
physical S3 COM23 / C3 COM35 runs completed 80 pairs / 3349 replies with
heap/stack/timing observations. MCU-03 added 10 pressure cases / 5717 replies,
36 completed candidates, safe NEW/Split OOM, rejected live reset and surviving
guard traffic. MCU-04 added separate worker-owned arenas/scratch and 36/36 host
checks; each MCU completed 224 local pairs. Its first C3 run exposed idle-task
watchdog starvation; a bounded per-cycle rendezvous/idle window fixed the
scheduler issue, then both images and physical cases were repeated and reviewed.
Links, source/build/physical hashes and limitations remain on the work board.

## 2026-09-27 — MCU-05 longer lifetimes and planned warm resets

Parent HEAD 0072f61 and fork c40f2dc retained. Independent read-only P01 audit
identified stale status statements: scoped S3/C3 runtime/concurrency exists;
full provider/security/resource and non-Espressif runtime gates are still open.
Coordinator updated README, plan status wording, matrix and board, without
changing normative requirements. The detailed remaining host boundary checks
are in [P01 reconciliation](evidence/noise-mcu-soak-20260927/p01-reconciliation.md).

Added Python orchestration only, reusing the accepted MCU-04 images. Independent
source review found startup filtering could ignore extra/abnormal resets;
coordinator confirmed and fixed that gap before hardware execution. Final RBO
job job_01M3H4PC5N5QPNM8DKMC9R9V4P passed 18/18 unique tests in ordinary and
optimized Python. Source hashes match reviewed code and collected artifacts.

S3 completed 12 two-worker 128-cycle RUNs across three boots: 3072 pairs,
58368 balanced allocations/frees, stable 347696-byte free heap and two resets
with ROM cause/banner evidence. C3 completed four RUNs: 1024 pairs, 19456
balanced allocations/frees and stable 286000-byte free heap. Its first EN pulse
produced a fresh HELLO boot ID and cleared command counter, but no ROM reset
diagnostics. The controller correctly exited failure and sent no further RUN.
The full C3 scenario is not passed; read-only espefuse summary subsequently found UART_PRINT_CONTROL=3, which
disables ROM UART output; USB ROM output remains enabled. No eFuse was changed.
An additional diagnostic EN pulse restored the same application (boot d2500317,
last_id=0), outside the scenario. Independent final review accepted S3 and
only C3's first epoch. A usable boot-log channel is needed for the C3 reset gate.

See [MCU-05 raw evidence, host gates and scoped results](evidence/noise-mcu-soak-20260927/README.md).
No C firmware change, rebuild, flash, commit or push in this wave. Normative
files, existing implementation changes and Git index are preserved. P01 remains
running, P02 pending. Next: host abort-first post-check/pre-read and ownership
gates; separately resolve C3 reset observability before repeating its full soak.

## 2026-09-27 — Owner-directed transition to actual library implementation

The owner identified that provider experiments had expanded without creating
the DMP library and explicitly authorized correcting the plan. The unvalidated
BOUNDARY-01 draft was stopped before any build and remains excluded from CMake;
its test-only owner/scheduler is not implementation or acceptance evidence.

Split P01 into P01A development feasibility, P01B actual library provider adapter
and P01C integrated target qualification. P01 remains an open umbrella before
P25. P02 now depends on accepted P00, P03 additionally on P01A, and P04 creates
the real libdmp target and headers/sources. Codec/framing/security tests and MCU
runners must link the same library implementation. P13 owns actual abort-first,
pin/payload, generations, cached flights and bounded restart; P14 still owns
protected FINISH/READY and activation after AEAD/AAD/PN. No normative rule or
outstanding target/security check was waived.

Independent read-only review confirmed the narrow P01A basis from existing
reviewed capability/provenance evidence; coordinator marked P01A done, P02
ready. No new test execution or full provider/production acceptance is implied.
The reviewer found one broken checklist anchor after renaming; an explicit alias
preserves existing links. Graph checks cover all 33 packages and no cycles;
normative documents, provider code, prior dirty implementation and Git index
remain unchanged. No build, flash, commit or push in this correction.

See [transition and obligation mapping](evidence/implementation-transition-20260927/README.md).
Next implementation: P02 contract/validator/corpus, P03 finite test manifests,
then P04/P05/P06 actual library target and wire/framing code. MCU qualification
continues at its named gates, rather than blocking unrelated host development.

## 2026-09-27 — P02 offline manifest contract and validator accepted

Implemented the versioned two-endpoint test-manifest contract, closed JSON
Schema, stdlib Python validator and separately authored interpretation corpus.
The validator checks original-byte PROFILE_HASH, service/identity/security policy,
worst PN/header/bootstrap sizing, separate handshake/confirmation budgets, R3
and retention/freshness inequalities, a finite per-relay duplicate/schedule
envelope, and role/region/pool resource reservations. This is configuration code;
no duplicate laboratory endpoint/state machine was introduced.

Independent Astra source review found seven concrete issues across its passes;
all were checked and fixed. Luna high completed the test corpus after an earlier
worker's usage limit. The owner corrected a temporary Sol fallback; it was
interrupted and the accepted worker assignment used the requested Luna route.
Final independent acceptance review verified exact fixture hashes and derived
bounds, then identified one non-isolating grant-buffer regression test. Corrected
20-byte rejection / 21-byte acceptance was independently reviewed and rerun.

RBO had no live agents at execution time, so the announced fallback ran locally.
The first sandboxed Ninja ABI probe hung; only that run's processes were stopped.
Identical unsandboxed CMake configure/build passed with GCC 15.2.0 and no emitted
warnings. Normal-sandbox CTest passed 3/3: 10 validator methods, 41 negative
manifest mutations, 17 raw cases, three valid manifests and explicit boundary/XX/
CLI cases; existing SEC-1 fixtures and C11 scaffold also passed. See
[P02 evidence and source hashes](evidence/profile-validator-20260927/README.md).

P02 is done and P03 ready. P03 freezes complete development deployment manifests
and case mappings; P04 creates libdmp; P09 supplies actual startup parity. No
endpoint, physical schedule or measured target-memory fit is inferred here.
Existing normative documents/vectors and HEAD remain unchanged. Git index changed
during the task to a staged snapshot; coordinator issued no staging/reset and
preserved that observed index. The change and hashes are recorded rather than
claiming initial-index equality. No commit, push, flash or DTrack integration.

## 2026-09-27 — P03 development manifests and traceability accepted

Frozen six complete host deployments: DIRECT-1 Stream R, RADIO-1 simulated
packet and separately named TEST-RADIO-RETRY-ALL, each NNpsk0/XX cipher 1.
Radio comparison tests enforce identical common schedules, deadlines, workload,
MTU and resource limits. Exact original-byte hashes are distinct. Historical
provider measurements inform explicit finite portable reserves; unimplemented
modules remain design allowances and physical target fit is unclaimed.

Luna xhigh produced the 137-case normative ledger; Luna high supplied focused
deployment tests and expected interpretations. Coordinator inspection caught and
fixed shifted R7 columns, scope/ownership details and a resource-source newline
portability issue. Every future implementation case remains not-run, including
endpoint/relay/mixed S10 gates and real-SEC-1 reruns. Early independent Astra
review closed one confirmed test-binding timer/reset-policy gap and found no
COBS/full/compact-reference contradiction. Additional final review invocation
was unavailable at the agent-thread limit; final acceptance is the coordinator's.

RBO returned no live agents; local fallback CTest passed 3/3 with 23 profile
methods, plus existing SEC-1 fixture and C11 scaffold checks. The exact Git index
observed at turn start and HEAD were preserved. No provider/MCU rerun, staging,
commit, push, hardware or DTrack integration. See [P03 evidence](evidence/profile-freeze-20260927/README.md).
P03 is done; P04 is ready to create the actual portable library and interface seams.

## 2026-09-27 — P04 real archive and interface acceptance

Created the portable C11 libdmp archive and linked C/C++ foundation tests.
Implemented checked byte views, deadlines, generations and local status names
once in src/core/base.c. Froze structural codec, CRC/framing and transport
contracts plus the bounded deterministic C-harness subprocess interface. P05/P06
symbols are explicitly declaration-only; no success stubs or substitute protocol.

Luna high implemented only the base/test files; coordinator integrated actual
sources/builds. Independent Astra xhigh reviewed interfaces, source and logs;
confirmed ownership, timer, error-output and harness event/trace ambiguities were
fixed and the final scoped review accepted. Debug CTest passed 6/6, Release core
3/3, final header core 3/3; tests-off C-only archive passed with five base exports
and no undefined allocator/SDK references. RBO was unavailable; sandbox compiler
probe stalled and the same local build succeeded outside sandbox without forced
compiler checks. See [P04 evidence](evidence/core-seams-20260927/README.md).

HEAD and normative authorities stayed unchanged. An external action changed
the index during work (238 to 293 staged files); both observed index snapshots
were preserved, with no staging/reset/commit/push by this task. No hardware or
DTrack integration. All codec/framing/endpoint normative cases remain not-run.
P04 is done; P05/P06/P07 and P01B are ready. Recommended next: independent P05
codec and P06 framing implementation, coordinated shared-header/build ownership.


## 2026-09-27 — P05 codec and P06 framing accepted

Implemented actual libdmp structural parser/encoder and role checks, CRC32C,
shared canonical COBS and caller-owned Stream L/R decoder/encoder. Two Luna high
workers used disjoint source/test ownership; coordinator integrated headers,
CMake, published-vector and layer tests. Independent Astra xhigh verified fixed
source and logs. Confirmed encoder constraints, zero-default role policy,
nested offsets and failed-decoder monotonic time defects were repaired with
regressions; no open actionable finding remains in the reviewed scope.

Strict Debug and Release CTest passed 10/10 each with zero build warnings.
64 published packets are checked byte-for-byte through the real codec; this
is structural evidence only. The tests-off C archive has no allocator/SDK
references. RBO was unavailable, so execution used the announced local fallback.
The ledger records 23 passed primary and 10 partial primary scopes; all whole
rows retain pending independent/later obligations. P08 fuzz/sanitizer/cross-host
and embedded checks, all endpoint acceptance and SEC-1 eligibility remain open.

See [P05/P06 evidence](evidence/codec-framing-20260927/README.md) for exact hashes,
commands, intermediate failures and review closures. HEAD, exact starting Git
index and normative sources were preserved. No staging, commit, push, MCU flash
or DTrack integration. Next: P07 deterministic harness, with independent P01B
provider adapter work when its assignment is frozen. P08 awaits P07.

## 2026-10-02 — P07 preparation; broker Cursor dispatch blocked

Owner authorized resuming implementation through Agent Broker. Live MCP is
READY, DMP discovery is fully paginated (24 entries, revision 3), and all eight
route bindings match saved configuration. Checkout and Noise submodule are
clean at ae7e06e133b92dcec818bd2006875bbf43d39956 and
c40f2dca78eee064e521233a5d884853d471028a. The original checkout was sealed;
[assignment and baseline](evidence/harness-20261002/assignment.md) preserve the
P07 contract and exclusive write boundaries.

Spawn of dmp_cursor_worker / Cursor / grok-4.7-high / high failed before
inference with PROVIDER_INCOMPATIBLE: Wrapper shell identity unavailable.
No turn ID or session exists; no paid launch. See [blocker evidence](evidence/harness-20261002/broker-blocker.md).
No workaround, daemon restart, quarantine change or model substitution.
P07 remains ready until successful dispatch; no implementation or checks claimed.

The owner selected dmp_cursor_reviewer / grok-4.7-xhigh / no effort override
and dmp_cursor_large / grok-4.7-high / high for reviewer and complex work,
respectively, with no silent escalation. RBO was initially offline; the owner
started it and allowed local host builds when RBO fails or fuller logs are needed.

## 2026-10-03 — P07 first implementation turn timed out

Live broker READY/project/routes and RBO were rechecked after Cursor recovery.
DMP discovery revision 8 is fully paginated, all configured routes/workspaces
match, the previous worker session is idle with no changed source snapshot, and
an RBO macOS/arm64 agent is idle. `dmp_cursor_worker` turn
`turn-ed50161de3bedec44b3255e9` was accepted/execution started, then TIMED_OUT
at its 900000 ms deadline. Broker returned no report, artifacts or final
snapshot; usage/billing is unknown. Checkout has no P07 source diff. No
replacement turn was sent to that session. The owner-approved retry uses the
exact `dmp_cursor_large` route/model/effort with a fresh isolated session and
current broker hard deadline. Build checks remain RBO-first; local host fallback
is owner-authorized.

## 2026-10-03 — P07 review fixes accepted

The recovered Cursor worker completed two bounded turns in a new
`dmp-current-project` workspace session. The coordinator reviewed the actual
source diff and addressed one adjacent `--interface-version` flush check in a
follow-up. A sealed read-only review compared `snap-a3d7f17808bf7ff6d7e81bb6`
to `snap-df6c5b35177fcbf91789a599` and reported no confirmed defects; it
verified all five identified correctness fixes. The first review attempt
`turn-8d21362e3a2f395e0502c243` failed before review because a worker-generated
Python bytecode cache prevented diff generation. The coordinator removed only
that generated cache, recaptured the sealed target, and retried successfully
with `turn-9dac5890dca0e2c9ea14e11d`. See [P07 review-fix evidence](evidence/harness-review-fixes-20261003/README.md).

RBO job `job_01M3ZSGFBW4VT46F8VP7EZM4RX` passed Debug and Release builds and
`harness.port` / `harness.subprocess` CTest checks (2/2 in each configuration).
The tests-off Release archive also built, with the harness target and CTest
entries verified absent. P07 is accepted for its host deterministic harness
scope; endpoint, SEC-1, provider, MCU runtime/resource, and physical transport
gates remain open. P08 is now eligible. No staging, commit, or push.

## 2026-10-03 — P08 fuzz component checkpoint; paused for broker restart

After P07 acceptance, live `broker_status` was READY and fully paginated
`agents_list` revision 10 showed the configured Cursor worker/reviewer models,
efforts, policies, and new `dmp-current-project` / `dmp-review-project`
workspaces matching saved configuration. The bounded P08 fuzz worker ran as
`dmp_cursor_large` / Cursor / `grok-4.7-high` / high in session
`session-786c164cb9f05015191e9613`; turn
`turn-b38e6c1420c78485ab8fc779` SUCCEEDED with final snapshot
`snap-d6edf6137ed89a61951c2a07` from baseline
`snap-1f59469d30b556c798c9ecdf`. The session status still exposed its initial
snapshot as `latest_snapshot_id`; reconcile this with the turn final snapshot
and actual checkout after restart.

Worker-reported fuzz targets and self-check are limited to `tests/fuzz/**`.
They are not yet reviewed or integrated. The worker reported the bounded GCC
self-check passed but could not link libFuzzer in its Windows environment; no
other host was checked. Twelve shell tool receipts in the same turn had
`status=unknown` / `decision=unknown` with no diagnostic payload, so their
command outcomes cannot be independently established from broker events. No
receipt was replayed and no replacement session was created. See [P08 partial
checkpoint](evidence/fuzz-p08-20261003/README.md).

The owner requested a pause for a broker restart after the current agent work.
The worker is IDLE and a fully paginated session listing showed no active DMP
turns. P08 remains running: coordinator integration, independent review, host
CI, ESP-IDF 6.x, Cortex-M4, map/size, and allocator checks remain. No build,
review session, staging, commit, or push was started after the worker completed.

## 2026-10-03 — P08 coordinator integration; independent review submitted

After the broker restart, `broker_status` returned READY and DMP `agents_list`
was fully paginated at configuration revision 11. The P08 worker turn
`turn-b38e6c1420c78485ab8fc779` is SUCCEEDED and its session is IDLE. Coordinator
integration adds the opt-in fuzz build, allocator probes/checks, and hosted
Linux/Windows, Cortex-M4, and ESP32-S3 CI jobs. Focused local checks are recorded
in [P08 coordinator integration evidence](evidence/fuzz-p08-20261003/coordinator-integration.md).

A sealed current-workspace snapshot has been submitted to the existing
read-only Cursor reviewer session using the original worker baseline and this
final target. No files are being changed while review is active. Hosted CI,
libFuzzer/ASan/UBSan execution, ESP32-S3 link/map, and hosted Cortex-M4 evidence
remain unrun; package acceptance is still open. No staging, commit, or push.

## 2026-10-03 — P08 review finding repaired; final review pending

The independent read-only review in turn `turn-0d69e2a08f701033fd67f4ef`
reported one P1: `tests/fuzz/CMakeLists.txt` declared the same self-check and
seed-generator targets twice, causing the `DMP_FUZZ=ON` CMake configure to
fail before any fuzz target could be built. Removed the duplicate second block;
the original definitions and single `fuzz.selfcheck` registration remain.

The targeted Clang 21.1.0 CMake configure retry again stopped at compiler ABI
detection and was canceled. Hosted fuzz CI is still required to establish the
actual Clang/libFuzzer build and run. Final read-only review uses the same
original worker baseline and a newly sealed target after this repair. No
staging, commit, or push.

## 2026-10-03 — P08 final source review

The final independent review in turn `turn-122bc0d3f9d9a40cd1f094fc`
confirmed the duplicate fuzz-target block is removed and found no additional
actionable P0-P2 issues. The review was read-only and did not run builds. P08
remains open until host CI, ASan/UBSan/libFuzzer, ESP32-S3 link/map/size, and
hosted Cortex-M4 evidence are available. No staging, commit, or push.

## 2026-10-03 — P08 hosted acceptance; P09 eligible

GitHub Actions run [37118205823](https://github.com/kuzyasun/dmp-protocol/actions/runs/37118205823)
passed all five jobs on commit `2bccf6bf7f8fac3e84eeeadfb8f570cdee5b0bb4`:
Linux GCC host (13/13 CTest), Windows MSVC host (12/12), Clang sanitizer/fuzz
(14/14 CTest and 1,000 seeded runs each for core and stream), Cortex-M4 Arm GNU
13.3.1 archive with no allocator references, and ESP32-S3 ESP-IDF 6.0.2 link
with map, total/component size reports and no allocator references. Both
embedded artifacts' source revisions match the workflow commit. Their measured
outputs and artifact references are recorded in
[P08 hosted CI evidence](evidence/fuzz-p08-20261003/ci-results.md).

The coordinator inspected the ESP32-S3 and Cortex-M4 artifacts. This closes
P08's host, fuzz/sanitizer, embedded compile/link, map/size and core allocator
checks. It does not claim P01C target qualification, MCU runtime, whole-device
memory-budget acceptance, or physical transport behavior. P08 is accepted;
P09 is the next eligible package. The pushed branch was clean at the accepted
source revision before recording this status.

## 2026-10-03 — P09 identity and startup profile admission accepted

P09 adds full-identity context handling with generation-safe caller-owned slots,
context retention/draining, sequence allocation, compact authenticated
references, and C-side startup profile admission checked against the shared P02
corpus. The P09 handoff records the frozen ownership, capacity, deadline and
transport-callback boundary for P10/P11 without adding protocol behavior.

The first independent source review (turn
`turn-dcfec9429532c4e2b068d61b`, artifact
`art-4936b23e7d2719b9c7a949d1`) found two defects. The endpoint bootstrap
component now has the required 120-byte per-slot floor, with a 119-byte corpus
mutation. Context opening now skips an exhausted unused generation and can use
a later free slot; a dedicated regression test covers this while retaining the
single-slot exhaustion result. Final source review of baseline
`snap-f5ec99a220ae02cd7c8512b8` to target
`snap-7ba380c7fbecb1a404ea3ff8` (turn
`turn-0477a66d2eb9474b90c88cc0`, artifact
`art-76f02fecd0bd2d5cfce3971d`) confirmed both fixes and reported no other
actionable P0-P2 findings. A separate review of the P09 handoff found and
closed two documentation mismatches: stop-and-wait is keyed by destination
endpoint and service, and the P10/P11 profile timing fields and §11 references
are now complete. The corrected handoff closure review (turn
`turn-dba14e273d3ca21e93a6dd34`, artifact
`art-c3d486d6859b16dc8a27e05c`) found no remaining discrepancy.

Coordinator acceptance checks:

- Direct GCC 15.2.0 compilation of the changed identity/profile C sources and
  identity regression test with C11 `-Wall -Wextra -Wpedantic -Werror`; the
  configured host archive and P09 test executables were relinked.
- Targeted host CTest: 4/4 passed (`profiles.contract`, `identity.context`,
  `identity.profile_admit`, `identity.profile_parity`).
- Profile Python suite: 23/23 passed; core archive check found no allocator
  references; `git diff --check` passed.

Full Ninja/CMake build and clean compiler-detection attempts hung during
command launch/ABI detection and were stopped. These attempts are not counted
as acceptance evidence. P09 remains host/profile validation only; SEC-1,
reliability/reassembly, endpoint integration, MCU, interoperability and
physical transport evidence remain open.

Broker observations: the worker used route `dmp_cursor_large` (Cursor,
`grok-4.7-high/high`), session
`session-ef443b35e17c1c499f8851ce`, turn
`turn-393326bf1b270db7374b4bb0`. Several read/edit tool receipts returned
errors without diagnostics and three shell receipts were `UNKNOWN`; no lost
operation was replayed. Coordinator compilation and the acceptance checks
above independently verified the affected paths. The first reviewer attempt
(turn `turn-1c97b82bb908f6be0f424cef`) stopped before inference with
`INPUT_UNSUPPORTED` because the sealed snapshot included generated Python
cache files; removing those exact cache files and sealing a fresh snapshot
allowed the review to proceed. The earlier successful findings review had one
optional grep call rejected as `unknown_inputshape`; the reviewer recovered
using bounded reads and searches. The handoff review had one read denied with
`path_resolution_failed` and recovered through other allowed reads. Reviews
used the existing approved read-only session
`session-0d68e81ab43e2a092cca438c` on `dmp-review-project`, retaining its
`grok-4.7-xhigh` session binding; current saved/live route discovery reports
`dmp_cursor_reviewer` as `grok-4.7-high` with no effort override. No reviewer
modified repository files.

## 2026-10-03 — P09 admitted resource slot counts for P10/P11

After P09 was accepted and pushed at `3814bab6481f32c9dce502670a0bf37fa9756efb`,
the P10 design pass showed that `dmp_admitted_profile` did not expose the
validated endpoint charge counts needed to size caller-owned sender, assembly,
result, history, correlation and adapter pools. Added those six fields, sourced
only from the endpoint resource row. `control_slots` and
`application_queue_slots` remain operational limits from `limits`; cross-pool
validation confirms endpoint charges fund those limits, while larger charges
do not raise the runtime limits. P11 remains separate.

The first read-only review (turn `turn-fd3f7117e320e63c94bb60b8`, findings
artifact `art-b92bba9248f9f1a666292c91`) raised two points: ensure the
operational limits remain distinct from resource charges, and make all six
component mappings observable in tests. The coordinator verified the P02
`cross_resources` floors, clarified the API and handoff documentation, and
added an in-memory valid-manifest case with distinct component counts plus
resource charges larger than the control/application limits. Closure review
from baseline `snap-1949cd04e8adb8c6157a49b3` to target
`snap-819d91f45f794569db865312` (turn
`turn-9814b1edbddee06106819ead`, artifact
`art-18d1c4c8dc2e6c71e2b7bfcb`) found no remaining issues. The first review
had two denied grep calls (`unknown_inputshape`) and one unsupported tool-call
receipt; it recovered through allowed reads and successful searches and
completed the review. No broker operation was replayed.

Coordinator checks on the final source:

- Direct GCC C11 compilation with `-Wall -Wextra -Wpedantic -Werror`, updating
  the host archive and profile-admission test executable.
- Targeted CTest: 4/4 passed (`profiles.contract`, `identity.context`,
  `identity.profile_admit`, `identity.profile_parity`).
- Profile Python suite: 23/23 passed; the core archive check found no allocator
  references; `git diff --check` passed.

The review used `dmp_cursor_reviewer` (Cursor, `grok-4.7-high`, configured
default effort) in the read-only `dmp-review-project`; the worker was not used
for this coordinator-owned API change. P09 remains host/profile evidence only;
no SEC-1, MCU, endpoint, interoperability or physical transport claim follows.

## 2026-10-03 — P10 API review checkpoint

The coordinator froze an initial `include/dmp/reliability.h`, root CMake
registration and package plan against Git baseline
`4db90acf626b5ee855f95fac80d8dee588ae8d97` and sealed target
`snap-b43c630fb07b9f26fd2f147f`. An independent read-only review used
`dmp_cursor_reviewer` (Cursor, `grok-4.7-high`, broker-default effort), turn
`turn-45bda806099c454bdd0bc591`, baseline `snap-9261f786fd5144306a8e7daf`,
target `snap-b43c630fb07b9f26fd2f147f`, findings artifact
`art-54a7917a0724ed24ce18417f`. It found P1 gaps for cached rejection versus
later acceptance and ERR status classification, notice plaintext/lifetime and
late-result payload semantics, canonical immutable metadata, pool byte-capacity
checks and operational queue/control limits; plus a P2 cancel/transport-pin
contract gap. It confirmed the one-context ABI is scoped to current profiles,
which all declare `peers == 1`, and the input separates structural frame from
plaintext. The coordinator is revising the ABI before implementation.

The first implementation send to `dmp_cursor_large` (Cursor,
`grok-4.7-high/high`), turn `turn-783da37df58e3ddf4bf85df2`, was cancelled before
source changes after the API review. Its final workspace check shows no worker
edits; the repository diff contains only coordinator-owned API, build, plan,
board and execution-log files. One
shell tool receipt returned `UNKNOWN` (call `898dd66f55ecded1592b3063c3cc8aa0`)
with no diagnostic; no response was replayed. The coordinator checked actual
Git status/diff and found no worker source or test files, which resolved the
uncertain workspace effect.

Broker read-only review observations: the reviewer turn above received two
`grep` tool receipts with `status=error` (calls
`4b67943b78b617484f4ae2c837af3179` and
`2ebf54d1db9bcdc7f9714934c688f73d`) and two `read` receipts with
`status=error` (calls `69ab9727ab3c27c7fd7b018dff205a8d` and
`72cdd29b479b7c25054129135cd6b527`); the event stream supplied no error code
or diagnostic. The reviewer recovered through later successful reads/searches
and completed the review. Impact was review delay; workaround was to use the
later successful bounded reads/searches. No provider output or credentials
were retained.

The closure review from `snap-b43c630fb07b9f26fd2f147f` to
`snap-8fc58c3446abfb2811605b0d` (reviewer turn
`turn-33a18b697fcaf4a6cbb123e6`, artifact
`art-6fff6367daf4cc6d5395812c`) confirmed all five prior findings were fixed,
then found two additional P2 contract gaps: `complete` needed to reject
mismatched `application_err`/STATUS pairs, and TX outcome mapping needed to
include `DMP_TX_FAILED_UNSENT`. Both have been added to the public API contract;
the updated target awaits closure review before implementation dispatch.

A narrow closure review from `snap-8fc58c3446abfb2811605b0d` to
`snap-fe9c6287b491dd6e6674c07a` (turn
`turn-4df75ba6d7b8c0895973f81b`, artifact
`art-ce3f47b6fa2afd33d47980dc`) confirmed both fixes and found one further P2
wording gap: a current-attempt `TRANSMITTED` / `POSSIBLY_TRANSMITTED` outcome
also requires `UNKNOWN`. The contract now says either outcome on any attempt
makes the exchange unknown; `LOCAL_UNSENT` requires the current/last attempt to
be proven unsent and no current or prior attempt to have possibly transmitted.
The final closure review is pending.

That narrow review (turn `turn-a2215700a9d12445ffa97c1f`, artifact
`art-8ae70d58ef1ead130c071266`) confirmed the current-attempt mapping and found
one further P2 edge: cancellation while still queued, before any transport
submission, needed an explicit `LOCAL_UNSENT` outcome. The API now states that
pre-submission cancellation settles locally unsent; a final closure review is
pending.

That review (turn `turn-d4b1862138088d29011ca213`, artifact
`art-db27edd6694d6c5fc09ff1d0`) found the new pre-submission rule contradicted
the following attempt-outcome condition. The cancellation comment is now a
four-case classification: no accepted submission gives `LOCAL_UNSENT`; each
accepted attempt is individually proven unsent or potentially transmitted;
any `TRANSMITTED`/`POSSIBLY_TRANSMITTED` yields `UNKNOWN`; and after all
accepted attempts settle, all-unsent yields `LOCAL_UNSENT`. A rejected submit
has no callback and did not reach transport. Another narrow closure review is
pending.

The final API closure review (reviewer turn `turn-74a13665074a409ea9627221`,
artifact `art-0a8dff0138592b11c34d20cb`) used baseline
`snap-0a0dbbbc54fb3284f0cbfd25` and target `snap-1c7684daa52c8a2cce3ff09d`.
It confirmed the cancellation classification is exhaustive and reported no
residual or new P0-P2 findings. This supersedes the preceding pending-review
notes; implementation is authorized against a new sealed snapshot. Live
Broker recheck at configuration revision 11 reports READY, permits
`dmp-protocol`, and confirms the approved Cursor worker and reviewer routes,
policies, and `dmp-current-project` / `dmp-review-project` workspaces. The
worker and reviewer sessions are IDLE and available.

P10 implementation worker route `dmp_cursor_large` (Cursor,
`grok-4.7-high/high`), turn `turn-bb0852cb9f8cfe5cd4bdb226`, reached its
deadline with `TIMED_OUT`; no final snapshot or agent report was produced.
Three worker `shell` receipts were `UNKNOWN` without diagnostics (calls
`f3188bef45c80c9b8716614193604de4`,
`0902173119390fbe599dd2047253148e`, and
`bab67caffaad103a188896e81938a89b`). Impact: worker-side build/test outcomes
are unverified. Workaround: after Broker confirmed quiescence, coordinator will
inspect the retained workspace and run the authorized local host checks once;
the UNKNOWN calls were not replayed. No provider output or credentials were
retained.

Coordinator validation of the retained P10 worker files: `cmake -S . -B
build/host -DDMP_BUILD_TESTS=ON` passed. The targeted build command
`cmake --build build/host --target dmp_test_reliability` reported “no work to
do” (so it did not independently establish that the current sources compiled).
`ctest --test-dir build/host --output-on-failure -R reliability.direct` failed
with four assertions at `tests/reliability/test_reliability.c` lines 784, 997,
530 and 1312 (ACK count, result SEQ expectation, held-frame parsing, and
delivery setup respectively). P10 remains unaccepted pending a clean targeted
rebuild, diagnosis, and test correction/fix.

Independent read-only review of target `snap-60c0836524ecb93646c05cb1` against
the author's baseline `snap-9261f786fd5144306a8e7daf` completed on reviewer
route `dmp_cursor_reviewer` (Cursor, `grok-4.7-high`, configured default
effort), turn `turn-01c7b2b9eb234ba76984364f`, findings artifact
`art-602846c469b5ebc8d801c629`. It found two implementation defects: P0, the
first poll frees the inbound result sender because `accept_request` leaves its
`send_deadline` at zero, suppressing the receipt ACK and preventing later
completion; P1, completion after the receipt deadline allocates the terminal
result SEQ before the due receipt ACK, so both transmitted identities are out
of allocation order. Review determined the four observed reliability test
assertions are valid and stem from these two defects; other checked contract
areas had no additional P0-P2 findings. One reviewer read receipt returned
`error` without a diagnostic (call `063d62113830f9077732f29d03f1ab33`); impact
was review delay, and the reviewer recovered through later successful bounded
reads/searches. No provider output or credentials were retained. The target
remains unaccepted while the coordinator fixes these findings.

Coordinator corrected both reviewed defects. Inbound result senders now carry
the request result deadline, and a completed result defers SEQ allocation when
a due receipt ACK must be sent first. Storage validation now enforces
overflow-safe minimum byte capacities and accepts over-provisioned arrays while
clamping operational slot counts to admitted profile quotas. It rejects
multi-peer profiles; P10 RX and rejection paths reject ROUTE and FRAG shapes.
Regression tests cover over-provisioned caller storage, single-peer validation,
and unsupported routed input.

Using the explicit GCC/MinGW host build at `build/p10-host-gcc`, the reliability
target rebuilt successfully and `reliability.direct` passed. The complete host
build passed; full CTest passed 14/15 tests. Only `harness.subprocess` failed,
with 62 Windows `PermissionError` errors while Python temporary directories
were being created/written/cleaned under `%TEMP%`; all other suites, including
the P10 reliability test, passed. This is an environment limitation already
observed on this host, unrelated to P10. Final independent closure review of a
fresh sealed target is still required before acceptance.

The first final-closure review submission on `dmp_cursor_reviewer` (Cursor,
`grok-4.7-high`, turn `turn-31d75adf3ed3ee0db64410b6`) failed before review
inference because broker diff generation encountered the ignored generated
Python bytecode `profiles/schema/__pycache__/build_schema.cpython-312.pyc` and
reported “file is binary or invalid UTF-8.” Impact: no review findings were
produced. Workaround: verified all five repository `.pyc` files were ignored
Python caches and removed only those generated files; the review was
resubmitted against a fresh sealed target with the original author baseline.

Final P10 closure review used baseline `snap-9261f786fd5144306a8e7daf` and
sealed target `snap-720d3be8d6c007aac6523d67`. Reviewer route
`dmp_cursor_reviewer` (Cursor, `grok-4.7-high`, configured default effort),
turn `turn-d9f0485de21f19c997310b33`, completed with `SUCCEEDED`; findings
artifact `art-07485688a0ee086119fec258` reports no remaining actionable
P0-P2 findings and confirms both earlier fixes. The review was read-only and
did not rerun tests. Coordinator acceptance follows independent source review,
targeted `reliability.direct` PASS and full CTest results (14/15; only the
unrelated Python `harness.subprocess` temporary-file permissions failed).

Acceptance toolchain: GCC 15.2.0, CMake/CTest 3.28.1, Python 3.12.8 on Windows.
SHA-256 for the accepted source/configuration inputs:

| File | SHA-256 |
|---|---|
| `CMakeLists.txt` | `6db2c91ca4bdd40f357518af4da45a97577d499bd3c2ef3ab15780c6351aa48e` |
| `include/dmp/reliability.h` | `c47bec37d4ea5b1e61417e0de67d3a7d00514e1fecd26f73d389e3f9bab5146e` |
| `src/reliability/reliability.c` | `611e39047bbb601ef2c182e8da60f22e1ff29debcd76284b8cbbc7cd9dbe65a0` |
| `tests/reliability/CMakeLists.txt` | `9b8ecab6e5a8c20224eddb895615cc6b877274a0cd90806759603f2c522e0823` |
| `tests/reliability/test_reliability.c` | `dc22c98169a842dd48612f29f6af1b7fa68dc5f288aa63cbb35ad4ef94f78066` |

P10 is accepted as host reliability behavior only. It does not establish SEC-1,
endpoint integration, MCU, independent-peer or physical transport conformance.

P11 broker observation (2026-10-03): the live `dmp_cursor_large` route
(Cursor, `grok-4.7-high`, configured `high` effort) emitted a shell tool receipt
with `status=unknown` and `decision=unknown` at event cursor 10458, call ID
`bbe372f2568f6e94af21639fa824f059`, turn `turn-40b707c9750f6ac5b3c2917a`.
The same turn also emitted `status=unknown` / `decision=unknown` shell receipts
at cursors 10461 (`f770c89ddedd84cbbf6af4bbb324f77a`), 10467
(`221006e80849c4fa20cc4a34031d5105`), 10473
(`e378442fa06b5e60283b7198359b46cc`), 10476
(`5aed3317cb4797150854398b87518ae1`) and 10479
(`eab11c7dd8d8d865c44e86ec6fb37957`). These receipts contained no command,
diagnostic or turn error code; the turn later completed `SUCCEEDED` with no
broker-observed turn error. Impact: the individual shell-command outcomes are
ambiguous, so worker-reported build/test results require coordinator replay.
Workaround/status: no shell command or turn was replayed while its result was
unknown and no replacement session was launched; after terminal completion,
inspect the sealed target and run coordinator-owned acceptance checks.

P11 reviewer event-poll observation (2026-10-03): coordinator event polling on
`dmp_cursor_reviewer` (Cursor, `grok-4.7-high`), turn
`turn-276782d7a7221bbc1182f3cc`, was rejected with `INVALID_REQUEST` because
`wait_ms=30000` exceeded the broker's accepted `[0, 20000]` range. Impact: no
turn or inference state changed; the reviewer remained `RUNNING`. Workaround:
continue with bounded event waits of at most 20000 ms. This was a coordinator
request-parameter error, not a provider or route failure.

P11 final-review preflight observation (2026-10-03): the live
`dmp_cursor_reviewer` route (Cursor, `grok-4.7-high`) turn
`turn-d2fe134f77941f05c97f42bc` terminated `FAILED` with `INPUT_UNSUPPORTED`
before inference because the sealed diff contained the generated binary
`tests/profiles/__pycache__/make_fixtures.cpython-312.pyc`. Impact: the final
review did not start and no inference ran. Workaround: remove only Python
bytecode outputs produced by the profile tests, capture a fresh sealed target,
and retry the review with a new idempotency key. No turn or response was
replayed.

P11 final-review preflight retry observation (2026-10-03): the live
`dmp_cursor_reviewer` route (Cursor, `grok-4.7-high`) turn
`turn-6a872955e23e19ef598fe183` terminated `FAILED` with `INPUT_UNSUPPORTED`
before inference because review diff generation encountered
`profiles/schema/__pycache__/build_schema.cpython-312.pyc` as binary/invalid
UTF-8. Impact: the final review again did not start; no inference ran. The file
was absent from the current workspace, so removing local bytecode alone did not
clear the binary path from the baseline-to-target diff. Workaround required:
exclude `**/__pycache__/**` from the registered DMP snapshot coverage (or make
the baseline and target cache bytes identical) before capturing a new review
target. No turn or response was replayed.

## 2026-10-04 — Stage-1 evidence cleanup

Worker-only cleanup on `feat/initial-version` at
`fc83b84354d16bd72164d37eb5b5e9efd862f321`. P11 was already committed and in
`review`, not a live assignment. No P09–P11 implementation, public API, CMake,
profile, or P12 file was edited. The staged `dev/DMP_Correction_Plan.md` index
entry was left untouched. No stage, commit, push, flash, or DTrack action.

Removed 330 tracked intermediate artifacts (jsonl traces, build/serial logs,
gzip archives, symbol/size dumps, and large run summaries), 44666522 worktree
bytes. Every removed path is in that commit. Sorted path-list SHA-256:
`d34cc7fc0ac08494b3518656a7c26625b668d65b2cd33bdcc92fceedc8cf0c08`.
Tracked evidence present afterward: 221 files, 898996 bytes. Ignored
uncommitted `dev/evidence/p00/initial-*.patch` (425757 bytes) was retained.
`test_resource_input_hashes_match_source_bytes` passed (1 test). Consolidated
measurements are in `dev/DMP_Validation_Results.md`. Config-API correction was
not started.

## 2026-10-04 — Stage-2 configuration freeze

Froze the typed configuration API, ownership rules, and acceptance checks in
`dev/DMP_Correction_Plan.md` under "Frozen stage-2 contract (2026-10-04)".
Baseline is HEAD `fc83b84354d16bd72164d37eb5b5e9efd862f321` plus the stage-1
worktree. No code, P12, stage, commit, push, flash, or DTrack action. The
index was left holding only the already staged correction plan.

## 2026-10-04 — Stage-3 typed admission

Replaced JSON admission in `libdmp` with `dmp_config_admit`. `dmp_config` and
`dmp_admitted_profile` are one struct layout. Host tools still own JSON and
`PROFILE_HASH`. No P12, stage, commit, push, flash, or DTrack action. The index
was left holding only `dev/DMP_Correction_Plan.md`.

Host tools: GCC 15.2.0, CMake/CTest 3.28.1, Python 3.12.8, GNU nm (Binutils)
2.45 at `C:\develop\mingw\w64devkit\bin\nm.exe`. Rebuilt existing `build/host`
without deleting it.

`sizeof(dmp_reassembly_tombstone)` is 48. The six-row budget is in
`dev/DMP_Validation_Results.md`.

Commands and outcomes:

- `cmake --build build/host` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "identity.profile_admit|identity.profile_parity|identity.context|reliability.direct|reassembly.direct"` — 5/5 passed, 0 failed (`identity.context`, `identity.profile_admit`, `identity.profile_parity`, `reassembly.direct`, `reliability.direct`).
- `python -m unittest discover -s tests/profiles -p "test_*.py" -v` — 24 tests, OK.
- `python tools/validate_profile.py profiles/deployments/direct-nnpsk0.json` — `valid: true`, sha256 `3d0229efafa5d15c1fcfe19265d81c70e7b004976d28303fb92fc27e4a357e2a`.
- `python -m unittest tests.profiles.test_deployments.DeploymentTests.test_resource_input_hashes_match_source_bytes` — 1 test, OK.
- `python tools/check_core_allocators.py build/host/libdmp.a --nm nm` — `no allocator references in build\host\libdmp.a`.
- `nm --defined-only build/host/libdmp.a` — defined `T dmp_config_admit`; `dmp_profile_admit` absent.

## 2026-10-04 — Reassembly test admission bypass removed

`gate_profile()` in `tests/reassembly/test_reassembly.c` no longer treats
`DMP_UNSUPPORTED` as success. `boot()` and the extra-storage path call
`dmp_reassembly_init` only after `dmp_config_admit` returns `DMP_OK`. The
profile with `assembly_tombstones_per_peer < assemblies_per_peer` is checked as
`DMP_UNSUPPORTED` with an unchanged output and is not initialized. Production
sources were not edited. Existing `build/host` was not deleted.

- `cmake --build build/host --target dmp_test_reassembly` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "reassembly.direct|reliability.direct|identity.profile_admit"` — 3/3 passed, 0 failed (`identity.profile_admit`, `reassembly.direct`, `reliability.direct`).

## 2026-10-04 — Coordinator rerun after the bypass fix

Inspected `gate_profile()`: success paths call `dmp_reassembly_init` only after
`DMP_OK`. The inadmissible tombstone/assembly pair is rejected and not
initialized. Reran
`ctest --test-dir build/host --output-on-failure -R "identity.profile_admit|identity.profile_parity|identity.context|reliability.direct|reassembly.direct"`:
5/5 passed, 0 failed. P11 stays `review`. P12 was not started. No stage,
commit, or push.

## 2026-10-04 — Adapter reserve and smaller buffer rows

Acceptance fix on `6779798644c7cdcb0e0d20596f3da84f6531ce26`. The reliability
reserve formula was not edited. `dmp_config_admit` and `tools/validate_profile.py`
reject `adapter_slots` that are not strictly greater than
`min(control_slots, adapter_slots)`. Direct manifests are adapter 3 / control 2.
Radio manifests are adapter 5 / control 4, because adapter 3 is not above that
reserve. Endpoint adapter charge counts match. `PROFILE_HASH` values are in
`profiles/deployments/digests.json`. P11 stays `review`. P12 was not started.
No stage, commit, push, flash, or DTrack action.

`sizeof(dmp_reassembly_tombstone)` is 48. All six buffer rows are supported
and are recorded in `dev/DMP_Validation_Results.md`. Each row admitted the
config, initialized reliability, and completed one request/result exchange.
The 4096-byte and 16384-byte rows also initialized reassembly and completed
one two-slice reassembly.

Commands and outcomes, existing `build/host`, GCC 15.2.0, CMake/CTest 3.28.1,
Python 3.12.8:

- `cmake --build build/host` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "identity.profile_admit|identity.profile_parity|identity.context|reliability.direct|reassembly.direct|profiles.contract"` — 6/6 passed, 0 failed (`profiles.contract`, `identity.context`, `identity.profile_admit`, `identity.profile_parity`, `reassembly.direct`, `reliability.direct`).
- `python -m unittest discover -s tests/profiles -p "test_*.py" -v` — 24 tests, OK.
- `python -m unittest tests.profiles.test_deployments.DeploymentTests.test_resource_input_hashes_match_source_bytes` — 1 test, OK. `resource-inputs.json` was not edited.
- `python tools/validate_profile.py` on each of the six deployment manifests — `valid: true`. Direct endpoint RAM 78720. Radio endpoint RAM 83584. Relay RAM 29441.

## 2026-10-04 — P11 coordinator acceptance

Coordinator accepted P11 after the independent review reported no findings. No new test run in this step. P12 was not started. No commit.

## 2026-10-04 — P12 direct endpoint, not accepted

Started at `3f1dbfe806435a320c9439c5af391af9cd01db86`. Two `libdmp` endpoints exchange Stream R frames. Unfragmented REQ/RSP/TELEM retries, duplicate suppression, and results go through `dmp_reliability`. Payloads larger than one core frame are sliced at the admitted 64-byte stride and reassembled by `dmp_reassembly` in the peer endpoint. SAMPLE-1 payload layout lives in the host test, not in `libdmp`. No JSON parsing, no heap on the receive/encode/retry path, no Noise, and no second retry state machine. A transmitted fragment that is then lost is not retried here. SEC-1 is not applied; these exchanges are provisional until P15. The host loopback is not physical-transport evidence. Manifest bytes and `PROFILE_HASH` were not edited. P12 is not marked done. No stage, commit, push, flash, or DTrack action.

GCC 15.2.0, CMake/CTest 3.28.1. Existing `build/host` was not deleted.

- `cmake --build build/host --target dmp_test_endpoint` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "endpoint\.(sample1|fragment|retry|duplicate|quota)|reliability\.direct|reassembly\.direct"` — 7/7 passed, 0 failed (`reassembly.direct`, `reliability.direct`, `endpoint.sample1`, `endpoint.fragment`, `endpoint.retry`, `endpoint.duplicate`, `endpoint.quota`).

## 2026-10-04 — P12 review fixes, not accepted

Independent review `3a0a69dc` on the uncommitted endpoint at `3f1dbfe`. Three defects only. `src/reassembly/reassembly.c` and `src/reliability/reliability.c` were not edited. Manifest bytes were not edited. P12 stays `running` and is not done. No stage, commit, or push.

SAMPLE-1 capture is the producer snapshot at `DMP_ENDPOINT_REQUEST`. Completion sends that snapshot. The consumer selects an epoch only from the designated READ, and a later older READ does not replace the live sample. A completed reassembly stays held, so the same slices are `DMP_DUPLICATE` and are not delivered again. Fragment input passes the parsed extension TLVs, omitting the per-frame SECURITY option. The test constant `DIRECT_SHA` is the current SHA-256 of `profiles/deployments/direct-nnpsk0.json` (`29cb7b91ee0c269bc14ac43e3a7c8fd8bdcfe11e9e052e8bd9e6af00fb89c3bf`). Admission still does not hash.

GCC 15.2.0, CMake/CTest 3.28.1. Existing `build/host` was not deleted.

- `cmake --build build/host --target dmp_test_endpoint` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "endpoint\.(sample1|sample_snapshot|fragment|fragment_replay|fragment_tlv|retry|duplicate|quota)|reliability\.direct|reassembly\.direct"` — 10/10 passed, 0 failed (`reassembly.direct`, `reliability.direct`, `endpoint.sample1`, `endpoint.sample_snapshot`, `endpoint.fragment`, `endpoint.fragment_replay`, `endpoint.fragment_tlv`, `endpoint.retry`, `endpoint.duplicate`, `endpoint.quota`).

## 2026-10-04 — P12 lifetime recheck, still running

Independent source recheck of the three P12 fixes confirmed they are present in the uncommitted tree on `3f1dbfe`. P12 stays `running`. Full A4, a SEC-1 rerun, and physical transport were not claimed. This recheck was source-only and did not re-run tests. The earlier CTest run after the fix was 10/10. `src/reliability/reliability.c` and `src/reassembly/reassembly.c` have no diff. No source, test, manifest, or CMake edit. No stage, commit, or push.

- SAMPLE-1 snapshot is taken at `DMP_ENDPOINT_REQUEST` and complete sends that snapshot; an older READ does not roll back a newer sample.
- `take_fragment` does not release the assembly after get; a full replay does not emit a second assembled callback.
- Reassembly receives the slice extension span; a mismatched unknown safe TLV returns `DMP_MALFORMED`.

## 2026-10-04 — P12 SAMPLE-1 A4 cases, still running

Host loopback only. Plaintext, so SEC-1 remains a P15 rerun. Not physical transport. P12 stays `running` and is not done. Manifest bytes were not edited. `src/reliability/reliability.c` and `src/reassembly/reassembly.c` were not edited. No stage, commit, or push. `build/host` was not deleted.

The consumer now sees the result source origin on `dmp_endpoint_notice` and a local `DMP_ENDPOINT_UNKNOWN` when a reliable READ ends without a result. SAMPLE-1 initialization stays in the host test. `direct-nnpsk0` sample budget is `init_attempts=1`, `init_retry_ms=5`, `init_deadline_ms=12000`, `no_sample_status=64`.

A4 cases now tested:

- First boot, telemetry before the READ result, and no epoch adoption from telemetry: `endpoint.sample1`. Accept-time snapshot: `endpoint.sample_snapshot`. Lost READ: `endpoint.retry`.
- NO_SAMPLE: `endpoint.sample_no_sample`. An accepted READ with no sample is terminal ERR STATUS 64 and an empty payload. The consumer stays unsynchronized. The one manifest attempt is then exhausted, so no second initialization READ is opened. Telemetry of a later sample is discarded. Replaying that same request is not accepted again. A new READ identity returns the new snapshot and does not initialize.
- Initialization budget: `endpoint.sample_init_budget`. Before the 12000 ms deadline the consumer is still unsynchronized and has not failed. At the deadline the READ ends unknown, local initialization fails, there is no live sample, and the retry interval does not open another request identity.
- Same-epoch older READ: `endpoint.sample_same_epoch`. After a new initialization generation, the correlated result is the older snapshot. Synchronization completes on the retained epoch and the greater cached index/value stays.
- Different epoch on the designated READ: `endpoint.sample_new_epoch`. A numerically smaller epoch replaces the cache. A later telemetry epoch is a contract violation and is not adopted.
- Late result from the previous association, including replacement while that result is outstanding: `endpoint.sample_late_assoc`. The generation and designated handle still match; only the association origin changes. The newer snapshot is delivered and does not select an epoch or change the cache.
- Superseded initialization request: `endpoint.sample_superseded`. Clearing the designation leaves the delivered READ result out of synchronization.
- Invalid correlated result: `endpoint.sample_invalid`. It does not complete synchronization.

Still deferred, not faked:

- Persistence failure and epoch reuse. A1: "counter/storage loss, rollback, failure or exhaustion MUST stop SAMPLE-1 publication until a separately authorized reprovisioning of producer identity/state prevents reuse." There is no persistence port.
- Producer restart or index exhaustion that must "atomically reserve and durably commit a never-reused epoch." The consumer rule for a different epoch on the designated READ is tested. The durable reservation is not.
- Shared-association closure during epoch change. A1: "Closing a shared association also ends outstanding exchanges on its other services with the main unknown-outcome rules." The endpoint has no close that settles other live services as unknown, and `dmp_reliability_close` refuses while an exchange is live.
- Lost result and lost receipt as their own SAMPLE-1 cases. Lost READ remains `endpoint.retry`. One discarded RSP was not redelivered by the existing schedule inside the request send horizon; that case was not given a passing CTest.
- Real SEC-1 and a second independent endpoint implementation.

GCC 15.2.0, CMake/CTest 3.28.1.

- `cmake --build build/host --target dmp_test_endpoint` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "endpoint\.|reliability\.direct|reassembly\.direct"` — 17/17 passed, 0 failed (`reassembly.direct`, `reliability.direct`, `endpoint.sample1`, `endpoint.sample_snapshot`, `endpoint.fragment`, `endpoint.fragment_replay`, `endpoint.fragment_tlv`, `endpoint.retry`, `endpoint.duplicate`, `endpoint.quota`, `endpoint.sample_no_sample`, `endpoint.sample_init_budget`, `endpoint.sample_same_epoch`, `endpoint.sample_new_epoch`, `endpoint.sample_late_assoc`, `endpoint.sample_superseded`, `endpoint.sample_invalid`).

P12 stays running: `endpoint.sample_init_budget` now fails on the consumer initialization clock at 5000 ms while reliability `result_deadline_ms` stays 12000, `init_failed` is 1 at now+5000 and now+5005 with no new READ, a later READ does not install a sample, and the requested ctest filter passed 5/5 with no edit to `src/reliability/reliability.c` or `src/reassembly/reassembly.c` and no commit.

## 2026-10-04 — P01B provider adapter, not accepted

Started at `9b2ac889c19f8627a421f156eedde8fd828f4f60`. The portable adapter is `src/security/provider_adapter.c` inside `libdmp`. Private ports live in `src/security/provider_port.h`. Tests in `tests/security/` link that same object plus the pinned Noise fork and the reviewed checked sodium backend. No public header change, no new cipher/KDF/handshake transition, no SEC-1 attempt scheduler, no P13/P14/P15 work. P01B is not done. P12 was not marked done.

Host only. Startup and runtime entropy are injected test ports, not physical or MCU entropy. The enabled cipher backend is ChaChaPoly; AESGCM is rejected. One provider is serialized. Scratch and retained caps are adapter admission limits, not a measured MCU budget. Sodium's own startup allocator is outside the Noise block quota.

GCC 15.2.0, CMake/CTest 3.28.1. Existing `build/host` was not deleted.

- `cmake --build build/host --target dmp_test_provider` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "^security\.provider_adapter$"` — 1/1 passed. Cases: init, entropy, oom, wrong-psk, low-order, pn-aad-nnpsk0, pn-aad-xx, suite-nnpsk0, suite-xx, cleanup.
- `cmake --build build/host --target dmp_test_endpoint` — exit 0. Endpoint tests were not re-run.

No stage, commit, or push.

## 2026-10-04 — P01B host adapter accepted

Coordinator accepted the host P01B adapter on 2026-10-04 after independent review found no defect. The accepted behavior is the uncommitted worktree on 9b2ac889: tests call libdmp; wrong-PSK, low-order, PN and AAD failures wipe output; AESGCM is rejected before state creation; there is no new primitive and no SEC-1 attempt scheduler; endpoint, reliability, reassembly and profiles were untouched. Physical entropy, MCU measurement, and the SEC-1 attempt scheduler are not included; scratch and retained caps stay admission limits. P13 has not started and P12 was not marked done. No commit was made in this step.

## 2026-10-04 — P13 bootstrap slice, running

Started at `0c808707844bbd5665d9546fad62b729ac89426b`. P13 is running, not done. P12 was not edited and was not marked done. P14 and P15 were not started. No stage, commit, or push. `build/host` was not deleted.

The handshake owner is `src/security/handshake.c` inside `libdmp`. It calls the accepted `dmp_provider_*` adapter, including one added read of the remote static public key. The adapter's Noise open/read/write/split mapping was not rewritten. There is no second handshake stack, no new cipher, and no test-only scheduler.

Implemented for ChaChaPoly NNpsk0 and XX, only where SEC-1 states the rule: abort-first bootstrap; episode scheduling whose attempt, work, and traffic counters are not reset by a fresh attempt, with the configured backoff and no automatic restart; pin and handshake-hash verification; candidate keys from Noise Split and the specified epoch hash; enrollment commit that does not activate an association; pre-read drops versus post-read abort, including zero CID, wrong pin, wrong PSK, and a low-order read failure; generation invalidation and stale completion; one Noise write per cached flight; same-attempt serialization; out-of-order flights, remote orphans, quotas, and cleanup that leaves another association in place. Application send is refused from candidate and enrolled states. There is no test-key fallback and no implicit trust.

Left for P14: AEAD/AAD, PN allocation, replay, protected FINISH/READY, confirmation loss, and activation. S10.17's FINISH assertion after a conflicting duplicate is not claimed here. Preserve-state remains deferred. AESGCM stays unsupported. Full fixed-stride fragment parsing stays with reassembly; this module only retains a bounded incomplete bootstrap payload and refuses a conflicting overwrite.

Not invented: SEC-1 S3.1 says the manifest defines restart backoff with any jitter, but it does not specify the jitter function, source, or distribution, so the configured backoff is applied exactly. A receive CID must be nonzero and locally unique; the allocator is a caller-configured counter that skips 0 and retained values. A work unit is one charged S3.1 ingress or Noise event, not a CPU-cycle measurement.

Host only. Fixture keys and injected entropy are not physical entropy or a transport. SAMPLE-1 was not rerun.

GCC 15.2.0, CMake/CTest 3.28.1.

- `cmake --build build/host --target dmp_test_handshake --target dmp_test_provider` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "^security\.(handshake|provider_adapter)$"` — 2/2 passed (`security.provider_adapter`, `security.handshake`). Handshake cases: nn-candidate, preread-conflict, duplicate-loss, zero-cid-low-order, wrong-psk, xx-pin-candidate, wrong-pin, oob-commit, episode-backoff, orphan-quota, scratch-serial-stale, entropy-cid-collision.

P13 stays running: epoch SHA-256 reuses one Noise HashState allocated in `dmp_hs_init`, so offer and accept no longer allocate a short-lived HashState; `epoch-hash-alloc` passed with the existing handshake cases (`ctest` 2/2), cipher selection was not changed, and nothing was committed.

P13 stays running: `epoch-hash-alloc` now counts HashState-sized allocations during `dmp_hs_accept` and requires that count to be zero with `DMP_HS_CANDIDATE` and the existing epoch values, while a null allocator on offer still returns `DMP_HS_ABORTED` without charging episode attempts or work (`ctest` `security.handshake` passed).

## 2026-10-04 — P14 confirmation slice, running

Started at baseline `146ef17ae02d445a202770555a4ecf48d30c01ec`. P14 is running, not done. P13 stays running. P15 was not started. P12 was not edited and was not marked done. No stage, commit, push, or flash. `build/host` was not deleted.

Protected FINISH/READY now uses the existing P01B ChaChaPoly cipher, S5 AAD (`DMP2-SEC1-DATA` || handshake hash || canonical header), and an explicit PN. The initiator sends FINISH only after peer authorization; a committed pin alone does not activate. The responder becomes active only after it validates FINISH and sends READY. The initiator becomes active on READY, or on a valid application packet from the responder while READY is still outstanding. Application send returns `DMP_HS_NOT_ACTIVE` before that transition. Confirmation loss retries FINISH with the same SEQ and a fresh PN until the configured attempt count; the same ciphertext is a replay. A confirmation timeout discards traffic keys and leaves an already committed pin enrolled but disconnected. The receive window is the configured power of two in [64, 65536], default 1024: a PN at least W behind the highest authenticated PN is dropped before AEAD. An isolated bad tag does not install replay state; the count is not reset by success and closes the association at the configured ceiling (hard maximum 65536).

The caller serializes an attempt. The sealed frame and accepted plaintext are attempt-owned fixed buffers; protected receive does not allocate. Epoch hashing still reuses the HashState created in `dmp_hs_init`.

Not implemented, because the cited text does not define them or they are outside this write set: restart jitter (S3.1 says "with any jitter" and does not define the distribution; the fixed backoff remains), ACL/freshness leases, rotation/drain, and endpoint S10 cases. AESGCM stays unsupported. No second Noise stack and no new KDF.

Host only. Fixture keys are not physical entropy or a transport.

GCC 15.2.0, CMake/CTest 3.28.1.

- `cmake --build build/host --target dmp_test_handshake` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "^security\.(handshake|provider_adapter)$"` — 2/2 passed. New handshake cases: finish-ready, confirmation-loss, replay-window, enroll-not-active, failed-aead-limit. Existing handshake cases still passed.

## 2026-10-04 — P14 host confirmation slice accepted

Coordinator accepted the host FINISH/READY, confirmation-loss, replay-window, and activation slice on 2026-10-04 after independent review found no defect. The accepted behavior is the uncommitted worktree on 146ef17. Activation stays 0 after enrollment commit and becomes 1 only on the FINISH/READY path. The replay window matches SEC-1 (power of two, 64..65536, default 1024). A too-old PN is dropped before AEAD. A bad tag does not mark the PN. Confirmation timeout wipes traffic keys and leaves the association inactive. Endpoint, reliability, reassembly, and profiles were not changed. P15 integration, ACL, rotation, S10 cases, physical transport, and a specified jitter distribution are not included; jitter remains the fixed restart interval because S3.1 does not define a distribution. P15 was not started. P12 and P13 were not marked done. No source, test, or CMake edit. No commit was made in this step.

## 2026-10-04 — P15 host integration, running

Started at baseline `448565b8d1f6bb1cab347a781453e9d5680fde70`. P15 is running, not done. P12, P13, and P14 were not marked done. No stage, commit, push, or flash. `build/host` was not deleted.

Two `dmp_endpoint` instances on the host loopback exchange SAMPLE-1 and fixed-stride DATA only after the existing P14 association is active. Before activation, application send and receive fail and nothing is delivered. Protected frames are the P14 records (`dmp_hs_seal_logical` / `dmp_hs_open_logical` on the existing ChaChaPoly provider path). There is no second handshake, cipher, or KDF. An altered protected reply is rejected and does not mark the PN. A lost request is retried by the existing reliability engine, which seals a new record rather than replaying the dropped ciphertext. A frame from one association is not accepted by the other. Authenticated fragments reorder and reassemble; a conflicting slice is not assembled; a fragment from the other association is not assembled. A TTL-only change of a routed protected TELEM still verifies; a destination change does not. Receive does not allocate and does not hash an epoch. The host loopback is not physical-transport evidence.

Not invented, and not implemented: ACL, freshness leases, key rotation, and a jitter distribution. S3.1 still does not define jitter. Explicitly deferred: the relay-state portion of S10 case 6 (P19) and multi-binding forwarding S10 case 11 (P23). Manifest bytes, cipher selection, and replay-window bounds were not edited. Fixture verification was not treated as closing this gate.

GCC 15.2.0.

- `cmake --build build/host` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "endpoint\.|security\.(handshake|provider_adapter)"` — 23/23 passed, including the existing `endpoint.*` and `security.handshake` / `security.provider_adapter` tests and `endpoint.protected_activation`, `endpoint.protected_alter`, `endpoint.protected_loss`, `endpoint.protected_isolate`, `endpoint.protected_reassembly`, `endpoint.protected_ttl`.

## 2026-10-04 — P15 host protected-endpoint integration accepted

Coordinator accepted the host protected-endpoint integration on 2026-10-04 after independent review found no defect in the uncommitted work on top of 448565b8d1f6bb1cab347a781453e9d5680fde70. Two endpoints exchange only after activation. An altered tag returns DMP_HS_DROPPED before the replay bit is committed. A reliability retry seals a new PN. A foreign association does not deliver payload. The receive path does not allocate or hash an epoch. Profiles and replay-window bounds were not changed. Relay S10 case 6 (later P19), multi-binding S10 case 11 (later P23), physical transport, ACL, key rotation, and a specified jitter distribution are not included. No commit was made in this step.

## 2026-10-04 — P16 selective recovery, running, stopped on missing types

Started at baseline `fe0d9a3842db7864fcbccfe574c8908c1265643e`. P16 is running, not done. P12 and P13 were not marked done. No stage, commit, push, or flash. `build/host` was not deleted. Profiles, deployment JSON, `include/dmp/endpoint.h`, wire encoding, and SEC-1 were not edited. `src/reliability/` and `src/reassembly/` were not edited.

SELECTIVE-32 revision 1 defines the receiver and sender transitions (R4 and R5). They were not implemented. The admitted C profile and the existing caller-owned slots cannot hold the state those transitions name, and the assignment forbids adding a new public type. No second recovery machine was added in tests. Retry-all remains the only fragmented send path, and it still lives in the endpoint as one ascending burst with no slice retry. Reliability still rejects fragmented input and TYPE 8. Reassembly still records a presence bitmap and delivers a completed message once.

Missing before a later assignment can implement the machine without inventing values:

- Admitted timing the engines can read: `burst_span`, `forward_delay`, `return_delay`, `feedback_guard`, `feedback_delay`, `max_probes`, `max_status`, and `record_margin`. Manifest JSON has them. `dmp_admitted_profile` does not. `collect_ms` is not the R4.2 collection interval.
- Sender slot fields: one pending missing mask, greatest accepted feedback SEQ, burst and probe counts, fragment count, and whether a burst is in flight. `dmp_reliability_logical` has no fragment index, chunk size, or total size, so the existing encode callback cannot emit one immutable slice.
- Receiver slot fields: collection-timer armed flag and due time, status count, and status-pending flag. `received_bitmap` already exists. Tombstones already refuse re-admission until context retirement.

Not invented: a numeric scheduler margin beyond the admitted `response_timeout`, a runtime `max_probes = max_bursts - 1`, static or heap recovery tables, or a test-only repair loop. No recovery CTest was added.

## 2026-10-04 — P16 selective recovery blocked

P16 is blocked at baseline `fe0d9a38`, not running and not done. No recovery machine was implemented. R4 and R5 of SELECTIVE-32 revision 1 need state that is not on the admitted profile or the engine slots: admitted-profile fields burst_span, forward_delay, return_delay, feedback_guard, feedback_delay, max_probes, max_status, and record_margin are present in manifest JSON and absent from dmp_admitted_profile, plus a sender-slot repair mask, feedback sequence, and in-flight flag and a fragment index on the logical record. No public type was added. Manifests were not edited. The existing reliability.direct, reassembly.direct, and endpoint.fragment tests stayed 5/5 and no recovery test was added.

## 2026-10-04 — Owner direction recorded, not implemented

Binding owner direction, not yet implemented, is in `dev/DMP_Correction_Plan.md` under "Owner direction 2026-10-04" (P16 SELECTIVE-32 fields, SAMPLE-1 durable epoch, jitter 0); package status cells were not changed.

## 2026-10-04 — Board correction, SAMPLE-1 epoch port, jitter 0

P12 stays `running`. P13 is `done`: closing commit `146ef17ae02d445a202770555a4ecf48d30c01ec`; no remaining P13 requirement was found, and P14/P15 own confirmation and activation. P15 is `running` again. Host loopback after activation is recorded, but P15 stays open until endpoint-local ACL and rotation are implemented. Jitter is not the reason it stays open. Only relay case 6 (P19) and multi-binding case 11 (P23) are deferred. P16 stays `blocked`. SELECTIVE-32 was not started. No NVS, filesystem, ACL policy, or key rotation. No stage, commit, or push. `build/host` was not deleted.

`reserve_sample_epoch` is the host SAMPLE-1 port in `tests/endpoint/test_endpoint.c`. The portable core does not store epochs, and `include/dmp/endpoint.h` was not changed. A saved result returns the new epoch and publication continues. A write failure or an indeterminate save stops publication, does not reserve that epoch, does not reset the sample index, and does not reissue the identity epoch. Restart returns the previously saved epoch with no second reservation, and publication continues. Recovery after state loss is not implemented. Ordinary reservation has no separate authorization flag.

Handshake restart delay is `restart_backoff_ms` plus explicit jitter 0. `security.handshake` (`episode-backoff`) refuses one millisecond early and admits the attempt at exactly `restart_backoff_ms`. Backoff limits were not changed. There is no random source.

GCC 15.2.0, CMake/CTest 3.28.1. Configure rewrote the existing `build/host` after the new endpoint test names.

- `cmake --build build/host --target dmp_test_endpoint dmp_test_handshake` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "endpoint\.sample|security\.handshake"` — 13/13 passed, 0 failed (`endpoint.sample1`, `endpoint.sample_snapshot`, `endpoint.sample_no_sample`, `endpoint.sample_init_budget`, `endpoint.sample_same_epoch`, `endpoint.sample_new_epoch`, `endpoint.sample_late_assoc`, `endpoint.sample_superseded`, `endpoint.sample_invalid`, `endpoint.sample_epoch_restart`, `endpoint.sample_epoch_fail`, `endpoint.sample_epoch_indeterminate`, `security.handshake`).

## 2026-10-04 — P15 endpoint ACL and rotation, running

P15 stays `running`. P16 stays `blocked` and was not started. No stage, commit, push, or flash. `build/host` was not deleted. Profiles and deployment JSON were not edited.

Permission is the authenticated node id plus the installed service-action grants. A secured endpoint with no grant table admits no application action. A disallowed request is not delivered to the notice handler. An authenticated REQ that the receiver's policy denies is marked in the replay window and answered with best-effort protected STATUS=6. Control permission on service 0 does not grant service 1. The core does not parse SAMPLE-1 opcodes.

Rotation uses the existing handshake attempt. New application sends move only after that attempt is active. An in-flight message keeps the association that admitted it and is not resealed onto the new one. Work whose original send or result deadline passes the caller-supplied drain bound is canceled locally as unknown. After the drain instant the old attempt is destroyed. A full identity table refuses the switch and leaves the live association. Lost FINISH/READY does not activate the replacement. Local revoke destroys the associations; a short received buffer does not. Host loopback is not physical-transport evidence.

Not implemented, because the admitted services set `freshness` false and `lease_ms` 0, so S7.1 allows omitting the token table: S10 case 10. Relay-state case 6 stays with P19. Multi-binding case 11 stays with P23. The 2^24 frame ceiling is the existing seal refusal; this host run does not drive that counter. No new cipher, KDF, NVS, filesystem, or jitter distribution. RADIO-1 was not switched to retry-all.

The host provider child table is 12 so one provider can track both peers' active and draining cipher pairs while a handshake is still registered at split. One device, one role, still fits in the previous 8.

GCC 15.2.0, CMake/CTest 3.28.1.

- `cmake --build build/host` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "endpoint\.|security\.(handshake|provider_adapter)"` — 28/28 passed, 0 failed, including `endpoint.protected_acl` and `endpoint.protected_rotation`.

## 2026-10-04 — P15 review defects, running

P15 stays `running`. P16 was not started. No stage, commit, push, or flash. `build/host` was not deleted. Deployment manifests were not edited. RADIO-1 was not switched to retry-all. No SELECTIVE-32 fields, no new cipher, no NVS, and jitter stays 0. `reserve_sample_epoch` stays in the application test port.

Local RESULT permission is checked on `dmp_endpoint_complete` whether or not a drain is live. Node 10 and node 20 each have only `PERMIT_REQ` on service 1. Node 20's READ still invokes node 10's handler, and `dmp_endpoint_complete` returns `DMP_UNSUPPORTED` with an empty output queue. No RSP is sent.

An authenticated REQ that policy rejects still does not call the handler. A fragmented REQ is not admitted to reassembly. Reliability still refuses `reject_req` when FRAG is set, so the endpoint clears only that flag on the parsed view and uses the existing unfragmented STATUS=6 rejection. A reseal of the same request does not call the handler. The review case is a sealed REQ with FRAG|ACK_REQ|SEQ, service 1, and a principal who has only `PERMIT_CONTROL` on service 0: `dmp_endpoint_rx` returns `DMP_OK`, and the next poll emits protected ERR STATUS=6.

If identity retire fails because reassembly still retains the draining context, `drain_live` stays set and a later poll retries retire. The handshake attempt is canceled at the drain deadline; the identity slot is not cleared while `retained != 0`. After the assembly deadline, the same poll releases the retain and retires the slot. With two identity slots and `drain_ms` shorter than the remaining `assembly_ms`, a second rotation then succeeds. The one-slot rotation that fails with `DMP_QUOTA_EXHAUSTED` before `drain_live` changes still passes. The 2^24 frame ceiling still stops a new seal; an in-flight message is not moved to another association.

S10 case 8 is host context destruction only. Cancel wipes traffic secrets. Cleanup drops the handshake object. Replaying the captured bootstrap does not restore the old keys or make application send succeed. A later handshake that reuses the old receive CID has different epochs; the captured old datagram fails authentication, and a new datagram on the new keys is delivered. This is not a physical reboot and does not add NVS. Sleeping-state loss is the destroyed host context; a new handshake is required.

S10 case 10 stays omitted: freshness is off and `lease_ms` is 0. Relay case 6 stays with P19. Multi-binding case 11 stays with P23.

Integrated provider accounting was compared with `profiles/deployments/direct-nnpsk0.json`, role `endpoint`, target `portable-host.endpoint.v1`: `provider_retained` count 3 × 12288 = 36864 bytes, and `provider_scratch` count 1 × 4096 = 4096 bytes. The host session puts both peers on one provider. After one active association the high-water retained was 2826 bytes (live 816, 6 blocks). With the old and new attempts both registered the high-water retained was 3338 bytes (live 1328, 10 blocks). The largest single allocation in both runs was 256 bytes. Those counts sit inside the two manifest charges. They are not an MCU budget, not stack, and not the JSON admission scratch.

GCC 15.2.0, CMake/CTest 3.28.1.

- `cmake --build build/host` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "endpoint\.|security\.(handshake|provider_adapter)"` — 32/32 passed, 0 failed, including `endpoint.protected_acl`, `endpoint.protected_rotation`, `endpoint.protected_result`, `endpoint.protected_fragdeny`, `endpoint.protected_drain`, and `endpoint.protected_context`.

## 2026-10-04 — P15 accepted, P16 running

Independent recheck 81817c1e confirmed the three P15 defects are fixed in the current tree. P15 is done. Accepted 2026-10-04 after the recheck of ACL, rotation, the three fixes, and host case 8. Still excluded: relay S10 case 6 (P19), multi-binding case 11 (P23), physical transport, and a measured-in-test retained peak. Retained peaks 2826 and 3338 are log literals inside the direct manifest charges (3×12288 and 1×4096) and are not re-measured by an assertion; that is an evidence limit, not a reason to keep P15 open. P16 is running from baseline `fe0d9a38` plus this uncommitted P15 tree and is not done. No commit.

## 2026-10-04 — P16 selective recovery, running

P16 stays running and is not done. The admitted profile now carries burst_span_ms, forward_delay_ms, return_delay_ms, feedback_guard_ms, feedback_delay_ms, max_probes, max_status, and record_margin_ms. collect_ms stays T_collect. SELECTIVE-32 admission checks the R3 and §11.1 combinations; retry-all does not require those fields. A selective repair sends only the missing slices, in ascending index order, from the saved payload, with a new encode. retry-all resends every slice. A recovered tail is delivered once. A protected fragment retry is sealed again, so the PN and ciphertext change. Manifest bytes, PROFILE_HASH, and RADIO-1 were not edited. Jitter stays 0. No identity reissue. Host state sizes, not total endpoint RAM: dmp_reliability 544, dmp_reassembly_slot 176, dmp_reassembly 336, tombstone 48; state bytes 608 and 1120. Eight-array sums are unchanged.

GCC 15.2.0. `cmake --build build/host` exit 0. `ctest --test-dir build/host --output-on-failure -R "reliability\.direct|reassembly\.direct|endpoint\.(fragment|protected)|identity\.profile_admit"` — 19/19 passed, including endpoint.protected_repair. No stage, commit, push, or flash. `build/host` was not deleted.

## 2026-10-04 — P16 large result slices, running

P16 stays running and is not done: a 1024-byte RSP and a terminal ERR are sliced from the one saved result for selective-32 and retry-all, a missing mask repairs that result without extending deadlines, and `cmake --build build/host` plus the reliability/reassembly/endpoint filter passed 18/18 with no stage, commit, or push.

## 2026-10-04 — P16 coordinator acceptance

Coordinator accepted host SELECTIVE-32 recovery on 2026-10-04 after independent recheck e4350cf5 confirmed the last gap is fixed: dmp_reliability_complete stores a 1024-byte RSP and a terminal ERR once and slices them from that buffer; FRAG_STATUS updates the result mask; repair does not move send_deadline or result_deadline; the test encodes the frames. Earlier review 2a16b7cd accepted the request selective path, a new PN, and retry-all. Missing slices are repaired from one saved payload. A protected retry receives a new PN. retry-all still sends every slice. Host CTest after the result fix was 18/18. This is not physical transport. RADIO-1 was not switched to retry-all. Manifest bytes were not changed. P16 is done. No commit was made in this step.

## 2026-10-04 — P17 static relay, running

P17 is running from baseline `4c00ea5338cb11ef33f9b1c4f48a5982a49dc604` and is not done. P18 was not started. A transparent static-unicast relay in `src/mesh/relay.c` forwards a parsed core frame to the configured next hop. It decrements the remaining-forwards nibble and, when INTEGRITY is present, recomputes CRC32C. SECURITY payload and tag bytes are copied. Cooldown starts at the caller-supplied forward completion and is not moved by a duplicate refused during cooldown. Absolute expiry stays at first admission. The forward and return instants use the admitted profile delays, queue, and the RADIO-1 period 64 / width 42 / cooldown 50 schedule with jitter 0. The selected public PN filter rejects PN>=2^24 without writing the output, the relay cache, the endpoint identity/reliability/reassembly slots, or the security replay window.

Not invented: ACL changes, key rotation, a jitter distribution, SELECTIVE-32 behavior, bounded flooding, or a retry-all switch of RADIO-1. Manifest bytes and PROFILE_HASH were not edited. libdmp does not parse JSON. The receive/forward path does not allocate. Host harness evidence is not physical transport. Relay-state S10 case 6 stays with P19.

GCC 15.2.0, CMake/CTest 3.28.1. `build/host` was not deleted.

- `cmake --build build/host` — exit 0.
- `ctest --test-dir build/host --output-on-failure -R "relay\.|endpoint\.protected|reliability\.direct"` — 15/15 passed, 0 failed, including `relay.transparent`, `endpoint.protected_acl`, `endpoint.protected_rotation`, and `reliability.direct`.

No stage, commit, push, or flash.

## 2026-10-04 — P17 coordinator acceptance

Coordinator accepted the host transparent relay on 2026-10-04 after independent review abfec04c found no defect. A transparent static hop changes only the forward-remaining nibble and, when INTEGRITY is set, recomputes CRC32C; payload and the other header fields are not rewritten. Cooldown and the schedule come from the relay/profile fields, not hardcoded 50/64/42/20 in relay.c. A forward during cooldown returns DMP_BUSY and does not move the cooldown anchor. There is no allocation on the forward path. Host CTest was reported 15/15 and was not rerun by the reviewer. INTEGRITY CRC recomputation was confirmed in source and is not covered by test_relay.c, which does not set INTEGRITY. Physical transport is not included. P17 is done. P18 was not started. No commit was made in this step.

## 2026-10-04 — P18 protected FRAG_STATUS vectors, running

P18 is running from baseline `edde21fdc063806feb4cf3f09fbad0308e59c747` and is not done. P19 was not started. `dev/dmp_generate_recovery_vectors.py` seals FRAG_STATUS with Python cryptography 46.0.4 ChaCha20-Poly1305. `dev/dmp_verify_recovery_vectors.cjs` rebuilds the header, AAD and ciphertext with Node.js v24.11.1 `node:crypto` and does not import the generator. Expected bytes are not produced by `src/reliability` or `dmp_core_encode`. The key and handshake hash are the published NNpsk0 ChaChaPoly `r_to_i_key` and `handshake_hash`; `docs/DMP_v2_Security_Test_Vectors.json` was not modified. The R6 illustrative header `48 0A C1 09 01 01 07 05 01 05` and plaintext `44 00 00 00` are recorded without a tag. Complete frames use receive CID 7 and fresh PNs. Cipher 1 is the supported suite. Cipher 2 and cipher 3 are rejected as outside that suite; AES-GCM is not invoked.

Covered: golden masks for two of eight, N=2 index 0 and N=32 index 31; explicit service 2; a routed return whose AAD zeros the TTL nibble; a two-byte PN; invalid masks (zero, all-N for N=2 and N=32, out of range); payload lengths other than 4; missing, full and non-minimal REPLY_TO; ACK_REQ, FRAG, PAYLOAD_DESC, STATUS, FRESHNESS and INTEGRITY+SECURITY; PN>=2^24; an explicit default service; altered SEQ, REPLY_TO, CID, PN, destination, ciphertext, tag and handshake hash. A TTL-only change still authenticates. `recovery.frag_status` parses those frames with `dmp_core_parse` and does not decrypt them.

Not invented: a JSON parser in libdmp, a manifest or PROFILE_HASH edit, a jitter distribution, NVS or filesystem persistence, identity reissue, a RADIO-1 retry-all switch, or an endpoint judgment of an ineligible or terminal reference. That last check needs retained transfer state and stays with P19. Host fixtures are not physical transport.

GCC 15.2.0, CMake/CTest 3.28.1, Python 3.12.8. `build/host` was not deleted.

- `cmake --build build/host` — exit 0.
- `ctest --test-dir build/host --output-on-failure` — 53/53 passed, including `fixtures.recovery` and `recovery.frag_status`. `harness.subprocess` passed in this run.

No stage, commit, push, or flash. P18 is not done.

## 2026-10-04 — P18 coordinator acceptance

Coordinator accepted the protected FRAG_STATUS vectors on 2026-10-04 after independent review 98a72880 found no defect. The reviewer rebuilt header, AAD, nonce and ChaCha20-Poly1305 output from the recovery annex and SEC-1 rules with a separate out-of-repository script, and all 26 cases and 8 mutations matched. The generator and verifier do not import each other or `src/`. The key is the published NNpsk0 `r_to_i_key`, which opens the published READY packet. `docs/DMP_v2_Security_Test_Vectors.json` is unchanged from HEAD (`dc8ba5a494d4f359402afe289cec733f5e7e12a0`). `fixtures.recovery` requires Node and Python and has no skip return code. The reviewed snapshot hashes were unchanged at the end of review.

Coordinator recheck: `node dev/dmp_verify_recovery_vectors.cjs` exit 0 (26 cases, 8 mutations, cipher 1 only); `ctest --test-dir build/host -R "fixtures.recovery|recovery.frag_status"` 2/2 passed. The reviewer's full run was 53/53.

Not covered: endpoint acceptance of FRAG_STATUS, replay window and old PN, ineligible or terminal references, service 0, a separate SERVICE_ID byte mutation, real AES-GCM frames and physical transport. Reference eligibility needs retained transfer state and stays with P19. `docs/DMP_v2_Recovery_Test_Vectors.json` stays in place; no normative text cites it yet. P18 is done. P19 was not started. No commit was made in this step.

## 2026-10-04 — P19 host recovery gate, not accepted

Worker baseline HEAD `13e2ff6` on `feat/initial-version`. P19 is `running`. It is not done. P12 was not marked done. No stage, commit, push, flash, or DTrack integration. `build/host` was not deleted. Manifests in `profiles/` were not edited. Public headers were not edited.

Three defects were fixed because a P19 test failed against the normative text. Details and the case map are in [DMP_Recovery_Matrix.md](DMP_Recovery_Matrix.md).

- Completed ACK_REQ reassembly did not enter reliability, so there was no acceptance ACK (R4.4). `take_fragment` now presents the assembled plaintext with FRAG cleared.
- A secured payload above the 32-byte seal cap but inside the clear MTU was not fragmented. RADIO-1 N=2 is a 64-byte service-2 REQ and two 32-byte slices.
- A duplicate probe of an incomplete transfer did not arm the next collection, so a lost FRAG_STATUS produced no later status.

Host evidence is not physical transport. RADIO-1 service 2 was exercised without an S7 token; that component is not in the endpoint and needs a public-header change. DIRECT-1 `chunk_bytes` 64 cannot be sealed under `DMP_HS_APP_PLAIN_MAX` 32. The endpoint encoder does not emit ROUTE or CONTEXT, and `dmp_config` has no TTL, so a live endpoint frame is not relay-admissible. The relay-cache check uses one frame sealed by the live association. S10 case 11 stays pending for P23.

Measured in the tests, not copied from a manifest charge: caller node `sizeof` 63872; provider allocator peak 2826; geometry retained payload peak 1986; r6 retained payload peak 512. Geometry moved 6226 tx bytes and 2914 rx bytes. The r6 process ended at 3813 tx bytes and 2088 rx bytes. Retry-all loss was 1212 tx bytes and 1035 rx bytes before the expiry case.

Commands, all exit 0:

- `cmake --build build/host`
- `ctest --test-dir build/host --output-on-failure` — 60/60 passed, including `harness.subprocess`
- `node dev/dmp_verify_security_vectors.cjs` — 4 fixtures, 64 packets, 44 mutations
- `node dev/dmp_verify_recovery_vectors.cjs` — 26 cases, 8 mutations, cipher 1 only

## 2026-10-05 — P19 review fixes, not accepted

P19 stays `running`. P12 was not marked done. No stage, commit, push, flash, or DTrack integration. `include/dmp/`, `profiles/`, `docs/`, `AGENTS.md` and `README` were not edited. `build/host` was not deleted.

`DMP_HS_APP_PLAIN_MAX` is 240, the largest plaintext that fits one direct frame with a 7-byte protected header and a 16-byte tag (`263 - 7 - 16`). Buffers that use the macro (`body[]` in seal/open/seal_record, `plain[]` in `take_frame`, `accepted[]` per attempt) grow with it. `handshake.c` did not need a separate edit.

Sizes, gcc `-fstack-usage`, before to after:

| Object | Before | After | Manifest charge |
|---|---:|---:|---|
| `sizeof(dmp_hs)` | 39160 | 39992 | association 512 endpoint, 256 relay. Already over before this change because each attempt holds an 8208-byte replay bitmap. Delta +832. |
| one `hs_attempt` | 9624 | 9832 | same association rows |
| `accepted[]` | 32 | 240 | 240 fits one 512-byte endpoint row and the 256-byte relay row |
| `dmp_hs_seal_logical` stack | 1360 | 1568 | stacks 12288 endpoint, 4096 relay |
| `dmp_hs_open_logical` stack | 992 | 1200 | same |
| `seal_record` stack | 1024 | 1232 | same |
| `dmp_hs_offer_protected` stack | 960 | 1168 | same |
| `take_frame` stack | 752 | 960 | same |

The deepest receive chain measured here is about 2512 bytes (`dmp_endpoint_rx` 144 + `take_frame` 960 + `open_protected` 208 + `dmp_hs_open_logical` 1200). That is inside both stack charges. The association row was already exceeded and this delta does not bring `dmp_hs` under 512. Manifests were not edited. The 32-byte cap was raised because leaving it would not satisfy that row either, and DIRECT-1 chunk 64 could not be sealed.

Fragmentation no longer uses the 32-byte seal cap. A protected payload fragments only when it does not fit `encoded_mtu` after a 73-byte worst header and tag. A 64-byte RADIO-1 service-2 REQ is one frame with no FRAG. 256/512/1024/993 bytes remain 8/16/32/32 frames at MTU 256. N=2 stays open: at chunk 32 and MTU 256 it is unreachable. A seal or encode failure after admission frees the sender and submits no frame. A duplicate accepted index at the assembly deadline returns `DMP_DEADLINE_EXPIRED` and does not arm collection.

Host evidence is not physical transport. Still open, owner decisions not taken: S7 freshness tokens for service 2, endpoint-originated ROUTE/CONTEXT/TTL, a delayed-completion seam under `synchronous_completion: true`, and the MTU or length that should exercise RADIO-1 N=2. DATA/EVENT with ACK_REQ is `DMP_UNSUPPORTED` for an unfragmented frame and has no submit path. S10 case 11 stays with P23.

`tests/reassembly/test_reassembly.c` changed one expectation from `DMP_DUPLICATE` to `DMP_DEADLINE_EXPIRED` at `now == deadline`. That file was outside the scenario write set; the old assertion encoded the defect.

Measured again, not copied from a charge: caller node 63872; provider peak 2826; geometry retained payload 2048; gaps retained payload 2048. Geometry moved 9356 tx bytes and 9356 rx bytes. The gaps process ended at 8369 tx bytes and 6318 rx bytes.

Commands, all exit 0. gcc 15.2.0, cmake 3.28.1, Node v24.11.1.

- `cmake --build build/host`
- `ctest --test-dir build/host --output-on-failure` — 61/61 passed, including `harness.subprocess`
- `node dev/dmp_verify_security_vectors.cjs` — 4 fixtures, 64 packets, 44 mutations
- `node dev/dmp_verify_recovery_vectors.cjs` — 26 cases, 8 mutations, cipher 1 only

## 2026-10-05 — P19 review findings, still running

P19 stays `running`. P12 was not marked done. No stage, commit, push, flash, or DTrack integration. `include/dmp/`, `profiles/`, `docs/`, `AGENTS.md`, `README`, and `dev/DMP_Validation_Results.md` were not edited. `build/host` was not deleted.

Four review findings were checked against the worktree. Three were fixed. The local-unsent event was stopped because it needs a new public enum.

1. A REQ admitted before activation was dropped on the first poll. `dmp_hs_send_application` returns `DMP_HS_NOT_ACTIVE` both while the attempt is alive and after cancel, and `from_hs` mapped both to `DMP_AUTHENTICATION_FAILURE`. `begin_send` then freed the sender. A live not-yet-active attempt now returns `DMP_BUSY` and the sender stays queued. A terminal attempt still frees the slot. `send_ready` does not publish `DMP_BUSY`, so `dmp_endpoint_poll` is `DMP_OK`. No frame leaves before activation. The same request is delivered after activation (`endpoint.protected_activation`). `scenarios.gaps` `seal-after-admit` still expects `DMP_AUTHENTICATION_FAILURE`.

2. Fragmentation used a fixed 73-byte or 48-byte margin. The endpoint now encodes the exact non-FRAG header, including the security block and 16-byte tag when protected, and fragments only when that size exceeds `encoded_mtu`. `DMP_HS_APP_PLAIN_MAX` 240 remains the seal buffer ceiling. `scenarios.geometry` covers the largest service-2 body that is one frame and the next byte, for radio and direct. Encoders that reject the NULL size probe still use the old margin. RADIO-1 N=2 stays open: at MTU 256 and chunk 32 the first fragmented body is already eight slices.

3. Stopped. `on_reliability_notice` still drops `DMP_REL_EVENT_LOCAL_UNSENT`. `DMP_ENDPOINT_UNKNOWN` is documented as possibly-sent, so it cannot mean "deadline before transmission." Proposed, not added, in `include/dmp/endpoint.h`: `DMP_ENDPOINT_LOCAL_UNSENT = 6`. Empty payload, own request key, no claim of remote cancellation. `deadline-before-tx` would assert that event once. `r7-expiry` would keep `unknowns == 1`.

4. The replay bitmap was `65536/8` bytes per attempt while every manifest uses 1024. `DMP_REPLAY_WINDOW_MAX` now defaults to 1024, is overridable with a compile definition, and is static-asserted to a power of two in [64, 65536]. The bitmap is `ceiling/8`. `W=0` selects 1024. Init rejects `W` above the ceiling (`DMP_HS_INVALID`), including 2048 and 65536 at the default ceiling. The previous `replay_window` comment allowed [64, 65536] in one build; that conflicts with the smaller bitmap, so the ceiling wins. `failed_aead_limit` is unchanged: zero still selects 65536. Manifest totals were not recalculated.

Sizes, gcc 15.2.0, before to after: `dmp_replay_window` 8208 to 144, one attempt 9832 to 1768, `dmp_hs` 39992 to 7736.

An intermediate full ctest before the encoder fallback was 60/61, failing `identity.profile_admit`, because a NULL size probe was treated as "does not fit." The final run below is after that fallback.

Host only. Not physical transport. Still open: S7 freshness tokens, endpoint ROUTE/CONTEXT/TTL, delayed completion, RADIO-1 N=2, manifest RAM charges and `PROFILE_HASH`.

gcc 15.2.0, cmake 3.28.1, Node v24.11.1.

- `cmake --build build/host` — exit 0.
- `ctest --test-dir build/host --output-on-failure` — 61/61 passed, 0 failed, including `harness.subprocess`.
- `node dev/dmp_verify_security_vectors.cjs` — exit 0, 4 fixtures, 64 packets, 44 mutations.
- `node dev/dmp_verify_recovery_vectors.cjs` — exit 0, 26 cases, 8 mutations, cipher 1 only.

## 2026-10-05 — P19 local-unsent, size probe, replay ceiling wording

P19 stays `running`. P12 was not marked done. No stage, commit, push, flash, or DTrack integration. `profiles/`, `docs/`, `AGENTS.md`, `README`, and `dev/DMP_Validation_Results.md` were not edited. `build/host` was not deleted. The encoder-port sentence was not added to `include/dmp/reliability.h`.

`DMP_ENDPOINT_LOCAL_UNSENT = 6` is now a public endpoint event. `on_reliability_notice` maps `DMP_REL_EVENT_LOCAL_UNSENT` to it: empty body, the request's own key, no claim of remote cancellation. `DMP_ENDPOINT_UNKNOWN` stays possibly-sent. `scenarios.gaps` `deadline-before-tx` expects one `LOCAL_UNSENT` and `unknowns == 0`. `deadline-before-activation` is the same outcome when the queue deadline passes while the attempt is still not active: the earlier poll stays `DMP_OK`, sends nothing, and keeps the sender. `scenarios.r7` `r7-expiry` keeps `unknowns == 1` and `local_unsents == 0`.

The 48/73-byte fragment margin is removed. A NULL size probe whose capacity is `encoded_mtu` must return `DMP_OK` or `DMP_LIMIT_EXHAUSTED`. Any other status frees the sender, sends no frame, and for a new REQ reports `LOCAL_UNSENT`. `budget_encode` answers the probe with `dmp_core_encode_header`. `dmp_core_encode` cannot answer it: `out.data == NULL` and a non-zero capacity is `DMP_INVALID_ARGUMENT` (`src/core/codec.c` line 420); capacity 0 falls through to `DMP_LIMIT_EXHAUSTED` for every non-empty frame, so it never reports a fit. `src/core` was not changed.

The compilable replay ceiling is a power of two in [1024, 65536] because the default W of 1024 must fit. `tests/security/test_handshake.c` accepts `W <= DMP_REPLAY_WINDOW_MAX` and rejects `2 * ceiling` when the ceiling is below 65536.

Host only. Not physical transport. Still open: S7 freshness tokens, endpoint ROUTE/CONTEXT/TTL, delayed completion, RADIO-1 N=2, manifest RAM charges, and the `include/dmp/reliability.h` encoder-port sentence.

gcc 15.2.0, cmake 3.28.1, Node v24.11.1.

- `cmake --build build/host` — exit 0.
- `ctest --test-dir build/host --output-on-failure` — 61/61 passed, 0 failed, including `harness.subprocess`.
- `node dev/dmp_verify_security_vectors.cjs` — exit 0, 4 fixtures, 64 packets, 44 mutations.
- `node dev/dmp_verify_recovery_vectors.cjs` — exit 0, 26 cases, 8 mutations, cipher 1 only.

## 2026-10-06 — P19 RAM tooling handoff, endpoint runtime gate remains open

P19 remains `running` and is not accepted. This closes one bounded step: the
RAM report now separates P01B provider-only fixture measurements from the
required libdmp endpoint lifecycle. The probe does not instantiate a
`dmp_endpoint`; its repeated provider cipher calls are not DMP request/result,
loss-retry, or reconnect-overlap measurements. Endpoint phases
`initial`, `handshake_peak`, `active_steady`, `request_result_retry`, `cleanup`,
and `reconnect` remain `not_measured`. Both report/layout `--check` paths fail
closed until those runtime phases and reconnect overlap are measured. Profile
charges remain reservations/projections; this step provides no measured
endpoint RAM total or charge reduction and did not edit manifests.

RAM-worker checks (reported in its handoff; the coordinator did not rerun them
in this paused step): `python -B tests/memory/test_ram_report.py` passed 12/12;
strict GCC syntax checking of `ram_measure.c`, Python AST parsing and
`git diff --check` passed. The Cortex-M compile-only probe reported 22 layout
records and 3 private sizes: `dmp_endpoint` 2144 B, freshness slot 88 B,
`dmp_hs` 7712 B and provider 672 B. These are ABI layout values, not runtime
peaks. No profile runtime allocator values were produced; `build/p19-gcc` has
an empty `DMP_SODIUM_SOURCE_DIR` and no `dmp_ram_measure` executable. The
provider adapter's process-global active provider prevents independent peer
and endpoint provider instances in the same process; an isolated peer-process
IPC harness or verified endpoint traces plus a runnable P01B build remain
necessary for one-device lifecycle measurement.

Coordinator verification attempt `job_01M4725W2BCFY9HAVCT8WKH9E5` failed before
the script started (`agent_disconnected`). No local retry was run. The staged
index tree remains `bf267a3107329d1ca9e927cf484369bc2d46f454`; no stage, commit,
push, hardware operation or DTrack integration was performed. P19 functional
review, full host gate, recovery-matrix reconciliation and final acceptance
remain pending.

## 2026-10-07 — P19 N=2/full-loss corrections and initial endpoint RAM phase

Resumed on `feat/initial-version` at `bd1d5c9e631a9d9a817d1c2844ff0976c92da6e3`;
the index remained unchanged. The RAM worker completed a bounded handoff and
stopped writing. No changes were staged, committed, pushed, flashed, or
integrated into DTrack.

The exact encoder showed that a 64-byte service-2 body at MTU 128 is still one
protected frame. TEST-RADIO-N2 now uses a 119-byte forward/return/encoded MTU;
the manifest digest and expected derivation were updated. The 64-byte workload
then emits two 32-byte fragments. Its index-0-loss case receives mask `0x01`
and repairs only index 0. The all-initial-loss R6 case now continues from probe
index 7 (`DMP_INCOMPLETE`) through missing mask `0x7f`, repair indices 0–6,
one acceptance and ACK. RADIO-1 and retry-all manifests did not change.

RAM worker added a real endpoint-initialization executable for minimal 128- and
256-byte profiles. Coordinator rebuilt and reran it after adding checked
provider allocation counters. Both outputs report a 10,096-byte caller-owned
endpoint bundle, 1,328-byte caller-owned provider state, zero provider-retained
current/peak/largest-allocation bytes at the unassociated initial phase, and
all later phases `not_measured`. Manifest RAM charges are 32,590 and 33,614
bytes for these profiles; those are reservations, not measured peaks. No
handshake, protected exchange/retry, cleanup/reconnect, MCU, or physical RAM
result is claimed. Keep fail-closed RAM checks and the 131,072-byte cap.

Checks run by the coordinator:

- `python -B tests/profiles/test_deployments.py` — 14/14 passed.
- `python tools/validate_profile.py --expect-sha256 46ef7a08f2b6caf53d13d7c2c900e522c87286af313e49a70f5249a077fb7376 profiles/deployments/radio-nnpsk0-n2.json` — valid; encoded frame 119 bytes, establishment traffic 1,666 bytes.
- `cmake --build build/host --target dmp_test_recovery_gate --parallel 2` — passed after the checked-Sodium configure step.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\\.(geometry|r6|async_radio)$"` — 3/3 passed.
- `cmake --build build/p19-ram-endpoint-gcc --target dmp_ram_endpoint_initial --parallel 4` — passed.
- `ctest --test-dir build/p19-ram-endpoint-gcc -V -R "^memory\\.test-direct-minimal-(128|256)\\.endpoint_initial$"` — 2/2 passed.

The recovery matrix and work board now reflect only the verified R6 full-loss,
delayed-status, TEST-RADIO-N2, and initial-RAM progress. Other stale matrix
rows still require reconciliation. Independent final review and the full host
gate remain pending; P19 remains `running` and unaccepted. See
`dev/DMP_P19_checkpoint_2026-10-07.md` for the precise resume point.

## 2026-10-07 — P19 matrix reconciliation after publication

The user authorized committing and pushing the initial-RAM/N=2/full-loss step.
Commit `e173b3a` (`feat(p19): add recovery and initial RAM evidence`) is on
`origin/feat/initial-version`. Work continued from that pushed snapshot; no
hardware or DTrack integration was performed.

Reconciled stale matrix rows against the current endpoint, recovery tests and
the binding 2026-10-05 owner direction. Freshness grant/expiry/quota/duplicate
coverage, routed REQ/RSP/ACK/FRAG_STATUS/TELEM over the host relay, reliable
DATA/EVENT, fragmented result loss/duplicate requests, distinct-key association
mismatch, and the PN/SEQ boundary limits are now stated from their named tests.
R7 no-slot, fragmented result/status overlap, a valid PN near 2^24, SEQ wrap,
explicit origin TTL 0, CRC after a TTL edit, narrower egress and independent
peer coverage remain open or partial; no physical-radio claim is made.

Checks run on the committed code before these evidence-only matrix updates:

- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.(freshness|relay_sample|feedback|r7)$"` — 4/4 passed.
- `ctest --test-dir build/host --output-on-failure -R "^(scenarios\.(async|gaps)|identity\.profile_admit)$"` — 3/3 passed.

P19 remains `running` and unaccepted. Independent review of `e173b3a` found the
best-effort fragment geometry defect recorded below; follow-up review confirmed
the fix. The next implementation milestone is a process-isolated peer/provider
path for the single-device endpoint RAM phases; keep lifecycle phases
`not_measured` until they are actually observed, and retain the existing
131,072-byte cap.

## 2026-10-07 — P19 best-effort fragment geometry review fix

Independent review of pushed commit `e173b3a` found that
`dmp_endpoint_submit_fragmented` checked only the short final slice. A 99-byte
message at chunk size 98 could therefore be admitted although its first
protected 98-byte slice exceeded MTU 128; the later poll failed and left the
best-effort transfer live. The endpoint now probes a full-size first slice
before allocating SEQ or retaining transfer state. The geometry regression
asserts early `DMP_LIMIT_EXHAUSTED`, no transmission or live fragment transfer,
and unchanged SEQ.

Checks:

- `cmake --build build/host --target dmp_test_recovery_gate --parallel 2` — passed; sandboxed invocation stalled during CMake regeneration, then the same exact command passed with approved temporary-file access.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.geometry$"` — 1/1 passed.
- Independent follow-up review of `src/endpoint/endpoint.c` and
  `tests/scenarios/recovery_gate.c` confirmed the finding resolved and found no
  new actionable issue.

This closes that geometry defect only. P19 remains `running` and unaccepted;
the lifecycle RAM harness and remaining recovery cases are still pending.

## 2026-10-07 — P19 async no-slot and result/repair race

Added `scenarios.async_radio` case `async-radio-no-slot-result-race` on the
explicit asynchronous TEST-RADIO-N2 profile. A real protected service-1 REQ
occupies the receiver's only assembly slot; a distinct authenticated REQ is
refused with `DMP_QUOTA_EXHAUSTED` without replacing the live transfer. The
receiver still emits the due FRAG_STATUS with mask `0x04`, repairs the missing
last slice, and dispatches the request once. Its RSP reaches the origin while
the repair's local TX-completion callback remains outstanding; the result is
reported exactly once and no `UNKNOWN` is emitted. The RSP is unfragmented, so
fragmented-response/FRAG_STATUS overlap remains open.

Checks:

- `cmake --build build/host --target dmp_test_recovery_gate --parallel 2` — passed after CMake regeneration required approved temporary-file access.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.async_radio$"` — 1/1 passed.
- `git diff --check` — passed for the current worktree.

RAM worker `/root/ram_tooling` extended the separate-process probe to send the
full manifest-sized reliable request (128 or 256 bytes) with a dropped frame
and fresh-PN retry; the 256-byte request is reassembled by the peer. The first
independent lifecycle review then found that the harness did not use the exact
manifest digest/security budget and repeated deterministic handshake entropy
on reconnect. Those findings invalidate the current profile/reconnect claims;
the worker is repairing the harness before its RAM output is accepted.

## 2026-10-07 — P19 async result/status and route boundary coverage

Added `async-radio-fragmented-rsp-status-overlap` to the explicit TEST-RADIO-N2
scenario. It emits a three-fragment RSP, drops the last slice, delivers
FRAG_STATUS mask `0x04` while the sender's local completion for that slice is
pending, then proves only index 2 is repaired and the exact result is delivered
once. The earlier no-slot/result race now reserves its synthetic second SEQ
through the endpoint identity allocator.

Added endpoint-origin TTL=0 coverage and a routed endpoint request rejected by
a narrower egress MTU without relay-cache reservation. Existing
`relay.transparent` assertions prove the integrity-only CRC is recomputed after
TTL decrement and the missing-frame-CONTEXT/narrow-egress failures preserve
output state.

Checks:

- `cmake --build build/host --target dmp_test_recovery_gate dmp_test_relay --parallel 2` — passed.
- `ctest --test-dir build/host --output-on-failure -R "^(scenarios\.(async_radio|relay_sample)|relay\.transparent)$"` — 3/3 passed.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.async_radio$"` — 1/1 passed after adding fragmented-RSP overlap.
- Independent read-only review confirmed the SEQ reservation fix and the TTL=0/narrow-egress assertions. A separate fragmented-RSP follow-up found no issues in that scenario.
- Earlier RAM lifecycle CTests were 2/2, but that run does not close RAM acceptance because the subsequent independent review found the profile/config and repeated-entropy defects above. No MCU peak is established.

P19 remains `running` and unaccepted. The manifest-bound RAM harness repair, valid fresh-handshake reconnect evidence, remaining PN/SEQ/profile cases, final independent review and full host gate are still open.

## 2026-10-07 — P19 RAM evidence fixes and independent recheck

The first review of the corrected process-isolated RAM harness found two evidence defects: it reported the bootstrap hash as the association epoch, and its 256-byte peer-assembly assertion allowed a zero-assembly pass. The coordinator now records the actual traffic epochs returned by `dmp_hs_epochs` separately for initiator and responder, requires both to change on reconnect, requires the 256-byte request to produce exactly four fragments and one exact 256-byte assembly, and requires the 128-byte request to remain one unfragmented frame.

After those changes:

- `cmake --build build/p19-ram-endpoint-gcc --target dmp_ram_endpoint_process --parallel 4` — passed.
- `ctest --test-dir build/p19-ram-endpoint-gcc --output-on-failure -R endpoint_lifecycle` — 2/2 passed.
- Direct JSON parsing confirmed both manifest digests, full request sizes, retry, fragment/assembly counts, four distinct old/new traffic epochs, and stale-frame `DMP_AUTHENTICATION_FAILURE` without dispatch.

Corrected host measurements: caller-owned current requested bytes are 18,328 (128) and 19,224 (256); requested high-water including provider peak is 19,805 and 20,701; provider current after handshake is 408, lifetime peak 1,477, and largest allocation 256. The 256-byte request assembles once at the peer. The response fixture is 17 bytes. Peer memory, allocator metadata/alignment, task stack high-water, scratch allocation origin and physical MCU peak remain outside the measured total or unknown. No manifest charge or 131,072-byte cap changed. The focused independent read-only review of the final RAM source found no actionable findings; it did not rerun the build or CTests.

## 2026-10-07 — Endpoint SEQ exhaustion boundary

Added `seq-exhaustion-endpoint` to `scenarios.gaps`. It seeds the active authenticated endpoint identity at `UINT32_MAX` as a bounded boundary injection, then sends a real protected TELEMETRY frame and checks the wire SEQ. The next two telemetry polls and a reliable service-1 REQ return `DMP_LIMIT_EXHAUSTED`; no additional frame or live sender is left, and the identity remains exhausted without wrapping.

Checks:

- `cmake --build build/host --target dmp_test_recovery_gate --parallel 2` — passed.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.gaps$"` — 1/1 passed.
- `build/host/tests/scenarios/dmp_test_recovery_gate.exe gaps` — emitted `seq-exhaustion-endpoint ... outcome=pass`; the existing `pn-limit-receive-guard` also passed.
- `git diff --check` — passed; only Git LF-to-CRLF notices were emitted.
- Independent read-only review found the capped `take_queue` could hide extra terminal frames. Added `CHECK(left.wire.n == 1)` before draining the queue; rebuilt and reran the same CTest/direct scenario. The reviewer follow-up confirmed the counterexample now fails and reported no new findings; it did not rerun tests.

The test starts at the terminal counter value rather than iterating through all 2^32 SEQs. Endpoint SEQ exhaustion is covered; authenticated receipt of a valid PN near 2^24 and recovery-specific invalid-profile behavior remain open. P19 remains running and unaccepted pending those rows, independent final review and the applicable host gate.
