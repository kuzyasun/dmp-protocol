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