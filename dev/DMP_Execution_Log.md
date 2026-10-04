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
