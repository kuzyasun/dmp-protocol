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
