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
