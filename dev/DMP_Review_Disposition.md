# Independent review: verified disposition

Date: 2026-09-26. Scope: the operator-supplied review, current documentation and
plans. Implementation remains paused. This is not a new whole-protocol audit,
provider approval, endpoint conformance result or physical transport claim.

The supplied review was treated as hypotheses. The coordinator checked the
actual text and calculations, used two bounded read-only reviewers, and made
only the corrections/clarifications recorded below. No crypto dependency was
adopted and no package was accepted.

## Baseline and evidence

- Review input and initial working-file hashes: [baseline](evidence/review-20260925/baseline.json).
- HEAD remains `afd460c24919b58296883c3b60b497149ad4366c`.
- Initial index SHA-256 was `930f2d356957546608ee5cee7ea4a823072195da32e6d7f0d93e43b0c654b8b7`.
  During the interruption, the index changed outside the coordinator's commands;
  the documentation corrections now appear staged. Preserve that new state,
  recorded in [resume baseline](evidence/review-20260925/resume-baseline.json),
  rather than restoring the earlier index.
- The coordinator issued no stage, reset, commit, push or publication commands.
  Existing scaffold, fixture helpers, fixture JSON and LICENSE are unchanged
  against the review baseline, as checked by SHA-256.
- Actual calculation/link/fixture results: [checks](evidence/review-20260925/checks.json).

## Normative/documentation claims

| ID | Claim | Verification and disposition |
|---|---|---|
| S01 | SELECTIVE-32 response timeout misses a forward delay | **Confirmed and corrected.** R3 defines forward delay from local completion to remote admission; R4 starts its collection timer at first slice admission. If only the last slice survives, status can arrive at `tL + 2*forward_delay + burst_span + feedback_guard + feedback_delay + return_delay`. The old lower bound could schedule a premature probe. R3 now contains the corrected bound, its derivation and equal-deadline handling. |
| S02 | Relay cooldown/count coordination is insufficiently explicit | **Partly confirmed; proposed universal inequalities rejected.** Main §10.4 already requires coordination and permits bounded delivery failure. `max_bursts` includes the initial burst, so `1 + max_bursts` double-counts it; delayed duplicates can consume additional forwards anyway. R3 now requires a checkable per-hop schedule/count/expiry/airtime envelope under stated duplication and delay assumptions. It does not promise delivery under unlimited hostile duplicates. |
| S03 | Remote reboot leaves an old association at the surviving endpoint | **Real deployment-policy gap, not a mandate for automatic eviction.** Local reboot destroys local state; it does not notify the other endpoint. S3.1 forbids implicit eviction and S9 already requires association limits and rotation/drain policy. S8 now explicitly requires per-pair limits and admission/replacement/full-capacity behavior for this case. A one-slot deployment may refuse until local policy releases old state; immediate restart recovery is not claimed. No same-principal automatic drain or cross-association state transfer was added. |
| S04 | COBS canonical variant differs at full blocks and lacks vectors | **Boundary coverage gap confirmed.** §15.2 already selects the trailing-empty-block variant; its choice is not itself a wire bug. Added exact 254/255/508-byte nonzero-run vectors, encoded lengths 256/257/511, negative shortened encodings and an interoperability note. The selected canonical encoding is preserved. An independently inspected COBS implementation demonstrates the alternative endpoint-of-run behavior; see external evidence below. |
| S05 | RADIO-1 freshness requires `send_horizon <= lease` | **Proposed inequality rejected; feasibility wording clarified.** Grant age, queueing and final new-message admission matter. A command accepted at 1 s may legally recover a lost receipt at 70 s after a 60 s token expires; its 90 s transmission horizon is not a freshness violation. Conversely, a 40 s horizon does not ensure acceptance if the grant was already delayed 30 s. S7 and P02 now distinguish acceptance bounds from receipt recovery and forbid replacing the token on the same identity. No assertion that all LoRa commands exceed 60 s is supported without a concrete binding/schedule. |
| S06 | Main §24 is stale | **Confirmed and corrected.** Before editing it instructed implementations to standardize selective recovery later, although the recovery annex already defines it, and duplicated a different implementation order. The section is now explicitly informative and points to the plan/board while preserving release evidence requirements. The issue was stale content, not a broken section anchor. |
| S07 | SAMPLE-1 oversized REQ could map to STATUS 3 or 7 | **Confirmed overlap and clarified precedence.** Configured message-size admission uses STATUS 3; schema length/opcode validation within that admitted limit uses STATUS 7. The added two-byte request example covers both configured-limit cases. Authentication and retained-rejection prerequisites remain unchanged. |
| S08 | PN >= 2^24 relay behavior is not explicit | **Endpoint rule confirmed; relay screening is not universally mandated.** S8 now explicitly says endpoint receiver. Structural ULEB64 validity does not imply endpoint acceptance. No new mandatory gateway filter or authenticated relay replay state was invented; selected profiles must declare any relay public-descriptor screening used in interoperability tests. |
| S09 | Replace the total AEAD-failure cap with rate limiting | **Not a demonstrated defect.** S8 already requires ingress/global rate limiting and a finite per-association verification-work cap, with the availability tradeoff stated. A rate-only replacement would remove the total-work bound. Preserve the current policy; a different security tradeoff requires an explicit design decision. |
| S10 | Tradeoffs has a stale revision-7 heading and invalid 4 KiB workload | **Not a normative contradiction; editorial clarification only.** The text explicitly describes decisions introduced in revision 7 and retained in revision 8, and already mentions application chunking. Clarified the table heading and that a 4 KiB application object consists of individually admitted messages no larger than 1,024 bytes or the lower path limit. No family ceiling was raised. |
| S11 | DTracker vs DTrack naming | **Editorial consistency only.** Both occurrences referred to the current product/firmware, not a wire identifier. Standardized them to DTrack; historical protocol-name meanings in other repositories were not changed. |

## Plan and workflow claims

| ID | Claim | Verification and disposition |
|---|---|---|
| P01 | Provider feasibility may block the plan; allow a custom HandshakeState | **Risk accepted, workaround not authorized.** The existing P01 is deliberately a blocking capability gate. Provider API inspection shows tentative-state strategies do exist, but does not prove a suitable maintained ESP32-S3 provider. Added candidate screening to P00 before selection, including pin-verification rollback, nonce/AAD, erasure, maintenance/license and target constraints. A custom Noise state machine over maintained primitives remains custom Noise and is not allowed merely because fixture tests pass. No claim that all C candidates are unusable was established. |
| P02 | Independent peer starts too late | **Scheduling proposal, not a correctness defect.** Current P20/P21 gates also freeze full workloads and binding contracts. Moving only the codec earlier can be useful, but does not justify bypassing those inputs or acceptance gates. Added an early independent read-only contract/vector review at P03 before interface freeze; retained the implementation dependency graph. |
| P03 | P18 protected feedback vectors can be produced earlier | **Valid optimization, no missing acceptance gate.** P18 is already independently generated/verified from normative inputs and mandatory before P19. Its schedule does not authorize implementation-derived expected bytes. Retained dependencies rather than redesigning dispatch merely to optimize parallelism. Earlier generation may be scheduled explicitly later without changing conformance requirements. |
| P04 | Manifest bytes are hashed but interpretation contract is not explicit enough | **Confirmed planning gap and corrected.** P02 must publish the versioned written contract/schema, field/unknown/duplicate rules, units, constraints and interpretation corpus. P03 freezes common bytes plus expected interpreted values. The independent peer independently parses those inputs; shared parser/validator code is excluded. DMP still does not acquire a universal implicit JSON canonicalization. |
| P05 | Phase 3 is necessarily plaintext-only | **Overstatement; existing provisional secure contexts were already allowed.** P09 now explicitly exercises compact protected references/context isolation as well as full unprotected identities. P12 evidence remains provisional where appropriate and requires actual P15 SEC-1 reruns. No early production authentication bypass or reordered activation was introduced. |
| P06 | Continuous embedded compilation/allocation evidence is absent | **Confirmed plan gap and corrected.** Added ESP32-S3/ESP-IDF 6.x compile-only checks from P08, linker map/size tracking, core allocator-reference checks and initialized hot-path allocation instrumentation, with later gate reruns. Provider/setup allocations and host-vs-MCU memory evidence remain separate. No embedded build or runtime result is claimed now. |
| P07 | Harness-to-Python boundary is unspecified | **Confirmed planning gap and corrected.** P04 freezes a bounded versioned subprocess interface to a C host executable linked with real endpoints before P07. Python supplies scenarios/seeds and consumes redacted results; it cannot substitute protocol state machines. Exact interface fields remain a P04 deliverable, not a newly implemented API. |
| P08 | Shared filesystem/model can correlate independent-peer mistakes | **Residual risk confirmed and documented.** Require a fresh context and recorded allowed input set; prefer a distinct language and independent reviewer/model where suitable. Neither a model name nor a different language proves independence. No formal clean-room claim is made. |
| P09 | A commit is required as P00 baseline | **Rejected.** Dirty-file hashes, index entries and preserved diff hashes identify the actual snapshot more precisely than HEAD alone. Committing would also violate the owner's explicit instruction. |
| P10 | AGENTS contains unavailable model names | **Not true of the working file reviewed.** It delegates model routing to the global policy; the named Luna/Sol models are also available in this session. No model-name rewrite is justified. |

## Narrow P22 follow-up and reviewer reconciliation

The previously interrupted P22 review was completed read-only by
`/root/p22_plan_review` (`gpt-6-luna`, xhigh). Its requirements and dependencies
were consistent. The remaining wording improvement is now explicit in both
plan and work packages: test smaller-egress-MTU and missing/wrong-context
failures in **each** direction of the implemented mixed Stream R/packet path.
This closes that plan review, not P22 implementation.

Two additional bounded fact checks used `/root/review_timing_claims`
(`gpt-6-astra`, high) and `/root/review_wire_claims` (`gpt-6-luna`, xhigh).
The coordinator verified conclusions directly. In particular, the second
reviewer's rejection of the §24 finding checked anchor existence instead of
stale content, and its reboot analysis considered only the restarted endpoint.
Those conclusions were not accepted; the actual stale paragraph and surviving
endpoint case support S06/S03 above. Its COBS-vector and STATUS-precedence
findings agree with direct inspection.

Final read-only review by `/root/review_timing_claims` found no actionable
findings in the corrected document snapshot. A subsequent separate review of
the P02/P17 public-descriptor-policy delta also passed. These results cover the
document corrections only; no provider or implementation gate was accepted.

## Checks and limits

- `node dev/dmp_verify_security_vectors.cjs`: RBO job
  `job_01M3CZHWR1J3873F5F8QV3QVA0`, Node v24.18.0, exit 0; **4 fixtures,
  64 packets, 44 mutations, 64 wrong-key rejections, 128 structural rejections**.
  This verifies the existing fixture corpus, not corrected timer/state behavior.
- Independent Python arithmetic reproduced §22.7 CRC32C, short COBS, Stream R,
  and the added boundary vectors. It also reproduced 274/406-byte direct
  establishment totals and the timeout counterexample (33 old vs 53 required
  time units for B=10, D=20, G=F=R=1).
- Seventeen local Markdown links/anchors in the two plans resolve.
- `git diff --check` passes. No new endpoint tests/builds/hardware operations
  were run. This review did not independently reimplement every §22 wire example
  or certify the original reviewer's entire manual byte audit.
- Normative draft clarification changes are explicit above: R3's timing bound
  tightens admissible schedules; SAMPLE-1 rejection precedence is deterministic;
  canonical wire layouts and crypto fixture bytes remain unchanged. New baseline
  hashes must be used when implementation resumes. P01, manifests, real endpoint
  conformance and physical gates remain unpassed.

## External evidence inspected

- [COBS-C encoder source](https://github.com/cmcqueen/cobs-c/blob/main/cobs.c):
  tests end-of-input before opening another full-run block, unlike DMP's chosen
  trailing-empty-block encoder. This supports the compatibility note, not a
  claim about every COBS library.
- [Noise-C README](https://github.com/rweather/noise-c): describes a C reference
  implementation under MIT; that alone does not prove production maintenance or
  compatibility with current SEC-1.
- [noise-protocol HandshakeState API](https://docs.rs/noise-protocol/0.2.1/noise_protocol/struct.HandshakeState.html):
  explicitly describes cloning before a destructive failed receive. This is API
  evidence for one candidate strategy, not erasure/target/provider acceptance.
- [Snow HandshakeState source](https://github.com/mcginty/snow/blob/main/src/handshakestate.rs):
  contains checkpoint-based handling; its presence alone does not prove rollback
  after external pinned-peer policy rejection or bounded ESP32-S3 resources.


## 2026-09-26 — Owner-approved four amendments

The owner approved the previously discussed four changes, not automatic adoption of all review recommendations. These supersede the earlier deferred disposition for these points: (1) protocol STATUS 1–7 ERR is always best effort, while terminal application-result ERR retains reliable exchange; (2) replies use their referenced message's service, with canonical default omission and explicit control/nondefault service; (3) SAMPLE-1 has a designated READ initialization procedure and persistent producer epoch reservation; (4) manifests and gates require aggregate resource envelopes and a hard cumulative failed-AEAD ceiling of 65536, configurable downward.

Baseline is now main revision 9, SEC-1 revision 4, SAMPLE-1/2 and DIRECT-1/3 / RADIO-1/3. Wire major 2, BOOT_VERSION 2 and SELECTIVE-32 recovery revision 1 remain. Old draft compatibility is not added. SAMPLE epoch transition closes associated service exchanges; numeric ESP32-S3 RAM/flash ceilings still require P00/P01/P03 decisions/evidence. All implementation packages remain pending.

Fixture profile /2 declares default application service 1 and explicit service 2. Its request receipts now explicitly match service 2. The exact new manifest changes the Noise transcript and derived public test keys, so fixtures were regenerated rather than hand-edited. The upstream Cacophony SHA-256 is enforced before regeneration. No production Noise code was created.

Two explicit Noise receive-error policies remain a discussion candidate only. S3.1 still requires preserved pre-flight state after an invalid expected flight. The owner has not yet selected a replacement policy; P01 remains bound to the current requirement. Any future dual-policy design must specify preprovisioned choice, provider capabilities, resource limits and independent negative tests; no automatic fallback is assumed.

Evidence: [approved amendments](evidence/approved-amendments-20260926/baseline.json). Implementation remains paused; no stage/commit/push or hardware action.
