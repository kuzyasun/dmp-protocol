# P21 peer acceptance plan — 2026-10-12

> **Superseded manifest direction (2026-10-14):** the historical P22 decision
> below says to add contract 3 and preserve contract 2. The current owner
> direction is one manifest format 1.0 with no compatibility paths; see
> [the continuation decision record](DMP_Continuation_Decisions_2026-10-13.md#superseding-owner-decision--one-manifest-format-10-2026-10-14).

## Baseline and boundary

- Repository: `C:\projects\gemslibe\dmp-protocol`
- Branch / HEAD: `feat/initial-version` / `734d20aa7d078b4799559f55050dca4dc4d2fac5`
- Preserve the uncommitted P21D implementation, tests, plan, checkpoint, and workboard changes.
- Keep changes in `tests/peer/`; do not edit manifests, schemas, normative documents, primary `src/` or `include/dmp/`, C tests, traces, or submodules.
- This package targets independent-peer host/simulation acceptance only. P22/P23, MCU/runtime/RAM, and physical transport remain separate.

## Work

1. Fix the four P21 audit findings against the frozen normative contract: unknown critical extension admission, forbidden fixed-schema PAYLOAD_DESC, derived Stream R candidate timeout, and SEC-1 SEQ exhaustion without wrap.
2. Add protected-frame regressions and close the highest-risk P21B protected coverage gaps: result correlation, retained rejection, fragmented retained-result or REQ expiry/tombstone behavior, and terminal request validation.
3. Run focused affected tests, the complete peer suite, compileall, security/recovery fixture validators, and diff checks on the final frozen snapshot.
4. Obtain one independent read-only review of the final code/tests and verify reviewed hashes before and after.
5. Record actual input paths, context separation, shared-filesystem boundary, and model-correlated interpretation risk. Update the P21 board/checkpoint only to the evidence actually established.

## Audit findings at start

- Main §6 requires an unknown critical extension to block local delivery; the live protected SAMPLE READ currently reaches `request_accepted`.
- The frozen test manifest fixes the schema and omits PAYLOAD_DESC for both services; a protected service-2 request currently reaches the application handler with an unexpected descriptor instead of retained STATUS 2.
- Stream R requires `frame_tx_ms + max(forward_delay_ms, return_delay_ms) + record_margin_ms`; DIRECT-1 computes 26 ms, but the endpoint currently uses `feedback_delay_ms` (110 ms).
- Main §5 and SEC-1 prohibit SEQ wrap; DIRECT-1 currently emits `0xffffffff`, then reuses SEQ 1 in the same live association.
- Existing protected P21C coverage has nine P21B scenarios. The missing categories include negative result-ACK correlation over authenticated frames, retained invalid-request replay, fragmented retained-result retry/expiry, and protected REQ expiry/tombstone/metadata edges.
- Historical P21 evidence lacks complete actual-read inventories for every package, especially P21A; the independent audit treats this as an evidence gap, not evidence of source reuse.

## Historical provenance audit

The records currently available establish these package boundaries, but not full actual-read inventories or enforced filesystem isolation:

| Package | Recorded context/base | Input/access evidence | Review evidence |
|---|---|---|---|
| P21A | No implementer context/session, start commit, or worktree recorded. | P20 permitted/prohibited categories only; no actual supplied-file/read-set or filesystem boundary recorded. | RBO run 33/33; independent GPT-6.1-sol High review, no findings. |
| P21B | Fresh broker detached worktree from `f950f7a…`; session/turn and snapshots recorded. | Assignment excluded primary `src/`, C tests, and traces; no complete read inventory or enforced read boundary. | Suite 166/166; 12 frozen hashes reviewed, no findings. |
| P21C | Fresh current-workspace session/turn `turn-539d9c5070d56917ed51b439`, baseline `eb8ae4c…`. | Primary paths reported unused; exact files supplied/read and actual filesystem access not recorded. | Suite 238/238; eight frozen hashes reviewed, no findings. |
| P21D | Plan records branch and base `734d20a…`; no implementer session/context ID or worktree recorded. | Plan lists inputs/exclusions and checkpoint reports primary paths unused; actual read set and filesystem access not recorded. | P21D 46/46, full peer suite 284/284; ten frozen hashes reviewed, no findings. |

The current repair package uses a new, fresh-context GPT-6-luna High native agent. Its read set and any scope deviation will be recorded from its handoff. Shared workspace access is not an enforced read ACL; the record can state observed paths and instructions only. This corrective package does not retroactively establish P21A–D input inventories. Shared-model interpretation remains correlated across the peer and primary implementations. No formal clean-room claim is made.

## Acceptance stop conditions

- Do not accept P21 while a required protected behavior, actionable review finding, or required fresh-context/input-set record remains unresolved.
- Do not claim formal clean-room certification or promote host/simulation evidence to binding, MCU, or physical qualification.
- Do not commit or push this package without a direct user request for this package.

## Follow-up review findings — pre-repair snapshot

Independent GPT-6.1-sol High review of the first repair snapshot verified these hashes before and after review:

| File | SHA-256 |
|---|---|
| `tests/peer/dmp_peer/endpoint.py` | `14BBB743462B1DB750F474D8A8F2745B886850C74C55263F01EA2B939B957F68` |
| `tests/peer/tests/test_p21c_s10.py` | `33A638362B4CBD989D0246B455A1564CD03C8FE9819FEB4E1213A29257AE5CCA` |

The review confirmed the descriptor rejection/retained STATUS 2 and Stream R boundary corrections, but found two remaining actionable defects:

1. The unknown-critical-extension guard was in the protected receive path only. A `test_only_disable_sec1=True` service-2 REQ with an unknown critical extension still reached `request_accepted`; main §6 applies regardless of SECURITY.
2. SEQ exhaustion set the association closed and raised without running security-context retirement. A 1024-byte request left 13 queued frames and no cancellation after exhaustion; a later terminal callback could submit another protected frame. Exhaustion while receiving a REQ could raise after scheduling output, so `handle()` lost the returned events and left a submission unknown to its controller.

The reviewer reproduced both findings through live peer `handle()` calls, ran the full unittest suite (290/290), security/recovery fixture verifiers, and `git diff --check --ignore-submodules=all`. These findings were assigned for bounded repairs in `endpoint.py` and `test_p21c_s10.py`; the package remains unaccepted pending those repairs and another frozen-snapshot review.

## Repair handoff — final review pending

The same GPT-6-luna High repair worker completed the two fixes. This was a follow-up in its existing fresh-context worker task, not a new implementer context. Its write set remained limited to `tests/peer/dmp_peer/endpoint.py` and `tests/peer/tests/test_p21c_s10.py`; the earlier P21D dirty work was preserved. The worker read `AGENTS.md`, `README.md`, `dev/DMP_Implementation_Plan.md`, `dev/DMP_Work_Packages.md`, `dev/P20_Independent_Peer_Brief.md`, `docs/DMP_v2_Device_Messaging_Protocol_Specification.md`, `docs/DMP_v2_Security_Profile.md`, `docs/DMP_Test_Manifest_Contract.md`, both DIRECT/RADIO NNpsk0 deployment manifests, `tests/peer/dmp_peer/endpoint.py`, `tests/peer/tests/test_p21c_s10.py`, and `tests/peer/dmp_peer/events.py`. The previously approved narrow read of `tests/peer/dmp_peer/delivery.py` remains part of the actual-read record. No primary `src/**`, `include/dmp/**`, C tests, traces, manifests, schemas, normative files, or coordinator records were read or changed during the follow-up. Shared workspace access is not an enforced read ACL; those exclusions are the worker's reported read boundary. Shared-model interpretation risk remains.

The second repair adds a plaintext/test-only §6 unknown-critical rejection regression and handles SEQ exhaustion at the event boundary: retire SEC-1, clear queued work, cancel outstanding submissions, suppress submissions created but never returned by the failing event, and return terminal events rather than leaking an exception. Tests cover queued plus admitted work under DIRECT retry-all and RADIO SELECTIVE-32, post-retirement terminal callbacks, and receive-side exhaustion after issuing `0xffffffff` for a result.

Final code/test hashes before independent review: `endpoint.py` `7CC424DF46946E2BF6977859394E3C89EAF9FCF91A5655BD796F8C5907BF376B`; `test_p21c_s10.py` `39B56A51AC338F64B3C392DAB1703F319BEFAB048521D8EDCDF0001751230FD1`. Branch/HEAD remain `feat/initial-version` / `734d20aa7d078b4799559f55050dca4dc4d2fac5`.

Coordinator reruns passed: focused P21C S10 50/50; complete peer unittest suite 291/291; `python -B -m compileall -q tests/peer`; `node dev/dmp_verify_security_vectors.cjs` (4 fixtures, 64 packets, 44 mutations, 64 wrong-key rejections, 164 structural rejections, 8 fixture-policy rejections); `node dev/dmp_verify_recovery_vectors.cjs` (26 cases, 8 mutations); and `git diff --check --ignore-submodules=all`. Independent final review of these hashes is in progress. P21 remains unaccepted because full protected P21B matrix coverage and historical P21A-D actual-input records remain unresolved.

That independent review verified both hashes before and after its probes, found the two follow-up fixes correct, and identified one more lifecycle blocker: after sequence exhaustion, a fresh SEC-1 handshake activates a new epoch while `next_seq` remains `0x1_0000_0000`. The first application request in that new association immediately closes it again. The fix must initialize the sequence counter on each new association activation, while leaving duplicate FINISH/READY handling in the same association unchanged. A reconnect + new-handshake + successful application-request regression is now required before the next frozen review.

## Follow-up repair and matrix expansion — 2026-10-12

The frozen-review SEQ lifecycle finding is repaired. New application SEQ allocation resets to 1 only when a new responder or initiator association is activated (including authorized-application activation after lost READY); a duplicate FINISH/READY on the active association does not reset it. The regression exhausts the old epoch, disconnects/reopens both peers, performs a fresh NNpsk0 handshake with distinct entropy, checks both new counters, sends a protected request/result, and verifies duplicate controls leave non-default counters unchanged.

Coordinator verification of this repair: `python -B -m unittest tests.test_p21c_s10 -q` from `tests/peer` — 51/51; `python -B -m compileall -q tests/peer` — pass; `node dev/dmp_verify_security_vectors.cjs` — 4 fixtures, 64 packets, 44 mutations, 64 wrong-key rejects, 164 structural rejects, 8 fixture-policy rejects; `node dev/dmp_verify_recovery_vectors.cjs` — 26 cases, 8 mutations; `git -c diff.ignoreSubmodules=all diff --check --ignore-submodules=all` — pass. Repair hashes at this point: `endpoint.py` `DF0376A0713182A3B077F120B62486A1219164BC1AAF0F6FE2F8FF8C1D25D854`; `test_p21c_s10.py` `6254471D369DF7CD31FCE3C1CFE425C50699C8FCDF3340896F9739249FC2B81C`. Branch/HEAD remain `feat/initial-version` / `734d20aa7d078b4799559f55050dca4dc4d2fac5`. P21 gate remains open pending final independent review and matrix completion.

A read-only P21 matrix map then identified required protected P21B cases missing from the nine existing focused scenarios: retained invalid-request replay; fragmented retained-result retry/expiry; protected terminal STATUS/ACK_REQ validation; and applicable protected SAMPLE-1 state/error rows. These are being added only in `test_p21c_protected_p21b.py`. The same map found P20 explicitly names `radio-xx.json` and `test-radio-retry-all-xx.json`; P21D runtime recovery evidence so far exercises only the corresponding NNpsk0 profiles. Focused live-XX SELECTIVE-32 and retry-all cases are being added in a separate test file. These additions do not close P22/P23, MCU/runtime/RAM, physical transport, or the historical P21A-D input-set provenance gap.

## Protected P21B / XX recovery additions — 2026-10-12

A live protected NNpsk0 request to the SAMPLE-1 producer with malformed `service_id=1` payload `ff` was receiving retained STATUS 6 because `_required_acl_action()` returned no action before payload validation. Reference Application A1 requires STATUS 7 for an authenticated caller permitted to use SAMPLE-1, after configured-size admission; STATUS 3 still takes precedence above the configured request limit, and STATUS 6 remains for absent/insufficient ACL. The peer now distinguishes that case without relaxing candidate authorization. `test_p21b_protected_malformed_sample1_request_retains_status7` verifies protected STATUS 7, fresh-PN retained replay, STATUS 3 above the limit, and STATUS 6 without permission.

The protected P21B suite now adds `test_p21b_protected_retained_unsupported_request_replay`, `test_p21b_protected_fragmented_retained_result_retry_and_expiry`, `test_p21b_protected_terminal_status_ack_req_validation`, and `test_p21b_protected_sample1_no_sample_and_status_rows`; its focused result is 14/14. XX recovery now exercises the P20-named `radio-xx.json` profile for selective request/large-result repair and `test-radio-retry-all-xx.json` for complete-set retry on a fresh live XX association. Three focused XX cases pass, including stable request/result identities, fresh PNs, payload completion, and protected ACK.

Final coordinator validation after these additions: `python -B -m unittest discover -s tests -p 'test_*.py' -q` from `tests/peer` — 300/300; `python -B -m compileall -q tests/peer` — pass; security fixtures — 4 fixtures, 64 packets, 44 mutations, 64 wrong-key rejects, 164 structural rejects, 8 policy rejects; recovery fixtures — 26 cases, 8 mutations; `git -c diff.ignoreSubmodules=all diff --check --ignore-submodules=all` — pass. The final code/test snapshot is under independent GPT-6.1-sol High review. P21 remains running and unaccepted until that review and the historical P21A–D actual input/read-set provenance gap are resolved or explicitly dispositioned by the project owner.

## Frozen-review repair and final P21 code review — 2026-10-12

The independent review found three remaining P21 issues: candidate readiness did not reject a service-2 `PAYLOAD_DESC`; the protected terminal-status regression omitted SERVICE_ID=2 and therefore did not target its pending request; and the live XX retry-all case stopped after producing retries without proving delivery, ACK, expiry, or late-fragment refusal. All three are repaired in the peer endpoint/tests: candidate remains pending with no dispatch or retained rejection for the descriptor-bearing request, then activates on a valid authorized request; negative protected terminal cases now target service 2 and retain the exchange until a valid correlated result; XX retry-all now proves fresh-PN completion, one dispatch, a protected correlated ACK, and a separate bounded-expiry/late-fragment refusal case.

The fresh frozen review found no actionable code/test findings. The reviewer verified the four-file snapshot hashes before and after, independently ran focused S10 **52/52**, protected P21B **14/14**, XX matrix **4/4**, full peer suite **302/302**, and `diff --check`. A sensitivity probe confirmed each of the six negative terminal cases fails its assertion if normalized into an otherwise valid correlated RSP. Coordinator reruns also pass: `python -B -m unittest discover -s tests -p 'test_*.py' -q` from `tests/peer` — **302/302**; `python -B -m compileall -q dmp_peer tests`; both security/recovery vector validators; and `git -c diff.ignoreSubmodules=all diff --check --ignore-submodules=all`.

Latest reviewed SHA-256 values: `endpoint.py` `69531721A8E7DDABD67362097660FA030FF92B38C474B1F8439E75A508AAE426`; `test_p21c_s10.py` `400FA93EFEB74F2C87DDC1A5B87CD2EF2699F5D8E40AE6415641DFBE19396CBB`; `test_p21c_protected_p21b.py` `C162622FD1E7DBFDBACEA572EA8B31E3610430F38FCDBE8A7603B5FB5F07F5F3`; `test_p21d_xx_matrix.py` `C837FBAA818B72C42287986CFB474489ACFF40265AE077762C67D70ECF0FF7CC`. Branch/HEAD remain unchanged. P21 host/peer code and test acceptance is clear, but the combined P21 gate remains `running` because historical P21A–D actual-input/read-set and enforced access-boundary evidence is incomplete; this limitation is not a code finding and is not retroactively repairable from the current snapshot.

P22 may proceed independently under its P20 dependency. Owner direction is confirmed: add contract 3 and a distinct mixed-simulation manifest; keep P02 contract-2 schemas, profiles and digests unchanged. P23 still depends on both P21 and P22.

## Owner disposition — 2026-10-12

The owner accepts P21 for its host/peer functional scope and authorizes P23 to proceed, with this explicit limitation: historical P21A-D actual input/read-set and enforced filesystem access-boundary evidence is incomplete and cannot be reconstructed from the current checkout. This is an evidence/provenance limitation, not a code or test finding. Do not claim formal clean-room certification or fully documented implementation independence. Preserve the limitation in P23 reports and keep MCU/runtime/RAM and physical transport separate.
