# P21C execution checkpoint — 2026-10-09

## Objective and boundary

Implement the independent peer's selected SEC-1 revision 5 lifecycle under P21C, retaining the frozen `DMP-PEER-TEST/1` API and the P20 independence boundary. The implementation must use the existing maintained `cryptography==46.0.4` provider for primitives, independently implement the normative handshake/session state machine, and exercise actual protected traffic between two peer instances.

The selected enabled credential modes are NNpsk0 and authenticated XX, with mandatory ChaChaPoly. AESGCM, relay state (S10.06), routing/SELECTIVE-32 (P21D), mixed-binding forwarding (S10.11/P23), primary C implementation, MCU/runtime qualification, and physical transport are outside this package.

## Frozen start

- Branch: `feat/initial-version`
- Baseline: `eb8ae4c feat(peer): accept P21B direct delivery`
- `git status --ignore-submodules=all --short --branch` was clean and the branch tracked `origin/feat/initial-version`.
- A default status walk reports an access error in the nested `third_party/noise-c` Git metadata; P21C writes stay outside that submodule, and final source staging must remain path-scoped.
- Local provider environment: CPython 3.12.8, `cryptography` 46.0.4, OpenSSL 3.0.15.
- Live AGY broker was `READY`, DMP project allowed, no pending intents. Full route discovery selected `dmp_agy_large` (`gemini-3.8-flash`, high); all listed DMP sessions were idle. A fresh current-workspace session accepted turn `turn-539d9c5070d56917ed51b439`.

## Milestones

1. Implement selected Noise handshake, trust/enrollment and confirmation/activation from SEC-1 S2-S4, including bounded abort-first bootstrap and failure cleanup.
2. Integrate protected framing, exact AAD, CID/epoch binding, replay, fresh-PN retries, ACL and configured S7 freshness into the peer endpoint.
3. Exercise two independent peer instances through real protected frames; cover P21B behavior and P21C endpoint-local S10 cases assigned by the work-package board. Do not use a fabricated active context as end-to-end evidence.
4. Run the full `tests/peer/` suite, inspect the exact diff and test-to-case mapping, obtain a frozen-snapshot independent GPT-6.1-sol High review, fix confirmed findings, then update the board/evidence and accept P21C.

## Acceptance — 2026-10-09

P21C peer-host scope is accepted by the coordinator after independent GPT-6.1-sol High read-only review of the final frozen snapshot. The reviewer verified eight source/test hashes unchanged across review and found no actionable findings. The primary implementation and primary C test/trace paths were not used for the independent peer implementation or review.

The peer now implements the selected NNpsk0 and authenticated XX handshakes with mandatory ChaChaPoly, protected framing/replay, ACL and configured S7 freshness, endpoint-local S10 lifecycle behavior, bounded bootstrap cleanup, and protected P21B delivery/reassembly scenarios. The final review findings were fixed: SAMPLE-1 rejects PAYLOAD_DESC before dispatch/readiness, and duplicate-triggered result replay shares the `attempts_left` transmission budget with timed retries, including the exact cache-expiry boundary.

Nine focused P21B scenarios exercise actual protected traffic between live endpoints, including request retry/deduplication, result-ACK loss/correlation, send deadline and borrowed-buffer ownership, protected fragmented reassembly/replay, queue admission, NNpsk0/XX, and the PN 127-to-128 encoding boundary. This is selected protected coverage, not a claim that the exhaustive P21B matrix or every prior fixture has been rerun under SEC-1.

### Final local validation

- `cd tests/peer && python -B -m unittest discover -s tests -p "test_*.py" -q` — 238/238 passed.
- `node dev/dmp_verify_security_vectors.cjs` — passed: 4 fixtures, 64 packets, 44 mutations, 64 wrong-key rejections, 164 structural rejections, and 8 fixture-policy rejections.
- `python -B -m py_compile` on all changed peer implementation and test modules — passed.
- `git diff --check --ignore-submodules=all` — passed; Git emitted only the existing LF-to-CRLF working-copy notices.

### Remaining gates and evidence limits

This acceptance covers only the independent peer host scope. The exhaustive protected P21B matrix and worst-header/fragment MTU reserve remain unproven. Relay state/recovery/routing including S10.06 belong to P21D; mixed-binding S10.11 and independent interoperability belong to P22/P23. MCU/runtime, hardware transport, and physical qualification remain separate. No contract, deployment profile, manifest, public API, or dependency changed in P21C.

The branch is `feat/initial-version`, with baseline `eb8ae4c6b9daae256e4a1268e8b3454c525b060d`. The coordinator is authorized to commit and push the accepted, path-scoped package.
