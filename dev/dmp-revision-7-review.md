# DMP revision 7 review

Date: 2026-09-24. Scope: main specification revision 7, SEC-1 profile revision 3 / BOOT_VERSION=2, design guide, public vectors and verification scripts. This document records the initial read-only review and the subsequently authorized fixes and independent re-review. The original findings below describe the pre-fix snapshot.

No P0/P1 defect was confirmed. The original review identified four actionable P2 findings, covering trust-state ambiguity, conflicting retention rules, handshake availability and fixture validation. These findings do not establish a break of Noise or AEAD. Byte-vector agreement does not demonstrate endpoint state-machine correctness.

## Remediation and independent review

The owner authorized fixes and a new independent review. All four findings are resolved in the current specification/verifier. Original line references below describe the pre-fix snapshot.

| Finding | Resolution |
|---|---|
| R1 | SEC-1 §S2 separates persistent enrollment commit from §S4 traffic activation. Committed pins survive confirmation timeout/reboot; uncommitted candidates do not. Pending approvals remain attempt-bound, while committed credentials support subsequent authorized associations. |
| R2 | SEC-1 §S7.1 uses main §8.1 result retention. A retained result retries within its original budget; after release, retained acceptance permits only its receipt ACK. Token state cannot recreate the result. |
| R3 | SEC-1 §S3.1 drops conflicting processed-flight duplicates without abort, transcript mutation, response or timer extension. |
| R4 | The Node verifier checks assigned C/U flags, exact STATUS encoding, required reply/status fields, ACK shape, ROUTE/ORIGIN exclusion and protected-only FRESHNESS. Positive STATUS cases and independent malformed cases cover the updated checks. |

The independent reviewer (`dmp_independent_review`, fresh context, not an author of the fixes) identified an additional expected-flight injection scenario: a forged next flight could still abort the pending attempt. This was also resolved. SEC-1 §S3.1 now requires bounded, serialized tentative receive processing; invalid framing, DH/tag or an existing-pin mismatch cannot mutate the saved pre-flight state. Outgoing encryption happens only after successful state commit and its flight is cached. The pre-authentication availability limit for unpinned XX candidates remains explicit. §S10 includes the corresponding implementation scenarios.

After rereading the final changes, the independent reviewer reported **no remaining actionable findings** in the current main specification, security annex or fixture verifier. This is a text/code review, not independent endpoint interoperability or executed lifecycle testing.

Final focused validation:

- `node dev/dmp_verify_security_vectors.cjs`: four fixtures, 64 packets, 44 mutations, 64 wrong-key rejections and **128 structural rejections** passed.
- The original review harness now rejects all **16** malformed frames it previously accepted.
- Added positive application-service RSP/ERR STATUS examples, including a multi-byte STATUS; corrected the unprotected-FRESHNESS negative so missing REPLY_TO cannot make it pass for the wrong reason.
- Main/annex wire-format code blocks are unchanged; the generator and generated JSON remain byte-identical to the staged baseline. No firmware/client implementation or wire revision was changed.
- Three current documents passed link/section checks (16 local links, 55 section references), fence/whitespace checks and `git diff --check`.
- RBO discovery again returned `fetch failed`; short verifier checks used the documented local fallback. No staging or commits were performed.

Enrollment, timeout, fragmentation and Noise-provider transaction scenarios are normative requirements added to §S10, not claims of runtime coverage by the fixture verifier. They must be exercised when an endpoint implementation is available.

## R1 — P2: distinguish enrollment commit from association activation

Evidence: [SEC-1](../docs/DMP_v2_Security_Profile.md), §S2 line 43, §S2.1 line 49, §S3.1 line 124 and §S4 lines 150–154.

The annex requires new identity authorization to be committed atomically before sending protected confirmation, but also says failed or timed-out pairing does not install new trust. Confirmation can time out after the required persistent commit. No rule specifies whether the committed authorization then remains or is rolled back.

Counterexample:

1. Two new XX peers complete Noise and approve the exact authenticated handshake hash.
2. The initiator atomically commits the peer pin and sends FINISH.
3. FINISH or every READY response is lost until the confirmation deadline.
4. The association fails. One implementation retains the verified pin; another removes it under the timed-out-pairing rule. Both have textual support.

This affects restart behavior, repeated enrollment and operator-visible trust state. It does not let an unauthenticated peer pass the required verification.

Minimal fix: define local enrollment commit separately from traffic-association activation. Unverified/uncommitted candidates disappear on timeout; an already verified and atomically committed pin remains after a transport/confirmation timeout until explicit revocation. State clearly when the UI reports enrollment complete and when it reports the connection active. Do not introduce distributed rollback or another confirmation round merely to resolve this wording.

Validation needed: drop FINISH/READY and restart each endpoint immediately before and after local credential commit; check persistent pins, permissions and the next pairing attempt.

## R2 — P2: freshness retries conflict with result release

Evidence: [SEC-1](../docs/DMP_v2_Security_Profile.md), §S7.1 line 233; [main specification](../docs/DMP_v2_Device_Messaging_Protocol_Specification.md), §8.1 line 355.

The freshness service says repeating the same control REQ returns the same result/token. Generic reliable request/result behavior says that after the result has been released, a duplicate request receives only its acceptance receipt. The freshness wording does not limit itself to the result-retention period or define an exception with its own retention budget.

Counterexample: a grant RSP is acknowledged and released; its token is still valid or its request acceptance record still exists. A delayed fresh-PN duplicate of the original REQ arrives. The main text prescribes ACK only, while the annex appears to require reproducing the RSP/token. Recreating a result after release also needs its original result identity and a rule that prevents restarting its expired retry lifetime.

Minimal fix: qualify the freshness rule by the normal result-retention period. While retained, resend the identical result/token within its original budget; after release, resend only the receipt. A new lease requires a new REQ identity. Do not add a special permanent grant-result cache.

Validation needed: duplicate a grant request before result release, after release with an unexpired token, and after token expiry. Neither result nor token lifetime may be extended.

## R3 — P2: an unauthenticated duplicate can abort a pending handshake

Evidence: [SEC-1](../docs/DMP_v2_Security_Profile.md), §S3 line 105, §S3.1 line 122, §S3.2 lines 128–132.

The mandated action for conflicting bytes of an already processed flight is to abort the pending attempt. In XX, flight 1 is unprotected and contains an unauthenticated ephemeral public key. An observer can copy its public attempt/context fields, change the ephemeral key to another valid key, and inject it while the responder waits for flight 3. The conflict rule then terminates the legitimate pending attempt without authenticating the conflicting sender.

This is a targeted availability weakness, not peer impersonation, decryption or teardown of a different active association. Bounded admission limits resource exhaustion but do not prevent this one-packet interruption. It also does not imply complete handshake DoS resistance can be achieved on an attacker-controlled transport.

Minimal hardening: keep the original pending transcript and ignore/rate-limit conflicting unauthenticated duplicates of an already processed flight; do not replace saved parameters or rerun Noise. Abort on the local deadline, explicit trusted cancellation, or a separately defined authenticated inconsistency. Keep failure handling for a genuinely new expected flight separate from duplicate handling.

Validation needed: inject a changed flight 1 into a pending XX attempt, then deliver the original valid flight 3 and FINISH. The conflicting duplicate must not alter the original transcript or reset its deadline.

## R4 — P2: fixture verification omits known structural rejection rules

Evidence: [Node verifier](../dev/dmp_verify_security_vectors.cjs), lines 26–34, 86–114 and 128–131; [main specification](../docs/DMP_v2_Device_Messaging_Protocol_Specification.md), lines 238, 246–251, 278 and 768–784.

The parser decodes extension IDs but does not validate the registered C/U flags. It also does not enforce the tested ACK's payload/ACK_REQ/STATUS restrictions or decode STATUS as its required integer. These are structural rules that can be checked without implementing a complete session engine.

A local in-memory harness loaded the existing verifier with Node `vm`, reused only its public fixture data and test-only `sealedVariant` helper, and exercised these malformed variants of `request_receipt`:

| Variant | Required outcome | Existing verifier |
|---|---|---|
| REPLY_TO tag 0x05 changed to 0x04, clearing its required C flag | Reject assigned-flag mismatch | Accepted |
| ACK with ACK_REQ set | Reject invalid ACK shape | Accepted |
| ACK with one plaintext payload byte | Reject nonempty ACK | Accepted |
| ACK with STATUS tag 0x15 and zero-length value | Reject forbidden STATUS and invalid known-field shape | Accepted |

All four cases were accepted for all four mode/cipher fixtures: 16 malformed frames total. Their tags were recalculated with public test keys solely to exercise post-authentication structural validation. This is not a forgery and says nothing about a production parser, which is not provided by these tools.

Minimal fix: extend the existing verifier and negative fixtures for registered extension flags, known value encodings and required type/option relationships. Keep the explicit limitation that this remains fixture validation, not full endpoint conformance. The current normative rules themselves are clear.

## Lower-priority precision and complexity observations

- Main §7 line 300 says a correlated ERR is not an acceptance ACK, while §8.1 correctly allows a terminal application-result ERR to prove acceptance and substitute for receipt. Qualify the first sentence as protocol-rejection ERR to avoid misleading implementers; the later rules already distinguish the two cases.
- A delayed, previously unseen retry PN can pass the replay window after its message acceptance record expires. With no freshness requirement, re-execution can follow. This is a documented boundary rather than a new contradiction: main §8 limits deduplication retention and §18 line 704 explains that sender expiry does not expire remote copies. Services that cannot tolerate this need enforced freshness or durable application operation IDs. The deployment policy should make that choice explicit.
- No reason was found to undo fixed-stride fragments, same-association compact replies or fixed-width epochs. They give a single current contract and remove avoidable representation choices. Freshness remains optional where delay is acceptable.
- Resolve R1/R2 by choosing one state transition/retention rule, not by adding new wire modes, confirmation messages or caches. Selective recovery, PAKE, session resumption and dynamic negotiation still lack a demonstrated need for this revision.
- The most useful next validation is a small endpoint state-machine harness covering loss, deadlines, persistent enrollment and duplicates. More positive encryption fixtures alone will not settle R1–R3. Hardware performance was not measured.

## Original verification and reference checks

- `node dev/dmp_verify_security_vectors.cjs` passed: four fixtures, 64 protected packets, 44 mutations, 64 wrong-key rejections and 48 structural rejections currently included in the suite.
- The additional read-only harness reproduced the 16 structural acceptances described in R4. It did not modify the verifier or generated JSON.
- RBO discovery returned `fetch failed`; these short checks used the repository-permitted local fallback.
- Read-only passes covered core encodings, canonical integers, fixed-stride geometry, stream framing, reliable request/result flow, relay suppression and asynchronous buffer ownership. No additional confirmed normative contradiction was found there.
- Checked DMP's security choices against [Noise revision 34, especially §§11.4 and 14](https://noiseprotocol.org/noise.html) and [RFC 9175 §2](https://www.rfc-editor.org/rfc/rfc9175.html#section-2). Noise requires tracking successfully received nonces for unordered traffic and leaves peer authorization to the application; RFC 9175 distinguishes request freshness from channel protection. Neither reference settles DMP's enrollment/retention state transitions.
- No firmware/client build, hardware test, independent endpoint interoperability run or complete cryptographic audit was performed. Only this review report was added.
