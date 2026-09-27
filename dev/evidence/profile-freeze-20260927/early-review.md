# Independent early contract/vector review

Reviewer: `p03_early_review`, GPT-6 Astra xhigh, read-only. Coordinator verified
the reported source references before applying the one confirmed correction.
No reviewer build/test/verifier/hardware run; no endpoint conformance claim.

## Confirmed finding and closure

Main 15.2 requires Stream R partial-frame expiry and documented independent
receiver-reset loss behavior. SIM-STREAM-R/1 initially left both unspecified.
Before first P03 freeze, the test-binding contract now defines an absolute
candidate timer from the first nonzero byte, derived from transmission + maximum
directional delay + record margin. It is not renewed by later bytes. Available
bytes/delimiter take precedence at an equal deadline; expiry discards through
the next delimiter. Coordinated open sends its initial delimiter after receiver
readiness; independent RX reset can lose the in-flight/next frame. No periodic
prefix/reset indication is selected; reliable traffic has only its finite retry
envelope. This clarifies the selected simulated binding, not the core wire.

The reviewer reread the correction and closed it. P06 must exercise the derived
deadline before/at/after expiry, no renewal, discard/resynchronization and reset
policy using the actual stream implementation.

## No contradictory findings in the other reviewed rules

- Main 15.2 / 22.7 canonical COBS encoder and 254/255/508-byte vectors agree,
  including the final empty `01` block and bound `N+floor(N/254)+1` before the
  delimiter. Manifest sizing counts envelope CRC and delimiter correctly.
- Main 6.1, 22.2 and 22.9, SEC-1 S5 and recovery R2 agree on full plaintext
  references versus protected SEQ-only references, local sending identity on
  the authenticated association, exact consumption and service matching.
- `dev/dmp_verify_security_vectors.cjs` lines 100-106 and 350-354 distinguish
  reference representations and reject obsolete/trailing forms. It does not
  test COBS; that remains P06, not an inferred pass from SEC-1 fixtures.
- Deployment resource rationale matches MEM-02/03 and MCU-01/02 evidence,
  explicitly distinguishing live peaks/backing, host reserves and target fit.

Reviewed hashes:

| File | SHA256 |
|---|---|
| `docs/DMP_Test_Manifest_Contract.md` | `c8bd50c14582f1f4e291f4f62f22e7a08bd2a17b2f3ddc6d671ab718df7bcfdf` |
| `profiles/deployments/README.md` | `53a3a8acea91fb28d18935d2f580c156294c4e71c164f8fdee012a47eb60fbaf` |

Outcome: early P03 contract/vector review closed with no remaining blocking
finding in scope. Six-instance validation, complete case mapping and final
coordinator acceptance are separate from this early review.
