# DMP conformance matrix

This initial P00 ledger separates scaffold/fixture evidence from provider and
endpoint conformance. P03 expands all normative numbered cases into concrete
test IDs, expected outcomes and ownership before any enabled-module claim.
`pending` / `not run` never means passed or unsupported.

| Requirement | Test / evidence | Owner gate | Expected outcome | Actual result |
|---|---|---|---|---|
| C11 host toolchain and CTest runner | `dmp_host_environment` | P00 | Compile with strict warnings; run successfully | Passed Windows/GCC 15.2.0 C11 scaffold, [log](evidence/noise-baseline-20260926/scaffold-ctest.log); no provider/MCU claim |
| Existing public SEC-1 fixture consistency | `fixtures.sec1` / `node dev/dmp_verify_security_vectors.cjs` | P00 baseline only | Current revision fixture verifier succeeds | Passed revision 10 corpus: 4 fixtures / 64 packets / 44 mutations / 64 wrong-key / 164 structural / 8 service negatives; fixture-only, [impact](evidence/noise-abort-first-20260926/vector-impact.json). Historical revision 9 [checks](evidence/approved-amendments-20260926/checks.json) remain dated evidence |
| Reviewed engine/backend, exact Noise suites/flights/prologue | `dmp_noise_fixture_probe` | P01 | Selected suites match independent vectors; controlled-core delta/provenance reviewed | NNpsk0/XX ChaChaPoly fixture flights, payloads, full hashes and Split AEAD passed; production provenance/resource gate remains open. [Evidence](evidence/noise-baseline-20260926/README.md) |
| S3.1 / S10.17 abort-first read and pin/payload checks | `dmp_noise_fixture_probe` plus pending wrapper/lifecycle cases | P01; endpoint P13/P15/P21C | Admitted bad read/post-check aborts attempt; late continuation cannot resume; separately scheduled fresh attempt within episode/global limits | Partial: corrupted final authenticated flight sets FAILED and blocks authentic retry in both modes. Pin/payload abort, cleanup and bounded restart remain pending; [evidence](evidence/noise-baseline-20260926/README.md) |
| S3.1 structural/conflicting-duplicate boundary | P01/P13 fault cases | P01/P13/P15/P21C | No crypto call, response, deadline renewal or destruction of admitted pending state | Pending |
| Future preserve-state read/pin transaction | No implementation selected | Future separately authorized scope | Requires tentative storage/erasure, nonrollbackable work/time and explicit pair/path policy | Deferred; not current acceptance or supported feature |
| S2 all-zero X25519 result / low-order inputs | `dmp_noise_dh_probe`, inherited DH/handshake units, baseline regression | P01/P13/P21C | SEC-1 rejection before MixKey, no masked backend failure or continued attempt | DH-01 host checks accepted after independent review: success-zero fault, exact backend errors/output clearing, no failed-DH MixKey, real e and authenticated s=0/u=1 in XX ES/SE, FAILED continuation/Split refusal and fresh fixtures. Full endpoint/provider gates remain open. [Evidence](evidence/noise-dh-20260926/README.md) |
| S2.2 / S3.2 cache, erasure and finite resource work | P01 experiment (not yet implemented) | P01 | No repeated flight encryption; bounded retained/scratch/work | Pending |
| S4 / S5 explicit nonce and authenticated header | `dmp_noise_pn_probe`, cipher unit tests; legacy baseline retained | P01 | Provider permits exact PN/AAD semantics | PN-01 sodium ChaChaPoly receive seam passed: 32 independent packets, reorder and invalid-high-PN isolation, AAD/tag and counter/error bounds. Full SEC-1 PN admission/replay/lifecycle remain pending; [evidence](evidence/noise-pn-20260926/README.md) |
| Main 22.8 structural/framing cases | Assigned case-by-case at P03 | P05–P08 | Normative positive/negative outcomes | Pending |
| Main 22.8 delivery/context/ownership cases | Assigned case-by-case at P03 | P09–P12, authenticated rerun P15 | No duplicate dispatch/lifetime renewal or buffer misuse | Pending |
| S10 endpoint-local assertions | Assigned case-by-case at P03 | P13–P15 / P21C | Real SEC-1 endpoint evidence; activation only after P14 | Pending |
| S10 case 6 authenticated reassembly | Dedicated endpoint scenario | P15 / P21C | Authenticated admission; no unauthenticated state damage | Pending |
| S10 case 6 relay-state portion | Dedicated routed scenario | P19 / P21D; rerun P23 | Bounded relay state and correct forwarding | Deferred, not passed |
| S10 case 7 local TTL/AAD | Dedicated endpoint scenario | P15 / P21C | Only specified mutable fields excluded from AAD | Pending |
| S10 case 11 mixed binding | Implemented P22 mixed path, independent P23 exchange | P22 prerequisite / P23 acceptance | Both directions, protected-object preservation, MTU/context rejection | Deferred, not passed |
| Recovery R6 / R7, SAMPLE-1 A1–A4 | Assigned case-by-case at P03 | Plan gates | Exact enabled-module contract | Pending |
| Retry-all comparison identity | Separate `DMP-test/TEST-RADIO-RETRY-ALL/1` manifest | P03 / P19 / P21D / P23 / P24 | RADIO-1 retry-all rejected; no live association toggle | Pending |
| Physical binding / MCU memory | Separately authorized target evidence | Target-specific gates | Actual target measurement | Not run; no support claim |

| Revision 9 requirement | Test / evidence | Owner gate | Expected outcome | Actual result |
|---|---|---|---|---|
| Best-effort protocol rejection | Loss/retry and invalid ACK_REQ/STATUS cases | P05/P10; P15/P21/P23 | Retained rejection, no execution or reliable rejection exchange; reliable terminal ERR unaffected | Pending endpoint tests |
| Canonical same-service replies | Default/nondefault/control/HELLO and wrong-service cases | P02/P05/P09/P21/P23 | Omit application default, encode nondefault/control, reject mismatch | Pending endpoint tests |
| SAMPLE-1 revision 2 initialization | A4 cases, including supersession races and persistence failure | P12; real SEC-1 P15/P21C/P23 | Fresh designated READ selects epoch; bounded state; no rollback | Pending |
| Aggregate target RAM/flash envelope | Numeric manifest, conservative bounds, map/size and applicable target peaks | P00/P01/P03; P08/P12/P15/P19/P25 | Missing limits/evidence or overruns block affected acceptance | P00 finite experimental sensitivity envelopes declared; provider/MCU measurements and P03 production freeze pending. [Inputs](../tests/provider/experiment_manifest.json) |
| Hard failed-AEAD ceiling | Boundary, successes interleaved, confirmation/draining, concurrent verification | P02/P14/P15/P21C/P23 | Cumulative actual failures plus reserved slots never exceed configured limit <=65536 | Pending |
