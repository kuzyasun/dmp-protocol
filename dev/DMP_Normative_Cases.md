# DMP normative case ledger

P03 case-to-future-test index for main revision 10, SEC-1 revision 5, SELECTIVE-32 revision 1 and SAMPLE-1 revision 2. The canonical rows and stable planned Test IDs are in [DMP_Normative_Cases.json](DMP_Normative_Cases.json); this index does not repeat them.

P05/P06 have 23 passed primary codec/framing scopes and 10 partially exercised
compound scopes, linked to actual tests and [evidence](evidence/codec-framing-20260927/README.md).
All 33 whole rows remain `partial` because independent peer/interoperability or
later primary obligations are unexecuted; the other 104 rows remain `not-run`.
`primary_checks` names actual linked functions; existing planned Test IDs remain
stable planning identifiers, not executable commands. P02 offline checks and
public fixtures alone do not pass endpoint behavior.

| Group | Rows |
|---|---:|
| Main wire/security vectors (§22.1–§22.7, §22.9–§22.11) | 26 |
| Main required cases (§22.8) | 31 |
| Simulated Stream R timeout/startup policy | 2 |
| SEC-1 S10 split subcases | 24 across all 18 numbered source cases |
| SELECTIVE-32 R6 rows | 10 |
| SELECTIVE-32 R7 obligations | 16 |
| SAMPLE-1 A1–A4 cases | 24 |
| Manifest rejection rows for excluded features | 4 |
| Total rows | 137 |

S10 case 6 separates endpoint reassembly (P15/P21C) and relay state (P19/P21D); case 11 separates P22 binding path and P23 independent-peer rerun. P13 owns candidate verification/enrollment, while P14 owns protected confirmation/activation.

S10.17 attempt/restart/backoff/episode and orphan-capacity checks stay in P13;
P14 repeats their effects through protected confirmation. Compound security rows
retain explicit required subcases. Plaintext wire examples are codec fixtures,
not plaintext traffic permitted by the six SEC-1 deployments. P09 rejection rows
are future runtime parity; P02/P03 offline validation has separate evidence.

The six host manifests pair NNpsk0 and XX with DIRECT-1, RADIO-1 SELECTIVE-32, and the separate TEST-RADIO-RETRY-ALL baseline. All use cipher 1, two endpoints and services 1/2. Radio models two static relays. Service-2 freshness is disabled for DIRECT and enabled on radio profiles only with actual S7 grants. Message limits: 1,024 bytes; DIRECT 16 × 64-byte fragments, radio 32 × 32-byte fragments.

AESGCM, group security, dynamic routing and physical bindings have separate scope/rejection statements. Their rows are not passes. Physical transport evidence remains outside this host-simulation scope. JSON metadata captures normative-source and manifest hashes.
