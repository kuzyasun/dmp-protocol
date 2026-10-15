# DMP normative case ledger

P03 case-to-future-test index for main revision 10, SEC-1 revision 5, SELECTIVE-32 revision 1 and SAMPLE-1 revision 2. The canonical rows and stable planned Test IDs are in [DMP_Normative_Cases.json](DMP_Normative_Cases.json); this index does not repeat them.

Current disposition across all 137 requirements (2026-10-15): **36 whole-row
passed, 101 partial, 0 not-run**. Separate evidence axes record primary C as
103 passed / 19 partial / 15 unrecorded, independent Python peer as 98 passed /
39 partial, and P23 interop as 46 passed / 7 partial / 84 not-applicable.
The current host test validates all primary/peer Test IDs and every recorded
primary, peer, and interop check against declared C/Python functions. Reference
validity does not promote a result or imply full normative coverage. The local
host gate passed DMP CTest 144/144; upstream Noise CTest passed 2/2 in the
current RBO host run. The integrated Python peer suite ran 439 tests, passed
438, and skipped one unreachable cross-endpoint quota state; the Node
crypto-vector check passed. The DMP CTest selection excludes the owner-deferred
ARM ABI probe and its seven dependent layout checks.

P12 has 34 rows: 10 whole-row passed / 24 partial; the primary axis is 29
passed / 5 partial, the peer axis 10 passed / 24 partial, and interop 5 passed
/ 29 not-applicable. The five primary-partial rows are `s-a1-epoch`,
`s-a1-epoch-transition`, `s-a2-designated-read`, `s-a4-restart`, and
`s-a4-persistence`; their remaining primary evidence is physical NVS/reset/
protected-UART behavior. Peer partials remain explicit where the peer model
does not implement the primary SEC-1 association or full lifecycle.

The JSON records exact executable references by evidence layer:
`primary_checks` for the C implementation, `peer_checks` for the independent
Python implementation, `interop_checks` for scoped C/Python endpoint tests,
and `profile_checks` for offline manifest validation. A reference identifies a
real test symbol; the separate result fields state its recorded outcome and
`primary_evidence`, `peer_evidence`, and `interop_evidence` retain scope limits.
The current peer relay tests include the v226 vector's unknown-extension
role/route checks. Excluded-feature profile rejections remain configuration
evidence and do not establish endpoint protocol behavior.

| Evidence layer | Exact rows with references | Recorded result |
|---|---:|---|
| Primary C checks | 125 of 137 | 390 links to 153 unique test symbols; result is per row |
| Independent Python peer | 83 of 137 | 130 links to 114 unique test symbols; result is per row |
| Offline profile validator | 4 | 4 links to the manifest validator; not endpoint or peer behavior |
| C/Python endpoint interoperability | 53 | 77 links to 46 unique tests; 46 passed, 7 partial, 84 not applicable |

`not-applicable` does not mean the underlying local requirement passed. P23's
matrix covers the selected exact-manifest host/simulation endpoints, not every
published vector, local negative case, application lifecycle, or future startup
parity case. Main rows distinguish decoded Core MTU from binding encoded MTU:
DIRECT-1 admits a 256-byte decoded Core frame and at most 263 encoded Stream R
bytes. P21 remains owner-accepted for host/peer functionality with its explicit
historical provenance caveat; no clean-room or complete-independence claim is
made.

The earlier P05/P06 baseline had 23 passed primary codec/framing scopes and 10
partially exercised compound scopes, linked to [evidence](evidence/codec-framing-20260927/README.md).
`primary_checks` names actual linked functions; planned Test IDs remain stable
planning identifiers, not executable commands. P02 offline checks and public
fixtures alone do not pass endpoint behavior.

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
