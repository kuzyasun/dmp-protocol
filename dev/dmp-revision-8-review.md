# DMP revision 8 documentation review

Date: 2026-09-25. Scope: SELECTIVE-32 revision 1, main/SEC-1 references, DIRECT-1/2 and RADIO-1/2, SAMPLE-1, standalone documentation extraction. This is a text/contract review, not an endpoint implementation audit.

An independent read-only reviewer (`dmp_revision8_review`) checked the new recovery contract against the main specification and SEC-1. Confirmed findings were fixed before extraction:

| Finding | Resolution |
|---|---|
| Recovery feedback allowed core INTEGRITY beside SECURITY | R2 now forbids it; only outer binding integrity remains permitted |
| Delay parameters had no precise clock origin | R3 defines transmission completion through authenticated endpoint receive processing, including queues/crypto |
| Pending status cancellation could reclaim an adapter-owned buffer | R4 distinguishes unsubmitted versus already submitted status and requires terminal adapter completion before release |
| Duplicate accepted REQ could trigger a parallel/full fragmented result resend | R4.5 and main §8.1 keep the existing selective-result state machine in control and repeat only the request receipt |
| Profile wording allowed recovery choice by transfer class within one service | One fixed policy per peer/application service and both directions is explicit |

Final independent pass found no further actionable contradictions in the inspected recovery/profile/application sections. This does not establish absence of all defects or measured security/performance.

The main-agent checks also confirmed: FRAG_STATUS example has a 10-byte header, four plaintext/ciphertext bytes and 16-byte tag (30 bytes before binding); malformed sample application requests use STATUS=7; main ACK remains acceptance-only; incomplete selective assembly loss becomes terminal through a bounded tombstone, not renewed reassembly.

## Existing fixture evidence

Local checks were used because RBO returned no live agents. Python 3.12 with cryptography 46.0.4 regenerated fixtures against the cached public Cacophony input whose SHA-256 is `3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae`.

- Generator: four upstream protocol combinations, four DMP fixtures, 64 protected packets, 44 mutation cases, nine replay-model assertions.
- Independent Node crypto verifier: four fixtures, 64 packets, 44 mutations, 64 wrong-key rejections and 128 structural rejections.
- Revision update changes the fixture specification label; existing cryptographic packet bytes remain unchanged.

These fixtures do not cover new FRAG_STATUS protected bytes, SELECTIVE-32 scheduling/state behavior, hardware or a real endpoint. Those checks are explicit implementation gates in [the development plan](DMP_Implementation_Plan.md). Canonical recovery header/plaintext cases and required failure scenarios are specified in [the recovery annex](../docs/DMP_v2_Selective_Recovery.md).
