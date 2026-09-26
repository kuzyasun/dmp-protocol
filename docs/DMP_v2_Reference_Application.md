# DMP v2 — SAMPLE-1 reference application

**Status:** normative only for deployments explicitly selecting `DMP-reference/SAMPLE-1/2`\
**Date:** 2026-09-26\
**Requires:** DMP revision 9, SEC-1 profile revision 4

This small contract demonstrates opaque payload interoperability across [DIRECT-1 and RADIO-1](DMP_v2_Deployment_Profiles.md). It is not a production DTrack RPC schema or an actuator/OTA interface. Products may define other profiles. Numeric values below have meaning only inside this explicitly selected profile.

## A1. Service and encoding

Application service ID is 1, also the default on both endpoints. All SAMPLE-1 messages and their receipts omit SERVICE_ID under the main canonical rule; replies use the same service. SEC-1 is required. PAYLOAD_DESC is omitted: the manifest selects this fixed binary schema and exact application revision. All integers are unsigned little-endian; no native C struct padding, strings, implicit fields or trailing bytes are permitted. Security service 0 retains its annex meaning. An invalid request length/opcode or missing ACK_REQ is rejected before request acceptance with main STATUS=7 and the required retained rejection decision; an unsupported selected schema/profile uses STATUS=2, and a message exceeding configured size uses STATUS=3.

For an otherwise eligible authenticated request, configured message-size admission precedes application payload validation: a request above that limit uses STATUS=3 even if its length/opcode is also invalid for SAMPLE-1. Within that limit, a malformed READ/STATUS payload uses STATUS=7. For example, `01 00` uses STATUS=7 when the configured limit admits two bytes, and STATUS=3 when it admits only one. These rules do not authorize an error response to unauthenticated traffic or bypass the main rejection/retention policy.

The application sample source has `sample_epoch:u64` and `sample_index:u32`, separate from DMP SEQ/SEC-1 PN. Revision 2 uses a producer-owned persistent epoch counter: before first publication and after source state loss/restart or index exhaustion, atomically reserve and durably commit a never-reused epoch. Crashes may skip reserved values; counter/storage loss, rollback, failure or exhaustion MUST stop SAMPLE-1 publication until a separately authorized reprovisioning of producer identity/state prevents reuse. Do not wrap, infer an epoch from wall time or write persistent state for every sample. Index increases within the reserved epoch; the epoch/index/value snapshot is atomic.

An association that carries SAMPLE-1 is bound to one producer epoch. Before exposing a new epoch, the producer MUST close every association bound to its previous sample epoch and discard that association's pending SAMPLE-1 work. Serialize this transition with READ acceptance/snapshot creation, publication and association activation so an old association cannot expose a new epoch. Subsequent SAMPLE-1 traffic requires a newly activated association. Association rotation alone does not change an intact sample epoch. Closing a shared association also ends outstanding exchanges on its other services with the main unknown-outcome rules; this is the cost of avoiding a separate epoch-change opcode/state machine.

| Message | Exact plaintext payload | Delivery |
|---|---|---|
| TELEM sample | `sample_epoch:u64, sample_index:u32, value:u32` (16 bytes) | Best effort, unfragmented; replace an unsent obsolete sample |
| REQ READ | `opcode:u8=1` (1 byte) | ACK_REQ=1; read current sample once at acceptance |
| RSP READ | `opcode:u8=1, sample_epoch:u64, sample_index:u32, value:u32` (17 bytes) | Main reliable terminal result with own SEQ/ACK_REQ/REPLY_TO |
| REQ STATUS | `opcode:u8=2` (1 byte) | ACK_REQ=1; read service readiness once at acceptance |
| RSP STATUS | `opcode:u8=2, ready:u8` (2 bytes), ready is exactly 0 or 1 | Main reliable terminal result |
| ERR NO_SAMPLE | STATUS=64, empty payload | Terminal reliable application-result ERR for an accepted READ when no sample exists |

`value` is a dimensionless demonstration measurement; a production unit/scale requires another schema revision. READ and STATUS have no side effects. Duplicate requests replay the same retained result, not a new reading. A new REQ identity intentionally obtains a new snapshot. The manifest specifies finite sample production, request processing, retained result and late-result bounds under main §8.1. Loss of a receipt/result follows those rules; this profile does not supply durable operation lookup because the operations are read-only. No unsolicited RSP or other application opcode/type is accepted on this service.

## A2. Ordering and authorization

Only the configured producer principal may emit samples/results; the consumer has READ/STATUS permission. Source identity is the authenticated association principal, not the last relay or a payload field. Epoch values are not numerically ordered. The consumer MUST use this initialization procedure:

1. On startup or selection of a newly active association to that producer, enter `unsynchronized`, advance a local initialization generation, and select a generation-safe association identity (not a CID alone). Retain at most the previous selected epoch and its greatest sample index/value for this producer, but do not present that cached value as synchronized/live. Discard telemetry while unsynchronized; no pre-sync buffering is required.
2. Send a new reliable READ and designate its full request identity as the current synchronization request. The manifest sets finite maximum initialization READ attempts, retry intervals and an absolute initialization deadline. Ordinary application READ results do not initialize the epoch. Only one designated request is current; cancel/timeout/retry supersession invalidates the previous designation.
3. Only a valid, authorized, correlated READ RSP for the current `(association, initialization generation, designated request)` while unsynchronized may select the epoch. Validate that tuple and update the sample state atomically with respect to association replacement/cancellation. For a different epoch, clear the previous sample cache and install this snapshot. For the same retained epoch, preserve the greatest index/value: an older READ snapshot may complete synchronization but MUST NOT roll back a newer cached sample. Mark synchronized.
4. A NO_SAMPLE result remains a reliable terminal application ERR=64 and is acknowledged normally. Stay unsynchronized; if the bounded initialization policy allows, issue another READ with a new request identity. Retrying the old identity only retrieves its retained NO_SAMPLE result. Invalid results never complete synchronization. A timeout may similarly start a new read-only request within the original initialization budget; exhausted attempts/deadline leave an explicit local initialization failure and no live sample.
5. Once synchronized, accept live samples only from the selected association/producer and selected epoch, and replace the sample only with a greater index. A different epoch on that association is an application-contract violation, not permission to adopt it or automatically restart initialization. Late results from old/draining associations, superseded initialization requests or tombstones cannot select an epoch or modify the live cache; ordinary retained-correlation rules may still require their receipt ACK. Losing/replacing the selected association returns to step 1.

This uses existing READ bytes and adds no DMP opcode. Trusted association establishment enables the READ; it does not itself choose an application epoch. A remote restart is not detectable instantly: old authenticated traffic may arrive before the consumer selects a replacement association. The rule prevents rollback after local supersession and does not promise measurement freshness.

Timestamps, maximum measurement age and actuator freshness are not provided. A newer index only orders samples within an epoch. READ results return the snapshot associated with that request; a late result must not roll back a newer live display sample. The caller can expose the older snapshot as a correlated result without replacing current state.

## A3. Canonical payload examples

```text
READ request:       01
STATUS request:     02
STATUS ready:       02 01
TELEM epoch=1, index=2, value=300:
01 00 00 00 00 00 00 00 02 00 00 00 2C 01 00 00
READ result for the same sample:
01 01 00 00 00 00 00 00 00 02 00 00 00 2C 01 00 00
```

These are payload examples, not complete protected packets. Reject READ request `01 00`, empty request, opcode `03`, STATUS result `02 02`, wrong result opcode for the correlated request, wrong sender/service, and any TELEM length other than 16. Validate result payload before treating a response as request acceptance. A schema change requires an explicitly agreed application revision and updated manifest digest; no runtime sniffing or parallel old/new decoding is implied.

The [development plan](../dev/DMP_Implementation_Plan.md) calls for independent encoders/decoders and positive/negative examples. This small service does not itself generate large fragmented traffic: use a separate test-only opaque DATA workload to exercise SELECTIVE-32 without expanding the application API.

## A4. Required initialization cases

Exercise first boot; telemetry before READ result; NO_SAMPLE then a newly produced sample and a new READ identity; lost READ/result/receipt; initialization timeout/exhaustion; same-epoch reconnect with an older READ snapshot; producer restart/index exhaustion with a new epoch; late prior-association and superseded-request results; association replacement racing result acceptance; persistence failure and epoch reuse prevention; and shared-association closure during epoch change. Verify bounded state and no automatic epoch adoption from telemetry. Repeat provisional tests over real SEC-1 and between independent endpoints before conformance acceptance.
