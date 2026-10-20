# DMP v2 — SAMPLE-1 reference application

**Status:** normative only for deployments explicitly selecting `DMP-reference/SAMPLE-1/3`\
**Date:** 2026-09-26\
**Requires:** DMP revision 11; optional SEC-1 profile revision 5

This small contract demonstrates opaque payload interoperability across [DIRECT-1 and RADIO-1](DMP_v2_Deployment_Profiles.md). It is not a production DTrack RPC schema or an actuator/OTA interface. Products may define other profiles. Numeric values below have meaning only inside this explicitly selected profile.

## A1. Service and encoding

Application service ID is 1, also the default on both endpoints. All SAMPLE-1 messages and their receipts omit SERVICE_ID under the main canonical rule; replies use the same service. The endpoint instance explicitly selects NONE or SEC-1 before traffic; no packet negotiates or changes that selection. PAYLOAD_DESC is omitted: the manifest selects this fixed binary schema and exact application revision. All integers are unsigned little-endian; no native C struct padding, strings, implicit fields or trailing bytes are permitted. Security service 0 retains its annex meaning only when SEC-1 is enabled. An invalid request length/opcode or missing ACK_REQ is rejected before request acceptance with main STATUS=7 and the required retained rejection decision; an unsupported selected schema/profile uses STATUS=2, and a message exceeding configured size uses STATUS=3. NONE Core frames use the main §13 CRC32C rule and configured contexts; CRC does not authenticate a sample producer.

For an otherwise eligible request (authenticated in SEC-1 mode, context-matched in NONE mode), configured message-size admission precedes application payload validation: a request above that limit uses STATUS=3 even if its length/opcode is also invalid for SAMPLE-1. Within that limit, a malformed READ/STATUS payload uses STATUS=7. For example, `01 00` uses STATUS=7 when the configured limit admits two bytes, and STATUS=3 when it admits only one. In NONE mode a CRC-valid configured peer can still be spoofed; this does not create an authentication guarantee. Apply the main rejection/retention policy only after selected-mode validation.

The application sample source has `sample_epoch:u64` and `sample_index:u32`, separate from the per-instance DMP boot epoch/SEQ and SEC-1 PN. Revision 3 preserves the producer-owned persistent sample epoch: before first publication and after source state loss/restart or index exhaustion, reserve and durably commit a new epoch. The bundled NVS adapter stores a CRC-protected anchor and epoch record, commits a pending reservation before the epoch record, and fails closed on malformed records or storage errors. Host tests cover normal restart and interrupted commits; power-loss behavior has not been qualified on a physical target. Ordinary NVS cannot detect restoration of a complete older flash/NVS image, so restoring such an image can reuse a sample epoch. This implementation therefore does not provide rollback resistance against full-device image restore.

Deployments that require rollback resistance MUST supply and qualify a separate trusted counter through the anchor port. The counter must keep its high-water mark outside storage restored with the application flash, bind that value to the producer principal, preserve pending reservations across resets, and fail closed if its state is lost or exhausted. A qualified secure element with a monotonic counter is one possible implementation; the exact component and target qualification remain open. No eFuse counter adapter or eFuse operation is included. Crashes may skip reserved values; counter/storage loss or exhaustion stops SAMPLE-1 publication until separately authorized reprovisioning prevents reuse. Do not wrap, infer an epoch from wall time or write persistent state for every sample. Index increases within the reserved epoch; the epoch/index/value snapshot is atomic.

SAMPLE-1 state is bound to its configured producer context and sample epoch. Before exposing a new application sample epoch, the producer MUST invalidate every prior context/association bound to its previous sample epoch and discard that generation's pending SAMPLE-1 work. Serialize this transition with READ acceptance/snapshot creation, publication and context/association activation so an old context cannot expose a new sample epoch. In NONE mode, install/rebind the new boot/context epoch explicitly through the API and require a new synchronization READ; in SEC-1 mode, retain the existing association lifecycle. Association rotation alone does not change an intact sample epoch. Closing a shared secure association also ends outstanding exchanges on its other services with the main unknown-outcome rules; no separate epoch-change opcode is added.

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

Only the configured producer may emit samples/results; the consumer has READ/STATUS permission. In SEC-1 mode, source identity is the authenticated association principal. In NONE mode, it is only the explicitly configured context/transport-peer mapping and provides no cryptographic source guarantee. Neither mode uses the last relay or a payload field as source identity. Application sample_epoch values are not numerically ordered. The consumer MUST use this initialization procedure:

1. On startup or explicit selection/replacement of a producer context/association, enter `unsynchronized`, advance a local initialization generation, and select a generation-safe context identity (not a slot index or CID alone). Retain at most the previous selected sample epoch and its greatest sample index/value for this producer, but do not present that cached value as synchronized/live. Discard telemetry while unsynchronized; no pre-sync buffering is required.
2. Send a new reliable READ and designate its full request identity as the current synchronization request. The manifest sets finite maximum initialization READ attempts, retry intervals and an absolute initialization deadline. Ordinary application READ results do not initialize the epoch. Only one designated request is current; cancel/timeout/retry supersession invalidates the previous designation.
3. Only a valid, configured-context-correlated READ RSP for the current `(context generation, initialization generation, designated request)` while unsynchronized may select the sample epoch. In SEC-1 mode it must also be authenticated and authorized. Validate that tuple and update the sample state atomically with respect to context/association replacement and cancellation. For a different sample epoch, clear the previous sample cache and install this snapshot. For the same retained sample epoch, preserve the greatest index/value: an older READ snapshot may complete synchronization but MUST NOT roll back a newer cached sample. Mark synchronized.
4. A NO_SAMPLE result remains a reliable terminal application ERR=64 and is acknowledged normally. Stay unsynchronized; if the bounded initialization policy allows, issue another READ with a new request identity. Retrying the old identity only retrieves its retained NO_SAMPLE result. Invalid results never complete synchronization. A timeout may similarly start a new read-only request within the original initialization budget; exhausted attempts/deadline leave an explicit local initialization failure and no live sample.
5. Once synchronized, accept live samples only from the selected association/producer and selected epoch, and replace the sample only with a greater index. A different epoch on that association is an application-contract violation, not permission to adopt it or automatically restart initialization. Late results from old/draining associations, superseded initialization requests or tombstones cannot select an epoch or modify the live cache; ordinary retained-correlation rules may still require their receipt ACK. Losing/replacing the selected association returns to step 1.

This uses existing READ bytes and adds no DMP opcode. The caller explicitly installs/selects the producer context and then designates a fresh READ; in SEC-1 mode an authenticated association is also required. Context/association selection does not itself choose the application sample epoch. A remote restart is not detectable instantly: delayed traffic may arrive before the consumer installs a replacement context. Incoming packets never replace the configured epoch/context automatically. The rule prevents rollback after local supersession and does not promise measurement freshness.

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
