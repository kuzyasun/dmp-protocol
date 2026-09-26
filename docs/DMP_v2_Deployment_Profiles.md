# DMP v2 — Reference deployment profiles

**Date:** 2026-09-26\
**Baseline:** DMP document revision 10, SEC-1 profile revision 5, BOOT_VERSION=2\
**Status:** normative reference-family choices for DIRECT-1 and RADIO-1. Site-specific manifests must still supply the parameters below; no implemented binding or production interoperability is claimed.

The [main specification](DMP_v2_Device_Messaging_Protocol_Specification.md) and [SEC-1 annex](DMP_v2_Security_Profile.md) remain authoritative. These two families narrow existing choices; they do not change packet encoding, ACK meaning or security policy for other DMP deployments. A completed manifest must still supply every applicable main §12.3 parameter. Claiming only `DIRECT-1` or `RADIO-1` does not establish interoperability.

## 1. Fixed reference-family choices

Owner namespace: `DMP-reference`; family revisions: `DIRECT-1/4` and `RADIO-1/4`. These identifiers are configuration strings, not newly allocated wire IDs. A product assigns its own deployment ID/revision and binds the exact complete manifest in SEC-1. Overrides of the fixed choices below require a differently identified family; they are not silent runtime adaptations.

| Choice | DIRECT-1 | RADIO-1 |
|---|---|---|
| Purpose | One direct device pair over UART or BLE | Device pair across raw-radio links, with zero or more transparent relays |
| Binding | Point-to-point UART uses Stream R; BLE requires an explicitly named and fully specified GATT/channel binding | One complete DMP frame per named raw-radio packet binding; no implicit binding segmentation |
| Routing | No DMP ROUTE; direct identity resolved from the authenticated association | Static unicast, explicit TO_NODE and CONTEXT from the origin, including on direct radio paths; no flooding or dynamic route discovery |
| Security | SEC-1 required for application traffic; ChaCha20-Poly1305 selected | Same pairwise end-to-end SEC-1 policy; relays hold no endpoint traffic keys |
| Enrollment | Deployment fixes PSK or authenticated XX for each pair; no automatic fallback | Same; small provisioned leaves can use PSK, while capable endpoints can use authenticated XX |
| Handshake failure | SEC-1 revision 5 abort-first; separately bounded establishment/restart policy | Same; loss retains cached retries, admitted invalid expected flights can end an attempt |
| Credentials and restart | Individual random PSK or authenticated public-key enrollment; volatile traffic associations; fresh handshake after state loss | Same; no offline restored traffic keys to avoid radio handshake cost |
| Live telemetry | Unfragmented TELEM, ACK_REQ=0; replace unsent obsolete state | Same; missed obsolete samples are not repaired |
| Commands/results | Main §8.1 reliable REQ/result exchange; one outstanding application operation per peer/service in this reference family | Same; return receive opportunities are required before admitting a reliable exchange |
| Fragment recovery | Whole-message retry under main §8 | SELECTIVE-32 for eligible reliable fragmented application messages; ordinary main §8 retry for unfragmented messages |
| Large objects | Separate bounded application blocks and explicit validation/commit | Same; never one arbitrarily large FRAG assembly |
| Payload | Product-defined service/schema; no mandatory serializer or per-frame descriptor when the manifest supplies it | Same service/schema wherever application semantics match DIRECT-1 |
| Gateway role | A direct endpoint terminates its own association | Relay preserves identity, immutable headers and ciphertext; only allowed TTL/outer-binding changes |

The two families deliberately exercise the same endpoint security and command semantics. SEC-1 remains optional in the general protocol; a trusted-wire plaintext product would use a separately identified profile. Native BLE security may coexist with SEC-1 but does not replace it in these families. CRC/framing detects corruption and is not authentication.

UART and BLE are binding variants of DIRECT-1, not interchangeable byte transports without a binding. A BLE manifest must specify UUID/channel identifiers, direction, packet boundaries, maximum value/frame size, any segmentation, ordering/loss handling, flow control and disconnect cleanup. RADIO-1 is raw radio, not LoRaWAN or Bluetooth Mesh. A UART multidrop bus is outside DIRECT-1.

## 2. Resource and deployment envelope

The following are fixed ceilings for the initial comparison families, chosen to bound an implementation experiment rather than derived from a particular MCU or radio. An instance may advertise lower limits explicitly in its agreed manifest. Higher limits require a new family revision and a new resource review.

| Bound | DIRECT-1 | RADIO-1 |
|---|---:|---:|
| Application logical message | 1,024 plaintext bytes | 1,024 plaintext bytes |
| Application fragments per logical message | 16 | 32 |
| Trusted application assemblies per peer | 1 | 1 |
| Concurrent reliable application operation per peer/service | 1 | 1 |
| SEC-1 replay window per direction | 1,024 bits | 1,024 bits |
| DMP forwarding TTL | Not present | At most 4 forwarding operations; actual route/TTL fixed by the instance |

The frame/path MTU can reduce the usable message size below 1,024 bytes: the fragment-count ceiling also applies. Live samples must fit one frame. A one-assembly-per-peer quota is shared across services, with admission failure handled before promising acceptance; it does not grant one assembly to every service. Independent bounded control/bootstrap capacity is reserved under main §18.1 and annex §S3.2 so an occupied application assembly cannot block security/control progress. Bootstrap fragmentation has its own explicit manifest quotas and must fit every required flight; it does not inherit the application-fragment RADIO-1 ceiling accidentally.

Each instance MUST also declare finite aggregate limits in bytes for DMP-owned/reserved RAM and DMP-attributable linked flash on each target role, plus finite admitted concurrency. The RAM envelope includes provider retained/scratch state, stacks, adapter/DMA buffers, queues, reassembly, result/correlation/rejection records and reserved control capacity at the worst permitted overlap (including handshake/rotation with application traffic). State any shared-storage accounting and hardware memory-region constraints. Admission MUST reserve within both per-pool and aggregate limits; multiplying per-peer limits without bounding the peer count is insufficient. Missing totals or a configuration whose conservative bound exceeds them fails validation. A measured target overrun fails the resource acceptance gate; raising the envelope requires an explicit reviewed profile revision, not an automatic update to match measurements.

These ceilings do not bound total RAM alone. The instance must bound peer count, global retained bytes, sender/result buffers, temporary decryption, accepted/rejected records, late-result correlation, queues and pending handshakes. An implementation may read immutable outgoing slices from bounded application storage instead of copying a whole object into a second RAM buffer. Storage lifetime must cover retries.

Before enabling either family, fill and validate:

1. **Transport:** binding ID/revision, maximum complete core/encoded frame, path MTU, actual link addresses, UART settings or BLE mapping, and disconnect/route-change behavior. RADIO-1 also needs radio PHY settings, channel access, legal/local airtime budgets, half-duplex turnaround, forward and return routes, and receive/sleep opportunities. A LoRa spreading factor or universal timeout cannot be inferred from the family name.
2. **Identity/application:** deployment ID/revision, namespace/node IDs, service map, exact payload schema, authorization, operation IDs/lookup where needed, and per-service freshness policy. Time-sensitive actuator commands explicitly select freshness; it is not silently disabled to save bytes.
3. **Finite timing:** transmission/queue/delivery bounds, receipt delay, processing/result deadlines, attempts/backoff/jitter, assembly lifetime, dedup/result/tombstone retention, and relay cooldown/count. Apply the inequalities in main §8.2 and §11.1; duplicates never renew absolute deadlines.
4. **Security/resources:** selected enrollment per pair, provisioning authority, secret lifecycle, handshake limits, association limits/drain, per-peer/global quotas, aggregate RAM/flash envelopes per target role, reserved control resources and admission outcomes. Include the explicit SEC-1 failed-verification limit in [1,65536], with no reset on successful traffic. Specify abort-first establishment episode attempt/deadline/work/traffic ceilings, restart backoff and later-episode rate/burst policy; retained pending attempts and simultaneous crypto/scratch slots are separate limits. Budget remote orphan occupancy and fresh-handshake cost across the complete scheduled path. No old manifest digest may select the new semantics implicitly.
5. **Reference sample initialization, when selected:** SAMPLE-1 revision 2 persistent producer epoch reservation and consumer synchronization by a fresh correlated READ; finite initialization attempts, retry intervals and total deadline. No epoch adoption from unsolicited telemetry.

If those facts are unavailable, the family is selected but the deployment is not ready to claim interoperability. In particular, no complete BLE binding, raw-LoRa PHY configuration or measured performance is asserted here.

## 3. Recovery policy follows the path and traffic

Use one statically agreed recovery policy per endpoint pair/application service, for both directions on the association. Eligibility is fixed by the recovery annex; it does not select another policy per message. One physical device may use DIRECT-1 toward a local controller and RADIO-1 toward a remote endpoint. A mixed UART/BLE-to-radio transparent path requires a separately identified mixed-binding profile: its origin applies the radio path's end-to-end limits and supplies explicit CONTEXT and ROUTE=TO_NODE before SEC-1 protection, even on the first wired/BLE hop. That is not a DIRECT-1 frame. A gateway cannot convert a protected DIRECT-1 frame into a routed RADIO-1 frame by inserting metadata, and must not change recovery mode, fragment geometry or encrypted content in transit.

| Traffic/path | Policy |
|---|---|
| Latest-state telemetry, any channel | Best effort, no repair of old samples |
| Small reliable message on a cheap path | Current whole-message retry; minimal recovery state |
| Unfragmented reliable message on RADIO-1 | Ordinary main §8 retry, within a finite admitted airtime budget |
| Eligible fragmented reliable message on RADIO-1 | SELECTIVE-32, at most 32 fragments, fixed service policy and finite feedback/repair/probe budget |
| File/log/firmware image | Independent application blocks with object identity, digest and final commit; bounded RAM and explicit resumption policy |

This is not a capability negotiation mechanism. A sender must not infer selective support from a timeout, radio type or an unrecognized response. There is no mid-transfer fallback. The current main revision defines SELECTIVE-32 in its own normative annex. The selected mode is fixed for both directions of a service on the association. The same application service ID is used for its replies and feedback. RADIO-1 excludes non-reliable fragmented application messages; bootstrap remains separately bounded retry-all.

## 4. Recovery and application contracts

[SELECTIVE-32](DMP_v2_Selective_Recovery.md) defines exact TYPE 8 control framing, missing-mask validation, timers, fresh-PN repairs/probes, state expiry and mandatory loss cases. It preserves final ACK/result meaning. DIRECT-1 does not implement that optional recovery module; RADIO-1 requires it. A cheap-radio retry-all deployment is still permitted by the general protocol under its own differently identified profile, not as a silently downgraded RADIO-1.

The [reference application](DMP_v2_Reference_Application.md) defines a deliberately small sample/read/status service shared across these families. It is an opt-in example contract; products can use their own separately identified schemas. It adds no firmware update or actuator command to the general protocol.

## 5. Conformance boundary

Before claiming a configured deployment, complete main §12.3 and validate every bound in the selected annex. RADIO-1 additionally specifies all recovery R3 parameters, a return slot capable of carrying protected FRAG_STATUS/ACK, strictly increasing per-origin SEQ allocation and retained terminal tombstones. A profile validator and deterministic loss simulator are development tasks in the [implementation plan](../dev/DMP_Implementation_Plan.md), not tools already supplied by this document.

The protocol contract is defined. Hardware-dependent values, independent endpoint implementations, full protected recovery vectors, fuzz/state-machine results, and measured performance remain release evidence to produce. Do not describe a selected profile family as a tested BLE binding or a measured LoRa deployment.
