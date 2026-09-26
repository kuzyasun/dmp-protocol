# DMP v2 — SELECTIVE-32 recovery

**Status:** normative implementation draft, recovery revision 1\
**Date:** 2026-09-26\
**Requires:** DMP document revision 9 and SEC-1 profile revision 4

This annex defines optional selective recovery for the [main specification](DMP_v2_Device_Messaging_Protocol_Specification.md). MUST/MUST NOT/SHOULD/MAY have their main-spec meanings. It specifies behavior, not a claim of implemented or measured interoperability. No cryptographic primitive or bootstrap encoding is changed.

## R1. Selection and scope

The authenticated deployment manifest selects exactly `retry-all` or `selective-32` for each peer/application service, including both its requests and reliable results. The choice is fixed before traffic and unchanged during an association. There is no negotiation, automatic fallback or per-fragment mode flag. An unsupported configured mode fails setup locally; timeout does not authorize downgrade. Unfragmented traffic uses ordinary main §8 behavior in either mode.

SELECTIVE-32 applies only to SEC-1-protected, unicast, ACK_REQ logical messages of TYPE REQ, RSP, EVENT, DATA, or terminal application-result ERR (STATUS >=64 with the service-defined terminal meaning). It requires 2–32 fragments and the profile's byte/resource limits. Protocol-rejection ERR, HELLO/bootstrap, ACK, TELEM and best-effort traffic never use this recovery. All original FRAG fields, immutable metadata, authorization/freshness rules and final acceptance semantics remain unchanged. Bootstrap still retries its complete flight.

The same service ID is used in both directions of a selective service, including feedback and results. The main canonical rule applies: omit the common application default and explicitly encode a nondefault service, including on feedback. Service 0 is excluded. Asymmetric reply-service translation is not supported by the main protocol. End-to-end paths through transparent relays are permitted; sources supply all routing metadata before encryption and relays do not terminate recovery.

## R2. FRAG_STATUS wire format

Allocate main TYPE **8**, named **FRAG_STATUS**, VT byte **0x48**. It is a recovery-control frame, not application DATA, a receipt ACK or a terminal ERR.

| Component | Requirement |
|---|---|
| OPTIONS | SEQ, SECURITY and EXT required; ACK_REQ, FRAG and PAYLOAD_DESC forbidden |
| Own SEQ | New logical control identity allocated by the feedback sender; never the referenced message's SEQ |
| SECURITY | Existing SEC-1 descriptor and full 16-byte tag; same association as the referenced transfer |
| ROUTE / CONTEXT / ORIGIN_ID | Existing rules; routed feedback uses TO_NODE back to the source and its own origin's context |
| REPLY_TO | Required; canonical compact ULEB32 reference to the original message SEQ, resolved by the recipient through its own sending direction on this association |
| SERVICE_ID | Explicit original application service, or omitted only when it equals the configured default |
| STATUS / FRESHNESS | Forbidden; feedback does not request command execution or carry a freshness lease |
| INTEGRITY | Forbidden together with SECURITY under SEC-1; any Stream R or native outer integrity remains outside the protected core |
| Other extensions | Existing unknown-extension/registry rules apply; no additional known extension is allocated here |
| Plaintext payload | Exactly four bytes, unsigned 32-bit **little-endian** missing mask |

Let `N` be the referenced transfer's fragment count derived from its retained geometry. Bit `i=1` requests fragment `i`; zero means that slice was present at snapshot time, not that application acceptance occurred. Require `2 <= N <= 32`, a nonzero mask, and all bits `i >= N` zero. For `N=32`, all 32 positions are available; implementations must avoid undefined shifts by 32. Feedback is generated only from an authenticated admitted incomplete assembly and therefore cannot request all N slices at once. The sender MUST reject an all-N-bits mask as well as a zero/out-of-range mask. Missing every initial fragment is recovered by the probe mechanism, not an unauthenticated synthetic status.

Authenticate before resolving the compact reference or modifying recovery state. Check exact peer, association/epoch, service, active referenced message, eligibility and N. Unmatched, malformed, unauthorized or stale feedback is dropped without a response. FRAG_STATUS is never ACKed, never causes an automatic ERR, never reaches an application message handler and never changes application receipt/result state. Endpoints that do not implement SELECTIVE-32 reject local TYPE 8 delivery; structurally capable relays may forward it under the usual rules.

### R2.1 Identity and ordering

On an association using SELECTIVE-32, each origin allocates SEQ in strictly increasing numeric order across all services/types in its epoch; retire the epoch before wrap. Gaps are permitted. Every emitted status snapshot, including a response to a later probe with an unchanged mask, gets a new SEQ and fresh PN. Do not retry feedback through the reliable-message engine. Lower-binding duplicate delivery is governed by SEC-1 replay rules.

The original sender retains the greatest accepted feedback SEQ per active transfer. Accept only a strictly greater one after all R2 validation; invalid feedback cannot advance that value. PN replay checks are separate: an old distinct snapshot can have a valid PN. Newer feedback may cause redundant repairs after network reordering, but cannot reopen a terminal transfer, extend deadlines, or trigger simultaneous repair bursts. It replaces the single pending mask; it is not added as another queued burst. Slices remain immutable even when a peer requests them again.

## R3. Timing and resource contract

The manifest supplies finite positive durations/counts in a specified monotonic time unit:

| Parameter | Definition |
|---|---|
| `burst_span` | Maximum elapsed time from first frame transmission start to last transmission completion in any initial/repair/probe burst, including channel-access gaps |
| `forward_delay`, `return_delay` | Maximum from local transmission completion of a frame at its origin to completion of its authenticated receive validation/admission at the remote endpoint, including downstream relay queues/transmissions, binding reconstruction and bounded endpoint queue/crypto work; forward is original-message direction, return is feedback/receipt direction |
| `feedback_guard` | Receiver quiet/turnaround margin after the bounded collection interval |
| `feedback_delay` | Maximum time from a feedback opportunity becoming due to complete feedback transmission, including queueing and receive-slot scheduling |
| `response_timeout` | Sender wait after last local transmission completion; at least `2 * forward_delay + burst_span + feedback_guard + feedback_delay + return_delay` |
| `send_horizon` | Absolute end-to-end transmission horizon from first transmission start, including all waits and retries |
| `max_bursts`, `max_probes`, `max_status` | Caps per logical transfer; initial burst counts toward max_bursts, probes count toward both max_bursts and max_probes |
| `max_transfer_airtime` | Origin/receiver transmission budget plus separately configured relay limits; not inferred from byte count alone |
| `record_margin` | Positive processing/clock uncertainty margin for retention calculations |

The binding must actually provide those bounds and feedback receive opportunities; otherwise configuration/admission fails. They are not universal LoRa constants. The response timeout must also meet main §8.2 final-receipt constraints. Reassembly lifetime from first admitted slice must be at least `send_horizon + forward_delay + record_margin` and cover main §11.1 `T_collect`; disabling the shorter inactivity timeout is the revision-1 policy. Old duplicates/probes do not renew absolute lifetimes.

The two forward-delay terms follow from R4's arrival-based timer. Let `tL` be the burst's last local transmission completion. If only its last slice survives, first admission can occur at `tL + forward_delay`; the collection timer then adds `burst_span + forward_delay + feedback_guard`, followed by feedback transmission and return delivery. A validator MUST use this bound rather than assume that the collection timer started at the sender's first transmission. At an equal deadline, process an already available valid terminal event or feedback before scheduling a timeout probe; otherwise reserve a positive scheduler margin in `response_timeout`.

For a relayed path, validate recovery against the configured per-hop cooldown, forward-count, expiry and airtime limits under the binding's stated delay/duplication model. Each intended repair/probe forwarding opportunity must occur after that key's cooldown and within its remaining count/lifetime/airtime budget; delay source scheduling when necessary and include that delay in the admitted burst/horizon bounds. Use arrival-time bounds at each relay, not only origin transmission spacing. `max_bursts` already includes the initial burst, and one slice need not occur in every repair. Additional lower-binding duplicates can consume forwarding opportunities, so neither `1 + max_bursts` nor one end-to-end cooldown inequality is a universal sufficient count/schedule rule. A manifest claiming those recovery opportunities MUST supply a checkable schedule/budget envelope; reject a contradictory one. Loss or hostile traffic beyond that envelope can still exhaust relay budgets under main §10.4; this is not a delivery guarantee.

Size frames for worst permitted PN and fragment-index encoding before admitting a transfer, including the complete protected status/receipt on the return path. A status is unfragmented and MUST fit the return MTU. Reserve sender storage, whole receive assembly, metadata/retention records and bounded control buffers before their respective admission. One application assembly per peer can suffice. Feedback bypasses the application stop-and-wait gate but obeys control quotas, scheduling fairness and rate/airtime limits. It must not borrow the only resource needed to authenticate an incoming receipt.

## R4. Receiver state machine

1. **Admission:** authenticate a slice; enforce service/geometry/freshness/admission rules and accepted/rejected history before creating an assembly. Retain first-admission time and immutable metadata. Quota failure may use main-spec rejection only with its required retained decision; otherwise drop locally.
2. **Collect:** retain valid slices and compare duplicates as in main §11. The first valid matching slice while no collection timer is armed starts one timer for `burst_span + forward_delay + feedback_guard` from its arrival. Subsequent valid slices, including the original final slice, do not move the due time. This conservative bound avoids treating ordinary in-burst gaps or reordering as loss.
3. **Feedback opportunity:** at the due time, atomically snapshot the current missing mask. If incomplete and budgets/association are valid, emit one FRAG_STATUS within feedback_delay. Only one status may be pending; regenerate its snapshot and allocate SEQ/PN at actual construction, or cancel it if no longer incomplete. No autonomous periodic statuses follow: another valid matching slice/probe is needed to arm the next collection timer after this opportunity. A status does not itself arm a timer. Status count and transfer/assembly deadlines are absolute bounds.
4. **Complete:** atomically prevent construction/submission of further partial feedback. A status already submitted to an asynchronous adapter may still arrive as stale feedback; cancellation/release must obey main §16.2 and its buffer stays owned until the terminal completion callback. Validate the complete message and required freshness, then accept/reject under main §7/§8.1. Full slice reception alone does not authorize a success ACK. A reliable REQ can yield its normal acceptance ACK or immediate reliable result; a reliable RSP/result ERR is ACKed as a result. Do not wait for the collection timer before returning a permitted complete-message receipt.
5. **Already accepted:** a valid fresh-PN duplicate/probe follows existing acceptance-record behavior without reassembly or re-execution. For accepted REQ with an active fragmented SELECTIVE-32 result transfer, repeat only the request receipt subject to limits; let the existing result state machine continue on its own schedule. Do not enqueue a second result transfer, repeat its full fragment set, or reset its timer. A terminal/released selective result is not reopened by the duplicate REQ; repeat only the retained request receipt. Non-selective results retain main §8.1 behavior within their original budget. No new partial feedback may be submitted after acceptance.
6. **Incomplete-state loss/expiry:** do not re-admit that previously admitted identity. Retain a bounded rejection/expired tombstone until at least `first_admission + send_horizon + forward_delay + return_delay + record_margin`, and longer if main §8 requires it. Cancel feedback and drop later slices (a retained protocol rejection may be repeated under main rules). Reserve tombstone capacity on initial admission; do not silently evict it. This deliberately avoids receiver bitmap rollback and a new resume protocol. SEC-1 state loss instead destroys the association under the annex restart rule.

A receiver that never admitted any slice and has no accepted/rejected record may admit an original-final-fragment probe as its first slice. That is initial admission, not reopening an evicted assembly. The probe authenticates total length, chunk size and identity; the missing mask then requests all other slices. A valid association is required. No feedback is generated for a completely unheard transfer.

## R5. Sender state machine

1. Allocate original SEQ once. Retain immutable logical contents/slices, association and transfer bounds. Check that the initial and configured possible repair/probe schedule fits send_horizon, receiver lifetime, result/receipt contracts and airtime limits.
2. Send the initial set in ascending index order. All slices have the original SEQ and their own fresh PN. A burst has one bounded transmission schedule and cannot overlap another burst for this transfer. Start response_timeout at its final local completion, using the adapter ownership rules.
3. Accept matching terminal receipt/result/rejection under main §8; these take precedence over any pending status and end recovery for the referenced logical message. Request-result waiting after a receipt remains main §8.1 behavior. A result's selective retransmission is a separate logical transfer.
4. For a valid newer FRAG_STATUS while waiting, schedule one ascending-index repair burst containing the requested missing slices. Status is only a repair hint, never a receipt. While another burst or its send callbacks are active, retain only the newest pending mask and process it once that burst completes; do not create concurrent sends. A terminal event cancels unsent work with ownership settled according to the adapter contract.
5. If the response wait expires with no pending valid repair and no terminal event, send the **original last fragment** (index N−1) as a one-frame probe with a fresh PN. This recovers lost final fragments, lost feedback, a completely lost initial burst and lost final receipts without allocating another control opcode. It may carry a full-size slice; budget its real cost.
6. After every repair/probe burst, wait again under the same absolute deadline and counters. Every scheduled burst/probe/status consumes its relevant budget. Reaching any configured limit, losing the association, path-MTU infeasibility or cancellation ends local recovery with the main-spec failure/unknown outcome. Do not automatically restart a non-idempotent operation under a new SEQ or switch to retry-all.

Store the full original logical data until final acceptance or termination. A zero bit in feedback does not permit freeing a slice. Re-protect retries with a fresh PN, preserve immutable metadata and account for header-length growth. Never resend cached ciphertext as a logical retry. Feedback cannot reset send_horizon, result deadline, counters or association limits. After terminal state, late feedback is dropped; main request/result tombstones and application lookup govern late results.

## R6. Loss cases and examples

| Fault | Required outcome |
|---|---|
| Two of eight fragments missing (indices 2 and 6) | Mask `0x00000044`; plaintext bytes `44 00 00 00`; repair indices 2,6 only |
| Final or all initial fragments lost | Sender probe of index N−1 can start/complete assembly; next status requests other gaps |
| Status lost | Timeout/probe yields a new bounded status with a new SEQ |
| Repair slice lost | Next collection opportunity reports remaining gaps |
| Final ACK lost | Fresh-PN probe reaches accepted cache; receipt/result repeated without execution |
| Status reordered/duplicated | Ignore logical SEQ <= greatest accepted for this transfer; never update from invalid input |
| Assembly expires/is discarded | Retained tombstone prevents new assembly/expiry renewal for that identity |
| Receiver restarts | Old association unusable; no selective resume across associations |
| Status arrives after acceptance | Drop; do not reopen recovery |
| No return schedule / smaller path MTU | Reject configuration/admission or terminate an affected active transfer explicitly |

Illustrative direct protected status before encryption, with own SEQ=9, cipher=1, receive CID=1, PN=7, referenced SEQ=5 and default service:

```text
48 0A C1 09 01 01 07 05 01 05 | 44 00 00 00
\________ header (AAD) _______/   plaintext mask
```

SECURITY_DESC uses the existing cipher/CID/PN layout; extension tag `05`, length `01`, value `05` is REPLY_TO. The complete frame replaces plaintext with four ciphertext bytes and appends the existing 16-byte AEAD tag: 30 bytes with these one-byte counters, excluding the binding. The above is a canonical header/plaintext example, **not** a complete authenticated frame or reusable nonce/key vector. Generate protected vectors through the SEC-1 fixture harness before implementation conformance is claimed.

Mask boundary examples: N=2, missing index0 -> `01 00 00 00`; N=32, missing index31 -> `00 00 00 80`. Reject N=2 with `04 00 00 00` (out of range), `03 00 00 00` (all missing), any zero mask, and payload sizes other than four. Reject ACK_REQ, FRAG, DESC, STATUS, FRESHNESS, missing reference, wrong association/service, unsupported mode and a reference to an ineligible/unfragmented/terminal message.

If data-frame cost is F and status cost is B, repairing two of eight equal-size fragments costs `2F+B` versus `8F`, before any extra probes/losses and excluding a common receipt. This is not a measured airtime/energy claim. Downlink limits, turnaround and feedback loss may make retry-all cheaper for tiny sets.

## R7. Implementation verification

The [implementation plan](../dev/DMP_Implementation_Plan.md) schedules canonical protected vectors, parser checks, a deterministic loss/state simulator, profile validation, two-endpoint interoperability and equivalent-workload benchmarks. Existing SEC-1 vectors cover their published subset only; they do not prove this state machine or the new control type. Required tests include the R6 table, full initial loss, delayed snapshots during transmission, no feedback storm, tombstone pressure, result-vs-status races, PN/SEQ boundaries, mismatched service/association, relays with cooldown, expiry, ACL/freshness failures and unavailable receive slots. Release requires independent implementation evidence.

Design precedents: [SCHC ACK-on-Error, RFC 8724](https://www.rfc-editor.org/rfc/rfc8724.html#section-8.4.3), [CoAP Q-Block, RFC 9177](https://www.rfc-editor.org/rfc/rfc9177.html#section-5). Their wire formats are not DMP modes.
