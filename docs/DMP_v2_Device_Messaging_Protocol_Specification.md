# DMP v2 — Device Messaging Protocol Specification

**Status:** implementation draft, revision 10\
**Date:** 2026-09-26\
**Wire major version:** 2\
**Document revision:** 10; not encoded in the VT byte\
**Payload:** opaque bytes; no required serializer\
**Scope:** packet framing, stream bindings, message identity, optional delivery and fragmentation, transport-independent routing profiles

> This unreleased draft uses document revision 10, SEC-1 profile revision 5 and BOOT_VERSION=2. Peers MUST explicitly agree on this revision and the selected modules/profile: VT=2 alone does not identify a compatible draft. Revision 10 changes handshake failure semantics, not bootstrap layout; old manifest digests must not be reinterpreted under the new policy. Other draft encodings/policies are unsupported and MUST NOT be autodetected. A released wire format will require a stable version/profile compatibility policy.

The informative [design tradeoffs and evaluation guide](DMP_v2_Design_Tradeoffs.md) records the prior-art review, candidate extensions and measurement plan. It does not allocate additional interoperable features.

The [reference profile families](DMP_v2_Deployment_Profiles.md) fix DIRECT-1 and RADIO-1 choices. The normative [SELECTIVE-32 annex](DMP_v2_Selective_Recovery.md) defines optional selective recovery; deployments without it retain retry-all. The [reference application](DMP_v2_Reference_Application.md) supplies a small exact sample/read/status contract, and the [development plan](../dev/DMP_Implementation_Plan.md) separates future implementation and tooling from specified behavior.

## Contents

1. Scope and conformance
2. Layering and network ownership
3. Core frame and message types
4. Integer encoding and parser boundaries
5. Sequence numbers and message identity
6. Extensions and registries
7. Replies, ACK and errors
8. Reliability profile
9. Routing metadata
10. Mesh profiles and forwarding
11. Fragmentation and reassembly
12. Payload descriptor and application profiles
13. Integrity
14. Security requirements
15. Stream bindings
16. Transport adapter contract
17. Bridges and mixed networks
18. Sleeping nodes, queues and expiry
19. Capability configuration and HELLO
20. Parsing, validation and error handling
21. Portable API and implementation boundaries
22. Wire examples and conformance vectors
23. Overhead accounting
24. Implementation and release sequence
25. Optional future features
26. Design references

## 1. Scope and conformance

The uppercase terms MUST, MUST NOT, SHOULD, SHOULD NOT and MAY express requirements of this draft. A feature marked **reserved** has no interoperable encoding in this revision. An implementation MUST reject an unsupported required feature; optional implementation support does not make an enabled wire feature ignorable.

DMP connects devices, gateways and applications over packet transports or explicitly selected stream bindings. It carries opaque application payloads and optional metadata. It does not require IP, a broker, an RTOS or MessagePack.

Conformance is modular:

| Module | Revision 10 status | Dependency |
|---|---|---|
| Core packet encoder/parser | Defined | Agreed application/binding context |
| Payload descriptor and extensions | Defined | Registry/profile agreement |
| CRC32C integrity | Defined | None |
| Stream L, length-delimited | Defined | Core |
| Stream R, COBS + CRC32C | Defined | Core |
| Direct reliability | Defined rules; deployment parameters required | Identity, REPLY_TO, cache/timers |
| Reliable request/result exchange | Single behavior for REQ with ACK_REQ; deployment parameters required | Direct reliability, result retention and correlation |
| Fixed-stride fragmentation | Defined | Identity, total-length admission and bounded reassembly |
| SELECTIVE-32 fragment recovery | Defined in normative recovery annex; optional implementation | SEC-1, reliable unicast, explicit service policy and bounded feedback schedule |
| Mesh static-unicast / bounded-flood | Defined data-plane behavior; deployment parameters required | ROUTE, identity, forwarding policy |
| Dynamic route discovery / tree control plane | Architecture only | Separate mesh-control profile |
| SECURITY / SEC-1 AEAD | Defined in normative security annex | Noise PSK or authenticated pairing; association/replay state |
| HELLO security bootstrap/confirmation | Defined for SEC-1 | Configured profile, credentials and bounded handshake state |
| SEC-1 freshness service | Optional implementation support; required only by services selecting it | SEC-1 and reliable request/result exchange |
| Generic capability negotiation | Not defined | Static configuration supported |

A conformance claim MUST name supported modules and configured limits. Supporting DMP Core does not imply reliable delivery, mesh participation, cryptographic protection or compatibility with another network's native routing protocol.

The [SEC-1 annex](DMP_v2_Security_Profile.md), its [test vectors](DMP_v2_Security_Test_Vectors.json) and the optional [SELECTIVE-32 annex](DMP_v2_Selective_Recovery.md) are part of this specification. Completeness is scoped: Core, the stated delivery/fragmentation/forwarding profiles, SELECTIVE-32 and SEC-1 have defined contracts. Dynamic mesh discovery, group cryptography, generic capability negotiation and vendor/native transport bindings not specified here are not silently included in a conformance claim. Profiles may configure finite limits and credentials; they MUST NOT invent encodings for an advertised module.

TLV and payload serialization solve different problems. The extension area uses a tag-length-value structure for optional metadata; this does not constrain payload representation, fragmentation or security. MessagePack is one optional payload codec, not the protocol's extensibility mechanism.

## 2. Layering and network ownership

DMP has three independent concerns:

- **Message layer:** type, payload, identity, replies, optional fragmentation and integrity.
- **Optional DMP mesh layer:** logical addressing and forwarding over links that do not already provide the required multi-hop delivery.
- **Binding/adapter:** packet boundaries or stream framing, local transport addresses, MTU, transmission scheduling and native-network delivery.

| Underlying environment | Routing owner | DMP use |
|---|---|---|
| Direct UART, TCP or packet link | No mesh required | Message framing and optional application delivery confirmation |
| UDP over Thread or another IP mesh | Existing IP/network stack | DMP in UDP payload; no repeated DMP routing by default |
| Bluetooth Mesh | Existing Bluetooth Mesh stack | Defined application/vendor model binding, with its own size and access rules |
| Existing LoRa mesh stack | That stack | Its supported application-data binding |
| LoRaWAN | LoRaWAN gateways/network infrastructure | Application payload; not a general peer mesh |
| Raw LoRa or another neighbor-only radio | Optional DMP mesh module | DMP ROUTE and an explicitly configured forwarding profile |

DMP is not automatically a native Thread, Bluetooth Mesh, LoRaWAN or Meshtastic application merely because the payload is binary. Each binding must obey the host stack's application model, provisioning, addressing and limits.

The wire decoder can recognize ROUTE while the application chooses whether to enable a DMP router. RSSI, SNR, radio settings, parent choice and next-hop link addresses do not belong in the mandatory core header.

## 3. Core frame and message types

A packet binding delivers exactly one complete DMP frame:

```text
VT : u8 | HDR_LEN : u8 | optional header | payload | optional trailer
```

No packet-mode magic or length prefix is required. Payload begins at HDR_LEN. The packet binding supplies the total frame length. Multiple DMP frames MUST NOT be concatenated into one packet without a separate batch/container binding.

### 3.1 VT

```text
VT = (2 << 5) | TYPE
```

| TYPE | Name | Meaning |
|---:|---|---|
| 0 | REQ | Application request |
| 1 | RSP | Application result, linked by REPLY_TO |
| 2 | ERR | Correlated rejection/failure; STATUS required |
| 3 | HELLO | SEC-1 bootstrap/confirmation; otherwise unsupported unless separately specified |
| 4 | EVENT | Asynchronous event |
| 5 | TELEM | Telemetry |
| 6 | ACK | Complete message accepted by final DMP endpoint |
| 7 | DATA | Generic application bytes |
| 8 | FRAG_STATUS | SELECTIVE-32 authenticated missing-fragment feedback; not a success receipt |
| 9–23 | Reserved | Reject at endpoint unless assigned by a later agreed revision |
| 24–31 | Profile-defined | Meaning requires an agreed application profile |

A router MAY carry an unknown TYPE opaquely if all required forwarding metadata is understood and policy permits it. An endpoint MUST NOT dispatch an unknown TYPE to a handler with guessed semantics.

### 3.2 Header length and OPTIONS

`2 <= HDR_LEN <= 255`. The length includes VT, HDR_LEN and all optional fields. It excludes payload and trailers. A header with no options MUST use HDR_LEN=2.

When HDR_LEN>2, OPTIONS appears at offset 2:

| Bit | Mask | Name |
|---:|---:|---|
| 0 | 0x01 | SEQ |
| 1 | 0x02 | ACK_REQ |
| 2 | 0x04 | ROUTE |
| 3 | 0x08 | FRAG |
| 4 | 0x10 | INTEGRITY |
| 5 | 0x20 | PAYLOAD_DESC |
| 6 | 0x40 | SECURITY; SEC-1 descriptor and 16-byte authentication tag |
| 7 | 0x80 | EXT |

OPTIONS=0 is noncanonical and MUST be rejected. ACK_REQ adds no field by itself.

Fields MUST occur in this order:

```text
OPTIONS
[SEQ]
[ROUTE]
[FRAG]
[PAYLOAD_DESC]
[INTEGRITY_DESC]
[SECURITY_DESC — SEC-1 when SECURITY is set]
[EXTENSIONS]
PAYLOAD
TRAILER
```

Without EXT, parsing the standard fields MUST end exactly at HDR_LEN. With EXT, one or more complete extension entries MUST end exactly at HDR_LEN. Padding and unexplained header bytes are forbidden.

## 4. Integer encoding and parser boundaries

All variable integers use minimal unsigned LEB128. Seven data bits are stored per byte, least significant group first; bit 7 means another byte follows. Signed or overlong encodings are forbidden.

| Fields | Maximum decoded value | Maximum encoded bytes |
|---|---:|---:|
| SEQ, node ID, namespace ID, codec/schema/service/profile ID | 2^32−1 | 5 |
| Fragment index/chunk size/total length, extension tag/length, frame length, status | 2^32−1 | 5 |
| Security packet number PN | 2^64−1 | 10 |

For u32 the fifth byte cannot contain data above bit 3; for u64 the tenth byte can contain only data bit 0. Neither final byte may request continuation. Encoders MUST use the shortest form. Parsers MUST reject truncation, overflow and non-minimal forms.

Examples: `0 -> 00`, `127 -> 7F`, `128 -> 80 01`, `16384 -> 80 80 01`. `80 00` is invalid.

Fixed multi-byte integers in defined DMP fields use little-endian encoding, including CRC32C and SEC-1 bootstrap/control integers. Cryptographic nonce construction follows the exact suite definition, including AESGCM's specified big-endian nonce counter. Payload byte order is controlled by its codec/schema, not by DMP. Sending a native C struct is portable only if the application specifies layout, padding and byte order independently.

Epoch is an exception to the variable-integer table: it is always exactly eight bytes, u64 little-endian, wherever explicitly carried in CONTEXT or a full REPLY_TO. It is not ULEB. This avoids expansion of the hash-derived SEC-1 epoch. PN retains its defined ULEB encoding and SEC-1 allocation limits.

Each decoder MUST enforce field, header, packet and deployment-specific limits before allocation. Compute payload length only after verifying `trailer_len <= frame_len - HDR_LEN` to avoid unsigned underflow.

## 5. Sequence numbers and message identity

SEQ identifies a logical message generated by its own origin. It is not a response correlation ID or a cryptographic nonce.

The full message key is:

```text
(namespace_id, origin_id, epoch, seq)
```

These values are obtained from a validated context and/or explicit fields:

- origin_id: ROUTE.source_id, ORIGIN_ID extension, or an unambiguous binding context;
- namespace_id and epoch: CONTEXT extension or an established binding/profile context;
- seq: SEQ field.

Explicit values MUST agree with any fixed/authenticated context. ROUTE.source_id and ORIGIN_ID MUST NOT both be present. A reliable direct binding must assign stable logical identities to both peers; a socket handle or next-hop radio address is not itself an end-to-end origin identity.

Namespace IDs partition a configured deployment; they are not globally unique or proof of trust. A bridge must map them consistently across its domains. CONTEXT identifies the **origin's** epoch, not the local router's epoch.

An origin MUST NOT reuse a full message key for different logical contents during the applicable acceptance/cache lifetime. SEQ is allocated per `(namespace, origin, epoch)` across destinations and message types. RSP, ERR and ACK allocate their own SEQ; they never echo the original SEQ as their own identity. Retransmission preserves identity and immutable content. All fragments of a message share its SEQ.

SEC-1 defines association-bound epochs and a separate encryption PN. Its logical retries retain SEQ and plaintext but use fresh PN/ciphertext/tag; those protection bytes and the resulting PN-length-derived HDR_LEN change are not immutable logical content. Receive selectors, cipher and association stay fixed during one logical message. Bootstrap provisional identities never enter trusted application acceptance state.

Epoch rules MUST be specified by the deployment:

- persist counters safely across restart, or establish a new epoch before reusing SEQ;
- retire an epoch before u32 SEQ wraps;
- define old-epoch acceptance, outstanding replies and maximum message lifetime;
- do not adopt an epoch from an unauthenticated packet as trusted security state.

Random boot identifiers require a collision model. They do not alone provide replay protection or AEAD nonce uniqueness. An epoch may be implicit only if every relevant participant can resolve it unambiguously. Otherwise send CONTEXT.

SEQ is REQUIRED for ACK_REQ, ACK, every REQ/RSP/ERR, FRAG, SECURITY and all DMP mesh forwarding. Simple best-effort DATA/EVENT/TELEM may omit it when none of those features requires identity.

## 6. Extensions and registries

Each entry in the EXT area is:

```text
EXT_TAG   : ULEB32 = (extension_id << 2) | (U << 1) | C
EXT_LEN   : ULEB32
EXT_VALUE : EXT_LEN bytes
```

C means critical for an endpoint. U means unsafe for an unaware DMP forwarding intermediary. These bits are independent; extension IDs therefore occupy at most 30 bits.

| Unknown extension | Endpoint behavior | DMP forwarding behavior |
|---|---|---|
| C=0, U=0 | Ignore semantics | Preserve and forward if otherwise valid |
| C=1, U=0 | Reject local delivery | Preserve and forward if otherwise valid |
| C=0, U=1 | Ignore endpoint semantics | Reject forwarding |
| C=1, U=1 | Reject local delivery | Reject forwarding |

If a node is both a destination and a relay, these decisions apply separately. Rejecting local delivery does not imply rejecting otherwise permitted forwarding. A network stack carrying the whole DMP frame as opaque application data is not a DMP extension interpreter.

Known extensions MUST use the flags assigned below and satisfy their defined encoding. A sender cannot downgrade an extension by clearing C or U. Entries MUST be in increasing extension ID order. All extensions in this revision are singleton; duplicates are malformed. For a known extension, zero-length values are allowed only by its definition, and its decoded value MUST consume exactly EXT_LEN bytes. For an unknown extension that the node's role permits it to ignore or forward, EXT_LEN=0 is structurally valid; the node MUST NOT guess value-level constraints. Bounds, canonical tags/lengths, ordering and singleton rules still apply. This structural acceptance does not authorize sending an unassigned extension without an agreed definition.

Forwarders MUST preserve unknown safe extensions byte-for-byte. They MUST NOT remove, reorder or reinterpret immutable metadata. A future extension must specify endpoint semantics, forwarding safety, mutability, security coverage and repetition rules.

### 6.1 Extension registry

| ID | Name | C | U | Value encoding |
|---:|---|---:|---:|---|
| 1 | REPLY_TO | 1 | 0 | SECURITY=0: namespace:ULEB32, origin:ULEB32, epoch:u64LE, seq:ULEB32; SECURITY=1: referenced seq:ULEB32 only |
| 2 | CONTEXT | 1 | 1 | namespace:ULEB32, origin_epoch:u64LE (exactly 8 bytes) |
| 3 | ORIGIN_ID | 1 | 1 | origin:u32 ULEB; only when ROUTE is absent |
| 4 | SERVICE_ID | 1 | 0 | service:u32 ULEB |
| 5 | STATUS | 1 | 0 | status:u32 ULEB |
| 6 | FRESHNESS | 1 | 0 | Exactly 16 token bytes; requires SEC-1; see annex §S7 |
| 7–63 | Reserved | — | — | Reject if required and unknown |
| 64–127 | Experimental | — | — | Requires an agreed profile |
| 128+ | Profile/vendor scoped | — | — | Requires an agreed profile namespace |

REPLY_TO has exactly one representation for each security state. SECURITY=0 carries the complete referenced key even on a configured direct binding. SECURITY=1 carries only the referenced SEQ; the receiving endpoint reconstructs namespace, origin and epoch from its **own sending direction on the same authenticated SEC-1 association**. A sender may reference only a message received from the peer on that association. The result ACK therefore references the result sender's SEQ on the same association. No discriminator, negotiated compression flag or full-reference alternative exists for protected frames. EXT_LEN must match the exact encoding; a protected reference has length 1-5 and no trailing bytes.

Resolve compact references only after authentication and association/context validation. Correlation also checks expected peer, identical resolved service ID and exchange state. The reconstructed full key remains the semantic identity; a CID or SEQ alone is never a global key. Late replies must use the original draining association, not a new one; expired associations cannot be reconstructed from a reply. Reused local context slots need generation/lifetime protection. Transparent relays preserve the compact reference without resolving it; routed frames still carry the origin/destination/context required by forwarding. Cross-association references require an application operation identifier, not an alternate REPLY_TO format.

SERVICE_ID selects an application endpoint on a device. It does not select payload encoding or next hop. The binding/profile MUST fix one application default service, identical at both endpoints. Application messages on that default MUST omit SERVICE_ID; other services MUST encode it explicitly. An explicit default-service ID is noncanonical and MUST be rejected for local delivery. ACK/RSP/ERR MUST use the same resolved service ID as the message referenced by REPLY_TO, including an ACK of a result. Arbitrary reply-service translation is not supported. A relay preserves the received bytes; it does not normalize authenticated headers. Message-specific prohibitions, including SEC-1 bootstrap and FINISH/READY with no SERVICE_ID, still apply; those HELLO messages are not application-default traffic.

With SEC-1, service 0 is reserved for its explicitly addressed control service; application service IDs are >=1. An omitted SERVICE_ID can only select the configured application default, not security control. The manifest fixes the common application default and includes this reservation. Security-control service 0 is always explicit, including its correlated replies and receipts.

Registry ranges alone do not prevent collisions. Experimental/private IDs, codec IDs, schema IDs and service IDs have meaning only under an agreed profile identifier, owner and revision. No globally coordinated registry is claimed by this draft.

## 7. Replies, ACK and errors

An ACK means:

> The final DMP endpoint has received, validated, completely reassembled if necessary, and accepted the message for processing.

It does not promise operation completion, persistence across power loss or exactly-once execution. RSP carries an application result. Durable receipt is an application-profile guarantee.

ACK requirements:

- own SEQ and resolvable own origin/context;
- exactly one REPLY_TO referencing the accepted message;
- empty payload; no FRAG, ACK_REQ, PAYLOAD_DESC or STATUS;
- routing/integrity/security metadata may be present;
- only the intended endpoint generates the end-to-end ACK.

A link send-success event is not DMP ACK. An adapter may report local transmission, neighbor acknowledgement or native network delivery separately. None proves application execution.

RSP and ERR require their own SEQ and REPLY_TO in this revision. ERR additionally requires STATUS. STATUS is optional on RSP only if an application profile defines its use. Error payloads remain opaque profile-defined diagnostic bytes.

Initial protocol rejection STATUS values:

| Value | Meaning |
|---:|---|
| 1 | Unsupported endpoint feature/type |
| 2 | Unsupported codec/schema/profile |
| 3 | Message exceeds configured size |
| 4 | Busy; message not accepted |
| 5 | Required context unavailable |
| 6 | Authenticated request denied by authorization/freshness policy |
| 7 | Invalid application request shape/value |
| 8–63 | Reserved |
| 64+ | Profile-defined |

A protocol-rejection ERR (STATUS 1–7) MUST have ACK_REQ=0. It is never queued for reliable retransmission or acknowledged; an incoming rejection with ACK_REQ=1 is invalid and MUST NOT terminate an exchange. A duplicate rejected request may trigger another best-effort ERR carrying the retained decision, within response-rate and absolute retention bounds. Each newly constructed response gets a new own SEQ and, under SEC-1, fresh PN. A lost rejection is recovered by the original sender retrying its request; best-effort requests have no such recovery guarantee. Reserved STATUS 8–63 are not application outcomes and MUST be rejected for local delivery. STATUS >=64 has only its explicitly defined application meaning.

A correlated protocol-rejection ERR may terminate an outstanding transmission when authenticated/bound to the expected responder; it does not assert acceptance. A terminal application-result ERR follows §8.1 and can substitute for the request receipt. Timeout means delivery/result **unknown**, not proof that the operation never ran.

A validated terminal RSP or application-result ERR for a reliable REQ substitutes for its receipt ACK under §8.1. This is the single reliable request/result rule. Generic reliable DATA/EVENT delivery still uses acceptance ACKs. A best-effort REQ without ACK_REQ does not create a reliable request exchange; its result/reliability requirements must be defined by the application and cannot claim §8.1 guarantees.

On a valid duplicate of an accepted ACK_REQ message, the endpoint SHOULD resend the cached ACK, subject to rate limits, without delivering the operation again. A fragment duplicate cannot cause a success ACK until a complete message has been accepted. ACK itself is never acknowledged. Unsolicited or unmatched replies are discarded or exposed as diagnostics, not matched by SEQ alone.

After acceptance, a receipt confirms the previously accepted identity, not a fresh acceptance of the duplicate's payload. Validate the incoming frame's structure, required integrity/authentication, identity/security domain and retained logical metadata before repeating that receipt. Retain type, destination, ACK_REQ, service/descriptor/reference/extensions and fragment geometry (when present), or an unambiguous comparison representation of those fields. Ignore fragment index and per-transmission protection/TTL/HDR_LEN differences for this accepted-message metadata comparison. Payload bytes and per-fragment payload hashes need not be retained solely for duplicate receipt generation. A metadata mismatch is rejected locally; an accepted duplicate is never dispatched again. The sender's prohibition on reusing an identity for different content remains absolute, but detection of changed payload under an already accepted identity is not promised. Incomplete assemblies still compare duplicate slice bytes (§11). Outgoing retransmission/result storage has separate retention requirements.

## 8. Reliability profile

The base reliability profile uses stop-and-wait: at most one unacknowledged ACK_REQ logical message per destination endpoint/service. Application operations already accepted but awaiting RSP are a separate concern; the application sets their concurrency limit.

The deployment MUST specify initial timeout, maximum timeout, jitter range, maximum attempts, total message lifetime, cache retention and queue bounds. Values must reflect actual airtime, turnaround and peer sleep windows. They are not universal constants in the wire format.

Sender behavior:

1. Resolve destination and full local identity; allocate SEQ once.
2. Transmit the message or its fragments and start the relevant timeout after scheduling/transmission, according to the adapter contract.
3. Accept ACK/ERR only from the expected destination/context and with an exact resolved REPLY_TO match. For reliable REQ, a validated terminal RSP or application-result ERR also supplies the receipt under §8.1.
4. Retry identical logical immutable contents with the same identity using bounded backoff and jitter. Under SEC-1, freshly protect each retry with a new PN under the same association.
5. Stop at acknowledgement, terminal correlated rejection, attempt limit, expiry or cancellation.

In the basic fragmented mode, retry all fragments. A service explicitly selecting [SELECTIVE-32](DMP_v2_Selective_Recovery.md) instead follows that annex's repair/probe state machine for eligible protected fragmented messages. Ordinary receipt/result semantics remain unchanged. Use separately specified application block-transfer profiles for large objects rather than unbounded retries of large messages.

Accepted-message deduplication retention MUST cover the configured retransmission horizon plus maximum accepted network/queue delay. A deployment must define those finite bounds. A receiver MUST reserve cache capacity before accepting reliable non-idempotent traffic; if it cannot preserve the stated guarantee, it rejects as busy or fails locally instead of silently evicting still-required entries.

Deduplication promises apply only within the defined lifetime and restart model. Applications needing durable idempotency must persist operation IDs/results independently.

DMP ACK_REQ to group/broadcast destinations is forbidden in the base profile to prevent ACK implosion. Group delivery receipts require a separately designed aggregation or scheduling profile.

Underlying reliable streams do not prove operation execution. Applications may choose ACK_REQ=0 on such bindings and define their own result policy. Once ACK_REQ=1 is selected, the receipt/result rules of this section remain mandatory; a reliable transport does not waive them. Public UDP bindings additionally require congestion-aware sending; bounded retries alone do not constitute a complete Internet congestion-control policy.

### 8.1 Reliable request/result exchange

Every admitted REQ with ACK_REQ uses this exchange behavior and requires SEQ. A service that does not support reliable request/result exchange must reject it before execution. REQ, RSP, ERR, ACK and REPLY_TO retain their defined message meanings. Each request has at most one terminal application result; progress events, streaming results and cancellation commands require separate application definitions. Implementations that support only telemetry or generic reliable DATA/EVENT need not implement the request/result module.

The request receipt and the application result are two independently tracked events:

| Sender state/event | Required behavior |
|---|---|
| Waiting for receipt and result | Retry the identical REQ under §8; maintain a separate result deadline |
| Matching ACK | Stop REQ retries; continue waiting for the result |
| Matching, valid RSP | Treat the request as accepted, stop REQ retries even if its ACK was lost, accept the result once, and ACK the RSP |
| Matching protocol-rejection ERR | Stop REQ retries and finish with the stated rejection; this does not assert acceptance |
| Matching application-result ERR | Stop REQ retries, accept the failure result once, and ACK the ERR |
| Receipt/result deadline expires | Report an unknown delivery/result outcome; do not create a new operation automatically |
| Late matching result | Apply the configured late-result policy; never complete an unrelated operation |

All matching includes the full REPLY_TO, expected responder identity and identical resolved service ID, and required integrity/authentication and payload validation. An unvalidated or merely structurally parseable RSP MUST NOT stop REQ retries. Protocol STATUS 1–7 describe rejection; application-result ERR uses profile-defined STATUS >=64 whose definition identifies it as a terminal application result. Within the declared lifetime/restart model, a pre-acceptance protocol rejection MUST NOT later be followed by execution of the same request identity. A responder that sends such a rejection retains a bounded rejection decision for the request retry horizon plus maximum accepted delivery delay; a requester may make a new attempt with a new identity according to application policy. If this decision cannot be retained, drop/fail locally instead of promising rejection and later accepting a retry.

Responder rules:

1. Before accepting a request, reserve the bounded request-deduplication and result/reliability resources required by the service. Admission failure causes a rejection or local drop; it MUST NOT execute the operation and subsequently report that it was never accepted.
2. Send the receipt ACK within a configured receipt-delay bound unless a terminal result can be sent within that bound. A validated immediate RSP or application-result ERR substitutes for that ACK. A protocol-rejection ERR ends the request without asserting acceptance.
3. Every terminal RSP or application-result ERR MUST carry its own SEQ, REPLY_TO and ACK_REQ. Retransmit that result independently with unchanged identity/content until its ACK or the result transmission limit. The ACK of a result references the result's identity, not the REQ identity. Protocol-rejection ERR MUST be best effort (ACK_REQ=0); duplicate rejected requests can trigger the retained rejection decision under §7, without a separate reliable-result state.
4. A duplicate REQ never re-executes the operation. While processing, resend its receipt subject to rate limits. If a result exists, retain and resend that same result subject to its transmission budget; a duplicate MUST NOT renew its absolute lifetime. For a fragmented SELECTIVE-32 result, annex R4.5 instead repeats the request receipt and leaves the existing result recovery state machine in control; it never starts a parallel/full-result burst or reopens a terminal result transfer. After the result has been released, preserve the request acceptance record for its required deduplication horizon and resend only the receipt.
5. Do not send ACK_REQ control traffic in a way that blocks receipt ACKs. ACKs bypass the stop-and-wait gate. Queued result transmissions still obey the per-destination/service gate and their configured deadlines; admission limits MUST account for that queueing.

The caller keeps bounded correlation tombstones for completed, timed-out and locally canceled requests for the configured late-result horizon. A valid duplicate/late reliable result for a retained request can be accepted and ACKed without repeating its application callback; the profile MUST specify whether a late result is also exposed diagnostically. Without retained correlation, an unexpected result is dropped. Tombstones and accepted-result deduplication MUST survive for the responder's permitted retry horizon plus maximum delivery delay, within the declared restart model. Admission MUST fail rather than evict still-required state silently.

A result timeout, local cancellation or lost result ACK does not undo a remote operation. Reliable request/result exchange provides bounded exchange behavior, not durable exactly-once execution. If an operation must be recoverable across restarts, result-cache expiry, gateway termination or a new REQ identity, the application profile MUST define a durable operation identifier, result retention and a status/result lookup operation. This exchange allocates no generic payload schema for those operations.

### 8.2 Timing and retention contract

Each deployment MUST state finite bounds for queue residence, one-way accepted delivery delay, request processing, receipt delay, retry horizons and late results. Define each horizon from a specified event (for example, first transmission or result creation); implementations MUST NOT silently reset an absolute deadline on a duplicate.

The receipt timeout MUST accommodate the applicable transmission schedule, forward delivery, receiver receipt delay and return delivery. A fragmented attempt cannot time out solely because its earlier slices were sent while later slices are still within the admitted transmission schedule. Sender APIs distinguish queued, transmitting, awaiting receipt and awaiting result; expiry may cancel unsent work in any state.

Result deadlines and retained correlation must account for admitted application processing plus result queueing/transmission/retries. Reassembly constraints are specified in §11.1. If a binding cannot offer the bounds assumed by a profile, it must reject that configuration or explicitly provide a weaker service; it cannot claim the same delivery/retention guarantees.

## 9. Routing metadata

ROUTE is for a DMP overlay whose participants actively forward DMP frames. Native mesh bindings omit it by default.

```text
ROUTE_CONTROL : u8 = (remaining_forwards << 4) | destination_mode
source_id     : ULEB32
[destination_id : ULEB32, only for TO_NODE]
```

| Mode | Meaning |
|---:|---|
| 0 | TO_ROOT: one root resolved by the mesh context |
| 1 | TO_NODE: explicit destination_id |
| 2 | BROADCAST: all eligible endpoints in the configured mesh scope |
| 3–15 | Reserved; reject DMP forwarding until assigned |

The upper nibble, TTL, means **remaining forwarding operations**, not seconds. Origin transmission does not decrement it. A relay receiving TTL>0 may decrement once and transmit, including an outgoing TTL of zero. A frame received with TTL=0 may be consumed locally but cannot be forwarded. An endpoint receiving its unicast destination consumes it and does not relay it further.

The origin chooses 0–15 according to the deployment. An extended hop limit is deferred; implementations must not silently reinterpret these four bits as a wider counter. Logical source/destination IDs are not MAC, IP or radio identifiers.

TO_ROOT is valid only when the context selects one concrete root. Anycast/failover semantics require an explicit service-routing profile. A root's reply normally uses TO_NODE back to the original source.

**Destination scope and routing algorithm are separate:** a TO_NODE packet can be carried by flooding or a unicast table. BROADCAST is a destination scope, not a command to ignore congestion policy.

## 10. Mesh profiles and forwarding

### 10.1 Roles and scope

A node may be an endpoint, relay, gateway or a combination. Leaf nodes need not relay. Forwarding requires SEQ, ROUTE and a resolvable full message identity. A radio address is only a local neighbor locator.

The selected mesh profile, network namespace, eligible relay roles, limits and retry policy are configured consistently. Mesh-control traffic cannot be smuggled into arbitrary TELEM fields; any discovery/control messages need their own specified service and schema.

### 10.2 Static unicast

The initial routed profile uses configured destination/root-to-next-hop mappings. It requires no dynamic discovery protocol. Missing routes yield a local failure; optionally report a correlated error through a separately defined routing diagnostic service. Do not invent an end-to-end ACK from an intermediate relay.

### 10.3 Bounded flooding

The initial flood profile uses eligible relays, TTL, per-frame duplicate suppression, randomized forwarding delay and local airtime/queue budgets. Hearing a duplicate does not automatically prove the destination received the message. Suppressing a pending forward based on overhearing is optional policy and must not be represented as reliable delivery.

### 10.4 Three different caches

| State | Key | Purpose |
|---|---|---|
| Endpoint accepted-message cache | Full message key | Prevent repeated application execution; resend receipt |
| Reassembly state | Full message key | Collect all fragments |
| Relay duplicate state | Full message key + fragment marker/index | Suppress redundant radio copies without dropping other fragments |

These are distinct semantic purposes, not a requirement for three separate maps. Reliable request/result exchange additionally tracks rejected requests, retained results and caller correlation/tombstones under §8.1. Related exchange states SHOULD share one bounded record where possible, while preserving their different deadlines and obligations. Accepted records retain the metadata described in §7, not historical payload solely to validate duplicate receipts.

Use a distinct unfragmented marker; it is not fragment index zero. A conflicting unfragmented/fragmented use of one message identity is invalid.

Permanent relay suppression over the whole retry horizon would block legitimate end-to-end retransmissions. Therefore relay state MUST permit a bounded later forwarding opportunity for a duplicate after a configured cooldown, provided its incoming TTL permits forwarding. It MUST also impose a maximum forward count per key, absolute expiry and per-origin/global airtime limits. Duplicates during the cooldown MUST NOT perpetually postpone eligibility or extend absolute expiry.

Source retry delays and relay cooldowns MUST be coordinated for the deployment. Success is not guaranteed: an exhausted relay budget can cause final delivery failure. No universally correct timers are implied by this document.

### 10.5 Relay pipeline

1. Decode bounded structure and required forwarding metadata.
2. Verify any supported required integrity/hop protection before using the frame to affect trusted state.
3. Resolve identity; distinguish fragments; enforce resource and conflict policies.
4. Process local delivery if applicable, including reassembly and endpoint checks.
5. For eligible nonlocal/broadcast forwarding, check incoming TTL, cache cooldown/count and queue/airtime budget.
6. Select next hop(s), decrement TTL once per forwarded copy, recompute the core CRC if present, and regenerate link/stream envelope protection.
7. Preserve origin, SEQ, fragment identity and all immutable extension/payload bytes.

A relay cannot claim end-to-end authentication when it only verified a CRC. SEC-1-aware structural relays may forward supported protected frames without endpoint keys under annex §S9. They preserve all bytes except the specified TTL/outer-binding changes. A relay unable to parse the security descriptor safely rejects forwarding. Protected retries have different PN/ciphertext/tag; relay duplicate suppression uses logical identity/fragment index and must not mistake those changes for conflicting plaintext. Only an authenticated endpoint can compare decrypted slice contents. Unverified relay cache state is bounded provisional state, not trusted origin/replay state.

### 10.6 Future dynamic routing

A separate control-plane specification may add neighbor discovery, rank/metric advertisements, parent selection with hysteresis, route lifetime, loop detection/repair and reverse routes. RPL/MRHOF/Trickle are design precedents, not protocols that this DMP data-plane format automatically implements.

RSSI and SNR are local observations. Compare paths using explicitly defined metrics; the strongest received signal alone is not proof of the best end-to-end path. No additional mandatory data-frame field is needed just to run a local route-selection algorithm.

## 11. Fragmentation and reassembly

FRAG requires SEQ and resolvable identity:

```text
fragment_index : ULEB32
chunk_size     : ULEB32
total_length   : ULEB32
```

The geometry is in plaintext bytes. Require `0 < chunk_size < total_length <= configured_max_message`. Derive `fragment_count = 1 + (total_length - 1) / chunk_size` using integer division, and require `2 <= fragment_count <= configured_max_fragments` and `fragment_index < fragment_count`. There is no transmitted count. The slice begins at `offset = fragment_index * chunk_size` and has exactly `min(chunk_size, total_length - offset)` bytes. All non-final slices have chunk_size bytes; the final slice is nonempty and may also be a full chunk. Use overflow-safe arithmetic and reject invalid geometry before allocation or pointer calculation. Empty and single-packet messages MUST omit FRAG.

Every fragment MUST carry the same chunk_size, total_length, type, ACK_REQ, origin/context, PAYLOAD_DESC, REPLY_TO/service metadata and integrity algorithm. Optional descriptor metadata is repeated; it cannot appear only in fragment zero. The routing destination/mode and all immutable extensions MUST also agree. TTL can differ due to path traversal and is not part of the immutable reassembly consistency comparison. CRC trailer bytes are verified per fragment rather than compared for equality across fragments.

Protected fragments additionally require the same SEC-1 association/cipher/receive CID and authorization domain. Verify/decrypt before trusted reassembly and compare duplicate plaintext slices. PN and authentication tags differ by frame and are excluded from logical consistency comparison. Plaintext and protected fragments or fragments from different associations MUST NOT share an assembly. A secure fresh-PN retry can repopulate an incomplete assembly under its original lifetime/quota rules.

A fragment is a separate DMP Core frame. CRC, if present, covers that fragment's header and slice. Fragment-level CRC is not a whole-object hash. The application can specify a content digest for large-object validation.

Receivers MUST support out-of-order slices and identical duplicates within their declared limits. After structural limits and required integrity/authentication, reserve the advertised total_length and assembly metadata against both per-peer and global quotas before creating a trusted assembly. For each slice, validate its exact length and write it at its computed offset. A contiguous buffer with a count-bit receipt bitmap is sufficient; bounded pools or other equivalent storage remain permitted. Do not reserve an unbounded buffer based on unauthenticated length. If quotas cannot admit the whole assembly, refuse it rather than acknowledging acceptance.

While an assembly is incomplete, a conflicting plaintext slice for an already received index is rejected and reported locally; it MUST NOT replace accepted bytes or refresh the timer. Geometry changes under one identity are conflicts even if individual slices fit. Incomplete messages are never dispatched. A receipt bitmap records which slices arrived, not their historical contents after acceptance.

The deployment defines maximum frame size, message size, fragment count, concurrent assemblies, per-origin quota and an absolute reassembly lifetime beginning with the first accepted slice. Inactivity timeouts may shorten that lifetime. Duplicates do not extend either lifetime. Quota failures reject new state or use a documented eviction policy for incomplete assemblies.

Endpoint success ACK is sent only after full reassembly, complete validation and acceptance. All accepted-message deduplication rules in §7 then apply to later copies of any structurally valid, metadata-matching fragment. A cached ACK may be resent without reconstructing the message or retaining fragment payloads/hashes solely for that purpose. The ACK refers to the original accepted logical identity; the duplicate's bytes are not executed or newly accepted. Release reassembly storage when its application ownership allows, independently of receipt-record retention.

Transparent relays MUST NOT re-fragment existing frames. An adapter must fit within the effective path MTU, use native lower-layer segmentation, or return a too-large outcome. Terminating gateways may reassemble and originate a new transfer under §17. A local reassembly bitmap is not a success acknowledgement; only an explicitly selected SELECTIVE-32 service emits FRAG_STATUS under the recovery annex.

### 11.1 Reassembly timing and narrowband operation

Define `T_collect` as the maximum admitted time from the first accepted slice to receipt of all required slices, including scheduling gaps, permitted retries and delivery delays. The configured absolute reassembly lifetime MUST exceed `T_collect` by a declared processing/timer margin. An optional inactivity timeout MUST likewise exceed the maximum admitted interval between new slices; duplicates do not refresh it. If no such bounds are available, completion is best-effort and MUST NOT be described as assured within a bounded retry schedule.

Before starting a transfer, the sender MUST check that the message fits the declared frame, derived fragment-count and message-size limits and that its admitted schedule fits the message/reassembly lifetimes. Size the header for the largest fragment_index in this transfer, repeated geometry/extensions and the worst permitted retry PN before choosing chunk_size; checking only fragment zero is insufficient at a varint boundary. A receiver reserves the total advertised message size and bitmap/metadata before assembly admission and enforces actual bounds on every copy. A local schedule change that makes completion infeasible produces an explicit failure/unknown outcome; it does not authorize changing slices under the same message identity.

For example, a configured first-slice-to-completion bound of 30 seconds and a 2-second margin requires an absolute reassembly lifetime of at least 32 seconds. This is a consistency example, not a LoRa timing recommendation. The bound must include the actual selected retry schedule and transport restrictions.

Retry-all is intended for small fragment sets. Under an illustrative independent 10% loss rate, all 20 fragments arrive in the first round with probability `0.9^20`, approximately 12.2%. Receivers retain valid slices across retries within their lifetime, so this is not the eventual success probability; retrying the whole set nevertheless consumes airtime for slices already held.

The normative [SELECTIVE-32 annex](DMP_v2_Selective_Recovery.md) allocates FRAG_STATUS (TYPE 8), a four-byte missing bitmap for at most 32 fragments, and bounded repair/probe rules. It MUST NOT reuse the empty-payload success ACK to mean partial reception. Its fixed receiver lifetimes and terminal tombstones override optional inactivity/eviction-and-repopulation behavior for services selecting that mode. Independent application blocks remain the approach for larger resumable objects; sliding windows and group feedback are not defined.

### 11.2 Message fragments versus transport segments

DMP FRAG divides a finite logical message into independently framed slices that share its message identity. Binding segmentation divides one already encoded DMP frame into units accepted by a particular lower transport. These are separate operations with separate identifiers, quotas and timers.

A binding may transparently segment and reconstruct an unchanged DMP frame, including its end-to-end protected bytes. Such a binding MUST define segment identification, size limits, loss/reordering behavior, integrity, quotas and reconstruction timeout. Only the complete reconstructed frame enters the DMP parser. An outgoing forwarding hop may then perform its specified TTL/outer-protection changes. Segment acknowledgements MUST NOT be reported as DMP endpoint acceptance.

There is no generic DMP binding-segmentation encoding in this revision. Use an existing lower-layer mechanism or a separately named binding; do not invent adapter-specific bytes while claiming interoperability with another binding.

## 12. Payload descriptor and application profiles

Payload bytes are opaque to the core. Absence of PAYLOAD_DESC means the active profile/context supplies their interpretation; it does not mean RAW or MessagePack automatically.

```text
DESC_FLAGS : u8
CODEC_ID : ULEB32
[SCHEMA_ID : ULEB32]       if flags bit 0
[SCHEMA_VERSION : ULEB32]  if flags bit 1
```

Bits 2–7 MUST be zero. Bit 1 requires bit 0. All other combinations using reserved flags are rejected.

| CODEC_ID | Meaning |
|---:|---|
| 0 | RAW / opaque |
| 1 | MessagePack |
| 2 | CBOR |
| 3 | Protocol Buffers |
| 4 | JSON UTF-8 |
| 5 | UTF-8 text |
| 6 | FlatBuffers |
| 7–63 | Reserved |
| 64–127 | Experimental under an agreed profile |
| 128+ | Profile/vendor scoped |

Codec specifies representation; schema specifies structure; type specifies message semantics; service specifies recipient application. An unknown codec/schema can be parsed structurally and forwarded opaquely, but local delivery returns unsupported unless the application explicitly accepts opaque data. Never guess a fallback codec.

A profile defines its owner/identifier/revision, default codec/schema/service per type, identity context, permitted modules, size/timing limits, RPC idempotency and any durable-delivery guarantees. DTrack can select MessagePack through a profile without including its headers in libdmp. Other projects may choose raw binary, CBOR or any supported serializer.

### 12.1 Delivery semantics for live data, commands and objects

Profiles MUST distinguish the following application behaviors; TYPE alone does not establish them:

| Behavior | Profile obligations |
|---|---|
| Latest state / live samples | Define stream or state key, sample ordering, allowable loss, freshness and replacement policy; stale samples must not overwrite newer accepted state |
| Commands / nonreplaceable events | Define receipt/result requirements, ordering where needed, idempotency, queue bounds and expiry; do not coalesce distinct accepted commands |
| Finite large objects | Define transfer/object identity, block addressing, total-length limits, recovery, content validation and final commit/abort semantics |

An indefinitely running measurement stream is a sequence of finite DMP messages, not one FRAG assembly with an unknown final count. DMP SEQ is a message identity allocated across services/destinations; it is not a contiguous per-stream sample counter or proof of measurement time. Stream/sample ordering and restart handling belong to the application profile or its explicitly defined metadata. No mandatory core stream ID or timestamp is added.

Large-object services may deliver independently validated blocks to bounded storage without retaining the whole object in RAM. Such blocks are complete application messages; they do not permit dispatch of incomplete DMP FRAG messages. The service MUST define how incomplete objects remain unavailable or are marked provisional until its validation/commit rule succeeds. A digest detects content mismatch but does not authenticate the object's origin unless bound to authenticated metadata.

### 12.2 Reference deployment profile templates

The [reference-profile document](DMP_v2_Deployment_Profiles.md#1-fixed-reference-family-choices) fixes two families for implementation and evaluation. They narrow existing module choices without changing the general protocol or allocating a new wire format. Each instance MUST have an owner, identifier and revision and fill every applicable item in §12.3. Family names alone are not a complete interoperability claim.

| Family | Fixed baseline | Parameters still required |
|---|---|---|
| DIRECT-1 | Direct UART Stream R or a named BLE binding; no ROUTE; SEC-1, best-effort live telemetry, reliable commands/results; retry-all fragmentation | Exact binding, MTU, schemas, credentials, finite queue/retry/result/cache bounds and global resources |
| RADIO-1 | Named raw-radio packet binding; static unicast with explicit context/destination; pairwise SEC-1 through transparent relays; SELECTIVE-32 for eligible fragmented reliable traffic | PHY/path MTU, forward/return schedule, sleep, airtime budget, routes, relay cooldown, credentials and finite resource/lifetime bounds |

The companion document specifies family ceilings and exclusions. Other deployments remain permitted by the general specification under their own explicit profiles. A device may use different profiles for different peer/service paths; an intermediate transparent gateway cannot silently switch the end-to-end recovery/security policy.

RADIO-1 is not a LoRaWAN or Bluetooth Mesh binding. Existing network stacks require their own application model and mapping. A UART multidrop bus similarly needs explicit addressing, bus access and turnaround rules; point-to-point Stream R alone does not supply them. BLE GATT/channel details are required from the selected binding, not implied by DIRECT-1.

### 12.3 Required deployment manifest

A completed profile MUST record the following in a machine-readable configuration or equivalently precise document. This is configuration metadata; its on-wire negotiation remains outside this revision.

- Document revision, profile owner/ID/revision, binding ID/revision and enabled modules, including which services support reliable request/result exchange and optional freshness.
- Namespace, logical origins/destinations, how epochs are established and changed, trusted context source, restart/old-epoch rules and the common default application service with canonical omission and same-service replies.
- Codec/schema/version per service/type, application status meanings, result size/processing bounds, idempotency and optional operation lookup.
- Maximum core frame and encoded binding frame, maximum logical message, fragment count, concurrent assemblies, per-origin/global retained bytes and queue bounds.
- Path-MTU selection, permitted binding segmentation, behavior on route/MTU changes and whether a gateway terminates identity/security.
- Retry attempt count/backoff/jitter, scheduling/delivery bounds, receipt delay, processing/result deadline, reassembly/inactivity lifetimes and accepted/rejected/result/correlation retention horizons with their time origins.
- Mesh roles/routes, TTL and forwarding budgets/cooldown where applicable; native receive-window and congestion/channel-access policy supplied by the binding.
- Integrity/security requirements and scope, authenticated identity source where used, late-result handling, local cancellation, freshness and object-transfer policies where applicable.
- Per-class queue count/byte limits, admission and overflow outcomes, control-path memory/CPU reservations, scheduling fairness, local send deadlines and adapter ownership/completion rules (§16.2 and §18.1).
- For SEC-1, pre-authentication assembly/attempt/CPU/response budgets, independent pending-state and crypto-operation limits, abort-first failure semantics, establishment-episode deadline/attempt/work/traffic bounds and restart backoff/rate policy, trust-enrollment method, pairing timeout, credential revocation/pin-reset authority and handling of lost volatile state.

A configuration validator SHOULD reject impossible combinations before traffic starts: a header/trailer larger than the frame budget, zero payload capacity for FRAG, insufficient state quotas for admitted concurrency, retry schedules longer than retention/reassembly bounds, and required replies with no permitted return opportunity. Two endpoints sharing a codec but disagreeing on this manifest are not necessarily interoperable.

## 13. Integrity

This revision defines one core integrity algorithm:

```text
INTEGRITY_DESC : u8 = 1  (CRC32C)
TRAILER : u32 little-endian CRC32C
```

Descriptor 0 and 2–255 are reserved and rejected by this implementation profile. Unknown trailer formats cannot be skipped merely using HDR_LEN.

CRC32C parameters: polynomial 0x1EDC6F41, reflected implementation polynomial 0x82F63B78, init 0xFFFFFFFF, refin=true, refout=true, xorout=0xFFFFFFFF. Check value for ASCII `123456789` is 0xE3069283; transmitted bytes are `83 92 06 E3`.

Coverage is every current core-frame byte from VT through the final payload byte; exclude the four-byte CRC trailer and any stream envelope. A relay modifying TTL MUST recompute this checksum. This checksum detects accidental corruption of the current forwarded frame. Because a relay can recompute it, it is not immutable-origin proof or cryptographic authentication.

INTEGRITY and SECURITY together are forbidden by Core/SEC-1. SEC-1 supplies a 16-byte authentication tag instead of a core CRC trailer. Native link checksums and the mandatory Stream R envelope checksum have independent scope and can surround a SEC-1 frame.

## 14. Security requirements

SECURITY=1 uses the normative [SEC-1 security annex](DMP_v2_Security_Profile.md). It defines both provisioned pairwise PSKs and authenticated public-key pairing, using Noise with fresh ephemeral key agreement. ChaCha20-Poly1305 is mandatory for SEC-1 endpoints; AES-256-GCM is optional. Both use full 16-byte tags. Core-only implementations may return unsupported; they MUST NOT dispatch ciphertext as a guessed payload codec.

```text
SECURITY_DESC = CIPHER:u8 | RX_CID:ULEB32 | PN:ULEB64
TRAILER       = authentication tag, exactly 16 bytes
```

Cipher 1 selects Noise ChaChaPoly; cipher 2 selects Noise AESGCM. The receiver CID identifies a live local association; PN is a per-direction encryption counter, separate from SEQ. Every protected frame requires SEQ. The annex defines exact nonce byte order and AAD, which authenticates the full header with only the TTL nibble normalized. Payload is encrypted after logical fragmentation; each slice is authenticated before trusted reassembly.

Retries preserve logical identity/content but allocate fresh PN and re-encrypt. This allows packet replay rejection and message-level repeat receipts to coexist. Protected ACKs have empty plaintext and still carry a tag. SEC-1 frames on routed paths use explicit CONTEXT and TO_NODE; group/broadcast and implicit-root security are unsupported. Relays preserve protected bytes while adapting transport framing.

Authentication, authorization and freshness are separate checks. FRESHNESS extension 6 and the protected control service in annex §S7 supply a receiver-timed, single-message token for services that require it. Required security/freshness policies cannot be disabled by timeout or negotiation failure. No application data is accepted through the plaintext bootstrap exception.

SEC-1 revision 5 uses abort-first for failed processing of an admitted new expected Noise flight, including mandatory post-read payload/pin checks. Pre-Noise structural rejects and conflicting processed-flight duplicates preserve the pending attempt; ordinary loss uses cached retries. A failed attempt cannot destroy another active association or revoke a committed credential. Restart is separately scheduled under bounded establishment policy, never triggered automatically by failure. Protected transport tag/replay handling, including FINISH/READY, remains governed by annex S5/S6/S8 rather than this bootstrap rule. Preserve-state is deferred and no policy negotiation is defined.

### 14.1 Lifecycle and validation boundary

SEC-1 stores traffic keys, counters and replay windows as one volatile association. Reboot or uncertain state destroys that association and requires a fresh handshake; it does not reload old keys with reset counters. Long-term PSKs/pins can persist. Key rotation, draining work, limits, credential revocation, trust verification and unknown outcomes are fully specified in the annex.

This draft includes deterministic cryptographic vectors and required fault scenarios. Conformance requires their relevant checks, not merely a successful encrypt/decrypt round trip. A release still needs independent implementation interoperability, security review and validation of entropy, concurrency and lifecycle on its target. CRC is not authentication; a valid AEAD tag is not proof of operation completion.

## 15. Stream bindings

A link MUST select its binding through configuration or a separately defined bootstrap. Bindings are not heuristically mixed. The decoded object is always one complete DMP Core frame.

### 15.1 Stream L: reliable ordered byte stream

```text
44 4D 50 | FRAME_LEN : ULEB32 | CORE_FRAME : FRAME_LEN bytes
```

FRAME_LEN includes core header, payload and core trailer. It excludes magic and length encoding. Require `2 <= FRAME_LEN <= configured_max_frame` before buffering/allocation.

For TCP or equivalent reliable streams, begin at an agreed frame boundary. Bad magic, invalid length or malformed core frame is a framing/protocol failure: terminate/reset the logical session. Do not scan arbitrary payload for a new magic and silently continue. Split reads and several frames in one read are normal. Impose a configured frame-assembly timeout and bounded buffering. This binding does not protect against arbitrary byte insertion/deletion; use Stream R for that environment.

### 15.2 Stream R: COBS with envelope CRC32C

```text
COBS(CORE_FRAME || CRC32C_LE(CORE_FRAME)) || 00
```

The envelope CRC has the parameters in §13 and covers the complete core frame, including its core trailer if present. It is removed before handing bytes to the packet parser. It is mandatory for Stream R regardless of whether core INTEGRITY is enabled.

Use ordinary Consistent Overhead Byte Stuffing with delimiter 0x00. Canonical encoder:

1. Start a block with a reserved code byte and code value 1.
2. For each nonzero input byte, append it and increment code. At code=255, fill the block code and start a new block with code=1.
3. For each zero input byte, fill the current code and start a new block with code=1, omitting that zero from encoded data.
4. Fill the last block code, including a final empty block when required by these rules. Append one 0x00 delimiter outside the COBS encoding.

Decoder: for each nonzero code C, copy the following C−1 nonzero bytes; insert a zero between blocks when C<255 and another block follows. A code that runs beyond the candidate or a zero inside a candidate is invalid. For canonical acceptance, re-encoding the decoded bytes must yield the candidate bytes exactly (implementations may enforce this equivalently without a second allocation).

This encoder retains a final empty `01` block after an exact 254-byte nonzero run, including at end of input. Some COBS libraries omit that final block. Although both forms can decode to the same bytes, only the form specified here is canonical for Stream R. Verify a library's boundary behavior against §22.7; do not broaden decoder acceptance or silently substitute another variant.

On startup/reset, discard until a delimiter. On opening or resetting its transmit binding, a sender MUST emit one initial empty delimiter before its first frame. A coordinated open MUST arrange for the receiver to be ready before this synchronization delimiter is sent. Between delimiters, buffer at most the configured encoded-frame maximum. Oversized or invalid candidates are discarded through the next delimiter. Empty candidates are ignored. After COBS decoding, require at least six bytes (two core bytes plus four CRC bytes), verify envelope CRC, remove it, and parse the core. A partial-frame timeout discards the partial candidate and resynchronizes at a delimiter.

If a receiver independently resets while its peer continues transmitting, it may discard the in-flight or next frame through its delimiter; initial synchronization is not a delivery guarantee across an unannounced reset. The binding/deployment MUST document this loss behavior and any restart indication, resynchronization exchange or application retry. For sparse best-effort serial traffic, a sender MAY prefix every frame with an extra delimiter so a receiver already ready before that prefix can accept the following complete frame; this costs one additional byte and still does not recover a mid-frame reset. Repeated empty delimiters remain valid.

For decoded length N including envelope CRC, a safe encoded-candidate bound for this encoder is `N + floor(N/254) + 1`; add one delimiter byte. The envelope protects against accidental corruption, not malicious modification.

## 16. Transport adapter contract

An adapter supplies capabilities and operations to the message layer. This is local API metadata, not an automatic wire negotiation protocol.

| Capability | Meaning |
|---|---|
| Boundary model | Complete packet/message or selected stream binding |
| Maximum core frame | Effective per-destination limit after outer overhead |
| Native multi-hop/addressing | Whether the lower stack delivers to remote endpoints |
| Broadcast/group support | Supported scopes and limitations |
| Delivery events | Local enqueue, transmitted, neighbor ACK, native delivery; distinct meanings |
| Ordering/reliability | Native behavior; does not imply application execution |
| Integrity/security scope | What the lower layer actually protects and against whom |
| Airtime/scheduling | Earliest send time, queue pressure, optional airtime estimate |
| Peer availability | Receive windows or reachable/asleep state when known |

Adapters expose backpressure and cancel/failure outcomes. The core must not busy-loop retransmissions into a full radio queue. Public UDP must obey a deployment-appropriate congestion policy and effective path MTU; radio bindings obey their channel-access and regional configuration.

For WebSocket, one complete reassembled binary **message** carries one DMP packet; a WebSocket message may itself consist of several WebSocket frames. TCP reads and USB CDC reads are not packet boundaries. BLE bindings explicitly define whether one GATT value or a reassembled channel message carries one DMP packet. A local link MTU is not automatically the path MTU.

### 16.1 Effective path MTU and changes of transport

The effective frame budget is the minimum DMP core-frame capacity across the selected path after each binding's overhead, unless a specified lower-layer segmentation mechanism reconstructs a larger frame before DMP processing. Frame sizing MUST include all optional headers and trailers, not just the payload slice. A forwarding implementation must check the outgoing capacity even if a received frame fitted its ingress interface.

SEC-1 fragment sizing and reliable admission MUST reserve its maximum permitted four-byte PN, even when the first frame's PN occupies one byte. Otherwise a later retry can exceed MTU solely because PN/HDR_LEN grew. Reserve space before committing immutable slices and still transmit canonical minimal varints.

For configured paths, the deployment may provision a conservative path MTU. Dynamic path discovery or automatic MTU negotiation is not defined here. If a route changes to a smaller unsegmented capacity, forwarding returns a local too-large outcome; a routing diagnostic requires its separately defined service. It MUST NOT silently truncate or re-fragment the original frame.

Changing a fragmented transfer's slice boundaries or count creates new immutable contents and therefore requires a new message identity. Before retrying an application command under that new identity, account for an unknown prior outcome and use the application's idempotency/operation identifier where required. An adapter that segments the unchanged frame under §11.2 does not change its DMP message identity.

### 16.2 Asynchronous buffer ownership and completion

Each adapter MUST document whether submission copies frame bytes or borrows them. For a borrowed buffer, successful submission transfers exclusive access to the adapter until exactly one terminal completion event returns it. The caller MUST NOT modify, re-encrypt, recycle or free that storage while the adapter or its DMA may still access it. Rejected submission leaves ownership with the caller and MUST NOT later produce completion for that rejected submission. Synchronous completion, if supported, must be explicit in the API contract.

Cancellation requests do not themselves return ownership. A successful cancellation completion means that no driver/DMA access or future transmission from that submission remains possible; if cancellation cannot prevent transmission, its outcome must say so. Completion after disconnect, reset or timeout still has to settle each accepted submission exactly once. Submission handles MUST distinguish late completions from a later reuse of the same pool slot. Link-driver adapters MUST serialize access or otherwise make these ownership transitions race-free.

Local transmission completion releases that encoded frame buffer; it is not a DMP receipt or operation result. Reliable sending separately retains the immutable logical message and the state needed for its allowed retries. SEC-1 retries require fresh PN and re-encryption, so an in-flight protected frame cannot be rewritten for a retry. Sensitive logical/plaintext buffers must remain valid for their retry lifetime and be erased when their last owner releases them. Shared immutable forwarding buffers require explicit references or copies when multiple interfaces are in flight.

An adapter MUST return bounded backpressure rather than wait indefinitely in a protocol callback. Caller-owned fixed pools are RECOMMENDED for predictable memory use. Zero-copy forwarding is an implementation option; authenticated decryption, framing or reassembly may still require separate storage. No zero-copy claim overrides the ownership rules above.

## 17. Bridges and mixed networks

Two gateway roles are distinct:

| Role | Identity and content | Security consequences |
|---|---|---|
| Transparent forwarding/binding conversion | Preserve original message identity and immutable core contents; only specified hop fields change | Must preserve end-to-end authentication; reapply outer link/stream protection |
| Terminating application gateway | Accept one message and originate another with a new identity | Terminates delivery/security scope; app defines provenance and acknowledgement mapping |

Transparent bridges must maintain a consistent namespace mapping, relay budgets and duplicate state across their DMP-facing interfaces. They must not reset remaining-forwards when moving between DMP overlay interfaces. One DMP forwarding operation may traverse many native-network hops; DMP TTL does not measure the physical path inside an opaque native mesh.

Transparent context mapping resolves to the same end-to-end identity; it is not permission to rewrite an explicit namespace, origin or epoch. If context omitted on ingress cannot be resolved consistently on egress, the bridge must reject that path/configuration or act as a terminating gateway. Inserting CONTEXT/ORIGIN_ID/ROUTE into an existing immutable frame is not transparent conversion under this revision. Origins must include the required metadata before entering a path that needs it.

An opaque adapter does not need to attach ROUTE simply because its native network uses mesh. Joining multiple native domains with a DMP overlay is a separate configured function, not an automatic broadcast bridge.

Terminating gateways that reassemble/re-fragment or translate schemas must use a new message identity and explicit application correlation/provenance where required. They cannot return an end-to-end ACK on behalf of the final destination unless the application explicitly defines custody acceptance. A new identity can bypass ordinary loop detection, so gateway topology/policy must prevent repeated translation loops.

## 18. Sleeping nodes, queues and expiry

The core has no persistent-connection requirement. A deployment may use leaf sleep schedules, native low-power buffering or configured receive windows. A sleeping node is not a reliable always-available relay merely because it supports the mesh parser.

Queues are bounded by bytes/count and lifetime. Applications distinguish replaceable telemetry from nonreplaceable commands; a local queue may coalesce unsent telemetry only before immutable message identity/security material is committed, or by explicitly canceling the old message and allocating a new one.

Origin expiry bounds retries and local queue residence, but does not automatically expire delayed remote copies. Commands requiring end-to-end expiry must carry a profile-defined authenticated deadline or use an agreed maximum-age protocol with an explicit clock model. Wall-clock timestamps and relative age are not interchangeable. No generic on-wire EXPIRY encoding is allocated in this revision.

Backlog representation, batch payloads and durable operation storage remain application concerns. Priority, scheduling and rate limits are primarily local policies; any transmitted priority/deadline extension requires a separate definition.

### 18.1 Admission, control reserves and queue policy

Implementations MUST bound queued messages, retained bytes, retransmission history and reassembly state globally and per admitted peer/service. Before acknowledging acceptance, an endpoint MUST reserve the processing and duplicate-decision state required by §8, plus result/correlation state for reliable requests under §8.1. It MUST NOT acknowledge acceptance and then silently evict that obligation to admit newer traffic. Resource refusal follows §7 and §8.1, including authenticated error policy and retained rejection decisions; a local enqueue refusal is a local API outcome, not an invented remote STATUS.

The resource budget MUST leave capacity to receive/process valid receipts and to send the required ACKs, errors and SEC-1 confirmation/control messages while application queues and retry histories are full. This includes RX ingress buffers, TX/control slots and bounded execution time; a separate logical queue without available underlying buffers is insufficient. Reserve sizes depend on the configured frame sizes and admitted concurrency, and MUST be stated and checked in the deployment manifest. An endpoint unable to preserve this progress capacity MUST stop admitting new application work before exhausting it.

Control reservations are not unlimited priority for any packet labeled HELLO or ACK. Pre-authentication traffic has separate bounded admission (§S3.2 of the security annex). Valid control traffic and authenticated principals also need rate limits and fair scheduling so that one peer cannot consume all progress capacity. The scheduler MUST provide configured finite service opportunities to already admitted work under its stated load and link-availability assumptions. A sleeping peer, unavailable radio or hostile medium does not create a delivery guarantee.

| Traffic class | Required local overflow behavior |
|---|---|
| Replaceable live state | A service may replace an unsent value for the same application key before identity commitment, or cancel it and create a new identity; bound age and report drops/coalescing locally |
| Nonreplaceable commands/events | Reject new local submissions explicitly or admit within declared limits; never silently replace an accepted distinct command |
| Reliable messages/results | Retain required logical content and decisions until their defined horizons; when full, apply backpressure before acceptance |
| ACK/security control | Use reserved progress capacity with bounded rate/CPU budgets; do not queue behind a stop-and-wait gate that the control message must release |
| Application object transfer | Bound pending chunks and yield between chunks to control/live traffic; this is local scheduling of an agreed application service, not a new DMP bulk-transfer format |

Queue counts alone do not bound memory: budgets MUST include payload storage, frame copies, adapter/DMA buffers, fragment metadata, crypto state, caches and queue entries. An implementation may share immutable storage only when its reference accounting preserves all retention and ownership requirements.

### 18.2 Local send deadlines and observable outcomes

The local send API SHOULD accept a monotonic latest-start deadline. At each queue-to-adapter submission, including retries, the sender MUST check any supplied deadline; the adapter must check it again at actual transmission start when it can enforce that boundary. Adapters MUST expose whether they can enforce latest-start or only submission-time expiry, and deployments requiring strict latest-start must reject incapable adapters. This deadline is not serialized, does not require synchronized clocks and does not bound receiver execution or the duration of a frame already started.

On expiry, stop new submissions and request cancellation of queued adapter work under §16.2. If no bytes of any attempt could have reached the peer, report local expiry before transmission. If any fragment/attempt may have been transmitted, report the unresolved remote outcome as unknown; cancellation cannot retract it. Do not free in-flight buffers before completion or discard already required acceptance/deduplication records. Remote command freshness continues to use the application policy and, where selected, SEC-1 freshness tokens.

The API MUST distinguish local queue admission, local transmission, peer receipt and application result. Expose bounded counters for queue refusals, expired/coalesced samples, retransmissions, assembly timeouts, high-water memory usage, security admission drops and authentication failures. Diagnostics MUST NOT expose secrets or confidential payloads; externally accessible diagnostics require service authorization. Service-name lookup may come from a generated deployment manifest, but does not imply an on-wire dynamic alias or discovery protocol.

## 19. Capability configuration and HELLO

This revision uses static or out-of-band agreement for:

- DMP draft revision and binding;
- application/profile registry namespace;
- identities and epoch interpretation;
- permitted optional features;
- peer frame/message/fragment limits;
- retry/cache/lifetime bounds;
- mesh forwarding parameters and native-network mapping;
- security requirements provided externally or by SEC-1, its allowed credential modes/ciphers and trust records.

The deployment manifest in §12.3 makes this agreement explicit, including reliable request/result support and any binding segmentation. A profile ID by itself does not imply that its limits or security context have been negotiated. The local adapter capability API is not an on-wire capability exchange.

HELLO has a fixed binary SEC-1 bootstrap/confirmation encoding in the security annex. It does not use the normal application codec and is not generic capability negotiation. SEC-1 binds the configured profile digest into its authenticated handshake and does not silently select another profile/cipher after failure. Non-SEC-1 endpoints return unsupported unless another explicitly named bootstrap is configured. Any additional bootstrap requires its own exact format and downgrade policy.

Static profiles are valid for sleeping and datagram-only nodes. Every peer need not implement negotiation.

## 20. Parsing, validation and error handling

Parsing is staged:

1. Bound packet size; require at least two bytes and supported wire version.
2. Validate HDR_LEN and parse canonical standard fields without crossing it.
3. Reject unknown SECURITY/integrity formats before guessing trailer size.
4. Parse extensions within HDR_LEN; validate order, bounds and required-role semantics.
5. Validate packet/header/trailer length relationships and core CRC if present.
6. Resolve binding/profile or SEC-1 receive-CID context and enforce structural semantic constraints without treating claims as authenticated.
7. Authenticate/decrypt SEC-1 frames; update packet replay state atomically only after tag verification. Verify association identity, authorization and required freshness before new-message acceptance.
8. Reassemble authenticated plaintext slices within one association/authorization domain, or plaintext slices in their separate permitted domain. Recheck freshness at final admission; dispatch only a complete accepted message. Bootstrap uses its separately bounded untrusted reassembly and never dispatches application data.

A structural parser may produce a view of unknown safe metadata, but that is not permission to execute it. Router and endpoint semantic checks are separate. Invalid checksum or unknown context must not create trusted accepted-message cache entries. Rate limits also bound unauthenticated parsing and temporary reassembly costs where no authenticated binding exists.

Mandatory relationships include:

```text
ACK_REQ       => SEQ + resolvable identity + unicast destination
FRAG          => SEQ + identity + valid stride/total/index + exact nonempty slice length
REQ           => own SEQ; ACK_REQ selects the single reliable request/result exchange
DMP forwarding=> ROUTE + SEQ + identity
ACK           => own SEQ + REPLY_TO + empty payload; no ACK_REQ/FRAG/DESC/STATUS
FRAG_STATUS   => own SEQ + SECURITY + REPLY_TO + 4-byte payload; no ACK_REQ/FRAG/DESC/STATUS/FRESHNESS; recovery annex applies
RSP           => own SEQ + REPLY_TO
ERR           => own SEQ + REPLY_TO + STATUS
SCHEMA_VERSION=> explicit SCHEMA_ID
ROUTE         => no ORIGIN_ID extension
SECURITY      => SEQ + supported SEC-1 descriptor; endpoint acceptance requires live authorized association
FRESHNESS     => SECURITY + exactly 16 token bytes + configured SEC-1 freshness rules
```

All limits and allocations must be checked with overflow-safe arithmetic. Structured local results distinguish malformed, unsupported, integrity-failed, context-missing, too-large, incomplete, duplicate and resource-exhausted outcomes. Malformed/untrusted input normally causes a local drop, not a response storm. Send wire ERR only when a valid request identity and return path are available and policy permits it. Do not answer ACK, ERR or FRAG_STATUS with another automatic ERR.

## 21. Portable API and implementation boundaries

The library core has no dependencies on ESP-IDF, FreeRTOS, sockets, radio drivers, application state or payload codecs.

```text
libdmp/
    core                 packet encode/decode, varints, registries
    stream_l             length framing
    stream_r             COBS and envelope CRC
    integrity            CRC32C
    security             optional SEC-1 state, Noise/AEAD provider interface, replay and freshness
    identity             context resolution and references
    reliability          optional bounded ACK/retry/cache state and SELECTIVE-32 recovery
    reassembly           optional bounded fragment collection
    mesh                 optional forwarding and routing-policy hooks
bindings/
    udp, websocket, uart, radio, native-mesh adapters
profiles/
    application schemas, service mapping, configured limits
```

A recommended API separates pure parsing from effectful acceptance:

```c
dmp_result_t dmp_parse_packet(const uint8_t *data, size_t len,
                              const dmp_limits_t *limits,
                              dmp_frame_view_t *out);
dmp_result_t dmp_accept_message(dmp_session_t *session,
                                const dmp_rx_context_t *rx,
                                const dmp_frame_view_t *frame);
dmp_result_t dmp_encode_packet(const dmp_frame_t *frame,
                               uint8_t *out, size_t capacity,
                               size_t *written);
```

These signatures are illustrative, not an ABI commitment. Views borrow input memory; document lifetime. Encoding reports errors separately from encoded length. Sessions receive caller-provided monotonic time, storage/allocator limits and send callbacks. No hidden socket ownership or mandatory global state. Reassembly may copy slices; a zero-copy core does not imply a zero-copy whole stack. Expose unknown safe extensions so a relay can preserve them. Optional security separates SEC-1 lifecycle/authorization, the reviewed Noise engine, existing primitive backend and platform entropy/persistence services. A controlled core is permitted under annex S1's provenance/maintenance/verification obligations. Public C headers expose no provider/SDK structs; compile-time selection is sufficient. Specify storage size/alignment, bounded scratch/concurrency, fallible RNG, explicit errors, in-place/borrowed buffer ownership, erasure and directional PN/AAD operations. No heap allocation in hot paths; bounded fallible setup allocation is allowed. Receive plus mandatory post-checks plus acceptance is one logical boundary over disposable state, not a required clone. A structural view of ciphertext is never an authenticated plaintext view; expose those states distinctly. Serialize PN allocation, replay marking and message acceptance across concurrent callers.

Decode each packet's header once into a bounded view; sorted singleton extensions need no per-extension heap allocation. Cache native decoded fields or offsets needed for dispatch/AAD, not reparsed copies of the wire header. Per-peer/association contexts SHOULD own shared namespace/origin/epoch data; message records may hold a generation-safe context reference plus SEQ. Do not reuse a context slot while retained acceptance/correlation records can resolve through it. This local representation never shortens an explicit routed identity on wire.

Unsupported modules SHOULD be removable at build time, including routing, reassembly, reliable exchange, optional cipher support and freshness. An implementation may select any already permitted replay-window size suited to its reordering budget; W=64 needs 8 bitmap bytes versus 128 for W=1024, excluding other state. Retain control progress within bounded shared pools and enforce lifetime/ownership; modularity is not a reason to allocate a large independent pool for every semantic state. These are implementation choices, not new wire profiles.

## 22. Wire examples and conformance vectors

All examples below use revision 10 encodings (unchanged from revision 9). Contextual identities are explicitly stated where omitted on wire. Protected examples and all cryptographic inputs/outputs are supplied separately in §22.11 and the normative annex. SELECTIVE-32 header/plaintext examples and mandatory loss cases are in its annex §R6; complete protected feedback vectors are an implementation verification deliverable.

### 22.1 Minimal telemetry

```text
45 02 AA BB
```

VT=0x45 (v2, TELEM), HDR_LEN=2, opaque payload `AA BB`. Header overhead: 2 bytes.

### 22.2 Reliable direct request

Configured namespace=1, requester origin=10, requester epoch=7, responder origin=20, responder epoch=9:

```text
40 04 03 2A AA
```

REQ, HDR_LEN=4, OPTIONS=SEQ|ACK_REQ, own SEQ=42, payload `AA`. Identity is `(1,10,7,42)` from binding context plus SEQ.

The receiver's ACK, with independently allocated SEQ=8:

```text
46 11 81 08 05 0B 01 0A 07 00 00 00 00 00 00 00 2A
```

OPTIONS=SEQ|EXT. EXT_TAG=5 means extension 1 REPLY_TO with C=1,U=0. EXT_LEN=11 includes the fixed eight-byte epoch. Referenced identity `(1,10,7,42)`. ACK's own identity is `(1,20,9,8)` from its direction's binding context. Payload is empty. SECURITY=0 requires this full reference even though the binding supplies implicit own identity.

### 22.3 Explicit-context routed telemetry

```text
45 11 85 51 30 1B 0B 09 01 07 00 00 00 00 00 00 00 AA
```

SEQ=81, route TTL=3/TO_ROOT, source=27. CONTEXT tag=11 (ID 2, C=1,U=1), length=9, namespace=1, epoch=7 as u64LE. HDR_LEN=17; payload `AA`. Identity `(1,27,7,81)`. With the same context unambiguously preconfigured and CONTEXT omitted, the header would be six bytes instead of seventeen.

### 22.4 Two direct fragments

For one configured origin/context:

```text
47 07 09 09 00 02 03 AA BB
47 07 09 09 01 02 03 CC
```

DATA, SEQ=9, indices 0 and 1, chunk_size=2, total_length=3, derived count=2. Offsets are 0 and 2; the final slice is one byte. Reassembled payload `AA BB CC`, including when index 1 arrives first. These are distinct relay/dedup entries but one reassembly identity.

### 22.5 Codec/schema override

```text
47 07 20 03 00 2A 01 DE AD
```

DATA, DESC_FLAGS=3, RAW codec=0, schema=42, version=1. Payload `DE AD`. Schema semantics require an agreed profile.

### 22.6 Unknown-extension role behavior

```text
47 08 80 81 02 02 DE AD
```

Unknown experimental ID 64, C=1/U=0; tag 257 is `81 02`. Endpoint rejects local delivery; a DMP relay may preserve/forward if the rest of the frame and forwarding context are valid. This isolated vector has no ROUTE and therefore does not itself qualify for DMP mesh forwarding.

### 22.7 CRC and COBS algorithm vectors

```text
CRC32C input ASCII "123456789": value E3069283, wire 83 92 06 E3
COBS input [11 00 22]: encoded [02 11 02 22], delimiter excluded
COBS input [11 repeated 254 times]: FF [11 repeated 254 times] 01 (256 bytes)
COBS input [11 repeated 255 times]: FF [11 repeated 254 times] 02 11 (257 bytes)
COBS input [11 repeated 508 times]: FF [11 repeated 254 times] FF [11 repeated 254 times] 01 (511 bytes)
Stream L carrying minimal telemetry: 44 4D 50 04 45 02 AA BB
Core telemetry with CRC32C: 45 04 10 01 AA BB A3 D5 0E BD
Stream R carrying minimal telemetry, including initial sync: 00 09 45 02 AA BB 39 EE 4C 1F 00
```

The repetition notation specifies exact octets, not literal bracket text; COBS lengths exclude the delimiter. The shortened 254/508-byte-run encodings with their final `01` removed are noncanonical and MUST be rejected under §15.2. Stream R vectors must also cover CRC validation, the initial synchronization delimiter, zero bytes adjacent to full blocks and oversized candidate recovery. Application headers cannot substitute for those binding tests.

### 22.8 Required negative and state-machine cases

- HDR_LEN below 2, above frame length, or unexplained header bytes;
- truncated/overflowed/non-minimal ULEB; OPTIONS=0 with HDR_LEN>2;
- duplicate/out-of-order extensions or extension length crossing HDR_LEN;
- unknown critical vs unsafe extension at different node roles;
- invalid descriptor flags, schema version without schema, unsupported CRC/security;
- same SEQ in different origins/epochs; own ACK SEQ different from REPLY_TO;
- lost ACK followed by retry: no second operation, repeated receipt;
- multiple fragments with one SEQ, out-of-order completion and conflicting duplicates;
- relay cooldown permits a later retry but limits duplicate bursts and total forwards;
- TTL=0 local consumption without forwarding; TTL=1 permits one relay to send TTL=0;
- corrupted core CRC after TTL mutation unless recalculated;
- stream partial reads, concatenated frames, bad lengths/delimiters/CRC and bounded recovery;
- quota exhaustion, reboot/epoch change, expiry and outstanding late replies.
- reliable request/result: immediate reliable RSP without separate request ACK; lost request ACK followed by RSP; lost RSP; lost result ACK; duplicate REQ while processing and after result release;
- reliable request/result: cached pre-acceptance rejection, terminal application ERR, processing/result timeout, local cancellation, late/duplicate result and exhausted correlation capacity;
- one shared outgoing request/result stop-and-wait gate per peer/service, receipt ACKs bypassing it, and result queueing within deadlines;
- unknown safe zero-length extension versus a known extension with an invalid zero-length value;
- Stream R coordinated startup, missing synchronization prefix, independent receiver restart and optional per-frame delimiter;
- a loss-free fragmented transfer spanning scheduling gaps, retry/reassembly timer consistency and quota exhaustion mid-transfer;
- outgoing path smaller than ingress MTU, rejected transparent re-fragmentation, named binding segmentation and missing egress identity context;
- stale live samples after newer samples and after epoch changes; new transfer identity must not bypass application operation idempotency.
- full application/retry queues still permit admitted receipt processing and ACK transmission; unauthenticated HELLO floods cannot consume all control reserves;
- accepted borrowed TX buffers remain unchanged through delayed DMA completion, disconnect, failed cancellation and late completion after pool-slot reuse;
- deadline expiry before transmission versus after a possibly transmitted fragment produces distinct local outcomes without claiming remote cancellation;
- byte/count/cache quotas, per-peer fairness and protected retries retain their guarantees under control/data contention and repeated admission failures.
- fixed-stride geometry: zero stride, total<=stride, invalid index/final length, total quota overflow, first arrival at the final index and index-varint boundary headroom;
- fixed eight-byte epochs and full versus secured compact references; reject trailing bytes and cross-association/old-slot correlation;
- accepted duplicate with unchanged metadata and different payload never dispatches or creates another acceptance; its receipt refers only to the original identity; incomplete conflicting slices still reject;
- reliable REQ has one immediate-result rule on every enabled service; unsupported exchange support rejects before execution.
- lost protocol-rejection ERR followed by a duplicate REQ repeats the retained rejection without execution, reliable ERR state or ACK; reject STATUS 1–7 with ACK_REQ and reserved STATUS 8–63; terminal application ERR remains reliable for reliable REQ;
- default-service omission, explicit nondefault replies/receipts, explicit SEC-1 control 0 and HELLO exclusions; reject explicit application default or wrong-service replies before exchange completion.

Two independent implementations should exchange golden frames and state-machine scenarios before the draft is frozen. Passing encoder/decoder round trips in one implementation is insufficient evidence of interoperability.

### 22.9 Immediate reliable response and result receipt

Use the identities and reliable request from §22.2 on a service supporting §8.1. The responder allocates SEQ=9 and sends an immediate RSP with ACK_REQ; the payload `BB` is a valid result under the example's configured application schema:

```text
41 11 83 09 05 0B 01 0A 07 00 00 00 00 00 00 00 2A BB
```

OPTIONS=SEQ|ACK_REQ|EXT; full REPLY_TO references request `(1,10,7,42)`. Once validated, this RSP stops REQ retries even without a separate request ACK. This behavior is mandatory for reliable REQ, not a profile-selection choice.

The requester allocates SEQ=43 and acknowledges the result's identity `(1,20,9,9)`:

```text
46 11 81 2B 05 0B 01 14 09 00 00 00 00 00 00 00 09
```

If this ACK is lost, the responder repeats the identical RSP under its result retry budget. The requester resends the cached ACK without delivering a second result callback. A duplicate original REQ must not allocate a new result SEQ or repeat execution.

### 22.10 Unknown safe empty extension

For a receiver that does not recognize experimental extension ID 64:

```text
47 06 80 80 02 00
```

EXT_TAG=256 encodes ID=64, C=0/U=0; EXT_LEN=0. This is structurally valid and ignorable at an endpoint. It has an empty payload and requires a profile that permits that DATA payload. It is not a routable mesh frame because ROUTE and SEQ are absent. By contrast, `47 05 80 05 00` carries known REPLY_TO with length zero and is malformed.

### 22.11 SEC-1 cryptographic vectors

The [security annex](DMP_v2_Security_Profile.md) and [JSON vectors](DMP_v2_Security_Test_Vectors.json) specify Noise flights, handshake hashes, directional keys, derived epochs, confirmation, telemetry, routed requests, fragments, repeated receipts, freshness-extension encoding and mutation outcomes. Public deterministic test keys are intentionally included; never provision them on devices. The fixture manifest bytes are test inputs, not a production deployment manifest.

The vector generator is checked against public Cacophony outputs for NNpsk0/XX with ChaChaPoly/AESGCM and SHA256. A separate Node crypto verifier reconstructs DMP header/AAD and checks packet encryption results. These checks do not substitute for real endpoint state-machine interoperability. See the development validation notes for commands and evidence; production conformance consumes the normative JSON independently.

## 23. Overhead accounting

Counts exclude native radio/IP/UDP/WebSocket headers and exclude payload. Context must be supplied explicitly or by a valid binding.

| Case | DMP overhead |
|---|---:|
| Minimal best-effort packet | 2 B |
| SEQ or SEQ+ACK_REQ, SEQ<128 | 4 B |
| ROUTE to root, small SEQ/source, implicit context | 6 B |
| Same routed frame, CONTEXT with one-byte namespace and fixed epoch | 17 B |
| TO_NODE instead of TO_ROOT, destination<128 | +1 B |
| FRAG, index/chunk_size/total_length<128, SEQ already present | +3 B |
| PAYLOAD_DESC with flags=0 and codec<128, OPTIONS already present | +2 B |
| CRC32C descriptor + trailer, OPTIONS already present | +5 B |
| Unprotected ACK in §22.2, small IDs/SEQ, fixed epoch, implicit own context | 17 B |
| Unprotected ACK with 3-byte own/referenced SEQ, 1-byte namespace/origin, implicit own context | 21 B |
| Same ACK with explicit own CONTEXT and TO_NODE (1-byte namespace/source/destination) | 35 B |
| Stream L | +3 B magic + ULEB32 frame length |
| Stream R | +4 B envelope CRC + COBS expansion +1 B delimiter |

If a feature creates OPTIONS where none existed, add that byte. SEQ uses two bytes from 128, three from 16384, and up to five. Epoch/context/security/service metadata costs additional bytes. Six bytes is a small-value conditional example, not a permanent cost of reliable secure mesh.

The 17/21/35-byte ACK examples exclude integrity/security and outer transport costs. Stream R's initial synchronization adds one byte per transmit-binding startup; an optional per-frame prefix adds one byte per prefixed frame. It is additional to the trailing delimiter listed above.

Evaluate a complete exchange: request, optional receipt, result, result receipt, repeats and radio receive windows. Under the small-ID/SEQ context of §22.9, an unprotected immediate exchange has 4 B REQ header + 17 B RSP header + 17 B result ACK = 38 B DMP overhead, excluding the two application payloads and all binding overhead. Sending a separate 17 B request ACK increases it to 55 B. Both forms have bounded result retransmission; a validated immediate result always substitutes for receipt.

SEC-1 compact REPLY_TO is defined in §6.1. With one-byte referenced SEQ its extension occupies 3 B (tag, length, SEQ), versus 13 B for the unprotected full reference with one-byte IDs/SEQ and an eight-byte epoch. Larger counters change these counts canonically; the two forms cannot be interchanged under the same SECURITY flag.

SEC-1 adds `1 + ULEB_size(RX_CID) + ULEB_size(PN) + 16` bytes when OPTIONS and SEQ already exist. For one-byte CID/PN this is 19 B. A direct protected telemetry frame with one-byte SEQ/CID/PN has 23 B overhead; a direct protected ACK with compact REPLY_TO and implicit own context/default service has 26 B. A similarly configured immediate protected REQ/RSP/result-ACK exchange has 23 + 26 + 26 = 75 B overhead. A routed protected frame also carries explicit CONTEXT and TO_NODE. FRESHNESS adds 18 B (tag + length + 16 token bytes); a protected frame already has OPTIONS. The companion vectors expose actual complete sizes. Bootstrap, fragmentation, native framing and receive windows add separate costs.

In the direct unfragmented public fixtures, PSK bootstrap totals 226 B for its two flights plus 48 B for FINISH/READY = 274 B; XX totals 358 B for three flights plus 48 B = 406 B. These loss-free DMP byte counts exclude binding framing, retries and out-of-band verification time. A 72-byte full initial prefix is followed by 18-byte continuation prefixes. These are calculated wire sizes, not measurements of CPU, energy or RAM.

### 23.1 Evaluation before wire-format optimization

The [evaluation guide](DMP_v2_Design_Tradeoffs.md) defines the comparison matrix for Noise SEC-1, constrained security alternatives and selective-recovery candidates. Record exact implementation/library revisions, manifest bytes, credentials/algorithms/tag lengths, MTU and native framing, loss/sleep conditions and queue budgets. Measure cold establishment separately from warm traffic and report completed-exchange bytes in both directions, retransmissions, airtime/receive windows, latency distribution, CPU and peak retained memory. Measure energy only when instrumentation supports it; byte counts alone are not energy measurements.

Security properties must be equivalent or their differences explicit: credential authentication, forward secrecy, tag strength, replay/freshness, restart safety and gateway trust scope. A shorter tag, omitted authenticated context or TLS-terminating intermediary cannot silently count as an equivalent SEC-1 optimization. Include direct and routed cases, actual epoch/sequence widths and negative/overload scenarios. No performance result is asserted by the comparison guide or by this document revision.

## 24. Implementation and release sequence

This section is informative. The [implementation plan](../dev/DMP_Implementation_Plan.md) and [dependency board](../dev/DMP_Work_Packages.md) define the current implementation order and acceptance gates. They do not override normative wire, security or recovery requirements.

The sequence begins with target/provider feasibility and manifests, then core/framing and deterministic transport, identity/delivery/reassembly, real SEC-1, routed SELECTIVE-32 integration, independent interoperability and measured readiness. SELECTIVE-32 is already specified by the [recovery annex](DMP_v2_Selective_Recovery.md); dynamic control-plane modules remain outside this revision. Protected confirmation/activation follows AEAD/AAD/PN implementation, and provisional test-context evidence requires real-security reruns. Physical bindings require their own evidence.

Freeze an interoperable release only after independent implementations agree on frames, profiles and required fault scenarios, with the resource/transport evidence described in §23.1. This specification does not certify existing DTrack firmware/client implementations. Implementations must explicitly select the draft and profile identified at the start of this document.

A controlled Noise core additionally requires source/component license provenance, review of its security-critical delta and independent standard-Noise/state-machine evidence. Translation of another implementation must not use only that source implementation as the independent peer. Track protocol-engine and primitive-backend independence separately. Public byte fixtures do not prove abort-first cleanup, scheduling, resource bounds or resistance to input floods; S10.17 remains an endpoint gate.

## 25. Optional future features

Features outside the defined conformance set include sliding/multiple selective windows, bulk-transfer services/content hashes, binding segmentation where the native transport does not provide it, generic capability negotiation, compression descriptors, group delivery/security, dynamic routing control messages, global namespace allocation, extended hop limits, absolute timestamp/deadline encoding, priority signaling and custody transfer. SEC-1 bootstrap, AEAD and optional freshness leases are defined in the security annex; bounded SELECTIVE-32 is defined in the recovery annex; the single reliable request/result behavior is defined in §8.1. Same-association compact replies are already defined by §6.1, not a future feature. An excluded feature is unsupported, not an implementation-specific interpretation of a reserved bit.

Each addition requires a demonstrated use case, exact encoding, bounded state machine, unknown-feature behavior, security interaction and test vectors. Keep mandatory core cost at two bytes. Do not add RSSI, radio parameters or repeated profile defaults to every message merely because one application uses them.

Candidate research and evaluation criteria are collected in the [design tradeoffs guide](DMP_v2_Design_Tradeoffs.md).

## 26. Design references

These sources inform design patterns. Their wire formats and full state machines are not automatically implemented by DMP.

| Source | Pattern used or considered |
|---|---|
| [CoAP, RFC 7252](https://www.rfc-editor.org/rfc/rfc7252.html), §§4–5 | Message identity vs request correlation; duplicate handling, bounded reliability; critical/elective and forwarding-safety distinctions |
| [UDP Usage Guidelines, RFC 8085](https://www.rfc-editor.org/rfc/rfc8085.html) | Path MTU and congestion-aware sending |
| [OSCORE, RFC 8613](https://www.rfc-editor.org/rfc/rfc8613.html) | Explicit classification of protected and intermediary-visible fields |
| [Noise Framework](https://noiseprotocol.org/noise.html), [SEC-1 annex](DMP_v2_Security_Profile.md) | Normative SEC-1 key establishment primitives and DMP-specific secure binding |
| [SCHC, RFC 8724](https://www.rfc-editor.org/rfc/rfc8724.html) | Constrained fragmentation and selective feedback precedents |
| [CoAP Block-Wise, RFC 7959](https://www.rfc-editor.org/rfc/rfc7959.html), [Q-Block, RFC 9177](https://www.rfc-editor.org/rfc/rfc9177.html) | Bounded application block transfer and selective recovery of missing blocks |
| [CoAP Echo/Request-Tag, RFC 9175](https://www.rfc-editor.org/rfc/rfc9175.html) | Freshness checks distinct from authentication, and operation/transfer correlation |
| [QUIC DATAGRAM, RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) | Coexisting reliable and unreliable delivery behaviors for different application traffic |
| [Micro XRCE-DDS transport](https://micro-xrce-dds.docs.eprosima.com/en/v2.4.1/transport.html) | Separate packet core and serial framing |
| [CSP / libcsp](https://github.com/libcsp/libcsp) | Modular embedded routing, pools and explicit zero-copy buffer ownership |
| [Micro XRCE-DDS streams](https://micro-xrce-dds.docs.eprosima.com/en/stable/client.html), [Matter MRP resource configuration](https://github.com/project-chip/connectedhomeip/blob/master/src/messaging/ReliableMessageProtocolConfig.h) | Bounded reliability history and buffer capacity for ACK progress |
| [WireGuard protocol](https://www.wireguard.com/protocol/) | Bounded handshake work and binding-specific cookie design precedent, not a DMP cookie format |
| [EDHOC, RFC 9528](https://www.rfc-editor.org/rfc/rfc9528.html), [combined EDHOC/OSCORE, RFC 9668](https://www.rfc-editor.org/rfc/rfc9668.html) | Constrained security comparison; no SEC-1 wire substitution |
| [SPAKE2+, RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html), [Matter commissioning security](https://docs.silabs.com/matter/2.2.0/matter-fundamentals-security/) | Candidate short-code commissioning through PAKE |
| [Zenoh key expressions](https://spec.zenoh.io/spec/1.0.0/concepts/key-expressions.html), [Libcanard](https://github.com/OpenCyphal/libcanard), [Nunavut](https://github.com/OpenCyphal/nunavut) | Readable local service names, deadline-aware sending and generated tooling |
| [MAVLink serialization](https://mavlink.io/en/guide/serialization.html) | Compatibility-aware feature handling |
| [RPL, RFC 6550](https://www.rfc-editor.org/rfc/rfc6550.html), [MRHOF, RFC 6719](https://www.rfc-editor.org/rfc/rfc6719.html), [Trickle, RFC 6206](https://www.rfc-editor.org/rfc/rfc6206.html) | Future route-selection/control-plane design precedents |
| [Bluetooth Mesh Protocol](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/MshPRT_v1.1/out/en/index-en.html) | Existing mesh stack owns native forwarding, counters and delivery machinery |

The current byte encodings, extension allocation, reliable exchange behavior and API suggestions are DMP design decisions. They remain a draft pending independent implementation validation.
