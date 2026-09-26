# DMP v2 — Design Trade-offs and Prior Art

**Status:** informative companion to DMP v2 document revision 10\
**Date:** 2026-09-26\
**Normative status:** explanatory only; the specification and SEC-1 annex define conformance

This guide records prior art and the simplifications adopted in revision 7. It explains the reasoning behind the current design; it does not define a wire format or amend the [DMP specification](DMP_v2_Device_Messaging_Protocol_Specification.md) or [SEC-1 security annex](DMP_v2_Security_Profile.md). The current baseline is document revision 10 with SEC-1 profile revision 5. Revision 9 added best-effort protocol rejection, canonical same-service replies, concrete SAMPLE-1 initialization and resource acceptance bounds. Revision 10 adopts abort-first and permits a reviewed controlled Noise core; earlier rationale below describes its dated source revision. Earlier draft policies are unsupported; no automatic compatibility mode is defined.

## Abort-first and provider choice in revision 10

An admitted invalid expected Noise flight or failed mandatory post-read pin/payload check now ends only that attempt. Structural rejects and conflicting processed-flight duplicates preserve it; normal loss uses cached bytes. This removes mandatory clone/scratch costs but allows an active injector to force bounded establishment failure. It does not solve provider-specific transport nonce limitations: receive PN=2 then PN=1 and failed-high-PN isolation still apply. Handshake errors and protected-packet tag failures have separate lifecycle rules.

Engine origin, primitive backend, storage/API and failure policy are separate decisions. A small maintained patch or controlled C fork can preserve more existing implementation/test provenance than translating Rust into C, but creates responsibility for every changed security-critical path. A C port loses Rust language guarantees and needs independent state-machine testing beyond its source implementation. Software primitives must work without vendor acceleration; hardware optimization is separately validated. See the dated [source survey](../dev/DMP_Noise_Provider_Survey.md) and [decision record](../dev/DMP_Noise_ADR.md).

No second error policy is enabled now. Preserve-state remains a future extension at receive/post-check/accept, including pin checks and nonrollbackable work/time budgets. Evaluate completed establishment over the whole path: cached retries under loss versus fresh exchanges, backoff and remote orphan capacity under injection. Compare policies on the same provider/configuration if later implemented; C+abort versus Rust+preserve confounds policy, implementation and backend. No target RAM/time/energy advantage has been measured.

## Adopted simplifications

| Area | Choice retained in revision 8 (introduced in revision 7) | Practical effect |
|---|---|---|
| Epoch encoding | Fixed eight-byte little-endian epoch | Predictable context size and simpler parsing. The epoch is an identity component, not a clock or nonce. |
| Reply correlation | SEC-1 uses a sequence-only `REPLY_TO`, resolved through the receiving endpoint's own sending identity on the same authenticated association. Unsecured frames use the full key with fixed-width epoch. | No selector or alternate compact mode; association state supplies secure identity. |
| Fragmentation | One fixed-stride `FRAG`: index, chunk size and total length; count and offset are derived. Geometry and slices stay immutable. | Any fragment can be placed directly, including out-of-order arrival, with bounded early length admission. |
| Reliable requests | Every reliable `REQ` uses the single request/result behavior in §8.1. | One reliable request/result contract. Generic reliable data/events and best-effort request/result remain distinct. |
| Accepted duplicates | Receipts refer to the accepted identity and retained logical metadata. Historical payload or per-fragment hashes need not be retained solely for a receipt. | Check metadata, avoid redispatch, and do not retain old payload just to compare accepted duplicates. Incomplete reassembly still checks duplicate slices; senders still keep payloads immutable. |
| SEC-1 bootstrap | `BOOT_VERSION=2`; initial prefix is 72 bytes and continuation prefix is 18 bytes. Complete bootstrap payloads, including prefix and Noise message, are 120/70 bytes for PSK and 104/118/82 for XX. | Smaller later flights. Continuations must resolve to an existing pending attempt and cannot create one. Full sizes are in the annex. |
| Freshness | Freshness support is an optional implementation component, enabled and bounded by the deployment manifest where required. | No rule that every SEC-1 endpoint must implement freshness tokens. |
| Implementation structure | Shared bounded contexts, explicit ownership, and removable modules where supported. | Routing, reassembly, reliable exchange, optional cipher support and freshness can be omitted when the selected profile permits it. Context handles can refer to shared state instead of duplicating it. |

For loss-free direct exchanges using the published fixtures, total DMP handshake plus FINISH/READY traffic is 274 bytes for PSK and 406 bytes for XX. These are calculated byte totals, not MCU CPU, RAM, energy or timing benchmarks. Exact flight sizes and counting boundaries are specified in the annex.

## Prior art and what transfers

### Modular routers and bounded memory

[libcsp](https://github.com/libcsp/libcsp) demonstrates a modular embedded router with configurable interfaces, FreeRTOS integration, fixed resource pools and zero-copy paths. These are useful implementation precedents: provision finite pools, make ownership transfer visible, and avoid copies where safe. They do not establish DMP framing, reliability, identity or security semantics. Zero-copy still requires a precise buffer-reuse rule.

DMP implementations should budget finite queues and pools, preserve control progress during application congestion, and document ownership while transport or crypto work is pending. An advertised message maximum does not imply unbounded memory. Failed enqueue and local expiry are local outcomes, not successful DMP acknowledgements.

### Constrained handshakes and field protection

[EDHOC (RFC 9528)](https://www.rfc-editor.org/rfc/rfc9528.html) specifies authenticated key exchange for constrained devices. [OSCORE (RFC 8613)](https://www.rfc-editor.org/rfc/rfc8613.html) protects CoAP messages end to end, and [RFC 9668](https://www.rfc-editor.org/rfc/rfc9668.html) defines their composition. [Lakers](https://github.com/lake-rs/lakers) illustrates constrained EDHOC implementation work. These are useful research precedents, not DMP modes or evidence of an independent security audit. SEC-1 continues to use Noise; an alternative requires an exact DMP binding, identity and authorization mapping, restart/replay rules, vectors and independent implementations.

External TLS/DTLS or native-link protection remains a separately declared binding choice. Its trust boundary depends on the deployment: transport security is not automatically end-to-end through a TLS-terminating gateway, and the manifest must describe the selected protection. No universal SEC-1 endpoint requirement for freshness tokens or one particular external binding is implied.

### Pairing and password-authenticated exchange

Matter uses SPAKE2+ for password-authenticated commissioning; see the [Matter security overview](https://docs.silabs.com/matter/2.2.0/matter-fundamentals-security/) and [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html). This is relevant when devices must pair without a pre-shared high-entropy key. A short PIN cannot safely be substituted into a PSK field.

A DMP PAKE candidate would need a precise transcript and state machine, identity confirmation, retry and lockout policy, pairing authorization/cancellation, credential storage and replacement, revocation, and vectors. Those decisions are not part of revision 8; PAKE remains unsupported. SEC-1 pairing instead uses a provisioned/pinned full static public key or an authenticated comparison of the full 32-byte final Noise handshake hash. A static-key hash is not that handshake hash. Each endpoint authorizes its peer; authorization at one side does not authorize the other.

### Under-load cookies

[WireGuard](https://www.wireguard.com/protocol/) uses a cookie mechanism tied to its transport and threat model. A public radio MAC is not an authenticator, and an IP-bound cookie cannot be copied to a raw radio link where source addresses can be spoofed, changed or relayed.

DMP uses bounded pre-authentication admission: cap pending handshakes, parser work, memory, rates and time spent on incomplete attempts. Revision 8 adds no cookie exchange. A future challenge would require a wire encoding, binding-specific return-path evidence, cryptographic binding, expiry/replay rules, anti-amplification analysis and vectors.

### Selective recovery and feedback

[SCHC fragmentation and recovery (RFC 8724)](https://www.rfc-editor.org/rfc/rfc8724.html) describes constrained fragmentation, bitmap windows and feedback recovery. It shows how selective recovery can avoid retransmitting every fragment, while also making feedback, fragment identity, window bounds, timeout behavior and receiver memory explicit.

Revision 8 retains fixed-stride indexed fragmentation and adds optional [SELECTIVE-32](DMP_v2_Selective_Recovery.md): one missing mask for at most 32 fragments, authenticated TYPE 8 feedback, bounded repairs/probes and unchanged final acceptance. Sliding windows, group recovery and capability negotiation remain unsupported.

The [reference profiles](DMP_v2_Deployment_Profiles.md) select retry-all for DIRECT-1 and SELECTIVE-32 for RADIO-1. Lost feedback/final receipts are probed with the original final fragment and a fresh SEC-1 PN. An incomplete assembly that was discarded cannot reopen under the same identity; a bounded tombstone prevents lifetime renewal. This is a specified design, not measured performance or implemented interoperability. Selective recovery saves redundant transmissions but retains sender slices and whole-message receive storage. Large resumable objects still belong in a separate application block-transfer service.

### Reliable histories and control capacity

[eProsima Micro XRCE-DDS](https://micro-xrce-dds.docs.eprosima.com/en/stable/client.html) distinguishes reliable and best-effort streams and documents bounded history resources. Matter's [reliable-message configuration](https://github.com/project-chip/connectedhomeip/blob/master/src/messaging/ReliableMessageProtocolConfig.h) is an example of explicit resource configuration. These precedents reinforce that reliability consumes finite memory and control capacity. A transport write does not prove DMP acceptance or application completion.

DMP keeps request receipts, result retries and accepted-message metadata within declared lifetimes and quotas. A timed-out command may have an unknown outcome; implementations must expose that uncertainty and must not silently repeat a non-idempotent operation under a new identity. Data congestion must not consume all resources needed for protocol control, but a control reserve must also be bounded and rate-limited.

### Names, deadlines and generated code

[Zenoh key expressions](https://spec.zenoh.io/spec/1.0.0/concepts/key-expressions.html) and its [QoS concepts](https://spec.zenoh.io/spec/1.0.0/concepts/qos.html) illustrate explicit name matching and QoS. DMP's numeric identifiers retain their defined meanings; dynamic aliases and name resolution remain unsupported until authority, scope, expiry, revocation, collision and authorization rules are specified.

[libcanard](https://github.com/OpenCyphal/libcanard) and [Nunavut](https://github.com/OpenCyphal/nunavut) are useful references for bounded allocation, transfer lifetime and generated serialization. Their type and transport contracts do not define DMP payload or operation semantics. A local deadline can stop new submissions and report an unknown outcome, but it cannot promise remote execution by that deadline without an application contract and trustworthy time model.

## Unsupported directions

The following remain research candidates and have no revision 8 wire support: PAKE pairing, EDHOC/OSCORE, sliding/multiple recovery windows, stateless cookies, dynamic aliases, session resumption, and alternative compact security contexts. Compact same-association `REPLY_TO` is already specified; it is not a future feature. Candidate names do not reserve extension IDs or permit experimental bytes on the wire.

Any future candidate needs a complete wire format and state machine, bounded resource and failure model, security analysis, canonical vectors and independent implementations. It must explain its interaction with SEC-1 and identify the deployment need it addresses. It must use reviewed protocols and primitives rather than introduce an ad-hoc cryptographic construction.

## Reproducible benchmark matrix

No MCU performance measurements are claimed by this guide. The handshake byte totals above are calculations from deterministic public fixtures. To compare implementations, hold the application operation and acceptance semantics constant, record the exact firmware, compiler, crypto library, board, radio, PHY, MTU and configuration, and report unavailable measurements as unavailable rather than estimating them.

| Dimension | Suggested values and records |
|---|---|
| Path | SEC-1 PSK, SEC-1 XX, warm protected transfer; unprotected framing only as a non-equivalent cost reference |
| Payload | 8 B, 32 B, 128 B and one 4 KiB application object split into separately admitted messages no larger than the selected family's 1,024-byte ceiling (or lower path limit); include the application block protocol and its overhead, never a single 4 KiB FRAG message |
| Loss and faults | 0%, 1%, 10%; loss model, reordering, lost receipt/result, restart and quota exhaustion |
| Link and topology | Wired, BLE and narrowband radio; direct pair and transparent routed path; record binding and PHY details |
| Load | Single peer and bounded concurrent peer/control load; report offered rate and queue limits |
| Procedure | Fixed warm-up and run duration/sample count, repeated runs, randomized path order and recorded failures |

Report handshake bytes and round trips, total wire bytes per accepted logical message including DMP and binding framing and retries, latency distributions, channel occupancy where measurable, peak RAM by state category, CPU cycles/time, and energy only when instrumented. Separate static pools, handshake state, replay state, queues and reassembly. Include timeouts, rejected handshakes, drops and unknown outcomes; distinguish attempted from accepted messages and initial transmission from retries. Publish raw samples, harness/configuration and analysis code for any measured result. Benchmarks do not establish cryptographic security, interoperability or release readiness.

## References

The linked specifications and project documentation support the limited prior-art claims above. The DMP specification and SEC-1 annex remain authoritative. RFC 9528 defines EDHOC, RFC 8613 defines OSCORE for CoAP, and RFC 9668 specifies their combination. These references do not make those protocols part of DMP conformance.
