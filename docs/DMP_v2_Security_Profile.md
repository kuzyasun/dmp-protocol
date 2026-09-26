# DMP v2 security profile SEC-1

**Status:** normative implementation draft accompanying DMP document revision 10\
**Profile revision:** 5\
**Date:** 2026-09-26

This annex is part of the [DMP specification](DMP_v2_Device_Messaging_Protocol_Specification.md). MUST, MUST NOT, SHOULD and MAY have the same meanings. SEC-1 specifies pairwise, end-to-end authenticated encryption, including bootstrap and lifecycle. It is optional to implement; once a service requires SEC-1, plaintext fallback is forbidden. This is a complete draft contract for the stated scope, not a claim of independent cryptographic audit or production implementation interoperability.

Profile revision 5 uses main document revision 10 and BOOT_VERSION=2. It replaces mandatory preserve-state receive with the abort-first rules in S3.1 and permits a reviewed controlled Noise core. Bootstrap layouts, standard Noise algorithms, protected framing, credentials and the hard failed-AEAD ceiling are unchanged. Failure semantics are not compatible merely because byte layouts match: exact agreed manifests MUST identify this revision; an old digest MUST NOT be reinterpreted under the new policy. No automatic policy fallback exists. SELECTIVE-32 remains optional. The informative [design tradeoffs guide](DMP_v2_Design_Tradeoffs.md) explains the design choices.

## S1. Scope, threat model and alternatives

An active attacker may observe, inject, alter, duplicate, reorder, delay or drop traffic and may operate a forwarding gateway. SEC-1 protects application payload confidentiality and immutable-header authenticity between authorized endpoints. It prevents repeated packet acceptance within a live association and separates that protection from DMP message deduplication. A relay need not possess endpoint keys. Metadata, lengths, timing and routes remain visible. Availability against jamming, compromised authorized endpoints, physical key extraction, traffic analysis and malicious TTL resetting is not promised.

| Approach | SEC-1 decision |
|---|---|
| Pairwise PSK with authenticated ephemeral exchange | Defined mode 1; suitable for provisioned devices; a fleet-wide shared secret is forbidden |
| Static public keys with authenticated pairing | Defined mode 2; keys must be pinned or verified through an authenticated out-of-band action |
| TLS 1.3 / DTLS 1.3 | Valid external binding protection when those endpoints match the intended trust boundary; not automatically SEC-1 and not end-to-end through a TLS-terminating gateway |
| EDHOC / OSCORE | Relevant constrained-device alternatives; their formats/exporters are not implicitly mapped to DMP by this annex |
| Permanently provisioned traffic key with persisted packet/replay counters | Not supported in SEC-1; avoids a handshake but requires crash-safe sender and receiver state and complicates rollback handling |
| Group-shared AEAD key | Not supported; a member with the key could impersonate another sender. Group origin authentication requires a separate design |

SEC-1 uses the standard Noise framework, revision 34, for key establishment. The DMP-specific work below defines its binding, trust decisions, framing and lifecycle. A maintained upstream engine, controlled fork, or reviewed C port of the standard Noise state machine is eligible; no new cryptographic primitives, nonstandard token transitions or ad-hoc KDF are permitted. A controlled core MUST have pinned source/component provenance and licenses, an identified maintenance owner, a reviewed change ledger, upstream security tracking and repeatable independent vector/state-machine/interoperability evidence before production acceptance. Translating another implementation does not transfer its memory-safety guarantees, audit scope or test results. Choose and verify the primitive backend separately from the engine, including software operation without a vendor SDK. The accompanying vector generator is not production cryptographic code.

There is no anonymous trusted pairing, password-derived PSK, zero-RTT application traffic, session resumption or persistent traffic-key restoration. A bidirectional path is required to establish an association. An established association can carry predominantly one-way telemetry while its volatile state is retained, including during sleep. A strictly transmit-only device cannot establish SEC-1 and must not claim support for it.

## S2. Algorithms and credentials

| Field | Value | Meaning |
|---|---:|---|
| MODE | 1 | Pairwise PSK: Noise `NNpsk0` |
| MODE | 2 | Pinned/verified static keys: Noise `XX` |
| CIPHER | 1 | `ChaChaPoly`: ChaCha20-Poly1305, 32-byte key, 16-byte tag |
| CIPHER | 2 | `AESGCM`: AES-256-GCM, 32-byte key, 16-byte tag |

Both modes use `25519` and `SHA256`. The exact protocol names are `Noise_NNpsk0_25519_ChaChaPoly_SHA256`, `Noise_XX_25519_ChaChaPoly_SHA256`, `Noise_NNpsk0_25519_AESGCM_SHA256` and `Noise_XX_25519_AESGCM_SHA256`. Cipher 1 is mandatory for SEC-1 endpoint conformance; cipher 2 is optional. Mode support must be declared; supporting SEC-1 does not require both credential modes. Other values are unsupported. Never truncate tags. Algorithm choice is fixed for an attempt and allowed by local credential policy, not negotiated by an unauthenticated fallback list.

Mode 1 uses a uniformly generated, individual 32-byte PSK shared only by the two authorized endpoints. KEY_HINT identifies the provisioned credential record; it is public and is not proof of identity. The record binds namespace, both logical node IDs, permitted profile digests, mode/ciphers and service ACLs. PSKs must not be made from serial numbers, MAC addresses, human passwords or one shared fleet secret.

Mode 2 uses Noise static X25519 key pairs. Each side must authorize the peer's actual full 32-byte static public key against its logical identity/profile and permitted services. For a new pair, either keys are already pinned through provisioning, or an authenticated out-of-band comparison verifies the full final 32-byte Noise handshake hash `h` at both endpoints and explicitly authorizes the identified pair. A local pairing window merely permits an attempt; it is not authentication. Blind TOFU, a bare remote 'approve' packet, truncated numeric codes and automatic replacement of a changed pinned key are forbidden in SEC-1. Products may use a physically verified QR transfer or compare the full hash through an already authenticated channel. Details of the human interface are product policy; the exact key/hash checked is not.

In mode 2, KEY_HINT MUST be zero. Existing peers remain pinned across associations; a mismatch fails without silently switching to new-pair mode. Pairing permissions and service authorization are separate: possession of a valid key does not authorize every DMP service.

Enrollment commit and traffic-association activation are separate local transitions. After Noise completion and the required identity/profile/key or hash verification, an endpoint MUST atomically commit the new pin and its granted permissions before sending its authorization confirmation (initiator FINISH or responder READY). Commit is permitted only while that attempt and its approval are still valid. Failed verification, expiry or cancellation before commit MUST discard the uncommitted candidate without installing trust. Once committed, the credential remains authorized across a later confirmation timeout, packet loss or reboot until trusted revocation/replacement; these events destroy pending traffic state, not the committed pin. Local commit does not assert that the other endpoint has also committed. Association activation still follows §S4.

### S2.1 Enrollment and operator-visible trust decisions

A product using QR enrollment MUST state whether it transfers a full static public key for pinning or a full final handshake hash for authorizing one specific attempt. The scan must use an authenticated physical/provisioning path to the intended device; an image supplied only by the unauthenticated peer is not such a path. A public-key QR scan verifies only the scanned party. The other endpoint still needs its own valid authorization of the peer under §S2; pressing a generic pairing button does not authenticate that peer's key. When verifying the handshake hash, both endpoints must bind their approval to that same attempt, logical identities and exact hash before their respective protected confirmations.

The product MUST distinguish pairing allowed, candidate awaiting verification, enrollment committed, connection active, expired and rejected states. Display names, radio names and discovered addresses do not replace verification of the actual key/hash and intended identity. An approval pending for one attempt MUST NOT be applied to another concurrent or later attempt. After enrollment commit, subsequent associations may use that stored credential under its existing identity/profile/permission policy without repeating enrollment. Credential installation is transactional: an uncommitted candidate never replaces an existing pin; revoked or changed credentials require explicit trusted re-enrollment (§S8). Report enrollment success only after local commit and connection success only after §S4 activation; a confirmation timeout after commit leaves the peer enrolled but disconnected. Enrollment grants only the declared service permissions, not an unrestricted administrator role.

SEC-1 has no manual PIN/password mode. A future short-code commissioning profile may use a standardized PAKE such as SPAKE2+ with its specified confirmations and online-attempt protections. That requires an exact DMP binding and independent review, not truncating the current handshake hash or converting a PIN to a PSK. PAKE, EDHOC and WireGuard-style cookies are research precedents, not alternative values for the current MODE field.

### S2.2 Cryptographic state and secret handling

Generate new ephemeral keys and ATTEMPT_ID using a cryptographically secure RNG for every new attempt. RNG calls MUST report failure; do not transmit on insufficient entropy or generation failure, including after cold boot. Never substitute fixed bytes or a noncryptographic generator. Reuse only cached bytes for a retransmission of the same Noise flight; do not regenerate that flight from the same ephemeral key. SEC-1 requires rejection of an all-zero X25519 shared result, including low-order public inputs that produce it, before MixKey; propagate backend errors. Noise revision 34 permits all-zero output or an error for these inputs; SEC-1 deliberately selects rejection. Test this failure path independently of a backend's public-key prechecks. Use X25519's standard decoding rules rather than inventing a new canonical-key restriction.

Use maintained constant-time cryptographic implementations and their authentication-tag verification APIs. After Split, erase ephemeral private keys, transient DH outputs and obsolete handshake/chaining keys; keep only the traffic state, final hash, required authorized peer identity and public/ciphertext flight cache. On abort/closure erase candidate/traffic secrets and sensitive retained plaintext. Long-term authorized credentials follow the trusted credential lifecycle. Production diagnostics MUST NOT log private keys, PSKs, traffic keys or plaintext from services marked confidential. Public test-vector keys are a fixture-only exception.

## S3. Bootstrap wire format

Bootstrap uses DMP TYPE=HELLO (3), SECURITY=0, ACK_REQ=0 and no REPLY_TO, SERVICE_ID, STATUS or PAYLOAD_DESC. Optional core CRC follows the selected binding policy. **Flight 1 only** carries the following fixed 72-byte initial prefix followed by its Noise message; multi-byte integers here are little-endian:

```text
offset  size  field
0       1     BOOT_VERSION = 2
1       1     MODE
2       1     CIPHER
3       1     FLIGHT = 1
4       16    ATTEMPT_ID
20      4     NAMESPACE
24      4     INITIATOR_ID
28      4     RESPONDER_ID
32      32    PROFILE_HASH
64      4     KEY_HINT
68      4     I_RX_CID
72      rest  NOISE_MESSAGE
```

Flights 2 and 3 carry exactly this continuation prefix followed by their Noise message:

```text
offset  size  field
0       1     BOOT_VERSION = 2
1       1     FLIGHT = 2 or 3
2       16    ATTEMPT_ID, identical to flight 1
18      rest  NOISE_MESSAGE
```

Outer SEQ selects the expected flight and MUST match its prefix's FLIGHT. A receiver never guesses the prefix layout from payload length or retries parsing under the previous format. Flight 3 is valid only in mode 2. Reject any other BOOT_VERSION, unrecognized flight or extra bytes. Modes/ciphers/identities/profile digest/hint/initiator CID for continuation flights come exclusively from the retained initial attempt state.

INITIATOR_ID and RESPONDER_ID must differ. I_RX_CID is a nonzero u32 allocated by the initiator as its local receive selector. The responder independently allocates nonzero R_RX_CID. Both peers reject a zero receive selector. A local receive CID must be unique among that endpoint's pending, active and draining associations. It need not be secret or random. CID reuse with fresh keys is permitted only after old association state is gone; a stale ciphertext then fails authentication. Lookup uses the receiving local endpoint and CID, not a global network CID table.

PROFILE_HASH is SHA-256 of the exact pre-provisioned profile-manifest byte string. Its bytes, encoding and line endings are part of provisioning; no implicit JSON/Markdown canonicalization is performed. That manifest fixes service/schema interpretation, security requirements, limits, trust/authorization rules and profile revision. Both peers must possess the same bytes and accepted digest before bootstrap; the handshake does not transfer the manifest. Unknown digests/modes/ciphers are dropped with a local unsupported outcome. No downgrade or generic capability negotiation is inferred.

The common manifest contains public policy/credential identifiers, never private keys or PSK values. Secret credential records and local implementation handles are stored separately. Role-specific policy must be represented consistently in that common manifest rather than hashing two different local configurations.

Noise initialization prologue is constructed once from the complete initial prefix and retained for the attempt. PREFIX below means **flight 1's 72-byte prefix**, not the compact continuation:

```text
ASCII("DMP2-SEC1-BOOT") || PREFIX[0:3] || PREFIX[4:72]
```

Strings have no terminating NUL; slices use an excluded upper index. Thus mode, cipher, attempt, both identities, profile, credential hint and initiator receive CID are transcript-bound. Each recipient also checks that outer origin/destination/context agrees with these fields. The bootstrap may use ROUTE only as TO_NODE to the stated recipient, never TO_ROOT or BROADCAST.

Pending attempt lookup uses the configured local endpoint/namespace, peer origin, ATTEMPT_ID and role. A continuation cannot allocate a new Noise attempt, select another manifest, or replace any saved initial parameter. On missing/expired state it is silently dropped; the sender continues only its phase-appropriate cached retries within the original budget, or its S3.1 scheduler may later request fresh establishment. A reboot cannot resume from a continuation. Once a complete flight 1 is accepted, its identical duplicate may trigger the cached flight 2 within the original budget; conflicting initial bytes do not overwrite the saved prologue. Compact selectors and provisional epochs are untrusted and never replace full attempt/identity validation.

Bootstrap provisional epoch is `LE64(SHA256(ASCII("DMP2-SEC1-BOOT-EPOCH") || ATTEMPT_ID)[0:8])`. Every bootstrap frame MUST include SEQ=FLIGHT, CONTEXT=(NAMESPACE, provisional epoch), and either ROUTE with the correct source/destination or ORIGIN_ID with the correct sender when direct. The provisional epoch is untrusted and is never an application or authenticated replay context. After reassembly, validate it against ATTEMPT_ID before processing Noise. Flights 1 and 3 originate at the initiator; flight 2 at the responder.

If a flight does not fit the path MTU, use the unchanged main fixed-stride FRAG for that one flight. All fragments have the flight's SEQ, consistent provisional context and fixed geometry/slices on retry. CONTEXT encodes the provisional epoch as u64LE. The maximum complete bootstrap payload is 120 bytes; reject larger total_length or retained payloads before allocation. Its prefix may span fragments, so a bounded provisional assembly may exist before the full attempt ID is available; this is not permission to create Noise state. After reassembly, validate the exact flight-specific size, complete prefix, full pending attempt and outer identity before Noise processing. Limits also bound derived fragment count, per-ingress/global incomplete bootstrap assemblies and total unauthenticated bytes. An implementation unable to fit a flight within its admitted fragment budget rejects the configuration. Bootstrap must not execute application callbacks, create trusted message-cache entries or trigger ordinary receipt ACKs.

### S3.1 Noise flights

Initialize Noise exactly once per admitted attempt with the selected protocol name, prologue and credentials. Noise handshake payloads are fixed as follows:

| Mode | Flight 1 | Flight 2 | Flight 3 |
|---|---|---|---|
| 1 / NNpsk0 | Empty plaintext | R_RX_CID as exactly 4 little-endian bytes | Forbidden |
| 2 / XX | Empty plaintext | R_RX_CID as exactly 4 little-endian bytes | Empty plaintext |

With either cipher, Noise message lengths are 48/52 bytes for mode 1 and 32/100/64 bytes for mode 2. Complete DMP bootstrap payload lengths are **120/70** for mode 1 and **104/118/82** for mode 2: the first prefix is 72 bytes and continuations use 18 bytes. Extra Noise payload bytes or trailing data are invalid. Do not substitute a generic Noise application's payloads, prologue, PSK location or protocol name.

Each sender stores the exact emitted flight bytes. Identical duplicates of the preceding valid flight cause a rate-limited retransmission of the cached next flight, not another Noise state transition. Compare complete bootstrap payloads and immutable outer identity/geometry after bounded reassembly; path-dependent TTL/checksum bytes are not part of this comparison. Ignore out-of-order flights that cannot advance the current attempt. A conflicting duplicate of an already processed flight MUST be dropped under the ingress budget: it MUST NOT abort the pending attempt, overwrite its saved parameters/transcript, invoke Noise again, trigger a cached response or reset any deadline. This applies also to changed flight-1 parameters under an existing attempt identity. A bounded diagnostic may record the conflict.

**Abort-first boundary.** Before Noise, validate the public framing, exact complete length, prefix, expected role/flight, full attempt lookup and outer identity/context under S3/S3.2. Classify duplicates before processing. Reserve a bounded work slot/scratch and serialize receive, cancellation and acceptance per attempt. Failure of these checks or lack of capacity does not invoke Noise or destroy existing pending state. Once an admitted new expected flight enters Noise ReadMessage, any DH/decrypt/read failure ends that attempt. Successful ReadMessage is not acceptance: validate the exact decrypted payload (empty or four-byte nonzero R_RX_CID as specified), saved identity/profile binding and applicable pinned-key/credential checks before accepting the result. Failure of a mandatory post-read check also ends that attempt; do not retain the partially advanced engine for a later candidate.

Read plus post-read checks plus result acceptance form one logical boundary. Do not generate the next flight before mandatory receive checks and result acceptance. Credential installation and association activation additionally require S2/S4 authorization; a new unpinned XX pair may complete Noise to obtain the final hash before its OOB decision, without installing trust. Outgoing Noise flights are generated exactly once after successful preceding receive acceptance and then cached. Noise state may be disposable and destructively updated; a clone/checkpoint is not required. If a successful read is awaiting local processing, retain only bounded owned state, preserve the original deadline, and accept no concurrent transition. Failure/expiry/cancellation during this interval follows the same cleanup rule.

| Event | Attempt state / allowed response | Timers and budgets | Cleanup |
|---|---|---|---|
| Flight lost; checksum/framing discard before Noise | Keep attempt; existing timer may retry cached outgoing bytes | Original absolute deadline and retry/response limits | Release only discarded input/assembly as its rules permit |
| Unknown/expired continuation, wrong prefix/context, impossible public length or unexpected flight | Cheap drop; no allocation of replacement Noise state or response | Charge ingress work; no deadline renewal | Release input; preserve other attempts |
| Identical processed-flight duplicate | No Noise call; cached next flight only if that phase still retains it | Original lifetime and response budget | Release duplicate input |
| Conflicting processed-flight duplicate, including changed flight 1 | Drop; no response or transcript mutation | Charge ingress work; no deadline renewal | Release conflicting candidate, preserve admitted state |
| No quota/work slot/scratch before processing | Bounded drop/defer; no crypto call | Original deadline; deferred bytes count toward queue limits | Release unretained input; do not evict admitted state |
| Admitted new expected flight fails Noise read/DH/tag | End only this attempt; no response | Consume work already spent; no automatic restart or budget reset | Abort cleanup below |
| Read succeeds but mandatory payload/CID/pin/policy check fails | End only this attempt; no response | Same accounting as a failed read | Abort cleanup below; no trust installation |
| Read and mandatory checks succeed | Accept result; advance once; next flight only when required | Preserve original deadline; cached-response limits apply | Erase obsolete transient material; retain required cache/state |
| Awaiting authenticated OOB approval for a new XX pair | Bounded candidate only; no confirmation/application activation | Original pairing and association limits continue | Release shared receive scratch; own only required candidate data |
| Expiry, trusted cancellation/rejection, fatal local error (including RNG or write failure) | End only corresponding attempt; local outcome, no failure response | No implicit retry; cancellation does not refund spent work | Abort cleanup below |

Abort cleanup marks the attempt terminal before releasing resources, invalidates its generation so late asynchronous results cannot commit, removes pending lookup/queued retries and releases CID reservations when no longer referenced. Erase owned ephemeral/DH/chaining/PSK copies, candidate traffic keys and sensitive plaintext; discard uncommitted enrollment/approvals. Cancel queued work and release or erase borrowed/in-flight buffers only after the adapter's completion/cancel contract permits it. Already transmitted public/ciphertext bytes cannot be recalled. Keep bounded terminal cleanup ownership until outstanding work finishes; its memory remains charged. Never erase the provisioned credential record or a different active/draining association. A previously committed pin survives under S2. A terminal attempt cannot be resumed by a later continuation or UI approval.

A valid Noise flight from a not-yet-pinned XX peer still requires the out-of-band decision under S2 before trust or traffic activation. Noise validity alone does not authenticate the intended identity. Pending human approval need not retain shared crypto receive scratch. An active injector can end an attempt by supplying an admissible invalid expected flight; this is the deliberate availability cost of abort-first. Ordinary loss does not invoke this transition. No handshake rule promises availability on an attacker-controlled transport.

The manifest defines absolute handshake/pairing timeouts, cached-flight retry schedules, pending quotas, and a finite **establishment episode** budget: maximum locally initiated attempts, total elapsed establishment deadline, cumulative work/traffic ceilings and restart backoff with any jitter. An episode begins at an explicit local establishment request; its limits are not restarted by packets, an attempt failure, UI progress, or a change of ATTEMPT_ID. Background policy may request later episodes only under explicit finite rate/burst limits. A separate local scheduler may start another attempt within those limits; abort itself never starts one or sends an error/restart message. Every newly initiated attempt has fresh ATTEMPT_ID and ephemeral keys. A responder echoes the admitted initiator's ID and generates fresh local ephemeral material for each newly admitted attempt. Global/per-ingress admission/work budgets persist across both attempts and episodes.

Neither repeated flights nor pairing UI events extend an attempt's absolute deadline. Simultaneous attempts are separately bounded and cannot evict admitted attempts/associations merely to make room; excess attempts are refused locally. A failed local attempt may leave a remote orphan until that peer's own deadline. New attempts consume additional quota there and may be refused. There is no implicit remote-close, cookie exchange or required historical-attempt tombstone table. After local state removal, a replayed flight 1 may be admitted as a new bounded responder attempt using fresh local ephemeral material, never restoring the old association; repeated recorded flight 1 bytes therefore can consume bounded work. Old continuations cannot recreate state or restore old keys and must pass the new state's checks if their identifier matches. Full suppression of historical flight-1 replays is not claimed without separately specified retention/lifetime state. Measure this cost and remote-capacity delay under S10.

**Deferred extension:** preserve-state is not supported by this revision. The logical receive/post-check/accept boundary permits a future explicitly specified tentative-state implementation, including pin verification, without changing the first version's storage requirement. Such a design must not roll back CPU/error budgets or elapsed time and must declare storage/erasure and pair/end-to-end-path policy. No second permanent state, wire flag, numeric policy ID, runtime negotiation or automatic fallback is allocated here; opaque state must not be assumed memcpy-cloneable.

### S3.2 Pre-authentication resource admission

Before allocating a provisional assembly or Noise state, an endpoint MUST apply structural frame/header limits and the configured global/ingress byte, fragment, count and arrival-rate budgets. Before invoking Noise/DH on a complete flight, validate its exact permitted length and prefix, recipient/context consistency, supported mode/cipher, accepted manifest digest and credential-hint policy. Continuations must resolve these parameters from an existing initial attempt before processing. Partial fragments do not justify early DH processing. Prefix checks are cheap admission filters; they are not authentication, and a syntactically valid or known credential hint grants no trusted quota.

The manifest MUST define finite limits for concurrent provisional assemblies, total provisional bytes, pending attempts, new attempt rate/burst, expensive cryptographic work, duplicate-response rate/bytes and absolute pending lifetime. Rate budgets must state their time base and burst allowance. Bound ingress parsing work as well as Noise work so a flood of small packets cannot consume an entire protocol worker. Global and per-ingress caps are required even when per-origin limits exist: an attacker can rotate ATTEMPT_ID, ORIGIN_ID or KEY_HINT. Principal-specific trusted quotas may be applied only after that principal has been authenticated.

Specify retained pending-attempt capacity separately from the maximum simultaneous crypto operations and shared scratch slots. Reserve capacity before processing; budget exhaustion is not a tag failure. Serialize or reserve work budget across concurrent callers and retain charges after abort. Startup/setup allocation may be bounded and fallible, but receive/encode/retry paths MUST NOT allocate heap storage, including through provider calls. Failure or cancellation cannot free scratch still owned by an operation. An untrusted flight does not start a new establishment episode or replenish global/ingress tokens.

Preserve the control/data progress resources reserved for already admitted associations by main specification §18.1. Bootstrap may use only its declared share. Repeated flights can trigger cached responses only inside the response budget and existing attempt deadline; they cannot restart timers or allocate duplicate Noise states. When a budget is exhausted, drop/refuse locally and count a bounded diagnostic; do not emit unbounded errors or an undefined retry/cookie message, invalidate an unrelated live association, or persistently revoke a credential based on unauthenticated failures. Forwarders also need bounded provisional forwarding/deduplication state and airtime budgets despite being unable to verify endpoint Noise traffic.

Pre-authentication source identifiers are untrusted. Binding-authenticated ingress identities may inform policy, but a shared gateway identity is not proof of the claimed endpoint principal. SEC-1 defines no stateless cookie exchange. A future return-path challenge must specify a binding with meaningful return-path evidence, transcript/context binding, expiry/replay rules and anti-amplification bounds. A raw DMP origin ID or publicly computable MAC alone is not that evidence.

## S4. Traffic keys, identity and confirmation

After the final Noise flight and its required receive-result acceptance, use the two directional traffic secrets from Noise Split without an extra ad-hoc KDF, through owned opaque traffic contexts or bounded key transfer. The first is initiator-to-responder; the second is responder-to-initiator. Raw-key export is not required if the provider supplies the S5 operations. Save the final 32-byte handshake hash `h`. Keys are direction-specific and association-specific. Do not use Noise half-duplex mode or its in-place Rekey operation in SEC-1; rotation creates a new handshake/association.

For each direction `d` (0=initiator origin, 1=responder origin), the DMP origin epoch for this association is:

```text
LE64(SHA256(ASCII("DMP2-SEC1-EPOCH") || h || byte(d))[0:8])
```

The full association identifier for internal security state is `h`, not this truncated epoch. The 64-bit epoch is an opaque DMP identity component, not a clock, nonce or global identifier. Before activation, check both derived (namespace, origin, epoch) values for collision with retained associations/message identities at that endpoint; end the candidate on collision. Only the separately bounded S3.1 scheduler may request another attempt with fresh ephemeral material. Retain the epoch reservations for the relevant message/cache lifetime. Across lost volatile state, old ciphertext cannot authenticate under fresh keys. Durable operation IDs must be independent of these epochs. SEQ starts at 0 per origin/epoch and follows ordinary DMP allocation rules; it must not wrap.

Direct frames may resolve namespace/origin/epoch from the selected association. Routed protected frames MUST include CONTEXT and ROUTE=TO_NODE so relays can resolve identity without the traffic key. Their namespace/origin/epoch and final destination must equal the association's values. TO_ROOT, BROADCAST and group delivery are not supported by SEC-1. A logical message, including all fragments and retries, stays on one association. Rotation cannot silently move it to a new identity.

After Noise completion and local peer authorization, the initiator sends protected TYPE=HELLO, payload `04` (FINISH). The responder accepts FINISH only after Noise completion and its own peer authorization, then sends protected TYPE=HELLO, payload `05` (READY). Both have own SEQ, SECURITY and optional routing/context, but no ACK_REQ, FRAG, REPLY_TO, STATUS, SERVICE_ID or PAYLOAD_DESC. These payloads are exactly one byte and cannot be confused with unprotected bootstrap. Their encryption uses §S5; these are the first newly protected records in each direction, with PN=0 and SEQ=0 in a loss-free attempt.

The initiator retries FINISH under a bounded confirmation timer until READY. For XX, it also retransmits its cached flight 3 while waiting, because FINISH may arrive before flight 3. Early FINISH without installed candidate keys is dropped. After validating FINISH, the responder resends the same logical READY on duplicate FINISH, with a fresh PN each time. Confirmation retains these logical identities for the association's confirmation-retry horizon. Do not run handshake/confirmation messages through application RPC callbacks.

The initiator becomes active on READY; a valid authorized application packet from the responder while waiting for READY can also prove readiness and is accepted normally. The responder becomes active after authorized FINISH and may send application traffic only after sending READY. Reordering can therefore recover readiness without accepting unauthenticated traffic. Other application traffic received before the local authorization/confirmation conditions are met is dropped. A candidate peer key must not become trusted merely because it can produce an AEAD tag before the required pin/out-of-band check.

## S5. Protected packet encoding

SECURITY=1 selects the following descriptor after PAYLOAD_DESC and before EXTENSIONS:

```text
SECURITY_DESC = CIPHER:u8 | RX_CID:ULEB32 | PN:ULEB64
wire frame   = CORE_HEADER | CIPHERTEXT | TAG[16]
```

CIPHER must equal the association cipher. RX_CID is the receiving peer's advertised CID, not the sender's CID. PN is an independent monotonically allocated per-direction encryption counter; allocate it atomically across all services, message types and fragments on that association. Both directions start at 0. SEQ is required on every protected frame but is never used as the AEAD nonce. INTEGRITY and SECURITY together are forbidden; Stream R's envelope CRC is still mandatory when that binding is selected. CIPHERTEXT has exactly the plaintext slice length; ACK has zero plaintext bytes and still carries its 16-byte authentication tag.

Protected REPLY_TO contains exactly one ULEB32 referenced SEQ. After AEAD verification, resolve it through the receiving endpoint's own origin/epoch/namespace on this association, as defined in main §6.1. The compact bytes are included in AAD; the authenticated association supplies their scope. Full references are invalid in protected frames. No response may transfer this compact reference to a new association after rekey/reboot; application operation lookup is the separate recovery mechanism.

Canonical ULEB64 rules apply to PN. A structural parser can recognize the two supported descriptors and locate their trailers without a key; an endpoint cannot accept their contents without the association. Unknown cipher/descriptor formats are unsupported, not guessed from HDR_LEN. Maximum plaintext slice length is 65519 bytes, additionally bounded by profile/transport limits. Check length arithmetic before accessing header, ciphertext or tag.

SEC-1's PN allocation limit makes its largest permitted PN encoding four bytes. Before fixing fragment slices or accepting a frame for reliable transmission, reserve capacity for that four-byte PN and recompute the maximum resulting HDR_LEN/core-frame length against header and path limits. The actual PN is still minimally encoded. This prevents a retry at a varint boundary (for example 127 to 128) from exceeding MTU. A smaller route appearing later still follows the ordinary MTU-failure rules; the PN reserve does not authorize changing slices.

Use the selected Noise cipher's AEAD function with explicit PN and the exact AAD below. The provider may expose opaque stateless-per-packet operations or an equivalent interface; a particular SetNonce API or raw-key export is not required. It MUST support valid receive order PN=2 then PN=1 within S6's replay window. A failed high-PN verification MUST NOT prevent a later valid lower PN, advance replay state or expose unauthenticated plaintext. Keep sender uniqueness/allocation separate from receiver ordering; changing a shared implicit nonce without serialization is not sufficient. The 12-byte nonces are:

```text
ChaChaPoly: 00 00 00 00 || LE64(PN)
AESGCM:    00 00 00 00 || BE64(PN)
```

The AESGCM nonce's byte order is the specified cryptographic construction; it does not change DMP integer byte order. The maximum u64 nonce is reserved by Noise; SEC-1 imposes stricter limits in §S8.

AAD is exactly:

```text
ASCII("DMP2-SEC1-DATA") || h || CANONICAL_HEADER
```

CANONICAL_HEADER is every received core header byte from VT through HDR_LEN-1, with only ROUTE_CONTROL's upper TTL nibble replaced by zero when ROUTE is present. The lower destination-mode nibble is preserved. Locate ROUTE_CONTROL by bounded parsing, not a fixed offset. No other byte may be removed, reordered, re-encoded or normalized. In particular RX_CID, PN, HDR_LEN, SEQ, fragment metadata, routing identities, all known/unknown extensions and their flags/lengths remain in AAD. The binding envelope is outside AAD.

| Field | Visible | End-to-end treatment |
|---|---|---|
| VT, header length, OPTIONS, SEQ, FRAG | Yes | Authenticated exactly |
| ROUTE source/destination/mode, CONTEXT, ORIGIN_ID | Yes | Authenticated exactly and checked against association |
| Remaining-forwards nibble | Yes | Normalized to zero; not end-to-end authenticated |
| SERVICE_ID, REPLY_TO, STATUS, codec/schema, FRESHNESS and all extensions | Yes | Authenticated exactly, including unknown safe extensions |
| SECURITY_DESC including CID/PN | Yes | Authenticated exactly |
| Application payload slice | No | Encrypted and authenticated |
| Outer framing, link addressing, native segmentation headers | Binding-dependent | Outside SEC-1; use binding/link protection where required |

A relay can reduce TTL and regenerate its outer checksum/protection without the endpoint key. SEC-1 cannot stop an authorized malicious relay from increasing/resetting TTL, dropping frames or spoofing unprotected routing observations; independent forwarding/airtime budgets still apply. If authenticated neighbors or protected hop metadata are required, the deployment MUST select an authenticated lower binding. Merely verifying CRC never satisfies that requirement.

## S6. Replay, retries, reassembly and admission

Maintain a receive window per association/direction: highest authenticated PN `H` and a W-bit bitmap. W is a configured power of two in [64,65536], default 1024. Check old/set PN before decryption for a cheap discard, but do not advance H or set a bit before successful AEAD verification. After verification, atomically recheck/mark the window to handle concurrent copies. For PN>H, shift by PN-H, clearing the bitmap if the shift is >=W; mark the new highest bit. For PN<=H, reject if H-PN>=W or the bit is already set, otherwise mark that bit. Initially no PN has been received; PN=0 is valid. Unauthenticated large counters must not advance state.

A successfully authenticated packet is marked even if subsequent service admission fails. Repeating that same protected packet does not get another application attempt. Do not emit an error for an invalid tag, unknown CID, replayed PN or unauthorized unprotected bootstrap; drop and rate-limit locally. Authenticated but unauthorized/expired application requests may receive protected STATUS=6 only if policy allows and a valid response path exists.

**Logical retries use a fresh PN.** Preserve SEQ, association, plaintext slice and all logical immutable metadata; allocate a new PN and produce new ciphertext/tag/AAD. This applies to repeated receipt ACKs, result retransmissions and retried fragments. A lower binding may naturally deliver the same protected frame twice, but the second copy is dropped by the packet replay window. If an ACK was lost, the sender's next logical retry has a fresh PN, passes packet replay checks, reaches the accepted-message cache, and triggers a newly protected ACK without repeating application execution. Never reuse a PN for another encryption call, even for identical plaintext. Failed/canceled sends may leave counter gaps.

The immutable-content rule excludes per-transmission PN/ciphertext/tag, the specified TTL nibble, and the derived HDR_LEN change caused solely by a different PN encoding length; it does not permit changing logical content under the same SEQ. Cipher, receive CID and association remain fixed for that logical message. Compare parsed logical fields rather than raw protected headers across retries. Each packet still authenticates its exact current HDR_LEN in AAD. Do not retransmit a stored old protected frame as the DMP reliability retry. A cache of plaintext/logical headers is needed for re-protection; handle those buffers as sensitive data with explicit ownership/lifetime.

Authenticate/decrypt each fragment before trusted reassembly. All fragments must use the same association, origin/epoch, destination, SEQ, type, chunk_size, total_length, descriptor, service, references and immutable extensions. PN and tag legitimately differ; TTL may differ. Validate exact plaintext slice length and offset from the authenticated geometry; reserve total_length plus bounded metadata against quotas. Compare duplicate slice plaintext while the assembly is incomplete. After acceptance, use retained identity/metadata under main §7; historical payload bytes or per-slice hashes are not needed solely to regenerate a receipt. Never mix plaintext and SEC-1 fragments or assemble across associations/principals. Bound all temporary memory before authentication; untrusted total_length cannot cause an unbounded allocation.

Packet replay state, message acceptance state and relay suppression remain different mechanisms. High-rate telemetry may move the PN window past an earlier frame; a logical retry with a fresh PN recovers under the existing retry/reassembly lifetime. The application acceptance cache must still prevent repeated execution. Namespace/origin/epoch cache entries from plaintext or another authorization domain must not satisfy or poison SEC-1 acceptance. A relay lacking endpoint keys may maintain bounded provisional forwarding suppression, but cannot treat it as authenticated origin state or publish healthy/authenticated status from it.

## S7. Authorization and command freshness

SELECTIVE-32 deployments additionally follow the [recovery annex](DMP_v2_Selective_Recovery.md). FRAG_STATUS is encrypted control plaintext under the same association and normal AAD/PN rules. Verify its peer/service/reference and active transfer before changing recovery state. It does not grant acceptance, authorize execution, refresh a command lease or replace a final ACK/result. Feedback/probes obey existing association limits, revocation and fresh-PN rules; bootstrap is excluded. No traffic or incomplete assembly resumes across a lost association.

After AEAD verification, check the peer's service/type authorization, schema and required freshness before accepting a new logical message or issuing a success ACK. An accepted duplicate may obtain its receipt/result without passing a now-expired freshness lease again; it MUST NOT execute again. Verify its identity, authenticated association/principal and retained logical metadata under main §7 first. Do not revalidate or dispatch the duplicate payload as a new command, and do not require retention of historical payload solely to regenerate receipts. A repeated receipt confirms only the original accepted identity. If acceptance state is gone, do not infer previous acceptance from a replay-window bit. Incomplete assemblies still reject conflicting duplicate plaintext slices.

SEC-1 authenticates a sender, not a command's age. The security control service below supplies a receiver-timed, single-message freshness lease without synchronized clocks. A service that requires freshness MUST reject a new command without a valid token. Services that tolerate delay may omit it. The manifest specifies which services require tokens and a maximum lifetime; there is no implicit 'all encrypted commands are fresh' rule.

### S7.1 Built-in freshness control service

The freshness service is an optional component of SEC-1. An endpoint with no service requiring leases may omit the token table and reliable control exchange, while still conforming to basic SEC-1. Its manifest MUST declare freshness support and which application services require it; a service requiring leases cannot be enabled without this component. Unsupported freshness requests are rejected before acceptance under the ordinary error policy, never downgraded to unfresh commands.

SERVICE_ID=0 remains reserved for SEC-1 control, even when the component is omitted, and must be explicit on its REQ/RSP, correlated ERR and receipt ACK. Application services use IDs >=1 when SEC-1 is enabled. This service requires SECURITY, the active association and the single reliable request/result behavior of main §8.1; its payload codec is the fixed encoding below, so PAYLOAD_DESC is forbidden. It is accessible only to an authenticated principal authorized to request freshness leases. It cannot authorize additional application services. All control replies use compact same-association REPLY_TO. The generic ACK still has empty plaintext; a control ERR uses the normal STATUS field and empty diagnostic payload.

```text
REQ payload: 10 | requested_lifetime_ms:u32LE
RSP payload: 11 | token[16] | granted_lifetime_ms:u32LE
```

The leading octets are hexadecimal opcodes. Payload lengths are exactly 5 and 21 bytes. Lifetime is in [1,60000] ms; grant must not exceed the request or local policy. For a structurally valid, authenticated control REQ, an unsupported opcode maps to STATUS=1; wrong payload length or an out-of-range lifetime maps to STATUS=7. Reply only when permitted by the RPC rejection/admission policy. A quota failure returns Busy (STATUS=4) or drops under that policy. The responder generates a uniformly random 16-byte token and records its association, requester identity, issuance monotonic time, granted lifetime and unused state before generating RSP. Grant expiry is measured from issuance, not from when RSP or its ACK arrives. Returning a grant never implies its whole lifetime remains after network delay.

Grant results follow the ordinary retention rules of main §8.1. While the original result is retained and its transmission budget permits, a duplicate control REQ resends the same RSP identity, token and granted lifetime; neither result nor token lifetime restarts, even if the token has since expired. After result release, a duplicate with a retained request acceptance record receives only its receipt ACK. It MUST NOT recreate the released RSP, mint another token or reconstruct a result from a still-live token-table entry. Token and request/result records have separate lifetimes. A new lease requires a new REQ identity and ordinary admission, including when an earlier grant expired or its result is unavailable.

Freshness control messages MUST NOT carry FRESHNESS themselves: requesting a lease requires authentication/authorization but no previous lease. This prevents a circular freshness requirement. Grant and token-table admission are bounded before accepting the control REQ.

FRESHNESS extension ID=6, C=1/U=0, EXT_LEN=16 carries that token on the protected command. It is invalid without SECURITY and is repeated identically on all fragments. At the first valid command frame, atomically bind an unused token to that command's full message identity and service; another identity cannot claim it. Binding does not extend expiry. Check expiry on new slices and at final admission immediately before application dispatch. Consume the token on acceptance or terminal rejection; an incomplete/expired assembly cannot recycle the token. An accepted duplicate follows the retained receipt rules. The receiving endpoint is the time authority; a slow route can legitimately make a freshly transmitted token-bearing command expire.

Token state is bounded per association/principal and disappears when its association is destroyed. Unexpired bound records and required acceptance records must not be silently evicted. Tokens do not survive rotation, do not create durable operation identity, and do not guarantee when an accepted operation finishes; execution deadlines/interlocks remain application semantics. A valid token copied by a forwarding attacker is unusable for a new command without the traffic key. There is no separate timestamp/deadline wire extension in SEC-1.

Freshness feasibility concerns the remaining grant lifetime up to final admission of a new command, including grant-delivery age, sender queueing, fragment/repair scheduling and receive validation. A deployment claiming bounded fresh completion must validate that entire acceptance bound against its granted lifetime; a slow path may instead produce the explicit expiry/failure outcome above. Comparing only `send_horizon` with 60000 ms is neither sufficient nor necessary: receipt recovery for an already accepted identity may outlast the lease. Do not renew or substitute a token on retries of the same logical message; its authenticated metadata remains immutable.

## S8. Limits, reboot, rotation and revocation

Abort-first applies only to the bootstrap attempt boundary in S3.1. Protected records, including FINISH/READY, use S5/S6 and the cumulative verification limit below: an isolated bad tag does not automatically abort the handshake/association, install replay state or revoke trust. Confirmation timeout ends the candidate traffic attempt under its original limits; already committed credentials survive. No malformed handshake may tear down another active association, and failure-driven establishment remains subject to S3's separate scheduler and episode budgets.

Each sending direction MUST stop encrypting and establish a fresh association before any of these limits: 2^24 protected frames, 2^30 total plaintext bytes, or the configured absolute association lifetime. Defaults: lifetime 24 hours of monotonic elapsed time, W=1024; a deployment may choose a shorter lifetime or explicitly document a longer bounded sleeping-node lifetime, but cannot increase the frame/byte limits. Count confirmation, control, empty ACKs and retries. Cipher 1 and 2 use the same conservative operational limits. Gaps from abandoned PN allocation count toward the frame allocation limit. PN therefore remains below 2^24 despite its ULEB64 wire capacity.

At each endpoint the association lifetime starts at its Noise Split event, including any later wait for pairing approval or confirmation. An endpoint receiver rejects PN>=2^24 and stops accepting under an expired association; it also bounds the sum of newly authenticated plaintext bytes it receives to 2^30. Packet losses do not relieve the sender's stricter obligation to count every encryption. Peer clocks need not agree: an earlier local expiry can cause bounded delivery failure, never acceptance past that endpoint's limit.

Rate-limit tag failures and bootstrap work per local ingress and globally. The manifest MUST set a positive integer maximum of at most 2^16 (65,536) actual failed AEAD verifications per receive direction of an association. This is a hard ceiling, configurable downward only. Count cumulatively from candidate traffic-key installation, including confirmation and draining traffic; successful packets, duplicate input, timers and key-state transitions MUST NOT reset the count. A cheap structural/replay discard without an AEAD call does not increment it. Serialize verification or atomically reserve in-flight slots so `failed_verifications + reserved_verifications <= configured_limit`; release each slot on completion, converting it to a failure count only on authentication failure; close the association locally when the failure count reaches it, discard in-flight results after closure, and require fresh establishment. Only fresh traffic keys start a new counter. This deliberate denial-of-service tradeoff limits forgery work; it is not evidence that the peer misbehaved. Do not ban a credential based solely on unauthenticated failures. Apply cheap structural and replay checks before expensive cryptography and do not amplify invalid traffic with responses.

Traffic keys, send counters, replay windows and association epochs form one volatile state unit. On reboot, context loss, counter uncertainty, snapshot rollback or an ordinary reconnect that cannot guarantee preservation of that entire unit, erase the association and establish fresh keys. Never reload old traffic keys with reset counters or empty replay windows. Device credentials/pins may persist; traffic associations may not be restored from disk/flash in SEC-1. Retained-memory sleep is allowed only if the full unit and trusted elapsed-time accounting remain intact; otherwise wake requires a fresh handshake.

No per-packet NVS write is required by this design. Its cost is a fresh authenticated handshake after loss of volatile state and the need for usable boot entropy. If the return path is unavailable after such loss, secure sending fails locally instead of using an old key, weakening replay protection or falling back to plaintext.

Rotation creates a new attempt, fresh ephemeral keys, new receive CIDs while overlapping, new h/epochs and PN=0 under new traffic keys. Choose one active association for new messages. Existing messages/results may drain on the old one only within its original lifetime/limits and an explicitly bounded drain deadline. If those limits cannot cover the remaining retry/result horizon, report unknown/canceled locally and use application operation lookup rather than re-executing with a new identity. Do not reset old lifetimes on rotation.

A peer's restart does not itself notify the surviving endpoint or erase that endpoint's old association. The manifest must state per-pair pending/active/draining limits and the local admission/replacement policy for a freshly authenticated attempt while old local state remains, including the full-capacity outcome. Same-principal authentication does not transfer old receipts, operations or tokens into the new association, and attempt completion alone does not authorize eviction under S3.1. A deployment without overlap/replacement capacity may refuse the new attempt until local policy releases old state; it must not claim immediate peer-restart recovery. This clarification does not mandate automatic draining or a new remote close operation.

Revocation is a trusted local/provisioning action. Remove the credential authorization and immediately destroy pending/active/draining associations derived from it, their queued protected sends and tokens. Report unresolved operations as unknown. A remote unauthenticated 'revoke', 'close' or 'key expired' packet cannot change trusted state. Credential replacement/pin reset requires the same trusted administrative or out-of-band authority as enrollment. Wire credential-management commands are not allocated by SEC-1.

## S9. Gateway behavior and deployment requirements

A transparent gateway preserves protected payload/tag, association selectors and all immutable header bytes; it may decrement TTL and change the outer binding. It cannot insert CONTEXT/ROUTE or translate namespace IDs inside a protected frame. Origins must supply path-required metadata before protection. A lower binding may segment and reconstruct the complete frame under its specified contract. Smaller MTU without that mechanism produces a local failure, not transparent re-fragmentation or decryption.

A gateway that decrypts, translates a schema, changes endpoint identity or re-fragments the logical message is a terminating application endpoint. Such a deployment has two separately secured associations and cannot claim endpoint-to-endpoint secrecy from that gateway. SEC-1 does not require such termination to cross transports.

For each enabled service, configure plaintext/external-binding/SEC-1 requirements explicitly. A peer timeout, handshake failure, unsupported cipher, lost CID or revoked credential MUST NOT relax that policy. Bootstrap HELLO is the narrow plaintext exception for establishing SEC-1, not a channel for executing application commands or changing security policy. DMP SECURITY=0 carried over an authenticated external binding is still distinguishable from SEC-1 in the local API and conformance claim.

Required deployment data: manifest bytes/digest; allowed modes/ciphers and trust records; explicit control/application service map; bootstrap path/MTU/fragment and pending quotas; pairing/handshake/confirmation deadlines and retries; association limits/replay window; ACLs/freshness policies/token quotas; restart/sleep entropy and volatile-state guarantees; rotation/drain behavior; ingress verification limits; and any required authenticated hop binding. Unsupported group delivery and offline association restoration must be reported as unsupported, never emulated silently.

Enrollment data also specifies the authenticated provisioning/QR path and verification at both endpoints, concurrent-attempt UI binding, persistent credential transaction and reset/revocation authority. Resource configuration includes all §S3.2 budgets and main-specification §18.1 progress reservations. Profile/manifest agreement is explicit; changing these requirements does not permit silent fallback to an older policy.

## S10. Conformance vectors and fault scenarios

The companion [JSON vectors](DMP_v2_Security_Test_Vectors.json) contain deterministic test-only credentials/ephemeral values, prologues, Noise flights, final hashes, split keys, epochs, protected frames, nonces/AAD and expected mutation results for both modes/ciphers. All embedded keys are public fixtures and MUST NOT be used on devices. A production implementation should consume the JSON independently.

The revision-10 fixture manifest explicitly selects main=10, sec1=5 and abort-first. Its exact bytes differ from the revision-9 fixture, so PROFILE_HASH/transcripts and dependent protected bytes are regenerated; bootstrap layouts and cryptographic algorithms did not change. These fixtures do not execute abort-first transitions. Required failure/lifecycle scenarios below need real endpoint/provider tests, and optional AESGCM vectors do not declare support in every build.

To verify the existing vectors, run the [Node verifier](../dev/dmp_verify_security_vectors.cjs) from the repository root. To regenerate them, first obtain the public Cacophony fixture identified by URL and SHA-256 in the JSON's `upstream_validation`, then run the [Python generator](../dev/dmp_generate_security_vectors.py):

```text
node dev/dmp_verify_security_vectors.cjs
python dev/dmp_generate_security_vectors.py --upstream <path-to-cacophony-fixture>
node dev/dmp_verify_security_vectors.cjs
```

The generator requires Python with `cryptography`; the verifier uses Node's built-in `crypto`. Generation checks the selected upstream Noise vectors before rewriting the DMP JSON. These tools are test utilities, not production protocol implementations.

Required scenarios in addition to byte-vector agreement:

1. Wrong PSK, wrong pinned key, unknown manifest, altered peer IDs/mode/cipher/CID/prologue and incomplete out-of-band verification do not activate an association.
2. Lost/duplicate/out-of-order Noise flights, simultaneous attempts, exhausted pending quotas, fragment conflicts, pairing expiry and lost FINISH/READY remain bounded and do not reset existing live associations.
3. No plaintext downgrade; forged ACK/RSP/ERR cannot complete a protected exchange; control-service permission does not grant actuator permission.
4. Exact protected duplicate is dropped; fresh-PN logical retry after lost ACK reaches deduplication and produces a fresh-PN receipt without another execution.
5. Invalid-tag high PN does not advance the window; valid out-of-order packets work within W; same-PN concurrent arrivals accept once; lower-than-window traffic drops.
6. Authenticated fragments reorder and retry, but cross-association fragments and conflicting slices never assemble. Rate-limited provisional relay state is not authenticated endpoint state.
7. TTL-only mutation retains endpoint AEAD validity; changes to destination, SEQ, service, descriptor, unknown extension, CID, PN, payload or tag fail or are rejected by association binding.
8. Reboot destroys traffic context; captured old bootstrap cannot restore the old keys; old data after CID reuse fails; sleeping-state loss requires a handshake.
9. Rotation drains old work only within bounds; key-limit exhaustion and revocation stop new encryption; counter allocation is atomic across services.
10. Freshness grants do not extend on duplicate control requests; retained results retry within their original budget, and requests duplicated after result release receive only ACK while acceptance state remains. Cover an unexpired token after result release and an expired token while a result remains retained. No duplicate reconstructs a released result or creates a new token. Expired/bound tokens reject new commands, fragment completion rechecks expiry and tokens cannot cross associations.
11. Multi-transport forwarding preserves the end-to-end protected object or reports MTU/context failure; a terminating gateway is never reported as transparent.
12. PN varint boundaries change only permitted protection/derived header bytes. Fixed slices still fit the reserved maximum header/MTU; HDR_LEN overflow is rejected before a transfer starts.
13. Rotating forged origin/attempt/hint values, tiny-packet floods, fragmented bootstrap floods and duplicate valid flights stay within global/ingress memory, CPU and response budgets; admitted associations retain configured progress opportunities.
14. QR verification of one endpoint alone cannot activate mutual trust; swapped/expired approvals, wrong physical-device keys and uncommitted enrollment cannot install or replace authorized pins. Drop FINISH/READY and restart each endpoint immediately before and after credential commit: only committed credentials survive, traffic state is discarded on loss, and the UI distinguishes enrolled from connected. One endpoint's commit does not imply the other's commit.
15. Admission failure and borrowed-buffer cancellation do not cause nonce reuse, mutation of an in-flight frame, secret-buffer premature release or unauthenticated teardown of another association.
16. Compact replies resolve only through the receiving endpoint's local sending identity on the authenticated association; reused CID/context slots, wrong-service replies or noncanonical explicit default service, old full references and cross-association results cannot complete an exchange.
17. Continuations use the exact 18-byte version-2 prefix and original pending parameters. Wrong attempt ID, lost initial state, old full-prefix continuation and structural rejects cannot advance Noise or install trust. Inject changed flight-1 bytes/parameters into a pending XX attempt, then deliver its original valid continuation and FINISH: the conflicting duplicate must not abort/mutate that attempt, emit a response or renew its deadline. Repeat with fragmented duplicates; incomplete conflicts must not overwrite retained bytes or destroy admitted Noise state. Separately inject an admitted invalid expected flight 1/2/3 where applicable, invalid/low-order DH, or a cryptographically valid flight with wrong pin/invalid decrypted payload or zero CID: abort only that attempt, erase transient state and reject its late genuine continuation. A separately scheduled fresh attempt must complete with fresh keys/ID when allowed; no immediate automatic restart. Test simultaneous attempts, concurrent duplicate/expiry/cancel, scratch exhaustion before read, fatal errors after read/write, fallible entropy/storage and late asynchronous completion. Distinguish pre-read drop from post-read abort; no repeated encryption or leaked secrets. Test old flight-1 replay after removal, remote orphan capacity, rotating IDs, episode/backoff exhaustion and bounded later episode requests; work counters must not reset. Loss-only retry and active-association progress must remain bounded separately from injection-induced failure. Future preserve-state success-after-rejection tests are deferred, not current acceptance.
18. Fixed-stride protected reassembly validates geometry and exact slice sizes. After acceptance, a fresh-PN duplicate with matching metadata but changed payload never executes; its receipt still refers only to the original accepted identity. No full payload/per-fragment hash retention is required solely for that receipt.

Vector calculations exercise cryptographic/framing interoperability, not implementation timing, concurrency, entropy quality, physical storage or application durability. The public Cacophony fixture provenance/hash in the JSON records the independent Noise vectors used to check the generator. Python cryptography and Node crypto checks are separate runtime/API calculations, not a claim that their underlying crypto engines are independent. A release must also validate the relevant state-machine scenarios in independent implementations.

## S11. Primary references and rationale

- [Noise Protocol Framework, revision 34](https://noiseprotocol.org/noise.html): normative algorithms/protocol names, PSK/XX processing, Split, handshake hash and explicit-nonce transport support. DMP prologues, CIDs, confirmation, AEAD-associated headers and policies are defined by this annex.
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html): ChaCha20-Poly1305 primitive and test vectors.
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html): HKDF background; use the exact Noise processing, not an independently substituted KDF.
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147.html): TLS/DTLS alternatives for appropriate bindings.
- [RFC 9528](https://www.rfc-editor.org/rfc/rfc9528.html), [RFC 8613](https://www.rfc-editor.org/rfc/rfc8613.html): constrained key establishment and end-to-end field-protection design precedents.
- [RFC 9175](https://www.rfc-editor.org/rfc/rfc9175.html): request freshness as a property separate from authentication/replay rejection.
- [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html), [Matter security](https://docs.silabs.com/matter/2.2.0/matter-fundamentals-security/): PAKE commissioning precedents; no password mode is enabled by this annex.
- [WireGuard protocol](https://www.wireguard.com/protocol/): handshake resource protection and binding-specific cookie precedent; SEC-1 does not reuse its cookie packets.
- [RFC 9668](https://www.rfc-editor.org/rfc/rfc9668.html): combined EDHOC/OSCORE exchange as a comparison target, not permission to bypass SEC-1 authorization/confirmation.
