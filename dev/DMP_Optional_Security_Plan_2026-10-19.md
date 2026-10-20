# DMP optional security implementation plan

Date: 2026-10-19.

Status: decision-complete. The owner answered the contract questions in this chat. Sections 1–5 record the accepted scope and rules; there is no outstanding owner choice blocking their implementation. This document replaces the earlier planning-only draft.

This turn updates the plan, not the protocol implementation. A subsequent instruction to implement this plan authorizes its specification, configuration, library, example and test changes within the standalone repository. Do not request approval again for the decisions recorded here. Escalate a concrete contradiction, an inability to satisfy an accepted requirement or a proposed scope/security change; ordinary implementation choices remain the implementer's responsibility.

## 1. Accepted scope and owner decisions

The sole feature is optional use of the security that already exists: NONE or unchanged SEC-1. Both DIRECT-1 and RADIO-1, including SELECTIVE-32, must work with and without SEC-1.

| ID | Accepted decision | Development consequence |
|---|---|---|
| D1 | One security mode per endpoint instance | All peers of that instance use NONE or all use SEC-1. Separate instances may coexist on a device. Mixed-mode peers/services inside one instance are out of scope. |
| D2 | Fresh random 64-bit boot-epoch for NONE | No mandatory flash/NVS boot counter. The application/platform provides fallible randomness; initialization fails if it cannot supply an appropriate fresh value. |
| D3 | CRC32C in every emitted/accepted NONE Core frame | Requests, results, telemetry, ACK, ERR, fragments and FRAG_STATUS all require Core INTEGRITY=CRC32C. Stream R also keeps its existing mandatory envelope CRC. |
| D4 | Include SAMPLE-1 NONE support in this implementation | Telemetry, READ, STATUS, NO_SAMPLE, initialization, ordering and restart handling are included; opaque DATA alone is insufficient for acceptance. |
| D5 | Do not simplify or optimize SEC-1 in this task | No new cipher, symmetric handshake, resumption, persistent traffic keys, lean SEC-1 profile, reduced secure limits, algorithm-removal build or new sleep qualification project. |
| D6 | NONE peer capacity is limited by provisioned RAM, not a fixed small peer count | Remove the inherited four-peer cap for NONE throughout API/admission/schema/endpoint/peer tooling. A concrete instance still has finite, explicitly allocated capacities and quotas. |
| D7 | Application explicitly installs/replaces NONE peer contexts through API | No new plaintext bootstrap, implicit epoch adoption, auto-discovery or operator interaction requirement. Incoming packets never select a replacement epoch automatically. |

The D6 answer supersedes the suggested four-peer NONE option. Existing SEC-1 support and its currently qualified/configured limits, including the four-authenticated-peer scope, remain unchanged.

Security is configured before traffic. It is never inferred from packet contents, changed after timeout or negotiated downward. Optional security does not mean optional validation of an already selected secure exchange.

### Explicit non-goals

Do not implement or investigate resource-saving security alternatives in this development package. Earlier ideas about symmetric-only establishment, persistent pairwise contexts, native-stack security substitution, Ascon, EDHOC, smaller secure buffers and retained-sleep optimization are deferred to a separately requested future task. Their omission is an accepted scope boundary, not an unresolved prerequisite.

Do not change DTrack firmware, its embedded web UI or Flutter client, add dynamic routing/group security, provision credentials, flash/erase hardware, operate eFuses, deploy, publish, stage or commit without separate authorization.

## 2. Behavior and revision contract

### 2.1 Supported combinations

| Deployment | NONE | SEC-1 |
|---|---|---|
| DIRECT-1, retry-all | Required | Existing NNpsk0 and XX behavior retained |
| RADIO-1, SELECTIVE-32 for eligible fragmented reliable traffic | Required | Existing NNpsk0 and XX behavior retained |
| Separately identified radio retry-all comparison | Supported as its own comparison profile | Existing comparison preserved |
| Eligible SELECTIVE-32 workload on another explicitly identified path | No cryptographic dependency | Existing secure validation remains |

Family recovery choices remain unchanged: DIRECT-1 uses retry-all; RADIO-1 uses SELECTIVE-32 for eligible fragmented reliable messages and ordinary reliability for unfragmented messages. This does not make recovery dynamically selectable within an association or redefine radio retry-all as RADIO-1.

Plaintext mode intentionally has no DMP confidentiality, cryptographic sender authentication or secure freshness guarantee. Node IDs, correct CRC and matching local policy establish configured identity consistency, not proof of the remote principal. Plaintext spoofing is an absent guarantee, not a test expected to fail authentication.

### 2.2 One selected pre-release contract

Implement a single updated contract with these revision labels:

| Item | New selected value |
|---|---|
| DMP wire major | 2, unchanged |
| Core document revision | 11 |
| DIRECT-1 and RADIO-1 family revisions | 5 |
| SELECTIVE-32 revision | 2 |
| SAMPLE-1 application revision | 3 |
| Test manifest format | DMP-test-manifest/1.1 |
| SEC-1 cryptographic profile revision | 5, unchanged |
| SEC-1 BOOT_VERSION | 2, unchanged |

Update SEC-1's references to the matching Core revision without changing its algorithms, protected packet rules, handshake, credentials, authorization, replay, freshness, failure policy, limits or lifecycle. The change is making its selection optional elsewhere.

Keep exactly one manifest parser/schema contract. Do not add old/new branches, aliases or migration support. New manifest bytes receive new exact digests; never reinterpret an old PROFILE_HASH under new rules. Refresh only fixtures whose inputs actually change, through existing generators, and retain independent expected bytes.

The selected endpoint security policy is explicit and required. NONE must not require Noise mode, PSK/pins, pairing, handshake admission, CID, PN, replay window, rotation, verification budgets or crypto reservations. SEC-1 retains the existing required settings. Missing/conflicting policy, mode mismatch or an unsupported selected module is a setup failure, never an implicit NONE default.

For NONE, PROFILE_HASH is a reproducibility/configuration identifier. Without SEC-1 it is not an authenticated remote configuration claim.

## 3. NONE identity, context and integrity

### 3.1 Boot-epoch and message numbering

The platform/application supplies one fresh random 64-bit local epoch when a NONE endpoint instance starts. It is not a wall clock, authentication token, strictly increasing number or anti-replay mechanism. Its collision probability must be documented using the 64-bit random-identifier model; uniqueness is probabilistic, not guaranteed.

No persistent boot-epoch counter or per-message flash write is required. Randomness failure fails initialization before transmission. If a generated identity collides with locally retained state, fail that initialization rather than silently reusing it. Keep randomness outside libdmp through an explicit fallible port/caller input; NONE does not need the Noise provider merely to obtain an epoch.

Use a single monotonically allocated SEQ space for each local (namespace, node ID, epoch), across all peers, services and message types, including ACK and FRAG_STATUS. Do not start independent per-peer SEQ counters under the same origin/epoch: the message key does not include destination, so that would reuse logical identities. Endpoint instances that do not share a sequence allocator must have distinct independently selected epochs. Stop before wrap; creating a new local epoch requires explicit endpoint/context replacement with the normal outstanding-work termination rules.

SAMPLE-1's persistent sample_epoch is a different application invariant and is preserved. D2 does not remove storage requirements of an application that explicitly selects that example.

### 3.2 Explicit context installation and replacement

The application owns bounded context storage and supplies namespace, local/remote node IDs and epochs, service mapping, transport-peer mapping and lifetime. Peer installation is explicit; an unknown incoming origin cannot allocate unlimited trusted state or create an enrolled peer.

For NONE origin frames, always carry explicit CONTEXT. Carry ORIGIN_ID on direct frames without ROUTE; routed frames carry the existing origin in ROUTE=TO_NODE. Keep fixed configured mapping to the intended transport peer/destination and service. CRC validation and mapping checks precede receive/reassembly/reliability state changes.

The application obtains the remote epoch through its binding/provisioning/application integration and installs it through API. That integration is not a newly defined DMP wire handshake. Examples and runners must demonstrate context installation and replacement programmatically; no manual user action is required by the library.

An incoming different epoch is rejected for the current context and does not automatically replace it. Random epochs are unordered: a delayed old packet must not switch the endpoint back to a prior context.

On explicit peer replacement:

1. Stop admission of new work on the old context and invalidate its generation for future callbacks.
2. Stop/cancel queued transmissions using the existing ownership/completion contract; settle in-flight buffers before reuse.
3. End unresolved possibly-sent operations as unknown. Preserve the existing local-unsent distinction where no bytes could have reached the peer. Replacement does not prove remote cancellation.
4. Release/retire old work and identity records according to their retention/ownership rules. Late callbacks, replies and fragments cannot attach to a reused slot or the replacement context.
5. Install the replacement context. SAMPLE-1 consumers become unsynchronized and use a fresh designated READ.

Maintain the original full message-key semantics. SECURITY=0 uses full REPLY_TO (namespace, origin, epoch, SEQ), including direct ACK/RSP/ERR and selective feedback. SECURITY=1 retains the existing compact sequence-only reference, resolved only after authentication on the same association.

### 3.3 Core CRC policy

Every NONE Core frame requires the existing INTEGRITY descriptor selecting CRC32C and its four-byte trailer. Validate the Core CRC before a frame influences identity admission, feedback, reassembly, deduplication, acknowledgement or application delivery. Missing/wrong integrity selection or failed CRC is a local rejection/drop; it cannot terminate or acknowledge an active exchange.

This rule applies uniformly to packet bindings and Stream R. Stream R retains its outer CRC, COBS and synchronization behavior. There is intentional duplicated corruption detection in that binding; no binding-specific exemption replaces the accepted Core rule.

SEC-1 frames retain their current authentication tag and prohibition on simultaneous Core INTEGRITY. Do not add a Core CRC to protected records. A relay recomputes a plaintext Core CRC after an allowed TTL change and rebuilds the outer binding envelope, while preserving origin, message identity, fragment geometry and payload.

## 4. SELECTIVE-32 and application semantics

### 4.1 One recovery state machine

Keep TYPE 8, four-byte missing mask, 2–32 fragments, existing eligible types, same-service correlation, ordered feedback SEQ, final-fragment probes, receipt/result semantics and absolute budgets. TELEM, best-effort traffic, ACK and bootstrap remain excluded from selective recovery.

NONE FRAG_STATUS has SEQ, EXT/full REPLY_TO, explicit origin context and CRC32C. SECURITY, CID, PN and tag are absent. SEC-1 FRAG_STATUS retains its existing protected format, compact reference and authorization checks.

Validation order is structure, required corruption/authenticity checks, source/destination/context/service correlation and retained-state/resource checks before state mutation. In SEC-1 authentication still precedes trusted identity/feedback changes; in NONE CRC does not make the source authentic.

Preserve all independent safeguards: nonzero/not-all/in-range masks, matching active fragmented transfer, monotonically newer feedback snapshots, immutable geometry and slices, single pending repair burst, bounded feedback/probes/airtime, fixed expiry, tombstones and no terminal reopening. FRAG_STATUS is never ACKed, never application-delivered and never itself a success receipt. Do not extend lifetimes on duplicates or introduce automatic fallback to retry-all.

### 4.2 SAMPLE-1 is included now

Revise SAMPLE-1 and its adapters for both policies in this package; do not defer the example to DATA-only acceptance. Preserve its binary payloads, read-only operation semantics, persistent producer sample_epoch reservation, sample ordering, generation-safe synchronization, NO_SAMPLE behavior and initialization budgets.

In SEC-1, use the existing authenticated producer/association behavior. In NONE, producer and consumer roles refer to explicitly configured contexts, with no cryptographic source guarantee. Both modes use a fresh designated reliable READ after context selection/replacement. Unsolicited telemetry, old epochs, stale/superseded request results and old context generations cannot initialize or roll back the live sample.

A producer sample-epoch transition closes/invalidates its old bound contexts through the application owner. NONE then requires explicit context installation/rebinding and a new synchronization READ; SEC-1 keeps its current association lifecycle. Do not introduce an epoch-change opcode.

Acceptance ACK still means complete endpoint acceptance, not operation completion. Reliable results retain their own identity, retransmission and receipt. Timeout remains an unknown outcome; NONE does not gain exactly-once guarantees after state loss.

SEC-1 freshness tokens remain SEC-1-only. A plaintext profile cannot select that mechanism and claim authenticated freshness. Update NONE opaque test services that previously selected SEC-1 freshness accordingly, while leaving the secure service configuration unchanged.

## 5. Peer capacity, resource admission and unchanged SEC-1

### 5.1 RAM-bounded NONE peer count

NONE has no protocol-level small maximum such as 4, 16 or 64 peers. The application chooses a finite capacity by supplying storage and explicit aggregate/per-pool budgets. Practical representable sizes, checked arithmetic and available RAM still bound any instance; this is not an infinite-allocation claim.

Audit the inherited DMP_PROFILE_MAX_PEERS=4 restriction and all related code, public comments, schema array limits, parser assumptions, endpoint admission, handle/index validation, adapters, independent-peer input and test tooling. Make the four-peer rule SEC-1-specific rather than merely raising a global constant to another small value.

Support caller-provisioned peer tables and associated identity, Stream R decoder, application, sender, assembly and history storage. Loops, handle slots, multiplication and aggregate sizing must use checked types and actual supplied capacities. No receive/retry/encode hot-path heap allocation or automatic growth is introduced.

New peer/work admission fails explicitly when memory or its declared quota is exhausted; never evict accepted work, live contexts or required tombstones to make room. Unknown packets do not allocate peers. Existing peers and reserved ACK/control progress continue under the stated scheduler/transport availability assumptions.

Retain fairness across all admitted NONE peers; progress bounds are expressed in admitted/eligible peer count and successful poll submissions, not a fixed four-peer schedule or an invented wall-clock guarantee.

DIRECT-1 still represents a direct logical path. A physical endpoint can have many configured direct peer channels; this does not define UART multidrop arbitration. NONE radio peers retain static routes. Enlarging peer tables does not introduce discovery or a routing control plane.

### 5.2 Resource accounting and scope

Keep every profile's RAM/flash, frame, message, history, control and lifetime limits finite. For the existing direct/radio comparison instances retain their currently declared budgets and ceilings. Remove nonexistent security reservations from NONE; do not reserve fictitious handshakes just to match a secure resource template.

For higher-peer NONE host cases, supply explicit instance capacities and conservative byte totals based on actual storage/layouts. Validate the supplied RAM budget before admission. Do not describe those host sizing cases as MCU support or require a user to pick a universal target RAM number before implementation can begin.

Compare like-for-like NONE and SEC-1 cases without increasing a pre-existing profile's limits automatically. Any overrun fails that declared instance. Resource evidence reports actual layout/retained/scratch/stack/linked-size boundaries; a particular saving is not a feature acceptance target or a promise.

Preserve current SEC-1 algorithms, provisioning, NNpsk0/XX, randomness requirements, packet numbers/replay, ACL/freshness, handshake failure handling, lifetimes, rotation and restart behavior. Do not tune secure capacities, create lean-secure variants or change sleep guarantees.

A crypto-free NONE endpoint build/link is part of making security optional, not a rewrite of SEC-1: prove NONE has no required Noise/provider/credential/handshake dependency or security-state reservations. An existing secure build continues to include and exercise the same SEC-1 implementation. Its full feature set and behavior must not be weakened to make NONE pass.

## 6. Implementation map and milestones

Current checkout when decisions were closed: branch feat/initial-version, HEAD 0c7f2f3e37275b68e57b2454bf91aeb4e604d10f. The earlier draft referred to a historical dirty checkout. Recapture status/index/source ownership at implementation start and preserve concurrent work; an old plan snapshot is not permission to overwrite files.

| Milestone | Work | Completion evidence |
|---|---|---|
| M0 publish accepted contract | Apply sections 1–5 to normative docs and revision references; record decisions without requesting them again | Cross-document NONE/SEC-1 matrix, context/restart/CRC rules, capacity semantics and full acceptance map |
| M1 configuration | Update the single manifest contract/schema generator, validator, typed admission, application revision and generated schema copies | Valid NONE/SEC-1 corpus, explicit mismatches rejected, variable NONE peer capacities, exact new digests |
| M2 shared library | Conditional FRAG_STATUS codec/encoding, explicit NONE context integration, shared recovery, variable NONE capacity and shared origin SEQ allocation | Real NONE direct and routed selective endpoints; crypto-free NONE link; unchanged protected rejection behavior |
| M3 sample and independent peer | SAMPLE-1 NONE, adapters/runners, independent implementation from the revised written contract | Both directions of telemetry/read/status/result/init/context replacement across both families and security policies |
| M4 loss, isolation and capacity | Full fault scenarios and independent read-only review of final contract/diff | Correct bounded state, corruption rejection, retention, fairness and negative/domain-isolation matrix |
| M5 qualification | Targeted/full applicable host gates, size/map checks and S3/C3 compile/link using actual library sources | Exact commands/configuration/source snapshot and scoped results; existing physical acceptance boundaries retained |

M0 is specification work using already accepted decisions, not another owner-approval checkpoint. A future explicit instruction to implement this plan covers M0–M5's software work. Physical operations remain separately authorized; physical/runtime evidence must not be claimed from compilation. Do not begin a new sleep or security-optimization project under M5.

| Area | Required edits/audit |
|---|---|
| [Core specification](../docs/DMP_v2_Device_Messaging_Protocol_Specification.md), [profiles](../docs/DMP_v2_Deployment_Profiles.md), [selective annex](../docs/DMP_v2_Selective_Recovery.md) | Conditional protection, NONE CRC/explicit identity/full references, unchanged routing/recovery semantics |
| [SEC-1](../docs/DMP_v2_Security_Profile.md) | Refresh Core references only; preserve the cryptographic/security behavior |
| [Manifest contract](../docs/DMP_Test_Manifest_Contract.md), [schema generator](../profiles/schema/build_schema.py), [validator](../tools/validate_profile.py), deployment fixtures | Single 1.1 contract, conditional fields, no NONE four-peer cap, mode-correct frame sizing and resource arithmetic |
| [Codec](../src/core/codec.c), [identity](../src/identity/identity.c), [typed admission](../src/identity/profile_admit.c), [identity API](../include/dmp/identity.h) | CRC/type constraints, source/reference resolution, shared NONE SEQ, conditional peer limits |
| [Endpoint](../src/endpoint/endpoint.c), [endpoint API](../include/dmp/endpoint.h) | NONE setup/rebind/status composition, runtime-capacity tables, generation/ownership and mode isolation |
| [Reliability](../src/reliability/reliability.c), [reassembly](../src/reassembly/reassembly.c) | Shared bounded recovery/correlation over configured NONE or authenticated SEC-1 context |
| [SAMPLE-1 specification](../docs/DMP_v2_Reference_Application.md), [sample adapter](../src/application/sample1_endpoint.c), epoch-owner integration | Both protection policies; preserve persistent sample epochs and initialization semantics |
| [Independent peer](../tests/peer/dmp_peer/endpoint.py) and its frame/manifest/selective/sample modules | Update from written contracts and independent vectors, not copied C logic |
| [Build composition](../CMakeLists.txt), provider boundary | Optional linkage/invocation for NONE; retain the full existing secure build |
| README, work board, normative ledger, affected tests/tools | Update current scope, references and evidence only after actual checks; preserve historical evidence labels |

Generated schemas, manifest digests, public fixtures and resource reports must be regenerated with repository tooling when inputs change. Do not hand-edit generated outputs. New filenames/API shapes and other routine implementation details are not additional owner decisions when they satisfy this contract.

## 7. Required acceptance matrix

### Feature and identity

- DIRECT-1 NONE, DIRECT-1 SEC-1 NNpsk0 and XX; RADIO-1 SELECTIVE-32 for those same protection choices. Keep radio retry-all separately identified.
- SAMPLE-1 telemetry, READ, STATUS, NO_SAMPLE, synchronization, persistent sample-epoch transition and late results in both modes. Add eligible opaque fragmented REQ/results and generic DATA/EVENT tests so SAMPLE-1's small payloads do not stand in for selective recovery coverage.
- NONE epoch randomness failure, supplied-context mismatch, explicit replacement, local epoch/SEQ exhaustion, late callback generation reuse and peer restart. Repeated/numerically larger observed epochs never trigger implicit adoption.
- A single NONE origin/epoch issues unique increasing logical SEQ across several peers/services/control classes. Test that independent per-peer starting counters cannot duplicate the full message key.
- Full plaintext REPLY_TO versus compact protected REPLY_TO; wrong node/destination/epoch/service/direction; stale context; maximum ULEB widths, Core CRC overhead and return MTU. Expected bytes are independently calculated.

### Corruption, recovery and separation

- Every NONE message/control type requires correct Core CRC. Test missing/unsupported integrity, changed header/payload/trailer, every fragment and feedback. Verify a Stream R envelope with a valid outer CRC does not bypass an invalid inner Core CRC.
- Lost first/middle/last/all initial fragments; lost feedback/repair/final receipt; duplicates/reordering; invalid masks; stale/new feedback; competing repair input; terminal late status; assembly expiry and tombstone exhaustion.
- Preserve geometry, immutable slices, one pending repair burst, deadline ordering, absolute retention, control reserves and finite counters/airtime.
- A secure instance rejects plaintext ACK/RSP/ERR/FRAG_STATUS and never downgrades. NONE traffic and its retained decisions cannot affect a protected instance's replay, identity or accepted-message domain. NONE does not report a cryptographically authenticated sender.
- NONE does not call credential, Noise handshake, encryption/decryption, SEC-1 replay/rotation or freshness paths. Its independent boot-randomness input may be used. Secure vectors and all relevant existing security failure/lifecycle tests remain valid for the selected revised manifests.

### Peer capacity and resources

- Test NONE with one peer, at least five peers (to catch the old cap), and at least sixteen peers, with independent identity/context/sample/result histories and both direct/packet compositions where applicable.
- Use the same implementation with two different caller-provisioned capacities above four; do not pass by substituting a new fixed constant or a special test path.
- Exact-capacity admission, capacity-plus-one rejection, per-pool and aggregate exhaustion, arithmetic overflow and insufficient storage all fail without damaging admitted peers. Unknown frames cannot grow the peer table.
- Under an available accepting transport, all eligible admitted peers receive bounded polling opportunities; a busy/failing peer cannot corrupt another peer's completions or monopolize protected control reserves.
- Link a real NONE endpoint/sample workload without the provider/backend; inspect symbols/maps and actual reservations. Retain current SEC-1 peer/concurrency behavior and rerun its regressions.
- Report host capacities/layouts and S3/C3 compile/link separately from target runtime, physical radio and power-loss qualification. No new numeric MCU peer-count/energy claim follows from the host sixteen-peer case.

Use RBO for builds/tests according to AGENTS.md. Existing gates include profiles.contract, identity.context, identity.profile_admit, reliability.direct, recovery.frag_status, relevant core/endpoint/application/security tests and independent-peer suites. The fixture-only recovery test does not replace actual endpoint tests. Add new cases to real production-source targets, then run the affected integration gates. Preserve the owner-deferred ARM and physical gates; do not silently mark them passed.

## 8. Completion and handoff

The implementation is complete for this package only when the single selected contract, both security policies, NONE capacity semantics, SAMPLE-1, independent-peer checks, mode isolation and applicable software/build gates above are implemented and evidenced. Retain all unresolved physical acceptance as explicitly scoped qualification work; it does not become an invented protocol decision.

The implementer reports changed files, final behavior, actual validation commands/results, source/manifest/backend versions, linked and retained resource evidence, and any concrete failures. A failed requirement is not permission to weaken this plan. Preserve the Git index and unrelated work; commit/push/hardware/publication permissions remain separate.

The [Ukrainian explanation](DMP_Explained_UA.md) provides the reader background on current SEC-1 and distinguishes future security alternatives from current functionality. This accepted plan controls this development package: its narrower no-SEC-optimization scope supersedes the earlier draft's research/lean/sleep milestones.

No open protocol choices remain in this plan for the requested optional-security work. Future choices about new protected modes, persistent traffic state, security optimization, dynamic discovery or mixed-mode peers belong to separate work, not a repeated M0 question.

## Implementation status — 2026-10-19

- M0–M2 are complete on the repaired tree; see [`DMP_Optional_Security_Evidence_2026-10-19.md`](DMP_Optional_Security_Evidence_2026-10-19.md) for exact evidence, including 42/42 profile tests and 187/187 native CTests.
- M3–M4 remain partial: 453/453 non-skipped independent-peer tests pass, but one R7 cross-endpoint tombstone-pressure case remains unverified because the independent Python peer API cannot inject service-1 DATA for that case. It is not counted as passed.
- M5 remains partial: the latest attempted actual `espnow_dmp` S3/C3 application builds produced no observable compiler result or generated build tree, and RBO dispatch failed before execution because no agent was connected. Earlier shared-source smoke builds cover a smaller composition only. Physical module/runtime, radio, power-loss, MCU RAM peak and runtime flash qualification are explicitly deferred by the owner and are not blockers for this software stage.
- R1–R4 were rechecked against the current tree by an independent read-only review; no original finding reproduced. The remaining software gates above prevent claiming full plan completion.

- Continuation note: R4's generated hashes now have a compile-using regression with byte-exact manifest digest checks (profile suite 42/42). Full native CTest passed 187/187 and the full peer suite passed 453 tests with the single R7 skip. The embedded espnow_dmp app compile/link, R7 pool-pressure interop, and integrated SAMPLE-1 capacities 5/16 remain software-open; see the evidence continuation for exact commands and limits. Do not mark M3–M5 complete.
- Latest continuation: profile tests pass 43/43; current native build and full CTest pass 189/189; independent peer suite passes 453 with one R7 skip. Production adapter STATUS is tested before epoch activation (`ready=0`) and after activation (`ready=1`). M3/M4 remain partial because integrated SAMPLE-1 at capacities 5/16 across both families/framing modes and R7 pressure recovery remain open. Fresh EIM app-build invocations returned no output and produced no Ninja build tree; RBO dispatch failed before execution with `no_connected_agent`, so M5's app S3/C3 compile/link remains unverified. Prior shared-source smoke builds are not substitutes. Physical qualification remains owner-deferred.
- The latest targeted rerun now admits N real producer peers, activates N SAMPLE-1 records and completes STATUS/READ production-adapter round-trips for every peer at N=5 and N=16. The exchanges are sequential and use only the current direct packet test composition; overlapping isolation/replacement/fairness and DIRECT Stream R/RADIO packet composition remain open. Full native CTest and R7/app compile-link statuses are recorded in the evidence ledger; M3–M5 remain open.
- Latest requested recheck supersedes the earlier skip status: R4 hash-array compilation and exact digest comparison pass; full native CTest passes 189/189 and the independent peer suite passes 453/453 with no skips. The R7 pressure cell now passes through a separately budgeted exact-digest test manifest and real C/Python interop. SAMPLE-1 5/16 also verifies replacement of one peer while a different peer has a live accepted sender, but duplicate/late-result/history isolation and Stream R/RADIO compositions remain open. Actual espnow_dmp S3/C3 app compile/link remains unverified: RBO had no connected agent and local EIM emitted no build output or Ninja tree. See the newest evidence continuation; M3–M5 remain partial.
- Current final host rerun supersedes previous counts and sample wording: CTest 189/189 and peer suite 453/453 with 0 skips pass; profiles 43/43, R4 generated-hash C compile/exact bytes 1/1, and R7 pressure interop pass. 5/16 SAMPLE-1 now checks same-SEQ independence across peer identities, request replay without a second SAMPLE-1 dispatch, duplicate completed STATUS RSP suppression, stale STATUS RSP noncompletion while a READ is outstanding, subsequent READ completion/correlation, and retained accepted sender state across a different peer's context replacement. Cross-peer concurrent result-history isolation, concurrent SAMPLE-1 quota-progress, and SAMPLE-1 composition over DIRECT Stream R/RADIO remain open. Actual espnow_dmp application S3/C3 compile/link remains unverified because RBO capture reports `no_connected_agent` and local `eim run` exits without output or an application build tree. M3–M5 remain partial; physical qualification remains owner-deferred.

## Current execution status — 2026-10-20

This continuation supersedes earlier progress counts without changing the agreed requirements:

| Milestone | Status | Remaining software evidence |
|---|---|---|
| M0 | Complete | — |
| M1 | Complete | Profile suite 48/48; R1 route pair-sizing exact fit (83 bytes) and underflow (82 bytes) agree across validator, C harness and independent peer. |
| M2 | Complete for software gates | Native CTest 193/193 with real SEC-1 backend; F1/F3, mode isolation and control/integrity regressions included. |
| M3 | Complete for software acceptance | Production SAMPLE-1 NONE covers capacities 5/16 over DIRECT packet, DIRECT Stream R and routed RADIO packet. The S1 async replacement lifecycle now proves BUSY/revoke/fence while a borrowed callback and another peer's accepted result are live, then successful retry and generation reuse. Independent Python consumers exchange with one shared production C endpoint/history under the S3 interleaving. Full evidence and checks are in the latest evidence continuation. |
| M4 | Complete for software acceptance | Loss/corruption, control, NONE/SEC-1 isolation, capacity, fair progress and R7 pressure gates pass. S2 verifies actual quota refusal while preserving accepted work and progressing other peers and control traffic under BUSY; S3 verifies wrong-peer rejection, retained A result, newer publication/B request, no rollback and ACK releasing only B. Physical transport/runtime remains explicitly deferred. |
| M5 | Complete for software qualification | Local ESP-IDF v6.1 actual `tests/embedded/espnow_dmp` S3/C3 compile/link, map/symbol and static-size gates pass on the current S1 production-source snapshot. ELF/map hashes and exact size reports are in the latest evidence continuation. S3 reports 0 bytes remaining in its 16 KiB IRAM region; retain as a static resource caveat. Physical qualification remains owner-deferred and is not claimed. |

Exact final host commands, focused commit mapping, independent review result, and current M5 artifact hashes are in “Review9 software closure — 2026-10-20” in the evidence ledger. M3–M5 are complete for their stated software acceptance and qualification scope; host/compile success does not imply physical acceptance.


Latest evidence update (2026-10-20): see “Review9 software closure” in the evidence ledger for the current 193/193 native CTest, 454/454 independent Python peer suite with zero skips, and S3/C3 actual application builds on the S1 production-source snapshot. The independent shared-production-history test and read-only Review9 review are included. M3/M4 software acceptance is complete; no physical gate is claimed.


M5 update (2026-10-20): Windows EIM actual `tests/embedded/espnow_dmp` S3/C3 compile/link, map/symbol, and static size gates pass locally. Fresh size commands confirmed ESP-IDF 6.1 project generation and the target builds; the recorded artifact hashes are in the evidence ledger. S3's 16 KiB IRAM region reports zero free bytes. M3–M5 are complete for software acceptance and qualification; physical qualification remains owner-deferred.
