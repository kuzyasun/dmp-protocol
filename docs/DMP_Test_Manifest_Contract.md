# DMP test manifest contract 2

**Scope:** P02 configuration contract 2 for a two-endpoint host test deployment.
This selects a bounded subset of main document 10, SEC-1 revision 5,
SELECTIVE-32 revision 1 and SAMPLE-1 revision 2. It changes no DMP wire rule.
The [JSON Schema](../profiles/schema/manifest-v2.schema.json) supplies exact
field names, types, required fields, enums and numerical bounds. This document
supplies semantics and cross-field constraints. Neither part alone is sufficient.
P03 separately freezes complete deployment instances and their evidence mapping.

## Bytes, parsing and digest

Input is one UTF-8 JSON object, at most 262144 bytes, without a BOM. Whitespace
and object member order are permitted and significant to the digest. Duplicate
members, including escape-equivalent names, unknown members at any depth,
unpaired Unicode surrogates, floating-point/exponent numbers, NaN, Infinity,
trailing values and non-JSON syntax are rejected. Integers use JSON integer
syntax and at most 20 digits; booleans are not integers. Maximum nesting is 24
containers. No comments, defaults, environment substitutions or secret values.
Arrays are ordered; uniqueness constraints below apply after parsing.

`PROFILE_HASH = SHA256(all original file bytes)`, including any trailing newline.
No canonicalization, newline conversion, field exclusion or embedded digest.
The manifest contains no PSK/private key. Provisioning supplies credentials
separately. The offline tool prints the digest and derived bounds; an optional
expected digest must match exactly. Passing without an expected digest validates
the configuration only; it does not prove provisioning agreement. Peers receive
the same original bytes, schema and this document, and independently implement
parsing/interpretation. Sharing the primary validator implementation is excluded.

## Selected model and units

All durations are integer **milliseconds** on a monotonic clock. All lengths and
memory charges are **bytes**; counts are integral finite admission caps. Zero is
allowed only where the schema says so. Arithmetic in this contract is exact,
without machine-integer wrap. A runtime must reject unrepresentable values.

The contract admits exactly one peer pair and two application services, 1 and 2.
Node IDs are distinct ULEB32 values; the namespace is ULEB32. Node order determines
only stable configuration order. Exactly one node is the SAMPLE-1 producer.
SEC-1 supplies association epochs; restart discards volatile traffic state and
requires a fresh handshake. SAMPLE-1 separately persists its never-reused u64
sample epoch. No state is restored from old traffic counters.

Supported profile identities are `DMP-reference/DIRECT-1/4`,
`DMP-reference/RADIO-1/4`, and `DMP-test/TEST-RADIO-RETRY-ALL/1`.
DIRECT uses `DMP-test/SIM-STREAM-R/1`, no ROUTE, association context, TTL=0 and
no relays. Radio uses `DMP-test/SIM-PACKET/1`, static unicast TO_NODE and
origin-supplied CONTEXT even when no relay is present. TTL covers every relay,
at most four. There is no lower segmentation, dynamic routing, identity/security
termination or automatic MTU adaptation. Route/MTU failure terminates an affected
transfer with its possibly unknown application outcome. Physical transports and
mixed bindings need a later contract revision; these IDs claim neither support.

These simulated bindings supply one core frame per packet or the exact main
section 15 Stream R envelope. `forward_mtu`/`return_mtu` are minimum core-frame
capacities over every hop, in each direction; they are not physical packet sizes.
`encoded_mtu` bounds one encoded binding frame. `frame_tx_ms` bounds one complete
origin transmission at either MTU. Bootstrap selects core CRC32C in both bindings.
Protected traffic uses only SEC-1's full 16-byte tag; Stream R always adds its
independent envelope CRC. No core CRC is combined with SECURITY.

SIM-STREAM-R/1 fixes its partial-candidate timeout to
`frame_tx_ms + max(forward_delay_ms,return_delay_ms) + record_margin_ms`.
This is an absolute timer from the first nonzero candidate byte, never renewed
by later bytes. Already-available bytes, including a delimiter, are processed
before expiry at the same timestamp. Expiry discards the candidate and ignores
input through the next delimiter, as do oversized/invalid candidates. This
derived bound covers a complete admitted frame traversal plus positive margin;
it is not the application reassembly timer. Empty delimiters start no timer.

On coordinated open/reset the receiver is ready before the sender emits its
initial empty synchronization delimiter. This binding does not prefix every
frame or signal an independent receive reset to the peer. An independently
reset receiver discards through a delimiter and may lose the in-flight or next
frame. Reliable traffic can recover only within its existing finite retry
envelope; best-effort loss is accepted. Reset never renews a transfer deadline.

The simulator uses a **single serialized burst gate across the pair**, including
both services, directions and bootstrap. Competing bursts are queued only if their
declared reservations/deadlines remain possible, otherwise refused. Each static
superframe of `return_slot_period_ms` reserves one complete source-to-endpoint
path traversal followed by two complete reverse control traversals. Let
`L=max(forward_delay,return_delay)` and `T=frame_tx_ms+L`. Require return width
`W>=2T` and `period-W>=T`; this covers relay transmissions and endpoint work, not
just origin airtime. Source frame starts are on period boundaries; a burst of N
frames reserves N periods. This conservative half-duplex schedule admits at most
one data frame per period. The initial source slot is time zero of the transfer;
source burst starts and handshake retry intervals are whole periods. Queue bound
covers at least one period for alignment. Return period+width is bounded by both
feedback and receipt delay. These are admitted reservations for this pair,
including control fairness, with no unbounded other transmitters. Directional delivery
delays include all downstream queues, relays, reconstruction and authenticated
validation. Binding implementations must meet these promises; the offline tool
cannot measure or prove a physical delay. Borrowed TX storage is immutable until
one generation-tagged terminal event; cancel/disconnect must settle submissions.
Rejected submission retains caller ownership. Copy mode must finish the copy
before returning. Synchronous completion is explicitly configured.

## Services and security

Both services require SEC-1 cipher 1. Recovery is fixed in both directions:
DIRECT and the separately identified test retry-all family use `retry-all`;
RADIO-1 uses `selective-32`. All reliable results/feedback use the request's
service. Default service 1 is omitted, service 2 explicit. PAYLOAD_DESC is omitted
because the schema is fixed by the manifest. Security service 0 remains explicit
and independent, and is not an application service entry.

Service 1 is unchanged SAMPLE-1/2: producer ACL `[produce,result]`, consumer
`[read,status]`; READ/STATUS requests at most 1 byte, results at most 17 bytes,
TELEM 16 bytes. Fixed lengths/status in `sample` are assertions, not overrides.
The consumer starts unsynchronized and uses only a correlated current-generation
READ result; telemetry cannot establish an epoch. Initialization attempts, retry
interval and absolute deadline are finite. Service 1 does not require freshness.

Service 2 is test-only `DMP-test/OPAQUE-1/1`: both nodes have `[data,result]` ACL;
reliable DATA/REQ carry arbitrary opaque fixture bytes, RSP returns opaque fixture
bytes within the configured request/result maxima. Its handler only records a
test acceptance/result, has no external side effect and is idempotent. It adds no
production opcode. Best-effort fragmentation is not enabled. Durable operations,
alternative codecs/schemas/ACL forms require a separately specified contract.

NNpsk0 selects individually provisioned pairwise PSK; XX selects authenticated
OOB verification. No secrets or unauthenticated trust fallback are represented.
Pin/ACL changes require owner authority and atomic commit. Pending, active and
draining limits are **per pair**, not a combined ambiguous total. Crypto slots
are independent and do not exceed pending slots. Full capacity rejects new state;
a restarted peer never implicitly evicts live state. Drain fits within the
original finite association lifetime; encryption, plaintext and failed-AEAD caps
are cumulative per direction and never raised by success/retry/rotation policy.
Replay window is a supported power of two from 64 through 1024.

Bootstrap preauth slots/bytes cover each admitted incomplete 120-byte flight.
Attempt deadline, pairing timeout, episode attempts/deadline, crypto and traffic
budgets, restart backoff, later-episode and ingress rate windows are independent
admission bounds. Episode budget must cover the configured attempts, including
backoffs; it is never refreshed by an attempt. A later episode consumes the global
window budget. Remote orphan capacity still follows the remote attempt deadline;
this contract promises no successful establishment while it is occupied.

`flight_attempts` includes the first send of each cached bootstrap flight;
`flight_retry_ms` is its start-to-start interval. Duplicate-triggered responses
consume `duplicate_responses_per_attempt` and use the same serialized flight
slots, never an immediate unbudgeted response. `confirmation_attempts` includes
initial FINISH/READY, with `confirmation_timeout_ms` as the reserved roundtrip
interval. All use the common binding gate but **separate establishment counters**.
Let `V=bootstrap_N*period`, `L=max(F,R)`, and `K` be 2 flights for NNpsk0 or 3
for XX. Require `flight_retry >= 2(V+L)+crypto_per_attempt+pairing_timeout` and
`confirmation_timeout >= 2(period+L)+receipt_delay`, both multiples of period.
For XX, add `V+L` to that confirmation bound and reserve one extra complete
cached flight-3 copy in every confirmation slot, including the initial one.
Conservatively reserve each of the `K*flight_attempts+duplicate_responses` full
flight slots, then `confirmation_attempts` complete confirmation intervals,
plus pairing timeout and crypto work, within `attempt_ms`.

Attempt wire budget covers
`((K*flight_attempts+duplicate_responses+X)*bootstrap_N+2*confirmation_attempts)`
where X=confirmation_attempts for XX and zero for NNpsk0. Response count likewise
includes X extra flight responses; the XX confirmation interval reserves their
transmission time. This conservative extra initial copy is budget, not a command
to transmit a redundant copy after success. The expression counts
frames at the maximum encoded-frame capacity (both origins combined). Episode
traffic covers all episode attempts. `response_window_ms <= attempt_ms`, with
responses/bytes per window sufficient for the whole selected attempt schedule;
these are ingress/global response caps, not reset by a new attempt. Ingress packet
budget admits at least that complete frame envelope. Actual emitted work still
consumes every per-attempt, episode and global/rate counter; no counter grants a
budget bypass. Confirmation's reserve does not imply its P14 implementation.

## Derived constraints

The validator reports stable error categories below; it may stop at the first
error. The invalid corpus avoids relying on order when multiple categories fail.

| Code | Required check |
|---|---|
| `encoding` / `json` / `schema` | Byte, syntax and closed structural contract above |
| `digest` | Supplied expected SHA256 equals exact original bytes |
| `profile` | Exact family/revision/binding/topology/recovery combination |
| `identity` / `service` | Distinct nodes/relays, exact service identities, canonical service addressing, same-service replies, ACL and SAMPLE semantics |
| `security` | Mode/credential match, crypto/pending admission, association/drain limits, finite establishment and global budgets |
| `geometry` | `0 < chunk < message`; `N=ceil(message/chunk)` within family/manifest ceiling; separate bootstrap `ceil(120/bootstrap_chunk)` within its own quota |
| `mtu` | Complete worst headers/trailers/payloads fit both path directions and HDR_LEN <=255; return control and bootstrap fit too |
| `schedule` | Burst, source reservations, return slots and total traffic/airtime fit finite caps |
| `timing` | Response, assembly, all history/result/correlation lifetimes and freshness feasibility below |
| `relay` | Each relay's arrival interval, cooldown, duplicate, count, expiry and airtime constraints below |
| `resources` | Finite role/region/component totals and admitted per-pool capacities below |

### Frame bound

Use maximum SEQ and receive CID widths (5 bytes each), **PN width 4**, and actual
configured identity/service ULEB widths. Base protected header is
`2 + OPTIONS(1) + SEQ(5) + cipher(1) + CID(5) + PN(4)`.
Routed headers add `1+width(source)+width(destination)` and a CONTEXT TLV
`2+width(namespace)+8`. Each extension in this subset has one-byte tag and length.
For a conservative application bound add REPLY_TO `(2+5)`, STATUS `(2+5)`,
nondefault SERVICE `(2+width(service))`, and FRESHNESS `(2+16)` when enabled.
These simultaneous reserves may exceed any single emitted message's needs;
they never authorize forbidden extension combinations.
FRAG adds `width(N-1)+width(chunk)+width(message)`. Payload bound is chunk,
tag 16. Check unfragmented SAMPLE-1 and security control (up to 21 bytes),
protected status (4 bytes, REPLY_TO and service but no STATUS/FRESHNESS), ACK,
FINISH/READY, and bootstrap separately. Bootstrap header has SEQ width 1,
CONTEXT, ROUTE or ORIGIN_ID, its own FRAG, CRC32C descriptor 1 and trailer 4.
Do not use application fragment quota for bootstrap.

For Stream R, let `n=maximum_core_frame+4`; maximum encoded size is
`n+floor(n/254)+2`, including the canonical final code block and delimiter.
For packet, encoded size equals the core size. Check the full declared core MTU,
not just the currently exercised payload. The future codec still emits minimal
canonical integers and checks actual outgoing sizes.

### Timing and history

Write `B=burst_span`, `F=forward_delay`, `R=return_delay`, `G=feedback_guard`,
`D=feedback_delay`, `H=send_horizon`, `M=record_margin`, `Q=queue`, all in ms.
The symmetric two-way workload uses the **larger** of F and R as `L` for its
ordinary receipt/retention/freshness checks. SELECTIVE-32 response timeout is at
least `max(2F+B+G+D+R, 2R+B+G+D+F, F+receipt_delay+R)`.
Retry-all still meets the final-receipt expression. Available valid terminal or
feedback events are processed before an equal timeout. Each source reservation
starts no earlier than prior start+B+response_timeout+jitter. Initial start is
zero; count equals max_bursts and final start+B <= H. Unused slots are not extra
bursts. A probe consumes one burst; max_probes <= max_bursts-1; max_status covers
one opportunity per burst. Retry-all declares zero probes/status.

`B >= max(N,bootstrap_N)*return_slot_period_ms`; receipt count covers every burst, and
origin/receiver airtime budget covers both application and worst complete
bootstrap bursts plus status and receipts. Bootstrap count allowance is
conservative; bootstrap still uses its own establishment retry/budget engine.
`collect >= H+L`; `assembly >= max(H+L,collect)+M`, inactivity disabled.
Manifest contract 2 also requires a per-peer expiry-tombstone count and a
matching endpoint `assembly_tombstone` resource charge. The admitted count is
bounded by that charge. A new assembly reserves its future tombstone before
the first accepted slice; expiry preserves the message/context key until the
identity context is retired. Tombstones are not evicted to admit later work.
Dedup/rejection/tombstone durations, from first admission/decision, are at least
`H+Q+F+R+M`. This deliberately covers R4's first-admission expiry bound as well
as delayed duplicates; no eviction or renewal is permitted within that bound.

`result_deadline >= Q+H+L+max_processing+Q+H+L+receipt_delay`, measured from
local request admission. `result_cache >= H+Q+F+R+M` from result creation;
`correlation >= result_deadline+late_result+M` from local request admission.
`tombstone >= correlation` conservatively retains terminal correlation too.
Association lifetime covers the complete correlation interval plus initial
queueing; admission near association expiry must still check remaining life.
SAMPLE init deadline covers all attempt result deadlines plus intervening retry
intervals. These conservative bounds are test-profile choices, not new universal
timer equations or proof of delivery in arbitrary loss.

Late-result policy is fixed: retain correlation until its absolute deadline;
authenticate/validate and ACK a matching reliable late result without reopening
the request or invoking the application result callback again. Emit a diagnostic
late-result event without payload. After correlation/tombstone expiry drop an
unmatched result; never deliver it as an unsolicited new result.

If freshness is enabled, `0 < lease <=60000` and
`grant_delivery_age+Q+H+L <= lease`. This covers **final new-command admission**;
accepted duplicates may still obtain receipts afterward. If disabled, lease and
grant age are zero. Sender must verify the actual granted remaining lifetime,
not assume the maximum requested grant. Partial-message reception is no pass.

When enabled, both endpoint node IDs appear exactly once in `grant_nodes`:
service-0 lease requests are authorized only for their already authorized fresh
service-2 operations. Reserve `grant_requests_per_pair` before accepting a grant
request; require `0 < grant_requests <= tokens_per_association <= tokens_per_principal`.
Enforce both token quotas across live/draining associations without eviction.
`token_record_ms >= lease_ms` from issuance; `grant_result_ms >= H+Q+F+R+M` from
grant-result creation. Grant result/correlation/accepted-rejected history follows
the same reliable control lifetime rules, independently of application slots.
Tokens are opaque 16-byte values bound to association/principal/service and never
renewed by duplicate traffic. Expiry/association teardown removes their authority.
Disabled freshness has empty grant_nodes and all its numeric fields zero.

### Relay reservation envelope

Relays appear in forward order and reverse order on the return path; no other
routes are admitted. An arrival offset is measured from the corresponding
origin frame's **transmission completion**, with min/max bounds. Each relay
transmits within its `frame_tx_ms`. At each hop reserve serial transmission
of every admitted lower-binding copy
after the last possible arrival. Its end is `arrival_max+duplicate_tail+
(1+lower_duplicates)*frame_tx`. The next hop's minimum follows that end and the
last hop end must fit the endpoint delivery bound. Duplicate bounds include all
copies arriving at that hop (including inherited copies); the test injector must
respect them. This is
a deliberately conservative, serial reserved schedule.

For every potential fragment/key in every reserved burst, arrival interval is
`[start+arrival_min, start+B+arrival_max]` (the lower bound conservatively also
covers a zero-duration origin transmission). Each key may have at most
`lower_duplicates` extra lower-binding copies per burst, no later than
`duplicate_tail_ms` after the upper arrival bound. Those copies may consume
forwarding slots. Cooldown starts at **last forward completion** in this model.
For every consecutive source reservation and each relay/direction require
`next_start+min >= prev_start+B+max+duplicate_tail+(1+lower_duplicates)*frame_tx+cooldown`.
This uses each relay's interval, not just source spacing.

Reserve `max_bursts*(1+lower_duplicates)` forwards per application-fragment key,
and expiry from first key admission through last possible arrival/duplicate and
forward completion (positive record margin included). Count covers the initial
burst exactly once. Treat every repair as potentially containing every fragment;
this over-approximation also covers probes. Newly identified feedback/receipts
have separate keys but consume the common airtime budget. Per-origin and global
relay budgets reserve the complete two-direction transfer envelope, including
status/receipt and bootstrap traffic, multiplied by duplicate copies and admitted
service concurrency. Extra lower-binding traffic is outside this claimed envelope
and may exhaust forwarding budgets, causing bounded failure rather than delivery.

Also check cached-bootstrap retries and confirmation intervals at each relay:
the same cooldown inequality uses their respective full-flight/one-period spans.
Per-key count covers the greater of application bursts, flight attempts plus all
duplicate responses plus X, and confirmation attempts. XX confirmation cooldown
uses a whole cached-flight span. Relay expiry covers the complete
establishment duration plus arrival uncertainty/copies/margin. Airtime reserves
the full establishment frame envelope for every episode attempt in addition to
both-direction application schedules; cache capacity includes those identities.

Public PN filtering is selected explicitly per relay: reject PN>=2^24, or forward
a structurally valid descriptor. This does not alter mandatory endpoint rejection,
authenticate the origin or create trusted replay/association state.

### Resource envelope

Each role has a finite linked-flash ceiling/reservation and named RAM regions.
There must be exactly one endpoint resource template (applied independently to
both endpoints), and one relay template iff relays exist (applied to each relay).
Each charge identifies component, region, slot count and bytes per slot. Sum all
`count*bytes_each` per region, without hidden sharing, against its limit. Every
listed component must occur exactly once per role. No subtraction for mutually
exclusive paths: application, bootstrap, rotation, queues, control, stacks and
adapter/DMA allocations are charged simultaneously. Flash reservation cannot
exceed the role limit. Unimplemented modules use explicit nonzero design reserves;
they are not measured allocations. Region names and target names identify these
declared budgets, not proof of MCU placement or memory capabilities.

Counts must cover: provider/association slots for pending+active+draining;
scratch for crypto slots; bootstrap for preauth slots; let `O=2*service_count`
(both directions), `G=grant_requests_per_pair`. Sender slots >=O,
result/correlation slots >=O+G, history slots >=2(O+G). Reserve one whole
application assembly and separate control slots >=feedback_buffers+G+1,
including one receipt authentication slot, plus application
queue slots and adapter slots. History count reserves every admission permitted
by its retention interval; this contract enforces capacity admission and refuses
new work until records expire rather than claiming an unbounded throughput.
Sender/assembly/result/application queue slots reserve a whole max message;
when grants are enabled every result slot also reserves at least 21 bytes for
the retained security-control grant RSP.
bootstrap slots >=120 bytes; control/adapter slots >=maximum encoded frame.
Freshness-token slots >=tokens_per_principal, each >=16 bytes when enabled.
All components keep at least one nonzero design reserve even when disabled.
For relay roles the endpoint-only component minimum is one slot/byte; control
and adapter still hold a complete encoded frame. Relay cache count is at least
`O*(N+bootstrap_N)+max_status+receipt_limit+establishment_frames*episode_attempts`.
These are capacity ceilings with refusal on exhaustion, not a sustained traffic
rate guarantee across repeated admitted episodes.
Other state-slot sizes are positive implementation reserves to be reconciled
against actual library layouts at P04/P08/P12/P15/P19. Missing measurement is not
a pass. Per-pool runtime exhaustion rejects admission and cannot evict protected
history or borrow the only receipt/control resource.

## Tool and corpus

`python tools/validate_profile.py FILE [--expect-sha256 HEX]` prints a JSON object
with `valid`, exact `sha256`, and conservative derived bounds, or `valid:false`
with an error code/path/message and nonzero exit status. No files are rewritten.
The library entry point is `validate_bytes(raw, expected_sha256=None)`; it returns
that success object or raises `ProfileError` carrying `code`, `path`, `message`.
`tests/profiles/` owns examples, independently stated expected interpretations,
and invalid mutations/raw encodings. These are P02 corpus inputs, not P03 accepted
physical/product manifests. Runtime/startup parity remains P09's obligation.
