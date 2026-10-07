# P20 independent peer brief — accepted contract

**Status:** P19 is accepted for host/simulation scope. The owner confirmed the
peer language/toolchain and first concrete P22 host binding. This brief freezes
those choices and the independent test interface before P21 implementation.
The coordinator's independent read-only review found no actionable findings;
the final package paths and command were rechecked against the P21A write set.

## Objective

Specify a narrow, independently implemented DMP v2 peer and a protocol-agnostic
test transport interface. The peer must implement its own manifest parser,
codec, security/session handling, endpoint state machines, routing and recovery.
It must not link to libdmp, wrap the primary harness, or reproduce a canned
response trace. P20 freezes inputs, ownership boundaries, interface and
acceptance mapping; P21A–P21D implement the peer in separate sequential packages.

## Normative and test inputs

The peer implementer receives these documents and their referenced sections as
the source of truth:

- `docs/DMP_v2_Device_Messaging_Protocol_Specification.md` — main revision 10,
  especially frame grammar, extensions, Stream R (§15.2), adapter completion and
  buffer ownership (§16), AAD/routing, and required cases (§22.8).
- `docs/DMP_v2_Security_Profile.md` — SEC-1 revision 5 / BOOT_VERSION 2,
  including S3–S10, the selected NNpsk0 and authenticated XX profiles, protected
  frame processing, freshness and lifecycle requirements.
- `docs/DMP_v2_Selective_Recovery.md` — SELECTIVE-32 revision 1, R1–R7.
- `docs/DMP_v2_Reference_Application.md` — SAMPLE-1 revision 2.
- `docs/DMP_Test_Manifest_Contract.md` and
  `profiles/schema/manifest-v2.schema.json` — manifest contract 2, exact-byte
  digest, parser rules, constraints and simulated-profile meanings.
- `docs/DMP_v2_Security_Test_Vectors.json` and
  `docs/DMP_v2_Recovery_Test_Vectors.json`. These are public vectors; matching
  them does not replace live endpoint tests. SAMPLE-1 behavior is specified in
  `docs/DMP_v2_Reference_Application.md` A1–A4.
- `dev/DMP_Recovery_Matrix.md` and `dev/DMP_Work_Packages.md` — required case
  ownership and deferred gates, not normative behavior.

The peer independently parses the exact original bytes of each selected
deployment manifest; it does not trust the primary validator's interpreted
configuration. The frozen inputs include these original-byte hashes from
`profiles/deployments/digests.json`:

| Manifest | SHA-256 |
|---|---|
| `direct-nnpsk0-async.json` | `f39204f1340debf9da99fbf985dda7af7150d1b4ea5e92a7ebdf86fe7f2187c6` |
| `direct-nnpsk0.json` | `29f7895ab3f8dadfbe7331f1981fa35dcad2bec59139464e29bddc4e841e5285` |
| `direct-xx.json` | `075e8ed25f6011c7dc20c84789eb61dff4784af86413415ddbd4aede07bcfce3` |
| `radio-nnpsk0-n2.json` | `1d11940b8905261bab2974d266435a04dcedac1a4775f5304406e59852e9bb96` |
| `radio-nnpsk0.json` | `9767b5daff88424e64887dd78a335c4de0f9b93900d4512c1cec9c4d041b53a9` |
| `radio-xx.json` | `8ddf226f205ac3e547b57858d6cd68aa960fab03f6462b9f27cca81c0822fe60` |
| `test-direct-minimal-128.json` | `3bbcce998d664fa74970f503a39b28474de9291d453373810d641b2b662fb6e4` |
| `test-direct-minimal-256.json` | `4dc75347343c209c1ed12ab67e60eba83ff974beaa9f351c121da87e7b18b946` |
| `test-radio-retry-all-nnpsk0.json` | `bc8bba7c929c6d0fe9ad39dbe66a6699d342304ae8485ddf5cac9e32605b55f1` |
| `test-radio-retry-all-xx.json` | `4aece0283e15774346dd2d0d73d45e8c496a4e91aec2ac2693a253e977c767c9` |

The peer must reject duplicate/unknown fields and any malformed or infeasible
profile under the published contract; primary parser code is not an oracle.

The test-only service 2 workload is `DMP-test/OPAQUE-1/1`: reliable opaque DATA
REQ and same-service opaque RSP, bounded by the selected manifest. Its handler
has no external side effect and is idempotent. The fixtures define exact request
and result bytes, including 1,024-byte fragmented request/result exchanges; they
do not alter SAMPLE-1 or add a production opcode. Service 1 remains the exact
SAMPLE-1 contract. RADIO profiles additionally exercise ROUTE/CONTEXT/TTL and
the real service-0 freshness grant/token path.

For the canonical large exchange, request length is the manifest's admitted
service-2 request maximum and result length is its admitted result maximum.
Fixture byte `i` is `(i mod 256) XOR 0x5A` for the request and
`(i mod 256) XOR 0xA5` for the result. Thus the full profiles exercise 1,024
bytes in both directions, while the minimal profiles exercise their own 128- or
256-byte request bound and configured result bound. Fragment-size/tail cases
derive their exact lengths from the selected manifest's chunk size and fragment
count; exact stride is `N*chunk`, and a one-byte short tail is
`(N-1)*chunk+1`. These are public fixture definitions, not shared primary
generator code.

## Independence boundary

Allowed inputs are the normative documents, schemas and manifests, published
byte vectors, fixed public test credentials/seeds, and the versioned test
transport interface. A maintained crypto provider may be shared; its exact
package/version and cryptographic-independence boundary must be recorded.

The implementer must not inspect or copy `src/` protocol implementations,
primary C endpoint/codec/security/reliability/reassembly/identity/relay/stream
tests, or generated primary traces that reveal internal decisions. The P20
assignment must give the implementer a fresh task context and list the exact
files supplied and excluded. Sharing this written contract does not by itself
prove clean-room independence; record actual inputs, filesystem access and the
correlated-interpretation risk.

## Test transport contract requirements

The new language-neutral interface is `DMP-PEER-TEST/1`. This version fixes the
operations, ownership, lifecycle, event-order and deadline semantics below;
language-specific serialization and process startup are frozen with the
selected language. Breaking semantic or schema changes require a new interface
version. It is separate from `tests/harness/PROTOCOL.md` v1.

The transport test interface carries opaque bytes and preserves only the
selected binding boundary: one packet datagram for a packet binding, or arbitrary
ordered byte chunks (which may split or combine Stream R frames) for a stream
binding. It must not parse DMP headers, interpret service/recovery state,
authenticate frames, or decide endpoint acceptance. The controller supplies a
deterministic monotonic clock. The peer interface exposes `open`, `receive`,
`advance`, `cancel`, `disconnect` and `restart`; lower-binding submissions and
completions use `tx_submit` and `tx_terminal`. There is no separate `poll`;
`advance` drives all due events. The controller can inject bounded packet loss,
duplication, reordering, delay, malformed bytes, stream read splits/coalescing
and stale generation-tagged completions. Both directions use the same declared
path MTU and return-opportunity contract.

The interface distinguishes local submit acceptance/completion from remote
frame arrival, authenticated receipt, application acceptance, ACK, and request
result. It declares copy or borrow ownership; rejected submissions retain caller
ownership; accepted borrows settle exactly once, including cancellation and
disconnect. A delayed completion is controllable independently of arrival. A
generation prevents stale completions from affecting a reused slot. Tests compare
wire bytes and externally visible results/rejections, not private state.

Language-neutral event semantics for `DMP-PEER-TEST/1`:

| Operation/event | Contract |
|---|---|
| `open(link, deadline_capability, at_ms)` | Controller calls this only after a fresh test binding is open and its receiver is ready. The capability is `strict_latest_start` or `submission_only`. The peer then emits the initial empty Stream R synchronization delimiter. |
| `receive(link, bytes, at_ms)` | Delivers one packet datagram, or one arbitrary ordered stream read chunk at the stated virtual time. Stream chunks may contain partial or multiple Stream R envelopes. The controller does not inspect their contents. |
| `advance(now_ms)` | Monotonic unsigned milliseconds and nondecreasing. Process due transport events and protocol deadlines in timestamp order; at equal timestamps, receive and terminal events precede protocol deadlines. Apply the advertised deadline capability to each transmission-start attempt: strict mode rejects a start at or after its cutoff, while submission-only mode may start already accepted work. The peer emits newly due submissions/events as events are processed. No wall-clock sleep is a protocol input. |
| `tx_submit(handle, generation, bytes, not_after_ms, at_ms)` | Peer emits immutable lower-binding bytes: one complete core-frame datagram for a packet binding, or the encoded Stream R envelope for a stream binding. `not_after_ms` is `None` or u64. Controller answers with `tx_admit`; accepted borrows remain immutable until exactly one matching terminal event. |
| `tx_admit(handle, generation, accepted, reason, at_ms)` | Synchronous controller response to `tx_submit`, delivered at the same timestamp before the next peer event. `reason` is `None` on acceptance; rejection reasons are `busy`, `expired`, `mtu_exceeded`, `disconnected` or `invalid_argument`. A rejected submission has no later terminal callback. Both peer and controller check the deadline at submission. |
| `tx_terminal(handle, generation, outcome, at_ms)` | Controller reports only local completion: `transmitted`, `failed_unsent`, `cancelled_unsent`, `expired_unsent` or `possibly_transmitted`. It says nothing about remote receipt or application execution. |
| `cancel(handle, generation, at_ms)` | Peer requests cancellation. It is not itself terminal; controller uses `cancelled_unsent` only when future transmission and driver access are impossible. Otherwise it settles as `possibly_transmitted`. |
| `disconnect(link, at_ms)` / `restart(at_ms, entropy)` | Controller reports link loss or endpoint restart. Settle all accepted submissions once and discard volatile protocol/association state. Reopening requires a fresh handshake and fresh ephemeral material; never restore old traffic counters or accept old protected frames. `entropy` is injected deterministic test bytes. |
| `application_event(kind, service_id, exchange_id, status, payload, at_ms)` | Peer exposes `request_accepted`, `request_result`, `protocol_rejection` or bounded `diagnostic`; includes the service ID, synthetic exchange handle, typed status, optional test payload bytes and event time needed by an assertion. Payload bytes are API data, not default log data. Never exposes private tables or raw keys. |

The Python API is `PeerEndpoint(manifest_bytes, test_credentials,
entropy_source, test_services).handle(input_event)`, returning an ordered tuple
of immutable output-event records. Use frozen dataclasses; do not add JSON or
another process serialization in P21. Event fields use u64 monotonic times, u8
local link IDs, u32 submission handles, generations, service IDs and statuses,
u64 synthetic exchange handles, immutable `bytes` for wire/payload data, and the
outcome enums in this contract. `accepted` is bool; `reason`, `outcome` and
`kind` use only the closed values in the event table. Entropy and test
credentials are injected, fixed public test inputs. Invalid API records and
backwards time fail closed without partial state mutation. The controller must
impose finite frame, event, output and virtual-time bounds; each call returns at
most 4,096 events and at most 1 MiB summed across byte fields. Missing terminal
events are harness failures. P22 may add a bounded process bridge without
changing these records.

Deadline semantics follow §18.2 and the harness convention: `not_after_ms` is
an optional monotonic exclusive latest-start cutoff in the shared virtual
clock. The peer checks it at every queue-to-adapter submission, including
retries, and the controller checks it again when accepting a submission. A new
submission at `now_ms >= not_after_ms` is expired. A strict binding likewise
rejects a start at or after the cutoff; a submission-only binding may start work
accepted earlier, as declared by its capability. An expired submit is
synchronously rejected with reason `expired` and has no later terminal event.
Other rejection reasons remain distinct from expiry.

Each binding advertises `strict_latest_start` or `submission_only` deadline
capability. With `strict_latest_start`, a transmission must start strictly
before the cutoff. Immediately before the first byte can leave the test
binding, the controller checks the cutoff again; if it has arrived or passed,
it sends no bytes and settles that accepted submission with `expired_unsent`. With
`submission_only`, the controller enforces the cutoff only at submission; an
accepted queued submission may start later. At expiry, the peer stops new
submissions and requests cancellation as required by §18.2, but cannot infer
that a submission-only binding prevented transmission. A profile requiring
strict latest-start MUST fail setup when its binding advertises only
submission-time expiry.

The peer reports local expiry before transmission only when no attempt could
have reached the peer. It reports an unresolved remote outcome as unknown only
while that outcome remains unresolved; a previously accepted terminal RSP or
application-result ERR remains the known result even if a queued retry later
expires. Where a possibly transmitted attempt remains unresolved, cancellation
does not retract it and the remote outcome is unknown.

Binding code belongs to the peer, not the controller: packet receive passes one
datagram to the core-frame parser; Stream R receive performs canonical COBS and
envelope-CRC validation before core parsing and accepts arbitrary read chunks.
Each Stream R transmitter emits the initial empty synchronization delimiter on
open/reset, after its receiver is ready. Test that reset/resynchronization path;
the transport may split or coalesce stream writes but must preserve byte order.

Controller and peer output are bounded and versioned. Default logs contain only
synthetic test handles, event times, sizes, statuses and public manifest hashes;
they exclude keys, PSKs, Noise transcripts, tokens, full frame bytes and payload
contents. A valid terminal record is mandatory; truncated output is a harness
failure. Existing `tests/harness/PROTOCOL.md` v1 remains a transport-self-test
contract and must not silently acquire endpoint-mode semantics; use an explicit
interface-version change or a separate peer interface.

## Selected peer language and test registration

Owner decision: implement the independent peer in CPython 3.12.8 with
`cryptography==46.0.4`. These exact versions were present in the local host when
the choice was confirmed. Use only the Python standard library and this pinned
maintained crypto provider; do not reuse a Noise/DMP protocol implementation.
The peer implements SEC-1's handshake and endpoint state machines independently
and uses `cryptography` for reviewed primitives. Record Python, package and
underlying OpenSSL versions in peer test evidence.

The P21 source root is `tests/peer/`, package `dmp_peer`, with tests in
`tests/peer/tests/`. `tests/peer/requirements.txt` pins the one external
runtime dependency. Tests use standard-library `unittest`; run the registered
command from `tests/peer/` once those paths exist:

```text
python -m unittest discover -s tests -p "test_*.py" -v
```

The peer exposes the `DMP-PEER-TEST/1` operations through an in-process Python
API (`dmp_peer.testing.PeerEndpoint`) and returns ordered immutable event
records. P21 does not add a second JSON-lines protocol. P22 may provide a bounded
process bridge for the existing harness, but it must preserve this interface's
event, ownership, redaction and deadline semantics.

## Selected host binding and P22 boundary

Owner decision: P22's first executable host binding is TCP carrying Stream R.
Its binding identity is `DMP-test/TCP-STREAM-R`, revision 1; the direct peer
profile is `DMP-test/PEER-TCP-STREAM-R/1`. P22's mixed-path profile is
`DMP-test/MIXED-TCP-STREAM-R-SIM-PACKET/1`. The TCP binding connects two peer
processes over IPv4 loopback (`127.0.0.1`) using an ephemeral local port; the
listener binds loopback only. This is a host test binding, not a
production-network or physical transport claim. Each TCP direction is one
ordered byte stream; each complete DMP Core frame is carried in exactly one
Stream R envelope. Within each peer process, event times and deadlines use
that process's monotonic clock shared with its local binding; deadlines are
local, never serialized, and never compared across TCP endpoints:

```text
COBS(CORE_FRAME || CRC32C_LE(CORE_FRAME)) || 00
```

The direct peer test profile fixes `forward_mtu=return_mtu=256` core bytes and
`encoded_mtu=263` bytes, including envelope CRC, canonical COBS expansion and
delimiter (`n=256+4`, `n+floor(n/254)+2`). These are application frame caps, not
TCP/IP MTU claims. Reject a core frame or encoded envelope above its cap. TCP
read calls may split or combine envelopes; feed every byte incrementally to the
canonical Stream R decoder. Serialize writes per direction so bytes from two
envelopes never interleave. Bound each receive candidate and queued envelope by
the declared caps and manifest adapter-slot quota. The selected binding declares
`deadline_capability="strict_latest_start"`; contract 3 records the capability
and the new profile identity. P22 owns schema/validator contract-3 implementation;
P02 contract-2 profiles remain unchanged.

The binding uses copy ownership: `tx_submit` copies an accepted envelope into a
bounded binding-owned queue; a rejected submission retains caller ownership.
The peer may reuse its buffer after acceptance. Emit exactly one generation-
matched terminal event when all bytes of that envelope have been accepted by the
local TCP socket (`transmitted`), when known unsent work is cancelled or fails,
or as `possibly_transmitted` if the connection fails after any bytes may have
left the process. This completion means local socket handoff only, never peer
receipt. Cancellation before the first socket write can settle
`cancelled_unsent`; after a frame starts, finish that envelope in stream order
or close the connection and report the uncertain outcome. Disconnect settles
every accepted slot exactly once; reconnect creates a new binding generation,
discards partial old envelopes and requires a fresh SEC-1 handshake.

The binding advertises `strict_latest_start`. Its local transmission-start
boundary is the first nonblocking socket write call that accepts bytes for an
envelope. Immediately before that call it checks the same monotonic
`not_after_ms` supplied at `tx_submit`; its timestamp is the call time for the
first positive write, and start is valid only when that time is strictly before
the cutoff. If the cutoff has arrived or passed, send no bytes and settle the
accepted item `expired_unsent`. A write attempt
accepting no bytes has not started transmission and must be retried only after
rechecking the deadline. Once any byte starts, the deadline does not limit the
remaining bytes of that envelope. This guarantee covers handoff to the local
TCP stack only; TCP/NIC scheduling after handoff and remote receipt are outside
the deadline claim. In the test manifest, encode the binding's capability and
the new profile under `DMP-test-manifest/3`; do not alter or relabel
`SIM-STREAM-R/1` or `SIM-PACKET/1`.

At coordinated open/reset, the receiver must be ready before the transmitter
sends the initial empty Stream R synchronization delimiter. An independent
receiver reset discards input through the next delimiter. Bound the partial-
candidate timer from the selected test manifest using the Stream R rule in
`DMP_Test_Manifest_Contract.md`; it is a host-test timeout, not a physical link
measurement. Exercise split/coalesced reads, reconnect/resynchronization,
copy ownership, delayed socket handoff, cancellation before and after start,
deadline expiry and disconnect with pending sends.

P22 must also implement both sides of `DMP-test/MIXED-TCP-STREAM-R-SIM-PACKET/1`.
It must preserve protected objects in both directions and test smaller-egress-MTU
and missing/wrong-CONTEXT failures separately in each direction before P23. Give
this path a distinct manifest under contract revision 3; it is not DIRECT-1 and does not relabel the
existing simulated binding IDs. Host loopback and simulated-path evidence do
not qualify a physical transport.

## Acceptance map

P20 is accepted only when this brief freezes the owner decisions, complete
versioned peer/test-transport interface, independent build/test registration,
exact inputs and exclusions, selected named binding contract, and all P21/P22
acceptance rows. P21A–P21D must then pass independent peer-local byte, hostile
input, lifecycle, SAMPLE-1, fragmented DATA/result, routing and recovery cases.

| Gate | Required independent-peer evidence |
|---|---|
| P21A | Independently parse exact manifest bytes and implement structural codec/framing. Pass public byte vectors, canonical Stream R boundary vectors, malformed-input and bounds cases. |
| P21B | Implement identity, direct receipt/result, reassembly and SAMPLE-1; pass local duplicate, loss, deadline and ownership cases. Provisional secure-context cases do not count until P21C reruns them. |
| P21C | Implement selected SEC-1 modes with the maintained crypto provider, including handshake, activation, AEAD/replay, ACL, freshness and lifecycle. Rerun P21B over actual protected frames and applicable endpoint-local S10 cases. |
| P21D | Implement ROUTE/CONTEXT/TTL and SELECTIVE-32; pass applicable R6/R7 cases with fragmented DATA and large request/result, relay-state S10 case 6, and the separately identified retry-all profile. |
| P21 | Accept the peer-local matrix across the full enabled-module set. It does not close interop/binding rows. |
| P22 | Implement the selected executable binding and the separately identified mixed Stream R/packet path. Preserve protected objects both directions and pass each-direction egress-MTU and missing/wrong-CONTEXT failures. |
| P23 | Run independent peers both directions across direct and routed paths, close S10 case 11, rerun relay case 6, and accept every applicable enabled-scope matrix row. |

The [package board](DMP_Work_Packages.md#phase-6-independent-peer-and-usable-interfaces)
owns detailed scope and dependencies. Physical binding and MCU runtime evidence
remain separately scoped.

Do not claim formal clean-room certification, physical transport, or product
readiness from the peer's language choice, public vectors, simulated schedule,
or a successful handshake alone.
