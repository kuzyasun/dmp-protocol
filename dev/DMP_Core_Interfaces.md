# Portable C library contracts

Status: P04 foundation and P05/P06 codec/framing implemented; P07 harness frozen. This is an
implementation contract, not a revision of the normative wire/security documents.

## Scope and build

`libdmp` / `dmp::dmp` builds a C11 static archive (`libdmp.a` on GNU systems).
The foundation (`base.h`), structural codec (`core.h`), CRC (`integrity.h`) and
framing (`stream.h`) functions are implemented in the archive. There
are no success stubs or test-only protocol engines. `transport.h` is a callback
port for injected adapters, not a driver. Public headers support C++ callers.

The archive requires no SDK, OS, crypto provider, allocator, Python or Node.
`DMP_BUILD_TESTS=OFF` builds only that archive. Test tools belong to the host
test graph, and C++ detection is optional and limited to the header consumer.
These properties cover the current P04-P06 modules; P08 and later packages verify
resource and module-wide properties as real protocol code is added.

## Values and ownership

Spans borrow real caller storage. A null data pointer is valid only for length
or capacity zero. Required output/control pointers must be non-null. Invalid
arguments return `DMP_INVALID_ARGUMENT`; output/status pointers must not alias
input or destination storage. Unless a function explicitly says otherwise,
input buffers and views remain valid for its entire call. No API can validate
the actual extent of a non-null C pointer supplied by a caller.

`dmp_status` describes local API outcomes, never wire STATUS values or remote
acceptance. `dmp_bytes_slice` checks bounds with subtraction before pointer
arithmetic, permits empty and one-past-end views, and leaves output unchanged
on failure. There is no allocation or copy of payload bytes.

Time is unsigned absolute monotonic milliseconds supplied by the owner, with
no sentinel infinity and no wraparound. `dmp_deadline_after` accepts duration
zero; overflow returns `DMP_LIMIT_EXHAUSTED` without publishing a deadline.
`dmp_deadline_reached` includes equality. Scheduler ordering determines which
already-arrived work precedes an expiry at that same time.

Generation zero is invalid. `dmp_generation_next(0)` returns one; exhaustion
returns `DMP_LIMIT_EXHAUSTED` without wrap or output mutation. Owners retain the
counter across resets/reuse, invalidate old generations, and keep callback
targets alive until outstanding work settles. A generation is not a security
identity, PN, wire epoch or proof of remote cancellation.

## Structural codec (P05)

Parse once into a bounded borrowed view; retain raw header/TLV/payload/trailer
spans, zero absent fields and preserve received bytes. Parse checks canonical
wire syntax, declared lengths, geometry and known value shapes; it does not
authenticate, verify CRC, resolve compact identities or update state. SECURITY
payload remains ciphertext. Error output is zeroed when the output pointer is
valid; invalid API arguments report offset zero. Packet truncation reports
input.size; a field truncated inside the declared header or TLV value reports
that enclosing boundary, even when later packet bytes exist. Nonminimal ULEB
reports its start; overflow reports the offending byte. This diagnostic
clarification does not change the wire contract.

Role validation is separate. The same structurally parsed packet can fail
local endpoint checks while remaining eligible for transparent forwarding.
Actual configured module/provider support and authenticated semantic decisions
remain later gates. An unknown endpoint-critical extension must never silently
become endpoint accepted merely because the relay can forward it.

SEC-1 eligibility still requires later identity/association checks: protected
routes must use TO_NODE and carry CONTEXT, advertised CIDs must be nonzero, and
control services/HELLO and enabled modules require their actual handlers. These
P09/P13/P14/P17 obligations are not guaranteed by structural role OK. This layer
recognizes cipher descriptors; it does not provide AESGCM or ChaChaPoly. Generic
plaintext default service zero is allowed; explicit configured defaults remain
noncanonical. SEC-1 reserves service zero and needs separate startup validation.

Encoding preflights the complete representation, size and destination capacity;
errors leave destination bytes unchanged and set a valid `written` to zero.
Header-only encoding checks payload/trailer lengths but never reads their bytes;
they may use null pointers as length-only placeholders in that call only. This
allows AAD/header construction before AEAD output exists. Full encoding requires
valid backing bytes and copies the supplied payload/trailer without calculating
CRC/AEAD. No source/destination overlap is permitted. Extension iteration accepts
only a validated extension span and never advances on malformed input.

## Stream framing (P06)

The caller owns decoder state and scratch. Init failure leaves both unchanged;
only successful init makes a decoder usable. R needs encoded-bound scratch;
L needs maximum-core scratch. Bounds include their wire framing and must reject
arithmetic overflow. Encode rejects overlapping input/output and preflights
before writing; failure sets a valid `written` to zero and preserves bytes.

Feed consumes a prefix and returns at most one event. FRAME is a borrowed scratch
view valid until the next decoder operation. Input must not overlap decoder or
scratch; caller consumes/copies the view before calling again. A successful
framing event does not establish valid core syntax, authentication or delivery.
When no frame is returned, frame is `{NULL, 0}`. Invalid arguments/backward time
consume nothing, emit NONE and preserve state. Poll always consumes zero.
Arithmetic exhaustion when starting a timer fails the logical session explicitly.

Drain all already-arrived bytes at time t before polling timers at t. Feed may
finish a pending frame at exact deadline; it expires old partial state before
new input only when t is later. Poll expires at equality. Partial input does not
renew an absolute timer. Stream R uses canonical COBS and mandatory envelope CRC,
with its timer armed on the first nonzero candidate byte after synchronization.
Stream L arms on the first magic/prefix byte, not after a complete length field.
Stream R
starts discarding through a delimiter and requires a startup 00 after receiver
readiness. Encoder emits the frame only, not that startup marker. Stream L never
scans for magic after failure. Its adapter must also close after a malformed
core frame. Reset means a coordinated new logical session, preserves the clock
ordering rule, and returns status; it is not a Stream L resynchronization escape.

## Transport port

Each transport context belongs to exactly one callback owner for its lifetime;
drivers sharing hardware expose separate contexts. The token (slot,generation)
is unique within that context, so cancellation is unambiguous. The submission
structure is call-local: an accepting adapter copies its metadata. COPY copies
frame bytes before return; BORROW requires immutable storage until the one
terminal callback. All rejected submissions produce no callback.

`synchronous_completion=true` permits either synchronous or delayed completion;
false forbids callback before submit returns. Register/pin before submit; an
inline callback must not be undone by the subsequent OK return. Serialize each
owner's submit/cancel/callback work; marshal ISR/worker events into that context.
Callbacks cannot recursively submit. No owner/storage destruction before all
accepted submissions settle, including timeout/disconnect/reset paths.

Cancel OK is an accepted request, not a release. Only CANCELLED_UNSENT proves
transmission was prevented. Uncertain delivery uses POSSIBLY_TRANSMITTED. Every
terminal callback proves the driver/DMA will no longer access borrowed memory,
but none proves peer receipt/authentication/application result. A deadline
prevents new transmission start at/after it and cannot retract already sent
bytes. Tests of these actual owner/adapter races belong to P07/P13-P15.

## Harness and delegation

The bounded subprocess contract is [tests/harness/PROTOCOL.md](../tests/harness/PROTOCOL.md).
It is private test infrastructure, not a libdmp ABI or a second protocol engine.
P05 owns `src/core/codec.c` and dedicated codec tests; P06 owns
`src/integrity/crc32c.c`, `src/stream/stream.c` and dedicated framing tests.
P07 owns harness sources/tests. Shared headers/build registration remain with
the coordinator; changing this freeze pauses affected workers and revalidates it.
