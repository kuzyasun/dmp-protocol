# DMPBENCH serial command protocol, version 1

Private P01 provider laboratory interface; not DMP wire format or a production
service. Public fixture PSK/static keys are compiled in. No credentials accepted.
One command runs at a time; no radio, automatic retry, hidden scenario loop or
automatic context recovery. Python schedules scenarios. Future transports can
carry the returned bytes without changing provider operations.

ASCII request line: `DMPBENCH 1 <id> <OP> [args...]\n`. ID is decimal 1..4294967295,
strictly increasing per boot/process, including failed accepted requests. The
sole exception is exact `DMPBENCH 1 0 HELLO`: read-only reconnect returns current
`last_id` without changing IDs/owners. A new host controller uses it to resume at
last_id+1, so successful scenarios can repeat without reflashing/resetting. It
does not recover live contexts left by an interrupted run. At most
3071 bytes before newline; overlong lines are discarded through newline and
produce an error, never an executable suffix. CR before LF is accepted. Hex is
even-length upper/lower ASCII, `-` means empty. No extra arguments. Slot 0..7.

Response: `DMPBENCH <JSON>\n`. Fields always include `v:1`, numeric `id`, `last_id`, `rc`,
`us`, `action`, string `data` (lowercase hex; empty on errors), `target`, `idf`,
`boot` (16-hex public boot-session identifier), `build` (source fingerprint),
and `stats`. A changed boot ID during a scenario is a reset and fails the run.
The public boot identifier is not provider key material or an entropy-quality test.
`rc=0` succeeds; negative codes are driver errors (-1 arguments,
-2 protocol/sequence, -3 capacity/output); positive codes are unchanged Noise
errors. Noise MAC failure is 17668, OOM 17665, SYSTEM 17670 and invalid state
17676 at the pinned provider revision. On parse errors ID may be 0.
`action` is the **post-operation** Noise action for slot operations or 0 otherwise:
WRITE normally advances to READ or SPLIT; READ advances to WRITE or SPLIT;
successful SPLIT/SEAL/OPEN report COMPLETE. `us` measures command parsing and
dispatch/provider work, excluding serial transfer, reply encoding/formatting
and final shared-scratch erasure. It is not an isolated primitive benchmark. Stats
follow the operation; serial/parser/format overhead is part of task stack/heap,
not a pure crypto memory measurement. Ignore unrelated boot/SDK lines, but reject
malformed prefixed JSON, wrong version, unexpected response ID, or device reset.
Timeout is an UNKNOWN outcome: do not automatically resend a mutating command.

| OP | Arguments | Behavior |
|---|---|---|
| HELLO | none | Identity/capabilities through common fields; no Noise init |
| INIT | none | Explicit checked Noise/backend initialization; repeat allowed |
| STATS | none | Current/cumulative statistics |
| RESET | byte_quota | Reinitialize empty arena only, 0..32768; reset allocator counters/peaks and faults; never erase live owners; IDs/init state remain |
| NEW | slot nn\|xx i\|r fixed\|random | Create/start handshake; fixed matches vectors, random uses platform ephemeral entropy; both use public test static/PSK/prologue |
| WRITE | slot payload_hex | Write one handshake flight, payload <=256; returned data <=512 |
| READ | slot flight_hex | Consume actual remote flight <=512; return authenticated plaintext <=256; failed read aborts provider state |
| SPLIT | slot | Return 32-byte handshake hash in data, transfer directional keys, destroy handshake |
| SEAL | slot pn aad_hex plaintext_hex | Fresh monotonic TX PN, no rewind/reuse; <=128 AAD and <=256 plaintext; burn admitted PN even on crypto failure |
| OPEN | slot pn aad_hex ciphertext_hex | Explicit unordered receive PN; <=128 AAD and <=272 ciphertext; authenticated plaintext only; no DMP replay acceptance |
| CLOSE | slot | Destroy only selected owner; empty slot is idempotent |
| ALLOCFAIL | ordinal | Refuse Nth future Noise allocation, 0 disables; one-shot |
| RNGFAIL | ordinal | Fail Nth future checked entropy read, 0 disables; one-shot |

PN is decimal 0..18446744073709551614. Equal/older TX PN rejected; valid lower RX
PN permitted by this provider probe. Retrying a wire flight/packet means reusing
Python's captured bytes, never requesting another WRITE/SEAL for that record.

Stats keys: `arena_live`, `arena_peak`, `blocks`, `quota`, `backing` (32768),
`metadata`, `owners`, `scratch`, `allocs`, `frees`, `attempts`, `refusals`,
`wipe_errors`, `rng_calls`, `heap_free`, `heap_min`, `heap_largest`,
`stack_free_min`. Sizes in bytes. Heap/stack are device-wide heap / command-task
stack observations, not per-owner costs. `owners` is static record storage size,
not a count of live contexts. The UART adapter also reserves 5120 static bytes
for input/reply lines and a 4096-byte SDK RX ring in heap, outside the provider
arena; account these in whole-image/whole-task measurements. Host platform reports 0 for unavailable
heap/stack fields. No keys, RNG bytes or private state in diagnostics.

Initial host scenarios: fixed exact-vector exchange for nn/xx in both role
orientations, random-ephemeral live exchange, bidirectional traffic with PN2 then
PN1 on receive, corrupted tag then authentic packet, wrong AAD, allocation/entropy
failure and explicit cleanup/retry, repeated lifetimes with stable arena baseline.
The runner saves JSONL commands, raw responses and metadata; hardware mode uses
explicit ports, baud 115200, finite deadlines, DTR/RTS deasserted, no auto-reset or
flash. A two-process host mode tests the same portable command core before MCU.
