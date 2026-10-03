# Deterministic C harness subprocess interface v1

Status: P04 contract, not an implemented command. P07 implements clock/queue/
transport self-tests linked with libdmp. Later endpoint packages add real endpoint
drivers with versioned input modes. Python supplies inputs and collects outputs;
it never implements DMP parsing, retries, security or state machines.

## Invocation and limits

Planned commands:

```text
dmp-harness --interface-version
dmp-harness --manifest FILE < scenario.json > trace.jsonl
```

The first prints `1` plus LF and exits zero. The second reads one UTF-8 JSON object
to EOF, at most 1,048,576 bytes; no BOM, duplicate keys, unknown fields, floats,
non-finite values or trailing content. CLI rejects unknown/repeated options.
Manifest bytes are bounded/validated against manifest-v2, including cross-field
constraints, by the executable's configuration boundary (a separately invoked
offline validator cannot be the only check). The input digest must match SHA-256
of the exact manifest bytes. Original bytes and manifest identity remain evidence.

Fixed process bounds: 8192 actions, 8192 fault entries, 65536 queued/executed
events, 65536 trace records, 16,777,216 trace bytes, 86,400,000 virtual milliseconds.
Manifest adapter/role quotas remain additional, tighter limits. These harness
bounds do not change protocol ceilings. Reserve the last trace record and 1024
bytes for the terminal record; exhaustion must report budget failure, never
silently truncate. A broken output pipe is a process failure; absence of a valid
terminal record always invalidates the run. stderr is bounded to 4096 bytes.

## Input shape

All fields below are required. Numbers are unsigned JSON integers unless noted.
The minimum P07 mode is `transport-selftest`; there is no endpoint emulation.

```json
{
  "interface_version": 1,
  "mode": "transport-selftest",
  "manifest_sha256": "64 lowercase hex digits",
  "seed": "00000001",
  "until_ms": 1000,
  "stress": false,
  "loss_threshold": 0,
  "actions": [],
  "faults": []
}
```

`seed` is eight lowercase hex digits encoding a nonzero uint32.
`until_ms` is in 1..86,400,000; the run horizon is independent of an individual
association lifetime, allowing many attempts/restarts. Each action has `at_ms`
in 0..until_ms and `op`. Actions are sorted by at_ms, with input array order
breaking ties. Each action has exactly its operation's fields:

- submit: `at_ms`, `op:"submit"`, `link` (0 or 1, reciprocal directions),
  `id` (unique 1..4294967295), `data_hex` (even lowercase hex, nonempty, at most
  that binding's encoded MTU bytes), `not_after_ms` (at_ms..until_ms),
  `reply_to` (0 for a source frame, otherwise a preceding source action ID),
  `return_slot` (0 for source, 1 or 2 for the corresponding reverse reservation).
- cancel: `at_ms`, `op:"cancel"`, `id` (a preceding accepted-or-rejected submit
  action ID; lookup of a rejected or already terminal submission is stale).

Self-test bytes are explicitly public synthetic fixtures, handled as opaque
transport bytes; they are not a model of DMP. IDs are control handles, never
wire identities. P07 assigns slots from the lowest free bounded slot and uses
the shared generation helper, refusing exhaustion. Rejected submissions consume
neither a live slot nor a fault ordinal. Frame invalidity is irrelevant to the
opaque transport self-test; actual codec validation remains libdmp's job.

Fault entries contain exactly `link`, `ordinal`, `drop`, `duplicates`,
`delivery_delay_ms`, `completion_delay_ms`. Ordinal is 1-based accepted-submission
order per link, each (link,ordinal) appears once; missing entry means false/0/0/0.
drop is Boolean; duplicates is 0 or 1; delays are 0..until_ms. Delays are offsets
from the binding's earliest otherwise admissible delivery/terminal event, not
permission to start transmission outside an allowed slot. Reordering follows
from different delays; duplicate copies retain the same opaque bytes. A drop
suppresses all copies but does not imply failed local transmission. Delayed
completion keeps the accepted token/storage live until terminal delivery.

Seeded loss uses xorshift32: state ^= state << 13; state ^= state >> 17;
state ^= state << 5, with uint32 truncation after each operation. Advance once
per accepted submission in the globally ordered event sequence, including ones
explicitly dropped. Drop all its copies when the unsigned draw is less than
`loss_threshold` (0..4294967296); explicit drop is ORed with this result.
No draws for rejected sends, duplicate copies, completion or cancellation.
Identical input, manifest, executable and version produce identical trace bytes.

With stress=false, reject timing/queue fault settings that violate the declared
binding envelope; probabilistic loss does not promise delivery or conformance.
With stress=true, out-of-envelope impairment is permitted but all hard memory,
frame and harness bounds still apply. The terminal record labels such a run
out-of-model, never a passed profile conformance run. Incompatible/unused fault
ordinals at run end are reported as invalid scenario, not successful coverage.

## Exact opaque self-test schedule

This models the manifest's pair reservation calendar, not relay or endpoint
logic. Let P=return_slot_period_ms, W=return_slot_width_ms,
F=frame_tx_ms, D[0]=forward_delay_ms, D[1]=return_delay_ms,
T=F+max(D[0],D[1]). The pair uses one shared calendar anchored at virtual zero.
An accepted source reserves the earliest free period boundary at/after at_ms;
source reservations are FIFO across both links, including ties. Cancellation
does not make an already reserved period reusable. Reject BUSY if start-at_ms
exceeds queue_ms, capacity is full, or no reservation within the finite horizon
exists. Reject DEADLINE_EXPIRED if its proposed start is at/after not_after_ms.
Each accepted source occupies exactly one period (the self-test has no bursts).

Two reverse slots are reserved at source_start+P-W and source_start+P-W+T.
A return submit references that admitted source, reverses its link and chooses
one still-unused slot; accept only if arrival of the call is no later than slot
start and waiting is within queue_ms. Reject a missing/wrong-direction reference
as INVALID_ARGUMENT, an occupied/too-late slot as BUSY. No automatic replies are
generated. Unused return slots remain idle. This supplies bidirectional schedule
tests without parsing data or deciding which DMP control reply should exist.

Each context has limits.adapter_slots live submissions; queues do not borrow
endpoint control capacity. Base terminal time is start+F and base arrival time
is start+F+D[link]; fault delays add to those respective times. Duplication emits
two arrivals at the same time in copy order. Admission accounts for all queued
copies/completions under the hard event limit. The selected P03 borrow bindings
complete asynchronously in this mode; P07's direct C port self-tests additionally
exercise inline completion. Adapter capacity is held until terminal callback,
even after physical transmit ended. Arrival copies are bounded harness-owned
storage and do not extend the sender's borrow lifetime.

With stress=false, delivery_delay_ms must be zero because this deterministic
baseline already uses the manifest's worst admitted traversal delay. Delayed
completion may hold capacity but never shifts a reserved start; busy admission
is explicit. stress=true permits extra propagation delay and duplicates beyond
the modeled lower-layer assumptions, while still respecting start reservations.
This is a selected deterministic envelope boundary, not a measured transport.

Before the actual transmission-start event, cancel removes pending transmit/arrival work and settles with
cancelled_unsent at the cancel action (after its cancel trace). At/after start,
cancel retains scheduled arrivals but replaces any not-yet-delivered terminal
with possibly_transmitted at that action, after releasing local adapter access.
Already terminal or rejected submissions return STALE_HANDLE without callback.
These are exact self-test adapter choices; generic production cancel remains
asynchronous under transport.h. Source reservation metadata persists to horizon
for return references, bounded by the action limit.
Transmission-start events run in phase 3 below. A same-time phase-2 cancellation
therefore still prevents start; classification uses actual started state, not
the reserved timestamp alone. Starts additionally check not_after before sending.

## Time, completion and cancellation

No wall-clock sleeps or time are protocol inputs. Order queued work by
(time_ms, phase, insertion_sequence), where phase is:

1. Previously queued arrivals and terminal completions (stable insertion order).
2. Scenario actions (stable input order), including cancellation requests.
3. Protocol/adapter timers.

Drain work at a phase before moving on. Same-time work produced by a callback
is appended to that phase's FIFO; it never rewinds to an already drained phase.
An inline completion inside submit occurs there before its OK return and before
the next action. Already queued completion wins a tie against cancel. A cancel
request is not terminal; the adapter emits exactly one eventual terminal result.
No new transmission starts at/after not_after_ms. Expiry/cancellation after
possible transmission cannot claim CANCELLED_UNSENT. Manifest
synchronous_completion=true allows inline and delayed callbacks, not inline only.

At until_ms process queued work in the above order, then stop admissions and
settle/cancel outstanding self-test adapter work without further wire delivery
or advancing virtual time. Report unresolved remote delivery separately. A
borrow is released only once that adapter has proved no future memory access.
An endpoint timeout is a scenario observation, not a subprocess crash.

## Trace and outcomes

stdout contains only UTF-8 JSONL (one LF per record), closed schemas, canonical
field order shown below, no spaces outside strings. All records start with
`seq` (zero-based contiguous), `time_ms` (monotonic), `event`.

- run_start adds `interface_version`, `manifest_sha256`, `seed`, `mode`, `stress`.
- submit adds `id`, `link`, `bytes`, `status`, `slot`, `generation` (16 lowercase
  hex digits). Rejection uses slot=0,generation="0000000000000000".
- arrival adds `id`, `link`, `bytes`, `copy` (0 or 1).
- cancel adds `id`, `status` (base.h lowercase status name).
- terminal adds `id`, `slot`, `generation`, `outcome` (transmitted,
  cancelled_unsent, failed_unsent, possibly_transmitted).
- run_end adds `outcome` (completed, invalid_input, budget_exhausted,
  internal_error), `exit_code`, `stress`, `accepted`, `rejected`, `delivered`,
  `terminal`, `pending_local_at_horizon`, `pending_delivery_at_horizon`,
  `events` (executed count).

The two pending counters are sampled before horizon cleanup: live accepted
submissions lacking a terminal callback, and queued undelivered arrival copies,
respectively. Explicitly/randomly dropped copies are not queued and not pending.
delivered counts arrival copies, not peer acceptance. Cleanup gives unsent work
cancelled_unsent, already-started work possibly_transmitted, then discards future
arrival copies. It does not increment delivered or claim remote cancellation.

Serialize a submit admission record before invoking a possible inline terminal
callback so that the trace always introduces the token first. Pre-execution invalid input
produces just run_end at seq=0,time_ms=0 with zero counters and stress=false
unless the complete input validated; no partial protocol execution. A fault
ordinal left unused is discovered only at horizon: retain all preceding trace
records/counters, perform local cleanup, then append run_end invalid_input/exit2.
Do not rewrite this late scenario failure into the pre-execution zero-counter form.

Exit 0: completed harness execution with all local ownership settled (does not
assert endpoint success or any normative case passed). Exit 2: invalid input,
manifest/digest or unused fault directive. Exit 3: bounded capacity exhausted.
Exit 4: internal invariant/I/O failure. A controller requires the terminal
record, matching exit code and syntactically valid complete trace; otherwise it
records an infrastructure failure. It must not accept a partial trace as success.

Default traces contain only local synthetic handles, sizes, times, counters,
outcomes and public configuration digest. Never log frames, data_hex, payloads,
keys, PSKs, wire CIDs, NodeIDs, tokens from credentials, or Noise transcripts.
stderr uses fixed diagnostic codes and safe indices, never input echoing. No
debug byte-dump switch is part of v1. Endpoint-mode additions require a reviewed
version update and may not introduce Python protocol logic.
