# P09 identity and admission acceptance

P09 adds caller-owned identity contexts and startup profile admission before
traffic. This note records the frozen P10/P11 integration boundary required by
the work package. It maps existing contracts; it adds no wire behavior or
deployment limits.

## P10/P11 ownership and admission boundary

- `dmp_identity_table` and its slots are caller-owned fixed storage. A context
  is addressed by `(slot, generation)`; sequence numbers alone are not global
  identities. P10 reliability records and P11 assemblies retain their context
  with `dmp_identity_context_retain` while records or callbacks can refer to
  it, then release exactly once after terminal cleanup. A draining context is
  not reusable until its deadline has passed and all retained owners settle.
- P02 admission supplies validated capacities and duration bounds through
  `dmp_admitted_profile`. P10 uses `peers`, `operations_per_service`,
  `sender_slots`, `result_slots`, `history_slots`, `correlation_slots`,
  `application_queue_slots`, `control_slots`, `adapter_slots`, `queue_ms`,
  `response_timeout_ms`, `jitter_ms`, `send_horizon_ms`, `max_bursts`,
  `receipt_delay_ms`, `receipt_limit`, `dedup_ms`, `rejection_ms`,
  `result_cache_ms`, `result_deadline_ms`, `correlation_ms`, `tombstone_ms`,
  and `late_result_ms`. P11 uses `peers`, `assemblies_per_peer`,
  `assembly_slots`, `encoded_mtu`, `message_bytes`, `fragments`, `chunk_bytes`,
  `collect_ms`, and `assembly_ms`. `sender_slots`, `assembly_slots`,
  `result_slots`, `history_slots`, `correlation_slots`, and `adapter_slots`
  expose the validated endpoint resource charge counts, excluding the separate
  relay row. `control_slots` and `application_queue_slots` remain the operational
  limits from `limits`; admission verifies that endpoint charges cover them, but
  a larger memory charge does not raise the runtime limit. Admission uses
  `record_margin_ms` to validate that the
  absolute assembly lifetime covers the collection bound and margin; runtime
  P11 consumes the admitted `collect_ms` and `assembly_ms` bounds. The current
  schema fixes `inactivity_ms` at zero, so no optional inactivity timer is
  configured. Each module uses caller-owned bounded storage sized for its
  admitted limits; admission fails before acceptance when a required record or
  buffer cannot be reserved. No live record is silently evicted to make room.
- Time inputs are monotonic `dmp_time_ms`. Convert admitted durations to
  overflow-checked absolute deadlines at the event named by the protocol
  contract. A duplicate does not renew a request, result, tombstone, rejection,
  or assembly lifetime. The original deadline may be shortened by policy.
- `dmp_transport` is the send ownership seam. Register a token and pin all
  borrowed bytes before `submit`. A rejected submit has no callback; an accepted
  submit settles exactly once through its terminal callback. A successful
  `cancel` request does not return buffer ownership; only the terminal callback
  does. The `synchronous_completion` capability permits inline completion, so
  state must already be valid before calling `submit`. Serialize each module's
  owner state across submit, cancel, completion, and timer processing.

## P10/P11 interaction

- P11 admits and assembles the entire message before reporting completion. It
  never dispatches partial payloads. An assembly reserves metadata and the
  complete bounded message storage before acceptance; conflicting duplicates
  do not replace accepted bytes or extend the original deadline.
- P10 starts request execution only after complete message validation and
  admission. Receipt and terminal result are separate events with independent
  retention and deadlines. The receipt for fragmented input follows completed
  assembly and acceptance. P10 may be tested with unfragmented messages without
  P11; P11 assembly tests do not depend on P10.
- Releasing assembly storage is independent of retaining the accepted-request
  decision, result, or correlation tombstone. After result release, the request
  acceptance record remains for the configured deduplication horizon and a
  duplicate receives only its receipt. The sender allows at most one
  outstanding `ACK_REQ` per destination endpoint and service. ACK sends bypass
  that gate; queued result sends obey it and their configured deadlines,
  without blocking receipt ACKs.
- P10/P11 resolve full message identity and service from the bound profile and
  context. Secured compact references are resolved only after the caller's
  authentication checks. Test-only authenticated-context fixtures remain
  provisional until the real SEC-1 reruns at P15.

The semantic contracts above are defined by the main specification §§7, 8.1,
8.2, 11 and 11.1; P07's transport ownership contract is in
`include/dmp/transport.h`. Exact P10/P11 callable APIs remain coordinator-owned
and will be frozen in their public headers before either implementation is
dispatched.

## P09 verification

- Changed C translation units compiled with the configured C11 warning-as-error
  flags using the direct compiler invocation after the generated Ninja build
  hung during command launch.
- Targeted host CTest: 4/4 passed (`profiles.contract`,
  `identity.context`, `identity.profile_admit`, `identity.profile_parity`).
- Profile Python suite: 23/23 passed.
- `python tools/check_core_allocators.py build/host/libdmp.a --nm nm`: no
  allocator references.
- Independent read-only review against baseline
  `snap-f5ec99a220ae02cd7c8512b8` and sealed source target
  `snap-7ba380c7fbecb1a404ea3ff8` closed the 120-byte endpoint bootstrap floor
  and generation-slot scan findings; no further actionable P0-P2 issue was
  reported. The reviewer did not rerun tests.

These are host/profile and source-review results. They do not establish SEC-1,
endpoint integration, MCU, interoperability, or physical transport
conformance. P10/P11 and the required real SEC-1 reruns remain open.
