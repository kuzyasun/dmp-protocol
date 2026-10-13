# P01 evidence reconciliation and remaining checks

Coordinator reconciliation after independent read-only audit `p01_reconcile`
(GPT-6 Luna xhigh), 2026-09-27. Historical status: P01 running; P02 pending.
Current status: P01 remains running; P02 is accepted.
Scheduling superseded by the owner-approved [implementation transition](../implementation-transition-20260927/README.md): P02 is now ready after P00; unfinished checks below move to P01B, P13/P15 or P01C as mapped there. The previous lab-first next step is no longer the current assignment. Historical test outcomes are unchanged.

This ledger maps existing requirements, without adding or weakening the
normative contract. MCU-05 results are recorded separately in [README](README.md).

## Accepted scopes

PN-01, DH-01, RNG-01, INIT-01 and BINIT-01 establish their recorded host provider
seams. MEM-01/02/03 cover owned-allocation cleanup, bounded allocator hooks,
quotas and serialized live owners. MCU-01 adds selected Cortex-M4 archives and
an isolated ESP image link. MCU-02 adds physical S3/C3 serial-controlled Noise
operations and heap/stack/timing; MCU-03 adds quota pressure and guard survival.
MCU-04 adds two independent workers (S3 distinct cores, C3 single-core scheduling)
and fixes the observed C3 idle-watchdog starvation. Each wave's evidence and
limitations remain authoritative for that experiment; none passes full P01.

## Remaining provider prerequisites, in dependency order

| Check | Existing evidence to reuse | Still required |
|---|---|---|
| Abort-first post-read policy | Failed authenticated Noise reads; owned-object destruction; entropy/OOM abort probes; current host `wrong-psk`, `wrong-pin`, `invalid-authenticated-payload-restart`, `low-order-dh-abort`, and `episode-backoff` cases | The combined host scenario passes as `test_invalid_authenticated_payload_restart`: a validly authenticated zero-CID response aborts and wipes the attempt, advances its generation, rejects the late authentic continuation, enforces the configured backoff, then schedules a fresh attempt with a new ID and Noise ephemeral public key while episode/global work counters continue from their post-abort values. Remaining lifecycle mapping and non-host target gates stay open. |
| Pre-read structural/conflicting-duplicate boundary | Host `preread-conflict` and `scratch-serial-stale`; `duplicate-loss-processed-conflict` now sends a changed authenticated payload under the same processed-flight identity | Host regressions verify malformed pre-read inputs do not invoke Noise or destroy the admitted attempt, and a conflicting processed duplicate causes no Noise read/retransmit, deadline change, candidate teardown, or cached-response mutation. Finish the requirement-to-test map; P21C peer-local rerun remains separate evidence for the independent endpoint |
| Cached-flight and same-owner serialization | Host `duplicate-loss-processed-conflict`, `scratch-serial-stale`, and `cached-flight-lifetime`; `endpoint.protected_transport_reject_retry` now covers endpoint transport rejection and uncertain completion; independent-worker concurrency remains separately evidenced by MCU-04 | The handshake case proves the configured retransmission ceiling, stable cached bytes, unchanged absolute deadline, and cache invalidation at attempt expiry. The endpoint case proves pre-accept `BUSY` leaves the reliable request queued without a frame/callback, and an accepted delayed `POSSIBLY_TRANSMITTED` completion is forwarded so revocation reports UNKNOWN rather than LOCAL_UNSENT. The production handshake owner still has no `dmp_transport` submission path, so cached-flight send faults through that owner remain open; two independent workers do not prove same-owner serialization |
| Buffer ownership and failure output | PN/AAD checks and MEM-01/02/03 owned-block, allocator-hook, quota and serialized-owner evidence | Host `security.provider_adapter` cases `output-contract` and `split-partial-registration-cleanup`, plus `security.handshake` cases `scratch-serial-stale`, `epoch-hash-alloc`, `cached-flight-lifetime`, and `finish-ready`, now cover representative validation versus operational failure output, short-capacity wiping, split partial cleanup, caller RX mutation after partial/AWAITING, and borrowed cached/protected TX lifetimes. The source inventory below maps owner copies. Exhaustive branch-by-branch provider failure/erasure review and all target-specific behavior remain open. |
| Resource sensitivity | MEM-03 serial quotas; MCU-03 pending owners; MCU-04 two concurrent workers | Complete the declared experiment matrix, including the manifest's four_parallel row (four peers, four pending attempts, two crypto slots), per-region retained/scratch/stack and resource bounds; MCU-04 private worker pairs do not exercise that aggregate topology |
| Non-Espressif target evidence | Cortex-M4 compile/archive/alignment evidence | Select a concrete available board/linker map and entropy/clock port before physical runtime claims. ESP32-C3 does not satisfy non-Espressif evidence. No board is currently selected |
| Whole-provider acceptance | Reviewed scoped waves, independent expected vectors and pinned backend provenance | Review remaining deltas and combined requirement-to-test mapping; record residual limitations explicitly. Production adoption remains a separate decision |

The next implementation should close the remaining host wrapper-boundary rows
with bounded private provider tests, reusing the accepted engine and fixtures.
Do not introduce production endpoint APIs merely to pass a laboratory gate.
The combined invalid authenticated-payload restart path is now covered at the
host handshake boundary. Full endpoint episode/global admission, replay,
transport scheduling and network lifecycle retain their P13-P15 and P21 owners;
the bounded provider driver does not substitute for those endpoint reruns.
Delayed transport send-completion/cancellation interfaces belong to P04 and
subsequent adapter gates; P01 covers provider/cache-owned buffer lifetimes.

## Later gates and external measurements

P03 freezes achievable numeric manifests/aggregate envelopes. P08/P12/P15/P19/P25
compare integrated target usage against them. P13 performs bootstrap, enrollment
and candidate keys. P14 owns AEAD/AAD/PN/replay, protected FINISH/READY and
activation. P22 implements the mixed Stream R/packet path before P23 independent
interoperation. Physical DMP bindings, RF behavior, hardware entropy quality and
energy measurements remain distinct from these provider laboratory workloads.

For a non-Espressif physical run the owner will need to supply/select a board;
that missing hardware does not block the host checks above. For C3's MCU-05 warm
reset, [read-only inspection](c3-rom-controls.log) found UART_PRINT_CONTROL=3 (ROM UART
disabled) and USB ROM output enabled. The [post-diagnostic HELLO](c3-post-diagnostic.jsonl)
confirms return to the unchanged application, without passing the reset gate. An observable boot-diagnostic channel must be selected
before repeating the full reset gate; a fresh HELLO boot ID alone does not
prove absence of an additional startup reset. Do not change eFuses.

## Host recheck — 2026-10-13

The latest focused host run passed 43/43 CTest cases, including
`security.provider_adapter` and `security.handshake`. Reusable P01 host evidence
now includes provider wrong-PSK handling (`tests/security/test_provider.c::test_wrong_psk`),
actual handshake wrong-PSK and wrong-pin aborts, zero-CID/low-order rejection,
pre-read conflict handling, same-owner scratch serialization/stale completion,
and scheduled episode/backoff (`tests/security/test_handshake.c` cases
`test_wrong_psk`, `test_wrong_pin_and_association`,
`test_invalid_authenticated_payload_restart`, `test_low_order_dh_abort`,
`test_preread_and_conflict`, `test_duplicate_loss_and_processed_conflict`,
`test_scratch_serial_partial_stale`, and `test_episode_backoff`). The added
retained-rejection/fragmented-replay regression is additional P12 endpoint
evidence; it does not add P01 provider evidence. The protected SAMPLE-1 request
validation test is P12/P15 endpoint evidence, not a Noise handshake-payload
test.

This recheck does not close the explicit inventory of secret copies/scratch
that must be erased, the aggregate four-peer/four-pending/two-crypto-slot
resource matrix, full integrated target peaks, non-Espressif runtime
qualification, or the C3 reset diagnostic scenario. Existing RAM values and
provider-only MCU measurements do not establish whole-DMP target fit or hardware
operation. Per owner direction, these target checks remain deferred to the final
hardware phase; P01C and the P01 umbrella remain open until then.

The follow-up `security.handshake::cached-flight-lifetime` case also confirms
the host attempt's two-response limit and absolute expiry boundary. It does not
stand in for adapter send-failure injection or physical transport evidence.

## Owner-directed host continuation — 2026-10-13

The current follow-up reconciled the stale SAMPLE-1 row against real SEC-1
endpoint behavior. `security.provider_adapter`, `security.handshake`, and the
five protected endpoint CTests for initialization ordering, rotation, request
loss, result loss, and receipt loss passed 7/7 together. The protected
`main228-sample-stale` primary result is now passed in the normative ledger.
These tests do not replace the open P01 provider cache/transport lifetime
review, branch-by-branch secret cleanup checks, aggregate resources, or the
deferred P01C target and hardware gates. The source map below records ownership
and erasure paths without claiming every failure branch has been exercised.

## DMP-owned secret-copy inventory — 2026-10-13

This source map is limited to the DMP handshake/provider boundary. Credentials
passed into the API remain caller-owned; the owner-side copies are:

| Copy or scratch | Contents and lifetime | Erasure path and host evidence |
|---|---|---|
| `dmp_hs.config.psk`, `dmp_hs.config.local_static` | Provisioned credentials retained so a live owner can schedule later attempts. | The complete owner object is wiped by `dmp_hs_cleanup`; `security.handshake` case `cleanup-erases-owner` runs both NNpsk0 (PSK) and XX (local-static) attempts, then asserts every byte of each owner is zero after cleanup. |
| `hs_attempt.ephemeral`, `psk`, `prologue` | Attempt private key, attempt PSK copy, and Noise prologue. | `close_crypto` wipes these on abort, candidate completion, and owner cleanup. `dmp_hs_secrets_wiped` checks the ephemeral and PSK after covered aborts; `cleanup-erases-owner` checks owner teardown. |
| `dmp_provider_handshake_body.secret` and Noise handshake/DH/cipher state | Provider PSK copy plus library-owned private keys and derived traffic keys in tracked Noise allocations. | Handshake/cipher close wipes wrapper objects and frees tracked state; allocator release wipes each allocated block before release. `security.provider_adapter` checks released blocks on its cleanup and failure cases; the handshake test's release hook checks the owner cleanup path. |
| Local working buffers in `handshake.c` and `provider_adapter.c` | Transcript-hash scratch, decrypted application bytes, copied receive flight, and encryption/decryption bodies. | `hash`, `message_copy`, AAD and cipher bodies are explicitly wiped on their use paths. `attempt.accepted` and `protected_frame` are wiped on abort/end-of-traffic/owner cleanup; successful application plaintext copied out through `dmp_hs_copy_accepted` becomes caller-owned. |

Successful output buffers from provider APIs remain caller-owned. In particular,
the caller must erase a successful `dmp_provider_dh_shared` result, handshake
payload, or in-place cipher-decrypt plaintext after use. The DH wrapper clears
its shared-secret output on failure, while the handshake owner wipes its local
payload/body buffers after copying or consuming them.

Handshake wire caches (`cached`, `seen`, `prefix`) and incomplete ingress
(`partial`) contain public or encrypted protocol bytes, not the private key,
PSK, or decrypted application buffer. The cached-flight length is invalidated
on terminal attempts; this storage is wiped when the owner is cleaned up. This
classification does not
close the separate P01 cached-flight transport/lifetime checks, prove erasure
inside CPU registers, or establish target memory behavior. External credential
source buffers and caller-provided application output remain outside DMP's
ownership boundary.

## Host buffer-ownership and failure-output follow-up — 2026-10-13

The private provider contract now distinguishes pre-operation validation from
operational failure: validation returns preserve caller output buffers and
length sentinels, except that `dmp_provider_handshake_remote_public` wipes its
output for a non-NULL closed/invalid handshake (a NULL handshake pointer leaves
the output untouched); once valid arguments/state enter an operation, failure
zeros the length and wipes the declared output capacity.
`security.provider_adapter` checks invalid handshake read/write and cipher arguments preserve sentinels,
short handshake/cipher output capacities wipe only the declared region, and a
forced second-child registration failure during Split releases partial state
and leaves both output objects zeroed. Its remote-public probes verify the
NULL-pointer preserve and closed-handshake wipe cases. The existing authentication-failure
decrypt case continues to assert zeroed plaintext output.

`security.handshake` mutates the caller's RX storage after partial admission and
after an `AWAITING` offer, then verifies owner-held processing still succeeds.
It saves flight 2 before mutation, accepts the owner-held copy, and re-submits
the original bytes; this duplicate leaves Noise read/write counts, deadline,
and candidate state unchanged.
It also checks cached-flight stability across retries and that the returned
protected FINISH borrow remains owner-backed and stable through a later
read-only/refused operation. It does not test retaining that pointer after a
subsequent output replacement. These host checks do not establish asynchronous
transport completion or exhaustive backend failure-branch cleanup.

Validation on the prepared `build/host` P01B host configuration:

```text
cmake --build build/host --target dmp_test_provider dmp_test_handshake
ctest --test-dir build/host -R "^(security\.provider_adapter|security\.handshake)$" --output-on-failure
```

The focused build completed and both CTests passed (2/2). This is host-only
evidence; target, MCU, and physical checks remain pending.

## Provider operational-failure regressions — 2026-10-13

Two additional cases in `tests/security/test_provider.c` extend, but do not
complete, the failure-output and owned-state map. `dh-shared-allocation-failure`
injects OOM on the second allocator request after local DH state is allocated;
it checks the shared-secret output is cleared, temporary tracked state is
released, provider counters return to zero, and a later DH call succeeds on the
same provider. The injected failure occurs before the private key is installed.

`cipher-child-capacity-cleanup` fills the adapter's real child table. It checks
the first refused `cipher_from_key` call directly: the output wrapper is wiped,
the temporary Noise object is released, and pre-call block/retained counts are
unchanged. An already-open cipher still matches its exact fixture ciphertext
and tag after the refusal. This is provider state survival in a single host
process, not a multi-peer concurrency or endpoint-scheduler test.

Independent GPT-6.1-sol High review found no actionable issue. The focused
provider build succeeded and `security.provider_adapter` passed 1/1; the
focused diff check passed. This closes only these failure branches. Exhaustive
provider branch/secret-copy cleanup, the four-peer/four-pending/two-crypto-slot
aggregate resource matrix, transport send-fault boundaries, target/runtime
measurements, and P01C remain open. Hardware qualification stays scheduled for
the final phase; acceptable host memory figures do not guarantee board operation.

## First-allocation and handshake-capacity follow-up — 2026-10-13

The same provider cases now cover first-allocation OOM in `dh_public`,
`dh_shared`, and `cipher_from_key`, plus failure to register a new handshake
when the actual child table is full. Assertions check wiped outputs, unchanged
resource counters where no persistent owner is created, release of temporary
Noise state after capacity refusal, and continued use of an existing cipher.
Independent GPT-6.1-sol High review found no actionable issue; the provider
target built and `security.provider_adapter` passed 1/1.

This extends the named failure branches only. It does not complete the
branch-by-branch provider cleanup map, four-peer/four-pending/two-crypto-slot
resource scenario, transport send-fault coverage, target runtime, or P01C.

## Endpoint transport submission and uncertain completion — 2026-10-13

Added `endpoint.protected_transport_reject_retry`. A real SEC-1 endpoint pair
first encounters transport `BUSY` before acceptance; the test checks that no
frame or completion was produced, the same request remains queued, and its
`possibly_sent` state stays clear. A later poll accepts a copied frame and
settles its delayed callback as `DMP_TX_POSSIBLY_TRANSMITTED`; revoking that
endpoint emits UNKNOWN and no LOCAL_UNSENT event.

This is endpoint-wrapper/transport-contract evidence. It does not connect the
production handshake owner's cached flights to `dmp_transport`, and does not
close same-owner serialization or hardware behavior.

## Provider split, remote-key, and cleanup host follow-up — 2026-10-13

`security.provider_adapter` now also covers three reachable lifecycle cases.
The output-contract case checks that a live NNpsk0 handshake with no peer key
returns REJECTED and wipes `remote_public` output. The Split case injects OOM
at the additional Noise cipher allocation, asserts zeroed output wrappers and
unchanged block/retained/release accounting, then retries Split successfully
on the same handshake. General provider cleanup now runs with both a live
handshake and a live cipher wrapper and checks both are erased along with
released allocations.

The adapter's block-table guard returns before invoking the custom allocator
when all tracking slots are occupied, so `remember_block`'s defensive failure
path is not reached through the ordinary allocator path and is not claimed as
covered. The current Noise Split implementation allocates its second cipher
before publishing either output, so partial Split outputs are not produced by
the tested OOM path. Exhaustive allocation-ordinal cleanup remains open.

The provider target built and `security.provider_adapter` passed 1/1. Independent
GPT-6.1-sol High review found no remaining issue after test failure cleanup was
added. Focused `git diff --ignore-submodules=all --check` passed. This adds host
regression evidence only. Aggregate four-peer resources, production
cached-flight transport integration, target runtime, physical operation, and
P01C remain open; hardware qualification stays deferred to the final phase.

## four_parallel direct-Noise host follow-up — 2026-10-13

The new `dmp_parallel_four_parallel` host case keeps four pending Noise
initiators and sixteen live cipher states together across two worker arenas.
Both worker threads reached the first real Noise allocator callback during
handshake construction (`noise_allocator_callback_overlap=2`); this is callback
occupancy evidence, not proof of simultaneous cryptographic execution. Both
handshakes per worker remain pending, while four separate traffic-check sets
complete. Each worker recorded 26/26
allocation-attempt/allocation/free counts, 3,840-byte retained and peak arena
use, and zero post-cleanup live allocations; aggregate retained/peak was
7,680 bytes. Four 32-byte application operation buffers (128 bytes) are
test-driver buffers excluded from arena usage. Fixture AEAD success, invalid
tag rejection, and subsequent valid decrypt passed.

This demonstrates the declared direct-Noise resource pressure with exactly two
workers, but does not model endpoint peer IDs/services, real association and
draining lifecycle, return windows, or MTU/message bounds. Its manifest row
remains partial. The isolated host CTest passed 1/1 because ordinary project
reconfiguration could not read submodule Git metadata in this environment;
independent GPT-6.1-sol High review found no actionable issue after correcting
callback overlap, failed-barrier counts, and traffic-check metrics. No
target/runtime or physical evidence was produced, and P01C remains deferred to
the final hardware phase.

## NNpsk0 handshake-open allocation ordinal sweep — 2026-10-13

`security.handshake-open-allocation-sweep` injects failure into every
allocator call reached by NNpsk0 initiator/responder and XX initiator/responder
constructors. The four paths reached 8/8/10/10 failure ordinals; the next
ordinal (9/9/11/11) opened successfully. Each `NO_MEMORY` result leaves the
handshake wrapper zeroed, provider block and retained counts at zero, and
released storage erased; the same provider then successfully opens/closes a
fresh handshake. The focused provider build and `security.provider_adapter`
CTest passed 1/1; direct output records all four counts and boundaries.
Independent GPT-6.1-sol High review found no actionable issue.

This closes only allocation cleanup during these four constructors. It does
not cover other provider/Noise failure branches, full handshake recovery,
target allocation behavior, or P01C.

## DH shared allocation ordinal sweep — 2026-10-13

The `dh-shared-allocation-failure` case now injects `NO_MEMORY` at both custom
allocator calls used by `dmp_provider_dh_shared`. Each failure leaves the
32-byte shared-secret output zeroed, returns provider block/retained counters
to zero, and releases any partially allocated state. After each failure, a
successful DH calculation on the same provider proves recovery. Failure
ordinal 3 is beyond the two allocations and succeeds; both temporary states
are released and accounting returns to zero. The focused provider build,
`security.provider_adapter` CTest (1/1), and direct executable passed.

This closes only the DH shared-operation allocation ordinals. It does not
close other provider failure branches, endpoint resource completeness, target
allocator behavior, or P01C.
