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
| Cached-flight and same-owner serialization | Host `duplicate-loss-processed-conflict`, `scratch-serial-stale`, and `cached-flight-lifetime`; independent-worker concurrency remains separately evidenced by MCU-04 | The new host case proves the configured retransmission ceiling, stable cached bytes, unchanged absolute deadline, and cache invalidation at attempt expiry. Transport faults before/after the adapter writes bytes remain open; two independent workers do not prove same-owner serialization |
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
