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
| Cached-flight and same-owner serialization | Current host `duplicate-loss-processed-conflict` and `scratch-serial-stale` cases; independent-worker concurrency remains separately evidenced by MCU-04 | Verify transport faults before/after write and the bounded cached lifetime against the exact P01 contract; two independent workers do not prove same-owner serialization |
| Buffer ownership and failure output | PN/AAD checks and MEM-01/02/03 owned-block, allocator-hook, quota and serialized-owner evidence | Reconcile mutable receive input versus immutable cached/borrowed TX and partial-output validity, then provide the explicit inventory of every secret copy/scratch buffer erased on abort/free |
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
