# P01 evidence reconciliation and remaining checks

Coordinator reconciliation after independent read-only audit `p01_reconcile`
(GPT-6 Luna xhigh), 2026-09-27. P01 remains running; P02 remains pending.
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
| Abort-first post-read policy | Failed authenticated Noise reads; owned-object destruction; entropy/OOM abort probes | Wrong PSK provider handshake (not fixture wrong-key counts), wrong pin and invalid decrypted payload/zero CID: rejection, generation invalidation, cleanup, refusal of late authentic continuation and separately scheduled fresh attempt under unreset experiment episode/global budgets and backoff |
| Pre-read structural/conflicting-duplicate boundary | Fixture parsing and provider-only checks | Minimal test owner rejects malformed/conflicting pre-read input without crypto work, mutation or destruction of admitted state; later real endpoint rerun remains P13/P15/P21C |
| Cached-flight and same-owner serialization | Immutable fixture inputs; independent-worker concurrency only | Exactly one Noise write per cached flight, duplicate operation serialization on the same owner, faults before/after write and bounded cached lifetime; no inference from two independent workers |
| Buffer ownership and failure output | PN/AAD checks and MEM owned-block erasure | Mutable receive input versus immutable cached/borrowed TX, cached lifetime, partial-output validity and explicit inventory of secret copies/scratch erased on abort/free |
| Resource sensitivity | MEM-03 serial quotas; MCU-03 pending owners; MCU-04 two concurrent workers | Complete the declared experiment matrix, including the manifest's four_parallel row (four peers, four pending attempts, two crypto slots), per-region retained/scratch/stack and resource bounds; MCU-04 private worker pairs do not exercise that aggregate topology |
| Non-Espressif target evidence | Cortex-M4 compile/archive/alignment evidence | Select a concrete available board/linker map and entropy/clock port before physical runtime claims. ESP32-C3 does not satisfy non-Espressif evidence. No board is currently selected |
| Whole-provider acceptance | Reviewed scoped waves, independent expected vectors and pinned backend provenance | Review remaining deltas and combined requirement-to-test mapping; record residual limitations explicitly. Production adoption remains a separate decision |

The next implementation should close the first two host wrapper-boundary rows
with a bounded private provider test, reusing the accepted engine and fixtures.
Do not introduce production endpoint APIs merely to pass a laboratory gate.
P01 must still prove bounded experiment restart budgets/backoff without resetting
episode/global counters on abort. Full endpoint episode/global admission, replay,
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
