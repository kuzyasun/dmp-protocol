# Implementation transition: provider evidence into one DMP library

Status: scheduling correction accepted after independent review, 2026-09-27.
P01A done (narrow development basis); P02 ready; full P01 remains running.
Owner explicitly requested correction after identifying that provider experiments
had expanded without creating `src/`, `include/dmp/` or a `libdmp` target.
No normative revision, suite, wire byte, security rule or existing test outcome changes.

## Decision and dependency graph

P01 remains an open umbrella for provider/security/resource acceptance, not a
prerequisite for every source file. Split its work into P01A (development
feasibility), P01B (actual library provider adapter), and P01C (target
qualification). Original obligations are assigned below, not silently passed.

- P00 -> P02 -> P03 -> P04 -> P05/P06/P07 -> P08 -> P09 -> P10/P11 -> P12.
- P00 -> P01A; P03 also requires P01A's existing measured provider input.
- P04 + P01A -> P01B, using actual library sources and tests linked to them.
- P12 + P01B -> P13 -> P14 -> P15; subsequent recovery/interop stays unchanged.
- P15 -> P01C; P01 closes only after P01A/B/C and P13/P15 acceptance.
- P25 requires both P24 and the completed P01 umbrella. Qualification is not waived.

P02 is the immediate ready assignment after accepted P00; it does not require
unimplemented endpoint code or completion of a physical MCU soak. P03 freezes
finite, validated development/test manifests and explicit resource allocations
informed by P01A; it does not assert measured whole-DMP fit before code exists.
Missing target measurements remain pending at their named qualification gates.
P04 creates the actual `libdmp` build target and headers; P05/P06 add its first
wire/framing implementation. Do not insert another laboratory state-machine
phase between these packages.

## P01A development feasibility basis

The existing pinned candidate is eligible for implementation work, not adopted
as production-ready. Existing independently reviewed evidence is sufficient for
this narrow gate: exact NNpsk0/XX ChaChaPoly fixtures/hash/Split (baseline), PN-01
explicit PN/AAD, DH-01 all-zero rejection, RNG-01 and BINIT-01 fallible selected
runtime/startup paths, MEM-01/02 bounded ownership and cleanup, and MCU-01
selected compile/link feasibility. Source inventories, backend preparation,
license/provenance and patch ledger remain recorded in those evidence folders.
No claim that all secret copies, endpoint policy or targets are qualified.
The original aborting backend remains ineligible; use the reviewed checked
backend, and reopen affected checks on any pin/configuration/provider change.

P01A acceptance uses these existing scoped results, not a new test execution or
reclassification of P01 as done. Independent review confirmed this scope and
the coordinator accepted it as recorded below.

## Obligation transfer and reuse

| Existing obligation / asset | Implementation and acceptance owner | Required treatment |
|---|---|---|
| Engine/backend provenance, selected suites and capability feasibility | P01A; revalidate on change | Reuse pinned reviewed source and evidence; no new primitive/backend selection |
| Wrong-PSK cryptographic failure, low-order DH, fallible init/entropy/storage, partial outputs, PN/AAD | P01B `src/security/` provider adapter and linked tests | Exercise the real adapter; preserve fixture/fault regressions; fail setup closed |
| Public framing, lengths, identity/prefix/lookup and conflicting duplicate boundary | P05 codec, P09 identities, P13 real handshake | No replacement parser/owner in a test executable; P13 accepts combined boundary |
| Pin/payload/zero-CID policy, generation invalidation, stale completion, abort cleanup and fresh scheduled restart | P13; P15 integrated rerun | Real SEC-1 module, unreset episode/global budgets, ingress limits/backoff and unaffected other associations |
| One write per cached flight and same-owner serialized duplicates | P13; P15 rerun | Instrument actual module/provider seam; sequential laboratory checks cannot pass concurrent ownership |
| Mutable input, borrowed/cache buffer lifetime and all owned secret copies | P01B adapter; P04 interface; P13/P14 implementation; P15 acceptance | Inventory ownership and erasure; delayed completion/cancel contract tested on actual code |
| Declared four_parallel sensitivity | P01C with actual P15 library | Four peers, four pending attempts, TWO crypto slots, four application operations; no inferred fit from two isolated workers |
| Reference MCU ports, heap/stack/maps/timing/energy/entropy evidence; non-Espressif runtime | P01C and affected target gates | Existing partial MCU evidence retained; missing evidence blocks target/full umbrella acceptance, not unrelated host development |
| C3 MCU-05 incomplete reset scenario | P01C | Remains not passed; ROM UART disabled by existing eFuse; investigate observable boot channel without eFuse changes |
| Existing fixture helpers, fault injectors and serial controllers | Test infrastructure | Retarget drivers to the same library objects used by firmware; distinguish old provider-only results from new module evidence |
| Unvalidated BOUNDARY-01 draft | Not accepted, not in build | Reuse only useful input/expectation ideas after review; do not adopt its toy scheduler/owner as a second implementation |

The required independent peer in P20/P21 remains separate: its independence is
intentional protocol evidence, unlike an extra laboratory copy of primary logic.

## Acceptance for this documentation change

Inspect the actual diff; validate the package graph (known nodes, no cycles,
all dependencies of ready/done packages done); verify requirement ownership,
P13/P14 split, S10 deferred portions, separate retry-all identity and P22 before
P23. Check local links and unchanged normative files, implementation files and
Git index against [baseline.json](baseline.json). No runtime tests/builds are
claimed for a scheduling-only change. No commit, push or hardware operation.

## Independent review and coordinator acceptance

Read-only reviewer `transition_review` (GPT-6 Astra xhigh) independently checked
33 package nodes, no cycles, prerequisite readiness, baseline hashes and the
narrow P01A evidence. The clean fork remains pinned at
`c40f2dca78eee064e521233a5d884853d471028a`, matching the accepted MEM-02/MCU-01
basis; later MCU results do not broaden that scope. Existing provenance is
recorded, while full licensing/security/adoption review remains open.

One confirmed traceability defect was fixed: renaming the plan checklist
heading had broken its old anchor, used by provider README and the source
survey. The old anchor is retained as an explicit alias to the new checklist.
The reviewer found no material issue in the gate split, finite P03 ceilings,
actual-library ownership, preserved P13/P14/S10/retry-all/P22 requirements or
P01A's narrow eligibility. Coordinator accepts P01A using existing evidence;
P01B/P01C and endpoint/production acceptance remain pending.

[checks.json](checks.json) records graph/link/anchor and preservation checks.
The immediate implementation assignment is P02's real manifest contract,
validator and valid/invalid corpus, then P03 and P04's actual library target.
No further laboratory owner/scheduler implementation is scheduled.
