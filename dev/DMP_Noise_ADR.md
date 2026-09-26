# ADR: abort-first SEC-1 and a controlled Noise core

**Date:** 2026-09-26  
**Status:** owner-directed draft decision; production implementation/adoption remains unapproved.  
**Baseline:** DMP revision 10 / SEC-1 revision 5 / BOOT_VERSION 2.

## Decision map

| Owner decision | Previous wording | Required change | Dependent evidence | Unknowns |
|---|---|---|---|---|
| Abort-first for an admitted new expected flight | S3.1 mandates tentative receive and preservation after failed read/pin | Destructive read or post-read failure ends only that attempt; structural/conflicting duplicate drops do not | S3/S10.17, plan P01/P13/P15/P21C, matrix | Injection-induced restart cost on each path |
| Bounded portable C interfaces | Provider selection was coupled to clone support | Separate lifecycle, engine, primitives and platform ports; one disposable state | Main API, storage/entropy/error/PN experiments | Exact size/alignment, compiler/ABI and target envelopes |
| Controlled fork or standard C engine organization allowed | Workflow/plan prohibit any private Noise implementation | Prefer smallest reviewed delta; require provenance, maintenance owner, independent tests | Source survey, P00/P01, release gate | Final base and patchset after experiment |
| Crypto backend selected independently | Candidate engine's bundled/default crypto could appear implied | Verify each primitive component and build separately | Backend survey, low-order/RNG/erasure tests | Target resources, component review coverage |

## Decisions and consequences

SEC-1 revision 5 uses abort-first, with the exact event boundary in S3.1. Loss, framing discard, unknown continuation, invalid public structure and conflicting processed-flight duplicates remain cheap drops. Failed admitted Noise processing or failed mandatory post-read checks destroy only the disposable attempt. No response or immediate restart follows failure. A separately bounded establishment scheduler may request a fresh attempt; global/ingress work budgets never reset with an attempt ID.

This avoids mandatory full-state cloning and its RAM/ownership burden. An active injector able to supply an admissible bogus expected flight can terminate that attempt; late authentic continuations then fail to progress. Loss alone retains cached retries. Assess the extra complete exchange, backoff and remote orphan occupancy on the entire path, including scheduled return opportunities. Abort never revokes a committed credential or destroys an unrelated active association. Protected FINISH/READY and transport tag errors keep their own S4/S5/S8 rules.

A maintained upstream implementation, controlled fork, or reviewed C port of standard Noise is eligible. No new primitives, modified Noise token processing, ad-hoc KDF, downgrade or automatic fallback is introduced. A fork needs a named maintenance owner, pinned provenance/licenses, a bounded reviewed patch ledger, upstream security tracking and repeatable vectors/fault/interoperability tests. Translating Rust code is a new C implementation responsibility, not inheritance of Rust's memory-safety guarantees or its test results. The source survey recommends experiments, not a production dependency.

The provider boundary separates DMP framing/reliability, SEC-1 authorization/lifecycle, Noise engine, primitive backend and platform services. Compile-time binding is sufficient; public DMP headers contain neither provider structs nor SDK types. Interface requirements live in the plan; no ABI is frozen by this ADR. Hot paths allocate no heap; bounded setup allocation is not categorically prohibited.

Preserve-state is deferred, not an enabled second policy. Keep one logical receive/post-check/accept boundary, with pin verification inside it. A future transaction may add tentative state there, but cannot roll back CPU/error budgets or elapsed time. It needs its own demonstrated use case, storage/erasure model, tests and explicit pair/path policy. No extra state, flag, numerical policy ID, negotiation or memcpy-clone promise is added now.

## Compatibility and fixtures

Increment main revision 9 to 10 and SEC-1 revision 4 to 5: failure semantics change even though bootstrap framing and standard Noise algorithms do not. Keep BOOT_VERSION=2 because prefix layouts, flight selectors and lengths are unchanged. Exact manifest agreement MUST select the new revisions/semantics; accepting an old digest under the new policy is not compatibility. Reference families advance to DIRECT-1/4 and RADIO-1/4; recovery revision 1 and SAMPLE-1 revision 2 retain their own behavior.

The public vector manifest advances from main=9/sec1=4 to main=10/sec1=5 and explicitly records abort-first. Its PROFILE_HASH, prologue and downstream cryptographic bytes therefore change. Regenerate with the existing hash-checked Cacophony input and independently verify; never hand-edit expected ciphertext. These are byte fixtures, not proof of the new failure state machine. Record baseline/input/output hashes and preserve the original fixed-input check as evidence that no cryptographic algorithm changed.

## Alternatives and reconsideration

- Mandatory preserve-state now: rejected for initial scope because of extra engine/storage/validation cost; reconsider if measured injection/restart costs justify it.
- Unchanged C provider: preferred if it gains required PN/AAD, fallible entropy and bounded storage capabilities without a maintained private delta.
- Controlled C fork: first experiment route if the change set stays smaller and more reviewable than translation; base/backend remain separate choices.
- Narrow Rust-to-C port: reserve route if C ownership/API changes become comparable to rebuilding the engine. Preserve attribution and add independent implementation evidence.
- Rust behind C ABI: comparison alternative if target/toolchain/FFI cost is acceptable. Rust can instead serve only as a host interoperability peer.

No numeric product minimum MCU or latency/RAM promise is selected. Missing target budgets, executable behavior, primitive provenance or independent review blocks the corresponding P01/adoption gate. Source observations, compilation, runtime correctness, MCU measurement and production acceptance remain separate evidence levels.
