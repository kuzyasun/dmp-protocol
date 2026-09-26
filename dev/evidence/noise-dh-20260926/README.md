# DH-01 experiment — 2026-09-26

Status: DH-01 accepted for the tested host sodium configuration after independent
read-only code and evidence review; P01 remains running. The local fork commit
is `c707782972b9c9015a8a1ba06724a07572306d50`. See [review result](review-result.json).

## Scope and plan

SEC-1 S1 requires rejection of an all-zero X25519 shared result before MixKey,
propagation of backend errors and standard X25519 input decoding. The owner
authorized this next bounded P01 patch. P00 is complete; P01 remains running.

1. Make the fork's X25519 DH operation reject successful all-zero results and
   preserve backend errors instead of the inherited literal-null success rule.
   Leave other DH algorithms outside this patch's selected policy.
2. Skip handshake MixKey on DH failure, propagate MixKey failure and always
   clean the temporary shared-secret buffer. Preserve normal Noise transitions.
3. Verify result-level rejection with an internal fake backend, and exercise
   real low-order ephemeral/static paths through the sodium-backed engine.
   Confirm failed attempts cannot continue/Split and fresh valid states work.
4. Run the complete existing host experiment suite, inspect actual diffs and
   obtain independent read-only review before accepting the patch.
5. Commit only reviewed local changes and pin the fork revision; do not push.

Coordinator owns production source, registration, documentation and acceptance.
Two workers own disjoint test files: inherited DH/handshake units and the new
host DH probe. No normative document, primitive or KDF change is intended.

RBO discovery returned `fetch failed`; host validation will use local fallback.
This wave does not close entropy/storage/allocation/erasure/resource gates,
prove full endpoint lifecycle, or establish MCU runtime behavior.

## Changes and executed evidence

The only production changes are the X25519 result-policy branch in
`dhstate.c` and the guarded MixKey call in `handshakestate.c`. The public
function signature and standard X25519 decoding are unchanged. The existing
null-success behavior is deliberately removed for X25519; other algorithms
are unchanged and are not accepted DMP configurations. Backend working-tree
digests still match the initial experiment; see [pins](backend-pins.json).

The coordinator inspected the actual test changes and corrected a missed
post-recreation null-vector expectation before building. The first build then
found two errors in the new probe: const plaintext passed to a mutable-buffer
macro and stale `fixture->name` access after a helper became string-based.
The final probe copies plaintext into a bounded mutable buffer and uses the
correct string argument. [Initial build](build.log) retains the failure;
[final build](build-final.log) passed with no emitted warnings. No production
source changed in response to these test-code errors.

Integrated Windows/GCC 15.2.0 CTest passed **8/8 entries** in 1.22 seconds:
[summary](ctest-summary.log), [full output](ctest-full.log). Commands are the
existing `tests/provider/README.md` host flow, with the pinned prepared sodium
path and compiler recorded by the [configuration](configure.log) and logs.
All DMP probes use C11 `-Wall -Wextra -Wpedantic -Werror`; inherited targets
retain their existing build flags. Inherited vectors still execute 52 and
skip 988; skipped algorithms and the expected legacy-PN limitations label
are not capability passes.

| Requirement | Executed test and result |
|---|---|
| Result rejection independent of input prechecks | Unit fake backend receives valid nonzero public input, returns success+zero; API rejects with INVALID_PUBLIC_KEY and clears output |
| Exact backend error and cleanup | Unit fake backend returns NO_MEMORY plus nonzero partial output; error is preserved and output cleared; successful nonzero output passes through |
| No MixKey after DH failure | NN unit read/write fault injection observes unchanged chaining key, unkeyed cipher and nonce, FAILED action, blocked continuation and Split |
| Real low-order X25519 inputs | DH probe checks u=0/u=1 and both high-bit aliases: exact sodium INVALID_PARAM and zeroed result |
| Standard decoding retained | Unit fixed RFC vector and probe accept u=9, high-bit alias and noncanonical p+9 with equal results |
| Ephemeral failure paths | NNpsk0 literal-zero e rejects early; authenticated u=1 e reaches responder-write EE; XX u=1 e reaches initiator-read EE |
| Authenticated static failure paths | XX flights 2/ES and 3/SE each carry encrypted s=0 and s=1; receiver decodes exact remote s and returns sodium DH error, not a MAC/length failure |
| No failed-attempt continuation | Valid replacement flights/next writes and Split reject on failed states; separately created NNpsk0 and XX states still match fixtures and Split |
| Regression | Existing exact flight/hash/Split fixture probe, PN-01 probe, inherited unit/vector suites and fixture verifier pass |

Malicious-message construction changes only a test sender's advertised public
key while retaining its private scalar. The real sender encrypts the static
field; the receiver uses the unmodified production backend. These are controlled
engine tests, not an independent peer implementation or a DMP restart scheduler.
Fixed public credentials and ephemeral reuse between test cases are fixture-only.

## Portability boundary

The changed `dhstate.c` translation unit compiled for Cortex-M4 and ESP32-S3
with strict C11 warnings. Reports are [ARM](dhstate-arm.su.txt) and
[Xtensa](dhstate-xtensa.su.txt); stack frames exclude callees and do not establish
runtime high-water or total provider memory.

The stricter ARM check of `handshakestate.c` failed at two inherited unused
parameters (`prefix_id`, `role`), reproduced from the pre-patch fork HEAD.
See [baseline failure](handshake-baseline-strict-compile.log) and
[commands/limits](compile-checks.json). This check remains unresolved; Xtensa
handshake compilation was not run after that failure. No warning suppression
was added. Full MCU provider builds, linking and runtime checks remain pending.

## Remaining work

P01 remains running: fallible platform entropy, storage/allocation failures,
complete secret cleanup, pin/payload post-check abort, bounded admission/restart
and MCU resource gates are not closed by DH-01. The recommended next bounded
patch is RNG-01: an explicit fallible entropy path with no transmitted flight
or fallback RNG after failure, followed by lifecycle/cleanup fault tests.
