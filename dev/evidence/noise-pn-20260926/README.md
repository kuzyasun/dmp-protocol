# PN-01 experiment — 2026-09-26

## Accepted scope

[P00 preparation](p00-acceptance.md) is complete: declared host/MCU configurations,
proposed finite sensitivity envelopes and a working runner. This does not accept
production budgets or a crypto provider. P01 remains running. This wave implements
only the explicit receive-nonce seam, retaining the existing TX/handshake APIs.

The controlled fork starts at `44722c19f7795dd409b46728712067fac87ffc53`.
Changed engine files: `include/noise/protocol/cipherstate.h` (declaration),
`src/protocol/cipherstate.c` (keyed receive wrapper),
`tests/unit/test-cipherstate.c` and `DMP_PATCHES.md`. No primitive, backend,
handshake, KDF or DMP normative bytes changed. Engine/backend source provenance
continues from the [baseline](../noise-baseline-20260926/baseline.json).

`noise_cipherstate_decrypt_with_ad_at_nonce` requires a key, selects the supplied
nonce only for the call, and restores the implicit nonce on every success/error.
The caller serializes access and owns replay checks, narrower SEC-1 PN limits,
failure budgets and delivery. Backend working state is mutable; this is not a
complete-state transaction. Error buffers must never be delivered as plaintext.

## Executed checks

RBO discovery returned `fetch failed`; local fallback used the recorded compilers.
The integrated Windows/GCC 15.2.0 build passed **7/7 CTest entries**; see
[configuration](configure.log), [build](build.log), [summary](ctest-summary.log)
and [full output](ctest-full.log). Logs preserve output content with trailing
whitespace normalized. All new DMP probes use C11 and strict warnings; no emitted
build warning was observed. Existing inherited vector totals remain 52 run and
988 explicitly skipped; disabled algorithms are not passes.

| Requirement | Evidence | Result and limit |
|---|---|---|
| PN2 then PN1, both modes/directions | `dmp_noise_pn_probe` | 32 independent JSON packets decrypt in descending PN order with exact plaintext |
| Invalid high PN isolation | Unit test and PN probe | Bad tag at PN128 then authentic PN1 succeeds; unit also exercises invalid PN100 |
| AAD and tag integrity | Unit test and PN probe | Wrong AAD/tag reject; correct lower/same PN remains usable |
| Implicit nonce preservation | Unit test and PN probe | Old sequential receive works at unchanged zero/nonzero value; exhausted implicit counter stays exhausted |
| Boundaries and validation | Inherited cipher unit additions | Keyless, null/invalid buffers and AD, short/oversized lengths, UINT64_MAX rejection; PN0, UINT64_MAX-1 and empty plaintext succeed |
| TX semantics unchanged | Existing and added unit tests | Old encryption increments its nonce and backward setter rejects |
| Caller-owned replay policy | Unit test and PN probe | Repeated explicit receive authenticates; this is intentionally not replay admission |
| Handshake regression | Existing DMP fixture and inherited suites | Exact NNpsk0/XX flights/hash/Split AEAD remain equal; FAILED/no-resume checks pass |
| Legacy API/DH baseline | `dmp_noise_baseline_probe` | Original monotonic setter limitation and zero-DH behavior remain; this label is not a conformance pass |

The unit packet preparer uses the existing encrypt operation, while the DMP
probe consumes independent JSON ciphertexts and expected plaintext. The latter
uses public fixture direction keys directly to isolate transport decryption;
the existing handshake probe separately verifies real Split contexts.

## Compile-only portability check

Compiled the changed `cipherstate.c` alone with each declared MCU compiler,
`-std=c11 -Wall -Wextra -Wpedantic -Werror -ffreestanding -Os -fstack-usage`,
plus Cortex-M4 `-mcpu=cortex-m4 -mthumb -mfloat-abi=soft`. Both object builds
passed without warnings. Full provider/backend builds, linking and on-target
execution remain pending.

[ARM compiler report](cipherstate-arm.su.txt) gives 16 bytes and
[Xtensa report](cipherstate-xtensa.su.txt) 32 bytes for this wrapper's own frame.
These are compiler estimates excluding callees, interrupts, runtime high-water,
provider state and buffers; they do not establish a DMP RAM budget. No allocation
or new secret storage was added by this wrapper. No allocator/erase measurement
is claimed by compiling it.

## Remaining P01 work

Strict all-zero DH-result rejection before MixKey (including e/static paths),
fallible entropy and storage, bounded allocation and cleanup/erasure, post-read
pin/payload abort, admission/restart/concurrency and both MCU provider/resource
gates remain open. AESGCM and other backends are not tested by this wave. Full
P14 replay/lifecycle and independent DMP interoperability remain later gates.

Recommended next patch is **DH-01**: enforce SEC-1's selected all-zero rejection
without inventing new X25519 decoding rules, then test complete ephemeral and
static paths. Do not mark P01 done from the PN patch alone.
