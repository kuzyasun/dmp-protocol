# P00 acceptance and P01 receive-PN brief

Coordinator acceptance: P00 preparation complete on 2026-09-26. This accepts
scope, provenance screening, declared experiment configurations and a working
runner. It does not accept a provider or production resource envelope.

## Evidence and decisions

- Parent starts clean at `f649853`; fork starts clean at
  `44722c19f7795dd409b46728712067fac87ffc53`. [Baseline](baseline.json) preserves
  exact normative and configuration hashes. Earlier baseline/index history is
  retained in the execution log; no existing work was reset.
- Main revision 10, SEC-1 revision 5, BOOT_VERSION 2 remain the normative inputs.
  Exact fixtures and independent source screening are already recorded in the
  [previous wave](../noise-baseline-20260926/README.md) and provider survey.
- Windows/GCC 15.2 C11 host runner passed; default root builds fetch no provider.
  Unmodified candidate and backend pins, licenses, component caveats, feature
  choices and 6/6 scoped tests are recorded there. No result is promoted from
  source review or a skipped vector to an executed provider capability.
- ESP32-S3 uses ESP-IDF v6.0.2 / Xtensa GCC 15.2.0
  `esp-15.2.0_20251204`; the actual compiler version was read locally. Initial
  mutable storage is internal DRAM with no PSRAM; the SDK linker script owns
  shared IRAM/DRAM layout. Proposed compile configuration uses 4 MiB flash.
- Non-Espressif reference is Cortex-M4, Thumb-2 EABI5, little-endian soft-float,
  GCC 13.3.1. The earlier scaffold compiled. The new toolchain file freezes
  archive-only flags; a physical board map is required before linking/runtime
  claims. This explicitly retains the prior M4/soft-float choice, rather than
  implying a hard-float M4F ABI.
- [Experiment manifest](../../../tests/provider/experiment_manifest.json)
  supplies finite 16/32/64 KiB RAM and 128/256/512 KiB linked-flash sensitivity
  envelopes, their accounting partitions, admitted peers/services/associations,
  pending attempts, distinct crypto slots, application concurrency and future
  path parameters. These are coordinator-selected experiment bounds, not
  measured capacity, validated deployment profiles or product minima. Each envelope
  and each peer/service/association/attempt/slot/application count applies to one
  endpoint instance. Coexisting roles/modes share that endpoint total; the RAM of
  remote endpoints is evaluated independently, never summed against one envelope.
- Scope without further owner decisions is sufficient for experiments. Actual
  product boards, complete P03 deployment manifests and proven production
  budgets remain open at their own gates. Resource sweeps and provider target
  builds are P01 work; declaring their inputs does not claim execution.

## Frozen first P01 patch boundary

Add `noise_cipherstate_decrypt_with_ad_at_nonce(state, nonce, ad, ad_len, buffer)`
to the controlled fork. It requires an initialized key and decrypts using the
caller-supplied 64-bit Noise nonce, preserving the implicit cipher nonce on
success and every error. The reserved `UINT64_MAX` remains invalid. Existing
sequential cipher operations, the monotonic setter, encryption and rekey stay
unchanged. No allocation, new primitive, KDF, wire field or raw-key export.

This API is receive-only and requires exclusive serialized access to the state,
including its mutable backend working state. It is not an atomic/thread-safe
primitive. Replay admission, SEC-1's narrower PN ceiling, failure budgets and
plaintext delivery belong to the caller. Input is mutable in place; only success
produces usable plaintext. Error buffer handling retains the underlying decrypt
contract and must not be described as preserving the complete cipher context.

Checks: authentic PN2 then PN1; invalid high PN followed by authentic lower PN;
nonempty/wrong AAD, modified tag, empty payload, reserved nonce, missing key,
null/invalid buffers and lengths; implicit-counter preservation after success
and each error; old TX monotonic behavior unchanged. Repeated explicit receive
is allowed at this primitive layer, proving the caller must enforce replay.
Keep inherited vectors and exact DMP fixture tests green. Independent review
must examine the actual source delta and execution evidence before accepting
this patch. Full P01 remains open, including strict DH, entropy, storage,
allocation/erase, admission/restart/concurrency and MCU resource evidence.

## Proposed controlled-fork patch ledger

| Item | Scope | State at P00 acceptance |
|---|---|---|
| PN-01 | Keyed explicit receive nonce/AAD operation, unchanged TX API | Ready for implementation and review |
| DH-01 | SEC-1 all-zero-result rejection before MixKey, e/static paths | Pending separate patch; no primitive rewrite |
| PORT-01 | Fallible entropy, bounded setup/storage and cleanup | Pending ownership/failure experiments |

The DMP project owns its fork changes and upstream tracking. Component license
and primitive review gaps remain adoption requirements, not waived by P00.


## Configuration verification

CMake configured the root scaffold with `DMP_BUILD_TESTS=OFF`, the recorded ARM
compiler and `tests/provider/targets/cortex-m4.cmake`; compiler ABI detection
passed using a static library. The first invocation omitted quoting around the
PowerShell `-D` toolchain argument and was rejected before configuring; the fully
quoted absolute path succeeded. A standard-library JSON check verified all
three envelope sums and the finite peer/crypto-slot counts. No provider linking
or resource measurement is inferred from these preparation checks.
