# Noise candidate experiments

These host-only tests characterize the controlled Noise-C candidate and its receive-PN, strict-DH and checked-entropy patches. They do not select
a production provider or pass P01. Public fixture keys are test-only.

The submodule is the owner's fork of ESPHome Noise-C, pinned by the superproject
gitlink. The original baseline is `44722c19f7795dd409b46728712067fac87ffc53`;
the current exact expected pin is in `noise_experiment.cmake`. The fork retains
a patch ledger in `DMP_PATCHES.md`. Never use a floating branch for tests.

## Minimal scaffold

`host_environment.c` checks C11 integer assumptions and CTest execution;
`fixtures.sec1` runs the existing independent fixture verifier unchanged.
Neither check satisfies P01. CMake 3.20+, a C11 compiler and Node.js are required:

```text
cmake -S . -B build/host -DDMP_BUILD_TESTS=ON
cmake --build build/host
ctest --test-dir build/host --output-on-failure
```

Multi-configuration generators need matching `--config Debug` / `-C Debug`.
`DMP_BUILD_TESTS=OFF` configures no library or tests. The private
`dmp_add_provider_experiment` runner applies strict warnings and a 30-second
timeout; it is not a public provider ABI. A capability test must fail on a
missing requirement. The separately labeled baseline limitation test below
asserts an incompatibility and cannot be counted as a capability pass.

## Reproduce on a host

Initialize the submodule, then run the pinned fork's inherited tests first.
This explicit upstream configuration downloads its sodium dependency and applies
the upstream port patches inside the ignored build directory. It needs Git,
CMake >= 3.14, Ninja, a C compiler and `sh` for the patch script.

```text
git submodule update --init third_party/noise-c
cmake -S third_party/noise-c -B build/noise-upstream -G Ninja -DNOISE_C_BUILD_TESTS=ON
cmake --build build/noise-upstream
ctest --test-dir build/noise-upstream --output-on-failure
```

Then build DMP's opt-in probes using that prepared source, without another fetch.
Use an absolute path for `DMP_SODIUM_SOURCE_DIR`.

```text
cmake -S . -B build/noise-experiments -G Ninja -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=<repo>/build/noise-upstream/_deps/esphome_libsodium-1.10021.11
cmake --build build/noise-experiments
ctest --test-dir build/noise-experiments --output-on-failure
```

Both configurations must use the same intended host compiler. The recorded
Windows run adds `-DCMAKE_C_COMPILER=C:/develop/mingw/w64devkit/bin/gcc.exe`.
The second configuration requires Python 3.10+ (standard library only) and Node.
It verifies engine, backend-port and nested libsodium commit IDs, rebuilds both
libraries from source, and requires the patched sodium fast path at compile time.
Commit checks do not prove a clean working tree; retain source hashes and review
any local source changes with the run evidence. Backend patches are expected
working-tree changes. Never point the upstream fetch/patch workflow at a checkout
containing personal edits.

Default root builds keep these experiments disabled and fetch no provider.

## What a pass means

- `dmp_noise_fixture_probe`: exact independent DMP ChaChaPoly NNpsk0/XX fixture
  flights, payloads and hashes, role-correct Split checked through FINISH/READY
  AEAD bytes, and the engine's destructive read-error boundary. FINISH/READY
  bytes do not test enrollment or association activation.
- `dmp_noise_pn_probe`: the new explicit-nonce receive API decrypts independent
  public fixture packets out of order. It checks invalid-high-PN isolation,
  wrong AAD/tag and retention of the old implicit receive counter. Repeated
  explicit receive is allowed here; DMP replay handling remains separate.
- `dmp_noise_baseline_probe` (`expected-limitations`): the retained legacy
  monotonic API still has its original limitations; sequential AEAD works,
  while the current monotonic nonce API cannot implement unordered receive;
  DH-01 now requires literal-zero and u=1 rejection with cleared outputs.
  Success means the recorded limitation was reproduced, **not** that SEC-1 passed.
- `dmp_noise_dh_probe`: real-backend low-order ephemeral/static handshake
  rejection, FAILED-state continuation/Split refusal and independent fresh
  valid states. Internal manipulation is confined to constructing malicious
  test messages; the receiving DH backend is unchanged.
- `dmp_noise_rng_state_probe`: checked-port failures through both DH generation
  APIs and RandState creation/reseed/generate/simple/pad. Checks invalidation,
  exact errors, partial-key cleanup and complete output clearing even when an
  automatic reseed fails after output has already been generated.
- `dmp_noise_rng_handshake_probe`: actual NNpsk0/XX ephemeral generation failures
  at initiator/responder writes, zero publishable flight, FAILED/no-resume,
  independent attempt isolation and fresh exact fixture/hash/Split recovery.
  Fixture ephemerals enter through the test entropy port, not fixed-key setters.
- `dmp_noise_init_serial_probe` and `dmp_noise_init_pthread_probe` (three cases
  each): the real Noise wrapper compiled with an injected sodium_init symbol
  propagates returned failures and retains pthread-once outcomes. These are
  wrapper fault tests, not real backend startup-failure acceptance.
- `dmp_noise_init_backend_abort` (`expected-limitations`, Windows/GNU only):
  healthy actual startup succeeds; an injected OS RNG failure reaches real
  backend SIGABRT in a supervised subprocess. A pass reproduces the blocker.
  [INIT-01 evidence](../../dev/evidence/noise-init-20260927/README.md) records why
  full startup/cold-boot acceptance remains open.
- Inherited `unit`/`vectors`: upstream regression evidence only. Disabled suites
  are explicitly skipped, not passed. AESGCM is disabled in this configuration.

The probes use serialized operations and bounded test buffers. They are neither
endpoint implementations nor resource measurements. The RNG probes link a
separate `dmp_noise_fallible_entropy` build requiring the checked custom port;
the inherited regression library keeps its legacy sodium RNG configuration.
Both invoke real host framework initialization before testing. The backend's
`sodium_init()` still accesses its own RNG outside the checked Noise port:
startup/cold-boot failure and production entropy quality remain open. See the
[RNG-01 evidence](../../dev/evidence/noise-rng-20260927/README.md).
Storage failure,
allocation/erasure, full endpoint attack paths, admission/restart budgets, MCU
resources and independent live interoperability remain separate acceptance work.
The full [P01 checklist](../../dev/DMP_Implementation_Plan.md#abort-first-provider-experiment-before-p01-acceptance)
remains required before production layouts are frozen.

## Experimental resource configurations

[experiment_manifest.json](experiment_manifest.json) freezes P00 test-only
target settings, finite envelopes and sensitivity rows. These are inputs for
P01 measurements, not validated deployment profiles. `targets/cortex-m4.cmake`
is archive-only; `targets/esp32s3/sdkconfig.defaults` is for a future isolated
IDF project. No MCU provider build or resource pass is implied by these files.


## Checked backend startup experiment

BINIT-01 adds a separately built, hash-pinned two-file startup patch and checked
platform entropy contract. It returns readiness/canary-read failures before
successful initialization, clears partial canary bytes and permits an explicit
later retry. The original backend and its abort reproduction remain unchanged.

[Backend integration and license](backend/README.md) describe the maintained
patch, source preparation and excluded legacy RNG APIs. [Evidence](../../dev/evidence/noise-backend-init-20260927/README.md)
records deterministic and Windows OS failure tests, exact Noise/PN/DH/RNG reruns
and inherited unit/vector regression on the checked backend. No production
entropy quality, MCU runtime/resource or complete P01 acceptance follows.
