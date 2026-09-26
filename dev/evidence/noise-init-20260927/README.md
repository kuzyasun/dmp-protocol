# INIT-01 startup boundary experiment - 2026-09-27

Status: INIT-01 returned-error handling accepted after independent review. Full backend startup acceptance remains open with a reproduced failure.

## Plan and frozen scope

Start from clean parent 3b5338f and fork 0d86934. Fix the confirmed Noise wrapper
bug that discards a returned sodium_init failure. Keep real backend initialization
in the normal path, accept sodium's successful 0 and already-initialized 1,
and map negative results to NOISE_ERROR_SYSTEM. Pthread-once must retain the
initializer result rather than returning success merely because once completed.
Non-pthread callers retain explicit per-call initialization and must serialize
startup; pthread callers retain the one-shot outcome, including failure.
Callers must require success before using Noise or separately initialize their
backend; this patch does not add global admission checks to every API.

A dedicated test compiles the real util.c with only its sodium_init symbol
renamed to a test stub. Separate processes inject negative/zero/positive returns
for pthread and serialized configurations. This proves the wrapper's result
handling only. Existing full Noise/RNG/PN/DH tests still call real sodium_init.
No fake initialization is used to claim backend entropy or cold-boot success.

Coordinator owns production files, registration, evidence and final acceptance.
One worker owns only tests/provider/noise_init_probe.c. Independent review follows
frozen source and actual results. No normative change, primitive change, backend
patch, push, hardware operation or DTrack integration in this bounded wave.

The second issue is being traced separately: libsodium's void randombytes_stir
and allocator-canary randombytes_buf cannot return entropy errors. Do not hide
it with a no-op RNG, global callback plus error flag, skipped initialization,
longjmp, fallback bytes or a Noise wrapper mock. Record exact upstream boundaries
and the next required backend decision. P01 remains running.

RBO discovery returned fetch failed; use local host fallback.

## Actual checks

The first integrated configure/build/test attempt passed: 73 Ninja build steps,
no emitted build warnings, and **17/17 CTest invocations**. Six new invocations
check wrapper return handling. One new `expected-limitations` invocation
reproduces the backend's abort on OS RNG failure. Its green test result means
the blocker was reproduced, not that startup safety passed. The existing
legacy PN limitation is also still labeled separately. Inherited vectors ran
52 cases and skipped 988; all previous PN/DH/RNG and fixture probes passed.

Commands from the repository root:

```text
cmake -S . -B build/noise-experiments -G Ninja -DCMAKE_C_COMPILER=C:/develop/mingw/w64devkit/bin/gcc.exe -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=C:/projects/gemslibe/dmp-protocol/build/noise-upstream/_deps/esphome_libsodium-1.10021.11
cmake --build build/noise-experiments
ctest --test-dir build/noise-experiments --output-on-failure
```

See [configure](configure.log), [build](build.log), [CTest summary](ctest-summary.log)
and [full test log](ctest-full.log). The normal suite still initializes the real
backend; only the explicitly labeled wrapper tests rename sodium_init.

| Requirement | Executable evidence | Boundary |
|---|---|---|
| Returned backend error is visible | Serial `failure`, three explicit calls each returning SYSTEM with one backend call per invocation | Stub injects returned -1; no real RNG failure claim |
| Successful init and already initialized | Serial default/`already`, injected 0/1 | Both map to NONE, preserving backend contract |
| Once result is not silently changed | Pthread default/`already`/`failure`, eight callers and two later calls | All see the same result; exactly one backend invocation; failure is retained |
| Real startup still succeeds | Existing full suite and diagnostic healthy subprocess | Healthy diagnostic reached actual OS RNG once and returned NONE |
| OS entropy failure does not return locally | Diagnostic failing subprocess uses real sodium_init with OS RNG returning FALSE | Observed real SIGABRT before Noise returned; **full startup gate fails** |
| Portable source build | [Exact compile checks](compile-checks.json), ARM/Xtensa stack reports | Only serialized util.c objects, not MCU provider/runtime/stack-budget acceptance |

The Windows diagnostic uses GNU linker interposition on SystemFunction036;
other hosts report it unavailable rather than counting it as passed. Pthread
tests similarly require available pthread headers/library. The subprocess
SIGABRT handler calls _Exit(86) solely for safe test supervision. It is not
linked into normal probes or production and does not catch/recover in-process.
No platform SDK dependency was added to the portable source.

[Backend boundary](backend-boundary.md) explains the exact remaining failure
path and recommended next experiment. [Baseline](baseline.json) records initial
clean source state and normative hashes; backend digests match the previous
wave. Final snapshot hashes identify the actual files reviewed/tested. Logs
were normalized only for trailing whitespace and final newline.

## Remaining gates

Only Noise's handling of a **returned** initialization error is fixed here.
The full startup/cold-boot/no-process-exit gate remains open, with an executable
counterexample. Callers must require init success; constructors do not enforce
that precondition automatically. OpenSSL/reference modes, pthread_once's own
error return injection, real MCU entropy quality/readiness, bounded startup,
full erasure/storage/allocation and complete resource measurements remain open.
P01 stays running. Next: the reviewed checked backend startup integration in
backend-boundary.md; no backend change is silently included in this patch.

## Independent review and local pin

`/root/dh_final_review` (GPT-6 Astra, max) verified 3 production and 17 final
snapshot entries, 7 normative hashes, baseline commits and both backend tree
digests. No actionable finding was reported. It reviewed recorded execution
without running builds/tests. The coordinator accepted only the returned-error
handling fix, retaining the demonstrated startup blocker.

The unchanged reviewed fork was committed locally as `cfb45b9041d174b3e3106333235c87af47dcb425`.
Updating the parent CMake engine pin and reconfiguring passed. Only the pin and
acceptance metadata changed after the reviewed snapshots. See
[review result](review-result.json). No push or hardware action occurred.
