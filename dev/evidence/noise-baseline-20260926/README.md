# Initial Noise-C experiment wave — 2026-09-26

## Scope and provenance

The owner authorized a local documentation commit, adding
`https://github.com/kuzyasun/noise-c` as a submodule and starting experiments.
Documentation was committed as `c9dabbf72746bb20bebe3546bf4ce5aa8b967a3d`.
The submodule at `third_party/noise-c` points to the inspected ESPHome ancestor
`44722c19f7795dd409b46728712067fac87ffc53`. Its local working branch is
`codex/dmp-provider-experiments`; no engine changes are part of this wave.
No push, production adoption, DTrack integration or hardware action is authorized
by this record.

[Baseline](baseline.json) records exact engine/backend revisions, aggregate
working-source hashes, normative hashes, tools and enabled algorithms. Engine:
MIT; ESPHome sodium port: MIT; libsodium: ISC root license with inherited
component notices. The existing component survey remains relevant; a complete
selected-source licensing/security audit is still required before adoption.
The expected dirty nested sodium tree consists of the port's upstream patches,
not DMP primitive changes. Hashes cover those resulting bytes too.

## Execution and evidence boundaries

RBO discovery failed with `fetch failed`. Local Windows compilation was used as
the documented fallback. The sandboxed compiler ABI probe stalled; retry outside
the sandbox succeeded. No global toolchain configuration was changed.

- Host scaffold: strict C11 GCC 15.2.0, 2/2 CTest checks passed; see
  [scaffold log](scaffold-ctest.log).
- Unchanged Noise-C: build succeeded; inherited unit/vector tests passed 2/2;
  see [upstream log](upstream-ctest.log). Cacophony ran 36 and skipped 540;
  basic ran 15 and skipped 225; fallback ran 1 and skipped 15; hybrid ran 0
  and skipped 208. Both mandatory NNpsk0/XX ChaChaPoly names ran successfully.
  The 988 skipped entries are not passes. AESGCM is disabled here.
- Initial ESP reference tool discovery: `eim run "idf.py --version"` reported
  ESP-IDF v6.0.2. No ESP provider build or execution occurred.
- Additional portable compile configuration: Cortex-M4, ARMv7E-M Thumb-2,
  soft-float EABI5, GCC 13.3.1. Only `host_environment.c` was compiled with
  `-ffreestanding -c`; readelf confirmed ELF32 ARM. This checks the toolchain,
  not the provider, linking, memory budget or MCU runtime.

Commands and generated-header workflow for candidate probes are in the
[provider test README](../../../tests/provider/README.md).

The integrated opt-in build passed **6/6** CTest entries: fixture verifier,
scaffold, two DMP probes and inherited unit/vector tests. See
[summary](ctest-summary.log), [full results](experiments-ctest.log),
[configuration](configure.log) and [final incremental build](build-final.log).
The first build exposed a Python literal-brace formatting error in the new
header generator; it was corrected before the successful build. The failure is
retained in [initial build log](build-initial-failure.log).

| Probe | Observed result | Acceptance meaning |
|---|---|---|
| NNpsk0 and XX, ChaChaPoly | Exact flights, decrypted payloads, both full hashes and role-correct Split AEAD match independent public fixtures | Candidate byte equivalence for these fixtures only |
| Corrupted final authenticated flight in each mode | MAC failure, FAILED action, authentic retry returns invalid-state and remains FAILED | Engine abort boundary only; no scheduler, pin/storage or erase proof |
| Ordered ChaChaPoly with nonempty AAD | Both packets authenticate with exact plaintext | Positive control |
| Authentic PN2 then PN1 | PN2 authenticates; selecting PN1 rejects; fresh independent receiver authenticates PN1 | Existing monotonic API fails the SEC-1 unordered receive requirement |
| Invalid PN100 then authentic PN3 | Bad tag rejects, lower nonce cannot be selected; fresh receiver authenticates PN3. Original PN100 then authenticates without resetting the failed candidate nonce | Invalid-high-PN isolation fails with this setter; not a passed capability |
| Literal-zero and low-order u=1 X25519 | Literal zero returns success/all-zero result; u=1 returns invalid-parameter | Public DH seam lacks SEC-1 strict rejection; no claim that full XX static attack paths were exercised |

The baseline probe uses an `expected-limitations` label and explicitly prints
`NOT SEC-1 CONFORMANT`. Its zero exit status asserts the incompatibility remains
reproducible; it is not counted as a passed P01 security requirement.

## Experimental limits and remaining gates

This first wave compares exact bytes and public API behavior, not performance.
It uses fixed public fixture inputs and serialized calls. No networking, threads,
application services, enrollment, timers, replay window or restart scheduler is
implemented. Fixed test buffers are not a production RAM budget. The host sodium
RNG is enabled by upstream tests; injected deterministic ephemeral pairs do not
demonstrate a fallible production entropy port.

P00 remains `running`: initial toolchains and scaffold are verified, but target
memory regions, numerical envelopes/sensitivity configurations and the remaining
resource experiment preparation are open. P01 remains pending its dependency
and full gate. These preparatory characterization tests must not be counted as
completion of P01. No downstream package is opened.

Next bounded work: define experimental resource envelopes separately from
product claims; introduce and independently review explicit receive-PN and
strict DMP DH-result handling in the controlled fork, then extend entropy,
allocation, erase and e/static failure tests. Keep the baseline tests or an
equivalent baseline executable so the before/after difference is reproducible.
Production envelopes, both MCU provider builds/resource evidence, and the full
abort-first checklist stay open.
