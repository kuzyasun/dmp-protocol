# RNG-01 experiment — 2026-09-27

Status: RNG-01 accepted for the tested post-initialization host scope after independent review. P01 remains running.

## Frozen implementation brief

The owner authorized continuing with RNG-01. Start from clean parent `a99d7bd`
and fork `c707782`. SEC-1 requires fresh cryptographic entropy and explicit
failure without a transmitted flight, fixed fallback or implicit restart.

- Replace the internal void entropy hook with the distinctly named link-time
  port `int noise_rand_bytes_checked(void *bytes, size_t size)`, declared in
  the public RandState header. Success means all requested bytes were supplied
  from an eligible CSPRNG; return a Noise error on partial/unavailable entropy.
  Ports must be bounded and serialize their own shared resources. No mutable
  global callback registration or vendor SDK dependency is added.
- A dedicated experiment build requires `NOISE_USE_CUSTOM_RAND=1`,
  `NOISE_USE_SODIUM_RAND=0`, and `NOISE_REQUIRE_FALLIBLE_RAND=1`. The requirement
  rejects the infallible sodium default; it is not a fallback path. Old custom
  hooks fail to link because their symbol differs. The void Ed25519 adapter is
  explicitly unsupported rather than swallowing failure.
- Propagate failures through X25519 generation, both public DH generation
  entrypoints and RandState new/reseed/generate/simple/pad. Failed key generation
  erases partial/previous key material and invalidates the key type. RandState
  reseed failure clears generator state and requires explicit successful reseed
  or a new object before reuse; a failed request clears its complete output,
  including bytes produced before an automatic mid-request reseed failure.
- Preserve existing Noise write failure behavior: zero publishable message
  length and FAILED state, with no automatic retry or entropy fallback.
  Fixed fixture keys remain test-only; successful deterministic fixture reruns
  do not establish entropy quality or a complete DMP restart scheduler.
- Adapt built-in OS entrypoints to status returns, checking actual OS success
  and clearing partial bytes. The sodium void RNG wrapper remains only for
  existing host regression configuration and is excluded from the required
  fallible-port build. No new generator, primitive or KDF is introduced.

Coordinator owns production source, interfaces, build registration and acceptance.
Independent workers own only a RandState/DH fault probe and a handshake fault
probe. Test callbacks are linked only into those experiment executables.
Run the existing host suite plus separate custom-port tests on a frozen snapshot;
then obtain independent read-only review before committing locally. No push,
hardware operation, DTrack integration or normative contract change is authorized.

RBO discovery returned `fetch failed`; local host fallback is used. MCU entropy
quality/boot readiness, retained-resource measurements, allocator failures and
complete erasure remain separate open gates.

Source inspection found an additional startup boundary: the pinned libsodium
`sodium_init()` calls its own `randombytes_stir()`, and Noise's existing framework
initializer does not expose all backend initialization failures. The custom
Noise entropy hook controls subsequent Noise requests, not that upstream
startup path. RNG-01 tests begin after successful host framework initialization;
they do not pass cold-boot entropy or no-process-exit requirements for a complete
deployment. Backend/platform initialization must be addressed before P01 can
accept a production combination. No backend initialization is skipped or mocked.

## Executed checks and evidence

The frozen source and both new probes built on the first integrated host attempt:
105 Ninja steps, no emitted build warnings, **10/10 CTest entries passed**.
See [configure](configure.log), [build](build.log), [CTest summary](ctest-summary.log)
and [complete test output](ctest-full.log). Exact commands from the repository root:

```text
cmake -S . -B build/noise-experiments -G Ninja -DCMAKE_C_COMPILER=C:/develop/mingw/w64devkit/bin/gcc.exe -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=C:/projects/gemslibe/dmp-protocol/build/noise-upstream/_deps/esphome_libsodium-1.10021.11
cmake --build build/noise-experiments
ctest --test-dir build/noise-experiments --output-on-failure
```

The inherited vector test ran 52 cases and explicitly skipped 988 unsupported
cases; skipped cases are not passes. The legacy baseline test still reproduces
its expected PN limitation. Existing PN-01/DH-01 and exact fixture probes passed.
All RNG tests use deterministic test-only entropy after actual successful host
framework initialization. No assertion of physical randomness follows.

| Requirement | Concrete check | Result / boundary |
|---|---|---|
| DH failure propagation | `noise_rng_state_probe.c`: both generation APIs, fresh and previously keyed states, partial writes, SYSTEM and NO_MEMORY errors | Exact error preserved; both keys zero and NO_KEY; separately requested later generation succeeds |
| RandState construction/reseed | Failed new leaves NULL; failed reseed rejects generation without another entropy call; explicit reseed recovers | Passed; internal generator erasure is source-reviewed, not a whole-process erasure measurement |
| Complete output discard | Simple generation, pre-request and mid-request automatic reseed failures | Passed; the 1,600,001-byte host request proves a nonzero prefix existed before the injected mid-request failure and the entire output is zero afterward |
| Padding boundaries | Zero/random/no-op padding, invalid state, real automatic entropy failure during random padding | Passed; original bytes and bytes beyond padding remain unchanged |
| No flight after entropy error | `noise_rng_handshake_probe.c`: NNpsk0 and XX, initiator flight 1 and responder flight 2, actual ephemeral generation | Passed; partial key material cleared, message length zero, FAILED, delayed read/write/Split rejected without another RNG call |
| Isolation and fresh recovery | Separate failed and valid attempts, fresh states consuming deterministic entropy through the port | Passed; exact independent fixture flights/hash and both Split directions still match; no DMP restart scheduler is implemented |
| Build configuration | [configuration checks](configuration-checks.json) | Required custom port compiles; required sodium RNG and mixed RNG configurations fail as expected |
| Portable wrappers | [compile commands](compile-checks.json), six `.su.txt` outputs | Cortex-M4 and Xtensa compile-only for DH/RandState wrappers and custom-mode rand_os; not a full MCU provider link/runtime or stack budget |
| Windows OS adapter | [OS compile](os-compile-check.json) | Final source compiled with strict host warnings; no OS fault injection/runtime acceptance |

The MCU invocation initially failed for missing generated sodium/version.h and
then PowerShell splitting unquoted dotted include paths. Adding the existing
port_include directory and passing literal argument arrays resolved those
invocation errors; no production code was changed to hide them. The inherited
handshake unused-parameter build issue from DH-01 remains open. Custom-mode
rand_os has no active OS implementation, so its empty stack reports prove no
OS behavior. Alternative reference-DH/OS ports are not runtime accepted.

[Baseline](baseline.json) records the clean starting commits and normative
hashes; [backend pins](backend-pins.json) identify the unchanged prepared backend
working trees. [Code snapshot](code-review-snapshot.json) freezes all ten fork
files. The final review snapshot records tests, registration and evidence as
actually executed. Text logs have only trailing whitespace/EOF normalization.

## Remaining acceptance

P01 remains running. Required work includes backend/platform startup failure
propagation and cold-boot entropy, production port quality and boundedness,
storage/allocation/cleanup, cached-flight and lifecycle cases, independent live
interoperability, and complete MCU resource evidence. Host partial-output checks
do not prove erasure of all secret copies. The opaque RandState layout and custom
entropy hook ABI changed; no production layout is frozen. Next recommended wave:
**INIT-01**, the backend/platform initialization boundary, before claiming the
complete entropy gate. No normative document changed.

## Independent review and local pin

`/root/dh_final_review` (GPT-6 Astra, max) independently checked all ten fork
files and 21 final test/evidence entries, seven normative hashes and both
backend tree digests. It found no actionable defect and confirmed the stated
post-init boundary; it did not rerun builds/tests. See [review result](review-result.json).
The coordinator committed the unchanged reviewed source locally as `0d86934919dc9220eaa49574bc9b22f0abe972b2`.
The parent CMake pin was updated and configuration passed again. The original
snapshots retain reviewed hashes; only that pin and acceptance/status metadata
changed afterward. No push, hardware operation or production adoption occurred.
