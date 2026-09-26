# Confirmed backend startup boundary

This is an inspection and diagnostic of the exact source identified in
[backend pins](backend-pins.json), not a new backend adoption decision. Backend
files were not edited. The coordinator verified the source findings from the
independent read-only `init_backend_survey` worker against actual code and the
Windows subprocess reproduction.

## Actual path

Relative to the nested libsodium `src/libsodium/`:

- `sodium/core.c:45-75`: sodium_init enters its critical section; returns -1 for
  reported lock failures, 1 when already initialized, otherwise detects CPU
  features, calls void randombytes_stir and _sodium_alloc_init, selects primitive
  implementations, sets initialized, leaves the critical section and returns 0.
- `sodium/utils.c:405-426`: _sodium_alloc_init unconditionally obtains allocator
  canary bytes through void randombytes_buf. Fixing only stir would miss this.
- `randombytes/randombytes.c:38-52,79-85,144-150`: the library owns a process-global
  implementation pointer. Its stir/buf callbacks return void; selecting a custom
  implementation does not create a checked failure channel.
- `randombytes/sysrandom/randombytes_sysrandom.c:289-300,360-366`: on Windows,
  system RNG initialization itself is a no-op. The subsequent canary fill calls
  RtlGenRandom (SystemFunction036); FALSE invokes sodium_misuse.
- `sodium/core.c:203-218`: sodium_misuse calls an optional handler and then aborts.
  A handler that returns cannot make initialization return an error.
- POSIX source paths also invoke sodium_misuse on unavailable RNG devices or
  failed reads. This is source inspection only, not a POSIX runtime test.

The actual Windows experiment produced one OS RNG request on healthy startup
and a real SIGABRT on injected OS failure, before noise_init_framework returned.
The diagnostic intercepts SIGABRT only to terminate the child with code 86 and
avoid interactive crash reporting. It neither resumes nor accepts that child.

## Consequence and next work

The Noise wrapper fix is necessary but insufficient. A checked Noise init hook
that simply calls current sodium_init would preserve the same failure path.
A no-op stir callback, prechecking entropy, or recording an error beside void
callbacks also fails to propagate the later canary failure before initialization
is accepted. Skipping sodium initialization loses its other required setup.
No such workaround is adopted.

Recommended next experiment: a small, maintained, separately reviewed backend
startup integration with a checked platform entropy contract covering **both**
startup RNG readiness and allocator-canary bytes. It must keep primitive setup,
return failure before publishing successful initialization, define terminal
failure/retry and concurrency semantics, and prove partial-output cleanup.
Track the patch against the pinned ESPHome/libsodium source with its licenses
and change ledger; do not hand-edit the ignored fetched tree or create another
algorithm. A platform-specific wrapper alone is not sufficient with this backend.

This changes the maintained backend integration surface and requires its own
source review and full provider reruns. The current wave stops at the confirmed
Noise error-propagation fix plus executable backend blocker. Full P01 startup,
MCU entropy quality, bounded work and production-provider acceptance stay open.
