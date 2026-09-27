# Pre-implementation concurrency constraints

Read-only investigation by `parallel_audit` (GPT-6 Luna, xhigh), checked against
the pinned Noise-C `c40f2dc` / sodium port `40c22448` / libsodium `d24faf56`.
This is source reasoning, not a runtime pass or general thread-safety guarantee.

- Noise handshake working state and child DH/hash/cipher states are instance
  owned (`src/protocol/internal.h`, sodium backend `dh-curve25519.c`,
  `hash-sha256.c`, `cipher-chachapoly.c`). The selected ChaChaPoly fast path
  uses per-cipher session state and call-local temporary storage.
- Sodium CPU feature and primitive dispatch selection is mutable global state
  initialized during `sodium_init`; no later lazy dispatch write was found in
  the selected SHA256/Curve25519/ChaChaPoly paths. Noise is compiled with
  `NOISE_USE_PTHREAD=0`: initialize once successfully before creating workers,
  and do not concurrently reinitialize/reselect primitives.
- Custom allocator callbacks have no owner argument. Route by a permanently
  bound worker identity, using private arenas. Do not swap a global current
  arena or move live contexts between workers. Operations on an individual
  Noise context remain serialized (also required by the fork patch ledger).
- The previous console has file-static scratch/arena/owners and a serialized
  entropy adapter. It must not be invoked from the two new workers. The new
  ESP adapter must lock the complete ADC entropy enable/read/disable region.

The coordinator implements these constraints in an isolated private probe.
Backend adoption, unsupported algorithm combinations, shared-context callers
and arbitrary allocator/task topologies are outside this evidence.
