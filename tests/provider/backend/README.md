# Checked libsodium startup experiment (BINIT-01)

This directory owns an experimental startup integration for the pinned
ESPHome/libsodium backend. It is not a production dependency selection or a
change to SEC-1. The coordinator owns the patch and its acceptance; repeat the
provider gate whenever patch, engine, backend or build configuration changes.

## Provenance and reproducibility

- ESPHome sodium port: 40c22448d6e8f42be56c45f739b52a5c8d21c8ca.
- Nested libsodium: d24faf56214469b354b01c8ba36257e04737101e, with the original
  ESPHome port patches already applied by the inherited preparation workflow.
- [LICENSE.libsodium](LICENSE.libsodium) preserves upstream ISC attribution.
- [inputs.json](inputs.json) pins the two original translation units. Pins
  normalize only CRLF to LF so equivalent Windows/Unix source is accepted;
  the generated report records both actual raw and normalized source hashes.
- [checked-init.patch](checked-init.patch) modifies only startup core.c and
  allocator setup utils.c. No crypto primitive or Noise token processing changes.

The CMake experiment invokes prepare_checked_sodium.py, verifies input hashes,
copies the two files to temporary storage outside Git, validates/applies the
patch there and writes generated translations under the binary directory.
Source bytes are checked again before materialization. Invalid input/patches
must not update generated outputs; source/output overlap and symlink redirects
are rejected. Changed outputs and reports are written to new temporary files
and atomically replaced, preserving any inode hard-linked to the old leaf.
Identical outputs are not rewritten. Temporary storage must be
writable and outside a Git worktree; no machine-specific path is embedded.
Generated translations must never be hand-edited or committed.

Unified patch context includes whitespace on empty context lines. The exact
patch has an LF/whitespace attribute so Git preserves the patch representation;
actual added C lines are still checked with git apply --whitespace=error.

## Selected contract and maintenance delta

Only dmp_sodium_checked defines DMP_SODIUM_CHECKED_INIT=1. It keeps backend CPU
feature detection, allocator metadata and primitive implementation selection.
The platform implements [dmp_sodium_entropy.h](dmp_sodium_entropy.h): readiness
and a complete canary-byte read, with 0 for success and any nonzero error.
The two hooks execute under the existing startup lock and must not reenter
Noise/libsodium initialization. The platform owns CSPRNG quality, readiness,
bounded work and its own resource synchronization.

An entropy failure returns -1 before initialized is published. Partial canary
bytes are erased with existing sodium_memzero. The existing lock is released;
there is no implicit retry. A later explicit init call may retry and return 0
on first successful initialization; later calls return 1. Invalid allocator
page geometry also returns an error in this checked mode; that rare branch is
source-reviewed but not fault-injected by the current runtime tests.
Noise's serialized startup wrapper maps negative return to SYSTEM. The optional
pthread-once wrapper still retains its first outcome; recovery there requires
a different lifecycle, and is not accepted by this experiment.

The selected Noise provider must use the checked custom RNG-01 port for runtime
entropy. This patch does not retrofit every libsodium legacy randombytes API;
those APIs remain outside the selected provider surface. Windows/GNU test links
trap randombytes_stir/randombytes_buf so accidental use by the exercised
checked provider fails the test. A caller must require successful initialization
before using objects; no global constructor guard is added.

The original backend remains a distinct regression/comparison configuration,
including its expected OS RNG abort. CMake links dmp_noise_checked_startup only
to dmp_sodium_checked; it never silently swaps the baseline target.

## Validation and open work

The same NNpsk0/XX fixture, PN, DH and RNG probes and inherited unit/vector suites
run on the checked backend. Startup tests call actual sodium_init: deterministic
readiness/read failures, canary cleanup, two failures then explicit recovery,
already-initialized behavior and real SHA-256. A Windows variant uses the actual
OS RNG on success and injects FALSE at SystemFunction036 on failure. No init
mock, abort recovery, fixed-byte fallback or new generator enters the provider.
All deterministic ports are test-only.

See [BINIT-01 evidence](../../../dev/evidence/noise-backend-init-20260927/README.md).
Host success does not establish physical cold-boot entropy quality, bounded
startup lock duration, MCU resource budgets, full secret erasure, storage or
production safety. Next gate: bounded setup allocation/OOM and cleanup (MEM-01),
with MCU entropy/readiness evidence tracked separately. P01 remains running.
