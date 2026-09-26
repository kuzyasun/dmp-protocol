# Milestone 0 experiments

This directory is a host-only C11 test scaffold. It contains no cryptographic
provider, production security adapter, endpoint implementation, or MCU budget.
`host_environment.c` checks compiler integer assumptions and CTest execution.
`fixtures.sec1` runs the existing independent public fixture verifier unchanged.
Neither check can satisfy P01.

Run from the repository root (CMake 3.20+, a C11 compiler and Node.js required):

```text
cmake -S . -B build/host -DDMP_BUILD_TESTS=ON
cmake --build build/host
ctest --test-dir build/host --output-on-failure
```

Multi-configuration generators additionally need the same `--config Debug` for
build and `-C Debug` for CTest. `DMP_BUILD_TESTS=OFF` configures no library or tests;
a production library will be introduced only after the prerequisite gates.

The private `dmp_add_provider_experiment(name sources...)` CMake function gives
P01 bounded executable tests, strict compiler warnings and a 30-second timeout.
The coordinator registers provider sources, pinned dependencies and any necessary
test timeout changes here. It is not a public provider ABI. Provider failure
must return a nonzero status; missing capabilities must not be reported as passes.

P01 must independently demonstrate exact SEC-1 revision 5 prologues/flights for
the declared modes/ciphers, abort-first after admitted read or mandatory
post-read/pin failure, and a separately scheduled fresh restart within unchanged
episode/global budgets. Structural rejects and conflicting processed-flight
duplicates retain their own preserve-attempt expectation; cloning is not required.
Test cached flights without another encryption call, unordered explicit PN/AAD,
invalid-high-PN isolation, low-order X25519 rejection, fallible entropy/storage,
erasure and bounded pre-authentication work. Record engine/backend provenance,
reviewed changes, retained/scratch/allocation/concurrency and target limitations
before freezing production layouts. Follow the experiment checklist in the
[implementation plan](../../dev/DMP_Implementation_Plan.md#abort-first-provider-experiment-before-p01-acceptance).
