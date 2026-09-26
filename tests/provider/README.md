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

P01 must independently demonstrate exact SEC-1 prologues and flight bytes for
the selected modes/ciphers, invalid-then-valid receive (including pinned-peer
rejection), bounded tentative state with unchanged deadline, cached flights
without another encryption call, explicit transport PN and AAD, erasure, and
bounded pre-authentication work. Record retained/scratch/allocation requirements
and declared target limitations before freezing production state layouts.
