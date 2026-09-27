# P02 offline manifest validator

Status: **P02 accepted** after independent source, corpus and execution-evidence
review. P03 is ready; runtime profile enforcement remains P09.

The owner authorized P02 after the implementation-first transition. Scope:
versioned two-endpoint test-manifest contract, standard JSON Schema, strict
stdlib Python offline validator and valid/invalid interpretation corpus.
The coordinator implemented contract/schema/validator/build registration. A
bounded Luna high worker completed the corpus and tests. Independent Astra xhigh
reviewers checked the frozen source and final corpus/evidence. The initial Luna
worker hit a usage limit; a Sol replacement was interrupted after the owner
corrected model routing. The completed test assignment followed Luna high routing.

`baseline.json` records HEAD, prior dirty status, Git index and relevant file
hashes. Existing dirty provider/MCU work is not part of P02. No commit, push,
hardware operation or DTrack integration was performed in this package. The index
changed during execution to a staged 238-file snapshot; coordinator issued no
staging/reset command. The observed index was preserved, not restored over those
changes. See `index-observation.json`; do not claim it equals the initial index.

Actual passing commands (Windows local fallback):

```text
python -m unittest discover -s tests/profiles -p 'test_*.py' -v
cmake -S . -B build/profile-gate -G Ninja -DCMAKE_C_COMPILER=C:/develop/mingw/w64devkit/bin/gcc.exe -DDMP_BUILD_TESTS=ON -DDMP_NOISE_EXPERIMENTS=OFF
cmake --build build/profile-gate
ctest --test-dir build/profile-gate -V --output-junit C:/projects/gemslibe/dmp-protocol/dev/evidence/profile-validator-20260927/ctest.xml
```

RBO initially had a macOS worker, but the pre-execution `agents_list` returned no
live agents. The operator was informed before local fallback. Initial sandboxed
CMake/Ninja ABI probing hung and was terminated; the identical configure/build
outside sandbox passed in 2.3 seconds. CTest then ran in the normal sandbox.
Versions: Python 3.12.8, GCC 15.2.0, CMake 3.28.1, Ninja 1.11.1, Node 24.11.1.

Results: **3/3 CTest targets passed**: `profiles.contract` (10 methods, 41 negative
manifest mutations, 17 raw-input cases, 3 byte-pinned positive fixtures and
dedicated exact-boundary/XX/CLI checks), existing SEC-1 fixture verifier, and C11
host scaffold. Build emitted no warnings. `ctest.log` and `ctest.xml` are actual
captured outputs; `checks.json` pins tested source/fixture hashes and confirms all
seven original normative documents/vectors remain unchanged.

The [source review](review.md) closed seven concrete findings before execution.
Final corpus review found the 21-byte grant-result regression initially failed
an unrelated 64-byte application bound. The worker isolated a 17-byte application
limit and checked 20-byte refusal / 21-byte acceptance, then the coordinator
reran CTest successfully. Initial nine-method logs/provenance are retained as
`*-initial.*`; they do not substitute for the corrected final run. Final reviewer
independently recomputed every expected bound/hash and accepted the correction.
The only subsequent edit was a reviewed README wording correction; no source or
fixture change invalidated the final execution.

The immutable-input corpus and selected static simulated binding are deliberately
narrow. RAM values are finite component design reserves, not measured provider
or library layouts. The test binding must still implement its serialized slots.
P03 freezes deployment instances; P09 implements runtime/startup parity. No
validator result establishes DMP endpoint behavior, real delay/airtime, memory
fit or physical transport support. P04 still creates the actual library.
