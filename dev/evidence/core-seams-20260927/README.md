# P04 portable core and interface seams

Status: accepted after independent review. Baseline HEAD/index and dirty file hashes are in `baseline.json`;
exact index and staged/unstaged patches are preserved under ignored
`build/core-seams-preserve/`. Existing P03 acceptance is reused.

## Plan and acceptance

1. Create the real `libdmp` static C11 target (`dmp::dmp`) and SDK-independent
   public headers. Implement checked foundational byte/time/generation helpers
   once under `src/core/`; tests link that archive.
2. Freeze the minimum structural codec, framing, caller-owned storage and adapter
   submission/completion contracts for P05-P07. Explicitly separate parsing,
   framing integrity, authentication, local transmission and peer acceptance.
   No success stubs for unimplemented modules and no test-only protocol engine.
3. Freeze a bounded versioned subprocess contract for the future real C harness,
   including virtual time, event ordering, finite input/trace quotas and redaction.
4. Build and run focused C and available C++ consumer tests; verify a tests-off
   library build without host tool dependencies. Check archive allocator/SDK
   references. Those checks establish only the foundation, not P08 module-wide
   allocator/target qualification or real asynchronous-driver correctness.
5. Independently review public contracts and actual source/diffs/results before
   P04 acceptance. Update readiness of P05-P07 and P01B; leave their tests pending.

Coordinator owns headers, root CMake, interface decisions and acceptance. A Luna
xhigh agent investigates the bounded harness contract; Luna high owns only
`src/core/base.c` and three dedicated header/base test sources. At most two
agents run concurrently. RBO returned no live agents; local validation is used.

No protocol wire/security revision, existing manifest, credentials, hardware or
DTrack integration is changed by this package. The coordinator did not modify
the Git index; its externally observed change is recorded below.

## Implemented and validated

Actual source: `src/core/base.c`. The archive exports checked byte slicing,
checked deadline addition/comparison, nonwrapping generation advance and local
status names. C and C++ consumers link this archive. The core/frame/CRC headers
freeze P05/P06 declarations only; no replacement endpoint or implementation stubs.
The [interface contract](../../DMP_Core_Interfaces.md) and
[harness v1 contract](../../../tests/harness/PROTOCOL.md) define the next owners.

| Check | Actual outcome | Evidence |
|---|---|---|
| Debug strict C11/C++11 build | Passed, zero compiler warnings | configure.log, build.log (final header rebuild) |
| Full enabled default CTest graph | 6/6, including 23 profile methods and fixture/scaffold checks | ctest.log |
| Release foundation consumers, explicit CHECK (not assert) | 3/3 | release.log |
| Final header clarification rebuild and focused tests | 3/3 | ctest-final-headers.log |
| Tests disabled, C-only Release archive | Passed; no Python/Node/C++ detection in library graph | library-only.log |
| GNU nm global/undefined symbols | Five base exports; no undefined references | symbols.log |
| Scope/authority preservation | Normative main, manifest contract, implementation plan and accepted P03 checks unchanged | checks.json |

Commands were run from the repository root using CMake 3.28.1, Ninja 1.11.1,
GCC/G++ 15.2.0, Python 3.12.8 and Node 24.11.1. Configure used `-G Ninja`,
`-DCMAKE_C_COMPILER=C:/develop/mingw/w64devkit/bin/gcc.exe`,
`-DCMAKE_CXX_COMPILER=C:/develop/mingw/w64devkit/bin/g++.exe` for test builds and
`-DPython3_EXECUTABLE=C:/develop/Python312/python.exe`. These are evidence paths,
not machine-specific requirements committed into the build configuration.

```text
cmake -S . -B build/core-seams -G Ninja -DCMAKE_BUILD_TYPE=Debug <compiler/Python options above>
cmake --build build/core-seams
ctest --test-dir build/core-seams --output-on-failure
cmake -S . -B build/core-seams-release -G Ninja -DCMAKE_BUILD_TYPE=Release <compiler/Python options above>
cmake --build build/core-seams-release --target dmp_test_base dmp_test_headers dmp_test_headers_cpp
ctest --test-dir build/core-seams-release -L core-foundation --output-on-failure
cmake -S . -B build/core-seams-library -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=C:/develop/mingw/w64devkit/bin/gcc.exe -DDMP_BUILD_TESTS=OFF
cmake --build build/core-seams-library
C:/develop/mingw/w64devkit/bin/nm.exe -g build/core-seams-library/libdmp.a
ctest --test-dir build/core-seams -L core-foundation --output-on-failure
```

The initial sandbox compiler probe stalled. Only the identified task's CMake/
Ninja processes were stopped; the same configuration succeeded outside the
sandbox. No compiler checks were forced to succeed. RBO had no live agents.

## Scope, review and preservation

Luna high wrote only the foundation and three consumer tests; coordinator fixed
their entrypoints to match three independent test executables, inspected the
source and performed actual builds. The harness investigation was read-only.
Astra xhigh independently reviewed final interfaces, source, tests and logs;
the findings and closure are recorded in `review.md`.

No normative implementation case is passed by these foundation checks. P05-P07,
P08 sanitizer/fuzz/other-toolchain checks, P01B actual provider integration and
physical target/resource qualification remain separate. A host symbol listing
does not prove future modules or MCU budgets. No board access was needed.

The initial index was preserved byte-for-byte in ignored local storage. During
this task, an external action staged additional files: index changed from
`d1ddf5da...` to `28381272...`, with 293 staged paths. We issued no staging,
reset, commit or push command and did not restore the original over that newer
state. The observed index was also saved; see `index-observation.json`.
Existing unrelated staged log whitespace was observed and left intact; focused
P04 source/document diff checks passed. HEAD stayed at the baseline commit.
