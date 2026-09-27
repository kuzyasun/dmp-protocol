# MEM-03 multiple live provider owners - 2026-09-27

Status: scoped host MEM-03 accepted after independent review. P01 remains running.

Cross-ABI follow-up: MCU-02's macOS arm64 run exposed an assumption in the
original sensitivity probe: a pending handshake fitting the 8192-byte slice
does not guarantee headroom for Split's extra CipherState. Windows results below
remain historical measurements, not portable admission counts. The corrected
probe records `pending_completed` and `split_refused`, verifies exact OOM,
unchanged failed-Split ownership/accounting and surviving guards, and explicitly
requires full completion for medium/large slices. See the
[MCU-02 evidence](../noise-mcu-console-20260927/README.md) for actual rerun status.

## Frozen scope

One serialized endpoint arena, no allocator-domain switching or peer objects.
Replay fixed incoming fixture flights; local Noise writes/read/hash/Split and
traffic are real. Test NNpsk0/XX, both roles and mixed live owners. Check exact
vectors, partial allocation failure (including Split), safe destruction, slot
reuse and unaffected neighboring traffic/pending owners. Use the manifest's
single/four_serial counts and small/medium/large retained slices; account arena
metadata separately. four_parallel is deferred, never a passed serialized test.
Provider-only storage excludes unimplemented endpoint/binding state and stacks.
No production memory envelope is accepted.

Coordinator owns integration, allocation policy, status and acceptance. A worker
owns only the private single-owner fixture helper. Independent final review is
required. Test-only fixed keys and entropy; no firmware or protocol changes.

## Hardware handoff

The owner offered two potentially different ESP32 boards for later behavior and
memory tests over ESP-NOW or Bluetooth. Inform the owner when the runtime harness
is ready and MCU evidence is required; choose exact chips/boards, transport and
ports then. That future offer is not a selected binding, firmware deployment or
physical evidence. Provider-only stack/heap/entropy measurements can precede the
later real endpoint/binding resilience tests. Two Espressif chips do not replace
the separate non-Espressif portability evidence. No board action in this wave.

RBO job job_01M3G1BY07QSQE24X71WV30H3S failed at repo_fetch on the local fork pin;
use local host tools, with no publication workaround.

## Results and accounting

Ordinary GCC 15.2.0 host suite: **35/35 PASS**. Release owner probe: **1/1 PASS**.
The review-fix logs exercise the accepted TX-isolation correction described
below. `validation-summary.json` records tools, pins and scope;
`sensitivity-results.json` contains the 36 measured cases from the Release log.
Initial ordinary and final Release runs report the same sensitivity/OOM/reuse
measurements; the final tests add a stronger TX-direction check.

Each guard is a pair of real Split traffic contexts after handshake destruction.
The active/draining counts select guard counts only; DMP active/draining timers,
activation and replay state machines do not yet exist in this experiment.

| Manifest row / retained slice | Guards | Pending admitted | Peak charged provider bytes | Outcome |
|---|---:|---:|---:|---|
| single / 8192, 16384, 32768 | 2 | 1 | 1872 NN; 2224 XX; 1968 mixed | All 18 cases fully admitted |
| four_serial / 8192 | 8 | 3 NN; 2 XX or mixed | 6000 | All 6 cases safely refuse additional setup |
| four_serial / 16384, 32768 | 8 | 4 | 7104 NN; 8512 XX; 7808 mixed | All 12 cases fully admitted |
| four_parallel / all | - | - | - | Deferred: simultaneous calls not exercised |

Modes 0/1 are NNpsk0 initiator/responder, 2/3 XX initiator/responder,
4 alternates NN initiator and XX responder, 5 NN responder and XX initiator.
The small slice is **not sufficient** for the full four_serial requested load;
the passing property is bounded failure and survival of existing owners.

All peaks include transient setup/Split allocations, alignment charges and
attempts that fail. Add **2112 bytes host arena metadata** to charged bytes for
the logical provider slice. This is quota sensitivity, not variable physical
reservation: the test always reserves **32768 bytes backing + 2112 metadata**.
Owner records, fixed fixture/scratch buffers, call stacks, backend globals and
future DMP/binding state are excluded from that slice. Target ABI sizes differ;
no host number is an accepted MCU or full-endpoint budget.

Additional checks:

- Forty forced allocation-failure ordinals: 9 per NN role, 11 per XX role,
  including fixture setup and Split. Existing traffic owners continue to reject
  bad tags and accept authentic packets; the adjacent pending XX also completes.
- Guard receive directions are checked throughout interference. Each guard's
  sole PN-0 transmission is deferred until after the entire interference
  sequence, before destruction; its ciphertext/tag must match the fixture.
- Cancellation of a middle pending owner and reconstruction while neighbors
  remain live. Thirty-two mixed lifecycle cycles return to the same guard-only
  charged-byte/block baseline, with constant cumulative peak 6272 bytes.
- Real XX flight-2 MAC failure invalidates that attempt; authentic continuation
  cannot resume it. Destroying that attempt preserves guard traffic and permits
  an explicitly created fresh fixture instance.
- The allocator validates erasure before release and exact pointer/size
  ownership; final live bytes/blocks are zero and allocations equal releases.
- Individual handshake read/write calls and repeated bad/valid AEAD receives
  make no additional calls through the Noise custom allocation hook. This is
  not a transitive no-allocation proof for a future endpoint or all SDK paths.

Fixture traffic is test-only: each new context sends its one fixture PN-0 packet
once; repeated explicit-nonce receives exercise provider behavior, not SEC-1
replay protection. Deterministic repeated keys across test instances are not a
production key/nonce lifecycle or live peer interoperability claim.

## Reproduction and source identity

Use the prepared pinned backend described in `tests/provider/README.md`.
No implicit fetch is required. The recorded host compiler is
`C:/develop/mingw/w64devkit/bin/gcc.exe`; put its directory on PATH. For a fresh
build directory, specify Ninja, the compiler and the following options:

```text
cmake -S . -B build/noise-experiments -G Ninja -DCMAKE_C_COMPILER=C:/develop/mingw/w64devkit/bin/gcc.exe -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=<prepared-backend>
cmake --build build/noise-experiments
ctest --test-dir build/noise-experiments --output-on-failure
cmake -S . -B build/noise-memory-release -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=C:/develop/mingw/w64devkit/bin/gcc.exe -DDMP_NOISE_EXPERIMENTS=ON -DDMP_SODIUM_SOURCE_DIR=<prepared-backend>
cmake --build build/noise-memory-release --target dmp_noise_owners_probe
ctest --test-dir build/noise-memory-release -R ^dmp_noise_owners_probe$ -V
```

This run reused the existing configured directories: configure commands were
`cmake -S . -B build/noise-experiments` and the Release equivalent with
`-DCMAKE_BUILD_TYPE=Release`. Final acceptance logs are
`ordinary-review-fix-ctest.log` and `release-review-fix-ctest.log`;
targeted/full and pre-review logs are retained too.
Expected injected errors on stderr do not indicate failed test cases.

Compressed CMake caches, Ninja graphs and `ninja -t commands` preserve actual
compile/link settings; generated fixture/configuration headers are retained.
`artifact-inventory.json` hashes these snapshots and local executables/archives.
The first collection attempt stopped because this build does not export a
compile database; collection uses actual Ninja commands instead. No test failed.
Readable logs normalize line endings/trailing whitespace only; changed raw
bytes are retained as `.raw.gz`. Incremental logs do not establish a clean
warning-free rebuild of unchanged dependencies.

The fork stays at c40f2dc with no changes. All 47 port and 670 nested libsodium
file hashes were rechecked against MCU-01's `backend-files.json`, as were the
recorded backend HEADs. Normative document hashes remain at the initial baseline.
The parent index hash remained unchanged before intentional final staging.

## Independent review correction

The first independent pass found one P2 evidence gap: guards sent their sole
PN-0 packet before OOM/destruction/reuse; later checks exercised only receive
contexts. A damaged send-only context could have escaped detection. Coordinator
confirmed this against actual call order. Guard transmission now occurs after
interference in sensitivity, fault-sweep and repeated-lifetime paths, before
destruction; successful candidate traffic remains exercised separately. Peak
accounting also includes these final sends. No repeated PN-0 encryption on a
single context is introduced. Full ordinary and targeted Release tests passed
again, with unchanged resource measurements. The original review snapshots are
retained as `initial-*-snapshot.json`; corrected snapshots passed a bounded independent re-review. No provider or
normative change was needed.

## Remaining work and recommendation

Prepare an isolated on-MCU provider runner next: explicit stage timings,
stack high-water and heap/arena baselines, repeated lifetime/OOM loops, checked
platform entropy and reproducible machine-readable results. Reuse the portable
tests with a small platform wrapper; retain a non-Espressif path. Once ready,
request exact board/chip identifiers and ports before choosing firmware and any
physical action. Actual radio tests with two boards follow implemented endpoint
and binding state; they must include loss/reconnect/backpressure and long runs.

Parallel crypto-slot behavior, MCU execution/entropy quality, complete secret-copy
cleanup and aggregate resource budgets remain unpassed P01 gates. This wave
changes no wire contract, production provider adoption, board firmware or DTrack.

## Acceptance

Independent re-review closed the TX-isolation finding with scoped PASS and no
remaining findings. It verified 47 code, 50 evidence and 22 artifact hashes;
review was source/evidence inspection, with no extra execution by the reviewer.
Coordinator independently checked the diff, test exits, measurements and hashes.
Only status documentation changed afterward. `reviewed-*.gz` preserves the two
reviewed evidence documents whose acceptance status was updated. The historical
review snapshot and final acceptance snapshot therefore serve different roles.
See `review-result.json`. MCU runtime and complete P01 are not accepted.
